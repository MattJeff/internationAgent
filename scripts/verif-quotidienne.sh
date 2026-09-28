#!/bin/bash
# Le contrôle réel du jour, une fois les nourrissages de 09:00 et 10:00 UTC
# passés. Trois pannes de la semaine du 22 sont restées invisibles des jours —
# réponses jamais ingérées (mauvais endpoint Resend), nourrissages tirés un
# jour trop tard, approbations en 403 — parce que rien ne VÉRIFIAIT, chaque
# jour, que chaque maillon avait bougé. Cinq contrôles, une ligne OK/KO chacun ;
# au moindre KO un mail rouge part à $AGENTOS_APPROVAL_NOTIFY. Tout OK = rien
# qu'une ligne de journal.
#
#   1. nourri à l'heure   — chaque séquence vivante avec `feed` dont l'heure
#                           est passée a `fed_on` = aujourd'hui (UTC)
#   2. lettres parties    — des runs ont démarré → au moins une lettre sortie,
#                           et moins de 50 % de runs arrêtés `not_sent`
#   3. entrant réel       — une sonde envoyée par Resend à un siège revient
#                           dans `messages` (direction=inbound) sous 10 min
#   4. approbations       — GET /v1/approvals?state=pending répond 200
#   5. tunnel             — $PUBLIC_HOST_FIXE/v1/health répond 200 ou 401
#
# LECTURE SEULE en base. DRY_RUN=true : tout sauf les deux envois Resend (la
# sonde et le mail rouge), qui sont affichés au lieu d'être envoyés.
# ponytail: psql + curl, pas de dépendance ; les adresses de la sonde sont des
# défauts surchargés par SONDE_DE / SONDE_VERS. Tourne depuis la veille de
# ce-soir.sh après 10:40 UTC, ou à la main.
set -uo pipefail
ETAT="${AGENTOS_ETAT:-$HOME/.agentos-ce-soir}"
API="${AGENTOS_API:-http://127.0.0.1:8787}"
RESEND="${EMAIL_API_BASE:-https://api.resend.com}"
LOG="$ETAT/verif-quotidienne.log"
DRY_RUN="${DRY_RUN:-false}"
JOUR="$(date -u +%F)"
exec > >(tee -a "$LOG") 2>&1
echo "== vérification du $JOUR ($(date -u +%FT%TZ))$([ "$DRY_RUN" = true ] && echo ' — DRY_RUN')"
. "$ETAT/secrets.env"
: "${CLE_OPS:?CLE_OPS manque dans $ETAT/secrets.env}"
: "${AGENTOS_APPROVAL_NOTIFY:?AGENTOS_APPROVAL_NOTIFY manque dans $ETAT/secrets.env}"
: "${PUBLIC_HOST_FIXE:?PUBLIC_HOST_FIXE manque dans $ETAT/secrets.env}"
# La clé Resend n'est pas dans secrets.env : elle vit dans l'environnement du
# serveur lancé en --reel. Lue sur le processus, comme `deja_reel` de ce-soir.sh.
if [ -z "${EMAIL_API_KEY:-}" ] && [ -f "$ETAT/serveur.pid" ]; then
  EMAIL_API_KEY="$(ps eww -p "$(cat "$ETAT/serveur.pid")" -o command= 2>/dev/null | tr ' ' '\n' | sed -n 's/^EMAIL_API_KEY=//p' | head -1)"
fi
# `sdr@` est la seule adresse où du courrier entrant réel est déjà arrivé
# (2026-09-23) ; `founder@` est sur le même domaine vérifié et son siège ne
# prend aucun tour (max_turns_per_day 0), donc une réponse du siège sondé
# n'en réveille pas un autre.
SONDE_DE="${SONDE_DE:-founder@agents.getorizn.com}"
SONDE_VERS="${SONDE_VERS:-sdr@agents.getorizn.com}"

sql() { PGTZ=UTC PGPORT="${PGPORT:-5432}" psql -X -d "${DB_NAME:-agentos_ce_soir}" -Atc "$1"; }
lignes=(); ko=0
note() { lignes+=("$1 $2"); [ "$1" = KO ] && ko=$((ko + 1)); echo "$1 $2"; }

# Le mail rouge et la sonde partent par la même porte que les lettres.
resend() { # $1 destinataire, $2 sujet, $3 corps HTML
  if [ "$DRY_RUN" = true ]; then
    echo "  (DRY_RUN) Resend de=$SONDE_DE vers=$1 sujet=« $2 »"; printf '%s\n' "$3" | sed 's/^/  | /'; return 0
  fi
  [ -n "${EMAIL_API_KEY:-}" ] || { echo "  EMAIL_API_KEY introuvable (ni dans l'environnement, ni sur le serveur) : rien n'est parti."; return 1; }
  python3 -c 'import json,sys; print(json.dumps({"from":sys.argv[1],"to":[sys.argv[2]],"subject":sys.argv[3],"html":sys.argv[4]}))' \
    "$SONDE_DE" "$1" "$2" "$3" \
    | curl -sS -m 30 -o /dev/null -w '%{http_code}' -X POST "$RESEND/emails" \
        -H "Authorization: Bearer $EMAIL_API_KEY" -H 'content-type: application/json' --data-binary @- \
    | grep -q '^200$'
}

# 1. Nourri à l'heure.
r="$(sql "select count(*) filter (where (feed->>'hour')::int <= extract(hour from now())::int),
                 coalesce(string_agg(name || ' (feed ' || (feed->>'hour') || 'h, fed_on ' || coalesce(fed_on::text,'jamais') || ')', ', ')
                   filter (where (feed->>'hour')::int <= extract(hour from now())::int and fed_on is distinct from current_date), '')
            from sequences where archived_at is null and feed is not null")" \
  || r="|psql injoignable"
dues="${r%%|*}"; tard="${r#*|}"
if [ -z "$tard" ]; then note OK "nourri à l'heure : $dues séquence(s) due(s), toutes nourries le $JOUR"
else note KO "nourri à l'heure : pas nourri aujourd'hui — $tard"; fi

# 2. Lettres parties.
r="$(sql "select count(*) filter (where started_at >= current_date),
                 count(*) filter (where ended_at >= current_date and stop_reason = 'not_sent'),
                 (select count(*) from messages where direction='outbound' and channel='email' and created_at >= current_date)
            from sequence_runs")" || r=""
IFS='|' read -r demarres non_envoyes sorties <<< "$r"
if [ -z "$r" ]; then note KO "lettres parties : psql injoignable"
elif [ "$demarres" -eq 0 ]; then note OK "lettres parties : aucun run démarré aujourd'hui, $sorties lettre(s) sortie(s)"
elif [ "$sorties" -eq 0 ]; then note KO "lettres parties : $demarres run(s) démarré(s), AUCUNE lettre sortie"
elif [ $((non_envoyes * 2)) -ge "$demarres" ]; then note KO "lettres parties : $non_envoyes not_sent sur $demarres démarrés (≥ 50 %), $sorties lettre(s) sortie(s)"
else note OK "lettres parties : $demarres démarré(s), $sorties sortie(s), $non_envoyes not_sent"; fi

# 3. Entrant réel : une sonde, puis jusqu'à 10 min d'attente.
nonce="$(openssl rand -hex 4)"; sujet="verif-quotidienne $JOUR $nonce"
if [ "$DRY_RUN" = true ]; then
  resend "$SONDE_VERS" "$sujet" "probe — no reply needed"
  note OK "entrant réel : DRY_RUN — sonde « $sujet » non envoyée, pas d'attente (dernier entrant : $(sql "select coalesce(max(created_at)::text,'jamais') from messages where direction='inbound' and channel='email'"))"
elif resend "$SONDE_VERS" "$sujet" "probe — no reply needed"; then
  vu=""
  for _ in $(seq 20); do
    sleep 30
    vu="$(sql "select created_at from messages where direction='inbound' and channel='email' and subject like '%$nonce%' limit 1")"
    [ -n "$vu" ] && break
  done
  if [ -n "$vu" ]; then note OK "entrant réel : sonde « $sujet » revenue dans messages à $vu"
  else note KO "entrant réel : sonde « $sujet » envoyée à $SONDE_VERS, rien dans messages après 10 min"; fi
else note KO "entrant réel : Resend a refusé la sonde (ou clé absente)"; fi

# 4. Approbations.
code="$(curl -s -o /dev/null -m 10 -w '%{http_code}' -H "Authorization: Bearer $CLE_OPS" "$API/v1/approvals?state=pending")"
if [ "$code" = 200 ]; then note OK "approbations : GET /v1/approvals?state=pending → 200"
else note KO "approbations : GET /v1/approvals?state=pending → $code"; fi

# 5. Tunnel.
code="$(curl -s -o /dev/null -m 10 -w '%{http_code}' "$PUBLIC_HOST_FIXE/v1/health")"
case "$code" in
  200|401) note OK "tunnel : $PUBLIC_HOST_FIXE/v1/health → $code" ;;
  *) note KO "tunnel : $PUBLIC_HOST_FIXE/v1/health → $code" ;;
esac

# Le verdict. Rouge = un mail ; vert = le journal suffit.
if [ "$ko" -gt 0 ]; then
  html="<pre>$(printf '%s\n' "${lignes[@]}" | sed 's/&/\&amp;/g; s/</\&lt;/g')</pre>"
  resend "$AGENTOS_APPROVAL_NOTIFY" "🔴 Orizn — vérification du $JOUR : $ko KO" "$html" \
    && echo "== $ko KO — mail rouge $([ "$DRY_RUN" = true ] && echo 'affiché, non envoyé (DRY_RUN)' || echo "envoyé à $AGENTOS_APPROVAL_NOTIFY")" \
    || echo "== $ko KO — et le mail rouge n'est PAS parti"
  exit 1
fi
echo "== tout OK ($(date -u +%FT%TZ))"

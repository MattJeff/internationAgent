#!/usr/bin/env bash
#
# Monter l'instance complète sur la machine du fondateur, en une commande.
#
# Ce que ce script fait, et où il s'arrête : il pose l'INFRASTRUCTURE — la base,
# les migrations (par le serveur, à son démarrage), le locataire, le plafond de
# politique, le serveur, la clé, et les deux choses qui ne sont pas du produit
# mais de la machine : le Chrome qui lit les pages et le tunnel par lequel on
# reçoit. Il ne crée NI la société NI le premier siège : c'est le geste que le
# fondateur veut faire depuis son terminal, et le lui voler lui retire la
# démonstration.
#
# Le modèle est le `claude` de cette machine (AGENTOS_LLM=cli). Rien n'est
# intermédié : pas de jeton collecté, pas de session stockée, pas de binaire
# modifié. Voir docs/CE_SOIR.md pour pourquoi c'est légal ici et pas sur le VPS.
#
# Relancer ce script ne casse rien : la base, le locataire, le plafond et les
# clés sont retrouvés plutôt que recréés.
#
#   scripts/ce-soir.sh             faux adaptateurs — rien ne part vraiment
#   scripts/ce-soir.sh --reel      e-mail réel via Resend (demande confirmation)
#   scripts/ce-soir.sh --recevoir  ouvre un tunnel public et enregistre la porte
#                                  d'entrée du courrier (webhook_endpoints)
#   scripts/ce-soir.sh --arreter   arrête le serveur, le Chrome et le tunnel
#   scripts/ce-soir.sh --effacer   arrête, puis supprime la base et l'état
#
# Le navigateur : si Google Chrome est installé, il est lancé en `--headless=new`
# et `BROWSER_CDP_URL` le nomme, donc un siège qui veut lire le site d'un
# prospect avant d'écrire le lit vraiment. Sans lui, `MockBrowser` répond
# `no_such_element` à toute lecture et le siège renonce — le script le dit.
#
# La répétition générale de `--reel`, sans clé Resend et sans destinataire :
#
#   python3 scripts/faux-resend.py --port 8081 \
#     --journal /tmp/envois.jsonl --etat /tmp/faux-resend.json &
#   EMAIL_API_KEY=re_faux AGENT_EMAIL_DOMAIN=… EMAIL_API_BASE=http://127.0.0.1:8081 \
#     scripts/ce-soir.sh --reel
#
# `EMAIL_API_BASE` est refusée par le serveur sans `AGENTOS_ALLOW_MOCKS` ; ici
# elle est posée, et le script ne demande pas de `OUI` parce qu'il n'y a rien à
# confirmer : rien ne sort de la machine.

set -euo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ETAT="${AGENTOS_CE_SOIR_ETAT:-$HOME/.agentos-ce-soir}"
PORT="${PORT:-8787}"
# Le port du protocole de débogage de Chrome. Un autre port que celui du serveur
# et réglable pour la même raison : deux instances sur la même machine ne
# partagent pas un navigateur, chacune veut le sien.
CDP_PORT="${CDP_PORT:-9222}"
PGPORT="${PGPORT:-5432}"
PGHOST="${PGHOST:-localhost}"
BASE_NOM="${DB_NAME:-agentos_ce_soir}"
# L'utilisateur est NOMMÉ, jamais sous-entendu. Une URL sans utilisateur laisse
# sqlx deviner, et quand la devinette échoue il essaie de se connecter en
# « anonymous » — l'erreur qu'on lit est alors `role "anonymous" does not exist`,
# qui ne dit rien de ce qui s'est passé. Mesuré le 2026-09-12 : le serveur
# mourait au démarrage sur une base que psql ouvrait sans broncher.
PGUSER="${PGUSER:-$(id -un)}"
BASE_URL="postgres://${PGUSER}@${PGHOST}:${PGPORT}"

CHROME_MAC="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

REEL=0
RECEVOIR=0
ACTION=monter
for arg in "$@"; do
  case "$arg" in
    --reel) REEL=1 ;;
    --recevoir) RECEVOIR=1 ;;
    --arreter) ACTION=arreter ;;
    --effacer) ACTION=effacer ;;
    -h|--help) sed -n '3,41p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "je ne connais pas « $arg ». --reel, --recevoir, --arreter, --effacer, --help." >&2; exit 2 ;;
  esac
done

dit()    { printf '\033[1m==\033[0m %s\n' "$*"; }
refuse() { printf '\033[1;31m== REFUS\033[0m %s\n' "$*" >&2; exit 1; }

PIDFILE="$ETAT/serveur.pid"
JOURNAL="$ETAT/serveur.log"
CHROME_PIDFILE="$ETAT/chrome.pid"
CHROME_PROFIL="$ETAT/chrome-profil"
TUNNEL_PIDFILE="$ETAT/tunnel.pid"
TUNNEL_JOURNAL="$ETAT/tunnel.log"

# Tout ce que ce script a lancé s'arrête par son pid, et par rien d'autre.
# Jamais `pkill` : d'autres agents, d'autres serveurs et le Chrome du fondateur
# tournent sur cette machine, et un `pkill chrome` fermerait ses onglets.
arreter_pid() { # fichier-pid, nom, secondes d'attente
  [ -f "$1" ] || return 0
  local pid; pid="$(cat "$1")"
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid"
    for _ in $(seq 1 "$3"); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
    dit "$2 $pid arrêté."
  else
    dit "le pid $pid de $2 ne tourne plus."
  fi
  rm -f "$1"
}

arreter() {
  if [ -f "$PIDFILE" ]; then
    # Attendre qu'il rende ses connexions : un `dropdb` lancé pendant que le
    # serveur tient encore seize connexions échoue, et `--effacer` laisserait
    # la base derrière lui en disant le contraire.
    arreter_pid "$PIDFILE" "serveur" 20
  else
    dit "aucun serveur lancé par ce script."
  fi
  arreter_pid "$TUNNEL_PIDFILE" "tunnel" 10
  arreter_pid "$CHROME_PIDFILE" "Chrome" 10
}

case "$ACTION" in
  arreter) arreter; exit 0 ;;
  effacer)
    arreter
    dropdb --if-exists -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" "$BASE_NOM" \
      || refuse "la base $BASE_NOM n'a pas pu être supprimée — quelque chose y est encore connecté. Rien d'autre n'a été effacé."
    dit "base $BASE_NOM supprimée."
    rm -rf "$ETAT"
    dit "état $ETAT effacé (clés comprises : la prochaine ligne « claude mcp add » sera une autre)."
    exit 0 ;;
esac

# ---------------------------------------------------------------------------
# Ce qu'il refuse, et il le dit avant de rien construire
# ---------------------------------------------------------------------------

command -v cargo >/dev/null || refuse "pas de cargo sur le PATH : rien à compiler."
command -v psql  >/dev/null || refuse "pas de psql sur le PATH : je ne sais pas parler à Postgres."
command -v curl  >/dev/null || refuse "pas de curl sur le PATH."

psql "$BASE_URL/postgres" -Atc 'select 1' >/dev/null 2>&1 \
  || refuse "Postgres ne répond pas à « $PGUSER » sur ${PGHOST}:${PGPORT}. (PGPORT=5442 est l'ancien port docker, mort ; le Homebrew 17 est sur 5432. PGUSER= pour un autre rôle.)"

command -v claude >/dev/null \
  || refuse "pas de binaire « claude » sur le PATH. C'est LUI le modèle de ce montage : sans lui il n'y a pas de tour, donc pas d'e-mail. Aucune clé Anthropic ne remplace ça ici — c'est le chemin cli, pas le chemin api_key."

if [ "$RECEVOIR" = 1 ]; then
  command -v cloudflared >/dev/null \
    || refuse "--recevoir sans cloudflared. C'est lui qui donne une adresse publique à ce portable : « brew install cloudflared ». Un tunnel rapide ne demande ni compte ni dépense."
fi

mkdir -p "$ETAT"; chmod 700 "$ETAT"

if [ "$REEL" = 1 ]; then
  [ -n "${EMAIL_API_KEY:-}" ] \
    || refuse "--reel sans EMAIL_API_KEY. Exporte la clé Resend d'abord ; sans elle l'adaptateur reste faux et --reel ne veut rien dire."
  [ -n "${AGENT_EMAIL_DOMAIN:-}" ] \
    || refuse "--reel sans AGENT_EMAIL_DOMAIN. Nomme le domaine d'envoi vérifié chez Resend ; le faux domaine par défaut ferait refuser chaque envoi par Resend."
  if [ -n "${EMAIL_API_BASE:-}" ]; then
    # La répétition générale. L'adaptateur est le vrai — même code, même
    # `Idempotency-Key`, même `provider_message_id` relu — et il parle à
    # l'adresse nommée. Pas de `OUI` à taper : il n'y a rien à confirmer quand
    # rien ne sort de la machine, et un avertissement qui ment la première fois
    # n'est plus lu la seconde.
    dit "--reel contre EMAIL_API_BASE=$EMAIL_API_BASE : l'adaptateur Resend est le vrai, son correspondant ne l'est pas. Rien ne sortira de cette machine."
  else
    cat >&2 <<'AVERT'

  ┌─ --reel : ce que tu viens de demander ───────────────────────────────────┐
  │ L'adaptateur e-mail devient Resend. Un siège qui prend un tour et décide │
  │ d'écrire ENVERRA un vrai e-mail, à une vraie adresse, depuis ton domaine │
  │ vérifié, et ça compte sur ta réputation d'envoi. Il n'y a pas de mode    │
  │ « presque ». Le téléphone et l'embedder restent faux ; le navigateur est │
  │ un vrai Chrome s'il est installé.                                        │
  └──────────────────────────────────────────────────────────────────────────┘

AVERT
    printf '  tape OUI pour continuer : ' >&2
    read -r reponse
    [ "$reponse" = "OUI" ] || refuse "annulé. Relance sans --reel pour la marche à blanc."
  fi
fi

# Le port : le nôtre, ou personne.
if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  if [ -f "$PIDFILE" ] && lsof -nP -iTCP:"$PORT" -sTCP:LISTEN -t 2>/dev/null | grep -qx "$(cat "$PIDFILE")"; then
    dit "le serveur de ce script écoute déjà sur $PORT ; je l'arrête pour repartir propre."
    arreter; sleep 1
  else
    refuse "quelque chose écoute déjà sur le port $PORT et ce n'est pas moi. Choisis-en un autre : PORT=8788 scripts/ce-soir.sh"
  fi
fi

# En dernier parmi les refus, parce que c'est le seul qui coûte quelque chose :
# un tour minuscule sur la session du fondateur. Tout ce qui pouvait refuser
# gratuitement a déjà refusé.
dit "je vérifie que ton claude est connecté (un tour minuscule, sur ta session)…"
if ! printf 'dis ok' | claude -p --max-turns 1 --setting-sources '' --strict-mcp-config >/dev/null 2>"$ETAT/sonde.log" ; then
  refuse "ton « claude » n'a pas répondu. Lance-le une fois à la main et connecte-toi ; c'est ta session à toi, ce script n'y touche jamais. Détail : $ETAT/sonde.log"
fi
dit "claude répond."

# ---------------------------------------------------------------------------
# L'état : créé une fois, retrouvé ensuite. C'est ce qui rend le script idempotent
# et surtout ce qui fait que la ligne `claude mcp add` reste valable d'un soir
# à l'autre.
# ---------------------------------------------------------------------------

SECRETS="$ETAT/secrets.env"
if [ ! -f "$SECRETS" ]; then
  dit "premier démarrage : je tire le locataire, la clé maîtresse et les deux clés d'API."
  # Deux clés parce qu'une seule ne suffit pas : l'étiquette EST le rôle, et
  # `may_decide` refuse les quatre yeux sur soi-même — une clé ne peut pas à la
  # fois demander et approuver un paiement.
  {
    echo "TENANT_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')"
    echo "MASTER_KEY=$(openssl rand -hex 32)"
    echo "CLE_OPS=$(openssl rand -hex 24)"
    echo "CLE_APPROBATEUR=$(openssl rand -hex 24)"
  } > "$SECRETS"
  chmod 600 "$SECRETS"
fi
# shellcheck disable=SC1090
. "$SECRETS"

# Les deux secrets de `--recevoir`, ajoutés le jour où on en a besoin plutôt
# qu'à la création : un état écrit avant ce mode-là n'en a pas, et le
# régénérer à chaque lancement ferait d'un `whsec_…` recollé chez le
# fournisseur un secret périmé au redémarrage suivant.
if [ "$RECEVOIR" = 1 ] && [ -z "${CLE_PLATEFORME:-}" ]; then
  {
    echo "CLE_PLATEFORME=$(openssl rand -hex 24)"
    # `whsec_` + du base64, la forme que Resend donne aux siens. La forme ne
    # change rien à la vérification — c'est un HMAC sur des octets — mais un
    # secret qui ne ressemble pas à ceux du fournisseur est un secret qu'on
    # colle au mauvais endroit.
    echo "SECRET_WEBHOOK=whsec_$(openssl rand -base64 24 | tr -d '\n')"
  } >> "$SECRETS"
  # shellcheck disable=SC1090
  . "$SECRETS"
fi

# ---------------------------------------------------------------------------
# Le tunnel, AVANT le serveur, parce que `PUBLIC_HOST` est lu au démarrage
# ---------------------------------------------------------------------------
#
# Un tunnel rapide (`cloudflared tunnel --url`) donne une adresse
# `https://…trycloudflare.com` sans compte et sans dépense. Elle CHANGE à chaque
# lancement : le webhook côté fournisseur est à recoller à chaque fois, et c'est
# le prix de ne pas demander de compte. Un tunnel NOMMÉ (`cloudflared tunnel
# create`) garderait l'adresse — il faudrait le compte Cloudflare du fondateur
# et un `cloudflared login` ; ce script ne le fait pas et ne le fera pas tout
# seul.
#
# Il est lancé ici plutôt qu'après le serveur parce que `PUBLIC_HOST` est ce que
# le produit croit être sa propre adresse : le lien de désabonnement, la carte
# d'agent et l'URL que le schéma de Twilio signe en sortent. Pointé sur
# `127.0.0.1`, le lien de désabonnement est mort chez le destinataire, et
# Gmail le lit.
PUBLIC="http://127.0.0.1:$PORT"
if [ "$RECEVOIR" = 1 ]; then
  # Celui d'avant, s'il tourne encore : une nouvelle exécution a de toute façon
  # une nouvelle adresse, et écraser le fichier de pid laisserait l'ancien
  # tunnel ouvert sans que rien ne sache plus l'arrêter.
  arreter_pid "$TUNNEL_PIDFILE" "l'ancien tunnel" 10
  dit "j'ouvre un tunnel rapide (sans compte, sans dépense)…"
  : > "$TUNNEL_JOURNAL"
  cloudflared tunnel --no-autoupdate --url "http://127.0.0.1:$PORT" \
    >"$TUNNEL_JOURNAL" 2>&1 &
  echo $! > "$TUNNEL_PIDFILE"
  ADRESSE=""
  for _ in $(seq 1 40); do
    ADRESSE="$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$TUNNEL_JOURNAL" | head -1 || true)"
    if [ -n "$ADRESSE" ]; then break; fi
    kill -0 "$(cat "$TUNNEL_PIDFILE")" 2>/dev/null \
      || { tail -20 "$TUNNEL_JOURNAL" >&2; refuse "cloudflared est mort avant d'annoncer une adresse. Journal : $TUNNEL_JOURNAL"; }
    printf .; sleep 1
  done; echo
  [ -n "$ADRESSE" ] || { tail -20 "$TUNNEL_JOURNAL" >&2; refuse "cloudflared n'a annoncé aucune adresse en 40 s. Journal : $TUNNEL_JOURNAL"; }
  PUBLIC="$ADRESSE"
  dit "tunnel ouvert : $PUBLIC (pid $(cat "$TUNNEL_PIDFILE"))"
fi

# ---------------------------------------------------------------------------
# Le navigateur : un vrai Chrome, ou rien, et il le dit
# ---------------------------------------------------------------------------
#
# `MockBrowser` répond `no_such_element` à chaque lecture — mesuré le
# 2026-09-10 — donc un siège commercial dont la charte exige de lire le site
# d'un prospect avant d'écrire renonce toujours, et le journal d'audit le
# montre. La ligne ci-dessous est celle que `browser_chrome.rs` documente pour
# macOS et celle que la CI lance sous Linux.
CHROME_URL=""
if [ -x "$CHROME_MAC" ]; then
  if curl -fsS "http://127.0.0.1:$CDP_PORT/json/version" >/dev/null 2>&1; then
    # Quelque chose parle déjà CDP sur ce port : c'est un navigateur, pas un
    # inconnu, et en relancer un second échouerait sur le port occupé.
    dit "un navigateur répond déjà en CDP sur $CDP_PORT ; je le prends tel quel."
    CHROME_URL="http://127.0.0.1:$CDP_PORT"
  elif lsof -nP -iTCP:"$CDP_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    refuse "le port $CDP_PORT est pris par quelque chose qui ne parle pas CDP. Choisis-en un autre : CDP_PORT=9223 scripts/ce-soir.sh"
  else
    mkdir -p "$CHROME_PROFIL"
    "$CHROME_MAC" --headless=new --remote-debugging-port="$CDP_PORT" \
      --user-data-dir="$CHROME_PROFIL" about:blank \
      >"$ETAT/chrome.log" 2>&1 &
    echo $! > "$CHROME_PIDFILE"
    for _ in $(seq 1 30); do
      curl -fsS "http://127.0.0.1:$CDP_PORT/json/version" >/dev/null 2>&1 && break
      kill -0 "$(cat "$CHROME_PIDFILE")" 2>/dev/null \
        || { tail -20 "$ETAT/chrome.log" >&2; refuse "Chrome est mort au démarrage. Journal : $ETAT/chrome.log"; }
      printf .; sleep 1
    done; echo
    curl -fsS "http://127.0.0.1:$CDP_PORT/json/version" >/dev/null 2>&1 \
      || refuse "Chrome n'a pas ouvert son port de débogage en 30 s. Journal : $ETAT/chrome.log"
    CHROME_URL="http://127.0.0.1:$CDP_PORT"
    dit "Chrome lancé, pid $(cat "$CHROME_PIDFILE"), CDP sur $CDP_PORT."
  fi
else
  dit "pas de « $CHROME_MAC » : le navigateur restera FAUX. Un siège qui veut lire le site d'un prospect avant d'écrire lira \`no_such_element\` et renoncera — et il le fera en silence, la charte satisfaite. Installe Google Chrome, ou accepte que la lecture de page ne marche pas ce soir."
fi

# ---------------------------------------------------------------------------
# La base, le binaire, le serveur
# ---------------------------------------------------------------------------

if [ "$(psql "$BASE_URL/postgres" -Atc "select 1 from pg_database where datname='$BASE_NOM'")" = 1 ]; then
  dit "base $BASE_NOM : déjà là."
else
  createdb -h "$PGHOST" -p "$PGPORT" "$BASE_NOM"
  dit "base $BASE_NOM créée."
fi
DATABASE_URL="$BASE_URL/$BASE_NOM"

dit "compilation (la première fois, c'est long ; ensuite c'est instantané)…"
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0
( cd "$RACINE" && cargo build -q -p agentos-server --bin agentos-server )
BIN="$RACINE/target/debug/agentos-server"

# Les quatre obligatoires, puis le reste. AGENTOS_ALLOW_MOCKS=1 est là parce que
# le téléphone et l'embedder n'ont pas de clé sur cette machine : sans lui le
# serveur REFUSE de démarrer, et il a raison — un faux adaptateur en production
# est une panne qui rend un succès.
export PUBLIC_HOST="$PUBLIC"
export AGENT_EMAIL_DOMAIN="${AGENT_EMAIL_DOMAIN:-agents.example.com}"
export DATABASE_URL
export AGENTOS_MASTER_KEY="$MASTER_KEY"
export APP_BIND="127.0.0.1:$PORT"
export AGENTOS_ALLOW_MOCKS=1
export AGENTOS_LLM=cli
export AGENTOS_API_KEYS="ops:$TENANT_ID:$CLE_OPS,approbateur:$TENANT_ID:$CLE_APPROBATEUR"
export RUST_LOG="${RUST_LOG:-info,agentos_server=debug}"
if [ -n "$CHROME_URL" ]; then export BROWSER_CDP_URL="$CHROME_URL"; fi
[ "$REEL" = 1 ] || unset EMAIL_API_KEY EMAIL_API_BASE
# La clé de plate-forme n'existe QUE sous `--recevoir`. C'est la seule qui peut
# écrire `webhook_endpoints` — aucune clé de locataire ne le peut, et c'est
# délibéré : un locataire qui écrirait sa propre ligne pourrait nommer un chemin
# et se mettre à ramasser le courrier d'un autre.
if [ "$RECEVOIR" = 1 ]; then export AGENTOS_PLATFORM_KEYS="ce-soir:$CLE_PLATEFORME"; fi

dit "démarrage du serveur (il applique les migrations lui-même)…"
"$BIN" >"$JOURNAL" 2>&1 &
echo $! > "$PIDFILE"
SERVEUR=$(cat "$PIDFILE")

attendre() { # url, secondes, quoi
  local fin=$((SECONDS + $2))
  until curl -fsS -o /dev/null "$1" 2>/dev/null; do
    kill -0 "$SERVEUR" 2>/dev/null || { echo; tail -20 "$JOURNAL" >&2; refuse "le serveur est mort au démarrage. Journal complet : $JOURNAL"; }
    [ $SECONDS -lt "$fin" ] || { echo; tail -20 "$JOURNAL" >&2; refuse "$3 n'est pas venu en $2 s. Journal : $JOURNAL"; }
    printf .; sleep 1
  done; echo
}
attendre "http://127.0.0.1:$PORT/livez" 60 "le serveur"
dit "serveur vivant, pid $SERVEUR, journal $JOURNAL"

# Le locataire. `new-tenant` crée, il n'adopte pas : une seconde exécution dit
# « existe déjà », et c'est exactement ce qu'on veut entendre.
if "$BIN" policy new-tenant siglair "Siglair" --id "$TENANT_ID" >/dev/null 2>&1; then
  dit "locataire $TENANT_ID créé."
else
  dit "locataire $TENANT_ID : déjà là."
fi

# Le plafond. Hors de portée d'un terminal MCP — aucune route ne l'écrit — donc
# c'est ici et nulle part ailleurs. Sans lui la grille est fermée et CHAQUE
# action est refusée en `no_platform_policy`.
dit "$("$BIN" policy install | head -1)"

attendre "http://127.0.0.1:$PORT/readyz" 30 "/readyz"
dit "prêt."

MOCKS="$(grep -o 'mock_adapters[^]]*]' "$JOURNAL" | tail -1 || true)"
if [ -n "$MOCKS" ]; then dit "faux adaptateurs : ${MOCKS#*: }"; fi

# ---------------------------------------------------------------------------
# La porte d'entrée du courrier, par la vraie route
# ---------------------------------------------------------------------------
#
# `POST /v1/platform/webhooks` est le seul chemin qui écrive `webhook_endpoints`
# (0053), et il rend un chemin OPAQUE — pas `/{locataire}/{fournisseur}` — parce
# qu'une adresse devinable est une adresse qu'on sonde. Rejouer la même
# inscription fait tourner le secret et GARDE le chemin, donc relancer ce script
# ne change pas l'URL à coller ; c'est le tunnel qui la change.
ROUTE_WEBHOOK=""
if [ "$RECEVOIR" = 1 ]; then
  REPONSE="$(curl -fsS -X POST "http://127.0.0.1:$PORT/v1/platform/webhooks" \
    -H "Authorization: Bearer $CLE_PLATEFORME" \
    -H 'Content-Type: application/json' \
    -d "{\"tenant_id\":\"$TENANT_ID\",\"provider\":\"email\",\"secret\":\"$SECRET_WEBHOOK\"}")" \
    || refuse "l'inscription du webhook a échoué. Journal : $JOURNAL"
  ROUTE_WEBHOOK="$(printf '%s' "$REPONSE" | sed -n 's/.*"route":"\([^"]*\)".*/\1/p')"
  [ -n "$ROUTE_WEBHOOK" ] || refuse "la route du webhook n'était pas dans la réponse : $REPONSE"
  dit "porte d'entrée enregistrée : $ROUTE_WEBHOOK"

  # Et on la traverse, parce qu'un tunnel qu'on n'a pas franchi est une adresse
  # qu'on a lue dans un journal.
  attendre "$PUBLIC/livez" 30 "le tunnel"
  dit "le tunnel passe : $PUBLIC/livez répond."
fi

cat <<FIN_MSG

────────────────────────────────────────────────────────────────────────────
 L'instance tourne. Colle ceci dans ton terminal :

   claude mcp add --transport http siglair http://127.0.0.1:$PORT/v1/mcp/server \\
     --header "Authorization: Bearer $CLE_OPS"

 Puis, dans Claude Code : /mcp doit montrer « siglair » connecté.

 Le premier geste est model_connect {"path":"cli"} — il prouve ton propre
 claude, ne stocke rien, et sans lui aucun siège ne prend de tour.
 Ensuite : company_create (la société, ses rôles et sa fenêtre — c'est LUI
 qui pose la première couche de limites ; org_apply n'en pose aucune et le
 geste suivant tomberait sur un 404). Puis le geste lancer-une-campagne.

 La clé qui approuve (une autre, sinon les quatre yeux refusent sur soi) :
   $CLE_APPROBATEUR

 Arrêter : scripts/ce-soir.sh --arreter
 Tout jeter : scripts/ce-soir.sh --effacer
────────────────────────────────────────────────────────────────────────────
FIN_MSG

if [ "$RECEVOIR" = 1 ]; then
  cat <<FIN_RECEVOIR
 À coller dans le tableau de bord Resend (Webhooks → Add endpoint) :

   URL     $PUBLIC$ROUTE_WEBHOOK
   Secret  $SECRET_WEBHOOK

 L'adresse du tunnel CHANGE à chaque lancement de ce script : c'est ce que
 coûte un tunnel rapide, qui ne demande ni compte ni carte. Le secret, lui,
 ne change pas — il est dans $SECRETS — donc seule l'URL est à recoller.
 Pour une adresse stable il faudrait un tunnel NOMMÉ, donc ton compte
 Cloudflare et un « cloudflared login » ; ce script ne le fait pas.

 La signature EST vérifiée sur ce chemin : schéma Standard Webhooks (celui
 de Resend), HMAC sur « id.horodatage.corps », fenêtre de rejeu comprise, et
 une livraison non signée est un 401 avant qu'une ligne soit écrite. Le
 tunnel est public ; la porte ne l'est pas.
────────────────────────────────────────────────────────────────────────────
FIN_RECEVOIR
fi

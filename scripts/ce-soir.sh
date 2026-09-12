#!/usr/bin/env bash
#
# Monter l'instance complète sur la machine du fondateur, en une commande.
#
# Ce que ce script fait, et où il s'arrête : il pose l'INFRASTRUCTURE — la base,
# les migrations (par le serveur, à son démarrage), le locataire, le plafond de
# politique, le serveur, la clé. Il ne crée NI la société NI le premier siège :
# c'est le geste que le fondateur veut faire depuis son terminal, et le lui
# voler lui retire la démonstration.
#
# Le modèle est le `claude` de cette machine (AGENTOS_LLM=cli). Rien n'est
# intermédié : pas de jeton collecté, pas de session stockée, pas de binaire
# modifié. Voir docs/CE_SOIR.md pour pourquoi c'est légal ici et pas sur le VPS.
#
# Relancer ce script ne casse rien : la base, le locataire, le plafond et les
# clés sont retrouvés plutôt que recréés.
#
#   scripts/ce-soir.sh            faux adaptateurs — rien ne part vraiment
#   scripts/ce-soir.sh --reel     e-mail réel via Resend (demande confirmation)
#   scripts/ce-soir.sh --arreter  arrête le serveur lancé par ce script
#   scripts/ce-soir.sh --effacer  arrête, puis supprime la base et l'état

set -euo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ETAT="${AGENTOS_CE_SOIR_ETAT:-$HOME/.agentos-ce-soir}"
PORT="${PORT:-8787}"
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

REEL=0
ACTION=monter
for arg in "$@"; do
  case "$arg" in
    --reel) REEL=1 ;;
    --arreter) ACTION=arreter ;;
    --effacer) ACTION=effacer ;;
    -h|--help) sed -n '3,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "je ne connais pas « $arg ». --reel, --arreter, --effacer, --help." >&2; exit 2 ;;
  esac
done

dit()    { printf '\033[1m==\033[0m %s\n' "$*"; }
refuse() { printf '\033[1;31m== REFUS\033[0m %s\n' "$*" >&2; exit 1; }

PIDFILE="$ETAT/serveur.pid"
JOURNAL="$ETAT/serveur.log"

arreter() {
  [ -f "$PIDFILE" ] || { dit "aucun serveur lancé par ce script."; return 0; }
  local pid; pid="$(cat "$PIDFILE")"
  # Par le pid, jamais pkill : d'autres agents et d'autres serveurs tournent.
  if kill -0 "$pid" 2>/dev/null; then kill "$pid"; dit "serveur $pid arrêté."
  else dit "le pid $pid ne tourne plus."; fi
  rm -f "$PIDFILE"
}

case "$ACTION" in
  arreter) arreter; exit 0 ;;
  effacer)
    arreter
    dropdb --if-exists -h "$PGHOST" -p "$PGPORT" "$BASE_NOM" && dit "base $BASE_NOM supprimée."
    rm -rf "$ETAT" && dit "état $ETAT effacé."
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

mkdir -p "$ETAT"; chmod 700 "$ETAT"

if [ "$REEL" = 1 ]; then
  [ -n "${EMAIL_API_KEY:-}" ] \
    || refuse "--reel sans EMAIL_API_KEY. Exporte la clé Resend d'abord ; sans elle l'adaptateur reste faux et --reel ne veut rien dire."
  [ -n "${AGENT_EMAIL_DOMAIN:-}" ] \
    || refuse "--reel sans AGENT_EMAIL_DOMAIN. Nomme le domaine d'envoi vérifié chez Resend ; le faux domaine par défaut ferait refuser chaque envoi par Resend."
  cat >&2 <<'AVERT'

  ┌─ --reel : ce que tu viens de demander ───────────────────────────────────┐
  │ L'adaptateur e-mail devient Resend. Un siège qui prend un tour et décide │
  │ d'écrire ENVERRA un vrai e-mail, à une vraie adresse, depuis ton domaine │
  │ vérifié, et ça compte sur ta réputation d'envoi. Il n'y a pas de mode    │
  │ « presque ». Le téléphone, le navigateur et l'embedder restent faux.     │
  └──────────────────────────────────────────────────────────────────────────┘

AVERT
  printf '  tape OUI pour continuer : ' >&2
  read -r reponse
  [ "$reponse" = "OUI" ] || refuse "annulé. Relance sans --reel pour la marche à blanc."
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
# le téléphone, le navigateur et l'embedder n'ont pas de clé sur cette machine :
# sans lui le serveur REFUSE de démarrer, et il a raison — un faux adaptateur en
# production est une panne qui rend un succès.
export PUBLIC_HOST="http://127.0.0.1:$PORT"
export AGENT_EMAIL_DOMAIN="${AGENT_EMAIL_DOMAIN:-agents.example.com}"
export DATABASE_URL
export AGENTOS_MASTER_KEY="$MASTER_KEY"
export APP_BIND="127.0.0.1:$PORT"
export AGENTOS_ALLOW_MOCKS=1
export AGENTOS_LLM=cli
export AGENTOS_API_KEYS="ops:$TENANT_ID:$CLE_OPS,approbateur:$TENANT_ID:$CLE_APPROBATEUR"
export RUST_LOG="${RUST_LOG:-info,agentos_server=debug}"
[ "$REEL" = 1 ] || unset EMAIL_API_KEY

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
[ -n "$MOCKS" ] && dit "faux adaptateurs : ${MOCKS#*: }"

cat <<FIN_MSG

────────────────────────────────────────────────────────────────────────────
 L'instance tourne. Colle ceci dans ton terminal :

   claude mcp add --transport http siglair http://127.0.0.1:$PORT/v1/mcp/server \\
     --header "Authorization: Bearer $CLE_OPS"

 Puis, dans Claude Code : /mcp doit montrer « siglair » connecté.

 Le premier geste est model_connect {"path":"cli"} — il prouve ton propre
 claude, ne stocke rien, et sans lui aucun siège ne prend de tour.
 Ensuite : org_apply (la société), puis le geste lancer-une-campagne.

 La clé qui approuve (une autre, sinon les quatre yeux refusent sur soi) :
   $CLE_APPROBATEUR

 Arrêter : scripts/ce-soir.sh --arreter
 Tout jeter : scripts/ce-soir.sh --effacer
────────────────────────────────────────────────────────────────────────────
FIN_MSG

#!/bin/bash
# Les inscrits du site (visa.orizn.app, table visa_api_users sur le serveur du
# site) entrent dans le CRM de la machine, une fois par jour : ce sont les
# seules personnes qui ont déjà dit oui au produit, et personne ne leur
# écrivait (1 751 comptes le 2026-09-28, 12 payants). Quatre viviers, par
# `origin_ref` :
#   site-inscrits · quota   — gratuit, ≥ 80 requêtes ce mois  → montee-en-gamme
#   site-inscrits · actif   — gratuit, connecté sous 30 j ou ≥ 10 requêtes → accueil-gratuit
#   site-inscrits           — gratuit, dormant (rien pour l'instant)
#   site-inscrits · payant  — abonné (Stripe fait le reste ; pas de nourrissage)
# L'import est idempotent (un contact existant est « existing », pas recréé) ;
# la base légale est `contract` (ils ont créé un compte).
# ponytail: un ssh + un psql + l'import CSV existant ; pas de webhook côté
# site, pas de table de plus. Tourne depuis la veille de ce-soir.sh.
set -euo pipefail
ETAT="${AGENTOS_ETAT:-$HOME/.agentos-ce-soir}"
SERVER="${SITE_SERVER:-root@204.168.244.123}"
API="${AGENTOS_API:-http://127.0.0.1:8787}"
. "$ETAT/secrets.env"
: "${CLE_OPS:?CLE_OPS manque dans $ETAT/secrets.env}"

cat > /tmp/inscrits.sql <<'SQL'
select id, email, coalesce(name,''), coalesce(company,''), plan, requests_month, requests_total,
       coalesce(last_login_at::text,''), created_at::date, email_verified,
       coalesce(stripe_customer_id,''), coalesce(acquisition_channel,'')
  from visa_api_users where email is not null and email <> '' and active;
-- Les comptes désactivés sur le site (mailinator, ferme w8sojib3…) : le
-- script les désactive aussi dans le CRM, l'import ne retouchant jamais un
-- contact existant.
select 'inactif', lower(email) from visa_api_users where not active and email is not null;
SQL
scp -q /tmp/inscrits.sql "$SERVER:/tmp/inscrits.sql"
ssh -o BatchMode=yes "$SERVER" 'docker exec -i backend-postgres-1 sh -c "PGPASSWORD=\$POSTGRES_PASSWORD psql -At -F \"|\" -U \$POSTGRES_USER -d wandr_spots" < /tmp/inscrits.sql; rm -f /tmp/inscrits.sql' \
  > "$ETAT/site-inscrits.psv"
rm -f /tmp/inscrits.sql
chmod 600 "$ETAT/site-inscrits.psv"

python3 "$(dirname "$0")/site-inscrits.py" "$ETAT/site-inscrits.psv" "$ETAT"
chmod 600 "$ETAT"/site-*.csv "$ETAT/site-inactifs.txt"

for k in quota actif dormant payant; do
  src="site-inscrits"; [ "$k" != dormant ] && src="site-inscrits · $k"
  enc=$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$src")
  curl -sS -X POST "$API/v1/prospects/import?segment=other&country=ZZ&dry_run=${DRY_RUN:-false}&source=$enc" \
    -H "Authorization: Bearer $CLE_OPS" -H 'content-type: text/csv' --data-binary @"$ETAT/site-$k.csv" \
    | python3 -c "import sys,json; j=json.loads(sys.stdin.read(),strict=False); c=j['contacts']; print('$k: créés', c['created'], '| déjà là', c['existing'], '| erreurs', len(j.get('errors') or []))"
done
# Un inscrit déjà en base qui est passé payant depuis change de vivier : l'import
# ne retouche pas un contact existant (Evan, gratuit le 28/09, Commercial le 14/10).
python3 - "$ETAT/site-payant.csv" <<'PY' | PGPORT="${PGPORT:-5432}" psql -d "${DB_NAME:-agentos_ce_soir}" -Atq
import csv,sys
mails=[r['email'].strip().lower() for r in csv.DictReader(open(sys.argv[1])) if r.get('email')]
if mails: print("update contacts set origin_ref='site-inscrits · payant' where lower(email) in (" + ",".join("'"+m.replace("'","''")+"'" for m in mails) + ") and origin_ref like 'site-inscrits%' and origin_ref <> 'site-inscrits · payant';")
PY
# Un compte désactivé sur le site l'est aussi dans le CRM : un contact inactif
# n'est plus jamais réclamé par une séquence (garde `active` de mark_contacted).
[ "${DRY_RUN:-false}" = true ] || python3 - "$ETAT/site-inactifs.txt" <<'PY' | PGPORT="${PGPORT:-5432}" psql -d "${DB_NAME:-agentos_ce_soir}" -Atq
import sys
mails=[m.strip() for m in open(sys.argv[1]) if m.strip()]
if mails: print("update contacts set active=false, updated_at=now() where lower(email) in (" + ",".join("'"+m.replace("'","''")+"'" for m in mails) + ") and origin_ref like 'site-inscrits%' and active;")
PY
# La base légale des inscrits est le contrat ; l'import pose « intérêt légitime ».
PGPORT="${PGPORT:-5432}" psql -d "${DB_NAME:-agentos_ce_soir}" -Atc \
  "update contacts set lawful_basis='contract' where origin_ref like 'site-inscrits%' and lawful_basis <> 'contract'" >/dev/null
echo "synchro des inscrits faite ($(date -u +%FT%TZ))"

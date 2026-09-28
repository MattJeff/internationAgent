#!/bin/bash
# Les inscrits du site (visa.orizn.app, table visa_api_users sur le serveur du
# site) entrent dans le CRM de la machine, une fois par jour : ce sont les
# seules personnes qui ont déjà dit oui au produit, et personne ne leur
# écrivait (1 751 comptes le 2026-09-28, 12 payants). Quatre viviers, par
# `origin_ref` :
#   site-inscrits · quota   — gratuit, ≥ 50 requêtes ce mois  → montee-en-gamme
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
  from visa_api_users where email is not null and email <> '';
SQL
scp -q /tmp/inscrits.sql "$SERVER:/tmp/inscrits.sql"
ssh -o BatchMode=yes "$SERVER" 'docker exec -i backend-postgres-1 sh -c "PGPASSWORD=\$POSTGRES_PASSWORD psql -At -F \"|\" -U \$POSTGRES_USER -d wandr_spots" < /tmp/inscrits.sql; rm -f /tmp/inscrits.sql' \
  > "$ETAT/site-inscrits.psv"
rm -f /tmp/inscrits.sql
chmod 600 "$ETAT/site-inscrits.psv"

python3 - "$ETAT/site-inscrits.psv" "$ETAT" <<'PY'
import sys, csv, re
from datetime import datetime, timedelta
src, out = sys.argv[1], sys.argv[2]
consumer = {'gmail.com','qq.com','163.com','126.com','yahoo.com','hotmail.com','outlook.com','icloud.com','proton.me','protonmail.com','live.com','yandex.ru','mail.ru','foxmail.com','gmx.de','web.de','me.com','aol.com','msn.com','hotmail.fr','yahoo.fr','orange.fr','free.fr','wanadoo.fr','laposte.net','sfr.fr'}
now = datetime.utcnow()
rows = {'quota':[], 'actif':[], 'dormant':[], 'payant':[]}
for line in open(src, encoding='utf-8', errors='replace'):
    p = line.rstrip('\n').split('|')
    if len(p) < 12: continue
    uid, email, name, company, plan, rm, rt, last_login, created, verified, stripe, chan = p[:12]
    email = email.strip().lower()
    if not re.match(r'^[^@\s]+@[^@\s]+\.[a-z]{2,}$', email) or email.endswith('@example.com'): continue
    dom = email.split('@')[1]
    first, last = (name.strip().split(' ',1)+[''])[:2] if name.strip() else ('','')
    comp = company.strip() or (dom if dom not in consumer else (name.strip() or email.split('@')[0]))
    try: ll = datetime.fromisoformat(last_login[:19]) if last_login else None
    except ValueError: ll = None
    rec = [email, first[:60], last[:60], comp[:120], '', ('https://'+dom) if dom not in consumer else '', '', '']
    if plan != 'free': rows['payant'].append(rec)
    elif int(rm or 0) >= 50: rows['quota'].append(rec)
    elif (ll and ll >= now - timedelta(days=30)) or int(rt or 0) >= 10: rows['actif'].append(rec)
    else: rows['dormant'].append(rec)
for k, v in rows.items():
    with open(f'{out}/site-{k}.csv','w', newline='', encoding='utf-8') as f:
        w = csv.writer(f); w.writerow(['email','first_name','last_name','company_name','phone_number','website','linkedin_profile','location']); w.writerows(v)
    print(f'{k} {len(v)}')
PY
chmod 600 "$ETAT"/site-*.csv

for k in quota actif dormant payant; do
  src="site-inscrits"; [ "$k" != dormant ] && src="site-inscrits · $k"
  enc=$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$src")
  curl -sS -X POST "$API/v1/prospects/import?segment=other&country=ZZ&dry_run=${DRY_RUN:-false}&source=$enc" \
    -H "Authorization: Bearer $CLE_OPS" -H 'content-type: text/csv' --data-binary @"$ETAT/site-$k.csv" \
    | python3 -c "import sys,json; j=json.loads(sys.stdin.read(),strict=False); c=j['contacts']; print('$k: créés', c['created'], '| déjà là', c['existing'], '| erreurs', len(j.get('errors') or []))"
done
# La base légale des inscrits est le contrat ; l'import pose « intérêt légitime ».
PGPORT="${PGPORT:-5432}" psql -d "${DB_NAME:-agentos_ce_soir}" -Atc \
  "update contacts set lawful_basis='contract' where origin_ref like 'site-inscrits%' and lawful_basis <> 'contract'" >/dev/null
echo "synchro des inscrits faite ($(date -u +%FT%TZ))"

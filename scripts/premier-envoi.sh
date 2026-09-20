#!/bin/sh
# Le premier vrai e-mail, vers UNE adresse nommée par un humain.
#
# Ne fait rien d'autre : un contact, une séquence d'un seul pas, une
# inscription. Le siège écrit lui-même le texte au tour suivant, et l'envoi
# passe la Gate comme n'importe quel autre. Volontairement sans `OUI` : le
# `OUI` a déjà été tapé au lancement de l'instance, et le redemander pour
# chaque geste apprendrait à ne plus le lire.
set -eu

[ $# -eq 1 ] || { echo "usage: $0 <adresse@destinataire>" >&2; exit 2; }
DEST="$1"
B=http://127.0.0.1:8787
. "$HOME/.agentos-ce-soir/secrets.env"
H="Authorization: Bearer $CLE_OPS"
SDR=01a0b894-790d-743f-adf1-90f635a5f1aa

echo "== le contact"
printf 'email,first_name,last_name,company_name,phone_number,website,linkedin_profile,location\n%s,Mathis,Higuinen,Orizn,,https://orizn.app,,France\n' "$DEST" \
  | curl -fsS -X POST "$B/v1/prospects/import?segment=other&country=FR&dry_run=false&source=premier-envoi" \
      -H "$H" -H 'Content-Type: text/csv' --data-binary @- \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print("   contacts créés", d["contacts"]["created"], "| déjà là", d["contacts"]["existing"], "| écartés", d["contacts"]["skipped"])'

CID="$(curl -fsS -H "$H" "$B/v1/contacts?email=$DEST" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["contacts"][0]["id"])')"
echo "   contact $CID"

echo "== la séquence, un seul pas"
NOM="premier-envoi-$(date +%s)"
SID="$(curl -fsS -X POST "$B/v1/sequences" -H "$H" -H 'Content-Type: application/json' \
  -d "{\"name\":\"$NOM\",\"steps\":[{\"kind\":\"email\",\"brief\":\"Le tout premier message que cette société envoie pour de vrai. Se présenter en une phrase comme le siège SDR d'Orizn, dire que ce message prouve la chaîne d'envoi de bout en bout, ne rien demander et ne rien promettre. Trois phrases au plus.\"}]}" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
echo "   séquence $SID"

echo "== l'inscription"
curl -fsS -X POST "$B/v1/sequences/$SID/enroll" -H "$H" -H 'Content-Type: application/json' \
  -d "{\"contact_id\":\"$CID\",\"employee_id\":\"$SDR\"}"
echo

cat <<FIN

  Inscrit. Le siège est réveillé au prochain tour et écrit le message.
  Suivre :
    psql "postgresql://postgres:postgres@localhost:5432/agentos_ce_soir" \\
      -Atc "select direction,sender,recipients,left(body,120) from messages order by created_at desc limit 3"
FIN

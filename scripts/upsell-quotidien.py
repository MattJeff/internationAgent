#!/usr/bin/env python3
"""Montée en gamme Orizn, une fois par jour : repère les inscrits qui viennent de
montrer un vrai besoin (premier refus de quota, intégration qui tourne, paiement
abandonné), lit leur site, fait écrire par `claude -p` un mail fondé sur ces seuls
faits, le rend dans la mise en page des vagues manuelles du 12/11 et l'envoie
par Resend. Lancé par la veille (scripts/ce-soir.sh) après la synchro des inscrits.

  DRY_RUN=true scripts/upsell-quotidien.py   -> aperçus dans $ETAT/upsell/apercu, rien n'est envoyé
  scripts/upsell-quotidien.py                -> envoi réel, au plus MAX_PAR_JOUR mails

Ne réécrit jamais à une adresse déjà écrite par une vague (vagues/upsell-1112/envoyes.jsonl)
ou par ce script depuis 30 jours, ni à une adresse supprimée dans le CRM.
"""
import html, json, os, pathlib, re, subprocess, sys, time, urllib.request, urllib.error
from datetime import datetime, timedelta, timezone

ETAT = pathlib.Path(os.environ.get("AGENTOS_ETAT", pathlib.Path.home() / ".agentos-ce-soir"))
DIR = ETAT / "upsell"; DIR.mkdir(exist_ok=True)
JOURNAL = DIR / "envoyes.jsonl"
VAGUES = ETAT / "vagues/upsell-1112/envoyes.jsonl"
SERVER = os.environ.get("SITE_SERVER", "root@204.168.244.123")
DRY = os.environ.get("DRY_RUN", "false") == "true"
MAX_PAR_JOUR = int(os.environ.get("UPSELL_MAX", "6"))
STARTER = "https://visa.orizn.app/visa-api/dashboard/billing?plan=starter"
PRO = "https://visa.orizn.app/visa-api/dashboard/billing?plan=pro"
DOCS = "https://visa.orizn.app/visa-api/docs"
INK, BRASS, MUTED, RULE = "#141517", "#b08d57", "#5b5e66", "#e4e4e7"
FREEMAIL = re.compile(r"@(gmail|googlemail|outlook|hotmail|live|yahoo|icloud|me|proton|protonmail|qq|163|126|foxmail|mail|yandex|gmx|aol)\.", re.I)

SQL = r"""
with u as (
  select u.id, lower(u.email) email, coalesce(u.name,'') name, coalesce(u.company,'') company, u.plan, u.created_at::date created
  from visa_api_users u
  where u.active and u.plan = 'free' and coalesce(u.name,'') <> 'w8sojib3'
    and u.email not ilike '%mailinator%' and u.email not ilike '%@orizn.app' and u.email not ilike '%@example.com'),
s as (
  select u.*,
    count(l.*) filter (where l.status_code < 400) ok,
    count(l.*) filter (where l.status_code = 429) refus,
    min(l.created_at) filter (where l.status_code = 429) premier_refus,
    count(distinct l.created_at::date) jours,
    count(distinct l.created_at::date) filter (where l.created_at > now() - interval '14 days') jours14,
    max(l.created_at)::date dernier,
    string_agg(distinct left(coalesce(l.user_agent,''), 70), ' ; ') ua,
    string_agg(distinct l.endpoint, ' ') ep
  from u left join visa_api_logs l on l.user_id = u.id group by u.id, u.email, u.name, u.company, u.plan, u.created)
select json_agg(row_to_json(t)) from (
  select s.*, (s.premier_refus > now() - interval '48 hours') nouveau_refus,
    (select string_agg(x, ' ') from (select distinct coalesce(l2.passport_iso3,'')||'>'||coalesce(l2.destination_iso3,'') x
       from visa_api_logs l2 where l2.user_id = s.id and l2.status_code < 400 order by 1 limit 30) z) paires,
    (select string_agg(coalesce(v.building,'')||' / '||coalesce(v.previous,'')||' / '||coalesce(v.source,''), ' ; ')
       from visa_onboarding_survey v where v.api_user_id = s.id) questionnaire,
    (select max(f.created_at)::date from visa_payment_funnel_events f where f.api_user_id = s.id and f.event = 'checkout_created'
       and f.created_at > now() - interval '72 hours'
       and not exists (select 1 from visa_payment_funnel_events g where g.api_user_id = s.id and g.event = 'checkout_completed' and g.created_at >= f.created_at)) paiement_abandonne
  from s
  where (s.premier_refus > now() - interval '48 hours')
     or (s.jours14 >= 3 and s.ok >= 10)
     or exists (select 1 from visa_payment_funnel_events f where f.api_user_id = s.id and f.event = 'checkout_created' and f.created_at > now() - interval '72 hours')
  order by s.refus desc, s.jours14 desc, s.ok desc limit 40) t;
"""


def psql(sql):
    r = subprocess.run(["ssh", "-o", "BatchMode=yes", SERVER,
                        'docker exec -i backend-postgres-1 sh -c "PGPASSWORD=\\$POSTGRES_PASSWORD psql -At -U \\$POSTGRES_USER -d wandr_spots"'],
                       input=sql, capture_output=True, text=True, timeout=120, check=True)
    return r.stdout.strip()


def deja_ecrits():
    vus, limite = set(), datetime.now(timezone.utc) - timedelta(days=30)
    if VAGUES.exists():
        vus |= {json.loads(l)["to"] for l in open(VAGUES)}
    if JOURNAL.exists():
        for l in open(JOURNAL):
            d = json.loads(l)
            if datetime.fromisoformat(d["at"]) > limite:
                vus.add(d["to"])
    return vus


def supprimes(adresses):
    if not adresses:
        return set()
    liste = ",".join("'" + a.replace("'", "''") + "'" for a in adresses)
    r = subprocess.run(["psql", "-At", "-d", os.environ.get("DB_NAME", "agentos_ce_soir"), "-c",
                        f"select lower(address) from suppressions where lower(address) in ({liste})"],
                       capture_output=True, text=True, check=True, env={**os.environ, "PGPORT": os.environ.get("PGPORT", "5432")})  # ponytail: échoue fort, jamais d'envoi sans la liste des refus
    return set(r.stdout.split())


def site(email):
    if FREEMAIL.search(email):
        return ""
    dom = email.split("@")[1].split("+")[0]
    try:
        req = urllib.request.Request(f"https://{dom}", headers={"User-Agent": "Mozilla/5.0"})
        t = urllib.request.urlopen(req, timeout=12).read(400_000).decode("utf-8", "ignore")
    except Exception:
        return ""
    monnaie = bool(re.search(r"adsbygoogle|googlesyndication|affiliate|utm_source=|pricing|checkout|/cart|book now", t, re.I))
    t = re.sub(r"(?s)<(script|style|noscript|svg).*?</\1>", " ", t)
    t = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", t)))[:1500]
    return f"{t}\n[signaux de revenu dans le code de la page : {'oui' if monnaie else 'aucun vu'}]"


EXEMPLE = {"lang": "en", "subject": "Visa answers for Akakpos1 Travel & Tours", "hi": "Hi Anthony,",
           "paras": ["Akakpos1 sells tour packages, visa services and corporate travel, and your tests show it: Nigerian passports to the UAE, Barbados, Canada, Germany, France, the UK and Ghana.",
                     "Using Orizn for your clients is commercial use, which the free plan doesn’t cover. Commercial gives your team 30,000 answers a month, each with the required documents and the official government page."],
           "cta": "Switch to Commercial", "after": "Reply with the ten routes you sell most and I’ll send the full answers for a Nigerian passport.", "plan": "starter"}

CONSIGNE = """Tu écris, au nom de Mathis Higuinen (fondateur d'Orizn, API des conditions de visa), UN mail court à un inscrit qui vient de montrer un vrai besoin.
Faits sur Orizn (n'en invente aucun autre) : 49 750 paires passeport×destination, 199 passeports, 15 langues (ar de en es fr hi it ja ko pt ru th tl vi zh) ; chaque réponse donne exigence, durée, coût, documents, page officielle (source_url) et last_verified_at.
Plans : Evaluation gratuit, 100 requêtes/mois, usage NON commercial ; Commercial 149 $/mois, 30 000 requêtes/mois, droit de servir des utilisateurs payants ; Production 499 $/mois, 250 000 requêtes, endpoint bulk et webhook ; License dès 1 500 $/mois pour redistribuer les données.
Règles :
- N'utilise QUE les faits du dossier ci-dessous (paires, jours d'usage, refus 429, identifiant d'appel, questionnaire, site). Cite-en deux ou trois précis : c'est ce qui rend le mail personnel.
- N'affirme JAMAIS que l'usage est commercial sans preuve dans le dossier (site d'entreprise qui vend, liens d'affiliation, outil interne d'entreprise, produit nommé). Sans preuve, dis « si ce que vous construisez sert à d'autres / à des utilisateurs payants ».
- Ne promets rien que le fondateur n'a pas promis : pas de remise, pas de rappel téléphonique, pas de délai inventé. Tu peux proposer de vérifier à la main des paires qu'on t'envoie.
- Paiement abandonné : demande simplement ce qui a bloqué, rappelle que rien n'a été prélevé.
- plan = "pro" seulement si l'usage montre du volume (milliers de requêtes, endpoint bulk, tout un passeport contre toutes les destinations) ; sinon "starter".
- Langue : chinois simplifié (zh) si les signaux sont chinois (adresse qq/163/126/foxmail, passeport CHN dominant) ; français (fr) si francophone évident ; sinon anglais (en).
- Ton : direct, chaleureux, sans formule creuse, sans « I hope this email finds you well », sans tiret long en série, sans emoji. 2 ou 3 paragraphes de 1 à 3 phrases. Pas de signature (ajoutée après).
- skip = true si le dossier ne montre en fait aucun besoin réel (seulement la démo FRA>JPN, ou compte de test, ou concurrent évident).
Réponds UNIQUEMENT par un objet JSON : {"skip": bool, "raison": str, "lang": "en|fr|zh", "subject": str, "hi": str, "paras": [str], "cta": str, "after": str, "plan": "starter|pro"}.
Exemple de ton et de forme :
""" + json.dumps(EXEMPLE, ensure_ascii=False)


def rediger(dossier):
    r = subprocess.run(["claude", "-p", CONSIGNE + "\n\nDossier :\n" + json.dumps(dossier, ensure_ascii=False, default=str),
                        "--output-format", "json", "--model", os.environ.get("UPSELL_MODEL", "claude-opus-5-5")],
                       capture_output=True, text=True, timeout=300)
    sortie = json.loads(r.stdout)
    if isinstance(sortie, list):  # certaines versions de la CLI rendent la liste des événements
        sortie = next(x for x in sortie if x.get("type") == "result")
    texte = sortie["result"]
    return json.loads(texte[texte.index("{"): texte.rindex("}") + 1])


SIG = {"en": "Mathis Higuinen, founder of Orizn", "zh": "Mathis Higuinen，Orizn 创始人", "fr": "Mathis Higuinen, fondateur d’Orizn"}
FOOT = {"en": "You get this because you created an Orizn API key. Reply “stop” and I won’t write again.",
        "zh": "您收到此邮件是因为您创建了 Orizn API 密钥。回复“stop”即不再收到。",
        "fr": "Vous recevez ce mail parce que vous avez créé une clé API Orizn. Répondez « stop » et je ne vous écrirai plus."}


def rendre(m, url):
    e = html.escape
    p = "".join(f'<p style="margin:0 0 16px">{e(x)}</p>' for x in m["paras"])
    return f"""<!doctype html><html lang="{m['lang']}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light only"><meta name="supported-color-schemes" content="light"><title>{e(m['subject'])}</title></head>
<body style="margin:0;padding:0;background:#ffffff">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#ffffff"><tr><td align="center" style="padding:32px 16px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;font-family:Inter,Helvetica,Arial,sans-serif;font-size:16px;line-height:1.6;color:{INK}">
<tr><td style="padding:0 0 24px;border-bottom:1px solid {RULE}"><span style="font-family:'Instrument Serif',Georgia,'Times New Roman',serif;font-size:26px;letter-spacing:-0.3px;color:{INK}">Orizn</span><span style="display:inline-block;width:18px;height:2px;background:{BRASS};margin-left:8px;vertical-align:middle"></span></td></tr>
<tr><td style="padding:28px 0 0">
<p style="margin:0 0 16px">{e(m['hi'])}</p>{p}
<table role="presentation" cellpadding="0" cellspacing="0" style="margin:8px 0 24px"><tr><td style="background:{INK};border-radius:6px;border-bottom:3px solid {BRASS}">
<a href="{url}" style="display:inline-block;padding:13px 26px;font-weight:600;font-size:15px;color:#ffffff;text-decoration:none">{e(m['cta'])} &rarr;</a></td></tr></table>
<p style="margin:0 0 24px">{e(m['after'])}</p>
<p style="margin:0;color:{INK}">{e(SIG[m['lang']])}</p>
<p style="margin:2px 0 0;font-size:14px;color:{MUTED}">WhatsApp +33 6 74 57 86 68 · <a href="https://linkedin.com/in/mathis-higuinen" style="color:{BRASS}">LinkedIn</a> · <a href="{DOCS}" style="color:{BRASS}">Docs</a></p>
</td></tr>
<tr><td style="padding:28px 0 0;font-size:12px;color:{MUTED};border-top:1px solid {RULE}">{e(FOOT[m['lang']])}</td></tr>
</table></td></tr></table></body></html>"""


def texte(m, url):
    return "\n\n".join([m["hi"], *m["paras"], f"{m['cta']}: {url}", m["after"], SIG[m["lang"]], "WhatsApp +33 6 74 57 86 68 · linkedin.com/in/mathis-higuinen", FOOT[m["lang"]]])


def envoyer(to, m, html_, txt):
    body = json.dumps({"from": "Mathis Higuinen <support@agents.getorizn.com>", "to": [to], "reply_to": "support@agents.getorizn.com",
                       "subject": m["subject"], "html": html_, "text": txt}).encode()
    req = urllib.request.Request("https://api.resend.com/emails", body, {"Authorization": f"Bearer {os.environ['EMAIL_API_KEY']}",
                                 "Content-Type": "application/json", "Idempotency-Key": f"upsell-auto-{to}-{datetime.now(timezone.utc):%Y%m%d}",
                                 "User-Agent": "orizn-mailer"})
    return json.load(urllib.request.urlopen(req, timeout=20))


def main():
    brut = psql(SQL)
    cands = json.loads(brut) if brut and brut != "" else []
    cands = cands or []
    vus = deja_ecrits()
    cands = [c for c in cands if c["email"] not in vus]
    cands = [c for c in cands if c["email"] not in supprimes([c["email"] for c in cands])]
    apercu = DIR / "apercu"; apercu.mkdir(exist_ok=True)
    faits = 0
    for c in cands:
        if faits >= MAX_PAR_JOUR:
            break
        c["site"] = site(c["email"])
        c["signal"] = ("paiement abandonné" if c.get("paiement_abandonne") else
                       "premier refus de quota" if c.get("nouveau_refus") else
                       "intégration qui tourne")
        try:
            m = rediger({k: c[k] for k in ("email", "name", "company", "plan", "created", "ok", "refus", "jours", "jours14", "dernier", "ua", "ep", "paires", "questionnaire", "paiement_abandonne", "signal", "site")})
        except Exception as err:
            print(c["email"], "rédaction impossible :", err)
            continue
        if m.get("skip"):
            print(c["email"], "ignoré :", m.get("raison"))
            continue
        assert m["lang"] in SIG and m["paras"] and m["subject"], m
        url = PRO if m.get("plan") == "pro" else STARTER
        h, t = rendre(m, url), texte(m, url)
        (apercu / f"{c['email']}.html").write_text(h)
        if DRY:
            print(c["email"], "[aperçu]", c["signal"], "|", m["subject"])
        else:
            try:
                res = envoyer(c["email"], m, h, t)
            except urllib.error.HTTPError as err:
                print(c["email"], "refus Resend", err.code, err.read()[:200]); continue
            with open(JOURNAL, "a") as f:
                f.write(json.dumps({"to": c["email"], "id": res.get("id"), "at": datetime.now(timezone.utc).isoformat(),
                                    "signal": c["signal"], "subject": m["subject"]}, ensure_ascii=False) + "\n")
            print(c["email"], "envoyé", c["signal"], "|", m["subject"])
        faits += 1
        time.sleep(1)
    print(f"{datetime.now(timezone.utc):%F %T} : {len(cands)} candidats neufs, {faits} {'aperçus' if DRY else 'envoyés'}")


if __name__ == "__main__":
    main()

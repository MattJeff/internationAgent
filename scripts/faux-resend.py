#!/usr/bin/env python3
"""Un faux Resend, pour que le chemin `--reel` se prouve autrement que par ses refus.

Le dépôt en avait déjà un — `FakeResend`, dans les tests de
`crates/providers/src/email_resend.rs` — et il est enfermé dans `#[cfg(test)]` :
aucun script ne peut le lancer. Celui-ci est le même contrat, servi par un
processus, pour la seule chose que l'autre ne sait pas faire : rester debout
pendant qu'une instance entière monte à côté de lui.

    python3 scripts/faux-resend.py --port 8081 --journal /tmp/envois.jsonl

Six routes, parce que ce sont les six que la marche touche — lues dans
`ResendEmailProvider`, pas devinées :

    GET  /domains              `find_domain`, appelé par les trois autres
    GET  /domains/{id}         `ensure_domain` relit le domaine en entier
    POST /domains              `ensure_domain` crée, après avoir cherché
    POST /domains/{id}/verify  `verify_domain`
    POST /emails               `send` — c'est le `provider_message_id` qui revient
    GET  /emails/{id}          `fetch_inbound` — ce que la boucle entrante lit
                               après qu'un webhook lui a donné un `email_id`

Et une septième qui n'existe pas chez Resend, `POST /_faux/inbound` : elle
dépose le courrier qu'un tiers nous aurait écrit et rend l'`email_id` à mettre
dans la livraison signée. C'est le seul endroit où ce fichier s'écarte du vrai,
et le préfixe est là pour que ça se voie.

**Il n'envoie rien.** C'est le fait, pas une précaution : chaque `POST /emails`
est écrit dans le journal, une ligne de JSON par envoi, et rien ne quitte la
machine. Ce que la marche prouve est que le chemin est complet jusqu'au
`provider_message_id` ; le vrai envoi est au fondateur, avec sa clé.

`Idempotency-Key` est honoré comme chez Resend : deux envois sous la même clé
rendent le même id, et le second n'est pas journalisé. Sans ça une marche qui
rejoue un pas de séquence lirait deux envois là où le produit n'en a fait qu'un.
"""

import argparse, json, os, re, sys, threading, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERROU = threading.Lock()
DOMAINES = {}  # id -> ligne
PAR_CLE = {}  # Idempotency-Key -> id d'envoi
COURRIER = {}  # id -> ce que `GET /emails/{id}` rend
JOURNAL = None
ETAT = None


def retenir():
    """Écrire l'état, s'il y a un fichier pour ça. Appelé sous VERROU.

    Un vrai compte Resend ne perd pas ses domaines quand on redémarre quelque
    chose. Sans ce fichier, relancer ce faux rendait 404 sur le
    `provider_domain_id` que `tenant_domains` avait retenu, et la marche
    s'arrêtait sur une panne que le vrai n'a pas.
    """
    if ETAT:
        with open(ETAT, "w", encoding="utf-8") as f:
            json.dump({"domaines": DOMAINES, "par_cle": PAR_CLE, "courrier": COURRIER}, f)


def ligne_domaine(nom, statut):
    """Ce que Resend rend pour un domaine, aux champs que l'adaptateur lit."""
    return {
        "id": str(uuid.uuid4()),
        "name": nom,
        "status": statut,
        "region": "us-east-1",
        # Les enregistrements que `domains_dns_publish` recopierait chez
        # Cloudflare. Ils sont là pour que la réponse ait la forme d'une vraie,
        # et la marche ne les pose pas : le DNS est du vrai DNS, pas du Resend.
        "records": [
            {
                "record": "SPF",
                "type": "TXT",
                "name": "send",
                "value": "v=spf1 include:amazonses.com ~all",
                "ttl": "Auto",
                "status": "not_started",
                "priority": None,
            },
            {
                "record": "DKIM",
                "type": "TXT",
                "name": "resend._domainkey",
                "value": "p=FAUX",
                "ttl": "Auto",
                "status": "not_started",
                "priority": None,
            },
        ],
    }


class Faux(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):  # le journal utile est celui des envois
        pass

    def _rendre(self, code, corps):
        octets = json.dumps(corps).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(octets)))
        self.end_headers()
        self.wfile.write(octets)

    def _corps(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def _cle_presente(self):
        """Resend refuse en 401 sans jeton, et l'adaptateur sait lire ce refus.

        Vérifié ici pour que la marche prouve aussi que la clé part bien : un
        faux qui accepte tout ne dirait pas si `EMAIL_API_KEY` a été perdue en
        route.
        """
        if (self.headers.get("Authorization") or "").startswith("Bearer "):
            return True
        self._rendre(401, {"message": "Missing API key"})
        return False

    def do_GET(self):
        if not self._cle_presente():
            return
        if self.path == "/domains":
            with VERROU:
                # Le listing de Resend ne porte pas `records` ; l'adaptateur
                # relit le domaine en entier justement pour ça, et un faux qui
                # les mettrait ici cacherait ce deuxième appel.
                data = [
                    {k: v for k, v in d.items() if k != "records"}
                    for d in DOMAINES.values()
                ]
            return self._rendre(200, {"data": data})
        if m := re.fullmatch(r"/domains/([0-9a-f-]+)", self.path):
            with VERROU:
                d = DOMAINES.get(m.group(1))
            return self._rendre(200, d) if d else self._rendre(404, {"message": "Not found"})
        if m := re.fullmatch(r"/emails/([0-9a-f-]+)", self.path):
            with VERROU:
                e = COURRIER.get(m.group(1))
            return self._rendre(200, e) if e else self._rendre(404, {"message": "Not found"})
        self._rendre(404, {"message": "Not found"})

    def do_POST(self):
        if not self._cle_presente():
            return
        if self.path == "/domains":
            nom = self._corps().get("name", "")
            with VERROU:
                for d in DOMAINES.values():
                    if d["name"] == nom:
                        return self._rendre(200, d)
                d = ligne_domaine(nom, "pending")
                DOMAINES[d["id"]] = d
                retenir()
            return self._rendre(201, d)

        if m := re.fullmatch(r"/domains/([0-9a-f-]+)/verify", self.path):
            with VERROU:
                d = DOMAINES.get(m.group(1))
                if d is None:
                    return self._rendre(404, {"message": "Not found"})
                # Le vrai Resend lit le DNS et peut rester `pending` des heures.
                # Celui-ci vérifie du premier coup : la marche prouve le chemin,
                # pas la propagation, et une attente ici ne prouverait rien de
                # plus qu'un `sleep`.
                d["status"] = "verified"
                for r in d["records"]:
                    r["status"] = "verified"
                retenir()
            return self._rendre(200, {"object": "domain", "id": d["id"]})

        if self.path == "/_faux/inbound":
            # Le courrier d'un tiers, déposé à la main. Resend n'a pas cette
            # route ; la boucle entrante, elle, lit `/emails/{id}` comme sur le
            # vrai, donc rien du chemin mesuré n'est court-circuité.
            c = self._corps()
            eid = str(uuid.uuid4())
            with VERROU:
                COURRIER[eid] = {
                    "id": eid,
                    "from": c.get("from", ""),
                    "to": c.get("to", []),
                    "subject": c.get("subject"),
                    "text": c.get("text"),
                    "html": None,
                    "created_at": c.get("created_at"),
                    "attachments": [],
                    "headers": [{"name": "From", "value": c.get("from", "")}],
                }
                retenir()
            return self._rendre(200, {"id": eid})

        if self.path == "/emails":
            corps = self._corps()
            cle = self.headers.get("Idempotency-Key") or ""
            with VERROU:
                if cle and cle in PAR_CLE:
                    return self._rendre(200, {"id": PAR_CLE[cle]})
                envoi_id = str(uuid.uuid4())
                if cle:
                    PAR_CLE[cle] = envoi_id
                # Relisible par `GET /emails/{id}`, comme chez Resend.
                COURRIER[envoi_id] = {
                    "id": envoi_id,
                    "from": corps.get("from", ""),
                    "to": corps.get("to", []),
                    "subject": corps.get("subject"),
                    "text": corps.get("text"),
                    "html": None,
                    "created_at": None,
                    "attachments": [],
                    "headers": [
                        {"name": k, "value": v}
                        for k, v in (corps.get("headers") or {}).items()
                    ],
                }
                if JOURNAL:
                    with open(JOURNAL, "a", encoding="utf-8") as f:
                        f.write(
                            json.dumps(
                                {
                                    "id": envoi_id,
                                    "idempotency_key": cle,
                                    "from": corps.get("from"),
                                    "to": corps.get("to"),
                                    "subject": corps.get("subject"),
                                    "headers": corps.get("headers", {}),
                                    "text": corps.get("text"),
                                },
                                ensure_ascii=False,
                            )
                            + "\n"
                        )
                retenir()
            return self._rendre(200, {"id": envoi_id})

        self._rendre(404, {"message": "Not found"})


def main():
    global JOURNAL, ETAT
    a = argparse.ArgumentParser(description=__doc__)
    a.add_argument("--port", type=int, default=0, help="0 = un port libre")
    a.add_argument("--journal", help="un JSON par envoi, en ajout")
    a.add_argument("--etat", help="où retenir domaines et courrier entre deux lancements")
    args = a.parse_args()
    JOURNAL = args.journal
    ETAT = args.etat
    if ETAT and os.path.exists(ETAT):
        with open(ETAT, encoding="utf-8") as f:
            retrouve = json.load(f)
        DOMAINES.update(retrouve.get("domaines", {}))
        PAR_CLE.update(retrouve.get("par_cle", {}))
        COURRIER.update(retrouve.get("courrier", {}))

    serveur = ThreadingHTTPServer(("127.0.0.1", args.port), Faux)
    # La seule ligne que le script qui le lance lit, et il la lit avant de
    # continuer : un `sleep` à la place serait trop court ou trop long.
    print(f"http://127.0.0.1:{serveur.server_address[1]}", flush=True)
    try:
        serveur.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())

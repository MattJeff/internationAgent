//! Les outils du domaine « commerce » : ce que l'entreprise **vend et
//! encaisse**.
//!
//! Quinze modules de routes, d'un bout à l'autre du cycle : on approche des
//! inconnus (`prospects`, `queue`, `sequences`, `outreach`, `domain`), on leur
//! propose un prix (`quotes`), on facture et on encaisse (`invoices`), et on
//! relit ce que ça a coûté et rapporté (`billing`, `accounting`, `pnl`,
//! `usage`, `spend`, `forecast`, `reports`, `events`).
//!
//! # Ce que les descriptions portent, et pourquoi
//!
//! Un modèle choisit un outil sur sa `description` seule. Les pièges qui
//! coûtent cher ici ne sont pas devinables depuis un nom de route, alors ils
//! sont écrits :
//!
//! * une **séquence ne poste rien** — un pas `email` réserve une promesse et
//!   c'est le siège qui écrit, derrière la Gate ;
//! * l'**import de prospects a un mode à blanc** qu'on passe d'abord ;
//! * un **domaine d'envoi doit être vérifié** avant qu'un siège s'y asseye, et
//!   son **plafond journalier s'épuise** — l'envoi attend le lendemain ;
//! * **rien ici n'émet une facture ni un devis** : seul un employé le fait,
//!   avec un jeton que la Policy Gate a émis pour lui. Les routes d'opérateur
//!   ne savent que constater (payée, acceptée, refusée) ou retirer (avoir).
//!
//! # Le risque, et où il est strict
//!
//! [`Risk::Destructive`] est mis dès qu'un appel **engage l'entreprise devant
//! un tiers** ou retire quelque chose qui ne revient pas : l'export d'une file
//! marque quarante inconnus comme approchés et dépense le budget du jour,
//! l'enrôlement met un contact sur une séquence qui lui écrira, l'avoir retire
//! une créance et sort un PDF, une réponse à un devis ne s'écrit qu'une fois.
//! Les lectures sont [`Risk::Read`] et rien d'autre.
//!
//! # La seule ligne à corps brut, et ce que le module disait avant
//!
//! `POST /v1/prospects/import` n'avait **pas** de ligne ici : son corps est du
//! `text/csv` — la route refuse tout le reste avec un 415 — et le contrat
//! d'exécution ne savait porter qu'un corps JSON. Le champ `raw_body` est
//! arrivé depuis ; `prospects_import` est la seule ligne de ce déploiement à
//! s'en servir, et le reste de ses arguments part en chaîne de requête faute de
//! place dans un corps qui est déjà le fichier.
//!
//! # Ce qui manque, et ce n'est pas un oubli
//!
//! Aucun outil n'**émet** une facture ni un devis, et il ne faut pas en
//! ajouter : seul un employé le fait, avec un jeton que la Policy Gate a émis
//! pour lui. Les lignes `invoices_*` et `quotes_*` d'ici ne savent que
//! constater ou retirer.

use serde_json::{Value, json};

use crate::mcp_server::{Method, Risk, ToolDef};

/// Un schéma d'entrée : des propriétés, et celles qui sont obligatoires.
fn schema(properties: Value, required: &[&str]) -> Value {
    json!({ "type": "object", "properties": properties, "required": required })
}

/// Un outil sans aucune entrée.
fn nothing() -> Value {
    schema(json!({}), &[])
}

/// La fenêtre de `PnlQuery` : `days`, ou `from`/`to`, jamais `days` **et**
/// `from` — la route répond 400. `to` est inclusif.
const WINDOW: &[&str] = &["days", "from", "to"];

fn window_props() -> Value {
    json!({
        "days": {
            "type": "integer",
            "minimum": 1,
            "description": "Fenêtre en jours comptée à rebours depuis `to` (défaut : aujourd'hui). Défaut 30, maximum 366. Ne pas combiner avec `from`."
        },
        "from": {
            "type": "string",
            "format": "date",
            "description": "Premier jour, inclusif, en UTC (`2026-09-01`). Alternative à `days`, pas un complément."
        },
        "to": {
            "type": "string",
            "format": "date",
            "description": "Dernier jour, inclusif, en UTC. Défaut : aujourd'hui."
        }
    })
}

/// Les lignes de ce domaine.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn tools() -> Vec<ToolDef> {
    vec![
        // -------------------------------------------------------------------
        // prospects — les inconnus, et le vocabulaire qui les range
        // -------------------------------------------------------------------
        ToolDef {
            name: "prospects_segments_list",
            title: "Les segments de prospection admis",
            description: "Rend la liste fermée des segments dans lesquels un compte peut être \
                 rangé, telle que la contrainte `accounts_segment` de la base l'admet. À appeler \
                 avant tout import de liste : un segment hors de cette liste est refusé avec un \
                 400 `bad_segment`, et c'est la seule façon de connaître l'orthographe exacte \
                 attendue. C'est exactement la valeur qu'attend le champ `segment` de \
                 `prospects_import`.",
            method: Method::Get,
            path: "/v1/prospects/segments",
            schema: nothing(),
            query: &[],
            raw_body: None,
            risk: Risk::Read,
        },
        ToolDef {
            name: "prospects_import",
            title: "Importer une liste de prospects, à blanc ou pour de vrai",
            description: "Verse un export CSV au format Smartlead — les huit premières colonnes, \
                 en-tête compris — dans les comptes et contacts de cette entreprise. Le corps est \
                 le CSV lui-même, pas du JSON. **Passez d'abord `dry_run: true`** : rien n'est \
                 écrit, et le rapport nomme chaque ligne refusée avec son numéro, ce qui est la \
                 seule façon de voir un en-tête de travers avant d'avoir importé la moitié d'un \
                 fichier. Le segment doit venir de `prospects_segments_list`. Un second import du \
                 même fichier ne duplique rien : un compte est son domaine, un contact son \
                 adresse. Corps plafonné à 1 Mio comme toute requête de cette API.",
            method: Method::Post,
            path: "/v1/prospects/import",
            schema: json!({
                "type": "object",
                "properties": {
                    "csv": {
                        "type": "string",
                        "description": "le contenu du fichier CSV, en-tête compris"
                    },
                    "segment": {
                        "type": "string",
                        "description": "un segment rendu par `prospects_segments_list`"
                    },
                    "country": {
                        "type": "string",
                        "description": "code pays à deux lettres, pour les lignes qui n'en portent pas"
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "true n'écrit rien et rend le rapport ; à faire en premier"
                    }
                },
                "required": ["csv", "segment"],
            }),
            query: &["segment", "country", "dry_run"],
            // La seule ligne de ce déploiement à corps brut, et la raison
            // d'être du champ : la route lit des octets et refuse en 415 tout
            // ce qui n'est pas `text/csv`.
            raw_body: Some(("text/csv", "csv")),
            risk: Risk::Write,
        },
        // -------------------------------------------------------------------
        // outreach — l'activité commerciale, pas l'administration
        // -------------------------------------------------------------------
        ToolDef {
            name: "outreach_summary_get",
            title: "Combien d'inconnus approchés, combien de réponses",
            description: "Rend, sur une fenêtre, le nombre d'inconnus approchés, de fils qui ont \
                 répondu, d'heures prises sur la page de réservation et d'adresses retirées, avec \
                 une ligne par jour (zéros compris) et la liste de ce que ces chiffres ne couvrent \
                 pas. C'est la seule lecture qui dit si l'entreprise *travaille* — `pnl_get` dit \
                 ce qu'elle brûle, `autonomy_get` qui décide, aucune ne dit si quelqu'un a été \
                 approché ; lire `unmeasured` avant de citer un chiffre, `approached` compte des \
                 créneaux réservés et non des envois partis. La réputation du domaine qui porte \
                 ces envois est sur `outreach_health_get`, et ce que le tirage de la file a \
                 consommé sur `prospects_queue_export`.",
            method: Method::Get,
            path: "/v1/outreach",
            schema: schema(window_props(), &[]),
            query: WINDOW,
            raw_body: None,
            risk: Risk::Read,
        },
        ToolDef {
            name: "outreach_health_get",
            title: "La réputation du domaine d'envoi",
            description: "Rend, depuis N jours, les envois, livraisons, ouvertures, clics, rebonds \
                 et plaintes, plus les deux taux **en pour mille des envois** — l'unité des seuils \
                 que Google et Yahoo publient (0,3 % de plaintes = 3 ‰). À consulter avant \
                 d'augmenter un plafond journalier ou de lancer une campagne : un domaine dont le \
                 taux de plaintes monte ne se répare pas par une cadence, et cette lecture est la \
                 seule qui le voie venir. Le plafond, lui, se change avec `domains_cap_set` — et \
                 il ne répare rien : un taux de plaintes qui monte ne se traite pas par une \
                 cadence.",
            method: Method::Get,
            path: "/v1/outreach/health",
            schema: schema(
                json!({
                    "days": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 365,
                        "description": "Nombre de jours en arrière depuis maintenant. Défaut 30, maximum 365 — au-delà d'un an, les traces ne disent plus rien de la réputation d'aujourd'hui."
                    }
                }),
                &[],
            ),
            query: &["days"],
            raw_body: None,
            risk: Risk::Read,
        },
        // -------------------------------------------------------------------
        // sequences — la promesse de relance, jamais l'envoi
        // -------------------------------------------------------------------
        ToolDef {
            name: "sequences_list",
            title: "Les séquences de l'entreprise",
            description: "Rend toutes les séquences définies, les vivantes d'abord puis les \
                 archivées, avec leurs pas. À appeler avant d'enrôler quelqu'un : c'est là que se \
                 lisent l'identifiant d'une séquence et le nombre de mails qu'elle promet. C'est \
                 la source de l'`id` de `sequences_enroll`, `sequences_runs_list` et \
                 `sequences_archive` ; pour savoir où en sont les inscrits d'une séquence déjà \
                 lancée, c'est `sequences_runs_list` et pas celui-ci.",
            method: Method::Get,
            path: "/v1/sequences",
            schema: nothing(),
            query: &[],
            raw_body: None,
            risk: Risk::Read,
        },
        ToolDef {
            name: "sequences_create",
            title: "Définir une séquence",
            description: "Crée une séquence : une liste ordonnée de pas `email` (un brief, pas un \
                 texte de mail), `wait` (des heures) et `branch` (sauter selon une ouverture ou un \
                 clic). Définir ne contacte personne — c'est `sequences_enroll` qui met quelqu'un \
                 dessus ; la liste est refusée en 400 si elle est vide, dépasse 12 pas, n'a aucun \
                 pas `email`, saute hors de la liste ou boucle sans `wait` (elle tournerait à \
                 chaque tick), et en 409 `name_taken` si une séquence vivante porte déjà ce nom.",
            method: Method::Post,
            path: "/v1/sequences",
            schema: schema(
                json!({
                    "name": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 200,
                        "description": "Unique parmi les séquences vivantes de l'entreprise."
                    },
                    "steps": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 12,
                        "description": "Les pas, dans l'ordre. Au moins un pas `email`.",
                        "items": {
                            "oneOf": [
                                {
                                    "type": "object",
                                    "description": "Réveiller le siège pour qu'il écrive. Ne poste rien lui-même.",
                                    "properties": {
                                        "kind": { "const": "email" },
                                        "brief": {
                                            "type": "string",
                                            "minLength": 1,
                                            "description": "Ce que l'employé doit écrire — l'intention, pas le texte du mail."
                                        }
                                    },
                                    "required": ["kind", "brief"]
                                },
                                {
                                    "type": "object",
                                    "description": "Attendre avant le pas suivant.",
                                    "properties": {
                                        "kind": { "const": "wait" },
                                        "hours": {
                                            "type": "integer",
                                            "minimum": 1,
                                            "maximum": 720,
                                            "description": "1 à 720 heures (30 jours)."
                                        }
                                    },
                                    "required": ["kind", "hours"]
                                },
                                {
                                    "type": "object",
                                    "description": "Sauter selon ce qu'est devenu le dernier mail.",
                                    "properties": {
                                        "kind": { "const": "branch" },
                                        "on": {
                                            "type": "string",
                                            "enum": ["opened", "clicked"],
                                            "description": "Pas de `replied` : une réponse termine le run avant qu'une branche soit évaluée."
                                        },
                                        "then": {
                                            "type": "integer",
                                            "minimum": 0,
                                            "description": "Index du pas si le signal est là. Un index égal au nombre de pas est la fin de la liste."
                                        },
                                        "otherwise": {
                                            "type": "integer",
                                            "minimum": 0,
                                            "description": "Index du pas sinon. Ni `then` ni `otherwise` ne peut pointer sur la branche elle-même."
                                        }
                                    },
                                    "required": ["kind", "on", "then", "otherwise"]
                                }
                            ]
                        }
                    }
                }),
                &["name", "steps"],
            ),
            query: &[],
            raw_body: None,
            risk: Risk::Write,
        },
        ToolDef {
            name: "sequences_enroll",
            title: "Inscrire un contact dans une séquence",
            description: "Met un contact sur une séquence sous la responsabilité d'un siège : la \
                 position est posée et le premier pas est joué au prochain tick. **Un pas `email` \
                 ne poste rien** — il réserve une promesse au calendrier, et quand elle sonne le \
                 siège est réveillé et écrit le mail lui-même, qui passe la Gate comme tout autre \
                 envoi (suppression, budget d'inconnus du jour, `MAX_TOUCHES`) ; refusé en 403 \
                 `suppressed` si l'adresse a demandé qu'on la laisse tranquille, en 409 si le \
                 contact est déjà inscrit, en 404 si la séquence, le contact ou le siège \
                 n'appartiennent pas à cette entreprise. L'`id` vient de `sequences_list`, le \
                 `contact_id` d'un import fait par `prospects_import`, et l'`employee_id` \
                 d'`employees_list` ; où en est l'inscrit ensuite se lit sur \
                 `sequences_runs_list`.",
            method: Method::Post,
            path: "/v1/sequences/{id}/enroll",
            schema: schema(
                json!({
                    "id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "La séquence, telle que `sequences_list` la rend."
                    },
                    "contact_id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "Le contact à inscrire. Il doit être de cette entreprise."
                    },
                    "employee_id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "Le siège qui écrira les mails de ce run — c'est son budget et sa Gate qui s'appliqueront."
                    }
                }),
                &["id", "contact_id", "employee_id"],
            ),
            query: &[],
            raw_body: None,
            risk: Risk::Destructive,
        },
        ToolDef {
            name: "sequences_runs_list",
            title: "Où en est chaque inscrit d'une séquence",
            description: "Rend, pour une séquence, chaque contact inscrit et sa position : le pas \
                 courant, quand le prochain est dû, et pourquoi le run s'est arrêté le cas échéant \
                 (`replied`, `max_touches`, `not_sent`, `done`). C'est la lecture qui explique \
                 pourquoi une séquence semble ne rien faire — `not_sent` veut dire que le siège a \
                 été réveillé et que rien n'est parti, souvent parce que la Gate a refusé. L'`id` \
                 vient de `sequences_list`. Un run bloqué en `not_sent` se diagnostique sur \
                 `refusals_get` et `domains_primary_get` — un plafond journalier épuisé est la \
                 cause la plus fréquente.",
            method: Method::Get,
            path: "/v1/sequences/{id}/runs",
            schema: schema(
                json!({
                    "id": { "type": "string", "format": "uuid", "description": "La séquence." }
                }),
                &["id"],
            ),
            query: &[],
            raw_body: None,
            risk: Risk::Read,
        },
        ToolDef {
            name: "sequences_archive",
            title: "Archiver une séquence",
            description: "Archive une séquence pour qu'on ne puisse plus y inscrire personne ; les \
                 runs déjà en cours vont jusqu'au bout, ce geste ne les arrête pas. 404 si la \
                 séquence n'est pas à cette entreprise ou est déjà archivée — il n'y a pas de \
                 désarchivage, le nom redevient seulement disponible. L'`id` vient de \
                 `sequences_list`.",
            method: Method::Delete,
            path: "/v1/sequences/{id}",
            schema: schema(
                json!({
                    "id": { "type": "string", "format": "uuid", "description": "La séquence à archiver." }
                }),
                &["id"],
            ),
            query: &[],
            raw_body: None,
            risk: Risk::Destructive,
        },
        // -------------------------------------------------------------------
        // domain — le domaine d'envoi, sans lequel aucun siège n'écrit
        // -------------------------------------------------------------------
        ToolDef {
            name: "domains_primary_get",
            title: "Le domaine d'envoi principal",
            description: "Rend le domaine principal du locataire — celui dont les sièges tirent \
                 leur adresse — avec son statut chez le fournisseur, les enregistrements DNS qu'il \
                 réclame, son plafond journalier et ce qui est déjà parti aujourd'hui. 404 \
                 `no_domain` quand aucun domaine n'est posé : c'est la première chose à vérifier \
                 quand un envoi ne part pas. Deux suites possibles selon ce qu'on lit : un statut \
                 qui n'est pas vérifié se traite par `domains_dns_publish` puis `domains_verify` — \
                 **un siège ne peut pas s'asseoir sur un domaine non vérifié** — et un compteur du \
                 jour collé à son plafond se traite par `domains_cap_set`, ou en attendant demain. \
                 Dès qu'il y a plus d'un domaine, `domains_list` les montre tous.",
            method: Method::Get,
            path: "/v1/domain",
            schema: nothing(),
            query: &[],
            raw_body: None,
            risk: Risk::Read,
        },
        ToolDef {
            name: "domains_list",
            title: "Tous les domaines d'envoi",
            description: "Rend tous les domaines d'envoi du locataire, la primaire en tête, chacun \
                 avec son statut, ses enregistrements, son plafond et son compteur du jour. À \
                 préférer à `domains_primary_get` dès qu'il y a plus d'un domaine, notamment pour \
                 voir lequel a épuisé son plafond.",
            method: Method::Get,
            path: "/v1/domains",
            schema: nothing(),
            query: &[],
            raw_body: None,
            risk: Risk::Read,
        },
        ToolDef {
            name: "domains_register",
            title: "Ajouter un domaine d'envoi",
            description: "Déclare un domaine chez le fournisseur email et rend les enregistrements \
                 DNS qu'il faudra poser ; le premier domaine déclaré devient la primaire. **Le \
                 domaine n'est pas utilisable pour autant** : il faut poser le DNS \
                 (`domains_dns_publish` ou à la main) puis appeler `domains_verify` — 409 \
                 `domain_taken` si un autre locataire l'a déjà, 200 au lieu de 201 s'il était déjà \
                 là.",
            method: Method::Post,
            path: "/v1/domain",
            schema: schema(
                json!({
                    "domain": {
                        "type": "string",
                        "description": "Le nom de domaine, sans protocole ni chemin (`agents.exemple.com`)."
                    }
                }),
                &["domain"],
            ),
            query: &[],
            raw_body: None,
            risk: Risk::Write,
        },
        ToolDef {
            name: "domains_verify",
            title: "Relire le statut d'un domaine chez le fournisseur",
            description: "Redemande au fournisseur où en est la vérification d'un domaine et \
                 enregistre la réponse ; si le domaine devient vérifié, les sièges qui attendaient \
                 pour écrire sont réveillés. **Un siège ne peut pas s'asseoir sur un domaine non \
                 vérifié** — c'est cet appel qu'on répète après avoir posé le DNS, sur la primaire \
                 quand `domain` est omis. Le domaine vient de `domains_list`, et les \
                 enregistrements qu'il faut avoir posés d'abord de `domains_dns_publish`.",
            method: Method::Post,
            path: "/v1/domain/verify",
            schema: schema(
                json!({
                    "domain": {
                        "type": "string",
                        "description": "Le domaine à relire. Omis, c'est la primaire."
                    }
                }),
                &[],
            ),
            query: &[],
            raw_body: None,
            risk: Risk::Write,
        },
        ToolDef {
            name: "domains_dns_publish",
            title: "Poser les enregistrements DNS chez Cloudflare",
            description: "Recopie chez Cloudflare, en un appel, les enregistrements que le \
                 fournisseur réclame pour ce domaine, et rend ce qui a été posé, ce qui existait \
                 déjà et la zone touchée. Le jeton Cloudflare est lu dans le corps, utilisé une \
                 fois et jamais stocké ni journalisé ; il faut ensuite `domains_verify` pour que \
                 le domaine devienne utilisable.",
            method: Method::Post,
            path: "/v1/domain/dns",
            schema: schema(
                json!({
                    "cloudflare_api_token": {
                        "type": "string",
                        "description": "Jeton d'API Cloudflare autorisé à écrire les enregistrements DNS de la zone. Utilisé une seule fois, jamais conservé."
                    },
                    "domain": {
                        "type": "string",
                        "description": "Le domaine concerné. Omis, c'est la primaire."
                    }
                }),
                &["cloudflare_api_token"],
            ),
            query: &[],
            raw_body: None,
            risk: Risk::Write,
        },
        ToolDef {
            name: "domains_cap_set",
            title: "Changer le plafond journalier d'un domaine",
            description: "Fixe combien de messages ce domaine peut envoyer par jour UTC. **Le \
                 plafond s'épuise** : une fois atteint, les envois de la journée sont refusés et \
                 attendent le lendemain — c'est la première explication d'une file qui n'avance \
                 plus l'après-midi ; zéro est refusé en 400 `bad_cap` (pour ne plus envoyer du \
                 tout, retirer le domaine). Le domaine vient de `domains_list`, et ce qui est déjà \
                 parti aujourd'hui de `domains_primary_get`.",
            method: Method::Put,
            path: "/v1/domains/{domain}/cap",
            schema: schema(
                json!({
                    "domain": { "type": "string", "description": "Le domaine dont on change le plafond." },
                    "daily_cap": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Messages par jour UTC. Monter ce nombre sans regarder `outreach_health_get` est la façon habituelle de griller un domaine."
                    }
                }),
                &["domain", "daily_cap"],
            ),
            query: &[],
            raw_body: None,
            risk: Risk::Write,
        },
        ToolDef {
            name: "domains_remove",
            title: "Retirer un domaine d'envoi",
            description: "Retire un domaine d'envoi du locataire ; les sièges qui en tiraient leur \
                 adresse n'en ont plus. 409 `primary_domain` sur la primaire — il faut en désigner \
                 une autre d'abord — et 404 si le domaine n'est pas à cette entreprise. Le domaine \
                 vient de `domains_list`.",
            method: Method::Delete,
            path: "/v1/domains/{domain}",
            schema: schema(
                json!({
                    "domain": { "type": "string", "description": "Le domaine à retirer." }
                }),
                &["domain"],
            ),
            query: &[],
            raw_body: None,
            risk: Risk::Destructive,
        },
        // -------------------------------------------------------------------
        // queue — le fichier de prospection, et ce qu'il dépense
        // -------------------------------------------------------------------
        ToolDef {
            name: "prospects_queue_export",
            title: "Tirer la file de prospection du jour",
            description: "Construit le fichier CSV des prospects à contacter sous les limites du \
                 siège nommé, et rend `{queued, csv}`. **Cet appel écrit** : il marque les \
                 personnes servies comme approchées, dépense le budget d'inconnus du jour et \
                 repousse leurs relances de 72 h — le rejouer rend un fichier différent, souvent \
                 vide, et les places dépensées ne reviennent pas ; le rejouer *pour cause \
                 d'erreur* demande donc de réutiliser la même clé d'idempotence, et `queued: 0` \
                 avec un 200 est une réponse normale (budget épuisé, ou rien de frais). L'`id` est \
                 le siège qui contactera, depuis `employees_list` ; ce que le tirage a consommé se \
                 relit ensuite sur `outreach_summary_get`.",
            method: Method::Post,
            path: "/v1/employees/{id}/queue/export",
            schema: schema(
                json!({
                    "id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "Le siège dont les limites s'appliquent. Ce n'est pas une autorisation : le locataire vient de la clé, et l'export reste à l'échelle de l'entreprise."
                    }
                }),
                &["id"],
            ),
            query: &[],
            raw_body: None,
            risk: Risk::Destructive,
        },
        // -------------------------------------------------------------------
        // quotes — ce qu'on a proposé, et ce que le client en a dit
        // -------------------------------------------------------------------
        ToolDef {
            name: "quotes_list",
            title: "Les devis proposés",
            description: "Rend une page de devis, le plus récent d'abord, versions remplacées \
                 comprises (`supersedes_quote_id` reconstitue les chaînes), avec le montant en \
                 unités mineures, la validité et la réponse du client. **Filtre d'abord** : \
                 `state` partitionne le registre en quatre — `open` (sans réponse et encore \
                 acceptable), `lapsed` (sans réponse, validité écoulée : à réémettre, jamais à \
                 antidater), `accepted`, `declined` — et sans `state` la page mélange les \
                 quatre. La marche se fait avec `after` = le `next_after` rendu ; `next_after` \
                 nul veut dire que la page était la dernière. Il n'y a volontairement aucun \
                 total : un devis n'est dû par personne, le carnet de créances se lit sur \
                 `invoices_list` ; `expired` sur une ligne est une question distincte de \
                 `state`, un devis accepté à temps peut avoir expiré depuis. C'est la source de \
                 l'`id` de `quotes_accept` et `quotes_decline`, et la seule lecture des devis : \
                 rien dans cette table n'en *émet* un, seul un employé le fait avec un jeton de \
                 la Policy Gate.",
            method: Method::Get,
            path: "/v1/quotes",
            schema: json!({
                "type": "object",
                "properties": {
                    "state": {
                        "type": "string",
                        "enum": ["open", "lapsed", "accepted", "declined"],
                        "description": "La coupe. Absent : les quatre ensemble.",
                    },
                    "after": {
                        "type": "string",
                        "format": "uuid",
                        "description": "Le `next_after` de la page précédente.",
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 200,
                        "description": "Défaut 50, maximum 200.",
                    },
                },
            }),
            query: &["state", "after", "limit"],
            raw_body: None,
            risk: Risk::Read,
        },
        ToolDef {
            name: "quotes_accept",
            title: "Enregistrer qu'un devis a été accepté",
            description: "Écrit que le client a dit oui, à l'instant du serveur — il n'y a pas de \
                 date à fournir, une date antidatée ressusciterait un devis périmé. **Cela ne \
                 s'écrit qu'une fois et ne se retire pas**, et c'est délibérément un geste \
                 d'opérateur : le siège qui a proposé le devis ne doit pas être ce qui déclare \
                 qu'il a été accepté ; 404 couvre les quatre refus (pas à cette entreprise, \
                 inexistant, déjà répondu, **périmé** — seul ce dernier est actionnable et le \
                 `detail` le dit). L'`id` vient de `quotes_list`.",
            method: Method::Post,
            path: "/v1/quotes/{id}/accepted",
            schema: schema(
                json!({
                    "id": { "type": "string", "format": "uuid", "description": "Le devis, tel que `quotes_list` le rend." }
                }),
                &["id"],
            ),
            query: &[],
            raw_body: None,
            risk: Risk::Destructive,
        },
        ToolDef {
            name: "quotes_decline",
            title: "Enregistrer qu'un devis a été refusé",
            description: "Écrit que le client a dit non, à l'instant du serveur, une seule fois et \
                 sans retour possible. Mêmes quatre refus en 404 que l'acceptation, péremption \
                 comprise : refuser une offre qui n'était déjà plus faite enregistrerait le refus \
                 de quelque chose qui n'était pas sur la table — dans ce cas, il faut réémettre un \
                 devis avec une nouvelle validité. L'`id` vient de `quotes_list`.",
            method: Method::Post,
            path: "/v1/quotes/{id}/declined",
            schema: schema(
                json!({
                    "id": { "type": "string", "format": "uuid", "description": "Le devis concerné." }
                }),
                &["id"],
            ),
            query: &[],
            raw_body: None,
            risk: Risk::Destructive,
        },
        // -------------------------------------------------------------------
        // invoices — le registre, et les deux seuls gestes d'opérateur
        // -------------------------------------------------------------------
        ToolDef {
            name: "invoices_list",
            title: "Le registre des factures",
            description: "Rend une page du registre, la plus ancienne d'abord, réglées et \
                 impayées ensemble par défaut, avec `outstanding_minor` **par devise** (il n'y a \
                 pas de taux de change dans ce produit, et il ne doit pas y en avoir). **Ce \
                 total est celui du registre entier, jamais celui de la page** : il ne rétrécit \
                 pas quand on pagine. `state=outstanding` répond à « qui relancer » (les \
                 factures impayées, avoirs exclus, montant brut), `state=paid` à « qu'est-ce qui \
                 est rentré » ; sans `state`, les deux et les avoirs avec elles — c'est la seule \
                 vue qui montre un avoir à côté du document qu'il corrige. La marche se fait \
                 avec `after` = le `next_after` rendu, qui est un **numéro de facture** et non un \
                 UUID, parce que le numéro est l'ordre. C'est la source de l'`id` de \
                 `invoices_payment_record` et d'`invoices_credit` ; ce qui n'est pas encore une \
                 créance — une offre en attente de réponse — est sur `quotes_list`. Il n'existe \
                 aucun outil pour *émettre* une facture : seule une décision d'employé passée \
                 par la Policy Gate en crée une.",
            method: Method::Get,
            path: "/v1/invoices",
            schema: json!({
                "type": "object",
                "properties": {
                    "state": {
                        "type": "string",
                        "enum": ["outstanding", "paid"],
                        "description": "La coupe. Absent : tout le registre, avoirs compris.",
                    },
                    "after": {
                        "type": "integer",
                        "description": "Le `next_after` de la page précédente — un numéro de facture.",
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 200,
                        "description": "Défaut 50, maximum 200.",
                    },
                },
            }),
            query: &["state", "after", "limit"],
            raw_body: None,
            risk: Risk::Read,
        },
        ToolDef {
            name: "invoices_issuer_get",
            title: "Les mentions obligatoires de l'émetteur",
            description: "Rend l'en-tête légal de l'entreprise (forme juridique, adresse, SIREN, \
                 ville du RCS, TVA, pénalités de retard) et, surtout, la liste nommée de ce qui \
                 manque. À lire avant tout document : tant que cette liste n'est pas vide, un \
                 avoir est refusé en 409 et tout PDF émis porte « FACTURE NON CONFORME » en \
                 travers. À lire avant `invoices_credit`, qui est refusé tant que la liste des \
                 manques n'est pas vide, et avant `invoices_issuer_set`, qui remplace ce document \
                 en entier.",
            method: Method::Get,
            path: "/v1/invoices/issuer",
            schema: nothing(),
            query: &[],
            raw_body: None,
            risk: Risk::Read,
        },
        ToolDef {
            name: "invoices_issuer_set",
            title: "Écrire les mentions obligatoires de l'émetteur",
            description: "Écrit l'en-tête légal de l'entreprise. **C'est un remplacement entier, \
                 pas une retouche** : un champ omis est effacé, donc relire `invoices_issuer_get` \
                 et renvoyer l'ensemble ; le nom n'est pas ici (c'est l'identité de l'entreprise, \
                 changée ailleurs), un taux de TVA de zéro est refusé — une entreprise hors TVA \
                 remplit `vat_exemption_reason` — et un en-tête qui resterait inémettable est \
                 refusé tout de suite avec les mentions manquantes nommées. **Aucun champ n'est \
                 obligatoire au schéma** — c'est la route qui l'est — donc le plus petit corps \
                 possible efface l'en-tête entier : à n'appeler qu'avec le document complet que \
                 `invoices_issuer_get` vient de rendre, corrigé.",
            method: Method::Put,
            path: "/v1/invoices/issuer",
            schema: schema(
                json!({
                    "legal_form": { "type": "string", "description": "Forme juridique (`SAS`, `SARL`…)." },
                    "postal_address": { "type": "string", "description": "Adresse postale du siège, telle qu'elle doit figurer sur le document." },
                    "siren": { "type": "string", "description": "Numéro SIREN." },
                    "rcs_city": { "type": "string", "description": "Ville du greffe d'immatriculation." },
                    "vat_number": { "type": "string", "description": "Numéro de TVA intracommunautaire." },
                    "vat_rate_bp": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Taux de TVA en points de base : 2000 pour 20 %. Jamais 0 — sans TVA, remplir `vat_exemption_reason` à la place."
                    },
                    "vat_exemption_reason": { "type": "string", "description": "Mention d'exonération, pour une entreprise hors TVA. Exclusif de `vat_rate_bp`." },
                    "late_penalty_rate_bp": { "type": "integer", "description": "Taux des pénalités de retard, en points de base." }
                }),
                &[],
            ),
            query: &[],
            // Destructif, et corrigé le 2026-09-11 : rien n'est `required`
            // ici, donc le plus petit corps possible efface tout l'en-tête
            // légal et rend l'entreprise inémettable jusqu'à ce que quelqu'un
            // le retape. Un remplacement qui reprend est destructif.
            raw_body: None,
            risk: Risk::Destructive,
        },
        ToolDef {
            name: "invoices_payment_record",
            title: "Déclarer qu'une facture a été payée",
            description: "Enregistre que l'argent est arrivé, à l'instant du serveur — il n'y a \
                 pas de date de valeur à fournir. Rien ici n'observe une banque : c'est une \
                 **affirmation d'opérateur**, écrite une fois et jamais retirée ni redatée (un \
                 second appel répond 404, comme une facture qui n'est pas à cette entreprise), et \
                 elle laisse une ligne au journal avec `source: operator` — le webhook Stripe \
                 écrit la même colonne pour les règlements qu'il constate. À utiliser pour un \
                 virement constaté hors Stripe, et pour rien d'autre : retirer une créance est \
                 `invoices_credit`, qui, lui, produit un document chez le client. L'`id` vient \
                 d'`invoices_list`.",
            method: Method::Post,
            path: "/v1/invoices/{id}/paid",
            schema: schema(
                json!({
                    "id": { "type": "string", "format": "uuid", "description": "La facture réglée, telle que `invoices_list` la rend." }
                }),
                &["id"],
            ),
            query: &[],
            raw_body: None,
            risk: Risk::Destructive,
        },
        ToolDef {
            name: "invoices_credit",
            title: "Émettre un avoir sur une facture",
            description: "Retire tout ou partie d'une facture émise en créant un avoir, qui \
                 produit un document destiné au client. Refusé en 409 si la facture a déjà son \
                 avoir (un seul par facture, garanti par un index unique) ou si les mentions de \
                 l'émetteur sont incomplètes, et en 404 si la facture n'est pas à cette \
                 entreprise, est elle-même un avoir, ou est plus petite que le montant retiré ; \
                 c'est le seul geste d'opérateur qui *émet* un document commercial, et il ne se \
                 défait pas. L'`id` vient d'`invoices_list`, et l'en-tête légal qu'il exige \
                 complet de `invoices_issuer_get`.",
            method: Method::Post,
            path: "/v1/invoices/{id}/credit",
            schema: schema(
                json!({
                    "id": { "type": "string", "format": "uuid", "description": "La facture corrigée." },
                    "amount_minor": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Montant retiré, en unités mineures de la devise de la facture (12000 pour 120,00 €). Pas plus que la facture. La devise n'est pas ici : c'est celle du document corrigé."
                    },
                    "memo": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 200,
                        "description": "Le motif, une ligne, 1 à 200 caractères."
                    }
                }),
                &["id", "amount_minor", "memo"],
            ),
            query: &[],
            raw_body: None,
            risk: Risk::Destructive,
        },
        // -------------------------------------------------------------------
        // billing, accounting, pnl, forecast — ce que ça coûte et rapporte
        // -------------------------------------------------------------------
        ToolDef {
            name: "billing_get",
            title: "La base de notre facture : jours-siège et jours-connecteur",
            description: "Compte, sur une fenêtre, les jours-siège et les jours-connecteur du \
                 locataire, avec une ligne par jour (zéros compris) et le détail par siège et par \
                 connecteur, de sorte que les totaux se recoupent ligne à ligne. **Aucun montant \
                 n'y figure** : c'est la mesure du service rendu, le tarif appartient au contrat — \
                 et ce ne sont jamais des jetons, ceux-là sont chez le client et se lisent avec \
                 `usage_get`.",
            method: Method::Get,
            path: "/v1/billing",
            schema: schema(
                json!({
                    "from": { "type": "string", "format": "date", "description": "Premier jour, inclusif, UTC." },
                    "to": { "type": "string", "format": "date", "description": "Dernier jour, inclusif, UTC. Défaut : aujourd'hui." }
                }),
                &[],
            ),
            query: &["from", "to"],
            raw_body: None,
            risk: Risk::Read,
        },
        ToolDef {
            name: "billing_worked_seats_get",
            title: "Les sièges qui ont travaillé ce mois-ci",
            description: "Sur un mois, dit combien de sièges existent et combien ont décidé \
                 quelque chose — autorisé ou refusé, un refus compte comme du travail. C'est la \
                 position commerciale qu'on imprime sur un contrat (« un siège qui n'a jamais rien \
                 décidé ne coûte rien »), à lire à côté de `billing_get` qui, lui, est le \
                 compteur.",
            method: Method::Get,
            path: "/v1/billing/worked-seats",
            schema: schema(
                json!({
                    "month": {
                        "type": "string",
                        "pattern": "^[0-9]{4}-[0-9]{2}$",
                        "description": "Le mois, `AAAA-MM`. Défaut : le mois en cours. La fenêtre est un mois entier, jamais un intervalle libre."
                    }
                }),
                &[],
            ),
            query: &["month"],
            raw_body: None,
            risk: Risk::Read,
        },
        ToolDef {
            name: "accounting_export",
            title: "Export comptable, une ligne par mouvement",
            description: "Rend en CSV le journal demandé — `invoices` (documents émis ou payés \
                 dans la fenêtre), `spend` (réservations, `released` compris, que le P&L ne compte \
                 pas) ou `usage` (une ligne par siège et par jour, **vide sans tarif déclaré, \
                 jamais zéro**) — pour l'outil d'un comptable. C'est la même matière que \
                 `pnl_get`, lue mouvement par mouvement : sommées sur la même fenêtre, les lignes \
                 donnent exactement les chiffres du P&L, et les cellules sont neutralisées contre \
                 l'injection de formules.",
            method: Method::Get,
            path: "/v1/accounting/export",
            schema: {
                let mut props = window_props();
                props["journal"] = json!({
                    "type": "string",
                    "enum": ["invoices", "spend", "usage"],
                    "description": "Obligatoire : lequel des trois journaux exporter."
                });
                schema(props, &["journal"])
            },
            query: &["journal", "days", "from", "to"],
            raw_body: None,
            risk: Risk::Read,
        },
        ToolDef {
            name: "pnl_get",
            title: "Ce que chaque siège a brûlé et encaissé",
            description: "Rend, par siège et pour l'entreprise entière, la consommation de modèle \
                 valorisée **au tarif que le locataire a lui-même déclaré**, face aux factures \
                 émises, aux encaissements, aux avoirs et aux dépenses. Sans tarif déclaré le coût \
                 est `null` et jamais zéro ; les montants sont donnés par devise et ne sont jamais \
                 additionnés entre devises, et `cost_source` dit d'où vient chaque chiffre. C'est \
                 la lecture de « est-ce que ça vaut le coup » ; `billing_get` est ce que nous \
                 facturons au locataire, `usage_get` ce que le modèle a consommé chez lui, et \
                 `accounting_export` exactement cette matière mouvement par mouvement.",
            method: Method::Get,
            path: "/v1/pnl",
            schema: schema(window_props(), &[]),
            query: WINDOW,
            raw_body: None,
            risk: Risk::Read,
        },
        ToolDef {
            name: "forecast_get",
            title: "Le débit des N prochains jours, et le point mort",
            description: "Estime, sur une fenêtre à venir, combien de tours les cadences \
                 produiront, combien d'appels de modèle cela fait, combien de personnes peuvent \
                 être approchées, ce que ça facturera, et à combien se situe le point mort. \
                 **Aucun pourcentage de réussite n'est rendu** — il n'est pas mesurable ici ; \
                 `cost_usd` est `null` quand le locataire tourne sur un abonnement CLI (il n'y a \
                 alors pas de facture au jeton), et un siège sans cadence est signalé plutôt que \
                 compté. La seule lecture de cette table tournée vers l'avant : à consulter avant \
                 de changer une cadence (`initiatives_set`) ou un plafond de domaine \
                 (`domains_cap_set`), puisque ce sont les deux entrées qu'elle projette.",
            method: Method::Get,
            path: "/v1/forecast",
            schema: schema(
                json!({
                    "days": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 90,
                        "description": "Durée de la fenêtre, 1 à 90 jours. Sans valeur honnête par défaut : au-delà d'un trimestre, les prix et les mesures sur lesquels ceci repose ont une durée de vie plus courte que la réponse."
                    },
                    "infra_usd_per_month": {
                        "type": "number",
                        "description": "Ce que notre contrat coûte à ce locataire, en USD par mois. Vient de l'appelant seulement — le dépôt ne connaît pas son propre prix ; absent, le point mort ne compte que les jetons et le dit."
                    }
                }),
                &["days"],
            ),
            query: &["days", "infra_usd_per_month"],
            raw_body: None,
            risk: Risk::Read,
        },
        // -------------------------------------------------------------------
        // usage, spend, reports, events — la consommation et le journal
        // -------------------------------------------------------------------
        ToolDef {
            name: "usage_get",
            title: "Les jetons consommés, par siège",
            description: "Rend, par siège et au total, les appels et les jetons consommés sur la \
                 fenêtre. **Il n'y a aucun montant ici** — ces jetons sont ceux du client, sur son \
                 propre contrat, et `billing_get` est notre facture à nous ; vérifier `complete` \
                 avant de citer `tokens_measured`, qui n'est qu'un plancher dès qu'un appel n'a \
                 pas été mesuré (inconnu n'est pas gratuit).",
            method: Method::Get,
            path: "/v1/usage",
            schema: schema(
                json!({
                    "from": { "type": "string", "format": "date", "description": "Premier jour, inclusif, UTC." },
                    "to": { "type": "string", "format": "date", "description": "Dernier jour, inclusif, UTC. Défaut : aujourd'hui." }
                }),
                &[],
            ),
            query: &["from", "to"],
            raw_body: None,
            risk: Risk::Read,
        },
        ToolDef {
            name: "usage_models_get",
            title: "La part de chaque modèle",
            description: "Rend la répartition des appels et des jetons par modèle sur les N \
                 derniers jours. C'est la lecture qui répond à « le routage a-t-il changé quelque \
                 chose » — une semaine suffit, d'où le défaut de 7 jours et le maximum de 90. La \
                 même matière, par siège au lieu de par modèle, est sur `usage_get`.",
            method: Method::Get,
            path: "/v1/usage/models",
            schema: schema(
                json!({
                    "days": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 90,
                        "description": "Nombre de jours. Défaut 7, maximum 90."
                    }
                }),
                &[],
            ),
            query: &["days"],
            raw_body: None,
            risk: Risk::Read,
        },
        ToolDef {
            name: "spend_caps_get",
            title: "Les plafonds de dépense d'un siège",
            description: "Rend, pour un siège et **une devise**, le plafond journalier, le plafond \
                 par paiement et le nombre de paiements permis par jour. `caps: null` ne veut pas \
                 dire « illimité » mais « ne peut pas payer » : sans ligne de plafonds, la Gate \
                 refuse toute dépense avec `no_spend_policy` — c'est l'état d'un déploiement où \
                 personne n'a encore écrit de plafonds. L'`id` vient d'`employees_list` ; pour \
                 écrire ces plafonds, `spend_caps_set`.",
            method: Method::Get,
            path: "/v1/employees/{id}/spend-caps",
            schema: schema(
                json!({
                    "id": { "type": "string", "format": "uuid", "description": "Le siège. Un siège d'un autre locataire est un 404, jamais un 403." },
                    "currency": {
                        "type": "string",
                        "description": "Code ISO 4217 (`EUR`, `USD`). Obligatoire : les plafonds sont par devise et il n'y a rien à deviner."
                    }
                }),
                &["id", "currency"],
            ),
            query: &["currency"],
            raw_body: None,
            risk: Risk::Read,
        },
        ToolDef {
            name: "spend_caps_set",
            title: "Écrire les plafonds de dépense d'un siège",
            description: "Fixe pour un siège, dans une devise, le plafond journalier, le plafond \
                 par paiement et le nombre de paiements par jour — les deux montants doivent être \
                 dans la même devise, et c'est elle qui identifie la ligne. C'est de la \
                 configuration et non de l'exécution : baisser un plafond ne reprend pas ce que la \
                 journée a déjà réservé, et zéro n'existe pas (pour interdire toute dépense, il \
                 faut n'avoir aucune ligne de plafonds). L'`id` vient d'`employees_list` ; lire \
                 `spend_caps_get` d'abord, dans la même devise, pour savoir s'il y avait une \
                 ligne — c'est un plafond d'argent réel, pas de tours : le budget de tours d'un \
                 siège est sur `employees_turns_get` et celui de son équipe sur \
                 `teams_budget_set`.",
            method: Method::Put,
            path: "/v1/employees/{id}/spend-caps",
            schema: schema(
                json!({
                    "id": { "type": "string", "format": "uuid", "description": "Le siège plafonné." },
                    "daily_total": {
                        "type": "object",
                        "description": "Plafond de tout ce qui peut être réservé en un jour UTC.",
                        "properties": {
                            "minor": { "type": "integer", "minimum": 1, "description": "Unités mineures : 30000 pour 300,00 €. Zéro est refusé." },
                            "currency": { "type": "string", "description": "Code ISO 4217." }
                        },
                        "required": ["minor", "currency"]
                    },
                    "per_transaction": {
                        "type": "object",
                        "description": "Plafond d'un paiement. Même devise que `daily_total`, sinon le plafond ne veut rien dire.",
                        "properties": {
                            "minor": { "type": "integer", "minimum": 1, "description": "Unités mineures." },
                            "currency": { "type": "string", "description": "Code ISO 4217, identique à celui de `daily_total`." }
                        },
                        "required": ["minor", "currency"]
                    },
                    "daily_transactions": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Nombre de paiements par jour. C'est ce qui empêche un gros paiement d'être découpé en beaucoup de petits, tous légaux."
                    }
                }),
                &["id", "daily_total", "per_transaction", "daily_transactions"],
            ),
            query: &[],
            raw_body: None,
            risk: Risk::Write,
        },
        ToolDef {
            name: "employees_reports_list",
            title: "L'équipe d'un siège, et ce qu'elle coûte",
            description: "Rend, pour un siège, la ligne de chacun de ses subordonnés **directs** : \
                 tours joués, jetons, plafond de tours, dépense du jour face au plafond, et ce qui \
                 est resté sans réponse. Un seul lien, jamais l'arbre entier — la ligne du \
                 responsable du dessous se demande avec son propre identifiant — et il n'y a pas \
                 de coût en euros ici, seulement la mesure. L'`id` vient d'`employees_list`, et \
                 les subordonnés d'un siège se lisent aussi, sans chiffres, sur \
                 `teams_members_list`. À utiliser quand la question est « que font les gens sous \
                 lui » ; pour ses propres tours, `employees_turns_get`, et pour ce qui le borne, \
                 `controls_get`.",
            method: Method::Get,
            path: "/v1/employees/{id}/reports",
            schema: schema(
                json!({
                    "id": { "type": "string", "format": "uuid", "description": "Le siège dont on lit la ligne. Un siège d'un autre locataire est un 404." }
                }),
                &["id"],
            ),
            query: &[],
            raw_body: None,
            risk: Risk::Read,
        },
        ToolDef {
            name: "events_list",
            title: "Le journal de ce que l'entreprise a fait",
            description: "Rend le journal d'activité — un verdict, un envoi, un message reçu, un \
                 changement de configuration — avec une étiquette d'autonomie par ligne et un \
                 curseur `next_since` pour reprendre. Sans `since` la page part des plus récents \
                 vers le passé ; **avec `since` elle repart de la marque vers le présent**, ce qui \
                 est ce qu'il faut pour rattraper une nuit sans rien sauter, et `limit` est un \
                 plancher de page (un groupe d'événements au même horodatage n'est jamais coupé). \
                 Aucun texte de tiers n'en sort. À utiliser quand la question est « qu'a fait \
                 cette entreprise, et dans quel ordre » ; pour « est-ce que ça tourne encore », \
                 `company_health_get` répond en un appel et en trois mots.",
            method: Method::Get,
            path: "/v1/events",
            schema: schema(
                json!({
                    "since": {
                        "type": "string",
                        "format": "date-time",
                        "description": "Le `next_since` de la page précédente, en RFC 3339 terminé par `Z`. Exclusif : l'événement qui a posé la marque n'est pas rendu deux fois."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 200,
                        "description": "Taille de page visée. Défaut 50, plafonnée à 200, et dépassée de quelques lignes plutôt que de couper un horodatage en deux."
                    }
                }),
                &[],
            ),
            query: &["since", "limit"],
            raw_body: None,
            risk: Risk::Read,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find(name: &str) -> ToolDef {
        tools()
            .into_iter()
            .find(|t| t.name == name)
            .unwrap_or_else(|| panic!("{name} n'est pas dans la table"))
    }

    /// Ce que le schéma d'un outil exige.
    fn required(tool: &ToolDef) -> Vec<String> {
        tool.schema
            .get("required")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// L'exécuteur préfixe l'hôte et joue le chemin tel quel : un chemin qui ne
    /// commence pas par `/v1/` ne tombe sur aucune route de ce déploiement.
    #[test]
    fn every_path_is_a_v1_route_with_no_unnamed_hole() {
        for tool in tools() {
            assert!(
                tool.path.starts_with("/v1/"),
                "{}: {}",
                tool.name,
                tool.path
            );
            let properties = tool.properties();
            for hole in tool.placeholders() {
                assert!(
                    properties.contains(&hole),
                    "{}: le chemin demande {hole:?} et le schéma ne le nomme pas",
                    tool.name
                );
            }
        }
        // La garde désarmée : sans la boucle ci-dessus, cette ligne passerait.
        let disarmed = ToolDef {
            path: "/v1/quotes/{id}/accepted",
            schema: schema(json!({}), &[]),
            ..find("quotes_accept")
        };
        assert_eq!(disarmed.placeholders(), vec!["id"]);
        assert!(
            !disarmed.properties().contains(&"id"),
            "le cas que la garde doit attraper"
        );
    }

    /// Un trou du chemin qui partirait *aussi* en chaîne de requête serait
    /// envoyé deux fois ; une clé de `query` que le schéma ne déclare pas ne
    /// serait jamais remplie.
    #[test]
    fn every_query_key_is_a_declared_property_and_never_a_path_hole() {
        for tool in tools() {
            let properties = tool.properties();
            let holes = tool.placeholders();
            for key in tool.query {
                assert!(
                    properties.contains(key),
                    "{}: `query` nomme {key:?}, absent du schéma",
                    tool.name
                );
                assert!(
                    !holes.contains(key),
                    "{}: {key:?} est un trou du chemin *et* une clé de requête",
                    tool.name
                );
            }
        }
    }

    /// [`Risk`] devient `readOnlyHint` / `destructiveHint`. Une lecture annoncée
    /// destructrice fait confirmer un `GET` ; une suppression annoncée en
    /// lecture ne fait rien confirmer du tout.
    #[test]
    fn the_risks_agree_with_the_verbs() {
        for tool in tools() {
            assert!(
                !(tool.method == Method::Get && tool.risk == Risk::Destructive),
                "{}: un GET annoncé destructeur",
                tool.name
            );
            assert!(
                !(tool.method == Method::Delete && tool.risk == Risk::Read),
                "{}: un DELETE annoncé en lecture seule",
                tool.name
            );
            if tool.method == Method::Get {
                assert!(tool.risk.read_only(), "{}", tool.name);
            }
        }
        // Désarmée : les deux formes que la garde refuse existent bien comme
        // valeurs — c'est la boucle, et elle seule, qui les tient dehors.
        let lying_get = ToolDef {
            raw_body: None,
            risk: Risk::Destructive,
            ..find("pnl_get")
        };
        assert_eq!(lying_get.method, Method::Get);
        assert!(lying_get.risk.destructive());
        let lying_delete = ToolDef {
            raw_body: None,
            risk: Risk::Read,
            ..find("domains_remove")
        };
        assert_eq!(lying_delete.method, Method::Delete);
        assert!(lying_delete.risk.read_only());
    }

    /// Les trois gestes qui engagent l'entreprise devant quelqu'un d'autre : un
    /// envoi, un document commercial, et un contact mis sur une machine qui lui
    /// écrira. Un client qui ne les fait pas confirmer les joue en silence.
    #[test]
    fn what_engages_the_company_before_a_third_party_is_destructive() {
        for name in [
            // l'envoi : quarante inconnus marqués contactés, le budget dépensé
            "prospects_queue_export",
            // le document : un avoir part chez le client (il n'existe aucune
            // route d'*émission* de facture, par construction — voir le module)
            "invoices_credit",
            // la machine qui écrira à quelqu'un
            "sequences_enroll",
            // l'argent déclaré arrivé, une fois, sans retour
            "invoices_payment_record",
            "quotes_accept",
            "domains_remove",
        ] {
            let tool = find(name);
            assert!(
                tool.risk.destructive(),
                "{name} doit être Destructive : c'est ce qui décide de la confirmation"
            );
            assert!(!tool.risk.read_only(), "{name}");
        }
    }

    // -----------------------------------------------------------------------
    // Une famille, un test : le schéma exige ce que la route exige.
    // -----------------------------------------------------------------------

    /// `POST /v1/sequences` refuse un nom vide et une liste sans pas `email` ;
    /// `enroll` a besoin du contact **et** du siège qui écrira.
    #[test]
    fn the_sequence_family_asks_for_what_the_routes_check() {
        let define = find("sequences_create");
        assert_eq!(required(&define), ["name", "steps"]);
        let steps = &define.schema["properties"]["steps"];
        assert_eq!(steps["maxItems"], json!(12));
        assert_eq!(steps["minItems"], json!(1));
        let kinds: Vec<&str> = steps["items"]["oneOf"]
            .as_array()
            .expect("les trois formes de pas")
            .iter()
            .map(|s| s["properties"]["kind"]["const"].as_str().expect("kind"))
            .collect();
        assert_eq!(kinds, ["email", "wait", "branch"]);

        let enroll = find("sequences_enroll");
        assert_eq!(required(&enroll), ["id", "contact_id", "employee_id"]);
        assert!(enroll.query.is_empty(), "tout part dans le corps");
    }

    /// Un domaine se nomme pour être enregistré ou retiré ; le plafond veut le
    /// domaine (dans le chemin) *et* un nombre ; `verify` et `dns` savent
    /// travailler sur la primaire, donc `domain` y est facultatif.
    #[test]
    fn the_domain_family_asks_for_what_the_routes_check() {
        assert_eq!(required(&find("domains_register")), ["domain"]);
        assert_eq!(required(&find("domains_remove")), ["domain"]);
        assert_eq!(required(&find("domains_cap_set")), ["domain", "daily_cap"]);
        assert_eq!(
            find("domains_cap_set").schema["properties"]["daily_cap"]["minimum"],
            json!(1),
            "un plafond de zéro est un 400 bad_cap"
        );
        assert_eq!(required(&find("domains_verify")), Vec::<String>::new());
        assert_eq!(
            required(&find("domains_dns_publish")),
            ["cloudflare_api_token"]
        );
    }

    /// L'export de file n'a pas de corps : tout ce dont il a besoin est déjà
    /// une valeur stockée, et un corps serait un second endroit où écrire une
    /// limite.
    #[test]
    fn the_queue_family_asks_for_a_seat_and_nothing_else() {
        let export = find("prospects_queue_export");
        assert_eq!(required(&export), ["id"]);
        assert_eq!(export.properties(), vec!["id"]);
        assert!(export.query.is_empty());
    }

    /// Un avoir est un montant et un motif ; une réponse à un devis et un
    /// règlement n'ont **aucun** corps — l'instant est celui du serveur.
    #[test]
    fn the_invoice_and_quote_family_asks_for_what_the_routes_check() {
        let credit = find("invoices_credit");
        assert_eq!(required(&credit), ["id", "amount_minor", "memo"]);
        assert_eq!(
            credit.schema["properties"]["memo"]["maxLength"],
            json!(200),
            "invoices_memo_shape"
        );
        assert!(
            credit.schema["properties"].get("currency").is_none(),
            "la devise est celle de la facture corrigée, jamais une seconde réponse"
        );
        for name in ["invoices_payment_record", "quotes_accept", "quotes_decline"] {
            let tool = find(name);
            assert_eq!(tool.properties(), vec!["id"], "{name}");
            assert_eq!(required(&tool), ["id"], "{name}");
        }
        assert!(
            !tools().iter().any(|t| t.name == "invoices_issue"),
            "aucune route n'émet une facture : seul un employé le fait, avec un jeton de la Policy \
             Gate"
        );
    }

    /// L'export comptable exige le journal ; les trois lectures de fenêtre
    /// prennent `days` **ou** `from`/`to`, en chaîne de requête.
    #[test]
    fn the_books_family_asks_for_a_journal_and_a_window() {
        let export = find("accounting_export");
        assert_eq!(required(&export), ["journal"]);
        assert_eq!(
            export.schema["properties"]["journal"]["enum"],
            json!(["invoices", "spend", "usage"])
        );
        for name in ["pnl_get", "outreach_summary_get", "accounting_export"] {
            let tool = find(name);
            for key in WINDOW {
                assert!(tool.query.contains(key), "{name}: {key}");
            }
        }
        assert_eq!(find("billing_worked_seats_get").query.to_vec(), ["month"]);
        assert_eq!(
            find("forecast_get").schema["properties"]["days"]["maximum"],
            json!(90),
            "au-delà d'un trimestre, les entrées sont plus périssables que la réponse"
        );
        assert_eq!(
            required(&find("forecast_get")),
            ["days"],
            "la route refuse une fenêtre absente : il n'y a pas de défaut honnête"
        );
    }

    /// Les plafonds sont par devise, des deux côtés : le `GET` la nomme en
    /// requête, le `PUT` la porte dans chacun de ses deux montants.
    #[test]
    fn the_spend_family_is_per_currency_on_both_sides() {
        let get = find("spend_caps_get");
        assert_eq!(required(&get), ["id", "currency"]);
        assert_eq!(get.query.to_vec(), ["currency"]);

        let set = find("spend_caps_set");
        assert_eq!(
            required(&set),
            ["id", "daily_total", "per_transaction", "daily_transactions"]
        );
        for money in ["daily_total", "per_transaction"] {
            let field = &set.schema["properties"][money];
            assert_eq!(field["required"], json!(["minor", "currency"]), "{money}");
            assert_eq!(field["properties"]["minor"]["minimum"], json!(1), "{money}");
        }
        assert_eq!(
            set.schema["properties"]["daily_transactions"]["minimum"],
            json!(1),
            "zéro transaction n'a pas d'orthographe : c'est l'absence de ligne"
        );
    }

    /// Le curseur du journal et les fenêtres de lecture partent en chaîne de
    /// requête ; aucune de ces lectures n'a de corps.
    #[test]
    fn the_reading_family_puts_its_window_in_the_query_string() {
        for name in [
            "events_list",
            "usage_get",
            "usage_models_get",
            "outreach_health_get",
            "billing_get",
            "forecast_get",
        ] {
            let tool = find(name);
            assert_eq!(tool.method, Method::Get, "{name}");
            let mut declared = tool.properties();
            declared.sort_unstable();
            let mut in_query: Vec<&str> = tool.query.to_vec();
            in_query.sort_unstable();
            assert_eq!(
                declared, in_query,
                "{name}: rien ne doit rester pour un corps"
            );
        }
        assert_eq!(
            required(&find("usage_models_get")),
            Vec::<String>::new(),
            "la route a un défaut de 7 jours : exiger `days` serait exiger plus qu'elle"
        );
        assert_eq!(
            find("events_list").schema["properties"]["limit"]["maximum"],
            json!(200)
        );
    }

    /// Les lectures sans aucune entrée : un schéma vide, et pas un schéma
    /// absent — un client qui n'y trouve pas `properties` invente un argument.
    #[test]
    fn the_input_less_readings_still_declare_an_object() {
        for name in [
            "prospects_segments_list",
            "sequences_list",
            "domains_primary_get",
            "domains_list",
            "invoices_issuer_get",
        ] {
            let tool = find(name);
            assert_eq!(tool.schema["type"], json!("object"), "{name}");
            assert!(tool.properties().is_empty(), "{name}");
            assert!(tool.query.is_empty(), "{name}");
            assert!(tool.risk.read_only(), "{name}");
        }
    }

    /// **Ce test disait l'inverse jusqu'au 2026-09-11**, et c'est la bonne
    /// forme de dette : il affirmait que l'import n'était pas là parce que le
    /// contrat d'exécution ne savait pas porter un corps `text/csv`, et il
    /// nommait la ligne qui tomberait le jour où il le saurait. Le champ
    /// `raw_body` est arrivé ; la voici tombée, et remplacée par la garde qui
    /// compte désormais — la route refuse en 415 tout ce qui n'est pas du CSV,
    /// donc annoncer un corps JSON ici serait un outil qui échoue à chaque
    /// appel.
    #[test]
    fn the_csv_import_carries_its_body_raw_and_not_as_json() {
        let tool = find("prospects_import");
        assert_eq!(
            tool.raw_body,
            Some(("text/csv", "csv")),
            "la route lit des octets et refuse le JSON en 415"
        );
        assert!(
            tool.properties().contains(&"csv"),
            "la propriété qui porte le corps doit être déclarée au schéma"
        );
        // Le reste part en chaîne de requête : la route les lit là, et un
        // corps brut n'a pas de place pour eux.
        for key in ["segment", "country", "dry_run"] {
            assert!(tool.query.contains(&key), "{key}");
        }
    }
}

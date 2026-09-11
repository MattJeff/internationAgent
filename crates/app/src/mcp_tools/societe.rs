//! Ce que la société **est** : les quatorze modules de routes qui décrivent
//! l'entreprise elle-même — ses employés, son organigramme, ses limites, son
//! bouton d'arrêt — rendus comme des lignes de table plutôt que du code.
//!
//! Le lecteur qui cherche ce que la société *vend* est dans
//! [`super::commerce`] ; ce qu'elle *exploite*, dans [`super::exploitation`].
//!
//! # L'ordre est celui d'une prise en main
//!
//! `company_create` d'abord, parce que rien n'existe avant lui ; puis
//! l'organigramme, les sièges, le bureau où on leur parle, les approbations
//! qu'ils demandent, les limites qui les bornent, et enfin l'interrupteur. Un
//! modèle qui lit la liste de haut en bas lit le mode d'emploi.
//!
//! # D'où viennent les identifiants
//!
//! Presque chaque ligne demande un UUID, et aucune ne les invente : les
//! employés sortent de `employees_list`, les équipes de `teams_list`, les
//! approbations de `approvals_list`. Chaque `description` le dit, parce qu'un
//! modèle qui doit deviner appelle la route avec un identifiant faux et lit un
//! 404 qu'il croit être une erreur de sa part.
//!
//! # Le risque, ligne par ligne
//!
//! [`Risk::Destructive`] est mis partout où l'appel **retire** quelque chose
//! (`DELETE`, un `PUT` de remplacement qui efface les champs omis, une
//! résiliation), **annule** (refuser une approbation), ou **engage la société**
//! (approuver une dépense, arrêter ou relancer l'entreprise). Il n'est pas mis
//! sur ce qui ajoute sans rien reprendre : un message au bureau réveille un
//! siège et lui coûte un tour, ce qui est cher, mais n'enlève rien et n'engage
//! personne devant un tiers.

use serde_json::{Value, json};

use crate::mcp_server::{Method, Risk, ToolDef};

/// Fabrique une ligne. Purement local : huit champs répétés quarante-cinq fois,
/// c'est quarante-cinq occasions d'en oublier un.
#[allow(clippy::too_many_arguments)]
fn t(
    name: &'static str,
    title: &'static str,
    description: &'static str,
    method: Method,
    path: &'static str,
    schema: Value,
    query: &'static [&'static str],
    risk: Risk,
) -> ToolDef {
    ToolDef {
        name,
        title,
        description,
        method,
        path,
        schema,
        query,
        // Aucune route de ce domaine ne prend autre chose que du JSON ; le
        // corps brut existe pour l'import de prospects, côté commerce.
        raw_body: None,
        risk,
    }
}

/// Un schéma sans aucune propriété : la route ne prend ni trou, ni requête, ni
/// corps. Le corps vide n'est alors pas envoyé du tout, ce qui est ce qu'un
/// `DELETE` sans corps veut dire.
fn nothing() -> Value {
    json!({ "type": "object", "properties": {}, "required": [] })
}

/// Le seul argument le plus fréquent de cette table : l'UUID d'un siège.
fn employee_id_only(what: &'static str) -> Value {
    json!({
        "type": "object",
        "properties": { "id": { "type": "string", "format": "uuid", "description": what } },
        "required": ["id"],
    })
}

/// Les lignes de ce domaine.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn tools() -> Vec<ToolDef> {
    vec![
        // -------------------------------------------------------------------
        // Le registre public : la seule chose que cette société publie d'elle
        // -------------------------------------------------------------------
        // -------------------------------------------------------------------
        // Les clés : ce avec quoi un terminal se présente
        // -------------------------------------------------------------------
        t(
            "keys_list",
            "Les clés de cette société, sans leurs secrets",
            "Rend les clés d'API que cette entreprise a émises — leur nom, leur identifiant, \
             leur date — et **jamais leur secret** : il n'est montré qu'une fois, à la création. \
             Sert à savoir quels terminaux ou services sont branchés avant d'en retirer un. Les \
             sessions de la console n'y figurent pas : ce ne sont pas des clés qu'on distribue, \
             et les retirer déconnecterait la personne qui regarde. L'identifiant rendu ici est \
             celui que `keys_remove` prend.",
            Method::Get,
            "/v1/keys",
            nothing(),
            &[],
            Risk::Read,
        ),
        t(
            "keys_create",
            "Une clé pour brancher un terminal ou un service",
            "Émet une clé d'API pour cette entreprise et rend son secret — **une seule fois, \
             ici** : il n'est relisible nulle part ensuite, et une clé perdue se remplace, elle \
             ne se retrouve pas. Le `label` la nomme (« claude-code », « ci », le nom d'un \
             service) ; il porte aussi le rôle, et une étiquette qui réclamerait un rôle que \
             l'appelant ne tient pas est refusée. C'est l'outil qui prépare la commande \
             d'installation d'un client MCP ; `keys_list` montre ensuite ce qui est branché.",
            Method::Post,
            "/v1/keys",
            json!({
                "type": "object",
                "properties": {
                    "label": {
                        "type": "string",
                        "description": "le nom de la clé, par exemple « claude-code »"
                    }
                },
            }),
            &[],
            Risk::Write,
        ),
        t(
            "keys_remove",
            "Retirer une clé, et couper ce qu'elle ouvrait",
            "Révoque une clé : tout ce qui s'en servait cesse d'entrer à l'instant, sans \
             préavis et sans retour — le secret n'étant relisible nulle part, une clé retirée \
             par erreur se remplace par une neuve et se recolle partout. L'identifiant vient de \
             `keys_list`. À faire quand un terminal est perdu, qu'un service est débranché, ou \
             qu'une clé a traîné quelque part.",
            Method::Delete,
            "/v1/keys/{id}",
            json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string", "description": "l'identifiant rendu par `keys_list`" }
                },
                "required": ["id"],
            }),
            &[],
            Risk::Destructive,
        ),
        t(
            "company_health_get",
            "Est-ce que cette société travaille encore ?",
            "Rend, en un appel, si les employés prennent leurs tours ou non : combien tentés et \
             combien ratés aujourd'hui, la date du dernier qui a réussi, le code et la phrase du \
             dernier échec, et un verdict — `working`, `degraded`, `stopped`. **C'est le premier \
             outil à appeler quand quelque chose semble immobile** : un employé qui ne répond pas, \
             une campagne qui n'avance pas, une demande sans suite. Une société au repos rend \
             `working` et pas `degraded` : ne rien avoir à faire n'est pas une panne. `stopped` \
             nomme la cause dans `last_failure_detail`, et c'est presque toujours la connexion au \
             modèle. Trois suites selon le verdict : `stopped` va voir `model_get` puis \
             `halt_get`, `degraded` va lire `refusals_get` et `events_list`, et un `working` sur \
             une société qui n'avance quand même pas va voir `initiatives_list` — un siège sans \
             cadence ne se réveille jamais tout seul.",
            Method::Get,
            "/v1/health/company",
            nothing(),
            &[],
            Risk::Read,
        ),
        t(
            "public_register_get",
            "Lire le registre public : ce que les gates des entreprises consentantes ont arrêté",
            "Rend le tableau public, en temps réel, de ce que les politiques ont refusé chez les \
             entreprises qui l'ont accepté. Sert à situer la vôtre, et à répondre à « à quoi sert \
             la gate » par un chiffre plutôt que par une phrase. Lecture publique : aucune donnée \
             d'un locataire n'y figure sans son consentement explicite, et une entreprise qui n'a \
             rien accepté n'apparaît pas, même agrégée. Le consentement de cette société-ci se \
             bascule avec `public_register_consent_set`, et ce que sa propre gate a refusé se lit \
             sur `refusals_get`.",
            Method::Get,
            "/v1/public-register",
            nothing(),
            &[],
            Risk::Read,
        ),
        t(
            "public_register_consent_set",
            "Décider si cette société figure au registre public",
            "Bascule le consentement de cette entreprise à figurer au registre public. `consent: \
             true` la publie, `false` la retire. C'est une décision du fondateur et pas un \
             réglage : à `true`, un chiffre tiré de vos refus devient visible de n'importe qui. La \
             bascule et sa ligne d'audit sont écrites dans la même transaction, donc un registre \
             qui montre une entreprise montre aussi quand elle a dit oui. Ce que la bascule publie \
             se relit sur `public_register_get`.",
            Method::Post,
            "/v1/public-register/consent",
            json!({
                "type": "object",
                "properties": {
                    "consent": {
                        "type": "boolean",
                        "description": "true publie cette société au registre, false l'en retire"
                    }
                },
                "required": ["consent"],
            }),
            &[],
            Risk::Destructive,
        ),
        // -------------------------------------------------------------------
        // La société : la porte par laquelle tout commence
        // -------------------------------------------------------------------
        t(
            "company_create",
            "Créer la société : organigramme, limites par rôle et date d'arrêt, en un appel",
            "Monte une société entière — la ligne « tenant », l'organigramme complet, une couche \
             de limites par rôle, et l'instant où ses agents s'arrêtent — en une seule \
             transaction. À utiliser une fois, sur une société qui n'existe pas encore : elle ne \
             remplace jamais rien, un rôle dont la couche diffère est un 409 `role_layer_exists` \
             et une fenêtre différente un 409 `window_exists`. Trois refus, avant toute écriture : \
             `window_ends_at` est obligatoire et sans défaut (une durée serait un prix que \
             personne ici n'a le droit d'inventer), chaque `team` cité dans `org.rows` doit avoir \
             son entrée dans `roles` (une couche absente hérite du plafond, donc un siège sans \
             couche devient l'employé le plus permissif de la maison), et chaque valeur de `roles` \
             est un document de limites **complet** — un champ manquant n'est pas « ne touche pas \
             », c'est un remplacement total qui coûte au siège ses canaux, ses domaines et son \
             modèle. Ensuite, pour éditer, c'est `org_apply` ; pour retoucher une limite, \
             `policy_role_set`.",
            Method::Post,
            "/v1/companies",
            json!({
                "type": "object",
                "properties": {
                    "slug": {
                        "type": "string",
                        "description": "Le handle de la société. Doit correspondre au tenant que porte la clé d'API : un autre nom est un 409 `tenant_mismatch`, c'est-à-dire la mauvaise clé dans le terminal.",
                    },
                    "name": {
                        "type": "string",
                        "description": "La société telle qu'on l'écrit : « Orizn ».",
                    },
                    "org": {
                        "type": "object",
                        "description": "L'organigramme, exactement la forme que prend `org_apply` : `{ domain?, rows: [...] }`.",
                        "properties": {
                            "domain": { "type": "string" },
                            "rows": { "type": "array", "items": { "type": "object" } },
                        },
                        "required": ["rows"],
                    },
                    "window_ends_at": {
                        "type": "string",
                        "format": "date-time",
                        "description": "Quand les agents de cette société s'arrêtent, en instant UTC — pas en durée. Obligatoire, et doit être dans le futur.",
                    },
                    "roles": {
                        "type": "object",
                        "description": "Un document de limites complet par `role_name` (le slug d'équipe), du même format que le corps de `policy_role_set`.",
                        "additionalProperties": { "type": "object" },
                    },
                },
                "required": ["slug", "name", "org", "window_ends_at", "roles"],
            }),
            &[],
            Risk::Write,
        ),
        // -------------------------------------------------------------------
        // Les employés
        // -------------------------------------------------------------------
        t(
            "employees_list",
            "La liste des sièges de cette société, du plus ancien au plus récent",
            "Rend les employés du locataire avec leur `id`, leur `slug` et leur cycle de vie, page \
             par page. C'est la source des UUID que presque toutes les autres lignes de cette \
             table réclament — appelle-la d'abord plutôt que de deviner un identifiant. Pagination \
             par clé : `limit` (50 par défaut, 200 au plus) et `after`, qui est le dernier `id` de \
             la page précédente ; une page pleine porte `next_after`, une page courte termine la \
             marche. L'`id` d'ici ouvre `employees_get` (le détail d'un siège), `initiatives_get` \
             (ce qu'il fait), `employees_turns_get` (ce qu'il a consommé aujourd'hui) et \
             `controls_get` (ce qui le borne).",
            Method::Get,
            "/v1/employees",
            json!({
                "type": "object",
                "properties": {
                    "after": {
                        "type": "string",
                        "format": "uuid",
                        "description": "Le `next_after` de la page précédente. Absent, on commence au début.",
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 200,
                        "description": "Nombre de lignes. 50 par défaut, borné à 200.",
                    },
                },
                "required": [],
            }),
            &["after", "limit"],
            Risk::Read,
        ),
        t(
            "employees_get",
            "Un siège en entier : cycle de vie, santé, et l'état de ses onze ressources",
            "Rend un employé complet — son adresse, son `lifecycle`, sa santé dérivée, les onze \
             étapes de provisionnement avec leur fournisseur, et les appels fournisseur partis \
             sans revenir. À utiliser quand `employees_list` ne suffit pas : c'est ici qu'on voit \
             *pourquoi* un siège reste en `draft` ou porte une santé dégradée. L'`id` vient de \
             `employees_list` ; un identifiant d'une autre société est un 404, jamais un 403.",
            Method::Get,
            "/v1/employees/{id}",
            employee_id_only("L'UUID du siège, tel que `employees_list` le rend."),
            &[],
            Risk::Read,
        ),
        t(
            "employees_create",
            "Embaucher un siège : la ligne, ses onze ressources en attente, et l'événement qui les fait acheter",
            "Crée un employé et le remet au provisionneur. Répond **202 et jamais 201** : la ligne \
             existe, mais rien de ce qu'il lui faut pour travailler n'existe encore — boîte mail, \
             numéro, identité sont `pending` et une boucle vient les chercher. À utiliser pour un \
             siège isolé ; pour monter ou corriger tout un organigramme d'un coup, `org_apply` \
             embauche aussi et le fait en une transaction. Le `slug` devient la partie locale de \
             l'adresse et l'identité du siège : il ne se change plus après. **Un siège ne peut pas \
             s'asseoir sur un domaine non vérifié** : le domaine qu'on lui donne ici doit être \
             passé par `domains_verify`, sinon la ligne existe et rien ne partira jamais de cette \
             adresse. Et embaucher ne dit pas à quoi le siège sert : c'est `initiatives_set` qui \
             lui donne un objectif et une cadence, sans quoi il ne se réveillera jamais tout seul.",
            Method::Post,
            "/v1/employees",
            json!({
                "type": "object",
                "properties": {
                    "slug": {
                        "type": "string",
                        "description": "Le handle de l'employé, et la partie locale de son adresse. Identité définitive.",
                    },
                    "domain": {
                        "type": "string",
                        "description": "Le domaine d'envoi, par exemple `agents.example.com` — un des domaines du locataire, enregistré au passage s'il ne l'a pas encore. Absent : le domaine principal du locataire.",
                    },
                },
                "required": ["slug"],
            }),
            &[],
            Risk::Write,
        ),
        t(
            "employees_suspend",
            "Mettre un siège en pause, sans rien lui reprendre",
            "Passe l'employé en `suspended` : il cesse d'agir — plus de tour, plus de réveil, plus \
             de jeton d'autorisation — mais **rien ne lui est retiré**. Son tableau de travail, \
             ses rendez-vous futurs et ses ressources restent à lui, et `employees_resume` le \
             remet exactement où il était. C'est le verbe à choisir quand on hésite avec \
             `employees_terminate`, qui, lui, est irréversible et rend tout. Un employé \
             `terminated` refuse la suspension par un 409.",
            Method::Post,
            "/v1/employees/{id}/suspend",
            employee_id_only("L'UUID du siège à mettre en pause, depuis `employees_list`."),
            &[],
            Risk::Destructive,
        ),
        t(
            "employees_resume",
            "Remettre au travail un siège suspendu",
            "L'inverse exact de `employees_suspend`, et seulement lui : `suspended → active`. Il \
             ne restaure rien parce qu'une suspension n'avait rien pris ; la semaine d'absence \
             n'est pas rejouée, l'initiative repart sur sa propre horloge. Deux refus distincts : \
             un siège `terminated` est un 409 `illegal_lifecycle` (l'état est absorbant et ses \
             ressources ont déjà été rendues), un siège `draft` est un 409 \
             `draft_is_not_resumable` — ce passage-là appartient à la boucle de provisionnement \
             seule, et le forcer donnerait un employé actif ne possédant ni numéro, ni boîte, ni \
             identité.",
            Method::Post,
            "/v1/employees/{id}/resume",
            employee_id_only("L'UUID du siège suspendu, depuis `employees_list`."),
            &[],
            Risk::Write,
        ),
        t(
            "employees_terminate",
            "Fin de vie d'un siège : absorbant, et il rend tout",
            "Passe l'employé en `terminated`, état **absorbant** : rien n'en sort, une suspension \
             postérieure est un 409 et il n'y a pas de verbe pour revenir. Dans la même \
             transaction, son tableau de travail retourne au pot non assigné et ses rendez-vous à \
             venir sont annulés ; ses ressources fournisseur — numéro, boîte — sont rendues juste \
             après par le gestionnaire d'événement, ce qui coûte de l'argent réel à ré-acheter. À \
             n'utiliser que si `employees_suspend`, qui est réversible et ne reprend rien, ne \
             suffit pas.",
            Method::Post,
            "/v1/employees/{id}/terminate",
            employee_id_only("L'UUID du siège à résilier, depuis `employees_list`."),
            &[],
            Risk::Destructive,
        ),
        // -------------------------------------------------------------------
        // L'organigramme
        // -------------------------------------------------------------------
        t(
            "org_apply",
            "L'organigramme entier, appliqué d'un bloc et en une transaction",
            "Applique le tableau de l'opérateur — *Fonction, Responsable, Mission* — d'un seul \
             coup : équipes créées ou renommées, employés manquants embauchés, missions écrites, \
             lignes hiérarchiques tracées, le tout dans une transaction, donc une mauvaise ligne 7 \
             défait l'équipe de la ligne 1. C'est le verbe à préférer dès qu'on touche plus d'un \
             siège : le document est déclaratif, on le ré-applique après l'avoir édité et cela \
             converge sans clé d'idempotence. Il **n'enlève jamais** : une équipe ou un siège \
             tombé du document reste debout, et sortir quelqu'un est `teams_members_remove`. Il \
             **n'accorde rien** non plus — pas une ligne de `policy_layers` n'est écrite ici, une \
             mission est de la prose et jamais une limite. Réponses : 202 s'il a embauché, 200 \
             sinon ; 400 si deux lignes nomment la même équipe ou le même responsable, ou si un \
             `reports_to` désigne un responsable qu'aucune ligne ne définit ; 409 \
             `reporting_cycle` si une ligne ferme une boucle. 500 lignes au plus.",
            Method::Post,
            "/v1/org",
            json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Le domaine d'envoi donné aux employés que cet appel embauche. Ignoré pour un employé déjà existant, dont l'adresse a été frappée à sa création.",
                    },
                    "rows": {
                        "type": "array",
                        "maxItems": 500,
                        "description": "Une ligne par fonction, dans n'importe quel ordre : tous les sièges sont résolus avant qu'une seule ligne hiérarchique soit tracée, donc le CEO peut être la dernière ligne.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "team": {
                                    "type": "string",
                                    "description": "La fonction comme handle : le slug de l'équipe, et l'identité sur laquelle le document est ré-apparié. C'est aussi le `role_name` sous lequel ses limites seront lues **si l'équipe est neuve** ; le pointeur d'une équipe existante n'est jamais déplacé ici.",
                                },
                                "name": {
                                    "type": "string",
                                    "description": "La fonction telle que l'opérateur l'écrit : « Produit et technologie ».",
                                },
                                "mission": {
                                    "type": "string",
                                    "description": "Ce à quoi sert cette fonction. De la prose, jamais une limite.",
                                },
                                "head": {
                                    "type": "string",
                                    "description": "Le responsable comme handle : le slug de l'employé. Un employé que ce locataire n'a pas encore est embauché.",
                                },
                                "title": {
                                    "type": "string",
                                    "description": "Le responsable tel que l'opérateur l'écrit : « CFO externalisé ». Texte d'affichage ; rien ne s'y résout et rien n'y est accordé.",
                                },
                                "reports_to": {
                                    "type": "string",
                                    "description": "Le `head` d'une autre ligne du même document. Absent : un siège sans personne au-dessus, ce à quoi ressemble la ligne du CEO.",
                                },
                            },
                            "required": ["team", "name", "mission", "head", "title"],
                        },
                    },
                },
                "required": ["rows"],
            }),
            &[],
            Risk::Write,
        ),
        t(
            "teams_list",
            "Les équipes de cette société, par slug",
            "Rend chaque équipe avec son `id`, son slug, son nom, sa mission et le `role_name` \
             sous lequel ses limites sont lues. C'est la source des `team_id` que réclament toutes \
             les lignes `teams_*` ci-dessous. Le `team_id` d'ici va dans `teams_members_list`, \
             `teams_budget_get`, `teams_mission_set` et `teams_policy_role_set`.",
            Method::Get,
            "/v1/teams",
            nothing(),
            &[],
            Risk::Read,
        ),
        t(
            "teams_create",
            "Une équipe, et la portée de politique par laquelle elle lira ses limites",
            "Crée une équipe seule. 201 et non 202 : contrairement à un employé, une équipe est \
             finie dès que la ligne est écrite — rien n'est provisionné, personne ne vient la \
             chercher. Le `slug` sert aussi de `role_name` initial, ce qui ne **crée pas** ses \
             limites : tant que personne n'a écrit de couche sous ce rôle, l'équipe hérite de \
             celle du locataire, c'est-à-dire de la plus large. Pour monter plusieurs équipes à la \
             fois avec leurs responsables, `org_apply`.",
            Method::Post,
            "/v1/teams",
            json!({
                "type": "object",
                "properties": {
                    "slug": {
                        "type": "string",
                        "description": "Le handle de l'équipe, **et** le `role_name` sous lequel sa couche de politique sera écrite.",
                    },
                    "name": {
                        "type": "string",
                        "description": "Le libellé humain. Texte libre ; rien ne s'y résout.",
                    },
                },
                "required": ["slug", "name"],
            }),
            &[],
            Risk::Write,
        ),
        t(
            "teams_sections_list",
            "Les sous-unités d'une équipe",
            "Rend les sections d'une équipe — EMEA dans achats, niveau 1 dans support. Le \
             `team_id` vient de `teams_list`. Une section ne porte ni politique ni budget : ces \
             deux-là sont à l'équipe.",
            Method::Get,
            "/v1/teams/{team_id}/sections",
            json!({
                "type": "object",
                "properties": {
                    "team_id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "L'UUID de l'équipe, depuis `teams_list`.",
                    },
                },
                "required": ["team_id"],
            }),
            &[],
            Risk::Read,
        ),
        t(
            "teams_sections_create",
            "Une sous-unité dans une équipe",
            "Crée une section : EMEA dans achats, niveau 1 dans support. Purement \
             organisationnel — aucune politique et aucun budget ne s'y attachent, ni ici ni \
             ailleurs. Une section n'est utile que si `teams_members_add` ou `teams_members_set` y \
             place quelqu'un, et elle appartient à exactement une équipe.",
            Method::Post,
            "/v1/teams/{team_id}/sections",
            json!({
                "type": "object",
                "properties": {
                    "team_id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "L'UUID de l'équipe, depuis `teams_list`.",
                    },
                    "slug": { "type": "string", "description": "Le handle de la section." },
                    "name": { "type": "string", "description": "Le libellé humain." },
                },
                "required": ["team_id", "slug", "name"],
            }),
            &[],
            Risk::Write,
        ),
        t(
            "teams_members_list",
            "Le trombinoscope d'une équipe, du plus ancien membre au plus récent",
            "Rend qui est sur cette équipe, avec la section, le titre et la ligne hiérarchique de \
             chaque siège. À lire avant `teams_members_remove` : ôter un responsable qui a des \
             rapports est refusé par un 409 qui les nomme, et cette liste dit lesquels.",
            Method::Get,
            "/v1/teams/{team_id}/members",
            json!({
                "type": "object",
                "properties": {
                    "team_id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "L'UUID de l'équipe, depuis `teams_list`.",
                    },
                },
                "required": ["team_id"],
            }),
            &[],
            Risk::Read,
        ),
        t(
            "teams_members_add",
            "Mettre un employé sur une équipe — ou refuser parce qu'il est déjà sur une autre",
            "Ajoute un employé à une équipe et **ne remplace jamais** : un siège déjà sur une \
             équipe est un 409 qui nomme laquelle. C'est délibéré — un employé sur deux équipes \
             donnerait au chargeur de politique deux couches `role`, et il garderait celle arrivée \
             en dernier, c'est-à-dire un tirage au sort entre le budget des achats et celui des \
             ventes, chaque décision paraissant correcte dans les journaux. Pour déplacer \
             quelqu'un d'une équipe à une autre, c'est `teams_members_set`. Cette ligne n'écrit \
             aucune position : ni titre, ni `reports_to`.",
            Method::Post,
            "/v1/teams/{team_id}/members",
            json!({
                "type": "object",
                "properties": {
                    "team_id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "L'UUID de l'équipe, depuis `teams_list`.",
                    },
                    "employee_id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "L'UUID du siège, depuis `employees_list`.",
                    },
                    "section_id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "Optionnel, et doit être une section **de cette équipe** — sinon 400. Depuis `teams_sections_list`.",
                    },
                },
                "required": ["team_id", "employee_id"],
            }),
            &[],
            Risk::Write,
        ),
        t(
            "teams_members_set",
            "Asseoir un employé : cette équipe, cette section, ce titre, sous ce responsable",
            "Le seul verbe qui remplace une appartenance et le seul qui écrive une **position**. \
             **Chaque champ omis est effacé, jamais conservé** : n'envoyer que `team_id` et \
             `employee_id` déplace le siège sur l'équipe sans section, sans titre et sans \
             responsable. Il n'y a pas de troisième état « garde l'ancienne valeur » — lis d'abord \
             `teams_members_list` et renvoie ce que tu veux garder. Trois refus : un `reports_to` \
             qui ne tient aucun siège chez ce locataire est un 400, un qui ferme une boucle dans \
             l'organigramme est un 409 `reporting_cycle`, et un employé qui se rapporte à lui-même \
             tombe sur les deux.",
            Method::Put,
            "/v1/teams/{team_id}/members/{employee_id}",
            json!({
                "type": "object",
                "properties": {
                    "team_id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "L'UUID de l'équipe d'arrivée, depuis `teams_list`.",
                    },
                    "employee_id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "L'UUID du siège à asseoir, depuis `employees_list`.",
                    },
                    "section_id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "Une section **de cette équipe**. Omis : le siège n'a pas de section.",
                    },
                    "title": {
                        "type": "string",
                        "description": "Comment s'appelle le siège : « Head of Growth ». Texte d'affichage ; rien n'y est accordé. Omis : siège sans titre.",
                    },
                    "reports_to": {
                        "type": "string",
                        "format": "uuid",
                        "description": "L'employé dont celui-ci relève. Doit tenir un siège chez ce locataire et ne pas fermer de boucle. Omis : personne au-dessus, ce à quoi ressemble un CEO.",
                    },
                },
                "required": ["team_id", "employee_id"],
            }),
            &[],
            Risk::Destructive,
        ),
        t(
            "teams_members_remove",
            "Sortir un employé d'une équipe",
            "Retire l'appartenance. **Cela desserre**, cela ne resserre pas : un employé sans \
             équipe n'est pas un employé sans politique, sa couche `role` devient absente et le \
             chargeur la résout par celle du locataire — donc sortir quelqu'un des achats le \
             remonte au plafond du locataire. Un responsable qui a des rapports n'est pas retiré \
             mais **refusé**, par un 409 nommant chaque employé dont la ligne casserait : \
             re-pointe-les avec `teams_members_set` d'abord. Supprimer une appartenance que \
             l'employé n'a pas est un 404, et non un succès silencieux qui l'aurait sorti de \
             l'équipe où il est vraiment.",
            Method::Delete,
            "/v1/teams/{team_id}/members/{employee_id}",
            json!({
                "type": "object",
                "properties": {
                    "team_id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "L'UUID de l'équipe, depuis `teams_list`.",
                    },
                    "employee_id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "L'UUID du siège, depuis `teams_members_list`.",
                    },
                },
                "required": ["team_id", "employee_id"],
            }),
            &[],
            Risk::Destructive,
        ),
        t(
            "teams_mission_set",
            "Dire à quoi sert cette fonction",
            "Écrit la mission d'une équipe — la troisième colonne de l'organigramme, et la seule \
             phrase durable qu'une équipe possède en propre : sans elle, une nouvelle recrue de \
             l'équipe croissance connaît sa tâche et rien de la croissance. Idempotent, et il \
             marche sur une équipe créée il y a un an comme sur une créée il y a une seconde. Une \
             mission n'est **pas** une limite : rien ici n'ouvre ni ne ferme quoi que ce soit, les \
             restrictions restent des lignes de `policy_layers` qu'on lit par `policy_role_get`.",
            Method::Put,
            "/v1/teams/{team_id}/mission",
            json!({
                "type": "object",
                "properties": {
                    "team_id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "L'UUID de l'équipe, depuis `teams_list`.",
                    },
                    "mission": {
                        "type": "string",
                        "description": "Ce à quoi sert cette fonction, dans les mots de l'opérateur.",
                    },
                },
                "required": ["team_id", "mission"],
            }),
            &[],
            Risk::Write,
        ),
        t(
            "teams_policy_role_set",
            "Pointer une équipe vers le `role_name` sous lequel ses limites sont écrites",
            "Déplace un pointeur et n'écrit rien d'autre — aucun plafond ne se règle ici. \
             **Attention au sens du danger** : un rôle pour lequel personne n'a écrit de couche \
             est une couche *absente*, qui hérite de celle du locataire ; pointer une équipe vers \
             une faute de frappe ne la verrouille donc pas, cela la **dé-restreint**, et \
             l'ancienne portée est perdue. Deux équipes peuvent partager un rôle — `purchasing-eu` \
             et `purchasing-us` sous `purchasing`. Vérifie avec `policy_role_get` que le rôle visé \
             a bien une couche avant d'appeler.",
            Method::Put,
            "/v1/teams/{team_id}/policy-role",
            json!({
                "type": "object",
                "properties": {
                    "team_id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "L'UUID de l'équipe, depuis `teams_list`.",
                    },
                    "role_name": {
                        "type": "string",
                        "description": "Le `policy_layers.role_name` sous lequel les limites de cette équipe seront lues. Validé comme un slug.",
                    },
                },
                "required": ["team_id", "role_name"],
            }),
            &[],
            Risk::Destructive,
        ),
        t(
            "teams_budget_get",
            "Le plafond quotidien d'une équipe dans une devise, ce qu'elle a déjà réservé, et ce qui reste",
            "Lecture seule et hors de toute réservation : c'est le chiffre qu'un opérateur \
             regarde, pas celui contre lequel un paiement est vérifié — cette vérification-là se \
             fait sous verrou de ligne, ailleurs. `currency` est **obligatoire** : un budget \
             libellé en USD ne dit rien d'un paiement en JPY, il n'y a donc pas de défaut \
             raisonnable à deviner. Pour voir tous les budgets de toutes les équipes d'un coup, \
             `controls_get`.",
            Method::Get,
            "/v1/teams/{team_id}/budget",
            json!({
                "type": "object",
                "properties": {
                    "team_id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "L'UUID de l'équipe, depuis `teams_list`.",
                    },
                    "currency": {
                        "type": "string",
                        "enum": ["USD", "EUR", "GBP", "CNY", "JPY", "KRW", "CHF", "CAD", "AUD", "INR"],
                        "description": "Code ISO-4217. Obligatoire.",
                    },
                },
                "required": ["team_id", "currency"],
            }),
            &["currency"],
            Risk::Read,
        ),
        t(
            "teams_budget_set",
            "Ce que toute une équipe peut réserver en un jour, dans une devise",
            "Fixe le plafond quotidien d'une équipe, par devise et de façon idempotente : le \
             renvoyer remplace le nombre. Baisser un budget ne **reprend pas** ce que la journée a \
             déjà réservé, cela contraint la suite — le registre des réservations n'est pas \
             touché. Le montant est en unités mineures avec son code : `{\"minor\": 500000, \
             \"currency\": \"USD\"}`, et zéro est refusé des deux côtés, au parseur puis dans la \
             base. Le `team_id` vient de `teams_list` et l'état courant du budget de \
             `teams_budget_get` ; pour plafonner l'argent d'un siège et non d'une équipe, c'est \
             `spend_caps_set`.",
            Method::Put,
            "/v1/teams/{team_id}/budget",
            json!({
                "type": "object",
                "properties": {
                    "team_id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "L'UUID de l'équipe, depuis `teams_list`.",
                    },
                    "daily_total": {
                        "type": "object",
                        "description": "Le plafond du jour, en unités mineures : `{\"minor\": 500000, \"currency\": \"USD\"}`. Zéro est refusé.",
                        "properties": {
                            "minor": { "type": "integer", "minimum": 1 },
                            "currency": {
                                "type": "string",
                                "enum": ["USD", "EUR", "GBP", "CNY", "JPY", "KRW", "CHF", "CAD", "AUD", "INR"],
                            },
                        },
                        "required": ["minor", "currency"],
                    },
                },
                "required": ["team_id", "daily_total"],
            }),
            &[],
            Risk::Write,
        ),
        // -------------------------------------------------------------------
        // Le bureau : la seule façon de parler à un employé
        // -------------------------------------------------------------------
        t(
            "desk_messages_list",
            "Ce qui attend sur un bureau, le plus récent d'abord",
            "Rend les messages posés sur le bureau d'un siège — répondus et non répondus ensemble, \
             sans filtre, parce que ce qu'on veut sur un écran c'est ce qui est en cours *et* ce \
             qui a été traité. C'est ici qu'on prend l'`id` d'une question pour le mettre dans le \
             champ `answers` de `desk_messages_send`. Tous les bureaux sont lisibles, pas \
             seulement ceux des fauteuils : c'est comme cela qu'un opérateur voit ce que sa \
             hiérarchie dit réellement à un employé qui travaille.",
            Method::Get,
            "/v1/employees/{id}/desk",
            employee_id_only("L'UUID du siège dont on lit le bureau, depuis `employees_list`."),
            &[],
            Risk::Read,
        ),
        t(
            "desk_messages_send",
            "Parler à un employé depuis un siège : un ordre, une question, ou une réponse",
            "Le verbe qui manquait au produit : la seule façon d'envoyer à un employé une phrase \
             qu'il lira. Trois pièges, dans l'ordre où ils mordent. **Le siège dans le chemin est \
             l'expéditeur, pas le destinataire**, et il doit être un *fauteuil* — un siège dont le \
             plafond de tours intersecté vaut zéro, ce qui est la façon dont ce système écrit \
             « une personne s'assoit ici » ; le destinataire est le `to`, par slug. **Le message \
             réveille le destinataire et lui coûte un tour** de son budget du jour, sur le modèle \
             et la facture du client — un budget épuisé est un 409. **Un `answers` répond à une \
             question précise** : il porte l'`id` d'un message lu sur `desk_messages_list`, il est \
             obligatoire pour `kind: \"answer\"` et ignoré par les deux autres. Un siège que cette \
             société n'a pas est un 404 ; tout ce que l'organigramme, la question ou le budget \
             refusent est un 409 nommé.",
            Method::Post,
            "/v1/employees/{id}/desk",
            json!({
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "L'**expéditeur** : l'UUID du fauteuil depuis lequel on parle. Doit avoir un plafond de tours nul.",
                    },
                    "to": {
                        "type": "string",
                        "description": "Le collègue destinataire, par slug court — le même que celui qu'un employé taperait.",
                    },
                    "kind": {
                        "type": "string",
                        "enum": ["order", "question", "answer"],
                        "description": "`order` donne une consigne, `question` en pose une, `answer` en referme une (et exige alors `answers`). Il n'y a pas de `handover` ici : un fauteuil ne possède aucune conversation à transférer.",
                    },
                    "body": {
                        "type": "string",
                        "description": "Les mots. Entrée d'opérateur, donc de confiance.",
                    },
                    "answers": {
                        "type": "string",
                        "format": "uuid",
                        "description": "Pour un `answer` : l'`id` du message qu'il referme, relevé sur `desk_messages_list`. Ignoré par `order` et `question`.",
                    },
                    "attachments": {
                        "type": "array",
                        "maxItems": 20,
                        "description": "Les documents joints, par le nom sous lequel chacun a été déposé. Un nom que cette société n'a pas classé est un 404 `no_such_file` — et le fichier d'une autre société se lit exactement pareil. L'employé lit chaque pièce dans le message en se réveillant ; il n'y a pas de verbe pour aller chercher un fichier.",
                        "items": {
                            "type": "object",
                            "properties": { "name": { "type": "string" } },
                            "required": ["name"],
                        },
                    },
                },
                "required": ["id", "to", "kind", "body"],
            }),
            &[],
            Risk::Write,
        ),
        // -------------------------------------------------------------------
        // Les approbations
        // -------------------------------------------------------------------
        t(
            "approvals_list",
            "La file d'attente humaine : ce que les employés demandent, du plus ancien au plus récent",
            "Rend les approbations `pending` de cette société. **Rien ne sort de cette file tout \
             seul** : `state` n'a pas de valeur « expirée », un jeton dure 24 heures et personne \
             ne déplace une ligne périmée — donc une quinzaine sans surveillance donne une file \
             dont la tête est le travail le plus certainement mort et dont la seule ligne encore \
             utilisable est en bas. Le compteur de supervision, lui, filtre les périmées : les \
             deux chiffres ne coïncident pas, et c'est connu. Une ligne périmée reste refusable \
             par `approvals_deny`, un appel chacune.",
            Method::Get,
            "/v1/approvals",
            nothing(),
            &[],
            Risk::Read,
        ),
        t(
            "approvals_get",
            "Une approbation, dans l'état où elle est",
            "Rend une demande, décidée ou non — « qu'est-il arrivé à ma demande ? » est la \
             deuxième question que tout le monde pose. C'est ici qu'on lit l'action exacte à \
             recopier dans le corps d'`approvals_approve` : elle doit être restituée mot pour mot. \
             L'`id` vient d'`approvals_list`.",
            Method::Get,
            "/v1/approvals/{id}",
            json!({
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "L'UUID de l'approbation, depuis `approvals_list`.",
                    },
                },
                "required": ["id"],
            }),
            &[],
            Risk::Read,
        ),
        t(
            "approvals_approve",
            "Dépenser une approbation sur l'action que le corps restitue",
            "Engage la société : pour `payment_create`, **l'argent part vraiment** ; pour toutes \
             les autres natures, le jeton est frappé, la décision enregistrée et le jeton jeté. Le \
             corps porte l'action, et ce n'est pas une formalité — l'échec que cette route existe \
             pour empêcher n'est pas « on a approuvé la mauvaise chose », c'est « on a approuvé \
             *ceci* et *cela* a été exécuté » : l'action est re-hachée contre celle déposée à la \
             demande, et une différence est un `approval_action_mismatch`. Recopie-la donc depuis \
             `approvals_get`, sans reformuler : le hachage est **octet par octet**, un même nom \
             écrit en NFC et en NFD sont deux approbations différentes. Deux gardes précèdent \
             tout : l'approbateur ne peut pas être le demandeur, et sa clé doit porter le rôle \
             exigé. Un 502 signifie approbation dépensée et argent peut-être en vol — il n'y a pas \
             de rejeu.",
            Method::Post,
            "/v1/approvals/{id}/approve",
            json!({
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "L'UUID de l'approbation, depuis `approvals_list`.",
                    },
                    "action": {
                        "type": "object",
                        "description": "L'action approuvée, restituée telle qu'`approvals_get` la rend. Union étiquetée par `action` : par exemple `{\"action\":\"payment_create\",\"amount\":{\"minor\":50000,\"currency\":\"EUR\"},\"payee\":\"…\"}`, ou `{\"action\":\"contract_sign\",\"title\":\"…\"}`. Ne rien reformuler : le hachage est octet par octet.",
                        "properties": { "action": { "type": "string" } },
                        "required": ["action"],
                    },
                },
                "required": ["id", "action"],
            }),
            &[],
            Risk::Destructive,
        ),
        t(
            "approvals_deny",
            "Refuser une approbation. Le jeton n'est plus dépensable, jamais",
            "Annule définitivement la demande : le nonce est brûlé et l'employé devra en déposer \
             une nouvelle. Contrairement à `approvals_approve`, il n'y a pas de règle des quatre \
             yeux — refuser sa propre demande est une annulation, il n'y a rien à empêcher — et \
             une ligne déjà périmée s'accepte sans regarder sa date, ce qui est la seule façon de \
             vider la file. La `note` est facultative et vaut la peine d'être écrite : c'est ce \
             que lira le prochain opérateur.",
            Method::Post,
            "/v1/approvals/{id}/deny",
            json!({
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "L'UUID de l'approbation, depuis `approvals_list`.",
                    },
                    "note": {
                        "type": "string",
                        "description": "Pourquoi. Facultatif, et vaut la peine d'être écrit.",
                    },
                },
                "required": ["id"],
            }),
            &[],
            Risk::Destructive,
        ),
        t(
            "capability_requests_list",
            "Ce qu'un employé se voit refuser sans arrêt, et à quelle fréquence",
            "L'autre sens de la file : non pas « il veut faire une chose qui demande un humain », \
             mais « il lui manque une permission ». **Personne n'a écrit ces lignes** : chacune \
             est dérivée de la piste d'audit que la Gate écrit déjà, une ligne par jugement — donc \
             une demande ne peut pas revendiquer un refus qui n'a pas eu lieu, et un modèle ne \
             peut pas en composer une. Le vocabulaire est volontairement pauvre : un slug, une \
             nature d'action, une raison de refus, un décompte, deux dates. Pas de nom d'outil, \
             pas de domaine — les mettre ferait de l'écran d'approbation une surface qu'un inconnu \
             peut écrire. Répondre à une ligne est `capability_requests_decide`.",
            Method::Get,
            "/v1/capability-requests",
            nothing(),
            &[],
            Risk::Read,
        ),
        t(
            "capability_requests_decide",
            "Répondre à une demande de permission — et ne changer aucune politique en le faisant",
            "Enregistre la décision d'un humain sur un refus récurrent : une ligne dans le \
             registre des décisions, une ligne d'audit, une transaction. **Cela n'élargit rien, et \
             c'est la moitié honnête de la fonctionnalité** : accorder ici n'écrit pas une couche \
             de politique, parce que remplacer une couche existante n'a aucune propriété de \
             rétrécissement — la réponse dit en toutes lettres qu'il reste à installer la couche à \
             la main. Un accord que personne n'installe n'est pas perdu : l'employé continue \
             d'être refusé et la demande revient avec son ancienne décision attachée. La demande \
             n'a pas d'identifiant — c'est une clé de regroupement — donc on la nomme par sa \
             forme, telle que `capability_requests_list` la rend. La clé doit porter le rôle \
             d'approbateur (403 `role_required`) ; un refus que la piste de cette société ne \
             connaît pas est un 404.",
            Method::Post,
            "/v1/capability-requests/decide",
            json!({
                "type": "object",
                "properties": {
                    "employee_id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "Le siège concerné, tel que `capability_requests_list` le nomme.",
                    },
                    "action_kind": {
                        "type": "string",
                        "enum": [
                            "email_send", "sms_send", "whatsapp_send", "call_place",
                            "browser_read", "browser_write", "file_upload", "mcp_call",
                            "a2a_send", "payment_create", "invoice_issue", "contract_sign",
                            "credential_change", "data_delete", "charter_set",
                            "internal_send", "appointment_book",
                        ],
                        "description": "La nature d'action refusée, recopiée depuis `capability_requests_list`.",
                    },
                    "deny_reason": {
                        "type": "string",
                        "description": "La raison du refus, recopiée depuis `capability_requests_list`. Les raisons non accordables — dont `untrusted_input`, l'arrêt anti-injection — n'apparaissent jamais dans cette liste.",
                    },
                    "granted": {
                        "type": "boolean",
                        "description": "`true` : « ce siège devrait l'avoir ». `false` : « il ne devrait pas ». Ni l'un ni l'autre ne modifie une limite.",
                    },
                    "note": {
                        "type": "string",
                        "description": "La phrase de l'opérateur, pour le prochain opérateur. Facultative et utile.",
                    },
                },
                "required": ["employee_id", "action_kind", "deny_reason", "granted"],
            }),
            &[],
            Risk::Write,
        ),
        // -------------------------------------------------------------------
        // Les limites
        // -------------------------------------------------------------------
        t(
            "policy_role_get",
            "La couche de limites d'un rôle, telle qu'elle est stockée",
            "Rend le document écrit sous ce `role_name` — **et non** l'intersection que la Gate \
             applique réellement. 404 quand le rôle n'a pas de couche à lui, et c'est la réponse \
             honnête : une couche absente hérite au *chargement*, donc afficher celle du locataire \
             rendrait « ce rôle n'a rien d'écrit » et « ce rôle a exactement les limites du \
             plafond » indiscernables. À lire avant tout `policy_role_set`, qui exige un document \
             complet. Ce que la Gate applique pour un siège donné se lit plutôt sur \
             `controls_get`.",
            Method::Get,
            "/v1/policy/roles/{role}",
            json!({
                "type": "object",
                "properties": {
                    "role": {
                        "type": "string",
                        "description": "Le `role_name`, qui est aussi un slug d'équipe. Depuis `teams_list`.",
                    },
                },
                "required": ["role"],
            }),
            &[],
            Risk::Read,
        ),
        t(
            "policy_role_set",
            "Remplacer la couche d'un rôle par une couche plus étroite",
            "La seule route qui puisse changer une limite, et elle ne peut que **resserrer** : un \
             corps qui n'est pas contenu dans la couche qu'il déplace est un 409 `policy_widens`, \
             refusé et non silencieusement intersecté. Deux pièges. **Le corps est un document \
             entier, pas un correctif** : un champ manquant n'est pas « laisse comme c'était », \
             c'est un remplacement total — `{\"max_turns_per_day\": 30}` a l'air d'une retouche et \
             coûte au siège ses canaux, ses domaines et son modèle ; lis d'abord `policy_role_get` \
             et renvoie le document complet modifié. **Elle ne crée pas** : un rôle sans couche \
             est un 404, la création appartient à `company_create`, qui connaît l'organigramme. Le \
             plafond de la plateforme et les couches locataire et employé ne sont pas atteignables \
             ici. `installed: false` signifie que la couche disait déjà exactement cela.",
            Method::Put,
            "/v1/policy/roles/{role}",
            json!({
                "type": "object",
                "properties": {
                    "role": {
                        "type": "string",
                        "description": "Le `role_name`, un slug. Depuis `teams_list` ou `policy_role_get`.",
                    },
                    "spend": {
                        "type": ["object", "null"],
                        "description": "Les plafonds d'argent, ou `null` pour n'autoriser aucune dépense. Trois montants `{\"minor\":…,\"currency\":…}` obligatoires ensemble.",
                        "properties": {
                            "max_per_transaction": { "type": "object" },
                            "max_per_day": { "type": "object" },
                            "approval_above": { "type": "object" },
                        },
                        "required": ["max_per_transaction", "max_per_day", "approval_above"],
                    },
                    "allowed_channels": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Les canaux ouverts. Liste vide : aucun.",
                    },
                    "allowed_calling_codes": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Les indicatifs appelables.",
                    },
                    "allowed_domains": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Les domaines lisibles ou écrivables.",
                    },
                    "denied_domains": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Les domaines interdits. Une liste d'interdiction ne peut que s'allonger.",
                    },
                    "allowed_mcp_tools": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Les outils MCP appelables.",
                    },
                    "allowed_a2a_peers": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Les pairs agent-à-agent joignables.",
                    },
                    "allowed_models": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["claude-haiku-4-5", "claude-sonnet-5", "claude-opus-5", "claude-fable-5"],
                        },
                        "description": "Les modèles permis. Le moins cher permis est celui qu'un rôle sans préférence obtient.",
                    },
                    "max_new_contacts_per_day": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Nouveaux contacts par jour. La chauffe du domaine peut encore réduire ce chiffre — voir `controls_get`.",
                    },
                    "max_turns_per_day": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Tours par jour. **Zéro veut dire « ne peut pas agir de lui-même »**, et c'est ce qui fait d'un siège un fauteuil au sens de `desk_messages_send`.",
                    },
                    "allow_file_upload": { "type": "boolean" },
                    "allow_credential_change": { "type": "boolean" },
                    "allow_data_delete": { "type": "boolean" },
                    "allow_lead_upload": { "type": "boolean" },
                },
                "required": [
                    "role", "spend", "allowed_channels", "allowed_calling_codes",
                    "allowed_domains", "denied_domains", "allowed_mcp_tools",
                    "allowed_a2a_peers", "allowed_models", "max_new_contacts_per_day",
                    "max_turns_per_day", "allow_file_upload", "allow_credential_change",
                    "allow_data_delete", "allow_lead_upload",
                ],
            }),
            &[],
            Risk::Destructive,
        ),
        t(
            "controls_get",
            "Ce qui borne chaque siège, et le bouton d'arrêt — en une lecture",
            "La page que regarde un client qui paie cher et se demande deux choses : est-ce que ça \
             coûte sans limite, et est-ce que ça s'arrête. Elle réunit ce qu'il fallait six routes \
             pour lire, et dit trois choses qu'aucune ne disait : **quelle couche a posé chaque \
             plafond** (`set_by`, ou `tightest_of` quand plusieurs disent le même chiffre — une \
             couche héritée n'apparaît jamais, elle n'a rien posé), **`acts_on_its_own`** en \
             clair, et **ce que le plafond libère réellement aujourd'hui** une fois la chauffe du \
             domaine passée, avec `contacts_held_back` qui nomme le mur. Le budget de l'équipe y \
             est aussi, lu comme le magasin le lit. À préférer à `policy_role_get` quand la \
             question est « qu'est-ce qui arrête ce siège en premier ».",
            Method::Get,
            "/v1/controls",
            nothing(),
            &[],
            Risk::Read,
        ),
        t(
            "employees_turns_get",
            "Ce qu'un siège a consommé aujourd'hui, et ce qui lui reste",
            "Rend le budget de tours du jour pour un employé. `turns_taken: 0` avec un 200 est la \
             réponse ordinaire d'un siège qui ne s'est pas encore réveillé — il n'y a pas de ligne \
             de compteur avant la première réservation, et « rien de consommé » est un fait, pas \
             une ressource absente. Le 404 est pour un employé qui n'existe pas *dans cette \
             société*. Le compteur repart de lui-même à minuit UTC. L'`id` vient \
             d'`employees_list`. Pour savoir quelle couche a posé ce plafond et ce qui arrêtera le \
             siège en premier, `controls_get` ; pour ce qu'il s'est vu refuser, `refusals_get`.",
            Method::Get,
            "/v1/employees/{id}/turns",
            employee_id_only("L'UUID du siège, depuis `employees_list`."),
            &[],
            Risk::Read,
        ),
        t(
            "refusals_get",
            "Ce que la Gate a refusé sur une fenêtre, par nature et par raison",
            "Compte les refus et rend les cinquante plus récents — ce qu'un humain relit ; le \
             reste est dans les décomptes. À utiliser quand un employé « ne fait rien » : c'est \
             ici qu'on voit s'il est refusé, et pourquoi. La fenêtre s'écrit `days` (N jours \
             calendaires UTC finissant aujourd'hui) ou `from`/`to`, `to` étant **inclusif** ; ce \
             sont les mêmes bornes que `autonomy_get`, pour que les deux se lisent côte à côte. \
             Zéro partout avec un 200 est la réponse ordinaire d'une fenêtre sans refus.",
            Method::Get,
            "/v1/refusals",
            json!({
                "type": "object",
                "properties": {
                    "days": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "La forme courte : N jours calendaires UTC finissant aujourd'hui.",
                    },
                    "from": {
                        "type": "string",
                        "format": "date",
                        "description": "Premier jour UTC, `2026-07-01`.",
                    },
                    "to": {
                        "type": "string",
                        "format": "date",
                        "description": "Dernier jour UTC, **inclus**.",
                    },
                },
                "required": [],
            }),
            &["days", "from", "to"],
            Risk::Read,
        ),
        t(
            "autonomy_get",
            "Quelle part du travail les agents ont faite eux-mêmes, sur une fenêtre",
            "Le chiffre commercial de ce produit : `autonomy_pct` par siège et pour la société. \
             `null` et non zéro quand il n'y avait rien à diviser — « pas de données » n'est pas \
             « 0 % autonome » — et la division tronque vers le bas, comme toute ambiguïté ici. La \
             fenêtre est celle de `refusals_get` : `from`/`to` en jours UTC, `to` inclus, 366 \
             jours au plus. À lire à côté de `refusals_get` : l'un dit ce que les agents ont fait, \
             l'autre ce qu'on les a empêchés de faire.",
            Method::Get,
            "/v1/autonomy",
            json!({
                "type": "object",
                "properties": {
                    "from": {
                        "type": "string",
                        "format": "date",
                        "description": "Premier jour UTC, `2026-07-01`. Absent : le début par défaut de la fenêtre.",
                    },
                    "to": {
                        "type": "string",
                        "format": "date",
                        "description": "Dernier jour UTC, **inclus**.",
                    },
                },
                "required": [],
            }),
            &["from", "to"],
            Risk::Read,
        ),
        // -------------------------------------------------------------------
        // L'initiative : ce qu'un employé fait quand personne ne lui écrit
        // -------------------------------------------------------------------
        t(
            "initiatives_list",
            "Tous les sièges programmés de cette société, en une lecture",
            "Toute la flotte d'un coup là où `initiatives_get` lit un siège, et la raison d'être \
             de cette ligne : un écran d'accueil qui montre « qui travaille en ce moment » faisait \
             une requête par siège. **Un siège sans cadence n'y est pas** — il ne se réveille \
             jamais tout seul, donc il ne *travaille* pas au sens de cette question. La surface \
             qui liste tous les sièges, programmés ou non, est `interview_questions_list`, et \
             c'est elle qu'il faut pour une société neuve, où aucun siège n'est encore lancé.",
            Method::Get,
            "/v1/initiative",
            nothing(),
            &[],
            Risk::Read,
        ),
        t(
            "initiatives_get",
            "La cadence d'un siège, sa prochaine échéance, ce qui s'est passé la dernière fois, et le plan tel qu'il tient aujourd'hui",
            "Répond aux trois questions qu'un opérateur a vraiment : est-ce qu'il travaille, quand \
             agit-il ensuite, et s'il ne travaille pas, que lui manque-t-il. Le plan est \
             **recalculé** à chaque lecture depuis l'objectif stocké, jamais stocké : c'est le \
             moyen le plus rapide de découvrir qu'un objectif qu'on vient de poser a un trou — la \
             réponse porte alors `clarify` et pose la question, dans le même aller-retour. 404 \
             quand le siège n'a pas d'initiative, n'existe pas, ou appartient à une autre \
             société : les trois sont indiscernables exprès. Si c'est toute la société qui semble \
             immobile et pas ce siège-là, `company_health_get` d'abord : une cadence parfaitement \
             réglée ne produit rien quand le modèle n'est pas connecté ou que la société est à \
             l'arrêt. L'`id` vient d'`employees_list`.",
            Method::Get,
            "/v1/employees/{id}/initiative",
            employee_id_only("L'UUID du siège, depuis `employees_list` ou `initiatives_list`."),
            &[],
            Risk::Read,
        ),
        t(
            "initiatives_set",
            "Lancer un siège : son objectif, et la fréquence à laquelle il y travaille seul",
            "La seule route qui écrive les deux moitiés à la fois — l'objectif (*ce pour quoi* le \
             siège est là) et la cadence (*quand* il agit) — dans une transaction, parce qu'un \
             employé réveillé sur une cadence pour un objectif annulé n'a pas de sens. **C'est un \
             remplacement, pas un correctif** : les deux champs sont obligatoires et l'ancien \
             objectif est perdu ; lis `initiatives_get` d'abord si tu veux en garder une partie. \
             C'est aussi la route qui **choisit le rôle** d'un siège, ce qu'aucun modèle ne fait à \
             ta place : le tag `role` de l'objectif est un choix fermé. Une cadence hors bornes \
             est **refusée et jamais rabotée** — plancher 300 s, plafond 30 jours — parce qu'un \
             raccourci silencieux ferait croire à l'opérateur que sa valeur a été prise. Poser une \
             cadence **déplace la prochaine échéance** à un intervalle d'ici. Chaque valeur \
             repasse par son constructeur : un pays écrit « Germany » ou un prix nul est un 400 \
             qui nomme le champ. Pour compléter un objectif en prose plutôt qu'en JSON, \
             `interview_answer`.",
            Method::Put,
            "/v1/employees/{id}/initiative",
            json!({
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "L'UUID du siège, depuis `employees_list`.",
                    },
                    "interval_secs": {
                        "type": "integer",
                        "minimum": 300,
                        "maximum": 2_592_000,
                        "description": "Tous les combien le siège agit seul, en secondes. Plancher 300 (5 min), plafond 2 592 000 (30 jours) ; hors bornes est un 400, jamais un rabotage.",
                    },
                    "objective": {
                        "type": "object",
                        "description": "Ce sur quoi il agit, union étiquetée par `role`. `international-buyer` : `what`, `quantity`, `max_unit_price {minor,currency}`, `delivery_country`, `requirements[]`. `sales-development` : `segment` (obligatoire), `market`, `target_accounts[]`. `customer-success` : `product`, `first_response_hours`, `escalate_to`. `growth` : `topic`, `market`, `measure`. `finance` : `period`, `currency`, `obligations[]`. `entry-requirements` : `destinations`, `passports[]`, `max_age_days`. `engineering` : `repository`, `checks`, `reviewer`. `managing` : `mission`, `seats {slug: role}`. Sauf `segment`, tout a un défaut : un objectif incomplet est stockable, et `initiatives_get` rend la question en `clarify` plutôt qu'un refus.",
                        "properties": {
                            "role": {
                                "type": "string",
                                "enum": [
                                    "international-buyer", "sales-development",
                                    "customer-success", "growth", "finance",
                                    "entry-requirements", "engineering", "managing",
                                ],
                            },
                        },
                        "required": ["role"],
                    },
                },
                "required": ["id", "interval_secs", "objective"],
            }),
            &[],
            Risk::Destructive,
        ),
        // -------------------------------------------------------------------
        // L'entretien : finir la société en parlant
        // -------------------------------------------------------------------
        t(
            "interview_questions_list",
            "Toutes les questions ouvertes de cette société, siège par siège",
            "Après `company_create` et `model_connect`, aucun siège ne sait encore à quoi il \
             sert : cette liste est ce qui reste à dire. **Tous les employés, pas tous les \
             chartés** — un siège que personne n'a chargé d'une mission est justement celui que \
             cette liste doit montrer, puisque c'est l'état dans lequel une société neuve est \
             entièrement. Chaque question porte un code, qu'on repasse à `interview_answer` pour \
             dire laquelle on répond. Une question marquée `answerable: false` ne se ferme par \
             aucune phrase : son remède est une couche de politique. C'est aussi la seule surface \
             qui liste chaque siège, programmé ou non, là où `initiatives_list` n'a que les \
             programmés.",
            Method::Get,
            "/v1/interview",
            nothing(),
            &[],
            Risk::Read,
        ),
        t(
            "interview_answer",
            "Un siège, une réponse en prose : le modèle propose, les constructeurs décident",
            "Fait dire au fondateur, en mots, ce qu'il aurait dû taper en JSON tagué dans \
             `initiatives_set` — un tour gaté et compté transforme la prose en valeurs candidates. \
             La frontière de confiance est nette : une proposition ne peut toucher qu'une clé \
             **que l'objectif possède déjà** et **encore vide**, jamais le tag `role` ni un champ \
             déjà répondu, puis chaque valeur repasse par le constructeur — donc ce que \
             l'entretien écrit est exactement ce qu'un opérateur aurait pu taper à la main. Tout \
             ou rien : une seule valeur que les constructeurs refusent jette l'objet entier et les \
             questions reviennent inchangées. Passe `question` avec le code lu sur \
             `interview_questions_list` — sans lui, le modèle reçoit les trente-cinq questions et \
             devine laquelle une phrase referme, mal. Un code qui ne nomme aucune question ouverte \
             est ignoré, pas refusé. **Cette route ne choisit pas le rôle d'un siège** : c'est \
             `initiatives_set`, et elle seule.",
            Method::Post,
            "/v1/employees/{id}/interview",
            json!({
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "L'UUID du siège, depuis `interview_questions_list` ou `employees_list`.",
                    },
                    "answer": {
                        "type": "string",
                        "description": "Ce que le fondateur dit, dans ses mots. Entrée d'opérateur, donc de confiance — mais cette confiance ne survit pas au modèle.",
                    },
                    "question": {
                        "type": "string",
                        "description": "Le code de la question à l'écran, relevé sur `interview_questions_list`. Absent quand le fondateur parle librement.",
                    },
                },
                "required": ["id", "answer"],
            }),
            &[],
            Risk::Write,
        ),
        // -------------------------------------------------------------------
        // Le modèle
        // -------------------------------------------------------------------
        t(
            "model_get",
            "Ce qui est connecté, et quand ça a été prouvé",
            "Rend le chemin d'accès au modèle de cette société et la date de sa vérification. 404 \
             quand rien n'est connecté : un locataire non connecté est un locataire sans cette \
             ressource, la même réponse que donne le chemin d'exécution d'un tour. La moitié \
             scellée du secret n'est jamais rendue — le type qui la porte n'est même pas \
             sérialisable. Un 404 ici est la première cause d'un `stopped` sur \
             `company_health_get` : ce qui le répare est `model_connect`, qui prouve la clé avant \
             de la stocker.",
            Method::Get,
            "/v1/model",
            nothing(),
            &[],
            Risk::Read,
        ),
        t(
            "model_connect",
            "Prouver une clé de modèle, puis la stocker",
            "Vérifie la connexion par **un vrai appel de modèle**, facturé à qui possède la clé \
             qu'on prouve, puis scelle celle-ci sur la ligne du locataire. Deux chemins et pas un \
             troisième : `api_key` — le locataire colle sa clé Anthropic, **sa clé paie**, et \
             c'est le chemin dont la production parle — ou `cli`, qui dépense la session de l'hôte \
             lui-même. **Un abonnement Claude d'un locataire n'est plus une voie d'entrée** : un \
             `cli` accompagné d'un jeton est refusé avant même la sonde, la licence interdisant de \
             collecter, stocker ou intermédier un identifiant Claude.ai — l'outil ne propose donc \
             pas ce champ. Prouver un modèle ne prouve rien des trois autres : l'appel en nomme \
             exactement un, et la réponse dit lequel. Ce qui est connecté, et depuis quand, se \
             relit ensuite sur `model_get`.",
            Method::Post,
            "/v1/model",
            json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "enum": ["api_key", "cli"],
                        "description": "`api_key` : la clé du locataire, qui paiera. `cli` : le `claude` local, sur la session de l'hôte.",
                    },
                    "api_key": {
                        "type": "string",
                        "description": "Le secret, pour `api_key`. Obligatoire là, ignoré sur `cli`.",
                    },
                    "model": {
                        "type": "string",
                        "enum": ["claude-haiku-4-5", "claude-sonnet-5", "claude-opus-5", "claude-fable-5"],
                        "description": "Le modèle à prouver. Par défaut `claude-opus-5`, ce que fait tourner une flotte non restreinte.",
                    },
                    "usd_per_mtok_input": {
                        "type": "number",
                        "description": "Le tarif propre du locataire, USD par million de jetons d'entrée. Facultatif ; « absent » reste distinct de « rien déclaré ».",
                    },
                    "usd_per_mtok_output": {
                        "type": "number",
                        "description": "USD par million de jetons de sortie.",
                    },
                    "usd_per_mtok_cache_read": {
                        "type": "number",
                        "description": "USD par million de jetons lus en cache.",
                    },
                },
                "required": ["path"],
            }),
            &[],
            Risk::Write,
        ),
        // -------------------------------------------------------------------
        // L'interrupteur
        // -------------------------------------------------------------------
        t(
            "halt_get",
            "Cette société est-elle arrêtée, et qu'a-t-elle refusé pendant ce temps",
            "Dit si un arrêt est posé, la phrase de qui l'a posé, la date de fin de fenêtre, et \
             **le nombre d'actions refusées** — la réponse à « qu'est-ce qui n'a pas eu lieu \
             pendant qu'on était à l'arrêt », dérivée de la piste d'audit et non d'un compteur, \
             donc elle ne peut pas dériver. `window_ends_at` est à côté de `halted` et non \
             dessous : les deux sont indépendants, une société qui tourne peut avoir une fenêtre, \
             et une société arrêtée peut l'être par sa fenêtre, par un opérateur, ou par les deux. \
             Même forme de réponse que `halt_place`, pour qu'un client teste le même champ dans \
             les deux cas.",
            Method::Get,
            "/v1/halt",
            nothing(),
            &[],
            Risk::Read,
        ),
        t(
            "halt_place",
            "Tout arrêter",
            "Le bouton rouge de la société : plus un tour, plus un envoi, plus un jeton \
             d'autorisation, pour tous les sièges à la fois. La `reason` est **obligatoire et sans \
             défaut** — elle est toute la valeur probante de la ligne : elle est montrée à chaque \
             refus, recopiée dans la piste d'audit, et relue au post-mortem, et un gestionnaire \
             qui l'inventerait mettrait des mots dans la bouche d'un opérateur au sujet d'une \
             urgence. 409 si la société est déjà arrêtée, et volontairement pas un 200 \
             silencieux : la raison du second appelant n'est **pas** enregistrée, donc lui \
             répondre « c'est fait » lui ferait croire que sa phrase est celle qui figure au \
             dossier. On relâche avec `halt_release`. Un trou connu : la boucle de provisionnement \
             continue d'acheter les ressources des sièges embauchés, arrêt ou pas.",
            Method::Post,
            "/v1/halt",
            json!({
                "type": "object",
                "properties": {
                    "reason": {
                        "type": "string",
                        "description": "Pourquoi la société est arrêtée. Obligatoire, sans défaut, et lue par tout le monde ensuite.",
                    },
                },
                "required": ["reason"],
            }),
            &[],
            Risk::Destructive,
        ),
        t(
            "halt_release",
            "Laisser la société repartir",
            "Retire l'arrêt de l'opérateur : les sièges reprennent leurs tours, leurs envois et \
             leurs réveils. Engage la société autant que `halt_place` et dans l'autre sens — c'est \
             la reprise d'une activité que quelqu'un avait délibérément stoppée, avec sa phrase au \
             dossier ; relis-la avec `halt_get` avant d'appeler. 409 si elle n'était pas arrêtée, \
             pour la même raison que le 409 de `halt_place` : « relâchée » et « n'a jamais été \
             arrêtée » sont deux faits différents, et un opérateur qui croit avoir redémarré une \
             société qui tournait depuis le début est un opérateur qui cesse de chercher le vrai \
             problème. Cela ne touche pas la fenêtre : une société dont la fenêtre est épuisée \
             reste arrêtée, et c'est `window_set` qui la prolonge.",
            Method::Delete,
            "/v1/halt",
            nothing(),
            &[],
            Risk::Destructive,
        ),
        t(
            "window_set",
            "Dire quand les agents de cette société s'arrêtent",
            "Écrit la fenêtre d'exploitation — un **instant**, jamais une durée : « 2 jours / 1 \
             semaine / 1 mois » est une arithmétique que quelqu'un fait une fois, et la faire ici \
             obligerait chaque lecteur ultérieur à la refaire depuis une date de départ qu'il ne \
             voit pas. Il n'y a pas de défaut et personne n'a le droit d'en inventer un : le \
             nombre serait un prix. Deux choses à savoir. **Prolonger une fenêtre déjà épuisée \
             fait repartir la société**, en un appel — c'est ce qui rend cette ligne engageante. \
             Et cela ne lève **jamais** l'arrêt d'un opérateur : quand les deux existent, c'est le \
             sien qui prime, et il se retire par `halt_release`. Idempotent : le même corps deux \
             fois laisse la même ligne, un corps différent la remplace ; une date dans le passé \
             est refusée, parce que ce serait un arrêt immédiat sans la phrase de personne.",
            Method::Put,
            "/v1/window",
            json!({
                "type": "object",
                "properties": {
                    "ends_at": {
                        "type": "string",
                        "format": "date-time",
                        "description": "L'instant UTC où les agents s'arrêtent. Doit être dans le futur.",
                    },
                },
                "required": ["ends_at"],
            }),
            &[],
            Risk::Destructive,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// Le source des quatorze modules de routes que ce domaine déclare, inclus
    /// tel quel.
    ///
    /// Une constante de chemins recopiés à la main ne prouverait rien : elle
    /// serait vraie le jour où on l'écrit et fausse le jour où quelqu'un renomme
    /// une route, sans qu'aucun test ne rougisse. En lisant le source, le test
    /// compare la table à ce qui est **réellement monté**, et un fichier déplacé
    /// ne compile même pas.
    const ROUTE_SOURCES: [&str; 17] = [
        include_str!("../../../../apps/server/src/routes/employees.rs"),
        include_str!("../../../../apps/server/src/routes/teams.rs"),
        include_str!("../../../../apps/server/src/routes/companies.rs"),
        include_str!("../../../../apps/server/src/routes/desk.rs"),
        include_str!("../../../../apps/server/src/routes/approvals.rs"),
        include_str!("../../../../apps/server/src/routes/policy.rs"),
        include_str!("../../../../apps/server/src/routes/turns.rs"),
        include_str!("../../../../apps/server/src/routes/autonomy.rs"),
        include_str!("../../../../apps/server/src/routes/initiative.rs"),
        include_str!("../../../../apps/server/src/routes/controls.rs"),
        include_str!("../../../../apps/server/src/routes/halt.rs"),
        include_str!("../../../../apps/server/src/routes/model.rs"),
        include_str!("../../../../apps/server/src/routes/interview.rs"),
        include_str!("../../../../apps/server/src/routes/refusals.rs"),
        // Ajouté le 2026-09-11 avec les deux outils du registre public : le
        // test de couverture de `mod.rs` a montré que ces deux routes étaient
        // montées et déclarées par personne.
        include_str!("../../../../apps/server/src/routes/public_register.rs"),
        include_str!("../../../../apps/server/src/routes/health.rs"),
        include_str!("../../../../apps/server/src/routes/keys.rs"),
    ];

    /// Tout chemin passé à un `.route(` dans ces sources.
    ///
    /// Le littéral cherché est celui qui suit immédiatement le `.route(`, ce qui
    /// exclut les chemins cités dans une chaîne quelconque — `"POST /v1/halt"`,
    /// la constante `STOP` de `controls`, en est un — et attrape les appels
    /// écrits sur plusieurs lignes, où la parenthèse et le littéral sont séparés
    /// par un saut de ligne.
    fn declared_routes() -> BTreeSet<&'static str> {
        let mut out = BTreeSet::new();
        for source in ROUTE_SOURCES {
            for chunk in source.split(".route(").skip(1) {
                let Some(open) = chunk.find('"') else {
                    continue;
                };
                let rest = &chunk[open + 1..];
                let Some(close) = rest.find('"') else {
                    continue;
                };
                out.insert(&rest[..close]);
            }
        }
        out
    }

    /// Les champs que le schéma déclare obligatoires.
    fn required(tool: &ToolDef) -> Vec<&str> {
        tool.schema
            .get("required")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default()
    }

    /// La ligne portant ce nom. Panique si elle n'existe pas : un test qui
    /// s'endort parce qu'un outil a été renommé ne vérifie plus rien.
    fn tool_named(name: &str) -> ToolDef {
        tools()
            .into_iter()
            .find(|tool| tool.name == name)
            .unwrap_or_else(|| panic!("aucun outil nommé {name}"))
    }

    /// Ce qu'une ligne doit exiger : les trous du chemin, plus les champs nommés.
    fn demands(name: &str, fields: &[&str]) {
        let tool = tool_named(name);
        let required = required(&tool);
        for hole in tool.placeholders() {
            assert!(
                required.contains(&hole),
                "{name}: le chemin porte {hole:?} et le schéma ne l'exige pas"
            );
        }
        for field in fields {
            assert!(
                required.contains(field),
                "{name}: la route exige {field:?} et le schéma ne l'exige pas"
            );
        }
    }

    /// La garde des risques, écrite une fois pour être désarmée plus bas.
    ///
    /// Deux mensonges mécaniquement détectables : une lecture annoncée comme
    /// destructrice, qui fait confirmer pour rien jusqu'à ce que le lecteur
    /// clique sans lire ; et un `DELETE` annoncé comme lecture, qui ne fait pas
    /// confirmer du tout.
    fn risk_is_coherent(tool: &ToolDef) -> bool {
        !(tool.method == Method::Get && tool.risk.destructive())
            && !(tool.method == Method::Delete && tool.risk.read_only())
    }

    // -----------------------------------------------------------------------
    // La table contre les routes
    // -----------------------------------------------------------------------

    #[test]
    fn every_path_is_a_route_this_repository_actually_mounts() {
        let declared = declared_routes();
        assert!(
            declared.len() > 25,
            "l'extraction des routes n'a trouvé que {} chemins : le format a changé",
            declared.len()
        );
        for tool in tools() {
            assert!(
                declared.contains(tool.path),
                "{}: {} n'est monté par aucun `.route(` de ce dépôt",
                tool.name,
                tool.path
            );
        }
    }

    /// La garde ci-dessus, désarmée : un chemin qu'aucune route ne monte doit
    /// bien être absent de l'ensemble, sinon le test précédent passerait sur
    /// n'importe quoi.
    #[test]
    fn a_path_no_route_mounts_is_not_in_the_set() {
        let declared = declared_routes();
        assert!(!declared.contains("/v1/employees/{id}/promote"));
        assert!(!declared.contains("/v1/halt/now"));
        // Et une chaîne qui *cite* un chemin sans le monter n'y entre pas non
        // plus : `controls::STOP` vaut `"POST /v1/halt"`.
        assert!(!declared.contains("POST /v1/halt"));
    }

    #[test]
    fn every_path_is_absolute_and_names_all_its_holes() {
        for tool in tools() {
            assert!(
                tool.path.starts_with("/v1/"),
                "{}: {}",
                tool.name,
                tool.path
            );
            assert_eq!(
                tool.path.matches('{').count(),
                tool.path.matches('}').count(),
                "{}: accolade dépareillée dans {}",
                tool.name,
                tool.path
            );
            let properties = tool.properties();
            for hole in tool.placeholders() {
                assert!(!hole.is_empty(), "{}: trou anonyme", tool.name);
                assert!(properties.contains(&hole), "{}: {hole}", tool.name);
            }
        }
    }

    /// Aucun outil sur la surface de déploiement, sur les comptes, ni sur le
    /// serveur MCP lui-même — celui-là serait une boucle.
    #[test]
    fn nothing_here_points_at_a_surface_this_table_must_not_expose() {
        for tool in tools() {
            for forbidden in ["/v1/mcp/server", "/v1/platform/", "/v1/accounts/"] {
                assert!(
                    !tool.path.starts_with(forbidden),
                    "{}: {} est interdit à cette table",
                    tool.name,
                    tool.path
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Les risques
    // -----------------------------------------------------------------------

    #[test]
    fn no_risk_in_this_table_lies_about_its_method() {
        for tool in tools() {
            assert!(
                risk_is_coherent(&tool),
                "{}: {} annoncé {:?}",
                tool.name,
                tool.method.as_str(),
                tool.risk
            );
        }
    }

    /// La garde des risques, désarmée. Sans ce test, `risk_is_coherent` pourrait
    /// rendre `true` partout et le test au-dessus serait vert sur une table
    /// entièrement fausse.
    #[test]
    fn the_risk_guard_bites_when_a_method_and_a_risk_disagree() {
        let lying_read = t(
            "x_y",
            "…",
            "…",
            Method::Get,
            "/v1/halt",
            nothing(),
            &[],
            Risk::Destructive,
        );
        assert!(!risk_is_coherent(&lying_read));

        let silent_delete = t(
            "x_y",
            "…",
            "…",
            Method::Delete,
            "/v1/halt",
            nothing(),
            &[],
            Risk::Read,
        );
        assert!(!risk_is_coherent(&silent_delete));

        let honest = t(
            "x_y",
            "…",
            "…",
            Method::Delete,
            "/v1/halt",
            nothing(),
            &[],
            Risk::Destructive,
        );
        assert!(risk_is_coherent(&honest));
    }

    /// Ce que le lecteur du risque doit pouvoir tenir pour acquis : tout ce qui
    /// retire, annule ou relance la société est annoncé destructeur.
    #[test]
    fn what_removes_or_commits_the_company_is_declared_destructive() {
        for name in [
            "employees_suspend",
            "employees_terminate",
            "teams_members_set",
            "teams_members_remove",
            "teams_policy_role_set",
            "approvals_approve",
            "approvals_deny",
            "policy_role_set",
            "initiatives_set",
            "halt_place",
            "halt_release",
            "window_set",
        ] {
            assert!(tool_named(name).risk.destructive(), "{name}");
        }
    }

    /// Et l'inverse : une lecture qui s'annoncerait autrement ferait confirmer
    /// une requête qui n'écrit rien.
    #[test]
    fn every_get_in_this_table_is_read_only() {
        for tool in tools() {
            if tool.method == Method::Get {
                assert!(tool.risk.read_only(), "{}", tool.name);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Un test par famille : le schéma exige ce que la route exige
    // -----------------------------------------------------------------------

    #[test]
    fn the_employees_family_demands_what_its_routes_demand() {
        demands("employees_create", &["slug"]);
        demands("employees_get", &[]);
        demands("employees_suspend", &[]);
        demands("employees_resume", &[]);
        demands("employees_terminate", &[]);
        // `domain` reste facultatif : absent, l'employé est embauché sur le
        // domaine principal du locataire.
        assert!(!required(&tool_named("employees_create")).contains(&"domain"));
        // Et la pagination est une chaîne de requête, pas un corps.
        assert_eq!(tool_named("employees_list").query, ["after", "limit"]);
    }

    #[test]
    fn the_teams_family_demands_what_its_routes_demand() {
        demands("org_apply", &["rows"]);
        demands("teams_create", &["slug", "name"]);
        demands("teams_sections_create", &["slug", "name"]);
        demands("teams_members_add", &["employee_id"]);
        demands("teams_members_set", &[]);
        demands("teams_members_remove", &[]);
        demands("teams_mission_set", &["mission"]);
        demands("teams_policy_role_set", &["role_name"]);
        demands("teams_budget_set", &["daily_total"]);
        // `?currency=` est obligatoire : un budget en USD ne dit rien d'un
        // paiement en JPY.
        demands("teams_budget_get", &["currency"]);
        assert_eq!(tool_named("teams_budget_get").query, ["currency"]);
        // Une ligne d'organigramme porte les cinq colonnes du tableau ;
        // `reports_to` est ce qui manque à la ligne du CEO.
        let org = tool_named("org_apply");
        let row = &org.schema["properties"]["rows"]["items"]["required"];
        let columns = row.as_array().expect("les colonnes d'une ligne");
        for column in ["team", "name", "mission", "head", "title"] {
            assert!(
                columns.iter().any(|value| value == column),
                "org_apply: une ligne doit exiger {column}"
            );
        }
        assert!(!columns.iter().any(|value| value == "reports_to"));
    }

    #[test]
    fn the_companies_family_demands_what_its_route_demands() {
        // Les cinq, et `window_ends_at` avec eux : la route le refuse par ses
        // propres mots plutôt que par serde, parce qu'une durée par défaut
        // serait un prix.
        demands(
            "company_create",
            &["slug", "name", "org", "window_ends_at", "roles"],
        );
    }

    #[test]
    fn the_desk_family_demands_a_sender_a_recipient_and_words() {
        demands("desk_messages_send", &["to", "kind", "body"]);
        // `answers` reste facultatif au niveau du schéma : il n'est exigé que
        // par `kind: "answer"`, ce qu'un JSON Schema plat ne sait pas dire — la
        // description le dit, et la route répond 409.
        assert!(!required(&tool_named("desk_messages_send")).contains(&"answers"));
        demands("desk_messages_list", &[]);
    }

    #[test]
    fn the_approvals_family_demands_the_action_it_hashes() {
        // Sans `action`, la route approuverait par identifiant seul et la
        // comparaison de hachage serait une tautologie.
        demands("approvals_approve", &["action"]);
        demands("approvals_deny", &[]);
        assert!(!required(&tool_named("approvals_deny")).contains(&"note"));
        demands(
            "capability_requests_decide",
            &["employee_id", "action_kind", "deny_reason", "granted"],
        );
    }

    #[test]
    fn the_policy_family_demands_a_whole_layer_document() {
        // Un champ manquant n'est pas « laisse comme c'était » : le document est
        // `#[serde(default)]` et son défaut n'accorde rien. Les quatorze champs
        // sont donc exigés, comme la route les exige.
        demands(
            "policy_role_set",
            &[
                "spend",
                "allowed_channels",
                "allowed_calling_codes",
                "allowed_domains",
                "denied_domains",
                "allowed_mcp_tools",
                "allowed_a2a_peers",
                "allowed_models",
                "max_new_contacts_per_day",
                "max_turns_per_day",
                "allow_file_upload",
                "allow_credential_change",
                "allow_data_delete",
                "allow_lead_upload",
            ],
        );
        demands("policy_role_get", &[]);
    }

    #[test]
    fn the_initiative_family_demands_both_halves() {
        // Une cadence sans objectif est un employé qui se réveille sans rien à
        // faire ; un objectif sans cadence est un employé qui ne se réveille
        // jamais.
        demands("initiatives_set", &["interval_secs", "objective"]);
        let tool = tool_named("initiatives_set");
        let objective = &tool.schema["properties"]["objective"]["required"];
        assert!(
            objective
                .as_array()
                .expect("le tag de l'union")
                .iter()
                .any(|value| value == "role"),
            "le tag `role` fait l'union : sans lui rien ne se désérialise"
        );
        demands("initiatives_get", &[]);
        demands("initiatives_list", &[]);
    }

    #[test]
    fn the_interview_family_demands_a_seat_and_prose() {
        demands("interview_answer", &["answer"]);
        // Le code de la question reste facultatif : un fondateur qui parle
        // librement n'en a pas, et un code qui ne nomme rien est ignoré.
        assert!(!required(&tool_named("interview_answer")).contains(&"question"));
        demands("interview_questions_list", &[]);
    }

    #[test]
    fn the_model_family_demands_a_path_and_offers_no_subscription_token() {
        demands("model_connect", &["path"]);
        // `oauth_token` est refusé par la route depuis 2026-09-06 ; l'outil ne
        // le propose donc pas du tout, sans quoi un modèle le remplirait et
        // lirait un 400.
        assert!(
            !tool_named("model_connect")
                .properties()
                .contains(&"oauth_token")
        );
        demands("model_get", &[]);
    }

    #[test]
    fn the_halt_family_demands_the_sentence_and_the_instant() {
        // La raison est toute la valeur probante de la ligne.
        demands("halt_place", &["reason"]);
        demands("window_set", &["ends_at"]);
        // Un `DELETE` sans corps : un schéma sans propriétés, donc rien n'est
        // envoyé — ce qui le distingue d'un `POST {}`.
        assert!(tool_named("halt_release").properties().is_empty());
        demands("halt_get", &[]);
    }

    #[test]
    fn the_reading_family_puts_its_window_on_the_query_string() {
        assert_eq!(tool_named("autonomy_get").query, ["from", "to"]);
        assert_eq!(tool_named("refusals_get").query, ["days", "from", "to"]);
        demands("controls_get", &[]);
        demands("employees_turns_get", &[]);
    }

    /// La garde des champs exigés, désarmée : `demands` doit rougir sur un
    /// schéma qui n'exige pas ce qu'on lui demande, sinon les onze tests
    /// au-dessus passeraient sur des schémas vides.
    #[test]
    fn the_required_guard_bites_when_a_schema_forgets_a_field() {
        let forgetful = t(
            "x_y",
            "…",
            "…",
            Method::Post,
            "/v1/halt",
            json!({
                "type": "object",
                "properties": { "reason": { "type": "string" } },
                "required": [],
            }),
            &[],
            Risk::Destructive,
        );
        assert!(required(&forgetful).is_empty());

        // Et un trou de chemin qu'aucun champ obligatoire ne nomme : l'URL
        // partirait avec `{id}` en toutes lettres.
        let hole_unnamed = t(
            "x_y",
            "…",
            "…",
            Method::Get,
            "/v1/employees/{id}/turns",
            json!({ "type": "object", "properties": {}, "required": [] }),
            &[],
            Risk::Read,
        );
        assert!(!required(&hole_unnamed).contains(&hole_unnamed.placeholders()[0]));
    }

    /// Enfin, ce que la table promet en volume : chaque famille de routes de ce
    /// domaine a au moins une ligne, et aucune n'a été oubliée en chemin.
    #[test]
    fn every_family_of_this_domain_has_at_least_one_tool() {
        let names: Vec<&str> = tools().iter().map(|tool| tool.name).collect();
        for prefix in [
            "company_",
            "employees_",
            "org_",
            "teams_",
            "desk_",
            "approvals_",
            "capability_requests_",
            "policy_",
            "controls_",
            "employees_turns_",
            "refusals_",
            "autonomy_",
            "initiatives_",
            "interview_",
            "model_",
            "halt_",
            "window_",
        ] {
            assert!(
                names.iter().any(|name| name.starts_with(prefix)),
                "aucun outil pour la famille {prefix}"
            );
        }
    }
}

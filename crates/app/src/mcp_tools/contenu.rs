//! Les outils du domaine « contenu » : **être cité quand quelqu'un demande à un
//! modèle comment faire ce que nous vendons.**
//!
//! `agentos_app::content` porte la thèse et les limites de la mesure,
//! `docs/CONTENU.md` la boucle entière. Douze lignes, une par route montée par
//! `apps/server/src/routes/content.rs`.
//!
//! # Ce que les descriptions portent, et pourquoi
//!
//! Un modèle choisit un outil sur sa `description` seule, et les quatre pièges
//! d'ici ne se devinent pas depuis un nom de route :
//!
//! * **`content_drafts_propose` a trois préalables, dont deux invisibles.** Un
//!   dépôt (`content_repos_set`), une politique qui nomme les trois outils de
//!   GitHub, et — celui que la boucle marchée le 2026-09-12 a trouvé —
//!   `integrations_tools_declare` sur chacun des trois. Un outil qu'aucune
//!   déclaration ne classe est traité comme destructif, donc refusé avant le
//!   transport ; la description le dit parce qu'aucun schéma ne le porte.
//! * **`content_questions_measure` nomme un siège.** La mesure est une lecture de page
//!   publique, donc une action sur laquelle la Policy Gate statue pour un
//!   employé. Un siège sans `web` ne mesure pas, et le refus est un 403 avec
//!   une raison, pas un bug.
//! * **Un seul moteur est lisible**, `duckduckgo_lite`, et les autres ne sont
//!   pas « à venir » : ils demandent un compte ou le refusent dans leur
//!   `robots.txt`. La description le dit pour qu'un modèle cesse de proposer
//!   `chatgpt` comme valeur.
//! * **Rien ici n'écrit de texte, et rien ici ne publie.** `content_briefs_get`
//!   rend une structure — ce qui est couvert, ce qui ne l'est pas, qui
//!   dépasser — et c'est l'employé qui écrit l'article, puis `content_drafts_*`
//!   qui le range. L'`url` d'un brouillon est une adresse **constatée**, et
//!   `content_drafts_propose` ne la remplit pas : elle ouvre une pull request,
//!   ce qui laisse le brouillon `proposed` et l'article nulle part. C'est la
//!   distinction que les deux descriptions répètent, parce que c'est celle
//!   qu'un modèle pressé écrasera.
//!
//! # Le risque, ligne par ligne
//!
//! [`Risk::Destructive`] sur cinq lignes : retirer une question emporte sa
//! série de mesures et ses brouillons par cascade ; réviser un brouillon, comme
//! remplacer le dépôt d'un siège, écrase ce qui est omis ;
//! `content_questions_measure` **sort sur le web au nom de la société** et
//! `content_drafts_propose` **écrit dans le dépôt d'un client et y ouvre une
//! demande en son nom**, ce qui est la deuxième moitié de la définition du mot
//! ici. Ajouter une question ou ouvrir un brouillon n'enlève rien et n'engage
//! personne : [`Risk::Write`].

use serde_json::{Value, json};

use crate::mcp_server::{Method, Risk, ToolDef};

/// Fabrique une ligne, comme les six autres domaines.
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
        // Aucune route de ce domaine ne prend autre chose que du JSON.
        raw_body: None,
        risk,
    }
}

fn schema(properties: Value, required: &[&str]) -> Value {
    json!({ "type": "object", "properties": properties, "required": required })
}

fn nothing() -> Value {
    schema(json!({}), &[])
}

/// L'identifiant d'une question, celui que `content_questions_list` rend.
fn question_id() -> Value {
    json!({
        "type": "string",
        "format": "uuid",
        "description": "L'identifiant de la question, tel que `content_questions_list` le rend."
    })
}

/// Les lignes de ce domaine.
#[must_use]
pub fn tools() -> Vec<ToolDef> {
    vec![
        t(
            "content_questions_list",
            "Les questions qu'on veut gagner",
            "Les questions sur lesquelles cette entreprise veut être citée, les plus lourdes d'abord. \
             À appeler en premier dans ce domaine : tout le reste prend un `question_id` qui vient d'ici.",
            Method::Get,
            "/v1/content/questions",
            nothing(),
            &[],
            Risk::Read,
        ),
        t(
            "content_questions_add",
            "Viser une question de plus",
            "Ajoute une question à gagner. Une phrase entière, pas un mot-clé : ce qu'on mesure est une \
             réponse à une question. Rejouer le même couple (question, locale) rend la ligne existante \
             et ne change ni son poids ni sa provenance — c'est ce qui garde la série de mesures accrochée \
             à une seule ligne.",
            Method::Post,
            "/v1/content/questions",
            schema(
                json!({
                    "question": {
                        "type": "string",
                        "description": "La question telle qu'un humain la poserait, p. ex. « comment vérifier les conditions d'entrée d'un pays par API »."
                    },
                    "locale": {
                        "type": "string",
                        "description": "`fr`, `en`, … La même question en deux langues est deux lignes : les pages citées ne sont pas les mêmes."
                    },
                    "source": {
                        "type": "string",
                        "enum": ["founder", "search_suggest", "customer"],
                        "description": "D'où elle vient. `customer` — quelqu'un l'a réellement posée — vaut dix `founder`."
                    },
                    "weight": {
                        "type": "integer",
                        "description": "Combien elle compte, pour trier la liste. 1 par défaut."
                    }
                }),
                &["question", "locale", "source"],
            ),
            &[],
            Risk::Write,
        ),
        t(
            "content_questions_remove",
            "Cesser de viser une question",
            "Retire une question **et tout ce qui pend dessous** : sa série de mesures et ses brouillons \
             partent avec elle. La série est le produit de ce domaine ; ne pas retirer une question pour \
             corriger son poids ou sa formulation, en ajouter une autre.",
            Method::Delete,
            "/v1/content/questions/{id}",
            schema(json!({ "id": question_id() }), &["id"]),
            &[],
            Risk::Destructive,
        ),
        t(
            "content_questions_measure",
            "Mesurer : qui est cité sur cette question, aujourd'hui",
            "Pose la question à un moteur, lit la page de résultats et classe une mesure : y sommes-nous, \
             à quel rang, et qui l'est à notre place. **Nomme un siège** (`employee_id`) parce que lire une \
             page publique est une action sur laquelle la politique statue — un siège sans le canal `web` \
             est refusé, avec la raison. Un seul moteur est lisible par ce déploiement, `duckduckgo_lite` : \
             les réponses de ChatGPT, de Claude ou de Gemini demandent un compte et ne sont pas mesurables \
             ici, et Google, Bing, Brave, Mojeek et Startpage refusent leurs pages de résultats dans leur \
             `robots.txt`. À appeler régulièrement : une mesure isolée ne dit rien, c'est la série qui parle.",
            Method::Post,
            "/v1/content/questions/{id}/measure",
            schema(
                json!({
                    "id": question_id(),
                    "employee_id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "Le siège à qui la lecture est attribuée. Sa politique doit porter le canal `web`."
                    },
                    "engine": {
                        "type": "string",
                        "enum": ["duckduckgo_lite"],
                        "description": "Le seul moteur que ce déploiement sait lire sans compte et sans contourner un refus."
                    }
                }),
                &["id", "employee_id", "engine"],
            ),
            &[],
            Risk::Destructive,
        ),
        t(
            "content_citations_list",
            "La série d'une question dans le temps",
            "Les mesures d'une question sur une fenêtre, de la plus récente à la plus ancienne. C'est ici \
             qu'on lit si on monte ou si on descend — et ce qu'a changé un article publié. Les lignes ne se \
             réécrivent jamais.",
            Method::Get,
            "/v1/content/citations",
            schema(
                json!({
                    "question_id": question_id(),
                    "days": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 366,
                        "description": "Jours comptés à rebours depuis maintenant. 30 par défaut."
                    }
                }),
                &["question_id"],
            ),
            &["question_id", "days"],
            Risk::Read,
        ),
        t(
            "content_briefs_get",
            "Ce qu'il faut écrire pour dépasser ceux qui sont cités",
            "Rend une **structure**, pas un texte : les facettes que les pages citées couvrent déjà, celles \
             qu'aucune ne couvre (c'est là qu'est la place), les hôtes à dépasser, et l'angle. Bâti sur la \
             dernière mesure de la question — appeler `content_questions_measure` d'abord, sinon la réponse est un 409 \
             qui le dit. C'est l'employé qui écrit l'article à partir de ça, et `content_drafts_add` qui le range.",
            Method::Get,
            "/v1/content/briefs",
            schema(json!({ "question_id": question_id() }), &["question_id"]),
            &["question_id"],
            Risk::Read,
        ),
        t(
            "content_drafts_list",
            "Ce qui a été écrit, et ce qui est publié",
            "Les brouillons de cette entreprise, du plus récent au plus ancien. `state` vaut `draft`, \
             `proposed` — une pull request est ouverte à l'adresse `review_url`, et rien n'est en ligne — ou \
             `published`, auquel cas la ligne porte l'adresse où l'article a été vu et la date où il l'a été.",
            Method::Get,
            "/v1/content/drafts",
            nothing(),
            &[],
            Risk::Read,
        ),
        t(
            "content_drafts_add",
            "Ranger un article écrit pour une question",
            "Ouvre un brouillon sur une question. Le texte est celui que tu viens d'écrire : rien dans ce \
             déploiement n'engendre de prose, et `content_briefs_get` ne rend que la structure à couvrir.",
            Method::Post,
            "/v1/content/drafts",
            schema(
                json!({
                    "question_id": question_id(),
                    "title": { "type": "string", "description": "Le titre de l'article." },
                    "body": { "type": "string", "description": "Le texte entier." }
                }),
                &["question_id", "title", "body"],
            ),
            &[],
            Risk::Write,
        ),
        t(
            "content_drafts_amend",
            "Réécrire un brouillon, ou constater qu'il est publié",
            "Remplace le titre et le texte — **ce qui est omis est perdu**, envoyer les deux à chaque fois. \
             Passer une `url` marque le brouillon comme publié à cette adresse ; ne la passer que si \
             l'article y est réellement, parce que cette colonne est un constat — `content_drafts_propose` \
             ouvre une pull request et ne remplit jamais celle-ci. **`url` est omise comme le reste : la \
             réenvoyer à chaque correction.** Un article publié qu'on corrige sans elle retombe à \
             `proposed` (ou à `draft`), perd son adresse **et sa date de publication** — et une adresse \
             remise ensuite porte une date neuve, donc la série de citations n'a plus rien à quoi comparer \
             un avant et un après. Avec elle, la date de la première publication ne bouge pas : corriger \
             une typo ne republie pas. Corriger un brouillon proposé mais non publié le laisse `proposed` \
             et ne repousse rien dans la pull request ouverte.",
            Method::Put,
            "/v1/content/drafts/{id}",
            schema(
                json!({
                    "id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "L'identifiant du brouillon, tel que `content_drafts_list` le rend."
                    },
                    "title": { "type": "string", "description": "Le titre, en entier." },
                    "body": { "type": "string", "description": "Le texte, en entier." },
                    "url": {
                        "type": "string",
                        "description": "L'adresse où l'article a été publié. **Omise, elle est effacée** : le brouillon cesse d'être publié et perd sa date. La réenvoyer à chaque correction d'un article en ligne."
                    }
                }),
                &["id", "title", "body"],
            ),
            &[],
            Risk::Destructive,
        ),
        t(
            "content_repos_list",
            "Les dépôts où les sièges poussent leurs articles",
            "Le dépôt de chaque siège qui en a un : le branchement GitHub utilisé, `propriétaire/nom`, la \
             branche qui sert le site et le dossier des articles. À lire avant `content_drafts_propose`, \
             qui échoue en `no_repo` pour un siège absent de cette liste.",
            Method::Get,
            "/v1/content/repos",
            nothing(),
            &[],
            Risk::Read,
        ),
        t(
            "content_repos_set",
            "Attacher un dépôt à un siège, ou remplacer le sien",
            "Dit où ce siège pousse ses articles. **Remplace la ligne en entier** : les quatre champs sont \
             obligatoires à chaque appel. `server` est le handle du branchement, celui qu'`integrations_servers_list` \
             rend — pas le nom du connecteur — et rien n'est écrit si aucun branchement ne porte ce handle. \
             `branch` est la branche **qui sert le site**, c'est-à-dire la cible de la pull request : celle \
             qui porte l'article est créée par `content_drafts_propose` et n'a pas à être configurée.",
            Method::Put,
            "/v1/content/repos/{employee_id}",
            schema(
                json!({
                    "employee_id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "Le siège, tel qu'`employees_list` le rend."
                    },
                    "server": {
                        "type": "string",
                        "description": "Le handle du branchement GitHub de ce locataire, tel qu'`integrations_servers_list` le rend."
                    },
                    "repo": {
                        "type": "string",
                        "description": "`propriétaire/nom`, comme GitHub l'écrit."
                    },
                    "branch": {
                        "type": "string",
                        "description": "La branche qui sert le site, p. ex. `main` : la pull request est ouverte vers elle."
                    },
                    "folder": {
                        "type": "string",
                        "description": "Le dossier que le générateur lit, p. ex. `content/blog` ou `_posts`. Relatif, sans `..` ni barre de tête."
                    }
                }),
                &["employee_id", "server", "repo", "branch", "folder"],
            ),
            &[],
            Risk::Destructive,
        ),
        t(
            "content_drafts_propose",
            "L'article devient une pull request chez le client",
            "Pousse l'article dans le dépôt du siège, sur une branche à lui, et ouvre une pull request vers \
             la branche qui sert le site. **Ça ne publie pas** : le brouillon passe à `proposed`, pas à \
             `published`, et ce qui met l'article en ligne est une personne qui fusionne la demande — c'est \
             elle, la relecture. **Trois choses doivent être en place avant le premier appel, et deux ne se \
             devinent pas** : le siège a un dépôt (`content_repos_set`) ; sa politique l'autorise à appeler \
             `create-branch`, `create-or-update-file` et `create-pull-request` — chacun des trois est un \
             verdict de la Policy Gate, et un refus est un 403 `no_rule` ; et ces trois outils ont été \
             **déclarés** sur le branchement GitHub par `integrations_tools_declare`, avec le `digest` que \
             rend `integrations_discover`. Un outil non déclaré est traité comme destructif, donc refusé \
             avant qu'un octet parte, et la réponse est un 409 `tool_unavailable` — pas une panne chez le \
             client. Seul un brouillon se propose : rappeler cet outil sur un brouillon déjà proposé rend \
             `not_a_draft` plutôt qu'une deuxième pull request. Et un article déjà fusionné sous le même \
             titre rend `github_refused` sur `create-or-update-file` : le chemin existe, et republier \
             demanderait le `sha` de la version remplacée, que rien ici ne lit.",
            Method::Post,
            "/v1/content/drafts/{id}/propose",
            schema(
                json!({
                    "id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "L'identifiant du brouillon, tel que `content_drafts_list` le rend."
                    },
                    "employee_id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "Le siège au nom de qui la pull request s'ouvre, et celui dont le dépôt est lu."
                    }
                }),
                &["id", "employee_id"],
            ),
            &[],
            Risk::Destructive,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Une ligne par route montée, et le chemin de chacune est bien un chemin de
    /// ce domaine. Le test de couverture de `mod.rs` prouve l'autre sens.
    #[test]
    fn douze_lignes_pour_douze_routes() {
        let all = tools();
        assert_eq!(all.len(), 12, "une route montée n'a pas sa ligne");
        for tool in &all {
            assert!(
                tool.path.starts_with("/v1/content/"),
                "{} sort du domaine : {}",
                tool.name,
                tool.path
            );
            assert!(
                tool.name.starts_with("content_"),
                "{} ne suit pas la convention domaine_objet_verbe",
                tool.name
            );
        }
    }

    /// Le seul moteur lisible est nommé dans le schéma, pas seulement en prose :
    /// un modèle qui propose `chatgpt` doit être refusé par le schéma avant
    /// qu'un appel parte.
    #[test]
    fn le_schema_de_la_mesure_ferme_la_liste_des_moteurs() {
        let measure = tools()
            .into_iter()
            .find(|tool| tool.name == "content_questions_measure")
            .expect("content_questions_measure");
        let engines = measure.schema["properties"]["engine"]["enum"]
            .as_array()
            .expect("une liste fermée");
        assert_eq!(engines, &[json!("duckduckgo_lite")]);
        // Et le siège est exigé : sans lui la Policy Gate n'a personne sur qui
        // statuer, et la route répond 422 plutôt que de lire une page.
        assert!(
            measure.schema["required"]
                .as_array()
                .expect("required")
                .contains(&json!("employee_id"))
        );
    }
}

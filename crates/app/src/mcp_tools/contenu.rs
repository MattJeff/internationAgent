//! Les outils du domaine « contenu » : **être cité quand quelqu'un demande à un
//! modèle comment faire ce que nous vendons.**
//!
//! `agentos_app::content` porte la thèse et les limites de la mesure,
//! `docs/CONTENU.md` la boucle entière. Neuf lignes, une par route montée par
//! `apps/server/src/routes/content.rs`.
//!
//! # Ce que les descriptions portent, et pourquoi
//!
//! Un modèle choisit un outil sur sa `description` seule, et les trois pièges
//! d'ici ne se devinent pas depuis un nom de route :
//!
//! * **`content_questions_measure` nomme un siège.** La mesure est une lecture de page
//!   publique, donc une action sur laquelle la Policy Gate statue pour un
//!   employé. Un siège sans `web` ne mesure pas, et le refus est un 403 avec
//!   une raison, pas un bug.
//! * **Un seul moteur est lisible**, `duckduckgo_lite`, et les autres ne sont
//!   pas « à venir » : ils demandent un compte ou le refusent dans leur
//!   `robots.txt`. La description le dit pour qu'un modèle cesse de proposer
//!   `chatgpt` comme valeur.
//! * **Rien ici ne publie, et rien n'écrit de texte.** `content_briefs_get`
//!   rend une structure — ce qui est couvert, ce qui ne l'est pas, qui
//!   dépasser — et c'est l'employé qui écrit l'article, puis `content_drafts_*`
//!   qui le range. L'`url` d'un brouillon est une adresse **constatée**.
//!
//! # Le risque, ligne par ligne
//!
//! [`Risk::Destructive`] sur trois lignes seulement : retirer une question
//! emporte sa série de mesures et ses brouillons par cascade ; réviser un
//! brouillon remplace son texte et ce qui est omis est perdu ; et
//! `content_questions_measure` **sort sur le web au nom de la société**, ce qui est la
//! deuxième moitié de la définition du mot ici. Ajouter une question ou ouvrir
//! un brouillon n'enlève rien et n'engage personne : [`Risk::Write`].

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
            "Les brouillons de cette entreprise, du plus récent au plus ancien. `state` vaut `draft` ou \
             `published` ; un publié porte l'adresse où il a été vu et la date où il l'a été.",
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
             l'article y est réellement, parce que rien ici ne publie et que cette colonne est un constat. \
             La date de publication est posée la première fois et ne bouge plus : corriger une typo ne \
             republie pas.",
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
                        "description": "L'adresse où l'article a été publié. Omise, le brouillon redevient un brouillon."
                    }
                }),
                &["id", "title", "body"],
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
    fn neuf_lignes_pour_neuf_routes() {
        let all = tools();
        assert_eq!(all.len(), 9, "une route montée n'a pas sa ligne");
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

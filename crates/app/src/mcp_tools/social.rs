//! Les outils du domaine « social » : ce que l'entreprise **publie**.
//!
//! Cinq lignes, une par route de `apps/server/src/routes/social.rs`, et ce
//! module ne fait rien d'autre — le câblage, le chemin choisi (un connecteur du
//! catalogue, pas un service hébergé) et la garde anti-contact-privé sont
//! argumentés là-bas, à l'endroit où le code tourne.
//!
//! # Ce que le locataire fait AVANT que ces outils répondent
//!
//! Trois gestes, tous avec des outils qui existaient déjà, et c'est la moitié du
//! choix « connecteur » : rien n'a été réécrit pour le social.
//!
//! 1. `integrations_connect` avec `connector: "custom"`, l'URL de
//!    `agentos-social`, le jeton frappé par `agentos-social mint-tenant`, et le
//!    handle **`social`** — c'est le nom que les routes cherchent.
//! 2. `integrations_discover` sur ce handle : la table du service, chaque outil
//!    avec le digest SHA-256 de ce qu'on vient de lire.
//! 3. `integrations_declare_tool` par outil, avec ce digest. **Sans cette
//!    étape rien ne part** : un outil que personne n'a déclaré est
//!    `Destructive`, donc il demande un humain, donc l'appel est refusé — et le
//!    403 de la route le dit avec les deux outils à appeler. C'est voulu :
//!    publier au nom de l'entreprise n'est pas une chose qu'on branche par
//!    accident.
//!
//! Puis `social_account_connect_url` par compte, une fois, et un humain ouvre
//! l'URL. Les comptes développeur, eux, restent au fondateur — `docs/SOCIAL.md`,
//! § « Les revues d'app ».
//!
//! # Les schémas reflètent la table **v3** du service
//!
//! `crate::mcp_server` refuse un argument que le schéma ne nomme pas, *avant*
//! l'appel. Donc tout champ que le service accepte et que ces schémas ignorent
//! est un champ inatteignable depuis un terminal, et tout champ nommé ici que le
//! service ne connaît pas est ignoré en silence par lui. Ces schémas sont un
//! miroir tenu à la main de `apps/social/src/mcp.rs::description_outils` — le
//! jour où `VERSION_TABLE` bouge, cette liste bouge avec, sinon un champ neuf
//! n'existe pour personne. Les bornes, elles, ne sont **pas** recopiées : le
//! service les tient, plateforme par plateforme, avec le mot exact et le chiffre
//! cités de la doc officielle.
//!
//! # Ce qui n'est pas ici, et pourquoi
//!
//! * **`post_metrics`** — le sixième outil du service. Rien ne l'empêche ; il
//!   n'a simplement pas de route parce que « combien de vues » n'est pas le
//!   chemin de « je veux publier » à « c'est publié ». Deux lignes le jour où
//!   quelqu'un le demande, et son mot (« la plateforme ne les sert pas ») vaut
//!   mieux qu'un tableau de zéros.
//! * **Les quatorze outils de `/mcp/messagerie`** — le service a une seconde
//!   table qui, elle, atteint des gens. Elle n'a aucune route ici, aucun nom
//!   dans cette liste, et le test `la_seconde_table_du_service_est_hors_de_portee`
//!   de `routes::social` tombe si l'un d'eux entre. La promesse
//!   `OptOuts::NoStrangers` de l'éditeur est vraie par construction chez le
//!   service ; du côté appelant, elle l'est par cette liste.

use serde_json::{Value, json};

use crate::mcp_server::{Method, Risk, ToolDef};

/// Les champs de contenu partagés par l'aperçu et la publication.
///
/// Une fonction et pas deux littéraux recopiés : deux schémas qui doivent dire
/// la même phrase et qu'on écrit deux fois sont deux schémas qui divergent, et
/// l'empreinte d'un aperçu contresigne exactement ce que la publication envoie.
fn contenu() -> Value {
    json!({
        "account_id": {
            "type": "string",
            "description": "Le compte à publier, tel que `social_accounts_list` le rend.",
        },
        "text": {
            "type": "string",
            "description": "Le texte du post. Côté YouTube c'est la description ; le titre \
                            de la vidéo est `media[].title`.",
        },
        "media": {
            "type": "array",
            "minItems": 1,
            "maxItems": 20,
            "description": "1 à 20 médias par leur URL https. Le service télécharge lui-même \
                            les octets, les vette (IP publique, type détecté aux magic bytes, \
                            plafond compté en vol) et les empreinte — l'URL n'est jamais \
                            tirée par la plateforme.",
            "items": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "alt_text": {"type": "string"},
                    "title": {
                        "type": "string",
                        "description": "OBLIGATOIRE pour une vidéo YouTube : c'est \
                                        `snippet.title`.",
                    },
                },
                "required": ["url"],
            },
        },
        "poll": {
            "type": "object",
            "description": "Un sondage, là où la plateforme en sert un. Les bornes exactes \
                            sont celles de la plateforme et c'est elle qui refuse, avec sa \
                            citation.",
            "properties": {
                "question": {"type": "string"},
                "options": {"type": "array", "items": {"type": "string"}},
                "duration_minutes": {"type": "integer"},
            },
            "required": ["options", "duration_minutes"],
        },
        "made_with_ai": {
            "type": "boolean",
            "description": "Déclare le contenu comme généré : `is_ai_generated` chez \
                            Instagram, `is_aigc` chez TikTok.",
        },
        "privacy": {
            "type": "string",
            "enum": ["public", "friends", "followers", "private", "unlisted"],
            "description": "REQUIS par TikTok (`privacy_level`), servi par YouTube \
                            (`privacyStatus`), refus nommé ailleurs. Absent chez TikTok : \
                            `SELF_ONLY`, ce qui est l'état d'une app non auditée.",
        },
        "publish_at": {
            "type": "string",
            "description": "ISO 8601, YouTube seul (`status.publishAt`, qui force `private` \
                            d'ici là). Refus nommé ailleurs.",
        },
    })
}

/// Les lignes de ce domaine.
#[must_use]
pub fn tools() -> Vec<ToolDef> {
    let publish_schema = {
        let mut properties = contenu();
        let object = properties.as_object_mut().expect("un objet");
        object.insert(
            "idempotency_key".to_owned(),
            json!({
                "type": "string",
                "description": "OBLIGATOIRE. Rejouer la même clé rend le même post sans \
                                republier — la contrainte est en base, pas dans du code, donc \
                                un tour retenté ne double-poste pas.",
            }),
        );
        object.insert(
            "expected_media_digests".to_owned(),
            json!({
                "type": "array",
                "items": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "description": "Les empreintes rendues par `social_post_preview`. Le service \
                                compare terme à terme les octets qu'il vient de télécharger à \
                                ceux contresignés et refuse (`media_change`) AVANT de \
                                consommer la clé d'idempotence — c'est ce qui empêche de \
                                changer l'image après l'approbation.",
            }),
        );
        json!({
            "type": "object",
            "properties": properties,
            "required": ["idempotency_key", "account_id", "text"],
        })
    };

    vec![
        ToolDef {
            name: "social_accounts_list",
            title: "Les comptes sociaux branchés",
            description: "Les comptes que ce locataire a connectés chez son agrégateur — \
                          plateforme, handle, état — et le seul endroit d'où sort l'\
                          `account_id` que les trois outils suivants demandent. Premier appel \
                          de tout ce domaine : une liste vide veut dire qu'aucun compte n'a \
                          encore été autorisé, et `social_account_connect_url` est l'étape \
                          d'après. Un 404 `no_social_binding` veut dire autre chose — que \
                          l'agrégateur lui-même n'est pas branché, ce qui se répare avec \
                          `integrations_connect` et non ici.",
            method: Method::Get,
            path: "/v1/social/accounts",
            schema: json!({"type": "object", "properties": {}}),
            query: &[],
            raw_body: None,
            risk: Risk::Read,
        },
        ToolDef {
            name: "social_account_connect_url",
            title: "L'URL d'autorisation d'un compte social",
            description: "Rend l'URL OAuth qu'un HUMAIN doit ouvrir pour autoriser un compte \
                          sur une plateforme ; le retour se fait tout seul sur le callback du \
                          service. Ne connecte rien par lui-même — il n'y a pas de chemin par \
                          lequel un modèle termine ce consentement, et c'est voulu. À \
                          utiliser quand `social_accounts_list` ne montre pas le compte voulu, \
                          ou quand un compte connecté répond par une erreur qui renvoie ici \
                          (des portées ont été ajoutées depuis : un seul re-consentement \
                          répare).",
            method: Method::Post,
            path: "/v1/social/accounts/connect",
            schema: json!({
                "type": "object",
                "properties": {
                    "platform": {
                        "type": "string",
                        "enum": ["x", "linkedin", "instagram", "tiktok", "youtube"],
                        "description": "Les cinq plateformes servies. Une sixième n'existe \
                                        pas : elle attend une revue d'app que seul le \
                                        fondateur peut déposer.",
                    },
                },
                "required": ["platform"],
            }),
            query: &[],
            raw_body: None,
            risk: Risk::Write,
        },
        ToolDef {
            name: "social_post_preview",
            title: "Ce qui partirait, au caractère et à l'octet près",
            description: "Le contenu EXACT qui serait publié — texte rendu, médias téléchargés \
                          avec l'empreinte SHA-256 de leurs octets, verdict des limites de la \
                          plateforme, coût estimé — plus une empreinte GLOBALE qui couvre le \
                          texte, chaque média, le sondage et la confidentialité. C'est cette \
                          empreinte qu'une approbation humaine contresigne, et qu'on repasse à \
                          `social_post_publish` dans `expected_media_digests`. À appeler avant \
                          toute publication qui porte un média : un aperçu qui passe et une \
                          publication qui échoue, c'est une limite de plateforme nommée dans \
                          les verdicts.",
            method: Method::Post,
            path: "/v1/social/preview",
            schema: json!({
                "type": "object",
                "properties": contenu(),
                "required": ["account_id", "text"],
            }),
            query: &[],
            raw_body: None,
            // Read : rien n'est publié, rien n'est visible de personne. Les
            // octets téléchargés atterrissent dans un dépôt adressé par digest
            // avec une heure de vie — un effet de bord de la lecture, pas un
            // fait qu'un opérateur puisse constater ailleurs.
            risk: Risk::Read,
        },
        ToolDef {
            name: "social_post_publish",
            title: "Publier, pour de vrai",
            description: "Publie sur le compte nommé. `idempotency_key` est OBLIGATOIRE et \
                          rejouer la même clé rend le même post sans republier — un tour \
                          retenté ne double-poste pas. Passer les `expected_media_digests` \
                          d'un `social_post_preview` refuse (`media_change`) si les octets ne \
                          sont plus ceux qui ont été contresignés, avant de consommer la clé. \
                          Ce qui part est public et engage l'entreprise : c'est le seul outil \
                          de ce domaine qu'on ne rejoue pas pour voir.",
            method: Method::Post,
            path: "/v1/social/posts",
            schema: publish_schema,
            query: &[],
            raw_body: None,
            // Rien ne s'efface, mais un post est vu — la définition même de
            // `Destructive` ici : engager la société devant un tiers.
            risk: Risk::Destructive,
        },
        ToolDef {
            name: "social_posts_list",
            title: "Ce qui est parti",
            description: "L'historique des posts de ce locataire, du plus récent au plus \
                          ancien, avec pour chacun l'identifiant côté plateforme, l'URL et les \
                          empreintes des médias publiés — l'audit du contreseing, octet par \
                          octet. À utiliser pour répondre à « est-ce que c'est bien parti » et \
                          pour retrouver le `post_id` d'un post.",
            method: Method::Get,
            path: "/v1/social/posts",
            schema: json!({
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 200,
                        "description": "Défaut du service, maximum 200.",
                    },
                },
            }),
            query: &["limit"],
            raw_body: None,
            risk: Risk::Read,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Les interdits du service, recopiés avec leur épreuve — un test qui ne
    /// peut pas échouer est pire que pas de test, donc chacun doit d'abord
    /// reconnaître un nom hostile.
    const INTERDITS: &[(&str, &str)] = &[
        ("dm", "social_send_dm"),
        ("message", "social_message_user"),
        ("broadcast", "social_broadcast_all"),
        ("direct", "social_direct_post"),
        ("inbox", "social_inbox_read"),
        ("chat", "social_chat_open"),
        ("reply", "social_reply_to_user"),
        ("send", "social_send_note"),
        ("mention", "social_mention_user"),
    ];

    /// **La promesse fondatrice, du côté de la table que le modèle lit.**
    ///
    /// `routes::social` crible les noms qu'il sait prononcer ; ceci crible ce
    /// qu'un modèle voit. Les deux sont nécessaires : un outil déclaré ici sans
    /// route est attrapé par la couverture de `super`, mais c'est cette table
    /// qui dit à un modèle ce qu'il a le droit de vouloir.
    ///
    /// La liste est celle du service, mot pour mot : deux cribles qui divergent
    /// seraient une porte fermée d'un côté et ouverte de l'autre.
    #[test]
    fn aucun_outil_de_ce_domaine_ne_parle_a_quelqu_un() {
        for (motif, hostile) in INTERDITS {
            assert!(
                hostile.contains(motif),
                "l'interdit `{motif}` ne reconnaît pas `{hostile}`"
            );
        }
        let outils = tools();
        assert!(!outils.is_empty(), "une table vide ne prouve rien");
        for outil in &outils {
            for (motif, _) in INTERDITS {
                assert!(
                    !outil.name.contains(motif),
                    "`{}` contient l'interdit `{motif}` : ce domaine publie, il n'atteint \
                     personne qui n'a rien demandé",
                    outil.name
                );
            }
        }
    }

    /// Le domaine tient dans son préfixe, des deux côtés : le nom qu'un modèle
    /// tape et le chemin qui part.
    #[test]
    fn chaque_ligne_est_du_social_et_rien_d_autre() {
        for outil in tools() {
            assert!(outil.name.starts_with("social_"), "{}", outil.name);
            assert!(outil.path.starts_with("/v1/social"), "{}", outil.path);
        }
    }

    /// Un `GET` qui n'est pas `Read` ment à l'annotation `readOnlyHint`, et
    /// publier qui ne serait pas `Destructive` ferait cliquer « oui » sans lire
    /// sur le seul appel de ce domaine qui engage l'entreprise devant le monde.
    #[test]
    fn les_risques_disent_la_verite_sur_les_verbes() {
        for outil in tools() {
            if outil.method == Method::Get {
                assert!(outil.risk.read_only(), "{}", outil.name);
            }
            assert_eq!(
                outil.risk.destructive(),
                outil.name == "social_post_publish",
                "{} : seul publier engage l'entreprise devant un tiers",
                outil.name
            );
        }
    }

    /// Ce que la route exige et que le schéma doit exiger aussi : le modèle lit
    /// le schéma, jamais le gestionnaire.
    #[test]
    fn publier_exige_la_cle_d_idempotence() {
        let publish = tools()
            .into_iter()
            .find(|t| t.name == "social_post_publish")
            .expect("l'outil de publication");
        let required = publish.schema["required"]
            .as_array()
            .expect("des champs requis")
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect::<Vec<_>>();
        for champ in ["idempotency_key", "account_id", "text"] {
            assert!(required.contains(&champ.to_owned()), "{champ}");
        }
        assert!(publish.properties().contains(&"expected_media_digests"));
    }
}

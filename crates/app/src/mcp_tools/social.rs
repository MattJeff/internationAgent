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
//! Puis `social_connect_url_get` par compte, une fois, et un humain ouvre
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
            "description": "ISO 8601 (RFC 3339). La file durable du service publie à cette \
                            heure sur tous les réseaux. YouTube ne reçoit plus `status.publishAt` : \
                            la vidéo part à l'heure dite, avec la visibilité demandée.",
        },
        "placement": {
            "type": "string",
            "enum": ["feed", "story", "reel"],
            "description": "instagram : `story` publie un conteneur STORIES sans légende, \
                            `reel` force un Reel, absent = image, Reel ou carrousel selon les octets. \
                            instagram_reels n'accepte que l'absence ou `reel`. \
                            facebook_page : absent ou `feed` = texte, photo ou vidéo de fil ; \
                            `reel` = Reel de Page.",
        },
        "delivery": {
            "type": "string",
            "enum": ["publish", "draft"],
            "description": "TikTok. `publish` poste (scope video.publish). `draft` envoie la \
                            vidéo en brouillon (scope video.upload) : le créateur la finalise \
                            dans l'application. Absent : publish. Une app non auditée retombe \
                            sur SELF_ONLY.",
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
                "description": "Les empreintes rendues par `social_post_preview_get`. Le service \
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
                          encore été autorisé, et `social_connect_url_get` est l'étape \
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
            name: "social_connect_url_get",
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
                        "enum": ["x", "linkedin", "instagram", "tiktok", "youtube", "instagram_reels", "facebook_page", "threads"],
                        "description": "instagram est le connecteur historique (SOCIAL_META_*, Instagram Login). \
                                        instagram_reels et facebook_page partagent UN consentement \
                                        Facebook Login for Business (META2_APP_* et META2_FB_CONFIG_ID) : \
                                        la Page et le compte Instagram professionnel qui y est lié. \
                                        threads est l'app Threads (META2_THREADS_APP_*). \
                                        Mode testeur tant que la revue n'est pas passée.",
                    },
                },
                "required": ["platform"],
            }),
            query: &[],
            raw_body: None,
            risk: Risk::Write,
        },
        ToolDef {
            name: "social_post_preview_get",
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
                          d'un `social_post_preview_get` refuse (`media_change`) si les octets ne \
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
        ToolDef {
            name: "social_calendar_list",
            title: "Le calendrier des posts de ce locataire",
            description: "Les créneaux, les posts en attente d'approbation et ce qui est déjà \
                          parti, pour un compte et une plage de dates optionnels. À appeler \
                          pour voir ce qui attend un humain avant d'en proposer un autre. Un \
                          404 `no_social_binding` veut dire que l'agrégateur n'est pas branché.",
            method: Method::Get,
            path: "/v1/social/calendar",
            schema: json!({
                "type": "object",
                "properties": {
                    "account_id": {"type": "string"},
                    "from": {"type": "string", "description": "RFC 3339, borne incluse."},
                    "to": {"type": "string", "description": "RFC 3339, borne incluse."},
                },
            }),
            query: &["account_id", "from", "to"],
            raw_body: None,
            risk: Risk::Read,
        },
        ToolDef {
            name: "social_calendar_create",
            title: "Un créneau en attente d'approbation",
            description: "Pose un post ou un fil à une heure RFC 3339. Par défaut le statut \
                          est `pending_approval` : rien ne part tant qu'un humain n'a pas \
                          approuvé. À utiliser pour programmer ; `social_approval_propose` \
                          est le même geste sans heure obligatoire. `publish_at` est obligatoire.",
            method: Method::Post,
            path: "/v1/social/calendar",
            schema: json!({
                "type": "object",
                "properties": contenu_programme(),
                "required": ["idempotency_key", "account_id", "publish_at"],
            }),
            query: &[],
            raw_body: None,
            risk: Risk::Write,
        },
        ToolDef {
            name: "social_calendar_set",
            title: "Un créneau déplacé",
            description: "Change l'heure d'un créneau encore `scheduled` ou `pending_approval`. \
                          L'identifiant vient de `social_calendar_list`. Un créneau déjà publié \
                          ne se déplace pas : la réponse le dit.",
            method: Method::Post,
            path: "/v1/social/calendar/move",
            schema: json!({
                "type": "object",
                "properties": {
                    "scheduled_id": {"type": "string"},
                    "publish_at": {"type": "string", "description": "Nouvelle heure, RFC 3339."},
                },
                "required": ["scheduled_id", "publish_at"],
            }),
            query: &[],
            raw_body: None,
            risk: Risk::Write,
        },
        ToolDef {
            name: "social_calendar_remove",
            title: "Un créneau retiré",
            description: "Annule un créneau qui n'est pas encore publié. L'identifiant vient \
                          de `social_calendar_list`. Un créneau en cours de publication ou déjà \
                          en ligne ne s'annule pas par ici.",
            method: Method::Post,
            path: "/v1/social/calendar/cancel",
            schema: json!({
                "type": "object",
                "properties": {
                    "scheduled_id": {"type": "string"},
                },
                "required": ["scheduled_id"],
            }),
            query: &[],
            raw_body: None,
            risk: Risk::Destructive,
        },
        ToolDef {
            name: "social_thread_preview_get",
            title: "Le fil tel qu'il partirait",
            description: "L'aperçu de chaque élément, dans l'ordre, et une empreinte qui couvre \
                          tout le fil. À appeler avant `social_thread_publish` ou \
                          `social_approval_propose` quand le contenu est une suite de posts X. \
                          Les autres réseaux n'ont pas de fil : un post suffit.",
            method: Method::Post,
            path: "/v1/social/threads/preview",
            schema: json!({
                "type": "object",
                "properties": {
                    "account_id": {"type": "string"},
                    "posts": {
                        "type": "array",
                        "minItems": 2,
                        "maxItems": 25,
                        "items": {"type": "object"},
                    },
                },
                "required": ["account_id", "posts"],
            }),
            query: &[],
            raw_body: None,
            risk: Risk::Read,
        },
        ToolDef {
            name: "social_thread_publish",
            title: "Un fil publié",
            description: "Publie un fil X comme une seule opération. `idempotency_key` couvre \
                          toute la chaîne : un rejeu ne renvoie pas les éléments déjà en ligne, \
                          et un échec au milieu est rapporté élément par élément. Les employés \
                          passent par `social_approval_propose` ; cet outil publie tout de suite.",
            method: Method::Post,
            path: "/v1/social/threads",
            schema: json!({
                "type": "object",
                "properties": {
                    "idempotency_key": {"type": "string"},
                    "account_id": {"type": "string"},
                    "posts": {
                        "type": "array",
                        "minItems": 2,
                        "maxItems": 25,
                        "items": {"type": "object"},
                    },
                    "publish_at": {"type": "string"},
                    "expected_media_digests": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": ["idempotency_key", "account_id", "posts"],
            }),
            query: &[],
            raw_body: None,
            risk: Risk::Destructive,
        },
        ToolDef {
            name: "social_approval_propose",
            title: "Un post en attente d'approbation",
            description: "Crée un post ou un fil au statut `pending_approval`. Rien n'est \
                          publié : un humain approuve par la route d'opérateur, qui n'est pas \
                          un outil de cette table. C'est le chemin par défaut d'un employé. \
                          `social_post_publish` et `social_thread_publish`, eux, publient tout de suite.",
            method: Method::Post,
            path: "/v1/social/approvals",
            schema: json!({
                "type": "object",
                "properties": contenu_programme(),
                "required": ["idempotency_key", "account_id"],
            }),
            query: &[],
            raw_body: None,
            risk: Risk::Write,
        },
    ]
}

/// Le corps d'un créneau ou d'une soumission : un post (`text`) ou un fil (`posts`).
fn contenu_programme() -> Value {
    let mut properties = contenu();
    let object = properties.as_object_mut().expect("un objet");
    object.insert("idempotency_key".to_owned(), json!({"type": "string"}));
    object.insert(
        "posts".to_owned(),
        json!({
            "type": "array",
            "description": "Un fil X : 2 à 25 éléments `{text, media?}`. Absent : un post, et `text` est obligatoire.",
            "minItems": 2,
            "maxItems": 25,
            "items": {"type": "object"},
        }),
    );
    properties
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
            let destructif = matches!(
                outil.name,
                "social_post_publish" | "social_thread_publish" | "social_calendar_remove"
            );
            assert_eq!(
                outil.risk.destructive(),
                destructif,
                "{} : publier ou annuler un créneau engage, le reste non",
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

    /// Approuver n'est pas un outil que le modèle voit. La route existe pour
    /// un humain ; elle est exclue de la couverture des outils pour cette raison.
    #[test]
    fn approuver_n_est_pas_un_outil_employe() {
        for outil in tools() {
            assert!(
                !outil.path.contains("decide"),
                "{} expose la décision humaine",
                outil.name
            );
            assert!(!outil.name.ends_with("_approve"), "{}", outil.name);
            assert!(!outil.name.ends_with("_reject"), "{}", outil.name);
        }
    }
}

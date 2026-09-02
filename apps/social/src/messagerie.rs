//! La SECONDE surface : POST /mcp/messagerie — DM, reponses, commentaires,
//! likes, favoris, reposts, recherche et lecture.
//!
//! Elle a SA table, SA version, SES empreintes — jamais une extension de
//! l'editeur (/mcp). Les noms d'ici contiennent VOLONTAIREMENT les motifs
//! interdits de l'editeur (`dm`, `inbox`, `reply`…) : c'est la preuve que les
//! deux tables sont disjointes — si quelqu'un fusionne les tables un jour, le
//! test anti-DM de l'editeur explose immediatement. C'est voulu.
//!
//! La messagerie peut atteindre des gens : c'est son metier. Elle n'est donc
//! pas NoStrangers et ne le pretendra jamais — elle est HeldHere : chaque
//! premier contact (`dm_open`) passe la table des suppressions AVANT tout
//! appel reseau, et chaque 403 de plateforme y entre pour toujours.
//!
//! Contenu de tiers : tout texte qui revient de `inbox_list`, `search_posts`,
//! `read_post`, `read_timeline`, `read_profile` est du contenu de tiers — les
//! adaptateurs le rangent sous `third_party: true` par element, et le runtime
//! l'enveloppe en Untrusted (meme discipline que les lectures GitHub du
//! catalogue). Le service ne « nettoie » rien : il marque.

use agentos_domain::ids::TenantId;
use agentos_providers::Secret;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::adapters::{ErreurMessagerie, ErreurPlateforme, linkedin};
use crate::mcp::{Erreur, Etat, arg_str, arg_uuid, avec_rejeu_401, erreur_rpc, reponse};
use crate::oauth_flux;
use crate::store;

// ---------------------------------------------------------------------------
// La table d'outils messagerie, versionnee
// ---------------------------------------------------------------------------

/// Meme regle que `mcp::VERSION_TABLE` : tout changement de la table bumpe
/// cette constante ET ajoute une ligne a `EMPREINTES_MESSAGERIE`.
pub const VERSION_TABLE_MESSAGERIE: &str = "1";

/// Les quatorze outils, et pas un de plus. Chaque endpoint, scope et prix est
/// recopie du plan fige sur sondes datees du 2026-09-02 (docs.x.com pricing,
/// « subject to change ») — rien d'invente. Ce qui n'y est PAS est nomme dans
/// le plan (post_quote : Enterprise seulement chez X, donc personne ne peut
/// l'appeler a notre palier et un outil que personne ne peut appeler est un
/// stub ; dm_delete : doc X ambigue entre v1.1 et v2 ; DM de groupe : aucun
/// besoin jour un) — l'ajouter plus tard sera un bump de version, pas une
/// surprise.
pub fn description_outils_messagerie() -> Value {
    json!([
        {
            "name": "inbox_list",
            "description": "Les DM recus (GET /2/dm_events, 0,010 USD/evenement retourne, retention 30 jours, 15 req/15 min/user) et les mentions (GET /2/users/{id}/mentions, 0,005 USD/post lu) — releves 2026-09-02. Les textes rendus sont du contenu de tiers (third_party).",
            "inputSchema": {
                "type": "object",
                "properties": { "account_id": { "type": "string" } },
                "required": ["account_id"],
                "additionalProperties": false
            }
        },
        {
            "name": "dm_reply",
            "description": "Repond dans une conversation DM EXISTANTE (POST /2/dm_conversations/{conversation_id}/messages chez X, 0,015 USD, 15/15min + 1440/24h par user — releve 2026-09-02). Un fil inexistant est un refus, jamais une nouvelle conversation.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account_id":      { "type": "string" },
                    "conversation_id": { "type": "string" },
                    "text":            { "type": "string" }
                },
                "required": ["account_id", "conversation_id", "text"],
                "additionalProperties": false
            }
        },
        {
            "name": "dm_open",
            "description": "OUVRE une conversation DM nouvelle avec participant_id (POST /2/dm_conversations/with/{participant_id}/messages chez X, 0,015 USD — releve 2026-09-02). Consulte la table des suppressions AVANT tout appel : un destinataire qui a refuse un jour n'est plus jamais contacte.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account_id":     { "type": "string" },
                    "participant_id": { "type": "string" },
                    "text":           { "type": "string" }
                },
                "required": ["account_id", "participant_id", "text"],
                "additionalProperties": false
            }
        },
        {
            "name": "post_reply",
            "description": "Repond publiquement a un post (POST /2/tweets avec reply.in_reply_to_tweet_id chez X : 0,015 USD, 0,200 USD si le texte contient une URL — releve 2026-09-02).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account_id": { "type": "string" },
                    "post_id":    { "type": "string" },
                    "text":       { "type": "string" }
                },
                "required": ["account_id", "post_id", "text"],
                "additionalProperties": false
            }
        },
        {
            "name": "post_comment",
            "description": "Commente un post, ou repond a un commentaire via parent_comment_id. Chez X ce geste EST post_reply (meme endpoint). Chez LinkedIn : POST /rest/socialActions/{urn}/comments, scope w_member_social_feed via le Community Management API sur candidature (releve 2026-09-02).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account_id":        { "type": "string" },
                    "post_id":           { "type": "string" },
                    "text":              { "type": "string" },
                    "parent_comment_id": { "type": "string" }
                },
                "required": ["account_id", "post_id", "text"],
                "additionalProperties": false
            }
        },
        {
            "name": "post_like",
            "description": "Like un post (POST /2/users/{id}/likes chez X : 0,015 USD, 50/15min + 1000/24h — releve 2026-09-02).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account_id": { "type": "string" },
                    "post_id":    { "type": "string" }
                },
                "required": ["account_id", "post_id"],
                "additionalProperties": false
            }
        },
        {
            "name": "post_unlike",
            "description": "Retire un like (DELETE /2/users/{id}/likes/{tweet_id} chez X : 0,010 USD — releve 2026-09-02).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account_id": { "type": "string" },
                    "post_id":    { "type": "string" }
                },
                "required": ["account_id", "post_id"],
                "additionalProperties": false
            }
        },
        {
            "name": "post_bookmark",
            "description": "Met un post en favori (POST /2/users/{id}/bookmarks chez X : 0,005 USD — le write le moins cher —, 50/15min, OAuth2 PKCE uniquement — releve 2026-09-02).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account_id": { "type": "string" },
                    "post_id":    { "type": "string" }
                },
                "required": ["account_id", "post_id"],
                "additionalProperties": false
            }
        },
        {
            "name": "post_unbookmark",
            "description": "Retire un favori (DELETE /2/users/{id}/bookmarks/{tweet_id} chez X — releve 2026-09-02).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account_id": { "type": "string" },
                    "post_id":    { "type": "string" }
                },
                "required": ["account_id", "post_id"],
                "additionalProperties": false
            }
        },
        {
            "name": "post_repost",
            "description": "Repartage un post (POST /2/users/{id}/retweets chez X : 0,015 USD, 50/15min — releve 2026-09-02).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account_id": { "type": "string" },
                    "post_id":    { "type": "string" }
                },
                "required": ["account_id", "post_id"],
                "additionalProperties": false
            }
        },
        {
            "name": "search_posts",
            "description": "Recherche de posts recents (GET /2/tweets/search/recent chez X : fenetre 7 jours, query 1-4096 chars, max_results 10-100, facture PAR POST RETOURNE 0,005 USD — une recherche a 100 resultats coute jusqu'a 0,50 USD ; 300/15min/user — releve 2026-09-02). Le retour porte le cout reel constate ; les textes sont du contenu de tiers (third_party).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account_id":  { "type": "string" },
                    "query":       { "type": "string", "minLength": 1, "maxLength": 4096 },
                    "max_results": { "type": "integer", "minimum": 10, "maximum": 100 }
                },
                "required": ["account_id", "query"],
                "additionalProperties": false
            }
        },
        {
            "name": "read_post",
            "description": "Lit un post (GET /2/tweets/{id} chez X : 0,005 USD/post — releve 2026-09-02). Contenu de tiers (third_party).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account_id": { "type": "string" },
                    "post_id":    { "type": "string" }
                },
                "required": ["account_id", "post_id"],
                "additionalProperties": false
            }
        },
        {
            "name": "read_profile",
            "description": "Lit un profil (GET /2/users/by/username/{username} chez X : 0,010 USD/user — releve 2026-09-02). Contenu de tiers (third_party).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account_id": { "type": "string" },
                    "username":   { "type": "string" }
                },
                "required": ["account_id", "username"],
                "additionalProperties": false
            }
        },
        {
            "name": "read_timeline",
            "description": "Lit les posts d'un utilisateur (GET /2/users/{id}/tweets chez X : 0,005 USD/post, 900/15min/user ; plafond global pay-per-use 3 000 000 lectures de posts/cycle — releve 2026-09-02). Contenu de tiers (third_party).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account_id": { "type": "string" },
                    "user_id":    { "type": "string" }
                },
                "required": ["account_id", "user_id"],
                "additionalProperties": false
            }
        }
    ])
}

// ---------------------------------------------------------------------------
// JSON-RPC
// ---------------------------------------------------------------------------

/// Traite un message JSON-RPC deja authentifie sur /mcp/messagerie — meme
/// forme que `mcp::traiter`, contre SA table.
pub async fn traiter(etat: &Etat, tenant: Uuid, req: &Value) -> Option<Value> {
    let methode = req.get("method").and_then(Value::as_str).unwrap_or("");
    let id = req.get("id")?; // pas d'id : notification, rien a repondre

    Some(match methode {
        "initialize" => reponse(
            id,
            json!({
                "protocolVersion": req.pointer("/params/protocolVersion").and_then(Value::as_str).unwrap_or("2025-03-26"),
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "agentos-social-messagerie", "version": VERSION_TABLE_MESSAGERIE }
            }),
        ),
        "ping" => reponse(id, json!({})),
        "tools/list" => reponse(id, json!({ "tools": description_outils_messagerie() })),
        "tools/call" => {
            let nom = req
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let vide = json!({});
            let args = req.pointer("/params/arguments").unwrap_or(&vide);
            match appeler_outil(etat, tenant, nom, args).await {
                Ok(v) => reponse(
                    id,
                    json!({ "content": [{ "type": "text", "text": v.to_string() }], "isError": false }),
                ),
                Err(e) => reponse(
                    id,
                    json!({
                        "content": [{ "type": "text", "text": json!({ "erreur": e.code, "message": e.message }).to_string() }],
                        "isError": true
                    }),
                ),
            }
        }
        _ => erreur_rpc(id, -32601, &format!("methode inconnue: {methode}")),
    })
}

// ---------------------------------------------------------------------------
// Le dispatch
// ---------------------------------------------------------------------------

fn noms_outils() -> Vec<String> {
    description_outils_messagerie()
        .as_array()
        .expect("la table est un tableau")
        .iter()
        .map(|o| {
            o["name"]
                .as_str()
                .expect("chaque outil a un nom")
                .to_owned()
        })
        .collect()
}

/// Une erreur d'adaptateur messagerie vers l'erreur d'outil. `NeSertPas`
/// rend TOUJOURS la citation ET le fait qui debloquerait — le Display du type
/// ne porte que la citation, et un refus sans chemin de deblocage serait une
/// ignorance silencieuse a moitie.
fn erreur_outil(e: ErreurMessagerie) -> Erreur {
    match e {
        ErreurMessagerie::NeSertPas {
            citation,
            deblocage,
        } => Erreur::nouvelle(
            "plateforme_ne_sert_pas",
            format!("{citation} — debloque par : {deblocage}"),
        ),
        autre => Erreur::nouvelle(autre.code(), autre.to_string()),
    }
}

/// Ouvre le jeton scelle d'un compte — la meme paire d'erreurs nommees que le
/// chemin de publication de l'editeur.
fn jeton_du_compte(
    etat: &Etat,
    tenant: Uuid,
    compte: &store::CompteScelle,
) -> Result<Secret, Erreur> {
    let octets = compte.sealed_token.as_ref().ok_or_else(|| {
        Erreur::nouvelle(
            "compte_sans_jeton",
            "ce compte n'a pas de jeton scelle — reconnecter via account_connect_url",
        )
    })?;
    oauth_flux::ouvrir_jeton(
        &etat.chiffreur,
        TenantId::from_uuid(tenant),
        &compte.platform,
        &compte.handle,
        octets,
    )
    .map_err(|_| {
        Erreur::nouvelle(
            "descellement",
            "le jeton de ce compte ne s'ouvre pas — reconnecter",
        )
    })
}

/// L'identifiant plateforme du compte — celui que les chemins
/// `/2/users/{id}/…` (mentions, likes, bookmarks, retweets) exigent chez X.
/// Le handle porte le USERNAME, qui n'y passe pas (la garde `id_x` de
/// l'adaptateur le refuserait avant tout octet reseau). None = compte
/// connecte avant la migration 0005 : le meme re-consentement humain que pour
/// les scopes dm.* repare les deux.
fn id_plateforme(compte: &store::CompteScelle) -> Result<&str, Erreur> {
    compte.platform_user_id.as_deref().ok_or_else(|| {
        Erreur::nouvelle(
            "compte_sans_id_plateforme",
            "ce compte a ete connecte avant que l'id plateforme soit garde — reconnecter via account_connect_url",
        )
    })
}

async fn appeler_outil(
    etat: &Etat,
    tenant: Uuid,
    nom: &str,
    args: &Value,
) -> Result<Value, Erreur> {
    if !noms_outils().iter().any(|n| n == nom) {
        return Err(Erreur::nouvelle(
            "outil_inconnu",
            format!("pas d'outil `{nom}` sur cette surface"),
        ));
    }
    // Tout outil de la table porte account_id : la plateforme et le jeton en
    // decoulent.
    let compte_id = arg_uuid(args, "account_id")?;
    let compte = store::compte_scelle(&etat.pool, tenant, compte_id)
        .await?
        .ok_or_else(|| {
            Erreur::nouvelle("compte_inconnu", "ce compte n'appartient pas a ce tenant")
        })?;

    // dm_open : la table des suppressions AVANT tout le reste — un handle
    // supprime rend un refus nomme, jamais un appel reseau (pas meme un
    // descellement de jeton, ni la resolution d'adaptateur).
    if nom == "dm_open" {
        let p = arg_str(args, "participant_id")?;
        if store::est_supprime(&etat.pool, tenant, &compte.platform, p).await? {
            return Err(Erreur::nouvelle(
                "destinataire_supprime",
                format!(
                    "`{p}` a refuse un jour (table des suppressions) : ce tenant ne le recontacte jamais — une levee passe par l'operateur, pas par un outil"
                ),
            ));
        }
    }

    let Some(adaptateur) = etat
        .adaptateurs_messagerie
        .iter()
        .find(|a| a.nom() == compte.platform)
    else {
        // L'absence d'implementation EST le refus — et il est cite. Pour
        // linkedin les citations datees vivent dans l'adaptateur (lot B) ;
        // toute autre plateforme sans adaptateur est une incoherence de
        // cablage, pas un refus de plateforme.
        if compte.platform == "linkedin"
            && let Some(refus) = linkedin::refus_messagerie(nom)
        {
            return Err(erreur_outil(refus));
        }
        return Err(Erreur::nouvelle(
            "plateforme_inconnue",
            format!("pas d'adaptateur messagerie `{}`", compte.platform),
        ));
    };
    let adaptateur = adaptateur.as_ref();

    // En Arc parce que la fonction de rejeu partagee prend une propriete
    // partagee (Secret n'est pas Clone, a dessein). Un seul bras s'execute :
    // chacun peut le deplacer.
    let jeton = std::sync::Arc::new(jeton_du_compte(etat, tenant, &compte)?);
    // Une reference nue (Copy) : les fermetures `async move` la copient au
    // lieu de deplacer la String hors de `compte`, encore emprunte a cote.
    let handle: &str = &compte.handle;
    // Chaque bras rend Result<Value, ErreurMessagerie> ; le chemin
    // 401 -> refresh -> UN rejeu est le meme que celui de post_publish,
    // par la fonction partagee.
    let resultat: Result<Value, ErreurMessagerie> = match nom {
        "inbox_list" => {
            let id = id_plateforme(&compte)?;
            avec_rejeu_401(etat, tenant, &compte, jeton, |j| async move {
                serialise(adaptateur.inbox(&j, id).await)
            })
            .await
        }
        "dm_reply" => {
            let conversation = arg_str(args, "conversation_id")?;
            let texte = arg_str(args, "text")?;
            avec_rejeu_401(etat, tenant, &compte, jeton, |j| async move {
                serialise(adaptateur.dm_reply(&j, conversation, texte).await)
            })
            .await
        }
        "dm_open" => {
            let participant = arg_str(args, "participant_id")?;
            let texte = arg_str(args, "text")?;
            let r = avec_rejeu_401(etat, tenant, &compte, jeton, |j| async move {
                serialise(adaptateur.dm_open(&j, participant, texte).await)
            })
            .await;
            // Le 403 apprend : « The recipient may have DM settings that
            // prevent messages from unknown users, or may have blocked you »
            // (docs.x.com/x-api/direct-messages/manage/integrate, releve
            // 2026-09-02) — le refus n'est detectable qu'a l'envoi, donc
            // c'est ICI que la liste des refus se remplit, pour toujours.
            if let Err(ErreurMessagerie::Plateforme(ErreurPlateforme::Refus { statut: 403 })) = r {
                store::supprimer(
                    &etat.pool,
                    tenant,
                    &compte.platform,
                    participant,
                    "403_plateforme",
                )
                .await?;
            }
            r
        }
        "post_reply" => {
            let post = arg_str(args, "post_id")?;
            let texte = arg_str(args, "text")?;
            avec_rejeu_401(etat, tenant, &compte, jeton, |j| async move {
                serialise(adaptateur.post_reply(&j, handle, post, texte).await)
            })
            .await
        }
        "post_comment" => {
            let post = arg_str(args, "post_id")?;
            let texte = arg_str(args, "text")?;
            let parent = args.get("parent_comment_id").and_then(Value::as_str);
            avec_rejeu_401(etat, tenant, &compte, jeton, |j| async move {
                serialise(
                    adaptateur
                        .post_comment(&j, handle, post, parent, texte)
                        .await,
                )
            })
            .await
        }
        "post_like" | "post_unlike" | "post_bookmark" | "post_unbookmark" | "post_repost" => {
            let post = arg_str(args, "post_id")?;
            let id = id_plateforme(&compte)?;
            avec_rejeu_401(etat, tenant, &compte, jeton, |j| async move {
                serialise(match nom {
                    "post_like" => adaptateur.post_like(&j, id, post).await,
                    "post_unlike" => adaptateur.post_unlike(&j, id, post).await,
                    "post_bookmark" => adaptateur.post_bookmark(&j, id, post).await,
                    "post_unbookmark" => adaptateur.post_unbookmark(&j, id, post).await,
                    _ => adaptateur.post_repost(&j, id, post).await,
                })
            })
            .await
        }
        "search_posts" => {
            let query = arg_str(args, "query")?;
            // ponytail: defaut 10, le minimum de l'endpoint — chez X chaque
            // resultat coute 0,005 USD, le defaut le moins cher est le bon.
            let max = args
                .get("max_results")
                .and_then(Value::as_u64)
                .unwrap_or(10)
                .clamp(10, 100) as u8;
            avec_rejeu_401(etat, tenant, &compte, jeton, |j| async move {
                serialise(adaptateur.search_posts(&j, query, max).await)
            })
            .await
        }
        "read_post" => {
            let post = arg_str(args, "post_id")?;
            avec_rejeu_401(etat, tenant, &compte, jeton, |j| async move {
                serialise(adaptateur.read_post(&j, post).await)
            })
            .await
        }
        "read_profile" => {
            let username = arg_str(args, "username")?;
            avec_rejeu_401(etat, tenant, &compte, jeton, |j| async move {
                serialise(adaptateur.read_profile(&j, username).await)
            })
            .await
        }
        // read_timeline — le seul dont la cible est un ARGUMENT : on lit la
        // timeline de quelqu'un, pas la sienne.
        _ => {
            let user = arg_str(args, "user_id")?;
            avec_rejeu_401(etat, tenant, &compte, jeton, |j| async move {
                serialise(adaptateur.read_timeline(&j, user).await)
            })
            .await
        }
    };
    resultat.map_err(erreur_outil)
}

/// Un retour type d'adaptateur vers le JSON de l'outil.
fn serialise<T: serde::Serialize>(
    r: Result<T, ErreurMessagerie>,
) -> Result<Value, ErreurMessagerie> {
    r.map(|v| serde_json::to_value(v).expect("les retours d'adaptateur se serialisent"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::adapters::{
        ActionFaite, ElementLu, Inbox, MessagePrive, PlateformeMessagerie, PostsLus, ProfilLu,
        ReponsePubliee, empreinte,
    };
    use crate::mcp;
    use crate::medias;
    use agentos_providers::secrets::LocalEnvelopeSecretStore;

    // -- L'invariant numero zero : la table de l'editeur, intacte. ----------

    /// Ce lot ne touche pas la table de l'editeur : son empreinte v2 (celle
    /// posee par le chantier medias) reste la DERNIERE. Si ce test rougit,
    /// quelqu'un a change /mcp depuis /mcp/messagerie — interdit.
    #[test]
    fn la_table_de_l_editeur_reste_celle_du_chantier_medias() {
        assert_eq!(mcp::VERSION_TABLE, "2");
        assert_eq!(
            empreinte(&mcp::description_outils().to_string()),
            "5e0d09aa3063c5a058935a2afe2d9230a9965b015e32c5071ca7140216d78870"
        );
    }

    // -- La table messagerie, versionnee, meme discipline. ------------------

    /// L'histoire complete des versions de la table messagerie. Reecrire une
    /// ligne existante est une falsification, pas une correction.
    const EMPREINTES_MESSAGERIE: &[(&str, &str)] = &[(
        "1",
        "b7b3f5b34be704bae7e8fb0b9de31a65a42851803ac4d1d905b883e48c26fcf4",
    )];

    #[test]
    fn la_table_messagerie_ne_change_pas_sans_bumper_la_version() {
        let calculee = empreinte(&description_outils_messagerie().to_string());
        let (version, attendue) = EMPREINTES_MESSAGERIE.last().expect("au moins une version");
        assert_eq!(
            *version, VERSION_TABLE_MESSAGERIE,
            "VERSION_TABLE_MESSAGERIE et EMPREINTES_MESSAGERIE ont diverge"
        );
        assert_eq!(
            &calculee, attendue,
            "la table messagerie a change : bumper VERSION_TABLE_MESSAGERIE et ajouter une ligne"
        );
        let mut versions: Vec<_> = EMPREINTES_MESSAGERIE.iter().map(|(v, _)| *v).collect();
        versions.dedup();
        assert_eq!(versions.len(), EMPREINTES_MESSAGERIE.len());
    }

    #[test]
    fn la_table_expose_exactement_les_quatorze_outils_convenus() {
        assert_eq!(
            noms_outils(),
            [
                "inbox_list",
                "dm_reply",
                "dm_open",
                "post_reply",
                "post_comment",
                "post_like",
                "post_unlike",
                "post_bookmark",
                "post_unbookmark",
                "post_repost",
                "search_posts",
                "read_post",
                "read_profile",
                "read_timeline"
            ]
        );
    }

    // -- Les faux adaptateurs : compteurs par chemin. -----------------------

    /// DEUX compteurs (`reponses`, `ouvertures`) : le decoupage reply/open se
    /// prouve en comptant quel chemin a ete appele. Les methodes que ces
    /// tests n'exercent pas paniquent — si un refactor les atteint, le test
    /// le dit au lieu de reussir en silence.
    struct FauxMessagerie {
        reponses: Arc<AtomicUsize>,
        ouvertures: Arc<AtomicUsize>,
        /// `true` : dm_open rend Refus{403}, comme un destinataire qui bloque.
        ouverture_refusee_403: bool,
    }

    fn plateforme(statut: u16) -> ErreurMessagerie {
        ErreurMessagerie::Plateforme(ErreurPlateforme::Refus { statut })
    }

    #[async_trait]
    impl PlateformeMessagerie for FauxMessagerie {
        fn nom(&self) -> &'static str {
            "x"
        }
        async fn dm_reply(
            &self,
            _jeton: &Secret,
            dm_conversation_id: &str,
            _texte: &str,
        ) -> Result<MessagePrive, ErreurMessagerie> {
            self.reponses.fetch_add(1, Ordering::SeqCst);
            // Un fil inconnu est un 404 de plateforme — JAMAIS un fallback
            // vers l'ouverture d'une conversation.
            if dm_conversation_id == "fil-inexistant" {
                return Err(plateforme(404));
            }
            Ok(MessagePrive {
                dm_conversation_id: dm_conversation_id.to_owned(),
                dm_event_id: "ev-1".into(),
                cout_usd: 0.015,
            })
        }
        async fn dm_open(
            &self,
            _jeton: &Secret,
            participant_id: &str,
            _texte: &str,
        ) -> Result<MessagePrive, ErreurMessagerie> {
            self.ouvertures.fetch_add(1, Ordering::SeqCst);
            if self.ouverture_refusee_403 {
                return Err(plateforme(403));
            }
            Ok(MessagePrive {
                dm_conversation_id: format!("conv-{participant_id}"),
                dm_event_id: "ev-2".into(),
                cout_usd: 0.015,
            })
        }
        async fn inbox(&self, _j: &Secret, _u: &str) -> Result<Inbox, ErreurMessagerie> {
            unreachable!("pas exerce par ces tests")
        }
        async fn post_reply(
            &self,
            _j: &Secret,
            _h: &str,
            _p: &str,
            _t: &str,
        ) -> Result<ReponsePubliee, ErreurMessagerie> {
            unreachable!("pas exerce par ces tests")
        }
        async fn post_comment(
            &self,
            _j: &Secret,
            _h: &str,
            _p: &str,
            _parent: Option<&str>,
            _t: &str,
        ) -> Result<ReponsePubliee, ErreurMessagerie> {
            unreachable!("pas exerce par ces tests")
        }
        async fn post_like(
            &self,
            _j: &Secret,
            user_id: &str,
            _p: &str,
        ) -> Result<ActionFaite, ErreurMessagerie> {
            // Le dispatcher doit passer l'ID PLATEFORME (numerique), jamais le
            // username : /2/users/{id}/likes le refuserait — et la garde id_x
            // de l'adaptateur reel aussi, avant tout octet reseau.
            assert_eq!(
                user_id, ID_X_DE_TEST,
                "post_like a recu autre chose que l'id plateforme"
            );
            Ok(ActionFaite { cout_usd: 0.015 })
        }
        async fn post_unlike(
            &self,
            _j: &Secret,
            _u: &str,
            _p: &str,
        ) -> Result<ActionFaite, ErreurMessagerie> {
            unreachable!("pas exerce par ces tests")
        }
        async fn post_bookmark(
            &self,
            _j: &Secret,
            _u: &str,
            _p: &str,
        ) -> Result<ActionFaite, ErreurMessagerie> {
            unreachable!("pas exerce par ces tests")
        }
        async fn post_unbookmark(
            &self,
            _j: &Secret,
            _u: &str,
            _p: &str,
        ) -> Result<ActionFaite, ErreurMessagerie> {
            unreachable!("pas exerce par ces tests")
        }
        async fn post_repost(
            &self,
            _j: &Secret,
            _u: &str,
            _p: &str,
        ) -> Result<ActionFaite, ErreurMessagerie> {
            unreachable!("pas exerce par ces tests")
        }
        async fn post_quote(
            &self,
            _j: &Secret,
            _h: &str,
            _p: &str,
            _t: &str,
        ) -> Result<ReponsePubliee, ErreurMessagerie> {
            unreachable!("post_quote n'est pas dans la table — personne ne peut l'appeler")
        }
        async fn search_posts(
            &self,
            _j: &Secret,
            _q: &str,
            _m: u8,
        ) -> Result<PostsLus, ErreurMessagerie> {
            unreachable!("pas exerce par ces tests")
        }
        async fn read_post(&self, _j: &Secret, _p: &str) -> Result<ElementLu, ErreurMessagerie> {
            unreachable!("pas exerce par ces tests")
        }
        async fn read_profile(&self, _j: &Secret, _u: &str) -> Result<ProfilLu, ErreurMessagerie> {
            unreachable!("pas exerce par ces tests")
        }
        async fn read_timeline(&self, _j: &Secret, _u: &str) -> Result<PostsLus, ErreurMessagerie> {
            unreachable!("pas exerce par ces tests")
        }
    }

    /// L'id NUMERIQUE du compte X de test — jamais egal au handle.
    const ID_X_DE_TEST: &str = "1000000001";

    struct Compteurs {
        reponses: Arc<AtomicUsize>,
        ouvertures: Arc<AtomicUsize>,
    }

    /// Un Etat de test : pool reel, un compte X scelle, un compte LinkedIn
    /// scelle, l'adaptateur messagerie compteur — et AUCUN adaptateur
    /// editeur : cette surface n'en a pas besoin, preuve par le type que les
    /// deux listes sont disjointes.
    async fn etat_de_test(
        ouverture_refusee_403: bool,
    ) -> Option<(Etat, Uuid, Uuid, Uuid, Compteurs)> {
        let pool = crate::store::pool_de_test("messagerie").await?;
        let chiffreur = Arc::new(LocalEnvelopeSecretStore::new(
            Sha256::digest("clef-de-test").into(),
        ));
        let tenant = Uuid::now_v7();
        sqlx::query("INSERT INTO social_tenants (id, label, token_hash) VALUES ($1, $2, $3)")
            .bind(tenant)
            .bind(format!("test-messagerie-{tenant}"))
            .bind(vec![0u8; 32])
            .execute(&pool)
            .await
            .unwrap();
        let mut comptes = Vec::new();
        // Le handle X est un USERNAME, l'id plateforme est NUMERIQUE : deux
        // valeurs distinctes exprès — un test qui confond les deux rougit.
        for (plateforme, handle, id) in [
            ("x", "agent_test", Some(ID_X_DE_TEST)),
            ("linkedin", "urn:li:person:t", Some("urn:li:person:t")),
        ] {
            let scelle = oauth_flux::sceller_jeton(
                &chiffreur,
                TenantId::from_uuid(tenant),
                plateforme,
                handle,
                &Secret::new("jeton-plateforme"),
            )
            .unwrap();
            comptes.push(
                crate::store::connecter_compte(
                    &pool, tenant, plateforme, handle, id, &scelle, None,
                )
                .await
                .unwrap(),
            );
        }
        let compteurs = Compteurs {
            reponses: Arc::new(AtomicUsize::new(0)),
            ouvertures: Arc::new(AtomicUsize::new(0)),
        };
        let etat = Etat {
            pool,
            chiffreur,
            adaptateurs: Vec::new(),
            telechargeur: medias::Telechargeur::de_test(medias::PLAFOND_ABSOLU_OCTETS),
            url_publique: "http://127.0.0.1:0".into(),
            oauth_x: None,
            oauth_linkedin: None,
            adaptateurs_messagerie: vec![Box::new(FauxMessagerie {
                reponses: compteurs.reponses.clone(),
                ouvertures: compteurs.ouvertures.clone(),
                ouverture_refusee_403,
            })],
        };
        Some((etat, tenant, comptes[0], comptes[1], compteurs))
    }

    async fn appel(etat: &Etat, tenant: Uuid, outil: &str, args: Value) -> (bool, Value) {
        let req = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": outil, "arguments": args }
        });
        let rep = traiter(etat, tenant, &req).await.expect("une reponse");
        let result = &rep["result"];
        let texte = result["content"][0]["text"]
            .as_str()
            .expect("contenu texte");
        (
            result["isError"].as_bool().unwrap(),
            serde_json::from_str(texte).unwrap(),
        )
    }

    // -- La gate des suppressions : AVANT le reseau. ------------------------

    #[tokio::test]
    async fn dm_open_refuse_un_supprime_sans_appeler_l_adaptateur() {
        let Some((etat, tenant, compte_x, _, compteurs)) = etat_de_test(false).await else {
            return;
        };
        crate::store::supprimer(&etat.pool, tenant, "x", "u-refus", "demande_humaine")
            .await
            .unwrap();

        let (err, rep) = appel(
            &etat,
            tenant,
            "dm_open",
            json!({ "account_id": compte_x.to_string(), "participant_id": "u-refus", "text": "bonjour" }),
        )
        .await;
        assert!(err, "{rep}");
        assert_eq!(rep["erreur"], "destinataire_supprime");
        // Le compteur a ZERO : la gate est avant le reseau, pas apres.
        assert_eq!(compteurs.ouvertures.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn un_403_sur_dm_open_apprend_pour_toujours() {
        let Some((etat, tenant, compte_x, _, compteurs)) = etat_de_test(true).await else {
            return;
        };
        let args = json!({ "account_id": compte_x.to_string(), "participant_id": "u-bloque", "text": "bonjour" });

        // Premier appel : la plateforme dit non, UN appel est parti.
        let (err, rep) = appel(&etat, tenant, "dm_open", args.clone()).await;
        assert!(err, "{rep}");
        assert_eq!(rep["erreur"], "plateforme_refus");
        assert_eq!(compteurs.ouvertures.load(Ordering::SeqCst), 1);

        // Second appel, meme cible : le refus est devenu permanent chez nous,
        // et le compteur n'a PAS bouge.
        let (err, rep) = appel(&etat, tenant, "dm_open", args).await;
        assert!(err, "{rep}");
        assert_eq!(rep["erreur"], "destinataire_supprime");
        assert_eq!(compteurs.ouvertures.load(Ordering::SeqCst), 1);
    }

    // -- Le decoupage reply/open, prouve par compteurs. ---------------------

    #[tokio::test]
    async fn un_fil_inexistant_ne_devient_jamais_une_conversation_nouvelle() {
        let Some((etat, tenant, compte_x, _, compteurs)) = etat_de_test(false).await else {
            return;
        };
        let (err, rep) = appel(
            &etat,
            tenant,
            "dm_reply",
            json!({ "account_id": compte_x.to_string(), "conversation_id": "fil-inexistant", "text": "re" }),
        )
        .await;
        assert!(err, "{rep}");
        assert_eq!(rep["erreur"], "plateforme_refus");
        assert_eq!(compteurs.reponses.load(Ordering::SeqCst), 1);
        // JAMAIS un fallback : le chemin d'ouverture n'a pas ete touche.
        assert_eq!(compteurs.ouvertures.load(Ordering::SeqCst), 0);

        // Et dm_open incremente `ouvertures`, jamais `reponses`.
        let (err, rep) = appel(
            &etat,
            tenant,
            "dm_open",
            json!({ "account_id": compte_x.to_string(), "participant_id": "u-nouveau", "text": "bonjour" }),
        )
        .await;
        assert!(!err, "{rep}");
        assert_eq!(compteurs.ouvertures.load(Ordering::SeqCst), 1);
        assert_eq!(compteurs.reponses.load(Ordering::SeqCst), 1);
    }

    // -- La couture username -> id : /2/users/{id}/… recoit l'id. -----------

    #[tokio::test]
    async fn les_chemins_a_id_recoivent_l_id_plateforme_jamais_le_username() {
        let Some((etat, tenant, compte_x, _, _)) = etat_de_test(false).await else {
            return;
        };
        // Le faux adaptateur assert lui-meme que post_like recoit
        // ID_X_DE_TEST — un dispatcher qui repasserait le handle paniquerait.
        let (err, rep) = appel(
            &etat,
            tenant,
            "post_like",
            json!({ "account_id": compte_x.to_string(), "post_id": "42" }),
        )
        .await;
        assert!(!err, "{rep}");

        // Un compte d'avant la migration 0005 (id plateforme absent) : refus
        // nomme qui renvoie vers le re-consentement, jamais un appel avec le
        // username dans le chemin.
        let scelle = oauth_flux::sceller_jeton(
            &etat.chiffreur,
            TenantId::from_uuid(tenant),
            "x",
            "agent_sans_id",
            &Secret::new("jeton-plateforme"),
        )
        .unwrap();
        let ancien = crate::store::connecter_compte(
            &etat.pool,
            tenant,
            "x",
            "agent_sans_id",
            None,
            &scelle,
            None,
        )
        .await
        .unwrap();
        let (err, rep) = appel(
            &etat,
            tenant,
            "post_like",
            json!({ "account_id": ancien.to_string(), "post_id": "42" }),
        )
        .await;
        assert!(err, "{rep}");
        assert_eq!(rep["erreur"], "compte_sans_id_plateforme");
    }

    // -- Les refus LinkedIn rendus par l'outil. -----------------------------

    #[tokio::test]
    async fn un_compte_linkedin_recoit_le_fait_cite_jamais_un_stub() {
        let Some((etat, tenant, _, compte_li, compteurs)) = etat_de_test(false).await else {
            return;
        };
        // Un jeu d'arguments superset : chaque outil y trouve les siens — le
        // dispatcher ne lit que ce dont l'outil a besoin.
        let args = json!({
            "account_id": compte_li.to_string(),
            "participant_id": "p", "conversation_id": "c", "text": "t",
            "post_id": "1", "query": "q", "username": "u", "user_id": "2"
        });

        let (err, rep) = appel(&etat, tenant, "dm_reply", args.clone()).await;
        assert!(err, "{rep}");
        assert_eq!(rep["erreur"], "plateforme_ne_sert_pas");
        assert!(
            rep["message"]
                .as_str()
                .unwrap()
                .contains("restricted to approved partners"),
            "{rep}"
        );

        // Tous les outils de la table refusent en citant un fait date, et en
        // nommant ce qui debloquerait.
        for nom in noms_outils() {
            let (err, rep) = appel(&etat, tenant, &nom, args.clone()).await;
            assert!(err, "{nom}: {rep}");
            assert_eq!(rep["erreur"], "plateforme_ne_sert_pas", "{nom}: {rep}");
            let message = rep["message"].as_str().unwrap();
            assert!(message.contains("2026-09-02"), "{nom}: refus sans date");
            assert!(
                message.contains("debloque par"),
                "{nom}: refus sans chemin de deblocage"
            );
        }
        // Et RIEN n'est parti vers un adaptateur.
        assert_eq!(compteurs.reponses.load(Ordering::SeqCst), 0);
        assert_eq!(compteurs.ouvertures.load(Ordering::SeqCst), 0);
    }
}

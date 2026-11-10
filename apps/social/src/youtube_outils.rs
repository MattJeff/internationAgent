//! Outils MCP YouTube (table v5). Un compte = un tenant + un handle, comme
//! le reste : `account_id` choisit la ligne, le jeton scellé de cette ligne
//! part en Bearer.
//!
//! Les actions destructives ou publiques (suppression, changement de
//! visibilité, modération) ne parlent pas à YouTube. Elles posent une ligne
//! `pending_approval` de kind `youtube` ; `approval_decide` les joue, le
//! même circuit que `post_publish` après approbation.

use std::sync::Arc;

use agentos_providers::Secret;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::adapters::empreinte;
use crate::adapters::youtube::{
    POINT_CHANNELS, POINT_COMMENT_THREADS, POINT_COMMENTS, POINT_PLAYLIST_ITEMS, POINT_VIDEOS,
};
use crate::adapters::youtube_gestion::{
    self, COUT_CAPTIONS_DELETE, COUT_CAPTIONS_LIST, COUT_ECRITURE, COUT_LECTURE, EchecYoutube,
    MESSAGE_RECONNEXION, POINT_ANALYTICS, POINT_CAPTIONS, POINT_CAPTIONS_UPLOAD,
    POINT_COMMENT_MODERATION, POINT_PLAYLISTS, PatchChaine, PatchVideo, Visibilite,
};
use crate::file;
use crate::mcp::{self, Erreur, Etat, Porte401};
use crate::store::{self, PoseFile};

impl Porte401 for EchecYoutube {
    fn est_401(&self) -> bool {
        matches!(
            self,
            EchecYoutube::Plateforme(crate::adapters::ErreurPlateforme::Refus { statut: 401 })
        )
    }
}

const GATES: &[&str] = &[
    "youtube_video_visibility",
    "youtube_video_delete",
    "youtube_playlist_visibility",
    "youtube_playlist_delete",
    "youtube_playlist_item_remove",
    "youtube_comment_moderate",
    "youtube_comment_delete",
    "youtube_caption_delete",
];

pub fn descriptions() -> Vec<Value> {
    vec![
        schema(
            "youtube_channel_get",
            "La chaîne du compte : description, mots-clés, pays, langue, bande-annonce. Les liens À propos, les posts Communauté et la bannière ne sont pas supportés.",
            json!({ "account_id": { "type": "string" } }),
            &["account_id"],
        ),
        schema(
            "youtube_channel_update",
            "Met à jour brandingSettings (description, keywords, country, default_language, unsubscribed_trailer). Relit la chaîne et fusionne : channels.update remplace toute la partie. Ne touche pas à la bannière.",
            props_chaine(),
            &["idempotency_key", "account_id"],
        ),
        schema(
            "youtube_video_update",
            "Met à jour titre, description, tags, category_id, made_for_kids (selfDeclaredMadeForKids). Fusionne avec la vidéo courante. La visibilité passe par youtube_video_visibility.",
            props_video(),
            &["idempotency_key", "account_id", "video_id"],
        ),
        schema(
            "youtube_video_visibility",
            "Change privacy (private, public, unlisted) ou programme publish_at. publish_at force private. Rien n'est envoyé à YouTube tant qu'un humain n'a pas appelé approval_decide.",
            props_visibilite(),
            &["idempotency_key", "account_id", "video_id"],
        ),
        schema(
            "youtube_video_delete",
            "Supprime une vidéo. Pose une approbation : approval_decide la joue. Rien n'est supprimé avant.",
            props_id("video_id"),
            &["idempotency_key", "account_id", "video_id"],
        ),
        schema(
            "youtube_playlists_list",
            "Les playlists de la chaîne (mine=true).",
            props_liste(json!({})),
            &["account_id"],
        ),
        schema(
            "youtube_playlist_create",
            "Crée une playlist. privacy absent = private.",
            props_playlist_create(),
            &["idempotency_key", "account_id", "title"],
        ),
        schema(
            "youtube_playlist_update",
            "Met à jour le titre ou la description d'une playlist, en fusionnant. La visibilité passe par youtube_playlist_visibility.",
            props_playlist_update(),
            &["idempotency_key", "account_id", "playlist_id"],
        ),
        schema(
            "youtube_playlist_visibility",
            "Change la visibilité d'une playlist. Approbation obligatoire (approval_decide) avant l'appel YouTube.",
            json!({
                "idempotency_key": cle(),
                "account_id": { "type": "string" },
                "playlist_id": { "type": "string" },
                "privacy": { "type": "string", "enum": ["private", "public", "unlisted"] }
            }),
            &["idempotency_key", "account_id", "playlist_id", "privacy"],
        ),
        schema(
            "youtube_playlist_delete",
            "Supprime une playlist. Approbation obligatoire avant l'appel YouTube.",
            props_id("playlist_id"),
            &["idempotency_key", "account_id", "playlist_id"],
        ),
        schema(
            "youtube_playlist_items_list",
            "Les vidéos d'une playlist, dans l'ordre.",
            props_liste(json!({ "playlist_id": { "type": "string" } })),
            &["account_id", "playlist_id"],
        ),
        schema(
            "youtube_playlist_item_add",
            "Ajoute une vidéo à une playlist, position optionnelle.",
            json!({
                "idempotency_key": cle(),
                "account_id": { "type": "string" },
                "playlist_id": { "type": "string" },
                "video_id": { "type": "string" },
                "position": { "type": "integer", "minimum": 0, "maximum": 5000 }
            }),
            &["idempotency_key", "account_id", "playlist_id", "video_id"],
        ),
        schema(
            "youtube_playlist_item_reorder",
            "Déplace un élément de playlist. Relit l'élément : playlistItems.update remplace le snippet.",
            json!({
                "idempotency_key": cle(),
                "account_id": { "type": "string" },
                "playlist_item_id": { "type": "string" },
                "position": { "type": "integer", "minimum": 0, "maximum": 5000 }
            }),
            &[
                "idempotency_key",
                "account_id",
                "playlist_item_id",
                "position",
            ],
        ),
        schema(
            "youtube_playlist_item_remove",
            "Retire une vidéo d'une playlist. Approbation obligatoire avant l'appel YouTube.",
            props_id("playlist_item_id"),
            &["idempotency_key", "account_id", "playlist_item_id"],
        ),
        schema(
            "youtube_comments_list",
            "Fils de commentaires. video_id : la vidéo. Absent : toute la chaîne. Chaque texte est third_party.",
            props_liste(json!({ "video_id": { "type": "string" } })),
            &["account_id"],
        ),
        schema(
            "youtube_comment_create",
            "Commentaire de premier niveau (video_id) ou suite (parent_id). 10 000 caractères maximum.",
            json!({
                "idempotency_key": cle(),
                "account_id": { "type": "string" },
                "text": { "type": "string" },
                "video_id": { "type": "string" },
                "parent_id": { "type": "string" }
            }),
            &["idempotency_key", "account_id", "text"],
        ),
        schema(
            "youtube_comment_moderate",
            "comments.setModerationStatus (heldForReview, published, rejected) et ban_author optionnel. Approbation obligatoire avant l'appel YouTube.",
            json!({
                "idempotency_key": cle(),
                "account_id": { "type": "string" },
                "comment_id": { "type": "string" },
                "moderation_status": { "type": "string", "enum": ["heldForReview", "published", "rejected"] },
                "ban_author": { "type": "boolean" }
            }),
            &[
                "idempotency_key",
                "account_id",
                "comment_id",
                "moderation_status",
            ],
        ),
        schema(
            "youtube_comment_delete",
            "Supprime un commentaire. Approbation obligatoire avant l'appel YouTube.",
            props_id("comment_id"),
            &["idempotency_key", "account_id", "comment_id"],
        ),
        schema(
            "youtube_captions_list",
            "Pistes de sous-titres d'une vidéo.",
            json!({
                "account_id": { "type": "string" },
                "video_id": { "type": "string" }
            }),
            &["account_id", "video_id"],
        ),
        schema(
            "youtube_caption_upload",
            "Envoie une piste (language, name, content SRT/VTT en texte). 400 unités de quota.",
            json!({
                "idempotency_key": cle(),
                "account_id": { "type": "string" },
                "video_id": { "type": "string" },
                "language": { "type": "string" },
                "name": { "type": "string" },
                "content": { "type": "string" },
                "is_draft": { "type": "boolean" }
            }),
            &[
                "idempotency_key",
                "account_id",
                "video_id",
                "language",
                "content",
            ],
        ),
        schema(
            "youtube_caption_download",
            "Télécharge une piste (format srt, vtt, sbv ou ttml ; défaut srt).",
            json!({
                "account_id": { "type": "string" },
                "caption_id": { "type": "string" },
                "format": { "type": "string", "enum": ["srt", "vtt", "sbv", "ttml"] }
            }),
            &["account_id", "caption_id"],
        ),
        schema(
            "youtube_caption_delete",
            "Supprime une piste de sous-titres. Approbation obligatoire avant l'appel YouTube.",
            props_id("caption_id"),
            &["idempotency_key", "account_id", "caption_id"],
        ),
        schema(
            "youtube_analytics_report",
            "Rapport YouTube Analytics v2 : vues, temps de visionnage, abonnés gagnés et perdus, par jour. video_id limite à une vidéo (sans les métriques d'abonnés, que l'API refuse dans ce filtre). Un compte connecté avant les portées Analytics doit être reconnecté via account_connect_url.",
            json!({
                "account_id": { "type": "string" },
                "start_date": { "type": "string" },
                "end_date": { "type": "string" },
                "video_id": { "type": "string" },
                "metrics": { "type": "string" },
                "dimensions": { "type": "string" }
            }),
            &["account_id", "start_date", "end_date"],
        ),
    ]
}

fn cle() -> Value {
    json!({ "type": "string", "minLength": 1, "maxLength": 200 })
}

fn schema(nom: &str, description: &str, properties: Value, required: &[&str]) -> Value {
    json!({
        "name": nom,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": false
        }
    })
}

fn props_chaine() -> Value {
    json!({
        "idempotency_key": cle(),
        "account_id": { "type": "string" },
        "description": { "type": "string" },
        "keywords": { "type": "string" },
        "country": { "type": "string" },
        "default_language": { "type": "string" },
        "unsubscribed_trailer": { "type": "string" }
    })
}

fn props_video() -> Value {
    json!({
        "idempotency_key": cle(),
        "account_id": { "type": "string" },
        "video_id": { "type": "string" },
        "title": { "type": "string" },
        "description": { "type": "string" },
        "tags": { "type": "array", "items": { "type": "string" }, "maxItems": 500 },
        "category_id": { "type": "string" },
        "made_for_kids": { "type": "boolean" }
    })
}

fn props_visibilite() -> Value {
    json!({
        "idempotency_key": cle(),
        "account_id": { "type": "string" },
        "video_id": { "type": "string" },
        "privacy": { "type": "string", "enum": ["private", "public", "unlisted"] },
        "publish_at": { "type": "string" }
    })
}

fn props_id(champ: &str) -> Value {
    json!({
        "idempotency_key": cle(),
        "account_id": { "type": "string" },
        champ: { "type": "string" }
    })
}

fn props_liste(extra: Value) -> Value {
    let mut props = json!({
        "account_id": { "type": "string" },
        "page_token": { "type": "string" },
        "max_results": { "type": "integer", "minimum": 1, "maximum": 50 }
    });
    if let (Some(dst), Some(src)) = (props.as_object_mut(), extra.as_object()) {
        for (k, v) in src {
            dst.insert(k.clone(), v.clone());
        }
    }
    props
}

fn props_playlist_create() -> Value {
    json!({
        "idempotency_key": cle(),
        "account_id": { "type": "string" },
        "title": { "type": "string" },
        "description": { "type": "string" },
        "privacy": { "type": "string", "enum": ["private", "public", "unlisted"] }
    })
}

fn props_playlist_update() -> Value {
    json!({
        "idempotency_key": cle(),
        "account_id": { "type": "string" },
        "playlist_id": { "type": "string" },
        "title": { "type": "string" },
        "description": { "type": "string" }
    })
}

pub fn est_outil(nom: &str) -> bool {
    descriptions()
        .iter()
        .any(|o| o["name"].as_str() == Some(nom))
}

pub(crate) async fn appeler(
    etat: &Etat,
    tenant: Uuid,
    nom: &str,
    args: &Value,
) -> Result<Value, Erreur> {
    if !est_outil(nom) {
        return Err(Erreur::nouvelle(
            "outil_inconnu",
            format!("pas d'outil `{nom}`"),
        ));
    }
    if GATES.contains(&nom) {
        soumettre(etat, tenant, nom, args).await
    } else if args.get("idempotency_key").is_some() {
        immediat(etat, tenant, nom, args).await
    } else {
        executer(etat, tenant, nom, args).await
    }
}

/// Joue une action déjà approuvée. Pas de seconde file.
pub(crate) async fn executer_depuis_la_file(
    etat: &Etat,
    ligne: &store::LigneFile,
) -> Result<Value, Erreur> {
    let nom = ligne
        .payload
        .get("youtube_tool")
        .and_then(Value::as_str)
        .ok_or_else(|| Erreur::nouvelle("argument_invalide", "action YouTube sans outil"))?;
    executer(etat, ligne.tenant_id, nom, &ligne.payload).await
}

fn traduire(e: EchecYoutube) -> Erreur {
    match e {
        EchecYoutube::ScopesInsuffisants => {
            Erreur::nouvelle("scopes_insuffisants", MESSAGE_RECONNEXION)
        }
        EchecYoutube::Argument(m) => Erreur::nouvelle("argument_invalide", m),
        EchecYoutube::Plateforme(p) => Erreur::nouvelle(p.code(), p.to_string()),
    }
}

async fn compte_yt(etat: &Etat, tenant: Uuid, args: &Value) -> Result<store::CompteScelle, Erreur> {
    let id = mcp::arg_uuid(args, "account_id")?;
    let compte = store::compte_scelle(&etat.pool, tenant, id)
        .await?
        .ok_or_else(|| {
            Erreur::nouvelle("compte_inconnu", "ce compte n'appartient pas à ce tenant")
        })?;
    if compte.platform != "youtube" {
        return Err(Erreur::nouvelle(
            "compte_pas_youtube",
            format!(
                "cet outil ne sert que YouTube, ce compte est `{}`",
                compte.platform
            ),
        ));
    }
    Ok(compte)
}

fn exiger_analytics(compte: &store::CompteScelle) -> Result<(), Erreur> {
    if youtube_gestion::scopes_analytics_ok(compte.oauth_scopes.as_deref()) {
        Ok(())
    } else {
        Err(Erreur::nouvelle("scopes_insuffisants", MESSAGE_RECONNEXION))
    }
}

fn digest_de(outil: &str, args: &Value) -> String {
    let mut lignes = vec![outil.to_owned()];
    if let Some(obj) = args.as_object() {
        let mut cles: Vec<_> = obj
            .keys()
            .filter(|k| k.as_str() != "idempotency_key" && k.as_str() != "youtube_tool")
            .cloned()
            .collect();
        cles.sort();
        for cle in cles {
            lignes.push(format!("{cle}={}", obj[&cle]));
        }
    }
    empreinte(&lignes.join("\n"))
}

fn payload_de(outil: &str, args: &Value) -> Result<Value, Erreur> {
    let mut obj = args
        .as_object()
        .cloned()
        .ok_or_else(|| Erreur::nouvelle("argument_invalide", "les arguments sont un objet"))?;
    obj.insert("youtube_tool".into(), json!(outil));
    Ok(Value::Object(obj))
}

async fn soumettre(etat: &Etat, tenant: Uuid, outil: &str, args: &Value) -> Result<Value, Erreur> {
    let cle = mcp::arg_str(args, "idempotency_key")?;
    let compte = compte_yt(etat, tenant, args).await?;
    valider_avant_file(outil, args)?;
    let digest = digest_de(outil, args);
    let payload = payload_de(outil, args)?;
    let expire = Some(chrono::Utc::now() + chrono::Duration::hours(etat.approval_ttl_hours));
    match store::poser_file(
        &etat.pool,
        tenant,
        compte.id,
        cle,
        "youtube",
        &payload,
        &digest,
        None,
        "pending_approval",
        expire,
    )
    .await?
    {
        Err(()) => Err(Erreur::nouvelle(
            "cle_reutilisee",
            "cette idempotency_key a déjà servi pour un AUTRE contenu",
        )),
        Ok(pose) => {
            let (ligne, replayed) = match pose {
                PoseFile::Nouvelle(l) => (l, false),
                PoseFile::Meme(l) => (l, true),
            };
            if ligne.status == "published"
                && let Some(resultat) = ligne.result.clone()
            {
                return Ok(marquer_rejeu(resultat, true));
            }
            let mut rendu = file::json_ligne(&ligne, replayed);
            if let Some(obj) = rendu.as_object_mut() {
                obj.insert(
                    "note".into(),
                    json!(
                        "en attente d'approbation : approval_decide joue l'action, rien n'est parti vers YouTube"
                    ),
                );
            }
            Ok(rendu)
        }
    }
}

fn marquer_rejeu(mut valeur: Value, replayed: bool) -> Value {
    if let Some(obj) = valeur.as_object_mut() {
        obj.insert("replayed".into(), json!(replayed));
    }
    valeur
}

async fn immediat(etat: &Etat, tenant: Uuid, outil: &str, args: &Value) -> Result<Value, Erreur> {
    let cle = mcp::arg_str(args, "idempotency_key")?;
    let compte = compte_yt(etat, tenant, args).await?;
    valider_immediat(outil, args)?;
    let digest = digest_de(outil, args);
    let payload = payload_de(outil, args)?;
    let pose = store::poser_file(
        &etat.pool,
        tenant,
        compte.id,
        cle,
        "youtube",
        &payload,
        &digest,
        None,
        "publishing",
        None,
    )
    .await?;
    let id = match pose {
        Err(()) => {
            return Err(Erreur::nouvelle(
                "cle_reutilisee",
                "cette idempotency_key a déjà servi pour un AUTRE contenu",
            ));
        }
        Ok(PoseFile::Nouvelle(l)) => l.id,
        Ok(PoseFile::Meme(l)) => match l.status.as_str() {
            "published" => {
                return Ok(match l.result {
                    Some(r) => marquer_rejeu(r, true),
                    None => file::json_ligne(&l, true),
                });
            }
            "failed" => {
                store::relancer_action_echouee(&etat.pool, tenant, l.id)
                    .await?
                    .ok_or_else(|| {
                        Erreur::nouvelle(
                            "publication_en_cours",
                            "une action avec cette clé est en vol ; rejouer dans un instant",
                        )
                    })?
                    .id
            }
            "pending_approval" => return Ok(file::json_ligne(&l, true)),
            _ => {
                return Err(Erreur::nouvelle(
                    "publication_en_cours",
                    "une action avec cette clé est en vol ; rejouer dans un instant",
                ));
            }
        },
    };
    match executer(etat, tenant, outil, args).await {
        Ok(valeur) => {
            let valeur = marquer_rejeu(valeur, false);
            store::marquer_file_resultat(&etat.pool, id, &valeur).await?;
            Ok(valeur)
        }
        Err(e) => {
            store::marquer_file_echec(&etat.pool, id, false, 0, &e.message).await?;
            Err(e)
        }
    }
}

fn valider_immediat(outil: &str, args: &Value) -> Result<(), Erreur> {
    match outil {
        "youtube_channel_update" => {
            let patch = patch_chaine(args).map_err(traduire)?;
            youtube_gestion::valider_chaine(&patch).map_err(traduire)
        }
        "youtube_video_update" => {
            let patch = patch_video(args).map_err(traduire)?;
            youtube_gestion::valider_video(&patch).map_err(traduire)
        }
        _ => Ok(()),
    }
}

fn valider_avant_file(outil: &str, args: &Value) -> Result<(), Erreur> {
    match outil {
        "youtube_video_visibility" => {
            exiger_id(args, "video_id")?;
            youtube_gestion::valider_visibilite(&Visibilite {
                privacy: opt_string(args, "privacy")?,
                publish_at: opt_string(args, "publish_at")?,
            })
            .map_err(traduire)?;
            if let Some(quand) = opt_str(args, "publish_at")? {
                file::parse_quand(quand)?;
            }
        }
        "youtube_video_delete" => {
            exiger_id(args, "video_id")?;
        }
        "youtube_playlist_visibility" => {
            exiger_id(args, "playlist_id")?;
            let privacy = mcp::arg_str(args, "privacy")?;
            if !matches!(privacy, "private" | "public" | "unlisted") {
                return Err(Erreur::nouvelle(
                    "argument_invalide",
                    "privacy : private, public ou unlisted",
                ));
            }
        }
        "youtube_playlist_delete" => exiger_id(args, "playlist_id")?,
        "youtube_playlist_item_remove" => exiger_id(args, "playlist_item_id")?,
        "youtube_comment_moderate" => {
            exiger_id(args, "comment_id")?;
            let statut = mcp::arg_str(args, "moderation_status")?;
            if !matches!(statut, "heldForReview" | "published" | "rejected") {
                return Err(Erreur::nouvelle(
                    "argument_invalide",
                    "moderation_status : heldForReview, published ou rejected",
                ));
            }
        }
        "youtube_comment_delete" => exiger_id(args, "comment_id")?,
        "youtube_caption_delete" => exiger_id(args, "caption_id")?,
        _ => {}
    }
    Ok(())
}

fn exiger_id(args: &Value, nom: &'static str) -> Result<(), Erreur> {
    let id = mcp::arg_str(args, nom)?;
    if youtube_gestion::id_youtube(id) {
        Ok(())
    } else {
        Err(Erreur::nouvelle(
            "argument_invalide",
            format!("`{nom}` n'est pas un identifiant YouTube"),
        ))
    }
}

async fn executer(etat: &Etat, tenant: Uuid, outil: &str, args: &Value) -> Result<Value, Erreur> {
    let compte = compte_yt(etat, tenant, args).await?;
    if outil == "youtube_analytics_report" {
        exiger_analytics(&compte)?;
    }
    let jeton = mcp::jeton_frais(etat, tenant, &compte).await?;
    let jeton = Arc::new(jeton);
    let resultat = mcp::avec_rejeu_401(etat, tenant, &compte, Arc::clone(&jeton), |j| {
        let args = args.clone();
        let outil = outil.to_owned();
        let chaine = compte.platform_user_id.clone();
        async move { jouer(&outil, &j, chaine.as_deref(), &args).await }
    })
    .await;
    resultat.map_err(traduire)
}

async fn jouer(
    outil: &str,
    secret: &Secret,
    chaine: Option<&str>,
    args: &Value,
) -> Result<Value, EchecYoutube> {
    match outil {
        "youtube_channel_get" => {
            youtube_gestion::lire_chaine(
                POINT_CHANNELS,
                secret,
                chaine.filter(|s| youtube_gestion::id_youtube(s)),
            )
            .await
        }
        "youtube_channel_update" => {
            let id = chaine_requise(chaine)?;
            youtube_gestion::ecrire_chaine(POINT_CHANNELS, secret, &id, &patch_chaine(args)?).await
        }
        "youtube_video_update" => {
            let id = id_de(args, "video_id")?;
            youtube_gestion::ecrire_video(POINT_VIDEOS, secret, &id, &patch_video(args)?).await
        }
        "youtube_video_visibility" => {
            let id = id_de(args, "video_id")?;
            let vis = Visibilite {
                privacy: opt_string(args, "privacy")
                    .map_err(|_| EchecYoutube::Argument("privacy illisible"))?,
                publish_at: opt_string(args, "publish_at")
                    .map_err(|_| EchecYoutube::Argument("publish_at illisible"))?,
            };
            youtube_gestion::ecrire_visibilite_video(POINT_VIDEOS, secret, &id, &vis).await
        }
        "youtube_video_delete" => {
            let id = id_de(args, "video_id")?;
            youtube_gestion::supprimer(POINT_VIDEOS, secret, &id, COUT_ECRITURE).await
        }
        "youtube_playlists_list" => {
            let mut q = vec![
                (
                    "part".to_owned(),
                    "snippet,status,contentDetails".to_owned(),
                ),
                ("mine".to_owned(), "true".to_owned()),
            ];
            page_dans(&mut q, args)?;
            let brut =
                youtube_gestion::lister(POINT_PLAYLISTS, secret, &paires(&q), COUT_LECTURE).await?;
            Ok(youtube_gestion::playlists_projetees(&brut))
        }
        "youtube_playlist_create" => {
            let titre = arg(args, "title")?;
            if titre.chars().count() > 150 {
                return Err(EchecYoutube::Argument(
                    "title de playlist : 150 caractères maximum",
                ));
            }
            let description = opt(args, "description")?;
            if description.is_some_and(|d| d.chars().count() > 5000) {
                return Err(EchecYoutube::Argument(
                    "description de playlist : 5000 caractères maximum",
                ));
            }
            let privacy = opt(args, "privacy")?.unwrap_or("private");
            if !matches!(privacy, "private" | "public" | "unlisted") {
                return Err(EchecYoutube::Argument(
                    "privacy : private, public ou unlisted",
                ));
            }
            let mut rendu = youtube_gestion::inserer(
                POINT_PLAYLISTS,
                secret,
                "snippet,status",
                &youtube_gestion::corps_playlist(titre, description, privacy),
                COUT_ECRITURE,
            )
            .await?;
            let identifiant = rendu.get("id").cloned().unwrap_or(Value::Null);
            if let Some(obj) = rendu.as_object_mut() {
                obj.insert("playlist_id".into(), identifiant);
            }
            Ok(rendu)
        }
        "youtube_playlist_update" => {
            let id = id_de(args, "playlist_id")?;
            let titre = opt(args, "title")?;
            let description = opt(args, "description")?;
            if titre.is_none() && description.is_none() {
                return Err(EchecYoutube::Argument(
                    "title ou description est obligatoire",
                ));
            }
            if titre.is_some_and(|t| t.is_empty() || t.chars().count() > 150) {
                return Err(EchecYoutube::Argument(
                    "title de playlist : 1 à 150 caractères",
                ));
            }
            let ressource = lire_une(POINT_PLAYLISTS, secret, &id, "snippet").await?;
            let corps = youtube_gestion::corps_playlist_meta(&ressource, titre, description)?;
            let mut rendu = youtube_gestion::inserer_put(
                POINT_PLAYLISTS,
                secret,
                "snippet",
                &corps,
                COUT_LECTURE + COUT_ECRITURE,
            )
            .await?;
            if let Some(obj) = rendu.as_object_mut() {
                obj.insert("playlist_id".into(), json!(id));
            }
            Ok(rendu)
        }
        "youtube_playlist_visibility" => {
            let id = id_de(args, "playlist_id")?;
            let privacy = arg(args, "privacy")?;
            let ressource = lire_une(POINT_PLAYLISTS, secret, &id, "status").await?;
            let corps = youtube_gestion::corps_playlist_visibilite(&ressource, privacy)?;
            youtube_gestion::inserer_put(
                POINT_PLAYLISTS,
                secret,
                "status",
                &corps,
                COUT_LECTURE + COUT_ECRITURE,
            )
            .await
        }
        "youtube_playlist_delete" => {
            let id = id_de(args, "playlist_id")?;
            youtube_gestion::supprimer(POINT_PLAYLISTS, secret, &id, COUT_ECRITURE).await
        }
        "youtube_playlist_items_list" => {
            let id = id_de(args, "playlist_id")?;
            let mut q = vec![
                ("part".to_owned(), "snippet".to_owned()),
                ("playlistId".to_owned(), id),
            ];
            page_dans(&mut q, args)?;
            let brut =
                youtube_gestion::lister(POINT_PLAYLIST_ITEMS, secret, &paires(&q), COUT_LECTURE)
                    .await?;
            Ok(youtube_gestion::items_projetes(&brut))
        }
        "youtube_playlist_item_add" => {
            let playlist = id_de(args, "playlist_id")?;
            let video = id_de(args, "video_id")?;
            let position = opt_u32(args, "position")?;
            let mut rendu = youtube_gestion::inserer(
                POINT_PLAYLIST_ITEMS,
                secret,
                "snippet",
                &youtube_gestion::corps_ajout_item(&playlist, &video, position),
                COUT_ECRITURE,
            )
            .await?;
            let identifiant = rendu.get("id").cloned().unwrap_or(Value::Null);
            if let Some(obj) = rendu.as_object_mut() {
                obj.insert("playlist_item_id".into(), identifiant);
            }
            Ok(rendu)
        }
        "youtube_playlist_item_reorder" => {
            let id = id_de(args, "playlist_item_id")?;
            let position = opt_u32(args, "position")?
                .ok_or(EchecYoutube::Argument("position est obligatoire"))?;
            let ressource = lire_une(POINT_PLAYLIST_ITEMS, secret, &id, "snippet").await?;
            let corps = youtube_gestion::corps_reordonner(&ressource, position)?;
            youtube_gestion::inserer_put(
                POINT_PLAYLIST_ITEMS,
                secret,
                "snippet",
                &corps,
                COUT_LECTURE + COUT_ECRITURE,
            )
            .await
        }
        "youtube_playlist_item_remove" => {
            let id = id_de(args, "playlist_item_id")?;
            youtube_gestion::supprimer(POINT_PLAYLIST_ITEMS, secret, &id, COUT_ECRITURE).await
        }
        "youtube_comments_list" => {
            let mut q = vec![
                ("part".to_owned(), "snippet,replies".to_owned()),
                ("textFormat".to_owned(), "plainText".to_owned()),
            ];
            match opt(args, "video_id")? {
                Some(video) => {
                    if !youtube_gestion::id_youtube(video) {
                        return Err(EchecYoutube::Argument(
                            "video_id n'est pas un identifiant YouTube",
                        ));
                    }
                    q.push(("videoId".into(), video.to_owned()));
                }
                None => {
                    let id = chaine_requise(chaine)?;
                    q.push(("allThreadsRelatedToChannelId".into(), id));
                }
            }
            page_dans(&mut q, args)?;
            let brut =
                youtube_gestion::lister(POINT_COMMENT_THREADS, secret, &paires(&q), COUT_LECTURE)
                    .await?;
            Ok(youtube_gestion::fils_projetes(&brut))
        }
        "youtube_comment_create" => {
            let texte = arg(args, "text")?;
            if texte.chars().count() > 10_000 {
                return Err(EchecYoutube::Argument("text : 10 000 caractères maximum"));
            }
            let parent = opt(args, "parent_id")?;
            let video = opt(args, "video_id")?;
            match (parent, video) {
                (Some(parent), _) => {
                    if !youtube_gestion::id_youtube(parent) {
                        return Err(EchecYoutube::Argument(
                            "parent_id n'est pas un identifiant YouTube",
                        ));
                    }
                    youtube_gestion::inserer(
                        POINT_COMMENTS,
                        secret,
                        "snippet",
                        &youtube_gestion::corps_commentaire_suite(parent, texte),
                        COUT_ECRITURE,
                    )
                    .await
                }
                (None, Some(video)) => {
                    if !youtube_gestion::id_youtube(video) {
                        return Err(EchecYoutube::Argument(
                            "video_id n'est pas un identifiant YouTube",
                        ));
                    }
                    let id = chaine_requise(chaine)?;
                    youtube_gestion::inserer(
                        POINT_COMMENT_THREADS,
                        secret,
                        "snippet",
                        &youtube_gestion::corps_commentaire_racine(&id, video, texte),
                        COUT_ECRITURE,
                    )
                    .await
                }
                (None, None) => Err(EchecYoutube::Argument(
                    "video_id ou parent_id est obligatoire",
                )),
            }
        }
        "youtube_comment_moderate" => {
            let id = id_de(args, "comment_id")?;
            let statut = arg(args, "moderation_status")?;
            let ban = opt_bool(args, "ban_author")?.unwrap_or(false);
            youtube_gestion::moderer(POINT_COMMENT_MODERATION, secret, &id, statut, ban).await
        }
        "youtube_comment_delete" => {
            let id = id_de(args, "comment_id")?;
            youtube_gestion::supprimer(POINT_COMMENTS, secret, &id, COUT_ECRITURE).await
        }
        "youtube_captions_list" => {
            let id = id_de(args, "video_id")?;
            let q = vec![
                ("part".to_owned(), "snippet".to_owned()),
                ("videoId".to_owned(), id),
            ];
            let brut =
                youtube_gestion::lister(POINT_CAPTIONS, secret, &paires(&q), COUT_CAPTIONS_LIST)
                    .await?;
            Ok(youtube_gestion::captions_projetees(&brut))
        }
        "youtube_caption_upload" => {
            let video = id_de(args, "video_id")?;
            let langue = arg(args, "language")?;
            let nom = opt(args, "name")?.unwrap_or(langue);
            let contenu = arg(args, "content")?;
            let brouillon = opt_bool(args, "is_draft")?.unwrap_or(false);
            youtube_gestion::televerser_caption(
                POINT_CAPTIONS_UPLOAD,
                secret,
                &video,
                langue,
                nom,
                contenu,
                brouillon,
            )
            .await
        }
        "youtube_caption_download" => {
            let id = id_de(args, "caption_id")?;
            let format = opt(args, "format")?.unwrap_or("srt");
            youtube_gestion::telecharger_caption(POINT_CAPTIONS, secret, &id, format).await
        }
        "youtube_caption_delete" => {
            let id = id_de(args, "caption_id")?;
            youtube_gestion::supprimer(POINT_CAPTIONS, secret, &id, COUT_CAPTIONS_DELETE).await
        }
        "youtube_analytics_report" => {
            let debut = arg(args, "start_date")?;
            let fin = arg(args, "end_date")?;
            let video = opt(args, "video_id")?;
            if let Some(video) = video
                && !youtube_gestion::id_youtube(video)
            {
                return Err(EchecYoutube::Argument(
                    "video_id n'est pas un identifiant YouTube",
                ));
            }
            youtube_gestion::rapport(
                POINT_ANALYTICS,
                secret,
                &youtube_gestion::Rapport {
                    debut,
                    fin,
                    video_id: video,
                    metrics: opt(args, "metrics")?,
                    dimensions: opt(args, "dimensions")?,
                },
            )
            .await
        }
        _ => Err(EchecYoutube::Argument("outil YouTube inconnu")),
    }
}

async fn lire_une(
    point: &str,
    secret: &Secret,
    id: &str,
    part: &str,
) -> Result<Value, EchecYoutube> {
    let brut =
        youtube_gestion::lister(point, secret, &[("part", part), ("id", id)], COUT_LECTURE).await?;
    brut.get("items")
        .and_then(Value::as_array)
        .and_then(|l| l.first())
        .cloned()
        .ok_or(EchecYoutube::Plateforme(
            crate::adapters::ErreurPlateforme::Refus { statut: 404 },
        ))
}

fn chaine_requise(chaine: Option<&str>) -> Result<String, EchecYoutube> {
    chaine
        .filter(|s| youtube_gestion::id_youtube(s))
        .map(str::to_owned)
        .ok_or(EchecYoutube::Argument(
            "ce compte YouTube n'a pas d'id de chaîne — reconnecter via account_connect_url",
        ))
}

fn id_de(args: &Value, nom: &str) -> Result<String, EchecYoutube> {
    let id = arg(args, nom)?;
    if youtube_gestion::id_youtube(id) {
        Ok(id.to_owned())
    } else {
        Err(EchecYoutube::Argument("identifiant YouTube invalide"))
    }
}

fn arg<'a>(args: &'a Value, nom: &str) -> Result<&'a str, EchecYoutube> {
    args.get(nom)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(EchecYoutube::Argument("argument obligatoire manquant"))
}

fn opt<'a>(args: &'a Value, nom: &str) -> Result<Option<&'a str>, EchecYoutube> {
    match args.get(nom) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        _ => Err(EchecYoutube::Argument("argument texte illisible")),
    }
}

fn opt_string(args: &Value, nom: &str) -> Result<Option<String>, Erreur> {
    match args.get(nom) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        _ => Err(Erreur::nouvelle(
            "argument_invalide",
            format!("`{nom}` doit être une chaîne"),
        )),
    }
}

fn opt_str<'a>(args: &'a Value, nom: &str) -> Result<Option<&'a str>, Erreur> {
    match args.get(nom) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        _ => Err(Erreur::nouvelle(
            "argument_invalide",
            format!("`{nom}` doit être une chaîne"),
        )),
    }
}

fn opt_bool(args: &Value, nom: &str) -> Result<Option<bool>, EchecYoutube> {
    match args.get(nom) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        _ => Err(EchecYoutube::Argument("argument booléen illisible")),
    }
}

fn opt_u32(args: &Value, nom: &str) -> Result<Option<u32>, EchecYoutube> {
    let n = match args.get(nom) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) => s.parse::<u64>().ok(),
        _ => None,
    };
    match n {
        Some(n) if n <= 5000 => Ok(Some(n as u32)),
        Some(_) => Err(EchecYoutube::Argument("position hors bornes (0 à 5000)")),
        None => Err(EchecYoutube::Argument("entier illisible")),
    }
}

fn patch_chaine(args: &Value) -> Result<PatchChaine, EchecYoutube> {
    Ok(PatchChaine {
        description: opt(args, "description")?.map(str::to_owned),
        keywords: opt(args, "keywords")?.map(str::to_owned),
        country: opt(args, "country")?.map(str::to_owned),
        default_language: opt(args, "default_language")?.map(str::to_owned),
        unsubscribed_trailer: opt(args, "unsubscribed_trailer")?.map(str::to_owned),
    })
}

fn patch_video(args: &Value) -> Result<PatchVideo, EchecYoutube> {
    let tags = match args.get("tags") {
        None | Some(Value::Null) => None,
        Some(Value::Array(liste)) => {
            let mut tags = Vec::new();
            for t in liste {
                let Some(s) = t.as_str() else {
                    return Err(EchecYoutube::Argument("tags : tableau de chaînes"));
                };
                tags.push(s.to_owned());
            }
            Some(tags)
        }
        _ => return Err(EchecYoutube::Argument("tags : tableau de chaînes")),
    };
    Ok(PatchVideo {
        title: opt(args, "title")?.map(str::to_owned),
        description: opt(args, "description")?.map(str::to_owned),
        tags,
        category_id: opt(args, "category_id")?.map(str::to_owned),
        made_for_kids: opt_bool(args, "made_for_kids")?,
    })
}

fn page_dans(q: &mut Vec<(String, String)>, args: &Value) -> Result<(), EchecYoutube> {
    let max = match args.get("max_results") {
        None | Some(Value::Null) => 20u64,
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(Value::String(s)) => s.parse().unwrap_or(0),
        _ => 0,
    };
    if !(1..=50).contains(&max) {
        return Err(EchecYoutube::Argument("max_results : 1 à 50"));
    }
    q.push(("maxResults".into(), max.to_string()));
    if let Some(token) = opt(args, "page_token")? {
        q.push(("pageToken".into(), token.to_owned()));
    }
    Ok(())
}

fn paires(q: &[(String, String)]) -> Vec<(&str, &str)> {
    q.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn les_outils_gates_sont_dans_la_table_et_les_noms_ne_parlent_a_personne() {
        let noms: Vec<_> = descriptions()
            .iter()
            .map(|o| o["name"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(noms.len(), 23);
        for gate in GATES {
            assert!(noms.iter().any(|n| n == gate), "{gate}");
        }
        let interdits = [
            "dm",
            "message",
            "broadcast",
            "direct",
            "inbox",
            "chat",
            "reply",
            "send",
            "mention",
        ];
        for nom in &noms {
            for motif in interdits {
                assert!(!nom.contains(motif), "{nom} contient {motif}");
            }
        }
    }

    #[test]
    fn un_compte_sans_portees_analytics_est_refuse_sans_panique() {
        let compte = store::CompteScelle {
            id: Uuid::nil(),
            platform: "youtube".into(),
            handle: "chaine".into(),
            platform_user_id: Some("UCabc".into()),
            sealed_token: None,
            sealed_refresh: None,
            token_expires_epoch: None,
            oauth_scopes: None,
        };
        let erreur = exiger_analytics(&compte).expect_err("anciennes portées");
        assert_eq!(erreur.code, "scopes_insuffisants");
        assert!(erreur.message.contains("account_connect_url"));
        let mut avec = compte;
        avec.oauth_scopes = Some(
            "https://www.googleapis.com/auth/youtube.readonly https://www.googleapis.com/auth/yt-analytics.readonly"
                .into(),
        );
        assert!(exiger_analytics(&avec).is_ok());
    }
}

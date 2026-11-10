//! Les requetes. Toute l'idempotence vit ici, parce qu'elle vit dans la base :
//! la contrainte UNIQUE (tenant_id, idempotency_key) est la garantie, et ce
//! module ne fait que la parler couramment.

use sqlx::Row;
use sqlx::postgres::PgPool;
use uuid::Uuid;

/// Un compte tel que `accounts_list` le montre.
pub struct Compte {
    pub id: Uuid,
    pub platform: String,
    pub handle: String,
    pub status: String,
}

/// Un compte tel que `post_publish` en a besoin : avec son enveloppe.
pub struct CompteScelle {
    pub id: Uuid,
    pub platform: String,
    pub handle: String,
    /// L'identifiant du compte chez la plateforme (id numerique chez X, URN
    /// chez LinkedIn) — celui que les chemins `/2/users/{id}/…` exigent.
    /// None = compte connecte avant 0005 : reconnecter via account_connect_url.
    pub platform_user_id: Option<String>,
    pub sealed_token: Option<Vec<u8>>,
    /// Le refresh token scellé, quand la plateforme en a émis un (X avec
    /// `offline.access` ; chez Instagram c'est une COPIE du jeton long, qui
    /// se rafraîchit lui-même). C'est lui qui permet au chemin de publication
    /// de survivre à l'expiration du jeton d'accès sans re-consentement humain.
    pub sealed_refresh: Option<Vec<u8>>,
    /// L'heure de mort annoncée du jeton d'accès, en secondes epoch — lue en
    /// entier plutôt qu'en timestamptz pour que `mcp::doit_rafraichir` reste
    /// une fonction pure sur deux nombres. None = inconnue (compte d'avant
    /// 0006) : pas de rafraîchissement proactif, le chemin 401 fait foi.
    pub token_expires_epoch: Option<i64>,
    /// Portées accordées au consentement (`scope` du point de jeton).
    /// None = compte connecté avant 0008 : les outils qui exigent une portée
    /// ajoutée depuis (Analytics YouTube) renvoient vers account_connect_url.
    pub oauth_scopes: Option<String>,
}

/// Une ligne de social_posts, telle que les outils la rendent.
pub struct Post {
    pub id: Uuid,
    pub account_id: Uuid,
    pub text_body: String,
    pub digest: String,
    /// SHA-256 hex de chaque média publié, dans l'ordre du tableau `media`
    /// de l'appel — vide pour un post texte seul. Pour l'audit : `digest`
    /// reste l'empreinte GLOBALE que le rejeu compare.
    pub media_digests: Vec<String>,
    pub platform_post_id: Option<String>,
    pub url: Option<String>,
    pub status: String,
}

fn post_de(l: &sqlx::postgres::PgRow) -> Post {
    Post {
        id: l.get("id"),
        account_id: l.get("account_id"),
        text_body: l.get("text_body"),
        digest: l.get("digest"),
        media_digests: l.get("media_digests"),
        platform_post_id: l.get("platform_post_id"),
        url: l.get("url"),
        status: l.get("status"),
    }
}

pub async fn comptes(pool: &PgPool, tenant: Uuid) -> sqlx::Result<Vec<Compte>> {
    let lignes = sqlx::query(
        "SELECT id, platform, handle, status FROM social_accounts \
         WHERE tenant_id = $1 ORDER BY created_at",
    )
    .bind(tenant)
    .fetch_all(pool)
    .await?;
    Ok(lignes
        .iter()
        .map(|l| Compte {
            id: l.get("id"),
            platform: l.get("platform"),
            handle: l.get("handle"),
            status: l.get("status"),
        })
        .collect())
}

pub async fn compte_scelle(
    pool: &PgPool,
    tenant: Uuid,
    compte: Uuid,
) -> sqlx::Result<Option<CompteScelle>> {
    let ligne = sqlx::query(
        "SELECT id, platform, handle, platform_user_id, sealed_token, sealed_refresh, \
                EXTRACT(EPOCH FROM token_expires_at)::bigint AS token_expires_epoch, \
                oauth_scopes \
         FROM social_accounts WHERE id = $1 AND tenant_id = $2",
    )
    .bind(compte)
    .bind(tenant)
    .fetch_optional(pool)
    .await?;
    Ok(ligne.map(|l| CompteScelle {
        id: l.get("id"),
        platform: l.get("platform"),
        handle: l.get("handle"),
        platform_user_id: l.get("platform_user_id"),
        sealed_token: l.get("sealed_token"),
        sealed_refresh: l.get("sealed_refresh"),
        token_expires_epoch: l.get("token_expires_epoch"),
        oauth_scopes: l.get("oauth_scopes"),
    }))
}

/// Connecte (ou reconnecte) un compte. L'upsert est ce qui permet a l'AAD de
/// porter le handle : la ligne survit a la reconnexion, le scellement aussi.
// Paramètres plats pour un INSERT plat : les grouper dans une struct ne
// ferait que déplacer les mêmes noms — le SQL en dessous est la vérité.
#[allow(clippy::too_many_arguments)]
pub async fn connecter_compte(
    pool: &PgPool,
    tenant: Uuid,
    platform: &str,
    handle: &str,
    platform_user_id: Option<&str>,
    sealed_token: &[u8],
    sealed_refresh: Option<&[u8]>,
    duree_s: Option<i64>,
    oauth_scopes: Option<&str>,
) -> sqlx::Result<Uuid> {
    let ligne = sqlx::query(
        // COALESCE sur platform_user_id : une reconnexion qui ne le porterait
        // pas n'efface jamais un id deja connu — le meme argument que le
        // refresh token dans resceller_jetons. Pareil pour oauth_scopes :
        // un flux qui ne les rapporte pas ne vide pas celles qu'on a.
        // token_expires_at = now() + duree_s : l'heure de mort du jeton frais.
        // NULL quand la duree est inconnue — et une reconnexion ECRASE (pas de
        // COALESCE ici) : le jeton est neuf, son ancienne heure de mort ment.
        "INSERT INTO social_accounts \
             (id, tenant_id, platform, handle, platform_user_id, sealed_token, sealed_refresh, \
              token_expires_at, oauth_scopes) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(secs => $8), $9) \
         ON CONFLICT (tenant_id, platform, handle) \
         DO UPDATE SET sealed_token = EXCLUDED.sealed_token, \
                       sealed_refresh = EXCLUDED.sealed_refresh, \
                       platform_user_id = COALESCE(EXCLUDED.platform_user_id, \
                                                   social_accounts.platform_user_id), \
                       token_expires_at = EXCLUDED.token_expires_at, \
                       oauth_scopes = COALESCE(EXCLUDED.oauth_scopes, social_accounts.oauth_scopes), \
                       status = 'connected' \
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(tenant)
    .bind(platform)
    .bind(handle)
    .bind(platform_user_id)
    .bind(sealed_token)
    .bind(sealed_refresh)
    .bind(duree_s.map(|s| s as f64))
    .bind(oauth_scopes)
    .fetch_one(pool)
    .await?;
    Ok(ligne.get("id"))
}

/// Rescelle les jetons d'un compte après un rafraîchissement réussi.
///
/// `sealed_refresh` n'écrase l'ancien que s'il est `Some` : X fait tourner ses
/// refresh tokens (la réponse en porte un nouveau) mais rien ne garantit qu'il
/// en porte un à chaque fois — et perdre celui qu'on a contre un `NULL`
/// coûterait un re-consentement humain. `COALESCE` dit exactement ça en SQL.
pub async fn resceller_jetons(
    pool: &PgPool,
    tenant: Uuid,
    compte: Uuid,
    sealed_token: &[u8],
    sealed_refresh: Option<&[u8]>,
    duree_s: Option<i64>,
    oauth_scopes: Option<&str>,
) -> sqlx::Result<()> {
    sqlx::query(
        // Meme COALESCE pour l'heure de mort que pour le refresh : une duree
        // absente ne remplace pas une heure connue par NULL — mais une duree
        // connue ecrase, le jeton vient d'etre re-emis. Les portées aussi :
        // un refresh qui ne les répète pas ne les efface pas.
        "UPDATE social_accounts \
         SET sealed_token = $3, sealed_refresh = COALESCE($4, sealed_refresh), \
             token_expires_at = COALESCE(now() + make_interval(secs => $5), token_expires_at), \
             oauth_scopes = COALESCE($6, oauth_scopes) \
         WHERE id = $1 AND tenant_id = $2",
    )
    .bind(compte)
    .bind(tenant)
    .bind(sealed_token)
    .bind(sealed_refresh)
    .bind(duree_s.map(|s| s as f64))
    .bind(oauth_scopes)
    .execute(pool)
    .await?;
    Ok(())
}

/// Ce que la reclamation d'une cle d'idempotence peut donner.
pub enum Reclamation {
    /// La cle est a nous : publier, puis marquer.
    ANous(Uuid),
    /// Deja publie avec cette cle : rejouer la reponse, sans republier.
    DejaPublie(Post),
    /// La meme cle porte un AUTRE texte : bug d'agent, on refuse.
    TexteDifferent,
    /// Une publication avec cette cle est en vol dans un autre tour.
    EnVol,
}

/// Reclame `(tenant, idempotency_key)` AVANT d'appeler la plateforme.
///
/// L'ordre est la securite : si le processus meurt entre la reclamation et la
/// reponse de la plateforme, la ligne 'pending' reste, et le rejeu la voit au
/// lieu de republier. Une ligne 'failed' se re-reclame (la plateforme n'a rien
/// publie) ; une ligne 'pending' d'un autre tour rend EnVol plutot que de
/// courir deux publications.
pub async fn reclamer(
    pool: &PgPool,
    tenant: Uuid,
    compte: Uuid,
    cle: &str,
    texte: &str,
    digest: &str,
    media_digests: &[String],
) -> sqlx::Result<Reclamation> {
    let gagne = sqlx::query(
        "INSERT INTO social_posts (id, tenant_id, account_id, idempotency_key, text_body, digest, media_digests) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (tenant_id, idempotency_key) DO NOTHING RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(tenant)
    .bind(compte)
    .bind(cle)
    .bind(texte)
    .bind(digest)
    .bind(media_digests)
    .fetch_optional(pool)
    .await?;
    if let Some(l) = gagne {
        return Ok(Reclamation::ANous(l.get("id")));
    }

    // La comparaison du rejeu reste sur `digest` SEUL : c'est l'empreinte
    // GLOBALE (texte + médias + sondage), donc une image différente sous la
    // même clé y tombe déjà — `media_digests` n'est que de l'audit.
    let existant = sqlx::query(
        "SELECT id, account_id, text_body, digest, media_digests, platform_post_id, url, status \
         FROM social_posts WHERE tenant_id = $1 AND idempotency_key = $2",
    )
    .bind(tenant)
    .bind(cle)
    .fetch_one(pool)
    .await?;
    let post = post_de(&existant);
    if post.digest != digest {
        return Ok(Reclamation::TexteDifferent);
    }
    match post.status.as_str() {
        "published" => Ok(Reclamation::DejaPublie(post)),
        // Un echec — ou un fil partiel — se re-reclame. Les éléments déjà
        // publiés restent en base : le rejeu ne les renvoie pas.
        "failed" | "partial" => {
            let repris = sqlx::query(
                "UPDATE social_posts SET status = 'pending' \
                 WHERE id = $1 AND status IN ('failed', 'partial') RETURNING id",
            )
            .bind(post.id)
            .fetch_optional(pool)
            .await?;
            Ok(match repris {
                Some(l) => Reclamation::ANous(l.get("id")),
                None => Reclamation::EnVol,
            })
        }
        _ => Ok(Reclamation::EnVol),
    }
}

pub async fn marquer_publie(
    pool: &PgPool,
    id: Uuid,
    platform_post_id: &str,
    url: Option<&str>,
) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE social_posts SET status = 'published', platform_post_id = $2, url = $3, \
         published_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(platform_post_id)
    .bind(url)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn marquer_echec(pool: &PgPool, id: Uuid) -> sqlx::Result<()> {
    sqlx::query("UPDATE social_posts SET status = 'failed' WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn post(pool: &PgPool, tenant: Uuid, id: Uuid) -> sqlx::Result<Option<Post>> {
    let ligne = sqlx::query(
        "SELECT id, account_id, text_body, digest, media_digests, platform_post_id, url, status \
         FROM social_posts WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(tenant)
    .fetch_optional(pool)
    .await?;
    Ok(ligne.as_ref().map(post_de))
}

pub async fn posts(pool: &PgPool, tenant: Uuid, limite: i64) -> sqlx::Result<Vec<Post>> {
    let lignes = sqlx::query(
        "SELECT id, account_id, text_body, digest, media_digests, platform_post_id, url, status \
         FROM social_posts WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2",
    )
    .bind(tenant)
    .bind(limite)
    .fetch_all(pool)
    .await?;
    Ok(lignes.iter().map(post_de).collect())
}

// ---------------------------------------------------------------------------
// Suppressions : la regle des refus permanents
// ---------------------------------------------------------------------------

/// `dm_open` appelle ceci AVANT tout appel plateforme : un destinataire
/// supprime rend un refus nomme, zero requete reseau, zero centime.
pub async fn est_supprime(
    pool: &PgPool,
    tenant: Uuid,
    platform: &str,
    target: &str,
) -> sqlx::Result<bool> {
    let ligne = sqlx::query(
        "SELECT 1 AS un FROM social_suppressions \
         WHERE tenant_id = $1 AND platform = $2 AND target = $3",
    )
    .bind(tenant)
    .bind(platform)
    .bind(target)
    .fetch_optional(pool)
    .await?;
    Ok(ligne.is_some())
}

/// Le refus de la plateforme devient permanent chez nous : un 403 au retour
/// de `dm_open` insere la ligne avant de rendre l'erreur. `ON CONFLICT DO
/// NOTHING` : la premiere raison enregistree est la bonne, on ne la reecrit
/// pas.
pub async fn supprimer(
    pool: &PgPool,
    tenant: Uuid,
    platform: &str,
    target: &str,
    reason: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO social_suppressions (tenant_id, platform, target, reason) \
         VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
    )
    .bind(tenant)
    .bind(platform)
    .bind(target)
    .bind(reason)
    .execute(pool)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// OAuth en attente
// ---------------------------------------------------------------------------

pub async fn creer_attente_oauth(
    pool: &PgPool,
    state: &str,
    tenant: Uuid,
    platform: &str,
    sealed_verifier: Option<&[u8]>,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO social_oauth_pending (state, tenant_id, platform, sealed_verifier) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(state)
    .bind(tenant)
    .bind(platform)
    .bind(sealed_verifier)
    .execute(pool)
    .await?;
    Ok(())
}

/// Consomme un state : le lit ET le supprime dans la meme requete — un state
/// ne sert qu'une fois, et la fenetre est de quinze minutes.
/// ponytail: pas de balayeur des lignes expirees ; elles sont inertes (le
/// DELETE conditionnel les ignore) et le volume est celui des clics humains.
pub async fn consommer_attente_oauth(
    pool: &PgPool,
    state: &str,
) -> sqlx::Result<Option<(Uuid, String, Option<Vec<u8>>)>> {
    let ligne = sqlx::query(
        "DELETE FROM social_oauth_pending \
         WHERE state = $1 AND created_at > now() - interval '15 minutes' \
         RETURNING tenant_id, platform, sealed_verifier",
    )
    .bind(state)
    .fetch_optional(pool)
    .await?;
    Ok(ligne.map(|l| {
        (
            l.get("tenant_id"),
            l.get("platform"),
            l.get("sealed_verifier"),
        )
    }))
}

// ---------------------------------------------------------------------------
// File durable : calendrier + approbation
// ---------------------------------------------------------------------------

/// Une ligne de `social_scheduled`.
pub struct LigneFile {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub account_id: Uuid,
    pub idempotency_key: String,
    pub kind: String,
    pub payload: serde_json::Value,
    pub digest: String,
    pub publish_at: Option<chrono::DateTime<chrono::Utc>>,
    pub status: String,
    pub attempts: i32,
    pub post_id: Option<Uuid>,
    /// Réponse d'une action YouTube déjà jouée, pour le rejeu de la clé.
    pub result: Option<serde_json::Value>,
}

fn ligne_file(l: &sqlx::postgres::PgRow) -> LigneFile {
    LigneFile {
        id: l.get("id"),
        tenant_id: l.get("tenant_id"),
        account_id: l.get("account_id"),
        idempotency_key: l.get("idempotency_key"),
        kind: l.get("kind"),
        payload: l.get("payload"),
        digest: l.get("digest"),
        publish_at: l.get("publish_at"),
        status: l.get("status"),
        attempts: l.get("attempts"),
        post_id: l.get("post_id"),
        result: l.get("result"),
    }
}

const COLS_FILE: &str = "id, tenant_id, account_id, idempotency_key, kind, payload, \
     digest, publish_at, status, attempts, post_id, result";
const SELECT_FILE: &str = "SELECT id, tenant_id, account_id, idempotency_key, kind, payload, \
     digest, publish_at, status, attempts, post_id, result FROM social_scheduled";

/// Création, ou rejeu de la même clé et du même digest.
pub enum PoseFile {
    Nouvelle(LigneFile),
    Meme(LigneFile),
}

/// Pose un créneau. La contrainte UNIQUE (tenant, clé) est le rejeu : même
/// digest → la ligne existante ; digest différent → `Err(())`.
#[allow(clippy::too_many_arguments)]
pub async fn poser_file(
    pool: &PgPool,
    tenant: Uuid,
    compte: Uuid,
    cle: &str,
    kind: &str,
    payload: &serde_json::Value,
    digest: &str,
    publish_at: Option<chrono::DateTime<chrono::Utc>>,
    status: &str,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> sqlx::Result<Result<PoseFile, ()>> {
    let prochaine = publish_at.unwrap_or_else(chrono::Utc::now);
    let gagne = sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO social_scheduled \
            (id, tenant_id, account_id, idempotency_key, kind, payload, digest, \
             publish_at, status, next_attempt_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
         ON CONFLICT (tenant_id, idempotency_key) DO NOTHING \
         RETURNING {cols}",
        cols = "id, tenant_id, account_id, idempotency_key, kind, payload, digest, publish_at, status, attempts, post_id, result"
    )))
    .bind(Uuid::now_v7())
    .bind(tenant)
    .bind(compte)
    .bind(cle)
    .bind(kind)
    .bind(payload)
    .bind(digest)
    .bind(publish_at)
    .bind(status)
    .bind(prochaine)
    .bind(expires_at)
    .fetch_optional(pool)
    .await?;
    if let Some(l) = gagne {
        return Ok(Ok(PoseFile::Nouvelle(ligne_file(&l))));
    }
    let existante = sqlx::query(sqlx::AssertSqlSafe(format!(
        "{SELECT_FILE} WHERE tenant_id = $1 AND idempotency_key = $2"
    )))
    .bind(tenant)
    .bind(cle)
    .fetch_one(pool)
    .await?;
    let ligne = ligne_file(&existante);
    if ligne.digest == digest {
        Ok(Ok(PoseFile::Meme(ligne)))
    } else {
        Ok(Err(()))
    }
}

pub async fn file_par_id(pool: &PgPool, tenant: Uuid, id: Uuid) -> sqlx::Result<Option<LigneFile>> {
    let ligne = sqlx::query(sqlx::AssertSqlSafe(format!(
        "{SELECT_FILE} WHERE id = $1 AND tenant_id = $2"
    )))
    .bind(id)
    .bind(tenant)
    .fetch_optional(pool)
    .await?;
    Ok(ligne.as_ref().map(ligne_file))
}

pub async fn file_par_cle(
    pool: &PgPool,
    tenant: Uuid,
    cle: &str,
) -> sqlx::Result<Option<LigneFile>> {
    let ligne = sqlx::query(sqlx::AssertSqlSafe(format!(
        "{SELECT_FILE} WHERE tenant_id = $1 AND idempotency_key = $2"
    )))
    .bind(tenant)
    .bind(cle)
    .fetch_optional(pool)
    .await?;
    Ok(ligne.as_ref().map(ligne_file))
}

/// Passe `pending_approval` dont l'échéance est dépassée à `expired`.
pub async fn expirer_file(pool: &PgPool) -> sqlx::Result<u64> {
    let r = sqlx::query(
        "UPDATE social_scheduled SET status = 'expired', updated_at = now() \
         WHERE status = 'pending_approval' AND expires_at IS NOT NULL AND expires_at < now()",
    )
    .execute(pool)
    .await?;
    Ok(r.rows_affected())
}

/// Reprend une publication coincée en `publishing` depuis plus de 15 minutes.
pub async fn reprendre_publishing_perime(pool: &PgPool) -> sqlx::Result<u64> {
    let r = sqlx::query(
        "UPDATE social_scheduled SET status = 'scheduled', updated_at = now() \
         WHERE status = 'publishing' AND updated_at < now() - interval '15 minutes'",
    )
    .execute(pool)
    .await?;
    Ok(r.rows_affected())
}

/// Réclame UNE ligne due. `None` = rien à poster.
pub async fn prendre_echeance(pool: &PgPool) -> sqlx::Result<Option<LigneFile>> {
    let ligne = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE social_scheduled SET status = 'publishing', updated_at = now() \
         WHERE id = ( \
             SELECT id FROM social_scheduled \
             WHERE status = 'scheduled' AND next_attempt_at <= now() \
               AND attempts < max_attempts \
             ORDER BY next_attempt_at \
             FOR UPDATE SKIP LOCKED \
             LIMIT 1 \
         ) RETURNING {cols}",
        cols = "id, tenant_id, account_id, idempotency_key, kind, payload, digest, publish_at, status, attempts, post_id, result"
    )))
    .fetch_optional(pool)
    .await?;
    Ok(ligne.as_ref().map(ligne_file))
}

pub async fn marquer_file_publiee(pool: &PgPool, id: Uuid, post_id: Uuid) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE social_scheduled SET status = 'published', post_id = $2, updated_at = now() \
         WHERE id = $1",
    )
    .bind(id)
    .bind(post_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Une action YouTube jouée : pas de ligne `social_posts`, la réponse tient
/// dans `result` pour le rejeu.
pub async fn marquer_file_resultat(
    pool: &PgPool,
    id: Uuid,
    resultat: &serde_json::Value,
) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE social_scheduled SET status = 'published', result = $2, updated_at = now() \
         WHERE id = $1",
    )
    .bind(id)
    .bind(resultat)
    .execute(pool)
    .await?;
    Ok(())
}

/// Reprend une action YouTube `failed` pour un rejeu de la même clé.
pub async fn relancer_action_echouee(
    pool: &PgPool,
    tenant: Uuid,
    id: Uuid,
) -> sqlx::Result<Option<LigneFile>> {
    let ligne = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE social_scheduled SET status = 'publishing', updated_at = now() \
         WHERE id = $1 AND tenant_id = $2 AND status = 'failed' \
         RETURNING {COLS_FILE}"
    )))
    .bind(id)
    .bind(tenant)
    .fetch_optional(pool)
    .await?;
    Ok(ligne.as_ref().map(ligne_file))
}

/// Recule la ligne. `reprendre` faux = tentatives épuisées, statut `failed`.
pub async fn marquer_file_echec(
    pool: &PgPool,
    id: Uuid,
    reprendre: bool,
    attendre_s: i64,
    erreur: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE social_scheduled \
         SET status = CASE WHEN $2 THEN 'scheduled' ELSE 'failed' END, \
             attempts = attempts + 1, \
             next_attempt_at = now() + make_interval(secs => $3), \
             last_error = $4, updated_at = now() \
         WHERE id = $1",
    )
    .bind(id)
    .bind(reprendre)
    .bind(attendre_s as f64)
    .bind(erreur)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn decider_file(
    pool: &PgPool,
    tenant: Uuid,
    id: Uuid,
    status: &str,
    note: Option<&str>,
) -> sqlx::Result<Option<LigneFile>> {
    let ligne = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE social_scheduled \
         SET status = $3, decision_note = $4, \
             next_attempt_at = COALESCE(publish_at, now()), updated_at = now() \
         WHERE id = $1 AND tenant_id = $2 AND status = 'pending_approval' \
         RETURNING {cols}",
        cols = "id, tenant_id, account_id, idempotency_key, kind, payload, digest, publish_at, status, attempts, post_id, result"
    )))
    .bind(id)
    .bind(tenant)
    .bind(status)
    .bind(note)
    .fetch_optional(pool)
    .await?;
    Ok(ligne.as_ref().map(ligne_file))
}

pub async fn editer_file(
    pool: &PgPool,
    tenant: Uuid,
    id: Uuid,
    payload: &serde_json::Value,
    digest: &str,
) -> sqlx::Result<Option<LigneFile>> {
    let ligne = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE social_scheduled SET payload = $3, digest = $4, updated_at = now() \
         WHERE id = $1 AND tenant_id = $2 AND status = 'pending_approval' \
         RETURNING {cols}",
        cols = "id, tenant_id, account_id, idempotency_key, kind, payload, digest, publish_at, status, attempts, post_id, result"
    )))
    .bind(id)
    .bind(tenant)
    .bind(payload)
    .bind(digest)
    .fetch_optional(pool)
    .await?;
    Ok(ligne.as_ref().map(ligne_file))
}

pub async fn annuler_file(
    pool: &PgPool,
    tenant: Uuid,
    id: Uuid,
) -> sqlx::Result<Option<LigneFile>> {
    let ligne = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE social_scheduled SET status = 'cancelled', updated_at = now() \
         WHERE id = $1 AND tenant_id = $2 \
           AND status IN ('scheduled', 'pending_approval') \
         RETURNING {cols}",
        cols = "id, tenant_id, account_id, idempotency_key, kind, payload, digest, publish_at, status, attempts, post_id, result"
    )))
    .bind(id)
    .bind(tenant)
    .fetch_optional(pool)
    .await?;
    Ok(ligne.as_ref().map(ligne_file))
}

pub async fn reprogrammer_file(
    pool: &PgPool,
    tenant: Uuid,
    id: Uuid,
    quand: chrono::DateTime<chrono::Utc>,
) -> sqlx::Result<Option<LigneFile>> {
    let ligne = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE social_scheduled \
         SET publish_at = $3, next_attempt_at = $3, updated_at = now() \
         WHERE id = $1 AND tenant_id = $2 \
           AND status IN ('scheduled', 'pending_approval') \
         RETURNING {cols}",
        cols = "id, tenant_id, account_id, idempotency_key, kind, payload, digest, publish_at, status, attempts, post_id, result"
    )))
    .bind(id)
    .bind(tenant)
    .bind(quand)
    .fetch_optional(pool)
    .await?;
    Ok(ligne.as_ref().map(ligne_file))
}

pub async fn lister_file(
    pool: &PgPool,
    tenant: Uuid,
    compte: Option<Uuid>,
    debut: Option<chrono::DateTime<chrono::Utc>>,
    fin: Option<chrono::DateTime<chrono::Utc>>,
) -> sqlx::Result<Vec<LigneFile>> {
    let lignes = sqlx::query(sqlx::AssertSqlSafe(format!(
        "{SELECT_FILE} WHERE tenant_id = $1 \
           AND ($2::uuid IS NULL OR account_id = $2) \
           AND ($3::timestamptz IS NULL OR publish_at IS NULL OR publish_at >= $3) \
           AND ($4::timestamptz IS NULL OR publish_at IS NULL OR publish_at <= $4) \
         ORDER BY COALESCE(publish_at, created_at) LIMIT 200"
    )))
    .bind(tenant)
    .bind(compte)
    .bind(debut)
    .bind(fin)
    .fetch_all(pool)
    .await?;
    Ok(lignes.iter().map(ligne_file).collect())
}

/// Secondes d'attente avant le prochain essai. 30 s, 2 min, 10 min, 30 min, 2 h.
pub fn delai_reessai(tentative: i32) -> i64 {
    match tentative {
        0 | 1 => 30,
        2 => 120,
        3 => 600,
        4 => 1800,
        _ => 7200,
    }
}

// ---------------------------------------------------------------------------
// Éléments d'un fil
// ---------------------------------------------------------------------------

pub struct ElementFil {
    pub position: i32,
    pub text_body: String,
    pub digest: String,
    pub media: serde_json::Value,
    pub media_digests: Vec<String>,
    pub made_with_ai: bool,
    pub poll: Option<serde_json::Value>,
    pub status: String,
    pub platform_post_id: Option<String>,
    pub url: Option<String>,
    pub last_error: Option<String>,
}

pub async fn poser_elements(
    pool: &PgPool,
    post_id: Uuid,
    elements: &[ElementFil],
) -> sqlx::Result<()> {
    for e in elements {
        sqlx::query(
            "INSERT INTO social_thread_items \
                (post_id, position, text_body, digest, media, media_digests, made_with_ai, poll, status) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending') \
             ON CONFLICT (post_id, position) DO NOTHING",
        )
        .bind(post_id)
        .bind(e.position)
        .bind(&e.text_body)
        .bind(&e.digest)
        .bind(&e.media)
        .bind(&e.media_digests)
        .bind(e.made_with_ai)
        .bind(&e.poll)
        .execute(pool)
        .await?;
    }
    Ok(())
}

pub async fn elements(pool: &PgPool, post_id: Uuid) -> sqlx::Result<Vec<ElementFil>> {
    let lignes = sqlx::query(
        "SELECT position, text_body, digest, media, media_digests, made_with_ai, poll, \
                status, platform_post_id, url, last_error \
         FROM social_thread_items WHERE post_id = $1 ORDER BY position",
    )
    .bind(post_id)
    .fetch_all(pool)
    .await?;
    Ok(lignes
        .iter()
        .map(|l| ElementFil {
            position: l.get("position"),
            text_body: l.get("text_body"),
            digest: l.get("digest"),
            media: l.get("media"),
            media_digests: l.get("media_digests"),
            made_with_ai: l.get("made_with_ai"),
            poll: l.get("poll"),
            status: l.get("status"),
            platform_post_id: l.get("platform_post_id"),
            url: l.get("url"),
            last_error: l.get("last_error"),
        })
        .collect())
}

pub async fn marquer_element(
    pool: &PgPool,
    post_id: Uuid,
    position: i32,
    status: &str,
    platform_post_id: Option<&str>,
    url: Option<&str>,
    erreur: Option<&str>,
) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE social_thread_items \
         SET status = $3, platform_post_id = COALESCE($4, platform_post_id), \
             url = COALESCE($5, url), last_error = COALESCE($6, last_error) \
         WHERE post_id = $1 AND position = $2",
    )
    .bind(post_id)
    .bind(position)
    .bind(status)
    .bind(platform_post_id)
    .bind(url)
    .bind(erreur)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn marquer_partiel(pool: &PgPool, id: Uuid) -> sqlx::Result<()> {
    sqlx::query("UPDATE social_posts SET status = 'partial' WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Aide aux tests
// ---------------------------------------------------------------------------

/// Un pool sur SOCIAL_DATABASE_URL, migrations posees — ou None avec un SKIP
/// nomme, meme convention que `crates/store::private_db` : une ligne par
/// module, pour que le garde de scripts/test.sh sache dire qui a saute.
#[cfg(test)]
pub async fn pool_de_test(module: &str) -> Option<PgPool> {
    let Ok(url) = std::env::var("SOCIAL_DATABASE_URL") else {
        eprintln!("SKIP: SOCIAL_DATABASE_URL est absent ; les tests {module} veulent un Postgres");
        return None;
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connexion a SOCIAL_DATABASE_URL");
    crate::MIGRATIONS.run(&pool).await.expect("migrations");
    Some(pool)
}

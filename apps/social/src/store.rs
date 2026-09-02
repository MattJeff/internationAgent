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
    /// `offline.access`). C'est lui qui permet au chemin de publication de
    /// survivre à l'expiration du jeton d'accès sans re-consentement humain.
    pub sealed_refresh: Option<Vec<u8>>,
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
        "SELECT id, platform, handle, platform_user_id, sealed_token, sealed_refresh \
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
    }))
}

/// Connecte (ou reconnecte) un compte. L'upsert est ce qui permet a l'AAD de
/// porter le handle : la ligne survit a la reconnexion, le scellement aussi.
pub async fn connecter_compte(
    pool: &PgPool,
    tenant: Uuid,
    platform: &str,
    handle: &str,
    platform_user_id: Option<&str>,
    sealed_token: &[u8],
    sealed_refresh: Option<&[u8]>,
) -> sqlx::Result<Uuid> {
    let ligne = sqlx::query(
        // COALESCE sur platform_user_id : une reconnexion qui ne le porterait
        // pas n'efface jamais un id deja connu — le meme argument que le
        // refresh token dans resceller_jetons.
        "INSERT INTO social_accounts \
             (id, tenant_id, platform, handle, platform_user_id, sealed_token, sealed_refresh) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (tenant_id, platform, handle) \
         DO UPDATE SET sealed_token = EXCLUDED.sealed_token, \
                       sealed_refresh = EXCLUDED.sealed_refresh, \
                       platform_user_id = COALESCE(EXCLUDED.platform_user_id, \
                                                   social_accounts.platform_user_id), \
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
) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE social_accounts \
         SET sealed_token = $3, sealed_refresh = COALESCE($4, sealed_refresh) \
         WHERE id = $1 AND tenant_id = $2",
    )
    .bind(compte)
    .bind(tenant)
    .bind(sealed_token)
    .bind(sealed_refresh)
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
        // Un echec anterieur se re-reclame — mais par UPDATE conditionnel,
        // pour qu'un seul des retenteurs concurrents gagne.
        "failed" => {
            let repris = sqlx::query(
                "UPDATE social_posts SET status = 'pending' \
                 WHERE id = $1 AND status = 'failed' RETURNING id",
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

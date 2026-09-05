//! Les tenants et leurs jetons.
//!
//! Un jeton se frappe UNE fois, par la CLI (`agentos-social mint-tenant`), et
//! seul son SHA-256 vit en base. Pas de route pour en frapper : une route de
//! frappe serait une route qu'un agent peut appeler, et le perimetre d'un
//! agent est exactement les six outils de mcp.rs.

use sha2::{Digest, Sha256};
use sqlx::PgPool;
use sqlx::Row;
use uuid::Uuid;

/// Comparaison sans sortie anticipee — meme concession que
/// `apps/server/src/auth.rs::ct_eq` : la longueur a le droit de fuir, elle
/// n'est pas le secret (et ici les deux cotes sont des SHA-256 de 32 octets).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Frappe un tenant et rend le jeton EN CLAIR — c'est le seul moment ou il
/// existe hors de la memoire de l'appelant. 32 octets d'alea, pas une chaine
/// que quelqu'un a tapee.
pub async fn frapper(pool: &PgPool, label: &str) -> anyhow::Result<String> {
    use rand::RngCore;
    let mut brut = [0u8; 32];
    rand::rng().fill_bytes(&mut brut);
    let jeton = format!("soc_{}", hex(&brut));
    let hachage = Sha256::digest(jeton.as_bytes());

    sqlx::query("INSERT INTO social_tenants (id, label, token_hash) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(label)
        .bind(hachage.as_slice())
        .execute(pool)
        .await?;
    Ok(jeton)
}

/// Resout un en-tete `Authorization` vers un tenant, ou rien.
///
/// On hache ce que le client presente puis on balaye TOUTES les lignes en
/// comparant en temps constant. Pas de `WHERE token_hash = $1` : l'index
/// deciderait du temps de reponse, et c'est precisement ce qu'on refuse.
/// ponytail: balayage lineaire — des dizaines de tenants, pas des millions ;
/// si un jour ils sont des millions, hacher cote client avec un sel par ligne.
pub async fn authentifier(pool: &PgPool, autorisation: Option<&str>) -> Option<Uuid> {
    let jeton = autorisation?.strip_prefix("Bearer ")?;
    let presente = Sha256::digest(jeton.as_bytes());

    let lignes = sqlx::query("SELECT id, token_hash FROM social_tenants")
        .fetch_all(pool)
        .await
        .ok()?;
    lignes
        .iter()
        .find(|l| ct_eq(&l.get::<Vec<u8>, _>("token_hash"), &presente))
        .map(|l| l.get("id"))
}

fn hex(octets: &[u8]) -> String {
    octets.iter().map(|o| format!("{o:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_compare_ce_qu_il_pretend() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(ct_eq(b"", b""));
    }

    #[tokio::test]
    async fn un_jeton_frappe_ouvre_et_un_faux_ne_donne_rien() {
        let Some(pool) = crate::store::pool_de_test("tenants").await else {
            return;
        };
        let jeton = frapper(&pool, &format!("t-{}", Uuid::now_v7()))
            .await
            .unwrap();

        // Le bon jeton resout ; le meme jeton avec un octet change ne resout
        // pas ; un en-tete sans schema Bearer non plus.
        assert!(
            authentifier(&pool, Some(&format!("Bearer {jeton}")))
                .await
                .is_some()
        );
        let mut faux = jeton.clone();
        faux.pop();
        faux.push('0');
        // Si le dernier octet etait deja '0', on en change un autre.
        let faux = if faux == jeton {
            format!("Bearer soc_{}", "0".repeat(64))
        } else {
            format!("Bearer {faux}")
        };
        assert!(authentifier(&pool, Some(&faux)).await.is_none());
        assert!(
            authentifier(&pool, Some(&jeton)).await.is_none(),
            "sans 'Bearer ' rien ne passe"
        );
        assert!(authentifier(&pool, None).await.is_none());
    }
}

//! Le profil de navigation d'un employé : sa langue, son fuseau, son écran.
//!
//! L'autre moitié de [`BrowserProfiles`], comme [`crate::cookie_jar`] est
//! l'autre moitié de `CookieJar` : le fournisseur tient un identifiant de
//! contexte (`provider = 'chrome'`, `external_id = ctx-<tag>`) et rien
//! d'autre ; c'est ici qu'on retrouve la ligne, donc l'employé, donc ce que
//! sa fiche dit de lui.
//!
//! # Pourquoi `employees.spec` et pas une table
//!
//! `spec` est déjà la colonne jsonb où vit ce qui décrit un employé sans
//! avoir de colonne — `store::employee::spec_of` y écrit son domaine, et rien
//! d'autre à ce jour. Un profil de navigation est exactement ça : quatre
//! valeurs, lues à l'ouverture d'un onglet, jamais indexées, jamais jointes,
//! jamais agrégées. Une table pour ça serait une migration, une ligne par
//! employé à créer, une deuxième à supprimer au `release`, et un `LEFT JOIN`
//! dont la branche vide est le défaut qu'on aurait de toute façon écrit. Donc
//! pas de migration : `spec->'browser'`, absent la plupart du temps, et le
//! défaut quand il l'est.
//!
//! # Le défaut n'est pas neutre, et c'est le point
//!
//! `fr-FR / Europe/Paris / 1366×768 / desktop / sans position`. Un Chromium
//! sans tête non configuré annonce `en-US` et `UTC` : mesuré le 2026-09-10,
//! `Intl.DateTimeFormat().resolvedOptions().timeZone` répond `UTC` sur la
//! machine de développement dont l'horloge est à Paris. Un employé qui écrit
//! en français à des prospects français depuis un navigateur américain dans
//! un fuseau que personne n'habite, c'est une incohérence qu'un site lit en
//! une ligne — et c'est une incohérence *gratuite*.
//!
//! Ce que ce module ne fait pas : il ne devine rien. Pas de fuseau déduit du
//! domaine du prospect, pas de langue déduite du texte du tour. Le profil est
//! ce que la fiche dit, ou le défaut ; deux sources et pas trois.

use agentos_providers::ProviderError;
use agentos_providers::browser_chrome::{BrowserProfile, BrowserProfiles};
use agentos_store::db::Db;
use async_trait::async_trait;
use serde_json::Value;

/// Seules les lignes `chrome` portent un contexte de ce module.
const PROVIDER: &str = agentos_providers::browser_chrome::PROVIDER;

/// Le profil, lu sur la fiche de l'employé.
pub struct SpecBrowserProfiles {
    db: Db,
}

impl SpecBrowserProfiles {
    /// Un par déploiement.
    pub const fn new(db: Db) -> Self {
        Self { db }
    }
}

#[async_trait]
impl BrowserProfiles for SpecBrowserProfiles {
    async fn profile_for(&self, ctx: &str) -> Result<BrowserProfile, ProviderError> {
        // `admin_tx_bypassing_rls` pour l'argument de la migration 0095 et de
        // `cookie_jar` : la recherche précède le locataire. Rien de secret ne
        // sort d'ici — une langue et un fuseau ne sont pas une donnée du
        // locataire au sens de la RLS — et l'identifiant de contexte est déjà
        // celui que l'appelant tient.
        let mut tx = self
            .db
            .admin_tx_bypassing_rls()
            .await
            .map_err(|_| ProviderError::timeout())?;
        let row = sqlx::query_scalar::<_, Option<Value>>(
            "SELECT e.spec -> 'browser' FROM employee_resources r \
               JOIN employees e ON e.id = r.employee_id \
              WHERE r.provider = $1 AND r.external_id = $2",
        )
        .bind(PROVIDER)
        .bind(ctx)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ProviderError::timeout())?;
        let _ = tx.rollback().await;
        Ok(profile_from(row.flatten().as_ref()))
    }
}

/// `spec->'browser'` rendu en profil, champ par champ, chacun retombant sur le
/// défaut tout seul.
///
/// **Un champ illisible ne fait pas échouer le profil.** La fiche est écrite
/// par un opérateur ou par une route, pas par un compilateur : un
/// `"viewport": "grand"` doit donner un employé au viewport par défaut, pas un
/// onglet qui refuse de s'ouvrir. Le port dit la même chose de son côté —
/// `BrowserProfiles::profile_for` en erreur, c'est le défaut chez
/// l'adaptateur — donc la sévérité serait de toute façon perdue en chemin.
fn profile_from(spec: Option<&Value>) -> BrowserProfile {
    let default = BrowserProfile::default();
    let Some(spec) = spec else { return default };
    BrowserProfile {
        locale: spec["locale"]
            .as_str()
            .map_or(default.locale, str::to_owned),
        timezone: spec["timezone"]
            .as_str()
            .map_or(default.timezone, str::to_owned),
        viewport: {
            let viewport = &spec["viewport"];
            let width = viewport["w"].as_u64();
            let height = viewport["h"].as_u64();
            match (width, height) {
                // Les deux ou aucune : une largeur sans hauteur est une fiche
                // à moitié écrite, et 1366×768 est une paire, pas deux
                // nombres qui se trouvent voisins.
                (Some(w), Some(h)) if w > 0 && h > 0 => (
                    u32::try_from(w).unwrap_or(default.viewport.0),
                    u32::try_from(h).unwrap_or(default.viewport.1),
                    viewport["mobile"].as_bool().unwrap_or(false),
                ),
                _ => default.viewport,
            }
        },
        geolocation: {
            let position = &spec["geolocation"];
            match (position[0].as_f64(), position[1].as_f64()) {
                (Some(latitude), Some(longitude))
                    if (-90.0..=90.0).contains(&latitude)
                        && (-180.0..=180.0).contains(&longitude) =>
                {
                    Some((latitude, longitude))
                }
                // Y compris pour une position hors du globe : `null` veut dire
                // « position indisponible », qui est une réponse honnête, là
                // où une latitude de 200 n'en est aucune.
                _ => None,
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn no_spec_is_a_french_desktop_that_says_it_is_nowhere() {
        let profile = profile_from(None);
        assert_eq!(profile.locale, "fr-FR");
        assert_eq!(profile.timezone, "Europe/Paris");
        assert_eq!(profile.viewport, (1366, 768, false));
        assert_eq!(profile.geolocation, None);
    }

    #[test]
    fn a_spec_is_read_field_by_field() {
        let profile = profile_from(Some(&json!({
            "locale": "de-DE",
            "timezone": "Europe/Berlin",
            "viewport": { "w": 390, "h": 844, "mobile": true },
            "geolocation": [52.52, 13.405],
        })));
        assert_eq!(profile.locale, "de-DE");
        assert_eq!(profile.timezone, "Europe/Berlin");
        assert_eq!(profile.viewport, (390, 844, true));
        assert_eq!(profile.geolocation, Some((52.52, 13.405)));
    }

    /// La garde : ce qui ne se lit pas retombe sur le défaut sans emporter le
    /// reste de la fiche avec lui.
    #[test]
    fn a_field_that_does_not_parse_is_the_default_and_nothing_more() {
        let profile = profile_from(Some(&json!({
            "locale": "it-IT",
            "viewport": "grand",
            "geolocation": [200.0, 13.0],
        })));
        assert_eq!(profile.locale, "it-IT", "le champ lisible a survécu");
        assert_eq!(profile.viewport, (1366, 768, false));
        assert_eq!(profile.geolocation, None, "200° de latitude n'existe pas");
        // Désarmée : une position dans le globe passe, donc le refus au-dessus
        // est bien le contrôle et pas le chemin par défaut.
        let profile = profile_from(Some(&json!({ "geolocation": [48.85, 2.35] })));
        assert_eq!(profile.geolocation, Some((48.85, 2.35)));
    }
}

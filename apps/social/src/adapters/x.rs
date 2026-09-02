//! X, texte seul.
//!
//! Tout ce qui suit vient de la doc officielle, relevée le 2026-09-02 :
//!
//! * Création : `POST https://api.x.com/2/tweets`, corps `{"text": "..."}`,
//!   contexte utilisateur OAuth 2.0, scope `tweet.write` —
//!   <https://docs.x.com/x-api/posts/creation-of-a-post>. Réponse :
//!   `{"data": {"id": "...", "text": "..."}}`.
//! * Lecture : `GET https://api.x.com/2/tweets/{id}` avec
//!   `post.fields=public_metrics` (le paramètre s'appelle bien `post.fields`
//!   dans l'OpenAPI servi par la doc), scope `tweet.read` ou `users.read` —
//!   <https://docs.x.com/x-api/posts/get-post-by-id>. `public_metrics` porte
//!   `impression_count`, `like_count`, `repost_count`, `reply_count`,
//!   `quote_count`, `bookmark_count`.
//! * Tarif : « Post: Create $0.015 per request », « Post: Create (with URL)
//!   $0.200 per request » — <https://docs.x.com/x-api/getting-started/pricing.md>.
//!   Un lien dans le texte multiplie le prix par treize : l'estimation doit le
//!   dire AVANT qu'un humain contresigne, c'est toute la raison du champ.
//! * Longueur : 280 pondérés ; toute URL compte 23 ; émojis et CJC comptent 2 ;
//!   « Latin, punctuation, common symbols » comptent 1 —
//!   <https://docs.x.com/resources/fundamentals/counting-characters>.

use agentos_providers::Secret;
use async_trait::async_trait;
use serde_json::json;

use super::{Apercu, ErreurPlateforme, Metriques, Plateforme, Publication, empreinte, http};

/// <https://docs.x.com/x-api/posts/creation-of-a-post>, relevé le 2026-09-02.
pub const POINT_PUBLICATION: &str = "https://api.x.com/2/tweets";
/// <https://docs.x.com/x-api/posts/get-post-by-id>, relevé le 2026-09-02. L'id
/// se concatène, le paramètre `post.fields=public_metrics` s'ajoute en query.
pub const POINT_LECTURE: &str = "https://api.x.com/2/tweets/";

/// « Post: Create $0.015 per request » / « Post: Create (with URL) $0.200 » —
/// <https://docs.x.com/x-api/getting-started/pricing.md>, relevé le 2026-09-02.
pub const COUT_PAR_POST_USD: f64 = 0.015;
pub const COUT_PAR_POST_AVEC_URL_USD: f64 = 0.200;

/// 280 pondérés — <https://docs.x.com/resources/fundamentals/counting-characters>.
pub const LIMITE_PONDEREE: usize = 280;

/// Le poids d'un texte selon les règles citées en tête de module.
///
/// ponytail: approximation de twitter-text — poids 1 jusqu'à U+10FF (latin,
/// grec, cyrillique, ponctuation ASCII), 2 au-delà (émojis, CJC), URL = 23.
/// Elle SURcompte la ponctuation typographique (U+2013, U+2019… que X compte
/// pour 1), donc elle ne peut que refuser un texte passable près de la borne,
/// jamais laisser passer un refusable. Le jour où un tenant bute dessus :
/// reprendre les plages exactes de twitter-text v3.
pub fn poids(texte: &str) -> usize {
    let blancs = texte.chars().filter(|c| c.is_whitespace()).count();
    texte
        .split(char::is_whitespace)
        .map(|morceau| {
            if contient_url(morceau) {
                23
            } else {
                morceau
                    .chars()
                    .map(|c| if (c as u32) <= 0x10FF { 1 } else { 2 })
                    .sum()
            }
        })
        .sum::<usize>()
        + blancs
}

/// Ce qui fait basculer le tarif de 0,015 à 0,200 USD.
fn contient_url(morceau: &str) -> bool {
    morceau.starts_with("https://") || morceau.starts_with("http://")
}

/// Le corps exact de `POST /2/tweets` pour un post texte — comparé à une
/// fixture de la doc dans les tests, jamais construit ailleurs.
pub fn corps_de_publication(texte: &str) -> serde_json::Value {
    json!({ "text": texte })
}

/// Lit la réponse de création. Un refus devient une [`ErreurPlateforme`]
/// nommée et jamais une [`Publication`] ; le corps n'entre pas dans l'erreur
/// (il écho la requête, et l'erreur finit dans des logs).
pub fn publication_depuis(
    statut: u16,
    corps: &[u8],
    handle: &str,
) -> Result<Publication, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    let id = document
        .pointer("/data/id")
        .and_then(|v| v.as_str())
        .ok_or(ErreurPlateforme::Illisible)?;
    Ok(Publication {
        id_plateforme: id.to_owned(),
        // Le format public `x.com/<handle>/status/<id>` : construit depuis le
        // handle du compte connecté, pas depuis la réponse (elle n'en porte pas).
        url: format!("https://x.com/{handle}/status/{id}"),
    })
}

/// Lit `GET /2/tweets/{id}?post.fields=public_metrics`.
pub fn metriques_depuis(statut: u16, corps: &[u8]) -> Result<Metriques, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    let publiques = document
        .pointer("/data/public_metrics")
        .ok_or(ErreurPlateforme::Illisible)?;
    let compte = |nom: &str| publiques.get(nom).and_then(|v| v.as_u64());
    Ok(Metriques {
        impressions: compte("impression_count"),
        likes: compte("like_count").unwrap_or(0),
        reposts: compte("repost_count").unwrap_or(0),
        replies: compte("reply_count").unwrap_or(0),
    })
}

/// L'adaptateur lui-même : l'assemblage des fonctions pures ci-dessus et d'un
/// client HTTP, rien d'autre — c'est ce qui rend le reste testable hors ligne.
pub struct X;

#[async_trait]
impl Plateforme for X {
    fn nom(&self) -> &'static str {
        "x"
    }

    fn apercu(&self, texte: &str) -> Apercu {
        let avec_url = texte.split(char::is_whitespace).any(contient_url);
        Apercu {
            rendered_text: texte.to_owned(),
            digest: empreinte(texte),
            platform_limits_ok: !texte.trim().is_empty() && poids(texte) <= LIMITE_PONDEREE,
            cost_estimate_usd: Some(if avec_url {
                COUT_PAR_POST_AVEC_URL_USD
            } else {
                COUT_PAR_POST_USD
            }),
        }
    }

    async fn publier(
        &self,
        jeton: &Secret,
        handle: &str,
        texte: &str,
    ) -> Result<Publication, ErreurPlateforme> {
        let reponse = http()
            .post(POINT_PUBLICATION)
            .bearer_auth(jeton.expose_for_transport())
            .json(&corps_de_publication(texte))
            .send()
            .await
            .map_err(|_| ErreurPlateforme::Injoignable)?;
        let statut = reponse.status().as_u16();
        let corps = reponse
            .bytes()
            .await
            .map_err(|_| ErreurPlateforme::Injoignable)?;
        publication_depuis(statut, &corps, handle)
    }

    async fn metriques(
        &self,
        jeton: &Secret,
        id_plateforme: &str,
    ) -> Result<Option<Metriques>, ErreurPlateforme> {
        let reponse = http()
            .get(format!("{POINT_LECTURE}{id_plateforme}"))
            .query(&[("post.fields", "public_metrics")])
            .bearer_auth(jeton.expose_for_transport())
            .send()
            .await
            .map_err(|_| ErreurPlateforme::Injoignable)?;
        let statut = reponse.status().as_u16();
        let corps = reponse
            .bytes()
            .await
            .map_err(|_| ErreurPlateforme::Injoignable)?;
        metriques_depuis(statut, &corps).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La forme documentée : `{"text": "Your post content here"}` —
    /// docs.x.com/x-api/posts/creation-of-a-post, relevé le 2026-09-02.
    #[test]
    fn le_corps_est_celui_de_la_doc() {
        assert_eq!(
            corps_de_publication("Hello world"),
            json!({ "text": "Hello world" })
        );
    }

    #[test]
    fn un_refus_ne_devient_jamais_une_publication_et_ne_porte_pas_le_jeton() {
        // Un point qui échoue écho volontiers la requête — y compris son
        // Authorization. Si ce corps hostile traversait vers l'erreur, le
        // jeton finirait dans un log.
        let corps_hostile = br#"{"errors":[{"detail":"Bearer JETON-SECRET refuse"}]}"#;
        for statut in [400, 401, 403, 429, 500] {
            let erreur = publication_depuis(statut, corps_hostile, "orizn")
                .expect_err("un non-2xx n'est pas un post");
            let rendu = format!("{erreur} / {erreur:?}");
            assert!(!rendu.contains("JETON-SECRET"), "le jeton a fui: {rendu}");
        }
    }

    #[test]
    fn une_reponse_de_creation_se_lit_comme_la_doc_le_montre() {
        let corps = br#"{"data":{"id":"1234567890","text":"Hello world","edit_history_post_ids":["1234567890"]}}"#;
        let publication = publication_depuis(201, corps, "orizn").expect("201 documenté");
        assert_eq!(publication.id_plateforme, "1234567890");
        assert_eq!(publication.url, "https://x.com/orizn/status/1234567890");
        // Un 2xx au corps difforme est illisible, pas un post à moitié.
        assert_eq!(
            publication_depuis(201, b"{}", "orizn"),
            Err(ErreurPlateforme::Illisible)
        );
    }

    /// Chaque règle de comptage citée a un cas qui échouerait si elle cassait.
    #[test]
    fn le_poids_suit_les_regles_citees() {
        // 280 latins passent, 281 non.
        assert_eq!(poids(&"a".repeat(280)), 280);
        assert!(X.apercu(&"a".repeat(280)).platform_limits_ok);
        assert!(!X.apercu(&"a".repeat(281)).platform_limits_ok);
        // « All URLs count as exactly 23 characters ».
        assert_eq!(poids("https://exemple.example/un/chemin/vraiment/long"), 23);
        // « emojis count as 2 » : 140 passent, 141 débordent.
        assert!(X.apercu(&"🦀".repeat(140)).platform_limits_ok);
        assert!(!X.apercu(&"🦀".repeat(141)).platform_limits_ok);
        // Les blancs comptent aussi.
        assert_eq!(poids("a b"), 3);
        // Un texte vide ne part pas.
        assert!(!X.apercu("   ").platform_limits_ok);
    }

    /// « Post: Create (with URL) $0.200 » contre « Post: Create $0.015 » — le
    /// facteur treize doit être visible dans l'aperçu contresigné.
    #[test]
    fn le_cout_distingue_un_post_avec_lien() {
        assert_eq!(X.apercu("bonjour").cost_estimate_usd, Some(0.015));
        assert_eq!(
            X.apercu("bonjour https://orizn.example").cost_estimate_usd,
            Some(0.200)
        );
    }

    #[test]
    fn l_apercu_rend_le_texte_exact_et_son_empreinte() {
        let apercu = X.apercu("Texte à publier");
        assert_eq!(apercu.rendered_text, "Texte à publier");
        assert_eq!(apercu.digest, empreinte("Texte à publier"));
    }

    #[test]
    fn les_metriques_publiques_se_lisent_champ_par_champ() {
        let corps = br#"{"data":{"id":"1","public_metrics":{"impression_count":42,"like_count":3,"repost_count":2,"reply_count":1,"quote_count":0,"bookmark_count":0}}}"#;
        let metriques = metriques_depuis(200, corps).expect("forme documentée");
        assert_eq!(metriques.impressions, Some(42));
        assert_eq!(metriques.likes, 3);
        assert_eq!(metriques.reposts, 2);
        assert_eq!(metriques.replies, 1);
        assert_eq!(
            metriques_depuis(404, corps),
            Err(ErreurPlateforme::Refus { statut: 404 })
        );
    }

    #[test]
    fn les_points_d_api_sont_en_https() {
        for point in [POINT_PUBLICATION, POINT_LECTURE] {
            assert!(point.starts_with("https://"), "{point}");
        }
    }
}

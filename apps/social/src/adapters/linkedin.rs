//! LinkedIn, publication texte sur le profil du membre.
//!
//! Tout vient de Microsoft Learn, relevé le 2026-09-02 :
//!
//! * Création : `POST https://api.linkedin.com/rest/posts`, en-têtes
//!   `Linkedin-Version: {YYYYMM}` et `X-Restli-Protocol-Version: 2.0.0`
//!   obligatoires sur toutes les APIs ; permission `w_member_social` (« Post,
//!   comment, and like posts on behalf of an authenticated member ») —
//!   <https://learn.microsoft.com/en-us/linkedin/marketing/community-management/shares/posts-api>.
//! * Réponse : `201` et l'en-tête `x-restli-id` porte l'URN du post
//!   (`urn:li:share:…` ou `urn:li:ugcPost:…`) ; un post publié se regarde à
//!   `https://www.linkedin.com/feed/update/<urn>/` (même page, section « Create
//!   Dark Posts »).
//! * Auteur membre : `urn:li:person:{id}` —
//!   <https://learn.microsoft.com/en-us/linkedin/marketing/community-management/shares/post-api-schema>.
//! * Version courante : le moniker par défaut de la doc est `li-lms-2026-08`,
//!   d'où `202608` ; la même page avertit que 202508 est éteinte le 2026-08-17.

use agentos_providers::Secret;
use async_trait::async_trait;
use serde_json::json;

use super::{Apercu, ErreurPlateforme, Metriques, Plateforme, Publication, empreinte, http};

/// <https://learn.microsoft.com/en-us/linkedin/marketing/community-management/shares/posts-api>,
/// relevé le 2026-09-02.
pub const POINT_PUBLICATION: &str = "https://api.linkedin.com/rest/posts";

/// Le moniker par défaut de la doc au 2026-09-02 (`li-lms-2026-08`). Une
/// constante et pas une chaîne en ligne : quand LinkedIn éteindra cette
/// version, il y aura UN endroit à bumper, et le test d'en-têtes à mettre à jour
/// avec lui.
pub const VERSION_LINKEDIN: &str = "202608";

/// « All APIs require the request header `X-Restli-Protocol-Version: 2.0.0` ».
pub const PROTOCOLE_RESTLI: &str = "2.0.0";

/// Les deux en-têtes versionnés, sortis en fonction pour que le test compare
/// exactement ce que `publier` enverra — pas une copie qui divergerait.
pub fn entetes_versionnees() -> [(&'static str, &'static str); 2] {
    [
        ("LinkedIn-Version", VERSION_LINKEDIN),
        ("X-Restli-Protocol-Version", PROTOCOLE_RESTLI),
    ]
}

/// Le corps exact d'un post texte de membre — la fixture « Text-Only Post
/// Creation Sample Request » de la doc, l'auteur organisation remplacé par
/// l'URN de personne que `w_member_social` autorise.
pub fn corps_de_publication(auteur: &str, texte: &str) -> serde_json::Value {
    json!({
        "author": auteur,
        "commentary": texte,
        "visibility": "PUBLIC",
        "distribution": {
            "feedDistribution": "MAIN_FEED",
            "targetEntities": [],
            "thirdPartyDistributionChannels": []
        },
        "lifecycleState": "PUBLISHED",
        "isReshareDisabledByAuthor": false
    })
}

/// Lit la réponse de création : le post est dans l'en-tête `x-restli-id`, pas
/// dans le corps. Un refus est une erreur nommée, jamais une [`Publication`].
pub fn publication_depuis(
    statut: u16,
    restli_id: Option<&str>,
) -> Result<Publication, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let urn = restli_id.ok_or(ErreurPlateforme::Illisible)?;
    Ok(Publication {
        id_plateforme: urn.to_owned(),
        // « an authorized member can view the post using the follow URL
        // structure: https://www.linkedin.com/feed/update/urn:li:ugcPost:<id>/ »
        url: format!("https://www.linkedin.com/feed/update/{urn}/"),
    })
}

pub struct Linkedin;

#[async_trait]
impl Plateforme for Linkedin {
    fn nom(&self) -> &'static str {
        "linkedin"
    }

    fn apercu(&self, texte: &str) -> Apercu {
        Apercu {
            rendered_text: texte.to_owned(),
            digest: empreinte(texte),
            // La doc nomme les refus `INVALID_VALUE_BLANK_FIELD` et
            // `FIELD_LENGTH_TOO_LONG` mais ne publie AUCUN nombre pour
            // `commentary` (vérifié dans posts-api et post-api-schema le
            // 2026-09-02). On vérifie donc ce qui est documenté — pas vide —
            // et rien d'inventé : une limite chiffrée sortie de nulle part
            // serait un mensonge de précision.
            platform_limits_ok: !texte.trim().is_empty(),
            // LinkedIn ne facture pas la création d'un post : `None`, pas 0.0 —
            // zéro affirmerait un tarif, None dit qu'il n'y a pas de compteur.
            cost_estimate_usd: None,
        }
    }

    /// `handle` EST l'URN d'auteur (`urn:li:person:{id}`) : le flux de
    /// connexion range l'identité que `GET /v2/userinfo` a rendue — c'est la
    /// seule que `w_member_social` connaisse, et c'est exactement le champ
    /// `author` que le schéma exige (post-api-schema, relevé le 2026-09-02).
    async fn publier(
        &self,
        jeton: &Secret,
        handle: &str,
        texte: &str,
    ) -> Result<Publication, ErreurPlateforme> {
        let mut requete = http()
            .post(POINT_PUBLICATION)
            .bearer_auth(jeton.expose_for_transport());
        for (nom, valeur) in entetes_versionnees() {
            requete = requete.header(nom, valeur);
        }
        let reponse = requete
            .json(&corps_de_publication(handle, texte))
            .send()
            .await
            .map_err(|_| ErreurPlateforme::Injoignable)?;
        let statut = reponse.status().as_u16();
        let restli_id = reponse
            .headers()
            .get("x-restli-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        publication_depuis(statut, restli_id.as_deref())
    }

    /// `Ok(None)`, et c'est un fait documenté, pas une paresse : lire les posts
    /// d'un membre demande `r_member_social`, que la doc marque « restricted…
    /// available to approved users only » (table Permissions de posts-api,
    /// relevé le 2026-09-02) — la sonde du 2026-09-02 l'avait établi. Rendre
    /// des zéros à la place serait un mensonge de plus que ne rien rendre :
    /// un agent lirait « 0 impressions » et conclurait que le post est mort,
    /// alors que la vérité est « personne n'a le droit de compter ».
    async fn metriques(
        &self,
        _jeton: &Secret,
        _id_plateforme: &str,
    ) -> Result<Option<Metriques>, ErreurPlateforme> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Champ pour champ, la fixture « Text-Only Post Creation Sample Request »
    /// de la doc (posts-api, relevé le 2026-09-02), auteur membre.
    #[test]
    fn le_corps_est_celui_de_la_doc() {
        assert_eq!(
            corps_de_publication("urn:li:person:5abc_dEfgH", "Sample text Post"),
            json!({
                "author": "urn:li:person:5abc_dEfgH",
                "commentary": "Sample text Post",
                "visibility": "PUBLIC",
                "distribution": {
                    "feedDistribution": "MAIN_FEED",
                    "targetEntities": [],
                    "thirdPartyDistributionChannels": []
                },
                "lifecycleState": "PUBLISHED",
                "isReshareDisabledByAuthor": false
            })
        );
    }

    #[test]
    fn les_entetes_portent_la_version_et_le_protocole() {
        assert_eq!(
            entetes_versionnees(),
            [
                ("LinkedIn-Version", "202608"),
                ("X-Restli-Protocol-Version", "2.0.0"),
            ]
        );
    }

    #[test]
    fn un_refus_ne_devient_jamais_une_publication() {
        for statut in [400, 401, 403, 422, 429, 503] {
            publication_depuis(statut, Some("urn:li:share:1"))
                .expect_err("un non-2xx n'est pas un post");
        }
        // Un 201 sans `x-restli-id` n'est pas un post identifiable non plus.
        assert_eq!(
            publication_depuis(201, None),
            Err(ErreurPlateforme::Illisible)
        );
    }

    #[test]
    fn une_creation_reussie_rend_l_urn_et_son_url_publique() {
        let publication = publication_depuis(201, Some("urn:li:share:6844785523593134080"))
            .expect("201 documenté");
        assert_eq!(
            publication.id_plateforme,
            "urn:li:share:6844785523593134080"
        );
        assert_eq!(
            publication.url,
            "https://www.linkedin.com/feed/update/urn:li:share:6844785523593134080/"
        );
    }

    #[tokio::test]
    async fn les_metriques_membre_disent_pas_de_donnees_au_lieu_de_zeros() {
        let resultat = Linkedin
            .metriques(&Secret::new("jeton"), "urn:li:share:1")
            .await
            .expect("l'absence de métriques n'est pas une panne");
        assert!(resultat.is_none(), "des zéros inventés sont un mensonge");
    }

    #[test]
    fn l_apercu_refuse_le_vide_et_n_invente_pas_de_tarif() {
        assert!(!Linkedin.apercu("  ").platform_limits_ok);
        let apercu = Linkedin.apercu("Bonjour");
        assert!(apercu.platform_limits_ok);
        assert_eq!(apercu.cost_estimate_usd, None);
        assert_eq!(apercu.rendered_text, "Bonjour");
        assert_eq!(apercu.digest, empreinte("Bonjour"));
    }

    #[test]
    fn le_point_d_api_est_en_https() {
        assert!(POINT_PUBLICATION.starts_with("https://"));
    }
}

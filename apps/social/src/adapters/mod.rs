//! Les deux plateformes du jour un, derrière un seul trait.
//!
//! Chaque adaptateur sépare ce qui se teste sans réseau (construire un corps
//! de requête, lire une réponse) de ce qui envoie (une fonction `async` courte
//! qui ne fait qu'assembler les deux). Les tests comparent les corps à des
//! fixtures tirées des docs officielles, citées sur place — c'est la règle de
//! la maison : rien d'inventé.

use std::sync::OnceLock;
use std::time::Duration;

use agentos_providers::Secret;
use async_trait::async_trait;
use sha2::{Digest, Sha256};

pub mod linkedin;
pub mod x;

/// LA définition du trait — l'unique. Le cœur (mcp.rs) en avait posé une
/// voisine pendant l'écriture parallèle des deux lots ; la couture est fermée
/// en gardant celle-ci, parce qu'elle seule porte ce que les vraies
/// plateformes exigent : le jeton reste un `Secret` jusqu'au `bearer_auth`,
/// et le `handle` du compte voyage jusqu'à l'adaptateur (URL publique chez X,
/// URN d'auteur chez LinkedIn).
#[async_trait]
pub trait Plateforme: Send + Sync {
    /// Le nom tel qu'il sort dans `accounts_list` : "x" ou "linkedin".
    fn nom(&self) -> &'static str;

    /// Le rendu EXACT qui partirait, son empreinte, et ce qu'il coûterait.
    ///
    /// Pur et sans réseau : c'est ce qu'une approbation humaine contresigne,
    /// donc il doit être calculable — et testable — sans toucher la plateforme.
    fn apercu(&self, texte: &str) -> Apercu;

    /// Publie `texte` pour le compte `handle`. Ne retente rien : l'idempotence
    /// vit dans la base (clé unique sur `idempotency_key`), pas ici.
    ///
    /// `handle` est la colonne `social_accounts.handle` : le nom d'écran chez
    /// X (il construit l'URL publique), l'URN `urn:li:person:{id}` chez
    /// LinkedIn (il est l'auteur du corps de requête) — c'est ce que le flux
    /// de connexion (oauth_flux::identite) a rangé là.
    async fn publier(
        &self,
        jeton: &Secret,
        handle: &str,
        texte: &str,
    ) -> Result<Publication, ErreurPlateforme>;

    /// `Ok(None)` quand la plateforme ne sert pas de métriques pour ce type de
    /// compte — dire « pas de données » au lieu de rendre des zéros qui
    /// ressembleraient à un post ignoré.
    async fn metriques(
        &self,
        jeton: &Secret,
        id_plateforme: &str,
    ) -> Result<Option<Metriques>, ErreurPlateforme>;
}

/// Les deux plateformes du jour un, et pas une de plus. C'est ce que
/// `mcp::Etat` embarque ; les tests du cœur y substituent leur adaptateur
/// compteur.
pub fn adaptateurs() -> Vec<Box<dyn Plateforme>> {
    vec![Box::new(x::X), Box::new(linkedin::Linkedin)]
}

/// Ce que `post_preview` rend, et que `post_publish` doit reproduire à l'octet.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Apercu {
    /// Le texte exact qui partirait. Texte seul au jour un : aucun adaptateur
    /// ne réécrit rien, donc `rendered_text == texte` — et le test le fige,
    /// parce que le jour où un adaptateur « améliore » le texte, l'empreinte
    /// contresignée ne couvre plus ce qui part.
    pub rendered_text: String,
    /// SHA-256 du rendu, en hexadécimal. C'est elle qu'une approbation signe.
    pub digest: String,
    /// Faux si la plateforme refusera (limite de longueur, texte vide).
    pub platform_limits_ok: bool,
    /// En USD, `None` quand la plateforme ne facture pas l'écriture.
    pub cost_estimate_usd: Option<f64>,
}

/// Un post accepté par la plateforme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publication {
    /// L'identifiant côté plateforme (id numérique chez X, URN chez LinkedIn).
    pub id_plateforme: String,
    /// L'URL publique du post.
    pub url: String,
}

/// Ce que `post_metrics` rend quand la plateforme sert des chiffres.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Metriques {
    pub impressions: Option<u64>,
    pub likes: u64,
    pub reposts: u64,
    pub replies: u64,
}

/// Le refus d'une plateforme, nommé — et JAMAIS un post enregistré.
///
/// Aucune variante ne porte un octet venu du corps de réponse : un point de
/// jeton qui échoue en écho de la requête ne peut donc pas faire transiter le
/// jeton dans un log via ce type. C'est la même discipline que
/// `the_api_key_never_appears_in_debug_or_error_output` côté runtime, obtenue
/// par construction plutôt que par relecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ErreurPlateforme {
    /// La plateforme a répondu, et la réponse était non.
    #[error("la plateforme a refusé (statut {statut})")]
    Refus { statut: u16 },
    /// Pas de réponse exploitable : réseau, timeout, 5xx.
    #[error("plateforme injoignable")]
    Injoignable,
    /// Un 2xx dont le corps n'a pas la forme documentée.
    #[error("réponse illisible")]
    Illisible,
    /// La plateforme n'offre pas de rafraîchissement programmatique — il faut
    /// faire re-consentir l'humain, pas réessayer.
    #[error("pas de rafraîchissement programmatique pour cette plateforme")]
    RafraichissementIndisponible,
}

impl ErreurPlateforme {
    /// Le code stable que les réponses d'outil montrent aux agents — le
    /// message est pour l'humain, le code est ce qu'un agent peut brancher.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Refus { .. } => "plateforme_refus",
            Self::Injoignable => "plateforme_injoignable",
            Self::Illisible => "reponse_illisible",
            Self::RafraichissementIndisponible => "rafraichissement_indisponible",
        }
    }

    /// Un statut HTTP devient une erreur nommée. 5xx et 429 sont « la
    /// plateforme a une mauvaise minute » (réessayable en amont), le reste des
    /// non-2xx est un refus qu'un rejeu ne changera pas — la même coupe que
    /// `ProviderError::from_status` côté runtime, gardée ici en deux lignes
    /// parce que ce binaire ne dépend pas du reste de la taxonomie.
    pub fn depuis_statut(statut: u16) -> Option<Self> {
        match statut {
            200..=299 => None,
            429 | 500..=599 => Some(Self::Injoignable),
            _ => Some(Self::Refus { statut }),
        }
    }
}

/// SHA-256 en hexadécimal — l'empreinte que `post_preview` publie.
pub fn empreinte(texte: &str) -> String {
    Sha256::digest(texte.as_bytes())
        .iter()
        .fold(String::with_capacity(64), |mut out, octet| {
            use std::fmt::Write;
            let _ = write!(out, "{octet:02x}");
            out
        })
}

/// Le client HTTP des adaptateurs : redirections coupées (un point d'API qui
/// 302 est un point auquel on ne renvoie pas un Bearer), timeout court parce
/// qu'un agent attend derrière — les deux décisions de `post_token` dans
/// `crates/app/src/oauth.rs`, reprises telles quelles.
pub(crate) fn http() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()
            .expect("configuration reqwest statique")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l_empreinte_est_le_sha256_du_texte() {
        // Vecteur connu : sha256("abc"), FIPS 180-2 annexe B.1.
        assert_eq!(
            empreinte("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn un_statut_de_refus_ne_passe_jamais_pour_un_succes() {
        for statut in [400, 401, 403, 404, 422] {
            assert_eq!(
                ErreurPlateforme::depuis_statut(statut),
                Some(ErreurPlateforme::Refus { statut })
            );
        }
        for statut in [429, 500, 503] {
            assert_eq!(
                ErreurPlateforme::depuis_statut(statut),
                Some(ErreurPlateforme::Injoignable)
            );
        }
        assert_eq!(ErreurPlateforme::depuis_statut(201), None);
    }
}

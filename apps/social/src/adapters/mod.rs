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

/// Un média téléchargé, vetté et empreinté par medias.rs. Les octets sont EN
/// MEMOIRE : le plafond absolu du téléchargeur (512 MiB) le permet.
#[derive(Clone)]
pub struct MediaPret {
    pub octets: std::sync::Arc<Vec<u8>>,
    pub type_detecte: TypeMedia,
    /// SHA-256 hex des octets — ce qu'une approbation contresigne.
    pub digest: String,
    pub alt_text: Option<String>,
    pub title: Option<String>,
}

/// Debug à la main : la taille et le digest identifient le média dans un
/// message de test ou un log — jamais les octets eux-mêmes (jusqu'à 512 MiB,
/// et un dump binaire n'a rien à faire dans une erreur).
impl std::fmt::Debug for MediaPret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaPret")
            .field("octets", &format_args!("{} octets", self.octets.len()))
            .field("type_detecte", &self.type_detecte)
            .field("digest", &self.digest)
            .field("alt_text", &self.alt_text)
            .field("title", &self.title)
            .finish()
    }
}

/// Détecté aux OCTETS (magic bytes), jamais à l'extension ni au Content-Type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeMedia {
    Jpeg,
    Png,
    Gif,
    Webp,
    Mp4,
    Pdf,
}

impl TypeMedia {
    pub fn mime(&self) -> &'static str {
        match self {
            Self::Jpeg => "image/jpeg",
            Self::Png => "image/png",
            Self::Gif => "image/gif",
            Self::Webp => "image/webp",
            Self::Mp4 => "video/mp4",
            Self::Pdf => "application/pdf",
        }
    }
}

/// Le sondage, forme commune ; chaque adaptateur refuse ce que sa plateforme
/// ne sert pas (X : pas de question séparée ; LinkedIn : durées fixes).
#[derive(Debug, Clone, serde::Serialize)]
pub struct Sondage {
    pub question: Option<String>,
    pub options: Vec<String>,
    pub duration_minutes: u32,
}

/// Le verdict d'UN média dans l'aperçu.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ApercuMedia {
    pub digest: String,
    pub size_bytes: u64,
    pub detected_type: &'static str,
    pub alt_text: Option<String>,
    pub limits_ok: bool,
    /// Mots exacts, chiffres cités ("5 MB max pour tweet_image, reçu 7 340 032 octets").
    pub verdicts: Vec<String>,
}

/// LA définition du trait — l'unique. Depuis le chantier médias, l'aperçu et
/// la publication portent les mêmes entrées (médias vettés, sondage,
/// made_with_ai) : pas de méthode sœur, une seule vérité — sinon l'empreinte
/// contresignée et ce qui part pourraient diverger.
#[async_trait]
pub trait Plateforme: Send + Sync {
    /// Le nom tel qu'il sort dans `accounts_list` : "x" ou "linkedin".
    fn nom(&self) -> &'static str;

    /// Le rendu EXACT qui partirait, son empreinte globale (texte + médias +
    /// sondage + made_with_ai, C3), le verdict par média et ce que ça coûterait.
    ///
    /// Pur et sans réseau : c'est ce qu'une approbation humaine contresigne,
    /// donc il doit être calculable — et testable — sans toucher la plateforme.
    fn apercu(
        &self,
        texte: &str,
        medias: &[MediaPret],
        sondage: Option<&Sondage>,
        made_with_ai: bool,
    ) -> Apercu;

    /// Publie pour le compte `handle`. Ne retente rien : l'idempotence
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
        medias: &[MediaPret],
        sondage: Option<&Sondage>,
        made_with_ai: bool,
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
    /// Le texte exact qui partirait. Aucun adaptateur ne réécrit rien, donc
    /// `rendered_text == texte` — et le test le fige, parce que le jour où un
    /// adaptateur « améliore » le texte, l'empreinte contresignée ne couvre
    /// plus ce qui part.
    pub rendered_text: String,
    /// L'empreinte globale (C3) : texte seul quand il n'y a ni média, ni
    /// sondage, ni made_with_ai (compat totale) ; sinon texte + digest de
    /// chaque média + sondage + drapeau, dans un ordre fixe. C'est elle
    /// qu'une approbation signe.
    pub digest: String,
    /// Faux si la plateforme refusera (limite de longueur, texte vide,
    /// verdict média ou sondage négatif).
    pub platform_limits_ok: bool,
    /// En USD, `None` quand la plateforme ne facture pas l'écriture.
    pub cost_estimate_usd: Option<f64>,
    /// Le verdict de chaque média, dans l'ordre reçu. Vide = post texte seul.
    pub media: Vec<ApercuMedia>,
    /// Les refus qui n'appartiennent à AUCUN média en particulier (sondage
    /// hors bornes, mélange photo+vidéo, cinquième photo…). Sans ce champ un
    /// `platform_limits_ok: false` sur un sondage serait muet — et une
    /// ignorance silencieuse est interdite par le contrat.
    pub verdicts: Vec<String>,
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
/// par construction plutôt que par relecture. Le 403 post-finalize de X (vidéo
/// au-dessus du droit du compte) sort en `Refus { statut: 403 }` — géré,
/// nommé, sans corps.
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

/// SHA-256 en hexadécimal — la brique des empreintes.
pub fn empreinte(texte: &str) -> String {
    Sha256::digest(texte.as_bytes())
        .iter()
        .fold(String::with_capacity(64), |mut out, octet| {
            use std::fmt::Write;
            let _ = write!(out, "{octet:02x}");
            out
        })
}

/// L'empreinte globale (contrat C3) : ce que le contreseing couvre.
///
/// Sans média, sans sondage, sans made_with_ai : `empreinte(texte)` telle
/// quelle — les posts texte existants gardent leur digest, `store::reclamer`
/// ne voit aucune différence. Sinon : composantes dans un ordre FIXE, jointes
/// par `"\n"`, puis SHA-256 du tout. Chaque composante média est un hex fixe
/// de 64 : pas d'ambiguïté de découpage. Le séparateur U+001F du sondage
/// évite qu'une option en collision avec `join` fabrique la même empreinte.
pub fn empreinte_globale(
    texte: &str,
    medias: &[MediaPret],
    sondage: Option<&Sondage>,
    made_with_ai: bool,
) -> String {
    if medias.is_empty() && sondage.is_none() && !made_with_ai {
        return empreinte(texte);
    }
    let mut composantes = vec![empreinte(texte)];
    composantes.extend(medias.iter().map(|m| m.digest.clone()));
    if let Some(s) = sondage {
        composantes.push(empreinte(&format!(
            "{}\u{1f}{}\u{1f}{}",
            s.question.as_deref().unwrap_or(""),
            s.options.join("\u{1f}"),
            s.duration_minutes
        )));
    }
    if made_with_ai {
        composantes.push("made_with_ai".to_owned());
    }
    empreinte(&composantes.join("\n"))
}

/// Le client HTTP des adaptateurs : redirections coupées (un point d'API qui
/// 302 est un point auquel on ne renvoie pas un Bearer), timeout court parce
/// qu'un agent attend derrière — les deux décisions de `post_token` dans
/// `crates/app/src/oauth.rs`, reprises telles quelles.
///
/// Exception nommée : les uploads (plusieurs MiB, jusqu'au plafond 512 MiB du
/// téléchargeur) ne tiennent pas en 15 s — ils passent par [`http_upload`].
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

/// Le client des téléversements de médias : mêmes redirections coupées, mais
/// un timeout dimensionné pour pousser un segment de 4 MiB sur un lien lent —
/// 15 s tuerait tout upload sérieux, et l'appelant borne déjà le tout.
pub(crate) fn http_upload() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(120))
            .build()
            .expect("configuration reqwest statique")
    })
}

#[cfg(test)]
pub(crate) mod test_medias {
    //! Fabriquer un [`MediaPret`] comme medias.rs le ferait — digest calculé
    //! sur les octets, pour que les tests d'empreinte globale mordent.
    use super::*;

    pub fn media(octets: &[u8], type_detecte: TypeMedia) -> MediaPret {
        let digest = Sha256::digest(octets)
            .iter()
            .fold(String::with_capacity(64), |mut out, o| {
                use std::fmt::Write;
                let _ = write!(out, "{o:02x}");
                out
            });
        MediaPret {
            octets: std::sync::Arc::new(octets.to_vec()),
            type_detecte,
            digest,
            alt_text: None,
            title: None,
        }
    }
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

    #[test]
    fn sans_media_ni_sondage_l_empreinte_globale_est_celle_du_texte() {
        // C3 : compat totale — les posts texte existants gardent leur digest.
        assert_eq!(empreinte_globale("abc", &[], None, false), empreinte("abc"));
    }

    #[test]
    fn l_empreinte_globale_change_quand_un_media_change_ou_quand_l_ordre_change() {
        let a = test_medias::media(b"octets A", TypeMedia::Png);
        let b = test_medias::media(b"octets B", TypeMedia::Png);
        let ab = empreinte_globale("texte", &[a.clone(), b.clone()], None, false);
        let ba = empreinte_globale("texte", &[b.clone(), a.clone()], None, false);
        let aa = empreinte_globale("texte", &[a.clone(), a.clone()], None, false);
        // Une image différente = un contreseing différent : c'est toute la
        // raison d'empreinter les octets, pas seulement le texte.
        assert_ne!(ab, aa);
        // L'ordre fait partie du contenu contresigné (C3 : ordre du tableau).
        assert_ne!(ab, ba);
        // Et le texte seul ne suffit plus dès qu'un média est là.
        assert_ne!(ab, empreinte("texte"));
    }

    #[test]
    fn l_empreinte_globale_couvre_sondage_et_made_with_ai() {
        let sondage = Sondage {
            question: None,
            options: vec!["oui".into(), "non".into()],
            duration_minutes: 1440,
        };
        let sans = empreinte_globale("texte", &[], None, false);
        let avec_sondage = empreinte_globale("texte", &[], Some(&sondage), false);
        let avec_ai = empreinte_globale("texte", &[], None, true);
        assert_ne!(sans, avec_sondage);
        assert_ne!(sans, avec_ai);
        assert_ne!(avec_sondage, avec_ai);
        // Une durée différente est un sondage différent.
        let sondage2 = Sondage {
            duration_minutes: 4320,
            ..sondage.clone()
        };
        assert_ne!(
            avec_sondage,
            empreinte_globale("texte", &[], Some(&sondage2), false)
        );
    }
}

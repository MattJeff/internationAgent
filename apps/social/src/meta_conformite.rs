//! Callbacks exigés par Meta pour la revue d'app du second connecteur.
//!
//! Data Deletion Request et Deauthorize, relevés le 2026-11-10 :
//! <https://developers.facebook.com/docs/development/create-an-app/app-dashboard/data-deletion-callback>.
//!
//! `signed_request` est `signature.payload` en base64url. La signature est
//! HMAC-SHA256 du payload ENCORE ENCODÉ, clé = secret de l'app. On vérifie
//! avant de lire `user_id`. Le secret du connecteur historique
//! (`SOCIAL_META_CLIENT_SECRET`) n'est pas accepté ici : ce module ne
//! connaît que le secret qu'on lui passe (`META2_APP_SECRET` ou
//! `META2_THREADS_APP_SECRET`).
//!
//! La réponse de suppression est `{url, confirmation_code}`. `url` pointe
//! la page publique de statut. Ni l'un ni l'autre ne portent l'id Meta.

use base64::Engine as _;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub const CHEMIN_SUPPRESSION: &str = "/meta/data-deletion";
pub const CHEMIN_DESAUTORISATION: &str = "/meta/deauthorize";
pub const CHEMIN_SUPPRESSION_THREADS: &str = "/meta/threads/data-deletion";
pub const CHEMIN_DESAUTORISATION_THREADS: &str = "/meta/threads/deauthorize";
pub const CHEMIN_STATUT: &str = "/meta/deletion-status";

/// Plateformes dont les jetons tombent quand CE secret d'app a signé.
/// `instagram` (le connecteur historique) n'y est pas.
pub fn plateformes_concernees(app: &str) -> &'static [&'static str] {
    match app {
        "threads" => &["threads"],
        _ => &["instagram_reels", "facebook_page"],
    }
}

/// Vérifie `signed_request` et rend l'id utilisateur Meta (chiffres seuls).
/// L'erreur ne porte ni le secret, ni le payload, ni l'id.
#[derive(Debug, PartialEq, Eq)]
pub struct SignatureInvalide;

pub fn utilisateur_signe(signed_request: &str, secret: &str) -> Result<String, SignatureInvalide> {
    let (signature, payload) = signed_request.split_once('.').ok_or(SignatureInvalide)?;
    if signature.is_empty() || payload.is_empty() || secret.is_empty() {
        return Err(SignatureInvalide);
    }
    let attendue = decoder(signature).ok_or(SignatureInvalide)?;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| SignatureInvalide)?;
    mac.update(payload.as_bytes());
    mac.verify_slice(&attendue).map_err(|_| SignatureInvalide)?;
    let octets = decoder(payload).ok_or(SignatureInvalide)?;
    let document: serde_json::Value =
        serde_json::from_slice(&octets).map_err(|_| SignatureInvalide)?;
    if document.get("algorithm").and_then(|v| v.as_str()) != Some("HMAC-SHA256") {
        return Err(SignatureInvalide);
    }
    let id = match document.get("user_id") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Number(n)) => {
            n.as_u64().map(|u| u.to_string()).ok_or(SignatureInvalide)?
        }
        _ => return Err(SignatureInvalide),
    };
    if (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_digit()) {
        Ok(id)
    } else {
        Err(SignatureInvalide)
    }
}

fn decoder(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| URL_SAFE.decode(s))
        .ok()
}

/// 16 octets d'OS, hex sur 32 caractères. Pas dérivé de l'id Meta.
pub fn code_confirmation() -> String {
    let mut octets = [0u8; 16];
    rand::rng().fill_bytes(&mut octets);
    octets.iter().fold(String::with_capacity(32), |mut s, o| {
        use std::fmt::Write;
        let _ = write!(s, "{o:02x}");
        s
    })
}

pub fn code_confirmation_valide(code: &str) -> bool {
    code.len() == 32
        && code
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// L'URL rendue à Meta : `{base}/meta/deletion-status?code=…`.
pub fn url_statut(base_publique: &str, code: &str) -> String {
    format!(
        "{}/meta/deletion-status?code={code}",
        base_publique.trim_end_matches('/')
    )
}

pub struct StatutSuppression {
    pub code: String,
    pub app: String,
    pub comptes: i32,
    pub quand: String,
}

/// Page publique. Pas d'id Meta, pas de jeton, pas de handle.
pub fn page_statut(s: &StatutSuppression) -> String {
    let produit = match s.app.as_str() {
        "threads" => "Threads",
        _ => "Instagram Reels et Facebook",
    };
    format!(
        "<!DOCTYPE html><html lang=\"fr\"><head><meta charset=\"utf-8\">\
         <title>Suppression des données</title></head><body>\
         <p>Demande <b>{}</b> enregistrée le {}.</p>\
         <p>Jetons révoqués pour {produit} : {}.</p>\
         <p>Le connecteur Instagram historique de l'entreprise n'est pas concerné.</p>\
         </body></html>",
        echapper(&s.code),
        echapper(&s.quand),
        s.comptes
    )
}

pub fn echapper(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Signe comme Meta, pour les tests. Le secret n'est pas une valeur réelle.
pub fn signer(payload_json: &str, secret: &str) -> String {
    let payload = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("clé hmac");
    mac.update(payload.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{signature}.{payload}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "secret-de-test-meta2";

    #[test]
    fn une_signature_valide_donne_l_id_et_une_autre_cle_non() {
        let ok = signer(r#"{"algorithm":"HMAC-SHA256","user_id":"218471"}"#, SECRET);
        assert_eq!(utilisateur_signe(&ok, SECRET).as_deref(), Ok("218471"));
        assert!(utilisateur_signe(&ok, "autre-secret").is_err());
        // Un chiffre JSON, pas une chaîne : Meta a les deux formes.
        let nombre = signer(r#"{"algorithm":"HMAC-SHA256","user_id":42}"#, SECRET);
        assert_eq!(utilisateur_signe(&nombre, SECRET).as_deref(), Ok("42"));
    }

    #[test]
    fn un_payload_touche_ou_un_algorithme_autre_est_refuse() {
        let ok = signer(r#"{"algorithm":"HMAC-SHA256","user_id":"218471"}"#, SECRET);
        let (sig, _) = ok.split_once('.').unwrap();
        let autre = signer(r#"{"algorithm":"HMAC-SHA256","user_id":"999"}"#, SECRET);
        let (_, payload) = autre.split_once('.').unwrap();
        assert!(utilisateur_signe(&format!("{sig}.{payload}"), SECRET).is_err());
        let mauvais = signer(r#"{"algorithm":"PLAINTEXT","user_id":"218471"}"#, SECRET);
        assert!(utilisateur_signe(&mauvais, SECRET).is_err());
        let sale = signer(
            r#"{"algorithm":"HMAC-SHA256","user_id":"12<script>"}"#,
            SECRET,
        );
        assert!(utilisateur_signe(&sale, SECRET).is_err());
    }

    #[test]
    fn la_suppression_ne_vise_pas_le_connecteur_historique() {
        assert_eq!(
            plateformes_concernees("meta2"),
            ["instagram_reels", "facebook_page"]
        );
        assert_eq!(plateformes_concernees("threads"), ["threads"]);
        assert!(!plateformes_concernees("meta2").contains(&"instagram"));
    }

    #[test]
    fn le_code_et_la_page_ne_portent_pas_l_id() {
        let code = code_confirmation();
        assert!(code_confirmation_valide(&code));
        assert!(!code_confirmation_valide(&code.to_uppercase()));
        let page = page_statut(&StatutSuppression {
            code: code.clone(),
            app: "meta2".into(),
            comptes: 2,
            quand: "2026-11-10T21:00:00Z".into(),
        });
        assert!(page.contains(&code));
        assert!(page.contains("Instagram Reels"));
        assert!(!page.contains("218471"));
        let url = url_statut("https://social-local.orizn.app/", &code);
        assert_eq!(
            url,
            format!("https://social-local.orizn.app/meta/deletion-status?code={code}")
        );
    }
}

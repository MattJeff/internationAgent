//! Le lien d'un clic : deux URL signées dans le mail d'approbation, une qui
//! approuve et une qui refuse **cette** approbation, et rien d'autre.
//!
//! Ce n'est pas une clé d'approbateur qui se promène dans un mail : la
//! signature couvre le locataire, l'approbation, la décision et l'échéance,
//! donc une URL approuve une demande, dans un sens, jusqu'à une date. Une
//! URL modifiée ne vérifie plus ; une URL rejouée trouve une approbation déjà
//! décidée (409). La boîte du fondateur est la seule chose qui la reçoit,
//! comme elle reçoit déjà le brouillon entier.
//!
//! La clé HMAC est dérivée de la clé maître avec une étiquette à elle, pour
//! que rien d'autre dans le produit ne signe avec les mêmes octets.
//!
//! ponytail: pas de table, pas de jeton à usage unique en base — l'état
//! `pending` de l'approbation est déjà le « pas encore consommé ».

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

/// Durée de validité d'un lien. Plus long que l'approbation d'un e-mail
/// (24 h), assez pour un article (7 jours) : passé ça, c'est l'approbation
/// elle-même qui n'est plus `pending`.
pub const LINK_TTL_DAYS: i64 = 7;

#[derive(Clone)]
pub struct ApprovalLink {
    key: Vec<u8>,
    base: String,
}

/// Ce qu'un lien demande.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Approve,
    Deny,
}

impl Decision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "approve" => Some(Self::Approve),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }
}

impl ApprovalLink {
    /// `public_host` est celui du serveur (`PUBLIC_HOST`), sans barre finale.
    #[must_use]
    pub fn new(master_key: &str, public_host: &str) -> Self {
        let mut mac = <Hmac<Sha256>>::new_from_slice(master_key.as_bytes())
            .expect("HMAC-SHA256 accepte une clé de toute longueur");
        mac.update(b"approval-link");
        Self {
            key: mac.finalize().into_bytes().to_vec(),
            base: public_host.trim_end_matches('/').to_owned(),
        }
    }

    fn sign(&self, tenant: Uuid, approval: Uuid, decision: Decision, exp: i64) -> String {
        let mut mac =
            <Hmac<Sha256>>::new_from_slice(&self.key).expect("HMAC-SHA256 accepte toute clé");
        mac.update(format!("{tenant}\0{approval}\0{}\0{exp}", decision.as_str()).as_bytes());
        B64.encode(mac.finalize().into_bytes())
    }

    fn url(&self, tenant: Uuid, approval: Uuid, decision: Decision, exp: i64) -> String {
        format!(
            "{}/v1/approvals/link?t={tenant}&a={approval}&d={}&e={exp}&s={}",
            self.base,
            decision.as_str(),
            self.sign(tenant, approval, decision, exp)
        )
    }

    /// Les deux URL du mail : (approuver, refuser).
    #[must_use]
    pub fn urls(&self, tenant: Uuid, approval: Uuid, now: DateTime<Utc>) -> (String, String) {
        let exp = (now + chrono::Duration::days(LINK_TTL_DAYS)).timestamp();
        (
            self.url(tenant, approval, Decision::Approve, exp),
            self.url(tenant, approval, Decision::Deny, exp),
        )
    }

    /// Vrai si la signature couvre exactement ces quatre valeurs et que
    /// l'échéance n'est pas passée. Comparaison en temps constant.
    #[must_use]
    pub fn verify(
        &self,
        tenant: Uuid,
        approval: Uuid,
        decision: Decision,
        exp: i64,
        sig: &str,
        now: DateTime<Utc>,
    ) -> bool {
        if now.timestamp() > exp {
            return false;
        }
        let Ok(given) = B64.decode(sig) else {
            return false;
        };
        let mut mac =
            <Hmac<Sha256>>::new_from_slice(&self.key).expect("HMAC-SHA256 accepte toute clé");
        mac.update(format!("{tenant}\0{approval}\0{}\0{exp}", decision.as_str()).as_bytes());
        mac.verify_slice(&given).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(url: &str) -> (Uuid, Uuid, Decision, i64, String) {
        let q = url.split_once('?').expect("query").1;
        let get = |k: &str| {
            q.split('&')
                .find_map(|kv| kv.strip_prefix(&format!("{k}=")))
                .expect(k)
                .to_owned()
        };
        (
            get("t").parse().unwrap(),
            get("a").parse().unwrap(),
            Decision::parse(&get("d")).unwrap(),
            get("e").parse().unwrap(),
            get("s"),
        )
    }

    #[test]
    fn a_link_verifies_its_own_four_values_and_nothing_else() {
        let link = ApprovalLink::new("clé-maître", "https://api.example.com/");
        let (tenant, approval) = (Uuid::new_v4(), Uuid::new_v4());
        let now = Utc::now();
        let (ok, no) = link.urls(tenant, approval, now);
        assert!(ok.starts_with("https://api.example.com/v1/approvals/link?"));

        let (t, a, d, e, s) = parts(&ok);
        assert_eq!(d, Decision::Approve);
        assert!(link.verify(t, a, d, e, &s, now));
        // La signature d'« approuver » ne refuse pas, et inversement.
        assert!(!link.verify(t, a, Decision::Deny, e, &s, now));
        let (_, _, d2, e2, s2) = parts(&no);
        assert_eq!(d2, Decision::Deny);
        assert!(link.verify(t, a, d2, e2, &s2, now));
        // Une autre approbation, un autre locataire, une autre échéance : non.
        assert!(!link.verify(t, Uuid::new_v4(), d, e, &s, now));
        assert!(!link.verify(Uuid::new_v4(), a, d, e, &s, now));
        assert!(!link.verify(t, a, d, e + 1, &s, now));
        // Passé l'échéance : non, même signée juste.
        assert!(!link.verify(
            t,
            a,
            d,
            e,
            &s,
            now + chrono::Duration::days(LINK_TTL_DAYS + 1)
        ));
        // Une autre clé maître ne reconnaît rien.
        assert!(!ApprovalLink::new("autre", "https://api.example.com").verify(t, a, d, e, &s, now));
        // Une signature qui n'est pas du base64 n'est pas une panique.
        assert!(!link.verify(t, a, d, e, "pas du base64 !", now));
    }
}

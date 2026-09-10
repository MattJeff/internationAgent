//! One-shot: publish a sending domain's DNS records in the Cloudflare zone
//! that holds it.
//!
//! # Why this exists, and why it is this small
//!
//! The customer registers a domain (`POST /v1/domain`), the provider hands
//! back three or four records, and the customer copies them into a DNS
//! console by hand — the step where Orizn lost five days on a domain nobody
//! owned, and the step a second customer will get wrong in a new way. This
//! module is the copy, done once, against the one DNS host both known
//! customers use.
//!
//! **Not a port.** There is one implementation and no trait, because a second
//! DNS host is speculation and a trait with one implementor is a lie about
//! flexibility. The day Route 53 is asked for, this file is what a trait
//! would be extracted from.
//!
//! # The token is used once and kept nowhere
//!
//! [`Cloudflare::new`] takes a [`Secret`], holds it for the length of one
//! [`Cloudflare::pose`], and the caller drops the client. It is never
//! written, never logged ([`Secret`] has no `Display` and a redacting
//! `Debug`), and no row anywhere in this workspace has a column for it —
//! `routes::domain` proves the absence on a captured log. A stored token
//! would be a credential to a customer's entire DNS, held for a feature that
//! runs once.
//!
//! # Cloudflare facts encoded here (API v4, read 2026-09-10)
//!
//! * `GET /zones?name=<exact name>` lists zones by their apex; a subdomain is
//!   not a zone, so the lookup walks suffixes from the longest to the
//!   registrable two labels and takes the first hit.
//! * Record names are fully qualified. Resend spells its records relative to
//!   the domain (`resend._domainkey`, `send`), so [`fqdn`] joins them; `@` or
//!   an empty name is the domain itself.
//! * `TXT` content is quoted (`"v=spf1 …"`), `ttl: 1` is "automatic",
//!   `proxied: false` because MX and TXT cannot be proxied and a DKIM record
//!   behind the orange cloud is a record nobody can read.
//! * `GET /zones/{id}/dns_records` is read once first so a second run poses
//!   nothing: the whole route is safe to click twice.

use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use crate::email::DnsRecord;
use crate::{ProviderError, Secret};

/// Cloudflare's v4 API root.
pub const API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// Hard ceiling on one request, connect included.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// What [`Cloudflare::pose`] did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Posed {
    /// Records created.
    pub posed: usize,
    /// Records the zone already carried, byte for byte.
    pub skipped: usize,
    /// The zone's name, so the caller can say where the records went.
    pub zone: String,
}

/// A client for one call. See the module docs.
pub struct Cloudflare {
    http: reqwest::Client,
    base_url: String,
    token: Secret,
}

impl Cloudflare {
    /// Wrap an API token the customer pasted. Needs `Zone:Read` and
    /// `DNS:Edit` on the zone.
    pub fn new(token: Secret) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .unwrap_or_default(),
            base_url: API_BASE.to_owned(),
            token,
        }
    }

    /// Point the client at another origin. For hermetic tests.
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into().trim_end_matches('/').to_owned();
        self
    }

    /// Put every record of `records` that the zone holding `domain` does not
    /// already carry.
    ///
    /// `Terminal { zone_not_found }` when no suffix of `domain` is a zone
    /// this token can see — the wrong account, or a token without
    /// `Zone:Read`. The 401/403 the API answers a bad token with come back
    /// as `ProviderError::from_status` names them.
    pub async fn pose(&self, domain: &str, records: &[DnsRecord]) -> Result<Posed, ProviderError> {
        let zone = self.find_zone(domain).await?;
        let existing: Vec<CfRecord> = self
            .call_json(
                self.http
                    .get(format!(
                        "{}/zones/{}/dns_records?per_page=500",
                        self.base_url, zone.id
                    ))
                    .bearer_auth(self.token.expose_for_transport()),
            )
            .await?;

        let mut posed = Posed {
            posed: 0,
            skipped: 0,
            zone: zone.name,
        };
        for record in records {
            let wanted = CfRecord {
                kind: record.kind.clone(),
                name: fqdn(domain, &record.name),
                content: content_for(record),
                priority: record.priority,
            };
            if existing.iter().any(|have| have.matches(&wanted)) {
                posed.skipped += 1;
                continue;
            }
            let mut body = serde_json::json!({
                "type": wanted.kind,
                "name": wanted.name,
                "content": wanted.content,
                "ttl": 1,
                "proxied": false,
            });
            if let Some(priority) = wanted.priority {
                body["priority"] = serde_json::json!(priority);
            }
            let _: serde_json::Value = self
                .call_json(
                    self.http
                        .post(format!("{}/zones/{}/dns_records", self.base_url, zone.id))
                        .bearer_auth(self.token.expose_for_transport())
                        .json(&body),
                )
                .await?;
            posed.posed += 1;
        }
        Ok(posed)
    }

    /// The zone holding `domain`: the longest suffix of it that is a zone.
    async fn find_zone(&self, domain: &str) -> Result<Zone, ProviderError> {
        let labels: Vec<&str> = domain.split('.').collect();
        // `agents.getorizn.com` → `agents.getorizn.com`, `getorizn.com`; never
        // a single label, which is no zone anybody can own.
        for start in 0..labels.len().saturating_sub(1) {
            let candidate = labels[start..].join(".");
            let zones: Vec<Zone> = self
                .call_json(
                    self.http
                        .get(format!("{}/zones", self.base_url))
                        .query(&[("name", candidate.as_str())])
                        .bearer_auth(self.token.expose_for_transport()),
                )
                .await?;
            if let Some(zone) = zones.into_iter().next() {
                return Ok(zone);
            }
        }
        Err(ProviderError::Terminal {
            code: "zone_not_found",
        })
    }

    /// Send, classify, and unwrap Cloudflare's `{success, result}` envelope.
    ///
    /// ponytail: every transport failure is [`ProviderError::timeout`], as in
    /// `email_resend`. A `success: false` on a 2xx (Cloudflare does that for
    /// some validation errors) is a `Terminal { cloudflare_rejected }`.
    async fn call_json<T: serde::de::DeserializeOwned>(
        &self,
        req: reqwest::RequestBuilder,
    ) -> Result<T, ProviderError> {
        let response = req.send().await.map_err(|_| ProviderError::timeout())?;
        let status = response.status();
        if !status.is_success() {
            return Err(match status {
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => ProviderError::Terminal {
                    code: "cloudflare_token_refused",
                },
                other => ProviderError::from_status(other.as_u16(), None),
            });
        }
        let envelope: Envelope<T> = response
            .json()
            .await
            .map_err(|_| ProviderError::timeout())?;
        match (envelope.success, envelope.result) {
            (true, Some(result)) => Ok(result),
            _ => Err(ProviderError::Terminal {
                code: "cloudflare_rejected",
            }),
        }
    }
}

/// `name` as Resend spells it, made absolute under `domain`.
///
/// Resend's `resend._domainkey` on `agents.getorizn.com` is
/// `resend._domainkey.agents.getorizn.com`; `@`, the empty name and a name
/// that already ends in the domain are left as the domain wants them.
pub fn fqdn(domain: &str, name: &str) -> String {
    let name = name.trim().trim_end_matches('.');
    if name.is_empty() || name == "@" || name == domain {
        return domain.to_owned();
    }
    if name.ends_with(&format!(".{domain}")) {
        return name.to_owned();
    }
    format!("{name}.{domain}")
}

/// What Cloudflare stores as `content`: TXT values quoted, the rest as is.
fn content_for(record: &DnsRecord) -> String {
    if record.kind.eq_ignore_ascii_case("TXT") && !record.value.starts_with('"') {
        format!("\"{}\"", record.value)
    } else {
        record.value.clone()
    }
}

#[derive(Deserialize)]
struct Envelope<T> {
    #[serde(default)]
    success: bool,
    result: Option<T>,
}

#[derive(Deserialize)]
struct Zone {
    id: String,
    name: String,
}

/// One record as Cloudflare lists it — the four fields that make two records
/// the same record.
#[derive(Deserialize)]
struct CfRecord {
    #[serde(rename = "type")]
    kind: String,
    name: String,
    content: String,
    #[serde(default)]
    priority: Option<u16>,
}

impl CfRecord {
    /// Same type, same host, same value once TXT quoting is ignored — the
    /// zone may store a TXT with or without its quotes depending on who
    /// wrote it, and the record is the same record either way.
    fn matches(&self, wanted: &Self) -> bool {
        self.kind.eq_ignore_ascii_case(&wanted.kind)
            && self.name.eq_ignore_ascii_case(&wanted.name)
            && self.content.trim_matches('"') == wanted.content.trim_matches('"')
            && self.priority == wanted.priority
    }
}

// ---------------------------------------------------------------------------
// Tests — hermetic: a loopback axum server standing in for Cloudflare.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::extract::{Path, Query, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::get;
    use axum::{Json, Router};
    use serde_json::{Value, json};

    use super::*;

    const TOKEN: &str = "cf_test_token_DO_NOT_LOG";

    #[derive(Default)]
    struct FakeState {
        /// The zones this "account" owns.
        zones: Vec<(&'static str, &'static str)>,
        /// Records per zone id, as posted or seeded.
        records: Vec<(String, Value)>,
        /// Every `POST` body, in order.
        posted: Vec<Value>,
    }

    struct FakeCloudflare {
        base: String,
        state: Arc<Mutex<FakeState>>,
    }

    impl FakeCloudflare {
        async fn start(zones: Vec<(&'static str, &'static str)>) -> Self {
            let state = Arc::new(Mutex::new(FakeState {
                zones,
                ..FakeState::default()
            }));
            let app = Router::new()
                .route("/zones", get(list_zones))
                .route(
                    "/zones/{id}/dns_records",
                    get(list_records).post(create_record),
                )
                .with_state(Arc::clone(&state));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let base = format!("http://{}", listener.local_addr().expect("addr"));
            tokio::spawn(async move {
                axum::serve(listener, app).await.expect("serve");
            });
            Self { base, state }
        }

        fn client(&self, token: &str) -> Cloudflare {
            Cloudflare::new(Secret::new(token)).with_base_url(&self.base)
        }

        fn posted(&self) -> Vec<Value> {
            self.state.lock().expect("not poisoned").posted.clone()
        }

        fn seed(&self, zone: &str, record: Value) {
            self.state
                .lock()
                .expect("not poisoned")
                .records
                .push((zone.to_owned(), record));
        }
    }

    fn authorised(headers: &HeaderMap) -> bool {
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == format!("Bearer {TOKEN}"))
    }

    async fn list_zones(
        State(state): State<Arc<Mutex<FakeState>>>,
        headers: HeaderMap,
        Query(q): Query<std::collections::HashMap<String, String>>,
    ) -> (StatusCode, Json<Value>) {
        if !authorised(&headers) {
            return (StatusCode::FORBIDDEN, Json(json!({"success": false})));
        }
        let name = q.get("name").cloned().unwrap_or_default();
        let hits: Vec<Value> = state
            .lock()
            .expect("not poisoned")
            .zones
            .iter()
            .filter(|(_, zone)| *zone == name)
            .map(|(id, zone)| json!({"id": id, "name": zone}))
            .collect();
        (
            StatusCode::OK,
            Json(json!({"success": true, "result": hits})),
        )
    }

    async fn list_records(
        State(state): State<Arc<Mutex<FakeState>>>,
        headers: HeaderMap,
        Path(id): Path<String>,
    ) -> (StatusCode, Json<Value>) {
        if !authorised(&headers) {
            return (StatusCode::FORBIDDEN, Json(json!({"success": false})));
        }
        let rows: Vec<Value> = state
            .lock()
            .expect("not poisoned")
            .records
            .iter()
            .filter(|(zone, _)| *zone == id)
            .map(|(_, r)| r.clone())
            .collect();
        (
            StatusCode::OK,
            Json(json!({"success": true, "result": rows})),
        )
    }

    async fn create_record(
        State(state): State<Arc<Mutex<FakeState>>>,
        headers: HeaderMap,
        Path(id): Path<String>,
        Json(body): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        if !authorised(&headers) {
            return (StatusCode::FORBIDDEN, Json(json!({"success": false})));
        }
        let mut state = state.lock().expect("not poisoned");
        state.posted.push(body.clone());
        state.records.push((id, body.clone()));
        (
            StatusCode::OK,
            Json(json!({"success": true, "result": body})),
        )
    }

    fn resend_records() -> Vec<DnsRecord> {
        let txt = |record: &str, name: &str, value: &str| DnsRecord {
            record: record.to_owned(),
            kind: "TXT".to_owned(),
            name: name.to_owned(),
            value: value.to_owned(),
            priority: None,
            ttl: "Auto".to_owned(),
            status: "not_started".to_owned(),
        };
        vec![
            txt(
                "DKIM",
                "resend._domainkey",
                "p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC",
            ),
            DnsRecord {
                record: "SPF".to_owned(),
                kind: "MX".to_owned(),
                name: "send".to_owned(),
                value: "feedback-smtp.eu-west-1.amazonses.com".to_owned(),
                priority: Some(10),
                ttl: "Auto".to_owned(),
                status: "not_started".to_owned(),
            },
            txt("SPF", "send", "v=spf1 include:amazonses.com ~all"),
        ]
    }

    #[test]
    fn names_are_made_absolute_under_the_domain() {
        assert_eq!(
            fqdn("agents.getorizn.com", "resend._domainkey"),
            "resend._domainkey.agents.getorizn.com"
        );
        assert_eq!(fqdn("agents.getorizn.com", "@"), "agents.getorizn.com");
        assert_eq!(fqdn("agents.getorizn.com", ""), "agents.getorizn.com");
        assert_eq!(
            fqdn("agents.getorizn.com", "send.agents.getorizn.com."),
            "send.agents.getorizn.com",
            "an already absolute name is not doubled"
        );
    }

    /// The zone is the registrable suffix, not the sending subdomain; the
    /// records land absolute, TXT quoted, MX with its priority, nothing
    /// proxied — and a second run poses nothing.
    #[tokio::test]
    async fn poses_the_absent_records_in_the_zone_that_holds_the_domain() {
        let fake = FakeCloudflare::start(vec![
            ("zone_other", "example.org"),
            ("zone_1", "getorizn.com"),
        ])
        .await;
        // One record is already there, quoted the way Cloudflare stores it.
        fake.seed(
            "zone_1",
            json!({"type": "TXT", "name": "send.agents.getorizn.com",
                   "content": "\"v=spf1 include:amazonses.com ~all\""}),
        );

        let posed = fake
            .client(TOKEN)
            .pose("agents.getorizn.com", &resend_records())
            .await
            .expect("posed");
        assert_eq!(
            posed,
            Posed {
                posed: 2,
                skipped: 1,
                zone: "getorizn.com".to_owned()
            }
        );
        let bodies = fake.posted();
        assert_eq!(
            bodies[0],
            json!({"type": "TXT", "name": "resend._domainkey.agents.getorizn.com",
                   "content": "\"p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC\"",
                   "ttl": 1, "proxied": false})
        );
        assert_eq!(
            bodies[1],
            json!({"type": "MX", "name": "send.agents.getorizn.com",
                   "content": "feedback-smtp.eu-west-1.amazonses.com",
                   "priority": 10, "ttl": 1, "proxied": false})
        );

        // Click twice: the zone has everything now.
        let again = fake
            .client(TOKEN)
            .pose("agents.getorizn.com", &resend_records())
            .await
            .expect("posed again");
        assert_eq!((again.posed, again.skipped), (0, 3));
        assert_eq!(fake.posted().len(), 2, "nothing was posted twice");
    }

    #[tokio::test]
    async fn no_zone_for_any_suffix_is_terminal_and_so_is_a_refused_token() {
        let fake = FakeCloudflare::start(vec![("zone_1", "getorizn.com")]).await;
        assert_eq!(
            fake.client(TOKEN)
                .pose("agents.example.com", &resend_records())
                .await,
            Err(ProviderError::Terminal {
                code: "zone_not_found"
            })
        );
        assert_eq!(
            fake.client("cf_wrong")
                .pose("agents.getorizn.com", &resend_records())
                .await,
            Err(ProviderError::Terminal {
                code: "cloudflare_token_refused"
            })
        );
        assert!(fake.posted().is_empty());
    }

    /// The token has no way out but the wire: the client prints as nothing.
    #[test]
    fn the_client_does_not_render_its_token() {
        let client = Cloudflare::new(Secret::new(TOKEN));
        let rendered = format!("{:?}", client.token);
        assert!(!rendered.contains(TOKEN), "{rendered}");
    }
}

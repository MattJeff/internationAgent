//! A peer's published key directory: fetched, vetted, and cached.
//!
//! Verifying an inbound signature needs *their* public keys, and the only place
//! those exist is a URL on their host. So a request path makes a network call
//! to an address a stranger controls, which is three problems.
//!
//! # 1. A peer name must not become an arbitrary URL
//!
//! This is the SSRF question, and `crate::mcp` already answered it for a URL an
//! operator typed. The same two locks are used here, in the same order, by
//! calling the same functions — [`crate::mcp::vet_url`] and
//! [`crate::mcp::resolve_and_vet`] — rather than a second copy that will
//! eventually disagree:
//!
//! * **The URL is built, not accepted.** The input is an
//!   [`agentos_domain::action::Domain`], whose `parse` already refuses `/`,
//!   `\`, `@`, `:`, `?`, `#`, whitespace and bare IP addresses. There is no
//!   spelling of a peer that carries a scheme, a port, a path or credentials,
//!   so `https://{peer}{DIRECTORY_PATH}` cannot be steered anywhere by the
//!   name.
//! * **Every resolved address is checked**, with [`Reach::Public`]: no
//!   loopback, no RFC 1918, no `169.254.169.254`. Not the first address — all
//!   of them, because a host that resolves to one public address and one
//!   metadata address reaches the metadata address on the retry.
//!
//! And a third lock this one needs that MCP does not: **redirects are not
//! followed.** A vetted host that answers `302 Location: http://169.254.169.254/`
//! would walk straight past both checks above, and a key directory has no
//! legitimate reason to redirect.
//!
//! There is a fourth thing that is not a lock but bounds the blast radius more
//! than any of them: `routes::a2a` only fetches a peer's directory *after* the
//! Policy Gate has allowed a call from that peer. The set of hosts this module
//! ever contacts is the tenant's own A2A allowlist.
//!
//! ponytail: the address check is TOCTOU — `reqwest` resolves the host again
//! when it connects, and a peer controlling its own DNS can answer differently
//! the second time. `crate::mcp` has the identical gap for the identical
//! reason, and closing it means connecting to a vetted IP with SNI and
//! certificate verification pinned to the hostname. Worth doing once, in one
//! place, for both callers — not twice, badly, here.
//!
//! # 2. A peer that is down must not take our endpoint down with it
//!
//! [`PeerKeys::keys_for`] returns `None` when a peer's directory cannot be
//! established, and `None` is a **downgrade in trust, not a refusal**. The
//! reasoning: the caller is already authenticated by an API key whose label is
//! that peer's domain, and the body it sent is `Untrusted` either way. Refusing
//! would trade a real availability loss — one peer's TLS certificate expiring
//! takes a channel offline — for no security gain over what the credential
//! already established. A *bad* signature is a different thing entirely and is
//! refused; see [`crate::http_signature::VerifyError`].
//!
//! # 3. A key directory must not be fetched per request
//!
//! One process-wide cache, one TTL, both outcomes cached. Caching the failure
//! matters more than caching the success: without it, a peer whose host is
//! unreachable costs a DNS timeout on every inbound call, which is how one
//! peer's outage becomes our latency.
//!
//! ponytail: one TTL for hits and misses, and a `Mutex<HashMap>` rather than
//! anything cleverer. The cost of the single TTL is that a peer who fixes its
//! directory waits up to [`DEFAULT_TTL`] to be believed again; the cost of the
//! mutex is a lock held across a hash lookup, never across the fetch. Split the
//! TTLs the day a peer complains, and reach for a real cache crate the day the
//! map needs eviction — it is bounded by the allowlist, so today it does not.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agentos_domain::action::Domain;
use agentos_domain::identity::{DIRECTORY_PATH, PublicKey};
use serde_json::Value;

use crate::mcp::{Reach, resolve_and_vet, vet_url};

/// How long a fetched directory — or a failure to fetch one — is believed.
///
/// Five minutes is the same order as the signature lifetime it supports, and
/// it bounds how long a rotated-away key keeps verifying. A peer that needs a
/// key withdrawn faster than this needs to suspend the employee, which stops
/// publication at the source.
pub const DEFAULT_TTL: Duration = Duration::from_secs(300);

/// Hard ceiling on one directory fetch, connect included. A peer that cannot
/// answer in two seconds is a peer we are not holding a request path open for.
const FETCH_TIMEOUT: Duration = Duration::from_secs(2);

/// Most a key directory may weigh. A JWKS with a hundred Ed25519 keys is under
/// 20 kB; this is generous and it is a hard stop, applied while the body
/// streams, so a peer cannot answer with a terabyte.
const MAX_DIRECTORY_BYTES: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// PeerKeys
// ---------------------------------------------------------------------------

/// The key directories of every peer this process has talked to.
///
/// Cheap to clone; clones share one cache and one connection pool, which is the
/// point — a cache per request handler is not a cache.
#[derive(Debug, Clone)]
pub struct PeerKeys {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    client: reqwest::Client,
    ttl: Duration,
    cache: Mutex<HashMap<String, Entry>>,
}

/// One cached outcome. `keys: None` is a peer we could not reach — cached on
/// purpose; see the module docs.
#[derive(Debug, Clone)]
struct Entry {
    at: Instant,
    keys: Option<Arc<Vec<PublicKey>>>,
}

impl Default for PeerKeys {
    fn default() -> Self {
        Self::new(DEFAULT_TTL)
    }
}

impl PeerKeys {
    /// A fresh, empty directory cache.
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Arc::new(Inner {
                // Redirects off — see the module docs, this is a lock and not a
                // preference. `build` fails only if the TLS backend cannot be
                // initialised, at which point nothing else in this process
                // works either, so the default client is the honest fallback.
                client: reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(FETCH_TIMEOUT)
                    .build()
                    .unwrap_or_default(),
                ttl,
                cache: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// A cache seeded with keys somebody already has, and never refreshed for
    /// those peers.
    ///
    /// Two callers. A test, which must not depend on a real host answering.
    /// And a deployment that has been handed a peer's key out of band and would
    /// rather trust that than a fetch — which is a stronger position, not a
    /// weaker one, and is why this is not `#[cfg(test)]`.
    pub fn pinned(entries: impl IntoIterator<Item = (Domain, Vec<PublicKey>)>) -> Self {
        let keys = Self::new(Duration::MAX);
        {
            let mut cache = keys.inner.lock();
            for (peer, published) in entries {
                cache.insert(
                    peer.as_str().to_owned(),
                    Entry {
                        at: Instant::now(),
                        keys: Some(Arc::new(published)),
                    },
                );
            }
        }
        keys
    }

    /// The keys `peer` publishes, or `None` if that could not be established.
    ///
    /// `None` is a downgrade and not a refusal — see the module docs. It is
    /// deliberately not a `Result`: there is exactly one thing a caller does
    /// with any of the failure modes, and an error type would invite a second.
    pub async fn keys_for(&self, peer: &Domain) -> Option<Arc<Vec<PublicKey>>> {
        if let Some(entry) = self.cached(peer.as_str()) {
            return entry;
        }

        let fetched = match self.fetch(peer).await {
            Ok(keys) => Some(Arc::new(keys)),
            Err(reason) => {
                tracing::warn!(
                    %peer, reason,
                    "could not fetch a peer's key directory; its signatures cannot be verified \
                     until this clears"
                );
                None
            }
        };

        self.inner.lock().insert(
            peer.as_str().to_owned(),
            Entry {
                at: Instant::now(),
                keys: fetched.clone(),
            },
        );
        fetched
    }

    /// The cached outcome, if it is still fresh. The outer `Option` is "was
    /// there a live entry"; the inner one is the entry's own answer.
    fn cached(&self, peer: &str) -> Option<Option<Arc<Vec<PublicKey>>>> {
        let cache = self.inner.lock();
        let entry = cache.get(peer)?;
        (entry.at.elapsed() < self.inner.ttl).then(|| entry.keys.clone())
    }

    /// One fetch. Returns a low-cardinality reason on failure — never the
    /// peer's response body, which is a stranger's text.
    async fn fetch(&self, peer: &Domain) -> Result<Vec<PublicKey>, &'static str> {
        // Built from a literal and a validated host. See the module docs for
        // why that sentence is the first half of the SSRF answer.
        let url = vet_url(&format!("https://{peer}{DIRECTORY_PATH}")).map_err(|_| "bad_url")?;
        resolve_and_vet(&url, Reach::Public)
            .await
            .map_err(|_| "blocked_or_unresolvable")?;

        let response = self
            .inner
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| "unreachable")?;
        if !response.status().is_success() {
            // Includes the 3xx a redirect-following client would have chased.
            return Err("not_published");
        }

        Ok(parse(&body(response).await?))
    }
}

impl Inner {
    /// The cache, unpoisoned. A panic while holding this lock could only come
    /// from the allocator; recovering the map is strictly better than turning
    /// every later verification into a panic.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// The response body, refusing anything over [`MAX_DIRECTORY_BYTES`] **while it
/// streams**.
///
/// Not `Content-Length` and then `bytes()`: a chunked response carries no
/// length, and `bytes()` buffers whatever arrives. This is the only shape that
/// actually bounds what a hostile peer can make us allocate.
async fn body(mut response: reqwest::Response) -> Result<Vec<u8>, &'static str> {
    let mut buffer = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| "truncated")? {
        if buffer.len() + chunk.len() > MAX_DIRECTORY_BYTES {
            return Err("too_large");
        }
        buffer.extend_from_slice(&chunk);
    }
    Ok(buffer)
}

/// Every Ed25519 key in a JWKS document.
///
/// Lenient on purpose, and only in this direction: a member that is not an
/// Ed25519 signing key — an RSA key, a key for encryption, a malformed `x` — is
/// skipped rather than failing the document, because a peer that also publishes
/// a TLS key should not thereby become unverifiable. What is *not* lenient is
/// what comes out: [`PublicKey`] is 32 bytes and its `kid` is derived from
/// them, so a member cannot claim to be a key it is not.
fn parse(document: &[u8]) -> Vec<PublicKey> {
    let Ok(document) = serde_json::from_slice::<Value>(document) else {
        return Vec::new();
    };
    document["keys"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter(|jwk| jwk["kty"] == "OKP" && jwk["crv"] == "Ed25519" && jwk["use"] != "enc")
        .filter_map(|jwk| PublicKey::from_jwk_x(jwk["x"].as_str()?).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use serde_json::json;

    use super::*;

    fn peer() -> Domain {
        Domain::parse("partner.example.com").expect("domain")
    }

    fn key(byte: u8) -> PublicKey {
        PublicKey::new([byte; 32])
    }

    #[test]
    fn a_jwks_yields_its_ed25519_keys_and_skips_everything_else() {
        let document = json!({"keys": [
            key(1).jwk(),
            // Right curve, wrong purpose.
            {"kty": "OKP", "crv": "Ed25519", "use": "enc", "x": B64URL.encode([2u8; 32])},
            // Right shape, wrong length — cannot be an Ed25519 key.
            {"kty": "OKP", "crv": "Ed25519", "x": B64URL.encode([3u8; 31])},
            // Another algorithm entirely.
            {"kty": "RSA", "n": "…", "e": "AQAB"},
            key(4).jwk(),
        ]});

        assert_eq!(
            parse(document.to_string().as_bytes()),
            vec![key(1), key(4)],
            "a peer publishing other key types must still be verifiable"
        );
    }

    #[test]
    fn a_document_that_is_not_a_key_set_yields_no_keys_rather_than_a_panic() {
        for document in [
            b"".as_slice(),
            b"not json",
            b"{}",
            br#"{"keys": {}}"#,
            br#"{"keys": []}"#,
            br#"{"keys": [null, 7, "x"]}"#,
        ] {
            assert!(parse(document).is_empty(), "{document:?}");
        }
    }

    #[tokio::test]
    async fn a_pinned_peer_never_touches_the_network() {
        let keys = PeerKeys::pinned([(peer(), vec![key(9)])]);
        assert_eq!(
            keys.keys_for(&peer()).await.as_deref(),
            Some(&vec![key(9)]),
            "a pinned directory answers from the cache"
        );

        // And a peer nobody pinned is not invented. `example.invalid` cannot
        // resolve — that is what the TLD is for — so this exercises the failure
        // path without depending on the internet being reachable.
        let unknown = Domain::parse("nobody.example.invalid").expect("domain");
        assert!(keys.keys_for(&unknown).await.is_none());
    }

    /// The SSRF stop, at the only layer this module can test without a network:
    /// no spelling of a peer reaches an address it should not, because no
    /// spelling of a peer carries anything but a hostname.
    #[test]
    fn no_peer_name_can_carry_a_scheme_a_port_a_path_or_an_address() {
        for hostile in [
            "127.0.0.1",
            "169.254.169.254",
            "[::1]",
            "localhost",
            "evil.example.com:8080",
            "evil.example.com/../../admin",
            "user:pass@evil.example.com",
            "evil.example.com?x=1",
            "evil.example.com#frag",
            "http://evil.example.com",
            "",
        ] {
            assert!(
                Domain::parse(hostile).is_err(),
                "{hostile:?} parsed as a peer, and would have become a URL"
            );
        }

        // What a legitimate peer becomes, for contrast: one host, our path.
        assert_eq!(
            format!("https://{}{DIRECTORY_PATH}", peer()),
            "https://partner.example.com/.well-known/http-message-signatures-directory"
        );
    }
}

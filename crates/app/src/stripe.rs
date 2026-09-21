//! A Stripe delivery settles an invoice: the fourth webhook scheme, and the
//! first that writes money *in*.
//!
//! `POST /v1/webhooks/{path}` verifies and stores; `main::on_stripe_webhook`
//! reads the stored row and calls [`record_stripe_payment`]. Same two halves,
//! same reasons, as the three schemes before it (`routes::webhooks` carries the
//! argument). What this module adds is the reading.
//!
//! # Which tenant
//!
//! The one the endpoint belongs to. A `webhook_endpoints` row (0053) is one
//! per `(tenant, provider)` behind an opaque path, and the handler runs in
//! `tenant_tx(endpoint.tenant_id)` — so an invoice number in the payload is
//! looked up under RLS and can only ever resolve to *that* company's document.
//! Two tenants with the same Stripe account are two endpoints; a delivery on
//! B's path naming A's invoice number finds B's invoice of that number or
//! nothing. That is the whole of the cross-tenant argument, and
//! `tenant_b_cannot_settle_tenant_a_s_invoice` is the test.
//!
//! # Which events
//!
//! Three, one per Stripe object a company might take money through, and the
//! same demand of each: `metadata.invoice_number` names our invoice, the
//! object says it is paid, and its amount and currency equal the demand.
//! [`FORMS`] is the table — where the paid flag and the amount live in each
//! object; the currency and the metadata sit at the same place in all three.
//! One read, three shapes, not three copies of the read.
//!
//! `checkout.session.completed` is the first and the one to prefer: a Checkout
//! Session is the object a company creates with a plain link, attaches the
//! metadata to, and hands a customer. `invoice.paid` is Stripe's own invoicing
//! product — a company that already bills there and mirrors the numbers in
//! this register gets settled too. `payment_intent.succeeded` is the intent
//! under either, and carries the metadata only if somebody put it there; when
//! they did, it is the same fact. A delivery of one form for a payment already
//! settled by another collapses on `declare_paid`'s `WHERE`, like a replay.
//! One field ([`INVOICE_NUMBER_KEY`]) in every case, documented in
//! `docs/RUNNING.md`.
//!
//! # The figure is compared, and a mismatch pays nothing
//!
//! Stripe's `amount_total` is in the currency's minor unit, which is what
//! `invoices.amount_minor` is. Equal and same currency: `declare_paid`, and an
//! `invoice_paid` audit row carrying the Stripe event id. Anything else: an
//! `invoice_payment_mismatch` row carrying both figures, and the invoice stays
//! outstanding for a person to look at. A partial payment marked paid would be
//! a receivable that vanished from the register.
//!
//! # Replays
//!
//! Three locks, none of them here: `outbox::enqueue` collapses a redelivery
//! onto the first row (the event id is in the dedupe key); `declare_paid`'s
//! `WHERE paid_at IS NULL` makes a second read a no-op that returns `false`;
//! and the audit row is written only when that returned `true`. The
//! signature's timestamp window ([`TOLERANCE_SECS`]) is Stripe's own
//! recommendation and is a fourth, weaker lock on top.
//!
//! # Un abonnement crée un client
//!
//! Mesuré le 2026-09-22 : une livraison Stripe réglait une facture (ci-dessus)
//! ou rien, et `stripe_subscriptions` lisait le MRR à la source. **Un client
//! qui venait de payer 49 $ sur `visa.orizn.app` n'existait dans aucune table
//! d'ici** — pas de compte, pas de contact, personne pour lui écrire, personne
//! pour savoir qu'il approche de son plafond. C'est la vente au prix affiché,
//! le pan le plus rentable, et il manquait. [`record_stripe_customer`] est la
//! seconde lecture de la même livraison, dans la même transaction.
//!
//! **Ce que chaque événement porte, et donc ce que chacun peut faire.**
//! `customer.created` et `checkout.session.completed` portent l'adresse
//! (`email`, `customer_details.email`) et l'identifiant client `cus_…` ; les
//! `customer.subscription.*` portent `cus_…` et le prix, jamais l'adresse.
//! Alors les premiers **écrivent la personne** — le compte au domaine de
//! l'adresse (segment `other`, pays de Stripe ou `ZZ`), le contact par
//! `upsert_contact` (la seule voie d'écriture, pour la raison de 0107),
//! `lawful_basis = contract` parce qu'un client a un contrat, `origin =
//! stripe` sur une ligne neuve et l'origine **gardée** sur un prospect qui
//! s'abonne (c'est l'attribution que 0107 a construite) — et posent
//! `contacts.stripe_customer` (0114), la clé par laquelle les seconds
//! **retrouvent la personne** et lui donnent son parcours. Une session
//! Checkout en mode `subscription` passe le compte à `customer` tout de suite ;
//! `customer.created` seul ne dit pas encore qu'il paie.
//!
//! **L'ordre n'est pas garanti**, et Stripe le dit. Un abonnement dont le
//! client n'a pas encore d'adresse ici rend [`Welcome::NoContactYet`] et
//! `main::on_stripe_webhook` le rejoue : la livraison qui porte l'adresse
//! arrive dans les secondes, et l'outbox rejoue au plus tôt deux minutes plus
//! tard. Un abonnement dont le client n'a d'adresse nulle part finit en
//! lettre morte après huit essais — visible, ce qu'un `Ok` silencieux ne
//! serait pas.
//!
//! **Le parcours est celui de l'opérateur, pas du code.** Une séquence est
//! déjà une liste de briefs rédigés par un siège derrière la Gate
//! (`crate::sequence`) ; `sequences.welcomes_tier` (0114) la rattache à un
//! palier, nommé comme Stripe le nomme — `price.nickname` en minuscules, ou
//! `lookup_key`, ou l'id du prix — et trois mots réservés : [`TIER_UPGRADE`],
//! [`TIER_DOWNGRADE`], [`TIER_CHURNED`]. Pas de séquence pour ce palier :
//! rien, et une ligne INFO. Le siège qui inscrit est celui du rôle
//! `customer-success`, le seul qui a le droit de répondre aux clients
//! (`docs/orizn-roles/customer-success.json`) ; pas de siège : rien, WARN.
//!
//! **Un client n'est pas un inconnu.** `max_new_contacts_per_day` borne la
//! prospection à froid — une obligation légale sur des gens qui ne nous ont
//! rien demandé. Un client a un contrat, une clé d'API, et une facture avec
//! notre nom dessus ; lui écrire n'est pas l'approcher. `gate::contacts` le
//! sait comme il sait que les domaines de l'entreprise ne sont pas des
//! inconnus : un contact dont le compte est `customer` est connu d'office, et
//! l'inscription d'un client sur son parcours ne dépense aucune place du jour.
//!
//! **`deleted` rend `engaged`, jamais `disqualified`.** Un client parti a
//! été client : il connaît le produit, il a payé, il peut revenir, et c'est
//! exactement ce à quoi sert une séquence `churned`. `disqualified` est le
//! mot pour une entreprise qu'on ne veut pas ; ce n'est pas celui-là.
//!
//! **Ce que ce lecteur ne fait pas.** Pas de relance à l'usage (« vous
//! approchez de vos 30 000 requêtes ») : l'usage n'est pas dans cette base, et
//! une relance sur un nombre qu'on n'a pas est une relance inventée. Le jour
//! où Orizn pousse l'usage ici, c'est un `welcomes_tier` de plus.

use agentos_domain::action::EmailAddress;
use agentos_domain::ids::{EmployeeId, InvoiceId, SequenceId, SequenceRunId};
use agentos_providers::Secret;
use agentos_providers::email::SigError;
use agentos_store::audit::{self, AuditActor, AuditEvent, AuditKind};
use agentos_store::db::{StoreError, TenantTx};
use agentos_store::invoices;
use agentos_store::revenue::{self as revenue_store, NewAccount, NewContact, RevenueError};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::inbound::{InboundError, body_digest, body_hex, ct_eq};
use crate::prospects::UNKNOWN_COUNTRY;
use crate::sequence::{self, EnrollError};

/// The endpoint `provider` whose deliveries are verified here and read by
/// `main::on_stripe_webhook`. `0081` widens
/// `webhook_endpoints_provider_is_wired` to it.
pub const STRIPE_PROVIDER: &str = "stripe";

/// Where Stripe puts its signature: `t=<unix>,v1=<hex>[,v1=<hex>…]`
/// (<https://docs.stripe.com/webhooks#verify-manually>).
pub const STRIPE_SIGNATURE_HEADER: &str = "stripe-signature";

/// How old a signed timestamp may be. Stripe's own default.
pub const TOLERANCE_SECS: i64 = 300;

/// The first of the three events this reader acts on, and the one a plain
/// payment link produces. See [`FORMS`].
pub const PAID_EVENT: &str = "checkout.session.completed";

/// The three shapes a settlement arrives in, and where each keeps what we
/// compare. Read as `(event type, the field that says it is paid, the value
/// that field must hold, the field that holds the amount in minor units)`;
/// `currency` and `metadata` are at the top of `data.object` in all three.
///
/// | event                       | paid when                     | amount            |
/// |-----------------------------|-------------------------------|-------------------|
/// | `checkout.session.completed`| `payment_status == "paid"`    | `amount_total`    |
/// | `invoice.paid`              | `status == "paid"`            | `amount_paid`     |
/// | `payment_intent.succeeded`  | `status == "succeeded"`       | `amount_received` |
pub const FORMS: [(&str, &str, &str, &str); 3] = [
    (PAID_EVENT, "payment_status", "paid", "amount_total"),
    ("invoice.paid", "status", "paid", "amount_paid"),
    (
        "payment_intent.succeeded",
        "status",
        "succeeded",
        "amount_received",
    ),
];

/// The metadata key a Checkout Session carries to name our invoice, as a
/// decimal string: `metadata: { invoice_number: "42" }`.
pub const INVOICE_NUMBER_KEY: &str = "invoice_number";

/// Stripe's signature over `"{timestamp}.{raw}"`, in the header's own spelling.
///
/// Exported for the tests on the route and for a deployment's own smoke check;
/// the verifier below is what a delivery meets.
pub fn sign_stripe_webhook(secret: &Secret, timestamp: i64, raw_body: &[u8]) -> String {
    format!("t={timestamp},v1={}", mac(secret, timestamp, raw_body))
}

fn mac(secret: &Secret, timestamp: i64, raw_body: &[u8]) -> String {
    use hmac::Mac as _;

    let mut mac =
        <hmac::Hmac<sha2::Sha256>>::new_from_slice(secret.expose_for_transport().as_bytes())
            .expect("HMAC-SHA256 takes a key of any length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(raw_body);
    body_hex(&mac.finalize().into_bytes())
}

/// Authenticate a Stripe delivery and name the id a replay collapses onto.
///
/// The id is the event's own `id` (`evt_…`) read off the body **after** the
/// MAC over that body passed, so it is authenticated; a body with no readable
/// id dedupes on its digest, like the two schemes with no id header. Any of
/// several `v1` signatures matching is enough — Stripe sends more than one
/// during a secret rotation.
pub fn verify_stripe_webhook(
    secret: &Secret,
    header: &str,
    raw_body: &[u8],
    now: DateTime<Utc>,
) -> Result<String, SigError> {
    let header = header.trim();
    if header.is_empty() {
        return Err(SigError::MissingHeader);
    }
    let mut timestamp: Option<i64> = None;
    let mut presented: Vec<&str> = Vec::new();
    for part in header.split(',') {
        match part.trim().split_once('=') {
            Some(("t", value)) => timestamp = value.parse().ok(),
            Some(("v1", value)) => presented.push(value),
            _ => {}
        }
    }
    let Some(timestamp) = timestamp else {
        return Err(SigError::Malformed);
    };
    if presented.is_empty() {
        return Err(SigError::Malformed);
    }
    if (now.timestamp() - timestamp).abs() > TOLERANCE_SECS {
        return Err(SigError::Stale);
    }
    let expected = mac(secret, timestamp, raw_body);
    // Every candidate is compared, none short-circuits: the loop's length is
    // the header's, not the secret's.
    let mut matched = false;
    for candidate in presented {
        matched |= ct_eq(
            expected.as_bytes(),
            candidate.to_ascii_lowercase().as_bytes(),
        );
    }
    if !matched {
        return Err(SigError::Mismatch);
    }
    let id = serde_json::from_slice::<Value>(raw_body)
        .ok()
        .and_then(|body| body.get("id")?.as_str().map(str::to_owned))
        .filter(|id| !id.is_empty());
    Ok(id.unwrap_or_else(|| body_digest(raw_body)))
}

/// What a verified delivery did to the register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settlement {
    /// The figure matched and the invoice is now paid.
    Paid(InvoiceId),
    /// The figure did not match; nothing was marked and a person has a row to
    /// read.
    Mismatch(InvoiceId),
    /// Paid already, or a credit note: the register did not move.
    AlreadySettled(InvoiceId),
    /// An event this reader does not act on, a session not yet paid, or a
    /// number that names no invoice of this company.
    NotOurs,
}

/// Read one stored Stripe delivery against this tenant's register.
///
/// `event_id` is the authenticated id `verify_stripe_webhook` produced, and it
/// goes on the audit row so a settlement can be traced to Stripe's dashboard.
/// A body that is not JSON is [`InboundError::BadNotice`], terminal — the
/// bytes will not become JSON on the eighth retry.
pub async fn record_stripe_payment(
    tx: &mut TenantTx<'_>,
    raw_body: &[u8],
    event_id: &str,
    now: DateTime<Utc>,
) -> Result<Settlement, InboundError> {
    let payload: Value = serde_json::from_slice(raw_body)
        .map_err(|_| InboundError::BadNotice("this Stripe delivery is not JSON"))?;

    // Third-party text, compared against constants and never rendered.
    let event = payload.get("type").and_then(Value::as_str);
    let Some((event, paid_field, paid_value, amount_field)) =
        FORMS.into_iter().find(|(form, ..)| Some(*form) == event)
    else {
        return Ok(Settlement::NotOurs);
    };
    let object = &payload["data"]["object"];
    if object.get(paid_field).and_then(Value::as_str) != Some(paid_value) {
        return Ok(Settlement::NotOurs);
    }
    let Some(number) = object["metadata"]
        .get(INVOICE_NUMBER_KEY)
        .and_then(Value::as_str)
        .and_then(|raw| raw.trim().parse::<i64>().ok())
    else {
        return Ok(Settlement::NotOurs);
    };
    let Some(invoice) = invoices::find_by_number(tx, number).await? else {
        return Ok(Settlement::NotOurs);
    };

    let paid_minor = object.get(amount_field).and_then(Value::as_i64);
    let paid_currency = object
        .get("currency")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let expected_minor = i64::try_from(invoice.amount.minor()).ok();
    let matches = paid_minor.is_some()
        && paid_minor == expected_minor
        && paid_currency.eq_ignore_ascii_case(invoice.amount.currency().code());

    let mut row = AuditEvent::new(AuditActor::System, AuditKind::InvoicePaid, now);
    row.payload = json!({
        "invoice_id": invoice.id.to_string(),
        "number": invoice.number,
        // `source` is what tells this row from an operator's — see
        // `routes::invoices::paid`, which writes the same kind with
        // `"operator"` and no event.
        "source": "stripe",
        "stripe_event_id": event_id,
        "stripe_event": event,
        "expected_minor": invoice.amount.minor(),
        "currency": invoice.amount.currency().code(),
        "paid_minor": paid_minor,
        "paid_currency": paid_currency,
    });

    if !matches {
        row.kind = AuditKind::InvoicePaymentMismatch;
        audit::append(tx, &row).await?;
        return Ok(Settlement::Mismatch(invoice.id));
    }
    if !invoices::declare_paid(tx, invoice.id, now).await? {
        return Ok(Settlement::AlreadySettled(invoice.id));
    }
    audit::append(tx, &row).await?;
    Ok(Settlement::Paid(invoice.id))
}

// ---------------------------------------------------------------------------
// Un abonnement crée un client — l'argument est en tête de module
// ---------------------------------------------------------------------------

/// `contacts.origin` d'une personne entrée par Stripe (`0114`).
pub const ORIGIN_STRIPE: &str = "stripe";

/// `contacts.lawful_basis` d'un client : il a un contrat avec nous.
pub const CUSTOMER_LAWFUL_BASIS: &str = "contract";

/// `welcomes_tier` d'une séquence jouée quand un abonnement monte de palier.
pub const TIER_UPGRADE: &str = "upgrade";
/// … quand il descend.
pub const TIER_DOWNGRADE: &str = "downgrade";
/// … quand il est résilié.
pub const TIER_CHURNED: &str = "churned";

/// Ce qu'une livraison a fait au registre des clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Welcome {
    /// Une adresse est arrivée : le compte et le contact existent, créés ou
    /// retrouvés, et le contact porte sa clé Stripe.
    Contact { account: Uuid, contact: Uuid },
    /// Inscrit sur la séquence de ce palier, par le siège `customer-success`.
    Enrolled { tier: String, run: SequenceRunId },
    /// Déjà sur cette séquence : un rejeu.
    AlreadyEnrolled(String),
    /// Aucune séquence vivante ne porte ce `welcomes_tier`.
    NoSequence(String),
    /// Aucun siège `customer-success` actif : personne pour écrire.
    NoSeat(String),
    /// Cette personne a demandé qu'on la laisse, ou l'adresse est suppressée :
    /// rien n'est écrit, rien n'est inscrit.
    Suppressed(String),
    /// Un abonnement dont le client n'a pas encore d'adresse ici : à rejouer,
    /// l'événement qui la porte arrive.
    NoContactYet(String),
    /// Une mise à jour qui ne change pas de palier, ou un abonnement sans prix
    /// lisible.
    Nothing,
    /// Un événement que ce lecteur n'écoute pas, ou sans adresse lisible.
    NotOurs,
}

/// Read one stored Stripe delivery against this tenant's customers.
///
/// La seconde lecture de `main::on_stripe_webhook`, après
/// [`record_stripe_payment`], dans la même transaction. Idempotente par
/// construction : `upsert_account` et `upsert_contact` sur leurs clés
/// naturelles, `UPDATE … WHERE state <> $2`, et `sequence::enroll` qui rend
/// `AlreadyActive` au second passage.
pub async fn record_stripe_customer(
    tx: &mut TenantTx<'_>,
    raw_body: &[u8],
    now: DateTime<Utc>,
) -> Result<Welcome, InboundError> {
    let payload: Value = serde_json::from_slice(raw_body)
        .map_err(|_| InboundError::BadNotice("this Stripe delivery is not JSON"))?;
    // Third-party text: compared, parsed by `EmailAddress`, never rendered.
    let kind = payload["type"].as_str().unwrap_or_default();
    let object = &payload["data"]["object"];
    let text = |v: &Value| {
        v.as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };

    match kind {
        "customer.created" | "checkout.session.completed" => {
            let (customer, email, name, country) = if kind == "customer.created" {
                (
                    text(&object["id"]),
                    text(&object["email"]),
                    text(&object["name"]),
                    text(&object["address"]["country"]),
                )
            } else {
                let details = &object["customer_details"];
                (
                    text(&object["customer"]),
                    text(&details["email"]).or_else(|| text(&object["customer_email"])),
                    text(&details["name"]),
                    text(&details["address"]["country"]),
                )
            };
            let (Some(customer), Some(email)) = (customer, email) else {
                return Ok(Welcome::NotOurs);
            };
            let Ok(email) = EmailAddress::parse(&email) else {
                return Ok(Welcome::NotOurs);
            };
            let Some((account, contact)) =
                upsert_customer(tx, &customer, &email, name.as_deref(), country.as_deref()).await?
            else {
                return Ok(Welcome::Suppressed(customer));
            };
            if object["mode"].as_str() == Some("subscription") {
                set_state(tx, account, "customer").await?;
            }
            Ok(Welcome::Contact { account, contact })
        }
        "customer.subscription.created"
        | "customer.subscription.updated"
        | "customer.subscription.deleted" => {
            let Some(customer) = text(&object["customer"]) else {
                return Ok(Welcome::NotOurs);
            };
            let found: Option<(Uuid, Uuid)> =
                sqlx::query_as("SELECT account_id, id FROM contacts WHERE stripe_customer = $1")
                    .bind(&customer)
                    .fetch_optional(&mut ***tx)
                    .await
                    .map_err(StoreError::from)?;
            let Some((account, contact)) = found else {
                return Ok(Welcome::NoContactYet(customer));
            };
            let tier = match kind {
                "customer.subscription.deleted" => {
                    set_state(tx, account, "engaged").await?;
                    Some(TIER_CHURNED.to_owned())
                }
                "customer.subscription.created" => {
                    set_state(tx, account, "customer").await?;
                    tier_of(object)
                }
                _ => {
                    // `previous_attributes` carries `items` only when the
                    // price changed; a cancel-at-period-end or a card update
                    // does not walk anybody through an upgrade.
                    let before = &payload["data"]["previous_attributes"]["items"];
                    (!before.is_null()).then(|| {
                        if amount_of(&object["items"]) > amount_of(before) {
                            TIER_UPGRADE.to_owned()
                        } else {
                            TIER_DOWNGRADE.to_owned()
                        }
                    })
                }
            };
            let Some(tier) = tier else {
                return Ok(Welcome::Nothing);
            };
            welcome(tx, contact, tier, now).await
        }
        _ => Ok(Welcome::NotOurs),
    }
}

/// Le palier tel que Stripe le nomme : `price.nickname`, sinon `lookup_key`,
/// sinon l'id du prix — en minuscules, comme `sequence::define` range
/// `welcomes_tier`.
fn tier_of(subscription: &Value) -> Option<String> {
    let price = &subscription["items"]["data"][0]["price"];
    ["nickname", "lookup_key", "id"]
        .into_iter()
        .find_map(|key| price[key].as_str())
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
}

fn amount_of(items: &Value) -> i64 {
    items["data"][0]["price"]["unit_amount"]
        .as_i64()
        .unwrap_or_default()
}

fn revenue_err(err: RevenueError) -> InboundError {
    match err {
        RevenueError::Store(err) => InboundError::Store(err),
        other => InboundError::Store(StoreError::conflict(other.to_string())),
    }
}

/// Le compte et le contact d'un client, créés ou retrouvés ; `None` quand
/// l'adresse est suppressée. Le contact retrouvé garde son compte et son
/// origine (0107) ; il gagne sa clé Stripe et la base légale d'un client.
async fn upsert_customer(
    tx: &mut TenantTx<'_>,
    customer: &str,
    email: &EmailAddress,
    name: Option<&str>,
    country: Option<&str>,
) -> Result<Option<(Uuid, Uuid)>, InboundError> {
    let address = email.to_string();
    let known: Option<(Uuid, Uuid)> =
        sqlx::query_as("SELECT account_id, id FROM contacts WHERE email = $1")
            .bind(&address)
            .fetch_optional(&mut ***tx)
            .await
            .map_err(StoreError::from)?;
    let (account, contact) = match known {
        Some(found) => found,
        None => {
            let domain = email.domain().as_str();
            let country = country
                .map(str::to_ascii_uppercase)
                .filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()))
                .unwrap_or_else(|| UNKNOWN_COUNTRY.to_owned());
            // ponytail: le compte est le domaine de l'adresse, comme un import.
            // Un client sur une boîte grand public (gmail.com) partage donc son
            // compte avec les autres clients de gmail.com ; un compte par
            // client Stripe le jour où quelqu'un lit les comptes un par un.
            let account = revenue_store::upsert_account(
                tx,
                Uuid::now_v7(),
                &NewAccount {
                    legal_name: name.unwrap_or(domain),
                    domain,
                    segment: "other",
                    country: &country,
                    employee_id: None,
                    location: None,
                    website: None,
                },
            )
            .await
            .map_err(revenue_err)?;
            let Some(account) = account.id() else {
                return Ok(None);
            };
            let origin_ref = format!("stripe:{customer}");
            let contact = revenue_store::upsert_contact(
                tx,
                Uuid::now_v7(),
                &NewContact {
                    account_id: account,
                    full_name: name.unwrap_or_default(),
                    email: Some(&address),
                    phone: None,
                    role: None,
                    language: None,
                    is_primary: false,
                    lawful_basis: CUSTOMER_LAWFUL_BASIS,
                    // Pas dans la file de relance à froid : un client n'est
                    // pas démarché, il est accueilli — par sa séquence.
                    next_follow_up_at: None,
                    origin: Some(ORIGIN_STRIPE),
                    origin_ref: Some(&origin_ref),
                },
            )
            .await
            .map_err(revenue_err)?;
            let Some(contact) = contact.id() else {
                return Ok(None);
            };
            (account, contact)
        }
    };
    sqlx::query("UPDATE contacts SET stripe_customer = $2, lawful_basis = $3 WHERE id = $1")
        .bind(contact)
        .bind(customer)
        .bind(CUSTOMER_LAWFUL_BASIS)
        .execute(&mut ***tx)
        .await
        .map_err(StoreError::from)?;
    Ok(Some((account, contact)))
}

async fn set_state(tx: &mut TenantTx<'_>, account: Uuid, state: &str) -> Result<(), InboundError> {
    sqlx::query("UPDATE accounts SET state = $2 WHERE id = $1 AND state <> $2")
        .bind(account)
        .bind(state)
        .execute(&mut ***tx)
        .await
        .map_err(StoreError::from)?;
    Ok(())
}

/// Inscrire un client sur la séquence vivante la plus récente de son palier,
/// par le siège `customer-success` le plus ancien encore actif.
async fn welcome(
    tx: &mut TenantTx<'_>,
    contact: Uuid,
    tier: String,
    now: DateTime<Utc>,
) -> Result<Welcome, InboundError> {
    let sequence: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM sequences WHERE welcomes_tier = $1 AND archived_at IS NULL \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&tier)
    .fetch_optional(&mut ***tx)
    .await
    .map_err(StoreError::from)?;
    let Some(sequence) = sequence else {
        return Ok(Welcome::NoSequence(tier));
    };
    let seat: Option<Uuid> = sqlx::query_scalar(
        "SELECT c.employee_id FROM employee_charters c JOIN employees e ON e.id = c.employee_id \
          WHERE c.role = $1 AND e.lifecycle = 'active' ORDER BY c.created_at LIMIT 1",
    )
    .bind(crate::rolepack_service::CUSTOMER_SUCCESS)
    .fetch_optional(&mut ***tx)
    .await
    .map_err(StoreError::from)?;
    let Some(seat) = seat else {
        return Ok(Welcome::NoSeat(tier));
    };
    match sequence::enroll(
        tx,
        SequenceId::from_uuid(sequence),
        contact,
        EmployeeId::from_uuid(seat),
        now,
    )
    .await
    {
        Ok(run) => Ok(Welcome::Enrolled { tier, run }),
        Err(EnrollError::AlreadyActive) => Ok(Welcome::AlreadyEnrolled(tier)),
        // `NotFound("contact")` is an inactive row, which is what an opt-out
        // leaves behind; the sequence and the seat were just read.
        Err(EnrollError::Suppressed | EnrollError::NotFound(_)) => Ok(Welcome::Suppressed(tier)),
        Err(EnrollError::Store(err)) => Err(InboundError::Store(err)),
    }
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::{EmployeeId, TenantId};
    use agentos_domain::money::{Currency, Money};
    use agentos_store::db::Db;
    use sqlx::Row as _;
    use uuid::Uuid;

    use super::*;

    const SECRET: &str = "whsec_test_stripe_signing_secret";

    fn body(number: &str, amount: i64, currency: &str) -> Vec<u8> {
        format!(
            r#"{{"id":"evt_1","type":"checkout.session.completed","data":{{"object":{{"payment_status":"paid","amount_total":{amount},"currency":"{currency}","metadata":{{"invoice_number":"{number}"}}}}}}}}"#
        )
        .into_bytes()
    }

    /// The other two forms, in each object's own field names — a Stripe
    /// invoice says `status`/`amount_paid`, a payment intent
    /// `status`/`amount_received`.
    fn stripe_invoice_body(number: &str, amount: i64, currency: &str) -> Vec<u8> {
        format!(
            r#"{{"id":"evt_2","type":"invoice.paid","data":{{"object":{{"status":"paid","amount_paid":{amount},"amount_due":{amount},"currency":"{currency}","metadata":{{"invoice_number":"{number}"}}}}}}}}"#
        )
        .into_bytes()
    }

    fn payment_intent_body(number: &str, amount: i64, currency: &str) -> Vec<u8> {
        format!(
            r#"{{"id":"evt_3","type":"payment_intent.succeeded","data":{{"object":{{"status":"succeeded","amount":{amount},"amount_received":{amount},"currency":"{currency}","metadata":{{"invoice_number":"{number}"}}}}}}}}"#
        )
        .into_bytes()
    }

    // -- the signature, pure --------------------------------------------------

    #[test]
    fn a_signature_over_the_timestamp_and_the_body_names_the_event() {
        let secret = Secret::new(SECRET);
        let now = Utc::now();
        let raw = body("42", 120_000, "eur");
        let header = sign_stripe_webhook(&secret, now.timestamp(), &raw);
        assert_eq!(
            verify_stripe_webhook(&secret, &header, &raw, now),
            Ok("evt_1".to_owned())
        );
        // A rotation sends two `v1`s; one good one is enough.
        let rotated = format!("{header},v1={}", "0".repeat(64));
        assert!(verify_stripe_webhook(&secret, &rotated, &raw, now).is_ok());
    }

    #[test]
    fn a_forged_stale_or_missing_signature_is_refused() {
        let secret = Secret::new(SECRET);
        let now = Utc::now();
        let raw = body("42", 120_000, "eur");
        let header = sign_stripe_webhook(&secret, now.timestamp(), &raw);
        assert_eq!(
            verify_stripe_webhook(&Secret::new("whsec_other"), &header, &raw, now),
            Err(SigError::Mismatch)
        );
        let mut tampered = raw.clone();
        tampered[10] ^= 1;
        assert_eq!(
            verify_stripe_webhook(&secret, &header, &tampered, now),
            Err(SigError::Mismatch)
        );
        let old = now.timestamp() - TOLERANCE_SECS - 1;
        let stale = sign_stripe_webhook(&secret, old, &raw);
        assert_eq!(
            verify_stripe_webhook(&secret, &stale, &raw, now),
            Err(SigError::Stale)
        );
        assert_eq!(
            verify_stripe_webhook(&secret, "", &raw, now),
            Err(SigError::MissingHeader)
        );
        assert_eq!(
            verify_stripe_webhook(&secret, "v1=abc", &raw, now),
            Err(SigError::Malformed)
        );
    }

    // -- the settlement, against Postgres -------------------------------------

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; settlement tests need a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// A tenant with one employee, one won deal, and one invoice of EUR
    /// 1200.00 against it. Returns the tenant and the invoice.
    async fn invoiced_tenant(db: &Db) -> (TenantId, invoices::Invoice) {
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let employee = EmployeeId::new_v7(now);
        let label = format!("stripe-{}", tenant.as_uuid().simple());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $2)")
            .bind(tenant.as_uuid())
            .bind(&label)
            .execute(&mut *tx)
            .await
            .expect("tenant");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'lena', 'lena', 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("employee");
        tx.commit().await.expect("commit");

        let account = Uuid::now_v7();
        let opportunity = Uuid::now_v7();
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        sqlx::query(
            "INSERT INTO accounts (id, tenant_id, legal_name, domain, segment, country) \
             VALUES ($1, $2, 'Buyer plc', $3, 'airline', 'FR')",
        )
        .bind(account)
        .bind(tenant.as_uuid())
        .bind(format!("buyer-{}.example", account.simple()))
        .execute(&mut **tx)
        .await
        .expect("account");
        sqlx::query(
            "INSERT INTO opportunities \
                 (id, tenant_id, account_id, stage, currency, value_minor, approval_id, closed_at) \
             VALUES ($1, $2, $3, 'closed_won', 'EUR', 120000, $4, now())",
        )
        .bind(opportunity)
        .bind(tenant.as_uuid())
        .bind(account)
        .bind(Uuid::now_v7())
        .execute(&mut **tx)
        .await
        .expect("opportunity");
        let invoice = invoices::issue(
            &mut tx,
            invoices::Draft {
                id: InvoiceId::new_v7(now),
                opportunity_id: opportunity,
                issued_by: employee,
                amount: Money::new(120_000, Currency::Eur).expect("nonzero"),
                memo: "March",
                due_at: None,
                lines: &[],
            },
        )
        .await
        .expect("issue");
        tx.commit().await.expect("commit");
        (tenant, invoice)
    }

    async fn paid_at(db: &Db, tenant: TenantId, id: InvoiceId) -> Option<DateTime<Utc>> {
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let found = invoices::find(&mut tx, id).await.expect("find");
        tx.rollback().await.expect("rollback");
        found.expect("the invoice exists").paid_at
    }

    /// `(kind, stripe_event_id)` of every settlement row this tenant has.
    async fn trail(db: &Db, tenant: TenantId) -> Vec<(String, Value)> {
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let rows = sqlx::query(
            "SELECT action_kind, payload FROM audit_log \
              WHERE action_kind IN ('invoice_paid', 'invoice_payment_mismatch') \
              ORDER BY occurred_at, id",
        )
        .fetch_all(&mut **tx)
        .await
        .expect("audit");
        tx.rollback().await.expect("rollback");
        rows.iter()
            .map(|row| (row.get("action_kind"), row.get("payload")))
            .collect()
    }

    async fn settle(db: &Db, tenant: TenantId, raw: &[u8]) -> Settlement {
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let settled = record_stripe_payment(&mut tx, raw, "evt_1", Utc::now())
            .await
            .expect("read the delivery");
        tx.commit().await.expect("commit");
        settled
    }

    #[tokio::test]
    async fn a_paid_checkout_naming_the_invoice_settles_it_once() {
        let Some(db) = db().await else { return };
        let (tenant, invoice) = invoiced_tenant(&db).await;
        let raw = body(&invoice.number.to_string(), 120_000, "eur");

        assert_eq!(
            settle(&db, tenant, &raw).await,
            Settlement::Paid(invoice.id)
        );
        let first = paid_at(&db, tenant, invoice.id).await;
        assert!(first.is_some(), "the invoice is paid");

        // The same delivery again: the register does not move and no second
        // audit row is written.
        assert_eq!(
            settle(&db, tenant, &raw).await,
            Settlement::AlreadySettled(invoice.id)
        );
        assert_eq!(paid_at(&db, tenant, invoice.id).await, first);
        let rows = trail(&db, tenant).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "invoice_paid");
        assert_eq!(rows[0].1["stripe_event_id"], json!("evt_1"));
        assert_eq!(rows[0].1["stripe_event"], json!(PAID_EVENT));
        assert_eq!(rows[0].1["source"], json!("stripe"));
        assert_eq!(rows[0].1["number"], json!(invoice.number));
    }

    /// The second form: Stripe's own invoice, `status`/`amount_paid`.
    #[tokio::test]
    async fn a_paid_stripe_invoice_naming_the_number_settles_it() {
        let Some(db) = db().await else { return };
        let (tenant, invoice) = invoiced_tenant(&db).await;
        let number = invoice.number.to_string();

        assert_eq!(
            settle(&db, tenant, &stripe_invoice_body(&number, 100_000, "eur")).await,
            Settlement::Mismatch(invoice.id),
            "the same figure rule applies to this form"
        );
        assert_eq!(
            settle(&db, tenant, &stripe_invoice_body(&number, 120_000, "eur")).await,
            Settlement::Paid(invoice.id)
        );
        assert!(paid_at(&db, tenant, invoice.id).await.is_some());
        let rows = trail(&db, tenant).await;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].0, "invoice_paid");
        assert_eq!(rows[1].1["stripe_event"], json!("invoice.paid"));
        assert_eq!(rows[1].1["paid_minor"], json!(120_000));
    }

    /// The third form: the intent, `status == succeeded`/`amount_received`.
    /// An intent still `processing` is not money.
    #[tokio::test]
    async fn a_succeeded_payment_intent_naming_the_number_settles_it() {
        let Some(db) = db().await else { return };
        let (tenant, invoice) = invoiced_tenant(&db).await;
        let number = invoice.number.to_string();

        let processing = String::from_utf8(payment_intent_body(&number, 120_000, "eur"))
            .expect("utf-8")
            .replace(r#""status":"succeeded""#, r#""status":"processing""#);
        assert_eq!(
            settle(&db, tenant, processing.as_bytes()).await,
            Settlement::NotOurs
        );
        assert_eq!(
            settle(&db, tenant, &payment_intent_body(&number, 120_000, "eur")).await,
            Settlement::Paid(invoice.id)
        );
        assert!(paid_at(&db, tenant, invoice.id).await.is_some());
        let rows = trail(&db, tenant).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1["stripe_event"], json!("payment_intent.succeeded"));

        // The intent under a Checkout already settled by its session is the
        // same money twice: the register does not move again.
        assert_eq!(
            settle(&db, tenant, &body(&number, 120_000, "eur")).await,
            Settlement::AlreadySettled(invoice.id)
        );
        assert_eq!(trail(&db, tenant).await.len(), 1);
    }

    #[tokio::test]
    async fn a_different_figure_pays_nothing_and_leaves_a_row() {
        let Some(db) = db().await else { return };
        let (tenant, invoice) = invoiced_tenant(&db).await;
        let number = invoice.number.to_string();

        assert_eq!(
            settle(&db, tenant, &body(&number, 100_000, "eur")).await,
            Settlement::Mismatch(invoice.id)
        );
        assert_eq!(
            settle(&db, tenant, &body(&number, 120_000, "usd")).await,
            Settlement::Mismatch(invoice.id),
            "the right figure in the wrong money is not the demand"
        );
        assert_eq!(paid_at(&db, tenant, invoice.id).await, None);
        let rows = trail(&db, tenant).await;
        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter()
                .all(|(kind, _)| kind == "invoice_payment_mismatch")
        );
        assert_eq!(rows[0].1["paid_minor"], json!(100_000));
        assert_eq!(rows[0].1["expected_minor"], json!(120_000));
    }

    #[tokio::test]
    async fn tenant_b_cannot_settle_tenant_a_s_invoice() {
        let Some(db) = db().await else { return };
        let (a, invoice) = invoiced_tenant(&db).await;
        let b = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $2)")
            .bind(b.as_uuid())
            .bind(format!("stripe-b-{}", b.as_uuid().simple()))
            .execute(&mut *tx)
            .await
            .expect("tenant b");
        tx.commit().await.expect("commit");

        // B's endpoint delivers a paid session naming A's number. B has no
        // invoice of that number, so RLS answers nothing.
        let raw = body(&invoice.number.to_string(), 120_000, "eur");
        assert_eq!(settle(&db, b, &raw).await, Settlement::NotOurs);
        assert_eq!(paid_at(&db, a, invoice.id).await, None);
        assert!(trail(&db, b).await.is_empty());
    }

    #[tokio::test]
    async fn an_unpaid_session_another_event_or_a_non_json_body_moves_nothing() {
        let Some(db) = db().await else { return };
        let (tenant, invoice) = invoiced_tenant(&db).await;
        let number = invoice.number.to_string();
        let unpaid = String::from_utf8(body(&number, 120_000, "eur"))
            .expect("utf-8")
            .replace(r#""payment_status":"paid""#, r#""payment_status":"unpaid""#);
        assert_eq!(
            settle(&db, tenant, unpaid.as_bytes()).await,
            Settlement::NotOurs
        );
        // An event outside `FORMS`, with every field a paid session would
        // carry: nothing happens and nothing breaks.
        let other = String::from_utf8(body(&number, 120_000, "eur"))
            .expect("utf-8")
            .replace("checkout.session.completed", "charge.refunded");
        assert_eq!(
            settle(&db, tenant, other.as_bytes()).await,
            Settlement::NotOurs
        );
        assert_eq!(paid_at(&db, tenant, invoice.id).await, None);

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let err = record_stripe_payment(&mut tx, b"}{", "evt_x", Utc::now())
            .await
            .expect_err("not JSON");
        tx.rollback().await.expect("rollback");
        assert!(matches!(err, InboundError::BadNotice(_)));
        assert!(!err.is_retryable());
    }

    // -- un abonnement crée un client, contre Postgres -----------------------

    /// Un locataire et un siège `customer-success` actif, chartré.
    async fn welcoming_tenant(db: &Db) -> (TenantId, EmployeeId) {
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let seat = EmployeeId::new_v7(now);
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $2)")
            .bind(tenant.as_uuid())
            .bind(format!("welcome-{}", tenant.as_uuid().simple()))
            .execute(&mut *tx)
            .await
            .expect("tenant");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'sam', 'sam', 'active')",
        )
        .bind(seat.as_uuid())
        .bind(tenant.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("employee");
        sqlx::query(
            "INSERT INTO employee_charters (employee_id, tenant_id, role, objective) \
             VALUES ($1, $2, 'customer-success', '{}'::jsonb)",
        )
        .bind(seat.as_uuid())
        .bind(tenant.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("charter");
        tx.commit().await.expect("commit");
        (tenant, seat)
    }

    fn checkout(customer: &str, email: &str) -> Vec<u8> {
        json!({
            "id": format!("evt_co_{customer}"),
            "type": "checkout.session.completed",
            "data": { "object": {
                "object": "checkout.session",
                "mode": "subscription",
                "customer": customer,
                "subscription": format!("sub_{customer}"),
                "payment_status": "paid",
                "amount_total": 4900,
                "currency": "usd",
                "customer_details": {
                    "email": email,
                    "name": "Ada Client",
                    "address": { "country": "fr" }
                },
                "metadata": {}
            } }
        })
        .to_string()
        .into_bytes()
    }

    fn subscription(kind: &str, customer: &str, nickname: &str, amount: i64) -> Value {
        json!({
            "id": format!("evt_{kind}_{customer}"),
            "type": kind,
            "data": { "object": {
                "object": "subscription",
                "id": format!("sub_{customer}"),
                "customer": customer,
                "status": "active",
                "items": { "object": "list", "data": [ { "price": {
                    "id": "price_x", "nickname": nickname, "unit_amount": amount
                } } ] }
            } }
        })
    }

    async fn welcomed(db: &Db, tenant: TenantId, body: &[u8]) -> Welcome {
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let out = record_stripe_customer(&mut tx, body, Utc::now())
            .await
            .expect("read");
        tx.commit().await.expect("commit");
        out
    }

    async fn welcome_sequence(db: &Db, tenant: TenantId, tier: &str) -> SequenceId {
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let id = sequence::define(
            &mut tx,
            &format!("welcome-{tier}-{}", Uuid::now_v7().simple()),
            &[sequence::Step::Email {
                brief: Some("dire bonjour et montrer la clé".to_owned()),
                variants: Vec::new(),
            }],
            Some(tier),
        )
        .await
        .expect("define");
        tx.commit().await.expect("commit");
        id
    }

    async fn contact_row(db: &Db, tenant: TenantId, email: &str) -> (Uuid, Uuid, String, String) {
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let row: (Uuid, Uuid, String, String) = sqlx::query_as(
            "SELECT c.id, c.account_id, c.lawful_basis, a.state \
               FROM contacts c JOIN accounts a ON a.id = c.account_id WHERE c.email = $1",
        )
        .bind(email)
        .fetch_one(&mut **tx)
        .await
        .expect("contact");
        tx.rollback().await.expect("rollback");
        row
    }

    #[tokio::test]
    async fn un_abonnement_cree_un_client_et_le_rejeu_ne_le_double_pas() {
        let Some(db) = db().await else { return };
        let (tenant, _) = welcoming_tenant(&db).await;
        let email = format!("ada@{}.example", tenant.as_uuid().simple());
        let body = checkout("cus_ada", &email);

        let first = welcomed(&db, tenant, &body).await;
        let Welcome::Contact { account, contact } = first else {
            panic!("{first:?}");
        };
        let (id, account_id, basis, state) = contact_row(&db, tenant, &email).await;
        assert_eq!((id, account_id), (contact, account));
        assert_eq!(basis, CUSTOMER_LAWFUL_BASIS, "un client a un contrat");
        assert_eq!(state, "customer");

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let (origin, origin_ref, stripe, segment, country): (
            String,
            String,
            String,
            String,
            String,
        ) = sqlx::query_as(
            "SELECT c.origin, c.origin_ref, c.stripe_customer, a.segment, a.country \
               FROM contacts c JOIN accounts a ON a.id = c.account_id WHERE c.id = $1",
        )
        .bind(contact)
        .fetch_one(&mut **tx)
        .await
        .expect("row");
        tx.rollback().await.expect("rollback");
        assert_eq!(
            (origin.as_str(), origin_ref.as_str(), stripe.as_str()),
            (ORIGIN_STRIPE, "stripe:cus_ada", "cus_ada")
        );
        assert_eq!((segment.as_str(), country.as_str()), ("other", "FR"));

        // Le rejeu retrouve les mêmes lignes et n'en écrit aucune autre.
        assert_eq!(welcomed(&db, tenant, &body).await, first);
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM contacts")
            .fetch_one(&mut **tx)
            .await
            .expect("count");
        assert_eq!(n, 1);
    }

    #[tokio::test]
    async fn un_prospect_qui_sinscrit_est_marque_client_pas_duplique() {
        let Some(db) = db().await else { return };
        let (tenant, _) = welcoming_tenant(&db).await;
        let email = format!("paul@{}.example", tenant.as_uuid().simple());
        let account = Uuid::now_v7();
        let prospect = Uuid::now_v7();
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        // Le compte est au domaine du site, pas de l'adresse, comme un import.
        sqlx::query(
            "INSERT INTO accounts (id, tenant_id, legal_name, domain, segment, country) \
             VALUES ($1, $2, 'Paul SAS', $3, 'ota', 'FR')",
        )
        .bind(account)
        .bind(tenant.as_uuid())
        .bind(format!("site-{}.example", account.simple()))
        .execute(&mut **tx)
        .await
        .expect("account");
        sqlx::query(
            "INSERT INTO contacts (id, tenant_id, account_id, full_name, email, origin, origin_ref) \
             VALUES ($1, $2, $3, 'Paul', $4, 'import', 'liste-ota.csv')",
        )
        .bind(prospect)
        .bind(tenant.as_uuid())
        .bind(account)
        .bind(&email)
        .execute(&mut **tx)
        .await
        .expect("contact");
        tx.commit().await.expect("commit");

        let out = welcomed(&db, tenant, &checkout("cus_paul", &email)).await;
        assert_eq!(
            out,
            Welcome::Contact {
                account,
                contact: prospect
            }
        );
        let (_, _, basis, state) = contact_row(&db, tenant, &email).await;
        assert_eq!((basis.as_str(), state.as_str()), ("contract", "customer"));
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let (origin, origin_ref, stripe, accounts): (String, String, String, i64) = sqlx::query_as(
            "SELECT origin, origin_ref, stripe_customer, (SELECT count(*) FROM accounts) \
                   FROM contacts WHERE id = $1",
        )
        .bind(prospect)
        .fetch_one(&mut **tx)
        .await
        .expect("row");
        // L'attribution de 0107 est gardée : c'est la liste qui a produit l'euro.
        assert_eq!(
            (origin.as_str(), origin_ref.as_str(), stripe.as_str()),
            ("import", "liste-ota.csv", "cus_paul")
        );
        assert_eq!(
            accounts, 1,
            "pas de compte orphelin au domaine de l'adresse"
        );
    }

    #[tokio::test]
    async fn la_sequence_du_palier_inscrit_le_client_par_le_siege_support() {
        let Some(db) = db().await else { return };
        let (tenant, seat) = welcoming_tenant(&db).await;
        let email = format!("ada@{}.example", tenant.as_uuid().simple());
        let seq = welcome_sequence(&db, tenant, "Starter").await;
        welcomed(&db, tenant, &checkout("cus_s", &email)).await;

        let created = subscription("customer.subscription.created", "cus_s", "Starter", 4900);
        let out = welcomed(&db, tenant, created.to_string().as_bytes()).await;
        let Welcome::Enrolled { tier, run } = out else {
            panic!("{out:?}");
        };
        assert_eq!(tier, "starter", "le palier se lit en minuscules");
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let runs = sequence::runs(&mut tx, seq).await.expect("runs");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].id, run);
        assert_eq!(
            runs[0].employee_id, seat,
            "c'est le siège support qui écrit"
        );
        assert_eq!(
            sequence::list(&mut tx).await.expect("list")[0]
                .welcomes_tier
                .as_deref(),
            Some("starter")
        );
        tx.rollback().await.expect("rollback");

        // Le rejeu n'inscrit pas deux fois.
        assert_eq!(
            welcomed(&db, tenant, created.to_string().as_bytes()).await,
            Welcome::AlreadyEnrolled("starter".to_owned())
        );
    }

    #[tokio::test]
    async fn sans_sequence_pour_ce_palier_rien_nest_inscrit() {
        let Some(db) = db().await else { return };
        let (tenant, _) = welcoming_tenant(&db).await;
        let email = format!("ada@{}.example", tenant.as_uuid().simple());
        welcomed(&db, tenant, &checkout("cus_n", &email)).await;
        let created = subscription(
            "customer.subscription.created",
            "cus_n",
            "Entreprise",
            60000,
        );
        assert_eq!(
            welcomed(&db, tenant, created.to_string().as_bytes()).await,
            Welcome::NoSequence("entreprise".to_owned())
        );
        let (_, _, _, state) = contact_row(&db, tenant, &email).await;
        assert_eq!(state, "customer", "le compte est client même sans parcours");
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM sequence_runs")
            .fetch_one(&mut **tx)
            .await
            .expect("count");
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn une_resiliation_rend_le_compte_engaged_et_joue_la_sequence_churned() {
        let Some(db) = db().await else { return };
        let (tenant, _) = welcoming_tenant(&db).await;
        let email = format!("ada@{}.example", tenant.as_uuid().simple());
        let churned = welcome_sequence(&db, tenant, TIER_CHURNED).await;
        welcomed(&db, tenant, &checkout("cus_d", &email)).await;
        assert_eq!(contact_row(&db, tenant, &email).await.3, "customer");

        let deleted = subscription("customer.subscription.deleted", "cus_d", "Starter", 4900);
        let out = welcomed(&db, tenant, deleted.to_string().as_bytes()).await;
        assert!(
            matches!(&out, Welcome::Enrolled { tier, .. } if tier == TIER_CHURNED),
            "{out:?}"
        );
        // Il a été client : `engaged`, pas `disqualified`.
        assert_eq!(contact_row(&db, tenant, &email).await.3, "engaged");
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        assert_eq!(
            sequence::runs(&mut tx, churned).await.expect("runs").len(),
            1
        );
    }

    #[tokio::test]
    async fn un_abonnement_avant_son_adresse_attend() {
        let Some(db) = db().await else { return };
        let (tenant, _) = welcoming_tenant(&db).await;
        let created = subscription(
            "customer.subscription.created",
            "cus_early",
            "Starter",
            4900,
        );
        assert_eq!(
            welcomed(&db, tenant, created.to_string().as_bytes()).await,
            Welcome::NoContactYet("cus_early".to_owned())
        );
        // Une mise à jour sans changement de prix ne joue rien non plus, une
        // fois le client là.
        let email = format!("ada@{}.example", tenant.as_uuid().simple());
        welcomed(&db, tenant, &checkout("cus_early", &email)).await;
        let updated = subscription(
            "customer.subscription.updated",
            "cus_early",
            "Starter",
            4900,
        );
        assert_eq!(
            welcomed(&db, tenant, updated.to_string().as_bytes()).await,
            Welcome::Nothing
        );
    }
}

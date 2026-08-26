//! The seller's input: the founder's own lists, become rows.
//!
//! [`crate::queue`] is the other end of this — it takes `contacts` that are due
//! and produces the file he uploads. It has always had a producer and no
//! source: `insert_account` and `insert_contact` are called from tests and from
//! nothing else, so in production the pipeline tables are empty and every query
//! over them returns nothing. Meanwhile ~1,600 prospects sit in
//! Smartlead-shaped CSVs on a laptop. This module is the missing half hour:
//! read those files, write those rows, twice if you like.
//!
//! # The shape it reads
//!
//! The founder's eight columns, and they are [`crate::queue::COLUMNS`]`[..8]`
//! rather than a second copy of the same list — the export's header and the
//! import's header are the same eight names by construction, and
//! `crates/app/tests/fixtures/smartlead_getorizn_prospection.csv` is a cut of
//! the real file that both are asserted against.
//!
//! # What identifies a prospect
//!
//! Two natural keys, one per table, and both are unique constraints
//! `0011_revenue.sql` already carries rather than new rules invented here.
//!
//! **An account is its domain** — `unique (tenant_id, domain)`. The domain comes
//! from `website` when the row has one and from the address otherwise, in that
//! order, because the schema says what a domain is *for*: "the identity of a
//! prospect: names are spelled six ways and a booking flow lives at a domain".
//! The booking flow lives at the website, not at the MX, and the proof-of-need
//! probe that this vertical is built around visits the former. In the founder's
//! lists the two disagree for 338 of the 1,552 rows that carry both — an
//! association whose site is `reisebueros.at` and whose mailbox is at `wko.at` —
//! so this is a choice with consequences and not a tidy-up.
//!
//! A `www.` prefix is dropped and nothing else is: it is the one cosmetic prefix
//! that never distinguishes two companies, and dropping it is what makes
//! `https://www.oerv.at` and `office@oerv.at` one account instead of two.
//!
//! ponytail: no public-suffix list. `Domain::parse` gives the full host, so
//! `aastravel.com.hk` is the account rather than `com.hk`, which is the right
//! answer here and the wrong one for a subdomain — `travel.example.com` and
//! `example.com` would be two accounts. Reach for the `publicsuffix` crate the
//! day a list carries subdomains; these do not.
//!
//! **A contact is its address** — `unique (tenant_id, email)`. Not the name
//! (there usually is not one), not the company (people move), and not a pair of
//! them. It is also what the suppression list is keyed on, which is the argument
//! that settles it: a second row for one address is a row that dodges the
//! opt-out cascade, and `0011_revenue.sql` says exactly that where it declares
//! the constraint.
//!
//! Running the same file twice therefore writes nothing the second time, and so
//! does running two files that overlap — which is not hypothetical: the
//! `getorizn_*` and `oriznapi_*` lists are the same 1,100 people under two
//! sending domains, and of 2,209 prospect rows only 1,133 are distinct people.
//!
//! # An import cannot wake a suppressed address
//!
//! This is the reason [`crate::queue`] exists in the shape it does and the
//! reason this module does not simply loop over `insert_contact`. The write goes
//! through [`upsert_contact`](agentos_store::revenue::upsert_contact), which
//! calls `revenue_suppression_of` **inside the INSERT**: a suppressed address is
//! never inserted, an existing inactive row for it is never touched, and the
//! BEFORE trigger on `contacts` is still underneath refusing an active
//! suppressed row whatever the statement thinks. The report counts them.
//!
//! # What it will not do
//!
//! **It will not invent a first name.** 3,012 of 3,048 rows across every list
//! have neither a first nor a last name, because they are `info@` and
//! `contact@` inboxes; `full_name` is the two fields joined, which for those
//! rows is the empty string. That is a fact about the list and the import
//! records it as one. It is *also* a September problem — Smartlead's
//! `add_leads_to_campaign` marks `first_name` required — and
//! [`Report::nameless`] is the number the founder has to make a decision about.
//! `SELECT count(*) FROM contacts WHERE full_name = ''` asks the same question
//! of the database.
//!
//! **It will not guess a country.** `accounts.country` is ISO-2 with a CHECK and
//! the lists carry `États-Unis`, `Mandaluyong, Philippines` and `inconnu` — 118
//! spellings in three languages. The verbatim string goes to `accounts.location`
//! (`0033_prospect_listing.sql`) and `country` is `ZZ` unless the operator
//! passes one, which is right for `--country PH` over the DMW list and honest
//! for FIDI, which is worldwide.
//!
//! **It will not bend a phone number.** `contacts.phone` is E.164 because
//! `revenue_suppression_of` matches a phone by string equality; 584 of the 2,044
//! numbers in these lists are not E.164 (`(02)83518906`) and turning one into
//! one means guessing a country per row. They are dropped, counted in
//! [`Report::phones_dropped`], and still in the founder's CSV.
//!
//! **It will not keep a `linkedin_profile`.** There is no column for it on
//! `accounts` or `contacts`, and there is no value for it either: all 3,048 rows
//! are empty. Adding a column for a field nobody has filled is a guess about its
//! shape. If one is ever filled, [`Report::linkedin_dropped`] says so and that
//! is the day for the migration.
//!
//! # Where it is called from
//!
//! `agentos-server import`, beside `agentos-server policy install`, for the same
//! reason and one more. The files are on the founder's laptop: a route would
//! need them uploaded to a server that has no reason to hold them, through a
//! multipart body nothing else in this API uses, authorised by an API key that
//! would then be a way to bulk-write another tenant's pipeline. A subcommand
//! runs on `DATABASE_URL` — the credential the operator already has — and adds
//! nothing to the HTTP surface. This module is the library half, so the day
//! there is a hosted control plane with a file picker, the route calls `import`
//! and none of the rules above move.

use agentos_domain::action::{Domain, EmailAddress};
use agentos_domain::ids::EmployeeId;
use agentos_store::db::TenantTx;
use agentos_store::revenue::{
    self as revenue_store, NewAccount, NewContact, RevenueError, Upserted,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::queue::COLUMNS;

/// The segments `accounts_segment` in `0011_revenue.sql` permits.
///
/// Not [`agentos_domain::revenue::Segment`], and the difference is worth
/// knowing: that enum has six variants, spells cruise `cruise_line`, and has no
/// `relocation` or `other` — so it cannot name the FIDI movers or the ECTAA
/// associations, and its spelling of cruise would violate the CHECK. The
/// database is the authority here; this array is checked against it by
/// `a_segment_the_check_refuses_is_refused_before_the_database_sees_it`.
pub const SEGMENTS: [&str; 8] = [
    "airline",
    "ota",
    "corporate_travel",
    "tmc",
    "insurer",
    "cruise",
    "relocation",
    "other",
];

/// ISO 3166-1 has no code for "nobody wrote it down"; this is what the CLDR
/// uses and what `CountryCode`'s own docs already accept.
pub const UNKNOWN_COUNTRY: &str = "ZZ";

/// GDPR still applies to a business address, so every row names its basis. Cold
/// B2B prospecting is `legitimate_interest` — the same default the column has,
/// written here so that the import states it rather than inherits it.
const LAWFUL_BASIS: &str = "legitimate_interest";

/// What a file is a list *of*: the two things its rows do not say.
#[derive(Debug, Clone, Copy)]
pub struct List<'a> {
    /// One of [`SEGMENTS`]. Not inferred from the filename: `smartlead_getorizn_fidi.csv`
    /// is a list of movers and `smartlead_associations_ectaa.csv` is a list of
    /// trade bodies, and a program that guessed which would be wrong quietly.
    pub segment: &'a str,
    /// ISO 3166-1 alpha-2 for every account in this file, or [`UNKNOWN_COUNTRY`].
    /// Right for a single-country list, honest for a worldwide one.
    pub country: &'a str,
    /// The employee who owns these prospects, if any.
    pub employee_id: Option<EmployeeId>,
}

/// Why a file could not be loaded at all.
///
/// A *row* that cannot be loaded is not one of these — it is a line in
/// [`Report::refused`], because one bad row in a thousand is a typo and
/// refusing the other 999 over it is not a service to anybody. These three are
/// the file being the wrong file, or the command being the wrong command, and
/// every one of them is decided before the first write.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    /// The header is not the founder's eight columns. Nothing else about the
    /// file is trustworthy after that, so no row of it is guessed at.
    #[error(
        "this is not a Smartlead list: the header is {0}, expected {expected}",
        expected = COLUMNS[..8].join(",")
    )]
    Header(String),

    /// A segment the CHECK constraint would refuse.
    #[error("segment {0:?} is not one of {list}", list = SEGMENTS.join(", "))]
    Segment(String),

    /// A country that is not two letters.
    #[error("country {0:?} is not an ISO 3166-1 alpha-2 code (try {UNKNOWN_COUNTRY})")]
    Country(String),

    /// The database refused a write. The whole import is one transaction, so
    /// nothing was committed and the file can be fixed and re-run.
    #[error(transparent)]
    Store(#[from] RevenueError),
}

/// What one run did, and everything it could not do.
///
/// The counters that are *not* zero are the interesting ones, and
/// [`Report::summary`] prints only those. A field here exists because dropping
/// something the founder collected without saying so is the one outcome this
/// module is not allowed to have.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Data rows read, before any of them were judged.
    pub rows: usize,
    /// New `accounts` rows.
    pub accounts_created: usize,
    /// Accounts that were already there, under this domain.
    pub accounts_existing: usize,
    /// New `contacts` rows.
    pub contacts_created: usize,
    /// Addresses already on file. The second run of the same list is all of
    /// these and that is the point.
    pub contacts_existing: usize,
    /// Addresses on the suppression list. No row was written and no inactive
    /// row was woken.
    pub suppressed: usize,
    /// One line per row that was not imported, naming the row and why.
    pub refused: Vec<String>,
    /// Rows whose phone number was not E.164 and was therefore not stored.
    pub phones_dropped: usize,
    /// Rows carrying a `linkedin_profile`, which has no column anywhere.
    pub linkedin_dropped: usize,
    /// Contacts with no name at all — the September problem, counted.
    pub nameless: usize,
    /// Accounts created with [`UNKNOWN_COUNTRY`], their location kept verbatim.
    pub unknown_country: usize,
}

impl Report {
    /// The operator's whole view of a run: what landed, and every silent loss
    /// made loud.
    pub fn summary(&self) -> String {
        let mut out = format!(
            "{} rows read\n\
             {} accounts created, {} already there\n\
             {} contacts created, {} already there",
            self.rows,
            self.accounts_created,
            self.accounts_existing,
            self.contacts_created,
            self.contacts_existing,
        );
        if self.suppressed > 0 {
            out.push_str(&format!(
                "\n{} addresses are on the suppression list and were skipped",
                self.suppressed
            ));
        }
        if self.nameless > 0 {
            out.push_str(&format!(
                "\n{} contacts have no name; none was invented. Smartlead's API \
                 requires first_name from 2026-09-01 — decide what these are \
                 called before then",
                self.nameless
            ));
        }
        if self.phones_dropped > 0 {
            out.push_str(&format!(
                "\n{} phone numbers are not E.164 and are NOT stored; they are \
                 still in the CSV",
                self.phones_dropped
            ));
        }
        if self.linkedin_dropped > 0 {
            out.push_str(&format!(
                "\n{} rows carry a linkedin_profile, which has no column \
                 anywhere and is NOT stored",
                self.linkedin_dropped
            ));
        }
        if self.unknown_country > 0 {
            out.push_str(&format!(
                "\n{} accounts have country {UNKNOWN_COUNTRY}; their location is \
                 stored verbatim. Pass --country for a single-country list",
                self.unknown_country
            ));
        }
        for line in &self.refused {
            out.push_str("\nrefused: ");
            out.push_str(line);
        }
        out
    }

    /// Whether this run wrote anything. A second import of the same file is
    /// `false`, which is what idempotent means here.
    pub const fn wrote_anything(&self) -> bool {
        self.accounts_created > 0 || self.contacts_created > 0
    }
}

/// Load one Smartlead-shaped list into `accounts` and `contacts`.
///
/// `now` is when the imported contacts become due: they are written with
/// `next_follow_up_at = now`, so they enter
/// [`contacts_due_for_follow_up`](agentos_store::revenue::contacts_due_for_follow_up)
/// immediately and [`crate::queue::plan`] meters them out against
/// `max_new_contacts_per_day`. The alternative — a NULL follow-up — would write
/// 1,600 rows that no query in this system ever returns, which is the state this
/// module exists to end.
///
/// **One transaction.** The caller commits, or does not: an import that half
/// happened is an import whose report is a lie. Re-running after a failure is
/// safe by construction — see this module's docs on the two natural keys.
pub async fn import(
    tx: &mut TenantTx<'_>,
    list: &List<'_>,
    text: &str,
    now: DateTime<Utc>,
) -> Result<Report, ImportError> {
    if !SEGMENTS.contains(&list.segment) {
        return Err(ImportError::Segment(list.segment.to_owned()));
    }
    if list.country.len() != 2 || !list.country.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(ImportError::Country(list.country.to_owned()));
    }

    let mut records = records(text).into_iter();
    match records.next() {
        Some((_, header))
            if header.len() == 8 && header.iter().zip(COLUMNS).all(|(had, want)| had == want) => {}
        Some((_, header)) => return Err(ImportError::Header(header.join(","))),
        None => return Err(ImportError::Header(String::new())),
    }

    let mut report = Report::default();
    for (line, record) in records {
        report.rows += 1;
        let Ok(fields) = <[String; 8]>::try_from(record) else {
            report
                .refused
                .push(format!("line {line}: not eight columns"));
            continue;
        };
        let [
            email,
            first_name,
            last_name,
            company_name,
            phone,
            website,
            linkedin,
            location,
        ] = fields;

        let address = match EmailAddress::parse(&email) {
            Ok(address) => address,
            Err(err) => {
                report
                    .refused
                    .push(format!("line {line}: email {email:?}: {err}"));
                continue;
            }
        };

        // `accounts.legal_name` is the name that goes on a contract and
        // `accounts.domain` would otherwise be a mailbox provider — the lists
        // hold 114 rows that are an address and nothing else, and one shared
        // `163.com` account holding sixty strangers is worse than not importing
        // them. A row with no company is not a prospect company.
        let company = company_name.trim();
        if company.is_empty() {
            report.refused.push(format!(
                "line {line}: {address}: no company_name, and an account is a company"
            ));
            continue;
        }

        let domain = match account_domain(&website, &address) {
            Ok(domain) => domain,
            Err(err) => {
                report.refused.push(format!(
                    "line {line}: {address}: website {website:?}: {err}"
                ));
                continue;
            }
        };

        let account = revenue_store::upsert_account(
            tx,
            Uuid::now_v7(),
            &NewAccount {
                legal_name: company,
                domain: domain.as_str(),
                segment: list.segment,
                country: list.country,
                employee_id: list.employee_id,
                location: some(&location),
                website: some(&website),
            },
        )
        .await?;
        match account {
            Upserted::Created(_) => {
                report.accounts_created += 1;
                if list.country == UNKNOWN_COUNTRY {
                    report.unknown_country += 1;
                }
            }
            Upserted::Existing(_) => report.accounts_existing += 1,
            // An account cannot opt out; `upsert_account` never says this.
            Upserted::Suppressed => report.suppressed += 1,
        }
        let Some(account_id) = account.id() else {
            continue;
        };

        // Joined, trimmed, and empty when the list gave nothing — never a
        // company name, never a local part, never "there". See the module docs.
        let joined = format!("{} {}", first_name.trim(), last_name.trim());
        let full_name = joined.trim();
        if full_name.is_empty() {
            report.nameless += 1;
        }
        if !linkedin.trim().is_empty() {
            report.linkedin_dropped += 1;
        }
        let e164_phone = e164(&phone);
        if e164_phone.is_none() && !phone.trim().is_empty() {
            report.phones_dropped += 1;
        }
        let normalised = address.to_string();

        let contact = revenue_store::upsert_contact(
            tx,
            Uuid::now_v7(),
            &NewContact {
                account_id,
                full_name,
                email: Some(normalised.as_str()),
                phone: e164_phone,
                role: None,
                // Not inferred from the country: the ECTAA list is one file with
                // twenty languages in it and a wrong tag writes to a German
                // association in Greek.
                language: None,
                // A directory does not know who the main line into a company is.
                // A reply does, and `contacts_primary_key` allows exactly one.
                is_primary: false,
                lawful_basis: LAWFUL_BASIS,
                next_follow_up_at: Some(now),
            },
        )
        .await?;
        match contact {
            Upserted::Created(_) => report.contacts_created += 1,
            Upserted::Existing(_) => report.contacts_existing += 1,
            Upserted::Suppressed => report.suppressed += 1,
        }
    }

    Ok(report)
}

/// The domain that identifies this account: the site's host without `www.`, or
/// the address's own domain when the row has no site.
fn account_domain(website: &str, address: &EmailAddress) -> Result<Domain, String> {
    if website.trim().is_empty() {
        return Ok(address.domain().clone());
    }
    let host = host_of(website.trim()).ok_or_else(|| "no host in it".to_owned())?;
    Domain::parse(host.strip_prefix("www.").unwrap_or(&host)).map_err(|err| err.to_string())
}

/// The host of a URL the founder typed, which may have no scheme:
/// `https://www.qyer.com/`, `http://www.2sage-alba.fr` and `safetywing.com` are
/// all things these lists contain.
fn host_of(website: &str) -> Option<String> {
    if let Ok(url) = url::Url::parse(website)
        && let Some(host) = url.host_str()
    {
        return Some(host.to_ascii_lowercase());
    }
    // No scheme: `Url::parse` calls the whole thing a relative reference.
    let bare = website
        .split(['/', '?', '#'])
        .next()?
        .split('@')
        .next_back()?;
    (!bare.is_empty()).then(|| bare.to_ascii_lowercase())
}

/// `None` for a field the list left blank, so a blank is a NULL and not an
/// empty string pretending to be data.
fn some(field: &str) -> Option<&str> {
    let field = field.trim();
    (!field.is_empty()).then_some(field)
}

/// The number if it is already E.164, and nothing if it is not. See the module
/// docs for why this does not try to make one.
fn e164(raw: &str) -> Option<&str> {
    let raw = raw.trim();
    let digits = raw.strip_prefix('+')?;
    let ok = (7..=15).contains(&digits.len())
        && digits.bytes().all(|b| b.is_ascii_digit())
        && digits.as_bytes().first() != Some(&b'0');
    ok.then_some(raw)
}

/// Split RFC 4180, with the line each record starts on.
///
/// ponytail: no `csv` crate, and this is the reading half `crate::queue::csv` is
/// the writing half of — thirty lines against a dependency, for a format whose
/// whole grammar is "a quote doubles itself". It handles what the founder's
/// files actually are: CRLF in twenty of them, LF in `smartlead_prospection.csv`,
/// and that one has no terminator on its last line.
fn records(text: &str) -> Vec<(usize, Vec<String>)> {
    let mut out = Vec::new();
    let mut record = vec![String::new()];
    let mut quoted = false;
    let mut line = 1usize;
    let mut started = 1usize;
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            // A doubled quote inside a quoted field is one quote.
            '"' if quoted && chars.peek() == Some(&'"') => {
                chars.next();
                push(&mut record, '"');
            }
            '"' => quoted = !quoted,
            ',' if !quoted => record.push(String::new()),
            '\r' | '\n' if !quoted => {
                if c == '\r' && chars.peek() == Some(&'\n') {
                    chars.next();
                }
                line += 1;
                out.push((started, std::mem::take(&mut record)));
                record.push(String::new());
                started = line;
            }
            // A newline *inside* quotes is data, and it still moves the file on.
            '\r' | '\n' => {
                line += 1;
                push(&mut record, c);
            }
            _ => push(&mut record, c),
        }
    }

    // A last line with no terminator is a record; a trailing terminator is not.
    if record.len() > 1 || !record[0].is_empty() {
        out.push((started, record));
    }
    out
}

fn push(record: &mut [String], c: char) {
    record
        .last_mut()
        .expect("a record always has at least one field")
        .push(c);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use agentos_store::db::Db;

    use super::*;

    /// The real thing, copied out of `~/Desktop/VOYAGEURS`: the header, a plain
    /// row, a row whose `company_name` contains a comma, and a row that is not
    /// ASCII. CRLF, no BOM, exactly as the founder's file is — and the same
    /// bytes `crate::queue`'s tests assert the export against, so the import and
    /// the export are proved against one file rather than two copies of one.
    const REAL: &str = include_str!("../tests/fixtures/smartlead_getorizn_prospection.csv");

    // -- the parser --------------------------------------------------------

    #[test]
    fn the_founders_own_header_is_the_one_this_reads() {
        let (line, header) = records(REAL).into_iter().next().expect("header");
        assert_eq!(line, 1);
        assert_eq!(header, COLUMNS[..8]);
    }

    #[test]
    fn a_quoted_comma_is_one_field_and_the_last_line_is_a_row() {
        let rows = records(REAL);
        assert_eq!(rows.len(), 4, "a header and the three real rows: {rows:?}");
        for (n, (line, fields)) in rows.iter().enumerate() {
            assert_eq!(*line, n + 1, "the line number is the file's own");
            assert_eq!(fields.len(), 8, "{fields:?}");
        }
        assert_eq!(rows[2].1[3], "Faye (Zenner, Inc.)");
        assert_eq!(rows[3].1[3], "穷游网 Qyer");
        assert_eq!(rows[1].1[7], "États-Unis");
    }

    /// `smartlead_prospection.csv` is LF and has no terminator on its last line,
    /// while the other twenty files are CRLF. Both are the founder's.
    #[test]
    fn lf_without_a_final_terminator_reads_the_same_as_crlf() {
        let crlf = "a,b\r\n1,2\r\n";
        let lf = "a,b\n1,2";
        assert_eq!(records(crlf), records(lf));
        assert_eq!(records(lf).len(), 2);
    }

    #[test]
    fn a_doubled_quote_is_one_quote_and_a_quoted_newline_is_not_a_row() {
        let rows = records("a,b\r\n\"say \"\"hi\"\"\",\"two\nlines\"\r\n");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].1, ["say \"hi\"", "two\nlines"]);
    }

    // -- what identifies an account ----------------------------------------

    #[test]
    fn the_site_identifies_an_account_and_the_address_only_when_there_is_none() {
        let at = |raw: &str| EmailAddress::parse(raw).expect("address");
        let domain = |site: &str, email: &str| {
            account_domain(site, &at(email))
                .expect("domain")
                .as_str()
                .to_owned()
        };

        // The `www.`, the scheme and the path are not the identity.
        assert_eq!(domain("https://www.qyer.com/", "bd@qyer.com"), "qyer.com");
        assert_eq!(
            domain("http://www.2sage-alba.fr", "i@x.com"),
            "2sage-alba.fr"
        );
        // A host with no scheme is still a host: the lists carry both.
        assert_eq!(
            domain("safetywing.com", "p@safetywing.com"),
            "safetywing.com"
        );
        // No public-suffix list, so the whole host is the account.
        assert_eq!(
            domain("http://aastravel.com.hk", "e@x.com"),
            "aastravel.com.hk"
        );
        // The 338 rows where the two disagree: the site wins, because the
        // booking flow is on the site.
        assert_eq!(
            domain("https://www.reisebueros.at", "r@wko.at"),
            "reisebueros.at"
        );
        // And with no site at all, the address is all there is.
        assert_eq!(
            domain("", "info@1stnortherninternational.com"),
            "1stnortherninternational.com"
        );
        assert_eq!(
            domain("   ", "info@1stnortherninternational.com"),
            "1stnortherninternational.com"
        );

        assert!(account_domain("https://", &at("a@b.com")).is_err());
    }

    #[test]
    fn only_a_number_that_is_already_e164_is_kept() {
        assert_eq!(e164("+441842816600"), Some("+441842816600"));
        assert_eq!(e164(" +85225437683 "), Some("+85225437683"));
        // The 584 the lists carry that this will not guess a country for.
        assert_eq!(e164("(02)83518906"), None);
        assert_eq!(e164("7916-8621"), None);
        assert_eq!(e164("+0441842816600"), None);
        assert_eq!(e164("+44184"), None);
        assert_eq!(e164(""), None);
    }

    // -- against the real tables -------------------------------------------

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; prospects tests need a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    async fn seed_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let label = format!("prospects-{}", tenant.as_uuid().simple());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)")
            .bind(tenant.as_uuid())
            .bind(&label)
            .bind(&label)
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    async fn drop_tenant(db: &Db, tenant: TenantId) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("delete tenant");
        tx.commit().await.expect("commit");
    }

    fn insurers() -> List<'static> {
        List {
            segment: "insurer",
            country: UNKNOWN_COUNTRY,
            employee_id: None,
        }
    }

    /// One account row, as the columns actually hold it.
    type Account = (
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
    );

    async fn accounts(tx: &mut TenantTx<'_>) -> Vec<Account> {
        sqlx::query_as(
            "SELECT legal_name, domain, segment, country, state, location, website \
               FROM accounts ORDER BY domain",
        )
        .fetch_all(&mut ***tx)
        .await
        .expect("accounts")
    }

    /// One contact row: name, address, phone, primary, active, basis, due.
    type Contact = (
        String,
        Option<String>,
        Option<String>,
        bool,
        bool,
        String,
        Option<DateTime<Utc>>,
    );

    async fn contacts(tx: &mut TenantTx<'_>) -> Vec<Contact> {
        sqlx::query_as(
            "SELECT full_name, email, phone, is_primary, active, lawful_basis, next_follow_up_at \
               FROM contacts ORDER BY email",
        )
        .fetch_all(&mut ***tx)
        .await
        .expect("contacts")
    }

    /// The strong one. Three rows of the founder's real file, asserted column by
    /// column against what the two tables end up holding.
    #[tokio::test]
    async fn the_founders_own_rows_become_the_rows_we_expect() {
        let Some(db) = db().await else { return };
        let tenant = seed_tenant(&db).await;
        let now = Utc::now();
        let mut tx = db.tenant_tx(tenant).await.expect("tx");

        let report = import(&mut tx, &insurers(), REAL, now)
            .await
            .expect("import");
        assert_eq!(report.rows, 3);
        assert_eq!(report.accounts_created, 3);
        assert_eq!(report.contacts_created, 3);
        assert_eq!(report.accounts_existing, 0);
        assert_eq!(report.contacts_existing, 0);
        assert_eq!(report.suppressed, 0);
        assert!(report.refused.is_empty(), "{:?}", report.refused);
        // Not one of these three people has a name, and the import did not give
        // them one.
        assert_eq!(report.nameless, 3);
        assert_eq!(report.unknown_country, 3);
        assert_eq!(report.phones_dropped, 0, "the fixture carries no phone");
        assert_eq!(report.linkedin_dropped, 0, "nor a linkedin_profile");

        // By domain, which is the order `accounts` is read in.
        assert_eq!(
            accounts(&mut tx).await,
            vec![
                (
                    "穷游网 Qyer".to_owned(),
                    "qyer.com".to_owned(),
                    "insurer".to_owned(),
                    "ZZ".to_owned(),
                    "candidate".to_owned(),
                    Some("Chine".to_owned()),
                    // The trailing slash is the founder's and it is kept.
                    Some("https://www.qyer.com/".to_owned()),
                ),
                (
                    "SafetyWing".to_owned(),
                    "safetywing.com".to_owned(),
                    "insurer".to_owned(),
                    "ZZ".to_owned(),
                    "candidate".to_owned(),
                    Some("États-Unis".to_owned()),
                    Some("https://safetywing.com".to_owned()),
                ),
                (
                    // The quoted comma survived the parser, and the derived
                    // domain dropped the `www.` the verbatim column keeps.
                    "Faye (Zenner, Inc.)".to_owned(),
                    "withfaye.com".to_owned(),
                    "insurer".to_owned(),
                    "ZZ".to_owned(),
                    "candidate".to_owned(),
                    Some("États-Unis".to_owned()),
                    Some("https://www.withfaye.com".to_owned()),
                ),
            ]
        );

        assert_eq!(
            contacts(&mut tx).await,
            vec![
                (
                    String::new(),
                    Some("bd@qyer.com".to_owned()),
                    None,
                    false,
                    true,
                    "legitimate_interest".to_owned(),
                    Some(now),
                ),
                (
                    String::new(),
                    Some("partnerships@safetywing.com".to_owned()),
                    None,
                    false,
                    true,
                    "legitimate_interest".to_owned(),
                    Some(now),
                ),
                (
                    String::new(),
                    Some("partnerships@withfaye.com".to_owned()),
                    None,
                    false,
                    true,
                    "legitimate_interest".to_owned(),
                    Some(now),
                ),
            ]
        );

        // And they are in the queue the seller reads, which is the whole point
        // of importing them.
        let due = agentos_store::revenue::contacts_due_for_follow_up(&mut tx, now, 100)
            .await
            .expect("due");
        assert_eq!(due.len(), 3);

        tx.rollback().await.expect("rollback");
        drop_tenant(&db, tenant).await;
    }

    /// He will run it twice. He will also run `getorizn` and `oriznapi`, which
    /// are the same 1,100 people under two sending domains.
    #[tokio::test]
    async fn importing_the_same_list_twice_changes_nothing() {
        let Some(db) = db().await else { return };
        let tenant = seed_tenant(&db).await;
        let now = Utc::now();
        let mut tx = db.tenant_tx(tenant).await.expect("tx");

        let first = import(&mut tx, &insurers(), REAL, now).await.expect("one");
        let before = (accounts(&mut tx).await, contacts(&mut tx).await);

        let second = import(
            &mut tx,
            &insurers(),
            REAL,
            now + chrono::TimeDelta::hours(1),
        )
        .await
        .expect("two");

        assert!(first.wrote_anything());
        assert!(!second.wrote_anything(), "{second:?}");
        assert_eq!(second.rows, 3);
        assert_eq!(second.accounts_created, 0);
        assert_eq!(second.contacts_created, 0);
        assert_eq!(second.accounts_existing, 3);
        assert_eq!(second.contacts_existing, 3);
        assert!(second.refused.is_empty(), "{:?}", second.refused);

        // Not one column moved — including `next_follow_up_at`, which the second
        // run passed a different `now` for. A re-import that rescheduled the
        // whole list would be a re-import that mails it again.
        assert_eq!((accounts(&mut tx).await, contacts(&mut tx).await), before);

        tx.rollback().await.expect("rollback");
        drop_tenant(&db, tenant).await;
    }

    /// The legal boundary, from both directions: an address suppressed before
    /// the import never becomes a contact, and one suppressed after it is not
    /// woken up by the next import.
    #[tokio::test]
    async fn a_suppressed_address_does_not_come_back() {
        let Some(db) = db().await else { return };
        let tenant = seed_tenant(&db).await;
        let now = Utc::now();
        let mut tx = db.tenant_tx(tenant).await.expect("tx");

        // Before: this address is on the list already.
        agentos_store::revenue::suppress(
            &mut tx,
            Uuid::now_v7(),
            &agentos_store::revenue::NewSuppression {
                scope: agentos_store::revenue::Scope::Tenant,
                channel: agentos_store::revenue::Channel::Email,
                address: "bd@qyer.com",
                reason: "opt_out",
                contact_id: None,
                note: Some("replied STOP"),
                suppressed_at: now,
            },
        )
        .await
        .expect("suppress");

        let report = import(&mut tx, &insurers(), REAL, now)
            .await
            .expect("import");
        assert_eq!(report.suppressed, 1);
        assert_eq!(report.contacts_created, 2, "the other two are contactable");
        let addresses: Vec<Option<String>> =
            contacts(&mut tx).await.into_iter().map(|c| c.1).collect();
        assert!(
            !addresses.contains(&Some("bd@qyer.com".to_owned())),
            "an opted-out address must not become a contact row: {addresses:?}"
        );

        // After: an address that opts out *between* two imports. The suppression
        // deactivates the row it names; the second import must not undo that.
        agentos_store::revenue::suppress(
            &mut tx,
            Uuid::now_v7(),
            &agentos_store::revenue::NewSuppression {
                scope: agentos_store::revenue::Scope::Tenant,
                channel: agentos_store::revenue::Channel::Email,
                address: "partnerships@safetywing.com",
                reason: "opt_out",
                contact_id: None,
                note: None,
                suppressed_at: now,
            },
        )
        .await
        .expect("suppress");

        let again = import(&mut tx, &insurers(), REAL, now)
            .await
            .expect("again");
        assert_eq!(again.suppressed, 2, "both of them, now");
        assert_eq!(again.contacts_created, 0);

        let stopped: (bool, Option<DateTime<Utc>>) = sqlx::query_as(
            "SELECT active, next_follow_up_at FROM contacts WHERE email = 'partnerships@safetywing.com'",
        )
        .fetch_one(&mut **tx)
        .await
        .expect("row");
        assert_eq!(
            stopped,
            (false, None),
            "an import may not re-activate an opt-out or put it back in the queue"
        );

        let due = agentos_store::revenue::contacts_due_for_follow_up(&mut tx, now, 100)
            .await
            .expect("due");
        assert_eq!(due.len(), 1, "only the one who never opted out");

        tx.rollback().await.expect("rollback");
        drop_tenant(&db, tenant).await;
    }

    /// 0 of the 150 rows in the DMW list have a first name — they are `info@`
    /// inboxes. That is a fact to record, not a hole to fill.
    #[tokio::test]
    async fn a_row_with_no_first_name_imports_without_inventing_one() {
        let Some(db) = db().await else { return };
        let tenant = seed_tenant(&db).await;
        let now = Utc::now();
        let mut tx = db.tenant_tx(tenant).await.expect("tx");

        // Two real DMW rows and one that does have a name, so the join is
        // proved in both directions.
        let list = format!(
            "{}\r\n\
             info@1stnortherninternational.com,,,1ST NORTHERN INTERNATIONAL PLACEMENT INC,7916-8621,,,\"Mandaluyong, Philippines\"\r\n\
             recruitment@21stcmri.com,,,21ST CENTURY MANPOWER RESOURCES INC,(02)83518906,,,\"Quezon City, Philippines\"\r\n\
             anke@lufthansa.com,Anke,Vogel,Deutsche Lufthansa AG,+4915112345678,https://www.lufthansa.com,,Germany\r\n",
            COLUMNS[..8].join(",")
        );

        let list_of = List {
            segment: "relocation",
            country: "PH",
            employee_id: None,
        };
        let report = import(&mut tx, &list_of, &list, now).await.expect("import");
        assert_eq!(report.contacts_created, 3);
        assert_eq!(report.nameless, 2);
        assert!(report.refused.is_empty(), "{:?}", report.refused);
        // Two of the three phone numbers are not E.164 and were not bent into
        // one; the report says so out loud.
        assert_eq!(report.phones_dropped, 2);
        assert!(
            report.summary().contains("2 phone numbers are not E.164"),
            "{}",
            report.summary()
        );
        assert!(
            report.summary().contains("Smartlead's API"),
            "the September problem is in the report the founder reads: {}",
            report.summary()
        );
        assert_eq!(report.unknown_country, 0, "--country PH was passed");

        let rows = contacts(&mut tx).await;
        assert_eq!(rows[0].0, "Anke Vogel", "a name that is there is stored");
        assert_eq!(rows[0].2, Some("+4915112345678".to_owned()));
        assert_eq!(rows[1].0, "", "and one that is not is not invented");
        assert_eq!(rows[1].2, None, "nor is a country guessed for its phone");
        assert_eq!(rows[2].0, "");

        // The number the founder has to decide about before September.
        let nameless: i64 =
            sqlx::query_scalar("SELECT count(*) FROM contacts WHERE full_name = ''")
                .fetch_one(&mut **tx)
                .await
                .expect("count");
        assert_eq!(nameless, 2);

        tx.rollback().await.expect("rollback");
        drop_tenant(&db, tenant).await;
    }

    /// One bad line in a thousand is a typo. Refusing the other 999 over it is
    /// not a service to anybody, so a row is refused by name and the batch goes
    /// on — and the report is where the founder finds out.
    #[tokio::test]
    async fn a_malformed_row_is_refused_by_name_and_the_batch_survives() {
        let Some(db) = db().await else { return };
        let tenant = seed_tenant(&db).await;
        let now = Utc::now();
        let mut tx = db.tenant_tx(tenant).await.expect("tx");

        let list = format!(
            "{}\r\n\
             good@example.com,,,Good Ltd,,https://good.example,,France\r\n\
             not-an-address,,,Broken Ltd,,https://broken.example,,France\r\n\
             lyj010124@163.com,,,,,,,\r\n\
             short@example.com,,,Short Ltd\r\n\
             linked@example.com,,,Linked Ltd,,https://linked.example,https://linkedin.com/in/x,France\r\n\
             also@example.com,,,Also Ltd,,https://also.example,,France\r\n",
            COLUMNS[..8].join(",")
        );

        let report = import(&mut tx, &insurers(), &list, now)
            .await
            .expect("import");
        assert_eq!(report.rows, 6);
        assert_eq!(report.contacts_created, 3, "good, linked and also");
        assert_eq!(report.refused.len(), 3);

        let refused = report.refused.join("\n");
        assert!(refused.contains("line 3"), "{refused}");
        assert!(refused.contains("not-an-address"), "{refused}");
        assert!(
            refused.contains("line 4") && refused.contains("no company_name"),
            "an address with no company is refused by name rather than filed \
             under its mailbox provider: {refused}"
        );
        assert!(
            refused.contains("line 5") && refused.contains("not eight columns"),
            "{refused}"
        );
        assert!(
            !refused.contains("line 6"),
            "a linkedin_profile is not fatal"
        );

        // It was not stored either, and the report is where that is said.
        assert_eq!(report.linkedin_dropped, 1);
        assert!(
            report
                .summary()
                .contains("linkedin_profile, which has no column"),
            "{}",
            report.summary()
        );

        // The refusals are per row: everything else is in the database.
        let addresses: Vec<Option<String>> =
            contacts(&mut tx).await.into_iter().map(|c| c.1).collect();
        assert_eq!(
            addresses,
            vec![
                Some("also@example.com".to_owned()),
                Some("good@example.com".to_owned()),
                Some("linked@example.com".to_owned()),
            ]
        );

        tx.rollback().await.expect("rollback");
        drop_tenant(&db, tenant).await;
    }

    /// A file that is not a Smartlead list, and arguments the CHECK constraints
    /// would refuse: all three are decided before anything is written.
    #[tokio::test]
    async fn a_wrong_header_or_a_wrong_argument_is_refused_before_the_first_write() {
        let Some(db) = db().await else { return };
        let tenant = seed_tenant(&db).await;
        let now = Utc::now();
        let mut tx = db.tenant_tx(tenant).await.expect("tx");

        let contexte = "email,segment,angle_email,score_global\r\na@b.com,ota,hi,9\r\n";
        let err = import(&mut tx, &insurers(), contexte, now)
            .await
            .expect_err("not a list");
        assert!(matches!(err, ImportError::Header(_)), "{err}");
        assert!(err.to_string().contains("linkedin_profile"), "{err}");

        let wrong_segment = List {
            segment: "cruise_line",
            country: UNKNOWN_COUNTRY,
            employee_id: None,
        };
        let err = import(&mut tx, &wrong_segment, REAL, now)
            .await
            .expect_err("bad segment");
        assert!(matches!(err, ImportError::Segment(_)), "{err}");

        let wrong_country = List {
            segment: "other",
            country: "Philippines",
            employee_id: None,
        };
        let err = import(&mut tx, &wrong_country, REAL, now)
            .await
            .expect_err("bad country");
        assert!(matches!(err, ImportError::Country(_)), "{err}");

        assert!(accounts(&mut tx).await.is_empty(), "nothing was written");

        tx.rollback().await.expect("rollback");
        drop_tenant(&db, tenant).await;
    }

    /// [`SEGMENTS`] is a copy of a CHECK constraint, so it is checked against
    /// the constraint rather than against the file it was copied from.
    #[tokio::test]
    async fn a_segment_the_check_refuses_is_refused_before_the_database_sees_it() {
        let Some(db) = db().await else { return };
        let tenant = seed_tenant(&db).await;
        let now = Utc::now();
        let mut tx = db.tenant_tx(tenant).await.expect("tx");

        for segment in SEGMENTS {
            let list = format!(
                "{}\r\n{segment}@example.com,,,{segment} Ltd,,https://{segment}.example,,France\r\n",
                COLUMNS[..8].join(",")
            );
            let list_of = List {
                segment,
                country: "FR",
                employee_id: None,
            };
            let report = import(&mut tx, &list_of, &list, now)
                .await
                .unwrap_or_else(|err| {
                    panic!("{segment} is not a segment this schema takes: {err}")
                });
            assert_eq!(report.accounts_created, 1, "{segment}");
        }
        assert_eq!(accounts(&mut tx).await.len(), SEGMENTS.len());

        tx.rollback().await.expect("rollback");
        drop_tenant(&db, tenant).await;
    }
}

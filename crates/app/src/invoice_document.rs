//! The invoice as a document: a PDF written by hand and filed under its number.
//!
//! `invoices` (0066, 0071) is the register — what is owed, to whom, numbered
//! without a gap. A customer does not pay a row; they pay a document they can
//! open, forward to accounts payable and archive. This module renders that
//! document from the row, at issue time, into the same transaction that claimed
//! the number, and [`file`] deposits it in `files` (0067) as
//! `invoice-<number>.pdf` — so the register and the classeur cannot disagree
//! about which documents went out.
//!
//! # Why the PDF is written by hand
//!
//! ponytail: no PDF crate. The workspace has none, and a document of one page,
//! one built-in font and a few dozen lines of text is exactly the subset PDF
//! 1.4 lets you write in eighty lines: a catalog, a page tree, one page, one
//! font object, one content stream, an xref table whose offsets are counted as
//! the bytes are pushed. What a library would add — layout, embedded fonts,
//! compression, forms — is what an invoice does not need. Pull one in the day
//! a customer asks for a logo.
//!
//! # The one thing this file must get right: escaping
//!
//! The account's legal name, the memo and every line's description are text
//! somebody outside this process typed — a prospect list, an operator, a model.
//! In a PDF string literal `(`, `)` and `\` are syntax; a name like
//! `Acme) Tj ET` would end the string and continue as content-stream
//! operators. [`text`] is the only place text enters the stream and it escapes
//! all three, plus every byte outside printable ASCII, which it emits as an
//! octal escape in WinAnsi — so a French `é` renders, and a control character
//! becomes a space rather than a line break inside a literal. Nothing is
//! interpolated into the stream by any other path, and
//! [`Untrusted::into_inner_for_rendering`] is called exactly there, so the
//! audit grep for that method finds this file once.
//!
//! # The mentions, and the one thing this document may never print
//!
//! A French invoice is not a total with a name on it: it carries the issuer's
//! legal identity, a breakdown by VAT rate, and what is owed for paying late.
//! Those facts belong to the tenant, not to this product, and `0087` puts them
//! on `tenants` — [`agentos_store::invoices::Issuer`] reads them and
//! [`Issuer::missing_mentions`] says which of them are absent.
//!
//! Two rules hold this file together:
//!
//! * **A rate of zero is never printed as a rate.** A company outside VAT owes a
//!   *sentence* — franchise en base, autoliquidation, exonération — and
//!   "TVA 0,00 %" is a different claim that happens to produce the same total.
//!   [`ventilate`] drops a zero into [`Ventilation::untaxed_minor`], and
//!   [`ventilation_lines`] prints either the tenant's sentence or a line saying
//!   the mention is missing. Neither can be misread as a rate.
//! * **A document that cannot carry the mentions says so on its face.** The
//!   refusal belongs on the surface that emits — `POST /v1/invoices/{id}/credit`
//!   makes it, naming the missing mentions — but this renderer is downstream of
//!   a path that does not (`Effects::issue_invoice`, whose transaction is not
//!   this crate's to change), so a PDF built from an incomplete issuer opens
//!   with `FACTURE NON CONFORME` and the list. An invoice that is not issuable
//!   must not be indistinguishable from one that is.
//!
//! # French, deliberately
//!
//! The labels are in the founder's language, because the recipient is the
//! founder's customer and the roadmap that asked for this document is written
//! in it. A per-tenant language is a column nobody has asked for.

use agentos_domain::money::Currency;
use agentos_domain::untrusted::Untrusted;
use agentos_store::db::{StoreError, TenantTx};
use agentos_store::files::{self, Filed};
use agentos_store::invoices::{self, Invoice, Issuer, Line, Parties};
use chrono::{DateTime, Utc};

use crate::files::digest_of;

/// What the classeur records the document as.
pub const CONTENT_TYPE: &str = "application/pdf";

/// The statutory fixed indemnity for recovery costs, in euro cents.
///
/// Article D441-5 of the code de commerce: forty euros, the same forty for every
/// company, so it is a constant of this module and not a tenant setting — a
/// column would let a customer write zero into a figure the law fixes. In euros
/// whatever the invoice is denominated in, because the article is about euros
/// and not about the currency two companies agreed to trade in; the line names
/// the currency explicitly for that reason.
const RECOVERY_INDEMNITY_EUR_MINOR: i64 = 4_000;

// ---------------------------------------------------------------------------
// The ventilation
// ---------------------------------------------------------------------------

/// One VAT band: everything taxed at one rate, and the tax on their *sum*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Band {
    /// Basis points. 2000 is 20,00 %. Never zero — see [`ventilate`].
    pub rate_bp: i32,
    /// The taxable base at this rate, in the invoice's minor units. Signed: a
    /// discount line is negative.
    pub base_minor: i64,
    /// The tax on [`Band::base_minor`], rounded **once**.
    pub tax_minor: i64,
}

/// What a French invoice has to show below its lines.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ventilation {
    /// One entry per rate, ascending, so two documents built from the same
    /// lines in a different order print the same table.
    pub bands: Vec<Band>,
    /// The base carrying no rate at all. Not a zero-rated band: see
    /// [`ventilate`].
    pub untaxed_minor: i64,
    /// Total excluding tax — the figure the register stores as the invoice's
    /// amount.
    pub base_minor: i64,
    /// The sum of the bands' tax.
    pub tax_minor: i64,
    /// Total including tax. What the customer pays.
    pub total_minor: i64,
}

/// Split lines into bands and total them.
///
/// `default_rate_bp` is the issuer's rate ([`Issuer::vat_rate_bp`]); a line's
/// own [`Line::tax_rate_bp`] overrides it, which is what makes an invoice at two
/// rates representable.
///
/// # The rounding happens once, per rate, on the total
///
/// **The bases are summed first and the rate is applied to the sum**, never to
/// each line with the results added afterwards. The two disagree, routinely, by
/// a centime: three lines of €10.01 at 20 % round to 2.00 each and sum to 6.00,
/// while their base of 30.03 rounds to 6.01. The second is the answer French
/// practice expects — the tax is due on the taxable base, and the base is the
/// band, not the line — and it is also the only one that stays stable when
/// somebody splits one line into two. Half away from zero on the exact tie, so a
/// credit note rounds the mirror image of the invoice it withdraws.
///
/// # Why a rate of zero is not a rate
///
/// `invoice_lines.tax_rate_bp` admits `0` (0071 declined to bound it) and
/// `tenants.vat_rate_bp` does not (0087). A zero here is read as *no rate*: it
/// falls into [`Ventilation::untaxed_minor`], where the document has to print
/// the mention that replaces VAT, rather than into a band printing
/// "TVA 0,00 %" — a sentence that asserts a rate nobody chose.
pub fn ventilate(lines: &[Line], default_rate_bp: Option<i32>) -> Ventilation {
    let mut bases: std::collections::BTreeMap<i32, i64> = std::collections::BTreeMap::new();
    let mut untaxed_minor = 0i64;
    for line in lines {
        match line.tax_rate_bp.or(default_rate_bp).filter(|bp| *bp > 0) {
            Some(rate_bp) => {
                let base = bases.entry(rate_bp).or_default();
                *base = base.saturating_add(line.amount_minor);
            }
            None => untaxed_minor = untaxed_minor.saturating_add(line.amount_minor),
        }
    }

    let bands: Vec<Band> = bases
        .into_iter()
        .map(|(rate_bp, base_minor)| Band {
            rate_bp,
            base_minor,
            tax_minor: tax_on(base_minor, rate_bp),
        })
        .collect();

    let base_minor = bands.iter().fold(untaxed_minor, |acc, band| {
        acc.saturating_add(band.base_minor)
    });
    let tax_minor = bands
        .iter()
        .fold(0i64, |acc, band| acc.saturating_add(band.tax_minor));
    Ventilation {
        bands,
        untaxed_minor,
        base_minor,
        tax_minor,
        total_minor: base_minor.saturating_add(tax_minor),
    }
}

/// `base * rate_bp / 10000`, rounded half away from zero, in `i128` so the
/// product cannot wrap.
fn tax_on(base_minor: i64, rate_bp: i32) -> i64 {
    let numerator = i128::from(base_minor) * i128::from(rate_bp);
    let denominator = 10_000i128;
    let magnitude = (numerator.abs() + denominator / 2) / denominator;
    let signed = if numerator.is_negative() {
        -magnitude
    } else {
        magnitude
    };
    // Unreachable while a rate is <= 100 % — the tax is then no larger than the
    // base — and 0071 bounds `invoice_lines.tax_rate_bp` from below only.
    i64::try_from(signed).unwrap_or(if signed.is_negative() {
        i64::MIN
    } else {
        i64::MAX
    })
}

/// Where the document lives in `files`: named by the number a human quotes,
/// and by its kind, so a credit note is not mistaken for the demand it
/// withdraws.
pub fn file_name(invoice: &Invoice) -> String {
    let kind = if invoice.corrects_invoice_id.is_some() {
        "credit-note"
    } else {
        "invoice"
    };
    format!("{kind}-{}.pdf", invoice.number)
}

/// Render and deposit, in the caller's transaction.
///
/// Reads the parties and, for a credit note, the number of the invoice it
/// corrects, so the document says "avoir n° 43, corrige la facture n° 42" and
/// not a uuid. [`StoreError::Conflict`] on `files_pkey` means the number was
/// filed already, which cannot happen for a number claimed in this same
/// transaction — and if it ever does, the write is refused rather than
/// overwritten, which is `0067`'s rule.
pub async fn file(tx: &mut TenantTx<'_>, invoice: &Invoice) -> Result<Filed, StoreError> {
    let parties = invoices::parties(tx, invoice.opportunity_id).await?;
    let corrects = match invoice.corrects_invoice_id {
        Some(id) => invoices::find(tx, id)
            .await?
            .map(|corrected| corrected.number),
        None => None,
    };
    let bytes = render(invoice, &parties, corrects);
    files::deposit(
        tx,
        &file_name(invoice),
        CONTENT_TYPE,
        &bytes,
        &digest_of(&bytes),
    )
    .await
}

/// The document's bytes. Pure, so a test can assert on them without a
/// database.
///
/// `corrects` is the number of the invoice a credit note withdraws, and is
/// ignored on an invoice.
pub fn render(invoice: &Invoice, parties: &Parties, corrects: Option<i64>) -> Vec<u8> {
    let currency = invoice.amount.currency();
    let issuer = &parties.issuer;
    let mut lines: Vec<String> = Vec::new();

    // The banner, first, and only when it is earned. A document that cannot
    // carry the mentions must not be mistaken for one that does — see the
    // module docs.
    let missing = issuer.missing_mentions();
    if !missing.is_empty() {
        lines.push(text(Untrusted::new(format!(
            "FACTURE NON CONFORME - mentions obligatoires absentes : {}",
            missing.join(", ")
        ))));
        lines.push(String::new());
    }

    // The letterhead: who is asking to be paid, in the terms an invoice has to
    // name them.
    lines.push(text(Untrusted::new(issuer.to_string())));
    if let Some(address) = &issuer.address {
        lines.push(text(Untrusted::new(address.clone())));
    }
    if let Some(siren) = &issuer.siren {
        lines.push(text(Untrusted::new(match &issuer.rcs_city {
            Some(city) => format!("SIREN {siren} - RCS {city}"),
            None => format!("SIREN {siren}"),
        })));
    }
    if let Some(vat_number) = &issuer.vat_number {
        lines.push(text(Untrusted::new(format!(
            "TVA intracommunautaire : {vat_number}"
        ))));
    }
    lines.push(String::new());
    match corrects {
        Some(number) => {
            lines.push(text(Untrusted::new(format!("Avoir n° {}", invoice.number))));
            lines.push(text(Untrusted::new(format!(
                "Corrige la facture n° {number}"
            ))));
        }
        None => lines.push(text(Untrusted::new(format!(
            "Facture n° {}",
            invoice.number
        )))),
    }
    lines.push(text(Untrusted::new(format!(
        "Émise le {}",
        day(invoice.issued_at)
    ))));
    // The date of the supply. This schema records no separate service date, and
    // inventing a column for one nothing writes would be worse than saying which
    // date is being offered: for a service billed when it is delivered the two
    // are the same day, and the label says which day it is.
    lines.push(text(Untrusted::new(format!(
        "Date de la prestation : {}",
        day(invoice.issued_at)
    ))));
    lines.push(text(Untrusted::new(format!(
        "Échéance : {}",
        invoice
            .due_at
            .map_or_else(|| "non convenue".to_owned(), day)
    ))));
    lines.push(String::new());
    lines.push(text(Untrusted::new(format!("Émetteur : {issuer}"))));
    lines.push(text(Untrusted::new(format!(
        "Destinataire : {}",
        parties.account
    ))));
    lines.push(String::new());
    lines.push(text(Untrusted::new(format!("Objet : {}", invoice.memo))));
    lines.push(String::new());

    // An invoice with no lines is its memo: one line, the whole amount, so the
    // ventilation below has a base to work on either way. `amount` is a `Money`
    // and stays one until here — the cast is the same one `invoices::issue`
    // makes to write the column.
    let head = [Line {
        description: invoice.memo.clone(),
        amount_minor: i64::try_from(invoice.amount.minor()).unwrap_or(i64::MAX),
        tax_rate_bp: None,
    }];
    let billed: &[Line] = if invoice.lines.is_empty() {
        &head
    } else {
        &invoice.lines
    };
    for line in billed {
        let rate = line
            .tax_rate_bp
            .or(issuer.vat_rate_bp)
            .filter(|bp| *bp > 0)
            .map_or(String::new(), |bp| format!("  ({})", rate_of(bp)));
        lines.push(text(Untrusted::new(format!(
            "{}    {} {}{rate}",
            line.description,
            currency.code(),
            minor(line.amount_minor, currency.exponent()),
        ))));
    }
    lines.push(String::new());
    lines.extend(ventilation_lines(
        &ventilate(billed, issuer.vat_rate_bp),
        issuer,
        currency,
    ));
    lines.push(String::new());
    lines.extend(late_payment_lines(issuer));

    // The content stream: one text object, 11pt Helvetica, a 14pt leading,
    // starting near the top-left of an A4 page.
    let mut stream = String::from("BT /F1 11 Tf 14 TL 50 790 Td\n");
    for line in &lines {
        stream.push('(');
        stream.push_str(line);
        stream.push_str(") Tj T*\n");
    }
    stream.push_str("ET\n");

    document(&stream)
}

/// A rate in basis points, as a percentage: `2000` is `"20.00 %"`.
///
/// A decimal point and not a comma, which is not the French typography and is
/// deliberate: every other figure this document prints goes through [`minor`],
/// which writes a point, and one document that punctuates two figures two ways
/// is harder to read than one that is consistently anglophone about decimals.
fn percent(bp: i32) -> String {
    format!("{}.{:02} %", bp / 100, (bp % 100).abs())
}

fn rate_of(bp: i32) -> String {
    format!("TVA {}", percent(bp))
}

/// The block below the lines: the base, the tax by rate, and the total due.
///
/// Takes the [`Issuer`] as well as the [`Ventilation`] because the *absence* of
/// tax is a sentence the issuer owns and the arithmetic cannot supply — see the
/// module docs on why a zero is never printed as a rate.
fn ventilation_lines(v: &Ventilation, issuer: &Issuer, currency: Currency) -> Vec<String> {
    let money = |amount: i64| format!("{} {}", currency.code(), minor(amount, currency.exponent()));
    // Either the tenant's own sentence, or a refusal that cannot be read as a
    // rate of zero. This is the line the module docs promise.
    let no_vat = match &issuer.vat_exemption_reason {
        Some(reason) => reason.clone(),
        None => "TVA : mention obligatoire absente - ni taux ni motif".to_owned(),
    };

    let mut out = vec![text(Untrusted::new(format!(
        "Total HT : {}",
        money(v.base_minor)
    )))];
    if v.bands.is_empty() {
        // Nothing is taxed: the mention *replaces* the tax lines, it does not
        // sit beside a zero.
        out.push(text(Untrusted::new(no_vat)));
        out.push(text(Untrusted::new(format!(
            "Total à payer : {}",
            money(v.total_minor)
        ))));
        return out;
    }
    for band in &v.bands {
        out.push(text(Untrusted::new(format!(
            "{} sur {} : {}",
            rate_of(band.rate_bp),
            money(band.base_minor),
            money(band.tax_minor)
        ))));
    }
    if v.untaxed_minor != 0 {
        out.push(text(Untrusted::new(format!(
            "Dont base hors TVA : {} - {no_vat}",
            money(v.untaxed_minor)
        ))));
    }
    out.push(text(Untrusted::new(format!(
        "Total TVA : {}",
        money(v.tax_minor)
    ))));
    out.push(text(Untrusted::new(format!(
        "Total TTC : {}",
        money(v.total_minor)
    ))));
    out
}

/// What is owed for paying late. Both mentions are obligatory between
/// professionals, and the second is the law's own figure — see
/// [`RECOVERY_INDEMNITY_EUR_MINOR`].
fn late_payment_lines(issuer: &Issuer) -> Vec<String> {
    vec![
        text(Untrusted::new(match issuer.late_penalty_rate_bp {
            Some(bp) => format!(
                "Pénalités de retard : {} l'an, exigibles dès le lendemain de l'échéance.",
                percent(bp)
            ),
            None => "Pénalités de retard : mention obligatoire absente.".to_owned(),
        })),
        text(Untrusted::new(format!(
            "Indemnité forfaitaire pour frais de recouvrement : EUR {} (art. D441-5 du code de \
             commerce).",
            minor(RECOVERY_INDEMNITY_EUR_MINOR, 2)
        ))),
    ]
}

/// Escape one line of text into a PDF string literal body.
///
/// The single exit from [`Untrusted`] in this module: see the module docs.
fn text(raw: Untrusted<String>) -> String {
    let raw = raw.into_inner_for_rendering();
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '(' | ')' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            ' '..='~' => out.push(c),
            // Latin-1 is WinAnsi for every letter French needs; a byte the
            // font cannot draw is a question mark, not an invisible one.
            c if (0xA0..=0xFF).contains(&(c as u32)) => {
                out.push_str(&format!("\\{:03o}", c as u32));
            }
            // A control character inside a literal would either vanish or
            // break a line where the layout did not plan one.
            c if c.is_control() => out.push(' '),
            _ => out.push('?'),
        }
    }
    out
}

/// Wrap one content stream in the smallest valid PDF 1.4 file.
///
/// Offsets are taken as the objects are pushed, which is the whole of what an
/// xref table is; the reader that only ever reads `%PDF-` will not notice, and
/// the one that checks every offset will find them exact.
fn document(stream: &str) -> Vec<u8> {
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] \
         /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
            .to_owned(),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
            .to_owned(),
        format!("<< /Length {} >>\nstream\n{stream}endstream", stream.len()),
    ];

    let mut out = String::from("%PDF-1.4\n");
    let mut offsets = Vec::with_capacity(objects.len());
    for (index, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.push_str(&format!("{} 0 obj\n{body}\nendobj\n", index + 1));
    }
    let xref = out.len();
    out.push_str(&format!("xref\n0 {}\n", objects.len() + 1));
    // Twenty bytes per entry, exactly: ten digits, five digits, a keyword and
    // a two-character line end.
    out.push_str("0000000000 65535 f \n");
    for offset in offsets {
        out.push_str(&format!("{offset:010} 00000 n \n"));
    }
    out.push_str(&format!(
        "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
        objects.len() + 1
    ));
    out.into_bytes()
}

fn day(at: DateTime<Utc>) -> String {
    at.format("%Y-%m-%d").to_string()
}

/// A signed figure in minor units, in the currency's decimal places.
fn minor(amount: i64, exponent: u32) -> String {
    let sign = if amount < 0 { "-" } else { "" };
    let magnitude = amount.unsigned_abs();
    if exponent == 0 {
        return format!("{sign}{magnitude}");
    }
    let unit = 10u64.pow(exponent);
    format!(
        "{sign}{}.{:0width$}",
        magnitude / unit,
        magnitude % unit,
        width = exponent as usize
    )
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::{EmployeeId, InvoiceId};
    use agentos_domain::money::{Currency, Money};
    use agentos_store::invoices::Line;

    use super::*;

    fn invoice(memo: &str) -> Invoice {
        let now = Utc::now();
        Invoice {
            id: InvoiceId::new_v7(now),
            number: 42,
            opportunity_id: uuid::Uuid::now_v7(),
            issued_by: Some(EmployeeId::new_v7(now)),
            amount: Money::new(120_000, Currency::Eur).expect("nonzero"),
            memo: memo.to_owned(),
            corrects_invoice_id: None,
            issued_at: now,
            due_at: None,
            paid_at: None,
            lines: vec![
                Line {
                    description: "Licence".to_owned(),
                    amount_minor: 125_000,
                    tax_rate_bp: Some(2000),
                },
                Line {
                    description: "Remise".to_owned(),
                    amount_minor: -5_000,
                    tax_rate_bp: None,
                },
            ],
        }
    }

    /// A company that may issue: every obligatory mention written down, at
    /// 20 %.
    fn issuer() -> Issuer {
        Issuer {
            name: "Orizn".to_owned(),
            legal_form: Some("SAS".to_owned()),
            address: Some("12 rue de la Paix, 75002 Paris".to_owned()),
            siren: Some("123456789".to_owned()),
            rcs_city: Some("Paris".to_owned()),
            vat_number: Some("FR12123456789".to_owned()),
            vat_rate_bp: Some(2000),
            vat_exemption_reason: None,
            late_penalty_rate_bp: Some(1200),
        }
    }

    fn parties() -> Parties {
        Parties {
            issuer: issuer(),
            account: "Buyer plc".to_owned(),
            contact_email: Some("ap@buyer.example".to_owned()),
        }
    }

    fn parties_of(issuer: Issuer) -> Parties {
        Parties {
            issuer,
            ..parties()
        }
    }

    /// The header, the number, the parties, the lines and the total are in
    /// the bytes; the xref offsets point where they claim to.
    #[test]
    fn a_rendered_invoice_is_a_pdf_that_names_its_number() {
        let bytes = render(&invoice("March"), &parties(), None);
        let text = String::from_utf8_lossy(&bytes);
        assert!(bytes.starts_with(b"%PDF-1.4\n"));
        assert!(text.contains("(Facture n\\260 42) Tj"), "{text}");
        assert!(text.contains("(Destinataire : Buyer plc) Tj"));
        assert!(text.contains("(Licence    EUR 1250.00  \\(TVA 20.00 %\\)) Tj"));
        // The discount carries no rate of its own and inherits the issuer's,
        // which is what puts it in the 20 % band below.
        assert!(text.contains("(Remise    EUR -50.00  \\(TVA 20.00 %\\)) Tj"));
        assert!(text.contains("(Total HT : EUR 1200.00) Tj"));
        assert!(text.contains("(TVA 20.00 % sur EUR 1200.00 : EUR 240.00) Tj"));
        assert!(text.contains("(Total TVA : EUR 240.00) Tj"));
        assert!(text.contains("(Total TTC : EUR 1440.00) Tj"));
        // The letterhead and the late-payment mentions.
        assert!(text.contains("(Orizn SAS) Tj"));
        assert!(text.contains("(SIREN 123456789 - RCS Paris) Tj"));
        assert!(text.contains("(TVA intracommunautaire : FR12123456789) Tj"));
        assert!(
            text.contains("nalit\\351s de retard : 12.00 % l'an"),
            "{text}"
        );
        assert!(text.contains("frais de recouvrement : EUR 40.00"));
        assert!(!text.contains("NON CONFORME"));
        assert!(text.ends_with("%%EOF\n"));

        // Every xref offset lands on "N 0 obj". `\nxref\n` and not `xref\n`,
        // which would match the tail of `startxref`.
        let xref = text.rfind("\nxref\n").expect("an xref table") + 1;
        for (index, entry) in text[xref..]
            .lines()
            .skip(2)
            .take_while(|line| line.ends_with(" n "))
            .enumerate()
        {
            let offset: usize = entry[..10].parse().expect("ten digits");
            assert!(
                text[offset..].starts_with(&format!("{} 0 obj", index + 1)),
                "offset {offset} of object {} is wrong",
                index + 1
            );
        }
        let declared: usize = text
            .rsplit("startxref\n")
            .next()
            .and_then(|tail| tail.lines().next())
            .and_then(|line| line.parse().ok())
            .expect("startxref");
        assert_eq!(declared, xref);
    }

    /// A memo written to end the string and keep going as operators comes out
    /// as text: the delimiters are escaped, the newline is a space.
    #[test]
    fn hostile_text_cannot_leave_the_string_literal() {
        let bytes = render(&invoice(") Tj ET\n/F1 99 Tf (pwned"), &parties(), None);
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.contains("(Objet : \\) Tj ET /F1 99 Tf \\(pwned) Tj"),
            "{text}"
        );
        // The operators the memo carried never reached a line of their own: the
        // same count as a benign memo renders, and the hostile `Tf` is inside a
        // literal, not at the start of a line. Counted against the benign
        // document rather than pinned to a number, so a mention added to the
        // layout does not look like an escape failing.
        let benign = String::from_utf8_lossy(&render(&invoice("March"), &parties(), None))
            .matches(") Tj T*\n")
            .count();
        assert_eq!(text.matches(") Tj T*\n").count(), benign);
        assert!(!text.contains("\n/F1 99 Tf"));
    }

    /// Two rates in one document, each band rounded on its own total, and the
    /// three figures agree to the centime.
    #[test]
    fn a_two_rate_invoice_ventilates_to_the_centime() {
        let lines = [
            Line {
                description: "Licence".to_owned(),
                amount_minor: 10_001,
                tax_rate_bp: Some(2000),
            },
            Line {
                description: "Support".to_owned(),
                amount_minor: 5_000,
                tax_rate_bp: Some(2000),
            },
            Line {
                description: "Livre".to_owned(),
                amount_minor: 3_333,
                tax_rate_bp: Some(550),
            },
        ];
        let v = ventilate(&lines, None);
        assert_eq!(
            v.bands,
            vec![
                // 3333 x 5,50 % = 183,315 -> 183
                Band {
                    rate_bp: 550,
                    base_minor: 3_333,
                    tax_minor: 183
                },
                // 15001 x 20 % = 3000,2 -> 3000
                Band {
                    rate_bp: 2000,
                    base_minor: 15_001,
                    tax_minor: 3_000
                },
            ]
        );
        assert_eq!(v.untaxed_minor, 0);
        assert_eq!(v.base_minor, 18_334);
        assert_eq!(v.tax_minor, 3_183);
        assert_eq!(v.total_minor, 21_517);
        // The identity a reader checks with a calculator.
        assert_eq!(v.base_minor + v.tax_minor, v.total_minor);
    }

    /// The centime the classic mistake loses: rounding each line and adding the
    /// results gives 6,00 where the band gives 6,01.
    #[test]
    fn the_rounding_happens_once_per_rate_and_not_line_by_line() {
        let lines: Vec<Line> = (0..3)
            .map(|n| Line {
                description: format!("Heure {n}"),
                amount_minor: 1_001,
                tax_rate_bp: Some(2000),
            })
            .collect();
        let per_line: i64 = lines
            .iter()
            .map(|l| ventilate(std::slice::from_ref(l), None).tax_minor)
            .sum();
        assert_eq!(per_line, 600, "1001 x 20 % rounds to 200 three times over");

        let v = ventilate(&lines, None);
        assert_eq!(v.base_minor, 3_003);
        // 3003 x 20 % = 600,60 -> 601. One rounding, on the band.
        assert_eq!(v.tax_minor, 601);
        assert_ne!(v.tax_minor, per_line);

        // And the tie goes away from zero, in both directions, so a credit note
        // rounds the mirror image of the invoice it withdraws.
        assert_eq!(tax_on(250, 1000), 25);
        assert_eq!(tax_on(-250, 1000), -25);
        assert_eq!(tax_on(255, 1000), 26);
        assert_eq!(tax_on(-255, 1000), -26);
    }

    /// A company outside VAT prints its mention, and nowhere a rate.
    #[test]
    fn an_invoice_outside_vat_carries_its_mention_and_never_a_zero() {
        let exempt = Issuer {
            vat_rate_bp: None,
            vat_number: None,
            vat_exemption_reason: Some("TVA non applicable, art. 293 B du CGI".to_owned()),
            ..issuer()
        };
        assert!(exempt.missing_mentions().is_empty());

        let mut without = invoice("mars");
        for line in &mut without.lines {
            line.tax_rate_bp = None;
        }
        let text =
            String::from_utf8_lossy(&render(&without, &parties_of(exempt), None)).into_owned();

        assert!(
            text.contains("(TVA non applicable, art. 293 B du CGI) Tj"),
            "{text}"
        );
        assert!(text.contains("(Total HT : EUR 1200.00) Tj"));
        assert!(text.contains("payer : EUR 1200.00) Tj"));
        // No band, no total-of-tax line, and above all no rate of zero: the
        // whole point of `0087`'s CHECK and of `ventilate`'s filter.
        assert!(!text.contains("Total TVA"));
        assert!(!text.contains("Total TTC"));
        assert!(!text.contains("TVA 0.00 %"), "{text}");
        assert!(!text.contains("NON CONFORME"));

        let v = ventilate(&without.lines, None);
        assert!(v.bands.is_empty());
        assert_eq!(v.untaxed_minor, 120_000);
        assert_eq!(v.tax_minor, 0);
        assert_eq!(v.total_minor, v.base_minor);
    }

    /// A tenant that has written nothing down gets a document that says so, and
    /// still not a rate of zero.
    #[test]
    fn a_document_from_an_incomplete_issuer_says_it_is_not_conformant() {
        let bare = Issuer {
            name: "Orizn".to_owned(),
            legal_form: None,
            address: None,
            siren: None,
            rcs_city: None,
            vat_number: None,
            vat_rate_bp: None,
            vat_exemption_reason: None,
            late_penalty_rate_bp: None,
        };
        assert_eq!(
            bare.missing_mentions(),
            vec![
                "legal_form",
                "postal_address",
                "siren",
                "rcs_city",
                "vat_rate_bp_or_vat_exemption_reason",
                "late_penalty_rate_bp",
            ]
        );

        let mut without = invoice("mars");
        for line in &mut without.lines {
            line.tax_rate_bp = None;
        }
        let text = String::from_utf8_lossy(&render(&without, &parties_of(bare), None)).into_owned();
        assert!(
            text.contains(
                "(FACTURE NON CONFORME - mentions obligatoires absentes : legal_form, \
                           postal_address, siren, rcs_city, \
                           vat_rate_bp_or_vat_exemption_reason, late_penalty_rate_bp) Tj"
            ),
            "{text}"
        );
        assert!(text.contains("(TVA : mention obligatoire absente - ni taux ni motif) Tj"));
        assert!(!text.contains("TVA 0.00 %"));
        assert!(text.contains("nalit\\351s de retard : mention obligatoire absente."));
    }

    #[test]
    fn a_credit_note_says_which_invoice_it_corrects() {
        let mut note = invoice("erreur de tarif");
        note.number = 43;
        note.corrects_invoice_id = Some(InvoiceId::new_v7(Utc::now()));
        note.lines.clear();
        let text = String::from_utf8_lossy(&render(&note, &parties(), Some(42))).into_owned();
        assert!(text.contains("(Avoir n\\260 43) Tj"));
        assert!(text.contains("(Corrige la facture n\\260 42) Tj"));
        assert_eq!(file_name(&note), "credit-note-43.pdf");
        assert_eq!(file_name(&invoice("x")), "invoice-42.pdf");
    }

    #[test]
    fn accents_are_octal_escapes_and_the_rest_is_a_question_mark() {
        assert_eq!(
            text(Untrusted::new("Émise à l'échéance".to_owned())),
            "\\311mise \\340 l'\\351ch\\351ance"
        );
        assert_eq!(text(Untrusted::new("日本".to_owned())), "??");
        assert_eq!(minor(-5, 2), "-0.05");
        assert_eq!(minor(500, 0), "500");
    }
}

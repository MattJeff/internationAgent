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
//! # French, deliberately
//!
//! The labels are in the founder's language, because the recipient is the
//! founder's customer and the roadmap that asked for this document is written
//! in it. A per-tenant language is a column nobody has asked for.

use agentos_domain::untrusted::Untrusted;
use agentos_store::db::{StoreError, TenantTx};
use agentos_store::files::{self, Filed};
use agentos_store::invoices::{self, Invoice, Parties};
use chrono::{DateTime, Utc};

use crate::files::digest_of;

/// What the classeur records the document as.
pub const CONTENT_TYPE: &str = "application/pdf";

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
    let mut lines: Vec<String> = Vec::new();
    lines.push(text(Untrusted::new(parties.issuer.clone())));
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
    lines.push(text(Untrusted::new(format!(
        "Échéance : {}",
        invoice
            .due_at
            .map_or_else(|| "non convenue".to_owned(), day)
    ))));
    lines.push(String::new());
    lines.push(text(Untrusted::new(format!(
        "Émetteur : {}",
        parties.issuer
    ))));
    lines.push(text(Untrusted::new(format!(
        "Destinataire : {}",
        parties.account
    ))));
    lines.push(String::new());
    lines.push(text(Untrusted::new(format!("Objet : {}", invoice.memo))));
    lines.push(String::new());
    for line in &invoice.lines {
        let rate = line.tax_rate_bp.map_or(String::new(), |bp| {
            format!("  (TVA {}.{:02} %)", bp / 100, bp % 100)
        });
        lines.push(text(Untrusted::new(format!(
            "{}    {} {}{rate}",
            line.description,
            currency.code(),
            minor(line.amount_minor, currency.exponent()),
        ))));
    }
    lines.push(String::new());
    lines.push(text(Untrusted::new(format!("Total : {}", invoice.amount))));

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

    fn parties() -> Parties {
        Parties {
            issuer: "Orizn SAS".to_owned(),
            account: "Buyer plc".to_owned(),
            contact_email: Some("ap@buyer.example".to_owned()),
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
        assert!(text.contains("(Remise    EUR -50.00) Tj"));
        assert!(text.contains("(Total : EUR 1200.00) Tj"));
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
        // The operators the memo carried never reached a line of their own:
        // exactly the fifteen `Tj` this fixture renders, and the hostile `Tf`
        // is inside a literal, not at the start of a line.
        assert_eq!(text.matches(") Tj T*\n").count(), 15);
        assert!(!text.contains("\n/F1 99 Tf"));
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

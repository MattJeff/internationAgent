//! Le devis comme document : le même PDF que la facture, moins le numéro, plus
//! une date de péremption.
//!
//! `sales_quotes` (`0090`) est le registre — ce qui a été offert, à quelle
//! version, et ce qu'ils en ont dit. Un prospect ne signe pas une ligne ; il
//! signe un document qu'il ouvre, transmet à sa direction et compare à celui
//! d'un concurrent. Ce module le rend depuis la ligne, au moment où elle est
//! écrite, dans la même transaction, et [`file`] le dépose dans `files` (0067)
//! sous `quote-<id>-v<version>.pdf` — de sorte que le registre et le classeur
//! ne peuvent pas être en désaccord sur ce qui est parti.
//!
//! # Ce qu'il reprend de [`crate::invoice_document`], et ce qu'il n'en reprend
//! pas
//!
//! **La ventilation est la sienne, appelée et non recopiée.**
//! [`crate::invoice_document::ventilate`] est la seule arithmétique de TVA de
//! ce dépôt, et c'est ce qui fait que le total d'un devis accepté est *le même
//! calcul* que celui de la facture qui le reprend — pas un second calcul qui
//! pourrait en différer d'un centime au troisième arrondi. `0090` donne à
//! `sales_quote_lines` les colonnes de `invoice_lines` exactement pour que cet
//! appel soit possible.
//!
//! Trois choses diffèrent, et chacune est une ligne du document :
//!
//! * **Il porte une durée de validité, et elle est en évidence.** C'est la
//!   seule mention qu'une facture n'a pas et qu'un devis doit avoir : passé la
//!   date, l'offre n'est plus faite. `agentos_store::quotes::accept` refuse en
//!   base ce que cette ligne annonce sur le papier.
//! * **Il ne porte aucun numéro de séquence.** `invoice_counters` (0071) sert
//!   une obligation comptable qu'un devis n'a pas, et son prix — l'émission
//!   sérialise par entreprise — serait payé pour rien. La référence est
//!   `(id, version)`, et le document le dit en toutes lettres pour que personne
//!   ne prenne ce PDF pour une pièce à comptabiliser.
//! * **Il porte sa version, et le devis qu'il remplace quand il en remplace
//!   un.** Un client qui reçoit une v2 doit pouvoir voir que c'en est une, ou
//!   il compare deux documents en croyant les avoir reçus dans l'ordre.
//!
//! # Et ce qu'il ne porte **pas** : la bannière de non-conformité
//!
//! [`crate::invoice_document`] ouvre par `FACTURE NON CONFORME` quand
//! l'émetteur n'a pas écrit ses mentions obligatoires, parce qu'une facture qui
//! ne peut pas être émise ne doit pas ressembler à une facture qui le peut.
//! Rien de tel ici, et c'est une décision plutôt qu'un oubli :
//! [`Issuer::missing_mentions`] est la liste des mentions d'une **facture** —
//! le taux de TVA, la pénalité de retard, le RCS — et un devis n'en doit
//! aucune. Reprendre la bannière ferait dire au document une chose fausse sur
//! lui-même.
//!
//! Ce qu'un devis doit, il l'a : l'identité de l'émetteur telle que `tenants`
//! la porte, la désignation, le prix HT et TTC, et la durée de validité. La
//! ligne « bon pour accord » est là parce que c'est ce qui transforme le
//! document en engagement quand le client la signe — et c'est exactement le
//! geste qu'une signature électronique remplace ; voir l'entrée `docusign` de
//! [`crate::catalog`].
//!
//! # L'échappement, et pourquoi il est écrit deux fois
//!
//! ponytail: [`text`] et [`document`] sont les jumeaux privés de ceux de
//! [`crate::invoice_document`], recopiés parce qu'ils y sont privés et que ce
//! module ne peut pas les emprunter. C'est la seule duplication assumée ici et
//! elle a un plafond nommé : **le jour où un troisième document arrive**, les
//! quatre fonctions (`text`, `document`, `minor`, `day`) montent dans un
//! `crate::pdf` et les deux modules l'appellent. À deux, un module partagé
//! coûterait plus de lecture qu'il n'en économise ; à trois, non.
//!
//! Ce qui n'est pas négociable, en revanche, c'est ce que [`text`] fait :
//! l'objet, la raison sociale du prospect et chaque description de ligne sont
//! du texte que quelqu'un d'autre a tapé. Dans un littéral PDF, `(`, `)` et
//! `\` sont de la syntaxe, et un nom comme `Acme) Tj ET` fermerait la chaîne
//! pour continuer en opérateurs de flux. [`text`] est le seul endroit où du
//! texte entre dans le flux, il échappe les trois, et
//! [`Untrusted::into_inner_for_rendering`] n'est appelé que là — donc le grep
//! d'audit sur cette méthode trouve ce fichier une fois.

use agentos_domain::money::Currency;
use agentos_domain::untrusted::Untrusted;
use agentos_store::db::{StoreError, TenantTx};
use agentos_store::files::{self, Filed};
use agentos_store::invoices::{self, Issuer, Line, Parties};
use agentos_store::quotes::Quote;
use chrono::{DateTime, Utc};

use crate::files::digest_of;
use crate::invoice_document::{Ventilation, ventilate};

/// Ce que le classeur enregistre le document comme.
pub const CONTENT_TYPE: &str = "application/pdf";

/// Où le document vit dans `files`.
///
/// La version est dans le nom, et pas seulement l'identifiant : un client qui
/// a deux PDF dans sa boîte doit pouvoir les mettre dans l'ordre sans les
/// ouvrir. Les deux ensemble sont uniques de toute façon — une révision est une
/// ligne neuve avec un `id` neuf — donc la version est là pour l'humain, pas
/// pour la clé.
pub fn file_name(quote: &Quote) -> String {
    format!("quote-{}-v{}.pdf", quote.id, quote.version)
}

/// Rendre et déposer, dans la transaction de l'appelant.
///
/// Lit les parties, et — pour une révision — la version du devis remplacé, de
/// sorte que le document dise « révise le devis … (v1) » et pas un uuid nu.
/// [`StoreError::Conflict`] sur `files_pkey` voudrait dire que ce couple
/// `(id, version)` a déjà été déposé, ce qui ne peut pas arriver pour une ligne
/// écrite dans cette même transaction — et si cela arrivait, l'écriture est
/// refusée plutôt qu'écrasée, ce qui est la règle de `0067`.
pub async fn file(tx: &mut TenantTx<'_>, quote: &Quote) -> Result<Filed, StoreError> {
    let parties = invoices::parties(tx, quote.opportunity_id).await?;
    let supersedes = match quote.supersedes_quote_id {
        Some(id) => agentos_store::quotes::find(tx, id)
            .await?
            .map(|previous| previous.version),
        None => None,
    };
    let bytes = render(quote, &parties, supersedes);
    files::deposit(
        tx,
        &file_name(quote),
        CONTENT_TYPE,
        &bytes,
        &digest_of(&bytes),
    )
    .await
}

/// Les octets du document. Pur, pour qu'un test puisse les affirmer sans base.
///
/// `supersedes_version` est le numéro de version du devis que celui-ci
/// remplace, et il est ignoré sur un original.
pub fn render(quote: &Quote, parties: &Parties, supersedes_version: Option<i32>) -> Vec<u8> {
    let currency = quote.amount.currency();
    let issuer = &parties.issuer;
    let mut lines: Vec<String> = Vec::new();

    // L'en-tête de l'émetteur : qui propose, dans les termes où l'entreprise se
    // nomme. Pas de bannière au-dessus — voir les docs du module.
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

    // Le titre, et la référence qui n'est pas un numéro.
    lines.push(text(Untrusted::new(format!(
        "DEVIS - version {}",
        quote.version
    ))));
    lines.push(text(Untrusted::new(format!("Référence : {}", quote.id))));
    if let Some(version) = supersedes_version {
        lines.push(text(Untrusted::new(format!(
            "Remplace et annule le devis version {version}"
        ))));
    }
    lines.push(text(Untrusted::new(format!(
        "Établi le {}",
        day(quote.issued_at)
    ))));
    // **La ligne pour laquelle ce document diffère de la facture.** Elle dit la
    // date *et* ce qui se passe après, parce qu'une date seule se lit comme une
    // indication et pas comme une limite.
    lines.push(text(Untrusted::new(format!(
        "Valable jusqu'au {} inclus - passé cette date, l'offre est caduque.",
        day(quote.valid_until)
    ))));
    lines.push(String::new());
    lines.push(text(Untrusted::new(format!("Émetteur : {issuer}"))));
    lines.push(text(Untrusted::new(format!(
        "Destinataire : {}",
        parties.account
    ))));
    lines.push(String::new());
    lines.push(text(Untrusted::new(format!("Objet : {}", quote.memo))));
    lines.push(String::new());

    // Un devis sans lignes est son objet : une ligne, le montant entier, pour
    // que la ventilation ait une base dans les deux cas. C'est le geste que
    // `invoice_document::render` fait, et pour la même raison.
    let head = [Line {
        description: quote.memo.clone(),
        amount_minor: i64::try_from(quote.amount.minor()).unwrap_or(i64::MAX),
        tax_rate_bp: None,
    }];
    let offered: &[Line] = if quote.lines.is_empty() {
        &head
    } else {
        &quote.lines
    };
    for line in offered {
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
    lines.extend(totals(
        &ventilate(offered, issuer.vat_rate_bp),
        issuer,
        currency,
    ));
    lines.push(String::new());

    // Ce que le document dit de lui-même, et ce qu'il demande.
    lines.push(text(Untrusted::new(
        "Ce devis n'est pas une facture : il ne porte aucun numéro de séquence comptable et \
         n'ouvre aucun droit à déduction."
            .to_owned(),
    )));
    lines.push(text(Untrusted::new(
        "Bon pour accord : date, nom et signature du client.".to_owned(),
    )));

    // Le flux : un objet texte, Helvetica 11pt, interligne 14pt, en haut à
    // gauche d'une A4.
    let mut stream = String::from("BT /F1 11 Tf 14 TL 50 790 Td\n");
    for line in &lines {
        stream.push('(');
        stream.push_str(line);
        stream.push_str(") Tj T*\n");
    }
    stream.push_str("ET\n");

    document(&stream)
}

/// Le bloc sous les lignes : la base, la TVA par taux, et le total à payer.
///
/// Le même que celui d'une facture — mêmes bandes, même arrondi une seule fois
/// par taux — avec un seul mot changé : « Total à payer » devient « Total TTC
/// de l'offre », parce qu'un devis ne demande rien, il propose.
///
/// Prend l'[`Issuer`] en plus de la [`Ventilation`] pour la raison de
/// `invoice_document` : l'**absence** de TVA est une phrase que l'émetteur
/// possède et que l'arithmétique ne peut pas fournir. Un taux de zéro n'est
/// jamais imprimé comme un taux, ici comme là.
fn totals(v: &Ventilation, issuer: &Issuer, currency: Currency) -> Vec<String> {
    let money = |amount: i64| format!("{} {}", currency.code(), minor(amount, currency.exponent()));
    let no_vat = match &issuer.vat_exemption_reason {
        Some(reason) => reason.clone(),
        None => "TVA : mention obligatoire absente - ni taux ni motif".to_owned(),
    };

    let mut out = vec![text(Untrusted::new(format!(
        "Total HT : {}",
        money(v.base_minor)
    )))];
    if v.bands.is_empty() {
        out.push(text(Untrusted::new(no_vat)));
        out.push(text(Untrusted::new(format!(
            "Total de l'offre : {}",
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
        "Total TTC de l'offre : {}",
        money(v.total_minor)
    ))));
    out
}

/// Un taux en points de base, en pourcentage : `2000` donne `"20.00 %"`.
///
/// Un point décimal et pas une virgule, comme dans `invoice_document` et pour
/// la même raison : tous les chiffres de ce document passent par [`minor`], qui
/// écrit un point, et un document qui ponctue deux chiffres de deux façons est
/// plus dur à lire qu'un document uniformément anglophone sur les décimales.
fn percent(bp: i32) -> String {
    format!("{}.{:02} %", bp / 100, (bp % 100).abs())
}

fn rate_of(bp: i32) -> String {
    format!("TVA {}", percent(bp))
}

/// Échapper une ligne de texte en corps de littéral PDF.
///
/// La seule sortie d'[`Untrusted`] de ce module : voir les docs du module.
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
            // Latin-1 est WinAnsi pour toutes les lettres dont le français a
            // besoin ; un octet que la police ne sait pas dessiner devient un
            // point d'interrogation, pas un caractère invisible.
            c if (0xA0..=0xFF).contains(&(c as u32)) => {
                out.push_str(&format!("\\{:03o}", c as u32));
            }
            // Un caractère de contrôle dans un littéral disparaîtrait ou
            // couperait une ligne là où la mise en page n'en prévoyait pas.
            c if c.is_control() => out.push(' '),
            _ => out.push('?'),
        }
    }
    out
}

/// Emballer un flux dans le plus petit fichier PDF 1.4 valide.
///
/// Les décalages sont relevés au fur et à mesure que les objets sont poussés,
/// ce qui est tout ce qu'est une table xref.
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
    // Vingt octets par entrée, exactement.
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

/// Un montant signé en unités mineures, avec les décimales de sa monnaie.
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
    use agentos_domain::ids::EmployeeId;
    use agentos_domain::money::{Currency, Money};
    use agentos_domain::revenue::QuoteId;
    use chrono::TimeDelta;

    use super::*;

    fn quote(memo: &str) -> Quote {
        let now = DateTime::from_timestamp(1_756_000_000, 0).expect("valid timestamp");
        Quote {
            id: QuoteId::from_uuid(
                uuid::Uuid::parse_str("018f0000-0000-7000-8000-00000000abcd").expect("uuid"),
            ),
            opportunity_id: uuid::Uuid::now_v7(),
            issued_by: EmployeeId::new_v7(now),
            amount: Money::new(120_000, Currency::Eur).expect("nonzero"),
            memo: memo.to_owned(),
            version: 1,
            supersedes_quote_id: None,
            issued_at: now,
            valid_until: now + TimeDelta::days(30),
            accepted_at: None,
            declined_at: None,
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

    /// Le document porte sa validité et sa version, et **ne porte pas** ce qui
    /// ferait d'un devis une facture.
    ///
    /// Les trois assertions négatives sont l'essentiel : pas de numéro de
    /// séquence, pas d'échéance de paiement, pas de bannière de non-conformité.
    /// Un devis qui ressemblerait à une facture est le document qu'un client
    /// paie sans avoir rien signé.
    #[test]
    fn a_rendered_quote_carries_its_validity_and_is_not_an_invoice() {
        let bytes = render(&quote("Plateforme"), &parties(), None);
        let text = String::from_utf8_lossy(&bytes);
        assert!(bytes.starts_with(b"%PDF-1.4\n"));
        assert!(text.contains("(DEVIS - version 1) Tj"), "{text}");
        assert!(text.contains("(R\\351f\\351rence : 018f0000-0000-7000-8000-00000000abcd) Tj"));
        assert!(text.contains("(\\311tabli le 2025-08-24) Tj"), "{text}");
        // La ligne pour laquelle ce document existe.
        assert!(
            text.contains("(Valable jusqu'au 2025-09-23 inclus - pass\\351 cette date, l'offre est caduque.) Tj"),
            "{text}"
        );
        assert!(text.contains("(Destinataire : Buyer plc) Tj"));
        assert!(text.contains("(Licence    EUR 1250.00  \\(TVA 20.00 %\\)) Tj"));
        assert!(text.contains("(Total HT : EUR 1200.00) Tj"));
        assert!(text.contains("(TVA 20.00 % sur EUR 1200.00 : EUR 240.00) Tj"));
        assert!(text.contains("(Total TTC de l'offre : EUR 1440.00) Tj"));
        assert!(text.contains("(Orizn SAS) Tj"));
        assert!(text.contains("Bon pour accord"));

        // Ce qu'un devis n'est pas, et le document le dit de lui-même.
        assert!(!text.contains("Facture n"), "{text}");
        assert!(
            !text.contains("\\311ch\\351ance"),
            "a quote has no due date"
        );
        assert!(!text.contains("NON CONFORME"));
        assert!(
            !text.contains("Remplace et annule"),
            "this one is an original"
        );
        assert!(text.contains("n'est pas une facture"));
        assert!(text.ends_with("%%EOF\n"));

        // Chaque décalage xref tombe sur « N 0 obj ».
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
    }

    /// Une révision se présente comme une révision.
    ///
    /// Un client qui reçoit deux PDF doit pouvoir les ordonner sans les ouvrir
    /// (le nom de fichier) et savoir lequel annule l'autre en les ouvrant (la
    /// ligne). Les deux sont ici.
    #[test]
    fn a_revision_says_which_version_it_replaces() {
        let mut second = quote("Plateforme, revu");
        second.version = 2;
        second.supersedes_quote_id = Some(QuoteId::new_v7(Utc::now()));
        let text = String::from_utf8_lossy(&render(&second, &parties(), Some(1))).into_owned();
        assert!(text.contains("(DEVIS - version 2) Tj"), "{text}");
        assert!(
            text.contains("(Remplace et annule le devis version 1) Tj"),
            "{text}"
        );
        assert_eq!(
            file_name(&second),
            "quote-018f0000-0000-7000-8000-00000000abcd-v2.pdf"
        );
        assert_eq!(
            file_name(&quote("x")),
            "quote-018f0000-0000-7000-8000-00000000abcd-v1.pdf"
        );
    }

    /// L'objet écrit pour sortir du littéral et continuer en opérateurs sort en
    /// texte : les délimiteurs sont échappés, le saut de ligne est un espace.
    #[test]
    fn hostile_text_cannot_leave_the_string_literal() {
        let bytes = render(&quote(") Tj ET\n/F1 99 Tf (pwned"), &parties(), None);
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.contains("(Objet : \\) Tj ET /F1 99 Tf \\(pwned) Tj"),
            "{text}"
        );
        // Les opérateurs que l'objet portait n'ont jamais eu de ligne à eux :
        // le même compte qu'un objet inoffensif, compté contre lui plutôt que
        // épinglé à un nombre, pour qu'une ligne ajoutée à la mise en page ne
        // ressemble pas à un échappement qui cède.
        let benign = String::from_utf8_lossy(&render(&quote("Plateforme"), &parties(), None))
            .matches(") Tj T*\n")
            .count();
        assert_eq!(text.matches(") Tj T*\n").count(), benign);
        assert!(!text.contains("\n/F1 99 Tf"));
    }

    /// **Le devis et la facture comptent pareil, parce qu'ils comptent une
    /// fois.**
    ///
    /// Les mêmes lignes, la même fonction, le même total — et l'assertion porte
    /// sur `invoice_document::ventilate` appelé depuis les deux, pas sur deux
    /// chiffres qui coïncident aujourd'hui. C'est ce qui fait qu'une facture ne
    /// peut pas être à un centime du devis signé.
    #[test]
    fn the_quote_totals_by_the_invoice_arithmetic_and_not_a_second_one() {
        let offered = quote("Plateforme");
        let v = ventilate(&offered.lines, issuer().vat_rate_bp);
        assert_eq!(v.base_minor, 120_000);
        assert_eq!(v.tax_minor, 24_000);
        assert_eq!(v.total_minor, 144_000);

        // La facture que cette offre deviendrait porte les mêmes lignes et le
        // même total, par le même appel.
        let billed = ventilate(&offered.lines, issuer().vat_rate_bp);
        assert_eq!(billed, v);
        assert_eq!(
            u64::try_from(v.base_minor).expect("positive"),
            offered.amount.minor(),
            "the head and its lines are the same offer"
        );

        // Et un émetteur hors TVA n'imprime jamais un taux de zéro, ici comme
        // sur la facture.
        let exempt = Issuer {
            vat_rate_bp: None,
            vat_number: None,
            vat_exemption_reason: Some("TVA non applicable, art. 293 B du CGI".to_owned()),
            ..issuer()
        };
        let mut without = quote("Plateforme");
        for line in &mut without.lines {
            line.tax_rate_bp = None;
        }
        let text = String::from_utf8_lossy(&render(
            &without,
            &Parties {
                issuer: exempt,
                ..parties()
            },
            None,
        ))
        .into_owned();
        assert!(
            text.contains("(TVA non applicable, art. 293 B du CGI) Tj"),
            "{text}"
        );
        assert!(text.contains("(Total de l'offre : EUR 1200.00) Tj"));
        assert!(!text.contains("TVA 0.00 %"), "{text}");
        assert!(!text.contains("Total TVA"));
    }

    #[test]
    fn accents_are_octal_escapes_and_the_rest_is_a_question_mark() {
        assert_eq!(
            text(Untrusted::new("Établi à l'échéance".to_owned())),
            "\\311tabli \\340 l'\\351ch\\351ance"
        );
        assert_eq!(text(Untrusted::new("日本".to_owned())), "??");
        assert_eq!(minor(-5, 2), "-0.05");
        assert_eq!(minor(500, 0), "500");
        assert_eq!(percent(550), "5.50 %");
    }
}

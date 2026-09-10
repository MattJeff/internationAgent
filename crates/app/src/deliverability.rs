//! La délivrabilité du contenu : un mail qui ressemble à du spam ne part pas.
//!
//! Lumail vend cela comme un « content deliverability checker » avec un bouton
//! IA. Ici il n'y a pas de bouton : ce sont des employés IA qui écrivent, et
//! une phrase dans le brief demandant au modèle de « ne pas faire spam » est
//! une intention. Une intention s'oublie ; une règle sur le chemin d'envoi
//! ne s'oublie pas — c'est l'argument de [`crate::follow_up`], « a reflex is a
//! rule rather than an intention », et il vaut ici mot pour mot. Le contrôle
//! est donc du code dans [`crate::effects::Effects::send_email`], avant le
//! fournisseur, et le refus remonte au modèle avec ses raisons pour qu'il
//! réécrive lui-même. Pas de score, pas de réécriture automatique : le modèle
//! sait écrire, il lui manquait un lecteur qui dit non.
//!
//! # Pourquoi ces règles et pas d'autres
//!
//! Les filtres de 2026 jugent d'abord l'authentification, la réputation du
//! domaine et le taux de plaintes — ce que le dépôt applique déjà :
//! [`agentos_domain::policy::Deliverability::MAX_REFUSALS_PER_MILLE`] porte les
//! 0,3 % de Google/Yahoo, `0085` porte le lien de désinscription. Le contenu
//! n'est que le troisième facteur, mais c'est le seul que le modèle contrôle à
//! chaque envoi, et c'est celui qui fait cliquer « spam » à un humain — et un
//! clic « spam » est exactement ce que le seuil de 0,3 % compte. Chaque règle
//! cite sa source à sa constante. Les seuils numériques (trois liens, deux
//! expressions, 30 % de majuscules) ne sont dans aucun document public : ce
//! sont des bornes de prospection à froid, larges pour un mail écrit par une
//! personne et étroites pour un mail écrit par un vendeur de montres.
//!
//! Sources, toutes lues le 2026-09-10 :
//!
//! * Google, « Email sender guidelines »,
//!   <https://support.google.com/a/answer/81126> : « Email message subject,
//!   headers, display names, and other message elements should accurately
//!   represent the sender identity and message content, and shouldn't be
//!   misleading » ; « Web links in the message body should be visible and easy
//!   to understand. Recipients should know what to expect when they click a
//!   link » ; « Keep spam rates reported in Postmaster Tools below 0.3% ».
//! * RFC 5322 §2.1.1, <https://www.rfc-editor.org/rfc/rfc5322#section-2.1.1> :
//!   « Each line of characters MUST be no more than 998 characters, and SHOULD
//!   be no more than 78 characters, excluding the CRLF » — le 78 est là pour
//!   les clients qui « may truncate, or disastrously wrap » au-delà.
//! * HubSpot, « Spam trigger words: How to keep your emails out of the spam
//!   folder », mis à jour le 2025-09-05,
//!   <https://blog.hubspot.com/blog/tabid/6307/bid/30684/the-ultimate-list-of-email-spam-trigger-words.aspx> :
//!   la liste d'où viennent `act now`, `100% free`, `click here`, `risk free`,
//!   `no obligation`, `winner`, `$$$`, `urgent`, `limited time`, `offer
//!   expires`. L'article dit lui-même que « filters are smarter and look at
//!   other things first, like authentication, sender reputation, and
//!   engagement » — d'où une liste **courte** et un seuil à deux expressions,
//!   pas un lexique.
//! * Mailchimp, « About spam filters »,
//!   <https://mailchimp.com/help/about-spam-filters/> : « there aren't any hard
//!   and fast rules » ; teste « all links before you send », évite les « link
//!   shorteners ». Cité pour ce qu'il ne dit pas : personne ne publie de
//!   seuil, donc les nôtres sont argumentés et pas recopiés.
//!
//! Pur : pas d'I/O, pas d'horloge, pas de regex. Une fonction, un verdict.

use std::fmt;

use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::is_combining_mark;

/// Le code de refus, tel que [`crate::effects::EffectError::code`] le rend et
/// tel que `docs/OPERATIONS.md` le liste.
pub const CODE: &str = "deliverability";

/// Combien d'URL un corps peut porter avant d'être refusé.
///
/// Google demande que les liens soient « visible and easy to understand » ;
/// une approche à froid en a un — la page dont on parle — et parfois deux. Au
/// quatrième, ce n'est plus une lettre, c'est une newsletter, et un
/// destinataire qui n'a rien demandé la classe comme telle. Le lien de
/// désinscription que nous ajoutons nous-mêmes (`0085`) **ne compte pas** : il
/// voyage en en-tête `List-Unsubscribe`, pas dans `body_text`, et le corps
/// vérifié ici ne le contient jamais — voir
/// `crates/providers/src/email_resend.rs` et le test qui le prouve dans
/// `effects.rs`.
pub const MAX_LINKS: usize = 3;

/// À partir de combien d'expressions à spam distinctes on refuse. Une seule
/// est un avertissement : « urgent » a des emplois honnêtes, deux de la liste
/// dans le même mail n'en ont pas.
pub const SPAM_PHRASES_REFUSED_AT: usize = 2;

/// Un sujet est « tout en majuscules » à partir de ce nombre de lettres : « HS »
/// ou « PDF » sont des sigles, « RELANCE URGENTE » est un cri.
pub const SUBJECT_CAPS_MIN_LETTERS: usize = 3;

/// Part de majuscules du corps, en pour cent, au-delà de laquelle on refuse.
/// Un texte anglais ou français ordinaire est sous 10 % ; 30 % est un corps
/// dont un tiers crie.
pub const BODY_CAPS_MAX_PERCENT: usize = 30;

/// Sous ce nombre de lettres, le ratio de majuscules ne veut rien dire — « OK »
/// est à 100 %.
pub const BODY_CAPS_MIN_LETTERS: usize = 40;

/// Points d'exclamation admis dans sujet + corps. Trois est déjà beaucoup pour
/// une lettre ; au quatrième c'est un motif de filtre classique.
pub const MAX_EXCLAMATIONS: usize = 3;

/// Longueur de sujet au-delà de laquelle on avertit : RFC 5322 §2.1.1 (« SHOULD
/// be no more than 78 characters ») — un client qui tronque coupe le sujet, pas
/// l'en-tête.
pub const SUBJECT_MAX_CHARS: usize = 78;

/// Sous ce nombre de mots, le corps est un avertissement : trop court pour
/// dire qui écrit et pourquoi, et les filtres traitent un corps quasi vide
/// avec un lien comme du phishing.
pub const BODY_MIN_WORDS: usize = 20;

/// Les expressions à spam, en anglais et en français, déjà **pliées** (voir
/// [`fold`]) : minuscules ASCII, sans accents. Quarante et pas quatre cents,
/// pour la raison que HubSpot donne lui-même — les filtres ne lisent plus les
/// mots en premier — et parce qu'un lexique long refuse « free trial » à une
/// entreprise qui en vend un.
const SPAM_PHRASES: &[&str] = &[
    // anglais
    "act now",
    "100% free",
    "100 % free",
    "click here",
    "risk-free",
    "risk free",
    "no obligation",
    "winner",
    "$$$",
    "urgent",
    "limited time",
    "offer expires",
    "buy now",
    "order now",
    "money back",
    "double your",
    "once in a lifetime",
    "this is not spam",
    "dear friend",
    "call now",
    "you have been selected",
    "congratulations",
    "no strings attached",
    "last chance",
    // français
    "gratuit a 100 %",
    "gratuit a 100%",
    "100 % gratuit",
    "100% gratuit",
    "cliquez ici",
    "offre limitee",
    "agissez maintenant",
    "sans engagement",
    "sans risque",
    "gagnant",
    "argent facile",
    "felicitations",
    "vous avez ete selectionne",
    "derniere chance",
    "achetez maintenant",
    "ceci n'est pas un spam",
];

/// Ce qui fait qu'un mail demande quelque chose : un « ? » ou l'un de ces
/// fragments, pliés. Un corps qui n'en a aucun n'est pas refusé — une lettre
/// d'information honnête n'en a pas — mais un vendeur qui ne demande rien
/// n'obtiendra rien, et c'est ce que l'avertissement dit au modèle.
const ASK_FRAGMENTS: &[&str] = &[
    "reply",
    "repond",
    "let me know",
    "dites-moi",
    "dites moi",
    "would you",
    "could you",
    "pouvez-vous",
    "pourriez-vous",
    "call",
    "appel",
    "book",
    "schedule",
    "creneau",
    "rendez-vous",
    "tell me",
    "let's",
    "contact",
    "ecri",
    "meet",
];

/// Une chose que le mail a de travers, dans les mots que le modèle relira.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// Stable, en snake_case, un par règle.
    pub code: &'static str,
    /// Le fait mesuré et la borne, pour que la réécriture sache où aller.
    pub detail: String,
}

impl Problem {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

/// Ce que [`check`] a lu. Un refus vide et des avertissements vides est un mail
/// qui part sans commentaire.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Verdict {
    /// Chacune suffit à ne pas envoyer.
    pub refusals: Vec<Problem>,
    /// Journalisées, jamais bloquantes.
    pub warnings: Vec<Problem>,
}

impl Verdict {
    /// Au moins un refus.
    pub fn is_refused(&self) -> bool {
        !self.refusals.is_empty()
    }
}

/// Une ligne par problème, refus d'abord : c'est ce texte que
/// `EffectError::Deliverability` rend au modèle.
impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for problem in &self.refusals {
            writeln!(f, "- {}: {}", problem.code, problem.detail)?;
        }
        for problem in &self.warnings {
            writeln!(f, "- {} (warning): {}", problem.code, problem.detail)?;
        }
        Ok(())
    }
}

/// Lit un sujet et un corps en texte brut et dit ce qui cloche.
///
/// Le corps est `body_text` tel que le modèle l'a écrit : sans le lien de
/// désinscription, qui est ajouté par le fournisseur en en-tête après ce
/// contrôle — voir [`MAX_LINKS`].
pub fn check(subject: &str, body: &str) -> Verdict {
    let mut refusals = Vec::new();
    let mut warnings = Vec::new();

    // -- refus --------------------------------------------------------------
    if subject.trim().is_empty() {
        refusals.push(Problem::new("empty_subject", "the subject is empty"));
    }
    if body.trim().is_empty() {
        refusals.push(Problem::new("empty_body", "the body is empty"));
    }

    let subject_letters = subject.chars().filter(|c| c.is_alphabetic()).count();
    if subject_letters >= SUBJECT_CAPS_MIN_LETTERS
        && subject
            .chars()
            .filter(|c| c.is_alphabetic())
            .all(char::is_uppercase)
    {
        refusals.push(Problem::new(
            "subject_all_caps",
            "the subject is entirely in capitals",
        ));
    }

    let links = links_in(body);
    if links > MAX_LINKS {
        refusals.push(Problem::new(
            "too_many_links",
            format!("{links} links in the body, at most {MAX_LINKS}"),
        ));
    }

    let folded = fold(&format!("{subject}\n{body}"));
    let phrases: Vec<&str> = SPAM_PHRASES
        .iter()
        .copied()
        .filter(|phrase| folded.contains(phrase))
        .collect();
    if phrases.len() >= SPAM_PHRASES_REFUSED_AT {
        refusals.push(Problem::new(
            "spam_phrases",
            format!(
                "{} spam phrases: {}; at most {}",
                phrases.len(),
                phrases.join(", "),
                SPAM_PHRASES_REFUSED_AT - 1
            ),
        ));
    } else if let Some(phrase) = phrases.first() {
        warnings.push(Problem::new(
            "spam_phrase",
            format!("one spam phrase: \"{phrase}\""),
        ));
    }

    let body_letters = body.chars().filter(|c| c.is_alphabetic()).count();
    let body_upper = body.chars().filter(|c| c.is_uppercase()).count();
    if body_letters >= BODY_CAPS_MIN_LETTERS
        && body_upper * 100 > body_letters * BODY_CAPS_MAX_PERCENT
    {
        refusals.push(Problem::new(
            "body_caps",
            format!(
                "{}% of the body's letters are capitals, at most {BODY_CAPS_MAX_PERCENT}%",
                body_upper * 100 / body_letters
            ),
        ));
    }

    let exclamations = subject
        .chars()
        .chain(body.chars())
        .filter(|&c| c == '!')
        .count();
    if exclamations > MAX_EXCLAMATIONS {
        refusals.push(Problem::new(
            "exclamations",
            format!("{exclamations} exclamation marks, at most {MAX_EXCLAMATIONS}"),
        ));
    }

    // -- avertissements ------------------------------------------------------
    let subject_chars = subject.chars().count();
    if subject_chars > SUBJECT_MAX_CHARS {
        warnings.push(Problem::new(
            "subject_long",
            format!(
                "the subject is {subject_chars} characters, {SUBJECT_MAX_CHARS} fit on one line"
            ),
        ));
    }

    let words = body.split_whitespace().count();
    if words > 0 && words < BODY_MIN_WORDS {
        warnings.push(Problem::new(
            "body_short",
            format!("the body is {words} words, under {BODY_MIN_WORDS}"),
        ));
    }

    if body
        .lines()
        .any(|line| line.split_whitespace().count() == 1 && links_in(line) == 1)
    {
        warnings.push(Problem::new(
            "bare_link",
            "a line is nothing but a URL; say what the reader will find there",
        ));
    }

    if !body.contains('?') && !ASK_FRAGMENTS.iter().any(|ask| folded.contains(ask)) {
        warnings.push(Problem::new(
            "no_ask",
            "the body asks nothing — no question and no call to reply, call or book",
        ));
    }

    Verdict { refusals, warnings }
}

/// Combien de mots du texte sont des URL. `http://`, `https://` ou `www.` au
/// début du mot, ponctuation d'encadrement retirée, ce qui suffit pour du
/// texte brut — un vrai parseur d'URL trouverait la même chose à trois
/// contorsions près.
fn links_in(text: &str) -> usize {
    text.split_whitespace()
        .map(|word| word.trim_matches(|c: char| "()<>[]\"'.,;:!?".contains(c)))
        .filter(|word| {
            let word = word.to_ascii_lowercase();
            word.starts_with("http://") || word.starts_with("https://") || word.starts_with("www.")
        })
        .count()
}

/// Minuscules, sans accents : « Cliquez ICI » et « cliquez ici » sont la même
/// expression. NFD puis suppression des marques combinantes, ce qui couvre tout
/// ce que le français écrit ; l'espace insécable devient une espace pour que
/// « 100 % » plié ressemble à « 100 % » tapé.
fn fold(text: &str) -> String {
    text.nfd()
        .filter(|c| !is_combining_mark(*c))
        .map(|c| {
            if c == '\u{a0}' || c == '\u{202f}' {
                ' '
            } else {
                c
            }
        })
        .flat_map(char::to_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Une lettre honnête : un lien, une question, vingt mots et des minuscules.
    const CLEAN_BODY: &str = "Bonjour Marie,\n\nJ'ai lu votre annonce sur le poste de responsable \
         export et je crois que notre outil peut vous faire gagner du temps sur les \
         visas. Auriez-vous vingt minutes cette semaine pour en parler ? Voici la page : \
         https://orizn.example/visas\n\nLena";

    fn codes(problems: &[Problem]) -> Vec<&'static str> {
        problems.iter().map(|p| p.code).collect()
    }

    #[test]
    fn a_plain_letter_passes_with_nothing_to_say() {
        let verdict = check("Visas pour vos équipes", CLEAN_BODY);
        assert!(!verdict.is_refused(), "{verdict}");
        assert!(verdict.warnings.is_empty(), "{verdict}");
    }

    /// Table : pour chaque règle de refus, un cas qui refuse et un cas juste
    /// sous le seuil qui passe. Le sujet et le corps du cas « passe » sont
    /// construits pour ne déclencher **que** la règle testée, sinon un refus
    /// voisin ferait passer un cas rouge pour un cas vert.
    #[test]
    fn each_refusal_bites_and_stops_just_under_its_threshold() {
        let links = |n: usize| {
            format!(
                "{CLEAN_BODY}\n{}",
                (0..n)
                    .map(|i| format!("https://example.com/{i}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        };
        let bangs = |n: usize| format!("{CLEAN_BODY}{}", "!".repeat(n));
        // 40 lettres dont `upper` en majuscules.
        let caps = |upper: usize| {
            let mut s = "A".repeat(upper);
            s.push_str(&"a".repeat(40 - upper));
            format!("{s} ?")
        };

        let cases: Vec<(&str, String, String, Option<&str>)> = vec![
            (
                "empty subject",
                String::new(),
                CLEAN_BODY.into(),
                Some("empty_subject"),
            ),
            (
                "blank subject",
                "   ".into(),
                CLEAN_BODY.into(),
                Some("empty_subject"),
            ),
            ("one-letter subject", "V".into(), CLEAN_BODY.into(), None),
            (
                "empty body",
                "Visas".into(),
                String::new(),
                Some("empty_body"),
            ),
            (
                "all caps subject",
                "VISAS POUR VOUS".into(),
                CLEAN_BODY.into(),
                Some("subject_all_caps"),
            ),
            (
                "a sigle is not a shout",
                "HS".into(),
                CLEAN_BODY.into(),
                None,
            ),
            (
                "one lowercase letter saves it",
                "VISAS POUR VOUs".into(),
                CLEAN_BODY.into(),
                None,
            ),
            (
                "four links",
                "Visas".into(),
                links(MAX_LINKS),
                Some("too_many_links"),
            ),
            ("three links", "Visas".into(), links(MAX_LINKS - 1), None),
            (
                "two spam phrases",
                "Visas".into(),
                format!("{CLEAN_BODY} Act now, click here."),
                Some("spam_phrases"),
            ),
            (
                "two spam phrases across subject and body, accents folded",
                "Offre LIMITÉE".into(),
                format!("{CLEAN_BODY} Cliquez ici."),
                Some("spam_phrases"),
            ),
            (
                "one spam phrase",
                "Visas".into(),
                format!("{CLEAN_BODY} Act now."),
                None,
            ),
            (
                "13 of 40 letters in caps",
                "Visas".into(),
                caps(13),
                Some("body_caps"),
            ),
            ("12 of 40 letters in caps", "Visas".into(), caps(12), None),
            (
                "39 letters, all caps, too short to judge",
                "Visas".into(),
                format!("{} ?", "A".repeat(BODY_CAPS_MIN_LETTERS - 1)),
                None,
            ),
            (
                "four exclamations",
                "Visas".into(),
                bangs(MAX_EXCLAMATIONS + 1),
                Some("exclamations"),
            ),
            (
                "three exclamations",
                "Visas".into(),
                bangs(MAX_EXCLAMATIONS),
                None,
            ),
            (
                "split exclamations count together",
                "Visas!!".into(),
                bangs(2),
                Some("exclamations"),
            ),
        ];
        for (name, subject, body, expected) in cases {
            let verdict = check(&subject, &body);
            match expected {
                Some(code) => assert_eq!(
                    codes(&verdict.refusals),
                    vec![code],
                    "{name}: expected exactly one refusal `{code}`, got {verdict}"
                ),
                None => assert!(
                    !verdict.is_refused(),
                    "{name}: expected no refusal, got {verdict}"
                ),
            }
        }
    }

    #[test]
    fn each_warning_is_a_warning_and_not_a_refusal() {
        let cases: Vec<(&str, String, String, &str)> = vec![
            (
                "79-character subject",
                "s".repeat(SUBJECT_MAX_CHARS + 1),
                CLEAN_BODY.into(),
                "subject_long",
            ),
            (
                "19 words",
                "Visas".into(),
                format!("{} ?", "mot ".repeat(BODY_MIN_WORDS - 2)),
                "body_short",
            ),
            (
                "one spam phrase",
                "Visas".into(),
                format!("{CLEAN_BODY} C'est urgent."),
                "spam_phrase",
            ),
            (
                "a bare URL on its own line",
                "Visas".into(),
                format!("{CLEAN_BODY}\nhttps://orizn.example/prix"),
                "bare_link",
            ),
            (
                "no question, no verb",
                "Visas".into(),
                "Bonjour Marie. Notre outil fait gagner du temps sur les visas à \
                 toutes les équipes export, et il est en ligne depuis mars dernier \
                 avec deux cents clients."
                    .into(),
                "no_ask",
            ),
        ];
        for (name, subject, body, code) in cases {
            let verdict = check(&subject, &body);
            assert!(!verdict.is_refused(), "{name}: refused: {verdict}");
            assert_eq!(codes(&verdict.warnings), vec![code], "{name}: {verdict}");
        }
        // Et le seuil de chacun : juste dessous, rien.
        let quiet = [
            ("s".repeat(SUBJECT_MAX_CHARS), CLEAN_BODY.to_owned()),
            (
                "Visas".into(),
                format!("{} ?", "mot ".repeat(BODY_MIN_WORDS - 1)),
            ),
            (
                "Visas".into(),
                format!("{CLEAN_BODY}\nPrix : https://orizn.example/prix"),
            ),
        ];
        for (subject, body) in quiet {
            let verdict = check(&subject, &body);
            assert!(verdict.warnings.is_empty(), "{subject}: {verdict}");
        }
    }

    #[test]
    fn the_verdict_prints_one_line_per_problem_refusals_first() {
        let verdict = check("", "Act now!!!! click here?");
        let text = verdict.to_string();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines,
            vec![
                "- empty_subject: the subject is empty",
                "- spam_phrases: 2 spam phrases: act now, click here; at most 1",
                "- exclamations: 4 exclamation marks, at most 3",
                "- body_short (warning): the body is 4 words, under 20",
            ]
        );
    }

    #[test]
    fn links_are_counted_by_scheme_or_www_with_punctuation_stripped() {
        assert_eq!(
            links_in("voir (https://a.example), www.b.example. et HTTP://c.example!"),
            3
        );
        assert_eq!(links_in("un mot https-like et wwwx.example"), 0);
    }
}

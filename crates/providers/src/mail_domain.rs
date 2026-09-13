//! Est-ce que ce domaine accepte du courrier ? Une question au DNS, et rien
//! d'autre.
//!
//! # Ce que ça vérifie, et surtout ce que ça ne vérifie pas
//!
//! Une adresse peut être fausse de quatre façons, et elles ne se lisent pas au
//! même endroit :
//!
//! 1. **La syntaxe** — `agentos_domain::action::EmailAddress::parse`, déjà là,
//!    et ce module ne la refait pas.
//! 2. **Le domaine n'existe pas** — NXDOMAIN, une réponse *faisant autorité*.
//!    [`MailDomain::NoSuchDomain`].
//! 3. **Le domaine existe et ne publie aucune destination de courrier** — ni
//!    MX, ni l'adresse que la RFC 5321 §5.1 rend implicite, ou bien un MX nul
//!    au sens de la RFC 7505. [`MailDomain::NoMailExchanger`].
//! 4. **La boîte n'existe pas.** *Pas ici, et pas ailleurs dans ce dépôt.*
//!
//! Le quatrième point est le seul qui demande de parler à un serveur de
//! courrier distant : ouvrir une session SMTP chez l'hébergeur du destinataire
//! et lui présenter un `RCPT TO` sans jamais envoyer le message. C'est ce que
//! vendent les vérificateurs d'adresses, et c'est **une sollicitation** — une
//! connexion non demandée à la machine de quelqu'un, dans le seul but de
//! savoir si quelqu'un habite là. Nous refusons pour trois raisons, dans
//! l'ordre où elles comptent :
//!
//! * C'est exactement ce qu'on reproche aux autres. `docs/CATALOGUE.md` refuse
//!   Apollo pour ses envois sans lecture des désabonnements ; frapper à la
//!   porte de dix mille serveurs pour compter les habitants est du même
//!   registre.
//! * Ça ne marche pas. Les grands hébergeurs (Google, Microsoft) répondent
//!   `250` à tout `RCPT TO` — le *catch-all* — donc la réponse est « oui » pour
//!   une boîte qui n'existe pas, et c'est le cas de la majorité des adresses
//!   d'une liste B2B. Une vérification qui rend « oui » sans information est
//!   pire qu'aucune : elle donne une confiance qu'elle n'a pas mesurée.
//! * Ça coûte le domaine qu'on essaie de sauver. Une IP qui ouvre des sessions
//!   SMTP vers mille serveurs sans jamais envoyer se fait lister ; la sanction
//!   tombe sur l'expéditeur, c'est-à-dire sur la réputation que ce chantier
//!   existe pour protéger.
//!
//! On s'arrête donc au serveur de courrier, et [`crate::mail_domain`] ne parle
//! à personne d'autre qu'au résolveur du système.
//!
//! # Ce n'est pas un contrôle SSRF, et la différence est le fond
//!
//! `agentos_app::mcp::resolve_and_vet` est la seule autre résolution du dépôt.
//! Elle existe parce que **le résultat devient une socket** : le nom vient d'un
//! locataire, et sans elle une liaison MCP atteint le point d'accès de
//! métadonnées du nuage. Ici, rien n'est composé. Le verdict est un booléen qui
//! sert à *ne pas* écrire une ligne ; aucune adresse résolue ne sort de ce
//! module, et `placement` n'a donc rien à juger. Ce qui reste de sa leçon :
//! un nom hostile est quand même un nom que notre résolveur ira demander, d'où
//! [`LOOKUP_TIMEOUT`] et le fait que les appelants sont déjà plafonnés
//! (`max_new_contacts_per_day` pour la découverte, un opérateur devant son
//! terminal pour l'import).
//!
//! # Le cache est celui du résolveur, et son TTL est celui du DNS
//!
//! Une liste de mille adresses porte trois cents domaines distincts. Une
//! requête par adresse serait sept cents requêtes pour rien — mais le cache
//! qui évite ça n'est pas écrit ici : c'est celui de hickory, réglé à
//! [`CACHE_ENTRIES`], et il expire chaque enregistrement au TTL que l'autorité
//! du domaine a publié, positif comme négatif (le `SOA` d'un NXDOMAIN porte le
//! sien). C'est la seule durée de vie qui ait une autorité derrière elle ;
//! n'importe quelle constante écrite ici serait un nombre inventé. Le
//! corollaire est qu'un résolveur se **partage** : une instance par processus,
//! passée par [`crate::mail_domain::MailDomains`], et non une par appel.
//!
//! # Ne pas savoir n'est pas un refus
//!
//! Un `Err` de ce module veut dire « le résolveur n'a pas répondu » — un
//! réseau coupé, un temps dépassé, un `SERVFAIL`. Les appelants ne refusent
//! **jamais** sur un `Err` : ils écrivent la ligne et le disent dans leur
//! rapport. Un résolveur en panne qui écarterait mille adresses valides ferait
//! plus de dégâts en une commande que tous les rebonds qu'il évite.

use std::collections::BTreeMap;
use std::time::Duration;

use async_trait::async_trait;
use hickory_resolver::config::ResolverOpts;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::{Resolver, TokioResolver};

use crate::ProviderError;

/// Plafond sur une question, retransmissions comprises. Un import de mille
/// lignes ne peut pas s'arrêter cinq secondes sur un domaine mort.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);

/// Domaines distincts gardés en mémoire par le résolveur. La valeur par défaut
/// de hickory est 32, ce qui est un cache pour un client interactif et pas pour
/// une liste : à 32, l'import de mille lignes rejoue des questions qu'il a
/// posées trente domaines plus tôt. Mille entrées tiennent dans quelques
/// dizaines de kilo-octets et couvrent la plus grosse liste du fondateur.
pub const CACHE_ENTRIES: u64 = 1_000;

/// Ce que le DNS dit d'un domaine, du point de vue d'une adresse qu'on voudrait
/// écrire dans `contacts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailDomain {
    /// Une destination de courrier est publiée : un `MX` utilisable, ou
    /// l'adresse que la RFC 5321 §5.1 rend implicite en l'absence de `MX`.
    Accepts,
    /// NXDOMAIN : le domaine n'existe pas. Personne ne peut y recevoir quoi que
    /// ce soit, aujourd'hui ni demain sans un enregistrement neuf.
    NoSuchDomain,
    /// Le domaine existe et ne veut pas de courrier : aucun `MX`, aucune adresse
    /// à la place, ou un `MX` nul (`.`, RFC 7505) qui dit explicitement non.
    NoMailExchanger,
}

impl MailDomain {
    /// Écrire une adresse sur ce domaine, oui ou non.
    pub const fn accepts(self) -> bool {
        matches!(self, Self::Accepts)
    }

    /// La raison, en une phrase, telle qu'elle part dans le rapport d'un import.
    /// Nos mots, pas ceux d'un serveur : rien de ce que le DNS a répondu ne
    /// traverse.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Accepts => "the domain publishes a mail exchanger",
            Self::NoSuchDomain => "the domain does not exist (NXDOMAIN)",
            Self::NoMailExchanger => "the domain publishes no mail exchanger",
        }
    }
}

/// Demander au DNS si un domaine accepte du courrier.
///
/// Un port, contre l'habitude de [`crate::dns_cloudflare`] qui refuse d'en être
/// un : il y a deux implémentations et la seconde n'est pas spéculative, c'est
/// [`MockMailDomains`]. Un test de ce dépôt ne touche pas le réseau, et une
/// suite qui interroge le vrai DNS est une suite qui rougit dans un train.
#[async_trait]
pub trait MailDomains: Send + Sync {
    /// `domain` est déjà un domaine — ce que `Domain::parse` ou
    /// `EmailAddress::domain()` ont produit, pas une chaîne libre.
    ///
    /// `Err` veut dire « pas de réponse », jamais « non » : voir l'en-tête du
    /// module.
    async fn lookup(&self, domain: &str) -> Result<MailDomain, ProviderError>;
}

/// Le vrai : le résolveur du système, tel que `/etc/resolv.conf` le décrit.
pub struct HickoryMailDomains {
    resolver: TokioResolver,
}

impl std::fmt::Debug for HickoryMailDomains {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HickoryMailDomains")
    }
}

impl HickoryMailDomains {
    /// Une instance par processus — c'est elle qui porte le cache.
    ///
    /// `Err` est un système sans configuration DNS lisible, ce qui est un
    /// déploiement cassé et pas une adresse douteuse.
    pub fn from_system() -> Result<Self, NetError> {
        let mut builder = Resolver::builder_tokio()?;
        let opts: &mut ResolverOpts = builder.options_mut();
        opts.timeout = LOOKUP_TIMEOUT;
        opts.cache_size = CACHE_ENTRIES;
        // Un domaine de prospect est absolu. Sans ça, `example.com` est
        // réessayé sous le `search` de la machine — `example.com.ec2.internal`
        // — ce qui est du bruit et, sur un résolveur joker, une réponse fausse.
        opts.ndots = 0;
        Ok(Self {
            resolver: builder.build()?,
        })
    }
}

#[async_trait]
impl MailDomains for HickoryMailDomains {
    async fn lookup(&self, domain: &str) -> Result<MailDomain, ProviderError> {
        // Le point final force le nom en absolu : aucune liste `search` ne s'y
        // ajoute, quelle que soit la machine qui fait tourner le binaire.
        let fqdn = format!("{}.", domain.trim_end_matches('.'));
        match self.resolver.mx_lookup(&fqdn).await {
            // Un `MX` dont l'échange est la racine (`.`) est le « null MX » de
            // la RFC 7505 : le domaine déclare qu'il ne reçoit pas de courrier.
            // C'est la seule réponse positive du DNS qui soit un refus.
            Ok(found) => Ok(if found.answers().iter().any(usable_mx) {
                MailDomain::Accepts
            } else {
                MailDomain::NoMailExchanger
            }),
            Err(err) => match no_records(&err) {
                // NXDOMAIN : le nom n'existe pas. Inutile de chercher une
                // adresse, elle n'existera pas non plus.
                Some(ResponseCode::NXDomain) => Ok(MailDomain::NoSuchDomain),
                // Le nom existe, il n'a simplement pas de `MX`. RFC 5321 §5.1 :
                // l'adresse du domaine est alors le serveur de courrier
                // implicite, et beaucoup de petits domaines n'ont que ça.
                // Sauter cette retombée, c'est écarter des adresses valides.
                Some(_) => match self.resolver.lookup_ip(&fqdn).await {
                    Ok(ips) if ips.iter().next().is_some() => Ok(MailDomain::Accepts),
                    Ok(_) => Ok(MailDomain::NoMailExchanger),
                    Err(err) if no_records(&err) == Some(ResponseCode::NXDomain) => {
                        Ok(MailDomain::NoSuchDomain)
                    }
                    Err(err) if no_records(&err).is_some() => Ok(MailDomain::NoMailExchanger),
                    Err(_) => Err(unavailable()),
                },
                // SERVFAIL, temps dépassé, pas de réseau : on ne sait pas.
                None => Err(unavailable()),
            },
        }
    }
}

/// Un `MX` qui désigne vraiment une machine. La réponse peut aussi porter des
/// `CNAME` (ignorés) et, une fois sur mille, l'échange racine `.` du MX nul de
/// la RFC 7505 — le seul enregistrement qui dise « n'écrivez pas ici ».
fn usable_mx(record: &hickory_resolver::proto::rr::Record) -> bool {
    matches!(&record.data, RData::MX(mx) if !mx.exchange.is_root())
}

/// Le code de réponse d'un « pas d'enregistrement », ou `None` si l'erreur est
/// une panne. C'est **la** distinction du module : une réponse faisant autorité
/// contre une absence de réponse.
fn no_records(err: &NetError) -> Option<ResponseCode> {
    match err {
        NetError::Dns(DnsError::NoRecordsFound(found)) => Some(found.response_code),
        _ => None,
    }
}

fn unavailable() -> ProviderError {
    ProviderError::Retryable {
        after: LOOKUP_TIMEOUT,
    }
}

/// Le faux : une table de domaines, et rien d'autre.
///
/// Un domaine absent de la table rend [`MailDomain::NoSuchDomain`], ce qui est
/// le bon défaut pour un test — un test qui oublie de déclarer un domaine voit
/// son adresse écartée, pas admise par inadvertance.
#[derive(Debug, Default)]
pub struct MockMailDomains {
    verdicts: BTreeMap<String, MailDomain>,
    /// Les domaines pour lesquels le résolveur « ne répond pas ».
    unreachable: Vec<String>,
}

impl MockMailDomains {
    /// Une table vide : tout est NXDOMAIN.
    pub fn new() -> Self {
        Self::default()
    }

    /// Tous ces domaines acceptent du courrier.
    pub fn accepting(domains: &[&str]) -> Self {
        let mut mock = Self::new();
        for domain in domains {
            mock = mock.with(domain, MailDomain::Accepts);
        }
        mock
    }

    /// Poser un verdict.
    #[must_use]
    pub fn with(mut self, domain: &str, verdict: MailDomain) -> Self {
        self.verdicts.insert(domain.to_ascii_lowercase(), verdict);
        self
    }

    /// Ce domaine-là fait tomber le résolveur en panne : `Err`, donc « je ne
    /// sais pas », donc pas de refus chez l'appelant.
    #[must_use]
    pub fn unreachable(mut self, domain: &str) -> Self {
        self.unreachable.push(domain.to_ascii_lowercase());
        self
    }
}

#[async_trait]
impl MailDomains for MockMailDomains {
    async fn lookup(&self, domain: &str) -> Result<MailDomain, ProviderError> {
        let domain = domain.to_ascii_lowercase();
        if self.unreachable.contains(&domain) {
            return Err(unavailable());
        }
        Ok(self
            .verdicts
            .get(&domain)
            .copied()
            .unwrap_or(MailDomain::NoSuchDomain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_accepts_lets_an_address_through() {
        assert!(MailDomain::Accepts.accepts());
        assert!(!MailDomain::NoSuchDomain.accepts());
        assert!(!MailDomain::NoMailExchanger.accepts());
    }

    #[tokio::test]
    async fn the_mock_answers_from_its_table_and_nxdomain_otherwise() {
        let mx = MockMailDomains::accepting(&["orizn.example"])
            .with("parked.example", MailDomain::NoMailExchanger)
            .unreachable("servfail.example");
        assert_eq!(
            mx.lookup("ORIZN.example").await.unwrap(),
            MailDomain::Accepts,
            "un domaine se compare sans casse"
        );
        assert_eq!(
            mx.lookup("parked.example").await.unwrap(),
            MailDomain::NoMailExchanger
        );
        assert_eq!(
            mx.lookup("jamais-declare.example").await.unwrap(),
            MailDomain::NoSuchDomain
        );
        assert!(
            mx.lookup("servfail.example").await.is_err(),
            "une panne est une erreur, pas un verdict"
        );
    }

    /// Le vrai résolveur ne se construit pas dans un test : il lit
    /// `/etc/resolv.conf`, et sa première question partirait sur le réseau.
    /// Ce qui se teste sans réseau, c'est la table de correspondance entre une
    /// erreur du protocole et un verdict — la seule logique de l'adaptateur.
    #[test]
    fn an_authoritative_no_is_a_verdict_and_a_failure_is_not() {
        use hickory_resolver::net::NoRecords;
        use hickory_resolver::proto::op::Query;

        let no_records_for = |code| {
            NetError::Dns(DnsError::NoRecordsFound(NoRecords::new(
                Query::default(),
                code,
            )))
        };
        assert_eq!(
            no_records(&no_records_for(ResponseCode::NXDomain)),
            Some(ResponseCode::NXDomain),
            "le domaine n'existe pas : un verdict"
        );
        assert_eq!(
            no_records(&no_records_for(ResponseCode::NoError)),
            Some(ResponseCode::NoError),
            "« pas de MX » sur un domaine qui existe doit retomber sur l'adresse"
        );
        for panne in [
            NetError::Timeout,
            NetError::Dns(DnsError::ResponseCode(ResponseCode::ServFail)),
            NetError::Dns(DnsError::ResponseCode(ResponseCode::Refused)),
        ] {
            assert_eq!(
                no_records(&panne),
                None,
                "une panne ne doit jamais écarter une adresse : {panne}"
            );
        }
    }

    /// Le MX nul de la RFC 7505 (`.`) est le seul enregistrement présent qui
    /// soit un refus, et un `CNAME` dans la réponse n'est pas un serveur de
    /// courrier.
    #[test]
    fn a_null_mx_is_a_refusal_and_a_cname_is_not_an_answer() {
        use hickory_resolver::proto::rr::rdata::{CNAME, MX};
        use hickory_resolver::proto::rr::{Name, Record};

        let name: Name = "example.com.".parse().unwrap();
        let mx = |exchange: &str| {
            Record::from_rdata(
                name.clone(),
                300,
                RData::MX(MX::new(10, exchange.parse().unwrap())),
            )
        };
        assert!(usable_mx(&mx("mail.example.com.")));
        assert!(!usable_mx(&mx(".")), "MX nul : le domaine dit non");
        assert!(!usable_mx(&Record::from_rdata(
            name,
            300,
            RData::CNAME(CNAME("ailleurs.example.com.".parse().unwrap())),
        )));
    }
}

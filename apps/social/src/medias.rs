//! Le téléchargement des médias : LA surface d'attaque de ce chantier.
//!
//! L'agent fournit une URL ; ce module la télécharge. Sans vet, c'est un SSRF
//! clé en main : `https://169.254.169.254/latest/meta-data` servirait les
//! credentials du cloud à quiconque tient un jeton de tenant. Donc :
//! https seulement, IP publique seulement (la discipline de `placement()`
//! dans crates/app/src/mcp.rs, recopiée plus bas), connexion épinglée sur
//! l'IP vettée (pas de re-résolution entre le vet et le GET — anti
//! DNS-rebinding), plafond compté EN VOL (un Content-Length menteur ne
//! remplit ni la RAM ni le disque), et le type lu sur les OCTETS — jamais
//! sur l'extension ni sur le Content-Type annoncé, qui sont des déclarations,
//! pas des preuves.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use url::Url;

use crate::adapters::{MediaPret, TypeMedia};

/// NOTRE garde-fou, au-dessus de tous les adaptateurs : aucune plateforme
/// n'impose ce chiffre, il borne ce que ce service accepte de tenir EN
/// MÉMOIRE pour un seul média. Il couvre les 500 MB de la vidéo feed
/// LinkedIn ; les vidéos X 8/16 GB (selon le statut Premium du compte) sont
/// hors plafond v1.
/// ponytail: tout le média vit en RAM ; le chemin d'upgrade est le streaming
/// direct vers l'upload chunké de la plateforme, sans jamais tenir le tout.
pub const PLAFOND_ABSOLU_OCTETS: u64 = 512 * 1024 * 1024;

/// Timeout du téléchargement, nommé : un agent attend derrière, et une URL
/// qui goutte un octet par seconde est une attaque de rétention, pas un CDN.
pub const TIMEOUT_TELECHARGEMENT: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Les refus, nommés
// ---------------------------------------------------------------------------

/// Chaque refus du téléchargeur, avec son code stable pour l'agent. Aucune
/// variante ne porte un octet du corps de réponse — même discipline
/// anti-fuite que `ErreurPlateforme`.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ErreurMedia {
    #[error("seul https est permis pour une URL de média")]
    HttpsSeulement,
    #[error("`{hote}` mène à une adresse non publique — refusé")]
    UrlPrivee { hote: String },
    #[error("média au-dessus du plafond du service ({plafond} octets)")]
    TropLourd { plafond: u64 },
    #[error("octets d'aucun type servi (jpeg, png, gif, webp, mp4, pdf)")]
    TypeInconnu,
    #[error("média injoignable : {detail}")]
    Injoignable { detail: String },
}

impl ErreurMedia {
    /// Le code stable que les réponses d'outil montrent aux agents.
    pub fn code(&self) -> &'static str {
        match self {
            Self::HttpsSeulement => "https_seulement",
            Self::UrlPrivee { .. } => "url_privee",
            Self::TropLourd { .. } => "media_trop_lourd",
            Self::TypeInconnu => "type_inconnu",
            Self::Injoignable { .. } => "media_injoignable",
        }
    }
}

fn injoignable(detail: impl Into<String>) -> ErreurMedia {
    ErreurMedia::Injoignable {
        detail: detail.into(),
    }
}

// ---------------------------------------------------------------------------
// Le vet d'adresse — la discipline de crates/app/src/mcp.rs, recopiée
// ---------------------------------------------------------------------------

/// Où se place une adresse résolue. Recopie de `placement()` dans
/// crates/app/src/mcp.rs (~l.429) : ce binaire ne dépend pas de crates/app,
/// mais la discipline SSRF doit être LA MÊME phrase — et ici elle est même
/// plus stricte : seul `Global` passe. Un serveur MCP peut légitimement être
/// un sidecar privé (opt-in `Reach::Private`) ; une URL de média, jamais.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    Global,
    Private,
    Forbidden,
}

fn placement(ip: IpAddr) -> Placement {
    match ip {
        IpAddr::V4(v4) => placement_v4(v4),
        // `::1` d'abord : il tombe dans la plage IPv4-compatible et se lirait
        // sinon comme l'adresse v4 `0.0.0.1`.
        IpAddr::V6(v6) if v6.is_loopback() => Placement::Private,
        // Une adresse IPv4 en costume IPv6 reste cette adresse IPv4 :
        // `to_ipv4` couvre `::ffff:169.254.169.254` ET la forme dépréciée
        // `::169.254.169.254`, et ni l'une ni l'autre n'échappe aux règles v4.
        IpAddr::V6(v6) => v6.to_ipv4().map_or_else(|| placement_v6(v6), placement_v4),
    }
}

fn placement_v4(ip: Ipv4Addr) -> Placement {
    let [a, b, ..] = ip.octets();
    if ip.is_link_local()          // 169.254/16 — le point metadata du cloud
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || a == 0                  // « ce réseau »
        || (a == 100 && (64..128).contains(&b))  // CGNAT 100.64/10
        || (a == 192 && b == 0)    // assignations IETF 192.0.0/24
        || (a == 198 && (b == 18 || b == 19))    // benchmarking 198.18/15
        || a >= 240
    {
        Placement::Forbidden
    } else if ip.is_loopback() || ip.is_private() {
        Placement::Private
    } else {
        Placement::Global
    }
}

fn placement_v6(ip: Ipv6Addr) -> Placement {
    // `is_unicast_link_local` et `is_unique_local` sont encore instables :
    // les deux préfixes se lisent à la main — fe80::/10 et fc00::/7.
    let tete = ip.segments()[0];
    if ip.is_unspecified() || ip.is_multicast() || (tete & 0xffc0) == 0xfe80 {
        Placement::Forbidden
    } else if ip.is_loopback() || (tete & 0xfe00) == 0xfc00 {
        Placement::Private
    } else {
        Placement::Global
    }
}

/// Vet une URL de média : https seul, hôte résolu, CHAQUE adresse vérifiée —
/// un hôte qui résout vers une seule adresse interne est refusé en bloc,
/// parce qu'on ne choisit pas laquelle le noyau prendra. Rend l'URL et la
/// première adresse vettée : c'est SUR ELLE que la connexion s'épingle.
pub async fn vetter_url(brute: &str) -> Result<(Url, IpAddr), ErreurMedia> {
    let url = Url::parse(brute).map_err(|_| injoignable("URL illisible"))?;
    if url.scheme() != "https" {
        return Err(ErreurMedia::HttpsSeulement);
    }
    let hote = url.host_str().unwrap_or_default().to_owned();
    let port = url.port_or_known_default().unwrap_or(443);
    let adresses: Vec<IpAddr> = match url.host() {
        Some(url::Host::Ipv4(ip)) => vec![IpAddr::V4(ip)],
        Some(url::Host::Ipv6(ip)) => vec![IpAddr::V6(ip)],
        Some(url::Host::Domain(domaine)) => tokio::net::lookup_host((domaine, port))
            .await
            .map_err(|e| injoignable(format!("résolution de {domaine} : {e}")))?
            .map(|sa| sa.ip())
            .collect(),
        None => return Err(injoignable("URL sans hôte")),
    };
    if adresses.is_empty() {
        return Err(injoignable(format!("{hote} ne résout vers rien")));
    }
    for ip in &adresses {
        if placement(*ip) != Placement::Global {
            return Err(ErreurMedia::UrlPrivee { hote });
        }
    }
    Ok((url, adresses[0]))
}

// ---------------------------------------------------------------------------
// La lecture bornée et la détection de type
// ---------------------------------------------------------------------------

/// Lit un corps EN COMPTANT, coupé au premier octet au-dessus du plafond.
///
/// Le Content-Length est vérifié avant d'appeler ici, mais il peut mentir ou
/// manquer (transfert chunké : hyper cadre le corps sur Content-Length quand
/// il existe, donc la vraie voie d'un corps sans borne annoncée est le
/// chunké) — c'est CE compte qui protège la RAM, pas l'annonce.
pub async fn lire_borne(
    reponse: &mut reqwest::Response,
    plafond: u64,
) -> Result<Vec<u8>, ErreurMedia> {
    let mut octets: Vec<u8> = Vec::new();
    while let Some(morceau) = reponse
        .chunk()
        .await
        .map_err(|e| injoignable(format!("lecture du corps : {e}")))?
    {
        if octets.len() as u64 + morceau.len() as u64 > plafond {
            return Err(ErreurMedia::TropLourd { plafond });
        }
        octets.extend_from_slice(&morceau);
    }
    Ok(octets)
}

/// Détecte le type AUX OCTETS (magic bytes) : JPEG `FF D8 FF`, PNG
/// `89 50 4E 47 0D 0A 1A 0A`, GIF `GIF87a`/`GIF89a`, WEBP `RIFF`+`WEBP`@8,
/// MP4 `ftyp`@4, PDF `%PDF-`. L'extension et le Content-Type sont des
/// déclarations du serveur d'en face ; les octets sont ce qu'on publiera.
pub fn detecter_type(octets: &[u8]) -> Option<TypeMedia> {
    if octets.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some(TypeMedia::Jpeg)
    } else if octets.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        Some(TypeMedia::Png)
    } else if octets.starts_with(b"GIF87a") || octets.starts_with(b"GIF89a") {
        Some(TypeMedia::Gif)
    } else if octets.starts_with(b"RIFF") && octets.get(8..12) == Some(b"WEBP".as_slice()) {
        Some(TypeMedia::Webp)
    } else if octets.get(4..8) == Some(b"ftyp".as_slice()) {
        Some(TypeMedia::Mp4)
    } else if octets.starts_with(b"%PDF-") {
        Some(TypeMedia::Pdf)
    } else {
        None
    }
}

/// SHA-256 hex d'octets bruts — le digest qu'une approbation contresigne.
/// (`adapters::empreinte` fait pareil sur du texte ; celui-ci prend les
/// octets d'un média tel quel.)
pub fn hex_sha256(octets: &[u8]) -> String {
    Sha256::digest(octets)
        .iter()
        .fold(String::with_capacity(64), |mut out, o| {
            use std::fmt::Write;
            let _ = write!(out, "{o:02x}");
            out
        })
}

// ---------------------------------------------------------------------------
// Le téléchargeur
// ---------------------------------------------------------------------------

pub struct Telechargeur {
    plafond: u64,
    /// Posé UNIQUEMENT par le constructeur `#[cfg(test)]` — jamais par la
    /// config : un opérateur ne doit pas pouvoir rouvrir la boucle locale en
    /// production, même en le voulant. Les tests montent leurs serveurs sur
    /// 127.0.0.1 en http (un TLS de test n'ajouterait rien à ce qu'on teste).
    permettre_boucle_locale: bool,
}

impl Default for Telechargeur {
    fn default() -> Self {
        Self::new()
    }
}

impl Telechargeur {
    pub fn new() -> Self {
        Self {
            plafond: PLAFOND_ABSOLU_OCTETS,
            permettre_boucle_locale: false,
        }
    }

    /// Le constructeur des tests : plafond choisi (on ne streame pas 512 MiB
    /// dans un test) et boucle locale permise.
    #[cfg(test)]
    pub fn de_test(plafond: u64) -> Self {
        Self {
            plafond,
            permettre_boucle_locale: true,
        }
    }

    /// Télécharge, vet et empreinte UN média. `alt_text` et `title` ne font
    /// que voyager : les vérifier est le travail des adaptateurs.
    pub async fn telecharger(
        &self,
        brute: &str,
        alt_text: Option<String>,
        title: Option<String>,
    ) -> Result<MediaPret, ErreurMedia> {
        let (url, epingle) = self.vetter(brute).await?;

        let mut fabrique = reqwest::Client::builder()
            // Une redirection est une re-résolution déguisée : coupée. Le
            // serveur qui 302 vers 169.254.169.254 n'aura pas son GET.
            .redirect(reqwest::redirect::Policy::none())
            .timeout(TIMEOUT_TELECHARGEMENT);
        // Connexion ÉPINGLÉE sur l'adresse vettée : entre le vet et le GET,
        // un DNS complice pourrait changer de réponse (rebinding). `resolve`
        // court-circuite la re-résolution — on parle à l'IP qu'on a jugée.
        if let (Some(url::Host::Domain(domaine)), Some(ip)) = (url.host(), epingle) {
            let port = url.port_or_known_default().unwrap_or(443);
            fabrique = fabrique.resolve(domaine, SocketAddr::new(ip, port));
        }
        let client = fabrique
            .build()
            .map_err(|e| injoignable(format!("client http : {e}")))?;

        let mut reponse = client
            .get(url)
            .send()
            .await
            .map_err(|e| injoignable(e.to_string()))?;
        let statut = reponse.status();
        if !statut.is_success() {
            return Err(injoignable(format!("statut {statut}")));
        }
        // Content-Length AVANT le corps : quand l'annonce dépasse déjà le
        // plafond, on refuse sans lire un octet…
        if let Some(annonce) = reponse.content_length()
            && annonce > self.plafond
        {
            return Err(ErreurMedia::TropLourd {
                plafond: self.plafond,
            });
        }
        // …et on compte quand même EN VOL : l'annonce peut mentir ou manquer.
        let octets = lire_borne(&mut reponse, self.plafond).await?;

        let type_detecte = detecter_type(&octets).ok_or(ErreurMedia::TypeInconnu)?;
        let digest = hex_sha256(&octets);
        Ok(MediaPret {
            octets: Arc::new(octets),
            type_detecte,
            digest,
            alt_text,
            title,
        })
    }

    /// Le vet, avec la seule exception du constructeur de test : une boucle
    /// locale EXPLICITEMENT en 127.0.0.0/8 ou ::1, pour parler au serveur du
    /// test. Tout le reste — même en mode test — passe par `vetter_url`.
    async fn vetter(&self, brute: &str) -> Result<(Url, Option<IpAddr>), ErreurMedia> {
        if self.permettre_boucle_locale {
            let url = Url::parse(brute).map_err(|_| injoignable("URL illisible"))?;
            let boucle = match url.host() {
                Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
                Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
                _ => false,
            };
            if boucle {
                return Ok((url, None));
            }
        }
        let (url, ip) = vetter_url(brute).await?;
        Ok((url, Some(ip)))
    }
}

// L'empreinte globale du contrat C3 vit dans `adapters::empreinte_globale` :
// les adaptateurs la calculent (le champ `digest` de leur Apercu), le cœur la
// consomme — une seule formule, pas deux qui divergeraient à la couture.

// ---------------------------------------------------------------------------
// Aide aux tests (partagée avec les tests de mcp.rs)
// ---------------------------------------------------------------------------

/// Un serveur TCP brut qui sert la MÊME réponse à chaque connexion, et rend
/// sa base http. Brut exprès : mentir sur Content-Length ou parler chunké
/// demande la main sur les octets, pas un framework qui corrigerait le
/// mensonge qu'on veut justement tester.
#[cfg(test)]
pub(crate) async fn serveur_brut(reponse: Vec<u8>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let ecoute = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let adresse = ecoute.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut prise, _)) = ecoute.accept().await else {
                return;
            };
            let corps = reponse.clone();
            tokio::spawn(async move {
                let mut tampon = [0u8; 4096];
                let _ = prise.read(&mut tampon).await; // la requête, ignorée
                let _ = prise.write_all(&corps).await;
                let _ = prise.flush().await;
                // Laisser le client finir de lire avant le FIN.
                tokio::time::sleep(Duration::from_millis(200)).await;
            });
        }
    });
    format!("http://{adresse}")
}

/// Une réponse HTTP 200 honnête (Content-Length juste) autour d'un corps.
#[cfg(test)]
pub(crate) fn reponse_http(content_type: &str, corps: &[u8]) -> Vec<u8> {
    let mut r = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
        corps.len()
    )
    .into_bytes();
    r.extend_from_slice(corps);
    r
}

/// Des octets qui SONT un PNG (le magic de 8 octets) suivis d'un lest — assez
/// pour que `detecter_type` dise Png, quel que soit le nom de fichier.
#[cfg(test)]
pub(crate) fn octets_png(lest: &[u8]) -> Vec<u8> {
    let mut o = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    o.extend_from_slice(lest);
    o
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Le vet d'URL : chaque littéral du brief, et le refus est nommé. ----

    #[tokio::test]
    async fn http_est_refuse_avant_toute_resolution() {
        assert!(matches!(
            vetter_url("http://example.com/photo.png").await,
            Err(ErreurMedia::HttpsSeulement)
        ));
    }

    #[tokio::test]
    async fn les_adresses_privees_sont_refusees() {
        for privee in [
            "https://127.0.0.1/photo.png",
            "https://169.254.169.254/latest/meta-data",
            "https://[::1]/photo.png",
            "https://192.168.1.1/photo.png",
        ] {
            assert!(
                matches!(vetter_url(privee).await, Err(ErreurMedia::UrlPrivee { .. })),
                "{privee} aurait dû être refusée url_privee"
            );
        }
    }

    #[tokio::test]
    async fn le_constructeur_normal_refuse_la_boucle_locale() {
        // La preuve que `permettre_boucle_locale` n'existe qu'en test : le
        // constructeur normal refuse 127.0.0.1 comme n'importe quelle privée.
        let t = Telechargeur::new();
        assert!(matches!(
            t.telecharger("https://127.0.0.1/photo.png", None, None)
                .await,
            Err(ErreurMedia::UrlPrivee { .. })
        ));
    }

    // -- La détection de type : les octets, jamais la déclaration. ----------

    #[test]
    fn chaque_magic_donne_son_type_et_l_inconnu_rien() {
        assert_eq!(
            detecter_type(&[0xFF, 0xD8, 0xFF, 0xE0]),
            Some(TypeMedia::Jpeg)
        );
        assert_eq!(detecter_type(&octets_png(b"x")), Some(TypeMedia::Png));
        assert_eq!(detecter_type(b"GIF87a..."), Some(TypeMedia::Gif));
        assert_eq!(detecter_type(b"GIF89a..."), Some(TypeMedia::Gif));
        assert_eq!(
            detecter_type(b"RIFF\x00\x00\x00\x00WEBPVP8 "),
            Some(TypeMedia::Webp)
        );
        assert_eq!(
            detecter_type(b"\x00\x00\x00\x20ftypisom"),
            Some(TypeMedia::Mp4)
        );
        assert_eq!(detecter_type(b"%PDF-1.7\n"), Some(TypeMedia::Pdf));
        assert_eq!(detecter_type(b"<svg xmlns="), None);
        assert_eq!(detecter_type(b""), None);
    }

    // -- Le plafond : avant le corps, et en vol. ----------------------------

    #[tokio::test]
    async fn une_annonce_au_dessus_du_plafond_est_refusee_sans_lire_le_corps() {
        // Le serveur annonce 4097 octets et n'envoie JAMAIS de corps : si le
        // client rend TropLourd (et pas un timeout/Injoignable), c'est qu'il
        // a jugé sur l'annonce seule — zéro octet lu.
        let entetes = b"HTTP/1.1 200 OK\r\nContent-Length: 4097\r\n\r\n".to_vec();
        let base = serveur_brut(entetes).await;
        let t = Telechargeur::de_test(4096);
        // Pas d'unwrap_err : MediaPret ne dérive pas Debug (contrat C2).
        let Err(erreur) = t.telecharger(&format!("{base}/gros.png"), None, None).await else {
            panic!("une annonce au-dessus du plafond aurait dû être refusée");
        };
        assert!(
            matches!(erreur, ErreurMedia::TropLourd { plafond: 4096 }),
            "{erreur}"
        );
    }

    #[tokio::test]
    async fn un_corps_sans_annonce_est_coupe_en_vol_au_plafond() {
        // Le mensonge « Content-Length petit, corps plus grand » est déjà
        // neutralisé par le cadrage hyper (le corps s'arrête à l'annonce).
        // La vraie voie d'un corps sans borne annoncée est le transfert
        // chunké : 64 KiB streamés contre un plafond de 4 KiB — le compte en
        // vol doit couper, pas accumuler.
        let mut rep = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for _ in 0..64 {
            rep.extend_from_slice(b"400\r\n"); // 0x400 = 1024 octets
            rep.extend_from_slice(&[b'a'; 1024]);
            rep.extend_from_slice(b"\r\n");
        }
        rep.extend_from_slice(b"0\r\n\r\n");
        let base = serveur_brut(rep).await;
        let t = Telechargeur::de_test(4096);
        let Err(erreur) = t.telecharger(&format!("{base}/flot.png"), None, None).await else {
            panic!("un corps chunké au-dessus du plafond aurait dû être coupé");
        };
        assert!(
            matches!(erreur, ErreurMedia::TropLourd { plafond: 4096 }),
            "{erreur}"
        );
    }

    // -- Les octets contre la déclaration. ----------------------------------

    #[tokio::test]
    async fn des_octets_png_sous_extension_et_content_type_menteurs_sont_un_png() {
        let corps = octets_png(b"le corps du png");
        let base = serveur_brut(reponse_http("image/jpeg", &corps)).await;
        let t = Telechargeur::de_test(PLAFOND_ABSOLU_OCTETS);
        let media = t
            .telecharger(&format!("{base}/photo.jpg"), Some("alt".into()), None)
            .await
            .unwrap();
        // `.jpg` dans l'URL, `image/jpeg` dans l'en-tête : les octets tranchent.
        assert_eq!(media.type_detecte, TypeMedia::Png);
        assert_eq!(media.type_detecte.mime(), "image/png");
        assert_eq!(media.digest, hex_sha256(&corps));
        assert_eq!(media.alt_text.as_deref(), Some("alt"));
    }

    // Les tests de l'empreinte globale (contrat C3) vivent avec elle, dans
    // adapters/mod.rs — une formule, un seul jeu de tests. Le rejeu de bout
    // en bout (même clé + image différente => cle_reutilisee) est prouvé
    // contre la base dans les tests de mcp.rs.
}

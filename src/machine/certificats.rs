//! Certificats racine ajoutés : celui qui en installe un peut fabriquer un faux certificat pour n'importe quel
//! site et lire tout le trafic HTTPS (banque, courriel), sans le moindre avertissement du navigateur.
//! Les certificats livrés par le système ne sont pas examinés : seulement ceux ajoutés à côté.

use super::{Constat, alerte, ok};
use crate::risk::Niveau;
use crate::{tr, trf};

const CAT: &str = "Certificats";

/// Ce qu'on sait d'un certificat d'après son nom.
#[derive(Debug, PartialEq, Clone, Copy)]
pub(crate) enum Famille {
    /// Logiciel connu pour avoir installé une racine dont la clé privée est la même partout (Superfish…).
    Compromis,
    /// Outil d'interception du trafic (débogage, test d'intrusion) : quiconque a sa clé lit tout.
    Interception,
    /// Antivirus, filtre ou proxy d'entreprise qui inspecte le HTTPS.
    Inspection,
    /// Autorité de développement (mkcert).
    Developpement,
    Autre,
}

pub(crate) fn famille(nom: &str) -> Famille {
    let n = nom.to_lowercase();
    let contient = |motifs: &[&str]| motifs.iter().any(|m| n.contains(m));
    if contient(&["superfish", "edellroot", "dsdtestprovider", "komodia", "privdog"]) {
        Famille::Compromis
    } else if contient(&[
        "mitmproxy",
        "fiddler",
        "charles proxy",
        "portswigger",
        "burp",
        "owasp zap",
        "zap root",
        "proxyman",
        "http toolkit",
        "httptoolkit",
    ]) {
        Famille::Interception
    } else if contient(&[
        "avast",
        "avg ",
        "kaspersky",
        "eset ssl",
        "bitdefender",
        "norton",
        "mcafee",
        "webroot",
        "adguard",
        "zscaler",
        "netskope",
        "umbrella",
        "sophos",
        "fortinet",
        "fortigate",
        "blue coat",
        "forcepoint",
        "palo alto",
        "untangle",
    ]) {
        Famille::Inspection
    } else if contient(&["mkcert"]) {
        Famille::Developpement
    } else {
        Famille::Autre
    }
}

/// Un élément DER : (étiquette, contenu, reste après lui).
pub(crate) fn tlv(octets: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&etiquette, reste) = octets.split_first()?;
    let (&premier, reste) = reste.split_first()?;
    let (longueur, reste) = if premier < 0x80 {
        (usize::from(premier), reste)
    } else {
        let n = usize::from(premier & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let (octets_longueur, reste) = reste.split_at_checked(n)?;
        let longueur = octets_longueur.iter().fold(0usize, |acc, &o| acc << 8 | usize::from(o));
        (longueur, reste)
    };
    let (contenu, apres) = reste.split_at_checked(longueur)?;
    Some((etiquette, contenu, apres))
}

/// Valeur d'un attribut d'un nom X.500 (CN = 2.5.4.3, O = 2.5.4.10…), donné par le dernier octet de son OID.
pub(crate) fn attribut(nom: &[u8], code: u8) -> Option<String> {
    let mut ensembles = nom;
    while let Some((_, ensemble, suite)) = tlv(ensembles) {
        ensembles = suite;
        let Some((_, paire, _)) = tlv(ensemble) else { continue };
        let Some((0x06, oid, reste)) = tlv(paire) else { continue };
        if oid == [0x55, 0x04, code]
            && let Some((genre, valeur, _)) = tlv(reste)
        {
            return Some(if genre == 0x1e {
                // BMPString : UTF-16 gros-boutiste.
                // Un octet seul en bout (longueur impaire) reste complété d'un zéro, comme avant.
                let (paires, impair) = valeur.as_chunks::<2>();
                let unites: Vec<u16> = paires
                    .iter()
                    .map(|&p| u16::from_be_bytes(p))
                    .chain(impair.first().map(|&o| u16::from_be_bytes([o, 0])))
                    .collect();
                String::from_utf16_lossy(&unites)
            } else {
                String::from_utf8_lossy(valeur).into_owned()
            });
        }
    }
    None
}

/// Nom du sujet d'un certificat DER : son CN, sinon son organisation, sinon son unité.
pub(crate) fn sujet(der: &[u8]) -> Option<String> {
    let (_, certificat, _) = tlv(der)?;
    let (_, tbs, _) = tlv(certificat)?;
    let mut champs = tbs;
    // Version facultative [0], puis numéro de série, algorithme, émetteur, validité, sujet.
    if champs.first() == Some(&0xa0) {
        champs = tlv(champs)?.2;
    }
    for _ in 0..4 {
        champs = tlv(champs)?.2;
    }
    let (_, nom, _) = tlv(champs)?;
    attribut(nom, 3)
        .or_else(|| attribut(nom, 10))
        .or_else(|| attribut(nom, 11))
}

/// Le base64 d'un certificat : un dernier bloc d'un seul caractère (texte tronqué) le rend illisible.
pub(crate) fn base64(texte: &str) -> Option<Vec<u8>> {
    let utiles = texte.bytes().filter(|c| !c.is_ascii_whitespace() && *c != b'=').count();
    if utiles % 4 == 1 {
        return None;
    }
    super::base64_decoder(texte)
}

/// Noms des certificats d'un fichier : un ou plusieurs blocs PEM, ou un certificat DER brut.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn noms_du_fichier(octets: &[u8]) -> Vec<String> {
    let texte = String::from_utf8_lossy(octets);
    if !texte.contains("-----BEGIN CERTIFICATE-----") {
        return sujet(octets).into_iter().collect();
    }
    texte
        .split("-----BEGIN CERTIFICATE-----")
        .skip(1)
        .filter_map(|bloc| bloc.split("-----END CERTIFICATE-----").next())
        .filter_map(base64)
        .filter_map(|der| sujet(&der))
        .collect()
}

/// Les noms des certificats d'un fichier d'ancres, et s'il est lu en entier : chaque bloc PEM (« -----BEGIN … »,
/// quel que soit son libellé) ou le fichier DER doit donner un nom. Un bloc « TRUSTED CERTIFICATE » d'OpenSSL, un
/// sujet sans CN, O ni OU, un fichier vide ou d'un autre format : le système peut lui faire confiance (p11-kit,
/// update-ca-trust) sans que Vanguard sache dire lequel ; jamais compté comme « rien d'ajouté ».
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn lire_ancre(octets: &[u8]) -> (Vec<String>, bool) {
    let noms = noms_du_fichier(octets);
    let blocs = String::from_utf8_lossy(octets).matches("-----BEGIN ").count().max(1);
    let entier = noms.len() >= blocs;
    (noms, entier)
}

/// Un fichier d'ancres qu'on n'a pas su lire en entier : à regarder, avec la commande qui le retire.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn ancre_non_nommee(ou: &str, retirer: &[String]) -> Constat {
    let ou = crate::ui::affichable(ou);
    let commandes: Vec<&str> = retirer.iter().map(String::as_str).collect();
    alerte(
        CAT,
        Niveau::Moyen,
        trf!(
            "Fichier ajouté aux certificats racine que Vanguard ne sait pas lire en entier ({ou}) : le système peut lui faire confiance quand même. Regardez ce qu'il contient ; retirez-le si vous ne l'avez pas installé.",
            "File added to the root certificates that Vanguard cannot fully read ({ou}): the system may trust it anyway. Check what it contains; remove it if you did not install it."
        ),
    )
    .manuel(
        trf!("Retirer le fichier {ou}", "Remove the file {ou}"),
        &commandes,
    )
}

/// Constat pour un certificat ajouté. `cle_privee` : sa clé privée est sur cette machine (Windows le sait). Le nom
/// (sujet du certificat, écrit par qui l'a fabriqué) et l'endroit sont montrés rendus inoffensifs ; `retirer` garde
/// le vrai nom.
fn juger(nom: &str, ou: &str, cle_privee: bool, retirer: &[String]) -> Constat {
    let sorte = famille(nom);
    let (nom, ou) = (crate::ui::affichable(nom), crate::ui::affichable(ou));
    let (niveau, message, retrait) = match sorte {
        Famille::Compromis => (
            Niveau::Critique,
            trf!(
                "Certificat racine « {nom} » ({ou}) : installé par un logiciel publicitaire, sa clé est publique et permet à n'importe qui de lire votre trafic HTTPS.",
                "Root certificate “{nom}” ({ou}): installed by adware, its key is public and lets anyone read your HTTPS traffic."
            ),
            true,
        ),
        Famille::Interception => (
            Niveau::Moyen,
            trf!(
                "Certificat racine « {nom} » ({ou}) : outil d'interception du trafic. À retirer si vous ne vous en servez plus.",
                "Root certificate “{nom}” ({ou}): traffic interception tool. Remove it if you no longer use it."
            ),
            true,
        ),
        // « localhost » est le nom que .NET et IIS Express donnent à leur certificat de développement ; mais ce nom
        // est écrit par qui fabrique le certificat, et la ligne lue ne dit pas si c'est une autorité (CA) capable de
        // signer d'autres sites : dit, jamais passé sous silence.
        _ if cle_privee && nom.eq_ignore_ascii_case("localhost") => (
            Niveau::Info,
            trf!(
                "Certificat racine « localhost » ({ou}) dont la clé privée est sur cet ordinateur : celui de .NET ou d'IIS Express si vous développez ; sinon, retirez-le, un nom ne prouve rien.",
                "Root certificate “localhost” ({ou}) whose private key is on this computer: .NET's or IIS Express's if you develop; otherwise remove it, a name proves nothing."
            ),
            false,
        ),
        _ if cle_privee => (
            Niveau::Eleve,
            trf!(
                "Certificat racine « {nom} » ({ou}) dont la clé privée est sur cet ordinateur : un programme peut fabriquer de faux certificats pour n'importe quel site.",
                "Root certificate “{nom}” ({ou}) whose private key is on this computer: a program can forge certificates for any site."
            ),
            true,
        ),
        Famille::Inspection => (
            Niveau::Info,
            trf!(
                "Certificat racine « {nom} » ({ou}) : un antivirus ou un filtre inspecte votre trafic HTTPS. Normal si vous l'avez installé.",
                "Root certificate “{nom}” ({ou}): an antivirus or filter inspects your HTTPS traffic. Normal if you installed it."
            ),
            false,
        ),
        Famille::Developpement => (
            Niveau::Info,
            trf!(
                "Certificat racine de développement « {nom} » ({ou}). Normal pour un développeur ; gardez sa clé privée pour vous.",
                "Development root certificate “{nom}” ({ou}). Normal for a developer; keep its private key to yourself."
            ),
            false,
        ),
        Famille::Autre => (
            Niveau::Info,
            trf!(
                "Certificat racine ajouté : « {nom} » ({ou}). Normal si vous l'avez installé (entreprise, école, VPN) ; sinon, retirez-le.",
                "Added root certificate: “{nom}” ({ou}). Normal if you installed it (work, school, VPN); otherwise remove it."
            ),
            false,
        ),
    };
    let constat = alerte(CAT, niveau, message);
    if retirer.is_empty() {
        return constat;
    }
    let action = trf!("Retirer le certificat « {nom} »", "Remove the “{nom}” certificate");
    if retrait {
        constat.corriger(action, retirer)
    } else {
        let commandes: Vec<&str> = retirer.iter().map(String::as_str).collect();
        constat.manuel(action, &commandes)
    }
}

/// Dossiers où chaque distribution range les autorités ajoutées par l'administrateur.
#[cfg(target_os = "linux")]
const DOSSIERS_AJOUTS: &[&str] = &[
    "/etc/ca-certificates/trust-source/anchors",
    "/usr/local/share/ca-certificates",
    "/etc/pki/ca-trust/source/anchors",
    "/etc/pki/trust/anchors",
];

#[cfg(target_os = "linux")]
fn fichiers(dossier: &std::path::Path, profondeur: u8, sortie: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dossier).into_iter().flatten().flatten() {
        let chemin = e.path();
        if chemin.is_dir() && profondeur > 0 {
            fichiers(&chemin, profondeur - 1, sortie);
        } else if chemin.is_file() {
            sortie.push(chemin);
        }
    }
}

#[cfg(target_os = "linux")]
pub fn certificats() -> Vec<Constat> {
    let mut trouves = Vec::new();
    for d in DOSSIERS_AJOUTS {
        fichiers(std::path::Path::new(d), 3, &mut trouves);
    }
    ancres(trouves)
}

/// Les constats des fichiers d'ancres trouvés. Un fichier illisible n'est pas vérifié, un fichier qu'on ne sait pas
/// nommer en entier est à regarder : « aucun certificat ajouté » seulement quand il n'y a aucun fichier.
#[cfg(any(target_os = "linux", test))]
fn ancres(trouves: Vec<std::path::PathBuf>) -> Vec<Constat> {
    let mut constats = Vec::new();
    for f in trouves {
        let chemin = f.display().to_string();
        let Ok(octets) = std::fs::read(&f) else {
            let ou = crate::ui::affichable(&chemin);
            constats.push(super::impossible(
                CAT,
                &trf!(
                    "fichier de certificats racine illisible : {ou}",
                    "unreadable root certificate file: {ou}"
                ),
            ));
            continue;
        };
        let retirer = vec![
            format!("sudo rm -f {}", crate::commande::sh_chaine(&chemin)),
            "if command -v update-ca-trust >/dev/null; then sudo update-ca-trust; else sudo update-ca-certificates --fresh; fi"
                .to_string(),
        ];
        let (noms, entier) = lire_ancre(&octets);
        for nom in noms {
            constats.push(juger(&nom, &chemin, false, &retirer));
        }
        if !entier {
            constats.push(ancre_non_nommee(&chemin, &retirer));
        }
    }
    if constats.is_empty() {
        constats.push(ok(
            CAT,
            tr!(
                "Aucun certificat racine ajouté aux certificats du système.",
                "No root certificate added to the system certificates."
            ),
        ));
    }
    constats
}

/// Noms des certificats auxquels une confiance particulière a été donnée (`security dump-trust-settings`) :
/// « Cert 0: Charles Proxy CA (12 Jan 2023, MacBook) ». Les racines d'Apple n'y figurent pas : elles ont leur
/// propre trousseau, que l'utilisateur ne modifie pas.
#[cfg(any(target_os = "macos", test))]
fn lire_reglages_confiance(sortie: &str) -> Vec<String> {
    sortie
        .lines()
        .filter_map(|l| l.trim().strip_prefix("Cert ")?.split_once(": ").map(|(_, nom)| nom))
        // La date et la machine d'ajout, entre parenthèses à la fin, ne font pas partie du nom.
        .map(|nom| {
            nom.rsplit_once(" (")
                .filter(|_| nom.ends_with(')'))
                .map_or(nom, |(n, _)| n)
        })
        .map(|nom| nom.trim().to_string())
        .collect()
}

/// macOS : certificats rendus « de confiance » par l'administrateur (trousseau Système) ou par l'utilisateur
/// (trousseau de session). C'est ce que font les outils d'interception et les logiciels publicitaires.
#[cfg(target_os = "macos")]
pub fn certificats() -> Vec<Constat> {
    let mut constats = Vec::new();
    for (admin, ou) in [
        (true, tr!("trousseau Système", "System keychain")),
        (false, tr!("trousseau de session", "login keychain")),
    ] {
        let args: &[&str] = if admin {
            &["dump-trust-settings", "-d"]
        } else {
            &["dump-trust-settings"]
        };
        // Sans réglage, la commande répond « No Trust Settings were found » avec un code d'erreur.
        let sortie = crate::commande::lancer(std::process::Command::new("security").args(args), 20)
            .map(|r| r.sortie)
            .unwrap_or_default();
        for nom in lire_reglages_confiance(&sortie) {
            let nom_cite = crate::commande::sh_chaine(&nom);
            let retirer = if admin {
                vec![format!(
                    "sudo security delete-certificate -c {nom_cite} /Library/Keychains/System.keychain"
                )]
            } else {
                vec![format!("security delete-certificate -c {nom_cite}")]
            };
            constats.push(juger(&nom, ou, false, &retirer));
        }
    }
    if constats.is_empty() {
        constats.push(ok(
            CAT,
            tr!(
                "Aucun certificat racine ajouté aux certificats du système.",
                "No root certificate added to the system certificates."
            ),
        ));
    }
    constats
}

/// Racines des magasins de la machine et de l'utilisateur : « CERT|magasin|clé privée|empreinte|sujet ».
/// Le magasin de l'utilisateur montre aussi ceux de la machine : un certificat présent dans les deux est de la
/// machine. Windows met à jour lui-même ses racines : seules les marques d'un ajout sont examinées.
#[cfg(windows)]
pub fn certificats() -> Vec<Constat> {
    // Lus par crypt32 ; PowerShell seulement si le magasin de l'ordinateur ne s'ouvre pas.
    let Some(sortie) = super::windows::magasins::racines().or_else(|| {
        super::windows::ps(
        // Module du lecteur Cert: chargé d'office (voir windows::powershell pour la cause de la panne vue en VM).
        "Import-Module Microsoft.PowerShell.Security -ErrorAction SilentlyContinue; \
         foreach ($m in 'LocalMachine', 'CurrentUser') { Get-ChildItem \"Cert:\\$m\\Root\" | ForEach-Object { $c = $_; \
         $nom = try { $c.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) } catch { $c.Subject }; \
         \"CERT|$m|$($c.HasPrivateKey)|$($c.Thumbprint)|$nom\" } }",
        )
    }) else {
        return vec![super::windows::illisible(CAT)];
    };
    let mut vus = std::collections::HashSet::new();
    let mut total = 0;
    let mut constats = Vec::new();
    for l in sortie.lines() {
        let c: Vec<&str> = l.trim().splitn(5, '|').collect();
        let ["CERT", magasin, cle, empreinte, nom] = c[..] else {
            continue;
        };
        if !vus.insert(empreinte.to_string()) {
            continue;
        }
        total += 1;
        let cle_privee = cle.eq_ignore_ascii_case("true");
        if famille(nom) == Famille::Autre && !cle_privee {
            continue;
        }
        let ou = if magasin == "LocalMachine" {
            tr!("magasin de l'ordinateur", "computer store")
        } else {
            tr!("magasin de l'utilisateur", "user store")
        };
        let retirer = vec![format!("Remove-Item -Path 'Cert:\\{magasin}\\Root\\{empreinte}'")];
        constats.push(juger(nom, ou, cle_privee, &retirer));
    }
    if constats.is_empty() {
        constats.push(ok(
            CAT,
            trf!(
                "{total} certificats racine, aucun ajouté par un outil d'interception ou un logiciel connu pour en abuser.",
                "{total} root certificates, none added by an interception tool or software known to abuse them."
            ),
        ));
    }
    constats
}

/// COM-CRT-001 au corpus de détection : une ligne par sujet de certificat racine ajouté.
#[cfg(test)]
pub(super) fn corpus(e: &crate::modele::corpus::Entree) -> Vec<Constat> {
    e.lignes()
        .into_iter()
        .map(|nom| juger(nom, "corpus", false, &[]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reglages_de_confiance_macos() {
        let sortie = "Number of trusted certs = 2\nCert 0: Charles Proxy CA (12 Jan 2023, MacBook)\n   Number of trust settings : 0\nCert 1: mitmproxy\n";
        assert_eq!(lire_reglages_confiance(sortie), ["Charles Proxy CA", "mitmproxy"]);
        assert_eq!(
            lire_reglages_confiance("SecTrustSettingsCopyCertificates: No Trust Settings were found."),
            Vec::<String>::new()
        );
    }

    /// Certificat autosigné « CN=Vanguard Test CA, O=Vanguard » (openssl req -x509, clé EC P-256).
    const PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBsTCCAVegAwIBAgIUNk+0eAFwLwngOVYPiSUQLdrH6QAwCgYIKoZIzj0EAwIw
LjEZMBcGA1UEAwwQVmFuZ3VhcmQgVGVzdCBDQTERMA8GA1UECgwIVmFuZ3VhcmQw
HhcNMjYxMDE5MTUzMjQ5WhcNMzYxMDE2MTUzMjQ5WjAuMRkwFwYDVQQDDBBWYW5n
dWFyZCBUZXN0IENBMREwDwYDVQQKDAhWYW5ndWFyZDBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABO6li7wNBvG58cVvUAO8x8MbwLw6+sJSlHQQEF3QihB7tNaTrLHI
1Kjunu34Azac9PL2Vl0qSCQxM6BKoZOLuvajUzBRMB0GA1UdDgQWBBQLNRnjyYUO
MUE4FCSskJprIu4RAzAfBgNVHSMEGDAWgBQLNRnjyYUOMUE4FCSskJprIu4RAzAP
BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIAw1C4ASo9mBvyoQbkIv
zFjhVZCJTZyJMc8UUk87nyaCAiEAwoEfebCe1+tJZhE4ypL4i0uaG6GD06Nd39my
xo1zjuQ=
-----END CERTIFICATE-----
";

    #[test]
    fn familles_de_certificats() {
        assert_eq!(famille("Superfish, Inc."), Famille::Compromis);
        assert_eq!(famille("mitmproxy"), Famille::Interception);
        assert_eq!(famille("Avast Web/Mail Shield Root"), Famille::Inspection);
        assert_eq!(famille("mkcert alice@portable"), Famille::Developpement);
        assert_eq!(famille("Mon entreprise CA"), Famille::Autre);
    }

    #[test]
    fn sujet_d_un_certificat() {
        let noms = noms_du_fichier(PEM.as_bytes());
        assert_eq!(noms, ["Vanguard Test CA"]);
        // Le même certificat en DER brut (.der, .cer).
        let corps: String = PEM.lines().filter(|l| !l.starts_with("-----")).collect();
        assert_eq!(noms_du_fichier(&base64(&corps).unwrap()), ["Vanguard Test CA"]);
        // Fichier qui n'est pas un certificat : rien, sans planter.
        let rien: Vec<String> = Vec::new();
        assert_eq!(noms_du_fichier(b"pas un certificat"), rien);
        assert_eq!(
            noms_du_fichier(b"-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n"),
            rien
        );
    }

    /// Le sujet d'un certificat est écrit par qui l'a fabriqué : celui qui installe une fausse autorité peut y mettre
    /// de quoi effacer l'alerte. Montré inoffensif ; la commande qui le retire garde le vrai nom (macOS le cherche par
    /// son nom).
    #[test]
    fn sujet_piege() {
        let piege = "Faux CA\x1b]52;c;eA==\x07\x1b[2K\r\u{202e}";
        let retirer = vec![format!("security delete-certificate -c '{piege}'")];
        for cle_privee in [false, true] {
            let c = juger(piege, "/etc/x\x1b[8m.pem", cle_privee, &retirer);
            assert!(!crate::ui::contient_un_piege(&c.message), "{}", c.message);
            let k = c.correctif.as_ref().unwrap();
            assert!(!crate::ui::contient_un_piege(&k.action), "{}", k.action);
            assert_eq!(k.commandes, retirer);
        }
        assert_eq!(lire_reglages_confiance(&format!("Cert 0: {piege}\n")), [piege]);
    }

    #[test]
    fn jugement() {
        let retirer = vec!["sudo rm -f '/x'".to_string()];
        let c = juger("Superfish, Inc.", "/x", false, &retirer);
        assert_eq!(c.probleme, Some(Niveau::Critique));
        assert!(c.correctif.as_ref().is_some_and(|k| k.automatique));
        let c = juger("Mon entreprise CA", "/x", false, &retirer);
        assert_eq!(c.probleme, Some(Niveau::Info));
        assert!(c.correctif.as_ref().is_some_and(|k| !k.automatique));
        assert_eq!(
            juger("Mon entreprise CA", "/x", true, &retirer).probleme,
            Some(Niveau::Eleve)
        );
    }

    /// Campagne d'attaque n° 6, M1 : un fichier d'ancres que le lecteur ne sait pas nommer (vide, octets quelconques,
    /// bloc « TRUSTED CERTIFICATE », sujet sans CN, O ni OU) ou illisible ne donne jamais « aucun certificat ajouté » ;
    /// chacun a son constat, qui le nomme.
    #[test]
    fn ancre_illisible_ou_sans_nom_n_est_jamais_verte() {
        let d = std::env::temp_dir().join(format!("vanguard-ancres-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let corps: String = PEM.lines().filter(|l| !l.starts_with("-----")).collect();
        let trusted = format!("-----BEGIN TRUSTED CERTIFICATE-----\n{corps}\n-----END TRUSTED CERTIFICATE-----\n");
        // Un DER dont le sujet n'a qu'une adresse (1.2.840.113549.1.9.1) : SEQUENCE { [0] v3, série, algorithme,
        // émetteur, validité, sujet }.
        let adresse = [
            0x30, 0x13, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16,
            0x02, b'a', b'@',
        ];
        let mut tbs = vec![
            0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00,
        ];
        tbs.extend_from_slice(&adresse);
        let mut tbs_tlv = vec![0x30, u8::try_from(tbs.len()).unwrap()];
        tbs_tlv.extend_from_slice(&tbs);
        let mut der = vec![0x30, u8::try_from(tbs_tlv.len()).unwrap()];
        der.extend_from_slice(&tbs_tlv);
        assert_eq!(sujet(&der), None, "le sujet d'essai ne doit avoir ni CN, ni O, ni OU");
        let cas: [(&str, Vec<u8>); 5] = [
            ("vide.crt", Vec::new()),
            ("octets.crt", (0..64u8).collect()),
            ("trusted.pem", trusted.into_bytes()),
            ("adresse.der", der),
            // Un certificat nommé, puis un bloc d'un autre libellé dans le même fichier.
            (
                "deux.pem",
                format!("{PEM}-----BEGIN TRUSTED CERTIFICATE-----\n{corps}\n-----END TRUSTED CERTIFICATE-----\n")
                    .into_bytes(),
            ),
        ];
        for (nom, octets) in &cas {
            let f = d.join(nom);
            std::fs::write(&f, octets).unwrap();
            let constats = ancres(vec![f]);
            let messages: Vec<&str> = constats.iter().map(|c| c.message.as_str()).collect();
            assert!(
                !constats.is_empty() && constats.iter().all(|c| c.probleme.is_some()),
                "{nom} : {messages:?}"
            );
            assert!(
                constats
                    .iter()
                    .any(|c| c.probleme == Some(Niveau::Moyen) && c.message.contains(nom)),
                "{nom} : {messages:?}"
            );
        }
        // Un fichier qu'on ne peut pas lire (ici, un chemin disparu) : non vérifié, jamais vert.
        let constats = ancres(vec![d.join("disparu.crt")]);
        assert!(!constats.is_empty() && constats.iter().all(|c| !c.verifie && c.message.contains("disparu.crt")));
        // Le certificat nommé seul reste ce qu'il était : un constat, sans fichier « à regarder ».
        let f = d.join("nomme.pem");
        std::fs::write(&f, PEM).unwrap();
        let constats = ancres(vec![f]);
        assert_eq!(constats.len(), 1);
        assert!(constats[0].message.contains("Vanguard Test CA"));
        // Aucun fichier : vert.
        assert!(ancres(Vec::new()).iter().all(|c| c.probleme.is_none()));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une racine nommée « localhost » avec sa clé privée n'est plus passée sous silence : le nom est choisi par qui
    /// fabrique le certificat, et une fausse autorité peut le porter. Dite en information, avec le pourquoi.
    #[test]
    fn localhost_avec_cle_privee_est_dit() {
        let retirer = vec!["Remove-Item -Path 'Cert:\\CurrentUser\\Root\\0A1B'".to_string()];
        let c = juger("localhost", "magasin de l'utilisateur", true, &retirer);
        assert_eq!(c.probleme, Some(Niveau::Info));
        assert!(c.message.contains("localhost") && c.message.contains("clé privée"));
        assert!(
            c.correctif
                .as_ref()
                .is_some_and(|k| !k.automatique && k.commandes == retirer)
        );
        // Sans clé privée, c'est un certificat ajouté comme un autre.
        assert_eq!(juger("LOCALHOST", "/x", false, &retirer).probleme, Some(Niveau::Info));
    }
}

//! Les pilotes du noyau : ce qui tourne au plus profond de Windows, avec tous les droits. Deux signes, en lecture
//! seule. Un pilote rangé dans un dossier du compte, temporaire ou de données, où rien d'installé normalement n'en
//! pose. Un pilote connu pour être vulnérable ou malveillant (liste LOLDrivers, Apache-2.0) : signé, il se charge
//! sans alerte, puis sert à un attaquant qui a les droits d'administrateur pour désarmer l'antivirus (« Bring Your Own
//! Vulnerable Driver »). La liste se télécharge une fois par semaine ; sans elle, c'est dit, jamais compté comme sain.
//! Les pilotes se lisent dans le registre des services (type pilote du noyau ou du système de fichiers, pas
//! désactivés), sans PowerShell ni droits d'administrateur. Rien ne se corrige tout seul : retirer un pilote peut
//! empêcher Windows de démarrer.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;

use super::*;
use crate::machine::regles::{Os, regle};
use crate::ui::{affichable, couper};

const CAT: &str = "Persistance";
use super::CLE_SERVICES as SERVICES;
const LOLDRIVERS: &str = "https://www.loldrivers.io/api/drivers.csv";
/// La liste fait environ 1,2 Mo en octobre 2026 : au-delà de 32 Mo, ce n'est pas elle.
const LISTE_MAX: u64 = 32 << 20;
const SEMAINE: Duration = Duration::from_hours(7 * 24);

regle!(
    "WIN-PRS-012",
    Os::Windows,
    229,
    (
        "pilotes du noyau (emplacement, pilotes vulnérables connus)",
        "kernel drivers (location, known vulnerable drivers)"
    ),
    &[
        "CIS Controls v8 2.5",
        "Microsoft : Microsoft recommended driver block rules",
        "MITRE ATT&CK T1543.003",
        "MITRE ATT&CK T1068",
        "LOLDrivers"
    ],
    pilotes
);

/// Un pilote déclaré : son nom de service et son fichier.
struct Pilote {
    nom: String,
    fichier: PathBuf,
}

/// Le fichier d'un pilote à partir de son ImagePath (« \SystemRoot\… », « System32\… », « \??\C:\… », un chemin
/// complet) ; sans ImagePath, Windows prend System32\drivers\<nom>.sys.
fn fichier_du_pilote(nom: &str, image: Option<&str>, racine: &str) -> PathBuf {
    let Some(image) = image.map(|i| i.trim().trim_matches('"')).filter(|i| !i.is_empty()) else {
        return Path::new(racine)
            .join("System32")
            .join("drivers")
            .join(format!("{nom}.sys"));
    };
    // Préfixes comparés en ASCII : to_lowercase change la longueur de certains caractères (K Kelvin, İ), et un
    // découpage fait d'après la chaîne en minuscules tombait au mauvais endroit, ou au milieu d'un caractère.
    if image
        .get(..12)
        .is_some_and(|p| p.eq_ignore_ascii_case("\\systemroot\\"))
    {
        return Path::new(racine).join(&image[12..]);
    }
    if let Some(reste) = image.strip_prefix("\\??\\") {
        return PathBuf::from(reste);
    }
    if image
        .get(..9)
        .is_some_and(|p| p.eq_ignore_ascii_case("system32\\") || p.eq_ignore_ascii_case("syswow64\\"))
    {
        return Path::new(racine).join(image);
    }
    PathBuf::from(image)
}

/// Les dossiers de ProgramData que seul le système peut modifier.
const PROTEGES: [&str; 2] = [
    "\\programdata\\microsoft\\windows defender\\",
    "\\programdata\\microsoft\\windows defender advanced threat protection\\",
];

/// Pourquoi l'emplacement d'un pilote est suspect, ou `None` : le dossier de Windows (dont DriverStore) et les dossiers
/// de programmes sont normaux.
fn emplacement_suspect(fichier: &Path) -> Option<&'static str> {
    let f = fichier.to_string_lossy().to_lowercase().replace('/', "\\");
    // Defender range son pilote d'analyse (MpKslDrv) dans ses mises à jour de définitions, sous ProgramData : un dossier
    // que seul le système peut modifier, contrairement au reste de ProgramData.
    if PROTEGES.iter().any(|p| f.contains(p)) {
        return None;
    }
    if f.contains("\\temp\\") || f.contains("\\users\\public\\") || f.contains("\\$recycle.bin\\") {
        return Some(tr!("dossier temporaire ou public", "temporary or public folder"));
    }
    if f.contains("\\appdata\\")
        || f.contains("\\users\\")
        || f.contains("\\programdata\\")
        || f.contains("\\downloads\\")
    {
        return Some(tr!("dossier du compte ou de données", "account or data folder"));
    }
    None
}

/// Les empreintes SHA-256 de la liste LOLDrivers (CSV) : toute suite de 64 chiffres hexadécimaux. Elle contient aussi
/// des empreintes Authenticode, qui ne correspondent à aucun fichier entier : les garder ne peut rien fausser.
fn empreintes_de_la_liste(texte: &str) -> HashSet<[u8; 32]> {
    texte
        .split(|c: char| !c.is_ascii_hexdigit())
        .filter(|m| m.len() == 64)
        .filter_map(|m| {
            let mut e = [0u8; 32];
            for (i, o) in e.iter_mut().enumerate() {
                *o = u8::from_str_radix(m.get(2 * i..2 * i + 2)?, 16).ok()?;
            }
            Some(e)
        })
        .collect()
}

/// Ce que donne le fichier d'un pilote.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fichier {
    /// Déclaré mais pas installé, cas courant : il n'est pas compté.
    Absent,
    /// Présent mais fermé à la lecture (droits, partage) : son emplacement compte toujours, car un attaquant qui pose
    /// un pilote peut aussi en refuser la lecture.
    Illisible,
    Lu([u8; 32]),
}

impl Fichier {
    fn empreinte(self) -> Option<[u8; 32]> {
        match self {
            Fichier::Lu(e) => Some(e),
            _ => None,
        }
    }
}

/// Lit le fichier d'un pilote. Seuls « fichier introuvable » et « chemin introuvable » (code 3 de Windows) disent
/// qu'il est absent ; toute autre erreur le dit illisible.
fn lire_fichier(fichier: &Path) -> Fichier {
    if let Some(e) = crate::protection::empreintes::sha256(fichier) {
        return Fichier::Lu(e);
    }
    match std::fs::metadata(fichier) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound || e.raw_os_error() == Some(3) => Fichier::Absent,
        _ => Fichier::Illisible,
    }
}

/// `liste` : les empreintes connues, `None` si la liste manque.
fn juger_pilotes(pilotes: &[(Pilote, Fichier)], liste: Option<&HashSet<[u8; 32]>>) -> Vec<Constat> {
    let mut constats = Vec::new();
    let suspects: Vec<String> = pilotes
        .iter()
        .filter(|(_, f)| *f != Fichier::Absent)
        .filter_map(|(p, _)| {
            emplacement_suspect(&p.fichier).map(|r| format!("{} : {} ({r})", p.nom, p.fichier.display()))
        })
        .collect();
    let lus = pilotes.iter().filter(|(_, f)| *f != Fichier::Absent).count();
    let illisibles = pilotes.iter().filter(|(_, f)| *f == Fichier::Illisible).count();
    if suspects.is_empty() {
        constats.push(ok(
            CAT,
            trf!(
                "Pilotes du noyau : {lus} fichier(s), aucun dans un dossier du compte ou temporaire",
                "Kernel drivers: {lus} file(s), none in an account or temporary folder"
            ),
        ));
    } else {
        let liste = couper(&affichable(&suspects.join(" ; ")), 240);
        constats.push(alerte(
            CAT,
            Niveau::Eleve,
            trf!(
                "Un pilote du noyau est rangé là où rien d'installé normalement n'en pose : {liste}. Un pilote a tous les droits sur l'ordinateur ; c'est la cachette d'un rootkit.",
                "A kernel driver is stored where nothing normally installed puts one: {liste}. A driver has full rights over the computer; it is a rootkit's hiding place."
            ),
        ));
    }
    let Some(liste) = liste else {
        // Typée : un Windows tout juste installé, sans Internet ou hors ligne, n'a pas encore de copie de la liste ;
        // l'autotest compte sinon ce constat parmi les « non vérifiés sans raison ».
        constats.push(crate::machine::impossible_par(
            CAT,
            crate::modele::Raison::Introuvable,
            tr!(
                "Impossible de vérifier (pilotes vulnérables connus : liste LOLDrivers indisponible, sans Internet ?).",
                "Could not check (known vulnerable drivers: LOLDrivers list unavailable, no Internet?)."
            ),
        ));
        return constats;
    };
    let vulnerables: Vec<String> = pilotes
        .iter()
        .filter(|(_, f)| f.empreinte().is_some_and(|e| liste.contains(&e)))
        .map(|(p, _)| format!("{} ({})", p.nom, p.fichier.display()))
        .collect();
    if vulnerables.is_empty() {
        let n = liste.len();
        let lus = lus - illisibles;
        constats.push(ok(
            CAT,
            trf!(
                "Pilotes vulnérables connus : aucun parmi {lus} (liste LOLDrivers, {n} empreintes)",
                "Known vulnerable drivers: none among {lus} (LOLDrivers list, {n} fingerprints)",
            ),
        ));
        if illisibles > 0 {
            let quoi = trf!(
                "pilotes vulnérables connus : {illisibles} fichier(s) de pilote illisible(s), comparés à aucune liste",
                "known vulnerable drivers: {illisibles} unreadable driver file(s), compared with no list"
            );
            constats.push(crate::machine::impossible_par(
                CAT,
                crate::modele::Raison::Illisible(quoi.clone()),
                trf!("Impossible de vérifier ({quoi}).", "Could not check ({quoi})."),
            ));
        }
    } else {
        let noms = couper(&affichable(&vulnerables.join(", ")), 240);
        constats.push(alerte(
            CAT,
            Niveau::Eleve,
            trf!(
                "Pilote connu pour être vulnérable ou malveillant (LOLDrivers) : {noms}. Signé, il se charge sans alerte ; un attaquant qui a les droits d'administrateur s'en sert pour désarmer l'antivirus. Mettez à jour ou désinstallez le logiciel qui l'a posé, et activez l'intégrité de la mémoire (elle bloque ces pilotes).",
                "Driver known to be vulnerable or malicious (LOLDrivers): {noms}. Being signed, it loads without warning; an attacker with administrator rights uses it to disarm the antivirus. Update or uninstall the software that put it there, and turn on memory integrity (it blocks these drivers)."
            ),
        ));
    }
    constats
}

/// Les pilotes déclarés dans le registre des services : type 1 (noyau) ou 2 (système de fichiers), pas désactivés.
fn lire_pilotes() -> Option<Vec<Pilote>> {
    let services = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(SERVICES).ok()?;
    let racine = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    Some(
        services
            .enum_keys()
            .flatten()
            .filter_map(|nom| {
                let k = services.open_subkey(&nom).ok()?;
                let genre = k.get_value::<u32, _>("Type").ok()?;
                if !matches!(genre, 1 | 2) || k.get_value::<u32, _>("Start").ok() == Some(4) {
                    return None;
                }
                let image = k.get_value::<String, _>("ImagePath").ok();
                let fichier = fichier_du_pilote(&nom, image.as_deref(), &racine);
                Some(Pilote { nom, fichier })
            })
            .collect(),
    )
}

/// La liste LOLDrivers, rafraîchie une fois par semaine ; la copie d'avant sert hors ligne. Seule une réponse qui
/// contient des empreintes la remplace : une page de maintenance ou d'erreur reçue avec un 200 effaçait la bonne
/// copie, et la semaine d'attente laissait la vérification des pilotes vulnérables tomber sept jours.
fn liste_loldrivers() -> Option<HashSet<[u8; 32]>> {
    let lieu = ("loldrivers", "drivers.csv");
    let octets = if cfg!(test) || crate::parametres::hors_ligne() {
        crate::socle::lire_ordinaire(&crate::socle::dossier_local().join(lieu.0).join(lieu.1), LISTE_MAX).ok()
    } else {
        let demande = crate::http::Demande {
            taille_max: LISTE_MAX,
            ..crate::http::Demande::get(LOLDRIVERS, Duration::from_secs(120))
        };
        crate::socle::cache::liste(demande, lieu, SEMAINE, liste_valide)
            .copie
            .map(|(o, _)| o)
    };
    let liste = empreintes_de_la_liste(&String::from_utf8_lossy(&octets?));
    (!liste.is_empty()).then_some(liste)
}

/// Une réponse qui est bien la liste : au moins une empreinte SHA-256.
fn liste_valide(octets: &[u8]) -> bool {
    !empreintes_de_la_liste(&String::from_utf8_lossy(octets)).is_empty()
}

fn pilotes() -> Vec<Constat> {
    let Some(pilotes) = lire_pilotes() else {
        return vec![registre_illisible(CAT)];
    };
    let avec: Vec<(Pilote, Fichier)> = pilotes
        .into_iter()
        .map(|p| {
            let f = lire_fichier(&p.fichier);
            (p, f)
        })
        .collect();
    juger_pilotes(&avec, liste_loldrivers().as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Les canaris de la veille de nuit (compilés sous Linux, où ce module n'existe pas) recopient la demande et la
    /// validation de la liste LOLDrivers : elles doivent rester celles du programme.
    #[test]
    fn canaris_de_la_veille_a_l_identique() {
        assert_eq!(
            (LOLDRIVERS, LISTE_MAX),
            (crate::canaris::LOLDRIVERS, crate::canaris::LOLDRIVERS_MAX)
        );
        let empreinte = "ab".repeat(32);
        for essai in [
            format!("\"Id\",\"KnownVulnerableSamples_SHA256\"\n\"x\",\"{empreinte}\"\n"),
            "<html>maintenance</html>".to_string(),
            format!("{empreinte}0"),
            String::new(),
        ] {
            assert_eq!(
                liste_valide(essai.as_bytes()),
                crate::canaris::loldrivers_lisible(essai.as_bytes()),
                "{essai}"
            );
        }
    }

    /// Une page de maintenance ou d'erreur reçue avec un 200 ne remplace pas la copie de la liste.
    #[test]
    fn page_qui_n_est_pas_la_liste_refusee() {
        let ligne = format!("\"id\",\"{}\"\n", "ab".repeat(32));
        assert!(liste_valide(
            format!("\"Id\",\"KnownVulnerableSamples_SHA256\"\n{ligne}").as_bytes()
        ));
        assert!(!liste_valide(b"<html><body>Maintenance en cours</body></html>"));
        assert!(!liste_valide(b""));
    }

    fn p(nom: &str, fichier: &str) -> Pilote {
        Pilote {
            nom: nom.into(),
            fichier: fichier.into(),
        }
    }

    /// Le vrai registre des services (celui de Wine pendant les tests) déclare des pilotes, et leurs fichiers se lisent.
    #[test]
    fn lecture_du_vrai_registre() {
        let pilotes = lire_pilotes().unwrap();
        assert!(!pilotes.is_empty());
        let lus = pilotes
            .iter()
            .filter(|p| crate::protection::empreintes::sha256(&p.fichier).is_some())
            .count();
        println!("{} pilotes déclarés, {lus} fichiers lus", pilotes.len());
    }

    /// Un fichier absent, ou dans un dossier absent (code 3 de Windows), est dit absent ; un fichier lu donne son
    /// empreinte. Un dossier se lit comme un fichier refusé : présent, donc jamais pris pour absent.
    #[test]
    fn absent_ou_illisible() {
        let d = std::env::temp_dir().join(format!("vanguard-pilotes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        assert_eq!(lire_fichier(&d.join("absent.sys")), Fichier::Absent);
        assert_eq!(lire_fichier(&d.join("dossier-absent").join("x.sys")), Fichier::Absent);
        std::fs::write(d.join("x.sys"), b"MZ").unwrap();
        assert!(matches!(lire_fichier(&d.join("x.sys")), Fichier::Lu(_)));
        assert_eq!(lire_fichier(&d), Fichier::Illisible);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn le_fichier_d_un_pilote() {
        let r = r"C:\Windows";
        let f = |n, i| fichier_du_pilote(n, i, r).to_string_lossy().replace('/', "\\");
        assert_eq!(f("disque", None), r"C:\Windows\System32\drivers\disque.sys");
        assert_eq!(
            f("a", Some(r"\SystemRoot\System32\drivers\a.sys")),
            r"C:\Windows\System32\drivers\a.sys"
        );
        assert_eq!(
            f("a", Some(r"\SYSTEMROOT\System32\drivers\A.sys")),
            r"C:\Windows\System32\drivers\A.sys"
        );
        assert_eq!(
            f("b", Some(r"System32\DriverStore\b.sys")),
            r"C:\Windows\System32\DriverStore\b.sys"
        );
        assert_eq!(
            f("c", Some(r"\??\C:\Program Files\Outil\c.sys")),
            r"C:\Program Files\Outil\c.sys"
        );
        assert_eq!(
            f("d", Some(r#""C:\Users\alice\AppData\Local\d.sys""#)),
            r"C:\Users\alice\AppData\Local\d.sys"
        );
    }

    #[test]
    fn l_emplacement_d_un_pilote() {
        assert!(emplacement_suspect(Path::new(r"C:\Windows\System32\drivers\a.sys")).is_none());
        assert!(emplacement_suspect(Path::new(r"C:\Program Files\Outil\c.sys")).is_none());
        assert!(emplacement_suspect(Path::new(r"C:\Users\alice\AppData\Local\d.sys")).is_some());
        assert!(emplacement_suspect(Path::new(r"C:\Windows\Temp\e.sys")).is_some());
        assert!(emplacement_suspect(Path::new(r"C:\ProgramData\x\f.sys")).is_some());
        let defender = r"C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{0A1B}\MpKslDrv.sys";
        assert!(emplacement_suspect(Path::new(defender)).is_none());
        // Un faux dossier « Windows Defender » ailleurs ne passe pas.
        assert!(emplacement_suspect(Path::new(r"C:\Users\alice\Windows Defender\x.sys")).is_some());
    }

    #[test]
    fn la_liste_et_le_jugement() {
        let vulnerable = "ab".repeat(32);
        let csv = format!(
            "\"Id\",\"KnownVulnerableSamples_SHA256\"\n\"1\",\"{vulnerable}, {}\"\n",
            "0".repeat(63)
        );
        let liste = empreintes_de_la_liste(&csv);
        assert_eq!(liste.len(), 1);
        let e = [0xab; 32];
        let sains = [(
            p("disque", r"C:\Windows\System32\drivers\disque.sys"),
            Fichier::Lu([1; 32]),
        )];
        let c = juger_pilotes(&sains, Some(&liste));
        assert!(c.iter().all(|c| c.probleme.is_none() && c.verifie));
        let vieux = [
            (
                p("disque", r"C:\Windows\System32\drivers\disque.sys"),
                Fichier::Lu([1; 32]),
            ),
            (p("vieuxoutil", r"C:\Program Files\Vieux\outil.sys"), Fichier::Lu(e)),
            (p("absent", r"C:\Windows\System32\drivers\absent.sys"), Fichier::Absent),
        ];
        let c = juger_pilotes(&vieux, Some(&liste));
        assert!(c[1].probleme == Some(Niveau::Eleve) && c[1].message.contains("vieuxoutil"));
        let cache = [(
            p("cache", r"C:\Users\alice\AppData\Local\Temp\x.sys"),
            Fichier::Lu([2; 32]),
        )];
        assert_eq!(juger_pilotes(&cache, Some(&liste))[0].probleme, Some(Niveau::Eleve));
        // Présent mais illisible (droits refusés par l'attaquant ou par le profil d'un autre compte) : toujours jugé
        // sur son emplacement, et dit non comparé à la liste.
        for f in [r"C:\Users\bob\AppData\Local\x.sys", r"C:\Windows\Temp\x.sys"] {
            let c = juger_pilotes(&[(p("cache", f), Fichier::Illisible)], Some(&liste));
            assert_eq!(c[0].probleme, Some(Niveau::Eleve), "{f}");
            assert!(c.iter().any(|c| !c.verifie), "{f}");
            // Avec sa raison : l'autotest compte les « non vérifiés » sans raison typée.
            assert!(
                c.iter().all(|c| !matches!(
                    c.etat(),
                    crate::modele::Etat::NonVerifie(crate::modele::Raison::NonPrecisee)
                )),
                "{f}"
            );
        }
        // Absent (déclaré, pas installé) : ni compté ni signalé.
        let c = juger_pilotes(
            &[(p("absent", r"C:\Windows\Temp\x.sys"), Fichier::Absent)],
            Some(&liste),
        );
        assert!(c.iter().all(|c| c.probleme.is_none() && c.verifie));
        // Sans la liste : dit non vérifié, jamais sain.
        let c = juger_pilotes(&sains, None);
        assert!(!c[1].verifie);
        // Hors ligne sur un Windows tout juste installé (aucune copie de la liste) : non vérifié avec sa raison.
        assert_eq!(
            c[1].etat(),
            crate::modele::Etat::NonVerifie(crate::modele::Raison::Introuvable)
        );
    }
}

/// La liste LOLDrivers vient d'Internet, et l'ImagePath d'un pilote de qui l'a installé : jamais de panique, et une
/// empreinte gardée est bien écrite dans la liste.
#[cfg(test)]
mod entrees_hostiles {
    use super::*;
    use proptest::prelude::*;

    fn hexa(e: &[u8; 32], majuscules: bool) -> String {
        e.iter()
            .map(|o| {
                if majuscules {
                    format!("{o:02X}")
                } else {
                    format!("{o:02x}")
                }
            })
            .collect()
    }

    /// Une liste CSV : des empreintes (minuscules, majuscules), des suites hexadécimales trop courtes ou trop longues,
    /// des séparateurs, des chiffres qui n'en sont pas en ASCII (pleine chasse, arabes), du texte quelconque.
    fn liste() -> impl Strategy<Value = String> {
        let bout = prop_oneof![
            (any::<[u8; 32]>(), any::<bool>()).prop_map(|(e, m)| hexa(&e, m)),
            "[0-9a-fA-F]{60,70}",
            prop::sample::select(vec![
                ",", "\"", "\n", ";", " ", "é", "😀", "\u{ff21}", "\u{0663}", "\u{212a}"
            ])
            .prop_map(str::to_string),
            any::<String>(),
        ];
        prop::collection::vec(bout, 0..30).prop_map(|b| b.concat())
    }

    /// Un ImagePath : les préfixes que Windows lit, avec une casse ou des caractères qui changent de longueur en
    /// minuscules, puis un chemin quelconque.
    fn image() -> impl Strategy<Value = String> {
        let prefixe = prop::sample::select(vec![
            "\\SystemRoot\\",
            "\\systemroot\\",
            "\\SYSTEMROOT",
            "System32\\",
            "SysWOW64\\",
            "\\??\\",
            "\"",
            "İ",
            "\u{212a}",
            "",
        ]);
        (prefixe, any::<String>()).prop_map(|(p, c)| format!("{p}{c}"))
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn liste_de_loldrivers(t in liste()) {
            let bas = t.to_ascii_lowercase();
            let empreintes = empreintes_de_la_liste(&t);
            prop_assert!(empreintes.len() <= t.len() / 64);
            for e in &empreintes {
                prop_assert!(bas.contains(&hexa(e, false)));
            }
        }

        /// Chaque empreinte d'une liste bien formée est lue.
        #[test]
        fn empreintes_lues(liste in prop::collection::vec(any::<[u8; 32]>(), 0..20), majuscules: bool) {
            let texte = liste.iter().map(|e| format!("\"{}\",x", hexa(e, majuscules))).collect::<Vec<_>>().join("\n");
            prop_assert_eq!(empreintes_de_la_liste(&texte), liste.into_iter().collect::<HashSet<_>>());
        }

        #[test]
        fn chemins_de_pilote(nom in any::<String>(), image in prop::option::of(image()), racine in prop_oneof![Just("C:\\Windows".to_string()), any::<String>()]) {
            let fichier = fichier_du_pilote(&nom, image.as_deref(), &racine);
            let _ = emplacement_suspect(&fichier);
        }
    }
}

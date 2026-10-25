//! Points d'ancrage profonds de Windows : des endroits du registre où une DLL se fait charger par Windows lui-même,
//! souvent avec les droits du système, sans apparaître parmi les programmes lancés au démarrage (persistance.rs) ni
//! les portes dérobées classiques (portes.rs). Les paquets de LSA, le gardien des mots de passe (un filtre de mot de
//! passe y reçoit chaque nouveau mot de passe en clair) ; AppCertDlls, chargée dans chaque programme qui en lance un
//! autre ; les moniteurs d'impression, chargés par le spouleur ; les fournisseurs de temps, chargés par le service de
//! l'heure ; le catalogue Winsock, chargé dans chaque programme qui utilise le réseau. Tout se lit dans le registre,
//! sans PowerShell ni droits d'administrateur. Rien ne se corrige tout seul : retirer une DLL de LSA ou du catalogue
//! Winsock sans enquête peut empêcher Windows de démarrer ou de se connecter.

use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;

use super::persistance::lancement_suspect;
use super::*;
use crate::machine::regles::{Os, regle};
use crate::ui::{affichable, couper};

const CAT: &str = "Persistance";

const LSA: &str = r"SYSTEM\CurrentControlSet\Control\Lsa";
const APPCERT: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls";
const MONITEURS: &str = r"SYSTEM\CurrentControlSet\Control\Print\Monitors";
const FOURNISSEURS_TEMPS: &str = r"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders";
const WINSOCK: [&str; 4] = [
    r"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries",
    r"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries64",
    r"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries",
    r"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries64",
];

/// Les paquets que Windows pose lui-même (en minuscules, sans « .dll ») : sécurité (fournisseurs d'authentification),
/// authentification et notification (filtres de mot de passe). La chaîne vide est la valeur d'origine de « Security
/// Packages » sur Windows 10 et 11.
const PAQUETS_DE_WINDOWS: [&str; 17] = [
    "",
    "kerberos",
    "msv1_0",
    "schannel",
    "wdigest",
    "tspkg",
    "pku2u",
    "cloudap",
    "negoexts",
    "livessp",
    "msoidssp",
    "credssp",
    "negotiate",
    "scecli",
    "rassfm",
    "kdcsvc",
    "fpnwclnt",
];

regle!(
    "WIN-PRS-007",
    Os::Windows,
    226,
    (
        "paquets chargés par LSA (sécurité, authentification, filtres de mot de passe)",
        "packages loaded by LSA (security, authentication, password filters)"
    ),
    &[
        "CIS Controls v8 13.2",
        "MITRE ATT&CK T1547.002",
        "MITRE ATT&CK T1547.005",
        "MITRE ATT&CK T1556.002"
    ],
    lsa
);

regle!(
    "WIN-PRS-008",
    Os::Windows,
    227,
    (
        "DLL chargées à chaque lancement de programme (AppCertDlls)",
        "DLLs loaded at every program start (AppCertDlls)"
    ),
    &["CIS Controls v8 13.2", "MITRE ATT&CK T1546.009"],
    appcert
);

regle!(
    "WIN-PRS-009",
    Os::Windows,
    228,
    ("moniteurs d'impression", "print monitors"),
    &["CIS Controls v8 13.2", "MITRE ATT&CK T1547.010"],
    moniteurs_impression
);

regle!(
    "WIN-PRS-010",
    Os::Windows,
    229,
    ("fournisseurs de temps", "time providers"),
    &["CIS Controls v8 13.2", "MITRE ATT&CK T1547.003"],
    fournisseurs_de_temps
);

regle!(
    "WIN-PRS-011",
    Os::Windows,
    229,
    ("catalogue Winsock", "Winsock catalog"),
    &["CIS Controls v8 13.2", "MITRE ATT&CK T1547", "MITRE ATT&CK T1574"],
    catalogue_winsock
);

/// Où se trouve une DLL nommée par un point d'ancrage.
#[derive(Debug, PartialEq)]
enum Lieu {
    /// Un nom seul (pris dans System32) ou un chemin dans System32 ou SysWOW64.
    Systeme,
    /// Ailleurs, dans un dossier de programmes : un logiciel installé (imprimante, machine virtuelle…).
    Installe,
    /// Un dossier du compte, temporaire, public ou de données : rien d'installé normalement n'y charge une DLL.
    Suspect(&'static str),
}

fn lieu(dll: &str) -> Lieu {
    let d = dll.trim().trim_matches('"').to_lowercase().replace('/', "\\");
    let d = d
        .replace("%systemroot%", "c:\\windows")
        .replace("%windir%", "c:\\windows");
    if !d.contains('\\') {
        return Lieu::Systeme;
    }
    if ["\\windows\\system32\\", "\\windows\\syswow64\\"]
        .iter()
        .any(|s| d.contains(s))
        && !d.contains("..")
    {
        return Lieu::Systeme;
    }
    if let Some(raison) = lancement_suspect(&d, "") {
        return Lieu::Suspect(raison);
    }
    if [
        "\\appdata\\",
        "\\programdata\\",
        "\\users\\",
        "%appdata%",
        "%localappdata%",
        "%programdata%",
    ]
    .iter()
    .any(|s| d.contains(s))
    {
        return Lieu::Suspect(tr!(
            "DLL rangée dans un dossier du compte ou de données",
            "DLL stored in an account or data folder"
        ));
    }
    Lieu::Installe
}

/// Le jugement commun d'une liste (nom de l'entrée, DLL) : rien hors du dossier système, c'est sain ; une DLL dans
/// un dossier suspect, c'est élevé ; ailleurs, `installe` (Info pour un ancrage où des logiciels en posent, Moyen
/// pour un ancrage que rien d'installé n'utilise d'ordinaire).
fn juger_dlls(sujet: (&str, &str), entrees: &[(String, String)], installe: Niveau) -> Constat {
    let (fr, en) = sujet;
    let mut niveau = None;
    let mut retenues = Vec::new();
    for (nom, dll) in entrees {
        let (n, pourquoi) = match lieu(dll) {
            Lieu::Systeme => continue,
            Lieu::Installe => (installe, None),
            Lieu::Suspect(r) => (Niveau::Eleve, Some(r)),
        };
        niveau = niveau.max(Some(n));
        retenues.push(match pourquoi {
            Some(r) => format!("{nom} : {dll} ({r})"),
            None => format!("{nom} : {dll}"),
        });
    }
    let Some(niveau) = niveau else {
        let n = entrees.len();
        return ok(
            CAT,
            trf!(
                "{fr} : {n} entrée(s), toutes dans le dossier système",
                "{en}: {n} entr(y/ies), all in the system folder",
            ),
        );
    };
    let liste = couper(&affichable(&retenues.join(" ; ")), 240);
    alerte(
        CAT,
        niveau,
        trf!(
            "{fr} : DLL chargée par Windows hors du dossier système : {liste}. Si le logiciel ne vous dit rien, c'est une façon pour un malware de se faire lancer par Windows lui-même.",
            "{en}: DLL loaded by Windows outside the system folder: {liste}. If you don't know the software, it is a way for malware to get started by Windows itself."
        ),
    )
}

// ------------------------------------------------------------------------------------------------------------ LSA

/// Les paquets d'une valeur de LSA. Windows les écrit en REG_MULTI_SZ, mais LSA lit aussi une valeur REG_SZ (ou
/// REG_EXPAND_SZ) posée à la main : l'ignorer laissait un filtre de mot de passe ajouté ainsi passer pour sain. Les
/// chaînes sont coupées aussi aux zéros, pour qu'un second paquet caché après un zéro dans une REG_SZ soit vu. Une
/// valeur d'un autre type rend None : elle n'est pas vérifiée, jamais comptée saine.
fn paquets_de(valeur: &winreg::RegValue) -> Option<Vec<String>> {
    use winreg::enums::RegType::{REG_EXPAND_SZ, REG_MULTI_SZ, REG_SZ};
    use winreg::types::FromRegValue;
    let texte = match valeur.vtype {
        REG_MULTI_SZ => Vec::<String>::from_reg_value(valeur).ok()?.join("\0"),
        REG_SZ | REG_EXPAND_SZ => String::from_reg_value(valeur).ok()?,
        _ => return None,
    };
    Some(texte.split('\0').map(str::to_owned).collect())
}

/// Chaque valeur lue : (nom de la valeur, paquets) ; `illisibles` : les valeurs présentes mais illisibles ou d'un type
/// inattendu. Un paquet inconnu est dit ; un paquet donné par un chemin, que LSA charge alors hors de System32, est
/// élevé. Sans paquet inconnu, une valeur illisible rend le constat non vérifié.
fn juger_lsa(lues: &[(&str, Vec<String>)], illisibles: &[&str]) -> Constat {
    let mut inconnus = Vec::new();
    let mut chemin = false;
    for (valeur, paquets) in lues {
        for p in paquets {
            // Windows 10 et 11 écrivent « "" » (deux guillemets) dans Security Packages, pas une chaîne vide.
            let nom = p.trim().trim_matches('"').to_lowercase();
            let nom = nom.strip_suffix(".dll").unwrap_or(&nom);
            if PAQUETS_DE_WINDOWS.contains(&nom) {
                continue;
            }
            chemin |= nom.contains('\\') || nom.contains('/');
            inconnus.push(format!("{p} ({valeur})"));
        }
    }
    let non_lues = illisibles.join(", ");
    if inconnus.is_empty() {
        if !illisibles.is_empty() {
            return impossible(
                CAT,
                &trf!(
                    "valeur de LSA illisible ou d'un type inattendu : {non_lues}",
                    "LSA value unreadable or of an unexpected type: {non_lues}"
                ),
            );
        }
        return ok(
            CAT,
            tr!(
                "Paquets de LSA : ceux de Windows seulement",
                "LSA packages: Windows' own only"
            ),
        );
    }
    let liste = couper(&affichable(&inconnus.join(", ")), 200);
    let mut message = trf!(
        "LSA, le gardien des mots de passe de Windows, charge un paquet que Vanguard ne connaît pas : {liste}. Un filtre de mot de passe (Notification Packages) reçoit chaque nouveau mot de passe en clair. S'il ne vient pas d'un logiciel que vous avez installé (gestionnaire de mots de passe d'entreprise, par exemple), c'est un vol de mots de passe.",
        "LSA, Windows' password keeper, loads a package Vanguard does not know: {liste}. A password filter (Notification Packages) receives every new password in clear text. If it does not come from software you installed (a company password manager, for example), it is password theft."
    );
    if !illisibles.is_empty() {
        message.push_str(&trf!(
            " Non vérifié (illisible ou d'un type inattendu) : {non_lues}.",
            " Not checked (unreadable or of an unexpected type): {non_lues}."
        ));
    }
    alerte(CAT, if chemin { Niveau::Eleve } else { Niveau::Moyen }, message)
}

/// Une valeur de LSA : Ok(None) si elle n'existe pas (Windows n'en pose pas toujours trois), Err si elle existe sans
/// pouvoir être lue ou n'a pas un type de texte.
fn valeur_lsa(cle: &RegKey, nom: &str) -> Result<Option<Vec<String>>, ()> {
    match cle.get_raw_value(nom) {
        Ok(v) => paquets_de(&v).map(Some).ok_or(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(()),
    }
}

fn lsa() -> Vec<Constat> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let Ok(cle) = hklm.open_subkey(LSA) else {
        return vec![registre_illisible(CAT)];
    };
    let mut lues: Vec<(&str, Vec<String>)> = Vec::new();
    let mut illisibles: Vec<&str> = Vec::new();
    let mut lire = |cle: &RegKey, nom: &'static str, affiche: &'static str| match valeur_lsa(cle, nom) {
        Ok(Some(p)) => lues.push((affiche, p)),
        Ok(None) => {}
        Err(()) => illisibles.push(affiche),
    };
    for v in ["Security Packages", "Authentication Packages", "Notification Packages"] {
        lire(&cle, v, v);
    }
    match cle.open_subkey("OSConfig") {
        Ok(os) => lire(&os, "Security Packages", "OSConfig\\Security Packages"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => illisibles.push("OSConfig"),
    }
    if lues.is_empty() && illisibles.is_empty() {
        return vec![registre_illisible(CAT)];
    }
    vec![juger_lsa(&lues, &illisibles)]
}

// ---------------------------------------------------------------------------------------------------- AppCertDlls

/// Les valeurs de la clé AppCertDlls (nom, DLL). Windows n'en pose aucune : toute entrée est dite.
fn juger_appcert(entrees: &[(String, String)]) -> Constat {
    if entrees.is_empty() {
        return ok(CAT, tr!("AppCertDlls : vide", "AppCertDlls: empty"));
    }
    let mut constat = juger_dlls(("AppCertDlls", "AppCertDlls"), entrees, Niveau::Moyen);
    if constat.probleme.is_none() {
        // Dans System32, mais Windows n'en pose jamais : une DLL déposée là par un programme qui avait les droits.
        let liste = couper(
            &affichable(
                &entrees
                    .iter()
                    .map(|(n, d)| format!("{n} : {d}"))
                    .collect::<Vec<_>>()
                    .join(" ; "),
            ),
            200,
        );
        constat = alerte(
            CAT,
            Niveau::Moyen,
            trf!(
                "AppCertDlls : une DLL est chargée dans chaque programme qui en lance un autre : {liste}. Windows n'en pose aucune ; un logiciel de sécurité le fait parfois.",
                "AppCertDlls: a DLL is loaded into every program that starts another one: {liste}. Windows sets none; security software sometimes does.",
            ),
        );
    }
    constat
}

fn appcert() -> Vec<Constat> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    match hklm.open_subkey(APPCERT) {
        // La clé n'existe pas d'origine.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => vec![juger_appcert(&[])],
        Err(_) => vec![registre_illisible(CAT)],
        Ok(cle) => vec![juger_appcert(&valeurs_texte(&cle))],
    }
}

/// Les valeurs texte d'une clé (nom, donnée) ; les autres types sont ignorés.
fn valeurs_texte(cle: &RegKey) -> Vec<(String, String)> {
    cle.enum_values()
        .flatten()
        .filter_map(|(nom, _)| cle.get_value::<String, _>(&nom).ok().map(|d| (nom, d)))
        .collect()
}

// ------------------------------------------------------------------------------------------- moniteurs, fournisseurs

/// Pour chaque sous-clé : (nom de la sous-clé, la valeur texte `valeur`), et pour les fournisseurs de temps, seulement
/// ceux qui sont activés. `None` si la clé ne s'ouvre pas.
fn sous_cles(chemin: &str, valeur: &str, actives_seulement: bool) -> Option<Vec<(String, String)>> {
    let cle = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(chemin).ok()?;
    Some(
        cle.enum_keys()
            .flatten()
            .filter_map(|nom| {
                let k = cle.open_subkey(&nom).ok()?;
                if actives_seulement && k.get_value::<u32, _>("Enabled").ok() == Some(0) {
                    return None;
                }
                k.get_value::<String, _>(valeur).ok().map(|d| (nom, d))
            })
            .collect(),
    )
}

fn moniteurs_impression() -> Vec<Constat> {
    match sous_cles(MONITEURS, "Driver", false) {
        // Les pilotes d'imprimante posent leurs moniteurs par leur seul nom, dans System32 : un chemin complet ailleurs
        // n'est pas la forme normale.
        Some(e) => vec![juger_dlls(
            ("Moniteurs d'impression", "Print monitors"),
            &e,
            Niveau::Moyen,
        )],
        None => vec![registre_illisible(CAT)],
    }
}

fn fournisseurs_de_temps() -> Vec<Constat> {
    match sous_cles(FOURNISSEURS_TEMPS, "DllName", true) {
        Some(e) => vec![juger_dlls(
            ("Fournisseurs de temps", "Time providers"),
            &e,
            Niveau::Moyen,
        )],
        None => vec![registre_illisible(CAT)],
    }
}

// ------------------------------------------------------------------------------------------------------- Winsock

/// Le chemin de la DLL au début d'un PackedCatalogItem (texte ANSI terminé par un zéro).
fn chemin_du_catalogue(octets: &[u8]) -> Option<String> {
    let fin = octets.iter().position(|&o| o == 0)?;
    let texte = String::from_utf8_lossy(&octets[..fin]).trim().to_string();
    (!texte.is_empty()).then_some(texte)
}

fn catalogue_winsock() -> Vec<Constat> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut entrees = Vec::new();
    let mut lues = 0;
    for chemin in WINSOCK {
        let Ok(cle) = hklm.open_subkey(chemin) else {
            continue;
        };
        lues += 1;
        for nom in cle.enum_keys().flatten() {
            let Ok(k) = cle.open_subkey(&nom) else {
                continue;
            };
            let dll = k.get_value::<String, _>("LibraryPath").ok().or_else(|| {
                k.get_raw_value("PackedCatalogItem")
                    .ok()
                    .and_then(|v| chemin_du_catalogue(&v.bytes))
            });
            if let Some(dll) = dll {
                entrees.push((nom, dll));
            }
        }
    }
    if lues == 0 {
        return vec![registre_illisible(CAT)];
    }
    // Des logiciels installés (machines virtuelles, Bluetooth, VPN) y posent leurs DLL : dit en information.
    vec![juger_dlls(
        ("Catalogue Winsock", "Winsock catalog"),
        &entrees,
        Niveau::Info,
    )]
}

/// WIN-PRS-007 au corpus de détection : `lsa|valeur|paquet,paquet…`.
#[cfg(test)]
pub(super) fn corpus_lsa(e: &crate::modele::corpus::Entree) -> Vec<Constat> {
    let lues: Vec<(&str, Vec<String>)> = e
        .de("lsa")
        .iter()
        .map(|c| (c[0], c[1].split(',').map(str::to_string).collect()))
        .collect();
    vec![juger_lsa(&lues, &[])]
}

/// Les entrées `entree|nom|DLL` d'un cas.
#[cfg(test)]
fn entrees_du_cas(e: &crate::modele::corpus::Entree) -> Vec<(String, String)> {
    e.de("entree")
        .iter()
        .map(|c| (c[0].to_string(), c[1].to_string()))
        .collect()
}

/// WIN-PRS-008 : les valeurs de AppCertDlls.
#[cfg(test)]
pub(super) fn corpus_appcert(e: &crate::modele::corpus::Entree) -> Vec<Constat> {
    vec![juger_appcert(&entrees_du_cas(e))]
}

/// WIN-PRS-009, 010 et 011 : le jugement commun des DLL, avec le niveau que chaque règle lui donne (moniteurs
/// d'impression et fournisseurs de temps : moyen ; catalogue Winsock : information).
#[cfg(test)]
pub(super) fn corpus_moniteurs(e: &crate::modele::corpus::Entree) -> Vec<Constat> {
    vec![juger_dlls(
        ("Moniteurs d'impression", "Print monitors"),
        &entrees_du_cas(e),
        Niveau::Moyen,
    )]
}

#[cfg(test)]
pub(super) fn corpus_fournisseurs(e: &crate::modele::corpus::Entree) -> Vec<Constat> {
    vec![juger_dlls(
        ("Fournisseurs de temps", "Time providers"),
        &entrees_du_cas(e),
        Niveau::Moyen,
    )]
}

#[cfg(test)]
pub(super) fn corpus_winsock(e: &crate::modele::corpus::Entree) -> Vec<Constat> {
    vec![juger_dlls(
        ("Catalogue Winsock", "Winsock catalog"),
        &entrees_du_cas(e),
        Niveau::Info,
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(n: &str, d: &str) -> (String, String) {
        (n.into(), d.into())
    }

    /// Le vrai registre (celui de Wine pendant les tests) : chaque lecture rend un constat, sans planter.
    #[test]
    fn lecture_du_vrai_registre() {
        let constats: Vec<Constat> = [
            lsa,
            appcert,
            moniteurs_impression,
            fournisseurs_de_temps,
            catalogue_winsock,
        ]
        .iter()
        .flat_map(|f| f())
        .collect();
        assert_eq!(constats.len(), 5);
        assert!(constats.iter().all(|c| !c.message.is_empty()));
    }

    #[test]
    fn le_lieu_d_une_dll() {
        assert_eq!(lieu("localspl.dll"), Lieu::Systeme);
        assert_eq!(lieu(r"%SystemRoot%\System32\mswsock.dll"), Lieu::Systeme);
        assert_eq!(lieu(r"C:\Windows\SysWOW64\w32time.dll"), Lieu::Systeme);
        assert_eq!(lieu(r"C:\Program Files\Imprimante\moniteur.dll"), Lieu::Installe);
        assert!(matches!(
            lieu(r"C:\Users\alice\AppData\Roaming\x.dll"),
            Lieu::Suspect(_)
        ));
        assert!(matches!(lieu(r"C:\ProgramData\x\y.dll"), Lieu::Suspect(_)));
        assert!(matches!(lieu(r"C:\Windows\Temp\z.dll"), Lieu::Suspect(_)));
        assert!(matches!(lieu(r"C:\Users\Public\z.dll"), Lieu::Suspect(_)));
        // Un détour par « .. » ne passe pas pour System32.
        assert_eq!(lieu(r"C:\Windows\System32\..\..\Outils\a.dll"), Lieu::Installe);
    }

    #[test]
    fn les_paquets_de_lsa() {
        let windows = [
            ("Security Packages", vec![String::new()]),
            ("Authentication Packages", vec!["msv1_0".into()]),
            ("Notification Packages", vec!["scecli".into()]),
            (
                "OSConfig\\Security Packages",
                vec!["kerberos".into(), "msv1_0".into(), "cloudap".into()],
            ),
        ];
        assert!(juger_lsa(&windows, &[]).probleme.is_none());
        let filtre = [("Notification Packages", vec!["scecli".into(), "filtremdp".into()])];
        let c = juger_lsa(&filtre, &[]);
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.message.contains("filtremdp (Notification Packages)"));
        let chemin = [("Security Packages", vec![r"C:\Users\alice\x.dll".into()])];
        assert_eq!(juger_lsa(&chemin, &[]).probleme, Some(Niveau::Eleve));
        // La valeur d'origine de Windows : deux guillemets, vue sur une vraie VM.
        assert!(
            juger_lsa(&[("Security Packages", vec!["\"\"".into()])], &[])
                .probleme
                .is_none()
        );
        // La casse et « .dll » ne changent rien.
        assert!(
            juger_lsa(&[("Security Packages", vec!["Kerberos.DLL".into()])], &[])
                .probleme
                .is_none()
        );
    }

    /// Une valeur de LSA en REG_SZ est lue comme une REG_MULTI_SZ ; un autre type n'est pas vérifié.
    #[test]
    fn valeurs_de_lsa_de_tous_types() {
        use std::borrow::Cow;
        use winreg::enums::RegType::{REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_SZ};
        let utf16 = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(u16::to_le_bytes).collect() };
        let valeur = |vtype, s: &str| winreg::RegValue {
            bytes: Cow::Owned(utf16(s)),
            vtype,
        };
        assert_eq!(
            paquets_de(&valeur(REG_MULTI_SZ, "scecli\0filtremdp\0\0")),
            Some(vec!["scecli".into(), "filtremdp".into()])
        );
        assert_eq!(
            paquets_de(&valeur(REG_SZ, "filtremdp\0")),
            Some(vec!["filtremdp".into()])
        );
        // Un second paquet caché après un zéro dans une REG_SZ est vu.
        assert_eq!(
            paquets_de(&valeur(REG_SZ, "scecli\0cache\0")),
            Some(vec!["scecli".into(), "cache".into()])
        );
        assert_eq!(paquets_de(&valeur(REG_BINARY, "scecli")), None);
        assert_eq!(paquets_de(&valeur(REG_DWORD, "ab")), None);
        let filtre = paquets_de(&valeur(REG_SZ, "filtremdp")).unwrap();
        assert_eq!(
            juger_lsa(&[("Notification Packages", filtre)], &[]).probleme,
            Some(Niveau::Moyen)
        );
        // Une valeur d'un type inattendu, sans autre alerte : non vérifié, jamais sain.
        let c = juger_lsa(
            &[("Security Packages", vec!["kerberos".into()])],
            &["Notification Packages"],
        );
        assert!(!c.verifie);
        assert!(c.message.contains("Notification Packages"));
        // Avec un paquet inconnu ailleurs, l'alerte reste et dit ce qui n'a pas été lu.
        let c = juger_lsa(
            &[("Security Packages", vec!["inconnu".into()])],
            &["Notification Packages"],
        );
        assert!(c.verifie && c.probleme == Some(Niveau::Moyen));
        assert!(c.message.contains("Notification Packages"));
    }

    #[test]
    fn appcertdlls() {
        assert!(juger_appcert(&[]).probleme.is_none());
        assert_eq!(juger_appcert(&[e("x", "x.dll")]).probleme, Some(Niveau::Moyen));
        assert_eq!(
            juger_appcert(&[e("x", r"C:\Users\alice\AppData\Local\x.dll")]).probleme,
            Some(Niveau::Eleve)
        );
    }

    #[test]
    fn moniteurs_fournisseurs_et_winsock() {
        let normaux = [e("Local Port", "localspl.dll"), e("Standard TCP/IP Port", "tcpmon.dll")];
        assert!(juger_dlls(("M", "M"), &normaux, Niveau::Moyen).probleme.is_none());
        let ailleurs = [e("Imprimante", r"C:\Program Files\Imprimante\mon.dll")];
        assert_eq!(
            juger_dlls(("M", "M"), &ailleurs, Niveau::Moyen).probleme,
            Some(Niveau::Moyen)
        );
        assert_eq!(
            juger_dlls(("W", "W"), &ailleurs, Niveau::Info).probleme,
            Some(Niveau::Info)
        );
        let pire = [
            ailleurs[0].clone(),
            e("Cache", r"C:\Users\alice\AppData\Local\Temp\a.dll"),
        ];
        let c = juger_dlls(("W", "W"), &pire, Niveau::Info);
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(c.message.contains("Imprimante") && c.message.contains("Cache"));
        assert_eq!(
            chemin_du_catalogue(b"%SystemRoot%\\system32\\mswsock.dll\0\0\x01"),
            Some(r"%SystemRoot%\system32\mswsock.dll".into())
        );
        assert_eq!(chemin_du_catalogue(b"\0abc"), None);
        assert_eq!(chemin_du_catalogue(b"sans fin"), None);
    }
}

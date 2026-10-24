//! Programmes installés, lus dans le registre (winreg) sans PowerShell : les noms du panneau « Applications
//! installées » (clés Uninstall), ceux des applications du Store et la présence de winget. Mêmes listes que
//! `Get-ItemProperty …\Uninstall\*`, `Get-AppxPackage` et `Get-Command winget`, en quelques millisecondes.
//!
//! `programmes` lit davantage (version, éditeur, emplacement) et pour tous les comptes dont la session est ouverte
//! (`HKEY_USERS`) ; les profils de `ProfileList` donnent les dossiers des autres. La ruche d'un compte fermé n'est
//! jamais chargée (RegLoadKey) : Vanguard ne touche pas au registre d'une personne absente.

use std::path::PathBuf;

use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY};

const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
const UNINSTALL_32: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";
/// Les trois clés Uninstall du panneau « Applications installées » : machine (64 puis 32 bits) et ce compte. Une
/// seule liste pour ceux qui les lisent (ici, et « Mon ordinateur est-il contrôlé ? »).
pub(crate) const CLES_UNINSTALL: [(winreg::HKEY, &str); 3] = [
    (HKEY_LOCAL_MACHINE, UNINSTALL),
    (HKEY_LOCAL_MACHINE, UNINSTALL_32),
    (HKEY_CURRENT_USER, UNINSTALL),
];
/// Les paquets du Store installés pour ce compte (ce que Get-AppxPackage liste sans -AllUsers).
const PAQUETS: &str =
    r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";

/// Les noms affichés (DisplayName) des programmes installés pour la machine (64 et 32 bits) et pour ce compte.
/// `None` si la clé Uninstall de la machine ne s'ouvre pas : l'appelant demande alors à PowerShell.
pub(crate) fn noms() -> Option<Vec<String>> {
    let [(racine, principale), autres @ ..] = CLES_UNINSTALL;
    let mut noms = noms_de(&RegKey::predef(racine).open_subkey(principale).ok()?);
    for (racine, chemin) in autres {
        if let Ok(cle) = RegKey::predef(racine).open_subkey(chemin) {
            noms.extend(noms_de(&cle));
        }
    }
    Some(noms)
}

fn noms_de(cle: &RegKey) -> Vec<String> {
    cle.enum_keys()
        .flatten()
        .filter_map(|sous| cle.open_subkey(sous).ok()?.get_value::<String, _>("DisplayName").ok())
        .filter(|n| !n.is_empty())
        .collect()
}

/// Les noms des paquets du Store de ce compte (« Microsoft.WindowsTerminal »), tirés de leur nom complet.
pub(crate) fn paquets_store() -> Vec<String> {
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(PAQUETS)
        .map(|cle| {
            cle.enum_keys()
                .flatten()
                .filter_map(|complet| nom_du_paquet(&complet))
                .collect()
        })
        .unwrap_or_default()
}

/// « Microsoft.WindowsTerminal_1.21.3231.0_x64__8wekyb3d8bbwe » → « Microsoft.WindowsTerminal » : le nom d'un paquet
/// ne contient jamais « _ » (lettres, chiffres, points et tirets), qui sépare les parties du nom complet.
pub(crate) fn nom_du_paquet(complet: &str) -> Option<String> {
    let (nom, reste) = complet.split_once('_')?;
    (!nom.is_empty() && !reste.is_empty()).then(|| nom.to_string())
}

/// Sous-clés lues au plus par clé : une clé Uninstall réelle en a quelques centaines.
const SOUS_CLES_MAX: usize = 5000;
/// Une valeur texte plus longue (en octets, UTF-16) n'est pas un nom ni un chemin : ignorée.
const VALEUR_MAX: usize = 2048;
/// Profils lus au plus dans ProfileList.
const PROFILS_MAX: usize = 64;
const PROFILE_LIST: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

/// Pour qui un programme est installé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Portee {
    Machine,
    /// Le compte de ce processus (HKCU).
    CompteCourant,
    /// Un autre compte dont la session est ouverte (`HKEY_USERS\<SID>`).
    Compte(String),
}

/// Un programme du panneau « Applications installées » : une clé Uninstall, sans les composants du système ni les
/// correctifs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Programme {
    pub nom: String,
    pub version: String,
    pub editeur: String,
    pub emplacement: Option<PathBuf>,
    pub portee: Portee,
    /// La clé, pour la nommer quand l'emplacement manque (« HKLM\…\Uninstall\{GUID} »).
    pub cle: String,
}

/// Une clé ouverte en lecture dans la vue de registre `vue` (`KEY_WOW64_64KEY` ou `KEY_WOW64_32KEY`) : la vue 32 bits
/// de `HKLM\SOFTWARE` est celle que Windows redirige vers WOW6432Node, sans écrire ce nom en dur.
pub(crate) fn ouvrir(racine: &RegKey, chemin: &str, vue: u32) -> Option<RegKey> {
    racine.open_subkey_with_flags(chemin, KEY_READ | vue).ok()
}

/// Une valeur texte (REG_SZ ou REG_EXPAND_SZ, non développée), si elle existe et n'est ni vide ni trop longue.
pub(crate) fn texte(cle: &RegKey, nom: &str) -> Option<String> {
    use winreg::enums::RegType::{REG_EXPAND_SZ, REG_SZ};
    use winreg::types::FromRegValue;
    let brute = cle.get_raw_value(nom).ok()?;
    if !matches!(brute.vtype, REG_SZ | REG_EXPAND_SZ) || brute.bytes.len() > VALEUR_MAX {
        return None;
    }
    let texte = String::from_reg_value(&brute).ok()?;
    let texte = texte.trim();
    (!texte.is_empty()).then(|| texte.to_string())
}

/// Les noms des sous-clés, bornés.
pub(crate) fn sous_cles(cle: &RegKey) -> Vec<String> {
    sous_cles_comptees(cle).0
}

/// Les noms des sous-clés, bornés, et si la borne a été atteinte : une sous-clé de plus que `SOUS_CLES_MAX` est
/// demandée pour le savoir, jamais gardée.
fn sous_cles_comptees(cle: &RegKey) -> (Vec<String>, bool) {
    let mut noms: Vec<String> = cle.enum_keys().take(SOUS_CLES_MAX + 1).flatten().collect();
    let coupee = noms.len() > SOUS_CLES_MAX;
    noms.truncate(SOUS_CLES_MAX);
    (noms, coupee)
}

/// Ce que la lecture des clés Uninstall n'a pas pu prendre, par portée : les clés coupées à `SOUS_CLES_MAX`
/// sous-clés (les suivantes ne sont pas lues : un programme peut y être caché derrière des milliers de clés vides)
/// et le nombre de clés sans nom affiché, écartées. Pour que la liste ne passe jamais pour entière quand elle ne
/// l'est pas.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Laisses {
    pub coupees: Vec<(Portee, String)>,
    pub sans_nom: Vec<(Portee, usize)>,
}

/// Les programmes d'une clé Uninstall déjà ouverte (`nom` la désigne dans `Programme::cle`). Écartés : les
/// composants du système (`SystemComponent` = 1), les correctifs et mises à jour d'un autre programme
/// (`ParentKeyName`), les clés sans nom affiché (comptées dans `laisses`, avec la borne atteinte).
pub(crate) fn programmes_de(
    cle: &RegKey,
    nom: &str,
    vue: u32,
    portee: &Portee,
    laisses: &mut Laisses,
) -> Vec<Programme> {
    let (sous_cles, coupee) = sous_cles_comptees(cle);
    if coupee {
        laisses.coupees.push((portee.clone(), nom.to_string()));
    }
    let mut sans_nom = 0;
    let programmes = sous_cles
        .into_iter()
        .filter_map(|sous| {
            let k = ouvrir(cle, &sous, vue)?;
            if k.get_value::<u32, _>("SystemComponent").is_ok_and(|v| v == 1) || texte(&k, "ParentKeyName").is_some() {
                return None;
            }
            let Some(affiche) = texte(&k, "DisplayName") else {
                sans_nom += 1;
                return None;
            };
            Some(Programme {
                nom: affiche,
                version: texte(&k, "DisplayVersion").unwrap_or_default(),
                editeur: texte(&k, "Publisher").unwrap_or_default(),
                emplacement: texte(&k, "InstallLocation").and_then(|e| emplacement_local(&e)),
                portee: portee.clone(),
                cle: format!(r"{nom}\{sous}"),
            })
        })
        .collect();
    if sans_nom > 0 {
        laisses.sans_nom.push((portee.clone(), sans_nom));
    }
    programmes
}

/// Un `InstallLocation` gardé seulement sur une lettre de lecteur locale (« C:\… »). La valeur peut venir de la
/// ruche d'un autre compte : un chemin réseau (`\\serveur\p`, `\\?\UNC\…`) ou de périphérique (`\\.\…`)
/// ferait ouvrir une connexion SMB qui présente l'identité de celui qui lance Vanguard, souvent l'administrateur.
fn emplacement_local(valeur: &str) -> Option<PathBuf> {
    let chemin = PathBuf::from(valeur.trim_matches('"'));
    let sur_disque = matches!(
        chemin.components().next(),
        Some(std::path::Component::Prefix(p)) if matches!(p.kind(), std::path::Prefix::Disk(_))
    );
    (sur_disque && chemin.is_absolute()).then_some(chemin)
}

/// Un SID de compte de personne, local ou de domaine (« S-1-5-21-… ») ou Microsoft Entra ID (« S-1-12-1-… », PC
/// joint à Azure AD) : pas SYSTEM (S-1-5-18), ni les services (19, 20), ni la ruche des classes d'un compte
/// (« …_Classes »). Un compte écarté ici ne serait ni lu ni compté comme non vérifié.
pub(crate) fn sid_de_personne(sid: &str) -> bool {
    sid.strip_prefix("S-1-5-21-")
        .or_else(|| sid.strip_prefix("S-1-12-1-"))
        .is_some_and(|r| !r.is_empty() && r.bytes().all(|o| o.is_ascii_digit() || o == b'-'))
}

/// Les comptes dont la ruche est chargée (session ouverte), sauf celui de ce processus.
pub(crate) fn ruches_chargees() -> Vec<String> {
    let moi = super::processus::sid();
    sous_cles(&RegKey::predef(HKEY_USERS))
        .into_iter()
        .filter(|s| sid_de_personne(s) && moi.as_deref() != Some(s))
        .collect()
}

/// Les profils des comptes de personnes (SID, dossier), d'après ProfileList : au plus 64. `%SystemDrive%` et les
/// autres variables d'environnement du chemin sont développées.
pub(crate) fn profils() -> Vec<(String, PathBuf)> {
    let Some(liste) = ouvrir(&RegKey::predef(HKEY_LOCAL_MACHINE), PROFILE_LIST, KEY_WOW64_64KEY) else {
        return Vec::new();
    };
    sous_cles(&liste)
        .into_iter()
        .filter(|s| sid_de_personne(s))
        .filter_map(|sid| {
            let chemin = texte(&ouvrir(&liste, &sid, KEY_WOW64_64KEY)?, "ProfileImagePath")?;
            let chemin = developper(&chemin, &|v| std::env::var(v).ok())?;
            Some((sid, PathBuf::from(chemin)))
        })
        .take(PROFILS_MAX)
        .collect()
}

/// `%NOM%` remplacé par la variable d'environnement `NOM` ; `None` si l'une manque (le chemin ne serait pas le bon).
pub(crate) fn developper(texte: &str, variable: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    let mut sortie = String::new();
    let mut reste = texte;
    while let Some(debut) = reste.find('%') {
        sortie.push_str(&reste[..debut]);
        let apres = &reste[debut + 1..];
        let fin = apres.find('%')?;
        sortie.push_str(&variable(&apres[..fin])?);
        reste = &apres[fin + 1..];
    }
    sortie.push_str(reste);
    Some(sortie)
}

/// Les programmes installés : machine (vues 64 et 32 bits), ce compte, et chaque autre compte dont la session est
/// ouverte (lisible en administrateur seulement ; sinon rien, et l'inventaire le dit).
pub(crate) fn programmes() -> Vec<Programme> {
    programmes_et_laisses().0
}

/// Les programmes installés (`programmes`) et ce que leur lecture a laissé (`Laisses`).
pub(crate) fn programmes_et_laisses() -> (Vec<Programme>, Laisses) {
    const CHEMIN: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall";
    let machine = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut tous = Vec::new();
    let mut laisses = Laisses::default();
    for (vue, nom) in [
        (
            KEY_WOW64_64KEY,
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            KEY_WOW64_32KEY,
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
    ] {
        if let Some(cle) = ouvrir(&machine, UNINSTALL, vue) {
            tous.extend(programmes_de(&cle, nom, vue, &Portee::Machine, &mut laisses));
        }
    }
    // HKCU\Software n'a qu'une vue (partagée entre 32 et 64 bits).
    if let Some(cle) = ouvrir(&RegKey::predef(HKEY_CURRENT_USER), CHEMIN, KEY_WOW64_64KEY) {
        tous.extend(programmes_de(
            &cle,
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall",
            KEY_WOW64_64KEY,
            &Portee::CompteCourant,
            &mut laisses,
        ));
    }
    let utilisateurs = RegKey::predef(HKEY_USERS);
    for sid in ruches_chargees() {
        if let Some(cle) = ouvrir(&utilisateurs, &format!(r"{sid}\{CHEMIN}"), KEY_WOW64_64KEY) {
            let nom = format!(r"HKU\{sid}\{CHEMIN}");
            tous.extend(programmes_de(
                &cle,
                &nom,
                KEY_WOW64_64KEY,
                &Portee::Compte(sid),
                &mut laisses,
            ));
        }
    }
    (tous, laisses)
}

/// winget trouvable par son nom, comme `Get-Command winget` : un fichier « winget » + une extension de PATHEXT dans
/// un dossier du PATH. Celui du Store est un alias d'exécution (point d'analyse) : son entrée se lit sans le suivre.
pub(crate) fn winget_present() -> bool {
    let extensions = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).any(|d| {
        extensions
            .split(';')
            .filter(|e| !e.is_empty())
            .any(|e| std::fs::symlink_metadata(d.join(format!("winget{}", e.to_lowercase()))).is_ok())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noms_des_paquets() {
        assert_eq!(
            nom_du_paquet("Microsoft.WindowsTerminal_1.21.3231.0_x64__8wekyb3d8bbwe").as_deref(),
            Some("Microsoft.WindowsTerminal")
        );
        assert_eq!(nom_du_paquet("sans-separateur"), None);
        assert_eq!(nom_du_paquet("_1.0_x64__abc"), None);
        assert_eq!(nom_du_paquet("Nom_"), None);
    }

    /// Le vrai registre (Wine ici, la VM ensuite), en lecture seule : la clé Uninstall de la machine s'ouvre et chaque
    /// nom lu est un vrai nom ; les programmes, profils et ruches se lisent sans erreur.
    #[test]
    fn programmes_lus_dans_le_registre() {
        let noms = noms().expect("clé Uninstall de la machine");
        assert!(noms.iter().all(|n| !n.is_empty()), "{noms:?}");
        assert!(paquets_store().iter().all(|p| !p.contains('_')));
        let programmes = programmes();
        assert!(
            programmes
                .iter()
                .all(|p| !p.nom.is_empty() && p.cle.contains(r"\Uninstall\"))
        );
        assert!(
            programmes
                .iter()
                .all(|p| p.emplacement.as_ref().is_none_or(|e| e.is_absolute()))
        );
        assert!(profils().len() <= PROFILS_MAX);
        assert!(ruches_chargees().iter().all(|s| sid_de_personne(s)));
    }

    #[test]
    fn emplacements_locaux_seulement() {
        assert_eq!(
            emplacement_local(r#""C:\Program Files\Mozilla Firefox""#),
            Some(PathBuf::from(r"C:\Program Files\Mozilla Firefox"))
        );
        // Un compte qui écrit un chemin réseau dans sa ruche ne doit pas faire sortir de connexion SMB.
        assert_eq!(emplacement_local(r"\\192.0.2.1\p"), None);
        assert_eq!(emplacement_local(r"\\?\UNC\192.0.2.1\p"), None);
        assert_eq!(emplacement_local(r"\\.\pipe\x"), None);
        assert_eq!(emplacement_local(r"\\?\C:\x"), None);
        assert_eq!(emplacement_local(r"C:relatif"), None);
        assert_eq!(emplacement_local(r"\sans-lecteur"), None);
    }

    #[test]
    fn sids_et_variables() {
        assert!(sid_de_personne("S-1-5-21-1-2-3-1001"));
        assert!(!sid_de_personne("S-1-5-21-1-2-3-1001_Classes"));
        assert!(!sid_de_personne("S-1-5-18"));
        assert!(!sid_de_personne("S-1-5-21-"));
        assert!(sid_de_personne("S-1-12-1-1-2-3-4"));
        assert!(!sid_de_personne("S-1-12-1-1-2-3-4_Classes"));
        assert!(!sid_de_personne("S-1-12-1-"));
        let v = |n: &str| (n == "SystemDrive").then(|| "C:".to_string());
        assert_eq!(
            developper(r"%SystemDrive%\Users\alice", &v).as_deref(),
            Some(r"C:\Users\alice")
        );
        assert_eq!(developper(r"C:\Users\alice", &v).as_deref(), Some(r"C:\Users\alice"));
        assert_eq!(developper(r"%Absente%\x", &v), None);
        assert_eq!(developper(r"%SystemDrive\x", &v), None);
    }

    /// Des clés Uninstall inventées sous `HKCU\Software\VanguardTest-<pid>`, effacées ensuite : un programme gardé,
    /// un composant du système et un correctif écartés, une clé sans nom ignorée, une valeur trop longue oubliée.
    #[test]
    fn programmes_d_une_cle_inventee() {
        let chemin = format!(r"Software\VanguardTest-{}\Uninstall", std::process::id());
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let Ok((cle, _)) = hkcu.create_subkey(&chemin) else {
            return crate::essais::saute("registre inaccessible");
        };
        let ecrire = |sous: &str, valeurs: &[(&str, &str)]| {
            let (k, _) = cle.create_subkey(sous).unwrap();
            for (n, v) in valeurs {
                k.set_value(n, &(*v).to_string()).unwrap();
            }
            k
        };
        ecrire(
            "{AC76BA86-1033-FFFF-7760-BC15014EA700}",
            &[
                ("DisplayName", "Adobe Acrobat (64-bit)"),
                ("DisplayVersion", "20.005.30774"),
                ("Publisher", "Adobe Inc."),
                ("InstallLocation", r"C:\Program Files\Adobe\Acrobat DC\"),
            ],
        );
        ecrire(
            "Google Chrome",
            &[("DisplayName", "Google Chrome"), ("DisplayVersion", "156.0.8078.48")],
        )
        .set_value("InstallLocation", &"x".repeat(VALEUR_MAX))
        .unwrap();
        ecrire("Composant", &[("DisplayName", "Composant")])
            .set_value("SystemComponent", &1u32)
            .unwrap();
        ecrire("KB1", &[("DisplayName", "Correctif"), ("ParentKeyName", "Office")]);
        ecrire("SansNom", &[("DisplayVersion", "1.0")]);
        let mut laisses = Laisses::default();
        let lus = programmes_de(&cle, "HKCU", KEY_WOW64_64KEY, &Portee::CompteCourant, &mut laisses);
        let _ = hkcu.delete_subkey_all(format!(r"Software\VanguardTest-{}", std::process::id()));
        assert_eq!(
            laisses,
            Laisses {
                coupees: Vec::new(),
                sans_nom: vec![(Portee::CompteCourant, 1)],
            }
        );
        let mut noms: Vec<&str> = lus.iter().map(|p| p.nom.as_str()).collect();
        noms.sort_unstable();
        assert_eq!(noms, ["Adobe Acrobat (64-bit)", "Google Chrome"]);
        let acrobat = lus.iter().find(|p| p.editeur == "Adobe Inc.").unwrap();
        assert_eq!(acrobat.version, "20.005.30774");
        assert_eq!(
            acrobat.emplacement.as_deref(),
            Some(std::path::Path::new(r"C:\Program Files\Adobe\Acrobat DC\"))
        );
        assert_eq!(acrobat.cle, r"HKCU\{AC76BA86-1033-FFFF-7760-BC15014EA700}");
        let chrome = lus.iter().find(|p| p.nom == "Google Chrome").unwrap();
        assert_eq!(chrome.emplacement, None, "valeur trop longue oubliée");
    }

    /// Une clé Uninstall remplie de milliers de clés vides, pour cacher un programme derrière la borne : la borne
    /// atteinte est dite (`Laisses::coupees`), jamais tue.
    #[test]
    fn cle_coupee_dite() {
        let chemin = format!(r"Software\VanguardTest-coupee-{}\Uninstall", std::process::id());
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let Ok((cle, _)) = hkcu.create_subkey(&chemin) else {
            return crate::essais::saute("registre inaccessible");
        };
        for i in 0..=SOUS_CLES_MAX {
            if cle.create_subkey(format!("{i:05}")).is_err() {
                let _ = hkcu.delete_subkey_all(format!(r"Software\VanguardTest-coupee-{}", std::process::id()));
                return crate::essais::saute("registre : clés non créées");
            }
        }
        let mut laisses = Laisses::default();
        let lus = programmes_de(&cle, "HKCU", KEY_WOW64_64KEY, &Portee::CompteCourant, &mut laisses);
        let _ = hkcu.delete_subkey_all(format!(r"Software\VanguardTest-coupee-{}", std::process::id()));
        assert_eq!(lus, Vec::<Programme>::new());
        assert_eq!(laisses.coupees, [(Portee::CompteCourant, "HKCU".to_string())]);
    }
}

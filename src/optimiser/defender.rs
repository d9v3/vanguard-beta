//! Protections de Microsoft Defender qui bloquent elles-mêmes les attaques : règles de réduction de la surface
//! d'attaque (ASR), protection réseau, applications potentiellement indésirables, accès contrôlé aux dossiers.
//! Vanguard ne bloque rien lui-même : il active, après accord, ce que Windows applique depuis son noyau et protège
//! contre la désactivation. Ce sont des protections : Vanguard ne les défait pas (`systeme::reglage_protege`), la
//! personne peut les changer dans Windows.
//!
//! Écartées, parce qu'elles bloqueraient Vanguard ou l'administration de la machine : processus non signés lancés
//! depuis une clé USB (Vanguard sur la clé), exécutables sans réputation suffisante et protection avancée contre les
//! rançongiciels (un programme neuf et non signé comme Vanguard), PsExec et WMI, outils système copiés (heuristique),
//! scripts brouillés, redémarrage en mode sans échec (dépannage), et celle des serveurs Exchange.
//!
//! Lues par Get-MpPreference, la seule source qui dit ce que Defender applique : son registre n'est pas lisible par
//! la personne. Une lecture par session, refaite après chaque écriture.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::ui::*;

/// Une préférence de Defender réglée par Vanguard.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pref {
    DossiersControles,
    ProtectionReseau,
    Pua,
    /// Règle ASR, par son identifiant (en minuscules, comme Microsoft l'écrit).
    Asr(&'static str),
}

/// Règles ASR que Microsoft dit sans revers (« standard protection rules »).
pub const ASR_BASE: [&str; 3] = [
    "56a863a9-875e-4185-98a7-b882c64b5ce5",
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
    "e6db77e5-3df2-4cf1-b95a-636979351e5b",
];

/// Règles ASR contre les documents et pièces jointes piégés : Office, Outlook, Adobe Reader, courriel, scripts.
pub const ASR_BUREAUTIQUE: [&str; 8] = [
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
    "3b576869-a4ec-4529-8536-b80a7769e899",
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",
    "26190899-1602-49e8-8b27-eb1d0a1ce869",
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
    "d3e037e1-3eb8-44c8-a917-57927947596d",
];

/// Ce que bloque une règle ASR, pour l'écran.
fn nom_asr(id: &str) -> &'static str {
    match id {
        "56a863a9-875e-4185-98a7-b882c64b5ce5" => {
            tr!("pilotes signés mais vulnérables", "vulnerable signed drivers")
        }
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" => {
            tr!("vol de mots de passe dans LSASS", "credential theft from LSASS")
        }
        "e6db77e5-3df2-4cf1-b95a-636979351e5b" => tr!("persistance par WMI", "persistence through WMI"),
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a" => {
            tr!("Office qui lance des programmes", "Office launching programs")
        }
        "3b576869-a4ec-4529-8536-b80a7769e899" => {
            tr!("Office qui crée des exécutables", "Office creating executables")
        }
        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" => tr!("Office qui injecte du code", "Office injecting code"),
        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" => {
            tr!("macros Office qui appellent Win32", "Office macros calling Win32")
        }
        "26190899-1602-49e8-8b27-eb1d0a1ce869" => {
            tr!("Outlook qui lance des programmes", "Outlook launching programs")
        }
        "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" => {
            tr!(
                "Adobe Reader qui lance des programmes",
                "Adobe Reader launching programs"
            )
        }
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" => {
            tr!("exécutables reçus par courriel", "executables from email")
        }
        "d3e037e1-3eb8-44c8-a917-57927947596d" => {
            tr!(
                "scripts JS/VBS qui lancent un téléchargement",
                "JS/VBS launching downloads"
            )
        }
        _ => "?",
    }
}

/// Ce que Defender applique, tel que Get-MpPreference le dit.
#[derive(Default, Debug, PartialEq)]
pub struct Etat {
    /// Defender a répondu (WMI ou PowerShell) : sans réponse, `actif` faux ne veut rien dire, et le bilan le dit non
    /// vérifié au lieu de le croire coupé.
    pub lu: bool,
    /// Defender est l'antivirus actif (ni coupé, ni en mode passif derrière un autre antivirus).
    pub actif: bool,
    /// La protection en temps réel : sans elle, aucun blocage (ASR, protection réseau, PUA, dossiers) ne s'applique,
    /// même réglé. `None` : pas dit (valeur vide), le jugement ne s'en sert pas.
    pub temps_reel: Option<bool>,
    /// « cfa », « np », « pua », ou l'identifiant d'une règle ASR → sa valeur.
    valeurs: HashMap<String, u32>,
    /// Dossiers ajoutés à ceux que l'accès contrôlé protège d'office ; illisibles (réservés aux administrateurs sur
    /// certains Windows) : aucun.
    ajoutes: Vec<String>,
}

const SCRIPT: &str = "$s = Get-MpComputerStatus; $p = Get-MpPreference; \
    \"mode|$($s.AMRunningMode)\"; \"av|$($s.AntivirusEnabled)\"; \
    \"rtp|$($s.RealTimeProtectionEnabled)\"; \
    \"cfa|$([int]$p.EnableControlledFolderAccess)\"; \"np|$([int]$p.EnableNetworkProtection)\"; \
    \"pua|$([int]$p.PUAProtection)\"; \
    $ids = @($p.AttackSurfaceReductionRules_Ids); $act = @($p.AttackSurfaceReductionRules_Actions); \
    for ($i = 0; $i -lt $ids.Count; $i++) { if ($ids[$i]) { \"asr|$($ids[$i])|$([int]$act[$i])\" } }; \
    foreach ($d in @($p.ControlledFolderAccessProtectedFolders)) { if ($d) { \"protege|$d\" } }";

/// La sortie de `SCRIPT`, une valeur par ligne.
pub fn lire_sortie(texte: &str) -> Etat {
    let mut e = Etat::default();
    let (mut mode, mut antivirus) = (String::new(), false);
    for ligne in texte.lines() {
        let mut champs = ligne.trim().splitn(3, '|');
        match (champs.next(), champs.next(), champs.next()) {
            (Some("mode"), Some(m), _) => {
                mode = m.trim().to_string();
                e.lu = true;
            }
            (Some("av"), Some(a), _) => {
                antivirus = a.trim().eq_ignore_ascii_case("true");
                e.lu = true;
            }
            (Some("rtp"), Some(r), _) => {
                let r = r.trim();
                if r.eq_ignore_ascii_case("true") {
                    e.temps_reel = Some(true);
                } else if r.eq_ignore_ascii_case("false") {
                    e.temps_reel = Some(false);
                }
            }
            (Some(cle @ ("cfa" | "np" | "pua")), Some(n), _) => {
                if let Ok(n) = n.trim().parse() {
                    e.valeurs.insert(cle.to_string(), n);
                }
            }
            (Some("asr"), Some(id), Some(n)) => {
                if let Ok(n) = n.trim().parse() {
                    e.valeurs.insert(id.trim().to_lowercase(), n);
                }
            }
            // « N/A: Must be an administrator to view… » : la liste n'est pas lisible ici.
            (Some("protege"), Some(chemin), _) if !chemin.starts_with("N/A") => {
                e.ajoutes.push(chemin.trim().to_string());
            }
            _ => {}
        }
    }
    // AMRunningMode manque sur les Windows 10 d'avant 2004 : l'antivirus allumé suffit alors.
    e.actif = mode == "Normal" || (mode.is_empty() && antivirus);
    e
}

/// Les lignes de `SCRIPT`, lues par WMI (les classes de Get-MpComputerStatus et Get-MpPreference) ; `None` si l'une
/// des deux ne répond pas, comme le script qui s'arrête à la première erreur.
#[cfg(windows)]
fn sortie_wmi() -> Option<String> {
    use crate::machine::windows::wmi::{self, Valeur};
    const DEFENDER: &str = r"root\Microsoft\Windows\Defender";
    let s = wmi::requete(
        DEFENDER,
        "MSFT_MpComputerStatus",
        "",
        &["AMRunningMode", "AntivirusEnabled", "RealTimeProtectionEnabled"],
    )?
    .into_iter()
    .next()?;
    let p = wmi::requete(
        DEFENDER,
        "MSFT_MpPreference",
        "",
        &[
            "EnableControlledFolderAccess",
            "EnableNetworkProtection",
            "PUAProtection",
            "AttackSurfaceReductionRules_Ids",
            "AttackSurfaceReductionRules_Actions",
            "ControlledFolderAccessProtectedFolders",
        ],
    )?
    .into_iter()
    .next()?;
    // Comme `[int]$null` : une valeur absente vaut 0 ; un booléen comme PowerShell l'écrit.
    let entier = |v: &Valeur| v.entier().unwrap_or(0);
    let booleen = |v: &Valeur| match v {
        Valeur::Booleen(true) => "True",
        Valeur::Booleen(false) => "False",
        _ => "",
    };
    let mut lignes = vec![
        format!("mode|{}", s["AMRunningMode"].texte().unwrap_or_default()),
        format!("av|{}", booleen(&s["AntivirusEnabled"])),
        format!("rtp|{}", booleen(&s["RealTimeProtectionEnabled"])),
        format!("cfa|{}", entier(&p["EnableControlledFolderAccess"])),
        format!("np|{}", entier(&p["EnableNetworkProtection"])),
        format!("pua|{}", entier(&p["PUAProtection"])),
    ];
    let actions = p["AttackSurfaceReductionRules_Actions"].liste();
    for (i, id) in p["AttackSurfaceReductionRules_Ids"].liste().iter().enumerate() {
        if let Some(id) = id.texte().filter(|id| !id.is_empty()) {
            lignes.push(format!("asr|{id}|{}", actions.get(i).map_or(0, entier)));
        }
    }
    for d in p["ControlledFolderAccessProtectedFolders"].liste() {
        if let Some(d) = d.texte().filter(|d| !d.is_empty()) {
            lignes.push(format!("protege|{d}"));
        }
    }
    Some(lignes.join("\n"))
}

static ETAT: Mutex<Option<Arc<Etat>>> = Mutex::new(None);

/// L'état de Defender, lu une fois puis gardé jusqu'à la prochaine écriture. PowerShell muet : Defender inactif.
pub fn etat() -> Arc<Etat> {
    let mut garde = ETAT.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    garde
        .get_or_insert_with(|| {
            // WMI d'abord, PowerShell en secours.
            Arc::new(
                sortie_wmi()
                    .or_else(|| crate::machine::windows::ps(SCRIPT))
                    .map_or_else(Etat::default, |t| lire_sortie(&t)),
            )
        })
        .clone()
}

/// Après une écriture : la prochaine lecture redemande à Defender.
pub fn oublier() {
    *ETAT.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = None;
}

/// Le nom court d'une préférence, celui des notes (« defender|np ») et de `SCRIPT`.
pub(crate) fn cle(pref: Pref) -> &'static str {
    match pref {
        Pref::DossiersControles => "cfa",
        Pref::ProtectionReseau => "np",
        Pref::Pua => "pua",
        Pref::Asr(id) => id,
    }
}

/// La préférence d'un nom court ; `None` hors de ce que Vanguard règle (une note qui viserait une autre règle ASR ne
/// vient pas de lui).
pub(crate) fn pref_de(cle: &str) -> Option<Pref> {
    match cle {
        "cfa" => Some(Pref::DossiersControles),
        "np" => Some(Pref::ProtectionReseau),
        "pua" => Some(Pref::Pua),
        _ => ASR_BASE
            .iter()
            .chain(&ASR_BUREAUTIQUE)
            .find(|id| **id == cle)
            .map(|id| Pref::Asr(id)),
    }
}

impl Etat {
    /// La valeur d'une préférence (« mp:1 ») ; `None` pour une règle ASR jamais réglée.
    pub fn valeur(&self, pref: Pref) -> Option<String> {
        self.valeurs.get(cle(pref)).map(|n| format!("mp:{n}"))
    }

    pub fn dossiers_ajoutes(&self) -> &[String] {
        &self.ajoutes
    }
}

fn nombre(v: Option<&str>) -> Option<u32> {
    v?.strip_prefix("mp:")?.parse().ok()
}

/// La commande de la fenêtre administrateur qui remet la préférence à `v`.
pub fn commande(pref: Pref, v: Option<&str>) -> Option<String> {
    let parametre = match pref {
        // Add-MpPreference ajoute ou change une seule règle ; Set-MpPreference remplacerait toute la liste.
        Pref::Asr(id) => {
            return Some(match v {
                None => format!("Remove-MpPreference -AttackSurfaceReductionRules_Ids '{id}'"),
                Some(_) => format!(
                    "Add-MpPreference -AttackSurfaceReductionRules_Ids '{id}' -AttackSurfaceReductionRules_Actions {}",
                    nombre(v)?
                ),
            });
        }
        Pref::DossiersControles => "EnableControlledFolderAccess",
        Pref::ProtectionReseau => "EnableNetworkProtection",
        Pref::Pua => "PUAProtection",
    };
    // Sans valeur notée : celle d'un Windows neuf, coupée.
    Some(format!("Set-MpPreference -{parametre} {}", nombre(v).unwrap_or(0)))
}

/// Ce qui est écrit, en clair : « Defender, protection réseau : bloque ».
pub fn decrire(pref: Pref, v: Option<&str>) -> String {
    let quoi = match pref {
        Pref::DossiersControles => tr!("accès contrôlé aux dossiers", "controlled folder access").to_string(),
        Pref::ProtectionReseau => tr!("protection réseau", "network protection").to_string(),
        Pref::Pua => tr!("applications indésirables (PUA)", "potentially unwanted apps (PUA)").to_string(),
        Pref::Asr(id) => trf!("règle « {} »", "rule “{}”", nom_asr(id)),
    };
    let mode = match nombre(v) {
        None => tr!("non réglée", "not configured").to_string(),
        Some(0) => tr!("coupée", "off").to_string(),
        Some(1) => tr!("bloque", "blocks").to_string(),
        Some(2) => tr!("audit (signale sans bloquer)", "audit (reports, does not block)").to_string(),
        Some(6) => tr!("avertit", "warns").to_string(),
        Some(n) => trf!("mode {n}", "mode {n}"),
    };
    trf!("Defender, {quoi} : {mode}", "Defender, {quoi}: {mode}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sortie_lue() {
        let e = lire_sortie(
            "mode|Normal\nav|True\ncfa|0\nnp|1\npua|2\n\
             asr|9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2|1\nasr|d4f940ab-401b-4efc-aadc-ad5f3c50688a|2\n\
             protege|D:\\Photos\n",
        );
        assert!(e.actif && e.lu);
        // Pas de ligne « rtp » : on ne sait pas, rien n'est supposé.
        assert_eq!(e.temps_reel, None);
        assert_eq!(lire_sortie("rtp|False\n").temps_reel, Some(false));
        assert_eq!(lire_sortie("rtp|True\n").temps_reel, Some(true));
        assert_eq!(lire_sortie("rtp|\n").temps_reel, None);
        assert_eq!(e.valeur(Pref::DossiersControles).as_deref(), Some("mp:0"));
        assert_eq!(e.valeur(Pref::ProtectionReseau).as_deref(), Some("mp:1"));
        assert_eq!(e.valeur(Pref::Pua).as_deref(), Some("mp:2"));
        // Identifiant en majuscules chez Windows, en minuscules chez Vanguard.
        assert_eq!(e.valeur(Pref::Asr(ASR_BASE[1])).as_deref(), Some("mp:1"));
        assert_eq!(e.valeur(Pref::Asr(ASR_BASE[0])), None);
        assert_eq!(e.dossiers_ajoutes(), ["D:\\Photos"]);
    }

    #[test]
    fn defender_passif_ou_illisible() {
        // Un autre antivirus : Defender passe en mode passif, ses blocages ne s'appliquent pas.
        assert!(!lire_sortie("mode|Passive Mode\nav|True\n").actif);
        assert!(!lire_sortie("").actif && !lire_sortie("").lu);
        assert!(lire_sortie("mode|Passive Mode\nav|True\n").lu);
        // Windows 10 d'avant 2004 : pas d'AMRunningMode.
        assert!(lire_sortie("mode|\nav|True\n").actif);
        let e = lire_sortie("mode|Normal\nprotege|N/A: Must be an administrator to view protected folders\n");
        assert_eq!(e.dossiers_ajoutes(), Vec::<String>::new());
    }

    #[test]
    fn commandes() {
        let r = Pref::Asr(ASR_BASE[0]);
        assert_eq!(
            commande(r, Some("mp:1")).unwrap(),
            "Add-MpPreference -AttackSurfaceReductionRules_Ids '56a863a9-875e-4185-98a7-b882c64b5ce5' -AttackSurfaceReductionRules_Actions 1"
        );
        // Jamais réglée avant : retirée à l'annulation, pas mise à « coupée ».
        assert_eq!(
            commande(r, None).unwrap(),
            "Remove-MpPreference -AttackSurfaceReductionRules_Ids '56a863a9-875e-4185-98a7-b882c64b5ce5'"
        );
        assert_eq!(commande(r, Some("mp:x")), None);
        assert_eq!(
            commande(Pref::DossiersControles, Some("mp:1")).unwrap(),
            "Set-MpPreference -EnableControlledFolderAccess 1"
        );
        assert_eq!(commande(Pref::Pua, None).unwrap(), "Set-MpPreference -PUAProtection 0");
    }

    /// Les noms courts des notes : ceux que Vanguard règle, et rien d'autre.
    #[test]
    fn noms_courts_aller_retour() {
        for pref in [
            Pref::DossiersControles,
            Pref::ProtectionReseau,
            Pref::Pua,
            Pref::Asr(ASR_BASE[2]),
        ] {
            assert_eq!(pref_de(cle(pref)), Some(pref));
        }
        assert_eq!(pref_de("b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"), None);
        assert_eq!(pref_de(""), None);
    }

    #[test]
    fn regles_connues_et_sans_celles_qui_bloqueraient_vanguard() {
        for id in ASR_BASE.iter().chain(&ASR_BUREAUTIQUE) {
            assert_ne!(nom_asr(id), "?", "{id}");
            assert_eq!(*id, id.to_lowercase());
        }
        for interdite in [
            "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",
            "01443614-cd74-433a-b99e-2ecdc07bfc25",
            "c1db55ab-c21a-4637-bb3f-a12568109d35",
            "d1e49aac-8f56-4280-b9ba-993a6d77406c",
            "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb",
            "5beb7efe-fd9a-4556-801d-275e5ffc04cc",
            "33ddedf1-c6e0-47cb-833e-de6133960387",
        ] {
            assert!(!ASR_BASE.contains(&interdite) && !ASR_BUREAUTIQUE.contains(&interdite));
        }
    }
}

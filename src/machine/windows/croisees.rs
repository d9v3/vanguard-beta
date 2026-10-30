//! Les lectures croisées de Windows (`autotest::croisees`) : ce que Vanguard lit par le registre, WMI ou les fonctions
//! de Windows, comparé aux applets PowerShell qui disent la même chose, lus en JSON (jamais le texte traduit de la
//! console). Sous Wine, sans PowerShell, chacune se dit sautée. BitLocker se lit par une classe WMI réservée à
//! l'administrateur : sans droits, sautée (droits), essayée en administrateur dans la VM (test.ps1).

use crate::autotest::croisees::{self, Comparaison, croisee};
use crate::machine::regles::Os;
use crate::modele::Raison;
use crate::tr;

/// Un booléen de ConvertTo-Json : vrai booléen, nombre (énumération GpoBoolean du pare-feu : 1 vrai, 0 faux) ou
/// texte (« True »).
fn booleen(v: &serde_json::Value) -> Option<bool> {
    match v {
        serde_json::Value::Bool(b) => Some(*b),
        serde_json::Value::Number(n) => match n.as_u64()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        },
        serde_json::Value::String(t) => match t.to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn oui_non(b: Option<bool>) -> String {
    b.map_or_else(|| "illisible".into(), |b| if b { "oui" } else { "non" }.into())
}

croisee!(
    "AUT-WIN-001",
    Os::Windows,
    ("profils du pare-feu", "firewall profiles"),
    "Get-NetFirewallProfile",
    &["WIN-PFE-001"],
    pare_feu
);

pub(super) fn pare_feu() -> Comparaison {
    let outil = match croisees::powershell(
        "Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,Enabled | ConvertTo-Json",
    ) {
        Ok(v) => v,
        Err(r) => return Comparaison::Saute(r),
    };
    comparer_pare_feu(&super::profils_pare_feu(), &outil)
}

fn comparer_pare_feu(natif: &[(&str, bool)], outil: &[serde_json::Value]) -> Comparaison {
    if outil.is_empty() {
        return Comparaison::inattendue();
    }
    croisees::comparer(
        natif.iter().map(|(n, a)| ((*n).to_string(), oui_non(Some(*a)))),
        outil.iter().map(|p| {
            (
                p["Name"].as_str().unwrap_or("?").to_string(),
                oui_non(booleen(&p["Enabled"])),
            )
        }),
    )
}

croisee!(
    "AUT-WIN-002",
    Os::Windows,
    ("état de Microsoft Defender", "Microsoft Defender state"),
    "Get-MpComputerStatus",
    &["WIN-ANV-001"],
    defender
);

const CHAMPS_DEFENDER: [&str; 3] = ["AntivirusEnabled", "RealTimeProtectionEnabled", "IsTamperProtected"];

pub(super) fn defender() -> Comparaison {
    trancher_defender(
        super::defender_par_wmi(),
        croisees::powershell(
            "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,IsTamperProtected | ConvertTo-Json",
        ),
    )
}

/// Deux lectures ratées ne disent pas « sans objet » : un délai, un refus (AppLocker, mode de langage restreint)
/// ou une lecture WMI cassée, justement ce que la lecture croisée doit attraper, passeraient pour sains.
fn trancher_defender(natif: Option<serde_json::Value>, outil: Result<Vec<serde_json::Value>, Raison>) -> Comparaison {
    let outil = match outil {
        Ok(v) => v,
        Err(r) => return Comparaison::Saute(r),
    };
    let (Some(natif), Some(outil)) = (natif, outil.first()) else {
        return Comparaison::inattendue();
    };
    comparer_defender(&natif, outil)
}

fn comparer_defender(natif: &serde_json::Value, outil: &serde_json::Value) -> Comparaison {
    croisees::comparer(
        CHAMPS_DEFENDER
            .iter()
            .map(|c| ((*c).to_string(), oui_non(booleen(&natif[*c])))),
        CHAMPS_DEFENDER
            .iter()
            .map(|c| ((*c).to_string(), oui_non(booleen(&outil[*c])))),
    )
}

croisee!(
    "AUT-WIN-003",
    Os::Windows,
    ("protection BitLocker de C:", "BitLocker protection of C:"),
    "manage-bde (Win32_EncryptableVolume)",
    &["WIN-CHF-001"],
    bitlocker
);

pub(super) fn bitlocker() -> Comparaison {
    let natif = super::protection_bitlocker();
    // Le JSON d'abord : sans droits, la classe refuse avant de rien dire (pas d'UAC demandée pour un autotest).
    if !super::processus::eleve() {
        return Comparaison::Saute(Raison::Droits);
    }
    let outil = match croisees::powershell(
        "Get-CimInstance -Namespace root/cimv2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume -Filter \"DriveLetter='C:'\" | Select-Object ProtectionStatus | ConvertTo-Json",
    ) {
        Ok(v) => v,
        Err(r) => return Comparaison::Saute(r),
    };
    comparer_bitlocker(
        natif.as_deref(),
        outil.first().and_then(|v| v["ProtectionStatus"].as_u64()),
    )
}

/// System.Volume.BitLockerProtection (1 et 6 : protégé ; 2, 5 et 8 : non) contre ProtectionStatus (1 : protégé,
/// 0 : non). Un chiffrement en cours (3, 4) ou un état inconnu (2 de ProtectionStatus) ne se compare pas.
fn comparer_bitlocker(natif: Option<&str>, outil: Option<u64>) -> Comparaison {
    let natif = match natif.map(str::trim) {
        Some("1" | "6") => true,
        Some("2" | "5" | "8") => false,
        Some("") if outil.is_none() => {
            return Comparaison::SansObjet(
                tr!("BitLocker absent de ce Windows", "no BitLocker on this Windows").into(),
            );
        }
        // Rien (et non un texte vide) : la lecture directe a raté, ce n'est pas un BitLocker absent.
        None => {
            return Comparaison::Saute(Raison::Illisible(
                tr!("lecture directe de BitLocker ratée", "direct BitLocker read failed").into(),
            ));
        }
        _ => {
            return Comparaison::Saute(Raison::Illisible(
                tr!("état intermédiaire de BitLocker", "intermediate BitLocker state").into(),
            ));
        }
    };
    let outil = match outil {
        Some(1) => true,
        Some(0) => false,
        _ => return Comparaison::inattendue(),
    };
    Comparaison::une_valeur("C: protégé", &oui_non(Some(natif)), &oui_non(Some(outil)))
}

croisee!(
    "AUT-WIN-004",
    Os::Windows,
    ("comptes locaux", "local accounts"),
    "Get-LocalUser",
    &["WIN-CPT-001"],
    comptes
);

pub(super) fn comptes() -> Comparaison {
    let natif = super::comptes_locaux();
    // Get-LocalUser n'existe pas dans le PowerShell 32 bits d'un Windows 64 bits : Vanguard est un programme 64 bits,
    // qui lance celui de System32 (le 64 bits).
    let outil =
        match croisees::powershell("Get-LocalUser | Select-Object Enabled,PasswordRequired,SID | ConvertTo-Json") {
            Ok(v) => v,
            Err(r) => return Comparaison::Saute(r),
        };
    let Some(usr) = crate::commande::section(natif.as_deref(), "USR") else {
        return Comparaison::Different {
            en_plus: Vec::new(),
            en_moins: Vec::new(),
            differents: Vec::new(),
            genre: croisees::Ecart::ChampIllisible,
        };
    };
    comparer_comptes(&usr, &outil)
}

/// Les comptes par SID (le nom se renomme) : actif, mot de passe exigé.
fn comparer_comptes(usr: &[&str], outil: &[serde_json::Value]) -> Comparaison {
    let natif = usr.iter().filter_map(|l| {
        let c: Vec<&str> = l.trim().splitn(4, '|').collect();
        let [actif, exige, sid, _] = c[..] else { return None };
        Some((
            sid.to_uppercase(),
            format!("{} {}", actif.to_ascii_lowercase(), exige.to_ascii_lowercase()),
        ))
    });
    let outil = outil.iter().filter_map(|u| {
        Some((
            // Le SID en objet ({"Value": "S-1-5-…", …}) sous PowerShell 5.1, en texte ailleurs.
            u.get("SID")
                .and_then(|s| s.get("Value"))
                .and_then(serde_json::Value::as_str)
                .or_else(|| u.get("SID").and_then(serde_json::Value::as_str))?
                .to_uppercase(),
            format!("{} {}", booleen(&u["Enabled"])?, booleen(&u["PasswordRequired"])?),
        ))
    });
    croisees::comparer(natif, outil)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Les comparaisons sur des JSON inventés, comme ConvertTo-Json les écrit (Windows PowerShell 5.1).
    #[test]
    fn comparaisons_sur_du_json_invente() {
        let pf: Vec<serde_json::Value> = croisees::json_en_liste(
            r#"[{"Name":"Domain","Enabled":1},{"Name":"Private","Enabled":1},{"Name":"Public","Enabled":0}]"#,
        )
        .unwrap();
        assert_eq!(
            comparer_pare_feu(&[("Domain", true), ("Private", true), ("Public", false)], &pf),
            Comparaison::Pareil { n: 3 }
        );
        assert!(matches!(
            comparer_pare_feu(&[("Domain", true), ("Private", true), ("Public", true)], &pf),
            Comparaison::Different { .. }
        ));
        let d = serde_json::json!({"AntivirusEnabled": true, "RealTimeProtectionEnabled": true, "IsTamperProtected": false});
        assert_eq!(comparer_defender(&d, &d), Comparaison::Pareil { n: 3 });
        assert_eq!(comparer_bitlocker(Some("1"), Some(1)), Comparaison::Pareil { n: 1 });
        assert!(matches!(
            comparer_bitlocker(Some("5"), Some(1)),
            Comparaison::Different { .. }
        ));
        assert!(matches!(comparer_bitlocker(Some("3"), Some(0)), Comparaison::Saute(_)));
        assert!(matches!(comparer_bitlocker(Some(""), None), Comparaison::SansObjet(_)));
        assert!(matches!(comparer_bitlocker(None, None), Comparaison::Saute(_)));
        assert!(matches!(comparer_bitlocker(None, Some(1)), Comparaison::Saute(_)));
        // Ni WMI ni l'applet : non vérifié, jamais « sans objet ».
        assert!(matches!(
            trancher_defender(None, Err(Raison::Delai)),
            Comparaison::Saute(Raison::Delai)
        ));
        let usr = [
            "True|True|S-1-5-21-1-1-1-1001|alice",
            "False|False|S-1-5-21-1-1-1-501|Invité",
        ];
        let lu = croisees::json_en_liste(
            r#"[{"Enabled":true,"PasswordRequired":true,"SID":{"BinaryLength":28,"Value":"S-1-5-21-1-1-1-1001"}},{"Enabled":false,"PasswordRequired":false,"SID":"S-1-5-21-1-1-1-501"}]"#,
        )
        .unwrap();
        assert_eq!(comparer_comptes(&usr, &lu), Comparaison::Pareil { n: 2 });
        assert!(matches!(
            comparer_comptes(&usr[..1], &lu),
            Comparaison::Different { .. }
        ));
    }

    /// Sous Wine, sans PowerShell : chaque lecture croisée se dit sautée (BitLocker peut se dire absent), jamais
    /// « pareil » ni un écart.
    #[test]
    fn sous_wine_tout_est_saute() {
        if !crate::journal::sous_wine() {
            return crate::essais::saute("pas sous Wine");
        }
        for f in [pare_feu, defender, comptes] {
            assert!(matches!(f(), Comparaison::Saute(_)));
        }
        // Seul « BitLocker absent » peut se dire sans objet.
        assert!(matches!(bitlocker(), Comparaison::Saute(_) | Comparaison::SansObjet(_)));
    }
}

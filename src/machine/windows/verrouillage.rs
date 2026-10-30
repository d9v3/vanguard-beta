//! Verrouillage de l'écran sous Windows. Trois voies verrouillent après inactivité : le délai d'inactivité de la
//! machine (stratégie InactivityTimeoutSecs), l'écran de veille avec mot de passe, et la mise en veille quand Windows
//! redemande la connexion au réveil. La plus courte compte ; aucune, l'écran ne se verrouille jamais.

use super::super::{Constat, impossible};
use super::registre;
use crate::ui::tr;

pub(super) fn verrouillage() -> Constat {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    // Lu sans PowerShell : le registre directement, et powercfg, un programme ordinaire.
    let texte = |racine, cle: &str, valeur: &str| registre::<String>(racine, cle, valeur).unwrap_or_default();
    let ecran = |racine, cle: &str| {
        ["ScreenSaveActive", "ScreenSaverIsSecure", "ScreenSaveTimeOut"]
            .map(|v| texte(racine, cle, v))
            .join("|")
    };
    let powercfg = |sous_groupe: &str, reglage: &str| {
        crate::commande::lancer(
            crate::commande::systeme("powercfg").args(["/q", "SCHEME_CURRENT", sous_groupe, reglage]),
            15,
        )
        .filter(|r| r.code == Some(0))
        .map(|r| r.sortie.split_whitespace().collect::<Vec<_>>().join(" "))
    };
    let (Some(veille), Some(connexion)) = (
        powercfg("SUB_SLEEP", "STANDBYIDLE"),
        powercfg("SUB_NONE", "CONSOLELOCK"),
    ) else {
        // Sans powercfg, on ne sait rien de la veille : ne pas conclure « jamais verrouillé ».
        return impossible(
            "Verrouillage",
            tr!("powercfg ne répond pas", "powercfg does not answer"),
        );
    };
    let inactif = registre::<u32>(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "InactivityTimeoutSecs",
    )
    .map(|s| s.to_string())
    .unwrap_or_default();
    let sortie = format!(
        "INACTIF|{inactif}\nECRAN|{}\nECRAN_STRATEGIE|{}\nVEILLE|{veille}\nCONNEXION|{connexion}\n",
        ecran(HKEY_CURRENT_USER, r"Control Panel\Desktop"),
        ecran(
            HKEY_CURRENT_USER,
            r"Software\Policies\Microsoft\Windows\Control Panel\Desktop"
        ),
    );
    super::super::verrouillage_selon_delai(
        delai(&sortie),
        tr!(
            "Paramètres > Comptes > Options de connexion : demander la connexion au réveil ; et Paramètres > Système > Alimentation : mise en veille après 10 minutes (ou un écran de veille avec « À la reprise, afficher l'écran de connexion »)",
            "Settings > Accounts > Sign-in options: require sign-in on wake; and Settings > System > Power: sleep after 10 minutes (or a screen saver with “On resume, display logon screen”)"
        ),
    )
}

/// Le délai de verrouillage en secondes, 0 si rien ne verrouille, d'après la sortie du script.
pub(super) fn delai(sortie: &str) -> u64 {
    let champ = |nom: &str| {
        sortie
            .lines()
            .find_map(|l| l.strip_prefix(nom)?.strip_prefix('|'))
            .map(str::trim)
    };
    let mut delais = Vec::new();
    // Délai d'inactivité de la machine.
    if let Some(s) = champ("INACTIF").and_then(|v| v.parse::<u64>().ok()).filter(|&s| s > 0) {
        delais.push(s);
    }
    // Écran de veille : la stratégie passe avant le réglage du compte, valeur par valeur.
    let ecran: Vec<&str> = champ("ECRAN").map(|v| v.split('|').collect()).unwrap_or_default();
    let strategie: Vec<&str> = champ("ECRAN_STRATEGIE")
        .map(|v| v.split('|').collect())
        .unwrap_or_default();
    let valeur = |i: usize| {
        strategie
            .get(i)
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .or_else(|| ecran.get(i).map(|v| v.trim()))
            .unwrap_or_default()
    };
    if valeur(0) == "1"
        && valeur(1) == "1"
        && let Some(s) = valeur(2).parse::<u64>().ok().filter(|&s| s > 0)
    {
        delais.push(s);
    }
    // Mise en veille sur secteur (le cas le moins sûr), quand Windows redemande la connexion au réveil (le réglage
    // d'origine si powercfg ne répond pas).
    let secteur = |nom: &str| champ(nom).and_then(index_secteur);
    let connexion_au_reveil = secteur("CONNEXION").is_none_or(|v| v != 0);
    if connexion_au_reveil && let Some(s) = secteur("VEILLE").filter(|&s| s > 0) {
        delais.push(s);
    }
    delais.into_iter().min().unwrap_or(0)
}

/// Valeur sur secteur d'un réglage de `powercfg /q` : l'avant-dernière valeur hexadécimale (la dernière est celle
/// sur batterie). Les libellés changent avec la langue de Windows, pas les valeurs.
fn index_secteur(sortie: &str) -> Option<u64> {
    let valeurs: Vec<u64> = sortie
        .split_whitespace()
        .filter_map(|m| m.strip_prefix("0x"))
        .filter_map(|h| u64::from_str_radix(h, 16).ok())
        .collect();
    valeurs.len().checked_sub(2).and_then(|i| valeurs.get(i)).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    const VEILLE_30_MIN: &str = "VEILLE|Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)   Subgroup GUID: 238c9fa8-0aad-41ed-83f4-97be242c8f20  (Sleep)     Power Setting GUID: 29f6c1db-86da-48c5-9fdb-f2b67b1f44da  (Sleep after)       Minimum Possible Setting: 0x00000000       Maximum Possible Setting: 0xffffffff       Possible Settings increment: 0x00000001       Possible Settings units: Seconds     Current AC Power Setting Index: 0x00000708     Current DC Power Setting Index: 0x00000384";

    #[test]
    fn la_voie_la_plus_courte() {
        // Veille après 30 min sur secteur, connexion redemandée (ou powercfg muet : le réglage d'origine).
        assert_eq!(delai(VEILLE_30_MIN), 1800);
        let connexion = "CONNEXION|Minimum Possible Setting: 0x00000000 Maximum Possible Setting: 0x00000001 Current AC Power Setting Index: 0x00000001 Current DC Power Setting Index: 0x00000001";
        assert_eq!(delai(&format!("{VEILLE_30_MIN}\n{connexion}")), 1800);
        // Connexion pas redemandée au réveil : la veille ne verrouille pas.
        let sans_connexion = connexion.replace(
            "AC Power Setting Index: 0x00000001",
            "AC Power Setting Index: 0x00000000",
        );
        assert_eq!(delai(&format!("{VEILLE_30_MIN}\n{sans_connexion}")), 0);
        // Écran de veille protégé après 5 min : plus court que la veille.
        assert_eq!(delai(&format!("ECRAN|1|1|300\n{VEILLE_30_MIN}")), 300);
        // Écran de veille sans mot de passe : ne compte pas.
        assert_eq!(delai("ECRAN|1|0|300"), 0);
        // La stratégie passe avant le compte, valeur par valeur.
        assert_eq!(delai("ECRAN|1|0|300\nECRAN_STRATEGIE||1|"), 300);
        assert_eq!(delai("ECRAN|1|1|300\nECRAN_STRATEGIE|0||"), 0);
        // Délai d'inactivité de la machine.
        assert_eq!(delai("INACTIF|600\nECRAN|1|1|900"), 600);
        assert_eq!(delai("INACTIF|\nECRAN||||\nVEILLE|0x0 0x0 0x0 0x0 0x0"), 0);
        assert_eq!(delai(""), 0);
    }

    #[test]
    fn valeurs_de_powercfg() {
        assert_eq!(index_secteur(VEILLE_30_MIN), Some(1800));
        assert_eq!(index_secteur("0x5"), None);
        assert_eq!(index_secteur("rien"), None);
    }
}

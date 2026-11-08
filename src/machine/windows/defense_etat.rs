//! Ce que lit l'écran « Options de défense » (`crate::options_defense`), en lecture seule : Microsoft Defender par
//! WMI natif (`MSFT_MpComputerStatus`, `MSFT_MpPreference`, sans PowerShell ni `Get-MpPreference`), le Pare-feu
//! Windows par INetFwPolicy2, le Centre de sécurité (`root\SecurityCenter2`), les stratégies et la gestion du PC par
//! le registre. Rien n'y est écrit. Chaque lecture qui échoue reste `None` : l'écran la dit non vérifiée.

use std::io::ErrorKind;
use std::time::Duration;

use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};

use windows::Win32::Foundation::{VARIANT_BOOL, VARIANT_FALSE, VARIANT_TRUE};
use windows::Win32::NetworkManagement::WindowsFirewall::{NET_FW_ACTION_BLOCK, NET_FW_PROFILE_TYPE2};

use super::wmi::{self, Ligne, Valeur};
use crate::compte_rendu::Contexte;
use crate::options_defense::{
    self as od, Asr, Centre, Compte, Edition, Etat, Gestion, ModeDefender, Opt, PareFeu, Preferences, Produit, Profil,
    SourceFalsif, Statut, Strategies,
};

const DEFENDER: &str = r"root\Microsoft\Windows\Defender";
const CENTRE: &str = r"root\SecurityCenter2";

/// Le mode de Defender et sa protection en temps réel, seuls : une requête WMI, pour l'analyse antivirus (place du
/// moteur de Vanguard, P19), sans lire tout l'écran. Illisible : `(Illisible, None)`, jamais « allumé ».
pub(crate) fn defender_en_marche() -> (ModeDefender, Option<bool>) {
    wmi::requete(DEFENDER, "MSFT_MpComputerStatus", "", &CHAMPS_STATUT)
        .and_then(|l| l.first().map(statut))
        .map_or((ModeDefender::Illisible, None), |s| (s.mode, s.temps_reel))
}

/// Tout lire, dans cet ordre ; chaque partie à part, une panne n'emporte pas les autres.
pub(crate) fn lire() -> Etat {
    Etat {
        statut: wmi::requete(DEFENDER, "MSFT_MpComputerStatus", "", &CHAMPS_STATUT).and_then(|l| l.first().map(statut)),
        preferences: wmi::requete(DEFENDER, "MSFT_MpPreference", "", &champs_preferences())
            .and_then(|l| l.first().map(preferences)),
        strategies: strategies(),
        pare_feu: pare_feu(),
        centre: Centre {
            antivirus: produits("AntiVirusProduct"),
            pare_feu: produits("FirewallProduct"),
        },
        gestion: gestion(),
        edition: lire_texte(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "EditionID").map(|e| Edition::depuis(&e)),
    }
}

const CHAMPS_STATUT: [&str; 5] = [
    "AMRunningMode",
    "AntivirusEnabled",
    "RealTimeProtectionEnabled",
    "IsTamperProtected",
    "TamperProtectionSource",
];

fn champs_preferences() -> Vec<&'static str> {
    let mut c: Vec<&str> = Opt::TOUTES.iter().map(|o| o.champ()).collect();
    c.extend([
        "AttackSurfaceReductionRules_Ids",
        "AttackSurfaceReductionRules_Actions",
        "ExclusionPath",
        "ExclusionProcess",
        "ExclusionExtension",
        "ControlledFolderAccessAllowedApplications",
    ]);
    c
}

/// Un champ d'une instance ; un champ manquant (version de Windows plus ancienne, ligne de test) est nul.
fn champ<'a>(l: &'a Ligne, nom: &str) -> &'a Valeur {
    l.get(nom).unwrap_or(&Valeur::Nul)
}

/// Un booléen de WMI ; un entier 0 ou 1 se relit aussi, rien d'autre n'est supposé.
fn booleen(v: &Valeur) -> Option<bool> {
    match v {
        Valeur::Booleen(b) => Some(*b),
        v => match v.entier() {
            Some(0) => Some(false),
            Some(1) => Some(true),
            _ => None,
        },
    }
}

/// Un nombre d'option : les `Disable…` sont des booléens, rangés en 1 (coupée) ou 0.
fn nombre(v: &Valeur) -> Option<i64> {
    match v {
        Valeur::Booleen(b) => Some(i64::from(*b)),
        v => v.entier(),
    }
}

fn statut(l: &Ligne) -> Statut {
    Statut {
        mode: ModeDefender::depuis(champ(l, "AMRunningMode").texte(), booleen(champ(l, "AntivirusEnabled"))),
        temps_reel: booleen(champ(l, "RealTimeProtectionEnabled")),
        falsifications: booleen(champ(l, "IsTamperProtected")),
        source: champ(l, "TamperProtectionSource")
            .texte()
            .and_then(SourceFalsif::depuis),
    }
}

fn preferences(l: &Ligne) -> Preferences {
    let valeurs = Opt::TOUTES.map(|o| nombre(champ(l, o.champ())));
    let actions: Vec<Option<i64>> = match champ(l, "AttackSurfaceReductionRules_Actions") {
        Valeur::Liste(a) => a.iter().map(Valeur::entier).collect(),
        Valeur::Nul => Vec::new(),
        v => vec![v.entier()],
    };
    let compte = |c: &str| Compte::depuis(&champ(l, c).textes());
    Preferences {
        valeurs,
        asr: Asr::depuis(&champ(l, "AttackSurfaceReductionRules_Ids").textes(), &actions),
        exclusions: [
            compte("ExclusionPath"),
            compte("ExclusionProcess"),
            compte("ExclusionExtension"),
        ],
        applis_permises: compte("ControlledFolderAccessAllowedApplications"),
    }
}

/// Une clé de HKLM ouverte en lecture : `Ok(None)` si elle n'existe pas, `Err` si elle ne se lit pas (droits).
fn ouvrir(cle: &str) -> Result<Option<RegKey>, ()> {
    match RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(cle, KEY_READ) {
        Ok(k) => Ok(Some(k)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(_) => Err(()),
    }
}

/// La valeur existe-t-elle ? `None` si on ne peut pas le savoir.
fn presente(cle: &str, valeur: &str) -> Option<bool> {
    let Some(k) = ouvrir(cle).ok()? else { return Some(false) };
    match k.get_raw_value(valeur) {
        Ok(_) => Some(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Some(false),
        Err(_) => None,
    }
}

/// Les noms des valeurs d'une clé (vide si elle n'existe pas).
fn noms_de_valeurs(cle: &str) -> Option<Vec<String>> {
    let Some(k) = ouvrir(cle).ok()? else {
        return Some(Vec::new());
    };
    k.enum_values().map(|v| v.map(|(nom, _)| nom).ok()).collect()
}

fn sous_cles(cle: &str) -> Option<Vec<String>> {
    let Some(k) = ouvrir(cle).ok()? else {
        return Some(Vec::new());
    };
    k.enum_keys().map(Result::ok).collect()
}

fn lire_texte(cle: &str, valeur: &str) -> Option<String> {
    ouvrir(cle).ok()??.get_value(valeur).ok()
}

fn strategies() -> Strategies {
    let options = Opt::TOUTES.map(|o| od::une_presente(od::strategies_de(o).iter().map(|(c, v)| presente(c, v))));
    let gpo_asr = noms_de_valeurs(od::GPO_ASR);
    let mdm_asr = match ouvrir(od::MDM_ASR.0) {
        Ok(None) => Some(Vec::new()),
        Ok(Some(k)) => match k.get_value::<String, _>(od::MDM_ASR.1) {
            Ok(s) => Some(od::asr_de_mdm(&s)),
            Err(e) if e.kind() == ErrorKind::NotFound => Some(Vec::new()),
            Err(_) => None,
        },
        Err(()) => None,
    };
    let asr = match (gpo_asr, mdm_asr) {
        (Some(g), Some(mut m)) => {
            m.extend(g.iter().filter_map(|n| od::asr_connue(n)));
            m.sort_unstable();
            m.dedup();
            Some(m)
        }
        _ => None,
    };
    let exclusions = od::une_presente(
        od::GPO_EXCLUSIONS
            .iter()
            .map(|c| noms_de_valeurs(c).map(|v| !v.is_empty()))
            .chain(od::MDM_EXCLUSIONS.iter().map(|(c, v)| presente(c, v))),
    );
    let pare_feu = od::GPO_PARE_FEU.map(|cles| {
        od::une_presente(
            cles.iter()
                .flat_map(|c| od::VALEURS_PARE_FEU.iter().map(move |v| presente(c, v))),
        )
    });
    Strategies {
        options,
        asr,
        exclusions,
        pare_feu,
    }
}

fn vrai_faux(v: VARIANT_BOOL) -> Option<bool> {
    if v == VARIANT_TRUE {
        Some(true)
    } else if v == VARIANT_FALSE {
        Some(false)
    } else {
        None
    }
}

/// INetFwPolicy2, ce que le pare-feu applique (une stratégie passe avant le réglage local). Chaque lecture à part :
/// une propriété refusée laisse les autres.
// FFI de COM (crate windows) : lectures de INetFwPolicy2.
#[allow(unsafe_code)]
fn pare_feu() -> Option<PareFeu> {
    wmi::com_delai(
        Contexte::PareFeuWindows,
        "INetFwPolicy2 (lecture des profils)",
        Duration::from_secs(30),
        || {
            let p = super::pare_feu::politique()?;
            let mut lu = PareFeu::default();
            // SAFETY: objet COM valide, créé dans ce fil ; chaque lecture rend une copie, et une erreur est défaite
            // ici (`ok()`), dans son appartement.
            unsafe {
                lu.courants = p.CurrentProfileTypes().ok();
                lu.profils = [1, 2, 4].map(|bit| {
                    let profil = NET_FW_PROFILE_TYPE2(bit);
                    Profil {
                        actif: p.get_FirewallEnabled(profil).ok().and_then(vrai_faux),
                        entrees_bloquees: p
                            .get_DefaultInboundAction(profil)
                            .ok()
                            .map(|a| a == NET_FW_ACTION_BLOCK),
                        sorties_bloquees: p
                            .get_DefaultOutboundAction(profil)
                            .ok()
                            .map(|a| a == NET_FW_ACTION_BLOCK),
                        tout_bloquer: p.get_BlockAllInboundTraffic(profil).ok().and_then(vrai_faux),
                    }
                });
                lu.modification = p.LocalPolicyModifyState().ok().map(|m| m.0);
                lu.regles = p.Rules().and_then(|r| r.Count()).ok();
            }
            Ok(lu)
        },
    )
}

/// Les produits inscrits au Centre de sécurité ; `None` sans lui (Windows Server, Wine).
fn produits(classe: &str) -> Option<Vec<Produit>> {
    let lignes = wmi::requete(
        CENTRE,
        classe,
        "",
        &["displayName", "productState", "pathToSignedProductExe"],
    )?;
    Some(lignes.iter().map(produit).collect())
}

fn produit(l: &Ligne) -> Produit {
    Produit::depuis(
        champ(l, "displayName").texte(),
        champ(l, "productState").entier(),
        champ(l, "pathToSignedProductExe").texte(),
    )
}

/// Le PC est-il sûrement hors domaine (local et Entra) et hors gestion (MDM) ? Une lecture qui manque vaut « géré
/// peut-être » : une stratégie n'est alors que montrée (plan §3.3).
pub(crate) fn hors_gestion() -> bool {
    gestion().geree() == Some(false)
}

fn gestion() -> Gestion {
    let domaine = wmi::requete(r"root\cimv2", "Win32_ComputerSystem", "", &["PartOfDomain"])
        .and_then(|l| l.first().and_then(|c| booleen(champ(c, "PartOfDomain"))));
    let entra = sous_cles(r"SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo").map(|s| !s.is_empty());
    let mdm = sous_cles(r"SOFTWARE\Microsoft\Enrollments").and_then(|ids| {
        let mut lues = true;
        for id in ids {
            match ouvrir(&format!(r"SOFTWARE\Microsoft\Enrollments\{id}")) {
                Ok(Some(k)) => {
                    let fournisseur: Option<String> = k.get_value("ProviderID").ok();
                    let etat: Option<u32> = k.get_value("EnrollmentState").ok();
                    if od::inscription_active(fournisseur.as_deref(), etat) {
                        return Some(true);
                    }
                }
                Ok(None) => {}
                Err(()) => lues = false,
            }
        }
        lues.then_some(false)
    });
    Gestion { domaine, entra, mdm }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ligne(champs: &[(&str, Valeur)]) -> Ligne {
        champs.iter().map(|(k, v)| ((*k).to_string(), v.clone())).collect()
    }

    fn textes(t: &[&str]) -> Valeur {
        Valeur::Liste(t.iter().map(|s| Valeur::Texte((*s).to_string())).collect())
    }

    #[test]
    fn statut_lu_dans_une_ligne() {
        let s = statut(&ligne(&[
            ("AMRunningMode", Valeur::Texte("Passive Mode".into())),
            ("AntivirusEnabled", Valeur::Booleen(true)),
            ("RealTimeProtectionEnabled", Valeur::Booleen(false)),
            ("IsTamperProtected", Valeur::Booleen(true)),
            ("TamperProtectionSource", Valeur::Texte("Intune".into())),
        ]));
        assert_eq!(s.mode, ModeDefender::Passif);
        assert_eq!(s.temps_reel, Some(false));
        assert_eq!(s.falsifications, Some(true));
        assert_eq!(s.source, Some(SourceFalsif::Organisation));
        // Une ligne vide (classe d'une version plus ancienne) : rien n'est supposé.
        let vide = statut(&Ligne::new());
        assert_eq!(vide.mode, ModeDefender::Illisible);
        assert_eq!(vide.falsifications, None);
    }

    #[test]
    fn preferences_lues_dans_une_ligne() {
        let p = preferences(&ligne(&[
            ("DisableRealtimeMonitoring", Valeur::Booleen(false)),
            ("MAPSReporting", Valeur::Entier(2)),
            ("SubmitSamplesConsent", Valeur::Texte("1".into())),
            ("DisableBlockAtFirstSeen", Valeur::Booleen(true)),
            (
                "AttackSurfaceReductionRules_Ids",
                textes(&["D4F940AB-401B-4EFC-AADC-AD5F3C50688A", "inconnue"]),
            ),
            (
                "AttackSurfaceReductionRules_Actions",
                Valeur::Liste(vec![Valeur::Entier(6), Valeur::Entier(1)]),
            ),
            ("ExclusionPath", textes(&["C:\\Jeux"])),
            (
                "ExclusionProcess",
                Valeur::Texte("N/A: Must be an administrator to view exclusions".into()),
            ),
        ]));
        assert_eq!(p.valeurs[0], Some(0));
        assert_eq!(p.valeurs[1], Some(2));
        assert_eq!(p.valeurs[2], Some(1));
        assert_eq!(p.valeurs[3], None);
        assert_eq!(p.valeurs[9], Some(1));
        assert_eq!(
            p.asr.regles,
            vec![("d4f940ab-401b-4efc-aadc-ad5f3c50688a", od::ActionAsr::Avertit)]
        );
        assert_eq!(p.asr.inconnues, 1);
        assert_eq!(p.exclusions, [Compte::Nombre(1), Compte::Masque, Compte::Nombre(0)]);
    }

    #[test]
    fn produits_du_centre() {
        let p = produit(&ligne(&[
            ("displayName", Valeur::Texte("Windows Defender".into())),
            ("productState", Valeur::Entier(397_568)),
            ("pathToSignedProductExe", Valeur::Texte("windowsdefender://".into())),
        ]));
        assert!(p.microsoft);
        assert_eq!(p.actif, Some(true));
        assert_eq!(booleen(&Valeur::Texte("oui".into())), None);
        assert_eq!(vrai_faux(VARIANT_BOOL(5)), None);
    }

    /// Le vrai appel, sous Wine ou Windows : il ne plante pas et ne prétend rien quand rien ne répond.
    #[test]
    fn lecture_reelle_sans_planter() {
        let e = lire();
        if e.statut.is_none() {
            assert_eq!(od::json(&e)["defender"]["mode"], "illisible");
        }
        assert_ne!(od::lignes(&e).len(), 0);
    }
}

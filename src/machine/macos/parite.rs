//! Ce que Linux et Windows vérifiaient déjà et que le Mac n'avait pas : la règle des mots de passe et le blocage
//! après des échecs (pwpolicy, comme LNX-CPT-002 et WIN-CPT-002), la sécurité du démarrage (Apple silicon par
//! bputil, puce T2 par sa variable de démarrage, comme LNX-DEM-001 et WIN-DEM-001), et la persistance au-delà de
//! launchd : les éléments d'ouverture et de fond (BTM, ce que les voleurs d'informations pour Mac posent), les
//! crochets de connexion et les extensions d'autorisation. SIP, Gatekeeper, FileVault et les profils de
//! configuration ont déjà leurs règles (MAC-SYS-001, MAC-CHF-001, MAC-PRF-001).
//!
//! Rien de tout cela ne se corrige seul : chaque alerte dit où le faire. Vérifié par clippy pour les cibles Mac et
//! par les tests sur des sorties inventées ; le Mac de GitHub les rejoue, aucun vrai Mac ne les a encore vues.

use std::path::Path;

use super::{Constat, alerte, ok, sortie};
use crate::machine::{impossible_par, sans_objet};
use crate::modele::{Absence, Objet, Raison};
use crate::risk::Niveau;
use crate::ui::{affichable, resume};
use crate::{tr, trf};

const CPT: &str = "Comptes";
const DEM: &str = "Démarrage";
const PRS: &str = "Persistance";

/// Le nombre entier qui suit `<key>cle</key>` dans un plist XML (« <integer>10</integer> »).
fn entier_apres_cle(xml: &str, cle: &str) -> Option<u64> {
    let apres = &xml[xml.find(&format!("<key>{cle}</key>"))? + cle.len() + 11..];
    let debut = apres.trim_start().strip_prefix("<integer>")?;
    debut[..debut.find('<')?].trim().parse().ok()
}

/// La longueur minimale d'une règle « policyAttributePassword matches '.{8,}+' », ou du paramètre minimumLength.
fn longueur_minimale(xml: &str) -> Option<u64> {
    entier_apres_cle(xml, "minimumLength").or_else(|| {
        let i = xml.find("matches '.{")? + "matches '.{".len();
        let reste = &xml[i..];
        reste[..reste.find([',', '}'])?].parse().ok()
    })
}

/// MAC-CPT-002, d'après la sortie de `pwpolicy -getaccountpolicies` (une ligne d'annonce, puis le plist XML).
pub(super) fn juger_politique(sortie: Option<&str>) -> Vec<Constat> {
    let Some(texte) = sortie else {
        return vec![impossible_par(
            CPT,
            Raison::Illisible("pwpolicy -getaccountpolicies".into()),
            tr!(
                "Impossible de vérifier la règle des mots de passe du Mac (pwpolicy n'a pas répondu).",
                "Could not check the Mac's password policy (pwpolicy did not answer)."
            ),
        )];
    };
    let blocage = entier_apres_cle(texte, "policyAttributeMaximumFailedAuthentications").filter(|n| *n > 0);
    let longueur = longueur_minimale(texte);
    let mut constats = Vec::new();
    match blocage {
        Some(n) if n <= 10 => {}
        Some(n) => constats.push(alerte(
            CPT,
            Niveau::Info,
            trf!(
                "Le compte se bloque après {n} mots de passe faux : 10 au plus serait plus sûr.",
                "The account locks after {n} wrong passwords: 10 at most would be safer."
            ),
        )),
        None => constats.push(
            alerte(
                CPT,
                Niveau::Info,
                tr!(
                    "Aucun blocage du compte après des mots de passe faux : macOS ralentit les essais, mais ne bloque jamais.",
                    "No account lockout after wrong passwords: macOS slows the attempts down, but never locks."
                ),
            )
            .avec_objet(Objet::de("politique", "blocage"))
            .manuel(
                tr!(
                    "Par un profil de configuration (Code d'accès : nombre maximal de tentatives), ou dans le Terminal : sudo pwpolicy -setaccountpolicies",
                    "With a configuration profile (Passcode: maximum number of failed attempts), or in Terminal: sudo pwpolicy -setaccountpolicies"
                ),
                &[],
            ),
        ),
    }
    if longueur.is_none_or(|n| n < 8) {
        constats.push(
            alerte(
                CPT,
                Niveau::Info,
                match longueur {
                    Some(n) => trf!(
                        "Les mots de passe des comptes peuvent n'avoir que {n} caractères : 12 au moins serait plus sûr.",
                        "Account passwords may have only {n} characters: 12 at least would be safer."
                    ),
                    None => tr!(
                        "Aucune longueur minimale imposée aux mots de passe des comptes du Mac.",
                        "No minimum length imposed on the Mac's account passwords."
                    )
                    .to_string(),
                },
            )
            .avec_objet(Objet::de("politique", "longueur")),
        );
    }
    if constats.is_empty() {
        constats.push(ok(
            CPT,
            trf!(
                "Règle des mots de passe en place : blocage après {} échecs, {} caractères au moins.",
                "Password policy in place: lockout after {} failures, {} characters at least.",
                blocage.unwrap_or_default(),
                longueur.unwrap_or_default()
            ),
        ));
    }
    constats
}

pub(super) fn politique_mots_de_passe() -> Vec<Constat> {
    juger_politique(sortie("pwpolicy", &["-getaccountpolicies"]).as_deref())
}

/// Ce que dit le démarrage sécurisé.
#[derive(Debug, PartialEq)]
pub(super) enum Demarrage {
    /// Apple silicon : la ligne « Security Mode » de `bputil -d` (réservé à root, sinon `None`).
    AppleSilicon(Option<String>),
    /// Puce T2 : la valeur de AppleSecureBootPolicy (« %02 » complète) ; `None` : variable absente, pas de T2.
    Intel(Option<String>),
}

/// MAC-DEM-001.
pub(super) fn juger_demarrage(d: &Demarrage, root: bool) -> Constat {
    let reduit = |niveau, texte: String| {
        alerte(DEM, niveau, texte).manuel(
            tr!(
                "Redémarrer en mode de récupération › Utilitaires › Utilitaire Sécurité au démarrage, choisir « Sécurité complète »",
                "Restart into Recovery › Utilities › Startup Security Utility, choose “Full Security”"
            ),
            &[],
        )
    };
    match d {
        Demarrage::AppleSilicon(None) => impossible_par(
            DEM,
            if root {
                Raison::Illisible("bputil -d".into())
            } else {
                Raison::Droits
            },
            tr!(
                "Impossible de vérifier la sécurité du démarrage (bputil -d se lit en administrateur : sudo vanguard machine).",
                "Could not check startup security (bputil -d is read as administrator: sudo vanguard machine)."
            ),
        ),
        Demarrage::AppleSilicon(Some(mode)) => {
            let m = mode.to_lowercase();
            if m.contains("full") {
                ok(DEM, tr!("Sécurité complète au démarrage.", "Full startup security."))
            } else if m.contains("permissive") {
                reduit(
                    Niveau::Eleve,
                    tr!(
                        "Sécurité du démarrage « permissive » : n'importe quel système, même non signé, peut démarrer ce Mac.",
                        "“Permissive” startup security: any system, even unsigned, can boot this Mac."
                    )
                    .to_string(),
                )
            } else if m.contains("reduced") {
                reduit(
                    Niveau::Moyen,
                    tr!(
                        "Sécurité du démarrage réduite : des versions anciennes de macOS ou des extensions du noyau de tiers peuvent se charger.",
                        "Reduced startup security: old macOS versions or third-party kernel extensions can load."
                    )
                    .to_string(),
                )
            } else {
                impossible_par(
                    DEM,
                    Raison::Illisible(affichable(mode)),
                    trf!(
                        "Impossible de vérifier la sécurité du démarrage (mode inconnu : {}).",
                        "Could not check startup security (unknown mode: {}).",
                        affichable(mode)
                    ),
                )
            }
        }
        Demarrage::Intel(None) => sans_objet(
            DEM,
            Absence::Plateforme,
            tr!(
                "Mac Intel sans puce T2 : pas de démarrage sécurisé à régler.",
                "Intel Mac without a T2 chip: no secure boot to set."
            ),
        ),
        Demarrage::Intel(Some(v)) => match v.trim() {
            "%02" => ok(DEM, tr!("Sécurité complète au démarrage (puce T2).", "Full startup security (T2 chip).")),
            "%01" => reduit(
                Niveau::Info,
                tr!(
                    "Sécurité moyenne au démarrage (puce T2) : des versions de macOS qu'Apple ne signe plus peuvent démarrer.",
                    "Medium startup security (T2 chip): macOS versions Apple no longer signs can boot."
                )
                .to_string(),
            ),
            "%00" => reduit(
                Niveau::Moyen,
                tr!(
                    "Aucune sécurité au démarrage (puce T2) : n'importe quel système peut démarrer ce Mac.",
                    "No startup security (T2 chip): any system can boot this Mac."
                )
                .to_string(),
            ),
            autre => impossible_par(
                DEM,
                Raison::Illisible(affichable(autre)),
                trf!(
                    "Impossible de vérifier la sécurité du démarrage (valeur inconnue : {}).",
                    "Could not check startup security (unknown value: {}).",
                    affichable(autre)
                ),
            ),
        },
    }
}

/// La ligne « Security Mode: Full » de `bputil -d`.
fn mode_bputil(texte: &str) -> Option<String> {
    texte.lines().find_map(|l| {
        let (cle, valeur) = l.split_once(':')?;
        cle.trim()
            .eq_ignore_ascii_case("security mode")
            .then(|| valeur.trim().to_string())
    })
}

pub(super) fn demarrage_securise() -> Constat {
    let root = crate::traces::privilegie();
    let d = if cfg!(target_arch = "aarch64") {
        Demarrage::AppleSilicon(sortie("bputil", &["-d"]).and_then(|t| mode_bputil(&t)))
    } else {
        // « 94b7…:AppleSecureBootPolicy	%02 » ; nvram sort en erreur si la variable manque (pas de T2).
        Demarrage::Intel(
            sortie("nvram", &["94b73556-2197-4702-82a8-3e1337dafbfb:AppleSecureBootPolicy"])
                .and_then(|t| t.split_whitespace().last().map(str::to_string)),
        )
    };
    juger_demarrage(&d, root)
}

/// Un élément de `sfltool dumpbtm`.
#[derive(Debug, Default, PartialEq)]
pub(super) struct ElementBtm {
    pub nom: String,
    pub developpeur: String,
    pub programme: String,
    pub actif: bool,
}

/// Les éléments de `sfltool dumpbtm` : un bloc par « #N: », des lignes « Clé: valeur » ; `None` si ce n'est pas sa
/// sortie (aucun « Records for UID »).
pub(super) fn lire_btm(texte: &str) -> Option<Vec<ElementBtm>> {
    if !texte.contains("Records for UID") {
        return None;
    }
    let mut elements: Vec<ElementBtm> = Vec::new();
    for ligne in texte.lines() {
        let l = ligne.trim();
        if l.starts_with('#') && l.ends_with(':') {
            elements.push(ElementBtm::default());
            continue;
        }
        let (Some(e), Some((cle, valeur))) = (elements.last_mut(), l.split_once(':')) else {
            continue;
        };
        let valeur = valeur.trim();
        match cle.trim() {
            "Name" => e.nom = valeur.to_string(),
            "Developer Name" => e.developpeur = valeur.to_string(),
            "Executable Path" => e.programme = valeur.to_string(),
            "Disposition" => e.actif = valeur.contains("enabled") && !valeur.contains("disabled"),
            _ => {}
        }
    }
    Some(elements)
}

/// MAC-PRS-002 : `None` sans les droits de root (la base ne se lit qu'ainsi).
pub(super) fn juger_btm(sortie: Option<&str>, root: bool) -> Vec<Constat> {
    let Some(elements) = sortie.and_then(lire_btm) else {
        return vec![impossible_par(
            PRS,
            if root {
                Raison::Illisible("sfltool dumpbtm".into())
            } else {
                Raison::Droits
            },
            tr!(
                "Impossible de vérifier les éléments d'ouverture et de fond (sfltool dumpbtm se lit en administrateur : sudo vanguard machine).",
                "Could not check login and background items (sfltool dumpbtm is read as administrator: sudo vanguard machine)."
            ),
        )];
    };
    let mut constats = Vec::new();
    let actifs: Vec<&ElementBtm> = elements.iter().filter(|e| e.actif).collect();
    for e in &actifs {
        if let Some(pourquoi) = super::persistance::soupcon(&e.programme, "") {
            constats.push(
                alerte(
                    PRS,
                    Niveau::Eleve,
                    trf!(
                        "Élément d'ouverture « {} » {} : {}.",
                        "Login item “{}” {}: {}.",
                        affichable(&e.nom),
                        pourquoi,
                        affichable(&e.programme)
                    ),
                )
                .avec_objet(Objet::fichier(&e.programme))
                .manuel(
                    tr!(
                        "Réglages Système › Général › Ouverture et extensions : le désactiver s'il n'est pas à vous, puis lancer l'antivirus",
                        "System Settings › General › Login Items & Extensions: turn it off if it is not yours, then run the antivirus"
                    ),
                    &[],
                ),
            );
        }
    }
    let inconnus: Vec<String> = actifs
        .iter()
        .filter(|e| e.developpeur.is_empty() || e.developpeur.eq_ignore_ascii_case("unknown developer"))
        .map(|e| affichable(if e.nom.is_empty() { &e.programme } else { &e.nom }))
        .collect();
    if !inconnus.is_empty() {
        constats.push(
            alerte(
                PRS,
                Niveau::Info,
                trf!(
                    "Éléments d'ouverture sans développeur identifié : {}. À reconnaître : un voleur d'informations pour Mac s'installe souvent ainsi.",
                    "Login items without an identified developer: {}. To recognize: a Mac information stealer often installs this way.",
                    resume(&inconnus, 6, ", ")
                ),
            )
            .avec_objet(Objet::de("btm-inconnus", &inconnus.join(","))),
        );
    }
    if constats.is_empty() {
        constats.push(ok(
            PRS,
            trf!(
                "Éléments d'ouverture et de fond : {} actifs, aucun suspect.",
                "Login and background items: {} enabled, none suspicious.",
                actifs.len()
            ),
        ));
    }
    constats
}

pub(super) fn elements_d_ouverture() -> Vec<Constat> {
    let root = crate::traces::privilegie();
    let texte = root
        .then(|| {
            crate::commande::lancer(std::process::Command::new("sfltool").arg("dumpbtm"), 30)
                .filter(|r| r.code == Some(0))
                .map(|r| r.sortie)
        })
        .flatten();
    juger_btm(texte.as_deref(), root)
}

/// MAC-PRS-003 : les crochets LoginHook et LogoutHook (lancés en root à chaque connexion), les extensions
/// d'autorisation de tiers (chargées par l'écran de connexion, elles voient le mot de passe tapé) et les vieux
/// StartupItems. `hooks` : (crochet, script) ; `extensions` et `demarrage` : les noms trouvés, `None` si le dossier
/// ne se lit pas.
pub(super) fn juger_crochets(
    hooks: &[(String, String)],
    extensions: Option<&[String]>,
    demarrage: Option<&[String]>,
    illisibles: &[(&str, Raison)],
) -> Vec<Constat> {
    let mut constats = Vec::new();
    // Un fichier de réglages qui ne se lit pas peut cacher un crochet : non vérifié, dit, jamais « aucun crochet ».
    for (chemin, raison) in illisibles {
        let message = if *raison == Raison::Droits {
            trf!(
                "Impossible de vérifier le crochet de connexion : {chemin} se lit en administrateur (sudo vanguard machine).",
                "Could not check the login hook: {chemin} is read as administrator (sudo vanguard machine)."
            )
        } else {
            trf!(
                "Impossible de vérifier le crochet de connexion : {chemin} ne se lit pas.",
                "Could not check the login hook: {chemin} cannot be read."
            )
        };
        constats.push(impossible_par(PRS, raison.clone(), message));
    }
    for (crochet, script) in hooks {
        constats.push(
            alerte(
                PRS,
                Niveau::Moyen,
                trf!(
                    "Crochet de connexion {} : « {} » se lance en root à chaque ouverture de session. Apple l'a abandonné ; un logiciel malveillant s'en sert encore.",
                    "Login hook {}: “{}” runs as root at every sign-in. Apple deprecated it; malware still uses it.",
                    affichable(crochet),
                    affichable(script)
                ),
            )
            .avec_objet(Objet::fichier(script))
            .manuel(
                trf!(
                    "S'il n'est pas à vous : sudo defaults delete com.apple.loginwindow {}",
                    "If it is not yours: sudo defaults delete com.apple.loginwindow {}",
                    affichable(crochet)
                ),
                &[],
            ),
        );
    }
    for (dossier, noms, quoi) in [
        (
            "/Library/Security/SecurityAgentPlugins",
            extensions,
            tr!(
                "extensions d'autorisation (elles voient le mot de passe tapé à l'écran de connexion)",
                "authorization plugins (they see the password typed at the sign-in screen)"
            ),
        ),
        (
            "/Library/StartupItems",
            demarrage,
            tr!(
                "éléments de démarrage anciens (lancés en root)",
                "old startup items (run as root)"
            ),
        ),
    ] {
        match noms {
            None => constats.push(impossible_par(
                PRS,
                Raison::Illisible(dossier.into()),
                trf!(
                    "Impossible de vérifier les {quoi} : {dossier} ne se lit pas.",
                    "Could not check the {quoi}: {dossier} cannot be read."
                ),
            )),
            Some([]) => {}
            Some(noms) => {
                let liste: Vec<String> = noms.iter().map(|n| affichable(n)).collect();
                constats.push(
                    alerte(
                        PRS,
                        Niveau::Moyen,
                        trf!(
                            "{} de tiers dans {dossier} : {}. À reconnaître (un outil d'entreprise en pose parfois).",
                            "Third-party {} in {dossier}: {}. To recognize (a company tool sometimes adds some).",
                            quoi,
                            resume(&liste, 6, ", ")
                        ),
                    )
                    .avec_objet(Objet::de("dossier", &format!("{dossier}#{}", noms.join(","))))
                    .manuel(
                        trf!(
                            "S'il n'est pas à vous : le mettre à la corbeille depuis {dossier} (mot de passe administrateur), puis redémarrer",
                            "If it is not yours: move it to the Trash from {dossier} (administrator password), then restart"
                        ),
                        &[],
                    ),
                );
            }
        }
    }
    if constats.is_empty() {
        constats.push(ok(
            PRS,
            tr!(
                "Aucun crochet de connexion, aucune extension d'autorisation ni élément de démarrage ancien de tiers.",
                "No login hook, no third-party authorization plugin or old startup item."
            ),
        ));
    }
    constats
}

/// Les noms d'un dossier (sans les fichiers cachés) ; vide s'il n'existe pas, `None` s'il ne se lit pas.
fn noms_dans(dossier: &Path) -> Option<Vec<String>> {
    match std::fs::read_dir(dossier) {
        Ok(e) => Some(
            e.flatten()
                .take(500)
                .map(|f| f.file_name().to_string_lossy().into_owned())
                .filter(|n| !n.starts_with('.'))
                .collect(),
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(Vec::new()),
        Err(_) => None,
    }
}

/// Les réglages de root, où « sudo defaults write com.apple.loginwindow LoginHook » écrit.
const ROOT_PREFS: &str = "/private/var/root/Library/Preferences/com.apple.loginwindow.plist";

pub(super) fn crochets_et_extensions() -> Vec<Constat> {
    let (mut hooks, mut illisibles) = (Vec::new(), Vec::new());
    // Celui de la machine se lit par tous ; celui de root (où « sudo defaults write » l'écrit) en root seulement.
    for prefs in ["/Library/Preferences/com.apple.loginwindow.plist", ROOT_PREFS] {
        let v = match crate::plist::lire_fichier(Path::new(prefs)) {
            Ok(crate::plist::Lu::Plist(v)) => v,
            // Pas de fichier : pas de crochet.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied && !crate::traces::privilegie() => {
                illisibles.push((prefs, Raison::Droits));
                continue;
            }
            // Refusé autrement, trop gros, fabriqué pour gêner l'analyse ou abîmé : peut-être exprès.
            Err(_) | Ok(_) => {
                illisibles.push((prefs, Raison::Illisible(prefs.into())));
                continue;
            }
        };
        for crochet in ["LoginHook", "LogoutHook"] {
            if let Some(script) = v
                .cle(crochet)
                .and_then(crate::plist::Valeur::texte)
                .filter(|s| !s.trim().is_empty())
            {
                hooks.push((crochet.to_string(), script.to_string()));
            }
        }
    }
    hooks.sort();
    hooks.dedup();
    let extensions = noms_dans(Path::new("/Library/Security/SecurityAgentPlugins"));
    let demarrage = noms_dans(Path::new("/Library/StartupItems"));
    juger_crochets(&hooks, extensions.as_deref(), demarrage.as_deref(), &illisibles)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modele::Etat;

    const AVEC_POLITIQUE: &str = "Getting global account policies\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n<dict>\n\t<key>policyCategoryAuthentication</key>\n\t<array>\n\t\t<dict>\n\t\t\t<key>policyContent</key>\n\t\t\t<string>(policyAttributeFailedAuthentications &lt; policyAttributeMaximumFailedAuthentications)</string>\n\t\t\t<key>policyParameters</key>\n\t\t\t<dict>\n\t\t\t\t<key>policyAttributeMaximumFailedAuthentications</key>\n\t\t\t\t<integer>10</integer>\n\t\t\t</dict>\n\t\t</dict>\n\t</array>\n\t<key>policyCategoryPasswordContent</key>\n\t<array>\n\t\t<dict>\n\t\t\t<key>policyContent</key>\n\t\t\t<string>policyAttributePassword matches '.{12,}+'</string>\n\t\t</dict>\n\t</array>\n</dict>\n</plist>\n";

    #[test]
    fn politique_des_mots_de_passe() {
        let c = juger_politique(Some(AVEC_POLITIQUE));
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].etat(), Etat::Sain);
        assert!(c[0].message.contains("10") && c[0].message.contains("12"));
        // Un Mac neuf : aucune règle.
        let vide =
            "Getting global account policies\n<?xml version=\"1.0\"?>\n<plist version=\"1.0\">\n<dict/>\n</plist>\n";
        let c = juger_politique(Some(vide));
        assert_eq!(c.len(), 2);
        assert!(c.iter().all(|c| c.probleme == Some(Niveau::Info) && c.coherent()));
        assert_eq!(
            longueur_minimale("<key>minimumLength</key>\n<integer>6</integer>"),
            Some(6)
        );
        assert!(matches!(
            juger_politique(None)[0].etat(),
            Etat::NonVerifie(Raison::Illisible(_))
        ));
    }

    #[test]
    fn securite_du_demarrage() {
        let probleme = |d: Demarrage| juger_demarrage(&d, true).probleme;
        assert_eq!(probleme(Demarrage::AppleSilicon(Some("Full".into()))), None);
        assert_eq!(
            probleme(Demarrage::AppleSilicon(Some("Reduced Security".into()))),
            Some(Niveau::Moyen)
        );
        assert_eq!(
            probleme(Demarrage::AppleSilicon(Some("Permissive".into()))),
            Some(Niveau::Eleve)
        );
        assert_eq!(probleme(Demarrage::Intel(Some("%02".into()))), None);
        assert_eq!(probleme(Demarrage::Intel(Some("%00".into()))), Some(Niveau::Moyen));
        assert_eq!(
            juger_demarrage(&Demarrage::Intel(None), false).etat(),
            Etat::SansObjet(Absence::Plateforme)
        );
        assert_eq!(
            juger_demarrage(&Demarrage::AppleSilicon(None), false).etat(),
            Etat::NonVerifie(Raison::Droits)
        );
        assert_eq!(
            mode_bputil("Local policy:\n  Security Mode: Full (smb0: absent)\n").as_deref(),
            Some("Full (smb0: absent)")
        );
    }

    const BTM: &str = "========================\n Records for UID 501 : 0A1B\n========================\n\n Items:\n\n #1:\n                 UUID: 1\n                 Name: Sauvegarde\n       Developer Name: Exemple Logiciels\n                 Type: app (0x2)\n          Disposition: [enabled, allowed, visible, notified] (0xb)\n      Executable Path: /Applications/Sauvegarde.app/Contents/MacOS/Sauvegarde\n\n #2:\n                 Name: updater\n       Developer Name: Unknown Developer\n          Disposition: [enabled, allowed, visible, notified] (0xb)\n      Executable Path: /Users/alice/.cache/updater\n\n #3:\n                 Name: Ancien\n          Disposition: [disabled, allowed, visible, notified] (0xa)\n      Executable Path: /tmp/ancien\n";

    #[test]
    fn elements_d_ouverture_lus_et_juges() {
        let e = lire_btm(BTM).unwrap();
        assert_eq!(e.len(), 3);
        assert!(e[0].actif && e[1].actif && !e[2].actif);
        let c = juger_btm(Some(BTM), true);
        // Le caché, actif : élevé ; le désactivé dans /tmp : rien ; le sans développeur : information.
        assert_eq!(c.iter().filter(|c| c.probleme == Some(Niveau::Eleve)).count(), 1);
        assert!(
            c.iter()
                .any(|c| c.probleme == Some(Niveau::Info) && c.message.contains("updater"))
        );
        assert!(c.iter().all(Constat::coherent));
        assert_eq!(juger_btm(None, false)[0].etat(), Etat::NonVerifie(Raison::Droits));
        assert!(lire_btm("autre chose").is_none());
    }

    #[test]
    fn crochets_extensions_et_demarrage() {
        let c = juger_crochets(&[], Some(&[]), Some(&[]), &[]);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].etat(), Etat::Sain);
        // Les réglages de root illisibles sans sudo : non vérifié, jamais « aucun crochet ».
        let c = juger_crochets(&[], Some(&[]), Some(&[]), &[(ROOT_PREFS, Raison::Droits)]);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].etat(), Etat::NonVerifie(Raison::Droits));
        assert!(c[0].message.contains("sudo vanguard machine"));
        let c = juger_crochets(
            &[],
            Some(&[]),
            Some(&[]),
            &[(ROOT_PREFS, Raison::Illisible(ROOT_PREFS.into()))],
        );
        assert!(c.iter().all(|c| c.etat() != Etat::Sain && c.coherent()));
        let c = juger_crochets(
            &[("LoginHook".into(), "/Users/Shared/.h.sh".into())],
            Some(&["Outil.bundle".into()]),
            None,
            &[],
        );
        assert_eq!(c.iter().filter(|c| c.probleme == Some(Niveau::Moyen)).count(), 2);
        assert!(c.iter().any(|c| matches!(c.etat(), Etat::NonVerifie(_))));
        assert!(c.iter().all(Constat::coherent));
    }
}

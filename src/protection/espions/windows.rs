//! Windows : les logiciels de surveillance connus parmi les programmes installés, les processus, les services et les
//! programmes lancés au démarrage (clés Run et RunOnce, dossiers Démarrage), lus dans le registre (winreg) et par les fonctions de Windows, sans
//! PowerShell. Les mêmes clés que « Mon ordinateur est-il contrôlé ? » (`distance.rs`) : la petite répétition est
//! voulue, chaque outil garde son propre relevé.

use super::Releve;
use super::echap::Indicateurs;
use crate::tr;

/// Le nom de fichier d'une commande ou d'un chemin d'image (« "C:\x\outil.exe" -a » → « outil.exe »).
fn fichier_de(commande: &str) -> &str {
    let c = commande.trim();
    let chemin = if let Some(r) = c.strip_prefix('"') {
        r.split('"').next().unwrap_or_default()
    } else {
        // Sans guillemets : jusqu'au premier « .exe », sinon jusqu'au premier blanc.
        let bas = c.to_ascii_lowercase();
        bas.find(".exe")
            .map_or_else(|| c.split(' ').next().unwrap_or_default(), |i| &c[..i + 4])
    };
    chemin.rsplit(['\\', '/']).next().unwrap_or_default()
}

pub(super) fn relever(r: &mut Releve, ind: Option<&Indicateurs>) {
    use crate::machine::windows::{installes, processus};
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;

    match installes::noms() {
        Some(noms) => {
            r.verifies += 1;
            for n in noms {
                let ou = crate::trf!("installé : {}", "installed: {}", crate::ui::affichable(&n));
                r.programme(&n, ou, false, ind);
            }
        }
        None => r.non_verifie(tr!("programmes installés illisibles", "installed programs unreadable")),
    }
    let liste = processus::liste();
    // Une liste vide est un échec de l'appel (au moins Vanguard tourne) : dit, jamais compté comme vérifié.
    if liste.is_empty() {
        r.non_verifie(tr!("processus illisibles", "processes unreadable"));
    } else {
        r.verifies += 1;
    }
    for p in liste {
        let ou = crate::trf!("en cours : {} (pid {})", "running: {} (pid {})", p.nom, p.pid);
        r.programme(&p.nom, ou, true, ind);
    }
    // Les services : nom, nom affiché et fichier ; démarrage automatique (Start ≤ 2) compté comme en marche.
    if let Ok(services) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(crate::machine::windows::CLE_SERVICES) {
        r.verifies += 1;
        for nom in services.enum_keys().flatten() {
            let Ok(s) = services.open_subkey(&nom) else {
                continue;
            };
            let affiche = s.get_value::<String, _>("DisplayName").unwrap_or_default();
            let image = s.get_value::<String, _>("ImagePath").unwrap_or_default();
            let demarre = s.get_value::<u32, _>("Start").is_ok_and(|d| d <= 2);
            let ou = crate::trf!("service : {}", "service: {}", crate::ui::affichable(&nom));
            for texte in [nom.as_str(), affiche.as_str(), fichier_de(&image)] {
                if !texte.is_empty() && !texte.starts_with('@') {
                    r.programme(texte, ou.clone(), demarre, ind);
                }
            }
        }
    } else {
        r.non_verifie(tr!("services illisibles", "services unreadable"));
    }
    // La lecture commune des clés Run et RunOnce : une valeur que winreg ne rend pas n'est plus jetée sans rien dire,
    // et une clé illisible est dite non vérifiée.
    let (valeurs, illisibles) = crate::machine::windows::persistance::lignes_run();
    for cle in illisibles {
        r.non_verifie(crate::trf!("clé {cle} illisible", "key {cle} unreadable"));
    }
    for v in valeurs {
        let ou = crate::trf!("au démarrage : {}", "at startup: {}", crate::ui::affichable(&v.nom));
        for texte in [v.nom.as_str(), fichier_de(&v.valeur)] {
            if !texte.is_empty() {
                r.programme(texte, ou.clone(), true, ind);
            }
        }
    }
    // Les dossiers Démarrage (du compte, puis de tous les comptes) : le nom de chaque raccourci.
    let demarrage = r"Microsoft\Windows\Start Menu\Programs\Startup";
    for base in ["APPDATA", "ProgramData"] {
        let Some(dossier) = std::env::var_os(base).map(|b| std::path::PathBuf::from(b).join(demarrage)) else {
            continue;
        };
        for e in std::fs::read_dir(&dossier).into_iter().flatten().flatten() {
            let fichier = e.file_name().to_string_lossy().into_owned();
            let nom = fichier.strip_suffix(".lnk").unwrap_or(&fichier);
            if nom.eq_ignore_ascii_case("desktop.ini") {
                continue;
            }
            let ou = crate::trf!(
                "dossier Démarrage : {}",
                "Startup folder: {}",
                crate::ui::affichable(&fichier)
            );
            r.programme(nom, ou, true, ind);
        }
    }
    r.non_verifie(tr!(
        "sous Windows, les crochets clavier ne se voient pas sans pilote : non vérifiable",
        "on Windows, keyboard hooks cannot be seen without a driver: not checkable"
    ));
    r.non_verifie(tr!(
        "tâches planifiées non vérifiées (les lire demande une API de Windows encore à écrire)",
        "scheduled tasks not checked (reading them needs a Windows API not written yet)"
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fichier_d_une_commande() {
        assert_eq!(fichier_de(r#""C:\Program Files\rvlkl\rvlkl.exe" /s"#), "rvlkl.exe");
        assert_eq!(fichier_de(r"C:\Program Files\Outil\outil.exe -a"), "outil.exe");
        assert_eq!(fichier_de(r"system32\drivers\tmfsdrv2.sys"), "tmfsdrv2.sys");
        assert_eq!(fichier_de(""), "");
    }
}

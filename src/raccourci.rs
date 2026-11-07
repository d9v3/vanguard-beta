//! Raccourci sur cet ordinateur : lancer Vanguard d'un clic, sans passer par la clé. Le programme est d'abord copié
//! dans le dossier de Vanguard de cet ordinateur (lancé depuis la clé, il disparaîtrait avec elle), puis un raccourci
//! le lance : une entrée du menu des applications sous Linux (avec son icône), un raccourci sur le Bureau sous
//! Windows. Montré puis accepté ; retiré aussi simplement.
//! Un raccourci qui n'a pas été posé par Vanguard n'est jamais remplacé ni retiré.

use std::path::{Path, PathBuf};

use crate::ui::*;

/// Ce qui marque un raccourci posé par Vanguard (Linux : une clé du fichier .desktop).
pub(crate) const MARQUE: &str = "X-Vanguard-Raccourci=1";
#[cfg(any(target_os = "linux", test))]
const ICONE: &[u8] = include_bytes!("../assets/icones/vanguard-128.png");

/// L'empreinte SHA-256 de chaque icône que Vanguard a posée (relevées dans l'historique du dépôt), la plus récente
/// d'abord. Une liste et non la seule d'aujourd'hui : l'icône n'est écrite que si elle manque (`poser`), un logo
/// d'avant a donc pu rester. Un nouveau logo y ajoute la sienne (le test le rappelle).
const ICONES_CONNUES: [&str; 4] = [
    "98ebce4cc226888dfa53df2850fb3ea1418d12b44f86eab8d7bc53370a40423f",
    "c28b6babe8b692cef129b0b7c0b06c7d6b630ee43a948f7b464c8014da2b4143",
    "18f536c20d212955b270f7b1d158ffd692f5abad7bd1368bb8fd84aa4aaef8f6",
    "5343419e7fb02a4ac7df09de84c14bcf592732a99fba3ea95c83690d89859b46",
];

/// Ces octets sont-ils une icône posée par Vanguard ? Une icône du même nom venue d'ailleurs n'est jamais retirée.
pub(crate) fn icone_de_vanguard(octets: &[u8]) -> bool {
    use sha2::Digest;
    let empreinte = sha2::Sha256::digest(octets)
        .iter()
        .fold(String::with_capacity(64), |mut s, o| {
            use std::fmt::Write as _;
            let _ = write!(s, "{o:02x}");
            s
        });
    ICONES_CONNUES.contains(&empreinte.as_str())
}

/// L'icône qui accompagne un raccourci du menu des applications (Linux, « …/applications/Vanguard.desktop ») :
/// `…/icons/hicolor/128x128/apps/vanguard.png`. Aucune pour un autre raccourci.
pub(crate) fn icone(ou: &Path) -> Option<PathBuf> {
    if ou.extension()? != "desktop" {
        return None;
    }
    Some(ou.parent()?.parent()?.join("icons/hicolor/128x128/apps/vanguard.png"))
}

/// Ce fichier est-il un raccourci posé par Vanguard ? Sous Windows, un .lnk ne se lit pas comme du texte : celui de
/// ce nom a été posé par Vanguard. Ailleurs, il porte la marque.
pub(crate) fn de_vanguard(p: &Path) -> bool {
    p.extension().is_some_and(|e| e.eq_ignore_ascii_case("lnk"))
        || std::fs::read_to_string(p).is_ok_and(|t| t.contains(MARQUE))
}

/// Où va le raccourci sur ce système.
pub(crate) fn chemin() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let donnees = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| crate::socle::personnel::dossier_personnel().map(|h| h.join(".local/share")))?;
        Some(donnees.join("applications/Vanguard.desktop"))
    }
    #[cfg(windows)]
    {
        let bureau = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
            .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
            .ok()
            .and_then(|k| k.get_value::<String, _>("Desktop").ok())
            .map(|c| PathBuf::from(crate::protection::pieges::developper(&c)))
            .or_else(|| std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join("Desktop")))?;
        Some(bureau.join("Vanguard.lnk"))
    }
}

/// L'entrée du menu des applications, Linux : Vanguard s'ouvre dans un terminal.
#[cfg(any(target_os = "linux", test))]
fn bureau_linux(exe: &str) -> String {
    // Exec : entre guillemets, « % » doublé (codes de champ de la spécification).
    let exe = format!(
        "\"{}\"",
        exe.replace('\\', "\\\\").replace('"', "\\\"").replace('%', "%%")
    );
    format!(
        "[Desktop Entry]\nType=Application\nName=Vanguard\nComment={}\nExec={exe}\nTerminal=true\nIcon=vanguard\nCategories=System;Security;\n{MARQUE}\n",
        tr!(
            "Cyberdéfense portable des postes et des réseaux",
            "Portable cyber defense for endpoints and networks"
        )
    )
}

/// Le raccourci existe-t-il, et est-il de Vanguard ?
fn etat() -> Option<(PathBuf, bool)> {
    let p = chemin()?;
    if !p.exists() {
        return Some((p, false));
    }
    let a_nous = de_vanguard(&p);
    Some((p, a_nous))
}

/// Reprise d'un raccourci posé sous l'ancien nom (`passage`) : le même, au nouveau nom.
pub(crate) fn reprendre(exe: &str, ou: &Path) -> bool {
    poser(exe, ou).is_ok()
}

/// Ce qu'est devenu un fichier qu'on retire.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Fait {
    Retire,
    /// Gardé exprès : pas posé par Vanguard.
    Garde,
    Echec(String),
}

/// Retire le raccourci `ou` (déjà reconnu comme celui de Vanguard), puis, sous Linux, son icône si c'est bien celle
/// que Vanguard pose : une icône d'un autre programme, au même nom, reste. Sans raccourci, une icône de Vanguard
/// restée seule part aussi. Rend ce qui a été fait de chaque fichier trouvé.
pub(crate) fn retirer(ou: &Path) -> Vec<(PathBuf, Fait)> {
    let mut faits = Vec::new();
    if std::fs::symlink_metadata(ou).is_ok() {
        let fait = match std::fs::remove_file(ou) {
            Ok(()) => Fait::Retire,
            Err(e) => Fait::Echec(e.to_string()),
        };
        faits.push((ou.to_path_buf(), fait));
    }
    if let Some(i) = icone(ou)
        && let Ok(meta) = std::fs::symlink_metadata(&i)
    {
        // Un lien à la place de l'icône n'a pas été posé par Vanguard (il écrit un fichier) : gardé, sans le suivre.
        let fait = if meta.is_file() && std::fs::read(&i).is_ok_and(|o| icone_de_vanguard(&o)) {
            match std::fs::remove_file(&i) {
                Ok(()) => Fait::Retire,
                Err(e) => Fait::Echec(e.to_string()),
            }
        } else {
            Fait::Garde
        };
        faits.push((i, fait));
    }
    faits
}

/// Une icône de Vanguard sans raccourci (le raccourci retiré par une version qui laissait l'icône) ?
fn icone_seule(ou: &Path) -> bool {
    !ou.exists()
        && icone(ou).is_some_and(|i| {
            std::fs::symlink_metadata(&i).is_ok_and(|m| m.is_file())
                && std::fs::read(&i).is_ok_and(|o| icone_de_vanguard(&o))
        })
}

/// Dit ce que `retirer` a fait.
fn dire_retrait(faits: &[(PathBuf, Fait)], ou: &Path) {
    let raccourci = faits.iter().find(|(p, _)| p == ou).map(|(_, f)| f);
    let icone = faits.iter().find(|(p, _)| p != ou);
    match (raccourci, icone.map(|(_, f)| f)) {
        (Some(Fait::Retire), Some(Fait::Retire)) => trp!(
            "  {VERT}✔{RESET} Raccourci retiré, et son icône.",
            "  {VERT}✔{RESET} Shortcut removed, and its icon."
        ),
        (Some(Fait::Retire), _) => trp!(
            "  {VERT}✔{RESET} Raccourci retiré.",
            "  {VERT}✔{RESET} Shortcut removed."
        ),
        (None, Some(Fait::Retire)) => {
            let montre = icone.map(|(p, _)| chemin_affichable(p)).unwrap_or_default();
            trp!(
                "  {VERT}✔{RESET} Icône de Vanguard retirée ({montre}).",
                "  {VERT}✔{RESET} Vanguard's icon removed ({montre})."
            );
        }
        _ => {}
    }
    if let Some(Fait::Echec(e)) = raccourci {
        trp!("  ✖ Raccourci non retiré : {e}", "  ✖ Shortcut not removed: {e}");
    }
    if let Some((p, f)) = icone {
        let montre = chemin_affichable(p);
        match f {
            Fait::Garde => trp!(
                "  Icône gardée ({montre}) : ce n'est pas celle que Vanguard pose.",
                "  Icon kept ({montre}): it is not the one Vanguard places."
            ),
            Fait::Echec(e) => trp!(
                "  ✖ Icône non retirée ({montre}) : {e}",
                "  ✖ Icon not removed ({montre}): {e}"
            ),
            Fait::Retire => {}
        }
    }
}

fn poser(exe: &str, ou: &Path) -> Result<(), String> {
    if let Some(parent) = ou.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "linux")]
    {
        std::fs::write(ou, bureau_linux(exe)).map_err(|e| e.to_string())?;
        if let Some(icone) = icone(ou) {
            let _ = std::fs::create_dir_all(icone.parent().unwrap_or(&icone));
            if !icone.exists() {
                let _ = std::fs::write(&icone, ICONE);
            }
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        let e = crate::commande::ps_texte;
        let script = format!(
            "$s = (New-Object -ComObject WScript.Shell).CreateShortcut('{}'); $s.TargetPath = '{}'; $s.IconLocation = '{},0'; \
             $s.Description = 'Vanguard'; $s.Save()",
            e(&ou.display().to_string()),
            e(exe),
            e(exe)
        );
        crate::machine::windows::ps(&script).map(|_| ()).ok_or_else(|| {
            tr!(
                "PowerShell n'a pas pu créer le raccourci",
                "PowerShell could not create the shortcut"
            )
            .into()
        })
    }
}

/// `vanguard raccourci [on|off]` et le menu Données : sans argument, l'état et la proposition.
pub fn commande(voulu: Option<bool>) {
    titre(tr!("Raccourci sur cet ordinateur", "Shortcut on this computer"));
    let Some((ou, a_nous)) = etat() else {
        trp!(
            "  ✖ Impossible de trouver le Bureau ou le menu des applications ici.",
            "  ✖ Could not find the Desktop or the applications menu here."
        );
        return;
    };
    let montre = chemin_affichable(&ou);
    let present = ou.exists();
    if present && !a_nous {
        trp!(
            "  {VERT}✔{RESET} Un raccourci vers Vanguard existe déjà ({montre}) : il n'a pas été posé par Vanguard, il reste tel quel.",
            "  {VERT}✔{RESET} A shortcut to Vanguard already exists ({montre}): it was not placed by Vanguard, it stays as it is."
        );
        return;
    }
    let explicite = voulu.is_some();
    let voulu = voulu.unwrap_or_else(|| {
        let question = if present {
            trf!("  Raccourci présent ({montre}). Le retirer ? [o/N] : ", "  Shortcut present ({montre}). Remove it? [y/N]: ")
        } else {
            trf!(
                "  Vanguard sera copié sur cet ordinateur, puis lancé d'un clic par {montre}. Le poser ? [o/N] : ",
                "  Vanguard will be copied onto this computer, then started with one click from {montre}. Place it? [y/N]: "
            )
        };
        demander(&question).oui() != present
    });
    if voulu {
        if present {
            trp!(
                "  {VERT}✔{RESET} Le raccourci est déjà là.",
                "  {VERT}✔{RESET} The shortcut is already there."
            );
            return;
        }
        let Some(exe) = crate::reseau::surveillance::executable() else {
            return;
        };
        match poser(&exe, &ou) {
            Ok(()) => trp!(
                "  {VERT}✔{RESET} Raccourci posé : {montre}",
                "  {VERT}✔{RESET} Shortcut placed: {montre}"
            ),
            Err(e) => trp!("  ✖ Raccourci non posé : {e}", "  ✖ Shortcut not placed: {e}"),
        }
    } else if present || (explicite && icone_seule(&ou)) {
        // « raccourci off » retire aussi une icône de Vanguard restée seule ; refuser de le poser ne touche à rien.
        dire_retrait(&retirer(&ou), &ou);
    } else if explicite {
        trp!(
            "  Pas de raccourci de Vanguard ici : rien à retirer.",
            "  No Vanguard shortcut here: nothing to remove."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fichiers_du_raccourci() {
        let d = bureau_linux("/home/alice/.local/share/vanguard/bin/gar\"dien 100%");
        assert!(
            d.contains("Exec=\"/home/alice/.local/share/vanguard/bin/gar\\\"dien 100%%\"\n"),
            "{d}"
        );
        assert!(d.contains("Terminal=true") && d.contains(MARQUE));
    }

    /// L'icône d'aujourd'hui est reconnue à son empreinte : un nouveau logo fait échouer ce test tant que la sienne
    /// n'est pas ajoutée à `ICONES_CONNUES` (sinon `raccourci off` ne la retirerait plus). D'autres octets, non.
    #[test]
    fn icone_reconnue_par_son_empreinte() {
        assert!(icone_de_vanguard(ICONE));
        assert!(!icone_de_vanguard(b"\x89PNG une autre icone"));
        assert!(!icone_de_vanguard(b""));
        assert_eq!(
            icone(Path::new("/home/alice/.local/share/applications/Vanguard.desktop")),
            Some(PathBuf::from(
                "/home/alice/.local/share/icons/hicolor/128x128/apps/vanguard.png"
            ))
        );
        assert_eq!(icone(Path::new("C:/Users/alice/Desktop/Vanguard.lnk")), None);
    }

    /// Dans un dossier jetable : le raccourci posé puis retiré emporte son icône ; une icône d'un autre programme
    /// au même nom reste ; un .desktop sans la marque n'est pas de Vanguard.
    #[cfg(target_os = "linux")]
    #[test]
    fn retrait_du_raccourci_et_de_son_icone() {
        let d = crate::socle::dossier_local().join("raccourci-retrait");
        let _ = std::fs::remove_dir_all(&d);
        let ou = d.join("applications/Vanguard.desktop");
        let i = icone(&ou).unwrap();
        poser("/home/alice/vanguard", &ou).unwrap();
        assert!(de_vanguard(&ou) && i.is_file());
        assert_eq!(retirer(&ou), [(ou.clone(), Fait::Retire), (i.clone(), Fait::Retire)]);
        assert!(!ou.exists() && !i.exists());
        // Une icône d'autres octets, au même endroit : gardée, et dite.
        poser("/home/alice/vanguard", &ou).unwrap();
        std::fs::write(&i, b"une autre icone").unwrap();
        assert_eq!(retirer(&ou), [(ou.clone(), Fait::Retire), (i.clone(), Fait::Garde)]);
        assert!(i.is_file());
        // Une icône de Vanguard restée seule : reconnue, et retirée par « off ».
        std::fs::write(&i, ICONE).unwrap();
        assert!(icone_seule(&ou));
        assert_eq!(retirer(&ou), [(i.clone(), Fait::Retire)]);
        // Un .desktop au même nom, sans la marque : pas de Vanguard.
        std::fs::write(&ou, "[Desktop Entry]\nName=Vanguard\nExec=vanguard\n").unwrap();
        assert!(!de_vanguard(&ou));
        let _ = std::fs::remove_dir_all(&d);
    }
}

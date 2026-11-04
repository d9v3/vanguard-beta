//! Le vrai Defender, le vrai Sécurité Windows, et ceux qui en prennent seulement le nom (D6d). Vanguard ne retire
//! jamais le vrai : rangé là où Windows le range ET signé par Microsoft (signature illisible : traité comme le vrai).
//! Un lancement qui n'en a que le nom se montre et se demande dans la console élevée, Non par défaut.

use crate::ui::{tr, trf};

/// Ce que Vanguard pense d'un lancement qui ressemble à Sécurité Windows ou à Defender (`run_protege`) : seul le vrai
/// programme est refusé ; un nom pris ailleurs se montre et se demande (décision D6c, « pas de refus qui nuit à la
/// défense ») : un maliciel qui se nomme « Windows Defender » doit pouvoir se retirer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Protege {
    /// Rien de Windows ni de Defender.
    Non,
    /// Le nom ou le programme de Defender, mais hors de ses dossiers ou sans la signature de Microsoft.
    NomSeul,
    /// Le vrai programme : rangé là où Windows le range, et signé par Microsoft (ou signature illisible).
    Vrai,
}

/// Les dossiers des vrais programmes, en minuscules, sans `\` final : celui de Windows, ceux de Program Files
/// (64 et 32 bits), ProgramData.
pub(crate) struct LieuxReels {
    pub(crate) windows: String,
    pub(crate) program_files: Vec<String>,
    pub(crate) program_data: Option<String>,
}

/// Le chemin d'un programme tel que Windows le lancerait, pour en juger le lieu : guillemets ôtés, variables du
/// système développées (les seules qu'un vrai lancement de Defender porte), « . » et « .. » résolus sans suivre de
/// lien, préfixe `\\?\` ôté ; un nom seul est cherché dans System32 (ce que fait la recherche de Windows en premier
/// pour un programme du système). Minuscules, `\` seulement. `None` : chemin relatif, réseau ou qui remonte trop.
pub(crate) fn chemin_du_programme(programme: &str, lieux: &LieuxReels) -> Option<String> {
    let mut p = programme.trim().trim_matches('"').to_lowercase().replace('/', "\\");
    if let Some(r) = p.strip_prefix(r"\\?\") {
        p = r.to_string();
    }
    let pf = lieux.program_files.first().cloned();
    for (variable, valeur) in [
        ("%windir%", Some(lieux.windows.clone())),
        ("%systemroot%", Some(lieux.windows.clone())),
        ("%programfiles%", pf.clone()),
        ("%programw6432%", pf),
        ("%programdata%", lieux.program_data.clone()),
    ] {
        if let Some(r) = p.strip_prefix(variable) {
            p = format!("{}{r}", valeur?);
        }
    }
    if p.contains('%') || p.starts_with('\\') {
        return None;
    }
    if !p.contains('\\') {
        p = format!(r"{}\system32\{p}", lieux.windows);
    }
    let (lecteur, reste) = p.split_once(r":\")?;
    if lecteur.len() != 1 || !lecteur.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    let mut parties: Vec<&str> = Vec::new();
    for c in reste.split('\\') {
        match c {
            "" | "." => {}
            ".." => {
                parties.pop()?;
            }
            // Windows ôte le point ou l'espace final d'un composant à l'ouverture (« temp. » ouvre « temp ») ; un
            // deux-points nomme un flux d'un dossier (« temp:x.exe »). Le lieu ne se juge pas : jamais le vrai.
            _ if c.ends_with(['.', ' ']) || c.contains(':') => return None,
            _ => parties.push(c),
        }
    }
    Some(format!(r"{lecteur}:\{}", parties.join(r"\")))
}

/// Le chemin (de `chemin_du_programme`) est-il là où Windows range ses programmes et ceux de Defender et de Sécurité
/// Windows : directement dans le dossier de Windows, System32 ou SysWOW64, sous Program Files\Windows Defender (et
/// Advanced Threat Protection), ou sous ProgramData\Microsoft\Windows Defender\Platform, où les mises à jour de
/// Defender posent MsMpEng et MpCmdRun.
/// Écrire là demande d'être administrateur (ou TrustedInstaller) : un maliciel du compte ne peut pas s'y ranger.
pub(crate) fn chemin_reel(chemin: &str, lieux: &LieuxReels) -> bool {
    let sous = |dossier: &str| {
        chemin
            .strip_prefix(dossier)
            .is_some_and(|r| r.starts_with('\\') && r.len() > 1)
    };
    let defender = lieux.program_files.iter().any(|pf| {
        ["windows defender", "windows defender advanced threat protection"]
            .iter()
            .any(|d| sous(&format!(r"{pf}\{d}")))
    });
    let plateforme = lieux
        .program_data
        .as_ref()
        .is_some_and(|pd| sous(&format!(r"{pd}\microsoft\windows defender\platform")));
    // Sous le dossier de Windows, seulement un fichier rangé directement dans Windows, System32 ou SysWOW64 (là où
    // sont SecurityHealthSystray et les autres) : leurs sous-dossiers ouverts aux comptes (Temp, Tasks, FxsTmp,
    // Com\dmp, spool\PRINTERS…) varient d'une version à l'autre, et un maliciel s'y range puis se rend illisible
    // (fichier ouvert sans partage) pour passer pour le vrai. Une liste de ceux-là manquerait toujours un dossier.
    let systeme = DOSSIERS_DU_VRAI.iter().any(|d| {
        let dossier = if d.is_empty() {
            lieux.windows.clone()
        } else {
            format!(r"{}\{d}", lieux.windows)
        };
        chemin
            .strip_prefix(&dossier)
            .and_then(|r| r.strip_prefix('\\'))
            .is_some_and(|f| !f.is_empty() && !f.contains('\\'))
    });
    systeme || defender || plateforme
}

/// Les dossiers sous celui de Windows dont un fichier rangé directement peut être le vrai (en minuscules ; « » : le
/// dossier de Windows lui-même). Aucun n'est ouvert en écriture aux comptes ordinaires.
const DOSSIERS_DU_VRAI: [&str; 3] = ["", "system32", "syswow64"];

/// Le jugement, pur : `run_protege` d'abord (rien de Defender : `Non`) ; puis le vrai programme seulement s'il est à
/// sa place ET signé par Microsoft. Une signature illisible compte comme celle de Microsoft (un refus de trop ne
/// casse rien ; un maliciel peut aussi se rendre illisible, mais il devrait alors être rangé dans le dossier de
/// Windows, ce qui demande d'être administrateur). Sauf un fichier absent : le vrai est toujours à sa place, une
/// valeur qui vise un fichier qui n'existe pas n'est pas lui.
pub(crate) fn juger_protege(
    nom: &str,
    programme: &str,
    reel: bool,
    signature: crate::protection::blocage::gardes::Signature,
) -> Protege {
    use crate::protection::blocage::gardes::{Illisibilite, Signature};
    if !super::gestes::run_protege(nom, programme) {
        return Protege::Non;
    }
    match (reel, signature) {
        (true, Signature::Illisible(Illisibilite::Absent)) => Protege::NomSeul,
        (true, Signature::Microsoft | Signature::Illisible(_)) => Protege::Vrai,
        _ => Protege::NomSeul,
    }
}

/// Les dossiers de cette machine pour `chemin_reel`, pris à Windows (jamais à l'environnement du compte).
pub(crate) fn lieux_reels() -> LieuxReels {
    let d = super::environnement::dossiers();
    let texte = |p: &std::path::Path| {
        p.to_string_lossy()
            .to_lowercase()
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_string()
    };
    let mut program_files: Vec<String> = [&d.program_files_x64, &d.program_files, &d.program_files_x86]
        .into_iter()
        .flatten()
        .map(|p| texte(p))
        .collect();
    program_files.dedup();
    LieuxReels {
        windows: texte(&d.windows),
        program_files,
        program_data: d.program_data.as_deref().map(texte),
    }
}

/// Le jugement sur cette machine : le lieu, puis la signature lue (seulement si le lieu est le vrai : un programme
/// rangé ailleurs n'est pas Defender, quelle que soit sa signature).
pub(crate) fn protege(nom: &str, programme: &str) -> Protege {
    use crate::protection::blocage::gardes::{Signature, signature_lue};
    if !super::gestes::run_protege(nom, programme) {
        return Protege::Non;
    }
    let lieux = lieux_reels();
    let Some(chemin) = chemin_du_programme(programme, &lieux).filter(|c| chemin_reel(c, &lieux)) else {
        return juger_protege(nom, programme, false, Signature::Autre);
    };
    juger_protege(nom, programme, true, signature_lue(&chemin))
}

/// Ce que la console élevée dit avant de demander, pour un nom de Defender qui n'est pas lui.
pub(crate) fn texte_nom_seul(nom: &str, programme: &str) -> String {
    trf!(
        "  « {} » porte le nom de Defender ou de Sécurité Windows mais n'est pas lui : son programme ({}) n'est pas à la place du vrai, ou n'est pas signé par Microsoft. Le vrai n'est jamais retiré.",
        "  “{}” bears the name of Defender or Windows Security but is not it: its program ({}) is not where the real one is, or is not signed by Microsoft. The real one is never removed.",
        crate::ui::affichable(nom),
        crate::ui::affichable(programme)
    )
}

/// Un nom venu d'ailleurs montré à l'identique : entre guillemets (les espaces de bordure se voient), chaque
/// caractère de contrôle, invisible ou de mise en page échappé (`\n`, `\r`, `\u{1b}`, `\u{202e}`…), guillemets et
/// barre oblique inverse aussi : rien ne s'exécute ni ne se cache dans la console. Coupé à `max` caractères montrés.
pub(crate) fn echappe_exact(texte: &str, max: usize) -> String {
    let mut sortie = String::from("\"");
    let mut montres = 0usize;
    for c in texte.chars() {
        let mut e: String = c.escape_debug().collect();
        // escape_debug laisse quelques caractères imprimables que la console sait détourner : ceux d'`affichable`.
        if e.chars().count() == 1 && crate::ui::affichable(&e) != e {
            e = format!("\\u{{{:x}}}", u32::from(c));
        }
        montres = montres.saturating_add(e.chars().count());
        if montres > max {
            sortie.push('…');
            break;
        }
        sortie.push_str(&e);
    }
    sortie.push('"');
    sortie
}

/// Une question de plus, posée ici, dans la console (élevée ou non), jamais par une ligne de la liste : aucune ligne ne
/// dit « quand même » ni « sans note », une liste forgée ne peut pas sauter la question. L'explication d'abord (déjà
/// nettoyée par l'appelant), puis la question ; seul un oui tapé dans une vraie console vaut oui (Entrée seule : non).
pub(super) fn accord(explication: &str, question: &str) -> bool {
    accord_selon(
        super::eleve::console_reelle(),
        explication,
        question,
        crate::ui::demander_ou_defaut,
    )
}

/// `accord`, la console et la réponse données (les tests).
pub(super) fn accord_selon(
    console: bool,
    explication: &str,
    question: &str,
    demander: impl FnOnce(&str) -> String,
) -> bool {
    crate::ui::imprimer(explication);
    crate::machine::reglages::confirmer(console, question, demander)
}

/// La question d'un geste qui ne pourra pas être défait par Vanguard (note impossible, copie trop grande…).
pub(super) fn question_non_annulable() -> &'static str {
    tr!(
        "  Le faire quand même, non annulable par Vanguard ? [o/N] : ",
        "  Do it anyway, not undoable by Vanguard? [y/N]: "
    )
}

/// La question d'un retrait qui porte le nom de Defender sans être lui.
pub(super) fn question_quand_meme() -> &'static str {
    tr!("  Le retirer quand même ? [o/N] : ", "  Remove it anyway? [y/N]: ")
}

/// Le refus d'une question à laquelle la réponse n'a pas été oui.
pub(super) fn non_confirme() -> String {
    tr!("non confirmé : rien d'écrit", "not confirmed: nothing written").to_string()
}

/// Un retrait accepté sans note : la note d'une version d'avant (qui remettrait une autre donnée) n'est effacée
/// qu'une fois la cible relue identique, juste avant le retrait. Relue changée : rien n'est effacé, le geste dit
/// « rien d'écrit » et c'est vrai. Rend la relecture.
pub(super) fn relue_puis_effacer(relue_identique: impl FnOnce() -> bool, effacer_l_ancienne: impl FnOnce()) -> bool {
    let identique = relue_identique();
    if identique {
        effacer_l_ancienne();
    }
    identique
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protection::blocage::gardes::{Illisibilite, Signature};

    #[test]
    fn l_ancienne_note_reste_si_la_relecture_change() {
        let fait = std::cell::RefCell::new(Vec::new());
        assert!(!relue_puis_effacer(
            || {
                fait.borrow_mut().push("relue");
                false
            },
            || fait.borrow_mut().push("effacée")
        ));
        assert_eq!(*fait.borrow(), ["relue"]);
        fait.borrow_mut().clear();
        assert!(relue_puis_effacer(
            || {
                fait.borrow_mut().push("relue");
                true
            },
            || fait.borrow_mut().push("effacée")
        ));
        assert_eq!(*fait.borrow(), ["relue", "effacée"]);
    }

    fn lieux() -> LieuxReels {
        LieuxReels {
            windows: r"c:\windows".to_string(),
            program_files: vec![r"c:\program files".to_string(), r"c:\program files (x86)".to_string()],
            program_data: Some(r"c:\programdata".to_string()),
        }
    }

    fn reel(programme: &str) -> bool {
        chemin_du_programme(programme, &lieux()).is_some_and(|c| chemin_reel(&c, &lieux()))
    }

    /// Le vrai lieu : un fichier rangé directement dans Windows, System32 ou SysWOW64, Program Files\Windows Defender,
    /// la plateforme de ProgramData ; variables du système, nom seul (System32), « .. » résolus.
    /// Un nom hostile (saut de ligne, échappement de terminal, retour chariot, espaces de bordure, inversion de sens,
    /// très long) se montre échappé : aucun caractère de contrôle n'arrive à la console, les bordures se voient, la
    /// longueur est bornée.
    #[test]
    fn nom_hostile_echappe() {
        assert_eq!(echappe_exact(" Upd\nater ", 80), r#"" Upd\nater ""#);
        assert_eq!(echappe_exact("a\u{1b}[31mb\rc", 80), r#""a\u{1b}[31mb\rc""#);
        assert_eq!(echappe_exact(r#"a"b\c'd"#, 80), r#""a\"b\\c\'d""#);
        assert!(echappe_exact("a\u{202e}b", 80).contains(r"\u{202e}"));
        let long = echappe_exact(&"x".repeat(10_000), 120);
        assert!(long.chars().count() <= 123 && long.ends_with("…\""), "{long}");
        for n in [" a ", "\n", "\r", "\u{1b}[2J", "\u{7}", "\t", "\u{200b}x", "\u{feff}"] {
            let e = echappe_exact(n, 80);
            assert!(!e.chars().any(char::is_control), "{e:?}");
            assert_eq!(crate::ui::affichable(&e), e, "{e:?}");
        }
    }

    #[test]
    fn le_lieu_du_vrai_defender() {
        for p in [
            r"%windir%\system32\SecurityHealthSystray.exe",
            r"%SystemRoot%\System32\SecurityHealthSystray.exe",
            "SecurityHealthSystray.exe",
            r#""C:\Program Files\Windows Defender\MSASCuiL.exe""#,
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1\MsMpEng.exe",
            r"c:/windows/system32/securityhealthsystray.exe",
            r"\\?\C:\Windows\System32\SecurityHealthSystray.exe",
            r"C:\Program Files (x86)\Windows Defender\MpCmdRun.exe",
        ] {
            assert!(reel(p), "{p}");
        }
        for p in [
            r"C:\Users\alice\AppData\Roaming\Windows Defender\MsMpEng.exe",
            r"C:\Windows\Temp\MsMpEng.exe",
            r"C:\Windows\Tasks\x\MsMpEng.exe",
            r"C:\Windows\System32\..\..\Users\Public\MsMpEng.exe",
            r"C:\Windows\..\..\..\x.exe",
            r"C:\ProgramData\Microsoft\Windows Defender\Scans\x.exe",
            r"C:\Program Files\Windows Defender Faux\x.exe",
            r"%APPDATA%\SecurityHealthSystray.exe",
            r"\\serveur\partage\MsMpEng.exe",
            r"..\MsMpEng.exe",
            r"C:\Windows",
            // Relecture D6d : des sous-dossiers de Windows ouverts aux comptes, absents de l'ancienne liste.
            r"C:\Windows\System32\FxsTmp\MsMpEng.exe",
            r"C:\Windows\SysWOW64\FxsTmp\MsMpEng.exe",
            r"C:\Windows\System32\Com\dmp\MsMpEng.exe",
            r"C:\Windows\System32\spool\PRINTERS\MsMpEng.exe",
            r"C:\Windows\System32\Tasks\SecurityHealthSystray.exe",
            r"C:\Windows\Tracing\MsMpEng.exe",
            // Le point ou l'espace final qu'ôte Windows, un flux d'un dossier.
            r"C:\Windows\Temp.\MsMpEng.exe",
            r"C:\Windows\Tasks \MsMpEng.exe",
            r"C:\Windows\System32\SecurityHealthSystray.exe.",
            r"C:\Windows\Temp:MsMpEng.exe",
            r"C:\Windows\System32\Temp:x:MsMpEng.exe",
        ] {
            assert!(!reel(p), "{p}");
        }
        assert!(chemin_du_programme(r"C:\Windows\Temp.\MsMpEng.exe", &lieux()).is_none());
    }

    /// Le faux « Windows Defender » hors de sa place : une question ; le vrai signé : refusé ; signature illisible au
    /// vrai lieu : refusé ; à sa place mais signé par un autre : une question ; rien de Defender : rien.
    #[test]
    fn seul_le_vrai_est_refuse() {
        let illisible = Signature::Illisible(Illisibilite::Verrouille);
        assert_eq!(
            juger_protege(
                "Windows Defender",
                r"C:\Users\Public\x.cmd",
                false,
                Signature::Microsoft
            ),
            Protege::NomSeul
        );
        assert_eq!(
            juger_protege("Windows Defender", r"C:\Users\Public\x.cmd", false, illisible),
            Protege::NomSeul
        );
        let vrai = r"%windir%\system32\SecurityHealthSystray.exe";
        assert_eq!(
            juger_protege("SecurityHealth", vrai, true, Signature::Microsoft),
            Protege::Vrai
        );
        assert_eq!(juger_protege("SecurityHealth", vrai, true, illisible), Protege::Vrai);
        // Relecture D6d : un fichier absent n'est pas le vrai (il est toujours à sa place).
        assert_eq!(
            juger_protege(
                "Windows Defender",
                vrai,
                true,
                Signature::Illisible(Illisibilite::Absent)
            ),
            Protege::NomSeul
        );
        assert_eq!(
            juger_protege("SecurityHealth", vrai, true, Signature::Autre),
            Protege::NomSeul
        );
        assert_eq!(
            juger_protege("Mise à jour", r"C:\x\y.exe", true, Signature::Microsoft),
            Protege::Non
        );
    }

    /// Une question : Non par défaut (Entrée seule, autre réponse), et non hors d'une vraie console.
    #[test]
    fn la_question_vaut_non_par_defaut() {
        assert!(!accord_selon(true, "x", question_non_annulable(), |_| String::new()));
        assert!(!accord_selon(true, "x", question_non_annulable(), |_| "oui non".to_string()));
        assert!(!accord_selon(false, "x", question_non_annulable(), |_| "o".to_string()));
        assert!(accord_selon(true, "x", question_quand_meme(), |_| "o".to_string()));
    }

    #[test]
    fn le_nom_seul_se_montre_nettoye() {
        let t = texte_nom_seul("Windows Defender\x1b[2K\r", "C:\\x\u{202e}.exe");
        assert!(!crate::ui::contient_un_piege(&t), "{t}");
    }
}

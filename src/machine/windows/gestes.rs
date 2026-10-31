//! La grammaire des lignes que le processus élevé (`eleve`) lit du Vanguard non élevé, pour ce qui n'est ni une
//! correction de la table (`corrections`) ni un ordre du blocage : le script PowerShell vérifié par empreinte
//! (`vanguard:script`) et les programmes fixes de Windows (`vanguard:programme`), lancés par leur chemin complet avec
//! des arguments figés, sans shell. Plus la découpe d'une liste de correctifs en morceaux (gestes natifs, scripts) et
//! la lecture des états d'un script : du code pur, sans E/S, testé sous Linux et lu par le banc de fuzzing
//! (fuzz/fuzz_targets/gestes.rs). C'est la seule entrée que le processus élevé lit d'un processus moins sûr : rien ici
//! ne dépend du reste de Vanguard.
//!
//! Le parent n'envoie jamais un chemin de programme ni un argument libre : seulement un identifiant de la table, et,
//! pour retirer une fonctionnalité de Windows, un nom pris dans une liste fermée. Le dossier, le programme et ses
//! arguments sont ceux de la table, lus par le processus élevé.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use std::fmt::Write as _;

/// La plus longue ligne admise : celle d'un ordre du blocage (un chemin de programme) ; `ordres::LIGNE_MAX`.
pub(crate) const LIGNE_MAX: usize = 8448;
/// Au-delà, une liste n'est pas celle d'une session de Vanguard ; `ordres::LIGNES_MAX`.
pub(crate) const LIGNES_MAX: usize = 512;
/// Le verbe d'un script PowerShell vérifié par empreinte.
pub(crate) const SCRIPT: &str = "vanguard:script ";
/// Le verbe d'un programme fixe de Windows.
pub(crate) const PROGRAMME: &str = "vanguard:programme ";
/// Une ligne de programme est courte : un identifiant, et au plus un nom de fonctionnalité.
const PROGRAMME_MAX: usize = 256;
/// Au-delà, les états d'un script ne viennent pas d'un script de Vanguard.
pub(crate) const ETATS_MAX: usize = 4096;

// ------------------------------------------------------------------ le script

/// Un script PowerShell à lancer seulement si ses octets ont cette empreinte (SHA-256, hexadécimal majuscule).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Script {
    pub empreinte: String,
    pub chemin: String,
}

/// La ligne qui demande ce script.
pub(crate) fn ligne_script(empreinte: &str, chemin: &str) -> String {
    let hex = chemin.bytes().fold(String::new(), |mut s, o| {
        let _ = write!(s, "{o:02x}");
        s
    });
    format!("{SCRIPT}{empreinte} {hex}")
}

/// Le script d'une ligne, si et seulement si elle est exactement de sa forme : 64 chiffres hexadécimaux majuscules,
/// une espace, un chemin complet de .ps1 en hexadécimal minuscule. Le chemin est découpé sur `\` à la main (pas par
/// `Path`, qui sous Linux n'y voit pas de séparateur) : « correction-….ps1 » dans un dossier « corrections », sans
/// composant « . » ni « .. ».
pub(crate) fn analyser_script(ligne: &str) -> Option<Script> {
    let (empreinte, hex) = ligne.strip_prefix(SCRIPT)?.split_once(' ')?;
    let forme = empreinte.len() == 64 && empreinte.bytes().all(|o| matches!(o, b'0'..=b'9' | b'A'..=b'F'));
    if !forme || hex.is_empty() || !hex.len().is_multiple_of(2) {
        return None;
    }
    let octets: Option<Vec<u8>> = hex
        .as_bytes()
        .chunks(2)
        .map(|paire| {
            let fort = chiffre_minuscule(*paire.first()?)?;
            let faible = chiffre_minuscule(*paire.get(1)?)?;
            fort.checked_mul(16)?.checked_add(faible)
        })
        .collect();
    let chemin = String::from_utf8(octets?).ok()?;
    let o = chemin.as_bytes();
    let complet = matches!(o, [lecteur, b':', b'\\', _, ..] if lecteur.is_ascii_alphabetic());
    let mut composants = chemin.rsplit('\\');
    let nom = composants.next().unwrap_or_default();
    let dossier = composants.next().unwrap_or_default();
    let ps1 = nom.starts_with("correction-")
        && nom.to_ascii_lowercase().ends_with(".ps1")
        && dossier.eq_ignore_ascii_case("corrections");
    let sans_detour = !chemin.split(['\\', '/']).any(|c| c == "." || c == "..");
    (complet && ps1 && sans_detour && !chemin.contains(['\0', '\n', '\r']) && ligne_script(empreinte, &chemin) == ligne)
        .then(|| Script {
            empreinte: empreinte.to_string(),
            chemin,
        })
}

fn chiffre_minuscule(o: u8) -> Option<u8> {
    match o {
        b'0'..=b'9' => o.checked_sub(b'0'),
        b'a'..=b'f' => o.checked_sub(b'a')?.checked_add(10),
        _ => None,
    }
}

// ------------------------------------------------------------- les programmes

/// Où est le programme : lu par le processus élevé lui-même, jamais dans l'environnement.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Dossier {
    /// System32 (GetSystemDirectoryW).
    Systeme32,
    /// `<lecteur de Windows>\Program Files\Windows Defender` : le chemin par défaut de FOLDERID_ProgramFiles pour un
    /// programme 64 bits (« %SystemDrive%\Program Files »), le lecteur pris dans le chemin de System32.
    Defender,
}

/// Le dossier de Defender, sous le lecteur de Windows.
pub(crate) const DOSSIER_DEFENDER: &str = r"Program Files\Windows Defender";

/// Un argument du programme : figé, ou désigné par la ligne dans une liste fermée.
#[derive(Debug)]
pub(crate) enum Argument {
    Fixe(&'static str),
    /// La lettre du lecteur de Windows (« C: »), lue par le processus élevé.
    LecteurSysteme,
    /// Ce préfixe, suivi du nom donné par la ligne (une des `noms` du programme).
    Nom(&'static str),
}

/// Un programme fixe de Windows : un outil de réparation, lancé tel quel.
#[derive(Debug)]
pub(crate) struct Programme {
    /// `[a-z0-9-]`, 40 caractères au plus.
    pub id: &'static str,
    pub dossier: Dossier,
    pub exe: &'static str,
    pub arguments: &'static [Argument],
    /// Les seuls noms admis après l'identifiant ; vide : la ligne n'en porte pas.
    pub noms: &'static [&'static str],
    /// Les codes de sortie qui veulent dire « fait ».
    pub reussites: &'static [i32],
    /// Ceux qui veulent dire « à finir au redémarrage » : ni fait ni échoué, la personne doit redémarrer.
    pub au_redemarrage: &'static [i32],
    pub fr: &'static str,
    pub en: &'static str,
}

/// 3010 : fait, redémarrage nécessaire (comme le script PowerShell le comptait déjà).
const FAIT: &[i32] = &[0, 3010];

/// Les fonctionnalités de Windows que Vanguard peut retirer : PowerShell 2.0 et le client SMBv1.
const FONCTIONS_A_RETIRER: &[&str] = &[
    "MicrosoftWindowsPowerShellV2Root",
    "MicrosoftWindowsPowerShellV2",
    "SMB1Protocol-Client",
];

/// La table fermée. Ce que le clic d'administrateur autorise pour une ligne `vanguard:programme`, ce sont ces
/// programmes-là, avec ces arguments-là.
pub(crate) static PROGRAMMES: &[Programme] = &[
    Programme {
        id: "dism-restorehealth",
        dossier: Dossier::Systeme32,
        exe: "dism.exe",
        arguments: &[
            Argument::Fixe("/Online"),
            Argument::Fixe("/Cleanup-Image"),
            Argument::Fixe("/RestoreHealth"),
        ],
        noms: &[],
        reussites: FAIT,
        au_redemarrage: &[],
        fr: "Réparer l'image de Windows (DISM)",
        en: "Repair the Windows image (DISM)",
    },
    Programme {
        id: "sfc-scannow",
        dossier: Dossier::Systeme32,
        exe: "sfc.exe",
        arguments: &[Argument::Fixe("/scannow")],
        noms: &[],
        reussites: FAIT,
        au_redemarrage: &[],
        fr: "Vérifier et réparer les fichiers système (SFC)",
        en: "Check and repair the system files (SFC)",
    },
    Programme {
        id: "chkdsk-scan-systeme",
        dossier: Dossier::Systeme32,
        exe: "chkdsk.exe",
        arguments: &[Argument::LecteurSysteme, Argument::Fixe("/scan")],
        noms: &[],
        // Microsoft (learn.microsoft.com, chkdsk) : 0 aucune erreur, 1 erreurs trouvées et corrigées, 2 nettoyage
        // fait ou non fait faute de /f ; 3 disque non vérifiable, erreurs non corrigeables ou non corrigées faute de
        // /f : la réparation demande le disque hors ligne, donc un redémarrage.
        reussites: &[0, 1, 2],
        au_redemarrage: &[3],
        fr: "Analyser le disque de Windows sans le bloquer (chkdsk /scan)",
        en: "Scan the Windows disk without locking it (chkdsk /scan)",
    },
    Programme {
        id: "netsh-winsock-reset",
        dossier: Dossier::Systeme32,
        exe: "netsh.exe",
        arguments: &[Argument::Fixe("winsock"), Argument::Fixe("reset")],
        noms: &[],
        reussites: FAIT,
        au_redemarrage: &[],
        fr: "Remettre Winsock à zéro",
        en: "Reset Winsock",
    },
    Programme {
        id: "netsh-ip-reset",
        dossier: Dossier::Systeme32,
        exe: "netsh.exe",
        arguments: &[Argument::Fixe("int"), Argument::Fixe("ip"), Argument::Fixe("reset")],
        noms: &[],
        reussites: FAIT,
        au_redemarrage: &[],
        fr: "Remettre la pile TCP/IP à zéro",
        en: "Reset the TCP/IP stack",
    },
    Programme {
        id: "w32tm-resync",
        dossier: Dossier::Systeme32,
        exe: "w32tm.exe",
        arguments: &[Argument::Fixe("/resync"), Argument::Fixe("/force")],
        noms: &[],
        reussites: FAIT,
        au_redemarrage: &[],
        fr: "Resynchroniser l'horloge (service de temps de Windows)",
        en: "Resynchronize the clock (Windows time service)",
    },
    Programme {
        id: "defender-signatures",
        dossier: Dossier::Defender,
        exe: "MpCmdRun.exe",
        arguments: &[Argument::Fixe("-SignatureUpdate")],
        noms: &[],
        reussites: &[0],
        au_redemarrage: &[],
        fr: "Mettre à jour les signatures de Microsoft Defender",
        en: "Update the Microsoft Defender signatures",
    },
    Programme {
        id: "dism-nettoyage-composants",
        dossier: Dossier::Systeme32,
        exe: "dism.exe",
        arguments: &[
            Argument::Fixe("/Online"),
            Argument::Fixe("/Cleanup-Image"),
            Argument::Fixe("/StartComponentCleanup"),
        ],
        noms: &[],
        reussites: FAIT,
        au_redemarrage: &[],
        fr: "Retirer les versions remplacées des composants de Windows (DISM)",
        en: "Remove the replaced versions of Windows components (DISM)",
    },
    Programme {
        id: "dism-retirer-fonction",
        dossier: Dossier::Systeme32,
        exe: "dism.exe",
        arguments: &[
            Argument::Fixe("/Online"),
            Argument::Fixe("/Disable-Feature"),
            Argument::Nom("/FeatureName:"),
            Argument::Fixe("/NoRestart"),
        ],
        noms: FONCTIONS_A_RETIRER,
        reussites: FAIT,
        au_redemarrage: &[],
        fr: "Retirer une fonctionnalité de Windows (DISM)",
        en: "Remove a Windows feature (DISM)",
    },
    Programme {
        id: "dism-ajouter-netfx3",
        dossier: Dossier::Systeme32,
        exe: "dism.exe",
        arguments: &[
            Argument::Fixe("/Online"),
            Argument::Fixe("/Enable-Feature"),
            Argument::Fixe("/FeatureName:NetFx3"),
            Argument::Fixe("/All"),
            Argument::Fixe("/NoRestart"),
        ],
        noms: &[],
        reussites: FAIT,
        au_redemarrage: &[],
        fr: "Installer .NET Framework 3.5 (DISM, par Windows Update)",
        en: "Install .NET Framework 3.5 (DISM, through Windows Update)",
    },
];

/// Une ligne `vanguard:programme`, relue : le programme de la table, et son nom s'il en prend un.
#[derive(Debug)]
pub(crate) struct Appel {
    pub programme: &'static Programme,
    pub nom: Option<&'static str>,
}

impl Appel {
    /// La ligne qui le demande, telle que le parent l'envoie.
    pub(crate) fn ligne(&self) -> String {
        match self.nom {
            Some(n) => format!("{PROGRAMME}{} {n}", self.programme.id),
            None => format!("{PROGRAMME}{}", self.programme.id),
        }
    }

    /// Les arguments, dans l'ordre, avec la lettre du lecteur de Windows donnée par le processus élevé.
    pub(crate) fn arguments(&self, lecteur: &str) -> Vec<String> {
        self.programme
            .arguments
            .iter()
            .map(|a| match a {
                Argument::Fixe(t) => (*t).to_string(),
                Argument::LecteurSysteme => lecteur.to_string(),
                Argument::Nom(prefixe) => format!("{prefixe}{}", self.nom.unwrap_or_default()),
            })
            .collect()
    }

    /// La commande à montrer : le programme et ses arguments, le lecteur sous son nom de variable.
    pub(crate) fn commande(&self) -> String {
        let mut c = self.programme.exe.to_string();
        for a in self.arguments("%SystemDrive%") {
            c.push(' ');
            c.push_str(&a);
        }
        c
    }

    /// L'équivalent PowerShell, pour le chemin par script (Wine) : le programme par son chemin complet, jamais par
    /// son seul nom, et ses autres codes de réussite remis à 0.
    pub(crate) fn powershell(&self) -> String {
        let dossier = match self.programme.dossier {
            Dossier::Systeme32 => r"$env:SystemRoot\System32".to_string(),
            Dossier::Defender => format!(r"$env:SystemDrive\{DOSSIER_DEFENDER}"),
        };
        let mut c = format!(r#"& "{dossier}\{}""#, self.programme.exe);
        for a in self.arguments("$env:SystemDrive") {
            c.push(' ');
            c.push_str(&a);
        }
        let autres: Vec<String> = self
            .programme
            .reussites
            .iter()
            .filter(|r| !FAIT.contains(r))
            .map(i32::to_string)
            .collect();
        if !autres.is_empty() {
            let _ = write!(
                c,
                "; if ($LASTEXITCODE -in {}) {{ $global:LASTEXITCODE = 0 }}",
                autres.join(", ")
            );
        }
        c
    }

    /// Ce code de sortie veut-il dire « fait » ?
    pub(crate) fn reussite(&self, code: i32) -> bool {
        self.programme.reussites.contains(&code)
    }

    /// Le code veut dire « à finir au redémarrage » (chkdsk 3), ni réussite ni échec.
    pub(crate) fn au_redemarrage(&self, code: i32) -> bool {
        self.programme.au_redemarrage.contains(&code)
    }
}

/// La ligne d'un programme de la table, pour un correctif ; `nom` seulement pour un programme qui en prend un.
pub(crate) fn ligne_programme(id: &str, nom: Option<&str>) -> String {
    let ligne = match nom {
        Some(n) => format!("{PROGRAMME}{id} {n}"),
        None => format!("{PROGRAMME}{id}"),
    };
    debug_assert!(analyser_programme(&ligne).is_some(), "programme inconnu : {ligne}");
    ligne
}

/// Le programme d'une ligne, si et seulement si elle est exactement de sa forme : `vanguard:programme <id>`, suivi
/// d'une espace et d'un nom de la liste fermée pour le seul programme qui en prend un. ASCII, 256 octets au plus,
/// sensible à la casse, réécrite à l'identique.
pub(crate) fn analyser_programme(ligne: &str) -> Option<Appel> {
    if ligne.len() > PROGRAMME_MAX || !ligne.is_ascii() {
        return None;
    }
    let reste = ligne.strip_prefix(PROGRAMME)?;
    let (id, nom) = match reste.split_once(' ') {
        Some((id, nom)) => (id, Some(nom)),
        None => (reste, None),
    };
    let programme = PROGRAMMES.iter().find(|p| p.id == id)?;
    let nom = match (nom, programme.noms.is_empty()) {
        (None, true) => None,
        (Some(n), false) => Some(*programme.noms.iter().find(|&&m| m == n)?),
        _ => return None,
    };
    let appel = Appel { programme, nom };
    (appel.ligne() == ligne).then_some(appel)
}

// ------------------------------------------------------------------ la liste

/// Une ligne de la liste, relue : celle d'un autre module (correction, ordre), un script ou un programme.
pub(crate) enum Ligne<E> {
    Autre(E),
    Script(Script),
    Programme(Appel),
}

/// La liste telle que le processus élevé la recevra, validée ligne à ligne, dans l'ordre ; `None` dès qu'une ligne
/// est trop longue, n'a pas sa forme, ou n'est pas reconnue par `autre`, qu'il y en a trop ou aucune, ou qu'un même
/// script (même empreinte) revient. Le parent l'appelle AVANT la demande d'administrateur, le processus élevé à la
/// réception : la même fonction des deux côtés. Un script seul est admis (une liste toute en PowerShell).
pub(crate) fn valider<E>(lignes: &[String], mut autre: impl FnMut(&str) -> Option<E>) -> Option<Vec<Ligne<E>>> {
    if lignes.is_empty() || lignes.len() > LIGNES_MAX {
        return None;
    }
    let mut empreintes = std::collections::HashSet::new();
    lignes
        .iter()
        .map(|l| {
            if l.len() > LIGNE_MAX {
                return None;
            }
            if l.starts_with(SCRIPT) {
                let s = analyser_script(l)?;
                return empreintes.insert(s.empreinte.clone()).then_some(Ligne::Script(s));
            }
            if l.starts_with(PROGRAMME) {
                return analyser_programme(l).map(Ligne::Programme);
            }
            autre(l).map(Ligne::Autre)
        })
        .collect()
}

// ---------------------------------------------------------------- la découpe

/// Un morceau d'une liste de correctifs : une suite de lignes natives (chacune désignée par son correctif et sa
/// place), ou un script fait des lignes PowerShell qui se suivent, correctif par correctif.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Morceau {
    Natif(Vec<(usize, usize)>),
    Script(Vec<(usize, Vec<usize>)>),
}

/// Découpe des correctifs en morceaux, dans l'ordre : chaque correctif est coupé là où il passe du natif au
/// PowerShell (le point de restauration en tête d'une réparation devient ainsi un geste natif à lui seul, avant le
/// script). Le résultat d'un correctif est le ET de ses morceaux ; un correctif vide n'en a aucun (rien à faire).
pub(crate) fn decouper(correctifs: &[Vec<String>], natif: impl Fn(&str) -> bool) -> Vec<Morceau> {
    let mut morceaux: Vec<Morceau> = Vec::new();
    for (i, c) in correctifs.iter().enumerate() {
        for (j, l) in c.iter().enumerate() {
            if natif(l) {
                match morceaux.last_mut() {
                    Some(Morceau::Natif(v)) => v.push((i, j)),
                    _ => morceaux.push(Morceau::Natif(vec![(i, j)])),
                }
                continue;
            }
            match morceaux.last_mut() {
                Some(Morceau::Script(v)) => match v.last_mut() {
                    Some((k, suite)) if *k == i => suite.push(j),
                    _ => v.push((i, vec![j])),
                },
                _ => morceaux.push(Morceau::Script(vec![(i, vec![j])])),
            }
        }
    }
    morceaux
}

// ---------------------------------------------------------------- les états

/// La réponse d'un script en échec : son code et l'état de chacun de ses correctifs (« 1 » fait, « 0 » non fait),
/// dans l'ordre, tels que le script les a écrits.
pub(crate) fn raison_du_script(code: i32, etats: &[bool]) -> String {
    let etats: String = etats
        .iter()
        .take(ETATS_MAX)
        .map(|&e| if e { '1' } else { '0' })
        .collect();
    format!("code={code} etats={etats}")
}

/// Les états d'une réponse « echec code=N etats=… » ; `None` : la réponse n'en porte pas (rien de sûr : tout est
/// « non fait »).
pub(crate) fn etats_du_script(reponse: &str) -> Option<Vec<bool>> {
    let (code, reste) = reponse.strip_prefix("echec code=")?.split_once(' ')?;
    code.parse::<i32>().ok()?;
    let etats = reste.strip_prefix("etats=")?.split(' ').next()?;
    if etats.len() > ETATS_MAX {
        return None;
    }
    etats
        .bytes()
        .map(|o| match o {
            b'1' => Some(true),
            b'0' => Some(false),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const POINT: &str = "vanguard:point-de-restauration";

    fn natif(l: &str) -> bool {
        l.starts_with("vanguard:") && !l.starts_with(SCRIPT)
    }

    fn lignes(l: &[&str]) -> Vec<String> {
        l.iter().map(|s| (*s).to_string()).collect()
    }

    /// Le bogue P0 : une réparation avec point de restauration (« Internet ne marche plus », DISM/sfc, Gaming) met
    /// le point EN TÊTE du même correctif que ses commandes PowerShell. Le correctif entier partait dans le script, la
    /// liste n'était faite que d'un script, et le processus élevé la refusait (« jamais seul ») après l'UAC. Le point
    /// doit être un geste natif à lui seul, avant le script.
    #[test]
    fn le_point_en_tete_est_un_morceau_a_lui() {
        let c = vec![lignes(&[POINT, "ipconfig /flushdns", "ipconfig /renew"])];
        assert_eq!(
            decouper(&c, natif),
            [Morceau::Natif(vec![(0, 0)]), Morceau::Script(vec![(0, vec![1, 2])])]
        );
    }

    #[test]
    fn la_decoupe_garde_l_ordre_et_chaque_ligne_une_fois() {
        let p = ligne_programme("sfc-scannow", None);
        // Natif seul : un seul morceau, sur plusieurs correctifs.
        let c = vec![lignes(&[POINT]), vec![p.clone(), p.clone()]];
        assert_eq!(decouper(&c, natif), [Morceau::Natif(vec![(0, 0), (1, 0), (1, 1)])]);
        // PowerShell seul : un seul script, un groupe par correctif ; un correctif vide n'a aucun morceau.
        let c = vec![lignes(&["a", "b"]), vec![], lignes(&["c"])];
        assert_eq!(
            decouper(&c, natif),
            [Morceau::Script(vec![(0, vec![0, 1]), (2, vec![0])])]
        );
        // Alternés, dans un même correctif et d'un correctif à l'autre.
        let c = vec![
            lignes(&["a", POINT, "b"]),
            lignes(&["c"]),
            vec![p.clone(), "d".to_string()],
        ];
        assert_eq!(
            decouper(&c, natif),
            [
                Morceau::Script(vec![(0, vec![0])]),
                Morceau::Natif(vec![(0, 1)]),
                Morceau::Script(vec![(0, vec![2]), (1, vec![0])]),
                Morceau::Natif(vec![(2, 0)]),
                Morceau::Script(vec![(2, vec![1])]),
            ]
        );
        assert_eq!(decouper(&[], natif), []);
    }

    fn empreinte(n: u8) -> String {
        format!("{n:02X}").repeat(32)
    }

    fn script(n: u8) -> String {
        ligne_script(
            &empreinte(n),
            &format!(r"C:\Users\a\AppData\Local\vanguard\corrections\correction-{n}.ps1"),
        )
    }

    fn valide(l: &[String]) -> bool {
        valider(l, |l| (l == POINT).then_some(())).is_some()
    }

    #[test]
    fn la_liste_hostile_est_refusee() {
        // Un script seul passe (liste toute en PowerShell), et deux scripts différents aussi ; le même deux fois, non.
        assert!(valide(&[script(1)]));
        assert!(valide(&[script(1), POINT.to_string(), script(2)]));
        assert!(!valide(&[script(1), script(1)]));
        let meme = ligne_script(&empreinte(1), r"C:\x\corrections\correction-autre.ps1");
        assert!(!valide(&[script(1), meme]));
        // Ni vide, ni trop longue (513 lignes), ni une ligne démesurée, ni une ligne inconnue.
        assert!(!valide(&[]));
        assert!(valide(&vec![ligne_programme("sfc-scannow", None); LIGNES_MAX]));
        assert!(!valide(&vec![ligne_programme("sfc-scannow", None); LIGNES_MAX + 1]));
        assert!(!valide(&[POINT.repeat(LIGNE_MAX)]));
        assert!(!valide(&[POINT.to_string(), "ipconfig /flushdns".to_string()]));
        // Les programmes : seulement la forme exacte.
        for l in [
            "vanguard:programme dism-restorehealth",
            "vanguard:programme chkdsk-scan-systeme",
            "vanguard:programme dism-retirer-fonction SMB1Protocol-Client",
            "vanguard:programme dism-retirer-fonction MicrosoftWindowsPowerShellV2Root",
        ] {
            assert!(valide(&[l.to_string()]), "{l}");
            assert_eq!(analyser_programme(l).map(|a| a.ligne()).as_deref(), Some(l));
        }
        for l in [
            "vanguard:programme inconnu",
            "vanguard:programme ",
            "vanguard:programme",
            "vanguard:programme  sfc-scannow",
            "vanguard:programme sfc-scannow ",
            "vanguard:programme sfc-scannow /offbootdir=C:\\",
            "vanguard:programme sfc-scannow x",
            "vanguard:programme SFC-SCANNOW",
            "VANGUARD:PROGRAMME sfc-scannow",
            "vanguard:programme sfc-scannow\0",
            "vanguard:programme sfc-scannow\n",
            "vanguard:programme ../sfc-scannow",
            "vanguard:programme ..\\System32\\cmd",
            "vanguard:programme dism-retirer-fonction",
            "vanguard:programme dism-retirer-fonction smb1protocol-client",
            "vanguard:programme dism-retirer-fonction SMB1Protocol-Client x",
            "vanguard:programme dism-retirer-fonction SMB1Protocol",
            "vanguard:programme dism-retirer-fonction Microsoft-Windows-Subsystem-Linux",
            "vanguard:programme dism-ajouter-netfx3 NetFx3",
            "vanguard:programme dism-restorehealth\u{a0}",
            "vanguard:programme aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(analyser_programme(l).is_none(), "{l:?}");
            assert!(!valide(&[l.to_string()]), "{l:?}");
        }
        assert!(analyser_programme(&format!("vanguard:programme {}", "a".repeat(PROGRAMME_MAX))).is_none());
    }

    #[test]
    fn la_table_est_bien_formee() {
        let mut ids = std::collections::HashSet::new();
        for p in PROGRAMMES {
            assert!(ids.insert(p.id), "{}", p.id);
            assert!(
                !p.id.is_empty()
                    && p.id.len() <= 40
                    && p.id
                        .bytes()
                        .all(|o| o.is_ascii_lowercase() || o.is_ascii_digit() || o == b'-'),
                "{}",
                p.id
            );
            assert!(p.reussites.contains(&0) && !p.fr.is_empty() && !p.en.is_empty());
            let a_un_nom = p.arguments.iter().any(|a| matches!(a, Argument::Nom(_)));
            assert_eq!(a_un_nom, !p.noms.is_empty(), "{}", p.id);
            // Ni séparateur ni espace dans un exe ou un argument : rien ne s'y glisse en passant par une ligne de
            // commande.
            assert!(p.exe.strip_suffix(".exe").is_some_and(|n| !n.is_empty()) && !p.exe.contains(['\\', '/', ' ']));
            for a in p.arguments {
                if let Argument::Fixe(t) | Argument::Nom(t) = a {
                    assert!(!t.is_empty() && !t.contains([' ', '"', '\'', ';', '&', '|']), "{t}");
                }
            }
        }
        for n in FONCTIONS_A_RETIRER {
            assert!(n.bytes().all(|o| o.is_ascii_alphanumeric() || o == b'-'), "{n}");
        }
    }

    /// Pour Wine (le chemin par script) : chaque programme par son chemin complet, jamais par son seul nom, que
    /// PowerShell chercherait dans le PATH.
    #[test]
    fn chaque_programme_a_son_equivalent_powershell_complet() {
        for p in PROGRAMMES {
            let nom = p.noms.first().copied();
            let a = analyser_programme(&ligne_programme(p.id, nom)).unwrap();
            let ps = a.powershell();
            let attendu = match p.dossier {
                Dossier::Systeme32 => format!(r#"& "$env:SystemRoot\System32\{}" "#, p.exe),
                Dossier::Defender => format!(r#"& "$env:SystemDrive\Program Files\Windows Defender\{}" "#, p.exe),
            };
            assert!(ps.starts_with(&attendu), "{ps}");
            assert!(!a.commande().contains('$'), "{}", a.commande());
        }
        let chkdsk = analyser_programme("vanguard:programme chkdsk-scan-systeme").unwrap();
        assert_eq!(
            chkdsk.powershell(),
            r#"& "$env:SystemRoot\System32\chkdsk.exe" $env:SystemDrive /scan; if ($LASTEXITCODE -in 1, 2) { $global:LASTEXITCODE = 0 }"#
        );
        assert_eq!(chkdsk.arguments("D:"), ["D:", "/scan"]);
        assert!(chkdsk.reussite(1) && chkdsk.reussite(2) && !chkdsk.reussite(3));
        // 3 : ni fait ni échoué, à finir au redémarrage ; aucun autre programme n'a ce troisième état.
        assert!(chkdsk.au_redemarrage(3) && !chkdsk.au_redemarrage(0) && !chkdsk.au_redemarrage(1));
        assert!(
            PROGRAMMES
                .iter()
                .all(|p| p.id == "chkdsk-scan-systeme" || p.au_redemarrage.is_empty())
        );
        assert!(
            PROGRAMMES
                .iter()
                .all(|p| p.au_redemarrage.iter().all(|c| !p.reussites.contains(c)))
        );
        let smb = analyser_programme("vanguard:programme dism-retirer-fonction SMB1Protocol-Client").unwrap();
        assert_eq!(
            smb.commande(),
            "dism.exe /Online /Disable-Feature /FeatureName:SMB1Protocol-Client /NoRestart"
        );
        assert!(smb.reussite(3010) && !smb.reussite(1));
    }

    #[test]
    fn le_script_a_une_forme_fixe() {
        let bon = script(0xAB);
        assert_eq!(
            analyser_script(&bon)
                .map(|s| ligne_script(&s.empreinte, &s.chemin))
                .as_deref(),
            Some(bon.as_str())
        );
        for chemin in [
            r"corrections\correction-1.ps1",
            r"C:\x\autre\correction-1.ps1",
            r"C:\x\corrections\script.ps1",
            r"C:\x\corrections\correction-1.ps1.txt",
            r"C:\x\corrections\..\corrections\correction-1.ps1",
            r"C:\x\corrections\.\correction-1.ps1",
            "C:\\x\\corrections\\correction-1.ps1\0",
        ] {
            assert!(
                analyser_script(&ligne_script(&empreinte(1), chemin)).is_none(),
                "{chemin}"
            );
        }
        let hex_majuscule = bon.replace("5c", "5C");
        assert!(analyser_script(&hex_majuscule).is_none());
        assert!(analyser_script(&bon.replacen(&empreinte(0xAB), &empreinte(0xAB).to_lowercase(), 1)).is_none());
        assert!(analyser_script(&format!("{bon}0")).is_none());
        assert!(analyser_script(&format!("{bon} ")).is_none());
    }

    #[test]
    fn les_etats_se_lisent() {
        assert_eq!(raison_du_script(1, &[true, false, true]), "code=1 etats=101");
        assert_eq!(etats_du_script("echec code=1 etats=101"), Some(vec![true, false, true]));
        assert_eq!(etats_du_script("echec code=-1 etats="), Some(vec![]));
        assert_eq!(etats_du_script("echec code=1 etats=10 suite"), Some(vec![true, false]));
        for r in [
            "ok",
            "echec code=6 script modifié",
            "echec code=x etats=1",
            "echec code=1 etats=12",
            "echec etats=1",
            "echec code=1  etats=1",
        ] {
            assert_eq!(etats_du_script(r), None, "{r}");
        }
        let long = format!("echec code=1 etats={}", "1".repeat(ETATS_MAX + 1));
        assert_eq!(etats_du_script(&long), None);
        assert_eq!(
            raison_du_script(1, &vec![true; ETATS_MAX + 9]).len(),
            "code=1 etats=".len() + ETATS_MAX
        );
    }

    /// Les bornes recopiées ici (module sans dépendance, pour le banc de fuzzing) restent celles des ordres.
    #[test]
    fn les_bornes_sont_celles_des_ordres() {
        use crate::protection::blocage::ordres;
        assert_eq!(LIGNE_MAX, ordres::LIGNE_MAX);
        assert_eq!(LIGNES_MAX, ordres::LIGNES_MAX);
    }
}

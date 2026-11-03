//! Désactiver un programme de démarrage de toute la machine comme le Gestionnaire des tâches, sans rien retirer : sa
//! valeur dans HKLM\…\Explorer\StartupApproved (Run, Run32 ou StartupFolder), par le processus élevé, sans PowerShell
//! (lot 3.5, passe b, R52). La ligne désigne, le processus élevé juge : le lancement est relu ici (la valeur Run, ou
//! le fichier du dossier Démarrage commun), jamais une entrée de Windows ou de Defender (`gestes::run_protege`) ni ce
//! qu'Optimiser garde (`optimiser::a_garder` : sécurité, pilotes, accessibilité, Vanguard). Les octets d'avant (ou
//! leur absence) et ceux qui sont écrits sont notés dans `gestes::LANCEMENT_AVANT_CLE` avant l'écriture. La
//! réactivation remet exactement les octets d'avant, seulement si la valeur est encore celle que Vanguard a écrite.

use std::io::ErrorKind::NotFound;

use winreg::enums::RegType::REG_BINARY;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY};
use winreg::{RegKey, RegValue};

use super::corrections::{Resultat, avant_notable};
use crate::machine::gestes::{self, CleRun, LancementMachine, ListeLancement, ValeurDesactivee};
use crate::ui::{tr, trf};

/// Où Windows note les programmes de démarrage de la machine désactivés.
const APPROUVES: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";

fn refus(raison: String) -> Resultat {
    Resultat::echec(None, raison)
}

/// Le nom de la note : la liste et le nom en hexadécimal, les mêmes pour la désactivation et la réactivation.
fn nom_note(l: &LancementMachine) -> String {
    gestes::Acte::LancementReactiver(l.clone())
        .ligne()
        .strip_prefix(gestes::LANCEMENT_REACTIVER)
        .unwrap_or_default()
        .to_string()
}

/// La note : 0 (pas de valeur avant) ou 1 suivi de la longueur (4 octets, petit-boutiste) et de la valeur d'avant
/// (`run_ecriture::note` : son type et ses octets), puis les octets écrits par Vanguard.
fn note(avant: Option<&RegValue>, ecrite: &[u8]) -> Option<Vec<u8>> {
    let mut n = Vec::new();
    match avant {
        None => n.push(0),
        Some(a) => {
            let v = super::run_ecriture::note(&a.vtype, &a.bytes)?;
            n.push(1);
            n.extend_from_slice(&u32::try_from(v.len()).ok()?.to_le_bytes());
            n.extend_from_slice(&v);
        }
    }
    n.extend_from_slice(ecrite);
    Some(n)
}

/// La valeur d'avant (`None` : il n'y en avait pas) et les octets écrits ; `None` si la note n'a pas cette forme.
fn lire_note(n: &[u8]) -> Option<(Option<RegValue<'static>>, Vec<u8>)> {
    let (&presente, reste) = n.split_first()?;
    match presente {
        0 => Some((None, reste.to_vec())),
        1 => {
            let (longueur, reste) = reste.split_first_chunk::<4>()?;
            let longueur = usize::try_from(u32::from_le_bytes(*longueur)).ok()?;
            let (avant, ecrite) = reste.split_at_checked(longueur)?;
            let (vtype, bytes) = super::run_ecriture::lire_note(avant)?;
            Some((
                Some(RegValue {
                    bytes: bytes.into(),
                    vtype,
                }),
                ecrite.to_vec(),
            ))
        }
        _ => None,
    }
}

/// La liste de StartupApproved, ouverte (créée pour écrire) dans la vue 64 bits ; `Ok(None)` si elle n'existe pas.
fn approuvee(l: ListeLancement, creer: bool) -> Result<Option<RegKey>, Resultat> {
    let chemin = format!(r"{APPROUVES}\{}", l.approuvee());
    let racine = RegKey::predef(HKEY_LOCAL_MACHINE);
    let drapeaux = KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY;
    let ouverte = if creer {
        racine.create_subkey_with_flags(&chemin, drapeaux).map(|(k, _)| k)
    } else {
        racine.open_subkey_with_flags(&chemin, drapeaux)
    };
    match ouverte {
        Ok(k) => Ok(Some(k)),
        Err(e) if e.kind() == NotFound => Ok(None),
        Err(e) => Err(refus(trf!(
            "HKLM\\{chemin} ne s'ouvre pas ({e}) : rien d'écrit",
            "HKLM\\{chemin} cannot be opened ({e}): nothing written"
        ))),
    }
}

/// La valeur actuelle de StartupApproved ; `Ok(None)` si elle n'existe pas.
fn valeur(cle: Option<&RegKey>, nom: &str) -> Result<Option<RegValue<'static>>, Resultat> {
    let Some(cle) = cle else {
        return Ok(None);
    };
    match cle.get_raw_value(nom) {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.kind() == NotFound => Ok(None),
        Err(e) => Err(refus(trf!(
            "la valeur de StartupApproved ne se lit pas ({e}) : rien d'écrit",
            "the StartupApproved value cannot be read ({e}): nothing written"
        ))),
    }
}

fn meme(a: Option<&RegValue>, b: Option<&RegValue>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => super::run_ecriture::meme(a, b),
        _ => false,
    }
}

fn binaire(octets: &[u8]) -> RegValue<'static> {
    RegValue {
        bytes: octets.to_vec().into(),
        vtype: REG_BINARY,
    }
}

/// Désactivée pour Windows : premier octet impair (03, 07…).
fn desactivee(v: Option<&RegValue>) -> bool {
    v.and_then(|v| v.bytes.first()).is_some_and(|b| b & 1 == 1)
}

fn hex_ou_absente(v: Option<&RegValue>) -> String {
    v.map_or_else(
        || tr!("absente", "absent").to_string(),
        |v| {
            use std::fmt::Write;
            v.bytes.iter().fold(String::new(), |mut s, o| {
                let _ = write!(s, "{o:02x}");
                s
            })
        },
    )
}

/// Ce que lance ce programme, relu ici : (programme, commande), comme Optimiser les montre ; `Ok(None)` s'il n'est
/// plus là.
fn lancement(l: &LancementMachine) -> Result<Option<(String, String)>, Resultat> {
    let illisible = |e: &dyn std::fmt::Display| {
        refus(trf!(
            "le lancement ne se relit pas ({e}) : rien d'écrit",
            "the startup entry cannot be read again ({e}): nothing written"
        ))
    };
    match l.liste() {
        ListeLancement::Run | ListeLancement::Run32 => {
            let cle = if l.liste() == ListeLancement::Run {
                CleRun::Run
            } else {
                CleRun::Run32
            };
            let cle = match RegKey::predef(HKEY_LOCAL_MACHINE)
                .open_subkey_with_flags(cle.chemin(), KEY_QUERY_VALUE | KEY_WOW64_64KEY)
            {
                Ok(k) => k,
                Err(e) if e.kind() == NotFound => return Ok(None),
                Err(e) => return Err(illisible(&e)),
            };
            match cle.get_raw_value(l.nom()) {
                Ok(v) => {
                    let (programme, _) = crate::commande::decouper_commande(&super::persistance::texte_valeur(&v));
                    Ok(Some((programme, v.to_string())))
                }
                Err(e) if e.kind() == NotFound => Ok(None),
                Err(e) => Err(illisible(&e)),
            }
        }
        ListeLancement::Dossier => {
            let Some(dossier) = super::environnement::demarrage_commun() else {
                return Err(refus(
                    tr!(
                        "dossier Démarrage commun introuvable : rien d'écrit",
                        "common Startup folder not found: nothing written"
                    )
                    .to_string(),
                ));
            };
            let chemin = dossier.join(l.nom());
            // Ouvert une seule fois sans suivre de lien : ce qui est jugé puis lu est ce même fichier, jamais la cible
            // d'un lien ou d'une jonction posé entre deux regards.
            let fichier = {
                use std::os::windows::fs::OpenOptionsExt as _;
                const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
                match std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(&chemin)
                {
                    Ok(f) => f,
                    Err(e) if e.kind() == NotFound => return Ok(None),
                    Err(e) => return Err(illisible(&e)),
                }
            };
            let ordinaire = fichier.metadata().is_ok_and(|m| {
                use std::os::windows::fs::MetadataExt as _;
                const ATTRIBUT_POINT_D_ANALYSE: u32 = 0x400;
                m.is_file() && m.file_attributes() & ATTRIBUT_POINT_D_ANALYSE == 0
            });
            if !ordinaire {
                return Err(refus(
                    tr!(
                        "ce n'est pas un fichier ordinaire du dossier Démarrage commun (lien ou dossier) : rien d'écrit",
                        "this is not a plain file of the common Startup folder (link or folder): nothing written"
                    )
                    .to_string(),
                ));
            }
            let plein = chemin.display().to_string();
            // Ce que lance un raccourci : sa cible, lue sans COM ; illisible, refusé (il pourrait viser Defender).
            let octets = if plein.to_lowercase().ends_with(".lnk") {
                use std::io::Read as _;
                let mut o = Vec::new();
                (&fichier)
                    .take(1 << 20)
                    .read_to_end(&mut o)
                    .map_err(|e| illisible(&e))?;
                o
            } else {
                Vec::new()
            };
            let Some(cible) = super::persistance::cible_demarrage(&plein, &octets) else {
                return Err(refus(
                    tr!(
                        "raccourci illisible sans COM : rien d'écrit",
                        "shortcut unreadable without COM: nothing written"
                    )
                    .to_string(),
                ));
            };
            let (programme, _) = crate::commande::decouper_commande(&cible);
            Ok(Some((programme, format!("{plein} {cible}"))))
        }
    }
}

/// Pourquoi ce lancement ne se désactive jamais : une entrée de Windows ou de Defender, ou ce qu'Optimiser garde.
fn refus_lancement(nom: &str, programme: &str, commande: &str) -> Option<String> {
    if gestes::run_protege(nom, programme) {
        return Some(
            tr!(
                "entrée de Sécurité Windows ou de Defender : Vanguard ne la désactive jamais ; rien d'écrit",
                "Windows Security or Defender entry: Vanguard never disables it; nothing written"
            )
            .to_string(),
        );
    }
    crate::optimiser::a_garder(nom, commande, false).map(|pourquoi| {
        trf!(
            "programme à garder ({pourquoi}) : rien d'écrit",
            "program to keep ({pourquoi}): nothing written"
        )
    })
}

/// Dans le processus élevé : désactive le programme `l` en écrivant `v` dans StartupApproved, comme le Gestionnaire
/// des tâches, si le lancement est encore là et n'est ni de Windows, ni de Defender, ni gardé par Optimiser.
pub(super) fn desactiver(l: &LancementMachine, v: &ValeurDesactivee) -> Resultat {
    let (programme, commande) = match lancement(l) {
        Ok(Some(p)) => p,
        Ok(None) => {
            return Resultat::rien(
                tr!(
                    "ce programme ne se lance plus au démarrage : rien à désactiver",
                    "this program no longer starts with Windows: nothing to disable"
                )
                .to_string(),
            );
        }
        Err(r) => return r,
    };
    if let Some(pourquoi) = refus_lancement(l.nom(), &programme, &commande) {
        return refus(pourquoi);
    }
    let cle = match approuvee(l.liste(), true) {
        Ok(Some(k)) => k,
        Ok(None) => {
            return refus(
                tr!(
                    "StartupApproved ne se crée pas : rien d'écrit",
                    "StartupApproved cannot be created: nothing written"
                )
                .to_string(),
            );
        }
        Err(r) => return r,
    };
    let avant = match valeur(Some(&cle), l.nom()) {
        Ok(a) => a,
        Err(r) => return r,
    };
    if desactivee(avant.as_ref()) {
        return Resultat::rien(
            tr!(
                "déjà désactivé au démarrage : rien à faire",
                "already disabled at startup: nothing to do"
            )
            .to_string(),
        );
    }
    let Some(donnee) = note(avant.as_ref(), v.octets()) else {
        return refus(
            tr!(
                "valeur d'avant que Vanguard ne sait pas noter : rien d'écrit",
                "previous value Vanguard cannot note: nothing written"
            )
            .to_string(),
        );
    };
    // Notée d'abord : sans note, pas d'écriture (la remise exacte serait perdue).
    let notes = RegKey::predef(HKEY_LOCAL_MACHINE)
        .create_subkey_with_flags(gestes::LANCEMENT_AVANT_CLE, KEY_SET_VALUE | KEY_WOW64_64KEY)
        .map(|(k, _)| k);
    let nom_note = nom_note(l);
    if let Err(e) = notes.as_ref().map(|k| k.set_raw_value(&nom_note, &binaire(&donnee))) {
        return refus(trf!(
            "les octets d'avant ne se notent pas ({e}) : rien d'écrit",
            "the previous bytes cannot be noted ({e}): nothing written"
        ));
    }
    let effacer_note = || {
        if let Ok(k) = &notes {
            let _ = k.delete_value(&nom_note);
        }
    };
    // Relue juste avant : jamais par-dessus une valeur qu'un programme aurait mise depuis la lecture.
    if !valeur(Some(&cle), l.nom()).is_ok_and(|encore| meme(encore.as_ref(), avant.as_ref())) {
        effacer_note();
        return refus(
            tr!(
                "la valeur a changé entre la lecture et l'écriture ; rien d'écrit",
                "the value changed between reading and writing; nothing written"
            )
            .to_string(),
        );
    }
    let montre = avant_notable(&hex_ou_absente(avant.as_ref()));
    let voulue = binaire(v.octets());
    if let Err(e) = cle.set_raw_value(l.nom(), &voulue) {
        effacer_note();
        return refus(e.to_string());
    }
    match valeur(Some(&cle), l.nom()) {
        Ok(Some(relue)) if super::run_ecriture::meme(&relue, &voulue) => Resultat::fait(montre),
        _ => Resultat::echec(
            Some(montre),
            tr!(
                "la valeur relue n'est pas celle écrite ; la note est gardée",
                "the value read back is not the one written; the note is kept"
            )
            .to_string(),
        ),
    }
}

/// Dans le processus élevé : remet exactement les octets que `desactiver` a notés pour `l` (ou retire la valeur s'il
/// n'y en avait pas), seulement si la valeur est encore celle que Vanguard a écrite ; la note est effacée après
/// relecture.
pub(super) fn reactiver(l: &LancementMachine) -> Resultat {
    let nom_note = nom_note(l);
    let notes = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(
        gestes::LANCEMENT_AVANT_CLE,
        KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY,
    );
    let lue = notes
        .as_ref()
        .ok()
        .and_then(|k| k.get_raw_value(&nom_note).ok())
        .filter(|n| n.vtype == REG_BINARY)
        .and_then(|n| lire_note(&n.bytes));
    let (Ok(notes), Some((avant, ecrite))) = (notes, lue) else {
        return refus(
            tr!(
                "aucun état d'avant noté par Vanguard pour ce programme : rien d'écrit",
                "no previous state noted by Vanguard for this program: nothing written"
            )
            .to_string(),
        );
    };
    let effacer_note = || {
        let _ = notes.delete_value(&nom_note);
    };
    let cle = match approuvee(l.liste(), false) {
        Ok(k) => k,
        Err(r) => return r,
    };
    let actuelle = match valeur(cle.as_ref(), l.nom()) {
        Ok(a) => a,
        Err(r) => return r,
    };
    if meme(actuelle.as_ref(), avant.as_ref()) {
        effacer_note();
        return Resultat::rien(
            tr!(
                "l'état d'avant est déjà là : rien à remettre",
                "the previous state is already there: nothing to put back"
            )
            .to_string(),
        );
    }
    let ecrite = binaire(&ecrite);
    if !meme(actuelle.as_ref(), Some(&ecrite)) {
        return refus(
            tr!(
                "la valeur a changé depuis que Vanguard l'a écrite : rien d'écrit (à régler dans le Gestionnaire des tâches)",
                "the value changed since Vanguard wrote it: nothing written (set it in Task Manager)"
            )
            .to_string(),
        );
    }
    let Some(cle) = cle else {
        return refus(
            tr!(
                "StartupApproved a disparu : rien d'écrit",
                "StartupApproved is gone: nothing written"
            )
            .to_string(),
        );
    };
    let montre = avant_notable(&hex_ou_absente(Some(&ecrite)));
    let ecrit = match &avant {
        Some(a) => cle.set_raw_value(l.nom(), a),
        None => cle.delete_value(l.nom()),
    };
    if let Err(e) = ecrit {
        return Resultat::echec(Some(montre), e.to_string());
    }
    match valeur(Some(&cle), l.nom()) {
        Ok(relue) if meme(relue.as_ref(), avant.as_ref()) => {
            effacer_note();
            Resultat::fait(montre)
        }
        _ => Resultat::echec(
            Some(montre),
            tr!(
                "la valeur relue n'est pas celle notée ; la note est gardée",
                "the value read back is not the noted one; the note is kept"
            )
            .to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use winreg::enums::RegType::{REG_DWORD, REG_SZ};

    #[test]
    fn la_note_garde_l_avant_et_l_ecrit() {
        let ecrite = [3u8, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(lire_note(&note(None, &ecrite).unwrap()), Some((None, ecrite.to_vec())));
        for (t, o) in [
            (REG_BINARY, vec![2u8, 0, 0, 0]),
            (REG_DWORD, vec![6, 0, 0, 0]),
            (REG_SZ, vec![]),
        ] {
            let a = RegValue {
                bytes: o.clone().into(),
                vtype: t.clone(),
            };
            let (avant, e) = lire_note(&note(Some(&a), &ecrite).unwrap()).unwrap();
            let avant = avant.unwrap();
            assert_eq!((avant.vtype, avant.bytes.to_vec(), e), (t, o, ecrite.to_vec()));
        }
        // Formes refusées : vide, drapeau inconnu, longueur au-delà de la note.
        assert_eq!(lire_note(&[]), None);
        assert_eq!(lire_note(&[2, 3]), None);
        assert_eq!(lire_note(&[1, 50, 0, 0, 0, 3, 0, 0, 0]), None);
    }

    #[test]
    fn desactivee_comme_windows() {
        assert!(!desactivee(None));
        assert!(desactivee(Some(&binaire(&[3, 0]))));
        assert!(desactivee(Some(&binaire(&[7]))));
        assert!(!desactivee(Some(&binaire(&[2, 0]))));
        assert!(!desactivee(Some(&binaire(&[]))));
    }

    #[test]
    fn refus_lancement_garde_windows_defender_et_optimiser() {
        let sh = r"C:\Windows\System32\SecurityHealthSystray.exe";
        assert!(refus_lancement("SecurityHealth", sh, sh).is_some());
        // Un autre nom ne suffit pas à faire passer le programme de Sécurité Windows.
        assert!(refus_lancement("Mise a jour", sh, sh).is_some());
        let mp = r"C:\Program Files\Windows Defender\MSASCuiL.exe";
        assert!(refus_lancement("Windows Defender", mp, mp).is_some());
        // Ce qu'Optimiser garde : un pilote, Vanguard lui-même.
        let rt = r"C:\Program Files\Realtek\Audio\RtkNGUI64.exe";
        assert!(refus_lancement("RTHDVCPL", rt, rt).is_some());
        let vg = r"C:\Outils\vanguard.exe";
        assert!(refus_lancement("Vanguard", vg, vg).is_some());
        // Un programme quelconque peut être désactivé.
        let x = r"C:\Program Files\Exemple\exemple.exe";
        assert!(refus_lancement("Exemple", x, x).is_none());
    }
}

//! Le retrait d'une valeur de démarrage de la machine (HKLM Run, RunOnce, Run des programmes 32 bits), par le
//! processus élevé, sans PowerShell (lot 3.5, passe a). La ligne désigne, le processus élevé juge : la valeur est
//! relue ici, jamais une entrée de Windows ou de Defender (`gestes::run_protege`), rejugée par les fonctions du bilan
//! (persistance suspecte, ou outil de prise en main à distance qui n'est plus installé), relue encore juste avant le
//! retrait, sa donnée exacte (type et octets) notée dans `gestes::RUN_AVANT_CLE`, puis retirée et relue absente. La
//! remise (`run-remettre`) ne remet que ce que le processus élevé a noté lui-même, jamais par-dessus une valeur
//! présente.

use std::ffi::OsString;
use std::io::ErrorKind::NotFound;
use std::os::windows::ffi::OsStringExt;

use winreg::enums::RegType::{REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_QWORD, REG_SZ};
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY, RegType};
use winreg::{RegKey, RegValue};

use super::corrections::{Resultat, avant_notable};
use crate::machine::gestes::{self, Acte, ValeurRunMachine};
use crate::ui::{tr, trf};

/// Le code Windows d'un type de valeur que la note sait garder ; `None` pour un autre (une valeur Run d'un autre type
/// ne lance rien que le bilan juge, elle n'arrive pas jusqu'ici).
fn code_type(t: &RegType) -> Option<u32> {
    match t {
        REG_SZ => Some(1),
        REG_EXPAND_SZ => Some(2),
        REG_BINARY => Some(3),
        REG_DWORD => Some(4),
        REG_MULTI_SZ => Some(7),
        REG_QWORD => Some(11),
        _ => None,
    }
}

fn type_du_code(c: u32) -> Option<RegType> {
    match c {
        1 => Some(REG_SZ),
        2 => Some(REG_EXPAND_SZ),
        3 => Some(REG_BINARY),
        4 => Some(REG_DWORD),
        7 => Some(REG_MULTI_SZ),
        11 => Some(REG_QWORD),
        _ => None,
    }
}

/// La note d'une valeur retirée : le code de son type (4 octets, petit-boutiste) puis ses octets exacts.
fn note(t: &RegType, octets: &[u8]) -> Option<Vec<u8>> {
    let mut n = code_type(t)?.to_le_bytes().to_vec();
    n.extend_from_slice(octets);
    Some(n)
}

/// Le type et les octets d'une note ; `None` si elle n'est pas de cette forme.
fn lire_note(n: &[u8]) -> Option<(RegType, Vec<u8>)> {
    let (code, octets) = n.split_first_chunk::<4>()?;
    Some((type_du_code(u32::from_le_bytes(*code))?, octets.to_vec()))
}

/// Le nom de la note d'une valeur : la ligne sans son verbe (« <clé> <nom en hex|defaut> »), le même pour le retrait
/// et la remise.
fn nom_note(v: &ValeurRunMachine) -> Option<String> {
    Acte::RunRetirer(v.clone())
        .ligne()
        .strip_prefix(gestes::RUN_RETIRER_MACHINE)
        .map(str::to_string)
}

fn refus(raison: String) -> Resultat {
    Resultat::echec(None, raison)
}

/// La clé Run de la machine, ouverte en lecture et écriture dans la vue 64 bits (WOW6432Node y est nommé) ;
/// `Ok(None)` si elle n'existe pas.
fn ouvrir(v: &ValeurRunMachine, creer: bool) -> Result<Option<RegKey>, Resultat> {
    let racine = RegKey::predef(HKEY_LOCAL_MACHINE);
    let drapeaux = KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY;
    let chemin = v.cle.chemin();
    let ouverte = if creer {
        racine.create_subkey_with_flags(chemin, drapeaux).map(|(k, _)| k)
    } else {
        racine.open_subkey_with_flags(chemin, drapeaux)
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

/// Les mêmes type et octets ?
fn meme(a: &RegValue, b: &RegValue) -> bool {
    a.vtype == b.vtype && a.bytes == b.bytes
}

/// Dans le processus élevé : retire la valeur `v` si et seulement si le bilan, refait ici sur la valeur relue à cet
/// instant, la signale et propose cette même ligne. Plus de valeur : rien à faire, rien d'écrit.
pub(super) fn retirer(v: &ValeurRunMachine) -> Resultat {
    let ligne = Acte::RunRetirer(v.clone()).ligne();
    let Some(nom_note) = nom_note(v) else {
        return refus(tr!("ligne mal formée : rien d'écrit", "malformed line: nothing written").to_string());
    };
    let cle = match ouvrir(v, false) {
        Ok(Some(k)) => k,
        Ok(None) => {
            return Resultat::rien(
                tr!(
                    "la clé n'existe plus : rien à retirer",
                    "the key no longer exists: nothing to remove"
                )
                .to_string(),
            );
        }
        Err(r) => return r,
    };
    let nom = OsString::from_wide(v.nom.unites());
    let lue = match cle.get_raw_value(&nom) {
        Ok(l) => l,
        Err(e) if e.kind() == NotFound => {
            return Resultat::rien(
                tr!(
                    "la valeur n'est plus là : rien à retirer",
                    "the value is no longer there: nothing to remove"
                )
                .to_string(),
            );
        }
        Err(e) => {
            return refus(trf!(
                "la valeur ne se lit pas ({e}) : rien d'écrit",
                "the value cannot be read ({e}): nothing written"
            ));
        }
    };
    let texte = super::persistance::texte_valeur(&lue);
    let (programme, _) = crate::commande::decouper_commande(&texte);
    if gestes::run_protege(&String::from_utf16_lossy(v.nom.unites()), &programme) {
        return refus(
            tr!(
                "entrée de Sécurité Windows ou de Defender : Vanguard ne la retire jamais (à vérifier à la main) ; rien d'écrit",
                "Windows Security or Defender entry: Vanguard never removes it (check it by hand); nothing written"
            )
            .to_string(),
        );
    }
    if !super::persistance::run_signale(v.cle, v.nom.unites(), &lue, &ligne)
        && !crate::protection::distance::retrait_propose(&ligne)
    {
        return refus(
            tr!(
                "le bilan refait ici ne signale pas cette valeur : rien d'écrit",
                "the check run again here does not report this value: nothing written"
            )
            .to_string(),
        );
    }
    let Some(donnee) = note(&lue.vtype, &lue.bytes) else {
        return refus(
            tr!(
                "type de valeur que Vanguard ne sait pas noter : rien d'écrit",
                "value type Vanguard cannot note: nothing written"
            )
            .to_string(),
        );
    };
    // Relue juste avant : le jugement porte sur ces octets-là, jamais sur ceux qu'un programme aurait mis depuis.
    match cle.get_raw_value(&nom) {
        Ok(encore) if meme(&encore, &lue) => {}
        _ => {
            return refus(
                tr!(
                    "la valeur a changé entre la lecture et l'écriture ; rien d'écrit",
                    "the value changed between reading and writing; nothing written"
                )
                .to_string(),
            );
        }
    }
    // Notée d'abord : sans note, pas de retrait (la remise exacte serait perdue).
    let notee = RegKey::predef(HKEY_LOCAL_MACHINE)
        .create_subkey_with_flags(gestes::RUN_AVANT_CLE, KEY_SET_VALUE | KEY_WOW64_64KEY)
        .and_then(|(k, _)| {
            k.set_raw_value(
                &nom_note,
                &RegValue {
                    bytes: donnee.into(),
                    vtype: REG_BINARY,
                },
            )
        });
    if let Err(e) = notee {
        return refus(trf!(
            "la donnée d'avant ne se note pas ({e}) : rien d'écrit",
            "the previous data cannot be noted ({e}): nothing written"
        ));
    }
    let avant = avant_notable(&texte);
    if let Err(e) = cle.delete_value(&nom)
        && e.kind() != NotFound
    {
        return Resultat::echec(Some(avant), e.to_string());
    }
    match cle.get_raw_value(&nom) {
        Err(e) if e.kind() == NotFound => Resultat::fait(avant),
        _ => Resultat::echec(
            Some(avant),
            tr!(
                "la valeur est toujours là après son retrait",
                "the value is still there after its removal"
            )
            .to_string(),
        ),
    }
}

/// Dans le processus élevé : remet exactement la donnée que `retirer` a notée pour `v`, jamais par-dessus une valeur
/// présente ; la note est effacée une fois la valeur relue identique.
pub(super) fn remettre(v: &ValeurRunMachine) -> Resultat {
    let Some(nom_note) = nom_note(v) else {
        return refus(tr!("ligne mal formée : rien d'écrit", "malformed line: nothing written").to_string());
    };
    let notes = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(gestes::RUN_AVANT_CLE, KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY);
    let lue_dans_la_note = notes
        .as_ref()
        .ok()
        .and_then(|k| k.get_raw_value(&nom_note).ok())
        .filter(|n| n.vtype == REG_BINARY)
        .and_then(|n| lire_note(&n.bytes));
    let (Ok(notes), Some((vtype, octets))) = (notes, lue_dans_la_note) else {
        return refus(
            tr!(
                "aucune donnée notée par Vanguard pour cette valeur : rien d'écrit",
                "no data noted by Vanguard for this value: nothing written"
            )
            .to_string(),
        );
    };
    let effacer_note = || {
        let _ = notes.delete_value(&nom_note);
    };
    let attendue = RegValue {
        bytes: octets.into(),
        vtype,
    };
    let cle = match ouvrir(v, true) {
        Ok(Some(k)) => k,
        Ok(None) => {
            return refus(
                tr!(
                    "la clé ne se crée pas : rien d'écrit",
                    "the key cannot be created: nothing written"
                )
                .to_string(),
            );
        }
        Err(r) => return r,
    };
    let nom = OsString::from_wide(v.nom.unites());
    match cle.get_raw_value(&nom) {
        Ok(presente) if meme(&presente, &attendue) => {
            effacer_note();
            return Resultat::rien(
                tr!(
                    "la valeur est déjà là, identique : rien à remettre",
                    "the value is already there, identical: nothing to put back"
                )
                .to_string(),
            );
        }
        Ok(_) => {
            return refus(
                tr!(
                    "une autre valeur porte déjà ce nom : Vanguard n'écrit jamais par-dessus ; rien d'écrit",
                    "another value already has this name: Vanguard never writes over it; nothing written"
                )
                .to_string(),
            );
        }
        Err(e) if e.kind() == NotFound => {}
        Err(e) => {
            return refus(trf!(
                "la valeur ne se lit pas ({e}) : rien d'écrit",
                "the value cannot be read ({e}): nothing written"
            ));
        }
    }
    if let Err(e) = cle.set_raw_value(&nom, &attendue) {
        return refus(e.to_string());
    }
    match cle.get_raw_value(&nom) {
        Ok(relue) if meme(&relue, &attendue) => {
            effacer_note();
            Resultat::fait(tr!("absente", "absent").to_string())
        }
        _ => Resultat::echec(
            Some(tr!("absente", "absent").to_string()),
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

    #[test]
    fn la_note_garde_type_et_octets() {
        for t in [REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD] {
            let octets = [0x43u8, 0, 0x3a, 0, 0, 0];
            let n = note(&t, &octets).expect("type noté");
            assert_eq!(lire_note(&n), Some((t, octets.to_vec())));
        }
        // Un type que la note ne garde pas, une note trop courte ou d'un code inconnu : rien.
        assert_eq!(note(&RegType::REG_NONE, &[1]), None);
        assert_eq!(lire_note(&[1, 0, 0]), None);
        assert_eq!(lire_note(&[5, 0, 0, 0, 1]), None);
        // Une valeur vide se note aussi.
        assert_eq!(lire_note(&note(&REG_SZ, &[]).unwrap()), Some((REG_SZ, Vec::new())));
    }
}

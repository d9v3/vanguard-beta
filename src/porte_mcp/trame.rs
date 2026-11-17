//! Le découpage des messages de la porte : une ligne terminée par `\n` (un `\r` juste avant est retiré), bornée
//! pendant la lecture. Un client qui envoie une ligne sans fin ne fait jamais grossir la mémoire au-delà de la
//! borne : la lecture s'arrête dès qu'elle la passe, sans attendre la fin de la ligne. Pur, sans `crate::` : le banc
//! de fuzzing l'inclut tel quel (fuzz/fuzz_targets/porte_mcp.rs).

#![forbid(unsafe_code)]
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::io::BufRead;

/// Ce que donne une lecture.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Lu {
    /// Une ligne entière, sans son `\n` ni le `\r` qui le précède, de `max` octets au plus.
    Ligne(Vec<u8>),
    /// La ligne passe la borne : la lecture s'est arrêtée là, le reste n'est pas lu.
    TropGrande,
    /// Le flot est fini, entre deux lignes.
    Fin,
    /// Le flot est fini au milieu d'une ligne.
    Coupee,
    /// La lecture a échoué (autre chose qu'une interruption).
    Erreur,
}

/// Lit une ligne de `lecteur`, `max` octets au plus (sans le `\n` ni le `\r` final). `debut` est appelé une fois,
/// au premier octet de la ligne : l'appelant y fait partir le délai d'un message commencé.
pub(crate) fn lire_ligne(lecteur: &mut impl BufRead, max: usize, debut: &mut impl FnMut()) -> Lu {
    // La borne pendant le cumul laisse la place du `\r` final, retiré avant le contrôle.
    let plafond = max.saturating_add(1);
    let mut ligne: Vec<u8> = Vec::new();
    let mut commencee = false;
    loop {
        let dispo = match lecteur.fill_buf() {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Lu::Erreur,
        };
        if dispo.is_empty() {
            return if commencee { Lu::Coupee } else { Lu::Fin };
        }
        if !commencee {
            commencee = true;
            debut();
        }
        let (morceau, fin_de_ligne) = match dispo.iter().position(|&o| o == b'\n') {
            Some(i) => (dispo.get(..i).unwrap_or_default(), true),
            None => (dispo, false),
        };
        if ligne.len().saturating_add(morceau.len()) > plafond {
            return Lu::TropGrande;
        }
        ligne.extend_from_slice(morceau);
        let pris = morceau.len().saturating_add(usize::from(fin_de_ligne));
        lecteur.consume(pris);
        if fin_de_ligne {
            if ligne.last() == Some(&b'\r') {
                ligne.pop();
            }
            if ligne.len() > max {
                return Lu::TropGrande;
            }
            return Lu::Ligne(ligne);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tout(entree: &[u8], max: usize) -> Vec<Lu> {
        let mut lecteur = std::io::BufReader::with_capacity(7, entree);
        let mut lus = Vec::new();
        loop {
            let lu = lire_ligne(&mut lecteur, max, &mut || {});
            let fin = !matches!(lu, Lu::Ligne(_));
            lus.push(lu);
            if fin {
                return lus;
            }
        }
    }

    #[test]
    fn decoupe_les_lignes_et_retire_le_retour_chariot() {
        assert_eq!(
            tout(b"abc\r\n\ndef\n", 10),
            vec![
                Lu::Ligne(b"abc".to_vec()),
                Lu::Ligne(Vec::new()),
                Lu::Ligne(b"def".to_vec()),
                Lu::Fin
            ]
        );
        assert_eq!(tout(b"abc\ndef", 10), vec![Lu::Ligne(b"abc".to_vec()), Lu::Coupee]);
    }

    #[test]
    fn la_borne_est_exacte_et_tenue_pendant_la_lecture() {
        assert_eq!(
            tout(b"0123456789\n", 10),
            vec![Lu::Ligne(b"0123456789".to_vec()), Lu::Fin]
        );
        assert_eq!(
            tout(b"0123456789\r\n", 10),
            vec![Lu::Ligne(b"0123456789".to_vec()), Lu::Fin]
        );
        assert_eq!(tout(b"0123456789a\n", 10), vec![Lu::TropGrande]);
        assert_eq!(tout(b"0123456789\r\r\n", 10), vec![Lu::TropGrande]);
        // Un flot sans fin de ligne s'arrête à la borne, sans tout lire.
        let mut sans_fin = std::io::BufReader::new(std::io::repeat(b'x'));
        assert_eq!(lire_ligne(&mut sans_fin, 64 * 1024, &mut || {}), Lu::TropGrande);
    }

    #[test]
    fn une_ligne_trop_grande_n_est_pas_lue_au_dela_de_la_borne() {
        // La borne tient la mémoire pendant le cumul, pas seulement à la fin de la ligne : sinon une ligne de 1 Go
        // serait d'abord gardée entière, puis refusée.
        let entree = vec![b'x'; 1000];
        let mut lecteur = std::io::BufReader::with_capacity(7, &entree[..]);
        assert_eq!(lire_ligne(&mut lecteur, 100, &mut || {}), Lu::TropGrande);
        let reste = lecteur.buffer().len().saturating_add(lecteur.get_ref().len());
        let pris = entree.len().saturating_sub(reste);
        assert!(pris <= 101, "{pris} octets pris pour une borne de 100");
    }

    #[test]
    fn le_debut_est_signale_une_fois_par_ligne() {
        let mut lecteur = std::io::BufReader::with_capacity(2, &b"abcdef\nxy\n"[..]);
        let mut debuts = 0u32;
        let mut compter = || debuts = debuts.saturating_add(1);
        assert_eq!(
            lire_ligne(&mut lecteur, 100, &mut compter),
            Lu::Ligne(b"abcdef".to_vec())
        );
        assert_eq!(lire_ligne(&mut lecteur, 100, &mut compter), Lu::Ligne(b"xy".to_vec()));
        assert_eq!(lire_ligne(&mut lecteur, 100, &mut compter), Lu::Fin);
        assert_eq!(debuts, 2);
    }
}

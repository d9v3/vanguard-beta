//! Le protocole entre la fenêtre et son relais (`relais`), sans rien d'autre : ni socket, ni processus, ni appel
//! système. À part pour être lu par le banc de fuzzing : c'est la frontière entre la fenêtre, dans son bac à sable,
//! et le relais, qui a les droits du compte. Le relais lit ce que la fenêtre lui envoie comme venant d'un inconnu.
//!
//! Des trames : la longueur sur 4 octets, petit-boutiste, puis le contenu. Fenêtre → relais : `1 id commande langue`
//! (lancer) ou `2 id` (arrêter). Relais → fenêtre : `1 id texte` (une ligne d'erreur) ou `2 id issue code durée
//! texte sortie` (la fin).

use std::io::{Read, Write};
use std::time::Duration;

use crate::commandes::{Commande, Fin, Issue};

/// Une demande de la fenêtre fait au plus 7 octets : plus long, c'est hors du protocole.
pub const DEMANDE_MAX: usize = 16;

/// Une demande de la fenêtre.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Demande {
    Lancer { id: u32, commande: Commande, anglais: bool },
    Arreter { id: u32 },
}

impl Demande {
    pub fn coder(self) -> Vec<u8> {
        match self {
            Demande::Lancer { id, commande, anglais } => {
                let mut v = vec![1];
                v.extend(id.to_le_bytes());
                v.push(rang(commande));
                v.push(u8::from(anglais));
                v
            }
            Demande::Arreter { id } => {
                let mut v = vec![2];
                v.extend(id.to_le_bytes());
                v
            }
        }
    }

    /// Une demande, lue strictement : le bon type, la bonne longueur, un rang de la liste, une langue 0 ou 1.
    pub fn lire(o: &[u8]) -> Option<Demande> {
        let id = u32::from_le_bytes(o.get(1..5)?.try_into().ok()?);
        match (o.first()?, o.len()) {
            (1, 7) => Some(Demande::Lancer {
                id,
                commande: *Commande::TOUTES.get(usize::from(*o.get(5)?))?,
                anglais: match o.get(6)? {
                    0 => false,
                    1 => true,
                    _ => return None,
                },
            }),
            (2, 5) => Some(Demande::Arreter { id }),
            _ => None,
        }
    }
}

fn rang(c: Commande) -> u8 {
    Commande::TOUTES
        .iter()
        .position(|x| *x == c)
        .and_then(|i| u8::try_from(i).ok())
        .unwrap_or(u8::MAX)
}

/// Une réponse du relais, avant d'être rendue à la tâche qui l'attend.
#[derive(Debug, PartialEq, Eq)]
pub enum Reponse {
    Ligne(u32, String),
    Fin {
        id: u32,
        code: Option<i32>,
        issue: Issue,
        duree: Duration,
        sortie: Vec<u8>,
    },
}

pub fn coder_ligne(id: u32, l: &str) -> Vec<u8> {
    let mut v = vec![1];
    v.extend(id.to_le_bytes());
    v.extend(l.as_bytes());
    v
}

pub fn coder_fin(id: u32, f: &Fin) -> Vec<u8> {
    let (issue, texte): (u8, &str) = match &f.issue {
        Issue::Terminee => (0, ""),
        Issue::Arretee => (1, ""),
        Issue::DelaiDepasse => (2, ""),
        Issue::TropLongue => (3, ""),
        Issue::Impossible(t) => (4, t),
    };
    let texte = texte.as_bytes().get(..texte.len().min(4096)).unwrap_or_default();
    let mut v = Vec::with_capacity(f.sortie.len().saturating_add(32).saturating_add(texte.len()));
    v.push(2);
    v.extend(id.to_le_bytes());
    v.push(issue);
    v.push(u8::from(f.code.is_some()));
    v.extend(f.code.unwrap_or(0).to_le_bytes());
    v.extend(u64::try_from(f.duree.as_millis()).unwrap_or(u64::MAX).to_le_bytes());
    v.extend(u32::try_from(texte.len()).unwrap_or(0).to_le_bytes());
    v.extend(texte);
    v.extend(&f.sortie);
    v
}

pub fn lire_reponse(o: &[u8]) -> Option<Reponse> {
    let id = u32::from_le_bytes(o.get(1..5)?.try_into().ok()?);
    match o.first()? {
        1 => Some(Reponse::Ligne(
            id,
            crate::nettoyage::ligne(&String::from_utf8_lossy(o.get(5..)?)),
        )),
        2 => {
            let code = i32::from_le_bytes(o.get(7..11)?.try_into().ok()?);
            let duree = u64::from_le_bytes(o.get(11..19)?.try_into().ok()?);
            let n = usize::try_from(u32::from_le_bytes(o.get(19..23)?.try_into().ok()?)).ok()?;
            let fin_texte = 23usize.checked_add(n)?;
            let texte =
                || crate::nettoyage::nom(&String::from_utf8_lossy(o.get(23..fin_texte).unwrap_or_default()), 300);
            let issue = match o.get(5)? {
                0 => Issue::Terminee,
                1 => Issue::Arretee,
                2 => Issue::DelaiDepasse,
                3 => Issue::TropLongue,
                4 => Issue::Impossible(texte()),
                _ => return None,
            };
            Some(Reponse::Fin {
                id,
                code: match o.get(6)? {
                    0 => None,
                    1 => Some(code),
                    _ => return None,
                },
                issue,
                duree: Duration::from_millis(duree),
                sortie: o.get(fin_texte..)?.to_vec(),
            })
        }
        _ => None,
    }
}

pub fn ecrire_trame(f: &mut impl Write, contenu: &[u8]) -> std::io::Result<()> {
    let n = u32::try_from(contenu.len()).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut t = Vec::with_capacity(contenu.len().saturating_add(4));
    t.extend(n.to_le_bytes());
    t.extend(contenu);
    f.write_all(&t)
}

/// Une trame entière ; `None` à la fermeture (ou au milieu d'une trame). Plus longue que `max` : une erreur, sans
/// rien réserver pour elle.
pub fn lire_trame(f: &mut impl Read, max: usize) -> std::io::Result<Option<Vec<u8>>> {
    let mut n = [0u8; 4];
    match f.read_exact(&mut n) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = usize::try_from(u32::from_le_bytes(n)).unwrap_or(usize::MAX);
    if n > max {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
    }
    let mut v = vec![0; n];
    match f.read_exact(&mut v) {
        Ok(()) => Ok(Some(v)),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn les_demandes_aller_retour_et_le_reste_refuse() {
        for c in Commande::TOUTES {
            for anglais in [false, true] {
                let d = Demande::Lancer {
                    id: 0xdead_beef,
                    commande: c,
                    anglais,
                };
                assert_eq!(Demande::lire(&d.coder()), Some(d));
            }
        }
        let d = Demande::Arreter { id: 7 };
        assert_eq!(Demande::lire(&d.coder()), Some(d));
        let rangs = u8::try_from(Commande::TOUTES.len()).unwrap();
        for faux in [
            &[][..],
            &[1],
            &[1, 0, 0, 0, 0, 0],
            &[1, 0, 0, 0, 0, rangs, 0],
            &[1, 0, 0, 0, 0, 0, 2],
            &[1, 0, 0, 0, 0, 0, 0, 0],
            &[2, 0, 0, 0, 0, 0],
            &[3, 0, 0, 0, 0],
            &[0, 0, 0, 0, 0],
        ] {
            assert_eq!(Demande::lire(faux), None, "{faux:?}");
        }
    }

    #[test]
    fn les_reponses_aller_retour() {
        assert_eq!(
            lire_reponse(&coder_ligne(3, "une ligne")),
            Some(Reponse::Ligne(3, "une ligne".into()))
        );
        for (issue, code) in [
            (Issue::Terminee, Some(0)),
            (Issue::Arretee, None),
            (Issue::DelaiDepasse, None),
            (Issue::TropLongue, Some(-1)),
            (Issue::Impossible("raison".into()), None),
        ] {
            let f = Fin {
                commande: Commande::Bilan,
                code,
                sortie: b"{\"a\": 1}".to_vec(),
                issue: issue.clone(),
                duree: Duration::from_millis(1234),
            };
            assert_eq!(
                lire_reponse(&coder_fin(9, &f)),
                Some(Reponse::Fin {
                    id: 9,
                    code,
                    issue,
                    duree: Duration::from_millis(1234),
                    sortie: f.sortie.clone()
                })
            );
        }
        let mut f = coder_fin(
            1,
            &Fin {
                commande: Commande::Bilan,
                code: None,
                sortie: Vec::new(),
                issue: Issue::Terminee,
                duree: Duration::ZERO,
            },
        );
        assert!(lire_reponse(&f[..10]).is_none());
        f[5] = 9;
        assert!(lire_reponse(&f).is_none());
        assert!(lire_reponse(&[3, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn une_trame_trop_longue_est_refusee_sans_reserver() {
        let mut t = Vec::new();
        ecrire_trame(&mut t, b"abc").unwrap();
        assert_eq!(lire_trame(&mut &t[..], 3).unwrap(), Some(b"abc".to_vec()));
        assert!(lire_trame(&mut &t[..], 2).is_err());
        assert_eq!(lire_trame(&mut &t[..5], 3).unwrap(), None);
        assert_eq!(lire_trame(&mut &[][..], 3).unwrap(), None);
        assert!(lire_trame(&mut &[0xff, 0xff, 0xff, 0xff][..], DEMANDE_MAX).is_err());
    }
}

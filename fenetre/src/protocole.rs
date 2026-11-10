//! Le protocole entre la fenêtre et son relais (`relais`), sans rien d'autre : ni socket, ni processus, ni appel
//! système. À part pour être lu par le banc de fuzzing : c'est la frontière entre la fenêtre, dans son bac à sable,
//! et le relais, qui a les droits du compte. Le relais lit ce que la fenêtre lui envoie comme venant d'un inconnu.
//!
//! Des trames : la longueur sur 4 octets, petit-boutiste, puis le contenu. Fenêtre → relais : `1 id commande langue`
//! (lancer une commande de la liste), `3 id sorte empreinte(16) langue` (un changement au démarrage : sorte 1
//! retirer, 2 remettre), `4 id theme action base rvb(15) langue` (un changement des couleurs de la fenêtre : thème 1
//! sombre, 2 clair ; action 1 un choix, sa base et ses cinq couleurs, ou 0 celles de Vanguard, base et couleurs
//! alors toutes à zéro) ou `2 id` (arrêter). Relais → fenêtre : `1 id texte` (une ligne d'erreur), `3 id pid`
//! (`vanguard` est lancé, sous ce numéro : pour les coulisses) ou `2 id issue code durée texte sortie` (la fin).

use std::io::{Read, Write};
use std::time::Duration;

use crate::commandes::{Changement, ChangementCouleurs, Commande, Empreinte, Fin, Issue, Lancement, Sorte};
use crate::couleurs::{Base, Choix, Rgb, Theme, VIFS};

/// Une demande de la fenêtre fait au plus 24 octets (des couleurs) : plus long, c'est hors du protocole.
pub const DEMANDE_MAX: usize = 32;

/// Une demande de la fenêtre.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Demande {
    Lancer {
        id: u32,
        lancement: Lancement,
        anglais: bool,
    },
    Arreter {
        id: u32,
    },
}

impl Demande {
    pub fn coder(self) -> Vec<u8> {
        match self {
            Demande::Lancer {
                id,
                lancement: Lancement::Commande(commande),
                anglais,
            } => {
                let mut v = vec![1];
                v.extend(id.to_le_bytes());
                v.push(rang(commande));
                v.push(u8::from(anglais));
                v
            }
            Demande::Lancer {
                id,
                lancement: Lancement::Changement(ch),
                anglais,
            } => {
                let mut v = vec![3];
                v.extend(id.to_le_bytes());
                v.push(ch.sorte.octet());
                v.extend(ch.empreinte.octets());
                v.push(u8::from(anglais));
                v
            }
            Demande::Lancer {
                id,
                lancement: Lancement::Couleurs(cc),
                anglais,
            } => {
                let mut v = vec![4];
                v.extend(id.to_le_bytes());
                v.push(cc.theme.octet());
                match cc.choix {
                    Some(c) => {
                        v.push(1);
                        v.push(c.base.octet());
                        v.extend(c.vifs.as_flattened());
                    }
                    None => v.extend([0u8; 2 + 3 * VIFS]),
                }
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

    /// Une demande, lue strictement : le bon type, la bonne longueur, un rang de la liste ou une sorte connue, une
    /// langue 0 ou 1. L'empreinte, elle, n'est que 16 octets : Vanguard seul sait à quoi elle répond.
    pub fn lire(o: &[u8]) -> Option<Demande> {
        let id = u32::from_le_bytes(o.get(1..5)?.try_into().ok()?);
        let langue = |i: usize| match o.get(i)? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        };
        match (o.first()?, o.len()) {
            (1, 7) => Some(Demande::Lancer {
                id,
                lancement: Lancement::Commande(*Commande::TOUTES.get(usize::from(*o.get(5)?))?),
                anglais: langue(6)?,
            }),
            (3, 23) => Some(Demande::Lancer {
                id,
                lancement: Lancement::Changement(Changement {
                    sorte: Sorte::depuis_octet(*o.get(5)?)?,
                    empreinte: Empreinte::depuis_octets(o.get(6..22)?.try_into().ok()?),
                }),
                anglais: langue(22)?,
            }),
            (4, 24) => Some(Demande::Lancer {
                id,
                lancement: Lancement::Couleurs(couleurs(o.get(5..23)?)?),
                anglais: langue(23)?,
            }),
            (2, 5) => Some(Demande::Arreter { id }),
            _ => None,
        }
    }
}

/// `theme action base rvb(15)`, strictement : un thème et une base connus ; pour « celles de Vanguard », tout le
/// reste à zéro. Les couleurs, elles, sont 15 octets quelconques : leur lisibilité est jugée par le relais
/// (`couleurs::verifier`) puis par `vanguard`.
fn couleurs(o: &[u8]) -> Option<ChangementCouleurs> {
    let (&[theme, action, base], rvb) = o.split_first_chunk::<3>()?;
    let theme = Theme::depuis_octet(theme)?;
    let choix = match action {
        0 if base == 0 && rvb.iter().all(|x| *x == 0) => None,
        1 => {
            let (paquets, []) = rvb.as_chunks::<3>() else {
                return None;
            };
            let vifs: [Rgb; VIFS] = paquets.try_into().ok()?;
            Some(Choix {
                base: Base::depuis_octet(base)?,
                vifs,
            })
        }
        _ => return None,
    };
    Some(ChangementCouleurs { theme, choix })
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
    /// `vanguard` est lancé : le numéro de son processus (montré dans les coulisses, rien d'autre).
    Lance(u32, u32),
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

pub fn coder_lance(id: u32, pid: u32) -> Vec<u8> {
    let mut v = vec![3];
    v.extend(id.to_le_bytes());
    v.extend(pid.to_le_bytes());
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
        // Exactement 9 octets : rien d'autre ne passe avec le numéro.
        3 if o.len() == 9 => Some(Reponse::Lance(id, u32::from_le_bytes(o.get(5..9)?.try_into().ok()?))),
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
                    lancement: Lancement::Commande(c),
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

    /// Un changement : aller-retour pour chaque sorte, langue et empreinte ; une autre longueur, une sorte inconnue,
    /// une langue hors de 0 et 1 : hors du protocole.
    #[test]
    fn les_changements_aller_retour_et_le_reste_refuse() {
        for sorte in [Sorte::Retirer, Sorte::Remettre] {
            for anglais in [false, true] {
                for octets in [[0u8; 16], [0xff; 16], *b"Lecteur\0alice\0\0\0"] {
                    let d = Demande::Lancer {
                        id: 42,
                        lancement: Lancement::Changement(Changement {
                            sorte,
                            empreinte: Empreinte::depuis_octets(octets),
                        }),
                        anglais,
                    };
                    let v = d.coder();
                    assert_eq!(v.len(), 23);
                    assert!(v.len() <= DEMANDE_MAX);
                    assert_eq!(Demande::lire(&v), Some(d));
                }
            }
        }
        let bonne = Demande::Lancer {
            id: 1,
            lancement: Lancement::Changement(Changement {
                sorte: Sorte::Retirer,
                empreinte: Empreinte::depuis_octets([7; 16]),
            }),
            anglais: false,
        }
        .coder();
        // Plus court, plus long (un octet de plus, un chemin au bout) : refusé.
        for n in 0..bonne.len() {
            assert_eq!(Demande::lire(&bonne[..n]), None, "{n}");
        }
        let mut longue = bonne.clone();
        longue.push(0);
        assert_eq!(Demande::lire(&longue), None);
        let mut chemin = bonne.clone();
        chemin.extend(b"/home/alice/.config/autostart/Lecteur.desktop");
        assert_eq!(Demande::lire(&chemin), None);
        for (i, faux) in [(5, 0u8), (5, 3), (5, 0xff), (22, 2), (22, 0xff)] {
            let mut v = bonne.clone();
            v[i] = faux;
            assert_eq!(Demande::lire(&v), None, "{i} {faux}");
        }
        // Le type 1 (une commande) à la longueur d'un changement, et l'inverse : refusés.
        let mut v = bonne.clone();
        v[0] = 1;
        assert_eq!(Demande::lire(&v), None);
        assert_eq!(Demande::lire(&[3, 0, 0, 0, 0, 1, 0]), None);
    }

    /// Des couleurs : aller-retour pour chaque thème, base, langue, et pour « celles de Vanguard » ; une autre
    /// longueur, un thème, une action ou une base inconnus, ou des octets non nuls après « celles de Vanguard » : hors
    /// du protocole.
    #[test]
    fn les_couleurs_aller_retour_et_le_reste_refuse() {
        for theme in Theme::TOUS {
            for anglais in [false, true] {
                let mut choix: Vec<Option<Choix>> = Base::TOUTES
                    .into_iter()
                    .map(|b| Some(Choix::du_prereglage(b, theme)))
                    .collect();
                choix.push(Some(Choix {
                    base: Base::Violet,
                    vifs: [[0, 0x10, 0xff], [0xff; 3], [0; 3], [1, 2, 3], [0x7f, 0x80, 0x81]],
                }));
                choix.push(None);
                for choix in choix {
                    let d = Demande::Lancer {
                        id: 77,
                        lancement: Lancement::Couleurs(ChangementCouleurs { theme, choix }),
                        anglais,
                    };
                    let v = d.coder();
                    assert_eq!(v.len(), 24);
                    assert!(v.len() <= DEMANDE_MAX);
                    assert_eq!(Demande::lire(&v), Some(d));
                }
            }
        }
        let bonne = Demande::Lancer {
            id: 1,
            lancement: Lancement::Couleurs(ChangementCouleurs {
                theme: Theme::Sombre,
                choix: Some(Choix::du_prereglage(Base::Braise, Theme::Sombre)),
            }),
            anglais: false,
        }
        .coder();
        for n in 0..bonne.len() {
            assert_eq!(Demande::lire(&bonne[..n]), None, "{n}");
        }
        let mut longue = bonne.clone();
        longue.extend(b",ffffff");
        assert_eq!(Demande::lire(&longue), None);
        for (i, faux) in [(5, 0u8), (5, 3), (6, 2), (6, 0xff), (7, 7), (7, 0xff), (23, 2)] {
            let mut v = bonne.clone();
            v[i] = faux;
            assert_eq!(Demande::lire(&v), None, "{i} {faux}");
        }
        let defaut = Demande::Lancer {
            id: 1,
            lancement: Lancement::Couleurs(ChangementCouleurs {
                theme: Theme::Clair,
                choix: None,
            }),
            anglais: true,
        }
        .coder();
        for i in 7..23 {
            let mut v = defaut.clone();
            v[i] = 1;
            assert_eq!(Demande::lire(&v), None, "{i}");
        }
        // Le type 3 (le démarrage) à la longueur des couleurs : refusé.
        let mut v = bonne.clone();
        v[0] = 3;
        assert_eq!(Demande::lire(&v), None);
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
                lancement: Lancement::Commande(Commande::Bilan),
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
                lancement: Lancement::Commande(Commande::Bilan),
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
        assert_eq!(lire_reponse(&coder_lance(4, 4242)), Some(Reponse::Lance(4, 4242)));
        let mut l = coder_lance(4, 4242);
        assert!(lire_reponse(&l[..8]).is_none());
        l.push(0);
        assert!(lire_reponse(&l).is_none());
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

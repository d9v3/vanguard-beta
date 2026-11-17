//! La fenêtre (`vanguard-fenetre`) d'un programme que la mise à jour remplace : elle le suit, vérifiée contre
//! l'empreinte gravée dans le nouveau programme (`demarrage::empreinte_fenetre`), lui-même déjà vérifié (signature,
//! taille et empreinte de GitHub, ou la version de la clé). La fenêtre d'abord, puis le programme ; si le programme
//! ne se pose pas, ce qui était là est remis, et ce qui ne peut pas l'être est dit (`Remise`). Même si ce retour
//! échouait, rien de dangereux : un programme ne lance jamais une fenêtre dont l'empreinte n'est pas la sienne (le
//! menu à la place).
//!
//! Depuis GitHub (C-6, 0.97), une fenêtre absente est ajoutée là où le lancement la cherche, au même accord que le
//! programme ; et au même numéro, un programme d'ici qui est exactement celui que l'auteur a signé reçoit sa fenêtre
//! seule, ajoutée ou réparée, sans être retéléchargé (`Seule`). Jamais rien sans avoir été montré puis accepté.
//!
//! Relecture C-6/C-7 : « juste » se juge comme le lancement : le fichier (`lancer_fenetre::refusee`) et ses dossiers
//! (`lancer_fenetre::dossiers_refuses`). Une fenêtre en lien, ou que le lancement refuserait (droits, propriétaire),
//! n'est jamais comptée juste, et n'est jamais lue à travers le lien (`Avant`) ; un dossier refusé est dit, jamais
//! « réparé » en reposant le fichier. Une fenêtre qui ne se lit pas, ou une copie qui est un lien, ne bloque jamais le
//! programme : il est posé seul, sa fenêtre n'est pas touchée, et c'est montré dans l'accord (`Laissee`, ronde 3) ;
//! pour une fenêtre seule, la copie est mise de côté (`Ecartee`). Deux programmes du même dossier partagent une
//! fenêtre : jugée et posée une fois (`trier`).

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::TAILLE_MAX as TAILLE_PROGRAMME;
use super::{Essai, Version, installer, lire_octets, meme_fichier, mettre_en_place_sous};
use crate::demarrage::empreinte_fenetre::{self, Gravee};
use crate::demarrage::lancer_fenetre::{self, TAILLE_MAX};
use crate::modele::{Echec, Raison};
use crate::tr;

/// La fenêtre posée à côté de `programme`, s'il y en a une, sous l'un des noms que le lancement cherche.
pub(super) fn a_cote(programme: &Path) -> Option<PathBuf> {
    lancer_fenetre::voisine(programme).filter(|p| std::fs::symlink_metadata(p).is_ok())
}

/// `fenetre` est-elle celle que grave `programme` ? Sinon, pourquoi pas.
/// Une fenêtre qui n'a pas l'empreinte gravée n'est jamais crue : `Raison::Falsifie`, sa phrase seule rendue.
fn juste(programme: &[u8], fenetre: &[u8]) -> Result<(), Echec> {
    match empreinte_fenetre::gravee(programme) {
        Some(Gravee::Empreinte(e)) if Sha256::digest(fenetre)[..] == e => Ok(()),
        Some(Gravee::Empreinte(_)) => Err(Echec::new("fenetre/juger", Raison::Falsifie).detail(tr!(
            "la fenêtre reçue n'est pas celle du nouveau programme : rien n'est remplacé",
            "the received window is not the new program's: nothing is replaced"
        ))),
        Some(Gravee::Aucune) => Err(Echec::refuse(
            "fenetre/juger",
            tr!(
                "le nouveau programme ne lance aucune fenêtre",
                "the new program launches no window"
            ),
        )),
        None => Err(sans_marque()),
    }
}

fn sans_marque() -> Echec {
    Echec::refuse(
        "fenetre/juger",
        tr!(
            "le nouveau programme ne dit pas quelle fenêtre il lance : rien n'est remplacé",
            "the new program does not say which window it launches: nothing is replaced"
        ),
    )
}

/// Un échec de la pose, sa phrase telle quelle : ce qu'en dit le système, ou le refus de `installer` (encore en
/// texte).
fn ratee(e: impl std::fmt::Display) -> Echec {
    Echec::echoue("fenetre/poser", e.to_string())
}

/// `e`, avec une phrase de plus à la fin (ce qui a été remis, ou pas) ; sa raison gardée.
fn avec(mut e: Echec, ajout: &str) -> Echec {
    e.detail = if e.detail.is_empty() {
        ajout.to_string()
    } else {
        format!("{}\n    {ajout}", e.detail)
    };
    e
}

/// `octets` à la place de `cible` (`installer`), et la fenêtre à côté (`vue.chemin`) remplacée, ou ajoutée si elle
/// n'y est pas (C-6, 0.97), par celle de la nouvelle version, que `recevoir` donne (appelé seulement s'il en faut une).
/// Tout ou rien : une fenêtre qui ne vient pas, ou qui n'est pas celle gravée, et rien n'est remplacé. Un nouveau
/// programme qui ne lance aucune fenêtre se pose seul : celle d'ici reste, il ne la lancera pas. Un qui ne dit pas sa
/// fenêtre se pose seul là où il n'y en a pas (rien à remplacer), et il est refusé à côté d'une fenêtre.
///
/// `vue` : la fenêtre que l'aperçu a montrée à côté de `cible` (C-7, relecture 0.96), son chemin et ce qui y était.
/// Apparue, partie ou changée depuis, rien n'est remplacé, le programme non plus : jamais une fenêtre remplacée sans
/// avoir été montrée (sauf par la copie d'avant du même dossier, `Vue::partagee`).
///
/// Une fenêtre laissée (`Vue::laissee`, ronde 3) : le programme seul, la fenêtre jamais touchée (`installer_seul`).
#[allow(clippy::too_many_arguments)] // chacun une garde : la liste des copies (registre) et la copie de cet ordinateur s'ajoutent
pub(super) fn installer_avec_sa_fenetre(
    octets: &[u8],
    cible: &Path,
    attendue: Version,
    registre: &Path,
    copie: &Path,
    essai: Essai,
    vue: &Vue,
    recevoir: &mut dyn FnMut() -> Result<Vec<u8>, Echec>,
) -> Result<(), Echec> {
    if vue.laissee.is_some() {
        return installer_seul(octets, cible, attendue, registre, copie, essai, vue);
    }
    vue.telle_quelle(cible, octets)?;
    let Some(chemin) = vue.chemin.clone() else {
        return installer(octets, cible, attendue, registre, copie, essai).map_err(ratee);
    };
    match empreinte_fenetre::gravee(octets) {
        Some(Gravee::Aucune) => return installer(octets, cible, attendue, registre, copie, essai).map_err(ratee),
        // Rien à remplacer ici : le programme seul, comme avant la 0.97 ; la ligne de la fenêtre dit pourquoi elle
        // n'est pas ajoutée (`posee_juste`).
        None if vue.etat == Montree::Absente => {
            return installer(octets, cible, attendue, registre, copie, essai).map_err(ratee);
        }
        // Rien n'est téléchargé pour un programme qui ne dit pas sa fenêtre : refusé tout de suite.
        None => return Err(sans_marque()),
        Some(Gravee::Empreinte(_)) => {}
    }
    let fenetre = recevoir()?;
    // Le téléchargement a pris du temps : une fenêtre a pu apparaître, partir ou changer.
    vue.telle_quelle(cible, octets)?;
    installer_avec(octets, cible, attendue, registre, copie, essai, &fenetre, &chemin, vue)
}

/// Le programme seul, sa fenêtre laissée (`Vue::laissee`, A-ACCORD-1, A-REFUS-1, ronde 3) : une fenêtre qui ne se lit
/// pas, une copie en lien, une fenêtre de la clé non vérifiée ne bloquent jamais la mise à jour du programme. Ce qui a
/// fait laisser la fenêtre doit tenir encore (`Vue::toujours_laissee`) ; sinon rien, pas même le programme : ce qui
/// est fait est toujours ce qui a été montré. La fenêtre n'est jamais touchée ; sa ligne le dit (`Vue::laissee_dite`).
#[allow(clippy::too_many_arguments)] // chacun une garde : la liste des copies (registre) et la copie de cet ordinateur s'ajoutent
pub(super) fn installer_seul(
    octets: &[u8],
    cible: &Path,
    attendue: Version,
    registre: &Path,
    copie: &Path,
    essai: Essai,
    vue: &Vue,
) -> Result<(), Echec> {
    vue.toujours_laissee(cible)?;
    installer(octets, cible, attendue, registre, copie, essai).map_err(ratee)
}

/// La copie `cible` est-elle un lien, regardée maintenant sans le suivre ?
pub(super) fn en_lien(cible: &Path) -> bool {
    std::fs::symlink_metadata(cible).is_ok_and(|m| m.file_type().is_symlink())
}

/// Une copie ordinaire à l'aperçu, devenue un lien avant la pose (A-ORIGINE-3) : rien n'est posé à côté.
fn devenue_lien() -> Echec {
    Echec::refuse(
        "fenetre/apercu",
        tr!(
            "la copie est devenue un lien depuis ce qui a été montré : rien n'est posé ; relancez la mise à jour pour la voir",
            "the copy became a link since what was shown: nothing is placed; run the update again to see it"
        ),
    )
}

/// GitHub, au même numéro (C-6, 0.97) : un programme d'ici qui est exactement celui que l'auteur a signé (taille et
/// empreinte du manifeste), sans sa fenêtre à côté, ou avec une autre que celle qu'il grave, ou une que le lancement
/// refuserait (un lien, des droits trop larges). Seule sa fenêtre est proposée, ajoutée ou réparée ; le programme,
/// déjà juste, n'est pas retéléchargé.
#[derive(Debug)]
pub(super) struct Seule {
    /// Le programme d'ici, tel que lu et reconnu pour l'aperçu : un fichier ordinaire (une copie en lien est mise de
    /// côté, `seule_a_poser`), revérifié à la pose (`Vue::telle_quelle`).
    programme: PathBuf,
    octets: Vec<u8>,
    /// Où sa fenêtre sera posée, et ce qui y était quand elle a été montrée.
    pub(super) vue: Vue,
}

impl Seule {
    /// Le chemin de la fenêtre qui sera posée.
    pub(super) fn chemin(&self) -> &Path {
        // `seule_a_poser` ne fait jamais de `Seule` sans chemin.
        self.vue.chemin.as_deref().unwrap_or(&self.programme)
    }

    /// Vrai si aucune fenêtre n'est là (ajoutée), faux si une autre l'est (réparée).
    pub(super) fn ajout(&self) -> bool {
        self.vue.etat == Montree::Absente
    }

    /// Ce que la ligne de la fenêtre dit dans l'aperçu.
    pub(super) fn dite(&self) -> &'static str {
        match self.vue.etat {
            Montree::Absente => tr!(
                "sa fenêtre, absente : ajoutée seule",
                "its window, missing: added alone"
            ),
            Montree::Lien(_) => tr!(
                "sa fenêtre, un lien : remplacée seule par un fichier",
                "its window, a link: replaced alone by a file"
            ),
            Montree::Refusee(_) => tr!(
                "sa fenêtre, refusée au lancement (droits) : remplacée seule",
                "its window, refused at launch (permissions): replaced alone"
            ),
            Montree::Empreinte(_) | Montree::Illisible => tr!(
                "sa fenêtre, pas la sienne : remplacée seule",
                "its window, not its own: replaced alone"
            ),
        }
    }

    /// Après l'accord : la fenêtre que `recevoir` donne, jugée contre l'empreinte que grave le programme d'ici
    /// (reconnu comme celui que l'auteur a signé), posée à la place de ce qui a été montré, puis relue
    /// (`posee_juste`). Rien d'autre n'est touché ; une fenêtre changée depuis l'aperçu, un programme d'ici changé,
    /// une fenêtre reçue qui n'est pas la gravée : rien. Posée mais pas juste à la relecture : ce qui était là est
    /// remis, et ce qui ne peut pas l'être est dit (POSE-2).
    pub(super) fn poser(&self, recevoir: &mut dyn FnMut() -> Result<Vec<u8>, Echec>) -> Result<(), Echec> {
        self.vue.telle_quelle(&self.programme, &self.octets)?;
        let Some(chemin) = self.vue.chemin.as_deref() else {
            return Err(changee_depuis_l_apercu());
        };
        if !matches!(empreinte_fenetre::gravee(&self.octets), Some(Gravee::Empreinte(_))) {
            return juste(&self.octets, &[]);
        }
        let fenetre = recevoir()?;
        juste(&self.octets, &fenetre)?;
        // Le téléchargement a pris du temps : la fenêtre ou le programme d'ici ont pu changer.
        self.vue.telle_quelle(&self.programme, &self.octets)?;
        if lire_octets(&self.programme, TAILLE_PROGRAMME).ok().as_deref() != Some(self.octets.as_slice()) {
            return Err(Echec::refuse(
                "fenetre/apercu",
                tr!(
                    "le programme à côté de cette fenêtre a changé depuis ce qui a été montré : sa fenêtre n'est pas posée ; relancez la mise à jour pour le voir",
                    "the program next to this window changed since what was shown: its window is not placed; run the update again to see it"
                ),
            ));
        }
        let avant = Avant::de(chemin, TAILLE_MAX);
        self.vue.meme_etat(chemin, &avant, &self.octets)?;
        poser_puis_relire(&fenetre, chemin, &avant, |c| posee_juste(&self.octets, c))
    }

    /// Ce que dit la ligne de la fenêtre après la pose : relue, jamais « à jour » sans l'être.
    pub(super) fn posee_juste(&self) -> Result<(), Echec> {
        posee_juste(&self.octets, self.chemin())
    }
}

/// `fenetre` posée à `chemin`, puis relue (`relire`) ; posée mais pas juste à la relecture, ce qui était là
/// (`avant`) est remis, et ce qui ne peut pas l'être est dit (POSE-2). Rien de renommé : rien à remettre (A-POSE-4).
fn poser_puis_relire(
    fenetre: &[u8],
    chemin: &Path,
    avant: &Avant,
    relire: impl FnOnce(&Path) -> Result<(), Echec>,
) -> Result<(), Echec> {
    match poser_dit(fenetre, chemin, MODE_NEUF) {
        Err((e, false)) => Err(e),
        Err((e, true)) => Err(avec_remise(e, &remettre(avant, chemin, fenetre))),
        Ok(()) => relire(chemin).map_err(|e| avec_remise(e, &remettre(avant, chemin, fenetre))),
    }
}

/// Une copie d'ici, déjà juste, dont la fenêtre seule ne sera pas posée (ILLISIBLE-1, relecture C-6/C-7, ronde 3) :
/// sa fenêtre ne se lit pas (droits, dossier, tube ou fichier spécial, démesurée), la copie est un lien, ou le
/// lancement refuse le dossier de la fenêtre (la reposer ne réparerait rien). Ni elle ni sa fenêtre ne sont touchées ;
/// c'est dit avec les chemins, les autres copies suivent. Sa ligne (chemins, geste « laisse de côté ») est dans
/// l'accord ; l'état illisible ne se compare à rien : redevenue lisible avant le clic, le plan refait n'a plus cette
/// ligne, l'accord change et rien n'est fait (`Refus::Change`, A-ACCORD-4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Ecartee {
    pub(super) programme: PathBuf,
    pub(super) fenetre: PathBuf,
    pourquoi: Pourquoi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pourquoi {
    Illisible,
    Lien,
    /// Le refus du lancement pour un dossier du chemin (`lancer_fenetre::dossiers_refuses`).
    Dossier(&'static str),
}

impl Ecartee {
    /// La ligne du programme dans l'aperçu (80 caractères au plus, la largeur de l'interface).
    pub(super) fn ligne_programme(&self) -> &'static str {
        match self.pourquoi {
            Pourquoi::Illisible => tr!(
                "laissé de côté : sa fenêtre ne se lit pas",
                "set aside: its window cannot be read"
            ),
            Pourquoi::Lien => tr!(
                "laissé de côté : un lien, sa fenêtre n'est pas posée",
                "set aside: a link, its window is not placed"
            ),
            Pourquoi::Dossier(_) => tr!(
                "laissé de côté : le lancement refuse son dossier",
                "set aside: the launch refuses its folder"
            ),
        }
    }

    /// La ligne de la fenêtre dans l'aperçu.
    pub(super) fn ligne_fenetre(&self) -> &'static str {
        match self.pourquoi {
            Pourquoi::Illisible => tr!(
                "sa fenêtre, illisible : retirez-la ou réparez-la",
                "its window, unreadable: remove or repair it"
            ),
            Pourquoi::Lien => tr!(
                "sa fenêtre, non touchée : la copie est un lien",
                "its window, untouched: the copy is a link"
            ),
            Pourquoi::Dossier(_) => tr!(
                "sa fenêtre, non touchée : la reposer ne réparerait rien",
                "its window, untouched: placing it again would fix nothing"
            ),
        }
    }

    /// La phrase entière (le résultat, le terminal), `programme` et `fenetre` déjà mis en forme pour l'affichage.
    pub(super) fn dite(&self, programme: &str, fenetre: &str) -> String {
        match self.pourquoi {
            Pourquoi::Illisible => crate::trf!(
                "la fenêtre {} ne se lit pas (droits, dossier, trop grande) : {} est laissé de côté, ni lui ni elle ne sont touchés ; retirez ou réparez ce fichier, puis relancez la mise à jour",
                "the window {} cannot be read (permissions, folder, too large): {} is set aside, neither it nor the window is touched; remove or repair this file, then run the update again",
                fenetre,
                programme
            ),
            Pourquoi::Lien => crate::trf!(
                "{} est un lien : sa fenêtre n'est posée ni à côté de lui ({}) ni à côté du fichier qu'il désigne, rien n'est touché ; posez la copie elle-même, puis relancez la mise à jour",
                "{} is a link: its window is placed neither next to it ({}) nor next to the file it points to, nothing is touched; install the copy itself, then run the update again",
                programme,
                fenetre
            ),
            Pourquoi::Dossier(raison) => crate::trf!(
                "le lancement de {} refuse sa fenêtre {} à cause de son dossier ({}) : la reposer ne réparerait rien, rien n'est touché ; corrigez ce dossier (par exemple chmod go-w), puis relancez la mise à jour",
                "the launch of {} refuses its window {} because of its folder ({}): placing it again would fix nothing, nothing is touched; fix this folder (for example chmod go-w), then run the update again",
                programme,
                fenetre,
                raison
            ),
        }
    }
}

/// Le même chemin de fenêtre, écrit autrement ou non (un dossier par un lien) : même nom, dans le même dossier.
fn meme_chemin(a: &Path, b: &Path) -> bool {
    a == b
        || (a.file_name() == b.file_name()
            && matches!((a.parent(), b.parent()), (Some(x), Some(y)) if meme_fichier(x, y)))
}

/// Les programmes à remplacer (`cibles`), chacun avec la fenêtre montrée à côté de lui (relue maintenant). Une
/// fenêtre qui ne se lit pas, ou une copie qui est un lien, laisse sa fenêtre (`Laissee`, ronde 3) : le programme est
/// posé seul, jamais bloqué. Deux programmes du même dossier partagent une fenêtre (ACCORD-1, POSE-1) : le second la
/// sait partagée (`Vue::partagee`), elle n'est montrée qu'une fois et il accepte la fenêtre que le premier vient de
/// poser ; une fenêtre laissée ne se partage pas, elle a sa ligne. La même logique pour l'interface et le terminal.
pub(super) fn trier(cibles: Vec<PathBuf>) -> Vec<(PathBuf, Vue)> {
    let mut gardees: Vec<(PathBuf, Vue)> = Vec::new();
    for cible in cibles {
        let mut vue = Vue::de(pour(&cible));
        if en_lien(&cible) {
            vue.laissee = Some(Laissee::CopieEnLien);
        } else if vue.etat == Montree::Illisible {
            vue.laissee = Some(Laissee::Illisible);
        }
        vue.partagee = vue.laissee.is_none()
            && vue.chemin.as_deref().is_some_and(|c| {
                gardees
                    .iter()
                    .any(|(_, v)| v.laissee.is_none() && v.chemin.as_deref().is_some_and(|d| meme_chemin(c, d)))
            });
        gardees.push((cible, vue));
    }
    gardees
}

/// Les fenêtres seules à proposer (`seule_a_poser`) à côté des `candidats` (au numéro publié), une par chemin, et
/// aucune là où une copie à remplacer (`gardees`) pose déjà la sienne ; celles qui ne se lisent pas, ou d'une copie
/// en lien qui ne peut pas la recevoir, vont dans `ecartees`.
pub(super) fn seules(
    candidats: &[PathBuf],
    publiee: &super::github::Publiee,
    gardees: &[(PathBuf, Vue)],
    ecartees: &mut Vec<Ecartee>,
) -> Vec<Seule> {
    let mut seules: Vec<Seule> = Vec::new();
    for c in candidats {
        match seule_a_poser(c, publiee) {
            None => {}
            Some(Err(e)) => {
                if !ecartees.contains(&e) {
                    ecartees.push(e);
                }
            }
            Some(Ok(s)) => {
                let deja = seules.iter().any(|t| meme_chemin(t.chemin(), s.chemin()))
                    || gardees
                        .iter()
                        .any(|(_, v)| v.chemin().is_some_and(|d| meme_chemin(d, s.chemin())));
                if !deja {
                    seules.push(s);
                }
            }
        }
    }
    seules
}

/// La fenêtre seule à proposer à côté de `cible` (C-6, 0.97), si `cible` est exactement le programme que l'auteur a
/// signé (`publiee`) et qu'il grave une fenêtre qui n'est pas celle d'ici, juste aux yeux du lancement (absente,
/// autre, un lien, refusée). Un programme d'ici qui n'est pas celui publié (une compilation d'ailleurs au même
/// numéro) : rien, sa fenêtre ne peut pas être jugée d'ici contre GitHub. `Err`, la copie mise de côté et dite : une
/// fenêtre illisible ; une copie qui est un lien (A-ORIGINE-1, ronde 3 : rien n'est posé ni à côté du lien ni à côté
/// de ce qu'il désigne, sous les deux systèmes) ; un dossier que le lancement refuse (A-ORIGINE-2 : la reposer ne
/// réparerait rien, même juste).
pub(super) fn seule_a_poser(cible: &Path, publiee: &super::github::Publiee) -> Option<Result<Seule, Ecartee>> {
    let octets = lire_octets(cible, TAILLE_PROGRAMME).ok().filter(|o| publiee.est(o))?;
    let Some(Gravee::Empreinte(e)) = empreinte_fenetre::gravee(&octets) else {
        return None;
    };
    let ecartee = |fenetre: PathBuf, pourquoi| {
        Some(Err(Ecartee {
            programme: cible.to_path_buf(),
            fenetre,
            pourquoi,
        }))
    };
    if en_lien(cible) {
        return ecartee(pour(cible).unwrap_or_else(|| cible.to_path_buf()), Pourquoi::Lien);
    }
    let vue = Vue::de(pour(cible));
    let chemin = vue.chemin.clone()?;
    match (vue.etat.clone(), vue.dossier) {
        (Montree::Illisible, _) => ecartee(chemin, Pourquoi::Illisible),
        (_, Some(raison)) => ecartee(chemin, Pourquoi::Dossier(raison)),
        (Montree::Empreinte(m), None) if m == e => None,
        _ => Some(Ok(Seule {
            programme: cible.to_path_buf(),
            octets,
            vue,
        })),
    }
}

/// La fenêtre telle que l'aperçu (ou la question du terminal) l'a montrée : le chemin que la mise à jour remplacera
/// ou ajoutera, s'il y en a un, et ce qui y était (C-7, relecture 0.96). La pose la compare à ce qui y est maintenant ;
/// sinon une fenêtre apparue pendant le téléchargement était remplacée sans avoir été montrée. Dans l'interface, où le
/// plan est refait au clic, ce qui y était entre aussi dans l'accord (`pour_l_accord`, C-7-1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Vue {
    chemin: Option<PathBuf>,
    etat: Montree,
    /// La même fenêtre qu'un programme d'avant dans la liste (même dossier, `trier`) : elle a déjà sa ligne, et ce
    /// programme accepte aussi, à sa place, la fenêtre juste de la nouvelle version, que le premier vient de poser.
    partagee: bool,
    /// Le refus du lancement pour un dossier du chemin de la fenêtre (`lancer_fenetre::dossiers_refuses`, A-ACCORD-2,
    /// ronde 3) : dit, dans l'accord ; reposer la fenêtre ne le répare pas.
    dossier: Option<&'static str>,
    /// La fenêtre laissée telle quelle, le programme posé seul (A-ACCORD-1, ronde 3), et pourquoi ; dans l'accord.
    laissee: Option<Laissee>,
}

/// Pourquoi une fenêtre est laissée telle quelle à côté d'un programme posé seul (A-ACCORD-1, A-REFUS-1, A-REFUS-5,
/// A-ORIGINE-1, ronde 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Laissee {
    /// Celle d'ici ne se lit pas (droits, dossier, tube ou fichier spécial, démesurée) : jamais écrasée, jamais
    /// comptée pareille.
    Illisible,
    /// La copie est un lien : rien n'est posé ni à côté du lien ni à côté de ce qu'il désigne.
    CopieEnLien,
    /// La fenêtre de la clé n'est pas posée : illisible, un lien, ou pas celle que grave le programme (la raison).
    DeLaCle(&'static str),
}

/// Ce qui était au chemin montré : rien, un fichier ordinaire (son empreinte SHA-256), un fichier que le lancement
/// refuserait (droits, propriétaire ; son empreinte), un lien (ce qu'il désigne, jamais suivi), ou quelque chose
/// d'illisible. Un lien ou un fichier refusé n'est jamais égal à l'empreinte gravée : il est proposé, « réparée ».
#[derive(Debug, Clone, PartialEq, Eq)]
enum Montree {
    Absente,
    Empreinte([u8; 32]),
    Refusee([u8; 32]),
    Lien(PathBuf),
    Illisible,
}

impl Montree {
    fn de(avant: &Avant) -> Montree {
        match avant {
            Avant::Absente => Montree::Absente,
            Avant::Lue(o, _) => Montree::Empreinte(Sha256::digest(o).into()),
            Avant::Refusee(o) => Montree::Refusee(Sha256::digest(o).into()),
            Avant::Lien(c) => Montree::Lien(c.clone()),
            Avant::Illisible => Montree::Illisible,
        }
    }
}

impl Vue {
    /// La fenêtre montrée à `chemin` (`None` : aucune ne sera touchée), relue maintenant.
    pub(super) fn de(chemin: Option<PathBuf>) -> Vue {
        let etat = chemin
            .as_deref()
            .map_or(Montree::Absente, |c| Montree::de(&Avant::de(c, TAILLE_MAX)));
        let dossier = chemin.as_deref().and_then(lancer_fenetre::dossiers_refuses);
        Vue {
            chemin,
            etat,
            partagee: false,
            dossier,
            laissee: None,
        }
    }

    /// Cette vue, sa fenêtre laissée telle quelle pour `pourquoi` : le programme sera posé seul.
    pub(super) fn laisser(mut self, pourquoi: Laissee) -> Vue {
        self.laissee = Some(pourquoi);
        self.partagee = false;
        self
    }

    /// La fenêtre est-elle laissée telle quelle (le programme posé seul) ?
    pub(super) fn laissee(&self) -> Option<Laissee> {
        self.laissee
    }

    /// Juste avant de poser le programme seul : ce qui a fait laisser la fenêtre tient-il encore (A-ACCORD-4) ?
    /// Redevenue lisible, ou la copie qui n'est plus un lien (ou l'est devenue) : changé depuis l'aperçu, rien n'est
    /// fait. La fenêtre n'est jamais touchée ici.
    fn toujours_laissee(&self, cible: &Path) -> Result<(), Echec> {
        self.dite(pour(cible).as_deref())?;
        let tient = match self.laissee {
            None => false,
            Some(Laissee::Illisible) => {
                !en_lien(cible)
                    && self
                        .chemin
                        .as_deref()
                        .is_some_and(|c| Avant::de(c, TAILLE_MAX) == Avant::Illisible)
            }
            Some(Laissee::CopieEnLien) => en_lien(cible),
            Some(Laissee::DeLaCle(_)) => !en_lien(cible),
        };
        if tient { Ok(()) } else { Err(changee_depuis_l_apercu()) }
    }

    /// La ligne de la fenêtre au résultat quand elle est laissée : jamais « à jour », la raison et ce qui n'est pas
    /// touché (code 1 : pas tout mis à jour).
    pub(super) fn laissee_dite(&self) -> Option<String> {
        Some(match self.laissee? {
            Laissee::Illisible => tr!(
                "sa fenêtre ne se lit pas (droits, dossier, tube ou fichier spécial, trop grande) : elle n'est pas touchée, le programme est posé seul et le menu s'ouvrira à sa place ; retirez ou réparez ce fichier, puis relancez la mise à jour",
                "its window cannot be read (permissions, folder, pipe or special file, too large): it is not touched, the program is placed alone and the menu will open instead; remove or repair this file, then run the update again"
            )
            .to_string(),
            Laissee::CopieEnLien => tr!(
                "la copie était un lien : sa fenêtre n'est posée ni à côté de lui ni à côté de ce qu'il désignait, le programme est posé seul ; pour avoir sa fenêtre, posez la copie elle-même à la place du lien",
                "the copy was a link: its window is placed neither next to it nor next to what it pointed to, the program is placed alone; to get its window, put the copy itself in place of the link"
            )
            .to_string(),
            Laissee::DeLaCle(raison) => crate::trf!(
                "la fenêtre de la clé n'est pas posée, non vérifiée ({}) : celle d'ici n'est pas touchée, le programme est posé seul",
                "the key's window is not placed, not verified ({}): the one here is not touched, the program is placed alone",
                raison
            ),
        })
    }

    /// Le chemin montré (`None` : aucune fenêtre ne sera touchée).
    pub(super) fn chemin(&self) -> Option<&Path> {
        self.chemin.as_deref()
    }

    /// Le chemin à montrer sur sa propre ligne : aucun pour une fenêtre déjà montrée avec un programme d'avant.
    pub(super) fn ligne(&self) -> Option<&Path> {
        self.chemin().filter(|_| !self.partagee)
    }

    /// Rien n'était au chemin montré : la fenêtre sera ajoutée.
    pub(super) fn absente(&self) -> bool {
        self.etat == Montree::Absente
    }

    /// Ce que dit la ligne de cette fenêtre dans l'aperçu, à côté d'un programme remplacé (80 caractères au plus) :
    /// d'abord si elle est laissée, puis si le lancement refuse son dossier, puis ce qui lui sera fait.
    pub(super) fn dite_a_cote(&self) -> &'static str {
        match self.laissee {
            Some(Laissee::Illisible) => {
                return tr!(
                    "programme seul, sa fenêtre ne se lit pas : non touchée, le menu s'ouvrira",
                    "program alone, its window cannot be read: untouched, the menu will open"
                );
            }
            Some(Laissee::CopieEnLien) => {
                return tr!(
                    "programme seul, la copie est un lien : sa fenêtre non touchée",
                    "program alone, the copy is a link: its window untouched"
                );
            }
            Some(Laissee::DeLaCle(_)) => {
                return tr!(
                    "programme seul, fenêtre de la clé non vérifiée : celle d'ici non touchée",
                    "program alone, the key's window not verified: the one here untouched"
                );
            }
            None => {}
        }
        if self.dossier.is_some() {
            return tr!(
                "sa fenêtre, posée, mais son dossier est refusé au lancement",
                "its window, placed, but its folder is refused at launch"
            );
        }
        match self.etat {
            Montree::Absente => tr!("sa fenêtre, nouvelle ici", "its window, new here"),
            Montree::Lien(_) => tr!(
                "sa fenêtre, un lien : remplacé par un fichier",
                "its window, a link: replaced by a file"
            ),
            Montree::Refusee(_) => tr!(
                "sa fenêtre, refusée au lancement (droits) : remplacée",
                "its window, refused at launch (permissions): replaced"
            ),
            Montree::Empreinte(_) | Montree::Illisible => tr!("sa fenêtre", "its window"),
        }
    }

    /// Le chemin que la pose toucherait est-il celui qui a été montré (ou aucun, si aucun ne l'a été) ?
    pub(super) fn dite(&self, maintenant: Option<&Path>) -> Result<(), Echec> {
        if self.chemin.as_deref() == maintenant {
            Ok(())
        } else {
            Err(changee_depuis_l_apercu())
        }
    }

    /// GitHub : la fenêtre à côté de `cible`, relue maintenant, est-elle encore celle qui a été montrée, au même
    /// chemin (un autre nom que le lancement cherche compris) et avec le même contenu ? `nouveau` : le programme qui
    /// sera posé (une fenêtre partagée peut déjà être la sienne).
    /// Une copie devenue un lien depuis l'aperçu (A-ORIGINE-3) : rien.
    fn telle_quelle(&self, cible: &Path, nouveau: &[u8]) -> Result<(), Echec> {
        if en_lien(cible) {
            return Err(devenue_lien());
        }
        self.dite(pour(cible).as_deref())?;
        match self.chemin.as_deref() {
            Some(c) => self.meme_etat(c, &Avant::de(c, TAILLE_MAX), nouveau),
            None => Ok(()),
        }
    }

    /// Ce qui est à `chemin` juste avant la pose (`avant`) est-il ce qui a été montré ? Une fenêtre montrée illisible
    /// ne l'est jamais (C-7-2, relecture 0.96) : rien ne dit que c'est la même ; non vérifié, donc non (une défense
    /// seulement : `trier` et `seule_a_poser` la mettent de côté avant). Une fenêtre partagée accepte aussi la fenêtre
    /// juste de `nouveau`, posée par le programme d'avant du même dossier, un fichier ordinaire.
    fn meme_etat(&self, chemin: &Path, avant: &Avant, nouveau: &[u8]) -> Result<(), Echec> {
        self.dite(Some(chemin))?;
        if self.etat == Montree::Illisible {
            return Err(illisible_refusee());
        }
        if self.etat == Montree::de(avant)
            || (self.partagee && matches!(avant, Avant::Lue(o, _) if juste(nouveau, o).is_ok()))
        {
            Ok(())
        } else {
            Err(changee_depuis_l_apercu())
        }
    }

    /// Ce que l'accord retient de cette fenêtre (C-7-1, relecture 0.96) : son chemin et ce qui y était (rien, une
    /// empreinte SHA-256, un fichier refusé au lancement et son empreinte, un lien et ce qu'il désigne). Un contenu
    /// changé entre l'aperçu et le clic change l'accord, même au même chemin ; un lien ou un fichier refusé ne vaut
    /// jamais l'empreinte du même contenu. Une fenêtre illisible y est comme telle, avec la raison pour laquelle elle
    /// est laissée (`Laissee`) et le refus d'un dossier : redevenue lisible avant le clic, l'accord change.
    pub(super) fn pour_l_accord(&self) -> Vec<u8> {
        let mut o = Vec::new();
        if let Some(c) = &self.chemin {
            o.push(1);
            o.extend_from_slice(c.as_os_str().as_encoded_bytes());
        }
        o.push(0);
        // Les champs de la ronde 3, avant l'état (qui finit par un chemin de lien sans fin marquée) : un code chacun,
        // une raison suivie d'un 0 (un chemin ni une raison ne contiennent d'octet nul).
        o.push(match self.laissee {
            None => 0,
            Some(Laissee::Illisible) => 1,
            Some(Laissee::CopieEnLien) => 2,
            Some(Laissee::DeLaCle(_)) => 3,
        });
        for raison in [
            match self.laissee {
                Some(Laissee::DeLaCle(r)) => Some(r),
                _ => None,
            },
            self.dossier,
        ] {
            if let Some(r) = raison {
                o.push(1);
                o.extend_from_slice(r.as_bytes());
            }
            o.push(0);
        }
        match &self.etat {
            Montree::Absente => o.push(0),
            Montree::Empreinte(e) => {
                o.push(1);
                o.extend_from_slice(e);
            }
            Montree::Illisible => o.push(2),
            Montree::Refusee(e) => {
                o.push(3);
                o.extend_from_slice(e);
            }
            Montree::Lien(c) => {
                o.push(4);
                o.extend_from_slice(c.as_os_str().as_encoded_bytes());
            }
        }
        o
    }
}

pub(super) fn changee_depuis_l_apercu() -> Echec {
    Echec::refuse(
        "fenetre/apercu",
        tr!(
            "la fenêtre à côté de ce programme a changé depuis ce qui a été montré (apparue, partie ou modifiée) : rien n'est remplacé ; relancez la mise à jour pour la voir",
            "the window next to this program changed since what was shown (appeared, gone or modified): nothing is replaced; run the update again to see it"
        ),
    )
}

fn illisible_refusee() -> Echec {
    Echec::refuse(
        "fenetre/apercu",
        tr!(
            "la fenêtre à côté de ce programme ne se lisait pas quand elle a été montrée (droits, dossier, trop grande) : rien ne dit que c'est la même, rien n'est remplacé ; retirez ou réparez ce fichier, puis relancez la mise à jour",
            "the window next to this program could not be read when it was shown (permissions, folder, too large): nothing shows it is the same one, nothing is replaced; remove or repair this file, then run the update again"
        ),
    )
}

/// La fenêtre posée à côté du programme de la clé (`de_la_source`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DeLaSource {
    /// Aucune à côté de lui : la copie se fait sans elle, comme avant la 0.97.
    Absente,
    /// Celle que gravent ses octets : elle suit.
    Juste(Vec<u8>),
    /// Là, mais pas posée (A-REFUS-5, ronde 3) : illisible, un lien, ou pas celle que grave le programme ; jamais
    /// comptée absente, dite (« non vérifiée »), le programme posé seul (`Laissee::DeLaCle`).
    Pas(&'static str),
}

/// La fenêtre posée à côté du programme `source` (la clé), jugée contre l'empreinte que gravent ses `octets`. Jamais
/// lue à travers un lien (ILLISIBLE-4) ; un fichier que le lancement refuserait sur la clé (une clé FAT donne ses
/// droits à tous) se copie : ses octets seuls comptent. Une copie faite sans elle laisse celle d'ici, que le
/// programme ne lancera pas si ce n'est pas la sienne.
pub(super) fn de_la_source(source: &Path, octets: &[u8]) -> DeLaSource {
    let Some(chemin) = a_cote(source) else {
        return DeLaSource::Absente;
    };
    match Avant::de(&chemin, TAILLE_MAX) {
        Avant::Lue(fenetre, _) | Avant::Refusee(fenetre) => match juste(octets, &fenetre) {
            Ok(()) => DeLaSource::Juste(fenetre),
            Err(_) => DeLaSource::Pas(tr!(
                "pas celle que grave son programme",
                "not the one its program carries"
            )),
        },
        Avant::Absente => DeLaSource::Absente,
        Avant::Lien(_) => DeLaSource::Pas(tr!("un lien", "a link")),
        Avant::Illisible => DeLaSource::Pas(tr!("illisible", "unreadable")),
    }
}

/// Depuis la clé (une seule copie, `copie`) : la fenêtre qui la suivra, et la vue de celle d'ici, à montrer et à
/// revérifier à la pose. Le programme n'est jamais bloqué par sa fenêtre (A-ACCORD-1, A-REFUS-5, ronde 3) : une
/// fenêtre de la clé pas posable, une fenêtre d'ici qui ne se lit pas, ou une copie qui est un lien, et la vue est
/// laissée (`Laissee`) : le programme seul, celle d'ici jamais touchée, dit. Pas de fenêtre sur la clé : aucune vue,
/// la copie se fait sans elle (comme avant la 0.97).
pub(super) fn de_la_cle(source: &Path, octets: &[u8], copie: &Path) -> (Option<Vec<u8>>, Vue) {
    let chemin = pour(copie);
    match de_la_source(source, octets) {
        DeLaSource::Absente => (None, Vue::de(None)),
        DeLaSource::Pas(raison) => (None, Vue::de(chemin).laisser(Laissee::DeLaCle(raison))),
        DeLaSource::Juste(f) => {
            let vue = Vue::de(chemin);
            if en_lien(copie) {
                (None, vue.laisser(Laissee::CopieEnLien))
            } else if vue.etat == Montree::Illisible {
                (None, vue.laisser(Laissee::Illisible))
            } else {
                (Some(f), vue)
            }
        }
    }
}

/// La fenêtre de la copie posée en `cible` : sous le nom que le lancement y cherche.
pub(super) fn pour(cible: &Path) -> Option<PathBuf> {
    lancer_fenetre::voisine(cible)
}

/// La fenêtre posée à `chemin` est-elle, relue maintenant (sans suivre de lien), celle que grave `programme`, et un
/// fichier que le lancement accepte ? Ce que dit la ligne de la fenêtre après une mise à jour : jamais « à jour »
/// sans l'avoir relue. Un programme qui ne lance aucune fenêtre, ou ne dit pas laquelle, le dit d'abord : la fenêtre
/// n'a pas été posée.
pub(super) fn posee_juste(programme: &[u8], chemin: &Path) -> Result<(), Echec> {
    match empreinte_fenetre::gravee(programme) {
        Some(Gravee::Empreinte(_)) => match Avant::de(chemin, TAILLE_MAX) {
            // Juste, mais un dossier que le lancement refuse (A-ORIGINE-2, ronde 3) : jamais « vérifiée » ; la
            // reposer ne réparerait rien, c'est dit.
            Avant::Lue(o, _) => juste(programme, &o).and_then(|()| match lancer_fenetre::dossiers_refuses(chemin) {
                None => Ok(()),
                Some(r) => Err(Echec::refuse(
                    "fenetre/juger",
                    crate::trf!(
                        "la fenêtre est posée, mais le lancement la refusera ({}) : la reposer ne réparerait rien, le menu s'ouvrira ; corrigez ce dossier (par exemple chmod go-w)",
                        "the window is placed, but the launch will refuse it ({}): placing it again would fix nothing, the menu will open; fix this folder (for example chmod go-w)",
                        r
                    ),
                )),
            }),
            Avant::Refusee(_) => Err(Echec::refuse(
                "fenetre/juger",
                tr!(
                    "la fenêtre posée serait refusée au lancement (droits ou propriétaire) : le menu s'ouvrira à sa place",
                    "the installed window would be refused at launch (permissions or owner): the menu will open instead"
                ),
            )),
            Avant::Lien(_) => Err(Echec::refuse(
                "fenetre/juger",
                tr!(
                    "un lien est à la place de la fenêtre : le lancement le refuse, le menu s'ouvrira à sa place",
                    "a link is in place of the window: the launch refuses it, the menu will open instead"
                ),
            )),
            Avant::Absente => Err(Echec::echoue(
                "fenetre/juger",
                tr!(
                    "la fenêtre posée n'est plus là",
                    "the installed window is no longer there"
                ),
            )),
            Avant::Illisible => Err(Echec::echoue(
                "fenetre/juger",
                tr!(
                    "la fenêtre posée ne se relit pas (droits, pas un fichier ordinaire, trop grande)",
                    "the installed window cannot be read back (permissions, not a regular file, too large)"
                ),
            )),
        },
        None => Err(Echec::refuse(
            "fenetre/juger",
            tr!(
                "le programme posé ne dit pas quelle fenêtre il lance : elle n'est pas posée",
                "the installed program does not say which window it launches: it is not placed"
            ),
        )),
        Some(Gravee::Aucune) => juste(programme, &[]),
    }
}

/// Les restes d'une mise à jour faite pendant que la fenêtre de la copie `cible` tournait (Windows) : effacés. Encore
/// ouverts, ils restent, et partiront la fois suivante. Seulement des fichiers ordinaires à un nom que la pose donne
/// (`<fenêtre>.ancien-<32 chiffres hexadécimaux>`, A-POSE-2, ronde 3 ; et `<fenêtre>.ancien`, le nom fixe d'avant) :
/// un dossier ou un lien à ce nom n'est pas à nous.
pub(super) fn effacer_l_ancienne(cible: &Path) {
    let Some(nom) = pour(cible).and_then(|f| f.file_name().and_then(|n| n.to_str()).map(str::to_string)) else {
        return;
    };
    let Some(dossier) = cible.parent() else {
        return;
    };
    let Ok(entrees) = std::fs::read_dir(dossier) else {
        return;
    };
    for e in entrees.flatten() {
        let a_nous = e
            .file_name()
            .to_str()
            .is_some_and(|n| n == format!("{nom}.ancien") || reste_de_pose(&nom, "ancien", n));
        if a_nous && std::fs::symlink_metadata(e.path()).is_ok_and(|m| m.file_type().is_file()) {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// `nom` est-il un nom de côté que la pose de la fenêtre `fenetre` donne (`<fenetre>.<sorte>-<32 hexadécimaux>`,
/// `nom_libre`, `poser_avec`) ? La désinstallation et le ménage ne retirent que ceux-là.
pub(crate) fn reste_de_pose(fenetre: &str, sorte: &str, nom: &str) -> bool {
    nom.strip_prefix(fenetre)
        .and_then(|r| r.strip_prefix('.'))
        .and_then(|r| r.strip_prefix(sorte))
        .and_then(|r| r.strip_prefix('-'))
        .is_some_and(|h| h.len() == 32 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// `chemin` lu sans jamais suivre de lien (Unix : O_NOFOLLOW ; Windows : FILE_FLAG_OPEN_REPARSE_POINT, le lien
/// lui-même), sans attendre un tube (O_NONBLOCK), un fichier ordinaire seulement, au plus `max` octets ; et ce que
/// le système dit de ce qui a été ouvert (droits, propriétaire : `lancer_fenetre::refusee`).
fn lire_sans_lien(chemin: &Path, max: u64) -> std::io::Result<(Vec<u8>, std::fs::Metadata)> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NOFOLLOW | libc::O_NONBLOCK);
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::custom_flags(&mut options, 0x0020_0000);
    let f = options.open(chemin)?;
    let m = f.metadata()?;
    if !m.is_file() {
        return Err(std::io::Error::other(tr!(
            "pas un fichier ordinaire",
            "not a regular file"
        )));
    }
    let mut o = Vec::new();
    (&f).take(max.saturating_add(1)).read_to_end(&mut o)?;
    if u64::try_from(o.len()).unwrap_or(u64::MAX) > max {
        return Err(std::io::Error::other(tr!("trop grande", "too large")));
    }
    Ok((o, m))
}

/// Ce qui était à la place de la fenêtre avant que la nouvelle y soit posée, pour l'y remettre et pour juger ce qui y
/// est (jamais à travers un lien : ILLISIBLE-4).
#[derive(Debug, PartialEq, Eq)]
enum Avant {
    /// Rien à ce nom (`NotFound` seulement : toute autre erreur est `Illisible`, ILLISIBLE-5).
    Absente,
    /// Un fichier ordinaire que le lancement accepterait, et ses droits (pour les lui rendre, A-ACCORD-5).
    Lue(Vec<u8>, Droits),
    /// Un fichier ordinaire que le lancement refuserait (droits, propriétaire).
    Refusee(Vec<u8>),
    /// Un lien, et ce qu'il désigne, jamais suivi.
    Lien(PathBuf),
    /// Là, mais illisible (droits, fichier spécial, démesurée) : elle ne pourra pas être remise.
    Illisible,
}

impl Avant {
    /// Ce qui est à `chemin` maintenant (au plus `max` octets lus).
    fn de(chemin: &Path, max: u64) -> Avant {
        match std::fs::symlink_metadata(chemin) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Avant::Absente,
            Err(_) => return Avant::Illisible,
            Ok(m) if m.file_type().is_symlink() => {
                return std::fs::read_link(chemin).map_or(Avant::Illisible, Avant::Lien);
            }
            Ok(_) => {}
        }
        match lire_sans_lien(chemin, max) {
            Ok((o, m)) if lancer_fenetre::refusee(&m).is_some() => Avant::Refusee(o),
            Ok((o, m)) => Avant::Lue(o, Droits::de(&m)),
            Err(_) => Avant::Illisible,
        }
    }

    /// `chemin` est-il encore exactement ce qu'il était ? Illisible avant : on ne peut pas le dire, donc non.
    fn toujours_la(&self, chemin: &Path, max: u64) -> bool {
        *self != Avant::Illisible && Avant::de(chemin, max) == *self
    }
}

/// Les droits d'un fichier que le lancement accepte (Unix : son mode et son propriétaire ; Windows : rien de plus).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Droits {
    mode: u32,
    proprietaire: u32,
}

impl Droits {
    fn de(m: &std::fs::Metadata) -> Droits {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Droits {
                mode: m.mode() & 0o7777,
                proprietaire: m.uid(),
            }
        }
        #[cfg(windows)]
        {
            let _ = m;
            Droits::default()
        }
    }

    /// Le mode qu'une remise peut lui rendre : jamais l'écriture du groupe ni des autres, ni un bit spécial.
    fn rendu(self) -> u32 {
        self.mode & 0o755
    }

    /// Une remise rend-elle exactement ces droits (même mode, et ce compte pour propriétaire) ?
    fn rendus_tels_quels(self) -> bool {
        #[cfg(unix)]
        return self.mode == self.rendu() && self.proprietaire == crate::socle::uid();
        #[cfg(windows)]
        {
            // Sous Windows, aucun mode n'est lu (`Droits::de`) : rien d'autre à rendre que les octets.
            let _ = self;
            true
        }
    }
}

/// Le mode d'une fenêtre neuve.
const MODE_NEUF: u32 = 0o755;

/// Ce que le retour en arrière a fait de la fenêtre d'avant (POSE-4) : rien à faire, remise (ses octets et ses
/// droits), remise avec ses octets seulement (le mode donné), ou pas remise, et pourquoi.
#[derive(Debug, PartialEq, Eq)]
enum Remise {
    Rien,
    Faite,
    SansSesDroits(u32),
    Pas(&'static str),
}

/// Après un échec : ce qui était à `chemin` (`avant`) y revient, seulement par-dessus la fenêtre que cette mise à
/// jour y a posée (`posee`) ; jamais par-dessus, ni à la place d'un fichier qu'un autre programme y aurait mis
/// depuis. Un lien revient en lien (Unix), jamais en copie de ce qu'il désignait.
fn remettre(avant: &Avant, chemin: &Path, posee: &[u8]) -> Remise {
    if avant.toujours_la(chemin, TAILLE_MAX) {
        return Remise::Rien;
    }
    match Avant::de(chemin, TAILLE_MAX) {
        Avant::Lue(o, _) | Avant::Refusee(o) if o == posee => {}
        _ => {
            return Remise::Pas(tr!(
                "ce qui est à sa place n'est ni elle ni celle posée : rien n'y est touché",
                "what is in its place is neither it nor the one placed: nothing is touched there"
            ));
        }
    }
    let pas_reposee = tr!("elle n'a pas pu être reposée", "it could not be put back");
    match avant {
        Avant::Absente => match std::fs::remove_file(chemin) {
            Ok(()) => Remise::Faite,
            Err(_) => Remise::Pas(tr!(
                "la fenêtre posée n'a pas pu être retirée",
                "the placed window could not be removed"
            )),
        },
        // Ses octets, et son mode quand il se rend tel quel (A-ACCORD-5, A-POSE-1) ; sinon c'est dit.
        Avant::Lue(o, d) => poser_dit(o, chemin, d.rendu()).map_or(Remise::Pas(pas_reposee), |()| {
            if d.rendus_tels_quels() {
                Remise::Faite
            } else {
                Remise::SansSesDroits(d.rendu())
            }
        }),
        // Refusée au lancement : jamais remise avec les droits qui la faisaient refuser.
        Avant::Refusee(o) => poser(o, chemin).map_or(Remise::Pas(pas_reposee), |()| Remise::SansSesDroits(MODE_NEUF)),
        Avant::Lien(vers) => remettre_lien(vers, chemin),
        Avant::Illisible => Remise::Pas(tr!(
            "elle ne se lisait pas, rien ne peut la refaire",
            "it could not be read, nothing can recreate it"
        )),
    }
}

/// Le lien d'avant (vers `vers`) refait à `chemin` : créé à côté sous un nom neuf, puis renommé d'un coup.
fn remettre_lien(vers: &Path, chemin: &Path) -> Remise {
    #[cfg(unix)]
    {
        let Ok((provisoire, ())) = nom_libre(chemin, |p| std::os::unix::fs::symlink(vers, p)) else {
            return Remise::Pas(tr!(
                "le lien d'avant n'a pas pu être refait",
                "the previous link could not be recreated"
            ));
        };
        if std::fs::rename(&provisoire, chemin).is_ok() {
            Remise::Faite
        } else {
            let _ = std::fs::remove_file(&provisoire);
            Remise::Pas(tr!(
                "le lien d'avant n'a pas pu être refait",
                "the previous link could not be recreated"
            ))
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (vers, chemin);
        Remise::Pas(tr!(
            "c'était un lien, que Windows ne laisse pas refaire ici : la fenêtre posée reste",
            "it was a link, which Windows does not let be recreated here: the placed window stays"
        ))
    }
}

/// `e`, avec ce que le retour en arrière a fait de la fenêtre d'avant, quand il faut le dire.
fn avec_remise(e: Echec, remise: &Remise) -> Echec {
    match remise {
        Remise::Rien | Remise::Faite => e,
        Remise::SansSesDroits(mode) => avec(
            e,
            &crate::trf!(
                "l'ancienne fenêtre est remise avec ses octets, en fichier neuf de ce compte (droits {}), pas avec ses droits ou son propriétaire d'avant",
                "the old window is put back with its bytes, as a new file of this account (permissions {}), not with its previous permissions or owner",
                format!("{mode:04o}")
            ),
        ),
        Remise::Pas(pourquoi) => avec(
            e,
            &crate::trf!(
                "l'ancienne fenêtre n'est pas remise ({}) : le menu s'ouvrira à sa place",
                "the old window is not put back ({}): the menu will open instead",
                pourquoi
            ),
        ),
    }
}

/// `octets` à la place de `cible`, `fenetre` posée à `chemin` d'abord, revérifiée ici contre l'empreinte gravée dans
/// `octets` (le seul endroit où cela se juge). Si le programme ne se pose pas, ce qui était à `chemin` y revient.
/// Tout ou rien : une fenêtre qui ne se pose pas arrête aussi le programme (GitHub, où l'aperçu les a montrés ensemble).
#[allow(clippy::too_many_arguments)] // chacun une garde : la liste des copies (registre) et la copie de cet ordinateur s'ajoutent
pub(super) fn installer_avec(
    octets: &[u8],
    cible: &Path,
    attendue: Version,
    registre: &Path,
    copie: &Path,
    essai: Essai,
    fenetre: &[u8],
    chemin: &Path,
    vue: &Vue,
) -> Result<(), Echec> {
    installer_avec_repli(
        octets,
        cible,
        attendue,
        registre,
        copie,
        essai,
        fenetre,
        chemin,
        Some(vue),
    )
    .map(|_| ())
}

/// `installer_avec` pour la copie depuis la clé (C-4, relecture 0.96) : une fenêtre qui ne peut pas être posée (un
/// dossier à son nom…), ou une copie qui est un lien (ronde 3), n'arrête pas le programme, posé seul ; la raison est
/// rendue pour être dite. La fenêtre d'avant reste (ou revient) à côté de lui, refusée par l'empreinte qu'il grave :
/// le menu.
#[allow(clippy::too_many_arguments)] // chacun une garde : la liste des copies (registre) et la copie de cet ordinateur s'ajoutent
pub(super) fn installer_avec_sinon_seul(
    octets: &[u8],
    cible: &Path,
    attendue: Version,
    registre: &Path,
    copie: &Path,
    essai: Essai,
    fenetre: &[u8],
    chemin: &Path,
) -> Result<Option<String>, Echec> {
    installer_avec_repli(octets, cible, attendue, registre, copie, essai, fenetre, chemin, None)
}

#[allow(clippy::too_many_arguments)] // chacun une garde : la liste des copies (registre) et la copie de cet ordinateur s'ajoutent
fn installer_avec_repli(
    octets: &[u8],
    cible: &Path,
    attendue: Version,
    registre: &Path,
    copie: &Path,
    essai: Essai,
    fenetre: &[u8],
    chemin: &Path,
    vue: Option<&Vue>,
) -> Result<Option<String>, Echec> {
    juste(octets, fenetre)?;
    // Une copie en lien (A-ORIGINE-1, A-ORIGINE-3, ronde 3) : rien n'est posé à côté. Avec un aperçu, elle y était un
    // fichier (sinon sa fenêtre aurait été laissée) : changé, rien n'est fait. Sans, le programme seul, dit.
    if en_lien(cible) {
        if vue.is_some() {
            return Err(devenue_lien());
        }
        installer(octets, cible, attendue, registre, copie, essai).map_err(ratee)?;
        return Ok(Some(
            tr!(
                "la copie est un lien : sa fenêtre n'est posée ni à côté de lui ni à côté de ce qu'il désigne, le programme est posé seul, le raccourci ouvrira le menu",
                "the copy is a link: its window is placed neither next to it nor next to what it points to, the program is placed alone, the shortcut will open the menu"
            )
            .to_string(),
        ));
    }
    let avant = Avant::de(chemin, TAILLE_MAX);
    // Avec un aperçu (`vue`) : ce qui est là doit être ce qu'il a montré, et tout ou rien. Sans (la copie depuis la
    // clé, C-4) : une fenêtre qui ne se pose pas laisse le programme se poser seul.
    let seul_sinon = match vue {
        Some(v) => {
            v.meme_etat(chemin, &avant, octets)?;
            false
        }
        None => true,
    };
    // Le programme d'avant, relu après un échec (C-2) : l'ancienne fenêtre ne revient qu'à côté de lui, ou là où il
    // n'y en avait pas et toujours pas. Lu à travers un lien s'il en est un : c'est le programme, pas sa fenêtre.
    // Illisible : rien ne dit que c'est le même, donc non.
    let lu = || match std::fs::symlink_metadata(cible) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(None),
        Err(_) => None,
        Ok(_) => lire_octets(cible, TAILLE_PROGRAMME).ok().map(Some),
    };
    let programme_avant = lu();
    let toujours_le_meme = || programme_avant.is_some() && lu() == programme_avant;
    // Déjà la fenêtre juste, en fichier que le lancement accepte : rien à poser (une fenêtre partagée, déjà posée).
    let changee = !matches!(&avant, Avant::Lue(o, _) if o == fenetre);
    if changee && let Err((e, renommee)) = poser_dit(fenetre, chemin, MODE_NEUF) {
        // Rien de renommé : ce qui était là n'a pas bougé, rien à remettre ni à dire (A-POSE-4).
        let e = if renommee {
            avec_remise(e, &remettre(&avant, chemin, fenetre))
        } else {
            e
        };
        if !seul_sinon {
            return Err(e);
        }
        installer(octets, cible, attendue, registre, copie, essai).map_err(ratee)?;
        return Ok(Some(crate::trf!(
            "la fenêtre n'a pas pu être posée à côté de la copie ({}) : le programme est posé seul, le raccourci ouvrira le menu",
            "the window could not be placed next to the copy ({}): the program is placed alone, the shortcut will open the menu",
            e
        )));
    }
    installer(octets, cible, attendue, registre, copie, essai).map(|()| None).map_err(|e| {
        if changee && !toujours_le_meme() {
            return ratee(format!(
                "{e}\n    {}",
                tr!(
                    "le programme n'est plus celui d'avant (changé pendant la mise à jour par un autre programme, ou illisible) : l'ancienne fenêtre n'est pas remise à côté de lui ; relancez la mise à jour",
                    "the program is no longer the previous one (changed during the update by another program, or unreadable): the old window is not put back next to it; run the update again"
                )
            ));
        }
        let remise = if changee {
            remettre(&avant, chemin, fenetre)
        } else {
            Remise::Rien
        };
        avec_remise(ratee(e), &remise)
    })
}

/// La copie de même version que la clé : seulement sa fenêtre, posée si celle d'ici n'est pas déjà la même, en
/// fichier que le lancement accepte.
pub(super) fn poser_si_autre(fenetre: &[u8], chemin: &Path) -> Result<(), Echec> {
    if matches!(Avant::de(chemin, TAILLE_MAX), Avant::Lue(o, _) if o == fenetre) {
        return Ok(());
    }
    poser(fenetre, chemin)
}

/// `octets` à `chemin`, comme `installer` le fait pour le programme : à côté d'abord (créé neuf, jamais par un lien),
/// relu et comparé, puis renommé d'un coup ; rien ne traîne à côté en cas d'échec.
fn poser(octets: &[u8], chemin: &Path) -> Result<(), Echec> {
    poser_dit(octets, chemin, MODE_NEUF).map_err(|(e, _)| e)
}

/// `poser`, avec le mode à donner (Unix) ; un échec dit si le renommage avait eu lieu (A-POSE-4 : sans lui, ce qui
/// était à `chemin` n'a pas bougé).
fn poser_dit(octets: &[u8], chemin: &Path, mode: u32) -> Result<(), (Echec, bool)> {
    poser_avec(octets, chemin, mode, |_| ())
}

/// Un nom de côté tiré au hasard (`<nom>.<sorte>-<32 hexadécimaux>`, A-POSE-3, ronde 3) : 128 bits de la source
/// d'aléa du système, que rien ne laisse deviner d'avance (le numéro du processus, un compteur le laissaient).
fn nom_au_hasard(nom: &str, sorte: &str) -> Result<String, Echec> {
    let mut octets = [0u8; 16];
    getrandom::fill(&mut octets).map_err(|e| ratee(format!("{e}")))?;
    Ok(format!("{nom}.{sorte}-{}", super::github::hex(&octets)))
}

/// Un nom neuf à côté de `chemin` (`nom_au_hasard`), que `creer` crée sans jamais écraser (`AlreadyExists` : un
/// autre). Deux mises à jour en même temps n'ont jamais le même (POSE-5), et rien n'est effacé d'avance : un fichier
/// à ce nom n'est pas le nôtre.
fn nom_libre<T>(chemin: &Path, creer: impl Fn(&Path) -> std::io::Result<T>) -> Result<(PathBuf, T), Echec> {
    nom_libre_tire(chemin, nom_au_hasard, creer)
}

/// `nom_libre`, les noms donnés par `tirer` (le hasard ; des noms choisis, dans les essais).
fn nom_libre_tire<T>(
    chemin: &Path,
    mut tirer: impl FnMut(&str, &str) -> Result<String, Echec>,
    creer: impl Fn(&Path) -> std::io::Result<T>,
) -> Result<(PathBuf, T), Echec> {
    let nom = chemin
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| {
            Echec::refuse(
                "fenetre/poser",
                tr!("chemin sans nom de fichier", "path without a file name"),
            )
        })?;
    for _ in 0..16 {
        let p = chemin.with_file_name(tirer(&nom, "nouveau")?);
        match creer(&p) {
            Ok(t) => return Ok((p, t)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(ratee(e)),
        }
    }
    Err(ratee(tr!(
        "aucun nom provisoire libre à côté de la fenêtre",
        "no free temporary name next to the window"
    )))
}

/// `poser`, avec ce qui se passe juste avant le renommage (`avant_renommage`, le chemin de la copie provisoire) : rien
/// en vrai ; un autre programme du compte, dans les essais.
///
/// La copie provisoire est tenue par son descripteur du début à la fin (C-1, relecture 0.96 ; la méthode de G-2 pour
/// le programme) : par son seul nom, un programme du compte pouvait l'échanger entre la relecture et le renommage, et
/// « fait » était dit sur une autre fenêtre. Après le renommage, la fenêtre posée doit être ce même fichier, avec ces
/// mêmes octets. En cas d'échec avant le renommage, la copie provisoire est effacée si c'est encore la nôtre.
///
/// Sous Windows, la fenêtre en marche est mise de côté sous un nom tiré au hasard (`<nom>.ancien-<hex>`, A-POSE-2,
/// ronde 3 : un nom fixe, effacé à l'aveugle, se bloquait par un dossier à ce nom), que `effacer_l_ancienne` retire
/// ensuite. Un échec dit si le renommage avait eu lieu.
fn poser_avec(
    octets: &[u8],
    chemin: &Path,
    mode: u32,
    avant_renommage: impl FnOnce(&Path),
) -> Result<(), (Echec, bool)> {
    let (provisoire, f) = nom_libre(chemin, creer_neuf).map_err(|e| (e, false))?;
    let nom = chemin.file_name().unwrap_or_default().to_string_lossy();
    let ancien = match nom_au_hasard(&nom, "ancien") {
        Ok(a) => chemin.with_file_name(a),
        Err(e) => {
            let _ = std::fs::remove_file(&provisoire);
            return Err((e, false));
        }
    };
    let mut renommee = false;
    let mut lue: Option<std::fs::File> = None;
    let posee = (|| -> Result<(), Echec> {
        let f = &*lue.insert(ecrire_provisoire(f, &provisoire, octets, mode)?);
        if !meme_contenu(f, octets)? {
            return Err(ratee(tr!(
                "la copie relue ne correspond pas",
                "the copy read back does not match"
            )));
        }
        avant_renommage(&provisoire);
        mettre_en_place_sous(&provisoire, chemin, &ancien).map_err(ratee)?;
        renommee = true;
        verifier_posee(f, chemin, octets)
    })();
    if posee.is_err() && !renommee && encore_la_notre(&provisoire, lue.as_ref(), octets) {
        let _ = std::fs::remove_file(&provisoire);
    }
    posee.map_err(|e| (e, renommee))
}

/// La copie provisoire, créée neuve : jamais un fichier déjà là, jamais par un lien posé à ce nom (O_EXCL).
fn creer_neuf(p: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(p)
}

/// La copie provisoire à `provisoire` est-elle encore la nôtre ? Sous Unix, le même fichier (appareil et inode) que
/// celui tenu ; sous Windows, les mêmes octets (effacer une copie des mêmes octets ne perd rien). Pas encore rouverte
/// (l'écriture a échoué) : le nom vient d'être créé neuf par nous, il l'est.
fn encore_la_notre(provisoire: &Path, tenue: Option<&std::fs::File>, octets: &[u8]) -> bool {
    let Some(f) = tenue else {
        return true;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = octets;
        matches!(
            (f.metadata(), std::fs::symlink_metadata(provisoire)),
            (Ok(a), Ok(b)) if a.dev() == b.dev() && a.ino() == b.ino()
        )
    }
    #[cfg(not(unix))]
    {
        let _ = f;
        lire_sans_lien(provisoire, TAILLE_MAX).is_ok_and(|(o, _)| o == octets)
    }
}

/// La copie provisoire `f`, créée neuve par `nom_libre` (O_EXCL : un lien posé à ce nom n'est jamais suivi, la
/// création échoue plutôt), écrite, mise sur le disque, ses droits donnés par le descripteur. Sous Linux, rouverte en
/// lecture seule par son descripteur (`/proc/self/fd`, le même fichier même si le nom a changé) et le descripteur
/// d'écriture fermé. Sous Windows, rouverte en lecture par son nom, l'écriture refusée aux autres tant qu'elle est
/// tenue (FILE_SHARE_READ | FILE_SHARE_DELETE : sans le partage de suppression, le renommage échouerait) ; ce qui est
/// ouvert est relu ensuite (par le nom, donc : entre la fermeture et la réouverture, un programme du compte peut
/// l'échanger ; la relecture après le renommage le verrait).
fn ecrire_provisoire(
    mut f: std::fs::File,
    provisoire: &Path,
    octets: &[u8],
    mode: u32,
) -> Result<std::fs::File, Echec> {
    use std::io::Write;
    f.write_all(octets).and_then(|()| f.sync_all()).map_err(ratee)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(mode))
            .map_err(ratee)?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let _ = provisoire;
        let lecture = std::fs::File::open(format!("/proc/self/fd/{}", f.as_raw_fd())).map_err(|e| {
            ratee(crate::trf!(
                "copie provisoire pas rouverte par son descripteur (/proc) : {}",
                "temporary copy not reopened through its descriptor (/proc): {}",
                e
            ))
        })?;
        drop(f);
        Ok(lecture)
    }
    #[cfg(windows)]
    {
        drop(f);
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        std::os::windows::fs::OpenOptionsExt::share_mode(&mut options, 1 | 4);
        options.open(provisoire).map_err(ratee)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = provisoire;
        Ok(f)
    }
}

/// Le fichier ouvert `f` contient-il exactement `octets` ? Relu depuis le début, jamais plus d'un octet de trop.
fn meme_contenu(mut f: &std::fs::File, octets: &[u8]) -> Result<bool, Echec> {
    use std::io::{Read, Seek};
    f.seek(std::io::SeekFrom::Start(0)).map_err(ratee)?;
    let mut lu = Vec::with_capacity(octets.len());
    let borne = u64::try_from(octets.len()).unwrap_or(u64::MAX).saturating_add(1);
    f.take(borne).read_to_end(&mut lu).map_err(ratee)?;
    Ok(lu == octets)
}

/// Après le renommage : la fenêtre posée à `chemin` est-elle la copie écrite (`f`), avec les octets reçus ? Sous Unix,
/// ouverte sans suivre de lien, le même fichier (appareil et inode) que `f`, puis relue. Sous Windows, relue par une
/// poignée qui refuse l'écriture et la suppression aux autres le temps de la lecture (l'identité du fichier n'y est
/// pas comparée ; les octets, eux, le sont). Sinon, un échec qui le dit : jamais « fait » sur une autre fenêtre (que
/// `vanguard`, de toute façon, ne lancera pas : son empreinte n'est pas la gravée).
fn verifier_posee(f: &std::fs::File, chemin: &Path, octets: &[u8]) -> Result<(), Echec> {
    // Changée par un autre programme : jamais crue, `Raison::Falsifie`, sa phrase seule rendue.
    let changee = || -> Echec {
        Echec::new("fenetre/poser", Raison::Falsifie).detail(tr!(
            "la fenêtre posée n'est pas celle qui a été reçue (changée pendant la mise à jour par un autre programme) : la mise à jour n'est pas faite, relancez-la",
            "the installed window is not the one that was received (changed during the update by another program): the update is not done, run it again"
        ))
    };
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NOFOLLOW | libc::O_NONBLOCK);
    // FILE_SHARE_READ seul.
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::share_mode(&mut options, 1);
    let posee = options.open(chemin).map_err(|_| changee())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let (a, b) = (f.metadata().map_err(ratee)?, posee.metadata().map_err(ratee)?);
        if !b.is_file() || a.dev() != b.dev() || a.ino() != b.ino() {
            return Err(changee());
        }
    }
    #[cfg(not(unix))]
    let _ = f;
    if meme_contenu(&posee, octets)? {
        Ok(())
    } else {
        Err(changee())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demarrage::empreinte_fenetre::marque_d_essai;
    use crate::mise_a_jour::NOM;

    const V: Version = (0, 96, 0, 5);

    /// Un programme inventé de version 0.96.0+5, qui grave `marque` (ou aucune).
    fn programme(marque: Option<&[u8]>) -> Vec<u8> {
        [
            b"prog ".as_slice(),
            &super::super::entete(),
            b"0.96.0+5; ",
            marque.unwrap_or_default(),
        ]
        .concat()
    }

    fn lancant(fenetre: &[u8]) -> Vec<u8> {
        programme(Some(&marque_d_essai(&Sha256::digest(fenetre).into())))
    }

    const SANS_ESSAI: Essai = |_, _| Ok(());
    const ESSAI_RATE: Essai = |_, _| Err("ne démarre pas".into());

    fn dossier(nom: &str) -> PathBuf {
        let d = crate::socle::dossier_local().join(nom);
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// La fenêtre à côté de `cible` telle qu'un aperçu la montrerait maintenant.
    fn montree(cible: &Path) -> Vue {
        Vue::de(pour(cible))
    }

    fn rien_a_cote(d: &Path) -> bool {
        std::fs::read_dir(d)
            .unwrap()
            .all(|e| !e.unwrap().file_name().to_string_lossy().contains(".nouveau"))
    }

    /// GitHub : la fenêtre posée à côté du programme remplacé suit, vérifiée contre l'empreinte gravée dans le
    /// nouveau ; tout ou rien, et l'ancienne remise si le programme ne se pose pas.
    #[test]
    fn la_fenetre_suit_le_programme_de_github() {
        let d = dossier("essai-sa-fenetre-github");
        let cible = d.join(NOM);
        let fenetre = pour(&cible).unwrap();
        let neuve = b"fenetre 0.96".to_vec();
        let nouveau = lancant(&neuve);
        let remettre = || {
            std::fs::write(&cible, b"ancien programme").unwrap();
            std::fs::write(&fenetre, b"ancienne fenetre").unwrap();
        };
        let inchange = || {
            std::fs::read(&cible).unwrap() == b"ancien programme"
                && std::fs::read(&fenetre).unwrap() == b"ancienne fenetre"
        };
        let appels = std::cell::Cell::new(0);
        // La bonne fenêtre : les deux remplacés.
        remettre();
        let mut recevoir = || -> Result<Vec<u8>, Echec> {
            appels.set(appels.get() + 1);
            Ok(neuve.clone())
        };
        installer_avec_sa_fenetre(
            &nouveau,
            &cible,
            V,
            &crate::socle::dossier_local(),
            &crate::mise_a_jour::copie_de_cet_ordinateur(),
            SANS_ESSAI,
            &montree(&cible),
            &mut recevoir,
        )
        .unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), nouveau);
        assert_eq!(std::fs::read(&fenetre).unwrap(), neuve);
        assert!(rien_a_cote(&d));
        // Une autre fenêtre que celle gravée, ou aucune reçue : rien n'est remplacé.
        remettre();
        let mut autre = || -> Result<Vec<u8>, Echec> { Ok(b"fenetre plantee".to_vec()) };
        assert!(
            installer_avec_sa_fenetre(
                &nouveau,
                &cible,
                V,
                &crate::socle::dossier_local(),
                &crate::mise_a_jour::copie_de_cet_ordinateur(),
                SANS_ESSAI,
                &montree(&cible),
                &mut autre
            )
            .is_err()
        );
        assert!(inchange());
        let mut panne = || -> Result<Vec<u8>, Echec> { Err(Echec::echoue("essai", "téléchargement interrompu")) };
        assert!(
            installer_avec_sa_fenetre(
                &nouveau,
                &cible,
                V,
                &crate::socle::dossier_local(),
                &crate::mise_a_jour::copie_de_cet_ordinateur(),
                SANS_ESSAI,
                &montree(&cible),
                &mut panne
            )
            .is_err()
        );
        assert!(inchange());
        // Le programme ne se pose pas : l'ancienne fenêtre est remise.
        assert!(
            installer_avec_sa_fenetre(
                &nouveau,
                &cible,
                V,
                &crate::socle::dossier_local(),
                &crate::mise_a_jour::copie_de_cet_ordinateur(),
                ESSAI_RATE,
                &montree(&cible),
                &mut recevoir
            )
            .is_err()
        );
        assert!(inchange());
        assert!(rien_a_cote(&d));
        // Un programme sans marque : refusé sans rien télécharger. Un qui ne lance aucune fenêtre : posé seul.
        let avant = appels.get();
        assert!(
            installer_avec_sa_fenetre(
                &programme(None),
                &cible,
                V,
                &crate::socle::dossier_local(),
                &crate::mise_a_jour::copie_de_cet_ordinateur(),
                SANS_ESSAI,
                &montree(&cible),
                &mut recevoir
            )
            .is_err()
        );
        assert!(inchange());
        let sans_fenetre = programme(Some(&[&marque_d_essai(&[0; 32])[..17], b"AUCUNE;"].concat()));
        installer_avec_sa_fenetre(
            &sans_fenetre,
            &cible,
            V,
            &crate::socle::dossier_local(),
            &crate::mise_a_jour::copie_de_cet_ordinateur(),
            SANS_ESSAI,
            &montree(&cible),
            &mut recevoir,
        )
        .unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), sans_fenetre);
        assert_eq!(std::fs::read(&fenetre).unwrap(), b"ancienne fenetre");
        assert_eq!(appels.get(), avant);
        // Pas de fenêtre à côté (C-6, 0.97) : celle de la nouvelle version est ajoutée là où le lancement la cherche,
        // vérifiée ; une autre que celle gravée, et rien n'est posé, ni elle ni le programme.
        std::fs::remove_file(&fenetre).unwrap();
        let vue = montree(&cible);
        assert!(
            installer_avec_sa_fenetre(
                &nouveau,
                &cible,
                V,
                &crate::socle::dossier_local(),
                &crate::mise_a_jour::copie_de_cet_ordinateur(),
                SANS_ESSAI,
                &vue,
                &mut autre
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&cible).unwrap(), sans_fenetre);
        assert!(std::fs::symlink_metadata(&fenetre).is_err());
        installer_avec_sa_fenetre(
            &nouveau,
            &cible,
            V,
            &crate::socle::dossier_local(),
            &crate::mise_a_jour::copie_de_cet_ordinateur(),
            SANS_ESSAI,
            &vue,
            &mut recevoir,
        )
        .unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), nouveau);
        assert_eq!(std::fs::read(&fenetre).unwrap(), neuve);
        assert_eq!(appels.get(), avant + 1);
        // Un programme qui ne dit pas sa fenêtre, là où il n'y en a pas : posé seul (rien à remplacer), rien n'est
        // téléchargé.
        std::fs::remove_file(&fenetre).unwrap();
        installer_avec_sa_fenetre(
            &programme(None),
            &cible,
            V,
            &crate::socle::dossier_local(),
            &crate::mise_a_jour::copie_de_cet_ordinateur(),
            SANS_ESSAI,
            &montree(&cible),
            &mut recevoir,
        )
        .unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), programme(None));
        assert!(std::fs::symlink_metadata(&fenetre).is_err());
        assert_eq!(appels.get(), avant + 1);
        // Posée sous le nom de la page de la version : c'est elle qui est remplacée.
        let page = d.join(lancer_fenetre::NOM_PAGE);
        std::fs::write(&page, b"ancienne fenetre").unwrap();
        installer_avec_sa_fenetre(
            &nouveau,
            &cible,
            V,
            &crate::socle::dossier_local(),
            &crate::mise_a_jour::copie_de_cet_ordinateur(),
            SANS_ESSAI,
            &montree(&cible),
            &mut recevoir,
        )
        .unwrap();
        assert_eq!(std::fs::read(&page).unwrap(), neuve);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// C-1 (relecture 0.96) : la fenêtre provisoire était relue puis renommée par son NOM ; un programme du compte
    /// qui l'échangeait entre les deux faisait poser sa fausse fenêtre, et la mise à jour disait « fait ». Tenue par
    /// son descripteur, la fenêtre posée doit être ce même fichier, avec ces octets : sinon un échec qui le dit.
    #[test]
    fn une_fenetre_provisoire_echangee_par_son_nom_n_est_jamais_dite_posee() {
        let d = dossier("essai-sa-fenetre-echange");
        let fenetre = pour(&d.join(NOM)).unwrap();
        std::fs::write(&fenetre, b"ancienne fenetre").unwrap();
        // Sous Windows, la provisoire tenue passe « en suppression » et son nom ne peut pas être réécrit : l'échange
        // échoue de lui-même. Sous Unix il réussit toujours, sinon l'essai ne prouverait rien.
        let substituee = std::cell::Cell::new(false);
        let echanger = |provisoire: &Path| {
            let fait = std::fs::remove_file(provisoire)
                .and_then(|()| std::fs::write(provisoire, b"FAUSSE FENETRE"))
                .is_ok();
            substituee.set(fait);
        };
        let r = poser_avec(b"fenetre 0.96", &fenetre, MODE_NEUF, echanger);
        assert!(substituee.get() || cfg!(windows), "l'échange n'a pas eu lieu");
        if substituee.get() {
            assert!(r.is_err(), "« fait » sur une fenêtre échangée : {r:?}");
        }
        if r.is_ok() {
            assert_eq!(std::fs::read(&fenetre).unwrap(), b"fenetre 0.96");
        }
        // Sans échange : posée.
        poser_avec(b"fenetre 0.96", &fenetre, MODE_NEUF, |_| ()).unwrap();
        assert_eq!(std::fs::read(&fenetre).unwrap(), b"fenetre 0.96");
        assert!(rien_a_cote(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// C-2 (relecture 0.96) : un échec après que le fichier du programme a changé remettait l'ancienne fenêtre à
    /// côté d'un programme inconnu, et disait seulement « pas faite ». Le programme d'avant est relu : changé, rien
    /// n'est remis, et c'est dit.
    #[test]
    fn un_programme_change_pendant_l_echec_n_est_pas_apparie_a_l_ancienne_fenetre() {
        const CHANGE_PUIS_RATE: Essai = |provisoire, _| {
            // Sous Linux, l'essai reçoit /proc/self/fd/N (lot-095) : son vrai chemin donne le dossier du programme.
            let vrai = std::fs::read_link(provisoire).unwrap_or_else(|_| provisoire.to_path_buf());
            std::fs::write(vrai.with_file_name(NOM), b"programme inconnu").unwrap();
            Err("ne démarre pas".into())
        };
        let d = dossier("essai-sa-fenetre-change");
        let cible = d.join(NOM);
        let fenetre = pour(&cible).unwrap();
        std::fs::write(&cible, b"ancien programme").unwrap();
        std::fs::write(&fenetre, b"ancienne fenetre").unwrap();
        let neuve = b"fenetre 0.96".to_vec();
        let mut recevoir = || -> Result<Vec<u8>, Echec> { Ok(neuve.clone()) };
        let r = installer_avec_sa_fenetre(
            &lancant(&neuve),
            &cible,
            V,
            &crate::socle::dossier_local(),
            &crate::mise_a_jour::copie_de_cet_ordinateur(),
            CHANGE_PUIS_RATE,
            &montree(&cible),
            &mut recevoir,
        );
        let e = r.expect_err("un échec").to_string();
        assert!(
            e.contains("n'est plus celui d'avant") || e.contains("no longer the previous"),
            "{e}"
        );
        assert_ne!(
            std::fs::read(&fenetre).unwrap(),
            b"ancienne fenetre",
            "remise à côté d'un inconnu"
        );
        assert!(rien_a_cote(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// C-7 (relecture 0.96) : la présence de la fenêtre était recalculée à la pose ; une fenêtre apparue pendant le
    /// téléchargement était remplacée sans avoir été montrée. Ce qui se pose est ce qui a été montré, sinon rien, le
    /// programme non plus, et c'est dit. Ici, la pose, après l'accord (pendant le téléchargement) ; un changement
    /// entre l'aperçu et le clic de l'interface change déjà l'accord (C-7-1, `apercu`).
    #[test]
    fn une_fenetre_changee_depuis_l_apercu_n_est_jamais_remplacee() {
        let d = dossier("essai-sa-fenetre-apercu");
        let cible = d.join(NOM);
        let fenetre = pour(&cible).unwrap();
        let page = d.join(lancer_fenetre::NOM_PAGE);
        let neuve = b"fenetre 0.96".to_vec();
        let nouveau = lancant(&neuve);
        let dit = |r: Result<(), Echec>| {
            let e = r.expect_err("posé sans avoir été montré").to_string();
            assert!(
                e.contains("depuis ce qui a été montré") || e.contains("since what was shown"),
                "{e}"
            );
        };
        let programme_inchange = || std::fs::read(&cible).unwrap() == b"ancien programme";
        std::fs::write(&cible, b"ancien programme").unwrap();
        // GitHub. Aucune fenêtre montrée, une apparaît pendant le téléchargement du programme : rien, rien téléchargé.
        let appels = std::cell::Cell::new(0);
        let mut recevoir = || -> Result<Vec<u8>, Echec> {
            appels.set(appels.get() + 1);
            Ok(neuve.clone())
        };
        let aucune = montree(&cible);
        std::fs::write(&fenetre, b"fenetre apparue").unwrap();
        dit(installer_avec_sa_fenetre(
            &nouveau,
            &cible,
            V,
            &crate::socle::dossier_local(),
            &crate::mise_a_jour::copie_de_cet_ordinateur(),
            SANS_ESSAI,
            &aucune,
            &mut recevoir,
        ));
        assert!(programme_inchange());
        assert_eq!(std::fs::read(&fenetre).unwrap(), b"fenetre apparue");
        assert_eq!(appels.get(), 0);
        // Montrée, puis changée pendant le téléchargement de la nouvelle fenêtre.
        std::fs::write(&fenetre, b"ancienne fenetre").unwrap();
        let vue = montree(&cible);
        let mut changer = || -> Result<Vec<u8>, Echec> {
            std::fs::write(&fenetre, b"fenetre changee").unwrap();
            Ok(neuve.clone())
        };
        dit(installer_avec_sa_fenetre(
            &nouveau,
            &cible,
            V,
            &crate::socle::dossier_local(),
            &crate::mise_a_jour::copie_de_cet_ordinateur(),
            SANS_ESSAI,
            &vue,
            &mut changer,
        ));
        assert!(programme_inchange());
        assert_eq!(std::fs::read(&fenetre).unwrap(), b"fenetre changee");
        // Montrée, puis partie.
        let vue = montree(&cible);
        std::fs::remove_file(&fenetre).unwrap();
        dit(installer_avec_sa_fenetre(
            &nouveau,
            &cible,
            V,
            &crate::socle::dossier_local(),
            &crate::mise_a_jour::copie_de_cet_ordinateur(),
            SANS_ESSAI,
            &vue,
            &mut recevoir,
        ));
        assert!(programme_inchange());
        assert!(std::fs::symlink_metadata(&fenetre).is_err());
        // Montrée sous le nom de la page ; une autre apparaît sous le premier nom pendant le téléchargement.
        std::fs::write(&page, b"ancienne fenetre").unwrap();
        let vue = montree(&cible);
        let mut apparait = || -> Result<Vec<u8>, Echec> {
            std::fs::write(&fenetre, b"fenetre apparue").unwrap();
            Ok(neuve.clone())
        };
        dit(installer_avec_sa_fenetre(
            &nouveau,
            &cible,
            V,
            &crate::socle::dossier_local(),
            &crate::mise_a_jour::copie_de_cet_ordinateur(),
            SANS_ESSAI,
            &vue,
            &mut apparait,
        ));
        assert!(programme_inchange());
        assert_eq!(std::fs::read(&page).unwrap(), b"ancienne fenetre");
        assert_eq!(std::fs::read(&fenetre).unwrap(), b"fenetre apparue");
        std::fs::remove_file(&page).unwrap();
        // Rien n'a changé depuis l'aperçu : les deux posés.
        std::fs::write(&fenetre, b"ancienne fenetre").unwrap();
        let vue = montree(&cible);
        installer_avec_sa_fenetre(
            &nouveau,
            &cible,
            V,
            &crate::socle::dossier_local(),
            &crate::mise_a_jour::copie_de_cet_ordinateur(),
            SANS_ESSAI,
            &vue,
            &mut recevoir,
        )
        .unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), nouveau);
        assert_eq!(std::fs::read(&fenetre).unwrap(), neuve);
        // La clé (`installer_avec`) : la fenêtre d'ici changée, ou apparue, depuis la question.
        for (avant, apres) in [
            (Some(b"ancienne fenetre"), b"fenetre changee"),
            (None, b"fenetre apparue"),
        ] {
            std::fs::write(&cible, b"ancien programme").unwrap();
            match avant {
                Some(o) => std::fs::write(&fenetre, o).unwrap(),
                None => std::fs::remove_file(&fenetre).unwrap(),
            }
            let vue = Vue::de(Some(fenetre.clone()));
            std::fs::write(&fenetre, apres).unwrap();
            dit(installer_avec(
                &nouveau,
                &cible,
                V,
                &crate::socle::dossier_local(),
                &crate::mise_a_jour::copie_de_cet_ordinateur(),
                SANS_ESSAI,
                &neuve,
                &fenetre,
                &vue,
            ));
            assert!(programme_inchange());
            assert_eq!(std::fs::read(&fenetre).unwrap(), apres);
        }
        assert!(rien_a_cote(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// La clé : la fenêtre posée à côté de son programme suit la copie si c'est la sienne ; sinon la copie se fait
    /// sans elle. Un programme qui ne se pose pas ne laisse pas une fenêtre neuve derrière lui.
    #[test]
    fn la_fenetre_de_la_cle_suit_la_copie() {
        let d = dossier("essai-sa-fenetre-cle");
        let source = d.join("cle").join(NOM);
        let cible = d.join("bin").join(NOM);
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        let neuve = b"fenetre 0.96".to_vec();
        std::fs::write(&source, lancant(&neuve)).unwrap();
        std::fs::write(pour(&source).unwrap(), &neuve).unwrap();
        let fenetre = pour(&cible).unwrap();
        // Rien ici : le programme et sa fenêtre posés. Mais pas si le programme ne démarre pas.
        assert!(
            super::super::poser_copie_dans(
                &source,
                &cible,
                crate::programmes_poses::empreinte_de(&source).ok().as_deref(),
                &super::super::tests::inconnue(),
                super::super::tests::HORS_HISTORIQUE,
                ESSAI_RATE
            )
            .is_err()
        );
        assert!(std::fs::symlink_metadata(&fenetre).is_err());
        super::super::poser_copie_dans(
            &source,
            &cible,
            crate::programmes_poses::empreinte_de(&source).ok().as_deref(),
            &super::super::tests::inconnue(),
            super::super::tests::HORS_HISTORIQUE,
            SANS_ESSAI,
        )
        .unwrap();
        assert_eq!(std::fs::read(&fenetre).unwrap(), neuve);
        // La même copie, sa fenêtre effacée : remise.
        std::fs::remove_file(&fenetre).unwrap();
        super::super::poser_copie_dans(
            &source,
            &cible,
            crate::programmes_poses::empreinte_de(&source).ok().as_deref(),
            &super::super::tests::inconnue(),
            super::super::tests::HORS_HISTORIQUE,
            SANS_ESSAI,
        )
        .unwrap();
        assert_eq!(std::fs::read(&fenetre).unwrap(), neuve);
        // Une fenêtre changée sur la clé : la copie de même version garde la sienne, jamais celle de la clé.
        std::fs::write(pour(&source).unwrap(), b"fenetre plantee").unwrap();
        std::fs::remove_file(&fenetre).unwrap();
        super::super::poser_copie_dans(
            &source,
            &cible,
            crate::programmes_poses::empreinte_de(&source).ok().as_deref(),
            &super::super::tests::inconnue(),
            super::super::tests::HORS_HISTORIQUE,
            SANS_ESSAI,
        )
        .unwrap();
        assert!(std::fs::symlink_metadata(&fenetre).is_err());
        // Ni pour remplacer une copie plus ancienne : le programme est posé, sans elle.
        std::fs::write(
            &cible,
            [b"prog ".as_slice(), &super::super::entete(), b"0.95.0+1; "].concat(),
        )
        .unwrap();
        super::super::poser_copie_dans(
            &source,
            &cible,
            crate::programmes_poses::empreinte_de(&source).ok().as_deref(),
            &super::super::tests::inconnue(),
            super::super::tests::HORS_HISTORIQUE,
            SANS_ESSAI,
        )
        .unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), std::fs::read(&source).unwrap());
        assert!(std::fs::symlink_metadata(&fenetre).is_err());
        assert!(rien_a_cote(&d.join("bin")));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// La fenêtre non posée est dite. Sous Windows, un dossier à son nom ne bloque pas : `mettre_en_place_sous` le
    /// met de côté (`.ancien`, comme un programme en marche) et la fenêtre est posée ; elle doit alors l'être vraiment.
    fn dite_ou_posee_sous_windows(note: Option<String>, fenetre: &Path, neuve: &[u8]) -> bool {
        match note {
            Some(n) => n.contains("fenêtre") || n.contains("window"),
            None => cfg!(windows) && std::fs::read(fenetre).is_ok_and(|l| l == neuve),
        }
    }

    /// C-4 (relecture 0.96) : une chose impossible à remplacer au nom de la fenêtre (un dossier) bloquait la copie
    /// du PROGRAMME depuis la clé. Le programme est posé seul, et c'est dit ; la fenêtre d'avant reste, refusée par
    /// l'empreinte du nouveau programme (le menu).
    #[test]
    fn une_fenetre_impossible_a_poser_ne_bloque_pas_la_copie_de_la_cle() {
        let d = dossier("essai-sa-fenetre-cle-bloquee");
        let source = d.join("cle").join(NOM);
        let cible = d.join("bin").join(NOM);
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::create_dir_all(cible.parent().unwrap()).unwrap();
        let neuve = b"fenetre 0.96".to_vec();
        std::fs::write(&source, lancant(&neuve)).unwrap();
        std::fs::write(pour(&source).unwrap(), &neuve).unwrap();
        std::fs::write(
            &cible,
            [b"prog ".as_slice(), &super::super::entete(), b"0.95.0+1; "].concat(),
        )
        .unwrap();
        let fenetre = pour(&cible).unwrap();
        std::fs::create_dir(&fenetre).unwrap();
        let note = super::super::poser_copie_dans(
            &source,
            &cible,
            crate::programmes_poses::empreinte_de(&source).ok().as_deref(),
            &super::super::tests::inconnue(),
            super::super::tests::HORS_HISTORIQUE,
            SANS_ESSAI,
        )
        .unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), std::fs::read(&source).unwrap());
        assert!(dite_ou_posee_sous_windows(note, &fenetre, &neuve), "rien n'est dit");
        // Un programme qui ne démarre pas : rien n'est posé, la fenêtre non plus.
        std::fs::write(
            &cible,
            [b"prog ".as_slice(), &super::super::entete(), b"0.95.0+1; "].concat(),
        )
        .unwrap();
        assert!(
            super::super::poser_copie_dans(
                &source,
                &cible,
                crate::programmes_poses::empreinte_de(&source).ok().as_deref(),
                &super::super::tests::inconnue(),
                super::super::tests::HORS_HISTORIQUE,
                ESSAI_RATE
            )
            .is_err()
        );
        assert_ne!(std::fs::read(&cible).unwrap(), std::fs::read(&source).unwrap());
        assert!(rien_a_cote(&d.join("bin")));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// C-5 (relecture 0.96) : la copie de même version dont la fenêtre ne peut pas être posée (ici, un dossier à son
    /// nom) répondait « fait » sans un mot. La copie reste faite, mais la raison est rendue pour être dite.
    #[test]
    fn une_fenetre_impossible_a_poser_a_cote_de_la_meme_copie_est_dite() {
        let d = dossier("essai-sa-fenetre-cle-dite");
        let source = d.join("cle").join(NOM);
        let cible = d.join("bin").join(NOM);
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        let neuve = b"fenetre 0.96".to_vec();
        std::fs::write(&source, lancant(&neuve)).unwrap();
        std::fs::write(pour(&source).unwrap(), &neuve).unwrap();
        assert_eq!(
            super::super::poser_copie_dans(
                &source,
                &cible,
                crate::programmes_poses::empreinte_de(&source).ok().as_deref(),
                &super::super::tests::inconnue(),
                super::super::tests::HORS_HISTORIQUE,
                SANS_ESSAI
            )
            .unwrap(),
            None
        );
        let fenetre = pour(&cible).unwrap();
        std::fs::remove_file(&fenetre).unwrap();
        std::fs::create_dir(&fenetre).unwrap();
        let note = super::super::poser_copie_dans(
            &source,
            &cible,
            crate::programmes_poses::empreinte_de(&source).ok().as_deref(),
            &super::super::tests::inconnue(),
            super::super::tests::HORS_HISTORIQUE,
            SANS_ESSAI,
        )
        .unwrap();
        assert!(dite_ou_posee_sous_windows(note, &fenetre, &neuve), "rien n'est dit");
        assert_eq!(std::fs::read(&cible).unwrap(), std::fs::read(&source).unwrap());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// C-7-2 (relecture 0.96) : une fenêtre montrée illisible était comptée pareille à une illisible au moment de la
    /// pose, et remplacée. Non vérifié n'est jamais pareil : une vue illisible qui n'a pas été laissée (`trier` et
    /// `de_la_cle` la laissent toujours, ronde 3 ; ceci est la défense derrière) ne pose rien, ne télécharge rien, ni
    /// par GitHub ni par la clé.
    #[test]
    fn une_fenetre_montree_illisible_n_est_jamais_comptee_pareille() {
        let d = dossier("essai-sa-fenetre-illisible");
        let cible = d.join(NOM);
        std::fs::write(&cible, b"ancien programme").unwrap();
        let fenetre = pour(&cible).unwrap();
        std::fs::create_dir_all(&fenetre).unwrap();
        let vue = montree(&cible);
        assert_eq!(
            (vue.chemin(), &vue.etat),
            (Some(fenetre.as_path()), &Montree::Illisible)
        );
        assert!(
            vue.meme_etat(&fenetre, &Avant::de(&fenetre, TAILLE_MAX), b"nouveau")
                .is_err()
        );
        let neuve = b"fenetre 0.96".to_vec();
        let nouveau = lancant(&neuve);
        let appels = std::cell::Cell::new(0);
        let mut recevoir = || -> Result<Vec<u8>, Echec> {
            appels.set(appels.get() + 1);
            Ok(neuve.clone())
        };
        assert!(
            installer_avec_sa_fenetre(
                &nouveau,
                &cible,
                V,
                &crate::socle::dossier_local(),
                &crate::mise_a_jour::copie_de_cet_ordinateur(),
                SANS_ESSAI,
                &vue,
                &mut recevoir
            )
            .is_err()
        );
        assert_eq!(appels.get(), 0);
        assert!(
            installer_avec(
                &nouveau,
                &cible,
                V,
                &crate::socle::dossier_local(),
                &crate::mise_a_jour::copie_de_cet_ordinateur(),
                SANS_ESSAI,
                &neuve,
                &fenetre,
                &vue
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&cible).unwrap(), b"ancien programme");
        assert!(fenetre.is_dir());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// C-6 (0.97) : la fenêtre seule d'un programme d'ici qui est exactement celui signé ; proposée absente ou autre,
    /// jamais pour un programme d'ailleurs ; posée seulement si c'est celle qu'il grave, et seulement si ni elle ni le
    /// programme d'ici n'ont changé depuis l'aperçu.
    #[test]
    fn une_fenetre_seule_ne_se_pose_que_telle_que_montree() {
        let d = dossier("essai-sa-fenetre-seule");
        let cible = d.join(NOM);
        let fenetre = pour(&cible).unwrap();
        let neuve = b"fenetre 0.96".to_vec();
        let ici = lancant(&neuve);
        std::fs::write(&cible, &ici).unwrap();
        let publiee = super::super::github::Publiee::d_essai(V, &ici);
        // Un programme d'ailleurs au même numéro : rien.
        let ailleurs = super::super::github::Publiee::d_essai(V, &lancant(b"fenetre d'ailleurs"));
        assert!(seule_a_poser(&cible, &ailleurs).is_none());
        let s = seule_a_poser(&cible, &publiee).unwrap().unwrap();
        assert!(s.ajout());
        assert_eq!(s.chemin(), fenetre.as_path());
        // Une autre que celle gravée, ou aucune reçue : rien.
        assert!(s.poser(&mut || Ok(b"fenetre plantee".to_vec())).is_err());
        assert!(
            s.poser(&mut || Err(Echec::echoue("essai", "téléchargement interrompu")))
                .is_err()
        );
        assert!(std::fs::symlink_metadata(&fenetre).is_err());
        // Le programme d'ici changé pendant le téléchargement : rien.
        let mut change = || -> Result<Vec<u8>, Echec> {
            std::fs::write(&cible, b"autre programme").unwrap();
            Ok(neuve.clone())
        };
        assert!(s.poser(&mut change).is_err());
        assert!(std::fs::symlink_metadata(&fenetre).is_err());
        std::fs::write(&cible, &ici).unwrap();
        // Une fenêtre apparue pendant le téléchargement : elle reste.
        let mut apparait = || -> Result<Vec<u8>, Echec> {
            std::fs::write(&fenetre, b"fenetre apparue").unwrap();
            Ok(neuve.clone())
        };
        assert!(s.poser(&mut apparait).is_err());
        assert_eq!(std::fs::read(&fenetre).unwrap(), b"fenetre apparue");
        // Montrée autre : réparée, relue juste ; juste, plus rien à proposer.
        let s = seule_a_poser(&cible, &publiee).unwrap().unwrap();
        assert!(!s.ajout());
        s.poser(&mut || Ok(neuve.clone())).unwrap();
        s.posee_juste().unwrap();
        assert_eq!(std::fs::read(&fenetre).unwrap(), neuve);
        assert_eq!(std::fs::read(&cible).unwrap(), ici);
        assert!(rien_a_cote(&d));
        assert!(seule_a_poser(&cible, &publiee).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Pose d'un programme avec sa fenêtre, comme le terminal et l'interface la font : `vue` montrée avant.
    fn poser_avec_vue(nouveau: &[u8], cible: &Path, vue: &Vue, fenetre: &[u8], essai: Essai) -> Result<(), Echec> {
        installer_avec_sa_fenetre(
            nouveau,
            cible,
            V,
            &crate::socle::dossier_local(),
            &crate::mise_a_jour::copie_de_cet_ordinateur(),
            essai,
            vue,
            &mut || Ok(fenetre.to_vec()),
        )
    }

    /// ACCORD-1, POSE-1 (relecture C-6/C-7) : deux programmes du même dossier partagent le chemin de leur fenêtre ;
    /// le second était refusé (« la fenêtre a changé depuis ce qui a été montré ») à cause de celle que la mise à
    /// jour venait de poser. Montrée une fois (`trier`), posée une fois, les deux programmes remplacés : le chemin du
    /// terminal (et de l'interface, `apercu`).
    #[test]
    fn deux_programmes_du_meme_dossier_posent_leur_fenetre_une_fois() {
        let d = dossier("essai-sa-fenetre-partagee");
        let (a, b) = (d.join(NOM), d.join("vanguard-autre"));
        let fenetre = pour(&a).unwrap();
        assert_eq!(pour(&b).as_deref(), Some(fenetre.as_path()));
        let neuve = b"fenetre 0.96".to_vec();
        let nouveau = lancant(&neuve);
        for ici in [None, Some(b"ancienne fenetre".as_slice())] {
            for c in [&a, &b] {
                std::fs::write(c, b"ancien programme").unwrap();
            }
            let _ = std::fs::remove_file(&fenetre);
            if let Some(o) = ici {
                std::fs::write(&fenetre, o).unwrap();
            }
            let gardees = trier(vec![a.clone(), b.clone()]);
            assert_eq!(gardees.len(), 2);
            assert_eq!(gardees[0].1.ligne(), Some(fenetre.as_path()));
            assert_eq!(gardees[1].1.ligne(), None, "une seule ligne pour la fenêtre partagée");
            for (c, vue) in &gardees {
                poser_avec_vue(&nouveau, c, vue, &neuve, SANS_ESSAI).unwrap();
            }
            assert_eq!(std::fs::read(&a).unwrap(), nouveau);
            assert_eq!(std::fs::read(&b).unwrap(), nouveau);
            assert_eq!(std::fs::read(&fenetre).unwrap(), neuve);
            assert!(rien_a_cote(&d));
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A-ACCORD-1, A-REFUS-1 (campagne d'attaque C-6/C-7) : un dossier posé au nom de la fenêtre laissait de côté
    /// son programme, gelé à l'ancienne version (une seule copie : plus aucune mise à jour). La fenêtre illisible ne
    /// bloque plus le programme : posé seul, rien téléchargé pour elle, elle non touchée, et c'est dit (« programme
    /// seul », puis pourquoi) ; l'autre copie suit avec sa fenêtre.
    #[test]
    fn une_fenetre_illisible_laisse_poser_son_programme_seul() {
        let d = dossier("essai-sa-fenetre-laissee");
        let (a, b) = (d.join("a").join(NOM), d.join("b").join(NOM));
        for c in [&a, &b] {
            std::fs::create_dir_all(c.parent().unwrap()).unwrap();
            std::fs::write(c, b"ancien programme").unwrap();
        }
        let illisible = pour(&a).unwrap();
        std::fs::create_dir_all(illisible.join("dedans")).unwrap();
        let gardees = trier(vec![a.clone(), b.clone()]);
        assert_eq!(gardees.iter().map(|(c, _)| c).collect::<Vec<_>>(), [&a, &b]);
        let (va, vb) = (&gardees[0].1, &gardees[1].1);
        assert_eq!((va.laissee(), vb.laissee()), (Some(Laissee::Illisible), None));
        assert_eq!(va.ligne(), Some(illisible.as_path()));
        assert!(va.dite_a_cote().contains("programme seul"), "{}", va.dite_a_cote());
        assert!(va.laissee_dite().unwrap().contains("posé seul"));
        let neuve = b"fenetre 0.96".to_vec();
        let nouveau = lancant(&neuve);
        let appels = std::cell::Cell::new(0);
        let mut recevoir = || -> Result<Vec<u8>, Echec> {
            appels.set(appels.get() + 1);
            Ok(neuve.clone())
        };
        installer_avec_sa_fenetre(
            &nouveau,
            &a,
            V,
            &crate::socle::dossier_local(),
            &crate::mise_a_jour::copie_de_cet_ordinateur(),
            SANS_ESSAI,
            va,
            &mut recevoir,
        )
        .unwrap();
        assert_eq!(appels.get(), 0, "rien n'est téléchargé pour une fenêtre laissée");
        assert_eq!(std::fs::read(&a).unwrap(), nouveau);
        assert!(illisible.join("dedans").is_dir(), "le dossier n'est pas touché");
        poser_avec_vue(&nouveau, &b, vb, &neuve, SANS_ESSAI).unwrap();
        assert_eq!(std::fs::read(pour(&b).unwrap()).unwrap(), neuve);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A-ACCORD-4 (campagne d'attaque C-6/C-7) : ce qui a été montré est ce qui se fait. Montrée illisible
    /// (« programme seul ») puis redevenue lisible avant le clic, ou l'inverse : rien n'est posé, ni le programme ni
    /// la fenêtre.
    #[test]
    fn une_fenetre_laissee_puis_changee_ne_fait_rien_poser() {
        let d = dossier("essai-sa-fenetre-laissee-changee");
        let cible = d.join(NOM);
        let fenetre = pour(&cible).unwrap();
        let neuve = b"fenetre 0.96".to_vec();
        let nouveau = lancant(&neuve);
        for illisible_d_abord in [true, false] {
            std::fs::write(&cible, b"ancien programme").unwrap();
            let _ = std::fs::remove_dir_all(&fenetre);
            let _ = std::fs::remove_file(&fenetre);
            let poser_l_autre = |lisible: bool| {
                if lisible {
                    std::fs::write(&fenetre, b"ancienne fenetre").unwrap();
                } else {
                    std::fs::create_dir_all(&fenetre).unwrap();
                }
            };
            poser_l_autre(!illisible_d_abord);
            let vue = trier(vec![cible.clone()]).remove(0).1;
            assert_eq!(vue.laissee().is_some(), illisible_d_abord);
            let _ = std::fs::remove_dir_all(&fenetre);
            let _ = std::fs::remove_file(&fenetre);
            poser_l_autre(illisible_d_abord);
            let e = poser_avec_vue(&nouveau, &cible, &vue, &neuve, SANS_ESSAI).unwrap_err();
            assert!(e.to_string().contains("depuis ce qui a été montré"), "{e}");
            assert_eq!(
                std::fs::read(&cible).unwrap(),
                b"ancien programme",
                "{illisible_d_abord}"
            );
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// ACCORD-2, POSE-3, ILLISIBLE-3 (relecture C-6/C-7) : une fenêtre au bon contenu mais que le lancement refuse (un
    /// lien, des droits trop larges) était comptée juste, jamais proposée. Elle est proposée, « réparée », et remplacée
    /// par un fichier que le lancement accepte ; ce que désignait le lien n'est pas touché.
    #[cfg(unix)]
    #[test]
    fn un_lien_ou_une_fenetre_refusee_n_est_jamais_juste() {
        use std::os::unix::fs::PermissionsExt;
        let d = dossier("essai-sa-fenetre-lien-refusee");
        let cible = d.join(NOM);
        let fenetre = pour(&cible).unwrap();
        let neuve = b"fenetre 0.96".to_vec();
        let ici = lancant(&neuve);
        std::fs::write(&cible, &ici).unwrap();
        let publiee = super::super::github::Publiee::d_essai(V, &ici);
        let ailleurs = d.join("ailleurs");
        std::fs::write(&ailleurs, &neuve).unwrap();
        // Un lien vers la bonne fenêtre.
        std::os::unix::fs::symlink(&ailleurs, &fenetre).unwrap();
        let s = seule_a_poser(&cible, &publiee).unwrap().unwrap();
        assert!(s.dite().contains("un lien"), "{}", s.dite());
        s.poser(&mut || Ok(neuve.clone())).unwrap();
        assert!(std::fs::symlink_metadata(&fenetre).unwrap().file_type().is_file());
        assert_eq!(std::fs::read(&fenetre).unwrap(), neuve);
        assert_eq!(std::fs::read(&ailleurs).unwrap(), neuve);
        assert!(seule_a_poser(&cible, &publiee).is_none(), "juste maintenant");
        // La bonne fenêtre, que d'autres comptes peuvent écrire.
        std::fs::set_permissions(&fenetre, std::fs::Permissions::from_mode(0o775)).unwrap();
        let s = seule_a_poser(&cible, &publiee).unwrap().unwrap();
        assert!(s.dite().contains("refusée au lancement"), "{}", s.dite());
        s.poser(&mut || Ok(neuve.clone())).unwrap();
        assert_eq!(std::fs::metadata(&fenetre).unwrap().permissions().mode() & 0o022, 0);
        assert!(seule_a_poser(&cible, &publiee).is_none());
        assert!(rien_a_cote(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// ILLISIBLE-4, POSE-4 (relecture C-6/C-7) : un lien à la place de la fenêtre était lu (un fichier hors du
    /// dossier), et après un échec du programme son contenu revenait en fichier 0755 à côté de lui. Le lien n'est
    /// jamais suivi (ici, il désigne un fichier que ce compte ne peut pas lire), et il revient en lien.
    #[cfg(unix)]
    #[test]
    fn un_lien_a_la_place_de_la_fenetre_n_est_jamais_lu_et_revient_en_lien() {
        use std::os::unix::fs::PermissionsExt;
        if crate::socle::uid() == 0 {
            return crate::essais::saute("root lit un fichier sans droits");
        }
        let d = dossier("essai-sa-fenetre-lien-prive");
        let cible = d.join(NOM);
        let fenetre = pour(&cible).unwrap();
        let prive = d.join("prive");
        std::fs::write(&prive, b"secret invente").unwrap();
        std::fs::set_permissions(&prive, std::fs::Permissions::from_mode(0o000)).unwrap();
        std::fs::write(&cible, b"ancien programme").unwrap();
        std::os::unix::fs::symlink(&prive, &fenetre).unwrap();
        let vue = montree(&cible);
        assert_ne!(vue.etat, Montree::Illisible, "un lien se montre sans être suivi");
        assert!(vue.dite_a_cote().contains("un lien"), "{}", vue.dite_a_cote());
        let neuve = b"fenetre 0.96".to_vec();
        let e = poser_avec_vue(&lancant(&neuve), &cible, &vue, &neuve, ESSAI_RATE).unwrap_err();
        assert_eq!(std::fs::read_link(&fenetre).unwrap(), prive, "{e}");
        assert_eq!(std::fs::read(&cible).unwrap(), b"ancien programme");
        std::fs::set_permissions(&prive, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(std::fs::read(&prive).unwrap(), b"secret invente");
        assert!(rien_a_cote(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// POSE-4 (relecture C-6/C-7) : le retour d'une fenêtre qui était absente effaçait sans relire. Seule la fenêtre
    /// que cette mise à jour a posée est retirée, jamais un fichier mis là depuis par un autre programme.
    #[test]
    fn le_retour_d_une_fenetre_absente_n_efface_pas_un_fichier_etranger() {
        let d = dossier("essai-sa-fenetre-retour-absente");
        let chemin = d.join("vanguard-fenetre");
        std::fs::write(&chemin, b"etranger").unwrap();
        assert!(matches!(remettre(&Avant::Absente, &chemin, b"posee"), Remise::Pas(_)));
        assert_eq!(std::fs::read(&chemin).unwrap(), b"etranger");
        std::fs::write(&chemin, b"posee").unwrap();
        assert_eq!(remettre(&Avant::Absente, &chemin, b"posee"), Remise::Faite);
        assert!(std::fs::symlink_metadata(&chemin).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// POSE-2 (relecture C-6/C-7) : une fenêtre seule posée puis fausse à la relecture restait en place, alors que le
    /// texte disait « rien n'est changé ». Ce qui était là revient : l'ancienne, ou rien.
    #[test]
    fn une_fenetre_posee_mais_fausse_a_la_relecture_est_remise() {
        let d = dossier("essai-sa-fenetre-relue-fausse");
        let chemin = d.join("vanguard-fenetre");
        let fausse = |_: &Path| Err(Echec::refuse("essai", "relue fausse"));
        std::fs::write(&chemin, b"ancienne fenetre").unwrap();
        let avant = Avant::de(&chemin, TAILLE_MAX);
        assert!(poser_puis_relire(b"neuve", &chemin, &avant, fausse).is_err());
        assert_eq!(std::fs::read(&chemin).unwrap(), b"ancienne fenetre");
        std::fs::remove_file(&chemin).unwrap();
        assert!(poser_puis_relire(b"neuve", &chemin, &Avant::Absente, fausse).is_err());
        assert!(std::fs::symlink_metadata(&chemin).is_err());
        assert!(rien_a_cote(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// POSE-5 (relecture C-6/C-7) : deux mises à jour en même temps partageaient le même nom provisoire et se
    /// l'effaçaient. Chaque pose a le sien, créé neuf ; un fichier qu'elle n'a pas créé n'est jamais effacé.
    #[test]
    fn un_nom_provisoire_d_un_autre_n_est_jamais_efface() {
        let d = dossier("essai-sa-fenetre-provisoire");
        let chemin = d.join("vanguard-fenetre");
        let autre = d.join("vanguard-fenetre.nouveau");
        std::fs::write(&autre, b"pose d'une autre mise a jour").unwrap();
        poser(b"neuve", &chemin).unwrap();
        assert_eq!(std::fs::read(&chemin).unwrap(), b"neuve");
        assert_eq!(std::fs::read(&autre).unwrap(), b"pose d'une autre mise a jour");
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 2, "rien d'autre à côté");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// ILLISIBLE-5 (relecture C-6/C-7) : toute erreur de lecture comptait « absente ». Seul « introuvable » l'est ;
    /// un dossier fermé (droits) est illisible : jamais rien d'ajouté par-dessus ce qu'on n'a pas vu.
    #[cfg(unix)]
    #[test]
    fn seule_l_absence_vraie_compte_absente() {
        use std::os::unix::fs::PermissionsExt;
        if crate::socle::uid() == 0 {
            return crate::essais::saute("root traverse un dossier sans droits");
        }
        let d = dossier("essai-sa-fenetre-absente-vraie");
        assert_eq!(Avant::de(&d.join("vanguard-fenetre"), TAILLE_MAX), Avant::Absente);
        let ferme = d.join("ferme");
        std::fs::create_dir_all(&ferme).unwrap();
        std::fs::set_permissions(&ferme, std::fs::Permissions::from_mode(0o000)).unwrap();
        let lu = Avant::de(&ferme.join("vanguard-fenetre"), TAILLE_MAX);
        std::fs::set_permissions(&ferme, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(lu, Avant::Illisible);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A-ORIGINE-1, A-ORIGINE-3 (campagne d'attaque C-6/C-7) : une copie qui est un lien recevait sa fenêtre à côté
    /// du fichier désigné, un chemin que le lien choisit (d'un autre dossier, d'un autre compte pour root). Pour les
    /// deux systèmes, sa fenêtre est laissée : rien n'est posé ni à côté du lien ni à côté de sa cible, c'est dit sur
    /// sa ligne ; remplacée, la copie est posée seule (« programme seul »).
    #[cfg(unix)]
    #[test]
    fn une_copie_en_lien_laisse_sa_fenetre() {
        let d = dossier("essai-sa-fenetre-copie-en-lien");
        let vrai = d.join("vrai").join(NOM);
        let lien = d.join("lien").join(NOM);
        for c in [&vrai, &lien] {
            std::fs::create_dir_all(c.parent().unwrap()).unwrap();
        }
        let neuve = b"fenetre 0.96".to_vec();
        let ici = lancant(&neuve);
        std::fs::write(&vrai, &ici).unwrap();
        std::os::unix::fs::symlink(&vrai, &lien).unwrap();
        let publiee = super::super::github::Publiee::d_essai(V, &ici);
        let rien_pose = || {
            for c in [&lien, &vrai] {
                assert!(
                    std::fs::symlink_metadata(pour(c).unwrap()).is_err(),
                    "rien à côté de {c:?}"
                );
            }
        };
        let Some(Err(e)) = seule_a_poser(&lien, &publiee) else {
            panic!("la fenêtre seule d'une copie en lien n'est pas laissée");
        };
        assert_eq!((&e.programme, e.pourquoi), (&lien, Pourquoi::Lien));
        assert!(e.dite("L", "F").contains("L est un lien"), "{}", e.dite("L", "F"));
        rien_pose();
        // À remplacer : la copie seule, montrée comme telle.
        std::fs::write(&vrai, b"ancien programme").unwrap();
        let vue = trier(vec![lien.clone()]).remove(0).1;
        assert_eq!(vue.laissee(), Some(Laissee::CopieEnLien));
        assert!(
            vue.dite_a_cote().contains("la copie est un lien"),
            "{}",
            vue.dite_a_cote()
        );
        poser_avec_vue(&ici, &lien, &vue, &neuve, SANS_ESSAI).unwrap();
        assert_eq!(std::fs::read(&lien).unwrap(), ici);
        rien_pose();
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A-ORIGINE-3 (campagne d'attaque C-6/C-7) : une copie devenue un lien entre l'aperçu et la pose était suivie au
    /// moment de poser. Revérifiée à la pose : rien n'est posé, ni la fenêtre seule ni le programme avec elle.
    #[cfg(unix)]
    #[test]
    fn une_copie_devenue_un_lien_ne_fait_rien_poser() {
        let d = dossier("essai-sa-fenetre-devenue-lien");
        let (cible, ailleurs) = (d.join("ici").join(NOM), d.join("ailleurs").join(NOM));
        for c in [&cible, &ailleurs] {
            std::fs::create_dir_all(c.parent().unwrap()).unwrap();
        }
        let neuve = b"fenetre 0.96".to_vec();
        let ici = lancant(&neuve);
        // La fenêtre seule (programme d'ici exactement celui signé), puis la fenêtre avec le programme.
        std::fs::write(&cible, &ici).unwrap();
        let s = seule_a_poser(&cible, &super::super::github::Publiee::d_essai(V, &ici))
            .unwrap()
            .unwrap();
        std::fs::write(&cible, b"ancien programme").unwrap();
        let vue = trier(vec![cible.clone()]).remove(0).1;
        assert_eq!(vue.laissee(), None);
        std::fs::write(&ailleurs, &ici).unwrap();
        std::fs::remove_file(&cible).unwrap();
        std::os::unix::fs::symlink(&ailleurs, &cible).unwrap();
        let e = s.poser(&mut || Ok(neuve.clone())).unwrap_err();
        assert!(e.to_string().contains("devenue un lien"), "{e}");
        let e = poser_avec_vue(&lancant(&neuve), &cible, &vue, &neuve, SANS_ESSAI).unwrap_err();
        assert!(e.to_string().contains("devenue un lien"), "{e}");
        for c in [&cible, &ailleurs] {
            assert!(
                std::fs::symlink_metadata(pour(c).unwrap()).is_err(),
                "rien à côté de {c:?}"
            );
        }
        assert_eq!(std::fs::read(&ailleurs).unwrap(), ici);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A-ACCORD-2, A-ORIGINE-2, A-REFUS-3 (campagne d'attaque C-6/C-7) : la fenêtre juste dans un dossier que le
    /// lancement refuse (modifiable par d'autres comptes) était dite « posée, vérifiée » ou « à jour ». Jugée comme le
    /// lancement, dossiers compris : jamais dite juste, la fenêtre seule n'est pas reposée (cela ne réparerait rien),
    /// le refus est dit avec ce qu'il faut corriger.
    #[cfg(unix)]
    #[test]
    fn un_dossier_que_le_lancement_refuse_est_dit_jamais_repare() {
        use std::os::unix::fs::PermissionsExt;
        let d = dossier("essai-sa-fenetre-dossier-refuse");
        let ouvert = d.join("ouvert");
        std::fs::create_dir_all(&ouvert).unwrap();
        let cible = ouvert.join(NOM);
        let fenetre = pour(&cible).unwrap();
        let neuve = b"fenetre 0.96".to_vec();
        let ici = lancant(&neuve);
        std::fs::write(&cible, &ici).unwrap();
        std::fs::write(&fenetre, &neuve).unwrap();
        let publiee = super::super::github::Publiee::d_essai(V, &ici);
        // Le dossier fermé aux autres : juste, rien à faire.
        assert!(posee_juste(&ici, &fenetre).is_ok());
        assert!(seule_a_poser(&cible, &publiee).is_none());
        std::fs::set_permissions(&ouvert, std::fs::Permissions::from_mode(0o777)).unwrap();
        let e = posee_juste(&ici, &fenetre).unwrap_err().to_string();
        assert!(
            e.contains("le lancement la refusera") && e.contains("chmod go-w"),
            "{e}"
        );
        let Some(Err(ecartee)) = seule_a_poser(&cible, &publiee) else {
            panic!("la fenêtre seule est reproposée dans un dossier refusé");
        };
        let dite = ecartee.dite("P", "F");
        assert!(
            dite.contains("la reposer ne réparerait rien") && dite.contains("modifiable par d'autres"),
            "{dite}"
        );
        assert!(ecartee.ligne_fenetre().contains("ne réparerait rien"));
        let vue = montree(&cible);
        assert!(
            vue.dite_a_cote().contains("son dossier est refusé"),
            "{}",
            vue.dite_a_cote()
        );
        assert_eq!(std::fs::read(&fenetre).unwrap(), neuve, "rien n'est touché");
        std::fs::set_permissions(&ouvert, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A-POSE-3 (campagne d'attaque C-6/C-7) : le nom provisoire se devinait (numéro du processus et compteur). Tiré
    /// au hasard, créé neuf (O_EXCL) : un fichier déjà à ce nom n'est ni repris ni écrasé, un autre nom est tiré.
    #[test]
    fn un_nom_provisoire_deja_pris_n_est_jamais_repris() {
        let d = dossier("essai-sa-fenetre-nom-pris");
        let fenetre = d.join("vanguard-fenetre");
        let pris = d.join(format!("vanguard-fenetre.nouveau-{}", "a".repeat(32)));
        std::fs::write(&pris, b"pas a nous").unwrap();
        let mut noms = ["a", "b"].into_iter();
        let (p, _) = nom_libre_tire(
            &fenetre,
            |nom, sorte| Ok(format!("{nom}.{sorte}-{}", noms.next().unwrap().repeat(32))),
            creer_neuf,
        )
        .unwrap();
        assert_eq!(p, d.join(format!("vanguard-fenetre.nouveau-{}", "b".repeat(32))));
        assert_eq!(std::fs::read(&pris).unwrap(), b"pas a nous");
        // Le hasard : deux noms tirés ne se suivent pas, et ce sont des restes reconnus.
        let (a, b) = (
            nom_au_hasard("vanguard-fenetre", "nouveau").unwrap(),
            nom_au_hasard("vanguard-fenetre", "nouveau").unwrap(),
        );
        assert_ne!(a, b);
        assert!(reste_de_pose("vanguard-fenetre", "nouveau", &a), "{a}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A-POSE-2 (campagne d'attaque C-6/C-7) : le ménage ne retire que les restes d'une pose (`<fenêtre>.ancien` ou
    /// `<fenêtre>.ancien-<32 hexadécimaux>`), des fichiers ordinaires ; rien d'autre du dossier, aucun dossier.
    #[test]
    fn le_menage_ne_retire_que_les_restes_d_une_pose() {
        let d = dossier("essai-sa-fenetre-menage");
        let cible = d.join(NOM);
        let nom = pour(&cible)
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let hex = "0123456789abcdef".repeat(2);
        let restes = [format!("{nom}.ancien"), format!("{nom}.ancien-{hex}")];
        let gardes = [
            format!("{nom}.ancien-{}", &hex[..31]),
            format!("{nom}.ancien-{hex}0"),
            format!("{nom}.ancien-{}", "z".repeat(32)),
            format!("{nom}.nouveau-{hex}"),
            format!("autre.ancien-{hex}"),
            nom.clone(),
        ];
        for n in restes.iter().chain(&gardes) {
            std::fs::write(d.join(n), b"x").unwrap();
        }
        let dossier_au_nom = d.join(format!("{nom}.ancien-{}", "f".repeat(32)));
        std::fs::create_dir_all(dossier_au_nom.join("dedans")).unwrap();
        effacer_l_ancienne(&cible);
        for n in &restes {
            assert!(!d.join(n).exists(), "{n} reste");
        }
        for n in &gardes {
            assert!(d.join(n).exists(), "{n} retiré");
        }
        assert!(dossier_au_nom.join("dedans").is_dir());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A-POSE-1 (campagne d'attaque C-6/C-7) : après un échec du programme, l'ancienne fenêtre revenait en 0755, et
    /// c'était dit « remise ». Elle revient avec ses droits (sans écriture des autres, sans bit spécial) ; ce qui ne
    /// peut pas revenir tel quel (un bit spécial, un autre propriétaire) est dit.
    #[cfg(unix)]
    #[test]
    fn l_ancienne_fenetre_revient_avec_ses_droits_ou_c_est_dit() {
        use std::os::unix::fs::PermissionsExt;
        let d = dossier("essai-sa-fenetre-remise-droits");
        let cible = d.join(NOM);
        let fenetre = pour(&cible).unwrap();
        let neuve = b"fenetre 0.96".to_vec();
        for (mode, dit) in [(0o700, false), (0o4700, true)] {
            std::fs::write(&cible, b"ancien programme").unwrap();
            let _ = std::fs::remove_file(&fenetre);
            std::fs::write(&fenetre, b"ancienne fenetre").unwrap();
            std::fs::set_permissions(&fenetre, std::fs::Permissions::from_mode(mode)).unwrap();
            let vue = montree(&cible);
            let e = poser_avec_vue(&lancant(&neuve), &cible, &vue, &neuve, ESSAI_RATE)
                .unwrap_err()
                .to_string();
            assert_eq!(std::fs::read(&fenetre).unwrap(), b"ancienne fenetre");
            let remis = std::fs::symlink_metadata(&fenetre).unwrap().permissions().mode() & 0o7777;
            assert_eq!(remis, 0o700, "{mode:o} : {e}");
            assert_eq!(e.contains("pas avec ses droits"), dit, "{mode:o} : {e}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A-POSE-4 (campagne d'attaque C-6/C-7) : une pose qui échoue avant le renommage disait « l'ancienne fenêtre
    /// n'est pas remise », alors qu'elle n'avait pas bougé. Rien n'a bougé, rien n'est dit remis ni pas remis.
    #[cfg(unix)]
    #[test]
    fn rien_n_est_dit_remis_quand_rien_n_a_bouge() {
        use std::os::unix::fs::PermissionsExt;
        if crate::socle::euid() == 0 {
            return crate::essais::saute("root écrit dans un dossier sans droit d'écriture");
        }
        let d = dossier("essai-sa-fenetre-rien-bouge");
        let ferme = d.join("ferme");
        std::fs::create_dir_all(&ferme).unwrap();
        let fenetre = ferme.join("vanguard-fenetre");
        std::fs::write(&fenetre, b"ancienne fenetre").unwrap();
        let avant = Avant::de(&fenetre, TAILLE_MAX);
        std::fs::set_permissions(&ferme, std::fs::Permissions::from_mode(0o555)).unwrap();
        let e = poser_puis_relire(b"fenetre 0.96", &fenetre, &avant, |_| Ok(()))
            .unwrap_err()
            .to_string();
        std::fs::set_permissions(&ferme, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!e.contains("remise"), "{e}");
        assert_eq!(std::fs::read(&fenetre).unwrap(), b"ancienne fenetre");
        // A-POSE-4 : ce qui était là ne se lisait pas (un dossier à son nom) et la pose échoue avant le renommage :
        // rien n'a bougé, la phrase ne dit pas « n'est pas remise » (qui laisserait croire qu'elle a disparu).
        let illisible = d.join("illisible");
        let fenetre = illisible.join("vanguard-fenetre");
        std::fs::create_dir_all(fenetre.join("dedans")).unwrap();
        let avant = Avant::de(&fenetre, TAILLE_MAX);
        assert_eq!(avant, Avant::Illisible);
        std::fs::set_permissions(&illisible, std::fs::Permissions::from_mode(0o555)).unwrap();
        let e = poser_puis_relire(b"fenetre 0.96", &fenetre, &avant, |_| Ok(()))
            .unwrap_err()
            .to_string();
        std::fs::set_permissions(&illisible, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!e.contains("remise") && !e.contains("put back"), "{e}");
        assert!(fenetre.join("dedans").is_dir());
        let _ = std::fs::remove_dir_all(&d);
    }
}

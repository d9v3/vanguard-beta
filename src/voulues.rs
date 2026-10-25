//! Les défenses que la personne a voulues (surveillance horaire, veilleur, veille anti-rançongiciel) : leur mise en
//! marche et leur arrêt par Vanguard, notés dans un état scellé (`sceau`) et au journal des événements.
//!
//! Pourquoi : la marque d'avant (`surveillance-voulue`, `veilleur-voulu`, `rancongiciel-voulu`) n'est qu'un fichier
//! vide du dossier du compte. Un programme du compte l'effaçait avec la minuterie, la tâche ou l'unité : la défense
//! était coupée et le bilan la disait « coupée, comme par défaut », en vert. Ici, une défense voulue un jour reste
//! voulue tant que Vanguard n'a pas noté son arrêt ; marque et tâche disparues sans cet arrêt, le bilan dit qu'elle a
//! été coupée sans passer par Vanguard. La marque reste (la désinstallation et les versions d'avant la lisent) : c'est
//! un indice de plus, jamais ce qui décide qu'une défense est coupée.
//!
//! Un état changé hors de Vanguard, accepté tel quel après des sceaux refaits, ou disparu avec eux, ne vaut jamais un
//! feu vert : un indice (la marque, la tâche en place) fait supposer la défense voulue, sinon le bilan dit qu'il ne
//! peut pas le vérifier. Réécrit ensuite par Vanguard pour une défense, il garde le doute sur les autres.
//!
//! Comme tout sceau : barrière, pas coffre. Un programme qui connaît ce mécanisme peut refaire le sceau.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::sceau::Lecture;
use crate::{tr, trf};

/// L'état scellé des défenses voulues, dans le dossier de données.
pub(crate) const FICHIER: &str = "defenses-voulues.json";

/// Une défense que la personne allume elle-même, et dont la disparition doit se voir.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Defense {
    Surveillance,
    Veilleur,
    Rancongiciel,
}

const TOUTES: [Defense; 3] = [Defense::Surveillance, Defense::Veilleur, Defense::Rancongiciel];

impl Defense {
    /// Son nom dans l'état et au journal : stable, jamais traduit.
    fn cle(self) -> &'static str {
        match self {
            Defense::Surveillance => "surveillance",
            Defense::Veilleur => "veilleur",
            Defense::Rancongiciel => "rancongiciel",
        }
    }

    fn nom(self) -> &'static str {
        match self {
            Defense::Surveillance => tr!("Surveillance horaire", "Hourly monitoring"),
            Defense::Veilleur => tr!("Veilleur", "Watcher"),
            Defense::Rancongiciel => tr!("Veille anti-rançongiciel", "Ransomware watch"),
        }
    }
}

/// Ce que Vanguard a noté d'une défense.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct Note {
    voulue: bool,
    /// Le jour du dernier changement noté (AAAA-MM-JJ).
    quand: String,
    /// Héritée d'un état qui ne pouvait pas être cru, quand Vanguard l'a réécrit pour une autre défense : on ne sait
    /// pas ce qu'elle était, jusqu'à ce que Vanguard la note de nouveau.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    douteuse: bool,
}

#[derive(Serialize, Deserialize, Default)]
struct Fichier {
    #[serde(default)]
    defenses: BTreeMap<String, Note>,
}

/// Pourquoi l'état des défenses voulues ne peut pas être cru.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Doute {
    /// Changé ou effacé hors de Vanguard : une écriture étrangère prouvée.
    HorsVanguard,
    Adopte,
    Inconnu,
    Illisible,
    /// Hérité d'un état qui ne pouvait pas être cru, quand Vanguard l'a réécrit pour une autre défense.
    Herite,
}

impl Doute {
    /// La fin d'une phrase dont le sujet est une note de Vanguard au féminin (« la note de Vanguard sur vos
    /// défenses », « la liste des programmes posés par Vanguard »), dite pour quelqu'un qui ne connaît pas les sceaux.
    pub(crate) fn texte(self) -> &'static str {
        match self {
            Doute::HorsVanguard => tr!(
                "a été modifiée ou effacée hors de Vanguard",
                "was changed or deleted outside Vanguard"
            ),
            Doute::Adopte | Doute::Inconnu => tr!(
                "a été perdue : les sceaux de Vanguard (sceaux.json) ont été effacés ou abîmés",
                "was lost: Vanguard's seals (sceaux.json) were deleted or damaged"
            ),
            Doute::Illisible => tr!("ne se lit pas", "cannot be read"),
            Doute::Herite => tr!(
                "n'a pas pu être relue après une modification hors de Vanguard",
                "could not be read back after a change outside Vanguard"
            ),
        }
    }
}

/// Ce que l'état scellé dit d'une défense.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Souvenir {
    /// Jamais notée : jamais allumée par une version qui note.
    Jamais,
    /// Allumée par Vanguard, ce jour-là, et jamais arrêtée par lui depuis.
    Voulue(String),
    /// Arrêtée par Vanguard, ce jour-là.
    Arretee(String),
    /// L'état ne peut pas être cru.
    Douteux(Doute),
}

/// Le jugement d'une défense d'après la marque, la tâche (ou l'unité) en place et l'état scellé.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Jamais voulue, ou arrêtée par Vanguard (le jour, s'il est connu) : coupée normalement.
    PasVoulue(Option<String>),
    /// Voulue : la marque ou la tâche le disent (à l'appelant de juger si elle tourne).
    Voulue,
    /// Marque et tâche disparues alors que Vanguard l'a notée voulue le jour dit, sans arrêt noté depuis ; ou (`None`)
    /// avec la note de Vanguard modifiée ou effacée hors de Vanguard, ce qui n'arrive qu'à qui veut faire oublier.
    CoupeeHors(Option<String>),
    /// Ni marque ni tâche, et l'état ne peut pas être cru : rien ne dit qui l'a coupée.
    NonVerifiee(Doute),
}

/// Le jugement, sans rien lire : `marque` et `installee` sont des indices (posés par Vanguard, ou forgés pour faire
/// croire une défense en place, ce qui ne coupe rien), l'état scellé décide seul qu'une défense est coupée normalement.
pub(crate) fn juger(marque: bool, installee: bool, s: &Souvenir) -> Verdict {
    if marque || installee {
        return Verdict::Voulue;
    }
    match s {
        Souvenir::Jamais => Verdict::PasVoulue(None),
        Souvenir::Arretee(quand) => Verdict::PasVoulue(Some(quand.clone())),
        Souvenir::Voulue(depuis) => Verdict::CoupeeHors(Some(depuis.clone())),
        // Une écriture étrangère prouvée, sans rien d'autre en place : coupée hors de Vanguard, pas un simple doute.
        Souvenir::Douteux(Doute::HorsVanguard) => Verdict::CoupeeHors(None),
        Souvenir::Douteux(d) => Verdict::NonVerifiee(*d),
    }
}

fn lire_fichier(dossier: &Path) -> Result<Fichier, Doute> {
    let octets = match crate::sceau::lire_dans(dossier, FICHIER) {
        Lecture::Absent => return Ok(Fichier::default()),
        Lecture::Intact(o) => o,
        // Né scellé : aucune version ne l'a écrit sans sceau. Accepté tel quel, c'est que sceaux.json a disparu,
        // refait ou pas (tout effacer d'un coup ne laisse pas de témoin) : rien ne prouve qui l'a écrit.
        Lecture::Adopte(_) => return Err(Doute::Adopte),
        Lecture::Falsifie(_) => return Err(Doute::HorsVanguard),
        Lecture::Inconnu => return Err(Doute::Inconnu),
        Lecture::Illisible(_) => return Err(Doute::Illisible),
    };
    serde_json::from_slice(&octets).map_err(|_| Doute::Illisible)
}

/// Ce que l'état scellé de `dossier` dit de `d`.
pub(crate) fn souvenir_dans(dossier: &Path, d: Defense) -> Souvenir {
    match lire_fichier(dossier) {
        Err(doute) => Souvenir::Douteux(doute),
        Ok(f) => match f.defenses.get(d.cle()) {
            None => Souvenir::Jamais,
            Some(n) if n.douteuse => Souvenir::Douteux(Doute::Herite),
            Some(n) if n.voulue => Souvenir::Voulue(n.quand.clone()),
            Some(n) => Souvenir::Arretee(n.quand.clone()),
        },
    }
}

pub(crate) fn souvenir(d: Defense) -> Souvenir {
    souvenir_dans(&crate::socle::dossier_local(), d)
}

/// Note `d` voulue ou arrêtée dans l'état scellé de `dossier`, et, si `au_journal`, le geste au journal des
/// événements. Rien n'est réécrit si c'est déjà ce qui est noté. Un état qui ne pouvait pas être cru repart de cette
/// seule défense : les autres y restent douteuses, jamais « jamais voulues ». Rend vrai si quelque chose a changé.
pub(crate) fn noter_dans(dossier: &Path, d: Defense, voulue: bool, au_journal: bool) -> std::io::Result<bool> {
    let aujourd_hui = chrono::Local::now().format("%Y-%m-%d").to_string();
    let mut f = if let Ok(f) = lire_fichier(dossier) {
        if f.defenses
            .get(d.cle())
            .is_some_and(|n| n.voulue == voulue && !n.douteuse)
        {
            return Ok(false);
        }
        f
    } else {
        let mut f = Fichier::default();
        for autre in TOUTES.into_iter().filter(|a| *a != d) {
            f.defenses.insert(
                autre.cle().to_string(),
                Note {
                    voulue: true,
                    quand: aujourd_hui.clone(),
                    douteuse: true,
                },
            );
        }
        f
    };
    f.defenses.insert(
        d.cle().to_string(),
        Note {
            voulue,
            quand: aujourd_hui,
            douteuse: false,
        },
    );
    let octets = serde_json::to_vec_pretty(&f).map_err(std::io::Error::other)?;
    crate::sceau::ecrire_dans(dossier, FICHIER, &octets)?;
    if au_journal {
        noter_au_journal(d, voulue);
    }
    Ok(true)
}

/// La mise en marche ou l'arrêt, au journal des événements : daté, à côté des alertes qui suivraient une coupure.
fn noter_au_journal(d: Defense, voulue: bool) {
    use crate::modele::evenement::{Evenement, Source};
    let quoi = if voulue {
        trf!("{} : mise en marche", "{}: turned on", d.nom())
    } else {
        trf!("{} : arrêt", "{}: turned off", d.nom())
    };
    crate::modele::journal::noter(
        Evenement::action(Source::Utilisateur, &quoi, true, &[]).cle(Some(&format!("defense|{}", d.cle()))),
    );
}

/// La personne allume ou coupe `d` par Vanguard : noté et scellé, au journal aussi. Un échec d'écriture ne retient
/// pas le geste : il va au journal des erreurs.
pub(crate) fn noter(d: Defense, voulue: bool) {
    if let Err(e) = noter_dans(&crate::socle::dossier_local(), d, voulue, true) {
        crate::modele::Echec::echoue("voulues/noter", e.to_string()).journaliser();
    }
}

/// Une défense trouvée en place sans rien de noté (allumée par une version d'avant) : notée voulue, sans geste au
/// journal. Jamais par-dessus un arrêt noté ni un état douteux.
pub(crate) fn adopter_dans(dossier: &Path, d: Defense) {
    if souvenir_dans(dossier, d) == Souvenir::Jamais {
        let _ = noter_dans(dossier, d, true, false);
    }
}

pub(crate) fn adopter(d: Defense) {
    adopter_dans(&crate::socle::dossier_local(), d);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn jetable(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vanguard-voulues-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn marche_et_arret_notes_et_scelles() {
        let d = jetable("notes");
        assert_eq!(souvenir_dans(&d, Defense::Veilleur), Souvenir::Jamais);
        assert!(noter_dans(&d, Defense::Veilleur, true, false).unwrap());
        assert!(matches!(souvenir_dans(&d, Defense::Veilleur), Souvenir::Voulue(_)));
        // Déjà noté : rien n'est réécrit.
        assert!(!noter_dans(&d, Defense::Veilleur, true, false).unwrap());
        assert_eq!(souvenir_dans(&d, Defense::Surveillance), Souvenir::Jamais);
        assert!(noter_dans(&d, Defense::Veilleur, false, false).unwrap());
        assert!(matches!(souvenir_dans(&d, Defense::Veilleur), Souvenir::Arretee(_)));
        assert!(matches!(crate::sceau::lire_dans(&d, FICHIER), Lecture::Intact(_)));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Le cas qui coupait une défense en silence : la marque effacée avec la tâche. Voulue sans arrêt noté, c'est une
    /// coupure hors de Vanguard, jamais « coupée comme par défaut ».
    #[test]
    fn marque_et_tache_effacees_ne_valent_pas_coupee_normalement() {
        let d = jetable("effacees");
        noter_dans(&d, Defense::Surveillance, true, false).unwrap();
        let s = souvenir_dans(&d, Defense::Surveillance);
        assert!(matches!(juger(false, false, &s), Verdict::CoupeeHors(_)));
        assert_eq!(juger(true, false, &s), Verdict::Voulue);
        assert_eq!(juger(false, true, &s), Verdict::Voulue);
        // Arrêtée par Vanguard : coupée normalement, avec son jour.
        noter_dans(&d, Defense::Surveillance, false, false).unwrap();
        assert!(matches!(
            juger(false, false, &souvenir_dans(&d, Defense::Surveillance)),
            Verdict::PasVoulue(Some(_))
        ));
        assert_eq!(juger(false, false, &Souvenir::Jamais), Verdict::PasVoulue(None));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// L'état réécrit sans sceau (« jamais voulue », ou effacé) : une écriture étrangère prouvée, jamais un feu vert.
    /// Une marque restée la fait supposer voulue ; sans indice, coupée hors de Vanguard (pas un simple doute).
    #[test]
    fn etat_reecrit_sans_sceau_douteux() {
        let d = jetable("reecrit");
        noter_dans(&d, Defense::Veilleur, true, false).unwrap();
        std::fs::write(
            d.join(FICHIER),
            br#"{"defenses":{"veilleur":{"voulue":false,"quand":"2026-01-01"}}}"#,
        )
        .unwrap();
        let s = souvenir_dans(&d, Defense::Veilleur);
        assert_eq!(s, Souvenir::Douteux(Doute::HorsVanguard));
        assert_eq!(juger(false, false, &s), Verdict::CoupeeHors(None));
        assert_eq!(juger(true, false, &s), Verdict::Voulue);
        // Effacé : douteux aussi (Vanguard l'avait écrit).
        std::fs::remove_file(d.join(FICHIER)).unwrap();
        assert_eq!(
            souvenir_dans(&d, Defense::Veilleur),
            Souvenir::Douteux(Doute::HorsVanguard)
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Les sceaux effacés : l'état accepté tel quel, ou disparu avec eux, ne se croit plus.
    #[test]
    fn etat_adopte_ou_inconnu_apres_sceaux_refaits() {
        let d = jetable("adopte");
        noter_dans(&d, Defense::Rancongiciel, true, false).unwrap();
        std::fs::write(
            d.join(FICHIER),
            br#"{"defenses":{"rancongiciel":{"voulue":false,"quand":"2026-01-01"}}}"#,
        )
        .unwrap();
        std::fs::remove_file(d.join("sceaux.json")).unwrap();
        let s = souvenir_dans(&d, Defense::Rancongiciel);
        assert_eq!(s, Souvenir::Douteux(Doute::Adopte));
        assert_eq!(juger(false, false, &s), Verdict::NonVerifiee(Doute::Adopte));
        // Effacé avec les sceaux : inconnu.
        let d2 = jetable("inconnu");
        noter_dans(&d2, Defense::Rancongiciel, true, false).unwrap();
        std::fs::remove_file(d2.join(FICHIER)).unwrap();
        std::fs::remove_file(d2.join("sceaux.json")).unwrap();
        assert_eq!(
            souvenir_dans(&d2, Defense::Rancongiciel),
            Souvenir::Douteux(Doute::Inconnu)
        );
        for x in [d, d2] {
            let _ = std::fs::remove_dir_all(&x);
        }
    }

    /// Accepté tel quel sans même des sceaux refaits (sceaux.json et son verrou effacés d'un coup) : né scellé, il ne
    /// se croit pas pour autant.
    #[test]
    fn adopte_sans_sceaux_refaits_pas_cru() {
        let d = jetable("adopte-neuf");
        noter_dans(&d, Defense::Surveillance, false, false).unwrap();
        for f in ["sceaux.json", "sceaux.verrou"] {
            let _ = std::fs::remove_file(d.join(f));
        }
        assert!(!crate::sceau::refaits_dans(&d));
        assert_eq!(
            souvenir_dans(&d, Defense::Surveillance),
            Souvenir::Douteux(Doute::Adopte)
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Réécrit par Vanguard pour une défense après un état douteux : les autres restent douteuses, et une adoption ne
    /// passe jamais par-dessus.
    #[test]
    fn le_doute_reste_sur_les_autres_defenses() {
        let d = jetable("doute");
        noter_dans(&d, Defense::Veilleur, true, false).unwrap();
        std::fs::write(d.join(FICHIER), br#"{"defenses":{}}"#).unwrap();
        noter_dans(&d, Defense::Surveillance, true, false).unwrap();
        assert!(matches!(souvenir_dans(&d, Defense::Surveillance), Souvenir::Voulue(_)));
        assert_eq!(souvenir_dans(&d, Defense::Veilleur), Souvenir::Douteux(Doute::Herite));
        assert_eq!(
            juger(false, false, &Souvenir::Douteux(Doute::Herite)),
            Verdict::NonVerifiee(Doute::Herite)
        );
        adopter_dans(&d, Defense::Veilleur);
        assert_eq!(souvenir_dans(&d, Defense::Veilleur), Souvenir::Douteux(Doute::Herite));
        // Noté de nouveau par Vanguard (« off ») : le doute part.
        noter_dans(&d, Defense::Veilleur, false, false).unwrap();
        assert!(matches!(souvenir_dans(&d, Defense::Veilleur), Souvenir::Arretee(_)));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn adoption_seulement_si_rien_n_est_note() {
        let d = jetable("adoption");
        adopter_dans(&d, Defense::Surveillance);
        assert!(matches!(souvenir_dans(&d, Defense::Surveillance), Souvenir::Voulue(_)));
        noter_dans(&d, Defense::Surveillance, false, false).unwrap();
        adopter_dans(&d, Defense::Surveillance);
        assert!(matches!(souvenir_dans(&d, Defense::Surveillance), Souvenir::Arretee(_)));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Le geste va au journal des événements, sous une clé stable, seulement quand il est demandé : compté avant et
    /// après dans le journal de ce fil d'essai.
    #[test]
    fn geste_au_journal() {
        let d = jetable("journal");
        let compter = || {
            crate::modele::journal::lire()
                .evenements
                .iter()
                .filter(|e| e.cle.as_deref() == Some("defense|surveillance"))
                .count()
        };
        let avant = compter();
        noter_dans(&d, Defense::Surveillance, true, false).unwrap();
        assert_eq!(compter(), avant, "sans journal demandé, rien n'y va");
        noter_dans(&d, Defense::Surveillance, false, true).unwrap();
        assert_eq!(compter(), avant + 1);
        // Déjà noté : ni réécrit, ni redit au journal.
        noter_dans(&d, Defense::Surveillance, false, true).unwrap();
        assert_eq!(compter(), avant + 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Le dossier d'une version d'avant (0.87) : des sceaux, mais pas encore l'état des défenses voulues. Rien n'y est
    /// douteux : jamais notée, et une marque la fait adopter.
    #[test]
    fn dossier_d_une_version_d_avant() {
        let d = jetable("avant");
        crate::sceau::ecrire_dans(&d, crate::sceau::APPRIS, br#"{"acceptees":{}}"#).unwrap();
        assert_eq!(souvenir_dans(&d, Defense::Surveillance), Souvenir::Jamais);
        assert_eq!(juger(false, false, &Souvenir::Jamais), Verdict::PasVoulue(None));
        adopter_dans(&d, Defense::Rancongiciel);
        assert!(matches!(souvenir_dans(&d, Defense::Rancongiciel), Souvenir::Voulue(_)));
        let _ = std::fs::remove_dir_all(&d);
    }
}

//! Les corrections du bilan faites par un geste de défense de Linux (`gestes_unix::Defense`), côté parent, sans
//! droits : l'identifiant de la note d'« avant », tiré au hasard, et la correction qui envoie la ligne du geste à
//! l'assistant élevé (`defense_eleve`), défaite par le même assistant (`optimiser::Geste::defense`). Le parent ne
//! juge rien ici : l'enfant root rejuge tout, montre, avertit et demande sur le terminal de la personne.

use super::Constat;
use super::gestes_unix::{CheminDesigne, Defense, GesteUnix, IdNote, NomCompte};

/// Un identifiant neuf : 8 octets du hasard du système, en 16 chiffres hexadécimaux. `None` si le hasard manque :
/// alors aucune correction n'est proposée (deux gestes ne doivent jamais partager une note).
pub(crate) fn nouvel_id() -> Option<IdNote> {
    let mut o = [0u8; 8];
    getrandom::fill(&mut o).ok()?;
    IdNote::nouveau(&super::gestes_unix::hex(&o))
}

/// Le constat `c` corrigé par ces gestes de défense, chacun avec sa note (son identifiant tiré au hasard), défaits
/// dans l'ordre inverse par l'assistant. Sans geste, ou si le hasard manque, `c` reste tel quel (sa correction à la
/// main, s'il en a une).
pub(crate) fn corriger(c: Constat, action: impl Into<String>, gestes: &[Defense]) -> Constat {
    if gestes.is_empty() {
        return c;
    }
    let mut lignes = Vec::with_capacity(gestes.len());
    let mut defaire = Vec::with_capacity(gestes.len());
    for &g in gestes {
        let Some(id) = nouvel_id() else {
            return c;
        };
        lignes.push(GesteUnix::Defense(g, id).ligne());
        defaire.push(crate::optimiser::Geste::defense(id));
    }
    c.corriger(action, &lignes).annulable(defaire)
}

/// Le constat `c` corrigé par ces gestes de défense qui ne se défont pas (un retrait, un arrêt, un appareil oublié) :
/// chacun garde sa note (la copie de ce qu'il retire), la correction est dite non annulable avant d'être appliquée.
pub(crate) fn corriger_sans_defaire(c: Constat, action: impl Into<String>, gestes: &[Defense]) -> Constat {
    if gestes.is_empty() {
        return c;
    }
    let mut lignes = Vec::with_capacity(gestes.len());
    for &g in gestes {
        let Some(id) = nouvel_id() else {
            return c;
        };
        lignes.push(GesteUnix::Defense(g, id).ligne());
    }
    c.corriger(action, &lignes)
}

/// Au plus autant de gestes par constat : au-delà, la liste se relit mal sur le terminal, et c'est un nettoyage à
/// mener soi-même (la correction reste à la main).
pub(crate) const GESTES_MAX: usize = 8;

/// Un geste pour chacun des `objets`, tous ou aucun : un seul qui ne se désigne pas (nom ou chemin refusé), ou plus
/// de `GESTES_MAX`, et la liste entière reste à la main. Jamais une correction qui en ferait une partie en laissant
/// croire qu'elle a tout fait.
pub(crate) fn tous<T>(objets: impl IntoIterator<Item = T>, geste: impl Fn(T) -> Option<Defense>) -> Vec<Defense> {
    let mut gestes = Vec::new();
    for o in objets {
        let Some(g) = geste(o) else {
            return Vec::new();
        };
        if gestes.len() == GESTES_MAX {
            return Vec::new();
        }
        gestes.push(g);
    }
    gestes
}

/// Verrouiller chacun de ces comptes (tous ou aucun).
pub(crate) fn verrouiller<'a>(noms: impl IntoIterator<Item = &'a str>) -> Vec<Defense> {
    tous(noms, |n| NomCompte::nouveau(n).map(Defense::VerrouillerCompte))
}

/// Le geste qui retire `ligne` (sans sa fin de ligne) de `fichier`, si ce fichier est l'un de ceux qu'un geste de
/// défense a le droit de modifier ; sinon `None` (la correction reste à la main).
pub(crate) fn retirer_ligne(fichier: &str, ligne: &str) -> Option<Defense> {
    let chemin = CheminDesigne::nouveau(fichier.as_bytes())?;
    if !super::gestes_unix::fichier_de_ligne_admis(fichier.as_bytes()) || ligne.contains('\n') {
        return None;
    }
    Some(Defense::RetirerLigne(
        super::defense_eleve::empreinte_de_ligne(ligne.as_bytes()),
        chemin,
    ))
}

/// Le geste qui met en commentaire la ligne de proxy `ligne` de `fichier` (un fichier du système admis) ; sinon
/// `None`.
pub(crate) fn commenter_proxy(fichier: &str, ligne: &str) -> Option<Defense> {
    match retirer_ligne(fichier, ligne)? {
        Defense::RetirerLigne(e, c) => Some(Defense::CommenterProxy(e, c)),
        _ => None,
    }
}

/// Le geste qui retire ce fichier d'ancre de confiance, s'il est dans l'un des dossiers d'ancres ; sinon `None`.
pub(crate) fn retirer_ancre(fichier: &str) -> Option<Defense> {
    let c = CheminDesigne::nouveau(fichier.as_bytes())?;
    super::gestes_unix::ancre_admise(fichier.as_bytes()).then_some(Defense::RetirerAncre(c))
}

/// Le geste « Refaire » qui remet un programme de Vanguard publié et signé à la place de ce programme de tâche, s'il
/// porte le nom du programme de Vanguard hors des dossiers des comptes ; sinon `None` (la correction reste à la main :
/// root n'écrit pas où un compte peut écrire).
pub(crate) fn remettre_programme(programme: &std::path::Path) -> Option<Defense> {
    use std::os::unix::ffi::OsStrExt;
    let octets = programme.as_os_str().as_bytes();
    let c = CheminDesigne::nouveau(octets)?;
    super::gestes_unix::programme_pose_admis(octets).then_some(Defense::RemettreProgramme(c))
}

/// Le geste qui arrête ce programme, désigné par son numéro et sa naissance (relue de `/proc/<pid>/stat` : un numéro
/// repris par un autre programme n'est jamais arrêté) ; `None` s'il est parti ou illisible.
pub(crate) fn arreter_programme(pid: u32) -> Option<Defense> {
    if pid <= 1 {
        return None;
    }
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, _, debut) = super::defense_eleve::naissance_du_stat(&stat)?;
    Some(Defense::ArreterProgramme(pid, debut))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::gestes_unix;

    #[test]
    fn identifiants_neufs_et_distincts() {
        let a = nouvel_id().unwrap();
        let b = nouvel_id().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.as_str().len(), 16);
    }

    /// La correction porte la ligne exacte du geste, que l'assistant relit à l'identique, et se défait par la note
    /// du même identifiant.
    #[test]
    fn correction_de_defense() {
        let c = crate::machine::alerte("Comptes", crate::risk::Niveau::Eleve, "essai");
        let n = NomCompte::nouveau("alice").unwrap();
        let c = corriger(c, "Verrouiller", &[Defense::VerrouillerCompte(n)]);
        let k = c.correctif.unwrap();
        assert!(k.automatique);
        let [ligne] = k.commandes.as_slice() else {
            panic!("une seule ligne")
        };
        let Some(GesteUnix::Defense(Defense::VerrouillerCompte(lu), id)) = gestes_unix::analyser(ligne) else {
            panic!("ligne de défense attendue : {ligne}");
        };
        assert_eq!(lu.as_str(), "alice");
        let crate::machine::Defaire::Gestes(g) = k.defaire else {
            panic!("annulable attendu")
        };
        assert_eq!(g, vec![crate::optimiser::Geste::defense(id)]);
        assert_eq!(g[0].0, format!("defense|{}", id.as_str()));
    }

    /// Plusieurs gestes : une note chacun, jamais partagée ; sans geste, le constat garde sa correction à la main.
    #[test]
    fn plusieurs_gestes_et_aucun() {
        let alice = NomCompte::nouveau("alice").unwrap();
        let bob = NomCompte::nouveau("bob").unwrap();
        let c = crate::machine::alerte("Comptes", crate::risk::Niveau::Eleve, "essai");
        let k = corriger(
            c,
            "Verrouiller",
            &[Defense::VerrouillerCompte(alice), Defense::VerrouillerCompte(bob)],
        )
        .correctif
        .unwrap();
        let ids: Vec<IdNote> = k
            .commandes
            .iter()
            .map(|l| match gestes_unix::analyser(l) {
                Some(GesteUnix::Defense(_, id)) => id,
                _ => panic!("ligne de défense attendue : {l}"),
            })
            .collect();
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
        let crate::machine::Defaire::Gestes(g) = k.defaire else {
            panic!("annulable attendu")
        };
        assert_eq!(g.len(), 2);

        let c =
            crate::machine::alerte("Comptes", crate::risk::Niveau::Eleve, "essai").manuel("À la main", &["usermod"]);
        let k = corriger(c, "Rien", &[]).correctif.unwrap();
        assert!(!k.automatique);
        assert_eq!(k.commandes, vec!["usermod".to_string()]);
    }

    /// Seuls les fichiers admis ; une ligne qui en contient deux est refusée ; l'empreinte est celle que l'assistant
    /// recalcule sur la ligne lue.
    #[test]
    fn retrait_de_ligne() {
        let Some(Defense::RetirerLigne(e, c)) = retirer_ligne("/etc/ld.so.preload", "/tmp/x.so") else {
            panic!("fichier admis");
        };
        assert_eq!(c.octets(), b"/etc/ld.so.preload");
        assert_eq!(e, crate::machine::defense_eleve::empreinte_de_ligne(b"/tmp/x.so"));
        assert!(retirer_ligne("/home/alice/.bashrc", "x").is_none());
        assert!(retirer_ligne("/etc/shadow", "x").is_none());
        assert!(retirer_ligne("/etc/../etc/ld.so.preload", "x").is_none());
        assert!(retirer_ligne("/etc/ld.so.preload", "a\nb").is_none());
    }

    /// Tous ou aucun : un nom refusé (forgé, hostile) ou une liste trop longue laisse tout à la main.
    #[test]
    fn tous_ou_aucun() {
        const AUCUN: [Defense; 0] = [];
        assert_eq!(verrouiller(["alice", "bob"]).len(), 2);
        assert_eq!(verrouiller(["alice", "bob;rm -rf /"]), AUCUN);
        assert_eq!(verrouiller(["alice", "-o"]), AUCUN);
        assert_eq!(verrouiller(["alice", ""]), AUCUN);
        assert_eq!(verrouiller(std::iter::empty()), AUCUN);
        let huit: Vec<String> = (0..GESTES_MAX).map(|i| format!("alice{i}")).collect();
        assert_eq!(verrouiller(huit.iter().map(String::as_str)).len(), GESTES_MAX);
        let neuf: Vec<String> = (0..=GESTES_MAX).map(|i| format!("alice{i}")).collect();
        assert_eq!(verrouiller(neuf.iter().map(String::as_str)), AUCUN);
    }
}

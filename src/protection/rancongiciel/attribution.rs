//! Qui a fait la rafale ? Sans droits, aucun système ne donne le pid de l'auteur d'un changement de fichier : on le
//! déduit, prudemment. Au début d'une rafale seulement (pas en continu), le veilleur relève deux fois à ~1 s d'écart
//! les compteurs d'écriture des processus du compte et leurs descripteurs ouverts, puis cette fonction PURE décide.
//!
//! La règle est volontairement stricte (Critique C1), car l'attribution seule peut déclencher un gel : un candidat
//! doit avoir un descripteur ouvert EN ÉCRITURE sur un fichier DE LA RAFALE (pas seulement un dossier touché) et des
//! octets écrits du même ordre que la taille réécrite ; et s'il reste un seul processus du compte illisible (non
//! dumpable), l'attribution est « Aucune » — jamais l'arrêt d'un programme visible quand un invisible a pu agir.

use std::collections::HashSet;
use std::path::PathBuf;

/// Un candidat possible : un groupe de processus (sa racine de lignée), ce qu'il a écrit entre les deux relevés, et
/// s'il tenait un descripteur en écriture sur un fichier de la rafale.
#[derive(Debug, Clone)]
pub(crate) struct Candidat {
    /// La racine de sa lignée : plusieurs processus d'un même rançongiciel partagent ce groupe.
    pub groupe: u32,
    /// Octets passés au stockage entre les deux relevés (`write_bytes`).
    pub ecrits: u64,
    /// Un descripteur ouvert en écriture (O_WRONLY/O_RDWR) sur un fichier vu dans la rafale.
    pub descripteur_rafale: bool,
}

/// À qui attribuer la rafale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Attribution {
    /// Un seul groupe candidat, sans ambiguïté : son identifiant (la racine de lignée).
    Une(u32),
    /// Plusieurs groupes candidats : on ne tranche pas (alerte, jamais d'arrêt).
    Plusieurs,
    /// Aucun candidat net, ou un processus illisible a pu faire le travail : non attribuée.
    Aucune,
}

/// Fraction de la taille réécrite qu'un candidat doit au moins avoir écrite pour être retenu : le chiffrement
/// intermittent écrit moins que la taille totale, mais reste du même ordre. 1/4 laisse passer ces cas sans retenir un
/// processus qui n'a presque rien écrit.
const FRACTION_OCTETS: u64 = 4;

/// Décide l'attribution. `octets_rafale` : la taille totale (approximative) des fichiers réécrits dans la fenêtre.
/// `un_illisible` : au moins un processus du compte était illisible (non dumpable) pendant la rafale. Un candidat
/// n'est retenu que s'il tenait un descripteur en écriture sur un fichier de la rafale ET a écrit au moins
/// `octets_rafale / 4`.
pub(crate) fn candidats(candidats: &[Candidat], octets_rafale: u64, un_illisible: bool) -> Attribution {
    if un_illisible {
        return Attribution::Aucune;
    }
    let seuil = (octets_rafale / FRACTION_OCTETS).max(1);
    let mut groupes: Vec<u32> = candidats
        .iter()
        .filter(|c| c.descripteur_rafale && c.ecrits >= seuil)
        .map(|c| c.groupe)
        .collect();
    groupes.sort_unstable();
    groupes.dedup();
    match groupes.as_slice() {
        [] => Attribution::Aucune,
        [un] => Attribution::Une(*un),
        _ => Attribution::Plusieurs,
    }
}

/// Ce qu'on a relevé d'un processus du compte, aux deux relevés.
#[derive(Debug, Clone, Default)]
pub(crate) struct Releve {
    /// La racine de sa lignée.
    pub groupe: u32,
    /// `write_bytes` au premier et au second relevé ; `None` : illisible.
    pub avant: Option<u64>,
    pub apres: Option<u64>,
    /// Il existe encore au second relevé.
    pub present: bool,
    /// Il était déjà illisible au démarrage de la veille (même pid, même heure de départ) : systemd --user, (sd-pam).
    pub illisible_connu: bool,
    /// Les fichiers qu'il tenait ouverts en écriture, à l'un ou l'autre relevé.
    pub ouverts: HashSet<PathBuf>,
}

/// L'attribution d'après les relevés. `rafale` : les fichiers de la rafale, liste prise APRÈS la pause (un fichier
/// tenu au premier relevé et refermé depuis y est entré). Un processus parti entre les deux relevés ne peut plus
/// agir ni être gelé : il est ignoré. Un illisible déjà connu au démarrage est ignoré aussi ; tout autre illisible
/// ferme l'attribution, comme avant (règle C1).
pub(crate) fn juger_releves(releves: &[Releve], rafale: &HashSet<PathBuf>, octets_rafale: u64) -> Attribution {
    let mut un_illisible = false;
    let mut liste = Vec::new();
    for r in releves {
        match (r.avant, r.apres) {
            (Some(a), Some(b)) => liste.push(Candidat {
                groupe: r.groupe,
                ecrits: b.saturating_sub(a),
                descripteur_rafale: r.ouverts.iter().any(|f| rafale.contains(f)),
            }),
            _ if !r.present || r.illisible_connu => {}
            _ => un_illisible = true,
        }
    }
    candidats(&liste, octets_rafale, un_illisible)
}

/// Les compteurs d'entrées-sorties d'un processus (Linux : `/proc/<pid>/io`). `None` : illisible (non dumpable, hidepid,
/// parti) — l'appelant en fait un « candidat inconnu ».
#[cfg(target_os = "linux")]
pub(crate) fn compteurs_io(pid: u32) -> Option<ComptesIo> {
    let texte = std::fs::read_to_string(format!("/proc/{pid}/io")).ok()?;
    lire_compteurs(&texte)
}

/// Les compteurs utiles d'un processus : octets lus et écrits au stockage.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ComptesIo {
    pub lus: u64,
    pub ecrits: u64,
}

/// Lit `read_bytes` et `write_bytes` du texte de `/proc/<pid>/io`. Testable sans /proc.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn lire_compteurs(texte: &str) -> Option<ComptesIo> {
    let champ = |cle: &str| {
        texte
            .lines()
            .find_map(|l| l.strip_prefix(cle)?.trim().parse::<u64>().ok())
    };
    Some(ComptesIo {
        lus: champ("read_bytes:")?,
        ecrits: champ("write_bytes:")?,
    })
}

/// Les fichiers que le processus tient ouverts en écriture (Linux : `/proc/<pid>/fd` et fdinfo), en chemins absolus.
/// Vide si rien ne se lit : un processus parti ou illisible n'a rien à montrer.
#[cfg(target_os = "linux")]
pub(crate) fn ouverts_en_ecriture(pid: u32) -> HashSet<PathBuf> {
    let mut ouverts = HashSet::new();
    let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return ouverts;
    };
    for entree in fds.flatten() {
        let Ok(cible) = std::fs::read_link(entree.path()) else {
            continue;
        };
        // fdinfo donne les drapeaux d'ouverture : bit O_WRONLY/O_RDWR.
        let Some(nom) = entree.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if let Ok(info) = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{nom}"))
            && ouvert_en_ecriture(&info)
        {
            ouverts.insert(cible);
        }
    }
    ouverts
}

/// Le champ « flags: » de fdinfo marque-t-il une ouverture en écriture ? Le noyau l'écrit en octal (« 0100002 ») :
/// les deux bits de poids faible du mode d'accès valent O_WRONLY=1 ou O_RDWR=2.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn ouvert_en_ecriture(fdinfo: &str) -> bool {
    fdinfo
        .lines()
        .find_map(|l| u32::from_str_radix(l.strip_prefix("flags:")?.trim(), 8).ok())
        .is_some_and(|flags| matches!(flags & 0b11, 1 | 2))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(groupe: u32, ecrits: u64, descripteur: bool) -> Candidat {
        Candidat {
            groupe,
            ecrits,
            descripteur_rafale: descripteur,
        }
    }

    #[test]
    fn un_seul_groupe() {
        let c = [cand(10, 1_000_000, true), cand(10, 900_000, true)];
        assert_eq!(candidats(&c, 2_000_000, false), Attribution::Une(10));
    }

    #[test]
    fn plusieurs_groupes() {
        let c = [cand(10, 1_000_000, true), cand(20, 1_000_000, true)];
        assert_eq!(candidats(&c, 2_000_000, false), Attribution::Plusieurs);
    }

    #[test]
    fn aucun_sans_descripteur() {
        // Un indexeur : compteurs qui montent, mais aucun descripteur en écriture sur un fichier de la rafale.
        let c = [cand(10, 5_000_000, false)];
        assert_eq!(candidats(&c, 2_000_000, false), Attribution::Aucune);
    }

    #[test]
    fn aucun_si_peu_ecrit() {
        let c = [cand(10, 100, true)];
        assert_eq!(candidats(&c, 2_000_000, false), Attribution::Aucune);
    }

    #[test]
    fn un_illisible_ferme_tout() {
        let c = [cand(10, 5_000_000, true)];
        assert_eq!(candidats(&c, 2_000_000, true), Attribution::Aucune);
    }

    fn releve(groupe: u32, avant: Option<u64>, apres: Option<u64>, ouverts: &[&str]) -> Releve {
        Releve {
            groupe,
            avant,
            apres,
            present: true,
            illisible_connu: false,
            ouverts: ouverts.iter().map(PathBuf::from).collect(),
        }
    }

    #[test]
    fn fichier_tenu_au_premier_releve_puis_referme() {
        // Un chiffreur séquentiel : f1 ouvert au premier relevé, refermé avant le second (il est alors dans la
        // rafale à jour), et il n'en tient plus aucun au second.
        let rafale: HashSet<PathBuf> = ["/home/alice/Documents/f1.docx", "/home/alice/Documents/f2.docx"]
            .iter()
            .map(PathBuf::from)
            .collect();
        let r = [releve(42, Some(0), Some(3_000_000), &["/home/alice/Documents/f1.docx"])];
        assert_eq!(juger_releves(&r, &rafale, 2_000_000), Attribution::Une(42));
    }

    #[test]
    fn illisible_connu_ignore_nouveau_ferme() {
        let rafale: HashSet<PathBuf> = [PathBuf::from("/home/alice/Documents/f1.docx")].into_iter().collect();
        let chiffreur = releve(42, Some(0), Some(3_000_000), &["/home/alice/Documents/f1.docx"]);
        let mut connu = releve(7, None, None, &[]);
        connu.illisible_connu = true;
        assert_eq!(
            juger_releves(&[chiffreur.clone(), connu], &rafale, 2_000_000),
            Attribution::Une(42)
        );
        let nouveau = releve(8, None, None, &[]);
        assert_eq!(
            juger_releves(&[chiffreur.clone(), nouveau], &rafale, 2_000_000),
            Attribution::Aucune
        );
        // Parti entre les deux relevés : ignoré.
        let mut parti = releve(9, Some(10), None, &[]);
        parti.present = false;
        assert_eq!(
            juger_releves(&[chiffreur, parti], &rafale, 2_000_000),
            Attribution::Une(42)
        );
    }

    #[test]
    fn compteurs_lus() {
        let texte = "rchar: 100\nwchar: 200\nread_bytes: 4096\nwrite_bytes: 8192\n";
        assert_eq!(
            lire_compteurs(texte),
            Some(ComptesIo {
                lus: 4096,
                ecrits: 8192
            })
        );
        assert_eq!(lire_compteurs("vide"), None);
    }

    #[test]
    fn fdinfo_en_ecriture() {
        assert!(ouvert_en_ecriture("pos:\t0\nflags:\t02\n"));
        assert!(ouvert_en_ecriture("flags:\t0100001\n"));
        assert!(!ouvert_en_ecriture("flags:\t0100000\n"));
    }
}

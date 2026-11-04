//! Les notes versionnées des fichiers du dossier Démarrage mis en quarantaine (défense D6d, R14), pures : la forme
//! d'une note, le nom des copies, la place d'une nouvelle copie et ce qu'il faudrait effacer pour la faire.
//!
//! Un programme qui se redépose doit pouvoir être remis en quarantaine : chaque fichier garde jusqu'à
//! `COPIES_MAX` copies (`<nom>.1` … `<nom>.8`), la remise prend la plus récente ou celle qu'on choisit. Un
//! programme qui se redépose sans fin ne doit pas remplir le disque par Vanguard : les copies écrites par Vanguard
//! tiennent ensemble dans `TOTAL_MAX` (64 Mio, P13 du plan), un fichier déplacé (plus gros qu'un fichier de
//! démarrage, `TAILLE_COPIE_MAX`) n'écrit rien de neuf sur le disque mais ne peut pas dépasser `DEPLACES_MAX`.
//! Au-delà, la plus vieille copie n'est effacée qu'après une question « non annulable » (non par défaut), posée par
//! l'appelant.
//!
//! Le nom d'une copie ne vient jamais tel quel du nom du fichier, choisi par le programme qui se fait relancer : il
//! est nettoyé (lettres et chiffres ASCII, `.`, `-`, `_`), coupé, suivi de l'empreinte de son nom exact (deux noms
//! nettoyés de même ne se mêlent pas) et du numéro de la copie.

use sha2::Digest as _;
use std::fmt::Write as _;

/// Les copies gardées au plus pour un même fichier.
pub(super) const COPIES_MAX: u8 = 8;
/// Le plus gros fichier copié (lu en mémoire, puis écrit) : au-delà, il est déplacé.
pub(super) const TAILLE_COPIE_MAX: u64 = 64 << 20;
/// Les octets de toutes les copies écrites par Vanguard, ensemble (P13).
pub(super) const TOTAL_MAX: u64 = 64 << 20;
/// Les fichiers déplacés gardés au plus, ensemble.
pub(super) const DEPLACES_MAX: usize = 8;
/// La partie lisible du nom d'une copie, au plus.
const NOM_PROPRE_MAX: usize = 40;

/// Comment le fichier est entré en quarantaine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Mode {
    /// Lu, copié, la copie relue, puis l'original retiré.
    Copie,
    /// Renommé par sa poignée dans le dossier de la quarantaine (même disque) : rien de neuf n'est écrit.
    Deplace,
}

impl Mode {
    fn lettre(self) -> char {
        match self {
            Mode::Copie => 'c',
            Mode::Deplace => 'd',
        }
    }
}

/// Une copie notée : son numéro (1 à 8), l'heure de la quarantaine (secondes depuis 1970), sa taille, son mode et
/// l'empreinte SHA-256 de son contenu.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Version {
    pub n: u8,
    pub secondes: u64,
    pub taille: u64,
    pub mode: Mode,
    pub empreinte: String,
}

/// L'empreinte SHA-256 en hexadécimal minuscule.
pub(super) fn hex(octets: &[u8]) -> String {
    octets.iter().fold(String::with_capacity(64), |mut s, o| {
        let _ = write!(s, "{o:02x}");
        s
    })
}

pub(super) fn sha256(octets: &[u8]) -> String {
    hex(&sha2::Sha256::digest(octets))
}

fn empreinte_bonne(e: &str) -> bool {
    e.len() == 64 && e.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// La note d'un fichier : ses copies, « n|secondes|taille|c ou d|empreinte », séparées par « ; ».
pub(super) fn ecrire(versions: &[Version]) -> String {
    versions
        .iter()
        .map(|v| {
            format!(
                "{}|{}|{}|{}|{}",
                v.n,
                v.secondes,
                v.taille,
                v.mode.lettre(),
                v.empreinte
            )
        })
        .collect::<Vec<_>>()
        .join(";")
}

/// Les copies d'une note, si et seulement si elle a exactement cette forme (relue, elle se réécrit à l'identique) :
/// de 1 à 8 copies, chacune d'un numéro différent, empreinte de 64 chiffres hexadécimaux minuscules.
pub(super) fn lire(texte: &str) -> Option<Vec<Version>> {
    let mut versions = Vec::new();
    for morceau in texte.split(';') {
        let c: Vec<&str> = morceau.split('|').collect();
        let [n, secondes, taille, mode, empreinte] = c[..] else {
            return None;
        };
        let n: u8 = n.parse().ok().filter(|n| (1..=COPIES_MAX).contains(n))?;
        let mode = match mode {
            "c" => Mode::Copie,
            "d" => Mode::Deplace,
            _ => return None,
        };
        if !empreinte_bonne(empreinte) || versions.iter().any(|v: &Version| v.n == n) {
            return None;
        }
        versions.push(Version {
            n,
            secondes: secondes.parse().ok()?,
            taille: taille.parse().ok()?,
            mode,
            empreinte: empreinte.to_string(),
        });
    }
    (versions.len() <= usize::from(COPIES_MAX) && ecrire(&versions) == texte).then_some(versions)
}

/// Le nom de la copie `n` du fichier `nom` (son nom exact dans le dossier Démarrage) : « demarrage- », le nom
/// nettoyé et coupé, l'empreinte de son nom exact (8 chiffres), puis « .n ». Toujours un seul composant, jamais
/// « . » ni « .. », jamais un nom de périphérique (il commence par « demarrage- »).
pub(super) fn nom_copie(nom: &str, n: u8) -> String {
    let propre: String = nom
        .chars()
        .take(NOM_PROPRE_MAX)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let marque = sha256(nom.as_bytes());
    format!("demarrage-{propre}-{}.{n}", marque.get(..8).unwrap_or_default())
}

/// La place d'une nouvelle copie : son numéro, et les copies à effacer d'abord (clé de la note, numéro), les plus
/// vieilles d'abord. Vide : rien à effacer, aucune question.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Ajout {
    pub n: u8,
    pub effacer: Vec<(String, u8)>,
}

/// Où mettre une nouvelle copie du fichier noté sous `cle`, de `taille` octets, vu `toutes` les notes de la
/// quarantaine (celle de ce fichier comprise) : au plus `COPIES_MAX` copies pour ce fichier (la plus vieille des
/// siennes cède sa place), au plus `TOTAL_MAX` octets copiés ensemble (les plus vieilles copies, tous fichiers
/// confondus, cèdent la leur), au plus `DEPLACES_MAX` fichiers déplacés. `None` : même en effaçant tout, la copie
/// ne tiendrait pas (plus grosse que `TOTAL_MAX`).
pub(super) fn placer(cle: &str, toutes: &[(String, Vec<Version>)], taille: u64, mode: Mode) -> Option<Ajout> {
    if mode == Mode::Copie && taille > TOTAL_MAX {
        return None;
    }
    let mut effacer: Vec<(String, u8)> = Vec::new();
    let efface = |e: &[(String, u8)], k: &str, v: &Version| e.iter().any(|(c, n)| c == k && *n == v.n);
    // Les plus vieilles d'abord (même seconde : le plus petit numéro).
    let mut rangees: Vec<(&str, &Version)> = toutes
        .iter()
        .flat_map(|(k, vs)| vs.iter().map(move |v| (k.as_str(), v)))
        .collect();
    rangees.sort_by_key(|(k, v)| (v.secondes, *k, v.n));
    let les_miennes = |e: &[(String, u8)]| rangees.iter().filter(|(k, v)| *k == cle && !efface(e, k, v)).count();
    while les_miennes(&effacer) >= usize::from(COPIES_MAX) {
        let (k, v) = rangees.iter().find(|(k, v)| *k == cle && !efface(&effacer, k, v))?;
        effacer.push(((*k).to_string(), v.n));
    }
    match mode {
        Mode::Copie => loop {
            let total: u64 = rangees
                .iter()
                .filter(|(k, v)| v.mode == Mode::Copie && !efface(&effacer, k, v))
                .map(|(_, v)| v.taille)
                .fold(0u64, u64::saturating_add);
            if total.saturating_add(taille) <= TOTAL_MAX {
                break;
            }
            let (k, v) = rangees
                .iter()
                .find(|(k, v)| v.mode == Mode::Copie && !efface(&effacer, k, v))?;
            effacer.push(((*k).to_string(), v.n));
        },
        Mode::Deplace => loop {
            let deplaces = rangees
                .iter()
                .filter(|(k, v)| v.mode == Mode::Deplace && !efface(&effacer, k, v))
                .count();
            if deplaces < DEPLACES_MAX {
                break;
            }
            let (k, v) = rangees
                .iter()
                .find(|(k, v)| v.mode == Mode::Deplace && !efface(&effacer, k, v))?;
            effacer.push(((*k).to_string(), v.n));
        },
    }
    let pris: Vec<u8> = rangees
        .iter()
        .filter(|(k, v)| *k == cle && !efface(&effacer, k, v))
        .map(|(_, v)| v.n)
        .collect();
    let n = (1..=COPIES_MAX).find(|n| !pris.contains(n))?;
    Some(Ajout { n, effacer })
}

/// La copie à remettre : celle qui porte ce numéro, ou la plus récente.
pub(super) fn choisir(versions: &[Version], n: Option<u8>) -> Option<&Version> {
    match n {
        Some(n) => versions.iter().find(|v| v.n == n),
        None => versions.iter().max_by_key(|v| (v.secondes, v.n)),
    }
}

/// Les premiers octets d'un raccourci que Vanguard ne sait pas lire sans COM, montrés tels quels (hexadécimal,
/// 16 par ligne, 256 au plus) puis les textes UTF-16 qu'il contient, échappés : la personne voit ce qu'il lance
/// avant de dire oui. Aucun caractère de contrôle n'arrive à la console.
pub(super) fn octets_montres(octets: &[u8]) -> String {
    let mut s = String::new();
    for ligne in octets.chunks(16).take(16) {
        let h: Vec<String> = ligne.iter().map(|o| format!("{o:02x}")).collect();
        let _ = writeln!(s, "    {}", h.join(" "));
    }
    if octets.len() > 256 {
        let _ = writeln!(s, "    …");
    }
    // Les textes du raccourci (cible, arguments, dossier) : des suites de caractères UTF-16 imprimables.
    let mots: Vec<u16> = octets
        .get(..octets.len().min(1 << 20))
        .unwrap_or_default()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&m| u16::from_le_bytes(m))
        .collect();
    let mut textes = Vec::new();
    for bout in mots.split(|&m| m == 0 || m >= 0xd800) {
        if bout.len() >= 4 && textes.len() < 6 {
            textes.push(super::protege::echappe_exact(&String::from_utf16_lossy(bout), 200));
        }
    }
    for t in textes {
        let _ = writeln!(s, "    {t}");
    }
    s
}

/// Le dossier `dossier` est-il atteint sans aucun lien ni jonction, de lui jusqu'à `base` comprise (`lien` : ce
/// dossier en est-il un ? une erreur de lecture refuse) ? Un dossier hors de `base` ou un chemin avec « .. » est
/// refusé.
pub(super) fn sans_lien(
    dossier: &std::path::Path,
    base: &std::path::Path,
    lien: impl Fn(&std::path::Path) -> std::io::Result<bool>,
) -> bool {
    use std::path::Component;
    let remonte = dossier
        .components()
        .chain(base.components())
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir));
    let bas = |p: &std::path::Path| -> Vec<String> {
        p.components()
            .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
            .collect()
    };
    let (d, b) = (bas(dossier), bas(base));
    if remonte || b.is_empty() || d.len() < b.len() || d.get(..b.len()) != Some(&b[..]) {
        return false;
    }
    dossier
        .ancestors()
        .take(d.len() - b.len() + 1)
        .all(|a| matches!(lien(a), Ok(false)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(n: u8, secondes: u64, taille: u64, mode: Mode) -> Version {
        Version {
            n,
            secondes,
            taille,
            mode,
            empreinte: "a".repeat(64),
        }
    }

    #[test]
    fn la_note_se_relit_a_l_identique() {
        let vs = vec![v(1, 10, 5, Mode::Copie), v(3, 20, 70 << 20, Mode::Deplace)];
        let t = ecrire(&vs);
        assert_eq!(lire(&t), Some(vs));
        // Forme abîmée ou forgée : refusée.
        for mauvaise in [
            "",
            "0|1|1|c|".to_string().as_str(),
            &format!("9|1|1|c|{}", "a".repeat(64)),
            &format!("1|1|1|x|{}", "a".repeat(64)),
            &format!("1|1|1|c|{}", "A".repeat(64)),
            &format!("1|1|1|c|{}", "a".repeat(63)),
            &format!("1|1|1|c|{e};1|2|1|c|{e}", e = "a".repeat(64)),
            &format!("01|1|1|c|{}", "a".repeat(64)),
            &format!("1|1|1|c|{}|..\\x", "a".repeat(64)),
        ] {
            assert_eq!(lire(mauvaise), None, "{mauvaise}");
        }
        let neuf: Vec<Version> = (1..=9).map(|n| v(n.min(8), 1, 1, Mode::Copie)).collect();
        assert_eq!(lire(&ecrire(&neuf)), None);
    }

    /// Le nom d'une copie ne garde rien d'hostile : un seul composant, ASCII sûr, borné ; deux noms qui se
    /// nettoient de même restent deux copies.
    #[test]
    fn nom_de_copie_nettoye() {
        for nom in [
            r"..\..\Windows\System32\x.dll",
            "a:b.lnk",
            "\x1b[31mrouge.lnk",
            "CON",
            "..",
            "nom\u{202e}knl.exe",
            &"é".repeat(5000),
            "a b.lnk",
            "a_b.lnk",
        ] {
            for n in 1..=COPIES_MAX {
                let c = nom_copie(nom, n);
                assert!(c.starts_with("demarrage-") && c.ends_with(&format!(".{n}")), "{c}");
                assert!(
                    c.chars()
                        .all(|x| x.is_ascii_alphanumeric() || matches!(x, '.' | '-' | '_')),
                    "{c}"
                );
                assert!(c.len() <= 10 + NOM_PROPRE_MAX + 1 + 8 + 2, "{c}");
            }
        }
        assert_ne!(nom_copie("a b.lnk", 1), nom_copie("a_b.lnk", 1));
        assert_ne!(nom_copie("x.lnk", 1), nom_copie("x.lnk", 2));
    }

    /// La 9e copie d'un même fichier fait effacer la plus vieille des siennes (la question vient de là) ; les 8
    /// premières, aucune.
    #[test]
    fn neuvieme_copie_demande_d_effacer_la_plus_vieille() {
        let mut toutes = vec![
            ("f".to_string(), Vec::new()),
            ("g".to_string(), vec![v(1, 0, 1, Mode::Copie)]),
        ];
        for i in 1..=COPIES_MAX {
            let a = placer("f", &toutes, 10, Mode::Copie).unwrap();
            assert!(a.effacer.is_empty(), "{i}");
            assert_eq!(a.n, i);
            toutes[0].1.push(v(a.n, 100 + u64::from(i), 10, Mode::Copie));
        }
        let a = placer("f", &toutes, 10, Mode::Copie).unwrap();
        // La plus vieille de ce fichier (la 1), jamais celle d'un autre (« g », plus vieille encore).
        assert_eq!(a.effacer, vec![("f".to_string(), 1)]);
        assert_eq!(a.n, 1);
    }

    /// Les copies tiennent ensemble dans `TOTAL_MAX` : au-delà, les plus vieilles cèdent leur place, et après
    /// l'ajout la somme ne dépasse jamais la borne. Une copie plus grosse que la borne n'a pas de place.
    #[test]
    fn taille_totale_bornee() {
        let mo = 1u64 << 20;
        let toutes = vec![
            ("a".to_string(), vec![v(1, 1, 30 * mo, Mode::Copie)]),
            (
                "b".to_string(),
                vec![v(1, 2, 30 * mo, Mode::Copie), v(2, 3, 900 * mo, Mode::Deplace)],
            ),
        ];
        assert_eq!(
            placer("c", &toutes, 4 * mo, Mode::Copie).unwrap().effacer,
            Vec::<(String, u8)>::new()
        );
        let a = placer("c", &toutes, 30 * mo, Mode::Copie).unwrap();
        assert_eq!(a.effacer, vec![("a".to_string(), 1)]);
        let a = placer("c", &toutes, 64 * mo, Mode::Copie).unwrap();
        assert_eq!(a.effacer, vec![("a".to_string(), 1), ("b".to_string(), 1)]);
        assert_eq!(placer("c", &toutes, 64 * mo + 1, Mode::Copie), None);
        // Toutes les tailles : jamais plus que la borne une fois la copie faite.
        for taille in (0..=64).map(|m| m * mo) {
            let a = placer("c", &toutes, taille, Mode::Copie).unwrap();
            let reste: u64 = toutes
                .iter()
                .flat_map(|(k, vs)| vs.iter().map(move |v| (k, v)))
                .filter(|(k, v)| v.mode == Mode::Copie && !a.effacer.contains(&((*k).clone(), v.n)))
                .map(|(_, v)| v.taille)
                .sum();
            assert!(reste + taille <= TOTAL_MAX, "{taille}");
        }
        // Un fichier déplacé n'écrit rien de neuf : hors de la somme, mais `DEPLACES_MAX` au plus.
        let a = placer("c", &toutes, 900 * mo, Mode::Deplace).unwrap();
        assert_eq!(a.effacer, Vec::<(String, u8)>::new());
        let deplaces: Vec<(String, Vec<Version>)> = (0..DEPLACES_MAX)
            .map(|i| (format!("d{i}"), vec![v(1, i as u64, 100 * mo, Mode::Deplace)]))
            .collect();
        let a = placer("c", &deplaces, 100 * mo, Mode::Deplace).unwrap();
        assert_eq!(a.effacer, vec![("d0".to_string(), 1)]);
    }

    #[test]
    fn remise_la_plus_recente_ou_au_choix() {
        let vs = vec![
            v(2, 50, 1, Mode::Copie),
            v(5, 90, 1, Mode::Copie),
            v(1, 10, 1, Mode::Copie),
        ];
        assert_eq!(choisir(&vs, None).map(|v| v.n), Some(5));
        assert_eq!(choisir(&vs, Some(1)).map(|v| v.n), Some(1));
        assert_eq!(choisir(&vs, Some(3)), None);
        assert_eq!(choisir(&[], None), None);
    }

    #[test]
    fn octets_bruts_montres_sans_controle() {
        let mut o: Vec<u8> = (0u8..=255).collect();
        o.extend("C:\\x\x1b[31m.exe".encode_utf16().flat_map(u16::to_le_bytes));
        let s = octets_montres(&o);
        assert!(s.lines().all(|l| !l.chars().any(char::is_control)), "{s}");
        assert!(s.contains("00 01 02") && s.contains('…'), "{s}");
        assert!(s.contains(r"C:\\x\u{1b}[31m.exe"), "{s}");
    }

    /// Le dossier de la quarantaine n'est jamais atteint par un lien ou une jonction, ni hors de sa base.
    #[test]
    fn quarantaine_par_un_lien_refusee() {
        use std::path::Path;
        let base = Path::new(r"C:\Users\alice\AppData\Local");
        let d = Path::new(r"C:\Users\alice\AppData\Local\vanguard\quarantaine-demarrage");
        assert!(sans_lien(d, base, |_| Ok(false)));
        for piege in [
            r"C:\Users\alice\AppData\Local\vanguard",
            r"C:\Users\alice\AppData\Local\vanguard\quarantaine-demarrage",
            r"C:\Users\alice\AppData\Local",
        ] {
            assert!(!sans_lien(d, base, |a| Ok(a == Path::new(piege))), "{piege}");
        }
        assert!(!sans_lien(d, base, |_| Err(std::io::Error::other("illisible"))));
        assert!(!sans_lien(Path::new(r"C:\Windows\System32"), base, |_| Ok(false)));
        assert!(!sans_lien(
            Path::new(r"C:\Users\alice\AppData\Local\..\..\x"),
            base,
            |_| Ok(false)
        ));
    }
}

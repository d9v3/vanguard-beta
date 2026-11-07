//! Ce que partagent les lecteurs de la base ClamAV : le niveau du moteur dont Vanguard lit les formats, les sortes de
//! fichiers que visent les signatures, et le compte de ce qui n'est pas lu (dit, jamais tu).
//!
//! Module pur, sans `crate::` : le banc de fuzzing l'inclut par son chemin.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

/// Le niveau de fonctions (FLEVEL) de ClamAV 1.5.4, dont Vanguard lit les formats : une signature écrite pour un
/// moteur plus récent (minimum au-dessus) ou plus ancien seulement (maximum au-dessous) n'est pas appliquée, comme
/// ClamAV le fait lui-même. Une signature de ce niveau dont une forme n'est pas comprise est comptée à part.
pub(crate) const NIVEAU: u32 = 234;

/// Une ligne de signature, au plus : les plus longues de la vraie base (logiques à plusieurs dizaines de
/// sous-signatures) font quelques dizaines de Kio.
pub(crate) const LIGNE_MAX: usize = 1 << 20;

/// Ce qui n'est pas appliqué, par raison : chaque compte se dit avec le résultat.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum NonLu {
    /// Programmes potentiellement indésirables (fichiers .hdu, .ndu, .ldu…) : sautés par défaut, comme clamscan.
    Pua,
    /// Ignorées par la base elle-même (.ign, .ign2).
    Ignoree,
    /// Prévues pour un autre niveau du moteur (FLEVEL).
    Niveau,
    /// Bytecode (.cbc) : un programme à exécuter, jamais lancé par Vanguard.
    Bytecode,
    /// Métadonnées d'archives (.cdb, .zmd, .rmd).
    Conteneurs,
    /// Icônes (.idb), certificats (.crb, .cat), imports (.imp), types de fichiers (.ftm), réglages du moteur (.cfg).
    AutreFormat,
    /// Hameçonnage (.pdb, .gdb, .wdb) : des adresses, pas des fichiers.
    Hameconnage,
    /// Règles YARA de la base (.yar, .yara) : Vanguard a les siennes.
    Yara,
    /// Expression rationnelle (PCRE) d'une signature logique.
    Pcre,
    /// Une forme de signature que Vanguard ne lit pas (comparaison d'octets, image floue, macro, `(B)`, `!(…)`…).
    Forme,
    /// Une cible que Vanguard ne prépare pas comme ClamAV (HTML ou texte normalisés, courriel, Flash…).
    Cible,
    /// Une condition du bloc cible des logiques que Vanguard ne sait pas juger (conteneur, icônes…).
    Condition,
    /// Une expression logique qui compte les occurrences au-delà de « présente » ou « absente ».
    Comptage,
    /// Refusée par les bornes du moteur de motifs (trop longue, trop chère, choix trop profonds).
    Bornes,
    /// Une ligne qui ne se lit pas (champs manquants, hexadécimal faux, taille illisible).
    Illisible,
    /// Pas chargée dans ce mode : les empreintes seules (veille continue) laissent les signatures de contenu.
    Mode,
}

/// Combien de signatures ne sont pas appliquées, par raison, et combien le sont seulement en partie.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Comptes {
    pub non_lues: BTreeMap<NonLu, usize>,
    /// Appliquées avec un saut sans fin (`*`, `{n-}`) borné : un écart plus grand entre deux morceaux échappe.
    pub approchees: usize,
    /// Membres d'une base absents de sa liste (.info) : ni crus ni lus.
    pub hors_liste: usize,
}

impl Comptes {
    pub(crate) fn ajouter(&mut self, raison: NonLu, n: usize) {
        if n > 0 {
            let compte = self.non_lues.entry(raison).or_insert(0);
            *compte = compte.saturating_add(n);
        }
    }

    pub(crate) fn un(&mut self, raison: NonLu) {
        self.ajouter(raison, 1);
    }

    pub(crate) fn fusionner(&mut self, autre: &Comptes) {
        for (&raison, &n) in &autre.non_lues {
            self.ajouter(raison, n);
        }
        self.approchees = self.approchees.saturating_add(autre.approchees);
        self.hors_liste = self.hors_liste.saturating_add(autre.hors_liste);
    }

    /// Toutes les signatures non appliquées, sauf celles que la base ignore elle-même, les PUA et celles qu'un mode
    /// laisse (des choix).
    pub(crate) fn manquees(&self) -> usize {
        self.non_lues
            .iter()
            .filter(|(r, _)| !matches!(r, NonLu::Ignoree | NonLu::Pua | NonLu::Mode))
            .fold(0usize, |t, (_, &n)| t.saturating_add(n))
    }
}

/// Les sortes de fichiers que visent les signatures (le champ `Target` de ClamAV), parmi celles que le socle d'analyse
/// reconnaît.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cible {
    /// 0 : n'importe quel fichier, tel quel.
    Tout,
    /// 1 : programme Windows (PE).
    Pe,
    /// 2 : fichier composé OLE (documents Office anciens, MSI) et ce qui en sort (flux, macros).
    Ole,
    /// 5 : image.
    Image,
    /// 6 : programme ELF.
    Elf,
    /// 9 : programme Mach-O.
    MachO,
    /// 10 : PDF, ses octets tels quels.
    Pdf,
    /// 12 : classe Java.
    Java,
}

impl Cible {
    /// La cible du numéro `n` ; `None` : une cible que Vanguard ne prépare pas comme ClamAV (3 HTML normalisé,
    /// 4 courriel, 7 texte normalisé, 11 Flash, 13 et au-delà…).
    pub(crate) fn du_numero(n: u32) -> Option<Cible> {
        Some(match n {
            0 => Cible::Tout,
            1 => Cible::Pe,
            2 => Cible::Ole,
            5 => Cible::Image,
            6 => Cible::Elf,
            9 => Cible::MachO,
            10 => Cible::Pdf,
            12 => Cible::Java,
            _ => return None,
        })
    }

    /// Une signature de cible `self` s'applique-t-elle à une partie de sorte `partie` ?
    pub(crate) fn vise(self, partie: Cible) -> bool {
        self == Cible::Tout || self == partie
    }
}

/// Le niveau de moteur `min` ou `min-max` permet-il la signature ? Champs absents : oui ; illisibles : `None`.
pub(crate) fn niveau_permis(min: Option<&str>, max: Option<&str>) -> Option<bool> {
    let lire = |c: Option<&str>| -> Option<Option<u32>> {
        match c.map(str::trim) {
            None | Some("") => Some(None),
            Some(t) => t.parse().ok().map(Some),
        }
    };
    let (min, max) = (lire(min)?, lire(max)?);
    Some(min.is_none_or(|m| m <= NIVEAU) && max.is_none_or(|m| m >= NIVEAU))
}

/// La valeur d'un chiffre hexadécimal (majuscule ou minuscule) ; `None` pour tout autre caractère (ni signe ni
/// espace : `u8::from_str_radix` accepterait « +1 »).
pub(crate) fn chiffre_hex(o: u8) -> Option<u8> {
    match o {
        b'0'..=b'9' => o.checked_sub(b'0'),
        b'a'..=b'f' => o.checked_sub(b'a')?.checked_add(10),
        b'A'..=b'F' => o.checked_sub(b'A')?.checked_add(10),
        _ => None,
    }
}

/// `N` octets écrits en exactement `2 × N` chiffres hexadécimaux.
pub(crate) fn hex_fixe<const N: usize>(texte: &str) -> Option<[u8; N]> {
    let mut sortie = [0u8; N];
    let octets = texte.as_bytes();
    if octets.len() != N.checked_mul(2)? {
        return None;
    }
    for (o, &[h, b]) in sortie.iter_mut().zip(octets.as_chunks::<2>().0) {
        *o = chiffre_hex(h)?.checked_mul(16)?.checked_add(chiffre_hex(b)?)?;
    }
    Some(sortie)
}

/// Les lignes d'un fichier de signatures : sans fin de ligne (`\n`, `\r\n`), sans lignes vides ni commentaires (`#`).
/// Une ligne qui n'est pas de l'UTF-8 ou plus longue que `LIGNE_MAX` est rendue en `Err(())` : comptée illisible.
pub(crate) fn lignes(texte: &[u8]) -> impl Iterator<Item = Result<&str, ()>> {
    texte.split(|&o| o == b'\n').filter_map(|l| {
        let l = l.strip_suffix(b"\r").unwrap_or(l);
        if l.is_empty() || l.first() == Some(&b'#') {
            return None;
        }
        if l.len() > LIGNE_MAX {
            return Some(Err(()));
        }
        Some(std::str::from_utf8(l).map_err(|_| ()))
    })
}

/// `octets` en hexadécimal (minuscules), pour écrire les bases miniatures des essais.
#[cfg(test)]
pub(crate) fn hex(octets: &[u8]) -> String {
    use std::fmt::Write;
    octets.iter().fold(String::new(), |mut s, o| {
        write!(s, "{o:02x}").unwrap();
        s
    })
}
#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn niveaux() {
        assert_eq!(niveau_permis(None, None), Some(true));
        assert_eq!(niveau_permis(Some("73"), None), Some(true));
        assert_eq!(niveau_permis(Some("234"), Some("234")), Some(true));
        assert_eq!(niveau_permis(Some("235"), None), Some(false));
        assert_eq!(niveau_permis(Some("51"), Some("99")), Some(false));
        assert_eq!(niveau_permis(Some(""), Some("")), Some(true));
        assert_eq!(niveau_permis(Some("x"), None), None);
        assert_eq!(niveau_permis(None, Some("-1")), None);
    }

    #[test]
    fn lignes_lues() {
        let t = b"# commentaire\r\nun:1\r\n\nde\xffux\ntrois";
        let l: Vec<_> = lignes(t).collect();
        assert_eq!(l, vec![Ok("un:1"), Err(()), Ok("trois")]);
        let longue = vec![b'a'; LIGNE_MAX + 1];
        assert_eq!(lignes(&longue).collect::<Vec<_>>(), vec![Err(())]);
    }

    #[test]
    fn hexadecimal() {
        assert_eq!(hex_fixe::<32>(&"aB".repeat(32)), Some([0xAB; 32]));
        assert_eq!(hex_fixe::<32>(&"ab".repeat(31)), None);
        assert_eq!(hex_fixe::<2>("zzzz"), None);
        assert_eq!(hex_fixe::<2>("+1+1"), None);
        assert_eq!(hex_fixe::<2>(" 1 1"), None);
        assert_eq!(hex_fixe::<0>(""), Some([]));
        assert_eq!(hex_fixe::<1>("é"), None);
        assert_eq!(chiffre_hex(b'F'), Some(15));
        assert_eq!(chiffre_hex(b'g'), None);
    }

    #[test]
    fn cibles() {
        assert_eq!(Cible::du_numero(1), Some(Cible::Pe));
        assert_eq!(Cible::du_numero(3), None);
        assert_eq!(Cible::du_numero(u32::MAX), None);
        assert!(Cible::Tout.vise(Cible::Pe));
        assert!(Cible::Pe.vise(Cible::Pe));
        assert!(!Cible::Pe.vise(Cible::Elf));
        assert!(!Cible::Pe.vise(Cible::Tout));
    }

    #[test]
    fn comptes() {
        let mut a = Comptes::default();
        a.un(NonLu::Pcre);
        a.ajouter(NonLu::Pua, 5);
        a.ajouter(NonLu::Ignoree, 2);
        a.ajouter(NonLu::Bornes, 0);
        let mut b = Comptes::default();
        b.ajouter(NonLu::Pcre, usize::MAX);
        b.approchees = 3;
        a.fusionner(&b);
        assert_eq!(a.non_lues.get(&NonLu::Pcre), Some(&usize::MAX));
        assert_eq!(a.non_lues.get(&NonLu::Bornes), None);
        assert_eq!(a.manquees(), usize::MAX);
        assert_eq!(a.approchees, 3);
    }
}

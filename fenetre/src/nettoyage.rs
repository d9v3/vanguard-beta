//! Ce que `vanguard` écrit, prêt à montrer. Ses sorties reprennent des noms venus de l'extérieur (réseau, programme,
//! fichier, appareil) : un nom piégé ne doit ni cacher une alerte, ni retourner un texte (caractères de sens
//! d'écriture), ni glisser une ligne de plus. Les séquences d'échappement (couleurs, déplacements, OSC) sont retirées ;
//! chaque autre caractère piégé devient « � », pour que la manipulation se voie, et une espace d'une autre largeur
//! devient une espace ordinaire, comme dans le terminal
//! (`ui::piege` de Vanguard, même liste). Chaque texte est aussi borné : une ligne immense ne gèle pas la fenêtre.

/// La longueur maximale d'un texte montré, en caractères (« … » compris).
pub const TEXTE_MAX: usize = 4000;

/// La longueur maximale d'une ligne de la console, en caractères.
pub const LIGNE_MAX: usize = 400;

/// Les caractères qui pilotent un affichage ou trompent la lecture : contrôles C0 et C1, trait d'union conditionnel,
/// marques et forçages du sens d'écriture, séparateurs de ligne Unicode, invisibles, étiquettes, et les blancs qui
/// n'en sont pas (remplissages coréens, Braille vide, joint de graphèmes), et les espaces trompeuses
/// (`espace_trompeur`), montrées comme une espace ordinaire. La liste de `ui::piege` de Vanguard.
pub fn piege(c: char) -> bool {
    matches!(
        u32::from(c),
        0x00..=0x1F
            | 0x7F..=0x9F
            | 0xAD
            | 0x034F
            | 0x061C
            | 0x115F..=0x1160
            | 0x180E
            | 0x200B..=0x200F
            | 0x2028..=0x2029
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x2069
            | 0x2800
            | 0x3164
            | 0xFEFF
            | 0xFFA0
            | 0xE0000..=0xE007F
    ) || espace_trompeur(c)
}

/// Les espaces d'une autre largeur que l'espace ordinaire : insécable (U+00A0), ogham (U+1680), de U+2000 à U+200A
/// (cadratin, fine, ultrafine…), fine insécable (U+202F), moyenne mathématique (U+205F), idéographique (U+3000).
/// L'ultrafine ne se voit presque pas (« Sa[U+200A]lon » lu « Salon »), l'idéographique prend deux colonnes et décale un
/// alignement, l'ogham se dessine parfois comme un trait. Ils viennent aussi de sorties normales (nombres écrits à la
/// française, « 12 % ») : montrés comme une espace ordinaire, un par un, ils gardent le texte lisible et ne trompent
/// plus que comme une espace ordinaire le ferait.
pub fn espace_trompeur(c: char) -> bool {
    matches!(u32::from(c), 0xA0 | 0x1680 | 0x2000..=0x200A | 0x202F | 0x205F | 0x3000)
}

/// Ce qui est montré à la place d'un caractère : une espace ordinaire pour une espace trompeuse, « � » pour un autre
/// piège, le caractère lui-même sinon (`ui::affichable` de Vanguard).
fn rendu(c: char) -> char {
    if espace_trompeur(c) {
        ' '
    } else if piege(c) {
        '\u{fffd}'
    } else {
        c
    }
}

/// Retire les séquences d'échappement (CSI `ESC [ … final`, OSC `ESC ] … BEL|ESC \`, DCS/APC/PM/SOS jusqu'à
/// `ESC \`, et les séquences courtes `ESC x`), et le CSI d'un octet (U+009B).
fn sans_sequences(texte: &str) -> String {
    let mut sortie = String::with_capacity(texte.len());
    let mut it = texte.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\u{1b}' => match it.next() {
                Some('[') => {
                    // Paramètres puis un octet final de @ à ~.
                    for x in it.by_ref() {
                        if ('@'..='~').contains(&x) {
                            break;
                        }
                    }
                }
                Some(']' | 'P' | '_' | '^' | 'X') => {
                    // Jusqu'à BEL ou ST (ESC \).
                    while let Some(x) = it.next() {
                        if x == '\u{7}' {
                            break;
                        }
                        if x == '\u{1b}' && it.peek() == Some(&'\\') {
                            it.next();
                            break;
                        }
                    }
                }
                // ESC suivi d'un octet intermédiaire (« ESC ( B ») : celui d'après termine la séquence.
                Some(' '..='/') => {
                    it.next();
                }
                _ => {}
            },
            '\u{9b}' => {
                for x in it.by_ref() {
                    if ('@'..='~').contains(&x) {
                        break;
                    }
                }
            }
            autre => sortie.push(autre),
        }
    }
    sortie
}

/// Coupe à `max` caractères, « … » compris.
pub fn couper(texte: &str, max: usize) -> String {
    if texte.chars().count() <= max {
        return texte.to_string();
    }
    texte
        .chars()
        .take(max.saturating_sub(1))
        .chain(std::iter::once('…'))
        .collect()
}

/// Une ligne de la console : séquences retirées, tabulations en espaces, le reste des pièges en « � », bornée.
pub fn ligne(texte: &str) -> String {
    let propre: String = sans_sequences(texte)
        .chars()
        .map(|c| match c {
            '\t' => ' ',
            c => rendu(c),
        })
        .collect();
    couper(propre.trim_end(), LIGNE_MAX)
}

/// Un texte lu dans un JSON de `vanguard` : séquences retirées ; les sauts de ligne de Vanguard gardés (ses messages
/// en ont), les autres pièges en « � » ; borné à `TEXTE_MAX`.
pub fn texte(texte: &str) -> String {
    let propre: String = sans_sequences(texte)
        .chars()
        .map(|c| match c {
            '\n' => '\n',
            '\t' => ' ',
            c => rendu(c),
        })
        .collect();
    couper(&propre, TEXTE_MAX)
}

/// Un nom sur une ligne (catégorie, règle, interrupteur) : comme `texte`, sans saut de ligne, plus court.
pub fn nom(texte: &str, max: usize) -> String {
    couper(&ligne(texte), max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retire_couleurs_et_deplacements() {
        assert_eq!(ligne("\u{1b}[1;31mAlerte\u{1b}[0m"), "Alerte");
        // Une alerte effacée puis réécrite par un nom piégé : l'effacement disparaît, le retour chariot se voit.
        assert_eq!(ligne("Salon\u{1b}[2K\rtout va bien"), "Salon\u{fffd}tout va bien");
        assert_eq!(ligne("a\u{9b}31mb"), "ab");
        assert_eq!(ligne("\u{1b}(Bx"), "x");
    }

    #[test]
    fn retire_osc_et_dcs() {
        // OSC 52 (presse-papier) terminé par BEL, puis par ST.
        assert_eq!(ligne("x\u{1b}]52;c;Y2F0\u{7}y"), "xy");
        assert_eq!(
            ligne("x\u{1b}]8;;https://exemple.invalid\u{1b}\\lien\u{1b}]8;;\u{1b}\\"),
            "xlien"
        );
        assert_eq!(ligne("\u{1b}Pq#0;2;0;0;0\u{1b}\\fin"), "fin");
        // Séquence jamais terminée : tout le reste part, rien ne panique.
        assert_eq!(ligne("debut\u{1b}]52;c;"), "debut");
        assert_eq!(ligne("\u{1b}"), "");
        assert_eq!(ligne("\u{1b}["), "");
    }

    #[test]
    fn rend_visibles_les_pieges() {
        // Forçage du sens d'écriture (« exe.txt » qui se lit « txt.exe ») et invisibles.
        assert_eq!(ligne("photo\u{202e}gpj.exe"), "photo\u{fffd}gpj.exe");
        assert_eq!(ligne("a\u{200b}b\u{2066}c\u{feff}d"), "a\u{fffd}b\u{fffd}c\u{fffd}d");
        assert_eq!(ligne("tab\tici"), "tab ici");
        assert_eq!(ligne("ligne\u{2028}deux"), "ligne\u{fffd}deux");
        // Tous les sens d'écriture, les largeurs nulles et la marque d'ordre des octets.
        for c in "\u{202a}\u{202b}\u{202c}\u{202d}\u{202e}\u{2066}\u{2067}\u{2068}\u{2069}\u{200b}\u{200c}\u{200d}\u{200e}\u{200f}\u{feff}\u{61c}".chars() {
            assert_eq!(ligne(&format!("a{c}b")), "a\u{fffd}b", "U+{:04X}", u32::from(c));
        }
        // Des blancs qui n'en sont pas : remplissages coréens, Braille vide, joint de graphèmes.
        for c in "\u{3164}\u{ffa0}\u{115f}\u{1160}\u{2800}\u{34f}".chars() {
            assert_eq!(ligne(&format!("Sa{c}lon")), "Sa\u{fffd}lon", "U+{:04X}", u32::from(c));
        }
        assert_eq!(ligne("é ü 漢字 🙂"), "é ü 漢字 🙂");
    }

    /// A4 : une espace d'une autre largeur devient une espace ordinaire, une par une ; elle ne cache plus rien
    /// (l'ultrafine collait « Sa lon » en « Salon ») et un nombre écrit à la française reste lisible.
    #[test]
    fn les_espaces_trompeuses_deviennent_ordinaires() {
        let espaces = "\u{a0}\u{1680}\u{2000}\u{2001}\u{2002}\u{2003}\u{2004}\u{2005}\u{2006}\u{2007}\u{2008}\u{2009}\u{200a}\u{202f}\u{205f}\u{3000}";
        for c in espaces.chars() {
            assert!(piege(c) && espace_trompeur(c), "U+{:04X}", u32::from(c));
            assert_eq!(ligne(&format!("Sa{c}lon")), "Sa lon", "U+{:04X}", u32::from(c));
            assert_eq!(texte(&format!("Sa{c}lon")), "Sa lon", "U+{:04X}", u32::from(c));
        }
        assert_eq!(ligne(&format!("a{espaces}b")), format!("a{}b", " ".repeat(16)));
        assert_eq!(nom("12\u{a0}345\u{202f}octets, 75\u{a0}%", 80), "12 345 octets, 75 %");
        // L'espace ordinaire, le saut de ligne et les blancs déjà traités ne changent pas de sort.
        for c in [' ', '\n', '\u{200b}', '\u{3164}'] {
            assert!(!espace_trompeur(c), "U+{:04X}", u32::from(c));
        }
    }

    /// Le corps de `fn <nom>(c: char) -> bool`, de l'accolade à la première fermeture en début de ligne.
    fn corps<'a>(source: &'a str, nom: &str) -> &'a str {
        let debut = source.find(&format!("fn {nom}(c: char) -> bool {{")).unwrap();
        let fin = source[debut..].find("\n}").unwrap();
        &source[debut..debut + fin]
    }

    /// La liste reste celle du terminal (`ui::piege`, `ui::espace_trompeur` de Vanguard), caractère pour caractère.
    #[test]
    fn meme_liste_que_le_terminal() {
        let ici = include_str!("nettoyage.rs");
        let terminal = include_str!("../../src/ui.rs");
        for nom in ["piege", "espace_trompeur"] {
            assert_eq!(corps(ici, nom), corps(terminal, nom), "{nom}");
        }
    }

    #[test]
    fn un_texte_garde_ses_sauts_de_ligne() {
        assert_eq!(texte("un\ndeux\r\ntrois"), "un\ndeux\u{fffd}\ntrois");
        assert_eq!(nom("un\ndeux", 80), "un\u{fffd}deux");
    }

    #[test]
    fn borne_les_longueurs() {
        let long = "x".repeat(LIGNE_MAX * 3);
        let l = ligne(&long);
        assert_eq!(l.chars().count(), LIGNE_MAX);
        assert!(l.ends_with('…'));
        assert_eq!(texte(&"é".repeat(TEXTE_MAX + 1)).chars().count(), TEXTE_MAX);
        assert_eq!(couper("abc", 3), "abc");
        assert_eq!(couper("abcd", 3), "ab…");
        assert_eq!(couper("abcd", 0), "…");
    }
}

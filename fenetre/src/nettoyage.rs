//! Ce que `vanguard` écrit, prêt à montrer. Ses sorties reprennent des noms venus de l'extérieur (réseau, programme,
//! fichier, appareil) : un nom piégé ne doit ni cacher une alerte, ni retourner un texte (caractères de sens
//! d'écriture), ni glisser une ligne de plus, ni cacher un caractère. Les séquences d'échappement (couleurs,
//! déplacements, OSC) sont retirées. Ensuite, la fenêtre ne montre tel quel que ce que ses polices dessinent vraiment
//! (`ENCRE`, mesurée sur les polices embarquées par `dessin/encre.rs`) : une liste de ce qui passe, pas de ce qui est
//! refusé. Une espace d'une autre largeur devient une espace ordinaire, un sélecteur de variante est retiré, une marque
//! combinante n'est gardée que si les polices la dessinent sur la lettre d'avant ; tout le reste (contrôles,
//! invisibles, caractères de format, non attribués, privés, signes absents des polices) devient « � », pour que la
//! manipulation se voie. Chaque texte est aussi borné : une ligne immense ne gèle pas la fenêtre.

/// La longueur maximale d'un texte montré, en caractères (« … » compris).
pub const TEXTE_MAX: usize = 4000;

/// La longueur maximale d'une ligne de la console, en caractères.
pub const LIGNE_MAX: usize = 400;

/// Marques combinantes gardées au plus sur un même signe : assez pour le vietnamien écrit décomposé (« ệ »), trop peu
/// pour empiler des marques jusqu'à cacher la lettre.
pub const MARQUES_MAX: usize = 2;

/// Ce que la fenêtre fait d'un caractère (la tabulation et le saut de ligne sont traités avant, par chaque lecteur).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dessin {
    /// Montré tel quel : les polices de la fenêtre le dessinent, avec de l'encre et une largeur (`ENCRE`).
    Encre,
    /// Une marque combinante que les polices dessinent sur la lettre d'avant (`marque_permise`) : gardée seulement
    /// sur un signe dessiné, `MARQUES_MAX` au plus, jamais deux fois la même (`montrer`).
    Marque,
    /// Une espace : l'ordinaire, et celles d'une autre largeur, montrées comme elle.
    Blanc,
    /// Un sélecteur de variante : retiré.
    Retire,
    /// Rien de dessiné, ou un piège : montré « � ».
    Rien,
}

/// Le sort d'un caractère, seul. Les listes du terminal d'abord (`ui::piege`, `ui::espace_trompeur`,
/// `ui::invisible_rare` de Vanguard ; `selecteur`, ici avec le sélecteur des émojis), puis ce que les polices
/// dessinent : ce qui n'est dans aucune liste de ce qui passe devient « � ».
pub fn dessin(c: char) -> Dessin {
    if c == ' ' || espace_trompeur(c) {
        Dessin::Blanc
    } else if selecteur(c) {
        Dessin::Retire
    } else if piege(c) || invisible_rare(c) {
        Dessin::Rien
    } else if marque_permise(c) {
        Dessin::Marque
    } else if dans(ENCRE, c) {
        Dessin::Encre
    } else {
        Dessin::Rien
    }
}

/// Les caractères qui pilotent un affichage ou trompent la lecture : contrôles C0 et C1, trait d'union conditionnel,
/// marques et forçages du sens d'écriture, séparateurs de ligne Unicode, invisibles, étiquettes, et les blancs qui
/// n'en sont pas (remplissages coréens, Braille vide, joint de graphèmes). La liste de `ui::piege` de Vanguard.
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
    )
}

/// Les espaces d'une autre largeur que l'espace ordinaire : insécable (U+00A0), ogham (U+1680), de U+2000 à U+200A
/// (cadratin, fine, ultrafine…), fine insécable (U+202F), moyenne mathématique (U+205F), idéographique (U+3000).
/// L'ultrafine ne se voit presque pas (« Sa[U+200A]lon » lu « Salon »), l'idéographique prend deux colonnes et décale un
/// alignement, l'ogham se dessine parfois comme un trait. Ils viennent aussi de sorties normales (nombres écrits à la
/// française, « 12 % ») : montrés comme une espace ordinaire, un par un, ils gardent le texte lisible et ne trompent
/// plus que comme une espace ordinaire le ferait. La liste de `ui::espace_trompeur` de Vanguard.
pub fn espace_trompeur(c: char) -> bool {
    matches!(u32::from(c), 0xA0 | 0x1680 | 0x2000..=0x200A | 0x202F | 0x205F | 0x3000)
}

/// Les sélecteurs de variante (U+FE00 à U+FE0F, U+E0100 à U+E01EF, U+180B à U+180D, U+180F) : légitimes (japonais,
/// chinois, mongol, émoji) et invisibles seuls, ils sont retirés à l'affichage. Le terminal garde le sélecteur des
/// émojis (U+FE0F) ; la fenêtre le retire aussi : ses polices n'ont pas d'émoji en couleur, il n'y dessine rien.
pub fn selecteur(c: char) -> bool {
    matches!(u32::from(c), 0x180B..=0x180D | 0x180F | 0xFE00..=0xFE0F | 0xE0100..=0xE01EF)
}

/// Les invisibles rares, sans usage dans un nom (U+2065, U+206A à U+206F, U+FFF9 à U+FFFB, U+17B4, U+17B5, les autres
/// caractères de format d'Unicode, points réservés invisibles, non-caractères) : montrés « � ». La liste de
/// `ui::invisible_rare` de Vanguard.
pub fn invisible_rare(c: char) -> bool {
    let n = u32::from(c);
    // Non-caractères : les deux derniers de chaque plan (U+xxFFFE, U+xxFFFF).
    n & 0xFFFE == 0xFFFE
        || matches!(
            n,
            0x17B4..=0x17B5
                | 0x2065
                | 0x206A..=0x206F
                | 0xFDD0..=0xFDEF
                | 0xFFF0..=0xFFFB
                | 0x110BD
                | 0x110CD
                | 0x13430..=0x1343F
                | 0x16FE4
                | 0x1BCA0..=0x1BCA3
                | 0x1D173..=0x1D17A
                | 0xE0080..=0xE00FF
                | 0xE01F0..=0xE0FFF
        )
}

/// Les marques combinantes que les trois familles de la fenêtre dessinent sur leur lettre, chacune à sa place (essai
/// `dessin::encre::chaque_marque_permise_se_voit`) : les accents du français et du vietnamien, le tréma, la cédille,
/// l'ogonek, le point souscrit, la corne. Les autres ne se dessinent pas dans une des polices (elles disparaîtraient),
/// recouvrent la lettre (barres obliques) ou se fondent dans son dessin (le point en chef, U+0307, remplace celui du
/// « j » sans rien changer à l'image).
pub fn marque_permise(c: char) -> bool {
    matches!(
        u32::from(c),
        0x0300..=0x0304 | 0x0306 | 0x0308..=0x030A | 0x030C | 0x030F | 0x031B | 0x0323 | 0x0326..=0x0328
    )
}

fn dans(plages: &[(u32, u32)], c: char) -> bool {
    let c = u32::from(c);
    plages
        .binary_search_by(|&(debut, fin)| {
            if fin < c {
                std::cmp::Ordering::Less
            } else if debut > c {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Ce qui est montré à la place d'un caractère seul : une espace ordinaire pour une espace, rien pour un sélecteur de
/// variante, « � » pour ce qui ne se dessine pas, le caractère lui-même sinon. Un caractère montré se montre
/// lui-même. Une marque n'est montrée que sur un signe (`montrer`) : `rendu` ne voit pas le caractère d'avant. Pour
/// les essais et le banc de fuzz (ce qu'un texte montré peut contenir) ; la fenêtre montre par `montrer`.
#[cfg(any(test, fuzzing))]
pub fn rendu(c: char) -> Option<char> {
    match dessin(c) {
        Dessin::Encre | Dessin::Marque => Some(c),
        Dessin::Blanc => Some(' '),
        Dessin::Retire => None,
        Dessin::Rien => Some('\u{fffd}'),
    }
}

/// Le texte a au moins une lettre ou un chiffre dessiné (`Dessin::Encre`) : fait seulement d'espaces, de séquences,
/// de sélecteurs, d'invisibles ou de marques, il se montrerait vide ou comme une suite de « � » ; fait seulement de
/// signes qui imitent un blanc ou un remplacement (« � », « ␠ » U+2420, le point en chef U+02D9), il se lirait comme
/// une commande vide ou retouchée. Les textes d'une correction de Vanguard (phrases, règle, version, commandes) ont
/// tous une lettre ou un chiffre.
pub fn lisible(texte: &str) -> bool {
    sans_sequences(texte)
        .chars()
        .any(|c| dessin(c) == Dessin::Encre && c.is_alphanumeric())
}

/// Les jumeaux gardés : des signes de `ENCRE` que JetBrains Mono dessine exactement comme un autre signe de la liste,
/// gardés parce que Vanguard les écrit lui-même ailleurs que dans une correction (« − », U+2212, marque ses listes
/// dans la console, où il se dessine comme « - »). Un aperçu de correction ne les montre pas tels quels : ils y
/// deviennent « � », et l'aperçu est dit retouché (`donnees::correction`). Tenu par
/// `dessin::encre::deux_signes_montres_ne_se_dessinent_pas_pareil`.
pub const JUMEAUX_GARDES: &[char] = &['\u{2212}'];

/// Les caractères montrés, dans l'ordre : chacun selon `dessin`, la tabulation en espace, le saut de ligne gardé si
/// `sauts`. Une marque n'est gardée que sur un signe montré (pas au début, ni sur une espace ou un saut de ligne),
/// `MARQUES_MAX` au plus et jamais deux fois la même : sinon elle se poserait sur rien, ou sur sa jumelle à la même
/// place, sans se voir. Elle devient alors « � ».
fn montrer(texte: &str, sauts: bool) -> String {
    let mut sortie = String::with_capacity(texte.len());
    // Le dernier caractère montré peut porter une marque ; celles qu'il porte déjà.
    let mut base = false;
    let mut posees: Vec<char> = Vec::with_capacity(MARQUES_MAX);
    for c in sans_sequences(texte).chars() {
        let d = match c {
            '\n' if sauts => {
                sortie.push('\n');
                base = false;
                continue;
            }
            '\t' => Dessin::Blanc,
            c => dessin(c),
        };
        match d {
            Dessin::Retire => {}
            Dessin::Blanc => {
                sortie.push(' ');
                base = false;
            }
            Dessin::Marque if base && posees.len() < MARQUES_MAX && !posees.contains(&c) => {
                posees.push(c);
                sortie.push(c);
            }
            Dessin::Encre => {
                sortie.push(c);
                base = true;
                posees.clear();
            }
            Dessin::Marque | Dessin::Rien => {
                sortie.push('\u{fffd}');
                base = true;
                posees.clear();
            }
        }
    }
    sortie
}

/// Les signes que les trois familles de la fenêtre dessinent (`dessin::polices` : Inter et JetBrains Mono), chacun
/// avec de l'encre et une largeur : lettres, chiffres, ponctuation et symboles, plages triées. Refaite par
/// `dessin::encre::refaire_la_liste`, tenue par `dessin::encre::chaque_signe_montre_se_dessine`.
///
/// Sans les sosies (`dessin::encre::ECARTES`) : un signe qui se dessine exactement comme un autre de la liste
/// (« Ⅰ » et « I », « ‐ » et « - », le point-virgule grec et « ; ») ou comme une suite de signes ASCII (« ‥ » et
/// « .. », « ⅺ » et « xi ») n'y est pas, avec quelques sosies très proches que le terminal écrit aussi `\u{…}`
/// (« ı », « ſ », « Đ », « Ĳ »). Tenu par `dessin::encre::deux_signes_montres_ne_se_dessinent_pas_pareil` et
/// `aucune_suite_ne_dessine_un_signe`. Restent, et c'est dit : les lettres de deux alphabets qui se dessinent pareil
/// (« A » latin, « Α » grec, « А » cyrillique : chacune est la lettre de son alphabet, la retirer rendrait illisibles
/// les noms écrits dans celui-ci) ; « − » (`JUMEAUX_GARDES`) ; les sosies proches sans être identiques (« – » et
/// « - ») ; et, hors de la feuille de correction qui dessine signe par signe, les ligatures (« -> » comme « → »).
#[rustfmt::skip]
pub const ENCRE: &[(u32, u32)] = &[
    (0x0021, 0x007E), (0x00A1, 0x00AC), (0x00AE, 0x010F), (0x0111, 0x0130), (0x0134, 0x0137), (0x0139, 0x013E),
    (0x0141, 0x0148), (0x014A, 0x017E), (0x0180, 0x0188), (0x018A, 0x019D), (0x019F, 0x01C2), (0x01C5, 0x01DC),
    (0x01DE, 0x0254), (0x0256, 0x0260), (0x0262, 0x027B), (0x027E, 0x0284), (0x0286, 0x0290), (0x0292, 0x02A4),
    (0x02A6, 0x02B8), (0x02BA, 0x02BB), (0x02BD, 0x02C8), (0x02CA, 0x02D2), (0x02D4, 0x02ED), (0x02EF, 0x02FF),
    (0x0374, 0x0374), (0x0376, 0x0376), (0x037A, 0x037D), (0x037F, 0x037F), (0x0384, 0x0386), (0x0388, 0x038A),
    (0x038C, 0x038C), (0x038E, 0x03A1), (0x03A3, 0x03D7), (0x03DC, 0x03DD), (0x03F0, 0x03F6), (0x03F9, 0x03F9),
    (0x03FC, 0x0471), (0x0473, 0x0477), (0x0480, 0x0482), (0x048A, 0x048B), (0x048D, 0x049D), (0x04A0, 0x04BF),
    (0x04C1, 0x04CE), (0x04D0, 0x04FF), (0x052F, 0x052F), (0x0AEA, 0x0AEA), (0x0E3F, 0x0E3F), (0x1D00, 0x1D00),
    (0x1D43, 0x1D43), (0x1D47, 0x1D49), (0x1D4D, 0x1D4D), (0x1D4F, 0x1D50), (0x1D52, 0x1D52), (0x1D56, 0x1D58),
    (0x1D5B, 0x1D5B), (0x1D62, 0x1D65), (0x1D9C, 0x1D9C), (0x1DA0, 0x1DA0), (0x1DBB, 0x1DBB), (0x1DBF, 0x1DBF),
    (0x1E00, 0x1E9B), (0x1E9D, 0x1F15), (0x1F18, 0x1F1D), (0x1F20, 0x1F45), (0x1F48, 0x1F4D), (0x1F50, 0x1F57),
    (0x1F59, 0x1F59), (0x1F5B, 0x1F5B), (0x1F5D, 0x1F5D), (0x1F5F, 0x1F70), (0x1F72, 0x1F72), (0x1F74, 0x1F74),
    (0x1F76, 0x1F76), (0x1F78, 0x1F78), (0x1F7A, 0x1F7A), (0x1F7C, 0x1F7C), (0x1F80, 0x1FB4), (0x1FB6, 0x1FBD),
    (0x1FC1, 0x1FC4), (0x1FC6, 0x1FC8), (0x1FCA, 0x1FCA), (0x1FCC, 0x1FD2), (0x1FD6, 0x1FDA), (0x1FDD, 0x1FE2),
    (0x1FE4, 0x1FEA), (0x1FEC, 0x1FED), (0x1FEF, 0x1FEF), (0x1FF2, 0x1FF4), (0x1FF6, 0x1FF8), (0x1FFA, 0x1FFA),
    (0x1FFC, 0x1FFC), (0x1FFE, 0x1FFE), (0x2012, 0x2014), (0x2016, 0x2023), (0x2026, 0x2026), (0x2030, 0x2055),
    (0x2057, 0x2057), (0x2070, 0x2071), (0x2074, 0x208E), (0x2090, 0x209C), (0x20A0, 0x20AF), (0x20B1, 0x20B5),
    (0x20B8, 0x20BA), (0x20BC, 0x20C0), (0x2100, 0x2103), (0x2105, 0x2106), (0x2109, 0x2109), (0x210D, 0x210D),
    (0x2113, 0x2113), (0x2115, 0x2117), (0x2119, 0x211A), (0x211D, 0x2122), (0x2124, 0x2124), (0x212E, 0x212E),
    (0x2132, 0x2132), (0x213B, 0x213B), (0x2140, 0x2140), (0x214D, 0x214D), (0x2150, 0x215F), (0x2189, 0x218B),
    (0x2190, 0x2199), (0x219D, 0x219E), (0x21A0, 0x21A0), (0x21A2, 0x21A3), (0x21A5, 0x21A7), (0x21A9, 0x21AA),
    (0x21AD, 0x21AD), (0x21B0, 0x21B1), (0x21B3, 0x21B5), (0x21BA, 0x21BB), (0x21BE, 0x21BE), (0x21C9, 0x21C9),
    (0x21D0, 0x21D4), (0x21DB, 0x21DB), (0x21DE, 0x21DF), (0x21E4, 0x21E5), (0x21E7, 0x21E8), (0x21EA, 0x21EA),
    (0x2200, 0x2205), (0x2207, 0x220C), (0x220E, 0x2213), (0x221A, 0x221A), (0x221E, 0x221E), (0x2223, 0x2225),
    (0x2227, 0x222A), (0x2234, 0x2235), (0x2237, 0x2239), (0x223E, 0x223E), (0x2243, 0x2243), (0x2245, 0x2245),
    (0x2247, 0x2249), (0x224B, 0x224B), (0x224D, 0x224D), (0x2254, 0x2254), (0x2257, 0x2257), (0x225F, 0x2265),
    (0x226A, 0x2273), (0x227C, 0x227C), (0x2282, 0x2289), (0x228E, 0x2299), (0x229B, 0x22A5), (0x22B4, 0x22B4),
    (0x22B8, 0x22B8), (0x22BB, 0x22BD), (0x22C4, 0x22C4), (0x22C6, 0x22C6), (0x22C8, 0x22CA), (0x22CE, 0x22CE),
    (0x22D0, 0x22D0), (0x22E2, 0x22E2), (0x22EE, 0x22F1), (0x2302, 0x2305), (0x2308, 0x230B), (0x2318, 0x2318),
    (0x231C, 0x231F), (0x2324, 0x2328), (0x232B, 0x232B), (0x2336, 0x2372), (0x2374, 0x237A), (0x2380, 0x2380),
    (0x2387, 0x2387), (0x2389, 0x238B), (0x2395, 0x2395), (0x23CE, 0x23CF), (0x23FB, 0x23FE), (0x2400, 0x2421),
    (0x2423, 0x2424), (0x2460, 0x2468), (0x24B6, 0x24CF), (0x24EA, 0x24EA), (0x2500, 0x25A2), (0x25AA, 0x25AB),
    (0x25B2, 0x25B5), (0x25B8, 0x25BF), (0x25C2, 0x25CC), (0x25CE, 0x25CF), (0x25D4, 0x25D5), (0x25E6, 0x25EB),
    (0x25F6, 0x25F6), (0x2600, 0x2600), (0x2605, 0x2606), (0x263C, 0x263C), (0x2661, 0x2661), (0x2665, 0x2665),
    (0x266A, 0x266B), (0x266D, 0x266D), (0x266F, 0x266F), (0x2687, 0x2687), (0x26A0, 0x26A1), (0x2713, 0x2713),
    (0x2715, 0x2715), (0x2717, 0x2717), (0x2736, 0x2736), (0x2756, 0x2756), (0x276E, 0x2771), (0x2794, 0x2794),
    (0x279C, 0x279E), (0x27C5, 0x27C6), (0x27DC, 0x27DC), (0x27E6, 0x27EB), (0x27EF, 0x27EF), (0x27F5, 0x27FA),
    (0x2913, 0x2913), (0x2916, 0x2916), (0x294A, 0x294A), (0x2987, 0x2988), (0x2A05, 0x2A06), (0x2A38, 0x2A38),
    (0x2B06, 0x2B06), (0x2B12, 0x2B13), (0x2B1C, 0x2B1C), (0x2B24, 0x2B24), (0x2B58, 0x2B58), (0x2C7C, 0x2C7C),
    (0x2C7F, 0x2C7F), (0x2E18, 0x2E18), (0xA7FF, 0xA7FF), (0xA92E, 0xA92E), (0xFE62, 0xFE62), (0xFFFD, 0xFFFD),
    (0x1D538, 0x1D539), (0x1D53B, 0x1D53E), (0x1D540, 0x1D544), (0x1D546, 0x1D546), (0x1D54A, 0x1D550),
    (0x1D552, 0x1D56B), (0x1F12F, 0x1F149), (0x1F16A, 0x1F16B), (0x1F850, 0x1F850), (0x1F852, 0x1F852),
];

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
    couper(&ligne_entiere(texte), LIGNE_MAX)
}

/// `ligne` sans la borne : à couper par l'appelant, qui saura ainsi s'il a coupé (l'aperçu d'une correction le dit).
pub fn ligne_entiere(texte: &str) -> String {
    montrer(texte, false).trim_end().to_string()
}

/// Un texte lu dans un JSON de `vanguard` : séquences retirées ; les sauts de ligne de Vanguard gardés (ses messages
/// en ont), les autres pièges en « � » ; borné à `TEXTE_MAX`.
pub fn texte(texte: &str) -> String {
    couper(&texte_entier(texte), TEXTE_MAX)
}

/// `texte` sans la borne (voir `ligne_entiere`).
pub fn texte_entier(texte: &str) -> String {
    montrer(texte, true)
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
        assert_eq!(ligne("é ü Ω Ж № € ✓ →"), "é ü Ω Ж № € ✓ →");
    }

    /// A4 : une espace d'une autre largeur devient une espace ordinaire, une par une ; elle ne cache plus rien
    /// (l'ultrafine collait « Sa lon » en « Salon ») et un nombre écrit à la française reste lisible.
    #[test]
    fn les_espaces_trompeuses_deviennent_ordinaires() {
        let espaces = "\u{a0}\u{1680}\u{2000}\u{2001}\u{2002}\u{2003}\u{2004}\u{2005}\u{2006}\u{2007}\u{2008}\u{2009}\u{200a}\u{202f}\u{205f}\u{3000}";
        for c in espaces.chars() {
            assert!(espace_trompeur(c) && !piege(c), "U+{:04X}", u32::from(c));
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

    /// Les listes du terminal (`ui::piege`, `ui::espace_trompeur`, `ui::selecteur`, `ui::invisible_rare` de Vanguard,
    /// recopiées le 11 nov. 2026) : aucun de leurs caractères ne se montre tel quel dans la fenêtre. Une espace
    /// trompeuse devient une espace ordinaire, un sélecteur disparaît, le reste devient « � ». La fenêtre en fait
    /// plus que le terminal (ce que ses polices ne dessinent pas) : la comparaison des deux listes, texte à texte, ne
    /// tient plus ; ce test dit qu'elle n'en fait jamais moins.
    #[test]
    fn rien_de_ce_que_le_terminal_retire_ne_passe() {
        let piege = [
            (0x00, 0x1F),
            (0x7F, 0x9F),
            (0xAD, 0xAD),
            (0x034F, 0x034F),
            (0x061C, 0x061C),
            (0x115F, 0x1160),
            (0x180E, 0x180E),
            (0x200B, 0x200F),
            (0x2028, 0x2029),
            (0x202A, 0x202E),
            (0x2060, 0x2064),
            (0x2066, 0x2069),
            (0x2800, 0x2800),
            (0x3164, 0x3164),
            (0xFEFF, 0xFEFF),
            (0xFFA0, 0xFFA0),
            (0xE0000, 0xE007F),
        ];
        let espace = [
            (0xA0, 0xA0),
            (0x1680, 0x1680),
            (0x2000, 0x200A),
            (0x202F, 0x202F),
            (0x205F, 0x205F),
            (0x3000, 0x3000),
        ];
        let selecteur = [(0x180B, 0x180D), (0x180F, 0x180F), (0xFE00, 0xFE0E), (0xE0100, 0xE01EF)];
        let rare = [(0x17B4, 0x17B5), (0x206A, 0x206F), (0xFFF9, 0xFFFB)];
        let chaque = |plages: &[(u32, u32)]| -> Vec<char> {
            plages
                .iter()
                .flat_map(|&(a, b)| (a..=b).filter_map(char::from_u32))
                .collect()
        };
        for c in chaque(&piege).into_iter().chain(chaque(&rare)) {
            assert_eq!(rendu(c), Some('\u{fffd}'), "U+{:04X}", u32::from(c));
            // La tabulation et le saut de ligne d'un texte ont leur sort ; ESC et CSI ouvrent une séquence, retirée.
            let attendu = match c {
                '\n' => "a\nb",
                '\t' => "a b",
                '\u{1b}' | '\u{9b}' => "a",
                _ => "a\u{fffd}b",
            };
            assert_eq!(texte(&format!("a{c}b")), attendu, "U+{:04X}", u32::from(c));
        }
        for c in chaque(&espace) {
            assert_eq!(rendu(c), Some(' '), "U+{:04X}", u32::from(c));
        }
        for c in chaque(&selecteur) {
            assert_eq!(rendu(c), None, "U+{:04X}", u32::from(c));
        }
    }

    /// P1 : la fenêtre ne montre tel quel que ce que ses polices dessinent. Un caractère de format hors des listes
    /// du terminal, un point non attribué, un caractère privé, un signe dont la police n'a qu'un contour vide, un
    /// signe absent des polices (case vide, ou rien du tout quand egui le fond dans la grappe d'avant : deux jamos
    /// coréens) deviennent « � ».
    #[test]
    fn ce_qui_ne_se_dessine_pas_se_voit() {
        for c in [
            '\u{2065}',
            '\u{1d173}',
            '\u{110bd}',
            '\u{13430}',
            '\u{378}',
            '\u{e000}',
            '\u{f8ff}',
            '\u{f0000}',
            '\u{16910}',
            '\u{ff9e}',
            '\u{1f3fb}',
            '\u{1100}',
            '\u{1161}',
            '\u{6f22}',
            '\u{1f642}',
            '\u{2714}',
        ] {
            assert_eq!(dessin(c), Dessin::Rien, "U+{:04X}", u32::from(c));
            assert_eq!(ligne(&format!("Sa{c}lon")), "Sa\u{fffd}lon", "U+{:04X}", u32::from(c));
        }
        assert_eq!(ligne("\u{1100}\u{1161}"), "\u{fffd}\u{fffd}");
        // Une espace et un caractère sans largeur en alternance : chaque caractère se voit, et les espaces restent seules.
        let piege = " \u{2065}".repeat(1500);
        let vu = ligne_entiere(&piege);
        assert_eq!(vu, " \u{fffd}".repeat(1500));
        assert!(!vu.contains("  "));
        // Ce qui se dessine passe : lettres de trois alphabets, accents précomposés, symboles et le « � » lui-même.
        for c in "aZé0€«»’…ΩЖ✓→─\u{fffd}".chars() {
            assert_eq!(dessin(c), Dessin::Encre, "U+{:04X}", u32::from(c));
        }
        assert_eq!(dessin(' '), Dessin::Blanc);
        assert_eq!(dessin('\u{fe0f}'), Dessin::Retire);
    }

    /// P1 : une marque combinante n'est gardée que si les polices la dessinent, sur un signe dessiné, deux au plus et
    /// pas deux fois la même ; sinon « � ». Le français et le vietnamien écrits décomposés restent lisibles.
    #[test]
    fn une_marque_ne_se_pose_que_sur_un_signe() {
        assert_eq!(ligne("e\u{301}te\u{301}"), "e\u{301}te\u{301}");
        assert_eq!(ligne("Vie\u{323}\u{302}t"), "Vie\u{323}\u{302}t");
        assert_eq!(ligne("c\u{327}a"), "c\u{327}a");
        // Seule, au début, sur une espace ou après un saut de ligne : rien pour la porter.
        assert_eq!(ligne("\u{301}a"), "\u{fffd}a");
        assert_eq!(ligne("a \u{301}b"), "a \u{fffd}b");
        assert_eq!(texte("a\n\u{301}b"), "a\n\u{fffd}b");
        // Deux fois la même (la seconde, à la même place, ne se verrait pas) ; une troisième.
        assert_eq!(ligne("e\u{301}\u{301}"), "e\u{301}\u{fffd}");
        assert_eq!(ligne("e\u{301}\u{300}\u{302}"), "e\u{301}\u{300}\u{fffd}");
        // Une marque que les polices ne dessinent pas, ou qui recouvre la lettre, et une marque englobante.
        for m in ['\u{305}', '\u{338}', '\u{20dd}', '\u{94d}', '\u{e31}', '\u{1ab0}'] {
            assert_eq!(dessin(m), Dessin::Rien, "U+{:04X}", u32::from(m));
            assert_eq!(ligne(&format!("e{m}")), "e\u{fffd}", "U+{:04X}", u32::from(m));
        }
        // Une marque peut se poser sur le « � » d'un caractère remplacé : le remplacement se voit déjà.
        assert_eq!(ligne("\u{200b}\u{301}"), "\u{fffd}\u{301}");
        // Un sélecteur retiré entre la lettre et sa marque ne change rien.
        assert_eq!(ligne("e\u{fe0e}\u{301}"), "e\u{301}");
    }

    /// F4 et P1 : un texte lisible a au moins une lettre ou un chiffre dessiné ; des espaces, des séquences, des
    /// invisibles, des marques seules, des caractères que les polices ne dessinent pas, ou seulement des signes qui
    /// imitent un blanc ou un remplacement (Fable n° 3, A6) n'en font pas un.
    #[test]
    fn un_texte_lisible_a_un_signe_dessine() {
        for t in [
            "",
            "   ",
            "\u{3000}\t",
            "\u{200b}\u{2065}",
            "\u{1b}[2K",
            "\u{301}\u{302}",
            "\u{fe0f}",
            "\u{e000}",
            "\u{6f22}\u{1100}",
            "\n\r",
            // Vérification de Fable n° 3, A6 : des signes qui ont de l'encre, mais pas une lettre ni un chiffre.
            "\u{fffd}",
            "\u{2420}",
            "\u{2d9}",
            "\u{fffd} \u{2420}\u{2d9}",
            "-- |",
        ] {
            assert!(!lisible(t), "{t:?}");
        }
        for t in [
            "a",
            " x ",
            "7",
            "\u{fffd}a",
            "\u{1b}[1mOK\u{1b}[0m",
            "\u{200b}é",
            "Ж",
            "Ω",
        ] {
            assert!(lisible(t), "{t:?}");
        }
    }

    /// Comme dans le terminal : un sélecteur de variante retiré (sans colonne de plus), un invisible rare en « � ».
    /// Le sélecteur des émojis est retiré aussi (le terminal le garde) : les polices de la fenêtre n'ont pas d'émoji.
    /// Ce qui est montré se montre tel quel.
    #[test]
    fn selecteurs_retires_et_invisibles_rares_visibles() {
        assert_eq!(ligne("Ж\u{e0100}Ω.pdf"), "ЖΩ.pdf");
        assert_eq!(nom("fac\u{206b}ture.pdf", 80), "fac\u{fffd}ture.pdf");
        assert_eq!(texte("a\u{fe0e}\u{fff9}\nb\u{fe0f}"), "a\u{fffd}\nb");
        assert_eq!(ligne("ж\u{180b}ω\u{17b4}"), "жω\u{fffd}");
        // Les sélecteurs ne comptent pas dans la borne : ils sont retirés avant de couper.
        let long = "x\u{fe00}".repeat(LIGNE_MAX);
        assert_eq!(ligne(&long), "x".repeat(LIGNE_MAX));
        for c in (0..=u32::from(char::MAX)).filter_map(char::from_u32) {
            assert!(!(selecteur(c) || invisible_rare(c)) || !(piege(c) || espace_trompeur(c)));
            if let Some(r) = rendu(c) {
                assert_eq!(rendu(r), Some(r), "U+{:04X}", u32::from(c));
            }
        }
        // La liste des signes dessinés est triée, sans chevauchement : la recherche par moitiés en dépend.
        assert!(ENCRE.iter().all(|&(a, b)| a <= b));
        assert!(ENCRE.windows(2).all(|p| p[0].1 < p[1].0));
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

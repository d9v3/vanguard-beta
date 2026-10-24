//! Les valeurs de substitution mises en texte, d'après la table des types de [MS-EVEN6] 2.2.12 (« Value Types »)
//! et leurs formes canoniques (3.1.4.7.3, 2.2.12.3), complétées par la documentation de libyal pour ce que le
//! fichier fait autrement (booléens sur 32 bits). Une valeur d'un type inconnu, ou d'une taille impossible pour son
//! type, est rendue « inconnu » et comptée : jamais une erreur qui ferait perdre l'enregistrement.

use chrono::{DateTime, Datelike, Timelike, Utc};

/// Le texte d'une valeur qui n'a pas pu être lue.
pub(crate) const INCONNU: &str = "inconnu";

/// Ce que le rendu d'une valeur a dû approximer.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Compte {
    pub inconnue: bool,
    pub tronquee: bool,
}

/// Un texte borné à `max` caractères : au-delà, la suite est perdue et c'est dit.
struct Texte {
    contenu: String,
    caracteres: usize,
    max: usize,
    tronque: bool,
}

impl Texte {
    fn new(max: usize) -> Self {
        Self {
            contenu: String::new(),
            caracteres: 0,
            max,
            tronque: false,
        }
    }

    fn pousser(&mut self, c: char) {
        if self.caracteres >= self.max {
            self.tronque = true;
            return;
        }
        self.caracteres += 1;
        self.contenu.push(c);
    }
}

/// De l'UTF-16 petit-boutiste en texte, au plus `max` caractères ; un demi-caractère orphelin devient U+FFFD (le
/// caractère piégé, lui, est gardé : son nettoyage se fait à l'affichage). Les zéros de fin, que Windows laisse
/// souvent dans la valeur, sont ôtés. Rend aussi si la chaîne a été coupée.
pub(crate) fn utf16(octets: &[u8], max: usize) -> (String, bool) {
    let mut unites: Vec<u16> = octets
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_le_bytes(*b))
        .collect();
    while unites.last() == Some(&0) {
        unites.pop();
    }
    let mut t = Texte::new(max);
    for c in char::decode_utf16(unites) {
        t.pousser(c.unwrap_or('\u{FFFD}'));
        if t.tronque {
            break;
        }
    }
    (t.contenu, t.tronque)
}

/// Une chaîne d'une page de code inconnue (AnsiStringType) : l'ASCII tel quel, le reste lu comme Latin-1, jusqu'au
/// premier zéro.
fn ansi(octets: &[u8], max: usize) -> (String, bool) {
    let mut t = Texte::new(max);
    for &b in octets.iter().take_while(|&&b| b != 0) {
        t.pousser(char::from(b));
        if t.tronque {
            break;
        }
    }
    (t.contenu, t.tronque)
}

fn tableau_fixe<const N: usize>(octets: &[u8]) -> Option<[u8; N]> {
    octets.try_into().ok()
}

/// Une valeur seule ([MS-EVEN6] 2.2.12.3 pour les formes : entiers en décimal, « 0x » et hexadécimal pour HexInt et
/// SizeT, GUID entre accolades, dates en UTC).
pub(crate) fn scalaire(type_valeur: u8, octets: &[u8], max: usize) -> (String, Compte) {
    let mut compte = Compte::default();
    let texte = match type_valeur {
        0x01 => {
            let (t, coupe) = utf16(octets, max);
            compte.tronquee = coupe;
            Some(t)
        }
        0x02 => {
            let (t, coupe) = ansi(octets, max);
            compte.tronquee = coupe;
            Some(t)
        }
        0x0E => {
            let (t, coupe) = hexadecimal(octets, max);
            compte.tronquee = coupe;
            Some(t)
        }
        0x13 => sid(octets).filter(|&(_, lu)| lu == octets.len()).map(|(t, _)| t),
        t => fixe(t, octets),
    };
    if let Some(t) = texte {
        (t, compte)
    } else {
        compte.inconnue = true;
        (INCONNU.to_string(), compte)
    }
}

/// Les types de taille fixe : rien si la taille ne va pas avec le type, ou si le type est inconnu.
fn fixe(type_valeur: u8, o: &[u8]) -> Option<String> {
    Some(match type_valeur {
        0x03 => i8::from_le_bytes(tableau_fixe(o)?).to_string(),
        0x04 => u8::from_le_bytes(tableau_fixe(o)?).to_string(),
        0x05 => i16::from_le_bytes(tableau_fixe(o)?).to_string(),
        0x06 => u16::from_le_bytes(tableau_fixe(o)?).to_string(),
        0x07 => i32::from_le_bytes(tableau_fixe(o)?).to_string(),
        0x08 => u32::from_le_bytes(tableau_fixe(o)?).to_string(),
        0x09 => i64::from_le_bytes(tableau_fixe(o)?).to_string(),
        0x0A => u64::from_le_bytes(tableau_fixe(o)?).to_string(),
        0x0B => f32::from_le_bytes(tableau_fixe(o)?).to_string(),
        0x0C => f64::from_le_bytes(tableau_fixe(o)?).to_string(),
        // Un octet selon [MS-EVEN6], quatre dans les fichiers selon libyal : toute taille de 1 à 8 octets. 0 et 1
        // seulement sont permis ([MS-EVEN6] 3.1.4.7.3) ; une autre valeur (vue dans de vrais journaux) est rendue
        // telle quelle, en décimal, plutôt que « true » qui la cacherait.
        0x0D if (1..=8).contains(&o.len()) => {
            let n = o.iter().rev().fold(0u64, |n, &b| (n << 8) | u64::from(b));
            match n {
                0 => "false".to_string(),
                1 => "true".to_string(),
                n => n.to_string(),
            }
        }
        0x0F => guid(tableau_fixe(o)?),
        0x10 if o.len() == 4 => format!("{:#x}", u32::from_le_bytes(tableau_fixe(o)?)),
        0x10 | 0x15 => format!("{:#x}", u64::from_le_bytes(tableau_fixe(o)?)),
        0x11 => date(filetime(u64::from_le_bytes(tableau_fixe(o)?))?),
        0x12 => systemtime(tableau_fixe(o)?),
        0x14 => format!("{:#x}", u32::from_le_bytes(tableau_fixe(o)?)),
        _ => return None,
    })
}

/// Un tableau ([MS-EVEN6] 3.1.4.7.5), case par case : chaînes séparées par leur zéro final, SID qui disent
/// eux-mêmes leur taille, types fixes découpés à leur taille. Ce qui reste d'une case incomplète est compté.
pub(crate) fn tableau(type_valeur: u8, octets: &[u8], max: usize) -> (Vec<String>, Compte) {
    let mut compte = Compte::default();
    let base = type_valeur & 0x7F;
    let mut cases = Vec::new();
    match base {
        0x01 => {
            for morceau in octets.as_chunks::<2>().0.split(|u| *u == [0u8, 0]) {
                let octets: Vec<u8> = morceau.iter().flatten().copied().collect();
                let (t, coupe) = utf16(&octets, max);
                compte.tronquee |= coupe;
                cases.push(t);
            }
            // Le zéro final de la dernière chaîne laisse une case vide derrière lui.
            if octets.len() >= 2 && cases.last().is_some_and(String::is_empty) {
                cases.pop();
            }
            compte.inconnue = !octets.len().is_multiple_of(2);
        }
        0x02 => {
            for morceau in octets.split(|&b| b == 0) {
                let (t, coupe) = ansi(morceau, max);
                compte.tronquee |= coupe;
                cases.push(t);
            }
            if !octets.is_empty() && cases.last().is_some_and(String::is_empty) {
                cases.pop();
            }
        }
        0x13 => {
            let mut reste = octets;
            while !reste.is_empty() {
                let Some((t, lu)) = sid(reste) else {
                    compte.inconnue = true;
                    break;
                };
                cases.push(t);
                reste = reste.get(lu..).unwrap_or_default();
            }
        }
        _ => {
            // SizeT : 32 ou 64 bits selon le Windows qui a écrit ; la taille du tout tranche quand elle le peut, et les
            // cases se lisent alors comme les HexInt de cette taille.
            let base = match base {
                0x10 if octets.len().is_multiple_of(8) => 0x15,
                0x10 => 0x14,
                b => b,
            };
            let taille = match base {
                0x03 | 0x04 => 1,
                0x05 | 0x06 => 2,
                // Les booléens d'un tableau : quatre octets chacun (libyal), comme les entiers de 32 bits.
                0x07 | 0x08 | 0x0B | 0x0D | 0x14 => 4,
                0x09 | 0x0A | 0x0C | 0x11 | 0x15 => 8,
                0x0F | 0x12 => 16,
                _ => {
                    compte.inconnue = true;
                    return (vec![INCONNU.to_string()], compte);
                }
            };
            for case in octets.chunks(taille) {
                if let Some(t) = fixe(base, case) {
                    cases.push(t);
                } else {
                    compte.inconnue = true;
                    cases.push(INCONNU.to_string());
                }
            }
        }
    }
    (cases, compte)
}

/// Des octets en hexadécimal majuscule, collés comme dans le XML de l'Observateur d'événements, au plus `max`
/// caractères.
fn hexadecimal(octets: &[u8], max: usize) -> (String, bool) {
    const CHIFFRES: &[u8; 16] = b"0123456789ABCDEF";
    let mut t = Texte::new(max);
    for &b in octets {
        t.pousser(char::from(CHIFFRES[usize::from(b >> 4)]));
        t.pousser(char::from(CHIFFRES[usize::from(b & 0x0F)]));
        if t.tronque {
            break;
        }
    }
    (t.contenu, t.tronque)
}

/// Un GUID : Data1, Data2, Data3 petit-boutistes, Data4 dans l'ordre ([MS-DTYP] 2.3.4), entre accolades.
fn guid(o: [u8; 16]) -> String {
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        u32::from_le_bytes([o[0], o[1], o[2], o[3]]),
        u16::from_le_bytes([o[4], o[5]]),
        u16::from_le_bytes([o[6], o[7]]),
        o[8],
        o[9],
        o[10],
        o[11],
        o[12],
        o[13],
        o[14],
        o[15]
    )
}

/// Un SID binaire ([MS-DTYP] 2.4.2.2 : révision, nombre de sous-autorités, autorité sur 6 octets gros-boutistes,
/// sous-autorités sur 4 octets petit-boutistes) en texte « S-1-5-… » ([MS-DTYP] 2.4.2.1 : autorité en décimal sous
/// 2^32, en hexadécimal au-delà), et la place qu'il occupe.
fn sid(o: &[u8]) -> Option<(String, usize)> {
    let revision = *o.first()?;
    let nombre = usize::from(*o.get(1)?);
    let longueur = 8 + 4 * nombre;
    let octets = o.get(..longueur)?;
    let autorite = octets[2..8].iter().fold(0u64, |a, &b| (a << 8) | u64::from(b));
    let mut texte = if autorite < 1 << 32 {
        format!("S-{revision}-{autorite}")
    } else {
        format!("S-{revision}-0x{autorite:012X}")
    };
    for s in octets[8..].as_chunks::<4>().0 {
        texte.push('-');
        texte.push_str(&u32::from_le_bytes(*s).to_string());
    }
    Some((texte, longueur))
}

/// Un FILETIME (centaines de nanosecondes depuis le 1er janvier 1601, UTC) en date ; rien hors de ce que chrono
/// sait représenter.
pub(crate) fn filetime(valeur: u64) -> Option<DateTime<Utc>> {
    const DE_1601_A_1970: i64 = 11_644_473_600;
    let secondes = i64::try_from(valeur / 10_000_000).ok()?.checked_sub(DE_1601_A_1970)?;
    let nanos = u32::try_from(valeur % 10_000_000).ok()? * 100;
    DateTime::from_timestamp(secondes, nanos)
}

/// Une date en texte RFC 3339 à la centaine de nanosecondes, la précision d'un FILETIME (la forme de [MS-EVEN6]
/// 2.2.12.3 s'arrête aux millisecondes : la suite perdue servirait pourtant à ordonner deux événements voisins).
pub(crate) fn date(d: DateTime<Utc>) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:07}Z",
        d.year(),
        d.month(),
        d.day(),
        d.hour(),
        d.minute(),
        d.second(),
        d.nanosecond() / 100
    )
}

/// Un SYSTEMTIME ([MS-DTYP] 2.3.13 : année, mois, jour de la semaine, jour, heure, minute, seconde, milliseconde,
/// sur 16 bits chacun), écrit tel quel : pas de calendrier à vérifier, c'est un texte.
fn systemtime(o: [u8; 16]) -> String {
    let champ = |i: usize| u16::from_le_bytes([o[2 * i], o[2 * i + 1]]);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        champ(0),
        champ(1),
        champ(3),
        champ(4),
        champ(5),
        champ(6),
        champ(7)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn les_types_courants_ont_leur_forme() {
        assert_eq!(scalaire(0x01, &[b'a', 0, b'b', 0, 0, 0], 100).0, "ab");
        assert_eq!(scalaire(0x08, &7u32.to_le_bytes(), 100).0, "7");
        assert_eq!(scalaire(0x03, &[0xFF], 100).0, "-1");
        assert_eq!(scalaire(0x14, &0x12u32.to_le_bytes(), 100).0, "0x12");
        assert_eq!(
            scalaire(0x15, &0x8020_0000_0000_0000u64.to_le_bytes(), 100).0,
            "0x8020000000000000"
        );
        assert_eq!(scalaire(0x0D, &1u32.to_le_bytes(), 100).0, "true");
        assert_eq!(scalaire(0x0D, &[0], 100).0, "false");
        assert_eq!(scalaire(0x0D, &16u32.to_le_bytes(), 100).0, "16");
        assert_eq!(scalaire(0x0E, &[0xDE, 0xAD, 0x01], 100).0, "DEAD01");
        // Le GUID du fournisseur Microsoft-Windows-Security-Auditing, tel que Windows l'écrit.
        let g = [
            0x25, 0x96, 0x84, 0x54, 0x78, 0x54, 0x94, 0x49, 0xA5, 0xBA, 0x3E, 0x3B, 0x03, 0x28, 0xC3, 0x0D,
        ];
        assert_eq!(scalaire(0x0F, &g, 100).0, "{54849625-5478-4994-A5BA-3E3B0328C30D}");
        // S-1-5-21-1-2-3-1001
        let mut s = vec![1, 5, 0, 0, 0, 0, 0, 5];
        for v in [21u32, 1, 2, 3, 1001] {
            s.extend(v.to_le_bytes());
        }
        assert_eq!(scalaire(0x13, &s, 100).0, "S-1-5-21-1-2-3-1001");
        // 1er janvier 1970 en FILETIME.
        assert_eq!(
            scalaire(0x11, &116_444_736_000_000_000u64.to_le_bytes(), 100).0,
            "1970-01-01T00:00:00.0000000Z"
        );
        let mut st = Vec::new();
        for v in [2026u16, 10, 6, 24, 13, 5, 9, 42] {
            st.extend(v.to_le_bytes());
        }
        assert_eq!(scalaire(0x12, &st, 100).0, "2026-10-24T13:05:09.042Z");
    }

    #[test]
    fn un_type_inconnu_ou_une_taille_fausse_se_disent() {
        let (t, c) = scalaire(0x20, &[1, 2, 3], 100);
        assert_eq!((t.as_str(), c.inconnue), (INCONNU, true));
        let (t, c) = scalaire(0x08, &[1, 2, 3], 100);
        assert_eq!((t.as_str(), c.inconnue), (INCONNU, true));
        let (_, c) = scalaire(0x13, &[1, 9, 0], 100);
        assert!(c.inconnue);
        let (cases, c) = tableau(0x88, &[1, 0, 0, 0, 2, 0], 100);
        assert_eq!(cases, ["1", INCONNU]);
        assert!(c.inconnue);
    }

    #[test]
    fn les_tableaux_se_decoupent() {
        let chaines: Vec<u8> = "un\0deux\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(tableau(0x81, &chaines, 100).0, ["un", "deux"]);
        assert_eq!(tableau(0x84, &[1, 2, 3], 100).0, ["1", "2", "3"]);
        assert_eq!(tableau(0x82, b"a\0bc\0", 100).0, ["a", "bc"]);
        // Un tableau vide : une seule case vide, que l'élément répété rendra une fois ([MS-EVEN6] 3.1.4.7.5).
        assert_eq!(tableau(0x81, &[], 100).0, [""]);
    }

    #[test]
    fn les_chaines_sont_bornees_et_le_disent() {
        let long: Vec<u8> = "abcdef".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let (t, c) = scalaire(0x01, &long, 3);
        assert_eq!((t.as_str(), c.tronquee), ("abc", true));
        let (t, c) = scalaire(0x0E, &[1, 2, 3, 4], 5);
        assert_eq!((t.as_str(), c.tronquee), ("01020", true));
        // Un demi-caractère orphelin ne fait pas échouer : U+FFFD à sa place.
        let (t, _) = utf16(&[0x00, 0xD8, b'a', 0], 10);
        assert_eq!(t, "\u{FFFD}a");
    }
}

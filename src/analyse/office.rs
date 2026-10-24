//! Ce que disent les documents Office au-delà de leurs macros VBA :
//! - Word 97-2003 ([MS-DOC] 2.5.2, FibBase) : wIdent 0xA5EC, et le bit fEncrypted (bit 8 du mot de drapeaux en 0x0A)
//!   d'un document chiffré ou obscurci ;
//! - Excel 97-2003 ([MS-XLS] 2.1.4, enregistrements : type et taille sur 16 bits) : FilePass (47) pour un classeur
//!   chiffré, BoundSheet8 (133) pour chaque feuille, son état masqué (hsState) et sa sorte (dt = 1 : feuille de
//!   macros Excel 4.0, « XLM »), lus dans le premier sous-flux (jusqu'à EOF, 10) ;
//! - OOXML ([MS-OFFMACRO2], ECMA-376) : dans [Content_Types].xml, les parties de macros (vbaProject,
//!   macroEnabled, macrosheet) et d'ActiveX ; dans les relations (.rels), celles qui sortent du document
//!   (TargetMode="External" : un modèle ou un objet chargé depuis ailleurs à l'ouverture).
//!
//! Des faits, lus bornés ; aucun verdict. Sans `crate::` (sauf `lecture`) : le banc de fuzzing l'inclut.

use super::lecture::u16le;

/// Le document Word est-il chiffré ou obscurci ? `None` : pas un FibBase de Word.
pub(crate) fn word_chiffre(word_document: &[u8]) -> Option<bool> {
    (u16le(word_document, 0)? == 0xA5EC).then_some(())?;
    Some(u16le(word_document, 0x0A)? & 0x0100 != 0)
}

/// Une feuille d'un classeur Excel 97-2003.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Feuille {
    pub nom: String,
    /// 0 visible, 1 masquée, 2 très masquée.
    pub masquage: u8,
    /// 0 feuille de calcul ou dialogue, 1 feuille de macros (XLM), 2 graphique, 6 module VBA.
    pub sorte: u8,
}

/// Ce que dit le sous-flux global d'un classeur.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Classeur {
    pub chiffre: bool,
    pub feuilles: Vec<Feuille>,
    /// Le sous-flux global ne se lit pas jusqu'à EOF.
    pub incomplet: bool,
}

const ENREGISTREMENTS_MAX: usize = 1 << 20;
const FEUILLES_MAX: usize = 4096;

/// Le flux « Workbook » (ou « Book ») d'un classeur.
pub(crate) fn classeur(flux: &[u8]) -> Classeur {
    let mut c = Classeur::default();
    let mut i = 0usize;
    for _ in 0..ENREGISTREMENTS_MAX {
        let (Some(type_), Some(taille)) = (u16le(flux, i), u16le(flux, i + 2)) else {
            c.incomplet = true;
            return c;
        };
        let taille = usize::from(taille);
        let Some(donnees) = flux.get(i + 4..i + 4 + taille) else {
            c.incomplet = true;
            return c;
        };
        i += 4 + taille;
        match type_ {
            // EOF : la fin du sous-flux global.
            0x000A => return c,
            0x002F => c.chiffre = true,
            0x0085 if c.feuilles.len() < FEUILLES_MAX && donnees.len() >= 8 => {
                // lbPlyPos (4), hsState (2 bits) et inutilisé, dt, puis ShortXLUnicodeString : cch, fHighByte.
                let masquage = donnees[4] & 0b11;
                let sorte = donnees[5];
                let n = usize::from(donnees[6]);
                let large = donnees[7] & 1 != 0;
                let nom = if large {
                    donnees
                        .get(8..8 + 2 * n)
                        .map(super::lecture::utf16le)
                        .unwrap_or_default()
                } else {
                    donnees
                        .get(8..8 + n)
                        .map(|b| b.iter().map(|&o| char::from(o)).collect())
                        .unwrap_or_default()
                };
                c.feuilles.push(Feuille { nom, masquage, sorte });
            }
            _ => {}
        }
    }
    c.incomplet = true;
    c
}

/// Ce que dit un [Content_Types].xml.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct TypesDeContenu {
    pub projet_vba: bool,
    pub macros_xlm: bool,
    pub activex: bool,
}

pub(crate) fn types_de_contenu(xml: &str) -> TypesDeContenu {
    // Les entités décodées d'abord : « vba&#80;roject » est le même type de contenu pour Office.
    let bas = entites(xml).to_ascii_lowercase();
    TypesDeContenu {
        projet_vba: bas.contains("application/vnd.ms-office.vbaproject"),
        macros_xlm: bas.contains("macrosheet+xml"),
        activex: bas.contains("application/vnd.ms-office.activex"),
    }
}

const RELATIONS_MAX: usize = 256;
/// Les éléments parcourus dans un fichier XML : au-delà, le reste n'est pas lu (`Xml::coupe`).
const ELEMENTS_MAX: usize = 1 << 16;

/// Le texte d'une partie XML, quel que soit son encodage : UTF-8 (avec ou sans marque), UTF-16 petit- ou
/// gros-boutiste (avec marque, ou reconnu à « < » suivi ou précédé d'un zéro), comme un lecteur XML le décode. Lu en
/// UTF-8, un .rels en UTF-16 cachait toutes ses relations.
pub(crate) fn texte_xml(octets: &[u8]) -> String {
    let utf16 = |o: &[u8], gros: bool| -> String {
        let mots: Vec<u16> = o
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| {
                if gros {
                    u16::from_be_bytes(*p)
                } else {
                    u16::from_le_bytes(*p)
                }
            })
            .collect();
        String::from_utf16_lossy(&mots)
    };
    match octets {
        [0xEF, 0xBB, 0xBF, reste @ ..] => String::from_utf8_lossy(reste).into_owned(),
        [0xFF, 0xFE, reste @ ..] => utf16(reste, false),
        [0xFE, 0xFF, reste @ ..] => utf16(reste, true),
        [b'<', 0, ..] => utf16(octets, false),
        [0, b'<', ..] => utf16(octets, true),
        _ => String::from_utf8_lossy(octets).into_owned(),
    }
}

/// Un élément XML ouvrant (ou vide) : son nom local (sans préfixe d'espace de noms) et ses attributs, valeurs
/// décodées (entités nommées et numériques).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Element {
    nom: String,
    attributs: Vec<(String, String)>,
}

/// Les éléments ouvrants de `xml`, lus comme un analyseur XML les lit : guillemets respectés (un « > » dans une
/// valeur ne ferme pas l'élément), commentaires, instructions, sections CDATA et déclarations sautés. Bornés à
/// `ELEMENTS_MAX` ; `true` en second : coupé à la borne.
fn elements(xml: &str) -> (Vec<Element>, bool) {
    let mut sortie = Vec::new();
    let mut reste = xml;
    while let Some(p) = reste.find('<') {
        if sortie.len() >= ELEMENTS_MAX {
            return (sortie, true);
        }
        reste = &reste[p + 1..];
        let sautee = [("!--", "-->"), ("![CDATA[", "]]>"), ("?", "?>"), ("!", ">")]
            .into_iter()
            .find(|(debut, _)| reste.starts_with(debut));
        if let Some((_, fin)) = sautee {
            reste = reste.find(fin).map_or("", |f| &reste[f + fin.len()..]);
            continue;
        }
        if reste.starts_with('/') || reste.is_empty() {
            continue;
        }
        let fin_nom = reste
            .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
            .unwrap_or(reste.len());
        let nom = reste[..fin_nom].rsplit(':').next().unwrap_or("").to_string();
        reste = &reste[fin_nom..];
        let mut attributs = Vec::new();
        loop {
            reste = reste.trim_start();
            if reste.is_empty() || reste.starts_with('>') || reste.starts_with("/>") {
                break;
            }
            let Some(egal) = reste.find('=') else {
                reste = "";
                break;
            };
            let cle = reste[..egal].trim().rsplit(':').next().unwrap_or("").to_string();
            let apres = reste[egal + 1..].trim_start();
            let Some(guillemet) = apres.chars().next().filter(|c| *c == '"' || *c == '\'') else {
                reste = apres;
                break;
            };
            let corps = &apres[1..];
            let Some(f) = corps.find(guillemet) else {
                reste = "";
                break;
            };
            attributs.push((cle, entites(&corps[..f])));
            reste = &corps[f + 1..];
        }
        sortie.push(Element { nom, attributs });
    }
    (sortie, false)
}

/// Les entités d'une valeur d'attribut : les cinq nommées de XML et les références numériques (« &#69; », « &#x45; »).
fn entites(valeur: &str) -> String {
    if !valeur.contains('&') {
        return valeur.to_string();
    }
    let mut sortie = String::with_capacity(valeur.len());
    let mut reste = valeur;
    while let Some(p) = reste.find('&') {
        sortie.push_str(&reste[..p]);
        reste = &reste[p..];
        let Some(fin) = reste.find(';').filter(|&f| f <= 12) else {
            sortie.push('&');
            reste = &reste[1..];
            continue;
        };
        let nom = &reste[1..fin];
        let caractere = match nom {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => nom
                .strip_prefix("#x")
                .or_else(|| nom.strip_prefix("#X"))
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .or_else(|| nom.strip_prefix('#').and_then(|d| d.parse().ok()))
                .and_then(char::from_u32),
        };
        if let Some(c) = caractere {
            sortie.push(c);
            reste = &reste[fin + 1..];
        } else {
            sortie.push('&');
            reste = &reste[1..];
        }
    }
    sortie.push_str(reste);
    sortie
}

/// Les cibles des relations vers l'extérieur (TargetMode="External") d'un fichier .rels : chaque élément
/// « Relationship », ses attributs Target et TargetMode, sans tenir compte de la casse des noms (ni de celle de
/// « External »), valeurs décodées. Un fichier coupé à la borne des éléments rend aussi `true`.
pub(crate) fn relations_externes(xml: &str) -> Vec<String> {
    relations_externes_bornees(xml).0
}

/// `relations_externes`, et si le fichier a été coupé à la borne des éléments (le reste n'est pas lu).
pub(crate) fn relations_externes_bornees(xml: &str) -> (Vec<String>, bool) {
    let (elements, coupe) = elements(xml);
    let mut cibles = Vec::new();
    for e in elements {
        if cibles.len() >= RELATIONS_MAX {
            return (cibles, true);
        }
        if !e.nom.eq_ignore_ascii_case("Relationship") {
            continue;
        }
        let valeur = |nom: &str| {
            e.attributs
                .iter()
                .find(|(c, _)| c.eq_ignore_ascii_case(nom))
                .map(|(_, v)| v.trim())
        };
        if valeur("TargetMode").is_some_and(|m| m.eq_ignore_ascii_case("External"))
            && let Some(cible) = valeur("Target")
        {
            cibles.push(cible.to_string());
        }
    }
    (cibles, coupe)
}

/// Le CLSID de la racine d'un paquet Windows Installer ({000C1084-0000-0000-C000-000000000046}, rangé comme le fait
/// un fichier composé : les trois premiers champs petit-boutistes).
pub(crate) const CLSID_MSI: [u8; 16] = [
    0x84, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

#[cfg(test)]
pub(crate) mod essais {
    /// Un sous-flux global d'Excel : BOF, éventuellement FilePass, des BoundSheet8 (nom, masquage, sorte), EOF.
    pub(crate) fn classeur(chiffre: bool, feuilles: &[(&str, u8, u8)]) -> Vec<u8> {
        let mut v = Vec::new();
        let mut enregistrement = |type_: u16, donnees: &[u8]| {
            v.extend(type_.to_le_bytes());
            v.extend(u16::try_from(donnees.len()).unwrap().to_le_bytes());
            v.extend(donnees);
        };
        enregistrement(0x0809, &[0, 6, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        if chiffre {
            enregistrement(0x002F, &[1, 0, 1, 0, 1, 0]);
        }
        for (nom, masquage, sorte) in feuilles {
            let mut d = vec![0u8; 4];
            d.push(*masquage);
            d.push(*sorte);
            d.push(u8::try_from(nom.len()).unwrap());
            d.push(0);
            d.extend(nom.as_bytes());
            enregistrement(0x0085, &d);
        }
        enregistrement(0x000A, &[]);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_et_excel() {
        let mut fib = vec![0u8; 32];
        fib[..2].copy_from_slice(&0xA5ECu16.to_le_bytes());
        assert_eq!(word_chiffre(&fib), Some(false));
        fib[0x0B] |= 1;
        assert_eq!(word_chiffre(&fib), Some(true));
        assert_eq!(word_chiffre(b"\0\0"), None);
        let c = classeur(&essais::classeur(false, &[("Feuil1", 0, 0), ("Macro1", 2, 1)]));
        assert!(!c.chiffre && !c.incomplet);
        assert_eq!(
            c.feuilles,
            [
                Feuille {
                    nom: "Feuil1".into(),
                    masquage: 0,
                    sorte: 0
                },
                Feuille {
                    nom: "Macro1".into(),
                    masquage: 2,
                    sorte: 1
                }
            ]
        );
        assert!(classeur(&essais::classeur(true, &[])).chiffre);
        let v = essais::classeur(false, &[("Feuil1", 0, 0)]);
        assert!(classeur(&v[..v.len() - 3]).incomplet);
    }

    #[test]
    fn ooxml() {
        let types = r#"<Types><Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/><Override ContentType="application/vnd.ms-excel.macrosheet+xml"/></Types>"#;
        assert_eq!(
            types_de_contenu(types),
            TypesDeContenu {
                projet_vba: true,
                macros_xlm: true,
                activex: false
            }
        );
        let rels = r#"<?xml version="1.0"?><Relationships xmlns="x"><Relationship Id="rId1" Type="t/attachedTemplate" Target="https://exemple.invalid/modele.dotm" TargetMode="External"/><Relationship Id="rId2" Target="styles.xml"/><Relationship TargetMode='External' Target='\\serveur\partage\a.dotm' Id="3"/></Relationships>"#;
        assert_eq!(
            relations_externes(rels),
            ["https://exemple.invalid/modele.dotm", "\\\\serveur\\partage\\a.dotm"]
        );
        assert_eq!(relations_externes("<Relationship Target="), Vec::<String>::new());
    }

    /// Les relations que la campagne d'attaque n° 3 cachait derrière un détail XML valide : un « > » dans une valeur
    /// placée avant TargetMode, une entité numérique dans « External », un .rels en UTF-16 ; et un commentaire qui
    /// contient une fausse relation ne compte pas.
    #[test]
    fn relations_cachees_par_le_xml() {
        let chevron = r#"<Relationships><Relationship Id="r1" Type="x/attachedTemplate" Target="https://exemple.invalid/m.dotm?a=>" TargetMode="External"/></Relationships>"#;
        assert_eq!(relations_externes(chevron), ["https://exemple.invalid/m.dotm?a=>"]);
        let reference = r#"<Relationships><Relationship Id="r1" Target="https://exemple.invalid/m.dotm" TargetMode="&#69;xternal"/><Relationship Target="&#x68;ttps://exemple.invalid/b" TargetMode="&#x45;xternal"/></Relationships>"#;
        assert_eq!(
            relations_externes(reference),
            ["https://exemple.invalid/m.dotm", "https://exemple.invalid/b"]
        );
        let normal = r#"<Relationships><Relationship Target="https://exemple.invalid/m.dotm" TargetMode="External"/></Relationships>"#;
        let mut utf16 = vec![0xFF, 0xFE];
        utf16.extend(normal.encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(
            relations_externes(&texte_xml(&utf16)),
            ["https://exemple.invalid/m.dotm"]
        );
        let gros: Vec<u8> = normal.encode_utf16().flat_map(u16::to_be_bytes).collect();
        assert_eq!(
            relations_externes(&texte_xml(&gros)),
            ["https://exemple.invalid/m.dotm"]
        );
        let mut bom = vec![0xEF, 0xBB, 0xBF];
        bom.extend(normal.as_bytes());
        assert_eq!(relations_externes(&texte_xml(&bom)), ["https://exemple.invalid/m.dotm"]);
        let commentaire = r#"<!-- <Relationship Target="https://faux.invalid" TargetMode="External"/> --><?xml version="1.0"?><x:Relationship xmlns:x="r" x:Target='&amp;b' x:TargetMode='EXTERNAL'/>"#;
        assert_eq!(relations_externes(commentaire), ["&b"]);
        // La borne des éléments : dit coupé.
        let enorme = "<a/>".repeat(ELEMENTS_MAX + 1);
        assert!(relations_externes_bornees(&enorme).1);
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 2000, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn jamais_de_plantage(octets in proptest::collection::vec(proptest::num::u8::ANY, 0..2000)) {
            let _ = classeur(&octets);
            let _ = word_chiffre(&octets);
            let texte = String::from_utf8_lossy(&octets);
            let _ = relations_externes(&texte);
            let _ = relations_externes(&texte_xml(&octets));
            let _ = types_de_contenu(&texte);
        }
    }
}

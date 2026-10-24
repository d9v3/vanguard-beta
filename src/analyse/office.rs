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
    let bas = xml.to_ascii_lowercase();
    TypesDeContenu {
        projet_vba: bas.contains("application/vnd.ms-office.vbaproject"),
        macros_xlm: bas.contains("macrosheet+xml"),
        activex: bas.contains("application/vnd.ms-office.activex"),
    }
}

const RELATIONS_MAX: usize = 256;

/// Les cibles des relations vers l'extérieur (TargetMode="External") d'un fichier .rels, lues sans analyseur XML :
/// chaque élément « <Relationship … /> », ses attributs Target et TargetMode.
pub(crate) fn relations_externes(xml: &str) -> Vec<String> {
    let mut cibles = Vec::new();
    for element in xml.split('<').skip(1) {
        if cibles.len() >= RELATIONS_MAX {
            break;
        }
        let element = element.split('>').next().unwrap_or("");
        let nom = element.split_whitespace().next().unwrap_or("");
        if !nom
            .rsplit(':')
            .next()
            .unwrap_or("")
            .eq_ignore_ascii_case("Relationship")
        {
            continue;
        }
        let externe = attribut(element, "TargetMode").is_some_and(|m| m.eq_ignore_ascii_case("External"));
        if externe && let Some(cible) = attribut(element, "Target") {
            cibles.push(cible.to_string());
        }
    }
    cibles
}

/// La valeur de l'attribut `nom` (entre guillemets simples ou doubles) d'un élément.
fn attribut<'a>(element: &'a str, nom: &str) -> Option<&'a str> {
    let mut reste = element;
    while let Some(p) = reste.find(nom) {
        let avant = reste[..p].chars().next_back();
        let apres = reste[p + nom.len()..].trim_start();
        reste = &reste[p + nom.len()..];
        if !avant.is_some_and(char::is_whitespace) {
            continue;
        }
        let Some(valeur) = apres.strip_prefix('=') else {
            continue;
        };
        let valeur = valeur.trim_start();
        let guillemet = valeur.chars().next()?;
        if guillemet != '"' && guillemet != '\'' {
            continue;
        }
        let corps = &valeur[1..];
        return corps.find(guillemet).map(|f| &corps[..f]);
    }
    None
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

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 2000, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn jamais_de_plantage(octets in proptest::collection::vec(proptest::num::u8::ANY, 0..2000)) {
            let _ = classeur(&octets);
            let _ = word_chiffre(&octets);
            let texte = String::from_utf8_lossy(&octets);
            let _ = relations_externes(&texte);
            let _ = types_de_contenu(&texte);
        }
    }
}

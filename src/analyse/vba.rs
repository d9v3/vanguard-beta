//! Le flux « dir » d'un projet VBA ([MS-OVBA] 2.3.4.2), une fois décompressé : une suite d'enregistrements
//! (identifiant de 16 bits, taille de 32 bits, données), sauf PROJECTVERSION (0x0009), dont le champ « Reserved »
//! vaut 4 alors que 6 octets suivent. On en tire la page de code (PROJECTCODEPAGE, 0x0003) et chaque module :
//! MODULENAME (0x0019) et sa forme Unicode (0x0047), MODULESTREAMNAME (0x001A, puis 0x0032 en Unicode), MODULEOFFSET
//! (0x0031 : où commence la source compressée dans le flux du module), MODULETYPE (0x0021 procédural, 0x0022 document
//! ou classe), jusqu'à son terminateur (0x002B). Fin du flux : 0x0010.
//!
//! Puis, dans la source d'un module, les procédures qui se lancent toutes seules : macros « auto » de Word (AutoOpen,
//! AutoExec, AutoNew, AutoClose, AutoExit ; documentation « Auto Macros » de Microsoft : aussi un module de ce nom qui
//! a une procédure Main), événements des documents et classeurs (Document_Open, Workbook_Open, Auto_Open…), et
//! événements de contrôles ActiveX qui se déclenchent au dessin (…_Layout, …_Painted, …_Resize). Un FAIT pour les
//! heuristiques (AV4), pas un verdict.
//!
//! Lecteur pur, sans `crate::` : le banc de fuzzing l'inclut par son chemin.

use super::lecture::{latin1_ou_utf8, tranche, u16le, u32le, utf16le};

const MODULES_MAX: usize = 4096;
const ENREGISTREMENTS_MAX: usize = 200_000;

/// Un module du projet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Module {
    pub nom: String,
    /// Le nom du flux qui porte le module, dans le stockage « VBA ».
    pub flux: String,
    /// Où commence la source compressée dans ce flux.
    pub decalage: u32,
    /// 0x0021 : module de code ; 0x0022 : document, feuille ou classe.
    pub type_: Option<u16>,
}

/// Ce que dit le flux « dir ».
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Projet {
    pub code_page: Option<u16>,
    pub nom: Option<String>,
    /// Le nombre de modules annoncé par PROJECTMODULES.
    pub annonces: Option<u16>,
    pub modules: Vec<Module>,
    /// Le flux ne se lit pas jusqu'à son terminateur (coupé, enregistrement qui déborde).
    pub incomplet: bool,
}

/// Le flux « dir » décompressé.
pub(crate) fn lire_dir(dir: &[u8]) -> Projet {
    let mut p = Projet::default();
    let mut i = 0usize;
    let mut module: Option<Module> = None;
    for _ in 0..ENREGISTREMENTS_MAX {
        let Some(id) = u16le(dir, i) else {
            p.incomplet = true;
            break;
        };
        if id == 0x0009 {
            // PROJECTVERSION : Reserved (4), VersionMajor (4), VersionMinor (2).
            i += 2 + 4 + 4 + 2;
            continue;
        }
        let Some(taille) = u32le(dir, i + 2).map(|t| t as usize) else {
            p.incomplet = true;
            break;
        };
        let Some(donnees) = tranche(dir, i + 6, taille) else {
            p.incomplet = true;
            break;
        };
        i += 6 + taille;
        match id {
            0x0003 => p.code_page = u16le(donnees, 0),
            0x0004 => p.nom = Some(latin1_ou_utf8(donnees)),
            0x000F => p.annonces = u16le(donnees, 0),
            0x0019 => {
                if let Some(m) = module.take() {
                    pousser(&mut p, m);
                }
                module = Some(Module {
                    nom: latin1_ou_utf8(donnees),
                    ..Module::default()
                });
            }
            0x0047 => {
                if let Some(m) = module.as_mut() {
                    m.nom = utf16le(donnees);
                }
            }
            0x001A => {
                if let Some(m) = module.as_mut() {
                    m.flux = latin1_ou_utf8(donnees);
                }
            }
            0x0032 => {
                if let Some(m) = module.as_mut().filter(|_| !donnees.is_empty()) {
                    m.flux = utf16le(donnees);
                }
            }
            0x0031 => {
                if let (Some(m), Some(d)) = (module.as_mut(), u32le(donnees, 0)) {
                    m.decalage = d;
                }
            }
            0x0021 | 0x0022 => {
                if let Some(m) = module.as_mut() {
                    m.type_ = Some(id);
                }
            }
            0x002B => {
                if let Some(m) = module.take() {
                    pousser(&mut p, m);
                }
            }
            0x0010 => {
                if let Some(m) = module.take() {
                    pousser(&mut p, m);
                }
                return p;
            }
            _ => {}
        }
    }
    if let Some(m) = module.take() {
        pousser(&mut p, m);
    }
    p.incomplet = true;
    p
}

fn pousser(p: &mut Projet, m: Module) {
    if p.modules.len() < MODULES_MAX {
        p.modules.push(m);
    } else {
        p.incomplet = true;
    }
}

/// Les macros « auto » de Word.
const AUTO_WORD: &[&str] = &["autoexec", "autoopen", "autonew", "autoclose", "autoexit"];

/// Les procédures que Word, Excel ou PowerPoint lancent d'eux-mêmes (ouverture, fermeture, activation).
const AUTOMATIQUES: &[&str] = &[
    "autoexec",
    "autoopen",
    "autonew",
    "autoclose",
    "autoexit",
    "auto_open",
    "auto_close",
    "auto_exec",
    "document_open",
    "document_close",
    "document_new",
    "document_contentcontrolonenter",
    "documentopen",
    "documentbeforeclose",
    "workbook_open",
    "workbook_activate",
    "workbook_beforeclose",
    "workbook_windowactivate",
    "app_documentopen",
    "app_newdocument",
    "app_workbookopen",
    "app_presentationopen",
];

/// Les événements de contrôles ActiveX qui se déclenchent dès l'affichage, sans clic.
const SUFFIXES_DE_CONTROLE: &[&str] = &["_layout", "_painted", "_resize", "_gotfocus", "_initialize"];

/// Les procédures de `source` (un module VBA) qui se lancent d'elles-mêmes, par leur déclaration (« Sub AutoOpen() »,
/// « Private Sub Document_Open() »), sans tenir compte de la casse ; les commentaires et les chaînes ne comptent pas.
/// Avec `nom_module` : un module nommé comme une macro auto de Word avec une procédure Main.
pub(crate) fn procedures_automatiques(source: &str, nom_module: &str) -> Vec<String> {
    let mut trouvees = Vec::new();
    let module_auto = AUTO_WORD.contains(&nom_module.to_ascii_lowercase().as_str());
    for ligne in source.lines() {
        let Some(nom) = procedure_declaree(ligne) else {
            continue;
        };
        let bas = nom.to_ascii_lowercase();
        let automatique = AUTOMATIQUES.contains(&bas.as_str())
            || SUFFIXES_DE_CONTROLE
                .iter()
                .any(|s| bas.len() > s.len() && bas.ends_with(s))
            || (module_auto && bas == "main");
        if automatique && !trouvees.iter().any(|t: &String| t.eq_ignore_ascii_case(nom)) {
            trouvees.push(nom.to_string());
        }
    }
    trouvees
}

/// Le nom d'une procédure déclarée sur `ligne` (« [Public|Private|Friend] [Static] Sub|Function Nom(… »).
fn procedure_declaree(ligne: &str) -> Option<&str> {
    let mut mots = ligne.split_whitespace().peekable();
    let mut mot = mots.next()?;
    for prefixe in ["public", "private", "friend", "static"] {
        if mot.eq_ignore_ascii_case(prefixe) {
            mot = mots.next()?;
        }
    }
    if mot.eq_ignore_ascii_case("static") {
        mot = mots.next()?;
    }
    if !(mot.eq_ignore_ascii_case("sub") || mot.eq_ignore_ascii_case("function")) {
        return None;
    }
    let reste = mots.next()?;
    let fin = reste
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(reste.len());
    (fin > 0).then(|| &reste[..fin])
}

#[cfg(test)]
pub(crate) mod essais {
    //! Un flux « dir » fabriqué ici (décompressé), avec les enregistrements obligatoires dans l'ordre de la
    //! spécification.

    fn enregistrement(v: &mut Vec<u8>, id: u16, donnees: &[u8]) {
        v.extend(id.to_le_bytes());
        v.extend(u32::try_from(donnees.len()).unwrap().to_le_bytes());
        v.extend(donnees);
    }

    /// Un flux « dir » pour `modules` : (nom, nom du flux, décalage de la source, type 0x21 ou 0x22).
    pub(crate) fn dir(modules: &[(&str, &str, u32, u16)]) -> Vec<u8> {
        let mut v = Vec::new();
        enregistrement(&mut v, 0x0001, &1u32.to_le_bytes());
        enregistrement(&mut v, 0x0002, &0x409u32.to_le_bytes());
        enregistrement(&mut v, 0x0014, &0x409u32.to_le_bytes());
        enregistrement(&mut v, 0x0003, &1252u16.to_le_bytes());
        enregistrement(&mut v, 0x0004, b"Projet");
        enregistrement(&mut v, 0x0005, b"");
        enregistrement(&mut v, 0x0040, b"");
        enregistrement(&mut v, 0x0006, b"");
        enregistrement(&mut v, 0x003D, b"");
        enregistrement(&mut v, 0x0007, &0u32.to_le_bytes());
        enregistrement(&mut v, 0x0008, &0u32.to_le_bytes());
        // PROJECTVERSION : la forme à part.
        v.extend(0x0009u16.to_le_bytes());
        v.extend(4u32.to_le_bytes());
        v.extend(1u32.to_le_bytes());
        v.extend(2u16.to_le_bytes());
        enregistrement(&mut v, 0x000C, b"");
        enregistrement(&mut v, 0x003C, b"");
        enregistrement(&mut v, 0x000F, &u16::try_from(modules.len()).unwrap().to_le_bytes());
        enregistrement(&mut v, 0x0013, &0xFFFFu16.to_le_bytes());
        for (nom, flux, decalage, type_) in modules {
            enregistrement(&mut v, 0x0019, nom.as_bytes());
            let unicode: Vec<u8> = nom.encode_utf16().flat_map(u16::to_le_bytes).collect();
            enregistrement(&mut v, 0x0047, &unicode);
            enregistrement(&mut v, 0x001A, flux.as_bytes());
            let unicode: Vec<u8> = flux.encode_utf16().flat_map(u16::to_le_bytes).collect();
            enregistrement(&mut v, 0x0032, &unicode);
            enregistrement(&mut v, 0x001C, b"");
            enregistrement(&mut v, 0x0048, b"");
            enregistrement(&mut v, 0x0031, &decalage.to_le_bytes());
            enregistrement(&mut v, 0x001E, &0u32.to_le_bytes());
            enregistrement(&mut v, 0x002C, &0xFFFFu16.to_le_bytes());
            enregistrement(&mut v, *type_, b"");
            enregistrement(&mut v, 0x002B, b"");
        }
        enregistrement(&mut v, 0x0010, b"");
        v
    }
}

#[cfg(test)]
mod tests {
    use super::essais::dir;
    use super::*;

    #[test]
    fn modules_du_projet() {
        let p = lire_dir(&dir(&[
            ("Module1", "Module1", 0x2A0, 0x21),
            ("ThisDocument", "ThisDocument", 0x400, 0x22),
        ]));
        assert!(!p.incomplet);
        assert_eq!(p.code_page, Some(1252));
        assert_eq!(p.nom.as_deref(), Some("Projet"));
        assert_eq!(p.annonces, Some(2));
        assert_eq!(p.modules.len(), 2);
        assert_eq!(
            p.modules[0],
            Module {
                nom: "Module1".into(),
                flux: "Module1".into(),
                decalage: 0x2A0,
                type_: Some(0x21)
            }
        );
        assert_eq!(p.modules[1].type_, Some(0x22));
        // Coupé : les modules lus avant restent, et c'est dit.
        let d = dir(&[("Module1", "Module1", 0, 0x21), ("Module2", "Module2", 0, 0x21)]);
        let p = lire_dir(&d[..d.len() - 40]);
        assert!(p.incomplet && !p.modules.is_empty());
        // Un enregistrement qui annonce plus que le flux.
        let mut faux = dir(&[]);
        faux[2..6].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(lire_dir(&faux).incomplet);
        assert!(lire_dir(b"").incomplet);
    }

    #[test]
    fn procedures_qui_se_lancent_seules() {
        let source = "Attribute VB_Name = \"ThisDocument\"\r\n' Sub AutoClose() en commentaire\r\nPrivate Sub Document_Open()\r\n  x = \"Sub AutoExit()\"\r\nEnd Sub\r\nSub AUTOOPEN ()\r\nEnd Sub\r\nPublic Function Calcul(a)\r\nEnd Function\r\nPrivate Sub InkPicture1_Painted(ByVal hDC As Long)\r\nEnd Sub\r\n";
        assert_eq!(
            procedures_automatiques(source, "ThisDocument"),
            ["Document_Open", "AUTOOPEN", "InkPicture1_Painted"]
        );
        assert_eq!(procedures_automatiques("Sub Main()\nEnd Sub", "AutoOpen"), ["Main"]);
        assert_eq!(
            procedures_automatiques("Sub Main()\nEnd Sub", "Module1"),
            Vec::<String>::new()
        );
        assert_eq!(procedures_automatiques("Sub _Layout()", "M"), Vec::<String>::new());
        assert_eq!(
            procedures_automatiques("Static Sub Workbook_Open()", "M"),
            ["Workbook_Open"]
        );
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 2000, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn jamais_de_plantage(octets in proptest::collection::vec(proptest::num::u8::ANY, 0..2000), i in 0usize..2000, x in proptest::num::u8::ANY) {
            let _ = lire_dir(&octets);
            let mut d = dir(&[("Module1", "Module1", 0, 0x21)]);
            let n = d.len();
            d[i % n] = x;
            let p = lire_dir(&d);
            proptest::prop_assert!(p.modules.len() <= MODULES_MAX);
            let _ = procedures_automatiques(&String::from_utf8_lossy(&octets), "AutoOpen");
        }
    }
}

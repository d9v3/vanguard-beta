//! L'arbre de parties sur des fichiers fabriqués ici (PE, ELF, Mach-O minimaux, fichiers composés avec un module VBA
//! compressé à la main, raccourcis, zips piégés, EICAR comme simple chaîne) : aucun vrai logiciel malveillant, aucun
//! fichier tiers.

use super::*;
use crate::archives::zip::essais::archive_controlee as zip_de;

/// La chaîne d'essai EICAR, assemblée à l'exécution : le source ne la contient pas d'un bloc (un antivirus qui
/// lirait le dépôt n'a pas à s'en alarmer).
fn eicar() -> Vec<u8> {
    [
        r"X5O!P%@AP[4\PZX54(P^)7CC)7}$",
        "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    ]
    .concat()
    .into_bytes()
}

fn analyse(octets: &[u8], nom: &str) -> Analyse {
    analyser(octets, nom, &Bornes::default(), &mut |_, _| {})
}

fn types(a: &Analyse) -> Vec<(String, Type)> {
    a.parties.iter().map(|p| (p.chemin.clone(), p.type_)).collect()
}

/// Un PE minimal (le fabricant du lecteur commun) dont la section est écrivable et exécutable, suivi de `ajout`.
fn pe_wx(ajout: &[u8]) -> Vec<u8> {
    let mut v = crate::pe::essais::pe(&crate::pe::essais::Fabrique::default());
    // La table des sections suit l'en-tête facultatif de PE32+ (0x40 + 24 + 240) ; Characteristics en 36.
    let section = 0x40 + 24 + 240;
    v[section + 36..section + 40].copy_from_slice(&0xE000_0020u32.to_le_bytes());
    v.extend_from_slice(ajout);
    v
}

#[test]
fn pe_avec_overlay_qui_contient_un_zip() {
    let zip = zip_de(&[("lisezmoi.txt", 8, &eicar())]);
    let v = pe_wx(&zip);
    let mut vus = Vec::new();
    let a = analyser(&v, "photo.jpg", &Bornes::default(), &mut |p, o| {
        vus.push((p.chemin.clone(), o.len()));
        assert_eq!(p.sha256, Some(super::arbre::essai_sha256(o)));
    });
    assert_eq!(
        types(&a),
        [
            ("photo.jpg".to_string(), Type::Pe),
            ("#overlay@1024".to_string(), Type::Zip),
            ("lisezmoi.txt".to_string(), Type::Texte),
        ]
    );
    let racine = &a.parties[0];
    assert!(racine.faits.contains(&Fait::SectionEcrivableExecutable(".rsrc".into())));
    assert!(racine.faits.contains(&Fait::ExtensionTrompeuse("jpg".into())));
    assert!(racine.faits.contains(&Fait::Overlay(zip.len() as u64)));
    assert!(
        racine
            .faits
            .contains(&Fait::Authenticode(crate::pe::Authenticode::Absente))
    );
    assert!(matches!(racine.details, Details::Pe(_)));
    assert_eq!(a.parties[2].parent, Some(1));
    assert_eq!(a.enfants(0).collect::<Vec<_>>(), [1]);
    assert_eq!(a.parties[2].taille, eicar().len() as u64);
    assert!(a.entierement_lue(), "{:?}", a.manques().collect::<Vec<_>>());
    assert_eq!(a.chemin_complet(2), "photo.jpg › #overlay@1024 › lisezmoi.txt");
    // Chaque partie lue visitée une fois, après ses enfants.
    assert_eq!(vus.len(), 3);
    assert_eq!(vus.last().unwrap().0, "photo.jpg");
}

#[test]
fn ce_qui_n_est_pas_lu_est_dit() {
    // Un format inconnu.
    let a = analyse(&[0u8, 1, 2, 3, 0xff, 0xfe, 0x10, 0x80], "x.dat");
    assert_eq!(a.parties[0].manques, [Raison::FormatInconnu]);
    assert!(!a.entierement_lue());
    // Des formats reconnus mais pas ouverts.
    for (octets, type_) in [
        (b"7z\xBC\xAF\x27\x1C\0\x04abcdef".to_vec(), Type::SeptZip),
        (b"Rar!\x1A\x07\x01\0abc".to_vec(), Type::Rar),
        (b"MSCF\0\0\0\0abcdefgh".to_vec(), Type::Cab),
        (b"%PDF-1.7\n1 0 obj\n".to_vec(), Type::Pdf),
    ] {
        let a = analyse(&octets, "a");
        assert_eq!(a.parties[0].manques, [Raison::FormatNonLu(type_)]);
    }
    // Un zip dont une entrée est chiffrée, une autre d'une méthode inconnue : chacune dite, l'autre lue.
    let mut z = zip_de(&[
        ("secret.txt", 0, b"abc"),
        ("b.txt", 12, b"bzip2"),
        ("c.txt", 0, b"clair"),
    ]);
    let central = z.windows(4).position(|f| f == b"PK\x01\x02").unwrap();
    z[central + 8] |= 1;
    let local = 0;
    z[local + 6] |= 1;
    let a = analyse(&z, "a.zip");
    let parties: Vec<(&str, &[Raison])> = a
        .parties
        .iter()
        .map(|p| (p.chemin.as_str(), p.manques.as_slice()))
        .collect();
    assert_eq!(
        parties,
        [
            ("a.zip", &[][..]),
            ("secret.txt", &[Raison::Chiffre][..]),
            ("b.txt", &[Raison::Methode(12)][..]),
            ("c.txt", &[][..]),
        ]
    );
    assert!(a.parties[1].sha256.is_none());
    // Coupé : pas de répertoire central, les entrées locales lues quand même, et dit.
    let z = zip_de(&[("a.txt", 8, &b"bonjour ".repeat(100))]);
    let central = z.windows(4).position(|f| f == b"PK\x01\x02").unwrap();
    let a = analyse(&z[..central], "coupe.zip");
    assert!(a.parties[0].manques.contains(&Raison::Tronque));
    assert_eq!(a.parties[1].origine, Origine::EntreeZipLocale);
    assert_eq!(a.parties[1].taille, 800);
}

#[test]
fn entrees_zip_cachees() {
    // Un en-tête local que le répertoire central ne désigne pas, glissé devant l'archive.
    let cache = zip_de(&[("cache.vbs", 0, b"CreateObject(\"WScript.Shell\")\nDim x\n")]);
    let central = cache.windows(4).position(|f| f == b"PK\x01\x02").unwrap();
    let visible = zip_de(&[("visible.txt", 0, b"rien ici")]);
    let mut v = cache[..central].to_vec();
    // Les positions de l'archive visible sont décalées d'autant : corrigées par le décalage, comme un extracteur.
    v.extend_from_slice(&visible);
    let a = analyse(&v, "a.zip");
    let chemins: Vec<(&str, Origine)> = a
        .parties
        .iter()
        .skip(1)
        .map(|p| (p.chemin.as_str(), p.origine))
        .collect();
    assert!(chemins.contains(&("visible.txt", Origine::EntreeZip)), "{chemins:?}");
    assert!(
        chemins.contains(&("cache.vbs", Origine::EntreeZipLocale)),
        "{chemins:?}"
    );
    // Une entrée centrale au-delà du nombre annoncé.
    let mut deux = zip_de(&[("a.txt", 0, b"a"), ("b.ps1", 0, b"Write-Host x; Invoke-Expression y")]);
    let fin = deux.len() - 22;
    deux[fin + 8..fin + 12].copy_from_slice(&[1, 0, 1, 0]);
    let a = analyse(&deux, "a.zip");
    let b = a.parties.iter().find(|p| p.chemin == "b.ps1").unwrap();
    assert_eq!(b.origine, Origine::EntreeZipCachee);
    assert_eq!(b.type_, Type::Script(texte::Langage::PowerShell));
    // Deux noms égaux à la casse près, un chemin qui sort, un nom local différent.
    let mut z = zip_de(&[
        ("A.exe", 0, b"x"),
        ("a.EXE", 0, b"y"),
        ("../../evil.sh", 0, b"#!/bin/sh\nid\n"),
    ]);
    let local = z.windows(5).position(|f| f == b"a.EXE").unwrap();
    z[local] = b'b';
    let a = analyse(&z, "a.zip");
    assert!(a.parties[1].faits.contains(&Fait::NomEnDouble));
    assert!(a.parties[2].faits.contains(&Fait::NomLocalDifferent("b.EXE".into())));
    assert!(a.parties[3].faits.contains(&Fait::Nom(nom::FaitNom::CheminSortant)));
}

#[test]
fn bombes_et_quines() {
    // 64 Mio de zéros dans un zip : bornés par partie, et dit.
    let bornes = Bornes {
        taille_partie: 4 << 20,
        ..Bornes::default()
    };
    let gros = vec![0u8; 16 << 20];
    let bombe = zip_de(&[("zero.bin", 8, &gros)]);
    let a = analyser(&bombe, "b.zip", &bornes, &mut |_, _| {});
    assert!(a.parties[1].manques.contains(&Raison::TropGros));
    assert_eq!(a.parties[1].taille, 4 << 20);
    // Des bombes imbriquées : le taux de compression arrête tout bien avant le total.
    let mut niveau = zip_de(&[("zero.bin", 8, &gros)]);
    for k in 0..3 {
        let noms: Vec<String> = (0..10).map(|j| format!("{k}-{j}.zip")).collect();
        let entrees: Vec<(&str, u16, &[u8])> = noms.iter().map(|n| (n.as_str(), 8, &niveau[..])).collect();
        niveau = zip_de(&entrees);
    }
    let bornes = Bornes {
        seuil_taux: 1 << 20,
        taux: 50,
        ..Bornes::default()
    };
    let a = analyser(&niveau, "42.zip", &bornes, &mut |_, _| {});
    assert!(
        a.manques().any(|(_, r)| *r == Raison::TauxDeCompression),
        "{}",
        a.produits
    );
    assert!(a.produits < 64 << 20, "{}", a.produits);
    // Une quine : une architecture d'un Mach-O universel qui couvre le fichier entier, lui-même.
    let mut u = macho::essais::universel(&[macho::essais::macho64(5, false)]);
    let n = u32::try_from(u.len()).unwrap();
    u[16..20].copy_from_slice(&0u32.to_be_bytes());
    u[20..24].copy_from_slice(&n.to_be_bytes());
    let a = analyse(&u, "u");
    assert!(a.parties.iter().any(|p| p.manques.contains(&Raison::Quine)));
    // L'imbrication : dix gzip l'un dans l'autre, arrêtés à la profondeur.
    let mut g = b"fin".to_vec();
    for _ in 0..10 {
        let mut membre = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
        membre.extend(miniz_oxide::deflate::compress_to_vec(&g, 6));
        membre.extend(crate::archives::crc32::crc32(&g).to_le_bytes());
        membre.extend(u32::try_from(g.len()).unwrap().to_le_bytes());
        g = membre;
    }
    let a = analyse(&g, "x.gz");
    assert!(a.manques().any(|(_, r)| *r == Raison::Profondeur));
    assert!(a.parties.len() <= Bornes::default().profondeur + 1);
    // Le nombre de parties.
    let noms: Vec<String> = (0..50).map(|j| format!("{j}.txt")).collect();
    let entrees: Vec<(&str, u16, &[u8])> = noms.iter().map(|n| (n.as_str(), 0, &b"x"[..])).collect();
    let bornes = Bornes {
        parties: 10,
        ..Bornes::default()
    };
    let a = analyser(&zip_de(&entrees), "z.zip", &bornes, &mut |_, _| {});
    assert_eq!(a.parties.len(), 10);
    assert!(a.parties[0].manques.contains(&Raison::TropDeParties));
}

/// Un fichier composé avec un projet VBA : flux « dir » et module compressés à la main, source à `decalage` après
/// un faux p-code.
fn document_vba(racine: &str, source: &str, avec_word: bool) -> Vec<u8> {
    let decalage = 0x40u32;
    let dir = ovba::essais::compresser(&vba::essais::dir(&[("Module1", "Module1", decalage, 0x21)]));
    let mut module = vec![0xCCu8; decalage as usize];
    module.extend(ovba::essais::compresser(source.as_bytes()));
    let vba_storage = if racine.is_empty() {
        "VBA".to_string()
    } else {
        format!("{racine}/VBA")
    };
    let dir_chemin = format!("{vba_storage}/dir");
    let module_chemin = format!("{vba_storage}/Module1");
    let projet = format!("{vba_storage}/_VBA_PROJECT");
    let mut fib = vec![0u8; 64];
    fib[..2].copy_from_slice(&0xA5ECu16.to_le_bytes());
    let mut elements: Vec<cfb::essais::Element<'_>> = Vec::new();
    if !racine.is_empty() {
        elements.push((racine, None));
    }
    elements.push((&vba_storage, None));
    elements.push((&dir_chemin, Some(&dir)));
    elements.push((&module_chemin, Some(&module)));
    elements.push((&projet, Some(b"\xCC\x61\xFF\xFF")));
    if avec_word {
        elements.push(("WordDocument", Some(&fib)));
    }
    cfb::essais::fichier(&elements)
}

#[test]
fn macros_vba_d_un_document_97_et_d_un_docx() {
    let source = "Attribute VB_Name = \"Module1\"\r\nSub AutoOpen()\r\n  Shell \"calc\"\r\nEnd Sub\r\n";
    let doc = document_vba("Macros", source, true);
    let a = analyse(&doc, "facture.doc");
    assert_eq!(a.parties[0].type_, Type::DocWord);
    assert!(a.parties[0].faits.contains(&Fait::MacrosVba(1)));
    assert!(a.parties[0].faits.contains(&Fait::ModuleVba("Module1".into())));
    assert!(
        a.parties[0]
            .faits
            .contains(&Fait::ProcedureAutomatique("AutoOpen".into()))
    );
    let src = a.parties.iter().find(|p| p.type_ == Type::SourceVba).unwrap();
    assert_eq!(src.chemin, "Macros/VBA/Module1#source");
    assert!(src.faits.contains(&Fait::ProcedureAutomatique("AutoOpen".into())));
    assert!(a.entierement_lue(), "{:?}", a.manques().collect::<Vec<_>>());
    // Le même projet dans un docx (vbaProject.bin), avec un modèle chargé depuis l'extérieur.
    let bin = document_vba("", source, false);
    let types = br#"<?xml version="1.0"?><Types><Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>"#;
    let rels = br#"<Relationships><Relationship Id="r1" Type="x/attachedTemplate" Target="https://exemple.invalid/m.dotm" TargetMode="External"/></Relationships>"#;
    let docx = zip_de(&[
        ("[Content_Types].xml", 8, types),
        ("word/vbaProject.bin", 8, &bin),
        ("word/_rels/settings.xml.rels", 8, rels),
    ]);
    let a = analyse(&docx, "facture.docm");
    assert_eq!(a.parties[0].type_, Type::Ooxml);
    assert!(
        a.parties[0]
            .faits
            .contains(&Fait::RelationExterne("https://exemple.invalid/m.dotm".into()))
    );
    let bin = a.parties.iter().find(|p| p.chemin == "word/vbaProject.bin").unwrap();
    assert_eq!(bin.type_, Type::Cfb);
    assert!(bin.faits.contains(&Fait::ProcedureAutomatique("AutoOpen".into())));
    assert!(a.entierement_lue(), "{:?}", a.manques().collect::<Vec<_>>());
    // Une source vide derrière du p-code (« VBA stomping ») : non vérifié.
    let vide = document_vba("Macros", "", true);
    let a = analyse(&vide, "a.doc");
    assert!(a.manques().any(|(_, r)| *r == Raison::SourceVbaIllisible));
    // Le module annoncé n'a pas de flux.
    let sans_module = {
        let dir = ovba::essais::compresser(&vba::essais::dir(&[("Fantome", "Fantome", 0, 0x21)]));
        cfb::essais::fichier(&[("VBA", None), ("VBA/dir", Some(&dir))])
    };
    let a = analyse(&sans_module, "a.bin");
    assert!(a.parties[0].manques.contains(&Raison::SourceVbaIllisible));
}

#[test]
fn documents_chiffres_et_xlm() {
    // Un docx protégé par mot de passe : un fichier composé EncryptionInfo + EncryptedPackage.
    let chiffre = cfb::essais::fichier(&[
        ("EncryptionInfo", Some(&[4, 0, 4, 0])),
        ("EncryptedPackage", Some(&[0x10; 64])),
    ]);
    let a = analyse(&chiffre, "a.docx");
    assert_eq!(a.parties[0].type_, Type::OoxmlChiffre);
    assert!(a.parties[0].manques.contains(&Raison::Chiffre));
    // Un classeur 97 à feuille de macros très masquée.
    let classeur = office::essais::classeur(false, &[("Feuil1", 0, 0), ("Auto_Open", 2, 1)]);
    let xls = cfb::essais::fichier(&[("Workbook", Some(&classeur))]);
    let a = analyse(&xls, "a.xls");
    assert_eq!(a.parties[0].type_, Type::ClasseurExcel);
    assert!(a.parties[0].faits.contains(&Fait::MacrosXlm("Auto_Open".into())));
    assert!(a.parties[0].faits.contains(&Fait::FeuilleMasquee {
        nom: "Auto_Open".into(),
        tres: true
    }));
    // Les formules XLM ne sont pas décodées : dit.
    assert_eq!(a.parties[0].manques, [Raison::MacrosXlmNonDecodees]);
    let chiffre = cfb::essais::fichier(&[("Workbook", Some(&office::essais::classeur(true, &[])))]);
    assert!(analyse(&chiffre, "a.xls").parties[0].manques.contains(&Raison::Chiffre));
}

#[test]
fn raccourci_elf_macho_et_scripts() {
    let lnk = lnk::essais::raccourci(
        None,
        Some("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
        Some("-w hidden -enc ZQBjAGgAbwA="),
        b"",
    );
    let a = analyse(&lnk, "Facture.pdf.lnk");
    assert_eq!(a.parties[0].type_, Type::Lnk);
    let f = &a.parties[0].faits;
    assert!(f.contains(&Fait::InterpreteurLance("powershell.exe")));
    assert!(f.contains(&Fait::ArgumentsLnk("-w hidden -enc ZQBjAGgAbwA=".into())));
    assert!(f.contains(&Fait::Nom(nom::FaitNom::DoubleExtension {
        avant: "pdf".into(),
        extension: "lnk".into()
    })));
    // ELF avec des octets ajoutés (un zip).
    let zip = zip_de(&[("a.txt", 0, b"x")]);
    let a = analyse(&elf::essais::elf64(7, true, 0x40_0180, &zip), "prog");
    assert_eq!(types(&a)[1].1, Type::Zip);
    assert!(a.parties[0].faits.contains(&Fait::SegmentEcrivableExecutable));
    assert!(a.parties[0].faits.contains(&Fait::PileExecutable));
    // Mach-O universel : chaque architecture analysée, la chiffrée dite.
    let u = macho::essais::universel(&[macho::essais::macho64(5, false), macho::essais::macho64(7, true)]);
    let a = analyse(&u, "app");
    assert_eq!(a.parties.len(), 3);
    assert!(a.parties[2].manques.contains(&Raison::Chiffre));
    assert!(
        a.parties[2]
            .faits
            .contains(&Fait::SegmentMachOEcrivableExecutable("__TEXT".into()))
    );
    // Un script PowerShell en UTF-16 : décodé en partie à part pour les motifs.
    let script = "$env:TEMP; Invoke-WebRequest x; Write-Host y";
    let mut ps = vec![0xFF, 0xFE];
    ps.extend(script.encode_utf16().flat_map(u16::to_le_bytes));
    let a = analyse(&ps, "a.ps1");
    assert_eq!(a.parties[0].type_, Type::Script(texte::Langage::PowerShell));
    assert_eq!(a.parties[1].origine, Origine::TexteDecode);
    assert_eq!(a.parties[1].taille, script.len() as u64);
    // EICAR, simple texte : lu, sans verdict ici.
    let a = analyse(&eicar(), "eicar.com");
    assert!(a.entierement_lue());
    assert!(matches!(a.parties[0].type_, Type::Texte | Type::Script(_)));
}

#[test]
fn zip_colle_derriere_une_image() {
    let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
    png.extend([0u8; 40]);
    png.extend(zip_de(&[(
        "charge.js",
        0,
        b"var s = new ActiveXObject('WScript.Shell'); eval(x);",
    )]));
    let a = analyse(&png, "chat.png");
    assert_eq!(a.parties[0].type_, Type::Image);
    assert_eq!(a.parties[1].origine, Origine::ZipAjoute);
    assert_eq!(a.parties[2].type_, Type::Script(texte::Langage::JScript));
}

#[test]
fn fichier_trop_gros_et_non_ordinaire() {
    let bornes = Bornes {
        taille_fichier: 10,
        ..Bornes::default()
    };
    let a = analyser(&[0u8; 11], "gros", &bornes, &mut |_, _| panic!("rien n'est lu"));
    assert_eq!(a.parties[0].manques, [Raison::TropGros]);
    let dossier = std::env::temp_dir().join(format!("vanguard-analyse-{}", std::process::id()));
    std::fs::create_dir_all(&dossier).unwrap();
    assert!(analyser_fichier(&dossier, &Bornes::default(), &mut |_, _| {}).is_err());
    let f = dossier.join("a.txt");
    std::fs::write(&f, "Bonjour, une lettre.\n").unwrap();
    let a = analyser_fichier(&f, &Bornes::default(), &mut |_, _| {}).unwrap();
    assert_eq!(
        (a.parties[0].chemin.as_str(), a.parties[0].type_),
        ("a.txt", Type::Texte)
    );
    let a = analyser_fichier(&f, &bornes, &mut |_, _| {}).unwrap();
    assert_eq!(a.parties[0].manques, [Raison::TropGros]);
    std::fs::remove_dir_all(&dossier).unwrap();
}

/// Les défauts trouvés par les relectures adverses du lot : chacun a son essai.
#[test]
fn relectures_donnees_hostiles() {
    // Une entrée centrale zip64 dont l'en-tête local serait à 2⁶⁴ - 1 : ni débordement, ni lecture.
    let mut z = zip_de(&[("a.txt", 0, b"abc")]);
    let central = z.windows(4).position(|f| f == b"PK\x01\x02").unwrap();
    z[central + 42..central + 46].copy_from_slice(&u32::MAX.to_le_bytes());
    // Un champ zip64 (0x0001, 8 octets) à la place du nom : longueur des champs 12, nom vidé.
    let fin = z.len() - 22;
    let mut avec = z[..central + 46].to_vec();
    avec[central + 28..central + 30].copy_from_slice(&0u16.to_le_bytes());
    avec[central + 30..central + 32].copy_from_slice(&12u16.to_le_bytes());
    avec.extend(1u16.to_le_bytes());
    avec.extend(8u16.to_le_bytes());
    avec.extend(u64::MAX.to_le_bytes());
    let taille = u32::try_from(avec.len() - central).unwrap();
    let mut eocd = z[fin..].to_vec();
    eocd[12..16].copy_from_slice(&taille.to_le_bytes());
    avec.extend(eocd);
    let _ = analyse(&avec, "a.zip");
    let mut image = b"\x89PNG\r\n\x1a\n".to_vec();
    image.extend(&avec);
    let _ = analyse(&image, "a.png");
    // Une chaîne de 300 stockages imbriqués : la profondeur suivie est bornée, et dit.
    let noms: Vec<String> = (0..300)
        .map(|k| (0..=k).map(|j| format!("{:x}", j % 16)).collect::<Vec<_>>().join("/"))
        .collect();
    let elements: Vec<cfb::essais::Element<'_>> = noms.iter().map(|n| (n.as_str(), None)).collect();
    let a = analyse(&cfb::essais::fichier(&elements), "profond.bin");
    assert!(
        a.parties[0].manques.contains(&Raison::EntreesLimitees),
        "{:?}",
        a.parties[0].manques
    );
    // Vingt projets VBA : au-delà de la borne, dit.
    let dir = ovba::essais::compresser(&vba::essais::dir(&[]));
    let stockages: Vec<String> = (0..20).map(|k| format!("S{k}")).collect();
    let vbas: Vec<String> = stockages.iter().map(|s| format!("{s}/VBA")).collect();
    let dirs: Vec<String> = vbas.iter().map(|v| format!("{v}/dir")).collect();
    let mut elements: Vec<cfb::essais::Element<'_>> = Vec::new();
    for k in 0..20 {
        elements.push((&stockages[k], None));
        elements.push((&vbas[k], None));
        elements.push((&dirs[k], Some(&dir)));
    }
    let a = analyse(&cfb::essais::fichier(&elements), "a.doc");
    assert!(a.parties[0].manques.contains(&Raison::EntreesLimitees));
}

#[test]
fn relectures_faux_verts() {
    // Un programme DOS ou NE (« MZ » sans PE), une classe Java : non lus, dits.
    assert_eq!(
        analyse(b"MZ\x90\0\x03\0\0\0", "a").parties[0].manques,
        [Raison::FormatNonLu(Type::ExecutableDos)]
    );
    assert_eq!(
        analyse(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52, 1, 2], "a").parties[0].manques,
        [Raison::FormatNonLu(Type::ClasseJava)]
    );
    // Un fichier universel de 40 architectures n'est pas une classe Java.
    assert_eq!(
        nature::deviner(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 40]),
        Type::MachOUniversel
    );
    // Tar : un type inconnu (« Z ») avec un contenu est lu ; une archive mise bout à bout après la fin aussi.
    let mut t = Vec::new();
    let entree = |t: &mut Vec<u8>, nom: &str, type_: u8, contenu: &[u8]| {
        let mut e = [0u8; 512];
        e[..nom.len()].copy_from_slice(nom.as_bytes());
        e[124..135].copy_from_slice(format!("{:011o}", contenu.len()).as_bytes());
        e[156] = type_;
        e[257..263].copy_from_slice(b"ustar\0");
        t.extend(e);
        t.extend(contenu);
        t.resize(t.len().next_multiple_of(512), 0);
    };
    entree(
        &mut t,
        "cache.vbs",
        b'Z',
        b"Dim o\r\nSet o = CreateObject(\"WScript.Shell\")\r\n",
    );
    t.extend([0u8; 1024]);
    entree(&mut t, "suite.sh", b'0', b"#!/bin/sh\nid\n");
    t.extend([0u8; 1024]);
    let a = analyse(&t, "a.tar");
    assert!(
        a.parties
            .iter()
            .any(|p| p.chemin == "cache.vbs" && p.type_ == Type::Script(texte::Langage::VbScript))
    );
    assert!(a.parties.iter().any(|p| p.chemin == "suite.sh"), "{:?}", types(&a));
    // Zip : deux entrées sur le même en-tête local, l'une stockée vide, l'autre deflate : la seconde est lue.
    let contenu = b"Write-Host x; Invoke-Expression y; $env:TEMP".repeat(10);
    let mut z = zip_de(&[("vide.txt", 0, b""), ("vrai.ps1", 8, &contenu)]);
    let premier = z.windows(4).position(|f| f == b"PK\x01\x02").unwrap();
    let second = premier + 46 + "vide.txt".len();
    let local_vrai = z[second + 42..second + 46].to_vec();
    z[premier + 42..premier + 46].copy_from_slice(&local_vrai);
    let a = analyse(&z, "a.zip");
    assert!(
        a.parties
            .iter()
            .any(|p| p.chemin == "vrai.ps1" && p.type_ == Type::Script(texte::Langage::PowerShell))
    );
    // Un zip collé derrière une image, avec une entrée centrale factice qui désigne la position 0.
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend([0x41u8; 64]);
    let mut colle = zip_de(&[
        ("factice", 0, b"x"),
        ("charge.js", 0, b"var s = new ActiveXObject('x'); eval(s);"),
    ]);
    let premier = colle.windows(4).position(|f| f == b"PK\x01\x02").unwrap();
    // Positions absolues dans le fichier entier (comme `zip -A`), sauf la factice, à 0.
    let decalage = u32::try_from(png.len()).unwrap();
    let second = premier + 46 + "factice".len();
    let pos = u32::from_le_bytes(colle[second + 42..second + 46].try_into().unwrap()) + decalage;
    colle[second + 42..second + 46].copy_from_slice(&pos.to_le_bytes());
    colle[premier + 42..premier + 46].copy_from_slice(&0u32.to_le_bytes());
    let fin = colle.len() - 22;
    let debut = u32::from_le_bytes(colle[fin + 16..fin + 20].try_into().unwrap()) + decalage;
    colle[fin + 16..fin + 20].copy_from_slice(&debut.to_le_bytes());
    png.extend(&colle);
    let a = analyse(&png, "chat.png");
    assert!(a.parties.iter().any(|p| p.chemin == "charge.js"), "{:?}", types(&a));
    // PNG suivi d'un programme : analysé à part.
    let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\0IEND\xae\x42\x60\x82".to_vec();
    png.extend(pe_wx(b""));
    let a = analyse(&png, "chat.png");
    assert_eq!(types(&a)[1], ("#apres-image".to_string(), Type::Pe));
    // PowerPoint 97 : son flux principal n'est pas lu, dit.
    let ppt = cfb::essais::fichier(&[
        ("PowerPoint Document", Some(&[0u8; 64])),
        ("Current User", Some(&[0u8; 16])),
    ]);
    let a = analyse(&ppt, "a.ppt");
    assert_eq!(a.parties[0].type_, Type::PresentationPowerPoint);
    assert!(
        a.parties[0]
            .manques
            .contains(&Raison::FormatNonLu(Type::PresentationPowerPoint))
    );
    // Un raccourci dont la liste d'identifiants ne nomme pas la cible de LinkInfo : la cible lue n'est pas sûre.
    let mut ids = 9u16.to_le_bytes().to_vec();
    ids.extend(b"\x31\0calc\0\0\0");
    let l = lnk::essais::raccourci(Some(&ids), Some("C:\\Windows\\notepad.exe"), None, b"");
    assert!(
        analyse(&l, "a.lnk").parties[0]
            .manques
            .contains(&Raison::CibleNonDecodee)
    );
    let mut ids = 15u16.to_le_bytes().to_vec();
    ids.extend(b"\x31\0notepad.exe\0");
    let l = lnk::essais::raccourci(Some(&ids), Some("C:\\Windows\\notepad.exe"), None, b"");
    assert!(analyse(&l, "a.lnk").entierement_lue());
    // ForceNoLinkInfo : Windows ignore LinkInfo.
    let mut l = lnk::essais::raccourci(None, Some("C:\\Windows\\notepad.exe"), None, b"");
    l[21] |= 1;
    assert!(
        analyse(&l, "a.lnk").parties[0]
            .manques
            .contains(&Raison::CibleNonDecodee)
    );
    // 64 Kio de texte puis du binaire : pas du texte.
    let mut t = b"ligne de texte\n".repeat(5000);
    t.extend([0u8, 1, 2, 3, 0, 0, 0xff]);
    assert!(analyse(&t, "a.txt").parties[0].manques.contains(&Raison::FormatInconnu));
    // Un tar dont le premier nom est « %PDF-1.7 » : lu comme tar, et le PDF dit non lu.
    let mut t = Vec::new();
    entree(&mut t, "%PDF-1.7", b'0', b"x");
    t.extend([0u8; 1024]);
    let a = analyse(&t, "a.tar");
    assert_eq!(a.parties[0].type_, Type::Tar);
    assert!(a.parties[0].manques.contains(&Raison::FormatNonLu(Type::Pdf)));
    // Un module VBA dont la source n'a plus que ses lignes « Attribute » (p-code seul) : non vérifié.
    let doc = document_vba("Macros", "Attribute VB_Name = \"Module1\"\r\n", true);
    assert!(
        analyse(&doc, "a.doc")
            .manques()
            .any(|(_, r)| *r == Raison::SourceVbaIllisible)
    );
}

/// Les plantages trouvés par le fuzzing, gardés en graines : plus jamais.
#[test]
fn regressions_du_fuzzing() {
    // Une source VBA dont une ligne commence par un caractère sur plusieurs octets (coupé au milieu).
    let _ = analyse(
        include_bytes!("../../fuzz/graines/analyse_fichier/regression-source-multioctet.bin"),
        "f",
    );
}

/// Les fichiers du socle d'analyse n'importent pas l'interface : aucun verdict ni affichage ici.
#[test]
fn sans_interface() {
    let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/analyse");
    for entree in std::fs::read_dir(&racine).unwrap() {
        let chemin = entree.unwrap().path();
        if chemin.file_name().is_some_and(|n| n == "tests.rs") {
            continue;
        }
        let texte = std::fs::read_to_string(&chemin).unwrap();
        assert!(!texte.contains("crate::ui"), "{} importe l'interface", chemin.display());
        assert!(!texte.contains("tr!("), "{} affiche du texte", chemin.display());
    }
}

/// Un passage sur de vrais fichiers sains de cet ordinateur, pour la robustesse et le coût : les dossiers de
/// `VANGUARD_ANALYSE_DOSSIERS` (séparés par « : »), rien de gardé ni d'affiché du chemin des fichiers. À la main :
/// `VANGUARD_ANALYSE_DOSSIERS=/usr/bin cargo test passage_sur_des_fichiers_sains -- --ignored --nocapture`.
#[test]
#[ignore = "à la main, sur les dossiers donnés"]
fn passage_sur_des_fichiers_sains() {
    let Some(dossiers) = std::env::var_os("VANGUARD_ANALYSE_DOSSIERS") else {
        return crate::essais::saute("VANGUARD_ANALYSE_DOSSIERS absent");
    };
    let mut pile: Vec<std::path::PathBuf> = std::env::split_paths(&dossiers).collect();
    let (mut fichiers, mut octets, mut parties, mut non_verifies) = (0u64, 0u64, 0u64, 0u64);
    let mut plus_lent = std::time::Duration::ZERO;
    let mut lent = String::new();
    let mut par_raison: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let mut par_type: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let debut = std::time::Instant::now();
    while let Some(d) = pile.pop() {
        let Ok(lecture) = std::fs::read_dir(&d) else { continue };
        for e in lecture.flatten() {
            let Ok(t) = e.file_type() else { continue };
            if t.is_dir() {
                pile.push(e.path());
            } else if t.is_file() {
                let Ok(a) = analyser_fichier(&e.path(), &Bornes::default(), &mut |_, _| {}) else {
                    continue;
                };
                fichiers += 1;
                octets += a.parties[0].taille;
                parties += a.parties.len() as u64;
                if a.duree > plus_lent {
                    plus_lent = a.duree;
                    lent = format!(
                        "{:?}, {} Ko, {} parties",
                        a.parties[0].type_,
                        a.parties[0].taille >> 10,
                        a.parties.len()
                    );
                }
                *par_type.entry(format!("{:?}", a.parties[0].type_)).or_default() += 1;
                if !a.entierement_lue() {
                    non_verifies += 1;
                    for (_, r) in a.manques() {
                        let cle = format!("{r:?}");
                        *par_raison.entry(cle).or_default() += 1;
                    }
                }
            }
        }
    }
    eprintln!(
        "{fichiers} fichiers, {} Mo, {parties} parties, {non_verifies} non vérifiés, {:.1} s en tout, le plus lent {:.2} s ({lent})",
        octets >> 20,
        debut.elapsed().as_secs_f64(),
        plus_lent.as_secs_f64()
    );
    eprintln!("types : {par_type:?}");
    eprintln!("manques : {par_raison:?}");
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig { cases: 400, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
    /// N'importe quels octets, ou un fichier fabriqué abîmé : jamais de panique, et les bornes tiennent.
    #[test]
    fn jamais_de_plantage_et_bornes(
        octets in proptest::collection::vec(proptest::num::u8::ANY, 0..3000),
        sorte in 0usize..6,
        i in 0usize..100_000,
        x in proptest::num::u8::ANY,
    ) {
        let bornes = Bornes { parties: 200, produits: 4 << 20, taille_partie: 1 << 20, ..Bornes::default() };
        let mut base = match sorte {
            0 => octets.clone(),
            1 => pe_wx(&zip_de(&[("a.txt", 8, &octets)])),
            2 => document_vba("Macros", "Sub AutoOpen()\r\nEnd Sub\r\n", true),
            3 => lnk::essais::raccourci(Some(&[5, 0, b'a', b'b', b'c']), Some("C:\\a.exe"), Some("x"), &octets),
            4 => zip_de(&[("a.zip", 0, &zip_de(&[("b.txt", 8, &octets)])), ("c", 8, &octets)]),
            _ => elf::essais::elf64(5, false, 0, &octets),
        };
        if !base.is_empty() && sorte != 0 {
            let n = base.len();
            base[i % n] ^= x;
        }
        let mut visites = 0usize;
        let a = analyser(&base, "f", &bornes, &mut |_, _| visites += 1);
        proptest::prop_assert!(a.parties.len() <= bornes.parties);
        proptest::prop_assert!(a.produits <= bornes.produits + bornes.texte as u64);
        proptest::prop_assert!(visites <= a.parties.len());
        for (k, p) in a.parties.iter().enumerate() {
            proptest::prop_assert!(p.parent.is_none_or(|q| q < k));
            proptest::prop_assert!(p.profondeur <= bornes.profondeur);
            // Un type inconnu est toujours dit.
            if p.type_ == Type::Inconnu && p.sha256.is_some() {
                proptest::prop_assert!(!p.manques.is_empty());
            }
        }
    }
}

/// Les graines du banc de fuzzing (fuzz/graines/analyse_fichier, analyse_lecteurs), fabriquées ici : à relancer à la
/// main quand un fabricant change, `VANGUARD_GRAINES=fuzz/graines cargo test ecrire_les_graines -- --ignored`.
#[test]
#[ignore = "à la main, pour refaire les graines"]
fn ecrire_les_graines() {
    let Some(racine) = std::env::var_os("VANGUARD_GRAINES") else {
        return crate::essais::saute("VANGUARD_GRAINES absent");
    };
    let racine = std::path::PathBuf::from(racine);
    let source = "Attribute VB_Name = \"Module1\"\r\nSub AutoOpen()\r\n  MsgBox 1\r\nEnd Sub\r\n";
    let bin = document_vba("", source, false);
    let mut ps = vec![0xFF, 0xFE];
    ps.extend(
        "$env:TEMP; Write-Host x; Invoke-Expression y"
            .encode_utf16()
            .flat_map(u16::to_le_bytes),
    );
    let mut gz = vec![0x1f, 0x8b, 8, 8, 0, 0, 0, 0, 0, 3];
    gz.extend(b"a.txt\0");
    gz.extend(miniz_oxide::deflate::compress_to_vec(b"bonjour bonjour", 6));
    gz.extend(crate::archives::crc32::crc32(b"bonjour bonjour").to_le_bytes());
    gz.extend(15u32.to_le_bytes());
    let mut tar = vec![0u8; 512];
    tar[..5].copy_from_slice(b"a.txt");
    tar[124..135].copy_from_slice(b"00000000003");
    tar[156] = b'0';
    tar[257..263].copy_from_slice(b"ustar\0");
    tar.extend(b"abc");
    tar.resize(2048, 0);
    let lnk = lnk::essais::raccourci(
        Some(&[6, 0, b'c', b'm', b'd', 0]),
        Some("C:\\Windows\\System32\\cmd.exe"),
        Some("/c x"),
        b"",
    );
    let fichier: Vec<(&str, Vec<u8>)> = vec![
        ("pe-overlay-zip.bin", pe_wx(&zip_de(&[("a.txt", 8, b"bonjour")]))),
        ("doc-vba.bin", document_vba("Macros", source, true)),
        (
            "docx-vba.bin",
            zip_de(&[
                (
                    "[Content_Types].xml",
                    8,
                    b"<Types ContentType=\"application/vnd.ms-office.vbaProject\"/>",
                ),
                ("word/vbaProject.bin", 8, &bin),
            ]),
        ),
        ("lnk.bin", lnk.clone()),
        ("elf.bin", elf::essais::elf64(7, true, 0x40_0180, b"PK\x05\x06")),
        (
            "macho-universel.bin",
            macho::essais::universel(&[macho::essais::macho64(5, false), macho::essais::macho64(7, true)]),
        ),
        ("gzip.bin", gz),
        ("tar.bin", tar),
        ("ps1-utf16.bin", ps),
        (
            "xls-xlm.bin",
            cfb::essais::fichier(&[("Workbook", Some(&office::essais::classeur(false, &[("M", 2, 1)])))]),
        ),
    ];
    let mut dir = vec![2u8];
    dir.extend(vba::essais::dir(&[("Module1", "Module1", 0, 0x21)]));
    let mut cfb_seul = vec![0u8];
    cfb_seul.extend(&bin);
    let mut ovba_seul = vec![1u8];
    ovba_seul.extend(ovba::essais::compresser(source.as_bytes()));
    let mut lnk_seul = vec![3u8];
    lnk_seul.extend(&lnk);
    let lecteurs: Vec<(&str, Vec<u8>)> = vec![
        ("cfb.bin", cfb_seul),
        ("ovba.bin", ovba_seul),
        ("dir.bin", dir),
        ("lnk.bin", lnk_seul),
    ];
    for (dossier, graines) in [("analyse_fichier", fichier), ("analyse_lecteurs", lecteurs)] {
        let d = racine.join(dossier);
        std::fs::create_dir_all(&d).unwrap();
        for (nom, octets) in graines {
            std::fs::write(d.join(nom), octets).unwrap();
        }
    }
}

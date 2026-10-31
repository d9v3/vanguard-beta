//! Le type d'un fichier, par son CONTENU (octets magiques, structure), jamais par son extension : un programme
//! renommé « facture.pdf » reste un programme. Les signatures sont celles des spécifications de chaque format (PE :
//! « MZ » puis « PE\0\0 » à e_lfanew ; ELF : 7F « ELF » ; Mach-O : FEEDFACE/FEEDFACF dans les deux ordres, CAFEBABE
//! et CAFEBABF pour les fichiers universels ; zip : en-tête local « PK\3\4 » ou fin de répertoire « PK\5\6 » ; gzip
//! 1F 8B 08 ; fichier composé D0CF11E0A1B11AE1 ; raccourci : taille 0x4C et CLSID ; tar : « ustar » en 257 ou somme
//! de contrôle juste), et celles, publiées par leurs auteurs, des formats reconnus mais pas ouverts ici (7z, RAR,
//! CAB, ISO 9660, bzip2, xz, zstd, PDF, RTF…), qui seront dits « non vérifiés ».

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use super::Type;
use super::texte;

/// Ce qu'on regarde pour deviner du texte : le reste est lu ensuite, si c'en est.
const ECHANTILLON_TEXTE: usize = 64 << 10;

/// Le type de `octets`.
pub(crate) fn deviner(octets: &[u8]) -> Type {
    if octets.is_empty() {
        return Type::Vide;
    }
    let commence = |m: &[u8]| octets.starts_with(m);
    let a = |position: usize, m: &[u8]| octets.get(position..).is_some_and(|r| r.starts_with(m));
    if commence(b"MZ") {
        let pe = super::lecture::u32le(octets, 0x3C)
            .and_then(|e| usize::try_from(e).ok())
            .is_some_and(|e| a(e, b"PE\0\0"));
        return if pe { Type::Pe } else { Type::ExecutableDos };
    }
    if commence(b"\x7fELF") {
        return Type::Elf;
    }
    if let Some(magie) = super::lecture::u32le(octets, 0) {
        use super::macho::{FAT_MAGIC, FAT_MAGIC_64, MH_MAGIC, MH_MAGIC_64};
        if matches!(magie, MH_MAGIC | MH_MAGIC_64) || matches!(magie.swap_bytes(), MH_MAGIC | MH_MAGIC_64) {
            return Type::MachO;
        }
        if matches!(magie.swap_bytes(), FAT_MAGIC | FAT_MAGIC_64) {
            // Même signature qu'une classe Java : un fichier universel a peu d'architectures, une classe a ses
            // numéros de version (45 et plus) à la place.
            let n = super::lecture::Ordre { gros_boutiste: true }
                .u32(octets, 4)
                .unwrap_or(0);
            return if (1..=super::macho::TRANCHES_MAX).contains(&n) {
                Type::MachOUniversel
            } else {
                Type::ClasseJava
            };
        }
    }
    if commence(b"PK\x03\x04") || commence(b"PK\x05\x06") || commence(b"PK\x07\x08") {
        return Type::Zip;
    }
    if commence(&[0x1f, 0x8b, 8]) {
        return Type::Gzip;
    }
    if commence(&super::cfb::SIGNATURE) {
        return Type::Cfb;
    }
    if commence(&[0x4C, 0, 0, 0]) && a(4, &super::lnk::CLSID) {
        return Type::Lnk;
    }
    if a(257, b"ustar") || tar_v7(octets) {
        return Type::Tar;
    }
    let non_lus: &[(&[u8], Type)] = &[
        (b"7z\xBC\xAF\x27\x1C", Type::SeptZip),
        (b"Rar!\x1A\x07\x00", Type::Rar),
        (b"Rar!\x1A\x07\x01\x00", Type::Rar),
        (b"MSCF\0\0\0\0", Type::Cab),
        (b"\xFD7zXZ\0", Type::Xz),
        (b"\x28\xB5\x2F\xFD", Type::Zstd),
        (b"{\\rtf", Type::Rtf),
        (b"ITSF", Type::Chm),
        (b"MSWIM\0\0\0", Type::Wim),
        (b"vhdxfile", Type::DisqueVirtuel),
        (b"conectix", Type::DisqueVirtuel),
        (b"xar!", Type::Xar),
        (b"!<arch>\n", Type::Ar),
        (b"\xED\xAB\xEE\xDB", Type::Rpm),
        (b"hsqs", Type::SquashFs),
        (b"070701", Type::Cpio),
        (b"070702", Type::Cpio),
        (b"070707", Type::Cpio),
        (b"LZIP", Type::Lzip),
        // OneNote : le GUID de section {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3}.
        (
            &[
                0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D, 0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3,
            ],
            Type::OneNote,
        ),
    ];
    for (signature, type_) in non_lus {
        if commence(signature) {
            return *type_;
        }
    }
    if commence(b"BZh") && octets.get(3).is_some_and(|c| (b'1'..=b'9').contains(c)) {
        return Type::Bzip2;
    }
    if iso(octets) {
        return Type::Iso;
    }
    // Une image disque d'Apple ou un disque virtuel : la signature est dans les 512 derniers octets.
    if let Some(queue) = octets.len().checked_sub(512) {
        // « koly », version 4, taille de l'en-tête 512 (gros-boutistes) : « koly » seul est un mot tchèque.
        if a(queue, b"koly\0\0\0\x04\0\0\x02\0") {
            return Type::Dmg;
        }
        if a(queue, b"conectix") {
            return Type::DisqueVirtuel;
        }
    }
    if pdf_au_debut(octets) {
        return Type::Pdf;
    }
    let inertes: &[(&[u8], Type)] = &[
        (b"\x89PNG\r\n\x1a\n", Type::Image),
        (b"\xFF\xD8\xFF", Type::Image),
        (b"GIF87a", Type::Image),
        (b"GIF89a", Type::Image),
        (b"\0\0\x01\0", Type::Image),
        (b"II*\0", Type::Image),
        (b"MM\0*", Type::Image),
        (b"ID3", Type::Media),
        (b"OggS", Type::Media),
        (b"fLaC", Type::Media),
        (b"\x1A\x45\xDF\xA3", Type::Media),
        (b"\0\x01\0\0\0", Type::Police),
        (b"OTTO", Type::Police),
        (b"wOFF", Type::Police),
        (b"wOF2", Type::Police),
        (b"SQLite format 3\0", Type::Sqlite),
        (b"\0asm", Type::Wasm),
    ];
    for (signature, type_) in inertes {
        if commence(signature) {
            return *type_;
        }
    }
    // BMP : « BM » puis, en 14, la taille d'un en-tête d'image connu (« BM » seul commence bien des textes).
    if commence(b"BM")
        && super::lecture::u32le(octets, 14).is_some_and(|t| matches!(t, 12 | 40 | 52 | 56 | 64 | 108 | 124))
    {
        return Type::Image;
    }
    if commence(b"RIFF") && a(8, b"WEBP") {
        return Type::Image;
    }
    if commence(b"RIFF") && (a(8, b"WAVE") || a(8, b"AVI ")) || a(4, b"ftyp") {
        return Type::Media;
    }
    match texte::lire(octets.get(..ECHANTILLON_TEXTE).unwrap_or(octets), ECHANTILLON_TEXTE) {
        Some(t) if t.langage == texte::Langage::Texte => Type::Texte,
        Some(t) => Type::Script(t.langage),
        None => Type::Inconnu,
    }
}

/// ISO 9660 et UDF : le descripteur de volume au secteur 16 (« CD001 », « BEA01 »…), et ses copies.
pub(crate) fn iso(octets: &[u8]) -> bool {
    let a = |position: usize, m: &[u8]| octets.get(position..).is_some_and(|r| r.starts_with(m));
    [0x8001usize, 0x8801, 0x9001]
        .iter()
        .any(|&p| a(p, b"CD001") || a(p, b"BEA01") || a(p, b"NSR02") || a(p, b"NSR03"))
}

/// Un PDF : l'en-tête peut être n'importe où dans le premier Kio (les lecteurs le cherchent là).
pub(crate) fn pdf_au_debut(octets: &[u8]) -> bool {
    octets.get(..1024).unwrap_or(octets).windows(5).any(|f| f == b"%PDF-")
}

/// La fin d'un PNG : après son morceau IEND (chaque morceau : longueur sur 32 bits gros-boutiste, type, données,
/// CRC). `None` : pas un PNG, ou pas de IEND dans le fichier.
pub(crate) fn fin_png(octets: &[u8]) -> Option<usize> {
    if !octets.starts_with(b"\x89PNG\r\n\x1a\n") {
        return None;
    }
    let o = super::lecture::Ordre { gros_boutiste: true };
    let mut p = 8usize;
    loop {
        let n = usize::try_from(o.u32(octets, p)?).ok()?;
        let type_ = octets.get(p..)?.get(4..8)?;
        let suivant = p.checked_add(12)?.checked_add(n)?;
        if suivant > octets.len() {
            return None;
        }
        if type_ == b"IEND" {
            return Some(suivant);
        }
        p = suivant;
    }
}

/// La fin d'une image (PNG, JPEG, GIF, BMP, ICO, WebP) : là où son format dit qu'elle finit. Un lecteur d'images
/// s'arrête là, un extracteur d'archives cherche sa signature au-delà : une archive collée derrière une photo passe
/// pour la photo. `None` : un format dont la fin ne se calcule pas ici (TIFF, dont les données sont n'importe où), ou
/// une image coupée ou abîmée avant sa fin.
pub(crate) fn fin_image(octets: &[u8]) -> Option<usize> {
    let fin = if octets.starts_with(b"\x89PNG\r\n\x1a\n") {
        fin_png(octets)?
    } else if octets.starts_with(b"\xFF\xD8\xFF") {
        fin_jpeg(octets)?
    } else if octets.starts_with(b"GIF87a") || octets.starts_with(b"GIF89a") {
        fin_gif(octets)?
    } else if octets.starts_with(b"BM") {
        // bfSize : la taille du fichier, écrite par tout éditeur (un zéro n'apprend rien).
        usize::try_from(super::lecture::u32le(octets, 2)?)
            .ok()
            .filter(|&n| n >= 26)?
    } else if octets.starts_with(b"\0\0\x01\0") {
        fin_ico(octets)?
    } else if octets.starts_with(b"RIFF") && octets.get(8..12) == Some(b"WEBP") {
        let n = usize::try_from(super::lecture::u32le(octets, 4)?).ok()?;
        8usize.checked_add(n)?.checked_add(n & 1)?
    } else {
        return None;
    };
    (fin <= octets.len()).then_some(fin)
}

/// JPEG (ITU T.81, annexe B) : des segments (FF, code, longueur sur 16 bits gros-boutiste, sauf les marqueurs seuls),
/// et après chaque début de balayage (SOS, FFDA) les données compressées, où FF n'est suivi que de 00 ou d'un
/// marqueur de reprise (FFD0-FFD7) ; la fin est FFD9 (EOI).
fn fin_jpeg(o: &[u8]) -> Option<usize> {
    let mut p = 2usize;
    loop {
        if *o.get(p)? != 0xFF {
            return None;
        }
        while *o.get(p)? == 0xFF {
            p = p.checked_add(1)?;
        }
        let code = *o.get(p)?;
        p = p.checked_add(1)?;
        match code {
            0xD9 => return Some(p),
            0x01 | 0xD0..=0xD7 => {}
            0x00 | 0xD8 => return None,
            _ => {
                let n = usize::from(u16::from_be_bytes([*o.get(p)?, *o.get(p.checked_add(1)?)?]));
                if n < 2 {
                    return None;
                }
                p = p.checked_add(n)?;
                if code == 0xDA {
                    // Les données du balayage, jusqu'au prochain vrai marqueur.
                    loop {
                        let q = p.checked_add(o.get(p..)?.iter().position(|&b| b == 0xFF)?)?;
                        match *o.get(q.checked_add(1)?)? {
                            0x00 | 0xD0..=0xD7 => p = q.checked_add(2)?,
                            0xFF => p = q.checked_add(1)?,
                            _ => {
                                p = q;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}

/// GIF (spécification 89a) : écran logique et table de couleurs globale, puis des blocs (image 0x2C, extension
/// 0x21), chacun suivi de sous-blocs (un octet de taille, 0 pour finir), jusqu'au bloc de fin 0x3B.
fn fin_gif(o: &[u8]) -> Option<usize> {
    let table = |drapeaux: u8| {
        if drapeaux & 0x80 != 0 {
            // 3 << (taille + 1) : 6 à 768 octets.
            6usize << (drapeaux & 7)
        } else {
            0
        }
    };
    let mut p = 13usize.checked_add(table(*o.get(10)?))?;
    let sous_blocs = |mut p: usize| -> Option<usize> {
        loop {
            let n = usize::from(*o.get(p)?);
            p = p.checked_add(1)?;
            if n == 0 {
                return Some(p);
            }
            p = p.checked_add(n)?;
        }
    };
    loop {
        match *o.get(p)? {
            0x3B => return p.checked_add(1),
            0x21 => p = sous_blocs(p.checked_add(2)?)?,
            0x2C => {
                let drapeaux = *o.get(p.checked_add(9)?)?;
                p = p.checked_add(10)?.checked_add(table(drapeaux))?.checked_add(1)?;
                p = sous_blocs(p)?;
            }
            _ => return None,
        }
    }
}

/// ICO : un répertoire d'images (16 octets chacune : taille en 8, position en 12) ; la fin est celle de l'image qui
/// finit le plus loin.
fn fin_ico(o: &[u8]) -> Option<usize> {
    let n = usize::from(super::lecture::u16le(o, 4)?);
    let mut fin = 6usize.checked_add(16 * n)?;
    for k in 0..n {
        let e = o.get(6..)?.get(k.checked_mul(16)?..)?;
        let taille = usize::try_from(super::lecture::u32le(e, 8)?).ok()?;
        let position = usize::try_from(super::lecture::u32le(e, 12)?).ok()?;
        fin = fin.max(position.checked_add(taille)?);
    }
    Some(fin)
}

/// Une archive d'un format non lu ici (RAR, 7z, CAB, xz) placée après le début de `octets` : sa position. Pour les
/// formats « inertes » dont la fin ne se calcule pas (TIFF, sons, vidéos, polices, bases SQLite, WebAssembly) et
/// l'intérieur des images, qu'un extracteur ouvrirait pourtant par cette signature. Les signatures sont longues (6 à
/// 8 octets) : une rencontre par hasard est négligeable.
pub(crate) fn archive_cachee(octets: &[u8]) -> Option<usize> {
    const SIGNATURES: [&[u8]; 4] = [b"Rar!\x1A\x07", b"7z\xBC\xAF\x27\x1C", b"MSCF\0\0\0\0", b"\xFD7zXZ\0"];
    SIGNATURES
        .iter()
        .filter_map(|s| octets.get(1..)?.windows(s.len()).position(|f| f == *s)?.checked_add(1))
        .min()
}

/// Un en-tête tar d'avant ustar : la somme de ses octets (le champ de contrôle compté en espaces) égale à la valeur
/// octale de ce champ, et un nom non vide.
fn tar_v7(octets: &[u8]) -> bool {
    let Some(entete) = octets.first_chunk::<512>() else {
        return false;
    };
    if entete[0] == 0 {
        return false;
    }
    let champ = &entete[148..156];
    let Ok(texte) = std::str::from_utf8(champ) else {
        return false;
    };
    let texte = texte.trim_matches(|c| c == ' ' || c == '\0');
    let Ok(attendue) = u32::from_str_radix(texte, 8) else {
        return false;
    };
    let somme: u32 = entete
        .iter()
        .enumerate()
        .map(|(i, &o)| if (148..156).contains(&i) { 32 } else { u32::from(o) })
        .sum();
    !texte.is_empty() && somme == attendue
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn par_le_contenu() {
        let mut pe = vec![0u8; 0x80];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3C] = 0x40;
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        assert_eq!(deviner(&pe), Type::Pe);
        assert_eq!(deviner(b"MZ\x90\0"), Type::ExecutableDos);
        assert_eq!(deviner(b"\x7fELF\x02\x01"), Type::Elf);
        assert_eq!(deviner(&[0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1]), Type::MachO);
        assert_eq!(deviner(&[0xfe, 0xed, 0xfa, 0xce, 0, 0, 0, 18]), Type::MachO);
        assert_eq!(deviner(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2]), Type::MachOUniversel);
        assert_eq!(deviner(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 65]), Type::ClasseJava);
        assert_eq!(deviner(b"PK\x03\x04\x14\0"), Type::Zip);
        assert_eq!(deviner(&[0x1f, 0x8b, 8, 0]), Type::Gzip);
        assert_eq!(deviner(&super::super::cfb::SIGNATURE), Type::Cfb);
        assert_eq!(deviner(b"7z\xBC\xAF\x27\x1C\0\x04"), Type::SeptZip);
        assert_eq!(deviner(b"Rar!\x1A\x07\x01\0"), Type::Rar);
        assert_eq!(deviner(b"MSCF\0\0\0\0\x10"), Type::Cab);
        assert_eq!(deviner(b"BZh91AY"), Type::Bzip2);
        assert_eq!(deviner(b"%PDF-1.7\n"), Type::Pdf);
        let mut iso = vec![0u8; 0x9000];
        iso[0x8001..0x8006].copy_from_slice(b"CD001");
        assert_eq!(deviner(&iso), Type::Iso);
        assert_eq!(deviner(b"\x89PNG\r\n\x1a\n"), Type::Image);
        assert_eq!(
            deviner(b"@echo off\r\nset /a x=1\r\n"),
            Type::Script(texte::Langage::Batch)
        );
        assert_eq!(deviner(b"Une lettre.\n"), Type::Texte);
        assert_eq!(deviner(&[0x00, 0x01, 0x02, 0x03, 0xff, 0x10]), Type::Inconnu);
        assert_eq!(deviner(b""), Type::Vide);
        // L'extension n'y est pour rien : seul le contenu compte (le nom n'est même pas donné).
    }

    #[test]
    fn tar_par_sa_somme() {
        let mut entete = [0u8; 512];
        entete[..5].copy_from_slice(b"a.txt");
        entete[124..135].copy_from_slice(b"00000000003");
        let somme: u32 = entete.iter().map(|&o| u32::from(o)).sum::<u32>() + 8 * 32;
        entete[148..155].copy_from_slice(format!("{somme:06o}\0").as_bytes());
        assert_eq!(deviner(&entete), Type::Tar);
        entete[0] ^= 1;
        assert_ne!(deviner(&entete), Type::Tar);
    }
}

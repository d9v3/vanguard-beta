//! Les lecteurs propres à l'analyse, seuls (src/analyse/) : fichiers composés OLE ([MS-CFB] : DIFAT, FAT et
//! mini-FAT qui bouclent, arbre qui revient sur lui-même), compression VBA ([MS-OVBA] : copies hors du tampon),
//! flux « dir » d'un projet VBA, raccourcis ([MS-SHLLINK]), parties XML d'un document OOXML (encodages, entités,
//! relations), en-têtes ELF (section dynamique, propriétés GNU) et Mach-O, que relit aussi `vanguard deploiement
//! verifier-binaire`. Le premier octet choisit le lecteur.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/, cales) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../src/analyse/lecture.rs"]
mod lecture;

#[allow(dead_code)]
#[path = "../../src/analyse/cfb.rs"]
mod cfb;

#[allow(dead_code)]
#[path = "../../src/analyse/ovba.rs"]
mod ovba;

#[allow(dead_code)]
#[path = "../../src/analyse/vba.rs"]
mod vba;

#[allow(dead_code)]
#[path = "../../src/analyse/lnk.rs"]
mod lnk;

#[allow(dead_code)]
#[path = "../../src/analyse/office.rs"]
mod office;

#[allow(dead_code)]
#[path = "../../src/analyse/elf.rs"]
mod elf;

#[allow(dead_code)]
#[path = "../../src/analyse/macho.rs"]
mod macho;

const LIMITE: usize = 1 << 18;

libfuzzer_sys::fuzz_target!(|donnees: &[u8]| {
    let Some((&choix, octets)) = donnees.split_first() else { return };
    // Les exécutables sur les derniers choix : ceux d'avant gardent leur lecteur, et le corpus appris son sens.
    if choix >= 250 {
        if let Some(e) = elf::lire(octets) {
            assert!(e.fin_des_donnees <= octets.len() as u64);
            assert!(!(e.dynamique.is_some() && e.dynamique_illisible));
            for s in &e.segments {
                let _ = elf::dans_un_load_ecrivable(&e.segments, s);
                // Quelques paires seulement : jusqu'à 4096 segments, toutes les paires ralentiraient le banc.
                for t in e.segments.iter().take(8) {
                    let _ = elf::contient(s, t);
                }
            }
        }
        if let Some(u) = macho::universel(octets) {
            for t in &u.tranches {
                let _ = octets
                    .get(t.position as usize..)
                    .and_then(|r| r.get(..t.taille as usize))
                    .and_then(macho::lire);
            }
        }
        if let Some(m) = macho::lire(octets) {
            // Une signature ne peut tenir dans le fichier sans avoir été annoncée.
            assert!(m.signature || !m.signature_dans_le_fichier);
        }
        return;
    }
    match choix % 5 {
        0 => {
            if let Ok(c) = cfb::Cfb::lire(octets, LIMITE) {
                for k in 0..c.entrees.len().min(64) {
                    if let Ok(f) = c.flux(k, LIMITE) {
                        assert!(f.len() <= LIMITE);
                    }
                }
                assert!(c.places.len() + c.orphelines.len() <= c.entrees.len());
            }
        }
        1 => {
            let d = ovba::decompresser(octets, LIMITE);
            assert!(d.contenu.len() <= LIMITE);
            let source = String::from_utf8_lossy(&d.contenu);
            let _ = vba::procedures_automatiques(&source, "AutoOpen");
            let _ = vba::source_sans_code(&source);
        }
        4 => {
            let texte = office::texte_xml(octets);
            let (cibles, _) = office::relations_externes_bornees(&texte);
            assert!(cibles.len() <= 256);
            let _ = office::types_de_contenu(&texte);
        }
        2 => {
            let p = vba::lire_dir(octets);
            assert!(p.modules.len() <= 4096);
        }
        _ => {
            if let Some(l) = lnk::lire(octets) {
                assert!(l.fin <= octets.len());
                let _ = (l.cible(), l.cible_approchee(), l.interpreteurs(), l.arguments_rembourres());
            }
        }
    }
});

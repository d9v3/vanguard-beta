//! Les lecteurs propres à l'analyse, seuls (src/analyse/) : fichiers composés OLE ([MS-CFB] : DIFAT, FAT et
//! mini-FAT qui bouclent, arbre qui revient sur lui-même), compression VBA ([MS-OVBA] : copies hors du tampon),
//! flux « dir » d'un projet VBA, raccourcis ([MS-SHLLINK]). Le premier octet choisit le lecteur.
#![no_main]

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

const LIMITE: usize = 1 << 18;

libfuzzer_sys::fuzz_target!(|donnees: &[u8]| {
    let Some((&choix, octets)) = donnees.split_first() else { return };
    match choix % 4 {
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
            let _ = vba::procedures_automatiques(&String::from_utf8_lossy(&d.contenu), "AutoOpen");
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

//! La lecture native des bases ClamAV (src/protection/clamav/) : conteneurs .cvd et .cld (en-tête, gzip, tar, liste
//! .info), signatures d'empreintes (.hdb, .hsb, .mdb…), de corps (.ndb), logiques (.ldb), listes blanches et
//! signatures ignorées. Une base est un fichier venu d'ailleurs : jamais de panique, aucune allocation sans borne, et
//! ce qui est chargé s'applique ensuite à quelques données sans dépasser son délai.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/, cales) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

#[allow(dead_code)]
#[path = "../../src/archives/mod.rs"]
mod archives;

// Les modules purs de la lecture, à la racine : ils se citent par `super::`, qui est ici la racine comme
// src/protection/clamav/ l'est pour eux dans Vanguard. Le reste (base.rs : la confiance par le propriétaire des
// fichiers, l'examen d'un fichier) touche la machine et n'est pas inclus.
#[allow(dead_code)]
#[path = "../../src/protection/clamav/commun.rs"]
mod commun;
#[allow(dead_code)]
#[path = "../../src/protection/clamav/corps.rs"]
mod corps;
#[allow(dead_code)]
#[path = "../../src/protection/clamav/cvd.rs"]
mod cvd;
#[allow(dead_code)]
#[path = "../../src/protection/clamav/fp.rs"]
mod fp;
#[allow(dead_code)]
#[path = "../../src/protection/clamav/hashes.rs"]
mod hashes;
#[allow(dead_code)]
#[path = "../../src/protection/clamav/ldb.rs"]
mod ldb;
#[allow(dead_code)]
#[path = "../../src/protection/clamav/ndb.rs"]
mod ndb;
#[allow(dead_code)]
#[path = "../../src/protection/clamav/signatures.rs"]
mod signatures;

// Le moteur de recherche qu'ils partagent avec YARA, à la place où ils le cherchent (`crate::protection::motifs`).
#[allow(dead_code)]
#[path = "../../src/protection/motifs.rs"]
mod motifs;
mod protection {
    pub(crate) use super::motifs;
}

use commun::Cible;
use corps::Cadre;
use signatures::{Chargement, Mode, Options};

/// Le premier octet choisit la sorte du fichier : le fuzzer n'a pas à deviner une extension.
const SORTES: [&str; 16] = [
    "essai.hdb",
    "essai.hsb",
    "essai.hdu",
    "essai.mdb",
    "essai.msb",
    "essai.ndb",
    "essai.ndu",
    "essai.ldb",
    "essai.ldu",
    "essai.fp",
    "essai.sfp",
    "essai.ign",
    "essai.ign2",
    "essai.cdb",
    "essai.cvd",
    "essai.cld",
];

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let Some((&choix, contenu)) = octets.split_first() else {
        return;
    };
    let nom = SORTES[usize::from(choix) % SORTES.len()];
    // Un conteneur : lu comme une base de freshclam, puis ses membres chargés comme les fichiers à part.
    let mut membres: Vec<(String, Vec<u8>)> = Vec::new();
    if nom.ends_with(".cvd") || nom.ends_with(".cld") {
        let _ = cvd::en_tete(contenu);
        let Ok(base) = cvd::lire(contenu.to_vec()) else {
            return;
        };
        assert!(base.membres().count() <= 10_000);
        membres.extend(base.membres().map(|(n, o)| (n.to_owned(), o.to_vec())));
    } else {
        membres.push((nom.to_owned(), contenu.to_vec()));
    }
    for options in [
        Options {
            mode: Mode::Complete,
            pua: choix & 0x80 != 0,
        },
        Options {
            mode: Mode::Empreintes,
            pua: false,
        },
    ] {
        let mut chargement = Chargement::nouveau(options);
        for (n, o) in &membres {
            chargement.ignorer(n, o);
        }
        for (n, o) in &membres {
            chargement.ajouter(n, o);
        }
        let signatures = chargement.finir();
        // La liste binaire (celle qu'un programme en administrateur lirait) ne garde que des SHA-256 entiers, et se
        // relit telle quelle.
        let liste = signatures.liste_sha256();
        let n = liste.len() / 32;
        let l = hashes::ListeSha256::lire(liste).expect("la liste produite se relit");
        assert_eq!(l.nombre(), n);
        if signatures.nombre() == 0 {
            continue;
        }
        let echeance = Some(Instant::now() + Duration::from_secs(2));
        for (donnees, cible) in [
            (&b"MZ\x90\x00 vanguard"[..], Cible::Pe),
            (b"\x7fELF\x02\x01\x01", Cible::Elf),
            (contenu, Cible::Tout),
        ] {
            let cadre = Cadre {
                point_entree: Some(2),
                sections: vec![(0, 4), (4, 1 << 20)],
                ..Cadre::simple(cible)
            };
            let _ = signatures.juger(donnees, &cadre, echeance);
            let _ = signatures.juger(donnees, &Cadre::simple(cible), echeance);
            let e = hashes::Empreintes::de(donnees);
            let _ = signatures.par_empreintes(&e, donnees.len() as u64);
            let _ = signatures.par_sha256(&e.sha256);
        }
    }
});

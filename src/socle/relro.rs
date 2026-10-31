//! RELRO appliqué par Vanguard lui-même, au démarrage. Le programme Linux livré est un static-pie musl : son
//! démarrage (rcrt1, `_dlstart_c`) fait les relocalisations, puis laisse PT_GNU_RELRO écrivable, car il n'appelle
//! jamais mprotect. La marque de l'éditeur de liens (PT_GNU_RELRO et BIND_NOW), que contrôle `verifier-binaire`, ne
//! protégeait donc rien : la GOT, `.data.rel.ro`, `.init_array`… restaient rw-p pendant toute la vie du processus,
//! une cible pour qui aurait trouvé une écriture arbitraire. On fait ici ce que fait `_dl_protect_relro` de glibc
//! pour un programme dynamique : retirer l'écriture, page par page, sur ce segment.
//!
//! Sous glibc dynamique (les essais, un `cargo run` sur la cible gnu), ld.so l'a déjà fait : le refaire sur une
//! plage déjà en lecture seule ne change rien.

// FFI de libc : dl_iterate_phdr, getauxval et mprotect n'ont pas d'équivalent dans std.
#![allow(unsafe_code)]

use crate::tr;

/// Pourquoi la protection n'a pas été posée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Echec {
    /// AT_PAGESZ absent, ou pas une puissance de deux.
    Page,
    /// Les en-têtes du programme principal (ceux de AT_PHDR) ne sont pas dans la liste de dl_iterate_phdr.
    Entetes,
    /// L'adresse du segment déborde : des en-têtes incohérents.
    Adresse,
    /// mprotect a refusé (errno).
    Mprotect(i32),
}

impl std::fmt::Display for Echec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Echec::Page => f.write_str(tr!(
                "taille de page inconnue (AT_PAGESZ)",
                "unknown page size (AT_PAGESZ)"
            )),
            Echec::Entetes => f.write_str(tr!(
                "en-têtes du programme introuvables (AT_PHDR)",
                "program headers not found (AT_PHDR)"
            )),
            Echec::Adresse => f.write_str(tr!(
                "segment PT_GNU_RELRO hors de l'espace d'adresses",
                "PT_GNU_RELRO segment outside the address space"
            )),
            Echec::Mprotect(errno) => write!(
                f,
                "{} {}",
                tr!("mprotect refusé, errno", "mprotect refused, errno"),
                errno
            ),
        }
    }
}

/// La plage à protéger, comme `_dl_protect_relro` de glibc : début et fin arrondis tous deux à la page inférieure.
/// La dernière page, partagée avec `.data` quand le segment ne finit pas sur une page, reste écrivable : la protéger
/// rendrait `.data` en lecture seule. `None` : rien à protéger (moins d'une page), ou une adresse qui déborde.
/// `page` doit être une puissance de deux.
fn plage(base: usize, adresse: usize, taille: usize, page: usize) -> Option<(usize, usize)> {
    let masque = !page.checked_sub(1)?;
    let debut = base.checked_add(adresse)?;
    let fin = debut.checked_add(taille)?;
    let (debut, fin) = (debut & masque, fin & masque);
    (debut < fin).then_some((debut, fin))
}

/// Ce que le rappel de dl_iterate_phdr retient du programme principal.
struct Recherche {
    /// AT_PHDR : l'adresse de ses en-têtes, qui le distingue des bibliothèques (glibc) et du vDSO.
    phdr: usize,
    trouve: bool,
    base: usize,
    /// (p_vaddr, p_memsz) de PT_GNU_RELRO, s'il y en a un.
    relro: Option<(u64, u64)>,
}

/// Le rappel de dl_iterate_phdr. Il ne doit jamais paniquer (une panique ne traverse pas une frontière « C » : le
/// processus avorterait) : ni indexation, ni unwrap.
unsafe extern "C" fn rappel(
    info: *mut libc::dl_phdr_info,
    _taille: libc::size_t,
    donnees: *mut libc::c_void,
) -> libc::c_int {
    // SAFETY: `donnees` est le `&mut Recherche` que `proteger` passe à dl_iterate_phdr, vivant et à nous seuls pendant
    // tout l'appel ; `info` est fourni par libc, valide pendant le rappel, et vérifié non nul.
    let (recherche, info) = unsafe {
        match (donnees.cast::<Recherche>().as_mut(), info.as_ref()) {
            (Some(r), Some(i)) => (r, i),
            _ => return 0,
        }
    };
    if info.dlpi_phdr.is_null() || info.dlpi_phdr.addr() != recherche.phdr {
        return 0;
    }
    // SAFETY: libc garantit que `dlpi_phdr` désigne `dlpi_phnum` en-têtes chargés en mémoire, lisibles et alignés, pour
    // toute la vie de l'objet (ici le programme lui-même) ; le pointeur est non nul (vérifié plus haut).
    let entetes = unsafe { std::slice::from_raw_parts(info.dlpi_phdr, usize::from(info.dlpi_phnum)) };
    let Ok(base) = usize::try_from(info.dlpi_addr) else {
        return 0;
    };
    recherche.trouve = true;
    recherche.base = base;
    recherche.relro = entetes
        .iter()
        .find(|e| e.p_type == libc::PT_GNU_RELRO)
        .map(|e| (e.p_vaddr, e.p_memsz));
    // Trouvé : on arrête le parcours.
    1
}

/// Retire l'écriture sur le segment PT_GNU_RELRO du programme. `Ok(Some((début, fin)))` : la plage protégée ;
/// `Ok(None)` : pas de segment, ou plus petit qu'une page.
pub(crate) fn proteger() -> Result<Option<(usize, usize)>, Echec> {
    // SAFETY: getauxval lit le vecteur auxiliaire que le noyau a donné au processus ; 0 si la clé est absente.
    let (phdr, page) = unsafe { (libc::getauxval(libc::AT_PHDR), libc::getauxval(libc::AT_PAGESZ)) };
    let page = usize::try_from(page)
        .ok()
        .filter(|p| p.is_power_of_two())
        .ok_or(Echec::Page)?;
    let phdr = usize::try_from(phdr).ok().filter(|&p| p != 0).ok_or(Echec::Entetes)?;
    let mut recherche = Recherche {
        phdr,
        trouve: false,
        base: 0,
        relro: None,
    };
    // SAFETY: `rappel` respecte la signature attendue et ne panique pas ; `recherche` vit jusqu'au retour de
    // dl_iterate_phdr, qui ne garde pas le pointeur après.
    unsafe { libc::dl_iterate_phdr(Some(rappel), (&raw mut recherche).cast()) };
    if !recherche.trouve {
        return Err(Echec::Entetes);
    }
    let Some((adresse, taille)) = recherche.relro else {
        return Ok(None);
    };
    let adresse = usize::try_from(adresse).map_err(|_| Echec::Adresse)?;
    let taille = usize::try_from(taille).map_err(|_| Echec::Adresse)?;
    let Some((debut, fin)) = plage(recherche.base, adresse, taille, page) else {
        return if recherche
            .base
            .checked_add(adresse)
            .and_then(|d| d.checked_add(taille))
            .is_some()
        {
            Ok(None)
        } else {
            Err(Echec::Adresse)
        };
    };
    // SAFETY: la plage est alignée sur la page et faite de pages du programme lui-même, déjà relocalisées. Rien de
    // ce que Rust peut écrire n'y vit : `.data.rel.ro`, la GOT, `.init_array`/`.fini_array` et `.dynamic` ne sont
    // écrits que par le démarrage, déjà fini ; `.tdata` n'est que le modèle que libc recopie pour chaque fil. Une
    // statique modifiable (`static mut`, `UnsafeCell`) va dans `.data` ou `.bss`, jamais ici.
    let r = unsafe {
        libc::mprotect(
            std::ptr::with_exposed_provenance_mut(debut),
            fin.wrapping_sub(debut),
            libc::PROT_READ,
        )
    };
    if r != 0 {
        return Err(Echec::Mprotect(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        ));
    }
    Ok(Some((debut, fin)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plage_arrondie_comme_glibc() {
        // Le cas du programme livré : base 0x7f00_0000_0000, segment à 0x1398a98 de 0x5b568 octets.
        let base = 0x7f00_0000_0000;
        assert_eq!(
            plage(base, 0x0139_8a98, 0x0005_b568, 0x1000),
            Some((base + 0x0139_8000, base + 0x013f_4000))
        );
        // Moins d'une page, dans une seule page : rien.
        assert_eq!(plage(0, 0x1010, 0x20, 0x1000), None);
        assert_eq!(plage(0, 0x1000, 0, 0x1000), None);
        // Exactement une page.
        assert_eq!(plage(0, 0x1000, 0x1000, 0x1000), Some((0x1000, 0x2000)));
        // Débordement : rien, sans panique.
        assert_eq!(plage(usize::MAX, 1, 1, 0x1000), None);
        assert_eq!(plage(0, usize::MAX, 0x2000, 0x1000), None);
        assert_eq!(plage(0, 0x1000, 0x1000, 0), None);
    }

    /// Les permissions des mappages qui couvrent [début, fin), lues dans /proc/self/maps.
    pub(crate) fn droits(maps: &str, debut: usize, fin: usize) -> Vec<String> {
        maps.lines()
            .filter_map(|l| {
                let (plage, reste) = l.split_once(' ')?;
                let (a, b) = plage.split_once('-')?;
                let (a, b) = (usize::from_str_radix(a, 16).ok()?, usize::from_str_radix(b, 16).ok()?);
                (a < fin && b > debut).then(|| reste.split(' ').next().unwrap_or("").to_owned())
            })
            .collect()
    }

    /// Après `proteger`, toute la plage RELRO du programme des essais est en lecture seule dans /proc/self/maps.
    /// Sous musl (la cible des essais), elle était rw-p avant : c'est ce que ce correctif change.
    #[test]
    fn relro_en_lecture_seule_apres_proteger() {
        let Some((debut, fin)) = proteger().unwrap() else {
            return crate::essais::saute("le programme des essais n'a pas de PT_GNU_RELRO d'au moins une page");
        };
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        let d = droits(&maps, debut, fin);
        assert!(!d.is_empty(), "{debut:#x}-{fin:#x} absent de /proc/self/maps");
        assert!(d.iter().all(|p| p.starts_with("r-")), "{debut:#x}-{fin:#x} : {d:?}");
        // Deux fois : sans effet, sans erreur.
        assert_eq!(proteger().unwrap(), Some((debut, fin)));
    }
}

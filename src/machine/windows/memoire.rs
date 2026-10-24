//! La mémoire des processus de Windows, lue et jamais écrite (VirtualQueryEx, ReadProcessMemory), pour le scan YARA
//! de la mémoire (`protection::memoire`). Un processus protégé (LSASS, antivirus, tout PPL) n'est jamais ouvert en
//! lecture : son niveau se lit d'abord avec les seuls droits « limités », et tout niveau autre que « aucun » l'exclut,
//! comme un niveau qui ne se lit pas. Jamais d'écriture, d'injection, de suspension, de MiniDump ni de
//! SeDebugPrivilege : lire la mémoire d'autrui ressemble déjà assez à un vol d'identifiants pour ne rien y ajouter.
//! Le dossier System32 est lu ici aussi : un processus au nom critique n'est écarté que si son programme y est.

use std::ffi::c_void;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{
    GetProcessInformation, OpenProcess, PROCESS_PROTECTION_LEVEL_INFORMATION, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ, PROTECTION_LEVEL_NONE, ProcessProtectionLevelInfo,
};

use crate::protection::memoire::{Region, Releve, image_windows, lisible_windows, region_windows, regrouper};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn VirtualQueryEx(
        processus: *mut c_void,
        adresse: *const c_void,
        information: *mut Information,
        taille: usize,
    ) -> usize;
    fn ReadProcessMemory(
        processus: *mut c_void,
        adresse: *const c_void,
        tampon: *mut c_void,
        taille: usize,
        lus: *mut usize,
    ) -> i32;
    fn GetSystemDirectoryW(tampon: *mut u16, taille: u32) -> u32;
    fn K32QueryWorkingSetEx(processus: *mut c_void, pages: *mut PageEx, taille: u32) -> i32;
    fn K32GetMappedFileNameW(processus: *mut c_void, adresse: *const c_void, nom: *mut u16, taille: u32) -> u32;
    fn GetFileAttributesW(nom: *const u16) -> u32;
    fn GetLastError() -> u32;
}

/// PSAPI_WORKING_SET_EX_INFORMATION (psapi.h) : l'adresse d'une page, puis ses attributs
/// (PSAPI_WORKING_SET_EX_BLOCK, un ULONG_PTR de champs de bits), remplis par QueryWorkingSetEx.
#[repr(C)]
#[derive(Clone, Copy)]
struct PageEx {
    adresse: *mut c_void,
    attributs: usize,
}

const MEM_IMAGE: u32 = 0x100_0000;
const PAGE: usize = 4096;
/// Les pages demandées d'un coup à QueryWorkingSetEx.
const PAGES_PAR_APPEL: usize = 4096;
/// Une image plus grande n'est pas examinée page à page : non vérifiée.
const PAGES_PAR_IMAGE_MAX: usize = (64 << 20) / PAGE;

/// MEMORY_BASIC_INFORMATION (winnt.h), telle que VirtualQueryEx la remplit sur x86_64.
#[repr(C)]
struct Information {
    base: *mut c_void,
    base_allocation: *mut c_void,
    protection_allocation: u32,
    partition: u16,
    taille: usize,
    etat: u32,
    protection: u32,
    sorte: u32,
}

/// Le niveau de protection d'un processus, lu avec les seuls droits « limités » : `Some(true)` protégé (PPL, LSA,
/// antimalware…), `Some(false)` aucun. `None` : le processus ne s'ouvre pas (autre compte, sans élévation) ou Windows
/// ne dit pas son niveau (avant 8.1) ; dans les deux cas, il n'est pas lu.
pub(crate) fn protege(pid: u32) -> Option<bool> {
    // SAFETY : la poignée vient d'OpenProcess (Err : refus) et est refermée une seule fois ; la structure reçue a la
    // taille annoncée à Windows, qui n'écrit rien au-delà.
    unsafe {
        let poignee = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut niveau = PROCESS_PROTECTION_LEVEL_INFORMATION::default();
        let lu = GetProcessInformation(
            poignee,
            ProcessProtectionLevelInfo,
            (&raw mut niveau).cast(),
            u32::try_from(size_of::<PROCESS_PROTECTION_LEVEL_INFORMATION>()).unwrap_or(0),
        )
        .is_ok();
        let _ = CloseHandle(poignee);
        lu.then(|| niveau.ProtectionLevel != PROTECTION_LEVEL_NONE)
    }
}

/// Le dossier System32 de ce Windows (« C:\WINDOWS\system32 »), tel que Windows le donne : pas la variable
/// SystemRoot, que choisit le programme qui lance Vanguard, ni un chemin écrit en dur. `None` s'il ne se lit pas.
pub(crate) fn system32() -> Option<String> {
    let mut tampon = [0u16; 1024];
    let taille = u32::try_from(tampon.len()).ok()?;
    // SAFETY : le tampon fait `taille` caractères ; GetSystemDirectoryW n'écrit pas au-delà et rend le nombre écrit
    // (sans le zéro final), la taille qu'il lui faudrait s'il est trop petit, ou 0 en cas d'échec.
    let ecrits = unsafe { GetSystemDirectoryW(tampon.as_mut_ptr(), taille) };
    let ecrits = usize::try_from(ecrits).ok()?;
    (ecrits > 0 && ecrits < tampon.len()).then(|| String::from_utf16_lossy(&tampon[..ecrits]))
}

/// Un processus ouvert pour lire sa mémoire, et rien d'autre (PROCESS_VM_READ) ; refermé avec lui.
pub(crate) struct Lecteur(HANDLE);

/// Une région telle que VirtualQueryEx la décrit.
struct Brute {
    region: Region,
    base: usize,
    etat: u32,
    protection: u32,
    sorte: u32,
}

impl Lecteur {
    /// `None` : Windows refuse (autre compte sans élévation, processus protégé). PROCESS_QUERY_INFORMATION d'abord
    /// (QueryWorkingSetEx et GetMappedFileNameW le demandent, d'après leur documentation), les droits « limités »
    /// sinon : les images chargées seront alors non vérifiées, jamais écartées.
    pub(crate) fn ouvrir(pid: u32) -> Option<Lecteur> {
        // SAFETY : OpenProcess rend une poignée valide ou Err ; elle est refermée par `Drop`, une seule fois.
        unsafe {
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
                .or_else(|_| OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, pid))
                .ok()
                .map(Lecteur)
        }
    }

    /// Les régions de VirtualQueryEx, depuis l'adresse 0 jusqu'à ce qu'il n'ait plus rien à dire.
    fn brutes(&self) -> Vec<Brute> {
        let mut liste = Vec::new();
        let mut adresse: usize = 0;
        loop {
            // SAFETY : `information` est une MEMORY_BASIC_INFORMATION de la taille annoncée, que VirtualQueryEx
            // remplit entièrement quand il rend autre chose que 0 ; la poignée est valide tant que `self` vit.
            let (rendu, information) = unsafe {
                let mut information: Information = std::mem::zeroed();
                let rendu = VirtualQueryEx(
                    self.0.0,
                    std::ptr::with_exposed_provenance(adresse),
                    &raw mut information,
                    size_of::<Information>(),
                );
                (rendu, information)
            };
            if rendu == 0 {
                break;
            }
            let base = information.base as usize;
            liste.push(Brute {
                region: Region {
                    debut: base as u64,
                    taille: information.taille as u64,
                },
                base: information.base_allocation as usize,
                etat: information.etat,
                protection: information.protection,
                sorte: information.sorte,
            });
            match base.checked_add(information.taille) {
                Some(suivante) if suivante > adresse => adresse = suivante,
                _ => break,
            }
        }
        liste
    }

    /// Les blocs à lire : les régions privées ou mappées exécutables (`region_windows`), et les images chargées que
    /// `image_windows` retient, chaque allocation recollée depuis sa base (positions = RVA pour une image).
    pub(crate) fn regions(&self) -> Releve {
        let brutes = self.brutes();
        let mut releve = Releve::default();
        let mut i = 0;
        while i < brutes.len() {
            let base = brutes[i].base;
            let fin = brutes[i..]
                .iter()
                .position(|b| b.base != base)
                .map_or(brutes.len(), |n| i + n);
            let groupe = &brutes[i..fin];
            i = fin;
            let place = |b: &Brute| (b.region, b.region.debut.saturating_sub(base as u64));
            let autres: Vec<(Region, u64)> = groupe
                .iter()
                .filter(|b| b.sorte != MEM_IMAGE && region_windows(b.etat, b.protection, b.sorte))
                .map(place)
                .collect();
            if !autres.is_empty() {
                releve.blocs.extend(regrouper(autres, true));
            }
            let image: Vec<&Brute> = groupe
                .iter()
                .filter(|b| b.sorte == MEM_IMAGE && lisible_windows(b.etat, b.protection))
                .collect();
            if image.is_empty() {
                continue;
            }
            let code: Vec<Region> = image
                .iter()
                .filter(|b| b.protection & 0xF0 != 0)
                .map(|b| b.region)
                .collect();
            let rwx = image.iter().any(|b| b.protection & 0xFF == 0x40);
            match image_windows(self.fichier_present(base), self.pages_privees(&code), rwx) {
                Some(true) => releve
                    .blocs
                    .extend(regrouper(image.iter().map(|b| place(b)).collect(), true)),
                Some(false) => {}
                None => releve.images_non_verifiees += 1,
            }
        }
        releve
    }

    /// Le fichier d'une image est-il encore là ? GetMappedFileNameW donne son chemin de périphérique
    /// (« \Device\HarddiskVolume3\… »), ouvert par « \\?\GLOBALROOT ». `Some(false)` : absent, ou que rien ne
    /// confirme (l'image sera lue, ce qui n'est jamais faux) ; `None` : les droits manquent pour le demander.
    fn fichier_present(&self, base: usize) -> Option<bool> {
        const ERROR_ACCESS_DENIED: u32 = 5;
        let mut nom = [0u16; 1024];
        let taille = u32::try_from(nom.len()).ok()?;
        // SAFETY : le tampon fait `taille` caractères, GetMappedFileNameW n'écrit pas au-delà et rend le nombre écrit
        // (sans le zéro final), `taille` s'il est coupé, 0 en cas d'échec ; la poignée est valide tant que `self` vit.
        let (ecrits, erreur) = unsafe {
            let ecrits = K32GetMappedFileNameW(
                self.0.0,
                std::ptr::with_exposed_provenance(base),
                nom.as_mut_ptr(),
                taille,
            );
            (ecrits, if ecrits == 0 { GetLastError() } else { 0 })
        };
        if ecrits == 0 {
            return if erreur == ERROR_ACCESS_DENIED {
                None
            } else {
                Some(false)
            };
        }
        let ecrits = usize::try_from(ecrits).ok()?;
        if ecrits >= nom.len() {
            return Some(false);
        }
        let chemin = String::from_utf16_lossy(&nom[..ecrits]);
        let ouvrable = if let Some(reste) = chemin.strip_prefix(r"\??\") {
            format!(r"\\?\{reste}")
        } else if chemin.starts_with(r"\Device\") {
            format!(r"\\?\GLOBALROOT{chemin}")
        } else {
            return Some(false);
        };
        let large: Vec<u16> = ouvrable.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY : chaîne terminée par un zéro, lue seulement.
        let attributs = unsafe { GetFileAttributesW(large.as_ptr()) };
        Some(attributs != u32::MAX)
    }

    /// Une page de code de ces régions est-elle privée (copiée à l'écriture : modifiée depuis le chargement) ?
    /// QueryWorkingSetEx, page par page : le bit « Shared » (bit 15 de PSAPI_WORKING_SET_EX_BLOCK, dans les deux
    /// formes, page présente ou non ; la forme « Invalid » est documentée depuis Windows 8) vaut 0 pour une page qui
    /// ne peut plus être partagée avec le fichier. `None` : l'appel échoue (droits) ou l'image est démesurée.
    fn pages_privees(&self, regions: &[Region]) -> Option<bool> {
        let mut pages: Vec<PageEx> = Vec::new();
        for r in regions {
            let (debut, taille) = (usize::try_from(r.debut).ok()?, usize::try_from(r.taille).ok()?);
            for k in 0..taille.div_ceil(PAGE) {
                if pages.len() >= PAGES_PAR_IMAGE_MAX {
                    return None;
                }
                pages.push(PageEx {
                    adresse: std::ptr::with_exposed_provenance_mut(debut + k * PAGE),
                    attributs: 0,
                });
            }
        }
        for lot in pages.chunks_mut(PAGES_PAR_APPEL) {
            let octets = u32::try_from(size_of_val(lot)).ok()?;
            // SAFETY : `lot` est un tableau à nous de PSAPI_WORKING_SET_EX_INFORMATION de `octets` octets, que
            // QueryWorkingSetEx remplit sans en sortir ; la poignée est valide tant que `self` vit.
            if unsafe { K32QueryWorkingSetEx(self.0.0, lot.as_mut_ptr(), octets) } == 0 {
                return None;
            }
            if lot.iter().any(|p| (p.attributs >> 15) & 1 == 0) {
                return Some(true);
            }
        }
        Some(false)
    }

    /// Lit le début d'une région dans `zone` (de sa taille, prise dans un tampon qui ne grandit jamais) et rend le
    /// nombre d'octets lus : 0 si rien n'a pu l'être (région disparue ou changée entre-temps). Une lecture partielle
    /// est gardée telle quelle : ce qui est lu est analysé.
    pub(crate) fn lire(&self, region: &Region, zone: &mut [u8]) -> usize {
        let Ok(debut) = usize::try_from(region.debut) else {
            return 0;
        };
        let mut lus = 0usize;
        // SAFETY : `zone` est une tranche à nous de `zone.len()` octets, la taille passée à ReadProcessMemory, qui
        // n'écrit pas au-delà et rend le nombre écrit ; la poignée est valide tant que `self` vit.
        unsafe {
            ReadProcessMemory(
                self.0.0,
                std::ptr::with_exposed_provenance(debut),
                zone.as_mut_ptr().cast(),
                zone.len(),
                &raw mut lus,
            );
        }
        lus.min(zone.len())
    }
}

impl Drop for Lecteur {
    fn drop(&mut self) {
        // SAFETY : la poignée vient d'OpenProcess et n'est refermée qu'ici.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

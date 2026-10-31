//! La mémoire des processus de Windows, lue et jamais écrite (VirtualQueryEx, ReadProcessMemory), pour le scan YARA
//! de la mémoire (`protection::memoire`). Un processus protégé (LSASS, antivirus, tout PPL) n'est jamais ouvert en
//! lecture : son niveau se lit d'abord avec les seuls droits « limités », et tout niveau autre que « aucun » l'exclut,
//! comme un niveau qui ne se lit pas. Jamais d'écriture, d'injection, de suspension, de MiniDump ni de
//! SeDebugPrivilege : lire la mémoire d'autrui ressemble déjà assez à un vol d'identifiants pour ne rien y ajouter.
//! Le dossier System32 est lu ici aussi : un processus au nom critique n'est écarté que si son programme y est.

// FFI de kernel32 : mémoire d'un autre processus (VirtualQueryEx, ReadProcessMemory…).
#![allow(unsafe_code)]

use std::ffi::c_void;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{
    GetProcessInformation, OpenProcess, PROCESS_PROTECTION_LEVEL_INFORMATION, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ, PROTECTION_LEVEL_NONE, ProcessProtectionLevelInfo,
};

use crate::protection::memoire::{
    ImageHorsSysteme, Region, Releve, entetes_pe_concordent, image_du_systeme_windows, image_windows, lisible_windows,
    recoller_image, region_windows, regrouper,
};

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
    fn QueryDosDeviceW(nom: *const u16, cible: *mut u16, taille: u32) -> u32;
    fn K32QueryWorkingSetEx(processus: *mut c_void, pages: *mut PageEx, taille: u32) -> i32;
    fn K32GetMappedFileNameW(processus: *mut c_void, adresse: *const c_void, nom: *mut u16, taille: u32) -> u32;
    fn GetFileAttributesW(nom: *const u16) -> u32;
    fn GetFileInformationByHandle(fichier: *mut c_void, information: *mut InformationFichier) -> i32;
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

/// BY_HANDLE_FILE_INFORMATION (fileapi.h) : treize ULONG, les dates (FILETIME) en deux moitiés.
#[repr(C)]
#[derive(Default)]
struct InformationFichier {
    attributs: u32,
    creation: [u32; 2],
    acces: [u32; 2],
    ecriture: [u32; 2],
    volume: u32,
    taille: [u32; 2],
    liens: u32,
    index_haut: u32,
    index_bas: u32,
}

const MEM_IMAGE: u32 = 0x100_0000;
const PAGE: usize = 4096;
/// Les pages demandées d'un coup à QueryWorkingSetEx.
const PAGES_PAR_APPEL: usize = 4096;
/// Une image plus grande n'est pas examinée page à page : non vérifiée. La demande ne coûte que 16 octets par page,
/// par lots : la borne laisse passer les plus grosses bibliothèques (celles des navigateurs dépassent 64 Mio de code).
const PAGES_PAR_IMAGE_MAX: usize = (1 << 30) / PAGE;

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
    // SAFETY: la poignée vient d'OpenProcess (Err : refus) et est refermée une seule fois ; la structure reçue a la
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
    // SAFETY: le tampon fait `taille` caractères ; GetSystemDirectoryW n'écrit pas au-delà et rend le nombre écrit
    // (sans le zéro final), la taille qu'il lui faudrait s'il est trop petit, ou 0 en cas d'échec.
    let ecrits = unsafe { GetSystemDirectoryW(tampon.as_mut_ptr(), taille) };
    let ecrits = usize::try_from(ecrits).ok()?;
    let lu = tampon
        .get(..ecrits)
        .filter(|l| !l.is_empty() && ecrits < tampon.len())?;
    Some(String::from_utf16_lossy(lu))
}

/// Le volume du système sous ses deux formes ouvrables (« \\?\C: », « \\?\GLOBALROOT\Device\HarddiskVolume3 ») et
/// le dossier de Windows sur ce volume (« \WINDOWS »), d'après System32 (`system32`) et QueryDosDeviceW, pour
/// `image_du_systeme_windows`. `None` s'ils ne se lisent pas : aucune image n'est alors dite du système.
fn volume_du_systeme() -> Option<(Vec<String>, String)> {
    let dossier = system32()?;
    let lettre = dossier.get(..2).filter(|l| l.ends_with(':'))?;
    let windows = dossier.get(2..)?.rsplit_once('\\')?.0.to_string();
    let nom: Vec<u16> = lettre.encode_utf16().chain(std::iter::once(0)).collect();
    let mut cible = [0u16; 1024];
    let taille = u32::try_from(cible.len()).ok()?;
    // SAFETY: `nom` est terminé par un zéro et lu seulement ; `cible` fait `taille` caractères, QueryDosDeviceW n'écrit
    // pas au-delà et rend le nombre écrit (une liste de chaînes finie par deux zéros), 0 en cas d'échec.
    let ecrits = unsafe { QueryDosDeviceW(nom.as_ptr(), cible.as_mut_ptr(), taille) };
    let ecrits = usize::try_from(ecrits).ok().filter(|&n| n > 0 && n <= cible.len())?;
    let lu = cible.get(..ecrits)?;
    // La première chaîne de la liste : jusqu'au premier zéro.
    let peripherique = String::from_utf16_lossy(lu.split(|&c| c == 0).next().unwrap_or(lu));
    if !peripherique.starts_with(r"\Device\") || windows.is_empty() {
        return None;
    }
    Some((
        vec![format!(r"\\?\{lettre}"), format!(r"\\?\GLOBALROOT{peripherique}")],
        windows,
    ))
}

/// Un processus ouvert pour lire sa mémoire, et rien d'autre (PROCESS_VM_READ) ; refermé avec lui.
pub(crate) struct Lecteur(HANDLE);

/// Le fichier d'une image, d'après GetMappedFileNameW.
enum Fichier {
    /// Présent, à ce chemin ouvrable.
    Present(String),
    /// Absent, ou que rien ne confirme : l'image sera lue, ce qui n'est jamais faux.
    Absent,
    /// Les droits manquent pour le demander.
    Inconnu,
}

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
        // SAFETY: OpenProcess rend une poignée valide ou Err ; elle est refermée par `Drop`, une seule fois.
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
            // SAFETY: `information` est une MEMORY_BASIC_INFORMATION de la taille annoncée, que VirtualQueryEx
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
    /// `image_windows` retient, chaque allocation recollée depuis sa base (positions = RVA pour une image) ; une image
    /// intacte hors des dossiers du système (`image_du_systeme_windows`) se lit aussi, une fois pour tous.
    pub(crate) fn regions(&self) -> Releve {
        let systeme = volume_du_systeme();
        let brutes = self.brutes();
        let mut releve = Releve::default();
        // Une allocation : les régions qui se suivent avec la même base (un groupe n'est jamais vide).
        for groupe in brutes.chunk_by(|a, b| a.base == b.base) {
            let Some(base) = groupe.first().map(|b| b.base) else {
                continue;
            };
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
            let fichier = self.fichier_present(base);
            // Le fichier présent : son en-tête doit être celui de l'image ; un en-tête qui ne se compare pas fait
            // lire l'image (ce qui n'est jamais faux).
            let present = match &fichier {
                Fichier::Present(chemin) => Some(self.entete_du_fichier(base, chemin) == Some(true)),
                Fichier::Absent => Some(false),
                Fichier::Inconnu => None,
            };
            let morceaux = || image.iter().map(|b| place(b)).collect();
            match (image_windows(present, self.pages_privees(&code), rwx), &fichier) {
                (Some(true), _) => {
                    let (blocs, morcelee) = recoller_image(morceaux(), true);
                    releve.blocs.extend(blocs);
                    releve.images_morcelees += usize::from(morcelee);
                }
                (Some(false), Fichier::Present(chemin))
                    if systeme
                        .as_ref()
                        .is_some_and(|(racines, windows)| image_du_systeme_windows(chemin, racines, windows)) =>
                {
                    releve.images_laissees += 1;
                }
                (Some(false), _) => {
                    let (blocs, morcelee) = recoller_image(morceaux(), true);
                    let cle = match &fichier {
                        Fichier::Present(chemin) => identite_du_fichier(chemin),
                        _ => None,
                    };
                    releve.hors_systeme.push(ImageHorsSysteme {
                        cle,
                        blocs,
                        morcelee,
                        entete_a_verifier: None,
                    });
                }
                (None, _) => releve.images_non_verifiees += 1,
            }
        }
        releve
    }

    /// Le fichier d'une image est-il encore là ? GetMappedFileNameW donne son chemin de périphérique
    /// (« \Device\HarddiskVolume3\… »), ouvert par « \\?\GLOBALROOT ».
    fn fichier_present(&self, base: usize) -> Fichier {
        const ERROR_ACCESS_DENIED: u32 = 5;
        let mut nom = [0u16; 1024];
        let taille = u32::try_from(nom.len()).unwrap_or(0);
        // SAFETY: le tampon fait `taille` caractères, GetMappedFileNameW n'écrit pas au-delà et rend le nombre écrit
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
                Fichier::Inconnu
            } else {
                Fichier::Absent
            };
        }
        // Coupé (le tampon plein) : le chemin lu n'est pas le bon, rien ne confirme le fichier.
        let Some(ecrits) = usize::try_from(ecrits).ok().filter(|&n| n < nom.len()) else {
            return Fichier::Absent;
        };
        let Some(lu) = nom.get(..ecrits) else {
            return Fichier::Absent;
        };
        let chemin = String::from_utf16_lossy(lu);

        let ouvrable = if let Some(reste) = chemin.strip_prefix(r"\??\") {
            format!(r"\\?\{reste}")
        } else if chemin.starts_with(r"\Device\") {
            format!(r"\\?\GLOBALROOT{chemin}")
        } else {
            return Fichier::Absent;
        };
        let large: Vec<u16> = ouvrable.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: chaîne terminée par un zéro, lue seulement.
        let attributs = unsafe { GetFileAttributesW(large.as_ptr()) };
        if attributs == u32::MAX {
            Fichier::Absent
        } else {
            Fichier::Present(ouvrable)
        }
    }

    /// L'en-tête de l'image en mémoire (sa première page, à `base`) est-il celui du fichier `chemin` sur le disque
    /// (`entetes_pe_concordent`) ? Un fichier réécrit après que son image a été créée, ou une image tirée d'une
    /// transaction annulée, garde des pages partagées et un fichier présent : seul cet écart les trahit. `None` : l'un
    /// ou l'autre ne se lit pas.
    fn entete_du_fichier(&self, base: usize, chemin: &str) -> Option<bool> {
        use std::io::Read;
        let mut memoire = vec![0u8; PAGE];
        let region = Region {
            debut: base as u64,
            taille: PAGE as u64,
        };
        let lus = self.lire(&region, &mut memoire);
        memoire.truncate(lus);
        let mut fichier = Vec::with_capacity(PAGE);
        std::fs::File::open(chemin)
            .ok()?
            .take(PAGE as u64)
            .read_to_end(&mut fichier)
            .ok()?;
        entetes_pe_concordent(&memoire, &fichier)
    }

    /// Une page de code de ces régions est-elle privée (copiée à l'écriture : modifiée depuis le chargement) ?
    /// QueryWorkingSetEx, page par page : le bit « Shared » (bit 15 de PSAPI_WORKING_SET_EX_BLOCK, dans les deux
    /// formes, page présente ou non ; la forme « Invalid » est documentée depuis Windows 8) vaut 0 pour une page qui
    /// ne peut plus être partagée avec le fichier. `None` : l'appel échoue (droits) ou l'image est démesurée.
    fn pages_privees(&self, regions: &[Region]) -> Option<bool> {
        let mut total = 0usize;
        let mut lot: Vec<PageEx> = Vec::with_capacity(PAGES_PAR_APPEL);
        let demander = |lot: &mut Vec<PageEx>| -> Option<bool> {
            if lot.is_empty() {
                return Some(false);
            }
            let octets = u32::try_from(size_of_val(lot.as_slice())).ok()?;
            // SAFETY: `lot` est un tableau à nous de PSAPI_WORKING_SET_EX_INFORMATION de `octets` octets, que
            // QueryWorkingSetEx remplit sans en sortir ; la poignée est valide tant que `self` vit.
            if unsafe { K32QueryWorkingSetEx(self.0.0, lot.as_mut_ptr(), octets) } == 0 {
                return None;
            }
            let privee = lot.iter().any(|p| (p.attributs >> 15) & 1 == 0);
            lot.clear();
            Some(privee)
        };
        for r in regions {
            let (debut, taille) = (usize::try_from(r.debut).ok()?, usize::try_from(r.taille).ok()?);
            for k in 0..taille.div_ceil(PAGE) {
                total += 1;
                if total > PAGES_PAR_IMAGE_MAX {
                    return None;
                }
                lot.push(PageEx {
                    adresse: std::ptr::with_exposed_provenance_mut(debut + k * PAGE),
                    attributs: 0,
                });
                if lot.len() == PAGES_PAR_APPEL && demander(&mut lot)? {
                    return Some(true);
                }
            }
        }
        demander(&mut lot)
    }

    /// Lit le début d'une région dans `zone` (de sa taille, prise dans un tampon qui ne grandit jamais) et rend le
    /// nombre d'octets lus : 0 si rien n'a pu l'être (région disparue ou changée entre-temps). Une lecture partielle
    /// est gardée telle quelle : ce qui est lu est analysé.
    pub(crate) fn lire(&self, region: &Region, zone: &mut [u8]) -> usize {
        let Ok(debut) = usize::try_from(region.debut) else {
            return 0;
        };
        let mut lus = 0usize;
        // SAFETY: `zone` est une tranche à nous de `zone.len()` octets, la taille passée à ReadProcessMemory, qui
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
        // SAFETY: la poignée vient d'OpenProcess et n'est refermée qu'ici.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Ce qui nomme le fichier d'une image hors du système (`ImageHorsSysteme::cle`) : le numéro de série du volume,
/// l'identifiant du fichier sur ce volume et sa date de dernière écriture (GetFileInformationByHandle). Un chemin ne
/// suffit pas : le même chemin peut mener à un autre fichier (remplacé, ou vu d'un autre lecteur réseau), et un même
/// fichier a plusieurs chemins (liens). `None` : le fichier ne s'ouvre pas, l'image se lit dans chaque processus.
fn identite_du_fichier(chemin: &str) -> Option<String> {
    use std::os::windows::io::AsRawHandle;
    let fichier = std::fs::File::open(chemin).ok()?;
    let mut info = InformationFichier::default();
    // SAFETY: la poignée vient d'un fichier ouvert qui vit jusqu'à la fin de la fonction ; `info` est une
    // BY_HANDLE_FILE_INFORMATION à nous, que l'appel remplit sans en sortir.
    if unsafe { GetFileInformationByHandle(fichier.as_raw_handle(), &raw mut info) } == 0 {
        return None;
    }
    Some(cle_de_fichier(&info))
}

fn cle_de_fichier(info: &InformationFichier) -> String {
    format!(
        "{:08x}:{:08x}{:08x}:{:08x}{:08x}",
        info.volume, info.index_haut, info.index_bas, info.ecriture[1], info.ecriture[0]
    )
}

#[cfg(test)]
mod tests {
    use super::identite_du_fichier;

    /// MEMORY_BASIC_INFORMATION mise à zéro avant VirtualQueryEx (exercé sous Miri par outils/preuves.sh) : zéro est
    /// une valeur permise de chaque champ (pointeurs nuls, entiers), et la taille est celle de winnt.h sur x86_64.
    #[test]
    fn information_mise_a_zero() {
        // SAFETY: c'est ce que vérifie l'essai : la structure n'a que des pointeurs bruts et des entiers.
        let information: super::Information = unsafe { std::mem::zeroed() };
        assert!(information.base.is_null() && information.taille == 0);
        assert_eq!(std::mem::size_of::<super::Information>(), 48);
    }

    /// Campagne n° 4, deuxième relecture (M4) : une image hors du système est nommée par son fichier (volume,
    /// identifiant, date d'écriture), pas par son chemin : un autre fichier au même chemin, ou réécrit, se relit ; un
    /// lien vers le même fichier ne se relit pas ; un fichier qui ne s'ouvre pas n'a pas de nom.
    #[test]
    fn identite_d_une_image_hors_du_systeme() {
        let d = std::env::temp_dir().join(format!("vanguard-identite-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let (a, b, lien) = (d.join("a.dll"), d.join("b.dll"), d.join("lien.dll"));
        std::fs::write(&a, b"MZ a").unwrap();
        std::fs::write(&b, b"MZ b").unwrap();
        let cle = |p: &std::path::Path| identite_du_fichier(p.to_str().unwrap());
        let premiere = cle(&a).unwrap();
        assert_eq!(cle(&a).as_ref(), Some(&premiere));
        assert_ne!(cle(&b).as_ref(), Some(&premiere));
        if std::fs::hard_link(&a, &lien).is_ok() {
            assert_eq!(cle(&lien).as_ref(), Some(&premiere));
        }
        std::fs::remove_file(&a).unwrap();
        std::fs::rename(&b, &a).unwrap();
        assert_ne!(cle(&a).as_ref(), Some(&premiere));
        assert_eq!(cle(&d.join("absent.dll")), None);
        std::fs::remove_dir_all(&d).unwrap();
    }
}

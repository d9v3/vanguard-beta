//! Parcours « Ordinateur qui part » (vente, don, retour à l'employeur, recyclage) : ce qu'il faut faire, dans
//! l'ordre, pour qu'il parte sans tes fichiers ni tes comptes : une copie vérifiée d'abord, les comptes déconnectés
//! (et le verrou d'activation levé), la clé BitLocker ou FileVault mise de côté, l'effacement sûr par l'outil du
//! système, la puce TPM remise à zéro. Vanguard vérifie et explique ; il n'efface rien lui-même : l'outil du système
//! sait traiter chaque disque (SSD, puce de sécurité), et c'est à toi d'appuyer.

use super::{Etat, a_savoir, bilan, conseil, proposer_outil, question, verifications};
use crate::ui::*;

/// Ce que devient l'ordinateur.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Devenir {
    VenduOuDonne,
    Rendu,
    Recycle,
}

impl Devenir {
    fn depuis(reponse: usize) -> Devenir {
        match reponse {
            0 => Devenir::VenduOuDonne,
            1 => Devenir::Rendu,
            _ => Devenir::Recycle,
        }
    }
}

/// Les catégories du bilan utiles au départ : le disque est-il chiffré, quels comptes existent.
pub(super) const CATEGORIES: &[&str] = &["Chiffrement", "Comptes"];

/// Une étape du départ, dans l'ordre.
pub(super) struct Etape {
    pub titre: &'static str,
    pub detail: String,
    pub outil: Option<(&'static str, fn())>,
}

/// La puce TPM : présente, absente, ou illisible. Sous Linux, le noyau l'expose dans /sys ; sous Windows, le service
/// TPM de base (TBS), qui répond sans droits, puis Get-Tpm (réservé à l'administrateur) en secours ; un Mac n'en a pas
/// (sa puce de sécurité est effacée avec le reste).
fn tpm() -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        tpm_dans(std::path::Path::new("/sys/class/tpm"))
    }
    #[cfg(windows)]
    {
        tpm_tbs().or_else(|| crate::machine::windows::ps("(Get-Tpm).TpmPresent").and_then(|s| tpm_de_ps(&s)))
    }
    #[cfg(target_os = "macos")]
    {
        None
    }
}

/// /sys/class/tpm : un « tpm0 » dedans, c'est une puce ; le dossier vide, pas de puce ; le dossier absent, illisible.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn tpm_dans(classe: &std::path::Path) -> Option<bool> {
    let entrees = std::fs::read_dir(classe).ok()?;
    Some(
        entrees
            .flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with("tpm")),
    )
}

/// Tbsi_GetDeviceInfo de tbs.dll, chargée à la demande depuis System32 seulement : une liaison fixe empêcherait
/// vanguard.exe de démarrer là où elle manque, et un nom seul la chercherait d'abord à côté du programme (clé USB,
/// Téléchargements), où une fausse DLL s'exécuterait. Sous Wine, la fonction n'est pas appelée (ses fonctions
/// système peuvent n'être que des coquilles) : le secours décide.
#[cfg(windows)]
fn tpm_tbs() -> Option<bool> {
    use std::ffi::c_void;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryExW(nom: *const u16, fichier: *mut c_void, drapeaux: u32) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, nom: *const u8) -> *mut c_void;
        fn FreeLibrary(module: *mut c_void) -> i32;
    }
    type LireInfo = unsafe extern "system" fn(u32, *mut c_void) -> u32;
    /// LOAD_LIBRARY_SEARCH_SYSTEM32.
    const CHERCHER_DANS_SYSTEM32: u32 = 0x800;

    if crate::journal::sous_wine() {
        return None;
    }
    let nom: Vec<u16> = "tbs.dll\0".encode_utf16().collect();
    // TPM_DEVICE_INFO (tbs.h) : quatre UINT32 (version de la structure, du TPM, type et révision de l'interface),
    // que seule la réussite de l'appel intéresse ici.
    let mut info = [0u32; 4];
    let taille = u32::try_from(std::mem::size_of_val(&info)).ok()?;
    // SAFETY: le nom de la DLL et celui de la fonction sont terminés par un zéro ; le pointeur rendu est vérifié non
    // nul avant d'être converti à la signature de tbs.h (UINT32, PVOID → TBS_RESULT) ; la structure est à nous, de la
    // taille annoncée, vivante pendant l'appel ; le module n'est libéré qu'une fois, après le dernier appel.
    unsafe {
        let module = LoadLibraryExW(nom.as_ptr(), std::ptr::null_mut(), CHERCHER_DANS_SYSTEM32);
        if module.is_null() {
            return None;
        }
        let fonction = GetProcAddress(module, c"Tbsi_GetDeviceInfo".as_ptr().cast());
        let resultat = if fonction.is_null() {
            None
        } else {
            let lire = std::mem::transmute::<*mut c_void, LireInfo>(fonction);
            tpm_de_tbs(lire(taille, (&raw mut info).cast()))
        };
        FreeLibrary(module);
        resultat
    }
}

/// Le code de Tbsi_GetDeviceInfo : réussite, une puce ; TBS_E_TPM_NOT_FOUND, aucune. Tout le reste (service TBS
/// arrêté ou désactivé, refus) ne prouve pas l'absence : illisible.
#[cfg_attr(not(windows), allow(dead_code))]
fn tpm_de_tbs(code: u32) -> Option<bool> {
    const TBS_SUCCESS: u32 = 0;
    const TBS_E_TPM_NOT_FOUND: u32 = 0x8028_400F;
    match code {
        TBS_SUCCESS => Some(true),
        TBS_E_TPM_NOT_FOUND => Some(false),
        _ => None,
    }
}

/// « True » ou « False », tels que PowerShell les écrit.
#[cfg_attr(not(windows), allow(dead_code))]
fn tpm_de_ps(texte: &str) -> Option<bool> {
    match texte.trim().to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// Où l'effacement sûr se fait sur ce système, et pourquoi lui et pas une suppression de fichiers.
fn effacement() -> &'static str {
    if cfg!(windows) {
        tr!(
            "Paramètres > Système > Récupération > Réinitialiser ce PC > Supprimer tout, puis « Modifier les paramètres » et « Nettoyer les données : Oui ». Sans ce nettoyage, les fichiers supprimés se récupèrent avec un outil gratuit.",
            "Settings > System > Recovery > Reset this PC > Remove everything, then “Change settings” and “Clean data: Yes”. Without that cleaning, deleted files are recovered with a free tool."
        )
    } else if cfg!(target_os = "macos") {
        tr!(
            "Réglages Système > Général > Transférer ou réinitialiser > Effacer contenu et réglages : il déconnecte l'identifiant Apple, désactive Localiser, efface les clés de la puce de sécurité et réinstalle macOS. Sur un Mac Intel sans puce T2 : démarrer sur la récupération, Utilitaire de disque, effacer le disque, puis réinstaller.",
            "System Settings > General > Transfer or Reset > Erase All Content and Settings: it signs out the Apple ID, turns off Find My, erases the security chip's keys and reinstalls macOS. On an Intel Mac without a T2 chip: boot to Recovery, Disk Utility, erase the disk, then reinstall."
        )
    } else {
        tr!(
            "Démarrez sur la clé VANGUARD (SystemRescue) : un SSD s'efface en entier avec « blkdiscard » (ou « nvme format » pour un NVMe), un disque dur avec « shred -n 1 » ; puis réinstallez le système pour le prochain. Un disque chiffré LUKS devient illisible dès que son en-tête est effacé (« cryptsetup erase »).",
            "Boot from the VANGUARD key (SystemRescue): an SSD is wiped whole with “blkdiscard” (or “nvme format” for an NVMe), a hard disk with “shred -n 1”; then reinstall the system for the next person. A LUKS-encrypted disk becomes unreadable as soon as its header is erased (“cryptsetup erase”)."
        )
    }
}

/// Les comptes à déconnecter sur ce système, et le verrou d'activation qui bloquerait le prochain.
fn comptes() -> &'static str {
    if cfg!(windows) {
        tr!(
            "Paramètres > Comptes : déconnectez le compte Microsoft, et retirez l'appareil de votre liste sur account.microsoft.com (Appareils) ; Paramètres > Confidentialité et sécurité > Localiser mon appareil : désactivé. Déconnectez aussi le navigateur (synchronisation), Office, Steam, Adobe (désautoriser).",
            "Settings > Accounts: sign out of the Microsoft account, and remove the device from your list on account.microsoft.com (Devices); Settings > Privacy & security > Find my device: off. Also sign out of the browser (sync), Office, Steam, Adobe (deauthorize)."
        )
    } else if cfg!(target_os = "macos") {
        tr!(
            "Réglages Système > Identifiant Apple : désactivez Localiser mon Mac, puis déconnectez-vous ; sinon le verrou d'activation rend le Mac inutilisable pour le prochain. Déconnectez aussi iMessage, Musique (désautoriser l'ordinateur), le navigateur, Steam, Adobe.",
            "System Settings > Apple ID: turn off Find My Mac, then sign out; otherwise the Activation Lock makes the Mac unusable for the next person. Also sign out of iMessage, Music (deauthorize this computer), the browser, Steam, Adobe."
        )
    } else {
        tr!(
            "Déconnectez le navigateur (synchronisation Firefox ou Google), les comptes en ligne du bureau (GNOME, KDE), Steam, et retirez les clés SSH et jetons (~/.ssh, gestionnaires de mots de passe) qui ouvrent vos serveurs et services depuis cet ordinateur.",
            "Sign out of the browser (Firefox or Google sync), the desktop's online accounts (GNOME, KDE), Steam, and remove the SSH keys and tokens (~/.ssh, password managers) that open your servers and services from this computer."
        )
    }
}

/// La clé de récupération du chiffrement : où elle est, et pourquoi la garder jusqu'au bout.
fn cle_de_recuperation(chiffre: Option<bool>) -> &'static str {
    match chiffre {
        Some(true) if cfg!(windows) => tr!(
            "Le disque est chiffré (BitLocker) : la clé de récupération est dans votre compte Microsoft (account.microsoft.com > Appareils > clés de récupération). Gardez-la jusqu'à la fin : un effacement interrompu laisse un disque chiffré qui ne démarre plus, et elle seule le rouvre. Après l'effacement, elle ne sert plus.",
            "The disk is encrypted (BitLocker): the recovery key is in your Microsoft account (account.microsoft.com > Devices > recovery keys). Keep it until the end: an interrupted wipe leaves an encrypted disk that no longer boots, and only the key reopens it. After the wipe, it is useless."
        ),
        Some(true) if cfg!(target_os = "macos") => tr!(
            "Le disque est chiffré (FileVault) : la clé de secours est celle notée à l'activation, ou dans iCloud. Gardez-la jusqu'à la fin de l'effacement ; après, elle ne sert plus.",
            "The disk is encrypted (FileVault): the recovery key is the one noted at activation, or in iCloud. Keep it until the wipe is done; afterwards, it is useless."
        ),
        Some(true) => tr!(
            "Le disque est chiffré (LUKS) : bonne nouvelle, les données sont déjà illisibles sans la phrase de passe ; effacer l'en-tête LUKS suffit à les rendre irrécupérables, même pour vous.",
            "The disk is encrypted (LUKS): good news, the data is already unreadable without the passphrase; erasing the LUKS header is enough to make it unrecoverable, even for you."
        ),
        Some(false) => tr!(
            "Le disque n'est pas chiffré : tout ce qui a été supprimé « normalement » depuis des années est encore récupérable dessus. L'effacement ci-dessous doit nettoyer le lecteur en entier, pas seulement supprimer des fichiers.",
            "The disk is not encrypted: everything “normally” deleted for years is still recoverable on it. The wipe below must clean the whole drive, not just delete files."
        ),
        None => tr!(
            "Vanguard n'a pas pu lire l'état du chiffrement : s'il est chiffré, mettez la clé de récupération de côté jusqu'à la fin de l'effacement ; sinon, l'effacement doit nettoyer le lecteur en entier.",
            "Vanguard could not read the encryption state: if encrypted, set the recovery key aside until the wipe is done; otherwise, the wipe must clean the whole drive."
        ),
    }
}

/// La puce TPM : à remettre à zéro après l'effacement, pour que les clés de ton disque n'y restent pas.
fn puce(tpm: Option<bool>) -> Option<&'static str> {
    if cfg!(target_os = "macos") {
        return None;
    }
    match tpm {
        Some(false) => None,
        Some(true) if cfg!(windows) => Some(tr!(
            "Puce TPM présente : elle garde les clés de BitLocker et de Windows Hello. Après l'effacement, « Réinitialiser ce PC » la remet à zéro ; sinon Sécurité Windows > Sécurité de l'appareil > Processeur de sécurité > Résolution des problèmes > Effacer le module.",
            "TPM chip present: it holds the BitLocker and Windows Hello keys. After the wipe, “Reset this PC” clears it; otherwise Windows Security > Device security > Security processor > Troubleshoot > Clear TPM."
        )),
        Some(true) => Some(tr!(
            "Puce TPM présente : elle peut garder des clés de votre disque. Après l'effacement, remettez-la à zéro dans le firmware (UEFI, section Sécurité : « Clear TPM »).",
            "TPM chip present: it may hold keys of your disk. After the wipe, clear it in the firmware (UEFI, Security section: “Clear TPM”)."
        )),
        None => Some(tr!(
            "Puce TPM : état illisible ici. Si l'ordinateur en a une (tous ceux faits pour Windows 11), remettez-la à zéro après l'effacement, dans le firmware (UEFI) ou par « Réinitialiser ce PC ».",
            "TPM chip: state unreadable here. If the computer has one (all those built for Windows 11), clear it after the wipe, in the firmware (UEFI) or with “Reset this PC”."
        )),
    }
}

/// Les étapes, dans l'ordre : la copie d'abord (rien de ce qui suit ne se rattrape), les comptes, la clé, puis
/// l'effacement et la puce ; rendu à l'employeur : rien d'effacé sans son accord, l'appareil n'est pas à toi.
pub(super) fn etapes(
    devenir: Devenir,
    copie_faite: bool,
    rien_a_garder: bool,
    chiffre: Option<bool>,
    tpm: Option<bool>,
) -> Vec<Etape> {
    let mut e = Vec::new();
    if !copie_faite && !rien_a_garder {
        e.push(Etape {
            titre: tr!("Une copie vérifiée d'abord", "A checked copy first"),
            detail: tr!(
                "Documents, Images, Vidéos, Musique, Bureau vers un disque externe, chaque fichier relu après la copie. Pensez aussi à ce qui n'est pas dans ces dossiers : mots de passe du navigateur (exportés dans le gestionnaire), clés de licence, favoris, courriels locaux, codes de validation en deux étapes.",
                "Documents, Pictures, Videos, Music, Desktop to an external disk, each file read back after the copy. Also think of what is not in those folders: browser passwords (exported to the manager), license keys, bookmarks, local emails, two-step verification codes."
            )
            .to_string(),
            outil: Some((
                tr!(
                    "\n  Ouvrir « Copier mes fichiers » ? [o/N] : ",
                    "\n  Open “Copy my files”? [y/N]: "
                ),
                crate::copier::menu,
            )),
        });
    }
    e.push(Etape {
        titre: tr!("Déconnecter vos comptes", "Sign out of your accounts"),
        detail: comptes().to_string(),
        outil: None,
    });
    e.push(Etape {
        titre: tr!("La clé de récupération du chiffrement", "The encryption recovery key"),
        detail: cle_de_recuperation(chiffre).to_string(),
        outil: None,
    });
    match devenir {
        Devenir::Rendu => e.push(Etape {
            titre: tr!("Rendu : ne l'effacez pas vous-même", "Returned: do not wipe it yourself"),
            detail: tr!(
                "L'appareil appartient à l'employeur, à l'école ou au loueur : c'est leur procédure qui s'applique, et un effacement non demandé peut leur poser problème (licences, gestion à distance). Retirez seulement vos comptes et fichiers personnels, et demandez-leur ce qu'ils attendent.",
                "The device belongs to the employer, the school or the renter: their procedure applies, and an unrequested wipe may cause them trouble (licenses, remote management). Only remove your personal accounts and files, and ask them what they expect."
            )
            .to_string(),
            outil: None,
        }),
        Devenir::Recycle => e.push(Etape {
            titre: tr!("Recyclage : le disque à part", "Recycling: keep the disk separate"),
            detail: tr!(
                "Si l'ordinateur ne démarre plus, le disque, lui, se lit sur un autre : retirez-le (SSD, NVMe ou disque dur) et gardez-le, ou détruisez-le (perceuse à travers un disque dur ; un SSD se casse). Le reste va au point de collecte. S'il démarre encore, l'effacement ci-dessous suffit.",
                "If the computer no longer boots, the disk itself is readable on another one: remove it (SSD, NVMe or hard disk) and keep it, or destroy it (drill through a hard disk; an SSD snaps). The rest goes to the collection point. If it still boots, the wipe below is enough."
            )
            .to_string(),
            outil: None,
        }),
        Devenir::VenduOuDonne => {}
    }
    if devenir != Devenir::Rendu {
        e.push(Etape {
            titre: tr!(
                "L'effacement sûr, par l'outil du système",
                "The secure wipe, with the system's tool"
            ),
            detail: effacement().to_string(),
            outil: None,
        });
        if let Some(p) = puce(tpm) {
            e.push(Etape {
                titre: tr!("La puce TPM", "The TPM chip"),
                detail: p.to_string(),
                outil: None,
            });
        }
    }
    e.push(Etape {
        titre: tr!("Les données de Vanguard", "Vanguard's data"),
        detail: trf!(
            "La base des appareils, les surnoms et l'historique de vos réseaux sont dans {} : exportez-les si vous voulez les retrouver sur le prochain ordinateur (ils partent avec l'effacement). La clé VANGUARD, elle, vous suit.",
            "The device database, the nicknames and the history of your networks are in {}: export them if you want them back on the next computer (the wipe erases them). The VANGUARD key itself goes with you.",
            chemin_affichable(&crate::socle::dossier_local())
        ),
        outil: Some((
            tr!(
                "\n  Ouvrir « Données de Vanguard » (sauvegarder) ? [o/N] : ",
                "\n  Open “Vanguard data” (back up)? [y/N]: "
            ),
            crate::donnees::menu,
        )),
    });
    e
}

pub(super) fn depart() {
    let Some(devenir) = question(
        tr!("Que devient-il ?", "What becomes of it?"),
        &[
            tr!("Vendu ou donné", "Sold or given away"),
            tr!(
                "Rendu à l'employeur, l'école ou le loueur",
                "Returned to the employer, school or renter"
            ),
            tr!(
                "Recyclé, jeté, ou il ne démarre plus",
                "Recycled, thrown away, or it no longer boots"
            ),
        ],
    ) else {
        return;
    };
    let devenir = Devenir::depuis(devenir);
    let Some(copie) = question(
        tr!(
            "Avez-vous déjà une copie vérifiée de ce que vous voulez garder ?",
            "Do you already have a checked copy of what you want to keep?"
        ),
        &[
            tr!("Oui", "Yes"),
            tr!("Non", "No"),
            tr!("Rien à garder", "Nothing to keep"),
        ],
    ) else {
        return;
    };
    verifications();
    let constats = bilan(CATEGORIES);
    let chiffre = super::nouveau::chiffre(&constats);
    let tpm = tpm();
    match tpm {
        Some(true) => Etat::Info.dire(tr!("Puce TPM présente.", "TPM chip present.")),
        Some(false) => Etat::Info.dire(tr!("Pas de puce TPM.", "No TPM chip.")),
        None if cfg!(target_os = "macos") => {}
        None => Etat::Info.dire(tr!(
            "Puce TPM : état illisible (droits d'administrateur).",
            "TPM chip: state unreadable (administrator rights)."
        )),
    }
    section(tr!("DANS L'ORDRE", "IN ORDER"));
    for (i, e) in etapes(devenir, copie == 0, copie == 2, chiffre, tpm).iter().enumerate() {
        println!("  {TOUCHE}{}{RESET} {GRAS}{}{RESET}", i + 1, e.titre);
        afficher_aligne("    ", &e.detail, 4, "");
        if let Some((question, outil)) = e.outil {
            proposer_outil(question, outil);
        }
        println!();
    }
    a_savoir(&[tr!(
        "Vanguard n'efface rien lui-même : l'outil du système sait traiter chaque disque (SSD, puce de sécurité, verrou d'activation), et c'est vous qui appuyez. Ce parcours vérifie et explique, c'est tout.",
        "Vanguard wipes nothing itself: the system's tool knows how to handle each disk (SSD, security chip, activation lock), and you are the one who presses. This path checks and explains, that is all."
    )]);
    if devenir == Devenir::VenduOuDonne {
        conseil(tr!(
            "Donnez au prochain la facture ou la boîte si vous les avez, et dites-lui que le disque a été effacé : il saura qu'il doit tout réinstaller lui-même, avec ses propres comptes.",
            "Give the next person the invoice or the box if you have them, and tell them the disk was wiped: they will know they must reinstall everything themselves, with their own accounts."
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn titres(e: &[Etape]) -> Vec<&str> {
        e.iter().map(|x| x.titre).collect()
    }

    #[test]
    fn la_copie_d_abord_sauf_si_faite() {
        let sans_copie = etapes(Devenir::VenduOuDonne, false, false, Some(true), Some(true));
        assert!(sans_copie[0].titre.contains("copie"), "{:?}", titres(&sans_copie));
        assert!(sans_copie[0].outil.is_some());
        let copie_faite = etapes(Devenir::VenduOuDonne, true, false, Some(true), Some(true));
        let rien = etapes(Devenir::VenduOuDonne, false, true, Some(true), Some(true));
        assert_eq!(titres(&copie_faite), titres(&rien));
        assert_eq!(copie_faite.len() + 1, sans_copie.len());
        assert!(copie_faite[0].titre.contains("comptes"));
    }

    #[test]
    fn rendu_a_l_employeur_rien_d_efface() {
        let rendu = etapes(Devenir::Rendu, true, false, Some(false), Some(true));
        let t = titres(&rendu);
        assert!(t.iter().any(|x| x.contains("Rendu")));
        assert!(
            !t.iter().any(|x| x.contains("effacement") || x.contains("TPM")),
            "{t:?}"
        );
        let vendu = etapes(Devenir::VenduOuDonne, true, false, Some(false), Some(true));
        let t = titres(&vendu);
        // Un Mac n'a pas de puce TPM (sa puce de sécurité s'efface avec le reste) : pas d'étape pour elle.
        assert!(
            t.iter().any(|x| x.contains("effacement"))
                && t.iter().any(|x| x.contains("TPM")) != cfg!(target_os = "macos"),
            "{t:?}"
        );
        // Les données de Vanguard ferment la liste, dans tous les cas.
        assert!(rendu.last().unwrap().titre.contains("Vanguard") && vendu.last().unwrap().titre.contains("Vanguard"));
    }

    #[test]
    fn la_puce_selon_ce_qu_on_sait() {
        if cfg!(target_os = "macos") {
            assert!(puce(Some(true)).is_none());
            return;
        }
        assert!(puce(Some(false)).is_none());
        assert!(puce(Some(true)).is_some_and(|p| p.contains("présente")));
        assert!(puce(None).is_some_and(|p| p.contains("illisible")));
        let recycle = etapes(Devenir::Recycle, true, false, None, Some(false));
        assert!(titres(&recycle).iter().any(|x| x.contains("Recyclage")));
        assert!(!titres(&recycle).iter().any(|x| x.contains("TPM")));
    }

    #[test]
    fn cle_selon_le_chiffrement() {
        assert!(cle_de_recuperation(Some(false)).contains("pas chiffré"));
        assert!(cle_de_recuperation(None).contains("pas pu lire"));
        assert!(cle_de_recuperation(Some(true)).contains("chiffré"));
    }

    #[test]
    fn tpm_lu_du_service_tbs() {
        assert_eq!(tpm_de_tbs(0), Some(true));
        assert_eq!(tpm_de_tbs(0x8028_400F), Some(false));
        // Service arrêté, désactivé, accès refusé, paramètre refusé : illisible, jamais « pas de puce ».
        for code in [0x8028_4008, 0x8028_4010, 0x8028_4001, 0x8028_4002, 5] {
            assert_eq!(tpm_de_tbs(code), None, "{code:#x}");
        }
    }

    /// Sous Wine, le service n'est pas appelé, sans planter ; sur un vrai Windows, une réponse se tient.
    #[cfg(windows)]
    #[test]
    fn tpm_tbs_sans_planter() {
        if crate::journal::sous_wine() {
            return crate::essais::saute("tbs.dll n'est pas appelée sous Wine");
        }
        let _ = tpm_tbs();
    }

    #[test]
    fn tpm_lu_de_powershell_et_de_sys() {
        assert_eq!(tpm_de_ps("True\r\n"), Some(true));
        assert_eq!(tpm_de_ps("  false "), Some(false));
        assert_eq!(tpm_de_ps(""), None);
        assert_eq!(tpm_de_ps("Get-Tpm : access denied"), None);
        let dossier = std::env::temp_dir().join(format!("vanguard-tpm-essai-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dossier);
        assert_eq!(tpm_dans(&dossier), None);
        std::fs::create_dir_all(&dossier).unwrap();
        assert_eq!(tpm_dans(&dossier), Some(false));
        std::fs::create_dir(dossier.join("tpm0")).unwrap();
        assert_eq!(tpm_dans(&dossier), Some(true));
        let _ = std::fs::remove_dir_all(&dossier);
    }
}

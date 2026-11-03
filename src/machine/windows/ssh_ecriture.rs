//! Les gestes SSH du processus élevé (défense D6c) : `vanguard:ssh-cles-admin-droits`, `vanguard:ssh-cle-droits
//! <nom>`, `vanguard:sshd-reglage <mot>` et leurs remises (grammaire fermée de `gestes.rs`, logique pure dans
//! `ssh_regles`).
//!
//! Les droits d'un fichier : le chemin vient d'ici, jamais de la ligne (administrators_authorized_keys sous le
//! ProgramData que Windows donne, une clé sous le profil du compte de la personne lu dans ProfileList, ses variables
//! développées comme le fait Windows). Le fichier est ouvert sans suivre de lien, refusé s'il est un dossier, un
//! lien, une jonction ou a plusieurs noms, ou si son chemin final n'est pas celui attendu ; rejugé sur cette poignée
//! par les fonctions du bilan (`ssh::droits_cles_admin`, `cle_protegee`, `ssh::cle_lisible_par_tous`), la liste
//! d'avant notée (relue), la nouvelle posée par la même poignée et relue. Le fichier n'est jamais vidé ni réécrit, son
//! propriétaire n'est pas changé.
//!
//! sshd_config : jamais créé ; sshd.exe pris au chemin du service (ImagePath), dans System32\OpenSSH ou un dossier
//! que seuls les administrateurs écrivent, comme le dossier ssh de ProgramData. La nouvelle version est écrite à
//! côté, éprouvée par `sshd -t -f`, puis échangée par ReplaceFileW, qui garde l'ancienne sous un nom daté. sshd ne
//! redémarre que s'il tourne et qu'aucune session SSH n'est ouverte ; sinon, la configuration vaut au prochain
//! démarrage. Couper les mots de passe : jamais pendant une session SSH (refus sans question), sinon après un oui à
//! « Une clé est-elle déjà posée pour votre compte ? ».

use std::ffi::c_void;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use super::corrections::{Resultat, avant_notable};
use crate::machine::gestes::{CibleSsh, Montre, ReglageSshd, Sens};
use crate::machine::reglages::{self, Issue};
use crate::machine::ssh_regles::{self, AccordMdp, Relance};
use crate::modele::raison::Echec;
use crate::ui::{tr, trf, trp};

const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const FILE_READ_DATA: u32 = 0x0001;
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const FILE_SHARE_READ: u32 = 0x0001;
const FILE_SHARE_WRITE: u32 = 0x0002;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const ATTRIBUT_DOSSIER: u32 = 0x10;
const ATTRIBUT_POINT_D_ANALYSE: u32 = 0x400;
/// Une clé privée tient en quelques Kio : au-delà, pas une clé (comme le bilan).
const CLE_MAX: u64 = 64 << 10;
/// Comme le bilan : au-delà d'un Mio, pas une configuration de sshd.
const CONFIG_MAX: u64 = 1 << 20;
/// Le nom du fichier neuf, avant l'échange : jamais un nom de copie (`ssh_regles::nom_copie_valide` le refuse).
const NOUVEAU: &str = "sshd_config.vanguard-nouveau";
const SERVICE: &str = "sshd";

fn refus(raison: &str) -> Resultat {
    Resultat::echec(None, raison.to_string())
}

fn resultat(issue: Issue) -> Resultat {
    match issue {
        Issue::Fait { avant } => Resultat::fait(avant_notable(&avant)),
        Issue::Rien(avant) => Resultat::rien(trf!(
            "déjà ainsi ({}), rien d'écrit",
            "already so ({}), nothing written",
            avant_notable(&avant)
        )),
        Issue::Echec { avant, raison } => Resultat::echec(avant.as_deref().map(avant_notable), raison),
    }
}

/// Le dossier ssh de ProgramData, d'après le dossier connu (jamais la variable d'environnement).
fn dossier_ssh() -> Option<PathBuf> {
    super::environnement::dossiers()
        .program_data
        .as_ref()
        .filter(|p| p.is_absolute())
        .map(|p| p.join("ssh"))
}

/// Le profil du compte `sid`, d'après ProfileList (que seul un administrateur écrit), ses variables développées comme
/// le fait Windows (`services::variable_systeme`), jamais par l'environnement de ce processus.
fn profil(sid: &str) -> Option<PathBuf> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_WOW64_64KEY};
    if !reglages::sid_valide(sid) {
        return None;
    }
    let cle = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(
            format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}"),
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
        )
        .ok()?;
    let brut = super::corrections::texte_reg(&cle.get_raw_value("ProfileImagePath").ok()?)?;
    let chemin = super::installes::developper(&brut, &super::services::variable_systeme)?;
    let p = PathBuf::from(chemin.trim());
    p.is_absolute().then_some(p)
}

/// Le chemin attendu du fichier visé.
fn chemin_vise(c: &CibleSsh, personne: Option<&str>) -> Result<PathBuf, &'static str> {
    match c {
        CibleSsh::ClesAdmin => dossier_ssh()
            .map(|d| d.join("administrators_authorized_keys"))
            .ok_or(tr!(
                "le dossier ProgramData ne se lit pas : rien d'écrit",
                "the ProgramData folder cannot be read: nothing written"
            )),
        CibleSsh::Cle(n) => personne
            .and_then(profil)
            .map(|p| p.join(".ssh").join(n.texte()))
            .ok_or(tr!(
                "le profil du compte de la personne ne se lit pas : rien d'écrit",
                "the person's account profile cannot be read: nothing written"
            )),
    }
}

/// Le contexte des échecs de ce module, pour le journal.
const CTX: &str = "ssh/ecriture";

/// Un nom hors du dossier de sshd, ou une copie au nom refusé : jamais ouvert.
fn inconnu() -> Echec {
    Echec::refuse(CTX, "?")
}

/// Ouvre le fichier pour lire et poser ses droits (et lire son contenu, `lire`), sans suivre de lien ; refusé s'il
/// est un dossier, un lien, une jonction, a plusieurs noms, ou si son chemin final n'est pas `chemin`.
fn ouvrir(chemin: &Path, lire: bool) -> Result<File, Echec> {
    let f = std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES | if lire { FILE_READ_DATA } else { 0 })
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(chemin)
        .map_err(|e| {
            Echec::echoue(
                CTX,
                trf!(
                    "le fichier ne s'ouvre pas ({}) : rien d'écrit",
                    "the file cannot be opened ({}): nothing written",
                    crate::ui::affichable(&e.to_string())
                ),
            )
        })?;
    let Some((attributs, liens)) = super::demarrage_ecriture::information(&f) else {
        return Err(Echec::refuse(
            CTX,
            tr!(
                "le fichier ne se lit pas : rien d'écrit",
                "the file cannot be read: nothing written"
            ),
        ));
    };
    if attributs & (ATTRIBUT_DOSSIER | ATTRIBUT_POINT_D_ANALYSE) != 0 || liens != 1 {
        return Err(Echec::refuse(
            CTX,
            tr!(
                "un dossier, un lien, une jonction ou un fichier à plusieurs noms : refusé, rien d'écrit",
                "a folder, a link, a junction or a file with several names: refused, nothing written"
            ),
        ));
    }
    let attendu = chemin.to_string_lossy();
    if !super::demarrage_ecriture::chemin_final(&f)
        .is_some_and(|fin| super::demarrage_ecriture::meme_chemin(&fin, &attendu))
    {
        return Err(Echec::refuse(
            CTX,
            tr!(
                "le fichier ouvert n'est pas celui attendu : refusé, rien d'écrit",
                "the opened file is not the expected one: refused, nothing written"
            ),
        ));
    }
    Ok(f)
}

/// Le fichier ouvert : ses droits par la poignée, les notes sous ChoixAvant.
struct FichierWin(File);

impl ssh_regles::Fichier for FichierWin {
    fn lire(&mut self) -> Option<String> {
        super::securite::droits_poignee(&self.0).map(|(_, sddl)| sddl)
    }
    fn poser(&mut self, sddl: &str) -> Result<(), Echec> {
        let protegee = ssh_regles::explicites(sddl)
            .ok_or_else(|| Echec::refuse(CTX, "SDDL"))?
            .protegee;
        super::securite::poser_droits(&self.0, sddl, protegee)
    }
    fn lire_note(&mut self, nom: &str) -> Option<Vec<u8>> {
        crate::machine::choix_avant::lire_brut(nom)
    }
    fn ecrire_note(&mut self, nom: &str, octets: &[u8]) -> Result<(), Echec> {
        crate::machine::choix_avant::ecrire_brut(nom, octets).map_err(|e| Echec::echoue(CTX, e.to_string()))
    }
    fn effacer_note(&mut self, nom: &str) {
        crate::machine::choix_avant::effacer_brut(nom);
    }
}

/// Le fichier est-il encore à corriger, d'après le bilan refait sur la poignée ? `Ok(false)` : déjà sûr.
fn rejuger(c: &CibleSsh, f: &File) -> Result<bool, &'static str> {
    let Some((octets, _)) = super::securite::droits_poignee(f) else {
        return Err(tr!(
            "la liste des droits ne se lit pas : rien d'écrit",
            "the list of rights cannot be read: nothing written"
        ));
    };
    match c {
        CibleSsh::ClesAdmin => match super::ssh::droits_cles_admin(Some(&octets), true) {
            super::ssh::Droits::Ouverts(_) => Ok(true),
            super::ssh::Droits::Surs => Ok(false),
            super::ssh::Droits::Absent | super::ssh::Droits::Illisibles => Err(tr!(
                "la liste des droits ne se lit pas : rien d'écrit",
                "the list of rights cannot be read: nothing written"
            )),
        },
        CibleSsh::Cle(_) => {
            let mut contenu = Vec::new();
            if f.take(CLE_MAX + 1).read_to_end(&mut contenu).is_err() || contenu.len() as u64 > CLE_MAX {
                return Err(tr!(
                    "la clé ne se lit pas (ou dépasse 64 Kio) : rien d'écrit",
                    "the key cannot be read (or exceeds 64 KiB): nothing written"
                ));
            }
            if crate::machine::cle_protegee(&String::from_utf8_lossy(&contenu)).is_none() {
                return Err(tr!(
                    "ce fichier n'est pas une clé privée : refusé, rien d'écrit",
                    "this file is not a private key: refused, nothing written"
                ));
            }
            match super::ssh::cle_lisible_par_tous(&octets) {
                Some(lisible) => Ok(lisible),
                None => Err(tr!(
                    "la liste des droits ne se lit pas : rien d'écrit",
                    "the list of rights cannot be read: nothing written"
                )),
            }
        }
    }
}

/// Réserve le fichier : SYSTEM et les administrateurs (plus le compte de la personne pour sa clé), sans héritage.
pub(super) fn droits(c: &CibleSsh, personne: Option<&str>) -> Resultat {
    let sid = match c {
        CibleSsh::ClesAdmin => None,
        CibleSsh::Cle(_) => personne,
    };
    let (Some(nom), Some(voulu)) = (ssh_regles::nom_note_droits(c, sid), ssh_regles::voulu(sid)) else {
        return refus(tr!(
            "le compte de la personne ne se lit pas : rien d'écrit",
            "the person's account cannot be read: nothing written"
        ));
    };
    // La forme que Windows relira (alias des comptes connus) : la relecture la compare telle quelle.
    let Some(voulu) = super::securite::sddl_canonique(&voulu) else {
        return refus(tr!(
            "liste des droits refusée par Windows",
            "list of rights refused by Windows"
        ));
    };
    let chemin = match chemin_vise(c, personne) {
        Ok(p) => p,
        Err(r) => return refus(r),
    };
    let f = match ouvrir(&chemin, matches!(c, CibleSsh::Cle(_))) {
        Ok(f) => f,
        Err(r) => return Resultat::echec(None, r.to_string()),
    };
    match rejuger(c, &f) {
        Ok(true) => {}
        Ok(false) => {
            let lu = super::securite::droits_poignee(&f).map(|(_, s)| s).unwrap_or_default();
            return resultat(Issue::Rien(lu));
        }
        Err(r) => return refus(r),
    }
    let question = tr!(
        "  La liste des droits d'avant est trop longue pour être notée : la réserver quand même, NON ANNULABLE ? [o/N] : ",
        "  The previous list of rights is too long to be noted: restrict it anyway, CANNOT BE UNDONE? [y/N]: "
    );
    let issue = ssh_regles::reserver(&mut FichierWin(f), &nom, &voulu, || {
        reglages::confirmer(super::eleve::console_reelle(), question, crate::ui::demander_ou_defaut)
    });
    resultat(issue)
}

/// Remet la liste des droits notée (une baisse, déjà montrée et confirmée).
pub(super) fn droits_remettre(c: &CibleSsh, personne: Option<&str>) -> Resultat {
    let sid = match c {
        CibleSsh::ClesAdmin => None,
        CibleSsh::Cle(_) => personne,
    };
    let Some(nom) = ssh_regles::nom_note_droits(c, sid) else {
        return refus(tr!(
            "le compte de la personne ne se lit pas : rien d'écrit",
            "the person's account cannot be read: nothing written"
        ));
    };
    let chemin = match chemin_vise(c, personne) {
        Ok(p) => p,
        Err(r) => return refus(r),
    };
    match ouvrir(&chemin, false) {
        Ok(f) => resultat(ssh_regles::remettre_droits(&mut FichierWin(f), &nom)),
        Err(r) => Resultat::echec(None, r.to_string()),
    }
}

/// Ce qu'une remise des droits va poser, montré avant la question des baisses.
pub(super) fn texte_remise_droits(c: &CibleSsh, personne: Option<&str>) -> String {
    let (fichier, sid) = match c {
        CibleSsh::ClesAdmin => ("administrators_authorized_keys".to_string(), None),
        CibleSsh::Cle(n) => (format!(r".ssh\{}", crate::ui::affichable(n.texte())), personne),
    };
    let note = ssh_regles::nom_note_droits(c, sid)
        .and_then(|n| crate::machine::choix_avant::lire_brut(&n).and_then(|o| ssh_regles::note_droits(&o, &n)));
    match note {
        Some((avant, _)) => trf!(
            "Droits de {fichier} : REMIS COMME AVANT ({})",
            "Rights of {fichier}: PUT BACK AS BEFORE ({})",
            avant_notable(&avant)
        ),
        None => trf!(
            "Droits de {fichier} : aucune liste d'avant notée, rien ne sera écrit",
            "Rights of {fichier}: no previous list noted, nothing will be written"
        ),
    }
}

// ------------------------------------------------------------------------------------------------ sshd_config

/// sshd_config, son dossier et sshd.exe, vérifiés avant tout geste.
struct ConfigWin {
    dossier: PathBuf,
    sshd: PathBuf,
}

/// Le programme de sshd d'après son service : absolu, « sshd.exe », dans System32\OpenSSH (le serveur de Windows)
/// ou dans un dossier que seuls les administrateurs écrivent.
fn programme_sshd() -> Result<PathBuf, &'static str> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_WOW64_64KEY};
    let absent = tr!(
        "le serveur OpenSSH n'est pas installé (service sshd) : rien d'écrit",
        "the OpenSSH server is not installed (sshd service): nothing written"
    );
    let cle = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(
            r"SYSTEM\CurrentControlSet\Services\sshd",
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
        )
        .map_err(|_| absent)?;
    let brut = cle
        .get_raw_value("ImagePath")
        .ok()
        .and_then(|v| super::corrections::texte_reg(&v))
        .ok_or(absent)?;
    let inattendu = tr!(
        "le programme du service sshd n'est pas à un endroit sûr : refusé, rien d'écrit",
        "the sshd service program is not in a safe place: refused, nothing written"
    );
    let chemin = super::installes::developper(
        crate::machine::gestes::programme_du_chemin(&brut),
        &super::services::variable_systeme,
    )
    .ok_or(inattendu)?;
    let p = PathBuf::from(chemin.trim());
    let dossier = p.parent().filter(|_| p.is_absolute()).ok_or(inattendu)?;
    if !p
        .file_name()
        .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case("sshd.exe"))
    {
        return Err(inattendu);
    }
    let windows = crate::commande::dossier_systeme().join("OpenSSH");
    let sur = super::demarrage_ecriture::meme_chemin(&dossier.to_string_lossy(), &windows.to_string_lossy())
        || super::securite::proprietaire_et_droits(dossier)
            .is_some_and(|d| super::securite::reserve_aux_administrateurs(&d));
    if sur { Ok(p) } else { Err(inattendu) }
}

impl ConfigWin {
    fn nouveau() -> Result<ConfigWin, &'static str> {
        let sshd = programme_sshd()?;
        let dossier = dossier_ssh().ok_or(tr!(
            "le dossier ProgramData ne se lit pas : rien d'écrit",
            "the ProgramData folder cannot be read: nothing written"
        ))?;
        // La nouvelle version y attend `sshd -t` : un dossier qu'un autre compte écrit pourrait l'échanger.
        if !super::securite::proprietaire_et_droits(&dossier)
            .is_some_and(|d| super::securite::reserve_aux_administrateurs(&d))
        {
            return Err(tr!(
                r"%ProgramData%\ssh peut être modifié par d'autres que SYSTEM et les administrateurs : refusé, rien d'écrit",
                r"%ProgramData%\ssh can be modified by others than SYSTEM and administrators: refused, nothing written"
            ));
        }
        Ok(ConfigWin { dossier, sshd })
    }

    fn config(&self) -> PathBuf {
        self.dossier.join("sshd_config")
    }

    /// Un fichier de ce dossier, par son seul nom (jamais un chemin).
    fn dans(&self, nom: &str) -> Option<PathBuf> {
        (!nom.is_empty() && !nom.contains(['\\', '/', ':']) && nom != "." && nom != "..")
            .then(|| self.dossier.join(nom))
    }

    /// Un nom libre dans le dossier : `nom`, ou `nom-2`, `nom-3`…
    fn libre(&self, nom: &str) -> String {
        let mut n = 2u32;
        let mut libre = nom.to_string();
        while self.dossier.join(&libre).exists() && n < 100 {
            libre = format!("{nom}-{n}");
            n = n.saturating_add(1);
        }
        libre
    }
}

fn large(chemin: &Path) -> Vec<u16> {
    chemin.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// ReplaceFileW : `cible` devient `temporaire` (droits de `cible` gardés), l'ancienne prend le nom `copie` s'il y en
/// a une. Un antivirus qui lit le fichier : l'échange est refait (dix fois, 300 ms).
// FFI de kernel32 : ReplaceFileW.
#[allow(unsafe_code)]
fn remplacer(cible: &Path, temporaire: &Path, copie: Option<&Path>) -> Result<(), Echec> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn ReplaceFileW(
            remplace: *const u16,
            remplacant: *const u16,
            copie: *const u16,
            drapeaux: u32,
            exclure: *mut c_void,
            reserve: *mut c_void,
        ) -> i32;
    }
    const REPLACEFILE_WRITE_THROUGH: u32 = 0x1;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    const ERROR_UNABLE_TO_REMOVE_REPLACED: i32 = 1175;
    const ERROR_UNABLE_TO_MOVE_REPLACEMENT_2: i32 = 1177;
    let (c, t) = (large(cible), large(temporaire));
    let s = copie.map(large);
    let mut derniere = Echec::echoue(CTX, "ReplaceFileW");
    for _ in 0..10 {
        // SAFETY: les chemins sont des chaînes UTF-16 terminées par un zéro, vivantes pendant l'appel (la copie, ou un
        // pointeur nul : pas de copie) ; les deux pointeurs réservés sont nuls, comme la documentation l'exige.
        let ok = unsafe {
            ReplaceFileW(
                c.as_ptr(),
                t.as_ptr(),
                s.as_ref().map_or(std::ptr::null(), Vec::as_ptr),
                REPLACEFILE_WRITE_THROUGH,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok != 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        derniere = Echec::ecriture(CTX, &e);
        match e.raw_os_error() {
            Some(ERROR_SHARING_VIOLATION | ERROR_UNABLE_TO_REMOVE_REPLACED) => {
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
            Some(ERROR_UNABLE_TO_MOVE_REPLACEMENT_2) => {
                // L'ancienne porte déjà le nom de la copie et la nouvelle n'a pas pris sa place : l'ancienne revient.
                if let Some(copie) = copie {
                    let _ = std::fs::rename(copie, cible).is_ok() || std::fs::copy(copie, cible).is_ok();
                }
                return Err(derniere);
            }
            _ => return Err(derniere),
        }
    }
    Err(derniere)
}

impl ssh_regles::Config for ConfigWin {
    fn lire(&mut self) -> Result<Vec<u8>, Echec> {
        crate::socle::lire_ordinaire(&self.config(), CONFIG_MAX).map_err(|e| Echec::io(CTX, &e))
    }
    fn ecrire_temporaire(&mut self, octets: &[u8]) -> Result<String, Echec> {
        let nom = self.libre(NOUVEAU);
        let chemin = self.dossier.join(&nom);
        let ecrit = (|| {
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&chemin)?;
            f.write_all(octets)?;
            f.sync_all()
        })();
        match ecrit {
            Ok(()) => Ok(nom),
            Err(e) => {
                let _ = std::fs::remove_file(&chemin);
                Err(Echec::ecriture(CTX, &e))
            }
        }
    }
    fn tester(&mut self, temporaire: &str) -> Result<(), Echec> {
        let chemin = self.dans(temporaire).ok_or_else(inconnu)?;
        let mut c = std::process::Command::new(&self.sshd);
        c.arg("-t").arg("-f").arg(&chemin);
        super::environnement::reduire(&mut c);
        match crate::commande::lancer(&mut c, 20) {
            Some(r) if r.code == Some(0) => Ok(()),
            Some(r) => Err(Echec::echoue(
                CTX,
                format!("{} {}", r.erreurs.trim(), r.sortie.trim()).trim(),
            )),
            None => Err(Echec::echoue(CTX, tr!("sshd ne répond pas", "sshd does not answer"))),
        }
    }
    fn effacer_temporaire(&mut self, temporaire: &str) {
        if temporaire.starts_with(NOUVEAU)
            && let Some(p) = self.dans(temporaire)
        {
            let _ = std::fs::remove_file(p);
        }
    }
    fn nom_copie(&mut self) -> String {
        let date = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
        self.libre(&format!("{}{date}", ssh_regles::PREFIXE_COPIE))
    }
    fn remplacer(&mut self, temporaire: &str, copie: Option<&str>) -> Result<(), Echec> {
        let t = self.dans(temporaire).ok_or_else(inconnu)?;
        let c = match copie {
            Some(n) if ssh_regles::nom_copie_valide(n) => Some(self.dans(n).ok_or_else(inconnu)?),
            Some(_) => return Err(inconnu()),
            None => None,
        };
        remplacer(&self.config(), &t, c.as_deref())
    }
    fn lire_copie(&mut self, nom: &str) -> Result<Vec<u8>, Echec> {
        if !ssh_regles::nom_copie_valide(nom) {
            return Err(inconnu());
        }
        let p = self.dans(nom).ok_or_else(inconnu)?;
        crate::socle::lire_ordinaire(&p, CONFIG_MAX).map_err(|e| Echec::io(CTX, &e))
    }
    fn lire_note(&mut self, nom: &str) -> Option<Vec<u8>> {
        crate::machine::choix_avant::lire_brut(nom)
    }
    fn ecrire_note(&mut self, nom: &str, octets: &[u8]) -> Result<(), Echec> {
        crate::machine::choix_avant::ecrire_brut(nom, octets).map_err(|e| Echec::echoue(CTX, e.to_string()))
    }
    fn effacer_note(&mut self, nom: &str) {
        crate::machine::choix_avant::effacer_brut(nom);
    }
}

/// Les ports de sshd d'après la configuration lue (22 sans elle).
fn ports(c: &mut ConfigWin) -> Vec<u16> {
    use ssh_regles::Config as _;
    c.lire()
        .ok()
        .and_then(|o| ssh_regles::texte_config(&o).map(ssh_regles::ports_sshd))
        .unwrap_or_else(|| vec![22])
}

/// Après une écriture de sshd_config : sshd redémarré s'il tourne et qu'aucune session SSH n'est ouverte (relue à
/// l'instant), sinon la configuration vaudra à son prochain démarrage ; dit dans la console élevée.
fn relancer(c: &mut ConfigWin) {
    let session = crate::protection::blocage::gardes::session_ssh_ouverte(&ports(c));
    match ssh_regles::relance(super::services_ecriture::en_marche(SERVICE), session) {
        Relance::Redemarrer => match super::services_ecriture::redemarrer_si_en_marche(SERVICE) {
            Ok(true) => trp!(
                "  sshd redémarré : le réglage vaut maintenant.",
                "  sshd restarted: the setting applies now."
            ),
            Ok(false) => trp!(
                "  sshd s'est arrêté entre-temps : le réglage vaudra à son prochain démarrage.",
                "  sshd stopped meanwhile: the setting will apply at its next start."
            ),
            Err(e) => trp!(
                "  sshd ne redémarre pas ({}) : le réglage vaudra au prochain redémarrage de sshd.",
                "  sshd does not restart ({}): the setting will apply at the next sshd restart.",
                crate::ui::affichable(&e.to_string())
            ),
        },
        Relance::AuProchain => trp!(
            "  Une session SSH est ouverte (ou les connexions ne se lisent pas) : Vanguard ne la coupe jamais, le réglage vaudra au prochain redémarrage de sshd.",
            "  An SSH session is open (or connections cannot be read): Vanguard never cuts it, the setting will apply at the next sshd restart."
        ),
        Relance::Arrete => trp!(
            "  sshd est arrêté : le réglage vaudra à son prochain démarrage.",
            "  sshd is stopped: the setting will apply at its next start."
        ),
    }
}

/// Met le réglage `r` de sshd_config à « no ».
pub(super) fn sshd(r: ReglageSshd) -> Resultat {
    use ssh_regles::Config as _;
    let mut c = match ConfigWin::nouveau() {
        Ok(c) => c,
        Err(raison) => return refus(raison),
    };
    // Déjà corrigé : rien, et aucune question.
    if let Ok(o) = c.lire()
        && let Some(t) = ssh_regles::texte_config(&o)
        && !ssh_regles::signale(r, t)
    {
        return resultat(Issue::Rien(format!("{} no", r.mot_cle())));
    }
    if r == ReglageSshd::MotsDePasse {
        let session = crate::protection::blocage::gardes::session_ssh_ouverte(&ports(&mut c));
        let question = tr!(
            "  Couper les mots de passe de SSH : seules les clés ouvriront encore une session. Une clé est-elle déjà posée pour votre compte ? [o/N] : ",
            "  Turn off SSH passwords: only keys will still open a session. Is a key already set up for your account? [y/N]: "
        );
        match ssh_regles::accord_mots_de_passe(session, || {
            reglages::confirmer(super::eleve::console_reelle(), question, crate::ui::demander_ou_defaut)
        }) {
            AccordMdp::RefusSession => {
                return refus(tr!(
                    "une session SSH est ouverte (ou les connexions ne se lisent pas) : elle a pu l'être par mot de passe, Vanguard ne coupe jamais une session à distance ; rien d'écrit",
                    "an SSH session is open (or connections cannot be read): it may have been opened with a password, Vanguard never cuts a remote session; nothing written"
                ));
            }
            AccordMdp::NonConfirme => {
                return refus(tr!("non confirmé : rien d'écrit", "not confirmed: nothing written"));
            }
            AccordMdp::Oui => {}
        }
    }
    let issue = ssh_regles::ecrire_sshd(&mut c, r, &ssh_regles::nom_note_sshd(r));
    if matches!(issue, Issue::Fait { .. }) {
        relancer(&mut c);
    }
    resultat(issue)
}

/// Remet la copie d'avant de sshd_config (une baisse, déjà montrée et confirmée).
pub(super) fn sshd_remettre(r: ReglageSshd) -> Resultat {
    let mut c = match ConfigWin::nouveau() {
        Ok(c) => c,
        Err(raison) => return refus(raison),
    };
    let issue = ssh_regles::remettre_sshd(&mut c, &ssh_regles::nom_note_sshd(r));
    if matches!(issue, Issue::Fait { .. }) {
        relancer(&mut c);
    }
    resultat(issue)
}

/// Ce qu'une remise de sshd_config va écrire, montré avant la question des baisses.
pub(super) fn texte_remise_sshd(r: ReglageSshd) -> String {
    let nom = ssh_regles::nom_note_sshd(r);
    let note = crate::machine::choix_avant::lire_brut(&nom).and_then(|o| ssh_regles::note_sshd(&o, &nom));
    match note {
        Some((copie, _, _)) => trf!(
            "sshd_config ({}) : REMIS COMME AVANT (copie {})",
            "sshd_config ({}): PUT BACK AS BEFORE (copy {})",
            r.mot_cle(),
            crate::ui::affichable(&copie)
        ),
        None => trf!(
            "sshd_config ({}) : aucune copie d'avant notée, rien ne sera écrit",
            "sshd_config ({}): no previous copy noted, nothing will be written",
            r.mot_cle()
        ),
    }
}

/// La remise d'un geste SSH, montrée comme une baisse ; `None` pour un autre acte.
pub(super) fn juger(acte: &crate::machine::gestes::Acte, personne: Option<&str>) -> Option<(Montre, String)> {
    use crate::machine::gestes::Acte;
    let texte = match acte {
        Acte::SshDroitsRemettre(c) => texte_remise_droits(c, personne),
        Acte::SshdReglageRemettre(r) => texte_remise_sshd(*r),
        _ => return None,
    };
    Some((
        Montre {
            sens: Sens::Baisse,
            lue: None,
        },
        texte,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::gestes::{self, Acte};

    /// Les remises SSH sont des baisses, montrées comme telles ; les gestes qui durcissent n'en sont pas : une liste
    /// qui mêle une remise à un autre geste est refusée en entier par le processus élevé (`liste_pure`).
    #[test]
    fn remises_jugees_baisses_et_liste_melee_refusee() {
        let remises = [
            gestes::ligne_ssh_droits_remettre(None).unwrap(),
            gestes::ligne_ssh_droits_remettre(Some("id_ed25519")).unwrap(),
            gestes::ligne_sshd_reglage_remettre(ReglageSshd::MotsDePasseVides),
            gestes::ligne_sshd_reglage_remettre(ReglageSshd::MotsDePasse),
        ];
        for l in &remises {
            let a = gestes::analyser_acte(l).unwrap();
            let (m, texte) = juger(&a, Some("S-1-5-21-1-2-3-1001")).unwrap();
            assert_eq!(m.sens, Sens::Baisse, "{l}");
            assert!(!texte.contains(['\x1b', '\r', '\n']), "{texte:?}");
        }
        let gestes_durs = [
            gestes::ligne_ssh_droits(None).unwrap(),
            gestes::ligne_ssh_droits(Some("id_ed25519")).unwrap(),
            gestes::ligne_sshd_reglage(ReglageSshd::MotsDePasse),
        ];
        for l in &gestes_durs {
            assert!(juger(&gestes::analyser_acte(l).unwrap(), None).is_none(), "{l}");
        }
        // Un autre acte n'est pas jugé ici.
        assert!(juger(&Acte::PareFeuActif, None).is_none());
        let melee: Vec<Option<Sens>> = [&gestes_durs[0], &remises[2]]
            .iter()
            .map(|l| juger(&gestes::analyser_acte(l).unwrap(), None).map(|(m, _)| m.sens))
            .collect();
        assert_eq!(gestes::liste_pure(&melee), Err(()));
    }

    /// Un fichier du dossier ssh se désigne par son seul nom : un chemin, un lecteur ou un nom vide n'y mènent pas.
    #[test]
    fn un_fichier_du_dossier_par_son_seul_nom() {
        let c = ConfigWin {
            dossier: PathBuf::from(r"C:\ProgramData\ssh"),
            sshd: PathBuf::from(r"C:\Windows\System32\OpenSSH\sshd.exe"),
        };
        assert_eq!(
            c.dans("sshd_config.vanguard-nouveau"),
            Some(PathBuf::from(r"C:\ProgramData\ssh\sshd_config.vanguard-nouveau"))
        );
        for nom in ["", ".", "..", r"..\sshd_config", "a/b", r"C:\x", "C:x", r"\\serveur\p"] {
            assert_eq!(c.dans(nom), None, "{nom:?}");
        }
        assert_eq!(c.config(), PathBuf::from(r"C:\ProgramData\ssh\sshd_config"));
    }
}

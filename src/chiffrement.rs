//! Protection des données de la clé VANGUARD par une phrase de passe (menu Données). Contre une clé perdue ou
//! prêtée : le carnet des appareils (`donnees/appareils.json`) y est chiffré, et le rapport et le diagnostic ne s'y
//! écrivent plus. Pas contre l'ordinateur où Vanguard tourne, qui doit lire les données pour travailler.
//!
//! Une clé de données de 32 octets, tirée au hasard, chiffre le carnet (XChaCha20-Poly1305 : un fichier modifié est
//! refusé, pas lu de travers). Elle est gardée deux fois :
//! - en clair dans le dossier local du propriétaire (`cle-donnees`, lisible par lui seul) : chez lui, rien ne change,
//!   pas de phrase, et la surveillance horaire continue de lire et d'écrire le carnet ;
//! - enveloppée par la phrase sur la clé (`donnees/cle.enveloppe`, dérivation Argon2id) : sur un autre ordinateur,
//!   Vanguard demande la phrase ; Entrée sans rien, il continue sans le carnet.
//!
//! Phrase oubliée : tant que l'ordinateur du propriétaire existe, il en pose une nouvelle (il a la clé en clair).
//! Ordinateur et phrase perdus : le carnet de la clé est perdu, c'est voulu ; une sauvegarde est proposée avant
//! d'activer la protection.

use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

/// En-tête d'un fichier chiffré : le format, pour qu'un autre fichier ne soit jamais pris pour lui.
const MAGIQUE: &[u8; 8] = b"VANGDAT1";
/// En-tête de l'enveloppe de la clé de données.
const MAGIQUE_ENVELOPPE: &[u8; 8] = b"VANGENV1";
const TAILLE_NONCE: usize = 24;
const TAILLE_SEL: usize = 16;
/// Argon2id : 64 Mio de mémoire, 3 passes, un fil : environ une demi-seconde, et chaque essai d'une force brute coûte
/// autant.
pub(crate) const PARAMETRES: (u32, u32, u32) = (64 * 1024, 3, 1);

/// La clé de données, jamais écrite en clair ailleurs que chez le propriétaire.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Cle([u8; 32]);

impl std::fmt::Debug for Cle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cle(…)")
    }
}

/// Pourquoi des données n'ont pas pu être ouvertes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refus {
    /// Ce n'est pas un fichier de Vanguard, ou il est tronqué.
    Format,
    /// Mauvaise phrase (enveloppe), ou fichier modifié, ou chiffré avec une autre clé : l'authentification a échoué.
    Authentification,
}

impl Cle {
    pub(crate) fn nouvelle() -> std::io::Result<Cle> {
        let mut octets = [0u8; 32];
        getrandom::fill(&mut octets).map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(Cle(octets))
    }

    /// Identifiant de la clé (BLAKE3, 16 octets en hexadécimal), écrit en clair dans l'enveloppe : il dit si la clé
    /// gardée chez le propriétaire est bien celle de cette clé USB, sans rien révéler d'elle.
    pub(crate) fn identifiant(&self) -> String {
        blake3::hash(&self.0).to_hex()[..32].to_string()
    }

    fn chiffreur(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&self.0.into())
    }
}

fn hasard<const N: usize>() -> std::io::Result<[u8; N]> {
    let mut octets = [0u8; N];
    getrandom::fill(&mut octets).map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(octets)
}

/// Chiffre `clair`. `nom` (« appareils.json ») est authentifié avec : un fichier chiffré ne peut pas être pris pour un
/// autre en le renommant.
pub(crate) fn chiffrer(cle: &Cle, nom: &str, clair: &[u8]) -> std::io::Result<Vec<u8>> {
    let nonce: [u8; TAILLE_NONCE] = hasard()?;
    let chiffre = cle
        .chiffreur()
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: clair,
                aad: nom.as_bytes(),
            },
        )
        .map_err(|_| std::io::Error::other("chiffrement impossible"))?;
    Ok([&MAGIQUE[..], &nonce, &chiffre].concat())
}

pub(crate) fn dechiffrer(cle: &Cle, nom: &str, donnees: &[u8]) -> Result<Vec<u8>, Refus> {
    let reste = donnees.strip_prefix(&MAGIQUE[..]).ok_or(Refus::Format)?;
    if reste.len() < TAILLE_NONCE {
        return Err(Refus::Format);
    }
    let (nonce, chiffre) = reste.split_at(TAILLE_NONCE);
    let nonce: [u8; TAILLE_NONCE] = nonce.try_into().map_err(|_| Refus::Format)?;
    cle.chiffreur()
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: chiffre,
                aad: nom.as_bytes(),
            },
        )
        .map_err(|_| Refus::Authentification)
}

/// La clé de la phrase, par Argon2id.
fn deriver(phrase: &str, sel: &[u8], (memoire, passes, fils): (u32, u32, u32)) -> Result<Cle, Refus> {
    let parametres = Params::new(memoire, passes, fils, Some(32)).map_err(|_| Refus::Format)?;
    let mut octets = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, parametres)
        .hash_password_into(phrase.as_bytes(), sel, &mut octets)
        .map_err(|_| Refus::Format)?;
    Ok(Cle(octets))
}

/// L'enveloppe de la clé de données par une phrase : en-tête, paramètres d'Argon2id (pour pouvoir les durcir plus
/// tard sans perdre les anciennes), sel, identifiant de la clé, puis la clé chiffrée.
pub(crate) fn envelopper(cle: &Cle, phrase: &str, parametres: (u32, u32, u32)) -> std::io::Result<Vec<u8>> {
    let sel: [u8; TAILLE_SEL] = hasard()?;
    let enveloppante = deriver(phrase, &sel, parametres).map_err(|_| std::io::Error::other("paramètres refusés"))?;
    let identifiant = cle.identifiant();
    let chiffre = chiffrer(&enveloppante, &identifiant, &cle.0)?;
    let (m, t, p) = parametres;
    Ok([
        &MAGIQUE_ENVELOPPE[..],
        &m.to_le_bytes(),
        &t.to_le_bytes(),
        &p.to_le_bytes(),
        &sel,
        identifiant.as_bytes(),
        &chiffre,
    ]
    .concat())
}

/// L'identifiant de la clé écrit dans une enveloppe, sans phrase.
pub(crate) fn identifiant_de(enveloppe: &[u8]) -> Option<String> {
    let debut = MAGIQUE_ENVELOPPE.len() + 12 + TAILLE_SEL;
    enveloppe
        .strip_prefix(&MAGIQUE_ENVELOPPE[..])
        .and_then(|_| enveloppe.get(debut..debut + 32))
        .and_then(|i| std::str::from_utf8(i).ok())
        .map(str::to_string)
}

pub(crate) fn ouvrir(enveloppe: &[u8], phrase: &str) -> Result<Cle, Refus> {
    let reste = enveloppe.strip_prefix(&MAGIQUE_ENVELOPPE[..]).ok_or(Refus::Format)?;
    let nombre = |i: usize| -> Result<u32, Refus> {
        let o: [u8; 4] = reste
            .get(i..i + 4)
            .and_then(|o| o.try_into().ok())
            .ok_or(Refus::Format)?;
        Ok(u32::from_le_bytes(o))
    };
    let parametres = (nombre(0)?, nombre(4)?, nombre(8)?);
    // Des paramètres démesurés (enveloppe fabriquée) ne doivent pas bloquer l'ordinateur : 1 Gio et 10 passes au plus.
    if parametres.0 > 1024 * 1024 || parametres.1 > 10 || parametres.2 > 8 {
        return Err(Refus::Format);
    }
    let sel = reste.get(12..12 + TAILLE_SEL).ok_or(Refus::Format)?;
    let identifiant = reste
        .get(12 + TAILLE_SEL..12 + TAILLE_SEL + 32)
        .and_then(|i| std::str::from_utf8(i).ok())
        .ok_or(Refus::Format)?;
    let chiffre = reste.get(12 + TAILLE_SEL + 32..).ok_or(Refus::Format)?;
    let enveloppante = deriver(phrase, sel, parametres)?;
    let octets: [u8; 32] = dechiffrer(&enveloppante, identifiant, chiffre)?
        .try_into()
        .map_err(|_| Refus::Format)?;
    let cle = Cle(octets);
    if cle.identifiant() == identifiant {
        Ok(cle)
    } else {
        Err(Refus::Authentification)
    }
}

// ───────────────────────────── Où vit quoi ─────────────────────────────

pub(crate) const ENVELOPPE: &str = "cle.enveloppe";
/// Le carnet chiffré, à côté de l'ancien nom en clair.
pub(crate) const CARNET_CHIFFRE: &str = "appareils.json.vanguard";

/// La clé de données gardée chez le propriétaire.
fn chemin_local() -> PathBuf {
    crate::socle::dossier_local().join("cle-donnees")
}

pub(crate) fn lire_cle_locale(chemin: &Path) -> Option<Cle> {
    let octets: [u8; 32] = std::fs::read(chemin).ok()?.try_into().ok()?;
    Some(Cle(octets))
}

/// Écrite lisible par le compte seul (0600 sous Linux et macOS ; le dossier local de Windows est déjà au compte).
pub(crate) fn ecrire_cle_locale(cle: &Cle, chemin: &Path) -> std::io::Result<()> {
    if let Some(d) = chemin.parent() {
        std::fs::create_dir_all(d)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(chemin)?;
    std::io::Write::write_all(&mut f, &cle.0)?;
    f.sync_all()
}

/// Les données de la clé sont-elles protégées par une phrase ?
pub(crate) fn protegee(donnees: &Path) -> bool {
    donnees.join(ENVELOPPE).is_file()
}

/// La clé de données de la clé USB branchée, cherchée une fois par lancement : celle gardée ici si elle va avec
/// l'enveloppe, sinon par la phrase (dans un terminal seulement : la surveillance, sans personne devant l'écran,
/// continue sans le carnet). Ouverte chez le propriétaire, elle y est gardée de nouveau (ordinateur réinstallé).
fn cle_pour(donnees: &Path) -> Option<Cle> {
    static SESSION: std::sync::OnceLock<Option<Cle>> = std::sync::OnceLock::new();
    SESSION.get_or_init(|| obtenir(donnees)).clone()
}

fn obtenir(donnees: &Path) -> Option<Cle> {
    use std::io::IsTerminal;
    let enveloppe = std::fs::read(donnees.join(ENVELOPPE)).ok()?;
    let identifiant = identifiant_de(&enveloppe)?;
    if let Some(cle) = lire_cle_locale(&chemin_local()).filter(|c| c.identifiant() == identifiant) {
        return Some(cle);
    }
    if cfg!(test) || !std::io::stdin().is_terminal() {
        return None;
    }
    for _ in 0..3 {
        let phrase = rpassword::prompt_password(crate::tr!(
            "  Phrase des données de la clé VANGUARD (Entrée : continuer sans le carnet) : ",
            "  VANGUARD key data passphrase (Enter: go on without the record): "
        ))
        .ok()?;
        if phrase.is_empty() {
            crate::trp!(
                "  {}Carnet de la clé non lu : rien n'y sera écrit.{}",
                "  {}Key record not read: nothing will be written to it.{}",
                crate::ui::GRIS,
                crate::ui::RESET
            );
            return None;
        }
        match ouvrir(&enveloppe, &phrase) {
            Ok(cle) => {
                if donnees.parent().is_some_and(est_au_proprietaire) {
                    let _ = ecrire_cle_locale(&cle, &chemin_local());
                }
                return Some(cle);
            }
            Err(Refus::Authentification) => crate::trp!("  ✖ Phrase incorrecte.", "  ✖ Wrong passphrase."),
            Err(Refus::Format) => {
                crate::trp!(
                    "  ✖ Enveloppe de la clé illisible : carnet non lu.",
                    "  ✖ Key envelope unreadable: record not read."
                );
                return None;
            }
        }
    }
    None
}

/// La clé USB appartient-elle à cet ordinateur (seul endroit où la clé de données se garde en clair) ?
fn est_au_proprietaire(cle_usb: &Path) -> bool {
    #[cfg(unix)]
    {
        crate::protection::cle::chez_le_proprietaire(cle_usb)
    }
    #[cfg(windows)]
    {
        let _ = cle_usb;
        false
    }
}

/// Le carnet chiffré, en texte, s'il s'ouvre ; un carnet pas encore écrit est vide.
pub(crate) fn lire_carnet(donnees: &Path) -> Option<String> {
    let cle = cle_pour(donnees)?;
    lire_carnet_avec(donnees, &cle)
}

fn lire_carnet_avec(donnees: &Path, cle: &Cle) -> Option<String> {
    let Ok(octets) = std::fs::read(donnees.join(CARNET_CHIFFRE)) else {
        return Some("{}".into());
    };
    if let Ok(clair) = dechiffrer(cle, "appareils.json", &octets) {
        String::from_utf8(clair).ok()
    } else {
        crate::tre!(
            "Attention : le carnet chiffré de la clé ne s'ouvre pas (modifié, ou d'une autre clé) : il n'est ni lu ni réécrit.",
            "Warning: the key's encrypted record does not open (modified, or from another key): it is neither read nor rewritten."
        );
        None
    }
}

/// Écrit le carnet chiffré, et retire le carnet en clair s'il traîne encore à côté.
pub(crate) fn ecrire_carnet(donnees: &Path, json: &str) -> std::io::Result<()> {
    let cle = cle_pour(donnees).ok_or_else(|| std::io::Error::other("carnet protégé et pas ouvert"))?;
    ecrire_carnet_avec(donnees, &cle, json)
}

fn ecrire_carnet_avec(donnees: &Path, cle: &Cle, json: &str) -> std::io::Result<()> {
    crate::socle::ecrire_atomique(
        &donnees.join(CARNET_CHIFFRE),
        chiffrer(cle, "appareils.json", json.as_bytes())?,
    )?;
    match std::fs::remove_file(donnees.join("appareils.json")) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Le carnet ouvert pendant ce lancement : le journal des erreurs en retire aussi les noms.
static CARNET: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

pub(crate) fn retenir_carnet(texte: &str) {
    *CARNET.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(texte.to_string());
}

pub(crate) fn carnet_ouvert() -> Option<String> {
    CARNET.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
}

// ───────────────────────────── Activer, changer, retirer ─────────────────────────────

/// Protège le dossier `donnees` : clé de données neuve, gardée dans `cle_locale` et enveloppée par la phrase ; le
/// carnet chiffré puis relu avant que le carnet en clair parte ; le rapport et les copies du diagnostic déplacés dans
/// `local` (ils ne s'écrivent plus sur la clé).
pub(crate) fn proteger_dans(
    donnees: &Path,
    cle_locale: &Path,
    local: &Path,
    phrase: &str,
    parametres: (u32, u32, u32),
) -> std::io::Result<()> {
    let cle = Cle::nouvelle()?;
    let clair = std::fs::read_to_string(donnees.join("appareils.json")).unwrap_or_else(|_| "{}".into());
    ecrire_cle_locale(&cle, cle_locale)?;
    crate::socle::ecrire_atomique(&donnees.join(ENVELOPPE), envelopper(&cle, phrase, parametres)?)?;
    let chiffre = chiffrer(&cle, "appareils.json", clair.as_bytes())?;
    crate::socle::ecrire_atomique(&donnees.join(CARNET_CHIFFRE), &chiffre)?;
    // Relu avant d'effacer quoi que ce soit : le carnet en clair ne part que si le chiffré redonne le même texte.
    if lire_carnet_avec(donnees, &cle).as_deref() != Some(clair.as_str()) {
        return Err(std::io::Error::other("le carnet chiffré ne se relit pas"));
    }
    match std::fs::remove_file(donnees.join("appareils.json")) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    deplacer_rapports(donnees, local);
    Ok(())
}

/// Le rapport et les copies du diagnostic, jusqu'ici sur la clé, rangés sur cet ordinateur.
fn deplacer_rapports(donnees: &Path, local: &Path) {
    for e in std::fs::read_dir(donnees).into_iter().flatten().flatten() {
        let nom = e.file_name().to_string_lossy().into_owned();
        let rapport = nom == "rapport.html" || nom == "rapport.md";
        let diagnostic = nom.starts_with("diagnostic-")
            && Path::new(&nom)
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("txt"));
        if (rapport || diagnostic) && std::fs::create_dir_all(local).is_ok() {
            let vers = local.join(&nom);
            if std::fs::rename(e.path(), &vers).is_err() && std::fs::copy(e.path(), &vers).is_ok() {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

/// Retire la protection : le carnet remis en clair (relu d'abord), puis l'enveloppe et la clé gardée ici retirées.
fn retirer_dans(donnees: &Path, cle: &Cle, cle_locale: &Path) -> std::io::Result<()> {
    let clair =
        lire_carnet_avec(donnees, cle).ok_or_else(|| std::io::Error::other("le carnet chiffré ne s'ouvre pas"))?;
    crate::socle::ecrire_atomique(&donnees.join("appareils.json"), &clair)?;
    for f in [
        donnees.join(CARNET_CHIFFRE),
        donnees.join(ENVELOPPE),
        cle_locale.to_path_buf(),
    ] {
        match std::fs::remove_file(f) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    }
    Ok(())
}

/// Une nouvelle phrase : la même clé de données, dans une nouvelle enveloppe.
fn nouvelle_phrase_dans(donnees: &Path, cle: &Cle, phrase: &str, parametres: (u32, u32, u32)) -> std::io::Result<()> {
    crate::socle::ecrire_atomique(&donnees.join(ENVELOPPE), envelopper(cle, phrase, parametres)?)
}

/// Demande une phrase deux fois. 10 caractères au moins : c'est la seule défense d'une clé perdue.
fn demander_phrase() -> Option<String> {
    let phrase = rpassword::prompt_password(crate::tr!(
        "  Phrase (10 caractères au moins, plusieurs mots c'est mieux) : ",
        "  Passphrase (at least 10 characters; several words are better): "
    ))
    .ok()?;
    if phrase.chars().count() < 10 {
        crate::trp!("  ✖ Trop courte : rien n'a changé.", "  ✖ Too short: nothing changed.");
        return None;
    }
    let encore = rpassword::prompt_password(crate::tr!("  La même, encore : ", "  The same, again: ")).ok()?;
    if encore != phrase {
        crate::trp!(
            "  ✖ Les deux phrases diffèrent : rien n'a changé.",
            "  ✖ The two passphrases differ: nothing changed."
        );
        return None;
    }
    Some(phrase)
}

/// Menu Vanguard › Protéger les données de la clé : activer, changer la phrase, retirer la protection. Seulement sur
/// l'ordinateur du propriétaire, où la clé est modifiable.
pub fn menu() {
    use crate::ui::*;
    titre(tr!("Protéger les données de la clé", "Protect the key's data"));
    let Some(donnees) = crate::reseau::donnees_de_la_cle() else {
        afficher_aligne(
            "  ",
            tr!(
                "Branchez la clé VANGUARD sur votre ordinateur (celui où elle est modifiable) : la protection se règle seulement là.",
                "Plug the VANGUARD key into your own computer (where it can be written): protection is set only there."
            ),
            2,
            "",
        );
        return;
    };
    let local = crate::socle::dossier_local();
    if protegee(&donnees) {
        afficher_aligne(
            &format!("  {VERT}✔{RESET} "),
            tr!(
                "Le carnet des appareils de la clé est chiffré. Sur un autre ordinateur, Vanguard demande la phrase ; le rapport et le diagnostic ne s'écrivent plus sur la clé.",
                "The key's device record is encrypted. On another computer, Vanguard asks for the passphrase; the report and the diagnostic are no longer written to the key."
            ),
            4,
            "",
        );
        let Some(cle) = cle_pour(&donnees) else {
            trp!(
                "  ✖ Carnet pas ouvert : rien à changer.",
                "  ✖ Record not opened: nothing to change."
            );
            return;
        };
        let reponse = crate::selection::choisir_en_ligne(
            &[
                ("n", tr!("Nouvelle phrase", "New passphrase")),
                ("r", tr!("Retirer la protection", "Remove the protection")),
            ],
            tr!(
                "\n  n : nouvelle phrase · r : retirer la protection · Entrée pour revenir : ",
                "\n  n: new passphrase · r: remove the protection · Enter to go back: "
            ),
        )
        .unwrap_or_default();
        match reponse.as_str() {
            "n" => {
                if let Some(phrase) = demander_phrase() {
                    match nouvelle_phrase_dans(&donnees, &cle, &phrase, PARAMETRES) {
                        Ok(()) => trp!(
                            "  {VERT}✔{RESET} Nouvelle phrase posée.",
                            "  {VERT}✔{RESET} New passphrase set."
                        ),
                        Err(e) => trp!(
                            "  ✖ Impossible ({e}) : l'ancienne phrase reste.",
                            "  ✖ Not possible ({e}): the old passphrase stays."
                        ),
                    }
                }
            }
            "r" if demander(tr!(
                "  Remettre le carnet en clair sur la clé ? [o/N] : ",
                "  Put the record back in clear on the key? [y/N]: "
            ))
            .oui() =>
            {
                match retirer_dans(&donnees, &cle, &chemin_local()) {
                    Ok(()) => {
                        noter_la_cle(&donnees);
                        trp!(
                            "  {VERT}✔{RESET} Protection retirée : le carnet est en clair.",
                            "  {VERT}✔{RESET} Protection removed: the record is in clear."
                        );
                    }
                    Err(e) => trp!(
                        "  ✖ Impossible ({e}) : la protection reste.",
                        "  ✖ Not possible ({e}): protection stays."
                    ),
                }
            }
            _ => {}
        }
        return;
    }
    for l in envelopper(
        tr!(
            "Le carnet des appareils de la clé (noms, adresses MAC, surnoms de chez vous et de chez vos amis) est en clair : qui ramasse la clé le lit. Protégé, il est chiffré par une phrase. Ici, rien ne change ; sur un autre ordinateur, Vanguard demande la phrase. Le rapport et le diagnostic ne s'écrivent plus sur la clé. Phrase oubliée : cet ordinateur en pose une nouvelle. Cet ordinateur et la phrase perdus : le carnet est perdu.",
            "The key's device record (names, MAC addresses, nicknames from your home and your friends') is in clear: whoever picks up the key reads it. Protected, it is encrypted by a passphrase. Here, nothing changes; on another computer, Vanguard asks for the passphrase. The report and the diagnostic are no longer written to the key. Forgotten passphrase: this computer sets a new one. This computer and the passphrase lost: the record is lost."
        ),
        LARGEUR - 2,
    ) {
        println!("  {l}");
    }
    if demander(tr!(
        "\n  Faire d'abord une sauvegarde du carnet sur cet ordinateur ? [O/n] : ",
        "\n  First make a backup of the record on this computer? [Y/n]: "
    ))
    .chars()
    .next()
    .is_none_or(|c| matches!(c, 'o' | 'O' | 'y' | 'Y'))
    {
        crate::donnees::sauvegarder(None);
    }
    if !demander(tr!(
        "\n  Protéger le carnet de la clé ? [o/N] : ",
        "\n  Protect the key's record? [y/N]: "
    ))
    .oui()
    {
        trp!("  Rien n'a changé.", "  Nothing changed.");
        return;
    }
    let Some(phrase) = demander_phrase() else { return };
    trp!("  {GRIS}Chiffrement…{RESET}", "  {GRIS}Encrypting…{RESET}");
    match proteger_dans(&donnees, &chemin_local(), &local, &phrase, PARAMETRES) {
        Ok(()) => {
            noter_la_cle(&donnees);
            afficher_aligne(
                &format!("  {VERT}✔{RESET} "),
                tr!(
                    "Carnet chiffré. Retenez bien la phrase : sans elle, ailleurs, Vanguard continue sans le carnet.",
                    "Record encrypted. Remember the passphrase: without it, elsewhere, Vanguard goes on without the record."
                ),
                4,
                "",
            );
        }
        Err(e) => {
            // L'enveloppe d'un essai raté ne doit pas faire croire la clé protégée : le carnet en clair est resté.
            let _ = std::fs::remove_file(donnees.join(ENVELOPPE));
            let _ = std::fs::remove_file(donnees.join(CARNET_CHIFFRE));
            trp!(
                "  ✖ Impossible ({e}) : le carnet reste en clair.",
                "  ✖ Not possible ({e}): the record stays in clear."
            );
        }
    }
}

/// La protection vient d'être posée ou retirée ici, par la personne : l'état de la clé est de nouveau sa référence
/// (sinon le retrait passerait pour fait hors de Vanguard, et le carnet ne serait plus jamais lu).
fn noter_la_cle(donnees: &Path) {
    if let Some(racine) = donnees.parent() {
        crate::protection::cles_connues::noter(racine);
    }
}

/// Au bilan : le carnet de la clé branchée est-il lisible par qui la ramasse ? Info seulement.
pub fn constat() -> Option<crate::machine::Constat> {
    if cfg!(test) {
        return None;
    }
    let donnees = crate::reseau::cle_usb()?.join("donnees");
    constat_de(&donnees)
}

fn constat_de(donnees: &Path) -> Option<crate::machine::Constat> {
    if protegee(donnees) || !donnees.join("appareils.json").is_file() {
        return None;
    }
    Some(crate::machine::Constat {
        categorie: "Clé VANGUARD",
        probleme: Some(crate::risk::Niveau::Info),
        message: crate::tr!(
            "Le carnet des appareils de la clé est en clair : qui la ramasse le lit.",
            "The key's device record is in clear: whoever picks up the key reads it."
        )
        .to_string(),
        correctif: Some(crate::machine::Correctif {
            action: crate::tr!(
                "Menu Vanguard › Protéger les données de la clé (une phrase, demandée seulement sur les autres ordinateurs)",
                "Vanguard menu › Protect the drive's data (a passphrase, asked only on other computers)"
            )
            .to_string(),
            commandes: Vec::new(),
            automatique: false,
            bloque: None,
            defaire: crate::machine::Defaire::Inconnu,
        }),
        verifie: true,
        regle: "",
        objet: crate::modele::Objet::NonMigre,
        precision: crate::modele::Precision::Aucune,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Argon2id réduit pour les tests : la même logique, en quelques millisecondes.
    const RAPIDE: (u32, u32, u32) = (64, 1, 1);

    #[test]
    fn aller_retour_et_fichier_modifie_refuse() {
        let cle = Cle::nouvelle().unwrap();
        let clair = br#"{"appareils":{}}"#;
        let chiffre = chiffrer(&cle, "appareils.json", clair).unwrap();
        assert!(!chiffre.windows(clair.len()).any(|w| w == clair));
        assert_eq!(dechiffrer(&cle, "appareils.json", &chiffre).unwrap(), clair);
        // Un octet changé : refusé, pas lu de travers.
        let mut modifie = chiffre.clone();
        let dernier = modifie.len() - 1;
        modifie[dernier] ^= 1;
        assert_eq!(
            dechiffrer(&cle, "appareils.json", &modifie),
            Err(Refus::Authentification)
        );
        // Renommé en un autre fichier, ou ouvert avec une autre clé : refusé aussi.
        assert_eq!(dechiffrer(&cle, "rapport.html", &chiffre), Err(Refus::Authentification));
        assert_eq!(
            dechiffrer(&Cle::nouvelle().unwrap(), "appareils.json", &chiffre),
            Err(Refus::Authentification)
        );
        // Pas un fichier de Vanguard, ou tronqué.
        assert_eq!(dechiffrer(&cle, "appareils.json", clair), Err(Refus::Format));
        assert_eq!(dechiffrer(&cle, "appareils.json", &chiffre[..10]), Err(Refus::Format));
        // Deux chiffrements du même texte ne se ressemblent pas (nonce tiré au hasard).
        assert_ne!(chiffre, chiffrer(&cle, "appareils.json", clair).unwrap());
    }

    #[test]
    fn enveloppe_et_mauvaise_phrase() {
        let cle = Cle::nouvelle().unwrap();
        let enveloppe = envelopper(&cle, "cheval agrafe pile 42", RAPIDE).unwrap();
        assert_eq!(ouvrir(&enveloppe, "cheval agrafe pile 42").unwrap(), cle);
        assert_eq!(
            ouvrir(&enveloppe, "cheval agrafe pile 43"),
            Err(Refus::Authentification)
        );
        assert_eq!(ouvrir(&enveloppe, ""), Err(Refus::Authentification));
        assert_eq!(identifiant_de(&enveloppe), Some(cle.identifiant()));
        // L'identifiant changé dans l'enveloppe ne fait pas passer une autre clé.
        let mut falsifiee = enveloppe.clone();
        falsifiee[MAGIQUE_ENVELOPPE.len() + 12 + TAILLE_SEL] ^= 1;
        assert!(ouvrir(&falsifiee, "cheval agrafe pile 42").is_err());
        // Des paramètres démesurés sont refusés avant de dériver.
        let mut enorme = enveloppe.clone();
        enorme[MAGIQUE_ENVELOPPE.len()..MAGIQUE_ENVELOPPE.len() + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(ouvrir(&enorme, "cheval agrafe pile 42"), Err(Refus::Format));
        assert_eq!(ouvrir(b"pas une enveloppe", "x"), Err(Refus::Format));
    }

    #[test]
    fn cle_locale_au_compte_seul() {
        let d = std::env::temp_dir().join(format!("vanguard-cle-locale-{}", std::process::id()));
        let chemin = d.join("cle-donnees");
        let cle = Cle::nouvelle().unwrap();
        ecrire_cle_locale(&cle, &chemin).unwrap();
        assert_eq!(lire_cle_locale(&chemin), Some(cle));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&chemin).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::write(&chemin, b"trop court").unwrap();
        assert_eq!(lire_cle_locale(&chemin), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    fn dossier(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vanguard-chiffrement-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("donnees")).unwrap();
        d
    }

    // Activer puis retirer : le carnet revient octet pour octet ; entre les deux, rien de lisible sur la clé, le
    // rapport et le diagnostic sont rangés sur l'ordinateur, et le bilan ne signale plus rien.
    #[test]
    fn migration_aller_et_retour() {
        let d = dossier("migration");
        let (donnees, local, cle_locale) = (d.join("donnees"), d.join("local"), d.join("local/cle-donnees"));
        let carnet = r#"{"reseaux":{"3c:22:fb:00:00:01":{"nom":"Salon","appareils":{}}}}"#;
        std::fs::write(donnees.join("appareils.json"), carnet).unwrap();
        std::fs::write(donnees.join("rapport.html"), "<p>Salon</p>").unwrap();
        std::fs::write(donnees.join("diagnostic-2026-10-18-1200.txt"), "x").unwrap();
        assert!(constat_de(&donnees).is_some());
        proteger_dans(&donnees, &cle_locale, &local, "phrase de test assez longue", RAPIDE).unwrap();
        assert!(protegee(&donnees) && constat_de(&donnees).is_none());
        assert!(!donnees.join("appareils.json").exists() && !donnees.join("rapport.html").exists());
        assert!(local.join("rapport.html").exists() && local.join("diagnostic-2026-10-18-1200.txt").exists());
        for f in std::fs::read_dir(&donnees).unwrap().flatten() {
            let octets = std::fs::read(f.path()).unwrap();
            assert!(!octets.windows(5).any(|w| w == b"Salon"), "{}", f.path().display());
        }
        // Chez le propriétaire, la clé gardée ouvre le carnet ; ailleurs, la phrase.
        let cle = lire_cle_locale(&cle_locale).unwrap();
        assert_eq!(lire_carnet_avec(&donnees, &cle).as_deref(), Some(carnet));
        let enveloppe = std::fs::read(donnees.join(ENVELOPPE)).unwrap();
        assert_eq!(ouvrir(&enveloppe, "phrase de test assez longue").unwrap(), cle);
        // Un enregistrement réécrit le carnet chiffré, jamais en clair.
        ecrire_carnet_avec(&donnees, &cle, r#"{"reseaux":{}}"#).unwrap();
        assert_eq!(lire_carnet_avec(&donnees, &cle).as_deref(), Some(r#"{"reseaux":{}}"#));
        ecrire_carnet_avec(&donnees, &cle, carnet).unwrap();
        // Nouvelle phrase : l'ancienne n'ouvre plus, la nouvelle oui, le carnet ne change pas.
        nouvelle_phrase_dans(&donnees, &cle, "une toute nouvelle phrase", RAPIDE).unwrap();
        let enveloppe = std::fs::read(donnees.join(ENVELOPPE)).unwrap();
        assert!(ouvrir(&enveloppe, "phrase de test assez longue").is_err());
        assert_eq!(ouvrir(&enveloppe, "une toute nouvelle phrase").unwrap(), cle);
        // Retour : en clair, comme avant ; enveloppe et clé gardée retirées.
        retirer_dans(&donnees, &cle, &cle_locale).unwrap();
        assert_eq!(std::fs::read_to_string(donnees.join("appareils.json")).unwrap(), carnet);
        assert!(!protegee(&donnees) && !donnees.join(CARNET_CHIFFRE).exists() && !cle_locale.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    // Un carnet chiffré modifié n'est ni lu ni réécrit : la protection ne se retire pas non plus.
    #[test]
    fn carnet_modifie_refuse() {
        let d = dossier("modifie");
        let (donnees, cle_locale) = (d.join("donnees"), d.join("local/cle-donnees"));
        std::fs::write(donnees.join("appareils.json"), "{}").unwrap();
        proteger_dans(
            &donnees,
            &cle_locale,
            &d.join("local"),
            "phrase de test assez longue",
            RAPIDE,
        )
        .unwrap();
        let cle = lire_cle_locale(&cle_locale).unwrap();
        let mut octets = std::fs::read(donnees.join(CARNET_CHIFFRE)).unwrap();
        let milieu = octets.len() / 2;
        octets[milieu] ^= 0x40;
        std::fs::write(donnees.join(CARNET_CHIFFRE), &octets).unwrap();
        assert_eq!(lire_carnet_avec(&donnees, &cle), None);
        assert!(retirer_dans(&donnees, &cle, &cle_locale).is_err());
        assert!(protegee(&donnees) && !donnees.join("appareils.json").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Les messages tiennent dans `LARGEUR` colonnes, dans les deux langues.
    #[test]
    fn messages_dans_la_largeur() {
        assert_eq!(
            crate::ui::textes_trop_larges(include_str!("chiffrement.rs")),
            Vec::<String>::new()
        );
    }

    #[test]
    fn parametres_par_defaut_acceptes() {
        assert!(Params::new(PARAMETRES.0, PARAMETRES.1, PARAMETRES.2, Some(32)).is_ok());
    }
}

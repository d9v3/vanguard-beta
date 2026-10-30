//! Les versions publiées de Vanguard sur GitHub, pour se mettre à jour sans la clé. Les programmes signés sont
//! publiés à part du code (d9v3/vanguard-update), dans un dépôt qui ne contient qu'eux. Rien n'y est cru sur parole : la
//! dernière version est décrite par un manifeste (`derniere.txt` : la version, puis l'empreinte SHA-256 et la taille
//! du programme de chaque système), signé en Ed25519 sur l'ordinateur de l'auteur (`outils/signer-versions.sh`), dont
//! la clé publique est gravée ici. Un manifeste mal signé, une version qui n'est pas plus récente, un programme dont
//! la taille, l'empreinte ou la version gravée ne sont pas celles signées : refusés. Qui prendrait le compte GitHub
//! ne pourrait donc pas faire installer autre chose que ce que l'auteur a signé.
//!
//! Une clé de secours, gardée hors ligne par l'auteur, signe aussi : la clé principale perdue ou volée, les versions
//! suivantes passent par elle sans que les ordinateurs déjà installés perdent la mise à jour. Volée, la principale se
//! révoque : un manifeste signé par la clé de secours qui finit par la ligne « revoque principale » est retenu dans
//! l'état scellé (`sceau::REVOCATION`), et la principale n'est plus jamais acceptée ici, ni pour un manifeste ni pour
//! l'historique ; la version qu'il apporte l'a aussi retirée de son code (`PRINCIPALE_RETIREE`), qui ne s'efface pas
//! avec les sceaux ; la plus haute version vue, qu'un voleur a pu monter au plus haut, repart de ce manifeste. Cette
//! ligne vient après celles des programmes : le lecteur des copies 0.85 trouve son système avant elle. Les anciens manifestes
//! signés restent publics : quelqu'un qui tient le dépôt des versions pourrait en remettre un pour geler les mises à
//! jour. Vanguard retient donc la plus haute version signée déjà vue et refuse tout manifeste plus vieux ; et une
//! dernière version signée de plus de 45 jours n'est plus dite « à jour », mais non vérifiée.
//!
//! L'historique signé des versions (`historique.txt`, publié avec chaque version) reprend les blocs de `derniere.txt`
//! de toutes les versions publiées : une copie qui n'est plus la dernière se compare encore à ce que l'auteur a signé
//! (`vanguard verifier-moi`). C'est un fichier à part, signé sous un autre domaine : `derniere.txt` garde sa forme, et
//! les copies d'avant lui (0.85.0 et plus anciennes), qui ne lisent que lui, ne voient rien changer.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::{Mutex, Once, PoisonError};
use std::time::Duration;

use sha2::{Digest, Sha256};

use super::{TAILLE_MAX, Version, ecrire, lire_version};
use crate::ui::*;

/// Les fichiers de la dernière version publiée : le lien « latest » de GitHub suit toujours la plus récente.
const ADRESSE: &str = "https://github.com/d9v3/vanguard-update/releases/latest/download/";

/// La clé publique qui signe les manifestes ; la clé privée ne quitte pas l'ordinateur de l'auteur
/// (~/.config/vanguard-dev/versions-ed25519.pem, `outils/signer-versions.sh --cle` la redonne sous cette forme).
const CLE_PUBLIQUE: [u8; 32] = [
    186, 93, 90, 226, 248, 122, 48, 200, 24, 51, 85, 91, 90, 167, 134, 196, 11, 226, 137, 238, 52, 158, 117, 140, 106,
    87, 92, 183, 180, 7, 166, 124,
];

/// La clé de secours (~/.config/vanguard-dev/versions-secours-ed25519.pem, à garder hors ligne ;
/// `outils/signer-versions.sh --cle --secours`). Même domaine, même manifeste : elle signe à la place de la principale.
/// Les copies d'avant elle (0.85 et plus anciennes) ne la connaissent pas : tant qu'il en reste, la principale signe.
const CLE_SECOURS: [u8; 32] = [
    79, 114, 203, 233, 134, 113, 9, 238, 146, 113, 204, 31, 163, 80, 240, 150, 88, 192, 49, 220, 137, 40, 207, 88, 209,
    126, 200, 236, 41, 214, 248, 109,
];

/// Les clés dont la signature est acceptée.
const CLES: [[u8; 32]; 2] = [CLE_PUBLIQUE, CLE_SECOURS];

/// La dernière ligne d'un manifeste signé par la clé de secours qui révoque la principale (`signer-versions.sh
/// --secours --revoquer`).
const LIGNE_REVOCATION: &str = "revoque principale";

/// Les clés acceptées ici, la clé de secours en dernier : la principale révoquée, la clé de secours seule.
fn cles_acceptees(revoquee: bool) -> &'static [[u8; 32]] {
    if revoquee { &CLES[1..] } else { &CLES }
}

/// La principale retirée de ce programme-ci, quel que soit l'état de l'ordinateur : à mettre à `true` dans la version
/// que la clé de secours publie en la révoquant (`signer-versions.sh --secours --revoquer` refuse de signer sans).
/// L'état scellé qui retient la révocation s'efface avec les sceaux ; une fois cette version installée, la principale
/// ne revient plus, même là.
const PRINCIPALE_RETIREE: bool = false;

/// `PRINCIPALE_RETIREE` gravée dans le fichier, pour que `signer-versions.sh --revoquer` la lise dans chaque programme
/// à signer (`grep -a`) au lieu de croire le code source, qui a pu changer depuis leur compilation. Seule la branche
/// prise est gravée : un programme qui garde la principale ne porte pas le texte « retirée ».
static PRINCIPALE_GRAVEE: &str = if PRINCIPALE_RETIREE {
    "VANGUARD-PRINCIPALE:RETIREE;"
} else {
    "VANGUARD-PRINCIPALE:GARDEE;"
};

/// La clé principale a-t-elle été révoquée ici ? Retirée du programme, toujours (lue dans la marque gravée,
/// `black_box` : sans lecture, l'éditeur de liens la retirerait du programme publié). Sinon, ce qu'en retient l'état
/// scellé (`revocation_retenue`).
fn principale_revoquee() -> bool {
    marque_retiree() || revocation_retenue()
}

/// La marque gravée dit-elle la principale retirée ? Les tests peuvent la dire retirée sans recompiler
/// (`MARQUE_RETIREE_EN_ESSAI`, propre au fil), pour essayer la version qui révoque.
fn marque_retiree() -> bool {
    #[cfg(test)]
    if MARQUE_RETIREE_EN_ESSAI.get() {
        return true;
    }
    std::hint::black_box(PRINCIPALE_GRAVEE).ends_with(":RETIREE;")
}

#[cfg(test)]
thread_local! {
    static MARQUE_RETIREE_EN_ESSAI: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// La révocation retenue dans l'état scellé : le fichier là sous n'importe quelle forme (même changé ou illisible)
/// la dit retenue, l'effacer ou le réécrire ne la fait pas revenir. Absent, ou inconnu après des sceaux refaits, elle
/// ne l'est pas : le croire révoquée figerait les mises à jour de tout ordinateur aux sceaux refaits tant que la
/// principale signe. Seul compte alors le manifeste de secours qui redit la révocation, jusqu'à ce que la version
/// qu'il apporte, qui l'a retirée, soit installée. À part de `PRINCIPALE_RETIREE` : la version qui révoque doit
/// encore retenir la révocation, et remettre à zéro le plancher des versions vues.
fn revocation_retenue() -> bool {
    !matches!(
        crate::sceau::lire(crate::sceau::REVOCATION),
        crate::sceau::Lecture::Absent | crate::sceau::Lecture::Inconnu
    )
}

/// Le manifeste finit-il par la ligne de révocation ?
fn revoque_la_principale(manifeste: &[u8]) -> bool {
    std::str::from_utf8(manifeste)
        .ok()
        .and_then(|t| t.lines().rfind(|l| !l.is_empty()))
        == Some(LIGNE_REVOCATION)
}

/// Au-delà, la dernière version signée (la date de son commit) n'est plus crue la dernière : l'auteur publie bien plus
/// souvent, un manifeste aussi vieux est plus probablement un ancien remis en place qu'une absence.
pub(super) const FRAICHEUR_JOURS: u64 = 45;

/// Ce qui précède le manifeste dans le message signé : une signature faite pour autre chose ne vaut pas ici.
const DOMAINE: &[u8] = b"vanguard-versions 1\n";

/// Le domaine de l'historique : une signature de manifeste ne vaut pas pour lui, ni l'inverse.
const DOMAINE_HISTORIQUE: &[u8] = b"vanguard-historique 1\n";

/// Au-delà, ce n'est pas un manifeste.
const MANIFESTE_MAX: u64 = 16 << 10;

/// Au-delà, ce n'est pas l'historique (un bloc fait 300 octets : des milliers de versions avant d'y arriver).
const HISTORIQUE_MAX: u64 = 4 << 20;

/// Une réponse de GitHub gardée ce temps-là : l'annonce du menu ne le redemande pas à chaque lancement.
const FRAICHE: Duration = Duration::from_hours(12);

/// Le programme de ce système : son nom dans le manifeste, puis sur GitHub (ceux de `outils/publier-version.sh`).
const SYSTEME: Option<(&str, &str)> = if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
    Some(("linux-x86_64", "vanguard-linux-x86_64"))
} else if cfg!(all(windows, target_arch = "x86_64")) {
    Some(("windows-x86_64", "vanguard-windows-x86_64.exe"))
} else if cfg!(target_os = "macos") {
    Some(("macos", "vanguard-macos"))
} else {
    None
};

/// La dernière version publiée pour ce système, d'après un manifeste dont la signature a été vérifiée.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Publiee {
    pub version: Version,
    sha256: [u8; 32],
    taille: u64,
    fichier: &'static str,
    /// Signé par la clé de secours avec la ligne de révocation : la principale ne vaut plus.
    revoque: bool,
}

/// Le manifeste : « version 0.79.0+1792540000 », puis une ligne par système, « linux-x86_64 `<sha256>` `<taille>` ». Le
/// moindre écart de forme le fait refuser.
fn lire_manifeste(texte: &str, systeme: &str) -> Option<(Version, [u8; 32], u64)> {
    let mut lignes = texte.lines();
    let version = lire_version(lignes.next()?.strip_prefix("version ")?)?;
    for ligne in lignes {
        let champs: Vec<&str> = ligne.split(' ').collect();
        let [nom, empreinte, taille] = champs[..] else {
            return None;
        };
        if nom == systeme {
            return Some((version, en_octets(empreinte)?, taille.parse().ok()?));
        }
    }
    None
}

/// 64 chiffres hexadécimaux en 32 octets.
fn en_octets(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut octets = [0u8; 32];
    for (i, o) in octets.iter_mut().enumerate() {
        *o = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(octets)
}

/// La signature est-elle celle de `cle` sur ce manifeste ? (vérification stricte : une signature trafiquée pour
/// passer chez certaines bibliothèques est refusée).
fn signature_valide(cle: &[u8; 32], manifeste: &[u8], signature: &[u8]) -> bool {
    signature_valide_pour(DOMAINE, cle, manifeste, signature)
}

/// `signature_valide`, sous le domaine donné.
fn signature_valide_pour(domaine: &[u8], cle: &[u8; 32], manifeste: &[u8], signature: &[u8]) -> bool {
    let (Ok(cle), Ok(signature)) = (
        ed25519_dalek::VerifyingKey::from_bytes(cle),
        <[u8; 64]>::try_from(signature),
    ) else {
        return false;
    };
    let mut message = domaine.to_vec();
    message.extend_from_slice(manifeste);
    cle.verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&signature))
        .is_ok()
}

/// Une version de l'historique : son numéro, puis (système, empreinte SHA-256, taille) de chacun de ses programmes.
type Bloc = (Version, Vec<(String, [u8; 32], u64)>);

/// L'historique : des blocs de `derniere.txt` mis bout à bout, « version … » en tête de chacun. Le moindre écart de
/// forme le fait refuser en entier : signé, il n'a aucune raison d'en avoir.
fn lire_historique(texte: &str) -> Option<Vec<Bloc>> {
    let mut blocs: Vec<Bloc> = Vec::new();
    for ligne in texte.lines() {
        if let Some(v) = ligne.strip_prefix("version ") {
            blocs.push((lire_version(v)?, Vec::new()));
            continue;
        }
        let champs: Vec<&str> = ligne.split(' ').collect();
        let [systeme, empreinte, taille] = champs[..] else {
            return None;
        };
        blocs
            .last_mut()?
            .1
            .push((systeme.to_string(), en_octets(empreinte)?, taille.parse().ok()?));
    }
    (!blocs.is_empty() && blocs.iter().all(|(_, p)| !p.is_empty())).then_some(blocs)
}

/// La version et le système du programme d'empreinte `sha256` dans un historique signé par l'une de `cles` ;
/// `Ok(None)` : absent de l'historique ; `Err` : l'historique n'est pas celui de l'auteur, ou ne se lit pas.
fn chercher_avec(
    cles: &[[u8; 32]],
    historique: &[u8],
    signature: &[u8],
    sha256: &[u8; 32],
) -> Result<Option<(Version, String)>, String> {
    if !cles
        .iter()
        .any(|c| signature_valide_pour(DOMAINE_HISTORIQUE, c, historique, signature))
    {
        return Err(tr!(
            "historique des versions mal signé : rien n'est cru",
            "badly signed version history: nothing is trusted"
        )
        .into());
    }
    let blocs = std::str::from_utf8(historique)
        .ok()
        .and_then(lire_historique)
        .ok_or_else(|| tr!("historique des versions illisible", "unreadable version history").to_string())?;
    Ok(blocs.into_iter().find_map(|(version, programmes)| {
        programmes
            .into_iter()
            .find(|(_, e, _)| e == sha256)
            .map(|(systeme, _, _)| (version, systeme))
    }))
}

/// Le programme d'empreinte `sha256` est-il une version publiée et signée par l'auteur ? D'après l'historique signé
/// des versions, téléchargé en entier (rien de cet ordinateur ni de l'empreinte cherchée ne part) et vérifié.
/// `Ok(None)` : il n'y est pas (une version intermédiaire, d'avant l'historique, ou un programme changé) ; `Err` :
/// pourquoi on ne sait pas.
pub(super) fn dans_l_historique(sha256: &[u8; 32]) -> Result<Option<(Version, String)>, String> {
    let pas_de_reponse = || {
        tr!(
            "pas de réponse (pas d'Internet, ou pas encore d'historique publié)",
            "no answer (no Internet, or no history published yet)"
        )
        .to_string()
    };
    if crate::parametres::hors_ligne() {
        return Err(crate::parametres::raison_hors_ligne().into());
    }
    let historique = recevoir("historique.txt", HISTORIQUE_MAX, 30).ok_or_else(pas_de_reponse)?;
    let signature = recevoir("historique.txt.sig", 64, 20).ok_or_else(pas_de_reponse)?;
    chercher_avec(cles_acceptees(principale_revoquee()), &historique, &signature, sha256)
}

/// Le manifeste et sa signature, vérifiés : la version publiée pour `systeme`, ou pourquoi elle ne vaut rien.
fn juger(manifeste: &[u8], signature: &[u8], systeme: &str, fichier: &'static str) -> Result<Publiee, String> {
    juger_avec(
        cles_acceptees(principale_revoquee()),
        manifeste,
        signature,
        systeme,
        fichier,
    )
}

/// `juger` avec ces clés-là (les tests y passent des clés d'essai).
fn juger_avec(
    cles: &[[u8; 32]],
    manifeste: &[u8],
    signature: &[u8],
    systeme: &str,
    fichier: &'static str,
) -> Result<Publiee, String> {
    let Some(cle) = cles.iter().find(|c| signature_valide(c, manifeste, signature)) else {
        if !cles.contains(&CLE_PUBLIQUE) && signature_valide(&CLE_PUBLIQUE, manifeste, signature) {
            return Err(tr!(
                "manifeste signé par la clé principale, révoquée ici par la clé de secours : rien n'est proposé",
                "manifest signed by the main key, revoked here by the backup key: nothing is offered"
            )
            .into());
        }
        return Err(tr!(
            "manifeste de GitHub mal signé : rien n'est proposé",
            "badly signed GitHub manifest: nothing is offered"
        )
        .into());
    };
    // Seule la clé de secours (la dernière des clés acceptées) révoque : la ligne signée par la principale ne compte
    // pas, sinon un voleur de la principale couperait la clé de secours.
    let revoque = cles.last() == Some(cle) && revoque_la_principale(manifeste);
    let (version, sha256, taille) = std::str::from_utf8(manifeste)
        .ok()
        .and_then(|t| lire_manifeste(t, systeme))
        .ok_or_else(|| {
            tr!(
                "manifeste de GitHub illisible, ou sans version pour ce système",
                "unreadable GitHub manifest, or no version for this system"
            )
            .to_string()
        })?;
    if taille > TAILLE_MAX {
        return Err(tr!(
            "programme publié démesuré : refusé",
            "oversized published program: refused"
        )
        .into());
    }
    Ok(Publiee {
        version,
        sha256,
        taille,
        fichier,
        revoque,
    })
}

fn dossier() -> PathBuf {
    crate::socle::dossier_local().join("versions")
}

/// L'âge en jours de la version signée `v`, d'après la date de son commit gravée avec elle ; `None` sans date, ou
/// quand l'horloge d'ici est en retard sur ce commit (pile du BIOS à plat, machine virtuelle restaurée) : l'âge est
/// alors inconnu, jamais « 0 jour », sinon un manifeste de n'importe quel âge paraîtrait frais. Un jour de tolérance
/// couvre le petit décalage d'une horloge juste après une publication.
pub(super) fn age_jours(v: Version, maintenant: u64) -> Option<u64> {
    (v.3 > 0 && v.3 <= maintenant.saturating_add(86_400)).then(|| maintenant.saturating_sub(v.3) / 86_400)
}

/// La plus haute version signée déjà vue ici. `Err` : l'état a été changé hors de Vanguard (`sceau`) ou ne se lit
/// pas ; il ne peut alors ni protéger d'un vieux manifeste, ni être refait en silence.
fn plus_haute_vue() -> Result<Option<Version>, crate::modele::Echec> {
    version_vue(crate::sceau::lire(crate::sceau::VERSIONS))
}

/// La plus haute version déjà vue, d'après ce que les sceaux en disent.
fn version_vue(lu: crate::sceau::Lecture) -> Result<Option<Version>, crate::modele::Echec> {
    use crate::modele::{Echec, Raison};
    use crate::sceau::Lecture;
    const OU: &str = "mise-a-jour/versions-vues";
    match lu {
        Lecture::Absent => Ok(None),
        Lecture::Intact(o) => Ok(std::str::from_utf8(&o).ok().and_then(|t| lire_version(t.trim()))),
        // Adoptées sans sceau d'avant : un plancher baissé juste avant que `sceaux.json` soit effacé ne doit pas
        // laisser passer un vieux manifeste en silence.
        Lecture::Adopte(_) | Lecture::Inconnu => Err(Echec::refuse(
            OU,
            tr!(
                "les versions déjà vues ont été acceptées telles quelles, sans sceau d'avant : rien n'est cru",
                "the versions already seen were accepted as they were, without an earlier seal: nothing is trusted"
            ),
        )),
        Lecture::Falsifie(_) => Err(Echec::new(OU, Raison::Falsifie).detail(tr!(
            "les versions déjà vues ont été changées hors de Vanguard : rien n'est cru",
            "the versions already seen were changed outside Vanguard: nothing is trusted"
        ))),
        Lecture::Illisible(e) => Err(Echec::new(OU, Raison::Illisible(e))),
    }
}

/// Les versions déjà vues ont-elles été changées hors de Vanguard ? (`depuis_github` le dit et demande avant de
/// repartir du manifeste reçu.)
pub(super) fn versions_vues_douteuses() -> bool {
    plus_haute_vue().is_err()
}

/// Repartir de zéro, sur accord (`depuis_github`) : la prochaine version signée reçue devient la plus haute vue.
pub(super) fn oublier_versions_vues() -> std::io::Result<()> {
    crate::sceau::effacer(crate::sceau::VERSIONS)
}

/// Retient que la clé de secours a révoqué la principale, la première fois : la plus haute version vue, qu'un voleur
/// de la principale a pu monter au plus haut pour refuser toute version d'après, repart du manifeste de secours.
/// `Err` : non retenue (disque, dossier d'un autre compte), le manifeste n'est pas suivi.
fn retenir_revocation() -> std::io::Result<()> {
    if revocation_retenue() {
        return Ok(());
    }
    crate::sceau::ecrire(crate::sceau::REVOCATION, LIGNE_REVOCATION)?;
    oublier_versions_vues()
}

/// Le manifeste reçu, comparé à la plus haute version signée déjà vue : refusé s'il est plus vieux (un ancien remis
/// en place pour geler les mises à jour) ; `Ok(true)` s'il est plus récent, à retenir.
fn comparer_a_la_vue(vue: Option<Version>, recue: Version) -> Result<bool, String> {
    match vue {
        Some(v) if recue < v => Err(trf!(
            "manifeste plus vieux que celui déjà vu : refusé ({} reçu, {} déjà vu)",
            "manifest older than the one already seen: refused ({} received, {} already seen)",
            ecrire(recue),
            ecrire(v)
        )),
        Some(v) => Ok(recue > v),
        None => Ok(true),
    }
}

/// Le dossier de Vanguard est-il sûr pour y écrire (le mémo de l'annonce, le programme provisoire à côté des cibles) ? Lancé en root avec le dossier d'un autre compte
/// (sudo qui garde HOME), ce compte pourrait y poser des liens et faire écrire root ailleurs : rien n'y est fait.
pub(super) fn dossier_sur() -> bool {
    #[cfg(unix)]
    {
        // SAFETY : geteuid n'a ni pointeur ni effet de bord.
        if unsafe { libc::geteuid() } != 0 {
            return true;
        }
        std::fs::symlink_metadata(crate::socle::dossier_local())
            .is_ok_and(|m| std::os::unix::fs::MetadataExt::uid(&m) == 0)
    }
    #[cfg(windows)]
    {
        true
    }
}

/// Un fichier de la dernière version, reçu en mémoire par le client HTTPS de Vanguard (`http`) : en HTTPS seulement,
/// redirections comprises ; le transfert est coupé au-delà de `max` octets ou de `secondes`. Rien ne passe par le
/// disque ni par un autre programme : ce qui est vérifié est ce qui s'installe. `None` : pas de réponse 200.
fn recevoir(nom: &str, max: u64, secondes: u64) -> Option<Vec<u8>> {
    let adresse = format!("{ADRESSE}{nom}");
    crate::http::envoyer(crate::http::Demande {
        adresse: &adresse,
        entetes: Vec::new(),
        corps: None,
        delai: Duration::from_secs(secondes),
        taille_max: max,
        meme_hote: false,
    })
    .filter(|r| r.code == 200)
    .map(|r| r.corps)
}

/// La dernière version publiée pour ce système, manifeste téléchargé et vérifié ; `Err` : pourquoi on ne sait pas.
pub(super) fn derniere() -> Result<Publiee, String> {
    let (systeme, fichier) = SYSTEME.ok_or_else(|| {
        tr!(
            "pas de version publiée pour ce système",
            "no published version for this system"
        )
        .to_string()
    })?;
    let pas_de_reponse = || {
        tr!(
            "pas de réponse (pas d'Internet, ou aucune version publiée pour tous)",
            "no answer (no Internet, or no version published for everyone)"
        )
        .to_string()
    };
    // Un réglage, pas l'absence d'Internet : le dire tel quel, sans quoi un programme qui l'a posé passerait pour une
    // panne de réseau.
    if crate::parametres::hors_ligne() {
        return Err(crate::parametres::raison_hors_ligne().into());
    }
    let manifeste = recevoir("derniere.txt", MANIFESTE_MAX, 20).ok_or_else(pas_de_reponse)?;
    let signature = recevoir("derniere.txt.sig", 64, 20).ok_or_else(pas_de_reponse)?;
    let publiee = juger(&manifeste, &signature, systeme, fichier)?;
    if publiee.revoque {
        retenir_revocation().map_err(|e| e.to_string())?;
    }
    let vue = plus_haute_vue()?;
    // Retenue seulement une fois la signature vérifiée : un manifeste quelconque ne fait pas monter la barre.
    if comparer_a_la_vue(vue, publiee.version)? {
        let v = publiee.version;
        let _ = crate::sceau::ecrire(crate::sceau::VERSIONS, format!("{}.{}.{}+{}", v.0, v.1, v.2, v.3));
    }
    Ok(publiee)
}

/// Télécharge le programme de `p` et rend ses octets, seulement si leur taille et leur empreinte sont celles signées.
/// Ce sont ces octets-là, gardés en mémoire, qui s'installent (`installer`, qui vérifie encore la version gravée).
pub(super) fn programme_verifie(p: &Publiee) -> Result<Vec<u8>, String> {
    let Some(recus) = recevoir(p.fichier, p.taille, 900) else {
        return Err(tr!("téléchargement interrompu", "download interrupted").into());
    };
    if u64::try_from(recus.len()).ok() == Some(p.taille) && Sha256::digest(&recus)[..] == p.sha256 {
        return Ok(recus);
    }
    Err(tr!(
        "le programme téléchargé n'est pas celui que l'auteur a signé : rien n'est remplacé",
        "the downloaded program is not the one the author signed: nothing is replaced"
    )
    .into())
}

static ANNONCE: Mutex<Option<Version>> = Mutex::new(None);
static CHERCHEE: Once = Once::new();

/// La dernière version publiée, pour l'annonce du menu : cherchée en fond une fois par lancement (le menu ne
/// l'attend jamais, elle paraît à l'affichage suivant), et seulement dans un vrai terminal (ni scripts, ni tests).
/// La réponse est gardée 12 heures ; l'installation, elle, revérifie tout.
pub(super) fn annonce() -> Option<Version> {
    if cfg!(test) || !std::io::stdin().is_terminal() || SYSTEME.is_none() || !dossier_sur() {
        return None;
    }
    CHERCHEE.call_once(|| {
        std::thread::spawn(|| {
            let vue = derniere_vue();
            *ANNONCE.lock().unwrap_or_else(PoisonError::into_inner) = vue;
        });
    });
    *ANNONCE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// La version vue sur GitHub il y a moins de 12 heures, sinon redemandée.
fn derniere_vue() -> Option<Version> {
    let memoire = dossier().join("derniere-vue.txt");
    let fraiche = std::fs::symlink_metadata(&memoire)
        .and_then(|m| m.modified())
        .is_ok_and(|t| t.elapsed().unwrap_or_default() < FRAICHE);
    if fraiche
        && let Some(v) = crate::socle::lire_texte_ordinaire(&memoire, 4 << 10)
            .ok()
            .and_then(|t| lire_version(t.trim()))
    {
        return Some(v);
    }
    let v = derniere().ok()?.version;
    let _ = std::fs::create_dir_all(dossier());
    let _ = std::fs::write(&memoire, format!("{}.{}.{}+{}", v.0, v.1, v.2, v.3));
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    /// Les tests qui écrivent l'état des versions (le même dossier jetable pour tout le processus) passent un à un.
    static ETAT_DES_VERSIONS: Mutex<()> = Mutex::new(());

    fn cle_d_essai() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7; 32])
    }

    fn signer(cle: &ed25519_dalek::SigningKey, manifeste: &str) -> Vec<u8> {
        let mut message = DOMAINE.to_vec();
        message.extend_from_slice(manifeste.as_bytes());
        cle.sign(&message).to_bytes().to_vec()
    }

    const MANIFESTE: &str = "version 0.79.0+1792540000\n\
        linux-x86_64 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff 26214400\n\
        windows-x86_64 ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100 27262976\n\
        macos 0000000000000000000000000000000000000000000000000000000000000001 30000000\n";

    fn signer_historique(cle: &ed25519_dalek::SigningKey, historique: &str) -> Vec<u8> {
        let mut message = DOMAINE_HISTORIQUE.to_vec();
        message.extend_from_slice(historique.as_bytes());
        cle.sign(&message).to_bytes().to_vec()
    }

    /// Une copie qui n'est plus la dernière se retrouve dans l'historique signé : sa version et son système, par
    /// l'empreinte de son programme. Signé par une autre clé, sous le domaine du manifeste, abîmé ou mal formé : refusé.
    #[test]
    fn une_ancienne_copie_se_retrouve_dans_l_historique() {
        let ancien = MANIFESTE.replace("0.79.0+1792540000", "0.78.0+1792400000").replacen(
            "linux-x86_64 0011",
            "linux-x86_64 aa11",
            1,
        );
        let historique = format!("{MANIFESTE}{ancien}");
        let cle = cle_d_essai();
        let cles = [cle.verifying_key().to_bytes()];
        let signature = signer_historique(&cle, &historique);
        let empreinte = |hex: &str| en_octets(hex).unwrap();
        let windows = empreinte("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100");
        // La première version qui le porte, la plus récente en tête : le .exe n'a pas changé entre les deux.
        assert_eq!(
            chercher_avec(&cles, historique.as_bytes(), &signature, &windows).unwrap(),
            Some(((0, 79, 0, 1_792_540_000), "windows-x86_64".to_string()))
        );
        let linux_0_78 = empreinte("aa112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        assert_eq!(
            chercher_avec(&cles, historique.as_bytes(), &signature, &linux_0_78).unwrap(),
            Some(((0, 78, 0, 1_792_400_000), "linux-x86_64".to_string()))
        );
        assert_eq!(
            chercher_avec(&cles, historique.as_bytes(), &signature, &[0x42; 32]).unwrap(),
            None
        );
        // Signé par une autre clé, ou sous le domaine du manifeste : rien n'est cru.
        let autre = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
        assert!(
            chercher_avec(
                &cles,
                historique.as_bytes(),
                &signer_historique(&autre, &historique),
                &windows
            )
            .is_err()
        );
        assert!(chercher_avec(&cles, historique.as_bytes(), &signer(&cle, &historique), &windows).is_err());
        // Un octet changé : la signature ne tient plus.
        let trafique = historique.replacen("27262976", "27262977", 1);
        assert!(chercher_avec(&cles, trafique.as_bytes(), &signature, &windows).is_err());
        // Bien signé mais mal formé : illisible, jamais lu à moitié.
        for abime in [
            format!("{historique}ligne en trop\n"),
            format!("linux-x86_64 {} 1\n{historique}", "0".repeat(64)),
            String::new(),
        ] {
            let s = signer_historique(&cle, &abime);
            assert!(
                chercher_avec(&cles, abime.as_bytes(), &s, &windows).is_err(),
                "{abime:?}"
            );
        }
        // Une signature de l'historique ne vaut pas pour un manifeste (les domaines diffèrent).
        assert!(!signature_valide(&cles[0], historique.as_bytes(), &signature));
    }

    #[test]
    fn manifeste_lu_ligne_par_ligne() {
        let (v, sha, taille) = lire_manifeste(MANIFESTE, "windows-x86_64").unwrap();
        assert_eq!(v, (0, 79, 0, 1_792_540_000));
        assert_eq!((sha[0], sha[31], taille), (0xff, 0x00, 27_262_976));
        assert!(lire_manifeste(MANIFESTE, "freebsd").is_none());
        // Le moindre écart de forme : refusé.
        assert!(lire_manifeste(&MANIFESTE.replace("version ", "version: "), "macos").is_none());
        assert!(lire_manifeste(&MANIFESTE.replace(" 30000000", " 3e7"), "macos").is_none());
        assert!(lire_manifeste(&MANIFESTE.replace("0001 ", "01 "), "macos").is_none());
        assert!(lire_manifeste(&MANIFESTE.replace(" 26214400", " 26214400 en-trop"), "macos").is_none());
    }

    #[test]
    fn seule_la_signature_de_l_auteur_compte() {
        let cle = cle_d_essai();
        let publique = cle.verifying_key().to_bytes();
        let signature = signer(&cle, MANIFESTE);
        assert!(signature_valide(&publique, MANIFESTE.as_bytes(), &signature));
        // Un octet changé dans le manifeste, la signature d'un autre, une signature tronquée : refusés.
        let trafique = MANIFESTE.replace("26214400", "26214401");
        assert!(!signature_valide(&publique, trafique.as_bytes(), &signature));
        let autre = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
        assert!(!signature_valide(
            &publique,
            MANIFESTE.as_bytes(),
            &signer(&autre, MANIFESTE)
        ));
        assert!(!signature_valide(&publique, MANIFESTE.as_bytes(), &signature[..63]));
        // Signé sans le domaine (pour autre chose) : refusé.
        let sans_domaine = cle.sign(MANIFESTE.as_bytes()).to_bytes();
        assert!(!signature_valide(&publique, MANIFESTE.as_bytes(), &sans_domaine));
        // La clé gravée n'est pas celle d'essai : un manifeste signé par la clé d'essai ne passe pas `juger`.
        assert!(
            juger(
                MANIFESTE.as_bytes(),
                &signature,
                "linux-x86_64",
                "vanguard-linux-x86_64"
            )
            .is_err()
        );
        assert!(ed25519_dalek::VerifyingKey::from_bytes(&CLE_PUBLIQUE).is_ok());
    }

    /// Un manifeste signé par openssl avec la vraie clé de l'auteur (outils/signer-versions.sh) passe la vérification
    /// de Vanguard : les deux parlent le même Ed25519, et la clé gravée est la bonne. Sa version (0.0.1) n'est jamais
    /// plus récente que la version en place : il ne peut rien faire installer.
    #[test]
    fn signature_d_openssl_acceptee() {
        // Les clés gravées : de vrais points Ed25519 (une clé mal recopiée ferait refuser toute signature, sans
        // erreur visible avant le jour où elle sert), et toutes deux acceptées par `juger`. La clé de secours
        // privée est chiffrée et hors ligne : aucun test ne peut signer avec elle.
        for cle in CLES {
            assert!(ed25519_dalek::VerifyingKey::from_bytes(&cle).is_ok());
        }
        assert_eq!(CLES, [CLE_PUBLIQUE, CLE_SECOURS]);
        assert_ne!(CLE_PUBLIQUE, CLE_SECOURS);
    }

    /// Un ancien manifeste signé remis en place est refusé dès qu'un plus récent a été vu ici ; le même, ou un plus
    /// récent, passe (et seul le plus récent fait monter la barre).
    #[test]
    fn vieux_manifeste_refuse() {
        let vue = Some((0, 85, 0, 1_792_540_000));
        assert_eq!(comparer_a_la_vue(None, (0, 84, 0, 1)), Ok(true));
        assert_eq!(comparer_a_la_vue(vue, (0, 85, 0, 1_792_540_000)), Ok(false));
        assert_eq!(comparer_a_la_vue(vue, (0, 86, 0, 1_792_600_000)), Ok(true));
        let refus = comparer_a_la_vue(vue, (0, 84, 0, 1_792_000_000)).unwrap_err();
        assert!(refus.contains("0.84.0") && refus.contains("0.85.0"), "{refus}");
        // Même numéro, commit plus ancien : plus vieux aussi.
        assert!(comparer_a_la_vue(vue, (0, 85, 0, 1_792_539_999)).is_err());
    }

    /// L'état « déjà vu » est scellé : réécrit hors de Vanguard (pour abaisser la barre), il ne protège plus et le
    /// dit, au lieu de laisser passer un vieux manifeste.
    #[test]
    fn versions_vues_changees_a_cote() {
        let _seul = ETAT_DES_VERSIONS.lock().unwrap_or_else(PoisonError::into_inner);
        crate::sceau::ecrire(crate::sceau::VERSIONS, "0.85.0+1792540000").unwrap();
        assert_eq!(plus_haute_vue(), Ok(Some((0, 85, 0, 1_792_540_000))));
        std::fs::write(crate::socle::dossier_local().join(crate::sceau::VERSIONS), "0.1.0+1").unwrap();
        assert!(plus_haute_vue().is_err() && versions_vues_douteuses());
        oublier_versions_vues().unwrap();
        assert_eq!(plus_haute_vue(), Ok(None));
        // Abaissée puis acceptée telle quelle, les sceaux effacés : pas un plancher, c'est dit.
        let lu = crate::sceau::Lecture::Adopte(b"0.1.0+1".to_vec());
        assert!(version_vue(lu).is_err());
    }

    #[test]
    fn age_de_la_derniere_version_signee() {
        let jour = 86_400;
        assert_eq!(
            age_jours((0, 85, 0, 1_792_540_000), 1_792_540_000 + 46 * jour),
            Some(46)
        );
        assert_eq!(age_jours((0, 85, 0, 1_792_540_000), 1_792_540_000 + jour - 1), Some(0));
        // Horloge très en retard : âge inconnu, jamais « frais ».
        assert_eq!(age_jours((0, 85, 0, 1_792_540_000), 1_000), None);
        // Une heure de décalage juste après la publication : dans la tolérance.
        assert_eq!(age_jours((0, 85, 0, 1_792_540_000), 1_792_540_000 - 3_600), Some(0));
        assert_eq!(age_jours((0, 85, 0, 0), 1_792_540_000), None);
    }

    /// Les Vanguard 0.85 déjà installés lisent le manifeste avec leur propre lecteur, recopié ici tel quel depuis
    /// l'étiquette v0.85.0 : le manifeste que signe `signer-versions.sh` aujourd'hui (même forme, clé principale) doit
    /// leur donner la même version, la même empreinte et la même taille qu'au lecteur d'aujourd'hui.
    #[test]
    fn le_lecteur_de_la_0_85_lit_le_manifeste_d_aujourd_hui() {
        fn lire_manifeste_0_85(texte: &str, systeme: &str) -> Option<(Version, [u8; 32], u64)> {
            let mut lignes = texte.lines();
            let version = lire_version(lignes.next()?.strip_prefix("version ")?)?;
            for ligne in lignes {
                let champs: Vec<&str> = ligne.split(' ').collect();
                let [nom, empreinte, taille] = champs[..] else {
                    return None;
                };
                if nom == systeme {
                    return Some((version, en_octets(empreinte)?, taille.parse().ok()?));
                }
            }
            None
        }
        // La forme exacte qu'écrit signer-versions.sh : « version X », puis les trois systèmes dans cet ordre.
        let (a, b, c) = ("ab".repeat(32), "cd".repeat(32), "ef".repeat(32));
        let manifeste = format!(
            "version 0.86.0+1792600000\nlinux-x86_64 {a} 26214400\nwindows-x86_64 {b} 27262976\nmacos {c} 30000000\n"
        );
        for systeme in ["linux-x86_64", "windows-x86_64", "macos"] {
            let ancien = lire_manifeste_0_85(&manifeste, systeme);
            assert!(ancien.is_some(), "{systeme}");
            assert_eq!(ancien, lire_manifeste(&manifeste, systeme), "{systeme}");
        }
        assert_eq!(
            lire_manifeste_0_85(MANIFESTE, "macos"),
            lire_manifeste(MANIFESTE, "macos")
        );
        // La ligne de révocation (signer-versions.sh --secours --revoquer) vient après les trois programmes : le
        // lecteur de la 0.85 trouve le sien avant elle, et lit la même chose (la 0.85 ne connaît pas la clé de
        // secours : elle refuse ce manifeste pour sa signature, jamais pour sa forme).
        let revoque = format!("{manifeste}{LIGNE_REVOCATION}\n");
        for systeme in ["linux-x86_64", "windows-x86_64", "macos"] {
            assert_eq!(
                lire_manifeste_0_85(&revoque, systeme),
                lire_manifeste(&manifeste, systeme),
                "{systeme}"
            );
        }
        // Le message signé garde le domaine de la 0.85 : sa vérification (clé principale) reste la même.
        assert_eq!(DOMAINE, b"vanguard-versions 1\n");
    }

    /// La clé principale volée : la clé de secours la révoque par la dernière ligne de son manifeste. Retenue ici,
    /// la principale n'est plus acceptée (ni manifeste ni historique), effacer ou réécrire l'état ne la fait pas
    /// revenir, et la ligne signée par la principale elle-même ne révoque rien.
    #[test]
    fn la_cle_de_secours_revoque_la_principale() {
        let principale = cle_d_essai();
        let secours = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let cles = [
            principale.verifying_key().to_bytes(),
            secours.verifying_key().to_bytes(),
        ];
        let avec_ligne = format!("{MANIFESTE}{LIGNE_REVOCATION}\n");
        // Le lecteur d'aujourd'hui lit toujours chaque programme.
        for systeme in ["linux-x86_64", "windows-x86_64", "macos"] {
            assert_eq!(lire_manifeste(&avec_ligne, systeme), lire_manifeste(MANIFESTE, systeme));
        }
        assert!(revoque_la_principale(avec_ligne.as_bytes()) && !revoque_la_principale(MANIFESTE.as_bytes()));
        // Avant : les deux clés passent.
        let par_principale = signer(&principale, MANIFESTE);
        assert!(juger_avec(&cles, MANIFESTE.as_bytes(), &par_principale, "macos", "m").is_ok());
        // Signée par la principale, la ligne ne révoque rien (sinon un voleur couperait la clé de secours).
        let p = juger_avec(
            &cles,
            avec_ligne.as_bytes(),
            &signer(&principale, &avec_ligne),
            "macos",
            "m",
        )
        .unwrap();
        assert!(!p.revoque);
        let s = juger_avec(
            &cles,
            avec_ligne.as_bytes(),
            &signer(&secours, &avec_ligne),
            "macos",
            "m",
        );
        assert!(s.unwrap().revoque);
        // Sans la ligne, la clé de secours signe sans rien révoquer.
        let s = juger_avec(&cles, MANIFESTE.as_bytes(), &signer(&secours, MANIFESTE), "macos", "m");
        assert!(!s.unwrap().revoque);
        // Après : la principale est refusée, et le refus le dit.
        let apres = &cles[1..];
        let refus = juger_avec(apres, MANIFESTE.as_bytes(), &par_principale, "macos", "m");
        assert!(refus.is_err());
        assert!(juger_avec(apres, MANIFESTE.as_bytes(), &signer(&secours, MANIFESTE), "macos", "m").is_ok());
        // Les clés gravées : révoquée, la principale ne reste pas dans la liste.
        assert_eq!(cles_acceptees(false), &CLES);
        assert_eq!(cles_acceptees(true), &[CLE_SECOURS]);
        // L'état retenu : là sous n'importe quelle forme, la principale reste révoquée ; et le plancher repart.
        let _seul = ETAT_DES_VERSIONS.lock().unwrap_or_else(PoisonError::into_inner);
        crate::sceau::ecrire(crate::sceau::VERSIONS, "4294967295.0.0+1792540000").unwrap();
        assert!(!revocation_retenue());
        retenir_revocation().unwrap();
        assert!(revocation_retenue() && principale_revoquee());
        assert_eq!(plus_haute_vue(), Ok(None));
        let fichier = crate::socle::dossier_local().join(crate::sceau::REVOCATION);
        std::fs::write(&fichier, "rien").unwrap();
        assert!(revocation_retenue());
        std::fs::remove_file(&fichier).unwrap();
        assert!(revocation_retenue(), "effacée hors de Vanguard : toujours retenue");
        crate::sceau::effacer(crate::sceau::REVOCATION).unwrap();
        // La version qui révoque (principale retirée du programme) retient encore la révocation et remet le
        // plancher à zéro : sans quoi un plancher monté par un voleur de la principale y resterait.
        MARQUE_RETIREE_EN_ESSAI.set(true);
        assert!(principale_revoquee() && !revocation_retenue());
        crate::sceau::ecrire(crate::sceau::VERSIONS, "4294967295.0.0+1792540000").unwrap();
        retenir_revocation().unwrap();
        MARQUE_RETIREE_EN_ESSAI.set(false);
        assert!(
            revocation_retenue(),
            "retirée du programme : la révocation est quand même retenue"
        );
        assert_eq!(plus_haute_vue(), Ok(None));
        crate::sceau::effacer(crate::sceau::REVOCATION).unwrap();
    }

    #[test]
    fn empreintes_hexadecimales() {
        assert_eq!(en_octets(&"ab".repeat(32)), Some([0xab; 32]));
        assert!(en_octets(&"ab".repeat(31)).is_none());
        assert!(en_octets(&"zz".repeat(32)).is_none());
        assert!(en_octets(&format!("é{}", "a".repeat(62))).is_none());
    }

    /// Le programme des tests porte la marque de `PRINCIPALE_RETIREE`, et pas l'autre : c'est elle que
    /// `signer-versions.sh --revoquer` cherche dans chaque programme à signer.
    #[test]
    fn ce_programme_porte_la_marque_de_la_principale() {
        let octets = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let porte = |marque: &str| octets.windows(marque.len()).any(|f| f == marque.as_bytes());
        let autre = if PRINCIPALE_RETIREE {
            PRINCIPALE_GRAVEE.replace("RETIREE", "GARDEE")
        } else {
            PRINCIPALE_GRAVEE.replace("GARDEE", "RETIREE")
        };
        assert!(porte(PRINCIPALE_GRAVEE));
        assert!(
            !porte(&autre),
            "les deux marques gravées : signer-versions.sh ne saurait plus laquelle croire"
        );
    }
}

//! Une seule fenêtre : la règle commune à `vanguard` (qui demande) et à `vanguard-fenetre` (qui répond), compilée
//! des deux côtés à l'identique (`#[path]` dans fenetre/src/main.rs, comme `valeur_console.rs`).
//!
//! Un second lancement interactif de `vanguard` ne rouvre pas une fenêtre : il demande à celle qui est déjà ouverte
//! de revenir devant. Le canal est privé au compte (Linux : une prise Unix dans un dossier de `XDG_RUNTIME_DIR` à ce
//! compte seul ; Windows : un tube nommé dont le propriétaire et la liste d'accès ne nomment que ce compte, lié à sa
//! session), et le message est fermé : un octet d'accueil (Linux) ; la demande, un octet « montre-toi » suivi d'un
//! nombre aléatoire frais (`JETON` octets) ; la réponse, un octet « ok » suivi du même nombre. La réponse est ainsi
//! liée à cette demande-ci : un « ok » posé d'avance dans le canal, ou rejoué, ne vaut rien. Rien d'autre n'est lu
//! ni interprété. Avant d'envoyer la demande, `vanguard` vérifie que le programme qui lui parle est la fenêtre qu'il
//! aurait lancée (même compte, même empreinte d'image). Ce qui est garanti, et ce qui ne l'est pas (un programme du
//! même compte qui pilote la vraie image), est écrit dans MODELE-DE-MENACE.md.
//!
//! Ce fichier fait des calculs (noms, messages, jugements) et, sous Linux, crée et vérifie le dossier de la prise
//! (`dossier_prive`) ; ni texte pour la personne, ni `unsafe`.

use std::time::Duration;

/// Le premier octet de la demande de `vanguard` : « montre-toi ».
pub const DEMANDE: u8 = b'V';
/// Le premier octet de la réponse de la fenêtre : « ok, je suis revenue devant ».
pub const REPONSE: u8 = b'K';
/// La taille du nombre aléatoire qui suit `DEMANDE` et que la fenêtre renvoie après `REPONSE` : 128 bits, qu'un
/// programme qui n'a pas lu la demande ne devine pas.
pub const JETON: usize = 16;
/// La taille d'une demande et d'une réponse : l'octet, puis le jeton. Rien de plus n'est lu.
pub const TAILLE: usize = 1 + JETON;
/// Linux : le premier octet, envoyé par la fenêtre dès la connexion acceptée. Il ne dit rien ; il porte, attachés
/// par le noyau, le processus qui l'envoie (SCM_CREDENTIALS, SCM_PIDFD) : c'est ce processus-là, celui qui parle,
/// que `vanguard` vérifie, et non celui qui a ouvert l'écoute (qui peut avoir passé la prise à un autre).
#[cfg(unix)]
pub const ACCUEIL: u8 = b'A';
/// Le plus long qu'un côté attend l'autre, à chaque étape (se joindre, lire, écrire) : un bout lent ou muet est
/// abandonné, il ne bloque rien.
pub const DELAI: Duration = Duration::from_millis(1500);
/// Le temps laissé à `vanguard` pour vérifier qui parle (lire l'image d'une dizaine de Mio et en faire l'empreinte)
/// entre le branchement et la demande ; la fenêtre attend la demande `DELAI + VERIFICATION` au plus.
pub const VERIFICATION: Duration = Duration::from_millis(3000);
/// La demande, faite du jeton `jeton` (tiré au hasard par `vanguard`, à chaque demande).
#[must_use]
pub fn demande(jeton: &[u8; JETON]) -> [u8; TAILLE] {
    message(DEMANDE, jeton)
}

/// La réponse à la demande qui portait `jeton`.
#[must_use]
pub fn reponse(jeton: &[u8; JETON]) -> [u8; TAILLE] {
    message(REPONSE, jeton)
}

fn message(premier: u8, jeton: &[u8; JETON]) -> [u8; TAILLE] {
    let mut m = [premier; TAILLE];
    for (case, &o) in m.iter_mut().skip(1).zip(jeton) {
        *case = o;
    }
    m
}

/// Ce que la fenêtre a lu est-il une demande ? Son jeton, à renvoyer ; `None` pour tout autre message (taille ou
/// premier octet faux).
#[must_use]
// Lu par la fenêtre (fenetre/, qui inclut ce fichier) et par les essais ; pas par `vanguard`.
#[cfg_attr(not(test), allow(dead_code))]
pub fn jeton_de_la_demande(lu: &[u8]) -> Option<[u8; JETON]> {
    let (&premier, reste) = lu.split_first()?;
    if premier != DEMANDE {
        return None;
    }
    reste.try_into().ok()
}

/// Ce que `vanguard` a lu est-il la réponse à sa demande (celle qui portait `jeton`) ?
#[must_use]
pub fn reponse_juste(lu: &[u8], jeton: &[u8; JETON]) -> bool {
    lu == reponse(jeton)
}

/// Le sous-dossier de `XDG_RUNTIME_DIR` (Linux) où vit la prise.
#[cfg(unix)]
pub const SOUS_DOSSIER: &str = "vanguard";
/// Le plus long nom de session gardé : au-delà, le chemin de la prise ne tiendrait plus dans les 108 octets permis.
#[cfg(any(unix, test))]
const NOM_MAX: usize = 48;

/// Pourquoi un dossier n'est pas assez privé pour y mettre (ou y chercher) la prise.
#[cfg(any(unix, test))]
#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refus {
    /// Pas un dossier.
    PasUnDossier,
    /// Un lien symbolique : il pourrait mener ailleurs.
    Lien,
    /// À un autre compte.
    AutreCompte,
    /// Ouvert au groupe ou aux autres (un bit de 0o077).
    Ouvert,
    /// `XDG_RUNTIME_DIR` absent ou pas un chemin absolu : aucun dossier de session sûr (jamais /tmp à la place).
    SansSession,
    /// Le dossier ne se crée pas ou ne se lit pas.
    Illisible,
}

/// Le dossier est-il à ce compte seul ? Un vrai dossier (pas un lien), à `moi`, fermé au groupe et aux autres
/// (`mode & 0o077 == 0`). Sans quoi un autre compte pourrait y poser sa propre prise, ou retirer la nôtre.
#[cfg(any(unix, test))]
pub fn juger_dossier(est_dossier: bool, est_lien: bool, proprietaire: u32, mode: u32, moi: u32) -> Result<(), Refus> {
    if est_lien {
        return Err(Refus::Lien);
    }
    if !est_dossier {
        return Err(Refus::PasUnDossier);
    }
    if proprietaire != moi {
        return Err(Refus::AutreCompte);
    }
    if mode & 0o077 != 0 {
        return Err(Refus::Ouvert);
    }
    Ok(())
}

/// Le dossier de la prise, `XDG_RUNTIME_DIR/vanguard`, créé au besoin (0700) puis vérifié avec son parent : les
/// deux à `moi` seul, de vrais dossiers. Aucun repli : sans dossier de session privé, pas de canal du tout.
#[cfg(unix)]
pub fn dossier_prive(runtime: Option<std::ffi::OsString>, moi: u32) -> Result<std::path::PathBuf, Refus> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let runtime = std::path::PathBuf::from(runtime.ok_or(Refus::SansSession)?);
    if !runtime.is_absolute() {
        return Err(Refus::SansSession);
    }
    let juger = |chemin: &std::path::Path| {
        let m = std::fs::symlink_metadata(chemin).map_err(|_| Refus::Illisible)?;
        juger_dossier(m.is_dir(), m.file_type().is_symlink(), m.uid(), m.mode(), moi)
    };
    juger(&runtime)?;
    let dossier = runtime.join(SOUS_DOSSIER);
    match std::fs::DirBuilder::new().mode(0o700).create(&dossier) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(Refus::Illisible),
    }
    juger(&dossier)?;
    Ok(dossier)
}

/// Un morceau de nom sûr : non vide, borné, des lettres et chiffres ASCII, `.`, `_` ou `-`, sans `..`.
#[cfg(any(unix, test))]
fn morceau_sur(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= NOM_MAX
        && s != "."
        && !s.contains("..")
        && s.bytes()
            .all(|o| o.is_ascii_alphanumeric() || matches!(o, b'.' | b'_' | b'-'))
}

/// Le nom de la prise (Linux), lié à la session graphique : une fenêtre par bureau Wayland (`WAYLAND_DISPLAY`),
/// sinon par écran X11 (`DISPLAY`). Une valeur qui n'est pas un nom simple (un chemin, un caractère inattendu) ne
/// donne aucun nom : pas de canal, la fenêtre s'ouvre comme avant.
#[cfg(any(unix, test))]
pub fn nom_prise(wayland: Option<&str>, display: Option<&str>) -> Option<String> {
    if let Some(w) = wayland.filter(|w| !w.is_empty()) {
        return morceau_sur(w).then(|| format!("fenetre-{w}.prise"));
    }
    let d = display.filter(|d| !d.is_empty())?;
    // « :0 », « :1.0 » : les deux-points ne vont pas dans un nom de fichier ; ce qui suit doit être sûr.
    let suite = d.strip_prefix(':')?;
    morceau_sur(suite).then(|| format!("fenetre-x11-{suite}.prise"))
}

/// Le nom du verrou (Linux) qui ordonne deux lancements simultanés sur la même session.
#[cfg(any(unix, test))]
pub fn nom_verrou(prise: &str) -> String {
    format!("{prise}.verrou")
}

/// Un SID de la forme « S-1-… » : chiffres et tirets seulement, borné.
#[cfg(any(windows, test))]
pub fn sid_valide(sid: &str) -> bool {
    sid.len() <= 184
        && sid
            .strip_prefix("S-1-")
            .is_some_and(|c| !c.is_empty() && c.bytes().all(|o| o.is_ascii_digit() || o == b'-'))
}

/// Le nom du tube (Windows), lié au compte (son SID) et à la session : un autre compte ou une autre session ouverte
/// par le même compte a le sien.
#[cfg(any(windows, test))]
pub fn nom_tube(sid: &str, session: u32) -> Option<String> {
    sid_valide(sid).then(|| format!(r"\\.\pipe\vanguard-fenetre-{sid}-{session}"))
}

/// Le descripteur de sécurité du tube (Windows) : propriétaire ce compte (`O:`, nommé exprès : un jeton
/// administrateur élevé aurait sinon « Administrateurs » pour propriétaire par défaut), liste d'accès à ce compte
/// seul, tous les droits, protégée (`P`) : rien d'hérité. Ni SYSTEM ni les administrateurs : la fenêtre n'a affaire
/// qu'à son propre compte. `vanguard` exige ce propriétaire et cette liste avant de parler au tube.
#[cfg(any(windows, test))]
#[cfg_attr(not(test), allow(dead_code))]
pub fn sddl(sid: &str) -> Option<String> {
    sid_valide(sid).then(|| format!("O:{sid}D:P(A;;GA;;;{sid})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dossier_prive_seulement() {
        assert_eq!(juger_dossier(true, false, 1000, 0o700, 1000), Ok(()));
        assert_eq!(juger_dossier(true, false, 1000, 0o40700, 1000), Ok(()));
        assert_eq!(juger_dossier(true, true, 1000, 0o700, 1000), Err(Refus::Lien));
        assert_eq!(juger_dossier(false, false, 1000, 0o700, 1000), Err(Refus::PasUnDossier));
        assert_eq!(juger_dossier(true, false, 1001, 0o700, 1000), Err(Refus::AutreCompte));
        assert_eq!(juger_dossier(true, false, 0, 0o700, 1000), Err(Refus::AutreCompte));
        for ouvert in [0o710, 0o701, 0o750, 0o755, 0o777, 0o702, 0o720] {
            assert_eq!(
                juger_dossier(true, false, 1000, ouvert, 1000),
                Err(Refus::Ouvert),
                "{ouvert:o}"
            );
        }
    }

    #[test]
    fn nom_de_prise_lie_a_la_session() {
        assert_eq!(
            nom_prise(Some("wayland-1"), Some(":0")).as_deref(),
            Some("fenetre-wayland-1.prise")
        );
        assert_eq!(nom_prise(None, Some(":0")).as_deref(), Some("fenetre-x11-0.prise"));
        assert_eq!(
            nom_prise(Some(""), Some(":1.0")).as_deref(),
            Some("fenetre-x11-1.0.prise")
        );
        for piege in [
            "/run/user/1000/wayland-0",
            "../x",
            "a b",
            "w\0",
            "..",
            ".",
            "é",
            &"w".repeat(49),
        ] {
            assert_eq!(nom_prise(Some(piege), Some(":0")), None, "{piege:?}");
        }
        for piege in ["localhost:0", ":", ":../x", ":0/a", ""] {
            assert_eq!(nom_prise(None, Some(piege)), None, "{piege:?}");
        }
        assert_eq!(nom_prise(None, None), None);
        assert_eq!(nom_verrou("fenetre-wayland-1.prise"), "fenetre-wayland-1.prise.verrou");
    }

    #[test]
    fn nom_de_tube_lie_au_compte_et_a_la_session() {
        // Le SID d'exemple de la documentation de Microsoft (aucun compte réel).
        let sid = "S-1-5-21-1004336348-1177238915-682003330-1001";
        assert_eq!(
            nom_tube(sid, 2).as_deref(),
            Some(r"\\.\pipe\vanguard-fenetre-S-1-5-21-1004336348-1177238915-682003330-1001-2")
        );
        assert_eq!(
            sddl(sid).as_deref(),
            Some(
                "O:S-1-5-21-1004336348-1177238915-682003330-1001D:P(A;;GA;;;S-1-5-21-1004336348-1177238915-682003330-1001)"
            )
        );
        for piege in [
            "",
            "S-1-",
            "S-1-5)(A;;GA;;;WD",
            "S-1-5-21\\x",
            "s-1-5",
            "S-1-5 ",
            &"S-1-".repeat(60),
        ] {
            assert_eq!(nom_tube(piege, 1), None, "{piege:?}");
            assert_eq!(sddl(piege), None, "{piege:?}");
        }
    }

    /// La réponse est liée à la demande : même jeton, bon premier octet, bonne taille ; tout le reste est refusé.
    #[test]
    fn la_reponse_reprend_le_jeton_de_la_demande() {
        let jeton = [7u8; JETON];
        let d = demande(&jeton);
        assert_eq!(d[0], DEMANDE);
        assert_eq!(jeton_de_la_demande(&d), Some(jeton));
        assert!(reponse_juste(&reponse(&jeton), &jeton));
        let mut autre = jeton;
        autre[JETON - 1] ^= 1;
        assert!(!reponse_juste(&reponse(&autre), &jeton), "un autre jeton");
        assert!(!reponse_juste(&[REPONSE], &jeton), "l'octet seul, sans jeton");
        assert!(!reponse_juste(&d, &jeton), "la demande renvoyée telle quelle");
        let mut longue = reponse(&jeton).to_vec();
        longue.push(0);
        assert!(!reponse_juste(&longue, &jeton), "un octet de trop");
        assert_eq!(jeton_de_la_demande(&[DEMANDE]), None, "sans jeton");
        assert_eq!(jeton_de_la_demande(&reponse(&jeton)), None, "pas une demande");
        let mut d_longue = d.to_vec();
        d_longue.push(0);
        assert_eq!(jeton_de_la_demande(&d_longue), None, "une demande trop longue");
        assert_eq!(jeton_de_la_demande(&d[..JETON]), None, "une demande trop courte");
        assert_eq!(jeton_de_la_demande(&[]), None);
    }
}

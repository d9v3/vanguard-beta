//! La valeur tapée dans la Console de la fenêtre, après le nom d'une commande (`verifier-fichier ~/Téléchargements/x.pdf`) :
//! sa sorte, ses bornes et ses refus, écrits une seule fois. Ce fichier est compilé trois fois, à l'identique : par
//! la fenêtre (qui type la saisie et la borne avant de l'envoyer), par son relais (qui la revalide sans faire confiance
//! à la fenêtre) et par `vanguard console` (qui la revalide encore, et seul sous Windows, où il n'y a pas de relais).
//! Une seule règle, donc un seul jugement : rien ne peut passer chez l'un et être compris autrement chez l'autre.
//!
//! La valeur ne devient jamais un drapeau ni une commande : `vanguard` la reçoit comme une seule case d'une liste
//! d'arguments fermée (`console <commande> -- <valeur>`), sans shell. Un chemin n'est lu que s'il désigne, une fois
//! chaque lien résolu, un fichier ordinaire sous Téléchargements, Bureau ou Documents du compte (ou un support
//! amovible), jamais dans un dossier caché : une fenêtre prise ou un adjoint abusé ne fait pas lire ~/.ssh ni
//! ~/.config/vanguard avec les droits du compte.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use std::path::{Component, Path, PathBuf};

/// La sorte de valeur qu'une commande accepte. Chaque commande n'en accepte qu'une.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum Argument {
    /// Un fichier : `verifier-fichier`, `courriel-suspect`, `verifier-moi`.
    Chemin,
    /// Un lien reçu : `lien`.
    Adresse,
    /// Des mots cherchés dans le menu : `chercher`.
    Mots,
    /// L'identifiant d'un incident du journal : `evenements`.
    Incident,
    /// Un nombre de jours, de 1 à 3650 : `dernieres-failles`, `journaux-windows`.
    Jours,
}

impl Argument {
    // La fenêtre seule s'en sert (sa trame, son aide) : `vanguard console` ne reçoit que du texte.
    #[allow(dead_code)]
    pub(crate) const TOUTES: [Argument; 5] = [
        Argument::Chemin,
        Argument::Adresse,
        Argument::Mots,
        Argument::Incident,
        Argument::Jours,
    ];

    /// Son octet dans la trame de la fenêtre au relais.
    // La fenêtre seule s'en sert (sa trame, son aide) : `vanguard console` ne reçoit que du texte.
    #[allow(dead_code)]
    pub(crate) fn octet(self) -> u8 {
        match self {
            Argument::Chemin => 1,
            Argument::Adresse => 2,
            Argument::Mots => 3,
            Argument::Incident => 4,
            Argument::Jours => 5,
        }
    }

    // La fenêtre seule s'en sert (sa trame, son aide) : `vanguard console` ne reçoit que du texte.
    #[allow(dead_code)]
    pub(crate) fn depuis_octet(o: u8) -> Option<Argument> {
        Argument::TOUTES.into_iter().find(|a| a.octet() == o)
    }

    /// La longueur permise, en octets : un chemin de Linux (PATH_MAX), une adresse que tout navigateur accepte, une
    /// recherche de quelques mots, un identifiant d'incident (une trentaine de caractères), quatre chiffres.
    pub(crate) fn max(self) -> usize {
        match self {
            Argument::Chemin => 4096,
            Argument::Adresse => 2048,
            Argument::Mots => 256,
            Argument::Incident => 64,
            Argument::Jours => 4,
        }
    }

    /// Ce qui est attendu, pour l'aide de la Console.
    // La fenêtre seule s'en sert (sa trame, son aide) : `vanguard console` ne reçoit que du texte.
    #[allow(dead_code)]
    pub(crate) fn attendu(self) -> &'static str {
        match self {
            Argument::Chemin => crate::tr!("<fichier>", "<file>"),
            Argument::Adresse => crate::tr!("<lien>", "<link>"),
            Argument::Mots => crate::tr!("<mots>", "<words>"),
            Argument::Incident => crate::tr!("<incident>", "<incident>"),
            Argument::Jours => crate::tr!("<jours>", "<days>"),
        }
    }
}

/// Pourquoi une valeur est refusée. Rien n'est lancé.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Refus {
    /// Rien, ou des espaces seulement.
    Vide,
    /// Plus longue que la borne de sa sorte.
    TropLongue,
    /// Un espace au début ou à la fin (un nom qui en a un se tape entre guillemets, sans eux autour).
    Bords,
    /// Commence par « - » : elle ressemblerait à une option.
    Tiret,
    /// Un caractère de contrôle (C0, C1, DEL, NUL, fin de ligne).
    Controle,
    /// Un caractère invisible ou qui retourne le texte (bidi, U+2028, espace sans largeur…).
    Invisible,
    /// La forme attendue n'y est pas (des chiffres, un identifiant, une adresse sans espace).
    Forme,
    /// « ~nom » : le dossier d'un autre compte.
    Tilde,
    /// Un chemin qui ne part ni de la racine ni de « ~ ».
    Relatif,
    /// « .. » dans le chemin.
    Remontee,
    /// Un chemin réseau ou de périphérique (Windows : \\serveur, \\?\, \\.\).
    Reseau,
    /// Le fichier n'est ni sous Téléchargements, Bureau ou Documents, ni sur un support amovible.
    HorsDesEndroits,
    /// Le fichier est dans un dossier caché, ou caché lui-même.
    Cache,
    /// Ce n'est pas un fichier ordinaire (dossier, tube nommé, périphérique).
    PasUnFichier,
    /// Introuvable (ou un lien qui ne mène nulle part).
    Introuvable,
    /// Le dossier personnel du compte est inconnu : aucun endroit n'est permis.
    MaisonInconnue,
}

impl Refus {
    pub(crate) fn phrase(self) -> &'static str {
        match self {
            Refus::Vide => crate::tr!("valeur vide", "empty value"),
            Refus::TropLongue => crate::tr!("valeur trop longue", "value too long"),
            Refus::Bords => crate::tr!(
                "espace au début ou à la fin de la valeur",
                "space at the start or end of the value"
            ),
            Refus::Tiret => crate::tr!(
                "une valeur ne commence pas par « - » : elle passerait pour une option",
                "a value does not start with \"-\": it would pass for an option"
            ),
            Refus::Controle => crate::tr!("caractère de contrôle dans la valeur", "control character in the value"),
            Refus::Invisible => crate::tr!(
                "caractère invisible ou qui retourne le texte dans la valeur",
                "invisible or text-reversing character in the value"
            ),
            Refus::Forme => crate::tr!(
                "la valeur n'a pas la forme attendue",
                "the value does not have the expected form"
            ),
            Refus::Tilde => crate::tr!(
                "« ~nom » désigne le dossier d'un autre compte : seul « ~/ » est compris",
                "\"~name\" means another account's folder: only \"~/\" is understood"
            ),
            Refus::Relatif => crate::tr!(
                "chemin relatif : il doit commencer par « ~/ » ou par la racine",
                "relative path: it must start with \"~/\" or at the root"
            ),
            Refus::Remontee => crate::tr!("« .. » refusé dans un chemin", "\"..\" refused in a path"),
            Refus::Reseau => crate::tr!(
                "chemin réseau ou de périphérique refusé",
                "network or device path refused"
            ),
            Refus::HorsDesEndroits => crate::tr!(
                "fichier hors des endroits permis (Téléchargements, Bureau, Documents, support amovible)",
                "file outside the allowed places (Downloads, Desktop, Documents, removable drive)"
            ),
            Refus::Cache => crate::tr!(
                "fichier caché ou dans un dossier caché",
                "hidden file or file in a hidden folder"
            ),
            Refus::PasUnFichier => crate::tr!("ce n'est pas un fichier ordinaire", "this is not a regular file"),
            Refus::Introuvable => crate::tr!("fichier introuvable", "file not found"),
            Refus::MaisonInconnue => crate::tr!(
                "dossier personnel inconnu : aucun fichier ne peut être lu",
                "home folder unknown: no file can be read"
            ),
        }
    }
}

/// Invisible ou qui retourne le texte : marques de sens et isolats (bidi), séparateurs de ligne et de paragraphe,
/// espaces et liants sans largeur, trait d'union conditionnel, sélecteurs de variante, étiquettes, remplissages
/// Hangûl, BOM. Une valeur qui s'affiche autrement qu'elle se lit ne passe pas.
fn invisible(c: char) -> bool {
    matches!(
        u32::from(c),
        0x00AD
            | 0x034F
            | 0x061C
            | 0x115F
            | 0x1160
            | 0x17B4
            | 0x17B5
            | 0x180B..=0x180F
            | 0x200B..=0x200F
            | 0x2028..=0x202E
            | 0x2060..=0x206F
            | 0x3164
            | 0xFE00..=0xFE0F
            | 0xFEFF
            | 0xFFA0
            | 0xFFF0..=0xFFFB
            | 0xE0000..=0xE0FFF
    )
}

/// La forme d'une valeur, sans rien lire sur le disque : ce que la fenêtre juge avant d'envoyer, et ce que le relais
/// et `vanguard` rejugent. Un chemin y est seulement lexical (« ~/ » ou absolu, sans « .. ») : les endroits permis
/// se jugent sur le chemin réel (`juger_chemin`).
pub(crate) fn valider(sorte: Argument, texte: &str) -> Result<(), Refus> {
    if texte.trim().is_empty() {
        return Err(Refus::Vide);
    }
    if texte.starts_with('-') {
        return Err(Refus::Tiret);
    }
    if texte.chars().any(char::is_control) {
        return Err(Refus::Controle);
    }
    if texte.chars().any(invisible) {
        return Err(Refus::Invisible);
    }
    if texte.trim() != texte {
        return Err(Refus::Bords);
    }
    if texte.len() > sorte.max() {
        return Err(Refus::TropLongue);
    }
    match sorte {
        Argument::Jours => jours(texte).map(|_| ()),
        Argument::Incident => {
            let permis = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ':' | '.');
            if texte.chars().all(permis) {
                Ok(())
            } else {
                Err(Refus::Forme)
            }
        }
        Argument::Adresse => {
            if texte.chars().any(char::is_whitespace) {
                Err(Refus::Forme)
            } else {
                Ok(())
            }
        }
        Argument::Mots => Ok(()),
        Argument::Chemin => forme_du_chemin(texte),
    }
}

/// Le nombre de jours : un à quatre chiffres ASCII, sans zéro devant, de 1 à 3650 (la borne de `--jours`).
pub(crate) fn jours(texte: &str) -> Result<u16, Refus> {
    if texte.is_empty()
        || texte.len() > Argument::Jours.max()
        || !texte.bytes().all(|o| o.is_ascii_digit())
        || texte.starts_with('0')
    {
        return Err(Refus::Forme);
    }
    match texte.parse::<u16>() {
        Ok(n) if (1..=3650).contains(&n) => Ok(n),
        _ => Err(Refus::Forme),
    }
}

/// « ~ » seul, ou suivi d'un séparateur : le reste du chemin, sans le séparateur. `None` : pas de « ~ » devant.
/// « ~nom » (le dossier d'un autre compte) : refusé.
fn apres_tilde(texte: &str) -> Option<Result<&str, Refus>> {
    let reste = texte.strip_prefix('~')?;
    if reste.is_empty() {
        return Some(Ok(""));
    }
    let separateurs: &[char] = if cfg!(windows) { &['/', '\\'] } else { &['/'] };
    Some(reste.strip_prefix(separateurs).ok_or(Refus::Tilde))
}

/// Un chemin lexicalement acceptable : « ~/… » ou absolu, sans « .. », et sous Windows sur une lettre de lecteur
/// seulement (ni \\serveur\partage, ni \\?\, ni \\.\, que `canonicalize` et l'ouverture traiteraient à part).
fn forme_du_chemin(texte: &str) -> Result<(), Refus> {
    let reste = match apres_tilde(texte) {
        Some(r) => r?,
        None => texte,
    };
    let chemin = Path::new(reste);
    for c in chemin.components() {
        match c {
            Component::ParentDir => return Err(Refus::Remontee),
            // Seule une lettre de lecteur (« C: ») ; et après « ~ », aucun préfixe.
            Component::Prefix(p) if texte != reste || !matches!(p.kind(), std::path::Prefix::Disk(_)) => {
                return Err(Refus::Reseau);
            }
            // Après « ~/ », le reste est relatif à la maison : une racine (« ~//etc ») le rendrait absolu.
            Component::RootDir if texte != reste => return Err(Refus::Relatif),
            _ => {}
        }
    }
    if texte == reste && !chemin.is_absolute() {
        return Err(Refus::Relatif);
    }
    Ok(())
}

/// Le chemin tapé, « ~ » remplacé par `maison` (le même remplacement chez le relais et chez `vanguard`, qui seuls le
/// font : la fenêtre envoie le texte tel quel). Refuse ce que refuse `forme_du_chemin`.
pub(crate) fn developper(texte: &str, maison: &Path) -> Result<PathBuf, Refus> {
    forme_du_chemin(texte)?;
    match apres_tilde(texte) {
        Some(reste) => {
            let reste = reste?;
            if !maison.is_absolute() || maison.as_os_str().as_encoded_bytes().contains(&0) {
                return Err(Refus::MaisonInconnue);
            }
            Ok(if reste.is_empty() {
                maison.to_path_buf()
            } else {
                maison.join(reste)
            })
        }
        None => Ok(PathBuf::from(texte)),
    }
}

/// Un composant caché (« .ssh », « .config ») : ce que la Console ne lit jamais, même sous un endroit permis.
fn cache(c: Component<'_>) -> bool {
    matches!(c, Component::Normal(n) if n.as_encoded_bytes().first() == Some(&b'.'))
}

/// `chemin` est-il strictement sous `racine`, sans aucun composant caché entre les deux ? Les deux sont des chemins
/// réels (liens résolus) : la comparaison est faite composant par composant.
fn strictement_sous(chemin: &Path, racine: &Path) -> Option<bool> {
    let reste = chemin.strip_prefix(racine).ok()?;
    let mut composants = reste.components().peekable();
    composants.peek()?;
    Some(!composants.any(cache))
}

/// Une racine permise : son chemin réel est strictement sous le chemin réel de la maison, sans dossier caché entre
/// les deux. Un « Documents » qui est un lien vers ~/.ssh, vers / ou vers la maison elle-même ne compte pas.
pub(crate) fn racine_permise(racine_reelle: &Path, maison_reelle: &Path) -> bool {
    strictement_sous(racine_reelle, maison_reelle) == Some(true)
}

/// Le dossier que déclare user-dirs.dirs pour `cle` (« XDG_DOWNLOAD_DIR="$HOME/Téléchargements" »), seulement s'il
/// est sous la maison : « $HOME/… », ou un chemin absolu. Lexical ; `racine_permise` juge ensuite le chemin réel.
#[cfg(unix)]
fn declare(declares: &str, cle: &str, maison: &Path) -> Option<PathBuf> {
    let valeur = declares
        .lines()
        .find_map(|l| l.trim().strip_prefix(cle)?.strip_prefix('='))?
        .trim()
        .trim_matches('"');
    let chemin = match valeur.strip_prefix("$HOME/") {
        Some(reste) => maison.join(reste),
        None => PathBuf::from(valeur),
    };
    (chemin.is_absolute() && !chemin.components().any(|c| c == Component::ParentDir)).then_some(chemin)
}

/// Les endroits permis sous Linux, en chemins réels : Téléchargements, Bureau et Documents (ceux que déclare
/// user-dirs.dirs, et leurs noms usuels), chacun gardé seulement si `racine_permise` ; et /run/media/<compte>, où le
/// bureau monte les supports amovibles, s'il est bien lui-même (aucun lien). `declares` : le texte de user-dirs.dirs
/// (vide s'il manque) ; `compte` : le nom du compte.
#[cfg(unix)]
pub(crate) fn racines_linux(maison: &Path, declares: &str, compte: Option<&str>) -> Vec<PathBuf> {
    let Ok(maison_reelle) = maison.canonicalize() else {
        return Vec::new();
    };
    let mut candidats: Vec<PathBuf> = ["XDG_DOWNLOAD_DIR", "XDG_DESKTOP_DIR", "XDG_DOCUMENTS_DIR"]
        .iter()
        .filter_map(|cle| declare(declares, cle, maison))
        .collect();
    candidats.extend(
        ["Téléchargements", "Downloads", "Bureau", "Desktop", "Documents"]
            .iter()
            .map(|n| maison.join(n)),
    );
    let mut racines: Vec<PathBuf> = Vec::new();
    for c in candidats {
        if let Ok(r) = c.canonicalize()
            && r.is_dir()
            && racine_permise(&r, &maison_reelle)
            && !racines.contains(&r)
        {
            racines.push(r);
        }
    }
    if let Some(compte) = compte.filter(|n| nom_de_compte(n)) {
        let media = Path::new("/run/media").join(compte);
        if media.canonicalize().is_ok_and(|r| r == media) {
            racines.push(media);
        }
    }
    racines
}

/// Un nom de compte qui fait un seul composant de chemin (ni vide, ni « . », ni « .. », ni séparateur, ni NUL).
#[cfg(unix)]
fn nom_de_compte(nom: &str) -> bool {
    !nom.is_empty() && !nom.starts_with('.') && !nom.contains(['/', '\0'])
}

/// Juge un chemin tapé : sa forme (`valider`), « ~ » développé, puis son chemin réel (chaque lien résolu) doit être un
/// fichier ordinaire strictement sous l'une des `racines` (déjà réelles), sans composant caché après elle. Rend ce
/// chemin réel, seul à être passé plus loin (jamais le texte tapé).
pub(crate) fn juger_chemin(texte: &str, maison: &Path, racines: &[PathBuf]) -> Result<PathBuf, Refus> {
    valider(Argument::Chemin, texte)?;
    let chemin = developper(texte, maison)?;
    let reel = chemin.canonicalize().map_err(|_| Refus::Introuvable)?;
    let mut sous = racines.iter().filter_map(|r| strictement_sous(&reel, r));
    match (sous.next(), sous.any(|visible| visible)) {
        (None, _) => return Err(Refus::HorsDesEndroits),
        (Some(false), false) => return Err(Refus::Cache),
        _ => {}
    }
    if !std::fs::metadata(&reel).is_ok_and(|m| m.is_file()) {
        return Err(Refus::PasUnFichier);
    }
    Ok(reel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chaque_octet_de_sorte_se_relit() {
        for a in Argument::TOUTES {
            assert_eq!(Argument::depuis_octet(a.octet()), Some(a));
        }
        assert_eq!(Argument::depuis_octet(0), None);
        assert_eq!(Argument::depuis_octet(6), None);
    }

    #[test]
    fn les_refus_communs() {
        for a in Argument::TOUTES {
            assert_eq!(valider(a, ""), Err(Refus::Vide), "{a:?}");
            assert_eq!(valider(a, "   "), Err(Refus::Vide), "{a:?}");
            assert_eq!(valider(a, "-x"), Err(Refus::Tiret), "{a:?}");
            assert_eq!(valider(a, "--internet"), Err(Refus::Tiret), "{a:?}");
            assert_eq!(valider(a, " 7"), Err(Refus::Bords), "{a:?}");
            assert_eq!(valider(a, "7 "), Err(Refus::Bords), "{a:?}");
            for c in ['\0', '\n', '\r', '\t', '\u{1b}', '\u{7f}', '\u{85}', '\u{9b}'] {
                assert_eq!(valider(a, &format!("1{c}2")), Err(Refus::Controle), "{a:?} {c:?}");
            }
            for c in [
                '\u{202E}',
                '\u{202A}',
                '\u{2066}',
                '\u{2069}',
                '\u{200E}',
                '\u{200F}',
                '\u{2028}',
                '\u{2029}',
                '\u{200B}',
                '\u{FEFF}',
                '\u{061C}',
                '\u{E0041}',
            ] {
                assert_eq!(valider(a, &format!("1{c}2")), Err(Refus::Invisible), "{a:?} {c:?}");
            }
            let long = "1".repeat(a.max().saturating_add(1));
            assert_eq!(valider(a, &long), Err(Refus::TropLongue), "{a:?}");
        }
    }

    #[test]
    fn les_bornes_de_chaque_sorte() {
        assert_eq!(valider(Argument::Mots, &"a".repeat(256)), Ok(()));
        assert_eq!(valider(Argument::Adresse, &"a".repeat(2048)), Ok(()));
        assert_eq!(valider(Argument::Incident, &"a".repeat(64)), Ok(()));
        let racine = if cfg!(windows) { "C:\\" } else { "/" };
        let juste = 4096_usize.saturating_sub(racine.len());
        assert_eq!(
            valider(Argument::Chemin, &format!("{racine}{}", "a".repeat(juste))),
            Ok(())
        );
        assert_eq!(
            valider(
                Argument::Chemin,
                &format!("{racine}{}", "a".repeat(juste.saturating_add(1)))
            ),
            Err(Refus::TropLongue)
        );
        // La borne compte des octets, pas des caractères.
        assert_eq!(valider(Argument::Mots, &"é".repeat(129)), Err(Refus::TropLongue));
    }

    #[test]
    fn les_jours() {
        for (t, n) in [("1", 1), ("7", 7), ("365", 365), ("3650", 3650)] {
            assert_eq!(jours(t), Ok(n));
            assert_eq!(valider(Argument::Jours, t), Ok(()));
        }
        for t in ["0", "07", "3651", "9999", "12345", "+7", "7j", "٣", "１", "1e3", "0x10"] {
            assert!(valider(Argument::Jours, t).is_err(), "{t}");
        }
    }

    #[test]
    fn les_incidents_et_les_adresses() {
        assert_eq!(valider(Argument::Incident, "20261023T140509-1a2b-0-deadbeef"), Ok(()));
        for t in ["a b", "a/b", "a;b", "é", "a\\b", "$(x)"] {
            assert_eq!(valider(Argument::Incident, t), Err(Refus::Forme), "{t}");
        }
        assert_eq!(valider(Argument::Adresse, "https://exemple.test/a?b=c&d"), Ok(()));
        assert_eq!(valider(Argument::Adresse, "https://a b"), Err(Refus::Forme));
        assert_eq!(valider(Argument::Adresse, "https://a\u{a0}b"), Err(Refus::Forme));
        assert_eq!(valider(Argument::Mots, "pare feu"), Ok(()));
    }

    #[test]
    fn la_forme_d_un_chemin() {
        assert_eq!(valider(Argument::Chemin, "~"), Ok(()));
        assert_eq!(valider(Argument::Chemin, "~/Téléchargements/x.pdf"), Ok(()));
        assert_eq!(valider(Argument::Chemin, "~/Mes documents/a b.pdf"), Ok(()));
        assert_eq!(valider(Argument::Chemin, "~bob/x"), Err(Refus::Tilde));
        assert_eq!(valider(Argument::Chemin, "x.pdf"), Err(Refus::Relatif));
        assert_eq!(valider(Argument::Chemin, "./x.pdf"), Err(Refus::Relatif));
        assert_eq!(valider(Argument::Chemin, "~//etc/passwd"), Err(Refus::Relatif));
        assert_eq!(valider(Argument::Chemin, "../../.ssh/id_ed25519"), Err(Refus::Remontee));
        assert_eq!(valider(Argument::Chemin, "~/../bob/x"), Err(Refus::Remontee));
        assert_eq!(valider(Argument::Chemin, "~/a/../../x"), Err(Refus::Remontee));
        #[cfg(unix)]
        {
            assert_eq!(valider(Argument::Chemin, "/home/alice/x.pdf"), Ok(()));
            assert_eq!(valider(Argument::Chemin, "/home/alice/../bob/x"), Err(Refus::Remontee));
        }
        #[cfg(windows)]
        {
            assert_eq!(valider(Argument::Chemin, r"C:\Users\alice\x.pdf"), Ok(()));
            assert_eq!(valider(Argument::Chemin, r"~\Downloads\x.pdf"), Ok(()));
            assert_eq!(
                valider(Argument::Chemin, r"\\serveur\partage\x.pdf"),
                Err(Refus::Reseau)
            );
            assert_eq!(valider(Argument::Chemin, r"\\?\C:\x.pdf"), Err(Refus::Reseau));
            assert_eq!(valider(Argument::Chemin, r"\\.\PhysicalDrive0"), Err(Refus::Reseau));
            assert_eq!(valider(Argument::Chemin, r"C:x.pdf"), Err(Refus::Relatif));
            assert_eq!(valider(Argument::Chemin, r"\x.pdf"), Err(Refus::Relatif));
            assert_eq!(valider(Argument::Chemin, r"~\C:\x"), Err(Refus::Reseau));
        }
    }

    #[test]
    fn le_tilde_se_developpe_dans_la_maison() {
        let maison = if cfg!(windows) {
            PathBuf::from(r"C:\Users\alice")
        } else {
            PathBuf::from("/home/alice")
        };
        assert_eq!(developper("~", &maison), Ok(maison.clone()));
        assert_eq!(
            developper("~/Documents/a.pdf", &maison),
            Ok(maison.join("Documents/a.pdf"))
        );
        assert_eq!(developper("~/x", Path::new("")), Err(Refus::MaisonInconnue));
        assert_eq!(developper("~/x", Path::new("relatif")), Err(Refus::MaisonInconnue));
    }

    /// Une maison jetable, effacée à la fin.
    struct Maison(PathBuf);

    impl Maison {
        fn nouvelle(nom: &str) -> Maison {
            let d = std::env::temp_dir().join(format!("vanguard-valeur-{nom}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Maison(d.canonicalize().unwrap())
        }
    }

    impl Drop for Maison {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Sous les deux systèmes (Wine compris) : un fichier ordinaire d'une racine passe, tapé avec « ~ » ou en entier ;
    /// un dossier caché sous elle, la racine elle-même, un fichier hors d'elle et un absent ne passent pas.
    #[test]
    fn juger_un_chemin_sous_les_deux_systemes() {
        let m = Maison::nouvelle("deux-systemes");
        // Le chemin tel qu'on le tape : sous Windows, la forme réelle (« \\?\C:\ ») serait refusée comme un
        // chemin de périphérique, ce qui est voulu.
        let tapee = std::env::temp_dir().join(m.0.file_name().unwrap());
        for d in ["Documents/sous", "Documents/.cache", "Autre"] {
            std::fs::create_dir_all(m.0.join(d)).unwrap();
        }
        for f in ["Documents/sous/a.txt", "Documents/.cache/b.txt", "Autre/c.txt"] {
            std::fs::write(m.0.join(f), "x").unwrap();
        }
        let racines = [m.0.join("Documents").canonicalize().unwrap()];
        let texte = |p: &Path| p.to_str().unwrap().to_owned();
        let attendu = m.0.join("Documents/sous/a.txt").canonicalize().unwrap();
        let sep = std::path::MAIN_SEPARATOR;
        assert_eq!(
            juger_chemin(&format!("~{sep}Documents{sep}sous{sep}a.txt"), &tapee, &racines),
            Ok(attendu.clone())
        );
        assert_eq!(
            juger_chemin(&texte(&tapee.join("Documents/sous/a.txt")), &tapee, &racines),
            Ok(attendu)
        );
        assert_eq!(
            juger_chemin(&texte(&tapee.join("Documents/.cache/b.txt")), &tapee, &racines),
            Err(Refus::Cache)
        );
        assert_eq!(
            juger_chemin(&texte(&tapee.join("Autre/c.txt")), &tapee, &racines),
            Err(Refus::HorsDesEndroits)
        );
        assert_eq!(
            juger_chemin(&texte(&tapee.join("Documents")), &tapee, &racines),
            Err(Refus::HorsDesEndroits)
        );
        assert_eq!(
            juger_chemin(&texte(&tapee.join("Documents/sous")), &tapee, &racines),
            Err(Refus::PasUnFichier)
        );
        assert_eq!(
            juger_chemin(&texte(&tapee.join("Documents/absent.txt")), &tapee, &racines),
            Err(Refus::Introuvable)
        );
    }

    #[test]
    fn une_racine_hors_de_la_maison_ou_cachee_n_est_pas_permise() {
        let m = Path::new("/home/alice");
        assert!(racine_permise(&m.join("Documents"), m));
        assert!(racine_permise(&m.join("Mes trucs/Documents"), m));
        assert!(!racine_permise(m, m));
        assert!(!racine_permise(Path::new("/"), m));
        // Un compte dont le nom commence par celui de la maison n'est pas sous elle (« /home/a », « /home/alice »).
        assert!(!racine_permise(
            Path::new("/home/alice/Documents"),
            Path::new("/home/a")
        ));
        assert!(!racine_permise(&m.join(".ssh"), m));
        assert!(!racine_permise(&m.join(".local/Documents"), m));
    }

    #[cfg(unix)]
    #[test]
    fn seuls_les_fichiers_ordinaires_des_endroits_permis_passent() {
        use std::os::unix::fs::symlink;
        let m = Maison::nouvelle("endroits");
        let maison = &m.0;
        for d in [
            "Téléchargements",
            "Documents",
            ".ssh",
            ".config/vanguard",
            "Images",
            "Téléchargements/.cache",
        ] {
            std::fs::create_dir_all(maison.join(d)).unwrap();
        }
        for f in [
            "Téléchargements/x.pdf",
            "Téléchargements/a b.pdf",
            "Documents/lettre.eml",
            ".ssh/id_ed25519",
            ".config/vanguard/cle",
            "Images/photo.png",
            "Téléchargements/.cache/y",
            "Téléchargements/.cache.pdf",
            "racine.txt",
        ] {
            std::fs::write(maison.join(f), b"essai").unwrap();
        }
        symlink(maison.join(".ssh/id_ed25519"), maison.join("Téléchargements/cle.pdf")).unwrap();
        symlink(maison.join(".ssh"), maison.join("Téléchargements/dossier")).unwrap();
        symlink("/proc/self/environ", maison.join("Téléchargements/env")).unwrap();
        symlink(
            maison.join("Téléchargements/x.pdf"),
            maison.join("Documents/vers-x.pdf"),
        )
        .unwrap();
        symlink(maison.join("absent"), maison.join("Téléchargements/casse")).unwrap();
        std::fs::create_dir_all(maison.join("Téléchargements/sous")).unwrap();
        let racines = racines_linux(maison, "", Some("alice"));
        assert_eq!(
            racines.iter().filter(|r| r.starts_with(maison)).count(),
            2,
            "{racines:?}"
        );
        let juge = |t: &str| juger_chemin(t, maison, &racines);
        assert_eq!(
            juge("~/Téléchargements/x.pdf"),
            Ok(maison.join("Téléchargements/x.pdf"))
        );
        assert_eq!(
            juge(&format!("{}/Documents/lettre.eml", maison.display())),
            Ok(maison.join("Documents/lettre.eml"))
        );
        assert_eq!(
            juge("~/Téléchargements/a b.pdf"),
            Ok(maison.join("Téléchargements/a b.pdf"))
        );
        // Un lien d'un endroit permis vers un autre : le chemin réel, permis.
        assert_eq!(juge("~/Documents/vers-x.pdf"), Ok(maison.join("Téléchargements/x.pdf")));
        for (t, refus) in [
            ("~/.ssh/id_ed25519", Refus::HorsDesEndroits),
            ("~/.config/vanguard/cle", Refus::HorsDesEndroits),
            ("~/Images/photo.png", Refus::HorsDesEndroits),
            ("~/racine.txt", Refus::HorsDesEndroits),
            ("~/Téléchargements/cle.pdf", Refus::HorsDesEndroits),
            ("~/Téléchargements/dossier/id_ed25519", Refus::HorsDesEndroits),
            ("~/Téléchargements/env", Refus::HorsDesEndroits),
            ("~/Téléchargements/.cache/y", Refus::Cache),
            ("~/Téléchargements/.cache.pdf", Refus::Cache),
            ("~/Téléchargements/casse", Refus::Introuvable),
            ("~/Téléchargements/absent.pdf", Refus::Introuvable),
            ("~/Téléchargements/sous", Refus::PasUnFichier),
            ("~/Téléchargements", Refus::HorsDesEndroits),
            ("/proc/self/environ", Refus::HorsDesEndroits),
            ("/dev/zero", Refus::HorsDesEndroits),
            ("/etc/passwd", Refus::HorsDesEndroits),
            ("~/Téléchargements/../.ssh/id_ed25519", Refus::Remontee),
            ("../../.ssh/id_ed25519", Refus::Remontee),
            ("Téléchargements/x.pdf", Refus::Relatif),
            ("-x", Refus::Tiret),
        ] {
            assert_eq!(juge(t), Err(refus), "{t}");
        }
        // Un tube nommé dans Téléchargements : jamais ouvert (son ouverture bloquerait), refusé.
        let tube = maison.join("Téléchargements/tube");
        let fait = std::process::Command::new("mkfifo").arg(&tube).status();
        if fait.is_ok_and(|s| s.success()) {
            assert_eq!(juge("~/Téléchargements/tube"), Err(Refus::PasUnFichier));
        }
        // Sans racine, rien ne passe.
        assert_eq!(
            juger_chemin("~/Téléchargements/x.pdf", maison, &[]),
            Err(Refus::HorsDesEndroits)
        );
    }

    #[cfg(unix)]
    #[test]
    fn les_racines_declarees_ou_liees_hors_de_la_maison_sont_ecartees() {
        use std::os::unix::fs::symlink;
        let m = Maison::nouvelle("racines");
        let maison = &m.0;
        std::fs::create_dir_all(maison.join(".ssh")).unwrap();
        std::fs::create_dir_all(maison.join("Mes téléchargements")).unwrap();
        // Bureau : un lien vers ~/.ssh ; Desktop : un lien vers / ; Documents : un lien vers la maison.
        symlink(maison.join(".ssh"), maison.join("Bureau")).unwrap();
        symlink("/", maison.join("Desktop")).unwrap();
        symlink(maison, maison.join("Documents")).unwrap();
        let declares = "XDG_DOWNLOAD_DIR=\"$HOME/Mes téléchargements\"\nXDG_DESKTOP_DIR=\"/etc\"\n\
                        XDG_DOCUMENTS_DIR=\"$HOME/.ssh\"\n";
        let racines = racines_linux(maison, declares, Some("../alice"));
        assert_eq!(racines, vec![maison.join("Mes téléchargements")]);
        // La maison elle-même, ou un nom de compte qui sort de /run/media : rien.
        assert_eq!(racines_linux(Path::new("/nulle/part"), "", None), Vec::<PathBuf>::new());
        assert!(!nom_de_compte(".."));
        assert!(!nom_de_compte("a/b"));
        assert!(nom_de_compte("alice"));
    }
}

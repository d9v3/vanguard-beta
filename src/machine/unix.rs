//! Ce que Linux vérifie hors de machine/linux/ : fichiers secrets lisibles par d'autres comptes, sudo sans mot de
//! passe, dossiers de commandes modifiables par d'autres comptes. Ce qu'il vérifie en plus est dans
//! machine/linux/privileges.rs.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::{Constat, alerte, ok, sortie};
use crate::risk::Niveau;
use crate::{tr, trf};

/// Le chemin du programme `cmd` dans les dossiers de `path` (le PATH), comme `command -v` le trouve, sans lancer de
/// shell. Un nom avec une barre oblique est un chemin, pris tel quel. Le bit d'exécution compte : un fichier
/// ordinaire du même nom ne se lance pas.
pub(crate) fn chemin_dans(cmd: &str, path: &OsStr) -> Option<PathBuf> {
    let executable = |f: &Path| {
        f.metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    if cmd.is_empty() {
        return None;
    }
    if cmd.contains('/') {
        return executable(Path::new(cmd)).then(|| PathBuf::from(cmd));
    }
    // Une entrée vide du PATH veut dire le dossier courant pour le shell : on ne la suit pas, un programme posé là
    // par un tiers passerait pour installé.
    std::env::split_paths(path)
        .filter(|d| !d.as_os_str().is_empty())
        .map(|d| d.join(cmd))
        .find(|f| executable(f))
}

/// Le programme `cmd` est-il dans le PATH, exécutable ?
pub(crate) fn present(cmd: &str) -> bool {
    chemin_dans(cmd, &std::env::var_os("PATH").unwrap_or_default()).is_some()
}

/// Fichiers qui contiennent des mots de passe ou des jetons d'accès, chemin relatif au dossier personnel.
const SECRETS: &[&str] = &[
    ".git-credentials",
    ".netrc",
    ".pgpass",
    ".my.cnf",
    ".npmrc",
    ".pypirc",
    ".aws/credentials",
    ".docker/config.json",
    ".kube/config",
    ".config/gh/hosts.yml",
    ".config/rclone/rclone.conf",
    ".gnupg",
];

/// Un secret est mal protégé si le groupe ou les autres comptes peuvent le lire (ou y entrer, pour un dossier).
pub(super) fn secret_expose(mode: u32) -> bool {
    mode & 0o077 != 0
}

/// Ce qu'une correction du compte attend au bout de son chemin : un `chmod 600` vise un fichier, un `chmod 700` ou
/// `750` un dossier. Un dossier nommé comme une clé (« id_… ») ou un ~/.ssh devenu fichier ne reçoit pas l'autre.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Attendu {
    Fichier,
    Dossier,
}

/// Pourquoi une correction du compte (un `chmod` sans mot de passe) ne viserait pas sûrement `relatif`, chemin sous
/// `maison` : `None` seulement si chaque élément, du dossier personnel lui-même jusqu'au bout, est lu sans suivre de
/// lien (`symlink_metadata`), appartient au compte qui fait le bilan, porte un nom lisible tel quel (UTF-8), et que
/// le bout est de la sorte `attendu` (un fichier sans second nom ailleurs, ou un dossier). Un lien n'importe où sur
/// le chemin (posé par stow, chezmoi, ou par un programme du compte) ferait changer par `chmod` le fichier visé, pas
/// celui que la personne a lu ; un nom qui n'est pas UTF-8 s'écrit, dans la commande et le geste, avec un caractère
/// de remplacement, donc vise un autre nom ; un lien physique changerait les droits de l'autre nom aussi. Le constat
/// le dit (où, pourquoi, nettoyé) et ne propose pas de correction du compte. Un chemin qui disparaît pendant la
/// lecture n'est pas corrigé non plus. Le lot qui appliquera ces corrections relira de même au moment d'agir (sans
/// shell : ouverture sans suivre de lien, puis fchmod).
pub(crate) fn hors_correction(maison: &Path, relatif: &Path, attendu: Attendu) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let montre = |n: &OsStr| crate::ui::affichable(&n.to_string_lossy());
    let mut chemin = match maison_simple(maison) {
        Ok(m) => m,
        Err(r) => return Some(r.to_string()),
    };
    let compte = crate::socle::euid();
    let mut ou = String::from("~");
    let mut elements = relatif.components().peekable();
    loop {
        let Ok(meta) = std::fs::symlink_metadata(&chemin) else {
            return Some(trf!(
                "{ou} a changé pendant la lecture",
                "{ou} changed while being read"
            ));
        };
        if meta.file_type().is_symlink() {
            let vers = std::fs::read_link(&chemin).map_or_else(
                |_| tr!("illisible", "unreadable").to_string(),
                |c| crate::modele::resultat::nom_sans_piege(&c.to_string_lossy(), 120),
            );
            return Some(trf!("{ou} est un lien vers {vers}", "{ou} is a link to {vers}"));
        }
        if meta.uid() != compte {
            return Some(trf!(
                "{ou} appartient à un autre compte",
                "{ou} belongs to another account"
            ));
        }
        let Some(suivant) = elements.next() else {
            return match attendu {
                Attendu::Dossier if meta.is_dir() => None,
                Attendu::Fichier if meta.is_file() && meta.nlink() <= 1 => None,
                Attendu::Fichier if meta.is_file() => Some(trf!(
                    "{ou} a un autre nom ailleurs (lien physique), dont les droits changeraient aussi",
                    "{ou} has another name elsewhere (hard link), whose permissions would change too"
                )),
                Attendu::Fichier => Some(trf!("{ou} n'est pas un simple fichier", "{ou} is not a plain file")),
                Attendu::Dossier => Some(trf!("{ou} n'est pas un dossier", "{ou} is not a folder")),
            };
        };
        let std::path::Component::Normal(nom) = suivant else {
            return Some(trf!("{ou} : chemin inattendu", "{ou}: unexpected path"));
        };
        if !meta.is_dir() {
            return Some(trf!("{ou} n'est pas un dossier", "{ou} is not a folder"));
        }
        chemin.push(nom);
        ou = format!("{ou}/{}", montre(nom));
        if nom.to_str().is_none() {
            return Some(trf!(
                "le nom de {ou} n'est pas lisible tel quel (pas en UTF-8) : une commande viserait un autre nom",
                "the name of {ou} cannot be read as is (not UTF-8): a command would target another name"
            ));
        }
    }
}

/// Le dossier personnel tel que le noyau le lit, élément par élément : `lstat` d'un chemin qui finit par « / » ou
/// « /. » suit le lien du dernier élément, donc un HOME écrit ainsi cachait que le dossier personnel est un lien.
/// Les « . » et les « / » en trop sont retirés ; un chemin relatif, un « .. » ou un nom qui n'est pas UTF-8 sont
/// refusés (le geste écrit le chemin en texte).
fn maison_simple(maison: &Path) -> Result<PathBuf, crate::modele::raison::Echec> {
    use std::path::Component;
    let refus = || {
        crate::modele::raison::Echec::refuse(
            "droits/poser",
            trf!(
                "le dossier personnel ({}) n'est pas un chemin simple",
                "the home folder ({}) is not a plain path",
                crate::modele::resultat::nom_sans_piege(&maison.to_string_lossy(), 120)
            ),
        )
    };
    if !maison.is_absolute() {
        return Err(refus());
    }
    let mut simple = PathBuf::new();
    for c in maison.components() {
        match c {
            Component::RootDir => simple.push(c),
            Component::Normal(n) if n.to_str().is_some() => simple.push(n),
            _ => return Err(refus()),
        }
    }
    Ok(simple)
}

/// Le geste d'une correction du compte sur `relatif` (le chemin qu'elle vise, pour relever et remettre ses droits),
/// ou pourquoi elle n'est pas proposée (`hors_correction`). Le geste n'existe que si la garde passe : rien d'autre ne
/// le fabrique pour un constat. L'erreur est un refus dont la phrase dit pourquoi (`Echec::refuse`).
pub(crate) fn geste_du_compte(
    maison: &Path,
    relatif: &Path,
    attendu: Attendu,
) -> Result<crate::optimiser::Geste, crate::modele::raison::Echec> {
    if let Some(r) = hors_correction(maison, relatif, attendu) {
        return Err(crate::modele::raison::Echec::refuse("droits/poser", r));
    }
    let chemin = maison_simple(maison)?;
    let chemin = if relatif.as_os_str().is_empty() {
        chemin
    } else {
        chemin.join(relatif)
    };
    crate::optimiser::Geste::droits(&chemin).ok_or_else(|| {
        crate::modele::raison::Echec::refuse(
            "droits/poser",
            tr!(
                "son nom n'est pas lisible tel quel (pas en UTF-8)",
                "its name cannot be read as is (not UTF-8)"
            ),
        )
    })
}

/// Les fichiers secrets de `maison`, et le dossier personnel lui-même. `dossier_ouvert` : le texte de l'alerte quand
/// les autres comptes peuvent lire le dossier personnel (il nomme la machine).
pub(super) fn fichiers_secrets(maison: &Path, dossier_ouvert: &str) -> Vec<Constat> {
    let mut exposes = Vec::new();
    let mut commandes = Vec::new();
    let mut gestes = Vec::new();
    // Exposés, mais à travers un lien (ou ni fichier ni dossier) : dits, jamais corrigés par le compte.
    let mut a_travers = Vec::new();
    let mut raisons = Vec::new();
    for nom in SECRETS {
        let chemin = maison.join(nom);
        // L'exposition se juge sur ce qui est visé, lien suivi : un lien symbolique (stow, chezmoi…) a toujours 777,
        // ce qui donnait une fausse alerte. La correction, elle, ne passe jamais par un lien (`hors_correction`).
        let Ok(meta) = std::fs::metadata(&chemin) else {
            continue;
        };
        if !secret_expose(meta.permissions().mode()) {
            continue;
        }
        // .gnupg est un dossier ; les autres, des fichiers. Ce qui n'est pas de la sorte attendue est dit, pas corrigé.
        let attendu = if *nom == ".gnupg" {
            Attendu::Dossier
        } else {
            Attendu::Fichier
        };
        match geste_du_compte(maison, Path::new(nom), attendu) {
            Ok(geste) => {
                exposes.push(format!("~/{nom}"));
                commandes.push(format!(
                    "chmod {} ~/{nom}",
                    if attendu == Attendu::Dossier { "700" } else { "600" }
                ));
                gestes.push(geste);
            }
            Err(r) => {
                a_travers.push(format!("~/{nom}"));
                raisons.push(r.to_string());
            }
        }
    }
    let mut constats = Vec::new();
    if !exposes.is_empty() {
        let cmds: Vec<&str> = commandes.iter().map(String::as_str).collect();
        constats.push(
            alerte(
                "Fichiers secrets",
                Niveau::Eleve,
                trf!(
                    "Lisible(s) par d'autres comptes : {} (mots de passe ou jetons d'accès).",
                    "Readable by other accounts: {} (passwords or access tokens).",
                    exposes.join(", ")
                ),
            )
            .corriger(
                tr!("Réserver ces fichiers à vous seul", "Restrict these files to you only"),
                &cmds,
            )
            .annulable(gestes)
            .du_compte()
            // L'ensemble des fichiers exposés, noms fixes de `SECRETS` : un choix accepté pour l'un ne tait pas un
            // nouveau venu, et l'aperçu de la fenêtre retrouve ce constat par sa clé.
            .avec_objet(crate::modele::Objet::de("chemins", &exposes.join(","))),
        );
    }
    if !a_travers.is_empty() {
        let message = trf!(
            "Lisible(s) par d'autres comptes : {} (mots de passe ou jetons d'accès).",
            "Readable by other accounts: {} (passwords or access tokens).",
            a_travers.join(", ")
        );
        constats.push(
            alerte(
                "Fichiers secrets",
                Niveau::Eleve,
                super::sans_correction_du_compte(&message, &raisons.join(" ; ")),
            )
            // Pas l'objet des fichiers corrigeables : un choix accepté pour ~/.netrc ordinaire ne tait pas ~/.netrc
            // devenu un lien.
            .avec_objet(crate::modele::Objet::de("liens", &a_travers.join(","))),
        );
    }
    // Le dossier personnel lui-même : ouvert en lecture, il laisse voir tous tes fichiers aux autres comptes.
    if std::fs::metadata(maison).is_ok_and(|m| m.permissions().mode() & 0o007 != 0) {
        constats.push(match geste_du_compte(maison, Path::new(""), Attendu::Dossier) {
            Ok(geste) => alerte("Fichiers secrets", Niveau::Info, dossier_ouvert)
                .corriger(
                    tr!(
                        "Fermer votre dossier personnel aux autres comptes",
                        "Close your home folder to the other accounts"
                    ),
                    &["chmod 750 ~"],
                )
                .annulable(vec![geste])
                .du_compte()
                .avec_objet(crate::modele::Objet::de("chemin", "~")),
            Err(r) => alerte(
                "Fichiers secrets",
                Niveau::Info,
                super::sans_correction_du_compte(dossier_ouvert, &r.to_string()),
            )
            .avec_objet(crate::modele::Objet::de("lien", "~")),
        });
    }
    if constats.is_empty() {
        constats.push(ok(
            "Fichiers secrets",
            tr!(
                "Fichiers de mots de passe et de jetons protégés.",
                "Password and token files are protected."
            ),
        ));
    }
    constats
}

/// Règles « sudo sans mot de passe » : (règles qui donnent tout, règles limitées à des commandes précises). Une règle
/// « (cible) NOPASSWD: ALL » suivie plus bas de « (cible) ALL » ou « (cible) PASSWD: ALL », la même cible écrite à
/// l'identique, ne compte plus : sudo applique la dernière règle qui correspond (c'est ainsi que Défense corrige).
pub(crate) fn regles_nopasswd(liste: &str) -> (Vec<String>, usize) {
    let lignes: Vec<&str> = liste.lines().map(str::trim).collect();
    let mut totales = Vec::new();
    let mut limitees = 0usize;
    for (i, l) in lignes.iter().enumerate().filter(|(_, l)| l.contains("NOPASSWD:")) {
        let commandes = l.split_once("NOPASSWD:").map_or("", |(_, c)| c).trim();
        if commandes == "ALL" || commandes.starts_with("ALL,") {
            let reprise = (commandes == "ALL")
                .then(|| l.strip_prefix('(').and_then(|r| r.split_once(") NOPASSWD:")))
                .flatten()
                .is_some_and(|(cible, _)| {
                    let (tout, passwd) = (format!("({cible}) ALL"), format!("({cible}) PASSWD: ALL"));
                    lignes
                        .iter()
                        .skip(i.saturating_add(1))
                        .any(|m| *m == tout || *m == passwd)
                });
            if !reprise {
                totales.push((*l).to_string());
            }
        } else {
            limitees = limitees.saturating_add(1);
        }
    }
    (totales, limitees)
}

/// sudo sans mot de passe. `tout_permis` : le texte de l'alerte quand une règle donne toutes les commandes (il dit ce
/// que risque ce système).
/// Réglages par défaut de sudo qui valent pour ce compte (« Matching Defaults entries », première section de
/// `sudo -l`) : (sudo ne demande jamais le mot de passe, délai de mémorisation en minutes s'il est donné).
pub(crate) fn defauts_sudo(liste: &str) -> (bool, Option<f64>) {
    let mut sans_mot_de_passe = false;
    let mut delai = None;
    let mut lignes = liste
        .lines()
        .skip_while(|l| !l.starts_with("Matching Defaults entries"));
    lignes.next();
    for ligne in lignes.take_while(|l| !l.trim().is_empty()) {
        // Une longue liste peut être coupée en fin de ligne après une virgule : elle est retirée.
        for reglage in ligne.split(", ").map(|r| r.trim().trim_end_matches(',')) {
            if reglage == "!authenticate" {
                sans_mot_de_passe = true;
            } else if reglage == "authenticate" {
                sans_mot_de_passe = false;
            } else if let Some(v) = reglage.strip_prefix("timestamp_timeout=") {
                delai = v.trim_matches('"').parse::<f64>().ok().or(delai);
            }
        }
    }
    (sans_mot_de_passe, delai)
}

pub(super) fn sudo_sans_mot_de_passe(tout_permis: &str) -> Vec<Constat> {
    // -n : jamais de demande de mot de passe. Sans règle NOPASSWD (ni sudo récent), la liste est refusée : rien à dire.
    // sudo par son chemin : un faux sudo du compte répondrait ce qu'il veut.
    let Some(liste) = crate::commande::outil_systeme("sudo").and_then(|s| sortie(&s.to_string_lossy(), &["-n", "-l"]))
    else {
        return Vec::new();
    };
    let constats = juger_sudo(&liste, tout_permis);
    #[cfg(target_os = "linux")]
    let constats = {
        let moi = crate::socle::personnel::compte_de(crate::socle::uid()).and_then(|(n, _)| n.into_string().ok());
        durcir_sudo(constats, &liste, moi.as_deref())
    };
    constats
}

/// Linux (D7a) : le premier constat de sudo à corriger reçoit le geste qui pose le complément de sudo de ce compte
/// (`Defense::DurcirSudo`, validé par visudo avant d'être posé, défait par sa note) : un seul geste, qui couvre tous
/// les réglages signalés ; les suivants gardent leur conseil (le complément ne se pose qu'une fois). Seulement si
/// chaque règle sans mot de passe a la forme simple que l'enfant root sait corriger, et pour un compte nommé (pas
/// root, pas de point : sudo ne lirait pas son complément). Sinon, tout reste à la main.
#[cfg(target_os = "linux")]
pub(super) fn durcir_sudo(mut constats: Vec<Constat>, liste: &str, moi: Option<&str>) -> Vec<Constat> {
    use super::gestes_unix::{Defense, NomCompte};
    let Some(nom) = moi
        .filter(|m| *m != "root" && !m.contains('.'))
        .and_then(NomCompte::nouveau)
    else {
        return constats;
    };
    if !super::defense_eleve::problemes_sudo(liste).is_ok_and(|p| p.a_corriger()) {
        return constats;
    }
    if let Some(c) = constats
        .iter_mut()
        .find(|c| c.categorie == "Sudo" && c.probleme.is_some() && c.correctif.is_some())
    {
        *c = super::defense::corriger(
            c.clone(),
            tr!(
                "Faire redemander votre mot de passe (un complément de sudo, dans /etc/sudoers.d, vérifié par visudo avant d'être posé ; il couvre tous les réglages signalés ici)",
                "Ask for your password again (an addition to sudo, in /etc/sudoers.d, checked by visudo before it is put in place; it covers every setting reported here)"
            ),
            &[Defense::DurcirSudo(nom)],
        );
    }
    constats
}

/// Le jugement de la sortie de `sudo -n -l` : séparé de sa lecture pour que le corpus de détection l'exerce.
pub(super) fn juger_sudo(liste: &str, tout_permis: &str) -> Vec<Constat> {
    let (totales, limitees) = regles_nopasswd(liste);
    let (jamais_demande, delai) = defauts_sudo(liste);
    let mut constats = Vec::new();
    if jamais_demande {
        constats.push(
            alerte(
                "Sudo",
                Niveau::Eleve,
                tr!(
                    "sudo ne demande jamais le mot de passe (« Defaults !authenticate ») : n'importe quel programme lancé par vous peut devenir root.",
                    "sudo never asks for the password (“Defaults !authenticate”): any program you run can become root."
                ),
            )
            .manuel(
                tr!(
                    "Retirer « !authenticate » des Defaults dans /etc/sudoers ou /etc/sudoers.d (toujours avec sudo visudo)",
                    "Remove “!authenticate” from the Defaults in /etc/sudoers or /etc/sudoers.d (always with sudo visudo)"
                ),
                &["sudo visudo"],
            ),
        );
    } else if let Some(minutes) = delai.filter(|&m| m < 0.0 || m > 60.0) {
        let message = if minutes < 0.0 {
            tr!(
                "sudo ne redemande jamais le mot de passe une fois tapé (« timestamp_timeout » négatif) : tout programme lancé ensuite dans ce terminal peut devenir root sans rien demander.",
                "sudo never asks for the password again once typed (negative “timestamp_timeout”): any program started later in that terminal can become root without asking."
            )
            .to_string()
        } else {
            trf!(
                "sudo garde le mot de passe {} minutes (« timestamp_timeout ») : un programme lancé pendant ce temps devient root sans rien demander.",
                "sudo keeps the password for {} minutes (“timestamp_timeout”): a program started during that time becomes root without asking.",
                minutes.round()
            )
        };
        constats.push(
            alerte("Sudo", if minutes < 0.0 { Niveau::Moyen } else { Niveau::Info }, message).manuel(
                tr!(
                    "Remettre le délai de sudo à 5 minutes, ou retirer « timestamp_timeout » (toujours avec sudo visudo)",
                    "Set sudo's delay back to 5 minutes, or remove “timestamp_timeout” (always with sudo visudo)"
                ),
                &["sudo visudo"],
            ),
        );
    }
    if !totales.is_empty() {
        constats.push(alerte("Sudo", Niveau::Eleve, tout_permis).manuel(
            tr!(
                "Retirer « NOPASSWD: » de cette règle dans /etc/sudoers.d (toujours avec sudo visudo, jamais à la main)",
                "Remove “NOPASSWD:” from this rule in /etc/sudoers.d (always with sudo visudo, never by hand)"
            ),
            &["sudo visudo"],
        ));
    } else if jamais_demande {
        // Déjà dit plus haut : pas de « demande toujours le mot de passe ».
    } else if limitees > 0 {
        constats.push(ok(
            "Sudo",
            trf!(
                "{limitees} règle(s) sudo sans mot de passe, limitée(s) à des commandes précises.",
                "{limitees} passwordless sudo rule(s), limited to specific commands."
            ),
        ));
    } else {
        constats.push(ok(
            "Sudo",
            tr!(
                "sudo demande toujours le mot de passe.",
                "sudo always asks for the password."
            ),
        ));
    }
    constats
}

// Lecture de sshd_config, la même sous Windows (OpenSSH de Microsoft) : `machine::sshd`.
pub(super) use super::sshd::partie_globale_sshd;

/// Configuration de sshd qui vaut pour toutes les connexions ; `None` si elle est réservée à root.
pub(super) fn configuration_sshd() -> Option<String> {
    // sshd garde la première valeur trouvée ; sur Arch, les fichiers .d sont inclus avant le reste.
    let mut fichiers: Vec<std::path::PathBuf> = std::fs::read_dir("/etc/ssh/sshd_config.d")
        .into_iter()
        .flatten()
        .flatten()
        .map(|f| f.path())
        .collect();
    fichiers.sort();
    fichiers.push("/etc/ssh/sshd_config".into());
    let mut conf = String::new();
    for f in &fichiers {
        match std::fs::read_to_string(f) {
            Ok(t) => conf += &partie_globale_sshd(&t),
            // Fedora et RHEL réservent la configuration à root : un fichier vide passerait pour les valeurs par
            // défaut (mot de passe permis), une fausse alerte.
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return None,
            Err(_) => {}
        }
    }
    Some(conf)
}

/// Un dossier de commandes tel qu'il est lu : son chemin réel, ses droits, son propriétaire, et si root y cherche ses
/// commandes.
pub(super) struct DossierDeCommandes {
    pub chemin: String,
    pub mode: u32,
    pub proprietaire: u32,
    pub de_root: bool,
}

/// Les dossiers de commandes modifiables par d'autres comptes. Quiconque peut écrire dans l'un d'eux y dépose un
/// programme du nom d'une vraie commande (« ls », « sudo ») : il tourne à la place de l'autre, avec les droits de qui
/// la tape, root compris après sudo. Un dossier ouvert à tous est fautif où qu'il soit ; un dossier de root qui
/// appartient à un autre compte que root l'est aussi. Le bit « sticky » (/tmp) n'y change rien : il empêche de
/// supprimer les fichiers des autres, pas d'en ajouter. Ailleurs, un dossier à un autre compte est voulu (Homebrew
/// sous Linux) : rien à dire.
pub(super) fn juger_dossiers_de_commandes(dossiers: &[DossierDeCommandes]) -> Option<Constat> {
    let ouverts: Vec<&DossierDeCommandes> = dossiers.iter().filter(|d| d.mode & 0o002 != 0).collect();
    let a_d_autres: Vec<&DossierDeCommandes> = dossiers
        .iter()
        .filter(|d| d.de_root && d.proprietaire != 0 && d.mode & 0o002 == 0)
        .collect();
    if ouverts.is_empty() && a_d_autres.is_empty() {
        return None;
    }
    let niveau = if ouverts.iter().chain(&a_d_autres).any(|d| d.de_root) {
        Niveau::Eleve
    } else {
        Niveau::Moyen
    };
    let noms: Vec<&str> = ouverts.iter().chain(&a_d_autres).map(|d| d.chemin.as_str()).collect();
    let constat = alerte(
        "Privilèges",
        niveau,
        trf!(
            "D'autres comptes peuvent déposer des programmes dans {} : une fausse commande y prendrait la place de la vraie, avec vos droits, ou ceux de root après sudo.",
            "Other accounts can drop programs into {}: a fake command there would take the real one's place, with your rights, or root's after sudo.",
            noms.join(", ")
        ),
    );
    // Un dossier au bit « sticky » est un dossier temporaire (/tmp mis dans le PATH) : lui retirer l'écriture
    // casserait tous les programmes ; c'est de le sortir du PATH qu'il s'agit.
    let temporaires: Vec<&str> = ouverts
        .iter()
        .filter(|d| d.mode & 0o1000 != 0 && !d.de_root)
        .map(|d| d.chemin.as_str())
        .collect();
    if !temporaires.is_empty() {
        return Some(constat.manuel(
            trf!(
                "Sortir {} du PATH (fichier de démarrage du shell : ~/.bashrc, ~/.profile, /etc/profile.d) ; pour un autre dossier, sudo chmod o-w <dossier>",
                "Take {} out of PATH (shell startup file: ~/.bashrc, ~/.profile, /etc/profile.d); for another folder, sudo chmod o-w <folder>",
                temporaires.join(", ")
            ),
            &[],
        ));
    }
    Some(if a_d_autres.is_empty() {
        // Retirer l'écriture aux autres se défait exactement (chmod o+w) et ne gêne pas un dossier de commandes : rien
        // ne doit pouvoir y écrire sans en être propriétaire.
        let commandes: Vec<String> = ouverts
            .iter()
            .map(|d| format!("sudo chmod o-w {}", crate::commande::sh_chaine(&d.chemin)))
            .collect();
        constat.corriger(
            tr!(
                "Retirer l'écriture aux autres comptes (chmod o-w)",
                "Remove write access for other accounts (chmod o-w)"
            ),
            &commandes,
        )
    } else {
        // Rendre un dossier à root peut casser l'outil qui l'a pris : à décider soi-même.
        constat.manuel(
            tr!(
                "Rendre ces dossiers à root (sudo chown root:root <dossier> ; sudo chmod 755 <dossier>), après avoir vérifié quel outil les a changés",
                "Give these folders back to root (sudo chown root:root <folder>; sudo chmod 755 <folder>), after checking which tool changed them"
            ),
            &[],
        )
    })
}

/// Les dossiers de root (`racines`), puis ceux du PATH de la personne, sous leur chemin réel (« /bin » mène souvent à
/// « /usr/bin ») et sans doublon. Un dossier absent est sauté ; le dossier personnel aussi, qui est à la personne.
pub(super) fn dossiers_de_commandes(racines: &[&str], maison: &Path) -> Option<Constat> {
    use std::os::unix::fs::MetadataExt;
    let maison = std::fs::canonicalize(maison).ok();
    let path = std::env::var("PATH").unwrap_or_default();
    let mut vus: Vec<DossierDeCommandes> = Vec::new();
    let candidats = racines
        .iter()
        .map(|d| (*d, true))
        .chain(path.split(':').filter(|d| d.starts_with('/')).map(|d| (d, false)));
    for (dossier, de_root) in candidats {
        let Ok(reel) = std::fs::canonicalize(dossier) else {
            continue;
        };
        if maison.as_ref().is_some_and(|m| reel.starts_with(m)) {
            continue;
        }
        let Ok(meta) = std::fs::metadata(&reel) else { continue };
        let chemin = reel.to_string_lossy().into_owned();
        match vus.iter_mut().find(|d| d.chemin == chemin) {
            Some(deja) => deja.de_root |= de_root,
            None => vus.push(DossierDeCommandes {
                chemin,
                mode: meta.mode(),
                proprietaire: meta.uid(),
                de_root,
            }),
        }
    }
    let constat = juger_dossiers_de_commandes(&vus);
    #[cfg(target_os = "linux")]
    let constat = constat.map(|c| rendre_a_root(c, &vus));
    constat
}

/// Linux : les dossiers de root pris par un autre compte (la correction à la main de `juger_dossiers_de_commandes`)
/// rendus à root par un geste de défense chacun, propriétaire et mode notés, que Défaire remet. Tous ou aucun : un
/// dossier fautif hors des dossiers de root (`DOSSIERS_DE_ROOT`, chemin réel), et tout reste à la main ; sans
/// dossier pris (seulement ouverts à tous), la correction par chmod o-w reste celle du bilan.
#[cfg(target_os = "linux")]
pub(super) fn rendre_a_root(constat: Constat, dossiers: &[DossierDeCommandes]) -> Constat {
    use super::gestes_unix::{CheminDesigne, Defense};
    let fautifs: Vec<&DossierDeCommandes> = dossiers
        .iter()
        .filter(|d| d.mode & 0o002 != 0 || (d.de_root && d.proprietaire != 0))
        .collect();
    if !fautifs
        .iter()
        .any(|d| d.de_root && d.proprietaire != 0 && d.mode & 0o002 == 0)
    {
        return constat;
    }
    let gestes = super::defense::tous(fautifs, |d| {
        if !super::linux::DOSSIERS_DE_ROOT.contains(&d.chemin.as_str()) {
            return None;
        }
        CheminDesigne::nouveau(d.chemin.as_bytes()).map(Defense::RendreDossierARoot)
    });
    super::defense::corriger(
        constat,
        tr!(
            "Rendre ces dossiers à root (propriétaire root, sans écriture du groupe ni des autres ; chacun demandé à part). L'outil qui les a pris peut cesser de s'y mettre à jour : Défaire les lui rend",
            "Give these folders back to root (owner root, no write access for the group or others; each asked separately). The tool that took them may stop updating there: Undo gives them back to it"
        ),
        &gestes,
    )
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests_dossiers_de_commandes {
    use super::*;

    #[test]
    fn dossiers_de_commandes_ouverts_a_d_autres() {
        let d = |chemin: &str, mode: u32, proprietaire: u32, de_root: bool| DossierDeCommandes {
            chemin: chemin.to_string(),
            mode: 0o40000 | mode,
            proprietaire,
            de_root,
        };
        let sains = [d("/usr/bin", 0o755, 0, true), d("/opt/outil/bin", 0o755, 1001, false)];
        assert!(juger_dossiers_de_commandes(&sains).is_none());
        // Ouvert à tous, même avec le bit sticky : corrigé par chmod o-w, le nom protégé.
        let ouvert = juger_dossiers_de_commandes(&[d("/usr/local/bin", 0o1777, 0, true)]).unwrap();
        assert_eq!(ouvert.probleme, Some(Niveau::Eleve));
        assert_eq!(ouvert.correctif.unwrap().commandes, ["sudo chmod o-w '/usr/local/bin'"]);
        let a_moi = juger_dossiers_de_commandes(&[d("/opt/l'outil/bin", 0o777, 1000, false)]).unwrap();
        assert_eq!(a_moi.probleme, Some(Niveau::Moyen));
        assert_eq!(
            a_moi.correctif.unwrap().commandes,
            ["sudo chmod o-w '/opt/l'\\''outil/bin'"]
        );
        // Un dossier de root à un autre compte : à décider soi-même.
        let pris = juger_dossiers_de_commandes(&[d("/usr/local/bin", 0o755, 1000, true)]).unwrap();
        assert!(pris.probleme == Some(Niveau::Eleve) && !pris.correctif.unwrap().automatique);
        // /tmp dans le PATH : ouvert à tous mais temporaire, jamais chmod : à sortir du PATH.
        let tmp = juger_dossiers_de_commandes(&[d("/tmp", 0o1777, 0, false)]).unwrap();
        assert!(!tmp.correctif.unwrap().automatique);
    }

    /// D7a : un dossier de root pris par un autre compte est rendu à root par un geste ; tous ou aucun.
    #[cfg(target_os = "linux")]
    #[test]
    fn dossiers_rendus_a_root_par_geste() {
        use crate::machine::gestes_unix::{Defense, GesteUnix, analyser};
        let d = |chemin: &str, mode: u32, proprietaire: u32, de_root: bool| DossierDeCommandes {
            chemin: chemin.to_string(),
            mode: 0o40000 | mode,
            proprietaire,
            de_root,
        };
        let juger = |v: &[DossierDeCommandes]| rendre_a_root(juger_dossiers_de_commandes(v).unwrap(), v);
        let v = [
            d("/usr/local/bin", 0o755, 1000, true),
            d("/usr/local/sbin", 0o777, 0, true),
        ];
        let k = juger(&v).correctif.unwrap();
        assert!(k.automatique);
        let chemins: Vec<Vec<u8>> = k
            .commandes
            .iter()
            .map(|l| match analyser(l) {
                Some(GesteUnix::Defense(Defense::RendreDossierARoot(c), _)) => c.octets().to_vec(),
                _ => panic!("geste attendu : {l}"),
            })
            .collect();
        assert_eq!(chemins, [b"/usr/local/bin".to_vec(), b"/usr/local/sbin".to_vec()]);
        assert!(matches!(k.defaire, crate::machine::Defaire::Gestes(ref g) if g.len() == 2));
        // Mêlé à un dossier qui n'est pas de root : tout à la main.
        let v = [
            d("/usr/local/bin", 0o755, 1000, true),
            d("/opt/outil/bin", 0o777, 1000, false),
        ];
        assert!(!juger(&v).correctif.unwrap().automatique);
        // Un chemin de root qui n'est pas dans la liste (forgé, ou réel ailleurs) : à la main.
        let v = [d("/usr/local/bin/../../tmp", 0o755, 1000, true)];
        assert!(!juger(&v).correctif.unwrap().automatique);
        // Seulement ouvert à tous : la correction chmod o-w du bilan reste.
        let v = [d("/usr/local/bin", 0o777, 0, true)];
        assert_eq!(
            juger(&v).correctif.unwrap().commandes,
            ["sudo chmod o-w '/usr/local/bin'"]
        );
        // /tmp dans le PATH avec un dossier pris : à la main.
        let v = [d("/usr/local/bin", 0o755, 1000, true), d("/tmp", 0o1777, 0, false)];
        assert!(!juger(&v).correctif.unwrap().automatique);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests_durcir_sudo {
    use super::*;
    use crate::machine::gestes_unix::{Defense, GesteUnix, analyser};

    const LISTE: &str = "Matching Defaults entries for alice on salon:\n    env_reset, !authenticate\n\nUser alice may run the following commands on salon:\n    (ALL : ALL) NOPASSWD: ALL\n";

    /// D7a : un seul geste, sur le premier constat à corriger ; les suivants gardent leur conseil.
    #[test]
    fn un_seul_complement_pour_tout() {
        let c = durcir_sudo(juger_sudo(LISTE, "tout"), LISTE, Some("alice"));
        let auto: Vec<&Constat> = c
            .iter()
            .filter(|c| c.correctif.as_ref().is_some_and(|k| k.automatique))
            .collect();
        let [premier] = auto.as_slice() else {
            panic!("un seul constat corrigé par un geste")
        };
        let k = premier.correctif.as_ref().unwrap();
        let [ligne] = k.commandes.as_slice() else {
            panic!("une ligne")
        };
        assert!(matches!(
            analyser(ligne),
            Some(GesteUnix::Defense(Defense::DurcirSudo(n), _)) if n.as_str() == "alice"
        ));
        assert!(c.iter().filter(|c| c.probleme.is_some()).count() >= 2);
    }

    /// Root, un nom à point (sudo sauterait le complément), un nom forgé, ou une règle que l'enfant ne sait pas
    /// corriger : tout reste à la main.
    #[test]
    fn a_la_main_sinon() {
        for moi in [None, Some("root"), Some("alice.b"), Some("al ice")] {
            let c = durcir_sudo(juger_sudo(LISTE, "tout"), LISTE, moi);
            assert!(
                c.iter().all(|c| c.correctif.as_ref().is_none_or(|k| !k.automatique)),
                "{moi:?}"
            );
        }
        let piege = "User alice may run the following commands on salon:\n    (ALL : ALL, `reboot`) NOPASSWD: ALL\n";
        let c = durcir_sudo(juger_sudo(piege, "tout"), piege, Some("alice"));
        assert!(c.iter().all(|c| c.correctif.as_ref().is_none_or(|k| !k.automatique)));
        // Rien à corriger : rien d'ajouté.
        let sain = "User alice may run the following commands on salon:\n    (ALL : ALL) ALL\n";
        let c = durcir_sudo(juger_sudo(sain, "tout"), sain, Some("alice"));
        assert!(c.iter().all(|c| c.correctif.is_none()));
    }
}

/// Vérification de Fable, V1 : à travers un lien, ce qui est montré (« ~/.netrc ») n'est pas ce qu'un chmod
/// changerait (la cible). Un chemin qui passe par un lien, ou qui n'est ni un fichier ni un dossier, est dit sans
/// correction du compte.
#[cfg(test)]
mod tests_liens {
    use super::*;

    fn mode(chemin: &Path, mode: u32) {
        std::fs::set_permissions(chemin, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn un_chemin_ordinaire_seulement_se_corrige_par_le_compte() {
        let maison = crate::essais::Jetable::nouveau("liens-maison");
        let ailleurs = crate::essais::Jetable::nouveau("liens-ailleurs");
        std::fs::create_dir_all(maison.join(".ssh")).unwrap();
        std::fs::write(maison.join(".ssh/id_essai"), "clé inventée\n").unwrap();
        std::fs::write(ailleurs.join("cible"), "x\n").unwrap();
        std::os::unix::fs::symlink(ailleurs.join("cible"), maison.join(".ssh/id_lien")).unwrap();
        std::os::unix::fs::symlink(&*ailleurs, maison.join("d")).unwrap();
        crate::essais::tube_nomme(&maison.join("tube")).unwrap();
        assert_eq!(hors_correction(&maison, Path::new(""), Attendu::Dossier), None);
        assert_eq!(hors_correction(&maison, Path::new(".ssh"), Attendu::Dossier), None);
        assert_eq!(
            hors_correction(&maison, Path::new(".ssh/id_essai"), Attendu::Fichier),
            None
        );
        let lien = hors_correction(&maison, Path::new(".ssh/id_lien"), Attendu::Fichier).unwrap();
        assert!(lien.contains("~/.ssh/id_lien") && lien.contains("cible"), "{lien}");
        // Un dossier du chemin qui est un lien : la fin, ordinaire, n'y change rien.
        let milieu = hors_correction(&maison, Path::new("d/cible"), Attendu::Fichier).unwrap();
        assert!(milieu.starts_with("~/d "), "{milieu}");
        for faux in ["tube", ".ssh/id_essai/x", "absent", "../x", "/etc/passwd"] {
            assert!(
                hors_correction(&maison, Path::new(faux), Attendu::Fichier).is_some(),
                "{faux}"
            );
        }
        // Le dossier personnel lui-même, un lien.
        let maison_lien = crate::essais::Jetable::nouveau("liens-maison-lien");
        let m = maison_lien.join("maison");
        std::os::unix::fs::symlink(&*maison, &m).unwrap();
        assert!(hors_correction(&m, Path::new(".ssh"), Attendu::Dossier).is_some());
    }

    /// Vérification de Fable n° 2, liens L1, L2, L4, L6 : la sorte attendue au bout (un dossier « id_… » ne reçoit pas
    /// de chmod 600, un ~/.ssh devenu fichier pas de chmod 700), un nom qui n'est pas UTF-8, un lien physique, un
    /// autre propriétaire, un HOME écrit avec « / » ou « /. » à la fin.
    #[test]
    fn la_correction_du_compte_vise_la_bonne_sorte_et_un_nom_lisible() {
        use std::os::unix::ffi::OsStrExt;
        let maison = crate::essais::Jetable::nouveau("liens-sorte");
        let ailleurs = crate::essais::Jetable::nouveau("liens-sorte-ailleurs");
        std::fs::create_dir_all(maison.join(".ssh/id_dossier")).unwrap();
        std::fs::write(maison.join(".ssh/id_essai"), "clé inventée\n").unwrap();
        std::fs::write(maison.join(".netrc"), "machine exemple.invalid login alice\n").unwrap();
        // L2, L6 : la sorte attendue.
        let dossier = hors_correction(&maison, Path::new(".ssh/id_dossier"), Attendu::Fichier).unwrap();
        assert!(dossier.contains("~/.ssh/id_dossier"), "{dossier}");
        assert!(hors_correction(&maison, Path::new(".ssh/id_essai"), Attendu::Dossier).is_some());
        assert!(hors_correction(&maison, Path::new(".netrc"), Attendu::Dossier).is_some());
        assert_eq!(
            hors_correction(&maison, Path::new(".ssh/id_dossier"), Attendu::Dossier),
            None
        );
        // L1 : un nom qui n'est pas UTF-8, et son sosie au caractère de remplacement (un lien) ; ni l'un ni l'autre ne
        // donne de geste, et celui du nom invalide n'est jamais écrit avec perte.
        let invalide = std::ffi::OsStr::from_bytes(b"id_\xff");
        std::fs::write(maison.join(".ssh").join(invalide), "clé inventée\n").unwrap();
        std::os::unix::fs::symlink(&*ailleurs, maison.join(".ssh/id_\u{FFFD}")).unwrap();
        let relatif = Path::new(".ssh").join(invalide);
        let r = hors_correction(&maison, &relatif, Attendu::Fichier).unwrap();
        assert!(r.contains("UTF-8"), "{r}");
        assert!(geste_du_compte(&maison, &relatif, Attendu::Fichier).is_err());
        assert!(crate::optimiser::Geste::droits(&maison.join(&relatif)).is_none());
        assert!(geste_du_compte(&maison, Path::new(".ssh/id_\u{FFFD}"), Attendu::Fichier).is_err());
        // L6 : une clé qui a un second nom ailleurs.
        std::fs::hard_link(maison.join(".ssh/id_essai"), ailleurs.join("double")).unwrap();
        let double = hors_correction(&maison, Path::new(".ssh/id_essai"), Attendu::Fichier).unwrap();
        assert!(double.contains("lien physique"), "{double}");
        std::fs::remove_file(ailleurs.join("double")).unwrap();
        assert_eq!(
            hors_correction(&maison, Path::new(".ssh/id_essai"), Attendu::Fichier),
            None
        );
        // Un autre propriétaire : la racine n'est à personne d'ici (root, ou personne sous un espace de noms).
        let autre = hors_correction(Path::new("/"), Path::new(""), Attendu::Dossier).unwrap();
        assert!(autre.contains("autre compte"), "{autre}");
        // L4 : le dossier personnel lien, écrit avec « / » ou « /. » à la fin, reste vu comme un lien ; « .. » et un
        // chemin relatif sont refusés.
        let parent = crate::essais::Jetable::nouveau("liens-sorte-parent");
        let m = parent.join("maison");
        std::os::unix::fs::symlink(&*maison, &m).unwrap();
        let texte = m.to_str().unwrap();
        for forme in [
            texte.to_string(),
            format!("{texte}/"),
            format!("{texte}/."),
            format!("{texte}/./"),
        ] {
            let r = hors_correction(Path::new(&forme), Path::new(".ssh"), Attendu::Dossier);
            assert!(r.as_deref().is_some_and(|r| r.starts_with("~ ")), "{forme} : {r:?}");
            assert!(
                geste_du_compte(Path::new(&forme), Path::new(""), Attendu::Dossier).is_err(),
                "{forme}"
            );
        }
        let vrai = maison.to_str().unwrap();
        for forme in [format!("{vrai}/"), format!("{vrai}/.")] {
            assert_eq!(
                hors_correction(Path::new(&forme), Path::new(".ssh"), Attendu::Dossier),
                None,
                "{forme}"
            );
        }
        for faux in [format!("{vrai}/.ssh/.."), "maison".to_string()] {
            assert!(
                hors_correction(Path::new(&faux), Path::new(""), Attendu::Dossier).is_some(),
                "{faux}"
            );
        }
        // Le geste suit le chemin simple : celui d'un HOME écrit avec « /. » est celui du HOME simple.
        assert_eq!(
            geste_du_compte(Path::new(&format!("{vrai}/.")), Path::new(".netrc"), Attendu::Fichier),
            Ok(crate::optimiser::Geste::droits(&maison.join(".netrc")).unwrap())
        );
    }

    #[test]
    fn un_secret_a_travers_un_lien_est_dit_sans_correction() {
        let maison = crate::essais::Jetable::nouveau("liens-secrets");
        let ailleurs = crate::essais::Jetable::nouveau("liens-secrets-cible");
        mode(&maison, 0o700);
        std::fs::write(maison.join(".netrc"), "machine exemple.invalid login alice\n").unwrap();
        mode(&maison.join(".netrc"), 0o644);
        std::fs::write(ailleurs.join("jetons"), "inventé\n").unwrap();
        mode(&ailleurs.join("jetons"), 0o644);
        std::os::unix::fs::symlink(ailleurs.join("jetons"), maison.join(".git-credentials")).unwrap();
        let constats = fichiers_secrets(&maison, "ouvert");
        let corrigeables: Vec<&Constat> = constats.iter().filter(|c| c.correctif.is_some()).collect();
        let messages: Vec<&str> = constats.iter().map(|c| c.message.as_str()).collect();
        assert_eq!(corrigeables.len(), 1, "{messages:?}");
        let c = corrigeables[0];
        assert!(c.message.contains("~/.netrc") && !c.message.contains(".git-credentials"));
        assert_eq!(c.correctif.as_ref().unwrap().commandes, ["chmod 600 ~/.netrc"]);
        let lie = constats
            .iter()
            .find(|c| c.message.contains("~/.git-credentials"))
            .expect("le lien n'est pas dit");
        assert!(lie.correctif.is_none() && lie.probleme == Some(Niveau::Eleve));
        assert!(lie.message.contains("jetons"), "{}", lie.message);
        assert_ne!(lie.objet, c.objet);
        assert!(
            [&lie.objet, &c.objet]
                .iter()
                .all(|o| **o != crate::modele::Objet::NonMigre)
        );
        // Le dossier personnel ouvert, mais à travers un lien : dit, sans correction.
        mode(&maison, 0o755);
        let parent = crate::essais::Jetable::nouveau("liens-secrets-parent");
        let m = parent.join("maison");
        std::os::unix::fs::symlink(&*maison, &m).unwrap();
        let ouvert = fichiers_secrets(&m, "ouvert");
        assert!(!ouvert.is_empty());
        assert!(ouvert.iter().all(|c| c.correctif.is_none()));
    }
}

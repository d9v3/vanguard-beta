//! Partages de fichiers ouverts à tout le monde : un dossier partagé sur le réseau sans mot de passe (invité, « Tout
//! le monde »), que n'importe quel appareil du réseau (un visiteur sur le Wi-Fi, un appareil infecté) peut lire, et
//! souvent modifier. Samba et NFS sous Linux, partages SMB sous Windows. Un partage
//! réservé à des comptes nommés n'est pas signalé : c'est l'accès sans mot de passe qui compte. La correction ferme
//! cet accès-là seulement ; les comptes nommés gardent le leur.

use super::{Constat, alerte, impossible, ok};
use crate::risk::Niveau;
use crate::{tr, trf};

const CAT: &str = "Partages de fichiers";

/// Ce qui tempère un partage ouvert : il n'est pas joignable sans mot de passe pour l'instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Nuance {
    Aucune,
    /// Le service de partage n'est pas lancé.
    ServiceArrete,
    /// Windows : « Tout le monde » désigne les comptes connus de l'ordinateur tant que le compte invité est désactivé.
    #[cfg_attr(not(windows), allow(dead_code))]
    InviteDesactive,
    /// Windows : l'état du compte invité n'a pas pu être lu. Rien n'est tempéré : une lecture qui
    /// n'a pas eu lieu ne vaut pas « invité désactivé ».
    #[cfg_attr(not(windows), allow(dead_code))]
    InviteNonLu,
}

/// Un partage ouvert sans mot de passe.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Partage {
    nom: String,
    chemin: String,
    /// À qui : « l'invité », « Tout le monde »…
    a_qui: String,
    /// `None` : pas su.
    ecriture: Option<bool>,
    nuance: Nuance,
    /// Commandes qui ferment l'accès sans mot de passe ; vides : à faire soi-même.
    fermeture: Vec<String>,
}

/// Un partage dont les droits n'ont pas pu être lus : dit, jamais compté comme sain.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Illisible {
    nom: String,
}

fn un_cran_plus_bas(niveau: Niveau) -> Niveau {
    match niveau {
        Niveau::Critique => Niveau::Eleve,
        Niveau::Eleve => Niveau::Moyen,
        Niveau::Moyen | Niveau::Info => Niveau::Info,
    }
}

/// Les constats : un par partage ouvert (élevé en écriture, moyen en lecture, un cran plus bas si le service est arrêté
/// ou l'invité désactivé), un par partage illisible, un par dossier ou fichier de partages illisible, ou un seul « rien
/// d'ouvert ».
fn juger(partages: &[Partage], illisibles: &[Illisible], sources: &[String], service_vu_arrete: bool) -> Vec<Constat> {
    let montre = crate::ui::affichable;
    let mut constats: Vec<Constat> = partages
        .iter()
        .map(|p| {
            let niveau = match (p.ecriture, p.nuance) {
                (Some(false), Nuance::Aucune | Nuance::InviteNonLu) => Niveau::Moyen,
                (_, Nuance::Aucune | Nuance::InviteNonLu) => Niveau::Eleve,
                (Some(false), _) => un_cran_plus_bas(Niveau::Moyen),
                (_, _) => un_cran_plus_bas(Niveau::Eleve),
            };
            let acces = match p.ecriture {
                Some(true) => tr!("lire et modifier ces fichiers", "read and modify these files"),
                Some(false) => tr!("lire ces fichiers", "read these files"),
                None => tr!("y accéder", "access it"),
            };
            let nuance = match p.nuance {
                Nuance::Aucune => "",
                Nuance::ServiceArrete => tr!(
                    " Le service de partage n'est pas lancé : inoffensif tant qu'il le reste.",
                    " The sharing service is not running: harmless as long as it stays so."
                ),
                Nuance::InviteDesactive => tr!(
                    " Le compte invité est désactivé : il faut encore un compte de cet ordinateur ; l'activer ouvrirait ce partage sans mot de passe.",
                    " The guest account is disabled: an account of this computer is still required; enabling it would open this share without a password."
                ),
                Nuance::InviteNonLu => tr!(
                    " L'état du compte invité n'a pas pu être lu : compté comme activé.",
                    " The guest account state could not be read: counted as enabled."
                ),
            };
            let (nom, chemin, a_qui) = (montre(&p.nom), montre(&p.chemin), montre(&p.a_qui));
            let constat = alerte(
                CAT,
                niveau,
                trf!(
                    "Le partage « {nom} » ({chemin}) est ouvert à {a_qui} : n'importe quel appareil du réseau (un visiteur sur le Wi-Fi, un appareil infecté) peut {acces} sans mot de passe.{nuance}",
                    "Share “{nom}” ({chemin}) is open to {a_qui}: any device on the network (a visitor on the Wi-Fi, an infected device) can {acces} without a password.{nuance}"
                ),
            );
            if p.fermeture.is_empty() {
                constat.manuel(
                    trf!(
                        "Fermer l'accès de {a_qui} au partage « {nom} » dans les réglages du partage ; les comptes nommés gardent le leur",
                        "Close {a_qui}'s access to share “{nom}” in the sharing settings; named accounts keep theirs"
                    ),
                    &[],
                )
            } else {
                constat.corriger(
                    trf!(
                        "Fermer l'accès de {a_qui} au partage « {nom} » (les comptes nommés gardent le leur)",
                        "Close {a_qui}'s access to share “{nom}” (named accounts keep theirs)"
                    ),
                    &p.fermeture,
                )
            }
        })
        .collect();
    constats.extend(illisibles.iter().map(|i| {
        impossible(
            CAT,
            &trf!(
                "droits du partage « {} » illisibles",
                "share “{}” permissions unreadable",
                montre(&i.nom)
            ),
        )
    }));
    // Un dossier ou un fichier de partages illisible : ce qu'il décrit n'est pas vérifié, jamais « rien d'ouvert ».
    constats.extend(sources.iter().map(|raison| impossible(CAT, raison)));
    if constats.is_empty() {
        constats.push(ok(
            CAT,
            if service_vu_arrete {
                tr!(
                    "Aucun partage de fichiers ouvert à tout le monde ; le service de partage n'est pas lancé.",
                    "No file share open to everyone; the sharing service is not running."
                )
            } else {
                tr!(
                    "Aucun partage de fichiers ouvert à tout le monde.",
                    "No file share open to everyone."
                )
            },
        ));
    }
    constats
}

/// Au bilan.
pub(super) fn partages() -> Vec<Constat> {
    match systeme::relever() {
        Some(r) => juger(&r.partages, &r.illisibles, &r.sources_illisibles, r.service_vu_arrete),
        None => vec![impossible(
            CAT,
            tr!("PowerShell indisponible ou bloqué", "PowerShell unavailable or blocked"),
        )],
    }
}

struct Releve {
    partages: Vec<Partage>,
    illisibles: Vec<Illisible>,
    /// Les raisons des dossiers et fichiers de partages qui n'ont pas pu être lus en entier.
    sources_illisibles: Vec<String>,
    /// Aucun partage, et le service de partage est arrêté : la phrase « rien d'ouvert » le dit.
    service_vu_arrete: bool,
}

// ───────────────────────────── Samba et NFS (Linux) ─────────────────────────────

/// Les sections d'une configuration Samba (smb.conf, ou la sortie de `testparm -s`) : (nom, clés en minuscules).
#[cfg(any(target_os = "linux", test))]
fn sections_samba(config: &str) -> Vec<(String, Vec<(String, String)>)> {
    let mut sections: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for ligne in config.lines().map(str::trim) {
        if ligne.is_empty() || ligne.starts_with(['#', ';']) {
            continue;
        }
        if let Some(nom) = ligne.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            sections.push((nom.trim().to_string(), Vec::new()));
        } else if let Some((cle, valeur)) = ligne.split_once('=')
            && let Some(section) = sections.last_mut()
        {
            section.1.push((cle.trim().to_lowercase(), valeur.trim().to_string()));
        }
    }
    sections
}

#[cfg(any(target_os = "linux", test))]
fn oui_samba(valeur: &str) -> bool {
    matches!(valeur.to_lowercase().as_str(), "yes" | "true" | "1")
}

/// Pour sed : le texte pris au pied de la lettre dans une expression de base, avec « / » comme séparateur.
#[cfg(any(target_os = "linux", test))]
fn pour_sed(texte: &str) -> String {
    let mut s = String::with_capacity(texte.len());
    for c in texte.chars() {
        if matches!(c, '\\' | '.' | '*' | '[' | ']' | '^' | '$' | '/') {
            s.push('\\');
        }
        s.push(c);
    }
    s
}

/// Ferme l'accès invité d'une section de `fichier` : copie du fichier d'abord (une seule fois), puis « guest ok » et
/// « public » passés à « no » dans cette section seulement, puis Samba relit sa configuration.
#[cfg(any(target_os = "linux", test))]
fn fermeture_samba(nom: &str, fichier: &str) -> Vec<String> {
    use crate::commande::sh_chaine;
    let f = sh_chaine(fichier);
    let expression = format!(
        "/^[[:space:]]*\\[{}\\][[:space:]]*$/,/^[[:space:]]*\\[/ s/^\\([[:space:]]*\\(guest ok\\|public\\)[[:space:]]*=[[:space:]]*\\)\\(yes\\|true\\|1\\)[[:space:]]*$/\\1no/I",
        pour_sed(nom)
    );
    vec![
        format!("test -e {f}.avant-vanguard || sudo cp -p {f} {f}.avant-vanguard"),
        format!("sudo sed -i {} {f}", sh_chaine(&expression)),
        // Lot U3 : le rechargement reste une commande, après le fichier changé par sed ; geste avec lui (U4).
        "sudo smbcontrol all reload-config 2>/dev/null || sudo systemctl reload smb smbd 2>/dev/null || true"
            .to_string(),
    ]
}

/// Les partages Samba ouverts à l'invité : « guest ok » ou « public » dans la section, ou l'ancien
/// « security = share » qui ouvrait tout (plus de correction automatique dans ce cas). Les imprimantes ne comptent pas.
#[cfg(any(target_os = "linux", test))]
fn samba(config: &str, fichier: &str, nuance: Nuance) -> Vec<Partage> {
    let sections = sections_samba(config);
    let global_share = sections.iter().any(|(nom, cles)| {
        nom.eq_ignore_ascii_case("global")
            && cles
                .iter()
                .any(|(k, v)| k == "security" && v.eq_ignore_ascii_case("share"))
    });
    sections
        .iter()
        .filter(|(nom, _)| !["global", "printers", "print$"].contains(&nom.to_lowercase().as_str()))
        .filter_map(|(nom, cles)| {
            let valeur = |k: &str| cles.iter().rev().find(|(c, _)| c == k).map(|(_, v)| v.as_str());
            if valeur("available").is_some_and(|v| !oui_samba(v)) {
                return None;
            }
            let invite = valeur("guest ok").or_else(|| valeur("public")).is_some_and(oui_samba);
            if !global_share && !invite {
                return None;
            }
            // Samba : « read only = yes » par défaut ; « writable » et « writeable » sont son contraire.
            let ecriture = valeur("writable")
                .or_else(|| valeur("writeable"))
                .map(oui_samba)
                .or_else(|| valeur("read only").map(|v| !oui_samba(v)))
                .unwrap_or(false);
            let chemin = valeur("path").map_or_else(
                || {
                    if nom.eq_ignore_ascii_case("homes") {
                        "~".to_string()
                    } else {
                        String::new()
                    }
                },
                str::to_string,
            );
            Some(Partage {
                nom: nom.clone(),
                chemin,
                a_qui: tr!("l'invité (sans mot de passe)", "the guest (no password)").to_string(),
                ecriture: Some(ecriture),
                nuance,
                fermeture: if invite {
                    fermeture_samba(nom, fichier)
                } else {
                    Vec::new()
                },
            })
        })
        .collect()
}

/// Un client NFS qui désigne tout le monde : un nom vide (des options seules), un joker fait seulement de « * »,
/// « ? » et « . » avec au moins une « * », ou un réseau de masque nul sous n'importe quelle écriture (« /0 »,
/// « /0.0.0.0 », « ::/0 »…).
#[cfg(any(target_os = "linux", test))]
fn client_nfs_ouvert(hote: &str) -> bool {
    if hote.is_empty() || (hote.contains('*') && hote.chars().all(|c| matches!(c, '*' | '?' | '.'))) {
        return true;
    }
    hote.rsplit_once('/').is_some_and(|(_, masque)| {
        masque.parse::<u8>() == Ok(0)
            || masque.parse::<std::net::Ipv4Addr>().is_ok_and(|m| m.is_unspecified())
            || masque.parse::<std::net::Ipv6Addr>().is_ok_and(|m| m.is_unspecified())
    })
}

/// Les exports NFS ouverts à tous (`client_nfs_ouvert`, ou aucun client du tout). Une ligne qui finit par « \ » se
/// continue sur la suivante (exports(5)) : recollée avant d'être jugée, et sans commande de fermeture, puisque sed ne
/// commenterait qu'une de ses lignes. Des options par défaut (« -rw » juste après le chemin) valent pour les clients qui suivent ; les leurs
/// l'emportent ; sans « rw », l'export est en lecture seule.
#[cfg(any(target_os = "linux", test))]
fn nfs(exports: &str, fichier: &str, nuance: Nuance) -> Vec<Partage> {
    use crate::commande::sh_chaine;
    // (texte recollé, ligne du fichier quand l'export tient sur une seule)
    let mut exports_lus: Vec<(String, Option<&str>)> = Vec::new();
    let mut en_cours: Option<String> = None;
    for ligne in exports.lines() {
        let utile = ligne.split('#').next().unwrap_or("").trim_end();
        let (morceau, suite) = utile.strip_suffix('\\').map_or((utile, false), |m| (m, true));
        let recolle = en_cours.take();
        let seule = recolle.is_none() && !suite;
        let texte = recolle.map_or_else(|| morceau.to_string(), |avant| format!("{avant} {morceau}"));
        if suite {
            en_cours = Some(texte);
        } else {
            exports_lus.push((texte, seule.then_some(ligne)));
        }
    }
    exports_lus.extend(en_cours.map(|texte| (texte, None)));
    exports_lus
        .into_iter()
        .filter_map(|(texte, ligne)| {
            let utile = texte.trim();
            if utile.is_empty() {
                return None;
            }
            let (chemin, clients) = if let Some(reste) = utile.strip_prefix('"') {
                let (c, r) = reste.split_once('"')?;
                (c, r)
            } else {
                utile.split_once(char::is_whitespace).unwrap_or((utile, ""))
            };
            let (mut defaut, mut clients_vus) = ("", false);
            let ouvert = clients.split_whitespace().find(|c| {
                if let Some(options) = c.strip_prefix('-') {
                    defaut = options;
                    return false;
                }
                clients_vus = true;
                client_nfs_ouvert(c.split('(').next().unwrap_or(""))
            });
            // Aucun client (« /srv/a », « /srv/a -rw ») : le client par défaut, vide, que nfs-utils prend pour
            // tout le monde (de mémoire de son code ; nfs-utils n'a pas pu être essayé). S'il refusait plutôt la
            // ligne, l'erreur serait une fausse alerte sur un fichier à root, jamais un faux « sain ».
            let ouvert = match ouvert {
                Some(client) => client,
                None if !clients_vus => "",
                None => return None,
            };
            let options = ouvert.split_once('(').map_or("", |(_, o)| o.trim_end_matches(')'));
            let ecriture = defaut
                .split(',')
                .chain(options.split(','))
                .fold(false, |rw, o| match o.trim() {
                    "rw" => true,
                    "ro" => false,
                    _ => rw,
                });
            let f = sh_chaine(fichier);
            Some(Partage {
                nom: chemin.to_string(),
                chemin: chemin.to_string(),
                a_qui: tr!("tout le monde (NFS, « * »)", "everyone (NFS, “*”)").to_string(),
                ecriture: Some(ecriture),
                nuance,
                fermeture: ligne.map_or_else(Vec::new, |ligne| {
                    vec![
                        format!("test -e {f}.avant-vanguard || sudo cp -p {f} {f}.avant-vanguard"),
                        format!(
                            "sudo sed -i {} {f}",
                            sh_chaine(&format!("s/^{}$/# Vanguard : &/", pour_sed(ligne)))
                        ),
                        "sudo exportfs -ra".to_string(),
                    ]
                }),
            })
        })
        .collect()
}

/// L'emplacement habituel des partages d'utilisateur de Samba, lu même quand la configuration en donne un autre.
#[cfg(target_os = "linux")]
const USERSHARES_PAR_DEFAUT: &str = "/var/lib/samba/usershares";

/// Au plus autant d'entrées lues dans un dossier de partages : au-delà, la suite est dite non vérifiée.
#[cfg(target_os = "linux")]
const FICHIERS_MAX: usize = 256;

/// Taille maximale d'un fichier de partage d'utilisateur : il tient en quelques lignes.
#[cfg(target_os = "linux")]
const USERSHARE_MAX: u64 = 16 * 1024;

/// Taille maximale d'un fichier d'exports NFS.
#[cfg(target_os = "linux")]
const EXPORTS_MAX: u64 = 1024 * 1024;

/// Le dossier des partages d'utilisateur donné par « usershare path » de `[global]` (testparm l'écrit ainsi).
#[cfg(any(target_os = "linux", test))]
fn dossier_usershares(config: &str) -> Option<String> {
    sections_samba(config)
        .into_iter()
        .filter(|(nom, _)| nom.eq_ignore_ascii_case("global"))
        .flat_map(|(_, cles)| cles)
        .rfind(|(cle, valeur)| cle.split_whitespace().eq(["usershare", "path"]) && !valeur.is_empty())
        .map(|(_, valeur)| valeur)
}

/// Un compte qui laisse entrer sans mot de passe : Tout le monde (S-1-1-0), les connexions anonymes (S-1-5-7), les
/// Invités (S-1-5-32-546) ou le compte invité (…-501). Windows seulement : les usershares de Samba se jugent à
/// l'inverse (`compte_nomme`).
#[cfg(any(windows, test))]
fn sid_ouvert(sid: &str) -> bool {
    matches!(sid, "S-1-1-0" | "S-1-5-7" | "S-1-5-32-546") || (sid.starts_with("S-1-5-21-") && sid.ends_with("-501"))
}

/// Les nombres d'un SID écrit en forme stricte : « S-1- » puis des nombres décimaux de 32 bits sans zéro devant, rien
/// d'autre. Samba lit aussi « s- », l'hexadécimal, les zéros devant, les guillemets : ces écritures-là ne sont jamais
/// prises pour un compte nommé, puisqu'on ne saurait pas dire lequel Samba y lit.
#[cfg(any(target_os = "linux", test))]
fn sid_strict(sid: &str) -> Option<Vec<u32>> {
    sid.strip_prefix("S-1-")?
        .split('-')
        .map(|n| {
            let decimal = !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) && (n == "0" || !n.starts_with('0'));
            decimal.then(|| n.parse().ok()).flatten()
        })
        .collect()
}

/// Un compte nommé, que l'invité de Samba ne porte pas dans son jeton : un compte de la base de Samba (S-1-5-21-…-RID,
/// RID dès 1000 ; en dessous, le compte invité …-501, les Invités du domaine …-514 et les autres comptes connus), ou un
/// compte ou groupe Unix ordinaire (S-1-22-1-uid, S-1-22-2-gid, de 1000 à 60000 ; l'invité est « nobody », 65534, par
/// défaut). Tout le reste (Tout le monde, Réseau, Invités, un SID mal écrit) peut laisser entrer l'invité.
#[cfg(any(target_os = "linux", test))]
fn compte_nomme(sid: &str) -> bool {
    match sid_strict(sid).as_deref() {
        Some([5, 21, _, _, _, rid]) => *rid >= 1000,
        Some([22, 1 | 2, id]) => (1000..=60000).contains(id),
        _ => false,
    }
}

/// Les règles d'une ACL d'usershare lues comme le fait Samba (parse_usershare_acl), à partir de l'octet `debut` du
/// tampon de `tampon_samba` : le SID tel qu'il le prend (jusqu'au premier « : » hors guillemets, « : » de tête
/// sautés, guillemets retirés) et la lettre du droit, en majuscule. Samba compte une règle par virgule de la chaîne C,
/// plus une, puis lit chacune en avançant d'un octet après sa lettre, même quand cet octet est le nul de fin : une
/// virgule mise dans un SID donne une règle de plus, lue dans la suite du tampon, après un « \r » (net 4.25.0). D'où
/// la lecture sur le tampon entier, pas ligne par ligne. `None` en dernier : Samba refuserait le fichier là.
#[cfg(any(target_os = "linux", test))]
fn regles_samba(tampon: &[u8], debut: usize) -> Vec<Option<(Vec<u8>, u8)>> {
    let octet = |i: usize| tampon.get(i).copied();
    let chaine = tampon
        .get(debut..)
        .unwrap_or_default()
        .split(|&o| o == 0)
        .next()
        .unwrap_or_default();
    if chaine.is_empty() {
        // Une ACL vide : Tout le monde en lecture, pour Samba.
        return vec![Some((b"S-1-1-0".to_vec(), b'R'))];
    }
    let mut regles = Vec::new();
    let mut i = debut;
    // Un morceau par virgule, plus un : le nombre de règles que Samba lit.
    for _ in chaine.split(|&o| o == b',') {
        while octet(i) == Some(b':') {
            i = i.saturating_add(1);
        }
        let (mut sid, mut guillemets) = (Vec::new(), false);
        while let Some(o) = octet(i).filter(|&o| o != 0 && (guillemets || o != b':')) {
            if o == b'"' {
                guillemets = !guillemets;
            } else {
                sid.push(o);
            }
            i = i.saturating_add(1);
        }
        if octet(i) == Some(b':') {
            i = i.saturating_add(1);
        }
        // Plus rien à lire (octet nul, ou au-delà du tampon, où Samba lirait n'importe quoi) : pas de lettre, refusé.
        let droit = octet(i).unwrap_or(0).to_ascii_uppercase();
        i = i.saturating_add(1);
        // Après la lettre : la fin de la chaîne ou une virgule, sinon Samba refuse (« bad acl string »).
        if !matches!(droit, b'F' | b'R' | b'D') || !matches!(octet(i), Some(0 | b',')) {
            regles.push(None);
            return regles;
        }
        i = i.saturating_add(1);
        regles.push(Some((sid, droit)));
    }
    regles
}

/// Le fichier tel que Samba le garde en mémoire (file_lines_parse) : chaque « \n » et chaque « \r » devient un octet
/// nul, et un octet nul ferme le tout (fd_load). Les lignes restent à leur place : un octet du texte, un du tampon.
#[cfg(any(target_os = "linux", test))]
fn tampon_samba(texte: &str) -> Vec<u8> {
    texte
        .bytes()
        .map(|o| if matches!(o, b'\n' | b'\r') { 0 } else { o })
        .chain([0])
        .collect()
}

/// Un partage d'utilisateur de Samba (`net usershare add`, la case « Partager ce dossier » du gestionnaire de
/// fichiers) : un fichier du dossier des usershares, hors de smb.conf, que `testparm` ne montre pas. Samba le lit par
/// position (« #VERSION 2 », path=, comment=, usershare_acl=, guest_ok=, sharename=), chaque ligne coupée au premier
/// octet nul ou retour chariot (`tampon_samba`), et n'y voit l'invité que si guest_ok commence par « y ». Ici, tout
/// ce qui pourrait ouvrir compte, rien de ce qu'il ne lit pas ne ferme : chaque ligne guest_ok et chaque ligne
/// usershare_acl, où qu'elle soit (pour un fichier que Samba accepte, la première de chaque clé est la sienne). Les
/// règles se lisent comme Samba les lit (`regles_samba`) ; une règle ne compte fermée à l'invité que si son SID est
/// un compte nommé écrit en forme stricte ; un refus de Tout le monde (que tout jeton porte) arrête la suite, ce qui
/// était déjà permis reste compté (côté prudent, quel que soit l'ordre que Samba applique). Une ACL que Samba
/// refuserait : accès compté, écriture pas sue. La fermeture se fait dans les réglages du partage (son propriétaire,
/// sans droits d'administrateur).
#[cfg(any(target_os = "linux", test))]
fn usershare(fichier: &str, texte: &str, nuance: Nuance) -> Option<Partage> {
    let tampon = tampon_samba(texte);
    // (début de la valeur dans le tampon, valeur vue comme une chaîne C)
    let mut debut = 0_usize;
    let lignes: Vec<(usize, &str)> = texte
        .split('\n')
        .map(|ligne| {
            let d = debut;
            debut = debut.saturating_add(ligne.len()).saturating_add(1);
            (d, ligne.split(['\0', '\r']).next().unwrap_or(""))
        })
        .collect();
    let valeurs = |cle: &'static str| {
        lignes
            .iter()
            .filter(|(_, l)| !l.trim_start().starts_with('#'))
            .filter_map(|&(d, l)| {
                l.split_once('=')
                    .map(|(k, v)| (k, (d.saturating_add(k.len()).saturating_add(1), v)))
            })
            .filter(move |(k, _)| k.trim().eq_ignore_ascii_case(cle))
            .map(|(_, valeur)| valeur)
    };
    // « Y », « true » et « 1 » n'ouvrent pas pour Samba ; comptés quand même, par prudence.
    let invite = valeurs("guest_ok").any(|(_, v)| {
        let v = v.trim();
        v.starts_with(['y', 'Y']) || matches!(v.to_ascii_lowercase().as_str(), "true" | "1")
    });
    if !invite {
        return None;
    }
    // Sans ligne d'ACL, Samba refuse le fichier ; compté ouvert en lecture, jamais « fermé » sans l'avoir lu.
    let (mut lecture, mut ecriture, mut inconnue) = (valeurs("usershare_acl").next().is_none(), false, false);
    'lignes: for (debut_acl, _) in valeurs("usershare_acl") {
        for regle in regles_samba(&tampon, debut_acl) {
            let Some((sid, droit)) = regle else {
                // Samba refuserait le fichier : accès compté, écriture pas sue.
                (lecture, inconnue) = (true, true);
                break;
            };
            if std::str::from_utf8(&sid).is_ok_and(compte_nomme) {
                continue;
            }
            match droit {
                b'F' => (lecture, ecriture) = (true, true),
                b'D' if sid == b"S-1-1-0" => break 'lignes,
                // Le refus d'un autre groupe n'arrête rien : l'invité ne le porte peut-être pas.
                b'D' => {}
                _ => lecture = true,
            }
        }
    }
    if !lecture {
        return None;
    }
    let premiere = |cle: &'static str| valeurs(cle).next().map(|(_, v)| v.trim());
    Some(Partage {
        nom: premiere("sharename")
            .filter(|n| !n.is_empty())
            .unwrap_or(fichier)
            .to_string(),
        chemin: premiere("path").unwrap_or("").to_string(),
        a_qui: tr!("l'invité (sans mot de passe)", "the guest (no password)").to_string(),
        ecriture: if ecriture {
            Some(true)
        } else {
            (!inconnue).then_some(false)
        },
        nuance,
        fermeture: Vec::new(),
    })
}

/// Lit un fichier ordinaire d'au plus `max` octets, sans jamais ouvrir autre chose : le type est vu avant d'ouvrir,
/// l'ouverture ne bloque pas (un tube nommé attendrait son écrivain) et ne suit pas de lien quand `suivre` est faux,
/// puis ce qui est ouvert est bien le fichier vu. `Ok(None)` : il n'existe pas. Toute autre erreur, et un fichier trop
/// gros, est rendue : non vérifié, jamais « rien ».
#[cfg(target_os = "linux")]
fn lire_fichier(chemin: &std::path::Path, max: u64, suivre: bool) -> std::io::Result<Option<String>> {
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let vu = match if suivre {
        std::fs::metadata(chemin)
    } else {
        std::fs::symlink_metadata(chemin)
    } {
        Ok(vu) => vu,
        Err(e) if super::unix::absent(&e) => return Ok(None),
        Err(e) => return Err(e),
    };
    let refus = || {
        std::io::Error::other(tr!(
            "pas un fichier ordinaire, ou trop gros",
            "not a regular file, or too big"
        ))
    };
    if !vu.is_file() {
        return Err(refus());
    }
    let mut drapeaux = libc::O_NONBLOCK | libc::O_NOCTTY;
    if !suivre {
        drapeaux |= libc::O_NOFOLLOW;
    }
    let fichier = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(drapeaux)
        .open(chemin)?;
    let ouvert = fichier.metadata()?;
    if !ouvert.is_file() || ouvert.dev() != vu.dev() || ouvert.ino() != vu.ino() {
        return Err(refus());
    }
    let mut octets = Vec::new();
    fichier.take(max.saturating_add(1)).read_to_end(&mut octets)?;
    if u64::try_from(octets.len()).unwrap_or(u64::MAX) > max {
        return Err(refus());
    }
    Ok(Some(String::from_utf8_lossy(&octets).into_owned()))
}

/// Les noms des entrées d'un dossier, au plus `FICHIERS_MAX`. `None` : pas de dossier. Un dossier illisible, ou
/// plus d'entrées que la borne, ajoute sa raison à `sources` : ce qui n'est pas lu n'est jamais compté sain.
#[cfg(target_os = "linux")]
fn entrees(dossier: &std::path::Path, sources: &mut Vec<String>) -> Option<Vec<String>> {
    let chemin = crate::ui::chemin_affichable(dossier);
    let lus = match std::fs::read_dir(dossier) {
        Ok(lus) => lus,
        Err(e) if super::unix::absent(&e) => return None,
        Err(_) => {
            sources.push(trf!("dossier {chemin} illisible", "folder {chemin} unreadable"));
            return Some(Vec::new());
        }
    };
    let mut noms = Vec::new();
    for entree in lus {
        let Ok(entree) = entree else {
            sources.push(trf!("dossier {chemin} lu en partie", "folder {chemin} partly read"));
            break;
        };
        if noms.len() == FICHIERS_MAX {
            sources.push(trf!(
                "plus de {FICHIERS_MAX} fichiers dans {chemin} : la suite n'est pas lue",
                "more than {FICHIERS_MAX} files in {chemin}: the rest is not read"
            ));
            break;
        }
        noms.push(entree.file_name().to_string_lossy().into_owned());
    }
    noms.sort_unstable();
    Some(noms)
}

/// Les partages d'utilisateur ouverts du dossier des usershares. Ce qui n'est pas un fichier ordinaire (lien,
/// sous-dossier, tube) est sauté sans rien dire : Samba ne le charge pas (« not a regular file. Ignoring. »). Un
/// fichier ordinaire illisible (droits, trop gros, changé pendant la lecture), un dossier illisible ou trop plein :
/// leur raison va dans `sources`, avec le chemin à retirer ou à vérifier.
#[cfg(target_os = "linux")]
fn lire_usershares(dossier: &std::path::Path, nuance: Nuance, sources: &mut Vec<String>) -> Vec<Partage> {
    let mut partages = Vec::new();
    for nom in entrees(dossier, sources).unwrap_or_default() {
        let fichier = dossier.join(&nom);
        match std::fs::symlink_metadata(&fichier) {
            Ok(vu) if !vu.is_file() => continue,
            Err(e) if super::unix::absent(&e) => continue,
            // Une autre erreur : lire_fichier la rend, et elle est dite.
            _ => {}
        }
        // Pas de lien suivi : le dossier est écrit par les comptes du groupe des partages, pas par root seul. Un
        // fichier remplacé par un lien entre les deux lectures est refusé par lire_fichier, donc dit.
        match lire_fichier(&fichier, USERSHARE_MAX, false) {
            Ok(Some(texte)) => partages.extend(usershare(&nom, &texte, nuance)),
            Ok(None) => {}
            Err(_) => {
                let chemin = crate::ui::chemin_affichable(&fichier);
                sources.push(trf!("{chemin} illisible", "{chemin} unreadable"));
            }
        }
    }
    partages
}

/// Les exports NFS ouverts de `etc`/exports et de `etc`/exports.d/*.exports (les seuls que nfs-utils lit là). `None` :
/// ni l'un ni l'autre n'existe. Un fichier ou un dossier illisible ajoute sa raison à `sources`.
#[cfg(target_os = "linux")]
fn lire_exports(etc: &std::path::Path, nuance: Nuance, sources: &mut Vec<String>) -> Option<Vec<Partage>> {
    let d = etc.join("exports.d");
    let mut fichiers = vec![etc.join("exports")];
    let dossier = entrees(&d, sources);
    let dossier_vu = dossier.is_some();
    fichiers.extend(
        dossier
            .unwrap_or_default()
            .into_iter()
            .filter(|n| n.ends_with(".exports"))
            .map(|n| d.join(n)),
    );
    let mut partages = Vec::new();
    let mut un_lu = dossier_vu;
    for f in fichiers {
        match lire_fichier(&f, EXPORTS_MAX, true) {
            Ok(Some(texte)) => {
                un_lu = true;
                partages.extend(nfs(&texte, &f.to_string_lossy(), nuance));
            }
            Ok(None) => {}
            Err(_) => {
                un_lu = true;
                let chemin = crate::ui::chemin_affichable(&f);
                sources.push(trf!("{chemin} illisible", "{chemin} unreadable"));
            }
        }
    }
    un_lu.then_some(partages)
}

#[cfg(target_os = "linux")]
fn nuance_service(actif: Option<bool>) -> Nuance {
    if actif == Some(false) {
        Nuance::ServiceArrete
    } else {
        Nuance::Aucune
    }
}

/// Le relevé Linux à partir de ses entrées, pour qu'un essai passe par le même câblage que le bilan : la
/// configuration de Samba (`None` : pas de Samba, ou illisible, dit alors dans `sources`), les dossiers des
/// usershares, le dossier où lire exports et exports.d, et l'état des services, demandé seulement quand il sert (un
/// partage trouvé, ou une configuration à dire « service pas lancé ») : un poste sans Samba ni NFS ne questionne pas
/// systemd.
#[cfg(target_os = "linux")]
fn relever_dans(
    config: Option<&str>,
    fichier_smb: &str,
    dossiers_usershares: &[std::path::PathBuf],
    etc: &std::path::Path,
    mut sources: Vec<String>,
    actif_smb: impl FnOnce() -> Option<bool>,
    actif_nfs: impl FnOnce() -> Option<bool>,
) -> Releve {
    let mut partages = Vec::new();
    let mut service_vu_arrete = false;
    let mut trouves = Vec::new();
    if let Some(config) = config {
        trouves.extend(samba(config, fichier_smb, Nuance::Aucune));
    }
    // Un même dossier écrit deux fois (barre finale, lien) n'est lu qu'une fois : chaque partage, un seul constat. Un
    // dossier dont le vrai chemin ne se lit pas est gardé tel quel, et lu.
    let mut vus: Vec<std::path::PathBuf> = Vec::new();
    for dossier in dossiers_usershares {
        let vrai = std::fs::canonicalize(dossier).unwrap_or_else(|_| dossier.clone());
        if vus.contains(&vrai) {
            continue;
        }
        vus.push(vrai);
        trouves.extend(lire_usershares(dossier, Nuance::Aucune, &mut sources));
    }
    let etat_smb = (config.is_some() || !trouves.is_empty()).then(actif_smb).flatten();
    for p in &mut trouves {
        p.nuance = nuance_service(etat_smb);
    }
    service_vu_arrete |= config.is_some() && trouves.is_empty() && etat_smb == Some(false);
    partages.extend(trouves);
    if let Some(mut trouves) = lire_exports(etc, Nuance::Aucune, &mut sources) {
        let etat_nfs = actif_nfs();
        for p in &mut trouves {
            p.nuance = nuance_service(etat_nfs);
        }
        service_vu_arrete |= trouves.is_empty() && etat_nfs == Some(false);
        partages.extend(trouves);
    }
    Releve {
        partages,
        illisibles: Vec::new(),
        sources_illisibles: sources,
        service_vu_arrete,
    }
}

#[cfg(target_os = "linux")]
mod systeme {
    use super::Releve;
    use crate::trf;

    /// Un service systemd est-il actif ? `None` sans systemd, ou quand son état n'a pu se lire : aucune nuance alors,
    /// jamais « service arrêté » sans l'avoir lu.
    fn actif(noms: &[&str]) -> Option<bool> {
        if !std::path::Path::new("/run/systemd/system").is_dir() {
            return None;
        }
        crate::machine::linux::un_service_actif(noms)
    }

    // Même signature que sous Windows, où la lecture PowerShell peut échouer.
    #[allow(clippy::unnecessary_wraps)]
    pub fn relever() -> Option<Releve> {
        let mut sources = Vec::new();
        // testparm donne la configuration réellement appliquée (fichiers inclus, valeurs par défaut) ; sans lui, le
        // fichier lui-même. Un smb.conf là mais illisible n'est pas « pas de Samba ».
        let smb = "/etc/samba/smb.conf";
        let config = super::super::sortie("testparm", &["-s", "--suppress-prompt"]).or_else(|| {
            match std::fs::read_to_string(smb) {
                Ok(texte) => Some(texte),
                Err(e) if super::super::unix::absent(&e) => None,
                Err(_) => {
                    sources.push(trf!("{smb} illisible", "{smb} unreadable"));
                    None
                }
            }
        });
        // Les partages d'utilisateur (Nautilus « Partager ce dossier », `net usershare add`) ne sont ni dans smb.conf ni
        // dans la sortie de testparm : smbd les lit dans leur dossier. Celui de la configuration et l'habituel sont lus
        // tous deux : une configuration mal comprise ici ne fait pas sauter le dossier que smbd lit vraiment.
        let mut dossiers = vec![std::path::PathBuf::from(super::USERSHARES_PAR_DEFAUT)];
        dossiers.extend(
            config
                .as_deref()
                .and_then(super::dossier_usershares)
                .map(std::path::PathBuf::from),
        );
        Some(super::relever_dans(
            config.as_deref(),
            smb,
            &dossiers,
            std::path::Path::new("/etc"),
            sources,
            || actif(&["smb", "smbd", "samba"]),
            || actif(&["nfs-server"]),
        ))
    }
}

// ───────────────────────────── Windows ─────────────────────────────

/// Les lignes « ACC|partage|chemin|compte|SID|type|droit » : les partages ouverts à Tout le monde (S-1-1-0), aux
/// connexions anonymes (S-1-5-7), aux Invités (S-1-5-32-546) ou au compte invité (…-501), hors partages
/// administratifs. Un partage dont les droits n'ont pas pu être lus (« ? ») est rendu à part.
#[cfg(any(windows, test))]
fn lire_windows(sortie: &str) -> Option<Releve> {
    use crate::commande::section;
    let acces = section(Some(sortie), "ACC")?;
    // « INV|True » : activé ; « INV|False » ou « INV| » (pas de compte invité) : désactivé. Sans la
    // section (lecture refusée, Get-LocalUser en échec), l'état n'est pas connu.
    let invite_actif = section(Some(sortie), "INV").and_then(|l| l.first().map(|v| v.trim() == "True"));
    let service_lance = section(Some(sortie), "SRV").is_none_or(|l| l.first().is_none_or(|v| v.trim() == "Running"));
    let nuance = match (service_lance, invite_actif) {
        (false, _) => Nuance::ServiceArrete,
        (true, Some(true)) => Nuance::Aucune,
        (true, Some(false)) => Nuance::InviteDesactive,
        (true, None) => Nuance::InviteNonLu,
    };
    let mut partages: Vec<Partage> = Vec::new();
    let mut illisibles: Vec<Illisible> = Vec::new();
    // Les partages dont un accès ne se retire pas par une ligne du processus élevé (nom ou SID hors de leur forme) : à
    // fermer soi-même, en entier, pour ne pas en laisser un derrière un « fait ».
    let mut a_la_main: Vec<&str> = Vec::new();
    // Un refus prime sur une autorisation, quel que soit l'ordre des règles : relevés d'abord.
    let refus: Vec<(&str, &str, &str)> = acces
        .iter()
        .filter_map(|l| {
            let champs: Vec<&str> = l.splitn(6, '|').collect();
            let [nom, _, _, sid, genre, droit] = champs[..] else {
                return None;
            };
            genre.eq_ignore_ascii_case("Deny").then(|| (nom, sid, droit.trim()))
        })
        .collect();
    for l in acces {
        let champs: Vec<&str> = l.splitn(6, '|').collect();
        let [nom, chemin, compte, sid, genre, droit] = champs[..] else {
            continue;
        };
        if compte == "?" {
            if !illisibles.iter().any(|i| i.nom == nom) {
                illisibles.push(Illisible { nom: nom.to_string() });
            }
            continue;
        }
        if !sid_ouvert(sid) || !genre.eq_ignore_ascii_case("Allow") {
            continue;
        }
        let refuse = |droits: &[&str]| {
            refus
                .iter()
                .any(|&(n, s, d)| n == nom && couvre(s, sid) && droits.contains(&d))
        };
        // Tout refusé : fermé. Écriture refusée : lecture seule. Un refus de lecture ou sur mesure
        // n'est pas interprété : le partage reste signalé tel qu'autorisé.
        if refuse(&["Full"]) {
            continue;
        }
        let ecriture = matches!(droit.trim(), "Full" | "Change") && !refuse(&["Change"]);
        // Les règles de ce compte retirées de la liste des droits du partage par le processus élevé (NetShareSetInfo), qui
        // relit le partage et le rejuge ici avant d'écrire.
        let fermeture = crate::machine::gestes::ligne_partage_retirer_acces(nom, sid);
        if fermeture.is_none() && !a_la_main.contains(&nom) {
            a_la_main.push(nom);
        }
        if let Some(p) = partages.iter_mut().find(|p| p.nom == nom) {
            if !p.a_qui.contains(compte) {
                p.a_qui = format!("{}, {compte}", p.a_qui);
            }
            p.ecriture = Some(p.ecriture.unwrap_or(false) || ecriture);
            if let Some(f) = fermeture
                && !p.fermeture.contains(&f)
            {
                p.fermeture.push(f);
            }
        } else {
            partages.push(Partage {
                nom: nom.to_string(),
                chemin: chemin.to_string(),
                a_qui: compte.to_string(),
                ecriture: Some(ecriture),
                nuance,
                fermeture: fermeture.into_iter().collect(),
            });
        }
    }
    for p in &mut partages {
        if a_la_main.contains(&p.nom.as_str()) {
            p.fermeture.clear();
        }
    }
    Some(Releve {
        partages,
        illisibles,
        sources_illisibles: Vec::new(),
        service_vu_arrete: !service_lance,
    })
}

/// Le bilan relu (lignes « ACC|… ») propose-t-il de retirer cet accès, par la ligne du processus élevé ? Rejugé par
/// lui avant d'écrire (`partages_ecriture`).
#[cfg(any(windows, test))]
pub(crate) fn acces_signale(sortie: &str, nom: &str, sid: &str) -> bool {
    let Some(ligne) = crate::machine::gestes::ligne_partage_retirer_acces(nom, sid) else {
        return false;
    };
    lire_windows(sortie).is_some_and(|r| r.partages.iter().any(|p| p.nom == nom && p.fermeture.contains(&ligne)))
}

/// Un refus visant `refuse` s'applique-t-il à `compte` ? Tout le monde (S-1-1-0) contient les
/// Invités et le compte invité, pas les connexions anonymes (S-1-5-7) : Windows ne les y met plus
/// par défaut, et les y compter pourrait taire un partage ouvert.
#[cfg(any(windows, test))]
fn couvre(refuse: &str, compte: &str) -> bool {
    refuse == compte || (refuse == "S-1-1-0" && compte != "S-1-5-7")
}

#[cfg(windows)]
mod systeme {
    use super::Releve;

    pub fn relever() -> Option<Releve> {
        // Les comptes sont rendus avec leur SID : « Tout le monde » s'écrit dans la langue de Windows, S-1-1-0 non.
        // Lus par les fonctions de Windows ; PowerShell seulement si elles refusent la liste des partages.
        if let Some(sortie) = crate::machine::windows::partages::releve() {
            return super::lire_windows(&sortie);
        }
        let sortie = crate::machine::windows::ps(
            "try { Get-SmbShare -ErrorAction Stop | Where-Object { -not $_.Special } | ForEach-Object { $s = $_; $a = @(); \
             try { $a = @(Get-SmbShareAccess -Name $s.Name -ErrorAction Stop) } catch { \"ACC|$($s.Name)|$($s.Path)|?|?|?|?\" }; \
             $a | ForEach-Object { $sid = ''; try { $sid = (New-Object System.Security.Principal.NTAccount($_.AccountName)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch {}; \
             \"ACC|$($s.Name)|$($s.Path)|$($_.AccountName)|$sid|$($_.AccessControlType)|$($_.AccessRight)\" } }; 'ACC_FIN' } catch {}; \
             try { $g = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -like 'S-1-5-21-*-501' } | Select-Object -First 1; \"INV|$($g.Enabled)\"; 'INV_FIN' } catch {}; \
             try { \"SRV|$((Get-Service LanmanServer -ErrorAction Stop).Status)\"; 'SRV_FIN' } catch {}",
        )?;
        super::lire_windows(&sortie)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn partage(nom: &str, ecriture: Option<bool>, nuance: Nuance, fermeture: &[&str]) -> Partage {
        Partage {
            nom: nom.to_string(),
            chemin: format!("/srv/{nom}"),
            a_qui: "l'invité".to_string(),
            ecriture,
            nuance,
            fermeture: fermeture.iter().map(ToString::to_string).collect(),
        }
    }

    #[test]
    fn niveaux_et_phrases() {
        let rien = juger(&[], &[], &[], false);
        assert!(rien[0].probleme.is_none() && rien[0].verifie);
        assert!(juger(&[], &[], &[], true)[0].message.contains("pas lancé"));
        let ecriture = juger(
            &[partage("Public", Some(true), Nuance::Aucune, &["x"])],
            &[],
            &[],
            false,
        );
        assert_eq!(ecriture[0].probleme, Some(Niveau::Eleve));
        assert!(
            ecriture[0].message.contains("lire et modifier"),
            "{}",
            ecriture[0].message
        );
        assert!(ecriture[0].correctif.as_ref().unwrap().automatique);
        let lecture = juger(&[partage("Public", Some(false), Nuance::Aucune, &[])], &[], &[], false);
        assert_eq!(lecture[0].probleme, Some(Niveau::Moyen));
        assert!(!lecture[0].correctif.as_ref().unwrap().automatique);
        // Service arrêté ou invité désactivé : un cran plus bas, et la nuance est dite.
        let arrete = juger(
            &[partage("Public", Some(true), Nuance::ServiceArrete, &[])],
            &[],
            &[],
            false,
        );
        assert_eq!(arrete[0].probleme, Some(Niveau::Moyen));
        assert!(arrete[0].message.contains("inoffensif"), "{}", arrete[0].message);
        let invite = juger(
            &[partage("Public", Some(false), Nuance::InviteDesactive, &[])],
            &[],
            &[],
            false,
        );
        assert_eq!(invite[0].probleme, Some(Niveau::Info));
        let inconnu = juger(&[partage("Public", None, Nuance::Aucune, &[])], &[], &[], false);
        assert_eq!(inconnu[0].probleme, Some(Niveau::Eleve));
        assert!(inconnu[0].message.contains("y accéder"));
        // Un partage illisible n'est jamais compté sain.
        let illisible = juger(&[], &[Illisible { nom: "Docs".into() }], &[], false);
        assert!(!illisible[0].verifie && illisible[0].message.contains("Docs"));
    }

    const SMB_CONF: &str = "[global]\n   workgroup = SALON\n   map to guest = Bad User\n\n\
        [public]\n   path = /srv/public\n   guest ok = yes\n   read only = no\n\n\
        [docs]\n   path = /srv/docs\n   public = Yes\n\n\
        [prive]\n   path = /srv/prive\n   valid users = alice\n   writable = yes\n\n\
        [vieux]\n   path = /srv/vieux\n   guest ok = yes\n   available = no\n\n\
        [printers]\n   path = /var/spool/samba\n   guest ok = yes\n   printable = yes\n";

    #[test]
    fn partages_samba_ouverts_a_l_invite() {
        let p = samba(SMB_CONF, "/etc/samba/smb.conf", Nuance::Aucune);
        let noms: Vec<(&str, Option<bool>)> = p.iter().map(|x| (x.nom.as_str(), x.ecriture)).collect();
        // « read only = yes » est la valeur par défaut de Samba ; prive est réservé, vieux indisponible, printers exclu.
        assert_eq!(noms, [("public", Some(true)), ("docs", Some(false))]);
        assert_eq!(p[0].chemin, "/srv/public");
        assert!(p[0].fermeture[1].starts_with("sudo sed -i "), "{}", p[0].fermeture[1]);
        // L'ancien « security = share » ouvre tout, sans correction automatique.
        let vieux = samba(
            "[global]\nsecurity = share\n[x]\npath = /x\n",
            "/etc/samba/smb.conf",
            Nuance::Aucune,
        );
        assert_eq!(vieux.len(), 1);
        assert_eq!(vieux[0].fermeture, Vec::<String>::new());
        assert_eq!(
            samba(
                "[global]\nworkgroup = X\n[x]\npath = /x\n",
                "/etc/samba/smb.conf",
                Nuance::Aucune
            ),
            Vec::new()
        );
    }

    /// La commande sed générée ne touche que la section visée, même avec un nom à caractères spéciaux.
    #[cfg(target_os = "linux")]
    #[test]
    fn fermeture_samba_ne_change_que_la_section() {
        let dossier = crate::essais::temporaire().join(format!("vanguard-smb-{}", std::process::id()));
        std::fs::create_dir_all(&dossier).unwrap();
        let fichier = dossier.join("smb.conf");
        let config = "[global]\n   workgroup = X\n[a.b]\n   path = /a\n   guest ok = yes\n   public = Yes\n[b]\n   path = /b\n   Guest OK = yes\n";
        std::fs::write(&fichier, config).unwrap();
        let commandes = fermeture_samba("a.b", &fichier.to_string_lossy());
        for c in &commandes[..2] {
            let sans_sudo = c.replace("sudo ", "");
            let statut = std::process::Command::new("bash")
                .arg("-c")
                .arg(&sans_sudo)
                .status()
                .unwrap();
            assert!(statut.success(), "{sans_sudo}");
        }
        let apres = std::fs::read_to_string(&fichier).unwrap();
        assert_eq!(
            apres,
            "[global]\n   workgroup = X\n[a.b]\n   path = /a\n   guest ok = no\n   public = no\n[b]\n   path = /b\n   Guest OK = yes\n"
        );
        assert_eq!(
            std::fs::read_to_string(dossier.join("smb.conf.avant-vanguard")).unwrap(),
            config
        );
        // Relancée, la copie d'avant n'est pas écrasée.
        let statut = std::process::Command::new("bash")
            .arg("-c")
            .arg(commandes[0].replace("sudo ", ""))
            .status()
            .unwrap();
        assert!(statut.success());
        assert_eq!(
            std::fs::read_to_string(dossier.join("smb.conf.avant-vanguard")).unwrap(),
            config
        );
        let _ = std::fs::remove_dir_all(&dossier);
    }

    #[test]
    fn exports_nfs_ouverts() {
        let exports = "# commentaire\n/srv/films *(ro,sync)\n/srv/sauvegardes 192.168.1.0/24(rw)\n\
                       \"/srv/mon dossier\" *(rw,no_root_squash)\n/srv/tout (rw)\n";
        let p = nfs(exports, "/etc/exports", Nuance::Aucune);
        let noms: Vec<(&str, Option<bool>)> = p.iter().map(|x| (x.nom.as_str(), x.ecriture)).collect();
        assert_eq!(
            noms,
            [
                ("/srv/films", Some(false)),
                ("/srv/mon dossier", Some(true)),
                ("/srv/tout", Some(true))
            ]
        );
        assert_eq!(
            p[0].fermeture[1],
            "sudo sed -i 's/^\\/srv\\/films \\*(ro,sync)$/# Vanguard : &/' '/etc/exports'"
        );
        assert_eq!(p[0].fermeture[2], "sudo exportfs -ra");
    }

    #[test]
    fn lecture_windows_par_sid() {
        let sortie = "ACC|Public|C:\\Users\\Public|Tout le monde|S-1-1-0|Allow|Full\n\
                      ACC|Public|C:\\Users\\Public|BUREAU\\alice|S-1-5-21-1-2-3-1001|Allow|Full\n\
                      ACC|Docs|D:\\Docs|Invités|S-1-5-32-546|Allow|Read\n\
                      ACC|Docs|D:\\Docs|BUREAU\\alice|S-1-5-21-1-2-3-1001|Deny|Full\n\
                      ACC|Prive|D:\\Prive|BUREAU\\alice|S-1-5-21-1-2-3-1001|Allow|Change\n\
                      ACC|Cache|D:\\Cache|?|?|?|?\n\
                      ACC_FIN\nINV|False\nINV_FIN\nSRV|Running\nSRV_FIN\n";
        let r = lire_windows(sortie).unwrap();
        let noms: Vec<(&str, Option<bool>, Nuance)> = r
            .partages
            .iter()
            .map(|p| (p.nom.as_str(), p.ecriture, p.nuance))
            .collect();
        assert_eq!(
            noms,
            [
                ("Public", Some(true), Nuance::InviteDesactive),
                ("Docs", Some(false), Nuance::InviteDesactive)
            ]
        );
        // Le nom en UTF-16 hexadécimal : « Public ».
        assert_eq!(
            r.partages[0].fermeture,
            ["vanguard:partage-retirer-acces 5000750062006c0069006300 S-1-1-0"]
        );
        assert!(acces_signale(sortie, "Public", "S-1-1-0"));
        // Un compte nommé n'est pas signalé (alice garde son accès), ni un partage inconnu.
        assert!(!acces_signale(sortie, "Public", "S-1-5-21-1-2-3-1001"));
        assert!(!acces_signale(sortie, "Absent", "S-1-1-0"));
        assert!(!acces_signale(sortie, "Prive", "S-1-1-0"));
        assert_eq!(r.illisibles, [Illisible { nom: "Cache".into() }]);
        assert!(!r.service_vu_arrete);
        // Invité activé et service lancé : rien ne tempère ; service arrêté : tempéré.
        let r =
            lire_windows("ACC|P|C:\\P|Everyone|S-1-1-0|Allow|Read\nACC_FIN\nINV|True\nINV_FIN\nSRV|Running\nSRV_FIN\n")
                .unwrap();
        assert_eq!(r.partages[0].nuance, Nuance::Aucune);
        let r =
            lire_windows("ACC|P|C:\\P|Everyone|S-1-1-0|Allow|Read\nACC_FIN\nINV|True\nINV_FIN\nSRV|Stopped\nSRV_FIN\n")
                .unwrap();
        assert_eq!(r.partages[0].nuance, Nuance::ServiceArrete);
        // Deux comptes ouverts sur un même partage : une seule entrée, deux retraits.
        let r = lire_windows(
            "ACC|P|C:\\P|Everyone|S-1-1-0|Allow|Read\nACC|P|C:\\P|Guest|S-1-5-21-1-2-3-501|Allow|Change\nACC_FIN\n",
        )
        .unwrap();
        assert_eq!(r.partages.len(), 1);
        assert_eq!(
            (r.partages[0].a_qui.as_str(), r.partages[0].ecriture),
            ("Everyone, Guest", Some(true))
        );
        assert_eq!(r.partages[0].fermeture.len(), 2);
        // Deux règles du même compte : une seule ligne.
        let r = lire_windows(
            "ACC|P|C:\\P|Everyone|S-1-1-0|Allow|Read\nACC|P|C:\\P|Everyone|S-1-1-0|Allow|Change\nACC_FIN\n",
        )
        .unwrap();
        assert_eq!(r.partages[0].fermeture.len(), 1);
        // Un nom hors de la forme d'une ligne (partage caché, trop long) : tout le partage à fermer soi-même, et
        // jamais de PowerShell.
        for nom in ["Cache$", &"x".repeat(81)] {
            let sortie = format!(
                "ACC|{nom}|C:\\P|Everyone|S-1-1-0|Allow|Read\nACC|{nom}|C:\\P|Guest|S-1-5-21-1-2-3-501|Allow|Read\nACC_FIN\n"
            );
            let r = lire_windows(&sortie).unwrap();
            assert!(r.partages[0].fermeture.is_empty(), "{nom}");
            let c = juger(&r.partages, &[], &[], false);
            assert!(
                c[0].correctif
                    .as_ref()
                    .is_some_and(|k| !k.automatique && k.commandes.is_empty())
            );
            assert!(!acces_signale(&sortie, nom, "S-1-1-0"));
        }
        // Sans la section des accès (PowerShell tombé), rien n'est conclu.
        assert!(lire_windows("INV|True\nINV_FIN\n").is_none());
    }

    /// Section INV absente : l'invité n'est pas dit désactivé et rien n'est tempéré ; « INV| »
    /// (pas de compte invité) vaut désactivé.
    #[test]
    fn invite_non_lu() {
        let r = lire_windows("ACC|P|C:\\P|Everyone|S-1-1-0|Allow|Full\nACC_FIN\nSRV|Running\nSRV_FIN\n").unwrap();
        assert_eq!(r.partages[0].nuance, Nuance::InviteNonLu);
        let c = juger(&r.partages, &[], &[], false);
        assert_eq!(c[0].probleme, Some(Niveau::Eleve));
        assert!(c[0].message.contains("n'a pas pu être lu") && !c[0].message.contains("est désactivé"));
        let r = lire_windows("ACC|P|C:\\P|Everyone|S-1-1-0|Allow|Read\nACC_FIN\nINV|\nINV_FIN\n").unwrap();
        assert_eq!(r.partages[0].nuance, Nuance::InviteDesactive);
    }

    /// Un refus prime, avant comme après l'autorisation ; Tout le monde couvre les Invités, pas
    /// les connexions anonymes.
    #[test]
    fn refus_sur_un_partage() {
        let sortie = "ACC|Bloque|D:\\B|Everyone|S-1-1-0|Allow|Read\n\
                      ACC|Bloque|D:\\B|Everyone|S-1-1-0|Deny|Full\n\
                      ACC|Invites|D:\\I|Deny|S-1-1-0|Deny|Full\n\
                      ACC|Invites|D:\\I|Guests|S-1-5-32-546|Allow|Full\n\
                      ACC|Lecture|D:\\L|Everyone|S-1-1-0|Deny|Change\n\
                      ACC|Lecture|D:\\L|Everyone|S-1-1-0|Allow|Full\n\
                      ACC|Anonyme|D:\\A|Everyone|S-1-1-0|Deny|Full\n\
                      ACC|Anonyme|D:\\A|ANONYMOUS LOGON|S-1-5-7|Allow|Read\n\
                      ACC|Ailleurs|D:\\X|Everyone|S-1-1-0|Allow|Read\n\
                      ACC|Autre|D:\\Y|Everyone|S-1-1-0|Deny|Full\n\
                      ACC|Mesure|D:\\M|Everyone|S-1-1-0|Deny|Read\n\
                      ACC|Mesure|D:\\M|Everyone|S-1-1-0|Allow|Change\n\
                      ACC_FIN\nINV|True\nINV_FIN\n";
        let r = lire_windows(sortie).unwrap();
        let vus: Vec<(&str, Option<bool>)> = r.partages.iter().map(|p| (p.nom.as_str(), p.ecriture)).collect();
        assert_eq!(
            vus,
            [
                ("Lecture", Some(false)),
                ("Anonyme", Some(false)),
                ("Ailleurs", Some(false)),
                ("Mesure", Some(true))
            ]
        );
    }

    /// Un dossier jetable propre à l'essai.
    #[cfg(target_os = "linux")]
    fn dossier_jetable(nom: &str) -> std::path::PathBuf {
        let d = crate::essais::temporaire().join(format!("vanguard-partages-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// root lit un fichier même sans droit de lecture : l'essai d'un fichier illisible n'a pas de sens alors.
    #[cfg(target_os = "linux")]
    fn root() -> bool {
        // Le propriétaire de /proc/self est le compte effectif du processus, sans appel unsafe.
        std::fs::metadata("/proc/self").is_ok_and(|m| std::os::unix::fs::MetadataExt::uid(&m) == 0)
    }

    /// Un partage d'utilisateur (Nautilus « Accès invité », `net usershare add … guest_ok=y`) : ouvert quand l'invité
    /// y est permis et que l'ACL le laisse entrer ; réservé aux comptes sinon.
    #[test]
    fn usershare_ouvert_a_l_invite() {
        let fichier = |acl: &str, invite: &str| {
            format!(
                "#VERSION 2\npath=/home/alice/Documents\ncomment=\nusershare_acl={acl}\nguest_ok={invite}\nsharename=Documents\n"
            )
        };
        let p = usershare("documents", &fichier("S-1-1-0:F", "y"), Nuance::Aucune).unwrap();
        assert_eq!(
            (p.nom.as_str(), p.chemin.as_str(), p.ecriture),
            ("Documents", "/home/alice/Documents", Some(true))
        );
        // Fermé dans les réglages du partage : aucune commande proposée.
        assert_eq!(p.fermeture, Vec::<String>::new());
        let lecture = usershare("documents", &fichier("S-1-1-0:R", "y"), Nuance::Aucune).unwrap();
        assert_eq!(lecture.ecriture, Some(false));
        // Le vrai format écrit par `net usershare add` : sans virgule finale (celle-ci n'est que dans la sortie de
        // `net usershare info`, et Samba refuse un fichier qui l'a).
        let vrai =
            "#VERSION 2\npath=/home/alice/Public\ncomment=\nusershare_acl=S-1-1-0:R\nguest_ok=y\nsharename=Public\n";
        assert_eq!(usershare("public", vrai, Nuance::Aucune).unwrap().ecriture, Some(false));
        // Le groupe des invités et le compte invité ouvrent aussi.
        assert!(usershare("d", &fichier("S-1-5-32-546:R", "y"), Nuance::Aucune).is_some());
        assert!(usershare("d", &fichier("S-1-5-21-1-2-3-501:F", "y"), Nuance::Aucune).is_some());
        // Le nom anglais de Tout le monde, s'il est écrit au lieu du SID.
        assert!(usershare("d", &fichier("Everyone:R", "y"), Nuance::Aucune).is_some());
        // Sans invité, un mot de passe est demandé : pas signalé.
        assert_eq!(usershare("d", &fichier("S-1-1-0:F", "n"), Nuance::Aucune), None);
        // Un compte nommé seulement, ou Tout le monde refusé d'abord : l'invité n'entre pas.
        assert_eq!(
            usershare("d", &fichier("S-1-5-21-1-2-3-1001:F", "y"), Nuance::Aucune),
            None
        );
        assert_eq!(
            usershare("d", &fichier("S-1-1-0:D,S-1-5-32-546:F", "y"), Nuance::Aucune),
            None
        );
        // Un refus après une lecture permise ne retire pas la lecture (règles lues dans l'ordre, côté prudent).
        let p = usershare("d", &fichier("S-1-1-0:R,S-1-1-0:D,S-1-5-32-546:F", "y"), Nuance::Aucune).unwrap();
        assert_eq!(p.ecriture, Some(false));
        // ACL vide ou absente : comptée « Tout le monde en lecture », jamais « fermé ».
        assert!(usershare("d", &fichier("", "y"), Nuance::Aucune).is_some());
        let sans_acl = usershare("d", "#VERSION 2\npath=/srv/x\nguest_ok=y\n", Nuance::Aucune).unwrap();
        assert_eq!((sans_acl.nom.as_str(), sans_acl.ecriture), ("d", Some(false)));
        // Au bilan : un constat moyen (lecture seule), à fermer soi-même.
        let c = juger(&[p], &[], &[], false);
        assert_eq!(c[0].probleme, Some(Niveau::Moyen));
        assert!(c[0].correctif.as_ref().is_some_and(|k| !k.automatique));
    }

    /// Un fichier d'usershare au vrai format (celui de `net usershare add` : pas de virgule finale dans l'ACL).
    fn usershare_type(acl: &str, invite: &str, suite: &str) -> String {
        format!(
            "#VERSION 2\npath=/srv/essai\ncomment=\nusershare_acl={acl}\nguest_ok={invite}\nsharename=essai\n{suite}"
        )
    }

    /// Samba (net 4.25) ne regarde que le premier octet de guest_ok, un « y » minuscule : tout ce qui commence par
    /// « y » ouvre à l'invité. « Y » ne l'ouvre pas pour Samba ; compté ouvert quand même (côté prudent).
    #[test]
    fn usershare_invite_au_premier_caractere() {
        for invite in ["yolo", "yn", "y\0n", "yup", "Y"] {
            let p = usershare("essai", &usershare_type("S-1-1-0:F", invite, ""), Nuance::Aucune);
            assert_eq!(p.and_then(|p| p.ecriture), Some(true), "{invite:?}");
        }
        // Un octet nul coupe la ligne pour Samba (chaîne C) : « n » derrière ne ferme rien, « y » derrière n'ouvre rien.
        for ferme in ["n", "\0y", "no", ""] {
            assert_eq!(
                usershare("essai", &usershare_type("S-1-1-0:F", ferme, ""), Nuance::Aucune),
                None,
                "{ferme:?}"
            );
        }
    }

    /// Toutes ces écritures valent « S-1-1-0:F » pour Samba 4.25 (`net usershare info --long`) : jamais « fermé ».
    #[test]
    fn usershare_sid_ecrit_autrement() {
        for acl in [
            "s-1-1-0:F",
            "S-1-01-00:F",
            "S-1-0x1-0:F",
            "S-1-1-0x0:F",
            "S-01-1-0:F",
            "\"S-1-1-0\":F",
            "S-1-\"1\"-0:F",
            "::S-1-1-0:F",
            "S-1-1-0:F\0",
            "S-1-1-0 :F",
            "S-1-1-0:f",
        ] {
            let p = usershare("essai", &usershare_type(acl, "y", ""), Nuance::Aucune);
            assert_eq!(p.and_then(|p| p.ecriture), Some(true), "{acl:?}");
        }
        // Un compte nommé écrit autrement que sa forme stricte n'est pas reconnu comme tel : compté ouvert.
        for acl in [
            "S-1-5-21-1-2-3-01001:F",
            "s-1-5-21-1-2-3-1001:F",
            "S-1-5-21-1-2-3-1001x:F",
        ] {
            assert!(
                usershare("essai", &usershare_type(acl, "y", ""), Nuance::Aucune).is_some(),
                "{acl:?}"
            );
        }
        // Un nombre trop grand pour Samba (au-delà de 32 bits) n'est pas un compte nommé.
        assert!(
            usershare(
                "essai",
                &usershare_type("S-1-5-21-1-2-3-4294967797:F", "y", ""),
                Nuance::Aucune
            )
            .is_some()
        );
        // Un octet nul avant un refus : Samba lit une ACL vide (Tout le monde en lecture).
        let p = usershare("essai", &usershare_type("\0S-1-1-0:D", "y", ""), Nuance::Aucune);
        assert_eq!(p.and_then(|p| p.ecriture), Some(false));
        // Un refus coupé par un octet nul reste un refus, et ce qui suit l'octet n'est pas lu.
        assert_eq!(
            usershare(
                "essai",
                &usershare_type("S-1-1-0:D\0,S-1-1-0:F", "y", ""),
                Nuance::Aucune
            ),
            None
        );
        // Un droit que Samba ne lit pas : l'écriture n'est pas sue, l'accès reste signalé.
        let p = usershare("essai", &usershare_type("S-1-1-0:X", "y", ""), Nuance::Aucune);
        assert_eq!(p.map(|p| p.ecriture), Some(None));
        // « Dx » n'est pas un refus pour Samba (« bad acl string », il refuse le fichier), ni une virgule finale : ce
        // qu'il refuserait reste signalé, jamais « fermé », même derrière un compte nommé.
        for acl in ["S-1-1-0:Dx,S-1-1-0:F", "S-1-5-21-1-2-3-1001:F,", "S-1-1-0:D "] {
            let p = usershare("essai", &usershare_type(acl, "y", ""), Nuance::Aucune);
            assert_eq!(p.map(|p| p.ecriture), Some(None), "{acl:?}");
        }
    }

    /// Samba (file_lines_parse) change chaque « \r » en octet nul, où qu'il soit, puis lit l'ACL sur le tampon entier
    /// (parse_usershare_acl) : une règle par virgule, plus une, chacune lue un octet après la précédente, au-delà du
    /// nul. Une virgule dans un SID fait donc lire une règle de plus après le « \r ». Chaque cas vient de
    /// `net usershare info --long` (Samba 4.25.0, guest_ok=y).
    #[test]
    fn usershare_retour_chariot_comme_samba() {
        for (acl, samba) in [
            // Samba : S-1-1-0:F.
            ("S-1-1-0:F\r:D", Some(Some(true))),
            ("S-1-5-21-1-2-3-1000:F,S-1-1-0:F\r:D", Some(Some(true))),
            // Samba : …-1000:R, puis S-1-1-0:F lu après le « \r ».
            ("S-1-5-21-1-2-3-1000,S-1-5-21-1-2-3-1001:R\rS-1-1-0:F", Some(Some(true))),
            ("\"S-1-5-21-1-2-3-1000,\":R\rS-1-1-0:F", Some(Some(true))),
            ("S-1-5-21-1-2-3-1000,a:R\r::S-1-1-0:F", Some(Some(true))),
            ("S-1-5-21-1-2-3-1000,a:R\r\"S-1-1-0\":F", Some(Some(true))),
            ("S-1-5-21-1-2-3-1000\u{e9},x:R\rS-1-1-0:F", Some(Some(true))),
            // Deux « \r » : trois règles, la dernière dans le second morceau.
            ("S-1-5-21-1-2-3-1000,a,b:R\rS-1-1-0:R\rS-1-1-0:F", Some(Some(true))),
            // Samba : ACL vide, donc S-1-1-0:R.
            ("\rS-1-1-0:D", Some(Some(false))),
            ("\rS-1-5-21-1-2-3-1000:F", Some(Some(false))),
            ("S-1-1-0:R\r", Some(Some(false))),
            // Samba : …-1000:R seulement (sans virgule, rien n'est lu après le « \r ») ; un refus de Tout le monde.
            ("S-1-5-21-1-2-3-1000:R\rS-1-1-0:F", None),
            ("S-1-1-0:D\r,S-1-1-0:F", None),
            // Samba refuse le fichier (la règle en trop tombe sur un nul, ou sur « guest_ok=y ») : signalé quand même.
            ("S-1-5-21-1-2-3-1000:R,\rS-1-1-0:F", Some(None)),
            ("S-1-5-21-1-2-3-1000,a:R\r\rS-1-1-0:F", Some(None)),
            ("S-1-5-21-1-2-3-1000,S-1-5-21-1-2-3-1001:R", Some(None)),
        ] {
            let p = usershare("essai", &usershare_type(acl, "y", ""), Nuance::Aucune);
            assert_eq!(p.map(|p| p.ecriture), samba, "{acl:?}");
        }
        // Les guillemets retirés du SID, un « : » entre guillemets gardé (Samba : S-1-1-0:F, puis …-1000:R).
        for (acl, samba) in [
            ("\"S-1-1-0:D\":F", Some(Some(true))),
            ("\"S-1-5-21-1-2-3-1000\":R", None),
        ] {
            let p = usershare("essai", &usershare_type(acl, "y", ""), Nuance::Aucune);
            assert_eq!(p.map(|p| p.ecriture), samba, "{acl:?}");
        }
        // guest_ok derrière un « \r » : Samba lit un octet nul, pas « y ».
        assert_eq!(
            usershare("essai", &usershare_type("S-1-1-0:F", "\ry", ""), Nuance::Aucune),
            None
        );
    }

    /// Samba ne lit que les six premières lignes, par position : une clé répétée plus bas ne ferme rien.
    #[test]
    fn usershare_lignes_en_trop() {
        for plus in [
            "guest_ok=n\n",
            "usershare_acl=S-1-5-21-1-2-3-1000:F\n",
            "usershare_acl=S-1-1-0:D\nguest_ok=n\n",
            "path=/srv/autre\n",
            "sharename=autre\n",
        ] {
            let p = usershare("essai", &usershare_type("S-1-1-0:F", "y", plus), Nuance::Aucune);
            assert_eq!(
                p.map(|p| (p.ecriture, p.chemin, p.nom)),
                Some((Some(true), "/srv/essai".to_string(), "essai".to_string())),
                "{plus:?}"
            );
        }
    }

    /// Le jeton de l'invité de Samba porte d'autres groupes que Tout le monde : Réseau, Invités du domaine, ses
    /// identités Unix. Seul un compte nommé, écrit en forme stricte, est compté fermé à l'invité.
    #[test]
    fn usershare_groupes_que_porte_l_invite() {
        for acl in [
            "S-1-5-2:F",
            "S-1-5-21-1-2-3-514:F",
            "S-1-5-21-1-2-3-500:F",
            "S-1-22-1-65534:F",
            "S-1-22-2-65534:F",
            "S-1-5-11:F",
            "S-1-5-32-545:F",
        ] {
            assert!(
                usershare("essai", &usershare_type(acl, "y", ""), Nuance::Aucune).is_some(),
                "{acl}"
            );
        }
        // Comptes nommés : un compte de la base de Samba (RID dès 1000) ou un compte ou groupe Unix ordinaire.
        for acl in [
            "S-1-5-21-1-2-3-1000:F",
            "S-1-22-1-1000:F",
            "S-1-22-2-1001:R",
            "S-1-5-21-1-2-3-1001:F,S-1-22-1-1002:R",
        ] {
            assert_eq!(
                usershare("essai", &usershare_type(acl, "y", ""), Nuance::Aucune),
                None,
                "{acl}"
            );
        }
        // Un refus d'un groupe autre que Tout le monde n'arrête rien : l'invité ne le porte peut-être pas.
        assert!(usershare("essai", &usershare_type("S-1-5-2:D,S-1-1-0:R", "y", ""), Nuance::Aucune).is_some());
    }

    /// exports(5) : une ligne se continue par « \ » en fin de ligne. Recollée avant d'être jugée ; la commande sed ne
    /// commenterait qu'une des lignes : fermeture à la main.
    #[test]
    fn export_nfs_sur_deux_lignes() {
        let p = nfs(
            "/srv/a \\\n    *(rw,sync)\n",
            "/etc/exports.d/a.exports",
            Nuance::Aucune,
        );
        assert_eq!(p.len(), 1, "{p:?}");
        assert_eq!((p[0].chemin.as_str(), p[0].ecriture), ("/srv/a", Some(true)));
        assert_eq!(p[0].fermeture, Vec::<String>::new());
        // Trois lignes, et une ligne simple à côté : celle-ci garde sa commande.
        let p = nfs(
            "/srv/b \\\n  10.0.0.1(rw) \\\n  *(ro)\n/srv/c *(rw)\n",
            "/etc/exports",
            Nuance::Aucune,
        );
        assert_eq!(
            p.iter()
                .map(|x| (x.chemin.as_str(), x.ecriture, x.fermeture.is_empty()))
                .collect::<Vec<_>>(),
            [("/srv/b", Some(false), true), ("/srv/c", Some(true), false)]
        );
    }

    /// Un masque de longueur nulle, sous toutes ses écritures, et un joker fait seulement de « * », « ? » et « . » :
    /// tout le monde. Des options par défaut « -rw » donnent l'écriture aux clients sans options.
    #[test]
    fn export_nfs_tout_le_monde_ecrit_autrement() {
        for client in [
            "0.0.0.0/0.0.0.0",
            "0/0",
            "0.0.0.0/0",
            "::/0",
            "::0/0",
            // Un masque IPv6 écrit en entier, s'il l'est : nul aussi.
            "::/::",
            "*.*",
            "?*",
            "**",
            "*(rw)",
        ] {
            let p = nfs(&format!("/srv/a {client}\n"), "/etc/exports", Nuance::Aucune);
            assert_eq!(p.len(), 1, "{client}");
        }
        for client in [
            "192.168.1.0/24",
            "10.0.0.0/8",
            "*.salon.lan",
            "poste?",
            "192.168.1.0/255.255.255.0",
        ] {
            assert_eq!(
                nfs(&format!("/srv/a {client}\n"), "/etc/exports", Nuance::Aucune),
                Vec::new(),
                "{client}"
            );
        }
        let p = nfs("/srv/a -rw,sync *\n", "/etc/exports", Nuance::Aucune);
        assert_eq!(p.iter().map(|x| x.ecriture).collect::<Vec<_>>(), [Some(true)]);
        // Les options du client l'emportent sur celles par défaut.
        let p = nfs("/srv/a -rw *(ro)\n", "/etc/exports", Nuance::Aucune);
        assert_eq!(p.iter().map(|x| x.ecriture).collect::<Vec<_>>(), [Some(false)]);
    }

    /// Un export sans aucun client : nfs-utils le donne au client par défaut, vide, c'est-à-dire à tout le monde
    /// (de mémoire de son code, non essayé ici) ; les options par défaut décident de l'écriture.
    #[test]
    fn export_nfs_sans_client() {
        for (exports, ecriture) in [
            ("/srv/a\n", false),
            ("/srv/a   \n", false),
            ("/srv/a -rw,sync\n", true),
            ("\"/srv/a b\"\n", false),
        ] {
            let p = nfs(exports, "/etc/exports", Nuance::Aucune);
            assert_eq!(
                p.iter().map(|x| x.ecriture).collect::<Vec<_>>(),
                [Some(ecriture)],
                "{exports:?}"
            );
        }
        // Un client nommé seul, avec ou sans options par défaut : pas tout le monde.
        for exports in ["/srv/a poste1\n", "/srv/a -rw poste1\n"] {
            assert_eq!(nfs(exports, "/etc/exports", Nuance::Aucune), Vec::new(), "{exports:?}");
        }
    }

    /// Le dossier des usershares vient de « usershare path » de [global] quand la configuration le donne.
    #[test]
    fn dossier_des_usershares_lu_dans_la_configuration() {
        let config = "[global]\n\tworkgroup = SALON\n\tusershare path = /srv/partages-perso\n[x]\n\tpath = /x\n";
        assert_eq!(dossier_usershares(config).as_deref(), Some("/srv/partages-perso"));
        assert_eq!(dossier_usershares("[global]\n\tworkgroup = SALON\n"), None);
        // Hors de [global], la clé ne compte pas.
        assert_eq!(dossier_usershares("[x]\n\tusershare path = /ailleurs\n"), None);
    }

    /// Une source illisible n'est jamais « aucun partage ouvert ».
    #[test]
    fn source_illisible_jamais_saine() {
        let c = juger(&[], &[], &["dossier X illisible".to_string()], false);
        assert_eq!(c.len(), 1);
        assert!(
            !c[0].verifie && c[0].message.contains("dossier X illisible"),
            "{}",
            c[0].message
        );
    }

    /// Les usershares d'un dossier jetable : un ouvert, un réservé ; un lien, un sous-dossier et un tube sautés comme
    /// Samba le fait ; un fichier trop gros non lu mais dit, avec son chemin.
    #[cfg(target_os = "linux")]
    #[test]
    fn usershares_lus_dans_le_dossier() {
        let d = dossier_jetable("usershares");
        let ouvert =
            "#VERSION 2\npath=/home/alice/Public\ncomment=\nusershare_acl=S-1-1-0:F\nguest_ok=y\nsharename=Public\n";
        std::fs::write(d.join("public"), ouvert).unwrap();
        std::fs::write(
            d.join("prive"),
            "#VERSION 2\npath=/home/alice/Prive\ncomment=\nusershare_acl=S-1-1-0:F\nguest_ok=n\nsharename=Prive\n",
        )
        .unwrap();
        std::fs::write(d.join("cible"), "rien").unwrap();
        std::os::unix::fs::symlink(d.join("public"), d.join("lien")).unwrap();
        std::fs::create_dir(d.join("sousdossier")).unwrap();
        std::fs::write(d.join("gros"), format!("{ouvert}{}", "#".repeat(17 * 1024))).unwrap();
        // Un tube nommé n'est pas ouvert (l'ouverture attendrait un écrivain) : sauté, sans bloquer.
        crate::essais::tube_nomme(&d.join("tube")).unwrap();
        let mut sources = Vec::new();
        let p = lire_usershares(&d, Nuance::Aucune, &mut sources);
        assert_eq!(p.iter().map(|x| x.nom.as_str()).collect::<Vec<_>>(), ["Public"]);
        assert_eq!(sources.len(), 1, "{sources:?}");
        assert!(sources[0].contains(&*d.join("gros").to_string_lossy()), "{sources:?}");
        // Pas de dossier : rien à lire, rien à dire.
        let mut sources = Vec::new();
        assert_eq!(
            lire_usershares(&d.join("absent"), Nuance::Aucune, &mut sources),
            Vec::new()
        );
        assert_eq!(sources, Vec::<String>::new());
        // Trop de fichiers : la suite est dite non vérifiée.
        let plein = dossier_jetable("usershares-plein");
        for n in 0..=FICHIERS_MAX {
            std::fs::write(plein.join(format!("p{n}")), "#VERSION 2\npath=/x\nguest_ok=n\n").unwrap();
        }
        let mut sources = Vec::new();
        lire_usershares(&plein, Nuance::Aucune, &mut sources);
        assert_eq!(sources.len(), 1, "{sources:?}");
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&plein);
    }

    /// Un dossier des usershares fermé au compte : non vérifié, jamais « rien d'ouvert ».
    #[cfg(target_os = "linux")]
    #[test]
    fn usershares_dossier_illisible() {
        use std::os::unix::fs::PermissionsExt as _;
        if root() {
            crate::essais::saute("root lit un dossier sans droit de lecture");
            return;
        }
        let d = dossier_jetable("usershares-ferme");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o000)).unwrap();
        let mut sources = Vec::new();
        let p = lire_usershares(&d, Nuance::Aucune, &mut sources);
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(p, Vec::new());
        assert_eq!(sources.len(), 1, "{sources:?}");
        let c = juger(&p, &[], &sources, false);
        assert!(c.iter().all(|c| !c.verifie));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// /etc/exports.d/*.exports est lu comme /etc/exports ; un autre nom ne l'est pas (nfs-utils ne le lit pas).
    #[cfg(target_os = "linux")]
    #[test]
    fn exports_d_lus() {
        use std::os::unix::fs::PermissionsExt as _;
        let etc = dossier_jetable("exports");
        std::fs::write(etc.join("exports"), "/srv/sauvegardes 192.168.1.0/24(rw)\n").unwrap();
        std::fs::create_dir(etc.join("exports.d")).unwrap();
        std::fs::write(etc.join("exports.d/tout.exports"), "/ *(rw,no_root_squash)\n").unwrap();
        std::fs::write(etc.join("exports.d/note.txt"), "/srv/note *(rw)\n").unwrap();
        let mut sources = Vec::new();
        let p = lire_exports(&etc, Nuance::Aucune, &mut sources).unwrap();
        assert_eq!(
            p.iter().map(|x| (x.nom.as_str(), x.ecriture)).collect::<Vec<_>>(),
            [("/", Some(true))]
        );
        // La fermeture vise le fichier où la ligne est écrite.
        assert!(
            p[0].fermeture[1].contains("exports.d/tout.exports"),
            "{}",
            p[0].fermeture[1]
        );
        assert!(sources.is_empty(), "{sources:?}");
        // Sans /etc/exports, exports.d seul compte aussi.
        std::fs::remove_file(etc.join("exports")).unwrap();
        assert_eq!(
            lire_exports(&etc, Nuance::Aucune, &mut sources).map(|p| p.len()),
            Some(1)
        );
        // Un fichier illisible : non vérifié.
        if root() {
            crate::essais::saute("root lit un fichier sans droit de lecture");
        } else {
            let ferme = etc.join("exports.d/ferme.exports");
            std::fs::write(&ferme, "/srv/x *(rw)\n").unwrap();
            std::fs::set_permissions(&ferme, std::fs::Permissions::from_mode(0o000)).unwrap();
            let mut sources = Vec::new();
            lire_exports(&etc, Nuance::Aucune, &mut sources);
            assert_eq!(sources.len(), 1, "{sources:?}");
        }
        // Ni /etc/exports ni exports.d : NFS n'est pas configuré.
        let vide = dossier_jetable("exports-vide");
        let mut sources = Vec::new();
        assert_eq!(lire_exports(&vide, Nuance::Aucune, &mut sources), None);
        assert_eq!(sources, Vec::<String>::new());
        let _ = std::fs::remove_dir_all(&etc);
        let _ = std::fs::remove_dir_all(&vide);
    }

    /// Le câblage du bilan Linux : la configuration, le dossier habituel des usershares et celui de la configuration,
    /// exports et exports.d sont tous lus ; un même dossier écrit deux fois ne l'est qu'une fois ; l'état des services
    /// n'est demandé que s'il sert.
    #[cfg(target_os = "linux")]
    #[test]
    fn releve_linux_cable() {
        use std::cell::Cell;
        let d = dossier_jetable("releve");
        let (habituel, config_us, etc) = (d.join("usershares"), d.join("perso"), d.join("etc"));
        for x in [&habituel, &config_us, &etc.join("exports.d")] {
            std::fs::create_dir_all(x).unwrap();
        }
        let us = |nom: &str| {
            format!(
                "#VERSION 2\npath=/home/alice/{nom}\ncomment=\nusershare_acl=S-1-1-0:F\nguest_ok=y\nsharename={nom}\n"
            )
        };
        std::fs::write(habituel.join("public"), us("Public")).unwrap();
        std::fs::write(config_us.join("photos"), us("Photos")).unwrap();
        std::fs::write(etc.join("exports.d/tout.exports"), "/srv/nfs *(rw)\n").unwrap();
        let config = "[global]\n\tworkgroup = SALON\n[invites]\n\tpath = /srv/invites\n\tguest ok = yes\n";
        let appels = Cell::new(0);
        let arrete = || {
            appels.set(appels.get() + 1);
            Some(false)
        };
        // Le dossier de la configuration écrit avec une barre finale, et par un lien : lu une seule fois.
        std::os::unix::fs::symlink(&config_us, d.join("lien")).unwrap();
        let dossiers = [habituel.clone(), config_us.clone(), d.join("perso/"), d.join("lien")];
        let r = relever_dans(
            Some(config),
            "/etc/samba/smb.conf",
            &dossiers,
            &etc,
            Vec::new(),
            arrete,
            arrete,
        );
        let mut noms: Vec<&str> = r.partages.iter().map(|p| p.nom.as_str()).collect();
        noms.sort_unstable();
        assert_eq!(noms, ["/srv/nfs", "Photos", "Public", "invites"]);
        assert!(r.partages.iter().all(|p| p.nuance == Nuance::ServiceArrete));
        assert_eq!(appels.get(), 2);
        assert!(r.sources_illisibles.is_empty(), "{:?}", r.sources_illisibles);
        // Ni Samba ni NFS : systemd n'est pas questionné, et rien d'ouvert.
        let vide = dossier_jetable("releve-vide");
        appels.set(0);
        let r = relever_dans(
            None,
            "/etc/samba/smb.conf",
            &[vide.join("absent")],
            &vide,
            Vec::new(),
            arrete,
            arrete,
        );
        assert_eq!((r.partages.len(), appels.get(), r.service_vu_arrete), (0, 0, false));
        // Une configuration sans partage ouvert, service arrêté : la phrase « rien d'ouvert » le dit.
        let r = relever_dans(
            Some("[global]\n"),
            "/etc/samba/smb.conf",
            &[],
            &vide,
            Vec::new(),
            || Some(false),
            || None,
        );
        assert!(r.service_vu_arrete && r.partages.is_empty());
        // Un dossier des usershares fermé : non vérifié, avec son chemin.
        if root() {
            crate::essais::saute("root lit un dossier sans droit de lecture");
        } else {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&config_us, std::fs::Permissions::from_mode(0o000)).unwrap();
            let r = relever_dans(
                None,
                "/etc/samba/smb.conf",
                std::slice::from_ref(&config_us),
                &vide,
                Vec::new(),
                || None,
                || None,
            );
            std::fs::set_permissions(&config_us, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(r.sources_illisibles.len(), 1, "{:?}", r.sources_illisibles);
        }
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&vide);
    }
}

//! Partages de fichiers ouverts à tout le monde : un dossier partagé sur le réseau sans mot de passe (invité, « Tout
//! le monde »), que n'importe quel appareil du réseau (un visiteur sur le Wi-Fi, un appareil infecté) peut lire, et
//! souvent modifier. Samba et NFS sous Linux, partages SMB sous Windows, Partage de fichiers sous macOS. Un partage
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
    /// `None` : pas su (macOS ne le dit pas).
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
/// ou l'invité désactivé), un par partage illisible, ou un seul « rien d'ouvert ».
fn juger(partages: &[Partage], illisibles: &[Illisible], service_vu_arrete: bool) -> Vec<Constat> {
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
        Some(r) => juger(&r.partages, &r.illisibles, r.service_vu_arrete),
        None => vec![impossible(
            CAT,
            tr!("PowerShell indisponible ou bloqué", "PowerShell unavailable or blocked"),
        )],
    }
}

struct Releve {
    partages: Vec<Partage>,
    illisibles: Vec<Illisible>,
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

/// Les exports NFS ouverts à tous : un client « * », « 0.0.0.0/0 », « ::/0 », ou des options sans client.
#[cfg(any(target_os = "linux", test))]
fn nfs(exports: &str, fichier: &str, nuance: Nuance) -> Vec<Partage> {
    use crate::commande::sh_chaine;
    exports
        .lines()
        .filter_map(|ligne| {
            let utile = ligne.split('#').next()?.trim();
            if utile.is_empty() {
                return None;
            }
            let (chemin, clients) = if let Some(reste) = utile.strip_prefix('"') {
                let (c, r) = reste.split_once('"')?;
                (c, r)
            } else {
                utile.split_once(char::is_whitespace).unwrap_or((utile, ""))
            };
            let ouvert = clients.split_whitespace().find(|c| {
                let hote = c.split('(').next().unwrap_or("");
                matches!(hote, "" | "*" | "0.0.0.0/0" | "::/0")
            })?;
            let options = ouvert.split_once('(').map_or("", |(_, o)| o.trim_end_matches(')'));
            let ecriture = options.split(',').any(|o| o.trim() == "rw");
            let f = sh_chaine(fichier);
            Some(Partage {
                nom: chemin.to_string(),
                chemin: chemin.to_string(),
                a_qui: tr!("tout le monde (NFS, « * »)", "everyone (NFS, “*”)").to_string(),
                ecriture: Some(ecriture),
                nuance,
                fermeture: vec![
                    format!("test -e {f}.avant-vanguard || sudo cp -p {f} {f}.avant-vanguard"),
                    format!(
                        "sudo sed -i {} {f}",
                        sh_chaine(&format!("s/^{}$/# Vanguard : &/", pour_sed(ligne)))
                    ),
                    "sudo exportfs -ra".to_string(),
                ],
            })
        })
        .collect()
}

#[cfg(target_os = "linux")]
mod systeme {
    use super::{Nuance, Releve};

    /// Un service systemd est-il actif ? `None` sans systemd.
    fn actif(noms: &[&str]) -> Option<bool> {
        std::path::Path::new("/run/systemd/system")
            .is_dir()
            .then(|| noms.iter().any(|n| crate::machine::linux::service_actif(n)))
    }

    fn nuance(actif: Option<bool>) -> Nuance {
        if actif == Some(false) {
            Nuance::ServiceArrete
        } else {
            Nuance::Aucune
        }
    }

    // Même signature que sous Windows, où la lecture PowerShell peut échouer.
    #[allow(clippy::unnecessary_wraps)]
    pub fn relever() -> Option<Releve> {
        let mut partages = Vec::new();
        let mut service_vu_arrete = false;
        // testparm donne la configuration réellement appliquée (fichiers inclus, valeurs par défaut) ; sans lui, le
        // fichier lui-même.
        let smb = "/etc/samba/smb.conf";
        if let Some(config) =
            super::super::sortie("testparm", &["-s", "--suppress-prompt"]).or_else(|| std::fs::read_to_string(smb).ok())
        {
            let actif = actif(&["smb", "smbd", "samba"]);
            let trouves = super::samba(&config, smb, nuance(actif));
            service_vu_arrete |= trouves.is_empty() && actif == Some(false);
            partages.extend(trouves);
        }
        let exports = "/etc/exports";
        if let Ok(texte) = std::fs::read_to_string(exports) {
            let actif = actif(&["nfs-server"]);
            let trouves = super::nfs(&texte, exports, nuance(actif));
            service_vu_arrete |= trouves.is_empty() && actif == Some(false);
            partages.extend(trouves);
        }
        Some(Releve {
            partages,
            illisibles: Vec::new(),
            service_vu_arrete,
        })
    }
}

// ───────────────────────────── Windows ─────────────────────────────

/// Les lignes « ACC|partage|chemin|compte|SID|type|droit » : les partages ouverts à Tout le monde (S-1-1-0), aux
/// connexions anonymes (S-1-5-7), aux Invités (S-1-5-32-546) ou au compte invité (…-501), hors partages
/// administratifs. Un partage dont les droits n'ont pas pu être lus (« ? ») est rendu à part.
#[cfg(any(windows, test))]
fn lire_windows(sortie: &str) -> Option<Releve> {
    use crate::commande::{ps_chaine, section};
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
        let ouvert = matches!(sid, "S-1-1-0" | "S-1-5-7" | "S-1-5-32-546")
            || (sid.starts_with("S-1-5-21-") && sid.ends_with("-501"));
        if !ouvert || !genre.eq_ignore_ascii_case("Allow") {
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
        let fermeture = format!(
            "Revoke-SmbShareAccess -Name {} -AccountName {} -Force",
            ps_chaine(nom),
            ps_chaine(compte)
        );
        if let Some(p) = partages.iter_mut().find(|p| p.nom == nom) {
            if !p.a_qui.contains(compte) {
                p.a_qui = format!("{}, {compte}", p.a_qui);
            }
            p.ecriture = Some(p.ecriture.unwrap_or(false) || ecriture);
            p.fermeture.push(fermeture);
        } else {
            partages.push(Partage {
                nom: nom.to_string(),
                chemin: chemin.to_string(),
                a_qui: compte.to_string(),
                ecriture: Some(ecriture),
                nuance,
                fermeture: vec![fermeture],
            });
        }
    }
    Some(Releve {
        partages,
        illisibles,
        service_vu_arrete: !service_lance,
    })
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

// ───────────────────────────── macOS ─────────────────────────────

/// Les points de partage de `sharing -l` dont un protocole (smb, afp, ftp) est partagé avec l'accès invité.
#[cfg(any(target_os = "macos", test))]
fn lire_sharing(sortie: &str, nuance: Nuance, dossier_modifiable: impl Fn(&str) -> Option<bool>) -> Vec<Partage> {
    use crate::commande::sh_chaine;
    let mut partages = Vec::new();
    let (mut nom, mut chemin, mut partage, mut invite) = (String::new(), String::new(), false, false);
    let mut ouvert = false;
    let clore = |nom: &str, chemin: &str, ouvert: bool, partages: &mut Vec<Partage>| {
        if ouvert && !nom.is_empty() {
            partages.push(Partage {
                nom: nom.to_string(),
                chemin: chemin.to_string(),
                a_qui: tr!("l'invité (sans mot de passe)", "the guest (no password)").to_string(),
                ecriture: dossier_modifiable(chemin),
                nuance,
                fermeture: vec![format!("sudo sharing -e {} -g 000", sh_chaine(nom))],
            });
        }
    };
    for ligne in sortie.lines() {
        let indente = ligne.starts_with(['\t', ' ']);
        let (cle, valeur) = ligne
            .trim()
            .split_once(':')
            .map_or(("", ""), |(c, v)| (c.trim(), v.trim()));
        match (indente, cle) {
            (false, "name") => {
                clore(&nom, &chemin, ouvert, &mut partages);
                nom = valeur.to_string();
                chemin.clear();
                ouvert = false;
            }
            (false, "path") => chemin = valeur.to_string(),
            (true, "afp" | "smb" | "ftp") => (partage, invite) = (false, false),
            (true, "shared") => partage = valeur == "1",
            (true, "guest access") => invite = valeur == "1",
            (true, "") if ligne.trim() == "}" => ouvert |= partage && invite,
            _ => {}
        }
    }
    clore(&nom, &chemin, ouvert, &mut partages);
    partages
}

#[cfg(target_os = "macos")]
mod systeme {
    use super::{Nuance, Releve};

    pub fn relever() -> Option<Releve> {
        let sortie = super::super::sortie("sharing", &["-l"])?;
        // smbd et AppleFileServer ne tournent que si le partage de fichiers est activé.
        // Demandé au noyau ; pgrep -x en secours quand la liste des processus ne se lit pas.
        let lance = ["smbd", "AppleFileServer"].iter().any(|p| {
            crate::machine::macos::noyau::en_marche(p).unwrap_or_else(|| {
                crate::commande::lancer(std::process::Command::new("pgrep").args(["-x", p]), 10)
                    .is_some_and(|r| r.code == Some(0))
            })
        });
        let nuance = if lance { Nuance::Aucune } else { Nuance::ServiceArrete };
        let modifiable = |chemin: &str| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(chemin)
                .ok()
                .map(|m| m.permissions().mode() & 0o002 != 0)
        };
        let partages = super::lire_sharing(&sortie, nuance, modifiable);
        Some(Releve {
            service_vu_arrete: partages.is_empty() && !lance,
            partages,
            illisibles: Vec::new(),
        })
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
        let rien = juger(&[], &[], false);
        assert!(rien[0].probleme.is_none() && rien[0].verifie);
        assert!(juger(&[], &[], true)[0].message.contains("pas lancé"));
        let ecriture = juger(&[partage("Public", Some(true), Nuance::Aucune, &["x"])], &[], false);
        assert_eq!(ecriture[0].probleme, Some(Niveau::Eleve));
        assert!(
            ecriture[0].message.contains("lire et modifier"),
            "{}",
            ecriture[0].message
        );
        assert!(ecriture[0].correctif.as_ref().unwrap().automatique);
        let lecture = juger(&[partage("Public", Some(false), Nuance::Aucune, &[])], &[], false);
        assert_eq!(lecture[0].probleme, Some(Niveau::Moyen));
        assert!(!lecture[0].correctif.as_ref().unwrap().automatique);
        // Service arrêté ou invité désactivé : un cran plus bas, et la nuance est dite.
        let arrete = juger(&[partage("Public", Some(true), Nuance::ServiceArrete, &[])], &[], false);
        assert_eq!(arrete[0].probleme, Some(Niveau::Moyen));
        assert!(arrete[0].message.contains("inoffensif"), "{}", arrete[0].message);
        let invite = juger(
            &[partage("Public", Some(false), Nuance::InviteDesactive, &[])],
            &[],
            false,
        );
        assert_eq!(invite[0].probleme, Some(Niveau::Info));
        let inconnu = juger(&[partage("Public", None, Nuance::Aucune, &[])], &[], false);
        assert_eq!(inconnu[0].probleme, Some(Niveau::Eleve));
        assert!(inconnu[0].message.contains("y accéder"));
        // Un partage illisible n'est jamais compté sain.
        let illisible = juger(&[], &[Illisible { nom: "Docs".into() }], false);
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
        let dossier = std::env::temp_dir().join(format!("vanguard-smb-{}", std::process::id()));
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
        assert_eq!(
            r.partages[0].fermeture,
            ["Revoke-SmbShareAccess -Name 'Public' -AccountName 'Tout le monde' -Force"]
        );
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
        // Sans la section des accès (PowerShell tombé), rien n'est conclu.
        assert!(lire_windows("INV|True\nINV_FIN\n").is_none());
    }

    /// Section INV absente : l'invité n'est pas dit désactivé et rien n'est tempéré ; « INV| »
    /// (pas de compte invité) vaut désactivé.
    #[test]
    fn invite_non_lu() {
        let r = lire_windows("ACC|P|C:\\P|Everyone|S-1-1-0|Allow|Full\nACC_FIN\nSRV|Running\nSRV_FIN\n").unwrap();
        assert_eq!(r.partages[0].nuance, Nuance::InviteNonLu);
        let c = juger(&r.partages, &[], false);
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

    #[test]
    fn lecture_de_sharing_macos() {
        let sortie = "List of Share Points\nname:\t\tPublic\npath:\t\t/Users/alice/Public\n\
                      \tafp:\t\t{\n\t\tname:\t\tPublic\n\t\tshared:\t\t1\n\t\tguest access:\t1\n\t\tinherit perms:\t0\n\t}\n\
                      \tftp:\t\t{\n\t\tname:\t\tPublic\n\t\tshared:\t\t0\n\t\tguest access:\t0\n\t}\n\
                      \tsmb:\t\t{\n\t\tname:\t\tPublic\n\t\tshared:\t\t1\n\t\tguest access:\t1\n\t}\n\
                      name:\t\tTravail\npath:\t\t/Users/alice/Travail\n\
                      \tafp:\t\t{\n\t\tshared:\t\t0\n\t\tguest access:\t1\n\t}\n\
                      \tsmb:\t\t{\n\t\tshared:\t\t1\n\t\tguest access:\t0\n\t}\n";
        let p = lire_sharing(sortie, Nuance::Aucune, |chemin| Some(chemin.ends_with("Public")));
        assert_eq!(p.len(), 1, "{p:#?}");
        assert_eq!(
            (p[0].nom.as_str(), p[0].chemin.as_str(), p[0].ecriture),
            ("Public", "/Users/alice/Public", Some(true))
        );
        assert_eq!(p[0].fermeture, ["sudo sharing -e 'Public' -g 000"]);
    }
}

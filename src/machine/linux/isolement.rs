//! L'isolement de Linux (Défense R4), côté root : la table `inet vanguard_isolement` (`nftables::isolement`), son état
//! noté dans un dossier à root, et sa persistance par sa propre unité, `vanguard-isolement.service` (oneshot), jamais
//! par le garde L3 (`PrivateNetwork=yes` : il ne voit pas le réseau de la machine).
//!
//! - Isoler : la table d'abord (l'isolement compte dès qu'elle est relue) ; puis, avec systemd, l'état dans
//!   /var/lib/vanguard/isolement, une copie de l'assistant root dans /opt/vanguard/isolement et l'unité, activée ;
//!   sans systemd (ou si la persistance échoue), l'état dans /run/vanguard/isolement et la note « jusqu'au
//!   redémarrage ».
//! - Au démarrage (`vanguard isolement-demarrage`, sous-commande cachée lancée par l'unité avant le réseau) : l'état
//!   relu, la même table remise ; un état absent ou abîmé isole sans rien garder (jamais ouvrir faute de note).
//! - Lever : l'unité désactivée, ses fichiers et l'état retirés, puis la table supprimée par son nom ; rien ne dépend
//!   de l'état noté.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::machine::gestes_unix::ActionUnite;
use crate::machine::linux::garde::poser::{agir_sur, copier_soi, dossier_root, ecrire_root, recharger};
use crate::machine::linux::nftables::isolement as table;
use crate::protection::blocage::ordres::Resultat;
use crate::protection::isolement::{Etat, Permis, etat_texte, lire_etat};
use crate::{tr, trf};

/// Le nom de l'unité.
pub(crate) const UNITE: &str = "vanguard-isolement.service";
/// Le fichier de l'unité.
pub(crate) const FICHIER_UNITE: &str = "/etc/systemd/system/vanguard-isolement.service";
/// Le lien d'activation (WantedBy=sysinit.target), retiré aussi à la main si systemd ne répond pas.
const LIEN_UNITE: &str = "/etc/systemd/system/sysinit.target.wants/vanguard-isolement.service";
/// Le dossier du programme lancé par l'unité, et le programme : une copie de l'assistant root, root:root 0755.
pub(crate) const DOSSIER_PROGRAMME: &str = "/opt/vanguard/isolement";
pub(crate) const PROGRAMME: &str = "/opt/vanguard/isolement/vanguard";
/// L'état d'un isolement qui dure (relu au démarrage), et celui d'un isolement « jusqu'au redémarrage ».
const DOSSIER_ETAT: &str = "/var/lib/vanguard/isolement";
const ETAT: &str = "/var/lib/vanguard/isolement/etat";
const DOSSIER_ETAT_RUN: &str = "/run/vanguard/isolement";
const ETAT_RUN: &str = "/run/vanguard/isolement/etat";
/// Un état plus gros n'est pas lu.
const ETAT_TAILLE_MAX: u64 = 16 * 1024;

/// Le texte de l'unité : lancée avant le réseau, elle remet la table et reste « active » ; relancée avec nftables.service
/// (`PartOf`, `ReloadPropagatedFrom` : un `flush ruleset` de nftables ne l'efface pas pour de bon). Jamais
/// `PrivateNetwork` : elle agit sur le réseau de la machine.
pub(crate) fn texte_unite() -> String {
    format!(
        "\
# Posée par Vanguard (isolement de l'ordinateur), retirée par « vanguard blocage annuler ».
[Unit]
Description=Vanguard : isolement de l'ordinateur du réseau
DefaultDependencies=no
After=local-fs.target nftables.service firewalld.service
Before=network-pre.target shutdown.target
Wants=network-pre.target
Conflicts=shutdown.target
PartOf=nftables.service
ReloadPropagatedFrom=nftables.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={PROGRAMME} isolement-demarrage
ExecReload={PROGRAMME} isolement-demarrage
TimeoutStartSec=30
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
RestrictAddressFamilies=AF_NETLINK AF_UNIX
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
UMask=0022

[Install]
WantedBy=sysinit.target
"
    )
}

/// Secondes depuis 1970.
fn maintenant() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

/// systemd est-il le gestionnaire de ce démarrage ?
fn systemd() -> bool {
    Path::new("/run/systemd/system").is_dir()
}

/// Ce qui est gardé, en une phrase pour la note.
fn resume(permis: &Permis) -> String {
    let mut t = trf!(
        "{} session(s) à distance, {} adresse(s) des serveurs de Vanguard, {} DNS gardés",
        "{} remote session(s), {} Vanguard server address(es), {} DNS kept",
        permis.garder.len(),
        permis.serveurs.len(),
        permis.dns.len()
    );
    if permis.serveurs.is_empty() {
        t.push_str(tr!(
            " ; aucun serveur de Vanguard ne s'est résolu : ni mises à jour ni listes pendant l'isolement",
            "; no Vanguard server resolved: no updates or lists during the isolation"
        ));
    }
    if permis.dns.is_empty() {
        t.push_str(tr!(
            " ; aucun DNS hors de la boucle locale : les noms ne se résoudront plus",
            "; no DNS outside loopback: names will no longer resolve"
        ));
    }
    t
}

/// Isole (root) : la table, puis sa persistance.
pub(crate) fn isoler(permis: &Permis) -> Resultat {
    if let Err(e) = table::isoler(permis) {
        return Resultat::echec(e.to_string());
    }
    let etat = Etat {
        depuis: maintenant(),
        permis: permis.clone(),
    };
    let texte = etat_texte(&etat);
    let gardes = resume(permis);
    if systemd() {
        match persister(&texte) {
            Ok(()) => {
                let _ = std::fs::remove_file(ETAT_RUN);
                return Resultat::ok_note(trf!(
                    "{gardes} ; remis à chaque démarrage par {UNITE}",
                    "{gardes}; set again at each start by {UNITE}"
                ));
            }
            Err(e) => {
                return jusqu_au_redemarrage(&texte, &gardes, Some(&e.to_string()));
            }
        }
    }
    jusqu_au_redemarrage(&texte, &gardes, None)
}

/// L'état, la copie du programme et l'unité, activée (et lancée : elle remet la même table, et suit nftables.service).
fn persister(texte: &str) -> Result<(), crate::modele::Echec> {
    dossier_root(Path::new(DOSSIER_ETAT))?;
    ecrire_root(Path::new(ETAT), texte.as_bytes(), 0o644)?;
    copier_soi(Path::new(DOSSIER_PROGRAMME), Path::new(PROGRAMME))?;
    ecrire_root(Path::new(FICHIER_UNITE), texte_unite().as_bytes(), 0o644)?;
    recharger()?;
    agir_sur(UNITE, ActionUnite::Activer, &["enable", "--now"])
}

/// L'isolement sans persistance : l'état dans /run (effacé au redémarrage), et la note qui le dit.
fn jusqu_au_redemarrage(texte: &str, gardes: &str, pourquoi: Option<&str>) -> Resultat {
    // Un état durable d'une persistance à moitié faite est retiré : l'unité ne doit pas remettre un isolement que la
    // note dit fini au redémarrage.
    let _ = std::fs::remove_file(ETAT);
    let ecrit = dossier_root(Path::new(DOSSIER_ETAT_RUN))
        .and_then(|()| ecrire_root(Path::new(ETAT_RUN), texte.as_bytes(), 0o644));
    let mut note = trf!(
        "{gardes} ; jusqu'au redémarrage seulement",
        "{gardes}; until restart only"
    );
    if let Some(p) = pourquoi {
        note.push_str(&trf!(" (unité non posée : {p})", " (unit not set up: {p})"));
    }
    if let Err(e) = ecrit {
        note.push_str(&trf!(
            " ; état non noté ({e}) : le bandeau ne le dira pas",
            "; state not recorded ({e}): the banner will not show it"
        ));
    }
    Resultat::ok_note(note)
}

/// Lève (root) : l'unité et ses fichiers, l'état, puis la table, par leurs noms.
pub(crate) fn lever() -> Resultat {
    let mut notes: Vec<String> = Vec::new();
    if Path::new(FICHIER_UNITE).exists()
        && let Err(e) = agir_sur(UNITE, ActionUnite::Desactiver, &["disable", "--now"])
    {
        notes.push(e.to_string());
    }
    // Le lien d'activation, s'il reste (systemd n'a pas répondu) : un lien seulement, jamais un fichier.
    if std::fs::symlink_metadata(LIEN_UNITE).is_ok_and(|m| m.file_type().is_symlink())
        && let Err(e) = std::fs::remove_file(LIEN_UNITE)
    {
        notes.push(format!("{LIEN_UNITE}: {e}"));
    }
    for f in [FICHIER_UNITE, PROGRAMME, ETAT, ETAT_RUN] {
        match std::fs::remove_file(f) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => notes.push(format!("{f}: {e}")),
        }
    }
    if systemd()
        && let Err(e) = recharger()
    {
        notes.push(e.to_string());
    }
    for d in [
        DOSSIER_PROGRAMME,
        "/opt/vanguard",
        DOSSIER_ETAT,
        "/var/lib/vanguard",
        DOSSIER_ETAT_RUN,
        "/run/vanguard",
    ] {
        let _ = std::fs::remove_dir(d);
    }
    match table::lever() {
        Err(e) => {
            notes.insert(0, e.to_string());
            Resultat::echec(notes.join(" ; "))
        }
        Ok(retiree) => {
            if !retiree {
                notes.insert(
                    0,
                    tr!(
                        "la table de l'isolement n'était pas là",
                        "the isolation table was not there"
                    )
                    .to_string(),
                );
            }
            if notes.is_empty() {
                Resultat::ok()
            } else {
                Resultat::ok_note(notes.join(" ; "))
            }
        }
    }
}

/// L'état noté, lu sans suivre de lien, seulement s'il est à root et que personne d'autre ne peut l'écrire.
fn lire_note(chemin: &str) -> Option<Etat> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(chemin)
        .ok()?;
    let m = f.metadata().ok()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 || m.len() > ETAT_TAILLE_MAX {
        return None;
    }
    let dossier = std::fs::symlink_metadata(Path::new(chemin).parent()?).ok()?;
    if !dossier.is_dir() || dossier.uid() != 0 || dossier.mode() & 0o022 != 0 {
        return None;
    }
    let mut texte = String::new();
    f.take(ETAT_TAILLE_MAX).read_to_string(&mut texte).ok()?;
    lire_etat(&texte)
}

/// L'isolement noté (durable, sinon jusqu'au redémarrage) : ce que lit le bandeau.
pub(crate) fn notee() -> Option<Etat> {
    lire_note(ETAT).or_else(|| lire_note(ETAT_RUN))
}

/// `vanguard isolement-demarrage`, lancé par l'unité : la table remise d'après l'état durable. Un état absent ou
/// abîmé isole sans rien garder (boucle locale, DHCP et découverte des voisins seulement) : l'unité n'existe que
/// pendant un isolement, et une note perdue ne doit pas le lever.
pub(crate) fn demarrage() -> i32 {
    if crate::socle::euid() != 0 {
        eprintln!("vanguard isolement-demarrage : root seulement");
        return 1;
    }
    let permis = if let Some(e) = lire_note(ETAT) {
        e.permis
    } else {
        eprintln!("vanguard isolement-demarrage : état absent ou abîmé ({ETAT}), isolement sans exception");
        Permis::default()
    };
    match table::isoler(&permis) {
        Ok(()) => {
            eprintln!(
                "vanguard isolement-demarrage : isolé ({} session(s), {} serveur(s), {} DNS gardés)",
                permis.garder.len(),
                permis.serveurs.len(),
                permis.dns.len()
            );
            0
        }
        Err(e) => {
            eprintln!("vanguard isolement-demarrage : {e}");
            1
        }
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    fn directives(t: &str) -> Vec<(&str, &str)> {
        t.lines()
            .filter(|l| !l.starts_with(['#', '[']) && !l.is_empty())
            .filter_map(|l| l.split_once('='))
            .collect()
    }

    #[test]
    fn unite_de_l_isolement() {
        let t = texte_unite();
        let d = directives(&t);
        let valeur = |cle: &str| {
            let v: Vec<&str> = d.iter().filter(|(c, _)| *c == cle).map(|(_, v)| *v).collect();
            assert!(v.len() <= 1, "{cle} en double");
            v.first().copied()
        };
        for (cle, attendu) in [
            ("DefaultDependencies", "no"),
            ("Before", "network-pre.target shutdown.target"),
            ("Wants", "network-pre.target"),
            ("PartOf", "nftables.service"),
            ("ReloadPropagatedFrom", "nftables.service"),
            ("Type", "oneshot"),
            ("RemainAfterExit", "yes"),
            ("ExecStart", "/opt/vanguard/isolement/vanguard isolement-demarrage"),
            ("ExecReload", "/opt/vanguard/isolement/vanguard isolement-demarrage"),
            ("CapabilityBoundingSet", "CAP_NET_ADMIN"),
            ("NoNewPrivileges", "yes"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "yes"),
            ("RestrictAddressFamilies", "AF_NETLINK AF_UNIX"),
            ("SystemCallArchitectures", "native"),
            ("WantedBy", "sysinit.target"),
        ] {
            assert_eq!(valeur(cle), Some(attendu), "{cle}");
        }
        // Jamais le réseau privé du garde : l'unité agit sur celui de la machine.
        assert_eq!(valeur("PrivateNetwork"), None);
        assert!(LIEN_UNITE.ends_with(UNITE) && FICHIER_UNITE.ends_with(UNITE));
        assert!(PROGRAMME.starts_with(DOSSIER_PROGRAMME));
    }

    #[test]
    fn note_lue_seulement_a_root() {
        // Un fichier du compte (essais : jamais root) n'est jamais pris pour l'état.
        let d = crate::essais::Jetable::nouveau("isolement-note");
        let f = d.join("etat");
        let e = Etat {
            depuis: 1_700_000_000,
            permis: Permis::default(),
        };
        std::fs::write(&f, etat_texte(&e)).unwrap();
        if crate::socle::euid() != 0 {
            assert_eq!(lire_note(f.to_str().unwrap()), None);
        }
    }

    #[test]
    fn resume_dit_ce_qui_manque() {
        let r = resume(&Permis::default());
        assert!(r.contains('0'), "{r}");
        assert!(r.contains(tr!("aucun serveur", "no Vanguard server")), "{r}");
        assert!(r.contains(tr!("aucun DNS", "no DNS")), "{r}");
    }
}

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
//! - Lever : la table supprimée par son nom d'abord ; seulement si c'est fait, l'unité désactivée, ses fichiers et
//!   l'état retirés (un échec laisse tout, et le bandeau qui le dit), puis la table supprimée encore une fois (un
//!   `systemctl restart nftables` pendant la levée a pu la remettre par l'unité). Rien ne dépend de l'état noté.
//! - En place : l'état lu, sinon une trace (état illisible, unité, copie), sinon, en root, la table elle-même.

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
            " ; aucun serveur de Vanguard gardé : ni mise à jour ni liste de menaces jusqu'à la levée",
            "; no Vanguard server kept: no update or threat list until it is lifted"
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
    // Une persistance à moitié faite est défaite (unité désactivée, son fichier, la copie et l'état durable retirés) :
    // l'unité ne doit pas remettre au redémarrage un isolement que la note dit fini au redémarrage.
    let restes = if pourquoi.is_some() {
        retirer_persistance()
    } else {
        let _ = std::fs::remove_file(ETAT);
        Vec::new()
    };
    let ecrit = dossier_root(Path::new(DOSSIER_ETAT_RUN))
        .and_then(|()| ecrire_root(Path::new(ETAT_RUN), texte.as_bytes(), 0o644));
    let mut note = trf!(
        "{gardes} ; jusqu'au redémarrage seulement",
        "{gardes}; until restart only"
    );
    if let Some(p) = pourquoi {
        note.push_str(&trf!(" (unité non posée : {p})", " (unit not set up: {p})"));
    }
    if !restes.is_empty() {
        let r = restes.join(" ; ");
        note.push_str(&trf!(
            " ; persistance à moitié faite non défaite ({r}) : l'isolement peut revenir au redémarrage, « vanguard blocage annuler » le lève",
            "; half-done persistence not undone ({r}): the isolation may come back at restart, “vanguard blocking undo” lifts it"
        ));
    }
    if let Err(e) = ecrit {
        note.push_str(&trf!(
            " ; état non noté ({e}) : le bandeau ne le dira pas",
            "; state not recorded ({e}): the banner will not show it"
        ));
    }
    Resultat::ok_note(note)
}

/// Les fichiers de la persistance : l'état durable, l'unité et la copie du programme (le lien d'activation à part).
const PERSISTANCE: [&str; 3] = [ETAT, FICHIER_UNITE, PROGRAMME];

/// Toutes les traces de l'isolement sur le disque : ce que lit le bandeau quand l'état ne l'est pas.
const TRACES: [&str; 4] = [ETAT, ETAT_RUN, FICHIER_UNITE, PROGRAMME];

/// Retire des fichiers par leur chemin absolu, pris sous `racine` (« / », ou un dossier jetable dans les essais) : un
/// fichier absent n'est pas une erreur ; rend ceux qui n'ont pas pu l'être, avec la raison.
fn retirer_fichiers(racine: &Path, chemins: &[&str]) -> Vec<String> {
    let mut restes = Vec::new();
    for f in chemins {
        let chemin = racine.join(f.trim_start_matches('/'));
        match std::fs::remove_file(&chemin) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => restes.push(format!("{f}: {e}")),
        }
    }
    restes
}

/// Désactive l'unité (root, au mieux) et retire son lien d'activation s'il reste : l'isolement ne revient plus au
/// démarrage ni par un rechargement de nftables, mais ses fichiers (état, unité, copie) restent, et le bandeau avec.
/// Rend ce qui n'a pas pu l'être. Ne touche jamais à la table.
fn desactiver_unite() -> Vec<String> {
    let mut restes: Vec<String> = Vec::new();
    if Path::new(FICHIER_UNITE).exists()
        && let Err(e) = agir_sur(UNITE, ActionUnite::Desactiver, &["disable", "--now"])
    {
        restes.push(e.to_string());
    }
    // Le lien d'activation, s'il reste (systemd n'a pas répondu) : un lien seulement, jamais un fichier.
    if std::fs::symlink_metadata(LIEN_UNITE).is_ok_and(|m| m.file_type().is_symlink())
        && let Err(e) = std::fs::remove_file(LIEN_UNITE)
    {
        restes.push(format!("{LIEN_UNITE}: {e}"));
    }
    restes
}

/// Recharge systemd après le retrait du fichier de l'unité (sans systemd, rien à faire).
fn recharger_systemd() -> Vec<String> {
    if systemd()
        && let Err(e) = recharger()
    {
        return vec![e.to_string()];
    }
    Vec::new()
}

/// Défait la persistance (root) : l'unité désactivée (au mieux), son lien s'il reste, ses fichiers et l'état durable
/// retirés, systemd rechargé. Rend ce qui n'a pas pu l'être. Ne touche jamais à la table.
fn retirer_persistance() -> Vec<String> {
    let mut restes = desactiver_unite();
    restes.extend(retirer_fichiers(Path::new("/"), &PERSISTANCE));
    restes.extend(recharger_systemd());
    restes
}

/// Efface les traces de l'isolement (root), une fois la table partie pour de bon : état durable et de session, unité,
/// copie du programme, leurs dossiers vides ; systemd rechargé. Rend ce qui n'a pas pu l'être.
fn effacer_traces() -> Vec<String> {
    let mut restes = retirer_fichiers(Path::new("/"), &TRACES);
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
    restes.extend(recharger_systemd());
    restes
}

/// Lève (root) : la table d'abord, par son nom ; seulement si c'est fait, l'unité désactivée, puis la table encore une
/// fois (un rechargement de nftables pendant la levée a pu la remettre par l'unité, `PartOf`) ; et seulement si ce
/// 2e retrait est fait aussi, l'état et l'unité effacés.
pub(crate) fn lever() -> Resultat {
    lever_par(table::lever, desactiver_unite, effacer_traces)
}

/// La levée, ses gestes passés en paramètres (les essais les remplacent). Tant qu'une table peut rester, les traces
/// (état, unité, copie) restent elles aussi : le bandeau ne disparaît jamais d'un ordinateur encore isolé, même pour un
/// compte qui ne peut pas lire nftables.
fn lever_par(
    mut retirer_table: impl FnMut() -> Result<bool, crate::modele::Echec>,
    desactiver: impl FnOnce() -> Vec<String>,
    effacer: impl FnOnce() -> Vec<String>,
) -> Resultat {
    let retiree = match retirer_table() {
        Ok(r) => r,
        Err(e) => {
            return Resultat::echec(trf!(
                "{e} ; rien d'autre n'est retiré : l'isolement, son état et son unité restent en place",
                "{e}; nothing else is removed: the isolation, its state and its unit stay in place"
            ));
        }
    };
    let mut notes: Vec<String> = Vec::new();
    if !retiree {
        notes.push(
            tr!(
                "la table de l'isolement n'était pas là",
                "the isolation table was not there"
            )
            .to_string(),
        );
    }
    notes.extend(desactiver());
    match retirer_table() {
        Ok(false) => {}
        Ok(true) => notes.push(
            tr!(
                "la table était revenue pendant la levée (nftables rechargé) : retirée de nouveau",
                "the table came back during the lift (nftables reloaded): removed again"
            )
            .to_string(),
        ),
        Err(e) => {
            notes.insert(
                0,
                trf!(
                    "la table est revenue pendant la levée et n'a pas pu être retirée de nouveau ({e}) : l'état et l'unité restent en place ; relancez « vanguard blocage annuler »",
                    "the table came back during the lift and could not be removed again ({e}): the state and the unit stay in place; run “vanguard blocking undo” again"
                ),
            );
            return Resultat::echec(notes.join(" ; "));
        }
    }
    notes.extend(effacer());
    if notes.is_empty() {
        Resultat::ok()
    } else {
        Resultat::ok_note(notes.join(" ; "))
    }
}

/// L'état noté, lu sans suivre de lien, seulement s'il est à root et que personne d'autre ne peut l'écrire.
fn lire_note(chemin: &str) -> Option<Etat> {
    lire_etat(&texte_note(chemin)?)
}

/// Le texte de l'état noté, aux mêmes conditions que `lire_note`.
fn texte_note(chemin: &str) -> Option<String> {
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
    Some(texte)
}

/// L'isolement noté (durable, sinon jusqu'au redémarrage) : ce que lit le bandeau.
fn notee() -> Option<Etat> {
    lire_note(ETAT).or_else(|| lire_note(ETAT_RUN))
}

/// Une trace de l'isolement sous `racine` (« / » hors essais) : un état (même illisible ou abîmé), l'unité ou la copie
/// du programme. Un lien compte aussi (`symlink_metadata`) : la trace est montrée, jamais suivie.
fn trace_sous(racine: &Path) -> bool {
    TRACES
        .iter()
        .any(|f| std::fs::symlink_metadata(racine.join(f.trim_start_matches('/'))).is_ok())
}

/// L'isolement est-il en place ? L'état lu donne sa date ; sinon une trace, ou (en root, qui seul peut lire nftables)
/// la table elle-même, donnent `Some(0)` (date inconnue) : un isolement présent sans état garde son bandeau et sa
/// levée. Sans root, une table seule (sans aucune trace) n'est pas vue.
pub(crate) fn en_place() -> Option<i64> {
    if let Some(e) = notee() {
        return Some(e.depuis);
    }
    if trace_sous(Path::new("/")) {
        return Some(0);
    }
    (crate::socle::euid() == 0 && table::presente().unwrap_or(false)).then_some(0)
}

/// Ce que remet le démarrage d'après le texte de l'état durable (`None` : absent ou illisible), et s'il a été lu. Un
/// état absent ou abîmé ne garde rien : jamais ouvrir faute de note.
fn permis_au_demarrage(texte: Option<&str>) -> (Permis, bool) {
    texte
        .and_then(lire_etat)
        .map_or_else(|| (Permis::default(), false), |e| (e.permis, true))
}

/// `vanguard isolement-demarrage`, lancé par l'unité : la table remise d'après l'état durable. Un état absent ou
/// abîmé isole sans rien garder (boucle locale, DHCP et découverte des voisins seulement) : l'unité n'existe que
/// pendant un isolement, et une note perdue ne doit pas le lever.
pub(crate) fn demarrage() -> i32 {
    if crate::socle::euid() != 0 {
        eprintln!("vanguard isolement-demarrage : root seulement");
        return 1;
    }
    let (permis, lu) = permis_au_demarrage(texte_note(ETAT).as_deref());
    if !lu {
        eprintln!("vanguard isolement-demarrage : état absent ou abîmé ({ETAT}), isolement sans exception");
    }
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

    /// M2/B4 : les fichiers de la persistance sont retirés par leur chemin (pris sous un dossier jetable ici) ; un
    /// absent n'est pas une erreur, un qui ne peut pas l'être est rendu.
    #[test]
    fn retirer_fichiers_rend_ce_qui_reste() {
        let d = crate::essais::Jetable::nouveau("isolement-retirer");
        assert_eq!(PERSISTANCE, [ETAT, FICHIER_UNITE, PROGRAMME]);
        for f in [ETAT, FICHIER_UNITE] {
            let c = d.join(f.trim_start_matches('/'));
            std::fs::create_dir_all(c.parent().unwrap()).unwrap();
            std::fs::write(&c, "x").unwrap();
        }
        // La copie du programme absente : rien à redire.
        assert_eq!(retirer_fichiers(&d, &PERSISTANCE), Vec::<String>::new());
        for f in PERSISTANCE {
            assert!(!d.join(f.trim_start_matches('/')).exists(), "{f}");
        }
        // Un dossier à la place d'un fichier n'est pas retiré (jamais un dossier) : il est rendu.
        std::fs::create_dir_all(d.join(ETAT_RUN.trim_start_matches('/'))).unwrap();
        let restes = retirer_fichiers(&d, &[ETAT_RUN]);
        assert_eq!(restes.len(), 1, "{restes:?}");
        assert!(restes[0].starts_with(ETAT_RUN), "{restes:?}");
    }

    /// M2 : une trace de l'isolement (état, même abîmé ; unité ; copie ; même un lien) suffit à le dire en place.
    #[test]
    fn une_trace_suffit() {
        for f in [ETAT, ETAT_RUN, FICHIER_UNITE, PROGRAMME] {
            let d = crate::essais::Jetable::nouveau("isolement-trace");
            assert!(!trace_sous(&d));
            let c = d.join(f.trim_start_matches('/'));
            std::fs::create_dir_all(c.parent().unwrap()).unwrap();
            std::fs::write(&c, "abîmé").unwrap();
            assert!(trace_sous(&d), "{f}");
            std::fs::remove_file(&c).unwrap();
            std::os::unix::fs::symlink("/nulle-part", &c).unwrap();
            assert!(trace_sous(&d), "lien {f}");
        }
    }

    /// C3 : la levée n'efface l'état et l'unité qu'après le retrait réussi des deux tables ; un 2e retrait qui échoue
    /// (la table revenue par un rechargement de nftables) laisse toutes les traces, donc le bandeau, en place.
    #[test]
    fn deuxieme_retrait_qui_echoue_garde_les_traces() {
        use crate::modele::Echec;
        let d = crate::essais::Jetable::nouveau("isolement-levee");
        let poser = || {
            for f in TRACES {
                let c = d.join(f.trim_start_matches('/'));
                std::fs::create_dir_all(c.parent().unwrap()).unwrap();
                std::fs::write(&c, "x").unwrap();
            }
        };
        poser();
        let (mut retraits, mut desactivee) = (0, false);
        let r = lever_par(
            || {
                retraits += 1;
                if retraits == 1 {
                    Ok(true)
                } else {
                    Err(Echec::echoue("essai", "netlink indisponible"))
                }
            },
            || {
                desactivee = true;
                Vec::new()
            },
            || retirer_fichiers(&d, &TRACES),
        );
        assert!(!r.reussi, "{r:?}");
        assert!(
            r.raison.contains("netlink indisponible") && r.raison.contains("relancez"),
            "{r:?}"
        );
        assert_eq!(retraits, 2);
        assert!(desactivee);
        for f in TRACES {
            assert!(d.join(f.trim_start_matches('/')).exists(), "{f}");
        }
        assert!(trace_sous(&d));

        // Le 1er retrait échoue : rien n'est désactivé ni effacé.
        let mut touche = false;
        let r = lever_par(
            || Err(Echec::echoue("essai", "netlink indisponible")),
            || {
                touche = true;
                Vec::new()
            },
            || retirer_fichiers(&d, &TRACES),
        );
        assert!(!r.reussi && !touche, "{r:?}");
        assert!(trace_sous(&d));

        // Les deux retraits faits (la table revenue, retirée de nouveau) : les traces partent, et le bandeau avec.
        let mut retraits = 0;
        let r = lever_par(
            || {
                retraits += 1;
                Ok(true)
            },
            Vec::new,
            || retirer_fichiers(&d, &TRACES),
        );
        assert!(r.reussi, "{r:?}");
        assert!(
            r.note.as_deref().is_some_and(|n| n.contains("retirée de nouveau")),
            "{r:?}"
        );
        assert!(!trace_sous(&d));
    }

    /// Démarrage avec un état abîmé : rien n'est gardé (aucune adresse, aucun port hors DHCP), jamais ouvert.
    #[test]
    fn demarrage_avec_etat_abime() {
        use crate::machine::linux::nftables::isolement::{Critere, criteres};
        use crate::protection::blocage::ordres::SessionGardee;
        let bon = Etat {
            depuis: 1_700_000_000,
            permis: Permis {
                garder: vec![SessionGardee {
                    distante: "192.0.2.7".parse().unwrap(),
                    port_distant: 51234,
                    port_local: 22,
                }],
                serveurs: vec!["198.51.100.20".parse().unwrap()],
                dns: vec!["192.0.2.53".parse().unwrap()],
            },
        };
        let texte = etat_texte(&bon);
        assert_eq!(permis_au_demarrage(Some(&texte)), (bon.permis.clone(), true));
        let ancien = texte.replacen("vanguard-isolement 2", "vanguard-isolement 1", 1);
        let coupe = &texte[..texte.len() / 2];
        let ligne_en_trop = format!("{texte}ouvrir tout\n");
        let session_mal_ecrite = texte.replace("192.0.2.7:51234>22", "192.0.2.7");
        for abime in [
            None,
            Some(""),
            Some("n'importe quoi"),
            Some(ancien.as_str()),
            Some(coupe),
            Some(ligne_en_trop.as_str()),
            Some(session_mal_ecrite.as_str()),
        ] {
            let (permis, lu) = permis_au_demarrage(abime);
            assert!(!lu, "{abime:?}");
            assert_eq!(permis, Permis::default(), "{abime:?}");
            for (_, c) in criteres(&permis) {
                for x in &c {
                    assert!(!matches!(x, Critere::Distante(_)), "{abime:?} : {c:?}");
                    if let Critere::PortSource(p) | Critere::PortDestination(p) = x {
                        assert!([67, 68, 546, 547].contains(p), "{abime:?} : {c:?}");
                    }
                }
            }
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

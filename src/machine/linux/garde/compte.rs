//! Ce que fait le Vanguard du compte pour le garde : préparer l'ensemble CERTAIN (les empreintes de MalwareBazaar et
//! de ClamAV, lues ici, sans droits, par leurs propres lecteurs), lui envoyer ses ordres par l'assistant root, et lire
//! ce qu'il écrit dans /run/vanguard/garde pour `vanguard garde etat` et le bilan (LNX-SUR-002). Rien de ce qui est lu
//! ici ne sort sans `affichable` : les chemins des événements viennent de fichiers que n'importe qui nomme.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::io::Read as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use super::sortie::{self, Etat};
use super::{FICHIER_UNITE, LISTE_MD5, LISTE_SHA256, PROGRAMME};
use crate::machine::regles::{Os, regle};
use crate::machine::{Constat, alerte, impossible, ok, sans_objet};
use crate::modele::etat::Absence;
use crate::protection::blocage::ordres::{self, Ordre};
use crate::protection::clamav::signatures::{Mode, Options};
use crate::risk::Niveau;
use crate::ui::{GRIS, RESET, VERT, affichable, afficher_aligne, couleur, titre};
use crate::{tr, trf, trp};

regle!(
    "LNX-SUR-002",
    Os::Linux,
    381,
    ("garde des lancements", "launch guard"),
    &["CIS Controls v8 10.1", "MITRE ATT&CK M1038"],
    || vec![constat()]
);

const CAT: &str = "Surveillance";
/// Au-delà, un battement est trop vieux : le garde est figé ou arrêté (il bat chaque seconde ; systemd le tue après
/// 5 s sans nouvelles et le relance).
pub(crate) const BATTEMENT_VIEUX: u64 = 30;
/// Les derniers événements montrés par `vanguard garde etat`.
const DERNIERS: usize = 8;

/// Le dossier des listes du compte.
pub(crate) fn dossier_listes() -> PathBuf {
    crate::socle::dossier_local().join("garde")
}

// ───────────────────────────── L'ensemble CERTAIN ─────────────────────────────

/// Ce que la préparation a écrit.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Preparees {
    pub sha256: usize,
    pub md5: usize,
    /// Ce qui manque ou a été laissé (dit à la personne).
    pub notes: Vec<String>,
}

/// La liste SHA-256 : celles de ClamAV d'abord, puis celles de MalwareBazaar tant que la liste tient dans la taille
/// que le garde relit ; triée, sans doublon. Le nombre laissé de côté est rendu.
pub(crate) fn fusionner(clamav: &[u8], bazaar: &[[u8; 32]], max: usize) -> (Vec<u8>, usize) {
    let mut toutes: Vec<[u8; 32]> = clamav.as_chunks::<32>().0.to_vec();
    toutes.sort_unstable();
    toutes.dedup();
    toutes.truncate(max);
    let place = max.saturating_sub(toutes.len());
    let mut nouvelles: Vec<[u8; 32]> = bazaar
        .iter()
        .filter(|e| toutes.binary_search(e).is_err())
        .copied()
        .collect();
    nouvelles.sort_unstable();
    nouvelles.dedup();
    let laissees = nouvelles.len().saturating_sub(place);
    nouvelles.truncate(place);
    toutes.extend(nouvelles);
    toutes.sort_unstable();
    (toutes.concat(), laissees)
}

/// Les entrées de 32 octets que le garde relit, au plus.
fn entrees_max() -> usize {
    usize::try_from(super::listes::TAILLE_MAX / 32).unwrap_or(usize::MAX)
}

/// Écrit les deux listes dans `dossier` (0700, au compte).
pub(crate) fn ecrire_dans(
    dossier: &Path,
    bazaar: &[[u8; 32]],
    sha_clamav: &[u8],
    md5_clamav: &[u8],
    mut notes: Vec<String>,
) -> Result<Preparees, String> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dossier)
        .map_err(|e| trf!("dossier {} : {e}", "folder {}: {e}", dossier.display()))?;
    let max = entrees_max();
    let (sha, laissees) = fusionner(sha_clamav, bazaar, max);
    if laissees > 0 {
        notes.push(trf!(
            "{laissees} empreintes de MalwareBazaar laissées de côté : la liste du garde est bornée à {max} empreintes",
            "{laissees} MalwareBazaar hashes left out: the guard's list is capped at {max} hashes"
        ));
    }
    let md5 = md5_clamav
        .get(..md5_clamav.len().min(max.saturating_mul(32)))
        .unwrap_or_default();
    for (nom, contenu) in [(LISTE_SHA256, sha.as_slice()), (LISTE_MD5, md5)] {
        crate::socle::ecrire_atomique(&dossier.join(nom), contenu)
            .map_err(|e| trf!("écriture de {nom} : {e}", "writing {nom}: {e}"))?;
    }
    Ok(Preparees {
        sha256: sha.len() / 32,
        md5: md5.len() / 32,
        notes,
    })
}

/// Prépare l'ensemble CERTAIN du compte : les empreintes de MalwareBazaar (téléchargées au besoin) et celles de la base
/// de ClamAV de l'ordinateur (.hsb, .hdb). Jamais en root : ces lecteurs de format ne tournent que sous le compte (P22).
pub(crate) fn preparer_listes() -> Result<Preparees, String> {
    if crate::socle::euid() == 0 {
        return Err(tr!(
            "les listes du garde se préparent sous votre compte, pas en root",
            "the guard's lists are prepared under your account, not as root"
        )
        .to_string());
    }
    let mut notes = Vec::new();
    let bazaar: &[[u8; 32]] = match crate::protection::empreintes::connues() {
        Ok(e) => e.triees(),
        Err(r) => {
            notes.push(trf!("MalwareBazaar : {r}", "MalwareBazaar: {r}"));
            &[]
        }
    };
    let (sha, md5) = match crate::protection::clamav::base::charger(Options {
        mode: Mode::Empreintes,
        pua: false,
    }) {
        Ok(b) => (b.signatures.liste_sha256(), b.signatures.liste_md5_taille()),
        Err(r) => {
            notes.push(trf!("ClamAV : {r}", "ClamAV: {r}"));
            (Vec::new(), Vec::new())
        }
    };
    ecrire_dans(&dossier_listes(), bazaar, &sha, &md5, notes)
}

// ───────────────────────────── Ce que le garde écrit ─────────────────────────────

/// Un fichier écrit par root (le garde), ouvert sans suivre de lien : un fichier qu'un autre aurait mis là n'est pas
/// cru.
fn ouvrir_de_root(chemin: &Path) -> Option<(std::fs::File, u64)> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(chemin)
        .ok()?;
    let m = f.metadata().ok()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 {
        return None;
    }
    Some((f, m.len()))
}

/// Un fichier écrit par root, en entier, s'il ne dépasse pas `max`.
fn lire_de_root(chemin: &Path, max: u64) -> Option<Vec<u8>> {
    let (f, taille) = ouvrir_de_root(chemin)?;
    if taille > max {
        return None;
    }
    let mut octets = Vec::new();
    f.take(max).read_to_end(&mut octets).ok()?;
    Some(octets)
}

/// Les `garde` derniers octets d'un fichier de lignes écrit par root, à partir d'une ligne entière. Le garde ne passe
/// à un nouveau fichier qu'une fois `EVENEMENTS_TAILLE_MAX` atteint : le fichier le dépasse d'un lot, et refuser de le
/// lire tairait tous ses événements.
fn lire_fin_de_root(chemin: &Path, garde: u64) -> Option<Vec<u8>> {
    use std::io::{Seek as _, SeekFrom};
    let (mut f, taille) = ouvrir_de_root(chemin)?;
    let debut = taille.saturating_sub(garde);
    f.seek(SeekFrom::Start(debut)).ok()?;
    let mut octets = Vec::new();
    f.take(garde).read_to_end(&mut octets).ok()?;
    Some(depuis_une_ligne(octets, debut > 0))
}

/// Sans la première ligne quand la lecture a commencé au milieu du fichier (elle est coupée).
fn depuis_une_ligne(mut octets: Vec<u8>, coupee: bool) -> Vec<u8> {
    if coupee {
        let fin = octets
            .iter()
            .position(|&o| o == b'\n')
            .map_or(octets.len(), |i| i.saturating_add(1));
        octets.drain(..fin);
    }
    octets
}

/// L'état écrit par le garde, s'il se lit.
pub(crate) fn etat() -> Option<Etat> {
    Etat::lire(&lire_de_root(Path::new(super::ETAT), sortie::ETAT_TAILLE_MAX)?)
}

/// Les derniers événements notés par le garde.
pub(crate) fn derniers_evenements(n: usize) -> Vec<sortie::Evenement> {
    let texte = lire_fin_de_root(
        Path::new(super::EVENEMENTS),
        sortie::EVENEMENTS_TAILLE_MAX.saturating_mul(2),
    )
    .and_then(|o| String::from_utf8(o).ok())
    .unwrap_or_default();
    let tous = sortie::sans_delai_double(sortie::evenements(&texte));
    let debut = tous.len().saturating_sub(n);
    tous.into_iter().skip(debut).collect()
}

/// Le garde est-il posé (son unité écrite) ?
pub(crate) fn pose() -> bool {
    std::fs::symlink_metadata(FICHIER_UNITE).is_ok_and(|m| m.is_file())
}

/// Une heure lisible (aujourd'hui : l'heure seule).
fn heure(t: u64) -> String {
    let Some(d) = i64::try_from(t)
        .ok()
        .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
    else {
        return t.to_string();
    };
    let local = d.with_timezone(&chrono::Local);
    if local.date_naive() == chrono::Local::now().date_naive() {
        local.format("%H:%M:%S").to_string()
    } else {
        local.format("%Y-%m-%d %H:%M").to_string()
    }
}

/// Le constat, pur : posé ou non, l'état lu, l'instant.
pub(crate) fn juger(posee: bool, etat: Option<&Etat>, maintenant: u64) -> Constat {
    if !posee {
        return sans_objet(
            CAT,
            Absence::Inactif,
            tr!(
                "Garde des lancements non posé (facultatif) : rien n'est refusé au lancement. vanguard garde on le pose, en observation.",
                "Launch guard not installed (optional): nothing is refused at launch. vanguard guard on installs it, in observation."
            ),
        );
    }
    let Some(e) = etat else {
        return alerte(
            CAT,
            Niveau::Critique,
            tr!(
                "Le garde des lancements est posé, mais il n'a écrit aucun état : il ne garde rien (systemctl status vanguard-garde).",
                "The launch guard is installed, but it has written no state: it guards nothing (systemctl status vanguard-garde)."
            ),
        );
    };
    if maintenant.saturating_sub(e.battement) > BATTEMENT_VIEUX {
        return alerte(
            CAT,
            Niveau::Critique,
            trf!(
                "Le garde des lancements est posé, mais il ne bat plus (vu à {}) : les lancements passent sans verdict (systemctl status vanguard-garde).",
                "The launch guard is installed, but its heartbeat stopped (seen at {}): launches go through unchecked (systemctl status vanguard-garde).",
                heure(e.battement)
            ),
        );
    }
    let vu = heure(e.battement);
    let n = e.certain;
    let mut c = if e.pause_jusqu_a.is_some_and(|f| maintenant < f) {
        alerte(
            CAT,
            Niveau::Moyen,
            trf!(
                "Garde des lancements en pause jusqu'à {} : rien n'est refusé (vanguard garde pause 0 la lève).",
                "Launch guard paused until {}: nothing is refused (vanguard guard pause 0 ends it).",
                heure(e.pause_jusqu_a.unwrap_or_default())
            ),
        )
    } else if n == 0 {
        alerte(
            CAT,
            Niveau::Moyen,
            tr!(
                "Le garde des lancements tourne sans aucune liste d'empreintes : seuls les fichiers d'essai sont reconnus (vanguard garde maj).",
                "The launch guard runs without any hash list: only test files are recognized (vanguard guard update)."
            ),
        )
    } else if e.refus {
        ok(
            CAT,
            trf!(
                "Garde des lancements actif (vu à {vu}) : il refuse les {n} programmes certainement malveillants connus.",
                "Launch guard active (seen at {vu}): it refuses the {n} known, certainly malicious programs."
            ),
        )
    } else {
        ok(
            CAT,
            trf!(
                "Garde des lancements actif en observation (vu à {vu}) : rien n'est refusé, les {n} programmes certainement malveillants connus sont notés à leur lancement (vanguard garde refus pour les refuser).",
                "Launch guard active in observation (seen at {vu}): nothing is refused, the {n} known, certainly malicious programs are noted when launched (vanguard guard refuse to refuse them)."
            ),
        )
    };
    let mut hausser = |niveau: Niveau, texte: String| {
        c.message.push(' ');
        c.message.push_str(&texte);
        c.probleme = c.probleme.max(Some(niveau));
    };
    let k = &e.compteurs;
    if k.certains_passes > 0 {
        let n = k.certains_passes;
        hausser(
            Niveau::Eleve,
            trf!(
                "{n} lancements de programmes certainement malveillants ont été permis faute de verdict à temps (garde saturé) : jugés après coup, leur verdict est gardé pour le lancement suivant (vanguard garde montre les derniers événements).",
                "{n} launches of certainly malicious programs were allowed for lack of a timely verdict (guard saturated): judged afterwards, their verdict is kept for the next launch (vanguard guard shows the latest events)."
            ),
        );
    }
    if k.debordements > 0 {
        let n = k.debordements;
        hausser(
            Niveau::Eleve,
            trf!(
                "La file des demandes du noyau a débordé {n} fois : des lancements ont pu passer sans être vus, ni jugés après coup. Elle reste bornée exprès (jamais illimitée, FAN_UNLIMITED_QUEUE) : sans borne, une rafale ferait grandir la mémoire sans fin ; le cache du garde a été vidé, tout est rehaché.",
                "The kernel's request queue overflowed {n} times: launches may have passed unseen, and cannot be judged afterwards. It stays bounded on purpose (never unlimited, FAN_UNLIMITED_QUEUE): without a bound, a burst would grow memory endlessly; the guard's cache was emptied, everything is hashed again."
            ),
        );
    }
    if k.rattrapages_perdus > 0 {
        let n = k.rattrapages_perdus;
        hausser(
            Niveau::Moyen,
            trf!(
                "{n} lancements ont été permis sans jamais être jugés (garde saturé, ou fichier de plus de 512 Mio).",
                "{n} launches were allowed without ever being judged (guard saturated, or file over 512 MiB)."
            ),
        );
    }
    if k.changes_avant_jugement > 0 {
        let n = k.changes_avant_jugement;
        hausser(
            Niveau::Moyen,
            trf!(
                "{n} programmes lancés sans verdict à temps (garde saturé) ont changé avant d'être jugés : ce qui a tourné ne peut plus être vérifié. Un programme d'essai effacé juste après (une compilation) le fait aussi ; sinon, un programme a pu se cacher ainsi (vanguard garde montre les derniers événements).",
                "{n} programs launched without a timely verdict (guard saturated) changed before being judged: what ran can no longer be checked. A test program deleted right after (a build) does this too; otherwise, a program may have hidden this way (vanguard guard shows the latest events)."
            ),
        );
    }
    if k.non_verifiees > 0 {
        let n = k.non_verifiees;
        hausser(
            Niveau::Info,
            trf!(
                "{n} lancements ont été permis sans vérification à temps (plus de 64 Mio, ou illisibles) : les gros sont hachés après coup, jusqu'à 512 Mio, et un programme certainement malveillant passé ainsi est dit.",
                "{n} launches were allowed without a timely check (over 64 MiB, or unreadable): big ones are hashed afterwards, up to 512 MiB, and a certainly malicious program that passed this way is reported."
            ),
        );
    }
    if e.listes_retirees > 0 {
        let n = e.listes_retirees;
        hausser(
            Niveau::Eleve,
            trf!(
                "Les listes du compte n'ont plus {n} empreintes que le garde avait reçues : il les garde (une liste ne retire rien). Si c'est voulu (une base allégée), « vanguard garde maj » dans un terminal repart des listes du compte ; sinon, un programme a touché aux listes.",
                "The account's lists no longer have {n} hashes the guard had received: it keeps them (a list removes nothing). If intended (a smaller database), “vanguard guard update” in a terminal starts over from the account's lists; otherwise, a program tampered with the lists."
            ),
        );
    }
    if e.listes_croissance > 0 {
        let n = e.listes_croissance;
        hausser(
            Niveau::Moyen,
            trf!(
                "{n} empreintes ont été ajoutées d'un coup aux listes du garde, bien au-delà de leur croissance normale (MalwareBazaar et ClamAV) : un programme sous votre compte a pu y mettre celles de programmes sains pour les faire refuser. Si vous venez d'installer ou de mettre à jour la base de ClamAV, c'est elle ; sinon, « vanguard garde maj » dans un terminal repart des listes refaites.",
                "{n} hashes were added at once to the guard's lists, far beyond their normal growth (MalwareBazaar and ClamAV): a program under your account may have put in those of safe programs to have them refused. If you just installed or updated the ClamAV database, that is it; otherwise, “vanguard guard update” in a terminal starts over from freshly made lists."
            ),
        );
    }
    if e.listes_bloquees > 0 {
        let n = e.listes_bloquees;
        hausser(
            Niveau::Eleve,
            trf!(
                "{n} empreintes des listes du compte n'entrent plus dans celles du garde, pleines : « vanguard garde maj » dans un terminal repart des listes du compte.",
                "{n} hashes from the account's lists no longer fit in the guard's, which are full: “vanguard guard update” in a terminal starts over from the account's lists."
            ),
        );
    }
    if !e.alertes.is_empty() {
        c.message.push_str(&trf!(
            " À voir : {}.",
            " To check: {}.",
            affichable(&e.alertes.join(" ; "))
        ));
        c.probleme = c.probleme.max(Some(Niveau::Info));
    }
    c
}

/// Le constat de cet ordinateur.
pub(crate) fn constat() -> Constat {
    if !crate::machine::linux::dbus::systeme::systemd_present() && !pose() {
        return impossible(CAT, tr!("systemd absent", "systemd not present"));
    }
    juger(pose(), etat().as_ref(), super::maintenant())
}

// ───────────────────────────── Les commandes ─────────────────────────────

/// `vanguard garde [etat|on|off|maj|refus|observation|pause <min>|permettre <sha256>]`.
pub(crate) fn commande(action: Option<&str>, argument: Option<&str>) {
    titre(tr!("Garde des lancements", "Launch guard"));
    match action {
        Some("on") => poser(),
        Some("off") => retirer(),
        Some("maj" | "update") => mettre_a_jour(),
        Some("refus" | "refuse") => regler(true),
        Some("observation" | "observe") => regler(false),
        Some("pause") => pause(argument),
        Some("permettre" | "allow") => permettre(argument),
        _ => afficher_etat(),
    }
}

fn afficher_etat() {
    let c = constat();
    let signe = match c.probleme {
        None => format!("{VERT}✔{RESET} "),
        Some(n) => format!("{}⚠{RESET} ", couleur(n)),
    };
    afficher_aligne(&format!("  {signe}"), &c.message, 4, "");
    let Some(e) = etat().filter(|_| pose()) else {
        return;
    };
    let k = &e.compteurs;
    afficher_aligne(
        "    ",
        &trf!(
            "{} lancements vus ({} déjà connus, {} hachés), {} notés, {} refusés ; {} permis faute de verdict à temps, {} non vérifiés (trop gros), {} quand la file était pleine.",
            "{} launches seen ({} already known, {} hashed), {} noted, {} refused; {} allowed for lack of a timely verdict, {} not checked (too big), {} while the queue was full.",
            k.demandes,
            k.cache,
            k.hachees,
            k.notees,
            k.refusees,
            k.delais,
            k.non_verifiees,
            k.file_pleine
        ),
        4,
        GRIS,
    );
    let derniers = derniers_evenements(DERNIERS);
    if !derniers.is_empty() {
        println!();
        trp!("  Derniers événements :", "  Latest events:");
        for ev in derniers {
            let mut ligne = genre_affiche(&ev.genre);
            for morceau in [affichable(&ev.chemin), precision(&ev)] {
                if !morceau.is_empty() {
                    ligne.push(' ');
                    ligne.push_str(&morceau);
                }
            }
            afficher_aligne(&format!("    {GRIS}{}{RESET} ", heure(ev.t)), &ligne, 6, "");
        }
    }
}

/// Le genre d'un événement, dans la langue de l'affichage (le nom interne reste français dans evenements.jsonl).
fn genre_affiche(genre: &str) -> String {
    match genre {
        "refuse" => tr!("refusé", "refused").into(),
        "observe" => tr!("noté (observation)", "noted (observing)").into(),
        "epargne" => tr!("épargné (exception)", "spared (exception)").into(),
        "permise" => tr!("permis par vous", "allowed by you").into(),
        "delai" => tr!("permis faute de verdict", "allowed, no verdict in time").into(),
        "non-verifie" => tr!("non vérifié", "not checked").into(),
        "trop-gros" => tr!("trop gros, jamais jugé", "too big, never judged").into(),
        "change-avant-jugement" => tr!("changé avant d'être jugé", "changed before being judged").into(),
        "file-pleine" => tr!("file pleine", "queue full").into(),
        "debordement" => tr!("débordement", "overflow").into(),
        "demarrage" => tr!("démarrage", "start").into(),
        "montage" => tr!("montage marqué", "mount marked").into(),
        "alerte" => tr!("alerte du garde", "guard alert").into(),
        autre => affichable(autre),
    }
}

/// Les champs d'un événement, dans la langue de l'affichage ; ce qui vient d'ailleurs que du garde (le nom du lanceur,
/// une alerte) passe par `affichable`.
fn precision(ev: &sortie::Evenement) -> String {
    let mut morceaux: Vec<String> = Vec::new();
    if let Some(v) = &ev.trop_tard {
        let v = genre_affiche(v);
        morceaux.push(trf!("verdict trop tard : {v}", "verdict too late: {v}"));
    }
    if let Some(n) = &ev.lanceur {
        let n = affichable(n);
        morceaux.push(trf!("lancé par {n}", "launched by {n}"));
    }
    if let Some(t) = ev.taille {
        morceaux.push(trf!("{t} octets", "{t} bytes"));
    }
    if let Some(g) = &ev.systeme {
        morceaux.push(affichable(g));
    }
    if let Some(d) = ev.demarrage {
        let oui_non = |b: bool| if b { tr!("oui", "yes") } else { tr!("non", "no") };
        let (pidfd, audit) = (oui_non(d.pidfd), oui_non(d.audit));
        morceaux.push(trf!(
            "{} systèmes de fichiers marqués, {} refusés ; pidfd {pidfd}, audit {audit}",
            "{} file systems marked, {} refused; pidfd {pidfd}, audit {audit}",
            d.marques,
            d.refuses
        ));
    }
    if !ev.detail.is_empty() {
        morceaux.push(affichable(&ev.detail));
    }
    if morceaux.is_empty() {
        return String::new();
    }
    format!("({})", morceaux.join(" ; "))
}

/// Montre l'ordre, le fait confirmer, puis le fait faire par l'assistant root (le mot de passe), et le note.
fn envoyer(o: &Ordre, question: &str) -> bool {
    if let Some(r) = ordres::juger(o, &ordres::Juge::lire(Some(std::process::id()))) {
        afficher_aligne("  ✘ ", &trf!("Refusé : {r}", "Refused: {r}"), 4, "");
        return false;
    }
    afficher_aligne("  › ", &o.texte(), 4, "");
    let gardes = crate::protection::blocage::gardes::console_reelle();
    if !crate::protection::blocage::gardes::confirmer(gardes, question, crate::ui::demander) {
        trp!("  Rien n'est fait.", "  Nothing is done.");
        return false;
    }
    let ligne = o.ligne();
    let (faits, notes) = crate::machine::appliquer_chacune_sans_noter(&[vec![ligne.clone()]]);
    let reussi = faits.first().copied().unwrap_or(false);
    crate::modele::journal::noter(crate::modele::evenement::Evenement::action(
        crate::modele::evenement::Source::Blocage,
        &o.texte(),
        reussi,
        &[ligne],
    ));
    if reussi {
        trp!("  {VERT}✔{RESET} Fait.", "  {VERT}✔{RESET} Done.");
    } else {
        let raison = notes.into_iter().flatten().collect::<Vec<_>>().join(" ; ");
        afficher_aligne(
            "  ✘ ",
            &trf!("Pas fait : {}", "Not done: {}", affichable(&raison)),
            4,
            "",
        );
    }
    reussi
}

fn le_faire() -> &'static str {
    tr!("  Le faire ? [o/N] : ", "  Do it? [y/N]: ")
}

fn dire_preparees(p: &Preparees) {
    afficher_aligne(
        "  ✔ ",
        &trf!(
            "Listes préparées : {} empreintes SHA-256, {} MD5 et taille.",
            "Lists prepared: {} SHA-256 hashes, {} MD5 and size.",
            p.sha256,
            p.md5
        ),
        4,
        "",
    );
    for n in &p.notes {
        afficher_aligne("    ", &affichable(n), 4, GRIS);
    }
}

fn poser() {
    if crate::socle::euid() == 0 {
        trp!(
            "  Lancez « vanguard garde on » sous votre compte, pas en root : le mot de passe est demandé au moment de poser le garde.",
            "  Run “vanguard guard on” under your account, not as root: the password is asked when the guard is installed."
        );
        return;
    }
    afficher_aligne(
        "  ",
        tr!(
            "Le garde est un service système qui voit chaque programme lancé et compare son empreinte aux listes de programmes certainement malveillants. Il commence en observation : rien n'est refusé, ce qu'il aurait refusé est noté.",
            "The guard is a system service that sees every program launched and compares its hash with lists of certainly malicious programs. It starts in observation: nothing is refused, what it would have refused is noted."
        ),
        2,
        "",
    );
    let p = match preparer_listes() {
        Ok(p) => p,
        Err(e) => {
            afficher_aligne("  ✘ ", &affichable(&e), 4, "");
            return;
        }
    };
    dire_preparees(&p);
    let Some(dossier) = dossier_listes().to_str().map(str::to_string) else {
        trp!(
            "  ✘ Le dossier de Vanguard n'a pas un nom lisible : le garde ne peut pas le nommer.",
            "  ✘ Vanguard's folder has no readable name: the guard cannot name it."
        );
        return;
    };
    if !envoyer(
        &Ordre::GardePoser {
            compte: crate::socle::uid(),
            dossier,
        },
        le_faire(),
    ) {
        return;
    }
    if super::minuterie::poser() {
        trp!(
            "  {GRIS}Les listes se rafraîchiront une fois par jour (« vanguard garde maj »).{RESET}",
            "  {GRIS}The lists will refresh once a day (“vanguard guard update”).{RESET}"
        );
    } else {
        trp!(
            "  ⚠ Rafraîchissement quotidien des listes non posé : lancez « vanguard garde maj » de temps en temps.",
            "  ⚠ Daily list refresh not set up: run “vanguard guard update” now and then."
        );
    }
}

/// Retire le garde (aussi depuis « Retirer Vanguard »), puis ce qui ne servait qu'à lui sous le compte : sa minuterie
/// et ses listes. Un garde déjà retiré laisse quand même ces deux-là partir.
pub(crate) fn retirer() {
    if pose() {
        if !envoyer(&Ordre::GardeRetirer, le_faire()) {
            return;
        }
    } else {
        trp!("  Le garde n'est pas posé.", "  The guard is not installed.");
    }
    nettoyer_le_compte();
}

/// Il reste quelque chose du garde sous le compte (sa minuterie, ses listes) ?
pub(crate) fn restes() -> bool {
    super::minuterie::posee() || std::fs::symlink_metadata(dossier_listes()).is_ok()
}

/// Efface la minuterie et les listes du compte ; dit ce qui n'a pas pu partir.
fn nettoyer_le_compte() {
    if !super::minuterie::retirer() {
        trp!(
            "  ⚠ La minuterie des listes ({}) n'a pas pu être retirée.",
            "  ⚠ The lists timer ({}) could not be removed.",
            super::minuterie::NOM
        );
    }
    let dossier = dossier_listes();
    let restes = effacer_listes(&dossier);
    if !restes.is_empty() {
        afficher_aligne(
            "  ⚠ ",
            &trf!(
                "Listes du garde non effacées ({}) : {}",
                "Guard lists not erased ({}): {}",
                dossier.display(),
                restes.join(", ")
            ),
            4,
            "",
        );
    }
}

/// Efface les deux listes, puis leur dossier s'il est vide : rien d'autre (un fichier que la personne y aurait mis
/// reste, avec le dossier).
fn effacer_listes(dossier: &Path) -> Vec<String> {
    let mut restes =
        crate::reseau::surveillance::retirer_fichiers(&[dossier.join(LISTE_SHA256), dossier.join(LISTE_MD5)]);
    match std::fs::remove_dir(dossier) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound || e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
        Err(e) => restes.push(format!("{} ({e})", dossier.display())),
        Ok(()) => {}
    }
    restes
}

/// L'empreinte d'un programme, s'il se lit.
fn empreinte_de_fichier(chemin: &Path) -> Option<[u8; 32]> {
    crate::protection::empreintes::sha256_de(std::fs::File::open(chemin).ok()?)
}

fn mettre_a_jour() {
    match preparer_listes() {
        Ok(p) => dire_preparees(&p),
        Err(e) => afficher_aligne("  ✘ ", &affichable(&e), 4, ""),
    }
    if !pose() {
        return;
    }
    // Le garde relit les listes de lui-même ; seul un autre programme demande l'assistant root.
    let ici = std::env::current_exe().ok().and_then(|c| empreinte_de_fichier(&c));
    let pose_la = empreinte_de_fichier(Path::new(PROGRAMME));
    // Le garde garde l'union de ce qu'il a reçu : des listes du compte plus courtes n'y retirent rien. Seul l'ordre
    // root (mettre à jour) l'efface et repart des listes du compte.
    let repartir = etat().is_some_and(|e| e.listes_retirees > 0 || e.listes_bloquees > 0 || e.listes_croissance > 0);
    if ici.is_some() && ici == pose_la && !repartir {
        trp!(
            "  Le programme du garde est déjà celui-ci.",
            "  The guard's program is already this one."
        );
        return;
    }
    // Lancé par la minuterie du jour : rien à demander à personne, seulement le dire.
    if !crate::protection::blocage::gardes::console_reelle() {
        if repartir {
            trp!(
                "  Les listes du garde ne sont plus celles du compte : « vanguard garde maj » dans un terminal le fait repartir des listes du compte.",
                "  The guard's lists no longer match the account's: “vanguard guard update” in a terminal makes it start over from the account's lists."
            );
        } else {
            trp!(
                "  Le programme du garde n'est pas celui-ci : « vanguard garde maj » dans un terminal le met à jour.",
                "  The guard's program is not this one: “vanguard guard update” in a terminal updates it."
            );
        }
        return;
    }
    if repartir {
        trp!(
            "  Le garde repartira des listes du compte (elles n'ont plus toutes ses empreintes).",
            "  The guard will start over from the account's lists (they no longer have all its hashes)."
        );
    }
    envoyer(&Ordre::GardeMettreAJour, le_faire());
}

fn regler(refus: bool) {
    if !pose() {
        trp!(
            "  Le garde n'est pas posé : vanguard garde on.",
            "  The guard is not installed: vanguard guard on."
        );
        return;
    }
    if refus {
        afficher_aligne(
            "  ",
            tr!(
                "En mode refus, le lancement d'un programme dont l'empreinte est dans les listes est refusé (« Opération non permise »), sauf pour les programmes du système, Vanguard et ce que lance init. Un programme refusé à tort se permet avec « vanguard garde permettre <SHA-256> ».",
                "In refuse mode, launching a program whose hash is in the lists is refused (“Operation not permitted”), except for system programs, Vanguard and what init launches. A program refused by mistake is allowed with “vanguard guard allow <SHA-256>”."
            ),
            2,
            "",
        );
        envoyer(
            &Ordre::GardeRegler { refus: true },
            tr!(
                "  Refuser les programmes certainement malveillants ? [o/N] : ",
                "  Refuse certainly malicious programs? [y/N]: "
            ),
        );
    } else {
        envoyer(&Ordre::GardeRegler { refus: false }, le_faire());
    }
}

/// Les minutes d'une pause relues : de 0 (lever) à `PAUSE_MAX` en secondes.
fn secondes_de_pause(minutes: Option<&str>) -> Option<u32> {
    let m: u32 = minutes?.trim().parse().ok()?;
    let s = m.checked_mul(60)?;
    (s <= ordres::PAUSE_MAX).then_some(s)
}

fn pause(minutes: Option<&str>) {
    let Some(secondes) = secondes_de_pause(minutes) else {
        trp!(
            "  Donnez la durée en minutes, de 1 à 1440 (0 lève la pause) : vanguard garde pause 30.",
            "  Give the length in minutes, from 1 to 1440 (0 ends the pause): vanguard guard pause 30."
        );
        return;
    };
    envoyer(&Ordre::GardePause { secondes }, le_faire());
}

fn permettre(sha256: Option<&str>) {
    let Some(e) = sha256.and_then(|s| super::empreinte_de(&s.trim().to_ascii_lowercase())) else {
        trp!(
            "  Donnez l'empreinte SHA-256 du fichier (64 caractères hexadécimaux) : sha256sum <fichier>.",
            "  Give the file's SHA-256 hash (64 hexadecimal characters): sha256sum <file>."
        );
        return;
    };
    envoyer(&Ordre::GardePermettre { sha256: e }, le_faire());
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    fn etat(battement: u64) -> Etat {
        Etat {
            battement,
            certain: 12,
            ..Etat::default()
        }
    }

    #[test]
    fn fusion_triee_sans_doublon_et_bornee() {
        let clamav: Vec<u8> = [[9u8; 32], [3u8; 32]].concat();
        let bazaar = [[1u8; 32], [3u8; 32], [5u8; 32], [7u8; 32]];
        let (l, laissees) = fusionner(&clamav, &bazaar, 100);
        assert_eq!(l, [[1u8; 32], [3; 32], [5; 32], [7; 32], [9; 32]].concat());
        assert_eq!(laissees, 0);
        // Bornée à trois : ClamAV d'abord, puis MalwareBazaar tant qu'il y a la place.
        let (l, laissees) = fusionner(&clamav, &bazaar, 3);
        assert_eq!(l, [[1u8; 32], [3; 32], [9; 32]].concat());
        assert_eq!(laissees, 2);
        assert!(crate::protection::clamav::hashes::ListeSha256::lire(l).is_some());
    }

    #[test]
    fn listes_ecrites_relues_par_le_garde() {
        let jetable = crate::essais::Jetable::nouveau("garde-compte");
        // Le garde n'ouvre rien à travers un lien : le dossier d'essai, par son vrai chemin.
        let dossier = jetable.canonicalize().unwrap().join("garde");
        let md5 = super::super::listes::enregistrement_md5(&[4; 16], 68);
        let p = ecrire_dans(&dossier, &[[2u8; 32]], &[1u8; 32], &md5, Vec::new()).unwrap();
        assert_eq!((p.sha256, p.md5), (2, 1));
        let moi = crate::socle::uid();
        let (depart, relatif) = super::super::listes::depart(&dossier, moi).unwrap();
        let relue = |nom: &str| super::super::listes::lire_sous(&depart, &relatif.join(nom), moi, None);
        assert_eq!(relue(LISTE_SHA256).unwrap().1.unwrap().nombre(), 2);
        assert!(relue(LISTE_MD5).unwrap().1.is_some());
        assert_eq!(std::fs::metadata(&dossier).unwrap().mode() & 0o777, 0o700);
    }

    #[test]
    fn non_pose_n_est_pas_un_probleme() {
        let c = juger(false, None, 1_000);
        assert!(c.probleme.is_none());
    }

    #[test]
    fn pose_sans_battement_est_critique() {
        assert_eq!(juger(true, None, 1_000).probleme, Some(Niveau::Critique));
        let vieux = etat(1_000);
        assert_eq!(
            juger(true, Some(&vieux), 1_000 + BATTEMENT_VIEUX + 1).probleme,
            Some(Niveau::Critique)
        );
        assert_eq!(juger(true, Some(&vieux), 1_000 + BATTEMENT_VIEUX).probleme, None);
        // Une horloge qui recule ne fait rien déborder.
        assert_eq!(juger(true, Some(&vieux), 10).probleme, None);
    }

    #[test]
    fn pause_sans_liste_et_alertes_dites() {
        let maintenant = 5_000;
        let pause = Etat {
            pause_jusqu_a: Some(maintenant + 60),
            ..etat(maintenant)
        };
        assert_eq!(juger(true, Some(&pause), maintenant).probleme, Some(Niveau::Moyen));
        let finie = Etat {
            pause_jusqu_a: Some(maintenant),
            ..etat(maintenant)
        };
        assert_eq!(juger(true, Some(&finie), maintenant).probleme, None);
        let vide = Etat {
            certain: 0,
            ..etat(maintenant)
        };
        assert_eq!(juger(true, Some(&vide), maintenant).probleme, Some(Niveau::Moyen));
        let alertes = Etat {
            alertes: vec!["liste: \u{1b}[2Jillisible".to_string()],
            ..etat(maintenant)
        };
        let c = juger(true, Some(&alertes), maintenant);
        assert_eq!(c.probleme, Some(Niveau::Info));
        assert!(!c.message.contains('\u{1b}'), "{}", c.message);
    }

    /// M-N1 et M-N2 : des listes du compte amputées, une union pleine, un certain passé faute de verdict : alerte
    /// haute, même quand tout le reste va bien ; un lancement jamais jugé : moyenne.
    #[test]
    fn listes_amputees_et_certains_passes_en_alerte_haute() {
        let maintenant = 5_000;
        assert_eq!(juger(true, Some(&etat(maintenant)), maintenant).probleme, None);
        let retirees = Etat {
            listes_retirees: 3,
            ..etat(maintenant)
        };
        let c = juger(true, Some(&retirees), maintenant);
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(c.message.contains('3'), "{}", c.message);
        let bloquees = Etat {
            listes_bloquees: 1,
            ..etat(maintenant)
        };
        assert_eq!(juger(true, Some(&bloquees), maintenant).probleme, Some(Niveau::Eleve));
        let mut passes = etat(maintenant);
        passes.compteurs.certains_passes = 1;
        assert_eq!(juger(true, Some(&passes), maintenant).probleme, Some(Niveau::Eleve));
        let mut perdus = etat(maintenant);
        perdus.compteurs.rattrapages_perdus = 9;
        assert_eq!(juger(true, Some(&perdus), maintenant).probleme, Some(Niveau::Moyen));
        // C7-2 : des lancements permis sans vérification à temps sont dits (au moins une information).
        let mut gros = etat(maintenant);
        gros.compteurs.non_verifiees = 4;
        let c = juger(true, Some(&gros), maintenant);
        assert_eq!(c.probleme, Some(Niveau::Info));
        assert!(c.message.contains("512"), "{}", c.message);
        // C7-5 : un fichier changé avant d'être jugé, au moins moyen.
        let mut change = etat(maintenant);
        change.compteurs.changes_avant_jugement = 1;
        assert_eq!(juger(true, Some(&change), maintenant).probleme, Some(Niveau::Moyen));
        // C7-1 : un débordement de la file du noyau, haut, et la borne voulue dite.
        let mut deborde = etat(maintenant);
        deborde.compteurs.debordements = 2;
        let c = juger(true, Some(&deborde), maintenant);
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(c.message.contains("FAN_UNLIMITED_QUEUE"), "{}", c.message);
        // N-1 : un rafraîchissement normal ne dit rien ; une croissance anormale, au moins moyenne, et le nombre.
        let rafraichi = Etat {
            listes_ajoutees: 4_000,
            ..etat(maintenant)
        };
        assert_eq!(juger(true, Some(&rafraichi), maintenant).probleme, None);
        let gonflee = Etat {
            listes_croissance: 300_000,
            ..etat(maintenant)
        };
        let c = juger(true, Some(&gonflee), maintenant);
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.message.contains("300000"), "{}", c.message);
        // En pause aussi : l'alerte haute l'emporte.
        let pause = Etat {
            pause_jusqu_a: Some(maintenant + 60),
            ..retirees
        };
        assert_eq!(juger(true, Some(&pause), maintenant).probleme, Some(Niveau::Eleve));
        // Un état d'avant, sans ces champs, se relit (zéro).
        let ancien = br#"{"version":"0.90.0","pid":1,"demarre":1,"battement":1,"refus":true,"pause_jusqu_a":null,"certain":2,"alertes":[],"marques":1,"compteurs":{"demandes":0,"cache":0,"hachees":0,"notees":0,"refusees":0,"delais":0,"non_verifiees":0,"file_pleine":0,"debordements":0}}"#;
        let e = Etat::lire(ancien).unwrap();
        assert_eq!((e.listes_retirees, e.compteurs.certains_passes), (0, 0));
        assert_eq!((e.listes_ajoutees, e.listes_croissance), (0, 0));
    }

    #[test]
    fn chaque_genre_est_traduit() {
        for g in [
            "refuse",
            "observe",
            "epargne",
            "permise",
            "delai",
            "non-verifie",
            "file-pleine",
            "debordement",
            "demarrage",
            "montage",
            "alerte",
        ] {
            assert_ne!(genre_affiche(g), g, "{g}");
        }
        assert_eq!(genre_affiche("inconnu"), "inconnu");
    }

    /// Recommandation 2 : le garde n'écrit que des champs ; leur texte vient d'ici, dans la langue de l'affichage.
    #[test]
    fn precision_des_champs_structures() {
        let ev = sortie::Evenement {
            genre: "delai".into(),
            trop_tard: Some("refuse".into()),
            lanceur: Some("outil\u{1b}[2J".into()),
            ..sortie::Evenement::default()
        };
        let p = precision(&ev);
        assert!(p.contains(&genre_affiche("refuse")), "{p}");
        assert!(!p.contains('\u{1b}'), "{p}");
        let demarrage = sortie::Evenement {
            demarrage: Some(sortie::Demarrage {
                marques: 4,
                refuses: 1,
                pidfd: true,
                audit: true,
            }),
            ..sortie::Evenement::default()
        };
        assert!(precision(&demarrage).contains('4'));
        assert_eq!(precision(&sortie::Evenement::default()), "");
    }

    #[test]
    fn pause_bornee() {
        assert_eq!(secondes_de_pause(Some("30")), Some(1_800));
        assert_eq!(secondes_de_pause(Some("0")), Some(0));
        assert_eq!(secondes_de_pause(Some("1440")), Some(86_400));
        for mauvaise in [None, Some("1441"), Some("-1"), Some("x"), Some("4294967295")] {
            assert_eq!(secondes_de_pause(mauvaise), None, "{mauvaise:?}");
        }
    }

    #[test]
    fn un_etat_qui_n_est_pas_a_root_n_est_pas_cru() {
        let d = crate::essais::Jetable::nouveau("garde-etat");
        let f = d.join("etat.json");
        std::fs::write(&f, b"{}").unwrap();
        if crate::socle::euid() == 0 {
            return crate::essais::saute("le fichier serait à root");
        }
        assert_eq!(lire_de_root(&f, 1024), None);
        assert_eq!(lire_fin_de_root(&f, 1024), None);
    }

    /// Recommandation 3 : au retrait, les deux listes partent, et leur dossier s'il est vide ; rien d'autre.
    #[test]
    fn listes_effacees_au_retrait() {
        let d = crate::essais::Jetable::nouveau("garde-effacer");
        let dossier = d.join("garde");
        ecrire_dans(&dossier, &[[2u8; 32]], &[], &[], Vec::new()).unwrap();
        assert_eq!(effacer_listes(&dossier), Vec::<String>::new());
        assert!(!dossier.exists());
        // Déjà effacées : rien à redire.
        assert_eq!(effacer_listes(&dossier), Vec::<String>::new());
        ecrire_dans(&dossier, &[[2u8; 32]], &[], &[], Vec::new()).unwrap();
        std::fs::write(dossier.join("a-moi.txt"), b"x").unwrap();
        assert_eq!(effacer_listes(&dossier), Vec::<String>::new());
        assert!(dossier.join("a-moi.txt").exists());
        assert!(!dossier.join(LISTE_SHA256).exists() && !dossier.join(LISTE_MD5).exists());
    }

    /// m2 : un evenements.jsonl plus gros que la borne se lit par sa fin, à partir d'une ligne entière.
    #[test]
    fn fin_d_un_fichier_de_lignes() {
        assert_eq!(depuis_une_ligne(b"a\nb\n".to_vec(), false), b"a\nb\n");
        assert_eq!(depuis_une_ligne(b"e\"}\n{\"b\"}\n".to_vec(), true), b"{\"b\"}\n");
        assert_eq!(depuis_une_ligne(b"sans fin".to_vec(), true), b"");
        assert_eq!(depuis_une_ligne(Vec::new(), true), b"");
    }
}

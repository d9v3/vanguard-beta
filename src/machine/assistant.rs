//! L'assistant élevé de Linux et macOS : Vanguard se relance lui-même avec les droits d'administrateur, sous la
//! sous-commande cachée `appliquer-eleve`, pour faire des ordres du blocage (`protection::blocage::ordres`) sans
//! aucun shell : jamais « sudo sh -c », jamais une commande écrite en texte.
//!
//! L'élévation, dans cet ordre : pkexec (Linux, s'il y a une session graphique : la fenêtre de l'agent polkit ; sans
//! agent, pkexec rend 127 et le suivant est essayé), run0 (Linux, systemd 256 et plus : son propre agent dans le
//! terminal), sudo (dans le terminal ; use_pty, la règle par défaut depuis sudo 1.9.14, passe nos tubes tels quels),
//! sinon c'est dit et rien n'est fait. Le programme lancé est, sous Linux, /proc/<pid>/exe de ce Vanguard : ce lien
//! désigne l'image qui tourne, même si le fichier est remplacé entre-temps (sudo et run0 l'exécutent tel quel ;
//! pkexec, lui, le résout en chemin réel avant de l'exécuter, comme pour tout programme qu'on lui donne).
//!
//! Le canal : l'entrée et la sortie standard du fils, deux tubes que seul ce processus tient (pkexec, run0 et sudo
//! les passent tels quels). Le fils dit d'abord qu'il est prêt (il tourne en root), lit la liste jusqu'à « fin »,
//! la relit contre la liste fermée (une ligne étrangère, et rien n'est fait), la montre sur sa sortie d'erreur (le
//! terminal), rejuge chaque ordre avec ses propres yeux (`ordres::juger`), le fait, puis répond une ligne par ordre.
//! Il n'écrit aucun fichier et ne lit rien du dossier de Vanguard. Le parent l'a déjà montrée avant l'accord : le fils
//! ne redemande pas (le mot de passe vaut accord), au contraire de Windows, dont la demande d'administrateur ne montre
//! que le nom du programme et où la fenêtre élevée est à part.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};

use crate::protection::blocage::ordres::{self, LIGNE_MAX, LIGNES_MAX, Ordre, Resultat};
use crate::ui::{GRIS, RESET};
use crate::{tr, trp};

/// La première ligne du fils : il tourne en root et attend la liste.
const PRET: &str = "vanguard-eleve pret";
/// La dernière ligne de chaque sens.
const FIN: &str = "fin";
/// Entre deux groupes de la liste : un ordre en échec n'arrête que la suite de son groupe.
const SUITE: &str = "suite";
/// Sortie du fils : la liste reçue n'est pas celle de Vanguard (rien n'a été fait).
const LISTE_REFUSEE: i32 = 8;
/// Sortie du fils : il ne tourne pas en root.
const SANS_DROITS: i32 = 9;

/// Une façon d'obtenir les droits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Methode {
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    Pkexec,
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    Run0,
    Sudo,
}

impl Methode {
    fn nom(self) -> &'static str {
        match self {
            Methode::Pkexec => "pkexec",
            Methode::Run0 => "run0",
            Methode::Sudo => "sudo",
        }
    }
}

/// Un programme du système par son chemin, jamais par le PATH du compte (qui choisirait un faux « sudo » posé dans un
/// dossier à lui). NixOS met ses programmes setuid dans /run/wrappers/bin.
fn outil(nom: &str) -> Option<std::path::PathBuf> {
    [
        "/run/wrappers/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
        "/run/current-system/sw/bin",
    ]
    .iter()
    .map(|d| std::path::Path::new(d).join(nom))
    .find(|c| c.is_file())
}

/// Un terminal où demander le mot de passe : le terminal de contrôle de ce processus.
fn terminal() -> bool {
    // En lecture seule : l'ouvrir suffit à savoir qu'il y en a un (ENXIO sinon).
    std::fs::File::open("/dev/tty").is_ok()
}

/// Les façons possibles ici, dans l'ordre où les essayer.
fn methodes(graphique: bool, terminal: bool, existe: impl Fn(&str) -> bool) -> Vec<Methode> {
    let mut m = Vec::new();
    if cfg!(target_os = "linux") {
        if graphique && existe("pkexec") {
            m.push(Methode::Pkexec);
        }
        if terminal && existe("run0") {
            m.push(Methode::Run0);
        }
    }
    if existe("sudo") {
        m.push(Methode::Sudo);
    }
    m
}

/// Le programme à relancer : l'image qui tourne (Linux), ou son chemin (macOS, sans /proc).
fn programme() -> Option<std::ffi::OsString> {
    if cfg!(target_os = "linux") {
        Some(format!("/proc/{}/exe", std::process::id()).into())
    } else {
        std::env::current_exe().ok().map(std::path::PathBuf::into_os_string)
    }
}

/// La ligne de commande de l'élévation, sans la lancer.
fn commande(m: Methode, chemin_outil: &std::path::Path, programme: &std::ffi::OsStr, terminal: bool) -> Command {
    let mut c = Command::new(chemin_outil);
    match m {
        // Sans son agent de secours dans le terminal : sans agent graphique, pkexec rend 127, et run0 ou sudo prend
        // la suite.
        Methode::Pkexec => {
            c.arg("--disable-internal-agent");
        }
        // Sans terminal, sudo seulement si le mot de passe n'est pas à demander (déjà donné, ou NOPASSWD).
        Methode::Sudo if !terminal => {
            c.args(["-n", "--"]);
        }
        Methode::Run0 | Methode::Sudo => {
            c.arg("--");
        }
    }
    c.arg(programme);
    c.args([
        "appliquer-eleve",
        "--langue",
        if crate::langue::anglais() { "en" } else { "fr" },
        "--parent",
        &std::process::id().to_string(),
    ]);
    c
}

/// Ce qu'une tentative a donné.
enum Issue {
    Fait(Vec<Vec<Resultat>>),
    /// La personne a refusé, ou le mot de passe n'a pas été donné : rien n'a été fait, sans redemander.
    Refuse,
    /// Cette façon ne marche pas ici (pas d'agent polkit) : la suivante peut l'être.
    Indisponible,
}

/// Le texte envoyé au fils : les ordres, groupe après groupe, séparés par « suite », puis « fin ».
fn envoi(groupes: &[Vec<Ordre>]) -> String {
    let mut t = String::new();
    for (i, g) in groupes.iter().enumerate() {
        if i > 0 {
            t += SUITE;
            t.push('\n');
        }
        for o in g {
            t += &o.ligne();
            t.push('\n');
        }
    }
    t + FIN + "\n"
}

/// Les lignes reçues jusqu'à « fin », bornées en nombre et en longueur ; `None` si le flux s'arrête avant.
fn lire_lignes(source: impl Read) -> Option<Vec<String>> {
    let borne = u64::try_from((2 * LIGNES_MAX + 2) * (LIGNE_MAX + 2)).ok()?;
    let mut lecteur = BufReader::new(source.take(borne));
    let mut lignes = Vec::new();
    loop {
        let mut ligne = String::new();
        if lecteur.read_line(&mut ligne).ok()? == 0 {
            return None;
        }
        let ligne = ligne.trim_end_matches(['\r', '\n']).to_string();
        if ligne == FIN {
            return Some(lignes);
        }
        if ligne.len() > LIGNE_MAX || lignes.len() > 2 * LIGNES_MAX {
            return None;
        }
        lignes.push(ligne);
    }
}

/// La liste reçue, relue : des groupes d'ordres de la liste fermée, permis sur ce système ; `None` dès qu'une ligne
/// n'en est pas un, qu'un groupe est vide, ou qu'il y en a trop.
fn analyser_liste(lignes: &[String]) -> Option<Vec<Vec<Ordre>>> {
    let mut groupes = vec![Vec::new()];
    let mut total = 0;
    for l in lignes {
        if l == SUITE {
            groupes.push(Vec::new());
            continue;
        }
        let o = ordres::analyser(l).filter(Ordre::permis_ici)?;
        total += 1;
        groupes.last_mut()?.push(o);
    }
    (total > 0 && total <= LIGNES_MAX && groupes.iter().all(|g| !g.is_empty())).then_some(groupes)
}

/// Tout « non fait », avec la même raison.
fn tous_en_echec(groupes: &[Vec<Ordre>], raison: &str) -> Vec<Vec<Resultat>> {
    groupes
        .iter()
        .map(|g| g.iter().map(|_| Resultat::echec(raison)).collect())
        .collect()
}

/// Les réponses du fils, rangées dans les groupes ; `None` si leur nombre n'est pas celui des ordres.
fn ranger(groupes: &[Vec<Ordre>], reponses: &[String]) -> Option<Vec<Vec<Resultat>>> {
    let total: usize = groupes.iter().map(Vec::len).sum();
    if reponses.len() != total {
        return None;
    }
    let mut r = reponses.iter();
    Some(
        groupes
            .iter()
            .map(|g| {
                g.iter()
                    .filter_map(|_| r.next().map(|l| ordres::lire_reponse(l)))
                    .collect()
            })
            .collect(),
    )
}

fn essayer(m: Methode, groupes: &[Vec<Ordre>]) -> Issue {
    let (Some(chemin), Some(programme)) = (outil(m.nom()), programme()) else {
        return Issue::Indisponible;
    };
    let terminal = terminal();
    trp!(
        "    {GRIS}Droits d'administrateur demandés par {} : Vanguard fera lui-même les gestes montrés, et rien d'autre.{RESET}",
        "    {GRIS}Administrator rights asked through {}: Vanguard itself will do the steps shown, and nothing else.{RESET}",
        m.nom()
    );
    let Ok(mut fils) = commande(m, &chemin, &programme, terminal)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
    else {
        return Issue::Indisponible;
    };
    let (Some(mut entree), Some(sortie)) = (fils.stdin.take(), fils.stdout.take()) else {
        crate::commande::arreter(&mut fils);
        return Issue::Indisponible;
    };
    let mut lecteur = BufReader::new(sortie.take(u64::try_from((LIGNES_MAX + 4) * (LIGNE_MAX + 2)).unwrap_or(0)));
    // Pas de délai : la personne tape son mot de passe. Le fils mort sans s'être dit prêt ferme le tube.
    let mut premiere = String::new();
    let pret = lecteur.read_line(&mut premiere).is_ok_and(|n| n > 0) && premiere.trim_end() == PRET;
    if !pret {
        drop(entree);
        let code = fils.wait().ok().and_then(|s| s.code());
        return match (m, code) {
            // pkexec : 126, la personne a fermé la fenêtre ; 127, pas d'agent, ou pas autorisé : on essaie la suite.
            (Methode::Pkexec, Some(127)) => Issue::Indisponible,
            _ => Issue::Refuse,
        };
    }
    let envoye = entree
        .write_all(envoi(groupes).as_bytes())
        .and_then(|()| entree.flush());
    drop(entree);
    let reponses = if envoye.is_ok() {
        lire_lignes(&mut lecteur)
    } else {
        None
    };
    let _ = fils.wait();
    match reponses.and_then(|r| ranger(groupes, &r)) {
        Some(r) => Issue::Fait(r),
        None => Issue::Fait(tous_en_echec(
            groupes,
            tr!(
                "l'assistant administrateur n'a pas répondu jusqu'au bout : compté comme non fait",
                "the administrator helper did not answer to the end: counted as not done"
            ),
        )),
    }
}

/// Fait ces groupes d'ordres avec les droits d'administrateur : ici même si Vanguard tourne déjà en root, sinon par
/// l'assistant élevé, une seule demande pour tous. Une réponse par ordre, dans l'ordre reçu ; une demande refusée
/// rend tout « non fait », sans redemander.
pub(crate) fn appliquer(groupes: &[Vec<Ordre>]) -> Vec<Vec<Resultat>> {
    // SAFETY : geteuid ne prend aucun argument et ne touche aucune mémoire.
    if unsafe { libc::geteuid() } == 0 {
        let juge = ordres::Juge::lire(None);
        return ordres::executer_groupes(groupes, &juge, &mut |t| println!("    {GRIS}{t}{RESET}"));
    }
    // Les essais ne lancent jamais pkexec, run0 ni sudo pour de vrai.
    if cfg!(test) {
        return tous_en_echec(groupes, "essai : aucune élévation");
    }
    let graphique = std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some();
    let possibles = methodes(graphique, terminal(), |n| outil(n).is_some());
    for m in possibles {
        match essayer(m, groupes) {
            Issue::Fait(r) => return r,
            Issue::Refuse => {
                trp!(
                    "    Droits d'administrateur non obtenus ({}) : rien n'a été modifié.",
                    "    Administrator rights not obtained ({}): nothing was changed.",
                    m.nom()
                );
                return tous_en_echec(
                    groupes,
                    tr!("droits d'administrateur refusés", "administrator rights refused"),
                );
            }
            Issue::Indisponible => {}
        }
    }
    let raison = tr!(
        "aucun moyen d'obtenir les droits d'administrateur ici (ni pkexec avec un agent polkit, ni run0, ni sudo) : rien n'a été fait",
        "no way to get administrator rights here (neither pkexec with a polkit agent, nor run0, nor sudo): nothing was done"
    );
    trp!("    ✖ {}", "    ✖ {}", raison);
    tous_en_echec(groupes, raison)
}

// ------------------------------------------------------------------ le fils

/// La sous-commande `appliquer-eleve` sous Linux et macOS : rend le code de sortie du processus.
pub(crate) fn executer(langue: Option<&str>, parent: Option<u32>) -> i32 {
    if let Some(l) = langue {
        crate::langue::forcer(l == "en");
    }
    // SAFETY : geteuid ne prend aucun argument et ne touche aucune mémoire.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!(
            "{}",
            tr!(
                "Ce processus n'a pas les droits d'administrateur : rien n'est fait.",
                "This process has no administrator rights: nothing is done."
            )
        );
        return SANS_DROITS;
    }
    let mut sortie = std::io::stdout().lock();
    if writeln!(sortie, "{PRET}").and_then(|()| sortie.flush()).is_err() {
        return SANS_DROITS;
    }
    let Some(lignes) = lire_lignes(std::io::stdin().lock()) else {
        return LISTE_REFUSEE;
    };
    let Some(groupes) = analyser_liste(&lignes) else {
        eprintln!(
            "{}",
            tr!(
                "La liste reçue n'est pas une liste de gestes de Vanguard : rien n'est fait. Un autre programme y a touché : lancez une analyse antivirus.",
                "The list received is not a Vanguard step list: nothing is done. Another program touched it: run an antivirus scan."
            )
        );
        let _ = writeln!(sortie, "{FIN}");
        return LISTE_REFUSEE;
    };
    eprintln!(
        "{}",
        tr!(
            "Vanguard (administrateur) va faire :",
            "Vanguard (administrator) will do:"
        )
    );
    for o in groupes.iter().flatten() {
        eprintln!("  · {}", o.texte());
    }
    let juge = ordres::Juge::lire(parent);
    let resultats = ordres::executer_groupes(&groupes, &juge, &mut |t| eprintln!("{t}"));
    let mut code = 0;
    for r in resultats.iter().flatten() {
        if !r.reussi {
            code = 1;
        }
        if writeln!(sortie, "{}", ordres::ligne_reponse(r)).is_err() {
            return 1;
        }
    }
    let _ = writeln!(sortie, "{FIN}");
    let _ = sortie.flush();
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protection::blocage::pare_feu::PareFeu;

    fn pf() -> PareFeu {
        if cfg!(target_os = "macos") {
            PareFeu::Pf
        } else {
            PareFeu::Nftables
        }
    }

    #[test]
    fn l_ordre_des_methodes() {
        let tout = |_: &str| true;
        if cfg!(target_os = "linux") {
            assert_eq!(
                methodes(true, true, tout),
                [Methode::Pkexec, Methode::Run0, Methode::Sudo]
            );
            // Sans session graphique : pas de pkexec ; sans terminal : pas de run0.
            assert_eq!(methodes(false, true, tout), [Methode::Run0, Methode::Sudo]);
            assert_eq!(methodes(false, false, tout), [Methode::Sudo]);
            assert_eq!(methodes(true, false, |n| n == "pkexec"), [Methode::Pkexec]);
        } else {
            assert_eq!(methodes(true, true, tout), [Methode::Sudo]);
        }
        assert_eq!(methodes(true, true, |_| false), []);
    }

    /// La ligne de commande de l'élévation : l'image qui tourne, la sous-commande et rien d'autre (aucun shell).
    #[test]
    fn la_commande_d_elevation() {
        let c = commande(
            Methode::Pkexec,
            std::path::Path::new("/usr/bin/pkexec"),
            std::ffi::OsStr::new("/proc/4242/exe"),
            true,
        );
        let args: Vec<String> = c.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(c.get_program(), "/usr/bin/pkexec");
        assert_eq!(
            args[..3],
            ["--disable-internal-agent", "/proc/4242/exe", "appliquer-eleve"]
        );
        assert!(args.contains(&"--parent".to_string()));
        let s = commande(
            Methode::Sudo,
            std::path::Path::new("/usr/bin/sudo"),
            std::ffi::OsStr::new("/proc/4242/exe"),
            false,
        );
        let args: Vec<String> = s.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(args[..3], ["-n", "--", "/proc/4242/exe"]);
        let r = commande(
            Methode::Run0,
            std::path::Path::new("/usr/bin/run0"),
            std::ffi::OsStr::new("/proc/4242/exe"),
            true,
        );
        assert_eq!(r.get_args().next().unwrap(), "--");
    }

    /// Le dialogue des deux côtés : ce que le parent envoie se relit à l'identique ; une ligne étrangère, une liste
    /// vide, un groupe vide ou un flux sans fin sont refusés en entier.
    #[test]
    fn le_canal_se_relit_et_refuse_l_etranger() {
        let groupes = vec![
            vec![
                Ordre::BloquerSortie {
                    pare_feu: pf(),
                    ip: "203.0.113.7".parse().unwrap(),
                },
                Ordre::CouperConnexions {
                    ip: "203.0.113.7".parse().unwrap(),
                },
            ],
            vec![Ordre::ArreterProcessus {
                pid: 4242,
                chemin: "/home/alice/.cache/x".into(),
            }],
        ];
        let t = envoi(&groupes);
        let lignes = lire_lignes(t.as_bytes()).unwrap();
        assert_eq!(analyser_liste(&lignes), Some(groupes.clone()));
        for hostile in [
            "sudo sh -c id\nfin\n".to_string(),
            "fin\n".to_string(),
            format!("{SUITE}\n{}\nfin\n", groupes[1][0].ligne()),
            format!("{}\n{SUITE}\nfin\n", groupes[1][0].ligne()),
            "vanguard:bloquer-sortie windows 203.0.113.7\nfin\n".to_string(),
        ] {
            let l = lire_lignes(hostile.as_bytes()).unwrap();
            assert_eq!(analyser_liste(&l), None, "{hostile:?}");
        }
        assert!(lire_lignes(&b"vanguard:couper-connexions 203.0.113.7\n"[..]).is_none());
        let longue = format!("{}\nfin\n", "a".repeat(LIGNE_MAX + 1));
        assert!(lire_lignes(longue.as_bytes()).is_none());
        let trop = format!("{}fin\n", "x\n".repeat(2 * LIGNES_MAX + 2));
        assert!(lire_lignes(trop.as_bytes()).is_none());
        // Les réponses : autant que d'ordres, sinon tout est compté non fait.
        let r = ranger(
            &groupes,
            &["ok".into(), "ok note=1 coupée".into(), "echec refusé".into()],
        )
        .unwrap();
        assert!(r[0][0].reussi && r[0][1].note.as_deref() == Some("1 coupée") && !r[1][0].reussi);
        assert!(ranger(&groupes, &["ok".into()]).is_none());
    }

    /// Sous les essais, rien n'est jamais élevé pour de vrai : tout est « non fait », dit.
    #[test]
    fn jamais_d_elevation_dans_les_essais() {
        // SAFETY : geteuid ne prend aucun argument et ne touche aucune mémoire.
        if unsafe { libc::geteuid() } == 0 {
            return crate::essais::saute("essais lancés en root : l'ordre se ferait ici");
        }
        let r = appliquer(&[vec![Ordre::CouperConnexions {
            ip: "203.0.113.7".parse().unwrap(),
        }]]);
        assert!(!r[0][0].reussi);
    }
}

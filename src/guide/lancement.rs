//! Lancer ici une commande du guide qui ne fait que lire : sa sortie défile dans Vanguard comme dans un terminal, et
//! Échap l'arrête. Jamais une commande marquée ⚠, ni une qui ouvre une fenêtre, occupe tout le terminal, écrit un
//! fichier ou demande les droits d'administrateur : celles-là se tapent dans un terminal (`pourquoi_pas`).

use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};

use super::{Commande, Obstacle, Programme, Systeme, installe};
use crate::risk::Niveau;
use crate::selection::ModeClavier;
use crate::ui::*;

/// Au-delà, la commande est arrêtée : une commande qui suit un journal (journalctl -f) ou qui ne finit pas d'elle-même
/// (ping sous Linux et macOS) ne tourne pas sans fin si on oublie Vanguard.
const DELAI: Duration = Duration::from_secs(120);

/// Au-delà, les lignes sont comptées sans être montrées : l'écran ne se noie pas sous un journal entier.
const LIGNES_MONTREES: usize = 1000;

/// Pourquoi Vanguard ne lance cette commande sur aucun ordinateur ; `None` : rien ne l'en empêche.
pub(super) fn obstacle(c: &Commande) -> Option<&'static str> {
    if c.obstacle == Obstacle::NonVerifiee {
        return Some(tr!(
            "Elle vient de tldr-pages, que Vanguard n'a pas vérifié : copiez-la, et lisez-la avant de la taper.",
            "It comes from tldr-pages, which Vanguard has not checked: copy it, and read it before typing it."
        ));
    }
    if c.modifie {
        return Some(tr!(
            "Elle change quelque chose : à taper vous-même dans un terminal, en sachant ce qu'elle fait.",
            "It changes something: type it yourself in a terminal, knowing what it does."
        ));
    }
    if c.ligne.contains('<') {
        return Some(tr!(
            "Elle a des mots à remplacer (<…>) : copiez-la, puis complétez-la dans un terminal.",
            "It has words to replace (<…>): copy it, then complete it in a terminal."
        ));
    }
    if c.ligne.starts_with("vanguard") {
        return Some(tr!(
            "C'est Vanguard lui-même : son menu fait la même chose.",
            "It is Vanguard itself: its menu does the same."
        ));
    }
    let obstacle = if c.ligne.split_whitespace().any(|m| m == "sudo") {
        Obstacle::Administrateur
    } else {
        c.obstacle
    };
    match obstacle {
        Obstacle::Aucun | Obstacle::NonVerifiee => None,
        Obstacle::Administrateur => Some(tr!(
            "Elle demande les droits d'administrateur : à taper dans un terminal.",
            "It needs administrator rights: type it in a terminal."
        )),
        Obstacle::Fenetre => Some(tr!(
            "Elle ouvre une fenêtre et n'écrit rien ici : à taper dans un terminal.",
            "It opens a window and writes nothing here: type it in a terminal."
        )),
        Obstacle::PleinEcran => Some(tr!(
            "Elle occupe tout le terminal : à taper dans un vrai terminal (q pour en sortir).",
            "It takes over the whole terminal: type it in a real terminal (q to leave)."
        )),
        Obstacle::Fichier => Some(tr!(
            "Elle écrit un fichier de rapport : à taper dans un terminal, dans le dossier de votre choix.",
            "It writes a report file: type it in a terminal, in the folder of your choice."
        )),
        Obstacle::Longue => Some(tr!(
            "Elle prend plusieurs minutes, avec les droits d'administrateur : à lancer dans un terminal administrateur.",
            "It takes several minutes, with administrator rights: run it in an administrator terminal."
        )),
    }
}

/// Pourquoi Vanguard ne lance pas cette commande sur cet ordinateur ; `None` : il le peut, au choix « Lancer ici ».
pub(super) fn pourquoi_pas(s: Systeme, p: &Programme, c: &Commande) -> Option<String> {
    if let Some(raison) = obstacle(c) {
        return Some(raison.to_string());
    }
    if !s.d_ici() {
        return Some(trf!(
            "C'est une commande de {} : elle ne marche pas sur cet ordinateur.",
            "It is a {} command: it does not work on this computer.",
            s.nom()
        ));
    }
    (!installe(p)).then(|| {
        tr!(
            "Son programme n'est pas installé sur cet ordinateur.",
            "Its program is not installed on this computer."
        )
        .to_string()
    })
}

/// Le programme qui lance la ligne : sh sous Linux et macOS ; sous Windows, Windows PowerShell, où se tapent les
/// commandes du guide pour Windows, sa sortie en UTF-8 et sans barre de progression (elle s'écrirait par-dessus
/// l'écran de Vanguard).
fn processus(ligne: &str) -> Command {
    #[cfg(windows)]
    {
        let mut c = crate::machine::windows::powershell();
        c.args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!(
                "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ProgressPreference='SilentlyContinue'; {ligne}"
            ),
        ]);
        c
    }
    #[cfg(not(windows))]
    {
        let mut c = Command::new("sh");
        c.args(["-c", ligne]);
        // Jamais de pager (la sortie va à Vanguard), et la largeur de la fenêtre pour ps, systemctl…
        c.env("PAGER", "cat")
            .env("GIT_PAGER", "cat")
            .env("SYSTEMD_PAGER", "cat");
        if let Ok((largeur, _)) = crossterm::terminal::size() {
            c.env("COLUMNS", largeur.saturating_sub(2).to_string());
        }
        c
    }
}

/// Ce qui a mis fin à une commande lancée ici.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Fin {
    /// Finie d'elle-même, avec son code de retour (`None` : tuée par un signal).
    Code(Option<i32>),
    /// Arrêtée par Échap ou Ctrl-C.
    Arretee,
    /// Arrêtée au bout du délai.
    TropLongue,
    /// Pas démarrée : l'erreur du système.
    PasDemarree(String),
}

/// Lance `ligne` et passe chacune de ses lignes (sortie et erreurs, dans l'ordre d'arrivée : deux lignes écrites à
/// la même milliseconde sur l'une et l'autre peuvent s'inverser) à `montrer`, au fil de l'eau ; `montrer(None)` revient entre deux, pour une attente qui avance. `clavier` : Échap ou Ctrl-C l'arrêtent
/// (le terminal doit être en mode clavier). Rend ce qui y a mis fin.
pub(super) fn derouler(ligne: &str, delai: Duration, clavier: bool, mut montrer: impl FnMut(Option<&str>)) -> Fin {
    let mut enfant = match processus(ligne)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(enfant) => enfant,
        Err(e) => return Fin::PasDemarree(e.to_string()),
    };
    let flux: Vec<Box<dyn Read + Send>> = [
        enfant.stdout.take().map(|f| Box::new(f) as Box<dyn Read + Send>),
        enfant.stderr.take().map(|f| Box::new(f) as Box<dyn Read + Send>),
    ]
    .into_iter()
    .flatten()
    .collect();
    let mut ouverts = flux.len();
    let (envoi, reception) = mpsc::channel::<Option<String>>();
    for f in flux {
        let envoi = envoi.clone();
        std::thread::spawn(move || {
            let mut lecteur = BufReader::new(f);
            let mut octets = Vec::new();
            while lecteur.read_until(b'\n', &mut octets).is_ok_and(|n| n > 0) {
                if envoi.send(Some(String::from_utf8_lossy(&octets).into_owned())).is_err() {
                    return;
                }
                octets.clear();
            }
            let _ = envoi.send(None);
        });
    }
    drop(envoi);
    let debut = Instant::now();
    let fin = loop {
        while let Ok(message) = reception.try_recv() {
            match message {
                Some(l) => montrer(Some(&l)),
                None => ouverts -= 1,
            }
        }
        montrer(None);
        if let Ok(Some(statut)) = enfant.try_wait() {
            break Fin::Code(statut.code());
        }
        if debut.elapsed() >= delai {
            crate::commande::arreter(&mut enfant);
            break Fin::TropLongue;
        }
        if !clavier {
            std::thread::sleep(Duration::from_millis(15));
        } else if event::poll(Duration::from_millis(30)).unwrap_or(false)
            && let Ok(Event::Key(k)) = event::read()
            && k.kind != KeyEventKind::Release
            && (k.code == KeyCode::Esc
                || (k.modifiers.contains(KeyModifiers::CONTROL) && matches!(k.code, KeyCode::Char('c' | 'd'))))
        {
            crate::commande::arreter(&mut enfant);
            break Fin::Arretee;
        }
    };
    // Ce que la commande a écrit juste avant de finir. Deux secondes au plus : un programme resté en arrière-plan peut
    // garder la sortie ouverte.
    let limite = Instant::now() + Duration::from_secs(2);
    while ouverts > 0 {
        match reception.recv_timeout(limite.saturating_duration_since(Instant::now())) {
            Ok(Some(l)) => montrer(Some(&l)),
            Ok(None) => ouverts -= 1,
            Err(_) => break,
        }
    }
    fin
}

/// Une ligne de sortie prête à montrer : sans sa fin de ligne, ses couleurs retirées, le retour chariot et le retour
/// arrière appliqués comme dans un terminal (barres de progression), les tabulations en espaces, et tout autre
/// caractère de contrôle neutralisé (`ui::affichable`) : la sortie peut contenir un nom piégé (réseau Wi-Fi, fichier).
pub(super) fn nettoyer(ligne: &str) -> String {
    let ligne = ligne.trim_end_matches(['\n', '\r']);
    // Après un retour chariot, la suite réécrit la ligne : seule sa dernière version compte.
    let ligne = ligne.rsplit('\r').find(|l| !l.trim().is_empty()).unwrap_or("");
    let mut sortie = String::with_capacity(ligne.len());
    let mut colonne: usize = 0;
    let mut caracteres = ligne.chars().peekable();
    while let Some(c) = caracteres.next() {
        match c {
            // Une couleur (ESC [ chiffres m) disparaît ; toute autre séquence reste neutralisée par `affichable`.
            '\x1b' if caracteres.peek() == Some(&'[') => {
                let parametres: String = caracteres
                    .clone()
                    .skip(1)
                    .take_while(|c| c.is_ascii_digit() || *c == ';')
                    .collect();
                if caracteres.clone().nth(parametres.len() + 1) == Some('m') {
                    for _ in 0..parametres.len() + 2 {
                        caracteres.next();
                    }
                } else {
                    sortie.push(c);
                }
            }
            '\x08' => {
                if let Some(efface) = sortie.pop() {
                    colonne = colonne.saturating_sub(largeur_car(efface));
                }
            }
            '\t' => {
                let espaces = 8 - colonne % 8;
                sortie.extend(std::iter::repeat_n(' ', espaces));
                colonne += espaces;
            }
            _ => {
                sortie.push(c);
                colonne += largeur_car(c);
            }
        }
    }
    affichable(&sortie)
}

/// Le dossier où la commande s'exécute, le dossier personnel abrégé en « ~ » comme à l'invite d'un terminal.
fn abreger(dossier: &Path) -> String {
    let maison = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from);
    match maison.and_then(|m| dossier.strip_prefix(m).ok().map(Path::to_path_buf)) {
        Some(reste) if reste.as_os_str().is_empty() => "~".to_string(),
        Some(reste) => format!("~{}{}", std::path::MAIN_SEPARATOR, reste.display()),
        None => dossier.display().to_string(),
    }
}

/// Lance la commande sous les yeux : son dossier et sa ligne comme à l'invite d'un terminal, sa sortie au fil de
/// l'eau (une attente qui avance, Échap pour arrêter), puis comment elle a fini. Revient après Entrée, le temps de lire.
pub(super) fn lancer_ici(c: &Commande) {
    let dossier = std::env::current_dir().map(|d| abreger(&d)).unwrap_or_default();
    println!(
        "  {GRIS}{}{RESET} {ACCENT}›{RESET} {GRAS}{}{RESET}\n",
        affichable(&dossier),
        c.ligne
    );
    let _ = std::io::stdout().flush();
    let interactif = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let mode = if interactif { ModeClavier::activer() } else { None };
    let clavier = mode.is_some();
    // En mode clavier, le terminal ne revient plus seul au début de la ligne.
    let saut = if clavier { "\r\n" } else { "\n" };
    let debut = Instant::now();
    let (mut montrees, mut cachees) = (0, 0);
    let mut seconde_montree = 0;
    let mut sortie = std::io::stdout();
    let fin = derouler(c.ligne, DELAI, clavier, |ligne| {
        let mut ecran = String::new();
        if let Some(l) = ligne {
            if montrees < LIGNES_MONTREES {
                // La ligne d'attente s'efface, la ligne de sortie prend sa place, l'attente revient dessous.
                ecran += "\r\x1b[K  ";
                ecran += &nettoyer(l);
                ecran += saut;
                montrees += 1;
                seconde_montree = 0;
            } else {
                cachees += 1;
            }
        }
        // L'attente ne paraît qu'après une seconde : une commande rapide ne clignote pas.
        let secondes = debut.elapsed().as_secs();
        if clavier && secondes >= 1 && secondes != seconde_montree {
            seconde_montree = secondes;
            ecran += &trf!(
                "\r\x1b[K  {GRIS}⏳ {secondes} s · Échap arrête{RESET}",
                "\r\x1b[K  {GRIS}⏳ {secondes} s · Esc stops{RESET}"
            );
        }
        if !ecran.is_empty() {
            let _ = sortie.write_all(ecran.as_bytes());
            let _ = sortie.flush();
        }
    });
    if clavier {
        print!("\r\x1b[K");
    }
    drop(mode);
    let duree = crate::langue::decimal(debut.elapsed().as_secs_f64(), 1);
    if montrees == 0 && !matches!(fin, Fin::PasDemarree(_)) {
        trp!("  {GRIS}(Rien d'écrit.){RESET}", "  {GRIS}(Nothing written.){RESET}");
    }
    if cachees > 0 {
        trp!(
            "  {GRIS}… et {cachees} ligne(s) de plus, non montrées.{RESET}",
            "  {GRIS}… and {cachees} more line(s), not shown.{RESET}"
        );
    }
    let orange = couleur(Niveau::Moyen);
    match fin {
        Fin::Code(Some(0)) => trp!(
            "\n  {VERT}✔{RESET} Terminée en {duree} s.",
            "\n  {VERT}✔{RESET} Done in {duree} s."
        ),
        Fin::Code(Some(code)) => trp!(
            "\n  {orange}●{RESET} Terminée en {duree} s, avec le code {code} : une erreur, ou rien de trouvé,\n    selon la commande.",
            "\n  {orange}●{RESET} Done in {duree} s, with code {code}: an error, or nothing found,\n    depending on the command."
        ),
        Fin::Code(None) => trp!(
            "\n  {orange}●{RESET} Arrêtée par le système après {duree} s.",
            "\n  {orange}●{RESET} Stopped by the system after {duree} s."
        ),
        Fin::Arretee => trp!(
            "\n  {GRIS}■{RESET} Arrêtée après {duree} s, à votre demande.",
            "\n  {GRIS}■{RESET} Stopped after {duree} s, as you asked."
        ),
        Fin::TropLongue => trp!(
            "\n  {orange}●{RESET} Arrêtée au bout de deux minutes : pour la laisser tourner, tapez-la dans\n    un terminal.",
            "\n  {orange}●{RESET} Stopped after two minutes: to let it run, type it in a terminal."
        ),
        Fin::PasDemarree(erreur) => trp!(
            "  {orange}✖{RESET} Elle n'a pas pu démarrer : {}",
            "  {orange}✖{RESET} It could not start: {}",
            affichable(&erreur)
        ),
    }
    crate::selection::attendre_retour(tr!("\n  Entrée pour revenir : ", "\n  Enter to go back: "));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn une_sortie_se_montre_sans_piege() {
        assert_eq!(nettoyer("a\tb\r\n"), "a       b");
        assert_eq!(nettoyer("\x1b[31mErreur\x1b[0m : disque\n"), "Erreur : disque");
        assert_eq!(nettoyer("\x1b[1;92mOK\x1b[m"), "OK");
        // Une barre de progression : seule la dernière version de la ligne reste.
        assert_eq!(nettoyer("10 %\r50 %\r100 %\r\n"), "100 %");
        assert_eq!(nettoyer("abc\x08\x08x"), "ax");
        // Ce qui piloterait le terminal (effacer, réécrire, presse-papier) est neutralisé, pas exécuté.
        let piege = nettoyer("Salon\x1b[2K\x1b]52;c;cGlwZQ==\x07\u{202e}fin");
        assert!(!piege.contains('\x1b') && !piege.contains('\u{202e}') && !piege.contains('\x07'));
        assert!(piege.starts_with("Salon\u{fffd}"));
        // Les tabulations suivent les colonnes, accents et émojis compris.
        assert_eq!(nettoyer("é\tx"), "é       x");
        assert_eq!(nettoyer("💾\tx"), "💾      x");
    }

    #[test]
    fn dossier_abrege_comme_a_l_invite() {
        let Some(maison) = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from)
        else {
            return crate::essais::saute("ni HOME ni USERPROFILE");
        };
        assert_eq!(abreger(&maison), "~");
        assert_eq!(
            abreger(&maison.join("Projets")),
            format!("~{}Projets", std::path::MAIN_SEPARATOR)
        );
    }

    /// Sortie et erreurs arrivent, dans l'ordre, avec le code de retour.
    #[cfg(unix)]
    #[test]
    fn une_commande_deroule_sa_sortie() {
        let mut lignes = Vec::new();
        let fin = derouler(
            "printf 'un\\n'; sleep 0.3; printf 'deux\\n' >&2; sleep 0.3; printf 'trois'; exit 3",
            Duration::from_secs(10),
            false,
            |l| lignes.extend(l.map(nettoyer)),
        );
        assert_eq!(fin, Fin::Code(Some(3)));
        assert_eq!(lignes, ["un", "deux", "trois"]);
    }

    /// Trop longue, elle est arrêtée, ses enfants aussi, et ce qu'elle avait écrit reste.
    #[cfg(unix)]
    #[test]
    fn une_commande_trop_longue_s_arrete() {
        let debut = Instant::now();
        let mut lignes = Vec::new();
        let fin = derouler(
            "echo avant; sleep 30 | cat; echo jamais",
            Duration::from_millis(500),
            false,
            |l| lignes.extend(l.map(nettoyer)),
        );
        assert_eq!(fin, Fin::TropLongue);
        assert_eq!(lignes, ["avant"]);
        assert!(debut.elapsed() < Duration::from_secs(10));
    }

    /// Sous Wine, PowerShell n'est qu'un bouchon : seulement sous Linux et macOS.
    #[cfg(unix)]
    #[test]
    fn un_programme_absent_ne_demarre_pas_ou_echoue() {
        let fin = derouler(
            "vanguard-programme-qui-n-existe-pas",
            Duration::from_secs(20),
            false,
            |_| {},
        );
        assert!(
            matches!(fin, Fin::Code(Some(c)) if c != 0) || matches!(fin, Fin::PasDemarree(_)),
            "{fin:?}"
        );
    }
}

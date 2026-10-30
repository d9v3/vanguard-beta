//! La fenêtre épouse le menu : large de `LARGEUR` + 2 colonnes, assez haute pour toutes ses lignes sans dépasser
//! l'écran. Sous Hyprland, une hauteur fixe posée une fois (`RANGEES_FIXES`), au milieu de l'écran : chaque
//! changement de taille s'anime, et la transition se voyait d'un menu à l'autre. Sous Windows, la hauteur suit
//! chaque menu, mais la fenêtre reste là où la personne l'a mise (ramenée dans l'écran seulement si elle en sort).
//!
//! Seulement une fenêtre ouverte pour Vanguard : sous Hyprland, la fenêtre flottante du terminal qui l'a lancé
//! lui-même (le raccourci du menu des applications) ; sous Windows, une console où Vanguard est seul (double-clic),
//! la vieille console comme le Terminal Windows. Lancé depuis un terminal déjà ouvert, sur les autres bureaux Linux
//! et sous macOS, rien ne dit que la fenêtre est la sienne : elle ne bouge pas.
//!
//! Le terminal arrondit la fenêtre à ses cases, et ses bordures ne se voient pas de l'intérieur : la taille d'une case
//! se devine d'abord (la fenêtre divisée par la grille, bordures comprises, donc un peu grande), puis se mesure entre
//! deux tailles ; trois retouches au plus, qui repartent toutes de la place choisie par la personne. Le tout dans un
//! fil à part : le menu n'attend pas, et se redessine quand sa grille change (annoncée par le terminal, ou relue par
//! `selection` : la vieille console de Windows ne l'annonce pas).

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crossterm::terminal;

use crate::ui::LARGEUR;

/// Les colonnes voulues : les lignes du menu (`LARGEUR`) et la marge que demande `selection` pour le mode clavier.
#[allow(clippy::cast_possible_truncation)]
const COLONNES: u16 = LARGEUR as u16 + 2;

/// Jamais moins : sous un petit menu, les pauses et les questions des outils ont besoin de place.
const RANGEES_MINIMUM: u16 = 12;

/// Sous Hyprland, la hauteur du cadre, la même pour tous les menus : assez pour le plus haut (bornée à l'écran par
/// `placement`). Un menu plus haut encore la fait grandir une fois, jamais rapetisser.
#[cfg(target_os = "linux")]
const RANGEES_FIXES: u16 = 40;

/// Recentrer la fenêtre : sous Hyprland seulement, avec sa taille fixe ; sous Windows, la place choisie est gardée.
const CENTRER: bool = cfg!(target_os = "linux");

/// Le numéro de la dernière demande : un fil plus ancien s'arrête dès qu'une autre a suivi.
static DEMANDE: AtomicU64 = AtomicU64::new(0);

/// La dernière hauteur demandée : redessiner le même menu (une flèche, un caractère tapé) ne redemande rien.
static DERNIERE: Mutex<Option<u16>> = Mutex::new(None);

/// Une fenêtre et ce qu'elle montre : position et taille en pixels du bureau, grille du terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Mesure {
    x: i32,
    y: i32,
    l: i32,
    h: i32,
    colonnes: u16,
    rangees: u16,
}

/// Ce que l'écran laisse aux fenêtres : sans la barre des tâches ni celle du bureau.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Zone {
    x: i32,
    y: i32,
    l: i32,
    h: i32,
}

/// Une place : position et taille en pixels.
type Place = (i32, i32, i32, i32);

/// Demande une fenêtre de `rangees` lignes (le menu, son aide et la saisie), sans attendre qu'elle soit faite.
pub fn epouser(rangees: usize) {
    let rangees = u16::try_from(rangees).unwrap_or(u16::MAX).max(RANGEES_MINIMUM);
    #[cfg(target_os = "linux")]
    let rangees = rangees.max(RANGEES_FIXES);
    {
        let Ok(mut derniere) = DERNIERE.lock() else {
            return;
        };
        // Sous Hyprland, la taille ne fait que grandir : la même, ou plus petite, ne redemande rien.
        if *derniere == Some(rangees) || (CENTRER && derniere.is_some_and(|d| d >= rangees)) {
            return;
        }
        *derniere = Some(rangees);
    }
    let demande = DEMANDE.fetch_add(1, Ordering::SeqCst) + 1;
    let _ = std::thread::Builder::new()
        .name("fenetre".into())
        .spawn(move || ajuster(demande, COLONNES, rangees));
}

fn ajuster(demande: u64, colonnes: u16, rangees: u16) {
    let Some(fenetre) = systeme::Fenetre::trouver() else {
        return;
    };
    let mut avant = None;
    // Trois retouches de la taille ; une quatrième mesure ne fait plus que remettre la fenêtre à sa place.
    for tour in 0..4 {
        if DEMANDE.load(Ordering::SeqCst) != demande {
            return;
        }
        let Some((m, zone)) = fenetre.mesurer() else {
            return;
        };
        let ancre = ancre(PLACE.lock().ok().and_then(|p| *p), &m);
        let pas = match pas(ancre, m, avant, colonnes, rangees, zone, CENTRER) {
            Pas::Poser(_) if tour == 3 => Pas::Finir(rester(ancre, &m, zone, CENTRER)),
            pas => pas,
        };
        match pas {
            Pas::Finir(place) => {
                if let Some(place) = place {
                    fenetre.placer(place, &m);
                }
                noter(ancre, place.map_or((m.x, m.y), |p| (p.0, p.1)));
                return;
            }
            Pas::Poser(place) => {
                fenetre.placer(place, &m);
                noter(ancre, (place.0, place.1));
                attendre_la_grille((m.colonnes, m.rangees));
                avant = Some(m);
            }
        }
    }
}

/// Le coin d'une fenêtre, en pixels du bureau.
type Coin = (i32, i32);

/// La place de la personne, et celle où Vanguard a posé la fenêtre en dernier pour la respecter : d'une retouche à
/// l'autre, et d'une demande à l'autre quand les menus se suivent vite (un fil coupé par le suivant).
static PLACE: Mutex<Option<(Coin, Coin)>> = Mutex::new(None);

fn noter(ancre: Coin, posee: Coin) {
    if let Ok(mut place) = PLACE.lock() {
        *place = Some((ancre, posee));
    }
}

/// D'où repart la retouche : la place de la personne, tant que la fenêtre est encore là où Vanguard l'a posée ;
/// ailleurs, c'est qu'elle l'a déplacée (ou mise sur un autre écran) : sa nouvelle place devient la référence.
fn ancre(memoire: Option<(Coin, Coin)>, m: &Mesure) -> Coin {
    match memoire {
        Some((ancre, posee)) if centree(m, (posee.0, posee.1, m.l, m.h)) => ancre,
        _ => (m.x, m.y),
    }
}

/// Ce que fait une retouche : poser la fenêtre puis la mesurer encore, ou finir, en la remettant à sa place s'il le
/// faut (la taille ne change plus).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pas {
    Poser(Place),
    Finir(Option<Place>),
}

/// Une retouche, depuis la mesure `m` (et celle d'avant la retouche précédente). `ancre` : la place choisie par la
/// personne (voir `ancre`) ; chaque retouche repart d'elle, pas du coin du moment. Au premier pas, la case devinée un
/// peu grande peut faire la fenêtre trop haute, donc la remonter pour rester dans la zone : le pas suivant, qui la
/// rapetisse, doit la redescendre d'autant, sans quoi un vide reste sous elle.
fn pas(ancre: Coin, m: Mesure, avant: Option<Mesure>, colonnes: u16, rangees: u16, zone: Zone, centrer: bool) -> Pas {
    let depuis = Mesure {
        x: ancre.0,
        y: ancre.1,
        ..m
    };
    let place = placement(depuis, avant, colonnes, rangees, zone, centrer);
    // La bonne grille, ou la plus grande que l'écran permet : reste la place, pour la taille d'à présent.
    if atteinte(&m, colonnes, rangees) || (place.2, place.3) == (m.l, m.h) {
        return Pas::Finir(rester(ancre, &m, zone, centrer));
    }
    Pas::Poser(place)
}

/// La place de la fenêtre à sa taille d'à présent, depuis `ancre` ; `None` si elle y est déjà.
fn rester(ancre: Coin, m: &Mesure, zone: Zone, centrer: bool) -> Option<Place> {
    let depuis = Mesure {
        x: ancre.0,
        y: ancre.1,
        ..*m
    };
    let (x, y, ..) = placement(depuis, None, m.colonnes, m.rangees, zone, centrer);
    let place = (x, y, m.l, m.h);
    (!centree(m, place)).then_some(place)
}

/// La grille est-elle à la taille voulue ? Une case de trop est permise : la fenêtre tombe sur les cases du terminal.
fn atteinte(m: &Mesure, colonnes: u16, rangees: u16) -> bool {
    (colonnes..=colonnes.saturating_add(1)).contains(&m.colonnes)
        && (rangees..=rangees.saturating_add(1)).contains(&m.rangees)
}

/// La fenêtre est-elle déjà à sa place ? Quelques pixels d'écart (bordures, arrondis du bureau) ne comptent pas.
fn centree(m: &Mesure, place: Place) -> bool {
    (m.x - place.0).abs() <= 4 && (m.y - place.1).abs() <= 4
}

/// La place de la fenêtre pour `colonnes` × `rangees` cases : bornée à la zone ; au milieu de la zone avec `centrer`,
/// sinon là où elle est, ramenée dans la zone si elle en dépasse.
fn placement(m: Mesure, avant: Option<Mesure>, colonnes: u16, rangees: u16, zone: Zone, centrer: bool) -> Place {
    let l = pixels(m.l, m.colonnes, colonnes, avant.map(|a| (a.l, a.colonnes))).clamp(1, zone.l.max(1));
    let h = pixels(m.h, m.rangees, rangees, avant.map(|a| (a.h, a.rangees))).clamp(1, zone.h.max(1));
    if centrer {
        (zone.x + (zone.l - l) / 2, zone.y + (zone.h - h) / 2, l, h)
    } else {
        let gauche = m.x.clamp(zone.x, (zone.x + zone.l - l).max(zone.x));
        let haut = m.y.clamp(zone.y, (zone.y + zone.h - h).max(zone.y));
        (gauche, haut, l, h)
    }
}

/// Les pixels d'une fenêtre de `cible` cases, quand `px` pixels en montrent `n`. La case se mesure entre deux tailles
/// (`avant`) ; sans elle, elle se devine par `px / n`, un peu grande à cause des bordures. Pour grandir, elle donne
/// assez de lignes ; pour rapetisser, elle en retire trop : la cible prend alors une ligne de plus (permise par
/// `atteinte`), et la retouche suivante, avec la case mesurée, finit le travail si ça ne suffit pas.
fn pixels(px: i32, n: u16, cible: u16, avant: Option<(i32, u16)>) -> i32 {
    let (mut pas_px, mut pas_n, mut cible) = (i64::from(px), i64::from(n.max(1)), i64::from(cible));
    let mesuree = avant.and_then(|(px_avant, n_avant)| {
        let (d_px, d_n) = (i64::from(px) - i64::from(px_avant), i64::from(n) - i64::from(n_avant));
        // Grille et fenêtre ont bougé dans le même sens ; sinon la mesure est fausse (fenêtre encore en mouvement).
        (d_px * d_n > 0).then_some((d_px.abs(), d_n.abs()))
    });
    match mesuree {
        Some(pas) => (pas_px, pas_n) = pas,
        None if cible < i64::from(n) => cible += 1,
        None => {}
    }
    let ecart = (cible - i64::from(n)) * pas_px;
    let ecart = if ecart >= 0 {
        (ecart + pas_n - 1) / pas_n
    } else {
        ecart / pas_n
    };
    i32::try_from(i64::from(px) + ecart).unwrap_or(px)
}

/// Attend que le terminal ait fini de suivre la fenêtre : le bureau anime le changement, et la grille passe par
/// chaque étape. Trois lectures égales après un changement, ou rien de changé après 0,6 s ; 1,5 s au plus.
fn attendre_la_grille(avant: (u16, u16)) {
    let debut = Instant::now();
    let (mut derniere, mut egales, mut changee) = (avant, 0, false);
    while debut.elapsed() < Duration::from_millis(1500) {
        std::thread::sleep(Duration::from_millis(40));
        let Ok(taille) = terminal::size() else {
            return;
        };
        changee |= taille != avant;
        egales = if taille == derniere { egales + 1 } else { 0 };
        derniere = taille;
        if (changee && egales >= 3) || (!changee && debut.elapsed() > Duration::from_millis(600)) {
            return;
        }
    }
}

/// La grille du terminal, avec la place de la fenêtre et la zone de son écran.
#[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
fn mesure(place: Place) -> Option<Mesure> {
    let (colonnes, rangees) = terminal::size().ok()?;
    (place.2 > 0 && place.3 > 0 && colonnes > 0 && rangees > 0).then_some(Mesure {
        x: place.0,
        y: place.1,
        l: place.2,
        h: place.3,
        colonnes,
        rangees,
    })
}

#[cfg(target_os = "linux")]
mod systeme {
    //! Hyprland, par son socket de commandes : la fenêtre du terminal parent, si elle flotte.

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::time::Duration;

    use serde_json::Value;

    use super::{Mesure, Place, Zone, mesure};

    /// Le bord laissé libre autour d'une fenêtre aussi haute que l'écran.
    const MARGE: i32 = 10;

    pub(super) struct Fenetre {
        socket: PathBuf,
        adresse: String,
    }

    impl Fenetre {
        pub(super) fn trouver() -> Option<Self> {
            let signature = std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE")?;
            let socket = PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR")?)
                .join("hypr")
                .join(signature)
                .join(".socket.sock");
            // SAFETY : getppid ne lit que le numéro du processus parent ; elle ne peut pas échouer.
            let parent = i64::from(unsafe { libc::getppid() });
            let clients: Value = serde_json::from_str(&demander(&socket, "j/clients")?).ok()?;
            // Le terminal qui a lancé Vanguard lui-même : pas un shell entre eux. Une seule fenêtre à ce processus
            // (un serveur de terminal en a plusieurs : laquelle ?), et qui flotte : une tuile appartient à la grille.
            let mut siennes = clients.as_array()?.iter().filter(|c| c["pid"].as_i64() == Some(parent));
            let client = siennes.next()?;
            if siennes.next().is_some() || client["floating"].as_bool() != Some(true) {
                return None;
            }
            let adresse = adresse(client["address"].as_str()?)?;
            Some(Fenetre { socket, adresse })
        }

        pub(super) fn mesurer(&self) -> Option<(Mesure, Zone)> {
            let clients: Value = serde_json::from_str(&demander(&self.socket, "j/clients")?).ok()?;
            let client = clients
                .as_array()?
                .iter()
                .find(|c| c["address"].as_str() == Some(self.adresse.as_str()))?;
            let nombre = |cle: &str, i: usize| client.get(cle)?.get(i)?.as_i64().and_then(|n| i32::try_from(n).ok());
            let place = (
                nombre("at", 0)?,
                nombre("at", 1)?,
                nombre("size", 0)?,
                nombre("size", 1)?,
            );
            let ecrans: Value = serde_json::from_str(&demander(&self.socket, "j/monitors")?).ok()?;
            let ecran = ecrans
                .as_array()?
                .iter()
                .find(|m| m["id"].as_i64().is_some() && m["id"] == client["monitor"])?;
            Some((mesure(place)?, zone(ecran)?))
        }

        /// Hyprland centre lui-même la fenêtre sur son écran ; seule la taille se donne.
        pub(super) fn placer(&self, place: Place, actuelle: &Mesure) {
            let fenetre = format!("window = \"address:{}\"", self.adresse);
            if (place.2, place.3) != (actuelle.l, actuelle.h) {
                let _ = demander(
                    &self.socket,
                    &format!(
                        "/dispatch hl.dsp.window.resize({{ {fenetre}, x = {}, y = {} }})",
                        place.2, place.3
                    ),
                );
            }
            let _ = demander(
                &self.socket,
                &format!("/dispatch hl.dsp.window.center({{ {fenetre} }})"),
            );
        }
    }

    /// L'adresse d'une fenêtre, vérifiée avant d'entrer dans une commande : « 0x » et des chiffres hexadécimaux.
    fn adresse(a: &str) -> Option<String> {
        let chiffres = a.strip_prefix("0x")?;
        (!chiffres.is_empty() && chiffres.len() <= 16 && chiffres.bytes().all(|o| o.is_ascii_hexdigit()))
            .then(|| a.to_string())
    }

    /// Ce que l'écran laisse aux fenêtres, en pixels du bureau : la taille de l'écran divisée par son échelle (largeur
    /// et hauteur échangées s'il est tourné d'un quart de tour), moins les barres (`reserved` : gauche, haut, droite,
    /// bas) et une marge.
    fn zone(ecran: &Value) -> Option<Zone> {
        let echelle = ecran["scale"].as_f64().filter(|e| *e > 0.0)?;
        let (l, h) = (ecran["width"].as_f64()?, ecran["height"].as_f64()?);
        let (l, h) = if ecran["transform"].as_i64()? % 2 == 1 {
            (h, l)
        } else {
            (l, h)
        };
        let reserve = |i: usize| {
            ecran
                .get("reserved")
                .and_then(|r| r.get(i))
                .and_then(Value::as_i64)
                .and_then(|n| i32::try_from(n).ok())
                .unwrap_or(0)
        };
        let entier = |v: f64| {
            // Une taille d'écran divisée par son échelle : quelques milliers de pixels, positifs.
            #[allow(clippy::cast_possible_truncation)]
            let n = (v / echelle).floor() as i32;
            n
        };
        let x = i32::try_from(ecran["x"].as_i64()?).ok()? + reserve(0) + MARGE;
        let y = i32::try_from(ecran["y"].as_i64()?).ok()? + reserve(1) + MARGE;
        let l = entier(l) - reserve(0) - reserve(2) - 2 * MARGE;
        let h = entier(h) - reserve(1) - reserve(3) - 2 * MARGE;
        (l > 0 && h > 0).then_some(Zone { x, y, l, h })
    }

    /// Une commande au socket de Hyprland, et sa réponse ; une seconde au plus.
    fn demander(socket: &std::path::Path, commande: &str) -> Option<String> {
        let mut flux = UnixStream::connect(socket).ok()?;
        flux.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
        flux.set_write_timeout(Some(Duration::from_secs(1))).ok()?;
        flux.write_all(commande.as_bytes()).ok()?;
        let mut reponse = String::new();
        flux.take(8 << 20).read_to_string(&mut reponse).ok()?;
        Some(reponse)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn adresse_verifiee() {
            assert_eq!(adresse("0x56174330da90").as_deref(), Some("0x56174330da90"));
            for piege in ["", "0x", "56174330da90", "0x1\" }) hl.exec(\"x", "0x12345678901234567"] {
                assert_eq!(adresse(piege), None, "{piege}");
            }
        }

        #[test]
        fn zone_d_un_ecran_mis_a_l_echelle_et_tourne() {
            let paysage = serde_json::json!({"x": 0, "y": 318, "width": 2560, "height": 1440, "scale": 1.6,
                "transform": 0, "reserved": [0, 26, 0, 0]});
            assert_eq!(
                zone(&paysage),
                Some(Zone {
                    x: 10,
                    y: 354,
                    l: 1580,
                    h: 854
                })
            );
            let portrait = serde_json::json!({"x": 1600, "y": 0, "width": 1920, "height": 1080, "scale": 1.25,
                "transform": 3, "reserved": [0, 26, 0, 0]});
            assert_eq!(
                zone(&portrait),
                Some(Zone {
                    x: 1610,
                    y: 36,
                    l: 844,
                    h: 1490
                })
            );
            assert_eq!(zone(&serde_json::json!({"scale": 0.0})), None);
        }
    }
}

#[cfg(windows)]
mod systeme {
    //! La fenêtre de la console : la vieille console (conhost) est elle-même la fenêtre ; sous le Terminal Windows,
    //! la console n'a qu'une fenêtre cachée, dont le propriétaire est la vraie fenêtre.

    use windows::Win32::Foundation::{HWND, RECT};
    use windows::Win32::Graphics::Gdi::{GetMonitorInfoW, MONITOR_DEFAULTTONEAREST, MONITORINFO, MonitorFromWindow};
    use windows::Win32::System::Console::{GetConsoleProcessList, GetConsoleWindow};
    use windows::Win32::UI::WindowsAndMessaging::{
        GA_ROOTOWNER, GetAncestor, GetClassNameW, GetWindowRect, SWP_NOACTIVATE, SWP_NOZORDER, SetWindowPos,
    };

    use super::{Mesure, Place, Zone, mesure};

    pub(super) struct Fenetre(HWND);

    impl Fenetre {
        pub(super) fn trouver() -> Option<Self> {
            let mut processus = [0u32; 4];
            // SAFETY : la liste est un tableau à nous, sa taille passée avec lui ; la fonction ne fait qu'y écrire.
            let n = unsafe { GetConsoleProcessList(&mut processus) };
            // Seul dans sa console : ouverte pour lui (double-clic, raccourci), pas l'invite de commandes de quelqu'un.
            if n != 1 {
                return None;
            }
            // SAFETY : sans argument ; rend une fenêtre nulle sans console.
            let console = unsafe { GetConsoleWindow() };
            if console.is_invalid() {
                return None;
            }
            let mut classe = [0u16; 64];
            // SAFETY : le tampon est à nous, sa taille passée avec lui ; la fenêtre vient d'être rendue par Windows.
            let n = unsafe { GetClassNameW(console, &mut classe) };
            let classe = String::from_utf16_lossy(classe.get(..usize::try_from(n).ok()?)?);
            match classe.as_str() {
                "ConsoleWindowClass" => Some(Fenetre(console)),
                "PseudoConsoleWindow" => {
                    // SAFETY : une fenêtre valide ; rend elle-même si elle n'a pas de propriétaire.
                    let vraie = unsafe { GetAncestor(console, GA_ROOTOWNER) };
                    (!vraie.is_invalid() && vraie != console).then_some(Fenetre(vraie))
                }
                _ => None,
            }
        }

        pub(super) fn mesurer(&self) -> Option<(Mesure, Zone)> {
            let mut r = RECT::default();
            // SAFETY : `r` est à nous ; une fenêtre fermée entre-temps fait seulement échouer l'appel.
            unsafe { GetWindowRect(self.0, &raw mut r) }.ok()?;
            // SAFETY : l'écran le plus proche existe toujours (MONITOR_DEFAULTTONEAREST).
            let ecran = unsafe { MonitorFromWindow(self.0, MONITOR_DEFAULTTONEAREST) };
            let mut info = MONITORINFO {
                cbSize: u32::try_from(std::mem::size_of::<MONITORINFO>()).ok()?,
                ..Default::default()
            };
            // SAFETY : `info` est à nous, sa taille déclarée dans cbSize.
            if !unsafe { GetMonitorInfoW(ecran, &raw mut info) }.as_bool() {
                return None;
            }
            let t = info.rcWork;
            let zone = Zone {
                x: t.left,
                y: t.top,
                l: t.right - t.left,
                h: t.bottom - t.top,
            };
            Some((mesure((r.left, r.top, r.right - r.left, r.bottom - r.top))?, zone))
        }

        pub(super) fn placer(&self, place: Place, _actuelle: &Mesure) {
            // SAFETY : une fenêtre fermée entre-temps fait seulement échouer l'appel ; rien n'est lu en retour.
            let _ = unsafe {
                SetWindowPos(
                    self.0,
                    None,
                    place.0,
                    place.1,
                    place.2,
                    place.3,
                    SWP_NOZORDER | SWP_NOACTIVATE,
                )
            };
        }
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod systeme {
    //! Ni Hyprland ni console Windows : aucun moyen sûr de reconnaître sa fenêtre.

    use super::{Mesure, Place, Zone};

    pub(super) struct Fenetre;

    // La même forme que sous Linux et Windows : `ajuster` ne connaît qu'elle.
    #[allow(clippy::unused_self)]
    impl Fenetre {
        pub(super) fn trouver() -> Option<Self> {
            None
        }

        pub(super) fn mesurer(&self) -> Option<(Mesure, Zone)> {
            None
        }

        pub(super) fn placer(&self, _place: Place, _actuelle: &Mesure) {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZONE: Zone = Zone {
        x: 0,
        y: 26,
        l: 1600,
        h: 874,
    };

    fn m(l: i32, h: i32, colonnes: u16, rangees: u16) -> Mesure {
        Mesure {
            x: 0,
            y: 0,
            l,
            h,
            colonnes,
            rangees,
        }
    }

    #[test]
    fn la_case_devinee_ne_manque_jamais_une_ligne() {
        // 20 px par ligne et 30 px de bordures : la case devinée (630 / 30 = 21 px) est un peu grande.
        let h = pixels(630, 30, 40, None);
        assert!(h >= 30 + 40 * 20, "{h}");
        // Rapetisser avec la case devinée : une ligne de plus visée, donc jamais sous la grille voulue tant que les
        // bordures font moins d'une ligne par dix retirées.
        let h = pixels(630, 30, 20, None);
        assert!((30 + 20 * 20..=30 + 21 * 20).contains(&h), "{h}");
    }

    #[test]
    fn la_case_mesuree_entre_deux_tailles_est_exacte() {
        // 30 lignes en 630 px, puis 41 en 850 px : 20 px par ligne.
        assert_eq!(pixels(850, 41, 40, Some((630, 30))), 830);
        // Une mesure prise pendant l'animation (fenêtre et grille en sens contraires) : la case devinée revient.
        assert_eq!(pixels(850, 41, 40, Some((900, 30))), pixels(850, 41, 40, None));
    }

    #[test]
    fn la_fenetre_reste_dans_l_ecran_et_au_milieu() {
        let (x, y, l, h) = placement(m(800, 630, 100, 30), None, 78, 200, ZONE, true);
        assert_eq!((l, h), (632, 874), "trop haute : bornée à l'écran");
        assert_eq!((x, y), ((1600 - 632) / 2, 26));
        let (x, y, l, h) = placement(m(800, 630, 100, 30), None, 78, 20, ZONE, true);
        // Au milieu de la zone, au pixel près (un écart impair se partage en deux).
        assert!(
            (x + l / 2 - 800).abs() <= 1 && (y + h / 2 - (26 + 874 / 2)).abs() <= 1,
            "{x} {y} {l} {h}"
        );
    }

    /// Sous Windows : la fenêtre garde sa place ; trop basse ou trop à droite pour sa nouvelle taille, elle est
    /// seulement ramenée dans l'écran.
    #[test]
    fn sans_centrer_la_fenetre_garde_sa_place() {
        let ici = Mesure {
            x: 300,
            y: 120,
            ..m(800, 630, 100, 30)
        };
        let (x, y, ..) = placement(ici, None, 78, 20, ZONE, false);
        assert_eq!((x, y), (300, 120));
        let au_bord = Mesure {
            x: 1400,
            y: 700,
            ..m(800, 630, 100, 30)
        };
        let (x, y, l, h) = placement(au_bord, None, 78, 30, ZONE, false);
        assert!(x + l <= ZONE.x + ZONE.l && y + h <= ZONE.y + ZONE.h, "{x} {y} {l} {h}");
        assert!(x >= ZONE.x && y >= ZONE.y);
    }

    /// Un terminal simulé, sous Windows (place gardée) : `bord` pixels de bordures et des cases de `case` pixels ; il
    /// arrondit chaque hauteur posée à ses cases. Rend la fenêtre après les retouches de `ajuster`.
    fn retoucher(depart: Mesure, rangees: u16, bord: i32, case: i32) -> Mesure {
        let zone = Zone {
            x: 0,
            y: 0,
            l: 1687,
            h: 865,
        };
        let (ancre, mut ici, mut avant) = ((depart.x, depart.y), depart, None);
        for _ in 0..3 {
            match pas(ancre, ici, avant, ici.colonnes, rangees, zone, false) {
                Pas::Finir(place) => {
                    if let Some(place) = place {
                        assert_eq!((place.2, place.3), (ici.l, ici.h), "finir ne change pas la taille");
                        (ici.x, ici.y) = (place.0, place.1);
                    }
                    return ici;
                }
                Pas::Poser(place) => {
                    avant = Some(ici);
                    let cases = (place.3 - bord) / case;
                    ici = Mesure {
                        x: place.0,
                        y: place.1,
                        l: place.2,
                        h: bord + cases * case,
                        colonnes: ici.colonnes,
                        rangees: u16::try_from(cases).unwrap(),
                    };
                }
            }
        }
        ici
    }

    /// Près du bas de l'écran, la fenêtre qui grandit remonte juste assez pour rester entière : la case devinée au
    /// premier pas, trop grande, la remontait davantage, et la suite la laissait là (un vide sous elle).
    #[test]
    fn en_grandissant_pres_du_bas_la_fenetre_remonte_juste_assez() {
        // Une ligne de trop au premier pas (25 rangées pour 24, permise) : la place se refait pour la vraie taille.
        let depart = Mesure {
            x: 868,
            y: 345,
            ..m(779, 107 + 19 * 17, 78, 19)
        };
        let fin = retoucher(depart, 24, 107, 17);
        assert_eq!(fin.rangees, 25);
        assert_eq!((fin.x, fin.y), (868, 865 - fin.h), "{fin:?}");
        // Deux lignes de trop au premier pas : le deuxième rapetisse la fenêtre et la redescend jusqu'à sa place.
        let depart = Mesure {
            x: 868,
            y: 345,
            ..m(779, 150 + 19 * 15, 78, 19)
        };
        let fin = retoucher(depart, 24, 150, 15);
        assert_eq!(fin.rangees, 24);
        assert_eq!((fin.x, fin.y), (868, 345), "{fin:?}");
        // Loin du bas, la place ne bouge pas du tout.
        let depart = Mesure {
            x: 200,
            y: 100,
            ..m(779, 150 + 19 * 15, 78, 19)
        };
        let fin = retoucher(depart, 24, 150, 15);
        assert_eq!((fin.x, fin.y, fin.rangees), (200, 100, 24), "{fin:?}");
    }

    /// La taille faite, une fenêtre déjà à sa place n'est pas reposée ; une autre y est remise, sans changer de taille.
    #[test]
    fn finir_remet_a_la_place_sans_retoucher_la_taille() {
        let zone = Zone {
            x: 0,
            y: 0,
            l: 1687,
            h: 865,
        };
        let ici = Mesure {
            x: 868,
            y: 316,
            ..m(779, 517, 78, 24)
        };
        assert_eq!(pas((868, 316), ici, None, 78, 24, zone, false), Pas::Finir(None));
        assert_eq!(
            pas((868, 345), ici, None, 78, 24, zone, false),
            Pas::Finir(Some((868, 345, 779, 517)))
        );
        // Trop basse pour sa taille : ramenée dans la zone.
        assert_eq!(
            pas((868, 600), ici, None, 78, 24, zone, false),
            Pas::Finir(Some((868, 865 - 517, 779, 517)))
        );
    }

    /// La place de la personne survit aux retouches et aux demandes qui se suivent, tant que la fenêtre est là où
    /// Vanguard l'a posée ; déplacée entre-temps, sa nouvelle place devient la référence.
    #[test]
    fn la_place_de_la_personne_suit_ses_deplacements() {
        let ici = Mesure {
            x: 868,
            y: 316,
            ..m(779, 517, 78, 24)
        };
        assert_eq!(ancre(None, &ici), (868, 316));
        assert_eq!(ancre(Some(((868, 345), (868, 316))), &ici), (868, 345));
        assert_eq!(
            ancre(Some(((868, 345), (870, 313))), &ici),
            (868, 345),
            "arrondis du bureau"
        );
        assert_eq!(
            ancre(Some(((868, 345), (600, 200))), &ici),
            (868, 316),
            "déplacée par la personne"
        );
    }

    #[test]
    fn une_case_de_trop_est_permise() {
        assert!(atteinte(&m(1, 1, 78, 40), 78, 40));
        assert!(atteinte(&m(1, 1, 79, 41), 78, 40));
        assert!(!atteinte(&m(1, 1, 78, 39), 78, 40));
        assert!(!atteinte(&m(1, 1, 80, 40), 78, 40));
    }
}

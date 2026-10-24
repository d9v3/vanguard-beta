//! Wi-Fi encombré : les réseaux voisins par bande et par canal, le canal le plus libre à régler sur la box, et le
//! signal de la connexion actuelle. En 2,4 GHz, deux réseaux à moins de cinq canaux d'écart se gênent : seuls les
//! canaux 1, 6 et 11 ne se recouvrent pas. En 5 GHz, les canaux ne se recouvrent pas, mais une box qui émet sur
//! 80 MHz en occupe quatre d'un coup : ils se comptent par blocs. Lecture seule : le canal se règle dans
//! l'administration de la box.

#[cfg(unix)]
use std::process::Command;

use crate::commande::lancer;
use crate::machine::wifi::{self, Bande, Borne};
use crate::ui::*;

const CANAUX_24: [u16; 3] = [1, 6, 11];

/// Un bloc de 80 MHz en 5 GHz : (premier canal, dernier canal, sans radar).
type Bloc = (u16, u16, bool);

/// Les blocs de 5 GHz. Les canaux 52 à 144 (DFS) se partagent avec des radars : la box doit écouter avant
/// d'émettre, et change de canal si un radar passe.
#[rustfmt::skip] // une ligne, que rustfmt étalerait sur six
const BLOCS_5: [Bloc; 6] = [
    (36, 48, true), (52, 64, false), (100, 112, false), (116, 128, false), (132, 144, false), (149, 161, true),
];

/// Ce que le système a pu lire : les bornes, et pourquoi la liste des voisins peut manquer.
struct Lecture {
    bornes: Vec<Borne>,
    note: Option<&'static str>,
}

/// Poids d'une borne voisine : son signal, une borne lointaine gênant peu ; inconnu, la moitié.
fn poids(b: &Borne) -> f64 {
    f64::from(b.signal.unwrap_or(50)) / 100.0
}

/// Gêne subie sur le canal `c` de 2,4 GHz : chaque borne à moins de cinq canaux d'écart, d'autant plus qu'elle en est
/// proche et qu'elle est forte. Une borne pile sur le canal, au signal maximal, compte 1.
fn gene_24(voisines: &[&Borne], c: u16) -> f64 {
    voisines
        .iter()
        .filter(|b| b.bande == Bande::G24)
        .map(|b| match b.canal.abs_diff(c) {
            ecart @ 0..5 => poids(b) * f64::from(5 - ecart) / 5.0,
            _ => 0.0,
        })
        .sum()
}

fn recouvrent_24(voisines: &[&Borne], c: u16) -> usize {
    voisines
        .iter()
        .filter(|b| b.bande == Bande::G24 && b.canal.abs_diff(c) < 5)
        .count()
}

/// Bornes d'un bloc de 5 GHz, et leur gêne.
fn bloc_5(voisines: &[&Borne], (debut, fin, _): Bloc) -> (usize, f64) {
    let dedans = voisines
        .iter()
        .filter(|b| b.bande == Bande::G5 && (debut..=fin).contains(&b.canal));
    (dedans.clone().count(), dedans.map(|b| poids(b)).sum())
}

/// Le canal de 2,4 GHz le moins gêné ; à gêne égale (à un dixième près), le plus petit.
fn meilleur_24(voisines: &[&Borne]) -> u16 {
    let plus_libre = |meilleur: (u16, f64), c| {
        let g = gene_24(voisines, c);
        if g + 0.1 < meilleur.1 { (c, g) } else { meilleur }
    };
    CANAUX_24.into_iter().fold((0, f64::INFINITY), plus_libre).0
}

/// Le bloc de 5 GHz sans radar le moins occupé ; et un bloc à radar entièrement libre, s'il y en a un alors que les
/// autres sont pris.
fn meilleur_5(voisines: &[&Borne]) -> (Bloc, Option<Bloc>) {
    let gene = |b| bloc_5(voisines, b).1;
    let sans_radar = BLOCS_5
        .into_iter()
        .filter(|b| b.2)
        .min_by(|a, b| gene(*a).total_cmp(&gene(*b)))
        .unwrap_or(BLOCS_5[0]);
    let libre = BLOCS_5.into_iter().find(|b| !b.2 && bloc_5(voisines, *b).0 == 0);
    (sans_radar, libre.filter(|_| gene(sans_radar) > 0.0))
}

/// Barre de gêne sur 10 cases, relative à la plus forte gêne montrée (au moins 1).
fn barre_gene(gene: f64, maximum: f64) -> String {
    let dixiemes = gene / maximum.max(1.0) * 10.0;
    // Le nombre de cases pleines, arrondi : le plus grand de 0 à 10 qui ne dépasse pas la valeur d'une demi-case.
    let n = (0..=10u8).rfind(|&n| f64::from(n) <= dixiemes + 0.5).unwrap_or(0);
    let teinte = match n {
        0..=3 => VERT,
        4..=6 => "\x1b[1;93m",
        _ => "\x1b[1;91m",
    };
    let (pleines, vides) = ("▰".repeat(usize::from(n)), "▱".repeat(usize::from(10 - n)));
    format!("{teinte}{pleines}{GRIS}{vides}{RESET}")
}

fn accord_reseaux(n: usize) -> String {
    match n {
        0 => tr!("aucun réseau", "no network").to_string(),
        1 => tr!("1 réseau", "1 network").to_string(),
        n => trf!("{n} réseaux", "{n} networks"),
    }
}

fn qualite(signal: u8) -> &'static str {
    match signal {
        70.. => tr!("excellent", "excellent"),
        50..=69 => tr!("bon", "good"),
        30..=49 => tr!(
            "moyen : rapprochez-vous du routeur, ou ajoutez un répéteur",
            "fair: move closer to the router, or add a repeater"
        ),
        _ => tr!(
            "faible : le routeur est loin ou derrière des murs épais ; un répéteur ou un système maillé (mesh) aiderait",
            "weak: the router is far or behind thick walls; a repeater or a mesh system would help"
        ),
    }
}

#[cfg(target_os = "linux")]
fn lire() -> Result<Lecture, &'static str> {
    let reussie = |c: &mut Command, delai| lancer(c, delai).filter(|r| r.code == Some(0)).map(|r| r.sortie);
    // NetworkManager d'abord ; sans lui (iwd, systemd-networkd), le dernier balayage gardé par le noyau. En anglais :
    // nmcli traduit la colonne ACTIVE (« oui » en français), et la borne de la connexion n'était plus reconnue.
    let champs = "-t -e no -f ACTIVE,SIGNAL,FREQ,CHAN,SSID dev wifi list".split(' ');
    let bornes = crate::commande::lancer_en_anglais(Command::new("nmcli").args(champs), 30)
        .filter(|r| r.code == Some(0))
        .map_or_else(Vec::new, |r| wifi::bornes_nmcli(&r.sortie));
    if !bornes.is_empty() {
        return Ok(Lecture { bornes, note: None });
    }
    let cartes: Vec<String> = std::fs::read_dir("/sys/class/net")
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().join("wireless").is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    if cartes.is_empty() {
        return Err(tr!(
            "Pas de carte Wi-Fi sur cet ordinateur.",
            "No Wi-Fi card on this computer."
        ));
    }
    let dump = |carte: &str| {
        let iw = reussie(Command::new("iw").args(["dev", carte, "scan", "dump"]), 15);
        iw.map_or_else(Vec::new, |s| wifi::bornes_iw(&s))
    };
    for carte in &cartes {
        let mut bornes = dump(carte);
        // Rien en mémoire : iwd sait balayer sans droits d'administrateur ; on lit le résultat quelques secondes après.
        if bornes.is_empty() && reussie(Command::new("iwctl").args(["station", carte, "scan"]), 10).is_some() {
            std::thread::sleep(std::time::Duration::from_secs(4));
            bornes = dump(carte);
        }
        if !bornes.is_empty() {
            return Ok(Lecture { bornes, note: None });
        }
    }
    Err(tr!(
        "Réseaux voisins illisibles : il faut NetworkManager (nmcli) ou l'outil iw.",
        "Nearby networks unreadable: NetworkManager (nmcli) or the iw tool is needed."
    ))
}

#[cfg(windows)]
fn lire() -> Result<Lecture, &'static str> {
    let netsh = |args: &[&str]| lancer(crate::commande::systeme("netsh").args(args), 20).map(|r| r.sortie);
    let active = netsh(&["wlan", "show", "interfaces"]).and_then(|s| wifi::borne_active_netsh(&s));
    let voisins = netsh(&["wlan", "show", "networks", "mode=bssid"]);
    let mut bornes = voisins.map_or_else(Vec::new, |s| wifi::bornes_netsh(&s));
    // Windows 11 24H2 ne liste les réseaux voisins qu'avec l'autorisation de localisation.
    let note = (bornes.is_empty() && active.is_some()).then_some(tr!(
        "Windows ne montre les réseaux voisins qu'avec la localisation : Paramètres > Confidentialité et sécurité > Localisation, autoriser les applications de bureau.",
        "Windows shows nearby networks only with location access: Settings > Privacy & security > Location, allow desktop apps."
    ));
    if let Some(a) = active {
        match bornes.iter_mut().find(|b| b.ssid == a.ssid && b.canal == a.canal) {
            Some(b) => (b.actif, b.signal) = (true, b.signal.or(a.signal)),
            None => bornes.push(a),
        }
    } else if bornes.is_empty() {
        return Err(tr!(
            "Pas de Wi-Fi sur cet ordinateur, ou le service WLAN est arrêté.",
            "No Wi-Fi on this computer, or the WLAN service is stopped."
        ));
    }
    Ok(Lecture { bornes, note })
}

#[cfg(target_os = "macos")]
fn lire() -> Result<Lecture, &'static str> {
    let Some(r) = lancer(Command::new("system_profiler").arg("SPAirPortDataType"), 40) else {
        return Err(tr!("Réseaux Wi-Fi illisibles.", "Wi-Fi networks unreadable."));
    };
    match wifi::bornes_system_profiler(&r.sortie) {
        b if b.is_empty() => Err(tr!(
            "Pas de Wi-Fi sur ce Mac, ou il est éteint.",
            "No Wi-Fi on this Mac, or it is turned off."
        )),
        bornes => Ok(Lecture { bornes, note: None }),
    }
}

/// Menu Réseau et Internet › Wi-Fi encombré, ou `vanguard canaux`.
pub fn analyser() {
    titre(tr!("Wi-Fi encombré ?", "Crowded Wi-Fi?"));
    let intro = tr!(
        "Les réseaux des voisins qui émettent sur le même canal que votre routeur se partagent l'antenne avec lui : le Wi-Fi ralentit et coupe. Vanguard regarde qui émet où, sans rien changer.",
        "Neighbors' networks on the same channel as your router share the air with it: the Wi-Fi slows down and drops. Vanguard looks at who transmits where, without changing anything."
    );
    for ligne in envelopper(intro, LARGEUR - 2) {
        println!("  {ligne}");
    }
    match lire() {
        Ok(lecture) => afficher(&lecture),
        Err(raison) => {
            println!();
            afficher_aligne("  ✖ ", raison, 4, "");
        }
    }
}

fn afficher(lecture: &Lecture) {
    let bornes = &lecture.bornes;
    let active = bornes.iter().find(|b| b.actif);
    // Les bornes de son propre réseau (les deux bandes, les répéteurs) ne gênent pas : elles sont la box.
    let du_reseau = |b: &Borne| active.is_some_and(|a| !a.ssid.is_empty() && b.ssid == a.ssid);
    let voisines: Vec<&Borne> = bornes.iter().filter(|b| !du_reseau(b)).collect();
    println!();
    if let Some(a) = active {
        let nom = match a.ssid.as_str() {
            "" => tr!("réseau caché", "hidden network").to_string(),
            ssid => format!("« {ssid} »"),
        };
        let signal = match a.signal {
            Some(s) => trf!(", signal {s} % ({})", ", signal {s}% ({})", qualite(s)),
            None => String::new(),
        };
        let connexion = trf!(
            "Connecté à {nom} : {}, canal {}{signal}.",
            "Connected to {nom}: {}, channel {}{signal}.",
            a.bande.libelle(),
            a.canal
        );
        afficher_aligne("  ", &connexion, 2, "");
    } else {
        let ailleurs = tr!(
            "Pas connecté en Wi-Fi : les conseils valent pour votre routeur, s'il est à portée.",
            "Not connected over Wi-Fi: the advice applies to your router, if it is within range."
        );
        afficher_aligne("  ", ailleurs, 2, GRIS);
    }
    if let Some(n) = lecture.note {
        afficher_aligne("  ", n, 2, DISCRET);
    }
    let autres = match voisines.len() {
        0 => tr!("Aucun autre réseau entendu d'ici.", "No other network heard from here.").to_string(),
        1 => tr!("Un autre réseau entendu d'ici.", "One other network heard from here.").to_string(),
        n => trf!(
            "{n} autres réseaux entendus d'ici.",
            "{n} other networks heard from here."
        ),
    };
    afficher_aligne("  ", &autres, 2, GRIS);
    // Le canal de ta box par bande : celui de la connexion, sinon celui de la borne la plus forte du même réseau.
    let canal_de_ta_box = |bande: Bande| {
        let siennes = bornes.iter().filter(|b| b.bande == bande && (b.actif || du_reseau(b)));
        siennes.max_by_key(|b| (b.actif, b.signal)).map(|b| b.canal)
    };
    let ta_box = tr!(" ← votre routeur", " ← your router");
    section(tr!("2,4 GHz", "2.4 GHz"));
    let canal_24 = canal_de_ta_box(Bande::G24);
    let genes = CANAUX_24.map(|c| gene_24(&voisines, c));
    let maximum = genes.into_iter().fold(0.0, f64::max);
    for (c, g) in CANAUX_24.into_iter().zip(genes) {
        let tien = if canal_24 == Some(c) { ta_box } else { "" };
        let (barre, reseaux) = (barre_gene(g, maximum), accord_reseaux(recouvrent_24(&voisines, c)));
        println!("  {} {c:>2}  {barre}  {reseaux}{tien}", tr!("Canal", "Channel"));
    }
    let meilleur = meilleur_24(&voisines);
    let conseil_24 = match canal_24 {
        Some(c) if !CANAUX_24.contains(&c) => trf!(
            "Votre routeur est sur le canal {}, qui chevauche ses voisins des deux côtés : réglez-le sur le canal {meilleur}.",
            "Your router is on channel {}, which overlaps its neighbors on both sides: set it to channel {meilleur}.",
            c
        ),
        Some(c) if gene_24(&voisines, c) <= gene_24(&voisines, meilleur) + 0.1 => String::from(tr!(
            "Votre canal est déjà le plus libre : rien à changer.",
            "Your channel is already the freest: nothing to change."
        )),
        Some(_) => trf!(
            "Le canal {meilleur} est plus libre : à régler dans l'administration du routeur (Wi-Fi 2,4 GHz, canal), au lieu de « automatique » s'il reste sur un canal chargé.",
            "Channel {meilleur} is freer: set it in the router's admin page (2.4 GHz Wi-Fi, channel), instead of “automatic” if it stays on a busy channel."
        ),
        None => trf!(
            "Le plus libre ici : le canal {meilleur}.",
            "The freest here: channel {meilleur}."
        ),
    };
    afficher_aligne("  → ", &conseil_24, 4, "");
    if bornes.iter().any(|b| b.bande == Bande::G5) {
        section("5 GHz");
        let canal_5 = canal_de_ta_box(Bande::G5);
        let occupation = BLOCS_5.map(|b| bloc_5(&voisines, b));
        let maximum = occupation.iter().map(|o| o.1).fold(0.0, f64::max);
        for ((debut, fin, sans_radar), (n, g)) in BLOCS_5.into_iter().zip(occupation) {
            let tien = canal_5.filter(|c| (debut..=fin).contains(c)).map_or("", |_| ta_box);
            let radar = if sans_radar { "" } else { tr!(" radar", " radar") };
            let canaux = trf!("Canaux {debut}-{fin}", "Channels {debut}-{fin}");
            let barre = barre_gene(g, maximum);
            println!("  {canaux:<17}{barre}  {}{GRIS}{radar}{RESET}{tien}", accord_reseaux(n));
        }
        let ((debut, fin, _), libre) = meilleur_5(&voisines);
        let mut conseil = match canal_5 {
            Some(c) if (debut..=fin).contains(&c) => String::from(tr!(
                "Votre routeur est déjà dans le bloc le plus libre sans radar.",
                "Your router is already in the freest block without radar."
            )),
            _ => trf!(
                "Le bloc le plus libre sans radar : canaux {debut} à {fin} (canal {debut} dans l'administration du routeur).",
                "The freest block without radar: channels {debut} to {fin} (channel {debut} in the router's admin page)."
            ),
        };
        if let Some((d, f, _)) = libre {
            conseil += &trf!(
                " Les canaux {d} à {f} sont libres, mais le routeur doit y céder la place aux radars (coupures de quelques secondes).",
                " Channels {d} to {f} are free, but the router must give way to radars there (drops of a few seconds)."
            );
        }
        afficher_aligne("  → ", &conseil, 4, "");
    }
    if bornes.iter().any(|b| b.bande == Bande::G6) {
        section("6 GHz");
        let six = trf!(
            "{} : cette bande, réservée au Wi-Fi 6E et 7, est rarement encombrée.",
            "{}: this band, reserved for Wi-Fi 6E and 7, is rarely crowded.",
            accord_reseaux(voisines.iter().filter(|b| b.bande == Bande::G6).count())
        );
        afficher_aligne("  ", &six, 2, GRIS);
    }
    // Connecté en 2,4 GHz alors que la box émet aussi en 5 GHz : plus rapide et moins encombré, de près.
    if active.is_some_and(|a| a.bande == Bande::G24) && bornes.iter().any(|b| b.bande != Bande::G24 && du_reseau(b)) {
        println!();
        let astuce = tr!(
            "Votre routeur émet aussi en 5 GHz sous le même nom : près de lui, c'est plus rapide et moins encombré. Si l'appareil reste en 2,4 GHz, donnez un nom différent à chaque bande dans le routeur.",
            "Your router also broadcasts in 5 GHz under the same name: near it, that is faster and less crowded. If the device stays on 2.4 GHz, give each band a different name in the router."
        );
        afficher_aligne(&format!("  {} ", ampoule()), astuce, 5, "");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn borne(ssid: &str, bande: Bande, canal: u16, signal: u8, actif: bool) -> Borne {
        Borne {
            ssid: ssid.into(),
            bssid: String::new(),
            bande,
            canal,
            signal: Some(signal),
            actif,
        }
    }

    #[test]
    fn gene_en_2_4_ghz() {
        let voisins = [
            borne("A", Bande::G24, 6, 100, false),
            borne("B", Bande::G24, 4, 50, false),
            borne("C", Bande::G5, 6, 100, false),
        ];
        let v: Vec<&Borne> = voisins.iter().collect();
        // A pile sur 6 (1), B à 2 canaux (0,5 × 3/5) ; le 5 GHz ne compte pas.
        assert!((gene_24(&v, 6) - 1.3).abs() < 1e-9);
        assert_eq!(recouvrent_24(&v, 6), 2);
        assert_eq!(recouvrent_24(&v, 11), 0);
        assert_eq!(meilleur_24(&v), 11);
        // Personne : le premier canal.
        assert_eq!(meilleur_24(&[]), 1);
    }

    #[test]
    fn blocs_en_5_ghz() {
        let voisins = [
            borne("A", Bande::G5, 36, 80, false),
            borne("B", Bande::G5, 44, 60, false),
            borne("C", Bande::G5, 149, 30, false),
        ];
        let v: Vec<&Borne> = voisins.iter().collect();
        assert_eq!(bloc_5(&v, BLOCS_5[0]).0, 2);
        let (meilleur, libre) = meilleur_5(&v);
        assert_eq!((meilleur.0, meilleur.1), (149, 161));
        // Les deux blocs sans radar sont pris : un bloc à radar libre est signalé.
        assert_eq!(libre.map(|b| b.0), Some(52));
        let rien: Vec<&Borne> = Vec::new();
        assert_eq!(meilleur_5(&rien), (BLOCS_5[0], None));
    }

    #[test]
    fn barres_et_libelles() {
        assert!(barre_gene(0.0, 0.0).contains("▱▱▱▱▱▱▱▱▱▱"));
        assert!(barre_gene(2.0, 2.0).contains("▰▰▰▰▰▰▰▰▰▰"));
        assert_eq!(largeur_affichee(&barre_gene(1.0, 2.0)), 10);
        assert!(qualite(80).contains(tr!("excellent", "excellent")));
        assert!(qualite(10).len() > 20);
    }

    #[test]
    fn affichage_sans_plantage() {
        // Connecté en 2,4 GHz sur un canal qui chevauche, une borne 5 GHz du même réseau, un voisin caché.
        let lecture = Lecture {
            bornes: vec![
                borne("Salon", Bande::G24, 3, 40, true),
                borne("Salon", Bande::G5, 36, 70, false),
                borne("", Bande::G24, 6, 60, false),
                borne("Voisin", Bande::G6, 37, 20, false),
            ],
            note: None,
        };
        afficher(&lecture);
        afficher(&Lecture {
            bornes: Vec::new(),
            note: Some("note"),
        });
    }
}

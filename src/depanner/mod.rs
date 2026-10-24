//! Dépanner pas à pas : les pannes de tous les jours (« Pas d'Internet », « L'ordinateur est lent »…), prises comme le
//! ferait quelqu'un qui s'y connaît. Deux ou trois questions, puis Vanguard vérifie lui-même ce qu'il peut, dit ce
//! qu'il a trouvé, et propose la bonne réparation (celles de Réparer) ou le bon outil (Nettoyer, Copier mes
//! fichiers…). Rien n'est changé sans être montré et accepté.

mod compte;
mod depart;
mod depuis_maj;
mod imprimante;
pub(crate) mod infection;
mod nouveau;
mod proche;
mod reseau;
mod son;

use crate::selection::{Ligne, choisir, correspond, simplifier};
use crate::ui::*;

/// Un parcours de dépannage.
pub struct Parcours {
    /// Le mot de la ligne de commande (« vanguard depanner internet »), en français puis en anglais.
    cles: (&'static str, &'static str),
    titre: (&'static str, &'static str),
    /// Précision de sa ligne au menu (33 caractères au plus).
    apercu: (&'static str, &'static str),
    /// Ce que la recherche trouve en plus, dans les deux langues.
    mots: &'static str,
    lancer: fn(),
}

static PARCOURS: [Parcours; 12] = [
    Parcours {
        cles: ("internet", "internet"),
        titre: ("Pas d'Internet", "No Internet"),
        apercu: ("sites introuvables, coupure", "sites not found, outage"),
        mots: "connexion connection réseau network box routeur router dns site page web",
        lancer: reseau::internet,
    },
    Parcours {
        cles: ("wifi", "wifi"),
        titre: ("Le Wi-Fi coupe", "Wi-Fi keeps dropping"),
        apercu: ("signal faible, coupures", "weak signal, drops"),
        mots: "wifi sans fil wireless signal coupure drop déconnexion disconnect",
        lancer: reseau::wifi,
    },
    Parcours {
        cles: ("lent", "slow"),
        titre: ("L'ordinateur est lent", "The computer is slow"),
        apercu: ("processeur, mémoire, démarrage", "processor, memory, startup"),
        mots: "lent slow lenteur rame freeze bloque",
        lancer: lent,
    },
    Parcours {
        cles: ("son", "sound"),
        titre: ("Pas de son", "No sound"),
        apercu: ("haut-parleurs, casque, HDMI", "speakers, headset, HDMI"),
        mots: "audio son sound haut-parleur speaker casque headset volume muet mute bluetooth",
        lancer: son::son,
    },
    Parcours {
        cles: ("imprimante", "printer"),
        titre: ("L'imprimante ne marche pas", "The printer does not work"),
        apercu: ("file d'attente, réseau, USB", "queue, network, USB"),
        mots: "imprimer print printer imprimante cups spooler impression",
        lancer: imprimante::imprimante,
    },
    Parcours {
        cles: ("disque", "disk"),
        titre: ("Disque plein", "Disk full"),
        apercu: ("place, gros dossiers, copie", "space, big folders, copy"),
        mots: "place space disque disk plein full stockage storage",
        lancer: disque_plein,
    },
    Parcours {
        cles: ("infection", "infection"),
        titre: ("Après une infection", "After an infection"),
        apercu: ("virus, rançon, faux technicien", "virus, ransom, fake technician"),
        mots: "virus malware infecté infected rançongiciel ransomware piraté hacked arnaque scam pirate hacker",
        lancer: infection::infection,
    },
    Parcours {
        cles: ("nouveau", "new"),
        titre: ("Nouvel ordinateur", "New computer"),
        apercu: ("premiers réglages, dans l'ordre", "first settings, in order"),
        mots: "nouveau new neuf achat acheté bought occasion reconditionné refurbished réinstallé reinstalled premier first",
        lancer: nouveau::nouveau,
    },
    Parcours {
        cles: ("depart", "leaving"),
        titre: ("Ordinateur qui part (vente, don)", "Computer leaving (sale, gift)"),
        apercu: ("comptes, clé, effacement sûr", "accounts, key, secure wipe"),
        mots: "vendre vente sell sale donner don give gift rendre return recycler recycle effacer wipe erase bitlocker filevault tpm",
        lancer: depart::depart,
    },
    Parcours {
        cles: ("compte", "account"),
        titre: ("Mon compte a été piraté", "My account was hacked"),
        apercu: ("courriel, réseau social, banque", "email, social network, bank"),
        mots: "piraté hacked compte account courriel email facebook instagram banque bank mot de passe password \
               volé stolen connexion login",
        lancer: compte::compte,
    },
    // À la fin : les numéros des parcours d'avant (« 11.7 », après une infection) ne changent pas.
    Parcours {
        cles: ("traces", "evidence"),
        titre: ("Collecter les traces", "Collect the traces"),
        apercu: ("avant de nettoyer, pour un expert", "before cleaning, for an expert"),
        mots: "traces preuves evidence forensique forensic collecte collect spécialiste specialist expert enquête \
               investigation journaux logs processus processes",
        lancer: infection::traces,
    },
    Parcours {
        cles: ("proche", "relative"),
        titre: ("Ordinateur d'un proche", "A relative's computer"),
        apercu: ("bilan simple, page à laisser", "simple check-up, page to leave"),
        mots: "proche relative parent parents famille family ami friend grand-mère grandmother grand-père \
               grandfather enfant child aîné senior",
        lancer: proche::proche,
    },
];

fn dans_la_langue(t: (&'static str, &'static str)) -> &'static str {
    if crate::langue::anglais() { t.1 } else { t.0 }
}

/// Le titre du parcours en cours, pour le cadre de chaque question.
static EN_COURS: std::sync::Mutex<&str> = std::sync::Mutex::new("");

fn entete() -> Vec<String> {
    let titre = *EN_COURS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    lignes_cadre(
        &format!(
            "{ACCENT}VANGUARD{RESET} {GRIS}›{RESET} {} {GRIS}›{RESET} {titre}",
            tr!("Dépanner", "Troubleshoot")
        ),
        tr!("pas à pas", "step by step"),
    )
    .to_vec()
}

/// Une question à choix, posée comme un petit menu sous le cadre du parcours : le numéro choisi (à partir de 0), ou
/// `None` (Échap, ou réponse vide).
fn question(texte: &str, reponses: &[&str]) -> Option<usize> {
    print!("\x1b[2J\x1b[H");
    let mut lignes: Vec<Ligne> = entete().into_iter().map(Ligne::Texte).collect();
    lignes.push(Ligne::Texte(String::new()));
    lignes.extend(
        envelopper(texte, LARGEUR - 4)
            .into_iter()
            .map(|l| Ligne::Texte(format!("  {GRAS}{l}{RESET}"))),
    );
    lignes.push(Ligne::Texte(String::new()));
    for (i, r) in reponses.iter().enumerate() {
        lignes.push(Ligne::choix(&(i + 1).to_string(), r, ""));
    }
    lignes.push(Ligne::Texte(String::new()));
    let choix = choisir(&lignes, tr!("  Réponse : ", "  Answer: "), "1", tr!("arrêter", "stop"))?;
    choix
        .trim()
        .parse::<usize>()
        .ok()?
        .checked_sub(1)
        .filter(|&i| i < reponses.len())
}

/// Ce que Vanguard a vérifié : bon, mauvais, ou à savoir.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Etat {
    Bon,
    Mauvais,
    Info,
}

impl Etat {
    /// Bon si c'est le cas, mauvais sinon.
    fn selon(ok: bool) -> Etat {
        if ok { Etat::Bon } else { Etat::Mauvais }
    }

    /// Dit ce qui a été vérifié, marqué de son état.
    fn dire(self, texte: &str) {
        let marque = match self {
            Etat::Bon => format!("{VERT}✔{RESET}"),
            Etat::Mauvais => format!("{}✖{RESET}", couleur(crate::risk::Niveau::Eleve)),
            Etat::Info => format!("{}ℹ{RESET}", couleur(crate::risk::Niveau::Info)),
        };
        afficher_aligne(&format!("  {marque} "), texte, 4, "");
    }
}

/// Une réparation faite.
fn fait(texte: &str) {
    println!("  {VERT}✔{RESET} {texte}");
}

/// Montre les commandes, puis les lance si on le veut.
#[cfg(unix)]
fn proposer(question: &str, commandes: &[String]) -> bool {
    for c in commandes {
        println!("    {GRIS}$ {}{RESET}", crate::ui::commande_affichable(c));
    }
    demander(question).oui() && crate::machine::appliquer(commandes)
}

/// Un conseil à suivre soi-même.
fn conseil(texte: &str) {
    afficher_aligne(&format!("  {} ", ampoule()), texte, 5, "");
}

/// Un écran neuf sous le cadre du parcours.
fn ecran() {
    print!("\x1b[2J\x1b[H");
    for l in entete() {
        println!("{l}");
    }
}

/// Le début de l'écran des vérifications, après les questions.
fn verifications() {
    ecran();
    section(tr!("CE QUE VANGUARD VÉRIFIE", "WHAT VANGUARD CHECKS"));
}

/// La réparation de ce titre (menu Réparer), si ce système en a une : montrée, puis lancée après accord.
fn proposer_reparation(titre: &str) -> bool {
    let Some(r) = crate::reparer::par_titre(titre) else {
        return false;
    };
    section(tr!("RÉPARATION PROPOSÉE", "SUGGESTED REPAIR"));
    crate::reparer::lancer(&r);
    true
}

/// « À savoir » et ses conseils, seulement s'il y en a.
fn a_savoir(conseils: &[&str]) {
    if conseils.is_empty() {
        return;
    }
    section(tr!("À SAVOIR", "GOOD TO KNOW"));
    for c in conseils {
        conseil(c);
    }
}

/// « 1.2 To », « 340 Go » : la place d'un disque.
fn taille(octets: u64) -> String {
    if octets >= 1 << 40 {
        #[allow(clippy::cast_precision_loss)]
        let to = octets as f64 / f64::from(1u32 << 20) / f64::from(1u32 << 20);
        trf!("{} To", "{} TB", crate::langue::decimal(to, 1))
    } else {
        crate::socle::taille_lisible(octets)
    }
}

/// Ouvre un outil de Vanguard si on le veut.
fn proposer_outil(question: &str, outil: fn()) {
    if demander(question).oui() {
        outil();
    }
}

/// Le bilan de cette machine, réduit aux catégories qui comptent pour ce parcours, affiché puis rendu (pour en tirer
/// une conclusion, l'état du chiffrement par exemple). Les vérifications impossibles restent dites, jamais comptées
/// comme saines.
fn bilan(categories: &[&str]) -> Vec<crate::machine::Constat> {
    trp!(
        "  {GRIS}Bilan en cours (quelques secondes ; jusqu'à une minute sous Windows)…{RESET}",
        "  {GRIS}Checking (a few seconds; up to a minute on Windows)…{RESET}"
    );
    let mut constats = crate::machine::auditer(false).constats;
    constats.retain(|c| categories.contains(&c.categorie));
    // Dans l'ordre demandé par le parcours, pas celui du bilan.
    constats.sort_by_key(|c| categories.iter().position(|k| *k == c.categorie));
    print!("\x1b[1A\x1b[2K");
    if constats.is_empty() {
        Etat::Info.dire(tr!(
            "Rien de ces catégories n'a pu être vérifié ici.",
            "None of these categories could be checked here."
        ));
    } else {
        crate::machine::afficher_constats(&constats);
    }
    constats
}

/// Lance un parcours.
fn suivre(p: &Parcours) {
    *EN_COURS.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = dans_la_langue(p.titre);
    (p.lancer)();
}

/// L'ordinateur est lent : la question qui oriente, puis la mesure de « Pourquoi c'est lent ? ».
fn lent() {
    let Some(quoi) = question(
        tr!("Qu'est-ce qui est lent ?", "What is slow?"),
        &[
            tr!("Tout l'ordinateur", "The whole computer"),
            tr!("Internet seulement", "Only the Internet"),
            tr!("Un programme en particulier", "One program in particular"),
            tr!("Le démarrage", "Startup"),
        ],
    ) else {
        return;
    };
    if quoi == 1 {
        // Internet lent : la connexion, pas l'ordinateur.
        reseau::internet_lent();
        return;
    }
    let Some(depuis) = question(
        tr!("Depuis quand ?", "Since when?"),
        &[
            tr!("Depuis toujours", "Always"),
            tr!(
                "Depuis peu (une mise à jour, un nouveau programme)",
                "Recently (an update, a new program)"
            ),
            tr!("Par moments seulement", "Only at times"),
        ],
    ) else {
        return;
    };
    ecran();
    let mut conseils = Vec::new();
    if depuis == 2 {
        conseils.push(tr!(
            "Par moments : lancez la mesure (outil « Pourquoi c'est lent ? », menu Optimiser et installer) au moment où c'est lent, elle dira qui travaille à ce moment-là.",
            "At times: run the measurement (“Why is it slow?” tool, Optimize and install menu) when it is slow: it will say what is working at that moment."
        ));
    }
    if depuis == 1 {
        conseils.push(tr!(
            "Depuis peu : un programme installé récemment peut se lancer au démarrage ou tourner en fond ; une mise à jour de pilote ratée se corrige par les mises à jour (menu Cet ordinateur).",
            "Recently: a newly installed program may start at login or run in the background; a failed driver update is fixed through the updates (This computer menu › System updates)."
        ));
    }
    if quoi == 2 {
        conseils.push(tr!(
            "Un programme : le mettre à jour, et regarder s'il est en tête de la mesure ci-dessous. Un navigateur lent vient souvent d'une extension ou d'onglets trop nombreux.",
            "One program: update it, and see if it tops the measurement below. A slow browser often comes from an extension or too many tabs."
        ));
    }
    if quoi == 3 {
        conseils.push(tr!(
            "Le démarrage : regardez la ligne « Retardé par » et les programmes lancés à l'ouverture ; chacun en moins fait gagner quelques secondes.",
            "Startup: look at the “Delayed by” line and the programs started at login; each one removed saves a few seconds."
        ));
    }
    a_savoir(&conseils);
    if depuis == 1 {
        depuis_maj::apres_mise_a_jour();
    }
    crate::lenteur::menu();
}

/// Disque plein : où, combien, ce qui prend la place, puis Nettoyer ou Copier mes fichiers.
fn disque_plein() {
    let Some(ou) = question(
        tr!("Où manque-t-il de la place ?", "Where is space missing?"),
        &[
            tr!("Sur le disque de l'ordinateur", "On the computer's disk"),
            tr!("Sur un autre disque ou une clé", "On another disk or a USB stick"),
            tr!("Je ne sais pas", "I don't know"),
        ],
    ) else {
        return;
    };
    let Some(a_garder) = question(
        tr!(
            "Avez-vous des photos, des vidéos ou de la musique à garder ailleurs, sur un disque externe ?",
            "Do you have photos, videos or music to keep elsewhere, on an external disk?"
        ),
        &[tr!("Oui", "Yes"), tr!("Non", "No")],
    ) else {
        return;
    };
    verifications();
    let volumes = volumes();
    if volumes.is_empty() {
        Etat::Info.dire(tr!("Place des disques illisible ici.", "Disk space not readable here."));
    }
    for (point, libre, total) in &volumes {
        #[allow(clippy::cast_precision_loss)]
        let pct = if *total == 0 {
            100.0
        } else {
            *libre as f64 * 100.0 / *total as f64
        };
        let texte = trf!(
            "{point} : {} libres sur {} ({pct:.0} %)",
            "{point}: {} free out of {} ({pct:.0}%)",
            taille(*libre),
            taille(*total)
        );
        Etat::selon(pct >= 10.0).dire(&texte);
    }
    let gros = plus_gros_dossiers();
    if !gros.is_empty() {
        let texte = gros
            .iter()
            .map(|(nom, octets)| format!("{nom} {}", taille(*octets)))
            .collect::<Vec<_>>()
            .join(", ");
        Etat::Info.dire(&trf!(
            "Plus gros dossiers du dossier personnel : {texte}.",
            "Largest folders of the home folder: {texte}."
        ));
    }
    section(tr!("QUE FAIRE", "WHAT TO DO"));
    if ou == 1 {
        conseil(tr!(
            "Sur un disque externe ou une clé, ce qu'on supprime va souvent dans une corbeille cachée sur ce disque : vider la corbeille rend la place.",
            "On an external disk or USB stick, what you delete often goes to a hidden trash on that disk: emptying the trash gives the space back."
        ));
    }
    if a_garder == 0 {
        conseil(tr!(
            "D'abord une copie vérifiée sur un disque externe (Copier mes fichiers). Ensuite seulement, supprimez vous-même les originaux dont vous n'avez plus besoin ici : Vanguard ne supprime jamais vos fichiers.",
            "First a checked copy on an external disk (Copy my files). Only then, delete the originals you no longer need here yourself: Vanguard never deletes your files."
        ));
        proposer_outil(
            tr!(
                "\n  Ouvrir « Copier mes fichiers » ? [o/N] : ",
                "\n  Open “Copy my files”? [y/N]: "
            ),
            crate::copier::menu,
        );
    }
    if ou != 1 {
        conseil(tr!(
            "« Nettoyer le système » montre ce qui se refait seul (caches, fichiers temporaires, paquets téléchargés…) et la place que chaque élément libère.",
            "“Clean up the system” shows what rebuilds itself (caches, temporary files, downloaded packages…) and the space each item frees."
        ));
        proposer_outil(
            tr!(
                "\n  Ouvrir « Nettoyer le système » ? [o/N] : ",
                "\n  Open “Clean up the system”? [y/N]: "
            ),
            crate::nettoyer::menu,
        );
    }
}

/// Les disques montés et leur place : (où, libre, total). « Où » est seulement montré : prêt à montrer, il porte
/// l'étiquette d'une clé branchée, choisie par qui l'a préparée.
fn volumes() -> Vec<(String, u64, u64)> {
    #[cfg(target_os = "linux")]
    {
        const SYSTEMES: &[&str] = &[
            "ext2", "ext3", "ext4", "btrfs", "xfs", "f2fs", "vfat", "exfat", "ntfs", "ntfs3", "fuseblk", "zfs",
        ];
        let mut vus = Vec::new();
        std::fs::read_to_string("/proc/mounts")
            .unwrap_or_default()
            .lines()
            .filter_map(|l| {
                let c: Vec<&str> = l.split_whitespace().collect();
                let [peripherique, point, genre, ..] = c[..] else {
                    return None;
                };
                if !SYSTEMES.contains(&genre) || vus.contains(&peripherique) || point.starts_with("/boot") {
                    return None;
                }
                vus.push(peripherique);
                // Espaces, tabulations… écrits en octal (« \\040 ») : décodés en entier, comme pour Copier.
                let point = crate::copier::sans_echappements(point);
                // La clé VANGUARD n'est pas un disque à libérer : elle est faite pour rester telle quelle.
                if crate::copier::est_la_cle(std::path::Path::new(&point)) {
                    return None;
                }
                let (libre, total) = crate::socle::volume(std::path::Path::new(&point))?;
                Some((affichable(&point), libre, total))
            })
            .collect()
    }
    #[cfg(target_os = "macos")]
    {
        let donnees = if std::path::Path::new("/System/Volumes/Data").is_dir() {
            "/System/Volumes/Data"
        } else {
            "/"
        };
        std::iter::once(std::path::PathBuf::from(donnees))
            .chain(
                std::fs::read_dir("/Volumes")
                    .into_iter()
                    .flatten()
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| !p.to_string_lossy().contains("com.apple.") && !crate::copier::est_la_cle(p)),
            )
            .filter_map(|p| {
                let (libre, total) = crate::socle::volume(&p)?;
                Some((chemin_affichable(&p), libre, total))
            })
            .fold(Vec::new(), |mut v, x| {
                // « Macintosh HD » est le même volume que le système : une fois.
                if !v.iter().any(|(_, l, t): &(String, u64, u64)| *l == x.1 && *t == x.2) {
                    v.push(x);
                }
                v
            })
    }
    #[cfg(windows)]
    {
        // Lus par kernel32 ; PowerShell seulement si la liste revient vide (le lecteur du système y est toujours).
        let natifs: Vec<String> = crate::machine::windows::lecteurs::lecteurs()
            .iter()
            .map(|l| format!("{}|{}|{}", l.racine.display(), l.libre, l.total))
            .collect();
        if natifs.is_empty() {
            crate::machine::windows::ps(
                "[IO.DriveInfo]::GetDrives() | Where-Object { $_.IsReady -and $_.DriveType -in 'Fixed','Removable' } | \
                 ForEach-Object { \"$($_.Name)|$($_.AvailableFreeSpace)|$($_.TotalSize)\" }",
            )
        } else {
            Some(natifs.join("\n"))
        }
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let c: Vec<&str> = l.trim().split('|').collect();
            let [point, libre, total] = c[..] else { return None };
            if crate::copier::est_la_cle(std::path::Path::new(point)) {
                return None;
            }
            Some((affichable(point), libre.parse().ok()?, total.parse().ok()?))
        })
        .collect()
    }
}

/// Les cinq plus gros dossiers du dossier personnel, mesurés en dix secondes au plus.
fn plus_gros_dossiers() -> Vec<(String, u64)> {
    #[cfg(windows)]
    let maison = std::path::PathBuf::from(std::env::var_os("USERPROFILE").unwrap_or_default());
    #[cfg(not(windows))]
    let maison = crate::socle::maison();
    if maison.as_os_str().is_empty() {
        return Vec::new();
    }
    let fin = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut tailles: Vec<(String, u64)> = std::fs::read_dir(&maison)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| std::fs::symlink_metadata(e.path()).is_ok_and(|m| m.is_dir()))
        .take_while(|_| std::time::Instant::now() < fin)
        .filter_map(|e| {
            let taille = crate::nettoyer::taille_dossier(&e.path(), crate::nettoyer::Age::Tout, &[])?;
            Some((affichable(&e.file_name().to_string_lossy()), taille))
        })
        .filter(|(_, t)| *t >= 1 << 30)
        .collect();
    tailles.sort_by_key(|(_, t)| std::cmp::Reverse(*t));
    tailles.truncate(5);
    tailles
}

/// Les parcours, pour la recherche d'un menu (« <cle>.3 » : le 3e parcours).
pub fn lignes_de_recherche(cle: &str) -> Vec<Ligne> {
    let chemin = format!("{} ›", tr!("Dépanner pas à pas", "Step-by-step troubleshooting"));
    PARCOURS
        .iter()
        .enumerate()
        .map(|(i, p)| {
            Ligne::cachee(
                &format!("{cle}.{}", i + 1),
                &chemin,
                dans_la_langue(p.titre),
                dans_la_langue(p.apercu),
            )
            .avec_mots(p.mots)
        })
        .collect()
}

/// Le nombre de parcours : les outils du groupe Dépanner les suivent au menu (11.13, 11.14).
pub fn nombre_de_parcours() -> usize {
    PARCOURS.len()
}

/// « 3 » → le 3e parcours, tapé ou trouvé par la recherche.
pub fn chemin(texte: &str) -> Option<usize> {
    texte
        .trim()
        .parse::<usize>()
        .ok()
        .filter(|n| (1..=PARCOURS.len()).contains(n))
}

/// Ouvre le n-ième parcours (à partir de 1), puis attend Entrée.
pub fn ouvrir(n: usize) {
    if let Some(p) = n.checked_sub(1).and_then(|i| PARCOURS.get(i)) {
        suivre(p);
        crate::selection::attendre_retour(&trf!(
            "\n{GRIS}Entrée pour revenir…{RESET}",
            "\n{GRIS}Enter to go back…{RESET}"
        ));
    }
}

/// L'écran des parcours, suivis des `autres` outils du groupe : 24 rangées au plus avec l'aide et la saisie (test),
/// d'où une explication d'une ligne.
fn lignes_du_menu(autres: &[(&str, &str, &str)]) -> Vec<Ligne> {
    let mut lignes: Vec<Ligne> = lignes_cadre(
        &format!(
            "{ACCENT}VANGUARD{RESET} {GRIS}›{RESET} {}",
            tr!("Dépanner pas à pas", "Step-by-step troubleshooting")
        ),
        tr!("une panne, des questions", "a problem, a few questions"),
    )
    .into_iter()
    .map(Ligne::Texte)
    .collect();
    lignes.push(Ligne::Texte(format!(
        "  {GRIS}{}{RESET}",
        tr!(
            "Quelques questions, puis la bonne réparation, avec votre accord.",
            "A few questions, then the right repair, with your consent."
        )
    )));
    lignes.push(Ligne::Texte(String::new()));
    for (i, p) in PARCOURS.iter().enumerate() {
        lignes.push(
            Ligne::choix(&(i + 1).to_string(), dans_la_langue(p.titre), dans_la_langue(p.apercu)).avec_mots(p.mots),
        );
    }
    for (i, (titre, precision, mots)) in autres.iter().enumerate() {
        lignes.push(Ligne::choix(&(PARCOURS.len() + i + 1).to_string(), titre, precision).avec_mots(mots));
    }
    lignes.push(Ligne::Texte(String::new()));
    lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
    lignes
}

/// Les parcours au menu, puis `autres` (titre, précision, mots), les outils du groupe qui ne sont pas des parcours :
/// `lancer` reçoit le rang de celui qui est choisi.
pub fn menu(autres: &[(&str, &str, &str)], lancer: &mut dyn FnMut(usize)) {
    let mut dernier = String::from("1");
    loop {
        print!("\x1b[2J\x1b[H");
        let lignes = lignes_du_menu(autres);
        let Some(choix) = choisir(
            &lignes,
            tr!("  Choix (Entrée pour revenir) : ", "  Choice (Enter to go back): "),
            &dernier,
            tr!("revenir", "back"),
        ) else {
            return;
        };
        let choix = choix.trim().to_string();
        let autre = choix
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(PARCOURS.len() + 1))
            .filter(|i| *i < autres.len());
        match (chemin(&choix), autre) {
            (Some(n), _) => {
                dernier = choix;
                ouvrir(n);
            }
            (None, Some(i)) => {
                dernier = choix;
                lancer(i);
            }
            _ if choix.is_empty() || choix == "↵" || choix.eq_ignore_ascii_case("q") => return,
            _ => {}
        }
    }
}

/// Le parcours que désignent ces mots : sa clé (« internet », « slow »), sinon une recherche dans les titres.
fn trouver(sujet: &str) -> Option<&'static Parcours> {
    let s = simplifier(sujet.trim());
    PARCOURS.iter().find(|p| s == p.cles.0 || s == p.cles.1).or_else(|| {
        let mut trouves = PARCOURS.iter().filter(|p| {
            let texte = simplifier(&format!("{} {} {} {}", p.titre.0, p.titre.1, p.apercu.0, p.mots));
            correspond(sujet, &texte)
        });
        let premier = trouves.next();
        // Plusieurs parcours possibles : on ne choisit pas au hasard.
        if trouves.next().is_some() { None } else { premier }
    })
}

/// « vanguard depanner [sujet] » : sans sujet, les parcours seuls (main.rs ouvre le menu avec les autres outils du
/// groupe) ; sinon le parcours désigné.
pub fn executer(sujet: &str) {
    if sujet.trim().is_empty() {
        menu(&[], &mut |_| {});
        return;
    }
    let Some(p) = trouver(sujet) else {
        trp!(
            "  Sujet inconnu : « {sujet} ». Les sujets :",
            "  Unknown subject: “{sujet}”. The subjects:"
        );
        for p in &PARCOURS {
            let cle = dans_la_langue(p.cles);
            println!("    {TOUCHE}{cle:<11}{RESET} {}", dans_la_langue(p.titre));
        }
        return;
    };
    suivre(p);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Les douze parcours et les deux outils du groupe (11.13, 11.14) tiennent dans un terminal de 24 rangées, avec
    /// l'aide et la saisie : sinon 11.13, 11.14 et « Revenir » passent sous le bord.
    #[test]
    fn l_ecran_tient_dans_24_lignes() {
        let autres = [("Réparer", "a", "m"), ("Diagnostic", "b", "m")];
        let lignes = lignes_du_menu(&autres);
        let affichees = lignes.iter().filter(|l| !matches!(l, Ligne::Cachee { .. })).count();
        assert!(affichees + 2 <= 24, "{affichees} lignes affichées");
    }

    #[test]
    fn chaque_parcours_tient_dans_son_menu() {
        for p in &PARCOURS {
            for t in [p.apercu.0, p.apercu.1] {
                assert!(largeur_affichee(t) <= 33, "« {t} » trop long");
            }
            for t in [p.titre.0, p.titre.1] {
                assert!(largeur_affichee(t) <= 34, "« {t} » trop long");
            }
            assert!(trouver(p.cles.0).is_some_and(|x| std::ptr::eq(x, p)));
            assert!(trouver(p.cles.1).is_some_and(|x| std::ptr::eq(x, p)));
        }
    }

    #[test]
    fn sujet_trouve_par_ses_mots() {
        assert!(trouver("imprimer").is_some_and(|p| p.cles.0 == "imprimante"));
        assert!(trouver("SON").is_some_and(|p| p.cles.0 == "son"));
        assert!(trouver("printer").is_some_and(|p| p.cles.0 == "imprimante"));
        assert!(trouver("zzz").is_none());
        assert_eq!(chemin("3"), Some(3));
        assert_eq!(chemin("12"), Some(12));
        assert_eq!(chemin("13"), None);
        assert!(trouver("grand-mère").is_some_and(|p| p.cles.1 == "relative"));
        assert!(trouver("traces").is_some_and(|p| p.cles.1 == "evidence"));
        assert_eq!(lignes_de_recherche("11").len(), PARCOURS.len());
    }

    /// Les réparations que les parcours proposent existent dans Réparer, sous le même titre.
    #[test]
    fn les_reparations_proposees_existent() {
        let titres: Vec<&str> = crate::reparer::liste().iter().map(|r| r.titre).collect();
        assert!(titres.contains(&reseau::titre_navigation()), "{titres:?}");
        // Sous Linux, « Internet ne marche plus » n'existe qu'avec NetworkManager ou systemd-networkd.
        if !cfg!(target_os = "linux") {
            assert!(titres.contains(&reseau::titre_internet()), "{titres:?}");
        }
    }
}

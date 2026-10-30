//! Journal des erreurs, pour améliorer Vanguard après coup : plantages, scripts PowerShell en échec, vérifications
//! impossibles, scans ratés. Il est écrit sur la petite partition VANGUARDLOG de la clé, la seule modifiable sur les
//! autres ordinateurs (la partition VANGUARD y est en lecture seule), et rapatrié par outils/deployer.sh au
//! branchement sur l'ordinateur de développement, qui en fait des tickets GitHub (outils/journal-vers-github.py).
//! Sans clé branchée, il est écrit dans le dossier de Vanguard de cet ordinateur (rapatrié de même sur l'ordinateur
//! de développement). Écrit en français : il est destiné au développement, pas à l'utilisateur.
//!
//! Rien de personnel, ni sur la personne ni sur les gens que Vanguard a croisés : le journal finit en tickets sur
//! GitHub. Avant l'écriture, le dossier personnel devient « ~ » ; le nom du compte, celui de la machine et ce que la
//! base des appareils garde (réseaux, appareils, surnoms) deviennent « `<utilisateur>` », « `<machine>` », « <réseau> »,
//! « `<appareil>` » ; les dossiers des autres comptes, les courriels, les numéros de série, les SID de Windows, les noms
//! du réseau local et du Wi-Fi sont masqués ; une adresse MAC ne garde que le préfixe du fabricant, une adresse IP
//! publique devient une adresse de documentation.

use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::OnceLock;

/// Fichier témoin à la racine de la partition VANGUARDLOG.
pub const TEMOIN: &str = "vanguard-journal.cle";

pub const FICHIER: &str = "journal-erreurs.txt";
/// Au-delà, plus rien n'est ajouté : une erreur répétée en boucle ne remplit pas la partition.
const TAILLE_MAX: u64 = 4 * 1024 * 1024;
/// Longueur maximale d'un détail (sortie d'erreur de PowerShell…).
const DETAIL_MAX: usize = 3000;

/// Où écrire : la partition VANGUARDLOG de la clé si elle est branchée, sinon le dossier de Vanguard.
fn dossier() -> Option<&'static PathBuf> {
    static DOSSIER: OnceLock<Option<PathBuf>> = OnceLock::new();
    DOSSIER
        .get_or_init(|| {
            // Pendant les tests automatiques, et sous Wine (tests de la version Windows, sans PowerShell) : pas de
            // journal, sinon de fausses erreurs partiraient en tickets.
            #[cfg(windows)]
            let essai = cfg!(test) || sous_wine();
            #[cfg(unix)]
            let essai = cfg!(test);
            if essai {
                return None;
            }
            partition_de_la_cle().or_else(|| Some(crate::socle::dossier_local()))
        })
        .as_ref()
}

/// Partition VANGUARDLOG de la clé, si elle est branchée.
pub(crate) fn partition_de_la_cle() -> Option<PathBuf> {
    let connues = crate::protection::cles_connues::jetons();
    #[cfg(windows)]
    {
        lecteur_windows(&connues)
    }
    #[cfg(unix)]
    {
        partition_parmi(crate::reseau::volumes_montes(), &connues)
    }
}

/// Parmi `montages`, la partition des journaux : le témoin et le jeton d'une clé connue de cet ordinateur (deployer.sh
/// y recopie celui de la clé), un volume étranger au seul témoin ne reçoit ni le journal ni « Mes ordinateurs ».
/// Choisie comme la clé (`cles_connues::seule_connue`) : une copie de la partition à son jeton ne reçoit pas le journal selon l'ordre des chemins, ni ne fait la liste de
/// « Mes ordinateurs » (campagne d'attaque n° 4, C-B2).
#[cfg(any(unix, test))]
fn partition_parmi(montages: Vec<PathBuf>, connues: &std::collections::BTreeSet<String>) -> Option<PathBuf> {
    crate::protection::cles_connues::seule_connue(
        montages.into_iter().filter(|d| d.join(TEMOIN).is_file()).collect(),
        connues,
    )
}

/// Lecteurs D: à Z: interrogés en même temps, 2 s au plus : un lecteur réseau déconnecté peut mettre de longues
/// secondes à répondre, et le journal ne doit jamais faire attendre le programme. Toutes les réponses attendues (ou le
/// délai), pas la première : une copie de la partition doit se voir, comme sous Linux (un lecteur qui répond après
/// le délai n'est pas compté, ni comme partition, ni comme copie).
#[cfg(windows)]
fn lecteur_windows(connues: &std::collections::BTreeSet<String>) -> Option<PathBuf> {
    use crate::protection::cles_connues;
    use std::time::{Duration, Instant};
    let (envoi, reception) = std::sync::mpsc::channel();
    for lettre in 'D'..='Z' {
        let envoi = envoi.clone();
        std::thread::spawn(move || {
            let lecteur = PathBuf::from(format!("{lettre}:\\"));
            // Le jeton lu ici aussi, sous le délai : relu après, un lecteur qui cesse de répondre figerait tout.
            let lu = lecteur
                .join(TEMOIN)
                .is_file()
                .then(|| (cles_connues::jeton_de(&lecteur), lecteur));
            let _ = envoi.send(lu);
        });
    }
    drop(envoi);
    let limite = Instant::now() + Duration::from_secs(2);
    let mut trouves = Vec::new();
    // Fin : toutes les réponses reçues (canal fermé), ou le délai passé.
    while let Ok(reponse) = reception.recv_timeout(limite.saturating_duration_since(Instant::now())) {
        trouves.extend(reponse);
    }
    cles_connues::seule_parmi_lus(trouves, connues)
}

/// Wine installe ses propres programmes dans system32 ; wineboot.exe n'existe pas sur un vrai Windows.
#[cfg(windows)]
pub(crate) fn sous_wine() -> bool {
    let systeme = std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from("C:\\windows"), PathBuf::from);
    systeme.join("system32").join("wineboot.exe").is_file()
}

/// Système et version, pour situer l'erreur (« Windows 10.0.26200.9711 », « Arch Linux 6.17.2 », « macOS 15.1 »).
pub(crate) fn systeme() -> &'static str {
    static SYSTEME: OnceLock<String> = OnceLock::new();
    SYSTEME.get_or_init(|| {
        #[cfg(target_os = "linux")]
        {
            let nom = crate::socle::systeme::nom();
            let noyau = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
            format!("{nom} {}", noyau.trim())
        }
        // « macOS 15.1 (Apple Silicon) »
        #[cfg(target_os = "macos")]
        {
            let version = crate::machine::macos::version_systeme("ProductVersion").unwrap_or_default();
            format!("macOS {version} ({})", crate::machine::macos::architecture())
        }
        #[cfg(windows)]
        {
            // « Microsoft Windows [Version 10.0.26200.9711] »
            crate::commande::lancer(crate::commande::cmd().args(["/d", "/c", "ver"]), 5)
                .and_then(|r| {
                    r.sortie
                        .split_once("Version ")
                        .map(|(_, v)| format!("Windows {}", v.trim().trim_end_matches(']')))
                })
                .unwrap_or_else(|| "Windows".into())
        }
    })
}

/// Noms de la personne et de la machine, avec leur remplacement, du plus long au plus court : un nom contenu dans
/// un autre (« alex » dans « alex-pc ») ne le coupe pas en deux.
fn noms_personnels() -> &'static [(String, &'static str)] {
    static NOMS: OnceLock<Vec<(String, &'static str)>> = OnceLock::new();
    NOMS.get_or_init(|| {
        let mut noms: Vec<(String, &str)> = ["USER", "USERNAME", "LOGNAME"]
            .iter()
            .filter_map(|v| std::env::var(v).ok())
            .map(|n| (n, "<utilisateur>"))
            .collect();
        #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
        let mut machines: Vec<String> = ["COMPUTERNAME", "HOSTNAME"]
            .iter()
            .filter_map(|v| std::env::var(v).ok())
            .chain(std::fs::read_to_string("/proc/sys/kernel/hostname").ok())
            .collect();
        // macOS n'exporte pas le nom de la machine et n'a pas /proc : on le demande (nom affiché « MacBook Pro de… »,
        // nom réseau, nom d'hôte « ….local »).
        #[cfg(target_os = "macos")]
        {
            use crate::machine::macos::{nom_hote, nom_machine};
            machines.extend(nom_machine("ComputerName"));
            machines.extend(nom_machine("LocalHostName"));
            machines.extend(nom_hote());
        }
        noms.extend(machines.into_iter().map(|n| (n.trim().to_string(), "<machine>")));
        // Un nom très court (« pc », « a ») remplacerait des morceaux de mots.
        noms.retain(|(n, _)| n.chars().count() >= 3);
        noms.sort_by_key(|(n, _)| std::cmp::Reverse(n.len()));
        noms
    })
}

/// Noms d'appareils et de réseaux qui ne nomment personne (sortes d'appareils, pièces, marques, systèmes) : un nom
/// fait seulement de ces mots reste en clair. Même liste que outils/confidentialite.py.
const MOTS_GENERIQUES: &str = "imprimante printer box routeur router modem téléphone telephone phone tablette \
    tablet ordinateur computer pc portable laptop console télé tele tv télévision television caméra camera enceinte \
    speaker montre watch nas serveur server switch répéteur repeater borne wifi hp lg local gateway _gateway \
    localhost salon cuisine chambre bureau garage maison home office kitchen living room bedroom chromecast airplay \
    echo alexa nest google apple iphone ipad macbook imac android galaxy pixel kindle fire roku sonos xbox \
    playstation nintendo raspberrypi raspberry pi synology brother epson canon samsung sony omarchy archlinux arch \
    ubuntu fedora debian linuxmint mint pop-os manjaro endeavouros cachyos bazzite opensuse";

fn generique(nom: &str) -> bool {
    let bas = nom.to_lowercase();
    let mut mots = bas
        .split(|c: char| !(c.is_alphanumeric() || c == '-' || c == '_'))
        .filter(|m| !m.is_empty())
        .peekable();
    mots.peek().is_some() && mots.all(|m| MOTS_GENERIQUES.split_whitespace().any(|g| g == m))
}

/// Les noms à retirer, du plus long au plus court (un nom contenu dans un autre, « alex » dans « alex-pc », ne le
/// coupe pas en deux) : la personne et la machine, puis ce que la base des appareils garde sur les gens d'ici,
/// relue à chaque erreur (un scan a pu l'enrichir).
pub(crate) fn noms_a_retirer() -> Vec<(String, &'static str)> {
    let (reseaux, appareils) = crate::reseau::noms_connus();
    let mut noms = noms_personnels().to_vec();
    let base = reseaux.into_iter().map(|n| (n, "<réseau>"));
    for (nom, remplacement) in base.chain(appareils.into_iter().map(|n| (n, "<appareil>"))) {
        let nom = nom.trim().to_string();
        if nom.chars().count() >= 4
            && !generique(&nom)
            && !noms.iter().any(|(n, _)| n.to_lowercase() == nom.to_lowercase())
        {
            noms.push((nom, remplacement));
        }
    }
    noms.sort_by_key(|(n, _)| std::cmp::Reverse(n.chars().count()));
    noms
}

/// Retire ce qui identifie une personne ou une machine.
pub(crate) fn anonymiser(texte: &str) -> String {
    let maisons: Vec<String> = ["HOME", "USERPROFILE"]
        .iter()
        .filter_map(|v| std::env::var(v).ok())
        .collect();
    anonymiser_avec(texte, &maisons, &noms_a_retirer())
}

fn anonymiser_avec(texte: &str, maisons: &[String], noms: &[(String, &str)]) -> String {
    let mut t = texte.to_string();
    for maison in maisons.iter().filter(|m| m.len() > 3) {
        // Aussi écrit avec des barres obliques (« C:/Users/… ») ou doublées (JSON, PowerShell : « C:\\Users\\… »).
        for variante in [maison.clone(), maison.replace('\\', "/"), maison.replace('\\', "\\\\")] {
            t = remplacer(
                &t,
                &variante,
                "~",
                |_| true,
                |c| c.is_none_or(|c| !(c.is_alphanumeric() || "._-".contains(c))),
            );
        }
    }
    let t = sans_noms_avec(&t, noms);
    let t = masquer_comptes(&t);
    let t = masquer_courriels(&t);
    let t = masquer_sid(&t);
    let t: String = t.split_inclusive('\n').map(masquer_ligne).collect();
    let t = masquer_noms_locaux(&t);
    let t = masquer_mac(&t);
    let t = masquer_ipv6(&t);
    masquer_ipv4(&t)
}

/// Le texte sans ces noms (personne, machine, réseaux et appareils de la base, voir `noms_a_retirer`), en mots
/// entiers et à la casse près.
pub(crate) fn sans_noms_avec(texte: &str, noms: &[(String, &str)]) -> String {
    let mut t = texte.to_string();
    for (nom, remplacement) in noms {
        t = remplacer(&t, nom, remplacement, mot_entier, mot_entier);
    }
    t
}

/// Un mot entier : ni lettre ni chiffre collés avant ou après (« Max » ne coupe pas « Maxime »).
fn mot_entier(c: Option<char>) -> bool {
    c.is_none_or(|c| !c.is_alphanumeric())
}

/// `nom` remplacé par `par`, à la casse près (« DESKTOP-AB12 » comme « desktop-ab12 »), là où les caractères d'avant
/// et d'après conviennent à `avant` et `apres` (None : début ou fin du texte).
fn remplacer(
    texte: &str,
    nom: &str,
    par: &str,
    avant: impl Fn(Option<char>) -> bool,
    apres: impl Fn(Option<char>) -> bool,
) -> String {
    let mut sortie = String::with_capacity(texte.len());
    let mut precedent = None;
    let mut reste = texte;
    while let Some(c) = reste.chars().next() {
        if let Some(n) = longueur_sans_casse(reste, nom)
            && avant(precedent)
            && apres(reste[n..].chars().next())
        {
            sortie.push_str(par);
            precedent = reste[..n].chars().next_back();
            reste = &reste[n..];
            continue;
        }
        sortie.push(c);
        precedent = Some(c);
        reste = &reste[c.len_utf8()..];
    }
    sortie
}

/// Longueur en octets du début de `texte` égal à `nom` à la casse près, s'il commence par lui.
fn longueur_sans_casse(texte: &str, nom: &str) -> Option<usize> {
    let mut lus = 0;
    let mut caracteres = texte.chars();
    for n in nom.chars() {
        let c = caracteres.next()?;
        if !c.to_lowercase().eq(n.to_lowercase()) {
            return None;
        }
        lus += c.len_utf8();
    }
    (lus > 0).then_some(lus)
}

/// Dossiers personnels des autres comptes (« C:\Users\Zoé », « /home/bob ») : le nom devient « `<compte>` ». Les
/// dossiers communs (Public, Default, Shared…) ne nomment personne.
fn masquer_comptes(texte: &str) -> String {
    let mut sortie = String::with_capacity(texte.len());
    let mut reste = texte;
    while let Some(c) = reste.chars().next() {
        if let Some((n, windows)) = debut_dossier_personnel(reste) {
            sortie.push_str(&reste[..n]);
            reste = &reste[n..];
            let fin = fin_du_compte(reste, windows);
            if fin > 0 && !compte_commun(&reste[..fin]) {
                sortie.push_str("<compte>");
                reste = &reste[fin..];
            }
            continue;
        }
        sortie.push(c);
        reste = &reste[c.len_utf8()..];
    }
    sortie
}

/// Longueur du début de dossier personnel qui commence `texte` (« /home/ », « C:\Users\ »…), et s'il est de Windows.
fn debut_dossier_personnel(texte: &str) -> Option<(usize, bool)> {
    // Le plus long d'abord : « /run/media/ » avant « /media/ ».
    for debut in ["/var/home/", "/run/media/", "/home/", "/Users/", "/media/"] {
        if let Some(n) = longueur_sans_casse(texte, debut) {
            return Some((n, false));
        }
    }
    if !matches!(texte.as_bytes(), [lecteur, b':', _, ..] if lecteur.is_ascii_alphabetic()) {
        return None;
    }
    // « C:\Users\ », « C:/Users/ », ou doublé dans du JSON, du PowerShell : « C:\\Users\\ ».
    for separateur in ["\\\\", "\\", "/"] {
        if let Some(apres) = texte[2..].strip_prefix(separateur)
            && let Some(n) = longueur_sans_casse(apres, "users")
            && apres[n..].starts_with(separateur)
        {
            return Some((2 + 2 * separateur.len() + n, true));
        }
    }
    None
}

/// Fin du nom de compte qui commence `texte`. Sous Windows, il peut avoir des espaces ou une apostrophe (« Jean
/// Dupont », « Zoé d'Alice ») : gardées seulement si le chemin continue après ; sinon l'apostrophe peut fermer une chaîne
/// (« 'C:\Users\bob' »).
fn fin_du_compte(texte: &str, windows: bool) -> usize {
    if !windows {
        return texte
            .find(|c: char| !(c.is_alphanumeric() || "._-".contains(c)))
            .unwrap_or(texte.len());
    }
    let fin = texte
        .find(|c: char| "\\/\"\n\r\t:;,|<>*?)]".contains(c))
        .unwrap_or(texte.len());
    let nom = if texte[fin..].starts_with(['\\', '/']) {
        &texte[..fin]
    } else {
        texte[..fin].split([' ', '\'']).next().unwrap_or_default()
    };
    nom.trim_end_matches([' ', '.']).len()
}

/// Dossiers communs à tous les ordinateurs, variable pas encore remplacée (« %USERNAME% », « $USER »), ou pas un
/// nom du tout (« C:\Users\… »).
fn compte_commun(nom: &str) -> bool {
    const COMMUNS: [&str; 8] = [
        "public",
        "default",
        "default user",
        "all users",
        "defaultuser0",
        "shared",
        "guest",
        "wdagutilityaccount",
    ];
    nom.contains(['%', '$', '{', '<', '~'])
        || !nom.chars().any(char::is_alphanumeric)
        || COMMUNS.iter().any(|c| nom.eq_ignore_ascii_case(c))
}

/// Adresses courriel (une recherche de fuites, une identité Git…) : « `<courriel>` ».
fn masquer_courriels(texte: &str) -> String {
    let b = texte.as_bytes();
    let locale = |c: u8| c.is_ascii_alphanumeric() || b"._%+-".contains(&c);
    let domaine = |c: u8| c.is_ascii_alphanumeric() || c == b'.' || c == b'-';
    let mut sortie = String::with_capacity(texte.len());
    let mut copie = 0;
    for (i, _) in texte.match_indices('@') {
        if i < copie {
            continue;
        }
        let debut = i - b.iter().take(i).skip(copie).rev().take_while(|c| locale(**c)).count();
        let mut fin = i + 1 + b.iter().skip(i + 1).take_while(|c| domaine(**c)).count();
        while fin > i + 1 && b.get(fin - 1) == Some(&b'.') {
            fin -= 1;
        }
        let nom_de_domaine = texte[i + 1..fin].rsplit_once('.').is_some_and(|(nom, fin_du_nom)| {
            !nom.is_empty() && fin_du_nom.len() >= 2 && fin_du_nom.bytes().all(|c| c.is_ascii_alphabetic())
        });
        if debut < i && nom_de_domaine {
            sortie.push_str(&texte[copie..debut]);
            sortie.push_str("<courriel>");
            copie = fin;
        }
    }
    sortie.push_str(&texte[copie..]);
    sortie
}

/// Identifiants de comptes Windows (SID « `S-1-5-21-<machine>-<compte>` ») : la partie propre à la machine devient
/// 0-0-0 ; le numéro du compte (500 : Administrateur, 1001 : premier compte…) reste, il aide à comprendre.
fn masquer_sid(texte: &str) -> String {
    const DEBUT: &str = "S-1-5-21-";
    let mut sortie = String::with_capacity(texte.len());
    let mut reste = texte;
    while let Some(i) = reste.find(DEBUT) {
        sortie.push_str(&reste[..i + DEBUT.len()]);
        reste = &reste[i + DEBUT.len()..];
        let b = reste.as_bytes();
        let (mut fin, mut nombres) = (0, 0);
        while nombres < 3 {
            let chiffres = b.iter().skip(fin).take_while(|c| c.is_ascii_digit()).count();
            if chiffres == 0 {
                break;
            }
            fin += chiffres;
            nombres += 1;
            if nombres < 3 {
                if b.get(fin) != Some(&b'-') {
                    break;
                }
                fin += 1;
            }
        }
        if nombres == 3 {
            sortie.push_str("0-0-0");
            reste = &reste[fin..];
        }
    }
    sortie.push_str(reste);
    sortie
}

/// Une ligne : numéros de série et identifiants du matériel (« Serial Number: … », « UUID : … ») ; noms du Wi-Fi
/// (« SSID : … », ou entre guillemets sur une ligne qui parle du Wi-Fi).
fn masquer_ligne(ligne: &str) -> String {
    const SERIES: [&str; 9] = [
        "serial number",
        "serialnumber",
        "serial_number",
        "serial no",
        "serial",
        "numéro de série",
        "uuid",
        "ioplatformuuid",
        "ioplatformserialnumber",
    ];
    const WIFI: [&str; 4] = [
        "ssid",
        "all user profile",
        "profil tous les utilisateurs",
        "current user profile",
    ];
    let mut t = ligne.to_string();
    for (cles, par) in [(&SERIES[..], "<numéro>"), (&WIFI[..], "<wifi>")] {
        for cle in cles {
            t = valeur_masquee(&t, cle, par);
        }
    }
    let bas = t.to_lowercase();
    if ["wi-fi", "wifi", "ssid", "wlan", "wireless", "sans fil"]
        .iter()
        .any(|m| bas.contains(m))
    {
        for (ouvrant, fermant) in [("« ", " »"), ("“", "”")] {
            t = entre_guillemets(&t, ouvrant, fermant, "<wifi>");
        }
    }
    t
}

/// La valeur qui suit `cle` (« Serial Number:    S4EV… », « "serial_number": "…" », « SSID 1 : Chez Max »)
/// remplacée par `par`. La clé est un mot entier ; entre elle et « : » ou « = », seulement des espaces, des
/// guillemets ou un numéro (« SSID 1 »).
fn valeur_masquee(ligne: &str, cle: &str, par: &str) -> String {
    let mut precedent = None;
    for (i, c) in ligne.char_indices() {
        if mot_entier(precedent)
            && let Some(n) = longueur_sans_casse(&ligne[i..], cle)
            && mot_entier(ligne[i + n..].chars().next())
        {
            let apres = &ligne[i + n..];
            let separateur = apres.find([':', '=']);
            if let Some(s) = separateur
                && apres[..s]
                    .chars()
                    .all(|c| c == ' ' || c == '\t' || c == '"' || c.is_ascii_digit())
            {
                let valeur = &apres[s + 1..];
                let debut = valeur.len() - valeur.trim_start_matches([' ', '\t', '"']).len();
                // Un nom de Wi-Fi peut avoir des espaces : jusqu'à la fin de la ligne. Un numéro : un seul mot.
                let longueur = if par == "<wifi>" {
                    valeur[debut..].trim_end_matches(['\n', '\r', '"', ' ']).len()
                } else {
                    valeur[debut..]
                        .find([' ', '\t', '"', ',', ';', '\n', '\r'])
                        .unwrap_or(valeur.len() - debut)
                };
                if longueur > 0 && !valeur[debut..].starts_with('<') {
                    let depart = i + n + s + 1 + debut;
                    return format!("{}{par}{}", &ligne[..depart], &ligne[depart + longueur..]);
                }
            }
        }
        precedent = Some(c);
    }
    ligne.to_string()
}

fn entre_guillemets(ligne: &str, ouvrant: &str, fermant: &str, par: &str) -> String {
    let mut sortie = String::with_capacity(ligne.len());
    let mut reste = ligne;
    while let Some(i) = reste.find(ouvrant) {
        let debut = i + ouvrant.len();
        let Some(n) = reste[debut..].find(fermant) else {
            break;
        };
        sortie.push_str(&reste[..debut]);
        sortie.push_str(par);
        sortie.push_str(fermant);
        reste = &reste[debut + n + fermant.len()..];
    }
    sortie.push_str(reste);
    sortie
}

/// Noms d'appareils du réseau local (« iPhone-de-Zoé.local », « nas.lan ») : le nom devient « `<appareil>` ».
fn masquer_noms_locaux(texte: &str) -> String {
    const SUFFIXES: [&str; 5] = [".home.arpa", ".internal", ".local", ".home", ".lan"];
    let nom = |c: char| c.is_alphanumeric() || "-_.".contains(c);
    let mut sortie = String::with_capacity(texte.len());
    let mut reste = texte;
    while let Some(debut) = reste.find(nom) {
        sortie.push_str(&reste[..debut]);
        reste = &reste[debut..];
        let fin = reste.find(|c: char| !nom(c)).unwrap_or(reste.len());
        let mot = reste[..fin].trim_end_matches('.');
        let bas = mot.to_lowercase();
        match SUFFIXES.iter().find(|s| bas.ends_with(*s) && bas.len() > s.len()) {
            Some(suffixe) if !mot.starts_with('.') => {
                sortie.push_str("<appareil>");
                sortie.push_str(&mot[mot.len() - suffixe.len()..]);
                sortie.push_str(&reste[mot.len()..fin]);
            }
            _ => sortie.push_str(&reste[..fin]),
        }
        reste = &reste[fin..];
    }
    sortie.push_str(reste);
    sortie
}

/// Nombre tiré d'une clé au hasard propre à ce lancement : une adresse garde le même remplaçant dans tout ce qu'une
/// session écrit, et rien ne permet de remonter à la vraie (la clé n'est écrite nulle part).
fn hasard(graine: &[u8]) -> u64 {
    use std::hash::{BuildHasher, Hasher};
    static CLE: OnceLock<std::collections::hash_map::RandomState> = OnceLock::new();
    let mut h = CLE
        .get_or_init(std::collections::hash_map::RandomState::new)
        .build_hasher();
    h.write(graine);
    h.finish()
}

/// Adresses MAC : le préfixe du fabricant (trois premiers octets) reste, le reste est inventé. Une adresse aléatoire
/// (téléphones : bit « local » du premier octet) est inventée en entier, sorte gardée.
fn masquer_mac(texte: &str) -> String {
    remplacer_passages(texte, |b, i| {
        let libre = precedent(b, i).is_none_or(|c| !(c.is_ascii_alphanumeric() || c == b':' || c == b'-'));
        if !libre {
            return None;
        }
        let (fin, octets, separateur) = lire_mac(b, i)?;
        let majuscules = b.iter().take(fin).skip(i).any(u8::is_ascii_uppercase);
        Some((fin, mac_inventee(octets, separateur, majuscules)))
    })
}

/// L'octet juste avant `i`, s'il y en a un.
fn precedent(b: &[u8], i: usize) -> Option<u8> {
    i.checked_sub(1).and_then(|k| b.get(k)).copied()
}

/// Le texte où chaque passage que `trouver` reconnaît à une position (sa fin et son remplaçant) est remplacé, de gauche
/// à droite ; la recherche reprend après chaque passage remplacé.
fn remplacer_passages(texte: &str, trouver: impl Fn(&[u8], usize) -> Option<(usize, String)>) -> String {
    let b = texte.as_bytes();
    let mut sortie = String::with_capacity(texte.len());
    let (mut copie, mut i) = (0, 0);
    while i < b.len() {
        if let Some((fin, remplacant)) = trouver(b, i) {
            sortie.push_str(&texte[copie..i]);
            sortie.push_str(&remplacant);
            copie = fin;
            i = fin;
        } else {
            i += 1;
        }
    }
    sortie.push_str(&texte[copie..]);
    sortie
}

/// Adresse MAC qui commence à `i` : six octets séparés par « : » (un ou deux chiffres, macOS écrit « 3c:8d:a:… »)
/// ou par « - » (deux chiffres, Windows). Rend sa fin, ses octets et le séparateur.
fn lire_mac(b: &[u8], i: usize) -> Option<(usize, [u8; 6], u8)> {
    let mut octets = [0u8; 6];
    let (mut j, mut separateur, mut courts) = (i, 0, false);
    for (k, octet) in octets.iter_mut().enumerate() {
        if k > 0 {
            let s = *b.get(j)?;
            if (k == 1 && s != b':' && s != b'-') || (k > 1 && s != separateur) {
                return None;
            }
            separateur = s;
            j += 1;
        }
        let chiffres = b.iter().skip(j).take(2).take_while(|c| c.is_ascii_hexdigit()).count();
        if chiffres == 0 {
            return None;
        }
        courts |= chiffres == 1;
        *octet = u8::from_str_radix(std::str::from_utf8(b.get(j..j + chiffres)?).ok()?, 16).ok()?;
        j += chiffres;
    }
    // Suivie d'un autre chiffre ou séparateur : un morceau d'autre chose (adresse IPv6…).
    if (separateur == b'-' && courts) || b.get(j).is_some_and(|c| c.is_ascii_alphanumeric() || b":-".contains(c)) {
        return None;
    }
    Some((j, octets, separateur))
}

fn mac_inventee(octets: [u8; 6], separateur: u8, majuscules: bool) -> String {
    let tirage = hasard(&octets).to_le_bytes();
    let mut neuf = octets;
    if octets[0] & 0x02 == 0 {
        neuf[3..].copy_from_slice(&tirage[3..6]);
    } else {
        // Adresse aléatoire : rien à garder, sauf sa sorte (bits « local » et « groupe »).
        neuf[0] = (tirage[0] & 0xFC) | (octets[0] & 0x03);
        neuf[1..].copy_from_slice(&tirage[1..6]);
    }
    // Jamais la vraie, même par un hasard d'une chance sur seize millions.
    if neuf == octets {
        neuf[5] ^= 1;
    }
    let octets: Vec<String> = neuf
        .iter()
        .map(|o| {
            if majuscules {
                format!("{o:02X}")
            } else {
                format!("{o:02x}")
            }
        })
        .collect();
    octets.join(&char::from(separateur).to_string())
}

/// Adresses IPv6 : elles contiennent le préfixe de la maison, parfois l'adresse MAC. La sorte reste (Internet, réseau
/// local, lien local), le reste est inventé ; celles qui sont les mêmes partout (::1, fe80::1, DNS publics,
/// documentation) restent.
fn masquer_ipv6(texte: &str) -> String {
    let b = texte.as_bytes();
    let classe = |c: u8| c.is_ascii_hexdigit() || c == b':' || c == b'.';
    let mut sortie = String::with_capacity(texte.len());
    let (mut copie, mut i) = (0, 0);
    while let Some(&c) = b.get(i) {
        if !classe(c) || precedent(b, i).is_some_and(|p| p.is_ascii_alphanumeric() || classe(p)) {
            i += 1;
            continue;
        }
        let fin = i + b.iter().skip(i).take_while(|c| classe(**c)).count();
        let mot = texte[i..fin].trim_end_matches('.');
        if b.get(fin).is_none_or(|c| !c.is_ascii_alphanumeric())
            && mot.matches(':').count() >= 2
            && let Ok(ip) = mot.parse::<Ipv6Addr>()
            && let Some(faux) = ipv6_inventee(ip, mot)
        {
            sortie.push_str(&texte[copie..i]);
            sortie.push_str(&faux);
            copie = i + mot.len();
        }
        i = fin;
    }
    sortie.push_str(&texte[copie..]);
    sortie
}

fn ipv6_inventee(ip: Ipv6Addr, ecrite: &str) -> Option<String> {
    let s = ip.segments();
    let documentation = s[0] == 0x2001 && s[1] == 0x0db8;
    // Services DNS publics connus (fournisseur() de src/machine/dns.rs).
    let resolveur = matches!(
        (s[0], s[1]),
        (0x2606, 0x4700)
            | (0x2001, 0x4860)
            | (0x2620, 0x00fe | 0x0119)
            | (0x2a07, 0xa8c0 | 0xa8c1 | 0xe340)
            | (0x2a10, 0x50c0)
    );
    // Presque vide après le premier groupe (« fe80::1 », « fd00::1 ») : la même chez tout le monde.
    let chiffres: usize = ecrite
        .split(':')
        .skip_while(|g| g.is_empty())
        .skip(1)
        .map(str::len)
        .sum();
    if ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || documentation
        || resolveur
        || chiffres <= 4
        || ip.to_ipv4_mapped().is_some()
    {
        return None;
    }
    let sorte = if s[0] & 0xfe00 == 0xfc00 {
        "fd00"
    } else if s[0] & 0xffc0 == 0xfe80 {
        "fe80"
    } else {
        "2001:db8"
    };
    Some(format!("{sorte}::{:x}", hasard(&ip.octets()) & 0xffff))
}

/// Adresses IPv4 publiques (la maison, un serveur…) : une adresse de documentation à la place (203.0.113.x). Les
/// adresses privées (192.168…, 10…) sont les mêmes dans des millions de maisons et aident à comprendre une erreur de
/// scan : elles restent, comme les DNS publics connus.
fn masquer_ipv4(texte: &str) -> String {
    remplacer_passages(texte, |b, i| {
        let libre = precedent(b, i).is_none_or(|c| !(c.is_ascii_alphanumeric() || c == b'.'));
        if !libre || !b.get(i).is_some_and(u8::is_ascii_digit) {
            return None;
        }
        let (fin, ip) = lire_ipv4(b, i).filter(|(_, ip)| !ipv4_commune(*ip))?;
        Some((fin, format!("203.0.113.{}", 1 + hasard(&ip.octets()) % 254)))
    })
}

/// Quatre nombres de 0 à 255 séparés par des points, ni collés à une lettre ni suivis d'un cinquième (« 5.1.2.3.4 »,
/// numéro de version).
fn lire_ipv4(b: &[u8], i: usize) -> Option<(usize, Ipv4Addr)> {
    let mut octets = [0u8; 4];
    let mut j = i;
    for (k, octet) in octets.iter_mut().enumerate() {
        if k > 0 {
            if b.get(j) != Some(&b'.') {
                return None;
            }
            j += 1;
        }
        let chiffres = b.iter().skip(j).take(4).take_while(|c| c.is_ascii_digit()).count();
        if !(1..=3).contains(&chiffres) {
            return None;
        }
        *octet = std::str::from_utf8(b.get(j..j + chiffres)?).ok()?.parse().ok()?;
        j += chiffres;
    }
    let suite = b.get(j).is_some_and(u8::is_ascii_alphanumeric)
        || (b.get(j) == Some(&b'.') && b.get(j + 1).is_some_and(u8::is_ascii_digit));
    (!suite).then_some((j, Ipv4Addr::from(octets)))
}

fn ipv4_commune(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    // Services DNS publics connus (fournisseur() de src/machine/dns.rs).
    let resolveur = matches!(
        (a, b, c),
        (1, 1, 1)
            | (1, 0, 0)
            | (9, 9, 9)
            | (149, 112, 112)
            | (208, 67, 222 | 220)
            | (45, 90, 28 | 30)
            | (94, 140, 14 | 15)
            | (194, 242, 2)
            | (185, 228, 168 | 169)
            | (76, 76, 2 | 10)
    ) || matches!((a, b, c, d), (8, 8, 8, 8) | (8, 8, 4, 4));
    // Tout ce qui n'est pas une adresse d'Internet (règle commune : privée, partagée, exemple, réservée…) est la
    // même chez tout le monde.
    crate::socle::adresses::portee(ip.into()) != crate::socle::adresses::Portee::Internet || resolveur
}

/// La commande lancée, pour le journal : le surnom donné par « vanguard nommer » nomme souvent quelqu'un
/// (« tablette de Zoé ») ; il ne reste que « `<surnom>` ».
fn commande_anonyme(args: &[String]) -> String {
    let mut args = args.to_vec();
    if let Some(k) = args.iter().position(|a| a == "nommer" || a == "name")
        && args.len() > k + 2
    {
        args.truncate(k + 2);
        args.push("<surnom>".into());
    }
    args.join(" ")
}

/// Les arguments en texte, les octets qui ne sont pas de l'UTF-8 remplacés par « � » : `std::env::args()` panique
/// sur un tel argument (un nom de fichier), et ici, appelé depuis le crochet de panique, il faisait avorter Vanguard.
fn arguments_lisibles(args: impl IntoIterator<Item = std::ffi::OsString>) -> Vec<String> {
    args.into_iter().map(|a| a.to_string_lossy().into_owned()).collect()
}

/// Ajoute une erreur au journal de la clé. Sans clé branchée, ou si l'écriture échoue : rien, en silence (le
/// journal ne doit jamais gêner le programme).
pub fn erreur(contexte: &str, detail: &str) {
    let Some(dossier) = dossier() else {
        return;
    };
    let chemin = dossier.join(FICHIER);
    // Le fichier lui-même : jamais la cible d'un lien, jamais un tube (ouvert en écriture, il attendait un lecteur
    // pour toujours, et chaque erreur notée figeait Vanguard).
    if std::fs::symlink_metadata(&chemin).is_ok_and(|m| !m.file_type().is_file() || m.len() > TAILLE_MAX) {
        return;
    }
    let commande = commande_anonyme(&arguments_lisibles(std::env::args_os().skip(1)));
    let mut detail = anonymiser(detail.trim());
    if detail.len() > DETAIL_MAX {
        let coupe = (0..=DETAIL_MAX)
            .rev()
            .find(|&i| detail.is_char_boundary(i))
            .unwrap_or(0);
        detail.truncate(coupe);
        detail.push_str(" […]");
    }
    let entree = format!(
        "== {} · vanguard {} · {} · {} · {}\n[{contexte}]\n{}\n\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M UTC"),
        env!("CARGO_PKG_VERSION"),
        systeme(),
        if crate::langue::anglais() { "en" } else { "fr" },
        if commande.is_empty() {
            "menu".into()
        } else {
            anonymiser(&commande)
        },
        detail.lines().map(|l| format!("  {l}")).collect::<Vec<_>>().join("\n")
    );
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let _ = options.open(&chemin).and_then(|mut f| {
        if !f.metadata()?.file_type().is_file() {
            return Ok(());
        }
        f.write_all(entree.as_bytes())
    });
}

/// Une sortie coupée par celui qui la lit (`vanguard regles | head`) : println! panique sur le tube fermé. Ce n'est pas
/// un plantage, juste la fin de la lecture (Linux, macOS : EPIPE ; Windows : « le canal de communication est fermé »).
fn sortie_coupee(message: &str) -> bool {
    message.contains("failed printing to std")
        && ["os error 32)", "os error 232)", "Broken pipe"]
            .iter()
            .any(|m| message.contains(m))
}

thread_local! {
    /// Les gardes (`rattraper`) ouvertes sur ce fil : une panique y sera rattrapée par l'appelant.
    static GARDES: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Lance `f` sous une garde (catch_unwind) : une panique n'arrête que `f`, et l'appelant en fait un résultat non
/// vérifié (règle du bilan, domaine de l'audit du réseau, fichier analysé par YARA). Le crochet de panique, appelé
/// avant que la garde ne la rattrape, le sait ainsi : pas de plantage affiché ni noté, le programme continue.
pub fn rattraper<R>(f: impl FnOnce() -> R + std::panic::UnwindSafe) -> std::thread::Result<R> {
    GARDES.with(|g| g.set(g.get().saturating_add(1)));
    let resultat = std::panic::catch_unwind(f);
    GARDES.with(|g| g.set(g.get().saturating_sub(1)));
    resultat
}

/// Une garde est-elle ouverte sur ce fil ? Non, si le fil est déjà en train de finir (ses variables sont parties).
pub(crate) fn sous_garde() -> bool {
    GARDES.try_with(|g| g.get() > 0).unwrap_or(false)
}

/// Ce que le crochet fait d'une panique.
#[derive(Debug, PartialEq)]
enum Panique {
    /// Le lecteur a fermé la sortie : fin sans bruit.
    SortieCoupee,
    /// Sous une garde : notée comme erreur interne rattrapée, avec sa position, sans message à l'écran (l'appelant
    /// dit déjà « non vérifié »).
    Rattrapee,
    /// Le programme s'arrête : noté, puis le message habituel.
    Plantage,
}

fn nature(message: &str, sous_garde: bool) -> Panique {
    if sortie_coupee(message) {
        Panique::SortieCoupee
    } else if sous_garde {
        Panique::Rattrapee
    } else {
        Panique::Plantage
    }
}

/// Les plantages (panic) sont aussi notés, avant le message habituel. Une sortie coupée par le lecteur finit sans bruit,
/// comme les autres commandes (code 141, celui d'un tube fermé). Une panique rattrapée (`rattraper`) n'est pas un
/// plantage : un débordement dans une seule règle du bilan, que la version publiée vérifie, ne fait plus croire à un
/// arrêt du programme, ni à l'écran ni dans le journal.
pub fn installer() {
    let defaut = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let message = info.to_string();
        match nature(&message, sous_garde()) {
            Panique::SortieCoupee => std::process::exit(141),
            Panique::Rattrapee => erreur("erreur interne rattrapée", &message),
            Panique::Plantage => {
                erreur("plantage", &message);
                defaut(info);
            }
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sortie_coupee_pas_un_plantage() {
        assert!(sortie_coupee(
            "panicked at library/std/src/io/stdio.rs:1168:9:\nfailed printing to stdout: Broken pipe (os error 32)"
        ));
        assert!(sortie_coupee(
            "failed printing to stdout: Le canal de communication est sur le point d'être fermé. (os error 232)"
        ));
        assert!(!sortie_coupee("called `Option::unwrap()` on a `None` value"));
        assert!(!sortie_coupee(
            "failed printing to stdout: Disk quota exceeded (os error 122)"
        ));
    }

    /// Une panique rattrapée par une garde (règle du bilan, domaine, fichier de YARA) n'est pas un plantage : elle
    /// s'affichait comme tel au milieu de l'écran et entrait au journal sous « plantage ». La garde se lève même quand
    /// `f` panique, et une garde imbriquée ne lève pas celle qui l'entoure.
    #[test]
    fn une_panique_rattrapee_n_est_pas_un_plantage() {
        assert!(!sous_garde());
        assert_eq!(rattraper(sous_garde).ok(), Some(true));
        let imbriquees = rattraper(|| (rattraper(sous_garde).ok(), sous_garde()));
        assert_eq!(imbriquees.ok(), Some((Some(true), true)));
        let tombee: std::thread::Result<()> = rattraper(|| panic!("attempt to add with overflow"));
        assert!(tombee.is_err());
        assert!(!sous_garde(), "garde restée ouverte après une panique");
        let debordement = "panicked at src/nettoyer/mod.rs:110:17:\nattempt to add with overflow";
        assert_eq!(nature(debordement, true), Panique::Rattrapee);
        assert_eq!(nature(debordement, false), Panique::Plantage);
        let coupee = "failed printing to stdout: Broken pipe (os error 32)";
        assert_eq!(nature(coupee, true), Panique::SortieCoupee);
    }

    /// La partition des journaux n'est prise qu'avec le jeton d'une clé connue : témoin seul, ou jeton inconnu,
    /// rien n'y va.
    #[test]
    fn partition_des_journaux_au_jeton_connu() {
        let d = std::env::temp_dir().join(format!("vanguard-journal-partition-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let (temoin_seul, inconnue, connue) = (d.join("a"), d.join("b"), d.join("c"));
        for p in [&temoin_seul, &inconnue, &connue] {
            std::fs::create_dir_all(p).unwrap();
            std::fs::write(p.join(TEMOIN), "").unwrap();
        }
        let jeton = "0123456789abcdef0123456789abcdef";
        std::fs::write(
            inconnue.join(crate::protection::cles_connues::JETON),
            "ffffffffffffffffffffffffffffffff",
        )
        .unwrap();
        std::fs::write(connue.join(crate::protection::cles_connues::JETON), jeton).unwrap();
        let connues: std::collections::BTreeSet<String> = [jeton.to_string()].into();
        let volumes = vec![inconnue.clone(), connue.clone(), temoin_seul.clone()];
        assert_eq!(partition_parmi(volumes.clone(), &connues), Some(connue.clone()));
        assert_eq!(partition_parmi(volumes, &std::collections::BTreeSet::new()), None);
        // Sans jeton du tout : un journal d'avant n'est pas écrit sur un volume quelconque.
        assert_eq!(partition_parmi(vec![temoin_seul.clone()], &connues), None);
        // Une copie de la partition, jeton compris : aucune des deux ne reçoit le journal.
        let copie = d.join("d");
        std::fs::create_dir_all(&copie).unwrap();
        std::fs::write(copie.join(TEMOIN), "").unwrap();
        std::fs::write(copie.join(crate::protection::cles_connues::JETON), jeton).unwrap();
        assert_eq!(
            partition_parmi(vec![connue.clone(), copie, temoin_seul], &connues),
            None
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rien_de_personnel() {
        let maison = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap();
        let t = anonymiser(&format!("échec dans {maison}/Documents/x.ps1"));
        assert!(!t.contains(&maison), "{t}");
        assert!(t.contains('~'), "{t}");
    }

    #[test]
    fn nom_de_la_machine_retire() {
        for (nom, _) in noms_personnels() {
            let t = anonymiser(&format!("hôte {nom} injoignable"));
            assert!(!t.contains(nom.as_str()), "{t}");
        }
        // Linux le lit dans /proc, macOS le demande à scutil : il doit avoir été trouvé, sauf s'il est trop court
        // pour être masqué (« vm », « pc »), comme le veut noms_personnels.
        #[cfg(target_os = "linux")]
        let masquable =
            std::fs::read_to_string("/proc/sys/kernel/hostname").is_ok_and(|n| n.trim().chars().count() >= 3);
        #[cfg(target_os = "macos")]
        let masquable = true;
        #[cfg(unix)]
        if masquable {
            assert!(noms_personnels().iter().any(|(_, r)| *r == "<machine>"));
        }
    }

    // Valeurs inventées : comptes alice, bob, Zoé, Jean Dupont ; réseau « Chez Max » ; préfixe d'Apple (3c:22:fb).

    #[test]
    fn dossier_personnel_sous_toutes_ses_ecritures() {
        // Le compte « a » ne coupe pas le dossier d'« alice », un autre compte.
        let maisons = [r"C:\Users\a".to_string()];
        let t = anonymiser_avec(
            r"C:/Users/a/a.ps1 ; c:\users\A\b.txt ; C:\\Users\\a\\c.json ; C:\Users\alice",
            &maisons,
            &[],
        );
        assert_eq!(t, r"~/a.ps1 ; ~\b.txt ; ~\\c.json ; C:\Users\<compte>");
    }

    #[test]
    fn noms_retires_a_la_casse_pres_et_en_mots_entiers() {
        let noms = [
            ("tablette de Zoé".to_string(), "<appareil>"),
            ("Chez Max".to_string(), "<réseau>"),
            ("DESKTOP-AB12CD".to_string(), "<machine>"),
        ];
        let t = anonymiser_avec(
            "TABLETTE DE ZOÉ injoignable, Chez Max, desktop-ab12cd ; Chez Maxime reste",
            &[],
            &noms,
        );
        assert_eq!(t, "<appareil> injoignable, <réseau>, <machine> ; Chez Maxime reste");
    }

    #[test]
    fn noms_generiques_gardes() {
        assert!(generique("imprimante HP") && generique("Salon") && generique("_gateway"));
        assert!(!generique("iPhone-de-Zoé") && !generique("Chez Max") && !generique(""));
    }

    #[test]
    fn dossiers_des_autres_comptes() {
        let t = anonyme(
            r"C:\Users\Jean Dupont\Documents\x.ps1 | C:\Users\Public\Desktop | /home/bob/.config | /run/media/bob/VANGUARD | /Users/Shared/a | %USERPROFILE%\x | C:\Users\Zoé est introuvable",
        );
        assert_eq!(
            t,
            r"C:\Users\<compte>\Documents\x.ps1 | C:\Users\Public\Desktop | /home/<compte>/.config | /run/media/<compte>/VANGUARD | /Users/Shared/a | %USERPROFILE%\x | C:\Users\<compte> est introuvable"
        );
        // Une apostrophe dans le nom, ou qui ferme la chaîne d'un script.
        assert_eq!(
            anonyme(r"C:\Users\Zoé d'Alice\Desktop et 'C:\Users\bob' -Force"),
            r"C:\Users\<compte>\Desktop et 'C:\Users\<compte>' -Force"
        );
    }

    fn anonyme(texte: &str) -> String {
        anonymiser_avec(texte, &[], &[])
    }

    #[test]
    fn courriels() {
        assert_eq!(
            anonyme("alice@example.com, jean+test@exemple.ca. git@github.com:alice/x"),
            "<courriel>, <courriel>. <courriel>:alice/x"
        );
        assert_eq!(
            anonyme("<utilisateur>@<machine> et 1@2"),
            "<utilisateur>@<machine> et 1@2"
        );
    }

    #[test]
    fn adresses_mac() {
        let t = masquer_mac(
            "box 3c:22:fb:12:34:56 puis 3c:22:fb:12:34:56, Windows 3C-22-FB-65-43-21, arp 3c:22:fb:1:2:3, heure 12:34:56, sept aa:bb:cc:dd:ee:ff:00",
        );
        let mots: Vec<&str> = t.split(' ').map(|m| m.trim_end_matches(',')).collect();
        assert!(
            mots[1].starts_with("3c:22:fb:") && mots[1] != "3c:22:fb:12:34:56",
            "{t}"
        );
        assert_eq!(mots[1], mots[3], "la même adresse, le même remplaçant : {t}");
        assert!(
            mots[5].starts_with("3C-22-FB-") && !mots[5].ends_with("65-43-21"),
            "{t}"
        );
        assert!(mots[7].starts_with("3c:22:fb:") && mots[7].len() == 17, "{t}");
        assert!(t.ends_with("heure 12:34:56, sept aa:bb:cc:dd:ee:ff:00"), "{t}");
        // Adresse aléatoire (bit « local ») : inventée en entier, sorte gardée.
        let aleatoire = masquer_mac("da:a1:19:12:34:56");
        assert_eq!(
            u8::from_str_radix(&aleatoire[..2], 16).unwrap() & 0x03,
            0x02,
            "{aleatoire}"
        );
        assert_ne!(aleatoire, "da:a1:19:12:34:56");
    }

    #[test]
    fn adresses_ipv4() {
        let t = masquer_ipv4(
            "box 192.168.1.1, maison 81.12.34.56 et 81.12.34.56/24, DNS 1.1.1.1 8.8.8.8, Windows 10.0.26200.9711, 5.1.2.3.4, v2.0.0.1",
        );
        assert!(t.starts_with("box 192.168.1.1, maison 203.0.113."), "{t}");
        assert!(!t.contains("81.12.34.56"), "{t}");
        assert!(
            t.ends_with("/24, DNS 1.1.1.1 8.8.8.8, Windows 10.0.26200.9711, 5.1.2.3.4, v2.0.0.1"),
            "{t}"
        );
        let remplacants: Vec<&str> = t.split([' ', '/']).filter(|m| m.starts_with("203.0.113.")).collect();
        assert_eq!(remplacants, [remplacants[0]; 2], "{t}");
    }

    #[test]
    fn adresses_ipv6() {
        let t = masquer_ipv6(
            "maison 2a01:e0a:2b3:4c50:1234:5678:9abc:def0, local fd12:3456:789a::1, lien fe80::3e22:fbff:fe12:3456%eth0, communes ::1 fe80::1 2606:4700:4700::1111 2001:db8::5, heure 12:34:56",
        );
        assert!(t.starts_with("maison 2001:db8::"), "{t}");
        assert!(
            t.contains(", local fd00::") && t.contains(", lien fe80::") && t.contains("%eth0"),
            "{t}"
        );
        assert!(
            !t.contains("2a01:e0a") && !t.contains("3456:789a") && !t.contains("fe12:3456"),
            "{t}"
        );
        assert!(
            t.ends_with("communes ::1 fe80::1 2606:4700:4700::1111 2001:db8::5, heure 12:34:56"),
            "{t}"
        );
    }

    #[test]
    fn sid_de_windows() {
        // SID d'exemple de la documentation de Microsoft.
        assert_eq!(
            masquer_sid("S-1-5-21-1004336348-1177238915-682003330-1001 et S-1-5-18, S-1-5-21-12-34"),
            "S-1-5-21-0-0-0-1001 et S-1-5-18, S-1-5-21-12-34"
        );
    }

    #[test]
    fn numeros_de_serie_et_wifi() {
        assert_eq!(
            masquer_ligne("Serial Number:    S4EVNX0N123456A\n"),
            "Serial Number:    <numéro>\n"
        );
        assert_eq!(
            masquer_ligne("SerialNumber : 0000_0000_0100_0000_E4D2."),
            "SerialNumber : <numéro>"
        );
        assert_eq!(
            masquer_ligne(r#"  "serial_number": "XYZ-123","#),
            r#"  "serial_number": "<numéro>","#
        );
        assert_eq!(
            masquer_ligne(r#"    "IOPlatformUUID" = "12345678-90AB-CDEF-1234-567890ABCDEF""#),
            r#"    "IOPlatformUUID" = "<numéro>""#
        );
        assert_eq!(masquer_ligne("    SSID 1 : Chez Max\n"), "    SSID 1 : <wifi>\n");
        assert_eq!(
            masquer_ligne("Profil Tous les utilisateurs : Chez Max"),
            "Profil Tous les utilisateurs : <wifi>"
        );
        assert_eq!(
            masquer_ligne("    BSSID 1 : 3c:22:fb:12:34:56"),
            "    BSSID 1 : 3c:22:fb:12:34:56"
        );
        assert_eq!(
            masquer_ligne("Wi-Fi : « Chez Max » illisible, “Chez Max” aussi"),
            "Wi-Fi : « <wifi> » illisible, “<wifi>” aussi"
        );
        assert_eq!(masquer_ligne("Certificat « Chez Max »"), "Certificat « Chez Max »");
    }

    #[test]
    fn noms_du_reseau_local() {
        assert_eq!(
            masquer_noms_locaux("iPhone-de-Zoé.local ne répond pas, nas.lan. ~/.local/share 192.168.1.5 hp.home.arpa"),
            "<appareil>.local ne répond pas, <appareil>.lan. ~/.local/share 192.168.1.5 <appareil>.home.arpa"
        );
    }

    #[test]
    fn surnom_de_la_commande() {
        let args = |a: &str| a.split(' ').map(String::from).collect::<Vec<_>>();
        assert_eq!(
            commande_anonyme(&args("nommer 192.168.1.20 tablette de Zoé")),
            "nommer 192.168.1.20 <surnom>"
        );
        assert_eq!(commande_anonyme(&args("nommer 192.168.1.20")), "nommer 192.168.1.20");
        assert_eq!(
            commande_anonyme(&args("reseau 192.168.1.0/24")),
            "reseau 192.168.1.0/24"
        );
    }

    #[cfg(unix)]
    #[test]
    fn argument_qui_n_est_pas_de_l_utf8() {
        use std::os::unix::ffi::OsStringExt;
        let args = [
            std::ffi::OsString::from("verifier-fichier"),
            std::ffi::OsString::from_vec(b"a\xff".to_vec()),
        ];
        assert_eq!(arguments_lisibles(args), ["verifier-fichier", "a\u{fffd}"]);
    }

    #[test]
    fn erreur_de_powershell_d_un_autre_ordinateur() {
        let erreur = "Get-NetAdapter : accès refusé (C:\\Users\\bob\\AppData\\Local\\Temp\\g.ps1)\n  MacAddress : 3C-22-FB-12-34-56\n  IPv4 : 81.12.34.56, passerelle 192.168.1.1\n  compte S-1-5-21-1004336348-1177238915-682003330-1001, courriel bob@exemple.ca";
        let t = anonyme(erreur);
        for reste in ["bob", "12-34-56", "81.12.34.56", "1004336348"] {
            assert!(!t.contains(reste), "{reste} : {t}");
        }
        assert!(
            t.contains("3C-22-FB-") && t.contains("192.168.1.1") && t.contains("S-1-5-21-0-0-0-1001"),
            "{t}"
        );
    }
}

//! La liste fermée des envois : tout ce que Vanguard peut joindre sur Internet est écrit dans MODELE-DE-MENACE.md
//! (« Ce qui sort de l'ordinateur ») et dans sa traduction, et rien d'autre. Trois portes :
//! - le HTTPS passe par `http.rs`, qui refuse tout hôte hors de `HOTES` ; ici, `HOTES` et la page sont comparées ;
//! - les prises réseau ouvertes à la main (DNS, STUN, sondes) : les fichiers qui en ouvrent forment une liste fermée,
//!   chacun avec ses destinations d'Internet écrites en dur ;
//! - les adresses `https://` écrites dans le code : chacune est jointe (dans `HOTES`), seulement montrée, ou laissée
//!   à un programme externe que la page nomme.
//!
//! Un nouvel envoi fait échouer un test qui dit dans quelle liste l'écrire, et la page avec.

use std::collections::BTreeSet;
use std::path::Path;

/// Les fichiers (hors tests) qui ouvrent une prise réseau, résolvent un nom ou appellent une fonction qui en ouvre une
/// vers une destination qu'ils choisissent, avec leurs destinations d'Internet écrites en dur (en adresse ou en nom).
/// Une destination du réseau local, ou reçue de l'appelant, n'est pas écrite ici.
const PRISES: &[(&str, &[&str], &str)] = &[
    (
        "dns_rapide.rs",
        &[
            "1.1.1.1",
            "1.0.0.1",
            "2606:4700:4700::1111",
            "2606:4700:4700::1001",
            "9.9.9.9",
            "149.112.112.112",
            "2620:fe::fe",
            "2620:fe::9",
            "8.8.8.8",
            "8.8.4.4",
            "2001:4860:4860::8888",
            "2001:4860:4860::8844",
            "94.140.14.14",
            "94.140.15.15",
            "2a10:50c0::ad1:ff",
            "2a10:50c0::ad2:ff",
            "149.112.121.20",
            "149.112.122.20",
            "2620:10a:80bb::20",
            "2620:10a:80bc::20",
            "www.amazon.com",
            "www.apple.com",
            "www.google.com",
            "www.microsoft.com",
            "www.wikipedia.org",
            "www.youtube.com",
        ],
        "DNS le plus rapide : des noms courants demandés au DNS actuel et à cinq DNS publics",
    ),
    (
        "audit/dns_tls.rs",
        &[
            "1.1.1.1",
            "1.0.0.1",
            "9.9.9.9",
            "149.112.112.112",
            "8.8.8.8",
            "8.8.4.4",
            "one.one.one.one",
            "dns.google",
            "dns.quad9.net",
            "internetsociety.org",
            "dnssec-failed.org",
        ],
        "audit DNS et TLS : résolveurs publics de référence, noms de test DNSSEC, sonde post-quantique vers 1.1.1.1",
    ),
    (
        "depanner/reseau.rs",
        &["1.1.1.1", "9.9.9.9", "8.8.8.8", "www.google.com", "www.wikipedia.org"],
        "« Pas d'Internet » : trois serveurs joignables ? deux noms traduits en adresses ?",
    ),
    (
        "reseau/nat.rs",
        &["stun.cloudflare.com", "stun.l.google.com", "stun1.l.google.com"],
        "type de NAT : deux opérateurs STUN disent l'adresse et le port qu'ils voient",
    ),
    (
        "reseau/connexion.rs",
        &["1.1.1.1"],
        "qualité de la connexion : temps d'établissement d'une connexion TCP",
    ),
    (
        "reseau/listes_noires.rs",
        &[
            "zen.spamhaus.org",
            "bl.spamcop.net",
            "dnsbl.dronebl.org",
            "psbl.surriel.com",
        ],
        "listes noires d'adresses, interrogées par le DNS du système",
    ),
    (
        "protection/lien.rs",
        &["dbl.spamhaus.org", "dbltest.com", "multi.surbl.org", "test.surbl.org"],
        "listes noires de domaines (par listes_noires::resoudre), et leur nom de test",
    ),
    (
        "reseau/wifi_public/portail.rs",
        &["www.example.com"],
        "Wi-Fi public : les noms se résolvent-ils ?",
    ),
    (
        "machine/dns.rs",
        &[],
        "le DNS invente-t-il des réponses ? un nom tiré au hasard sous .com",
    ),
    (
        "audit/dns_client.rs",
        &[],
        "client DNS : le serveur vient de l'appelant",
    ),
    (
        "audit/tls_pq.rs",
        &[],
        "sonde post-quantique : l'adresse vient de l'appelant",
    ),
    (
        "audit/ssh_kex.rs",
        &[],
        "sonde SSH : la box, adresse reçue de l'appelant",
    ),
    ("audit/http_local.rs", &[], "réseau local seulement (refuse Internet)"),
    ("audit/igd.rs", &[], "UPnP de la box, réseau local"),
    (
        "depanner/imprimante.rs",
        &[],
        "imprimantes du réseau local, nommées par CUPS",
    ),
    ("reseau/cameras.rs", &[], "caméras du réseau local"),
    ("reseau/empoisonnement.rs", &[], "LLMNR et mDNS, réseau local"),
    ("reseau/scan.rs", &[], "balayage du réseau local"),
    (
        "reseau/ping.rs",
        &[],
        "écho ICMP vers une adresse reçue de l'appelant (la box)",
    ),
    (
        "machine/windows/routes.rs",
        &[],
        "écho ICMP (IcmpSendEcho) vers une adresse reçue de l'appelant (la box)",
    ),
    (
        "protection/sortantes.rs",
        &[],
        "noms inverses des adresses distantes des connexions en cours, demandés au DNS du système",
    ),
    (
        "machine/linux/ecoute.rs",
        &[],
        "netlink : prises en écoute, lues dans le noyau",
    ),
    ("machine/linux/netlink.rs", &[], "netlink : le noyau seulement"),
    ("machine/linux/veilleur.rs", &[], "netlink : le noyau seulement"),
    ("machine/wifi/nl80211.rs", &[], "netlink : le Wi-Fi, lu dans le noyau"),
];

/// Ce qui marque une prise réseau ou une fonction qui en ouvre une vers la destination qu'on lui donne.
const MARQUES_DE_PRISE: &[&str] = &[
    "TcpStream",
    "UdpSocket",
    "TcpListener",
    "ToSocketAddrs",
    "to_socket_addrs",
    "lookup_host",
    "dns_client::interroger",
    "tls_pq::sonder",
    "ssh_kex::kexinit",
    "listes_noires::resoudre",
    // Prises du système, crates réseau et clients HTTP : seul http.rs a le droit de parler HTTPS.
    "libc::socket",
    "libc::connect",
    "libc::sendto",
    "socket2",
    "TcpSocket",
    "dns_lookup::",
    "reqwest::",
    "rustls::",
    "hyper::",
    "IcmpSendEcho",
    "WinHttpOpen",
    "InternetOpen",
    "URLDownloadToFile",
];

/// Ce qui ressemble à une destination dans un fichier de `PRISES` sans en être une.
const PAS_DES_DESTINATIONS: &[(&str, &str, &str)] = &[
    (
        "audit/dns_tls.rs",
        "ssl.com",
        "nom d'une autorité de certification, comparé au certificat",
    ),
    ("audit/dns_tls.rs", "network.trr.mode", "réglage de Firefox, lu"),
    ("audit/dns_tls.rs", "org.gnome.system.proxy", "réglages de GNOME, lus"),
    ("reseau/listes_noires.rs", "dnsbl.dronebl", "début de zone, comparé"),
    (
        "reseau/ping.rs",
        "8.0.0.0",
        "en-tête ICMP (type 8, écho), pas une adresse",
    ),
    (
        "machine/dns.rs",
        "8.8.8.8",
        "DNS configuré reconnu par son adresse, comparé",
    ),
    (
        "machine/dns.rs",
        "8.8.4.4",
        "DNS configuré reconnu par son adresse, comparé",
    ),
];

/// Les tables de noms d'un fichier de `PRISES` comparées à un nom reçu, jamais jointes : ôtées avant la recherche des
/// destinations (de `const NOM` au `;` qui finit la ligne).
const TABLES_COMPAREES: &[(&str, &str, &str)] = &[
    (
        "protection/lien.rs",
        "TABLE_DES_MARQUES",
        "domaines des marques, comparés au lien examiné",
    ),
    (
        "protection/lien.rs",
        "RACCOURCISSEURS",
        "raccourcisseurs de liens, comparés",
    ),
    ("protection/lien.rs", "HEBERGEURS", "hébergeurs partagés, comparés"),
    (
        "protection/lien.rs",
        "SUFFIXES_DOUBLES",
        "suffixes comme co.uk, comparés",
    ),
];

/// `code` sans les tables de `TABLES_COMPAREES` de `fichier`.
fn sans_tables(fichier: &str, code: &str) -> String {
    let mut code = code.to_string();
    for (_, nom, _) in TABLES_COMPAREES.iter().filter(|(f, _, _)| *f == fichier) {
        let debut = code
            .find(&format!("const {nom}:"))
            .unwrap_or_else(|| panic!("{fichier} : table {nom} introuvable"));
        let fin = debut + code[debut..].find(";\n").map_or(code.len() - debut, |f| f + 1);
        code.replace_range(debut..fin, "");
    }
    code
}

/// Les hôtes écrits dans une adresse `http(s)://` du code sans être joints par Vanguard.
const MONTRES: &[(&str, &str)] = &[
    ("attack.mitre.org", "page d'une technique, montrée"),
    ("auth.abuse.ch", "où créer sa clé, montré"),
    (
        "bughunters.google.com",
        "Signaler : page ouverte dans le navigateur après accord",
    ),
    (
        "bugzilla.mozilla.org",
        "Signaler : page ouverte dans le navigateur après accord",
    ),
    (
        "captive.apple.com",
        "portail du Wi-Fi public, ouvert dans le navigateur après accord",
    ),
    ("cert.cyber.gouv.fr", "Signaler : source citée"),
    ("chromium.googlesource.com", "Signaler : source citée"),
    (
        "club.ssi.gouv.fr",
        "Signaler : page ouverte dans le navigateur après accord",
    ),
    ("devblogs.microsoft.com", "source citée par une règle"),
    (
        "docs.github.com",
        "Signaler : page ouverte dans le navigateur après accord",
    ),
    ("echap.eu.org", "aide aux victimes, montrée"),
    ("exemple.invalid", "exemple dans un texte"),
    ("ifconfig.me", "commande du guide, tapée par la personne"),
    (
        "issues.chromium.org",
        "Signaler : page ouverte dans le navigateur après accord",
    ),
    ("learn.microsoft.com", "documentation citée"),
    (
        "localhost",
        "page de CUPS sur cet ordinateur, ouverte dans le navigateur",
    ),
    (
        "msrc.microsoft.com",
        "Signaler : page ouverte dans le navigateur après accord",
    ),
    ("officecdn.microsoft.com", "identifiant de canal d'Office, comparé"),
    ("rpmfusion.org", "commande du guide, tapée par la personne"),
    (
        "safebrowsing.google.com",
        "Signaler : page ouverte dans le navigateur après accord",
    ),
    ("schemas.xmlsoap.org", "espace de noms XML, jamais téléchargé"),
    (
        "security.apple.com",
        "Signaler : page ouverte dans le navigateur après accord",
    ),
    ("support.apple.com", "Signaler : source citée"),
    ("trivy.dev", "site d'un outil, montré"),
    ("wiki.mozilla.org", "Signaler : source citée"),
    ("www.amd.com", "page des pilotes, montrée"),
    ("www.apple.com", "DTD d'un fichier plist, jamais téléchargée"),
    (
        "www.cyber.gc.ca",
        "Signaler : page ouverte dans le navigateur après accord",
    ),
    ("www.debian.org", "documentation citée"),
    ("www.intel.com", "page des pilotes, montrée"),
    (
        "www.kb.cert.org",
        "Signaler : page ouverte dans le navigateur après accord",
    ),
    (
        "www.microsoft.com",
        "Signaler : page ouverte dans le navigateur après accord",
    ),
    (
        "www.msftconnecttest.com",
        "portail du Wi-Fi public, ouvert dans le navigateur après accord",
    ),
    ("www.nvidia.com", "page des pilotes, montrée"),
    ("www.onvif.org", "espace de noms XML, jamais téléchargé"),
    ("www.w3.org", "espace de noms XML, jamais téléchargé"),
];

/// Les hôtes d'une adresse du code joints par un programme externe que Vanguard lance sur un geste de la personne :
/// la page les nomme, sans que `http.rs` les ferme.
const EXTERNES: &[(&str, &str)] = &[
    ("brew.sh", "Homebrew, montré et installé après accord"),
    (
        "dl.flathub.org",
        "flatpak, dépôt Flathub ajouté avant une installation acceptée",
    ),
];

/// Les sources de src/ hors tests, par chemin relatif : (chemin, code sans le module de tests ni les commentaires).
fn sources() -> Vec<(String, String)> {
    fn parcourir(base: &Path, dossier: &Path, sortie: &mut Vec<(String, String)>) {
        let mut entrees: Vec<_> = std::fs::read_dir(dossier)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        entrees.sort();
        for chemin in entrees {
            let nom = chemin.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            if chemin.is_dir() {
                if nom != "tests" {
                    parcourir(base, &chemin, sortie);
                }
            // Ce fichier-ci, tout entier de tests, écrit des exemples d'adresses.
            } else if chemin.extension().is_some_and(|e| e == "rs")
                && nom != "tests.rs"
                && chemin != base.join("http/envois.rs")
            {
                let texte = std::fs::read_to_string(&chemin).unwrap();
                let code = sans_tests(&texte);
                let code: Vec<&str> = code.lines().filter(|l| !l.trim_start().starts_with("//")).collect();
                let relatif = chemin.strip_prefix(base).unwrap().to_string_lossy().replace('\\', "/");
                sortie.push((relatif, code.join("\n")));
            }
        }
    }
    let base = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
    let mut sortie = Vec::new();
    parcourir(base, base, &mut sortie);
    sortie
}

/// `texte` sans ses modules de tests écrits dans le fichier (`#[cfg(test)]` puis `mod x {` en tête de ligne, jusqu'à
/// la `}` seule en tête de ligne qui le ferme, rustfmt l'écrit ainsi) : le code d'après, même placé après un module
/// de tests, reste lu ; une déclaration `#[cfg(test)] mod x;` n'ôte rien.
fn sans_tests(texte: &str) -> String {
    let mut garde = Vec::new();
    let mut lignes = texte.lines().peekable();
    while let Some(ligne) = lignes.next() {
        if ligne == "#[cfg(test)]" && lignes.peek().is_some_and(|l| l.starts_with("mod ") && l.ends_with('{')) {
            for l in lignes.by_ref() {
                if l == "}" {
                    break;
                }
            }
        } else {
            garde.push(ligne);
        }
    }
    garde.join("\n")
}

/// Les hôtes que la page nomme dans les tableaux de « Ce qui sort de l'ordinateur » (première colonne, entre `…`),
/// et le texte entier de cette partie.
fn page(nom: &str, titre: &str) -> (BTreeSet<String>, String) {
    let texte = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(nom)).unwrap();
    let debut = texte
        .find(titre)
        .unwrap_or_else(|| panic!("{nom} : partie « {titre} » introuvable"));
    let partie = &texte[debut + titre.len()..];
    let partie = &partie[..partie.find("\n## ").unwrap_or(partie.len())];
    let mut hotes = BTreeSet::new();
    for ligne in partie.lines().filter(|l| l.starts_with('|')) {
        let colonne = ligne.split('|').nth(1).unwrap_or_default();
        for (i, morceau) in colonne.split('`').enumerate() {
            if i % 2 == 1 {
                hotes.insert(morceau.to_string());
            }
        }
    }
    (hotes, partie.to_string())
}

/// Les deux pages, française et anglaise.
fn pages() -> [(&'static str, BTreeSet<String>, String); 2] {
    let (fr, texte_fr) = page("MODELE-DE-MENACE.md", "## Ce qui sort de l'ordinateur");
    let (en, texte_en) = page("MODELE-DE-MENACE.en.md", "## What leaves the computer");
    [
        ("MODELE-DE-MENACE.md", fr, texte_fr),
        ("MODELE-DE-MENACE.en.md", en, texte_en),
    ]
}

/// Les hôtes des adresses `http://` et `https://` écrites dans `code`.
fn hotes_d_adresses(code: &str) -> Vec<String> {
    let mut hotes = Vec::new();
    for prefixe in ["http://", "https://"] {
        for (i, _) in code.match_indices(prefixe) {
            let reste = &code[i + prefixe.len()..];
            let fin = reste
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
                .unwrap_or(reste.len());
            if fin > 0 {
                hotes.push(reste[..fin].to_ascii_lowercase());
            }
        }
    }
    hotes
}

/// Un nom d'hôte écrit seul entre guillemets : des lettres, des chiffres, des tirets, au moins un point, et une
/// extension alphabétique qui n'est pas celle d'un fichier.
fn est_un_nom(texte: &str) -> bool {
    const FICHIERS: &[&str] = &[
        "conf", "csv", "dll", "exe", "js", "json", "log", "plist", "ps1", "rs", "service", "sh", "sys", "toml", "txt",
        "xml", "yaml", "yml", "zip",
    ];
    let Some((_, extension)) = texte.rsplit_once('.') else {
        return false;
    };
    texte
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
        && !texte.starts_with('.')
        && !texte.contains("..")
        && extension.len() >= 2
        && extension.chars().all(|c| c.is_ascii_lowercase())
        && !FICHIERS.contains(&extension)
}

/// Une adresse IP d'Internet (ni locale, ni réservée aux exemples, ni de groupe) écrite en texte.
fn est_une_adresse_publique(texte: &str) -> bool {
    match texte.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) => {
            let [x, y, _, _] = a.octets();
            !(a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_multicast()
                || a.is_broadcast()
                || a.is_unspecified()
                || a.is_documentation()
                || x == 0
                || (x == 100 && (64..128).contains(&y))
                || (x == 198 && (y == 18 || y == 19))
                || x >= 240)
        }
        Ok(std::net::IpAddr::V6(a)) => {
            let s = a.segments();
            !(a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8))
        }
        Err(_) => false,
    }
}

/// Les destinations d'Internet écrites dans `code` : noms et adresses seuls entre guillemets, adresses écrites
/// `Ipv4Addr::new(a, b, c, d)` ou `[a, b, c, d]`.
fn destinations_ecrites(code: &str) -> BTreeSet<String> {
    let mut trouvees = BTreeSet::new();
    let guillemets: Vec<usize> = code.match_indices('"').map(|(i, _)| i).collect();
    for paire in guillemets.windows(2) {
        // En minuscules seulement, comme tout nom d'hôte du code : « org.freedesktop.resolve1.Link » est un nom D-Bus.
        let texte = &code[paire[0] + 1..paire[1]];
        // « hôte:port » : l'hôte compte (une adresse IPv6 seule a plusieurs « : » et reste entière).
        let hote = match texte.rsplit_once(':') {
            Some((h, port)) if port.parse::<u16>().is_ok() && !h.contains(':') => h,
            _ => texte,
        };
        if est_un_nom(hote) || est_une_adresse_publique(hote) {
            trouvees.insert(hote.to_string());
        }
    }
    for (ouverture, fermeture) in [("Ipv4Addr::new(", ')'), ("[", ']')] {
        for (i, _) in code.match_indices(ouverture) {
            let reste = &code[i + ouverture.len()..];
            let Some(fin) = reste.find(fermeture) else { continue };
            let octets: Vec<&str> = reste[..fin].split(',').map(str::trim).collect();
            if octets.len() == 4 && octets.iter().all(|o| o.parse::<u8>().is_ok()) {
                let adresse = octets.join(".");
                if est_une_adresse_publique(&adresse) {
                    trouvees.insert(adresse);
                }
            }
        }
    }
    trouvees
}

/// `HOTES`, les destinations des prises et les deux pages : la même liste, dans les deux sens.
#[test]
fn chaque_envoi_est_dans_le_modele_de_menace() {
    let mut attendus: BTreeSet<String> = super::HOTES.iter().map(|h| (*h).to_string()).collect();
    for (_, destinations, _) in PRISES {
        attendus.extend(destinations.iter().map(|d| (*d).to_string()));
    }
    for (nom, hotes, texte) in pages() {
        let manquants: Vec<_> = attendus.difference(&hotes).collect();
        assert!(
            manquants.is_empty(),
            "{nom} : destinations jointes par Vanguard que les tableaux de « Ce qui sort de l'ordinateur » ne \
             nomment pas (une ligne, entre `…`, avec ce qui part) : {manquants:?}"
        );
        let en_trop: Vec<_> = hotes.difference(&attendus).collect();
        assert!(
            en_trop.is_empty(),
            "{nom} : la page nomme des destinations que Vanguard ne joint plus (ni http::HOTES, ni PRISES) : \
             {en_trop:?}"
        );
        for (hote, _) in EXTERNES {
            assert!(
                texte.contains(&format!("`{hote}`")),
                "{nom} : programme externe vers {hote} non nommé"
            );
        }
    }
}

/// Chaque `https://hôte` du code est joint (dans `HOTES`), seulement montré, ou laissé à un programme externe.
#[test]
fn adresses_du_code_en_liste_fermee() {
    let mut nouveaux = Vec::new();
    let mut vus = BTreeSet::new();
    for (fichier, code) in sources() {
        for hote in hotes_d_adresses(&code) {
            vus.insert(hote.clone());
            let connu = hote == "127.0.0.1"
                || super::HOTES.contains(&hote.as_str())
                || MONTRES.iter().chain(EXTERNES).any(|(h, _)| *h == hote);
            if !connu {
                nouveaux.push(format!("{fichier} : {hote}"));
            }
        }
    }
    assert!(
        nouveaux.is_empty(),
        "adresses d'hôtes inconnus dans le code : jointes par Vanguard → http::HOTES et MODELE-DE-MENACE.md ; \
         seulement montrées → MONTRES ; laissées à un programme externe → EXTERNES et la page :\n{}",
        nouveaux.join("\n")
    );
    let morts: Vec<_> = MONTRES
        .iter()
        .chain(EXTERNES)
        .filter(|(h, _)| !vus.contains(*h))
        .collect();
    assert!(morts.is_empty(), "hôtes listés que le code n'écrit plus : {morts:?}");
    let doubles: Vec<_> = MONTRES
        .iter()
        .chain(EXTERNES)
        .filter(|(h, _)| super::HOTES.contains(h))
        .collect();
    assert!(
        doubles.is_empty(),
        "hôtes joints ET dits seulement montrés : {doubles:?}"
    );
}

/// Les fichiers qui ouvrent une prise réseau sont ceux de `PRISES`, et chacun n'écrit que ses destinations.
#[test]
fn prises_reseau_en_liste_fermee() {
    let sources = sources();
    let avec_prise: BTreeSet<&str> = sources
        .iter()
        .filter(|(fichier, code)| fichier != "http.rs" && MARQUES_DE_PRISE.iter().any(|m| code.contains(m)))
        .map(|(fichier, _)| fichier.as_str())
        .collect();
    let listes: BTreeSet<&str> = PRISES.iter().map(|(f, _, _)| *f).collect();
    let nouveaux: Vec<_> = avec_prise.difference(&listes).collect();
    assert!(
        nouveaux.is_empty(),
        "fichiers qui ouvrent une prise réseau sans être dans PRISES (avec leurs destinations d'Internet, et la page) : \
         {nouveaux:?}"
    );
    let morts: Vec<_> = listes.difference(&avec_prise).collect();
    assert!(
        morts.is_empty(),
        "fichiers de PRISES qui n'ouvrent plus de prise : {morts:?}"
    );
    for (fichier, destinations, _) in PRISES {
        let code = &sources.iter().find(|(f, _)| f == fichier).unwrap().1;
        let ecrites = destinations_ecrites(&sans_tables(fichier, code));
        let permises: BTreeSet<String> = destinations
            .iter()
            .map(|d| (*d).to_string())
            .chain(
                PAS_DES_DESTINATIONS
                    .iter()
                    .filter(|(f, _, _)| f == fichier)
                    .map(|(_, d, _)| (*d).to_string()),
            )
            .collect();
        let inconnues: Vec<_> = ecrites.difference(&permises).collect();
        assert!(
            inconnues.is_empty(),
            "{fichier} : destinations d'Internet écrites sans être dans PRISES (ni dans PAS_DES_DESTINATIONS) : \
             {inconnues:?}"
        );
        let absentes: Vec<_> = destinations.iter().filter(|d| !ecrites.contains(**d)).collect();
        assert!(
            absentes.is_empty(),
            "{fichier} : destinations de PRISES que le fichier n'écrit plus : {absentes:?}"
        );
    }
}

#[test]
fn destinations_reconnues() {
    let code = r#"const A: &str = "stun.example.org"; let b = "x.json"; let c = ("1.1.1.1", 53);
        let d = Ipv4Addr::new(9, 9, 9, 9); let e = [8, 8, 8, 8]; let f = "192.168.1.1"; let g = "203.0.113.7";
        let h = "Une phrase. Puis une autre"; let i = "2606:4700::1111"; let j = "fe80::1"; let k = [10, 0, 0, 1];
        let l = "dns.exemple.net:853"; let m = "org.freedesktop.Exemple";"#;
    let attendues: BTreeSet<String> = [
        "stun.example.org",
        "1.1.1.1",
        "9.9.9.9",
        "8.8.8.8",
        "2606:4700::1111",
        "dns.exemple.net",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(destinations_ecrites(code), attendues);
    assert_eq!(
        hotes_d_adresses("x(\"https://Api.Exemple.org/v1\"); y(\"http://127.0.0.1:8080/\")"),
        ["127.0.0.1", "api.exemple.org"]
    );
}

/// La garde de `http.rs` : hors de la liste, rien ne part, même vers un hôte qui ressemble à un permis.
#[test]
fn garde_de_http() {
    let permise = |a: &str| super::lire_permise(a).is_some();
    assert!(permise(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    ));
    assert!(permise("https://WWW.CISA.GOV/x"));
    assert!(permise("http://127.0.0.1:8080/"));
    for refusee in [
        "https://exemple.org/",
        "https://www.cisa.gov.exemple.org/",
        "https://www.cisa.gov@exemple.org/",
        // Un nom de compte avant l'hôte (écrit « nom:@ ») : refusé.
        "https://alice:@www.cisa.gov/",
        "https://www.cisa.gov:8443/",
        "http://www.cisa.gov/",
        "http://localhost:8080/",
        "ftp://www.cisa.gov/",
        "https://1.1.1.2/",
        "pas une adresse",
    ] {
        assert!(!permise(refusee), "{refusee}");
    }
    // Sur GitHub, seuls les dépôts lus par Vanguard.
    assert!(permise(
        "https://github.com/d9v3/vanguard-update/releases/latest/download/SHA256SUMS.txt"
    ));
    assert!(permise(
        "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml"
    ));
    for refusee in [
        "https://github.com/alice/fuite/releases/x",
        "https://raw.githubusercontent.com/alice/fuite/main/x",
        "https://github.com/d9v3/vanguard-update/releases/../../../alice/fuite",
        "https://github.com/d9v3/vanguard-update/releases/%2e%2e/%2e%2e/%2e%2e/alice/fuite",
        "https://codeload.github.com/alice/fuite/tar.gz/main",
    ] {
        assert!(!permise(refusee), "{refusee}");
    }
    // rdap.org seul, un seul saut, vers un nom de registre en HTTPS.
    let url = |a: &str| reqwest::Url::parse(a).unwrap();
    assert!(super::vers_un_registre(
        Some("rdap.org"),
        1,
        &url("https://rdap.verisign.com/com/v1/domain/x.com")
    ));
    for (depart, sauts, refusee) in [
        (Some("github.com"), 1, "https://rdap.verisign.com/"),
        (Some("rdap.org"), 2, "https://rdap.verisign.com/"),
        (Some("rdap.org"), 1, "http://rdap.verisign.com/"),
        (Some("rdap.org"), 1, "https://rdap.verisign.com:8443/"),
        (Some("rdap.org"), 1, "https://alice:@rdap.verisign.com/"),
        (Some("rdap.org"), 1, "https://203.0.113.7/"),
        (Some("rdap.org"), 1, "https://[2001:db8::1]/"),
    ] {
        assert!(
            !super::vers_un_registre(depart, sauts, &url(refusee)),
            "{depart:?} {sauts} {refusee}"
        );
    }
    assert!(
        super::envoyer(super::Demande::get(
            "https://exemple.org/",
            std::time::Duration::from_secs(1)
        ))
        .is_none()
    );
    assert_eq!(
        super::certificat_presente("https://exemple.org/", std::time::Duration::from_secs(1)).err(),
        Some(super::Refus::Reseau)
    );
}

/// La politique de redirection, avec le serveur local : un saut en clair ou vers un hôte hors liste n'est pas suivi,
/// la réponse de redirection est rendue telle quelle.
#[test]
fn redirections_hors_liste_arretees() {
    let (temoin, attente) =
        super::tests::serveur(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
    for vers in [
        temoin.clone(),
        "https://exemple.org/".to_string(),
        "https://www.cisa.gov.exemple.org/".to_string(),
    ] {
        let reponse =
            format!("HTTP/1.1 302 Found\r\nLocation: {vers}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let (adresse, _) = super::tests::serveur(Box::leak(reponse.into_bytes().into_boxed_slice()));
        let r = super::envoyer(super::Demande::get(&adresse, std::time::Duration::from_secs(5))).unwrap();
        assert_eq!(r.code, 302, "{vers}");
    }
    // Le témoin n'a jamais été joint : sa connexion attend encore.
    assert!(!attente.is_finished());
}

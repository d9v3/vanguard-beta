//! Ce lien est-il dangereux ? Un lien reçu (courriel, texto, message) examiné sans jamais l'ouvrir. D'abord sur
//! l'ordinateur seul : lettres d'un autre alphabet qui imitent les nôtres (punycode), sous-domaine trompeur
//! (« paypal.com.exemple.xyz »), marque imitée ou mal orthographiée, raccourcisseur, adresse IP brute, « @ » qui
//! cache le vrai site, extension de domaine prisée des arnaques. Puis, après accord, car le nom de domaine sort de
//! l'ordinateur (jamais le lien entier) : l'âge du domaine (RDAP), et les listes publiques de sites dangereux
//! (URLhaus, téléchargée sans rien dire de ce qu'on cherche ; Spamhaus DBL et SURBL, par le DNS). Une liste qui ne
//! répond pas, ou qui refuse le DNS utilisé, est dite : jamais « pas listé ». Le verdict reste prudent : aucun outil
//! ne peut dire qu'un lien est sûr.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use crate::reseau::listes_noires::resoudre;
use crate::risk::Niveau;
use crate::ui::*;

/// Un lien découpé. L'hôte est en minuscules, tel qu'écrit (punycode compris).
#[derive(Debug, Default, PartialEq, Eq)]
struct Lien {
    /// « https », « http », « javascript »… ; vide si le lien n'en a pas (« exemple.com/page »).
    schema: String,
    /// Ce qui précède « @ » : un faux nom de site, qu'on lit à la place du vrai.
    utilisateur: Option<String>,
    hote: String,
    port: Option<u16>,
    /// Chemin, requête et ancre.
    reste: String,
}

/// Ce qu'on a vu dans le lien, et sa gravité.
#[derive(Debug, PartialEq, Eq)]
struct Signe {
    niveau: Niveau,
    texte: String,
}

fn signe(niveau: Niveau, texte: impl Into<String>) -> Signe {
    Signe {
        niveau,
        texte: texte.into(),
    }
}

/// Une marque souvent imitée : ses mots dans un nom de domaine, et ses vrais domaines (le premier est celui qu'on
/// conseille).
struct Marque {
    nom: &'static str,
    mots: Vec<&'static str>,
    domaines: Vec<&'static str>,
}

/// Les marques souvent imitées, une par ligne : nom | mots de ses noms de domaine | ses vrais domaines.
const TABLE_DES_MARQUES: &str = "\
PayPal | paypal | paypal.com paypal.me paypal.ca paypal.fr
Apple | apple icloud appleid itunes | apple.com icloud.com me.com itunes.com apple.ca
Microsoft | microsoft outlook office365 onedrive hotmail sharepoint microsoftonline | microsoft.com live.com \
    outlook.com office.com office365.com onedrive.com hotmail.com microsoftonline.com sharepoint.com windows.com \
    msn.com skype.com bing.com xbox.com
Google | google gmail youtube | google.com google.ca google.fr gmail.com youtube.com youtu.be googleapis.com \
    gstatic.com
Meta | facebook instagram whatsapp messenger | facebook.com fb.com instagram.com whatsapp.com messenger.com \
    meta.com wa.me facebookmail.com
Amazon | amazon | amazon.com amazon.ca amazon.fr amazon.co.uk amazon.de amzn.to amazonaws.com
Netflix | netflix | netflix.com
Steam | steam steampowered steamcommunity | steampowered.com steamcommunity.com steamstatic.com \
    valvesoftware.com
Epic Games | epicgames fortnite | epicgames.com fortnite.com unrealengine.com
Discord | discord discordapp | discord.com discord.gg discordapp.com discordapp.net discord.media
Roblox | roblox | roblox.com
PlayStation | playstation | playstation.com sony.com
Nintendo | nintendo | nintendo.com nintendo.net
Spotify | spotify | spotify.com
Twitch | twitch | twitch.tv
eBay | ebay | ebay.com ebay.ca ebay.fr
LinkedIn | linkedin | linkedin.com lnkd.in
Dropbox | dropbox | dropbox.com
DocuSign | docusign | docusign.com docusign.net
Adobe | adobe | adobe.com
Airbnb | airbnb | airbnb.com airbnb.ca airbnb.fr
Telegram | telegram | telegram.org t.me
DHL | dhl | dhl.com dhl.ca dhl.fr dhl.de
FedEx | fedex | fedex.com
UPS | ups | ups.com
Postes Canada | postescanada canadapost | canadapost.ca postescanada.ca canadapost-postescanada.ca
La Poste | laposte colissimo chronopost | laposte.fr laposte.net colissimo.fr chronopost.fr
Desjardins | desjardins | desjardins.com
Banque Nationale | bnc banquenationale | bnc.ca nbc.ca
RBC | rbc rbcroyalbank | rbc.com rbcroyalbank.com
BMO | bmo | bmo.com
TD | td tdbank tdcanadatrust | td.com tdbank.com tdcanadatrust.com
Scotiabank | scotiabank | scotiabank.com
Tangerine | tangerine | tangerine.ca
Interac | interac | interac.ca
Hydro-Québec | hydroquebec | hydroquebec.com
Revenu Québec | revenuquebec | revenuquebec.ca
SAAQ | saaq | saaq.gouv.qc.ca
Agence du revenu du Canada | cra craarc arccra | canada.ca gc.ca
Vidéotron | videotron | videotron.com
Rogers | rogers | rogers.com
Telus | telus | telus.com
Ameli | ameli | ameli.fr
Impôts (France) | impots dgfip | impots.gouv.fr
ANTAI | antai | antai.gouv.fr
La Banque Postale | labanquepostale | labanquepostale.fr
Crédit Agricole | creditagricole | credit-agricole.fr credit-agricole.com
Mastercard | mastercard | mastercard.com mastercard.ca
American Express | americanexpress amex | americanexpress.com
Binance | binance | binance.com
Coinbase | coinbase | coinbase.com
MetaMask | metamask | metamask.io";

fn marques() -> &'static [Marque] {
    static MARQUES: std::sync::LazyLock<Vec<Marque>> = std::sync::LazyLock::new(|| {
        TABLE_DES_MARQUES
            .lines()
            .filter_map(|l| {
                let mut champs = l.split('|').map(str::trim);
                Some(Marque {
                    nom: champs.next()?,
                    mots: champs.next()?.split_whitespace().collect(),
                    domaines: champs.next()?.split_whitespace().collect(),
                })
            })
            .collect()
    });
    &MARQUES
}

/// Mots qu'un faux site colle à une marque (« paypal-verification », « appleidlogin ») pour faire sérieux.
const MOTS_DE_PIEGE: &str = "\
login signin logon verify verification secure security account accounts update confirm support service services \
help auth wallet billing payment pay refund id online web app client clients compte connexion securite \
remboursement colis livraison delivery parcel tracking suivi gift free bonus promo";

/// Raccourcisseurs : on ne voit pas où mène le lien avant de l'ouvrir.
const RACCOURCISSEURS: &str = "\
bit.ly bitly.com tinyurl.com t.co goo.gl ow.ly is.gd v.gd buff.ly rebrand.ly cutt.ly shorturl.at tiny.cc rb.gy \
s.id t.ly bl.ink x.co qrco.de tr.im clck.ru u.to short.gy lnk.bio";

/// Hébergements gratuits où chacun crée son site en une minute : le vrai propriétaire est le sous-domaine. Comptés
/// comme suffixes publics, comme le fait la liste publique des suffixes (« evil.github.io » appartient à « evil »).
const HEBERGEURS: &str = "\
github.io gitlab.io blogspot.com wordpress.com wixsite.com weebly.com webflow.io netlify.app vercel.app \
pages.dev workers.dev web.app firebaseapp.com herokuapp.com glitch.me repl.co replit.app azurewebsites.net \
appspot.com 000webhostapp.com ngrok.io ngrok-free.app trycloudflare.com duckdns.org s3.amazonaws.com";

/// Suffixes publics à deux étiquettes les plus courants : le domaine de « shop.exemple.co.uk » est
/// « exemple.co.uk », pas « co.uk ». Une liste courte, pas la liste publique entière : un suffixe rare donne un
/// domaine trop court, ce qui rend l'analyse plus méfiante, jamais moins.
const SUFFIXES_DOUBLES: &[&str] = &[
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "com.au", "net.au", "org.au",
    "gov.au", "edu.au", "co.nz", "org.nz", "net.nz", "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "com.br", "net.br",
    "org.br", "gov.br", "com.mx", "org.mx", "gob.mx", "com.ar", "com.co", "com.pe", "co.za", "org.za", "com.cn",
    "net.cn", "org.cn", "gov.cn", "com.hk", "com.tw", "com.sg", "com.my", "com.ph", "com.vn", "co.th", "co.id",
    "co.in", "net.in", "org.in", "co.kr", "or.kr", "com.tr", "com.ua", "com.pl", "com.ru", "com.sa", "com.eg",
    "com.ng", "co.ke", "co.il", "org.il", "gouv.fr", "asso.fr", "qc.ca", "on.ca", "bc.ca", "ab.ca", "gc.ca",
];

/// Extensions de domaine très prisées des arnaques (rapports de Spamhaus et d'Interisle), et .zip et .mov, qu'on
/// prend pour des noms de fichiers. Pas une preuve à elle seule : des sites honnêtes en ont.
const EXTENSIONS_A_RISQUE: &[&str] = &[
    "zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "loan", "men", "rest", "cam",
    "icu", "bond", "sbs", "cfd", "quest", "lol", "buzz", "monster", "cyou", "fit", "support", "online", "site", "live",
    "shop", "store", "vip", "win", "date", "review",
];

/// Extensions de fichiers qui sont des programmes ou des installateurs.
const PROGRAMMES: &[&str] = &[
    "exe", "scr", "msi", "msix", "bat", "cmd", "com", "pif", "js", "jse", "vbs", "vbe", "wsf", "hta", "ps1", "jar",
    "apk", "dmg", "pkg", "app", "sh", "lnk", "iso", "img",
];

// ───────────────────────────── Découpage ─────────────────────────────

/// Le lien tel qu'on le colle, sans espaces ni guillemets autour, « désamorcé » remis en état : les alertes de
/// sécurité écrivent « hxxp://exemple[.]com » pour qu'on ne clique pas. Il vient d'un message reçu : ce qui piloterait
/// le terminal ou retournerait l'écriture devient « � » (`affichable`), visible dans tout ce qui en est montré.
fn nettoyer(entree: &str) -> String {
    let t = affichable(entree.trim())
        .trim_matches(['<', '>', '"', '\'', '`', '«', '»', ' ', '\u{a0}'])
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[dot]", ".")
        .replace("[:]", ":");
    match t.get(..4) {
        Some(debut) if debut.eq_ignore_ascii_case("hxxp") => format!("http{}", &t[4..]),
        _ => t,
    }
}

fn decouper(adresse: &str) -> Option<Lien> {
    // « https: », « javascript: », « mailto: »… ; pas « exemple.com:8080 » (un port n'est pas un schéma).
    let (schema, reste) = match adresse.split_once(':') {
        Some((s, r))
            if s.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                && s.chars().all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c))
                && !r.starts_with(|c: char| c.is_ascii_digit()) =>
        {
            (s.to_ascii_lowercase(), r)
        }
        _ => (String::new(), adresse),
    };
    if !matches!(schema.as_str(), "" | "http" | "https") {
        // javascript:, data:, file:… : pas de site, c'est le lien lui-même qui agit.
        return Some(Lien {
            schema,
            reste: reste.to_string(),
            ..Lien::default()
        });
    }
    let reste = reste.strip_prefix("//").unwrap_or(reste);
    let fin = reste.find(['/', '?', '#', '\\']).unwrap_or(reste.len());
    let (autorite, suite) = reste.split_at(fin);
    let (utilisateur, hote_port) = autorite
        .rsplit_once('@')
        .map_or((None, autorite), |(u, h)| (Some(u.to_string()), h));
    let (hote, port) = if let Some(r) = hote_port.strip_prefix('[') {
        let (h, apres) = r.split_once(']')?;
        (h, apres.strip_prefix(':').and_then(|p| p.parse().ok()))
    } else {
        match hote_port.rsplit_once(':') {
            Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => (h, p.parse().ok()),
            _ => (hote_port, None),
        }
    };
    let hote = hote.trim_end_matches('.').to_lowercase();
    // Un nom DNS fait au plus 253 octets : au-delà, ce n'est pas un site joignable, et l'examiner (chaque étiquette
    // pour chaque marque) coûterait des secondes par lien fabriqué pour ça.
    if hote.len() > 253 {
        return None;
    }
    // Un nom de site a au moins un point, ou c'est une adresse IP (parfois déguisée en un seul nombre) ; « bonjour »
    // n'est pas un lien.
    if hote.is_empty() || (!hote.contains('.') && !adresse_ip(&hote)) || hote.contains(char::is_whitespace) {
        return None;
    }
    Some(Lien {
        schema,
        utilisateur,
        hote,
        port,
        reste: suite.to_string(),
    })
}

/// Une adresse IP déguisée : un seul nombre (« 3232235777 ») ou des morceaux en hexadécimal (« 0x7f.0x0.0x0.0x1 »),
/// que les navigateurs comprennent comme une adresse.
fn ip_deguisee(hote: &str) -> bool {
    hote.parse::<IpAddr>().is_err()
        && hote.split('.').all(|e| {
            !e.is_empty()
                && (e.chars().all(|c| c.is_ascii_digit())
                    || e.strip_prefix("0x")
                        .is_some_and(|h| h.chars().all(|c| c.is_ascii_hexdigit())))
        })
}

/// L'hôte est-il une adresse IP, en clair ou déguisée ?
fn adresse_ip(hote: &str) -> bool {
    hote.parse::<IpAddr>().is_ok() || ip_deguisee(hote)
}

/// Ce qu'on vérifie en ligne : le domaine qu'on achète, ou l'adresse IP elle-même.
fn site(lien: &Lien) -> String {
    if adresse_ip(&lien.hote) {
        lien.hote.clone()
    } else {
        domaine_enregistrable(&lien.hote)
    }
}

/// Décode une étiquette punycode (« pple-43d », sans « xn-- ») : RFC 3492.
fn punycode(entree: &str) -> Option<String> {
    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    let (basique, code) = entree.rsplit_once('-').unwrap_or(("", entree));
    if !basique.is_ascii() {
        return None;
    }
    let mut sortie: Vec<char> = basique.chars().collect();
    // Les noms de la RFC : n (caractère), i (rang), k (palier), t (seuil).
    let (mut caractere, mut rang, mut biais) = (128_u32, 0_u32, 72_u32);
    let mut octets = code.bytes().peekable();
    while octets.peek().is_some() {
        let ancien = rang;
        let mut poids = 1_u32;
        let mut palier = BASE;
        loop {
            let octet = octets.next()?;
            let chiffre = u32::from(match octet {
                b'a'..=b'z' => octet - b'a',
                b'A'..=b'Z' => octet - b'A',
                b'0'..=b'9' => octet - b'0' + 26,
                _ => return None,
            });
            rang = rang.checked_add(chiffre.checked_mul(poids)?)?;
            let seuil = palier.saturating_sub(biais).clamp(TMIN, TMAX);
            if chiffre < seuil {
                break;
            }
            poids = poids.checked_mul(BASE - seuil)?;
            palier += BASE;
        }
        let nombre = u32::try_from(sortie.len()).ok()? + 1;
        biais = adapter(rang - ancien, nombre, ancien == 0);
        caractere = caractere.checked_add(rang / nombre)?;
        rang %= nombre;
        sortie.insert(usize::try_from(rang).ok()?, char::from_u32(caractere)?);
        rang += 1;
    }
    Some(sortie.into_iter().collect())
}

fn adapter(delta: u32, nombre: u32, premier: bool) -> u32 {
    let mut delta = if premier { delta / 700 } else { delta / 2 };
    delta += delta / nombre;
    let mut k = 0;
    while delta > ((36 - 1) * 26) / 2 {
        delta /= 36 - 1;
        k += 36;
    }
    k + (36 * delta) / (delta + 38)
}

/// L'hôte tel qu'un navigateur peut l'afficher : étiquettes punycode décodées. Le punycode code n'importe quel
/// caractère, bidi compris : le nom décodé est rendu `affichable`.
fn affiche(hote: &str) -> String {
    hote.split('.')
        .map(|l| {
            l.strip_prefix("xn--")
                .and_then(punycode)
                .map_or_else(|| l.to_string(), |n| affichable(&n))
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Le domaine qu'on achète (« exemple.co.uk » pour « shop.exemple.co.uk ») : le vrai propriétaire du site.
pub(crate) fn domaine_enregistrable(hote: &str) -> String {
    let hote = hote.trim_end_matches('.').to_lowercase();
    let etiquettes: Vec<&str> = hote.split('.').collect();
    let suffixe = SUFFIXES_DOUBLES
        .iter()
        .copied()
        .chain(HEBERGEURS.split_whitespace())
        .filter(|s| hote.ends_with(&format!(".{s}")))
        .map(|s| s.matches('.').count() + 1)
        .max()
        .unwrap_or(1);
    let garde = (suffixe + 1).min(etiquettes.len());
    etiquettes[etiquettes.len() - garde..].join(".")
}

/// La lettre latine qu'imite un caractère d'un autre alphabet (cyrillique, grec, arménien, latin rare ou accentué,
/// pleine chasse). `None` : ni une lettre latine, ni une imitation connue.
fn latine(c: char) -> Option<char> {
    if c.is_ascii_alphanumeric() || c == '-' {
        return Some(c);
    }
    // Pleine chasse : « ａ » à « ｚ ».
    if ('\u{ff41}'..='\u{ff5a}').contains(&c) {
        return char::from_u32(u32::from(c) - 0xff41 + u32::from(b'a'));
    }
    Some(match c {
        'а' | 'α' | 'ɑ' | 'à' | 'á' | 'â' | 'ä' | 'ã' | 'å' => 'a',
        'Ь' | 'ƅ' => 'b',
        'с' | 'ϲ' | 'ç' => 'c',
        'ԁ' => 'd',
        'е' | 'é' | 'è' | 'ê' | 'ë' | 'ё' => 'e',
        'ɡ' | 'ց' => 'g',
        'һ' => 'h',
        'і' | 'ι' | 'ı' | 'ɩ' | 'î' | 'ï' | 'í' | 'ì' => 'i',
        'ј' | 'ϳ' | 'ȷ' => 'j',
        'к' | 'κ' => 'k',
        'ӏ' | 'ǀ' | 'ℓ' => 'l',
        'ո' | 'ñ' => 'n',
        'о' | 'ο' | 'ö' | 'ô' | 'ó' | 'ò' | 'õ' | 'օ' => 'o',
        'р' | 'ρ' => 'p',
        'ԛ' => 'q',
        'ѕ' => 's',
        'ս' | 'υ' | 'ü' | 'û' | 'ú' | 'ù' => 'u',
        'ν' => 'v',
        'ԝ' | 'ω' => 'w',
        'х' | 'χ' => 'x',
        'у' | 'ý' | 'ÿ' => 'y',
        _ => return None,
    })
}

/// Alphabet d'une lettre, pour repérer un nom qui en mélange deux (le signe des lettres déguisées).
fn alphabet(c: char) -> &'static str {
    match u32::from(c) {
        0x30..=0x39 | 0x61..=0x7a | 0x41..=0x5a | 0xc0..=0x24f | 0xff41..=0xff5a => "latin",
        0x370..=0x3ff => "grec",
        0x400..=0x52f => "cyrillique",
        0x530..=0x58f => "arménien",
        _ => "autre",
    }
}

// ───────────────────────────── Ressemblances ─────────────────────────────

/// Un mot ramené à ce qu'on lit d'un coup d'œil : chiffres pris pour des lettres, « rn » pour « m », « vv » pour
/// « w », tirets retirés.
fn normaliser(mot: &str) -> String {
    mot.replace("rn", "m")
        .replace("vv", "w")
        .chars()
        .filter(|c| *c != '-')
        .map(|c| match c {
            '0' => 'o',
            '1' | '|' => 'l',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            '8' => 'b',
            '9' => 'g',
            c => c,
        })
        .collect()
}

/// Deux lettres qu'on confond facilement à l'écran.
fn confondues(a: char, b: char) -> bool {
    let paire = |x: char, y: char| (a == x && b == y) || (a == y && b == x);
    paire('l', 'i') || paire('n', 'm') || paire('u', 'v') || paire('c', 'e') || paire('g', 'q') || paire('o', 'c')
}

/// Une seule retouche d'un mot à l'autre : lettre confondue, deux lettres voisines échangées, lettre doublée ou
/// perdue (« gooogle », « paypall ») ; n'importe quelle lettre en trop ou en moins pour les mots longs.
fn une_retouche(a: &[char], b: &[char], long: bool) -> bool {
    if a.len() == b.len() {
        let ecarts: Vec<usize> = (0..a.len()).filter(|&i| a[i] != b[i]).collect();
        return match ecarts[..] {
            [i] => confondues(a[i], b[i]),
            [i, j] => j == i + 1 && a[i] == b[j] && a[j] == b[i],
            _ => false,
        };
    }
    if a.len().abs_diff(b.len()) != 1 {
        return false;
    }
    let (court, longue) = if a.len() < b.len() { (a, b) } else { (b, a) };
    let i = (0..court.len()).find(|&i| court[i] != longue[i]).unwrap_or(court.len());
    if court[i..] != longue[i + 1..] {
        return false;
    }
    long || (i > 0 && longue[i] == longue[i - 1]) || (i + 1 < longue.len() && longue[i] == longue[i + 1])
}

/// `mot` imite-t-il la marque `cle` sans l'être ? (« paypa1 », « arnazon », « micros0ft », « gooogle »). Les clés
/// courtes ne comptent qu'à l'identique après lecture rapide : « steam » ne doit pas attraper « stream ».
fn ressemble(mot: &str, cle: &str) -> bool {
    if mot == cle {
        return false;
    }
    let (m, c) = (normaliser(mot), normaliser(cle));
    if m == c {
        return true;
    }
    let (m, c): (Vec<char>, Vec<char>) = (m.chars().collect(), c.chars().collect());
    c.len() >= 6 && une_retouche(&m, &c, c.len() >= 8)
}

/// La marque dont parle une étiquette du nom (« paypal-secure », « appleidlogin », « secure-paypal »).
fn parle_de(etiquette: &str, cle: &str) -> bool {
    if etiquette.split('-').any(|m| m == cle) {
        return true;
    }
    let colle = etiquette.replace('-', "");
    let piege = |reste: &str| {
        !reste.is_empty()
            && (MOTS_DE_PIEGE.split_whitespace().any(|m| m == reste) || reste.chars().all(|c| c.is_ascii_digit()))
    };
    colle == cle || colle.strip_prefix(cle).is_some_and(piege) || colle.strip_suffix(cle).is_some_and(piege)
}

/// Le nom est-il un vrai domaine de la marque, ou l'un de ses sous-domaines ?
fn officiel(hote: &str, marque: &Marque) -> bool {
    marque
        .domaines
        .iter()
        .any(|d| hote == *d || hote.ends_with(&format!(".{d}")))
}

// ───────────────────────────── Examen sur l'ordinateur ─────────────────────────────

/// Tout ce qui se voit dans le lien lui-même, sans rien demander à personne.
fn examiner(lien: &Lien) -> Vec<Signe> {
    match lien.schema.as_str() {
        "javascript" | "vbscript" | "data" => {
            return vec![signe(
                Niveau::Critique,
                tr!(
                    "Ce lien n'ouvre pas un site : il exécute du code ou contient une page cachée.",
                    "This link does not open a site: it runs code or carries a hidden page."
                ),
            )];
        }
        "" | "http" | "https" => {}
        autre => {
            return vec![signe(
                Niveau::Eleve,
                trf!(
                    "Lien « {autre}: », pas une page web : il ouvre un fichier ou un programme.",
                    "“{autre}:” link, not a web page: it opens a file or a program."
                ),
            )];
        }
    }
    let mut signes = Vec::new();
    let hote = lien.hote.as_str();
    let domaine = domaine_enregistrable(hote);

    if let Some(faux) = &lien.utilisateur {
        signes.push(signe(
            Niveau::Eleve,
            trf!(
                "Un « @ » cache le vrai site : on lit « {faux} », mais le lien mène à {hote}.",
                "An “@” hides the real site: you read “{faux}”, but the link leads to {hote}."
            ),
        ));
    }

    // Adresse IP au lieu d'un nom, parfois déguisée en un seul nombre (« http://3232235777/ »).
    if let Ok(ip) = hote.parse::<IpAddr>() {
        // Cette machine ou le réseau de la maison seulement : le réseau partagé du fournisseur (100.64/10) n'en est
        // pas, ce sont les box d'autres abonnés, comme dans `reseau::nmap`.
        use crate::socle::adresses::{Portee, portee};
        let locale = matches!(portee(ip), Portee::Machine | Portee::Locale);
        signes.push(if locale {
            signe(
                Niveau::Info,
                tr!(
                    "Adresse d'un appareil de votre réseau (routeur, imprimante…), pas un site d'Internet.",
                    "Address of a device on your network (router, printer…), not an Internet site."
                ),
            )
        } else {
            signe(
                Niveau::Eleve,
                tr!(
                    "Adresse IP brute au lieu d'un nom : les vrais services ont un nom, les pièges souvent pas.",
                    "Raw IP address instead of a name: real services have a name, traps often do not."
                ),
            )
        });
    } else if ip_deguisee(hote) {
        signes.push(signe(
            Niveau::Eleve,
            tr!(
                "Adresse IP déguisée (en un seul nombre ou en hexadécimal) : une ruse pour cacher où mène le lien.",
                "Disguised IP address (one number or hexadecimal): a trick to hide where the link leads."
            ),
        ));
    } else {
        signes.extend(lettres_deguisees(hote));
        signes.extend(examiner_marques(hote, &domaine));
    }

    if lien.schema == "http" {
        // Une page de connexion ou de paiement sans chiffrement : plus grave qu'une simple page.
        let reste = lien.reste.to_lowercase();
        let piege = MOTS_DE_PIEGE
            .split_whitespace()
            .any(|m| m.len() > 4 && reste.contains(m));
        signes.push(signe(
            if piege { Niveau::Moyen } else { Niveau::Info },
            tr!(
                "Pas chiffré (http, sans « s ») : ce qu'on y tape peut être lu en route.",
                "Not encrypted (http, without “s”): what you type there can be read on the way."
            ),
        ));
    }
    if let Some(p) = lien.port.filter(|p| ![80, 443].contains(p)) {
        signes.push(signe(
            Niveau::Info,
            trf!(
                "Port {p} : inhabituel pour un site.",
                "Port {p}: unusual for a website."
            ),
        ));
    }
    // Le dernier morceau du chemin, sans requête ni ancre : un programme à télécharger ?
    let chemin = lien.reste.split(['?', '#']).next().unwrap_or("");
    if let Some(ext) = chemin
        .rsplit('/')
        .next()
        .and_then(|f| f.rsplit_once('.'))
        .map(|(_, e)| e.to_lowercase())
        .filter(|e| PROGRAMMES.contains(&e.as_str()))
    {
        signes.push(signe(
            Niveau::Moyen,
            trf!(
                "Il télécharge un fichier .{ext} : un programme ou un installateur. Ne le lancez pas s'il ne vient pas du site officiel.",
                "It downloads a .{ext} file: a program or an installer. Do not run it unless it comes from the official site."
            ),
        ));
    }
    if lien.reste.len() > 200 || lien.reste.matches('%').count() > 10 {
        signes.push(signe(
            Niveau::Info,
            tr!(
                "Lien très long ou rempli de caractères codés : souvent pour cacher sa vraie destination.",
                "Very long link or full of encoded characters: often to hide where it really goes."
            ),
        ));
    }
    signes
}

/// Lettres d'un autre alphabet : le nom tel qu'on le lit, ramené aux lettres latines qu'il imite.
fn lettres_deguisees(hote: &str) -> Option<Signe> {
    let lisible = affiche(hote);
    if lisible == hote && lisible.is_ascii() {
        return None;
    }
    let mut lu = String::new();
    let mut melange = false;
    let mut etranger = false;
    for etiquette in lisible.split('.') {
        let alphabets: std::collections::BTreeSet<&str> =
            etiquette.chars().filter(|c| *c != '-').map(alphabet).collect();
        melange |= alphabets.len() > 1;
        etranger |= alphabets.iter().any(|a| *a != "latin");
        if !lu.is_empty() {
            lu.push('.');
        }
        lu.extend(etiquette.chars().map(|c| latine(c).unwrap_or('?')));
    }
    Some(match marques().iter().find(|m| officiel(&lu, m)) {
        Some(m) => signe(
            Niveau::Critique,
            trf!(
                "Lettres déguisées : s'affiche « {lisible} », se lit comme {} de {}, mais n'en est pas un.",
                "Disguised letters: shows as “{lisible}”, reads like {} of {}, but is not.",
                domaine_enregistrable(&lu),
                m.nom
            ),
        ),
        None if melange => signe(
            Niveau::Eleve,
            trf!(
                "Lettres de deux alphabets mélangées dans « {lisible} » : la ruse des faux sites qui imitent un vrai nom.",
                "Letters from two alphabets mixed in “{lisible}”: the trick of fake sites imitating a real name."
            ),
        ),
        None if etranger => signe(
            Niveau::Info,
            trf!(
                "Nom écrit dans un autre alphabet : « {lisible} ».",
                "Name written in another alphabet: “{lisible}”."
            ),
        ),
        // Lettres accentuées seules (« québec.ca ») : un nom honnête, sauf s'il imite une marque.
        None => return None,
    })
}

/// Marque imitée, sous-domaine trompeur, raccourcisseur, hébergement gratuit, extension à risque.
fn examiner_marques(hote: &str, domaine: &str) -> Vec<Signe> {
    examiner_marques_de(hote, domaine, true)
}

/// `examiner_marques`, avec ou sans le « Domaine officiel de… » : ce texte parle d'un lien reçu, il serait faux pour
/// l'adresse d'un expéditeur.
fn examiner_marques_de(hote: &str, domaine: &str, dire_officiel: bool) -> Vec<Signe> {
    let mut signes = Vec::new();
    let etiquettes: Vec<&str> = hote.split('.').collect();
    let n_domaine = domaine.split('.').count();
    let sous_domaine = &etiquettes[..etiquettes.len().saturating_sub(n_domaine)];
    let principal = domaine.split('.').next().unwrap_or(domaine);
    let sous = sous_domaine.join(".");
    let mut marque_imitee = false;
    for marque in marques() {
        if officiel(hote, marque) {
            if !dire_officiel {
                continue;
            }
            signes.push(signe(
                Niveau::Info,
                trf!(
                    "Domaine officiel de {} : bon signe, mais un lien reçu peut quand même mener à une fausse page de connexion ailleurs.",
                    "Official {} domain: a good sign, but a link you received can still lead to a fake login page elsewhere.",
                    marque.nom
                ),
            ));
            continue;
        }
        let vrai = marque.domaines[0];
        // Sous-domaine trompeur : « paypal.com.exemple.xyz » commence par un vrai domaine.
        if marque
            .domaines
            .iter()
            .any(|d| sous == *d || sous.ends_with(&format!(".{d}")) || sous.starts_with(&format!("{d}.")))
        {
            signes.push(signe(
                Niveau::Critique,
                trf!(
                    "Sous-domaine trompeur : commence par un nom de {}, mais le site est {domaine} (le vrai : {vrai}).",
                    "Misleading subdomain: starts with a {} name, but the site is {domaine} (the real one: {vrai}).",
                    marque.nom
                ),
            ));
            marque_imitee = true;
            continue;
        }
        let mentionnee = etiquettes[..etiquettes.len().saturating_sub(1)]
            .iter()
            .any(|e| marque.mots.iter().any(|m| parle_de(e, m)));
        let imitee = marque.mots.iter().any(|m| ressemble(principal, m));
        if mentionnee || imitee {
            signes.push(signe(
                Niveau::Eleve,
                if imitee {
                    trf!(
                        "Ressemble à {} sans en être : « {principal} ». Le vrai site : {vrai}.",
                        "Looks like {} without being it: “{principal}”. The real site: {vrai}.",
                        marque.nom
                    )
                } else {
                    trf!(
                        "Utilise le nom de {} sans être un de ses sites (le vrai : {vrai}).",
                        "Uses the {} name without being one of its sites (the real one: {vrai}).",
                        marque.nom
                    )
                },
            ));
            marque_imitee = true;
        }
    }

    // Un « .com » ou un « .ca » au milieu : on croit lire la fin du nom.
    if !marque_imitee
        && sous_domaine
            .iter()
            .any(|e| ["com", "net", "org", "ca", "fr", "gouv", "gov"].contains(e))
    {
        signes.push(signe(
            Niveau::Moyen,
            trf!(
                "Le nom contient une fausse fin (« .com », « .ca »…) avant le vrai domaine, qui est {domaine}.",
                "The name contains a fake ending (“.com”, “.ca”…) before the real domain, which is {domaine}."
            ),
        ));
    }
    if sous_domaine.len() >= 4 {
        signes.push(signe(
            Niveau::Moyen,
            trf!(
                "Beaucoup de sous-domaines : le vrai site est seulement {domaine}.",
                "Many subdomains: the real site is only {domaine}."
            ),
        ));
    }
    if RACCOURCISSEURS.split_whitespace().any(|r| r == domaine) {
        signes.push(signe(
            Niveau::Moyen,
            tr!(
                "Raccourcisseur de liens : on ne voit pas où il mène avant de l'ouvrir. Ne l'ouvrez que si vous connaissez l'expéditeur.",
                "Link shortener: you cannot see where it leads before opening it. Only open it if you know the sender."
            ),
        ));
    }
    if let Some(h) = HEBERGEURS.split_whitespace().find(|h| hote.ends_with(&format!(".{h}"))) {
        signes.push(signe(
            if marque_imitee { Niveau::Eleve } else { Niveau::Info },
            trf!(
                "Site hébergé gratuitement ({h}) : n'importe qui en crée un en une minute, aucun service sérieux n'y demande votre mot de passe.",
                "Site on free hosting ({h}): anyone can create one in a minute; no serious service asks for your password there."
            ),
        ));
    }
    let extension = domaine.rsplit('.').next().unwrap_or("");
    if EXTENSIONS_A_RISQUE.contains(&extension) {
        signes.push(signe(
            Niveau::Moyen,
            trf!(
                "Extension .{extension}, très prisée des arnaques (pas une preuve à elle seule).",
                "“.{extension}” extension, very popular with scams (not proof on its own)."
            ),
        ));
    }
    signes
}

// ───────────────────────────── Vérifications en ligne ─────────────────────────────

/// Réponse d'une liste de sites dangereux.
#[derive(Debug, PartialEq)]
enum Inscription {
    /// Inscrit, avec la raison et sa gravité.
    Inscrit(String, Niveau),
    Absent,
    Impossible(String),
}

/// Cherche un domaine dans une liste par le DNS, après son entrée d'essai (toujours listée) : un DNS qui retire les
/// réponses de la liste (filtres, résolveur public refusé) rendrait « absent » mensonger.
fn chercher_dns(
    domaine: &str,
    zone: &str,
    essai: &str,
    refuse: impl Fn(&[Ipv4Addr]) -> bool,
    resoudre: impl Fn(&str) -> Option<Vec<Ipv4Addr>>,
) -> Result<Vec<Ipv4Addr>, String> {
    let muet = || tr!("votre DNS n'a pas répondu", "your DNS did not answer").to_string();
    let reponse = resoudre(&format!("{essai}.{zone}")).ok_or_else(muet)?;
    if reponse.is_empty() {
        return Err(tr!(
            "votre DNS ne transmet pas les réponses de cette liste",
            "your DNS does not pass this list's answers on"
        )
        .into());
    }
    if refuse(&reponse) {
        return Err(tr!(
            "la liste refuse votre DNS (résolveur public ou trop de demandes)",
            "the list refuses your DNS (public resolver or too many queries)"
        )
        .into());
    }
    let codes = resoudre(&format!("{domaine}.{zone}")).ok_or_else(muet)?;
    if refuse(&codes) {
        return Err(tr!("la liste a refusé la requête", "the list refused the query").into());
    }
    Ok(codes)
}

/// Spamhaus DBL : 127.0.1.x, la raison dans le dernier nombre ; 127.255.255.x et 127.0.1.255, des refus.
fn refus_dbl(codes: &[Ipv4Addr]) -> bool {
    codes
        .iter()
        .any(|c| c.octets()[..3] == [127, 255, 255] || *c == Ipv4Addr::new(127, 0, 1, 255))
}

fn sens_dbl(codes: &[Ipv4Addr]) -> Inscription {
    let pire = codes
        .iter()
        .filter_map(|c| {
            let [a, b, x, y] = c.octets();
            (a == 127 && b == 0 && x == 1).then_some(y)
        })
        .map(|y| match y {
            4 | 104 => (Niveau::Critique, tr!("hameçonnage", "phishing")),
            5 | 105 => (Niveau::Critique, tr!("logiciels malveillants", "malware")),
            6 | 106 => (Niveau::Critique, tr!("réseau de zombies (botnet)", "botnet")),
            103 => (Niveau::Eleve, tr!("redirection détournée", "abused redirector")),
            _ => (Niveau::Eleve, tr!("pourriel", "spam")),
        })
        .max_by_key(|(n, _)| *n);
    match pire {
        Some((niveau, raison)) => Inscription::Inscrit(raison.into(), niveau),
        None if codes.is_empty() => Inscription::Absent,
        None => Inscription::Impossible(tr!("réponse inconnue de la liste", "unknown answer from the list").into()),
    }
}

/// SURBL (multi) : 127.0.0.x, une case par liste dans le dernier nombre ; 127.0.0.1, un refus.
fn refus_surbl(codes: &[Ipv4Addr]) -> bool {
    codes.contains(&Ipv4Addr::LOCALHOST)
}

fn sens_surbl(codes: &[Ipv4Addr]) -> Inscription {
    let cases = codes
        .iter()
        .filter(|c| c.octets()[..3] == [127, 0, 0])
        .fold(0_u8, |acc, c| acc | c.octets()[3]);
    if cases & 8 != 0 {
        Inscription::Inscrit(tr!("hameçonnage", "phishing").into(), Niveau::Critique)
    } else if cases & 16 != 0 {
        Inscription::Inscrit(tr!("logiciels malveillants", "malware").into(), Niveau::Critique)
    } else if cases & 128 != 0 {
        Inscription::Inscrit(tr!("site piraté", "hacked site").into(), Niveau::Eleve)
    } else if cases & 64 != 0 {
        Inscription::Inscrit(tr!("pourriel, abus", "spam, abuse").into(), Niveau::Eleve)
    } else if codes.is_empty() {
        Inscription::Absent
    } else {
        Inscription::Impossible(tr!("réponse inconnue de la liste", "unknown answer from the list").into())
    }
}

/// Une liste d'abuse.ch téléchargée sert 12 heures sans être retéléchargée.
pub(crate) const URLHAUS_FRAICHE: Duration = Duration::from_hours(12);
/// Au-delà d'une semaine sans avoir pu être rafraîchies, les listes ne servent plus : un site piège vit quelques
/// jours, une vieille liste ne le connaît pas encore.
pub(crate) const URLHAUS_TROP_VIEILLE: Duration = Duration::from_hours(7 * 24);

/// Une liste d'URLhaus (abuse.ch), avec la clé de la personne, gardée 12 heures dans le dossier de Vanguard : la liste
/// des hôtes qui distribuent des logiciels malveillants (`hostfile.txt`, « 127.0.0.1 <hôte> » par ligne) ou celle des
/// liens en service (`urls_online.txt`, un par ligne), de la même forme que les exports publics fermés le 21 oct. 2026.
/// La télécharger ne dit à personne quel lien on vérifie. Sans Internet, la copie d'avant sert encore : son contenu, et
/// son âge.
fn liste_urlhaus(fichier: &str, nom: &str) -> Result<(Vec<u8>, Duration), crate::protection::abuse_ch::Echec> {
    use crate::protection::abuse_ch;
    abuse_ch::export(
        abuse_ch::Service::Urlhaus,
        fichier,
        ("urlhaus", nom),
        URLHAUS_FRAICHE,
        Duration::from_secs(40),
    )
}

/// Les hôtes d'URLhaus consacrés aux logiciels malveillants, en minuscules, pour les comparer aux noms que l'ordinateur
/// a demandés, et l'âge de la liste quand elle n'a pas pu être rafraîchie. `Err` : pourquoi la liste ne sert pas (sans
/// clé, trop vieille, illisible) ; rien n'est alors dédouané.
pub(crate) fn hotes_urlhaus() -> Result<(std::collections::HashSet<String>, Option<String>), String> {
    let (octets, age) = liste_urlhaus("hostfile.txt", "hotes.txt").map_err(|e| {
        trf!(
            "liste d'URLhaus non vérifiée : {}",
            "URLhaus list not checked: {}",
            e.raison()
        )
    })?;
    let note = age_des_listes(age).map_err(|r| trf!("liste d'URLhaus : {r}", "URLhaus list: {r}"))?;
    analyser_hotes(&String::from_utf8_lossy(&octets))
        .map(|h| (h, note))
        .ok_or_else(|| {
            tr!(
                "liste d'URLhaus illisible (page d'un portail Wi-Fi ?) : pas vérifiée",
                "URLhaus list unreadable (a Wi-Fi portal page?): not checked"
            )
            .to_string()
        })
}

/// La liste des hôtes d'URLhaus (« 127.0.0.1 <hôte> » par ligne, en-tête « # »). `None` pour tout autre texte : un
/// portail Wi-Fi ne doit pas passer pour une liste vide, donc vérifiée.
fn analyser_hotes(texte: &str) -> Option<std::collections::HashSet<String>> {
    let mut lignes = texte.lines().map(str::trim).filter(|l| !l.is_empty()).peekable();
    if !lignes.peek()?.starts_with('#') {
        return None;
    }
    Some(
        lignes
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split_whitespace().nth(1))
            .map(str::to_lowercase)
            .collect(),
    )
}

/// Ce que dit l'âge des listes d'URLhaus utilisées : rien quand elles sont fraîches ; leur âge quand elles n'ont pas
/// pu être rafraîchies (pas d'Internet) ; au-delà d'une semaine, elles ne servent plus (`Err` : la raison).
fn age_des_listes(age: Duration) -> Result<Option<String>, String> {
    if age < URLHAUS_FRAICHE {
        return Ok(None);
    }
    let heures = age.as_secs() / 3600;
    let duree = if heures < 48 {
        trf!("{heures} heures", "{heures} hours")
    } else {
        trf!("{} jours", "{} days", heures / 24)
    };
    if age > URLHAUS_TROP_VIEILLE {
        Err(trf!(
            "listes vieilles de {duree} : rafraîchissement impossible",
            "lists {duree} old: could not refresh them"
        ))
    } else {
        Ok(Some(trf!(
            "listes d'il y a {duree} : rafraîchissement impossible",
            "lists from {duree} ago: could not refresh them"
        )))
    }
}

/// URLhaus : les noms consacrés aux logiciels malveillants (liste des hôtes), et les liens en service (liste des
/// liens), pour les hébergeurs partagés (GitHub, Discord…) où seul le lien exact compte.
fn chercher_urlhaus(lien: &Lien, adresse: &str, hotes: Option<&str>, liens: Option<&str>) -> Inscription {
    let (Some(hotes), Some(liens)) = (hotes, liens) else {
        return Inscription::Impossible(
            tr!(
                "listes impossibles à télécharger (pas d'Internet ?)",
                "lists could not be downloaded (no Internet?)"
            )
            .into(),
        );
    };
    let domaine = site(lien);
    let dans_hotes = hotes
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_whitespace().nth(1))
        .any(|h| h.eq_ignore_ascii_case(&lien.hote) || h.eq_ignore_ascii_case(&domaine));
    let exact = adresse.trim_end_matches('/');
    let dans_liens = liens.lines().map(str::trim).any(|l| {
        l.trim_end_matches('/') == exact
            || (adresse_ip(&lien.hote) && decouper(l).is_some_and(|autre| autre.hote == lien.hote))
    });
    if dans_hotes || dans_liens {
        Inscription::Inscrit(
            tr!("distribue des logiciels malveillants", "distributes malware").into(),
            Niveau::Critique,
        )
    } else {
        Inscription::Absent
    }
}

/// Date d'enregistrement d'un domaine, dans une réponse RDAP.
fn date_d_enregistrement(json: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let date = v
        .get("events")?
        .as_array()?
        .iter()
        .find(|e| e.get("eventAction").and_then(serde_json::Value::as_str) == Some("registration"))?
        .get("eventDate")?
        .as_str()?;
    chrono::DateTime::parse_from_rfc3339(date)
        .ok()
        .map(|d| d.with_timezone(&chrono::Utc))
}

/// Âge du domaine d'après son registre (RDAP ; rdap.org renvoie au bon registre).
fn age(domaine: &str) -> Result<(chrono::DateTime<chrono::Utc>, i64), String> {
    if !domaine
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(tr!("nom non latin : âge non vérifié", "non-Latin name: age not checked").into());
    }
    // rdap.org renvoie vers le registre du domaine : la redirection reste en HTTPS (voir http.rs).
    let adresse = format!("https://rdap.org/domain/{domaine}");
    let mut demande = crate::http::Demande::get(&adresse, Duration::from_secs(12));
    demande.entetes.push(("Accept", "application/rdap+json".into()));
    let r = crate::http::envoyer(demande).ok_or_else(|| {
        tr!(
            "pas de réponse du registre (pas d'Internet ?)",
            "no answer from the registry (no Internet?)"
        )
        .to_string()
    })?;
    match r.code {
        200 => {}
        404 => {
            return Err(tr!(
                "inconnu du registre, ou registre sans RDAP",
                "unknown to the registry, or registry without RDAP"
            )
            .into());
        }
        autre => return Err(trf!("le registre a répondu {autre}", "the registry answered {autre}")),
    }
    let corps = r.texte();
    let corps = corps.as_str();
    let date = date_d_enregistrement(corps).ok_or_else(|| {
        tr!(
            "date d'enregistrement absente de la réponse",
            "registration date missing from the answer"
        )
        .to_string()
    })?;
    Ok((date, (chrono::Utc::now() - date).num_days()))
}

/// Ce que dit l'âge d'un domaine : un site piège a souvent quelques jours.
fn signe_d_age(date: chrono::DateTime<chrono::Utc>, jours: i64) -> Signe {
    let quand = date.format("%Y-%m-%d");
    if jours < 30 {
        signe(
            Niveau::Eleve,
            trf!(
                "Domaine tout neuf : créé le {quand}, il y a {jours} jour(s). Les sites pièges vivent rarement plus de quelques semaines.",
                "Brand-new domain: created on {quand}, {jours} day(s) ago. Trap sites rarely live more than a few weeks."
            ),
        )
    } else if jours < 180 {
        signe(
            Niveau::Moyen,
            trf!(
                "Domaine récent : créé le {quand}, il y a {} mois.",
                "Recent domain: created on {quand}, {} month(s) ago.",
                jours / 30
            ),
        )
    } else {
        signe(
            Niveau::Info,
            trf!(
                "Domaine créé le {quand}, il y a {} an(s) : bon signe, pas une garantie (un vieux site peut être piraté).",
                "Domain created on {quand}, {} year(s) ago: a good sign, not a guarantee (an old site can be hacked).",
                (jours / 365).max(1)
            ),
        )
    }
}

// ───────────────────────────── Affichage ─────────────────────────────

/// Un paragraphe coupé à la largeur de l'écran, en retrait de deux colonnes.
fn paragraphe(texte: &str) {
    for ligne in envelopper(texte, LARGEUR - 2) {
        println!("  {ligne}");
    }
}

fn afficher_signe(s: &Signe) {
    let marque = match s.niveau {
        Niveau::Info => format!("{GRIS}ℹ{RESET}"),
        Niveau::Moyen => format!("{}⚠{RESET}", couleur(Niveau::Moyen)),
        n => format!("{}✖{RESET}", couleur(n)),
    };
    afficher_aligne(&format!("  {marque} "), &s.texte, 4, "");
}

fn afficher_reponse(liste: &str, reponse: &Inscription, note: Option<&str>) {
    let (marque, mut texte) = match reponse {
        Inscription::Absent => (format!("{VERT}✔{RESET}"), tr!("pas listé", "not listed").to_string()),
        Inscription::Inscrit(raison, niveau) => (
            format!("{}✖{RESET}", couleur(*niveau)),
            trf!("listé : {raison}", "listed: {raison}"),
        ),
        Inscription::Impossible(raison) => (
            format!("{GRIS}?{RESET}"),
            trf!("impossible à vérifier : {raison}", "could not check: {raison}"),
        ),
    };
    if let Some(n) = note {
        texte = format!("{texte} ({n})");
    }
    afficher_aligne(&format!("  {marque} {} ", ajuster(liste, 13)), &texte, 18, "");
}

/// Une vérification en ligne : la liste, sa réponse, ce qu'elle dit (âge du domaine) et une précision (âge d'une liste
/// qu'on n'a pas pu rafraîchir).
struct Verification {
    liste: String,
    reponse: Inscription,
    signe: Option<Signe>,
    note: Option<String>,
}

impl Verification {
    fn simple(liste: &str, reponse: Inscription) -> Self {
        Verification {
            liste: liste.to_string(),
            reponse,
            signe: None,
            note: None,
        }
    }
}

/// Ce qu'ont pu faire les vérifications en ligne, pour le verdict.
#[derive(Debug, PartialEq)]
enum EnLigne {
    /// Toutes faites.
    Faites,
    /// Refusées, ou aucune n'a pu se faire : seulement l'examen local.
    Aucune,
    /// Certaines n'ont pas pu se faire : leurs noms.
    Incompletes(Vec<String>),
    /// Rien à vérifier en ligne (javascript:, data:… : pas de site).
    SansObjet,
}

/// Les vérifications en ligne, en parallèle : (âge, URLhaus, Spamhaus DBL, SURBL). Aucune n'ouvre le site.
fn en_ligne(lien: &Lien, adresse: &str) -> Vec<Verification> {
    // Un nom tapé en lettres non latines (« pаypal.com », avec un « а » cyrillique) : les listes et les registres ne
    // connaissent que sa forme « xn-- ». Le demander tel quel ferait répondre « absent » sans l'avoir vraiment cherché.
    if !lien.hote.is_ascii() {
        let raison = tr!(
            "nom en lettres non latines, que les listes ne connaissent que sous sa forme « xn-- »",
            "name in non-Latin letters, which the lists only know in its “xn--” form"
        );
        return [tr!("Âge", "Age"), "URLhaus", "Spamhaus DBL", "SURBL"]
            .into_iter()
            .map(|liste| Verification::simple(liste, Inscription::Impossible(raison.into())))
            .collect();
    }
    let domaine = site(lien);
    // Une adresse IP n'a ni âge ni place dans les listes de noms : seule URLhaus la connaît.
    let ip = adresse_ip(&lien.hote);
    std::thread::scope(|s| {
        let urlhaus = s.spawn(|| {
            let (hotes, liens) = match (
                liste_urlhaus("hostfile.txt", "hotes.txt"),
                liste_urlhaus("urls_online.txt", "liens.txt"),
            ) {
                (Ok(hotes), Ok(liens)) => (hotes, liens),
                (Err(echec), _) | (_, Err(echec)) => {
                    let raison = trf!("listes non vérifiées : {}", "lists not checked: {}", echec.raison());
                    return (Inscription::Impossible(raison), None);
                }
            };
            // La plus vieille des deux listes décide.
            match age_des_listes(hotes.1.max(liens.1)) {
                Err(raison) => (Inscription::Impossible(raison), None),
                Ok(note) => (
                    chercher_urlhaus(
                        lien,
                        adresse,
                        Some(String::from_utf8_lossy(&hotes.0).as_ref()),
                        Some(String::from_utf8_lossy(&liens.0).as_ref()),
                    ),
                    note,
                ),
            }
        });
        let age = (!ip).then(|| s.spawn(|| age(&domaine)));
        let dbl = (!ip).then(|| {
            s.spawn(|| {
                chercher_dns(&domaine, "dbl.spamhaus.org", "dbltest.com", refus_dbl, resoudre)
                    .map_or_else(Inscription::Impossible, |c| sens_dbl(&c))
            })
        });
        let surbl = (!ip).then(|| {
            s.spawn(|| {
                chercher_dns(&domaine, "multi.surbl.org", "test.surbl.org", refus_surbl, resoudre)
                    .map_or_else(Inscription::Impossible, |c| sens_surbl(&c))
            })
        });
        let erreur = || Inscription::Impossible(tr!("erreur interne", "internal error").into());
        let mut resultats = Vec::new();
        let nom_age = tr!("Âge", "Age");
        if let Some(age) = age {
            resultats.push(match age.join() {
                Ok(Ok((date, jours))) => Verification {
                    signe: Some(signe_d_age(date, jours)),
                    ..Verification::simple(nom_age, Inscription::Absent)
                },
                Ok(Err(raison)) => Verification::simple(nom_age, Inscription::Impossible(raison)),
                Err(_) => Verification::simple(nom_age, erreur()),
            });
        }
        let (reponse, note) = urlhaus.join().unwrap_or_else(|_| (erreur(), None));
        resultats.push(Verification {
            note,
            ..Verification::simple("URLhaus", reponse)
        });
        for (nom, fil) in [("Spamhaus DBL", dbl), ("SURBL", surbl)] {
            if let Some(fil) = fil {
                resultats.push(Verification::simple(nom, fil.join().unwrap_or_else(|_| erreur())));
            }
        }
        resultats
    })
}

/// Le verdict, prudent : jamais « sûr », et jamais « rien de suspect » tout court quand les vérifications en ligne
/// n'ont pas (toutes) pu se faire.
fn verdict(pire: Option<Niveau>, en_ligne: &EnLigne) -> String {
    let rappel = tr!(
        "Après un lien reçu, ne tapez jamais de mot de passe : allez sur le site en tapant son adresse vous-même.",
        "After a link you received, never type a password: go to the site by typing its address yourself."
    );
    let mut t = match pire {
        Some(Niveau::Critique | Niveau::Eleve) => tr!(
            "Dangereux : ne l'ouvrez pas. Supprimez le message. S'il parle d'un service que vous utilisez, allez sur son site en tapant vous-même son adresse.",
            "Dangerous: do not open it. Delete the message. If it mentions a service you use, go to its site by typing the address yourself."
        )
        .to_string(),
        Some(Niveau::Moyen) => tr!(
            "Douteux : ne l'ouvrez que si vous connaissez l'expéditeur et que vous attendiez ce lien. N'y tapez jamais de mot de passe.",
            "Doubtful: only open it if you know the sender and were expecting this link. Never type a password there."
        )
        .to_string(),
        _ => {
            return match en_ligne {
                EnLigne::Faites | EnLigne::SansObjet => trf!(
                    "Rien de suspect trouvé. Ce n'est pas une garantie : un site piège tout neuf n'est encore sur aucune liste. {rappel}",
                    "Nothing suspicious found. That is not a guarantee: a brand-new trap site is on no list yet. {rappel}"
                ),
                EnLigne::Aucune => trf!(
                    "Seulement l'examen local : listes et âge du domaine non vérifiés. Le lien lui-même ne montre rien de suspect, ce qui ne suffit pas : un site piège a souvent l'air normal. {rappel}",
                    "Only the local check: lists and domain age not checked. The link itself shows nothing suspicious, which is not enough: a trap site often looks normal. {rappel}"
                ),
                EnLigne::Incompletes(manquent) => trf!(
                    "Rien de suspect trouvé, mais pas tout a pu être vérifié ({}) : rien n'est conclu pour ce qui manque. Ce n'est pas une garantie : un site piège tout neuf n'est encore sur aucune liste. {rappel}",
                    "Nothing suspicious found, but not everything could be checked ({}): nothing is concluded for what is missing. That is not a guarantee: a brand-new trap site is on no list yet. {rappel}",
                    resume(manquent, 4, ", ")
                ),
            };
        }
    };
    if matches!(en_ligne, EnLigne::Aucune | EnLigne::Incompletes(_)) {
        t += tr!(
            " Certaines vérifications en ligne n'ont pas été faites (voir plus haut) : rien n'est conclu pour elles.",
            " Some online checks were not done (see above): nothing is concluded for them."
        );
    }
    t
}

/// Les vérifications en ligne d'un lien, affichées : le pire de ce qu'elles disent (au-dessus d'une information), les
/// listes qui n'ont pas pu répondre, et combien ont été tentées. Le site n'est jamais contacté.
fn afficher_en_ligne(lien: &Lien, adresse: &str) -> (Option<Niveau>, Vec<String>, usize) {
    let verifications = en_ligne(lien, adresse);
    let mut pire = None;
    let mut manquent = Vec::new();
    for v in &verifications {
        match &v.signe {
            Some(s) => {
                afficher_signe(s);
                pire = pire.max(Some(s.niveau).filter(|n| *n > Niveau::Info));
            }
            None => afficher_reponse(&v.liste, &v.reponse, v.note.as_deref()),
        }
        match &v.reponse {
            Inscription::Inscrit(_, n) => pire = pire.max(Some(*n)),
            Inscription::Impossible(_) => manquent.push(v.liste.clone()),
            Inscription::Absent => {}
        }
    }
    (pire, manquent, verifications.len())
}

// ───────────────────────────── Pour les autres outils ─────────────────────────────
// Le courriel suspect (`courriel_suspect`) juge ses liens et ses expéditeurs avec les mêmes règles et les mêmes
// tables : deux outils qui ne diraient pas la même chose d'un même nom perdraient la confiance des deux.

/// Un lien trouvé ailleurs (dans un courriel) : son site (vide pour « javascript: » et pareils) et ce qu'on y voit,
/// sans rien demander à personne. `None` : ce n'est pas un lien.
pub(crate) fn examiner_lien(texte: &str) -> Option<(String, Vec<(Niveau, String)>)> {
    let lien = decouper(&nettoyer(texte))?;
    let site = if lien.hote.is_empty() {
        String::new()
    } else {
        site(&lien)
    };
    Some((site, examiner(&lien).into_iter().map(|s| (s.niveau, s.texte)).collect()))
}

/// Le domaine d'une adresse de courriel : lettres déguisées, marque imitée, sous-domaine trompeur, hébergement
/// gratuit, extension à risque ; sans le « domaine officiel » des liens.
pub(crate) fn examiner_domaine(hote: &str) -> Vec<(Niveau, String)> {
    // Il vient d'un en-tête écrit par l'expéditeur et reparaît dans les messages : rien qui pilote le terminal.
    let hote = affichable(hote.trim_end_matches('.')).to_lowercase();
    if hote.is_empty() || adresse_ip(&hote) {
        return Vec::new();
    }
    if hote.len() > 253 {
        return vec![(
            Niveau::Moyen,
            tr!(
                "Nom de domaine impossible (plus de 253 caractères) : fabriqué, aucun serveur ne porte ce nom.",
                "Impossible domain name (over 253 characters): made up, no server has this name."
            )
            .to_string(),
        )];
    }
    let domaine = domaine_enregistrable(&hote);
    // Un « � » (caractère piège neutralisé, déjà signalé par l'appelant) n'est pas une lettre d'un autre alphabet.
    let deguisees = if hote.contains('\u{fffd}') {
        None
    } else {
        lettres_deguisees(&hote)
    };
    deguisees
        .into_iter()
        .chain(examiner_marques_de(&hote, &domaine, false))
        .map(|s| (s.niveau, s.texte))
        .collect()
}

/// La marque dont `hote` est un vrai domaine (ou un sous-domaine).
pub(crate) fn marque_officielle(hote: &str) -> Option<&'static str> {
    let hote = hote.trim_end_matches('.').to_lowercase();
    marques().iter().find(|m| officiel(&hote, m)).map(|m| m.nom)
}

/// La marque que nomme un texte (le nom affiché d'un expéditeur : « PayPal Service ») et son vrai domaine. Mots entiers,
/// sans tenir compte de la casse ; les noms de trois lettres ou moins (TD, UPS, BMO…) seulement en majuscules, sinon le
/// « ups » d'un « Oups » crierait.
/// Les lettres déguisées comptent aussi (`marque_nommee_telle_quelle` pour les mots tels qu'écrits).
pub(crate) fn marque_nommee(texte: &str) -> Option<(&'static str, &'static str)> {
    marque_nommee_telle_quelle(texte).or_else(|| marque_dans(texte, true))
}

/// `marque_nommee`, mots pris tels qu'écrits : « LinkedIn » reste LinkedIn, alors que sa lecture rapide (I pris pour
/// l) ne le serait plus.
pub(crate) fn marque_nommee_telle_quelle(texte: &str) -> Option<(&'static str, &'static str)> {
    marque_dans(texte, false)
}

/// `lu` : chaque mot ramené à ce qu'on voit à l'écran ; un I majuscule au milieu de minuscules se lit l (« PayPaI »),
/// une lettre d'un autre alphabet se lit comme la latine qu'elle imite (« PаyPаl » en а cyrillique).
fn marque_dans(texte: &str, lu: bool) -> Option<(&'static str, &'static str)> {
    let mots: Vec<&str> = texte
        .split(|c: char| !c.is_alphanumeric())
        .filter(|m| !m.is_empty())
        .collect();
    let lire = |m: &str| -> String {
        if !lu {
            return m.to_lowercase();
        }
        let mixte = m.chars().any(char::is_lowercase);
        m.chars()
            .map(|c| if mixte && c == 'I' { 'l' } else { c })
            .flat_map(char::to_lowercase)
            .map(|c| latine(c).unwrap_or(c))
            .collect()
    };
    let minuscules: Vec<String> = mots.iter().map(|m| lire(m)).collect();
    let suite = format!(" {} ", minuscules.join(" "));
    marques()
        .iter()
        .find(|m| {
            let nom: Vec<String> = m
                .nom
                .split(|c: char| !c.is_alphanumeric())
                .filter(|x| !x.is_empty())
                .map(&lire)
                .collect();
            let nom_present = if nom.len() > 1 {
                suite.contains(&format!(" {} ", nom.join(" ")))
            } else {
                nom.first().is_some_and(|n| present(&mots, &minuscules, n))
            };
            nom_present || m.mots.iter().any(|cle| present(&mots, &minuscules, cle))
        })
        .map(|m| (m.nom, m.domaines[0]))
}

/// Un mot parmi `mots` ; une clé courte seulement écrite en majuscules.
fn present(mots: &[&str], minuscules: &[String], cle: &str) -> bool {
    minuscules
        .iter()
        .zip(mots)
        .any(|(m, original)| m == cle && (cle.chars().count() > 3 || original.chars().all(|c| !c.is_lowercase())))
}

/// Les vérifications en ligne d'un nom de domaine (âge, URLhaus, Spamhaus DBL, SURBL), affichées comme dans « Ce
/// lien est-il dangereux ? » : le pire, les listes qui n'ont pas répondu, combien ont été tentées. Seul le nom sort.
pub(crate) fn verifier_en_ligne(domaine: &str) -> (Option<Niveau>, Vec<String>, usize) {
    match decouper(&nettoyer(domaine)).filter(|l| !l.hote.is_empty()) {
        Some(lien) => afficher_en_ligne(&lien, &format!("https://{}/", lien.hote)),
        None => (None, Vec::new(), 0),
    }
}

/// Menu Antivirus et protection › Ce lien est-il dangereux ?, ou `vanguard lien <adresse>`.
pub fn verifier(adresse: Option<&str>) {
    titre(tr!("Ce lien est-il dangereux ?", "Is this link dangerous?"));
    paragraphe(tr!(
        "Vanguard examine le lien sans jamais l'ouvrir : le site n'est pas contacté.",
        "Vanguard examines the link without ever opening it: the site is not contacted."
    ));
    let saisie = match adresse {
        Some(a) => a.to_string(),
        None => demander(tr!(
            "\n  Lien à vérifier (collez-le ici) : ",
            "\n  Link to check (paste it here): "
        )),
    };
    let propre = nettoyer(&saisie);
    let Some(lien) = decouper(&propre) else {
        trp!(
            "  ✖ Ce n'est pas un lien reconnu (il faut au moins un nom comme « exemple.com »).",
            "  ✖ This is not a recognized link (it needs at least a name like “example.com”)."
        );
        return;
    };
    println!();
    let montre = couper(&propre, LARGEUR - 12);
    println!("  {GRIS}{}{RESET} {montre}", ajuster(tr!("Lien", "Link"), 9));
    if !lien.hote.is_empty() {
        println!(
            "  {GRIS}{}{RESET} {ACCENT}{}{RESET}",
            ajuster(tr!("Vrai site", "Real site"), 9),
            site(&lien)
        );
        let lisible = affiche(&lien.hote);
        if lisible != lien.hote {
            println!("  {GRIS}{}{RESET} {lisible}", ajuster(tr!("S'affiche", "Shows as"), 9));
        }
    }
    println!();
    let mut signes = examiner(&lien);
    signes.sort_by_key(|s| std::cmp::Reverse(s.niveau));
    if signes.is_empty() {
        trp!(
            "  {GRIS}Rien de suspect dans le lien lui-même.{RESET}",
            "  {GRIS}Nothing suspicious in the link itself.{RESET}"
        );
    }
    for s in &signes {
        afficher_signe(s);
    }
    let mut pire = signes.iter().map(|s| s.niveau).filter(|n| *n > Niveau::Info).max();
    let mut fait_en_ligne = EnLigne::SansObjet;
    if !lien.hote.is_empty() {
        let domaine = site(&lien);
        println!();
        paragraphe(&trf!(
            "Vérifier aussi en ligne ? L'âge du domaine (son registre) et trois listes publiques de sites dangereux (URLhaus, Spamhaus, SURBL). Seul le nom {domaine} sortira de l'ordinateur, jamais le lien entier ; le site lui-même n'est pas contacté.",
            "Also check online? The domain's age (its registry) and three public lists of dangerous sites (URLhaus, Spamhaus, SURBL). Only the name {domaine} will leave the computer, never the whole link; the site itself is not contacted."
        ));
        if demander(tr!("  Continuer ? [o/N] : ", "  Continue? [y/N]: ")).oui() {
            println!();
            let (pire_en_ligne, manquent, faites) = afficher_en_ligne(&lien, &propre);
            pire = pire.max(pire_en_ligne);
            fait_en_ligne = if manquent.is_empty() {
                EnLigne::Faites
            } else if manquent.len() == faites {
                EnLigne::Aucune
            } else {
                EnLigne::Incompletes(manquent)
            };
        } else {
            trp!("  Rien n'a été envoyé.", "  Nothing was sent.");
            fait_en_ligne = EnLigne::Aucune;
        }
    }
    println!();
    // Pas en vert quand des vérifications n'ont pas été faites, comme pour un fichier téléchargé.
    let couleur_verdict = match (pire, &fait_en_ligne) {
        (Some(n), _) => couleur(n),
        (None, EnLigne::Aucune | EnLigne::Incompletes(_)) => couleur(Niveau::Moyen),
        (None, _) => VERT,
    };
    for ligne in envelopper(&verdict(pire, &fait_en_ligne), LARGEUR - 2) {
        println!("  {couleur_verdict}{ligne}{RESET}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lien(t: &str) -> Lien {
        decouper(&nettoyer(t)).unwrap()
    }

    fn niveaux(t: &str) -> Vec<Niveau> {
        examiner(&lien(t)).iter().map(|s| s.niveau).collect()
    }

    fn pire(t: &str) -> Option<Niveau> {
        niveaux(t).into_iter().max()
    }

    #[test]
    fn table_des_marques_lue_en_entier() {
        // Une ligne mal formée serait sautée sans bruit par filter_map : chaque ligne doit donner une marque complète.
        assert_eq!(marques().len(), TABLE_DES_MARQUES.lines().count());
        assert!(
            marques()
                .iter()
                .all(|m| !m.nom.is_empty() && !m.mots.is_empty() && !m.domaines.is_empty())
        );
        assert_eq!(marques()[0].domaines[0], "paypal.com");
    }

    #[test]
    fn hote_trop_long() {
        // Un nom DNS fait au plus 253 octets.
        assert!(decouper(&format!("https://{}example.com/", "a.".repeat(200))).is_none());
        assert!(decouper(&format!("https://{}example.com/", "a.".repeat(100))).is_some());
        assert_eq!(pire_domaine(&"a.".repeat(200)), Some(Niveau::Moyen));
    }

    fn pire_domaine(d: &str) -> Option<Niveau> {
        examiner_domaine(d).into_iter().map(|(n, _)| n).max()
    }

    #[test]
    fn marques_aux_lettres_deguisees() {
        assert_eq!(marque_nommee("P\u{430}yP\u{430}l Service").map(|m| m.0), Some("PayPal"));
        assert_eq!(marque_nommee("PayPaI").map(|m| m.0), Some("PayPal"));
        assert_eq!(marque_nommee_telle_quelle("PayPaI"), None);
        assert_eq!(marque_nommee("LinkedIn").map(|m| m.0), Some("LinkedIn"));
        assert_eq!(marque_nommee("Alice Martin"), None);
        // Un nom de domaine piégé ne pilote pas le terminal.
        assert!(
            examiner_domaine("paypal.com.x\u{1b}[8mcache.example")
                .iter()
                .all(|(_, t)| !t.contains('\u{1b}'))
        );
    }

    #[test]
    fn decoupage() {
        let l = lien("https://alice@exemple.com:8443/chemin?a=1#b");
        assert_eq!(l.schema, "https");
        assert_eq!(l.utilisateur.as_deref(), Some("alice"));
        assert_eq!(l.hote, "exemple.com");
        assert_eq!(l.port, Some(8443));
        assert_eq!(l.reste, "/chemin?a=1#b");
        // Sans schéma, désamorcé, en IPv6, avec un port collé au nom.
        assert_eq!(lien("Exemple.COM/page").hote, "exemple.com");
        assert_eq!(lien("hxxps://exemple[.]com/x").hote, "exemple.com");
        assert_eq!(lien("hxxps://exemple[.]com/x").schema, "https");
        assert_eq!(lien("http://[2001:db8::1]:8080/").hote, "2001:db8::1");
        assert_eq!(lien("exemple.com:8080").port, Some(8080));
        assert_eq!(lien("  <https://exemple.com>  ").hote, "exemple.com");
        // Pas des liens.
        assert!(decouper("bonjour").is_none());
        assert!(decouper("").is_none());
        assert_eq!(lien("javascript:alert(1)").schema, "javascript");
    }

    #[test]
    fn punycode_decode() {
        assert_eq!(punycode("pple-43d").as_deref(), Some("аpple"));
        assert_eq!(punycode("80ak6aa92e").as_deref(), Some("аррӏе"));
        assert_eq!(punycode("bcher-kva").as_deref(), Some("bücher"));
        assert_eq!(punycode("e1afmkfd").as_deref(), Some("пример"));
        assert_eq!(punycode("!!"), None);
        assert_eq!(affiche("www.xn--80ak6aa92e.com"), "www.аррӏе.com");
    }

    /// Un lien reçu peut cacher ce qui pilote le terminal ou retourne l'écriture : collé, il arrive inoffensif, et ce
    /// qui en est montré aussi (lien, faux nom devant « @ », site, nom décodé du punycode, signes). Le danger, lui,
    /// reste jugé : une lettre invisible au milieu d'une marque est toujours un mélange d'alphabets.
    #[test]
    fn lien_piege_inoffensif() {
        assert_eq!(
            nettoyer("https://exemple.com/\x1b]52;c;eA==\x07\x1b[2K\r\u{202e}fdp.exe"),
            "https://exemple.com/�]52;c;eA==��[2K��fdp.exe"
        );
        let l = lien("https://\x1b[8mpaypal.com@pay\u{200b}pal.xyz/\u{202e}gpj.exe");
        let signes = examiner(&l);
        assert!(signes.iter().any(|s| s.niveau == Niveau::Eleve));
        for s in &signes {
            assert!(!crate::ui::contient_un_piege(&s.texte), "{}", s.texte);
        }
        // « xn--paypal-dm0c » se décode en « pay[U+202E]pal ».
        assert_eq!(affiche("xn--paypal-dm0c.com"), "pay�pal.com");
        assert_eq!(pire("https://xn--paypal-dm0c.com/"), Some(Niveau::Eleve));
    }

    #[test]
    fn domaine_du_proprietaire() {
        assert_eq!(domaine_enregistrable("www.exemple.com"), "exemple.com");
        assert_eq!(domaine_enregistrable("shop.exemple.co.uk"), "exemple.co.uk");
        assert_eq!(domaine_enregistrable("faux-site.github.io"), "faux-site.github.io");
        assert_eq!(domaine_enregistrable("a.b.c.exemple.qc.ca"), "exemple.qc.ca");
        assert_eq!(domaine_enregistrable("exemple.com"), "exemple.com");
        assert_eq!(domaine_enregistrable("localhost"), "localhost");
    }

    #[test]
    fn ressemblances() {
        for (mot, cle) in [
            ("paypa1", "paypal"),
            ("arnazon", "amazon"),
            ("micros0ft", "microsoft"),
            ("gooogle", "google"),
            ("microsfot", "microsoft"),
            ("micrsoft", "microsoft"),
            ("netfl1x", "netflix"),
            ("app1e", "apple"),
        ] {
            assert!(ressemble(mot, cle), "{mot} devrait ressembler à {cle}");
        }
        for (mot, cle) in [
            ("stream", "steam"),
            ("finance", "binance"),
            ("paypal", "paypal"),
            ("pineapple", "apple"),
            ("goggles", "google"),
        ] {
            assert!(!ressemble(mot, cle), "{mot} ne devrait pas ressembler à {cle}");
        }
        assert!(parle_de("paypal-secure", "paypal"));
        assert!(parle_de("appleidlogin", "appleid"));
        assert!(parle_de("secure-login-td", "td"));
        assert!(parle_de("craarcrefund", "craarc"));
        assert!(!parle_de("pineapple", "apple"));
        assert!(!parle_de("ltd", "td"));
    }

    #[test]
    fn liens_dangereux() {
        // Sous-domaine trompeur, marque imitée, lettres déguisées, « @ », adresse IP brute ou déguisée.
        assert_eq!(
            pire("https://paypal.com.compte-secure.xyz/login"),
            Some(Niveau::Critique)
        );
        assert_eq!(pire("https://paypa1.com/"), Some(Niveau::Eleve));
        assert_eq!(pire("https://secure-paypal-verification.com/"), Some(Niveau::Eleve));
        assert_eq!(pire("https://xn--pple-43d.com/"), Some(Niveau::Critique));
        assert_eq!(pire("https://www.paypal.com@203.0.113.7/"), Some(Niveau::Eleve));
        assert_eq!(pire("http://203.0.113.7/facture.exe"), Some(Niveau::Eleve));
        assert_eq!(pire("http://3232235777/"), Some(Niveau::Eleve));
        assert_eq!(pire("javascript:alert(1)"), Some(Niveau::Critique));
        assert_eq!(
            pire("https://arc-remboursement.ca/"),
            None,
            "« arc » seul ne suffit pas"
        );
        assert_eq!(pire("https://cra-arc-refund.com/"), Some(Niveau::Eleve));
    }

    #[test]
    fn liens_douteux_ou_normaux() {
        // Raccourcisseur, extension à risque, téléchargement d'un programme : douteux.
        assert_eq!(pire("https://bit.ly/3AbCdEf"), Some(Niveau::Moyen));
        assert_eq!(pire("https://promo-chaussures.xyz/"), Some(Niveau::Moyen));
        assert_eq!(pire("https://exemple.com/outil.exe"), Some(Niveau::Moyen));
        // Vrais sites : au plus une information.
        assert!(pire("https://www.paypal.com/signin").is_none_or(|n| n == Niveau::Info));
        assert!(pire("https://accounts.google.com/").is_none_or(|n| n == Niveau::Info));
        assert!(pire("https://www.pineapple-recettes.com/").is_none());
        assert!(pire("https://www.desjardins.com/").is_none_or(|n| n == Niveau::Info));
        assert!(pire("https://xn--bcher-kva.example/").is_none_or(|n| n == Niveau::Info));
        // Un appareil du réseau : information seulement.
        assert_eq!(pire("http://192.168.1.1/"), Some(Niveau::Info));
        assert_eq!(pire("http://127.0.0.1:8080/"), Some(Niveau::Info));
        // Le réseau partagé du fournisseur (CGNAT) : la box d'un autre abonné, une adresse IP brute.
        assert_eq!(pire("http://100.88.1.2/connexion"), Some(Niveau::Eleve));
        // Site gratuit qui parle d'une marque : très suspect.
        assert_eq!(pire("https://netflix-compte.github.io/"), Some(Niveau::Eleve));
    }

    #[test]
    fn listes_par_le_dns() {
        let ip = |t: &str| t.parse::<Ipv4Addr>().unwrap();
        // L'essai répond ; le domaine n'y est pas.
        let liste = |nom: &str| {
            Some(if nom.starts_with("dbltest.com.") {
                vec![ip("127.0.1.2")]
            } else {
                vec![]
            })
        };
        assert_eq!(
            chercher_dns("exemple.com", "dbl.spamhaus.org", "dbltest.com", refus_dbl, liste),
            Ok(vec![])
        );
        // Résolveur public : Spamhaus refuse, jamais « absent ».
        let public = |_: &str| Some(vec![ip("127.255.255.254")]);
        assert!(chercher_dns("exemple.com", "dbl.spamhaus.org", "dbltest.com", refus_dbl, public).is_err());
        // DNS qui retire les réponses (Google répond « nom inconnu ») : impossible.
        assert!(
            chercher_dns(
                "exemple.com",
                "dbl.spamhaus.org",
                "dbltest.com",
                refus_dbl,
                |_: &str| Some(vec![])
            )
            .is_err()
        );
        // SURBL refuse par 127.0.0.1.
        let refuse = |_: &str| Some(vec![Ipv4Addr::LOCALHOST]);
        assert!(chercher_dns("exemple.com", "multi.surbl.org", "test.surbl.org", refus_surbl, refuse).is_err());
        // Sens des codes.
        assert_eq!(
            sens_dbl(&[ip("127.0.1.4")]),
            Inscription::Inscrit("hameçonnage".into(), Niveau::Critique)
        );
        assert_eq!(sens_dbl(&[]), Inscription::Absent);
        assert_eq!(
            sens_surbl(&[ip("127.0.0.24")]),
            Inscription::Inscrit("hameçonnage".into(), Niveau::Critique)
        );
        assert_eq!(
            sens_surbl(&[ip("127.0.0.64")]),
            Inscription::Inscrit("pourriel, abus".into(), Niveau::Eleve)
        );
    }

    #[test]
    fn hotes_d_urlhaus() {
        let h = analyser_hotes("# URLhaus\n\n127.0.0.1\tPiege-Exemple.com\n127.0.0.1 203.0.113.9\n").unwrap();
        assert!(h.contains("piege-exemple.com") && h.contains("203.0.113.9") && h.len() == 2);
        assert!(analyser_hotes("<html>Bienvenue au Salon</html>").is_none());
        assert!(analyser_hotes("").is_none());
    }

    #[test]
    fn urlhaus_et_age() {
        let hotes = "# commentaire\n127.0.0.1\tpiege-exemple.com\n";
        let liens = "http://203.0.113.9:4444/i\nhttps://depot.example.org/alice/outil.zip\n";
        let l = lien("https://www.piege-exemple.com/a");
        assert!(matches!(
            chercher_urlhaus(&l, "https://www.piege-exemple.com/a", Some(hotes), Some(liens)),
            Inscription::Inscrit(_, Niveau::Critique)
        ));
        let l = lien("https://depot.example.org/alice/outil.zip");
        assert!(matches!(
            chercher_urlhaus(
                &l,
                "https://depot.example.org/alice/outil.zip",
                Some(hotes),
                Some(liens)
            ),
            Inscription::Inscrit(..)
        ));
        let l = lien("http://203.0.113.9/autre");
        assert!(matches!(
            chercher_urlhaus(&l, "http://203.0.113.9/autre", Some(hotes), Some(liens)),
            Inscription::Inscrit(..)
        ));
        let l = lien("https://depot.example.org/bob/autre.zip");
        assert_eq!(
            chercher_urlhaus(&l, "https://depot.example.org/bob/autre.zip", Some(hotes), Some(liens)),
            Inscription::Absent
        );
        assert!(matches!(
            chercher_urlhaus(&l, "https://x.example", None, Some(liens)),
            Inscription::Impossible(_)
        ));
        let json = r#"{"events":[{"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"},{"eventAction":"expiration","eventDate":"2030-08-13T04:00:00Z"}]}"#;
        let date = date_d_enregistrement(json).unwrap();
        assert_eq!(date.format("%Y-%m-%d").to_string(), "1995-08-14");
        assert_eq!(date_d_enregistrement("{}"), None);
        assert_eq!(signe_d_age(date, 3).niveau, Niveau::Eleve);
        assert_eq!(signe_d_age(date, 90).niveau, Niveau::Moyen);
        assert_eq!(signe_d_age(date, 9000).niveau, Niveau::Info);
    }

    #[test]
    fn nom_non_latin_jamais_dit_absent() {
        // Rien ne part sur le réseau : chaque liste dit qu'elle n'a pas pu chercher.
        let lien = decouper("https://pаypal.com/connexion").unwrap();
        let reponses = en_ligne(&lien, "https://pаypal.com/connexion");
        assert_eq!(reponses.len(), 4);
        assert!(reponses.iter().all(|v| matches!(v.reponse, Inscription::Impossible(_))));
    }

    #[test]
    fn verdict_sans_verification_en_ligne() {
        let local = |t: &str| t.contains("Seulement l'examen local") || t.contains("Only the local check");
        let rien = |t: &str| t.starts_with("Rien de suspect trouvé.") || t.starts_with("Nothing suspicious found.");
        // Refusée ou impossible : seulement l'examen local, jamais « rien de suspect » tout court.
        let refuse = verdict(None, &EnLigne::Aucune);
        assert!(local(&refuse) && !rien(&refuse), "{refuse}");
        let partiel = verdict(None, &EnLigne::Incompletes(vec!["SURBL".into()]));
        assert!(partiel.contains("SURBL") && !rien(&partiel), "{partiel}");
        // Toutes faites, ou rien à vérifier en ligne : le verdict d'avant.
        assert!(rien(&verdict(None, &EnLigne::Faites)));
        assert!(rien(&verdict(None, &EnLigne::SansObjet)));
        // Dangereux reste dangereux.
        let danger = verdict(Some(Niveau::Critique), &EnLigne::Aucune);
        assert!(danger.starts_with("Dangereux") || danger.starts_with("Dangerous"));
    }

    #[test]
    fn age_des_listes_urlhaus() {
        let heures = |h: u64| Duration::from_hours(h);
        assert_eq!(age_des_listes(heures(1)), Ok(None));
        // Pas rafraîchies : leur âge est dit.
        let note = age_des_listes(heures(30)).unwrap().unwrap();
        assert!(note.contains("30"), "{note}");
        assert!(age_des_listes(heures(5 * 24)).unwrap().unwrap().contains('5'));
        // Plus d'une semaine : elles ne servent plus.
        let trop = age_des_listes(heures(8 * 24)).unwrap_err();
        assert!(trop.contains('8'), "{trop}");
    }
}

/// PROVISOIRE (lot H, à remplacer) : `--json` rend un résultat vide, donc « non vérifié ».
pub fn json(_adresse: &str, _internet: bool) {
    let debut = (chrono::Utc::now(), std::time::Instant::now());
    let r = crate::modele::resultat::Resultat::nouveau(
        "PRO-LIE-001",
        debut,
        &[],
        crate::modele::resultat::Couverture::default(),
    );
    println!("{}", crate::modele::resultat::json(&r));
}

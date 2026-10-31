//! Les liens du corps du courriel, en texte et en HTML, et des pages web jointes. Le HTML est lu par un petit lecteur
//! de balises, pas par un navigateur : rien n'est rendu, aucune image n'est chargée, aucun script ne tourne. Il en
//! retient ce qu'un clic ferait : l'adresse de chaque lien et le texte qu'il montre, les formulaires, une redirection
//! automatique, une base qui change la destination des liens.

use super::Signe;
use crate::protection::lien;
use crate::risk::Niveau;
use crate::ui::{affichable, piege};
use crate::{tr, trf};

/// D'où vient un lien.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Source {
    Texte,
    Html,
    /// Une page web jointe (son nom).
    PieceHtml(String),
    /// Dans un courriel joint (transféré).
    Transfere,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LienTrouve {
    /// L'adresse, entités décodées.
    pub cible: String,
    /// Le texte que montre le lien, balises retirées.
    pub affiche: Option<String>,
    pub source: Source,
}

/// Ce que le HTML contient d'utile à juger.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Html {
    pub liens: Vec<LienTrouve>,
    /// L'adresse où partent les formulaires.
    pub formulaires: Vec<String>,
    /// Redirection automatique (`<meta http-equiv="refresh">`).
    pub rafraichit: Option<String>,
    pub base: Option<String>,
    pub images_distantes: usize,
    pub images: usize,
    /// Caractères de texte visibles (hors balises et espaces) : un courriel fait d'une seule image se voit.
    pub texte_visible: usize,
    /// Une borne atteinte : des liens n'ont pas été lus.
    pub coupe: bool,
}

/// Le HTML lu au plus : au-delà, ses liens ne sont pas lus (c'est dit).
pub(crate) const HTML_MAX: usize = 5_000_000;
const AFFICHE_MAX: usize = 500;

/// Une balise lue : son nom en minuscules, fermante ou pas, ses attributs (noms en minuscules, valeurs décodées).
struct Balise {
    nom: String,
    fermante: bool,
    attributs: Vec<(String, String)>,
    /// Un de ses attributs, même au-delà des 50 gardés, lance du code : gestionnaire d'événement (`onload`…) ou
    /// adresse `javascript:`.
    actif: bool,
}

impl Balise {
    fn attribut(&self, nom: &str) -> Option<&str> {
        self.attributs.iter().find(|(n, _)| n == nom).map(|(_, v)| v.as_str())
    }

    /// Le nom sans son préfixe d'espace de noms : dans une image SVG, lue comme du XML, `<svg:a>` est un lien.
    fn local(&self) -> &str {
        self.nom.rsplit(':').next().unwrap_or(&self.nom)
    }

    /// L'adresse d'un lien : `href`, sinon `xlink:href` (SVG 1.1), quel que soit le préfixe qui désigne XLink.
    fn lien(&self) -> Option<&str> {
        self.attribut("href").or_else(|| {
            self.attributs
                .iter()
                .find(|(n, _)| n.ends_with(":href"))
                .map(|(_, v)| v.as_str())
        })
    }
}

/// L'attribut `nom` = `valeur` lance du code : gestionnaire d'événement (préfixe compris), ou valeur qui porte une
/// adresse `javascript:` ou `vbscript:` (celle d'un lien, ou celle qu'une animation SVG lui donne : `<set to=…>`,
/// `<animate values=…>`). La valeur est lue comme le navigateur lit une adresse : entités décodées, caractères de
/// contrôle retirés. Une animation SMIL qui vise un gestionnaire ou l'adresse d'un lien (`attributeName="onload"`,
/// `"xlink:href"`) l'est aussi, quelle que soit la valeur qu'elle donne : celle-ci peut venir d'une entité ou d'une
/// liste que la lecture ne déroule pas (relecture du lot campagne 6).
fn attribut_actif(nom: &str, valeur: &str) -> bool {
    let gestionnaire = |nom: &str| {
        let local = nom.rsplit(':').next().unwrap_or(nom);
        local.len() > 2 && local.starts_with("on") && local.bytes().all(|o| o.is_ascii_lowercase())
    };
    let v = adresse_attribut(valeur).to_ascii_lowercase();
    let anime =
        nom.rsplit(':').next() == Some("attributename") && (gestionnaire(&v) || v.rsplit(':').next() == Some("href"));
    gestionnaire(nom) || anime || v.contains("javascript:") || v.contains("vbscript:")
}

/// Les octets de `h` qui vérifient `garder` à partir de `i`, et l'indice qui les suit. Au-delà de la fin, il n'y a
/// plus rien à lire : rien n'est pris.
fn prendre(h: &[u8], i: usize, garder: impl Fn(u8) -> bool) -> (&[u8], usize) {
    let reste = h.get(i..).unwrap_or_default();
    let n = reste.iter().take_while(|&&o| garder(o)).count();
    (reste.get(..n).unwrap_or(reste), i + n)
}

/// Lit la balise qui commence à `debut` (sur « < ») ; rend la balise et l'indice qui suit « > ». En `xml` (une image
/// SVG), un nom va jusqu'à l'espace, « / » ou « > » : un préfixe d'espace de noms peut porter `_`, `.` ou une lettre
/// non ASCII (`<a_b:script>`), et s'arrêter avant cachait le nom local (relecture du lot campagne 6). En HTML, le nom
/// reste fait de lettres, chiffres, « - » et « : » : un « < » suivi d'autre chose y est du texte, et le lire comme une
/// balise avalerait le lien qui suit.
fn lire_balise(h: &[u8], debut: usize, xml: bool) -> (Option<Balise>, usize) {
    let mut i = debut + 1;
    let fermante = h.get(i) == Some(&b'/');
    if fermante {
        i += 1;
    }
    let (nom, suite) = if xml {
        prendre(h, i, |o| !o.is_ascii_whitespace() && !matches!(o, b'/' | b'>'))
    } else {
        prendre(h, i, |o| o.is_ascii_alphanumeric() || o == b'-' || o == b':')
    };
    if nom.is_empty() {
        // « < » seul dans le texte : pas une balise.
        return (None, debut + 1);
    }
    let nom = String::from_utf8_lossy(nom).to_ascii_lowercase();
    i = suite;
    let mut attributs = Vec::new();
    let mut actif = false;
    loop {
        i = prendre(h, i, |o| o.is_ascii_whitespace() || o == b'/').1;
        let Some(&o) = h.get(i) else {
            break;
        };
        if o == b'>' {
            i += 1;
            break;
        }
        let (nom_attr, suite) = prendre(h, i, |o| !o.is_ascii_whitespace() && !matches!(o, b'=' | b'>' | b'/'));
        if nom_attr.is_empty() {
            i += 1;
            continue;
        }
        let nom_attr = String::from_utf8_lossy(nom_attr).to_ascii_lowercase();
        i = prendre(h, suite, |o| o.is_ascii_whitespace()).1;
        let mut valeur = String::new();
        if h.get(i) == Some(&b'=') {
            i = prendre(h, i + 1, |o| o.is_ascii_whitespace()).1;
            if let Some(&q @ (b'"' | b'\'')) = h.get(i) {
                // Jusqu'au guillemet qui ferme, ou la fin.
                let (v, fin) = prendre(h, i + 1, |o| o != q);
                valeur = String::from_utf8_lossy(v).into_owned();
                i = (fin + 1).min(h.len());
            } else {
                let (v, fin) = prendre(h, i, |o| !o.is_ascii_whitespace() && o != b'>');
                valeur = String::from_utf8_lossy(v).into_owned();
                i = fin;
            }
        }
        let valeur = entites(&valeur);
        actif |= attribut_actif(&nom_attr, &valeur);
        if attributs.len() < 50 {
            attributs.push((nom_attr, valeur));
        }
    }
    (
        Some(Balise {
            nom,
            fermante,
            attributs,
            actif,
        }),
        i,
    )
}

/// Indice de la première occurrence de `aiguille` (ASCII, sans tenir compte de la casse) à partir de `debut`.
fn chercher_casse(h: &[u8], debut: usize, aiguille: &[u8]) -> Option<usize> {
    if aiguille.is_empty() || debut >= h.len() {
        return None;
    }
    h.get(debut..)?
        .windows(aiguille.len())
        .position(|w| w.eq_ignore_ascii_case(aiguille))
        .map(|p| debut + p)
}

/// Une adresse lue dans un attribut, comme le navigateur la lit : sauts de ligne, tabulations et autres caractères de
/// contrôle retirés, espaces autour aussi, « \ » lu comme « / » (« https:\site\page » mène à https://site/page).
/// Sans cela, une adresse écrite ainsi passerait pour un lien qui ne mène nulle part, et ne serait pas examinée.
fn adresse_attribut(v: &str) -> String {
    v.chars()
        .filter(|c| !c.is_ascii_control())
        .map(|c| if c == '\\' { '/' } else { c })
        .collect::<String>()
        .trim()
        .to_string()
}

/// Lit le HTML d'une partie (au plus `HTML_MAX` octets, `max_liens` liens).
pub(crate) fn lire_html(html: &str, max_liens: usize, source: &Source) -> Html {
    let mut r = Html::default();
    let h = match html.as_bytes().split_at_checked(HTML_MAX) {
        Some((lu, reste)) if !reste.is_empty() => {
            r.coupe = true;
            lu
        }
        _ => html.as_bytes(),
    };
    // Le lien ouvert (son adresse, et le texte qu'il montre).
    let mut ouvert: Option<(String, Vec<u8>)> = None;
    let mut i = 0;
    let fermer = |ouvert: &mut Option<(String, Vec<u8>)>, r: &mut Html| {
        if let Some((cible, texte)) = ouvert.take() {
            pousser(r, cible, Some(texte_affiche(&texte)), source, max_liens);
        }
    };
    while let Some(ici) = h.get(i..).filter(|ici| !ici.is_empty()) {
        if !ici.starts_with(b"<") {
            let (morceau, fin) = prendre(h, i, |c| c != b'<');
            r.texte_visible += morceau.iter().filter(|c| !c.is_ascii_whitespace()).count();
            if let Some((_, texte)) = &mut ouvert
                && texte.len() < AFFICHE_MAX
            {
                texte.extend(morceau.iter().take(AFFICHE_MAX - texte.len()));
            }
            i = fin;
            continue;
        }
        // Commentaire : un lien qu'il contient n'est pas cliquable.
        if ici.starts_with(b"<!--") {
            i = chercher_casse(h, i + 4, b"-->").map_or(h.len(), |p| p + 3);
            continue;
        }
        if ici.starts_with(b"<!") || ici.starts_with(b"<?") {
            i = ici.iter().position(|&c| c == b'>').map_or(h.len(), |p| i + p + 1);
            continue;
        }
        let (balise, suite) = lire_balise(h, i, false);
        i = suite;
        let Some(lue) = balise else {
            continue;
        };
        if lue.fermante {
            if lue.local() == "a" {
                fermer(&mut ouvert, &mut r);
            }
            continue;
        }
        // `script` et `style` sans préfixe seuls : un `<o:script>` est, pour un client de messagerie, un élément
        // inconnu qui montre son contenu ; sauté jusqu'à une fermeture qui ne vient pas, il avalait le reste du
        // courriel (relecture du lot campagne 6). Le nom local ne sert qu'aux liens et aux images, que `<svg:a>`
        // désigne aussi.
        if matches!(lue.nom.as_str(), "script" | "style") {
            let fin = format!("</{}", lue.nom);
            i = chercher_casse(h, i, fin.as_bytes()).unwrap_or(h.len());
            continue;
        }
        match lue.local() {
            "a" => {
                // Un lien jamais fermé se termine où le suivant commence.
                fermer(&mut ouvert, &mut r);
                if let Some(href) = lue.lien() {
                    ouvert = Some((adresse_attribut(href), Vec::new()));
                }
            }
            "area" => {
                if let Some(href) = lue.lien() {
                    pousser(&mut r, adresse_attribut(href), None, source, max_liens);
                }
            }
            "form" => {
                if r.formulaires.len() < 20 {
                    r.formulaires
                        .push(adresse_attribut(lue.attribut("action").unwrap_or("")));
                }
            }
            "meta" => {
                if lue
                    .attribut("http-equiv")
                    .is_some_and(|v| v.eq_ignore_ascii_case("refresh"))
                    && let Some(contenu) = lue.attribut("content")
                {
                    let cible = contenu
                        .split_once(['=', ';'])
                        .map(|(_, reste)| reste.trim_start_matches([' ', ';']))
                        .map(|reste| {
                            let bas = reste.to_ascii_lowercase();
                            match bas.find("url") {
                                Some(pos) => reste[pos + 3..].trim_start_matches([' ', '=']).to_string(),
                                None => reste.to_string(),
                            }
                        })
                        .map(|c| adresse_attribut(c.trim_matches(['"', '\''])))
                        .unwrap_or_default();
                    if !cible.is_empty() {
                        r.rafraichit = Some(cible);
                    }
                }
            }
            "base" => {
                if let Some(href) = lue.attribut("href") {
                    r.base = Some(adresse_attribut(href));
                }
            }
            // `<image>` : l'image d'un SVG, désignée comme un lien.
            "img" | "image" => {
                r.images += 1;
                if lue.attribut("src").or_else(|| lue.lien()).is_some_and(|s| {
                    s.trim().get(..4).is_some_and(|d| d.eq_ignore_ascii_case("http")) || s.trim().starts_with("//")
                }) {
                    r.images_distantes += 1;
                }
            }
            _ => {}
        }
    }
    fermer(&mut ouvert, &mut r);
    if r.liens.len() >= max_liens {
        r.coupe = true;
    }
    r
}

/// Une image SVG (ou une page XML) porte du code qui tourne à son ouverture : élément `script` ou `foreignObject`
/// (du HTML dans l'image), cadre ou objet HTML (`iframe`, `embed`, `object`), préfixe compris, gestionnaire
/// d'événement, adresse `javascript:` ou animation qui vise l'un ou l'autre. Une déclaration d'entité ou d'attribut
/// par défaut dans la DTD (`<!ENTITY`, `<!ATTLIST`) peut les porter sans qu'ils soient écrits, et une feuille de style
/// XML (`<?xml-stylesheet`, XSLT) transformer l'image : la lecture ne les déroule pas, l'image se dit active
/// (relecture du lot campagne 6). Au-delà de `HTML_MAX` octets, rien n'est lu : `None`, à dire comme un manque.
pub(crate) fn svg_actif(h: &[u8]) -> Option<bool> {
    if h.len() > HTML_MAX {
        return None;
    }
    if [b"<!entity".as_slice(), b"<!attlist", b"<?xml-stylesheet"]
        .iter()
        .any(|m| chercher_casse(h, 0, m).is_some())
    {
        return Some(true);
    }
    let mut i = 0;
    while let Some(debut) = h.get(i..).and_then(|ici| ici.iter().position(|&c| c == b'<')) {
        i += debut;
        let ici = h.get(i..).unwrap_or_default();
        if ici.starts_with(b"<!--") {
            i = chercher_casse(h, i + 4, b"-->").map_or(h.len(), |p| p + 3);
            continue;
        }
        if ici.starts_with(b"<!") || ici.starts_with(b"<?") {
            i = ici.iter().position(|&c| c == b'>').map_or(h.len(), |p| i + p + 1);
            continue;
        }
        let (balise, suite) = lire_balise(h, i, true);
        i = suite;
        if let Some(lue) = balise
            && !lue.fermante
            && (lue.actif
                || matches!(
                    lue.local(),
                    "script" | "foreignobject" | "handler" | "iframe" | "embed" | "object"
                ))
        {
            return Some(true);
        }
    }
    Some(false)
}

fn pousser(r: &mut Html, cible: String, affiche: Option<String>, source: &Source, max: usize) {
    if r.liens.len() >= max {
        r.coupe = true;
        return;
    }
    r.liens.push(LienTrouve {
        cible,
        affiche: affiche.filter(|a| !a.is_empty()),
        source: source.clone(),
    });
}

/// Le texte montré par un lien : balises retirées, entités décodées, espaces resserrés.
fn texte_affiche(octets: &[u8]) -> String {
    entites(&String::from_utf8_lossy(octets))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Une référence numérique (« &#104; », « &#x68 »), lue comme le navigateur : le « ; » est facultatif, les chiffres
/// s'arrêtent d'eux-mêmes. Rend le caractère et la longueur lue ; une valeur impossible donne « � ».
fn reference_numerique(reste: &str) -> Option<(char, usize)> {
    let apres = reste.strip_prefix("&#")?;
    let (hexa, chiffres_debut) = match apres.strip_prefix(['x', 'X']) {
        Some(_) => (true, 3),
        None => (false, 2),
    };
    let chiffres: &str = {
        let corps = &reste[chiffres_debut..];
        let n = corps
            .bytes()
            .take_while(|c| {
                if hexa {
                    c.is_ascii_hexdigit()
                } else {
                    c.is_ascii_digit()
                }
            })
            .count();
        &corps[..n]
    };
    if chiffres.is_empty() {
        return None;
    }
    let mut longueur = chiffres_debut + chiffres.len();
    if reste[longueur..].starts_with(';') {
        longueur += 1;
    }
    let significatifs = chiffres.trim_start_matches('0');
    let valeur = if significatifs.len() > 8 {
        None
    } else if significatifs.is_empty() {
        Some(0)
    } else {
        u32::from_str_radix(significatifs, if hexa { 16 } else { 10 }).ok()
    };
    let c = valeur
        .filter(|v| *v != 0)
        .and_then(char::from_u32)
        .unwrap_or('\u{fffd}');
    Some((c, longueur))
}

/// Les entités HTML courantes décodées (« &amp; », « &#39; », « &#x2F; », « &colon; »…) ; une inconnue reste telle
/// quelle. Celles qui écrivent une adresse (« https&colon;// », « &#104ttps ») y sont, sinon un lien ainsi écrit
/// échapperait à l'examen.
pub(crate) fn entites(t: &str) -> String {
    if !t.contains('&') {
        return t.to_string();
    }
    let mut s = String::with_capacity(t.len());
    let mut reste = t;
    while let Some(p) = reste.find('&') {
        s.push_str(&reste[..p]);
        reste = &reste[p..];
        if let Some((c, longueur)) = reference_numerique(reste) {
            s.push(c);
            reste = &reste[longueur..];
            continue;
        }
        // Une entité tient en quelques lettres : chercher son « ; » plus loin relirait le texte à chaque « & ».
        let fin = reste.bytes().skip(1).take(10).position(|c| c == b';').map(|f| f + 1);
        let decode = fin.and_then(|f| {
            let nom = &reste[1..f];
            let c = match nom {
                "amp" => Some(Some('&')),
                "lt" => Some(Some('<')),
                "gt" => Some(Some('>')),
                "quot" => Some(Some('"')),
                "apos" => Some(Some('\'')),
                "nbsp" => Some(Some('\u{a0}')),
                "colon" => Some(Some(':')),
                "sol" => Some(Some('/')),
                "bsol" => Some(Some('\\')),
                "period" => Some(Some('.')),
                "quest" => Some(Some('?')),
                "equals" => Some(Some('=')),
                "commat" => Some(Some('@')),
                "num" => Some(Some('#')),
                "percnt" => Some(Some('%')),
                // Retirées de l'adresse par le navigateur.
                "Tab" | "NewLine" => Some(None),
                _ => None,
            };
            c.map(|c| (c, f + 1))
        });
        if let Some((c, longueur)) = decode {
            s.extend(c);
            reste = &reste[longueur..];
        } else {
            s.push('&');
            reste = &reste[1..];
        }
    }
    s.push_str(reste);
    s
}

/// Une adresse lue dans un texte, au plus (comme `HTML_MAX` pour le HTML).
const ADRESSE_TEXTE_MAX: usize = 8_192;

/// Les adresses écrites dans un texte : « http:// », « https:// », « www. », et désamorcées (« hxxp:// »).
pub(crate) fn liens_texte(texte: &str, max: usize, source: &Source) -> Vec<LienTrouve> {
    const DEBUTS: [&str; 5] = ["http://", "https://", "hxxp://", "hxxps://", "www."];
    let mut liens = Vec::new();
    let bas = texte.to_ascii_lowercase();
    // La prochaine place de chaque début, recherchée seulement quand on l'a dépassée : un texte de 50 Mo sans aucun
    // « www. » ne doit pas être relu à chaque lien trouvé.
    let mut prochains = [0_usize; 5];
    let chercher = |depuis: usize, prochains: &mut [usize; 5]| {
        for (m, prochain) in DEBUTS.iter().zip(prochains.iter_mut()) {
            if *prochain != usize::MAX && *prochain < depuis {
                *prochain = bas[depuis..].find(m).map_or(usize::MAX, |p| depuis + p);
            }
        }
        prochains.iter().copied().min().filter(|p| *p != usize::MAX)
    };
    let mut i = 0;
    // Le premier tour cherche depuis 0 : les places valent 0, « dépassées » seulement après.
    for (m, prochain) in DEBUTS.iter().zip(prochains.iter_mut()) {
        *prochain = bas.find(m).unwrap_or(usize::MAX);
    }
    while i < bas.len() && liens.len() < max {
        let Some(debut) = chercher(i, &mut prochains) else {
            break;
        };
        // « www. » au milieu d'un mot (« awww.example ») n'est pas un début d'adresse.
        let mot_avant = texte[..debut].chars().next_back().is_some_and(char::is_alphanumeric);
        let fin = texte[debut..]
            .find(|c: char| c.is_whitespace() || "<>\"'`«»".contains(c))
            .map_or(texte.len(), |p| debut + p);
        let adresse = texte[debut..fin].trim_end_matches(['.', ',', ';', ':', '!', '?', ')', ']', '}']);
        // Le site est au début : 8 Ko suffisent à le lire. Une « adresse » de 45 Mo sans espace occuperait sinon
        // chaque examen des secondes, et la mémoire en proportion.
        let mut borne = adresse.len().min(ADRESSE_TEXTE_MAX);
        while !adresse.is_char_boundary(borne) {
            borne -= 1;
        }
        let adresse = &adresse[..borne];
        if !mot_avant && adresse.len() > 4 {
            liens.push(LienTrouve {
                cible: adresse.to_string(),
                affiche: None,
                source: source.clone(),
            });
        }
        i = fin.max(debut + 1);
        while !texte.is_char_boundary(i) {
            i += 1;
        }
    }
    liens
}

/// Ce que l'examen des liens a trouvé.
#[derive(Debug, Default)]
pub(crate) struct ExamenLiens {
    /// Par site : le site, un lien d'exemple, d'où il vient, ses signes.
    pub par_site: Vec<(String, String, Source, Vec<Signe>)>,
    /// Liens dont le texte montre une autre adresse.
    pub trompeurs: Vec<Signe>,
    /// Sites au-delà de la borne, pas examinés.
    pub non_examines: usize,
    /// Liens examinés.
    pub examines: usize,
    /// Ce qui n'a pas pu être vérifié (adresse illisible, vraie destination cachée par un filtre).
    pub manques: Vec<String>,
}

/// Les liens qui ne mènent pas à un site : écrire un courriel, appeler, une partie du courriel lui-même, une ancre.
fn sans_site(cible: &str) -> bool {
    let bas = cible.trim().to_ascii_lowercase();
    bas.is_empty()
        || bas.starts_with('#')
        || ["mailto:", "tel:", "sms:", "cid:", "mid:", "about:blank"]
            .iter()
            .any(|p| bas.starts_with(p))
}

/// Un lien relatif (« page.html », « /x ») : sans « <base> », il ne mène nulle part depuis un courriel.
fn relatif(cible: &str) -> bool {
    let bas = cible.trim().to_ascii_lowercase();
    let schema = bas
        .split_once(':')
        .is_some_and(|(s, _)| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c)));
    !schema && !bas.starts_with("//") && !bas.starts_with("www.")
}

/// Les liens réécrits par un filtre de sécurité (Microsoft Safe Links, Proofpoint, Google) : la vraie destination est
/// dans le lien ; c'est elle qu'on juge.
fn deballer(cible: &str) -> String {
    let bas = cible.to_ascii_lowercase();
    let parametre = |nom: &str| {
        let requete = cible.split_once('?')?.1;
        requete
            .split('&')
            .find_map(|p| {
                p.split_once('=')
                    .filter(|(k, _)| k.eq_ignore_ascii_case(nom))
                    .map(|(_, v)| v)
            })
            .map(|v| String::from_utf8_lossy(&pourcents(v)).into_owned())
    };
    let brut = |nom: &str| {
        cible.split_once('?')?.1.split('&').find_map(|p| {
            p.split_once('=')
                .filter(|(k, _)| k.eq_ignore_ascii_case(nom))
                .map(|(_, v)| v.to_string())
        })
    };
    let hote = lien::examiner_lien(cible).map(|(s, _)| s).unwrap_or_default();
    if hote == "proofpoint.com" && bas.contains("urldefense.proofpoint.com/v2/url") {
        // Proofpoint v2 : « - » tient lieu de « % » et « _ » de « / » (« https-3A__site.example_page »).
        if let Some(u) = brut("u") {
            return String::from_utf8_lossy(&pourcents(&u.replace('-', "%").replace('_', "/"))).into_owned();
        }
    } else if hote == "google.com"
        && let Some(p) = bas.find("google.com/amp/s/")
    {
        // Google AMP : « google.com/amp/s/site.example/page » ouvre site.example.
        return format!("https://{}", &cible[p + "google.com/amp/s/".len()..]);
    }
    if hote == "outlook.com" && bas.contains("safelinks.protection.outlook.com") {
        if let Some(v) = parametre("url") {
            return v;
        }
    } else if hote == "urldefense.com"
        && let Some(p) = cible.find("/v3/__")
    {
        let reste = &cible[p + 6..];
        if let Some(f) = reste.find("__;") {
            return reste[..f].to_string();
        }
    } else if hote == "google.com"
        && bas.contains("google.com/url?")
        && let Some(v) = parametre("q").or_else(|| parametre("url"))
    {
        return v;
    }
    cible.to_string()
}

fn pourcents(v: &str) -> Vec<u8> {
    let o = v.as_bytes();
    let mut s = Vec::with_capacity(o.len());
    let mut i = 0;
    while let Some(&c) = o.get(i) {
        if c == b'%'
            && let Some(h) = v.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            s.push(h);
            i += 3;
            continue;
        }
        s.push(if c == b'+' { b' ' } else { c });
        i += 1;
    }
    s
}

/// Services d'envoi d'infolettres : ils font passer chaque lien par chez eux pour compter les clics. Un texte qui montre
/// une adresse et mène chez eux est courant, et pas une ruse.
/// Filtres de sécurité d'entreprise qui réécrivent tous les liens sans garder la vraie adresse en clair : la vraie
/// destination n'est connue que de leur serveur.
const PASSERELLES: &str = "mimecast.com mimecastprotect.com cudasvc.com sophos.com trendmicro.com \
proofpoint.com urldefense.com";

/// Domaines d'une marque où n'importe qui publie (stockage, formulaires, partages, liens vers un numéro) : un texte
/// qui montre la marque et y mène peut mener à une page piégée.
const OUVERTS_A_TOUS: &str = "amazonaws.com googleapis.com sharepoint.com office.com live.com onedrive.com \
docusign.net wa.me t.me youtube.com youtu.be";

const SUIVI_DES_CLICS: &str = "sendgrid.net list-manage.com mailchimp.com mcsv.net rs6.net exct.net awstrack.me \
mandrillapp.com mailgun.org sparkpostmail.com hubspotlinks.com hs-sites.com klclick.com klclick1.com ctctcdn.com \
cmail19.com cmail20.com createsend1.com mailjet.com sendinblue.com brevo.com";

/// Un texte affiché qui ressemble à une adresse : il commence par « http », « www. », ou c'est un nom de domaine
/// (« paypal.com »), pas un nom de fichier (« facture.pdf »).
fn ressemble_a_une_adresse(t: &str) -> bool {
    let t = t.trim();
    if t.is_empty() || t.contains(char::is_whitespace) {
        return false;
    }
    let bas = t.to_ascii_lowercase();
    if bas.starts_with("http://") || bas.starts_with("https://") || bas.starts_with("www.") || bas.starts_with("hxxp") {
        return true;
    }
    let hote = bas.split(['/', '?', '#']).next().unwrap_or("");
    let fin = hote.rsplit('.').next().unwrap_or("");
    hote.contains('.')
        && !hote.contains('@')
        && fin.len() >= 2
        && fin.chars().all(|c| c.is_ascii_alphabetic())
        && !matches!(
            fin,
            "pdf"
                | "doc"
                | "docx"
                | "xls"
                | "xlsx"
                | "ppt"
                | "pptx"
                | "txt"
                | "jpg"
                | "jpeg"
                | "png"
                | "gif"
                | "html"
                | "htm"
                | "exe"
                | "csv"
                | "odt"
                | "rtf"
        )
}

/// Examine chaque lien : par site (au plus `max_sites`), avec les règles de « Ce lien est-il dangereux ? » ; et chaque
/// texte qui montre une autre adresse que la vraie.
pub(crate) fn examiner_liens(liens: &[LienTrouve], max_sites: usize) -> ExamenLiens {
    let mut r = ExamenLiens::default();
    let mut trompeurs_vus: Vec<String> = Vec::new();
    // Les sites au-delà de la borne, comptés une fois chacun.
    let mut hors_borne = std::collections::HashSet::new();
    let mut illisibles = 0;
    let mut passerelles: Vec<String> = Vec::new();
    // Un lien qu'on ne sait pas lire ne passe pas pour rien : son texte montre une adresse, ou son adresse est écrite
    // d'une façon qu'on ne décode pas.
    let mut illisible = |l: &LienTrouve, r: &mut ExamenLiens| {
        let montre = l
            .affiche
            .as_deref()
            .map(|a| a.chars().filter(|c| !piege(*c)).collect::<String>())
            .filter(|a| ressemble_a_une_adresse(a));
        if montre.is_none() && !l.cible.contains(['&', '\\']) {
            return;
        }
        illisibles += 1;
        if let Some(a) = montre
            && r.trompeurs.len() < 50
        {
            let texte_montre = crate::ui::couper(&affichable(&a), 60);
            r.trompeurs.push((
                Niveau::Moyen,
                trf!(
                    "Le lien affiche « {texte_montre} », mais sa vraie adresse est écrite d'une façon que Vanguard ne lit pas.",
                    "The link shows “{texte_montre}”, but its real address is written in a way Vanguard cannot read."
                ),
            ));
        }
    };
    for l in liens {
        if sans_site(&l.cible) {
            continue;
        }
        if relatif(&l.cible) {
            illisible(l, &mut r);
            continue;
        }
        let cible = deballer(&l.cible);
        let cible = if cible.starts_with("//") {
            format!("https:{cible}")
        } else {
            cible
        };
        let Some((site, signes)) = lien::examiner_lien(&cible) else {
            illisible(l, &mut r);
            continue;
        };
        r.examines += 1;
        if PASSERELLES.split_whitespace().any(|p| p == site) && !passerelles.contains(&site) {
            passerelles.push(site.clone());
        }
        let cle = if site.is_empty() {
            cible.chars().take(60).collect()
        } else {
            site.clone()
        };
        if let Some((_, _, _, existants)) = r.par_site.iter_mut().find(|(s, _, _, _)| *s == cle) {
            for s in signes {
                if !existants.contains(&s) {
                    existants.push(s);
                }
            }
        } else if r.par_site.len() < max_sites {
            r.par_site.push((cle, cible.clone(), l.source.clone(), signes));
        } else {
            hors_borne.insert(cle);
            r.non_examines = hors_borne.len();
        }
        // Le texte montré : caractères invisibles retirés avant de comparer (« pay​pal.com » coupé par U+200B reste
        // « paypal.com »).
        let Some(affiche) = &l.affiche else {
            continue;
        };
        let propre: String = affiche.chars().filter(|c| !piege(*c)).collect();
        if site.is_empty() || !ressemble_a_une_adresse(&propre) {
            continue;
        }
        let Some((site_montre, _)) = lien::examiner_lien(&propre).filter(|(s, _)| !s.is_empty()) else {
            continue;
        };
        if site_montre == site || trompeurs_vus.len() >= 50 {
            continue;
        }
        let texte_montre: String = crate::ui::couper(&affichable(affiche), 60);
        let cle = format!("{site_montre}→{site}");
        if trompeurs_vus.contains(&cle) {
            continue;
        }
        trompeurs_vus.push(cle);
        // Deux domaines d'une même marque (« rbc.com » qui mène à rbcroyalbank.com) : courant dans ses infolettres.
        // Pas quand la cible est un de ses domaines où n'importe qui publie.
        let ouvert = |s: &str| {
            OUVERTS_A_TOUS
                .split_whitespace()
                .any(|o| s == o || s.ends_with(&format!(".{o}")))
        };
        let meme_marque = !ouvert(&site)
            && lien::marque_officielle(&site_montre).is_some_and(|m| lien::marque_officielle(&site) == Some(m));
        if PASSERELLES.split_whitespace().any(|s| s == site) {
            r.trompeurs.push((
                Niveau::Info,
                trf!(
                    "Le lien affiche « {texte_montre} » mais passe par {site}, le filtre de sécurité de votre organisation ; la vraie destination n'a pas pu être vérifiée.",
                    "The link shows “{texte_montre}” but goes through {site}, your organization's security filter; the real destination could not be checked."
                ),
            ));
        } else if meme_marque {
            r.trompeurs.push((
                Niveau::Info,
                trf!(
                    "Le lien affiche « {texte_montre} » mais mène à {site}, un autre domaine de la même marque.",
                    "The link shows “{texte_montre}” but leads to {site}, another domain of the same brand."
                ),
            ));
        } else if SUIVI_DES_CLICS.split_whitespace().any(|s| s == site) {
            r.trompeurs.push((
                Niveau::Info,
                trf!(
                    "Le lien affiche « {texte_montre} » mais passe d'abord par {site}, un service d'infolettres qui compte les clics (courant).",
                    "The link shows “{texte_montre}” but first goes through {site}, a newsletter service that counts clicks (common)."
                ),
            ));
        } else {
            r.trompeurs.push((
                Niveau::Eleve,
                trf!(
                    "Le lien affiche « {texte_montre} » mais mène à {site}.",
                    "The link shows “{texte_montre}” but leads to {site}."
                ),
            ));
        }
    }
    if illisibles > 0 {
        r.manques.push(trf!(
            "{illisibles} lien(s) à l'adresse illisible",
            "{illisibles} link(s) with an unreadable address"
        ));
    }
    if !passerelles.is_empty() {
        r.manques.push(trf!(
            "la vraie destination des liens réécrits par {}",
            "the real destination of the links rewritten by {}",
            passerelles.join(", ")
        ));
    }
    r
}

/// Ce que le HTML montre d'autre que ses liens : formulaire, redirection automatique, lecture coupée. (La base est
/// ajoutée aux liens, et les images distantes comptées, par l'appelant.)
pub(crate) fn signes_html(h: &Html, ou: &str) -> Vec<Signe> {
    let mut signes = Vec::new();
    if !h.formulaires.is_empty() {
        let cible = h
            .formulaires
            .iter()
            .find_map(|a| lien::examiner_lien(a).map(|(s, _)| s).filter(|s| !s.is_empty()));
        signes.push((
            Niveau::Eleve,
            match cible {
                Some(site) => trf!(
                    "Formulaire {ou} (envoyé à {site}) : un vrai service ne vous fait jamais taper votre mot de passe dans un courriel.",
                    "Form {ou} (sent to {site}): a real service never has you type your password in an email."
                ),
                None => trf!(
                    "Formulaire {ou} : un vrai service ne vous fait jamais taper votre mot de passe dans un courriel.",
                    "Form {ou}: a real service never has you type your password in an email."
                ),
            },
        ));
    }
    if let Some(c) = &h.rafraichit {
        let site = lien::examiner_lien(c).map(|(s, _)| s).filter(|s| !s.is_empty());
        signes.push((
            Niveau::Moyen,
            trf!(
                "Redirection automatique {ou} vers {} : la page part ailleurs sans clic.",
                "Automatic redirect {ou} to {}: the page goes elsewhere without a click.",
                site.unwrap_or_else(|| crate::ui::couper(&affichable(c), 40))
            ),
        ));
    }
    if h.coupe {
        signes.push((
            Niveau::Info,
            tr!(
                "HTML très long : seuls ses premiers liens ont été lus.",
                "Very long HTML: only its first links were read."
            )
            .to_string(),
        ));
    }
    signes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn html(t: &str) -> Html {
        lire_html(t, 1_000, &Source::Html)
    }

    fn pire(signes: &[Signe]) -> Option<Niveau> {
        signes.iter().map(|(n, _)| *n).max()
    }

    #[test]
    fn lien_deguise() {
        let h = html("<p>Bonjour</p><a href=\"https://paypa1.example/login\">https://www.paypal.com</a>");
        assert_eq!(h.liens.len(), 1);
        assert_eq!(h.liens[0].affiche.as_deref(), Some("https://www.paypal.com"));
        let e = examiner_liens(&h.liens, 50);
        assert_eq!(pire(&e.trompeurs), Some(Niveau::Eleve));
        assert!(e.trompeurs[0].1.contains("paypa1.example"));
        // Le site lui-même imite PayPal.
        assert_eq!(pire(&e.par_site[0].3), Some(Niveau::Eleve));
        // Texte ordinaire, ou même site : rien de trompeur.
        let e = examiner_liens(&html("<a href=https://example.com/x>Cliquez ici</a>").liens, 50);
        assert_eq!(e.trompeurs, Vec::<Signe>::new());
        let e = examiner_liens(&html("<a href='https://www.example.com/a'>example.com</a>").liens, 50);
        assert_eq!(e.trompeurs, Vec::<Signe>::new());
        // Un nom de fichier n'est pas une adresse.
        let e = examiner_liens(&html("<a href='https://example.com/f'>facture.pdf</a>").liens, 50);
        assert_eq!(e.trompeurs, Vec::<Signe>::new());
    }

    #[test]
    fn attributs_tolerants() {
        let h = html("<A HREF=https://example.com/a?b=1&amp;c=2>x</A><a\nhref=\"https://exam\nple.org/\"\n>y</a>");
        assert_eq!(h.liens[0].cible, "https://example.com/a?b=1&c=2");
        assert_eq!(h.liens[1].cible, "https://example.org/");
        // Commentaire et script : pas des liens.
        let h = html(
            "<!-- <a href='https://cache.example'>x</a> --><script>var a='<a href=\"https://s.example\">';</script><a href='https://vu.example'>v</a>",
        );
        assert_eq!(
            h.liens.iter().map(|l| l.cible.as_str()).collect::<Vec<_>>(),
            ["https://vu.example"]
        );
        // Lien jamais fermé : gardé quand même.
        let h = html("<a href='https://a.example'>un <a href='https://b.example'>deux");
        assert_eq!(h.liens.len(), 2);
        assert_eq!(h.liens[0].affiche.as_deref(), Some("un"));
    }

    /// Relecture du lot campagne 6 : seuls `script` et `style` sans préfixe se sautent jusqu'à leur fermeture. Un
    /// `<o:script>` est, pour un client de messagerie, un élément inconnu qui montre son contenu : non fermé, il ne
    /// doit pas avaler le reste du courriel.
    #[test]
    fn script_prefixe_non_saute() {
        for debut in ["<o:script>", "<x:style>", "<o:script >"] {
            let h = html(&format!("{debut}<a href=\"https://paypa1-login.example/\">Payer</a>"));
            assert_eq!(
                h.liens.iter().map(|l| l.cible.as_str()).collect::<Vec<_>>(),
                ["https://paypa1-login.example/"],
                "{debut}"
            );
        }
        // Sans préfixe, le contenu reste sauté.
        let h = html("<SCRIPT>x='<a href=\"https://s.example/\">'</script><a href='https://vu.example/'>v</a>");
        assert_eq!(
            h.liens.iter().map(|l| l.cible.as_str()).collect::<Vec<_>>(),
            ["https://vu.example/"]
        );
    }

    /// Une image SVG minimale autour de `corps`.
    fn svg(corps: &str) -> Vec<u8> {
        format!("<svg xmlns=\"http://www.w3.org/2000/svg\">{corps}</svg>").into_bytes()
    }

    /// Relecture du lot campagne 6 : un préfixe XML peut porter `_`, `.` ou une lettre non ASCII ; le nom lu ne
    /// s'arrête plus avant le nom local.
    #[test]
    fn svg_prefixe_xml_large() {
        for corps in [
            "<a_b:script xmlns:a_b=\"http://www.w3.org/2000/svg\">alert(1)</a_b:script>",
            "<s.v:script xmlns:s.v=\"http://www.w3.org/2000/svg\">alert(1)</s.v:script>",
            "<é:script xmlns:é=\"http://www.w3.org/2000/svg\">alert(1)</é:script>",
            "<_:foreignObject xmlns:_=\"http://www.w3.org/2000/svg\"/>",
        ] {
            assert_eq!(svg_actif(&svg(corps)), Some(true), "{corps}");
        }
        assert_eq!(
            svg_actif(&svg("<a_b:rect xmlns:a_b=\"http://www.w3.org/2000/svg\"/>")),
            Some(false)
        );
    }

    /// Relecture du lot campagne 6 : une entité déclarée dans la DTD (ou un attribut par défaut) peut porter le
    /// script ou l'adresse `javascript:` ; la lecture ne les déroule pas, l'image se dit active.
    #[test]
    fn svg_declarations_de_la_dtd() {
        for debut in [
            "<!DOCTYPE svg [<!ENTITY s \"&#60;script&#62;alert(1)&#60;/script&#62;\">]>",
            "<!DOCTYPE svg [<!ENTITY j \"javascript:\">]>",
            "<!DOCTYPE svg [\n  <!entity j \"javascript:\">\n]>",
            "<!DOCTYPE svg [<!ATTLIST svg onload CDATA \"alert(1)\">]>",
        ] {
            let mut h = debut.as_bytes().to_vec();
            h.extend(svg("<a href=\"&j;alert(1)\"><text>&s;</text></a>"));
            assert_eq!(svg_actif(&h), Some(true), "{debut}");
        }
        let mut h =
            b"<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">"
                .to_vec();
        h.extend(svg("<rect/>"));
        assert_eq!(svg_actif(&h), Some(false));
    }

    /// Relecture du lot campagne 6 : une feuille de style XSLT intégrée (`<?xml-stylesheet?>`) transforme l'image
    /// avant qu'elle soit montrée.
    #[test]
    fn svg_feuille_de_style_xml() {
        for debut in [
            "<?xml-stylesheet type=\"text/xsl\" href=\"#x\"?>",
            "<?xml version=\"1.0\"?>\n<?XML-STYLESHEET href=\"x.xsl\"?>",
        ] {
            let mut h = debut.as_bytes().to_vec();
            h.extend(svg("<rect/>"));
            assert_eq!(svg_actif(&h), Some(true), "{debut}");
        }
        let mut h = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>".to_vec();
        h.extend(svg("<rect/>"));
        assert_eq!(svg_actif(&h), Some(false));
    }

    /// Relecture du lot campagne 6 : un cadre ou un objet HTML, préfixé ou non, charge une autre page sans
    /// `foreignObject`.
    #[test]
    fn svg_cadre_ou_objet() {
        for corps in [
            "<h:iframe xmlns:h=\"http://www.w3.org/1999/xhtml\" src=\"https://vol.example/\"/>",
            "<h:embed xmlns:h=\"http://www.w3.org/1999/xhtml\" src=\"https://vol.example/\"/>",
            "<h:object xmlns:h=\"http://www.w3.org/1999/xhtml\" data=\"https://vol.example/\"/>",
            "<iframe src=\"https://vol.example/\"/>",
        ] {
            assert_eq!(svg_actif(&svg(corps)), Some(true), "{corps}");
        }
    }

    /// Relecture du lot campagne 6 : une animation SMIL qui vise un gestionnaire d'événement ou l'adresse d'un lien
    /// change ce que fait l'image, quelle que soit la valeur donnée.
    #[test]
    fn svg_animation_d_un_gestionnaire_ou_d_un_lien() {
        let cinquante = "a ".repeat(50);
        for corps in [
            "<set attributeName=\"onload\" to=\"alert(1)\"/>".to_string(),
            "<animate attributeName=\"ONCLICK\" values=\"alert(1)\"/>".to_string(),
            "<a><set attributeName=\"href\" to=\"&j;alert(1)\"/><text>x</text></a>".to_string(),
            "<a><animate attributeName=\"xlink:href\" values=\"https://vol.example/\"/><text>x</text></a>".to_string(),
            format!("<set {cinquante}attributeName=\"onbegin\" to=\"alert(1)\"/>"),
        ] {
            assert_eq!(svg_actif(&svg(&corps)), Some(true), "{corps}");
        }
        assert_eq!(
            svg_actif(&svg("<animate attributeName=\"opacity\" values=\"0;1\"/>")),
            Some(false)
        );
    }

    #[test]
    fn texte_coupe_par_un_invisible() {
        let h = html("<a href='https://paypa1.example/'>pay\u{200b}pal.com</a>");
        let e = examiner_liens(&h.liens, 50);
        assert_eq!(pire(&e.trompeurs), Some(Niveau::Eleve));
        assert!(e.trompeurs[0].1.contains('\u{fffd}'), "{:?}", e.trompeurs);
    }

    #[test]
    fn javascript_formulaire_base_et_refresh() {
        let h = html(
            "<base href='https://base.example/'><form action='https://vol.example/post'><input name=mdp></form>\
<meta http-equiv=\"Refresh\" content=\"0; URL='https://ailleurs.example/'\"><a href='javascript:alert(1)'>x</a>\
<img src='https://pisteur.example/p.gif'><img src='cid:logo'>",
        );
        assert_eq!(h.base.as_deref(), Some("https://base.example/"));
        assert_eq!(h.formulaires, ["https://vol.example/post"]);
        assert_eq!(h.rafraichit.as_deref(), Some("https://ailleurs.example/"));
        assert_eq!((h.images, h.images_distantes), (2, 1));
        let s = signes_html(&h, "dans le courriel");
        assert_eq!(pire(&s), Some(Niveau::Eleve));
        assert!(
            s.iter()
                .any(|(n, t)| *n == Niveau::Moyen && t.contains("ailleurs.example"))
        );
        let e = examiner_liens(&h.liens, 50);
        assert_eq!(pire(&e.par_site[0].3), Some(Niveau::Critique));
    }

    #[test]
    fn borne_des_liens() {
        let beaucoup = "<a href='https://x.example/'>x</a>".repeat(10_000);
        let h = html(&beaucoup);
        assert_eq!(h.liens.len(), 1_000);
        assert!(h.coupe);
        let liens: Vec<LienTrouve> = (0..100)
            .map(|i| LienTrouve {
                cible: format!("https://site{i}.example/"),
                affiche: None,
                source: Source::Texte,
            })
            .collect();
        let e = examiner_liens(&liens, 50);
        assert_eq!((e.par_site.len(), e.non_examines), (50, 50));
    }

    #[test]
    fn liens_du_texte() {
        let l = liens_texte(
            "Va sur https://example.com/a. Ou www.example.org, ou hxxp://piege[.]example/x (désamorcé). awww.non",
            10,
            &Source::Texte,
        );
        let cibles: Vec<&str> = l.iter().map(|l| l.cible.as_str()).collect();
        assert_eq!(
            cibles,
            ["https://example.com/a", "www.example.org", "hxxp://piege[.]example/x"]
        );
        assert_eq!(liens_texte("é https://é.example/ à", 10, &Source::Texte).len(), 1);
    }

    #[test]
    fn liens_qui_ne_menent_a_aucun_site() {
        let h = html(
            "<a href='mailto:alice@example.com'>a</a><a href='#haut'>h</a><a href='tel:+15550100'>t</a><a href='page.html'>p</a>",
        );
        let e = examiner_liens(&h.liens, 50);
        assert_eq!(e.examines, 0);
        assert_eq!(e.par_site.len(), 0);
    }

    #[test]
    fn liens_reecrits_par_un_filtre() {
        let h = html(
            "<a href='https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fpaypa1.example%2Flogin&data=x'>https://www.paypal.com</a>",
        );
        let e = examiner_liens(&h.liens, 50);
        assert_eq!(e.par_site[0].0, "paypa1.example");
        assert_eq!(pire(&e.trompeurs), Some(Niveau::Eleve));
        // Infolettre : le compteur de clics n'est pas une ruse.
        let h = html("<a href='https://u1.ct.sendgrid.net/ls/click?x'>www.example.com</a>");
        let e = examiner_liens(&h.liens, 50);
        assert_eq!(pire(&e.trompeurs), Some(Niveau::Info));
    }

    #[test]
    fn entites_html() {
        assert_eq!(
            entites("a&amp;b&lt;&#39;&#x2F;&nbsp;&inconnue;&"),
            "a&b<'/\u{a0}&inconnue;&"
        );
        // Comme le navigateur : « ; » facultatif après un nombre, entités d'adresse, valeur impossible en « � ».
        assert_eq!(
            entites("&#104ttps&colon;&sol;&sol;x&period;example"),
            "https://x.example"
        );
        assert_eq!(entites("&#x68;&#0;&#99999999999;&#;"), "h\u{fffd}\u{fffd}&#;");
        assert_eq!(entites("a&Tab;b&NewLine;c"), "abc");
    }

    #[test]
    fn adresses_ecrites_pour_echapper() {
        for href in [
            "&#104ttps://paypa1-login.example/connexion",
            "https&colon;//paypa1-login.example/connexion",
            "https:\\\\paypa1-login.example\\connexion",
            "ht\ttps://paypa1-login.example/connexion",
        ] {
            let h = html(&format!("<a href=\"{href}\">https://www.paypal.com</a>"));
            let e = examiner_liens(&h.liens, 50);
            assert_eq!(e.examines, 1, "{href}");
            assert_eq!(e.par_site[0].0, "paypa1-login.example", "{href}");
            assert_eq!(pire(&e.trompeurs), Some(Niveau::Eleve), "{href}");
        }
        // Une adresse qu'on ne sait pas lire, sous un texte qui montre une adresse : dite, jamais passée pour rien.
        let h = html("<a href=\"&unknown;//paypa1-login.example/\">https://www.paypal.com</a>");
        let e = examiner_liens(&h.liens, 50);
        assert_eq!(pire(&e.trompeurs), Some(Niveau::Moyen));
        assert_ne!(e.manques, Vec::<String>::new());
        // Un vrai lien relatif sous un texte ordinaire : rien.
        let e = examiner_liens(&html("<a href='page.html'>la page</a>").liens, 50);
        assert!(e.manques.is_empty() && e.trompeurs.is_empty());
    }

    #[test]
    fn meme_marque_et_passerelles() {
        let h = html(
            "<a href=\"https://www.rbcroyalbank.com/fr/\">rbc.com</a> <a href=\"https://www.amazon.com/x\">amazon.ca</a>",
        );
        let e = examiner_liens(&h.liens, 50);
        assert_eq!(pire(&e.trompeurs), Some(Niveau::Info), "{:?}", e.trompeurs);
        // Un compartiment de stockage, où n'importe qui publie, n'est pas « la même marque ».
        let h = html("<a href=\"https://piege.s3.amazonaws.com/x\">amazon.ca</a>");
        assert_eq!(pire(&examiner_liens(&h.liens, 50).trompeurs), Some(Niveau::Eleve));
        // Mimecast : pas une ruse, mais la vraie destination n'est pas vérifiée.
        let h = html("<a href=\"https://protect-us.mimecast.com/s/abc\">www.example.com</a>");
        let e = examiner_liens(&h.liens, 50);
        assert_eq!(pire(&e.trompeurs), Some(Niveau::Info));
        assert!(e.manques.iter().any(|m| m.contains("mimecast.com")), "{:?}", e.manques);
        // Proofpoint v2 et Google AMP : la vraie destination est dans le lien.
        let h = html(
            "<a href=\"https://urldefense.proofpoint.com/v2/url?u=https-3A__paypa1-2Dlogin.example_connexion&d=x\">https://www.paypal.com</a>\
<a href=\"https://www.google.com/amp/s/paypa1-login.example/connexion\">x</a>",
        );
        let e = examiner_liens(&h.liens, 50);
        assert_eq!(
            e.par_site.iter().map(|(s, _, _, _)| s.as_str()).collect::<Vec<_>>(),
            ["paypa1-login.example"]
        );
        assert_eq!(pire(&e.trompeurs), Some(Niveau::Eleve));
        assert!(e.manques.is_empty(), "{:?}", e.manques);
    }

    #[test]
    fn adresse_geante_bornee() {
        let texte = format!("voir {}", "www.a".repeat(200_000));
        let l = liens_texte(&texte, 10, &Source::Texte);
        assert_eq!(l.len(), 1);
        assert!(l[0].cible.len() <= ADRESSE_TEXTE_MAX);
        // Son hôte dépasse 253 octets : pas un site, et vite écarté.
        let debut = std::time::Instant::now();
        let e = examiner_liens(&l, 50);
        assert_eq!(e.examines, 0);
        assert!(debut.elapsed() < std::time::Duration::from_secs(5));
    }
}

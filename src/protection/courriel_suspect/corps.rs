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
/// Un nom d'entité tient en peu d'octets (Illustrator : « ns_adobe_xpath ») : `derouler` ne cherche pas son « ; » plus
/// loin, et `lire_entite` refuse un nom plus long, que le déroulé laisserait tel quel (relecture A des restes c6).
const NOM_ENTITE_MAX: usize = 64;

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

/// Ce que porte une image SVG (`juger_svg`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Svg {
    /// Rien qui tourne, rien de déclaré.
    Inerte,
    /// Des déclarations XML lues jusqu'au bout, sans rien d'actif : entités internes (les espaces de noms
    /// qu'Illustrator déclare dans sa DTD), feuille de style CSS (`<?xml-stylesheet type="text/css"?>`).
    Declarations,
    /// Du code qui tourne à l'ouverture, ou une déclaration qui peut en cacher.
    Actif,
}

/// Une image SVG (ou une page XML) porte du code qui tourne à son ouverture : élément `script` ou `foreignObject`
/// (du HTML dans l'image), cadre ou objet HTML (`iframe`, `embed`, `object`), préfixe compris, gestionnaire
/// d'événement, adresse `javascript:` ou animation qui vise l'un ou l'autre. Les déclarations de la DTD sont lues :
/// une entité interne est déroulée dans l'image avant de la lire (`&j;` qui vaut « javascript: » dans un lien se
/// voit), et son texte ne doit porter ni balise, ni gestionnaire, ni adresse qui exécute ; une entité externe ou
/// paramètre, une valeur d'attribut par défaut (`<!ATTLIST`), ce que la lecture ne connaît pas ou ne sait pas
/// dérouler (le « milliard de rires ») rendent l'image active. Une feuille de style XML n'est sûre qu'en CSS : XSLT
/// transforme l'image (relecture du lot campagne 6 ; le reste, B-2 de sa relecture). Au-delà de `HTML_MAX` octets,
/// rien n'est lu : `None`, à dire comme un manque ; de même quand `echeance` passe avant la fin de la lecture (une
/// forme de document qui la ralentirait ne doit pas tenir l'examen du courriel). Une image en UTF-16 est lue
/// transcodée (`svg_utf8`).
pub(crate) fn juger_svg(h: &[u8], echeance: Option<std::time::Instant>) -> Option<Svg> {
    let h = svg_utf8(h)?;
    let h: &[u8] = &h;
    if h.len() > HTML_MAX {
        return None;
    }
    let mut declarations = false;
    let mut i = 0;
    while let Some(p) = chercher_casse(h, i, b"<?xml-stylesheet") {
        let (balise, suite) = lire_balise(h, p, true);
        // Tous ses `type` en CSS : un second `type` ne doit pas cacher du XSLT derrière le premier.
        let css = balise.is_some_and(|b| {
            let mut types = b.attributs.iter().filter(|(n, _)| n == "type").peekable();
            !b.actif && types.peek().is_some() && types.all(|(_, v)| v.trim().eq_ignore_ascii_case("text/css"))
        });
        if !css {
            return Some(Svg::Actif);
        }
        declarations = true;
        i = suite.max(p.saturating_add(1));
    }
    let mut doc = std::borrow::Cow::Borrowed(h);
    // L'image telle qu'elle est écrite, DTD retirée, quand ses entités ont été déroulées dans `doc`.
    let mut brut = None;
    let mut lues = 0;
    if let Some(debut) = chercher_casse(h, 0, b"<!doctype") {
        let Some(dtd) = lire_dtd(h, debut) else {
            return Some(Svg::Actif);
        };
        lues = dtd.entites.len();
        declarations |= dtd.interne;
        if !dtd.entites.is_empty() {
            let avant = h.get(..debut).unwrap_or_default();
            let apres = h.get(dtd.fin..).unwrap_or_default();
            let Some(suite) = derouler(apres, &dtd.entites, echeance) else {
                // Ce qui ne se déroule pas est actif ; un déroulé arrêté par l'échéance n'a rien vérifié.
                return (!depassee(echeance)).then_some(Svg::Actif);
            };
            let mut d = avant.to_vec();
            d.extend(suite);
            doc = std::borrow::Cow::Owned(d);
            brut = Some([avant, apres].concat());
        }
    }
    // Chaque déclaration de l'image doit être une entité lue plus haut : une autre DTD, une déclaration hors de la
    // DTD ou dans un commentaire de celle-ci ne se lit pas ici.
    let declarees = [b"<!entity".as_slice(), b"<!attlist"]
        .iter()
        .map(|m| compter_casse(h, m))
        .sum::<usize>();
    if declarees != lues {
        return Some(Svg::Actif);
    }
    // Le déroulé, puis le texte écrit : ce que le déroulé masquerait (une entité qui fermerait un attribut et ferait
    // passer le gestionnaire écrit ensuite pour du texte : H-1 de la relecture B des restes c6) reste vu en clair.
    let mut actif = false;
    for texte in [Some(doc.as_ref()), brut.as_deref()].into_iter().flatten() {
        for xml in [true, false] {
            actif = actif || balayer_svg(texte, xml, echeance)?;
        }
    }
    Some(if actif {
        Svg::Actif
    } else if declarations {
        Svg::Declarations
    } else {
        Svg::Inerte
    })
}

/// Le texte d'une image en UTF-16 transcodé en UTF-8 : marque d'ordre des octets (FF FE, FE FF), ou « <? » écrit en
/// UTF-16 sans elle, que les lecteurs XML reconnaissent aussi. Le navigateur exécute le script d'une telle image, et
/// ses balises, lues octet par octet en ASCII, ne se voyaient pas (relecture A des restes c6). Un caractère mal formé
/// (moitié de paire, octet impair à la fin) devient « � », comme dans le navigateur. Tout autre texte est rendu tel
/// quel ; `None` au-delà de `HTML_MAX` octets transcodés.
pub(crate) fn svg_utf8(h: &[u8]) -> Option<std::borrow::Cow<'_, [u8]>> {
    let (gros_boutiste, debut) = match h {
        [0xff, 0xfe, ..] => (false, 2),
        [0xfe, 0xff, ..] => (true, 2),
        [0x3c, 0, 0x3f, 0, ..] => (false, 0),
        [0, 0x3c, 0, 0x3f, ..] => (true, 0),
        _ => return Some(std::borrow::Cow::Borrowed(h)),
    };
    // Chaque caractère d'UTF-16 (2 ou 4 octets) prend au plus 3 octets sur 2 en UTF-8 : le texte se borne d'avance.
    if h.len() > HTML_MAX.saturating_mul(2) {
        return None;
    }
    let unites = h.get(debut..).unwrap_or_default().chunks(2).map(|paire| match *paire {
        [a, b] if gros_boutiste => u16::from_be_bytes([a, b]),
        [a, b] => u16::from_le_bytes([a, b]),
        _ => 0xfffd,
    });
    let mut texte = String::new();
    for c in char::decode_utf16(unites) {
        texte.push(c.unwrap_or('\u{fffd}'));
        if texte.len() > HTML_MAX {
            return None;
        }
    }
    Some(std::borrow::Cow::Owned(texte.into_bytes()))
}

/// Les balises de `h` : l'une lance-t-elle du code ? Un commentaire, un bloc CDATA, une déclaration ou une instruction
/// se sautent comme le ferait un lecteur XML (`xml`) ou HTML : `juger_svg` prend les deux lectures, une image active
/// pour l'une l'est, et ce que l'ancienne lecture (HTML) voyait reste vu. Une passe : chaque octet est relu un nombre
/// borné de fois, quelle que soit la forme du document (`Prochain`). `None` quand `echeance` est passée.
fn balayer_svg(h: &[u8], xml: bool, echeance: Option<std::time::Instant>) -> Option<bool> {
    let mut fins = FinsDeBloc::default();
    let mut i = 0;
    let mut tours = 0_u32;
    while let Some(debut) = h.get(i..).and_then(|ici| ici.iter().position(|&c| c == b'<')) {
        // Dès la première balise, puis toutes les 1024 : lire l'horloge à chacune coûterait plus que la lecture.
        if tours.is_multiple_of(1024) && depassee(echeance) {
            return None;
        }
        tours = tours.wrapping_add(1);
        i += debut;
        let ici = h.get(i..).unwrap_or_default();
        if ici.starts_with(b"<!--") {
            i = fin_du_commentaire(h, i, xml, &mut fins);
            continue;
        }
        if xml && ici.starts_with(b"<![CDATA[") {
            // Un bloc qui ne se ferme pas : la suite est lue comme des balises, plutôt que tue.
            i = fins.cdata.depuis(h, i + 9).map_or(i + 9, |p| p + 3);
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

/// L'échéance est passée.
fn depassee(echeance: Option<std::time::Instant>) -> bool {
    echeance.is_some_and(|e| std::time::Instant::now() >= e)
}

/// La prochaine place d'un marqueur de fin, gardée d'une recherche à l'autre : absent après un indice, il l'est après
/// tout indice plus grand ; une place trouvée sert tant qu'elle n'est pas dépassée. Chercher à chaque ouverture
/// jusqu'au bout relisait le document une fois par commentaire ou par bloc sans fin : 5 Mo de « <!----!> » ou de
/// « <![CDATA[ » tenaient le processeur des dizaines de minutes (relectures A et B des restes c6). Les recherches
/// successives portent sur des tranches disjointes.
struct Prochain {
    marqueur: &'static [u8],
    /// L'indice d'où vient `place`, et `place` elle-même ; `None` avant la première recherche.
    connue: Option<(usize, Option<usize>)>,
}

impl Prochain {
    const fn new(marqueur: &'static [u8]) -> Self {
        Prochain { marqueur, connue: None }
    }

    /// La première place du marqueur à partir de `i`.
    fn depuis(&mut self, h: &[u8], i: usize) -> Option<usize> {
        match self.connue {
            Some((de, place)) if de <= i && place.is_none_or(|p| p >= i) => place,
            _ => {
                let place = chercher_casse(h, i, self.marqueur);
                self.connue = Some((i, place));
                place
            }
        }
    }
}

/// Les marqueurs de fin d'une lecture de `balayer_svg`.
struct FinsDeBloc {
    commentaire: Prochain,
    commentaire_html: Prochain,
    cdata: Prochain,
}

impl Default for FinsDeBloc {
    fn default() -> Self {
        FinsDeBloc {
            commentaire: Prochain::new(b"-->"),
            commentaire_html: Prochain::new(b"--!>"),
            cdata: Prochain::new(b"]]>"),
        }
    }
}

/// L'indice qui suit le commentaire ouvert en `i` (« <!-- »). XML le ferme sur « --> » seul ; HTML aussi sur « --!> »,
/// et ferme aussitôt « <!--> » et « <!---> ». Sans fin, il va jusqu'au bout.
fn fin_du_commentaire(h: &[u8], i: usize, xml: bool, fins: &mut FinsDeBloc) -> usize {
    let apres = i + 4;
    let fleche = fins.commentaire.depuis(h, apres).map(|p| p + 3);
    if xml {
        return fleche.unwrap_or(h.len());
    }
    let reste = h.get(apres..).unwrap_or_default();
    if reste.starts_with(b">") {
        return apres + 1;
    }
    if reste.starts_with(b"->") {
        return apres + 2;
    }
    let bang = fins.commentaire_html.depuis(h, apres).map(|p| p + 4);
    fleche.into_iter().chain(bang).min().unwrap_or(h.len())
}

/// Les occurrences de `aiguille` (ASCII, sans tenir compte de la casse) dans `h`.
fn compter_casse(h: &[u8], aiguille: &[u8]) -> usize {
    let mut n = 0;
    let mut i = 0;
    while let Some(p) = chercher_casse(h, i, aiguille) {
        n += 1;
        i = p + 1;
    }
    n
}

/// La DTD d'une image : où elle finit, si elle a un sous-ensemble interne (`[ … ]`), et ses entités internes
/// (nom, texte de remplacement).
struct Dtd {
    fin: usize,
    interne: bool,
    entites: std::collections::HashMap<Vec<u8>, Vec<u8>>,
}

/// Les entités qu'une image déclare au plus : Illustrator en écrit une dizaine.
const ENTITES_MAX: usize = 256;

/// Lit la DTD qui commence en `debut` (« <!DOCTYPE »). `None` dès qu'elle porte autre chose que des entités internes
/// inoffensives, des éléments, des notations, des commentaires ou des instructions : entité externe ou paramètre,
/// `<!ATTLIST`, référence d'entité paramètre (`%p;`), section conditionnelle, ou une fin qui manque.
fn lire_dtd(h: &[u8], debut: usize) -> Option<Dtd> {
    let mut i = debut.checked_add(9)?;
    // Jusqu'au « [ » du sous-ensemble interne ou au « > » de la fin ; l'identifiant public ou système, entre
    // guillemets, peut porter l'un ou l'autre.
    loop {
        match *h.get(i)? {
            b'>' => {
                return Some(Dtd {
                    fin: i + 1,
                    interne: false,
                    entites: std::collections::HashMap::new(),
                });
            }
            b'[' => break,
            q @ (b'"' | b'\'') => i = apres_guillemet(h, i, q)?,
            _ => i += 1,
        }
    }
    i += 1;
    let mut entites = std::collections::HashMap::new();
    loop {
        i = prendre(h, i, |o| o.is_ascii_whitespace()).1;
        let ici = h.get(i..)?;
        if ici.first() == Some(&b']') {
            i = prendre(h, i + 1, |o| o.is_ascii_whitespace()).1;
            return (h.get(i) == Some(&b'>')).then_some(Dtd {
                fin: i + 1,
                interne: true,
                entites,
            });
        }
        if ici.starts_with(b"<!--") {
            i = chercher_casse(h, i + 4, b"-->")? + 3;
        } else if ici.starts_with(b"<?") {
            i = chercher_casse(h, i + 2, b"?>")? + 2;
        } else if ici.get(..8).is_some_and(|d| d.eq_ignore_ascii_case(b"<!entity")) {
            let (nom, texte, suite) = lire_entite(h, i + 8)?;
            if entites.len() >= ENTITES_MAX || entite_active(&texte) {
                return None;
            }
            // Comme XML : la première déclaration d'un nom l'emporte.
            entites.entry(nom).or_insert(texte);
            i = suite;
        } else if ["<!element", "<!notation"]
            .iter()
            .any(|m| ici.get(..m.len()).is_some_and(|d| d.eq_ignore_ascii_case(m.as_bytes())))
        {
            // Jusqu'au « > », guillemets sautés : rien d'actif, mais un identifiant entre guillemets peut porter « > ».
            loop {
                match *h.get(i)? {
                    b'>' => break,
                    q @ (b'"' | b'\'') => i = apres_guillemet(h, i, q)?,
                    _ => i += 1,
                }
            }
            i += 1;
        } else {
            return None;
        }
    }
}

/// L'indice qui suit le guillemet `q` qui ferme celui ouvert en `i`.
fn apres_guillemet(h: &[u8], i: usize, q: u8) -> Option<usize> {
    let ferme = h.get(i + 1..)?.iter().position(|&o| o == q)?;
    Some(i + ferme + 2)
}

/// Une déclaration d'entité interne, lue après « <!ENTITY » : son nom, son texte de remplacement (références de
/// caractères décodées, comme XML le fait à la déclaration) et l'indice qui suit son « > ». `None` pour une entité
/// paramètre (`%`), externe (`SYSTEM`, `PUBLIC` : son texte est ailleurs) ou mal écrite, et pour un nom que `derouler`
/// ne déroulerait pas : plus long que `NOM_ENTITE_MAX`, ou qui porte « ; », « & » ou « < » (aucun lecteur XML ne
/// l'accepte ; laissé tel quel, son appel cachait le texte qu'il donne : relecture A des restes c6).
fn lire_entite(h: &[u8], i: usize) -> Option<(Vec<u8>, Vec<u8>, usize)> {
    let (blanc, i) = prendre(h, i, |o| o.is_ascii_whitespace());
    let (nom, i) = prendre(h, i, |o| {
        !o.is_ascii_whitespace() && !matches!(o, b'"' | b'\'' | b'>' | b'%')
    });
    if blanc.is_empty()
        || nom.is_empty()
        || nom.len() > NOM_ENTITE_MAX
        || nom.iter().any(|o| matches!(o, b';' | b'&' | b'<'))
    {
        return None;
    }
    let i = prendre(h, i, |o| o.is_ascii_whitespace()).1;
    let q = *h.get(i).filter(|q| matches!(q, b'"' | b'\''))?;
    let fin = apres_guillemet(h, i, q)?;
    let texte = h.get(i + 1..fin - 1)?;
    let i = prendre(h, fin, |o| o.is_ascii_whitespace()).1;
    if h.get(i) != Some(&b'>') {
        return None;
    }
    Some((nom.to_vec(), references_de_caracteres(texte), i + 1))
}

/// `texte` où les seules références de caractères (`&#60;`, `&#x3C;`) sont décodées ; les appels d'entités restent,
/// déroulés plus tard (`derouler`).
fn references_de_caracteres(texte: &[u8]) -> Vec<u8> {
    let t = String::from_utf8_lossy(texte);
    let mut s = String::with_capacity(t.len());
    let mut reste: &str = &t;
    while let Some(p) = reste.find("&#") {
        s.push_str(reste.get(..p).unwrap_or_default());
        reste = reste.get(p..).unwrap_or_default();
        if let Some((c, longueur)) = reference_numerique(reste) {
            s.push(c);
            reste = reste.get(longueur..).unwrap_or_default();
        } else {
            s.push('&');
            reste = reste.get(1..).unwrap_or_default();
        }
    }
    s.push_str(reste);
    s.into_bytes()
}

/// Le texte d'une entité (références de caractères déjà décodées : `&#34;` y est un « " ») porte du contenu actif une
/// fois appelé, ou change la lecture de ce qui l'entoure : une balise (`<script`, `<image onerror=…`, tout « < »), un
/// gestionnaire d'événement (`onload=` : tout « = »), une adresse qui exécute (`javascript:`), ou un guillemet, « > »
/// ou « & ». Déroulée telle quelle, une entité « "/> » fermait la valeur de l'attribut où elle est appelée, et le
/// gestionnaire écrit ensuite passait pour du texte ; un lecteur XML, lui, lit ces caractères comme des données (H-1
/// de la relecture B des restes c6). Une passe : le texte peut faire 5 Mo, et chercher « on…= » à chaque « on » le
/// relisait jusqu'au bout (relecture A des restes c6).
fn entite_active(texte: &[u8]) -> bool {
    if texte
        .iter()
        .any(|o| matches!(o, b'<' | b'>' | b'"' | b'\'' | b'&' | b'='))
    {
        return true;
    }
    let t = adresse_attribut(&String::from_utf8_lossy(texte)).to_ascii_lowercase();
    t.contains("javascript:") || t.contains("vbscript:")
}

/// `h` où chaque appel d'une entité déclarée (`&nom;`) est remplacé par son texte, de proche en proche (une entité
/// peut en appeler une autre). `None` si le résultat dépasse `HTML_MAX` octets ou si un appel reste après `TOURS`
/// tours : le « milliard de rires » et l'entité qui s'appelle elle-même ne se déroulent pas. `None` aussi pour un nom
/// plus long que `NOM_ENTITE_MAX`, dont l'appel resterait tel quel (`lire_entite` les refuse déjà), et quand
/// `echeance` passe.
fn derouler(
    h: &[u8],
    entites: &std::collections::HashMap<Vec<u8>, Vec<u8>>,
    echeance: Option<std::time::Instant>,
) -> Option<Vec<u8>> {
    const TOURS: usize = 16;
    if entites.keys().any(|nom| nom.len() > NOM_ENTITE_MAX) {
        return None;
    }
    let mut texte = h.to_vec();
    for _ in 0..TOURS {
        let mut sortie = Vec::with_capacity(texte.len());
        let mut change = false;
        let mut i = 0;
        let mut appels = 0_u32;
        while let Some(p) = texte.get(i..).and_then(|r| r.iter().position(|&o| o == b'&')) {
            if appels.is_multiple_of(4096) && depassee(echeance) {
                return None;
            }
            appels = appels.wrapping_add(1);
            sortie.extend_from_slice(texte.get(i..i + p).unwrap_or_default());
            i += p;
            // Le « ; » n'est pas cherché plus loin que le plus long nom permis.
            let appel = texte
                .get(i + 1..)
                .and_then(|r| r.iter().take(NOM_ENTITE_MAX + 1).position(|&o| o == b';'))
                .and_then(|n| entites.get(texte.get(i + 1..i + 1 + n)?).map(|t| (n, t)));
            if let Some((n, t)) = appel {
                sortie.extend_from_slice(t);
                i += n + 2;
                change = true;
            } else {
                sortie.push(b'&');
                i += 1;
            }
            if sortie.len() > HTML_MAX {
                return None;
            }
        }
        sortie.extend_from_slice(texte.get(i..).unwrap_or_default());
        if sortie.len() > HTML_MAX {
            return None;
        }
        if !change {
            return Some(sortie);
        }
        texte = sortie;
    }
    None
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

    /// Sans échéance : les essais chronométrés mesurent la lecture elle-même.
    fn juger_svg(h: &[u8]) -> Option<Svg> {
        super::juger_svg(h, None)
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
            assert_eq!(juger_svg(&svg(corps)), Some(Svg::Actif), "{corps}");
        }
        assert_eq!(
            juger_svg(&svg("<a_b:rect xmlns:a_b=\"http://www.w3.org/2000/svg\"/>")),
            Some(Svg::Inerte)
        );
    }

    /// Relecture du lot campagne 6 : une entité déclarée dans la DTD (ou un attribut par défaut) peut porter le
    /// script ou l'adresse `javascript:` ; une entité au texte actif, ou un attribut par défaut, rend l'image active.
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
            assert_eq!(juger_svg(&h), Some(Svg::Actif), "{debut}");
        }
        let mut h =
            b"<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">"
                .to_vec();
        h.extend(svg("<rect/>"));
        assert_eq!(juger_svg(&h), Some(Svg::Inerte));
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
            assert_eq!(juger_svg(&h), Some(Svg::Actif), "{debut}");
        }
        let mut h = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>".to_vec();
        h.extend(svg("<rect/>"));
        assert_eq!(juger_svg(&h), Some(Svg::Inerte));
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
            assert_eq!(juger_svg(&svg(corps)), Some(Svg::Actif), "{corps}");
        }
    }

    /// B-3 de la relecture des correctifs c6 : un bloc CDATA va jusqu'à « ]]> », pas jusqu'au premier « > » ; un
    /// « > » et un guillemet ouvert dans le bloc ne cachent plus la balise qui le suit. Un bloc qui ne se ferme pas
    /// laisse lire la suite comme des balises.
    #[test]
    fn svg_bloc_cdata() {
        for corps in [
            "<text><![CDATA[ > <x y=\"]]><rect onload=\"alert(1)\"/></text>",
            "<text><![CDATA[ a > b ]]></text><rect onload=\"alert(1)\"/>",
            "<text><![CDATA[ <rect onload=\"alert(1)\"/>",
        ] {
            assert_eq!(juger_svg(&svg(corps)), Some(Svg::Actif), "{corps}");
        }
        // Le contenu d'un bloc CDATA est du texte : il ne s'exécute que dans un `<script>`, déjà vu par sa balise.
        // Un `<script` écrit dedans reste levé par la recherche brute de `pieces::juger`.
        for corps in [
            "<text><![CDATA[ if (a < b && c) x(); ]]></text>",
            "<text><![CDATA[<script>alert(1)</script>]]></text>",
        ] {
            assert_eq!(juger_svg(&svg(corps)), Some(Svg::Inerte), "{corps}");
        }
    }

    /// B-3 de la relecture des correctifs c6 : un commentaire se ferme comme le lirait l'une ou l'autre lecture. HTML
    /// le ferme aussi sur « --!> », et « <!--> » ou « <!---> » se ferment aussitôt ; ce qui suit est lu.
    #[test]
    fn svg_commentaire() {
        for corps in [
            "<!-- --!><rect onload=\"alert(1)\"/> -->",
            "<!--><rect onload=\"alert(1)\"/>-->",
            "<!---><rect onload=\"alert(1)\"/>-->",
            "<!-- a --><rect onload=\"alert(1)\"/>",
        ] {
            assert_eq!(juger_svg(&svg(corps)), Some(Svg::Actif), "{corps}");
        }
        for corps in ["<!-- onload=\"x\" <script> -->", "<!-- a > b --><rect/>"] {
            assert_eq!(juger_svg(&svg(corps)), Some(Svg::Inerte), "{corps}");
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
            assert_eq!(juger_svg(&svg(&corps)), Some(Svg::Actif), "{corps}");
        }
        assert_eq!(
            juger_svg(&svg("<animate attributeName=\"opacity\" values=\"0;1\"/>")),
            Some(Svg::Inerte)
        );
    }

    /// `corps` dans une image SVG précédée de la DTD `dtd`.
    fn svg_dtd(dtd: &str, corps: &str) -> Vec<u8> {
        let mut h = format!("<!DOCTYPE svg [{dtd}]>").into_bytes();
        h.extend(svg(corps));
        h
    }

    /// H-1 de la relecture B des restes c6 : déroulée telle quelle, une entité qui porte un guillemet ou un « > »
    /// fermait la valeur de l'attribut où elle est appelée, et le gestionnaire écrit en clair après semblait en être
    /// le texte. Pour un lecteur XML, ce guillemet est une donnée : `onerror` reste un attribut de `<image>`.
    #[test]
    fn svg_entite_qui_ferme_un_attribut() {
        for dtd in [
            "<!ENTITY e '\"/>'>",
            "<!ENTITY e '\" z='>",
            "<!ENTITY e \"&#34;/&#62;\">",
            "<!ENTITY e \"&#x27; z=&#x27;\">",
            "<!ENTITY e \"&quot;\">",
            "<!ENTITY e \"x=\">",
        ] {
            let h = svg_dtd(dtd, "<image href=\"x\" a=\"&e;\" onerror=\"alert(1)\"/>");
            assert_eq!(juger_svg(&h), Some(Svg::Actif), "{dtd}");
        }
        // Une entité inoffensive appelée dans un attribut : seulement des déclarations.
        let h = svg_dtd("<!ENTITY e \"x\">", "<image href=\"x\" a=\"&e;\"/>");
        assert_eq!(juger_svg(&h), Some(Svg::Declarations));
    }

    /// Relecture A des restes c6 : un nom d'entité plus long que ce que `derouler` cherche n'était jamais déroulé, et
    /// « java » + « script: » passaient pour des déclarations. Il est refusé dès la DTD, comme un nom qui porte « ; ».
    #[test]
    fn svg_nom_d_entite_long() {
        let lien = |nom: &str| {
            svg_dtd(
                &format!("<!ENTITY {nom} \"java\"><!ENTITY s \"script:alert(1)\">"),
                &format!("<a href=\"&{nom};&s;\"><text>x</text></a>"),
            )
        };
        for nom in [
            "a".repeat(NOM_ENTITE_MAX),
            "a".repeat(NOM_ENTITE_MAX + 1),
            "名".repeat(22),
        ] {
            assert_eq!(juger_svg(&lien(&nom)), Some(Svg::Actif), "{nom}");
        }
        let o = "o".repeat(70);
        let h = svg_dtd(
            &format!("<!ENTITY {o} \"onload\">"),
            &format!("<rect><set attributeName=\"&{o};\" to=\"alert(1)\"/></rect>"),
        );
        assert_eq!(juger_svg(&h), Some(Svg::Actif));
        let h = svg_dtd("<!ENTITY a;b \"x\">", "<text>&a;b;</text>");
        assert_eq!(juger_svg(&h), Some(Svg::Actif));
        // Ceinture : un nom trop long qui arriverait jusqu'à `derouler` ne se déroule pas.
        let entites = std::collections::HashMap::from([(b"a".repeat(NOM_ENTITE_MAX + 1), b"x".to_vec())]);
        assert_eq!(derouler(b"<svg/>", &entites, None), None);
    }

    /// Relectures A et B des restes c6 : chaque commentaire, bloc CDATA ou texte d'entité relisait le document jusqu'au
    /// bout quand sa fin manquait ; 5 Mo (un .svgz de 50 Ko) tenaient le processeur des dizaines de minutes. Lu en une
    /// passe, chaque motif tient en quelques secondes même sans optimisation.
    #[test]
    fn svg_lu_en_temps_lineaire() {
        let borne = std::time::Duration::from_secs(if cfg!(debug_assertions) { 60 } else { 2 });
        let remplir = |motif: &str| motif.repeat((HTML_MAX - 200) / motif.len());
        for (quoi, h) in [
            ("<!----!>", svg(&remplir("<!----!>"))),
            ("<!-- -->", svg(&remplir("<!-- -->"))),
            ("<![CDATA[", svg(&remplir("<![CDATA["))),
            ("]]>", svg(&format!("<![CDATA[{}", remplir("<!--")))),
            (
                "onon",
                svg_dtd(&format!("<!ENTITY a \"{}\">", remplir("on")), "<rect/>"),
            ),
            (
                "on a",
                svg_dtd(&format!("<!ENTITY a \"{}\">", remplir("on a ")), "<rect/>"),
            ),
        ] {
            assert!(h.len() <= HTML_MAX, "{quoi}");
            let debut = std::time::Instant::now();
            let jugee = juger_svg(&h);
            let duree = debut.elapsed();
            eprintln!("{quoi} : {} octets, {jugee:?} en {duree:?}", h.len());
            assert!(jugee.is_some(), "{quoi}");
            assert!(duree < borne, "{quoi} : {duree:?}");
        }
        // Le filet : une échéance passée arrête la lecture, sans conclure, entités déroulées ou pas.
        let passee = Some(std::time::Instant::now());
        assert_eq!(super::juger_svg(&svg("<rect/>"), passee), None);
        assert_eq!(
            super::juger_svg(&svg_dtd("<!ENTITY e \"x\">", "<text>&e;</text>"), passee),
            None
        );
    }

    /// Relecture A des restes c6 : une image en UTF-16 (avec BOM, ou « <? » en UTF-16 sans BOM) s'exécute dans le
    /// navigateur ; ses balises, lues octet par octet, ne se voyaient pas.
    #[test]
    fn svg_en_utf16() {
        let texte = "<?xml version=\"1.0\" encoding=\"UTF-16\"?><svg xmlns=\"http://www.w3.org/2000/svg\">\
                     <script>alert(1)</script></svg>";
        let le: Vec<u8> = texte.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let be: Vec<u8> = texte.encode_utf16().flat_map(u16::to_be_bytes).collect();
        for (quoi, h) in [
            ("LE avec BOM", [&[0xff, 0xfe][..], &le].concat()),
            ("BE avec BOM", [&[0xfe, 0xff][..], &be].concat()),
            ("LE sans BOM", le.clone()),
            ("BE sans BOM", be.clone()),
        ] {
            assert_eq!(juger_svg(&h), Some(Svg::Actif), "{quoi}");
        }
        let sain: Vec<u8> = [0xff, 0xfe]
            .into_iter()
            .chain(
                String::from_utf8(svg("<rect/>"))
                    .unwrap()
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes),
            )
            .collect();
        assert_eq!(juger_svg(&sain), Some(Svg::Inerte));
        // Un nombre impair d'octets ou une moitié de paire : remplacés, comme le ferait le navigateur, sans panique.
        assert!(juger_svg(&[0xff, 0xfe, 0x3c, 0x00, 0x00, 0xd8, 0x41]).is_some());
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

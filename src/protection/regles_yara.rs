//! Lecteur du sous-ensemble du langage YARA que Vanguard applique (`moteur_yara`), écrit pour Vanguard d'après la
//! documentation de YARA (yara.readthedocs.io, « Writing YARA rules ») et celle de YARA-X
//! (virustotal.github.io/yara-x) : imports, règles, métadonnées, chaînes de texte (`ascii`, `wide`) et hexadécimales
//! (octets, demi-octets `4?`, jokers `??`, sauts bornés `[n-m]`, choix `( … | … )`), conditions (`and`, `or`, `not`,
//! `$a`, `$a at …`, `all/any/none/N of (…)`, `them`, ensembles `$a*`, `uint8/16/32`, `int8/16/32` et leurs formes `be`,
//! `filesize`, comparaisons, `pe.entry_point`, `pe.number_of_signatures > 0`, `elf.entry_point`).
//!
//! Tout le reste est refusé, jamais ignoré : la règle qui s'en sert est rendue dans `refus`, avec son nom, sa ligne et
//! la construction en cause, et ne s'applique pas (« non vérifiée »). Les règles sont des données de confiance
//! moyenne (elles viennent de l'auteur, mais un fichier abîmé ne doit jamais faire paniquer) : tailles, nombres et
//! profondeurs bornés ; une erreur dans une règle n'emporte qu'elle, la lecture reprend à la règle suivante.
//!
//! Module pur, sans `crate::` (sauf `super::motifs`) : le banc de fuzzing l'inclut par son chemin.

use super::motifs::Element;

/// Le texte des règles, au plus (celles de ReversingLabs : 2,7 Mo), et ses jetons : chacun pèse quelques dizaines
/// d'octets, un texte fait de parenthèses en ferait sinon des centaines de Mo.
pub(crate) const SOURCE_MAX: usize = 8 << 20;
const JETONS_MAX: usize = 2_000_000;
/// Règles, et chaînes par règle, au plus.
pub(crate) const REGLES_MAX: usize = 100_000;
pub(crate) const CHAINES_MAX: usize = 10_000;
/// Imbrication des conditions (parenthèses, `not`) et des choix d'une chaîne hexadécimale.
const PROFONDEUR_MAX: usize = 100;

/// Pourquoi une règle est refusée.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Raison {
    /// Une construction du langage que le moteur ne connaît pas (« xor », « for », « #a », expression régulière…).
    Inconnue(String),
    /// Le texte ne suit pas la grammaire : ce qui était attendu.
    Syntaxe(&'static str),
    /// Un nom déjà pris (règle ou chaîne), ou une chaîne citée qui n'existe pas.
    Nom(String),
    /// Un module (`pe`, `elf`) utilisé sans `import`.
    Import(String),
    /// Une borne dépassée (taille, nombre, profondeur).
    Borne(&'static str),
    /// Une chaîne refusée par le moteur de motifs (`motifs::Refus`), décrite.
    Motif(String),
}

/// Une règle refusée : son nom quand il a pu être lu, sa ligne (à partir de 1), la raison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Refus {
    pub regle: Option<String>,
    pub ligne: usize,
    pub raison: Raison,
}

/// Les métadonnées utiles au constat.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Meta {
    pub auteur: Option<String>,
    pub reference: Option<String>,
    pub description: Option<String>,
}

/// Une chaîne : son nom (« $a ») et ses formes, chacune une suite d'éléments (deux pour `ascii wide`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Chaine {
    pub nom: String,
    pub formes: Vec<Vec<Element>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Comparaison {
    Egal,
    Different,
    Inferieur,
    InferieurOuEgal,
    Superieur,
    SuperieurOuEgal,
}

/// Combien de chaînes d'un ensemble doivent être trouvées.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Quantite {
    Toutes,
    AuMoins(u64),
    Aucune,
}

/// Une valeur entière (64 bits signés, comme dans YARA), peut-être indéfinie à l'évaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Entier {
    Nombre(i64),
    TailleFichier,
    /// uint8/16/32 et int8/16/32 (`signe`), petit-boutiste sauf `gros` (les formes `be`), à une position.
    Lire {
        octets: u8,
        signe: bool,
        gros: bool,
        position: Box<Entier>,
    },
    PeEntree,
    ElfEntree,
}

/// Une condition. Les chaînes sont désignées par leur rang dans la règle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Expr {
    Vrai,
    Faux,
    Et(Vec<Expr>),
    Ou(Vec<Expr>),
    Non(Box<Expr>),
    Chaine(usize),
    ChaineA(usize, Entier),
    Ensemble(Quantite, Vec<usize>),
    Comparer(Entier, Comparaison, Entier),
    /// pe.number_of_signatures > 0 (voir `pe::signature_presente`) : seule forme admise de ce champ.
    SignaturePresente,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Regle {
    pub nom: String,
    pub ligne: usize,
    pub meta: Meta,
    pub chaines: Vec<Chaine>,
    pub condition: Expr,
}

/// Le résultat de la lecture : les règles comprises, les refusées.
#[derive(Debug, Default)]
pub(crate) struct Fichier {
    pub regles: Vec<Regle>,
    pub refus: Vec<Refus>,
}

// ---------------------------------------------------------------------------------------------------------------
// Découpage en jetons
// ---------------------------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum J {
    Mot(String),
    /// « $a », « $a* », « $* », « $ ».
    Var(String),
    /// « #a », « @a », « !a » : compte, position, longueur d'une correspondance.
    Compte(String),
    Nombre(u64),
    Texte(Vec<u8>),
    /// Le dedans d'une chaîne hexadécimale, accolades ôtées.
    Hex(String),
    Regex,
    Signe(&'static str),
    /// Un morceau que le découpage ne comprend pas (échappement inconnu, nombre trop grand, caractère inattendu) :
    /// la règle qui le porte sera refusée, la lecture continue après lui.
    Illisible(&'static str),
}

const SIGNES: &[&str] = &[
    "..", "==", "!=", "<=", ">=", "<<", ">>", "{", "}", "(", ")", "[", "]", ":", "=", ",", ".", "<", ">", "-", "+",
    "*", "\\", "%", "&", "|", "^", "~",
];

#[allow(clippy::many_single_char_names)] // un découpeur : position, octet courant, morceaux lus
fn jetons(source: &str) -> Vec<(J, usize)> {
    let c = source.as_bytes();
    let mut liste: Vec<(J, usize)> = Vec::new();
    let mut i = 0;
    let mut ligne = 1;
    let apres_egal = |liste: &Vec<(J, usize)>| liste.last().is_some_and(|(j, _)| *j == J::Signe("="));
    // Ce qui reste à lire depuis `k` : rien au-delà de la fin (un commentaire ou une expression non fermés y
    // mènent, et la lecture s'y arrête de toute façon).
    let suite = |k: usize| c.get(k..).unwrap_or_default();
    // L'octet `k` est-il un caractère de nom ?
    let de_nom = |k: usize| c.get(k).is_some_and(|o| o.is_ascii_alphanumeric() || *o == b'_');
    while let Some(&x) = c.get(i) {
        if liste.len() >= JETONS_MAX {
            // La suite n'est pas lue : dit, à sa ligne.
            liste.push((J::Illisible("trop de jetons"), ligne));
            break;
        }
        if x == b'\n' {
            ligne += 1;
            i += 1;
        } else if x.is_ascii_whitespace() {
            i += 1;
        } else if suite(i).starts_with(b"//") {
            while c.get(i).is_some_and(|&o| o != b'\n') {
                i += 1;
            }
        } else if suite(i).starts_with(b"/*") {
            let debut = ligne;
            i += 2;
            while let Some(&o) = c.get(i).filter(|_| !suite(i).starts_with(b"*/")) {
                if o == b'\n' {
                    ligne += 1;
                }
                i += 1;
            }
            if i >= c.len() {
                liste.push((J::Illisible("*/"), debut));
            }
            i += 2;
        } else if x == b'"' {
            let debut = ligne;
            i += 1;
            let mut texte = Vec::new();
            let mut defaut = None;
            loop {
                let Some(&o) = c.get(i) else {
                    defaut = Some("\"");
                    break;
                };
                match o {
                    b'"' => {
                        i += 1;
                        break;
                    }
                    b'\n' => {
                        defaut = Some("\"");
                        break;
                    }
                    b'\\' => {
                        let suite = c.get(i + 1).copied();
                        let (octet, pas) = match suite {
                            Some(b'"') => (Some(b'"'), 2),
                            Some(b'\\') => (Some(b'\\'), 2),
                            Some(b't') => (Some(b'\t'), 2),
                            Some(b'n') => (Some(b'\n'), 2),
                            Some(b'r') => (Some(b'\r'), 2),
                            Some(b'x') => {
                                // Deux chiffres hexadécimaux, et rien d'autre (from_str_radix admettrait « +1 »).
                                let h = c
                                    .get(i + 2..i + 4)
                                    .filter(|h| h.iter().all(u8::is_ascii_hexdigit))
                                    .and_then(|h| std::str::from_utf8(h).ok());
                                (h.and_then(|h| u8::from_str_radix(h, 16).ok()), 4)
                            }
                            _ => (None, 2),
                        };
                        match octet {
                            Some(o) => texte.push(o),
                            None => defaut = Some("\\"),
                        }
                        i += pas;
                    }
                    _ => {
                        texte.push(o);
                        i += 1;
                    }
                }
            }
            // Plus long qu'aucun motif ne peut l'être : refusé dès ici, sans le développer en éléments.
            if texte.len() > super::motifs::LONGUEUR_MAX as usize / 2 {
                defaut = defaut.or(Some("texte trop long"));
                texte = Vec::new();
            }
            liste.push((defaut.map_or(J::Texte(texte), J::Illisible), debut));
        } else if x == b'{' && apres_egal(&liste) {
            // Le dedans d'une chaîne hexadécimale, commentaires ôtés, jusqu'à l'accolade qui la ferme.
            let debut = ligne;
            i += 1;
            let mut dedans = String::new();
            let mut ferme = false;
            while let Some(&o) = c.get(i) {
                if o == b'}' {
                    ferme = true;
                    i += 1;
                    break;
                }
                if suite(i).starts_with(b"//") {
                    while c.get(i).is_some_and(|&o| o != b'\n') {
                        i += 1;
                    }
                    continue;
                }
                if suite(i).starts_with(b"/*") {
                    i += 2;
                    while let Some(&o) = c.get(i).filter(|_| !suite(i).starts_with(b"*/")) {
                        ligne += usize::from(o == b'\n');
                        i += 1;
                    }
                    i += 2;
                    dedans.push(' ');
                    continue;
                }
                ligne += usize::from(o == b'\n');
                dedans.push(char::from(o));
                i += 1;
            }
            liste.push((if ferme { J::Hex(dedans) } else { J::Illisible("}") }, debut));
        } else if x == b'/' && apres_egal(&liste) {
            // Une expression régulière : refusée, mais sautée entière pour que la suite se lise.
            let debut = ligne;
            i += 1;
            while let Some(&o) = c.get(i).filter(|&&o| o != b'/' && o != b'\n') {
                i += if o == b'\\' { 2 } else { 1 };
            }
            i += 1;
            while c.get(i).is_some_and(u8::is_ascii_alphabetic) {
                i += 1;
            }
            liste.push((J::Regex, debut));
        } else if x.is_ascii_digit() {
            let debut = i;
            while de_nom(i) {
                i += 1;
            }
            let mot = &source[debut..i];
            let valeur = match mot.strip_prefix("0x").or_else(|| mot.strip_prefix("0X")) {
                Some(h) => u64::from_str_radix(h, 16).ok(),
                None => mot.parse::<u64>().ok(),
            };
            liste.push((valeur.map_or(J::Illisible("nombre"), J::Nombre), ligne));
        } else if x.is_ascii_alphabetic() || x == b'_' {
            let debut = i;
            while de_nom(i) {
                i += 1;
            }
            liste.push((J::Mot(source[debut..i].to_string()), ligne));
        } else if matches!(x, b'$' | b'#' | b'@')
            || (x == b'!' && c.get(i + 1).is_some_and(|o| o.is_ascii_alphabetic() || *o == b'_'))
        {
            let debut = i;
            i += 1;
            while de_nom(i) {
                i += 1;
            }
            if x == b'$' && c.get(i) == Some(&b'*') {
                i += 1;
            }
            let nom = source[debut..i].to_string();
            liste.push((if x == b'$' { J::Var(nom) } else { J::Compte(nom) }, ligne));
        } else if let Some(s) = SIGNES.iter().find(|s| suite(i).starts_with(s.as_bytes())) {
            liste.push((J::Signe(s), ligne));
            i += s.len();
        } else {
            // Un caractère hors du langage (ou le début d'un caractère non ASCII) : sauté entier.
            let largeur = source[i..].chars().next().map_or(1, char::len_utf8);
            liste.push((J::Illisible("caractère"), ligne));
            i += largeur;
        }
    }
    liste
}

// ---------------------------------------------------------------------------------------------------------------
// Lecture des règles
// ---------------------------------------------------------------------------------------------------------------

/// Les mots réservés du langage : ni nom de règle, ni identifiant.
const RESERVES: &[&str] = &[
    "all",
    "and",
    "any",
    "ascii",
    "at",
    "base64",
    "base64wide",
    "condition",
    "contains",
    "defined",
    "endswith",
    "entrypoint",
    "false",
    "filesize",
    "for",
    "fullword",
    "global",
    "import",
    "icontains",
    "iendswith",
    "iequals",
    "in",
    "include",
    "int16",
    "int16be",
    "int32",
    "int32be",
    "int8",
    "int8be",
    "istartswith",
    "matches",
    "meta",
    "nocase",
    "none",
    "not",
    "of",
    "or",
    "private",
    "rule",
    "startswith",
    "strings",
    "them",
    "true",
    "uint16",
    "uint16be",
    "uint32",
    "uint32be",
    "uint8",
    "uint8be",
    "wide",
    "xor",
    "with",
    "equals",
];

type R<T> = Result<T, Raison>;

/// Le lecteur d'une règle : ses jetons, la position, les modules importés.
struct Lecteur<'a> {
    j: &'a [(J, usize)],
    i: usize,
    imports: &'a [String],
    profondeur: usize,
}

impl Lecteur<'_> {
    fn voir(&self) -> Option<&J> {
        self.j.get(self.i).map(|(j, _)| j)
    }

    fn voir_a(&self, k: usize) -> Option<&J> {
        self.j.get(self.i + k).map(|(j, _)| j)
    }

    fn avancer(&mut self) -> Option<&J> {
        let j = self.j.get(self.i).map(|(j, _)| j);
        self.i += 1;
        j
    }

    fn mot(&self, m: &str) -> bool {
        matches!(self.voir(), Some(J::Mot(x)) if x == m)
    }

    fn signe(&self, s: &str) -> bool {
        matches!(self.voir(), Some(J::Signe(x)) if *x == s)
    }

    fn attendre_signe(&mut self, s: &'static str) -> R<()> {
        if self.signe(s) {
            self.i += 1;
            Ok(())
        } else {
            Err(self.inattendu(s))
        }
    }

    fn attendre_mot(&mut self, m: &'static str) -> R<()> {
        if self.mot(m) {
            self.i += 1;
            Ok(())
        } else {
            Err(self.inattendu(m))
        }
    }

    /// Ce qui ne va pas au jeton courant : un morceau illisible, une construction inconnue, ou une faute de grammaire.
    fn inattendu(&self, attendu: &'static str) -> Raison {
        match self.voir() {
            Some(J::Illisible(quoi)) => Raison::Syntaxe(quoi),
            Some(J::Regex) => Raison::Inconnue("expression régulière".into()),
            Some(J::Compte(c)) => Raison::Inconnue(c.chars().next().unwrap_or('#').to_string() + "…"),
            Some(J::Mot(m))
                if RESERVES.contains(&m.as_str())
                    && !["and", "or", "of", "condition", "strings", "meta"].contains(&m.as_str()) =>
            {
                Raison::Inconnue(m.clone())
            }
            _ => Raison::Syntaxe(attendu),
        }
    }

    fn identifiant(&mut self) -> R<String> {
        match self.voir() {
            Some(J::Mot(m)) if !RESERVES.contains(&m.as_str()) => {
                let m = m.clone();
                self.i += 1;
                Ok(m)
            }
            _ => Err(self.inattendu("identifiant")),
        }
    }

    fn regle(&mut self) -> R<Regle> {
        if self.mot("private") || self.mot("global") {
            let Some(J::Mot(m)) = self.voir() else { unreachable!() };
            return Err(Raison::Inconnue(m.clone()));
        }
        let ligne = self.j.get(self.i).map_or(0, |(_, l)| *l);
        self.attendre_mot("rule")?;
        let nom = self.identifiant()?;
        if self.signe(":") {
            self.i += 1;
            while matches!(self.voir(), Some(J::Mot(_))) && !self.signe("{") {
                self.identifiant()?;
            }
        }
        self.attendre_signe("{")?;
        let mut meta = Meta::default();
        if self.mot("meta") {
            self.i += 1;
            self.attendre_signe(":")?;
            self.metas(&mut meta)?;
        }
        let mut chaines: Vec<Chaine> = Vec::new();
        if self.mot("strings") {
            self.i += 1;
            self.attendre_signe(":")?;
            while matches!(self.voir(), Some(J::Var(_))) {
                let c = self.chaine()?;
                if chaines.iter().any(|x| x.nom == c.nom) {
                    return Err(Raison::Nom(c.nom));
                }
                if chaines.len() >= CHAINES_MAX {
                    return Err(Raison::Borne("chaînes"));
                }
                chaines.push(c);
            }
            if chaines.is_empty() {
                return Err(self.inattendu("$"));
            }
        }
        self.attendre_mot("condition")?;
        self.attendre_signe(":")?;
        let condition = self.booleen(&chaines)?;
        self.attendre_signe("}")?;
        if self.i != self.j.len() {
            return Err(self.inattendu("fin de règle"));
        }
        // Une chaîne que la condition ne cite pas : YARA et YARA-X refusent la règle, le moteur aussi.
        let mut citees = vec![false; chaines.len()];
        citer(&condition, &mut citees);
        if let Some((c, _)) = chaines.iter().zip(&citees).find(|(_, citee)| !**citee) {
            return Err(Raison::Nom(c.nom.clone()));
        }
        Ok(Regle {
            nom,
            ligne,
            meta,
            chaines,
            condition,
        })
    }

    fn metas(&mut self, meta: &mut Meta) -> R<()> {
        while let Some(J::Mot(cle)) = self.voir() {
            if (cle == "strings" || cle == "condition") && self.voir_a(1) == Some(&J::Signe(":")) {
                break;
            }
            let cle = self.identifiant()?;
            self.attendre_signe("=")?;
            let valeur = self.avancer().cloned();
            let texte = match valeur {
                Some(J::Texte(t)) => Some(String::from_utf8_lossy(&t).into_owned()),
                Some(J::Nombre(_)) => None,
                Some(J::Signe("-")) if matches!(self.voir(), Some(J::Nombre(_))) => {
                    self.i += 1;
                    None
                }
                Some(J::Mot(m)) if m == "true" || m == "false" => None,
                _ => {
                    self.i -= 1;
                    return Err(self.inattendu("valeur"));
                }
            };
            let place = match cle.as_str() {
                "author" => &mut meta.auteur,
                "reference" => &mut meta.reference,
                "description" => &mut meta.description,
                _ => continue,
            };
            if place.is_none() {
                *place = texte;
            }
        }
        Ok(())
    }

    fn chaine(&mut self) -> R<Chaine> {
        let Some(J::Var(nom)) = self.avancer() else {
            unreachable!()
        };
        let nom = nom.clone();
        if nom == "$" || nom.ends_with('*') {
            return Err(Raison::Inconnue(nom));
        }
        self.attendre_signe("=")?;
        match self.avancer() {
            Some(J::Texte(t)) => {
                let t = t.clone();
                if t.is_empty() {
                    return Err(Raison::Syntaxe("texte vide"));
                }
                let (mut ascii, mut wide) = (false, false);
                let mut vus: Vec<String> = Vec::new();
                while let Some(J::Mot(m)) = self.voir() {
                    let m = m.clone();
                    if ![
                        "ascii",
                        "wide",
                        "nocase",
                        "fullword",
                        "private",
                        "xor",
                        "base64",
                        "base64wide",
                    ]
                    .contains(&m.as_str())
                    {
                        break;
                    }
                    if vus.contains(&m) {
                        return Err(Raison::Syntaxe("modificateur en double"));
                    }
                    match m.as_str() {
                        "ascii" => ascii = true,
                        "wide" => wide = true,
                        _ => return Err(Raison::Inconnue(m)),
                    }
                    vus.push(m);
                    self.i += 1;
                }
                let exact = |o: &[u8]| {
                    o.iter()
                        .map(|&valeur| Element::Octet { valeur, masque: 0xFF })
                        .collect::<Vec<_>>()
                };
                let mut formes = Vec::new();
                if ascii || !wide {
                    formes.push(exact(&t));
                }
                if wide {
                    let large: Vec<u8> = t.iter().flat_map(|&o| [o, 0]).collect();
                    formes.push(exact(&large));
                }
                Ok(Chaine { nom, formes })
            }
            Some(J::Hex(h)) => {
                let h = h.clone();
                if let Some(J::Mot(m)) = self.voir()
                    && [
                        "ascii",
                        "wide",
                        "nocase",
                        "fullword",
                        "private",
                        "xor",
                        "base64",
                        "base64wide",
                    ]
                    .contains(&m.as_str())
                {
                    return Err(Raison::Inconnue(m.clone()));
                }
                Ok(Chaine {
                    nom,
                    formes: vec![hexadecimal(&h)?],
                })
            }
            _ => {
                self.i -= 1;
                Err(self.inattendu("chaîne"))
            }
        }
    }

    fn plus_profond(&mut self) -> R<()> {
        self.profondeur += 1;
        if self.profondeur > PROFONDEUR_MAX {
            return Err(Raison::Borne("profondeur"));
        }
        Ok(())
    }

    /// Une condition booléenne : `or` au plus bas, puis `and`, puis `not`.
    fn booleen(&mut self, chaines: &[Chaine]) -> R<Expr> {
        match self.ou(chaines)? {
            Valeur::Bool(e) => Ok(e),
            Valeur::Entier(_) => Err(Raison::Inconnue("entier comme condition".into())),
        }
    }

    fn ou(&mut self, chaines: &[Chaine]) -> R<Valeur> {
        let premier = self.et(chaines)?;
        if !self.mot("or") {
            return Ok(premier);
        }
        let mut termes = vec![premier.booleen()?];
        while self.mot("or") {
            self.i += 1;
            termes.push(self.et(chaines)?.booleen()?);
        }
        Ok(Valeur::Bool(Expr::Ou(termes)))
    }

    fn et(&mut self, chaines: &[Chaine]) -> R<Valeur> {
        let premier = self.non(chaines)?;
        if !self.mot("and") {
            return Ok(premier);
        }
        let mut termes = vec![premier.booleen()?];
        while self.mot("and") {
            self.i += 1;
            termes.push(self.non(chaines)?.booleen()?);
        }
        Ok(Valeur::Bool(Expr::Et(termes)))
    }

    fn non(&mut self, chaines: &[Chaine]) -> R<Valeur> {
        if self.mot("not") {
            self.i += 1;
            self.plus_profond()?;
            let e = self.non(chaines)?.booleen()?;
            self.profondeur -= 1;
            return Ok(Valeur::Bool(Expr::Non(Box::new(e))));
        }
        self.comparaison(chaines)
    }

    fn comparaison(&mut self, chaines: &[Chaine]) -> R<Valeur> {
        let gauche = self.primaire(chaines)?;
        let op = match self.voir() {
            Some(J::Signe("==")) => Comparaison::Egal,
            Some(J::Signe("!=")) => Comparaison::Different,
            Some(J::Signe("<")) => Comparaison::Inferieur,
            Some(J::Signe("<=")) => Comparaison::InferieurOuEgal,
            Some(J::Signe(">")) => Comparaison::Superieur,
            Some(J::Signe(">=")) => Comparaison::SuperieurOuEgal,
            Some(J::Signe(s)) if ["+", "-", "*", "\\", "%", "&", "|", "^", "<<", ">>", "~"].contains(s) => {
                return Err(Raison::Inconnue(format!("opérateur {s}")));
            }
            Some(J::Mot(m))
                if [
                    "contains",
                    "matches",
                    "startswith",
                    "endswith",
                    "icontains",
                    "iequals",
                    "istartswith",
                    "iendswith",
                    "equals",
                ]
                .contains(&m.as_str()) =>
            {
                return Err(Raison::Inconnue(m.clone()));
            }
            _ => {
                if let Valeur::Entier(Entier::Nombre(-1)) = gauche {
                    // Le marqueur de pe.number_of_signatures, qui n'a de sens que comparé (voir plus bas).
                    return Err(Raison::Inconnue("pe.number_of_signatures".into()));
                }
                return Ok(gauche);
            }
        };
        self.i += 1;
        let droite = self.primaire(chaines)?;
        let (Valeur::Entier(g), Valeur::Entier(d)) = (gauche, droite) else {
            return Err(Raison::Inconnue("comparaison d'une condition".into()));
        };
        // pe.number_of_signatures n'est admis que pour dire « au moins une » (voir pe::signature_presente).
        let signatures = |e: &Entier| *e == SIGNATURES;
        if signatures(&g) || signatures(&d) {
            return match (g, op, d) {
                (s, Comparaison::Superieur | Comparaison::Different, Entier::Nombre(0))
                | (s, Comparaison::SuperieurOuEgal, Entier::Nombre(1))
                    if s == SIGNATURES =>
                {
                    Ok(Valeur::Bool(Expr::SignaturePresente))
                }
                _ => Err(Raison::Inconnue(
                    "pe.number_of_signatures (autrement que « > 0 »)".into(),
                )),
            };
        }
        Ok(Valeur::Bool(Expr::Comparer(g, op, d)))
    }

    fn rang(chaines: &[Chaine], nom: &str) -> R<usize> {
        chaines
            .iter()
            .position(|c| c.nom == nom)
            .ok_or_else(|| Raison::Nom(nom.to_string()))
    }

    /// Les chaînes d'un ensemble : `them`, ou `( $a, $b*, … )`.
    fn ensemble(&mut self, chaines: &[Chaine]) -> R<Vec<usize>> {
        if self.mot("them") {
            self.i += 1;
            if chaines.is_empty() {
                return Err(Raison::Nom("them".into()));
            }
            return Ok((0..chaines.len()).collect());
        }
        self.attendre_signe("(")?;
        // Marquées plutôt qu'empilées : un ensemble qui répète « $a* » des milliers de fois reste de la taille des chaînes.
        let mut dedans = vec![false; chaines.len()];
        loop {
            let Some(J::Var(nom)) = self.voir() else {
                return Err(self.inattendu("$"));
            };
            let nom = nom.clone();
            self.i += 1;
            if let Some(prefixe) = nom.strip_suffix('*') {
                let mut un = false;
                for (c, d) in chaines.iter().zip(dedans.iter_mut()) {
                    if c.nom.starts_with(prefixe) {
                        *d = true;
                        un = true;
                    }
                }
                if !un {
                    return Err(Raison::Nom(nom));
                }
            } else {
                let k = Self::rang(chaines, &nom)?;
                *dedans.get_mut(k).ok_or(Raison::Nom(nom))? = true;
            }
            if self.signe(",") {
                self.i += 1;
                continue;
            }
            break;
        }
        self.attendre_signe(")")?;
        Ok(dedans.iter().enumerate().filter(|(_, d)| **d).map(|(k, _)| k).collect())
    }

    fn module(&mut self, module: &'static str) -> R<Entier> {
        self.i += 1;
        if !self.imports.iter().any(|m| m == module) {
            return Err(Raison::Import(module.into()));
        }
        self.attendre_signe(".")?;
        let Some(J::Mot(champ)) = self.voir() else {
            return Err(self.inattendu("champ"));
        };
        let champ = champ.clone();
        self.i += 1;
        if self.signe("(") || self.signe("[") || self.signe(".") {
            return Err(Raison::Inconnue(format!("{module}.{champ}…")));
        }
        match (module, champ.as_str()) {
            ("pe", "entry_point") => Ok(Entier::PeEntree),
            ("pe", "number_of_signatures") => Ok(SIGNATURES),
            ("elf", "entry_point") => Ok(Entier::ElfEntree),
            _ => Err(Raison::Inconnue(format!("{module}.{champ}"))),
        }
    }

    fn entier(&mut self, chaines: &[Chaine]) -> R<Entier> {
        match self.primaire(chaines)? {
            Valeur::Entier(e) if e != SIGNATURES => Ok(e),
            Valeur::Entier(_) => Err(Raison::Inconnue("pe.number_of_signatures".into())),
            Valeur::Bool(_) => Err(Raison::Syntaxe("entier")),
        }
    }

    fn primaire(&mut self, chaines: &[Chaine]) -> R<Valeur> {
        let Some(j) = self.voir().cloned() else {
            return Err(Raison::Syntaxe("condition"));
        };
        match j {
            J::Mot(m) if m == "true" => {
                self.i += 1;
                Ok(Valeur::Bool(Expr::Vrai))
            }
            J::Mot(m) if m == "false" => {
                self.i += 1;
                Ok(Valeur::Bool(Expr::Faux))
            }
            J::Signe("(") => {
                self.i += 1;
                self.plus_profond()?;
                let v = self.ou(chaines)?;
                self.profondeur -= 1;
                self.attendre_signe(")")?;
                Ok(v)
            }
            J::Var(nom) => {
                self.i += 1;
                if nom == "$" || nom.ends_with('*') {
                    return Err(Raison::Inconnue(nom));
                }
                let rang = Self::rang(chaines, &nom)?;
                if self.mot("at") {
                    self.i += 1;
                    let position = self.entier(chaines)?;
                    return Ok(Valeur::Bool(Expr::ChaineA(rang, position)));
                }
                if self.mot("in") {
                    return Err(Raison::Inconnue("in".into()));
                }
                Ok(Valeur::Bool(Expr::Chaine(rang)))
            }
            J::Mot(m) if m == "all" || m == "any" || m == "none" => {
                self.i += 1;
                self.quantite(
                    chaines,
                    match m.as_str() {
                        "all" => Quantite::Toutes,
                        "any" => Quantite::AuMoins(1),
                        _ => Quantite::Aucune,
                    },
                )
            }
            J::Nombre(n) if self.voir_a(1) == Some(&J::Mot("of".into())) => {
                self.i += 1;
                if n == 0 {
                    // « 0 of » : « aucune » pour YARA 4.3, « au moins zéro » pour YARA-X. Ambigu, refusé.
                    return Err(Raison::Inconnue("0 of".into()));
                }
                self.quantite(chaines, Quantite::AuMoins(n))
            }
            J::Nombre(n) => {
                self.i += 1;
                if self.signe("%") {
                    return Err(Raison::Inconnue("%".into()));
                }
                let n = i64::try_from(n).map_err(|_| Raison::Syntaxe("nombre"))?;
                Ok(Valeur::Entier(Entier::Nombre(n)))
            }
            J::Mot(m) if m == "filesize" => {
                self.i += 1;
                Ok(Valeur::Entier(Entier::TailleFichier))
            }
            J::Mot(m) if lecture(&m).is_some() => {
                let (octets, signe, gros) = lecture(&m).unwrap_or((1, false, false));
                self.i += 1;
                self.attendre_signe("(")?;
                self.plus_profond()?;
                let position = self.entier(chaines)?;
                self.profondeur -= 1;
                self.attendre_signe(")")?;
                Ok(Valeur::Entier(Entier::Lire {
                    octets,
                    signe,
                    gros,
                    position: Box::new(position),
                }))
            }
            J::Mot(m) if m == "pe" => Ok(Valeur::Entier(self.module("pe")?)),
            J::Mot(m) if m == "elf" => Ok(Valeur::Entier(self.module("elf")?)),
            J::Mot(m) if RESERVES.contains(&m.as_str()) => Err(Raison::Inconnue(m)),
            J::Mot(m) => Err(Raison::Inconnue(format!("identifiant {m}"))),
            J::Signe("-") => Err(Raison::Inconnue("nombre négatif".into())),
            _ => Err(self.inattendu("condition")),
        }
    }

    fn quantite(&mut self, chaines: &[Chaine], quantite: Quantite) -> R<Valeur> {
        self.attendre_mot("of")?;
        let rangs = self.ensemble(chaines)?;
        if self.mot("in") || self.mot("at") {
            let Some(J::Mot(m)) = self.voir() else { unreachable!() };
            return Err(Raison::Inconnue(format!("of … {m}")));
        }
        Ok(Valeur::Bool(Expr::Ensemble(quantite, rangs)))
    }
}

/// Marque les chaînes que cite une condition.
fn citer(e: &Expr, citees: &mut [bool]) {
    match e {
        // Un rang hors des chaînes ne marque rien : il ne cite aucune chaîne de la règle.
        Expr::Chaine(c) | Expr::ChaineA(c, _) => citees.get_mut(*c).into_iter().for_each(|x| *x = true),
        Expr::Ensemble(_, rangs) => {
            for c in rangs {
                if let Some(x) = citees.get_mut(*c) {
                    *x = true;
                }
            }
        }
        Expr::Et(t) | Expr::Ou(t) => t.iter().for_each(|x| citer(x, citees)),
        Expr::Non(x) => citer(x, citees),
        Expr::Vrai | Expr::Faux | Expr::Comparer(..) | Expr::SignaturePresente => {}
    }
}

/// Le marqueur interne de pe.number_of_signatures pendant la lecture : jamais une vraie valeur (un nombre lu est
/// toujours positif), remplacé par `Expr::SignaturePresente` ou refusé.
const SIGNATURES: Entier = Entier::Nombre(-1);

/// uint8, int16be… : (octets, signé, gros-boutiste).
fn lecture(mot: &str) -> Option<(u8, bool, bool)> {
    let (reste, gros) = match mot.strip_suffix("be") {
        Some(r) => (r, true),
        None => (mot, false),
    };
    let (reste, signe) = match reste.strip_prefix('u') {
        Some(r) => (r, false),
        None => (reste, true),
    };
    let octets = match reste {
        "int8" => 1,
        "int16" => 2,
        "int32" => 4,
        _ => return None,
    };
    Some((octets, signe, gros))
}

/// Une valeur pendant la lecture d'une condition : booléenne ou entière.
enum Valeur {
    Bool(Expr),
    Entier(Entier),
}

impl Valeur {
    fn booleen(self) -> R<Expr> {
        match self {
            Valeur::Bool(e) => Ok(e),
            Valeur::Entier(_) => Err(Raison::Inconnue("entier comme condition".into())),
        }
    }
}

/// Le dedans d'une chaîne hexadécimale, en éléments.
fn hexadecimal(texte: &str) -> R<Vec<Element>> {
    // Les blancs séparent : un octet ne s'écrit pas à cheval sur un blanc (« 4 1 » est refusé, comme par YARA-X).
    let c: Vec<char> = texte.chars().map(|x| if x.is_whitespace() { ' ' } else { x }).collect();
    // Chaque élément prend au moins un signe : au-delà, le motif serait refusé, autant ne pas le construire.
    if c.len() > 4 * super::motifs::ELEMENTS_MAX {
        return Err(Raison::Borne("chaîne hexadécimale"));
    }
    let mut i = 0;
    let suite = suite_hex(&c, &mut i, 0)?;
    if i != c.len() {
        return Err(Raison::Syntaxe("chaîne hexadécimale"));
    }
    Ok(suite)
}

/// Une suite d'éléments, jusqu'à « | », « ) » ou la fin.
fn suite_hex(c: &[char], i: &mut usize, profondeur: usize) -> R<Vec<Element>> {
    if profondeur > super::motifs::PROFONDEUR_MAX {
        return Err(Raison::Borne("choix imbriqués"));
    }
    let mut elements = Vec::new();
    while let Some(&x) = c.get(*i) {
        match x {
            ' ' => *i += 1,
            '|' | ')' => break,
            '(' => {
                *i += 1;
                let mut suites = vec![suite_hex(c, i, profondeur + 1)?];
                while c.get(*i) == Some(&'|') {
                    *i += 1;
                    suites.push(suite_hex(c, i, profondeur + 1)?);
                }
                if c.get(*i) != Some(&')') {
                    return Err(Raison::Syntaxe(")"));
                }
                *i += 1;
                if suites.len() < 2 {
                    return Err(Raison::Syntaxe("|"));
                }
                elements.push(Element::Choix(suites));
            }
            '[' => {
                let fin = c
                    .get(*i..)
                    .and_then(|r| r.iter().position(|x| *x == ']'))
                    .ok_or(Raison::Syntaxe("]"))?
                    + *i;
                let dedans: String = c
                    .get(*i + 1..fin)
                    .ok_or(Raison::Syntaxe("]"))?
                    .iter()
                    .filter(|x| **x != ' ')
                    .collect();
                *i = fin + 1;
                let nombre = |s: &str| -> R<u32> {
                    if s.is_empty() || !s.bytes().all(|o| o.is_ascii_digit()) {
                        return Err(Raison::Syntaxe("saut"));
                    }
                    s.parse::<u32>().map_err(|_| Raison::Borne("saut"))
                };
                let (min, max) = match dedans.split_once('-') {
                    None => {
                        let n = nombre(&dedans)?;
                        (n, n)
                    }
                    Some((_, "")) => return Err(Raison::Inconnue("saut sans fin [n-]".into())),
                    Some(("", b)) => (0, nombre(b)?),
                    Some((a, b)) => (nombre(a)?, nombre(b)?),
                };
                // Un saut à l'envers, ou nul (« [0] », que YARA-X refuse : inutile).
                if min > max || max == 0 {
                    return Err(Raison::Syntaxe("saut"));
                }
                elements.push(Element::Saut { min, max });
            }
            '~' => return Err(Raison::Inconnue("~".into())),
            _ => {
                let (Some(&h), Some(&b)) = (c.get(*i), c.get(*i + 1)) else {
                    return Err(Raison::Syntaxe("octet"));
                };
                if b == ' ' {
                    return Err(Raison::Syntaxe("octet"));
                }
                *i += 2;
                let demi = |x: char| -> R<(u8, u8)> {
                    match x {
                        '?' => Ok((0, 0)),
                        _ => x
                            .to_digit(16)
                            .and_then(|v| u8::try_from(v).ok())
                            .map(|v| (v, 0xF))
                            .ok_or(Raison::Syntaxe("octet")),
                    }
                };
                let ((vh, mh), (vb, mb)) = (demi(h)?, demi(b)?);
                elements.push(Element::Octet {
                    valeur: (vh << 4) | vb,
                    masque: (mh << 4) | mb,
                });
            }
        }
    }
    if elements.is_empty() {
        return Err(Raison::Syntaxe("octet"));
    }
    Ok(elements)
}

/// La fin (exclue) de la règle qui commence au jeton `debut` : le jeton après l'accolade qui ferme la première
/// accolade ouverte. `None` : jamais fermée.
fn fin_de_regle(j: &[(J, usize)], debut: usize) -> Option<usize> {
    let mut profondeur = 0usize;
    for (k, (t, _)) in j.iter().enumerate().skip(debut) {
        match t {
            J::Signe("{") => profondeur += 1,
            J::Signe("}") => {
                profondeur = profondeur.checked_sub(1)?;
                if profondeur == 0 {
                    return Some(k + 1);
                }
            }
            // Une déclaration suivante avant la fermeture, à n'importe quelle profondeur (ces mots sont réservés : aucun
            // corps de règle ne peut les contenir) : celle-ci est tronquée. S'arrêter là garde la lecture linéaire, même
            // sur des milliers de règles jamais fermées.
            J::Mot(m) if k > debut + 1 && matches!(m.as_str(), "rule" | "import" | "include") => {
                return None;
            }
            _ => {}
        }
    }
    None
}

/// Le début de la déclaration suivante après celle qui commence au jeton `debut` (règle jamais fermée) : le prochain
/// « rule » (ou le « private »/« global » qui le précède) ou « import », ou la fin.
fn prochain_debut(j: &[(J, usize)], debut: usize) -> usize {
    let mot = |k: usize| match j.get(k) {
        Some((J::Mot(m), _)) => m.as_str(),
        _ => "",
    };
    let mut k = debut + 1;
    // Le « rule » de cette déclaration même, derrière ses « private » ou « global ».
    while matches!(mot(k), "private" | "global" | "rule") && k <= debut + 2 {
        k += 1;
    }
    while k < j.len() {
        match mot(k) {
            "import" | "include" => return k,
            "rule" => {
                let mut d = k;
                while d > debut + 1 && matches!(mot(d - 1), "private" | "global") {
                    d -= 1;
                }
                return d;
            }
            _ => k += 1,
        }
    }
    j.len()
}

/// Lit `source` : les règles comprises, et les refusées.
pub(crate) fn lire(source: &str) -> Fichier {
    let mut fichier = Fichier::default();
    if source.len() > SOURCE_MAX {
        fichier.refus.push(Refus {
            regle: None,
            ligne: 1,
            raison: Raison::Borne("taille du fichier de règles"),
        });
        return fichier;
    }
    let j = jetons(source);
    let mut imports: Vec<String> = Vec::new();
    let mut noms: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut i = 0;
    while let Some((jeton, ligne)) = j.get(i) {
        let ligne = *ligne;
        match jeton {
            J::Mot(m) if m == "import" => {
                if let Some((J::Texte(t), _)) = j.get(i + 1) {
                    imports.push(String::from_utf8_lossy(t).into_owned());
                    i += 2;
                } else {
                    fichier.refus.push(Refus {
                        regle: None,
                        ligne,
                        raison: Raison::Syntaxe("import"),
                    });
                    i += 1;
                }
            }
            J::Mot(m) if m == "include" => {
                fichier.refus.push(Refus {
                    regle: None,
                    ligne,
                    raison: Raison::Inconnue("include".into()),
                });
                i += if matches!(j.get(i + 1), Some((J::Texte(_), _))) {
                    2
                } else {
                    1
                };
            }
            J::Mot(m) if m == "rule" || m == "private" || m == "global" => {
                let nom = j
                    .iter()
                    .skip(i)
                    .skip_while(|(t, _)| *t != J::Mot("rule".into()))
                    .nth(1)
                    .and_then(|(t, _)| match t {
                        J::Mot(n) => Some(n.clone()),
                        _ => None,
                    });
                let fin = fin_de_regle(&j, i);
                let bout = fin.unwrap_or_else(|| prochain_debut(&j, i));
                let resultat = if fin.is_none() {
                    Err(Raison::Syntaxe("}"))
                } else if fichier.regles.len() >= REGLES_MAX {
                    Err(Raison::Borne("règles"))
                } else if let Some(morceau) = j.get(i..bout) {
                    let mut l = Lecteur {
                        j: morceau,
                        i: 0,
                        imports: &imports,
                        profondeur: 0,
                    };
                    l.regle()
                } else {
                    // Une fin de règle hors des jetons : la règle est refusée, jamais lue de travers.
                    Err(Raison::Syntaxe("}"))
                };
                match resultat {
                    Ok(r) if !noms.insert(r.nom.clone()) => fichier.refus.push(Refus {
                        regle: Some(r.nom.clone()),
                        ligne,
                        raison: Raison::Nom(r.nom),
                    }),
                    Ok(r) => fichier.regles.push(r),
                    Err(raison) => fichier.refus.push(Refus {
                        regle: nom,
                        ligne,
                        raison,
                    }),
                }
                i = bout.max(i + 1);
            }
            _ => {
                // Hors de toute règle : sauté jusqu'au prochain début de règle ou import, dit une seule fois.
                fichier.refus.push(Refus {
                    regle: None,
                    ligne,
                    raison: Raison::Syntaxe("rule"),
                });
                i += 1;
                while j.get(i).is_some_and(|(t, _)| {
                    !matches!(t, J::Mot(m) if ["rule", "private", "global", "import", "include"].contains(&m.as_str()))
                }) {
                    i += 1;
                }
            }
        }
    }
    fichier
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)] // des tirages au hasard, réduits exprès
mod tests {
    use super::*;

    fn raison_seule(source: &str) -> Raison {
        let f = lire(source);
        assert!(f.regles.is_empty(), "{source} : {:?}", f.regles);
        assert_eq!(f.refus.len(), 1, "{source} : {:?}", f.refus);
        f.refus[0].raison.clone()
    }

    /// Ce que le moteur ne connaît pas est refusé, nommé, jamais ignoré ni appliqué à moitié.
    #[test]
    fn constructions_refusees() {
        let inconnue = |source: &str, quoi: &str| match raison_seule(source) {
            Raison::Inconnue(c) => assert!(c.contains(quoi), "{source} : {c}"),
            autre => panic!("{source} : {autre:?}"),
        };
        inconnue(r#"rule r { strings: $a = "x" xor condition: $a }"#, "xor");
        inconnue(r#"rule r { strings: $a = "x" nocase condition: $a }"#, "nocase");
        inconnue(r#"rule r { strings: $a = "x" fullword condition: $a }"#, "fullword");
        inconnue(r#"rule r { strings: $a = "xyz" base64 condition: $a }"#, "base64");
        inconnue(r#"rule r { strings: $a = "x" private condition: $a }"#, "private");
        inconnue(r"rule r { strings: $a = { 41 } private condition: $a }", "private");
        inconnue(r"rule r { strings: $a = /ab+c/ condition: $a }", "expression régulière");
        inconnue(r"private rule r { condition: true }", "private");
        inconnue(r"global rule r { condition: true }", "global");
        inconnue(r#"rule r { strings: $a = "x" condition: #a > 2 }"#, "#");
        inconnue(r#"rule r { strings: $a = "x" condition: @a[1] == 0 }"#, "@");
        inconnue(r#"rule r { strings: $a = "x" condition: !a[1] == 1 }"#, "!");
        inconnue(r#"rule r { strings: $a = "x" condition: $a in (0..10) }"#, "in");
        inconnue(r#"rule r { strings: $a = "x" condition: 0 of them }"#, "0 of");
        inconnue(r#"rule r { strings: $a = "x" condition: 50% of them }"#, "%");
        inconnue(r#"rule r { strings: $a = "x" condition: any of them in (0..4) }"#, "in");
        inconnue(
            r#"rule r { strings: $a = "x" condition: for any of them : ( $ ) }"#,
            "for",
        );
        inconnue(r"rule r { strings: $a = { 41 [2-] 42 } condition: $a }", "[n-]");
        inconnue(r"rule r { strings: $a = { 41 ~42 } condition: $a }", "~");
        inconnue(r#"import "pe" rule r { condition: pe.is_dll() }"#, "pe.is_dll");
        inconnue(
            r#"import "pe" rule r { condition: pe.number_of_sections == 1 }"#,
            "pe.number_of_sections",
        );
        inconnue(
            r#"import "pe" rule r { condition: pe.number_of_signatures == 2 }"#,
            "number_of_signatures",
        );
        inconnue(r#"import "math" rule r { condition: math.entropy(0, 10) > 7 }"#, "math");
        inconnue(r"rule r { condition: filesize + 1 > 2 }", "+");
        inconnue(r"rule r { condition: entrypoint == 0 }", "entrypoint");
        inconnue(
            r"rule a { condition: true } rule r { condition: a }"
                .split("} ")
                .nth(1)
                .unwrap(),
            "a",
        );
        inconnue(r"rule r { condition: 5 }", "entier comme condition");
        assert_eq!(
            raison_seule(r"rule r { condition: pe.entry_point == 0 }"),
            Raison::Import("pe".into())
        );
        assert!(matches!(
            raison_seule(r#"rule r { strings: $a = "x" $a = "y" condition: $a }"#),
            Raison::Nom(_)
        ));
        assert!(matches!(
            raison_seule(r#"rule r { strings: $a = "x" condition: $b }"#),
            Raison::Nom(_)
        ));
        assert!(matches!(
            raison_seule(r#"rule r { strings: $a = "x" condition: all of ($c*) }"#),
            Raison::Nom(_)
        ));
        assert!(
            matches!(raison_seule(r#"rule r { strings: $a = "x" $b = "y" condition: $a }"#), Raison::Nom(n) if n == "$b")
        );
        assert!(matches!(
            raison_seule(r"rule r { strings: $a = { 41 [0] 42 } condition: $a }"),
            Raison::Syntaxe(_)
        ));
        assert!(matches!(
            raison_seule(r"rule r { strings: $a = { 41 [3-2] 42 } condition: $a }"),
            Raison::Syntaxe(_)
        ));
        assert!(matches!(
            raison_seule(r#"rule r { strings: $a = "\q" condition: $a }"#),
            Raison::Syntaxe(_)
        ));
        // Relecture adverse : deux formes que YARA-X refuse.
        assert!(matches!(
            raison_seule(r#"rule r { strings: $a = "\x+1" condition: $a }"#),
            Raison::Syntaxe(_)
        ));
        assert!(matches!(
            raison_seule("rule r { strings: $a = { 4 1 } condition: $a }"),
            Raison::Syntaxe(_)
        ));
        assert!(matches!(
            raison_seule(r#"rule r { strings: $a = "x" wide wide condition: $a }"#),
            Raison::Syntaxe(_)
        ));
        // Une règle en double : la seconde est refusée, la première reste.
        let f = lire(r"rule r { condition: true } rule r { condition: false }");
        assert_eq!((f.regles.len(), f.refus.len()), (1, 1));
        assert_eq!(f.regles[0].condition, Expr::Vrai);
    }

    /// Une règle abîmée n'emporte qu'elle : la suivante se lit, même après une règle jamais fermée.
    #[test]
    fn reprise_apres_une_erreur() {
        let f = lire(
            "rule a { condition: ( true }\nrule b { strings: $x = \"ok\" condition: $x }\nrule c { condition: \nrule d { condition: false }\n",
        );
        let noms: Vec<&str> = f.regles.iter().map(|r| r.nom.as_str()).collect();
        assert_eq!(noms, ["b", "d"]);
        let refusees: Vec<(Option<&str>, usize)> = f.refus.iter().map(|r| (r.regle.as_deref(), r.ligne)).collect();
        assert_eq!(refusees, [(Some("a"), 1), (Some("c"), 3)]);
        // Du texte hors de toute règle : dit une fois, puis la lecture reprend.
        let f = lire("n'importe quoi ici\nrule e { condition: true }");
        assert_eq!(f.regles.len(), 1);
        assert_eq!(f.refus.len(), 1);
    }

    /// Ce que le moteur comprend : chaînes de texte (échappements, ascii et wide), hexadécimales (demi-octets, jokers,
    /// sauts, choix imbriqués, commentaires), métadonnées, priorités (`and` avant `or`, `at` avant `and`).
    #[test]
    fn constructions_comprises() {
        let f = lire(
            r#"
            import "pe"
            rule R : etiquette autre {
                meta:
                    author = "alice"
                    reference = "https://exemple.invalid/r"
                    score = 5
                    negatif = -3
                    actif = true
                strings:
                    $t = "a\"b\\c\x41\t" wide ascii
                    $h = { 4D 5A ?? 4? ?F [2-4] ( 01 | 02 ( 03 | 04 05 ) ) // commentaire
                           /* autre */ FF [3] 00 }
                condition:
                    uint16(0) == 0x5A4D and $h at pe.entry_point or $t and not int8be(filesize - 0) == 1
            }"#,
        );
        // filesize - 0 est une opération : refusée. Sans elle, la règle se lit.
        assert_eq!(f.regles.len(), 0, "{:?}", f.refus);
        let f = lire(
            r#"
            import "pe"
            rule R : etiquette autre {
                meta:
                    author = "alice"
                    reference = "https://exemple.invalid/r"
                    score = 5
                    negatif = -3
                    actif = true
                strings:
                    $t = "a\"b\\c\x41\t" wide ascii
                    $h = { 4D 5A ?? 4? ?F [2-4] ( 01 | 02 ( 03 | 04 05 ) ) // commentaire
                           /* autre */ FF [3] 00 }
                condition:
                    uint16(0) == 0x5A4D and $h at pe.entry_point or $t and not int8be(filesize) == 1
            }"#,
        );
        assert_eq!(f.refus, []);
        let r = &f.regles[0];
        assert_eq!(r.meta.auteur.as_deref(), Some("alice"));
        assert_eq!(r.meta.reference.as_deref(), Some("https://exemple.invalid/r"));
        let texte = b"a\"b\\cA\t";
        let exact = |o: &[u8]| {
            o.iter()
                .map(|&valeur| Element::Octet { valeur, masque: 0xFF })
                .collect::<Vec<_>>()
        };
        let large: Vec<u8> = texte.iter().flat_map(|&o| [o, 0]).collect();
        assert_eq!(r.chaines[0].formes, [exact(texte), exact(&large)]);
        let h = &r.chaines[1].formes[0];
        assert_eq!(h.len(), 10);
        assert_eq!(
            h[3],
            Element::Octet {
                valeur: 0x40,
                masque: 0xF0
            }
        );
        assert_eq!(
            h[4],
            Element::Octet {
                valeur: 0x0F,
                masque: 0x0F
            }
        );
        assert_eq!(h[5], Element::Saut { min: 2, max: 4 });
        assert_eq!(h[8], Element::Saut { min: 3, max: 3 });
        let Expr::Ou(termes) = &r.condition else {
            panic!("{:?}", r.condition)
        };
        assert!(matches!(&termes[0], Expr::Et(e) if matches!(e[1], Expr::ChaineA(1, Entier::PeEntree))));
        assert!(matches!(&termes[1], Expr::Et(e) if matches!(e[1], Expr::Non(_))));
        // pe.number_of_signatures, dans ses formes admises.
        for forme in ["> 0", ">= 1", "!= 0"] {
            let f = lire(&format!(
                r#"import "pe" rule s {{ condition: pe.number_of_signatures {forme} }}"#
            ));
            assert_eq!(f.regles[0].condition, Expr::SignaturePresente, "{forme}");
        }
    }

    /// Des textes de règles abîmés au hasard : jamais de panique, et tout ce qui n'est pas lu est dit.
    #[test]
    fn jamais_de_panique() {
        let base = include_str!("../../assets/yara/reversinglabs.yara");
        let morceau = &base[..base.len().min(200_000)];
        let mut h = 0x1234_5678_9ABC_DEF0u64;
        for _ in 0..300 {
            h ^= h << 13;
            h ^= h >> 7;
            h ^= h << 17;
            let mut octets = morceau.as_bytes()[..(h as usize % morceau.len())].to_vec();
            let n = octets.len().max(1);
            for k in 0..8 {
                let p = (h.rotate_left(k * 8) as usize) % n;
                if let Some(o) = octets.get_mut(p) {
                    *o = b"{}()[]$\"/*\\?|-=:."[(h >> (k * 4)) as usize % 17];
                }
            }
            let texte = String::from_utf8_lossy(&octets);
            let f = lire(&texte);
            assert!(f.regles.len() <= REGLES_MAX);
        }
        // Des milliers de règles jamais fermées : lues en temps linéaire (avant, chacune relisait tout le reste).
        let debut = std::time::Instant::now();
        let f = lire(&"rule a {\n".repeat(80_000));
        assert_eq!((f.regles.len(), f.refus.len()), (0, 80_000));
        assert!(debut.elapsed().as_secs() < 10, "{:?}", debut.elapsed());
        // « $a* » répété : l'ensemble garde la taille des chaînes.
        let chaines = (0..50).fold(String::new(), |mut t, k| {
            let _ = std::fmt::Write::write_fmt(&mut t, format_args!("$a{k} = \"x{k}\" "));
            t
        });
        let f = lire(&format!(
            "rule e {{ strings: {chaines} condition: any of ({}$a*) }}",
            "$a*, ".repeat(20_000)
        ));
        assert!(matches!(&f.regles[0].condition, Expr::Ensemble(_, r) if r.len() == 50));
        // Un texte plus long qu'aucun motif : refusé dès le découpage.
        let long = format!("rule t {{ strings: $a = \"{}\" condition: $a }}", "x".repeat(1 << 20));
        assert_eq!(raison_seule(&long), Raison::Syntaxe("texte trop long"));
        // Des parenthèses à n'en plus finir : refusées, sans déborder la pile.
        let profond = format!(
            "rule p {{ condition: {}true{} }}",
            "(".repeat(100_000),
            ")".repeat(100_000)
        );
        assert_eq!(raison_seule(&profond), Raison::Borne("profondeur"));
        let profond = format!("rule p {{ condition: {}true }}", "not ".repeat(100_000));
        assert_eq!(raison_seule(&profond), Raison::Borne("profondeur"));
        let profond = format!(
            "rule p {{ strings: $a = {{ 41 {}42{} }} condition: $a }}",
            "( 43 | ".repeat(1000),
            " )".repeat(1000)
        );
        assert_eq!(raison_seule(&profond), Raison::Borne("choix imbriqués"));
    }
}

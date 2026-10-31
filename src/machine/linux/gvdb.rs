//! Lecteur GVDB et GVariant, en lecture seule : le format des bases de dconf (`~/.config/dconf/user`,
//! `/etc/dconf/db/*`), des schémas compilés de GSettings (`gschemas.compiled`) et des autorisations que gardent les
//! portails de Flatpak (`~/.local/share/flatpak/db/*`).
//!
//! Pourquoi : `gsettings get` et `flatpak permissions` ne font que lire ces fichiers. Les lire ici évite un
//! programme qui peut manquer, être remplacé dans le PATH, ou attendre un service D-Bus ; la commande reste en
//! secours quand le fichier ne se lit pas.
//!
//! GVDB : un en-tête (« GVariant », version, racine), puis des tables de hachage. Chaque élément d'une table a un
//! nom (dont le début peut se trouver chez un élément parent : dconf range ainsi `/org/gnome/` puis `desktop/`), un
//! genre (`v` une valeur, `H` une table imbriquée, `L` une liste) et un pointeur vers ses données. Une clé se
//! cherche comme dans GLib (`gvdb-reader.c`) : hachage de djb, filtre de Bloom, seau, premier élément du seau dont le
//! hachage, le nom (comparé depuis la fin, parent par parent) et le genre conviennent, données alignées (8 pour une
//! valeur, 4 pour une table). Ranger tous les noms dans une table à soi donnait, sur un fichier forgé, une autre
//! valeur que celle que GNOME applique (un doublon, un hachage faux, une valeur mal alignée) et une mémoire sans
//! borne (des noms rebâtis par leurs parents).
//!
//! GVariant : la forme sérialisée de GLib (types de taille fixe alignés, chaînes terminées par un zéro, décalages de
//! fin rangés en queue des tableaux et des n-uplets). Tout est vérifié : un fichier tronqué ou forgé rend `None`,
//! jamais une valeur inventée ni une panique. Le travail aussi est borné (taille du fichier, nombre de valeurs
//! décodées) : une donnée forgée ne bloque pas Vanguard des minutes. Seuls les fichiers petit-boutistes sont lus
//! (ceux qu'écrit un PC ou un ARM sous Linux) ; un autre rend `None` et la commande prend le relais.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::fmt::Write;
use std::io::{ErrorKind, Read};
use std::path::Path;
use std::rc::Rc;

/// Profondeur d'imbrication des types et des valeurs au-delà de laquelle une donnée est refusée : GLib n'en
/// produit pas d'aussi profondes, et une donnée forgée ne doit pas épuiser la pile.
const PROFONDEUR_MAX: usize = 64;

/// Taille au-delà de laquelle un fichier n'est pas lu : un `gschemas.compiled` de GNOME fait quelques centaines de
/// Ko, une base de dconf moins encore.
const FICHIER_MAX: u64 = 32 << 20;

/// Octets des noms complets que `noms_des_valeurs` rebâtit au plus : des éléments chaînés par leur parent qui
/// répètent chacun un long morceau de nom coûteraient sinon n² octets.
const NOMS_OCTETS_MAX: usize = 4 << 20;

/// Valeurs qu'un décodage produit au plus (copies de types comprises) : les réglages lus ici en ont quelques
/// dizaines, et une valeur forgée de 1 Mo en ferait des dizaines de millions.
const NOEUDS_MAX: usize = 1 << 18;

// ---------------------------------------------------------------------------------------------------------------
// Fichier et tables

/// Un fichier GVDB lu en mémoire.
pub(crate) struct Gvdb {
    octets: Rc<[u8]>,
}

/// Un élément d'une table, tel qu'il est rangé (24 octets).
#[derive(Clone, Copy)]
struct Element {
    hachage: u32,
    parent: u32,
    debut_nom: usize,
    longueur_nom: usize,
    genre: u8,
    debut: usize,
    fin: usize,
}

/// Une table de hachage du fichier : son en-tête vérifié, ses éléments lus à la demande.
pub(crate) struct Table {
    octets: Rc<[u8]>,
    /// Position du filtre de Bloom, et son nombre de mots.
    bloom: usize,
    mots_bloom: usize,
    /// Position des seaux, et leur nombre.
    seaux: usize,
    n_seaux: usize,
    /// Position des éléments, et leur nombre.
    elements: usize,
    n: usize,
}

fn u32_le(octets: &[u8], position: usize) -> Option<u32> {
    let mot = octets.get(position..position.checked_add(4)?)?;
    Some(u32::from_le_bytes(mot.try_into().ok()?))
}

/// Un `u32_le` qui sert de taille ou de position.
fn usize_le(octets: &[u8], position: usize) -> Option<usize> {
    usize::try_from(u32_le(octets, position)?).ok()
}

fn u16_le(octets: &[u8], position: usize) -> Option<u16> {
    let mot = octets.get(position..position.checked_add(2)?)?;
    Some(u16::from_le_bytes(mot.try_into().ok()?))
}

/// Le hachage de djb que GLib calcule sur les noms, octet par octet comme des `signed char`.
pub(crate) fn hachage(nom: &[u8]) -> u32 {
    nom.iter().fold(5381u32, |h, &c| {
        h.wrapping_mul(33)
            .wrapping_add(i32::from(c.cast_signed()).cast_unsigned())
    })
}

impl Gvdb {
    /// `None` : pas un fichier GVDB lisible ici (signature, version, ou ordre des octets d'une autre machine).
    pub(crate) fn depuis(octets: Vec<u8>) -> Option<Gvdb> {
        if octets.get(..8)? != b"GVariant" || u32_le(&octets, 8)? != 0 {
            return None;
        }
        Some(Gvdb { octets: octets.into() })
    }

    /// Le fichier `chemin` : `Ok(None)` s'il n'existe pas ; `Err` s'il ne se lit pas, n'est pas un fichier ordinaire
    /// (un tube nommé bloquerait la lecture), dépasse `FICHIER_MAX` ou n'est pas du GVDB lisible ici.
    pub(crate) fn ouvrir(chemin: &Path) -> Result<Option<Gvdb>, ()> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
        let fichier = match options.open(chemin) {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(()),
        };
        if !fichier.metadata().map_err(|_| ())?.is_file() {
            return Err(());
        }
        let mut octets = Vec::new();
        fichier.take(FICHIER_MAX + 1).read_to_end(&mut octets).map_err(|_| ())?;
        if u64::try_from(octets.len()).ok().is_none_or(|n| n > FICHIER_MAX) {
            return Err(());
        }
        Gvdb::depuis(octets).map(Some).ok_or(())
    }

    pub(crate) fn racine(&self) -> Option<Table> {
        let debut = usize_le(&self.octets, 16)?;
        let fin = usize_le(&self.octets, 20)?;
        Table::lire(Rc::clone(&self.octets), debut, fin)
    }
}

impl Table {
    /// L'en-tête de la table rangée de `debut` à `fin`, vérifié comme `gvdb_table_setup_root`. Là où GLib se
    /// contente d'une table vide (en-tête faux, place qui n'est pas un nombre entier d'éléments), `None` : la
    /// commande dira mieux ce que GNOME en fait.
    fn lire(octets: Rc<[u8]>, debut: usize, fin: usize) -> Option<Table> {
        if !debut.is_multiple_of(4) || debut > fin || fin > octets.len() {
            return None;
        }
        // Les 5 bits du haut du premier mot portent un décalage que GLib ne lit pas.
        let mots_bloom = usize::try_from(u32_le(&octets, debut)? & (u32::MAX >> 5)).ok()?;
        let n_seaux = usize_le(&octets, debut.checked_add(4)?)?;
        let place = fin
            .checked_sub(debut)?
            .checked_sub(8)?
            .checked_sub(mots_bloom.checked_mul(4)?)?
            .checked_sub(n_seaux.checked_mul(4)?)?;
        if !place.is_multiple_of(24) {
            return None;
        }
        let bloom = debut.checked_add(8)?;
        let seaux = bloom.checked_add(mots_bloom.checked_mul(4)?)?;
        Some(Table {
            octets,
            bloom,
            mots_bloom,
            seaux,
            n_seaux,
            elements: seaux.checked_add(n_seaux.checked_mul(4)?)?,
            n: place / 24,
        })
    }

    fn element(&self, i: usize) -> Option<Element> {
        let e = self.elements.checked_add(i.checked_mul(24)?)?;
        let o = &self.octets;
        let a = |decalage: usize| e.checked_add(decalage);
        Some(Element {
            hachage: u32_le(o, e)?,
            parent: u32_le(o, a(4)?)?,
            debut_nom: usize_le(o, a(8)?)?,
            longueur_nom: usize::from(u16_le(o, a(12)?)?),
            genre: *o.get(a(14)?)?,
            debut: usize_le(o, a(16)?)?,
            fin: usize_le(o, a(20)?)?,
        })
    }

    /// Le morceau de nom que l'élément porte lui-même.
    fn morceau(&self, e: &Element) -> Option<&[u8]> {
        self.octets.get(e.debut_nom..e.debut_nom.checked_add(e.longueur_nom)?)
    }

    /// Le nom complet de `e` est `cle` : comparé depuis la fin, morceau par morceau en remontant les parents, comme
    /// `gvdb_table_check_name`. Chaque pas mange au moins un octet de la clé : rien ne coûte plus que sa longueur, et
    /// une boucle de parents s'arrête d'elle-même.
    fn nom_est(&self, mut e: Element, cle: &[u8]) -> bool {
        let mut reste = cle.len();
        loop {
            let Some(morceau) = self.morceau(&e) else {
                return false;
            };
            let Some(avant) = reste.checked_sub(morceau.len()) else {
                return false;
            };
            if cle.get(avant..reste) != Some(morceau) {
                return false;
            }
            reste = avant;
            if reste == 0 && e.parent == u32::MAX {
                return true;
            }
            let Some(parent) = usize::try_from(e.parent).ok().filter(|&p| p < self.n) else {
                return false;
            };
            if morceau.is_empty() {
                return false;
            }
            let Some(p) = self.element(parent) else {
                return false;
            };
            e = p;
        }
    }

    /// L'élément que GLib trouverait pour `cle` et `genre` (`gvdb_table_lookup`).
    fn chercher(&self, cle: &str, genre: u8) -> Option<Element> {
        if self.n_seaux == 0 || self.n == 0 {
            return None;
        }
        let cle = cle.as_bytes();
        let h = hachage(cle);
        if self.mots_bloom > 0 {
            let place = usize::try_from(h / 32)
                .ok()?
                .checked_rem(self.mots_bloom)?
                .checked_mul(4)?;
            let mot = u32_le(&self.octets, self.bloom.checked_add(place)?)?;
            // GLib n'affecte jamais son `bloom_shift`, qui reste à 0 : ses deux bits du filtre n'en font qu'un.
            let masque = 1u32 << (h & 31);
            if mot & masque != masque {
                return None;
            }
        }
        let seau = usize::try_from(h).ok()?.checked_rem(self.n_seaux)?;
        let place = |s: usize| self.seaux.checked_add(s.checked_mul(4)?);
        let premier = usize_le(&self.octets, place(seau)?)?;
        let suivant = seau.checked_add(1)?;
        let dernier = if suivant == self.n_seaux {
            self.n
        } else {
            usize_le(&self.octets, place(suivant)?)?.min(self.n)
        };
        (premier..dernier)
            .map_while(|i| self.element(i))
            .find(|e| e.hachage == h && self.nom_est(*e, cle) && e.genre == genre)
    }

    /// Les données de l'élément, refusées si elles débordent du fichier ou ne sont pas alignées comme GLib l'exige
    /// (`gvdb_table_dereference`).
    fn donnees(&self, e: &Element, alignement: usize) -> Option<&[u8]> {
        if e.debut > e.fin || !e.debut.is_multiple_of(alignement) {
            return None;
        }
        self.octets.get(e.debut..e.fin)
    }

    /// La valeur rangée sous `nom` (genre `v`), avec son type ; `None` si elle manque ou ne se lit pas.
    pub(crate) fn valeur(&self, nom: &str) -> Option<Variante> {
        let e = self.chercher(nom, b'v')?;
        match decoder(&Genre::Variante, self.donnees(&e, 8)?)? {
            Variante::Boite(v) => Some(*v),
            _ => None,
        }
    }

    /// La table imbriquée rangée sous `nom` (genre `H`) : `Ok(None)` si elle n'y est pas, `Err` si elle ne se lit
    /// pas.
    pub(crate) fn table(&self, nom: &str) -> Result<Option<Table>, ()> {
        let Some(e) = self.chercher(nom, b'H') else {
            return Ok(None);
        };
        Table::lire(Rc::clone(&self.octets), e.debut, e.fin).map(Some).ok_or(())
    }

    /// GLib trouve une valeur sous ce nom (`gvdb_table_has_value`, ce que regarde dconf dans chaque base et dans la
    /// table des verrous) ; `valeur` peut encore ne pas la décoder.
    pub(crate) fn contient_valeur(&self, nom: &str) -> bool {
        self.chercher(nom, b'v').is_some_and(|e| self.donnees(&e, 8).is_some())
    }

    /// Les noms complets des valeurs de la table (genre `v`), triés et sans doublon, comme `gvdb_table_get_names` les
    /// rebâtit : un nom n'existe que si la chaîne de ses parents mène à la racine. `None` : noms trop longs en tout,
    /// ou qui ne sont pas de l'UTF-8.
    pub(crate) fn noms_des_valeurs(&self) -> Option<Vec<String>> {
        enum Nom {
            Inconnu,
            EnCours,
            Aucun,
            Connu(Vec<u8>),
        }
        let mut noms: Vec<Nom> = (0..self.n).map(|_| Nom::Inconnu).collect();
        let mut total = 0usize;
        for i in 0..self.n {
            // Monter jusqu'à un nom déjà rebâti, la racine ou une impasse ; chaque élément n'est rebâti qu'une fois.
            let mut pile = Vec::new();
            let mut courant = i;
            let mut debut: Option<Vec<u8>> = loop {
                match noms.get(courant)? {
                    Nom::Connu(n) => break Some(n.clone()),
                    // Une boucle de parents, ou une chaîne déjà sans issue.
                    Nom::EnCours | Nom::Aucun => break None,
                    Nom::Inconnu => {}
                }
                *noms.get_mut(courant)? = Nom::EnCours;
                pile.push(courant);
                let parent = self.element(courant)?.parent;
                if parent == u32::MAX {
                    break Some(Vec::new());
                }
                let Some(p) = usize::try_from(parent).ok().filter(|&p| p < self.n) else {
                    break None;
                };
                courant = p;
            };
            for &j in pile.iter().rev() {
                let e = self.element(j)?;
                debut = match (debut, self.morceau(&e)) {
                    (Some(mut nom), Some(morceau)) => {
                        nom.extend_from_slice(morceau);
                        total = total.checked_add(nom.len())?;
                        if total > NOMS_OCTETS_MAX {
                            return None;
                        }
                        Some(nom)
                    }
                    _ => None,
                };
                *noms.get_mut(j)? = debut.clone().map_or(Nom::Aucun, Nom::Connu);
            }
        }
        let mut valeurs = Vec::new();
        for (i, nom) in noms.into_iter().enumerate() {
            if let Nom::Connu(nom) = nom
                && self.element(i)?.genre == b'v'
            {
                valeurs.push(String::from_utf8(nom).ok()?);
            }
        }
        valeurs.sort_unstable();
        valeurs.dedup();
        Some(valeurs)
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Types GVariant

/// Un type GVariant. `Simple` : une lettre de base (b y n q i u x t h d s o g).
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Genre {
    Simple(u8),
    Variante,
    Tableau(Box<Genre>),
    Peut(Box<Genre>),
    Tuple(Vec<Genre>),
    Entree(Box<Genre>, Box<Genre>),
}

const SIMPLES: &[u8] = b"bynqiuxthdsog";

impl Genre {
    /// Un type complet, et rien d'autre, depuis sa chaîne (« as », « (s(yau)) »…).
    pub(crate) fn depuis(texte: &[u8]) -> Option<Genre> {
        let mut position = 0;
        let g = lire_genre(texte, &mut position, 0)?;
        (position == texte.len()).then_some(g)
    }

    pub(crate) fn chaine(&self) -> String {
        match self {
            Genre::Simple(c) => char::from(*c).to_string(),
            Genre::Variante => "v".to_string(),
            Genre::Tableau(e) => format!("a{}", e.chaine()),
            Genre::Peut(e) => format!("m{}", e.chaine()),
            Genre::Tuple(m) => format!("({})", m.iter().map(Genre::chaine).collect::<String>()),
            Genre::Entree(k, v) => format!("{{{}{}}}", k.chaine(), v.chaine()),
        }
    }

    /// L'alignement d'une valeur de ce type (pour l'écriture et les tests ; le décodage lit celui de son `Plan`).
    fn alignement(&self) -> usize {
        Plan::de(self).alignement
    }

    /// La taille d'une valeur de ce type quand elle est fixe ; `None` pour les chaînes, tableaux, variantes…
    fn taille_fixe(&self) -> Option<usize> {
        Plan::de(self).taille
    }
}

/// Ce que le décodage d'un type demande, calculé une fois par type plutôt qu'à chaque valeur : la taille et
/// l'alignement d'un n-uplet imbriqué, recalculés à chaque élément et à chaque niveau, coûtaient le cube de sa
/// profondeur pour chaque élément d'un tableau.
struct Plan<'g> {
    genre: &'g Genre,
    taille: Option<usize>,
    alignement: usize,
    /// Nœuds du type : ce que coûte une copie de `genre`.
    noeuds: usize,
    /// L'élément (tableau, « peut-être ») ou les membres (n-uplet, entrée).
    enfants: Vec<Plan<'g>>,
}

impl<'g> Plan<'g> {
    fn de(genre: &'g Genre) -> Plan<'g> {
        let enfants: Vec<Plan<'g>> = match genre {
            Genre::Simple(_) | Genre::Variante => Vec::new(),
            Genre::Tableau(e) | Genre::Peut(e) => vec![Plan::de(e)],
            Genre::Tuple(m) => m.iter().map(Plan::de).collect(),
            Genre::Entree(k, v) => vec![Plan::de(k), Plan::de(v)],
        };
        let (taille, alignement) = match genre {
            Genre::Simple(b'b' | b'y') => (Some(1), 1),
            Genre::Simple(b'n' | b'q') => (Some(2), 2),
            Genre::Simple(b'i' | b'u' | b'h') => (Some(4), 4),
            Genre::Simple(b'x' | b't' | b'd') => (Some(8), 8),
            Genre::Simple(_) => (None, 1),
            Genre::Variante => (None, 8),
            // Un seul enfant : son alignement est le plus grand.
            Genre::Tableau(_) | Genre::Peut(_) => (None, enfants.iter().map(|m| m.alignement).max().unwrap_or(1)),
            Genre::Tuple(_) | Genre::Entree(..) => {
                let alignement = enfants.iter().map(|m| m.alignement).max().unwrap_or(1);
                (taille_membres(&enfants, alignement), alignement)
            }
        };
        let noeuds = enfants.iter().fold(1usize, |n, e| n.saturating_add(e.noeuds));
        Plan {
            genre,
            taille,
            alignement,
            noeuds,
            enfants,
        }
    }
}

fn taille_membres(membres: &[Plan], alignement: usize) -> Option<usize> {
    let mut taille = 0;
    for m in membres {
        taille = aligner(taille, m.alignement)?.checked_add(m.taille?)?;
    }
    // Un n-uplet vide occupe tout de même un octet.
    Some(aligner(taille, alignement)?.max(1))
}

fn aligner(position: usize, alignement: usize) -> Option<usize> {
    position.checked_next_multiple_of(alignement)
}

fn lire_genre(texte: &[u8], position: &mut usize, profondeur: usize) -> Option<Genre> {
    if profondeur > PROFONDEUR_MAX {
        return None;
    }
    let dessous = profondeur.checked_add(1)?;
    let c = *texte.get(*position)?;
    *position = position.checked_add(1)?;
    Some(match c {
        b'v' => Genre::Variante,
        b'a' => Genre::Tableau(Box::new(lire_genre(texte, position, dessous)?)),
        b'm' => Genre::Peut(Box::new(lire_genre(texte, position, dessous)?)),
        b'(' => {
            let mut membres = Vec::new();
            while *texte.get(*position)? != b')' {
                membres.push(lire_genre(texte, position, dessous)?);
            }
            *position = position.checked_add(1)?;
            Genre::Tuple(membres)
        }
        b'{' => {
            let cle = lire_genre(texte, position, dessous)?;
            // La clé d'un dictionnaire est toujours d'un type de base.
            if !matches!(cle, Genre::Simple(_)) {
                return None;
            }
            let valeur = lire_genre(texte, position, dessous)?;
            if *texte.get(*position)? != b'}' {
                return None;
            }
            *position = position.checked_add(1)?;
            Genre::Entree(Box::new(cle), Box::new(valeur))
        }
        c if SIMPLES.contains(&c) => Genre::Simple(c),
        _ => return None,
    })
}

// ---------------------------------------------------------------------------------------------------------------
// Valeurs GVariant

/// Une valeur GVariant décodée.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Variante {
    Booleen(bool),
    Octet(u8),
    Entier16(i16),
    Naturel16(u16),
    Entier32(i32),
    Naturel32(u32),
    Entier64(i64),
    Naturel64(u64),
    Poignee(i32),
    Double(f64),
    Chaine(String),
    Objet(String),
    Signature(String),
    Boite(Box<Variante>),
    /// Type de l'élément, et la valeur s'il y en a une.
    Peut(Genre, Option<Box<Variante>>),
    /// Type des éléments, et les éléments.
    Tableau(Genre, Vec<Variante>),
    Tuple(Vec<Variante>),
    Entree(Box<Variante>, Box<Variante>),
}

impl Variante {
    pub(crate) fn genre(&self) -> Genre {
        match self {
            Variante::Booleen(_) => Genre::Simple(b'b'),
            Variante::Octet(_) => Genre::Simple(b'y'),
            Variante::Entier16(_) => Genre::Simple(b'n'),
            Variante::Naturel16(_) => Genre::Simple(b'q'),
            Variante::Entier32(_) => Genre::Simple(b'i'),
            Variante::Naturel32(_) => Genre::Simple(b'u'),
            Variante::Entier64(_) => Genre::Simple(b'x'),
            Variante::Naturel64(_) => Genre::Simple(b't'),
            Variante::Poignee(_) => Genre::Simple(b'h'),
            Variante::Double(_) => Genre::Simple(b'd'),
            Variante::Chaine(_) => Genre::Simple(b's'),
            Variante::Objet(_) => Genre::Simple(b'o'),
            Variante::Signature(_) => Genre::Simple(b'g'),
            Variante::Boite(_) => Genre::Variante,
            Variante::Peut(g, _) => Genre::Peut(Box::new(g.clone())),
            Variante::Tableau(g, _) => Genre::Tableau(Box::new(g.clone())),
            Variante::Tuple(m) => Genre::Tuple(m.iter().map(Variante::genre).collect()),
            Variante::Entree(k, v) => Genre::Entree(Box::new(k.genre()), Box::new(v.genre())),
        }
    }

    pub(crate) fn chaine(&self) -> Option<&str> {
        match self {
            Variante::Chaine(s) => Some(s),
            _ => None,
        }
    }

    /// Les chaînes d'un tableau de chaînes (« as »).
    pub(crate) fn chaines(&self) -> Option<Vec<&str>> {
        match self {
            Variante::Tableau(Genre::Simple(b's'), v) => v.iter().map(Variante::chaine).collect(),
            _ => None,
        }
    }

    /// Le texte que donnerait `g_variant_print (valeur, TRUE)`, donc `gsettings get` : `true`, `uint32 300`,
    /// `'none'`, `['a', 'b']`, `@as []`. `None` pour ce que ce lecteur ne sait pas écrire à l'identique
    /// (nombres à virgule, octets, « peut-être », dictionnaires, caractères dont GLib décide l'échappement par ses
    /// tables Unicode) : l'appelant demande alors à la commande.
    pub(crate) fn texte(&self) -> Option<String> {
        let mut s = String::new();
        self.ecrire(&mut s, true)?;
        Some(s)
    }

    fn ecrire(&self, s: &mut String, annoter: bool) -> Option<()> {
        let prefixe = |s: &mut String, p: &str| {
            if annoter {
                s.push_str(p);
            }
        };
        match self {
            Variante::Booleen(b) => s.push_str(if *b { "true" } else { "false" }),
            Variante::Entier16(n) => {
                prefixe(s, "int16 ");
                s.push_str(&n.to_string());
            }
            Variante::Naturel16(n) => {
                prefixe(s, "uint16 ");
                s.push_str(&n.to_string());
            }
            // int32 n'est jamais annoté : c'est le type des nombres par défaut.
            Variante::Entier32(n) => s.push_str(&n.to_string()),
            Variante::Naturel32(n) => {
                prefixe(s, "uint32 ");
                s.push_str(&n.to_string());
            }
            Variante::Entier64(n) => {
                prefixe(s, "int64 ");
                s.push_str(&n.to_string());
            }
            Variante::Naturel64(n) => {
                prefixe(s, "uint64 ");
                s.push_str(&n.to_string());
            }
            Variante::Poignee(n) => {
                prefixe(s, "handle ");
                s.push_str(&n.to_string());
            }
            Variante::Chaine(t) => ecrire_chaine(s, t)?,
            Variante::Objet(t) => {
                prefixe(s, "objectpath ");
                s.push('\'');
                s.push_str(t);
                s.push('\'');
            }
            Variante::Signature(t) => {
                prefixe(s, "signature ");
                s.push('\'');
                s.push_str(t);
                s.push('\'');
            }
            Variante::Boite(v) => {
                s.push('<');
                v.ecrire(s, true)?;
                s.push('>');
            }
            Variante::Tableau(g, v) => {
                // Un tableau d'octets s'écrit en b'…', un dictionnaire entre accolades : non repris ici.
                if matches!(g, Genre::Simple(b'y') | Genre::Entree(..)) {
                    return None;
                }
                if v.is_empty() {
                    if annoter {
                        s.push('@');
                        s.push_str(&self.genre().chaine());
                        s.push(' ');
                    }
                    s.push_str("[]");
                } else {
                    s.push('[');
                    for (i, e) in v.iter().enumerate() {
                        if i > 0 {
                            s.push_str(", ");
                        }
                        // Seul le premier élément porte son type : il vaut pour tous.
                        e.ecrire(s, annoter && i == 0)?;
                    }
                    s.push(']');
                }
            }
            Variante::Tuple(m) => {
                s.push('(');
                for (i, e) in m.iter().enumerate() {
                    if i > 0 {
                        s.push_str(", ");
                    }
                    e.ecrire(s, annoter)?;
                }
                if m.len() == 1 {
                    s.push(',');
                }
                s.push(')');
            }
            Variante::Octet(_) | Variante::Double(_) | Variante::Peut(..) | Variante::Entree(..) => return None,
        }
        Some(())
    }
}

/// Une chaîne entre guillemets simples, doubles si elle contient une apostrophe ; la barre oblique inverse et le
/// guillemet choisi sont échappés, les caractères de contrôle aussi (\n, \t, \u0001…). GLib échappe en plus ce que
/// ses tables Unicode disent non imprimable (formats, caractères non attribués) : hors de l'ASCII, seuls les lettres,
/// chiffres et espaces sont écrits ici, le reste rend `None`.
fn ecrire_chaine(s: &mut String, t: &str) -> Option<()> {
    let guillemet = if t.contains('\'') { '"' } else { '\'' };
    s.push(guillemet);
    for c in t.chars() {
        if c == guillemet || c == '\\' {
            s.push('\\');
            s.push(c);
        } else if c.is_control() {
            s.push('\\');
            match c {
                '\u{7}' => s.push('a'),
                '\u{8}' => s.push('b'),
                '\u{c}' => s.push('f'),
                '\n' => s.push('n'),
                '\r' => s.push('r'),
                '\t' => s.push('t'),
                '\u{b}' => s.push('v'),
                _ => {
                    let _ = write!(s, "u{:04x}", u32::from(c));
                }
            }
        } else if c.is_ascii() || c.is_alphanumeric() || c.is_whitespace() {
            s.push(c);
        } else {
            return None;
        }
    }
    s.push(guillemet);
    Some(())
}

/// Taille des décalages de fin d'un conteneur de `taille` octets, comme GLib la choisit.
fn taille_decalage(taille: usize) -> usize {
    match taille {
        0 => 0,
        1..=0xff => 1,
        0x100..=0xffff => 2,
        0x1_0000..=0xffff_ffff => 4,
        _ => 8,
    }
}

fn lire_decalage(octets: &[u8]) -> Option<usize> {
    let mut mot = [0u8; 8];
    mot.get_mut(..octets.len())?.copy_from_slice(octets);
    usize::try_from(u64::from_le_bytes(mot)).ok()
}

/// Décode `octets`, sérialisés comme le type `genre`. `None` : données qui ne sont pas sous la forme normale que
/// GLib écrit (taille fausse, chaîne sans zéro final, décalage hors du conteneur…), ou qui produiraient plus de
/// `NOEUDS_MAX` valeurs.
pub(crate) fn decoder(genre: &Genre, octets: &[u8]) -> Option<Variante> {
    let mut budget = NOEUDS_MAX;
    decoder_plan(&Plan::de(genre), octets, 0, &mut budget)
}

/// Retire `n` du budget de valeurs ; `None` quand il est épuisé.
fn depenser(budget: &mut usize, n: usize) -> Option<()> {
    *budget = budget.checked_sub(n)?;
    Some(())
}

fn decoder_plan(plan: &Plan, octets: &[u8], profondeur: usize, budget: &mut usize) -> Option<Variante> {
    if profondeur > PROFONDEUR_MAX {
        return None;
    }
    depenser(budget, 1)?;
    let dessous = profondeur.checked_add(1)?;
    if let Some(taille) = plan.taille
        && octets.len() != taille
    {
        return None;
    }
    let tableau = |o: &[u8]| -> Option<[u8; 8]> {
        let mut m = [0u8; 8];
        m.get_mut(..o.len())?.copy_from_slice(o);
        Some(m)
    };
    Some(match plan.genre {
        Genre::Simple(c) => match c {
            b'b' => match octets {
                [0] => Variante::Booleen(false),
                [1] => Variante::Booleen(true),
                _ => return None,
            },
            b'y' => Variante::Octet(u8::from_le_bytes(octets.try_into().ok()?)),
            b'n' => Variante::Entier16(i16::from_le_bytes(octets.try_into().ok()?)),
            b'q' => Variante::Naturel16(u16::from_le_bytes(octets.try_into().ok()?)),
            b'i' => Variante::Entier32(i32::from_le_bytes(octets.try_into().ok()?)),
            b'h' => Variante::Poignee(i32::from_le_bytes(octets.try_into().ok()?)),
            b'u' => Variante::Naturel32(u32::from_le_bytes(octets.try_into().ok()?)),
            b'x' => Variante::Entier64(i64::from_le_bytes(tableau(octets)?)),
            b't' => Variante::Naturel64(u64::from_le_bytes(tableau(octets)?)),
            b'd' => Variante::Double(f64::from_le_bytes(tableau(octets)?)),
            _ => {
                let (zero, texte) = octets.split_last()?;
                if *zero != 0 || texte.contains(&0) {
                    return None;
                }
                let texte = std::str::from_utf8(texte).ok()?.to_string();
                match c {
                    b's' => Variante::Chaine(texte),
                    b'o' => Variante::Objet(texte),
                    _ => Variante::Signature(texte),
                }
            }
        },
        Genre::Variante => {
            let zero = octets.iter().rposition(|&o| o == 0)?;
            let (valeur, apres) = octets.split_at_checked(zero)?;
            let interieur = Genre::depuis(apres.get(1..)?)?;
            let p = Plan::de(&interieur);
            depenser(budget, p.noeuds)?;
            Variante::Boite(Box::new(decoder_plan(&p, valeur, dessous, budget)?))
        }
        Genre::Peut(e) => {
            let pe = plan.enfants.first()?;
            depenser(budget, pe.noeuds)?;
            let valeur = if octets.is_empty() {
                None
            } else if pe.taille.is_some() {
                Some(decoder_plan(pe, octets, dessous, budget)?)
            } else {
                let (zero, reste) = octets.split_last()?;
                if *zero != 0 {
                    return None;
                }
                Some(decoder_plan(pe, reste, dessous, budget)?)
            };
            Variante::Peut((**e).clone(), valeur.map(Box::new))
        }
        Genre::Tableau(e) => {
            let pe = plan.enfants.first()?;
            depenser(budget, pe.noeuds)?;
            Variante::Tableau((**e).clone(), elements(pe, octets, profondeur, budget)?)
        }
        Genre::Tuple(_) | Genre::Entree(..) => {
            let n = plan.enfants.len();
            let tde = taille_decalage(octets.len());
            let mut fin_decalages = octets.len();
            let mut position = 0;
            let mut valeurs = Vec::with_capacity(n);
            for (i, m) in plan.enfants.iter().enumerate() {
                position = aligner(position, m.alignement)?;
                let fin = match m.taille {
                    Some(t) => position.checked_add(t)?,
                    None if i.checked_add(1) == Some(n) => fin_decalages,
                    None => {
                        fin_decalages = fin_decalages.checked_sub(tde)?;
                        lire_decalage(octets.get(fin_decalages..fin_decalages.checked_add(tde)?)?)?
                    }
                };
                if position > fin || fin > fin_decalages {
                    return None;
                }
                valeurs.push(decoder_plan(m, octets.get(position..fin)?, dessous, budget)?);
                position = fin;
            }
            match plan.genre {
                Genre::Entree(..) => {
                    let mut v = valeurs.into_iter();
                    Variante::Entree(Box::new(v.next()?), Box::new(v.next()?))
                }
                _ => Variante::Tuple(valeurs),
            }
        }
    })
}

fn elements(e: &Plan, octets: &[u8], profondeur: usize, budget: &mut usize) -> Option<Vec<Variante>> {
    let dessous = profondeur.checked_add(1)?;
    if let Some(taille) = e.taille {
        if !octets.len().is_multiple_of(taille) || octets.len().checked_div(taille)? > *budget {
            return None;
        }
        return octets
            .chunks(taille)
            .map(|o| decoder_plan(e, o, dessous, budget))
            .collect();
    }
    if octets.is_empty() {
        return Some(Vec::new());
    }
    let tde = taille_decalage(octets.len());
    let debut_decalages = lire_decalage(octets.get(octets.len().checked_sub(tde)?..)?)?;
    let place = octets.len().checked_sub(debut_decalages)?;
    let n = place.checked_div(tde)?;
    if !place.is_multiple_of(tde) || n > *budget {
        return None;
    }
    let mut valeurs = Vec::with_capacity(n);
    let mut position = 0;
    for mot in octets.get(debut_decalages..)?.chunks(tde) {
        let fin = lire_decalage(mot)?;
        position = aligner(position, e.alignement)?;
        if position > fin || fin > debut_decalages {
            return None;
        }
        valeurs.push(decoder_plan(e, octets.get(position..fin)?, dessous, budget)?);
        position = fin;
    }
    Some(valeurs)
}

// ---------------------------------------------------------------------------------------------------------------
// Écriture GVariant (l'écrivain de dconf, et les tests), puis fabrique de fichiers GVDB pour les tests.

/// L'écriture d'une valeur au format sérialisé de GVariant (celui de GLib, petit-boutiste) : ce que l'écrivain de
/// dconf attend dans un changement (`dconf::changement`), et ce que les essais fabriquent.
pub(crate) mod ecriture {
    use super::{Variante, taille_decalage};

    pub(crate) fn completer(sortie: &mut Vec<u8>, alignement: usize) {
        // Un Vec ne dépasse pas isize::MAX octets : le multiple suivant (8 au plus de plus) ne déborde pas.
        sortie.resize(sortie.len().next_multiple_of(alignement.max(1)), 0);
    }

    pub(crate) fn decalages(corps: &mut Vec<u8>, fins: &[usize]) {
        let mut tde = 1;
        // Une somme au-delà de usize ne prend de toute façon que la plus grande largeur.
        while taille_decalage(corps.len().saturating_add(fins.len().saturating_mul(tde))) > tde {
            #[expect(
                clippy::arithmetic_side_effects,
                reason = "tde < taille_decalage(…) ≤ 8 ici : le double tient"
            )]
            let double = tde * 2;
            tde = double;
        }
        for f in fins {
            // `tde` vaut 1, 2, 4 ou 8 (taille_decalage) : les octets de poids faible, sur sa largeur.
            corps.extend(f.to_le_bytes().iter().take(tde));
        }
    }

    /// La forme sérialisée de `v`, celle qu'écrit GLib.
    pub(crate) fn serialiser(v: &Variante) -> Vec<u8> {
        match v {
            Variante::Booleen(b) => vec![u8::from(*b)],
            Variante::Octet(o) => vec![*o],
            Variante::Entier16(n) => n.to_le_bytes().to_vec(),
            Variante::Naturel16(n) => n.to_le_bytes().to_vec(),
            Variante::Entier32(n) | Variante::Poignee(n) => n.to_le_bytes().to_vec(),
            Variante::Naturel32(n) => n.to_le_bytes().to_vec(),
            Variante::Entier64(n) => n.to_le_bytes().to_vec(),
            Variante::Naturel64(n) => n.to_le_bytes().to_vec(),
            Variante::Double(n) => n.to_le_bytes().to_vec(),
            Variante::Chaine(s) | Variante::Objet(s) | Variante::Signature(s) => {
                let mut o = s.as_bytes().to_vec();
                o.push(0);
                o
            }
            Variante::Boite(v) => {
                let mut o = serialiser(v);
                o.push(0);
                o.extend_from_slice(v.genre().chaine().as_bytes());
                o
            }
            Variante::Peut(g, v) => match v {
                None => Vec::new(),
                Some(v) => {
                    let mut o = serialiser(v);
                    if g.taille_fixe().is_none() {
                        o.push(0);
                    }
                    o
                }
            },
            Variante::Tableau(g, v) => {
                let mut o = Vec::new();
                let mut fins = Vec::new();
                for e in v {
                    completer(&mut o, g.alignement());
                    o.extend(serialiser(e));
                    fins.push(o.len());
                }
                if g.taille_fixe().is_none() && !v.is_empty() {
                    decalages(&mut o, &fins);
                }
                o
            }
            Variante::Tuple(_) | Variante::Entree(..) => {
                let membres: Vec<&Variante> = match v {
                    Variante::Tuple(m) => m.iter().collect(),
                    Variante::Entree(k, v) => vec![k, v],
                    _ => unreachable!(),
                };
                let genre = v.genre();
                let mut o = Vec::new();
                let mut fins = Vec::new();
                for (i, m) in membres.iter().enumerate() {
                    let g = m.genre();
                    completer(&mut o, g.alignement());
                    o.extend(serialiser(m));
                    if g.taille_fixe().is_none() && i.checked_add(1).is_some_and(|suivant| suivant < membres.len()) {
                        fins.push(o.len());
                    }
                }
                if let Some(t) = genre.taille_fixe() {
                    o.resize(t, 0);
                } else {
                    fins.reverse();
                    decalages(&mut o, &fins);
                }
                o
            }
        }
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
pub(crate) mod fabrique {
    use super::ecriture::completer;
    pub(crate) use super::ecriture::serialiser;
    use super::{Genre, Variante, hachage};

    /// Le contenu d'une table à fabriquer : une valeur, une table imbriquée ou un dossier de dconf (genre `L`).
    pub(crate) enum Contenu {
        Valeur(Variante),
        Table(Vec<(String, Contenu)>),
        Dossier,
    }

    pub(crate) fn valeur(nom: &str, v: Variante) -> (String, Contenu) {
        (nom.to_string(), Contenu::Valeur(v))
    }

    fn mot(sortie: &mut [u8], position: usize, valeur: usize) {
        let v = u32::try_from(valeur).expect("fichier de test trop grand");
        sortie[position..position + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// Range la table `entrees` à la fin de `sortie` ; rend son étendue. Avec `parents`, un nom dont le début est
    /// celui d'un dossier (« /org/gnome/ ») n'en garde que la fin et pointe vers lui, comme dconf.
    fn ecrire_table(sortie: &mut Vec<u8>, entrees: &[(String, Contenu)], parents: bool) -> (usize, usize) {
        completer(sortie, 4);
        let n = entrees.len();
        let seaux = n.max(1);
        let mut ordre: Vec<usize> = (0..n).collect();
        ordre.sort_by_key(|&i| hachage(entrees[i].0.as_bytes()) as usize % seaux);
        let index: Vec<usize> = {
            let mut index = vec![0; n];
            for (place, &i) in ordre.iter().enumerate() {
                index[i] = place;
            }
            index
        };
        let debut = sortie.len();
        sortie.resize(debut + 8 + seaux * 4 + n * 24, 0);
        mot(sortie, debut, 0);
        mot(sortie, debut + 4, seaux);
        for s in 0..seaux {
            let premier = ordre
                .iter()
                .position(|&i| hachage(entrees[i].0.as_bytes()) as usize % seaux >= s)
                .unwrap_or(n);
            mot(sortie, debut + 8 + 4 * s, premier);
        }
        let fin = sortie.len();
        for (place, &i) in ordre.iter().enumerate() {
            let (nom, contenu) = &entrees[i];
            let parent = parents
                .then(|| {
                    entrees
                        .iter()
                        .enumerate()
                        .filter(|(j, (p, c))| {
                            *j != i && matches!(c, Contenu::Dossier) && nom.starts_with(p.as_str()) && nom != p
                        })
                        .max_by_key(|(_, (p, _))| p.len())
                        .map(|(j, (p, _))| (j, p.len()))
                })
                .flatten();
            let (parent, propre) = match parent {
                Some((j, longueur)) => (index[j], &nom[longueur..]),
                None => (u32::MAX as usize, nom.as_str()),
            };
            let e = debut + 8 + seaux * 4 + 24 * place;
            mot(sortie, e, hachage(nom.as_bytes()) as usize);
            mot(sortie, e + 4, parent);
            let debut_nom = sortie.len();
            sortie.extend_from_slice(propre.as_bytes());
            mot(sortie, e + 8, debut_nom);
            sortie[e + 12..e + 14].copy_from_slice(&u16::try_from(propre.len()).expect("nom court").to_le_bytes());
            let (genre, etendue) = match contenu {
                Contenu::Valeur(v) => {
                    completer(sortie, 8);
                    let d = sortie.len();
                    sortie.extend(serialiser(&Variante::Boite(Box::new(v.clone()))));
                    (b'v', (d, sortie.len()))
                }
                Contenu::Table(t) => (b'H', ecrire_table(sortie, t, parents)),
                Contenu::Dossier => (b'L', (sortie.len(), sortie.len())),
            };
            sortie[e + 14] = genre;
            mot(sortie, e + 16, etendue.0);
            mot(sortie, e + 20, etendue.1);
        }
        (debut, fin)
    }

    /// Un fichier GVDB complet dont la racine est `entrees`.
    pub(crate) fn fichier(entrees: &[(String, Contenu)], parents: bool) -> Vec<u8> {
        let mut sortie = b"GVariant".to_vec();
        sortie.resize(24, 0);
        let (debut, fin) = ecrire_table(&mut sortie, entrees, parents);
        mot(&mut sortie, 16, debut);
        mot(&mut sortie, 20, fin);
        sortie
    }

    /// Une base de dconf : les dossiers de chaque clé, la clé, et les verrous dans la table `.locks`.
    pub(crate) fn base_dconf(valeurs: &[(&str, Variante)], verrous: &[&str]) -> Vec<u8> {
        let mut entrees: Vec<(String, Contenu)> = Vec::new();
        let mut dossiers: Vec<String> = Vec::new();
        for (cle, v) in valeurs {
            let mut fin = 0;
            while let Some(p) = cle[fin + 1..].find('/') {
                fin += p + 1;
                let dossier = cle[..=fin].to_string();
                if !dossiers.contains(&dossier) {
                    dossiers.push(dossier);
                }
            }
            entrees.push(valeur(cle, v.clone()));
        }
        if !dossiers.iter().any(|d| d == "/") {
            dossiers.push("/".to_string());
        }
        entrees.extend(dossiers.into_iter().map(|d| (d, Contenu::Dossier)));
        if !verrous.is_empty() {
            entrees.push((
                ".locks".to_string(),
                Contenu::Table(
                    verrous
                        .iter()
                        .map(|v| valeur(v, Variante::Chaine(String::new())))
                        .collect(),
                ),
            ));
        }
        fichier(&entrees, true)
    }

    /// Les octets d'un texte hexadécimal (fichiers relevés tels que leurs programmes les écrivent).
    pub(crate) fn hexa(texte: &str) -> Vec<u8> {
        let chiffres: Vec<u8> = texte.bytes().filter(u8::is_ascii_hexdigit).collect();
        chiffres
            .chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).expect("hexadécimal"), 16).expect("hexadécimal"))
            .collect()
    }

    pub(crate) fn chaines(v: &[&str]) -> Variante {
        Variante::Tableau(
            Genre::Simple(b's'),
            v.iter().map(|s| Variante::Chaine((*s).to_string())).collect(),
        )
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::fabrique::{Contenu, base_dconf, chaines, fichier, hexa, serialiser, valeur};
    use super::*;

    fn aller_retour(v: &Variante) {
        let octets = serialiser(v);
        assert_eq!(decoder(&v.genre(), &octets).as_ref(), Some(v), "{v:?} : {octets:?}");
    }

    #[test]
    fn types_depuis_leur_chaine() {
        for t in [
            "b",
            "as",
            "(s(yau))",
            "a{sv}",
            "(va{sas})",
            "mmi",
            "()",
            "a(ii)",
            "{sv}",
        ] {
            assert_eq!(Genre::depuis(t.as_bytes()).map(|g| g.chaine()).as_deref(), Some(t));
        }
        for t in ["", "a", "(i", "{vs}", "{s}", "z", "ii", "{sii}"] {
            assert_eq!(Genre::depuis(t.as_bytes()), None, "{t}");
        }
        // Une imbrication sans fin, forgée, est refusée sans épuiser la pile.
        assert_eq!(Genre::depuis(&[b'a'; 10_000]), None);
        assert_eq!(
            Genre::depuis(format!("{}i{}", "(".repeat(5000), ")".repeat(5000)).as_bytes()),
            None
        );
    }

    #[test]
    fn tailles_et_alignements_de_glib() {
        let g = |t: &str| Genre::depuis(t.as_bytes()).expect(t);
        assert_eq!(g("(yu)").taille_fixe(), Some(8));
        assert_eq!(g("(uy)").taille_fixe(), Some(8));
        assert_eq!(g("(ii)").taille_fixe(), Some(8));
        assert_eq!(g("(bdy)").taille_fixe(), Some(24));
        assert_eq!(g("()").taille_fixe(), Some(1));
        assert_eq!(g("(ys)").taille_fixe(), None);
        assert_eq!(g("(yx)").alignement(), 8);
    }

    #[test]
    fn valeurs_aller_retour() {
        let s = |t: &str| Variante::Chaine(t.to_string());
        for v in [
            Variante::Booleen(true),
            Variante::Naturel32(300),
            Variante::Entier32(-7),
            Variante::Entier64(-1 << 40),
            Variante::Naturel16(65535),
            Variante::Double(0.5),
            s("none"),
            s(""),
            chaines(&["localhost", "127.0.0.0/8", "::1"]),
            chaines(&[]),
            Variante::Tuple(vec![Variante::Entier32(890), Variante::Entier32(550)]),
            Variante::Tuple(vec![
                s("none"),
                Variante::Tuple(vec![
                    Variante::Octet(b'e'),
                    Variante::Tableau(
                        Genre::Simple(b'u'),
                        vec![Variante::Naturel32(0), Variante::Naturel32(u32::MAX)],
                    ),
                ]),
            ]),
            Variante::Boite(Box::new(Variante::Booleen(false))),
            Variante::Peut(Genre::Simple(b's'), Some(Box::new(s("x")))),
            Variante::Peut(Genre::Simple(b'i'), None),
            Variante::Tableau(
                Genre::Entree(
                    Box::new(Genre::Simple(b's')),
                    Box::new(Genre::Tableau(Box::new(Genre::Simple(b's')))),
                ),
                vec![Variante::Entree(
                    Box::new(s("org.exemple.Camera")),
                    Box::new(chaines(&["yes"])),
                )],
            ),
            // Plus de 255 octets : les décalages passent à deux octets.
            chaines(&vec!["une chaîne assez longue pour grossir le tableau"; 20]),
        ] {
            aller_retour(&v);
        }
    }

    /// Octets écrits par GLib (gschemas.compiled de GNOME, base de dconf) : le décodage les relit tels quels.
    #[test]
    fn octets_ecrits_par_glib() {
        let v = |o: &[u8]| decoder(&Genre::Variante, o);
        assert_eq!(
            v(b",\x01\x00\x00\x00(u)"),
            Some(Variante::Boite(Box::new(Variante::Tuple(vec![Variante::Naturel32(
                300
            )]))))
        );
        assert_eq!(
            v(b"localhost\x00127.0.0.0/8\x00::1\x00\n\x16\x1a\x00(as)").and_then(|b| match b {
                Variante::Boite(t) => Some(*t),
                _ => None,
            }),
            Some(Variante::Tuple(vec![chaines(&["localhost", "127.0.0.0/8", "::1"])]))
        );
        let mode = v(b"none\x00\x00\x00\x00e\x00\x00\x00\x00\x00\x00\x00\xffnone\x00\x00\xff\x01\x00\x00\x00\xffmanual\x00\x00\x00\x00\xff\x02\x00\x00\x00\xffauto\x00\x00\xff\x05\x00(s(yau))");
        let Some(Variante::Boite(t)) = mode else {
            panic!("{mode:?}")
        };
        let Variante::Tuple(m) = *t else { panic!() };
        assert_eq!(m[0], Variante::Chaine("none".into()));
        assert!(matches!(&m[1], Variante::Tuple(x) if x[0] == Variante::Octet(b'e')));
        assert_eq!(
            v(b"z\x03\x00\x00&\x02\x00\x00\x00(ii)"),
            Some(Variante::Boite(Box::new(Variante::Tuple(vec![
                Variante::Entier32(890),
                Variante::Entier32(550)
            ]))))
        );
    }

    #[test]
    fn donnees_forgees_refusees() {
        let s = |g: &str, o: &[u8]| decoder(&Genre::depuis(g.as_bytes()).unwrap(), o);
        assert_eq!(s("s", b"abc"), None, "sans zéro final");
        assert_eq!(s("s", b"a\0c\0"), None, "zéro au milieu");
        assert_eq!(s("s", b"\xff\0"), None, "pas de l'UTF-8");
        assert_eq!(s("b", b"\x02"), None);
        assert_eq!(s("u", b"\x01\x00"), None, "taille fausse");
        assert_eq!(s("as", b"a\0\x09"), None, "décalage hors du conteneur");
        assert_eq!(s("(si)", b"a\0\0\0\x01\0\0\0\x09"), None);
        assert_eq!(s("v", b"\x01\0zz"), None, "type inconnu");
        // Des variantes imbriquées à l'infini : refusées à la profondeur maximale.
        let mut o = vec![1u8, 0, b'b'];
        for _ in 0..200 {
            o.extend_from_slice(b"\0v");
        }
        assert_eq!(s("v", &o), None);
    }

    #[test]
    fn texte_comme_gsettings() {
        let t = |v: Variante| v.texte();
        assert_eq!(t(Variante::Booleen(true)).as_deref(), Some("true"));
        assert_eq!(t(Variante::Naturel32(300)).as_deref(), Some("uint32 300"));
        assert_eq!(t(Variante::Entier32(1)).as_deref(), Some("1"));
        assert_eq!(t(Variante::Entier64(-2)).as_deref(), Some("int64 -2"));
        assert_eq!(t(Variante::Chaine("none".into())).as_deref(), Some("'none'"));
        assert_eq!(t(Variante::Chaine("l'été".into())).as_deref(), Some("\"l'été\""));
        assert_eq!(t(Variante::Chaine("a\\b\n".into())).as_deref(), Some("'a\\\\b\\n'"));
        assert_eq!(t(Variante::Chaine("\u{1}".into())).as_deref(), Some("'\\u0001'"));
        assert_eq!(
            t(Variante::Chaine("«".into())),
            None,
            "échappement décidé par les tables de GLib"
        );
        assert_eq!(t(chaines(&["a", "b"])).as_deref(), Some("['a', 'b']"));
        assert_eq!(t(chaines(&[])).as_deref(), Some("@as []"));
        assert_eq!(
            t(Variante::Tableau(
                Genre::Simple(b'u'),
                vec![Variante::Naturel32(1), Variante::Naturel32(2)]
            ))
            .as_deref(),
            Some("[uint32 1, 2]")
        );
        assert_eq!(
            t(Variante::Tuple(vec![Variante::Entier32(890), Variante::Entier32(550)])).as_deref(),
            Some("(890, 550)")
        );
        assert_eq!(
            t(Variante::Tuple(vec![Variante::Naturel32(1)])).as_deref(),
            Some("(uint32 1,)")
        );
        assert_eq!(
            t(Variante::Boite(Box::new(Variante::Naturel32(1)))).as_deref(),
            Some("<uint32 1>")
        );
        assert_eq!(t(Variante::Double(1.0)), None);
        assert_eq!(t(Variante::Octet(1)), None);
    }

    #[test]
    fn table_lue_avec_ses_parents() {
        let octets = base_dconf(
            &[
                ("/org/gnome/desktop/screensaver/lock-enabled", Variante::Booleen(false)),
                ("/org/gnome/desktop/session/idle-delay", Variante::Naturel32(600)),
                ("/system/proxy/mode", Variante::Chaine("manual".into())),
            ],
            &["/org/gnome/desktop/screensaver/lock-enabled"],
        );
        let base = Gvdb::depuis(octets).expect("en-tête");
        let racine = base.racine().expect("racine");
        assert_eq!(
            racine.valeur("/org/gnome/desktop/session/idle-delay"),
            Some(Variante::Naturel32(600))
        );
        assert_eq!(
            racine.valeur("/system/proxy/mode"),
            Some(Variante::Chaine("manual".into()))
        );
        assert_eq!(racine.valeur("/system/proxy/"), None, "un dossier n'est pas une valeur");
        assert_eq!(racine.valeur("/absente"), None);
        let verrous = racine.table(".locks").expect("lisible").expect("verrous");
        assert!(verrous.contient_valeur("/org/gnome/desktop/screensaver/lock-enabled"));
        assert!(!verrous.contient_valeur("/system/proxy/mode"));
        assert_eq!(
            racine.noms_des_valeurs().expect("noms"),
            [
                "/org/gnome/desktop/screensaver/lock-enabled",
                "/org/gnome/desktop/session/idle-delay",
                "/system/proxy/mode"
            ]
        );
    }

    /// Une base écrite par `dconf compile` (dconf 51.0 d'Arch), avec un verrou : la même lecture.
    #[test]
    fn base_ecrite_par_dconf() {
        let base = Gvdb::depuis(hexa(BASE_DCONF)).expect("en-tête");
        let racine = base.racine().expect("racine");
        assert_eq!(
            racine.valeur("/org/gnome/desktop/screensaver/lock-enabled"),
            Some(Variante::Booleen(false))
        );
        assert_eq!(
            racine.valeur("/org/gnome/desktop/session/idle-delay"),
            Some(Variante::Naturel32(600))
        );
        assert_eq!(
            racine.valeur("/system/proxy/mode"),
            Some(Variante::Chaine("manual".into()))
        );
        assert!(
            racine
                .table(".locks")
                .expect("lisible")
                .expect("verrous")
                .contient_valeur("/org/gnome/desktop/screensaver/lock-enabled")
        );
    }

    /// Un élément d'une table écrite à la main ; positions comptées depuis le début de la queue du fichier.
    struct Brut {
        hachage: u32,
        parent: u32,
        nom: (usize, usize),
        genre: u8,
        donnees: (usize, usize),
    }

    /// Un fichier GVDB écrit à la main, pour les formes que la fabrique n'écrit pas (filtre de Bloom, éléments
    /// chaînés, positions fausses) : la table racine, puis `queue`, rangée sur 8 octets.
    fn gvdb_brut(bloom: &[u32], seaux: &[u32], elements: &[Brut], queue: &[u8]) -> Vec<u8> {
        let debut = 24;
        let fin = debut + 8 + 4 * (bloom.len() + seaux.len()) + 24 * elements.len();
        let base = aligner(fin, 8).unwrap();
        let u = |n: usize| u32::try_from(n).unwrap().to_le_bytes();
        let mut o = b"GVariant".to_vec();
        o.resize(16, 0);
        o.extend(u(debut));
        o.extend(u(fin));
        o.extend(u(bloom.len()));
        o.extend(u(seaux.len()));
        for m in bloom.iter().chain(seaux) {
            o.extend(m.to_le_bytes());
        }
        for e in elements {
            o.extend(e.hachage.to_le_bytes());
            o.extend(e.parent.to_le_bytes());
            o.extend(u(base + e.nom.0));
            o.extend(u16::try_from(e.nom.1).unwrap().to_le_bytes());
            o.extend([e.genre, 0]);
            o.extend(u(base + e.donnees.0));
            o.extend(u(base + e.donnees.1));
        }
        o.resize(base, 0);
        o.extend_from_slice(queue);
        o
    }

    /// La queue des tests à la main : `true` boîté en 0..3, `false` en 8..11, puis le texte `noms` en 16.
    fn queue(noms: &[u8]) -> Vec<u8> {
        let mut q = b"\x01\0b\0\0\0\0\0\0\0b\0\0\0\0\0".to_vec();
        q.extend_from_slice(noms);
        q
    }

    /// Des éléments chaînés par leur parent, qui portent chacun le même nom de 65 535 octets : rebâtir leurs noms
    /// coûterait n² × 65 535 octets (33 Go pour 1 000 éléments). La recherche, elle, ne coûte que la clé.
    #[test]
    fn noms_chaines_bornes() {
        let long = vec![b'a'; 65_535];
        let elements: Vec<Brut> = (0..1000u32)
            .map(|i| Brut {
                hachage: if i == 0 { hachage(&long) } else { i },
                parent: i.checked_sub(1).unwrap_or(u32::MAX),
                nom: (16, long.len()),
                genre: b'v',
                donnees: (0, 3),
            })
            .collect();
        let fichier = gvdb_brut(&[], &[0], &elements, &queue(&long));
        let debut = std::time::Instant::now();
        let racine = Gvdb::depuis(fichier).unwrap().racine().expect("racine");
        assert_eq!(
            racine.valeur(std::str::from_utf8(&long).unwrap()),
            Some(Variante::Booleen(true))
        );
        assert_eq!(racine.valeur("x"), None);
        assert_eq!(racine.noms_des_valeurs(), None, "noms trop longs en tout");
        assert!(debut.elapsed().as_secs() < 10, "{:?}", debut.elapsed());
    }

    /// La recherche de GLib : le premier élément du seau l'emporte sur un doublon, un hachage faux, une valeur mal
    /// alignée ou un filtre de Bloom qui exclut la clé ne laissent rien trouver.
    #[test]
    fn recherche_comme_glib() {
        let k = |hachage: u32, donnees: (usize, usize)| Brut {
            hachage,
            parent: u32::MAX,
            nom: (16, 1),
            genre: b'v',
            donnees,
        };
        let h = hachage(b"k");
        let lire = |bloom: &[u32], elements: &[Brut]| {
            let t = Gvdb::depuis(gvdb_brut(bloom, &[0], elements, &queue(b"k")))
                .unwrap()
                .racine()
                .expect("racine");
            (t.contient_valeur("k"), t.valeur("k"))
        };
        let faux = (false, None);
        assert_eq!(
            lire(&[], &[k(h, (8, 11)), k(h, (0, 3))]),
            (true, Some(Variante::Booleen(false))),
            "le premier doublon, comme GLib"
        );
        assert_eq!(lire(&[], &[k(h ^ 1, (0, 3))]), faux, "hachage faux");
        assert_eq!(
            lire(&[], &[k(h ^ 1, (0, 3)), k(h, (8, 11))]),
            (true, Some(Variante::Booleen(false))),
            "le seul au bon hachage"
        );
        assert_eq!(lire(&[], &[k(h, (1, 3))]), faux, "valeur mal alignée");
        assert_eq!(
            lire(&[1 << (h & 31)], &[k(h, (0, 3))]),
            (true, Some(Variante::Booleen(true))),
            "admise par le filtre de Bloom"
        );
        assert_eq!(lire(&[!(1 << (h & 31))], &[k(h, (0, 3))]), faux, "exclue par le filtre");
        let mut table = k(h, (0, 3));
        table.genre = b'H';
        assert_eq!(lire(&[], &[table]), faux, "pas une valeur");
    }

    /// Un tableau d'éléments d'un octet dont le type est un n-uplet imbriqué sur 60 niveaux : 1 Mo de fichier en
    /// faisait 2,7 Go de mémoire et 8 minutes de calcul. Refusé tout de suite ; un petit se lit.
    #[test]
    fn valeur_forgee_bornee() {
        let genre = format!("a{}{}", "(".repeat(60), ")".repeat(60));
        let boite = |n: usize| {
            let mut o = vec![0u8; n];
            o.push(0);
            o.extend_from_slice(genre.as_bytes());
            o
        };
        let debut = std::time::Instant::now();
        assert_eq!(decoder(&Genre::Variante, &boite(1_000_000)), None);
        assert_eq!(decoder(&Genre::Variante, &boite(10_000)), None, "60 × 10 000 valeurs");
        assert!(debut.elapsed().as_secs() < 10, "{:?}", debut.elapsed());
        let Some(Variante::Boite(petit)) = decoder(&Genre::Variante, &boite(100)) else {
            panic!("petit tableau illisible");
        };
        assert!(matches!(*petit, Variante::Tableau(_, ref v) if v.len() == 100));
    }

    /// Un fichier trop gros ou qui n'est pas un fichier ordinaire (un tube nommé bloquerait) n'est pas lu.
    #[test]
    fn fichiers_refuses_a_l_ouverture() {
        let d = std::env::temp_dir().join(format!("vanguard-gvdb-ouvrir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        assert!(matches!(Gvdb::ouvrir(&d.join("absent")), Ok(None)));
        let bon = d.join("bon");
        std::fs::write(&bon, fichier(&[valeur("k", Variante::Booleen(true))], false)).unwrap();
        let lu = Gvdb::ouvrir(&bon).unwrap().unwrap().racine().unwrap().valeur("k");
        assert_eq!(lu, Some(Variante::Booleen(true)));
        let gros = std::fs::File::create(d.join("gros")).unwrap();
        gros.set_len(FICHIER_MAX + 1).unwrap();
        assert!(Gvdb::ouvrir(&d.join("gros")).is_err());
        assert!(Gvdb::ouvrir(&d).is_err(), "un dossier");
        let tube = std::ffi::CString::new(d.join("tube").into_os_string().into_encoded_bytes()).unwrap();
        // SAFETY: chemin terminé par un zéro, valable le temps de l'appel.
        if unsafe { libc::mkfifo(tube.as_ptr(), 0o600) } == 0 {
            assert!(Gvdb::ouvrir(&d.join("tube")).is_err(), "un tube nommé");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn fichiers_tronques_ou_forges() {
        assert!(
            Gvdb::depuis(b"GVariant".to_vec()).is_none()
                || Gvdb::depuis(b"GVariant".to_vec()).unwrap().racine().is_none()
        );
        assert!(
            Gvdb::depuis(b"raVGtnai\0\0\0\0\0\0\0\0\x18\0\0\0\x20\0\0\0".to_vec()).is_none(),
            "gros-boutiste"
        );
        assert!(Gvdb::depuis(b"Pas un GVDB du tout....".to_vec()).is_none());
        let bon = fichier(
            &[
                valeur("cle", Variante::Chaine("valeur".into())),
                ("t".into(), Contenu::Table(vec![valeur("x", Variante::Booleen(true))])),
            ],
            false,
        );
        // Chaque troncature et chaque octet changé : jamais de panique, au pire « illisible ».
        for longueur in 0..bon.len() {
            if let Some(b) = Gvdb::depuis(bon[..longueur].to_vec()) {
                let _ = b
                    .racine()
                    .map(|t| (t.valeur("cle"), t.table("t").ok().flatten().map(|x| x.valeur("x"))));
            }
        }
        for i in 0..bon.len() {
            for o in [0u8, 1, 0x7f, 0xff] {
                let mut abime = bon.clone();
                abime[i] = o;
                if let Some(b) = Gvdb::depuis(abime) {
                    let _ = b
                        .racine()
                        .map(|t| (t.valeur("cle"), t.table("t").ok().flatten().map(|x| x.valeur("x"))));
                }
            }
        }
        // Une boucle de parents forgée ne tourne pas sans fin.
        let mut boucle = base_dconf(&[("/a/b", Variante::Booleen(true))], &[]);
        let racine = Gvdb::depuis(boucle.clone()).unwrap().racine().unwrap();
        assert_eq!(racine.valeur("/a/b"), Some(Variante::Booleen(true)));
        let debut = u32_le(&boucle, 16).unwrap() as usize;
        let seaux = u32_le(&boucle, debut + 4).unwrap() as usize;
        let elements = debut + 8 + 4 * seaux;
        for e in 0..3 {
            let p = elements + 24 * e + 4;
            boucle[p..p + 4].copy_from_slice(&u32::try_from(e).unwrap().to_le_bytes());
        }
        let racine = Gvdb::depuis(boucle.clone()).unwrap().racine().unwrap();
        assert_eq!(racine.valeur("/a/b"), None, "sans chemin jusqu'à la racine, pas de nom");
        assert_eq!(racine.noms_des_valeurs(), Some(Vec::new()));
        // Deux éléments parents l'un de l'autre.
        for (e, parent) in [(0, 1u32), (1, 0)] {
            let p = elements + 24 * e + 4;
            boucle[p..p + 4].copy_from_slice(&parent.to_le_bytes());
        }
        let racine = Gvdb::depuis(boucle).unwrap().racine().unwrap();
        assert_eq!(racine.valeur("/a/b"), None);
        assert!(racine.noms_des_valeurs().is_some());
    }

    /// `dconf compile` d'un dossier : lock-enabled=false (verrouillé), idle-delay=uint32 600, mode='manual'.
    const BASE_DCONF: &str = "
    4756617269616e7400000000000000001800000070010000000000280c000000000000000000000001000000010000000200000004000000
    0400000007000000080000000a0000000c0000000c00000029b90fc60a000000700100000c004c007c010000800100008f390d7bffffffff
    800100000600480088010000ac010000e837d59208000000db01000007004c00e4010000e80100008c87dd660a000000e801000008004c00
    f0010000f4010000e6c919d503000000f40100000a0076000002000006020000aacd936000000000060200000c007600180200001b020000
    5e31bcef0b0000001b0200000400760020020000290200004b50900b080000002902000004004c003002000034020000d4b50200ffffffff
    3402000001004c003802000040020000b0b72430070000004002000006004c00480200004c020000b988fdda090000004c02000008004c00
    540200005c0200001922f931020000005c02000006004c00640200006802000073637265656e73617665722f050000002e6c6f636b730000
    000000280100000000000000aacd9360ffffffffac0100002b007600d8010000db0100002f6f72672f676e6f6d652f6465736b746f702f73
    637265656e73617665722f6c6f636b2d656e61626c65640000007373797374656d2f00000b00000073657373696f6e2f0400000069646c65
    2d64656c617900005802000000756c6f636b2d656e61626c65640000000000000000626d6f6465006d616e75616c0000736f72672f000000
    090000002f0000000700000002000000676e6f6d652f00000a0000006465736b746f702f000000000300000070726f78792f000006000000";
}

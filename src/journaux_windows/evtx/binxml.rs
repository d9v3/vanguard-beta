//! Le BinXml d'un morceau .evtx : la forme binaire du XML des événements ([MS-EVEN6] 2.2.12 et 3.1.4.7), avec ce
//! que le fichier y change (documentation de libyal, § « Binary XML ») : les noms et les définitions de gabarits y
//! sont rangés une fois dans le morceau, puis désignés par leur position depuis le début du morceau.
//!
//! Deux temps. La lecture (`Morceau`) suit les octets et en tire un modèle : éléments, attributs, textes,
//! substitutions, instances de gabarits avec leurs valeurs ; elle avance d'au moins un octet par jeton et ne sort
//! jamais de l'enregistrement (ni du morceau pour ce qui y est désigné), son coût est donc borné par sa taille. Le
//! rendu (`Rendu`) remplace ensuite chaque substitution par sa valeur : c'est là qu'un fichier piégé pourrait
//! démultiplier le travail (une même valeur BinXml substituée mille fois, et ainsi de suite à chaque niveau), d'où
//! un budget de travail, de nœuds et de texte par enregistrement, en plus de la profondeur.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::cell::Cell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use super::valeurs;
use super::{Bornes, Noeud};

/// Pourquoi un enregistrement n'a pas pu être rendu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErreurBinxml {
    /// Une lecture sortirait de l'enregistrement, ou du morceau pour un nom ou un gabarit désigné.
    Tronque,
    /// Un jeton qui n'a pas sa place ici (valeur du jeton).
    Jeton(u8),
    /// Éléments, gabarits et valeurs BinXml imbriqués plus profond que `Bornes::profondeur`.
    Profondeur,
    /// Le rendu demanderait plus de travail que `Bornes::travail`.
    Travail,
    /// Plus de `Bornes::noeuds` éléments rendus.
    Noeuds,
    /// Plus de `Bornes::texte_enregistrement` octets de texte rendus.
    Texte,
    /// Une instance annonce plus de `Bornes::substitutions` valeurs.
    Substitutions,
    /// La lecture du morceau a dépassé `Bornes::lecture_morceau`.
    Lecture,
    /// Un élément ne finit pas là où sa longueur (ElementByteLength) l'annonce.
    Longueur,
    /// La définition d'un gabarit est illisible, ou se contient elle-même.
    Gabarit,
    /// Un nom illisible ou démesuré.
    Nom,
    /// Aucun élément rendu.
    Vide,
}

type R<T> = Result<T, ErreurBinxml>;

/// Ce qui a été rendu à peu près, compté pour le bilan : jamais une erreur, toujours dit.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Compteurs {
    /// Valeurs de substitution d'un type inconnu ou d'une taille impossible pour leur type, rendues « inconnu ».
    pub valeurs_inconnues: u64,
    /// Chaînes coupées à `Bornes::texte` caractères.
    pub chaines_tronquees: u64,
    /// Substitutions qui désignent une valeur absente de l'instance (rendues vides).
    pub substitutions_manquantes: u64,
}

/// Un nom XML plus long n'existe pas dans un vrai journal (« SubjectUserName », « Provider ») : la borne garde petit
/// le cache des noms, qu'un fichier piégé remplirait sinon de chaînes de 32 000 caractères à chaque position.
const NOM_MAX: usize = 256;

/// Les jetons du BinXml ([MS-EVEN6] 2.2.12, « Token Types ») ; le bit 0x40 dit « il en suit d'autres » ou, pour
/// l'ouverture d'un élément, « avec des attributs ».
const FIN: u8 = 0x00;
const OUVERTURE: u8 = 0x01;
const FERMETURE_OUVERTURE: u8 = 0x02;
const FERMETURE_VIDE: u8 = 0x03;
const FIN_ELEMENT: u8 = 0x04;
const VALEUR: u8 = 0x05;
const ATTRIBUT: u8 = 0x06;
const CDATA: u8 = 0x07;
const REF_CARACTERE: u8 = 0x08;
const REF_ENTITE: u8 = 0x09;
const PI_CIBLE: u8 = 0x0A;
const PI_DONNEES: u8 = 0x0B;
const INSTANCE: u8 = 0x0C;
const SUBSTITUTION: u8 = 0x0D;
const SUBSTITUTION_OPTIONNELLE: u8 = 0x0E;
const EN_TETE_FRAGMENT: u8 = 0x0F;
const ENCORE: u8 = 0x40;

/// Le type BinXml d'une valeur de substitution ([MS-EVEN6] 3.1.4.7.4) : un fragment à lire à son tour.
const TYPE_BINXML: u8 = 0x21;
const TYPE_NUL: u8 = 0x00;
/// Le bit des tableaux ([MS-EVEN6] 3.1.4.7.5).
const TYPE_TABLEAU: u8 = 0x80;

/// Le modèle lu, avant que les substitutions ne soient remplacées.
#[derive(Debug)]
enum Contenu {
    Element(Element),
    Texte(String),
    Substitution { id: u16, optionnelle: bool },
    Instance(Instance),
}

#[derive(Debug)]
struct Element {
    nom: Arc<str>,
    /// L'indice d'une valeur dont la nullité ôte l'élément ([MS-EVEN6] 2.2.12, DependencyId ; 0xFFFF : aucune).
    dependance: Option<u16>,
    attributs: Vec<Attribut>,
    contenu: Vec<Contenu>,
}

#[derive(Debug)]
struct Attribut {
    nom: Arc<str>,
    /// Textes et substitutions seulement.
    pieces: Vec<Contenu>,
}

/// Un gabarit lu une fois par morceau, partagé par toutes ses instances.
#[derive(Debug)]
struct Gabarit {
    contenu: Vec<Contenu>,
}

#[derive(Debug)]
struct Instance {
    gabarit: Rc<Gabarit>,
    valeurs: Vec<Valeur>,
}

/// Une valeur de substitution, déjà mise en texte (sauf un fragment BinXml, rendu à sa place).
#[derive(Debug)]
enum Valeur {
    Nulle,
    Texte(String),
    /// Un tableau : l'élément qui le reçoit est répété pour chaque case ([MS-EVEN6] 3.1.4.7.5).
    Tableau(Vec<String>),
    Fragment(Vec<Contenu>),
}

/// Une zone d'octets à lire, dans le morceau : `pos` avance, jamais au-delà de `fin` (fin de l'enregistrement, de
/// la valeur ou du gabarit en cours).
#[derive(Debug, Clone, Copy)]
struct Curseur {
    pos: usize,
    fin: usize,
}

impl Curseur {
    /// Passe l'octet que `regarder` vient de rendre.
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "appelé juste après un `regarder` réussi : pos < fin, pos + 1 ne déborde pas"
    )]
    fn passer(&mut self) {
        self.pos += 1;
    }
}

/// Un compteur de plus. Chacun compte au plus une fois par octet lu : il sature plutôt que de paniquer.
fn un_de_plus(compteur: &mut u64) {
    *compteur = compteur.saturating_add(1);
}

/// Un niveau de plus, pour le contrôle de profondeur de l'appel suivant.
fn plus_profond(profondeur: usize) -> R<usize> {
    profondeur.checked_add(1).ok_or(ErreurBinxml::Profondeur)
}

/// La lecture d'un morceau de 64 Kio : noms et gabarits gardés d'un enregistrement à l'autre, comme le fichier les
/// partage. Un gabarit illisible est retenu comme tel : relu à chaque enregistrement qui le désigne, il coûterait sa
/// taille autant de fois.
pub(crate) struct Morceau<'a> {
    octets: &'a [u8],
    bornes: &'a Bornes,
    noms: HashMap<usize, Arc<str>>,
    gabarits: HashMap<usize, Option<Rc<Gabarit>>>,
    /// Les gabarits en cours de lecture : une définition qui se désignerait elle-même s'arrête là.
    en_cours: Vec<usize>,
    /// Lectures d'octets faites dans ce morceau (`Bornes::lecture_morceau`). Une `Cell` : les lectures passent par
    /// des méthodes qui n'empruntent le morceau qu'en lecture.
    lectures: Cell<usize>,
    pub compteurs: Compteurs,
}

impl<'a> Morceau<'a> {
    pub(crate) fn new(octets: &'a [u8], bornes: &'a Bornes) -> Self {
        Self {
            octets,
            bornes,
            noms: HashMap::new(),
            gabarits: HashMap::new(),
            en_cours: Vec::new(),
            lectures: Cell::new(0),
            compteurs: Compteurs::default(),
        }
    }

    /// Le BinXml d'un enregistrement, entre `debut` et `fin` (positions dans le morceau), rendu en arbre : l'élément
    /// racine (`Event`). Les compteurs ne gardent que ce qu'a compté un enregistrement rendu.
    pub(crate) fn rendre(&mut self, debut: usize, fin: usize) -> R<Noeud> {
        let avant = self.compteurs;
        let resultat = self.rendre_sans_compter(debut, fin);
        if resultat.is_err() {
            self.compteurs = avant;
        }
        resultat
    }

    fn rendre_sans_compter(&mut self, debut: usize, fin: usize) -> R<Noeud> {
        let fin = fin.min(self.octets.len());
        if debut > fin {
            return Err(ErreurBinxml::Tronque);
        }
        let mut c = Curseur { pos: debut, fin };
        let contenus = self.fragment(&mut c, false, 0)?;
        let mut rendu = Rendu {
            bornes: self.bornes,
            travail: 0,
            noeuds: 0,
            texte: 0,
            compteurs: &mut self.compteurs,
        };
        let mut racine = Noeud::default();
        rendu.contenus(&contenus, &[], None, &mut racine, 0)?;
        racine.enfants.into_iter().next().ok_or(ErreurBinxml::Vide)
    }

    // ---- Lecture des octets ----

    /// Chaque lecture d'octets compte, pour tout le morceau.
    fn compter_lecture(&self) -> R<()> {
        // Un budget : sature, puis dépasse la borne et arrête la lecture.
        let n = self.lectures.get().saturating_add(1);
        self.lectures.set(n);
        if n > self.bornes.lecture_morceau {
            return Err(ErreurBinxml::Lecture);
        }
        Ok(())
    }

    fn regarder(&self, c: &Curseur) -> R<u8> {
        self.compter_lecture()?;
        if c.pos >= c.fin {
            return Err(ErreurBinxml::Tronque);
        }
        self.octets.get(c.pos).copied().ok_or(ErreurBinxml::Tronque)
    }

    fn prendre(&self, c: &mut Curseur, n: usize) -> R<&'a [u8]> {
        self.compter_lecture()?;
        let fin = c.pos.checked_add(n).ok_or(ErreurBinxml::Tronque)?;
        if fin > c.fin {
            return Err(ErreurBinxml::Tronque);
        }
        let octets = self.octets.get(c.pos..fin).ok_or(ErreurBinxml::Tronque)?;
        c.pos = fin;
        Ok(octets)
    }

    fn octet(&self, c: &mut Curseur) -> R<u8> {
        let b = self.regarder(c)?;
        c.passer();
        Ok(b)
    }

    /// `N` octets pris d'un coup, en tableau (les entiers se lisent sans index à vérifier).
    fn prendre_fixe<const N: usize>(&self, c: &mut Curseur) -> R<[u8; N]> {
        self.prendre(c, N)?.try_into().map_err(|_| ErreurBinxml::Tronque)
    }

    fn mot(&self, c: &mut Curseur) -> R<u16> {
        self.prendre_fixe(c).map(u16::from_le_bytes)
    }

    fn double_mot(&self, c: &mut Curseur) -> R<u32> {
        self.prendre_fixe(c).map(u32::from_le_bytes)
    }

    /// Un mot de 32 bits à une position du morceau, hors de tout curseur (noms et gabarits désignés).
    fn double_mot_a(&self, pos: usize) -> Option<u32> {
        let b = self.octets.get(pos..pos.checked_add(4)?)?;
        Some(u32::from_le_bytes(b.try_into().ok()?))
    }

    /// Une position lue dans le fichier, en `usize`, bornée au morceau.
    fn position(&self, decalage: u32) -> Option<usize> {
        usize::try_from(decalage).ok().filter(|&p| p < self.octets.len())
    }

    // ---- Noms ----

    /// Un nom (élément, attribut, entité, instruction) : sa position dans le morceau ; s'il est rangé juste là, le
    /// curseur le saute (`[libyal]` « Name » : 4 octets inconnus, empreinte, nombre de caractères, UTF-16, zéro final).
    fn nom(&mut self, c: &mut Curseur) -> R<Arc<str>> {
        let decalage = self.double_mot(c)?;
        let pos = self.position(decalage).ok_or(ErreurBinxml::Nom)?;
        let (nom, longueur) = self.lire_nom(pos)?;
        if pos == c.pos {
            let fin = pos.checked_add(longueur).ok_or(ErreurBinxml::Tronque)?;
            if fin > c.fin {
                return Err(ErreurBinxml::Tronque);
            }
            c.pos = fin;
        }
        Ok(nom)
    }

    /// Le nom rangé à `pos`, et la place qu'il y occupe.
    fn lire_nom(&mut self, pos: usize) -> R<(Arc<str>, usize)> {
        // Le nom vu depuis sa position : 8 octets d'en-tête (nombre de caractères aux octets 6 et 7), puis l'UTF-16.
        let nom = self.octets.get(pos..).unwrap_or_default();
        let nombre = nom
            .get(6..8)
            .and_then(|b| b.try_into().ok())
            .map(|b| usize::from(u16::from_le_bytes(b)))
            .ok_or(ErreurBinxml::Nom)?;
        if nombre > NOM_MAX {
            return Err(ErreurBinxml::Nom);
        }
        // 8 octets d'en-tête, les caractères, le zéro final.
        let caracteres = nombre.checked_mul(2).ok_or(ErreurBinxml::Nom)?;
        let longueur = caracteres.checked_add(10).ok_or(ErreurBinxml::Nom)?;
        if let Some(nom) = self.noms.get(&pos) {
            return Ok((nom.clone(), longueur));
        }
        let octets = nom
            .get(8..)
            .and_then(|r| r.get(..caracteres))
            .ok_or(ErreurBinxml::Nom)?;
        let (nom, _) = valeurs::utf16(octets, NOM_MAX);
        let nom: Arc<str> = Arc::from(nom);
        self.noms.insert(pos, nom.clone());
        Ok((nom, longueur))
    }

    // ---- Fragments, éléments, contenus ----

    /// Un fragment ([MS-EVEN6] 2.2.12, Fragment / Document) : en-têtes, un élément ou une instance de gabarit,
    /// jusqu'au jeton de fin. `gabarit` : dans une définition de gabarit (les éléments y portent leur DependencyId,
    /// et une instance n'y a pas sa place).
    fn fragment(&mut self, c: &mut Curseur, gabarit: bool, profondeur: usize) -> R<Vec<Contenu>> {
        if profondeur > self.bornes.profondeur {
            return Err(ErreurBinxml::Profondeur);
        }
        let mut sortie = Vec::new();
        // Le jeton de fin manque parfois au bout d'une valeur : la fin de la zone en tient lieu.
        while c.pos < c.fin {
            match self.regarder(c)? {
                FIN => {
                    c.passer();
                    break;
                }
                EN_TETE_FRAGMENT => {
                    self.prendre(c, 4)?;
                }
                INSTANCE if !gabarit => {
                    let instance = self.instance(c, plus_profond(profondeur)?)?;
                    sortie.push(Contenu::Instance(instance));
                }
                j if j & !ENCORE == OUVERTURE => {
                    let element = self.element(c, gabarit, plus_profond(profondeur)?)?;
                    sortie.push(Contenu::Element(element));
                }
                PI_CIBLE => self.instruction(c)?,
                j => return Err(ErreurBinxml::Jeton(j)),
            }
        }
        Ok(sortie)
    }

    /// Un élément ([MS-EVEN6] 2.2.12, Element / StartElement), lu jusqu'à sa fermeture.
    fn element(&mut self, c: &mut Curseur, gabarit: bool, profondeur: usize) -> R<Element> {
        if profondeur > self.bornes.profondeur {
            return Err(ErreurBinxml::Profondeur);
        }
        let jeton = self.octet(c)?;
        let dependance = if self.dependance_presente(c, gabarit) {
            Some(self.mot(c)?)
        } else {
            None
        };
        // ElementByteLength : la suite se lit jeton par jeton, puis doit finir juste là. Le DependencyId est deviné
        // (plus bas) : un mauvais choix qui donnerait par hasard un arbre valide mais faux se voit ici, et
        // l'enregistrement est compté illisible au lieu d'être rendu de travers.
        let longueur = usize::try_from(self.double_mot(c)?).map_err(|_| ErreurBinxml::Longueur)?;
        let attendue = c.pos.checked_add(longueur).ok_or(ErreurBinxml::Longueur)?;
        let nom = self.nom(c)?;
        let mut attributs = Vec::new();
        if jeton & ENCORE != 0 {
            // AttributeListByteLength, lui aussi inutile pour une lecture dans l'ordre.
            self.double_mot(c)?;
            while self.regarder(c)? & !ENCORE == ATTRIBUT {
                c.passer();
                let nom = self.nom(c)?;
                let pieces = self.pieces(c)?;
                attributs.push(Attribut { nom, pieces });
            }
        }
        let mut contenu = Vec::new();
        match self.octet(c)? {
            FERMETURE_VIDE => {}
            FERMETURE_OUVERTURE => loop {
                match self.regarder(c)? {
                    FIN_ELEMENT => {
                        c.passer();
                        break;
                    }
                    j if j & !ENCORE == OUVERTURE => {
                        contenu.push(Contenu::Element(self.element(c, gabarit, plus_profond(profondeur)?)?));
                    }
                    PI_CIBLE => self.instruction(c)?,
                    j if est_piece(j) || j & !ENCORE == CDATA => contenu.push(self.piece(c)?),
                    j => return Err(ErreurBinxml::Jeton(j)),
                }
            },
            j => return Err(ErreurBinxml::Jeton(j)),
        }
        if c.pos != attendue {
            return Err(ErreurBinxml::Longueur);
        }
        Ok(Element {
            nom,
            dependance,
            attributs,
            contenu,
        })
    }

    /// Le DependencyId est facultatif dans la grammaire ([MS-EVEN6] 2.2.12, « 0*1DependencyId ») sans rien qui
    /// l'annonce : dans un .evtx, il est là dans les définitions de gabarits, pas dans un fragment porté par une
    /// valeur BinXml (`[libyal]` « Element start », note). Le contexte décide ; seul un cas net le contredit : la
    /// position du nom n'est plausible (nom rangé juste après, ou plus haut dans le morceau) que d'une des deux façons.
    fn dependance_presente(&self, c: &Curseur, gabarit: bool) -> bool {
        let plausible = |ou: usize| {
            self.double_mot_a(ou)
                .and_then(|d| usize::try_from(d).ok())
                .is_some_and(|d| {
                    ou.checked_add(4) == Some(d) || (d < ou && d.checked_add(8).is_some_and(|f| f <= self.octets.len()))
                })
        };
        let a = |n: usize| c.pos.checked_add(n).is_some_and(plausible);
        match (a(6), a(4)) {
            (true, false) => true,
            (false, true) => false,
            _ => gabarit,
        }
    }

    /// Les données d'un attribut : textes, substitutions, références.
    fn pieces(&mut self, c: &mut Curseur) -> R<Vec<Contenu>> {
        let mut pieces = Vec::new();
        while c.pos < c.fin && est_piece(self.regarder(c)?) {
            pieces.push(self.piece(c)?);
        }
        Ok(pieces)
    }

    /// Un texte, une substitution, une référence de caractère ou d'entité, une section CDATA.
    fn piece(&mut self, c: &mut Curseur) -> R<Contenu> {
        let jeton = self.octet(c)?;
        match jeton & !ENCORE {
            VALEUR => {
                // Le type (StringType, 0x01) puis une chaîne précédée de sa longueur.
                self.octet(c)?;
                Ok(Contenu::Texte(self.chaine(c)?))
            }
            CDATA => Ok(Contenu::Texte(self.chaine(c)?)),
            SUBSTITUTION | SUBSTITUTION_OPTIONNELLE if jeton & ENCORE == 0 => {
                let id = self.mot(c)?;
                // Le type attendu : seul compte celui de la valeur, dans l'instance.
                self.octet(c)?;
                Ok(Contenu::Substitution {
                    id,
                    optionnelle: jeton == SUBSTITUTION_OPTIONNELLE,
                })
            }
            REF_CARACTERE => {
                let code = self.mot(c)?;
                Ok(Contenu::Texte(
                    char::from_u32(u32::from(code)).unwrap_or('\u{FFFD}').to_string(),
                ))
            }
            REF_ENTITE => {
                let nom = self.nom(c)?;
                // Les cinq entités de XML 1.0 ; une autre reste écrite comme dans le XML.
                let texte = match &*nom {
                    "lt" => "<".to_string(),
                    "gt" => ">".to_string(),
                    "amp" => "&".to_string(),
                    "quot" => "\"".to_string(),
                    "apos" => "'".to_string(),
                    autre => format!("&{autre};"),
                };
                Ok(Contenu::Texte(texte))
            }
            _ => Err(ErreurBinxml::Jeton(jeton)),
        }
    }

    /// Une chaîne précédée de son nombre de caractères (LengthPrefixedUnicodeString).
    fn chaine(&mut self, c: &mut Curseur) -> R<String> {
        let nombre = usize::from(self.mot(c)?);
        let octets = self.prendre(c, nombre.checked_mul(2).ok_or(ErreurBinxml::Tronque)?)?;
        let (texte, tronquee) = valeurs::utf16(octets, self.bornes.texte);
        if tronquee {
            un_de_plus(&mut self.compteurs.chaines_tronquees);
        }
        Ok(texte)
    }

    /// Une instruction de traitement (`<?cible données?>`) : lue pour être sautée, elle ne porte rien d'utile.
    fn instruction(&mut self, c: &mut Curseur) -> R<()> {
        self.octet(c)?;
        self.nom(c)?;
        if c.pos < c.fin && self.regarder(c)? == PI_DONNEES {
            c.passer();
            self.chaine(c)?;
        }
        Ok(())
    }

    // ---- Gabarits ----

    /// Une instance de gabarit ([MS-EVEN6] 2.2.12, TemplateInstance ; `[libyal]` « Template instance ») : un octet
    /// inconnu, 4 octets d'identifiant, la position de la définition (rangée juste là la première fois, désignée
    /// ensuite), puis les valeurs : leur nombre, leurs descripteurs (taille, type), leurs octets.
    fn instance(&mut self, c: &mut Curseur, profondeur: usize) -> R<Instance> {
        if profondeur > self.bornes.profondeur {
            return Err(ErreurBinxml::Profondeur);
        }
        self.prendre(c, 2)?;
        self.double_mot(c)?;
        let decalage = self.double_mot(c)?;
        let definition = self.position(decalage).ok_or(ErreurBinxml::Gabarit)?;
        if definition == c.pos {
            // Définition sur place : 4 octets (suivante), GUID, taille, corps ; les valeurs suivent le corps.
            let taille = definition
                .checked_add(20)
                .and_then(|p| self.double_mot_a(p))
                .ok_or(ErreurBinxml::Tronque)?;
            let taille = usize::try_from(taille).map_err(|_| ErreurBinxml::Tronque)?;
            let fin = definition
                .checked_add(24)
                .and_then(|corps| corps.checked_add(taille))
                .ok_or(ErreurBinxml::Tronque)?;
            if fin > c.fin {
                return Err(ErreurBinxml::Tronque);
            }
            c.pos = fin;
        }
        let gabarit = self.gabarit(definition)?;
        let nombre = usize::try_from(self.double_mot(c)?).map_err(|_| ErreurBinxml::Substitutions)?;
        if nombre > self.bornes.substitutions {
            return Err(ErreurBinxml::Substitutions);
        }
        // Le nombre est borné, et ses descripteurs doivent tenir dans l'enregistrement avant toute allocation.
        let descripteurs = self.prendre(c, nombre.checked_mul(4).ok_or(ErreurBinxml::Substitutions)?)?;
        let mut liste = Vec::with_capacity(nombre);
        for d in descripteurs.as_chunks::<4>().0 {
            let taille = usize::from(u16::from_le_bytes([d[0], d[1]]));
            let debut = c.pos;
            let octets = self.prendre(c, taille)?;
            liste.push(self.valeur(d[2], octets, debut, profondeur)?);
        }
        Ok(Instance {
            gabarit,
            valeurs: liste,
        })
    }

    /// Une valeur de substitution, mise en texte ; un fragment BinXml (type 0x21) est lu à son tour, à sa place
    /// dans le morceau (ses noms y désignent des positions).
    fn valeur(&mut self, type_valeur: u8, octets: &[u8], debut: usize, profondeur: usize) -> R<Valeur> {
        Ok(match type_valeur {
            TYPE_NUL => Valeur::Nulle,
            TYPE_BINXML => {
                let mut c = Curseur {
                    pos: debut,
                    fin: debut.checked_add(octets.len()).ok_or(ErreurBinxml::Tronque)?,
                };
                Valeur::Fragment(self.fragment(&mut c, false, plus_profond(profondeur)?)?)
            }
            t if t & TYPE_TABLEAU != 0 => {
                let (cases, compte) = valeurs::tableau(t, octets, self.bornes.texte);
                self.compter(compte);
                Valeur::Tableau(cases)
            }
            t => {
                let (texte, compte) = valeurs::scalaire(t, octets, self.bornes.texte);
                self.compter(compte);
                Valeur::Texte(texte)
            }
        })
    }

    fn compter(&mut self, compte: valeurs::Compte) {
        if compte.inconnue {
            un_de_plus(&mut self.compteurs.valeurs_inconnues);
        }
        if compte.tronquee {
            un_de_plus(&mut self.compteurs.chaines_tronquees);
        }
    }

    /// Le gabarit défini à `pos`, lu une seule fois par morceau.
    fn gabarit(&mut self, pos: usize) -> R<Rc<Gabarit>> {
        if let Some(lu) = self.gabarits.get(&pos) {
            return lu.clone().ok_or(ErreurBinxml::Gabarit);
        }
        if self.en_cours.contains(&pos) {
            return Err(ErreurBinxml::Gabarit);
        }
        self.en_cours.push(pos);
        let lu = self.lire_gabarit(pos);
        self.en_cours.pop();
        self.gabarits.insert(pos, lu.as_ref().ok().cloned());
        lu.map_err(|_| ErreurBinxml::Gabarit)
    }

    /// Une définition de gabarit (`[libyal]` « Template definition ») : 4 octets (définition suivante), GUID, taille
    /// du corps, puis le corps, un fragment. Lue sans le contexte de qui la désigne : le résultat ne dépend que de
    /// sa position, il peut être gardé.
    fn lire_gabarit(&mut self, pos: usize) -> R<Rc<Gabarit>> {
        let taille = pos
            .checked_add(20)
            .and_then(|p| self.double_mot_a(p))
            .ok_or(ErreurBinxml::Tronque)?;
        let taille = usize::try_from(taille).map_err(|_| ErreurBinxml::Tronque)?;
        let debut = pos.checked_add(24).ok_or(ErreurBinxml::Tronque)?;
        let fin = debut.checked_add(taille).ok_or(ErreurBinxml::Tronque)?;
        if fin > self.octets.len() {
            return Err(ErreurBinxml::Tronque);
        }
        let mut c = Curseur { pos: debut, fin };
        let contenu = self.fragment(&mut c, true, 0)?;
        Ok(Rc::new(Gabarit { contenu }))
    }
}

/// Les jetons qui peuvent former la valeur d'un attribut ([MS-EVEN6] 2.2.12, AttributeCharData).
fn est_piece(jeton: u8) -> bool {
    matches!(jeton & !ENCORE, VALEUR | REF_CARACTERE | REF_ENTITE)
        || matches!(jeton, SUBSTITUTION | SUBSTITUTION_OPTIONNELLE)
}

/// Le rendu d'un enregistrement : les substitutions remplacées, dans les budgets de `Bornes`.
struct Rendu<'b> {
    bornes: &'b Bornes,
    travail: usize,
    noeuds: usize,
    texte: usize,
    compteurs: &'b mut Compteurs,
}

impl Rendu<'_> {
    fn depenser(&mut self) -> R<()> {
        // Un budget : sature, puis dépasse la borne et arrête le rendu.
        self.travail = self.travail.saturating_add(1);
        if self.travail > self.bornes.travail {
            return Err(ErreurBinxml::Travail);
        }
        Ok(())
    }

    fn ajouter(&mut self, dans: &mut String, texte: &str) -> R<()> {
        self.texte = self.texte.saturating_add(texte.len());
        if self.texte > self.bornes.texte_enregistrement {
            return Err(ErreurBinxml::Texte);
        }
        dans.push_str(texte);
        Ok(())
    }

    /// Des contenus rendus dans `parent`, avec les valeurs de l'instance en cours ; `rang` : la case des tableaux
    /// pour un élément répété.
    fn contenus(
        &mut self,
        contenus: &[Contenu],
        valeurs: &[Valeur],
        rang: Option<usize>,
        parent: &mut Noeud,
        profondeur: usize,
    ) -> R<()> {
        if profondeur > self.bornes.profondeur {
            return Err(ErreurBinxml::Profondeur);
        }
        for contenu in contenus {
            self.depenser()?;
            match contenu {
                Contenu::Element(e) => self.element(e, valeurs, parent, plus_profond(profondeur)?)?,
                Contenu::Texte(t) => self.ajouter(&mut parent.texte, t)?,
                Contenu::Substitution { id, .. } => match valeurs.get(usize::from(*id)) {
                    None => un_de_plus(&mut self.compteurs.substitutions_manquantes),
                    Some(Valeur::Nulle) => {}
                    Some(Valeur::Texte(t)) => self.ajouter(&mut parent.texte, t)?,
                    Some(Valeur::Tableau(cases)) => match rang {
                        Some(i) => {
                            if let Some(t) = cases.get(i) {
                                self.ajouter(&mut parent.texte, t)?;
                            }
                        }
                        None => self.ajouter(&mut parent.texte, &cases.join(", "))?,
                    },
                    // Un fragment porté par une valeur : ses substitutions n'ont pas de valeurs à elles, ses
                    // instances apportent les leurs.
                    Some(Valeur::Fragment(sous)) => {
                        self.contenus(sous, &[], None, parent, plus_profond(profondeur)?)?;
                    }
                },
                Contenu::Instance(i) => {
                    self.contenus(&i.gabarit.contenu, &i.valeurs, None, parent, plus_profond(profondeur)?)?;
                }
            }
        }
        Ok(())
    }

    /// Un élément rendu dans `parent`, ou omis ([MS-EVEN6] 3.1.4.7.2 et 2.2.12.1 : une substitution optionnelle
    /// nulle, ou la valeur nulle de sa DependencyId, ôte l'élément), ou répété pour chaque case d'un tableau
    /// substitué dans son contenu ([MS-EVEN6] 3.1.4.7.5 ; un tableau vide donne un seul élément vide).
    fn element(&mut self, e: &Element, valeurs: &[Valeur], parent: &mut Noeud, profondeur: usize) -> R<()> {
        if profondeur > self.bornes.profondeur {
            return Err(ErreurBinxml::Profondeur);
        }
        let nulle = |id: u16| matches!(valeurs.get(usize::from(id)), Some(Valeur::Nulle));
        if e.dependance.is_some_and(|d| d != 0xFFFF && nulle(d)) {
            return Ok(());
        }
        if e.contenu
            .iter()
            .any(|c| matches!(c, Contenu::Substitution { id, optionnelle: true } if nulle(*id)))
        {
            return Ok(());
        }
        let cases = e
            .contenu
            .iter()
            .filter_map(|c| match c {
                Contenu::Substitution { id, .. } => match valeurs.get(usize::from(*id)) {
                    Some(Valeur::Tableau(cases)) => Some(cases.len()),
                    _ => None,
                },
                _ => None,
            })
            .max();
        let copies = match cases {
            None => 1,
            Some(n) => n.max(1),
        };
        for copie in 0..copies {
            self.noeuds = self.noeuds.saturating_add(1);
            if self.noeuds > self.bornes.noeuds {
                return Err(ErreurBinxml::Noeuds);
            }
            let rang = cases.map(|_| copie);
            let mut noeud = Noeud {
                nom: e.nom.clone(),
                ..Noeud::default()
            };
            for a in &e.attributs {
                if let Some(texte) = self.attribut(a, valeurs)? {
                    noeud.attributs.push((a.nom.clone(), texte));
                }
            }
            self.contenus(&e.contenu, valeurs, rang, &mut noeud, profondeur)?;
            // Les événements rendus restent en mémoire par centaines de milliers : sans la place gagnée en
            // poussant (capacités doublées), un événement de sécurité pesait 10 Kio au lieu de la moitié.
            noeud.texte.shrink_to_fit();
            noeud.attributs.shrink_to_fit();
            noeud.enfants.shrink_to_fit();
            parent.enfants.push(noeud);
        }
        Ok(())
    }

    /// La valeur d'un attribut, ou rien s'il est à omettre : aucune donnée ([MS-EVEN6] 2.2.12.2), ou une
    /// substitution optionnelle nulle ([MS-EVEN6] 3.1.4.7.2).
    fn attribut(&mut self, a: &Attribut, valeurs: &[Valeur]) -> R<Option<String>> {
        if a.pieces.is_empty() {
            return Ok(None);
        }
        let mut texte = String::new();
        for piece in &a.pieces {
            self.depenser()?;
            match piece {
                Contenu::Texte(t) => self.ajouter(&mut texte, t)?,
                Contenu::Substitution { id, optionnelle } => match valeurs.get(usize::from(*id)) {
                    None => un_de_plus(&mut self.compteurs.substitutions_manquantes),
                    Some(Valeur::Nulle) if *optionnelle => return Ok(None),
                    Some(Valeur::Nulle) => {}
                    Some(Valeur::Texte(t)) => self.ajouter(&mut texte, t)?,
                    Some(Valeur::Tableau(cases)) => self.ajouter(&mut texte, &cases.join(", "))?,
                    // Interdit dans un attribut ([MS-EVEN6] 3.1.4.7.4 : seulement dans le contenu d'un élément).
                    Some(Valeur::Fragment(_)) => un_de_plus(&mut self.compteurs.valeurs_inconnues),
                },
                _ => {}
            }
        }
        Ok(Some(texte))
    }
}

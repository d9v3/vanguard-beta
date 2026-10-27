//! Le XML d'un événement tel que le rend le service des journaux de Windows (EvtRender, celui que montre
//! l'Observateur d'événements, onglet « Détails », vue XML), changé en l'arbre du lecteur .evtx (`evtx::Noeud`) :
//! la source vivante tire ensuite ses champs par la même extraction que la source fichiers.
//!
//! Le texte vient du service de Windows, mais ses valeurs viennent de qui a écrit l'événement (parfois un attaquant) :
//! mêmes bornes que le lecteur .evtx (profondeur, éléments, caractères d'une valeur, texte de tout l'événement),
//! aucune récursion, aucune panique ; un XML mal formé ou démesuré est illisible, et compté par l'appelant. Module
//! autonome (aucun `crate::`) : le banc de fuzzing l'inclut par son chemin.

// La source vivante est celle de Windows : ailleurs, seuls les tests et le banc de fuzzing s'en servent.
#![cfg_attr(not(windows), allow(dead_code))]

use std::sync::Arc;

use quick_xml::events::{BytesStart, Event};

use super::evtx::{Bornes, Enregistrement, Noeud};

/// Le plus long XML lu : un enregistrement tient dans un morceau de 64 Kio, et son rendu, gabarit déplié, en fait
/// au plus quelques centaines de Kio.
pub(crate) const XML_MAX: usize = 4 << 20;

/// L'arbre d'un événement et le nombre de textes coupés à `Bornes::texte` caractères.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Arbre {
    pub racine: Noeud,
    pub chaines_tronquees: u64,
}

/// Ce qui rend le XML illisible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErreurXml {
    /// Plus long que `XML_MAX`, plus profond que `Bornes::profondeur`, plus d'éléments que `Bornes::noeuds` ou plus
    /// de texte que `Bornes::texte_enregistrement`.
    Demesure,
    /// Pas du XML, ou coupé avant la fin de son premier élément.
    MalForme,
}

/// Un élément en cours de lecture : le nœud, le nombre de caractères de son texte, et s'il a déjà été coupé.
struct Ouvert {
    noeud: Noeud,
    caracteres: usize,
    coupe: bool,
}

/// Les compteurs d'une lecture, sous les bornes.
struct Compte<'b> {
    bornes: &'b Bornes,
    noeuds: usize,
    texte_total: usize,
    tronquees: u64,
}

impl Compte<'_> {
    /// Ajoute `texte` à `dans` (qui en a déjà `caracteres`) : coupé à `Bornes::texte` caractères (compté une fois
    /// par valeur), et le texte de tout l'événement borné à `Bornes::texte_enregistrement` octets.
    fn ajouter(
        &mut self,
        dans: &mut String,
        caracteres: &mut usize,
        coupe: &mut bool,
        texte: &str,
    ) -> Result<(), ErreurXml> {
        let place = self.bornes.texte.saturating_sub(*caracteres);
        let (garde, n) = match texte.char_indices().nth(place) {
            Some((i, _)) => {
                if !*coupe {
                    *coupe = true;
                    self.tronquees += 1;
                }
                (&texte[..i], place)
            }
            None => (texte, texte.chars().count()),
        };
        self.texte_total = self.texte_total.saturating_add(garde.len());
        if self.texte_total > self.bornes.texte_enregistrement {
            return Err(ErreurXml::Demesure);
        }
        dans.push_str(garde);
        *caracteres += n;
        Ok(())
    }

    /// Un élément ouvert : son nom, ses attributs, sous les bornes (un attribut compte comme un élément : un élément
    /// aux milliers d'attributs s'arrête aussi). `profondeur` : les éléments déjà ouverts.
    fn ouvrir(&mut self, e: &BytesStart, profondeur: usize) -> Result<Ouvert, ErreurXml> {
        self.noeuds += 1;
        if profondeur >= self.bornes.profondeur || self.noeuds > self.bornes.noeuds {
            return Err(ErreurXml::Demesure);
        }
        let nom = e.name();
        let mut noeud = Noeud {
            nom: Arc::from(AsRef::<str>::as_ref(&nom)),
            ..Noeud::default()
        };
        for a in e.attributes() {
            self.noeuds += 1;
            if self.noeuds > self.bornes.noeuds {
                return Err(ErreurXml::Demesure);
            }
            let a = a.map_err(|_| ErreurXml::MalForme)?;
            let nom: &str = a.key.as_ref();
            let valeur = deplier(&a.value);
            let (mut v, mut caracteres, mut coupe) = (String::new(), 0, false);
            self.ajouter(&mut v, &mut caracteres, &mut coupe, &valeur)?;
            noeud.attributs.push((Arc::from(nom), v));
        }
        Ok(Ouvert {
            noeud,
            caracteres: 0,
            coupe: false,
        })
    }

    fn texte(&mut self, o: &mut Ouvert, texte: &str) -> Result<(), ErreurXml> {
        self.ajouter(&mut o.noeud.texte, &mut o.caracteres, &mut o.coupe, texte)
    }
}

/// Une référence (« amp », « #x41 ») : les cinq entités de XML et les références de caractères ; rien d'autre
/// n'est défini (aucune DTD n'est lue ni dépliée). Inconnue ou invalide : U+FFFD, la valeur reste, marquée.
fn reference(nom: &str) -> char {
    match nom {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        _ => {
            let nombre = match nom.strip_prefix("#x").or_else(|| nom.strip_prefix("#X")) {
                Some(h) => u32::from_str_radix(h, 16).ok(),
                None => nom.strip_prefix('#').and_then(|d| d.parse::<u32>().ok()),
            };
            nombre
                .and_then(char::from_u32)
                .filter(|&c| c != '\0')
                .unwrap_or('\u{FFFD}')
        }
    }
}

/// La valeur d'un attribut, ses références dépliées, sans la normalisation des blancs de XML (§ 3.3.3) : le lecteur
/// .evtx garde tabulations et fins de ligne, la source vivante doit rendre la même valeur. Un « & » sans « ; » dans
/// les 32 caractères qui suivent reste tel quel.
pub(crate) fn deplier(brut: &str) -> String {
    let mut sortie = String::with_capacity(brut.len());
    let mut reste = brut;
    while let Some(i) = reste.find('&') {
        sortie.push_str(&reste[..i]);
        let apres = &reste[i + 1..];
        if let Some((j, _)) = apres.char_indices().take(32).find(|&(_, c)| c == ';') {
            sortie.push(reference(&apres[..j]));
            reste = &apres[j + 1..];
        } else {
            sortie.push('&');
            reste = apres;
        }
    }
    sortie.push_str(reste);
    sortie
}

/// L'arbre du premier élément du XML (l'élément Event) ; ce qui le suit est ignoré, comme EvtRender n'en rend
/// qu'un.
pub(crate) fn arbre(xml: &str, bornes: &Bornes) -> Result<Arbre, ErreurXml> {
    if xml.len() > XML_MAX {
        return Err(ErreurXml::Demesure);
    }
    let mut lecteur = quick_xml::Reader::from_str(xml);
    let mut pile: Vec<Ouvert> = Vec::new();
    let mut compte = Compte {
        bornes,
        noeuds: 0,
        texte_total: 0,
        tronquees: 0,
    };
    loop {
        let evenement = lecteur.read_event().map_err(|_| ErreurXml::MalForme)?;
        // Un élément fini (vide, ou à sa fin) : rangé chez son parent, ou c'est la racine.
        let fini = match evenement {
            Event::Start(e) => {
                let o = compte.ouvrir(&e, pile.len())?;
                pile.push(o);
                None
            }
            Event::Empty(e) => Some(compte.ouvrir(&e, pile.len())?.noeud),
            // quick-xml vérifie que la fin répond à son début (réglage par défaut) : la pile n'est pas vide ici.
            Event::End(_) => Some(pile.pop().ok_or(ErreurXml::MalForme)?.noeud),
            Event::Text(t) => {
                if let Some(o) = pile.last_mut() {
                    // Tel quel, sans la normalisation des fins de ligne de XML (§ 2.11) : le lecteur .evtx garde
                    // « \r\n », la source vivante doit rendre le même texte (un bloc de script, une ligne de
                    // commande).
                    let t = t.into_inner();
                    compte.texte(o, &t)?;
                }
                None
            }
            Event::CData(t) => {
                if let Some(o) = pile.last_mut() {
                    let t = t.into_inner();
                    compte.texte(o, &t)?;
                }
                None
            }
            Event::GeneralRef(r) => {
                if let Some(o) = pile.last_mut() {
                    let c = reference(r.as_ref());
                    compte.texte(o, c.encode_utf8(&mut [0; 4]))?;
                }
                None
            }
            Event::Eof => return Err(ErreurXml::MalForme),
            // Déclaration, commentaires, instructions de traitement, DOCTYPE.
            _ => None,
        };
        if let Some(n) = fini {
            match pile.last_mut() {
                Some(parent) => parent.noeud.enfants.push(n),
                None => {
                    return Ok(Arbre {
                        racine: n,
                        chaines_tronquees: compte.tronquees,
                    });
                }
            }
        }
    }
}

/// L'événement d'un XML rendu, par la même extraction que celle d'un fichier (numéro et date d'en-tête : aucun,
/// le XML ne porte que ceux de System), et le nombre de textes coupés. La racine doit être l'élément Event.
pub(crate) fn enregistrement(xml: &str, bornes: &Bornes) -> Result<(Enregistrement, u64), ErreurXml> {
    let a = arbre(xml, bornes)?;
    if &*a.racine.nom != "Event" {
        return Err(ErreurXml::MalForme);
    }
    Ok((super::evtx::enregistrement(0, None, a.racine), a.chaines_tronquees))
}

/// L'EventRecordID d'un XML que `enregistrement` n'a pas pu lire (mal formé plus loin, démesuré) : le texte du
/// premier élément EventRecordID. Il est dans System, qui vient avant les données de l'événement, et une valeur
/// écrite par qui que ce soit y est échappée (« &lt; ») : la première balise littérale est bien celle de System.
pub(crate) fn numero_de_secours(xml: &str) -> Option<u64> {
    const OUVRE: &str = "<EventRecordID>";
    let debut = xml.find(OUVRE)? + OUVRE.len();
    let reste = xml.get(debut..)?;
    let fin = reste.find("</EventRecordID>")?;
    reste[..fin].trim().parse().ok()
}

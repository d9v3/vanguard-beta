//! La forme commune d'un événement de Windows, quelle que soit sa source : lu dans un fichier .evtx par le lecteur
//! maison (`fichiers`), ou rendu en XML par le service des journaux de l'ordinateur vivant (`vivant`). Les deux
//! passent par la même extraction (`evtx::enregistrement`, sur l'arbre du BinXml ou sur celui du XML), pour que les
//! règles (E3) lisent les mêmes noms de champs d'où que vienne l'événement.
//!
//! Les textes sont ceux du journal, tels quels : ils viennent parfois d'un attaquant (un nom de compte tenté, une
//! ligne de commande). Rien ici ne les interprète ; le nettoyage des caractères piégés se fait à l'affichage, et
//! aucune valeur ne doit servir de chemin, de commande ou de format. Module autonome (aucun `crate::`) : le banc de
//! fuzzing l'inclut par son chemin avec `evtx` et `xml`.

use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, Utc};

use super::evtx::Enregistrement;

/// D'où vient un événement : de quoi le retrouver et dire ce que vaut son numéro.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Origine {
    // Seule la source vivante (Windows) en rend.
    /// Rendu par le service des journaux de cet ordinateur.
    #[cfg_attr(not(windows), allow(dead_code))]
    Vivant,
    /// Lu dans un fichier .evtx : son chemin (partagé entre tous ses événements) et le numéro de l'enregistrement
    /// dans le fichier (en-tête de l'enregistrement), qui diffère de l'EventRecordID dans un fichier exporté
    /// (renuméroté depuis 1) ou une archive d'événements transférés.
    Fichier { chemin: Arc<Path>, numero_fichier: u64 },
}

/// Un événement de Windows, d'une source ou de l'autre.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EvenementWindows {
    /// Le journal (System/Channel) : « Security », « System », « Microsoft-Windows-PowerShell/Operational »…
    pub journal: String,
    /// Le numéro d'événement (System/EventID).
    pub id: u32,
    /// System/Level (0 : toujours journalisé, 1 critique, 2 erreur, 3 avertissement, 4 information, 5 détail).
    pub niveau: Option<u8>,
    /// System/TimeCreated, attribut SystemTime ; à défaut, pour un fichier, la date d'écriture de l'enregistrement.
    /// En UTC. Rien si aucune n'est lisible.
    pub date: Option<DateTime<Utc>>,
    /// System/Computer.
    pub ordinateur: String,
    /// L'EventRecordID (System/EventRecordID) ; pour un fichier qui ne le porte pas, le numéro de l'enregistrement.
    pub numero: Option<u64>,
    /// System/Provider, attribut Name (à défaut EventSourceName).
    pub fournisseur: String,
    /// Le compte au nom duquel l'événement a été écrit (System/Security, attribut UserID : un SID), s'il y est.
    pub utilisateur: Option<String>,
    /// Les champs de EventData (Data : attribut Name, texte ; un autre élément, Binary par exemple, sous son propre
    /// nom) ou, à défaut, de UserData (les feuilles sous son premier élément, nommées par leur chemin « a/b »).
    pub champs: Vec<(String, String)>,
    pub origine: Origine,
    /// Faux pour un événement relu dans un morceau .evtx au CRC faux (en-tête ou données) : sa structure se tient,
    /// mais rien ne prouve que Windows l'ait écrit tel quel (page recopiée à moitié dans une copie à chaud, morceau
    /// retouché). Toujours vrai pour la source vivante. Une règle (E3) peut en tirer un indice, en le disant ; jamais
    /// conclure « sain » ou « rien vu » sur des événements non vérifiés seuls, ni sur leur absence.
    pub verifie: bool,
}

impl EvenementWindows {
    /// La forme commune d'un événement lu, ou rien s'il n'a pas de numéro d'événement lisible : il n'est alors
    /// d'aucune règle, et la source le compte à part (jamais tu).
    pub(crate) fn depuis(e: Enregistrement, origine: Origine) -> Option<Self> {
        let id = e.id?;
        let utilisateur = e
            .evenement
            .enfant("System")
            .and_then(|s| s.enfant("Security"))
            .and_then(|s| s.attribut("UserID"))
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty());
        let verifie = e.verifie;
        let numero = match origine {
            Origine::Vivant => e.numero_systeme,
            Origine::Fichier { .. } => e.numero_systeme.or(Some(e.numero)),
        };
        Some(Self {
            journal: e.canal,
            id,
            niveau: e.niveau,
            date: e.cree.or(e.date),
            ordinateur: e.ordinateur,
            numero,
            fournisseur: e.fournisseur,
            utilisateur,
            champs: e.champs,
            origine,
            verifie,
        })
    }

    /// La valeur du premier champ de ce nom.
    pub(crate) fn champ(&self, nom: &str) -> Option<&str> {
        self.champs.iter().find(|(n, _)| n == nom).map(|(_, v)| v.as_str())
    }
}

/// Les événements voulus. Vide (`Filtre::default()`) : tous.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Filtre {
    /// Les journaux voulus (System/Channel), sans égard à la casse ; vide : tous.
    pub journaux: Vec<String>,
    /// Les numéros d'événements voulus ; vide : tous.
    pub ids: Vec<u32>,
    /// Les événements datés de cet instant ou après.
    pub depuis: Option<DateTime<Utc>>,
    /// Les événements datés de cet instant ou avant.
    pub jusqua: Option<DateTime<Utc>>,
}

/// Pourquoi un événement n'a pas été donné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ecart {
    /// Hors des journaux ou des numéros voulus, ou daté hors de la fenêtre : écarté exprès.
    Filtre,
    /// La fenêtre de dates est posée et l'événement n'a aucune date lisible : il ne peut être placé ni dedans ni
    /// dehors. Compté à part, pour qu'une règle sache qu'elle ne l'a pas jugé.
    SansDate,
}

impl Filtre {
    /// Le journal est-il voulu ?
    pub(crate) fn veut_journal(&self, journal: &str) -> bool {
        self.journaux.is_empty() || self.journaux.iter().any(|j| j.eq_ignore_ascii_case(journal))
    }

    /// L'événement est-il voulu ? `Err` dit pourquoi non.
    pub(crate) fn juger(&self, e: &EvenementWindows) -> Result<(), Ecart> {
        if !self.veut_journal(&e.journal) || !(self.ids.is_empty() || self.ids.contains(&e.id)) {
            return Err(Ecart::Filtre);
        }
        if self.depuis.is_none() && self.jusqua.is_none() {
            return Ok(());
        }
        let Some(date) = e.date else {
            return Err(Ecart::SansDate);
        };
        let dedans = self.depuis.is_none_or(|d| date >= d) && self.jusqua.is_none_or(|j| date <= j);
        if dedans { Ok(()) } else { Err(Ecart::Filtre) }
    }
}

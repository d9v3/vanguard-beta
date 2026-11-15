//! L'état de la fenêtre, sans rien dessiner : l'écran montré, la tâche en cours et sa file d'attente, la console,
//! les derniers résultats. Les écrans (`dessin`) lisent cet état et ne demandent que des gestes d'ici (`demander`,
//! `arreter`, `saisir`, `proposer`) ; aucun ne lance un programme lui-même. Une seule commande tourne à la fois.
//!
//! Le seul geste qui change l'ordinateur (lot 2a : retirer un programme du démarrage, remettre ce que Vanguard en a
//! retiré) passe par deux temps : `proposer` ouvre la confirmation (le nom, la commande, ce qui va se passer), et
//! seul `accepter` le lance, un à la fois, quand rien d'autre ne tourne. La console n'en lance jamais.
//!
//! Les couleurs de la fenêtre suivent le même chemin (`proposer_couleurs`, puis `accepter`) : la fenêtre ne les écrit
//! jamais, `vanguard couleurs` les revérifie et les enregistre ; elle les relit ensuite de sa réponse, comme au
//! lancement. La valeur d'avant reste offerte pour revenir en arrière (`revenir_couleurs`).
//!
//! « Voir la correction » d'un constat du bilan (`voir_correction`) ouvre une feuille en lecture seule : la fenêtre
//! demande l'aperçu à `vanguard` par le jeton du constat (`correction --voir`), qui rejuge tout et ne change rien. La
//! feuille n'a qu'« Annuler » dans ce lot : appliquer viendra avec le suivant.
//!
//! Les animations aussi sont gardées par `vanguard` (`couleurs --animations`), relues dans la même réponse au
//! lancement. Un clic sur « Réduites » ou « Toutes » est tout le geste : il vaut tout de suite pour la fenêtre, et
//! son enregistrement part dès que rien ne tourne (`regler_animations`), sans confirmation, car il ne touche que
//! l'apparence de la fenêtre et se défait d'un clic.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::commandes::{
    self, APERCU_LU, Accord, Changement, ChangementCouleurs, Commande, Empreinte, Famille, Forme, Geste, Lancement,
    Rubrique, Saisie, Sorte,
};
use crate::console::{self, Console};
use crate::couleurs::{Choix, Jeu, Theme};
use crate::coulisses::{Chemin, Coulisses};
use crate::donnees::changements::{self, IssueChange, Relu};
use crate::donnees::couleurs::{IssueAnimations, IssueCouleurs, Lues};
use crate::donnees::{appareils, bilan, correction, evenements, libre, mise_a_jour, protection};
use crate::lanceur::{Fin, Issue, Message, Programme, Reveil, Tache};

/// Saisies gardées pour ↑.
const HISTORIQUE_MAX: usize = 50;
/// Commandes en attente au plus.
const FILE_MAX: usize = 8;
/// Le journal est relu à ce rythme, quand rien ne tourne, pour dire une alerte nouvelle dans la console.
pub const SONDAGE: Duration = Duration::from_secs(60);

/// Écrans retenus au plus pour « Retour » : assez pour tout parcours, borné pour une fenêtre ouverte des jours.
const RETOURS_MAX: usize = 50;

/// L'écran montré.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ecran {
    Accueil,
    Bilan,
    Alertes,
    /// Le scan du réseau local (`appareils --json`).
    Appareils,
    Rubrique(Rubrique),
    Commande(Commande),
    Guide,
}

/// Le ton d'une ligne de la console.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ton {
    Normal,
    Commande,
    Bon,
    Attention,
    Grave,
    Discret,
}

#[derive(Clone, Debug)]
pub struct LigneConsole {
    /// Croissant, jamais réutilisé (même après « effacer ») : la console y retrouve ses mesures et compte les
    /// lignes nouvelles.
    pub numero: u64,
    pub heure: String,
    pub source: String,
    pub texte: String,
    pub ton: Ton,
}

/// Le dernier résultat d'une commande, lu.
#[derive(Clone, Debug)]
pub enum Contenu {
    Constats(bilan::Vue),
    Protection(protection::Vue),
    Evenements(evenements::Vue),
    Appareils(appareils::Vue),
    /// « Ce que Vanguard a changé » (`changements --json`).
    Changements(changements::Vue),
    Libre(libre::Vue),
    /// La commande n'a rien rendu de lisible : pourquoi, en une phrase.
    Erreur(String),
}

#[derive(Clone, Debug)]
pub struct Resultat {
    pub contenu: Contenu,
    /// L'heure locale de la fin.
    pub heure: String,
    pub duree: Duration,
    /// L'instant de la fin (la ligne d'état de la console dit depuis combien de temps).
    pub fin: Instant,
}

/// Un changement proposé, en attente d'« Accepter » ou d'« Annuler ».
#[derive(Clone, Debug, PartialEq)]
enum Proposition {
    Demarrage(bilan::Geste),
    /// Les couleurs d'un thème : le changement, et la valeur montrée comme « avant ».
    Couleurs(ChangementCouleurs, Option<Choix>),
    /// L'aperçu d'une correction ou d'une annulation, puis son geste et son issue.
    Correction(FeuilleCorrection),
}

/// La feuille « Voir la correction » (famille `Correction`) ou « Remettre comme avant » (famille `Annulation`) : le
/// jeton, où en est l'aperçu, puis le geste.
#[derive(Clone, Debug, PartialEq)]
pub struct FeuilleCorrection {
    pub famille: Famille,
    pub jeton: Empreinte,
    pub etat: EtatFeuille,
    /// L'instant où l'aperçu lu s'est montré : le bouton qui change ne s'active que `APERCU_LU` après (Q7).
    pub montre: Option<Instant>,
    /// Une phrase de la fenêtre en tête de la feuille : le refus du geste d'avant, ou « ça a changé pendant que vous
    /// lisiez ».
    pub avis: Option<String>,
    /// L'accord du geste refusé : un nouvel aperçu à l'accord différent dit que ça a changé pendant la lecture.
    envoye: Option<Accord>,
}

impl FeuilleCorrection {
    fn nouvelle(famille: Famille, jeton: Empreinte) -> FeuilleCorrection {
        FeuilleCorrection {
            famille,
            jeton,
            etat: EtatFeuille::Attente { lance: false },
            montre: None,
            avis: None,
            envoye: None,
        }
    }

    /// Une feuille de correction dans cet état, pour les essais du dessin (montrée à l'instant).
    #[cfg(test)]
    pub fn essai(famille: Famille, jeton: Empreinte, etat: EtatFeuille) -> FeuilleCorrection {
        FeuilleCorrection {
            etat,
            montre: Some(Instant::now()),
            ..FeuilleCorrection::nouvelle(famille, jeton)
        }
    }

    /// L'accord de l'aperçu montré, s'il s'accepte maintenant (`peut_accepter`).
    fn acceptable(&self, maintenant: Instant) -> Option<Accord> {
        peut_accepter(&self.etat, self.montre, maintenant)
    }
}

/// L'accord à rendre, si l'aperçu montré s'accepte depuis la fenêtre maintenant : un aperçu lu (ni refusé, ni
/// illisible, ni contradictoire), que rien n'empêche d'appliquer d'ici (`pas_d_ici` : droits du compte, annulable,
/// automatique, ni retouché ni coupé, assez court), montré depuis `APERCU_LU` au moins. La feuille ajoute un seul
/// empêchement à ceux-ci, qu'elle seule voit : un texte plus large qu'elle (`dessin::bilan::correction`). Rien
/// d'autre que cet accord, tel que Vanguard l'a donné, ne part avec le jeton.
pub fn peut_accepter(etat: &EtatFeuille, montre: Option<Instant>, maintenant: Instant) -> Option<Accord> {
    let lu = montre.is_some_and(|m| maintenant.saturating_duration_since(m) >= APERCU_LU);
    match etat {
        EtatFeuille::Lue(correction::Lecture::Lue(a)) if lu && a.pas_d_ici().is_none() => Some(a.accord),
        EtatFeuille::Annulation(correction::Lecture::Lue(a)) if lu && a.pas_d_ici().is_none() => Some(a.accord),
        EtatFeuille::MiseAJour(mise_a_jour::Vue::Proposee(a)) if lu && a.pas_d_ici().is_none() => Some(a.accord),
        _ => None,
    }
}

/// Où en est une feuille.
#[derive(Clone, Debug, PartialEq)]
pub enum EtatFeuille {
    /// L'aperçu demandé à `vanguard` (`lance`), ou en attente que la commande en cours finisse.
    Attente { lance: bool },
    /// L'aperçu d'une correction, lu strictement (`donnees::correction`).
    Lue(correction::Lecture),
    /// L'aperçu d'une annulation, lu strictement (`donnees::changements`).
    Annulation(correction::Lecture<changements::Annulation>),
    /// L'aperçu de la mise à jour de Vanguard, lu strictement (`donnees::mise_a_jour`).
    MiseAJour(mise_a_jour::Vue),
    /// Le geste accepté est parti : il ne s'interrompt pas, la feuille attend son issue.
    Envoi,
    /// L'issue du geste : fait, en échec, ou inconnue (jamais un refus : la feuille montre alors un nouvel aperçu).
    Recu(IssueChange),
    /// Pas d'aperçu : arrêté, trop long, pas pu lancer.
    Echec(String),
}

pub struct Appli {
    pub ecran: Ecran,
    /// Les écrans d'avant, le plus récent à la fin (« Retour », Alt+←, le bouton Précédent de la souris, Échap).
    retours: Vec<Ecran>,
    pub sombre: bool,
    /// « Réduire les animations » : plus de fondu d'écran, de chiffres qui montent, de pouls ni d'ouverture ; l'état
    /// final s'affiche tout de suite. Gardé par `vanguard` (`regler_animations`), relu au lancement.
    pub animations_reduites: bool,
    /// Les animations ont été choisies dans cette fenêtre : une relecture ne les change plus (un enregistrement
    /// refusé ne doit pas défaire le choix montré).
    animations_choisies: bool,
    /// Les animations à enregistrer, dès que rien ne tourne (le dernier clic seul).
    animations_a_garder: Option<bool>,
    programme: Result<Programme, String>,
    tache: Option<Tache>,
    file: VecDeque<Commande>,
    /// Les lignes et les blocs de la console (bornée).
    pub console: Console,
    /// Ce que fait la fenêtre, pour la fenêtre « Coulisses » (en mémoire seulement).
    pub coulisses: Coulisses,
    pub saisie: String,
    historique: Vec<String>,
    /// Position dans l'historique pendant ↑ / ↓ (None : la saisie en cours).
    rappel: Option<usize>,
    resultats: HashMap<Commande, Resultat>,
    /// Le dernier journal lu, pour reconnaître une alerte nouvelle.
    journal: Option<evenements::Vue>,
    dernier_sondage: Instant,
    reveil: Reveil,
    /// Le changement proposé, en attente d'« Accepter » ou d'« Annuler ».
    confirmation: Option<Proposition>,
    /// Les couleurs réglées, relues de `vanguard couleurs --json` (rien lu encore : celles de Vanguard).
    couleurs: Lues,
    /// Les couleurs en cours de choix pour un thème, pas encore proposées (l'écran Vanguard les montre seul).
    pub brouillon: Option<(Theme, Choix)>,
    /// Le changement qui remet les couleurs d'avant le dernier changement fait.
    revenir: Option<ChangementCouleurs>,
}

impl Appli {
    /// Va à un écran en retenant celui-ci pour « Retour ». Seul chemin pour changer d'écran (un essai le garde) :
    /// une affectation directe ferait sauter un pas au retour. Une confirmation ouverte se ferme, et des couleurs en
    /// cours de choix sont abandonnées : rien ne reste en attente hors de la vue de la personne.
    pub fn aller(&mut self, vers: Ecran) {
        if vers == self.ecran {
            return;
        }
        self.annuler();
        self.abandonner_brouillon();
        if self.retours.len() >= RETOURS_MAX {
            self.retours.remove(0);
        }
        self.retours.push(self.ecran);
        self.ecran = vers;
    }

    /// L'écran où « Retour » mènerait.
    pub fn retour(&self) -> Option<Ecran> {
        self.retours.last().copied()
    }

    /// Revient à l'écran d'avant (une confirmation ouverte se ferme, comme avec `aller`) ; sans écran d'avant, rien.
    /// Une feuille « Voir la correction » ouverte se ferme seule, sans changer d'écran.
    pub fn revenir(&mut self) {
        // Échap sur la feuille « Voir la correction » ne ferme qu'elle : l'écran du bilan reste sous les yeux.
        if self.feuille_correction().is_some() {
            self.annuler();
            return;
        }
        if let Some(e) = self.retours.pop() {
            self.annuler();
            self.abandonner_brouillon();
            self.ecran = e;
        }
    }

    pub fn nouvelle(programme: Result<Programme, String>, reveil: Reveil) -> Appli {
        let mut a = Appli {
            ecran: Ecran::Accueil,
            retours: Vec::new(),
            sombre: true,
            animations_reduites: false,
            animations_choisies: false,
            animations_a_garder: None,
            programme,
            tache: None,
            file: VecDeque::new(),
            console: Console::nouvelle(),
            coulisses: Coulisses::nouvelles(etat_du_bac()),
            saisie: String::new(),
            historique: Vec::new(),
            rappel: None,
            resultats: HashMap::new(),
            journal: None,
            dernier_sondage: Instant::now(),
            reveil,
            confirmation: None,
            couleurs: Lues::default(),
            brouillon: None,
            revenir: None,
        };
        #[cfg(target_os = "linux")]
        if let Some((phrase, souligner)) = crate::relais::etat() {
            let ton = if *souligner { Ton::Attention } else { Ton::Discret };
            a.dire("fenêtre", phrase, ton);
        }
        match &a.programme {
            Ok(_) => {
                a.dire(
                    "fenêtre",
                    crate::tr!(
                        "Prête. Tapez « aide » pour la liste des commandes permises.",
                        "Ready. Type “help” for the list of allowed commands."
                    ),
                    Ton::Discret,
                );
                // Au lancement : les couleurs réglées (un instant), l'état de la protection, le journal, puis le
                // bilan (quelques secondes).
                for c in [
                    Commande::Couleurs,
                    Commande::Protection,
                    Commande::Evenements,
                    Commande::Bilan,
                ] {
                    a.demander(c);
                }
            }
            Err(e) => {
                let e = e.clone();
                a.dire("fenêtre", &e, Ton::Grave);
            }
        }
        a
    }

    /// Pour les captures (`dessin::captures`) : une fenêtre qui a trouvé `vanguard` mais ne lance rien (son chemin
    /// n'existe pas : la garde d'avant chaque lancement le refuserait), la console vide.
    #[cfg(test)]
    pub fn pour_captures() -> Appli {
        let mut a = Appli::nouvelle(Err(String::new()), std::sync::Arc::new(|| {}));
        a.programme = Ok(Programme::factice());
        a.console.effacer();
        // L'état du bac de cette machine-ci n'a rien à faire dans une capture : une phrase inventée, fixe.
        a.coulisses = Coulisses::nouvelles((
            crate::tr!(
                "Bac à sable actif (Landlock 6) : la fenêtre ne peut ni lire vos fichiers, ni en écrire, ni lancer de programme, ni ouvrir de connexion ; `vanguard` est lancé à côté d'elle, avec tous ses droits de lecture.",
                "Sandbox active (Landlock 6): the window can neither read your files, nor write any, nor start a program, nor open a connection; `vanguard` is started beside it, with all its read rights."
            )
            .into(),
            false,
        ));
        a
    }

    /// Pour les captures : la réponse de `vanguard correction --voir` posée dans la feuille ouverte, lue comme une
    /// vraie (données inventées).
    #[cfg(test)]
    pub fn poser_apercu(&mut self, sortie: &[u8]) {
        if let Some(Proposition::Correction(f)) = &mut self.confirmation {
            f.etat = match f.famille {
                Famille::Correction => EtatFeuille::Lue(correction::lire(f.jeton, Some(0), sortie)),
                Famille::Annulation => EtatFeuille::Annulation(changements::lire_apercu(f.jeton, Some(0), sortie)),
                Famille::MiseAJour => EtatFeuille::MiseAJour(mise_a_jour::lire_apercu(Some(0), sortie)),
            };
            f.montre = Some(Instant::now());
        }
    }

    /// Pour les captures : la réponse de `vanguard se-mettre-a-jour --voir` qui ne propose rien (code 1), lue comme
    /// une vraie (données inventées).
    #[cfg(test)]
    pub fn poser_vue_mise_a_jour(&mut self, code: i32, sortie: &[u8]) {
        if let Some(Proposition::Correction(f)) = &mut self.confirmation
            && f.famille == Famille::MiseAJour
        {
            f.etat = EtatFeuille::MiseAJour(mise_a_jour::lire_apercu(Some(code), sortie));
            f.montre = Some(Instant::now());
        }
    }

    /// Pour les captures : la feuille ouverte rendue comme après son geste (données inventées).
    #[cfg(test)]
    pub fn poser_issue(&mut self, issue: IssueChange, avis: Option<String>) {
        if let Some(Proposition::Correction(f)) = &mut self.confirmation {
            f.etat = EtatFeuille::Recu(issue);
            f.avis = avis;
        }
    }

    /// Pour les captures et les essais : l'aperçu montré depuis plus de `APERCU_LU`.
    #[cfg(test)]
    pub fn vieillir_apercu(&mut self) {
        if let Some(Proposition::Correction(f)) = &mut self.confirmation {
            f.montre = f.montre.and_then(|m| m.checked_sub(APERCU_LU));
        }
    }

    /// Pour les captures : un résultat posé comme si `vanguard` l'avait rendu (données inventées).
    #[cfg(test)]
    pub fn poser(&mut self, c: Commande, sortie: &[u8]) {
        let fin = Fin {
            lancement: c.into(),
            code: Some(0),
            sortie: sortie.to_vec(),
            issue: Issue::Terminee,
            duree: Duration::from_millis(2143),
        };
        // Les coulisses le notent comme un vrai passage par le relais (numéro de processus inventé).
        self.coulisses.lancee(fin.lancement, Chemin::Relais);
        self.coulisses.processus(4242);
        self.coulisses.finie(&fin);
        self.finir(&fin);
    }

    /// Ajoute une ligne simple à la console (nettoyée).
    pub fn dire(&mut self, source: &str, texte: &str, ton: Ton) {
        self.console.dire(source, texte, ton);
    }

    pub fn programme_trouve(&self) -> bool {
        self.programme.is_ok()
    }

    /// Demande une commande : lancée tout de suite si rien ne tourne, sinon mise en file, avec son bloc « en
    /// attente ». Déjà en cours ou déjà en attente : dit, pas ajoutée une seconde fois.
    pub fn demander(&mut self, c: Commande) {
        if self.programme.is_err() {
            let e = self.programme.as_ref().err().cloned().unwrap_or_default();
            self.dire("fenêtre", &e, Ton::Grave);
            return;
        }
        if self
            .tache
            .as_ref()
            .is_some_and(|t| t.lancement == Lancement::Commande(c))
        {
            self.dire(
                "fenêtre",
                &crate::trf!("{} : déjà en cours.", "{}: already running.", c.nom_affiche()),
                Ton::Discret,
            );
            return;
        }
        if self.file.contains(&c) {
            self.dire(
                "fenêtre",
                &crate::trf!("{} : déjà en attente.", "{}: already queued.", c.nom_affiche()),
                Ton::Discret,
            );
            return;
        }
        if self.tache.is_some() {
            if self.file.len() >= FILE_MAX {
                self.dire(
                    "fenêtre",
                    crate::tr!("Trop de commandes en attente.", "Too many queued commands."),
                    Ton::Attention,
                );
                return;
            }
            self.file.push_back(c);
            self.console.attendre(c.into());
            return;
        }
        self.lancer(c.into());
    }

    /// Retire une commande de la file (le ✕ de son bloc) ; rien si elle n'y est pas.
    pub fn retirer(&mut self, c: Commande) {
        if self.file.contains(&c) {
            self.file.retain(|x| *x != c);
            self.console.retirer(c.into());
        }
    }

    fn lancer(&mut self, l: Lancement) {
        let Ok(p) = &self.programme else {
            return;
        };
        let tache = Tache::lancer(p, l, crate::langue::anglais(), &self.reveil);
        let chemin = if tache.par_le_relais() {
            Chemin::Relais
        } else {
            Chemin::Direct
        };
        self.coulisses.lancee(l, chemin);
        self.tache = Some(tache);
        self.console.commencer(l);
    }

    /// Arrête la commande en cours et vide la file. Un changement en cours ne s'interrompt pas : tué au milieu, il
    /// pourrait laisser le programme retiré sans la note qui permet de le remettre. Il finit seul (la fenêtre
    /// administrateur refusée ou fermée suffit), borné par son délai.
    pub fn arreter(&mut self) {
        for c in std::mem::take(&mut self.file) {
            self.console.retirer(c.into());
        }
        if let Some(t) = &self.tache
            && !t.arret_demande()
        {
            if t.lancement.change() {
                self.dire(
                    "fenêtre",
                    crate::tr!(
                        "Un changement ne s'interrompt pas : il finit seul (refusez la fenêtre administrateur pour l'abandonner).",
                        "A change is not interrupted: it finishes on its own (decline the administrator window to abandon it)."
                    ),
                    Ton::Attention,
                );
                return;
            }
            t.arreter();
            self.dire("fenêtre", crate::tr!("Arrêt demandé…", "Stopping…"), Ton::Attention);
        }
    }

    /// La commande en cours et depuis quand (un changement au démarrage compte pour l'écran du démarrage).
    /// Un aperçu de correction ne compte pour aucun écran (le bilan n'est pas « en cours ») : sa feuille dit son
    /// attente.
    pub fn en_cours(&self) -> Option<(Commande, Duration)> {
        self.tache
            .as_ref()
            .filter(|t| !matches!(t.lancement, Lancement::Geste(_)))
            .map(|t| (t.lancement.commande(), t.debut.elapsed()))
    }

    /// Un changement peut-il être proposé maintenant ? Seulement quand rien ne tourne ni n'attend, et qu'aucune
    /// confirmation n'est ouverte : un à la fois, jamais en même temps qu'une lecture.
    pub fn changement_possible(&self) -> bool {
        self.programme.is_ok() && self.tache.is_none() && self.file.is_empty() && self.confirmation.is_none()
    }

    /// Le changement au démarrage proposé, en attente de la réponse de la personne.
    pub fn confirmation(&self) -> Option<&bilan::Geste> {
        match &self.confirmation {
            Some(Proposition::Demarrage(g)) => Some(g),
            _ => None,
        }
    }

    /// Le changement des couleurs proposé, et la valeur d'avant montrée.
    pub fn confirmation_couleurs(&self) -> Option<(ChangementCouleurs, Option<Choix>)> {
        match &self.confirmation {
            Some(Proposition::Couleurs(cc, avant)) => Some((*cc, *avant)),
            _ => None,
        }
    }

    /// La feuille « Voir la correction » ouverte, s'il y en a une.
    pub fn feuille_correction(&self) -> Option<&FeuilleCorrection> {
        match &self.confirmation {
            Some(Proposition::Correction(f)) => Some(f),
            _ => None,
        }
    }

    /// Le constat de ce jeton est-il dans le dernier bilan lu ? Seul un jeton de ce bilan ouvre une feuille.
    fn dans_le_bilan(&self, jeton: Empreinte) -> bool {
        self.bilan()
            .is_some_and(|v| v.constats.iter().any(|c| c.correction == Some(jeton)))
    }

    /// La dernière liste de « Ce que Vanguard a changé » lue, si elle s'est lue.
    pub fn changements(&self) -> Option<&changements::Vue> {
        match self.resultats.get(&Commande::Changements).map(|r| &r.contenu) {
            Some(Contenu::Changements(v)) => Some(v),
            _ => None,
        }
    }

    /// La dernière liste de « Ce que Vanguard a changé » offre-t-elle de remettre ce jeton ?
    pub fn dans_les_changements(&self, jeton: Empreinte) -> bool {
        self.changements().is_some_and(|v| v.offre(jeton))
    }

    /// « Remettre comme avant » (une ligne de « Ce que Vanguard a changé », ou « Annuler cette correction » après
    /// une correction faite) : ouvre la feuille de l'annulation et demande son aperçu dès que rien ne tourne.
    /// Seulement pour un jeton de la dernière liste lue ; une feuille ouverte n'est remplacée que si son geste est
    /// fini (`Recu`) : rien ne change sur l'ordinateur ici.
    pub fn voir_annulation(&mut self, jeton: Empreinte) {
        if self.programme.is_err() {
            return;
        }
        let fini = matches!(
            &self.confirmation,
            Some(Proposition::Correction(f)) if matches!(f.etat, EtatFeuille::Recu(_))
        );
        if self.confirmation.is_some() && !fini {
            self.pas_maintenant();
            return;
        }
        if !self.dans_les_changements(jeton) {
            self.dire(
                "changements",
                crate::tr!(
                    "Ce changement n'est plus offert dans la dernière liste : relisez « Ce que Vanguard a changé ».",
                    "This change is no longer offered in the last list: read “What Vanguard changed” again."
                ),
                Ton::Attention,
            );
            return;
        }
        self.confirmation = Some(Proposition::Correction(FeuilleCorrection::nouvelle(
            Famille::Annulation,
            jeton,
        )));
        if self.tache.is_none() && self.file.is_empty() {
            self.lancer_correction();
        }
    }

    /// « Voir la correction » : ouvre la feuille et demande l'aperçu dès que rien ne tourne. Seulement pour un
    /// constat du dernier bilan, et sans autre confirmation ouverte ; rien ne change sur l'ordinateur.
    pub fn voir_correction(&mut self, jeton: Empreinte) {
        if self.programme.is_err() {
            return;
        }
        if self.confirmation.is_some() {
            self.pas_maintenant();
            return;
        }
        if !self.dans_le_bilan(jeton) {
            self.dire(
                "bilan",
                crate::tr!(
                    "Ce constat n'est plus dans le dernier bilan : refaites-le.",
                    "This finding is no longer in the last check: run it again."
                ),
                Ton::Attention,
            );
            return;
        }
        self.confirmation = Some(Proposition::Correction(FeuilleCorrection::nouvelle(
            Famille::Correction,
            jeton,
        )));
        if self.tache.is_none() && self.file.is_empty() {
            self.lancer_correction();
        }
    }

    /// « Mettre à jour Vanguard » (la carte des réglages) : ouvre la feuille et demande l'aperçu dès que rien ne
    /// tourne. Aucune liste n'offre la mise à jour : son jeton est fixe. Rien ne change sur l'ordinateur ici, ni dans
    /// l'aperçu (Vanguard ne fait que lire, et regarder GitHub ou la clé) : l'installer attend l'accord.
    pub fn voir_mise_a_jour(&mut self) {
        if self.programme.is_err() {
            return;
        }
        if self.confirmation.is_some() {
            self.pas_maintenant();
            return;
        }
        self.confirmation = Some(Proposition::Correction(FeuilleCorrection::nouvelle(
            Famille::MiseAJour,
            Empreinte::MISE_A_JOUR,
        )));
        if self.tache.is_none() && self.file.is_empty() {
            self.lancer_correction();
        }
    }

    /// Lance l'aperçu de la feuille ouverte, s'il attend encore son tour.
    fn lancer_correction(&mut self) -> bool {
        let Some(Proposition::Correction(f)) = &mut self.confirmation else {
            return false;
        };
        if f.etat != (EtatFeuille::Attente { lance: false }) {
            return false;
        }
        f.etat = EtatFeuille::Attente { lance: true };
        f.montre = None;
        let g = Geste::voir(f.famille, f.jeton);
        self.lancer(Lancement::Geste(g));
        true
    }

    /// Les couleurs réglées et ce que `vanguard` en a dit.
    pub fn couleurs(&self) -> &Lues {
        &self.couleurs
    }

    /// Toutes les couleurs montrées pour le thème affiché : le brouillon en cours (l'aperçu en direct dans toute la
    /// fenêtre), sinon celles réglées. Un brouillon qui se verrait à peine n'est jamais montré : la fenêtre reste
    /// lisible pendant qu'on cherche.
    pub fn jeu(&self) -> Jeu {
        let t = Theme::depuis_sombre(self.sombre);
        let brouillon = self.brouillon_de(t).filter(|c| crate::couleurs::verifier(t, c).is_ok());
        Jeu::de(t, brouillon.or(self.couleurs.de(t)).as_ref())
    }

    /// Le brouillon de ce thème, s'il y en a un.
    pub fn brouillon_de(&self, t: Theme) -> Option<Choix> {
        self.brouillon.filter(|(b, _)| *b == t).map(|(_, c)| c)
    }

    /// Abandonne le brouillon des couleurs (l'aperçu revient à celles réglées), en le disant s'il changeait quelque
    /// chose.
    pub fn abandonner_brouillon(&mut self) {
        if let Some((t, c)) = self.brouillon.take()
            && self.couleurs.de(t) != Some(c)
        {
            self.dire(
                "couleurs",
                crate::tr!(
                    "Couleurs non enregistrées : abandonnées, celles réglées reviennent.",
                    "Unsaved colors: dropped, the saved ones come back."
                ),
                Ton::Discret,
            );
        }
    }

    /// Le changement qui remettrait les couleurs d'avant le dernier changement, s'il y en a un.
    pub fn revenir_couleurs(&self) -> Option<ChangementCouleurs> {
        self.revenir
    }

    /// La raison de ne pas proposer un changement maintenant, dite dans la console.
    fn pas_maintenant(&mut self) {
        let raison = if self.confirmation.is_some() {
            crate::tr!(
                "Une confirmation est déjà ouverte : acceptez-la ou annulez-la d'abord. Rien n'a changé.",
                "A confirmation is already open: accept or cancel it first. Nothing changed."
            )
        } else {
            crate::tr!(
                "Une commande tourne encore : rien n'a changé. Réessayez à sa fin.",
                "A command is still running: nothing changed. Try again when it ends."
            )
        };
        self.dire("fenêtre", raison, Ton::Attention);
    }

    /// Ouvre la confirmation d'un changement des couleurs. Seulement un choix lisible (`couleurs::verifier`, que
    /// `vanguard` refait), différent de celui réglé, et quand un changement est possible ; rien n'est lancé ici.
    pub fn proposer_couleurs(&mut self, cc: ChangementCouleurs) {
        if !self.changement_possible() {
            self.pas_maintenant();
            return;
        }
        if let Some(Err(r)) = cc.choix.map(|c| crate::couleurs::verifier(cc.theme, &c)) {
            let texte = crate::trf!(
                "Refusé, rien n'a changé : une couleur se verrait à peine sur le fond (contraste {}:1).",
                "Refused, nothing changed: a color would barely show on the background (contrast {}:1).",
                crate::langue::nombre(r.ratio, 2)
            );
            self.dire("couleurs", &texte, Ton::Attention);
            return;
        }
        let avant = self.couleurs.de(cc.theme);
        if avant == cc.choix {
            self.dire(
                "couleurs",
                crate::tr!(
                    "Ce sont déjà les couleurs réglées.",
                    "These are already the saved colors."
                ),
                Ton::Discret,
            );
            return;
        }
        self.confirmation = Some(Proposition::Couleurs(cc, avant));
    }

    /// Ouvre la confirmation d'un changement. Seulement un geste de la dernière liste du démarrage (pas un autre,
    /// même si l'écran le demandait) et quand un changement est possible ; rien n'est lancé ici.
    pub fn proposer(&mut self, geste: &bilan::Geste) {
        if !self.changement_possible() {
            self.pas_maintenant();
            return;
        }
        if self.dans_la_liste(geste) {
            self.confirmation = Some(Proposition::Demarrage(geste.clone()));
        }
    }

    /// Le geste est-il dans la dernière liste du démarrage lue ? Seul un geste de cette liste se propose et s'accepte.
    fn dans_la_liste(&self, geste: &bilan::Geste) -> bool {
        matches!(
            self.resultats.get(&Commande::Demarrage).map(|r| &r.contenu),
            Some(Contenu::Constats(v)) if v.constats.iter().any(|c| c.geste.as_ref() == Some(geste))
        )
    }

    /// La liste a changé sous une confirmation ouverte : elle se ferme, rien n'est lancé.
    fn fermer_si_disparu(&mut self) {
        if self.confirmation().is_some_and(|g| !self.dans_la_liste(g)) {
            self.confirmation = None;
            self.dire(
                "fenêtre",
                crate::tr!(
                    "La liste a changé : rien n'a changé.",
                    "The list changed: nothing changed."
                ),
                Ton::Attention,
            );
        }
    }

    /// Les couleurs relues ont changé sous une confirmation ouverte (l'« avant » montré n'est plus vrai) : elle se
    /// ferme, rien n'est lancé.
    fn fermer_si_couleurs_changees(&mut self) {
        if self
            .confirmation_couleurs()
            .is_some_and(|(cc, avant)| self.couleurs.de(cc.theme) != avant)
        {
            self.confirmation = None;
            self.dire(
                "couleurs",
                crate::tr!(
                    "Les couleurs réglées ont changé entre-temps : rien n'a changé.",
                    "The saved colors changed in the meantime: nothing changed."
                ),
                Ton::Attention,
            );
        }
    }

    /// « Accepter » : lance le changement confirmé, s'il y en a un et que rien ne tourne. Seul chemin qui lance un
    /// changement.
    pub fn accepter(&mut self) {
        if self.tache.is_some() || !self.file.is_empty() {
            self.dire(
                "fenêtre",
                crate::tr!(
                    "Une commande tourne encore : rien n'a changé. Acceptez à sa fin.",
                    "A command is still running: nothing changed. Accept when it ends."
                ),
                Ton::Attention,
            );
            return;
        }
        self.fermer_si_disparu();
        self.fermer_si_couleurs_changees();
        match self.confirmation.take() {
            Some(Proposition::Demarrage(g)) => self.lancer(Lancement::Changement(g.changement)),
            Some(Proposition::Couleurs(cc, _)) => self.lancer(Lancement::Couleurs(cc)),
            // Un aperçu qui ne s'accepte pas (pas encore lu 2 s, pas d'ici, déjà envoyé) : la feuille reste ouverte,
            // rien n'est lancé. Sinon, seuls le jeton de la feuille et l'accord de l'aperçu partent ; la feuille
            // passe à `Envoi`, un second clic n'a plus rien à accepter.
            Some(Proposition::Correction(mut f)) => {
                let accord = f.acceptable(Instant::now());
                if let Some(accord) = accord {
                    f.etat = EtatFeuille::Envoi;
                    f.avis = None;
                    f.envoye = Some(accord);
                }
                let g = Geste::changer(f.famille, f.jeton, accord.unwrap_or(Accord::NUL));
                self.confirmation = Some(Proposition::Correction(f));
                if accord.is_some() {
                    self.lancer(Lancement::Geste(g));
                }
            }
            None => {}
        }
    }

    /// « Annuler » (ou « Fermer ») : ferme la confirmation, rien n'est lancé. Une feuille dont le geste est parti
    /// se ferme aussi, mais le geste ne s'arrête pas (`arreter` ne coupe pas un changement) : son issue sera dite dans
    /// la console, jamais « rien n'a changé ».
    pub fn annuler(&mut self) {
        let fermee = self.confirmation.take();
        // Un aperçu encore en lecture n'a plus personne pour le lire : il s'arrête (il ne change rien).
        if let Some(Proposition::Correction(f)) = &fermee
            && let Some(t) = &self.tache
            && t.lancement == Lancement::Geste(Geste::voir(f.famille, f.jeton))
            && !t.arret_demande()
        {
            t.arreter();
        }
        let phrase = match &fermee {
            None => None,
            Some(Proposition::Correction(f)) if f.etat == EtatFeuille::Envoi => Some(crate::tr!(
                "Feuille fermée : le geste accepté finit seul, son issue sera dite ici.",
                "Sheet closed: the accepted action finishes on its own, its outcome will be told here."
            )),
            // Un geste fini a déjà dit son issue.
            Some(Proposition::Correction(f)) if matches!(f.etat, EtatFeuille::Recu(_)) => None,
            Some(_) => Some(crate::tr!("Annulé : rien n'a changé.", "Cancelled: nothing changed.")),
        };
        if let Some(phrase) = phrase {
            self.dire("fenêtre", phrase, Ton::Discret);
        }
    }

    /// La commande attend-elle son tour ?
    pub fn en_attente(&self, c: Commande) -> bool {
        self.file.contains(&c)
    }

    pub fn taches(&self) -> usize {
        usize::from(self.tache.is_some()).saturating_add(self.file.len())
    }

    pub fn resultat(&self, c: Commande) -> Option<&Resultat> {
        self.resultats.get(&c)
    }

    pub fn bilan(&self) -> Option<&bilan::Vue> {
        match self.resultats.get(&Commande::Bilan).map(|r| &r.contenu) {
            Some(Contenu::Constats(v)) => Some(v),
            _ => None,
        }
    }

    pub fn journal(&self) -> Option<&evenements::Vue> {
        self.journal.as_ref()
    }

    pub fn protection(&self) -> Option<&protection::Vue> {
        match self.resultats.get(&Commande::Protection).map(|r| &r.contenu) {
            Some(Contenu::Protection(v)) => Some(v),
            _ => None,
        }
    }

    /// À chaque image : les messages de la tâche, la suivante de la file, le sondage du journal.
    pub fn avancer(&mut self) {
        let messages = self.tache.as_ref().map(Tache::recevoir).unwrap_or_default();
        for m in messages {
            match m {
                Message::Ligne(l) => {
                    // Une étape (`@etape n/N libellé`, forme exacte) fait avancer le bloc sans rien de plus ; toute
                    // autre ligne est gardée dans le bloc, et notée dans les coulisses comme avant.
                    if crate::progression::lire(&l).is_none() {
                        self.coulisses.erreur(&l);
                    }
                    if !self.console.recevoir(&l) {
                        let source = self.tache.as_ref().map_or("vanguard", |t| t.lancement.nom_affiche());
                        self.dire(source, &l, Ton::Discret);
                    }
                }
                Message::Lance(pid) => self.coulisses.processus(pid),
                Message::Fin(f) => {
                    self.tache = None;
                    self.finir(&f);
                }
            }
        }
        if self.tache.is_none() {
            if let Some(reduites) = self.animations_a_garder.take() {
                self.lancer(Lancement::Animations(reduites));
            } else if self.file.is_empty() && self.lancer_correction() {
                // L'aperçu demandé pendant une commande part à sa fin.
            } else if let Some(c) = self.file.pop_front() {
                self.lancer(c.into());
            } else if self.programme.is_ok() && self.dernier_sondage.elapsed() >= SONDAGE {
                // Même pendant une confirmation ouverte : la veille des alertes ne s'arrête jamais pour elle
                // (« Accepter » pendant la lecture dit d'attendre sa fin, la confirmation reste ouverte).
                self.dernier_sondage = Instant::now();
                self.lancer(Commande::Evenements.into());
            }
        }
    }

    fn finir(&mut self, f: &Fin) {
        self.coulisses.finie(f);
        let c = match f.lancement {
            Lancement::Commande(Commande::Couleurs) => return self.lire_couleurs(f),
            Lancement::Commande(c) => c,
            Lancement::Changement(ch) => return self.finir_changement(ch, f),
            Lancement::Couleurs(cc) => return self.finir_couleurs(cc, f),
            Lancement::Animations(reduites) => return self.finir_animations(reduites, f),
            Lancement::Geste(g) => return self.finir_geste(g, f),
        };
        let contenu = match &f.issue {
            Issue::Terminee => match lire(c, &f.sortie) {
                Ok(contenu) => contenu,
                Err(e) => Contenu::Erreur(match f.code {
                    Some(0) | None => e,
                    Some(code) => crate::trf!("{} (code de sortie {})", "{} (exit code {})", e, code),
                }),
            },
            Issue::Arretee => Contenu::Erreur(crate::tr!("arrêtée à votre demande", "stopped at your request").into()),
            Issue::DelaiDepasse => Contenu::Erreur(crate::trf!(
                "arrêtée : plus de {} s sans finir",
                "stopped: more than {} s without finishing",
                c.delai().as_secs()
            )),
            Issue::TropLongue => {
                Contenu::Erreur(crate::tr!("arrêtée : réponse trop longue", "stopped: answer too long").into())
            }
            Issue::Impossible(e) => Contenu::Erreur(crate::trf!("pas pu lancer : {}", "could not start: {}", e)),
        };
        let texte = match &contenu {
            Contenu::Erreur(e) => e.clone(),
            Contenu::Constats(v) => v.resume(),
            Contenu::Protection(v) => {
                let n = v.interrupteurs.len();
                format!(
                    "{} {}",
                    crate::trn!(n, "interrupteur", "interrupteurs", "switch", "switches"),
                    crate::tra!(n, "lu", "lus", "read", "read")
                )
            }
            Contenu::Evenements(v) => format!(
                "{} · {}",
                v.etat.phrase(),
                crate::trn!(v.alertes().count(), "alerte", "alertes", "alert", "alerts")
            ),
            Contenu::Appareils(v) => v.resume(),
            Contenu::Changements(v) => v.resume(),
            Contenu::Libre(v) => crate::trn!(v.lignes.len(), "valeur", "valeurs", "value", "values"),
        };
        self.console.finir(
            f.lancement,
            console::Fini {
                resume: texte,
                ton: ton(&contenu),
                points: console::points(&contenu),
                duree: f.duree,
                echec: matches!(contenu, Contenu::Erreur(_)),
            },
        );
        if let Contenu::Evenements(v) = &contenu {
            self.dernier_sondage = Instant::now();
            let nouvelles: Vec<String> = match &self.journal {
                Some(avant) => v
                    .nouvelles_alertes(avant)
                    .iter()
                    .map(|e| crate::trf!("Nouvelle alerte : {}", "New alert: {}", e.titre))
                    .collect(),
                None => Vec::new(),
            };
            for n in nouvelles {
                self.dire("alerte", &n, Ton::Grave);
            }
            self.journal = Some(v.clone());
        }
        // Une erreur ne remplace pas un résultat lisible d'avant : celui-ci reste, la console dit l'échec.
        if matches!(contenu, Contenu::Erreur(_))
            && self
                .resultats
                .get(&c)
                .is_some_and(|r| !matches!(r.contenu, Contenu::Erreur(_)))
        {
            return;
        }
        self.resultats.insert(
            c,
            Resultat {
                contenu,
                heure: crate::temps::heure_minute(),
                duree: f.duree,
                fin: Instant::now(),
            },
        );
        if c == Commande::Demarrage {
            self.fermer_si_disparu();
        }
    }

    /// La fin d'un changement : une ligne de la console (fait, refusé ou échec, avec la raison), puis la liste du
    /// démarrage relue, qui montre l'état réel.
    fn finir_changement(&mut self, ch: Changement, f: &Fin) {
        let issue = issue_du_changement(ch, f);
        let echec = !matches!(issue, IssueChangement::Fait);
        let (texte, ton) = match issue {
            IssueChangement::Fait => (
                match ch.sorte {
                    Sorte::Retirer => crate::tr!(
                        "Fait : retiré du démarrage ; il reste installé.",
                        "Done: removed from startup; it stays installed."
                    ),
                    Sorte::Remettre => crate::tr!(
                        "Fait : remis au démarrage, exactement comme avant.",
                        "Done: put back at startup, exactly as before."
                    ),
                }
                .to_string(),
                Ton::Bon,
            ),
            IssueChangement::Refuse(r) => (
                crate::trf!("Refusé, rien n'a changé : {}", "Refused, nothing changed: {}", r),
                Ton::Attention,
            ),
            IssueChangement::Echec(r) => (crate::trf!("Échec : {}", "Failed: {}", r), Ton::Attention),
        };
        self.console.finir(
            f.lancement,
            console::Fini {
                resume: texte,
                ton,
                points: Vec::new(),
                duree: f.duree,
                echec,
            },
        );
        self.demander(Commande::Demarrage);
    }

    /// La fin d'un aperçu : une ligne de la console, et la feuille remplie si c'est bien la sienne (fermée entre-temps,
    /// ou pour un autre jeton : la réponse est laissée). Un nouvel aperçu après un refus dont l'accord n'est plus
    /// celui envoyé dit que ça a changé pendant la lecture.
    fn finir_geste(&mut self, g: Geste, f: &Fin) {
        if !g.sorte.voir() {
            return self.finir_geste_qui_change(g, f);
        }
        let famille = g.sorte.famille();
        let etat = match &f.issue {
            Issue::Terminee => match famille {
                Famille::Correction => EtatFeuille::Lue(correction::lire(g.jeton, f.code, &f.sortie)),
                Famille::Annulation => EtatFeuille::Annulation(changements::lire_apercu(g.jeton, f.code, &f.sortie)),
                Famille::MiseAJour => EtatFeuille::MiseAJour(mise_a_jour::lire_apercu(f.code, &f.sortie)),
            },
            Issue::Arretee => EtatFeuille::Echec(crate::tr!("arrêté", "stopped").to_string()),
            Issue::DelaiDepasse => EtatFeuille::Echec(crate::trf!(
                "arrêté : plus de {} s sans finir",
                "stopped: more than {} s without finishing",
                Lancement::Geste(g).delai().as_secs()
            )),
            Issue::TropLongue => EtatFeuille::Echec(crate::tr!("réponse trop longue", "answer too long").to_string()),
            Issue::Impossible(e) => EtatFeuille::Echec(crate::trf!("pas pu lancer : {}", "could not start: {}", e)),
        };
        let (lue, accord, refus) = match &etat {
            EtatFeuille::Lue(correction::Lecture::Lue(a)) => (true, Some(a.accord), None),
            EtatFeuille::Annulation(correction::Lecture::Lue(a)) => (true, Some(a.accord), None),
            EtatFeuille::MiseAJour(mise_a_jour::Vue::Proposee(a)) => (true, Some(a.accord), None),
            EtatFeuille::Lue(correction::Lecture::Refusee(r))
            | EtatFeuille::Annulation(correction::Lecture::Refusee(r))
            | EtatFeuille::MiseAJour(mise_a_jour::Vue::Refusee(r)) => (false, None, Some((r.clone(), false))),
            EtatFeuille::Lue(correction::Lecture::Illisible(r))
            | EtatFeuille::Annulation(correction::Lecture::Illisible(r))
            | EtatFeuille::MiseAJour(mise_a_jour::Vue::Illisible(r))
            | EtatFeuille::Echec(r) => (false, None, Some((r.clone(), true))),
            // Rien n'est proposé : dit tel quel, « à jour » seulement quand Vanguard l'a vérifié.
            EtatFeuille::MiseAJour(
                mise_a_jour::Vue::AJour(_) | mise_a_jour::Vue::Rien(_) | mise_a_jour::Vue::NonVerifiee(_),
            )
            | EtatFeuille::Attente { .. }
            | EtatFeuille::Envoi
            | EtatFeuille::Recu(_) => (false, None, None),
        };
        let (resume, ton, echec) = match (&etat, lue, refus) {
            (_, true, _) => (
                crate::tr!("Aperçu prêt : rien n'a changé.", "Preview ready: nothing changed.").to_string(),
                Ton::Bon,
                false,
            ),
            (EtatFeuille::MiseAJour(mise_a_jour::Vue::AJour(r)), ..) => (
                crate::trf!("À jour, vérifié : {}", "Up to date, verified: {}", r),
                Ton::Bon,
                false,
            ),
            (EtatFeuille::MiseAJour(mise_a_jour::Vue::Rien(r)), ..) => (
                crate::trf!("Rien à mettre à jour : {}", "Nothing to update: {}", r),
                Ton::Discret,
                false,
            ),
            (EtatFeuille::MiseAJour(mise_a_jour::Vue::NonVerifiee(r)), ..) => (
                crate::trf!(
                    "Pas vérifié, rien n'est dit à jour : {}",
                    "Not verified, nothing is said up to date: {}",
                    r
                ),
                Ton::Attention,
                false,
            ),
            (_, false, Some((r, echec))) => (
                crate::trf!("Pas d'aperçu : {}", "No preview: {}", r),
                Ton::Attention,
                echec,
            ),
            (_, false, None) => (String::new(), Ton::Discret, true),
        };
        self.console.finir(
            f.lancement,
            console::Fini {
                resume,
                ton,
                points: Vec::new(),
                duree: f.duree,
                echec,
            },
        );
        if let Some(Proposition::Correction(feuille)) = &mut self.confirmation
            && feuille.famille == famille
            && feuille.jeton == g.jeton
            && feuille.etat == (EtatFeuille::Attente { lance: true })
        {
            feuille.etat = etat;
            feuille.montre = lue.then(Instant::now);
            if let Some(envoye) = feuille.envoye.take()
                && accord.is_some_and(|a| a != envoye)
            {
                feuille.avis = Some(
                    crate::tr!(
                        "Ça a changé pendant que vous lisiez. Rien n'a été fait.",
                        "It changed while you were reading. Nothing was done."
                    )
                    .to_string(),
                );
            }
        }
    }

    /// La fin d'un geste qui change (appliquer une correction, la remettre comme avant) : une ligne de la console,
    /// et la feuille qui l'a envoyé dit l'issue. Refusé (rien n'a été fait) : la feuille redemande l'aperçu, avec le
    /// refus en tête. Fait, en échec ou inconnu : la feuille le dit, et le bilan et « Ce que Vanguard a changé » sont
    /// relus (ils montrent l'état réel). Seul un refus de Vanguard dit « rien n'a été fait ».
    fn finir_geste_qui_change(&mut self, g: Geste, f: &Fin) {
        let famille = g.sorte.famille();
        let issue = match &f.issue {
            Issue::Terminee => changements::lire_issue(famille, f.code, &f.sortie),
            Issue::Arretee => IssueChange::Illisible(crate::tr!("arrêté", "stopped").to_string()),
            Issue::DelaiDepasse => IssueChange::Illisible(crate::trf!(
                "plus de {} s sans finir",
                "more than {} s without finishing",
                Lancement::Geste(g).delai().as_secs()
            )),
            Issue::TropLongue => {
                IssueChange::Illisible(crate::tr!("réponse trop longue", "answer too long").to_string())
            }
            Issue::Impossible(e) => IssueChange::Illisible(e.clone()),
        };
        let phrase = phrase_issue(famille, &issue);
        let ton = match &issue {
            IssueChange::Fait { relu, .. } if relu.bon() => Ton::Bon,
            _ => Ton::Attention,
        };
        self.console.finir(
            f.lancement,
            console::Fini {
                resume: phrase.clone(),
                ton,
                points: Vec::new(),
                duree: f.duree,
                echec: !matches!(issue, IssueChange::Fait { .. }),
            },
        );
        let sienne = matches!(
            &self.confirmation,
            Some(Proposition::Correction(feuille))
                if feuille.famille == famille && feuille.jeton == g.jeton && feuille.etat == EtatFeuille::Envoi
        );
        if let IssueChange::Refuse(_) = issue {
            // Rien n'a été fait : un nouvel aperçu, lu comme le premier (2 s avant d'accepter à nouveau).
            if sienne && let Some(Proposition::Correction(feuille)) = &mut self.confirmation {
                feuille.etat = EtatFeuille::Attente { lance: false };
                feuille.avis = Some(phrase);
                if self.file.is_empty() {
                    self.lancer_correction();
                }
            }
            return;
        }
        if sienne && let Some(Proposition::Correction(feuille)) = &mut self.confirmation {
            feuille.etat = EtatFeuille::Recu(issue);
            feuille.avis = None;
            feuille.envoye = None;
        }
        // Ce qui a peut-être changé se relit : le bilan, et la liste qui offre (ou n'offre plus) de remettre. La
        // mise à jour ne touche ni l'un ni l'autre.
        if famille != Famille::MiseAJour {
            self.demander(Commande::Changements);
            self.demander(Commande::Bilan);
        }
    }

    /// Les couleurs relues (`vanguard couleurs --json`) : elles valent pour la fenêtre dès l'image suivante. Une
    /// réponse illisible laisse les couleurs d'avant ; un fichier douteux est dit, dans la console et les coulisses.
    fn lire_couleurs(&mut self, f: &Fin) {
        let lues = match (&f.issue, f.code) {
            (Issue::Terminee, Some(0)) => crate::donnees::couleurs::lire(&f.sortie),
            _ => Err(crate::tr!("pas lues", "not read").to_string()),
        };
        // Le bloc ouvert au lancement se ferme toujours ici (sinon « lecture en cours… » pour toujours).
        let (resume, ton, echec) = match lues {
            Ok(l) => {
                let fin = match l.doute {
                    Some(d) if self.couleurs.doute != Some(d) => {
                        self.coulisses.avis(d.texte());
                        (d.texte().to_string(), Ton::Attention, false)
                    }
                    _ => (
                        crate::tr!("couleurs lues", "colors read").to_string(),
                        Ton::Discret,
                        false,
                    ),
                };
                // Les animations gardées valent dès qu'elles sont lues, sauf choisies ici entre-temps.
                if !self.animations_choisies
                    && let Some(reduites) = l.animations_reduites
                {
                    self.animations_reduites = reduites;
                }
                self.couleurs = l;
                self.fermer_si_couleurs_changees();
                fin
            }
            Err(e) => {
                let texte = crate::trf!(
                    "Couleurs réglées illisibles ({}) : celles d'avant restent.",
                    "Saved colors unreadable ({}): the previous ones stay.",
                    e
                );
                self.coulisses.avis(&texte);
                (texte, Ton::Attention, true)
            }
        };
        self.console.finir(
            f.lancement,
            console::Fini {
                resume,
                ton,
                points: Vec::new(),
                duree: f.duree,
                echec,
            },
        );
    }

    /// Un changement des couleurs a fini : son issue dans la console, puis les couleurs relues (seule source de ce
    /// qui est montré : jamais celles demandées, toujours celles que `vanguard` a gardées).
    fn finir_couleurs(&mut self, cc: ChangementCouleurs, f: &Fin) {
        let (texte, ton, echec) = match crate::donnees::couleurs::lire_issue(cc, f) {
            IssueCouleurs::Fait { avant, apres: _ } => {
                self.revenir = Some(ChangementCouleurs {
                    theme: cc.theme,
                    choix: avant,
                });
                self.brouillon = None;
                (
                    crate::tr!(
                        "Fait : couleurs enregistrées. « Revenir à celles d'avant » les remet exactement.",
                        "Done: colors saved. “Back to the previous ones” puts them back exactly."
                    )
                    .to_string(),
                    Ton::Bon,
                    false,
                )
            }
            IssueCouleurs::Refuse(r) => (
                crate::trf!("Refusé, rien n'a changé : {}", "Refused, nothing changed: {}", r),
                Ton::Attention,
                false,
            ),
            IssueCouleurs::Echec(r) => (crate::trf!("Échec : {}", "Failed: {}", r), Ton::Attention, true),
        };
        self.console.finir(
            f.lancement,
            console::Fini {
                resume: texte,
                ton,
                points: Vec::new(),
                duree: f.duree,
                echec,
            },
        );
        self.demander(Commande::Couleurs);
    }

    /// « Réduites » ou « Toutes » cliqué : vaut tout de suite, et `vanguard` l'enregistre dès que rien ne tourne
    /// (le dernier clic seul part). Sans programme, rien ne peut l'être : dit.
    pub fn regler_animations(&mut self, reduites: bool) {
        if self.animations_reduites == reduites {
            return;
        }
        self.animations_reduites = reduites;
        self.animations_choisies = true;
        if let Err(e) = &self.programme {
            let texte = crate::trf!(
                "Animations changées pour cette fois seulement : {}",
                "Animations changed for this time only: {}",
                e
            );
            self.dire("fenêtre", &texte, Ton::Attention);
            return;
        }
        self.animations_a_garder = Some(reduites);
    }

    /// Un enregistrement des animations a fini : dit dans la console. Refusé ou en échec, le choix vaut pour cette
    /// fois seulement, et c'est dit.
    fn finir_animations(&mut self, reduites: bool, f: &Fin) {
        let issue = crate::donnees::couleurs::lire_issue_animations(reduites, f);
        let echec = !matches!(issue, IssueAnimations::Fait { .. });
        let (texte, ton) = match issue {
            IssueAnimations::Fait { .. } => (
                crate::tr!(
                    "Fait : animations gardées pour les prochaines ouvertures.",
                    "Done: animations kept for the next openings."
                )
                .to_string(),
                Ton::Bon,
            ),
            IssueAnimations::Refuse(r) => (
                crate::trf!(
                    "Refusé, pour cette fois seulement : {}",
                    "Refused, for this time only: {}",
                    r
                ),
                Ton::Attention,
            ),
            IssueAnimations::Echec(r) => (
                crate::trf!(
                    "Échec, pour cette fois seulement : {}",
                    "Failed, for this time only: {}",
                    r
                ),
                Ton::Attention,
            ),
        };
        self.console.finir(
            f.lancement,
            console::Fini {
                resume: texte,
                ton,
                points: Vec::new(),
                duree: f.duree,
                echec,
            },
        );
    }

    /// La saisie de la console validée par Entrée.
    pub fn saisir(&mut self) {
        let texte = std::mem::take(&mut self.saisie);
        self.rappel = None;
        let propre = crate::nettoyage::nom(texte.trim(), 60);
        if !propre.is_empty() && self.historique.last() != Some(&propre) {
            if self.historique.len() >= HISTORIQUE_MAX {
                self.historique.remove(0);
            }
            self.historique.push(propre.clone());
        }
        match commandes::comprendre(&texte) {
            Saisie::Rien => {}
            Saisie::Effacer => self.console.effacer(),
            Saisie::Aide => {
                self.dire(
                    "aide",
                    crate::tr!("Commandes permises ici :", "Commands allowed here:"),
                    Ton::Normal,
                );
                for c in Commande::ici() {
                    let l = format!("{:<22} {}", c.nom_affiche(), c.titre());
                    self.dire("aide", &l, Ton::Discret);
                }
                self.dire(
                    "aide",
                    crate::tr!(
                        "Rien d'autre ne se lance d'ici : ni option, ni argument, ni commande qui change l'ordinateur (un changement se fait d'un clic, après confirmation).",
                        "Nothing else runs from here: no option, no argument, no command that changes the computer (a change is one click, after confirmation)."
                    ),
                    Ton::Discret,
                );
                self.dire(
                    "aide",
                    crate::tr!(
                        "« aide <commande> » la décrit sans la lancer · Ctrl+R cherche dans vos saisies · Ctrl+F cherche dans la console · Échap arrête la commande en cours.",
                        "“help <command>” describes it without running it · Ctrl+R searches your entries · Ctrl+F searches the console · Esc stops the running command."
                    ),
                    Ton::Discret,
                );
            }
            Saisie::AideSur(c) => self.aide_sur(c),
            // Le bloc de la commande dit ce qui est lancé, avec ses arguments exacts : pas de ligne « vous » en plus.
            Saisie::Lancer(c) => {
                self.aller(ecran_de(c));
                self.demander(c);
            }
            Saisie::Refusee(t) => {
                self.coulisses.refusee(&texte);
                self.dire("vous", &t, Ton::Commande);
                self.dire(
                    "fenêtre",
                    crate::tr!(
                        "Commande inconnue ou pas encore permise ici : rien n'a été lancé. Tapez « aide ».",
                        "Unknown command, or not allowed here yet: nothing was run. Type “help”."
                    ),
                    Ton::Attention,
                );
                // Une faute de frappe : la commande proche est proposée, jamais lancée à la place.
                if let Some(c) = commandes::suggestions(&texte).first() {
                    self.dire(
                        "fenêtre",
                        &crate::trf!(
                            "Vouliez-vous dire « {} » ? Retapez-la, ou choisissez-la dans la liste (↓ puis Entrée).",
                            "Did you mean “{}”? Type it again, or pick it in the list (↓ then Enter).",
                            c.nom_affiche()
                        ),
                        Ton::Discret,
                    );
                }
            }
        }
    }

    /// `aide <commande>` : ce qu'elle fait, où elle se range, ce qui est lancé exactement. Rien n'est lancé.
    fn aide_sur(&mut self, c: Commande) {
        self.dire("aide", &format!("{} — {}", c.nom_affiche(), c.titre()), Ton::Normal);
        self.dire("aide", c.description(), Ton::Discret);
        self.dire(
            "aide",
            &crate::trf!(
                "Rubrique : {} · lance exactement : vanguard {} · tapez « {} » pour la lancer.",
                "Section: {} · runs exactly: vanguard {} · type “{}” to run it.",
                c.rubrique().nom(),
                c.arguments().join(" "),
                c.nom_affiche()
            ),
            Ton::Discret,
        );
    }

    /// Les saisies d'avant, la plus récente à la fin (Ctrl+R y cherche).
    pub fn historique(&self) -> &[String] {
        &self.historique
    }

    /// ↑ / ↓ rappellent-ils l'historique en ce moment (plutôt que de choisir une suggestion) ?
    pub fn en_rappel(&self) -> bool {
        self.rappel.is_some()
    }

    /// ↑ (plus ancien) ou ↓ (plus récent) dans l'historique des saisies.
    pub fn rappeler(&mut self, plus_ancien: bool) {
        if self.historique.is_empty() {
            return;
        }
        let dernier = self.historique.len().saturating_sub(1);
        self.rappel = match (self.rappel, plus_ancien) {
            (None, true) => Some(dernier),
            (None, false) => None,
            (Some(i), true) => Some(i.saturating_sub(1)),
            (Some(i), false) if i >= dernier => None,
            (Some(i), false) => Some(i.saturating_add(1)),
        };
        self.saisie = self
            .rappel
            .and_then(|i| self.historique.get(i).cloned())
            .unwrap_or_default();
    }

    /// Tab : complète la saisie quand un seul nom convient.
    pub fn completer(&mut self) {
        if let Some(n) = commandes::completer(&self.saisie) {
            self.saisie = n.to_string();
        }
    }
}

/// Ce qu'est devenu un changement, d'après Vanguard.
#[derive(Clone, Debug, PartialEq, Eq)]
enum IssueChangement {
    Fait,
    Refuse(String),
    Echec(String),
}

/// La dernière ligne de `vanguard demarrage --retirer|--remettre … --json` : `{"geste", "issue", "raison"}`.
#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct IssueBrute {
    geste: crate::donnees::Texte,
    issue: crate::donnees::Texte,
    raison: crate::donnees::Texte,
}

/// Lit l'issue d'un changement, strictement : « fait » seulement si Vanguard le dit, pour ce geste-là, avec le code
/// 0 ; une réponse illisible, d'un autre geste ou qui se contredit est un échec (la liste relue dira l'état réel).
fn issue_du_changement(ch: Changement, f: &Fin) -> IssueChangement {
    let illisible = || {
        IssueChangement::Echec(
            crate::tr!(
                "réponse de Vanguard illisible ; la liste relue montre l'état réel",
                "unreadable answer from Vanguard; the reloaded list shows the real state"
            )
            .to_string(),
        )
    };
    match &f.issue {
        Issue::Terminee => {}
        Issue::Arretee => return IssueChangement::Echec(crate::tr!("arrêté", "stopped").to_string()),
        Issue::DelaiDepasse => {
            return IssueChangement::Echec(crate::trf!(
                "arrêté : plus de {} s sans finir",
                "stopped: more than {} s without finishing",
                ch_delai(ch)
            ));
        }
        Issue::TropLongue => return illisible(),
        Issue::Impossible(e) => {
            return IssueChangement::Echec(crate::trf!("pas pu lancer : {}", "could not start: {}", e));
        }
    }
    // La dernière ligne non vide : Vanguard peut avoir écrit avant elle (un point de restauration, un avertissement).
    let Some(ligne) = f
        .sortie
        .split(|o| *o == b'\n')
        .rev()
        .find(|l| !l.iter().all(u8::is_ascii_whitespace))
    else {
        return illisible();
    };
    let Ok(b) = crate::donnees::lire::<IssueBrute>(ligne) else {
        return illisible();
    };
    if b.geste.as_str() != ch.sorte.mot() {
        return illisible();
    }
    let raison = crate::nettoyage::nom(b.raison.as_str(), 200);
    match (b.issue.as_str(), f.code) {
        ("fait", Some(0)) => IssueChangement::Fait,
        ("refuse", Some(c)) if c != 0 => IssueChangement::Refuse(raison),
        ("echec", Some(c)) if c != 0 => IssueChangement::Echec(raison),
        _ => illisible(),
    }
}

/// L'issue d'un geste qui change, en une phrase (la console et la feuille). Seul un refus dit « rien n'a été
/// fait » : un échec a pu commencer, une issue inconnue a pu tout faire.
pub fn phrase_issue(famille: Famille, issue: &IssueChange) -> String {
    match (famille, issue) {
        // La mise à jour ne passe pas par « Ce que Vanguard a changé » : son aperçu redit la version de chaque
        // programme en place.
        (Famille::MiseAJour, IssueChange::Echec(r)) => crate::trf!(
            "Échec : {}. Là où un programme n'est pas remplacé, l'ancien reste en place ; l'aperçu redit la version de chacun.",
            "Failed: {}. Where a program is not replaced, the old one stays in place; the preview tells each one's version again.",
            r
        ),
        (Famille::MiseAJour, IssueChange::Illisible(r)) => crate::trf!(
            "Issue inconnue ({}) : Vanguard a peut-être remplacé un programme. L'aperçu redit la version de chacun.",
            "Unknown outcome ({}): Vanguard may have replaced a program. The preview tells each one's version again.",
            r
        ),
        (_, issue) => phrase_issue_commune(issue),
    }
}

fn phrase_issue_commune(issue: &IssueChange) -> String {
    match issue {
        IssueChange::Fait { relu, .. } => {
            let relu = match relu {
                Relu::Corrige => crate::tr!("corrigé", "fixed"),
                Relu::EncoreSignale => crate::tr!("encore signalé", "still reported"),
                Relu::Revenu => crate::tr!("revenu comme avant", "back as before"),
                Relu::PasRevenu => crate::tr!("pas revenu comme avant partout", "not back as before everywhere"),
                // Sous Windows, la nouvelle copie n'est pas lancée pour essai (`mise_a_jour::essayer`) : pas dit.
                Relu::MisAJour if cfg!(windows) => crate::tr!(
                    "chaque programme remplacé, relu et comparé",
                    "each program replaced, read back and compared"
                ),
                Relu::MisAJour => crate::tr!(
                    "chaque programme remplacé, relu et essayé",
                    "each program replaced, read back and tried"
                ),
            };
            crate::trf!("Fait. Vanguard a relu : {}", "Done. Vanguard read it again: {}", relu)
        }
        IssueChange::Refuse(r) => crate::trf!("Refusé, rien n'a été fait : {}", "Refused, nothing was done: {}", r),
        IssueChange::Echec(r) => crate::trf!(
            "Échec : {}. Ce qui a pu changer se voit dans « Ce que Vanguard a changé ».",
            "Failed: {}. What may have changed shows in “What Vanguard changed”.",
            r
        ),
        IssueChange::Illisible(r) => crate::trf!(
            "Issue inconnue ({}) : Vanguard a peut-être changé quelque chose. Voyez « Ce que Vanguard a changé ».",
            "Unknown outcome ({}): Vanguard may have changed something. See “What Vanguard changed”.",
            r
        ),
    }
}

fn ch_delai(ch: Changement) -> u64 {
    Lancement::Changement(ch).delai().as_secs()
}

/// L'état du bac à sable pour les coulisses, tel que dit au démarrage.
fn etat_du_bac() -> (String, bool) {
    #[cfg(target_os = "linux")]
    if let Some(e) = crate::relais::etat() {
        return e.clone();
    }
    (
        if cfg!(windows) {
            crate::tr!(
                "Pas de bac à sable sous Windows : la fenêtre lance `vanguard` elle-même, chaque commande dans son objet de travail.",
                "No sandbox on Windows: the window starts `vanguard` itself, each command in its own job object."
            )
        } else {
            crate::tr!("Bac à sable pas posé.", "Sandbox not set up.")
        }
        .into(),
        false,
    )
}

/// L'écran où le résultat d'une commande se montre.
pub fn ecran_de(c: Commande) -> Ecran {
    match c {
        Commande::Bilan => Ecran::Bilan,
        Commande::Evenements => Ecran::Alertes,
        Commande::Appareils => Ecran::Appareils,
        _ => Ecran::Commande(c),
    }
}

fn lire(c: Commande, sortie: &[u8]) -> Result<Contenu, String> {
    Ok(match c.forme() {
        Forme::Audit | Forme::Resultat => Contenu::Constats(bilan::lire(sortie)?),
        Forme::AuditReseau => Contenu::Constats(bilan::lire_audit_reseau(sortie)?),
        Forme::Appareils => Contenu::Appareils(appareils::lire(sortie)?),
        Forme::Protection => Contenu::Protection(protection::lire(sortie)?),
        Forme::Evenements => Contenu::Evenements(evenements::lire(sortie)?),
        Forme::Changements => Contenu::Changements(changements::lire(sortie)?),
        Forme::Libre => Contenu::Libre(libre::lire(sortie)?),
    })
}

/// La couleur de la ligne de la console qui dit un résultat. Vert seulement pour ce qui a été vérifié et va bien :
/// un interrupteur éteint, une alerte, un constat à corriger ou une vérification qui n'a pas pu se faire ne passe
/// jamais pour sain ; ce que la fenêtre ne sait pas juger (un état en d'autres mots, des valeurs brutes) reste neutre.
fn ton(contenu: &Contenu) -> Ton {
    match contenu {
        Contenu::Erreur(_) => Ton::Attention,
        Contenu::Constats(v) => {
            if v.compte(bilan::Rang::Corriger) > 0 || v.compte(bilan::Rang::NonVerifie) > 0 || v.note_retenue {
                Ton::Attention
            } else if v.constats.is_empty() {
                Ton::Normal
            } else {
                Ton::Bon
            }
        }
        Contenu::Protection(v) => {
            if v.compte(protection::Allure::Eteint) > 0 || v.illisibles > 0 {
                Ton::Attention
            } else if v.interrupteurs.is_empty() || v.compte(protection::Allure::Nuance) > 0 {
                Ton::Normal
            } else {
                Ton::Bon
            }
        }
        Contenu::Evenements(v) => match v.etat.gravite() {
            Some(bilan::Gravite::Elevee | bilan::Gravite::Critique) => Ton::Grave,
            Some(_) => Ton::Attention,
            None if v.alertes().next().is_some() || v.illisibles > 0 => Ton::Attention,
            None => Ton::Bon,
        },
        // Un appareil nouveau, un risque, ce qui n'a pas pu être vu : jamais sain. Vert seulement pour un scan qui a
        // trouvé des appareils et tout pu vérifier, sans rien à signaler.
        Contenu::Appareils(v) => {
            if v.a_signaler() || !v.manques().is_empty() {
                Ton::Attention
            } else if v.appareils.is_empty() {
                Ton::Normal
            } else {
                Ton::Bon
            }
        }
        // Le relevé des corrections (`changements --json`) effacé, changé hors de Vanguard ou illisible, une ligne
        // interrompue, douteuse ou illisible : jamais lu comme un historique ordinaire. Sinon, neutre.
        Contenu::Changements(v)
            if !v.releve_sain()
                || v.illisibles > 0
                || v.lignes
                    .iter()
                    .any(|l| l.douteuse || l.etat == changements::Etat::Interrompue) =>
        {
            Ton::Attention
        }
        Contenu::Changements(_) | Contenu::Libre(_) => Ton::Normal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rien_d_eteint_d_alerte_ni_de_non_verifie_ne_passe_pour_sain() {
        use protection::Allure::{Allume, Eteint, Nuance};
        let p = |allures: &[protection::Allure], illisibles| {
            ton(&Contenu::Protection(protection::Vue {
                interrupteurs: allures
                    .iter()
                    .map(|a| protection::Interrupteur {
                        id: "x".into(),
                        nom: "x".into(),
                        etat: "x".into(),
                        allure: *a,
                    })
                    .collect(),
                illisibles,
            }))
        };
        assert_eq!(p(&[Allume, Allume], 0), Ton::Bon);
        assert_eq!(p(&[Allume, Eteint], 0), Ton::Attention);
        assert_eq!(p(&[Allume], 1), Ton::Attention);
        assert_eq!(p(&[Allume, Nuance], 0), Ton::Normal);
        assert_eq!(p(&[], 0), Ton::Normal);

        let e = |json: &str| ton(&Contenu::Evenements(evenements::lire(json.as_bytes()).unwrap()));
        assert_eq!(e(r#"{"etat": "intact", "evenements": []}"#), Ton::Bon);
        assert_eq!(
            e(r#"{"etat": "intact", "illisibles": 2, "evenements": []}"#),
            Ton::Attention
        );
        assert_eq!(e(r#"{"etat": "incomplet", "evenements": []}"#), Ton::Attention);
        assert_eq!(e(r#"{"etat": "falsifie", "evenements": []}"#), Ton::Grave);
        assert_eq!(e(r#"{"etat": "inattendu", "evenements": []}"#), Ton::Attention);
        let alerte = r#"{"etat": "intact", "evenements": [{"v": 1, "id": "a1", "quand": "2026-11-09T13:10:00Z",
            "source": "surveillance", "quoi": {"sorte": "alerte", "famille": "botnet", "titre": "Connexion"}}]}"#;
        assert_eq!(e(alerte), Ton::Attention);

        let b = |json: &str| ton(&Contenu::Constats(bilan::lire(json.as_bytes()).unwrap()));
        let sain = r#"{"regle": "R1", "categorie": "Pare-feu", "etat": "sain", "message": "Actif."}"#;
        assert_eq!(
            b(&format!(r#"{{"score": 100, "fiable": true, "constats": [{sain}]}}"#)),
            Ton::Bon
        );
        let manque = r#""couverture": {"non_verifies": ["Les disques"]}"#;
        assert_eq!(
            b(&format!(
                r#"{{"score": 100, "fiable": true, "constats": [{sain}], {manque}}}"#
            )),
            Ton::Attention
        );
        assert_eq!(b(r#"{"constats": []}"#), Ton::Normal);

        assert_eq!(ton(&Contenu::Libre(libre::Vue::default())), Ton::Normal);
        let releve = |etat: &str| {
            Contenu::Changements(
                changements::lire(format!(r#"{{"schema":1,"releve":"{etat}","total":0}}"#).as_bytes()).unwrap(),
            )
        };
        assert_eq!(ton(&releve("intact")), Ton::Normal);
        assert_eq!(ton(&releve("absent")), Ton::Normal);
        assert_eq!(ton(&releve("efface")), Ton::Attention);
        assert_eq!(ton(&releve("change-hors-de-vanguard")), Ton::Attention);

        let a = |json: &str| ton(&Contenu::Appareils(appareils::lire(json.as_bytes()).unwrap()));
        let teste = r#""upnp": "Absent", "empoisonnement": {"Teste": []}"#;
        let un = r#"{"ip": "192.168.1.20", "ports": [], "alertes": [], "nouvelle": false}"#;
        assert_eq!(a(&format!(r#"{{"hotes": [{un}], {teste}}}"#)), Ton::Bon);
        assert_eq!(a(&format!(r#"{{"hotes": [], {teste}}}"#)), Ton::Normal);
        // UPnP pas interrogé, sonde des faux noms pas lancée : non vérifié, jamais vert.
        assert_eq!(
            a(&format!(
                r#"{{"hotes": [{un}], "upnp": "OutilAbsent", "empoisonnement": {{"Teste": []}}}}"#
            )),
            Ton::Attention
        );
        assert_eq!(
            a(&format!(
                r#"{{"hotes": [{un}], "upnp": "Absent", "empoisonnement": "SansReseauLocal"}}"#
            )),
            Ton::Attention
        );
        let nouveau = r#"{"ip": "192.168.1.21", "nouvelle": true}"#;
        assert_eq!(a(&format!(r#"{{"hotes": [{nouveau}], {teste}}}"#)), Ton::Attention);
        assert_eq!(a(&format!(r#"{{"hotes": [{un}, 7], {teste}}}"#)), Ton::Attention);
    }

    fn appli() -> Appli {
        // Sans programme : rien ne peut se lancer, l'état seul est essayé.
        Appli::nouvelle(Err("absent".into()), std::sync::Arc::new(|| {}))
    }

    #[test]
    fn la_console_refuse_sans_lancer() {
        let mut a = appli();
        a.saisie = "bilan; rm -rf ~".into();
        a.saisir();
        assert!(a.en_cours().is_none());
        assert_eq!(a.taches(), 0);
        assert!(a.console.dit("rien n'a été lancé"));
        assert_eq!(a.saisie, "");
    }

    #[test]
    fn la_console_est_bornee() {
        let mut a = appli();
        for i in 0..(console::ENTREES_MAX + 20) {
            a.dire("x", &format!("{i}"), Ton::Normal);
        }
        assert_eq!(a.console.len(), console::ENTREES_MAX);
        // Les numéros suivent, même quand les plus anciennes partent : la console y retrouve ses places.
        let e = a.console.entrees();
        assert!(
            e.iter()
                .zip(e.iter().skip(1))
                .all(|(x, y)| y.numero() == x.numero() + 1)
        );
    }

    /// « Retour » revient pas à pas, sans pas doublé pour un même écran, et la pile reste bornée.
    #[test]
    fn retour_pas_a_pas() {
        let mut a = appli();
        assert_eq!(a.retour(), None);
        a.revenir();
        assert_eq!(a.ecran, Ecran::Accueil);
        a.aller(Ecran::Rubrique(Rubrique::Optimiser));
        a.aller(Ecran::Rubrique(Rubrique::Optimiser));
        a.aller(Ecran::Commande(Commande::Demarrage));
        assert_eq!(a.retour(), Some(Ecran::Rubrique(Rubrique::Optimiser)));
        a.revenir();
        assert_eq!(a.ecran, Ecran::Rubrique(Rubrique::Optimiser));
        a.revenir();
        assert_eq!(a.ecran, Ecran::Accueil);
        assert_eq!(a.retour(), None);
        for i in 0..RETOURS_MAX * 2 {
            a.aller(if i % 2 == 0 { Ecran::Guide } else { Ecran::Bilan });
        }
        assert_eq!(a.retours.len(), RETOURS_MAX);
    }

    /// Aucun écran n'est changé sans `aller` (ou `revenir`) : sinon « Retour » sauterait un pas.
    #[test]
    fn un_seul_chemin_pour_changer_d_ecran() {
        let aiguille = concat!(".ecran", " = ");
        let mut vus = 0;
        let mut pile = vec![std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/src"))];
        while let Some(d) = pile.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let chemin = e.unwrap().path();
                if chemin.is_dir() {
                    pile.push(chemin);
                } else if chemin.extension().is_some_and(|x| x == "rs") {
                    let code = std::fs::read_to_string(&chemin).unwrap();
                    let n = code.matches(aiguille).count();
                    if chemin.ends_with("appli.rs") {
                        vus += n;
                    } else {
                        assert_eq!(n, 0, "{} change d'écran sans aller()", chemin.display());
                    }
                }
            }
        }
        assert_eq!(vus, 2, "seuls aller() et revenir() changent d'écran");
    }

    #[test]
    fn l_historique_se_rappelle() {
        let mut a = appli();
        for s in ["aide", "effacer", "aide"] {
            a.saisie = s.into();
            a.saisir();
        }
        a.rappeler(true);
        assert_eq!(a.saisie, "aide");
        a.rappeler(true);
        assert_eq!(a.saisie, "effacer");
        a.rappeler(false);
        a.rappeler(false);
        assert_eq!(a.saisie, "");
    }

    #[test]
    fn une_erreur_garde_le_resultat_d_avant() {
        let mut a = appli();
        let fin = |sortie: &[u8], issue| Fin {
            lancement: Commande::Bilan.into(),
            code: Some(0),
            sortie: sortie.to_vec(),
            issue,
            duree: Duration::from_secs(1),
        };
        a.finir(&fin(
            br#"{"score": 90, "fiable": true, "constats": [{"etat": "sain", "categorie": "A"}]}"#,
            Issue::Terminee,
        ));
        a.finir(&fin(b"", Issue::DelaiDepasse));
        assert_eq!(a.bilan().and_then(|b| b.note), Some(90));
        a.finir(&fin(b"pas du json", Issue::Terminee));
        assert!(a.bilan().is_some());
    }

    /// L'issue d'un changement n'est « fait » que dite ainsi par Vanguard, pour ce geste, avec le code 0 ; des lignes
    /// avant la dernière ne gênent pas ; tout le reste est un échec, jamais un succès.
    #[test]
    fn l_issue_d_un_changement_est_lue_strictement() {
        use crate::commandes::Empreinte;
        let ch = Changement {
            sorte: Sorte::Retirer,
            empreinte: Empreinte::lire("0123456789abcdef0123456789abcdef").unwrap(),
            accord: crate::commandes::Accord::NUL,
        };
        let fin = |sortie: &str, code, issue| Fin {
            lancement: Lancement::Changement(ch),
            code,
            sortie: sortie.as_bytes().to_vec(),
            issue,
            duree: Duration::ZERO,
        };
        let lire = |sortie: &str, code| issue_du_changement(ch, &fin(sortie, code, Issue::Terminee));
        assert_eq!(
            lire(
                "Point de restauration…\n{\"geste\":\"retirer\",\"issue\":\"fait\",\"raison\":\"\"}\n\n",
                Some(0)
            ),
            IssueChangement::Fait
        );
        assert_eq!(
            lire(
                "{\"geste\":\"retirer\",\"issue\":\"refuse\",\"raison\":\"inconnu\\u001b[2K\\u202e\"}",
                Some(1)
            ),
            IssueChangement::Refuse("inconnu\u{fffd}".into())
        );
        assert!(matches!(
            lire("{\"geste\":\"retirer\",\"issue\":\"echec\",\"raison\":\"refusé\"}", Some(1)),
            IssueChangement::Echec(r) if r == "refusé"
        ));
        // Ce qui se contredit ou ne se lit pas : un échec.
        for (sortie, code) in [
            ("{\"geste\":\"retirer\",\"issue\":\"fait\"}", Some(1)),
            ("{\"geste\":\"retirer\",\"issue\":\"fait\"}", None),
            ("{\"geste\":\"remettre\",\"issue\":\"fait\"}", Some(0)),
            ("{\"geste\":\"retirer\",\"issue\":\"refuse\"}", Some(0)),
            ("{\"geste\":\"retirer\",\"issue\":\"Fait\"}", Some(0)),
            ("{\"geste\":\"retirer\",\"issue\":\"fait\"}\nfin", Some(0)),
            ("{\"geste\":\"retirer\",\"issue\":\"fait\"", Some(0)),
            ("[\"fait\"]", Some(0)),
            ("", Some(0)),
            ("\n  \n", Some(0)),
        ] {
            assert!(
                matches!(lire(sortie, code), IssueChangement::Echec(_)),
                "{sortie:?} {code:?}"
            );
        }
        for issue in [
            Issue::Arretee,
            Issue::DelaiDepasse,
            Issue::TropLongue,
            Issue::Impossible("x".into()),
        ] {
            let f = fin("{\"geste\":\"retirer\",\"issue\":\"fait\"}", Some(0), issue);
            assert!(matches!(issue_du_changement(ch, &f), IssueChangement::Echec(_)));
        }
    }

    /// Un faux `vanguard` (un script dans target/, jamais le vrai) : la liste du démarrage, et chaque changement noté
    /// dans un fichier au lieu d'être fait.
    #[cfg(unix)]
    const FAUX_DEMARRAGE: &str = r#"#!/bin/sh
case "$1 $2" in
"demarrage --json") cat liste.json ;;
"demarrage --retirer"|"demarrage --remettre") echo "$@" >> changements
  printf 'une ligne avant\n{"geste": "%s", "issue": "fait", "raison": ""}\n' "${2#--}" ;;
*) exit 7 ;;
esac
"#;

    #[cfg(unix)]
    fn finir_tout(a: &mut Appli) {
        let debut = Instant::now();
        while a.taches() > 0 {
            assert!(debut.elapsed() < Duration::from_secs(20), "jamais fini");
            a.avancer();
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Un faux `vanguard` pour l'aperçu d'une correction : le bilan, et chaque aperçu noté dans un fichier.
    #[cfg(unix)]
    const FAUX_CORRECTION: &str = r#"#!/bin/sh
case "$1 $2" in
"audit --json") cat bilan.json ;;
"correction --voir") echo "$@" >> apercus
  [ -f lent ] && sleep 30
  printf '{"geste":"voir-correction","issue":"refuse","raison":"ce problème a disparu"}\n'; exit 1 ;;
*) exit 7 ;;
esac
"#;

    /// « Voir la correction » : seulement pour un jeton du dernier bilan ; attend la commande en cours ; la réponse
    /// remplit la feuille ; « Accepter » n'y fait rien ; « Annuler » et Échap la ferment (et arrêtent l'aperçu
    /// encore en lecture) sans changer d'écran.
    #[cfg(unix)]
    #[test]
    fn la_feuille_de_correction_ne_montre_que_le_dernier_bilan() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = crate::essais::banc("feuille-correction");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let j1 = "0123456789abcdef0123456789abcdef";
        let j2 = "fedcba9876543210fedcba9876543210";
        let script = d.join("vanguard");
        std::fs::write(&script, FAUX_CORRECTION).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let moi = std::fs::metadata(&d).unwrap().uid();
        let p = Programme::dans(&d, moi).unwrap();
        let mut a = Appli::nouvelle(Ok(p), std::sync::Arc::new(|| {}));
        finir_tout(&mut a);
        a.aller(Ecran::Bilan);
        let apercus = || std::fs::read_to_string(d.join("apercus")).unwrap_or_default();
        let e1 = Empreinte::lire(j1).unwrap();
        let e2 = Empreinte::lire(j2).unwrap();

        // Sans bilan (celui de l'ouverture n'a rien rendu), puis pour un jeton absent du bilan : rien ne s'ouvre ni
        // ne se lance.
        assert!(a.bilan().is_none());
        a.voir_correction(e1);
        assert!(a.feuille_correction().is_none());
        std::fs::write(
            d.join("bilan.json"),
            format!(
                r#"{{"systeme": "Linux", "constats": [{{"etat": "probleme", "probleme": "Moyen", "message": "SSH",
                "geste": {{"sorte": "voir-correction", "jeton": "{j1}"}}}}]}}"#
            ),
        )
        .unwrap();
        a.demander(Commande::Bilan);
        finir_tout(&mut a);
        a.voir_correction(e2);
        assert!(a.feuille_correction().is_none());
        assert_eq!(apercus(), "");

        // Une commande tourne : la feuille attend son tour, puis l'aperçu part seul et la remplit.
        a.demander(Commande::Bilan);
        a.voir_correction(e1);
        assert_eq!(
            a.feuille_correction().map(|f| &f.etat),
            Some(&EtatFeuille::Attente { lance: false })
        );
        finir_tout(&mut a);
        assert_eq!(apercus(), format!("correction --voir {j1} --json\n"));
        assert_eq!(
            a.feuille_correction().map(|f| &f.etat),
            Some(&EtatFeuille::Lue(correction::Lecture::Refusee(
                "ce problème a disparu".into()
            )))
        );
        // Rien à accepter : la feuille reste, rien n'est lancé.
        a.accepter();
        assert!(a.feuille_correction().is_some());
        assert_eq!(a.taches(), 0);
        // Une seule feuille : une autre demande attend qu'on ferme celle-ci.
        a.voir_correction(e1);
        assert_eq!(apercus().lines().count(), 1);
        // Échap ferme la feuille seule : l'écran du bilan reste.
        a.revenir();
        assert!(a.feuille_correction().is_none());
        assert_eq!(a.ecran, Ecran::Bilan);

        // Fermée pendant la lecture : l'aperçu s'arrête, sa fin ne rouvre rien.
        std::fs::write(d.join("lent"), "").unwrap();
        a.voir_correction(e1);
        assert_eq!(
            a.feuille_correction().map(|f| &f.etat),
            Some(&EtatFeuille::Attente { lance: true })
        );
        // L'aperçu a commencé (il dort 30 s) : l'arrêt doit le couper, `finir_tout` n'attend pas 30 s.
        let debut = Instant::now();
        while apercus().lines().count() < 2 {
            assert!(debut.elapsed() < Duration::from_secs(10), "aperçu jamais lancé");
            std::thread::sleep(Duration::from_millis(20));
        }
        a.annuler();
        assert!(a.feuille_correction().is_none());
        finir_tout(&mut a);
        assert!(a.feuille_correction().is_none());
        assert!(debut.elapsed() < Duration::from_secs(25));
    }

    /// Un faux `vanguard` pour les gestes qui changent : chaque appel noté dans `appels`, la réponse de chaque
    /// commande lue dans `r-<commande><option>`, son code dans `c-<commande><option>` (0 sinon).
    #[cfg(unix)]
    const FAUX_GESTES: &str = r#"#!/bin/sh
echo "$@" >> appels
cle="$1$2"
[ "$1" = changements ] && [ "$2" = --json ] && cle=changements
[ -f "r-$cle" ] || exit 7
cat "r-$cle"
[ -f "c-$cle" ] && exit "$(cat "c-$cle")"
exit 0
"#;

    /// Le bouton qui change ne s'accepte qu'un aperçu lu, d'ici, montré depuis 2 s au moins (Q7) ; jamais avant,
    /// jamais un refus, une lecture illisible, une feuille en attente, envoyée ou reçue.
    #[test]
    fn rien_ne_s_accepte_avant_deux_secondes() {
        let jeton = Empreinte::lire(&"b8".repeat(16)).unwrap();
        let ligne = include_str!("../essais/apercus-noms-guillemets.jsonl")
            .lines()
            .next()
            .unwrap();
        let vrai = serde_json::from_str::<serde_json::Value>(ligne).unwrap();
        let ligne = ligne.replace(vrai["apercu"]["jeton"].as_str().unwrap(), &jeton.hex());
        let lue = EtatFeuille::Lue(correction::lire(jeton, Some(0), ligne.as_bytes()));
        let accord = Accord::lire(vrai["accord"].as_str().unwrap()).unwrap();
        let t0 = Instant::now();
        assert_eq!(peut_accepter(&lue, Some(t0), t0), None);
        assert_eq!(
            peut_accepter(&lue, Some(t0), t0 + APERCU_LU.saturating_sub(Duration::from_millis(1))),
            None
        );
        assert_eq!(peut_accepter(&lue, Some(t0), t0 + APERCU_LU), Some(accord));
        // Jamais montré (encore en lecture) : jamais acceptable, même tard.
        assert_eq!(peut_accepter(&lue, None, t0 + Duration::from_secs(60)), None);
        // Une horloge qui recule ne compte pas comme du temps lu.
        assert_eq!(peut_accepter(&lue, Some(t0 + Duration::from_secs(5)), t0), None);
        let tard = t0 + Duration::from_secs(60);
        for etat in [
            EtatFeuille::Attente { lance: true },
            EtatFeuille::Envoi,
            EtatFeuille::Echec("x".into()),
            EtatFeuille::Lue(correction::Lecture::Refusee("x".into())),
            EtatFeuille::Lue(correction::Lecture::Illisible("x".into())),
            EtatFeuille::Recu(IssueChange::Echec("x".into())),
        ] {
            assert_eq!(peut_accepter(&etat, Some(t0), tard), None, "{etat:?}");
        }
        // D'administrateur ou pas annulable : pas d'ici, même lu depuis longtemps.
        for (champ, valeur) in [
            ("droits", serde_json::json!("admin")),
            ("annulable", serde_json::json!(false)),
        ] {
            let mut v = vrai.clone();
            v["apercu"][champ] = valeur;
            v["apercu"]["jeton"] = serde_json::json!(jeton.hex());
            let e = EtatFeuille::Lue(correction::lire(jeton, Some(0), v.to_string().as_bytes()));
            // (Un aperçu automatique qui ne s'annule pas se contredit : illisible, pas acceptable non plus.)
            if champ == "droits" {
                assert!(matches!(e, EtatFeuille::Lue(correction::Lecture::Lue(_))), "{champ}");
            }
            assert_eq!(peut_accepter(&e, Some(t0), tard), None, "{champ}");
        }
    }

    /// De bout en bout, avec un faux `vanguard` : l'aperçu lu ne s'accepte pas avant 2 s ; accepté, seuls le jeton
    /// et l'accord de l'aperçu partent, une fois (un second clic n'envoie rien) ; un refus redemande l'aperçu et dit
    /// que ça a changé pendant la lecture ; fait, la feuille le dit, « Ce que Vanguard a changé » et le bilan sont
    /// relus, et « Annuler cette correction » ouvre l'aperçu de l'annulation, qui s'accepte de même.
    #[cfg(unix)]
    #[test]
    fn appliquer_puis_remettre_de_bout_en_bout() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = crate::essais::banc("gestes-qui-changent");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let script = d.join("vanguard");
        std::fs::write(&script, FAUX_GESTES).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let ecrire = |nom: &str, contenu: &str| std::fs::write(d.join(nom), contenu).unwrap();
        let appels = || std::fs::read_to_string(d.join("appels")).unwrap_or_default();
        let compter = |motif: &str| appels().lines().filter(|l| l.starts_with(motif)).count();

        let j = "b8d7b4e8da9c5f36ca6d4a4696642cdc";
        let k = "00112233445566778899aabbccddeeff";
        let (a1, a2, a3) = ("a1".repeat(32), "a2".repeat(32), "a3".repeat(32));
        ecrire(
            "r-audit--json",
            &format!(
                r#"{{"systeme": "Linux", "constats": [{{"etat": "probleme", "probleme": "Critique",
                "message": "Clé lisible", "geste": {{"sorte": "voir-correction", "jeton": "{j}"}}}}]}}"#
            ),
        );
        let reel = include_str!("../essais/apercus-noms-guillemets.jsonl")
            .lines()
            .next()
            .unwrap();
        let apercu = |accord: &str| {
            let mut v = serde_json::from_str::<serde_json::Value>(reel).unwrap();
            v["accord"] = serde_json::json!(accord);
            v.to_string()
        };
        ecrire("r-correction--voir", &apercu(&a1));

        let moi = std::fs::metadata(&d).unwrap().uid();
        let mut a = Appli::nouvelle(Ok(Programme::dans(&d, moi).unwrap()), std::sync::Arc::new(|| {}));
        finir_tout(&mut a);
        a.aller(Ecran::Bilan);
        a.demander(Commande::Bilan);
        finir_tout(&mut a);
        let ej = Empreinte::lire(j).unwrap();
        a.voir_correction(ej);
        finir_tout(&mut a);
        let etat = |a: &Appli| a.feuille_correction().map(|f| f.etat.clone());
        assert!(matches!(etat(&a), Some(EtatFeuille::Lue(correction::Lecture::Lue(_)))));

        // Tout de suite : rien ne part, la feuille reste.
        a.accepter();
        finir_tout(&mut a);
        assert_eq!(compter("correction --appliquer"), 0);
        assert!(matches!(etat(&a), Some(EtatFeuille::Lue(correction::Lecture::Lue(_)))));

        // Après 2 s : le jeton et l'accord de l'aperçu, tels quels, une fois. Vanguard refuse (l'état a changé
        // pendant la lecture) : un nouvel aperçu, à l'accord nouveau, et l'avis le dit.
        ecrire(
            "r-correction--appliquer",
            r#"{"geste":"appliquer-correction","issue":"refuse","raison":"l'aperçu a changé","relu":""}"#,
        );
        ecrire("c-correction--appliquer", "1");
        ecrire("r-correction--voir", &apercu(&a2));
        a.vieillir_apercu();
        a.accepter();
        assert_eq!(etat(&a), Some(EtatFeuille::Envoi));
        a.accepter();
        a.accepter();
        finir_tout(&mut a);
        assert_eq!(compter("correction --appliquer"), 1);
        assert!(appels().contains(&format!("correction --appliquer {j} --accord {a1} --json\n")));
        assert_eq!(compter("correction --voir"), 2);
        let f = a.feuille_correction().unwrap();
        assert!(matches!(&f.etat, EtatFeuille::Lue(correction::Lecture::Lue(x)) if x.accord.hex() == a2));
        assert_eq!(
            f.avis.as_deref(),
            Some("Ça a changé pendant que vous lisiez. Rien n'a été fait.")
        );
        // Le nouvel aperçu se relit 2 s, comme le premier.
        a.accepter();
        finir_tout(&mut a);
        assert_eq!(compter("correction --appliquer"), 1);

        // Fait : la feuille le dit, la liste et le bilan sont relus, l'annulation y est offerte.
        ecrire(
            "r-correction--appliquer",
            &format!(
                r#"{{"geste":"appliquer-correction","issue":"fait","raison":"","relu":"corrige","annulation":"{k}"}}"#
            ),
        );
        ecrire("c-correction--appliquer", "0");
        ecrire(
            "r-changements",
            &format!(
                r#"{{"schema":1,"releve":"intact","total":1,"montres":1,"plus_anciens":0,"changements":[
                {{"date":"2026-11-11 15:10","reussi":true,"genre":"correction","texte":"chmod 600 ~/.ssh/id_x",
                  "commandes":1,"etat":"annulable","origine":null,"preuve":"","geste":{{"sorte":"voir-annulation","jeton":"{k}"}}}}]}}"#
            ),
        );
        let (bilans, listes) = (compter("audit --json"), compter("changements --json"));
        a.vieillir_apercu();
        a.accepter();
        finir_tout(&mut a);
        assert!(appels().contains(&format!("correction --appliquer {j} --accord {a2} --json\n")));
        let ek = Empreinte::lire(k).unwrap();
        assert_eq!(
            etat(&a),
            Some(EtatFeuille::Recu(IssueChange::Fait {
                relu: changements::Relu::Corrige,
                annulation: Some(ek)
            }))
        );
        assert_eq!(compter("audit --json"), bilans + 1);
        assert_eq!(compter("changements --json"), listes + 1);
        assert!(a.dans_les_changements(ek));
        // Fermer une feuille reçue ne dit rien de plus (l'issue est déjà dite).
        a.accepter();
        assert_eq!(compter("correction --appliquer"), 2);

        // « Annuler cette correction » : l'aperçu de l'annulation, puis, 2 s après, le geste qui remet.
        let mut annulation = serde_json::json!({
            "accord": a3,
            "apercu": {
                "date": "2026-11-11 15:10", "droits": "compte", "jeton": k, "langue": "fr",
                "titre": "chmod 600 ~/.ssh/id_x", "version": "0.99.0",
                "valeurs": [{"actuel": "0600", "avant": "0644", "change_depuis": false, "chemin": "~/.ssh/id_x",
                             "pose": "0600"}]
            },
            "geste": "voir-annulation", "issue": "fait", "raison": ""
        });
        ecrire("r-changements--voir", &annulation.to_string());
        ecrire(
            "r-changements--annuler",
            r#"{"geste":"annuler-correction","issue":"fait","raison":"","relu":"revenu"}"#,
        );
        a.voir_annulation(ek);
        finir_tout(&mut a);
        assert_eq!(a.feuille_correction().map(|f| f.famille), Some(Famille::Annulation));
        assert!(matches!(
            etat(&a),
            Some(EtatFeuille::Annulation(correction::Lecture::Lue(_)))
        ));
        a.accepter();
        finir_tout(&mut a);
        assert_eq!(compter("changements --annuler"), 0);
        a.vieillir_apercu();
        a.accepter();
        a.accepter();
        finir_tout(&mut a);
        assert_eq!(compter("changements --annuler"), 1);
        assert!(appels().contains(&format!("changements --annuler {k} --accord {a3} --json\n")));
        assert_eq!(
            etat(&a),
            Some(EtatFeuille::Recu(IssueChange::Fait {
                relu: changements::Relu::Revenu,
                annulation: None
            }))
        );

        // Une annulation qui n'est plus offerte n'ouvre rien ; une valeur « changée depuis » se montre, et s'accepte
        // (la personne la voit en jaune), mais un chemin retouché ne s'accepte pas d'ici.
        ecrire(
            "r-changements",
            r#"{"schema":1,"releve":"intact","total":0,"montres":0,"plus_anciens":0,"changements":[]}"#,
        );
        a.annuler();
        a.demander(Commande::Changements);
        finir_tout(&mut a);
        a.voir_annulation(ek);
        assert!(a.feuille_correction().is_none());
        assert_eq!(compter("changements --voir"), 1);
        annulation["apercu"]["valeurs"][0]["chemin"] = serde_json::json!("~/.ssh/id\u{202e}x");
        let lu = changements::lire_apercu(ek, Some(0), annulation.to_string().as_bytes());
        let e = EtatFeuille::Annulation(lu);
        assert_eq!(
            peut_accepter(&e, Instant::now().checked_sub(APERCU_LU), Instant::now()),
            None
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// « Mettre à jour Vanguard », de bout en bout avec un faux `vanguard` : la carte ouvre la feuille et ne lance
    /// que `se-mettre-a-jour --voir --json` ; l'aperçu proposé ne s'accepte pas avant 2 s ; accepté, seul l'accord
    /// montré part, une fois, sans jeton ; un refus redemande l'aperçu ; fait, la feuille le dit sans relire le bilan.
    /// « Pas vérifié » ne se lit jamais « à jour » et ne s'accepte jamais.
    #[cfg(unix)]
    #[test]
    fn mettre_a_jour_ne_part_qu_avec_l_accord_montre() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = crate::essais::banc("mise-a-jour");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let script = d.join("vanguard");
        std::fs::write(&script, FAUX_GESTES).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let ecrire = |nom: &str, contenu: &str| std::fs::write(d.join(nom), contenu).unwrap();
        let appels = || std::fs::read_to_string(d.join("appels")).unwrap_or_default();
        let compter = |motif: &str| appels().lines().filter(|l| l.starts_with(motif)).count();
        let (a1, a2) = ("e1".repeat(32), "e2".repeat(32));
        let apercu = |accord: &str| {
            format!(
                r#"{{"geste":"voir-mise-a-jour","issue":"fait","raison":"","etat":"propose","apercu":{{"version":"0.95.0","langue":"fr","jeton":"{}","origine":"github","visee":"0.96.0","sha256":"{}","taille":12345678,"cibles":[{{"chemin":"~/.local/share/vanguard/bin/vanguard","version":"0.95.0"}}]}},"accord":"{accord}"}}"#,
                Empreinte::MISE_A_JOUR.hex(),
                "ab".repeat(32)
            )
        };
        ecrire("r-se-mettre-a-jour--voir", &apercu(&a1));
        let moi = std::fs::metadata(&d).unwrap().uid();
        let mut a = Appli::nouvelle(Ok(Programme::dans(&d, moi).unwrap()), std::sync::Arc::new(|| {}));
        finir_tout(&mut a);
        let etat = |a: &Appli| a.feuille_correction().map(|f| f.etat.clone());

        a.voir_mise_a_jour();
        finir_tout(&mut a);
        assert_eq!(a.feuille_correction().map(|f| f.famille), Some(Famille::MiseAJour));
        assert!(appels().contains("se-mettre-a-jour --voir --json\n"));
        assert!(matches!(
            etat(&a),
            Some(EtatFeuille::MiseAJour(mise_a_jour::Vue::Proposee(_)))
        ));
        // Tout de suite : rien ne part.
        a.accepter();
        finir_tout(&mut a);
        assert_eq!(compter("se-mettre-a-jour --appliquer"), 0);

        // Après 2 s : l'accord montré, sans jeton, une fois. Vanguard refuse (la version a changé) : un nouvel
        // aperçu, à l'accord nouveau.
        ecrire(
            "r-se-mettre-a-jour--appliquer",
            r#"{"geste":"mettre-a-jour","issue":"refuse","raison":"la mise à jour a changé depuis l'aperçu","cibles":[]}"#,
        );
        ecrire("c-se-mettre-a-jour--appliquer", "1");
        ecrire("r-se-mettre-a-jour--voir", &apercu(&a2));
        a.vieillir_apercu();
        a.accepter();
        a.accepter();
        finir_tout(&mut a);
        assert_eq!(compter("se-mettre-a-jour --appliquer"), 1);
        assert!(appels().contains(&format!("se-mettre-a-jour --appliquer --accord {a1} --json\n")));
        assert_eq!(compter("se-mettre-a-jour --voir"), 2);
        assert!(matches!(
            etat(&a),
            Some(EtatFeuille::MiseAJour(mise_a_jour::Vue::Proposee(m))) if m.accord.hex() == a2
        ));

        // Fait : la feuille le dit ; le bilan n'est pas relu (la mise à jour ne le touche pas).
        ecrire(
            "r-se-mettre-a-jour--appliquer",
            r#"{"geste":"mettre-a-jour","issue":"fait","raison":"","cibles":[{"chemin":"~/.local/share/vanguard/bin/vanguard","issue":"fait","raison":""}]}"#,
        );
        ecrire("c-se-mettre-a-jour--appliquer", "0");
        let bilans = compter("audit --json");
        a.vieillir_apercu();
        a.accepter();
        finir_tout(&mut a);
        assert!(appels().contains(&format!("se-mettre-a-jour --appliquer --accord {a2} --json\n")));
        assert_eq!(
            etat(&a),
            Some(EtatFeuille::Recu(IssueChange::Fait {
                relu: changements::Relu::MisAJour,
                annulation: None
            }))
        );
        assert_eq!(compter("audit --json"), bilans);

        // « Pas vérifié » (code 1) : jamais « à jour », jamais acceptable.
        a.annuler();
        ecrire(
            "r-se-mettre-a-jour--voir",
            r#"{"geste":"voir-mise-a-jour","issue":"refuse","raison":"GitHub n'a pas répondu","etat":"non-verifie"}"#,
        );
        ecrire("c-se-mettre-a-jour--voir", "1");
        a.voir_mise_a_jour();
        finir_tout(&mut a);
        assert!(matches!(
            etat(&a),
            Some(EtatFeuille::MiseAJour(mise_a_jour::Vue::NonVerifiee(_)))
        ));
        a.vieillir_apercu();
        a.accepter();
        finir_tout(&mut a);
        assert_eq!(compter("se-mettre-a-jour --appliquer"), 2);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// La confirmation est obligatoire et un changement passe seul : sans proposition, « Accepter » ne fait rien ; un
    /// geste absent de la liste n'ouvre rien ; une proposition ouverte bloque les autres ; « Annuler » ne lance rien ;
    /// pendant qu'une commande tourne, « Accepter » attend ; un changement lancé ne s'arrête pas d'un clic, sa fin est
    /// dite puis la liste relue.
    #[cfg(unix)]
    #[test]
    fn un_changement_demande_la_confirmation_et_passe_seul() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = crate::essais::banc("demarrage");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let e1 = "0123456789abcdef0123456789abcdef";
        std::fs::write(
            d.join("liste.json"),
            format!(
                r#"{{"outil": "PRO-DEM-001", "constats": [
                {{"categorie": "Démarrage", "etat": "sain", "message": "Lecteur — se lance · /usr/bin/lecteur",
                  "objet": "demarrage:Lecteur",
                  "geste": {{"sorte": "retirer", "empreinte": "{e1}", "nom": "Lecteur", "commande": "/usr/bin/lecteur"}}}},
                {{"categorie": "Démarrage", "etat": "sain",
                  "message": "Murdefeu — pare-feu : le retirer baisserait la protection · /usr/bin/murdefeu",
                  "objet": "demarrage:Murdefeu"}}]}}"#
            ),
        )
        .unwrap();
        let script = d.join("vanguard");
        std::fs::write(&script, FAUX_DEMARRAGE).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let moi = std::fs::metadata(&d).unwrap().uid();
        let p = Programme::dans(&d, moi).unwrap();
        let mut a = Appli::nouvelle(Ok(p), std::sync::Arc::new(|| {}));
        finir_tout(&mut a);
        let changements = || std::fs::read_to_string(d.join("changements")).unwrap_or_default();

        let g1 = bilan::Geste {
            changement: Changement {
                sorte: Sorte::Retirer,
                empreinte: crate::commandes::Empreinte::lire(e1).unwrap(),
                accord: crate::commandes::Accord::NUL,
            },
            nom: "Lecteur".into(),
            commande: "/usr/bin/lecteur".into(),
            machine: false,
        };
        // Avant la liste : rien à proposer.
        a.proposer(&g1);
        assert!(a.confirmation().is_none());
        a.demander(Commande::Demarrage);
        finir_tout(&mut a);
        let Some(Contenu::Constats(v)) = a.resultat(Commande::Demarrage).map(|r| &r.contenu) else {
            panic!("pas de liste");
        };
        assert_eq!(v.constats.first().and_then(|c| c.geste.clone()), Some(g1.clone()));
        // Le pare-feu n'a pas de bouton : pas de geste.
        assert_eq!(v.constats.get(1).map(|c| c.geste.is_none()), Some(true));

        // Sans proposition, « Accepter » ne lance rien.
        a.accepter();
        assert!(a.en_cours().is_none());
        // Un geste absent de la liste (une empreinte que la fenêtre aurait inventée) n'ouvre rien.
        let mut faux = g1.clone();
        faux.changement.empreinte = crate::commandes::Empreinte::lire("ffffffffffffffffffffffffffffffff").unwrap();
        a.proposer(&faux);
        assert!(a.confirmation().is_none());
        // Remettre ce qui n'est pas proposé à remettre : rien non plus.
        let mut autre = g1.clone();
        autre.changement.sorte = Sorte::Remettre;
        a.proposer(&autre);
        assert!(a.confirmation().is_none());

        // Ouverte : une seule, et le reste attend.
        a.proposer(&g1);
        assert_eq!(a.confirmation(), Some(&g1));
        assert!(!a.changement_possible());
        a.proposer(&g1);
        assert_eq!(a.confirmation(), Some(&g1));
        // Annuler : rien de lancé.
        a.annuler();
        assert!(a.confirmation().is_none());
        assert!(a.en_cours().is_none());
        assert_eq!(changements(), "");

        // Une commande tourne : « Accepter » attend, la confirmation reste ouverte.
        a.proposer(&g1);
        a.demander(Commande::Bilan);
        a.accepter();
        assert_eq!(a.confirmation(), Some(&g1));
        finir_tout(&mut a);
        assert_eq!(changements(), "");

        // Accepté : un seul changement, de forme fermée ; Arrêter ne l'interrompt pas ; la fin dite, la liste relue.
        a.accepter();
        assert!(a.confirmation().is_none());
        assert_eq!(a.en_cours().map(|(c, _)| c), Some(Commande::Demarrage));
        assert!(!a.changement_possible());
        a.arreter();
        assert!(a.tache.as_ref().is_some_and(|t| !t.arret_demande()));
        finir_tout(&mut a);
        assert_eq!(changements(), format!("demarrage --retirer {e1} --json\n"));
        assert!(
            a.console
                .blocs()
                .any(|b| b.ton == Ton::Bon && b.resume.contains("retiré du démarrage"))
        );
        // La liste a été relue après le changement.
        let lancees: Vec<String> = a.console.blocs().map(console::Bloc::ligne_de_commande).collect();
        assert_eq!(
            lancees.iter().rev().take(2).map(String::as_str).collect::<Vec<_>>(),
            [
                "vanguard demarrage --json",
                &*format!("vanguard demarrage --retirer {e1} --json")
            ]
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une confirmation ouverte n'arrête pas la veille des alertes ; changer d'écran la ferme ; une liste relue qui
    /// n'a plus le geste la ferme ; « Accepter » revérifie le geste dans la dernière liste. Rien n'est lancé.
    #[cfg(unix)]
    #[test]
    fn une_confirmation_ne_bloque_rien_et_suit_la_liste() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = crate::essais::banc("confirmation");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let e1 = "0123456789abcdef0123456789abcdef";
        let avec = format!(
            r#"{{"outil": "PRO-DEM-001", "constats": [
            {{"categorie": "Démarrage", "etat": "sain", "message": "Lecteur — se lance · /usr/bin/lecteur",
              "objet": "demarrage:Lecteur",
              "geste": {{"sorte": "retirer", "empreinte": "{e1}", "nom": "Lecteur", "commande": "/usr/bin/lecteur"}}}}]}}"#
        );
        let sans = r#"{"outil": "PRO-DEM-001", "constats": []}"#;
        std::fs::write(d.join("liste.json"), &avec).unwrap();
        let script = d.join("vanguard");
        std::fs::write(&script, FAUX_DEMARRAGE).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let moi = std::fs::metadata(&d).unwrap().uid();
        let mut a = Appli::nouvelle(Ok(Programme::dans(&d, moi).unwrap()), std::sync::Arc::new(|| {}));
        finir_tout(&mut a);
        let changements = || std::fs::read_to_string(d.join("changements")).unwrap_or_default();
        let g1 = bilan::Geste {
            changement: Changement {
                sorte: Sorte::Retirer,
                empreinte: crate::commandes::Empreinte::lire(e1).unwrap(),
                accord: crate::commandes::Accord::NUL,
            },
            nom: "Lecteur".into(),
            commande: "/usr/bin/lecteur".into(),
            machine: false,
        };
        let lire_la_liste = |a: &mut Appli| {
            a.demander(Commande::Demarrage);
            finir_tout(a);
        };
        let dit = |a: &Appli, mot: &str| a.console.dit(mot);
        lire_la_liste(&mut a);

        // Le sondage repart pendant une confirmation ouverte ; « Accepter » attend sa fin, la confirmation reste.
        a.proposer(&g1);
        assert_eq!(a.confirmation(), Some(&g1));
        a.dernier_sondage = Instant::now().checked_sub(SONDAGE + Duration::from_secs(1)).unwrap();
        a.avancer();
        assert_eq!(a.en_cours().map(|(c, _)| c), Some(Commande::Evenements));
        a.accepter();
        assert_eq!(a.confirmation(), Some(&g1));
        // Une autre proposition dit la vraie raison.
        a.console.effacer();
        finir_tout(&mut a);
        a.proposer(&g1);
        assert!(dit(&a, "déjà ouverte") || dit(&a, "already open"));

        // Changer d'écran ferme la confirmation, sans rien lancer.
        a.aller(Ecran::Bilan);
        assert!(a.confirmation().is_none());
        assert!(dit(&a, "Annulé") || dit(&a, "Cancelled"));
        a.revenir();

        // La liste relue n'a plus le geste : la confirmation se ferme.
        a.proposer(&g1);
        assert_eq!(a.confirmation(), Some(&g1));
        std::fs::write(d.join("liste.json"), sans).unwrap();
        lire_la_liste(&mut a);
        assert!(a.confirmation().is_none());
        assert!(dit(&a, "La liste a changé") || dit(&a, "The list changed"));

        // « Accepter » revérifie : le geste parti de la dernière liste, rien ne se lance.
        std::fs::write(d.join("liste.json"), &avec).unwrap();
        lire_la_liste(&mut a);
        a.proposer(&g1);
        assert_eq!(a.confirmation(), Some(&g1));
        a.resultats.remove(&Commande::Demarrage);
        a.console.effacer();
        a.accepter();
        assert!(a.confirmation().is_none());
        assert!(a.en_cours().is_none());
        assert!(dit(&a, "La liste a changé") || dit(&a, "The list changed"));
        assert_eq!(changements(), "");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn une_nouvelle_alerte_est_dite() {
        let mut a = appli();
        // La ligne « programme absent » d'appli() est grave : seules celles d'après comptent ici.
        a.console.effacer();
        let fin = |sortie: &[u8]| Fin {
            lancement: Commande::Evenements.into(),
            code: Some(0),
            sortie: sortie.to_vec(),
            issue: Issue::Terminee,
            duree: Duration::ZERO,
        };
        a.finir(&fin(br#"{"etat": "intact", "evenements": []}"#));
        assert!(!a.console.lignes().any(|l| l.ton == Ton::Grave));
        a.finir(&fin(
            br#"{"etat": "intact", "evenements": [{"id": "b1", "quoi": {"sorte": "alerte", "titre": "Connexion suspecte"}}]}"#,
        ));
        assert!(
            a.console
                .lignes()
                .any(|l| l.ton == Ton::Grave && l.texte.contains("Connexion suspecte"))
        );
    }

    /// Laisse finir ce qui tourne (avec le programme des captures, chaque lancement échoue tout de suite).
    fn vider(a: &mut Appli) {
        let debut = Instant::now();
        while a.taches() > 0 && debut.elapsed() < Duration::from_secs(5) {
            a.avancer();
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(a.taches(), 0);
    }

    /// Les animations gardées par `vanguard` : relues à l'ouverture (dans la réponse des couleurs), puis un clic les
    /// change tout de suite et lance leur enregistrement, en mots fermés, dès que rien ne tourne ; un refus ou un
    /// échec le dit (pour cette fois seulement) sans défaire le choix, qu'une relecture ne défait pas non plus.
    #[test]
    fn les_animations_se_relisent_a_l_ouverture_et_s_enregistrent_par_vanguard() {
        let mut a = Appli::pour_captures();
        a.poser(Commande::Couleurs, br#"{"animations":"reduites"}"#);
        assert!(a.animations_reduites, "relues à l'ouverture");
        // Un `vanguard` d'avant ce réglage n'en dit rien : la fenêtre garde ce qu'elle a.
        a.poser(Commande::Couleurs, b"{}");
        assert!(a.animations_reduites);
        a.poser(Commande::Couleurs, br#"{"animations":"toutes"}"#);
        assert!(!a.animations_reduites);

        a.regler_animations(true);
        assert!(a.animations_reduites, "vaut tout de suite");
        // Même valeur : rien de plus à enregistrer.
        a.regler_animations(true);
        a.avancer();
        let lignes: Vec<_> = a.coulisses.passages().iter().map(|p| p.ligne.clone()).collect();
        assert_eq!(
            lignes.iter().filter(|l| l.contains("--animations")).collect::<Vec<_>>(),
            ["vanguard couleurs --animations reduites --json"]
        );
        vider(&mut a);
        let fin = |sortie: &[u8], code| Fin {
            lancement: Lancement::Animations(true),
            code: Some(code),
            sortie: sortie.to_vec(),
            issue: Issue::Terminee,
            duree: Duration::from_millis(5),
        };
        let refus = br#"{"geste":"animations","issue":"refuse","raison":"parametres.json a ete change hors de Vanguard","avant":null,"apres":null,"douteux":"hors_vanguard"}"#;
        a.finir(&fin(refus, 1));
        assert!(a.animations_reduites, "un refus ne défait pas le choix montré");
        // Relues ensuite (« toutes » : le fichier douteux) : le choix fait ici reste.
        a.poser(
            Commande::Couleurs,
            br#"{"animations":"toutes","douteux":"hors_vanguard"}"#,
        );
        assert!(a.animations_reduites);
        let fait =
            br#"{"geste":"animations","issue":"fait","raison":"","avant":"toutes","apres":"reduites","douteux":null}"#;
        a.finir(&fin(fait, 0));
        let console = format!("{:?}", a.console.entrees());
        assert!(console.contains("Refusé, pour cette fois seulement"), "{console}");
        assert!(console.contains("gardées pour les prochaines ouvertures"), "{console}");

        // Sans programme : rien ne peut s'enregistrer, et c'est dit.
        let mut sans = Appli::nouvelle(Err("vanguard introuvable".into()), std::sync::Arc::new(|| {}));
        sans.regler_animations(true);
        assert!(sans.animations_reduites);
        assert_eq!(sans.animations_a_garder, None);
        assert_eq!(sans.taches(), 0);
    }

    /// Chaque lancement fini ferme le bloc ouvert pour lui dans la console, réussi ou non : aucun ne reste « en
    /// cours » (les couleurs relues à l'ouverture y restaient, « lecture en cours… » pour toujours).
    #[test]
    fn chaque_lancement_fini_ferme_son_bloc_dans_la_console() {
        let couleurs = ChangementCouleurs {
            theme: Theme::Sombre,
            choix: None,
        };
        let mut lancements: Vec<Lancement> = Commande::TOUTES.iter().map(|&c| c.into()).collect();
        lancements.extend([Lancement::Couleurs(couleurs), Lancement::Animations(true)]);
        for l in lancements {
            for (code, sortie, issue) in [
                (Some(0), &b"{}"[..], Issue::Terminee),
                (Some(1), &b"illisible"[..], Issue::Terminee),
                (None, &b""[..], Issue::DelaiDepasse),
            ] {
                let mut a = Appli::pour_captures();
                a.console.commencer(l);
                let numero = a.console.en_cours().map(|b| b.numero).expect("bloc ouvert");
                a.finir(&Fin {
                    lancement: l,
                    code,
                    sortie: sortie.to_vec(),
                    issue,
                    duree: Duration::from_millis(7),
                });
                let bloc = a.console.blocs().find(|b| b.numero == numero).expect("bloc gardé");
                assert_ne!(bloc.etat, console::Etat::EnCours, "{l:?} {code:?} : resté en cours");
                assert!(!bloc.resume.is_empty(), "{l:?} {code:?} : sans résumé");
            }
        }
        // Les couleurs relues : lues, dit discrètement ; illisibles, un échec qui le dit.
        let mut a = Appli::pour_captures();
        a.console.commencer(Commande::Couleurs.into());
        a.poser(Commande::Couleurs, b"{}");
        let bloc = a.console.blocs().last().expect("bloc");
        assert_eq!((bloc.etat, bloc.ton), (console::Etat::Fini, Ton::Discret));
        a.console.commencer(Commande::Couleurs.into());
        a.poser(Commande::Couleurs, b"pas du json");
        let bloc = a.console.blocs().last().expect("bloc");
        assert_eq!(bloc.etat, console::Etat::Echec);
        assert!(bloc.resume.contains("illisibles"), "{}", bloc.resume);
    }

    /// Les couleurs : l'aperçu en direct sans rien écrire, jamais une couleur presque invisible, la confirmation
    /// avant tout lancement, des arguments exacts, puis « revenir à celles d'avant » qui remet exactement l'ancien ;
    /// un fichier douteux remet celles de Vanguard, dit dans la console et les coulisses.
    #[test]
    fn les_couleurs_se_proposent_s_enregistrent_par_vanguard_et_s_annulent() {
        use crate::couleurs::{Base, Vif};
        let cc = |choix| ChangementCouleurs {
            theme: Theme::Sombre,
            choix,
        };
        let mut a = Appli::pour_captures();
        a.poser(
            Commande::Couleurs,
            br#"{"sombre":null,"clair":null,"douteux":null,"systeme":null}"#,
        );
        let vanguard = Jeu::de(Theme::Sombre, None);
        assert_eq!(a.jeu(), vanguard);

        // Le brouillon se montre dans toute la fenêtre, sans rien lancer ; presque invisible, il ne se montre pas et
        // ne se propose pas.
        let braise = Choix::du_prereglage(Base::Braise, Theme::Sombre);
        a.brouillon = Some((Theme::Sombre, braise));
        assert_eq!(a.jeu(), Jeu::de(Theme::Sombre, Some(&braise)));
        let mut noir = braise;
        noir.poser(Vif::Accent, [0, 0, 0]);
        a.brouillon = Some((Theme::Sombre, noir));
        assert_eq!(a.jeu(), vanguard);
        a.proposer_couleurs(cc(Some(noir)));
        assert_eq!(a.confirmation_couleurs(), None);
        a.sombre = false;
        assert_eq!(
            a.jeu(),
            Jeu::de(Theme::Clair, None),
            "le brouillon d'un thème ne touche pas l'autre"
        );
        a.sombre = true;

        // Proposer n'ouvre que la confirmation ; « Accepter » lance exactement ces arguments.
        a.brouillon = Some((Theme::Sombre, braise));
        a.proposer_couleurs(cc(Some(braise)));
        assert_eq!(a.confirmation_couleurs(), Some((cc(Some(braise)), None)));
        assert_eq!(a.taches(), 0);
        a.accepter();
        assert_eq!(
            a.coulisses.passages().back().map(|p| p.ligne.as_str()),
            Some("vanguard couleurs --theme sombre --base braise --vifs f85c30,e94f97,ea900f,ddc33c,45b45e --json")
        );
        vider(&mut a);

        // Vanguard dit « fait » : la valeur d'avant devient le retour ; les couleurs montrées sont celles relues.
        let fait = br#"{"geste":"couleurs","issue":"fait","raison":"","theme":"sombre","avant":null,"apres":{"base":"braise","vifs":"f85c30,e94f97,ea900f,ddc33c,45b45e"}}"#;
        a.finir(&Fin {
            lancement: Lancement::Couleurs(cc(Some(braise))),
            code: Some(0),
            sortie: fait.to_vec(),
            issue: Issue::Terminee,
            duree: Duration::from_millis(5),
        });
        assert_eq!(a.revenir_couleurs(), Some(cc(None)));
        assert_eq!(a.brouillon, None);
        vider(&mut a);
        a.poser(
            Commande::Couleurs,
            br#"{"sombre":{"base":"braise","vifs":"f85c30,e94f97,ea900f,ddc33c,45b45e"}}"#,
        );
        assert_eq!(a.jeu(), Jeu::de(Theme::Sombre, Some(&braise)));
        a.proposer_couleurs(cc(None));
        assert_eq!(a.confirmation_couleurs(), Some((cc(None), Some(braise))));

        // Le fichier changé hors de Vanguard pendant la confirmation : celles de Vanguard, la confirmation fermée
        // (son « avant » n'est plus vrai), et la raison dite.
        a.poser(
            Commande::Couleurs,
            br#"{"sombre":null,"clair":null,"douteux":"hors_vanguard"}"#,
        );
        assert_eq!(a.jeu(), vanguard);
        assert_eq!(a.confirmation_couleurs(), None);
        assert!(
            a.coulisses
                .notes()
                .iter()
                .any(|n| n.sorte == crate::coulisses::Sorte::Avis && n.texte.contains("hors de Vanguard"))
        );
        assert!(
            a.console
                .lignes()
                .any(|l| l.ton == Ton::Attention && l.texte.contains("hors de Vanguard"))
        );
    }
}

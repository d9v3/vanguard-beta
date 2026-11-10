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

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::commandes::{self, Changement, ChangementCouleurs, Commande, Forme, Lancement, Rubrique, Saisie, Sorte};
use crate::console::{self, Console};
use crate::couleurs::{Choix, Jeu, Theme};
use crate::coulisses::{Chemin, Coulisses};
use crate::donnees::couleurs::{IssueCouleurs, Lues};
use crate::donnees::{appareils, bilan, evenements, libre, protection};
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
}

pub struct Appli {
    pub ecran: Ecran,
    /// Les écrans d'avant, le plus récent à la fin (« Retour », Alt+←, le bouton Précédent de la souris, Échap).
    retours: Vec<Ecran>,
    pub sombre: bool,
    /// « Réduire les animations » : plus de fondu d'écran, de chiffres qui montent, de pouls ni d'ouverture ; l'état
    /// final s'affiche tout de suite. Pour cette fois, comme le thème et la langue (rien n'est enregistré).
    pub animations_reduites: bool,
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
    pub fn revenir(&mut self) {
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
    pub fn en_cours(&self) -> Option<(Commande, Duration)> {
        self.tache.as_ref().map(|t| (t.lancement.commande(), t.debut.elapsed()))
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
            None => {}
        }
    }

    /// « Annuler » : ferme la confirmation, rien n'est lancé.
    pub fn annuler(&mut self) {
        if self.confirmation.take().is_some() {
            self.dire(
                "fenêtre",
                crate::tr!("Annulé : rien n'a changé.", "Cancelled: nothing changed."),
                Ton::Discret,
            );
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
                        let source = self
                            .tache
                            .as_ref()
                            .map_or("vanguard", |t| t.lancement.commande().nom_affiche());
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
            if let Some(c) = self.file.pop_front() {
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

    /// Les couleurs relues (`vanguard couleurs --json`) : elles valent pour la fenêtre dès l'image suivante. Une
    /// réponse illisible laisse les couleurs d'avant ; un fichier douteux est dit, dans la console et les coulisses.
    fn lire_couleurs(&mut self, f: &Fin) {
        let lues = match (&f.issue, f.code) {
            (Issue::Terminee, Some(0)) => crate::donnees::couleurs::lire(&f.sortie),
            _ => Err(crate::tr!("pas lues", "not read").to_string()),
        };
        match lues {
            Ok(l) => {
                if let Some(d) = l.doute
                    && self.couleurs.doute != Some(d)
                {
                    self.coulisses.avis(d.texte());
                    self.dire("couleurs", d.texte(), Ton::Attention);
                }
                self.couleurs = l;
                self.fermer_si_couleurs_changees();
            }
            Err(e) => {
                let texte = crate::trf!(
                    "Couleurs réglées illisibles ({}) : celles d'avant restent.",
                    "Saved colors unreadable ({}): the previous ones stay.",
                    e
                );
                self.coulisses.avis(&texte);
                self.dire("couleurs", &texte, Ton::Attention);
            }
        }
    }

    /// Un changement des couleurs a fini : son issue dans la console, puis les couleurs relues (seule source de ce
    /// qui est montré : jamais celles demandées, toujours celles que `vanguard` a gardées).
    fn finir_couleurs(&mut self, cc: ChangementCouleurs, f: &Fin) {
        let (texte, ton) = match crate::donnees::couleurs::lire_issue(cc, f) {
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
                )
            }
            IssueCouleurs::Refuse(r) => (
                crate::trf!("Refusé, rien n'a changé : {}", "Refused, nothing changed: {}", r),
                Ton::Attention,
            ),
            IssueCouleurs::Echec(r) => (crate::trf!("Échec : {}", "Failed: {}", r), Ton::Attention),
        };
        self.dire("couleurs", &texte, ton);
        self.demander(Commande::Couleurs);
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
        // Le relevé des corrections (`changements --json`) effacé, changé hors de Vanguard ou illisible : jamais lu
        // comme un historique ordinaire. Seuls « intact » et « absent » (rien encore) restent neutres.
        Contenu::Libre(v)
            if v.lignes
                .iter()
                .any(|l| l.retrait == 0 && l.cle == "releve" && !matches!(l.valeur.as_str(), "intact" | "absent")) =>
        {
            Ton::Attention
        }
        Contenu::Libre(_) => Ton::Normal,
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
            Contenu::Libre(libre::lire(format!(r#"{{"schema":1,"releve":"{etat}","total":0}}"#).as_bytes()).unwrap())
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

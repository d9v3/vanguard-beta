//! La console, sans rien dessiner : des lignes simples (ce que dit la fenêtre, une alerte nouvelle, l'aide) et un bloc
//! par commande lancée ou en attente. Un bloc garde son état (en attente, en cours, fini, échec), sa progression telle
//! que `vanguard` l'écrit, ses constats les plus graves, ce que `vanguard` a dit sur sa sortie des erreurs, sa durée et
//! son résumé. Tout est borné : les entrées, les blocs, ce que chaque bloc garde. Les filtres et la recherche se
//! calculent ici (essayés sans fenêtre) ; `dessin::console` ne fait que peindre les places rendues par `places`.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::appli::{Contenu, LigneConsole, Ton};
use crate::commandes::{Lancement, Rubrique};
use crate::donnees::bilan::{Gravite, Rang};
use crate::donnees::protection::Allure;
use crate::progression::Etape;

/// Entrées gardées (lignes et blocs).
pub const ENTREES_MAX: usize = 2000;
/// Blocs gardés : au-delà, le plus ancien fini part en entier.
pub const BLOCS_MAX: usize = 200;
/// Constats gardés par bloc, les plus graves (le nombre réel est gardé à part).
pub const POINTS_MAX: usize = 40;
/// Lignes de la sortie des erreurs gardées par bloc (les plus récentes).
pub const MESSAGES_MAX: usize = 200;
/// Ce qu'un bloc montre de son corps avant « + N autres ».
pub const MONTRES: usize = 3;

/// Où en est la commande d'un bloc.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Etat {
    EnAttente,
    EnCours,
    Fini,
    Echec,
}

/// La sorte d'un point du corps d'un bloc.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Marque {
    /// Un constat à corriger (sa gravité dit sa couleur).
    Corriger,
    /// Une vérification qui n'a pas pu se faire : jamais comptée comme saine.
    NonVerifie,
    Savoir,
    /// Une alerte du journal.
    Alerte,
    /// Un interrupteur de protection éteint.
    Eteint,
    /// Un appareil nouveau ou à risque.
    Appareil,
}

/// Un constat réel montré dans le bloc : gravité, sujet, message (nettoyés, sur une ligne).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Point {
    pub marque: Marque,
    pub gravite: Option<Gravite>,
    pub sujet: String,
    pub message: String,
}

impl Point {
    fn nouveau(marque: Marque, gravite: Option<Gravite>, sujet: &str, message: &str) -> Point {
        Point {
            marque,
            gravite,
            sujet: crate::nettoyage::nom(sujet, 40),
            message: crate::nettoyage::ligne(message),
        }
    }

    /// Le mot court devant le point.
    pub fn mot(&self) -> &'static str {
        match (self.marque, self.gravite) {
            (Marque::Corriger | Marque::Alerte, Some(g)) => g.nom(),
            (Marque::Corriger, None) => crate::tr!("à corriger", "to fix"),
            (Marque::Alerte, None) => crate::tr!("alerte", "alert"),
            (Marque::NonVerifie, _) => crate::tr!("pas vérifié", "not checked"),
            (Marque::Savoir, _) => crate::tr!("à savoir", "to know"),
            (Marque::Eteint, _) => crate::tr!("éteint", "off"),
            (Marque::Appareil, _) => crate::tr!("à voir", "to look at"),
        }
    }
}

/// Le bloc d'une commande.
#[derive(Clone, Debug)]
pub struct Bloc {
    pub numero: u64,
    /// L'heure locale de son arrivée dans la console.
    pub heure: String,
    pub lancement: Lancement,
    pub etat: Etat,
    /// Le début de la commande (absent tant qu'elle attend).
    pub debut: Option<Instant>,
    pub duree: Option<Duration>,
    /// Ce que la commande a rendu, en une phrase (vide tant qu'elle tourne).
    pub resume: String,
    pub ton: Ton,
    pub points: Vec<Point>,
    /// Les points en tout (les plus graves seulement sont gardés).
    pub total: usize,
    /// Ce que `vanguard` a dit sur sa sortie des erreurs, nettoyé (les plus récentes).
    pub messages: VecDeque<String>,
    /// La dernière étape lue (`progression::lire`).
    pub etape: Option<Etape>,
    /// Replié : l'en-tête seul.
    pub replie: bool,
    /// Tout le corps montré (sinon les `MONTRES` premiers).
    pub deplie: bool,
}

impl Bloc {
    /// `vanguard <arguments>` : la commande exacte, telle qu'elle est lancée.
    pub fn ligne_de_commande(&self) -> String {
        format!("vanguard {}", self.lancement.arguments().join(" "))
    }

    /// Les éléments du corps : les points, puis les messages.
    pub fn elements(&self) -> usize {
        self.points.len().saturating_add(self.messages.len())
    }

    /// Ce qui n'est pas montré quand le bloc n'est pas déplié : les points et messages au-delà des premiers, plus
    /// les points que le bloc n'a pas gardés.
    pub fn autres(&self) -> usize {
        self.elements()
            .saturating_sub(MONTRES)
            .saturating_add(self.total.saturating_sub(self.points.len()))
    }

    pub fn actif(&self) -> bool {
        matches!(self.etat, Etat::EnAttente | Etat::EnCours)
    }

    /// Le bloc en texte, pour « Copier » : l'en-tête, puis chaque point et chaque message.
    pub fn texte(&self) -> String {
        use std::fmt::Write as _;
        // Écrire dans une String ne peut pas échouer : le résultat de `write!` est ignoré sans risque.
        let mut t = format!("{} {}", self.heure, self.ligne_de_commande());
        if let Some(d) = self.duree {
            let _ = write!(t, " · {}", crate::langue::secondes(d.as_secs_f32()));
        }
        if !self.resume.is_empty() {
            let _ = write!(t, " · {}", self.resume);
        }
        for p in &self.points {
            let _ = write!(t, "\n  [{}] {} — {}", p.mot(), p.sujet, p.message);
        }
        if self.total > self.points.len() {
            t.push_str(&crate::trf!(
                "\n  (+ {} autres, voir l'écran)",
                "\n  (+ {} more, see the screen)",
                self.total - self.points.len()
            ));
        }
        for m in &self.messages {
            let _ = write!(t, "\n  {m}");
        }
        t
    }

    /// Le bloc contient-il `cherche` (déjà en minuscules) ?
    fn contient(&self, cherche: &str) -> bool {
        let a = |s: &str| s.to_lowercase().contains(cherche);
        a(&self.ligne_de_commande())
            || a(&self.resume)
            || a(self.lancement.commande().nom_affiche())
            || self.points.iter().any(|p| a(&p.sujet) || a(&p.message))
            || self.messages.iter().any(|m| a(m))
    }
}

/// Une entrée de la console.
#[derive(Clone, Debug)]
pub enum Entree {
    Ligne(LigneConsole),
    Bloc(Bloc),
}

impl Entree {
    pub fn numero(&self) -> u64 {
        match self {
            Entree::Ligne(l) => l.numero,
            Entree::Bloc(b) => b.numero,
        }
    }

    fn active(&self) -> bool {
        matches!(self, Entree::Bloc(b) if b.actif())
    }
}

/// Les filtres de la console.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Filtre {
    #[default]
    Tout,
    /// Ce qui demande un regard : un bloc à corriger, en échec ou qui n'a pas tout pu vérifier, une ligne en
    /// attention ou grave.
    Problemes,
    /// Les commandes qui lisent cet ordinateur (tout sauf le réseau).
    CePc,
    /// Les commandes du réseau.
    Reseau,
}

impl Filtre {
    pub const TOUS: [Filtre; 4] = [Filtre::Tout, Filtre::Problemes, Filtre::CePc, Filtre::Reseau];

    pub fn nom(self) -> &'static str {
        match self {
            Filtre::Tout => crate::tr!("Tout", "All"),
            Filtre::Problemes => crate::tr!("Problèmes", "Problems"),
            Filtre::CePc => crate::tr!("Ce PC", "This PC"),
            Filtre::Reseau => crate::tr!("Réseau", "Network"),
        }
    }

    fn garde(self, e: &Entree) -> bool {
        let probleme = |t: Ton| matches!(t, Ton::Attention | Ton::Grave);
        match (self, e) {
            (Filtre::Tout, _) => true,
            (Filtre::Problemes, Entree::Ligne(l)) => probleme(l.ton),
            (Filtre::Problemes, Entree::Bloc(b)) => b.etat == Etat::Echec || probleme(b.ton),
            // Les lignes de la fenêtre ne sont ni de ce PC ni du réseau : seulement dans « Tout » et « Problèmes ».
            (Filtre::CePc | Filtre::Reseau, Entree::Ligne(_)) => false,
            (Filtre::CePc, Entree::Bloc(b)) => b.lancement.commande().rubrique() != Rubrique::Reseau,
            (Filtre::Reseau, Entree::Bloc(b)) => b.lancement.commande().rubrique() == Rubrique::Reseau,
        }
    }
}

/// Une place de la console : une rangée de hauteur fixe, d'une entrée (son indice dans `entrees`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Place {
    Ligne(usize),
    /// L'en-tête d'un bloc.
    Tete(usize),
    /// La progression d'un bloc en cours.
    Etape(usize),
    /// Le k-ième point du bloc.
    Point(usize, usize),
    /// Le k-ième message du bloc.
    Message(usize, usize),
    /// « + N autres » (ou « Replier » quand le bloc est déplié).
    Autres(usize),
    /// Les suites du bloc : Voir dans l'écran, Relancer, Copier.
    Suites(usize),
}

impl Place {
    pub fn entree(self) -> usize {
        match self {
            Place::Ligne(i)
            | Place::Tete(i)
            | Place::Etape(i)
            | Place::Point(i, _)
            | Place::Message(i, _)
            | Place::Autres(i)
            | Place::Suites(i) => i,
        }
    }
}

/// La console : ses entrées, dans l'ordre d'arrivée.
#[derive(Default)]
pub struct Console {
    entrees: VecDeque<Entree>,
    /// Le numéro de la prochaine entrée : croissant, jamais réutilisé (même après « effacer »).
    suivante: u64,
    blocs: usize,
}

impl Console {
    pub fn nouvelle() -> Console {
        Console {
            entrees: VecDeque::new(),
            suivante: 1,
            blocs: 0,
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entrees.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entrees.is_empty()
    }

    #[cfg(test)]
    pub fn entrees(&self) -> &VecDeque<Entree> {
        &self.entrees
    }

    pub fn get(&self, i: usize) -> Option<&Entree> {
        self.entrees.get(i)
    }

    #[cfg(test)]
    /// Les lignes simples (sans les blocs).
    pub fn lignes(&self) -> impl Iterator<Item = &LigneConsole> {
        self.entrees.iter().filter_map(|e| match e {
            Entree::Ligne(l) => Some(l),
            Entree::Bloc(_) => None,
        })
    }

    #[cfg(test)]
    pub fn blocs(&self) -> impl Iterator<Item = &Bloc> {
        self.entrees.iter().filter_map(|e| match e {
            Entree::Bloc(b) => Some(b),
            Entree::Ligne(_) => None,
        })
    }

    #[cfg(test)]
    /// Une ligne ou un bloc dit-il `mot` ?
    pub fn dit(&self, mot: &str) -> bool {
        self.lignes().any(|l| l.texte.contains(mot))
            || self
                .blocs()
                .any(|b| b.resume.contains(mot) || b.messages.iter().any(|m| m.contains(mot)))
    }

    /// Vide la console, sauf les blocs en cours et en attente (leur fin s'y écrira).
    pub fn effacer(&mut self) {
        self.entrees.retain(Entree::active);
        self.blocs = self.entrees.len();
    }

    /// Ajoute une entrée, la plus ancienne finie partant quand la borne est atteinte.
    fn pousser(&mut self, faire: impl FnOnce(u64, String) -> Entree) -> u64 {
        let numero = self.suivante;
        self.suivante = self.suivante.saturating_add(1);
        let e = faire(numero, crate::temps::heure_locale());
        let bloc = matches!(e, Entree::Bloc(_));
        while self.entrees.len() >= ENTREES_MAX || (bloc && self.blocs >= BLOCS_MAX) {
            // La plus ancienne qui n'est pas active (pour un bloc de trop : le plus ancien bloc fini).
            let Some(i) = self
                .entrees
                .iter()
                .position(|x| !x.active() && (self.entrees.len() >= ENTREES_MAX || matches!(x, Entree::Bloc(_))))
            else {
                break;
            };
            if let Some(Entree::Bloc(_)) = self.entrees.remove(i) {
                self.blocs = self.blocs.saturating_sub(1);
            }
        }
        if bloc {
            self.blocs = self.blocs.saturating_add(1);
        }
        self.entrees.push_back(e);
        numero
    }

    /// Une ligne simple (nettoyée).
    pub fn dire(&mut self, source: &str, texte: &str, ton: Ton) {
        self.pousser(|numero, heure| {
            Entree::Ligne(LigneConsole {
                numero,
                heure,
                source: crate::nettoyage::nom(source, 12),
                texte: crate::nettoyage::ligne(texte),
                ton,
            })
        });
    }

    fn bloc_mut(&mut self, cherche: impl Fn(&Bloc) -> bool) -> Option<&mut Bloc> {
        self.entrees.iter_mut().rev().find_map(|e| match e {
            Entree::Bloc(b) if cherche(b) => Some(b),
            _ => None,
        })
    }

    #[cfg(test)]
    /// Le bloc en cours.
    pub fn en_cours(&self) -> Option<&Bloc> {
        self.blocs().find(|b| b.etat == Etat::EnCours)
    }

    /// Un bloc « en attente », pour une commande mise en file.
    pub fn attendre(&mut self, l: Lancement) {
        self.pousser(|numero, heure| Entree::Bloc(Bloc::nouveau(numero, heure, l, Etat::EnAttente)));
    }

    /// Retire le bloc en attente de `l` (✕, ou « Arrêter » qui vide la file).
    pub fn retirer(&mut self, l: Lancement) {
        let avant = self.entrees.len();
        self.entrees
            .retain(|e| !matches!(e, Entree::Bloc(b) if b.etat == Etat::EnAttente && b.lancement == l));
        self.blocs = self.blocs.saturating_sub(avant - self.entrees.len());
    }

    /// La commande `l` commence : son bloc en attente passe en cours (ou un bloc nouveau), et les blocs finis
    /// d'avant se replient.
    pub fn commencer(&mut self, l: Lancement) {
        for e in &mut self.entrees {
            if let Entree::Bloc(b) = e
                && !b.actif()
            {
                b.replie = true;
            }
        }
        let attendu = self
            .entrees
            .iter()
            .position(|e| matches!(e, Entree::Bloc(b) if b.etat == Etat::EnAttente && b.lancement == l));
        // Un bloc en attente remonte à la fin : la console se lit dans l'ordre où les commandes ont tourné.
        let bloc = match attendu.and_then(|i| self.entrees.remove(i)) {
            Some(Entree::Bloc(mut b)) => {
                self.blocs = self.blocs.saturating_sub(1);
                b.heure = crate::temps::heure_locale();
                Some(b)
            }
            _ => None,
        };
        self.pousser(|numero, heure| {
            let mut b = bloc.unwrap_or_else(|| Bloc::nouveau(numero, heure.clone(), l, Etat::EnCours));
            b.numero = numero;
            b.heure = heure;
            b.etat = Etat::EnCours;
            b.debut = Some(Instant::now());
            Entree::Bloc(b)
        });
    }

    /// Une ligne de la sortie des erreurs de la commande en cours : une étape, ou un message gardé dans son bloc.
    /// Rend faux si aucun bloc ne tourne.
    pub fn recevoir(&mut self, ligne: &str) -> bool {
        let Some(b) = self.bloc_mut(|b| b.etat == Etat::EnCours) else {
            return false;
        };
        if let Some(e) = crate::progression::lire(ligne) {
            b.etape = Some(e);
        } else {
            if b.messages.len() >= MESSAGES_MAX {
                b.messages.pop_front();
            }
            b.messages.push_back(crate::nettoyage::ligne(ligne));
        }
        true
    }

    /// La fin de la commande en cours : son résumé, ses points, sa durée. Sans bloc en cours (effacé entre-temps,
    /// ce qui ne devrait pas arriver), un bloc fini est ajouté.
    pub fn finir(&mut self, l: Lancement, fin: Fini) {
        if self.bloc_mut(|b| b.etat == Etat::EnCours && b.lancement == l).is_none() {
            self.pousser(|numero, heure| Entree::Bloc(Bloc::nouveau(numero, heure, l, Etat::EnCours)));
        }
        if let Some(b) = self.bloc_mut(|b| b.etat == Etat::EnCours && b.lancement == l) {
            b.etat = if fin.echec { Etat::Echec } else { Etat::Fini };
            b.duree = Some(fin.duree);
            b.resume = crate::nettoyage::ligne(&fin.resume);
            b.ton = fin.ton;
            b.total = fin.points.len();
            b.points = fin.points;
            b.points.truncate(POINTS_MAX);
            b.etape = None;
        }
    }

    /// Replie ou déplie un bloc (son en-tête cliqué).
    pub fn basculer(&mut self, numero: u64) {
        if let Some(b) = self.bloc_mut(|b| b.numero == numero) {
            b.replie = !b.replie;
        }
    }

    /// Montre tout le corps d'un bloc, ou seulement ses premiers éléments.
    pub fn deplier(&mut self, numero: u64) {
        if let Some(b) = self.bloc_mut(|b| b.numero == numero) {
            b.deplie = !b.deplie;
            b.replie = false;
        }
    }

    /// Les places à montrer, dans l'ordre, pour un filtre et une recherche (vide : aucune). Pendant une recherche,
    /// les blocs trouvés se montrent dépliés.
    pub fn places(&self, filtre: Filtre, cherche: &str) -> Vec<Place> {
        let cherche = cherche.trim().to_lowercase();
        let mut v = Vec::new();
        for (i, e) in self.entrees.iter().enumerate() {
            if !filtre.garde(e) {
                continue;
            }
            match e {
                Entree::Ligne(l) => {
                    if cherche.is_empty()
                        || l.texte.to_lowercase().contains(&cherche)
                        || l.source.to_lowercase().contains(&cherche)
                    {
                        v.push(Place::Ligne(i));
                    }
                }
                Entree::Bloc(b) => {
                    if !cherche.is_empty() && !b.contient(&cherche) {
                        continue;
                    }
                    v.push(Place::Tete(i));
                    if b.etat == Etat::EnAttente || (b.replie && cherche.is_empty()) {
                        continue;
                    }
                    if b.etat == Etat::EnCours {
                        v.push(Place::Etape(i));
                    }
                    // Une recherche : seulement les points et messages qui la contiennent (tous, si elle ne se
                    // trouve que dans l'en-tête).
                    if !cherche.is_empty() {
                        let a = |t: &str| t.to_lowercase().contains(&cherche);
                        let points = b
                            .points
                            .iter()
                            .enumerate()
                            .filter(|(_, p)| a(&p.sujet) || a(&p.message));
                        let points: Vec<Place> = points.map(|(k, _)| Place::Point(i, k)).collect();
                        let messages = b.messages.iter().enumerate().filter(|(_, m)| a(m));
                        let messages: Vec<Place> = messages.map(|(k, _)| Place::Message(i, k)).collect();
                        if !points.is_empty() || !messages.is_empty() {
                            v.extend(points);
                            v.extend(messages);
                            if b.etat != Etat::EnCours {
                                v.push(Place::Suites(i));
                            }
                            continue;
                        }
                    }
                    let tout = b.deplie || !cherche.is_empty();
                    let montres = if tout { usize::MAX } else { MONTRES };
                    let n_points = b.points.len().min(montres);
                    v.extend((0..n_points).map(|k| Place::Point(i, k)));
                    // Pendant qu'il tourne, les derniers messages ; fini, les premiers après les points.
                    let reste = montres.saturating_sub(n_points);
                    let n = b.messages.len();
                    if b.etat == Etat::EnCours && !tout {
                        v.extend((n.saturating_sub(reste)..n).map(|k| Place::Message(i, k)));
                    } else {
                        v.extend((0..n.min(reste)).map(|k| Place::Message(i, k)));
                    }
                    if b.etat != Etat::EnCours && (b.autres() > 0 || b.deplie) && cherche.is_empty() {
                        v.push(Place::Autres(i));
                    }
                    if b.etat != Etat::EnCours {
                        v.push(Place::Suites(i));
                    }
                }
            }
        }
        v
    }
}

impl Bloc {
    fn nouveau(numero: u64, heure: String, lancement: Lancement, etat: Etat) -> Bloc {
        Bloc {
            numero,
            heure,
            lancement,
            etat,
            debut: None,
            duree: None,
            resume: String::new(),
            ton: Ton::Commande,
            points: Vec::new(),
            total: 0,
            messages: VecDeque::new(),
            etape: None,
            replie: false,
            deplie: false,
        }
    }
}

/// La fin d'une commande, pour son bloc.
pub struct Fini {
    pub resume: String,
    pub ton: Ton,
    pub points: Vec<Point>,
    pub duree: Duration,
    pub echec: bool,
}

/// Les constats réels d'un résultat, les plus graves d'abord : à corriger (par gravité), pas pu vérifier, bon à
/// savoir ; les alertes du journal ; les interrupteurs éteints ; les appareils nouveaux ou à risque.
pub fn points(contenu: &Contenu) -> Vec<Point> {
    match contenu {
        Contenu::Constats(v) => {
            let mut p: Vec<Point> = Vec::new();
            for (rang, marque) in [
                (Rang::Corriger, Marque::Corriger),
                (Rang::NonVerifie, Marque::NonVerifie),
                (Rang::Savoir, Marque::Savoir),
            ] {
                p.extend(
                    v.de_rang(rang)
                        .into_iter()
                        .map(|c| Point::nouveau(marque, c.gravite, &c.categorie, &c.message)),
                );
            }
            p
        }
        Contenu::Evenements(v) => {
            // Les plus graves d'abord, les plus récentes d'abord à gravité égale (le journal vient du plus récent).
            let mut a: Vec<_> = v.alertes().collect();
            a.sort_by_key(|e| std::cmp::Reverse(e.gravite));
            a.into_iter()
                .map(|e| Point::nouveau(Marque::Alerte, e.gravite, &e.source, &e.titre))
                .collect()
        }
        Contenu::Protection(v) => v
            .interrupteurs
            .iter()
            .filter(|i| i.allure == Allure::Eteint)
            .map(|i| Point::nouveau(Marque::Eteint, None, &i.nom, &i.etat))
            .collect(),
        Contenu::Appareils(v) => v
            .appareils
            .iter()
            .filter(|a| a.nouveau || a.a_risque())
            .map(|a| {
                let quoi = if a.a_risque() {
                    crate::tr!("à risque", "at risk")
                } else {
                    crate::tr!("nouveau sur le réseau", "new on the network")
                };
                Point::nouveau(Marque::Appareil, None, &a.ip, &format!("{} — {quoi}", a.titre))
            })
            .collect(),
        Contenu::Libre(_) | Contenu::Erreur(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commandes::Commande;

    fn fini(resume: &str, ton: Ton, n: usize) -> Fini {
        Fini {
            resume: resume.into(),
            ton,
            points: (0..n)
                .map(|k| Point::nouveau(Marque::Corriger, Some(Gravite::Moyenne), "SSH", &format!("point {k}")))
                .collect(),
            duree: Duration::from_millis(2100),
            echec: false,
        }
    }

    /// Un bloc par commande : en attente, puis en cours (il remonte à la fin), ses étapes et messages, puis fini avec
    /// ses trois points les plus graves et « + N autres » ; le bloc d'avant se replie quand un autre commence.
    #[test]
    fn un_bloc_suit_sa_commande() {
        let mut c = Console::nouvelle();
        let bilan: Lancement = Commande::Bilan.into();
        let prot: Lancement = Commande::Protection.into();
        c.commencer(prot);
        c.attendre(bilan);
        assert!(c.recevoir("@etape 1/2 Pare-feu"));
        assert_eq!(c.en_cours().and_then(|b| b.etape.clone()).map(|e| e.fait), Some(1));
        c.finir(prot, fini("4 interrupteurs lus", Ton::Bon, 0));
        c.dire("fenêtre", "entre les deux", Ton::Discret);
        c.commencer(bilan);
        assert!(c.recevoir("avertissement : lent"));
        assert!(c.recevoir("@etape 3/9 Comptes"));
        let b = c.en_cours().unwrap();
        assert_eq!(b.lancement, bilan);
        assert_eq!(b.messages, ["avertissement : lent"]);
        // Le bloc du bilan est passé après la ligne de la fenêtre ; celui de la protection s'est replié.
        assert!(matches!(c.get(2), Some(Entree::Bloc(b)) if b.lancement == bilan));
        assert!(matches!(c.get(0), Some(Entree::Bloc(b)) if b.replie));
        c.finir(bilan, fini("9 vérifications", Ton::Attention, 5));
        let p = c.places(Filtre::Tout, "");
        assert_eq!(
            p,
            [
                Place::Tete(0),
                Place::Ligne(1),
                Place::Tete(2),
                Place::Point(2, 0),
                Place::Point(2, 1),
                Place::Point(2, 2),
                Place::Autres(2),
                Place::Suites(2),
            ]
        );
        let Some(Entree::Bloc(b)) = c.get(2) else { panic!() };
        assert_eq!((b.etat, b.autres()), (Etat::Fini, 3));
        assert!(b.texte().contains("[moyen] SSH — point 4") && b.texte().contains("avertissement"));
        let n = b.numero;
        c.deplier(n);
        // Les deux têtes et la ligne, les cinq points, le message, « replier » et les suites.
        assert_eq!(c.places(Filtre::Tout, "").len(), 3 + 5 + 1 + 1 + 1);
        c.basculer(n);
        assert_eq!(
            c.places(Filtre::Tout, ""),
            [Place::Tete(0), Place::Ligne(1), Place::Tete(2)]
        );
    }

    /// Une ligne qui ressemble à une étape sans en avoir la forme exacte reste un message ; sans bloc en cours, rien
    /// n'est reçu.
    #[test]
    fn seule_une_etape_exacte_fait_avancer() {
        let mut c = Console::nouvelle();
        assert!(!c.recevoir("@etape 1/2 x"));
        c.commencer(Commande::Bilan.into());
        for l in ["@etape 3/2 trop", "@etape 1/2\u{1b}[31m", "@ETAPE 1/2"] {
            c.recevoir(l);
        }
        let b = c.en_cours().unwrap();
        assert_eq!(b.etape, None);
        assert_eq!(b.messages.len(), 3);
        assert!(b.messages.iter().all(|m| !m.contains('\u{1b}')));
    }

    /// Les filtres : les problèmes, ce PC, le réseau ; la recherche trouve dans les points et ne montre qu'eux.
    #[test]
    fn les_filtres_et_la_recherche() {
        let mut c = Console::nouvelle();
        c.dire("fenêtre", "Prête.", Ton::Discret);
        c.dire("alerte", "Nouvelle alerte : Connexion suspecte", Ton::Grave);
        for (cmd, ton, n) in [
            (Commande::Protection, Ton::Bon, 0),
            (Commande::Appareils, Ton::Attention, 1),
            (Commande::Bilan, Ton::Attention, 4),
        ] {
            c.commencer(cmd.into());
            c.finir(cmd.into(), fini("x", ton, n));
        }
        let tetes = |f: Filtre, q: &str| {
            c.places(f, q)
                .into_iter()
                .filter(|p| matches!(p, Place::Tete(_) | Place::Ligne(_)))
                .map(Place::entree)
                .collect::<Vec<_>>()
        };
        assert_eq!(tetes(Filtre::Tout, ""), [0, 1, 2, 3, 4]);
        assert_eq!(tetes(Filtre::Problemes, ""), [1, 3, 4]);
        assert_eq!(tetes(Filtre::CePc, ""), [2, 4]);
        assert_eq!(tetes(Filtre::Reseau, ""), [3]);
        assert_eq!(tetes(Filtre::Tout, "POINT 3"), [4]);
        assert_eq!(tetes(Filtre::Tout, "suspecte"), [1]);
        // Seulement le point trouvé, puis les suites ; un mot de l'en-tête seul montre tous les points.
        assert_eq!(
            c.places(Filtre::Tout, "point 3"),
            [Place::Tete(4), Place::Point(4, 3), Place::Suites(4)]
        );
        assert_eq!(c.places(Filtre::Tout, "audit").len(), 1 + 4 + 1);
        assert_eq!(tetes(Filtre::Reseau, "point 3"), Vec::<usize>::new());
    }

    /// Bornée : en entrées, en blocs, en points et en messages par bloc ; un bloc actif ne part jamais ; « effacer »
    /// garde les blocs actifs ; les numéros ne reviennent jamais.
    #[test]
    fn la_console_est_bornee() {
        let mut c = Console::nouvelle();
        c.commencer(Commande::Bilan.into());
        for k in 0..(ENTREES_MAX + 10) {
            c.dire("x", &k.to_string(), Ton::Normal);
        }
        assert_eq!(c.len(), ENTREES_MAX);
        assert!(c.en_cours().is_some(), "le bloc en cours est parti");
        for _ in 0..(MESSAGES_MAX + 5) {
            c.recevoir("message");
        }
        assert_eq!(c.en_cours().map(|b| b.messages.len()), Some(MESSAGES_MAX));
        c.finir(Commande::Bilan.into(), fini("x", Ton::Attention, POINTS_MAX + 7));
        let b = c.blocs().next().unwrap();
        assert_eq!((b.points.len(), b.total), (POINTS_MAX, POINTS_MAX + 7));
        for _ in 0..(BLOCS_MAX + 5) {
            c.commencer(Commande::Protection.into());
            c.finir(Commande::Protection.into(), fini("x", Ton::Bon, 0));
        }
        assert_eq!(c.blocs().count(), BLOCS_MAX);
        assert!(c.len() <= ENTREES_MAX);
        let numeros: Vec<u64> = c.entrees().iter().map(Entree::numero).collect();
        assert!(numeros.windows(2).all(|w| w[0] < w[1]));
        c.attendre(Commande::Bilan.into());
        let dernier = *numeros.last().unwrap();
        c.effacer();
        assert_eq!(c.len(), 1);
        c.dire("x", "y", Ton::Normal);
        assert!(c.entrees().iter().all(|e| e.numero() > dernier));
    }

    /// Le corps d'un bloc vient des vrais constats, les plus graves d'abord, nettoyés.
    #[test]
    fn les_points_sont_les_constats_les_plus_graves() {
        let json = r#"{"constats": [
            {"categorie": "Comptes", "probleme": "Info", "message": "Sans expiration.", "verifie": true, "etat": "probleme"},
            {"categorie": "Chiffrement", "message": "Illisible.", "verifie": false, "etat": "non-verifie"},
            {"categorie": "SSH!", "probleme": "Critique", "message": "Root permis.", "verifie": true, "etat": "probleme"},
            {"categorie": "Pare-feu", "message": "Actif.", "verifie": true, "etat": "sain"}
        ]}"#
        .replace("SSH!", "SSH\u{202e}");
        let v = crate::donnees::bilan::lire(json.as_bytes()).unwrap();
        let p = points(&Contenu::Constats(v));
        let ordre: Vec<(Marque, Option<Gravite>)> = p.iter().map(|p| (p.marque, p.gravite)).collect();
        assert_eq!(
            ordre,
            [
                (Marque::Corriger, Some(Gravite::Critique)),
                (Marque::NonVerifie, None),
                (Marque::Savoir, Some(Gravite::Info))
            ]
        );
        assert!(!p.iter().any(|p| p.sujet.contains('\u{202e}')));
    }
}

//! L'état de la fenêtre, sans rien dessiner : l'écran montré, la tâche en cours et sa file d'attente, la console,
//! les derniers résultats. Les écrans (`dessin`) lisent cet état et ne demandent que des gestes d'ici (`demander`,
//! `arreter`, `saisir`) ; aucun ne lance un programme lui-même. Une seule commande tourne à la fois.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::commandes::{self, Commande, Forme, Rubrique, Saisie};
use crate::donnees::{bilan, evenements, libre, protection};
use crate::lanceur::{Fin, Issue, Message, Programme, Reveil, Tache};

/// Lignes gardées dans la console.
const CONSOLE_MAX: usize = 500;
/// Saisies gardées pour ↑.
const HISTORIQUE_MAX: usize = 50;
/// Commandes en attente au plus.
const FILE_MAX: usize = 8;
/// Le journal est relu à ce rythme, quand rien ne tourne, pour dire une alerte nouvelle dans la console.
pub const SONDAGE: Duration = Duration::from_secs(60);

/// L'écran montré.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ecran {
    Accueil,
    Bilan,
    Alertes,
    /// Pas encore dans la fenêtre (le scan du réseau) : un écran le dit.
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
}

pub struct Appli {
    pub ecran: Ecran,
    pub sombre: bool,
    programme: Result<Programme, String>,
    tache: Option<Tache>,
    file: VecDeque<Commande>,
    pub console: VecDeque<LigneConsole>,
    pub saisie: String,
    historique: Vec<String>,
    /// Position dans l'historique pendant ↑ / ↓ (None : la saisie en cours).
    rappel: Option<usize>,
    resultats: HashMap<Commande, Resultat>,
    /// Le dernier journal lu, pour reconnaître une alerte nouvelle.
    journal: Option<evenements::Vue>,
    dernier_sondage: Instant,
    reveil: Reveil,
}

impl Appli {
    pub fn nouvelle(programme: Result<Programme, String>, reveil: Reveil) -> Appli {
        let mut a = Appli {
            ecran: Ecran::Accueil,
            sombre: true,
            programme,
            tache: None,
            file: VecDeque::new(),
            console: VecDeque::new(),
            saisie: String::new(),
            historique: Vec::new(),
            rappel: None,
            resultats: HashMap::new(),
            journal: None,
            dernier_sondage: Instant::now(),
            reveil,
        };
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
                // Au lancement : l'état de la protection, le journal, puis le bilan (quelques secondes).
                for c in [Commande::Protection, Commande::Evenements, Commande::Bilan] {
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

    /// Ajoute une ligne à la console (nettoyée).
    pub fn dire(&mut self, source: &str, texte: &str, ton: Ton) {
        if self.console.len() >= CONSOLE_MAX {
            self.console.pop_front();
        }
        self.console.push_back(LigneConsole {
            heure: crate::temps::heure_locale(),
            source: crate::nettoyage::nom(source, 12),
            texte: crate::nettoyage::ligne(texte),
            ton,
        });
    }

    pub fn programme_trouve(&self) -> bool {
        self.programme.is_ok()
    }

    /// Demande une commande : lancée tout de suite si rien ne tourne, sinon mise en file (une seule fois).
    pub fn demander(&mut self, c: Commande) {
        if self.programme.is_err() {
            let e = self.programme.as_ref().err().cloned().unwrap_or_default();
            self.dire("fenêtre", &e, Ton::Grave);
            return;
        }
        if self.tache.as_ref().is_some_and(|t| t.commande == c) || self.file.contains(&c) {
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
            self.dire(
                "fenêtre",
                &crate::trf!("{} : en attente", "{}: queued", c.nom_affiche()),
                Ton::Discret,
            );
            return;
        }
        self.lancer(c);
    }

    fn lancer(&mut self, c: Commande) {
        let Ok(p) = &self.programme else {
            return;
        };
        let tache = Tache::lancer(p, c, crate::langue::anglais(), &self.reveil);
        self.tache = Some(tache);
        self.dire(
            "vanguard",
            &format!("vanguard {}", c.arguments().join(" ")),
            Ton::Commande,
        );
    }

    /// Arrête la commande en cours et vide la file.
    pub fn arreter(&mut self) {
        self.file.clear();
        if let Some(t) = &self.tache
            && !t.arret_demande()
        {
            t.arreter();
            self.dire("fenêtre", crate::tr!("Arrêt demandé…", "Stopping…"), Ton::Attention);
        }
    }

    /// La commande en cours et depuis quand.
    pub fn en_cours(&self) -> Option<(Commande, Duration)> {
        self.tache.as_ref().map(|t| (t.commande, t.debut.elapsed()))
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
                    let source = self.tache.as_ref().map_or("vanguard", |t| t.commande.nom_affiche());
                    self.dire(source, &l, Ton::Discret);
                }
                Message::Fin(f) => {
                    self.tache = None;
                    self.finir(&f);
                }
            }
        }
        if self.tache.is_none() {
            if let Some(c) = self.file.pop_front() {
                self.lancer(c);
            } else if self.programme.is_ok() && self.dernier_sondage.elapsed() >= SONDAGE {
                self.dernier_sondage = Instant::now();
                self.lancer(Commande::Evenements);
            }
        }
    }

    fn finir(&mut self, f: &Fin) {
        let c = f.commande;
        let secondes = f.duree.as_secs_f32();
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
                crate::trf!("{} interrupteur(s) lus", "{} switch(es) read", v.interrupteurs.len())
            }
            Contenu::Evenements(v) => format!(
                "{} · {}",
                v.etat.phrase(),
                crate::trf!("{} alerte(s)", "{} alert(s)", v.alertes().count())
            ),
            Contenu::Libre(v) => crate::trf!("{} valeur(s)", "{} value(s)", v.lignes.len()),
        };
        self.dire(c.nom_affiche(), &format!("{texte} ({secondes:.1} s)"), ton(&contenu));
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
            Saisie::Effacer => self.console.clear(),
            Saisie::Aide => {
                self.dire(
                    "aide",
                    crate::tr!("Commandes permises ici :", "Commands allowed here:"),
                    Ton::Normal,
                );
                for c in Commande::TOUTES {
                    let l = format!("{:<22} {}", c.nom_affiche(), c.titre());
                    self.dire("aide", &l, Ton::Discret);
                }
                self.dire(
                    "aide",
                    crate::tr!(
                        "Rien d'autre ne se lance d'ici : ni option, ni argument, ni commande qui change l'ordinateur.",
                        "Nothing else runs from here: no option, no argument, no command that changes the computer."
                    ),
                    Ton::Discret,
                );
            }
            Saisie::Lancer(c) => {
                self.dire("vous", &propre, Ton::Commande);
                self.ecran = ecran_de(c);
                self.demander(c);
            }
            Saisie::Refusee(t) => {
                self.dire("vous", &t, Ton::Commande);
                self.dire(
                    "fenêtre",
                    crate::tr!(
                        "Commande inconnue ou pas encore permise ici : rien n'a été lancé. Tapez « aide ».",
                        "Unknown command, or not allowed here yet: nothing was run. Type “help”."
                    ),
                    Ton::Attention,
                );
            }
        }
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

/// L'écran où le résultat d'une commande se montre.
pub fn ecran_de(c: Commande) -> Ecran {
    match c {
        Commande::Bilan => Ecran::Bilan,
        Commande::Evenements => Ecran::Alertes,
        _ => Ecran::Commande(c),
    }
}

fn lire(c: Commande, sortie: &[u8]) -> Result<Contenu, String> {
    Ok(match c.forme() {
        Forme::Audit | Forme::Resultat => Contenu::Constats(bilan::lire(sortie)?),
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
        assert!(a.console.iter().any(|l| l.texte.contains("rien n'a été lancé")));
        assert_eq!(a.saisie, "");
    }

    #[test]
    fn la_console_est_bornee() {
        let mut a = appli();
        for i in 0..(CONSOLE_MAX + 20) {
            a.dire("x", &format!("{i}"), Ton::Normal);
        }
        assert_eq!(a.console.len(), CONSOLE_MAX);
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
            commande: Commande::Bilan,
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

    #[test]
    fn une_nouvelle_alerte_est_dite() {
        let mut a = appli();
        // La ligne « programme absent » d'appli() est grave : seules celles d'après comptent ici.
        a.console.clear();
        let fin = |sortie: &[u8]| Fin {
            commande: Commande::Evenements,
            code: Some(0),
            sortie: sortie.to_vec(),
            issue: Issue::Terminee,
            duree: Duration::ZERO,
        };
        a.finir(&fin(br#"{"etat": "intact", "evenements": []}"#));
        assert!(!a.console.iter().any(|l| l.ton == Ton::Grave));
        a.finir(&fin(
            br#"{"etat": "intact", "evenements": [{"id": "b1", "quoi": {"sorte": "alerte", "titre": "Connexion suspecte"}}]}"#,
        ));
        assert!(
            a.console
                .iter()
                .any(|l| l.ton == Ton::Grave && l.texte.contains("Connexion suspecte"))
        );
    }
}

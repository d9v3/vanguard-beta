//! Les coulisses : ce que fait la fenêtre, noté pour qui veut le voir (la fenêtre « Vanguard — Coulisses »). Chaque
//! commande lancée (ses arguments exacts, de la liste fermée), par où elle part (le relais ou la fenêtre elle-même),
//! le bac à sable, le numéro du processus, la durée, le code de sortie, la taille du résultat, chaque ligne de
//! `vanguard` ; et les saisies de la console refusées, avec la raison.
//!
//! En mémoire seulement, borné, jamais écrit nulle part ; tout texte venu de `vanguard` est nettoyé (`nettoyage`).
//! Rien ne se lance d'ici : ce module n'a que des notes à prendre, la vue ne fait que les lire.

use std::collections::VecDeque;
use std::time::Duration;

use crate::commandes::{Commande, Fin, Issue, Lancement};

/// Commandes retenues au plus (les plus anciennes partent).
pub const PASSAGES_MAX: usize = 50;
/// Lignes retenues au plus, toutes commandes confondues.
pub const NOTES_MAX: usize = 2000;
/// Lignes de la sortie (le JSON) notées au plus par commande : le reste est compté, pas gardé.
pub const SORTIE_LIGNES_MAX: usize = 200;

/// Par où une commande part.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Chemin {
    /// Lancée par le relais, hors du bac à sable de la fenêtre (Linux).
    Relais,
    /// Lancée par la fenêtre elle-même.
    Direct,
}

/// La fin d'une commande, telle que la fenêtre l'a vue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinVue {
    pub duree: Duration,
    pub code: Option<i32>,
    /// L'issue en quelques mots (terminée, arrêtée, délai dépassé…).
    pub issue: String,
    /// La taille du résultat (la sortie lue), en octets.
    pub taille: usize,
}

/// Une commande lancée.
#[derive(Clone, Debug)]
pub struct Passage {
    pub numero: u64,
    pub heure: String,
    /// La ligne exacte : `vanguard` et les arguments fixés dans le code (`Lancement::arguments`).
    pub ligne: String,
    pub chemin: Chemin,
    pub pid: Option<u32>,
    pub fin: Option<FinVue>,
}

/// La sorte d'une ligne des coulisses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sorte {
    Lancement,
    Processus,
    /// Une ligne de la sortie des erreurs de `vanguard` (stderr).
    Erreur,
    /// Une ligne de sa sortie (stdout, le JSON).
    Sortie,
    Fin,
    /// Une saisie de la console refusée.
    Refus,
}

#[derive(Clone, Debug)]
pub struct Note {
    /// Croissant, jamais réutilisé : la vue y retrouve ses mesures.
    pub numero: u64,
    pub heure: String,
    pub sorte: Sorte,
    pub texte: String,
}

#[derive(Debug)]
pub struct Coulisses {
    /// L'état du bac à sable de la fenêtre, tel que dit au démarrage (et s'il est à souligner).
    pub bac: (String, bool),
    passages: VecDeque<Passage>,
    notes: VecDeque<Note>,
    suivant: u64,
    /// Le passage en cours.
    en_cours: Option<u64>,
    refus: usize,
}

impl Coulisses {
    pub fn nouvelles(bac: (String, bool)) -> Coulisses {
        Coulisses {
            bac,
            passages: VecDeque::new(),
            notes: VecDeque::new(),
            suivant: 1,
            en_cours: None,
            refus: 0,
        }
    }

    pub fn passages(&self) -> &VecDeque<Passage> {
        &self.passages
    }

    pub fn notes(&self) -> &VecDeque<Note> {
        &self.notes
    }

    /// Les saisies refusées depuis l'ouverture.
    pub fn refus(&self) -> usize {
        self.refus
    }

    fn numero(&mut self) -> u64 {
        let n = self.suivant;
        self.suivant = self.suivant.saturating_add(1);
        n
    }

    fn noter(&mut self, sorte: Sorte, texte: &str) {
        if self.notes.len() >= NOTES_MAX {
            self.notes.pop_front();
        }
        let numero = self.numero();
        self.notes.push_back(Note {
            numero,
            heure: crate::temps::heure_locale(),
            sorte,
            texte: crate::nettoyage::ligne(texte),
        });
    }

    fn passage_mut(&mut self, n: u64) -> Option<&mut Passage> {
        self.passages.iter_mut().rev().find(|p| p.numero == n)
    }

    /// Une commande (ou un changement au démarrage) part.
    pub fn lancee(&mut self, lancement: Lancement, chemin: Chemin) {
        if self.passages.len() >= PASSAGES_MAX {
            self.passages.pop_front();
        }
        let numero = self.numero();
        let ligne = format!("vanguard {}", lancement.arguments().join(" "));
        self.passages.push_back(Passage {
            numero,
            heure: crate::temps::heure_locale(),
            ligne: ligne.clone(),
            chemin,
            pid: None,
            fin: None,
        });
        self.en_cours = Some(numero);
        let par = match chemin {
            Chemin::Relais => crate::tr!("par le relais", "through the relay"),
            Chemin::Direct => crate::tr!("par la fenêtre elle-même", "by the window itself"),
        };
        self.noter(Sorte::Lancement, &format!("{ligne} · {par}"));
    }

    /// `vanguard` est lancé, sous ce numéro de processus.
    pub fn processus(&mut self, pid: u32) {
        let Some(n) = self.en_cours else {
            return;
        };
        if let Some(p) = self.passage_mut(n) {
            p.pid = Some(pid);
        }
        self.noter(Sorte::Processus, &crate::trf!("pid {}", "pid {}", pid));
    }

    /// Une ligne de la sortie des erreurs de `vanguard`.
    pub fn erreur(&mut self, ligne: &str) {
        self.noter(Sorte::Erreur, ligne);
    }

    /// La commande en cours a fini : sa fin, puis les premières lignes de sa sortie (le reste compté).
    pub fn finie(&mut self, f: &Fin) {
        let Some(n) = self.en_cours.take() else {
            return;
        };
        let issue = issue(&f.issue);
        let fin = FinVue {
            duree: f.duree,
            code: f.code,
            issue: issue.clone(),
            taille: f.sortie.len(),
        };
        if let Some(p) = self.passage_mut(n) {
            p.fin = Some(fin);
        }
        let code = f
            .code
            .map_or_else(|| crate::tr!("sans code", "no code").to_string(), |c| c.to_string());
        self.noter(
            Sorte::Fin,
            &crate::trf!(
                "{} · {:.1} s · code {} · {} octet(s)",
                "{} · {:.1} s · code {} · {} byte(s)",
                issue,
                f.duree.as_secs_f32(),
                code,
                f.sortie.len()
            ),
        );
        let mut lignes = f.sortie.split(|o| *o == b'\n');
        let mut gardees = 0;
        for l in lignes.by_ref().take(SORTIE_LIGNES_MAX) {
            if !l.is_empty() {
                self.noter(Sorte::Sortie, &String::from_utf8_lossy(l));
                gardees += 1;
            }
        }
        let reste = lignes.filter(|l| !l.is_empty()).count();
        if reste > 0 {
            self.noter(
                Sorte::Sortie,
                &crate::trf!(
                    "… {} ligne(s) de plus, non gardées ici ({} montrées)",
                    "… {} more line(s), not kept here ({} shown)",
                    reste,
                    gardees
                ),
            );
        }
    }

    /// Une saisie de la console refusée : ce qui a été tapé (nettoyé, coupé) et pourquoi.
    pub fn refusee(&mut self, saisie: &str) {
        self.refus = self.refus.saturating_add(1);
        let texte = crate::trf!(
            "« {} » : {}",
            "“{}”: {}",
            crate::nettoyage::nom(saisie.trim(), 60),
            pourquoi(saisie)
        );
        self.noter(Sorte::Refus, &texte);
    }
}

/// L'issue d'une commande, en quelques mots.
fn issue(i: &Issue) -> String {
    match i {
        Issue::Terminee => crate::tr!("terminée", "finished").into(),
        Issue::Arretee => crate::tr!("arrêtée à votre demande", "stopped at your request").into(),
        Issue::DelaiDepasse => crate::tr!("délai dépassé", "time limit exceeded").into(),
        Issue::TropLongue => crate::tr!("réponse trop longue", "answer too long").into(),
        Issue::Impossible(e) => crate::trf!("pas lancée : {}", "not started: {}", crate::nettoyage::nom(e, 200)),
    }
}

/// Pourquoi une saisie est refusée (`commandes::comprendre` l'a déjà refusée : ceci ne fait que l'expliquer).
pub fn pourquoi(saisie: &str) -> &'static str {
    let t = saisie.trim();
    let mots: Vec<&str> = t.split_whitespace().collect();
    let mot = match mots.as_slice() {
        [m] => *m,
        [v, m] if v.eq_ignore_ascii_case("vanguard") => *m,
        _ => {
            return crate::tr!(
                "un seul mot permis : ni option, ni argument",
                "a single word only: no option, no argument"
            );
        }
    };
    if mot.starts_with('-') {
        return crate::tr!("une option n'est jamais passée", "an option is never passed on");
    }
    if mot.chars().any(|c| !(c.is_ascii_alphanumeric() || c == '-')) {
        return crate::tr!(
            "signes refusés : rien n'est découpé ni confié à un shell",
            "characters refused: nothing is split or handed to a shell"
        );
    }
    let m = mot.to_ascii_lowercase();
    if Commande::TOUTES
        .iter()
        .any(|c| !c.sur_ce_systeme() && (c.nom() == m || c.nom_anglais() == m))
    {
        return crate::tr!("pas sur ce système", "not on this system");
    }
    crate::tr!(
        "pas dans la liste fermée des commandes permises ici",
        "not in the closed list of commands allowed here"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fin(sortie: &[u8], issue: Issue, code: Option<i32>) -> Fin {
        Fin {
            lancement: Commande::Bilan.into(),
            code,
            sortie: sortie.to_vec(),
            issue,
            duree: Duration::from_millis(1500),
        }
    }

    #[test]
    fn une_commande_est_notee_de_bout_en_bout() {
        let mut c = Coulisses::nouvelles(("bac".into(), false));
        c.lancee(Commande::Bilan.into(), Chemin::Relais);
        c.processus(4242);
        c.erreur("une ligne d'erreur");
        c.finie(&fin(b"{\"a\": 1}\n{\"b\": 2}\n", Issue::Terminee, Some(0)));
        let p = c.passages().back().unwrap();
        assert_eq!(p.ligne, "vanguard audit --json");
        assert_eq!((p.chemin, p.pid), (Chemin::Relais, Some(4242)));
        let f = p.fin.as_ref().unwrap();
        assert_eq!((f.code, f.taille, f.duree), (Some(0), 18, Duration::from_millis(1500)));
        let sortes: Vec<Sorte> = c.notes().iter().map(|n| n.sorte).collect();
        assert_eq!(
            sortes,
            [
                Sorte::Lancement,
                Sorte::Processus,
                Sorte::Erreur,
                Sorte::Fin,
                Sorte::Sortie,
                Sorte::Sortie
            ]
        );
        // Après la fin, rien ne s'accroche plus à elle.
        c.processus(1);
        assert_eq!(c.passages().back().unwrap().pid, Some(4242));
    }

    /// Un changement au démarrage se montre avec sa ligne exacte, empreinte comprise : ce qui part vraiment.
    #[test]
    fn un_changement_montre_sa_ligne_exacte() {
        use crate::commandes::{Changement, Empreinte, Sorte as Geste};
        let empreinte = Empreinte::lire(&"a".repeat(32)).unwrap();
        let mut c = Coulisses::nouvelles(("bac".into(), false));
        c.lancee(
            Lancement::Changement(Changement {
                sorte: Geste::Retirer,
                empreinte,
            }),
            Chemin::Relais,
        );
        let p = c.passages().back().unwrap();
        assert_eq!(
            p.ligne,
            format!(
                "vanguard {}",
                Lancement::Changement(Changement {
                    sorte: Geste::Retirer,
                    empreinte
                })
                .arguments()
                .join(" ")
            )
        );
        assert!(p.ligne.starts_with("vanguard demarrage --retirer "), "{}", p.ligne);
        assert!(p.ligne.contains(&"a".repeat(32)), "{}", p.ligne);
    }

    #[test]
    fn tout_est_borne() {
        let mut c = Coulisses::nouvelles(("bac".into(), false));
        for _ in 0..PASSAGES_MAX + 5 {
            c.lancee(Commande::Protection.into(), Chemin::Direct);
            c.finie(&fin(b"", Issue::Terminee, Some(0)));
        }
        assert_eq!(c.passages().len(), PASSAGES_MAX);
        c.lancee(Commande::Bilan.into(), Chemin::Direct);
        let sortie = "{}\n".repeat(SORTIE_LIGNES_MAX + 30);
        c.finie(&fin(sortie.as_bytes(), Issue::Terminee, Some(0)));
        let derniere = c.notes().back().unwrap();
        assert!(derniere.texte.contains("30"), "{}", derniere.texte);
        for _ in 0..NOTES_MAX {
            c.erreur(&"x".repeat(10_000));
        }
        assert_eq!(c.notes().len(), NOTES_MAX);
        assert!(
            c.notes()
                .iter()
                .all(|n| n.texte.chars().count() <= crate::nettoyage::LIGNE_MAX)
        );
        // Les numéros croissent toujours, même quand les plus anciennes partent.
        assert!(
            c.notes()
                .iter()
                .zip(c.notes().iter().skip(1))
                .all(|(a, b)| a.numero < b.numero)
        );
    }

    /// Un nom piégé venu de `vanguard` (séquences de terminal, sens d'écriture forcé, saut de ligne) ne passe pas tel
    /// quel dans les coulisses.
    #[test]
    fn un_texte_piege_est_nettoye() {
        let mut c = Coulisses::nouvelles(("bac".into(), false));
        c.lancee(Commande::Bilan.into(), Chemin::Direct);
        c.erreur("\u{1b}[2J\u{1b}]0;titre\u{7}Sal\u{202e}on\rfaux");
        c.finie(&fin(
            "{\"nom\": \"Lecteur\u{1b}[31m\u{200b}\"}".as_bytes(),
            Issue::Impossible("\u{1b}[1mraison\u{2028}x".into()),
            None,
        ));
        c.refusee("bilan\u{1b}[8m; rm -rf ~");
        for n in c.notes() {
            assert!(
                !n.texte
                    .chars()
                    .any(|ch| ch == '\u{1b}' || ch.is_control() || crate::nettoyage::piege(ch)),
                "{:?}",
                n.texte
            );
        }
        let refus = c.notes().back().unwrap();
        assert_eq!(refus.sorte, Sorte::Refus);
        assert_eq!(c.refus(), 1);
    }

    #[test]
    fn la_raison_d_un_refus() {
        crate::langue::choisir(Some(false));
        assert!(pourquoi("bilan --html").contains("un seul mot"));
        assert!(pourquoi("--html").contains("option"));
        assert!(pourquoi("bilan;rm").contains("shell"));
        assert!(pourquoi("$(corriger)").contains("shell"));
        assert!(pourquoi("corriger").contains("liste fermée"));
    }
}

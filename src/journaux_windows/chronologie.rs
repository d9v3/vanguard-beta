//! « Que s'est-il passé ? » : les alertes `EVT-` d'une analyse remises dans l'ordre du temps, avec ce qui aide à les
//! retrouver (journal, numéro d'événement, numéro d'enregistrement, fichier, ordinateur), et la période que chaque
//! journal a vraiment couverte. Sans écran : la commande (`commande`), CHRONOLOGIE.txt de `vanguard traces` et le
//! rapport le reprennent.
//!
//! Les dates restent en UTC (celles des journaux) ; l'affichage les dit à l'heure de l'ordinateur qui lit. Tout texte
//! venu d'un journal (un compte, un chemin, un nom d'ordinateur, le nom d'un journal ou d'un fichier) passe par
//! `nom_sans_piege` : une séquence de terminal, un saut de ligne ou un caractère bidi devient « � », et la longueur est
//! bornée.

use chrono::{DateTime, Utc};

use super::regles::jeu::JOURNAUX;
use super::regles::moteur::{Gravite, Lecture, Manque};
use super::regles::resultat::{self, Analyse};
use crate::modele::resultat::nom_sans_piege;

/// Une alerte de la chronologie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AlerteDatee {
    /// Le premier événement à l'appui ; rien : aucun n'est daté (montrée à part, jamais perdue).
    pub date: Option<DateTime<Utc>>,
    /// Le dernier, quand il y en a plusieurs.
    pub dernier: Option<DateTime<Utc>>,
    pub regle: &'static str,
    /// La première technique ATT&CK de la règle.
    pub technique: Option<&'static str>,
    pub gravite: Gravite,
    /// Sa clé d'alerte normale (`resultat::cle_normale`).
    pub cle: String,
    /// Ce qui s'est passé, dans la langue du moment, nettoyé : pourquoi, détails, nombre d'événements, réserves.
    pub texte: String,
    /// Où le retrouver : journal, numéro d'événement et d'enregistrement, fichier, ordinateur ; nettoyé.
    pub contexte: String,
}

/// La période qu'un journal des règles a couverte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Periode {
    /// Le nom du journal, tel que les règles le lisent.
    pub journal: &'static str,
    pub etat: EtatPeriode,
    pub evenements: u64,
    pub premier: Option<DateTime<Utc>>,
    pub dernier: Option<DateTime<Utc>>,
    /// Le journal ne remonte pas au début de la période demandée (`Manque::PeriodeCourte`).
    pub courte: bool,
    /// Ce que les règles ont relevé d'autre sur ce journal (vide, muet, désactivé, trous non vérifiés, audit réduit
    /// ou sans preuve), dans la langue du moment, sans doublon : un journal lu sans erreur n'est pas pour autant
    /// sain.
    pub remarques: Vec<String>,
}

/// Le journal dont parle un manque, pour ceux que la lecture elle-même ne dit pas (`Periode::etat`).
fn journal_du_manque(m: &Manque) -> Option<&str> {
    match m {
        Manque::Vide(j) | Manque::Desactive(j) => Some(j),
        Manque::Muet { journal, .. }
        | Manque::AuditReduit { journal }
        | Manque::NonVerifies { journal, .. }
        | Manque::NonAudite { journal, .. }
        | Manque::TrousIllisibles { journal, .. }
        | Manque::SuiteNonProuvee { journal, .. }
        | Manque::TrousAuDela { journal, .. } => Some(journal),
        Manque::Absent(_)
        | Manque::Refuse(_)
        | Manque::Illisible(..)
        | Manque::Partiel(..)
        | Manque::PeriodeCourte { .. }
        | Manque::Bornes(_)
        | Manque::SansDate(_)
        | Manque::DefenderInconnu => None,
    }
}

/// Ce que la source a pu faire d'un journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EtatPeriode {
    /// Lu ; ce qui en manque (vide : tout lu), déjà nettoyé.
    Lu(Vec<String>),
    Absent,
    Refuse,
    Illisible(String),
}

/// Ce qu'une règle a laissé au-delà de ses bornes : des événements comptés, pas montrés un à un.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuDela {
    pub regle: &'static str,
    pub evenements: u64,
    pub pire: Option<Gravite>,
}

/// La chronologie d'une analyse.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Chronologie {
    /// Les alertes datées, de la plus ancienne à la plus récente (à date égale : règle, puis texte), puis celles sans
    /// date.
    pub alertes: Vec<AlerteDatee>,
    /// Les alertes déclarées normales, tues (jamais une critique).
    pub tues: u64,
    pub au_dela: Vec<AuDela>,
}

/// Où retrouver une trouvaille : son premier repère.
fn contexte(t: &super::regles::moteur::Trouvaille) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(r) = t.reperes.first() {
        parts.push(nom_sans_piege(&r.journal, 80));
        parts.push(crate::trf!("événement {}", "event {}", r.id));
        if let Some(n) = r.numero {
            parts.push(crate::trf!("enregistrement n° {n}", "record #{n}"));
        }
        if let Some(f) = r.fichier.as_deref().and_then(|f| f.file_name()) {
            parts.push(nom_sans_piege(&f.to_string_lossy(), 80));
        }
    }
    if !t.ordinateur.is_empty() {
        parts.push(crate::trf!(
            "ordinateur {}",
            "computer {}",
            nom_sans_piege(&t.ordinateur, 64)
        ));
    }
    parts.join(", ")
}

/// Ce qu'une trouvaille dit, sans sa première date (la chronologie la montre à part).
fn texte(t: &super::regles::moteur::Trouvaille) -> String {
    let mut m = resultat::corps(t);
    match t.dernier {
        Some(d) if t.nombre > 1 && t.premier != Some(d) => m.push_str(&crate::trf!(
            " ({} fois, jusqu'au {})",
            " ({} times, until {})",
            t.nombre,
            resultat::date(d)
        )),
        _ if t.nombre > 1 => m.push_str(&crate::trf!(" ({} fois)", " ({} times)", t.nombre)),
        _ => {}
    }
    for r in &t.reserves {
        m.push_str(" — ");
        m.push_str(resultat::reserve(*r));
    }
    m
}

/// La chronologie des alertes d'une analyse. `est_normale` : la même que pour le résultat (`resultat::resultat`),
/// pour que l'écran, le rapport et CHRONOLOGIE.txt taisent les mêmes alertes, et jamais une critique.
pub(crate) fn chronologie(a: &Analyse, est_normale: &dyn Fn(&str) -> bool) -> Chronologie {
    let mut c = Chronologie::default();
    for j in &a.jugements {
        let r = j.regle;
        for t in &j.trouvailles {
            if t.gravite < Gravite::Critique && est_normale(&resultat::cle_normale(r.id, &t.objet)) {
                c.tues += 1;
                continue;
            }
            c.alertes.push(AlerteDatee {
                date: t.premier,
                dernier: t.dernier,
                regle: r.id,
                technique: r.techniques.first().copied(),
                gravite: t.gravite,
                cle: resultat::cle_normale(r.id, &t.objet),
                texte: texte(t),
                contexte: contexte(t),
            });
        }
        if j.au_dela > 0 {
            c.au_dela.push(AuDela {
                regle: r.id,
                evenements: j.au_dela,
                pire: j.au_dela_pire,
            });
        }
    }
    // Les datées d'abord, dans l'ordre du temps ; puis les autres.
    c.alertes.sort_by(|x, y| {
        (x.date.is_none(), x.date, x.regle, &x.texte).cmp(&(y.date.is_none(), y.date, y.regle, &y.texte))
    });
    c
}

/// La période que chaque journal des règles a couverte, dans l'ordre des règles.
pub(crate) fn periodes(a: &Analyse) -> Vec<Periode> {
    let courte = |journal: &str| {
        a.jugements
            .iter()
            .flat_map(|j| &j.manques)
            .any(|m| matches!(m, Manque::PeriodeCourte { journal: x, .. } if x.eq_ignore_ascii_case(journal)))
    };
    JOURNAUX
        .iter()
        .map(|journal| {
            let etats: Vec<_> = a.etats.iter().filter(|e| e.nom.eq_ignore_ascii_case(journal)).collect();
            // Un journal lu dans au moins un fichier est lu ; ce que les autres n'ont pas donné est dit avec.
            let mut manques: Vec<String> = Vec::new();
            let mut lu = false;
            let mut refuse = false;
            let mut illisible = None;
            for e in &etats {
                match &e.lecture {
                    Lecture::Lu(m) => {
                        lu = true;
                        manques.extend(m.iter().map(|x| nom_sans_piege(x, 200)));
                    }
                    Lecture::Refuse => refuse = true,
                    Lecture::Illisible(x) => illisible = Some(nom_sans_piege(x, 200)),
                    Lecture::Absent => {}
                }
            }
            let etat = if lu {
                if let Some(x) = illisible {
                    manques.push(x);
                }
                EtatPeriode::Lu(manques)
            } else if refuse {
                EtatPeriode::Refuse
            } else if let Some(x) = illisible {
                EtatPeriode::Illisible(x)
            } else {
                EtatPeriode::Absent
            };
            let mut remarques: Vec<String> = Vec::new();
            for m in a.jugements.iter().flat_map(|j| &j.manques) {
                if journal_du_manque(m).is_some_and(|x| x.eq_ignore_ascii_case(journal)) {
                    let t = nom_sans_piege(&resultat::manque(&a.source, m).0, 300);
                    if !remarques.contains(&t) {
                        remarques.push(t);
                    }
                }
            }
            let stat = a.journaux.iter().find(|s| s.nom.eq_ignore_ascii_case(journal));
            Periode {
                journal,
                etat,
                evenements: stat.map_or(0, |s| s.evenements),
                premier: stat.and_then(|s| s.premier),
                dernier: stat.and_then(|s| s.dernier),
                courte: courte(journal),
                remarques,
            }
        })
        .collect()
}

/// Une gravité, telle qu'on la dit.
pub(crate) fn gravite(g: Gravite) -> &'static str {
    match g {
        Gravite::Info => crate::tr!("information", "information"),
        Gravite::Alerte => crate::tr!("alerte", "alert"),
        Gravite::Critique => crate::tr!("critique", "critical"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journaux_windows::evenement::{EvenementWindows, Origine};
    use crate::journaux_windows::regles::jeu::REGLES;
    use crate::journaux_windows::regles::moteur::{BornesMoteur, EtatJournal, Moteur, Options, Repere};
    use crate::journaux_windows::regles::resultat::Source;
    use chrono::Duration;

    fn t0() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-18T14:00:00Z").unwrap().to_utc()
    }

    fn ev(journal: &str, fournisseur: &str, id: u32, s: i64, numero: u64, champs: &[(&str, &str)]) -> EvenementWindows {
        EvenementWindows {
            journal: journal.into(),
            id,
            niveau: Some(4),
            date: Some(t0() + Duration::seconds(s)),
            ordinateur: "poste-alice".into(),
            numero: Some(numero),
            fournisseur: fournisseur.into(),
            utilisateur: None,
            champs: champs
                .iter()
                .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
                .collect(),
            origine: Origine::Vivant,
            verifie: true,
        }
    }

    /// Une analyse de ces événements, tous les journaux des règles lus sauf `sans`.
    fn analyse(evs: &[EvenementWindows], sans: &[&str]) -> Analyse {
        let options = Options {
            depuis: Some(t0() - Duration::days(7)),
            defender_antivirus: Some(true),
        };
        let mut m = Moteur::nouveau(REGLES, options, BornesMoteur::default());
        for e in evs {
            m.recevoir(e);
        }
        let etats: Vec<EtatJournal> = JOURNAUX
            .iter()
            .filter(|j| !sans.contains(j))
            .map(|j| EtatJournal {
                nom: (*j).to_string(),
                lecture: Lecture::Lu(Vec::new()),
                active: Some(true),
                principal: true,
                suites: Vec::new(),
            })
            .collect();
        let journaux = m.journaux();
        let jugements = m.conclure(&etats);
        Analyse {
            source: Source::Dossier("d".into()),
            jugements,
            journaux,
            etats,
            manques_source: Vec::new(),
        }
    }

    const SCM: &str = "Service Control Manager";
    const AUDIT: &str = "Microsoft-Windows-Security-Auditing";

    fn service(s: i64, numero: u64, nom: &str, chemin: &str) -> EvenementWindows {
        ev(
            "System",
            SCM,
            7045,
            s,
            numero,
            &[("ServiceName", nom), ("ImagePath", chemin)],
        )
    }

    fn efface(s: i64, numero: u64) -> EvenementWindows {
        ev(
            "Security",
            "Microsoft-Windows-Eventlog",
            1102,
            s,
            numero,
            &[("SubjectUserName", "alice")],
        )
    }

    /// Dans l'ordre du temps quel que soit l'ordre des règles, avec le contexte, et les textes hostiles nettoyés.
    #[test]
    fn alertes_dans_l_ordre_du_temps() {
        let evs = vec![
            ev("Security", AUDIT, 4624, 0, 1, &[("LogonType", "5")]),
            ev("System", SCM, 7036, 0, 2, &[("param1", "x")]),
            service(
                3600,
                10,
                "piege\u{1b}]52;c;Zm9v\u{7}\u{1b}[2K",
                r"C:\Windows\Temp\x.exe",
            ),
            efface(60, 20),
        ];
        let a = analyse(&evs, &[]);
        let c = chronologie(&a, &|_| false);
        let datees: Vec<_> = c.alertes.iter().filter(|x| x.date.is_some()).collect();
        assert!(datees.len() >= 2, "{c:#?}");
        assert!(datees.windows(2).all(|w| w[0].date <= w[1].date), "{c:#?}");
        let eff = c.alertes.iter().position(|x| x.regle == "EVT-EFF-001").unwrap();
        let srv = c.alertes.iter().position(|x| x.regle == "EVT-SRV-001").unwrap();
        assert!(eff < srv, "le journal effacé (60 s) avant le service (3600 s)");
        let s = &c.alertes[srv];
        assert_eq!(s.date, Some(t0() + Duration::seconds(3600)));
        assert!(
            s.contexte.contains("System") && s.contexte.contains("7045") && s.contexte.contains("10"),
            "{s:?}"
        );
        assert!(s.contexte.contains("poste-alice"), "{s:?}");
        for x in &c.alertes {
            assert!(!x.texte.chars().any(crate::ui::piege), "{x:?}");
            assert!(!x.contexte.chars().any(crate::ui::piege), "{x:?}");
        }
        assert!(s.texte.contains('\u{fffd}'), "{s:?}");
        assert_eq!(
            s.technique,
            REGLES
                .iter()
                .find(|r| r.id == "EVT-SRV-001")
                .unwrap()
                .techniques
                .first()
                .copied()
        );
    }

    /// Une alerte déclarée normale est tue et comptée ; une critique ne se tait jamais.
    #[test]
    fn normales_tues_sauf_critiques() {
        let evs = vec![
            ev("Security", AUDIT, 4624, 0, 1, &[("LogonType", "5")]),
            ev("System", SCM, 7036, 0, 2, &[("param1", "x")]),
            service(10, 3, "x", r"C:\Windows\Temp\x.exe"),
            efface(20, 4),
        ];
        let a = analyse(&evs, &[]);
        let tout = |_: &str| true;
        let c = chronologie(&a, &tout);
        // Ce qui reste est critique, et ce qui est tu ne l'était pas.
        assert!(c.alertes.iter().all(|x| x.gravite == Gravite::Critique), "{c:#?}");
        let toutes = chronologie(&a, &|_| false);
        let critiques = toutes.alertes.iter().filter(|x| x.gravite == Gravite::Critique).count();
        assert_eq!(c.alertes.len(), critiques);
        assert_eq!(c.tues, u64::try_from(toutes.alertes.len() - critiques).unwrap());
        // Le résultat tait les mêmes.
        let r = resultat::resultat(&a, (Utc::now(), std::time::Instant::now()), &tout);
        assert_eq!(r.constats.iter().filter(|x| x.etat == "probleme").count(), critiques);
    }

    /// Chaque alerte du résultat porte sa date en UTC ; les autres constats n'en ont pas.
    #[test]
    fn dates_du_resultat() {
        let evs = vec![
            ev("Security", AUDIT, 4624, 0, 1, &[("LogonType", "5")]),
            ev("System", SCM, 7036, 0, 2, &[("param1", "x")]),
            service(3600, 3, "x", r"C:\Windows\Temp\x.exe"),
        ];
        let a = analyse(&evs, &[]);
        let r = resultat::resultat(&a, (Utc::now(), std::time::Instant::now()), &|_| false);
        let srv = r
            .constats
            .iter()
            .find(|c| c.regle == "EVT-SRV-001" && c.etat == "probleme")
            .unwrap();
        assert_eq!(srv.date.as_deref(), Some("2026-10-18T15:00:00Z"));
        assert!(
            r.constats
                .iter()
                .filter(|c| c.etat != "probleme")
                .all(|c| c.date.is_none())
        );
    }

    /// La période de chaque journal : lu (et sur combien), absent, refusé ; plus courte que demandée, dite.
    #[test]
    fn periodes_par_journal() {
        let evs = vec![
            ev("Security", AUDIT, 4624, 0, 1, &[("LogonType", "5")]),
            ev("System", SCM, 7036, 3600, 2, &[("param1", "x")]),
        ];
        let mut a = analyse(&evs, &["Microsoft-Windows-Bits-Client/Operational"]);
        a.etats.iter_mut().find(|e| e.nom == "Security").unwrap().lecture = Lecture::Refuse;
        let p = periodes(&a);
        assert_eq!(p.len(), JOURNAUX.len());
        let de = |j: &str| p.iter().find(|x| x.journal == j).unwrap();
        assert_eq!(de("Security").etat, EtatPeriode::Refuse);
        assert_eq!(
            de("Microsoft-Windows-Bits-Client/Operational").etat,
            EtatPeriode::Absent
        );
        let sys = de("System");
        assert_eq!(sys.etat, EtatPeriode::Lu(Vec::new()));
        assert_eq!(sys.evenements, 1);
        assert_eq!(sys.premier, Some(t0() + Duration::seconds(3600)));
        // Demandé depuis sept jours avant t0 : System ne remonte qu'à t0 + 1 h.
        assert!(sys.courte, "{sys:?}");
        // Lu sans erreur mais vide : dit, jamais muet.
        let vide = analyse(&[ev("System", SCM, 7036, 0, 2, &[("param1", "x")])], &[]);
        let sec = periodes(&vide).into_iter().find(|x| x.journal == "Security").unwrap();
        assert_eq!(sec.etat, EtatPeriode::Lu(Vec::new()));
        assert!(sec.remarques.iter().any(|r| r.contains("vide")), "{sec:?}");
    }

    /// Une trouvaille sans date reste montrée, après les datées.
    #[test]
    fn sans_date_apres() {
        let mut a = analyse(&[], &[]);
        let j = a.jugements.iter_mut().find(|j| j.regle.id == "EVT-SRV-001").unwrap();
        j.trouvailles.push(super::super::regles::moteur::Trouvaille {
            volet: 0,
            objet: "x".into(),
            ordinateur: String::new(),
            gravite: Gravite::Alerte,
            pourquoi: ("p", "p"),
            details: Vec::new(),
            nombre: 1,
            verifies: 1,
            premier: None,
            dernier: None,
            reperes: vec![Repere {
                journal: "System".into(),
                id: 7045,
                date: None,
                numero: None,
                verifie: true,
                fichier: None,
            }],
            reserves: std::collections::BTreeSet::new(),
        });
        j.au_dela = 12;
        j.au_dela_pire = Some(Gravite::Critique);
        let c = chronologie(&a, &|_| false);
        assert_eq!(c.alertes.last().unwrap().date, None);
        assert_eq!(
            c.au_dela,
            vec![AuDela {
                regle: "EVT-SRV-001",
                evenements: 12,
                pire: Some(Gravite::Critique)
            }]
        );
    }
}

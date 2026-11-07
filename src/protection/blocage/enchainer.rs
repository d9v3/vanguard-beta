//! Dérouler une suite (`suites`) : chaque geste à son tour, fait par le geste de R1 qui le rejuge lui-même
//! (`suspension::suspendre` et ses gardes, `gestes::preparer` puis `faire`, `surveiller::ajouter`, `ordres::juger`).
//! Un geste refusé par un garde-fou reste refusé dans une suite ; un geste sauté ou refusé ne casse jamais la suite,
//! la suivante se fait.
//!
//! Chaque geste qui change quelque chose se note comme seul (la suspension dans sa liste scellée et au journal, le
//! blocage dans « Ce que Vanguard a changé », la surveillance au journal) et s'annule comme seul, un par un ; la suite
//! entière est notée à la fin, une ligne par geste, avec ce qui a été sauté et pourquoi.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::path::PathBuf;

use super::gestes::{self, Contexte, Pret};
use super::menaces::{Geste, Menace};
use super::suites::{Cible, Etape, Plan, Type, planifier};
use super::{ordres, surveiller, suspension};
use crate::modele::Echec;
use crate::{tr, trf};

/// Ce qu'un geste de la suite est devenu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Issue {
    Fait(String),
    /// Fait par le geste Bloquer de la même suite (la preuve juste avant lui, les connexions avec lui).
    AvecBloquer(String),
    /// Sauté, sans objet ici ou pas encore disponible : la suite continue.
    Saute(String),
    /// Refusé (garde-fou, droits) ou échoué : la suite continue.
    Echoue(String),
}

impl Issue {
    /// La ligne montrée et notée : le geste, puis ce qu'il est devenu.
    pub(super) fn ligne(&self, e: Etape) -> String {
        let marque = match self {
            Issue::Fait(_) | Issue::AvecBloquer(_) => "✔",
            Issue::Saute(_) => "–",
            Issue::Echoue(_) => "✖",
        };
        format!("{marque} {}", self.phrase(e))
    }

    /// Le geste et ce qu'il est devenu, sans la marque.
    pub(super) fn phrase(&self, e: Etape) -> String {
        let (Issue::Fait(t) | Issue::AvecBloquer(t) | Issue::Saute(t) | Issue::Echoue(t)) = self;
        trf!("{} : {t}", "{}: {t}", e.texte())
    }
}

/// Ce que la suite a fait jusqu'ici, pour le geste Prévenir.
pub(super) struct Deroule {
    pub(super) issues: Vec<(Etape, Issue)>,
    /// Le geste Bloquer : ce qui a été fait (vérifié ou non), ou pourquoi pas ; `None` : pas encore, ou pas dans la
    /// suite.
    pub(super) bloque: Option<Result<gestes::Fait, String>>,
    /// Suspendu par la suite et toujours là (« reprendre » le relance) : faux si Bloquer l'a arrêté ensuite.
    pub(super) a_reprendre: bool,
}

/// Le type d'alerte d'une menace, qui choisit sa suite ; `None` : pas de suite (un démarrage, la liste des pilotes,
/// le reste des programmes douteux de COM-PRG-001), le menu des gestes de R1 seul.
pub(super) fn type_de(m: &Menace) -> Option<Type> {
    match &m.geste {
        Geste::Programme { detection, .. } if detection == super::menaces::raison_rancongiciel() => {
            Some(Type::Rancongiciel)
        }
        // La raison écrite par `sources::juger_programme`, dans la langue de ce passage.
        Geste::Programme { detection, .. }
            if detection.starts_with("outil offensif : ") || detection.starts_with("offensive tool: ") =>
        {
            Some(Type::OutilDAttaque)
        }
        // Le reste du certain : une empreinte connue de MalwareBazaar.
        Geste::Programme { .. } if m.certaine => Some(Type::MalwareConnu),
        Geste::Adresse { .. } => Some(Type::ServeurDeCommande),
        Geste::ServeurIa { .. } | Geste::Permissions { .. } => Some(Type::AgentIa),
        _ => None,
    }
}

/// Ce que la suite sait de sa cible, lu une fois avant le premier geste : l'empreinte du fichier, avant que la
/// quarantaine ne le déplace.
pub(super) struct Avant {
    pub(super) cible: Cible,
    surveiller: Option<(PathBuf, [u8; 32])>,
}

pub(super) fn avant(m: &Menace) -> Avant {
    let surveiller = m
        .fichier_du_programme()
        .map(std::path::Path::to_path_buf)
        .zip(m.empreinte());
    let cible = match &m.geste {
        Geste::Programme { pid, chemin, .. } => Cible::Programme {
            en_marche: pid.is_some() && chemin.is_some(),
            empreinte: surveiller.is_some(),
        },
        Geste::Adresse { .. } => Cible::Adresse,
        Geste::ServeurIa { .. } => Cible::Port,
        _ => Cible::Reglage,
    };
    Avant { cible, surveiller }
}

/// Le plan de la suite pour cette menace : chaque geste fait ou sauté, avec pourquoi. `bloquer_possible` : le geste
/// Bloquer est prêt (ses garde-fous l'acceptent) ; sinon la preuve se relève seule et la coupure se fait à part.
pub(super) fn plan(etapes: &[Etape], a: &Avant, bloquer_possible: bool) -> Vec<(Etape, Plan)> {
    planifier(etapes, a.cible, cfg!(target_os = "linux"), bloquer_possible)
}

/// Déroule la suite, dans son ordre. `pret` : le geste Bloquer préparé (et rejugé) avant le premier geste, ou
/// pourquoi il ne se fera pas ; `automatique` : sans clic (protection active), les gardes sont alors plus strictes ;
/// `prevenir` : le geste Prévenir (notification et tableau de bord), avec ce qui a été fait jusque-là.
pub(super) fn derouler(
    m: &Menace,
    etapes: &[Etape],
    ctx: &Contexte,
    automatique: bool,
    pret: Result<Pret, Echec>,
    prevenir: &mut dyn FnMut(&Deroule) -> Issue,
) -> Deroule {
    let releve = avant(m);
    let plan = plan(etapes, &releve, pret.is_ok());
    let mut pret = Some(pret);
    let mut d = Deroule {
        issues: Vec::with_capacity(plan.len()),
        bloque: None,
        a_reprendre: false,
    };
    // `gestes::faire` note son propre geste au journal : la suite ne le redit pas seule (`a_noter`).
    let mut faire_appele = false;
    for (e, p) in plan {
        let issue = match p {
            Plan::PasDisponible => Issue::Saute(tr!("pas encore disponible", "not available yet").to_string()),
            Plan::SansObjet(r) => Issue::Saute(r.to_string()),
            Plan::AvecBloquer(r) => Issue::AvecBloquer(r.to_string()),
            Plan::Faire => match e {
                Etape::Suspendre => suspendre(m, ctx, automatique),
                Etape::CouperConnexions => couper(m, ctx, automatique),
                Etape::Preuve if gestes::relever_seule(m) => Issue::Fait(tr!("relevée", "recorded").to_string()),
                Etape::Preuve => Issue::Saute(tr!("rien à relever", "nothing to record").to_string()),
                Etape::Bloquer => {
                    let fait = match pret.take() {
                        Some(Ok(p)) => {
                            if automatique && ctx.interactif {
                                super::montrer(m, &p);
                            }
                            faire_appele = true;
                            gestes::faire(m, p, automatique).map_err(|e| e.to_string())
                        }
                        Some(Err(e)) => Err(e.to_string()),
                        None => Err(tr!("déjà fait plus haut", "already done above").to_string()),
                    };
                    let issue = match &fait {
                        Ok(f) if f.verifie => Issue::Fait(f.quoi.clone()),
                        Ok(f) => Issue::Fait(trf!("{} (non vérifié)", "{} (not verified)", f.quoi)),
                        Err(e) => Issue::Echoue(e.clone()),
                    };
                    if fait.is_ok() {
                        arrete_apres_suspension(m, &mut d);
                    }
                    d.bloque = Some(fait);
                    issue
                }
                Etape::Surveiller => match &releve.surveiller {
                    Some((fichier, empreinte)) => {
                        match surveiller::ajouter(&fichier.to_string_lossy(), empreinte, &m.quoi) {
                            Ok(fin) => Issue::Fait(trf!("jusqu'au {fin}", "until {fin}")),
                            Err(e) => Issue::Echoue(e.to_string()),
                        }
                    }
                    None => Issue::Saute(
                        tr!(
                            "aucun fichier dont l'empreinte se lit",
                            "no file whose fingerprint can be read"
                        )
                        .to_string(),
                    ),
                },
                Etape::Prevenir => prevenir(&d),
                Etape::CouperReseau => Issue::Saute(tr!("pas encore disponible", "not available yet").to_string()),
            },
        };
        if e == Etape::Suspendre && matches!(issue, Issue::Fait(_)) {
            d.a_reprendre = true;
        }
        d.issues.push((e, issue));
    }
    if a_noter(&d.issues, faire_appele) {
        noter(m, automatique, &d);
    }
    d
}

/// Bloquer a arrêté le processus que la suite venait de suspendre : son entrée de suspension est oubliée, et
/// « reprendre » n'est plus conseillé (il n'y a plus rien à relancer). Encore là (l'arrêt pas encore constaté) :
/// rien ne change, le bilan l'oubliera.
fn arrete_apres_suspension(m: &Menace, d: &mut Deroule) {
    let Geste::Programme { pid: Some(pid), .. } = &m.geste else {
        return;
    };
    if !d.a_reprendre || !suspension::oublier_s_il_est_fini(*pid) {
        return;
    }
    d.a_reprendre = false;
    for (e, i) in &mut d.issues {
        if *e == Etape::Suspendre && matches!(i, Issue::Fait(_)) {
            *i = Issue::Fait(tr!("gelé, puis arrêté par Bloquer", "frozen, then stopped by Block").to_string());
        }
    }
}

/// La suite se note-t-elle au journal ? Pas quand elle ne dirait que le geste Bloquer, déjà noté par
/// `gestes::faire` (`faire_appele`), avec Prévenir et ce qui s'est fait avec Bloquer : deux actions pour un seul
/// geste, sinon, au tableau de bord. Dès qu'un autre geste est fait, sauté ou manqué, ou que Bloquer ne s'est pas
/// fait (refusé d'avance : rien d'autre ne le note), elle se note.
fn a_noter(issues: &[(Etape, Issue)], faire_appele: bool) -> bool {
    !faire_appele
        || issues
            .iter()
            .any(|(e, i)| !matches!(e, Etape::Bloquer | Etape::Prevenir) && !matches!(i, Issue::AvecBloquer(_)))
}

/// La suite entière au journal, une ligne par geste (ce qui a été sauté aussi, avec pourquoi), sous la clé de la
/// menace : le fil va de l'alerte aux gestes, chacun noté et annulable à part.
fn noter(m: &Menace, automatique: bool, d: &Deroule) {
    use crate::modele::evenement::{Evenement, Source};
    let lignes: Vec<String> = d.issues.iter().map(|(e, i)| i.ligne(*e)).collect();
    let reussi = !d.issues.iter().any(|(_, i)| matches!(i, Issue::Echoue(_)));
    let quoi = if automatique {
        trf!(
            "Suite de gestes faite toute seule (protection active) : {}",
            "Suite of actions run by itself (active protection): {}",
            m.quoi
        )
    } else {
        trf!("Suite de gestes : {}", "Suite of actions: {}", m.quoi)
    };
    crate::modele::journal::noter(Evenement::action(Source::Blocage, &quoi, reussi, &lignes).cle(Some(&m.cle)));
}

/// Suspendre, à son tour : sous les gardes du gel (`suspension::suspendre` les rejuge). Un programme du système se
/// suspend seulement à part (Suspendre), montré et confirmé : jamais dans une suite. Sans clic, rien ne demande de
/// droits à personne.
fn suspendre(m: &Menace, ctx: &Contexte, automatique: bool) -> Issue {
    let Geste::Programme {
        pid: Some(pid),
        chemin: Some(chemin),
        ..
    } = &m.geste
    else {
        return Issue::Saute(tr!("aucun processus en marche", "no running process").to_string());
    };
    let chemin = chemin.to_string_lossy();
    if let Some(role) = suspension::role(*pid, &chemin) {
        return Issue::Saute(trf!(
            "c'est {role} : il se suspend seulement à part (Suspendre), montré et confirmé",
            "this is {role}: it is only suspended on its own (Suspend), shown and confirmed"
        ));
    }
    if automatique && !ctx.admin && !ctx.interactif && !suspension::sans_droits_de_plus(*pid) {
        return Issue::Echoue(gestes::droits_manquants());
    }
    // Sans clic, la protection active l'a fait : le journal le dit (jamais « demandé par la personne »).
    let source = if automatique {
        crate::modele::evenement::Source::Blocage
    } else {
        crate::modele::evenement::Source::Utilisateur
    };
    match suspension::suspendre(
        *pid,
        &chemin,
        &m.quoi,
        Some(&m.cle_normale()),
        &ctx.intouchables,
        source,
    ) {
        Ok(()) => Issue::Fait(trf!(
            "« vanguard blocage reprendre {pid} » le reprend",
            "“vanguard blocking resume {pid}” resumes it"
        )),
        Err(e) => Issue::Echoue(e.to_string()),
    }
}

/// Couper seules les connexions déjà ouvertes vers une adresse (sans la règle de Bloquer) : l'ordre est rejugé ici,
/// puis par celui qui a les droits.
fn couper(m: &Menace, ctx: &Contexte, automatique: bool) -> Issue {
    use crate::modele::evenement::{Evenement, Source};
    let Geste::Adresse { ip } = &m.geste else {
        return Issue::Saute(tr!("aucune adresse désignée", "no address designated").to_string());
    };
    let o = ordres::Ordre::CouperConnexions { ip: ip.to_canonical() };
    if !o.permis_ici() {
        return Issue::Saute(
            tr!(
                "pas sous ce système : seules les nouvelles connexions sont bloquées",
                "not on this system: only new connections are blocked"
            )
            .to_string(),
        );
    }
    if let Some(raison) = ordres::juger(&o, &ordres::Juge::lire(None).avec(&ctx.intouchables)) {
        return Issue::Echoue(raison);
    }
    if automatique && !ctx.admin && !ctx.interactif {
        return Issue::Echoue(gestes::droits_manquants());
    }
    let (reussi, lancees) = crate::machine::appliquer_sans_noter(&[o.ligne()]);
    crate::modele::journal::noter(Evenement::action(Source::Blocage, &o.texte(), reussi, &lancees).cle(Some(&m.cle)));
    if reussi {
        Issue::Fait(tr!("coupées", "cut").to_string())
    } else {
        Issue::Echoue(lancees.join(" ; "))
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::protection::blocage::parametres::Categorie;

    /// Une suite sans Bloquer sur un programme qui n'est plus là : rien ne se fait sur le système, chaque geste est
    /// sauté avec sa raison (« couper le réseau » dit pas encore disponible), Prévenir se fait quand même, à son
    /// tour, et la suite entière est notée.
    #[test]
    fn suite_sans_objet_sautee_sans_casser() {
        let m = Menace {
            categorie: Categorie::Programmes,
            certaine: false,
            quoi: "« essai » : x".into(),
            cle: "programme:essai-suite".into(),
            geste: Geste::Programme {
                pid: None,
                nom: "essai".into(),
                chemin: None,
                fichier: None,
                detection: "x".into(),
            },
        };
        let ctx = Contexte {
            os: crate::machine::regles::Os::actuel(),
            intouchables: std::collections::HashSet::new(),
            sessions: None,
            pare_feu: Err(Echec::refuse("essai", "x")),
            admin: false,
            interactif: false,
            mon_programme: None,
        };
        let s = [
            Etape::Suspendre,
            Etape::CouperReseau,
            Etape::CouperConnexions,
            Etape::Surveiller,
            Etape::Prevenir,
        ];
        let mut prevenus = 0;
        let d = derouler(&m, &s, &ctx, false, Err(Echec::refuse("essai", "refusé")), &mut |d| {
            prevenus += 1;
            assert_eq!(d.issues.len(), 4);
            Issue::Fait("prévenu".into())
        });
        assert_eq!(prevenus, 1);
        assert_eq!(d.issues.iter().map(|(e, _)| *e).collect::<Vec<_>>(), s);
        assert!(
            d.issues[..4].iter().all(|(_, i)| matches!(i, Issue::Saute(_))),
            "{:?}",
            d.issues
        );
        assert!(d.bloque.is_none());
    }

    /// Une seule action au journal pour un seul geste : la suite par défaut (preuve et coupure avec Bloquer,
    /// Bloquer, Prévenir) ne redit pas ce que `gestes::faire` a noté ; un autre geste, ou Bloquer refusé d'avance
    /// (personne d'autre ne le note), et elle se note.
    #[test]
    fn suite_notee_sans_doublon() {
        let fait = || Issue::Fait("x".into());
        let avec = || Issue::AvecBloquer("x".into());
        let defaut = [
            (Etape::Preuve, avec()),
            (Etape::Bloquer, fait()),
            (Etape::CouperConnexions, avec()),
            (Etape::Prevenir, fait()),
        ];
        assert!(!a_noter(&defaut, true));
        assert!(a_noter(&defaut, false));
        let refuse = [
            (Etape::Bloquer, Issue::Echoue("pas administrateur".into())),
            (Etape::Prevenir, fait()),
        ];
        assert!(a_noter(&refuse, false));
        let gele = [
            (Etape::Suspendre, fait()),
            (Etape::Bloquer, fait()),
            (Etape::Prevenir, fait()),
        ];
        assert!(a_noter(&gele, true));
        let saute = [(Etape::Bloquer, fait()), (Etape::Surveiller, Issue::Saute("x".into()))];
        assert!(a_noter(&saute, true));
    }

    /// Le type d'alerte, d'après ce qui a désigné la menace.
    #[test]
    fn type_d_alerte() {
        let programme = |certaine: bool, detection: &str| Menace {
            categorie: Categorie::Programmes,
            certaine,
            quoi: "q".into(),
            cle: "programme:1:/x".into(),
            geste: Geste::Programme {
                pid: Some(1),
                nom: "x".into(),
                chemin: None,
                fichier: None,
                detection: detection.into(),
            },
        };
        assert_eq!(
            type_de(&programme(true, "outil offensif : mimikatz")),
            Some(Type::OutilDAttaque)
        );
        assert_eq!(
            type_de(&programme(false, "offensive tool: laZagne")),
            Some(Type::OutilDAttaque)
        );
        assert_eq!(
            type_de(&programme(true, crate::protection::sources::raison_empreinte())),
            Some(Type::MalwareConnu)
        );
        assert_eq!(
            type_de(&programme(false, super::super::menaces::raison_rancongiciel())),
            Some(Type::Rancongiciel)
        );
        assert_eq!(type_de(&programme(false, "commande qui télécharge")), None);
        let mut adresse = programme(true, "x");
        adresse.geste = Geste::Adresse {
            ip: "203.0.113.7".parse().unwrap(),
        };
        assert_eq!(type_de(&adresse), Some(Type::ServeurDeCommande));
        let mut ia = programme(false, "x");
        ia.geste = Geste::ServeurIa {
            port: 11434,
            nom: "ollama".into(),
        };
        assert_eq!(type_de(&ia), Some(Type::AgentIa));
        ia.geste = Geste::Demarrage {
            id: "x".into(),
            nom: "x".into(),
            machine: false,
        };
        assert_eq!(type_de(&ia), None);
    }

    /// Bloquer refusé par ses garde-fous reste refusé dans la suite : dit, et la suite continue.
    #[test]
    fn bloquer_refuse_reste_refuse() {
        let m = Menace {
            categorie: Categorie::Programmes,
            certaine: true,
            quoi: "« essai » : x".into(),
            cle: "programme:essai-refus".into(),
            geste: Geste::Programme {
                pid: None,
                nom: "essai".into(),
                chemin: None,
                fichier: None,
                detection: "x".into(),
            },
        };
        let ctx = Contexte {
            os: crate::machine::regles::Os::actuel(),
            intouchables: std::collections::HashSet::new(),
            sessions: None,
            pare_feu: Err(Echec::refuse("essai", "x")),
            admin: false,
            interactif: false,
            mon_programme: None,
        };
        let mut apres = false;
        let d = derouler(
            &m,
            &[Etape::Bloquer, Etape::Prevenir],
            &ctx,
            true,
            Err(Echec::refuse("essai", "garde-fou")),
            &mut |d| {
                apres = matches!(d.bloque, Some(Err(_)));
                Issue::Fait("prévenu".into())
            },
        );
        assert!(apres);
        assert!(matches!(&d.issues[0].1, Issue::Echoue(r) if r.contains("garde-fou")));
        assert_eq!(d.issues[1].1, Issue::Fait("prévenu".into()));
    }
}

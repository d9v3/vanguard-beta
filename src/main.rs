//! Vanguard — cyberdéfense portable des postes et des réseaux : bilan, correctifs, réglages.
//!
//! N'utilise le scan réseau que sur un réseau qui t'appartient ou que tu as le droit d'auditer.
//! Lancé sans argument, affiche un menu.

// Débordements et `as` refusés dans tout le programme que Linux compile (LANG-ARITH, CONFORMITE-ANSSI.md) : la
// racine vaut pour chaque module. Les parties Windows ne sont pas encore relues ; les essais en sont
// exemptés (y déborder fait échouer l'essai), comme de `unwrap` (clippy.toml).
#![cfg_attr(
    all(target_os = "linux", not(test)),
    warn(clippy::arithmetic_side_effects, clippy::as_conversions)
)]
// Pas d'`unsafe` sans raison : chaque module qui appelle le système (FFI) lève ce refus pour lui seul, avec une
// ligne qui dit pourquoi ; les modules que lit le banc de fuzzing le refusent sans recours (`forbid`). Garde :
// `chaque_module_fuzze_refuse_unsafe`.
#![deny(unsafe_code)]

mod a_laisser;
// L'Agent Vanguard (sans IA) : un petit agent intégré qui règle Vanguard dans le sens sûr (voir src/agent/mod.rs).
mod agent;
// La voie ouverte de l'auto-amélioration (lot A1) : le nettoyage des textes d'erreur et le détecteur de secrets,
// que les lots suivants (A2, A3) brancheront au journal et aux lots envoyés.
#[cfg_attr(not(test), allow(dead_code))]
mod amelioration;
// Le socle d'analyse des fichiers (lot AV1 de l'antivirus maison) : ses lecteurs servent aux motifs, aux signatures
// et aux heuristiques du moteur commun (AV2 à AV4) ; quelques-uns attendent encore les lots suivants.
#[cfg_attr(not(test), allow(dead_code))]
mod analyse;
mod annulation;
mod apprentissage;
mod archives;
mod audit;
mod autotest;
#[cfg(test)]
mod canaris;
mod changements;
mod chiffrement;
mod commande;
mod compte_rendu;
mod copier;
mod corriger;
mod coulisses;
mod demarrage;
mod depanner;
mod deploiement;
mod descriptions;
mod desinstaller;
mod diagnostic;
mod dns_rapide;
mod donnees;
mod entretien;
mod envoi;
#[cfg(test)]
mod essais;
mod evenements;
mod fenetre;
mod fiche;
mod gaming;
mod guide;
mod historique;
mod http;
mod journal;
mod journaux_windows;
mod langue;
mod lenteur;
mod logiciels;
mod machine;
mod maj;
mod masque;
mod menu;
mod mise_a_jour;
mod modele;
mod nettoyer;
mod optimiser;
// Le modèle ne sert qu'à l'écran de Windows ; ailleurs, seuls ses essais le lisent (sur tous les systèmes).
#[cfg_attr(not(windows), allow(dead_code))]
mod options_defense;
mod ordinateurs;
mod parametres;
mod passage;
mod pe;
mod plugins;
mod prediction;
mod programmes_poses;
mod protection;
mod raccourci;
mod rapport;
mod recherche;
mod reparer;
mod reseau;
mod risk;
mod sauvegarde;
mod sceau;
mod selection;
mod signaler;
mod socle;
mod sqlite;
mod traces;
mod ui;
mod verifier_cle;
mod voulues;

use clap::FromArgMatches;

use machine::Audit;
use reseau::{Options, Rapport};
use ui::*;

use demarrage::aide::{aide_courte, aide_longue, ligne_de_commande};
use demarrage::arguments::{Args, Commande};
use demarrage::droits::{avertir, avertir_si_eleve, commande_d_optimiser, refuser_optimiser};
use menu::etat::fonctions_du_menu;
use menu::lancer::{cible_tapee, depanner_avec_ses_outils, executer, menu, nommer, sous_menu};
use menu::outils::{
    Action, Groupe, OUTILS, etat_de_la_protection, garde, interrupteur, interrupteurs, interrupteurs_json,
    precision_surveillance, sans_etat, veilleur,
};
use menu::recherche::chercher;

/// Résultats de la session, pour le rapport HTML et les corrections.
#[derive(Default)]
struct Session {
    audit: Option<Audit>,
    reseau: Option<Rapport>,
    /// Quand le scan du réseau local (ports courants) a fini : l'audit du réseau le réutilise s'il a moins de dix
    /// minutes.
    scan_le: Option<std::time::Instant>,
    audit_reseau: Option<audit::AuditReseau>,
    /// Le dernier outil choisi dans chaque écran d'outils, par son chemin (« Réseau et Internet », ou un écran à
    /// choix sous son groupe) : y revenir pendant la session remet la surbrillance dessus, pas sur la ligne 1.
    choisis: std::collections::HashMap<String, Action>,
}

impl Session {
    /// La ligne à mettre en surbrillance en entrant dans l'écran `chemin` : celle de l'outil choisi la dernière fois,
    /// retrouvé par l'outil et non par son numéro (un outil devenu indisponible décale les numéros) ; sinon la 1.
    fn ligne_gardee(&self, chemin: &str, actions: &[Action]) -> String {
        self.choisis
            .get(chemin)
            .and_then(|a| actions.iter().position(|b| b == a))
            .map_or(1, |i| i.saturating_add(1))
            .to_string()
    }

    async fn scanner_reseau(&mut self, cible: Option<String>, ports: &str) {
        let du_reseau_local = cible.is_none() && ports == "courants";
        match reseau::executer(Options::defaut(cible, ports)).await {
            Ok(r) => {
                self.reseau = Some(r);
                self.scan_le = du_reseau_local.then(std::time::Instant::now);
            }
            Err(e) => {
                journal::erreur(crate::compte_rendu::Contexte::ScanReseau, &e);
                eprintln!("{}", trf!("Scan réseau impossible : {e}", "Network scan failed: {e}"));
            }
        }
    }

    /// L'audit du réseau par domaine : le scan de la session s'il a moins de dix minutes, sinon un scan silencieux ;
    /// puis les six domaines, à l'écran ou en JSON. Sans réseau local, six domaines « non vérifié ».
    async fn audit_reseau(&mut self, json: bool, html: bool, invite: bool) {
        let recent = self
            .scan_le
            .is_some_and(|t| t.elapsed() < std::time::Duration::from_secs(600));
        if self.reseau.is_none() || !recent {
            if !json {
                trp!(
                    "  {GRIS}Scan du réseau local en cours…{RESET}",
                    "  {GRIS}Scanning the local network…{RESET}"
                );
            }
            let options = Options {
                silencieux: true,
                ..Options::defaut(None, "courants")
            };
            match reseau::executer(options).await {
                Ok(r) => {
                    self.reseau = Some(r);
                    self.scan_le = Some(std::time::Instant::now());
                }
                Err(e) => {
                    journal::erreur(crate::compte_rendu::Contexte::AuditReseau, &e);
                    let a = audit::AuditReseau::sans_reseau(&e);
                    audit::rendre(&a, json);
                    self.audit_reseau = Some(a);
                    if html {
                        rapport::ouvrir(None, None, self.audit_reseau.as_ref());
                    }
                    return;
                }
            }
        }
        let Some(scan) = &self.reseau else { return };
        let a = audit::auditer(scan, None, invite, false).await;
        audit::rendre(&a, json);
        self.audit_reseau = Some(a);
        if html {
            rapport::ouvrir(None, self.reseau.as_ref(), self.audit_reseau.as_ref());
        }
    }

    async fn complet(&mut self) {
        self.audit = Some(machine::executer(false));
        self.scanner_reseau(None, "courants").await;
        // L'audit du réseau par domaine, après le scan : les constats réseau du bilan qui vient de finir lui servent
        // tels quels (le domaine Postes), sans relancer ces règles.
        if let Some(scan) = &self.reseau {
            let machine = self.audit.as_ref().map(|a| {
                a.constats
                    .iter()
                    .filter(|c| audit::regle_du_reseau(c.regle))
                    .cloned()
                    .collect()
            });
            let a = audit::auditer(scan, machine, false, false).await;
            audit::afficher(&a);
            self.audit_reseau = Some(a);
        }
        // Les extensions sans restrictions qui l'ont demandé (dans_le_bilan) : à part, hors de la note.
        plugins::avec_le_bilan();
        titre(tr!("Bilan global", "Overall result"));
        let m = self.audit.as_ref().filter(|a| a.fiable()).map(|a| a.score);
        let r = self.reseau.as_ref().map(|r| r.score_global);
        let audit_reseau = self.audit_reseau.as_ref().and_then(|a| a.score);
        match m {
            Some(m) => afficher_note(tr!("Cet ordinateur", "This computer"), m),
            None => trp!(
                "  Cet ordinateur : pas de note (vérifications impossibles)",
                "  This computer: no grade (checks could not be done)"
            ),
        }
        if let Some(r) = r {
            afficher_note(tr!("Réseau", "Network"), r);
        }
        match (self.audit_reseau.as_ref(), audit_reseau) {
            (Some(_), Some(s)) => afficher_note(tr!("Audit du réseau", "Network audit"), s),
            (Some(_), None) => trp!(
                "  Audit du réseau : pas de note (domaines non vérifiés)",
                "  Network audit: no grade (domains not checked)"
            ),
            (None, _) => {}
        }
        if let Some(g) = [m, r, audit_reseau].into_iter().flatten().min() {
            afficher_note(tr!("Global", "Overall"), g);
        }
        let (precedent, nouveau) =
            historique::enregistrer_complet(self.audit.as_ref(), self.reseau.as_ref(), self.audit_reseau.as_ref());
        // Sur la clé VANGUARD branchée (partition VANGUARDLOG) : la visite de cet ordinateur, pour « Mes ordinateurs ».
        ordinateurs::noter(self.audit.as_ref(), self.reseau.as_ref());
        if let Some(p) = precedent {
            historique::afficher_changements(&p, &nouveau);
        }
        // Les menaces à bloquer : le certain tout seul si la protection active est en marche, le reste d'un clic.
        protection::blocage::au_bilan();
        let a_corriger = self.audit.as_ref().is_some_and(|a| {
            a.constats
                .iter()
                .any(|c| c.correctif.as_ref().is_some_and(|k| k.automatique))
        });
        if a_corriger {
            let cle = cle_a_molette();
            trp!(
                "\n  {cle} Des corrections sont possibles : choix « 2 » du menu ou « vanguard corriger ».",
                "\n  {cle} Fixes are available: menu choice “2” or “vanguard fix”."
            );
        }
        let _ = rapport::generer(self.audit.as_ref(), self.reseau.as_ref(), self.audit_reseau.as_ref());
    }

    /// Le code de sortie de « vanguard corriger » : `corriger::Bilan::code`.
    fn corriger(&mut self) -> i32 {
        let audit = self.audit.get_or_insert_with(|| machine::executer(false));
        let (nouveau, code) = corriger::corriger(audit, self.reseau.as_ref());
        if let Some(nouveau) = nouveau {
            self.audit = Some(nouveau);
        }
        code
    }
}

/// `vanguard optimiser [quoi]` : l'outil du menu Optimiser qui porte ce nom, lancé comme depuis le menu (la même
/// ligne de `OUTILS`, la même `executer`) ; sans nom, le sous-menu.
async fn optimiser_en_ligne_de_commande(quoi: Option<&str>) {
    let mut s = Session::default();
    let action = match quoi {
        None => return sous_menu(&mut s, Groupe::Optimiser).await,
        Some("recommandes" | "recommended") => Action::OptimiserRecommandes,
        Some("confidentialite" | "privacy") => Action::OptimiserConfidentialite,
        Some("performance") => Action::OptimiserPerformance,
        Some("confort" | "comfort") => Action::OptimiserConfort,
        Some("annuler" | "undo") => Action::OptimiserAnnuler,
        Some(_) => {
            trp!(
                "Pas de réglages de performance proposés sur ce système.",
                "No performance settings offered on this system."
            );
            return;
        }
    };
    executer(&mut s, action).await;
}

/// La portée d'une analyse demandée en ligne de commande : le dossier donné, sinon tout le dossier personnel
/// (--complet), sinon les endroits à risque.
fn portee(dossier: Option<std::path::PathBuf>, complet: bool) -> protection::antivirus::Portee {
    match (dossier, complet) {
        (Some(d), _) => protection::antivirus::Portee::Dossier(d),
        (None, true) => protection::antivirus::Portee::Complete,
        (None, false) => protection::antivirus::Portee::Rapide,
    }
}

#[tokio::main]
async fn main() {
    // La clé de données gardée pour la session, effacée à chaque retour de `main` et pendant une panique ;
    // `std::process::exit` ne détruisant rien, ses appels plus bas l'effacent eux-mêmes.
    let _oubli = chiffrement::OublierALaSortie;
    // RELRO, avant tout le reste : le démarrage de musl laisse PT_GNU_RELRO écrivable (socle/relro.rs). Un échec ne
    // tue pas le programme : Vanguard sans cette protection reste celui de la 0.88, alors que refuser de démarrer
    // laisserait la machine sans aucune de ses défenses, pour une page que rien n'attaque encore. Il est noté au
    // journal plus bas, une fois la langue et les réglages lus : ici, le texte sortirait dans la langue par défaut,
    // et le journal ferait la première écriture du programme avant qu'il sache qui il est (processus élevé compris,
    // qui ne doit rien écrire). 64 bits seulement : relro.rs lit des Elf64_Phdr, et on ne livre rien d'autre.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    let relro = crate::socle::relro::proteger();
    // Couleurs ANSI dans l'ancienne console Windows (Windows Terminal les gère déjà) : crossterm ouvre CONOUT$ et y
    // active ENABLE_VIRTUAL_TERMINAL_PROCESSING, le même appel que faisait une crate à part pour cela seul.
    #[cfg(windows)]
    let _ = crossterm::ansi_support::supports_ansi();
    // « vanguard --version » (ou -V) seul : la version, rien d'autre. Ni réglages, ni journal, ni sceaux : un verrou
    // des sceaux gardé ailleurs le faisait attendre des secondes pour une ligne connue d'avance.
    if let [v] = std::env::args_os().skip(1).collect::<Vec<_>>().as_slice()
        && (v == "--version" || v == "-V")
    {
        return println!("vanguard {}", env!("CARGO_PKG_VERSION"));
    }
    // Le garde des lancements, root, lancé par systemd : rien d'autre ne tourne avant lui (ni journal, ni passage, ni
    // réglages, qui liraient ou écriraient dans des dossiers que /root ou le compte contrôlent).
    #[cfg(target_os = "linux")]
    if std::env::args_os().skip(1).eq(["garde-servir"]) {
        std::process::exit(machine::linux::garde::servir::servir());
    }
    // L'isolement remis au démarrage (Défense R4), root, lancé par son unité avant le réseau : rien d'autre non plus.
    #[cfg(target_os = "linux")]
    if std::env::args_os().skip(1).eq(["isolement-demarrage"]) {
        std::process::exit(machine::linux::isolement::demarrage());
    }
    // Le processus élevé ne fait que sa liste : rien d'autre ne doit tourner avec le jeton administrateur (journal,
    // passage, reconnaissance de la clé écrivent dans des dossiers que le compte contrôle).
    if std::env::args_os().nth(1).is_some_and(|a| a == "appliquer-eleve") {
        // La langue du Vanguard qui demande, avant le premier texte (l'aide de clap en est un) : pkexec et run0
        // donnent au fils un environnement neuf, sans LANG.
        #[cfg(unix)]
        {
            let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
            if let Some(i) = args.iter().position(|a| a == "--langue")
                && let Some(l) = args.get(i.saturating_add(1))
            {
                langue::forcer(l == "en");
            }
        }
        let code = match Args::from_arg_matches(&ligne_de_commande().get_matches()) {
            #[cfg(windows)]
            Ok(Args {
                commande:
                    Some(Commande::AppliquerEleve {
                        canal: Some(canal),
                        parent: Some(parent),
                        ..
                    }),
                ..
            }) => machine::windows::eleve::executer(&canal, parent),
            #[cfg(unix)]
            Ok(Args {
                commande: Some(Commande::AppliquerEleve { langue, parent, .. }),
                ..
            }) => machine::assistant::executer(langue.as_deref(), parent),
            _ => 2,
        };
        std::process::exit(code);
    }
    // Les réglages du lancement (langue, emojis, travail sans Internet), avant tout affichage.
    parametres::au_lancement();
    journal::installer();
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    if let Err(e) = relro {
        journal::erreur(crate::compte_rendu::Contexte::ProtectionRelro, &e.to_string());
    }
    #[cfg(unix)]
    protection::cle::proteger_cle();
    protection::environnement::afficher();
    avertir_si_eleve();
    // Tant que dure l'isolement (Défense R4) : dit à chaque lancement, avec la commande qui le lève.
    if let Some(b) = protection::isolement::banniere() {
        avertir(&b);
    }
    passage::au_lancement();
    // Après le passage, qui a pu déplacer l'ancien dossier avec ses droits d'avant.
    #[cfg(unix)]
    crate::socle::proteger_dossier_local();
    protection::cles_connues::reconnaitre_la_cle_du_programme();
    // « vanguard -h » ou « --help » seuls : les aides générées depuis le menu (`aide_courte`, `aide_longue`). L'aide
    // d'une commande reste celle de clap (« vanguard bilan --help »), et « vanguard help » sa liste à plat, dans
    // l'ordre des déclarations (outils/page-fonctions.py la lit). args_os : un argument qui n'est pas de l'UTF-8
    // (un nom de fichier) ne doit pas arrêter le programme ici.
    let premiers: Vec<std::ffi::OsString> = std::env::args_os().skip(1).take(2).collect();
    match premiers.as_slice() {
        [h] if h == "-h" => return print!("{}", aide_courte()),
        [h] if h == "--help" => return print!("{}", aide_longue()),
        _ => {}
    }
    let matches = ligne_de_commande().get_matches();
    let args = Args::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    // Le lot d'amélioration en attente, dans un fil qui ne retarde jamais la sortie (rien sans relais). Ni pendant
    // un autotest, qui se met hors ligne après ce point, ni pour la passe horaire, qui le lance elle-même et
    // l'attend.
    if !matches!(
        args.commande,
        Some(Commande::Autotest { .. } | Commande::Surveiller | Commande::Agent { .. })
    ) {
        crate::envoi::en_fond(false);
    }
    // Le relevé local ne garde que le nom d'une sous-commande qui est un outil de la table, jamais ses arguments.
    let outil_ligne = matches
        .subcommand_name()
        .and_then(|n| OUTILS.iter().find(|o| !o.commande.is_empty() && o.commande == n))
        .map(|o| o.commande);
    if let Some(c) = outil_ligne {
        crate::amelioration::ligne_lancee(c);
    }
    if args.commande.as_ref().is_some_and(commande_d_optimiser) && refuser_optimiser() {
        machine::quitter(2);
    }
    match args.commande {
        // La fenêtre de Vanguard quand elle est là et que la personne est devant un écran ; sinon le menu.
        None => {
            if args.menu || !demarrage::lancer_fenetre::ouvrir() {
                menu().await;
            }
        }
        Some(Commande::Complet { html, texte }) => {
            let mut s = Session::default();
            s.complet().await;
            if html {
                rapport::ouvrir(s.audit.as_ref(), s.reseau.as_ref(), s.audit_reseau.as_ref());
            }
            if texte {
                println!(
                    "\n{}",
                    rapport::markdown(s.audit.as_ref(), s.reseau.as_ref(), s.audit_reseau.as_ref())
                );
            }
        }
        Some(Commande::Machine { json }) => {
            machine::executer(json);
        }
        Some(Commande::Corriger) => {
            let code = Session::default().corriger();
            if code != 0 {
                machine::quitter(code);
            }
        }
        Some(Commande::Reseau {
            cible,
            ports,
            timeout,
            parallele,
            json,
        }) => {
            // Une cible mal tapée est une erreur de la personne, dite ici, pas un défaut du programme pour le journal.
            if let Some(Some(Err(e))) = cible.as_deref().map(cible_tapee) {
                eprintln!("{}", trf!("Erreur : {e}", "Error: {e}"));
                machine::quitter(2);
            }
            let o = Options {
                cible,
                ports,
                timeout,
                parallele,
                json,
                silencieux: false,
            };
            if let Err(e) = reseau::executer(o).await {
                journal::erreur(crate::compte_rendu::Contexte::ScanReseau, &e);
                eprintln!("{}", trf!("Erreur : {e}", "Error: {e}"));
                machine::quitter(1);
            }
        }
        Some(Commande::AuditReseau { json, html, invite }) => {
            Session::default().audit_reseau(json, html, invite).await;
        }
        Some(Commande::Antivirus {
            etat: true, json: true, ..
        }) => protection::etat_antivirus::json(),
        Some(Commande::Antivirus { json: true, .. }) => protection::antivirus::json(),
        Some(Commande::Antivirus { etat: true, detail, .. }) => {
            protection::etat_antivirus::montrer(if detail {
                protection::etat_antivirus::Detail::Oui
            } else {
                protection::etat_antivirus::Detail::Non
            });
        }
        Some(Commande::Antivirus { complet, dossier, .. }) => protection::antivirus::analyser(portee(dossier, complet)),
        Some(Commande::Surveillance { etat }) => match etat.as_str() {
            "on" | "off" => reseau::surveillance::activer(etat == "on"),
            _ => println!(
                "  {} : {}",
                tr!("Surveillance toutes les heures", "Hourly monitoring"),
                precision_surveillance(
                    reseau::surveillance::active(),
                    protection::temps_reel::coupure().is_some()
                )
            ),
        },
        Some(Commande::Tableau { sans_ouvrir }) => reseau::tableau::ouvrir(sans_ouvrir, fonctions_du_menu()),
        Some(Commande::Veilleur {
            etat,
            sous_etat,
            servir,
        }) => veilleur(sans_etat(etat.as_deref()), sans_etat(sous_etat.as_deref()), servir),
        Some(Commande::Garde { action, argument }) => garde(action.as_deref(), argument.as_deref()),
        Some(Commande::SitesDangereux { etat }) => protection::sites_bloques::commande(sans_etat(etat.as_deref())),
        Some(Commande::DernieresFailles { jours, json }) => {
            if json {
                protection::kev::json(jours);
            } else {
                protection::kev::ecran(jours);
            }
        }
        Some(Commande::Surveiller) => reseau::surveillance::surveiller().await,
        Some(Commande::Entretien { etat }) => match sans_etat(etat.as_deref()) {
            Some(e) => entretien::activer(e == "on"),
            None => entretien::maintenant(),
        },
        Some(Commande::Entretenir) => entretien::entretenir(),
        // Traité au tout début de main, avant tout le reste : jamais ici.
        Some(Commande::AppliquerEleve { .. } | Commande::GardeServir) => machine::quitter(2),
        Some(Commande::Maj { json }) => {
            if json {
                maj::json();
            } else {
                maj::executer();
            }
        }
        Some(Commande::Reparer) => reparer::menu(),
        Some(Commande::Gaming) => gaming::menu(),
        Some(Commande::Nettoyer { liste }) => {
            if liste {
                nettoyer::liste();
            } else {
                nettoyer::menu();
            }
        }
        Some(Commande::Connexion { json: false }) => reseau::connexion::tester().await,
        Some(Commande::Connexion { json: true }) => reseau::connexion::json().await,
        Some(Commande::Diagnostic { json: false }) => diagnostic::diagnostic(),
        Some(Commande::Diagnostic { json: true }) => diagnostic::json(),
        Some(Commande::Logiciels { liste, recommandes }) => {
            if liste {
                logiciels::liste();
            } else if recommandes {
                logiciels::recommandes();
            } else {
                logiciels::menu();
            }
        }
        Some(Commande::MotDePasse) => protection::fuites::verifier(),
        Some(Commande::Navigateurs) => machine::mots_de_passe::navigateurs(),
        Some(Commande::Courriel) => protection::fuites::verifier_courriel(),
        // Un seul écran, sans la boucle du menu (clé abuse.ch, « Après une infection ») : une commande se lit d'un
        // script. Le menu, lui, lance `sortantes::menu`, qui montre le même écran puis propose la suite.
        Some(Commande::Sortantes { json: false }) => protection::sortantes::afficher(),
        Some(Commande::Sortantes { json: true }) => protection::sortantes::json(),
        Some(Commande::Distance { json: false }) => protection::distance::menu(),
        Some(Commande::Distance { json: true }) => protection::distance::json(),
        Some(Commande::VerifierMoi { programme }) => protection::manifeste::verifier_moi(programme.as_deref()),
        Some(Commande::Manifeste {
            ecrire,
            forcer,
            accepter,
            images,
            image,
        }) => {
            protection::manifeste::commande(
                ecrire.as_deref(),
                forcer,
                accepter,
                images.as_deref().map(|d| (d, &image[..])),
            );
        }
        Some(Commande::CompteRendu { quoi }) => {
            let code = compte_rendu::executer(&quoi);
            if code != 0 {
                chiffrement::oublier_session();
                std::process::exit(code);
            }
        }
        Some(Commande::Deploiement { etape }) => {
            let code = deploiement::executer(etape);
            if code != 0 {
                chiffrement::oublier_session();
                std::process::exit(code);
            }
        }
        Some(Commande::Lien {
            adresse, json: false, ..
        }) => protection::lien::verifier(Some(&adresse)),
        Some(Commande::Lien {
            adresse,
            json: true,
            internet,
        }) => protection::lien::json(&adresse, internet),
        Some(Commande::VerifierFichier {
            fichier,
            empreinte,
            json: false,
        }) => {
            protection::telechargement::verifier(Some(&fichier), empreinte.as_deref());
        }
        Some(Commande::VerifierFichier {
            fichier,
            empreinte,
            json: true,
        }) => protection::telechargement::json(&fichier, empreinte.as_deref()),
        Some(Commande::CourrielSuspect { fichier, json: false }) => {
            protection::courriel_suspect::verifier(Some(&fichier));
        }
        Some(Commande::CourrielSuspect { fichier, json: true }) => protection::courriel_suspect::json(&fichier),
        Some(Commande::LogicielsEspions { json: false }) => protection::espions::afficher(),
        Some(Commande::LogicielsEspions { json: true }) => protection::espions::json(),
        Some(Commande::LogicielsPerimes { json: false }) => protection::perimes::afficher(),
        Some(Commande::LogicielsPerimes { json: true }) => protection::perimes::json(),
        Some(Commande::OptionsDefense {
            choisir: Some(choix), ..
        }) => {
            let (id, valeur) = (
                choix.first().map_or("", String::as_str),
                choix.get(1).map_or("", String::as_str),
            );
            machine::quitter(i32::from(!options_defense::choisir(id, valeur)));
        }
        Some(Commande::OptionsDefense { rallumer: Some(id), .. }) => {
            machine::quitter(i32::from(!options_defense::rallumer(&id)))
        }
        Some(Commande::OptionsDefense { exclure: Some(e), .. }) => {
            let (genre, texte) = (
                e.first().map_or("", String::as_str),
                e.get(1).map_or("", String::as_str),
            );
            machine::quitter(i32::from(!options_defense::exclure(genre, texte)));
        }
        Some(Commande::OptionsDefense { permettre: Some(p), .. }) => {
            machine::quitter(i32::from(!options_defense::permettre(&p)))
        }
        Some(Commande::OptionsDefense { noter: Some(id), .. }) => {
            machine::quitter(i32::from(!options_defense::noter(&id)))
        }
        Some(Commande::OptionsDefense {
            remettre: Some(mot), ..
        }) => machine::quitter(i32::from(!options_defense::remettre(&mot))),
        Some(Commande::OptionsDefense { json: false, .. }) => options_defense::afficher(),
        Some(Commande::OptionsDefense { json: true, .. }) => options_defense::afficher_json(),
        Some(Commande::Signaler {
            incident,
            outil,
            programme,
            langue,
            json,
            effacer,
        }) => signaler::commande(&signaler::Options {
            incident,
            outil,
            programme,
            langue,
            json,
            effacer,
        }),
        Some(Commande::CameraMicro) => protection::camera::afficher_tout(),
        Some(Commande::Acces { json: false }) => protection::acces::afficher_tout(),
        Some(Commande::Acces { json: true }) => protection::acces::json(),
        Some(Commande::Quarantaine) => protection::quarantaine::menu(),
        Some(Commande::Secrets) => protection::secrets_git::analyser(),
        Some(Commande::Conteneurs) => protection::conteneurs::analyser(),
        Some(Commande::Blocage { quoi }) => protection::blocage::commande(&quoi),
        Some(Commande::Parametres { quoi }) => parametres::commande(&quoi),
        Some(Commande::Chercher { mots, premier, json }) => {
            if !chercher(&mots.join(" "), premier, json).await {
                machine::quitter(1);
            }
        }
        // Le rapport du dernier bilan s'il a moins d'une heure ; sinon un bilan complet d'abord.
        Some(Commande::Rapport) => {
            if let Some(chemin) = rapport::recent(std::time::Duration::from_secs(3600)) {
                trp!("  Rapport : {}", "  Report: {}", chemin.display());
                machine::ouvrir(&chemin.display().to_string());
            } else {
                let mut s = Session::default();
                executer(&mut s, Action::Rapport).await;
            }
        }
        Some(Commande::Annuler) => optimiser::tout_annuler(),
        // `quoi` prend tout ce qui suit le premier mot (trailing_var_arg) : « etat --json » y laisse --json, qui vaut
        // pourtant pour la commande ; sans cela, l'écran sortait là où un script attendait du JSON.
        Some(Commande::Protection { json, quoi }) if json || quoi.iter().any(|m| m == "--json") => {
            let mots: Vec<&String> = quoi.iter().filter(|m| *m != "--json").collect();
            let etat = match mots.as_slice() {
                [] => true,
                [mot] => interrupteur(mot).as_deref() == Ok("etat"),
                _ => false,
            };
            if !etat {
                eprintln!(
                    "  ✖ {}",
                    tr!(
                        "--json montre l'état seulement : sans oui ni non",
                        "--json shows the state only: without on or off"
                    )
                );
                machine::quitter(2);
            }
            println!("{}", interrupteurs_json(&interrupteurs()));
        }
        Some(Commande::Protection { quoi, .. }) => match quoi.split_first() {
            None => etat_de_la_protection(),
            Some((valeur, reste)) => match interrupteur(valeur).as_deref() {
                Ok("etat") => etat_de_la_protection(),
                // oui, marche, on… : la valeur que « parametres temps-reel » connaît.
                Ok(v) => {
                    let mots: Vec<String> = ["temps-reel".to_string(), v.to_string()]
                        .into_iter()
                        .chain(reste.iter().cloned())
                        .collect();
                    parametres::commande(&mots);
                }
                Err(e) => {
                    eprintln!("  ✖ {e}");
                    machine::quitter(2);
                }
            },
        },
        Some(Commande::Isoler { fichier }) => protection::isoler::isoler(&fichier),
        Some(Commande::Pieges { retirer }) => protection::pieges::commande(retirer),
        // La portée vient des options ; le menu la demande (`yara::menu`), puis lance la même analyse.
        Some(Commande::Yara { json: true, .. }) => protection::yara::json(),
        Some(Commande::Yara { complet, dossier, .. }) => protection::yara::analyser(&portee(dossier, complet)),
        Some(Commande::Memoire { json: false }) => protection::memoire::analyser(),
        Some(Commande::Memoire { json: true }) => protection::memoire::json(),
        Some(Commande::ListesNoires { json: false, .. }) => reseau::listes_noires::verifier(),
        Some(Commande::ListesNoires { json: true, internet }) => reseau::listes_noires::json(internet),
        Some(Commande::Canaux) => reseau::canaux::analyser(),
        Some(Commande::Nat) => reseau::nat::tester(),
        Some(Commande::Cameras) => reseau::cameras::chercher_cameras().await,
        Some(Commande::Objets { json: false }) => reseau::objets::montrer(),
        Some(Commande::Objets { json: true }) => reseau::objets::json(),
        Some(Commande::DnsRapide) => dns_rapide::mesurer_et_proposer(),
        Some(Commande::Optimiser { quoi }) => optimiser_en_ligne_de_commande(quoi.as_deref()).await,
        Some(Commande::WifiPublic { etat }) => reseau::wifi_public::commande(sans_etat(etat.as_deref())),
        Some(Commande::Appris) => apprentissage::menu(),
        Some(Commande::Integrite {
            accepter,
            temps_reel,
            json,
        }) => {
            if json {
                protection::integrite::json();
            } else if temps_reel {
                protection::integrite::temps_reel();
            } else {
                protection::integrite::verifier(accepter);
            }
        }
        Some(Commande::Sauvegarder { fichier }) => donnees::sauvegarder(fichier),
        Some(Commande::Restaurer { fichier }) => donnees::restaurer(&fichier),
        Some(Commande::Nommer { appareil, surnom }) => nommer(&appareil, &surnom.join(" ")),
        Some(Commande::Guide { quoi, sommaire }) => guide::executer(&quoi.join(" "), sommaire),
        Some(Commande::Lenteur { json: false }) => lenteur::commande(),
        Some(Commande::Lenteur { json: true }) => lenteur::json(),
        Some(Commande::Demarrage { json }) => {
            if json {
                optimiser::demarrage_json();
            } else {
                optimiser::programmes_au_demarrage();
            }
        }
        Some(Commande::Fiche { json }) => fiche::fiche(json),
        Some(Commande::CopierFichiers { destination }) => copier::commande(destination.as_deref()),
        Some(Commande::VerifierCopie { dossier }) => copier::verifier_copie(dossier.as_deref()),
        Some(Commande::VerifierSauvegarde) => sauvegarde::verifier_sauvegarde(),
        Some(Commande::VerifierCle { dossier }) => verifier_cle::commande(dossier.as_deref()),
        Some(Commande::Changements) => changements::afficher(),
        Some(Commande::Evenements { json, incident }) => evenements::afficher(json, incident.as_deref()),
        Some(Commande::Alerte { id }) => protection::blocage::alerte(&id),
        Some(Commande::JournauxWindows { dossier, jours, json }) => {
            journaux_windows::commande::executer(dossier.as_deref(), jours, json);
        }
        Some(Commande::ALaisser) => a_laisser::laisser(&machine::executer(false)),
        Some(Commande::SauvegardeAuto { annuler }) => {
            if annuler {
                sauvegarde::annuler();
            } else {
                sauvegarde::menu();
            }
        }
        Some(Commande::Raccourci { etat }) => raccourci::commande(sans_etat(etat.as_deref()).map(|e| e == "on")),
        Some(Commande::Ordinateurs) => ordinateurs::menu(),
        Some(Commande::SeMettreAJour) => mise_a_jour::commande(),
        Some(Commande::Desinstaller { liste }) => desinstaller::commande(liste),
        Some(Commande::Regles) => machine::regles::afficher(),
        // En lecture seule : ni envoi en fond (plus haut), ni tour de sortie de l'agent (plus bas), qui écriraient.
        Some(Commande::Agent { json }) => {
            if json {
                use std::io::Write as _;
                let o = agent::sortie::json_dans(&socle::dossier_local());
                if std::io::stdout().lock().write_all(&o).is_err() {
                    machine::quitter(1);
                }
            } else {
                parametres::agent::afficher_tout();
            }
            return;
        }
        Some(Commande::Autotest {
            json,
            compte_rendu,
            internet,
            detail,
            une_par_une,
        }) => {
            let code = autotest::executer(&autotest::Options {
                json,
                compte_rendu,
                internet,
                detail,
                une_par_une,
            });
            // La sortie du processus arrête aussi une règle restée bloquée au-delà de son délai.
            machine::quitter(code);
        }
        Some(Commande::Depanner { sujet }) if sujet.is_empty() => depanner_avec_ses_outils(),
        // « depanner traces [dossier] » : la collecte, comme l'ancienne commande « traces », avec son code de sortie
        // (1 si elle a échoué) pour un script ou une tâche ; le menu passe par le parcours 11.11 et son conseil.
        Some(Commande::Depanner { sujet })
            if sujet.len() <= 2 && matches!(sujet.first().map(String::as_str), Some("traces" | "evidence")) =>
        {
            if !traces::commande(sujet.get(1).map(std::path::Path::new)) {
                machine::quitter(1);
            }
        }
        Some(Commande::Depanner { sujet }) => depanner::executer(&sujet.join(" ")),
        Some(Commande::Plugin { quoi }) => {
            let code = plugins::commande(&quoi);
            if code != 0 {
                machine::quitter(code);
            }
        }
        Some(Commande::Labo { quoi }) => {
            let code = plugins::labo::commande(&quoi);
            if code != 0 {
                machine::quitter(code);
            }
        }
        Some(Commande::Extensions { sans_restrictions }) => match sans_restrictions {
            None => plugins::extensions(),
            Some(etat) => {
                let code = plugins::regler_restrictions(etat == "on");
                if code != 0 {
                    machine::quitter(code);
                }
            }
        },
    }
    crate::amelioration::ligne_finie();
    // Ce que le relevé local a noté, versé avant de partir (rien à noter : rien de lu).
    crate::agent::tic(crate::agent::Moment::Sortie);
    // Une page ouverte juste avant la fin (« vanguard rapport », le tableau de bord) : son ouverture aboutit avant
    // que le processus ne parte.
    machine::attendre_ouvertures();
    // Les événements remis faute de verrou du journal, écrits avant que la commande ne parte avec eux.
    modele::journal::ecrire_differes();
}

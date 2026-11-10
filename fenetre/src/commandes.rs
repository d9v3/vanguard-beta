//! La liste fermée : les seules commandes de `vanguard` que la fenêtre sait lancer, chacune avec ses arguments
//! fixés ici, dans le code. Un clic ou une saisie choisit une entrée de cette liste, jamais un texte : aucun argument
//! libre ne part vers `vanguard`, et une saisie qui n'est pas un nom de la liste ne lance rien. Lot 1 : des commandes
//! qui ne changent rien à l'ordinateur (elles lisent, et notent leur résultat dans les données de Vanguard).

use std::time::Duration;

/// Les rubriques du rail, dans l'ordre du menu de Vanguard.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Rubrique {
    Accueil,
    Ordinateur,
    Reseau,
    Virus,
    Arnaques,
    Bloquer,
    Donnees,
    Guide,
    Depanner,
    Optimiser,
    Vanguard,
}

impl Rubrique {
    pub const TOUTES: [Rubrique; 11] = [
        Rubrique::Accueil,
        Rubrique::Ordinateur,
        Rubrique::Reseau,
        Rubrique::Virus,
        Rubrique::Arnaques,
        Rubrique::Bloquer,
        Rubrique::Donnees,
        Rubrique::Guide,
        Rubrique::Depanner,
        Rubrique::Optimiser,
        Rubrique::Vanguard,
    ];

    /// Le nom du rail, coupé en lignes courtes.
    pub fn nom_court(self) -> &'static str {
        match self {
            Rubrique::Accueil => crate::tr!("Menu\nprincipal", "Main\nmenu"),
            Rubrique::Ordinateur => crate::tr!("Cet\nordinateur", "This\ncomputer"),
            Rubrique::Reseau => crate::tr!("Réseau et\nInternet", "Network and\nInternet"),
            Rubrique::Virus => crate::tr!("Virus et\nlogiciels\nespions", "Viruses\nand\nspyware"),
            Rubrique::Arnaques => crate::tr!("Arnaques et\nvie privée", "Scams and\nprivacy"),
            Rubrique::Bloquer => crate::tr!("Bloquer et\nréagir", "Block and\nrespond"),
            Rubrique::Donnees => crate::tr!("Données et\nsauvegardes", "Data and\nbackups"),
            Rubrique::Guide => crate::tr!("Guide des\ncommandes", "Command\nguide"),
            Rubrique::Depanner => crate::tr!("Dépanner\npas à pas", "Step-by-step\nhelp"),
            Rubrique::Optimiser => crate::tr!("Optimiser et\ninstaller", "Optimize and\ninstall"),
            Rubrique::Vanguard => "Vanguard",
        }
    }

    /// Le nom en titre, sur une ligne.
    pub fn nom(self) -> &'static str {
        match self {
            Rubrique::Accueil => crate::tr!("Vue d'ensemble", "Overview"),
            Rubrique::Ordinateur => crate::tr!("Cet ordinateur", "This computer"),
            Rubrique::Reseau => crate::tr!("Réseau et Internet", "Network and Internet"),
            Rubrique::Virus => crate::tr!("Virus et logiciels espions", "Viruses and spyware"),
            Rubrique::Arnaques => crate::tr!("Arnaques et vie privée", "Scams and privacy"),
            Rubrique::Bloquer => crate::tr!("Bloquer et réagir", "Block and respond"),
            Rubrique::Donnees => crate::tr!("Données et sauvegardes", "Data and backups"),
            Rubrique::Guide => crate::tr!("Guide des commandes", "Command guide"),
            Rubrique::Depanner => crate::tr!("Dépanner pas à pas", "Step-by-step help"),
            Rubrique::Optimiser => crate::tr!("Optimiser et installer", "Optimize and install"),
            Rubrique::Vanguard => "Vanguard",
        }
    }

    /// Les commandes de la liste rangées dans cette rubrique.
    pub fn commandes(self) -> impl Iterator<Item = Commande> {
        Commande::TOUTES.into_iter().filter(move |c| c.rubrique() == self)
    }
}

/// La forme de ce que la commande écrit sur sa sortie : la fenêtre choisit son lecteur d'après elle.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Forme {
    /// `audit --json` : note, fiabilité, constats.
    Audit,
    /// Le résultat commun des outils (`modele::resultat` de Vanguard) : couverture et constats.
    Resultat,
    /// `protection --json` : les interrupteurs.
    Protection,
    /// `evenements --json` : le journal.
    Evenements,
    /// Un autre JSON, montré tel quel (clés et valeurs), borné.
    Libre,
}

/// Une commande de la liste fermée.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Commande {
    Bilan,
    Protection,
    Evenements,
    Diagnostic,
    TestConnexion,
    ConnexionsSortantes,
    AccesADistance,
    LogicielsEspions,
    LogicielsPerimes,
    BilanConfidentialite,
    Lenteur,
    FicheOrdinateur,
    OptionsDefense,
}

impl Commande {
    pub const TOUTES: [Commande; 13] = [
        Commande::Bilan,
        Commande::Protection,
        Commande::Evenements,
        Commande::Diagnostic,
        Commande::TestConnexion,
        Commande::ConnexionsSortantes,
        Commande::AccesADistance,
        Commande::LogicielsEspions,
        Commande::LogicielsPerimes,
        Commande::BilanConfidentialite,
        Commande::Lenteur,
        Commande::FicheOrdinateur,
        Commande::OptionsDefense,
    ];

    /// Le nom tapé dans la console (français).
    pub fn nom(self) -> &'static str {
        match self {
            Commande::Bilan => "bilan",
            Commande::Protection => "protection",
            Commande::Evenements => "evenements",
            Commande::Diagnostic => "diagnostic",
            Commande::TestConnexion => "test-connexion",
            Commande::ConnexionsSortantes => "connexions-sortantes",
            Commande::AccesADistance => "acces-a-distance",
            Commande::LogicielsEspions => "logiciels-espions",
            Commande::LogicielsPerimes => "logiciels-perimes",
            Commande::BilanConfidentialite => "bilan-confidentialite",
            Commande::Lenteur => "lenteur",
            Commande::FicheOrdinateur => "fiche-ordinateur",
            Commande::OptionsDefense => "options-defense",
        }
    }

    /// Le nom anglais, accepté aussi (les alias de Vanguard).
    pub fn nom_anglais(self) -> &'static str {
        match self {
            Commande::Bilan => "check",
            Commande::Protection => "protection",
            Commande::Evenements => "events",
            Commande::Diagnostic => "diagnostics",
            Commande::TestConnexion => "connection-test",
            Commande::ConnexionsSortantes => "outbound-connections",
            Commande::AccesADistance => "remote-access",
            Commande::LogicielsEspions => "spyware",
            Commande::LogicielsPerimes => "outdated-software",
            Commande::BilanConfidentialite => "privacy-review",
            Commande::Lenteur => "slow",
            Commande::FicheOrdinateur => "specs",
            Commande::OptionsDefense => "defense-options",
        }
    }

    /// Le nom montré dans la langue de l'interface.
    pub fn nom_affiche(self) -> &'static str {
        if crate::langue::anglais() {
            self.nom_anglais()
        } else {
            self.nom()
        }
    }

    /// Les arguments donnés à `vanguard`, fixés ici. Chacun écrit du JSON et ne pose aucune question (stdin fermé).
    /// « bilan » lance l'audit de cet ordinateur (`audit --json`), pas le bilan complet du terminal, qui demande.
    pub fn arguments(self) -> &'static [&'static str] {
        match self {
            Commande::Bilan => &["audit", "--json"],
            Commande::Protection => &["protection", "--json"],
            Commande::Evenements => &["evenements", "--json"],
            Commande::Diagnostic => &["diagnostic", "--json"],
            Commande::TestConnexion => &["test-connexion", "--json"],
            Commande::ConnexionsSortantes => &["connexions-sortantes", "--json"],
            Commande::AccesADistance => &["acces-a-distance", "--json"],
            Commande::LogicielsEspions => &["logiciels-espions", "--json"],
            Commande::LogicielsPerimes => &["logiciels-perimes", "--json"],
            Commande::BilanConfidentialite => &["bilan-confidentialite", "--json"],
            Commande::Lenteur => &["lenteur", "--json"],
            Commande::FicheOrdinateur => &["fiche-ordinateur", "--json"],
            Commande::OptionsDefense => &["options-defense", "--json"],
        }
    }

    /// Le délai au-delà duquel la commande est arrêtée (son groupe tué) : l'audit en prend quelques secondes, les
    /// outils qui lisent une liste en ligne jusqu'à quelques minutes sur une connexion lente.
    pub fn delai(self) -> Duration {
        Duration::from_secs(match self {
            Commande::Bilan | Commande::LogicielsEspions | Commande::LogicielsPerimes => 300,
            Commande::TestConnexion | Commande::ConnexionsSortantes | Commande::Lenteur => 180,
            _ => 120,
        })
    }

    pub fn forme(self) -> Forme {
        match self {
            Commande::Bilan => Forme::Audit,
            Commande::Protection => Forme::Protection,
            Commande::Evenements => Forme::Evenements,
            Commande::FicheOrdinateur | Commande::OptionsDefense => Forme::Libre,
            _ => Forme::Resultat,
        }
    }

    /// Le titre de son écran.
    pub fn titre(self) -> &'static str {
        match self {
            Commande::Bilan => crate::tr!("Bilan de cet ordinateur", "Check of this computer"),
            Commande::Protection => crate::tr!("Protection", "Protection"),
            Commande::Evenements => crate::tr!("Alertes et événements", "Alerts and events"),
            Commande::Diagnostic => crate::tr!("Diagnostic du réseau", "Network diagnostics"),
            Commande::TestConnexion => crate::tr!("Test de la connexion", "Connection test"),
            Commande::ConnexionsSortantes => crate::tr!("Connexions sortantes", "Outbound connections"),
            Commande::AccesADistance => crate::tr!("Accès à distance", "Remote access"),
            Commande::LogicielsEspions => crate::tr!("Logiciels espions", "Spyware"),
            Commande::LogicielsPerimes => crate::tr!("Logiciels périmés", "Outdated software"),
            Commande::BilanConfidentialite => crate::tr!("Bilan de confidentialité", "Privacy review"),
            Commande::Lenteur => crate::tr!("Pourquoi c'est lent", "Why it is slow"),
            Commande::FicheOrdinateur => crate::tr!("Fiche de l'ordinateur", "Computer specs"),
            Commande::OptionsDefense => crate::tr!("Options de défense", "Defense options"),
        }
    }

    /// Ce qu'elle fait, en une phrase.
    pub fn description(self) -> &'static str {
        match self {
            Commande::Bilan => crate::tr!(
                "Pare-feu, comptes, mises à jour, chiffrement, persistance… tout se lit sur cet ordinateur.",
                "Firewall, accounts, updates, encryption, persistence… all read on this computer."
            ),
            Commande::Protection => crate::tr!(
                "L'état de chaque interrupteur de la protection. Rien n'est changé.",
                "The state of each protection switch. Nothing is changed."
            ),
            Commande::Evenements => crate::tr!(
                "Le journal de Vanguard : alertes, preuves, actions, et s'il est intact.",
                "Vanguard's journal: alerts, evidence, actions, and whether it is intact."
            ),
            Commande::Diagnostic => crate::tr!(
                "Carte réseau, passerelle, DNS : ce qui marche et ce qui bloque.",
                "Network card, gateway, DNS: what works and what is stuck."
            ),
            Commande::TestConnexion => crate::tr!(
                "Débit, latence et noms de domaine, mesurés en ligne.",
                "Speed, latency and domain names, measured online."
            ),
            Commande::ConnexionsSortantes => crate::tr!(
                "Les programmes qui parlent à Internet en ce moment.",
                "The programs talking to the Internet right now."
            ),
            Commande::AccesADistance => crate::tr!(
                "Bureau à distance, SSH, outils de prise en main : ce qui est ouvert.",
                "Remote desktop, SSH, remote-control tools: what is open."
            ),
            Commande::LogicielsEspions => crate::tr!(
                "Les logiciels espions connus (liste d'Échap), cherchés sur cet ordinateur.",
                "Known stalkerware (Échap's list), searched for on this computer."
            ),
            Commande::LogicielsPerimes => crate::tr!(
                "Les logiciels qui n'ont plus leurs mises à jour de sécurité.",
                "Software that no longer gets security updates."
            ),
            Commande::BilanConfidentialite => crate::tr!(
                "Caméra, micro, position : quelles applications y ont accès.",
                "Camera, microphone, location: which apps can use them."
            ),
            Commande::Lenteur => crate::tr!(
                "Ce qui force en ce moment : processeur, mémoire, disque.",
                "What is straining right now: processor, memory, disk."
            ),
            Commande::FicheOrdinateur => crate::tr!(
                "Le modèle, le processeur, la mémoire et les disques, sans numéro de série.",
                "Model, processor, memory and disks, without serial numbers."
            ),
            Commande::OptionsDefense => crate::tr!(
                "Les baisses de protection choisies, et ce qui peut se rallumer.",
                "The protection decreases you chose, and what can be turned back on."
            ),
        }
    }

    pub fn rubrique(self) -> Rubrique {
        match self {
            Commande::Bilan | Commande::FicheOrdinateur | Commande::Lenteur => Rubrique::Ordinateur,
            Commande::Diagnostic
            | Commande::TestConnexion
            | Commande::ConnexionsSortantes
            | Commande::AccesADistance => Rubrique::Reseau,
            Commande::LogicielsEspions => Rubrique::Virus,
            Commande::BilanConfidentialite => Rubrique::Arnaques,
            Commande::Protection | Commande::Evenements | Commande::OptionsDefense => Rubrique::Bloquer,
            Commande::LogicielsPerimes => Rubrique::Optimiser,
        }
    }
}

/// Ce qu'une saisie de la console demande.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Saisie {
    /// Rien (ligne vide).
    Rien,
    /// Une commande de la liste.
    Lancer(Commande),
    /// La liste des commandes permises, sans rien lancer.
    Aide,
    /// Vider la console.
    Effacer,
    /// Tout le reste : rien n'est lancé. Le texte tapé, nettoyé et coupé, pour le redire.
    Refusee(String),
}

/// Les mots de la console qui ne lancent rien.
const AIDE: [&str; 3] = ["aide", "help", "?"];
const EFFACER: [&str; 2] = ["effacer", "clear"];

/// Lit une saisie de la console : un seul mot, nom français ou anglais d'une commande de la liste (« vanguard »
/// devant est permis), sans argument. Tout autre texte est refusé tel quel : jamais découpé, jamais complété,
/// jamais passé à un programme.
pub fn comprendre(saisie: &str) -> Saisie {
    let t = saisie.trim();
    if t.is_empty() {
        return Saisie::Rien;
    }
    let refus = || Saisie::Refusee(crate::nettoyage::nom(t, 60));
    let mots: Vec<&str> = t.split_whitespace().collect();
    let mot = match mots.as_slice() {
        [m] => *m,
        [v, m] if v.eq_ignore_ascii_case("vanguard") => *m,
        _ => return refus(),
    };
    let m = mot.to_ascii_lowercase();
    if AIDE.contains(&m.as_str()) {
        return Saisie::Aide;
    }
    if EFFACER.contains(&m.as_str()) {
        return Saisie::Effacer;
    }
    Commande::TOUTES
        .into_iter()
        .find(|c| c.nom() == m || c.nom_anglais() == m)
        .map_or_else(refus, Saisie::Lancer)
}

/// Complète un début de nom (touche Tab) quand un seul nom de la liste commence ainsi.
pub fn completer(debut: &str) -> Option<&'static str> {
    let d = debut.trim().to_ascii_lowercase();
    if d.is_empty() {
        return None;
    }
    let mut noms: Vec<&'static str> = Commande::TOUTES
        .iter()
        .map(|c| c.nom_affiche())
        .chain([crate::tr!("aide", "help"), crate::tr!("effacer", "clear")])
        .filter(|n| n.starts_with(&d))
        .collect();
    noms.dedup();
    match noms.as_slice() {
        [un] => Some(*un),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chaque_commande_a_des_noms_uniques_et_du_json() {
        let mut noms: Vec<&str> = Commande::TOUTES.iter().map(|c| c.nom()).collect();
        // « protection » est le même mot dans les deux langues.
        noms.extend(
            Commande::TOUTES
                .iter()
                .map(|c| c.nom_anglais())
                .filter(|n| *n != "protection"),
        );
        let avant = noms.len();
        noms.sort_unstable();
        noms.dedup();
        assert_eq!(noms.len(), avant, "un nom sert deux fois");
        for c in Commande::TOUTES {
            let a = c.arguments();
            // Toujours deux arguments : la sous-commande et --json, rien d'autre (aucun mot qui agit : « oui »,
            // « non », --choisir, --rallumer…).
            assert_eq!(a.len(), 2, "{c:?}");
            assert_eq!(a.get(1), Some(&"--json"), "{c:?}");
            assert!(!AIDE.contains(&c.nom()) && !EFFACER.contains(&c.nom()));
            assert!(c.delai().as_secs() >= 60 && c.delai().as_secs() <= 300, "{c:?}");
        }
    }

    #[test]
    fn la_console_n_accepte_que_la_liste() {
        assert_eq!(comprendre("bilan"), Saisie::Lancer(Commande::Bilan));
        assert_eq!(comprendre("  Bilan  "), Saisie::Lancer(Commande::Bilan));
        assert_eq!(comprendre("check"), Saisie::Lancer(Commande::Bilan));
        assert_eq!(
            comprendre("vanguard spyware"),
            Saisie::Lancer(Commande::LogicielsEspions)
        );
        assert_eq!(comprendre("aide"), Saisie::Aide);
        assert_eq!(comprendre("?"), Saisie::Aide);
        assert_eq!(comprendre("clear"), Saisie::Effacer);
        assert_eq!(comprendre("   "), Saisie::Rien);
        // Un argument de plus, une commande qui agit, un shell, une option : refusés, rien de lancé.
        for refus in [
            "bilan --html",
            "protection non",
            "protection --json non",
            "corriger",
            "options-defense --rallumer pare-feu",
            "rm -rf ~",
            "bilan; rm -rf ~",
            "bilan && corriger",
            "$(corriger)",
            "`corriger`",
            "audit",
            "--json",
            "vanguard",
            "vanguard vanguard bilan",
            "bilan\u{0}",
            "bilan\ncorriger",
            "biIan",
        ] {
            assert!(matches!(comprendre(refus), Saisie::Refusee(_)), "{refus:?} accepté");
        }
    }

    #[test]
    fn un_refus_redit_le_texte_nettoye_et_court() {
        let Saisie::Refusee(t) = comprendre(&format!("\u{1b}]52;c;eA==\u{7}x{}", "y".repeat(500))) else {
            panic!("accepté");
        };
        assert!(t.chars().count() <= 60, "{t}");
        assert!(!t.contains('\u{1b}'));
    }

    #[test]
    fn tab_complete_un_seul_nom() {
        assert_eq!(completer("bil"), None, "bilan et bilan-confidentialite");
        assert_eq!(completer("bilan-"), Some("bilan-confidentialite"));
        assert_eq!(completer("lo"), None);
        assert_eq!(completer("logiciels-e"), Some("logiciels-espions"));
        assert_eq!(completer("eff"), Some("effacer"));
        assert_eq!(completer(""), None);
        assert_eq!(completer("zzz"), None);
    }

    #[test]
    fn chaque_rubrique_garde_ses_commandes() {
        let total: usize = Rubrique::TOUTES.iter().map(|r| r.commandes().count()).sum();
        assert_eq!(total, Commande::TOUTES.len());
        assert_eq!(Rubrique::Accueil.commandes().count(), 0);
        for r in Rubrique::TOUTES {
            assert!(r.nom_court().lines().all(|l| l.chars().count() <= 12), "{r:?}");
        }
    }
}

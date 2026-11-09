use super::etat::*;
use super::lancer::*;
use super::outils::*;
use super::recherche::*;
use crate::demarrage::aide::*;
use crate::demarrage::arguments::*;
use crate::demarrage::droits::*;
use crate::selection::Ligne;
use crate::*;
use clap::{CommandFactory, Parser};

/// Le tableau de bord liste toutes les places du menu, chacune une fois, dans l'ordre de l'écran, et chaque
/// commande citée existe ; le guide et le dépannage, ouverts directement, y ont la place de leur groupe.
#[test]
fn le_tableau_liste_tout_le_menu() {
    let rubriques = fonctions_du_menu();
    assert_eq!(rubriques.len(), GROUPES.len() + 1);
    let listees: Vec<&str> = rubriques
        .iter()
        .flat_map(|r| r.fonctions.iter().map(|f| f.place.as_str()))
        .collect();
    for (place, _) in places() {
        assert_eq!(listees.iter().filter(|p| **p == place).count(), 1, "{place}");
    }
    for attendue in ["1", "2", "3", "10", "11"] {
        assert!(listees.contains(&attendue), "{attendue}");
    }
    assert_eq!(listees.len(), places().len() + 5);
    let clap = Args::command();
    for f in rubriques.iter().flat_map(|r| &r.fonctions) {
        if let Some(c) = &f.commande {
            let nom = c.strip_prefix("vanguard ").unwrap();
            assert!(
                clap.get_subcommands()
                    .any(|s| s.get_name() == nom || s.get_all_aliases().any(|a| a == nom)),
                "{c}"
            );
        }
    }
}

/// Revenir dans un écran d'outils remet la surbrillance sur l'outil choisi la dernière fois, retrouvé par l'outil
/// même si son numéro a changé ; un autre écran, ou un outil disparu, repart à la ligne 1.
#[test]
fn ligne_gardee_par_ecran() {
    let mut s = Session::default();
    let ecran = [Action::Scanner, Action::Appareil, Action::Conteneurs];
    assert_eq!(s.ligne_gardee("Réseau", &ecran), "1");
    s.choisis.insert("Réseau".into(), Action::Appareil);
    assert_eq!(s.ligne_gardee("Réseau", &ecran), "2");
    assert_eq!(s.ligne_gardee("Réseau", &[Action::Appareil]), "1");
    assert_eq!(
        s.ligne_gardee("Réseau", &[Action::Conteneurs, Action::Scanner, Action::Appareil]),
        "3"
    );
    assert_eq!(s.ligne_gardee("Réseau", &[Action::Scanner]), "1");
    assert_eq!(s.ligne_gardee("Virus", &ecran), "1");
}

/// Analyser un appareil : Entrée seule renonce sans rien noter ; une cible mal tapée est refusée avec son message,
/// avant le scan (donc hors du journal des erreurs) ; une bonne cible passe, sans les espaces autour.
#[test]
fn cible_tapee_vide_fausse_ou_bonne() {
    assert_eq!(cible_tapee(""), None);
    assert_eq!(cible_tapee("   "), None);
    assert!(matches!(cible_tapee("imprimante"), Some(Err(e)) if e.contains("imprimante")));
    assert!(matches!(cible_tapee("10.0.0.50-10"), Some(Err(_))));
    assert_eq!(cible_tapee(" 10.0.0.1 "), Some(Ok("10.0.0.1".to_string())));
    assert_eq!(cible_tapee("10.0.0.0/24"), Some(Ok("10.0.0.0/24".to_string())));
}

/// Les sous-commandes refusées en administrateur sont exactement celles des outils d'Optimiser de la table.
#[test]
fn commandes_d_optimiser() {
    for o in OUTILS.iter().filter(|o| !o.commande.is_empty()) {
        let Ok(args) = Args::try_parse_from(["vanguard", o.commande]) else {
            assert_ne!(
                o.groupe,
                Some(Groupe::Optimiser),
                "{} : sous-commande illisible",
                o.commande
            );
            continue;
        };
        let refusee = args.commande.as_ref().is_some_and(commande_d_optimiser);
        assert_eq!(refusee, o.groupe == Some(Groupe::Optimiser), "{}", o.commande);
    }
    let refusee = |l: &[&str]| {
        Args::try_parse_from(l)
            .unwrap()
            .commande
            .as_ref()
            .is_some_and(commande_d_optimiser)
    };
    assert!(!refusee(&["vanguard", "optimiser", "annuler"]));
    assert!(!refusee(&["vanguard", "optimize", "undo"]));
    assert!(refusee(&["vanguard", "optimiser", "confort"]));
    assert!(refusee(&["vanguard", "lenteur", "--json"]));
    assert!(refusee(&["vanguard", "nettoyer", "--liste"]));
}

#[test]
fn optimiser_refuse_seulement_eleve_depuis_un_compte_ordinaire() {
    assert!(optimiser_refuse(true, true));
    // Root seul (ssh root@, conteneur), Windows sans UAC : refuser ne protégerait rien.
    assert!(!optimiser_refuse(true, false));
    assert!(!optimiser_refuse(false, true));
    assert!(!optimiser_refuse(false, false));
}

#[test]
fn venu_de_sudo_ou_d_une_session_ordinaire() {
    assert!(venu_d_un_autre_compte(true, None));
    assert!(venu_d_un_autre_compte(true, Some(0)));
    // su ou sudo -i sans variables : la session reste celle du compte ordinaire.
    assert!(venu_d_un_autre_compte(false, Some(1000)));
    // ssh root@, console root, conteneur sans session.
    assert!(!venu_d_un_autre_compte(false, Some(0)));
    assert!(!venu_d_un_autre_compte(false, Some(u32::MAX)));
    assert!(!venu_d_un_autre_compte(false, None));
}

#[test]
fn root_d_un_espace_de_noms_ou_de_l_ordinateur() {
    assert_eq!(root_hors_de_l_espace("         0          0 4294967295\n"), Some(true));
    // unshare -r : le compte 0 de l'espace est le compte 1000 de l'ordinateur.
    assert_eq!(root_hors_de_l_espace("         0       1000          1\n"), Some(false));
    assert_eq!(root_hors_de_l_espace("         0     100000      65536\n"), Some(false));
    assert_eq!(root_hors_de_l_espace("      1000       1000          1\n"), None);
    assert_eq!(root_hors_de_l_espace("0 0 0\n"), None);
    assert_eq!(root_hors_de_l_espace(""), None);
    assert_eq!(root_hors_de_l_espace("x y z\n"), None);
}

/// Le menu, `--help` et le lanceur reprennent l'accroche de la vitrine (la ligne en gras du README, sans
/// « depuis une clé USB ») : changée d'un côté seulement, les deux se contredisaient sans que rien le voie.
#[test]
fn l_accroche_est_celle_de_la_vitrine() {
    let lire = |f: &str| std::fs::read_to_string(format!("{}/{f}", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let (menu, lanceur) = (lire("src/main.rs"), lire("src/raccourci.rs"));
    for (readme, fin) in [
        ("README.md", ", depuis une clé USB."),
        ("README.en.md", ", from a USB key."),
    ] {
        let texte = lire(readme);
        let accroche = texte
            .lines()
            .find_map(|l| l.trim().strip_prefix("<b>")?.split("</b>").next()?.strip_suffix(fin))
            .unwrap_or_else(|| panic!("accroche introuvable dans {readme}"));
        let citee = format!("\"{accroche}");
        // Dans main.rs : le menu et `--help`.
        assert!(
            menu.matches(&citee).count() >= 2,
            "{readme} : « {accroche} » manque dans main.rs"
        );
        assert!(
            lanceur.contains(&citee),
            "{readme} : « {accroche} » manque dans raccourci.rs"
        );
    }
}

#[test]
fn chaque_commande_a_son_aide_en_anglais() {
    // Une commande oubliée gardait son aide française dans l'interface anglaise (« distance »).
    let traduites: Vec<&str> = AIDES_EN.iter().map(|(nom, _)| *nom).collect();
    let manquantes: Vec<String> = Args::command()
        .get_subcommands()
        // Les commandes cachées (surveillance, planificateur) n'apparaissent pas dans l'aide.
        .filter(|s| !s.is_hide_set())
        .map(|s| s.get_name().to_string())
        .filter(|nom| nom != "help" && !traduites.contains(&nom.as_str()))
        .collect();
    assert_eq!(manquantes, Vec::<String>::new());
}

#[test]
fn chaque_option_a_son_aide_en_anglais() {
    let traduites: Vec<(&str, &str)> = OPTIONS_EN.iter().map(|(c, o, _)| (*c, *o)).collect();
    let mut manquantes = Vec::new();
    for s in Args::command().get_subcommands().filter(|s| !s.is_hide_set()) {
        for a in s.get_arguments().filter(|a| !a.is_hide_set() && a.get_help().is_some()) {
            let (c, o) = (s.get_name(), a.get_id().as_str());
            if !traduites.contains(&(c, o)) {
                manquantes.push(format!("{c} {o}"));
            }
        }
    }
    assert_eq!(manquantes, Vec::<String>::new());
}

#[test]
fn chaque_outil_a_sa_place() {
    // 1, 2, 3 au menu principal ; une variante dans un seul écran à choix ; tout le reste dans un seul groupe.
    let principal = [Action::Complet, Action::Corriger, Action::Rapport];
    for (i, o) in OUTILS.iter().enumerate() {
        // La ligne d'un outil est à son numéro : `Action::outil` la trouve sans chercher.
        assert_eq!(o.action as usize, i);
        let groupes = GROUPES.iter().filter(|g| g.actions().contains(&o.action)).count();
        let ecrans = ECRANS.iter().filter(|(_, v)| v.contains(&o.action)).count();
        assert_eq!(
            groupes + ecrans + usize::from(principal.contains(&o.action)),
            1,
            "{}",
            o.titre[0]
        );
    }
    // Un écran à choix est dans un groupe, et ses variantes n'en ouvrent pas d'autre (trois niveaux au plus).
    for (ecran, variantes) in ECRANS {
        assert!(ecran.outil().groupe.is_some(), "{}", ecran.outil().titre[0]);
        assert!(variantes.len() >= 2 && variantes.iter().all(|v| v.variantes().is_empty()));
    }
    // Raccourcis uniques, et jamais un chiffre (les chiffres ouvrent les groupes).
    let mut lettres: Vec<&str> = OUTILS.iter().map(|o| o.lettre).filter(|l| !l.is_empty()).collect();
    assert!(
        lettres
            .iter()
            .all(|l| !l.starts_with(|c: char| c.is_ascii_digit()) && *l != "q")
    );
    let n = lettres.len();
    lettres.sort_unstable();
    lettres.dedup();
    assert_eq!(lettres.len(), n);
}

/// Les lignes propres à un système vont en fin de groupe : les places annoncées (4.1 à 4.8, 8.1 à 8.9, 12.1 à
/// 12.10…) sont les mêmes sous Linux et Windows.
#[test]
fn lignes_propres_a_un_systeme_en_fin() {
    let propres = [
        Action::LogicielsPerimes,
        Action::OptionsDefense,
        Action::Veilleur,
        Action::OptimiserConfidentialite,
        Action::OptimiserConfort,
        Action::OptimiserPerformance,
    ];
    for g in GROUPES {
        let actions = g.actions();
        let premiere = actions.iter().position(|a| propres.contains(a));
        if let Some(p) = premiere {
            assert!(
                actions[p..].iter().all(|a| propres.contains(a)),
                "{} : une ligne commune après une ligne propre à un système",
                g.titre()
            );
        }
    }
    assert_eq!(Groupe::Optimiser.actions().last(), Some(&Action::OptimiserPerformance));
    assert!(Action::Signaler.disponible());
    assert_eq!(Action::LogicielsPerimes.disponible(), cfg!(windows));
}

/// Le test de la VM ouvre les Options de défense en 4.10 : toujours là sous Windows, juste après les logiciels
/// pas à jour, à la place des anciens « Blocages de Windows Defender ».
#[test]
fn options_de_defense_toujours_en_4_10_sous_windows() {
    assert_eq!(
        touche_de(Action::OptionsDefense).as_deref(),
        if cfg!(windows) {
            Some("4.10")
        } else {
            // Sous Linux, juste après les lignes communes (pas de logiciels pas à jour).
            cfg!(target_os = "linux").then_some("4.9")
        }
    );
    assert_eq!(
        touche_de(Action::LogicielsPerimes).as_deref(),
        cfg!(windows).then_some("4.9")
    );
}

/// Aucun écran ne défile : un groupe ou un écran à choix fait au plus 15 lignes (cadre, aide et saisie compris,
/// 24 rangées), comme le menu principal.
#[test]
fn chaque_sous_menu_tient_dans_24_lignes() {
    for g in GROUPES {
        let n = g.actions().len();
        assert!(n + 9 <= 24 || g.direct(), "{} : {n} lignes", g.titre());
    }
    for (ecran, variantes) in ECRANS {
        assert!(variantes.len() + 9 <= 24, "{}", ecran.outil().titre[0]);
    }
    // Dépanner : `depanner::tests::l_ecran_tient_dans_24_lignes`, avec ses deux outils.
}

/// Dépanner s'ouvre sur ses parcours, suivis de ses deux outils : `depanner_avec_ses_outils` sait lancer chacun.
#[test]
fn depanner_a_ses_deux_outils() {
    assert_eq!(
        Groupe::Depanner.actions(),
        [Action::Depanner, Action::Reparer, Action::Diagnostic]
    );
    assert_eq!(touche_de(Action::Reparer).as_deref(), Some("11.13"));
    assert_eq!(touche_de(Action::Diagnostic).as_deref(), Some("11.14"));
    assert_eq!(Groupe::Guide.actions(), [Action::Guide]);
}

#[test]
fn le_menu_principal_tient_dans_24_lignes() {
    // Trois lignes d'état au plus (dernier bilan, connexion ou avis, clé) : le menu le plus haut. Avec l'aide et
    // la saisie, il doit tenir dans un terminal de 24 lignes, sinon les flèches ne marchent plus.
    let s = |t: &str| t.to_string();
    for (connexion, avis) in [
        (None, None),
        (Some(s("c")), None),
        (None, Some(s("a"))),
        (Some(s("c")), Some(s("a"))),
    ] {
        assert!(lignes_d_etat(s("b"), connexion, s("k"), avis).len() <= 3);
    }
    assert_eq!(
        lignes_d_etat(s("b"), Some(s("c")), s("k"), Some(s("a"))),
        [s("b"), s("k"), s("a")]
    );
    let lignes = lignes_du_menu(vec![String::new(); 3]);
    let affichees = selection::rangees_a_l_ecran(&lignes);
    assert!(affichees + 2 <= 24, "{affichees} lignes affichées");
    // La recherche voit plus que l'écran : outils des sous-menus et pages du guide.
    assert!(lignes.len() > affichees + 50);
}

/// Le temps réel coupé, la ligne Surveillance dit la pause, dans la largeur d'une précision.
#[test]
fn surveillance_en_pause_au_menu() {
    assert_eq!(precision_surveillance(true, false), tr!("activée", "on"));
    let pause = precision_surveillance(true, true);
    assert!(
        pause.contains(tr!("pause", "paused")) && largeur_affichee(pause) <= 33,
        "{pause}"
    );
    assert_eq!(precision_surveillance(false, true), tr!("désactivée", "off"));
}

/// La protection en temps réel coupée se dit sur la ligne de la clé, à côté de la surveillance, sans jamais
/// dépasser la largeur : la clé la plus longue lui laisse la place de la surveillance, puis sans son échéance.
#[test]
fn temps_reel_coupe_dans_l_en_tete() {
    let coupe = Some((
        "temps réel coupé → 22/10 01:30".to_string(),
        "temps réel coupé".to_string(),
    ));
    let courte = ligne_de_la_cle("clé non branchée", "surveillance active", coupe.clone());
    assert!(
        courte.contains("surveillance active") && courte.contains("→ 22/10"),
        "{courte}"
    );
    assert_eq!(
        ligne_de_la_cle("clé non branchée", "surveillance active", None),
        format!("  clé non branchée {GRIS}·{RESET} surveillance active")
    );
    for cle in [
        "clé VANGUARD branchée (protégée en écriture)",
        "clé VANGUARD inconnue, ignorée",
        &"x".repeat(60),
    ] {
        let l = ligne_de_la_cle(cle, "surveillance coupée", coupe.clone());
        assert!(l.contains("temps réel coupé"), "{l}");
        assert!(largeur_affichee(&l) <= LARGEUR || cle.len() == 60, "{l}");
    }
}

#[test]
fn chaque_outil_trouve_par_la_recherche_s_ouvre() {
    let places = places();
    for (chemin, a) in &places {
        assert!(outil_au_chemin(chemin) == Some(*a), "{chemin}");
    }
    // Chaque outil disponible a une place, une seule (sauf 1, 2, 3, au menu principal, et les deux groupes ouverts
    // directement).
    for o in OUTILS.iter().filter(|o| o.action.disponible()) {
        let n = places.iter().filter(|(_, a)| *a == o.action).count();
        let ailleurs = matches!(
            o.action,
            Action::Complet | Action::Corriger | Action::Rapport | Action::Guide | Action::Depanner
        );
        assert_eq!(n, usize::from(!ailleurs), "{}", o.titre[0]);
    }
    assert!(outil_au_chemin("4.99").is_none() && outil_au_chemin("x.1").is_none());
    assert!(outil_au_chemin("10.1").is_none(), "le guide a ses propres chemins");
    assert!(outil_au_chemin("11.1").is_none(), "le dépannage a ses propres chemins");
    assert!(depanner::chemin("1").is_some());
    // Les places de la conception (§ 2.5), citées par l'aide, le CHANGELOG et le test de la VM.
    for (chemin, action) in [
        ("4.1", Action::Audit),
        ("4.6", Action::Fiche),
        ("4.8.2", Action::Conteneurs),
        ("5.1.1", Action::Scanner),
        ("5.2", Action::AuditReseau),
        ("6.1.3", Action::AntivirusDossier),
        ("6.2", Action::LogicielsEspions),
        ("7.1", Action::Lien),
        ("8.1", Action::Blocage),
        ("8.8", Action::OptimiserAnnuler),
        ("8.9", Action::Signaler),
        ("9.1", Action::CopierFichiers),
        ("9.3.1", Action::VerifierSauvegarde),
        ("12.1", Action::Logiciels),
        ("12.10", Action::WifiCanaux),
        ("13.1", Action::Parametres),
        ("13.3", Action::MettreAJour),
        ("13.4.2", Action::Autotest),
        ("13.10", Action::Extensions),
        ("13.11", Action::Desinstaller),
    ] {
        assert!(outil_au_chemin(chemin) == Some(action), "{chemin}");
    }
    // Paramètres : en 13.1, et « s » au menu principal.
    assert!(OUTILS.iter().any(|o| o.action == Action::Parametres && o.lettre == "s"));
}

/// `--help` range chaque commande visible dans une rubrique du menu (aucune dans « Aussi »), et ses deux aides
/// tiennent dans la largeur ; `-h` reste court.
#[test]
fn l_aide_cite_chaque_commande() {
    let rubriques = rubriques_de_l_aide();
    assert_eq!(rubriques.len(), 11, "bilan puis les dix groupes");
    let noms: Vec<&String> = rubriques.iter().flat_map(|(_, n)| n).collect();
    for (nom, _) in sous_commandes() {
        assert_eq!(
            noms.iter().filter(|n| ***n == nom).count(),
            1,
            "vanguard {nom} dans --help"
        );
    }
    for aide in [aide_longue(), aide_courte()] {
        for ligne in aide.lines() {
            assert!(largeur_affichee(ligne) <= LARGEUR, "{ligne}");
        }
    }
    assert!(aide_courte().lines().count() <= 15);
}

/// Le tableau « Toutes les commandes » du README suit les rubriques de `--help`, dans le même ordre.
#[test]
fn le_readme_suit_les_rubriques_de_l_aide() {
    let readme = lire("README.md");
    let tableau: Vec<String> = readme
        .lines()
        .filter_map(|l| l.strip_prefix("| `vanguard "))
        .filter_map(|l| l.split([' ', '`']).next().map(str::to_string))
        .collect();
    let aide: Vec<String> = rubriques_de_l_aide().into_iter().flat_map(|(_, n)| n).collect();
    assert_eq!(tableau, aide);
}

/// Un interrupteur se dit dans l'une ou l'autre langue ; « etat » ne change jamais rien.
#[test]
fn interrupteurs_dans_les_deux_langues() {
    for (mot, attendu) in [
        ("on", "on"),
        ("oui", "on"),
        ("Marche", "on"),
        ("off", "off"),
        ("non", "off"),
        ("arrêt", "off"),
        ("etat", "etat"),
        ("status", "etat"),
    ] {
        assert_eq!(interrupteur(mot).as_deref(), Ok(attendu), "{mot}");
    }
    assert!(interrupteur("peut-etre").is_err());
    assert_eq!(interrupteur_veilleur("ransomware").as_deref(), Ok("rancongiciel"));
    assert_eq!(interrupteur_veilleur("known").as_deref(), Ok("connus"));
    assert_eq!(interrupteur_veilleur("isolation").as_deref(), Ok("isolement"));
    assert_eq!(interrupteur_veilleur("arrêt").as_deref(), Ok("off"));
    assert_eq!(interrupteur_wifi_public("portal").as_deref(), Ok("portail"));
    assert_eq!(sans_etat(Some("etat")), None);
    assert_eq!(sans_etat(Some("on")), Some("on"));
}

/// Chaque touche de l'index de recherche (outils, variantes, parcours, logiciels, réglages, guide) mène quelque
/// part par `destination`, le même aiguillage que le menu et `vanguard chercher`.
#[test]
fn chaque_touche_de_l_index_s_ouvre() {
    for l in lignes_du_menu(Vec::new()) {
        let (Ligne::Choix { touche, .. } | Ligne::Cachee { touche, .. }) = &l else {
            continue;
        };
        if touche != "q" {
            assert!(destination(touche).is_some(), "« {touche} » ne mène nulle part");
        }
    }
    assert_eq!(destination("12.1.7"), Some(Destination::Logiciel(7)));
    assert_eq!(destination("zz"), None);
}

/// Les mots de la conception (§ 5.9) mettent leur cible dans les trois premiers résultats.
#[test]
fn la_recherche_trouve_ce_qu_on_attend() {
    let lignes = lignes_du_menu(Vec::new());
    let trois = |requete: &str| -> Vec<String> {
        selection::chercher(&lignes, requete)
            .0
            .into_iter()
            .take(3)
            .map(|t| t.touche)
            .collect()
    };
    let place = |a: Action| touche_de(a).unwrap();
    for (requete, cible) in [
        ("wifi public", place(Action::WifiPublic)),
        ("mot de passe", place(Action::MotsDePasse)),
        ("password", place(Action::MotsDePasse)),
        ("lent", "11.3".to_string()),
        ("imprimante", "11.5".to_string()),
        ("imprimnte", "11.5".to_string()),
        ("ransomware", place(Action::Pieges)),
        ("box", place(Action::Objets)),
        ("maj", place(Action::Maj)),
        ("sortantes", place(Action::QuiParle)),
    ] {
        assert!(
            trois(requete).contains(&cible),
            "« {requete} » : {:?}, attendu {cible}",
            trois(requete)
        );
    }
    let logiciels = format!("{}.", place(Action::Logiciels));
    assert!(
        trois("gimp").iter().any(|t| t.starts_with(&logiciels)),
        "{:?}",
        trois("gimp")
    );
    // Proton VPN et Mullvad VPN n'ont de paquet que sous Arch (et winget) : ailleurs, la recherche ne
    // propose pas un logiciel qu'elle ne saurait installer (`pour_ce_systeme`), la CI Ubuntu comprise.
    let vpn_ici = lignes.iter().any(
        |l| matches!(l, Ligne::Cachee { touche, texte, .. } if touche.starts_with(&logiciels) && texte.contains("VPN")),
    );
    assert_eq!(
        trois("vpn").iter().any(|t| t.starts_with(&logiciels)),
        vpn_ici,
        "{:?}",
        trois("vpn")
    );
    #[cfg(windows)]
    assert!(trois("harden").contains(&"4.10".to_string()));
    assert!(
        !selection::chercher(&lignes, "imprimnte").1.is_empty(),
        "la faute est dite"
    );
}

/// Les commandes dites « en lecture » au guide existent, et celles qui changent quelque chose y sont marquées ⚠.
#[test]
fn le_guide_dit_ce_qui_change() {
    let commandes = sous_commandes();
    for nom in COMMANDES_EN_LECTURE {
        assert!(commandes.iter().any(|(n, _)| n == nom), "{nom}");
    }
    let marquee = |ligne: &str| {
        programmes_vanguard()
            .iter()
            .flat_map(|p| p.commandes.iter())
            .find(|c| c.ligne == ligne)
            .map(|c| c.modifie)
    };
    assert_eq!(marquee("vanguard corriger"), Some(true));
    assert_eq!(marquee("vanguard nettoyer"), Some(true));
    assert_eq!(marquee("vanguard audit"), Some(false));
    assert_eq!(place_de_commande("depanner").as_deref(), Some("11"));
    assert_eq!(place_de_commande("guide").as_deref(), Some("10"));
    assert_eq!(place_de_commande("bilan").as_deref(), Some("1"));
}

/// Les outils du menu qui n'ont pas de sous-commande, et pourquoi.
const MENU_SEULEMENT: &[(Action, &str)] = &[
    (
        Action::ProtegerDonnees,
        "la phrase se tape et se confirme à l'écran, sur l'ordinateur du propriétaire",
    ),
    (
        Action::Developpeurs,
        "un écran à choix : secrets et conteneurs ont chacun leur commande",
    ),
    (
        Action::VerifierCopies,
        "un écran à choix : verifier-sauvegarde et verifier-copie",
    ),
    (Action::VerifierVanguard, "un écran à choix : verifier-moi et autotest"),
];

/// Les sous-commandes sans outil du menu, et pourquoi.
const LIGNE_DE_COMMANDE_SEULEMENT: &[(&str, &str)] = &[
    (
        "importer",
        "le menu Vanguard › Exporter ou importer les réglages propose aussi l'import",
    ),
    ("plugins", "le menu Extensions les liste et les lance"),
    ("labo", "le menu Extensions les liste et les lance"),
    (
        "agent",
        "Paramètres › Agent Vanguard montre la même vue et en tient les interrupteurs",
    ),
    (
        "protection",
        "l'état de tous les interrupteurs d'un coup ; chacun a aussi sa ligne dans son groupe",
    ),
    (
        "chercher",
        "la recherche de l'accueil (« Numéro, ou un mot à chercher »)",
    ),
    (
        "alerte",
        "l'identifiant d'une alerte notifiée ; Blocage des menaces propose les mêmes gestes",
    ),
];

/// Les sous-commandes visibles : (nom, alias visibles).
fn sous_commandes() -> Vec<(String, Vec<String>)> {
    Args::command()
        .get_subcommands()
        .filter(|s| !s.is_hide_set() && s.get_name() != "help")
        .map(|s| {
            let alias = s.get_visible_aliases().map(str::to_string).collect();
            (s.get_name().to_string(), alias)
        })
        .collect()
}

fn lire(fichier: &str) -> String {
    std::fs::read_to_string(format!("{}/{fichier}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// Le texte d'un fichier Rust tel que le compilateur en lit les éléments : les commentaires (`//`, `/* */`
/// imbriqués) et, si `chaines`, les littéraux (chaînes, brutes `r#"…"#` comprises, octets, caractères) changés en
/// espaces octet pour octet, sauts de ligne gardés : positions et numéros de ligne ne bougent pas. Le `r#` d'un
/// identifiant brut aussi (`mod r#x;` se lit `mod   x;`). Toute la garde de l'`unsafe` lit ce texte : sur le texte
/// brut, un `]` ou un `mod x;` écrit dans un commentaire ou une chaîne la trompait.
pub(crate) fn blanchi(texte: &str, chaines: bool) -> String {
    let o = texte.as_bytes();
    let mut blanc = o.to_vec();
    let effacer = |blanc: &mut Vec<u8>, de: usize, a: usize| {
        for b in &mut blanc[de..a.min(o.len())] {
            if *b != b'\n' {
                *b = b' ';
            }
        }
    };
    let lettre = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b >= 0x80;
    // Rien de collé devant : un `r` qui commence un mot, pas la fin de `bar`.
    let libre = |k: usize| k == 0 || !lettre(o[k - 1]);
    let mut i = 0;
    while i < o.len() {
        let reste = &o[i..];
        i = if reste.starts_with(b"//") {
            let fin = reste.iter().position(|&b| b == b'\n').map_or(o.len(), |p| i + p);
            effacer(&mut blanc, i, fin);
            fin
        } else if reste.starts_with(b"/*") {
            let (mut j, mut profondeur) = (i + 2, 1usize);
            while j < o.len() && profondeur > 0 {
                if o[j..].starts_with(b"/*") {
                    profondeur += 1;
                    j += 2;
                } else if o[j..].starts_with(b"*/") {
                    profondeur -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            effacer(&mut blanc, i, j);
            j
        } else if o[i] == b'r' && (libre(i) || (matches!(o[i - 1], b'b' | b'c') && libre(i - 1))) {
            // Une chaîne brute (`r"…"`, `r#"…"#`, `br"…"`…) ou un identifiant brut (`r#x`).
            let dieses = reste[1..].iter().take_while(|&&b| b == b'#').count();
            let ouvre = i + 1 + dieses;
            if o.get(ouvre) == Some(&b'"') {
                let ferme: Vec<u8> = std::iter::once(b'"').chain(std::iter::repeat_n(b'#', dieses)).collect();
                let fin = o[ouvre + 1..]
                    .windows(ferme.len())
                    .position(|w| w == ferme.as_slice())
                    .map_or(o.len(), |p| ouvre + 1 + p + ferme.len());
                if chaines {
                    effacer(&mut blanc, i, fin);
                }
                fin
            } else if dieses == 1 && o.get(ouvre).is_some_and(|&b| lettre(b)) {
                effacer(&mut blanc, i, ouvre);
                ouvre
            } else {
                i + 1
            }
        } else if o[i] == b'"' {
            let mut j = i + 1;
            while j < o.len() && o[j] != b'"' {
                j += if o[j] == b'\\' { 2 } else { 1 };
            }
            let fin = (j + 1).min(o.len());
            if chaines {
                effacer(&mut blanc, i, fin);
            }
            fin
        } else if o[i] == b'\'' {
            // Un caractère (`'x'`, `'"'`, `'\''`, `'\u{…}'`) ; sinon une durée de vie (`'a`), qui reste.
            let fin = if o.get(i + 1) == Some(&b'\\') {
                o.iter().skip(i + 3).position(|&b| b == b'\'').map(|p| i + 3 + p + 1)
            } else {
                texte[i + 1..]
                    .chars()
                    .next()
                    .map(|c| i + 1 + c.len_utf8())
                    .filter(|&j| o.get(j) == Some(&b'\''))
                    .map(|j| j + 1)
            };
            if let (Some(fin), true) = (fin, chaines) {
                effacer(&mut blanc, i, fin);
            }
            fin.unwrap_or(i + 1)
        } else {
            i + 1
        };
    }
    String::from_utf8(blanc).unwrap()
}

/// La fin (après le `]` qui le ferme) de l'attribut qui ouvre `texte` (`#[` ou `#![`), chaînes comprises : une
/// raison peut contenir des crochets. Tout le texte s'il n'est jamais fermé.
fn fin_d_attribut(texte: &str) -> usize {
    let (mut profondeur, mut chaine, mut echappe) = (0usize, false, false);
    for (i, c) in texte.char_indices() {
        match c {
            _ if echappe => echappe = false,
            '\\' if chaine => echappe = true,
            '"' => chaine = !chaine,
            '[' if !chaine => profondeur += 1,
            ']' if !chaine => {
                profondeur -= 1;
                if profondeur == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
    }
    texte.len()
}

/// Les lignes d'un fichier Rust, chacune avec ses attributs : ceux qui se suivent au-dessus d'un même élément (aucun
/// pour la plupart des lignes). Un attribut va de `#[` (ou `#![`) en tête de ligne au `]` qui le ferme ; l'élément
/// peut suivre sur la même ligne. Lu sur le texte blanchi (`blanchi`) : un commentaire ou une chaîne ne fait ni
/// attribut ni élément. Les attributs gardent leurs chaînes (le chemin d'un `#[path]`), les éléments non.
fn elements_et_attributs(texte: &str) -> Vec<(Vec<String>, String)> {
    let blanc = blanchi(texte, true);
    let avec_chaines = blanchi(texte, false);
    let mut groupes = Vec::new();
    let mut attributs: Vec<String> = Vec::new();
    let mut i = 0;
    loop {
        let reste = &blanc[i..];
        let debut = blanc.len() - reste.trim_start_matches([' ', '\t', '\r', '\n']).len();
        if blanc[debut..].starts_with("#[") || blanc[debut..].starts_with("#![") {
            let fin = debut + fin_d_attribut(&blanc[debut..]);
            attributs.push(avec_chaines[debut..fin].to_string());
            i = fin;
            continue;
        }
        // L'élément d'un groupe commence après ses attributs (et les blancs qui les suivent).
        let reste_lu = if attributs.is_empty() { reste } else { &blanc[debut..] };
        let (ligne, apres) = reste_lu.split_once('\n').unwrap_or((reste_lu, ""));
        groupes.push((std::mem::take(&mut attributs), ligne.trim().to_string()));
        if apres.is_empty() && ligne.len() == reste_lu.len() {
            return groupes;
        }
        i = blanc.len() - apres.len();
    }
}

/// Les modules hors ligne qu'un fichier déclare et que le banc compile, avec leur `#[path]` : chaque `mod x;` avec
/// SES attributs (deux déclarations du même nom sous des `cfg` exclusifs ont chacune les leurs), sauf les essais et
/// les preuves de Kani (outils/preuves/), que le banc ne compile jamais.
fn enfants_hors_ligne(elements: &[(Vec<String>, String)]) -> Vec<(&str, Option<&str>)> {
    elements
        .iter()
        .filter_map(|(attributs, element)| {
            let nom = module_hors_ligne(element)?;
            if attributs.iter().any(|a| a == "#[cfg(test)]" || a == "#[cfg(kani)]") {
                return None;
            }
            Some((nom, attributs.iter().find_map(|a| chemin_de(a))))
        })
        .collect()
}

/// Un `allow` ou un `expect` (`cfg_attr` compris) qui tait tous les avertissements ou tout le groupe restriction,
/// donc aussi les lints des modules fuzzés : `warnings` l'emporte même sur `-D warnings` de la ligne de commande.
fn tait_tout(attribut: &str) -> bool {
    // Hors des chaînes : une raison peut parler des avertissements.
    let (mut code, mut chaine, mut echappe) = (String::new(), false, false);
    for c in attribut.chars() {
        match c {
            _ if echappe => echappe = false,
            '\\' if chaine => echappe = true,
            '"' => chaine = !chaine,
            _ if !chaine => code.push(c),
            _ => {}
        }
    }
    (code.contains("allow(") || code.contains("expect("))
        && code
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':'))
            .any(|mot| mot == "warnings" || mot == "clippy::restriction")
}

/// La garde suit chaque déclaration avec ses propres attributs : une variante sous `cfg` qui porte le même nom
/// qu'une déclaration sautée (essais, Kani) ou qu'une autre plateforme est lue à son propre chemin.
#[test]
fn garde_des_modules_fuzzes_lit_chaque_declaration() {
    let texte = "#[cfg(kani)]\nmod lecteur;\n#[cfg(not(kani))]\n#[path = \"lecteur_brut.rs\"]\nmod lecteur;\n\n\
                     #[cfg(unix)]\nmod plateforme;\n#[cfg(windows)]\n// la variante\n#[path = \"plateforme_win.rs\"]\n\
                     pub(crate) mod plateforme;\n#[cfg(test)]\nmod tests;\nmod simple;\n#[cfg(unix)] mod une_ligne;\n";
    assert_eq!(
        enfants_hors_ligne(&elements_et_attributs(texte)),
        [
            ("lecteur", Some("lecteur_brut.rs")),
            ("plateforme", None),
            ("plateforme", Some("plateforme_win.rs")),
            ("simple", None),
            ("une_ligne", None),
        ]
    );
    for a in [
        "#[allow(warnings)]",
        "#![expect(unused, warnings, reason = \"x\")]",
        "#[cfg_attr(fuzzing, allow(clippy::restriction))]",
    ] {
        assert!(tait_tout(a), "{a}");
    }
    for a in [
        "#[allow(unused_mut)]",
        "#[expect(clippy::as_conversions, reason = \"warnings : non\")]",
        "#[cfg(warnings)]",
    ] {
        assert!(!tait_tout(a), "{a}");
    }
}

/// Le chemin d'un `#[path = "…"]` (espaces permis autour du `=`, chaîne brute `r"…"` ou `r#"…"#` comprise), s'il
/// en est un.
fn chemin_de(attribut: &str) -> Option<&str> {
    let dedans = attribut.strip_prefix("#[")?.strip_suffix(']')?.trim();
    let valeur = dedans.strip_prefix("path")?.trim_start().strip_prefix('=')?.trim();
    litteral(valeur)
        .filter(|(_, reste)| reste.is_empty())
        .map(|(chemin, _)| chemin)
}

/// La chaîne (sans échappement : un chemin) qui ouvre `texte`, `"…"`, `r"…"` ou `r#"…"#`, et ce qui la suit.
fn litteral(texte: &str) -> Option<(&str, &str)> {
    let (dieses, corps) = match texte.strip_prefix('r') {
        Some(brut) => {
            let corps = brut.trim_start_matches('#');
            (&brut[..brut.len() - corps.len()], corps)
        }
        None => ("", texte),
    };
    let corps = corps.strip_prefix('"')?;
    let fin = format!("\"{dieses}");
    let i = corps.find(&fin)?;
    Some((&corps[..i], &corps[i + fin.len()..]))
}

/// Une ligne sans sa visibilité en tête (`pub`, `pub(crate)`…).
fn sans_visibilite(ligne: &str) -> &str {
    ligne
        .strip_prefix("pub")
        .map_or(ligne, |l| {
            l.split_once(')').filter(|_| l.starts_with('(')).map_or(l, |(_, r)| r)
        })
        .trim_start()
}

/// Le nom d'un module déclaré hors ligne (`mod x;`, `pub(crate) mod x;`…), s'il en est un.
fn module_hors_ligne(ligne: &str) -> Option<&str> {
    let nom = sans_visibilite(ligne)
        .strip_prefix("mod ")?
        .trim()
        .strip_suffix(';')?
        .trim();
    nom.bytes()
        .all(|o| o.is_ascii_alphanumeric() || o == b'_')
        .then_some(nom)
}

/// Les modules de src/ que le banc de fuzzing compile, avec leur texte : ceux que fuzz/fuzz_targets/ et fuzz/cale/
/// incluent par `#[path]` (écrit avec ou sans espaces) ou `include!`, puis, de proche en proche, chaque `mod x;`
/// qu'ils déclarent hors essais et preuves de Kani.
fn modules_fuzzes() -> std::collections::BTreeMap<std::path::PathBuf, String> {
    use std::path::{Path, PathBuf};
    let racine = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = racine.join("src").canonicalize().unwrap();
    let mut a_lire: Vec<PathBuf> = Vec::new();
    for d in ["fuzz/fuzz_targets", "fuzz/cale"] {
        for banc in std::fs::read_dir(racine.join(d)).unwrap() {
            let banc = banc.unwrap().path();
            let texte = std::fs::read_to_string(&banc).unwrap();
            let dossier = banc.parent().unwrap();
            let groupes = elements_et_attributs(&texte);
            let mut chemins: Vec<&str> = groupes
                .iter()
                .flat_map(|(a, _)| a.iter().filter_map(|a| chemin_de(a)))
                .collect();
            let sans_commentaires = blanchi(&texte, false);
            for morceau in sans_commentaires.split("include!(").skip(1) {
                chemins.push(litteral(morceau.trim_start()).unwrap().0);
            }
            for chemin in chemins {
                let vrai = dossier.join(chemin).canonicalize().unwrap();
                if vrai.starts_with(&src) {
                    a_lire.push(vrai);
                }
            }
        }
    }
    let mut modules = std::collections::BTreeMap::new();
    while let Some(module) = a_lire.pop() {
        if modules.contains_key(&module) {
            continue;
        }
        let texte = std::fs::read_to_string(&module).unwrap();
        // Les enfants hors ligne : à côté d'un mod.rs, dans le dossier du même nom sinon (règle de rustc).
        let dossier = module.parent().unwrap();
        let sous = if module.file_name().unwrap() == "mod.rs" {
            dossier.to_path_buf()
        } else {
            dossier.join(module.file_stem().unwrap())
        };
        for (nom, chemin) in enfants_hors_ligne(&elements_et_attributs(&texte)) {
            let enfant = match chemin {
                Some(c) => dossier.join(c),
                None if sous.join(format!("{nom}.rs")).exists() => sous.join(format!("{nom}.rs")),
                None => sous.join(nom).join("mod.rs"),
            };
            a_lire.push(
                enfant
                    .canonicalize()
                    .unwrap_or_else(|e| panic!("{}, mod {nom} : {e}", module.display())),
            );
        }
        modules.insert(module, texte);
    }
    assert!(
        modules.len() >= 50,
        "trop peu de modules lus dans fuzz/ : {:?}",
        modules.keys()
    );
    modules
}

/// Chaque module de src/ que le banc de fuzzing compile (`modules_fuzzes`) refuse débordements et `as`
/// (Cargo.toml, [lints.clippy]). Et aucun d'eux ne lève ces lints ailleurs que sur un module d'essais : seul
/// `#[expect]` (avec sa raison, exigée) les tait sur du code lu par le banc, et rien n'y tait `warnings` ni tout le
/// groupe restriction. Un lecteur ajouté au banc sans l'attribut, ou un `allow` glissé sur une fonction, garderait
/// des calculs bruts sur des données hostiles sans que clippy le dise.
#[test]
fn chaque_module_fuzze_refuse_debordements_et_as() {
    const ATTRIBUT: &str = "#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]";
    // Les noms qui lèvent ou baissent ces lints : les deux (et l'ancien nom du premier), et le groupe qui les
    // contient ; `warnings`, qui les tait aussi, est refusé par `tait_tout`.
    const NOMS: [&str; 4] = [
        "arithmetic_side_effects",
        "integer_arithmetic",
        "as_conversions",
        "clippy::restriction",
    ];
    let mut modules = std::collections::BTreeMap::new();
    for (module, texte) in modules_fuzzes() {
        let groupes = elements_et_attributs(&texte);
        // Chaque attribut qui nomme ces lints : l'en-tête, un `#[expect]`, ou l'`allow` d'un module d'essais.
        let mut fautes = Vec::new();
        for (attributs, element) in &groupes {
            // Un module d'essais, hors ligne (`mod tests;`) ou écrit sur place (`mod tests {`).
            let essais = attributs.iter().any(|a| a == "#[cfg(test)]")
                && element.trim_start_matches("pub(crate) ").starts_with("mod ");
            for a in attributs.iter().filter(|a| NOMS.iter().any(|n| a.contains(n))) {
                // Un `#[expect]` dit pourquoi : sans raison, il tairait un calcul sans preuve.
                let avec_raison = a.split_whitespace().collect::<String>().contains("reason=\"");
                let permis =
                    a == ATTRIBUT || a.starts_with("#[expect(") && avec_raison || essais && a.starts_with("#[allow(");
                if !permis {
                    fautes.push(a.clone());
                }
            }
            fautes.extend(attributs.iter().filter(|a| tait_tout(a)).cloned());
        }
        // Un nom de ces lints hors de tout attribut lu (au milieu d'une ligne, dans un cfg_attr…) : refusé aussi.
        let vus: usize = groupes
            .iter()
            .flat_map(|(a, _)| a.iter())
            .map(|a| NOMS.iter().map(|n| a.matches(n).count()).sum::<usize>())
            .sum();
        let ecrits: usize = blanchi(&texte, false)
            .lines()
            .map(|l| NOMS.iter().map(|n| l.matches(n).count()).sum::<usize>())
            .sum();
        if ecrits != vus {
            fautes.push(format!(
                "{} nom(s) de ces lints hors d'un attribut en tête de ligne",
                ecrits - vus
            ));
        }
        let en_tete = attributs_de_tete(&blanchi(&texte, true))
            .iter()
            .any(|(_, a)| *a == ATTRIBUT);
        modules.insert(module, (en_tete, fautes));
    }
    let sans: Vec<_> = modules.iter().filter(|(_, (a, _))| !a).map(|(m, _)| m).collect();
    assert!(sans.is_empty(), "modules fuzzés sans « {ATTRIBUT} » : {sans:?}");
    let leves: Vec<_> = modules
        .iter()
        .filter(|(_, (_, f))| !f.is_empty())
        .map(|(m, (_, f))| (m, f))
        .collect();
    assert!(
        leves.is_empty(),
        "lints levés hors d'un module d'essais (seul #[expect] est permis) : {leves:?}"
    );
}

/// Les attributs intérieurs de tête d'un fichier blanchi (`blanchi`), avec la ligne (comptée de zéro) où chacun
/// commence : les `#![…]` en colonne zéro avant tout élément, les seuls qui valent pour tout le fichier. Un `#![…]`
/// rangé plus bas (dans un `mod tests {`…) ne vaut que pour ce qui l'entoure ; un attribut que suit autre chose
/// sur sa ligne arrête la lecture.
fn attributs_de_tete(blanc: &str) -> Vec<(usize, &str)> {
    let mut attributs = Vec::new();
    let (mut reste, mut numero) = (blanc, 0usize);
    while !reste.is_empty() {
        let (ligne, apres) = reste.split_once('\n').unwrap_or((reste, ""));
        if ligne.trim().is_empty() {
            reste = apres;
            numero += 1;
            continue;
        }
        if !ligne.starts_with("#![") {
            break;
        }
        let (attribut, suite) = reste.split_at(fin_d_attribut(reste));
        let (bout, apres) = suite.split_once('\n').unwrap_or((suite, ""));
        if !bout.trim().is_empty() {
            break;
        }
        attributs.push((numero, attribut));
        numero += attribut.matches('\n').count() + 1;
        reste = apres;
    }
    attributs
}

/// L'élément que portent les attributs qui ouvrent `blanc` (blanchi) : la suite, depuis sa première ligne.
fn element_porte(blanc: &str) -> &str {
    let mut reste = blanc;
    loop {
        reste = reste.trim_start();
        if !reste.starts_with("#[") {
            return reste;
        }
        reste = &reste[fin_d_attribut(reste)..];
    }
}

/// L'élément qui ouvre `blanc` (blanchi), jusqu'au `;` qui le termine ou à l'accolade qui ferme son corps, la
/// dernière de sa ligne : `impl A<{ 1 }> for B {` ne s'arrête pas à la première accolade fermée. Tout le texte s'il
/// ne se ferme jamais.
fn etendue(blanc: &str) -> &str {
    let mut profondeur = 0usize;
    for (i, c) in blanc.char_indices() {
        match c {
            '(' | '[' | '{' => profondeur += 1,
            ')' | ']' | '}' => {
                profondeur = profondeur.saturating_sub(1);
                let fin_de_ligne = blanc[i + 1..].split('\n').next().unwrap_or("").trim().is_empty();
                if c == '}' && profondeur == 0 && fin_de_ligne {
                    return &blanc[..=i];
                }
            }
            ';' if profondeur == 0 => return &blanc[..=i],
            _ => {}
        }
    }
    blanc
}

/// Les positions du mot `mot` dans `texte` : ni lettre, ni chiffre, ni `_` collés devant ou derrière.
fn mots<'a>(texte: &'a str, mot: &'a str) -> impl Iterator<Item = usize> + 'a {
    let lettre = |c: char| c.is_alphanumeric() || c == '_';
    texte.match_indices(mot).map(|(i, _)| i).filter(move |&i| {
        !texte[..i].chars().next_back().is_some_and(lettre)
            && !texte[i + mot.len()..].chars().next().is_some_and(lettre)
    })
}

/// Un nom (identifiant) en tête de `texte`, et ce qui le suit.
fn nom_en_tete(texte: &str) -> (&str, &str) {
    texte.split_at(
        texte
            .find(|c: char| !(c.is_alphanumeric() || c == '_'))
            .unwrap_or(texte.len()),
    )
}

/// Ce qui, dans `blanc` (blanchi), ferait hériter d'une levée du code écrit ailleurs : un module hors ligne
/// (`mod x;`, sous `#[path]` ou non, dans une fonction comprise), un `include!`, une macro définie là
/// (`macro_rules!`).
fn heritiers(blanc: &str) -> Vec<String> {
    let mut trouves: Vec<String> = mots(blanc, "mod")
        .filter_map(|i| {
            let (nom, suite) = nom_en_tete(blanc[i + 3..].trim_start());
            (!nom.is_empty() && suite.trim_start().starts_with(';')).then(|| format!("mod {nom};"))
        })
        .collect();
    for m in ["include", "macro_rules"] {
        if mots(blanc, m).next().is_some() {
            trouves.push(format!("{m}!"));
        }
    }
    trouves
}

/// Un élément (blanchi) sur lequel une levée reste à lui : une fonction, un `impl`, un bloc `extern`, un `static`
/// ou un module écrit sur place (`mod x {`). Jamais une déclaration hors ligne (`mod x;`), un appel de macro, un
/// `use`… : la levée irait à du code qu'on ne voit pas sous elle.
fn levable(element: &str) -> bool {
    let mut reste = sans_visibilite(element);
    let mut externe = false;
    loop {
        let (mot, suite) = nom_en_tete(reste);
        let suite = suite.trim_start();
        match mot {
            "const" | "async" | "unsafe" | "safe" => {}
            "extern" => externe = true,
            "fn" | "impl" | "static" => return true,
            "mod" => {
                let (nom, apres) = nom_en_tete(suite);
                return !nom.is_empty() && apres.trim_start().starts_with('{');
            }
            // Un bloc `extern "C" {` : l'ABI est blanchie.
            "" => return externe && reste.starts_with('{'),
            _ => return false,
        }
        reste = suite;
    }
}

/// Les fautes d'un fichier de src/ envers le refus de l'`unsafe` (`unsafe_code`), lues sur le texte blanchi
/// (`blanchi`) : un commentaire ou une chaîne n'y fait ni attribut, ni module, ni accolade. `fuzze` dit si le banc
/// de fuzzing le lit, `racine` si c'est la racine de la crate. La racine refuse (`deny`) ; un module fuzzé refuse
/// sans recours (`forbid`) et ne lève rien : c'est la seconde ceinture, le banc imposant déjà ce refus par le
/// compilateur (`chaque_cible_du_banc_refuse_unsafe`). Ailleurs, le refus se lève par `allow` seul sur sa ligne,
/// sous une ligne de commentaire qui dit pourquoi : en tête d'un fichier (pas la racine), ou sur une fonction, un
/// `impl`, un bloc `extern`, un `static` ou un module écrit sur place (`levable`). Jamais sur du code écrit
/// ailleurs, qui en hériterait sans la montrer : ni module hors ligne, ni `include!`, ni macro définie sous la
/// levée (`heritiers`). Nulle part une macro qui écrirait un module, un `include!` ou une levée là où on l'appelle,
/// ni `include` renommé ; nulle part un `cfg_attr`, un `expect` ou un `warn` : la levée doit se lire telle quelle,
/// sur toutes les plateformes.
fn fautes_envers_l_unsafe(texte: &str, fuzze: bool, racine: bool) -> Vec<String> {
    const NOM: &str = "unsafe_code";
    const DENY: &str = "#![deny(unsafe_code)]";
    const FORBID: &str = "#![forbid(unsafe_code)]";
    const ALLOW_MODULE: &str = "#![allow(unsafe_code)]";
    const ALLOW: &str = "#[allow(unsafe_code)]";
    let blanc = blanchi(texte, true);
    let mut fautes = Vec::new();
    let en_tete = attributs_de_tete(&blanc);
    let a_en_tete = |a: &str| en_tete.iter().any(|(_, x)| *x == a);
    if racine && !a_en_tete(DENY) {
        fautes.push(format!("racine sans « {DENY} » en tête du fichier"));
    }
    if fuzze && !a_en_tete(FORBID) {
        fautes.push(format!("module fuzzé sans « {FORBID} » en tête du fichier"));
    }
    let origine: Vec<&str> = texte.lines().collect();
    let lignes: Vec<&str> = blanc.lines().collect();
    let debuts: Vec<usize> = blanc
        .split_inclusive('\n')
        .scan(0, |lu, l| {
            let debut = *lu;
            *lu += l.len();
            Some(debut)
        })
        .collect();
    for (i, ligne) in lignes.iter().enumerate() {
        if !ligne.contains(NOM) {
            continue;
        }
        // Une des quatre formes, seule sur sa ligne : rien avant (un `cfg` ou un autre lint), rien après (un
        // élément). Celle de module, seulement parmi les attributs de tête.
        let forme = ligne.trim();
        let de_tete = |a: &str| en_tete.iter().any(|(l, x)| *l == i && *x == a);
        let permis = match forme {
            DENY => racine && de_tete(DENY),
            FORBID => true,
            ALLOW_MODULE => !fuzze && !racine && de_tete(ALLOW_MODULE),
            ALLOW => !fuzze,
            _ => false,
        };
        if !permis {
            fautes.push(format!(
                "ligne {} : refusé ici : {forme} (seuls le deny en tête de la racine, le forbid et, hors banc, \
                     l'allow, seuls sur leur ligne, celui de module en tête d'un fichier autre que la racine)",
                i + 1
            ));
            continue;
        }
        if ![ALLOW_MODULE, ALLOW].contains(&forme) {
            continue;
        }
        // La raison : la ligne d'avant n'est qu'un commentaire simple (ni `///` ni `//!`, qui documenteraient
        // l'élément ou le module au lieu de dire pourquoi l'`unsafe`), avec des mots.
        let raison = i
            .checked_sub(1)
            .filter(|&j| lignes[j].trim().is_empty())
            .and_then(|j| origine[j].trim().strip_prefix("//"))
            .filter(|r| !r.starts_with(['/', '!']));
        if !raison.is_some_and(|r| r.chars().any(char::is_alphabetic)) {
            fautes.push(format!(
                "ligne {} : « {forme} » sans commentaire qui dise pourquoi",
                i + 1
            ));
        }
        if forme == ALLOW {
            let element = debuts.get(i + 1).map_or("", |&d| element_porte(&blanc[d..]));
            let premiere = element.lines().next().unwrap_or("").trim();
            if !levable(element) {
                fautes.push(format!(
                    "ligne {} : « {ALLOW} » sur « {premiere} » (seulement sur une fonction, un impl, un bloc \
                         extern, un static ou un module écrit sur place)",
                    i + 1
                ));
                continue;
            }
            let heritiers = heritiers(etendue(element));
            if !heritiers.is_empty() {
                fautes.push(format!(
                    "ligne {} : « {ALLOW} » sur « {premiere} », dont hériteraient {heritiers:?}",
                    i + 1
                ));
            }
        }
    }
    // Une levée en tête d'un fichier qui inclut du code écrit ailleurs : elle s'étendrait à lui. Un module écrit
    // sur place, lui, est sous les yeux de qui lit la levée.
    if a_en_tete(ALLOW_MODULE) {
        let heritiers = heritiers(&blanc);
        if !heritiers.is_empty() {
            fautes.push(format!(
                "« {ALLOW_MODULE} » dans un fichier dont hériteraient {heritiers:?}"
            ));
        }
    }
    // Une macro pose ce qu'elle écrit là où on l'appelle, peut-être sous une levée, hors de la vue de cette
    // garde : aucune n'écrit de module, d'`include!` ni de levée. Et `include` renommé (`use std::include as
    // i;`) échapperait à la recherche d'`include!`.
    for i in mots(&blanc, "macro_rules") {
        let corps = etendue(&blanc[i..]);
        for m in ["mod", "include", NOM] {
            if mots(corps, m).next().is_some() {
                let ligne = blanc[..i].matches('\n').count() + 1;
                fautes.push(format!("ligne {ligne} : une macro qui écrit « {m} »"));
            }
        }
    }
    for i in mots(&blanc, "include") {
        if !blanc[i + "include".len()..].trim_start().starts_with('!') {
            let ligne = blanc[..i].matches('\n').count() + 1;
            fautes.push(format!("ligne {ligne} : « include » ailleurs que dans « include! »"));
        }
    }
    fautes
}

/// Le refus de l'`unsafe` des lecteurs fuzzés, imposé par le compilateur : chaque cible du banc, racine de sa
/// crate, le refuse sans recours en tête (`#![forbid(unsafe_code)]`), ce qui couvre tout ce qu'elle inclut
/// (modules de src/ par `#[path]`, cales, leurs enfants hors ligne, macros et `include!`) ; un `allow` en dessous,
/// où qu'il soit, ne compile pas (E0453), et outils/verifier.sh compile le banc. Ce test vérifie seulement que
/// chaque cible porte ce refus, et que le banc n'a pas d'autre racine (bibliothèque, binaire rangé ailleurs) qui
/// inclurait un lecteur sans lui.
#[test]
fn chaque_cible_du_banc_refuse_unsafe() {
    const FORBID: &str = "#![forbid(unsafe_code)]";
    let fuzz = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz");
    let manifeste = std::fs::read_to_string(fuzz.join("Cargo.toml")).unwrap();
    let sections: Vec<&str> = manifeste.lines().filter(|l| l.starts_with('[')).collect();
    assert!(
        sections.iter().all(|s| !s.starts_with("[lib")
            && !s.starts_with("[[example")
            && !s.starts_with("[[test")
            && !s.starts_with("[[bench")),
        "fuzz/Cargo.toml : une racine autre qu'une cible : {sections:?}"
    );
    assert!(
        !fuzz.join("src").exists(),
        "fuzz/src/ : une racine découverte par cargo"
    );
    let declarees: Vec<&str> = manifeste
        .lines()
        .filter_map(|l| l.strip_prefix("path = \"")?.strip_suffix('"'))
        .collect();
    let mut cibles: Vec<String> = std::fs::read_dir(fuzz.join("fuzz_targets"))
        .unwrap()
        .map(|e| format!("fuzz_targets/{}", e.unwrap().file_name().to_string_lossy()))
        .collect();
    cibles.sort();
    let mut tries = declarees.clone();
    tries.sort_unstable();
    assert_eq!(
        tries, cibles,
        "fuzz/Cargo.toml et fuzz/fuzz_targets/ ne listent pas les mêmes cibles"
    );
    assert!(cibles.len() >= 28, "trop peu de cibles : {}", cibles.len());
    let sans: Vec<&String> = cibles
        .iter()
        .filter(|c| {
            let texte = std::fs::read_to_string(fuzz.join(c)).unwrap();
            !attributs_de_tete(&blanchi(&texte, true))
                .iter()
                .any(|(_, a)| *a == FORBID)
        })
        .collect();
    assert!(sans.is_empty(), "cibles du banc sans « {FORBID} » en tête : {sans:?}");
}

/// Le compilateur refuse l'`unsafe` partout où il ne sert pas (`fautes_envers_l_unsafe`) : la racine le refuse, les
/// modules que lit le banc de fuzzing (`modules_fuzzes`, les lecteurs de données hostiles) le refusent sans
/// recours, et chaque module ou élément qui appelle le système le lève pour lui seul, en disant pourquoi. Aucune
/// exception : un lecteur fuzzé qui aurait besoin d'`unsafe` le confierait à un petit module voisin, hors du banc.
/// Un `forbid` ôté, un module ajouté au banc sans lui, ou une levée sans raison arrêtent ce test.
#[test]
fn chaque_module_fuzze_refuse_unsafe() {
    let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = racine.join("src").canonicalize().unwrap();
    let fuzzes = modules_fuzzes();
    let mut fichiers = Vec::new();
    let mut a_voir = vec![src.clone()];
    while let Some(d) = a_voir.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                a_voir.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                fichiers.push(p.canonicalize().unwrap());
            }
        }
    }
    assert!(
        fichiers.len() > 300,
        "trop peu de fichiers lus dans src/ : {}",
        fichiers.len()
    );
    assert!(
        fuzzes.keys().all(|m| fichiers.contains(m)),
        "un module fuzzé hors de src/"
    );
    let mut fautes = Vec::new();
    for f in &fichiers {
        let texte = std::fs::read_to_string(f).unwrap();
        for faute in fautes_envers_l_unsafe(&texte, fuzzes.contains_key(f), *f == src.join("main.rs")) {
            fautes.push(format!("{} : {faute}", f.strip_prefix(&src).unwrap().display()));
        }
    }
    assert!(fautes.is_empty(), "refus de l'unsafe :\n{}", fautes.join("\n"));
}

/// B-6 de la relecture des correctifs c6 : un essai écrit ses fichiers jetables sous `essais::temporaire()` (dans
/// le dossier de compilation), jamais dans le dossier temporaire du système, qui peut avoir un quota. Restent les usages du
/// programme lui-même et les essais qui jugent ce dossier-là, comptés ici fichier par fichier : un usage de plus
/// arrête ce test.
#[test]
fn les_essais_n_ecrivent_pas_dans_le_dossier_temporaire() {
    let permis: std::collections::BTreeMap<&str, usize> = [
        // Le programme : bac à sable, fichier pour ClamAV, disques exclus, dossiers risqués, traces de Windows.
        ("src/protection/isoler.rs", 1),
        ("src/protection/antivirus.rs", 1),
        ("src/protection/cle.rs", 1),
        // Le programme : le lieu d'un fichier pour les heuristiques (dossier temporaire).
        ("src/protection/moteur.rs", 1),
        ("src/traces/windows.rs", 2),
        // Le programme (dossier risqué) et un essai qui juge le dossier temporaire du compte.
        ("src/protection/sortantes.rs", 2),
        // Des prises Unix d'essai : leur chemin tient en 108 octets, que le dépôt peut dépasser.
        ("src/machine/linux/http_unix.rs", 1),
        ("src/machine/linux/dbus/actions.rs", 1),
        // Des essais qui jugent ce dossier-là, sans y écrire.
        ("src/verifier_cle.rs", 1),
        ("src/protection/distance.rs", 1),
        ("src/essais.rs", 1),
        ("tests/programme.rs", 1),
    ]
    .into_iter()
    .collect();
    let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut trouves = std::collections::BTreeMap::new();
    let mut a_voir = vec![racine.join("src"), racine.join("tests")];
    let mut lus = 0;
    while let Some(d) = a_voir.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                a_voir.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                lus += 1;
                let n = usages_du_dossier_temporaire(&std::fs::read_to_string(&p).unwrap());
                if n > 0 {
                    let nom = p.strip_prefix(racine).unwrap().to_string_lossy().replace('\\', "/");
                    trouves.insert(nom, n);
                }
            }
        }
    }
    assert!(lus > 300, "trop peu de fichiers lus : {lus}");
    let trop: Vec<String> = trouves
        .iter()
        .filter(|(f, n)| permis.get(f.as_str()).is_none_or(|p| *n > p))
        .map(|(f, n)| format!("{f} ({n})"))
        .collect();
    assert!(
        trop.is_empty(),
        "dossier temporaire du système dans des essais, à remplacer par essais::temporaire() : {trop:?}"
    );
}

/// Les usages du dossier temporaire du système dans un fichier de code.
fn usages_du_dossier_temporaire(texte: &str) -> usize {
    // En morceaux : ce fichier ne se compte pas lui-même. Le nom de la fonction suivi de sa parenthèse couvre
    // chaque chemin qui y mène, complet, raccourci par un `use` ou importé.
    texte.matches(concat!("temp_", "dir(")).count() + texte.matches(concat!("\"TMP", "DIR\"")).count()
}

/// B-5 de la relecture des restes c6 : la garde voit le dossier temporaire sous chacune de ses formes, pas
/// seulement le chemin complet : `env::temp_dir` après `use std::env`, `temp_dir` importé, la variable
/// `TMPDIR` lue ou donnée à un programme.
#[test]
fn garde_du_dossier_temporaire_voit_chaque_forme() {
    // Les noms en morceaux, comme dans la garde : ce fichier ne se compte pas lui-même.
    let (td, var) = (concat!("temp_", "dir"), concat!("\"TMP", "DIR\""));
    for (texte, n) in [
        (format!("let d = std::env::{td}();"), 1),
        (format!("use std::env;\nlet d = env::{td}().join(\"x\");"), 1),
        (format!("use std::env::{td};\nlet d = {td}();"), 1),
        (format!("let d = std::env::var_os({var});"), 1),
        (format!("c.env({var}, j);"), 1),
        ("let d = crate::essais::temporaire();".to_string(), 0),
    ] {
        assert_eq!(usages_du_dossier_temporaire(&texte), n, "{texte}");
    }
}

/// La garde de l'`unsafe` sur des fichiers inventés : ce qu'elle laisse passer, et chaque contournement qu'elle
/// arrête (levée dans un lecteur fuzzé, par cfg_attr, sans raison ou à côté d'autre chose sur sa ligne, sur un
/// module dont d'autres hériteraient, refus rangé ailleurs qu'en tête du fichier…).
#[test]
fn garde_de_l_unsafe_lit_chaque_levee() {
    let fuzze = "//! Un lecteur.\n\n// Pourquoi.\n#![forbid(unsafe_code)]\n\nfn lire() {}\n#[cfg(test)]\nmod tests;\n";
    assert_eq!(fautes_envers_l_unsafe(fuzze, true, false), Vec::<String>::new());
    let ffi = "//! FFI.\n\n// FFI de libc : kill.\n#![allow(unsafe_code)]\n\nfn f() {}\n#[cfg(test)]\nmod tests {}\n";
    assert_eq!(fautes_envers_l_unsafe(ffi, false, false), Vec::<String>::new());
    let element = "#[cfg(unix)]\n// FFI de libc : kill.\n#[allow(unsafe_code)]\nfn f() {}\nmod enfant;\n";
    assert_eq!(fautes_envers_l_unsafe(element, false, false), Vec::<String>::new());
    // Le blanchiment : commentaires (imbriqués), chaînes (brutes, d'octets), caractères et `r#` effacés octet pour
    // octet ; les préfixes, les durées de vie et les sauts de ligne restent.
    let mots_blanchis = |t: &str| {
        let b = blanchi(t, true);
        assert_eq!((b.len(), b.lines().count()), (t.len(), t.lines().count()), "{t:?}");
        b.split_whitespace().collect::<Vec<_>>().join(" ")
    };
    assert_eq!(mots_blanchis("a /* b /* c */ ] */ d // e\nf"), "a d f");
    assert_eq!(mots_blanchis(r##"x "b \" ]" r#"c "] d"# b"e" br"f" y"##), "x b b y");
    assert_eq!(
        mots_blanchis(r#"f('"', '\'', &'a u8, c"z") mod r#x;"#),
        "f( , , &'a u8, c ) mod x;"
    );
    assert_eq!(blanchi("#[path = \"a.rs\"] // b", false), "#[path = \"a.rs\"]     ");
    // Ce qui reste levable : un bloc extern, un static, un impl dont l'en-tête porte une accolade, une fonction
    // où un commentaire ou une chaîne parle de modules, un module sur place qui n'en déclare que sur place ; et
    // un `include!` hors de toute levée.
    for texte in [
        "// FFI.\n#[allow(unsafe_code)]\nextern \"system\" {\n    fn g() -> i32;\n}\nmod enfant;\n",
        "// R.\n#[allow(unsafe_code)]\n#[cfg(windows)]\npub(crate) static S: u8 = 0;\nmod enfant;\n",
        "// R.\n#[allow(unsafe_code)]\nimpl A<{ 1 }> for B {}\nmod enfant;\n",
        "// R.\n#[allow(unsafe_code)]\npub(crate) const fn f() -> &'static str {\n    // mod x;\n    \"mod y; include!\"\n}\nmod enfant;\n",
        "// R.\n#[allow(unsafe_code)]\nmod tests {\n    mod sur_place {}\n}\nmod enfant;\n",
        "mod base {\n    include!(\"x.rs\");\n}\n",
    ] {
        assert_eq!(
            fautes_envers_l_unsafe(texte, false, false),
            Vec::<String>::new(),
            "{texte:?}"
        );
    }
    let racine = "//! Racine.\n\n// Pourquoi.\n#![deny(unsafe_code)]\n\nmod a;\n";
    assert_eq!(fautes_envers_l_unsafe(racine, false, true), Vec::<String>::new());
    // Un module d'essais écrit sur place peut être levé : rien n'en hérite sans le montrer (l'accolade d'un
    // caractère ne ferme pas le bloc, et `mod enfant;` est hors de lui).
    let essais = "// FFI de libc : mmap.\n#[allow(unsafe_code)]\nmod tests {\n    fn f() -> char {\n        '}'\n    }\n}\nmod enfant;\n";
    assert_eq!(fautes_envers_l_unsafe(essais, false, false), Vec::<String>::new());
    assert_eq!(chemin_de(r#"#[path = "a.rs"]"#), Some("a.rs"));
    assert_eq!(chemin_de(r#"#[path = r"a.rs"]"#), Some("a.rs"));
    assert_eq!(chemin_de(r##"#[path = r#"a.rs"#]"##), Some("a.rs"));
    assert_eq!(chemin_de(r#"#[path = "a.rs" ]"#), Some("a.rs"));
    assert_eq!(chemin_de(r#"#[path = "a.rs" "b"]"#), None);
    for (texte, fuzze, racine) in [
        // Le module fuzzé sans forbid, la racine sans deny.
        ("fn lire() {}\n", true, false),
        ("mod a;\n", false, true),
        // Toute levée dans un module fuzzé, même avec sa raison, même sur une fonction.
        (
            "// R.\n#![forbid(unsafe_code)]\n// R.\n#[allow(unsafe_code)]\nfn f() {}\n",
            true,
            false,
        ),
        (
            "// R.\n#![forbid(unsafe_code)]\n#[expect(unsafe_code, reason = \"r\")]\nfn f() {}\n",
            true,
            false,
        ),
        // Une levée conditionnelle, ou glissée parmi d'autres lints.
        (
            "// R.\n#[cfg_attr(windows, allow(unsafe_code))]\nfn f() {}\n",
            false,
            false,
        ),
        ("// R.\n#[allow(dead_code, unsafe_code)]\nfn f() {}\n", false, false),
        ("fn f() {} #[allow(unsafe_code)] fn g() {}\n", false, false),
        // Sans raison, ou sous une doc au lieu d'une raison.
        ("#[allow(unsafe_code)]\nfn f() {}\n", false, false),
        ("/// La fonction.\n#[allow(unsafe_code)]\nfn f() {}\n", false, false),
        ("//!\n#![allow(unsafe_code)]\n", false, false),
        // En tête d'un fichier dont les modules hériteraient.
        ("// R.\n#![allow(unsafe_code)]\n\nmod enfant;\n", false, false),
        (
            "// R.\n#![allow(unsafe_code)]\n\n#[cfg(unix)]\npub(crate) mod enfant;\n",
            false,
            false,
        ),
        // Un deny ailleurs qu'à la racine ne lève rien, mais n'a rien à y faire.
        ("// R.\n#![deny(unsafe_code)]\n", false, false),
        // Le refus ailleurs qu'en tête du fichier : il ne couvre que ce qui l'entoure, ou rien (chaîne brute).
        (
            "fn lire() {}\nmod tests {\n    #![forbid(unsafe_code)]\n}\n",
            true,
            false,
        ),
        ("mod x {\n    #![forbid(unsafe_code)]\n}\nfn lire() {}\n", true, false),
        ("#[cfg(test)]\nmod tests {\n#![forbid(unsafe_code)]\n}\n", true, false),
        (
            "fn lire() {}\nconst T: &str = r#\"\n#![forbid(unsafe_code)]\n\"#;\n",
            true,
            false,
        ),
        ("fn main() {}\nmod x {\n#![deny(unsafe_code)]\n}\n", false, true),
        // Une levée posée sur un module dont d'autres hériteraient : hors ligne, sur place avec un enfant hors
        // ligne, en tête d'un fichier qui déclare ses essais hors ligne, ou intérieure à un module sur place.
        ("// R.\n#[allow(unsafe_code)]\nmod enfant;\n", false, false),
        (
            "// R.\n#[allow(unsafe_code)]\n#[cfg(unix)]\n// Pourquoi.\npub(crate) mod enfant;\n",
            false,
            false,
        ),
        ("// R.\n#[allow(unsafe_code)]\nmod x {\n    mod y;\n}\n", false, false),
        (
            "// R.\n#[allow(unsafe_code)]\nmod x {\n    #[cfg(test)] mod tests;\n}\n",
            false,
            false,
        ),
        (
            "// R.\n#![allow(unsafe_code)]\n\n#[cfg(test)]\nmod tests;\n",
            false,
            false,
        ),
        (
            "fn a() {}\nmod x {\n    // R.\n    #![allow(unsafe_code)]\n    mod y;\n}\n",
            false,
            false,
        ),
        // La raison contournée sur une seule ligne : autre chose avant ou après la levée, ou une raison sans mot.
        ("fn a() {}\n#[allow(unsafe_code)] // \nfn f() {}\n", false, false),
        ("// R.\n#[allow(unsafe_code)] fn f() {}\n", false, false),
        ("#![allow(unsafe_code)] //\nfn f() {}\n", false, false),
        ("// R.\n#[cfg(unix)] #[allow(unsafe_code)]\nfn f() {}\n", false, false),
        ("// .\n#[allow(unsafe_code)]\nfn f() {}\n", false, false),
        // Un refus de tête qui n'en est pas un : dans un commentaire ou une chaîne que le `]` d'un attribut ouvre
        // et referme.
        (
            "#![doc = \"x\" /*]\n#![forbid(unsafe_code)]\n*/]\nfn lire() {}\n",
            true,
            false,
        ),
        (
            "#![doc = r#\"x\"]\n#![forbid(unsafe_code)]\n\"#]\nfn lire() {}\n",
            true,
            false,
        ),
        // Un module hors ligne caché sous une levée : commentaire après, commentaire ou `r#` au milieu, accolade
        // dans un commentaire ou une chaîne, dans une fonction, dans un impl dont l'en-tête porte une accolade.
        ("// R.\n#[allow(unsafe_code)]\nmod x; // c\n", false, false),
        ("// R.\n#[allow(unsafe_code)]\nmod /* c */ x;\n", false, false),
        ("// R.\n#[allow(unsafe_code)]\nmod r#x;\n", false, false),
        (
            "// R.\n#[allow(unsafe_code)]\nmod x {\n    // }\n    mod y;\n}\n",
            false,
            false,
        ),
        (
            "// R.\n#[allow(unsafe_code)]\nmod x {\n    const C: &str = \"}\";\n    mod y;\n}\n",
            false,
            false,
        ),
        (
            "// R.\n#[allow(unsafe_code)]\nmod x {\n    /* } */ pub mod y;\n}\n",
            false,
            false,
        ),
        (
            "// R.\n#[allow(unsafe_code)]\nfn f() {\n    #[path = \"l.rs\"]\n    mod m;\n}\n",
            false,
            false,
        ),
        (
            "// R.\n#[allow(unsafe_code)]\nimpl A<{ 1 }> for B {\n    fn f() {\n        #[path = \"l.rs\"]\n        mod m;\n    }\n}\n",
            false,
            false,
        ),
        // Un include! ou une macro sous une levée, en tête comme sur l'élément.
        (
            "// R.\n#[allow(unsafe_code)]\nfn f() {\n    include!(\"l.rs\");\n}\n",
            false,
            false,
        ),
        (
            "// R.\n#![allow(unsafe_code)]\n\nmod base {\n    include!(\"l.rs\");\n}\n",
            false,
            false,
        ),
        (
            "// R.\n#[allow(unsafe_code)]\nfn f() {\n    macro_rules! m {\n        () => {};\n    }\n}\n",
            false,
            false,
        ),
        // Une macro qui écrit un module, un include! ou une levée, où qu'elle soit : l'appel les poserait sous une
        // levée sans le montrer. Ou `include` renommé.
        (
            "macro_rules! m {\n    ($n:ident) => {\n        mod $n;\n    };\n}\n",
            false,
            false,
        ),
        (
            "macro_rules! m {\n    () => {\n        include!(\"l.rs\");\n    };\n}\n",
            false,
            false,
        ),
        (
            "macro_rules! m {\n    ($i:item) => {\n        // R.\n        #[allow(unsafe_code)]\n        $i\n    };\n}\n",
            false,
            false,
        ),
        ("use std::include as i;\n", false, false),
        // Une levée sur ce qui n'est ni fonction, ni impl, ni bloc extern, ni static, ni module sur place.
        ("// R.\n#[allow(unsafe_code)]\nm! {}\n", false, false),
        ("// R.\n#[allow(unsafe_code)]\nconst C: u8 = 0;\n", false, false),
        ("// R.\n#[allow(unsafe_code)]\nextern crate x;\n", false, false),
        // La racine qui lève en tête sous son deny ; une levée de module ailleurs qu'en tête.
        (
            "// R.\n#![deny(unsafe_code)]\n// R.\n#![allow(unsafe_code)]\n",
            false,
            true,
        ),
        ("fn a() {}\n// R.\n#![allow(unsafe_code)]\n", false, false),
        // La raison après du code.
        ("fn a() {} // R.\n#[allow(unsafe_code)]\nfn f() {}\n", false, false),
    ] {
        assert!(!fautes_envers_l_unsafe(texte, fuzze, racine).is_empty(), "{texte:?}");
    }
    // Le contournement combiné des relecteurs : le parent lève sur `mod lecteur;`, le lecteur range son refus dans
    // ses essais ; le haut du lecteur n'est plus couvert que par la levée du parent, et rustc y compilerait un bloc
    // `unsafe`. La garde arrête chacun des deux fichiers.
    let parent = "// R\n#[allow(unsafe_code)]\nmod lecteur;\n";
    let lecteur = "fn lire(x: &[u8]) -> u8 {\n    x[0]\n}\n#[cfg(test)]\nmod tests {\n    #![forbid(unsafe_code)]\n}\n";
    assert!(!fautes_envers_l_unsafe(parent, false, false).is_empty(), "{parent:?}");
    assert!(!fautes_envers_l_unsafe(lecteur, true, false).is_empty(), "{lecteur:?}");
}

/// Une seule table d'outils : chaque outil du menu nomme la sous-commande qui fait la même chose, ou dit pourquoi
/// il n'en a pas ; chaque sous-commande a son outil, ou dit pourquoi. Un outil ajouté d'un côté seulement (les
/// cinq d'Optimiser n'avaient aucune commande, aucun script ne pouvait tout annuler) arrête ce test.
#[test]
fn menu_et_ligne_de_commande_ont_les_memes_outils() {
    let commandes = sous_commandes();
    let existe = |nom: &str| commandes.iter().any(|(n, _)| n == nom);
    for o in OUTILS {
        let sans = MENU_SEULEMENT.iter().any(|(a, _)| *a == o.action);
        if o.commande.is_empty() {
            assert!(
                sans,
                "« {} » : ni sous-commande, ni raison dans MENU_SEULEMENT",
                o.titre[0]
            );
        } else {
            assert!(
                !sans,
                "« {} » : une sous-commande et une raison de ne pas en avoir",
                o.titre[0]
            );
            assert!(
                existe(o.commande),
                "« {} » : la sous-commande « {} » n'existe pas",
                o.titre[0],
                o.commande
            );
        }
    }
    for (nom, _) in &commandes {
        let dans_le_menu = OUTILS.iter().any(|o| o.commande == nom);
        let a_part = LIGNE_DE_COMMANDE_SEULEMENT.iter().any(|(n, _)| n == nom);
        assert!(
            dans_le_menu != a_part,
            "vanguard {nom} : {}",
            if a_part {
                "dans le menu et dans LIGNE_DE_COMMANDE_SEULEMENT"
            } else {
                "ni outil du menu, ni raison dans LIGNE_DE_COMMANDE_SEULEMENT"
            }
        );
    }
    for (nom, _) in LIGNE_DE_COMMANDE_SEULEMENT {
        assert!(existe(nom), "LIGNE_DE_COMMANDE_SEULEMENT : « {nom} » n'existe plus");
    }
}

/// Chaque sous-commande visible a son aide française : un commentaire décollé de sa commande donnait à
/// `dernieres-failles` l'aide de trois commandes, et aucune au veilleur ni aux sites dangereux.
#[test]
fn chaque_commande_a_son_aide() {
    for s in Args::command()
        .get_subcommands()
        .filter(|s| !s.is_hide_set() && s.get_name() != "help")
    {
        let aide = s.get_about().map(ToString::to_string).unwrap_or_default();
        assert!(!aide.trim().is_empty(), "vanguard {} : sans aide", s.get_name());
    }
    // Celle de « dernieres-failles » parle des failles, pas du veilleur ni des sites.
    let commande = Args::command();
    let failles = commande.find_subcommand("dernieres-failles").unwrap();
    let aide = failles.get_about().unwrap().to_string();
    assert!(aide.starts_with("Dernières failles exploitées"), "{aide}");
}

/// Le tableau des commandes du README (« | `vanguard nom …` | … ») a une ligne par sous-commande visible : le
/// nom français dans README.md, l'alias anglais (ou le nom, s'il n'en a pas) dans README.en.md.
#[test]
fn le_readme_liste_chaque_commande() {
    let lignes_du_tableau = |texte: &str| -> Vec<String> {
        texte
            .lines()
            .filter_map(|l| l.strip_prefix("| `vanguard "))
            .filter_map(|l| l.split([' ', '`']).next().map(str::to_string))
            .collect()
    };
    let (fr, en) = (
        lignes_du_tableau(&lire("README.md")),
        lignes_du_tableau(&lire("README.en.md")),
    );
    let mut manquantes = Vec::new();
    for (nom, alias) in sous_commandes() {
        if !fr.contains(&nom) {
            manquantes.push(format!("README.md : {nom}"));
        }
        if !en.iter().any(|e| *e == nom || alias.contains(e)) {
            manquantes.push(format!("README.en.md : {nom} ({})", alias.join(", ")));
        }
    }
    // Les noms de l'autre langue, dans le paragraphe qui les liste : les alias anglais dans README.md, les noms
    // français dans README.en.md.
    let (readme, readme_en) = (lire("README.md"), lire("README.en.md"));
    for (nom, alias) in sous_commandes() {
        for a in &alias {
            if !readme.contains(&format!("`{a}`")) {
                manquantes.push(format!("README.md, noms anglais : {a}"));
            }
        }
        // Un nom sans alias est le même dans les deux langues (antivirus, yara…) : rien à traduire.
        if !alias.is_empty() && !readme_en.contains(&format!("`{nom}`")) {
            manquantes.push(format!("README.en.md, noms français : {nom}"));
        }
    }
    assert_eq!(manquantes, Vec::<String>::new());
}

/// Le mode d'emploi de la clé (outils/LISEZMOI.txt, outils/README.txt) cite chaque outil du menu : par son titre
/// tel que le menu l'affiche, ou par sa commande (« vanguard memoire »).
#[test]
fn le_mode_d_emploi_de_la_cle_cite_chaque_outil() {
    let (lisezmoi, readme) = (lire("outils/LISEZMOI.txt"), lire("outils/README.txt"));
    let commandes = sous_commandes();
    let mut manquants = Vec::new();
    for o in OUTILS {
        let alias = commandes
            .iter()
            .find(|(n, _)| n == o.commande)
            .map(|(_, a)| a.clone())
            .unwrap_or_default();
        let cite_fr = lisezmoi.contains(o.titre[0])
            || (!o.commande.is_empty() && lisezmoi.contains(&format!("vanguard {}", o.commande)));
        let cite_en = readme.contains(o.titre[1])
            || alias
                .iter()
                .chain(std::iter::once(&o.commande.to_string()))
                .any(|c| !c.is_empty() && readme.contains(&format!("vanguard {c}")));
        if !cite_fr {
            manquants.push(format!("LISEZMOI.txt : {}", o.titre[0]));
        }
        if !cite_en {
            manquants.push(format!("README.txt : {}", o.titre[1]));
        }
    }
    assert_eq!(manquants, Vec::<String>::new());
}

/// Le tableau Structure de CONTRIBUTING.md et CONTRIBUTING.en.md nomme chaque fichier de src/ : par son chemin,
/// son nom seul dans une ligne qui en groupe plusieurs (`dns.rs`, `wifi.rs`), ou un dossier qui le contient quand
/// la ligne vaut pour tout ce dossier (`src/machine/linux/`). Un module ajouté sans sa ligne arrête ce test.
#[test]
fn le_tableau_structure_nomme_chaque_module() {
    let fichiers: Vec<String> = {
        let mut tous = Vec::new();
        let mut a_voir = vec![std::path::PathBuf::from(format!("{}/src", env!("CARGO_MANIFEST_DIR")))];
        while let Some(d) = a_voir.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    a_voir.push(p);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    let relatif = p.strip_prefix(env!("CARGO_MANIFEST_DIR")).unwrap();
                    tous.push(relatif.to_string_lossy().replace('\\', "/"));
                }
            }
        }
        tous.sort();
        tous
    };
    for (document, titre) in [("CONTRIBUTING.md", "## Structure"), ("CONTRIBUTING.en.md", "## Layout")] {
        let texte = lire(document);
        let debut = texte
            .find(titre)
            .unwrap_or_else(|| panic!("{document} : pas de « {titre} »"));
        let section = &texte[debut..];
        let section = &section[..section[titre.len()..]
            .find("\n## ")
            .map_or(section.len(), |f| f + titre.len())];
        // Ce qui est entre accents graves, coupé aux virgules et aux espaces (« `a.rs`, `b.rs` »).
        let cites: Vec<&str> = section
            .split('`')
            .skip(1)
            .step_by(2)
            .flat_map(|c| c.split([',', ' ', '(', ')']))
            .filter(|c| !c.is_empty())
            .collect();
        let mut manquants = Vec::new();
        for f in &fichiers {
            let (dossier, nom) = f.rsplit_once('/').unwrap();
            let dossier = format!("{dossier}/");
            // mod.rs et tests.rs vont avec leur dossier ; `src/` seul ne vaut pas pour tout le programme.
            let par_le_dossier = cites
                .iter()
                .any(|c| c.ends_with('/') && *c != "src/" && f.starts_with(*c));
            let par_le_nom = matches!(nom, "mod.rs" | "tests.rs")
                && cites.iter().any(|c| c.starts_with(&dossier) || *c == f.as_str());
            if !(cites.contains(&f.as_str()) || cites.contains(&nom) || par_le_dossier || par_le_nom) {
                manquants.push(f.clone());
            }
        }
        assert_eq!(manquants, Vec::<String>::new(), "{document}, tableau « {titre} »");
    }
}

/// LANG-ERRWRAP (CONFORMITE-ANSSI.md) : les erreurs rendues par le crate sont des erreurs standard, avec un texte.
/// Une variante de chaque, de quoi casser la compilation si `Display` ou `Error` venait à manquer.
#[test]
fn erreurs_standard() {
    fn dite(e: &dyn std::error::Error) {
        assert!(!e.to_string().trim().is_empty(), "{e:?}");
    }
    use crate::socle::cache;
    dite(&crate::compte_rendu::envoi::Refus::TropGros);
    dite(&crate::protection::manifeste::PasEcrit::SansReference);
    dite(&crate::modele::Echec::new("essai", crate::modele::Raison::Droits));
    dite(&crate::optimiser::annulables::PourquoiPas::NonReleve);
    dite(&crate::protection::cles_connues::Refus::CarnetModifie);
    dite(&crate::sceau::Doute::HorsVanguard);
    dite(&cache::Refus::Effacee);
    dite(&cache::Echec::SansReponse);
    dite(&cache::Echec::CopieRefusee(
        cache::Refus::DateFuture,
        cache::Redemande::Attente,
    ));
    dite(&crate::chiffrement::Refus::Authentification);
    dite(&crate::http::Refus::Certificat("UnknownIssuer".into()));
    dite(&crate::http::Refus::Reseau);
    dite(&crate::sauvegarde::Refus::Identite);
    dite(&crate::socle::SansVerrou::Impossible("EACCES".into()));
    #[cfg(target_os = "linux")]
    {
        dite(&crate::machine::linux::veilleur::Refus::Erreur(22));
        dite(&crate::machine::linux::connexions::PasLue::Illisible("droits".into()));
    }
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    dite(&crate::socle::relro::Echec::Mprotect(13));
}

//! Le menu lui-même : afficher, choisir, lancer un outil.

use crate::Session;
use crate::demarrage::droits::refuser_optimiser;
use crate::menu::etat::{etat_du_menu, fonctions_du_menu, lignes_du_menu};
use crate::menu::outils::{Action, Groupe, veilleur};
use crate::menu::recherche::ouvrir_touche;
use crate::selection::{Ligne, choisir, choisir_au_sommet};
use crate::ui::*;
use crate::{
    a_laisser, apprentissage, changements, chiffrement, copier, depanner, desinstaller, diagnostic, dns_rapide,
    donnees, entretien, evenements, fiche, gaming, guide, historique, journaux_windows, lenteur, logiciels, machine,
    maj, mise_a_jour, nettoyer, optimiser, options_defense, ordinateurs, parametres, plugins, protection, raccourci,
    rapport, reparer, reseau, sauvegarde, signaler, socle, ui, verifier_cle,
};

/// La cible tapée par la personne (menu « Analyser un appareil », `vanguard reseau <cible>`) : vide, elle renonce
/// (`None`, rien à faire ni à noter) ; sinon la cible, ou l'erreur à lui montrer. Une faute de frappe n'est pas un
/// défaut du programme : elle n'a rien à faire dans le journal des erreurs, qui en faisait un ticket (#19).
pub(crate) fn cible_tapee(reponse: &str) -> Option<Result<String, String>> {
    let cible = reponse.trim();
    (!cible.is_empty()).then(|| reseau::scan::parse_cible(cible).map(|_| cible.to_string()))
}

pub(crate) fn nommer(appareil: &str, surnom: &str) {
    let surnom = Some(surnom.trim()).filter(|s| !s.is_empty());
    match reseau::nommer(appareil, surnom) {
        Ok(qui) => match surnom {
            Some(s) => trp!(
                "  {VERT}✔{RESET} {qui} s'appelle maintenant « {s} ».",
                "  {VERT}✔{RESET} {qui} is now called “{s}”."
            ),
            None => trp!(
                "  {VERT}✔{RESET} Surnom retiré pour {qui}.",
                "  {VERT}✔{RESET} Nickname removed for {qui}."
            ),
        },
        Err(e) => println!("  ✖ {e}"),
    }
}

/// L'autotest lancé du menu, dans un Vanguard à part : il pose pour tout son processus la lecture seule et le travail
/// sans Internet, et n'arrête une règle bloquée qu'en sortant. Lancé ici, la suite de la session n'écrirait plus rien
/// (corrections non notées, donc impossibles à défaire) et se croirait hors ligne.
fn autotest_a_part() {
    // Sous Linux, la copie temporaire s'est effacée : `current_exe` rendrait un chemin « (deleted) ».
    let lance = crate::protection::cle::programme_a_relancer()
        .and_then(|exe| crate::coulisses::Suivie::status_suivi(std::process::Command::new(exe).arg("autotest")));
    if let Err(e) = lance {
        trp!(
            "  ✖ Autotest impossible à lancer : {e}. En ligne de commande : vanguard autotest.",
            "  ✖ Could not start the self-test: {e}. From the command line: vanguard self-test."
        );
    }
}

/// La première ouverture du menu de la 0.87 par quelqu'un qui connaissait l'ancien (un bilan déjà fait) : l'en-tête
/// le dit pendant cette session, à la place d'un autre avis, sans touche de plus (les essais de la VM tapent leurs
/// chemins à l'aveugle). Les chemins 4.x, 6.x, 7.x, 8.x et 12.x ont changé de sens ; rien ne se modifie sans accord,
/// mais un ancien chemin ouvre un autre écran.
fn premiere_ouverture_du_nouveau_menu() -> bool {
    !marque_du_nouveau_menu().exists() && !historique::charger().is_empty()
}

fn marque_du_nouveau_menu() -> std::path::PathBuf {
    socle::dossier_local().join("menu-0.87")
}

/// L'avis du nouveau menu a paru : la marque est posée une fois (sans suivre de lien : Vanguard peut tourner en root
/// avec le dossier d'un compte). Sans dossier inscriptible, l'avis reviendra à la prochaine session : rien de faux.
pub(crate) fn avis_du_nouveau_menu_vu() {
    static VU: std::sync::Once = std::sync::Once::new();
    VU.call_once(|| {
        let _ = socle::ecrire_atomique(&marque_du_nouveau_menu(), b"");
    });
}

pub(crate) async fn menu() {
    // La tête du journal notée dès l'ouverture du menu (preuve d'une prochaine mise à jour, `sceau::forme_d_avant`).
    crate::modele::journal::noter_version();
    let mut s = Session::default();
    let nouveau_menu = premiere_ouverture_du_nouveau_menu();
    // L'avis du partage (phase 1) ou la question (phase 2), avant le premier écran du menu ; rien tant que le relais
    // n'est pas en service.
    parametres::partage::au_menu();
    // La ligne en surbrillance au retour dans le menu : la dernière choisie.
    let mut dernier = String::from("1");
    loop {
        print!("\x1b[2J\x1b[H");
        let lignes = lignes_du_menu(etat_du_menu(reseau::surveillance::active(), nouveau_menu));
        let invite = format!(
            "  {ACCENT}›{RESET} {}",
            tr!("Numéro, ou un mot à chercher : ", "Number, or a word to search: ")
        );
        let Some(choix) = choisir_au_sommet(&lignes, &invite, &dernier, tr!("quitter", "quit")) else {
            break;
        };
        let choix = choix.trim().to_lowercase();
        if choix == "q" {
            break;
        }
        println!();
        if ouvrir_touche(&mut s, &choix).await {
            // Le groupe d'où vient l'outil, en surbrillance au retour (« 5 » pour « 5.2 »).
            dernier = choix.split('.').next().unwrap_or(&choix).to_string();
        }
    }
}

/// Le choix fait dans un menu, avec l'invite commune (`None` : Échap, qui fait `echap`).
fn choix_du_menu(lignes: &[Ligne], dernier: &str, echap: &str) -> Option<String> {
    let invite = format!("  {ACCENT}›{RESET} {}", tr!("Choix : ", "Choice: "));
    choisir(lignes, &invite, dernier, echap)
}

/// Après un outil lancé du menu : Entrée pour y revenir, sauf pour ceux qui ont leurs propres écrans.
pub(crate) fn revenir_au_menu(action: Action) {
    // Quitté par « revenir » : l'outil s'est arrêté à ta demande, la pause serait un appui de trop.
    if action.attendre_apres() && !ui::vient_de_revenir() {
        crate::selection::attendre_retour(&trf!(
            "\n{GRIS}Entrée pour revenir au menu…{RESET}",
            "\n{GRIS}Enter to go back to the menu…{RESET}"
        ));
    }
}

/// Un écran d'outils numérotés (un groupe, ou les variantes d'un écran à choix), Entrée pour revenir.
async fn liste_d_outils(s: &mut Session, chemin: &str, resume: &str, actions: &[Action], retour: &str) {
    let mut dernier = s.ligne_gardee(chemin, actions);
    loop {
        print!("\x1b[2J\x1b[H");
        let mut lignes: Vec<Ligne> = vec![Ligne::cadre(
            &format!("{ACCENT}VANGUARD{RESET} {GRIS}›{RESET} {chemin}"),
            resume,
        )];
        lignes.push(Ligne::Texte(String::new()));
        for (i, a) in actions.iter().enumerate() {
            let (texte, precision) = a.libelle();
            let texte = if a.variantes().is_empty() && !a.ouvre_ses_ecrans() {
                texte.to_string()
            } else {
                format!("{texte} {ACCENT}›{RESET}")
            };
            // Les variantes d'un écran à choix n'ont pas de ligne ici : l'aperçu les montre.
            lignes.push(
                Ligne::choix(&i.saturating_add(1).to_string(), &texte, precision)
                    .avec_description(a.description())
                    .avec_sous(a.ce_qu_il_ouvre()),
            );
        }
        lignes.push(Ligne::Texte(String::new()));
        lignes.push(Ligne::choix("↵", retour, ""));
        lignes.push(Ligne::Texte(String::new()));
        let Some(choix) = choix_du_menu(&lignes, &dernier, tr!("revenir", "back")) else {
            return;
        };
        let choix = choix.trim();
        if choix.is_empty() || choix == "↵" || choix.eq_ignore_ascii_case("q") {
            return;
        }
        let Some(&action) = choix
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|i| actions.get(i))
        else {
            continue;
        };
        dernier = choix.to_string();
        s.choisis.insert(chemin.to_string(), action);
        println!();
        lancer(s, action, chemin).await;
        if action.attendre_apres() && !ui::vient_de_revenir() {
            crate::selection::attendre_retour(&trf!(
                "\n{GRIS}Entrée pour revenir…{RESET}",
                "\n{GRIS}Enter to go back…{RESET}"
            ));
        }
    }
}

/// Un outil, ou l'écran de ses variantes s'il en a (`chemin` : celui de l'écran d'où il est ouvert).
pub(crate) async fn lancer(s: &mut Session, action: Action, chemin: &str) {
    let variantes: Vec<Action> = action.variantes().iter().copied().filter(|v| v.disponible()).collect();
    if variantes.is_empty() {
        return executer(s, action).await;
    }
    let (titre, precision) = action.libelle();
    let chemin = format!("{chemin} {GRIS}›{RESET} {titre}");
    Box::pin(liste_d_outils(
        s,
        &chemin,
        precision,
        &variantes,
        tr!("Revenir", "Back"),
    ))
    .await;
}

/// Sous-menu d'un groupe. Le guide et le dépannage s'ouvrent directement sur leurs propres écrans.
pub(crate) async fn sous_menu(s: &mut Session, groupe: Groupe) {
    let actions: Vec<Action> = groupe.actions().into_iter().filter(|a| a.disponible()).collect();
    // Un groupe direct sans outil disponible tombe sur sa liste (vide) plutôt que d'arrêter le programme.
    if groupe.direct()
        && let Some(&premier) = actions.first()
    {
        executer(s, premier).await;
        revenir_au_menu(premier);
        return;
    }
    liste_d_outils(
        s,
        groupe.titre(),
        groupe.resume(),
        &actions,
        tr!("Revenir au menu principal", "Back to the main menu"),
    )
    .await;
}

/// Dépanner pas à pas : les parcours, puis les autres outils du groupe (réparer une panne connue, le matériel).
pub(crate) fn depanner_avec_ses_outils() {
    let autres: Vec<Action> = Groupe::Depanner
        .actions()
        .into_iter()
        .filter(|a| *a != Action::Depanner && a.disponible())
        .collect();
    let lignes: Vec<(&str, &str, &str)> = autres
        .iter()
        .map(|a| {
            let (titre, precision) = a.libelle();
            (titre, precision, a.outil().mots)
        })
        .collect();
    depanner::menu(&lignes, &mut |i| {
        // `i` vient d'une ligne de `lignes`, bâtie depuis `autres` : un numéro hors liste ne lance rien.
        let Some(&action) = autres.get(i) else { return };
        match action {
            Action::Reparer => reparer::menu(),
            Action::Diagnostic => diagnostic::diagnostic(),
            // Le test `depanner_a_ses_deux_outils` arrête tout autre outil ajouté au groupe sans sa ligne ici.
            _ => {}
        }
        revenir_au_menu(action);
    });
}

/// Un outil du menu, compté par le relevé local (`amelioration`) : lancé, fini ou laissé, et sa durée.
pub(crate) async fn executer(s: &mut Session, action: Action) {
    let commande = action.outil().commande;
    crate::amelioration::outil_lance(commande, crate::compte_rendu::envoi::Origine::Menu);
    let debut = std::time::Instant::now();
    executer_outil(s, action).await;
    crate::amelioration::outil_fini(
        commande,
        crate::compte_rendu::envoi::Origine::Menu,
        ui::revenu(),
        debut.elapsed(),
    );
}

async fn executer_outil(s: &mut Session, action: Action) {
    // Le choix de l'outil dans le menu n'est pas un « revenir » : seul compte ce qui se répond dans l'outil.
    ui::noter_retour(false);
    if action.outil().groupe == Some(Groupe::Optimiser) && refuser_optimiser() {
        return;
    }
    match action {
        Action::Complet => s.complet().await,
        Action::Corriger => {
            s.corriger();
        }
        Action::Rapport => {
            if s.audit.is_none() && s.reseau.is_none() {
                s.complet().await;
            }
            rapport::ouvrir(s.audit.as_ref(), s.reseau.as_ref(), s.audit_reseau.as_ref());
        }
        Action::Audit => s.audit = Some(machine::executer(false)),
        Action::Integrite => protection::integrite::verifier(false),
        Action::Appris => apprentissage::menu(),
        Action::Changements => changements::afficher(),
        Action::Lenteur => lenteur::menu(),
        Action::Fiche => fiche::fiche(false),
        Action::ALaisser => {
            let audit = s.audit.get_or_insert_with(|| machine::executer(false));
            a_laisser::laisser(audit);
        }
        Action::Entretien => entretien::activer(!entretien::active()),
        Action::Diagnostic => diagnostic::diagnostic(),
        Action::Maj => maj::executer(),
        Action::Reparer => reparer::menu(),
        Action::Scanner => s.scanner_reseau(None, "courants").await,
        Action::AuditReseau => s.audit_reseau(false, false, false).await,
        Action::Appareil => {
            let reponse = demander(tr!(
                "Adresse IP de l'appareil (ex. 10.0.0.1) : ",
                "IP address of the device (e.g. 10.0.0.1): "
            ));
            match cible_tapee(&reponse) {
                None => {}
                Some(Ok(ip)) => s.scanner_reseau(Some(ip), "tous").await,
                Some(Err(e)) => println!("  ✖ {e}"),
            }
        }
        Action::Nommer => {
            let qui = demander(tr!(
                "IP ou adresse MAC de l'appareil : ",
                "IP or MAC address of the device: "
            ));
            let surnom = demander(tr!(
                "Surnom (vide pour le retirer) : ",
                "Nickname (empty to remove it): "
            ));
            nommer(&qui, &surnom);
        }
        Action::Surveillance => reseau::surveillance::activer(!reseau::surveillance::active()),
        Action::Tableau => reseau::tableau::ouvrir(false, fonctions_du_menu()),
        Action::Veilleur => veilleur(None, None, false),
        Action::Connexion => reseau::connexion::tester().await,
        Action::ListesNoires => reseau::listes_noires::verifier(),
        Action::WifiCanaux => reseau::canaux::analyser(),
        Action::Nat => reseau::nat::tester(),
        Action::Cameras => reseau::cameras::chercher_cameras().await,
        Action::Objets => reseau::objets::montrer(),
        Action::WifiPublic => reseau::wifi_public::commande(None),
        Action::AntivirusRapide => protection::antivirus::analyser(protection::antivirus::Portee::Rapide),
        Action::AntivirusComplet => protection::antivirus::analyser(protection::antivirus::Portee::Complete),
        Action::AntivirusDossier => protection::antivirus::choisir(),
        Action::AntivirusEtat => protection::etat_antivirus::montrer(protection::etat_antivirus::Detail::Demander),
        Action::Yara => protection::yara::menu(),
        Action::Memoire => protection::memoire::analyser(),
        Action::Pieges => protection::pieges::menu(),
        Action::Bac => {
            let chemin = demander(tr!("  Programme à isoler (chemin) : ", "  Program to isolate (path): "));
            let chemin = chemin.trim().trim_matches(['"', '\'']);
            if !chemin.is_empty() {
                protection::isoler::isoler(std::path::Path::new(chemin));
            }
        }
        Action::MotsDePasse => protection::fuites::verifier(),
        Action::Navigateurs => machine::mots_de_passe::navigateurs(),
        Action::Courriel => protection::fuites::verifier_courriel(),
        Action::QuiParle => protection::sortantes::menu(),
        Action::SitesDangereux => protection::sites_bloques::menu(),
        Action::DernieresFailles => protection::kev::ecran(7),
        Action::CameraMicro => protection::camera::afficher_tout(),
        Action::Acces => protection::acces::afficher_tout(),
        Action::Distance => protection::distance::menu(),
        Action::Lien => protection::lien::verifier(None),
        Action::CourrielSuspect => protection::courriel_suspect::verifier(None),
        Action::LogicielsEspions => protection::espions::afficher(),
        Action::LogicielsPerimes => protection::perimes::afficher(),
        Action::Signaler => signaler::menu(),
        Action::VerifierFichier => protection::telechargement::verifier(None, None),
        Action::Quarantaine => protection::quarantaine::menu(),
        Action::SecretsGit => protection::secrets_git::analyser(),
        Action::Conteneurs => protection::conteneurs::analyser(),
        Action::Blocage => protection::blocage::menu(),
        Action::Logiciels => logiciels::menu(),
        Action::Gaming => gaming::menu(),
        Action::Nettoyer => nettoyer::menu(),
        Action::OptimiserRecommandes => optimiser::recommandes(),
        Action::OptimiserConfidentialite => optimiser::menu(optimiser::Categorie::Confidentialite),
        Action::OptimiserPerformance => optimiser::menu(optimiser::Categorie::Performance),
        Action::OptimiserConfort => optimiser::menu(optimiser::Categorie::Confort),
        Action::OptionsDefense => options_defense::afficher(),
        Action::DnsRapide => dns_rapide::mesurer_et_proposer(),
        Action::OptimiserAnnuler => optimiser::tout_annuler(),
        Action::Sauvegarder => donnees::menu(),
        Action::CopierFichiers => copier::menu(),
        Action::SauvegardeAuto => sauvegarde::menu(),
        Action::VerifierCopie => copier::verifier_copie(None),
        Action::VerifierSauvegarde => sauvegarde::verifier_sauvegarde(),
        Action::Desinstaller => desinstaller::commande(false),
        Action::VerifierCle => verifier_cle::menu(),
        Action::Raccourci => raccourci::commande(None),
        Action::Ordinateurs => ordinateurs::menu(),
        Action::ProtegerDonnees => chiffrement::menu(),
        Action::MettreAJour => mise_a_jour::commande(),
        Action::Guide => guide::menu(),
        Action::Depanner => depanner_avec_ses_outils(),
        Action::DepannerInfection => depanner::executer("infection"),
        Action::DepannerCompte => depanner::executer("compte"),
        // Le parcours 11.11, avec son conseil (avant de nettoyer, et où ranger le dossier).
        Action::Traces => depanner::executer("traces"),
        Action::Evenements => evenements::afficher(false, None),
        Action::JournauxWindows => journaux_windows::commande::menu(),
        Action::Demarrage => optimiser::programmes_au_demarrage(),
        Action::Regles => machine::regles::afficher(),
        Action::VerifierMoi => protection::manifeste::verifier_moi(None),
        Action::Autotest => autotest_a_part(),
        // Les écrans à choix passent par `lancer` : jamais exécutés eux-mêmes.
        Action::Developpeurs
        | Action::Appareils
        | Action::Antivirus
        | Action::VerifierCopies
        | Action::VerifierVanguard => {}
        Action::Extensions => plugins::extensions(),
        Action::Parametres => parametres::menu(),
    }
}

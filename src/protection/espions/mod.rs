//! Logiciels espions : en ai-je un ? Les signes qu'un ordinateur est épié par quelqu'un de l'entourage : connexions
//! et noms demandés vers les serveurs et sites des logiciels espions connus (liste d'Échap, CC-BY 4.0), logiciels de
//! surveillance connus installés ou en marche, et ce que chaque système laisse voir des programmes qui lisent le
//! clavier (Linux : /dev/input ; macOS : les autorisations de surveillance). Lecture seule : rien n'est retiré ni
//! bloqué, car celui qui a posé le logiciel peut le voir disparaître ; l'écran le dit, avec qui appeler.
//!
//! Ce qui n'a pas pu être vérifié est dit et compté : le verdict n'est jamais « aucun logiciel espion », seulement
//! « aucun signe parmi ce qui a été vérifié ». Un logiciel de prise de contrôle à distance est renvoyé à « Mon
//! ordinateur est-il contrôlé ? ».

#[cfg(any(target_os = "linux", test))]
mod clavier;
mod connus;
mod echap;
pub(crate) mod resultat;
#[cfg(any(target_os = "macos", test))]
pub(crate) mod tcc;
#[cfg(windows)]
mod windows;

use std::collections::BTreeSet;
use std::time::Duration;

use echap::{Genre, Indicateurs};
// Les canaris de la veille de nuit relisent la vraie liste par ce lecteur-ci.
#[cfg(test)]
pub(crate) use echap::{comptes as echap_comptes, demande as echap_demande};

use crate::machine::{Constat, alerte, impossible, ok};
use crate::protection::sortantes::ConnexionVue;
use crate::risk::Niveau;
use crate::ui::*;

const CAT: &str = "Logiciels espions";
/// Le bilan ne télécharge rien : il se sert de la copie d'Échap gardée par l'écran, si elle a moins d'une semaine.
const AGE_BILAN: Duration = Duration::from_hours(7 * 24);

/// Les navigateurs : un site de logiciel espion ouvert dans l'un d'eux peut être une simple visite (un article, une
/// recherche) ; le même serveur joint par un autre programme est bien plus grave.
const NAVIGATEURS: &[&str] = &[
    "firefox",
    "librewolf",
    "chrome",
    "chromium",
    "msedge",
    "brave",
    "vivaldi",
    "opera",
    "safari",
    "zen",
    "floorp",
    "epiphany",
];

/// Où une trouvaille est montrée.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Section {
    /// Serveurs et sites de la liste d'Échap.
    Indicateurs,
    /// Logiciels de surveillance connus.
    Programmes,
    /// Ce qui est propre au système : lecteurs du clavier, autorisations de macOS.
    Systeme,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Trouvaille {
    pub niveau: Niveau,
    pub section: Section,
    /// Ce qui a été trouvé (« Spyrix : logiciel vendu pour épier »).
    pub quoi: String,
    /// Où (« en cours : spyrix.exe (pid 12) ») ; une trouvaille vue à plusieurs endroits les garde tous.
    pub ou: Vec<String>,
    /// Ce qui a été trouvé, sans langue ni numéro de processus (« programme:Spyrix », « module:kl ») : l'objet du
    /// constat, qui le reconnaît d'un bilan à l'autre.
    pub objet: String,
}

/// Tout ce que le relevé a vu.
#[derive(Debug, Default)]
pub(super) struct Releve {
    pub trouvailles: Vec<Trouvaille>,
    /// Ce qui ressemble à de la surveillance mais est normal (compositeur, autorisation d'OBS) : montré, jamais caché.
    pub reconnus: Vec<String>,
    pub non_verifies: Vec<String>,
    /// Remarques sans alerte (groupe input, session X11, journal WAL).
    pub notes: Vec<String>,
    /// Logiciels de prise de contrôle à distance vus : renvoyés à `distance.rs`.
    pub a_distance: BTreeSet<String>,
    /// Vérifications faites : sans aucune, le bilan dit « impossible », jamais « rien trouvé ».
    pub verifies: usize,
    /// Noms de programmes comparés aux listes.
    pub programmes_vus: usize,
    /// Les connexions en cours, puis la mémoire DNS, ont été comparées à la liste d'Échap : sans elles, aucune ligne
    /// verte ne dit « rien ne correspond ».
    pub connexions_lues: bool,
    pub dns_lu: bool,
    /// Processus dont les fichiers ouverts n'ont pas pu être lus (Linux, sans root) : un enregistreur de frappe tourne
    /// d'ordinaire en root, parmi eux.
    pub clavier_illisibles: usize,
}

/// « Spyrix : logiciel vendu pour épier », avec ce qui rend un contrôle parental ou d'employeur normal.
pub(super) fn texte_genre(s: &connus::Surveillance) -> String {
    match s.genre {
        connus::Genre::Espion => trf!(
            "{} : logiciel vendu pour épier",
            "{}: software sold to spy on people",
            s.nom
        ),
        connus::Genre::Parental => trf!(
            "{} : contrôle parental, normal s'il a été installé exprès (ordinateur d'un enfant) ; sinon, quelqu'un vous surveille",
            "{}: parental control, normal if installed on purpose (a child's computer); otherwise, someone is watching you",
            s.nom
        ),
        connus::Genre::Employeur => trf!(
            "{} : surveillance des employés, normale sur un ordinateur de travail ; sinon, quelqu'un vous surveille",
            "{}: employee monitoring, normal on a work computer; otherwise, someone is watching you",
            s.nom
        ),
    }
}

/// Un logiciel espion nommé par la liste d'Échap.
pub(super) fn texte_echap(entree: &str) -> String {
    trf!(
        "{entree} : logiciel espion de la liste d'Échap",
        "{entree}: spyware on Échap's list"
    )
}

impl Releve {
    /// Une trouvaille ; vue déjà ailleurs (même section, même texte), elle gagne un lieu et garde le niveau le plus
    /// haut.
    pub(super) fn signe(&mut self, section: Section, niveau: Niveau, objet: &str, quoi: &str, ou: String) {
        if let Some(t) = self
            .trouvailles
            .iter_mut()
            .find(|t| t.section == section && t.quoi == quoi)
        {
            t.niveau = t.niveau.max(niveau);
            if !t.ou.contains(&ou) {
                t.ou.push(ou);
            }
            return;
        }
        self.trouvailles.push(Trouvaille {
            niveau,
            section,
            quoi: quoi.to_string(),
            ou: vec![ou],
            objet: objet.to_string(),
        });
    }

    pub(super) fn non_verifie(&mut self, raison: impl Into<String>) {
        let raison = raison.into();
        if !self.non_verifies.contains(&raison) {
            self.non_verifies.push(raison);
        }
    }

    pub(super) fn renvoyer(&mut self, nom: &str) {
        self.a_distance.insert(affichable(nom));
    }

    /// Un nom de programme (installé, processus, service, démarrage) comparé aux logiciels de surveillance connus,
    /// puis aux noms de la liste d'Échap. `actif` : en marche ou lancé au démarrage, plus grave que seulement installé.
    pub(super) fn programme(&mut self, nom: &str, ou: String, actif: bool, ind: Option<&Indicateurs>) {
        self.programmes_vus += 1;
        if crate::protection::distance::controle_a_distance(nom) {
            self.renvoyer(nom);
            return;
        }
        if let Some(s) = connus::reconnu(nom) {
            let niveau = if s.genre == connus::Genre::Espion && actif {
                Niveau::Eleve
            } else {
                Niveau::Moyen
            };
            self.signe(
                Section::Programmes,
                niveau,
                &format!("programme:{}", s.nom),
                &texte_genre(s),
                ou,
            );
        } else if let Some(entree) = ind.and_then(|i| i.produit(nom)) {
            let niveau = if actif { Niveau::Eleve } else { Niveau::Moyen };
            self.signe(
                Section::Programmes,
                niveau,
                &format!("echap:{entree}"),
                &texte_echap(entree),
                ou,
            );
        }
    }
}

/// Le verdict : au moins un signe élevé, sinon moyen, sinon rien parmi ce qui a été vérifié (avec le nombre de
/// points non vérifiés, jamais « sain »).
pub(super) fn juger(r: &Releve) -> (Option<Niveau>, String) {
    let pire = r.trouvailles.iter().map(|t| t.niveau).max();
    let texte = match pire {
        Some(n) if n >= Niveau::Eleve => {
            tr!("Signes sérieux d'un logiciel espion.", "Serious signs of spyware.").to_string()
        }
        Some(_) => tr!(
            "À regarder : rien de sûr, mais ces points méritent un coup d'œil.",
            "Worth a look: nothing certain, but check these."
        )
        .to_string(),
        None => trf!(
            "Aucun signe parmi ce qui a été vérifié ({} point(s) non vérifié(s)).",
            "No sign among what was checked ({} item(s) not checked).",
            r.non_verifies.len()
        ),
    };
    (pire, texte)
}

/// Le programme d'une connexion est-il un navigateur ?
fn navigateur(c: &ConnexionVue) -> bool {
    let exe = c.chemin.as_deref().and_then(|c| c.rsplit(['/', '\\']).next());
    [c.programme.as_deref(), exe].into_iter().flatten().any(|n| {
        let bas = n.to_lowercase();
        NAVIGATEURS
            .iter()
            .any(|nav| crate::protection::distance::contient_mot(&bas, nav))
    })
}

/// Les connexions en cours vers une adresse de la liste. Un navigateur peut n'avoir ouvert qu'une page (moyen) ; un
/// autre programme, ou un programme d'un autre compte qu'on ne voit pas, parle au serveur lui-même (élevé).
fn connexions_espions(r: &mut Releve, ind: &Indicateurs, connexions: &[ConnexionVue]) {
    for c in connexions
        .iter()
        .filter(|c| crate::socle::adresses::sur_internet(c.distante))
    {
        let Some((entree, genre)) = ind.ip(c.distante) else {
            continue;
        };
        let quoi = match genre {
            Genre::Serveur => trf!(
                "connexion à un serveur de {entree} (logiciel espion)",
                "connection to a server of {entree} (spyware)"
            ),
            Genre::Site => trf!(
                "connexion à un site de {entree} (logiciel espion)",
                "connection to a site of {entree} (spyware)"
            ),
        };
        let adresse = std::net::SocketAddr::new(c.distante.to_canonical(), c.port);
        let (niveau, programme) = match (&c.programme, navigateur(c)) {
            (None, _) => (
                Niveau::Eleve,
                tr!("programme d'un autre compte", "program of another account").to_string(),
            ),
            (Some(p), true) => (Niveau::Moyen, p.clone()),
            (Some(p), false) => (Niveau::Eleve, p.clone()),
        };
        let pid = c.pid.map(|p| format!(" (pid {p})")).unwrap_or_default();
        let objet = match genre {
            Genre::Serveur => format!("connexion-serveur:{entree}"),
            Genre::Site => format!("connexion-site:{entree}"),
        };
        r.signe(
            Section::Indicateurs,
            niveau,
            &objet,
            &quoi,
            format!("{programme}{pid} → {adresse}"),
        );
    }
}

/// Les noms demandés récemment (mémoire DNS) qui sont sur la liste : la connexion peut être fermée, le nom reste.
fn memoire_espions(r: &mut Releve, ind: &Indicateurs, noms: &[String]) {
    for n in noms {
        let Some((entree, genre)) = ind.nom(n) else {
            continue;
        };
        let quoi = match genre {
            Genre::Serveur => trf!(
                "cet ordinateur a contacté un serveur de {entree} (logiciel espion)",
                "this computer contacted a server of {entree} (spyware)"
            ),
            Genre::Site => trf!(
                "site de vente ou tableau de bord de {entree} consulté : quelqu'un a pu s'en servir pour surveiller un téléphone depuis cet ordinateur, ou pour l'installer",
                "sales site or dashboard of {entree} visited: someone may have used it to watch a phone from this computer, or to install it"
            ),
        };
        let objet = match genre {
            Genre::Serveur => format!("nom-serveur:{entree}"),
            Genre::Site => format!("nom-site:{entree}"),
        };
        r.signe(
            Section::Indicateurs,
            Niveau::Moyen,
            &objet,
            &quoi,
            trf!("nom demandé : {}", "name asked: {}", affichable(n)),
        );
    }
}

/// Linux : les processus (nom court et exécutable, lisibles pour tous les comptes) comparés aux logiciels connus ;
/// les lecteurs du clavier ; un module du noyau enregistreur ; le groupe « input » et X11.
#[cfg(target_os = "linux")]
fn relever_linux(r: &mut Releve, ind: Option<&Indicateurs>) {
    use crate::socle::processus;
    // /proc illisible : non vérifié. La boucle d'avant, vide, comptait la vérification comme faite.
    if let Some(pids) = processus::pids() {
        for pid in pids {
            let Some(comm) = processus::nom_court(pid) else {
                continue;
            };
            let comm = affichable(&comm);
            let ou = trf!("en cours : {comm} (pid {pid})", "running: {comm} (pid {pid})");
            r.programme(&comm, ou.clone(), true, ind);
            if let Some(exe) = processus::programme(pid)
                && let Some(nom) = exe.file_name().map(|n| n.to_string_lossy().into_owned())
                && nom != comm
            {
                r.programme(&nom, ou, true, ind);
            }
        }
        r.verifies += 1;
        if processus::autres_comptes_caches() {
            r.non_verifie(tr!(
                "processus des autres comptes cachés (/proc monté avec hidepid)",
                "other accounts' processes hidden (/proc mounted with hidepid)"
            ));
        }
    } else {
        r.non_verifie(tr!("processus illisibles (/proc)", "processes unreadable (/proc)"));
    }
    let montages = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    let (lecteurs, illisibles) = clavier::lecteurs();
    r.verifies += 1;
    r.clavier_illisibles = illisibles;
    for l in &lecteurs {
        let claviers = l.claviers.join(", ");
        // L'exécutable est montré même pour un lecteur reconnu : un nom court emprunté se voit à côté de lui.
        let lecteur = match l.chemin.as_deref() {
            Some(c) => format!("{} (pid {}, {})", l.programme, l.pid, affichable(c)),
            None => format!("{} (pid {})", l.programme, l.pid),
        };
        let ou = trf!("{lecteur} tient : {claviers}", "{lecteur} holds: {claviers}");
        match clavier::juger(l, &montages) {
            None => r.reconnus.push(ou),
            Some((niveau, raison)) => {
                let quoi = trf!(
                    "{} lit le clavier — {raison}",
                    "{} reads the keyboard — {raison}",
                    l.programme
                );
                r.signe(Section::Systeme, niveau, &format!("clavier:{}", l.programme), &quoi, ou);
            }
        }
    }
    if illisibles > 0 {
        r.non_verifie(trf!(
            "{illisibles} processus d'autres comptes non vérifiés (sudo vanguard logiciels-espions)",
            "{illisibles} processes of other accounts not checked (sudo vanguard spyware)"
        ));
    }
    match std::fs::read_to_string("/proc/modules") {
        Ok(modules) => {
            if let Some(m) = clavier::module_espion(&modules) {
                r.signe(
                    Section::Systeme,
                    Niveau::Eleve,
                    &format!("module:{m}"),
                    &trf!(
                        "module du noyau enregistreur de frappes : {m}",
                        "kernel module that records keystrokes: {m}"
                    ),
                    "/proc/modules".into(),
                );
            }
        }
        Err(_) => r.non_verifie(tr!("modules du noyau illisibles", "kernel modules unreadable")),
    }
    let group = std::fs::read_to_string("/etc/group").unwrap_or_default();
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    if clavier::dans_le_groupe_input(&group, &status) {
        r.notes.push(
            tr!(
                "votre compte est dans le groupe « input » : tout programme lancé par votre compte peut lire le clavier sans droits",
                "your account is in the “input” group: any program started by your account can read the keyboard without rights"
            )
            .to_string(),
        );
    }
    let variable = |v: &str| std::env::var_os(v).is_some_and(|x| !x.is_empty());
    let x11 = std::env::var("XDG_SESSION_TYPE").is_ok_and(|t| t == "x11")
        || (variable("DISPLAY") && !variable("WAYLAND_DISPLAY"));
    if x11 {
        r.non_verifie(tr!(
            "sous X11, un programme lit les touches sans passer par /dev/input : non vérifiable",
            "on X11, a program reads keys without going through /dev/input: not checkable"
        ));
    }
}

/// Ce que le système laisse voir, sans réseau : partagé par l'écran et le bilan.
fn relever_systeme(r: &mut Releve, ind: Option<&Indicateurs>) {
    #[cfg(target_os = "linux")]
    relever_linux(r, ind);
    #[cfg(target_os = "macos")]
    tcc::relever(r, ind);
    #[cfg(windows)]
    windows::relever(r, ind);
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    let _ = (r, ind);
}

/// L'âge d'une copie, tel qu'il est montré.
fn age_montre(age: Duration) -> String {
    match age.as_secs() / 86_400 {
        0 => tr!("copie de moins d'un jour", "copy less than a day old").to_string(),
        j => trf!("copie de {j} jour(s)", "copy {j} day(s) old"),
    }
}

/// Le relevé de l'écran : la liste d'Échap (téléchargée si besoin), les connexions et la mémoire DNS, puis le système.
/// Rend aussi l'âge de la copie d'Échap quand elle a servi.
fn relever_ecran() -> (Releve, Option<Duration>) {
    let mut r = Releve::default();
    let echap = echap::indicateurs(true, echap::AGE_ECRAN);
    let (ind, age) = match echap {
        Ok((ind, age)) => (Some(ind), Some(age)),
        Err(raison) => {
            r.non_verifie(trf!(
                "liste d'Échap non vérifiée : {raison}",
                "Échap list not checked: {raison}"
            ));
            (None, None)
        }
    };
    if let Some(ind) = &ind {
        match crate::protection::sortantes::connexions_vues() {
            Some(c) => {
                r.verifies += 1;
                r.connexions_lues = true;
                connexions_espions(&mut r, ind, &c);
            }
            None => r.non_verifie(tr!("connexions illisibles", "connections unreadable")),
        }
        match crate::protection::memoire_dns::noms() {
            Ok(noms) => {
                r.verifies += 1;
                r.dns_lu = true;
                memoire_espions(&mut r, ind, &noms);
            }
            Err(raison) => r.non_verifie(trf!(
                "mémoire DNS non vérifiée : {raison}",
                "DNS cache not checked: {raison}"
            )),
        }
    }
    relever_systeme(&mut r, ind.as_ref());
    (r, age)
}

/// La ligne « rien ne correspond » des serveurs et sites : seulement pour ce qui a vraiment été comparé à la liste.
fn rien_indicateurs(r: &Releve, echap_lue: bool) -> Option<&'static str> {
    match (echap_lue, r.connexions_lues, r.dns_lu) {
        (true, true, true) => Some(tr!(
            "Aucune connexion ni aucun nom demandé ne correspond à la liste.",
            "No connection or name asked matches the list."
        )),
        (true, true, false) => Some(tr!(
            "Aucune connexion en cours ne correspond à la liste.",
            "No current connection matches the list."
        )),
        (true, false, true) => Some(tr!(
            "Aucun nom demandé ne correspond à la liste.",
            "No name asked matches the list."
        )),
        _ => None,
    }
}

/// La ligne « rien » des logiciels de surveillance : (texte, coche verte). Sans la liste d'Échap, les noms n'ont été
/// comparés qu'aux logiciels que Vanguard connaît lui-même : une information, pas une coche.
fn rien_programmes(r: &Releve, echap_lue: bool) -> Option<(String, bool)> {
    if r.programmes_vus == 0 {
        return None;
    }
    Some(if echap_lue {
        (
            trf!(
                "Aucun logiciel de surveillance connu parmi {} noms vérifiés.",
                "No known monitoring software among {} names checked.",
                r.programmes_vus
            ),
            true,
        )
    } else {
        (
            trf!(
                "Aucun logiciel de surveillance connu parmi {} noms, comparés à la liste de Vanguard seulement.",
                "No known monitoring software among {} names, compared with Vanguard's own list only.",
                r.programmes_vus
            ),
            false,
        )
    })
}

/// La ligne « rien » de « Qui lit le clavier ? » : (texte, tout a été lu). Des processus illisibles (ceux de root,
/// sans sudo) la rendent partielle, sans coche verte.
fn rien_clavier(r: &Releve) -> (&'static str, bool) {
    if r.clavier_illisibles == 0 {
        (
            tr!(
                "Aucun programme inconnu ne lit le clavier.",
                "No unknown program reads the keyboard."
            ),
            true,
        )
    } else {
        (
            tr!(
                "Aucun programme inconnu parmi ceux lus ; ceux des autres comptes n'ont pas été vus.",
                "No unknown program among those read; other accounts' were not seen."
            ),
            false,
        )
    }
}

/// Les trouvailles d'une section, ou une ligne qui dit que rien n'y a été vu : (texte, coche verte ; sinon une
/// simple information, quand une partie n'a pas été lue).
fn afficher_section(r: &Releve, section: Section, titre: &str, rien: Option<(&str, bool)>) {
    let liste: Vec<&Trouvaille> = r.trouvailles.iter().filter(|t| t.section == section).collect();
    if liste.is_empty() && rien.is_none() {
        return;
    }
    crate::ui::section(titre);
    for t in &liste {
        let (signe, style) = match t.niveau {
            Niveau::Eleve | Niveau::Critique => ("✖", couleur(Niveau::Eleve)),
            _ => ("⚠", couleur(Niveau::Moyen)),
        };
        afficher_aligne(&format!("  {style}{signe}{RESET} "), &t.quoi, 4, "");
        for ou in t.ou.iter().take(5) {
            afficher_aligne("      ", ou, 6, GRIS);
        }
        if t.ou.len() > 5 {
            afficher_aligne(
                "      ",
                &trf!("… et {} autre(s)", "… and {} more", t.ou.len() - 5),
                6,
                GRIS,
            );
        }
    }
    if let (true, Some((rien, complet))) = (liste.is_empty(), rien) {
        let signe = if complet {
            format!("  {VERT}✔{RESET} ")
        } else {
            format!("  {}ℹ{RESET} ", couleur(Niveau::Info))
        };
        afficher_aligne(&signe, rien, 4, "");
    }
}

/// L'écran entier ; rend le niveau le plus grave trouvé.
fn ecran() -> Option<Niveau> {
    titre(tr!(
        "Logiciels espions : en ai-je un ?",
        "Spyware: is someone watching me?"
    ));
    for ligne in envelopper(
        tr!(
            "Les signes d'un logiciel espion sur cet ordinateur : serveurs et sites connus, logiciels de surveillance, programmes qui lisent le clavier. Lecture seule : rien n'est retiré ni bloqué.",
            "Signs of spyware on this computer: known servers and sites, monitoring software, programs reading the keyboard. Read-only: nothing is removed or blocked."
        ),
        LARGEUR - 2,
    ) {
        println!("  {ligne}");
    }
    let debut = (chrono::Utc::now(), std::time::Instant::now());
    let (r, age) = relever_ecran();
    crate::modele::resultat::verser(&resultat::resultat(&r, debut));
    let echap_lue = age.is_some();
    afficher_section(
        &r,
        Section::Indicateurs,
        tr!("Serveurs et sites connus (Échap)", "Known servers and sites (Échap)"),
        rien_indicateurs(&r, echap_lue).map(|t| (t, true)),
    );
    let programmes_rien = rien_programmes(&r, echap_lue);
    afficher_section(
        &r,
        Section::Programmes,
        tr!("Logiciels de surveillance connus", "Known monitoring software"),
        programmes_rien.as_ref().map(|(t, complet)| (t.as_str(), *complet)),
    );
    let (titre_systeme, rien_systeme) = if cfg!(target_os = "linux") {
        (
            tr!("Qui lit le clavier ?", "Who reads the keyboard?"),
            Some(rien_clavier(&r)),
        )
    } else if cfg!(target_os = "macos") {
        (tr!("Autorisations de surveillance", "Monitoring permissions"), None)
    } else {
        (tr!("Ce que Windows ne montre pas", "What Windows does not show"), None)
    };
    afficher_section(&r, Section::Systeme, titre_systeme, rien_systeme);
    if !r.reconnus.is_empty() {
        crate::ui::section(tr!("Reconnus (normaux)", "Recognized (normal)"));
        for l in &r.reconnus {
            afficher_aligne(&format!("  {GRIS}·{RESET} "), l, 4, GRIS);
        }
    }
    if !r.a_distance.is_empty() {
        let noms: Vec<&String> = r.a_distance.iter().collect();
        println!();
        afficher_aligne(
            &format!("  {}ℹ{RESET} ", couleur(Niveau::Info)),
            &trf!(
                "Logiciel de prise de contrôle à distance vu ({}) : regardez « Mon ordinateur est-il contrôlé ? ».",
                "Remote control software seen ({}): see “Is my computer being controlled?”.",
                resume(&noms, 3, ", ")
            ),
            4,
            "",
        );
    }
    for n in &r.notes {
        afficher_aligne(&format!("  {}ℹ{RESET} ", couleur(Niveau::Info)), n, 4, "");
    }
    if !r.non_verifies.is_empty() {
        crate::ui::section(tr!("Non vérifié", "Not checked"));
        for n in &r.non_verifies {
            afficher_aligne(&format!("  {GRIS}?{RESET} "), n, 4, GRIS);
        }
    }
    let (pire, verdict) = juger(&r);
    println!();
    let style = pire.map_or(VERT, |n| couleur(n.max(Niveau::Moyen)));
    afficher_aligne(&format!("  {style}{GRAS}"), &verdict, 2, "");
    if pire.is_some() {
        afficher_aligne(
            &format!("  {}! {RESET}", couleur(Niveau::Eleve)),
            tr!(
                "Si quelqu'un de votre entourage a pu l'installer, le retirer peut l'alerter : gardez des captures et demandez de l'aide avant (Échap : https://echap.eu.org).",
                "If someone close to you may have installed it, removing it can alert them: keep screenshots and ask for help first (Échap: https://echap.eu.org)."
            ),
            4,
            "",
        );
    }
    afficher_aligne(
        "  ",
        tr!(
            "Rien n'a été retiré ni bloqué. Un programme en cours se bloque dans « Blocage des menaces » ; « Après une infection » (Dépanner) guide la suite.",
            "Nothing was removed or blocked. A running program is blocked in “Threat blocking”; “After an infection” (Troubleshoot) guides what comes next."
        ),
        2,
        GRIS,
    );
    let mention = tr!("Indicateurs : Échap (CC-BY 4.0)", "Indicators: Échap (CC-BY 4.0)");
    let pied = age.map_or_else(|| mention.to_string(), |a| format!("{mention} · {}", age_montre(a)));
    afficher_aligne("  ", &pied, 2, DISCRET);
    pire
}

/// `vanguard logiciels-espions`, et le menu (qui demande Entrée ensuite, comme pour chaque outil).
pub fn afficher() {
    let _ = ecran();
}

/// `vanguard logiciels-espions --json` : le même relevé que l'écran, jugé en résultat et versé comme lui.
pub fn json() {
    let debut = (chrono::Utc::now(), std::time::Instant::now());
    let (r, _) = relever_ecran();
    let res = resultat::resultat(&r, debut);
    crate::modele::resultat::verser(&res);
    println!("{}", crate::modele::resultat::json(&res));
}

/// Les constats du bilan, sans réseau : la copie d'Échap seulement si elle a moins d'une semaine (pour les noms des
/// logiciels), puis ce que le système laisse voir.
pub(crate) fn constats() -> Vec<Constat> {
    let ind = echap::indicateurs(false, AGE_BILAN);
    constats_avec(ind.as_ref().map(|(i, _)| i), relever_systeme)
}

/// Le bilan, avec la liste lue (ou pourquoi elle ne l'est pas) et le relevé du système (`relever_systeme`, ou un
/// relevé inventé dans les tests).
fn constats_avec(ind: Result<&Indicateurs, &String>, systeme: fn(&mut Releve, Option<&Indicateurs>)) -> Vec<Constat> {
    let mut r = Releve::default();
    match &ind {
        Err(raison) => r.non_verifie(trf!(
            "liste d'Échap non vérifiée : {raison}",
            "Échap list not checked: {raison}"
        )),
        // Le bilan ne regarde ni les connexions ni la mémoire DNS (l'écran le fait) : les serveurs de la liste n'y
        // sont pas comparés, et un « aucun signe » sans le dire les compterait comme sains. Sous macOS, tcc.rs dit
        // déjà les connexions.
        Ok(_) => r.non_verifie(if cfg!(target_os = "macos") {
            tr!(
                "mémoire DNS non comparée à la liste dans le bilan (vanguard logiciels-espions)",
                "DNS cache not compared with the list in the audit (vanguard spyware)"
            )
        } else {
            tr!(
                "connexions et mémoire DNS non comparées à la liste dans le bilan (vanguard logiciels-espions)",
                "connections and DNS cache not compared with the list in the audit (vanguard spyware)"
            )
        }),
    }
    systeme(&mut r, ind.ok());
    constats_de(&r)
}

/// Les constats d'un relevé : un par trouvaille ; sinon « aucun signe » avec les points non vérifiés ; sinon, rien
/// n'ayant pu être vérifié, impossible.
fn constats_de(r: &Releve) -> Vec<Constat> {
    if r.trouvailles.is_empty() {
        if r.verifies == 0 {
            let raison = if r.non_verifies.is_empty() {
                tr!("rien de lisible", "nothing readable").to_string()
            } else {
                r.non_verifies.join(" ; ")
            };
            return vec![impossible(CAT, &raison)];
        }
        return vec![ok(CAT, juger(r).1)];
    }
    r.trouvailles
        .iter()
        .map(|t| {
            let objet = t
                .objet
                .split_once(':')
                .map_or(crate::modele::Objet::NonMigre, |(genre, valeur)| {
                    crate::modele::Objet::de(genre, valeur)
                });
            alerte(CAT, t.niveau, format!("{} ({})", t.quoi, resume(&t.ou, 2, " ; "))).avec_objet(objet)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn indicateurs() -> Indicateurs {
        let mut entrees = vec![echap::Entree {
            nom: "TheTruthSpy".into(),
            noms: vec!["ExactSpy".into()],
            sites: vec!["vendeur.example".into()],
            domaines: vec!["c2.example.com".into()],
            ips: vec!["203.0.113.7".into()],
            ..echap::Entree::default()
        }];
        for i in 0..30 {
            entrees.push(echap::Entree {
                nom: format!("Remplissage{i}"),
                domaines: (0..2).map(|j| format!("r{i}-{j}.example.net")).collect(),
                ..echap::Entree::default()
            });
        }
        echap::indicateurs_de(&entrees).unwrap()
    }

    fn connexion(programme: Option<&str>, ip: &str) -> ConnexionVue {
        ConnexionVue {
            pid: Some(4242),
            programme: programme.map(String::from),
            chemin: None,
            distante: ip.parse::<IpAddr>().unwrap(),
            port: 443,
        }
    }

    #[test]
    fn verdict_prudent() {
        let mut r = Releve::default();
        let (pire, texte) = juger(&r);
        assert_eq!(pire, None);
        assert!(texte.contains("0 point(s) non vérifié(s)"), "{texte}");
        r.non_verifie("liste d'Échap non vérifiée : hors ligne");
        r.non_verifie("liste d'Échap non vérifiée : hors ligne");
        assert!(juger(&r).1.contains("(1 point(s) non vérifié(s))"));
        assert!(!juger(&r).1.to_lowercase().contains("aucun logiciel espion"));
        r.signe(
            Section::Programmes,
            Niveau::Moyen,
            "programme:Qustodio",
            "Qustodio",
            "installé".into(),
        );
        assert_eq!(juger(&r).0, Some(Niveau::Moyen));
        assert!(juger(&r).1.starts_with("À regarder"));
        r.signe(
            Section::Programmes,
            Niveau::Eleve,
            "programme:Qustodio",
            "Qustodio",
            "en cours".into(),
        );
        assert_eq!(r.trouvailles.len(), 1);
        assert_eq!(r.trouvailles[0].ou, ["installé", "en cours"]);
        assert_eq!(
            juger(&r),
            (Some(Niveau::Eleve), "Signes sérieux d'un logiciel espion.".into())
        );
    }

    #[test]
    fn navigateur_moins_grave_qu_un_programme() {
        let ind = indicateurs();
        let mut r = Releve::default();
        connexions_espions(
            &mut r,
            &ind,
            &[
                connexion(Some("firefox"), "203.0.113.7"),
                connexion(Some("outil"), "::ffff:203.0.113.7"),
                connexion(None, "203.0.113.7"),
                connexion(Some("outil"), "198.51.100.1"),
                connexion(Some("outil"), "192.168.1.7"),
            ],
        );
        assert_eq!(r.trouvailles.len(), 1);
        let t = &r.trouvailles[0];
        assert_eq!(t.niveau, Niveau::Eleve);
        assert!(t.quoi.contains("TheTruthSpy"), "{}", t.quoi);
        assert_eq!(t.ou.len(), 3, "{:?}", t.ou);
        assert!(t.ou[2].starts_with("programme d'un autre compte"), "{:?}", t.ou);
        let mut seul = Releve::default();
        connexions_espions(&mut seul, &ind, &[connexion(Some("firefox"), "203.0.113.7")]);
        assert_eq!(seul.trouvailles[0].niveau, Niveau::Moyen);
        let mut dns = Releve::default();
        memoire_espions(
            &mut dns,
            &ind,
            &[
                "api.c2.example.com".into(),
                "www.vendeur.example".into(),
                "example.org".into(),
            ],
        );
        assert_eq!(dns.trouvailles.len(), 2);
        assert!(dns.trouvailles.iter().all(|t| t.niveau == Niveau::Moyen));
    }

    #[test]
    fn programmes_reconnus_ou_renvoyes() {
        let ind = indicateurs();
        let mut r = Releve::default();
        r.programme("AnyDesk", "installé : AnyDesk".into(), true, Some(&ind));
        r.programme("WiseMo Guest", "installé".into(), false, Some(&ind));
        assert_eq!(r.trouvailles, Vec::<Trouvaille>::new());
        assert!(r.a_distance.contains("AnyDesk"));
        r.programme("Spyrix Free Keylogger", "installé".into(), false, Some(&ind));
        r.programme("spyrix.exe", "en cours".into(), true, Some(&ind));
        r.programme("exactspy.exe", "en cours".into(), true, Some(&ind));
        r.programme("Teramind Agent", "service".into(), true, None);
        r.programme("Steam", "en cours".into(), true, Some(&ind));
        r.programme("OBS Studio", "en cours".into(), true, Some(&ind));
        let niveaux: Vec<(Niveau, &str)> = r.trouvailles.iter().map(|t| (t.niveau, t.quoi.as_str())).collect();
        assert_eq!(niveaux.len(), 3, "{niveaux:?}");
        assert_eq!(niveaux[0].0, Niveau::Eleve);
        assert!(niveaux[1].1.starts_with("TheTruthSpy"), "{niveaux:?}");
        assert_eq!(niveaux[2].0, Niveau::Moyen);
        assert_eq!(r.programmes_vus, 8);
        // Le bilan : une alerte par trouvaille.
        let c = constats_de(&r);
        assert_eq!(c.len(), 3);
        assert!(c.iter().all(|c| c.categorie == CAT && c.probleme.is_some()));
    }

    #[test]
    fn bilan_jamais_sain_sans_verification() {
        let mut r = Releve::default();
        r.non_verifie("liste d'Échap non vérifiée : aucune copie récente");
        let c = constats_de(&r);
        assert_eq!(c.len(), 1);
        assert!(!c[0].verifie);
        r.verifies = 1;
        let c = constats_de(&r);
        assert!(c[0].verifie && c[0].probleme.is_none());
        assert!(c[0].message.contains("1 point(s) non vérifié(s)"), "{}", c[0].message);
    }

    #[test]
    fn bilan_dit_les_serveurs_non_compares() {
        // Avant : avec la liste lue, le bilan disait « 0 point(s) non vérifié(s) » sans avoir regardé une seule
        // connexion ni la mémoire DNS.
        fn systeme(r: &mut Releve, _: Option<&Indicateurs>) {
            r.verifies += 1;
        }
        let ind = indicateurs();
        let c = constats_avec(Ok(&ind), systeme);
        assert_eq!(c.len(), 1);
        assert!(c[0].message.contains("1 point(s) non vérifié(s)"), "{}", c[0].message);
        let raison = "aucune copie récente".to_string();
        let c = constats_avec(Err(&raison), systeme);
        assert!(c[0].message.contains("1 point(s) non vérifié(s)"), "{}", c[0].message);
    }

    #[test]
    fn rien_seulement_pour_ce_qui_a_ete_lu() {
        let mut r = Releve::default();
        // Liste lue, mais ni connexions ni mémoire DNS (macOS ; Linux sans root) : aucune ligne verte.
        assert_eq!(rien_indicateurs(&r, true), None);
        r.dns_lu = true;
        assert_eq!(
            rien_indicateurs(&r, true),
            Some("Aucun nom demandé ne correspond à la liste.")
        );
        r.connexions_lues = true;
        assert!(rien_indicateurs(&r, true).unwrap().starts_with("Aucune connexion ni"));
        r.dns_lu = false;
        assert_eq!(
            rien_indicateurs(&r, true),
            Some("Aucune connexion en cours ne correspond à la liste.")
        );
        assert_eq!(rien_indicateurs(&r, false), None);
        // Sans la liste d'Échap, les noms ne sont comparés qu'à ceux de Vanguard : pas de coche verte.
        assert_eq!(rien_programmes(&r, true), None);
        r.programmes_vus = 120;
        assert!(rien_programmes(&r, true).unwrap().1);
        let (texte, complet) = rien_programmes(&r, false).unwrap();
        assert!(!complet && texte.contains("liste de Vanguard seulement"), "{texte}");
        // Des processus de root non lus : pas de coche verte pour le clavier.
        assert!(rien_clavier(&r).1);
        r.clavier_illisibles = 335;
        assert!(!rien_clavier(&r).1);
    }

    #[test]
    fn textes_dans_la_largeur() {
        // Les textes courts (titres, verdicts) tiennent sur une ligne ; les longs passent par afficher_aligne.
        for t in [
            "Logiciels espions : en ai-je un ?",
            "Serveurs et sites connus (Échap)",
            "Logiciels de surveillance connus",
            "Signes sérieux d'un logiciel espion.",
            "À regarder : rien de sûr, mais ces points méritent un coup d'œil.",
            "Indicateurs : Échap (CC-BY 4.0) · copie de 59 jour(s)",
        ] {
            assert!(largeur_affichee(t) + 2 <= LARGEUR, "{t}");
        }
    }

    /// T4 : une trouvaille se reconnaît à ce qui a été trouvé (produit, entrée de la liste), jamais à sa phrase ni au
    /// numéro du processus.
    #[test]
    fn cles_sans_langue() {
        let ind = indicateurs();
        let releve = || {
            let mut r = Releve::default();
            r.programme("spyrix.exe", "en cours".into(), true, Some(&ind));
            r.programme("exactspy.exe", "en cours".into(), true, Some(&ind));
            connexions_espions(&mut r, &ind, &[connexion(Some("outil"), "203.0.113.7")]);
            memoire_espions(&mut r, &ind, &["www.vendeur.example".into()]);
            constats_de(&r)
        };
        let cles = crate::machine::controler_regle("COM-ESP-001", releve);
        assert_eq!(cles.len(), 4, "{cles:?}");
        assert!(cles.iter().all(|c| c.starts_with("COM-ESP-001|")));
        assert!(
            cles.iter().any(|c| c == "COM-ESP-001|connexion-serveur:TheTruthSpy"),
            "{cles:?}"
        );
        assert!(cles.iter().any(|c| c == "COM-ESP-001|nom-site:TheTruthSpy"), "{cles:?}");
        assert!(cles.iter().any(|c| c == "COM-ESP-001|echap:TheTruthSpy"), "{cles:?}");
    }
}

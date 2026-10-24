//! Audit de sécurité de cette machine : types communs, affichage et exécution des correctifs.
//! Les vérifications elles-mêmes dépendent du système (linux/, windows/, macos/).

#[cfg(unix)]
use std::process::Command;

use serde::Serialize;

use crate::modele::{Absence, Cle, Etat, Objet, Precision, Raison};
use crate::risk::Niveau;
use crate::ui::*;

mod administrateurs;
pub(crate) mod agents_ia;
mod bluetooth;
pub(crate) mod certificats;
pub(crate) mod chasse;
mod comptes_oublies;
#[cfg(any(target_os = "macos", test))]
pub(crate) mod darwin;
pub(crate) mod dns;
pub(crate) mod extensions;
pub(crate) mod fin_de_support;
mod heure;
mod journaux;
#[cfg(target_os = "linux")]
pub mod linux;
mod logiciels_vus;
pub(crate) mod mots_de_passe;
mod navigateur;
mod navigation_detournee;
mod partages;
mod post_quantique;
pub(crate) mod regles;
mod regles_communes;
mod sante;
mod sensibles;
mod sshd;
pub(crate) use sshd::nom_pq;
pub(crate) mod wifi;
#[cfg(target_os = "linux")]
use linux as os;
#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
use windows as os;
#[cfg(unix)]
pub(crate) mod assistant;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(unix)]
pub(crate) mod unix;
#[cfg(target_os = "macos")]
use macos as os;

#[derive(Serialize, Clone)]
pub struct Correctif {
    /// Ce que fait la correction, en une phrase.
    pub action: String,
    /// Commandes exécutées dans l'ordre : bash sous Linux, PowerShell (administrateur) sous Windows.
    pub commandes: Vec<String>,
    /// `false` = à faire soi-même (redémarrage, réglage du routeur…) : on affiche seulement la marche à suivre.
    pub automatique: bool,
    /// Port bloqué en entrée par cette correction (« 8080/tcp »), retenu une fois appliquée.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bloque: Option<String>,
    /// Ce qui permet de l'annuler (`optimiser::annulables`) : dit avant de l'appliquer.
    #[serde(skip)]
    pub defaire: Defaire,
}

/// Comment une correction se défait.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Defaire {
    /// Vanguard ne sait pas relever l'état d'avant : la correction est dite non annulable avant d'être appliquée.
    #[default]
    Inconnu,
    /// Les gestes dont la valeur d'avant est relevée juste avant d'appliquer, puis remise pour annuler.
    Gestes(Vec<crate::optimiser::Geste>),
    /// Remet en marche une protection de base (pare-feu, antivirus, chiffrement, UAC…) : Vanguard ne la remet
    /// jamais hors service, même pour annuler.
    Protection,
}

impl Correctif {
    /// Comment cette correction se défait. Sous Windows, une correction faite tout entière de corrections natives
    /// (DWORD sous HKLM) se défait d'elle-même, sauf celles qui rallument l'UAC.
    pub(crate) fn comment_defaire(&self) -> Defaire {
        #[cfg(windows)]
        if self.defaire == Defaire::Inconnu && !self.commandes.is_empty() {
            return windows::corrections::comment_defaire(&self.commandes);
        }
        self.defaire.clone()
    }

    /// Pourquoi elle ne se défait pas ; `None` : elle se défait (si son état d'avant se relève).
    pub(crate) fn pourquoi_pas(&self) -> Option<crate::optimiser::annulables::PourquoiPas> {
        use crate::optimiser::annulables::PourquoiPas;
        match self.comment_defaire() {
            Defaire::Gestes(_) => None,
            Defaire::Protection => Some(PourquoiPas::Protection),
            Defaire::Inconnu => Some(PourquoiPas::NonReleve),
        }
    }
}

#[derive(Clone)]
pub struct Constat {
    pub categorie: &'static str,
    /// `None` = tout va bien.
    pub probleme: Option<Niveau>,
    pub message: String,
    pub correctif: Option<Correctif>,
    /// `false` = la vérification n'a pas pu se faire. C'est ce champ, et non le texte du message,
    /// qui décide de la note : reformuler un message ne doit pas désactiver ce garde-fou.
    pub verifie: bool,
    /// L'identifiant de la règle qui l'a produit (« LNX-PLT-001 »), pour les règles du registre (`regles`) ; vide sinon.
    pub regle: &'static str,
    /// Ce que juge ce constat, à côté de sa règle : avec elle, sa clé (`cle`), qui le reconnaît d'un bilan à l'autre
    /// sans dépendre de la langue ni de la tournure du message. `NonMigre` : reconnu à son texte, comme avant.
    pub objet: Objet,
    /// Ce que `probleme` et `verifie` ne disent pas : l'absence d'un « sans objet », la raison d'un « non vérifié ».
    pub precision: Precision,
}

/// Le JSON d'un constat : les champs d'avant, tels quels (des scripts les lisent), puis sa clé et son état, calculés.
impl Serialize for Constat {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let etat = self.etat();
        let mut m = s.serialize_struct("Constat", 12)?;
        m.serialize_field("categorie", self.categorie)?;
        m.serialize_field("probleme", &self.probleme)?;
        m.serialize_field("message", &self.message)?;
        m.serialize_field("correctif", &self.correctif)?;
        m.serialize_field("verifie", &self.verifie)?;
        if self.regle.is_empty() {
            m.skip_field("regle")?;
        } else {
            m.serialize_field("regle", self.regle)?;
        }
        match &self.objet {
            Objet::De(o) => m.serialize_field("objet", o)?,
            _ => m.skip_field("objet")?,
        }
        match self.cle() {
            Some(c) => m.serialize_field("cle", &c.to_string())?,
            None => m.skip_field("cle")?,
        }
        // La référence d'abord citée de sa règle (CIS, Microsoft ou ANSSI) : un script relie l'alerte au référentiel
        // sans tenir sa propre table.
        match regles::reference_de(self.regle) {
            Some(r) => m.serialize_field("reference", r)?,
            None => m.skip_field("reference")?,
        }
        m.serialize_field("etat", etat.code())?;
        match &etat {
            Etat::NonVerifie(r) => m.serialize_field("raison", r.code())?,
            _ => m.skip_field("raison")?,
        }
        match &etat {
            Etat::SansObjet(a) => m.serialize_field("absence", a.code())?,
            _ => m.skip_field("absence")?,
        }
        m.end()
    }
}

#[derive(Serialize)]
pub struct Audit {
    pub systeme: &'static str,
    pub score: u32,
    pub constats: Vec<Constat>,
}

impl Audit {
    /// Nombre de vérifications qui n'ont pas pu se faire.
    pub fn impossibles(&self) -> usize {
        self.constats.iter().filter(|c| !c.verifie).count()
    }

    /// Une note n'a de sens que si le pare-feu a été vérifié et qu'au plus un tiers des vérifications a échoué :
    /// sinon une machine peu vérifiée obtiendrait un « A » rassurant (vu en test sur Fedora en conteneur). Il faut un
    /// constat du pare-feu vérifié, pas seulement l'absence d'un non vérifié : une règle du pare-feu qui plante rend
    /// une « erreur interne » d'une autre catégorie, reconnue à son identifiant (« LNX-PFE-001 »). Un constat
    /// « sans objet » ne compte pas parmi les vérifications : rien n'y a été jugé, il ne dilue pas les non vérifiés.
    /// Le garde-fou vise la lecture du pare-feu lui-même (règle `*-PFE-001`, plantage et règle muette compris) : un
    /// réglage secondaire illisible, comme le mode furtif de macOS, compte comme toute vérification dans la limite du
    /// tiers, sans retirer la note à lui seul. Un constat sans règle (les tests) compte par sa catégorie.
    pub fn fiable(&self) -> bool {
        let pare_feu =
            |c: &&Constat| c.regle.ends_with("-PFE-001") || (c.regle.is_empty() && c.categorie == "Pare-feu");
        let mut constats_pare_feu = self.constats.iter().filter(pare_feu);
        let pare_feu_verifie = constats_pare_feu.clone().any(|c| c.verifie) && constats_pare_feu.all(|c| c.verifie);
        let juges = self
            .constats
            .iter()
            .filter(|c| !matches!(c.etat(), Etat::SansObjet(_)))
            .count();
        pare_feu_verifie && self.impossibles() * 3 < juges
    }
}

pub(crate) fn ok(categorie: &'static str, message: impl Into<String>) -> Constat {
    Constat {
        categorie,
        probleme: None,
        message: message.into(),
        correctif: None,
        verifie: true,
        regle: "",
        objet: Objet::NonMigre,
        precision: Precision::Aucune,
    }
}

pub(crate) fn alerte(categorie: &'static str, niveau: Niveau, message: impl Into<String>) -> Constat {
    Constat {
        categorie,
        probleme: Some(niveau),
        message: message.into(),
        correctif: None,
        verifie: true,
        regle: "",
        objet: Objet::NonMigre,
        precision: Precision::Aucune,
    }
}

/// Vérification qui n'a pas pu se faire : on le dit, sans jamais conclure « OK ».
pub(crate) fn impossible(categorie: &'static str, raison: &str) -> Constat {
    Constat {
        verifie: false,
        ..alerte(
            categorie,
            Niveau::Info,
            trf!("Impossible de vérifier ({raison}).", "Could not check ({raison})."),
        )
    }
}

/// `impossible`, avec sa raison typée (`modele::Raison`) : le JSON et l'historique la comparent par son code.
pub(crate) fn impossible_par(categorie: &'static str, raison: Raison, message: impl Into<String>) -> Constat {
    Constat {
        verifie: false,
        precision: Precision::NonVerifie(raison),
        ..alerte(categorie, Niveau::Info, message)
    }
}

/// Rien à juger ici, et c'est prouvé (pas de carte Wi-Fi, aucun réseau connecté) : jamais compté comme sain dans la
/// fiabilité de la note, jamais confondu avec une lecture qui a échoué.
pub(crate) fn sans_objet(categorie: &'static str, absence: Absence, message: impl Into<String>) -> Constat {
    Constat {
        precision: Precision::SansObjet(absence),
        ..ok(categorie, message)
    }
}

impl Constat {
    /// Sa clé (règle + objet), si sa règle pose un objet ; sinon on le reconnaît à son texte.
    pub(crate) fn cle(&self) -> Option<Cle> {
        Cle::de(self.regle, &self.objet)
    }

    /// Son état : sain, sans objet, non vérifié ou problème (`modele::Etat`).
    pub(crate) fn etat(&self) -> Etat {
        Etat::de(self.probleme, self.verifie, &self.precision)
    }

    /// Pas une combinaison impossible (`modele::etat::coherent`) : un invariant vérifié par l'autotest.
    pub(crate) fn coherent(&self) -> bool {
        crate::modele::etat::coherent(self.probleme, self.verifie, self.correctif.is_some(), &self.precision)
    }

    /// Pose l'objet de ce constat.
    pub(crate) fn avec_objet(mut self, objet: Objet) -> Self {
        self.objet = objet;
        self
    }

    pub(crate) fn corriger(mut self, action: impl Into<String>, commandes: &[impl ToString]) -> Self {
        self.correctif = Some(Correctif {
            action: action.into(),
            commandes: commandes.iter().map(ToString::to_string).collect(),
            automatique: true,
            bloque: None,
            defaire: Defaire::Inconnu,
        });
        self
    }

    /// La correction se défait : la valeur d'avant de chacun de ces gestes est relevée juste avant de l'appliquer.
    #[cfg_attr(windows, allow(dead_code))]
    pub(crate) fn annulable(mut self, gestes: Vec<crate::optimiser::Geste>) -> Self {
        if let Some(k) = &mut self.correctif {
            k.defaire = Defaire::Gestes(gestes);
        }
        self
    }

    /// La correction remet en marche une protection de base : jamais défaite par Vanguard.
    pub(crate) fn protection(mut self) -> Self {
        if let Some(k) = &mut self.correctif {
            k.defaire = Defaire::Protection;
        }
        self
    }

    /// La correction bloque ce port (« 8080/tcp ») dans le pare-feu.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    fn bloquant(mut self, port: String) -> Self {
        if let Some(k) = &mut self.correctif {
            k.bloque = Some(port);
        }
        self
    }

    pub(crate) fn manuel(self, action: impl Into<String>, commandes: &[&str]) -> Self {
        let mut c = self.corriger(action, commandes);
        if let Some(k) = &mut c.correctif {
            k.automatique = false;
        }
        c
    }
}

/// Niveau d'un service ouvert sur le réseau. Avec un pare-feu actif, il n'est en général pas joignable : on baisse
/// d'un cran ; sans pare-feu, même un service anodin est exposé (Info → Moyen). Une ligne par cas, pour la lecture.
#[allow(clippy::match_same_arms)]
fn niveau_expose(pare_feu_actif: bool, niveau: Niveau) -> Niveau {
    match (pare_feu_actif, niveau) {
        (true, Niveau::Critique) => Niveau::Eleve,
        (true, Niveau::Eleve) => Niveau::Moyen,
        (true, _) => Niveau::Info,
        (false, Niveau::Info) => Niveau::Moyen,
        (false, n) => n,
    }
}

/// Une vérification à lancer : elle rend ses constats.
pub(crate) type Verification<'a> = Box<dyn FnOnce() -> Vec<Constat> + Send + 'a>;

/// Lance les vérifications en même temps (chacune attend surtout des commandes du système) et rend leurs constats
/// dans l'ordre de la liste. Une vérification qui plante le dit, sans emporter les autres. La durée de chaque règle
/// va au journal des mesures (`autotest::mesures`), qui voit ainsi une règle ralentir d'une semaine à l'autre.
fn en_parallele(verifications: Vec<Verification<'_>>) -> Vec<Constat> {
    let (constats, durees) = en_parallele_mesure(verifications);
    crate::autotest::mesures::noter(&durees);
    constats
}

/// `en_parallele`, avec la durée de chaque règle du registre (celles qui n'ont pas d'identifiant ne sont pas
/// mesurées).
fn en_parallele_mesure(
    verifications: Vec<Verification<'_>>,
) -> (Vec<Constat>, Vec<(&'static str, std::time::Duration)>) {
    // VANGUARD_CHRONO : chaque vérification dit son temps sur la sortie d'erreur, pour trouver ce qui ralentit le bilan.
    let chrono = std::env::var_os("VANGUARD_CHRONO").is_some();
    let mut durees = Vec::new();
    let constats = std::thread::scope(|s| {
        let fils: Vec<_> = verifications
            .into_iter()
            .map(|v| {
                s.spawn(move || {
                    let debut = std::time::Instant::now();
                    let constats = v();
                    (constats, debut.elapsed())
                })
            })
            .collect();
        fils.into_iter()
            .enumerate()
            .flat_map(|(i, f)| {
                let (constats, duree) = f.join().unwrap_or_else(|_| {
                    (
                        vec![impossible("Audit", tr!("erreur interne", "internal error"))],
                        std::time::Duration::ZERO,
                    )
                });
                if chrono {
                    let quoi = constats
                        .first()
                        .map_or("(rien)", |c| if c.regle.is_empty() { c.categorie } else { c.regle });
                    eprintln!("chrono {i:>2} {:>6} ms  {quoi}", duree.as_millis());
                }
                if let Some(c) = constats.first().filter(|c| !c.regle.is_empty()) {
                    durees.push((c.regle, duree));
                }
                constats
            })
            .collect()
    });
    (constats, durees)
}

/// Les règles de ce système que `garder` retient, lancées pour l'autotest sous garde et délai comme au bilan, en même
/// temps ou une par une (des durées propres quand une régression est signalée) : leurs constats bruts (sans les
/// alertes déclarées normales) et la durée de chacune. Rien n'est noté au journal des mesures : l'autotest les garde
/// dans son résultat.
pub(crate) fn essai_des_regles(
    une_par_une: bool,
    garder: impl Fn(&str) -> bool,
) -> (Vec<Constat>, Vec<(&'static str, std::time::Duration)>) {
    BILAN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let choisies: Vec<&'static regles::Regle> = regles::regles(regles::Os::actuel())
        .into_iter()
        .filter(|r| garder(r.id))
        .collect();
    if !une_par_une {
        return en_parallele_mesure(choisies.into_iter().map(regles::verification).collect());
    }
    let mut constats = Vec::new();
    let mut durees = Vec::new();
    for r in choisies {
        let debut = std::time::Instant::now();
        constats.extend(regles::verification(r)());
        durees.push((r.id, debut.elapsed()));
    }
    (constats, durees)
}

/// L'audit d'un système : les règles du registre, celles du système (le pare-feu en tête) puis les communes
/// (regles_communes.rs), lancées en même temps et rendues dans l'ordre de leurs rangs.
fn audit(systeme: &'static str) -> Audit {
    // Un nouveau bilan relit ce que ses règles partagent (`ParBilan`) : une correction a pu le changer.
    BILAN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let constats = en_parallele(regles::verifications());
    Audit {
        systeme,
        score: score(&constats),
        constats,
    }
}

/// Le numéro du bilan en cours : ce que `ParBilan` a gardé d'un bilan précédent est périmé.
static BILAN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Ce que plusieurs règles d'un bilan demandent en même temps (le pare-feu, l'adresse sur le réseau local) : la
/// première le lit, les autres l'attendent et le reprennent. Deux lectures pourraient se contredire si l'état change
/// pendant le bilan. Le bilan suivant le relit.
pub(crate) struct ParBilan<T>(std::sync::Mutex<Option<(u64, T)>>);

impl<T: Clone> ParBilan<T> {
    pub(crate) const fn new() -> Self {
        Self(std::sync::Mutex::new(None))
    }

    /// La valeur de ce bilan, lue par `lecture` si aucune règle ne l'a encore fait.
    pub(crate) fn lire(&self, lecture: impl FnOnce() -> T) -> T {
        self.lire_au(BILAN.load(std::sync::atomic::Ordering::Relaxed), lecture)
    }

    fn lire_au(&self, bilan: u64, lecture: impl FnOnce() -> T) -> T {
        let mut garde = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((n, valeur)) = garde.as_ref()
            && *n == bilan
        {
            return valeur.clone();
        }
        let valeur = lecture();
        *garde = Some((bilan, valeur.clone()));
        valeur
    }
}

fn score(constats: &[Constat]) -> u32 {
    100u32.saturating_sub(constats.iter().filter_map(|c| c.probleme).map(Niveau::penalite).sum())
}

/// Un port ouvert sur le réseau par un programme, sous Linux et macOS : (niveau qu'il vaut derrière ce pare-feu,
/// alerte).
#[cfg(unix)]
fn port_expose(
    port: u16,
    proto: &str,
    i: &crate::risk::InfoPort,
    programme: &str,
    pare_feu_actif: bool,
) -> (Niveau, Constat) {
    let niveau = niveau_expose(pare_feu_actif, i.niveau);
    let constat = alerte(
        "Ports en écoute",
        niveau,
        trf!(
            "{port}/{proto} ({}) ouvert sur le réseau par « {programme} ». {}",
            "{port}/{proto} ({}) open to the network by “{programme}”. {}",
            i.service,
            i.conseil
        ),
    );
    (niveau, constat)
}

/// Le verrouillage de l'écran d'après son délai en secondes (0 = jamais), avec où l'activer quand il manque.
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn verrouillage_selon_delai(secondes: u64, ou_l_activer: &str) -> Constat {
    match secondes {
        0 => alerte(
            "Verrouillage",
            Niveau::Moyen,
            tr!(
                "L'écran ne se verrouille jamais tout seul : un ordinateur laissé ouvert est accessible à tous.",
                "The screen never locks by itself: a computer left open is accessible to anyone."
            ),
        )
        .manuel(ou_l_activer, &[]),
        s if s > 15 * 60 => alerte(
            "Verrouillage",
            Niveau::Info,
            trf!(
                "L'écran se verrouille après {} minutes : 5 à 10 minutes serait plus sûr.",
                "The screen locks after {} minutes: 5 to 10 minutes would be safer.",
                s / 60
            ),
        ),
        s if s >= 60 => ok(
            "Verrouillage",
            trf!(
                "L'écran se verrouille après {} minute(s) d'inactivité.",
                "The screen locks after {} minute(s) of inactivity.",
                s / 60
            ),
        ),
        _ => ok(
            "Verrouillage",
            tr!(
                "L'écran se verrouille après inactivité.",
                "The screen locks after inactivity."
            ),
        ),
    }
}

/// Aucun service exposé au réseau, sous Linux et macOS.
#[cfg(unix)]
fn aucun_port_expose() -> Constat {
    ok(
        "Ports en écoute",
        tr!(
            "Aucun service TCP ou UDP exposé au réseau (tout écoute en local).",
            "No TCP or UDP service exposed to the network (everything listens locally)."
        ),
    )
}

/// Sortie standard d'une commande, ou `None` si elle est absente ou échoue.
#[cfg(unix)]
pub(crate) fn sortie(cmd: &str, args: &[&str]) -> Option<String> {
    let r = crate::commande::lancer(Command::new(cmd).args(args), 30)?;
    (r.code == Some(0)).then_some(r.sortie)
}

/// Permissions de ~/.ssh.
#[cfg(unix)]
fn cles_ssh() -> Vec<Constat> {
    let dossier = crate::socle::maison().join(".ssh");
    let Ok(meta) = std::fs::metadata(&dossier) else {
        return vec![ok("Clés SSH", tr!("Pas de dossier ~/.ssh.", "No ~/.ssh folder."))];
    };
    let mut constats = Vec::new();
    if std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o077 != 0 {
        constats.push(
            alerte(
                "Clés SSH",
                Niveau::Eleve,
                tr!(
                    "~/.ssh est lisible par d'autres utilisateurs.",
                    "~/.ssh is readable by other users."
                ),
            )
            .corriger(
                tr!("Restreindre ~/.ssh à vous seul", "Restrict ~/.ssh to you only"),
                &["chmod 700 ~/.ssh"],
            )
            .annulable(vec![crate::optimiser::Geste::droits(&dossier)]),
        );
    }
    for f in std::fs::read_dir(&dossier).into_iter().flatten().flatten() {
        let brut = f.file_name().to_string_lossy().into_owned();
        // Toute clé privée, quel que soit son nom (pas seulement id_*).
        let protegee = std::fs::read_to_string(f.path()).ok().and_then(|t| cle_protegee(&t));
        // Nom entre apostrophes dans les commandes : une clé « ma cle » ne casse pas la commande. Les commandes visent
        // le vrai nom ; les messages montrent un nom rendu inoffensif.
        let chemin = format!("~/.ssh/{}", crate::commande::sh_chaine(&brut));
        let nom = affichable(&brut);
        if protegee == Some(false) {
            constats.push(
                alerte(
                    "Clés SSH",
                    Niveau::Moyen,
                    trf!("Clé privée ~/.ssh/{nom} sans phrase de passe : volée, elle ouvre tous les serveurs où elle est autorisée.", "Private key ~/.ssh/{nom} has no passphrase: if stolen, it opens every server where it is authorized."),
                )
                .corriger(
                    trf!("Ajouter une phrase de passe à {nom} (la clé publique ne change pas, rien à refaire sur les serveurs)", "Add a passphrase to {nom} (the public key does not change, nothing to redo on the servers)"),
                    &[&format!("ssh-keygen -p -f {chemin}")],
                ),
            );
        }
        // Même règle que ci-dessus : une clé « github » ou « serveur » compte autant qu'« id_ed25519 ».
        let privee = protegee.is_some()
            || (brut.starts_with("id_")
                && !std::path::Path::new(&brut)
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("pub")));
        if privee
            && f.metadata()
                .is_ok_and(|m| std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o077 != 0)
        {
            constats.push(
                alerte(
                    "Clés SSH",
                    Niveau::Critique,
                    trf!(
                        "Clé privée ~/.ssh/{nom} lisible par d'autres.",
                        "Private key ~/.ssh/{nom} is readable by others."
                    ),
                )
                .corriger(
                    trf!("Protéger la clé {nom}", "Protect the key {nom}"),
                    &[&format!("chmod 600 {chemin}")],
                )
                .annulable(vec![crate::optimiser::Geste::droits(&f.path())]),
            );
        }
    }
    if let Ok(config) = std::fs::read_to_string(dossier.join("config")) {
        let mut lignes = Vec::new();
        deplier_config_ssh(
            "~/.ssh/config",
            &config,
            &|motif| fichiers_inclus_ssh(&dossier, motif),
            8,
            &mut lignes,
        );
        constats.extend(constats_config_ssh(&lignes));
    }
    if constats.is_empty() {
        constats.push(ok(
            "Clés SSH",
            tr!("Permissions de ~/.ssh correctes.", "~/.ssh permissions are correct."),
        ));
    }
    constats
}

/// La configuration de SSH avec ses fichiers inclus (« Include ») dépliés à leur place, comme SSH les lit : (fichier
/// à montrer, numéro de ligne, ligne). `lire` rend les fichiers d'un motif d'inclusion ; `profondeur` arrête une
/// inclusion en boucle.
#[cfg(unix)]
fn deplier_config_ssh(
    nom: &str,
    texte: &str,
    lire: &dyn Fn(&str) -> Vec<(String, String)>,
    profondeur: u32,
    sortie: &mut Vec<(String, usize, String)>,
) {
    for (i, ligne) in texte.lines().enumerate() {
        let propre = ligne.split('#').next().unwrap_or_default().trim();
        let (cle, motifs) = propre
            .split_once(|c: char| c.is_whitespace() || c == '=')
            .unwrap_or((propre, ""));
        if cle.eq_ignore_ascii_case("include") && profondeur > 0 {
            for motif in motifs
                .trim_start_matches(|c: char| c.is_whitespace() || c == '=')
                .split_whitespace()
            {
                for (inclus, contenu) in lire(motif.trim_matches('"')) {
                    deplier_config_ssh(&inclus, &contenu, lire, profondeur - 1, sortie);
                }
            }
        } else {
            sortie.push((nom.to_string(), i + 1, ligne.to_string()));
        }
    }
}

/// Les fichiers d'un motif d'inclusion de ~/.ssh/config, triés : relatif à ~/.ssh, ou commençant par « ~/ » ; les
/// jokers « * » et « ? » valent dans le dernier élément du chemin.
#[cfg(unix)]
fn fichiers_inclus_ssh(dossier_ssh: &std::path::Path, motif: &str) -> Vec<(String, String)> {
    let maison = dossier_ssh.parent().unwrap_or(dossier_ssh);
    let chemin = match motif.strip_prefix("~/") {
        Some(reste) => maison.join(reste),
        None => dossier_ssh.join(motif),
    };
    let montrer = |p: &std::path::Path| match p.strip_prefix(maison) {
        Ok(r) => format!("~/{}", r.display()),
        Err(_) => p.display().to_string(),
    };
    let nom = chemin
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut trouves: Vec<std::path::PathBuf> = if nom.contains(['*', '?']) {
        let parent = chemin.parent().unwrap_or(dossier_ssh);
        std::fs::read_dir(parent)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| joker(&nom, &e.file_name().to_string_lossy()))
            .map(|e| e.path())
            .collect()
    } else {
        vec![chemin]
    };
    trouves.sort();
    trouves
        .into_iter()
        .filter(|p| p.is_file())
        .filter_map(|p| Some((montrer(&p), std::fs::read_to_string(&p).ok()?)))
        .collect()
}

/// Un nom correspond-il à un motif à jokers (« * » : n'importe quelle suite, « ? » : un caractère) ?
#[cfg(unix)]
fn joker(motif: &str, nom: &str) -> bool {
    let (m, n): (Vec<char>, Vec<char>) = (motif.chars().collect(), nom.chars().collect());
    // Programmation dynamique : possible[j] = le début du motif correspond aux j premiers caractères du nom.
    let mut possible = vec![false; n.len() + 1];
    possible[0] = true;
    for c in m {
        let mut suivant = vec![false; n.len() + 1];
        for j in 0..=n.len() {
            suivant[j] = match c {
                '*' => possible[j] || (j > 0 && suivant[j - 1]),
                '?' => j > 0 && possible[j - 1],
                _ => j > 0 && possible[j - 1] && n[j - 1] == c,
            };
        }
        possible = suivant;
    }
    possible[n.len()]
}

/// Réglages risqués de ~/.ssh/config qui valent pour tous les serveurs (avant le premier « Host », sous « Host * »
/// ou « Match all ») : (numéro de ligne, réglage en minuscules). Un réglage sous un « Host » précis reste : un
/// serveur de test qu'on recrée souvent peut s'en passer.
#[cfg(unix)]
fn reglages_ssh_risques(config: &str) -> Vec<(usize, &'static str)> {
    let mut global = true;
    let mut trouves = Vec::new();
    for (i, ligne) in config.lines().enumerate() {
        let ligne = ligne.split('#').next().unwrap_or_default().trim();
        let (cle, valeur) = ligne
            .split_once(|c: char| c.is_whitespace() || c == '=')
            .map_or((ligne, ""), |(c, v)| {
                (c, v.trim_start_matches(|c: char| c.is_whitespace() || c == '='))
            });
        let cle = cle.to_ascii_lowercase();
        let valeur = valeur.trim().trim_matches('"').to_ascii_lowercase();
        match cle.as_str() {
            "host" => global = valeur.split_whitespace().all(|motif| motif == "*"),
            "match" => global = valeur == "all",
            "stricthostkeychecking" if global && matches!(valeur.as_str(), "no" | "off") => {
                trouves.push((i + 1, "stricthostkeychecking"));
            }
            "forwardagent" if global && valeur == "yes" => trouves.push((i + 1, "forwardagent")),
            _ => {}
        }
    }
    trouves
}

#[cfg(unix)]
fn constats_config_ssh(lignes: &[(String, usize, String)]) -> Vec<Constat> {
    let texte = lignes.iter().map(|(_, _, l)| l.as_str()).collect::<Vec<_>>().join("\n");
    reglages_ssh_risques(&texte)
        .into_iter()
        .filter_map(|(n, reglage)| {
            let (fichier, ligne, _) = lignes.get(n - 1)?;
            let fichier = affichable(fichier);
            Some((fichier, *ligne, reglage))
        })
        .map(|(fichier, ligne, reglage)| {
            let (message, conseil) = if reglage == "stricthostkeychecking" {
                (
                    trf!(
                        "{fichier}, ligne {ligne} : SSH se connecte à n'importe quel serveur sans vérifier qu'il est le bon ; un appareil au milieu peut se faire passer pour lui et lire le mot de passe.",
                        "{fichier}, line {ligne}: SSH connects to any server without checking it is the right one; a device in the middle can pose as it and read the password."
                    ),
                    tr!(
                        "Retirer cette ligne, ou la réserver aux serveurs de test sous leur propre « Host » ; « accept-new » accepte un nouveau serveur mais refuse un serveur qui change",
                        "Remove this line, or keep it for test servers under their own “Host”; “accept-new” accepts a new server but refuses one that changes"
                    ),
                )
            } else {
                (
                    trf!(
                        "{fichier}, ligne {ligne} : votre agent SSH est prêté à tous les serveurs ; un serveur piraté peut s'en servir pour se connecter ailleurs avec vos clés.",
                        "{fichier}, line {ligne}: your SSH agent is lent to every server; a hacked server can use it to log in elsewhere with your keys."
                    ),
                    tr!(
                        "Retirer cette ligne, ou la réserver aux serveurs de confiance sous leur propre « Host » ; « ssh -J » remplace le plus souvent ce prêt",
                        "Remove this line, or keep it for trusted servers under their own “Host”; “ssh -J” usually replaces this lending"
                    ),
                )
            };
            alerte("Clés SSH", Niveau::Moyen, message).manuel(conseil, &[])
        })
        .collect()
}

/// Une clé privée SSH est-elle protégée par une phrase de passe ? `None` si ce n'est pas une clé privée.
pub(crate) fn cle_protegee(texte: &str) -> Option<bool> {
    let entete = texte.lines().next()?.trim();
    if !entete.starts_with("-----BEGIN") || !entete.contains("PRIVATE KEY") {
        return None;
    }
    match entete {
        // PKCS#8 : le type dit tout.
        "-----BEGIN ENCRYPTED PRIVATE KEY-----" => Some(true),
        // Format OpenSSH : le nom du chiffrement est écrit dans la clé (« none » = pas de phrase de passe).
        "-----BEGIN OPENSSH PRIVATE KEY-----" => {
            let corps: String = texte.lines().filter(|l| !l.starts_with("-----")).collect();
            let octets = base64_decoder(&corps)?;
            let reste = octets.strip_prefix(b"openssh-key-v1\0")?;
            let longueur = u32::from_be_bytes(reste.get(..4)?.try_into().ok()?) as usize;
            Some(reste.get(4..4 + longueur)? != b"none")
        }
        // Ancien format PEM (RSA, EC, DSA) : un en-tête Proc-Type signale le chiffrement.
        _ => Some(texte.contains("Proc-Type: 4,ENCRYPTED")),
    }
}

/// Décode du base64, espaces et « = » ignorés ; `None` si un caractère n'est pas de l'alphabet. Un dernier bloc d'un
/// seul caractère ne donne aucun octet.
fn base64_decoder(texte: &str) -> Option<Vec<u8>> {
    let valeur = |c: u8| -> Option<u32> {
        Some(u32::from(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        }))
    };
    let propre: Vec<u8> = texte
        .bytes()
        .filter(|c| !c.is_ascii_whitespace() && *c != b'=')
        .collect();
    let mut sortie = Vec::with_capacity(propre.len() * 3 / 4);
    for bloc in propre.chunks(4) {
        let n = bloc.iter().try_fold(0u32, |acc, &c| Some(acc << 6 | valeur(c)?))? << (6 * (4 - bloc.len()));
        sortie.extend_from_slice(&n.to_be_bytes()[1..bloc.len()]);
    }
    Some(sortie)
}

/// Ports que Vanguard a bloqués dans le pare-feu de cet ordinateur, un par ligne (« 8080/tcp »).
/// Un port bloqué écoute toujours : sans ce registre, l'alerte et la même correction revenaient à chaque audit.
/// Sous Linux, les règles ufw ne sont pas lisibles sans root ; Windows, lui, relit ses règles directement.
fn fichier_blocages() -> std::path::PathBuf {
    crate::socle::dossier_local().join("ports-bloques.txt")
}

fn lire_blocages(texte: &str) -> std::collections::HashSet<String> {
    texte
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// Les ports que Vanguard a bloqués en entrée, d'après sa note (« 11434/tcp ») : le bilan (Linux) et le blocage ne
/// les reproposent pas.
pub(crate) fn ports_bloques() -> std::collections::HashSet<String> {
    lire_blocages(&std::fs::read_to_string(fichier_blocages()).unwrap_or_default())
}

/// À appeler après une correction réussie : retient le port qu'elle a bloqué.
/// Empreinte de cet ordinateur : SHA-1 de son identifiant (/etc/machine-id sous Linux, IOPlatformUUID sous macOS,
/// MachineGuid sous Windows). La clé s'en sert pour reconnaître l'ordinateur de son propriétaire, et « Mes
/// ordinateurs » pour retrouver l'entrée d'un ordinateur ; elle ne dit pas qui est la personne.
pub fn empreinte_machine() -> Option<String> {
    #[cfg(target_os = "linux")]
    let id = std::fs::read_to_string("/etc/machine-id").ok()?;
    // « "IOPlatformUUID" = "564D…" »
    #[cfg(target_os = "macos")]
    let id = crate::commande::lancer(Command::new("ioreg").args(["-rd1", "-c", "IOPlatformExpertDevice"]), 10)?
        .sortie
        .lines()
        .find(|l| l.contains("\"IOPlatformUUID\""))?
        .rsplit('"')
        .nth(1)?
        .to_string();
    #[cfg(windows)]
    let id: String = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(r"SOFTWARE\Microsoft\Cryptography")
        .and_then(|k| k.get_value("MachineGuid"))
        .ok()?;
    empreinte_d_identifiant(&id)
}

/// L'empreinte d'un identifiant d'ordinateur, tel qu'il est lu : espaces et sauts de ligne autour retirés, puis
/// SHA-1 en hexadécimal. Le témoin `vanguard.cle` du déploiement est fait par elle : la clé et le programme ne peuvent
/// pas diverger, et une empreinte qui changerait remonterait la clé en lecture seule chez son propriétaire.
pub(crate) fn empreinte_d_identifiant(id: &str) -> Option<String> {
    let id = id.trim();
    (!id.is_empty()).then(|| crate::socle::hachage::sha1_hexa(id.as_bytes()))
}

pub fn retenir_blocage(k: &Correctif) {
    if let Some(port) = &k.bloque {
        retenir_port(port);
    }
}

/// Retient un port bloqué en entrée par Vanguard (« 11434/tcp ») : le bilan le dit fermé au lieu de le reproposer.
pub(crate) fn retenir_port(port: &str) {
    changer_blocages(|deja| deja.insert(port.to_string()));
}

/// L'oublie, quand sa règle est retirée (l'annulation d'un blocage) : le bilan le voit de nouveau ouvert.
pub(crate) fn oublier_port(port: &str) {
    changer_blocages(|deja| deja.remove(port));
}

fn changer_blocages(changer: impl FnOnce(&mut std::collections::HashSet<String>) -> bool) {
    let chemin = fichier_blocages();
    let mut deja = lire_blocages(&std::fs::read_to_string(&chemin).unwrap_or_default());
    if changer(&mut deja) {
        let mut lignes: Vec<_> = deja.into_iter().collect();
        lignes.sort();
        let _ = std::fs::create_dir_all(chemin.parent().unwrap_or(&chemin));
        let texte = if lignes.is_empty() {
            String::new()
        } else {
            lignes.join("\n") + "\n"
        };
        let _ = std::fs::write(&chemin, texte);
    }
}

/// Exécute les commandes d'un correctif. Sous Windows, une seule fenêtre UAC par correctif.
pub fn appliquer(commandes: &[String]) -> bool {
    appliquer_chacune(&[commandes.to_vec()]) == [true]
}

/// Applique plusieurs correctifs indépendants (chacun sa liste de commandes) et dit lesquels ont réussi : un
/// correctif en échec n'empêche pas les suivants. Sous Linux et macOS, les commandes d'un correctif s'arrêtent à la
/// première en échec ; sous Windows, une seule fenêtre UAC pour tous.
pub fn appliquer_chacune(correctifs: &[Vec<String>]) -> Vec<bool> {
    appliquer_annulables(correctifs, &[])
}

/// Comme `appliquer_chacune`, pour des corrections du bilan : `annulables`, pour chacune, l'id de la note qui la
/// défait (`optimiser::annulables`), gardé avec elle dans « Ce que Vanguard a changé ».
pub(crate) fn appliquer_annulables(correctifs: &[Vec<String>], annulables: &[Option<String>]) -> Vec<bool> {
    let (resultats, notes) = lancer_chacune(correctifs);
    // Gardé sur cet ordinateur : « Ce que Vanguard a changé » (changements.rs), avec la valeur d'avant quand le
    // processus élevé l'a lue, et le lien vers la note qui l'annule exactement.
    crate::changements::noter_annulables(&notes, &resultats, annulables);
    resultats
}

/// Comme `appliquer`, sans la note : pour un blocage (protection/blocage), qui note lui-même une seule ligne avec de
/// quoi l'annuler (`changements::noter_blocage`). Rend la réussite et les commandes telles qu'il faut les noter.
pub(crate) fn appliquer_sans_noter(commandes: &[String]) -> (bool, Vec<String>) {
    let (resultats, notes) = lancer_chacune(&[commandes.to_vec()]);
    (resultats == [true], notes.into_iter().next().unwrap_or_default())
}

/// Comme `appliquer_sans_noter`, pour plusieurs groupes faits dans le même passage de droits (un seul mot de passe,
/// une seule fenêtre administrateur) : la réussite de chacun, et ce qu'il faut noter.
pub(crate) fn appliquer_groupes_sans_noter(groupes: &[Vec<String>]) -> (Vec<bool>, Vec<Vec<String>>) {
    let garder: Vec<usize> = (0..groupes.len()).filter(|i| !groupes[*i].is_empty()).collect();
    let pleins: Vec<Vec<String>> = garder.iter().map(|i| groupes[*i].clone()).collect();
    let (r, n) = if pleins.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        lancer_chacune(&pleins)
    };
    // Un groupe vide n'a rien à faire : il est réussi, sans rien noter.
    let mut reussis = vec![true; groupes.len()];
    let mut notes = vec![Vec::new(); groupes.len()];
    for ((i, ok), note) in garder.into_iter().zip(r).zip(n) {
        reussis[i] = ok;
        notes[i] = note;
    }
    (reussis, notes)
}

/// La ligne notée d'une commande faite : la commande, et ce qu'il faut en garder (valeur d'avant, précision, raison
/// de l'échec).
#[cfg(unix)]
fn note_d_ordre(ligne: &str, r: &crate::protection::blocage::ordres::Resultat) -> String {
    match (&r.reussi, &r.note) {
        (true, Some(n)) => format!("{ligne} ({n})"),
        (true, None) => ligne.to_string(),
        (false, _) => format!("{ligne} (échec : {})", r.raison),
    }
}

/// Les ordres typés du blocage (`protection::blocage::ordres`), sous Linux et macOS : tous les groupes faits d'ordres
/// passent ensemble par l'assistant élevé (une seule demande de droits), ou par Vanguard lui-même s'il est root ; un
/// groupe qui mêle ordres et commandes n'est pas fait (une liste de Vanguard ne les mêle jamais).
#[cfg(unix)]
fn lancer_les_ordres(correctifs: &[Vec<String>], resultats: &mut [Option<bool>], notes: &mut [Vec<String>]) {
    use crate::protection::blocage::ordres;
    let mut indices = Vec::new();
    let mut groupes = Vec::new();
    for (i, c) in correctifs.iter().enumerate() {
        let n = c.iter().filter(|l| ordres::est_ordre(l)).count();
        if n == 0 {
            continue;
        }
        if n != c.len() {
            trp!(
                "    ✖ Une liste mêle des gestes de Vanguard et des commandes : elle n'est pas faite.",
                "    ✖ A list mixes Vanguard steps and commands: it is not done."
            );
            resultats[i] = Some(false);
            continue;
        }
        indices.push(i);
        groupes.push(c.iter().filter_map(|l| ordres::analyser(l)).collect::<Vec<_>>());
    }
    if groupes.is_empty() {
        return;
    }
    for o in groupes.iter().flatten() {
        println!("    {GRIS}> {}{RESET}", o.texte());
    }
    let reponses = assistant::appliquer(&groupes);
    for ((i, groupe), reponse) in indices.into_iter().zip(&groupes).zip(reponses) {
        resultats[i] = Some(reponse.len() == groupe.len() && reponse.iter().all(|r| r.reussi));
        notes[i] = correctifs[i]
            .iter()
            .zip(reponse.iter().map(Some).chain(std::iter::repeat(None)))
            .map(|(l, r)| r.map_or_else(|| l.clone(), |r| note_d_ordre(l, r)))
            .collect();
    }
}

/// Les résultats, et ce qu'il faut noter pour chaque correctif (ses commandes, enrichies de la valeur d'avant).
fn lancer_chacune(correctifs: &[Vec<String>]) -> (Vec<bool>, Vec<Vec<String>>) {
    #[cfg(windows)]
    {
        for c in correctifs.iter().flatten() {
            println!("    {GRIS}> {}{RESET}", windows::corrections::affichable(c));
        }
        // Rien que des corrections natives ou des ordres du blocage, et une vraie élévation possible (pas sous Wine) :
        // par Vanguard lui-même, relancé en administrateur ; une liste mêlée de PowerShell passe aussi par lui, en
        // une seule demande (`admin_mele`) ; sinon par le script PowerShell, comme avant.
        if !windows::corrections::toutes_natives(correctifs)
            && !crate::journal::sous_wine()
            && let Some(fait) = windows::admin_mele(correctifs)
        {
            return fait;
        }
        if windows::corrections::toutes_natives(correctifs) && !crate::journal::sous_wine() {
            let lignes: Vec<String> = correctifs.iter().flatten().cloned().collect();
            if let Some(reponses) = windows::eleve::appliquer(&lignes) {
                let mut reponses = reponses.into_iter();
                let mut resultats = Vec::with_capacity(correctifs.len());
                let mut notes = Vec::with_capacity(correctifs.len());
                for commandes in correctifs {
                    let mut reussi = true;
                    let mut note = Vec::with_capacity(commandes.len());
                    for c in commandes {
                        let r = reponses.next();
                        reussi &= r.as_ref().is_some_and(|r| r.reussi);
                        note.push(match r.map(|r| (r.avant, r.note)) {
                            Some((Some(avant), _)) => format!("{c} (avant : {avant})"),
                            Some((None, Some(n))) => format!("{c} ({n})"),
                            _ => c.clone(),
                        });
                    }
                    resultats.push(reussi);
                    notes.push(note);
                }
                return (resultats, notes);
            }
        }
        trp!(
            "    {GRIS}Une fenêtre administrateur s'ouvre et montre chaque étape ; attendez qu'elle se ferme.{RESET}",
            "    {GRIS}An administrator window opens and shows each step; wait for it to close.{RESET}"
        );
        (windows::powershell_admin_chacune(correctifs), correctifs.to_vec())
    }
    #[cfg(not(windows))]
    {
        let mut faits: Vec<Option<bool>> = vec![None; correctifs.len()];
        let mut notes = correctifs.to_vec();
        lancer_les_ordres(correctifs, &mut faits, &mut notes);
        // Le reste : les commandes des corrections du bilan, et les annulations notées par une version d'avant
        // (reconnues mot pour mot, rejouées telles quelles), par bash comme avant.
        let resultats = correctifs
            .iter()
            .zip(faits)
            .map(|(commandes, fait)| {
                fait.unwrap_or_else(|| {
                    commandes.iter().all(|c| {
                        println!("    {GRIS}$ {}{RESET}", crate::ui::commande_affichable(c));
                        Command::new("bash")
                            .arg("-c")
                            .arg(c)
                            .status()
                            .is_ok_and(|s| s.success())
                    })
                })
            })
            .collect();
        (resultats, notes)
    }
}

/// Prises en écoute de `lsof -nP -iTCP -sTCP:LISTEN`, chacune avec son adresse (crochets d'IPv6 ôtés), son port et
/// le nom de son programme. « COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME » … « llama-server 512 alice 9u
/// IPv4 … TCP *:8080 (LISTEN) » → (« * », 8080, « llama-server »). Deux programmes peuvent tenir le même port sur
/// deux adresses (127.0.0.1:8080 et *:8080).
#[cfg(any(target_os = "macos", test))]
pub(crate) fn lire_lsof_prises(sortie: &str) -> Vec<(String, u16, String)> {
    let mut prises = Vec::new();
    for l in sortie.lines().skip(1) {
        let c: Vec<&str> = l.split_whitespace().collect();
        let prise = c.iter().rev().find_map(|m| {
            let (adresse, port) = m.rsplit_once(':')?;
            Some((adresse.trim_matches(['[', ']']).to_string(), port.parse::<u16>().ok()?))
        });
        if let (Some((adresse, port)), Some(nom)) = (prise, c.first()) {
            // lsof échappe les espaces des noms : « Google\x20Chrome ».
            prises.push((adresse, port, affichable(&nom.replace("\\x20", " "))));
        }
    }
    prises
}

/// macOS : les prises en écoute nommées par lsof, sans droits admin (les programmes du compte seulement). `None` :
/// lsof absent ou en échec. Sans aucune prise à montrer, lsof répond 1 sans rien écrire, ni sortie ni erreur : une
/// liste vide, pas un échec.
#[cfg(target_os = "macos")]
pub(crate) fn prises_lsof() -> Option<Vec<(String, u16, String)>> {
    let r = crate::commande::lancer(
        Command::new("lsof").args(["+c", "0", "-nP", "-iTCP", "-sTCP:LISTEN"]),
        30,
    )?;
    let vide = r.code == Some(1) && r.sortie.trim().is_empty() && r.erreurs.trim().is_empty();
    (r.code == Some(0) || vide).then(|| lire_lsof_prises(&r.sortie))
}

/// macOS : les prises TCP en écoute des programmes lisibles (ceux du compte sans droits admin, comme lsof), avec
/// leur adresse (« * » pour toutes), leur port et le nom de leur programme. Lues au noyau (libproc) d'abord ; lsof
/// reste en secours tant que le test d'oracle de macos.yml (machine/macos/noyau.rs) ne l'a pas remplacé, et prend le
/// relais quand la lecture native est muette.
#[cfg(target_os = "macos")]
pub(crate) fn prises_du_compte() -> Option<Vec<(String, u16, String)>> {
    macos::noyau::prises()
        .map(|lues| {
            lues.prises
                .into_iter()
                .filter(|(_, _, p)| p.tcp && p.etat == darwin::TSI_S_LISTEN)
                .map(|(_, nom, p)| {
                    let adresse = if p.locale.is_unspecified() {
                        "*".to_string()
                    } else {
                        p.locale.to_string()
                    };
                    (adresse, p.port_local, affichable(&nom))
                })
                .collect::<Vec<_>>()
        })
        // Aucune prise en écoute lue : peut-être une lecture native qui ne comprend pas ce macOS ; lsof tranche.
        .filter(|prises| !prises.is_empty())
        .or_else(prises_lsof)
}

/// Programme qui écoute sur chaque port TCP de cette machine (port → nom du programme, que chaque programme choisit :
/// prêt à montrer). Sans droits admin, les programmes de root/SYSTEM restent souvent anonymes.
pub fn programmes_en_ecoute() -> std::collections::HashMap<u16, String> {
    let mut map = std::collections::HashMap::new();
    // Les prises lues dans le noyau (netlink, sinon /proc/net), sans lancer ss : le service de chacune vient de son
    // groupe de contrôle, ce qui nomme aussi ceux de root.
    #[cfg(target_os = "linux")]
    for p in linux::ecoute::prises_ou_ss()
        .unwrap_or_default()
        .iter()
        .filter(|p| !p.udp)
    {
        if let Some(nom) = p.nom() {
            map.insert(p.port, nom);
        }
    }
    // Sans droits admin, le noyau (comme lsof) ne montre que les programmes de l'utilisateur. Le nom est celui du
    // fichier du programme, entier : un nom coupé (« llama-ser ») ne reconnaîtrait plus un serveur d'IA.
    #[cfg(target_os = "macos")]
    map.extend(
        prises_du_compte()
            .unwrap_or_default()
            .into_iter()
            .map(|(_, port, nom)| (port, nom)),
    );
    // netstat et tasklist, sans PowerShell ; PowerShell seulement s'ils ne répondent pas.
    #[cfg(windows)]
    let paires = windows::ports_tcp_et_noms().unwrap_or_else(|| {
        windows::ps("$noms = @{}; Get-Process | ForEach-Object { $noms[$_.Id] = $_.ProcessName }; Get-NetTCPConnection -State Listen | ForEach-Object { \"$($_.LocalPort)|$($noms[[int]$_.OwningProcess])\" }")
            .unwrap_or_default()
            .lines()
            .filter_map(|l| {
                let (p, nom) = l.split_once('|')?;
                Some((p.trim().parse::<u16>().ok()?, nom.to_string()))
            })
            .collect()
    });
    #[cfg(windows)]
    for (port, nom) in paires {
        if !nom.trim().is_empty() {
            map.insert(port, affichable(nom.trim()));
        }
    }
    map
}

/// Ouvre un fichier ou une URL avec l'application par défaut du système.
pub fn ouvrir(cible: &str) {
    #[cfg(target_os = "linux")]
    let _ = Command::new("xdg-open").arg(cible).spawn();
    // ShellExecuteExW dans un fil à part, sans cmd : ni « & » ni « %VAR% » d'un lien ou d'un dossier n'y sont lus.
    #[cfg(windows)]
    windows::ouvrir::ouvrir(cible, None);
    #[cfg(target_os = "macos")]
    let _ = Command::new("open").arg(cible).spawn();
}

/// Ouvre un programme du système avec ses paramètres (« C:\Windows\System32\control.exe », « /name
/// Microsoft.FileHistory »), que ShellExecuteExW veut séparés : un seul texte serait cherché comme un fichier de ce
/// nom. `programme` est un chemin entier (`commande::systeme32`) : un nom seul serait cherché d'abord dans le dossier
/// courant.
#[cfg(windows)]
pub fn ouvrir_avec(programme: &str, parametres: &str) {
    windows::ouvrir::ouvrir(programme, Some(parametres));
}

/// À la fin du programme, laisse aux ouvertures en cours le temps d'aboutir (Windows : chacune a son fil, qui
/// disparaîtrait avec le processus). Ailleurs, le programme ouvert est un processus à part : rien à attendre.
pub fn attendre_ouvertures() {
    #[cfg(windows)]
    windows::ouvrir::attendre(std::time::Duration::from_secs(10));
}

/// Quitte le programme avec `code`, après avoir laissé aboutir les ouvertures en cours (Échap, Ctrl+C dans un menu) :
/// `std::process::exit` les couperait.
pub fn quitter(code: i32) -> ! {
    attendre_ouvertures();
    std::process::exit(code)
}

pub fn auditer(bavard: bool) -> Audit {
    if bavard {
        tre!(
            "{GRAS}Audit de cet ordinateur{RESET} ({})",
            "{GRAS}Audit of this computer{RESET} ({})",
            os::NOM
        );
        tre!(
            "{GRIS}Vérifications en cours (quelques secondes)…{RESET}",
            "{GRIS}Checking (a few seconds)…{RESET}"
        );
    }
    let mut a = os::auditer();
    // Alertes que tu as déclarées normales : au niveau info, sans correction proposée (apprentissage.rs).
    if crate::apprentissage::appliquer(&mut a.constats) > 0 {
        a.score = score(&a.constats);
    }
    // Une règle dont la lecture croisée a divergé au dernier autotest : ses constats sains le disent (jamais ses
    // problèmes), sans changer la note.
    crate::autotest::annoter(&mut a.constats);
    // Vérifications impossibles : souvent une version de Windows ou une distribution que le code ne connaît pas.
    // Seulement à la demande : la surveillance horaire répéterait les mêmes lignes.
    if bavard {
        for c in a.constats.iter().filter(|c| !c.verifie) {
            crate::journal::erreur("vérification impossible", &format!("{} : {}", c.categorie, c.message));
        }
    }
    a
}

/// Le bilan des seules règles que `garder` retient (d'après leur identifiant), tel que le système le montre : sans les
/// alertes déclarées normales, qu'`auditer` rabaisse. Les traces le joignent sans les mises à jour, qui interrogent
/// Internet et peuvent prendre des minutes.
pub fn auditer_seulement(garder: impl Fn(&str) -> bool) -> Audit {
    BILAN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let verifications = regles::regles(regles::Os::actuel())
        .into_iter()
        .filter(|r| garder(r.id))
        .map(regles::verification)
        .collect();
    let constats = en_parallele(verifications);
    Audit {
        systeme: os::NOM,
        score: score(&constats),
        constats,
    }
}

/// Système, programmes, pilotes et firmware : tout ce qui doit être à jour (`vanguard mises-a-jour`). `seulement` limite
/// les longues recherches à ces catégories, pour revérifier ce qui vient d'être installé.
pub fn mises_a_jour_completes(seulement: Option<&[&str]>) -> Vec<Constat> {
    os::mises_a_jour_completes(seulement)
}

pub fn afficher(a: &Audit) {
    titre(&trf!("Cet ordinateur ({})", "This computer ({})", a.systeme));
    afficher_constats(&a.constats);
    println!();
    if a.fiable() {
        afficher_note(tr!("Note de la machine", "Machine grade"), a.score);
    } else {
        trp!(
            "  Note de la machine : {}aucune{RESET} (pare-feu ou trop de vérifications impossibles à faire ici)",
            "  Machine grade: {}none{RESET} (firewall or too many checks could not be done here)",
            couleur(Niveau::Eleve)
        );
    }
    if a.impossibles() > 0 {
        trp!(
            "  {}⚠ {} vérification(s) impossible(s) : résultat incomplet.{RESET}",
            "  {}⚠ {} check(s) could not be done: incomplete result.{RESET}",
            couleur(Niveau::Moyen),
            a.impossibles()
        );
    }
}

pub fn afficher_constats(constats: &[Constat]) {
    for c in constats {
        let (icone, etiquette) = match c.probleme {
            None => (format!("{VERT}✔{RESET}"), String::new()),
            // Une simple information n'est pas un problème : pas de croix rouge.
            Some(Niveau::Info) => (format!("{}ℹ{RESET}", couleur(Niveau::Info)), String::new()),
            Some(n) => (
                format!("{}✖{RESET}", couleur(n)),
                format!(" {}[{}]{RESET}", couleur(n), n.libelle()),
            ),
        };
        let cat = crate::langue::categorie(c.categorie);
        // Le message commence à la 21e colonne ; sa suite s'y aligne.
        afficher_aligne(
            &format!("  {icone} {GRAS}{cat:<16}{RESET}{etiquette} "),
            &c.message,
            21,
            "",
        );
        if let Some(k) = &c.correctif {
            let marque = if k.automatique {
                trf!("{} correction possible", "{} fix available", cle_a_molette())
            } else {
                trf!("{} à faire", "{} to do", ampoule())
            };
            let texte = trf!("{marque} : {}", "{marque}: {}", k.action);
            afficher_aligne(&format!("  {:18}", ""), &texte, 23, GRIS);
        }
    }
}

pub fn executer(json: bool) -> Audit {
    let a = auditer(!json);
    if json {
        println!("{}", serde_json::to_string_pretty(&a).unwrap_or_default());
    } else {
        afficher(&a);
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noms_entiers_de_lsof() {
        let l = lire_lsof_prises(
            "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n\
             llama-server 512 alice 9u IPv4 0x1 0t0 TCP *:8080 (LISTEN)\n\
             LM\\x20Studio 600 alice 12u IPv6 0x2 0t0 TCP [::1]:1234 (LISTEN)\n",
        );
        let nom = |port: u16| l.iter().find(|(_, p, _)| *p == port).map(|(_, _, n)| n.as_str());
        assert_eq!(nom(8080), Some("llama-server"));
        assert_eq!(nom(1234), Some("LM Studio"));
    }

    /// Le même port sur deux adresses : chaque prise garde son programme ; l'IPv6 perd ses crochets.
    #[test]
    fn prises_de_lsof_par_adresse() {
        let p = lire_lsof_prises(
            "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n\
             nginx 300 alice 6u IPv4 0x1 0t0 TCP 127.0.0.1:8080 (LISTEN)\n\
             llama-server 512 alice 9u IPv4 0x2 0t0 TCP 192.168.1.20:8080 (LISTEN)\n\
             LM\\x20Studio 600 alice 12u IPv6 0x3 0t0 TCP [::1]:1234 (LISTEN)\n",
        );
        let vues: Vec<(&str, u16, &str)> = p.iter().map(|(a, port, n)| (a.as_str(), *port, n.as_str())).collect();
        assert_eq!(
            vues,
            [
                ("127.0.0.1", 8080, "nginx"),
                ("192.168.1.20", 8080, "llama-server"),
                ("::1", 1234, "LM Studio")
            ]
        );
    }

    fn audit(etats: &[(&'static str, Option<Niveau>, &str)]) -> Audit {
        let constats: Vec<Constat> = etats
            .iter()
            .map(|(c, n, m)| Constat {
                verifie: !m.starts_with("Impossible de vérifier"),
                categorie: c,
                probleme: *n,
                message: m.to_string(),
                correctif: None,
                regle: "",
                objet: crate::modele::Objet::NonMigre,
                precision: crate::modele::Precision::Aucune,
            })
            .collect();
        Audit {
            systeme: "test",
            score: score(&constats),
            constats,
        }
    }

    #[cfg(unix)]
    #[test]
    fn config_ssh_avec_inclusions() {
        assert!(joker("*.conf", "travail.conf") && joker("c?nfig", "config") && joker("*", ""));
        assert!(!joker("*.conf", "travail.conf.bak") && !joker("c?nfig", "cnfig"));
        // Un Include déplié à sa place ; l'alerte nomme le fichier inclus et sa ligne. Une boucle s'arrête.
        let lire = |motif: &str| -> Vec<(String, String)> {
            match motif {
                "config.d/*" => vec![("~/.ssh/config.d/labo".into(), "# labo\nForwardAgent yes\n".into())],
                "boucle" => vec![("~/.ssh/boucle".into(), "Include boucle\n".into())],
                _ => Vec::new(),
            }
        };
        let mut lignes = Vec::new();
        deplier_config_ssh(
            "~/.ssh/config",
            "Include config.d/*\nInclude boucle\nHost x\n",
            &lire,
            8,
            &mut lignes,
        );
        // Les deux lignes du fichier inclus, « Host x », et l'Include de trop au bout de la boucle (laissé tel quel).
        assert_eq!(lignes.len(), 4);
        let c = constats_config_ssh(&lignes);
        assert!(
            c.len() == 1
                && (c[0].message.contains("~/.ssh/config.d/labo, ligne 2")
                    || c[0].message.contains("~/.ssh/config.d/labo, line 2"))
        );
        // Inclus sous un Host précis : le réglage ne vaut que pour lui.
        let mut lignes = Vec::new();
        deplier_config_ssh(
            "~/.ssh/config",
            "Host labo\n  Include config.d/*\n",
            &lire,
            8,
            &mut lignes,
        );
        assert!(constats_config_ssh(&lignes).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn config_ssh_risquee() {
        let config = "\
# commun
ForwardAgent yes
Host labo labo2
    StrictHostKeyChecking no
Host *
    StrictHostKeyChecking=off # pour aller vite
    ForwardAgent no
Host serveur
    ForwardAgent yes
Match all
  stricthostkeychecking \"no\"
Match host x
  StrictHostKeyChecking no
Host *
  StrictHostKeyChecking accept-new
";
        assert_eq!(
            reglages_ssh_risques(config),
            [
                (2, "forwardagent"),
                (6, "stricthostkeychecking"),
                (11, "stricthostkeychecking")
            ]
        );
        assert_eq!(reglages_ssh_risques("Host *\n  User moi\n"), []);
        let c = constats_config_ssh(&[("~/.ssh/config".into(), 1, "StrictHostKeyChecking no".into())]);
        assert!(c.len() == 1 && c[0].probleme == Some(Niveau::Moyen));
        assert!(c[0].message.contains("ligne 1") || c[0].message.contains("line 1"));
    }

    #[cfg(unix)]
    #[test]
    fn phrase_de_passe_des_cles_ssh() {
        // Clés générées pour le test, si ssh-keygen est disponible.
        let dossier = std::env::temp_dir().join(format!("vanguard-cles-{}", std::process::id()));
        std::fs::create_dir_all(&dossier).unwrap();
        let generer = |nom: &str, phrase: &str| {
            std::process::Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", phrase, "-f"])
                .arg(dossier.join(nom))
                .status()
                .is_ok_and(|s| s.success())
        };
        if generer("nue", "") && generer("protegee", "phrase de test") {
            let lire = |n: &str| std::fs::read_to_string(dossier.join(n)).unwrap();
            assert_eq!(cle_protegee(&lire("nue")), Some(false));
            assert_eq!(cle_protegee(&lire("protegee")), Some(true));
            assert_eq!(cle_protegee(&lire("nue.pub")), None);
        }
        std::fs::remove_dir_all(&dossier).unwrap();
        assert_eq!(cle_protegee("-----BEGIN ENCRYPTED PRIVATE KEY-----\nxx"), Some(true));
        assert_eq!(
            cle_protegee("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"),
            Some(true)
        );
        assert_eq!(cle_protegee("-----BEGIN RSA PRIVATE KEY-----\nMIIE\n"), Some(false));
        assert_eq!(base64_decoder("TWFu").unwrap(), b"Man");
        assert_eq!(base64_decoder("TQ==").unwrap(), b"M");
    }

    #[test]
    fn pas_de_note_sans_pare_feu_verifie() {
        let inconnu = "Impossible de vérifier (systemd absent).";
        let sans_pare_feu = audit(&[
            ("Pare-feu", Some(Niveau::Info), inconnu),
            ("Mises à jour", None, "Système à jour."),
            ("Chiffrement", None, "Disque chiffré."),
            ("Comptes", None, "Seul root a l'UID 0."),
        ]);
        assert!(!sans_pare_feu.fiable());
        let peu_verifie = audit(&[
            ("Pare-feu", None, "ufw est actif."),
            ("SSH", Some(Niveau::Info), inconnu),
            ("Services", Some(Niveau::Info), inconnu),
            ("Comptes", None, "Seul root a l'UID 0."),
        ]);
        assert!(!peu_verifie.fiable());
        let complet = audit(&[
            ("Pare-feu", None, "ufw est actif."),
            ("SSH", None, "Serveur SSH désactivé."),
            ("Mises à jour", Some(Niveau::Info), inconnu),
            ("Comptes", None, "Seul root a l'UID 0."),
        ]);
        assert!(complet.fiable());
        // Aucun constat du pare-feu (sa règle n'a rien rendu) : pas de note.
        let sans_constat = audit(&[
            ("SSH", None, "Serveur SSH désactivé."),
            ("Mises à jour", None, "Système à jour."),
            ("Comptes", None, "Seul root a l'UID 0."),
        ]);
        assert!(!sans_constat.fiable());
        // La règle du pare-feu a planté (« erreur interne » de catégorie Audit), mais le mode furtif de macOS, de
        // catégorie Pare-feu, a répondu : toujours pas de note.
        let mut plante = audit(&[
            ("Pare-feu", None, "Mode furtif actif."),
            (
                "Audit",
                Some(Niveau::Info),
                "Impossible de vérifier (erreur interne, règle MAC-PFE-001).",
            ),
            ("SSH", None, "Serveur SSH désactivé."),
            ("Mises à jour", None, "Système à jour."),
            ("Comptes", None, "Seul root a l'UID 0."),
        ]);
        plante.constats[1].regle = "MAC-PFE-001";
        assert!(!plante.fiable());
    }

    /// macOS : le mode furtif illisible (MAC-PFE-002) ne retire plus la note quand le pare-feu, lui, a été lu ; le
    /// pare-feu illisible (MAC-PFE-001), toujours.
    #[test]
    fn mode_furtif_illisible_garde_la_note() {
        let inconnu = "Impossible de vérifier (mode furtif illisible).";
        let mut a = audit(&[
            ("Pare-feu", None, "Pare-feu de macOS actif."),
            ("Pare-feu", Some(Niveau::Info), inconnu),
            ("SSH", None, "Serveur SSH désactivé."),
            ("Mises à jour", None, "Système à jour."),
            ("Comptes", None, "Seul root a l'UID 0."),
        ]);
        a.constats[0].regle = "MAC-PFE-001";
        a.constats[1].regle = "MAC-PFE-002";
        a.constats[1].verifie = false;
        for c in &mut a.constats[2..] {
            c.regle = "MAC-TST-001";
        }
        assert!(a.fiable());
        a.constats[0].verifie = false;
        a.constats[0].probleme = Some(Niveau::Info);
        assert!(!a.fiable());
    }

    /// Une règle qui plante ne fait pas tomber le bilan : son constat « erreur interne » n'est pas vérifié et garde
    /// l'identifiant de la règle.
    #[test]
    fn regle_qui_plante_garde_son_identifiant() {
        let regle: &'static regles::Regle = Box::leak(Box::new(regles::Regle {
            id: "LNX-TST-001",
            systeme: regles::Os::actuel(),
            rang: 1,
            sujet: ("essai", "test"),
            references: &[],
            verifier: || panic!("règle d'essai"),
        }));
        let constats = en_parallele(vec![regles::verification(regle)]);
        assert_eq!(constats.len(), 1);
        assert!(!constats[0].verifie);
        assert_eq!(constats[0].regle, "LNX-TST-001");
        assert!(constats[0].message.contains("LNX-TST-001"));
    }

    #[cfg(unix)]
    #[test]
    fn un_correctif_en_echec_n_arrete_pas_les_autres() {
        let temoin = std::env::temp_dir().join(format!("vanguard-test-appliquer-{}", std::process::id()));
        let toucher = format!("touch '{}'", temoin.display());
        let r = appliquer_chacune(&[vec!["true".into()], vec!["false".into(), toucher], vec!["true".into()]]);
        assert_eq!(r, [true, false, true]);
        // Dans un même correctif, rien ne part après une commande en échec.
        assert!(!temoin.exists());
    }

    /// Ce que plusieurs règles demandent en même temps se lit une fois par bilan ; le bilan suivant le relit.
    #[test]
    fn lu_une_fois_par_bilan() {
        let pare_feu = ParBilan::new();
        let lectures = std::sync::atomic::AtomicU32::new(0);
        let lire = |bilan| {
            pare_feu.lire_au(bilan, || {
                lectures.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1
            })
        };
        let lues: Vec<u32> = std::thread::scope(|s| {
            let fils: Vec<_> = (0..8).map(|_| s.spawn(|| lire(7))).collect();
            fils.into_iter().map(|f| f.join().unwrap()).collect()
        });
        assert_eq!(lues, [1; 8]);
        assert_eq!(lire(8), 2);
        assert_eq!(lire(8), 2);
    }
}

/// Configuration SSH du client et réglages de sudo, sur des entrées au hasard : jamais de plantage ; les jokers des
/// inclusions se comportent comme ceux de SSH.
#[cfg(all(test, unix))]
mod tests_au_hasard {
    use super::*;
    use proptest::prelude::*;

    fn texte() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop_oneof![
                any::<String>(),
                "[ -~\\t\u{1b}é=\"#]{0,60}",
                "(Host|Match|Include|StrictHostKeyChecking|ForwardAgent|PermitRootLogin|PasswordAuthentication)[ =]+[ -~]{0,20}",
                "(Matching Defaults entries for alice:|    [ -~]{0,40}|)",
            ],
            0..12,
        )
        .prop_map(|l| l.join("\n"))
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn lecteurs_sans_plantage(t in texte()) {
            let _ = reglages_ssh_risques(&t);
            let lire = |_: &str| vec![("~/.ssh/inclus".to_string(), t.clone())];
            let mut lignes = Vec::new();
            deplier_config_ssh("~/.ssh/config", &t, &lire, 3, &mut lignes);
            let _ = constats_config_ssh(&lignes);
            let _ = unix::defauts_sudo(&t);
            let _ = unix::regles_nopasswd(&t);
            let _ = unix::juger_sshd_mac(&t);
        }

        #[test]
        fn jokers(nom in "[a-z.]{0,12}") {
            prop_assert!(joker("*", &nom));
            prop_assert!(joker(&nom, &nom));
            let ajout = format!("{nom}x");
            prop_assert!(!joker(&nom, &ajout));
            let interrogations = "?".repeat(nom.chars().count());
            prop_assert!(joker(&interrogations, &nom));
        }
    }
}

/// T4 : une règle jugée en français puis en anglais rend les mêmes clés et les mêmes états, et deux constats d'une
/// même exécution ne partagent jamais une clé. Rend les clés (triées), que chaque test compare à celles qu'il
/// attend : un instantané qui montre une clé qui change.
#[cfg(test)]
pub(crate) fn controler_regle(regle: &'static str, juger: impl Fn() -> Vec<Constat>) -> Vec<String> {
    let lire = |constats: Vec<Constat>| {
        let mut vus: Vec<(String, &'static str)> = Vec::new();
        for mut c in constats {
            c.regle = regle;
            assert!(c.coherent(), "{regle} : constat incohérent « {} »", c.message);
            if let Some(k) = c.cle() {
                let k = k.to_string();
                assert!(vus.iter().all(|(v, _)| *v != k), "{regle} : clé en double {k}");
                vus.push((k, c.etat().code()));
            }
        }
        vus.sort();
        vus
    };
    let fr = lire(juger());
    let en = lire(crate::langue::en_anglais(&juger));
    assert_eq!(fr, en, "{regle} : les clés ou les états changent avec la langue");
    fr.into_iter().map(|(k, _)| k).collect()
}

/// L'état des constats (`modele::Etat`) : quatre cas jamais confondus, un JSON qui garde ses champs d'avant, et une
/// note qui ne monte jamais quand une vérification se perd (T7).
#[cfg(test)]
mod tests_etat {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn quatre_cas_et_json() {
        let sain = ok("Pare-feu", "ufw actif.");
        let probleme = alerte("Ports en écoute", Niveau::Moyen, "8080/tcp ouvert.").avec_objet(Objet::port(
            8080,
            "tcp",
            Some("python3"),
        ));
        let ancien = impossible("SSH", "sshd absent");
        let muette = impossible_par("Audit", Raison::Muette, "rien");
        let sans = sans_objet("Wi-Fi", Absence::Materiel, "Pas de carte Wi-Fi.");
        assert_eq!(sain.etat(), Etat::Sain);
        assert_eq!(probleme.etat(), Etat::Probleme { niveau: Niveau::Moyen });
        assert_eq!(ancien.etat(), Etat::NonVerifie(Raison::NonPrecisee));
        assert_eq!(muette.etat(), Etat::NonVerifie(Raison::Muette));
        assert_eq!(sans.etat(), Etat::SansObjet(Absence::Materiel));
        for c in [&sain, &probleme, &ancien, &muette, &sans] {
            assert!(c.coherent(), "{}", c.message);
        }
        // Sans règle, pas de clé ; avec, « règle|objet ».
        assert_eq!(probleme.cle(), None);
        let mut avec_regle = probleme.clone();
        avec_regle.regle = "LNX-RES-001";
        assert_eq!(
            avec_regle.cle().map(|c| c.to_string()).as_deref(),
            Some("LNX-RES-001|port:8080/tcp:python3")
        );
        let json = serde_json::to_value(&avec_regle).unwrap();
        assert_eq!(json["probleme"], "Moyen");
        assert_eq!(json["verifie"], true);
        assert_eq!(json["regle"], "LNX-RES-001");
        assert_eq!(json["objet"], "port:8080/tcp:python3");
        assert_eq!(json["cle"], "LNX-RES-001|port:8080/tcp:python3");
        assert_eq!(json["etat"], "probleme");
        assert_eq!(
            json.get("reference").and_then(|r| r.as_str()),
            regles::reference_de("LNX-RES-001")
        );
        let json = serde_json::to_value(&muette).unwrap();
        assert_eq!(
            (json["etat"].as_str(), json["raison"].as_str()),
            (Some("non-verifie"), Some("muette"))
        );
        assert!(json.get("regle").is_none() && json.get("cle").is_none() && json.get("objet").is_none());
        assert!(json.get("reference").is_none());
        let json = serde_json::to_value(&sans).unwrap();
        assert_eq!(
            (json["etat"].as_str(), json["absence"].as_str()),
            (Some("sans-objet"), Some("materiel"))
        );
    }

    /// Un « sans objet » ne dilue pas les non vérifiés : deux non vérifiés sur six constats laissent une note, pas
    /// sur trois constats jugés et trois sans objet.
    #[test]
    fn sans_objet_jamais_compte_sain() {
        let mut constats = vec![
            ok("Pare-feu", "ufw actif."),
            impossible("SSH", "x"),
            impossible("DNS", "y"),
        ];
        let jugee = |c: Vec<Constat>| Audit {
            systeme: "Linux",
            score: score(&c),
            constats: c,
        };
        let mut avec_sains = constats.clone();
        avec_sains.extend((0..4).map(|_| ok("Comptes", "Seul root a l'UID 0.")));
        assert!(jugee(avec_sains).fiable());
        constats.extend((0..4).map(|_| sans_objet("Wi-Fi", Absence::Inactif, "Aucun réseau Wi-Fi connecté.")));
        assert!(!jugee(constats).fiable());
    }

    /// Un constat au hasard, décrit (cas, niveau, catégorie) : sain, problème, non vérifié ou sans objet.
    fn description() -> impl Strategy<Value = (u8, u8, &'static str)> {
        (
            0u8..4,
            0u8..4,
            prop::sample::select(vec!["Comptes", "SSH", "DNS", "Ports en écoute"]),
        )
    }

    fn fabriquer(&(cas, n, categorie): &(u8, u8, &'static str)) -> Constat {
        let niveau = [Niveau::Info, Niveau::Moyen, Niveau::Eleve, Niveau::Critique][usize::from(n)];
        match cas {
            0 => ok(categorie, "sain"),
            1 => alerte(categorie, niveau, "problème"),
            2 => impossible(categorie, "raison"),
            _ => sans_objet(categorie, Absence::Inactif, "rien à juger"),
        }
    }

    fn jugee(c: &[Constat]) -> (u32, bool) {
        let mut tous = vec![ok("Pare-feu", "ufw actif.")];
        tous.extend_from_slice(c);
        let a = Audit {
            systeme: "Linux",
            score: score(&tous),
            constats: tous,
        };
        (a.score, a.fiable())
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]

        /// T7 : perdre une vérification (sain → non vérifié, sain → sans objet) ne fait jamais monter la note ni
        /// passer la fiabilité de faux à vrai ; aggraver un problème ne fait jamais monter la note.
        #[test]
        fn la_note_ne_monte_jamais_quand_on_voit_moins(
            d in prop::collection::vec(description(), 0..14),
            i in any::<prop::sample::Index>(),
        ) {
            let c: Vec<Constat> = d.iter().map(fabriquer).collect();
            let note = jugee(&c).0;
            for remplacant in [impossible("Comptes", "perdu"), sans_objet("Comptes", Absence::Inactif, "rien")] {
                let mut moins = c.clone();
                moins.push(ok("Comptes", "sain"));
                let (note_avant, fiable_avant) = jugee(&moins);
                let dernier = moins.len() - 1;
                moins[dernier] = remplacant;
                let (note_apres, fiable_apres) = jugee(&moins);
                prop_assert!(note_apres <= note_avant);
                prop_assert!(!fiable_apres || fiable_avant);
            }
            if !c.is_empty() {
                let k = i.index(c.len());
                if let Some(n) = c[k].probleme.filter(|_| c[k].verifie) {
                    let mut pire = c.clone();
                    pire[k].probleme = Some(Niveau::Critique.max(n));
                    prop_assert!(jugee(&pire).0 <= note);
                }
            }
        }
    }
}

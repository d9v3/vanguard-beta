//! L'aperçu d'une correction, sans rien changer : `vanguard correction --voir <jeton> [--json]`.
//!
//! La fenêtre ne désigne jamais un constat par son nom, son chemin ou sa commande : `audit --json` donne à chaque
//! constat corrigeable un **jeton** (16 octets, 32 chiffres hexadécimaux minuscules), et c'est lui seul qu'elle
//! renvoie. Vanguard relance la seule règle qu'il désigne, retrouve le constat d'aujourd'hui qui y répond, puis dit
//! tout ce qu'il ferait (phrase, commandes, droits, valeurs d'avant, annulation) et l'**accord** : l'empreinte de
//! tout ce qui est montré. Le lot suivant applique une correction seulement si l'accord recalculé est le même ; ici,
//! rien n'est appliqué, noté ni écrit : l'interrupteur de lecture seule de l'autodiagnostic est posé dès l'entrée
//! de `main`, avant tout le reste (ni passage, ni « déjà vu », ni sceau, ni journal, ni verrou, ni dossier créé), et
//! seules les règles relues pour cela, qui ne lancent aucun programme, sont relancées (`RELUES_SANS_PROGRAMME`).
//! L'essai `voir_une_correction_n_ecrit_rien` (tests/programme.rs) part d'un dossier personnel vide, relance chaque
//! règle du bilan et compare les fichiers avant et après (contenu, droits, cibles des liens).
//!
//! Le jeton n'est pas un secret : il dit seulement « ce constat-là ». Ses 4 premiers octets viennent de la règle, les
//! 12 suivants de la clé du constat (« règle|objet ») : Vanguard retrouve la règle sans rien garder entre la liste et
//! l'aperçu, et ne relance qu'elle (une à deux secondes au lieu du bilan entier).

use serde::Serialize;

use super::{Constat, Correctif, Defaire, Droits, regles};
use crate::risk::Niveau;
use crate::tr;

/// Le contexte BLAKE3 de la part « règle » du jeton.
const CONTEXTE_REGLE: &str = "vanguard jeton v1 regle";
/// Le contexte BLAKE3 de la part « clé » du jeton.
const CONTEXTE_CLE: &str = "vanguard jeton v1 cle";
/// Le contexte BLAKE3 de l'accord d'une correction : `vanguard accord v1 <sorte>`, la sorte du geste qui changera.
const CONTEXTE_ACCORD: &str = "vanguard accord v1 correction";
/// La sorte du geste, dans `audit --json` et la dernière ligne de `--voir`.
pub(crate) const SORTE: &str = "voir-correction";
/// Les octets du jeton tirés de la règle.
const OCTETS_REGLE: usize = 4;

/// Le jeton d'un constat : 16 octets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Jeton([u8; 16]);

impl Jeton {
    /// Le jeton du constat de la règle `regle` et de clé `cle` (« règle|objet »).
    pub(crate) fn de(regle: &str, cle: &str) -> Jeton {
        let r = blake3::derive_key(CONTEXTE_REGLE, regle.as_bytes());
        let c = blake3::derive_key(CONTEXTE_CLE, cle.as_bytes());
        let mut o = [0u8; 16];
        o[..OCTETS_REGLE].copy_from_slice(&r[..OCTETS_REGLE]);
        o[OCTETS_REGLE..].copy_from_slice(&c[..16 - OCTETS_REGLE]);
        Jeton(o)
    }

    /// Lu strictement : 32 chiffres hexadécimaux minuscules, rien d'autre (ni espace, ni majuscule, ni préfixe).
    pub(crate) fn lire(texte: &str) -> Option<Jeton> {
        let (paires, reste) = texte.as_bytes().as_chunks::<2>();
        if paires.len() != 16 || !reste.is_empty() {
            return None;
        }
        let mut j = [0u8; 16];
        for (octet, [haut, bas]) in j.iter_mut().zip(paires) {
            *octet = (chiffre(*haut)? << 4) | chiffre(*bas)?;
        }
        Some(Jeton(j))
    }

    pub(crate) fn hex(&self) -> String {
        use std::fmt::Write;
        self.0.iter().fold(String::with_capacity(32), |mut t, b| {
            let _ = write!(t, "{b:02x}");
            t
        })
    }

    /// Ce jeton peut-il venir de la règle `id` ? (Ses 4 premiers octets.)
    fn de_la_regle(&self, id: &str) -> bool {
        let r = blake3::derive_key(CONTEXTE_REGLE, id.as_bytes());
        self.0[..OCTETS_REGLE] == r[..OCTETS_REGLE]
    }
}

/// Un chiffre hexadécimal minuscule ; une majuscule ou autre chose : `None` (une seule écriture d'un même jeton).
fn chiffre(b: u8) -> Option<u8> {
    if !matches!(b, b'0'..=b'9' | b'a'..=b'f') {
        return None;
    }
    char::from(b).to_digit(16).and_then(|n| u8::try_from(n).ok())
}

/// Le geste qu'un constat de `audit --json` offre à la fenêtre.
#[derive(Serialize, Debug, PartialEq, Eq)]
pub(crate) struct GesteOffert {
    sorte: &'static str,
    jeton: String,
}

/// Les règles que l'aperçu relance : chacune relue pour cela, elle ne lit que des fichiers (le dossier personnel,
/// /proc, /sys, les dossiers du PATH) et ne lance AUCUN programme. Liste permise plutôt que liste d'exclus : beaucoup
/// d'outils du système écrivent en lisant (pacman, checkupdates et flatpak leur base ou leur dépôt, gsettings et
/// dconf `$XDG_RUNTIME_DIR/dconf/user`, docker sa configuration…), et l'interrupteur de lecture seule de Vanguard ne
/// les retient pas ; une règle oubliée dans une liste d'exclus romprait la promesse « rien n'a changé », une règle
/// oubliée ici ne coûte qu'un aperçu (la carte dit « depuis le terminal pour l'instant »). Une règle s'ajoute après
/// relecture de tout ce qu'elle appelle ; `relire` refuse quand même l'aperçu si un programme a été lancé pendant la
/// relecture (`coulisses::lancements`), et l'essai `voir_une_correction_n_ecrit_rien` relance chaque règle permise
/// dans un dossier personnel jetable. Les règles de Windows n'y sont pas encore : rien n'y a été relu.
const RELUES_SANS_PROGRAMME: &[&str] = &[
    // Clés SSH du compte : ~/.ssh, ses fichiers, sa configuration et ses fichiers inclus.
    "LNX-SSH-003",
    // Fichiers secrets et dossier personnel : leurs droits.
    "LNX-PRV-001",
    // Durcissement du noyau (mémoire, fichiers partagés, réseau) : /proc/sys.
    "LNX-NOY-003",
    "LNX-NOY-007",
    "LNX-RES-003",
    // Module de sécurité : /sys/kernel/security, /sys/fs/selinux, os-release.
    "LNX-NOY-004",
    // Failles du processeur : /sys/devices/system/cpu/vulnerabilities, os-release.
    "LNX-MAT-001",
    // Dossiers de commandes modifiables par d'autres : les droits des dossiers du PATH.
    "LNX-PRV-004",
];

/// Une règle que l'aperçu ne relance pas : toute règle hors de `RELUES_SANS_PROGRAMME`.
fn hors_apercu(id: &str) -> bool {
    !RELUES_SANS_PROGRAMME.contains(&id)
}

/// Les règles du registre de ce système que l'aperçu relance.
fn relancables() -> Vec<&'static str> {
    regles::regles(regles::Os::actuel())
        .iter()
        .map(|r| r.id)
        .filter(|id| !hors_apercu(id))
        .collect()
}

/// Le jeton d'un constat qui offre « Voir la correction » : un problème, une correction, une clé, d'une règle de
/// `connues` (en vrai : `relancables`, celles que l'aperçu peut relancer sans rien écrire). Sinon rien (la carte dit
/// « depuis le terminal pour l'instant »).
fn jeton_du(c: &Constat, connues: &[&'static str]) -> Option<Jeton> {
    c.probleme?;
    c.correctif.as_ref()?;
    if !connues.contains(&c.regle) {
        return None;
    }
    let cle = c.cle()?;
    Some(Jeton::de(c.regle, &cle.to_string()))
}

/// Le geste de chaque constat d'un bilan, dans l'ordre : un jeton porté par deux constats n'est offert à aucun des
/// deux (`--voir` le refuserait, autant ne pas montrer un bouton qui ne mène à rien).
pub(crate) fn gestes_offerts(constats: &[Constat]) -> Vec<Option<GesteOffert>> {
    let connues = relancables();
    let jetons: Vec<Option<Jeton>> = constats.iter().map(|c| jeton_du(c, &connues)).collect();
    jetons
        .iter()
        .map(|j| {
            let j = (*j)?;
            (jetons.iter().filter(|k| **k == Some(j)).count() == 1).then(|| GesteOffert {
                sorte: SORTE,
                jeton: j.hex(),
            })
        })
        .collect()
}

/// Une valeur d'avant relevée : le geste (« droits:/home/alice/.ssh ») et sa valeur (absente : `None`).
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct ValeurAvant {
    pub geste: String,
    pub valeur: Option<String>,
}

/// Tout ce que l'aperçu donne à montrer. Chaque champ est dans l'accord (`champs`, tenu par un essai qui relit les
/// clés du JSON) : rien de montré n'échappe à l'engagement « voilà ce qui a été vu ».
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Apercu {
    pub version: String,
    /// « fr » ou « en » : la langue des textes montrés.
    pub langue: String,
    pub jeton: String,
    pub cle: String,
    pub regle: String,
    pub categorie: String,
    /// « Info », « Moyen », « Eleve » ou « Critique », comme `audit --json`.
    pub niveau: String,
    pub message: String,
    pub action: String,
    pub commandes: Vec<String>,
    /// `false` : à faire soi-même, seulement la marche à suivre.
    pub automatique: bool,
    /// « compte », « admin » ou « terminal » : jugé ici, jamais repris de la liste.
    pub droits: String,
    pub annulable: bool,
    /// Pourquoi elle ne s'annulerait pas ; vide si elle s'annule.
    pub pourquoi_pas: String,
    pub avant: Vec<ValeurAvant>,
    /// Toujours faux dans ce lot : snapper et timeshift demandent les droits d'administrateur.
    pub point_de_restauration: bool,
}

/// Un bloc de l'accord : sa longueur (8 octets, petit-boutiste) puis ses octets. Une longueur préfixée ne laisse
/// pas deux suites de champs différentes donner les mêmes octets (« ab » + « c » contre « a » + « bc »).
fn bloc(sortie: &mut Vec<u8>, octets: &[u8]) {
    sortie.extend_from_slice(&longueur(octets.len()));
    sortie.extend_from_slice(octets);
}

/// Une longueur en 8 octets petit-boutistes (un `usize` tient toujours dans un `u64` sur les cibles de Vanguard).
fn longueur(n: usize) -> [u8; 8] {
    u64::try_from(n).unwrap_or(u64::MAX).to_le_bytes()
}

/// Une liste de blocs : leur nombre, puis chacun.
fn liste<'a>(blocs: impl ExactSizeIterator<Item = &'a [u8]>) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(&longueur(blocs.len()));
    for b in blocs {
        bloc(&mut o, b);
    }
    o
}

fn booleen(b: bool) -> Vec<u8> {
    vec![u8::from(b)]
}

impl Apercu {
    /// Chaque champ montré, nommé comme dans le JSON, en octets. Écrit à la main plutôt que tiré du JSON : la forme
    /// de serde_json (espaces, échappements) ne décide pas de l'accord ; un champ ajouté à `Apercu` sans être ajouté
    /// ici fait échouer l'essai `chaque_champ_montre_est_dans_l_accord`.
    fn champs(&self) -> Vec<(&'static str, Vec<u8>)> {
        let avant = liste(
            self.avant
                .iter()
                .map(|v| {
                    let mut o = Vec::new();
                    bloc(&mut o, v.geste.as_bytes());
                    match &v.valeur {
                        Some(t) => {
                            o.push(1);
                            bloc(&mut o, t.as_bytes());
                        }
                        None => o.push(0),
                    }
                    o
                })
                .collect::<Vec<_>>()
                .iter()
                .map(Vec::as_slice),
        );
        vec![
            ("version", self.version.clone().into_bytes()),
            ("langue", self.langue.clone().into_bytes()),
            ("jeton", self.jeton.clone().into_bytes()),
            ("cle", self.cle.clone().into_bytes()),
            ("regle", self.regle.clone().into_bytes()),
            ("categorie", self.categorie.clone().into_bytes()),
            ("niveau", self.niveau.clone().into_bytes()),
            ("message", self.message.clone().into_bytes()),
            ("action", self.action.clone().into_bytes()),
            ("commandes", liste(self.commandes.iter().map(String::as_bytes))),
            ("automatique", booleen(self.automatique)),
            ("droits", self.droits.clone().into_bytes()),
            ("annulable", booleen(self.annulable)),
            ("pourquoi_pas", self.pourquoi_pas.clone().into_bytes()),
            ("avant", avant),
            ("point_de_restauration", booleen(self.point_de_restauration)),
        ]
    }

    /// L'accord : BLAKE3 à contexte de chaque champ, nom puis valeur, à longueur préfixée. 32 octets, 64 chiffres.
    pub(crate) fn accord(&self) -> String {
        let mut o = Vec::new();
        for (nom, valeur) in self.champs() {
            bloc(&mut o, nom.as_bytes());
            bloc(&mut o, &valeur);
        }
        let mut h = blake3::Hasher::new_derive_key(CONTEXTE_ACCORD);
        h.update(&o);
        h.finalize().to_hex().to_string()
    }
}

/// Une ligne qu'une correction « du compte » peut lancer sans mot de passe : seulement `chmod <mode> <chemin>`, d'un
/// chemin du dossier personnel, rien d'autre. Liste PERMISE plutôt que liste d'élévateurs refusés : une liste de noms
/// se contourne (sudoedit, s\udo, systemd-run --uid=0, ssh root@localhost, `vanguard:geste`, fait par l'assistant
/// élevé…), une forme permise non. Tout ce qui n'y entre pas devient « admin » : un faux refus coûte un mot de passe,
/// jamais un geste fait en douce. Ce n'est qu'une porte sur le TEXTE : elle ne peut pas savoir si `~/.ssh` ou la clé
/// est un lien, que `chmod` suivrait jusqu'à un autre fichier. Ce sont les règles qui ne proposent jamais de
/// correction du compte à travers un lien (`unix::hors_correction`), et le lot qui appliquera relira sans suivre de
/// lien au moment d'agir.
fn permise_au_compte(ligne: &str) -> bool {
    let Some(reste) = ligne.strip_prefix("chmod ") else {
        return false;
    };
    let Some((mode, chemin)) = reste.split_once(' ') else {
        return false;
    };
    mode_permis(mode) && chemin_du_compte(chemin).is_some()
}

/// Trois chiffres octaux, sans bit spécial : le groupe peut lire ou entrer, jamais écrire ; les autres comptes rien.
/// C'est ce que posent les corrections du compte (600, 700, 750) : fermer, jamais ouvrir.
fn mode_permis(mode: &str) -> bool {
    matches!(mode.as_bytes(), [b'0'..=b'7', b'0' | b'1' | b'4' | b'5', b'0'])
}

/// Le chemin qu'une ligne vise, tel que bash le lirait, s'il est dans le dossier personnel : `~` seul ou `~/…`, des
/// caractères sans effet pour le shell, des textes entre apostrophes (`commande::sh_chaine`, son `'\''` compris) ;
/// ni `..`, ni caractère de contrôle, ni rien d'autre (espace, `$`, `;`, guillemets, joker, barre oblique inverse).
fn chemin_du_compte(texte: &str) -> Option<String> {
    let reste = texte.strip_prefix('~')?;
    if !(reste.is_empty() || reste.starts_with('/')) {
        return None;
    }
    let mut lu = String::from("~");
    let mut c = reste.chars().peekable();
    while let Some(x) = c.next() {
        match x {
            '\'' => loop {
                match c.next()? {
                    '\'' => break,
                    y => lu.push(y),
                }
            },
            '\\' if c.next_if_eq(&'\'').is_some() => lu.push('\''),
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | '-' | '+' | '/' | '@' | ',' | '%' | '=' | ':' => lu.push(x),
            _ => return None,
        }
    }
    // Le caractère de remplacement : la trace d'un nom qui n'était pas UTF-8, écrit avec perte ; le chemin lu n'est
    // alors pas celui du fichier jugé (vérification de Fable n° 2, liens L1).
    let sain =
        !lu.chars().any(|x| x.is_control() || x == char::REPLACEMENT_CHARACTER) && !lu.split('/').any(|p| p == "..");
    sain.then_some(lu)
}

/// Les droits que la correction demande vraiment : ceux posés là où elle est écrite, sauf qu'une correction « du
/// compte » dont une ligne n'est pas permise (`permise_au_compte`), sans ligne, ou sous Windows (une seule fenêtre
/// administrateur), devient « admin ». Jamais l'inverse : rien ne fait descendre une correction vers moins de droits.
fn droits_effectifs(k: &Correctif) -> Droits {
    match k.droits {
        Droits::Compte
            if cfg!(windows) || k.commandes.is_empty() || !k.commandes.iter().all(|l| permise_au_compte(l)) =>
        {
            Droits::Admin
        }
        d => d,
    }
}

fn niveau_mot(n: Niveau) -> &'static str {
    match n {
        Niveau::Info => "Info",
        Niveau::Moyen => "Moyen",
        Niveau::Eleve => "Eleve",
        Niveau::Critique => "Critique",
    }
}

/// Pourquoi l'aperçu n'est pas donné.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refus {
    /// Le jeton n'a pas la forme : code 2, avant toute lecture du système.
    MalForme,
    /// Aucune règle, ou aucun constat d'aujourd'hui, n'y répond.
    Disparu,
    /// Deux constats (ou deux règles) y répondent : aucun n'est choisi.
    EnDouble,
    /// Le constat n'a plus de correction (déclaré normal, ou corrigé entre-temps).
    SansCorrection,
    /// La règle n'est pas de celles que l'aperçu relance (`hors_apercu`), ou elle a lancé un programme pendant la
    /// relecture : un autre programme a pu écrire.
    EcritAilleurs,
}

impl Refus {
    fn raison(&self) -> String {
        match self {
            Refus::MalForme => tr!(
                "jeton mal formé : 32 chiffres hexadécimaux minuscules attendus",
                "malformed token: 32 lowercase hexadecimal digits expected"
            ),
            Refus::Disparu => tr!(
                "ce problème a disparu ou a déjà été corrigé : refaites le bilan",
                "this problem is gone or already fixed: run the check again"
            ),
            Refus::EnDouble => tr!(
                "deux constats répondent à ce jeton : aucun n'est choisi",
                "two findings match this token: none is chosen"
            ),
            Refus::SansCorrection => tr!(
                "ce constat n'a plus de correction à proposer",
                "this finding no longer has a fix to offer"
            ),
            Refus::EcritAilleurs => tr!(
                "cette vérification lance d'autres programmes, qui peuvent écrire leurs propres fichiers : pas d'aperçu pour l'instant, la correction se fait depuis le terminal (vanguard corriger)",
                "this check runs other programs, which may write their own files: no preview for now, the fix is done from the terminal (vanguard corriger)"
            ),
        }
        .to_string()
    }
}

/// Le seul constat d'aujourd'hui qui répond au jeton.
fn retrouver<'a>(constats: &'a [Constat], jeton: &Jeton, connues: &[&'static str]) -> Result<&'a Constat, Refus> {
    let mut trouves = constats
        .iter()
        .filter(|c| !c.regle.is_empty() && c.cle().is_some_and(|k| Jeton::de(c.regle, &k.to_string()) == *jeton));
    let c = trouves.next().ok_or(Refus::Disparu)?;
    if trouves.next().is_some() {
        return Err(Refus::EnDouble);
    }
    // Même retrouvé, il faut qu'il offre encore le geste (problème, correction, règle connue).
    if jeton_du(c, connues).is_none() {
        return Err(Refus::SansCorrection);
    }
    Ok(c)
}

/// L'aperçu d'un constat retrouvé : une seule lecture des valeurs d'avant (`annulables::relever`, lecture seule),
/// qui sert à ce qui est montré et à l'accord.
fn apercu_de(c: &Constat, jeton: &Jeton) -> Option<Apercu> {
    let k = c.correctif.as_ref()?;
    let cle = c.cle()?.to_string();
    let releve = match k.comment_defaire() {
        // L'id ne sert qu'à la note, qui n'est pas écrite ici : fixe, pour ne rien tirer au hasard.
        Defaire::Gestes(g) => crate::optimiser::annulables::relever("apercu".to_string(), &k.action, &g),
        _ => Err(k
            .pourquoi_pas()
            .unwrap_or(crate::optimiser::annulables::PourquoiPas::NonReleve)),
    };
    let (annulable, pourquoi_pas, avant) = match &releve {
        Ok(r) => (
            true,
            String::new(),
            r.valeurs()
                .map(|(g, v)| ValeurAvant {
                    geste: g.to_string(),
                    valeur: v.map(str::to_string),
                })
                .collect(),
        ),
        Err(p) => (false, p.texte(), Vec::new()),
    };
    Some(Apercu {
        version: env!("CARGO_PKG_VERSION").to_string(),
        langue: if crate::langue::anglais() { "en" } else { "fr" }.to_string(),
        jeton: jeton.hex(),
        cle,
        regle: c.regle.to_string(),
        categorie: c.categorie.to_string(),
        niveau: niveau_mot(c.probleme?).to_string(),
        message: c.message.clone(),
        action: k.action.clone(),
        commandes: k.commandes.clone(),
        automatique: k.automatique,
        droits: droits_effectifs(k).mot().to_string(),
        annulable,
        pourquoi_pas,
        avant,
        point_de_restauration: false,
    })
}

/// Relit la seule règle du jeton, sans rien noter ni écrire : ni mesure de durée, ni relevé d'amélioration, ni tic de
/// l'Agent, ni appris.json (les alertes déclarées normales rabaissées comme au bilan, sans compléter leurs clés), ni
/// le « déjà vu » que certaines règles tiennent elles-mêmes.
fn relire(jeton: &Jeton) -> Result<Vec<Constat>, Refus> {
    relire_parmi(jeton, regles::regles(regles::Os::actuel()), RELUES_SANS_PROGRAMME)
}

/// `relire` parmi `toutes` les règles, `permises` étant celles que l'aperçu relance (les essais y mettent les leurs).
fn relire_parmi(jeton: &Jeton, toutes: Vec<&'static regles::Regle>, permises: &[&str]) -> Result<Vec<Constat>, Refus> {
    let choisies: Vec<&'static regles::Regle> = toutes.into_iter().filter(|r| jeton.de_la_regle(r.id)).collect();
    match choisies.len() {
        0 => return Err(Refus::Disparu),
        1 => {}
        // 4 octets pour quelques centaines de règles : un essai tient qu'aucune paire ne se croise ; si cela
        // arrivait quand même, rien n'est choisi au hasard.
        _ => return Err(Refus::EnDouble),
    }
    if choisies.iter().any(|r| !permises.contains(&r.id)) {
        return Err(Refus::EcritAilleurs);
    }
    // L'interrupteur de lecture seule de l'autodiagnostic, pour tout le processus : les règles qui tiennent leur
    // « déjà vu » (administrateurs, logiciels installés) ne l'écrivent pas, ni sceau, ni journal, ni verrou.
    crate::autotest::lecture_seule::poser();
    // Un nouveau bilan relit ce que ses règles partagent (`ParBilan`).
    super::BILAN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let lances = crate::coulisses::lancements();
    let (mut constats, _durees) = super::regles_en_parallele(choisies);
    // Une règle permise qui lancerait quand même un programme (une relecture manquée, un ajout plus tard) : l'aperçu
    // ne promet pas « rien n'a changé » sur ce qu'un autre programme a pu écrire. Un filet, pas une preuve : le
    // compteur ne voit que les lancements passés par `coulisses::Suivi` (ni D-Bus, ni socket, ni fork ou exec bruts),
    // et une règle hors délai continue dans son fil après ce contrôle. La vraie garde reste la liste relue
    // (`RELUES_SANS_PROGRAMME`), tenue par l'essai `voir_une_correction_n_ecrit_rien` (tests/programme.rs), qui attend
    // « ce problème a disparu » de chacune : une règle permise qui lance un programme y est refusée et le fait échouer.
    if crate::coulisses::lancements() != lances {
        return Err(Refus::EcritAilleurs);
    }
    crate::apprentissage::appliquer_sans_ecrire(&mut constats);
    Ok(constats)
}

/// `vanguard correction --voir <jeton> [--json]` : l'aperçu, rien de changé. Avec `json`, l'issue est la dernière
/// ligne : `{"geste":"voir-correction","issue":"fait"|"refuse","raison","apercu","accord"}`. Rend le code de
/// sortie : 0 aperçu donné, 1 refusé, 2 jeton mal formé (avant toute lecture).
pub(crate) fn voir(jeton: &str, json: bool) -> i32 {
    let issue = Jeton::lire(jeton).ok_or(Refus::MalForme).and_then(|j| {
        let constats = relire(&j)?;
        let c = retrouver(&constats, &j, &relancables())?;
        apercu_de(c, &j).ok_or(Refus::SansCorrection)
    });
    let code = match &issue {
        Ok(_) => 0,
        Err(Refus::MalForme) => 2,
        Err(_) => 1,
    };
    let texte = if json {
        let ligne = match &issue {
            Ok(a) => serde_json::json!({
                "geste": SORTE, "issue": "fait", "raison": "", "apercu": a, "accord": a.accord()
            }),
            Err(r) => serde_json::json!({ "geste": SORTE, "issue": "refuse", "raison": r.raison() }),
        };
        format!("{ligne}\n")
    } else {
        match &issue {
            Ok(a) => format!("{}\n", lignes(a).join("\n")),
            Err(r) => format!(
                "{}\n",
                crate::ui::mettre_en_lignes(&crate::trf!("  ✖ Pas d'aperçu : {}", "  ✖ No preview: {}", r.raison()))
            ),
        }
    };
    ecrire_sortie(std::io::stdout().lock(), &texte).map_or(SORTIE_COUPEE, |()| code)
}

/// Le code d'une sortie qui n'a pas pu être écrite : celui d'un tube fermé (128 + SIGPIPE), comme le chemin ordinaire
/// (`journal::installer`).
const SORTIE_COUPEE: i32 = 141;

/// Écrit l'aperçu d'un coup. Une sortie fermée (`| head`) ou pleine (/dev/full) n'est pas un plantage : `println!` y
/// paniquait (code 101) ; ici l'erreur est rendue, et rien n'est écrit ailleurs (vérification de Fable n° 2, L6).
fn ecrire_sortie(mut sortie: impl std::io::Write, texte: &str) -> std::io::Result<()> {
    sortie.write_all(texte.as_bytes())?;
    sortie.flush()
}

/// Les lignes de l'aperçu au terminal. Tout texte de l'aperçu passe par `montre_strict` : un nom de fichier piégé
/// (ESC [2K, retour chariot, OSC 52, U+202E, saut de ligne suivi d'un faux « ✔ », caractère qui ne dessine rien) ne
/// pilote pas le terminal, ne réécrit pas l'aperçu et ne se confond pas avec un autre nom. L'accord, lui, porte sur
/// les vrais octets.
fn lignes(a: &Apercu) -> Vec<String> {
    use crate::ui::{GRAS, GRIS, RESET};
    let mut l = vec![
        crate::trf!(
            "{GRAS}Aperçu de la correction{RESET} (rien n'a changé)",
            "{GRAS}Fix preview{RESET} (nothing changed)"
        ),
        crate::trf!(
            "  [{}] {} : {}",
            "  [{}] {}: {}",
            montre_strict(&a.niveau),
            montre_strict(&a.categorie),
            montre_strict(&a.message)
        ),
        crate::trf!(
            "  Ce que Vanguard ferait : {}",
            "  What Vanguard would do: {}",
            montre_strict(&a.action)
        ),
    ];
    l.extend(
        a.commandes
            .iter()
            .map(|c| format!("    {GRIS}{}{RESET}", commande_montree(c))),
    );
    for v in &a.avant {
        // Une valeur absente se distingue d'un texte « (absente) » : entre guillemets quand elle existe.
        let valeur = v.valeur.as_deref().map_or_else(
            || tr!("(absente)", "(absent)").to_string(),
            |t| format!("« {} »", montre_strict(t)),
        );
        l.push(crate::trf!(
            "  Avant : {} = {}",
            "  Before: {} = {}",
            montre_strict(&v.geste),
            valeur
        ));
    }
    l.push(if a.annulable {
        tr!("  S'annule exactement : oui", "  Undone exactly: yes").to_string()
    } else {
        crate::trf!(
            "  Ne s'annule pas : {}",
            "  Cannot be undone: {}",
            montre_strict(&a.pourquoi_pas)
        )
    });
    l.push(
        match a.droits.as_str() {
            "compte" => tr!("  Droits : ceux de votre compte", "  Rights: those of your account"),
            "terminal" => tr!(
                "  Elle pose une question : elle se fait dans le terminal (vanguard corriger)",
                "  It asks a question: it is done in the terminal (vanguard corriger)"
            ),
            _ => tr!("  Droits : administrateur", "  Rights: administrator"),
        }
        .to_string(),
    );
    l.push(crate::trf!("  Accord : {}", "  Consent: {}", a.accord()));
    l
}

/// Une commande au terminal. Un geste de Vanguard (`vanguard:…`) que `ui::commande_affichable` sait dire se montre par
/// sa phrase, faite de textes fixes et de noms déjà validés ; toute autre commande, et une ligne `vanguard:` qui ne se
/// relit pas, se montrent telles qu'elles seraient lancées. Les deux passent par `montre_strict`.
fn commande_montree(commande: &str) -> String {
    const GESTE: &str = "vanguard:";
    let phrase = crate::ui::commande_affichable(commande);
    if commande.starts_with(GESTE) && !phrase.starts_with(GESTE) {
        montre_strict(&phrase)
    } else {
        montre_strict(commande)
    }
}

/// Un texte de l'aperçu, montré sans perte et sans ambiguïté au terminal (vérification de Fable n° 2, P1 et P4).
/// `ui::affichable` refuse une liste de pièges et laisse passer le reste : un caractère hors liste qui ne dessine rien
/// (sélecteur, marque combinante, caractère de format) passait sans se voir, et une vraie tabulation se montrait comme
/// les deux caractères « \ » et « t ». Ici, c'est l'inverse : seuls les caractères d'une courte liste (`se_montre`) se
/// montrent eux-mêmes ; tout autre s'écrit `\u{…}`, la tabulation `\t`, le saut de ligne `\n`, et la barre oblique
/// inverse elle-même `\\`, si bien que chaque marque se relit d'une seule façon. Une espace en bout de texte, et
/// celles d'une suite au-delà de la troisième, s'écrivent `\u{20}` : une longue suite de blancs ne repousse rien hors
/// de la vue. Le prix : un nom écrit dans une autre écriture que le latin se montre en `\u{…}` dans l'aperçu ; il
/// reste juste, seulement moins lisible. `ui::affichable` ne change pas pour le reste de Vanguard.
fn montre_strict(texte: &str) -> String {
    use std::fmt::Write as _;
    let mut sortie = String::with_capacity(texte.len());
    let dernier = texte.chars().count().checked_sub(1);
    let mut espaces = 0usize;
    for (i, c) in texte.chars().enumerate() {
        espaces = if c == ' ' { espaces.saturating_add(1) } else { 0 };
        match c {
            ' ' if i == 0 || Some(i) == dernier || espaces > 3 => sortie.push_str("\\u{20}"),
            ' ' => sortie.push(' '),
            '\\' => sortie.push_str("\\\\"),
            '\t' => sortie.push_str("\\t"),
            '\n' => sortie.push_str("\\n"),
            c if se_montre(c) => sortie.push(c),
            c => {
                let _ = write!(sortie, "\\u{{{:x}}}", u32::from(c));
            }
        }
    }
    sortie
}

/// Les caractères qui se montrent eux-mêmes dans l'aperçu au terminal : ceux de l'ASCII visibles, ceux du latin
/// (français et langues voisines, sans le trait d'union conditionnel U+00AD, qui ne se dessine pas), et les quelques
/// signes des textes de Vanguard. Chacun dessine un caractère d'une colonne, distinct des autres de la liste.
fn se_montre(c: char) -> bool {
    matches!(
        u32::from(c),
        0x21..=0x7E
            | 0xA1..=0xAC
            | 0xAE..=0x17F
            | 0x2013 // –
            | 0x2014 // —
            | 0x2018 // ‘
            | 0x2019 // ’
            | 0x201C // “
            | 0x201D // ”
            | 0x2022 // •
            | 0x2026 // …
            | 0x20AC // €
            | 0x2190..=0x2193 // ← ↑ → ↓
            | 0x2260 // ≠
            | 0x2264..=0x2265 // ≤ ≥
            | 0x23CE // ⏎
            | 0x26A0 // ⚠
            | 0x2714 // ✔
            | 0x2716 // ✖
            | 0xFFFD // �
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modele::Objet;

    fn constat(regle: &'static str, objet: &str, correctif: Option<Correctif>) -> Constat {
        let mut c = super::super::alerte("SSH", Niveau::Moyen, "Un problème inventé");
        c.regle = regle;
        c.objet = Objet::de("chemin", objet);
        c.correctif = correctif;
        c
    }

    fn correctif(droits: Droits, commandes: &[&str]) -> Correctif {
        Correctif {
            action: "Réserver ce dossier à vous seul".into(),
            commandes: commandes.iter().map(|s| (*s).to_string()).collect(),
            automatique: true,
            bloque: None,
            droits,
            defaire: Defaire::Inconnu,
            temoins: crate::machine::temoins::Temoins::default(),
        }
    }

    fn apercu() -> Apercu {
        Apercu {
            version: "0.0.0".into(),
            langue: "fr".into(),
            jeton: "00112233445566778899aabbccddeeff".into(),
            cle: "LNX-ESS-001|/home/alice/.ssh".into(),
            regle: "LNX-ESS-001".into(),
            categorie: "SSH".into(),
            niveau: "Moyen".into(),
            message: "Dossier .ssh lisible par les autres".into(),
            action: "Réserver ~/.ssh à vous seul".into(),
            commandes: vec!["chmod 700 /home/alice/.ssh".into()],
            automatique: true,
            droits: "compte".into(),
            annulable: true,
            pourquoi_pas: String::new(),
            avant: vec![ValeurAvant {
                geste: "droits:/home/alice/.ssh".into(),
                valeur: Some("755".into()),
            }],
            point_de_restauration: false,
        }
    }

    #[test]
    fn le_jeton_se_lit_strictement() {
        let j = Jeton::de("LNX-ESS-001", "LNX-ESS-001|/home/alice/.ssh");
        assert_eq!(Jeton::lire(&j.hex()), Some(j));
        assert!(j.de_la_regle("LNX-ESS-001"));
        assert!(!j.de_la_regle("LNX-ESS-002"));
        for faux in [
            "",
            "0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef0",
            "0123456789ABCDEF0123456789ABCDEF",
            " 0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdeg",
            "+123456789abcdef0123456789abcdef",
            "../../etc/passwd",
            "0123456789abcdef0123456789abcdé",
        ] {
            assert_eq!(Jeton::lire(faux), None, "{faux:?}");
        }
    }

    /// 4 octets de règle : aucune paire de règles d'un même système ne doit les partager, sinon `--voir` refuserait
    /// leurs jetons (en double) sans que personne le sache.
    #[test]
    fn deux_regles_ne_partagent_pas_le_debut_du_jeton() {
        for os in [regles::Os::Linux, regles::Os::Windows] {
            let mut vus = std::collections::HashMap::new();
            for r in regles::regles(os) {
                let j = Jeton::de(r.id, "");
                let debut: [u8; 4] = j.0[..4].try_into().unwrap();
                if let Some(autre) = vus.insert(debut, r.id) {
                    panic!("{} et {autre} partagent le début du jeton", r.id);
                }
            }
            assert!(vus.len() > 10, "{os:?} : trop peu de règles lues");
        }
    }

    #[test]
    fn un_jeton_inconnu_ou_en_double_ne_choisit_rien() {
        let connues = ["LNX-ESS-001"];
        let k = || Some(correctif(Droits::Compte, &["chmod 700 /home/alice/.ssh"]));
        let un = constat("LNX-ESS-001", "/home/alice/.ssh", k());
        let jeton = Jeton::de("LNX-ESS-001", &un.cle().unwrap().to_string());
        assert_eq!(
            retrouver(std::slice::from_ref(&un), &jeton, &connues).map(|c| c.message.clone()),
            Ok(un.message.clone())
        );
        // Inconnu : aucun constat, ou un autre objet.
        let autre = Jeton::de("LNX-ESS-001", "LNX-ESS-001|/home/alice/.gnupg");
        assert_eq!(
            retrouver(std::slice::from_ref(&un), &autre, &connues).err(),
            Some(Refus::Disparu)
        );
        assert_eq!(retrouver(&[], &jeton, &connues).err(), Some(Refus::Disparu));
        // En double : deux constats de même clé.
        let deux = [un.clone(), un.clone()];
        assert_eq!(retrouver(&deux, &jeton, &connues).err(), Some(Refus::EnDouble));
        assert_eq!(gestes_offerts_avec(&deux, &connues), vec![None, None]);
        // Retrouvé, mais plus de correction (déclaré normal entre la liste et l'aperçu) ou règle hors registre.
        let sans = constat("LNX-ESS-001", "/home/alice/.ssh", None);
        assert_eq!(
            retrouver(std::slice::from_ref(&sans), &jeton, &connues).err(),
            Some(Refus::SansCorrection)
        );
        assert_eq!(
            retrouver(std::slice::from_ref(&un), &jeton, &[]).err(),
            Some(Refus::SansCorrection)
        );
    }

    /// `gestes_offerts` avec une liste de règles connues donnée (le registre réel n'a pas « LNX-ESS-001 »).
    fn gestes_offerts_avec(constats: &[Constat], connues: &[&'static str]) -> Vec<Option<String>> {
        let jetons: Vec<Option<Jeton>> = constats.iter().map(|c| jeton_du(c, connues)).collect();
        jetons
            .iter()
            .map(|j| {
                let j = (*j)?;
                (jetons.iter().filter(|k| **k == Some(j)).count() == 1).then(|| j.hex())
            })
            .collect()
    }

    #[test]
    fn seul_un_probleme_corrigeable_d_une_regle_connue_offre_le_geste() {
        let connues = ["LNX-ESS-001"];
        let k = || Some(correctif(Droits::Admin, &["x"]));
        let mut sain = constat("LNX-ESS-001", "a", k());
        sain.probleme = None;
        let sans_cle = {
            let mut c = constat("LNX-ESS-001", "b", k());
            c.objet = Objet::NonMigre;
            c
        };
        let constats = [
            constat("LNX-ESS-001", "a", k()),
            sain,
            sans_cle,
            constat("LNX-ESS-001", "c", None),
            constat("LNX-AUT-009", "d", k()),
            constat("", "e", k()),
        ];
        let offerts = gestes_offerts_avec(&constats, &connues);
        assert!(offerts[0].is_some());
        assert_eq!(&offerts[1..], &[None, None, None, None, None]);
        // Le geste réel n'offre que des règles du registre : un constat inventé n'a rien.
        assert!(gestes_offerts(&constats).iter().all(Option::is_none));
        // Une règle qui n'a pas été relue pour l'aperçu (ici celle des mises à jour, qui lance pacman), même du
        // registre, n'offre rien et n'est jamais relancée.
        assert_eq!(gestes_offerts(&[constat("LNX-MAJ-001", "a", k())]), vec![None]);
        let j = Jeton::de("LNX-MAJ-001", "LNX-MAJ-001|a");
        assert_eq!(relire(&j).err(), Some(Refus::EcritAilleurs));
        assert!(hors_apercu("WIN-MAJ-002") && hors_apercu("LNX-SSH-002") && hors_apercu("COM-NAV-001"));
        // Une règle permise offre son geste dans le vrai registre.
        let permise = constat("LNX-SSH-003", "~/.ssh", k());
        assert_eq!(
            gestes_offerts(std::slice::from_ref(&permise)).len(),
            1,
            "une entrée par constat"
        );
        #[cfg(target_os = "linux")]
        assert!(gestes_offerts(&[permise])[0].is_some());
    }

    /// Une règle d'essai, permise, qui lance un programme comme le ferait une règle mal relue.
    #[cfg(unix)]
    static LANCE_UN_PROGRAMME: regles::Regle = regles::Regle {
        id: "ESS-APE-001",
        systeme: regles::Os::Tous,
        rang: 0,
        sujet: ("Essai", "Test"),
        references: &[],
        verifier: lance_un_programme,
        partage: regles::Partage::Sorte,
    };

    #[cfg(unix)]
    fn lance_un_programme() -> Vec<Constat> {
        let _ = crate::machine::sortie("true", &[]);
        Vec::new()
    }

    /// Une règle d'essai, permise, qui ne lance rien.
    #[cfg(unix)]
    static NE_LANCE_RIEN: regles::Regle = regles::Regle {
        id: "ESS-APE-002",
        systeme: regles::Os::Tous,
        rang: 0,
        sujet: ("Essai", "Test"),
        references: &[],
        verifier: Vec::new,
        partage: regles::Partage::Sorte,
    };

    /// Vérification de Fable n° 2, lecture L2 : une règle permise qui lance quand même un programme fait refuser
    /// l'aperçu (« lance d'autres programmes »), même dite permise ; une qui ne lance rien est relue.
    #[cfg(unix)]
    #[test]
    fn une_regle_permise_qui_lance_un_programme_est_refusee() {
        let lance = Jeton::de("ESS-APE-001", "ESS-APE-001|a");
        let rien = Jeton::de("ESS-APE-002", "ESS-APE-002|a");
        let toutes = || vec![&LANCE_UN_PROGRAMME, &NE_LANCE_RIEN];
        let permises = &["ESS-APE-001", "ESS-APE-002"];
        let refus = relire_parmi(&lance, toutes(), permises).err();
        let relue = relire_parmi(&rien, toutes(), permises);
        crate::autotest::lecture_seule::relever_pour_le_test();
        assert_eq!(refus, Some(Refus::EcritAilleurs));
        // Le compteur est commun au processus : un autre essai qui lance un programme au même moment ferait refuser
        // celle-ci aussi. Seul le refus de la première est donc exigé ; la seconde, quand elle passe, ne rend que son
        // « non vérifié » (une règle qui ne rend rien est dite, pas comptée saine).
        if let Ok(c) = relue {
            assert!(c.iter().all(|x| x.regle == "ESS-APE-002" && !x.verifie));
        }
        // Hors de la liste permise, refusée avant d'être lancée (l'interrupteur n'est même pas posé).
        assert_eq!(
            relire_parmi(&lance, toutes(), &["ESS-APE-002"]).err(),
            Some(Refus::EcritAilleurs)
        );
        assert!(!crate::autotest::lecture_seule::active());
    }

    /// Vérification de Fable n° 2, lecture L6 : une sortie fermée ou pleine rend une erreur (code 141 dans `voir`), pas
    /// une panique.
    #[test]
    fn une_sortie_coupee_n_est_pas_un_plantage() {
        struct Fermee;
        impl std::io::Write for Fermee {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(ecrire_sortie(Fermee, "x\n").is_err());
        let mut v = Vec::new();
        assert!(ecrire_sortie(&mut v, "x\n").is_ok());
        assert_eq!(v, b"x\n");
        assert_eq!(SORTIE_COUPEE, 141);
    }

    /// Chaque règle permise existe au registre de Linux (une faute de frappe la rendrait muette sans le dire), et le
    /// vrai registre ne relance qu'elles.
    #[test]
    fn la_liste_permise_ne_nomme_que_des_regles_du_registre() {
        let linux: Vec<&str> = regles::regles(regles::Os::Linux).iter().map(|r| r.id).collect();
        for id in RELUES_SANS_PROGRAMME {
            assert!(linux.contains(id), "{id} n'est pas une règle de Linux");
            assert!(
                !crate::autotest::va_sur_internet(id),
                "{id} : les mises à jour lancent des outils"
            );
        }
        assert!(relancables().iter().all(|id| RELUES_SANS_PROGRAMME.contains(id)));
    }

    /// Les mêmes champs donnent le même accord, et chaque champ changé en donne un autre : un essai par champ.
    #[test]
    fn l_accord_change_avec_chaque_champ() {
        type Changer = fn(&mut Apercu);
        let a = apercu();
        assert_eq!(a.accord(), apercu().accord());
        assert_eq!(a.accord().len(), 64);
        let cas: &[(&str, Changer)] = &[
            ("version", |a| a.version.push('1')),
            ("langue", |a| a.langue = "en".into()),
            ("jeton", |a| a.jeton = "f".repeat(32)),
            ("cle", |a| a.cle.push('x')),
            ("regle", |a| a.regle = "LNX-ESS-002".into()),
            ("categorie", |a| a.categorie = "Réseau".into()),
            ("niveau", |a| a.niveau = "Eleve".into()),
            ("message", |a| a.message.push(' ')),
            ("action", |a| a.action.push('.')),
            ("commandes", |a| a.commandes[0] = "chmod 700 /home/alice/.sshx".into()),
            ("automatique", |a| a.automatique = false),
            ("droits", |a| a.droits = "admin".into()),
            ("annulable", |a| a.annulable = false),
            ("pourquoi_pas", |a| a.pourquoi_pas = "non".into()),
            ("avant", |a| a.avant[0].valeur = Some("700".into())),
            ("point_de_restauration", |a| a.point_de_restauration = true),
        ];
        let base = a.accord();
        for (nom, changer) in cas {
            let mut b = apercu();
            changer(&mut b);
            assert_ne!(b.accord(), base, "le champ {nom} ne change pas l'accord");
        }
        // Chaque champ du JSON a son cas ici.
        let mut noms: Vec<&str> = cas.iter().map(|(n, _)| *n).collect();
        noms.sort_unstable();
        assert_eq!(noms, cles_du_json(&a));
        // Les listes : une ligne en plus, une valeur absente plutôt que vide, deux lignes recollées.
        let mut b = apercu();
        b.commandes.push(String::new());
        assert_ne!(b.accord(), base);
        let mut b = apercu();
        b.avant[0].valeur = None;
        let mut c = apercu();
        c.avant[0].valeur = Some(String::new());
        assert_ne!(b.accord(), c.accord());
        let mut b = apercu();
        b.commandes = vec!["ab".into(), "c".into()];
        let mut c = apercu();
        c.commandes = vec!["a".into(), "bc".into()];
        assert_ne!(b.accord(), c.accord());
    }

    fn cles_du_json(a: &Apercu) -> Vec<String> {
        // Triées : l'ordre des clés dépend des options de serde_json, l'ensemble non.
        let v = serde_json::to_value(a).unwrap();
        let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    }

    /// Tout champ que l'aperçu donne à montrer est dans l'accord : les clés du JSON sont exactement les noms de
    /// `champs`. Un champ ajouté à `Apercu` sans son entrée dans `champs` échoue ici.
    #[test]
    fn chaque_champ_montre_est_dans_l_accord() {
        let a = apercu();
        let mut noms: Vec<String> = a.champs().iter().map(|(n, _)| (*n).to_string()).collect();
        noms.sort();
        assert_eq!(noms, cles_du_json(&a));
    }

    /// Chaque contournement trouvé par la campagne d'attaque, et d'autres : rien de ce qui n'est pas `chmod <mode
    /// fermé> <chemin du dossier personnel>` ne reste « du compte ».
    #[test]
    fn seule_une_forme_permise_reste_du_compte() {
        let compte = |l: &str| droits_effectifs(&correctif(Droits::Compte, &[l]));
        for l in [
            // Les élévateurs, nommés ou déguisés.
            "sudo chmod 700 /home/alice/.ssh",
            "sudoedit /etc/sudoers",
            "sudo</dev/null id",
            "sudo>/x id",
            "s\\udo id",
            "s${e}udo id",
            "{sudo,id}",
            "sudo\\\nid",
            "systemd-run --uid=0 id",
            "machinectl shell root@ /bin/id",
            "gsudo id",
            "please id",
            "su- root",
            "ssh root@localhost id",
            "pkexec chmod 700 ~/.ssh",
            "run0 id",
            "doas id",
            // Les gestes de Vanguard : faits par l'assistant élevé.
            "vanguard:geste programme x",
            "vanguard:geste defense rendre-a-root x",
            // Un chmod qui sort de la forme.
            "chmod 700 ~/.ssh; sudo id",
            "chmod 700 ~/.ssh && id",
            "chmod 700 ~/.ssh | id",
            "chmod 700 ~/$(id)",
            "chmod 700 ~/`id`",
            "chmod 700 ~/x\nsudo id",
            "chmod 700 ~/'x'$(id)",
            "chmod 700 ~/'x",
            "chmod 700 ~/x*",
            "chmod 700 ~/a b",
            "chmod 700 ~/\"x\"",
            "chmod 4755 ~/x",
            "chmod 777 ~/.ssh",
            "chmod 720 ~/.ssh",
            "chmod 701 ~/.ssh",
            "chmod u+s ~/x",
            "chmod -R 700 ~",
            "chmod 700 /etc/shadow",
            "chmod 700 ~root",
            "chmod 700 ~/../../etc/shadow",
            "chmod 700 ~/.ssh/'..'/../x",
            "chmod 700 ~/'\u{1b}[2K'",
            "chmod  700 ~/.ssh",
            "chmod 700 ~/.ssh ",
            " chmod 700 ~/.ssh",
            "/bin/chmod 700 ~/.ssh",
            "",
        ] {
            assert!(!permise_au_compte(l), "{l:?}");
            assert_eq!(compte(l), Droits::Admin, "{l:?}");
        }
        // Les formes que posent les corrections du compte d'aujourd'hui (unix.rs, mod.rs).
        let attendu = if cfg!(windows) { Droits::Admin } else { Droits::Compte };
        for l in [
            "chmod 700 ~/.ssh",
            "chmod 750 ~",
            "chmod 600 ~/.aws/credentials",
            "chmod 700 ~/.gnupg",
            "chmod 600 ~/.config/rclone/rclone.conf",
            "chmod 600 ~/.ssh/'id_ed25519'",
            "chmod 600 ~/.ssh/'ma cle'",
            "chmod 600 ~/.ssh/'l'\\''autre'",
        ] {
            assert!(permise_au_compte(l), "{l:?}");
            assert_eq!(compte(l), attendu, "{l:?}");
        }
        assert_eq!(
            chemin_du_compte("~/.ssh/'l'\\''autre'").as_deref(),
            Some("~/.ssh/l'autre")
        );
        assert_eq!(
            chemin_du_compte(&format!("~/.ssh/{}", crate::commande::sh_chaine("a b'c"))).as_deref(),
            Some("~/.ssh/a b'c")
        );
        // Vérification de Fable n° 2, liens L1 : un nom écrit avec un caractère de remplacement (la trace d'un nom
        // qui n'était pas UTF-8) ne vise pas le fichier jugé : admin.
        assert_eq!(chemin_du_compte("~/.ssh/'id_\u{FFFD}'"), None);
        assert_eq!(compte("chmod 600 ~/.ssh/'id_\u{FFFD}'"), Droits::Admin);
        // Une ligne permise suivie d'une autre qui ne l'est pas : admin. Aucune ligne : admin aussi.
        assert_eq!(
            droits_effectifs(&correctif(Droits::Compte, &["chmod 700 ~/.ssh", "id"])),
            Droits::Admin
        );
        assert_eq!(droits_effectifs(&correctif(Droits::Compte, &[])), Droits::Admin);
        // Jamais vers moins de droits.
        assert_eq!(
            droits_effectifs(&correctif(Droits::Admin, &["chmod 700 ~/.ssh"])),
            Droits::Admin
        );
        assert_eq!(
            droits_effectifs(&correctif(Droits::Terminal, &["ssh-keygen -p -f x"])),
            Droits::Terminal
        );
    }

    /// Garde du code : chaque correction marquée « du compte » (`.du_compte()` en bout de chaîne) est dans une
    /// fonction qui ne nomme aucun élévateur jusque-là (`compte_sudo`, la garde du lot Unix). Le champ est posé à la
    /// main ; cet essai tient qu'on ne le pose pas sur une correction qui passerait par sudo.
    #[cfg(unix)]
    #[test]
    fn chaque_correction_du_compte_est_sans_elevateur() {
        use crate::commande::tests_sh_chaine::compte_sudo;
        fn fichiers(d: &std::path::Path, sortie: &mut Vec<std::path::PathBuf>) {
            for e in std::fs::read_dir(d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    fichiers(&p, sortie);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    sortie.push(p);
                }
            }
        }
        let mut tous = Vec::new();
        fichiers(
            std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src")),
            &mut tous,
        );
        let mut vus = 0;
        let mut fautes = Vec::new();
        for f in &tous {
            let texte = std::fs::read_to_string(f).unwrap();
            let lignes: Vec<&str> = texte.lines().collect();
            for (i, l) in lignes.iter().enumerate() {
                if !l.trim_start().starts_with(".du_compte()") {
                    continue;
                }
                vus += 1;
                // Le début de la fonction qui l'entoure : la dernière ligne `fn …` moins indentée que l'appel.
                let debut = (0..i)
                    .rev()
                    .find(|&j| {
                        let t = lignes[j].trim_start();
                        t.starts_with("fn ")
                            || t.starts_with("pub fn ")
                            || t.starts_with("pub(crate) fn ")
                            || t.starts_with("pub(super) fn ")
                    })
                    .unwrap_or_else(|| panic!("{}:{} : fonction introuvable", f.display(), i + 1));
                let morceau = lignes[debut..=i].join("\n");
                if compte_sudo(&morceau) != 0 {
                    fautes.push(format!("{}:{}", f.display(), i + 1));
                }
            }
        }
        assert!(
            fautes.is_empty(),
            "corrections « du compte » qui nomment un élévateur : {fautes:?}"
        );
        // Celles posées par ce lot (~/.ssh, clés, fichiers secrets, dossier personnel) : la garde lit bien quelque chose.
        assert!(vus >= 4, "{vus} corrections « du compte » lues");
        assert_eq!(
            compte_sudo("fn f() {\n    let c = \"sudo chmod 700 x\";\n    .du_compte()"),
            1
        );
    }

    /// L'aperçu d'un constat dont l'état d'avant se relève (un fichier jetable) : les valeurs relevées, montrées et
    /// liées à l'accord ; rien n'est écrit (aucune note d'annulation).
    #[cfg(unix)]
    #[test]
    fn l_apercu_montre_les_valeurs_d_avant_sans_rien_ecrire() {
        use std::os::unix::fs::PermissionsExt;
        let dossier = crate::socle::dossier_local();
        std::fs::create_dir_all(&dossier).unwrap();
        let fichier = dossier.join(format!("apercu-essai-{}", std::process::id()));
        std::fs::write(&fichier, "x").unwrap();
        std::fs::set_permissions(&fichier, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut k = correctif(Droits::Compte, &["chmod 600 ~/x"]);
        k.defaire = Defaire::Gestes(vec![crate::optimiser::Geste::droits(&fichier).unwrap()]);
        let c = constat("LNX-ESS-001", "x", Some(k));
        let j = Jeton::de("LNX-ESS-001", &c.cle().unwrap().to_string());
        // Les noms du dossier, sans les verrous : les essais voisins, qui tournent en même temps dans ce même dossier,
        // en prennent et en lâchent (`sceaux.verrou`). Le programme entier, lui, est relevé sans exception dans un
        // dossier personnel à lui (`voir_une_correction_n_ecrit_rien`, tests/programme.rs).
        let noms = || -> std::collections::BTreeSet<std::ffi::OsString> {
            std::fs::read_dir(&dossier)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .filter(|n| !n.to_string_lossy().ends_with(".verrou"))
                .collect()
        };
        let avant = noms();
        let a = apercu_de(&c, &j).unwrap();
        assert!(a.annulable, "{}", a.pourquoi_pas);
        assert_eq!(a.avant.len(), 1);
        assert!(
            a.avant[0].valeur.as_deref().is_some_and(|v| v.contains("644")),
            "{:?}",
            a.avant
        );
        assert_eq!(a.droits, "compte");
        assert_eq!(a.niveau, "Moyen");
        let apres = noms();
        assert!(
            apres.is_subset(&avant),
            "l'aperçu a écrit : {:?}",
            apres.difference(&avant)
        );
        // Le même état relu donne le même accord ; le fichier changé en donne un autre.
        assert_eq!(apercu_de(&c, &j).unwrap().accord(), a.accord());
        std::fs::set_permissions(&fichier, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_ne!(apercu_de(&c, &j).unwrap().accord(), a.accord());
        let _ = std::fs::remove_file(&fichier);
    }

    /// Les textes piégés du terminal (ceux des essais de `ui.rs`) ne passent pas tels quels dans l'aperçu au terminal :
    /// aucun caractère de contrôle, aucun bidi, et un saut de ligne n'ajoute pas de fausse ligne.
    #[test]
    fn l_apercu_au_terminal_ne_laisse_passer_aucun_piege() {
        let pieges = [
            "x\x1b[2K\recho rassurant",
            "a\n  \u{2714} Tout est propre",
            "b\x1b[1Ac",
            "d\u{202e}txt.exe",
            "\x1b]52;c;ZWNobyBwd24=\x07e",
            "f\u{9b}2Kg",
            // Vérification de Fable, T1 : une tabulation dans une commande.
            "h\t\t\t\tcache",
        ];
        for p in pieges {
            let mut a = apercu();
            a.message = p.into();
            a.action = p.into();
            a.categorie = p.into();
            a.niveau = p.into();
            a.commandes = vec![format!("chmod 700 '/home/alice/{p}'")];
            a.avant = vec![ValeurAvant {
                geste: format!("droits:/home/alice/{p}"),
                valeur: Some(p.into()),
            }];
            a.annulable = false;
            a.pourquoi_pas = p.into();
            let l = lignes(&a);
            // Les couleurs de Vanguard (ESC [ … m) sont les seules séquences permises.
            let sans_couleurs: Vec<String> = l
                .iter()
                .map(|t| {
                    [crate::ui::GRAS, crate::ui::GRIS, crate::ui::RESET]
                        .iter()
                        .fold(t.clone(), |t, c| t.replace(c, ""))
                })
                .collect();
            for t in &sans_couleurs {
                assert!(
                    !t.chars()
                        .any(|c| c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')),
                    "{p:?} : {t:?}"
                );
            }
            // Pas de ligne de plus que sans piège : un saut de ligne n'en fabrique pas une fausse.
            assert_eq!(l.len(), lignes(&apercu_non_annulable()).len(), "{p:?}");
        }
        // Une valeur absente et le texte « (absente) » ne se montrent pas pareil.
        let mut a = apercu();
        a.avant[0].valeur = None;
        let mut b = apercu();
        b.avant[0].valeur = Some("(absente)".into());
        assert_ne!(lignes(&a), lignes(&b));
    }

    /// Relit un texte de `montre_strict` : chaque marque n'a qu'un sens. Rend `None` pour une marque inconnue.
    fn relire_strict(montre: &str) -> Option<String> {
        let mut sortie = String::new();
        let mut it = montre.chars();
        while let Some(c) = it.next() {
            if c != '\\' {
                sortie.push(c);
                continue;
            }
            match it.next()? {
                '\\' => sortie.push('\\'),
                't' => sortie.push('\t'),
                'n' => sortie.push('\n'),
                'u' => {
                    if it.next()? != '{' {
                        return None;
                    }
                    let hex: String = it.by_ref().take_while(|&c| c != '}').collect();
                    sortie.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                }
                _ => return None,
            }
        }
        Some(sortie)
    }

    /// Vérification de Fable n° 2, P4 et P1 : une vraie tabulation et les deux caractères « \ » et « t » ne se montrent
    /// plus pareil ; un caractère qui ne dessine rien (sélecteur, marque combinante, caractère de format, caractère
    /// musical sans glyphe), une longue suite d'espaces ou une espace en bout de nom se voient ; le latin, les
    /// guillemets et les signes de Vanguard restent tels quels.
    #[test]
    fn le_terminal_montre_chaque_caractere_d_une_seule_facon() {
        assert_eq!(montre_strict("a\tb"), "a\\tb");
        assert_eq!(montre_strict("a\\tb"), "a\\\\tb");
        assert_ne!(montre_strict("a\tb"), montre_strict("a\\tb"));
        assert_eq!(montre_strict("a\nb"), "a\\nb");
        assert_eq!(montre_strict("id\u{fe0f}"), "id\\u{fe0f}");
        assert_eq!(montre_strict("e\u{301}"), "e\\u{301}");
        assert_eq!(montre_strict("x\u{1d173}y"), "x\\u{1d173}y");
        assert_eq!(montre_strict("x\u{200b}y"), "x\\u{200b}y");
        assert_eq!(montre_strict("\x1b[2K"), "\\u{1b}[2K");
        assert_eq!(montre_strict("soft\u{ad}"), "soft\\u{ad}");
        // Un « а » cyrillique ne passe pas pour un « a » latin.
        assert_eq!(montre_strict("id_rs\u{430}"), "id_rs\\u{430}");
        assert_eq!(
            montre_strict("a          b"),
            "a   \\u{20}\\u{20}\\u{20}\\u{20}\\u{20}\\u{20}\\u{20}b"
        );
        assert_eq!(montre_strict(" id "), "\\u{20}id\\u{20}");
        assert_eq!(montre_strict(" "), "\\u{20}");
        assert_eq!(montre_strict("a b  c   d"), "a b  c   d");
        let francais = "Été « clé » – œuvre … ✔ ⏎ ’ → ≤ ⚠ ✖ €";
        assert_eq!(montre_strict(francais), francais);
        assert_eq!(montre_strict(""), "");
    }

    /// Tout Unicode, caractère par caractère : ce qui se montre tel quel est un caractère qui se dessine sur une
    /// colonne, sans piège ni blanc caché ; tout le reste est une marque qui se relit d'une seule façon. Puis des
    /// textes faits de ces caractères : la relecture rend chaque fois le texte de départ, donc deux textes différents ne
    /// se montrent jamais pareil.
    #[test]
    fn le_terminal_ne_montre_que_des_caracteres_visibles_et_se_relit() {
        let mut gardes = 0usize;
        for c in (0..=0x0010_FFFF_u32).filter_map(char::from_u32) {
            let montre = montre_strict(&format!("a{c}a"));
            assert_eq!(
                relire_strict(&montre).as_deref(),
                Some(format!("a{c}a").as_str()),
                "{c:?}"
            );
            for m in montre.chars() {
                assert!(
                    m == ' '
                        || (crate::ui::rendu(m) == Some(m)
                            && !m.is_control()
                            && !m.is_whitespace()
                            && crate::ui::largeur_car(m) == 1),
                    "{c:?} montre {m:?}"
                );
            }
            if montre == format!("a{c}a") {
                gardes += 1;
            }
        }
        // La liste reste courte : 93 de l'ASCII visible (sans « \ »), 222 du latin, 21 signes, et l'espace.
        assert_eq!(gardes, 93 + 222 + 21 + 1);
        let briques = [
            " ",
            "  ",
            "\t",
            "\n",
            "\\",
            "\\t",
            "\\n",
            "\\u{20}",
            "\\u{",
            "}",
            "a",
            "é",
            "\u{fe0f}",
            "\u{301}",
            "\u{0}",
            "\u{7f}",
            "\u{ad}",
            "\u{a0}",
            "\u{3000}",
            "\u{202e}",
            "\u{10ffff}",
            "�",
            "«",
            "'",
        ];
        for x in briques {
            for y in briques {
                for z in briques {
                    let texte = format!("{x}{y}{z}");
                    assert_eq!(relire_strict(&montre_strict(&texte)), Some(texte.clone()), "{texte:?}");
                }
            }
        }
        for n in 0..12 {
            let texte = format!("{}x{}", " ".repeat(n), " ".repeat(n));
            assert_eq!(relire_strict(&montre_strict(&texte)), Some(texte.clone()), "{n}");
            assert!(!montre_strict(&texte).contains("    "), "{n}");
        }
    }

    /// De bout en bout dans l'aperçu : deux noms qui ne diffèrent que par un caractère invisible ou par « \t » contre
    /// une tabulation donnent des lignes différentes, dans la commande comme dans le relevé.
    #[test]
    fn deux_noms_differents_ne_se_montrent_jamais_pareil_au_terminal() {
        let avec = |nom: &str| {
            let mut a = apercu();
            a.commandes = vec![format!("chmod 600 '/home/alice/.ssh/{nom}'")];
            a.avant = vec![ValeurAvant {
                geste: format!("droits:/home/alice/.ssh/{nom}"),
                valeur: Some("644".into()),
            }];
            lignes(&a)
        };
        let paires = [
            ("id\tx", "id\\tx"),
            ("id_rsa", "id_rsa\u{fe0f}"),
            ("id_rsa", "id_r\u{200d}sa"),
            ("id_rsa", "id_rs\u{430}"),
            ("a b", "a     b"),
            ("id", "id "),
        ];
        for (x, y) in paires {
            let (lx, ly) = (avec(x), avec(y));
            assert_ne!(lx, ly, "{x:?} / {y:?}");
            let differentes = lx.iter().zip(&ly).filter(|(a, b)| a != b).count();
            // Au moins la commande et le relevé.
            assert!(differentes >= 2, "{x:?} / {y:?} : {differentes}");
        }
    }

    fn apercu_non_annulable() -> Apercu {
        let mut a = apercu();
        a.annulable = false;
        a.pourquoi_pas = "non".into();
        a
    }

    /// Sans gestes : non annulable, la raison dite et liée à l'accord.
    #[test]
    fn une_correction_sans_releve_dit_pourquoi_elle_ne_s_annule_pas() {
        let c = constat("LNX-ESS-001", "x", Some(correctif(Droits::Admin, &["x"])));
        let j = Jeton::de("LNX-ESS-001", &c.cle().unwrap().to_string());
        let a = apercu_de(&c, &j).unwrap();
        assert!(!a.annulable);
        assert_ne!(a.pourquoi_pas, "");
        assert_eq!(a.avant, Vec::new());
        assert_eq!(a.droits, "admin");
    }
}

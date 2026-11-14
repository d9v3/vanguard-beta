//! Le programme que lancent les tâches de Vanguard (surveillance horaire, entretien du mois, veilleur) : son chemin et
//! son empreinte BLAKE3, scellés (`sceau`) quand Vanguard pose la tâche ou met sa copie à jour.
//!
//! Pourquoi : une tâche était jugée sur l'existence seule de son programme. Une unité réécrite (ExecStart=, l'action
//! de la tâche planifiée, ProgramArguments de l'agent) qui lançait autre chose, ou la copie de cet ordinateur
//! remplacée, laissaient le bilan vert, et tout ce que la surveillance disait ensuite venait d'un autre programme. Le
//! bilan compare donc le chemin ET l'empreinte : un écart est une alerte ; ce qui ne se lit pas, ou un sceau qui ne
//! peut pas être cru, est « non vérifié », jamais sain.
//!
//! Le programme qui tourne se reconnaît lui-même : sous Linux, `/proc/self/exe` est l'image lancée, même si le
//! fichier a été remplacé depuis. Une tâche qui lance exactement ses octets lance Vanguard, quel que soit le sceau ;
//! le sceau est alors renoté, ce qui suit une mise à jour faite hors de Vanguard (gestionnaire de paquets, cargo) au
//! premier bilan de la nouvelle version. Ailleurs, le chemin du programme lancé peut désigner un fichier remplacé
//! depuis son lancement : seul le sceau compte.
//!
//! Le texte de la tâche (l'unité et sa minuterie, le XML de la tâche) est scellé aussi : changé hors de
//! Vanguard, c'est une alerte élevée, quoi qu'il change. Une tâche posée par une version d'avant, sans rien de noté,
//! est notée telle quelle au premier bilan (confiance au premier usage, comme `sceau`), jamais par-dessus une liste
//! qui ne peut pas être crue. Un programme remplacé par une version publiée et signée (l'historique signé des versions
//! le dit) est renoté et dit en information ; sans réponse de l'historique, il reste dit, jamais tu.
//!
//! Comme tout sceau : barrière, pas coffre. Un programme qui connaît ce mécanisme peut refaire le sceau ; un
//! programme remplacé qu'on lance soi-même n'est plus Vanguard, et rien de ce qu'il dit ne compte.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::machine::Constat;
use crate::modele::Echec;
use crate::risk::Niveau;
use crate::sceau::Lecture;
use crate::voulues::Doute;
use crate::{tr, trf};

/// L'état scellé des programmes posés, dans le dossier de données.
pub(crate) const FICHIER: &str = "programmes-planifies.json";

/// Au-delà, ce n'est pas le programme de Vanguard : il n'est pas lu en entier.
const TAILLE_MAX: u64 = 512 << 20;

/// Le contexte des échecs de la lecture d'une empreinte.
const OU_EMPREINTE: &str = "programmes_poses/empreinte";

/// Ce que Vanguard planifie et qui lance son programme sans personne devant l'écran.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tache {
    Surveillance,
    Entretien,
    Veilleur,
}

impl Tache {
    /// Son nom dans l'état : stable, jamais traduit.
    fn cle(self) -> &'static str {
        match self {
            Tache::Surveillance => "surveillance",
            Tache::Entretien => "entretien",
            Tache::Veilleur => "veilleur",
        }
    }

    fn dans_une_phrase(self) -> &'static str {
        match self {
            Tache::Surveillance => tr!("la surveillance horaire", "the hourly monitoring"),
            Tache::Entretien => tr!("l'entretien du mois", "the monthly check-up"),
            Tache::Veilleur => tr!("le veilleur", "the watcher"),
        }
    }

    /// La commande qui refait la tâche, et renote son programme.
    fn refaire(self) -> &'static str {
        match self {
            Tache::Surveillance => tr!("vanguard surveillance on", "vanguard monitor on"),
            Tache::Entretien => tr!("vanguard entretien on", "vanguard maintenance on"),
            Tache::Veilleur => tr!("vanguard veilleur on", "vanguard watcher on"),
        }
    }
}

/// Le programme posé pour une tâche.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct Pose {
    chemin: String,
    empreinte: String,
    /// L'empreinte BLAKE3 du texte de la tâche tel que Vanguard l'a posé (Linux : le service et sa minuterie ;
    /// Windows : le XML de la tâche). Le programme seul ne suffit pas : une ligne `ExecCondition=` ajoutée, une seconde
    /// `ExecStart=` ou une minuterie annuelle coupent la défense, ou lancent autre chose, sous son nom.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    texte: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
struct Fichier {
    #[serde(default)]
    taches: BTreeMap<String, Pose>,
    /// Les copies que Vanguard a lui-même posées (`copie_posee_ici` : depuis des octets vérifiés, ou une mise à jour signée)
    /// : chemin → empreinte BLAKE3 et version. Sans elles, une copie trouvée dans bin/ ne se distinguait pas d'un fichier
    /// posé là par un autre programme du compte, et `noter` la scellait comme celle de Vanguard.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    copies: BTreeMap<String, Copie>,
    /// R4-REGISTRE-1 : la liste a été réécrite par Vanguard par-dessus une liste qui ne pouvait pas être crue
    /// (effacée, abîmée ou réécrite hors de Vanguard alors qu'un sceau l'attendait). Ce qu'elle disait des copies est
    /// perdu : une copie plus récente y était peut-être notée. Tant que ce drapeau tient, aucune copie n'y est crue
    /// (`copie_notee_dans` rend le doute, `connue` rend faux) ; seule une pose À LA COPIE DE CET ORDINATEUR qui a passé
    /// la garde du registre (une clé prouvée la dernière version signée, ou cette version reçue de GitHub) le lève
    /// (`copie_posee_ici`). Une pose ailleurs (R5-REGISTRE-1 : un Vanguard mis à jour dans ~/Téléchargements) jamais.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    copies_douteuses: bool,
    /// Pareil pour les tâches : une tâche sans entrée n'est pas « posée par une version d'avant » (premier usage,
    /// renoté sans rien dire) mais non vérifiée, jusqu'à ce que Vanguard la repose.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    taches_douteuses: bool,
}

/// Une copie posée par Vanguard : son empreinte BLAKE3 et sa version gravée (« 0.94.0+1760900000 »). Sans la version
/// (R3-C1), rien ne pouvait dire qu'une copie plus récente avait été posée là une fois le fichier abîmé, effacé ou
/// rendu illisible, et la pose suivante depuis une clé plus ancienne revenait en arrière sans un mot. L'entrée d'avant,
/// l'empreinte seule (écrite par les compilations de ce lot avant la ronde 4, jamais par une version publiée), se lit
/// encore : sa version est inconnue, et elle est réécrite avec la version dès que Vanguard repose ou garde la copie.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
enum Copie {
    Notee {
        empreinte: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        version: Option<String>,
    },
    EmpreinteSeule(String),
}

impl Copie {
    fn empreinte(&self) -> &str {
        match self {
            Copie::Notee { empreinte, .. } | Copie::EmpreinteSeule(empreinte) => empreinte,
        }
    }

    fn version(&self) -> Option<&str> {
        match self {
            Copie::Notee { version, .. } => version.as_deref(),
            Copie::EmpreinteSeule(_) => None,
        }
    }
}

/// La copie que Vanguard a notée à un chemin (`copie_notee_dans`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CopieNotee {
    /// Son empreinte BLAKE3.
    pub(crate) empreinte: String,
    /// Sa version gravée, telle que notée (`None` : une entrée d'avant, sans version).
    pub(crate) version: Option<String>,
}

/// Scellé à la place d'une empreinte quand le programme posé n'a pas pu être reconnu comme celui de Vanguard : jamais
/// une empreinte BLAKE3 (64 chiffres hexadécimaux), donc jamais égal à un programme lu ; le bilan le dit non vérifié.
const NON_VERIFIE: &str = "non-verifie";

impl Fichier {
    /// Ce qui est noté pour la tâche `t` ; rien de noté dans une liste réécrite par-dessus un doute : non vérifié
    /// (`Doute::Herite`), jamais « premier usage ».
    fn tache(&self, t: Tache) -> Result<Option<&Pose>, Doute> {
        match self.taches.get(t.cle()) {
            None if self.taches_douteuses => Err(Doute::Herite),
            p => Ok(p),
        }
    }

    /// L'empreinte de la copie posée par Vanguard à `chemin`, si elle est notée.
    fn copie_posee(&self, chemin: &Path) -> Option<&str> {
        self.copie_a(chemin).map(Copie::empreinte)
    }

    fn copie_a(&self, chemin: &Path) -> Option<&Copie> {
        if self.copies_douteuses {
            return None;
        }
        self.copies
            .iter()
            .find(|(c, _)| meme_chemin(Path::new(c), chemin))
            .map(|(_, e)| e)
    }

    /// `empreinte` est-elle celle d'un programme que Vanguard a posé à `chemin` ? Seule la liste des copies compte
    /// (écrite par `copie_posee_ici`, après une pose depuis des octets vérifiés ou une mise à jour signée). Un sceau de
    /// tâche, lui, ne prouve pas une pose (R1-M1) : le bilan scelle au premier usage le programme de toute tâche qui
    /// n'a pas encore d'entrée, quel qu'il soit, et une unité posée par un autre programme du compte en aurait fait
    /// « une copie de Vanguard ».
    fn connue(&self, chemin: &Path, empreinte: &str) -> bool {
        empreinte != NON_VERIFIE && self.copie_posee(chemin) == Some(empreinte)
    }
}

/// `empreinte` est-elle celle d'un programme que Vanguard a posé à `cible` (voir `Fichier::connue`) ? Une liste qui ne
/// peut pas être crue ne connaît rien. `dossier` : celui du registre scellé (le dossier local, sauf aux essais).
pub(crate) fn copie_connue_dans(dossier: &Path, cible: &Path, empreinte: &str) -> bool {
    lire_dans(dossier).is_ok_and(|f| f.connue(cible, empreinte))
}

/// La copie que Vanguard a notée à `cible` dans le registre scellé de `dossier` (`None` : aucune). `Err` : la liste
/// ne peut pas être crue, rien de ce qu'elle dit ne compte.
pub(crate) fn copie_notee_dans(dossier: &Path, cible: &Path) -> Result<Option<CopieNotee>, Doute> {
    let f = lire_dans(dossier)?;
    if f.copies_douteuses {
        return Err(Doute::Herite);
    }
    Ok(f.copie_a(cible).map(|c| CopieNotee {
        empreinte: c.empreinte().to_string(),
        version: c.version().map(str::to_string),
    }))
}

/// L'empreinte BLAKE3 du programme `chemin`, lu en entier. Le lien est suivi (la tâche le suit aussi) ; ouvert sans
/// attendre puis jugé sur ce qui a été ouvert : un tube nommé posé à sa place ne fige pas le bilan.
pub(crate) fn empreinte_de(chemin: &Path) -> Result<String, Echec> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
    let f = options.open(chemin).map_err(|e| Echec::io(OU_EMPREINTE, &e))?;
    empreinte_du_fichier(&f)
}

/// L'empreinte du fichier déjà ouvert `f`, lue depuis sa poignée (pas par un chemin qu'on pourrait changer entre
/// l'ouverture et la lecture) : un simple fichier, de taille raisonnable.
pub(crate) fn empreinte_du_fichier(f: &std::fs::File) -> Result<String, Echec> {
    let m = f.metadata().map_err(|e| Echec::io(OU_EMPREINTE, &e))?;
    if !m.is_file() {
        return Err(Echec::refuse(
            OU_EMPREINTE,
            tr!("pas un simple fichier", "not a plain file"),
        ));
    }
    if m.len() > TAILLE_MAX {
        return Err(Echec::refuse(OU_EMPREINTE, tr!("fichier démesuré", "oversized file")));
    }
    let mut h = blake3::Hasher::new();
    h.update_reader(std::io::Read::take(f, TAILLE_MAX))
        .map_err(|e| Echec::io(OU_EMPREINTE, &e))?;
    Ok(h.finalize().to_hex().to_string())
}

/// L'empreinte de l'image du programme qui tourne (Linux seulement, voir l'en-tête), lue une fois. Jamais pendant
/// les tests : le programme des essais n'est pas Vanguard.
pub(crate) fn soi() -> Option<&'static str> {
    static SOI: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    if cfg!(test) || !cfg!(target_os = "linux") {
        return None;
    }
    SOI.get_or_init(|| empreinte_de(Path::new("/proc/self/exe")).ok())
        .as_deref()
}

fn lire_dans(dossier: &Path) -> Result<Fichier, Doute> {
    let octets = match crate::sceau::lire_dans(dossier, FICHIER) {
        Lecture::Absent => return Ok(Fichier::default()),
        Lecture::Intact(o) => o,
        // Né scellé : jamais écrit sans sceau par une version d'avant. Accepté tel quel, c'est que sceaux.json a
        // disparu, refait ou pas (tout effacer d'un coup ne laisse pas de témoin).
        Lecture::Adopte(_) => return Err(Doute::Adopte),
        Lecture::Falsifie(_) => return Err(Doute::HorsVanguard),
        Lecture::Inconnu => return Err(Doute::Inconnu),
        Lecture::Illisible(_) => return Err(Doute::Illisible),
    };
    serde_json::from_slice(&octets).map_err(|_| Doute::Illisible)
}

/// L'empreinte d'un texte de tâche lu.
fn empreinte_texte(texte: &std::io::Result<Vec<u8>>) -> std::io::Result<String> {
    match texte {
        Ok(o) => Ok(blake3::hash(o).to_hex().to_string()),
        Err(e) => Err(std::io::Error::new(e.kind(), e.to_string())),
    }
}

/// Réécrit l'état. Un état qui ne pouvait pas être cru n'est jamais rescellé à neuf (R4-REGISTRE-1) : ce qu'il disait
/// n'est pas recopié, et le doute l'est (`copies_douteuses`, `taches_douteuses`) : les autres tâches se diront non
/// vérifiées, et aucune copie n'y sera crue, plutôt que « rien de noté ».
fn changer_dans(dossier: &Path, changer: impl FnOnce(&mut Fichier) -> bool) -> std::io::Result<()> {
    let mut f = lire_dans(dossier).unwrap_or_else(|_| Fichier {
        copies_douteuses: true,
        taches_douteuses: true,
        ..Fichier::default()
    });
    if !changer(&mut f) {
        return Ok(());
    }
    let octets = serde_json::to_vec_pretty(&f).map_err(std::io::Error::other)?;
    crate::sceau::ecrire_dans(dossier, FICHIER, &octets)
}

fn retenir_dans(
    dossier: &Path,
    t: Tache,
    chemin: &Path,
    empreinte: String,
    texte: Option<String>,
) -> std::io::Result<()> {
    let pose = Pose {
        chemin: chemin.display().to_string(),
        empreinte,
        texte,
    };
    changer_dans(dossier, |f| {
        f.taches.insert(t.cle().to_string(), pose.clone()) != Some(pose)
    })
}

/// Ce qui est scellé pour une tâche que Vanguard vient de poser : l'empreinte lue à `chemin`, sauf si le programme qui
/// tourne se connaît (`soi`) et n'a pas ces octets alors que `chemin` n'est pas la copie de cet ordinateur. Vanguard
/// pose alors ce programme-ci : un fichier changé entre la pose et sa lecture, ou un chemin d'origine soufflé par une
/// variable d'environnement du compte (`VANGUARD_ORIGINE`), n'est jamais scellé comme le sien ; il se dira remplacé.
///
/// La copie de cet ordinateur (`copie`) peut être une version plus récente gardée (`mise_a_jour::poser_copie`) ; mais
/// le fichier qui s'y trouve a pu être posé par un autre programme du compte, ou échangé depuis la pose. Ses octets ne
/// sont scellés que s'ils sont ceux du programme qui tourne (`image`) ou de la copie que Vanguard y a posée (la
/// liste des copies de `poses` ; un sceau de tâche ne compte pas). Sinon : l'empreinte de la copie posée par Vanguard s'il y en a une (le fichier
/// se dira remplacé), et à défaut rien qui le vaille (`NON_VERIFIE`, dit non vérifié), jamais ces octets-là.
fn a_sceller(
    chemin: &Path,
    lu: String,
    soi: Option<&str>,
    image: Option<&str>,
    copie: &Path,
    poses: Option<&Fichier>,
) -> String {
    if !meme_chemin(chemin, copie) {
        return match soi {
            Some(s) if s != lu => s.to_string(),
            _ => lu,
        };
    }
    if image == Some(lu.as_str()) || poses.is_some_and(|f| f.connue(copie, &lu)) {
        return lu;
    }
    poses
        .and_then(|f| f.copie_posee(copie))
        .unwrap_or(NON_VERIFIE)
        .to_string()
}

/// Vanguard vient de poser la tâche `t`, qui lance `chemin`, et dont le texte posé est `texte` : leurs empreintes
/// sont scellées. Un nom sans chemin (le programme ne s'est pas situé) n'a rien à sceller : le bilan le dit non
/// vérifié.
pub(crate) fn noter(t: Tache, chemin: &Path, texte: &std::io::Result<Vec<u8>>) {
    noter_dans(&crate::socle::dossier_local(), t, chemin, texte);
}

/// `noter` dans le registre de `dossier`.
pub(crate) fn noter_dans(dossier: &Path, t: Tache, chemin: &Path, texte: &std::io::Result<Vec<u8>>) {
    if !chemin.is_absolute() {
        return;
    }
    let copie = crate::mise_a_jour::copie_de_cet_ordinateur();
    let poses = lire_dans(dossier).ok();
    // L'image qui tourne compte aussi sous Windows pour la copie (le fichier tenu au départ) ; `soi` reste celle de
    // Linux pour le reste, comme le bilan.
    let image = crate::protection::cle::image_qui_tourne();
    let r = empreinte_de(chemin).map_err(std::io::Error::other).and_then(|lu| {
        retenir_dans(
            dossier,
            t,
            chemin,
            a_sceller(chemin, lu, soi(), image.as_deref(), &copie, poses.as_ref()),
            empreinte_texte(texte).ok(),
        )
    });
    if let Err(e) = r {
        crate::modele::Echec::echoue("programmes_poses/noter", e.to_string()).journaliser();
    }
}

/// Le chemin posé pour la tâche `t`, s'il est noté (et la liste crue).
pub(crate) fn chemin_pose(t: Tache) -> Option<String> {
    lire_dans(&crate::socle::dossier_local())
        .ok()?
        .taches
        .get(t.cle())
        .map(|p| p.chemin.clone())
}

pub(crate) fn oublier_dans(dossier: &Path, t: Tache) {
    let _ = changer_dans(dossier, |f| f.taches.remove(t.cle()).is_some());
}

/// Vanguard a retiré la tâche `t`.
pub(crate) fn oublier(t: Tache) {
    oublier_dans(&crate::socle::dossier_local(), t);
}

/// `copie_posee_ici` quand `cible` est la copie de cet ordinateur (essais, et la copie gardée par `poser_copie_dans`).
pub(crate) fn copie_posee_dans(dossier: &Path, cible: &Path, octets: &[u8]) -> Vec<Tache> {
    copie_posee_ici(dossier, cible, octets, cible)
}

/// Vanguard vient de mettre `octets` à la place de `cible` (sa copie de cet ordinateur `ici`, ou un autre programme
/// mis à jour depuis GitHub) : chaque tâche qui la lance garde un sceau juste. Rend les tâches concernées. Lève le
/// doute sur les copies (`copies_douteuses`) seulement si `cible` est la copie `ici` : n'y mènent que les poses qui
/// ont passé la garde du registre (`mise_a_jour::retour_en_arriere`, sortie prouvée par `sortie_du_doute`) et la
/// dernière version signée reçue de GitHub ; les copies d'avant le doute, jamais crues, sont oubliées. Une pose à un
/// autre chemin (R5-REGISTRE-1) n'a rien prouvé pour la copie : le doute reste.
pub(crate) fn copie_posee_ici(dossier: &Path, cible: &Path, octets: &[u8], ici: &Path) -> Vec<Tache> {
    let empreinte = blake3::hash(octets).to_hex().to_string();
    let copie = Copie::Notee {
        empreinte: empreinte.clone(),
        version: crate::mise_a_jour::version_notee(octets),
    };
    let mut touchees = Vec::new();
    let r = changer_dans(dossier, |f| {
        let levee = meme_chemin(cible, ici) && std::mem::take(&mut f.copies_douteuses);
        if levee {
            f.copies.clear();
        }
        // Une entrée d'avant (sans version) est réécrite avec elle ; sous le doute, toujours (rien n'y est lu).
        let copie_changee = levee || f.copies_douteuses || f.copie_a(cible) != Some(&copie);
        if copie_changee {
            f.copies.retain(|c, _| !meme_chemin(Path::new(c), cible));
            f.copies.insert(cible.display().to_string(), copie.clone());
        }
        for t in [Tache::Surveillance, Tache::Entretien, Tache::Veilleur] {
            if let Some(p) = f.taches.get_mut(t.cle())
                && meme_chemin(Path::new(&p.chemin), cible)
                && p.empreinte != empreinte
            {
                p.empreinte.clone_from(&empreinte);
                touchees.push(t);
            }
        }
        copie_changee || !touchees.is_empty()
    });
    // R4-REGISTRE-6 : la copie n'a pas pu être notée (disque plein, dossier refusé) ; dit au journal, jamais tu.
    if let Err(e) = r {
        Echec::echoue("programmes_poses/noter", e.to_string()).journaliser();
    }
    touchees
}

/// Deux chemins du même programme : sous Windows, sans « \\?\ » ni casse ; ailleurs tels quels, puis canoniques.
pub(crate) fn meme_chemin(a: &Path, b: &Path) -> bool {
    if cfg!(windows) {
        let court = |p: &Path| {
            crate::reseau::surveillance::sans_verbatim(p)
                .display()
                .to_string()
                .to_lowercase()
        };
        return court(a) == court(b);
    }
    a == b || matches!((a.canonicalize(), b.canonicalize()), (Ok(x), Ok(y)) if x == y)
}

/// Le jugement du programme qu'une tâche lance.
#[derive(Debug, PartialEq, Eq)]
enum Jugement {
    /// Le programme que Vanguard a posé, tel qu'il l'a posé, et la tâche telle qu'il l'a posée.
    Sain,
    /// Au bon chemin, les octets du programme qui tourne (Vanguard lui-même, mis à jour) : l'empreinte est renotée.
    Soi,
    /// Rien de noté pour cette tâche (posée par une version d'avant) : notée telle quelle, premier usage.
    Premier,
    /// Un autre chemin que celui que Vanguard a posé.
    AutreChemin(String),
    /// Le chemin posé, mais d'autres octets.
    Remplace,
    /// Le texte de la tâche (unité, minuterie, XML) n'est plus celui que Vanguard a posé.
    TexteChange,
    /// La liste des programmes posés a été changée hors de Vanguard, et le programme lancé n'est pas celui qui tourne.
    ListeForgee,
    NonVerifie(String),
}

/// Le jugement, sans rien lire : le programme lancé, son empreinte lue, ce que le sceau dit de la tâche,
/// l'empreinte du programme qui tourne quand elle se connaît, et l'empreinte du texte de la tâche lu.
fn juger(
    programme: &Path,
    lu: &Result<String, Echec>,
    pose: Result<Option<&Pose>, Doute>,
    soi: Option<&str>,
    texte: &std::io::Result<String>,
) -> Jugement {
    let lu = match lu {
        Ok(l) => l,
        Err(e) => {
            return Jugement::NonVerifie(trf!(
                "son programme ne se lit pas : {e}",
                "its program cannot be read: {e}"
            ));
        }
    };
    let soi_ok = soi == Some(lu.as_str());
    let p = match pose {
        // La liste changée hors de Vanguard est une écriture étrangère prouvée : un programme lancé qui n'est pas
        // celui qui tourne ne se croit pas.
        Err(Doute::HorsVanguard) if soi.is_some() && !soi_ok => return Jugement::ListeForgee,
        Err(d) => {
            return Jugement::NonVerifie(trf!(
                "la liste des programmes posés par Vanguard {}",
                "the list of programs placed by Vanguard {}",
                d.texte()
            ));
        }
        Ok(None) => return Jugement::Premier,
        Ok(Some(p)) => p,
    };
    // Le chemin d'abord : même aux octets du programme qui tourne, une copie ailleurs n'est pas ce que Vanguard a
    // posé (« vanguard surveillance on » est la seule voie pour en changer).
    if !meme_chemin(Path::new(&p.chemin), programme) {
        return Jugement::AutreChemin(p.chemin.clone());
    }
    // Rien de vérifié n'a été scellé à la pose (`a_sceller`) : ni sain, ni « remplacé » (rien ne dit ce qu'il y avait).
    if p.empreinte == NON_VERIFIE && !soi_ok {
        return Jugement::NonVerifie(
            tr!(
                "quand Vanguard a posé la tâche, ce fichier n'était ni le programme qui tourne ni une copie posée par Vanguard",
                "when Vanguard set up the task, this file was neither the running program nor a copy placed by Vanguard"
            )
            .to_string(),
        );
    }
    if p.empreinte != *lu && !soi_ok {
        return Jugement::Remplace;
    }
    match (&p.texte, texte) {
        (Some(h), Ok(t)) if h != t => return Jugement::TexteChange,
        (Some(_), Ok(_)) => {}
        (Some(_), Err(e)) => {
            return Jugement::NonVerifie(trf!("sa tâche ne se lit pas : {e}", "its task cannot be read: {e}"));
        }
        (None, _) => {
            return Jugement::NonVerifie(
                tr!(
                    "le texte de sa tâche n'a pas été noté quand Vanguard l'a posée",
                    "the text of its task was not noted when Vanguard set it up"
                )
                .to_string(),
            );
        }
    }
    if p.empreinte == *lu {
        Jugement::Sain
    } else {
        Jugement::Soi
    }
}

/// Le programme remplacé est-il une version publiée et signée ? Seulement pour un programme qui n'est plus celui
/// noté : ce qu'en dit l'historique signé des versions (rien de cet ordinateur ne part).
#[derive(Debug, PartialEq, Eq)]
enum Signee {
    Oui(String),
    /// Publiée et signée, mais plus ancienne que ce Vanguard (R3-C7) : un retour en arrière, jamais renoté comme une
    /// mise à jour.
    Ancienne(String),
    Non,
    /// L'historique n'a pas répondu (hors ligne, pas encore publié) : la raison.
    Inconnu(String),
}

/// Ce que l'historique signé dit d'une empreinte (le type de `mise_a_jour::version_signee`, qui n'est pas changé ici).
type VueSignee = Result<Option<(String, String)>, String>;

/// `vue` : l'historique signé interrogé par l'empreinte SHA-256 du programme (`mise_a_jour::version_signee`, sauf
/// aux essais) ; `dossier` : celui du registre scellé.
fn signee_dans(dossier: &Path, programme: &Path, vue: impl FnOnce(&[u8; 32]) -> VueSignee) -> Signee {
    let Some(sha) = crate::protection::empreintes::sha256(programme) else {
        return Signee::Inconnu(tr!("programme illisible", "unreadable program").to_string());
    };
    // R4-REGISTRE-2 : la version notée pour cette copie compte aussi.
    let notee = copie_notee_dans(dossier, programme);
    let version = notee.as_ref().ok().cloned().flatten().and_then(|c| c.version);
    sous_doute(classer(vue(&sha), version.as_deref()), notee.err())
}

/// R5-REGISTRE-4 : une liste des copies en doute a perdu la version notée ; une version signée n'y est donc jamais
/// crue « au moins aussi récente » (`Oui`, renotée sans rien dire) : non vérifiée, dite à chaque bilan.
fn sous_doute(s: Signee, doute: Option<Doute>) -> Signee {
    match (s, doute) {
        (Signee::Oui(_), Some(d)) => Signee::Inconnu(trf!(
            "la liste des copies posées par Vanguard {}",
            "the list of copies set up by Vanguard {}",
            d.texte()
        )),
        (s, _) => s,
    }
}

/// Ce que dit l'historique signé d'un programme remplacé. Une version signée plus ancienne que ce Vanguard, ou que la
/// version notée pour cette copie (`notee`, R4-REGISTRE-2), n'est pas une mise à jour : un programme du compte peut y
/// remettre une ancienne version authentique, aux défauts connus.
fn classer(vue: Result<Option<(String, String)>, String>, notee: Option<&str>) -> Signee {
    let ancienne = |v: &str| {
        crate::mise_a_jour::plus_ancienne_que_ce_programme(v)
            || notee.is_some_and(|n| crate::mise_a_jour::plus_ancienne_que(v, n))
    };
    match vue {
        Ok(Some((v, _))) if ancienne(&v) => Signee::Ancienne(v),
        Ok(Some((v, _))) => Signee::Oui(v),
        Ok(None) => Signee::Non,
        Err(e) => Signee::Inconnu(e),
    }
}

/// Le constat d'un jugement : rien quand c'est Vanguard ; une alerte élevée pour un autre programme ou une tâche
/// changée ; une information pour une version signée posée hors de Vanguard ; « non vérifié » sinon. `signee` : ce
/// que l'historique signé dit d'un programme remplacé.
fn constat_de(t: Tache, programme: &Path, j: &Jugement, signee: Option<&Signee>) -> Option<Constat> {
    const CAT: &str = "Surveillance";
    let tache = t.dans_une_phrase();
    // En tête de phrase : « Le veilleur lance… », pas « le veilleur lance… ».
    let tache_debut: String = tache
        .chars()
        .take(1)
        .flat_map(char::to_uppercase)
        .chain(tache.chars().skip(1))
        .collect();
    let chemin = crate::ui::chemin_affichable(programme);
    let remettre = || {
        trf!(
            "Si c'est vous qui l'avez changé : « {} » refait la tâche et note son programme ; sinon, regardez ce qui tourne sous votre compte (Protection › Qui parle à Internet ?)",
            "If you changed it yourself: “{}” redoes the task and notes its program; otherwise, look at what runs under your account (Protection › Who talks to the Internet?)",
            t.refaire()
        )
    };
    let eleve = |texte: String| Some(crate::machine::alerte(CAT, Niveau::Eleve, texte).manuel(remettre(), &[]));
    // Lot D7b, « Refaire » : le programme lui-même n'est plus celui de Vanguard ; un programme publié et signé peut
    // y être remis par root, celui qui y est mis en quarantaine. Une tâche qui lance un autre chemin, ou dont le texte
    // a changé, se refait par la tâche : remettre le programme n'y changerait rien.
    let refaire = |c: Option<Constat>| c.map(|c| remis(c, t, programme));
    match j {
        Jugement::Sain | Jugement::Soi | Jugement::Premier => None,
        Jugement::AutreChemin(pose) => eleve(trf!(
            "{tache_debut} lance un autre programme que celui que Vanguard a posé : {chemin}, au lieu de {}. Un logiciel malveillant peut s'y faire passer pour Vanguard.",
            "{tache_debut} starts a different program from the one Vanguard placed: {chemin}, instead of {}. Malware can pass itself off as Vanguard there.",
            crate::ui::chemin_affichable(Path::new(pose))
        )),
        Jugement::Remplace => match signee {
            Some(Signee::Oui(v)) => Some(crate::machine::alerte(
                CAT,
                Niveau::Info,
                trf!(
                    "Le programme que lance {tache} ({chemin}) a été mis à jour hors de Vanguard, vers la version {v}, publiée et signée par l'auteur : Vanguard l'a noté.",
                    "The program {tache} starts ({chemin}) was updated outside Vanguard, to version {v}, published and signed by the author: Vanguard noted it."
                ),
            )),
            Some(Signee::Ancienne(v)) => refaire(Some(
                crate::machine::alerte(
                    CAT,
                    Niveau::Moyen,
                    trf!(
                        "Le programme que lance {tache} ({chemin}) a été remplacé hors de Vanguard par la version {v}, publiée et signée par l'auteur, mais plus ancienne que ce Vanguard ({}) : un retour en arrière, que Vanguard ne note pas. Une version plus ancienne peut avoir des défauts corrigés depuis.",
                        "The program {tache} starts ({chemin}) was replaced outside Vanguard by version {v}, published and signed by the author, but older than this Vanguard ({}): a rollback, which Vanguard does not note. An older version may have flaws fixed since.",
                        env!("CARGO_PKG_VERSION")
                    ),
                )
                .manuel(remettre(), &[]),
            )),
            Some(Signee::Inconnu(e)) => refaire(Some(
                crate::machine::Constat {
                    verifie: false,
                    ..crate::machine::alerte(
                        CAT,
                        Niveau::Moyen,
                        trf!(
                            "Le programme que lance {tache} ({chemin}) a été remplacé hors de Vanguard, et l'historique signé des versions n'a pas pu dire si c'est une version publiée ({e}) : non vérifié.",
                            "The program {tache} starts ({chemin}) was replaced outside Vanguard, and the signed version history could not tell whether it is a published version ({e}): not checked."
                        ),
                    )
                }
                .manuel(remettre(), &[]),
            )),
            Some(Signee::Non) | None => refaire(eleve(trf!(
                "Le programme que lance {tache} ({chemin}) a été remplacé hors de Vanguard : ce ne sont plus les octets que Vanguard a posés, ni une version publiée et signée. Ce qu'il fait et dit ne vient peut-être plus de Vanguard.",
                "The program {tache} starts ({chemin}) was replaced outside Vanguard: these are no longer the bytes Vanguard placed, nor a published and signed version. What it does and says may no longer come from Vanguard."
            ))),
        },
        Jugement::TexteChange => eleve(trf!(
            "La tâche posée pour {tache} a été changée hors de Vanguard : ce n'est plus celle que Vanguard a posée (un programme lancé en plus, une heure changée, une condition qui la fait sauter…). Un logiciel malveillant peut s'en servir pour la couper ou lancer autre chose sous son nom.",
            "The task of {tache} was changed outside Vanguard: it is no longer the one Vanguard set up (an extra program started, a changed schedule, a condition that skips it…). Malware can use this to switch it off or run something else under its name."
        )),
        Jugement::ListeForgee => refaire(eleve(trf!(
            "La liste des programmes posés par Vanguard a été changée hors de Vanguard, et {tache} lance un programme qui n'est pas ce Vanguard-ci ({chemin}).",
            "The list of programs placed by Vanguard was changed outside Vanguard, and {tache} starts a program that is not this Vanguard ({chemin})."
        ))),
        Jugement::NonVerifie(raison) => refaire(Some(
            crate::machine::impossible(
                CAT,
                &trf!(
                    "programme lancé par {tache} ({chemin}) non vérifié : {raison}",
                    "program started by {tache} ({chemin}) not checked: {raison}"
                ),
            )
            .manuel(
                trf!(
                    "« {} » refait la tâche et note son programme",
                    "“{}” redoes the task and notes its program",
                    t.refaire()
                ),
                &[],
            ),
        )),
    }
}

/// Le constat `c`, avec le geste « Refaire » de Linux quand le programme se désigne (`defense::remettre_programme`) :
/// remettre un programme publié et signé, celui qui y est en quarantaine, non annulable. Sinon `c` tel quel.
fn remis(c: Constat, t: Tache, programme: &Path) -> Constat {
    #[cfg(target_os = "linux")]
    if let Some(g) = crate::machine::defense::remettre_programme(programme) {
        return crate::machine::defense::corriger_sans_defaire(
            c,
            trf!(
                "Remettre le programme de Vanguard publié et signé par l'auteur (signature Ed25519 vérifiée) ; celui qui y est va en quarantaine dans /var/lib/vanguard/quarantaine (non annulable). Si c'est vous qui l'avez changé : « {} » refait la tâche",
                "Put back the Vanguard program published and signed by the author (Ed25519 signature checked); the one there goes to quarantine in /var/lib/vanguard/quarantaine (cannot be undone). If you changed it yourself: “{}” redoes the task",
                t.refaire()
            ),
            &[g],
        );
    }
    let _ = (t, programme);
    c
}

/// Le constat d'une tâche qui lance `programme` (un nom sans chemin, que rien d'ici ne situe) alors que Vanguard a posé
/// `pose` : un autre programme, dit en élevé.
pub(crate) fn autre_chemin(t: Tache, programme: &Path, pose: &str) -> Constat {
    constat_de(t, programme, &Jugement::AutreChemin(pose.to_string()), None)
        .unwrap_or_else(|| crate::machine::impossible("Surveillance", pose))
}

/// L'empreinte notée pour la tâche `t` dans le registre de `dossier` (essais d'autres modules).
#[cfg(test)]
pub(crate) fn empreinte_notee_dans(dossier: &Path, t: Tache) -> Option<String> {
    lire_dans(dossier)
        .ok()?
        .taches
        .get(t.cle())
        .map(|p| p.empreinte.clone())
}

/// Au bilan : le programme que lance la tâche `t`, et le texte de la tâche (`texte`, lu par l'appelant), sont-ils
/// ceux que Vanguard a posés ? Rien s'ils le sont. Renoté sans rien dire : le programme qui tourne au bon chemin
/// (une mise à jour par paquet), une tâche posée par une version d'avant (premier usage) ; une version signée posée
/// hors de Vanguard, dite. Jamais par-dessus une liste qui ne peut pas être crue : la réécrire effacerait ce doute
/// pour les autres tâches.
pub(crate) fn constat(t: Tache, programme: &Path, texte: &std::io::Result<Vec<u8>>) -> Option<Constat> {
    let dossier = crate::socle::dossier_local();
    constat_dans(&dossier, t, programme, texte, soi(), |p| {
        signee_dans(&dossier, p, crate::mise_a_jour::version_signee)
    })
}

/// `constat` sur le registre de `dossier`, avec `soi` et l'historique (`signee`) donnés : les essais jugent par le
/// même chemin que le bilan (R5-ESSAIS-1), jamais par une recopie de son branchement.
fn constat_dans(
    dossier: &Path,
    t: Tache,
    programme: &Path,
    texte: &std::io::Result<Vec<u8>>,
    soi: Option<&str>,
    signee: impl FnOnce(&Path) -> Signee,
) -> Option<Constat> {
    let lu = empreinte_de(programme);
    let texte = empreinte_texte(texte);
    let poses = lire_dans(dossier);
    let pose = poses.as_ref().map_err(|d| *d).and_then(|f| f.tache(t));
    let ancien_texte = pose.as_ref().ok().and_then(|p| p.and_then(|p| p.texte.clone()));
    let j = juger(programme, &lu, pose, soi, &texte);
    let signe = (j == Jugement::Remplace).then(|| signee(programme));
    let renoter = a_renoter(&j, signe.as_ref(), ancien_texte, texte.ok());
    if let (Some(Renoter(texte)), Ok(e)) = (renoter, &lu) {
        let _ = retenir_dans(dossier, t, programme, e.clone(), texte);
    }
    constat_de(t, programme, &j, signe.as_ref())
}

/// Un sceau de tâche à renoter, avec ce texte de tâche (s'il y en a un).
#[derive(Debug, PartialEq)]
struct Renoter(Option<String>);

/// Le texte de tâche à renoter avec le programme lu (`Some`), ou rien à renoter (`None`) : le programme qui tourne au
/// bon chemin et une version signée au moins aussi récente que ce Vanguard gardent le texte noté (`ancien`) ; le
/// premier usage note le texte lu (`lu`). Jamais une version signée plus ancienne (`Signee::Ancienne`, R3-C7) : un
/// retour en arrière n'est pas renoté comme une mise à jour, il reste dit à chaque bilan.
fn a_renoter(j: &Jugement, signe: Option<&Signee>, ancien: Option<String>, lu: Option<String>) -> Option<Renoter> {
    match (j, signe) {
        (Jugement::Soi, _) | (Jugement::Remplace, Some(Signee::Oui(_))) => Some(Renoter(ancien)),
        (Jugement::Premier, _) => Some(Renoter(lu)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn jetable(nom: &str) -> PathBuf {
        let d = crate::essais::temporaire().join(format!("vanguard-poses-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Un faux programme dans le dossier jetable, et son chemin.
    fn programme(d: &Path, octets: &[u8]) -> PathBuf {
        let p = d.join("bin-vanguard");
        std::fs::write(&p, octets).unwrap();
        p
    }

    const UNITE: &[u8] = b"[Service]\nExecStart=\"/x/vanguard\" surveiller\n";

    /// Le temps de calcul de ce fil seul : celui des autres programmes de la machine n'y entre pas.
    #[cfg(unix)]
    // FFI de libc : std n'a pas d'horloge du temps de calcul d'un fil.
    #[allow(unsafe_code)]
    fn calcul_du_fil() -> std::time::Duration {
        let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: clock_gettime écrit dans `t`, qui vit le temps de l'appel, et n'en garde rien.
        let rendu = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &raw mut t) };
        assert_eq!(rendu, 0);
        std::time::Duration::new(u64::try_from(t.tv_sec).unwrap(), u32::try_from(t.tv_nsec).unwrap())
    }

    /// L'empreinte d'une copie de Vanguard (copie_posee_dans, relue après chaque mise à jour) se calcule vite même
    /// dans un programme de développement ou de test : sans optimisation, BLAKE3 n'avançait qu'à 17 Mo/s, et le
    /// programme de test (325 Mo) demandait une vingtaine de secondes de calcul ; avec la suite de tests autour, la
    /// mise à jour depuis la clé dépassait la minute (tests/programme.rs, mise_a_jour_depuis_la_cle). Compté en temps
    /// de calcul du fil, pas en temps écoulé : une machine chargée ne fait pas échouer l'essai. Mesuré le 11 nov.
    /// 2026 pour 64 Mio : 3,9 s sans optimisation, 0,02 s optimisée (Cargo.toml, profile.dev.package.blake3). Le
    /// seuil d'une seconde garde près de quatre fois d'écart avec l'oubli de l'optimisation, et de la marge pour une
    /// machine sans AVX2 (SSE4.1 seul, ou le code portable de BLAKE3, plusieurs fois plus lents) : celui d'un quart de
    /// seconde n'en laissait presque pas (vérification 0.94, S-5).
    #[cfg(unix)]
    #[test]
    fn empreinte_d_une_copie_rapide_meme_en_developpement() {
        let octets = vec![0x5au8; 64 << 20];
        let debut = calcul_du_fil();
        let empreinte = blake3::hash(&octets);
        let duree = calcul_du_fil().checked_sub(debut).unwrap().as_secs_f64();
        assert_ne!(empreinte, blake3::hash(b""));
        assert!(
            duree < 1.0,
            "BLAKE3 : {duree:.2} s de calcul pour 64 Mio (Cargo.toml, profile.dev.package.blake3)"
        );
    }

    fn texte(o: &[u8]) -> std::io::Result<String> {
        empreinte_texte(&Ok(o.to_vec()))
    }

    /// Pose la tâche `t` comme `noter` (sans `soi` : les essais ne sont pas Vanguard).
    fn poser(d: &Path, t: Tache, p: &Path) {
        retenir_dans(d, t, p, empreinte_de(p).unwrap(), texte(UNITE).ok()).unwrap();
    }

    fn juger_dans(d: &Path, t: Tache, p: &Path, soi: Option<&str>, unite: &[u8]) -> Jugement {
        let lu = empreinte_de(p);
        let f = lire_dans(d);
        juger(
            p,
            &lu,
            f.as_ref().map_err(|x| *x).and_then(|f| f.tache(t)),
            soi,
            &texte(unite),
        )
    }

    #[test]
    fn empreinte_d_un_fichier() {
        let d = jetable("empreinte");
        let p = programme(&d, b"vanguard 1");
        assert_eq!(
            empreinte_de(&p).unwrap(),
            blake3::hash(b"vanguard 1").to_hex().to_string()
        );
        assert!(empreinte_de(&d).is_err(), "un dossier n'est pas un programme");
        assert!(empreinte_de(&d.join("absent")).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn programme_pose_puis_remplace() {
        let d = jetable("remplace");
        let p = programme(&d, b"vanguard 1");
        poser(&d, Tache::Surveillance, &p);
        assert_eq!(juger_dans(&d, Tache::Surveillance, &p, None, UNITE), Jugement::Sain);
        // Remplacé par un autre programme du compte : alerte élevée, jamais sain.
        std::fs::write(&p, b"autre chose").unwrap();
        let j = juger_dans(&d, Tache::Surveillance, &p, None, UNITE);
        assert_eq!(j, Jugement::Remplace);
        for s in [None, Some(&Signee::Non)] {
            let c = constat_de(Tache::Surveillance, &p, &j, s).expect("alerte");
            assert_eq!(c.probleme, Some(Niveau::Eleve));
            assert!(c.verifie);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Remplacé par une version publiée et signée (mise à jour hors de Vanguard) : dit en information, pas en
    /// élevé ; sans réponse de l'historique : moyen et non vérifié, jamais tu.
    #[test]
    fn version_signee_posee_hors_de_vanguard() {
        let p = Path::new("/x/vanguard");
        let c = constat_de(
            Tache::Surveillance,
            p,
            &Jugement::Remplace,
            Some(&Signee::Oui("0.88.0".into())),
        )
        .unwrap();
        assert_eq!(c.probleme, Some(Niveau::Info));
        assert!(c.message.contains("0.88.0"), "{}", c.message);
        let c = constat_de(
            Tache::Surveillance,
            p,
            &Jugement::Remplace,
            Some(&Signee::Inconnu("hors ligne".into())),
        )
        .unwrap();
        assert!(c.probleme == Some(Niveau::Moyen) && !c.verifie, "{}", c.message);
        // R3-C7 : une version signée plus ancienne que ce Vanguard est un retour en arrière, dit en moyen.
        let c = constat_de(
            Tache::Surveillance,
            p,
            &Jugement::Remplace,
            Some(&Signee::Ancienne("0.1.0".into())),
        )
        .unwrap();
        assert!(
            c.probleme == Some(Niveau::Moyen) && c.message.contains("0.1.0"),
            "{}",
            c.message
        );
    }

    /// R3-C7 : l'historique signé dit une version plus ancienne que ce Vanguard : `Ancienne`, jamais `Oui` (qui
    /// renoterait le sceau de la tâche) ; la même ou une plus récente : `Oui`.
    #[test]
    fn version_signee_plus_ancienne_est_un_retour_en_arriere() {
        let vue = |v: &str| Ok(Some((v.to_string(), "linux-x86_64".to_string())));
        assert!(matches!(classer(vue("0.1.0"), None), Signee::Ancienne(v) if v == "0.1.0"));
        assert!(matches!(classer(vue(env!("CARGO_PKG_VERSION")), None), Signee::Oui(_)));
        assert!(matches!(classer(vue("99.0.0"), None), Signee::Oui(_)));
        assert!(matches!(classer(Ok(None), None), Signee::Non));
        assert!(matches!(classer(Err("hors ligne".into()), None), Signee::Inconnu(_)));
        // R4-REGISTRE-2 : plus récente que ce programme, mais plus ancienne que la version notée pour la copie.
        assert!(matches!(classer(vue("98.0.0"), Some("99.0.0+1700000000")), Signee::Ancienne(v) if v == "98.0.0"));
        assert!(matches!(
            classer(vue("99.0.0"), Some("99.0.0+1700000000")),
            Signee::Oui(_)
        ));
        assert!(matches!(
            classer(vue("99.1.0"), Some("99.0.0+1700000000")),
            Signee::Oui(_)
        ));
        assert!(matches!(classer(vue("99.0.0"), Some("illisible")), Signee::Oui(_)));
    }

    /// Lot D7b, « Refaire » : le programme remplacé (ni posé, ni signé, ou l'historique muet), la liste forgée et le
    /// programme non vérifié portent le geste qui remet un programme signé, à un chemin de root seulement ; une tâche
    /// qui lance un autre chemin ou dont le texte a changé se refait par la tâche, à la main.
    #[cfg(target_os = "linux")]
    #[test]
    fn refaire_porte_le_geste_de_remise() {
        let pose = Path::new("/usr/local/bin/vanguard");
        let ligne = format!(
            "vanguard:geste defense remettre-programme {} ",
            crate::machine::gestes_unix::hex(b"/usr/local/bin/vanguard")
        );
        let inconnu = Signee::Inconnu("hors ligne".into());
        let avec = [
            (Jugement::Remplace, None),
            (Jugement::Remplace, Some(&Signee::Non)),
            (Jugement::Remplace, Some(&inconnu)),
            (Jugement::ListeForgee, None),
            (Jugement::NonVerifie("illisible".into()), None),
        ];
        for (j, s) in &avec {
            let c = constat_de(Tache::Surveillance, pose, j, *s).unwrap();
            let k = c.correctif.expect("correction");
            assert!(k.automatique, "{j:?}");
            assert_eq!(k.commandes.len(), 1, "{j:?}");
            assert!(k.commandes[0].starts_with(&ligne), "{j:?} : {:?}", k.commandes);
            assert!(
                k.action.contains("quarantaine") && k.action.contains("non annulable"),
                "{}",
                k.action
            );
        }
        // Le programme dans le dossier du compte : root n'y écrit pas, la correction reste à la main.
        let compte = Path::new("/home/alice/.local/share/vanguard/bin/vanguard");
        let sans = [
            (Jugement::Remplace, compte),
            (Jugement::AutreChemin("/usr/local/bin/vanguard".into()), pose),
            (Jugement::TexteChange, pose),
        ];
        for (j, p) in &sans {
            let c = constat_de(Tache::Surveillance, p, j, None).unwrap();
            assert!(c.correctif.is_none_or(|k| k.commandes.is_empty()), "{j:?}");
        }
    }

    /// L'unité pointée vers un autre programme : l'autre chemin est dit, même s'il existe, et même aux octets du
    /// programme qui tourne (une copie ailleurs n'est pas ce que Vanguard a posé).
    #[test]
    fn unite_pointee_ailleurs() {
        let d = jetable("ailleurs");
        let p = programme(&d, b"vanguard 1");
        poser(&d, Tache::Veilleur, &p);
        let autre = d.join("faux-veilleur");
        std::fs::write(&autre, b"vanguard 1").unwrap();
        let soi = empreinte_de(&autre).unwrap();
        for s in [None, Some(soi.as_str())] {
            let j = juger_dans(&d, Tache::Veilleur, &autre, s, UNITE);
            assert!(matches!(j, Jugement::AutreChemin(_)), "{j:?}");
            assert_eq!(
                constat_de(Tache::Veilleur, &autre, &j, None).unwrap().probleme,
                Some(Niveau::Eleve)
            );
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Le texte de la tâche changé (une seconde ExecStart=, une condition, une minuterie annuelle), programme
    /// intact : alerte élevée ; illisible : non vérifié.
    #[test]
    fn tache_changee_hors_de_vanguard() {
        let d = jetable("texte");
        let p = programme(&d, b"vanguard 1");
        poser(&d, Tache::Surveillance, &p);
        let change = b"[Service]\nExecCondition=/bin/false\nExecStart=\"/x/vanguard\" surveiller\n";
        let j = juger_dans(&d, Tache::Surveillance, &p, None, change);
        assert_eq!(j, Jugement::TexteChange);
        assert_eq!(
            constat_de(Tache::Surveillance, &p, &j, None).unwrap().probleme,
            Some(Niveau::Eleve)
        );
        // Même le programme qui tourne n'excuse pas une tâche changée.
        let soi = empreinte_de(&p).unwrap();
        assert_eq!(
            juger_dans(&d, Tache::Surveillance, &p, Some(&soi), change),
            Jugement::TexteChange
        );
        let lu = empreinte_de(&p);
        let f = lire_dans(&d);
        let j = juger(
            &p,
            &lu,
            f.as_ref().map(|f| f.taches.get("surveillance")).map_err(|x| *x),
            None,
            &Err(std::io::Error::other("refus")),
        );
        assert!(matches!(j, Jugement::NonVerifie(_)), "{j:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// La liste réécrite sans sceau (l'empreinte d'un autre programme mise à la place) : non vérifiée, ou élevée
    /// quand le programme lancé n'est pas celui qui tourne ; adoptée après des sceaux effacés : non vérifiée.
    #[test]
    fn liste_forgee() {
        let d = jetable("forgee");
        let p = programme(&d, b"vanguard 1");
        poser(&d, Tache::Entretien, &p);
        std::fs::write(&p, b"autre chose").unwrap();
        let forge = format!(
            r#"{{"taches":{{"entretien":{{"chemin":"{}","empreinte":"{}"}}}}}}"#,
            p.display(),
            empreinte_de(&p).unwrap()
        );
        std::fs::write(d.join(FICHIER), forge).unwrap();
        let j = juger_dans(&d, Tache::Entretien, &p, None, UNITE);
        assert!(matches!(j, Jugement::NonVerifie(_)), "{j:?}");
        assert!(!constat_de(Tache::Entretien, &p, &j, None).unwrap().verifie);
        assert_eq!(
            juger_dans(&d, Tache::Entretien, &p, Some("0000"), UNITE),
            Jugement::ListeForgee
        );
        // Adoptée après des sceaux effacés : jamais crue (née scellée).
        std::fs::remove_file(d.join("sceaux.json")).unwrap();
        assert!(matches!(lire_dans(&d), Err(Doute::Adopte)));
        assert!(matches!(
            juger_dans(&d, Tache::Entretien, &p, None, UNITE),
            Jugement::NonVerifie(_)
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Rien de noté (tâche d'une version d'avant) : premier usage ; programme illisible : non vérifié.
    #[test]
    fn premier_usage_ou_illisible() {
        let d = jetable("jamais");
        let p = programme(&d, b"vanguard 1");
        assert_eq!(juger_dans(&d, Tache::Surveillance, &p, None, UNITE), Jugement::Premier);
        assert!(constat_de(Tache::Surveillance, &p, &Jugement::Premier, None).is_none());
        let absent = d.join("absent");
        assert!(matches!(
            juger_dans(&d, Tache::Surveillance, &absent, None, UNITE),
            Jugement::NonVerifie(_)
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Le programme qui tourne, au chemin posé, se reconnaît (mise à jour par paquet) ; d'autres octets : remplacé.
    #[test]
    fn le_programme_qui_tourne_se_reconnait() {
        let d = jetable("soi");
        let p = programme(&d, b"vanguard 1");
        poser(&d, Tache::Surveillance, &p);
        std::fs::write(&p, b"vanguard 2").unwrap();
        let e = empreinte_de(&p).unwrap();
        assert_eq!(juger_dans(&d, Tache::Surveillance, &p, Some(&e), UNITE), Jugement::Soi);
        assert!(constat_de(Tache::Surveillance, &p, &Jugement::Soi, None).is_none());
        assert_eq!(
            juger_dans(&d, Tache::Surveillance, &p, Some("0000"), UNITE),
            Jugement::Remplace
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// À la pose, le programme qui tourne scelle ses propres octets, sauf pour la copie de cet ordinateur (une
    /// version plus récente gardée) : un fichier changé entre la pose et sa lecture n'est pas scellé comme le sien.
    #[test]
    fn pose_scelle_les_octets_du_programme_qui_tourne() {
        let (p, copie) = (Path::new("/x/vanguard"), Path::new("/d/bin/vanguard"));
        let mut f = Fichier::default();
        f.copies
            .insert(copie.display().to_string(), Copie::EmpreinteSeule("recente".into()));
        let f = Some(&f);
        assert_eq!(
            a_sceller(p, "etranger".into(), Some("soi"), Some("soi"), copie, f),
            "soi"
        );
        assert_eq!(a_sceller(p, "soi".into(), Some("soi"), Some("soi"), copie, f), "soi");
        assert_eq!(
            a_sceller(copie, "recente".into(), Some("soi"), Some("soi"), copie, f),
            "recente"
        );
        assert_eq!(a_sceller(p, "lu".into(), None, None, copie, f), "lu");
    }

    /// BASSE (relecture adverse, R1-N1) : un fichier mis dans bin/ par un autre programme du compte (une version gravée
    /// plus haute suffisait pour qu'il y soit gardé), ou échangé entre la pose et `noter`, n'est jamais scellé comme
    /// le programme de Vanguard. Seuls se scellent les octets du programme qui tourne ou de la copie que Vanguard y a
    /// posée (R1-M1 : un sceau de tâche ne compte pas) ; sinon la copie posée (le fichier se dira remplacé), et sans elle
    /// une marque que le bilan dit « non vérifié », jamais « sain ».
    #[test]
    fn copie_de_l_ordinateur_scellee_seulement_si_connue() {
        let copie = Path::new("/d/bin/vanguard");
        let vide = Fichier::default();
        let etranger = || "etranger".to_string();
        // Rien de connu : ni ses octets, ni une empreinte inventée.
        assert_eq!(
            a_sceller(copie, etranger(), Some("soi"), Some("soi"), copie, Some(&vide)),
            NON_VERIFIE
        );
        assert_eq!(a_sceller(copie, etranger(), None, None, copie, None), NON_VERIFIE);
        // La copie posée par Vanguard notée : c'est elle qui est scellée.
        let mut posee = Fichier::default();
        posee
            .copies
            .insert(copie.display().to_string(), Copie::EmpreinteSeule("posee".into()));
        assert_eq!(
            a_sceller(copie, etranger(), Some("soi"), Some("soi"), copie, Some(&posee)),
            "posee"
        );
        assert_eq!(
            a_sceller(copie, "posee".into(), Some("soi"), Some("soi"), copie, Some(&posee)),
            "posee"
        );
        // Seulement scellée pour une tâche (le sceau de premier usage du bilan en est un, R1-M1) : pas une pose de
        // Vanguard, jamais scellée comme telle.
        let mut tache = Fichier::default();
        tache.taches.insert(
            "surveillance".into(),
            Pose {
                chemin: copie.display().to_string(),
                empreinte: "signee".into(),
                texte: None,
            },
        );
        assert_eq!(
            a_sceller(copie, "signee".into(), None, None, copie, Some(&tache)),
            NON_VERIFIE
        );
        assert!(!tache.connue(copie, "signee"));
        // Le programme qui tourne lui-même.
        assert_eq!(
            a_sceller(copie, "soi".into(), Some("soi"), Some("soi"), copie, Some(&vide)),
            "soi"
        );
        // Au bilan, la marque n'est ni saine ni « remplacée » : non vérifiée, sauf pour le programme qui tourne.
        let d = jetable("non-verifie");
        let prog = programme(&d, b"vanguard 9");
        retenir_dans(&d, Tache::Surveillance, &prog, NON_VERIFIE.into(), texte(UNITE).ok()).unwrap();
        assert!(matches!(
            juger_dans(&d, Tache::Surveillance, &prog, None, UNITE),
            Jugement::NonVerifie(_)
        ));
        let lu = empreinte_de(&prog).unwrap();
        assert_eq!(
            juger_dans(&d, Tache::Surveillance, &prog, Some(&lu), UNITE),
            Jugement::Soi
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// La copie posée par Vanguard est notée même sans tâche qui la lance encore : la pose qui suit la reconnaît.
    #[test]
    fn copie_posee_notee_sans_tache() {
        let d = jetable("copie-notee");
        let p = programme(&d, b"vanguard 3");
        assert_eq!(copie_posee_dans(&d, &p, b"vanguard 3"), Vec::<Tache>::new());
        let f = lire_dans(&d).unwrap();
        assert!(f.connue(&p, &blake3::hash(b"vanguard 3").to_hex()));
        assert!(!f.connue(&p, &blake3::hash(b"autre").to_hex()));
        assert!(!f.connue(&p, NON_VERIFIE));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// R3-C1 : la copie posée est notée avec sa version ; une entrée d'avant (l'empreinte seule) se lit encore, sans
    /// version, et elle est réécrite avec la version quand Vanguard repose ou garde la copie.
    #[test]
    fn copie_notee_avec_sa_version_et_entree_d_avant_lue() {
        let d = jetable("copie-version");
        let octets = crate::mise_a_jour::grave("0.91.2+1700000000");
        let p = programme(&d, &octets);
        let empreinte = blake3::hash(&octets).to_hex().to_string();
        changer_dans(&d, |f| {
            f.copies
                .insert(p.display().to_string(), Copie::EmpreinteSeule(empreinte.clone()));
            true
        })
        .unwrap();
        let brut: serde_json::Value = serde_json::from_slice(&std::fs::read(d.join(FICHIER)).unwrap()).unwrap();
        assert_eq!(brut["copies"][p.display().to_string()], serde_json::json!(empreinte));
        assert_eq!(
            copie_notee_dans(&d, &p).unwrap(),
            Some(CopieNotee {
                empreinte: empreinte.clone(),
                version: None
            })
        );
        assert!(copie_connue_dans(&d, &p, &empreinte));
        copie_posee_dans(&d, &p, &octets);
        assert_eq!(
            copie_notee_dans(&d, &p).unwrap(),
            Some(CopieNotee {
                empreinte: empreinte.clone(),
                version: Some("0.91.2+1700000000".into())
            })
        );
        let brut: serde_json::Value = serde_json::from_slice(&std::fs::read(d.join(FICHIER)).unwrap()).unwrap();
        assert_eq!(
            brut["copies"][p.display().to_string()],
            serde_json::json!({ "empreinte": empreinte, "version": "0.91.2+1700000000" })
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un nom sans chemin (« vanguard », « @… ») alors qu'un chemin a été posé : un autre programme, élevé.
    #[test]
    fn nom_sans_chemin_apres_une_pose() {
        let c = autre_chemin(Tache::Surveillance, Path::new("vanguard"), "/x/bin/vanguard");
        assert_eq!(c.probleme, Some(Niveau::Eleve), "{}", c.message);
    }

    /// Une mise à jour par Vanguard renote l'empreinte de chaque tâche qui lance la copie ; les autres ne bougent pas.
    #[test]
    fn mise_a_jour_par_vanguard_renote() {
        let d = jetable("maj");
        let p = programme(&d, b"vanguard 1");
        let ailleurs = d.join("autre-vanguard");
        std::fs::write(&ailleurs, b"vanguard x").unwrap();
        poser(&d, Tache::Surveillance, &p);
        poser(&d, Tache::Veilleur, &ailleurs);
        std::fs::write(&p, b"vanguard 2").unwrap();
        assert_eq!(copie_posee_dans(&d, &p, b"vanguard 2"), vec![Tache::Surveillance]);
        assert_eq!(juger_dans(&d, Tache::Surveillance, &p, None, UNITE), Jugement::Sain);
        assert_eq!(juger_dans(&d, Tache::Veilleur, &ailleurs, None, UNITE), Jugement::Sain);
        assert_eq!(copie_posee_dans(&d, &p, b"vanguard 2"), Vec::<Tache>::new());
        oublier_dans(&d, Tache::Surveillance);
        assert_eq!(juger_dans(&d, Tache::Surveillance, &p, None, UNITE), Jugement::Premier);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// R4-REGISTRE-1 : la liste effacée (ou réécrite) alors qu'un sceau l'attendait n'est jamais rescellée à neuf. La
    /// pose d'une tâche qui suit garde le doute : aucune copie n'y est crue (une copie plus récente y était peut-être
    /// notée), et une autre tâche sans entrée est non vérifiée, pas « premier usage ». Seule une copie posée par Vanguard
    /// après la garde du registre (`copie_posee_dans`) lève le doute sur les copies.
    #[test]
    fn liste_douteuse_jamais_rescellee_a_neuf() {
        let d = jetable("douteuse");
        let octets = crate::mise_a_jour::grave("0.99.0+1700000000");
        let p = programme(&d, &octets);
        copie_posee_dans(&d, &p, &octets);
        poser(&d, Tache::Veilleur, &p);
        assert!(copie_notee_dans(&d, &p).unwrap().is_some());
        std::fs::remove_file(d.join(FICHIER)).unwrap();
        assert!(matches!(copie_notee_dans(&d, &p), Err(Doute::HorsVanguard)));
        // Une tâche reposée par Vanguard réécrit la liste : le doute la suit.
        poser(&d, Tache::Surveillance, &p);
        assert!(matches!(copie_notee_dans(&d, &p), Err(Doute::Herite)));
        let lue = lire_dans(&d).unwrap();
        assert!(!lue.connue(&p, &blake3::hash(&octets).to_hex()));
        assert_eq!(juger_dans(&d, Tache::Surveillance, &p, None, UNITE), Jugement::Sain);
        let jugement = juger_dans(&d, Tache::Veilleur, &p, None, UNITE);
        assert!(
            matches!(&jugement, Jugement::NonVerifie(m) if m.contains(Doute::Herite.texte())),
            "{jugement:?}"
        );
        oublier_dans(&d, Tache::Surveillance);
        assert!(matches!(copie_notee_dans(&d, &p), Err(Doute::Herite)));
        // Une entrée glissée dans la liste en doute (inventée : une autre copie notée 0.99.1) n'y survit pas.
        let autre = d.join("autre-copie");
        changer_dans(&d, |f| {
            f.copies.insert(
                autre.display().to_string(),
                Copie::Notee {
                    empreinte: "0".repeat(64),
                    version: Some("0.99.1+1700000001".into()),
                },
            );
            true
        })
        .unwrap();
        // Levé par une copie posée après la garde : notée de nouveau, les autres tâches restent non vérifiées.
        copie_posee_dans(&d, &p, &octets);
        assert!(matches!(copie_notee_dans(&d, &autre), Ok(None)));
        assert_eq!(
            copie_notee_dans(&d, &p).unwrap().and_then(|c| c.version),
            Some("0.99.0+1700000000".into())
        );
        assert!(matches!(
            juger_dans(&d, Tache::Veilleur, &p, None, UNITE),
            Jugement::NonVerifie(_)
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une liste des copies en doute (sa note effacée, puis une tâche reposée : `Doute::Herite`).
    fn liste_en_doute(nom: &str) -> (PathBuf, PathBuf, Vec<u8>) {
        let d = jetable(nom);
        let octets = crate::mise_a_jour::grave("0.99.0+1700000000");
        let p = programme(&d, &octets);
        copie_posee_dans(&d, &p, &octets);
        poser(&d, Tache::Surveillance, &p);
        std::fs::remove_file(d.join(FICHIER)).unwrap();
        poser(&d, Tache::Surveillance, &p);
        assert!(matches!(copie_notee_dans(&d, &p), Err(Doute::Herite)));
        (d, p, octets)
    }

    /// R5-REGISTRE-1 : une pose à un autre chemin que la copie de cet ordinateur (un autre programme mis à jour depuis
    /// GitHub) ne prouve rien pour la copie : le doute reste ; seule la pose de la copie elle-même le lève.
    #[test]
    fn pose_ailleurs_ne_leve_jamais_le_doute() {
        let (d, p, octets) = liste_en_doute("pose-ailleurs");
        let autre = d.join("autre-programme");
        std::fs::write(&autre, &octets).unwrap();
        copie_posee_ici(&d, &autre, &octets, &p);
        assert!(matches!(copie_notee_dans(&d, &p), Err(Doute::Herite)));
        assert!(matches!(copie_notee_dans(&d, &autre), Err(Doute::Herite)));
        copie_posee_ici(&d, &p, &octets, &p);
        assert_eq!(
            copie_notee_dans(&d, &p).unwrap().and_then(|c| c.version),
            Some("0.99.0+1700000000".into())
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// R5-REGISTRE-4 : seule une réponse `Oui` devient non vérifiée sous le doute ; le reste garde son sens.
    #[test]
    fn version_signee_sous_doute_jamais_crue() {
        let oui = || Signee::Oui("99.0.0".into());
        assert!(
            matches!(sous_doute(oui(), Some(Doute::Herite)), Signee::Inconnu(m) if m.contains(Doute::Herite.texte()))
        );
        assert_eq!(sous_doute(oui(), None), oui());
        assert_eq!(sous_doute(Signee::Non, Some(Doute::Adopte)), Signee::Non);
        assert_eq!(
            sous_doute(Signee::Ancienne("0.1.0".into()), Some(Doute::Adopte)),
            Signee::Ancienne("0.1.0".into())
        );
    }

    /// R5-ESSAIS-1 et R5-REGISTRE-4, par le chemin du bilan (`constat_dans`, `signee_dans`) : sous une liste en doute,
    /// une tâche sans entrée est dite non vérifiée sans être notée, et un programme remplacé par une version signée
    /// plus récente reste non vérifié, son sceau intact. Sans doute, la même version signée est renotée (l'essai
    /// n'est pas aveugle).
    #[test]
    fn bilan_sous_doute_dit_non_verifie_sans_rien_noter() {
        let signee_99 = |_: &[u8; 32]| Ok(Some(("99.0.0".to_string(), "linux-x86_64".to_string())));
        let unite = Ok(UNITE.to_vec());
        let (d, p, _) = liste_en_doute("bilan-doute");
        let c = constat_dans(&d, Tache::Veilleur, &p, &unite, None, |q| signee_dans(&d, q, signee_99)).unwrap();
        assert!(!c.verifie, "{}", c.message);
        assert!(!lire_dans(&d).unwrap().taches.contains_key(Tache::Veilleur.cle()));
        std::fs::write(&p, crate::mise_a_jour::grave("99.0.0+1800000000")).unwrap();
        let avant = lire_dans(&d).unwrap().taches[Tache::Surveillance.cle()]
            .empreinte
            .clone();
        let c = constat_dans(&d, Tache::Surveillance, &p, &unite, None, |q| {
            signee_dans(&d, q, signee_99)
        })
        .unwrap();
        assert!(!c.verifie && c.probleme == Some(Niveau::Moyen), "{}", c.message);
        assert_eq!(
            lire_dans(&d).unwrap().taches[Tache::Surveillance.cle()].empreinte,
            avant
        );
        let _ = std::fs::remove_dir_all(&d);
        // Témoin : la même chose sans doute est renotée.
        let d = jetable("bilan-temoin");
        let octets = crate::mise_a_jour::grave("0.99.0+1700000000");
        let p = programme(&d, &octets);
        copie_posee_dans(&d, &p, &octets);
        poser(&d, Tache::Surveillance, &p);
        std::fs::write(&p, crate::mise_a_jour::grave("99.0.0+1800000000")).unwrap();
        let c = constat_dans(&d, Tache::Surveillance, &p, &unite, None, |q| {
            signee_dans(&d, q, signee_99)
        })
        .unwrap();
        assert_eq!(c.probleme, Some(Niveau::Info), "{}", c.message);
        assert_eq!(
            lire_dans(&d).unwrap().taches[Tache::Surveillance.cle()].empreinte,
            empreinte_de(&p).unwrap()
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// R4-ESSAIS-3 : au bilan, seuls le programme qui tourne, une version signée au moins aussi récente et le premier
    /// usage se renotent ; une version signée plus ancienne (retour en arrière) jamais, ni rien d'autre.
    #[test]
    fn retour_en_arriere_signe_jamais_renote() {
        let ancien = || Some("texte-note".to_string());
        let lu = || Some("texte-lu".to_string());
        let oui = Signee::Oui("9.9.9".into());
        assert_eq!(
            a_renoter(&Jugement::Remplace, Some(&oui), ancien(), lu()),
            Some(Renoter(ancien()))
        );
        assert_eq!(a_renoter(&Jugement::Soi, None, ancien(), lu()), Some(Renoter(ancien())));
        assert_eq!(a_renoter(&Jugement::Premier, None, ancien(), lu()), Some(Renoter(lu())));
        let ancienne = Signee::Ancienne("0.1.0".into());
        let non = Signee::Non;
        let inconnu = Signee::Inconnu("hors ligne".into());
        for s in [Some(&ancienne), Some(&non), Some(&inconnu), None] {
            assert_eq!(a_renoter(&Jugement::Remplace, s, ancien(), lu()), None, "{s:?}");
        }
        for j in [
            Jugement::Sain,
            Jugement::TexteChange,
            Jugement::ListeForgee,
            Jugement::AutreChemin("/x".into()),
            Jugement::NonVerifie("x".into()),
        ] {
            assert_eq!(a_renoter(&j, Some(&oui), ancien(), lu()), None, "{j:?}");
        }
    }
}

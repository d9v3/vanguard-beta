//! Les gestes de défense de Linux (`gestes_unix::Defense`), faits par l'assistant élevé (`assistant`), en root. Pour
//! chacun, dans cet ordre : il est rejugé ici, avec les yeux de root (le fichier, le compte, le paquet relus, jamais
//! ce que la ligne en dit) ; ce qui est trouvé est montré sur le terminal de la personne (/dev/tty, jamais le canal du
//! parent ni l'entrée standard), avec un AVERTISSEMENT quand le geste peut la couper de son ordinateur (root, son
//! propre compte, le dernier administrateur, sudo, su et pkexec rendus inutilisables), et la question `[o/N]` : Entrée
//! seule dit non ; rejugé encore après la réponse (rien n'a dû changer) ; la note d'« avant » écrite par root dans
//! `/var/lib/vanguard/avant/<id>` (sans elle, rien n'est fait) ; le geste ; puis rejugé une dernière fois : il ne doit
//! plus rien rester à faire. `Remettre` relit la note (à root, en 0600, dans un dossier que les autres ne lisent ni ne
//! modifient), la rejuge, redemande, puis remet ce qu'elle dit, seulement si rien n'a changé depuis (même fichier, même
//! empreinte).
//!
//! Aucun shell : chaque outil (usermod, gpasswd, visudo, sudo) par son chemin du système, arguments séparés, dans un
//! environnement vidé ; un nom de compte n'y passe qu'après `--` quand l'outil le permet, et il ne commence jamais
//! par « - » (`gestes_unix::nom_compte_admis`). Un fichier est changé par son descripteur, ouvert sans suivre de lien,
//! après avoir vérifié qu'il est bien celui qui a été jugé (même disque, même inode, même chemin réel).

// Partout les mêmes lettres : a l'accès au système, s ses services, d le geste, c le chemin, n le nom, f sa fiche.
#![allow(clippy::many_single_char_names)]

use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::commande::Resultat as Sortie;
use crate::machine::arret_designe::{self, ArretCharge, Chemin, SessionVue};
use crate::machine::gestes_unix::{
    self, ActionUnite, CheminDesigne, Defense, Empreinte, GesteUnix, GroupeSensible, IdNote, NomCompte, NomUnite,
    echappe,
};
use crate::machine::linux::{DOSSIERS_DE_ROOT, EtatPaquet};
use crate::machine::note_avant_unix::{Note, VALEUR_MAX};
use crate::modele::Echec;
use crate::protection::blocage::ordres::Resultat;
use crate::{tr, trf};

mod pare_feu;
mod pose;
mod programme;
mod systeme;

pub(crate) use programme::naissance_du_stat;
pub(crate) use systeme::ligne_de_proxy;

/// Le dossier des notes d'« avant », à root, ni lisible ni modifiable par les autres comptes. Il se traverse (0711) :
/// le parent sans droits voit si la note de son geste existe (`optimiser::systeme::Changement::Defense`), sans pouvoir
/// lister les autres, les lire ni en poser une.
pub(crate) const DOSSIER_NOTES: &str = "/var/lib/vanguard/avant";
/// Ses droits à la création, et ceux qu'il ne doit jamais avoir : lecture ou écriture du groupe ou des autres.
const DROITS_NOTES: u32 = 0o711;
const FERME_NOTES: u32 = 0o066;
/// Son parent, créé s'il manque.
const DOSSIER_VANGUARD: &str = "/var/lib/vanguard";
/// La taille la plus grande d'un fichier de comptes lu.
const COMPTES_MAX: usize = 8 * 1024 * 1024;
const PASSWD: &str = "/etc/passwd";
const SHADOW: &str = "/etc/shadow";
const GROUP: &str = "/etc/group";
const SUDOERS: &str = "/etc/sudoers";
const SUDOERS_D: &str = "/etc/sudoers.d";
/// Ce qui donne les droits d'administrateur par le droit « setuid » : si aucun ne reste, la personne ne peut plus
/// devenir root sans run0 ou une clé de secours.
const ELEVATEURS: [&str; 8] = [
    "/usr/bin/sudo",
    "/usr/bin/sudo-rs",
    "/usr/bin/su",
    "/usr/bin/pkexec",
    "/usr/bin/doas",
    "/bin/sudo",
    "/bin/su",
    "/usr/local/bin/sudo",
];
/// Les dossiers temporaires et personnels : un programme privilégié n'y a jamais sa place.
const DOSSIERS_SUSPECTS: [&str; 6] = ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/home/", "/root/"];
/// Où le programme qui refuse l'ouverture d'un compte est cherché.
const NOLOGIN: [&str; 3] = ["/usr/sbin/nologin", "/sbin/nologin", "/usr/bin/nologin"];

/// Ce qu'est un chemin, vu sans suivre de lien.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Genre {
    Fichier,
    Dossier,
    /// Un lien, un tube, un périphérique… : jamais touché.
    Autre,
}

/// Ce que `lstat` dit d'un chemin : de quoi le reconnaître au moment d'agir (disque, inode) et ce que le geste change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Fiche {
    pub(crate) genre: Genre,
    /// Les 12 bits de droits (setuid, setgid, sticky compris).
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) dev: u64,
    pub(crate) ino: u64,
    pub(crate) taille: u64,
}

/// Un changement d'un fichier par son descripteur.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Modif {
    Mode(u32),
    Proprietaire(u32, u32),
    /// `security.capability` posé (`Some`), ou retiré (`None`).
    Capacites(Option<Vec<u8>>),
}

/// Comment un fichier est écrit : droits, propriétaire ; `avant` : le fichier remplacé, qui doit être encore celui-là
/// (même disque, même inode) au moment de le remplacer ; `None` : le fichier ne doit pas exister.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ecriture {
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) avant: Option<Fiche>,
}

/// Ce que l'enfant lit et change de l'ordinateur pour un geste de défense : le vrai (`Reel`), ou un faux sous les
/// essais, qui garde tout en mémoire.
pub(crate) trait Acces {
    /// La question, sur le terminal de la personne (`assistant::question_au_terminal`) : la ligne tapée ; `Err(())`
    /// sans terminal.
    fn question(&mut self, texte: &str) -> Result<Option<String>, ()>;
    /// Secondes depuis 1970.
    fn date(&self) -> u64;
    /// Les comptes de la personne devant l'écran : celui du Vanguard qui a demandé, celui de sa connexion (loginuid),
    /// SUDO_UID, PKEXEC_UID.
    fn personnes(&self) -> Vec<u32>;
    /// Un outil du système par son chemin, ces arguments, environnement vidé et en anglais ; `None` : absent, ou pas
    /// fini à temps.
    fn lancer(&mut self, outil: &str, arguments: &[OsString]) -> Option<Sortie>;
    /// L'outil est-il installé dans les dossiers du système ?
    fn outil(&self, nom: &str) -> bool;
    /// `lstat` : `None` si le chemin ne se lit pas.
    fn fiche(&self, p: &Path) -> Option<Fiche>;
    /// Le chemin réel (liens résolus).
    fn reel(&self, p: &Path) -> Option<PathBuf>;
    /// Le contenu d'un fichier ordinaire, ouvert sans suivre de lien, `max` octets au plus.
    fn lire(&self, p: &Path, max: usize) -> Option<Vec<u8>>;
    /// Le SHA-256 du contenu, si le fichier est encore celui de la fiche.
    fn empreinte(&self, p: &Path, f: &Fiche) -> Option<[u8; 32]>;
    /// `security.capability` du fichier de la fiche ; `Ok(None)` : aucune.
    fn capacites(&self, p: &Path, f: &Fiche) -> Result<Option<Vec<u8>>, ()>;
    /// Change le fichier de la fiche (vérifié encore par son descripteur).
    fn changer(&mut self, p: &Path, f: &Fiche, m: &Modif) -> Result<(), Echec>;
    /// Écrit un fichier entier : tout de suite à sa place s'il ne doit pas exister, sinon par un fichier voisin
    /// renommé par-dessus (jamais à moitié écrit).
    fn ecrire(&mut self, p: &Path, contenu: &[u8], e: Ecriture) -> Result<(), Echec>;
    /// Déplace un fichier sans jamais en remplacer un autre.
    fn deplacer(&mut self, de: &Path, vers: &Path) -> Result<(), Echec>;
    fn retirer(&mut self, p: &Path) -> Result<(), Echec>;
    /// Le paquet du fichier (`linux::etat_paquet`).
    fn paquet(&self, p: &Path) -> EtatPaquet;
    fn note_ecrire(&mut self, id: IdNote, octets: &[u8]) -> Result<(), Echec>;
    /// La note, seulement si elle est à root, en 0600, dans le dossier des notes à root, que les autres ne lisent ni
    /// ne modifient.
    fn note_lire(&self, id: IdNote) -> Result<Option<Vec<u8>>, Echec>;
    fn note_retirer(&mut self, id: IdNote) -> Result<(), Echec>;
    /// Lot D7b. Crée un dossier de root avec ces droits, dans un dossier de root fermé aux autres.
    fn creer_dossier(&mut self, p: &Path, mode: u32) -> Result<(), Echec>;
    /// Ce que /proc dit du processus `pid` ; `None` : il n'existe plus.
    fn processus(&self, pid: u32) -> Option<VueProcessus>;
    /// Ce que Vanguard trouve de suspect à ce processus, relu par root (`chasse::juger_programme`, programme sans
    /// fichier), déjà dans la langue de l'interface et échappé ; `None` : rien.
    fn soupcon(&self, pid: u32, v: &VueProcessus) -> Option<String>;
    /// Pourquoi ce processus ne s'arrête jamais (vital, Vanguard lui-même ou sa lignée, programme du système) ; `None` :
    /// aucune garde ne le retient.
    fn garde(&self, pid: u32, v: &VueProcessus) -> Option<String>;
    /// Copie les traces du processus (programme, commande, environnement, fichiers ouverts) dans
    /// /var/lib/vanguard/traces : le dossier où elles sont.
    fn copier_traces(&mut self, pid: u32, v: &VueProcessus) -> Result<PathBuf, Echec>;
    /// Arrête le processus s'il fait encore tourner le programme vu (`blocage::arreter_confirme`).
    fn arreter(&mut self, pid: u32, v: &VueProcessus) -> Result<(), Echec>;
    /// Lot D7b. La version publiée et signée par l'auteur, pour ce système, du programme d'empreinte `sha256`, d'après
    /// l'historique signé des versions (Ed25519) ; `Ok(None)` : il n'y est pas ; `Err` : on ne sait pas (pourquoi).
    fn version_signee(&self, sha256: &[u8; 32]) -> Result<Option<String>, Echec>;
    /// Lot D7b. Un programme de Vanguard publié et signé, reçu en mémoire et vérifié (`mise_a_jour`) : sa version,
    /// ses octets ; rien n'est écrit.
    fn programme_signe(&mut self) -> Result<(String, Vec<u8>), Echec>;
}

/// Ce que l'enfant demande au gestionnaire de services (le bus système, par `assistant::Monde`).
pub(crate) trait Services {
    fn systemd(&self) -> bool;
    fn fichier_sur(&self, unite: &str) -> Result<bool, Echec>;
    fn arret_charge(&mut self, unite: &str) -> Result<Option<ArretCharge>, Echec>;
    fn etat_du_fichier(&mut self, unite: &str) -> Result<Option<String>, Echec>;
    fn etat_d_activite(&mut self, unite: &str) -> Result<Option<String>, Echec>;
    /// systemd a-t-il refusé de lancer l'unité à cause de ses propres conditions, à sa dernière tentative ?
    fn condition_refusee(&mut self, unite: &str) -> Result<bool, Echec>;
    fn unite(&mut self, action: ActionUnite, unite: &str) -> Result<(), Echec>;
    fn groupes_de_la_lignee(&self) -> Vec<String>;
    fn sessions(&mut self) -> Option<Vec<SessionVue>>;
    fn chemin(&self, chemin: &str) -> Chemin;
}

/// L'empreinte d'une ligne d'un fichier, sans son saut de ligne : ce que `Defense::RetirerLigne` porte.
pub(crate) fn empreinte_de_ligne(ligne: &[u8]) -> Empreinte {
    Empreinte(Sha256::digest(ligne).into())
}

/// Ce qu'un geste ferait, d'après ce que l'enfant a relu : montré, noté, puis fait. Deux jugements égaux disent
/// que rien n'a changé entre eux.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Plan {
    /// Ce qui a été trouvé, une ligne par fait, déjà échappé.
    texte: String,
    avertissement: Option<String>,
    non_annulable: bool,
    /// Une seconde question, posée après le premier oui (lot D7b).
    seconde: Option<Seconde>,
    /// Les valeurs d'avant, pour la note.
    champs: Vec<(String, Vec<u8>)>,
    action: Action,
}

/// La seconde question d'un plan, `[o/N]` comme la première, Entrée seule disant non.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Seconde {
    /// Un second oui est exigé : un clavier ou une souris oubliés, par exemple. Non : rien n'est fait.
    Obligatoire(String),
    /// Un choix : oui fait cette autre action à la place de celle du plan ; non garde celle du plan.
    Choix(String, Action),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Action {
    /// Des outils lancés l'un après l'autre ; un code autre que 0 arrête la suite.
    Outils(Vec<(&'static str, Vec<OsString>)>),
    Changer(PathBuf, Fiche, Vec<Modif>),
    /// Le complément de sudo de ce compte, validé par visudo avant d'être posé.
    PoserSudo {
        nom: NomCompte,
        contenu: Vec<u8>,
    },
    /// Un fichier retiré s'il est encore celui de la fiche, avec ce contenu.
    Retirer(PathBuf, Fiche, [u8; 32]),
    Unites(Vec<ActionUnite>, NomUnite),
    Reecrire(PathBuf, Fiche, Vec<u8>),
    /// Lot D7b. Ces actions l'une après l'autre ; la première qui échoue arrête la suite.
    Suite(Vec<Action>),
    /// Un dossier de root créé, avec ces droits (il ne doit pas exister).
    CreerDossier(PathBuf, u32),
    /// Un fichier neuf de root, avec ces droits (il ne doit pas exister).
    Ecrire(PathBuf, Vec<u8>, u32),
    /// Une unité nommée par Vanguard lui-même (jamais par la ligne du parent).
    UniteSysteme(ActionUnite, &'static str),
    /// Le fichier de sshd_config.d posé, validé par `sshd -t` (sinon retiré, rien n'est rechargé), relu par
    /// `sshd -T` (sans effet : retiré), puis sshd rechargé s'il tourne : les sessions ouvertes restent.
    PoserSsh {
        fichier: PathBuf,
        contenu: Vec<u8>,
        reglage: gestes_unix::ReglageSsh,
        unite: Option<&'static str>,
    },
    /// Les traces du programme copiées d'abord ; puis, s'il est encore celui qui a été vu, arrêté.
    Arreter(u32, VueProcessus),
    /// Un programme de tâche remis : le programme signé reçu et revérifié dans l'historique, celui qui y est copié
    /// d'abord en quarantaine (`copier` : la copie n'y est pas encore), puis remplacé s'il est encore celui vu.
    RemettreProgramme {
        chemin: PathBuf,
        fiche: Fiche,
        empreinte: [u8; 32],
        quarantaine: PathBuf,
        copier: bool,
    },
    /// Lot D7c. Des règles de nftables passées par un fichier de root (0600) : vérifiées par `nft -c -f`, puis
    /// chargées d'un bloc si `appliquer` ; le fichier est retiré dans tous les cas.
    Nft {
        contenu: Vec<u8>,
        appliquer: bool,
    },
}

/// Ce que l'enfant voit d'un processus dans /proc : de quoi le reconnaître au moment d'agir (sa naissance, en tops
/// d'horloge depuis le démarrage : un PID repris par un autre programme ne s'y confond pas).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VueProcessus {
    pub(crate) debut: u64,
    pub(crate) tgid: u32,
    pub(crate) nom: String,
    /// Le lien `/proc/<pid>/exe`, tel quel (« (deleted) » compris) ; `None` : illisible, ou un fil du noyau.
    pub(crate) exe: Option<String>,
    pub(crate) uid: u32,
    pub(crate) noyau: bool,
    pub(crate) zombie: bool,
}

type Jugement = Result<Option<Plan>, Echec>;

/// Le contexte des échecs de la défense, au journal des erreurs.
const CONTEXTE: &str = "machine/defense";

/// Un refus de l'enfant (rien n'est fait), sa phrase déjà dans la langue de l'interface.
fn refus(phrase: impl Into<String>) -> Echec {
    Echec::refuse(CONTEXTE, phrase)
}

/// Un échec du système ou d'une commande, sa phrase déjà dans la langue de l'interface.
fn echoue(phrase: impl Into<String>) -> Echec {
    Echec::echoue(CONTEXTE, phrase)
}

fn dit(fr_en: (String, String)) -> String {
    if crate::langue::anglais() { fr_en.1 } else { fr_en.0 }
}

fn chemin_de(c: &CheminDesigne) -> PathBuf {
    PathBuf::from(OsStr::from_bytes(c.octets()))
}

/// Fait le geste de défense `d`, noté sous `id`.
#[allow(
    clippy::large_types_passed_by_value,
    reason = "un geste lu d'une ligne, copié une fois : quelques centaines d'octets"
)]
pub(crate) fn faire(d: Defense, id: IdNote, a: &mut dyn Acces, s: &mut dyn Services) -> Resultat {
    let g = GesteUnix::Defense(d, id);
    if let Some((fr, en)) = g.refus() {
        return Resultat::echec(if crate::langue::anglais() { en } else { fr });
    }
    if d == Defense::Remettre {
        return remettre(id, a, s);
    }
    if g.par_systemd() && !s.systemd() {
        return Resultat::echec(sans_systemd());
    }
    match a.note_lire(id) {
        Ok(None) => {}
        // Lot D7c : la note d'une coupure de pare-feu rallumé hors de Vanguard (déjà comme avant) est retirée, et
        // la coupure jugée à neuf ; encore coupé par ce choix : rien n'est fait.
        Ok(Some(o)) if matches!(d, Defense::CouperPareFeu(_)) => {
            let Defense::CouperPareFeu(p) = d else {
                return Resultat::echec(note_abimee());
            };
            match pare_feu::note_perimee(p, &o, a, s) {
                Ok(true) => {
                    if let Err(r) = a.note_retirer(id) {
                        return Resultat::echec(r);
                    }
                }
                Ok(false) => {
                    return Resultat::ok_note(tr!(
                        "ce pare-feu est déjà coupé par votre choix : rien n'est fait (Rallumer, dans les Options de défense, le remet)",
                        "this firewall is already off by your choice: nothing is done (Turn back on, in the Defense options, puts it back)"
                    ));
                }
                Err(r) => return Resultat::echec(r),
            }
        }
        Ok(Some(_)) => {
            return Resultat::echec(tr!(
                "une note de ce geste existe déjà : rien n'est fait",
                "a note for this step already exists: nothing is done"
            ));
        }
        Err(r) => return Resultat::echec(r),
    }
    let phrase = dit(g.phrase());
    let p1 = match juger(d, a, s) {
        Ok(Some(p)) => p,
        Ok(None) => {
            return Resultat::ok_note(trf!(
                "{phrase} : déjà fait, rien à changer",
                "{phrase}: already done, nothing to change"
            ));
        }
        Err(r) => return Resultat::echec(r),
    };
    let choisi = match demander(a, &phrase, &p1) {
        Ok(c) => c,
        Err(r) => return Resultat::echec(r),
    };
    // La réponse a pu attendre : ce qui a été montré doit être encore ce qui est.
    if juger(d, a, s) != Ok(Some(p1.clone())) {
        return Resultat::echec(change_pendant_la_question());
    }
    let note = Note {
        geste: g.ligne(),
        date: a.date(),
        champs: p1.champs.clone(),
    };
    let Some(octets) = note.octets(id.as_str()) else {
        return Resultat::echec(tr!(
            "la note d'« avant » ne s'écrit pas (trop grande) : rien n'est fait",
            "the \"before\" note cannot be written (too large): nothing is done"
        ));
    };
    if let Err(r) = a.note_ecrire(id, &octets) {
        return Resultat::echec(trf!(
            "la note d'« avant » ne s'écrit pas ({r}) : rien n'est fait",
            "the \"before\" note cannot be written ({r}): nothing is done"
        ));
    }
    let action = match &p1.seconde {
        Some(Seconde::Choix(_, autre)) if choisi => autre,
        _ => &p1.action,
    };
    let fait = agir(action, a, s);
    let relu = juger(d, a, s);
    match (fait, relu) {
        (Ok(()), Ok(None)) if p1.non_annulable => {
            // Rallumer un pare-feu sans note (D7c) : rien à garder (champs vides) et Défaire le refuse ; la note
            // resterait à jamais dans le dossier des notes.
            if matches!(d, Defense::RallumerPareFeu(_)) && p1.champs.is_empty() {
                let _ = a.note_retirer(id);
            }
            Resultat::ok_note(trf!("{phrase} : fait", "{phrase}: done"))
        }
        (Ok(()), Ok(None)) => Resultat::ok_note(trf!(
            "{phrase} : fait ; Défaire le remet comme avant",
            "{phrase}: done; Undo puts it back as before"
        )),
        (fait, relu) => {
            // Rien n'a changé : la note ne sert à rien. Sinon elle reste, pour que Défaire remette ce qui a changé.
            if relu == Ok(Some(p1)) {
                let _ = a.note_retirer(id);
            }
            let r = fait.err().unwrap_or_else(|| {
                refus(tr!(
                    "relu après le geste, ce n'est pas comme prévu",
                    "read again after the step, it is not as expected"
                ))
            });
            Resultat::echec(trf!("{phrase} : pas fait ({r})", "{phrase}: not done ({r})"))
        }
    }
}

fn change_pendant_la_question() -> &'static str {
    tr!(
        "ce qui a été montré a changé pendant la question : rien n'est fait. Relancez le bilan",
        "what was shown changed during the question: nothing is done. Run the check again"
    )
}

fn sans_systemd() -> &'static str {
    tr!(
        "cet ordinateur n'utilise pas le gestionnaire de services habituel (systemd) : rien n'est fait",
        "this computer does not use the usual service manager (systemd): nothing is done"
    )
}

/// Montre le plan et pose la question `[o/N]` sur le terminal : seul un oui tapé le fait, Entrée seule dit non. Puis
/// la seconde question du plan, s'il en a une : `Ok(true)` quand elle a reçu un oui.
fn demander(a: &mut dyn Acces, phrase: &str, p: &Plan) -> Result<bool, Echec> {
    let mut q = trf!(
        "Vanguard (administrateur) : {phrase}.",
        "Vanguard (administrator): {phrase}."
    );
    if !p.texte.is_empty() {
        q.push('\n');
        q.push_str(&p.texte);
    }
    if let Some(w) = &p.avertissement {
        q.push('\n');
        q.push_str(&trf!("AVERTISSEMENT : {w}", "WARNING: {w}"));
    }
    if p.non_annulable {
        q.push('\n');
        q.push_str(tr!(
            "Ce geste est non annulable : Vanguard ne pourra pas le défaire.",
            "This step cannot be undone: Vanguard will not be able to undo it."
        ));
    }
    if !oui_au_terminal(a, &q)? {
        return Err(pas_dit_oui());
    }
    match &p.seconde {
        None => Ok(false),
        Some(Seconde::Obligatoire(q2)) => {
            if oui_au_terminal(a, q2)? {
                Ok(true)
            } else {
                Err(pas_dit_oui())
            }
        }
        Some(Seconde::Choix(q2, _)) => oui_au_terminal(a, q2),
    }
}

/// Pose `q` sur le terminal, suivie de « [o/N] » : vrai pour un oui tapé ; sans terminal, refusé.
fn oui_au_terminal(a: &mut dyn Acces, q: &str) -> Result<bool, Echec> {
    let mut q = q.to_string();
    q.push('\n');
    q.push_str(tr!(
        "D'accord ? [o/N] (Entrée seule : non)",
        "Agree? [y/N] (Enter alone: no)"
    ));
    match a.question(&q) {
        Err(()) => Err(refus(tr!(
            "ce geste demande votre accord, et aucun terminal n'est là pour le donner : rien n'est fait. Lancez Vanguard depuis un terminal",
            "this step needs your agreement, and no terminal is there to give it: nothing is done. Start Vanguard from a terminal"
        )
        .to_string())),
        Ok(Some(r)) => Ok(super::assistant::est_oui(&r)),
        Ok(None) => Ok(false),
    }
}

fn pas_dit_oui() -> Echec {
    refus(tr!("pas fait : vous n'avez pas dit oui", "not done: you did not say yes").to_string())
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "un geste lu d'une ligne, copié une fois : quelques centaines d'octets"
)]
fn juger(d: Defense, a: &mut dyn Acces, s: &mut dyn Services) -> Jugement {
    match d {
        Defense::VerrouillerCompte(n) => juger_verrou(n, a),
        Defense::RetirerDuGroupe(g, n) => juger_groupe(g, n, a),
        Defense::DurcirSudo(n) => juger_sudo(n, a),
        Defense::RetirerSetuid(c) => juger_droits(&c, false, a),
        Defense::RetirerCapacites(c) => juger_droits(&c, true, a),
        Defense::RendreDossierARoot(c) => juger_dossier(&c, a),
        Defense::DesactiverService(u) => juger_service(u, a, s),
        Defense::RetirerLigne(e, c) => juger_ligne(e, &c, a),
        Defense::DurcirSsh(r) => systeme::juger_ssh(r, a, s),
        Defense::ReserverBpf => systeme::juger_bpf(a),
        Defense::GarderJournal => systeme::juger_journal(a),
        Defense::RetirerAncre(c) => systeme::juger_ancre(&c, a),
        Defense::CommenterProxy(e, c) => systeme::juger_proxy(e, &c, a),
        Defense::OublierBluetooth(b) => systeme::juger_bluetooth(b, a, s),
        Defense::ArreterProgramme(pid, debut) => programme::juger_arret(pid, debut, a),
        Defense::RemettreProgramme(c) => pose::juger_remise(&c, a),
        Defense::CouperPareFeu(p) => pare_feu::juger_couper(p, a, s),
        Defense::RallumerPareFeu(p) => pare_feu::juger_rallumer(p, a, s),
        Defense::Remettre => Err(refus(tr!("geste refusé", "step refused").to_string())),
    }
}

fn agir(action: &Action, a: &mut dyn Acces, s: &mut dyn Services) -> Result<(), Echec> {
    match action {
        Action::Outils(liste) => {
            for (outil, arguments) in liste {
                lancer_ok(a, outil, arguments)?;
            }
            Ok(())
        }
        Action::Changer(p, f, modifs) => {
            for m in modifs {
                a.changer(p, f, m)?;
            }
            Ok(())
        }
        Action::PoserSudo { nom, contenu } => poser_sudo(*nom, contenu, a),
        Action::Retirer(p, f, empreinte) => {
            let meme = a.fiche(p).is_some_and(|g| meme_fichier(&g, f)) && a.empreinte(p, f).as_ref() == Some(empreinte);
            if !meme {
                return Err(refus(change_pendant_la_question()));
            }
            a.retirer(p)
        }
        Action::Unites(actions, u) => {
            for act in actions {
                s.unite(*act, u.as_str())?;
            }
            Ok(())
        }
        Action::Reecrire(p, f, contenu) => a.ecrire(
            p,
            contenu,
            Ecriture {
                mode: f.mode,
                uid: f.uid,
                gid: f.gid,
                avant: Some(*f),
            },
        ),
        Action::Suite(liste) => {
            for x in liste {
                agir(x, a, s)?;
            }
            Ok(())
        }
        Action::CreerDossier(p, mode) => a.creer_dossier(p, *mode),
        Action::Ecrire(p, contenu, mode) => a.ecrire(
            p,
            contenu,
            Ecriture {
                mode: *mode,
                uid: 0,
                gid: 0,
                avant: None,
            },
        ),
        Action::UniteSysteme(act, u) => s.unite(*act, u),
        Action::PoserSsh {
            fichier,
            contenu,
            reglage,
            unite,
        } => systeme::poser_ssh(fichier, contenu, *reglage, *unite, a, s),
        Action::Arreter(pid, v) => programme::arreter(*pid, v, a),
        Action::RemettreProgramme {
            chemin,
            fiche,
            empreinte,
            quarantaine,
            copier,
        } => pose::remettre(chemin, fiche, empreinte, quarantaine, *copier, a),
        Action::Nft { contenu, appliquer } => pare_feu::nft_fichier(contenu, *appliquer, a),
    }
}

/// Le même fichier : même disque, même inode, même genre.
fn meme_fichier(a: &Fiche, b: &Fiche) -> bool {
    a.dev == b.dev && a.ino == b.ino && a.genre == b.genre
}

fn lancer_ok(a: &mut dyn Acces, outil: &str, arguments: &[OsString]) -> Result<Sortie, Echec> {
    let Some(r) = a.lancer(outil, arguments) else {
        return Err(refus(trf!(
            "{outil} n'est pas installé dans les dossiers du système, ou n'a pas fini à temps",
            "{outil} is not installed in the system folders, or did not finish in time"
        )));
    };
    if r.code == Some(0) {
        return Ok(r);
    }
    let pourquoi = super::assistant::derniere_ligne(&r.erreurs).or_else(|| super::assistant::derniere_ligne(&r.sortie));
    let code = r.code.map_or_else(|| "signal".to_string(), |c| c.to_string());
    Err(echoue(match pourquoi {
        Some(l) => trf!(
            "{outil} a échoué (code {code}) : {l}",
            "{outil} failed (code {code}): {l}"
        ),
        None => trf!("{outil} a échoué (code {code})", "{outil} failed (code {code})"),
    }))
}

fn os(t: &str) -> OsString {
    OsString::from(t)
}

// ————— Comptes —————

/// /etc/passwd, /etc/shadow et /etc/group, relus par root.
struct Comptes {
    passwd: String,
    shadow: String,
    group: String,
}

fn lire_texte(a: &dyn Acces, p: &str) -> Result<String, Echec> {
    a.lire(Path::new(p), COMPTES_MAX)
        .and_then(|o| String::from_utf8(o).ok())
        .ok_or_else(|| {
            refus(trf!(
                "{p} ne se lit pas : rien n'est fait",
                "{p} cannot be read: nothing is done"
            ))
        })
}

impl Comptes {
    fn lire(a: &dyn Acces) -> Result<Self, Echec> {
        Ok(Comptes {
            passwd: lire_texte(a, PASSWD)?,
            shadow: lire_texte(a, SHADOW)?,
            group: lire_texte(a, GROUP)?,
        })
    }

    /// Les champs de la seule ligne de `nom` dans `texte` ; deux lignes, ou aucune : refusé.
    fn ligne<'a>(texte: &'a str, nom: &str, fichier: &str) -> Result<Vec<&'a str>, Echec> {
        let lignes: Vec<&str> = texte.lines().filter(|l| l.split(':').next() == Some(nom)).collect();
        match lignes.as_slice() {
            [l] => Ok(l.split(':').collect()),
            _ => Err(refus(trf!(
                "le compte {nom} n'a pas exactement une ligne dans {fichier} : rien n'est fait",
                "the account {nom} does not have exactly one line in {fichier}: nothing is done"
            ))),
        }
    }

    /// uid, gid et shell de `nom`.
    fn passwd_de(&self, nom: &str) -> Result<(u32, u32, String), Echec> {
        let champs = Self::ligne(&self.passwd, nom, PASSWD)?;
        let illisible = || {
            refus(trf!(
                "la ligne de {nom} dans {PASSWD} ne se lit pas",
                "the line of {nom} in {PASSWD} cannot be read"
            ))
        };
        let [_, _, uid, gid, _, _, shell] = champs.as_slice() else {
            return Err(illisible());
        };
        Ok((
            uid.parse().map_err(|_| illisible())?,
            gid.parse().map_err(|_| illisible())?,
            (*shell).to_string(),
        ))
    }

    /// Mot de passe chiffré et date d'expiration (en jours, texte tel quel) de `nom`.
    fn shadow_de(&self, nom: &str) -> Result<(String, String), Echec> {
        let champs = Self::ligne(&self.shadow, nom, SHADOW)?;
        match (champs.get(1), champs.get(7), champs.len()) {
            (Some(h), Some(e), 8 | 9) => Ok(((*h).to_string(), (*e).to_string())),
            _ => Err(refus(trf!(
                "la ligne de {nom} dans {SHADOW} ne se lit pas",
                "the line of {nom} in {SHADOW} cannot be read"
            ))),
        }
    }

    /// Le compte peut-il s'ouvrir par son mot de passe aujourd'hui (`jour` : jours depuis 1970) ?
    fn mot_de_passe_utilisable(&self, nom: &str, jour: u64) -> bool {
        let Ok((hash, expire)) = self.shadow_de(nom) else {
            return false;
        };
        let expire = expire.trim();
        !hash.is_empty()
            && !hash.starts_with('!')
            && !hash.starts_with('*')
            && (expire.is_empty() || expire.parse::<u64>().is_ok_and(|e| e > jour))
            && self.passwd_de(nom).is_ok_and(|(_, _, shell)| !shell_ferme(&shell))
    }

    /// Les comptes du groupe des administrateurs (wheel, sudo, admin) : membres ajoutés et groupe principal.
    fn administrateurs(&self) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        for l in self.group.lines() {
            let champs: Vec<&str> = l.split(':').collect();
            let [nom, _, gid, membres] = champs.as_slice() else {
                continue;
            };
            if !GroupeSensible::Administrateurs.noms().contains(nom) {
                continue;
            }
            v.extend(
                membres
                    .split(',')
                    .map(str::trim)
                    .filter(|m| !m.is_empty())
                    .map(String::from),
            );
            v.extend(self.passwd.lines().filter_map(|p| {
                let c: Vec<&str> = p.split(':').collect();
                (c.get(3) == Some(gid))
                    .then(|| c.first().map(|n| (*n).to_string()))
                    .flatten()
            }));
        }
        v.sort();
        v.dedup();
        v
    }

    /// Reste-t-il un chemin vers les droits d'administrateur sans `sauf` : root avec un mot de passe utilisable
    /// (« su - »), ou un autre administrateur qui en a un ?
    fn autre_administrateur(&self, sauf: &str, jour: u64) -> bool {
        (sauf != "root" && self.mot_de_passe_utilisable("root", jour))
            || self
                .administrateurs()
                .iter()
                .any(|n| n != sauf && n != "root" && self.mot_de_passe_utilisable(n, jour))
    }
}

/// Un shell qui refuse l'ouverture de session.
fn shell_ferme(shell: &str) -> bool {
    shell.ends_with("/nologin") || shell == "/bin/false" || shell == "/usr/bin/false"
}

/// Une valeur notée reprise dans une commande : du texte imprimable d'ASCII, sans « : » (le séparateur des fichiers
/// de comptes) ; un shell commence par « / ».
fn shell_admis(s: &str) -> bool {
    s.starts_with('/') && s.len() <= 256 && s.bytes().all(|o| o.is_ascii_graphic() && o != b':')
}

fn expiration_admise(e: &str) -> bool {
    e.len() <= 12 && e.bytes().all(|o| o.is_ascii_digit())
}

fn jour(a: &dyn Acces) -> u64 {
    a.date() / 86_400
}

fn juger_verrou(n: NomCompte, a: &mut dyn Acces) -> Jugement {
    let nom = n.as_str();
    let c = Comptes::lire(a)?;
    let (uid, _, shell) = c.passwd_de(nom)?;
    let (hash, expire) = c.shadow_de(nom)?;
    let root = nom == "root";
    // root, un compte caché de uid 0, ou celui d'une personne ; jamais un compte du système (un service tomberait).
    if !(uid == 0 || ((1000..=60_000).contains(&uid) && uid != 65_534)) {
        return Err(refus(trf!(
            "{nom} est un compte du système (uid {uid}) : Vanguard ne le verrouille pas",
            "{nom} is a system account (uid {uid}): Vanguard does not lock it"
        )));
    }
    let verrouille = hash.starts_with('!') || hash.starts_with('*');
    let nologin = if root {
        None
    } else {
        let trouve = NOLOGIN.iter().find(|p| {
            a.fiche(Path::new(p))
                .is_some_and(|f| f.genre == Genre::Fichier && f.uid == 0)
        });
        Some(trouve.ok_or_else(|| {
            refus(
                tr!(
                    "le programme nologin est introuvable : rien n'est fait",
                    "the nologin program cannot be found: nothing is done"
                )
                .to_string(),
            )
        })?)
    };
    let fait = if root {
        verrouille
    } else {
        verrouille && expire.trim() == "1" && shell_ferme(&shell)
    };
    if fait {
        return Ok(None);
    }
    let j = jour(a);
    let personnes = a.personnes();
    let mut raisons = Vec::new();
    if root {
        raisons.push(tr!(
            "c'est le compte root lui-même : « su - » et la console de secours ne s'ouvriront plus avec son mot de passe (sudo continue de marcher pour les administrateurs)",
            "this is the root account itself: \"su -\" and the rescue console will no longer open with its password (sudo keeps working for administrators)"
        ));
    }
    if personnes.contains(&uid) {
        raisons.push(tr!(
            "c'est votre propre compte, celui de cette session : il ne s'ouvrira plus, ni par mot de passe ni par clé SSH ; cette session continue jusqu'à sa fermeture",
            "this is your own account, the one of this session: it will no longer open, neither by password nor by SSH key; this session goes on until it is closed"
        ));
    }
    // Même sans mot de passe à lui (clé SSH seule, règle NOPASSWD), le dernier administrateur verrouillé ferme tout.
    if !c.autre_administrateur(nom, j) && (root || c.administrateurs().iter().any(|x| x == nom)) {
        raisons.push(tr!(
            "aucun autre administrateur n'a de mot de passe utilisable : après ce geste, plus personne ne pourra devenir administrateur",
            "no other administrator has a usable password: after this step, no one will be able to become administrator"
        ));
    }
    let avertissement = (!raisons.is_empty()).then(|| {
        trf!(
            "{}. Pour revenir : Défaire dans Vanguard avant de fermer cette session, ou depuis un autre compte administrateur ; sinon, démarrer sur une clé USB de secours (live USB) et retirer le « ! » devant le mot de passe dans /etc/shadow.",
            "{}. To come back: Undo in Vanguard before closing this session, or from another administrator account; otherwise, start from a rescue USB stick (live USB) and remove the \"!\" in front of the password in /etc/shadow.",
            raisons.join(" ; ")
        )
    });
    let mut arguments = vec![os("--lock")];
    if let Some(nl) = nologin {
        arguments.extend([os("--expiredate"), os("1"), os("--shell"), os(nl)]);
    }
    arguments.extend([os("--"), os(nom)]);
    let etat = if verrouille {
        tr!("déjà verrouillé", "already locked")
    } else if hash.is_empty() {
        tr!(
            "vide (Défaire rouvrira le compte, mais ne remettra pas un mot de passe vide)",
            "empty (Undo will reopen the account, but will not put back an empty password)"
        )
    } else {
        tr!("actif", "active")
    };
    // « vide » : usermod --unlock refuse de rendre un mot de passe vide ; Défaire rouvre sans lui.
    let note_verrou: &[u8] = if hash.starts_with('!') {
        b"oui"
    } else if hash.is_empty() {
        b"vide"
    } else {
        b"non"
    };
    Ok(Some(Plan {
        texte: trf!(
            "Compte {nom} (uid {uid}), mot de passe {etat}, shell {}.",
            "Account {nom} (uid {uid}), password {etat}, shell {}.",
            echappe(shell.as_bytes())
        ),
        avertissement,
        non_annulable: false,
        seconde: None,
        champs: vec![
            ("verrouille".into(), note_verrou.to_vec()),
            ("expiration".into(), expire.into_bytes()),
            ("shell".into(), shell.into_bytes()),
            ("uid".into(), uid.to_string().into_bytes()),
        ],
        action: Action::Outils(vec![("usermod", arguments)]),
    }))
}

fn remettre_verrou(n: NomCompte, note: &Note, a: &mut dyn Acces) -> Jugement {
    let nom = n.as_str();
    let c = Comptes::lire(a)?;
    let (uid, _, shell) = c.passwd_de(nom)?;
    let (hash, expire) = c.shadow_de(nom)?;
    if note.texte("uid") != Some(uid.to_string().as_str()) {
        return Err(change_depuis(nom));
    }
    let mut arguments = Vec::new();
    if note.texte("verrouille") == Some("non") && hash.starts_with('!') {
        arguments.push(os("--unlock"));
    }
    if nom != "root" {
        let ancienne = note
            .texte("expiration")
            .filter(|e| expiration_admise(e))
            .ok_or_else(note_abimee)?;
        if expire != ancienne {
            arguments.extend([os("--expiredate"), os(ancienne)]);
        }
        let ancien = note.texte("shell").filter(|s| shell_admis(s)).ok_or_else(note_abimee)?;
        if shell != ancien {
            arguments.extend([os("--shell"), os(ancien)]);
        }
    }
    if arguments.is_empty() {
        return Ok(None);
    }
    arguments.extend([os("--"), os(nom)]);
    let texte = if note.texte("verrouille") == Some("vide") {
        trf!(
            "Compte {nom} : rouvert, sans mot de passe (il était vide ; pour en donner un : « passwd {nom} », en administrateur).",
            "Account {nom}: reopened, without a password (it was empty; to give one: \"passwd {nom}\", as administrator)."
        )
    } else {
        trf!(
            "Compte {nom} : rouvert comme avant.",
            "Account {nom}: reopened as before."
        )
    };
    Ok(Some(Plan {
        texte,
        avertissement: None,
        non_annulable: false,
        seconde: None,
        champs: Vec::new(),
        action: Action::Outils(vec![("usermod", arguments)]),
    }))
}

fn change_depuis(quoi: &str) -> Echec {
    refus(trf!(
        "{quoi} a changé depuis le geste : rien n'est remis, pour ne pas écraser ce changement",
        "{quoi} changed since the step: nothing is put back, so as not to overwrite that change"
    ))
}

fn note_abimee() -> Echec {
    refus(tr!(
        "la note d'« avant » ne se lit pas : rien n'est remis",
        "the \"before\" note cannot be read: nothing is put back"
    ))
}

/// Les groupes de `g` dont `nom` est membre ajouté ; un groupe de la famille qui est son groupe principal : refusé
/// (gpasswd ne l'en sort pas, la commande reste à faire soi-même).
fn groupes_membre(c: &Comptes, g: GroupeSensible, nom: &str) -> Result<Vec<String>, Echec> {
    let (_, gid, _) = c.passwd_de(nom)?;
    let mut v = Vec::new();
    for l in c.group.lines() {
        let champs: Vec<&str> = l.split(':').collect();
        let [groupe, _, gid_g, membres] = champs.as_slice() else {
            continue;
        };
        if !g.noms().contains(groupe) {
            continue;
        }
        if gid_g.parse::<u32>().ok() == Some(gid) {
            return Err(refus(trf!(
                "{groupe} est le groupe principal de {nom} : Vanguard ne le change pas (usermod -g, à faire soi-même)",
                "{groupe} is the primary group of {nom}: Vanguard does not change it (usermod -g, to do yourself)"
            )));
        }
        if membres.split(',').any(|m| m.trim() == nom) {
            v.push((*groupe).to_string());
        }
    }
    Ok(v)
}

fn juger_groupe(g: GroupeSensible, n: NomCompte, a: &mut dyn Acces) -> Jugement {
    let nom = n.as_str();
    let c = Comptes::lire(a)?;
    let (uid, _, _) = c.passwd_de(nom)?;
    let groupes = groupes_membre(&c, g, nom)?;
    if groupes.is_empty() {
        return Ok(None);
    }
    let mut avertissement = None;
    if g == GroupeSensible::Administrateurs {
        let j = jour(a);
        let mut raisons = Vec::new();
        if a.personnes().contains(&uid) {
            raisons.push(tr!(
                "vous retirez votre propre compte des administrateurs : à votre prochaine session, sudo vous sera refusé",
                "you are removing your own account from the administrators: at your next session, sudo will be refused to you"
            ));
        }
        if !c.autre_administrateur(nom, j) {
            raisons.push(tr!(
                "c'est le dernier administrateur qui ait un mot de passe utilisable, et root n'en a pas : après sa prochaine session, plus personne ne pourra devenir administrateur",
                "this is the last administrator with a usable password, and root has none: after its next session, no one will be able to become administrator"
            ));
        }
        if !raisons.is_empty() {
            avertissement = Some(trf!(
                "{}. Cette session garde ses droits jusqu'à sa fermeture. Pour revenir : Défaire dans Vanguard avant de la fermer ; sinon « su - » si root a un mot de passe, ou une clé USB de secours (live USB).",
                "{}. This session keeps its rights until it is closed. To come back: Undo in Vanguard before closing it; otherwise \"su -\" if root has a password, or a rescue USB stick (live USB).",
                raisons.join(" ; ")
            ));
        }
    }
    let liste = groupes.join(", ");
    Ok(Some(Plan {
        texte: trf!(
            "Compte {nom}, membre de : {liste}. Effectif à sa prochaine session.",
            "Account {nom}, member of: {liste}. Effective at its next session."
        ),
        avertissement,
        non_annulable: false,
        seconde: None,
        champs: vec![("groupes".into(), groupes.join(",").into_bytes())],
        action: Action::Outils(
            groupes
                .iter()
                .map(|gr| ("gpasswd", vec![os("-d"), os(nom), os("--"), os(gr)]))
                .collect(),
        ),
    }))
}

fn remettre_groupe(g: GroupeSensible, n: NomCompte, note: &Note, a: &mut dyn Acces) -> Jugement {
    let nom = n.as_str();
    let c = Comptes::lire(a)?;
    let notes = note.texte("groupes").ok_or_else(note_abimee)?;
    let notes: Vec<&str> = notes.split(',').collect();
    if notes.iter().any(|gr| !g.noms().contains(gr)) {
        return Err(note_abimee());
    }
    let membre = groupes_membre(&c, g, nom)?;
    let existe = |gr: &str| c.group.lines().any(|l| l.split(':').next() == Some(gr));
    let a_remettre: Vec<&str> = notes
        .into_iter()
        .filter(|gr| existe(gr) && !membre.iter().any(|m| m == gr))
        .collect();
    if a_remettre.is_empty() {
        return Ok(None);
    }
    Ok(Some(Plan {
        texte: trf!(
            "Compte {nom} : remis dans {} (effectif à sa prochaine session).",
            "Account {nom}: put back into {} (effective at its next session).",
            a_remettre.join(", ")
        ),
        avertissement: None,
        non_annulable: false,
        seconde: None,
        champs: Vec::new(),
        action: Action::Outils(
            a_remettre
                .iter()
                .map(|gr| ("gpasswd", vec![os("-a"), os(nom), os("--"), os(gr)]))
                .collect(),
        ),
    }))
}

// ————— sudo —————

/// Ce qui laisse sudo donner les droits sans le mot de passe de ce compte, d'après `sudo -l -U` (en anglais).
#[derive(Debug, PartialEq)]
pub(crate) struct ProblemesSudo {
    jamais: bool,
    delai: Option<f64>,
    /// Les comptes cibles (« ALL : ALL ») des règles « NOPASSWD: ALL » qui valent encore.
    cibles: Vec<String>,
}

impl ProblemesSudo {
    /// Quelque chose que le complément de sudo corrige (ce que l'enfant rejuge avant de rien poser).
    pub(crate) fn a_corriger(&self) -> bool {
        self.jamais || self.delai.is_some() || !self.cibles.is_empty()
    }
}

pub(crate) fn problemes_sudo(liste: &str) -> Result<ProblemesSudo, Echec> {
    let (jamais, delai) = crate::machine::unix::defauts_sudo(liste);
    let (totales, _) = crate::machine::unix::regles_nopasswd(liste);
    let mut cibles = Vec::new();
    for l in totales {
        let cible = l
            .strip_prefix('(')
            .and_then(|r| r.split_once(')'))
            .filter(|(c, reste)| {
                reste.trim() == "NOPASSWD: ALL"
                    && !c.is_empty()
                    && c.bytes().all(|o| o.is_ascii_alphanumeric() || b"_%: ,.-".contains(&o))
            })
            .map(|(c, _)| c.to_string());
        let Some(cible) = cible else {
            return Err(refus(trf!(
                "une règle sudo sans mot de passe n'a pas la forme simple que Vanguard sait corriger ({}) : à corriger soi-même avec sudo visudo",
                "a passwordless sudo rule does not have the simple form Vanguard can fix ({}): fix it yourself with sudo visudo",
                echappe(l.as_bytes())
            )));
        };
        if !cibles.contains(&cible) {
            cibles.push(cible);
        }
    }
    Ok(ProblemesSudo {
        jamais,
        delai: delai.filter(|m| *m < 0.0 || *m > 60.0),
        cibles,
    })
}

fn chemin_sudo(nom: NomCompte) -> PathBuf {
    Path::new(SUDOERS_D).join(format!("zz-vanguard-{}", nom.as_str()))
}

fn chemin_sudo_provisoire(nom: NomCompte) -> PathBuf {
    Path::new(SUDOERS_D).join(format!(".zz-vanguard-{}.tmp", nom.as_str()))
}

fn liste_sudo(nom: NomCompte, a: &mut dyn Acces) -> Result<ProblemesSudo, Echec> {
    let r = lancer_ok(a, "sudo", &[os("-n"), os("-l"), os("-U"), os(nom.as_str())])?;
    problemes_sudo(&r.sortie)
}

fn juger_sudo(n: NomCompte, a: &mut dyn Acces) -> Jugement {
    let nom = n.as_str();
    // sudo saute les fichiers de /etc/sudoers.d dont le nom contient un point : le complément n'aurait aucun effet.
    if nom.contains('.') {
        return Err(refus(trf!(
            "le nom {nom} contient un point : sudo ne lirait pas le complément, rien n'est fait (à corriger soi-même avec sudo visudo)",
            "the name {nom} contains a dot: sudo would not read the addition, nothing is done (fix it yourself with sudo visudo)"
        )));
    }
    let c = Comptes::lire(a)?;
    let _ = c.passwd_de(nom)?;
    let sudoers = lire_texte(a, SUDOERS)?;
    if !sudoers
        .lines()
        .map(str::trim)
        .any(|l| l == "@includedir /etc/sudoers.d" || l == "#includedir /etc/sudoers.d")
    {
        return Err(refus(
            tr!(
                "/etc/sudoers ne lit pas /etc/sudoers.d : rien n'est fait (à corriger soi-même avec sudo visudo)",
                "/etc/sudoers does not read /etc/sudoers.d: nothing is done (fix it yourself with sudo visudo)"
            )
            .to_string(),
        ));
    }
    let p = liste_sudo(n, a)?;
    if !p.a_corriger() {
        return Ok(None);
    }
    if a.fiche(&chemin_sudo(n)).is_some() {
        return Err(refus(
            tr!(
                "un complément de Vanguard est déjà posé pour ce compte : Défaire d'abord, puis refaire",
                "a Vanguard addition is already in place for this account: Undo first, then do it again"
            )
            .to_string(),
        ));
    }
    let mut contenu = String::from("# Vanguard : geste de defense / defense step. Defaire (Undo) le retire.\n");
    let mut faits = Vec::new();
    if p.jamais {
        let _ = writeln!(contenu, "Defaults:{nom} authenticate");
        faits.push(
            tr!(
                "sudo ne demande jamais le mot de passe",
                "sudo never asks for the password"
            )
            .to_string(),
        );
    }
    if let Some(m) = p.delai {
        let _ = writeln!(contenu, "Defaults:{nom} timestamp_timeout=5");
        faits.push(trf!(
            "sudo garde le mot de passe {} minutes (ramené à 5)",
            "sudo keeps the password for {} minutes (brought back to 5)",
            m.round()
        ));
    }
    for cible in &p.cibles {
        let _ = writeln!(contenu, "{nom} ALL=({cible}) PASSWD: ALL");
        faits.push(trf!(
            "règle « ({cible}) NOPASSWD: ALL » : le mot de passe sera redemandé",
            "rule \"({cible}) NOPASSWD: ALL\": the password will be asked again"
        ));
    }
    // Sans mot de passe utilisable, sudo lui demanderait un mot de passe qu'il n'a pas : la personne perdrait sudo,
    // et Défaire, qui passe par sudo, ne pourrait plus la tirer de là. Refusé, sans question.
    if !c.mot_de_passe_utilisable(nom, jour(a)) {
        return Err(refus(trf!(
            "le compte {nom} n'a pas de mot de passe utilisable : sudo lui demanderait un mot de passe qu'il n'a pas, et ne marcherait plus pour lui. Donnez-lui d'abord un mot de passe (« passwd {nom} », en administrateur), puis refaites ce geste",
            "the account {nom} has no usable password: sudo would ask it for a password it does not have, and would no longer work for it. Give it a password first (\"passwd {nom}\", as administrator), then do this step again"
        )));
    }
    // Ce complément ne fait que redemander le mot de passe (que le compte a) : sudo reste le chemin du retour.
    let avertissement = (!a.outil("pkexec") && !a.outil("run0")).then(|| {
        trf!(
            "ni pkexec ni run0 n'est installé : sudo restera le seul chemin vers les droits d'administrateur. Pour revenir : Défaire dans Vanguard (sudo demandera votre mot de passe), « su - » si root a un mot de passe, ou une clé USB de secours (live USB) pour retirer {}.",
            "neither pkexec nor run0 is installed: sudo will remain the only way to administrator rights. To come back: Undo in Vanguard (sudo will ask for your password), \"su -\" if root has a password, or a rescue USB stick (live USB) to remove {}.",
            chemin_sudo(n).display()
        )
    });
    Ok(Some(Plan {
        texte: trf!(
            "Compte {nom} : {}. Complément posé : {} (validé par visudo avant d'être posé).",
            "Account {nom}: {}. Addition put in place: {} (checked by visudo before being put in place).",
            faits.join(" ; "),
            chemin_sudo(n).display()
        ),
        avertissement,
        non_annulable: false,
        seconde: None,
        champs: vec![("contenu".into(), contenu.clone().into_bytes())],
        action: Action::PoserSudo {
            nom: n,
            contenu: contenu.into_bytes(),
        },
    }))
}

/// Pose le complément de sudo : écrit sous un nom que sudo ignore (il contient un point), validé seul par visudo,
/// mis à sa place sans rien remplacer, puis toute la configuration revalidée. Le moindre échec le retire : sudo n'est
/// jamais laissé avec une configuration refusée.
fn poser_sudo(n: NomCompte, contenu: &[u8], a: &mut dyn Acces) -> Result<(), Echec> {
    let provisoire = chemin_sudo_provisoire(n);
    let final_ = chemin_sudo(n);
    // Un reste d'une coupure d'avant (à root, ignoré par sudo) : retiré avant d'écrire.
    if a.fiche(&provisoire)
        .is_some_and(|f| f.genre == Genre::Fichier && f.uid == 0)
    {
        a.retirer(&provisoire)?;
    }
    a.ecrire(
        &provisoire,
        contenu,
        Ecriture {
            mode: 0o440,
            uid: 0,
            gid: 0,
            avant: None,
        },
    )?;
    if let Err(r) = lancer_ok(
        a,
        "visudo",
        &[os("-c"), os("-q"), os("-f"), provisoire.clone().into_os_string()],
    ) {
        let _ = a.retirer(&provisoire);
        return Err(refus(trf!(
            "visudo refuse le complément, rien n'est posé : {r}",
            "visudo refuses the addition, nothing is put in place: {r}"
        )));
    }
    if let Err(r) = a.deplacer(&provisoire, &final_) {
        let _ = a.retirer(&provisoire);
        return Err(r);
    }
    if let Err(r) = lancer_ok(a, "visudo", &[os("-c"), os("-q")]) {
        let _ = a.retirer(&final_);
        return Err(refus(trf!(
            "visudo refuse la configuration entière, le complément est retiré : {r}",
            "visudo refuses the whole configuration, the addition is removed: {r}"
        )));
    }
    match liste_sudo(n, a) {
        Ok(p) if !p.jamais && p.delai.is_none() && p.cibles.is_empty() => Ok(()),
        _ => {
            let _ = a.retirer(&final_);
            Err(refus(
                tr!(
                    "le complément n'a pas l'effet voulu (une règle venue après lui l'emporte) : il est retiré",
                    "the addition does not have the intended effect (a later rule wins over it): it is removed"
                )
                .to_string(),
            ))
        }
    }
}

fn remettre_sudo(n: NomCompte, note: &Note, a: &mut dyn Acces) -> Jugement {
    let p = chemin_sudo(n);
    let contenu = note.champ("contenu").ok_or_else(note_abimee)?;
    let Some(f) = a.fiche(&p) else {
        return Ok(None);
    };
    let attendu: [u8; 32] = Sha256::digest(contenu).into();
    if f.genre != Genre::Fichier || f.uid != 0 || a.empreinte(&p, &f) != Some(attendu) {
        return Err(change_depuis(&p.display().to_string()));
    }
    Ok(Some(Plan {
        texte: trf!(
            "Retirer {} : sudo redevient comme avant.",
            "Remove {}: sudo goes back to how it was.",
            p.display()
        ),
        avertissement: None,
        non_annulable: false,
        seconde: None,
        champs: Vec::new(),
        action: Action::Retirer(p, f, attendu),
    }))
}

// ————— Droits de programmes et dossiers —————

fn lisible(p: &Path) -> String {
    echappe(p.as_os_str().as_bytes())
}

/// Le fichier désigné, s'il est son propre chemin réel (aucun lien sur le chemin) et de ce genre.
fn fiche_designee(p: &Path, genre: Genre, a: &dyn Acces) -> Result<Fiche, Echec> {
    let vu = lisible(p);
    let f = a.fiche(p).ok_or_else(|| {
        refus(trf!(
            "{vu} est introuvable : rien n'est fait",
            "{vu} cannot be found: nothing is done"
        ))
    })?;
    if f.genre != genre || a.reel(p).as_deref() != Some(p) {
        return Err(refus(trf!(
            "{vu} n'est pas ce qui a été désigné (un lien, ou autre chose) : rien n'est fait",
            "{vu} is not what was named (a link, or something else): nothing is done"
        )));
    }
    Ok(f)
}

/// Le paquet, dit : `Ok(None)` pour aucun paquet, `Ok(Some(..))` pour un fichier modifié ; intact ou illisible :
/// refusé.
fn paquet_suspect(p: &Path, a: &dyn Acces) -> Result<Option<String>, Echec> {
    let vu = lisible(p);
    match a.paquet(p) {
        EtatPaquet::Aucun => Ok(None),
        EtatPaquet::Modifie(nom) => Ok(Some(echappe(nom.as_bytes()))),
        EtatPaquet::Intact(nom) => Err(refus(trf!(
            "{vu} vient intact du paquet {} : Vanguard n'y touche pas",
            "{vu} comes intact from the package {}: Vanguard does not touch it",
            echappe(nom.as_bytes())
        ))),
        EtatPaquet::Illisible => Err(refus(trf!(
            "le gestionnaire de paquets ne dit pas d'où vient {vu} : rien n'est fait",
            "the package manager does not say where {vu} comes from: nothing is done"
        ))),
    }
}

/// Reste-t-il, sans `p`, un programme qui donne les droits d'administrateur par setuid ?
fn elevateur_restant(p: &Path, a: &dyn Acces) -> bool {
    // su ne sert que si root a un mot de passe (Debian et Ubuntu le verrouillent), pkexec que si un administrateur en
    // a un ; sudo et doas se règlent aussi par leurs fichiers : leur seule présence compte.
    let j = jour(a);
    let comptes = Comptes::lire(a).ok();
    let su_ouvre = comptes.as_ref().is_some_and(|c| c.mot_de_passe_utilisable("root", j));
    let pkexec_ouvre = comptes
        .as_ref()
        .is_some_and(|c| c.administrateurs().iter().any(|x| c.mot_de_passe_utilisable(x, j)));
    ELEVATEURS.iter().any(|e| {
        let ouvre = match e.rsplit('/').next() {
            Some("su") => su_ouvre,
            Some("pkexec") => pkexec_ouvre,
            _ => true,
        };
        ouvre
            && a.reel(Path::new(e)).is_some_and(|r| {
                r != p
                    && a.fiche(&r)
                        .is_some_and(|f| f.genre == Genre::Fichier && f.uid == 0 && f.mode & 0o4000 != 0)
            })
    })
}

fn juger_droits(c: &CheminDesigne, capacites: bool, a: &mut dyn Acces) -> Jugement {
    let p = chemin_de(c);
    let vu = lisible(&p);
    let f = fiche_designee(&p, Genre::Fichier, a)?;
    let caps = if capacites {
        match a.capacites(&p, &f) {
            Ok(Some(v)) if !v.is_empty() => v,
            Ok(_) => return Ok(None),
            Err(()) => {
                return Err(refus(trf!(
                    "les capacités de {vu} ne se lisent pas : rien n'est fait",
                    "the capabilities of {vu} cannot be read: nothing is done"
                )));
            }
        }
    } else {
        if f.mode & 0o6000 == 0 {
            return Ok(None);
        }
        Vec::new()
    };
    let suspect_par_place = DOSSIERS_SUSPECTS
        .iter()
        .any(|d| p.as_os_str().as_bytes().starts_with(d.as_bytes()));
    let d_ou = if suspect_par_place {
        tr!(
            "dans un dossier temporaire ou personnel",
            "in a temporary or personal folder"
        )
        .to_string()
    } else {
        match paquet_suspect(&p, a)? {
            None => tr!("à aucun paquet", "from no package").to_string(),
            Some(nom) => trf!("modifié depuis son paquet {nom}", "modified since its package {nom}"),
        }
    };
    let empreinte = a.empreinte(&p, &f).ok_or_else(|| {
        refus(trf!(
            "{vu} ne se lit pas : rien n'est fait",
            "{vu} cannot be read: nothing is done"
        ))
    })?;
    let mut avertissement = None;
    let mut non_annulable = false;
    if !capacites && f.mode & 0o4000 != 0 && f.uid == 0 && !elevateur_restant(&p, a) {
        let run0 = a.outil("run0");
        non_annulable = !run0;
        avertissement = Some(trf!(
            "après ce geste, ni sudo, ni su, ni pkexec ne pourra plus donner les droits d'administrateur (ils ont besoin de ce droit). Pour revenir : {}, puis chmod u+s {vu}.",
            "after this step, neither sudo, su nor pkexec will be able to give administrator rights any more (they need this right). To come back: {}, then chmod u+s {vu}.",
            if run0 {
                tr!("run0 (encore là)", "run0 (still there)")
            } else {
                tr!("une clé USB de secours (live USB)", "a rescue USB stick (live USB)")
            }
        ));
    }
    let texte = if capacites {
        trf!(
            "Programme {vu}, {d_ou}, avec des capacités du noyau ({} octets).",
            "Program {vu}, {d_ou}, with kernel capabilities ({} bytes).",
            caps.len()
        )
    } else {
        trf!(
            "Programme {vu}, {d_ou}, mode {:04o}, à l'uid {}.",
            "Program {vu}, {d_ou}, mode {:04o}, owned by uid {}.",
            f.mode,
            f.uid
        )
    };
    let modif = if capacites {
        Modif::Capacites(None)
    } else {
        Modif::Mode(f.mode & 0o7777 & !0o6000)
    };
    Ok(Some(Plan {
        texte,
        avertissement,
        non_annulable,
        seconde: None,
        champs: vec![
            ("mode".into(), f.mode.to_string().into_bytes()),
            ("uid".into(), f.uid.to_string().into_bytes()),
            ("gid".into(), f.gid.to_string().into_bytes()),
            ("dev".into(), f.dev.to_string().into_bytes()),
            ("ino".into(), f.ino.to_string().into_bytes()),
            ("empreinte".into(), empreinte.to_vec()),
            ("capacites".into(), caps),
        ],
        action: Action::Changer(p, f, vec![modif]),
    }))
}

fn nombre<T: std::str::FromStr>(note: &Note, cle: &str) -> Result<T, Echec> {
    note.texte(cle).and_then(|t| t.parse().ok()).ok_or_else(note_abimee)
}

/// Le fichier désigné est-il encore celui de la note (même disque, même inode) ?
fn encore_celui_de_la_note(p: &Path, f: &Fiche, note: &Note) -> Result<(), Echec> {
    if nombre::<u64>(note, "dev")? != f.dev || nombre::<u64>(note, "ino")? != f.ino {
        return Err(change_depuis(&lisible(p)));
    }
    Ok(())
}

fn remettre_droits(c: &CheminDesigne, capacites: bool, note: &Note, a: &mut dyn Acces) -> Jugement {
    let p = chemin_de(c);
    let f = fiche_designee(&p, Genre::Fichier, a)?;
    encore_celui_de_la_note(&p, &f, note)?;
    if a.empreinte(&p, &f).as_ref().map(<[u8; 32]>::as_slice) != note.champ("empreinte") {
        return Err(change_depuis(&lisible(&p)));
    }
    let modif = if capacites {
        let anciennes = note
            .champ("capacites")
            .filter(|v| !v.is_empty())
            .ok_or_else(note_abimee)?;
        if a.capacites(&p, &f).ok().flatten().as_deref() == Some(anciennes) {
            return Ok(None);
        }
        Modif::Capacites(Some(anciennes.to_vec()))
    } else {
        let mode: u32 = nombre(note, "mode")?;
        if mode > 0o7777 {
            return Err(note_abimee());
        }
        if f.mode == mode {
            return Ok(None);
        }
        Modif::Mode(mode)
    };
    Ok(Some(Plan {
        texte: trf!(
            "Programme {} : remis comme avant.",
            "Program {}: put back as before.",
            lisible(&p)
        ),
        avertissement: None,
        non_annulable: false,
        seconde: None,
        champs: Vec::new(),
        action: Action::Changer(p, f, vec![modif]),
    }))
}

fn juger_dossier(c: &CheminDesigne, a: &mut dyn Acces) -> Jugement {
    let p = chemin_de(c);
    let vu = lisible(&p);
    if !DOSSIERS_DE_ROOT.iter().any(|d| Path::new(d) == p) {
        return Err(refus(trf!(
            "{vu} n'est pas un dossier de commandes de root : rien n'est fait",
            "{vu} is not one of root's command folders: nothing is done"
        )));
    }
    let f = fiche_designee(&p, Genre::Dossier, a)?;
    if f.uid == 0 && f.mode & 0o022 == 0 {
        return Ok(None);
    }
    Ok(Some(Plan {
        texte: trf!(
            "Dossier {vu}, à l'uid {} et au gid {}, mode {:04o} : rendu à root (0:0), sans écriture du groupe ni des autres.",
            "Folder {vu}, owned by uid {} and gid {}, mode {:04o}: given back to root (0:0), without write access for the group or others.",
            f.uid,
            f.gid,
            f.mode
        ),
        avertissement: None,
        non_annulable: false,
        seconde: None,
        champs: vec![
            ("mode".into(), f.mode.to_string().into_bytes()),
            ("uid".into(), f.uid.to_string().into_bytes()),
            ("gid".into(), f.gid.to_string().into_bytes()),
            ("dev".into(), f.dev.to_string().into_bytes()),
            ("ino".into(), f.ino.to_string().into_bytes()),
        ],
        action: Action::Changer(
            p,
            f,
            vec![Modif::Proprietaire(0, 0), Modif::Mode(f.mode & 0o7777 & !0o022)],
        ),
    }))
}

fn remettre_dossier(c: &CheminDesigne, note: &Note, a: &mut dyn Acces) -> Jugement {
    let p = chemin_de(c);
    let f = fiche_designee(&p, Genre::Dossier, a)?;
    encore_celui_de_la_note(&p, &f, note)?;
    let (mode, uid, gid): (u32, u32, u32) = (nombre(note, "mode")?, nombre(note, "uid")?, nombre(note, "gid")?);
    if mode > 0o7777 {
        return Err(note_abimee());
    }
    if (f.mode, f.uid, f.gid) == (mode, uid, gid) {
        return Ok(None);
    }
    Ok(Some(Plan {
        texte: trf!(
            "Dossier {} : rendu à l'uid {uid} et au gid {gid}, mode {mode:04o}, comme avant.",
            "Folder {}: given back to uid {uid} and gid {gid}, mode {mode:04o}, as before.",
            lisible(&p)
        ),
        avertissement: None,
        non_annulable: false,
        seconde: None,
        champs: Vec::new(),
        action: Action::Changer(p, f, vec![Modif::Proprietaire(uid, gid), Modif::Mode(mode)]),
    }))
}

// ————— Services —————

fn lance_au_demarrage(etat: &str) -> bool {
    etat.starts_with("enabled") || etat.starts_with("linked")
}

fn tourne(activite: &str) -> bool {
    matches!(activite, "active" | "activating" | "reloading" | "refreshing")
}

/// Le fichier d'un service ajouté à la main : dans /etc/systemd/system, fichier ordinaire de root fermé aux autres,
/// d'aucun paquet.
fn fichier_de_service(u: NomUnite, a: &dyn Acces) -> Result<(PathBuf, Fiche), Echec> {
    let p = Path::new("/etc/systemd/system").join(u.as_str());
    let vu = echappe(u.as_str().as_bytes());
    let f = fiche_designee(&p, Genre::Fichier, a)?;
    if f.uid != 0 || f.mode & 0o022 != 0 {
        return Err(refus(trf!(
            "le fichier de {vu} n'est pas à root, ou un autre compte peut le changer : rien n'est fait",
            "the file of {vu} is not root's, or another account can change it: nothing is done"
        )));
    }
    if let Some(nom) = paquet_suspect(&p, a)? {
        return Err(refus(trf!(
            "{vu} vient du paquet {nom} : ce n'est pas un service ajouté à la main",
            "{vu} comes from the package {nom}: it is not a service added by hand"
        )));
    }
    Ok((p, f))
}

fn juger_service(u: NomUnite, a: &mut dyn Acces, s: &mut dyn Services) -> Jugement {
    let nom = u.as_str();
    let (p, f) = fichier_de_service(u, a)?;
    if !s.fichier_sur(nom)? {
        return Err(refus(trf!(
            "{nom} n'est pas installé : rien n'est fait",
            "{nom} is not installed: nothing is done"
        )));
    }
    let etat = s.etat_du_fichier(nom)?.unwrap_or_default();
    let activite = s.etat_d_activite(nom)?.unwrap_or_default();
    if !lance_au_demarrage(&etat) && !tourne(&activite) {
        return Ok(None);
    }
    if let Some(lu) = s.arret_charge(nom)? {
        // Ce que l'arrêt lancerait est revu, et une session qui passe par lui (celle de Vanguard comprise) le refuse.
        arret_designe::juger_arret(nom, &lu, &|c| s.chemin(c))?;
        let lignee = s.groupes_de_la_lignee();
        let sessions = s.sessions().ok_or_else(|| refus(tr!(
                "les sessions ouvertes ne se lisent pas, et l'une d'elles passe peut-être par ce service : rien n'est fait",
                "the open sessions cannot be read, and one of them may go through this service: nothing is done"
            )
            .to_string()))?;
        if let Some(r) = arret_designe::porte_par_l_outil(nom, &lu.groupe, &lignee, &sessions) {
            return Err(refus(r));
        }
    }
    let empreinte = a.empreinte(&p, &f).ok_or_else(|| {
        refus(trf!(
            "le fichier de {nom} ne se lit pas",
            "the file of {nom} cannot be read"
        ))
    })?;
    let (etat_vu, activite_vue) = (echappe(etat.as_bytes()), echappe(activite.as_bytes()));
    Ok(Some(Plan {
        texte: trf!(
            "Service {nom}, ajouté à la main dans /etc/systemd/system (d'aucun paquet) : {etat_vu}, {activite_vue}.",
            "Service {nom}, added by hand in /etc/systemd/system (from no package): {etat_vu}, {activite_vue}."
        ),
        avertissement: None,
        non_annulable: false,
        seconde: None,
        champs: vec![
            ("etat".into(), etat.into_bytes()),
            ("activite".into(), activite.into_bytes()),
            ("empreinte".into(), empreinte.to_vec()),
        ],
        action: Action::Unites(vec![ActionUnite::Desactiver], u),
    }))
}

fn remettre_service(u: NomUnite, note: &Note, a: &mut dyn Acces, s: &mut dyn Services) -> Jugement {
    let nom = u.as_str();
    if !s.systemd() {
        return Err(refus(sans_systemd()));
    }
    let (p, f) = fichier_de_service(u, a)?;
    if a.empreinte(&p, &f).as_ref().map(<[u8; 32]>::as_slice) != note.champ("empreinte") {
        return Err(change_depuis(nom));
    }
    let (etat0, activite0) = (
        note.texte("etat").ok_or_else(note_abimee)?,
        note.texte("activite").ok_or_else(note_abimee)?,
    );
    let etat = s.etat_du_fichier(nom)?.unwrap_or_default();
    let activite = s.etat_d_activite(nom)?.unwrap_or_default();
    let (lance0, tourne0) = (lance_au_demarrage(etat0), tourne(activite0));
    let lance_comme_avant = lance_au_demarrage(&etat) == lance0;
    if lance_comme_avant && tourne(&activite) == tourne0 {
        return Ok(None);
    }
    // Il tournait, il ne tourne plus, et systemd a refusé de le relancer à cause de ses propres conditions (un service
    // du premier démarrage, `ConditionFirstBoot=`, par exemple) : le relancer encore n'y changerait rien, et la note
    // gardée bloquerait pour toujours les remises suivantes. Son démarrage revenu, il est comme le système le veut.
    if lance_comme_avant && tourne0 && s.condition_refusee(nom)? {
        return Ok(None);
    }
    let actions = match (lance0, tourne0) {
        (true, true) => vec![ActionUnite::Activer],
        // Activé mais arrêté : activé seulement, jamais lancé un instant (`enable --now` puis `stop` l'aurait fait).
        (true, false) => vec![ActionUnite::ActiverSansDemarrer],
        (false, true) => vec![ActionUnite::Demarrer],
        (false, false) => return Ok(None),
    };
    let texte = if tourne0 {
        trf!(
            "Service {nom} : remis comme avant. S'il ne se relance pas parce que systemd refuse ses propres conditions (un service du premier démarrage, par exemple), seul son lancement au démarrage revient, comme le système le ferait de lui-même.",
            "Service {nom}: put back as before. If it does not start again because systemd refuses its own conditions (a first-boot service, for example), only its start at boot comes back, as the system itself would do."
        )
    } else {
        trf!(
            "Service {nom} : remis comme avant.",
            "Service {nom}: put back as before."
        )
    };
    Ok(Some(Plan {
        texte,
        avertissement: None,
        non_annulable: false,
        seconde: None,
        champs: Vec::new(),
        action: Action::Unites(actions, u),
    }))
}

// ————— Lignes de fichiers de démarrage —————

/// Le fichier désigné pour une ligne : son chemin, sa fiche et son contenu, s'il est à root, fermé aux autres, et
/// pas trop grand pour tenir dans la note.
fn fichier_de_ligne(c: &CheminDesigne, a: &dyn Acces) -> Result<(PathBuf, Fiche, Vec<u8>), Echec> {
    let p = chemin_de(c);
    let vu = lisible(&p);
    let f = fiche_designee(&p, Genre::Fichier, a)?;
    if f.uid != 0 || f.mode & 0o022 != 0 {
        return Err(refus(trf!(
            "{vu} n'est pas à root, ou un autre compte peut le changer : rien n'est fait",
            "{vu} is not root's, or another account can change it: nothing is done"
        )));
    }
    let contenu = a.lire(&p, VALEUR_MAX).ok_or_else(|| {
        refus(trf!(
            "{vu} ne se lit pas, ou est trop grand : rien n'est fait",
            "{vu} cannot be read, or is too large: nothing is done"
        ))
    })?;
    Ok((p, f, contenu))
}

fn juger_ligne(e: Empreinte, c: &CheminDesigne, a: &mut dyn Acces) -> Jugement {
    let (p, f, contenu) = fichier_de_ligne(c, a)?;
    let vu = lisible(&p);
    let mut garde = Vec::with_capacity(contenu.len());
    let mut retiree: Option<&[u8]> = None;
    for morceau in contenu.split_inclusive(|o| *o == b'\n') {
        let ligne = morceau.strip_suffix(b"\n").unwrap_or(morceau);
        if empreinte_de_ligne(ligne) == e {
            retiree = Some(ligne);
        } else {
            garde.extend_from_slice(morceau);
        }
    }
    let Some(ligne) = retiree else {
        return Ok(None);
    };
    // Seule une ligne que Vanguard sait suspecte part : une liste qui désignerait une autre ligne (un réglage de
    // sécurité) est refusée ici, quoi qu'elle dise.
    let fichier = std::str::from_utf8(c.octets()).unwrap_or_default();
    if !std::str::from_utf8(ligne).is_ok_and(|l| crate::machine::linux::ligne_suspecte(fichier, l)) {
        return Err(refus(trf!(
            "la ligne désignée dans {vu} n'est pas de celles que Vanguard retire : rien n'est fait",
            "the line named in {vu} is not one Vanguard removes: nothing is done"
        )));
    }
    let apres: [u8; 32] = Sha256::digest(&garde).into();
    // ld.so.preload : une ligne peut nommer plusieurs bibliothèques (espaces ou « : ») ; toutes partent avec elle.
    let bibliotheques = ligne
        .split(|o| o.is_ascii_whitespace() || *o == b':')
        .filter(|m| !m.is_empty())
        .count();
    let texte = if fichier == "/etc/ld.so.preload" && bibliotheques > 1 {
        trf!(
            "Fichier {vu}, ligne retirée en entier, avec les {bibliotheques} bibliothèques qu'elle nomme (remettez à la main celles que vous reconnaissez, ou Défaire) : {}",
            "File {vu}, line removed whole, with the {bibliotheques} libraries it names (put back by hand the ones you recognize, or Undo): {}",
            echappe(ligne)
        )
    } else {
        trf!(
            "Fichier {vu}, ligne retirée : {}",
            "File {vu}, line removed: {}",
            echappe(ligne)
        )
    };
    Ok(Some(Plan {
        texte,
        avertissement: None,
        non_annulable: false,
        seconde: None,
        champs: vec![
            ("contenu".into(), contenu.clone()),
            ("apres".into(), apres.to_vec()),
            ("mode".into(), f.mode.to_string().into_bytes()),
            ("uid".into(), f.uid.to_string().into_bytes()),
            ("gid".into(), f.gid.to_string().into_bytes()),
        ],
        action: Action::Reecrire(p, f, garde),
    }))
}

fn remettre_ligne(c: &CheminDesigne, note: &Note, a: &mut dyn Acces) -> Jugement {
    let (p, f, contenu) = fichier_de_ligne(c, a)?;
    let avant = note.champ("contenu").ok_or_else(note_abimee)?;
    if contenu == avant {
        return Ok(None);
    }
    let apres: [u8; 32] = Sha256::digest(&contenu).into();
    if note.champ("apres") != Some(apres.as_slice()) {
        return Err(change_depuis(&lisible(&p)));
    }
    let (mode, uid, gid): (u32, u32, u32) = (nombre(note, "mode")?, nombre(note, "uid")?, nombre(note, "gid")?);
    if mode > 0o7777 || mode & 0o022 != 0 {
        return Err(note_abimee());
    }
    Ok(Some(Plan {
        texte: trf!(
            "Fichier {} : remis comme avant.",
            "File {}: put back as before.",
            lisible(&p)
        ),
        avertissement: None,
        non_annulable: false,
        seconde: None,
        champs: Vec::new(),
        action: Action::Reecrire(p, Fiche { mode, uid, gid, ..f }, avant.to_vec()),
    }))
}

// ————— Défaire —————

#[allow(
    clippy::large_types_passed_by_value,
    reason = "un geste lu d'une ligne, copié une fois : quelques centaines d'octets"
)]
fn remettre_juger(d: Defense, note: &Note, a: &mut dyn Acces, s: &mut dyn Services) -> Jugement {
    match d {
        Defense::VerrouillerCompte(n) => remettre_verrou(n, note, a),
        Defense::RetirerDuGroupe(g, n) => remettre_groupe(g, n, note, a),
        Defense::DurcirSudo(n) => remettre_sudo(n, note, a),
        Defense::RetirerSetuid(c) => remettre_droits(&c, false, note, a),
        Defense::RetirerCapacites(c) => remettre_droits(&c, true, note, a),
        Defense::RendreDossierARoot(c) => remettre_dossier(&c, note, a),
        Defense::DesactiverService(u) => remettre_service(u, note, a, s),
        Defense::RetirerLigne(_, c) => remettre_ligne(&c, note, a),
        Defense::DurcirSsh(r) => systeme::remettre_ssh(r, a, s),
        Defense::ReserverBpf => systeme::remettre_bpf(note, a),
        Defense::CouperPareFeu(p) => pare_feu::remettre(p, note, a, s),
        Defense::RallumerPareFeu(_) => Err(refus(tr!(
            "rallumer un pare-feu ne se défait pas : pour le recouper, passez par les Options de défense",
            "turning a firewall back on is not undone: to turn it off again, go through the Defense options"
        )
        .to_string())),
        // Non annulables : la note garde la copie de ce qui a été retiré, à remettre à la main.
        Defense::GarderJournal
        | Defense::RetirerAncre(_)
        | Defense::CommenterProxy(..)
        | Defense::OublierBluetooth(_)
        | Defense::ArreterProgramme(..)
        | Defense::RemettreProgramme(_) => Err(refus(tr!(
            "ce geste est non annulable : Vanguard ne le défait pas (la note d'« avant » garde la copie de ce qu'il a changé, dans /var/lib/vanguard/avant)",
            "this step cannot be undone: Vanguard does not undo it (the \"before\" note keeps the copy of what it changed, in /var/lib/vanguard/avant)"
        )
        .to_string())),
        Defense::Remettre => Err(note_abimee()),
    }
}

/// Remet ce que le geste noté sous `id` avait changé, d'après sa note relue (à root, en 0600, empreinte juste, même
/// identifiant, geste de défense de la liste fermée), seulement si rien n'a changé depuis.
fn remettre(id: IdNote, a: &mut dyn Acces, s: &mut dyn Services) -> Resultat {
    let octets = match a.note_lire(id) {
        Ok(Some(o)) => o,
        Ok(None) => {
            return Resultat::ok_note(tr!(
                "aucune note de ce geste : rien à remettre",
                "no note for this step: nothing to put back"
            ));
        }
        Err(r) => return Resultat::echec(r),
    };
    let Some(note) = Note::lire(id.as_str(), &octets) else {
        return Resultat::echec(note_abimee());
    };
    let d0 = match gestes_unix::analyser(&note.geste) {
        Some(GesteUnix::Defense(d0, id0)) if id0 == id && d0 != Defense::Remettre => d0,
        _ => return Resultat::echec(note_abimee()),
    };
    if GesteUnix::Defense(d0, id).refus().is_some() {
        return Resultat::echec(note_abimee());
    }
    let phrase = dit(GesteUnix::Defense(Defense::Remettre, id).phrase());
    let origine = dit(GesteUnix::Defense(d0, id).phrase());
    let p1 = match remettre_juger(d0, &note, a, s) {
        Ok(Some(mut p)) => {
            p.texte = trf!(
                "Geste d'origine : {origine}.\n{}",
                "Original step: {origine}.\n{}",
                p.texte
            );
            p
        }
        Ok(None) => {
            let _ = a.note_retirer(id);
            return Resultat::ok_note(tr!("déjà comme avant", "already as before"));
        }
        Err(r) => return Resultat::echec(r),
    };
    if let Err(r) = demander(a, &phrase, &p1) {
        return Resultat::echec(r);
    }
    match remettre_juger(d0, &note, a, s) {
        Ok(Some(mut p)) => {
            p.texte = trf!(
                "Geste d'origine : {origine}.\n{}",
                "Original step: {origine}.\n{}",
                p.texte
            );
            if p != p1 {
                return Resultat::echec(change_pendant_la_question());
            }
        }
        _ => return Resultat::echec(change_pendant_la_question()),
    }
    let fait = agir(&p1.action, a, s);
    match (fait, remettre_juger(d0, &note, a, s)) {
        (Ok(()), Ok(None)) => {
            let _ = a.note_retirer(id);
            Resultat::ok_note(trf!("{origine} : remis comme avant", "{origine}: put back as before"))
        }
        (fait, _) => {
            let r = fait.err().unwrap_or_else(|| {
                refus(tr!(
                    "relu après, ce n'est pas comme avant",
                    "read again afterwards, it is not as before"
                ))
            });
            Resultat::echec(trf!("{origine} : pas remis ({r})", "{origine}: not put back ({r})"))
        }
    }
}

// ————— Le vrai ordinateur —————

/// Le vrai ordinateur, pour l'enfant root. `demandeur` : le Vanguard qui a demandé (`--parent`).
pub(crate) struct Reel {
    pub(crate) demandeur: Option<u32>,
    /// Les empreintes déjà trouvées dans l'historique signé pendant ce geste : les trois jugements d'un même geste
    /// lisent la même réponse, et Internet qui tombe après le remplacement ne le fait pas dire « pas fait ».
    pub(crate) signees: std::cell::RefCell<std::collections::HashMap<[u8; 32], Option<String>>>,
}

/// La réponse de l'historique signé pour `sha256`, gardée dans `memoire` quand elle est sûre (`Ok`) ; un échec n'est
/// jamais gardé (il se redemande).
fn de_memoire(
    memoire: &std::cell::RefCell<std::collections::HashMap<[u8; 32], Option<String>>>,
    sha256: &[u8; 32],
    lire: impl FnOnce() -> Result<Option<String>, Echec>,
) -> Result<Option<String>, Echec> {
    if let Some(v) = memoire.borrow().get(sha256) {
        return Ok(v.clone());
    }
    let v = lire()?;
    memoire.borrow_mut().insert(*sha256, v.clone());
    Ok(v)
}

/// L'uid réel d'un processus (`/proc/<pid>/status`).
fn uid_du_processus(pid: &str) -> Option<u32> {
    let t = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    t.lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|r| r.split_whitespace().next()?.parse().ok())
}

/// Le compte de la connexion d'un processus (`/proc/<pid>/loginuid`) : il ne change ni par sudo ni par su.
fn uid_de_connexion(pid: &str) -> Option<u32> {
    std::fs::read_to_string(format!("/proc/{pid}/loginuid"))
        .ok()?
        .trim()
        .parse()
        .ok()
        .filter(|u| *u != u32::MAX)
}

/// Le terminal de contrôle d'après `/proc/<pid>/stat` (7e champ, `tty_nr`, après le nom entre parenthèses, qui peut
/// en contenir) : son numéro de périphérique et le chemin où il se trouve, pour un pseudo-terminal (majeur 136) ou
/// une console (majeur 4, mineur 1 à 63). `tty_nr` s'écrit comme un `st_rdev` : les deux se comparent tels quels.
fn terminal_de_controle(stat: &str) -> Option<(u64, PathBuf)> {
    let apres = &stat[stat.rfind(')')? + 1..];
    let tty: u64 = apres.split_whitespace().nth(4)?.parse().ok()?;
    let majeur = ((tty >> 8) & 0xfff) | ((tty >> 32) & !0xfff);
    let mineur = (tty & 0xff) | ((tty >> 12) & !0xff);
    let chemin = match majeur {
        136 => format!("/dev/pts/{mineur}"),
        4 if (1..64).contains(&mineur) => format!("/dev/tty{mineur}"),
        _ => return None,
    };
    Some((tty, PathBuf::from(chemin)))
}

/// Le compte à qui appartient le terminal de contrôle du fils, celui où la question est posée : c'est la personne qui
/// répondra, quoi que le parent ait dit de lui. Un terminal de root ne dit rien de plus (console libre, ou root
/// lui-même, que ses gestes avertissent déjà).
fn uid_du_terminal() -> Option<u32> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let (tty, chemin) = terminal_de_controle(&std::fs::read_to_string("/proc/self/stat").ok()?)?;
    let m = std::fs::symlink_metadata(chemin).ok()?;
    (m.file_type().is_char_device() && m.rdev() == tty && m.uid() != 0).then(|| m.uid())
}

fn fiche_de(m: &std::fs::Metadata) -> Fiche {
    use std::os::unix::fs::MetadataExt;
    let t = m.file_type();
    Fiche {
        genre: if t.is_file() {
            Genre::Fichier
        } else if t.is_dir() {
            Genre::Dossier
        } else {
            Genre::Autre
        },
        mode: m.mode() & 0o7777,
        uid: m.uid(),
        gid: m.gid(),
        dev: m.dev(),
        ino: m.ino(),
        taille: m.size(),
    }
}

/// Ouvre `p` en lecture sans suivre de lien (ni bloquer sur un tube), et vérifie que c'est le fichier de la fiche,
/// à ce chemin : même disque, même inode, même genre, et le chemin du descripteur est `p`.
fn ouvrir_le_meme(p: &Path, f: &Fiche) -> Result<std::fs::File, Echec> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let change = || refus(change_pendant_la_question());
    let fichier = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(p)
        .map_err(|e| echoue(e.to_string()))?;
    let vu = fichier.metadata().map_err(|e| echoue(e.to_string()))?;
    if !meme_fichier(&fiche_de(&vu), f) {
        return Err(change());
    }
    let lien = std::fs::read_link(format!("/proc/self/fd/{}", fichier.as_raw_fd())).map_err(|_| change())?;
    if lien != p {
        return Err(change());
    }
    Ok(fichier)
}

const CAPACITE: &std::ffi::CStr = c"security.capability";

// FFI de libc : fgetxattr (lire les capacités d'un fichier par son descripteur).
#[allow(unsafe_code)]
fn lire_capacites(fichier: &std::fs::File) -> Result<Option<Vec<u8>>, ()> {
    use std::os::fd::AsRawFd;
    let mut tampon = [0u8; 1024];
    // SAFETY: le descripteur est tenu par `fichier` pendant l'appel ; le nom est une chaîne C terminée ; le tampon
    // vit sur la pile et sa taille est celle passée.
    let n = unsafe {
        libc::fgetxattr(
            fichier.as_raw_fd(),
            CAPACITE.as_ptr(),
            tampon.as_mut_ptr().cast(),
            tampon.len(),
        )
    };
    if n < 0 {
        return match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ENODATA | libc::ENOTSUP) => Ok(None),
            _ => Err(()),
        };
    }
    let n = usize::try_from(n).map_err(|_| ())?;
    tampon.get(..n).map(|v| Some(v.to_vec())).ok_or(())
}

// FFI de libc : fsetxattr et fremovexattr (poser ou retirer les capacités d'un fichier par son descripteur).
#[allow(unsafe_code)]
fn ecrire_capacites(fichier: &std::fs::File, valeur: Option<&[u8]>) -> Result<(), Echec> {
    use std::os::fd::AsRawFd;
    let r = match valeur {
        // SAFETY: descripteur tenu par `fichier`, nom en chaîne C terminée, valeur et sa longueur d'une même tranche.
        Some(v) => unsafe { libc::fsetxattr(fichier.as_raw_fd(), CAPACITE.as_ptr(), v.as_ptr().cast(), v.len(), 0) },
        // SAFETY: descripteur tenu par `fichier`, nom en chaîne C terminée.
        None => unsafe { libc::fremovexattr(fichier.as_raw_fd(), CAPACITE.as_ptr()) },
    };
    if r == 0 {
        return Ok(());
    }
    let e = std::io::Error::last_os_error();
    if valeur.is_none() && e.raw_os_error() == Some(libc::ENODATA) {
        return Ok(());
    }
    Err(echoue(e.to_string()))
}

/// Sous les essais, rien n'est écrit pour de vrai : seule la mémoire du faux ordinateur change.
fn essais_sans_ecriture() -> Result<(), Echec> {
    if cfg!(test) {
        return Err(refus("essais : aucune écriture réelle"));
    }
    Ok(())
}

/// Le dossier qui reçoit un fichier écrit : à root, sans lien, fermé en écriture au groupe et aux autres.
fn dossier_sur(d: &Path, ferme: u32) -> Result<(), Echec> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(d).map_err(|e| echoue(e.to_string()))?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & ferme != 0 {
        return Err(refus(trf!(
            "{} n'est pas un dossier de root fermé aux autres comptes",
            "{} is not a root folder closed to other accounts",
            lisible(d)
        )));
    }
    Ok(())
}

/// Crée `p` (il ne doit pas exister) avec ce contenu, ce propriétaire et ces droits, écrit jusqu'au disque ; un
/// échec le retire.
fn creer(p: &Path, contenu: &[u8], e: Ecriture) -> Result<(), Echec> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut fichier = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)
        .map_err(|x| echoue(x.to_string()))?;
    let fait = fichier
        .write_all(contenu)
        .and_then(|()| std::os::unix::fs::fchown(&fichier, Some(e.uid), Some(e.gid)))
        .and_then(|()| fichier.set_permissions(std::fs::Permissions::from_mode(e.mode)))
        .and_then(|()| fichier.sync_all());
    if let Err(x) = fait {
        let _ = std::fs::remove_file(p);
        return Err(echoue(x.to_string()));
    }
    Ok(())
}

impl Acces for Reel {
    fn question(&mut self, texte: &str) -> Result<Option<String>, ()> {
        super::assistant::question_au_terminal(texte)
    }

    fn date(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    fn personnes(&self) -> Vec<u32> {
        let mut v = Vec::new();
        if let Some(d) = self.demandeur {
            v.extend(uid_du_processus(&d.to_string()));
            v.extend(uid_de_connexion(&d.to_string()));
        }
        v.extend(uid_de_connexion("self"));
        v.extend(uid_du_terminal());
        for var in ["SUDO_UID", "PKEXEC_UID"] {
            v.extend(std::env::var(var).ok().and_then(|u| u.parse::<u32>().ok()));
        }
        v.sort_unstable();
        v.dedup();
        v
    }

    fn lancer(&mut self, outil: &str, arguments: &[OsString]) -> Option<Sortie> {
        if cfg!(test) {
            return None;
        }
        let chemin = crate::commande::outil_systeme(outil)?;
        let mut c = std::process::Command::new(chemin);
        c.args(arguments);
        crate::commande::environnement_propre(
            &mut c,
            std::env::vars_os().filter(|(n, _)| super::assistant::langue_ou_terminal(n)),
        );
        // En anglais : la sortie de sudo -l est lue.
        c.env("LC_ALL", "C");
        crate::commande::lancer(&mut c, 120)
    }

    fn outil(&self, nom: &str) -> bool {
        crate::commande::outil_systeme(nom).is_some()
    }

    fn fiche(&self, p: &Path) -> Option<Fiche> {
        std::fs::symlink_metadata(p).ok().map(|m| fiche_de(&m))
    }

    fn reel(&self, p: &Path) -> Option<PathBuf> {
        std::fs::canonicalize(p).ok()
    }

    fn lire(&self, p: &Path, max: usize) -> Option<Vec<u8>> {
        use std::io::Read as _;
        use std::os::unix::fs::OpenOptionsExt;
        let fichier = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(p)
            .ok()?;
        if !fichier.metadata().ok()?.is_file() {
            return None;
        }
        let mut o = Vec::new();
        fichier
            .take(u64::try_from(max).ok()?.saturating_add(1))
            .read_to_end(&mut o)
            .ok()?;
        (o.len() <= max).then_some(o)
    }

    fn empreinte(&self, p: &Path, f: &Fiche) -> Option<[u8; 32]> {
        use std::io::Read as _;
        let mut fichier = ouvrir_le_meme(p, f).ok()?;
        let mut h = Sha256::new();
        let mut tampon = vec![0u8; 64 * 1024];
        loop {
            match fichier.read(&mut tampon) {
                Ok(0) => break,
                Ok(n) => h.update(tampon.get(..n)?),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return None,
            }
        }
        Some(h.finalize().into())
    }

    fn capacites(&self, p: &Path, f: &Fiche) -> Result<Option<Vec<u8>>, ()> {
        let fichier = ouvrir_le_meme(p, f).map_err(|_| ())?;
        lire_capacites(&fichier)
    }

    fn changer(&mut self, p: &Path, f: &Fiche, m: &Modif) -> Result<(), Echec> {
        use std::os::unix::fs::PermissionsExt;
        essais_sans_ecriture()?;
        let fichier = ouvrir_le_meme(p, f)?;
        match m {
            Modif::Mode(mode) => fichier
                .set_permissions(std::fs::Permissions::from_mode(*mode))
                .map_err(|e| echoue(e.to_string())),
            Modif::Proprietaire(u, g) => {
                std::os::unix::fs::fchown(&fichier, Some(*u), Some(*g)).map_err(|e| echoue(e.to_string()))
            }
            Modif::Capacites(v) => ecrire_capacites(&fichier, v.as_deref()),
        }
    }

    fn ecrire(&mut self, p: &Path, contenu: &[u8], e: Ecriture) -> Result<(), Echec> {
        essais_sans_ecriture()?;
        let (Some(dossier), Some(nom)) = (p.parent(), p.file_name()) else {
            return Err(note_abimee());
        };
        dossier_sur(dossier, 0o022)?;
        let Some(avant) = e.avant else {
            return creer(p, contenu, e);
        };
        let mut voisin = OsString::from(".");
        voisin.push(nom);
        voisin.push(".vanguard-tmp");
        let voisin = dossier.join(voisin);
        if self
            .fiche(&voisin)
            .is_some_and(|f| f.genre == Genre::Fichier && f.uid == 0)
        {
            std::fs::remove_file(&voisin).map_err(|x| echoue(x.to_string()))?;
        }
        creer(&voisin, contenu, e)?;
        if !self.fiche(p).is_some_and(|f| meme_fichier(&f, &avant)) {
            let _ = std::fs::remove_file(&voisin);
            return Err(refus(change_pendant_la_question()));
        }
        std::fs::rename(&voisin, p).map_err(|x| {
            let _ = std::fs::remove_file(&voisin);
            echoue(x.to_string())
        })
    }

    fn deplacer(&mut self, de: &Path, vers: &Path) -> Result<(), Echec> {
        essais_sans_ecriture()?;
        // Un lien dur échoue si `vers` existe : rien n'est jamais remplacé.
        std::fs::hard_link(de, vers).map_err(|e| echoue(e.to_string()))?;
        std::fs::remove_file(de).map_err(|e| echoue(e.to_string()))
    }

    fn retirer(&mut self, p: &Path) -> Result<(), Echec> {
        essais_sans_ecriture()?;
        std::fs::remove_file(p).map_err(|e| echoue(e.to_string()))
    }

    fn paquet(&self, p: &Path) -> EtatPaquet {
        crate::machine::linux::etat_paquet(p)
    }

    fn note_ecrire(&mut self, id: IdNote, octets: &[u8]) -> Result<(), Echec> {
        use std::os::unix::fs::DirBuilderExt;
        essais_sans_ecriture()?;
        for (d, mode, ferme) in [
            (DOSSIER_VANGUARD, 0o755, 0o022),
            (DOSSIER_NOTES, DROITS_NOTES, FERME_NOTES),
        ] {
            if std::fs::symlink_metadata(d).is_err() {
                std::fs::DirBuilder::new()
                    .mode(mode)
                    .create(d)
                    .map_err(|e| echoue(e.to_string()))?;
            }
            dossier_sur(Path::new(d), ferme)?;
        }
        creer(
            &Path::new(DOSSIER_NOTES).join(id.as_str()),
            octets,
            Ecriture {
                mode: 0o600,
                uid: 0,
                gid: 0,
                avant: None,
            },
        )
    }

    fn note_lire(&self, id: IdNote) -> Result<Option<Vec<u8>>, Echec> {
        use std::io::Read as _;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        if std::fs::symlink_metadata(DOSSIER_VANGUARD).is_err() {
            return Ok(None);
        }
        dossier_sur(Path::new(DOSSIER_VANGUARD), 0o022)?;
        if std::fs::symlink_metadata(DOSSIER_NOTES).is_err() {
            return Ok(None);
        }
        dossier_sur(Path::new(DOSSIER_NOTES), FERME_NOTES)?;
        let fichier = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(Path::new(DOSSIER_NOTES).join(id.as_str()))
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(echoue(e.to_string())),
        };
        let m = fichier.metadata().map_err(|e| echoue(e.to_string()))?;
        let max = crate::machine::note_avant_unix::NOTE_MAX;
        if !m.is_file() || m.uid() != 0 || m.mode() & 0o7777 != 0o600 || m.size() > u64::try_from(max).unwrap_or(0) {
            return Err(note_abimee());
        }
        let mut o = Vec::new();
        fichier
            .take(u64::try_from(max).unwrap_or(0))
            .read_to_end(&mut o)
            .map_err(|e| echoue(e.to_string()))?;
        Ok(Some(o))
    }

    fn note_retirer(&mut self, id: IdNote) -> Result<(), Echec> {
        essais_sans_ecriture()?;
        std::fs::remove_file(Path::new(DOSSIER_NOTES).join(id.as_str())).map_err(|e| echoue(e.to_string()))
    }

    fn creer_dossier(&mut self, p: &Path, mode: u32) -> Result<(), Echec> {
        programme::creer_dossier_reel(p, mode)
    }

    fn processus(&self, pid: u32) -> Option<VueProcessus> {
        programme::processus_reel(pid)
    }

    fn soupcon(&self, pid: u32, v: &VueProcessus) -> Option<String> {
        programme::soupcon_reel(pid, v)
    }

    fn garde(&self, pid: u32, v: &VueProcessus) -> Option<String> {
        programme::garde_reelle(pid, v, self.demandeur)
    }

    fn copier_traces(&mut self, pid: u32, v: &VueProcessus) -> Result<PathBuf, Echec> {
        programme::copier_traces_reel(pid, v, self.date())
    }

    fn arreter(&mut self, pid: u32, v: &VueProcessus) -> Result<(), Echec> {
        programme::arreter_reel(pid, v)
    }

    fn version_signee(&self, sha256: &[u8; 32]) -> Result<Option<String>, Echec> {
        if cfg!(test) {
            return Err(echoue("essais : pas de réseau"));
        }
        de_memoire(&self.signees, sha256, || crate::mise_a_jour::version_signee_ici(sha256))
    }

    fn programme_signe(&mut self) -> Result<(String, Vec<u8>), Echec> {
        if cfg!(test) {
            return Err(echoue("essais : pas de réseau"));
        }
        crate::mise_a_jour::programme_signe_a_remettre()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};

    use super::*;

    const ID: &str = "0123456789abcdef";

    fn id() -> IdNote {
        IdNote::nouveau(ID).unwrap()
    }

    fn compte(n: &str) -> NomCompte {
        NomCompte::nouveau(n).unwrap()
    }

    #[derive(Clone)]
    struct FauxFichier {
        contenu: Vec<u8>,
        fiche: Fiche,
        caps: Option<Vec<u8>>,
    }

    /// Un ordinateur en mémoire : fichiers, liens, paquets, réponses tapées, notes ; usermod, gpasswd, visudo et
    /// sudo -l y sont imités sur les fichiers de comptes.
    struct Faux {
        fichiers: BTreeMap<PathBuf, FauxFichier>,
        liens: BTreeMap<PathBuf, PathBuf>,
        paquets: BTreeMap<PathBuf, EtatPaquet>,
        reponses: VecDeque<Result<Option<String>, ()>>,
        questions: Vec<String>,
        journal: Vec<String>,
        notes: BTreeMap<String, Vec<u8>>,
        personnes: Vec<u32>,
        outils: Vec<&'static str>,
        visudo_seul: i32,
        visudo_tout: i32,
        sudo_avant: String,
        sudo_apres: String,
        ino: u64,
        /// Un fichier changé pendant la question.
        pendant_la_question: Option<(PathBuf, Vec<u8>)>,
        /// Lot D7b : les processus vus, leurs soupçons et leurs gardes.
        processus: BTreeMap<u32, VueProcessus>,
        soupcons: BTreeMap<u32, String>,
        gardes: BTreeMap<u32, String>,
        /// Le programme change pendant la copie de ses traces (relancé sous le même numéro).
        change_pendant_traces: bool,
        /// Le code de `sshd -t`.
        sshd_t: i32,
        /// sshd -T ne voit pas les fichiers de Vanguard (un réglage lu avant eux l'emporte).
        sshd_sans_effet: bool,
        /// sshd -T sans les fichiers de Vanguard : clé, valeur.
        sshd_base: Vec<(String, String)>,
        /// Ce que `bluetoothctl info` dit de l'appareil ; `None` : il n'est pas connu.
        bluetooth: Option<String>,
        /// L'historique signé des versions : empreinte, version ; `None` : il ne se lit pas.
        historique: Option<BTreeMap<[u8; 32], String>>,
        /// Le programme signé reçu : version, octets ; `None` : rien reçu.
        signe: Option<(String, Vec<u8>)>,
        /// Lot D7c : ufw et nftables imités.
        pf: d7c::FauxPareFeu,
    }

    fn fiche(genre: Genre, mode: u32, uid: u32, ino: u64) -> Fiche {
        Fiche {
            genre,
            mode,
            uid,
            gid: uid,
            dev: 1,
            ino,
            taille: 0,
        }
    }

    const PASSWD_DE: &str = "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/bash\ntoor:x:0:0::/root:/bin/sh\ndaemon:x:1:1::/:/usr/sbin/nologin\n";
    const SHADOW_DE: &str = "root:$6$r:19000:0:99999:7:::\nalice:$6$a:19000:0:99999:7:::\nbob:$6$b:19000:0:99999:7:::\ntoor:$6$t:19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::\n";
    const GROUP_DE: &str = "root:x:0:\nwheel:x:10:alice,bob\ndocker:x:970:alice\nalice:x:1000:\nbob:x:1001:\n";

    impl Faux {
        fn nouveau() -> Self {
            let mut f = Faux {
                fichiers: BTreeMap::new(),
                liens: BTreeMap::new(),
                paquets: BTreeMap::new(),
                reponses: VecDeque::new(),
                questions: Vec::new(),
                journal: Vec::new(),
                notes: BTreeMap::new(),
                personnes: vec![1000],
                outils: vec!["usermod", "gpasswd", "visudo", "sudo", "pkexec", "run0"],
                visudo_seul: 0,
                visudo_tout: 0,
                sudo_avant: String::new(),
                sudo_apres: String::new(),
                ino: 100,
                pendant_la_question: None,
                processus: BTreeMap::new(),
                change_pendant_traces: false,
                soupcons: BTreeMap::new(),
                gardes: BTreeMap::new(),
                sshd_t: 0,
                sshd_sans_effet: false,
                sshd_base: [
                    ("permitemptypasswords", "no"),
                    ("permitrootlogin", "prohibit-password"),
                    ("passwordauthentication", "yes"),
                    ("kbdinteractiveauthentication", "yes"),
                    ("pubkeyauthentication", "yes"),
                    ("authenticationmethods", "any"),
                    ("authorizedkeysfile", ".ssh/authorized_keys .ssh/authorized_keys2"),
                ]
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
                bluetooth: None,
                historique: Some(BTreeMap::new()),
                signe: None,
                pf: d7c::FauxPareFeu::default(),
            };
            f.poser("/etc/passwd", PASSWD_DE.as_bytes(), 0o644);
            f.poser("/etc/shadow", SHADOW_DE.as_bytes(), 0o640);
            f.poser("/etc/group", GROUP_DE.as_bytes(), 0o644);
            f.poser(
                "/etc/sudoers",
                b"root ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n",
                0o440,
            );
            f.poser("/usr/sbin/nologin", b"nologin", 0o755);
            f.poser("/usr/bin/su", b"su", 0o4755);
            f.poser("/usr/bin/pkexec", b"pkexec", 0o4755);
            f.dossier("/etc/sudoers.d", 0o750, 0);
            f
        }

        fn poser(&mut self, p: &str, contenu: &[u8], mode: u32) {
            self.ino += 1;
            self.fichiers.insert(
                PathBuf::from(p),
                FauxFichier {
                    contenu: contenu.to_vec(),
                    fiche: fiche(Genre::Fichier, mode, 0, self.ino),
                    caps: None,
                },
            );
        }

        fn dossier(&mut self, p: &str, mode: u32, uid: u32) {
            self.ino += 1;
            self.fichiers.insert(
                PathBuf::from(p),
                FauxFichier {
                    contenu: Vec::new(),
                    fiche: fiche(Genre::Dossier, mode, uid, self.ino),
                    caps: None,
                },
            );
        }

        fn texte(&self, p: &str) -> String {
            String::from_utf8(self.fichiers[Path::new(p)].contenu.clone()).unwrap()
        }

        fn mode(&self, p: &str) -> u32 {
            self.fichiers[Path::new(p)].fiche.mode
        }

        fn repondre(mut self, r: &str) -> Self {
            self.reponses.push_back(Ok(Some(format!("{r}\n"))));
            self
        }

        /// Remplace la ligne de `nom` dans un fichier de comptes, champ `i`.
        fn champ(&mut self, fichier: &str, nom: &str, i: usize, valeur: &str) {
            let t = self.texte(fichier);
            let nouveau: String = t
                .lines()
                .map(|l| {
                    let mut c: Vec<String> = l.split(':').map(String::from).collect();
                    if c[0] == nom {
                        c[i] = valeur.to_string();
                    }
                    c.join(":") + "\n"
                })
                .collect();
            self.fichiers.get_mut(Path::new(fichier)).unwrap().contenu = nouveau.into_bytes();
        }

        fn valeur(&self, fichier: &str, nom: &str, i: usize) -> String {
            self.texte(fichier)
                .lines()
                .find(|l| l.split(':').next() == Some(nom))
                .map(|l| l.split(':').nth(i).unwrap().to_string())
                .unwrap()
        }

        fn imiter(&mut self, outil: &str, a: &[String]) -> i32 {
            match outil {
                "usermod" => {
                    let nom = a.last().unwrap().clone();
                    let mut i = 0;
                    while i < a.len() {
                        match a[i].as_str() {
                            "--lock" => {
                                let h = self.valeur(SHADOW, &nom, 1);
                                self.champ(SHADOW, &nom, 1, &format!("!{h}"));
                            }
                            "--unlock" => {
                                let h = self.valeur(SHADOW, &nom, 1);
                                // Comme le vrai : pas de compte rendu sans mot de passe.
                                if h == "!" {
                                    return 1;
                                }
                                self.champ(SHADOW, &nom, 1, h.strip_prefix('!').unwrap_or(&h));
                            }
                            "--expiredate" => {
                                i += 1;
                                let v = a[i].clone();
                                self.champ(SHADOW, &nom, 7, &v);
                            }
                            "--shell" => {
                                i += 1;
                                let v = a[i].clone();
                                self.champ(PASSWD, &nom, 6, &v);
                            }
                            _ => {}
                        }
                        i += 1;
                    }
                    0
                }
                "gpasswd" => {
                    // Le groupe vient après « -- » : sans lui, l'outil imité refuse.
                    if a.len() != 4 || a[2] != "--" {
                        return 2;
                    }
                    let (op, nom, groupe) = (a[0].as_str(), a[1].as_str(), a[3].as_str());
                    let membres = self.valeur(GROUP, groupe, 3);
                    let mut m: Vec<&str> = membres.split(',').filter(|x| !x.is_empty()).collect();
                    if op == "-d" {
                        m.retain(|x| *x != nom);
                    } else {
                        m.push(nom);
                    }
                    let j = m.join(",");
                    self.champ(GROUP, groupe, 3, &j);
                    0
                }
                "visudo" if a.iter().any(|x| x == "-f") => self.visudo_seul,
                "visudo" => self.visudo_tout,
                "sshd" if a == ["-t"] => self.sshd_t,
                "sysctl" => {
                    let v = a[1].strip_prefix("kernel.unprivileged_bpf_disabled=").unwrap();
                    self.fichiers.get_mut(Path::new(BPF_FAUX)).unwrap().contenu = format!("{v}\n").into_bytes();
                    0
                }
                "journalctl" => {
                    if self
                        .fichiers
                        .contains_key(Path::new("/etc/systemd/journald.conf.d/zz-vanguard-persistant.conf"))
                    {
                        self.dossier("/var/log/journal", 0o2755, 0);
                    }
                    0
                }
                _ => 0,
            }
        }

        /// Ce que `sshd -T` dirait : la base, puis les fichiers 00-vanguard-*.conf posés (s'ils ont effet).
        fn sshd_grand_t(&self) -> String {
            let mut cfg = self.sshd_base.clone();
            if !self.sshd_sans_effet {
                for (p, f) in &self.fichiers {
                    let p = p.to_string_lossy();
                    if !p.starts_with("/etc/ssh/sshd_config.d/00-vanguard-") {
                        continue;
                    }
                    for l in String::from_utf8_lossy(&f.contenu).lines() {
                        let (k, v) = l.split_once(' ').unwrap();
                        let k = k.to_ascii_lowercase();
                        cfg.retain(|(c, _)| *c != k);
                        cfg.push((k, v.to_string()));
                    }
                }
            }
            cfg.iter().fold(String::new(), |mut s, (k, v)| {
                let _ = writeln!(s, "{k} {v}");
                s
            })
        }
    }

    const BPF_FAUX: &str = "/proc/sys/kernel/unprivileged_bpf_disabled";

    impl Acces for Faux {
        fn question(&mut self, texte: &str) -> Result<Option<String>, ()> {
            self.questions.push(texte.to_string());
            if let Some((p, c)) = self.pendant_la_question.take() {
                self.fichiers.get_mut(&p).unwrap().contenu = c;
            }
            self.reponses.pop_front().unwrap_or(Err(()))
        }

        fn date(&self) -> u64 {
            1_762_300_000
        }

        fn personnes(&self) -> Vec<u32> {
            self.personnes.clone()
        }

        fn lancer(&mut self, outil: &str, arguments: &[OsString]) -> Option<Sortie> {
            if !self.outils.contains(&outil) {
                return None;
            }
            let a: Vec<String> = arguments.iter().map(|x| x.to_string_lossy().into_owned()).collect();
            self.journal.push(format!("{outil} {}", a.join(" ")));
            if let Some(r) = d7c::imiter(self, outil, &a) {
                return Some(r);
            }
            if outil == "sudo" {
                let pose = self.fichiers.contains_key(&chemin_sudo(compte(a.last().unwrap())));
                let sortie = if pose {
                    self.sudo_apres.clone()
                } else {
                    self.sudo_avant.clone()
                };
                return Some(Sortie {
                    code: Some(0),
                    sortie,
                    erreurs: String::new(),
                });
            }
            if outil == "sshd" && a == ["-T"] {
                return Some(Sortie {
                    code: Some(0),
                    sortie: self.sshd_grand_t(),
                    erreurs: String::new(),
                });
            }
            if outil == "bluetoothctl" {
                let (code, sortie) = match (a[0].as_str(), &self.bluetooth) {
                    ("info", Some(t)) => (0, t.clone()),
                    ("remove", Some(_)) => {
                        self.bluetooth = None;
                        (0, "Device has been removed\n".to_string())
                    }
                    (_, None) => (1, format!("Device {} not available\n", a[1])),
                    _ => (1, String::new()),
                };
                return Some(Sortie {
                    code: Some(code),
                    sortie,
                    erreurs: String::new(),
                });
            }
            let code = self.imiter(outil, &a);
            Some(Sortie {
                code: Some(code),
                sortie: String::new(),
                erreurs: if code == 0 { String::new() } else { "refusé\n".into() },
            })
        }

        fn outil(&self, nom: &str) -> bool {
            self.outils.contains(&nom)
        }

        fn fiche(&self, p: &Path) -> Option<Fiche> {
            if self.liens.contains_key(p) {
                return Some(fiche(Genre::Autre, 0o777, 0, 1));
            }
            self.fichiers.get(p).map(|f| f.fiche)
        }

        fn reel(&self, p: &Path) -> Option<PathBuf> {
            if let Some(c) = self.liens.get(p) {
                return Some(c.clone());
            }
            self.fichiers.contains_key(p).then(|| p.to_path_buf())
        }

        fn lire(&self, p: &Path, max: usize) -> Option<Vec<u8>> {
            let f = self.fichiers.get(p)?;
            (f.fiche.genre == Genre::Fichier && f.contenu.len() <= max).then(|| f.contenu.clone())
        }

        fn empreinte(&self, p: &Path, f: &Fiche) -> Option<[u8; 32]> {
            let v = self.fichiers.get(p)?;
            meme_fichier(&v.fiche, f).then(|| Sha256::digest(&v.contenu).into())
        }

        fn capacites(&self, p: &Path, f: &Fiche) -> Result<Option<Vec<u8>>, ()> {
            let v = self.fichiers.get(p).ok_or(())?;
            if !meme_fichier(&v.fiche, f) {
                return Err(());
            }
            Ok(v.caps.clone())
        }

        fn changer(&mut self, p: &Path, f: &Fiche, m: &Modif) -> Result<(), Echec> {
            let v = self.fichiers.get_mut(p).ok_or_else(|| refus("absent"))?;
            if !meme_fichier(&v.fiche, f) {
                return Err(refus("changé"));
            }
            self.journal.push(format!("changer {} {m:?}", p.display()));
            match m {
                Modif::Mode(x) => v.fiche.mode = *x,
                Modif::Proprietaire(u, g) => {
                    v.fiche.uid = *u;
                    v.fiche.gid = *g;
                }
                Modif::Capacites(c) => v.caps.clone_from(c),
            }
            Ok(())
        }

        fn ecrire(&mut self, p: &Path, contenu: &[u8], e: Ecriture) -> Result<(), Echec> {
            match (e.avant, self.fichiers.get(p)) {
                (None, Some(_)) => return Err(refus("existe")),
                (Some(a), Some(v)) if !meme_fichier(&a, &v.fiche) => return Err(refus("changé")),
                (Some(_), None) => return Err(refus("absent")),
                _ => {}
            }
            self.journal.push(format!("ecrire {}", p.display()));
            self.ino += 1;
            self.fichiers.insert(
                p.to_path_buf(),
                FauxFichier {
                    contenu: contenu.to_vec(),
                    fiche: Fiche {
                        mode: e.mode,
                        uid: e.uid,
                        gid: e.gid,
                        ..fiche(Genre::Fichier, 0, 0, self.ino)
                    },
                    caps: None,
                },
            );
            Ok(())
        }

        fn deplacer(&mut self, de: &Path, vers: &Path) -> Result<(), Echec> {
            if self.fichiers.contains_key(vers) {
                return Err(refus("existe"));
            }
            let f = self.fichiers.remove(de).ok_or_else(|| refus("absent"))?;
            self.fichiers.insert(vers.to_path_buf(), f);
            Ok(())
        }

        fn retirer(&mut self, p: &Path) -> Result<(), Echec> {
            self.journal.push(format!("retirer {}", p.display()));
            self.fichiers.remove(p).map(|_| ()).ok_or_else(|| refus("absent"))
        }

        fn paquet(&self, p: &Path) -> EtatPaquet {
            self.paquets.get(p).cloned().unwrap_or(EtatPaquet::Aucun)
        }

        fn note_ecrire(&mut self, id: IdNote, octets: &[u8]) -> Result<(), Echec> {
            if self.notes.contains_key(id.as_str()) {
                return Err(refus("existe"));
            }
            // Comme le vrai : le dossier de Vanguard est créé avec la première note.
            if !self.fichiers.contains_key(Path::new(DOSSIER_VANGUARD)) {
                self.dossier(DOSSIER_VANGUARD, 0o755, 0);
            }
            self.notes.insert(id.as_str().to_string(), octets.to_vec());
            Ok(())
        }

        fn note_lire(&self, id: IdNote) -> Result<Option<Vec<u8>>, Echec> {
            Ok(self.notes.get(id.as_str()).cloned())
        }

        fn note_retirer(&mut self, id: IdNote) -> Result<(), Echec> {
            self.notes.remove(id.as_str());
            Ok(())
        }

        fn creer_dossier(&mut self, p: &Path, mode: u32) -> Result<(), Echec> {
            if self.fichiers.contains_key(p) {
                return Err(refus("existe"));
            }
            self.journal.push(format!("dossier {}", p.display()));
            self.dossier(&p.to_string_lossy(), mode, 0);
            Ok(())
        }

        fn processus(&self, pid: u32) -> Option<VueProcessus> {
            self.processus.get(&pid).cloned()
        }

        fn soupcon(&self, pid: u32, _: &VueProcessus) -> Option<String> {
            self.soupcons.get(&pid).cloned()
        }

        fn garde(&self, pid: u32, _: &VueProcessus) -> Option<String> {
            self.gardes.get(&pid).cloned()
        }

        fn copier_traces(&mut self, pid: u32, v: &VueProcessus) -> Result<PathBuf, Echec> {
            self.journal.push(format!("traces {pid}"));
            if self.change_pendant_traces
                && let Some(p) = self.processus.get_mut(&pid)
            {
                p.debut += 1;
            }
            Ok(PathBuf::from(format!("/var/lib/vanguard/traces/{pid}-{}", v.debut)))
        }

        fn arreter(&mut self, pid: u32, _: &VueProcessus) -> Result<(), Echec> {
            self.journal.push(format!("arreter {pid}"));
            self.processus.remove(&pid).map(|_| ()).ok_or_else(|| refus("absent"))
        }

        fn version_signee(&self, sha256: &[u8; 32]) -> Result<Option<String>, Echec> {
            let h = self
                .historique
                .as_ref()
                .ok_or_else(|| echoue("pas d'Internet\x1b[31m"))?;
            Ok(h.get(sha256).cloned())
        }

        fn programme_signe(&mut self) -> Result<(String, Vec<u8>), Echec> {
            self.journal.push("recevoir le programme signé".into());
            self.signe.clone().ok_or_else(|| echoue("rien reçu"))
        }
    }

    struct FauxServices {
        etat: String,
        activite: String,
        charge: Option<ArretCharge>,
        lignee: Vec<String>,
        sessions: Option<Vec<SessionVue>>,
        faits: Vec<String>,
        /// Ses conditions refusées : un lancement le laisse arrêté, et `condition_refusee` le dit.
        condition_refusee: bool,
        /// Un lancement le laisse arrêté pour une autre raison (il échoue), conditions remplies.
        ne_demarre_pas: bool,
        /// Un rechargement échoue (bus occupé, délai dépassé).
        recharger_echoue: bool,
    }

    impl FauxServices {
        fn nouveau() -> Self {
            FauxServices {
                etat: "enabled".into(),
                activite: "active".into(),
                charge: Some(ArretCharge {
                    groupe: "/system.slice/minage.service".into(),
                    ..ArretCharge::default()
                }),
                lignee: vec!["/user.slice/user-1000.slice/session-2.scope".into()],
                sessions: Some(Vec::new()),
                faits: Vec::new(),
                condition_refusee: false,
                ne_demarre_pas: false,
                recharger_echoue: false,
            }
        }
    }

    impl Services for FauxServices {
        fn systemd(&self) -> bool {
            true
        }
        fn fichier_sur(&self, _: &str) -> Result<bool, Echec> {
            Ok(true)
        }
        fn arret_charge(&mut self, _: &str) -> Result<Option<ArretCharge>, Echec> {
            Ok(self.charge.clone())
        }
        fn etat_du_fichier(&mut self, _: &str) -> Result<Option<String>, Echec> {
            Ok(Some(self.etat.clone()))
        }
        fn etat_d_activite(&mut self, _: &str) -> Result<Option<String>, Echec> {
            Ok(Some(self.activite.clone()))
        }
        fn condition_refusee(&mut self, _: &str) -> Result<bool, Echec> {
            Ok(self.condition_refusee)
        }
        fn unite(&mut self, action: ActionUnite, unite: &str) -> Result<(), Echec> {
            self.faits.push(format!("{} {unite}", action.mot()));
            if self.recharger_echoue && matches!(action, ActionUnite::Recharger) {
                return Err(echoue("systemctl reload : délai dépassé"));
            }
            let lance = if self.condition_refusee || self.ne_demarre_pas {
                "inactive"
            } else {
                "active"
            }
            .to_string();
            let (e, a) = match action {
                ActionUnite::Desactiver => ("disabled".to_string(), "inactive".to_string()),
                ActionUnite::Activer => ("enabled".to_string(), lance),
                // Démarré ou redémarré : il repart comme au démarrage ; rechargé : il tourne toujours.
                ActionUnite::Demarrer | ActionUnite::Redemarrer => (self.etat.clone(), lance),
                ActionUnite::ActiverSansDemarrer => ("enabled".to_string(), self.activite.clone()),
                ActionUnite::Recharger => (self.etat.clone(), self.activite.clone()),
                _ => (self.etat.clone(), "inactive".to_string()),
            };
            self.etat = e;
            self.activite = a;
            Ok(())
        }
        fn groupes_de_la_lignee(&self) -> Vec<String> {
            self.lignee.clone()
        }
        fn sessions(&mut self) -> Option<Vec<SessionVue>> {
            self.sessions.clone()
        }
        fn chemin(&self, c: &str) -> Chemin {
            Chemin::Sur { reel: c.to_string() }
        }
    }

    #[allow(
        clippy::large_types_passed_by_value,
        reason = "un geste lu d'une ligne, copié une fois : quelques centaines d'octets"
    )]
    fn faire_avec(d: Defense, a: &mut Faux, s: &mut FauxServices) -> Resultat {
        faire(d, id(), a, s)
    }

    fn defaire(a: &mut Faux, s: &mut FauxServices) -> Resultat {
        faire(Defense::Remettre, id(), a, s)
    }

    /// Rien d'écrit : ni commande lancée qui change, ni note.
    fn rien_ecrit(a: &Faux, avant: &BTreeMap<PathBuf, FauxFichier>) {
        assert!(a.notes.is_empty(), "note écrite");
        assert!(
            !a.journal.iter().any(|l| l.starts_with("usermod")
                || l.starts_with("gpasswd")
                || l.starts_with("changer")
                || l.starts_with("ecrire")
                || l.starts_with("retirer")),
            "{:?}",
            a.journal
        );
        assert_eq!(a.fichiers.len(), avant.len());
        for (p, f) in avant {
            assert_eq!(a.fichiers[p].contenu, f.contenu, "{}", p.display());
            assert_eq!(a.fichiers[p].fiche, f.fiche, "{}", p.display());
        }
    }

    #[test]
    fn verrouiller_puis_defaire() {
        let mut a = Faux::nouveau().repondre("o");
        let mut s = FauxServices::nouveau();
        let r = faire_avec(Defense::VerrouillerCompte(compte("bob")), &mut a, &mut s);
        assert!(r.reussi, "{}", r.raison);
        assert!(
            a.journal
                .contains(&"usermod --lock --expiredate 1 --shell /usr/sbin/nologin -- bob".to_string())
        );
        assert_eq!(a.valeur(SHADOW, "bob", 1), "!$6$b");
        assert_eq!(a.valeur(PASSWD, "bob", 6), "/usr/sbin/nologin");
        assert_eq!(a.notes.len(), 1);
        // Pas de mise en garde : bob n'est pas la personne, et alice reste administratrice.
        assert!(!a.questions[0].contains("AVERTISSEMENT"), "{}", a.questions[0]);
        assert!(a.questions[0].contains("[o/N]"));
        let mut a = a.repondre("oui");
        let r = defaire(&mut a, &mut s);
        assert!(r.reussi, "{}", r.raison);
        assert_eq!(a.valeur(SHADOW, "bob", 1), "$6$b");
        assert_eq!(a.valeur(SHADOW, "bob", 7), "");
        assert_eq!(a.valeur(PASSWD, "bob", 6), "/bin/bash");
        assert!(a.notes.is_empty());
    }

    /// Le terminal de contrôle lu dans /proc/<pid>/stat, même quand le nom du programme contient « ) » et des espaces.
    #[test]
    fn terminal_de_controle_lu() {
        let pts3 = (136 << 8) | 3;
        // pts/300 : le mineur dépasse 255, ses bits hauts passent au-dessus du majeur.
        let pts300 = (136 << 8) | (0x12c & 0xff) | ((0x12c & !0xff) << 12);
        let ligne = |nom: &str, tty: u64| format!("4242 ({nom}) S 1 4242 4242 {tty} 4242 4194560 0 0");
        assert_eq!(
            terminal_de_controle(&ligne("vanguard", pts3)),
            Some((pts3, PathBuf::from("/dev/pts/3")))
        );
        assert_eq!(
            terminal_de_controle(&ligne("a) S 1 2 3 99 (b", pts300)),
            Some((pts300, PathBuf::from("/dev/pts/300")))
        );
        assert_eq!(
            terminal_de_controle(&ligne("agetty", (4 << 8) | 2)),
            Some(((4 << 8) | 2, PathBuf::from("/dev/tty2")))
        );
        for tty in [0, 4 << 8, (4 << 8) | 64, (5 << 8) | 1] {
            assert_eq!(terminal_de_controle(&ligne("x", tty)), None, "{tty}");
        }
        assert_eq!(terminal_de_controle("4242 (x S 1"), None);
    }

    /// Le dernier administrateur, même à clé SSH seule (hash « * ») : verrouillé, plus personne ne s'élève ; c'est dit.
    #[test]
    fn dernier_administrateur_sans_mot_de_passe_averti() {
        for (autre, averti) in [("!$6$a", true), ("$6$a", false)] {
            let mut a = Faux::nouveau().repondre("");
            a.champ(SHADOW, "root", 1, "!$6$r");
            a.champ(SHADOW, "alice", 1, autre);
            a.champ(SHADOW, "bob", 1, "*");
            let r = faire_avec(
                Defense::VerrouillerCompte(compte("bob")),
                &mut a,
                &mut FauxServices::nouveau(),
            );
            assert!(!r.reussi);
            assert_eq!(a.valeur(SHADOW, "bob", 1), "*");
            assert!(a.notes.is_empty());
            assert_eq!(
                a.questions[0].contains("plus personne ne pourra devenir administrateur"),
                averti,
                "{}",
                a.questions[0]
            );
        }
    }

    /// Mot de passe vide à l'origine : dit d'avance, et Défaire rouvre le compte sans --unlock (que usermod refuse).
    #[test]
    fn verrou_d_un_mot_de_passe_vide_defait() {
        let mut a = Faux::nouveau().repondre("o");
        a.champ(SHADOW, "bob", 1, "");
        let mut s = FauxServices::nouveau();
        let r = faire_avec(Defense::VerrouillerCompte(compte("bob")), &mut a, &mut s);
        assert!(r.reussi, "{}", r.raison);
        assert!(
            a.questions[0].contains("ne remettra pas un mot de passe vide"),
            "{}",
            a.questions[0]
        );
        assert_eq!(a.valeur(SHADOW, "bob", 1), "!");
        let mut a = a.repondre("o");
        let r = defaire(&mut a, &mut s);
        assert!(r.reussi, "{}", r.raison);
        assert!(!a.journal.iter().any(|l| l.contains("--unlock")));
        assert_eq!(a.valeur(SHADOW, "bob", 7), "");
        assert_eq!(a.valeur(PASSWD, "bob", 6), "/bin/bash");
        assert!(a.notes.is_empty());
    }

    /// Chaque avertissement anti-verrouillage : une question, Entrée seule = non, rien d'écrit.
    #[test]
    fn avertissements_entree_dit_non() {
        type Preparer = Box<dyn Fn(&mut Faux)>;
        let cas: Vec<(Defense, Preparer)> = vec![
            // root lui-même.
            (Defense::VerrouillerCompte(compte("root")), Box::new(|_| {})),
            // Le compte de la personne.
            (Defense::VerrouillerCompte(compte("alice")), Box::new(|_| {})),
            // Un compte caché de uid 0 quand la personne est root.
            (
                Defense::VerrouillerCompte(compte("toor")),
                Box::new(|a| a.personnes = vec![0]),
            ),
            // Le dernier administrateur (bob verrouillé, root sans mot de passe).
            (
                Defense::RetirerDuGroupe(GroupeSensible::Administrateurs, compte("alice")),
                Box::new(|a| {
                    a.personnes = vec![4242];
                    a.champ(SHADOW, "bob", 1, "!$6$b");
                    a.champ(SHADOW, "root", 1, "*");
                }),
            ),
            // La personne elle-même retirée des administrateurs.
            (
                Defense::RetirerDuGroupe(GroupeSensible::Administrateurs, compte("alice")),
                Box::new(|_| {}),
            ),
            // sudo durci, ni pkexec ni run0.
            (
                Defense::DurcirSudo(compte("alice")),
                Box::new(|a| {
                    a.outils.retain(|o| *o != "pkexec" && *o != "run0");
                    a.sudo_avant = sudo_l(false);
                }),
            ),
            // Le droit setuid retiré du dernier programme qui élève.
            (
                Defense::RetirerSetuid(CheminDesigne::nouveau(b"/usr/bin/su").unwrap()),
                Box::new(|a| {
                    a.fichiers.remove(Path::new("/usr/bin/pkexec"));
                    a.paquets
                        .insert("/usr/bin/su".into(), EtatPaquet::Modifie("util-linux".into()));
                }),
            ),
        ];
        for (i, (d, preparer)) in cas.into_iter().enumerate() {
            let mut a = Faux::nouveau().repondre("");
            preparer(&mut a);
            let avant = a.fichiers.clone();
            let mut s = FauxServices::nouveau();
            let r = faire_avec(d, &mut a, &mut s);
            assert!(!r.reussi, "cas {i}");
            assert_eq!(a.questions.len(), 1, "cas {i} : {}", r.raison);
            assert!(a.questions[0].contains("AVERTISSEMENT"), "cas {i} : {}", a.questions[0]);
            assert!(a.questions[0].contains("[o/N] (Entrée seule : non)"), "cas {i}");
            rien_ecrit(&a, &avant);
        }
    }

    /// Relecture D7a : sudo durci pour un compte sans mot de passe utilisable lui ôterait sudo, et Défaire avec :
    /// refusé, sans question, rien d'écrit, même avec un « o » prêt.
    #[test]
    fn sudo_durci_sans_mot_de_passe_refuse() {
        let mut a = Faux::nouveau().repondre("o");
        a.champ(SHADOW, "alice", 1, "*");
        a.sudo_avant = sudo_l(false);
        let avant = a.fichiers.clone();
        let r = faire_avec(
            Defense::DurcirSudo(compte("alice")),
            &mut a,
            &mut FauxServices::nouveau(),
        );
        assert!(!r.reussi);
        assert!(r.raison.contains("« passwd alice »"), "{}", r.raison);
        assert_eq!(a.questions.len(), 0);
        rien_ecrit(&a, &avant);
    }

    /// Relecture D7a : l'avertissement de sudo durci ne promet plus un mot de passe « gardé quelques minutes » (rien
    /// n'est gardé après une règle sans mot de passe) ; il dit la vraie voie du retour.
    #[test]
    fn sudo_durci_avertissement_dit_vrai() {
        let mut a = Faux::nouveau().repondre("");
        a.outils.retain(|o| *o != "pkexec" && *o != "run0");
        a.sudo_avant = sudo_l(false);
        let _ = faire_avec(
            Defense::DurcirSudo(compte("alice")),
            &mut a,
            &mut FauxServices::nouveau(),
        );
        let q = &a.questions[0];
        assert!(!q.contains("quelques minutes"), "{q}");
        assert!(
            q.contains("sudo demandera votre mot de passe") && q.contains("live USB"),
            "{q}"
        );
    }

    /// « non annulable » est dit quand c'est vrai : le dernier élévateur sans run0.
    #[test]
    fn setuid_du_dernier_elevateur_non_annulable() {
        let mut a = Faux::nouveau().repondre("o");
        a.fichiers.remove(Path::new("/usr/bin/pkexec"));
        a.outils.retain(|o| *o != "run0");
        a.paquets
            .insert("/usr/bin/su".into(), EtatPaquet::Modifie("util-linux".into()));
        let r = faire_avec(
            Defense::RetirerSetuid(CheminDesigne::nouveau(b"/usr/bin/su").unwrap()),
            &mut a,
            &mut FauxServices::nouveau(),
        );
        assert!(r.reussi, "{}", r.raison);
        assert!(a.questions[0].contains("non annulable"), "{}", a.questions[0]);
        assert!(a.questions[0].contains("live USB"));
        assert_eq!(a.mode("/usr/bin/su"), 0o755);
    }

    /// Une issue qui ne s'ouvre pas ne compte pas : su avec root verrouillé, pkexec sans administrateur à mot de passe.
    #[test]
    fn elevateur_inutilisable_ne_compte_pas() {
        // Le geste, le programme désigné, la machine préparée, l'avertissement attendu.
        type Cas = (fn() -> Defense, &'static str, fn(&mut Faux), bool);
        let pkexec = || Defense::RetirerSetuid(CheminDesigne::nouveau(b"/usr/bin/pkexec").unwrap());
        let su = || Defense::RetirerSetuid(CheminDesigne::nouveau(b"/usr/bin/su").unwrap());
        let cas: [Cas; 4] = [
            (pkexec, "/usr/bin/pkexec", |_| {}, false),
            (pkexec, "/usr/bin/pkexec", |a| a.champ(SHADOW, "root", 1, "!$6$r"), true),
            (su, "/usr/bin/su", |_| {}, false),
            (
                su,
                "/usr/bin/su",
                |a| {
                    a.champ(SHADOW, "alice", 1, "!$6$a");
                    a.champ(SHADOW, "bob", 1, "*");
                },
                true,
            ),
        ];
        for (i, (d, chemin, preparer, averti)) in cas.into_iter().enumerate() {
            let mut a = Faux::nouveau().repondre("");
            a.paquets
                .insert(chemin.into(), EtatPaquet::Modifie("util-linux".into()));
            preparer(&mut a);
            let r = faire_avec(d(), &mut a, &mut FauxServices::nouveau());
            assert!(!r.reussi, "cas {i}");
            assert_eq!(a.questions.len(), 1, "cas {i}");
            assert_eq!(
                a.questions[0].contains("AVERTISSEMENT"),
                averti,
                "cas {i} : {}",
                a.questions[0]
            );
            assert_eq!(a.mode(chemin), 0o4755, "cas {i}");
        }
    }

    #[test]
    fn sans_terminal_rien() {
        let mut a = Faux::nouveau();
        let avant = a.fichiers.clone();
        let r = faire_avec(
            Defense::VerrouillerCompte(compte("bob")),
            &mut a,
            &mut FauxServices::nouveau(),
        );
        assert!(!r.reussi);
        assert!(r.raison.contains("terminal"), "{}", r.raison);
        rien_ecrit(&a, &avant);
    }

    #[test]
    fn compte_du_systeme_refuse() {
        let mut a = Faux::nouveau().repondre("o");
        let r = faire_avec(
            Defense::VerrouillerCompte(compte("daemon")),
            &mut a,
            &mut FauxServices::nouveau(),
        );
        assert!(!r.reussi);
        assert_eq!(a.questions.len(), 0);
    }

    /// Ce qui a été montré change pendant la question : rien n'est fait.
    #[test]
    fn change_pendant_la_question_rien() {
        let mut a = Faux::nouveau().repondre("o");
        let passwd = PASSWD_DE.replace("/home/bob:/bin/bash", "/home/bob:/bin/zsh");
        a.pendant_la_question = Some((PASSWD.into(), passwd.into_bytes()));
        let r = faire_avec(
            Defense::VerrouillerCompte(compte("bob")),
            &mut a,
            &mut FauxServices::nouveau(),
        );
        assert!(!r.reussi);
        assert!(a.notes.is_empty());
        assert!(!a.journal.iter().any(|l| l.starts_with("usermod")));
    }

    #[test]
    fn note_deja_la_refuse() {
        let mut a = Faux::nouveau().repondre("o");
        a.notes.insert(ID.into(), b"x".to_vec());
        let r = faire_avec(
            Defense::VerrouillerCompte(compte("bob")),
            &mut a,
            &mut FauxServices::nouveau(),
        );
        assert!(!r.reussi);
        assert_eq!(a.questions.len(), 0);
    }

    #[test]
    fn groupe_docker_puis_defaire() {
        let mut a = Faux::nouveau().repondre("o");
        let mut s = FauxServices::nouveau();
        let r = faire_avec(
            Defense::RetirerDuGroupe(GroupeSensible::Docker, compte("alice")),
            &mut a,
            &mut s,
        );
        assert!(r.reussi, "{}", r.raison);
        assert!(a.journal.contains(&"gpasswd -d alice -- docker".to_string()));
        assert_eq!(a.valeur(GROUP, "docker", 3), "");
        assert!(a.questions[0].contains("prochaine session"));
        let mut a = a.repondre("o");
        assert!(defaire(&mut a, &mut s).reussi);
        assert_eq!(a.valeur(GROUP, "docker", 3), "alice");
    }

    #[test]
    fn groupe_principal_refuse() {
        let mut a = Faux::nouveau().repondre("o");
        a.champ(PASSWD, "alice", 3, "970");
        let r = faire_avec(
            Defense::RetirerDuGroupe(GroupeSensible::Docker, compte("alice")),
            &mut a,
            &mut FauxServices::nouveau(),
        );
        assert!(!r.reussi);
        assert!(r.raison.contains("principal"), "{}", r.raison);
    }

    /// `sudo -l -U alice` en anglais, avec ou sans le complément de Vanguard.
    fn sudo_l(apres: bool) -> String {
        let mut t = String::from(
            "Matching Defaults entries for alice on salon:\n    env_reset, !authenticate, timestamp_timeout=-1\n",
        );
        if apres {
            t.push_str("    authenticate, timestamp_timeout=5\n");
        }
        t.push_str("\nUser alice may run the following commands on salon:\n    (ALL : ALL) NOPASSWD: ALL\n");
        if apres {
            t.push_str("    (ALL : ALL) PASSWD: ALL\n");
        }
        t
    }

    #[test]
    fn sudo_durci_puis_defaire() {
        let mut a = Faux::nouveau().repondre("o");
        a.sudo_avant = sudo_l(false);
        a.sudo_apres = sudo_l(true);
        let mut s = FauxServices::nouveau();
        let r = faire_avec(Defense::DurcirSudo(compte("alice")), &mut a, &mut s);
        assert!(r.reussi, "{}", r.raison);
        assert_eq!(
            a.texte("/etc/sudoers.d/zz-vanguard-alice"),
            "# Vanguard : geste de defense / defense step. Defaire (Undo) le retire.\nDefaults:alice authenticate\nDefaults:alice timestamp_timeout=5\nalice ALL=(ALL : ALL) PASSWD: ALL\n"
        );
        assert_eq!(a.mode("/etc/sudoers.d/zz-vanguard-alice"), 0o440);
        assert!(
            !a.fichiers
                .contains_key(Path::new("/etc/sudoers.d/.zz-vanguard-alice.tmp"))
        );
        let i = a.journal.iter().position(|l| l.starts_with("visudo -c -q -f")).unwrap();
        assert!(a.journal[i + 1..].contains(&"visudo -c -q".to_string()));
        let mut a = a.repondre("o");
        assert!(defaire(&mut a, &mut s).reussi);
        assert!(!a.fichiers.contains_key(Path::new("/etc/sudoers.d/zz-vanguard-alice")));
        assert!(a.notes.is_empty());
    }

    /// `visudo -cf` en échec : rien n'est posé, la note est retirée.
    #[test]
    fn visudo_en_echec_rien_ecrit() {
        for (seul, tout) in [(1, 0), (0, 1)] {
            let mut a = Faux::nouveau().repondre("o");
            a.sudo_avant = sudo_l(false);
            a.sudo_apres = sudo_l(true);
            a.visudo_seul = seul;
            a.visudo_tout = tout;
            let r = faire_avec(
                Defense::DurcirSudo(compte("alice")),
                &mut a,
                &mut FauxServices::nouveau(),
            );
            assert!(!r.reussi);
            assert!(r.raison.contains("visudo"), "{}", r.raison);
            assert!(
                !a.fichiers
                    .keys()
                    .any(|p| p.starts_with("/etc/sudoers.d/") && p != Path::new("/etc/sudoers.d"))
            );
            assert!(a.notes.is_empty());
        }
    }

    /// Un complément sans effet (une règle venue après l'emporte) est retiré.
    #[test]
    fn sudo_sans_effet_retire() {
        let mut a = Faux::nouveau().repondre("o");
        a.sudo_avant = sudo_l(false);
        a.sudo_apres = sudo_l(false);
        let r = faire_avec(
            Defense::DurcirSudo(compte("alice")),
            &mut a,
            &mut FauxServices::nouveau(),
        );
        assert!(!r.reussi);
        assert!(!a.fichiers.contains_key(Path::new("/etc/sudoers.d/zz-vanguard-alice")));
        assert!(a.notes.is_empty());
    }

    #[test]
    fn sudo_regle_complexe_refusee() {
        let mut a = Faux::nouveau().repondre("o");
        a.sudo_avant =
            "User alice may run the following commands on salon:\n    (ALL) NOPASSWD: ALL, !/usr/bin/su\n".into();
        let r = faire_avec(
            Defense::DurcirSudo(compte("alice")),
            &mut a,
            &mut FauxServices::nouveau(),
        );
        assert!(!r.reussi);
        assert_eq!(a.questions.len(), 0);
    }

    fn programme(a: &mut Faux, p: &str, mode: u32) {
        a.poser(p, b"\x7fELF", mode);
    }

    #[test]
    fn setuid_dans_tmp_puis_defaire() {
        let mut a = Faux::nouveau().repondre("o");
        programme(&mut a, "/tmp/.x", 0o4755);
        let mut s = FauxServices::nouveau();
        let c = CheminDesigne::nouveau(b"/tmp/.x").unwrap();
        let r = faire_avec(Defense::RetirerSetuid(c), &mut a, &mut s);
        assert!(r.reussi, "{}", r.raison);
        assert_eq!(a.mode("/tmp/.x"), 0o755);
        let mut a = a.repondre("o");
        assert!(defaire(&mut a, &mut s).reussi);
        assert_eq!(a.mode("/tmp/.x"), 0o4755);
    }

    /// Paquet illisible, ou programme intact de son paquet : refusé, sans question.
    #[test]
    fn paquet_illisible_ou_intact_refuse() {
        for etat in [EtatPaquet::Illisible, EtatPaquet::Intact("sudo".into())] {
            let mut a = Faux::nouveau().repondre("o");
            programme(&mut a, "/usr/local/bin/x", 0o4755);
            a.paquets.insert("/usr/local/bin/x".into(), etat);
            let r = faire_avec(
                Defense::RetirerSetuid(CheminDesigne::nouveau(b"/usr/local/bin/x").unwrap()),
                &mut a,
                &mut FauxServices::nouveau(),
            );
            assert!(!r.reussi);
            assert_eq!(a.questions.len(), 0);
            assert_eq!(a.mode("/usr/local/bin/x"), 0o4755);
        }
    }

    /// Un lien désigné : refusé (le fils ne suit jamais un lien vers ce qu'il changerait).
    #[test]
    fn lien_refuse() {
        let mut a = Faux::nouveau().repondre("o");
        programme(&mut a, "/usr/bin/sudo", 0o4755);
        a.liens.insert("/tmp/x".into(), "/usr/bin/sudo".into());
        let r = faire_avec(
            Defense::RetirerSetuid(CheminDesigne::nouveau(b"/tmp/x").unwrap()),
            &mut a,
            &mut FauxServices::nouveau(),
        );
        assert!(!r.reussi);
        assert_eq!(a.mode("/usr/bin/sudo"), 0o4755);
    }

    #[test]
    fn capacites_puis_defaire() {
        let mut a = Faux::nouveau().repondre("o");
        programme(&mut a, "/opt/x", 0o755);
        a.fichiers.get_mut(Path::new("/opt/x")).unwrap().caps = Some(vec![1, 2, 3]);
        let mut s = FauxServices::nouveau();
        let r = faire_avec(
            Defense::RetirerCapacites(CheminDesigne::nouveau(b"/opt/x").unwrap()),
            &mut a,
            &mut s,
        );
        assert!(r.reussi, "{}", r.raison);
        assert_eq!(a.fichiers[Path::new("/opt/x")].caps, None);
        let mut a = a.repondre("o");
        assert!(defaire(&mut a, &mut s).reussi);
        assert_eq!(a.fichiers[Path::new("/opt/x")].caps, Some(vec![1, 2, 3]));
    }

    /// Un nom hostile (saut de ligne, échappement de terminal, retour chariot, très long) : échappé par le fils.
    #[test]
    fn nom_hostile_echappe() {
        let mut nom = b"/tmp/a\n\x1b[2J\rVanguard (administrateur) : rien\x9b".to_vec();
        nom.extend(std::iter::repeat_n(b'z', 200));
        let mut a = Faux::nouveau();
        let chemin = PathBuf::from(OsStr::from_bytes(&nom));
        a.ino += 1;
        a.fichiers.insert(
            chemin,
            FauxFichier {
                contenu: b"x".to_vec(),
                fiche: fiche(Genre::Fichier, 0o4755, 0, a.ino),
                caps: None,
            },
        );
        let r = faire_avec(
            Defense::RetirerSetuid(CheminDesigne::nouveau(&nom).unwrap()),
            &mut a,
            &mut FauxServices::nouveau(),
        );
        assert!(!r.reussi);
        let q = &a.questions[0];
        assert!(
            !q.contains('\x1b') && !q.contains('\r') && !q.contains('\u{9b}'),
            "{q:?}"
        );
        assert!(q.contains("\\x0a\\x1b[2J\\x0d"), "{q}");
        // Le nom n'ajoute aucune ligne : chaque saut de ligne de la question est le sien.
        assert_eq!(q.lines().count(), 3, "{q}");
    }

    #[test]
    fn dossier_a_root_puis_defaire() {
        let mut a = Faux::nouveau().repondre("o");
        a.dossier("/usr/local/bin", 0o775, 1000);
        let mut s = FauxServices::nouveau();
        let c = CheminDesigne::nouveau(b"/usr/local/bin").unwrap();
        let r = faire_avec(Defense::RendreDossierARoot(c), &mut a, &mut s);
        assert!(r.reussi, "{}", r.raison);
        let f = a.fichiers[Path::new("/usr/local/bin")].fiche;
        assert_eq!((f.uid, f.gid, f.mode), (0, 0, 0o755));
        let mut a = a.repondre("o");
        assert!(defaire(&mut a, &mut s).reussi);
        let f = a.fichiers[Path::new("/usr/local/bin")].fiche;
        assert_eq!((f.uid, f.gid, f.mode), (1000, 1000, 0o775));
        // Hors des dossiers de root : refusé.
        a.dossier("/opt/bin", 0o777, 1000);
        let r = faire(
            Defense::RendreDossierARoot(CheminDesigne::nouveau(b"/opt/bin").unwrap()),
            IdNote::nouveau("1111111111111111").unwrap(),
            &mut a,
            &mut s,
        );
        assert!(!r.reussi);
    }

    fn service(a: &mut Faux) {
        a.poser(
            "/etc/systemd/system/minage.service",
            b"[Service]\nExecStart=/opt/m\n",
            0o644,
        );
    }

    #[test]
    fn service_ajoute_puis_defaire() {
        let mut a = Faux::nouveau().repondre("o");
        service(&mut a);
        let mut s = FauxServices::nouveau();
        let u = NomUnite::nouveau("minage.service").unwrap();
        let r = faire_avec(Defense::DesactiverService(u), &mut a, &mut s);
        assert!(r.reussi, "{}", r.raison);
        assert_eq!(s.faits, ["desactiver minage.service"]);
        let mut a = a.repondre("o");
        assert!(defaire(&mut a, &mut s).reussi);
        assert_eq!(s.faits, ["desactiver minage.service", "activer minage.service"]);
    }

    /// Relecture D7a : un service activé qui ne tournait pas revient activé, sans être lancé un instant (pas de
    /// `enable --now` suivi de `stop`) ; il reste arrêté.
    #[test]
    fn service_active_mais_arrete_remis_sans_etre_lance() {
        let mut a = Faux::nouveau().repondre("o");
        service(&mut a);
        let mut s = FauxServices::nouveau();
        s.activite = "inactive".into();
        let u = NomUnite::nouveau("minage.service").unwrap();
        assert!(faire_avec(Defense::DesactiverService(u), &mut a, &mut s).reussi);
        let mut a = a.repondre("o");
        assert!(defaire(&mut a, &mut s).reussi);
        assert_eq!(
            s.faits,
            ["desactiver minage.service", "activer-sans-demarrer minage.service"]
        );
        assert_eq!((s.etat.as_str(), s.activite.as_str()), ("enabled", "inactive"));
    }

    /// Essai QEMU D7a (Arch, pacman-init.service, `ConditionFirstBoot=yes`) : un service qui tournait et que systemd
    /// refuse de relancer à cause de ses propres conditions revient lancé au démarrage, et sa note se retire (gardée,
    /// elle bloquait pour toujours les remises suivantes). Un service qui ne se relance pas pour une autre raison
    /// reste un échec, sa note gardée.
    #[test]
    fn service_a_condition_refusee_remis_au_demarrage() {
        for (refusee, reussi) in [(true, true), (false, false)] {
            let mut a = Faux::nouveau().repondre("o");
            service(&mut a);
            let mut s = FauxServices::nouveau();
            let u = NomUnite::nouveau("minage.service").unwrap();
            assert!(faire_avec(Defense::DesactiverService(u), &mut a, &mut s).reussi);
            s.condition_refusee = refusee;
            s.ne_demarre_pas = !refusee;
            let mut a = a.repondre("o");
            let r = defaire(&mut a, &mut s);
            assert_eq!(r.reussi, reussi, "{refusee} {}", r.raison);
            assert_eq!(s.faits, ["desactiver minage.service", "activer minage.service"]);
            assert_eq!((s.etat.as_str(), s.activite.as_str()), ("enabled", "inactive"));
            assert_eq!(a.notes.is_empty(), reussi, "{refusee}");
            let question = a.questions.last().cloned().unwrap_or_default();
            assert!(
                question.contains("seul son lancement au démarrage revient"),
                "{question}"
            );
        }
    }

    /// La session en cours (sshd, gestionnaire de session) : refus, jamais une question.
    #[test]
    fn service_de_session_refuse() {
        for nom in [
            "sshd.service",
            "gdm.service",
            "sddm.service",
            "ssh.socket",
            "openvpn-salon.service",
            "nftables.service",
        ] {
            let mut a = Faux::nouveau().repondre("o");
            a.poser(&format!("/etc/systemd/system/{nom}"), b"[Service]\n", 0o644);
            let mut s = FauxServices::nouveau();
            let r = faire_avec(
                Defense::DesactiverService(NomUnite::nouveau(nom).unwrap()),
                &mut a,
                &mut s,
            );
            assert!(!r.reussi, "{nom}");
            assert!(a.questions.is_empty() && s.faits.is_empty(), "{nom}");
        }
        // Vanguard tourne dans une session ouverte par ce service : refusé.
        let mut a = Faux::nouveau().repondre("o");
        service(&mut a);
        let mut s = FauxServices::nouveau();
        s.lignee = vec!["/system.slice/minage.service/session".into()];
        let u = NomUnite::nouveau("minage.service").unwrap();
        assert!(!faire_avec(Defense::DesactiverService(u), &mut a, &mut s).reussi);
        // Les sessions ne se lisent pas : refusé.
        s.lignee.clear();
        s.sessions = None;
        assert!(!faire_avec(Defense::DesactiverService(u), &mut a, &mut s).reussi);
        assert!(a.questions.is_empty() && s.faits.is_empty());
        // D'un paquet, ou paquet illisible : refusé.
        s.sessions = Some(Vec::new());
        for etat in [EtatPaquet::Illisible, EtatPaquet::Intact("x".into())] {
            a.paquets.insert("/etc/systemd/system/minage.service".into(), etat);
            assert!(!faire_avec(Defense::DesactiverService(u), &mut a, &mut s).reussi);
        }
        assert!(a.questions.is_empty() && s.faits.is_empty());
    }

    #[test]
    fn ligne_suspecte_puis_defaire() {
        let mut a = Faux::nouveau().repondre("o");
        let avant = b"# rien\n/tmp/.x/libhook.so\n".to_vec();
        a.poser("/etc/ld.so.preload", &avant, 0o644);
        let mut s = FauxServices::nouveau();
        let e = empreinte_de_ligne(b"/tmp/.x/libhook.so");
        let c = CheminDesigne::nouveau(b"/etc/ld.so.preload").unwrap();
        let r = faire_avec(Defense::RetirerLigne(e, c), &mut a, &mut s);
        assert!(r.reussi, "{}", r.raison);
        assert_eq!(a.texte("/etc/ld.so.preload"), "# rien\n");
        let mut a = a.repondre("o");
        assert!(defaire(&mut a, &mut s).reussi);
        assert_eq!(a.fichiers[Path::new("/etc/ld.so.preload")].contenu, avant);
    }

    /// Une ligne de ld.so.preload qui nomme plusieurs bibliothèques part en entier : c'est dit avant la question.
    #[test]
    fn ligne_de_plusieurs_bibliotheques_dite() {
        for (ligne, dit) in [
            (&b"/usr/lib/libalice.so /tmp/.x/libhook.so"[..], true),
            (b"/usr/lib/libalice.so:/tmp/.x/libhook.so", true),
            (b"/tmp/.x/libhook.so", false),
        ] {
            let mut a = Faux::nouveau().repondre("");
            let mut contenu = ligne.to_vec();
            contenu.push(b'\n');
            a.poser("/etc/ld.so.preload", &contenu, 0o644);
            let c = CheminDesigne::nouveau(b"/etc/ld.so.preload").unwrap();
            let r = faire_avec(
                Defense::RetirerLigne(empreinte_de_ligne(ligne), c),
                &mut a,
                &mut FauxServices::nouveau(),
            );
            assert!(!r.reussi);
            assert_eq!(a.questions[0].contains("2 bibliothèques"), dit, "{}", a.questions[0]);
            assert_eq!(a.fichiers[Path::new("/etc/ld.so.preload")].contenu, contenu);
        }
    }

    /// Une ligne qui n'est pas suspecte (un réglage ordinaire) : refusée, même désignée par son empreinte.
    #[test]
    fn ligne_ordinaire_refusee() {
        let mut a = Faux::nouveau().repondre("o");
        a.poser("/etc/profile", b"umask 077\nexport PATH=/usr/bin\n", 0o644);
        let r = faire_avec(
            Defense::RetirerLigne(
                empreinte_de_ligne(b"umask 077"),
                CheminDesigne::nouveau(b"/etc/profile").unwrap(),
            ),
            &mut a,
            &mut FauxServices::nouveau(),
        );
        assert!(!r.reussi);
        assert_eq!(a.questions.len(), 0);
        assert_eq!(a.texte("/etc/profile"), "umask 077\nexport PATH=/usr/bin\n");
    }

    #[test]
    fn ouverture_automatique_coupee() {
        let mut a = Faux::nouveau().repondre("o");
        a.poser(
            "/etc/gdm/custom.conf",
            b"[daemon]\nAutomaticLoginEnable=True\nAutomaticLogin=alice\n",
            0o644,
        );
        let c = CheminDesigne::nouveau(b"/etc/gdm/custom.conf").unwrap();
        let r = faire_avec(
            Defense::RetirerLigne(empreinte_de_ligne(b"AutomaticLoginEnable=True"), c),
            &mut a,
            &mut FauxServices::nouveau(),
        );
        assert!(r.reussi, "{}", r.raison);
        assert_eq!(a.texte("/etc/gdm/custom.conf"), "[daemon]\nAutomaticLogin=alice\n");
    }

    /// Le texte hostile d'une ligne montrée : échappé.
    #[test]
    fn ligne_hostile_echappee() {
        let mut a = Faux::nouveau();
        a.poser("/etc/ld.so.preload", b"/tmp/x.so\x1b]0;titre\x07\r\n", 0o644);
        let e = empreinte_de_ligne(b"/tmp/x.so\x1b]0;titre\x07\r");
        let _ = faire_avec(
            Defense::RetirerLigne(e, CheminDesigne::nouveau(b"/etc/ld.so.preload").unwrap()),
            &mut a,
            &mut FauxServices::nouveau(),
        );
        let q = &a.questions[0];
        assert!(!q.contains('\x1b') && !q.contains('\r') && !q.contains('\x07'), "{q:?}");
    }

    /// Une note abîmée, d'un autre identifiant, ou qui demande « remettre » : rien n'est remis.
    #[test]
    fn note_forgee_refusee() {
        let mut s = FauxServices::nouveau();
        let ligne = GesteUnix::Defense(Defense::VerrouillerCompte(compte("bob")), id()).ligne();
        let autre = GesteUnix::Defense(
            Defense::VerrouillerCompte(compte("bob")),
            IdNote::nouveau("1111111111111111").unwrap(),
        )
        .ligne();
        let remettre = GesteUnix::Defense(Defense::Remettre, id()).ligne();
        for geste in [autre, remettre, "vanguard:geste programme x".to_string()] {
            let mut a = Faux::nouveau().repondre("o");
            a.champ(SHADOW, "bob", 1, "!$6$b");
            let n = Note {
                geste,
                date: 1,
                champs: vec![("verrouille".into(), b"non".to_vec())],
            };
            a.notes.insert(ID.into(), n.octets(ID).unwrap());
            assert!(!defaire(&mut a, &mut s).reussi);
            assert_eq!(a.valeur(SHADOW, "bob", 1), "!$6$b");
        }
        let mut a = Faux::nouveau().repondre("o");
        let mut o = Note {
            geste: ligne,
            date: 1,
            champs: Vec::new(),
        }
        .octets(ID)
        .unwrap();
        o[10] ^= 1;
        a.notes.insert(ID.into(), o);
        assert!(!defaire(&mut a, &mut s).reussi);
        assert_eq!(a.questions.len(), 0);
    }

    /// Défaire après un changement fait par quelqu'un d'autre : rien n'est écrasé.
    #[test]
    fn defaire_apres_changement_refuse() {
        let mut a = Faux::nouveau().repondre("o");
        programme(&mut a, "/tmp/.x", 0o4755);
        let mut s = FauxServices::nouveau();
        let c = CheminDesigne::nouveau(b"/tmp/.x").unwrap();
        assert!(faire_avec(Defense::RetirerSetuid(c), &mut a, &mut s).reussi);
        a.fichiers.get_mut(Path::new("/tmp/.x")).unwrap().contenu = b"autre".to_vec();
        let mut a = a.repondre("o");
        assert!(!defaire(&mut a, &mut s).reussi);
        assert_eq!(a.mode("/tmp/.x"), 0o755);
        assert_eq!(a.notes.len(), 1);
    }

    #[test]
    fn problemes_sudo_lus() {
        let p = problemes_sudo(&sudo_l(false)).unwrap();
        assert!(p.jamais);
        assert_eq!(p.delai, Some(-1.0));
        assert_eq!(p.cibles, ["ALL : ALL"]);
        let p = problemes_sudo(&sudo_l(true)).unwrap();
        assert_eq!(
            p,
            ProblemesSudo {
                jamais: false,
                delai: None,
                cibles: Vec::new()
            }
        );
        // Une cible piégée (coupée par un saut de ligne, ou hors des caractères admis) : refusée.
        assert!(problemes_sudo("User alice may run:\n    (ALL) NOPASSWD: ALL\n    (ALL\nx) NOPASSWD: ALL\n").is_err());
        assert!(problemes_sudo("User a may run:\n    (ALL=#) NOPASSWD: ALL\n").is_err());
    }

    mod d7b;
    mod d7c;
}

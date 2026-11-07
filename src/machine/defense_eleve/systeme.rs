//! Lot D7b : les gestes de défense du système, rejugés par root comme les autres (`defense_eleve`). Le serveur SSH
//! (un fichier de sshd_config.d validé par `sshd -t`, refusé depuis une session SSH), BPF réservé aux
//! administrateurs, le journal gardé sur le disque, un fichier de certificats racine illisible retiré, une ligne de
//! proxy mise en commentaire, un appareil Bluetooth oublié. Rien n'y vient de la ligne du parent que ce qu'elle
//! désigne : chaque chemin et chaque commande sont ceux que Vanguard écrit lui-même.

use super::*;
use crate::machine::gestes_unix::{AdresseBt, ReglageSsh};

// ————— Serveur SSH —————

const SSHD_D: &str = "/etc/ssh/sshd_config.d";
/// Les noms du service de sshd selon la distribution (Debian : ssh.service, sshd.service en alias).
const UNITES_SSH: [&str; 2] = ["sshd.service", "ssh.service"];
/// La taille la plus grande d'un fichier authorized_keys lu.
const CLES_MAX: usize = 1024 * 1024;

/// Le fichier de Vanguard pour ce réglage : « 00-vanguard-… » passe avant les autres fichiers de sshd_config.d
/// (sshd garde la première valeur lue), et avant 00-vanguard.conf, celui des corrections à la main.
fn fichier_ssh(r: ReglageSsh) -> PathBuf {
    PathBuf::from(format!("{SSHD_D}/00-vanguard-{}.conf", r.mot()))
}

fn contenu_ssh(r: ReglageSsh) -> &'static [u8] {
    match r {
        ReglageSsh::MotsDePasseVides => b"PermitEmptyPasswords no\n",
        ReglageSsh::Root => b"PermitRootLogin no\n",
        ReglageSsh::MotsDePasse => b"PasswordAuthentication no\nKbdInteractiveAuthentication no\n",
    }
}

/// La configuration que sshd lirait (`sshd -T`) : chaque clé, en minuscules, avec sa valeur.
fn config_sshd(a: &mut dyn Acces) -> Result<Vec<(String, String)>, Echec> {
    let r = lancer_ok(a, "sshd", &[os("-T")])?;
    Ok(r.sortie
        .lines()
        .filter_map(|l| {
            let (k, v) = l.trim().split_once(' ')?;
            Some((k.to_ascii_lowercase(), v.trim().to_string()))
        })
        .collect())
}

fn valeur<'a>(cfg: &'a [(String, String)], cle: &str) -> Option<&'a str> {
    cfg.iter().find(|(k, _)| k == cle).map(|(_, v)| v.as_str())
}

fn valeur_exigee<'a>(cfg: &'a [(String, String)], cle: &str) -> Result<&'a str, Echec> {
    valeur(cfg, cle).ok_or_else(|| {
        refus(trf!(
            "sshd -T ne dit pas « {cle} » : rien n'est fait",
            "sshd -T does not say \"{cle}\": nothing is done"
        ))
    })
}

/// Ce que dit sshd -T des clés de ce réglage, montré tel quel (échappé).
fn etat_ssh(r: ReglageSsh, cfg: &[(String, String)]) -> Result<String, Echec> {
    let cles: &[&str] = match r {
        ReglageSsh::MotsDePasseVides => &["permitemptypasswords"],
        ReglageSsh::Root => &["permitrootlogin"],
        ReglageSsh::MotsDePasse => &["passwordauthentication", "kbdinteractiveauthentication"],
    };
    let mut vu = Vec::new();
    for k in cles {
        let v = valeur_clavier(cfg, k)?;
        vu.push(format!("{k} {}", echappe(v.as_bytes())));
    }
    Ok(vu.join(", "))
}

/// Une valeur, avec l'ancien nom de KbdInteractiveAuthentication (ChallengeResponseAuthentication, OpenSSH < 8.7).
fn valeur_clavier<'a>(cfg: &'a [(String, String)], cle: &str) -> Result<&'a str, Echec> {
    match (cle, valeur(cfg, cle)) {
        (_, Some(v)) => Ok(v),
        ("kbdinteractiveauthentication", None) => valeur_exigee(cfg, "challengeresponseauthentication"),
        (_, None) => valeur_exigee(cfg, cle),
    }
}

/// Le réglage est-il déjà fermé, d'après sshd -T ? Une clé absente refuse : rien n'est conclu en sa faveur.
fn en_vigueur(r: ReglageSsh, cfg: &[(String, String)]) -> Result<bool, Echec> {
    Ok(match r {
        ReglageSsh::MotsDePasseVides => valeur_exigee(cfg, "permitemptypasswords")? == "no",
        // prohibit-password (le défaut) refuse déjà le mot de passe de root : seul « yes » est à fermer.
        ReglageSsh::Root => valeur_exigee(cfg, "permitrootlogin")? != "yes",
        ReglageSsh::MotsDePasse => {
            valeur_exigee(cfg, "passwordauthentication")? == "no"
                && valeur_clavier(cfg, "kbdinteractiveauthentication")? == "no"
        }
    })
}

/// Un groupe de contrôle de sshd (ou dropbear) lui-même : un processus de la lignée y est, la session vient de lui.
pub(super) fn groupe_ssh(g: &str) -> bool {
    let dernier = g.rsplit('/').next().unwrap_or(g);
    (dernier.starts_with("ssh") && dernier.ends_with(".service"))
        || g.contains("/system-sshd")
        || g.contains("dropbear")
}

fn scope_de_session(g: &str) -> bool {
    let dernier = g.rsplit('/').next().unwrap_or(g);
    // Un nom de cgroup, pas un fichier : la casse compte.
    dernier
        .strip_prefix("session-")
        .is_some_and(|r| r.strip_suffix(".scope").is_some())
}

/// Refusé si Vanguard tourne peut-être dans une session SSH : un réglage de sshd changé depuis elle pourrait couper
/// la personne de son ordinateur. Sans lignée lue, ou sans la liste des sessions, refusé aussi.
pub(super) fn session_ssh(s: &mut dyn Services) -> Result<(), Echec> {
    let refuse = || {
        refus(tr!(
            "Vanguard tourne peut-être dans une session SSH (ou ne peut pas dire le contraire) : changer le serveur SSH depuis elle pourrait vous couper de cet ordinateur. Rien n'est fait ; refaites-le depuis l'écran de l'ordinateur",
            "Vanguard may be running in an SSH session (or cannot tell otherwise): changing the SSH server from it could cut you off from this computer. Nothing is done; do it again from the computer's own screen"
        )
        .to_string())
    };
    let lignee = s.groupes_de_la_lignee();
    if lignee.is_empty() || lignee.iter().any(|g| groupe_ssh(g)) {
        return Err(refuse());
    }
    let sessions = s.sessions().ok_or_else(refuse)?;
    let scopes: Vec<&String> = lignee.iter().filter(|g| scope_de_session(g)).collect();
    let par_ssh = sessions.iter().any(|v| {
        let ssh = v.distante || v.service.starts_with("ssh") || v.service.contains("dropbear");
        ssh && v.groupes_du_meneur.iter().any(|g| scopes.contains(&g))
    });
    if par_ssh {
        return Err(refuse());
    }
    Ok(())
}

/// Un fichier authorized_keys qui donne une clé : une ligne non commentée qui en contient une (ses options devant).
fn contient_une_cle(o: &[u8]) -> bool {
    String::from_utf8_lossy(o).lines().any(|l| {
        let l = l.trim();
        !l.starts_with('#')
            && l.split_whitespace()
                .any(|m| m.starts_with("ssh-") || m.starts_with("ecdsa-") || m.starts_with("sk-"))
    })
}

/// Un chemin d'AuthorizedKeysFile pour ce compte (%h, %u, %U, %%), relatif au dossier personnel ; `None` pour un
/// motif que Vanguard ne sait pas remplir.
pub(super) fn chemin_de_cles(motif: &str, nom: &str, uid: u32, maison: &str) -> Option<PathBuf> {
    let mut sortie = String::new();
    let mut lettres = motif.chars();
    while let Some(c) = lettres.next() {
        if c != '%' {
            sortie.push(c);
            continue;
        }
        match lettres.next()? {
            'h' => sortie.push_str(maison),
            'u' => sortie.push_str(nom),
            'U' => sortie.push_str(&uid.to_string()),
            '%' => sortie.push('%'),
            _ => return None,
        }
    }
    let p = PathBuf::from(&sortie);
    Some(if p.is_absolute() { p } else { Path::new(maison).join(p) })
}

/// Chaque personne devant l'écran a-t-elle une clé SSH que sshd accepterait ? Sinon, couper les mots de passe la
/// couperait de son ordinateur à distance : refusé.
fn cles_presentes(a: &mut dyn Acces, cfg: &[(String, String)]) -> Result<(), Echec> {
    if valeur_exigee(cfg, "pubkeyauthentication")? != "yes" {
        return Err(refus(tr!(
            "sshd refuse les clés (PubkeyAuthentication) : couper les mots de passe fermerait le SSH à tous. Rien n'est fait",
            "sshd refuses keys (PubkeyAuthentication): turning off passwords would close SSH to everyone. Nothing is done"
        )
        .to_string()));
    }
    if valeur_exigee(cfg, "authenticationmethods")? != "any" {
        return Err(refus(tr!(
            "sshd a ses propres méthodes de connexion (AuthenticationMethods) : Vanguard n'y touche pas. Rien n'est fait",
            "sshd has its own login methods (AuthenticationMethods): Vanguard does not touch them. Nothing is done"
        )
        .to_string()));
    }
    let motifs = valeur_exigee(cfg, "authorizedkeysfile")?.to_string();
    let personnes = a.personnes();
    if personnes.is_empty() {
        return Err(refus(tr!(
            "Vanguard ne sait pas quel compte est devant l'écran : il ne peut pas vérifier que le vôtre a une clé SSH. Rien n'est fait",
            "Vanguard does not know which account is at the screen: it cannot check that yours has an SSH key. Nothing is done"
        )
        .to_string()));
    }
    let passwd = lire_texte(a, PASSWD)?;
    for uid in personnes {
        let ligne = passwd.lines().find_map(|l| match l.split(':').collect::<Vec<_>>()[..] {
            [nom, _, u, _, _, maison, _, ..] if u.parse::<u32>().ok() == Some(uid) => Some((nom, maison)),
            _ => None,
        });
        let Some((nom, maison)) = ligne else {
            return Err(refus(trf!(
                "le compte {uid} n'est pas dans /etc/passwd : sa clé SSH ne se vérifie pas. Rien n'est fait",
                "account {uid} is not in /etc/passwd: its SSH key cannot be checked. Nothing is done"
            )));
        };
        let cles: Vec<PathBuf> = motifs
            .split_whitespace()
            .filter(|m| *m != "none")
            .filter_map(|m| chemin_de_cles(m, nom, uid, maison))
            .filter(|p| {
                fiche_designee(p, Genre::Fichier, a).is_ok_and(|f| (f.uid == uid || f.uid == 0) && f.mode & 0o022 == 0)
                    && a.lire(p, CLES_MAX).is_some_and(|o| contient_une_cle(&o))
            })
            .collect();
        let ouvert = cles
            .iter()
            .map(|p| dossier_ouvert(p, uid, Path::new(maison), a))
            .collect::<Vec<_>>();
        if !cles.is_empty() && ouvert.iter().all(Option::is_some) {
            let d = ouvert.into_iter().flatten().next().unwrap_or_default();
            return Err(refus(trf!(
                "{} est à un autre compte ou modifiable par d'autres : sshd refuserait la clé SSH de {} (StrictModes), et couper les mots de passe le couperait de cet ordinateur à distance. Rien n'est fait ; fermez-le (chmod go-w), puis refaites-le",
                "{} belongs to another account or can be changed by others: sshd would refuse the SSH key of {} (StrictModes), and turning off passwords would cut it off from this computer remotely. Nothing is done; close it (chmod go-w), then do it again",
                lisible(&d),
                echappe(nom.as_bytes())
            )));
        }
        if cles.is_empty() {
            return Err(refus(trf!(
                "le compte {} n'a aucune clé SSH que sshd accepterait (authorized_keys) : couper les mots de passe le couperait de cet ordinateur à distance. Rien n'est fait ; posez d'abord sa clé (ssh-copy-id), puis refaites-le",
                "the account {} has no SSH key sshd would accept (authorized_keys): turning off passwords would cut it off from this computer remotely. Nothing is done; add its key first (ssh-copy-id), then do it again",
                echappe(nom.as_bytes())
            )));
        }
    }
    Ok(())
}

/// Le premier dossier, du fichier de clés jusqu'au dossier personnel (ou jusqu'à / hors de lui), que sshd ne jugerait
/// pas sûr : ni au compte ni à root, modifiable par le groupe ou les autres, ou qui n'est pas un vrai dossier. Avec
/// StrictModes (le réglage par défaut), sshd refuse alors la clé ; Vanguard l'exige même sans, par prudence.
fn dossier_ouvert(cles: &Path, uid: u32, maison: &Path, a: &dyn Acces) -> Option<PathBuf> {
    for d in cles.ancestors().skip(1) {
        let sur = a
            .fiche(d)
            .is_some_and(|f| f.genre == Genre::Dossier && (f.uid == uid || f.uid == 0) && f.mode & 0o022 == 0);
        if !sur {
            return Some(d.to_path_buf());
        }
        if d == maison {
            break;
        }
    }
    None
}

/// Le service de sshd qui tourne, à recharger ; `None` : sshd ne tourne pas en service (lancé par sa socket à chaque
/// connexion, ou arrêté) : il lira le fichier à la prochaine connexion ou au prochain lancement.
fn unite_ssh(s: &mut dyn Services) -> Result<Option<&'static str>, Echec> {
    if !s.systemd() {
        return Ok(None);
    }
    for u in UNITES_SSH {
        if s.etat_d_activite(u)?.is_some_and(|t| tourne(&t)) {
            return Ok(Some(u));
        }
    }
    Ok(None)
}

pub(super) fn juger_ssh(r: ReglageSsh, a: &mut dyn Acces, s: &mut dyn Services) -> Jugement {
    if !a.outil("sshd") {
        return Err(refus(
            tr!(
                "le serveur SSH (sshd) n'est pas installé dans les dossiers du système : rien n'est fait",
                "the SSH server (sshd) is not installed in the system folders: nothing is done"
            )
            .to_string(),
        ));
    }
    let cfg = config_sshd(a)?;
    if en_vigueur(r, &cfg)? {
        return Ok(None);
    }
    let p = fichier_ssh(r);
    let vu = lisible(&p);
    if a.fiche(&p).is_some() {
        return Err(refus(trf!(
            "{vu} est déjà là, sans effet : un réglage lu avant lui l'emporte (sshd_config, ou un fichier de sshd_config.d au nom plus petit). Rien n'est fait",
            "{vu} is already there, without effect: a setting read before it wins (sshd_config, or a file of sshd_config.d with a smaller name). Nothing is done"
        )));
    }
    let d = fiche_designee(Path::new(SSHD_D), Genre::Dossier, a)?;
    if d.uid != 0 || d.mode & 0o022 != 0 {
        return Err(refus(trf!(
            "{SSHD_D} n'est pas à root, ou un autre compte peut le changer : rien n'est fait",
            "{SSHD_D} is not root's, or another account can change it: nothing is done"
        )));
    }
    session_ssh(s)?;
    if r == ReglageSsh::MotsDePasse {
        cles_presentes(a, &cfg)?;
    }
    let unite = unite_ssh(s)?;
    let etat = etat_ssh(r, &cfg)?;
    let contenu = contenu_ssh(r);
    let montre = String::from_utf8_lossy(contenu).trim().replace('\n', " ; ");
    let recharge = match unite {
        Some(u) => trf!("puis {u} rechargé", "then {u} reloaded"),
        None => tr!(
            "sshd ne tourne pas en service : il le lira à sa prochaine connexion ou à son prochain lancement",
            "sshd does not run as a service: it will read it at its next connection or its next start"
        )
        .to_string(),
    };
    let avertissement = match r {
        ReglageSsh::MotsDePasseVides => None,
        ReglageSsh::Root => Some(tr!(
            "root ne pourra plus se connecter en SSH, même avec une clé. Si cet ordinateur ne s'administre à distance qu'en root, gardez d'abord une autre porte : un compte qui a sudo, avec sa clé.",
            "root will no longer be able to log in over SSH, even with a key. If this computer is only managed remotely as root, keep another way in first: an account with sudo, with its key."
        )
        .to_string()),
        ReglageSsh::MotsDePasse => Some(tr!(
            "les mots de passe ne marcheront plus en SSH, seules les clés : un compte sans clé dans authorized_keys ne pourra plus se connecter à distance (le vôtre en a une).",
            "passwords will no longer work over SSH, only keys: an account without a key in authorized_keys will no longer be able to log in remotely (yours has one)."
        )
        .to_string()),
    };
    Ok(Some(Plan {
        texte: trf!(
            "Serveur SSH, aujourd'hui (sshd -T) : {etat}.\nFichier posé : {vu} (« {montre} »), validé par sshd -t avant que sshd ne le relise, {recharge}. Les sessions SSH ouvertes restent ouvertes.",
            "SSH server, today (sshd -T): {etat}.\nFile added: {vu} (\"{montre}\"), checked by sshd -t before sshd reads it, {recharge}. Open SSH sessions stay open."
        ),
        avertissement,
        non_annulable: false,
        seconde: None,
        champs: vec![("avant".into(), etat.into_bytes())],
        action: Action::PoserSsh {
            fichier: p,
            contenu: contenu.to_vec(),
            reglage: r,
            unite,
        },
    }))
}

/// Pose le fichier, le fait valider par sshd -t (en échec : retiré, rien n'est rechargé), vérifie par sshd -T qu'il
/// a pris (sinon : retiré), puis recharge sshd s'il tourne.
pub(super) fn poser_ssh(
    fichier: &Path,
    contenu: &[u8],
    r: ReglageSsh,
    unite: Option<&'static str>,
    a: &mut dyn Acces,
    s: &mut dyn Services,
) -> Result<(), Echec> {
    a.ecrire(
        fichier,
        contenu,
        Ecriture {
            mode: 0o644,
            uid: 0,
            gid: 0,
            avant: None,
        },
    )?;
    let retire = |a: &mut dyn Acces, e: Echec| {
        let _ = a.retirer(fichier);
        Err(e)
    };
    if let Err(e) = lancer_ok(a, "sshd", &[os("-t")]) {
        return retire(a, e);
    }
    match config_sshd(a).and_then(|c| en_vigueur(r, &c)) {
        Ok(true) => {}
        Ok(false) => {
            return retire(
                a,
                refus(tr!(
                    "sans effet : un réglage lu avant celui de Vanguard l'emporte ; le fichier est retiré, rien n'est rechargé",
                    "without effect: a setting read before Vanguard's wins; the file is removed, nothing is reloaded"
                )
                .to_string()),
            );
        }
        Err(e) => return retire(a, e),
    }
    // Rechargement en échec : le fichier est retiré, pour que « pas fait » reste vrai au prochain lancement de sshd.
    if let Some(u) = unite
        && let Err(e) = s.unite(ActionUnite::Recharger, u)
    {
        return retire(a, e);
    }
    Ok(())
}

pub(super) fn remettre_ssh(r: ReglageSsh, a: &mut dyn Acces, s: &mut dyn Services) -> Jugement {
    let p = fichier_ssh(r);
    let vu = lisible(&p);
    if a.fiche(&p).is_none() {
        return Ok(None);
    }
    let f = fiche_designee(&p, Genre::Fichier, a)?;
    if f.uid != 0 || a.lire(&p, 4096).as_deref() != Some(contenu_ssh(r)) {
        return Err(change_depuis(&vu));
    }
    let e = a.empreinte(&p, &f).ok_or_else(|| change_depuis(&vu))?;
    let mut suite = vec![Action::Retirer(p, f, e), Action::Outils(vec![("sshd", vec![os("-t")])])];
    let unite = unite_ssh(s)?;
    if let Some(u) = unite {
        suite.push(Action::UniteSysteme(ActionUnite::Recharger, u));
    }
    Ok(Some(Plan {
        texte: trf!(
            "Fichier {vu} retiré, sshd validé (sshd -t){} : ce réglage revient à ce que dit sshd_config.",
            "File {vu} removed, sshd checked (sshd -t){}: this setting goes back to what sshd_config says.",
            if unite.is_some() {
                tr!(" puis rechargé", " then reloaded")
            } else {
                ""
            }
        ),
        avertissement: None,
        non_annulable: false,
        seconde: None,
        champs: Vec::new(),
        action: Action::Suite(suite),
    }))
}

// ————— BPF —————

const BPF: &str = "/proc/sys/kernel/unprivileged_bpf_disabled";
const BPF_DURABLE: &str = "/etc/sysctl.d/90-vanguard-bpf.conf";
const BPF_CONTENU: &[u8] = b"kernel.unprivileged_bpf_disabled = 2\n";

fn sysctl_bpf(v: u8) -> Action {
    Action::Outils(vec![(
        "sysctl",
        vec![os("-w"), os(&format!("kernel.unprivileged_bpf_disabled={v}"))],
    )])
}

/// La valeur du noyau : 0 (ouvert à tous), 1 (fermé jusqu'au redémarrage), 2 (fermé, root peut rouvrir).
fn valeur_bpf(a: &dyn Acces) -> Result<u8, Echec> {
    a.lire(Path::new(BPF), 16)
        .and_then(|o| String::from_utf8(o).ok())
        .and_then(|t| match t.trim() {
            "0" => Some(0),
            "1" => Some(1),
            "2" => Some(2),
            _ => None,
        })
        .ok_or_else(|| {
            refus(tr!(
                "le réglage BPF du noyau ne se lit pas (/proc/sys/kernel/unprivileged_bpf_disabled) : rien n'est fait",
                "the kernel BPF setting cannot be read (/proc/sys/kernel/unprivileged_bpf_disabled): nothing is done"
            )
            .to_string())
        })
}

/// Le fichier de /etc/sysctl.d que Vanguard pose, s'il est là avec le contenu de Vanguard ; autre chose : refusé.
fn bpf_durable(a: &dyn Acces) -> Result<Option<(Fiche, [u8; 32])>, Echec> {
    let p = Path::new(BPF_DURABLE);
    if a.fiche(p).is_none() {
        return Ok(None);
    }
    let f = fiche_designee(p, Genre::Fichier, a)?;
    if f.uid != 0 || a.lire(p, 4096).as_deref() != Some(BPF_CONTENU) {
        return Err(change_depuis(BPF_DURABLE));
    }
    let e = a.empreinte(p, &f).ok_or_else(|| change_depuis(BPF_DURABLE))?;
    Ok(Some((f, e)))
}

pub(super) fn juger_bpf(a: &mut dyn Acces) -> Jugement {
    if valeur_bpf(a)? != 0 {
        return Ok(None);
    }
    if a.fiche(Path::new(BPF_DURABLE)).is_some() {
        return Err(refus(trf!(
            "{BPF_DURABLE} est déjà là, et BPF reste ouvert à tous : un autre réglage l'emporte. Rien n'est fait",
            "{BPF_DURABLE} is already there, and BPF stays open to everyone: another setting wins. Nothing is done"
        )));
    }
    if !a.outil("sysctl") {
        return Err(refus(
            tr!(
                "sysctl n'est pas installé dans les dossiers du système : rien n'est fait",
                "sysctl is not installed in the system folders: nothing is done"
            )
            .to_string(),
        ));
    }
    // Le garder demande /etc/sysctl.d, à root et fermé aux autres ; sinon, la question n'est pas posée.
    let dossier_sur =
        fiche_designee(Path::new("/etc/sysctl.d"), Genre::Dossier, a).is_ok_and(|d| d.uid == 0 && d.mode & 0o022 == 0);
    let seconde = dossier_sur.then(|| {
        Seconde::Choix(
            trf!(
                "Le garder aussi après un redémarrage ? Vanguard pose pour cela le fichier {BPF_DURABLE} (Défaire le retire).",
                "Keep it after a restart too? Vanguard adds the file {BPF_DURABLE} for that (Undo removes it)."
            ),
            Action::Suite(vec![
                sysctl_bpf(2),
                Action::Ecrire(PathBuf::from(BPF_DURABLE), BPF_CONTENU.to_vec(), 0o644),
            ]),
        )
    });
    Ok(Some(Plan {
        texte: tr!(
            "Noyau : BPF est ouvert à tous les comptes (kernel.unprivileged_bpf_disabled = 0) : un programme sans droits peut s'en servir pour attaquer le noyau.\nRéglé à 2 (les administrateurs seulement), tout de suite, jusqu'au prochain redémarrage.",
            "Kernel: BPF is open to every account (kernel.unprivileged_bpf_disabled = 0): a program without rights can use it to attack the kernel.\nSet to 2 (administrators only), right away, until the next restart."
        )
        .to_string(),
        avertissement: None,
        non_annulable: false,
        seconde,
        champs: vec![("valeur".into(), b"0".to_vec())],
        action: sysctl_bpf(2),
    }))
}

pub(super) fn remettre_bpf(note: &Note, a: &mut dyn Acces) -> Jugement {
    if nombre::<u8>(note, "valeur")? != 0 {
        return Err(note_abimee());
    }
    let durable = bpf_durable(a)?;
    let mut suite = Vec::new();
    match valeur_bpf(a)? {
        0 => {}
        2 => suite.push(sysctl_bpf(0)),
        _ => return Err(change_depuis("kernel.unprivileged_bpf_disabled")),
    }
    if let Some((f, e)) = durable {
        suite.push(Action::Retirer(PathBuf::from(BPF_DURABLE), f, e));
    }
    if suite.is_empty() {
        return Ok(None);
    }
    Ok(Some(Plan {
        texte: if durable.is_some() {
            trf!(
                "Noyau : kernel.unprivileged_bpf_disabled remis à 0 (BPF ouvert à tous, comme avant), et {BPF_DURABLE} retiré.",
                "Kernel: kernel.unprivileged_bpf_disabled put back to 0 (BPF open to everyone, as before), and {BPF_DURABLE} removed."
            )
        } else {
            tr!(
                "Noyau : kernel.unprivileged_bpf_disabled remis à 0 (BPF ouvert à tous, comme avant).",
                "Kernel: kernel.unprivileged_bpf_disabled put back to 0 (BPF open to everyone, as before)."
            )
            .to_string()
        },
        avertissement: None,
        non_annulable: false,
        seconde: None,
        champs: Vec::new(),
        action: Action::Suite(suite),
    }))
}

// ————— Journal du système —————

const JOURNAL: &str = "/var/log/journal";
const JOURNALD_D: &str = "/etc/systemd/journald.conf.d";
/// « zz- » : lu après les autres compléments, il l'emporte sur eux.
const JOURNALD_VANGUARD: &str = "/etc/systemd/journald.conf.d/zz-vanguard-persistant.conf";
const JOURNALD_CONTENU: &[u8] = b"[Journal]\nStorage=persistent\n";

/// Un dossier de root, sans lien, fermé en écriture aux autres comptes.
fn dossier_de_root(p: &str, a: &dyn Acces) -> Result<(), Echec> {
    let d = fiche_designee(Path::new(p), Genre::Dossier, a)?;
    if d.uid != 0 || d.mode & 0o022 != 0 {
        return Err(refus(trf!(
            "{p} n'est pas à root, ou un autre compte peut le changer : rien n'est fait",
            "{p} is not root's, or another account can change it: nothing is done"
        )));
    }
    Ok(())
}

pub(super) fn juger_journal(a: &mut dyn Acces) -> Jugement {
    match a.fiche(Path::new(JOURNAL)) {
        Some(f) if f.genre == Genre::Dossier => return Ok(None),
        Some(_) => {
            return Err(refus(trf!(
                "{JOURNAL} existe mais n'est pas un dossier : rien n'est fait",
                "{JOURNAL} exists but is not a folder: nothing is done"
            )));
        }
        None => {}
    }
    if a.fiche(Path::new(JOURNALD_VANGUARD)).is_some() {
        return Err(refus(trf!(
            "{JOURNALD_VANGUARD} est déjà là, sans effet : rien n'est fait",
            "{JOURNALD_VANGUARD} is already there, without effect: nothing is done"
        )));
    }
    if !a.outil("journalctl") {
        return Err(refus(
            tr!(
                "journalctl n'est pas installé dans les dossiers du système : rien n'est fait",
                "journalctl is not installed in the system folders: nothing is done"
            )
            .to_string(),
        ));
    }
    let mut suite = Vec::new();
    if a.fiche(Path::new(JOURNALD_D)).is_some() {
        dossier_de_root(JOURNALD_D, a)?;
    } else {
        dossier_de_root("/etc/systemd", a)?;
        suite.push(Action::CreerDossier(PathBuf::from(JOURNALD_D), 0o755));
    }
    suite.push(Action::Ecrire(
        PathBuf::from(JOURNALD_VANGUARD),
        JOURNALD_CONTENU.to_vec(),
        0o644,
    ));
    suite.push(Action::UniteSysteme(
        ActionUnite::Redemarrer,
        "systemd-journald.service",
    ));
    suite.push(Action::Outils(vec![("journalctl", vec![os("--flush")])]));
    Ok(Some(Plan {
        texte: trf!(
            "Journal du système : gardé en mémoire seulement ({JOURNAL} absent), perdu à chaque redémarrage, et les traces d'une intrusion avec lui.\nFichier posé : {JOURNALD_VANGUARD} (Storage=persistent), journald relancé, puis le journal en mémoire écrit sur le disque (journalctl --flush). Il y prendra de la place (selon les réglages de journald, 10 % du disque et 4 Go au plus).",
            "System log: kept in memory only ({JOURNAL} missing), lost at every restart, and the traces of an intrusion with it.\nFile added: {JOURNALD_VANGUARD} (Storage=persistent), journald restarted, then the in-memory log written to disk (journalctl --flush). It will take space there (by journald's settings, 10% of the disk and 4 GB at most)."
        ),
        avertissement: None,
        non_annulable: true,
        seconde: None,
        champs: Vec::new(),
        action: Action::Suite(suite),
    }))
}

// ————— Certificats racine —————

pub(super) fn juger_ancre(c: &CheminDesigne, a: &mut dyn Acces) -> Jugement {
    let p = chemin_de(c);
    let vu = lisible(&p);
    if a.fiche(&p).is_none() {
        return Ok(None);
    }
    let f = fiche_designee(&p, Genre::Fichier, a)?;
    let contenu = a.lire(&p, VALEUR_MAX).ok_or_else(|| {
        refus(trf!(
            "{vu} ne se lit pas, ou est trop grand pour être copié : rien n'est fait",
            "{vu} cannot be read, or is too large to be copied: nothing is done"
        ))
    })?;
    // Seul un fichier que Vanguard ne sait pas lire en entier part : une ligne qui désignerait un certificat nommé
    // (celui d'une entreprise, d'un réseau) est refusée ici, quoi qu'elle dise.
    if crate::machine::certificats::lire_ancre(&contenu).1 {
        return Err(refus(trf!(
            "Vanguard sait lire {vu} en entier : il ne le retire pas de lui-même. Rien n'est fait",
            "Vanguard can read {vu} in full: it does not remove it by itself. Nothing is done"
        )));
    }
    if let Some(nom) = paquet_suspect(&p, a)? {
        return Err(refus(trf!(
            "{vu} vient du paquet {nom} : rien n'est fait",
            "{vu} comes from the package {nom}: nothing is done"
        )));
    }
    let debian = c.octets().starts_with(b"/usr/local/share/ca-certificates/");
    let refaire = if debian && a.outil("update-ca-certificates") {
        ("update-ca-certificates", vec![os("--fresh")])
    } else if a.outil("update-ca-trust") {
        ("update-ca-trust", vec![os("extract")])
    } else if a.outil("update-ca-certificates") {
        ("update-ca-certificates", vec![os("--fresh")])
    } else {
        return Err(refus(tr!(
            "ni update-ca-trust ni update-ca-certificates ne sont installés : la liste des certificats ne serait pas refaite. Rien n'est fait",
            "neither update-ca-trust nor update-ca-certificates is installed: the certificate list would not be rebuilt. Nothing is done"
        )
        .to_string()));
    };
    let e = a.empreinte(&p, &f).ok_or_else(|| change_depuis(&vu))?;
    let outil = refaire.0;
    Ok(Some(Plan {
        texte: trf!(
            "Fichier {vu} ({} octets), ajouté aux certificats racine, que Vanguard ne sait pas lire en entier : le système peut lui faire confiance quand même.\nRetiré, copié en entier dans la note d'« avant » de Vanguard (/var/lib/vanguard/avant), puis la liste des certificats refaite ({outil}).",
            "File {vu} ({} bytes), added to the root certificates, that Vanguard cannot fully read: the system may trust it anyway.\nRemoved, copied whole into Vanguard's \"before\" note (/var/lib/vanguard/avant), then the certificate list rebuilt ({outil}).",
            contenu.len()
        ),
        avertissement: None,
        non_annulable: true,
        seconde: None,
        champs: vec![
            ("contenu".into(), contenu),
            ("mode".into(), f.mode.to_string().into_bytes()),
            ("uid".into(), f.uid.to_string().into_bytes()),
            ("gid".into(), f.gid.to_string().into_bytes()),
        ],
        action: Action::Suite(vec![Action::Retirer(p, f, e), Action::Outils(vec![refaire])]),
    }))
}

// ————— Proxy imposé —————

/// La marque mise devant une ligne de proxy commentée.
pub(super) const MARQUE_PROXY: &[u8] = b"# Vanguard : ";

/// Une ligne qui règle le proxy, et rien d'autre : `[export ]http_proxy=…` (https, ftp, all ; majuscules comprises).
pub(crate) fn ligne_de_proxy(l: &[u8]) -> bool {
    let Ok(t) = std::str::from_utf8(l) else {
        return false;
    };
    let t = t.trim_start();
    let t = match t.strip_prefix("export") {
        Some(r) if r.starts_with([' ', '\t']) => r.trim_start(),
        _ => t,
    };
    let Some((nom, _)) = t.split_once('=') else {
        return false;
    };
    ["http_proxy", "https_proxy", "ftp_proxy", "all_proxy"]
        .iter()
        .any(|v| nom.eq_ignore_ascii_case(v))
}

pub(super) fn juger_proxy(e: Empreinte, c: &CheminDesigne, a: &mut dyn Acces) -> Jugement {
    let (p, f, contenu) = fichier_de_ligne(c, a)?;
    let vu = lisible(&p);
    let mut nouveau = Vec::with_capacity(contenu.len().saturating_add(MARQUE_PROXY.len()));
    let mut trouvee: Option<&[u8]> = None;
    for morceau in contenu.split_inclusive(|o| *o == b'\n') {
        let ligne = morceau.strip_suffix(b"\n").unwrap_or(morceau);
        if empreinte_de_ligne(ligne) == e {
            trouvee = Some(ligne);
            nouveau.extend_from_slice(MARQUE_PROXY);
        }
        nouveau.extend_from_slice(morceau);
    }
    let Some(ligne) = trouvee else {
        return Ok(None);
    };
    if !ligne_de_proxy(ligne) {
        return Err(refus(trf!(
            "la ligne désignée dans {vu} ne règle pas le proxy : rien n'est fait",
            "the line named in {vu} does not set the proxy: nothing is done"
        )));
    }
    Ok(Some(Plan {
        texte: trf!(
            "Fichier {vu}, ligne mise en commentaire : {}\nLe fichier entier est copié dans la note d'« avant » de Vanguard (/var/lib/vanguard/avant). Les programmes lancés ensuite n'auront plus ce proxy (ouvrez une nouvelle session).",
            "File {vu}, line commented out: {}\nThe whole file is copied into Vanguard's \"before\" note (/var/lib/vanguard/avant). Programs started afterwards will no longer have this proxy (open a new session).",
            echappe(ligne)
        ),
        avertissement: None,
        non_annulable: true,
        seconde: None,
        champs: vec![
            ("contenu".into(), contenu.clone()),
            ("mode".into(), f.mode.to_string().into_bytes()),
            ("uid".into(), f.uid.to_string().into_bytes()),
            ("gid".into(), f.gid.to_string().into_bytes()),
        ],
        action: Action::Reecrire(p, f, nouveau),
    }))
}

// ————— Bluetooth —————

/// Le nom d'un appareil, tel que montré : échappé, 64 caractères au plus.
fn nom_d_appareil(nom: &str) -> String {
    echappe(nom.as_bytes()).chars().take(64).collect()
}

pub(super) fn juger_bluetooth(b: AdresseBt, a: &mut dyn Acces, s: &mut dyn Services) -> Jugement {
    if !s.systemd() {
        return Err(refus(sans_systemd()));
    }
    if !s.etat_d_activite("bluetooth.service")?.is_some_and(|t| tourne(&t)) {
        return Err(refus(
            tr!(
                "le service Bluetooth ne tourne pas : rien n'est fait",
                "the Bluetooth service is not running: nothing is done"
            )
            .to_string(),
        ));
    }
    let mac = b.texte();
    let r = a.lancer("bluetoothctl", &[os("info"), os(&mac)]).ok_or_else(|| {
        refus(tr!(
            "bluetoothctl n'est pas installé dans les dossiers du système, ou n'a pas répondu à temps : rien n'est fait",
            "bluetoothctl is not installed in the system folders, or did not answer in time: nothing is done"
        )
        .to_string())
    })?;
    if r.code != Some(0) {
        if r.sortie.contains("not available") || r.erreurs.contains("not available") {
            return Ok(None);
        }
        return Err(refus(
            tr!(
                "bluetoothctl ne dit rien de cet appareil : rien n'est fait",
                "bluetoothctl says nothing about this device: nothing is done"
            )
            .to_string(),
        ));
    }
    let premiere = r.sortie.lines().next().unwrap_or_default();
    if !premiere.to_ascii_uppercase().contains(&format!("DEVICE {mac}")) {
        return Err(refus(
            tr!(
                "bluetoothctl a répondu pour un autre appareil : rien n'est fait",
                "bluetoothctl answered for another device: nothing is done"
            )
            .to_string(),
        ));
    }
    let champ = |k: &str| r.sortie.lines().find_map(|l| l.trim().strip_prefix(k)).map(str::trim);
    let nom = nom_d_appareil(champ("Name:").or_else(|| champ("Alias:")).unwrap_or_default());
    let icone = champ("Icon:").unwrap_or_default();
    let classe = champ("Class:").and_then(|c| u32::from_str_radix(c.trim_start_matches("0x"), 16).ok());
    // Un clavier, une souris, une manette : « input-… », la classe majeure « périphérique » (0x05), ou le profil HID.
    let saisie = icone.starts_with("input-")
        || classe.is_some_and(|c| (c >> 8) & 0x1f == 0x05)
        || r.sortie.contains("Human Interface Device");
    let jumele = if champ("Paired:") == Some("yes") {
        tr!("jumelé", "paired")
    } else {
        tr!("pas jumelé", "not paired")
    };
    let connecte = if champ("Connected:") == Some("yes") {
        tr!("connecté", "connected")
    } else {
        tr!("pas connecté", "not connected")
    };
    let (avertissement, seconde) = if saisie {
        (
            Some(tr!(
                "c'est un clavier, une souris ou une manette : si c'est le seul que vous avez, vous ne pourrez plus taper ni cliquer avec lui avant de le re-jumeler (avec un autre clavier, ou par câble).",
                "this is a keyboard, a mouse or a controller: if it is the only one you have, you will not be able to type or click with it until you pair it again (with another keyboard, or by cable)."
            )
            .to_string()),
            Some(Seconde::Obligatoire(trf!(
                "Vraiment oublier ce clavier, cette souris ou cette manette, « {nom} » ?",
                "Really forget this keyboard, mouse or controller, \"{nom}\"?"
            ))),
        )
    } else {
        (None, None)
    };
    Ok(Some(Plan {
        texte: trf!(
            "Appareil Bluetooth {mac} : « {nom} » ({jumele}, {connecte}).\nOublié par bluetoothctl remove : non annulable, il faudra le re-jumeler pour s'en servir encore.",
            "Bluetooth device {mac}: \"{nom}\" ({jumele}, {connecte}).\nForgotten by bluetoothctl remove: cannot be undone, it will have to be paired again to be used."
        ),
        avertissement,
        non_annulable: true,
        seconde,
        champs: vec![("nom".into(), nom.into_bytes())],
        action: Action::Outils(vec![("bluetoothctl", vec![os("remove"), os(&mac)])]),
    }))
}

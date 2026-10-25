//! Algorithmes cassés ou faibles que le serveur SSH accepte (l'idée de ssh-audit, écrite pour Vanguard). Seules
//! comptent les valeurs écrites dans la configuration de sshd : celles par défaut d'OpenSSH récent sont sûres, et la
//! règle ne parle que de ce que quelqu'un a rouvert. La correction ajoute au fichier de Vanguard pour sshd une ligne
//! par réglage, lue avant la ligne fautive (sshd garde la première valeur trouvée), et ne recharge sshd qu'après
//! « sshd -t » : un rechargement ne coupe aucune connexion en cours.

use super::super::sshd::{correspond, premiere_valeur, version_dans_le_programme, version_openssh};
use super::super::unix::partie_globale_sshd;
use super::*;
use crate::machine::regles::{Os, regle};

regle!(
    "LNX-SSH-006",
    Os::Linux,
    127,
    (
        "algorithmes cassés ou faibles du serveur SSH",
        "broken or weak SSH server algorithms"
    ),
    &[
        "CIS Controls v8 3.10",
        "ANSSI, Recommandations pour un usage sécurisé d'(Open)SSH",
        "OpenSSH : sshd_config(5)",
        "MITRE ATT&CK M1054"
    ],
    || algorithmes_ssh().into_iter().collect()
);

/// Les réglages de sshd qui listent des algorithmes : (nom montré, noms acceptés en minuscules). PubkeyAcceptedKeyTypes
/// est l'ancien nom de PubkeyAcceptedAlgorithms (OpenSSH 8.5) : le premier écrit des deux l'emporte.
const REGLAGES: &[(&str, &[&str])] = &[
    ("KexAlgorithms", &["kexalgorithms"]),
    ("Ciphers", &["ciphers"]),
    ("MACs", &["macs"]),
    ("HostKeyAlgorithms", &["hostkeyalgorithms"]),
    (
        "PubkeyAcceptedAlgorithms",
        &["pubkeyacceptedalgorithms", "pubkeyacceptedkeytypes"],
    ),
];

/// Algorithmes à écarter : (nom, cassé). Cassé : une attaque connue en pratique (Diffie-Hellman de 1024 bits,
/// chiffrement par blocs de 64 bits, RC4, MD5, DSA de 1024 bits). Faible : pas d'attaque pratique sur SSH, mais
/// retiré des valeurs par défaut d'OpenSSH (SHA-1 dans l'échange de clés et les signatures, mode CBC, sceaux tronqués
/// à 96 bits). hmac-sha1 et umac-64 restent permis : OpenSSH 9 les garde par défaut, HMAC ne dépend pas de la
/// résistance de SHA-1 aux collisions, et un sceau de 64 bits ne se force pas sans couper la connexion à chaque
/// essai ; les signaler alerterait sur chaque serveur réglé par défaut.
const FAIBLES: &[(&str, bool)] = &[
    ("diffie-hellman-group1-sha1", true),
    ("diffie-hellman-group14-sha1", false),
    ("diffie-hellman-group-exchange-sha1", false),
    ("3des-cbc", true),
    ("blowfish-cbc", true),
    ("cast128-cbc", true),
    ("des-cbc", true),
    ("arcfour", true),
    ("arcfour128", true),
    ("arcfour256", true),
    ("aes128-cbc", false),
    ("aes192-cbc", false),
    ("aes256-cbc", false),
    ("rijndael-cbc@lysator.liu.se", false),
    ("hmac-md5", true),
    ("hmac-md5-96", true),
    ("hmac-md5-etm@openssh.com", true),
    ("hmac-md5-96-etm@openssh.com", true),
    ("hmac-sha1-96", false),
    ("hmac-sha1-96-etm@openssh.com", false),
    ("ssh-dss", true),
    ("ssh-dss-cert-v01@openssh.com", true),
    ("ssh-rsa", false),
    ("ssh-rsa-cert-v01@openssh.com", false),
    // Échanges de clés GSSAPI (Debian, Fedora) : le nom finit par un code ; ceux-ci servent aux motifs.
    ("gss-group1-sha1-", true),
    ("gss-group14-sha1-", false),
    ("gss-gex-sha1-", false),
];

/// Un nom d'algorithme est-il cassé (`Some(true)`) ou faible (`Some(false)`) ?
pub(super) fn faiblesse(nom: &str) -> Option<bool> {
    let nom = nom.to_ascii_lowercase();
    if let Some((_, casse)) = FAIBLES.iter().find(|(f, _)| *f == nom) {
        return Some(*casse);
    }
    if nom.starts_with("gss-") && nom.contains("-sha1-") {
        return Some(nom.starts_with("gss-group1-"));
    }
    // Tout autre chiffrement en mode CBC (twofish-cbc…).
    nom.ends_with("-cbc").then_some(false)
}

/// Une entrée d'une liste écrite (nom ou motif) : cassée, faible, ou sûre (`None`). Un motif vaut ce que vaut le
/// pire des algorithmes qu'il ouvre.
fn faiblesse_entree(entree: &str) -> Option<bool> {
    if !entree.contains(['*', '?']) {
        return faiblesse(entree);
    }
    FAIBLES
        .iter()
        .filter(|(f, _)| {
            // Les noms GSSAPI finissent par un code : le motif est essayé sur un nom complet.
            let complet = if f.ends_with('-') {
                format!("{f}x")
            } else {
                (*f).to_string()
            };
            correspond(entree.as_bytes(), complet.as_bytes())
        })
        .map(|(_, casse)| *casse)
        .max()
}

/// Une liste d'algorithmes que la correction peut écrire dans le fichier de Vanguard : des faibles retirés
/// (« -… »), ou une liste écrite sans aucun faible. Jamais d'ajout (« +… », « ^… ») : Vanguard n'en écrit pas, et
/// une note qui en remettrait un rouvrirait ce que la correction a fermé.
pub(crate) fn liste_sure(valeur: &str) -> bool {
    if valeur.starts_with('-') {
        return true;
    }
    !valeur.starts_with(['+', '^'])
        && valeur
            .split(',')
            .map(str::trim)
            .all(|e| !e.is_empty() && faiblesse_entree(e).is_none())
}

/// Un réglage qui rouvre des algorithmes cassés ou faibles.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Trouvaille {
    /// Le nom montré (« Ciphers »).
    pub reglage: &'static str,
    /// Le mot tel qu'écrit, gardé pour la correction : un OpenSSH d'avant 8.5 ne connaît que PubkeyAcceptedKeyTypes.
    pub ecrit: String,
    /// La place, dans l'ordre de lecture de sshd, du fichier qui l'écrit.
    pub segment: usize,
    /// La valeur telle qu'écrite (« +3des-cbc », « aes256-ctr,aes128-cbc »).
    pub valeur: String,
    /// Les entrées cassées ou faibles.
    pub faibles: Vec<String>,
    pub casse: bool,
}

/// Les réglages qui acceptent des algorithmes cassés ou faibles. « -liste » retire des valeurs par défaut : rien
/// d'ouvert. « +liste » (ajout) et « ^liste » (en tête) ouvrent ce qu'elles nomment ; une liste sans préfixe remplace
/// les valeurs par défaut. Une sortie de « sshd -T » se lit pareil (un seul fichier, des listes complètes).
pub(super) fn trouver(segments: &[(String, String)]) -> Vec<Trouvaille> {
    REGLAGES
        .iter()
        .filter_map(|(reglage, noms)| {
            let (segment, ecrit, valeur) = premiere_valeur(segments, noms)?;
            if valeur.starts_with('-') {
                return None;
            }
            let mut faibles = Vec::new();
            let mut casse = false;
            for entree in valeur.trim_start_matches(['+', '^']).split(',').map(str::trim) {
                if let Some(c) = faiblesse_entree(entree) {
                    faibles.push(entree.to_string());
                    casse |= c;
                }
            }
            (!faibles.is_empty()).then(|| Trouvaille {
                reglage,
                ecrit: ecrit.to_string(),
                segment,
                valeur: valeur.to_string(),
                faibles,
                casse,
            })
        })
        .collect()
}

/// Ce qui peut s'écrire dans le fichier de Vanguard et dans la commande qui l'écrit entre apostrophes : noms
/// d'algorithmes (base64 des noms GSSAPI compris), motifs, virgules.
fn ligne_sure(ligne: &str) -> bool {
    ligne
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "@._+-=/*?, ".contains(c))
}

/// La ligne à ajouter au fichier de Vanguard pour cette trouvaille, ou `None` s'il faut corriger à la main. `vanguard`
/// : la place du fichier de Vanguard dans l'ordre de lecture (`None` : sshd ne l'inclut pas). `version` : celle
/// d'OpenSSH, qui accepte le préfixe « - » depuis la 7.5.
pub(super) fn ligne_corrigee(t: &Trouvaille, vanguard: Option<usize>, version: Option<(u32, u32)>) -> Option<String> {
    // Lue après la ligne fautive (ou dans le même fichier), une nouvelle ligne ne compterait pas.
    if vanguard? >= t.segment {
        return None;
    }
    let moins = version.is_some_and(|v| v >= (7, 5));
    let retirer = || moins.then(|| format!("{} -{}", t.ecrit, t.faibles.join(",")));
    let ligne = if t.valeur.starts_with(['+', '^']) {
        // Ajout aux valeurs par défaut : les retirer redonne les valeurs par défaut, sûres.
        retirer()?
    } else {
        // Liste écrite à la main : garder ses algorithmes sûrs, dans son ordre, plutôt que revenir aux valeurs
        // par défaut ; si elle n'en a aucun, retirer les faibles des valeurs par défaut.
        let gardes: Vec<&str> = t
            .valeur
            .split(',')
            .map(str::trim)
            .filter(|e| !e.is_empty() && !t.faibles.iter().any(|f| f == e))
            .collect();
        if gardes.is_empty() {
            retirer()?
        } else {
            format!("{} {}", t.ecrit, gardes.join(","))
        }
    };
    ligne_sure(&ligne).then_some(ligne)
}

/// Copie du fichier de Vanguard le temps de vérifier la nouvelle configuration (hors de sshd_config.d : sshd ne doit
/// pas la lire).
const COPIE_SSHD_VANGUARD: &str = "/etc/ssh/00-vanguard.conf.avant";

/// Les commandes qui ajoutent ces lignes au fichier de Vanguard. Si « sshd -t » refuse la configuration, le fichier
/// d'avant revient tel quel et rien n'est rechargé : sshd ne doit pas refuser de démarrer au prochain redémarrage. Les
/// lignes sont le format de printf : `ligne_sure` n'y laisse ni « % » ni « \ ».
pub(super) fn commandes_ajout(lignes: &[String]) -> Vec<String> {
    let texte = crate::commande::sh_chaine(&lignes.iter().fold(String::new(), |t, l| t + l + "\\n"));
    vec![
        format!(
            "sudo rm -f {COPIE_SSHD_VANGUARD} && {{ sudo test ! -e {SSHD_VANGUARD} || sudo cp -p {SSHD_VANGUARD} {COPIE_SSHD_VANGUARD}; }}"
        ),
        format!("printf {texte} | sudo tee -a {SSHD_VANGUARD} >/dev/null"),
        format!(
            "sudo sshd -t || {{ if sudo test -e {COPIE_SSHD_VANGUARD}; then sudo mv {COPIE_SSHD_VANGUARD} {SSHD_VANGUARD}; else sudo rm -f {SSHD_VANGUARD}; fi; false; }}"
        ),
        format!("sudo rm -f {COPIE_SSHD_VANGUARD}"),
        RECHARGER_SSHD.to_string(),
    ]
}

/// Le jugement : `segments`, la configuration de sshd dans son ordre de lecture (fichier, partie qui vaut pour toutes
/// les connexions) ; `version` d'OpenSSH quand elle se lit.
pub(super) fn juger_algorithmes(
    segments: &[(String, String)],
    trouvailles: &[Trouvaille],
    version: Option<(u32, u32)>,
) -> Option<Constat> {
    if trouvailles.is_empty() {
        return None;
    }
    let liste: Vec<String> = trouvailles
        .iter()
        .map(|t| format!("{} {}", t.reglage, crate::ui::affichable(&t.faibles.join(", "))))
        .collect();
    let casse = trouvailles.iter().any(|t| t.casse);
    let c = alerte(
        "SSH",
        if casse { Niveau::Moyen } else { Niveau::Info },
        if casse {
            trf!(
                "sshd accepte des algorithmes cassés, rouverts dans sa configuration : {}. Un client qui les propose s'en sert, et sa connexion devient plus facile à déchiffrer ou à falsifier.",
                "sshd accepts broken algorithms, reopened in its configuration: {}. A client that offers them uses them, and its connection becomes easier to decrypt or tamper with.",
                liste.join(" ; ")
            )
        } else {
            trf!(
                "sshd accepte des algorithmes faibles, rouverts dans sa configuration : {}. OpenSSH les a retirés de ses valeurs par défaut.",
                "sshd accepts weak algorithms, reopened in its configuration: {}. OpenSSH removed them from its defaults.",
                liste.join("; ")
            )
        },
    );
    let vanguard = segments.iter().position(|(f, _)| f == SSHD_VANGUARD);
    let lignes: Option<Vec<String>> = trouvailles
        .iter()
        .map(|t| ligne_corrigee(t, vanguard, version))
        .collect();
    Some(if let Some(lignes) = lignes {
        c.corriger(
            tr!(
                "Les retirer (fichier de Vanguard pour sshd, vérifié par sshd -t avant le rechargement ; les connexions en cours restent ouvertes, un client SSH de plus de dix ans ne pourra plus se connecter)",
                "Remove them (Vanguard's sshd file, checked by sshd -t before reloading; current connections stay open, an SSH client over ten years old will no longer connect)"
            ),
            &commandes_ajout(&lignes),
        )
        .annulable(vec![crate::optimiser::Geste::fichier(SSHD_VANGUARD)])
    } else {
        let ou: Vec<String> = trouvailles
            .iter()
            .map(|t| {
                let fichier = segments.get(t.segment).map_or("?", |(f, _)| f.as_str());
                format!("{} ({})", t.reglage, crate::ui::affichable(fichier))
            })
            .collect();
        c.manuel(
            trf!(
                "Retirer ces algorithmes de la ligne qui les ouvre : {} (Vanguard ne peut pas l'emporter sur elle sans risque), puis vérifier et recharger",
                "Remove these algorithms from the line that opens them: {} (Vanguard cannot override it safely), then check and reload",
                ou.join(", ")
            ),
            &[RECHARGER_SSHD],
        )
    })
}

/// La configuration de sshd dans l'ordre où sshd la lit : (fichier, partie qui vaut pour toutes les connexions). Un
/// « Include » insère à sa place les fichiers de ses motifs, triés comme sshd le fait (`inclure` les rend). `None` :
/// un fichier réservé à root.
pub(super) fn ordonner(
    principal: &str,
    mut inclure: impl FnMut(&str) -> Option<Vec<(String, String)>>,
) -> Option<Vec<(String, String)>> {
    let mut segments = Vec::new();
    let mut courant = String::new();
    for l in partie_globale_sshd(principal).lines() {
        let mut mots = l.split_whitespace();
        if mots.next().is_some_and(|m| m.eq_ignore_ascii_case("include")) {
            segments.push((SSHD_PRINCIPAL.to_string(), std::mem::take(&mut courant)));
            for motif in mots {
                segments.extend(inclure(motif)?);
            }
        } else {
            courant.push_str(l);
            courant.push('\n');
        }
    }
    segments.push((SSHD_PRINCIPAL.to_string(), courant));
    Some(segments)
}

const SSHD_PRINCIPAL: &str = "/etc/ssh/sshd_config";

/// Les fichiers d'un motif d'« Include » (relatif à /etc/ssh), triés. Le fichier de Vanguard y figure, même absent,
/// quand le motif l'inclurait : sa place dit si une ligne qu'il ajoute passerait avant les autres.
fn inclure(motif: &str) -> Option<Vec<(String, String)>> {
    let chemin = if motif.starts_with('/') {
        motif.to_string()
    } else {
        format!("/etc/ssh/{motif}")
    };
    let (dossier, nom) = chemin.rsplit_once('/')?;
    let mut fichiers: Vec<String> = if nom.contains(['*', '?']) {
        let Ok(entrees) = std::fs::read_dir(dossier) else {
            return Some(Vec::new());
        };
        let mut f: Vec<String> = entrees
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| correspond(nom.as_bytes(), n.as_bytes()))
            .map(|n| format!("{dossier}/{n}"))
            .collect();
        if SSHD_VANGUARD
            .rsplit_once('/')
            .is_some_and(|(d, n)| d == dossier && correspond(nom.as_bytes(), n.as_bytes()))
        {
            f.push(SSHD_VANGUARD.to_string());
        }
        f
    } else {
        vec![chemin.clone()]
    };
    fichiers.sort();
    fichiers.dedup();
    let mut segments = Vec::new();
    for f in fichiers {
        match std::fs::read_to_string(&f) {
            Ok(t) => segments.push((f, partie_globale_sshd(&t))),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return None,
            Err(_) if f == SSHD_VANGUARD => segments.push((f, String::new())),
            Err(_) => {}
        }
    }
    Some(segments)
}

/// La version du serveur, sans le lancer : celle du paquet (openssh sous Arch, openssh-server sous Debian, epoch
/// retirée), sinon la chaîne « OpenSSH_x.y » écrite dans le programme lui-même (rpm, compilé à la main). « sshd -V »
/// et « ssh -V » ne servent qu'en dernier recours.
pub(crate) fn version_sshd() -> Option<(u32, u32)> {
    let sshd = ["/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd"]
        .into_iter()
        .find(|p| Path::new(p).exists());
    version_du_paquet()
        .or_else(|| version_dans_le_programme(&std::fs::read(sshd?).ok()?))
        .or_else(|| {
            sshd.into_iter()
                .chain(["ssh"])
                .filter_map(|p| crate::commande::lancer(Command::new(p).arg("-V"), 5))
                .find_map(|r| version_openssh(&r.erreurs).or_else(|| version_openssh(&r.sortie)))
        })
}

/// La version du paquet d'OpenSSH dans la base de pacman, sinon de dpkg.
pub(super) fn version_du_paquet() -> Option<(u32, u32)> {
    let pacman = || Some(natif::desc_pacman("openssh")?.get("VERSION")?.first()?.clone());
    let dpkg = || {
        let paquets = natif::paquets_dpkg()?;
        ["openssh-server", "openssh-client"]
            .iter()
            .find_map(|n| paquets.iter().find(|(p, _)| p == n).map(|(_, v)| v.clone()))
    };
    version_de_paquet(&pacman().or_else(dpkg)?)
}

/// « 10.0p1-2 » (pacman), « 1:9.6p1-3ubuntu13.5 » (dpkg, l'époque avant le deux-points) → (10, 0), (9, 6).
fn version_de_paquet(version: &str) -> Option<(u32, u32)> {
    let sans_epoque = version.split_once(':').map_or(version, |(_, v)| v);
    version_openssh(&format!("OpenSSH_{sans_epoque}"))
}

/// Le serveur SSH tourne-t-il ? `None` sans systemd : on ne sait pas quels services tournent.
pub(crate) fn sshd_en_marche() -> Option<bool> {
    systemd().then(sshd_actif)
}

/// La configuration de sshd dans son ordre de lecture (`ordonner`), pour les règles communes.
pub(crate) fn sshd_dans_l_ordre() -> Result<Vec<(String, String)>, crate::modele::Echec> {
    let principal =
        std::fs::read_to_string(SSHD_PRINCIPAL).map_err(|e| crate::modele::Echec::io("bilan/sshd-config", &e))?;
    ordonner(&principal, inclure)
        .ok_or_else(|| crate::modele::Echec::new("bilan/sshd-config", crate::modele::Raison::Droits))
}

/// La version du client ssh, sans le lancer : celle du paquet (openssh sous Arch, openssh-client sous Debian),
/// sinon celle écrite dans le programme.
pub(crate) fn version_ssh() -> Option<(u32, u32)> {
    let pacman = || Some(natif::desc_pacman("openssh")?.get("VERSION")?.first()?.clone());
    let dpkg = || {
        natif::paquets_dpkg()?
            .into_iter()
            .find(|(p, _)| p == "openssh-client")
            .map(|(_, v)| v)
    };
    pacman().or_else(dpkg).and_then(|v| version_de_paquet(&v)).or_else(|| {
        ["/usr/bin/ssh", "/bin/ssh"]
            .iter()
            .find_map(|p| version_dans_le_programme(&std::fs::read(p).ok()?))
    })
}

fn algorithmes_ssh() -> Option<Constat> {
    // Configuration illisible ou serveur arrêté : la règle du serveur SSH le dit déjà.
    if !systemd() || !sshd_actif() {
        return None;
    }
    let segments = ordonner(&std::fs::read_to_string(SSHD_PRINCIPAL).ok()?, inclure)?;
    let trouvailles = trouver(&segments);
    if trouvailles.is_empty() {
        return None;
    }
    juger_algorithmes(&segments, &trouvailles, version_sshd())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_lue_sans_lancer_sshd() {
        assert_eq!(version_de_paquet("10.0p1-2"), Some((10, 0)));
        assert_eq!(version_de_paquet("1:9.6p1-3ubuntu13.5"), Some((9, 6)));
        assert_eq!(version_de_paquet("rien"), None);
        // Les motifs de compatibilité (« * », « , ») ne comptent pas ; la vraie version, suivie d'un zéro, si.
        let programme = b"\x7fELF..OpenSSH_2.*,OpenSSH_3.0*\0OpenSSH_7.0*\0OpenSSH_for_Windows\0\
                          OpenSSH_9.6p1\0OpenSSH_9.6\0usage: sshd\0";
        assert_eq!(version_dans_le_programme(programme), Some((9, 6)));
        assert_eq!(version_dans_le_programme(b"OpenSSH_2.*\0OpenSSH_"), None);
    }

    /// Sur cet ordinateur, la version lue sans lancer sshd est celle que « sshd -V » écrit, quand il est là.
    #[test]
    fn version_comme_sshd() {
        crate::autotest::croisees::essayer("AUT-LNX-009");
    }

    /// « sshd -T » d'un OpenSSH 9.6 réglé par défaut (lignes des algorithmes seulement).
    const SSHD_T_DEFAUT: &str = "port 22
kexalgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256
ciphers chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
macs umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1
hostkeyalgorithms ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,sk-ssh-ed25519@openssh.com,rsa-sha2-512,rsa-sha2-256
pubkeyacceptedalgorithms ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,sk-ssh-ed25519@openssh.com,rsa-sha2-512,rsa-sha2-256
";

    fn segments(fichiers: &[(&str, &str)]) -> Vec<(String, String)> {
        fichiers
            .iter()
            .map(|(f, t)| ((*f).to_string(), (*t).to_string()))
            .collect()
    }

    /// Debian : « Include /etc/ssh/sshd_config.d/*.conf » en tête de sshd_config.
    fn debian(dans_d: &[(&str, &str)], principal: &str) -> Vec<(String, String)> {
        let texte = format!("Include /etc/ssh/sshd_config.d/*.conf\n{principal}");
        ordonner(&texte, |_| {
            let mut f: Vec<(String, String)> = dans_d
                .iter()
                .map(|(n, t)| (format!("/etc/ssh/sshd_config.d/{n}"), (*t).to_string()))
                .collect();
            if !f.iter().any(|(n, _)| n == SSHD_VANGUARD) {
                f.push((SSHD_VANGUARD.to_string(), String::new()));
            }
            f.sort();
            Some(f)
        })
        .unwrap()
    }

    #[test]
    fn openssh_9_par_defaut_ne_dit_rien() {
        assert_eq!(trouver(&segments(&[("sshd -T", SSHD_T_DEFAUT)])), []);
        assert_eq!(trouver(&debian(&[], "PermitRootLogin no\n")), []);
        // « - » retire des valeurs par défaut : rien d'ouvert.
        assert_eq!(trouver(&debian(&[], "Ciphers -aes128-cbc,3des-cbc\n")), []);
    }

    #[test]
    fn noms_et_motifs() {
        assert_eq!(faiblesse("3des-cbc"), Some(true));
        assert_eq!(faiblesse("aes256-cbc"), Some(false));
        assert_eq!(faiblesse("twofish-cbc"), Some(false));
        assert_eq!(faiblesse("ssh-rsa"), Some(false));
        assert_eq!(faiblesse("rsa-sha2-512"), None);
        assert_eq!(faiblesse("hmac-sha1"), None);
        assert_eq!(faiblesse("umac-64-etm@openssh.com"), None);
        assert_eq!(faiblesse("gss-gex-sha1-toWM5Slw5Ew8Mqkay+al2g=="), Some(false));
        assert_eq!(faiblesse("gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g=="), Some(true));
        assert_eq!(faiblesse("gss-curve25519-sha256-toWM5Slw5Ew8Mqkay+al2g=="), None);
        assert!(correspond(b"*-cbc", b"aes128-cbc") && !correspond(b"*-cbc", b"aes128-ctr"));
        assert!(correspond(b"hmac-md5*", b"hmac-md5-96-etm@openssh.com"));
        assert!(correspond(b"*.conf", b"00-vanguard.conf") && !correspond(b"*.conf", b"x.conf.avant"));
        assert_eq!(faiblesse_entree("*-cbc"), Some(true));
        assert_eq!(faiblesse_entree("aes*-ctr"), None);
        assert_eq!(faiblesse_entree("gss-*"), Some(true));
    }

    #[test]
    fn ajout_rouvert_puis_retire_par_vanguard() {
        let s = debian(&[], "Ciphers +3des-cbc,aes128-cbc\nMACs +hmac-md5\n");
        let t = trouver(&s);
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].faibles, ["3des-cbc", "aes128-cbc"]);
        assert!(t[0].casse);
        let c = juger_algorithmes(&s, &t, Some((9, 6))).unwrap();
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        let k = c.correctif.unwrap();
        assert!(k.automatique);
        assert_eq!(
            k.commandes[1],
            format!(
                "printf 'Ciphers -3des-cbc,aes128-cbc\\nMACs -hmac-md5\\n' | sudo tee -a {SSHD_VANGUARD} >/dev/null"
            )
        );
        assert_eq!(k.commandes.last().map(String::as_str), Some(RECHARGER_SSHD));
        // OpenSSH d'avant la 7.5 : pas de « - », et la liste par défaut est inconnue : à la main.
        let c = juger_algorithmes(&s, &t, Some((7, 4))).unwrap();
        assert!(!c.correctif.unwrap().automatique);
        let c = juger_algorithmes(&s, &t, None).unwrap();
        assert!(!c.correctif.unwrap().automatique);
    }

    #[test]
    fn liste_ecrite_gardee_sans_les_faibles() {
        let s = debian(
            &[(
                "50-ancien.conf",
                "Ciphers aes256-ctr,aes128-cbc\nPubkeyAcceptedKeyTypes ssh-ed25519,ssh-rsa\n",
            )],
            "",
        );
        let t = trouver(&s);
        assert_eq!(t.len(), 2);
        assert!(!t[0].casse && !t[1].casse);
        assert_eq!(t[1].ecrit, "PubkeyAcceptedKeyTypes");
        let vanguard = s.iter().position(|(f, _)| f == SSHD_VANGUARD);
        // La liste explicite des sûrs déjà acceptés : valable même sans « - » (OpenSSH ancien).
        assert_eq!(
            ligne_corrigee(&t[0], vanguard, Some((7, 4))).as_deref(),
            Some("Ciphers aes256-ctr")
        );
        assert_eq!(
            ligne_corrigee(&t[1], vanguard, None).as_deref(),
            Some("PubkeyAcceptedKeyTypes ssh-ed25519")
        );
        let c = juger_algorithmes(&s, &t, Some((8, 2))).unwrap();
        assert_eq!(c.probleme, Some(Niveau::Info));
        // Rien que des faibles : retirés des valeurs par défaut.
        let s = debian(&[("50-ancien.conf", "KexAlgorithms diffie-hellman-group1-sha1\n")], "");
        let t = trouver(&s);
        let vanguard = s.iter().position(|(f, _)| f == SSHD_VANGUARD);
        assert_eq!(
            ligne_corrigee(&t[0], vanguard, Some((9, 0))).as_deref(),
            Some("KexAlgorithms -diffie-hellman-group1-sha1")
        );
    }

    #[test]
    fn ligne_lue_avant_celle_de_vanguard_corrigee_a_la_main() {
        // Un fichier trié avant celui de Vanguard : sa valeur gagne, une ligne de Vanguard n'y changerait rien.
        let s = debian(&[("00-avant.conf", "Ciphers +3des-cbc\n")], "");
        let t = trouver(&s);
        let c = juger_algorithmes(&s, &t, Some((9, 6))).unwrap();
        let k = c.correctif.unwrap();
        assert!(!k.automatique);
        assert!(k.action.contains("00-avant.conf"), "{}", k.action);
        // Déjà dans le fichier de Vanguard lui-même.
        let s = debian(&[("00-vanguard.conf", "MACs hmac-md5\n")], "");
        let t = trouver(&s);
        assert!(
            !juger_algorithmes(&s, &t, Some((9, 6)))
                .unwrap()
                .correctif
                .unwrap()
                .automatique
        );
        // Réglage écrit avant l'Include : lu le premier.
        let s = ordonner("Ciphers +arcfour\nInclude sshd_config.d/*.conf\n", |_| {
            Some(vec![(SSHD_VANGUARD.to_string(), String::new())])
        })
        .unwrap();
        assert!(ligne_corrigee(&trouver(&s)[0], Some(1), Some((9, 6))).is_none());
        // Pas d'Include du tout : le fichier de Vanguard n'est pas lu.
        let s = ordonner("Ciphers +arcfour\n", |_| None).unwrap();
        let t = trouver(&s);
        assert!(
            !juger_algorithmes(&s, &t, Some((9, 6)))
                .unwrap()
                .correctif
                .unwrap()
                .automatique
        );
    }

    #[test]
    fn noms_gssapi_et_valeurs_piegees() {
        let s = debian(&[], "KexAlgorithms +gss-gex-sha1-toWM5Slw5Ew8Mqkay+al2g==\n");
        let t = trouver(&s);
        let vanguard = s.iter().position(|(f, _)| f == SSHD_VANGUARD);
        // La casse du base64 est gardée.
        assert_eq!(
            ligne_corrigee(&t[0], vanguard, Some((9, 6))).as_deref(),
            Some("KexAlgorithms -gss-gex-sha1-toWM5Slw5Ew8Mqkay+al2g==")
        );
        // Une apostrophe ou un « ; » n'entre jamais dans une commande.
        let s = debian(&[], "Ciphers aes256-ctr,3des-cbc,x';reboot;'\n");
        let t = trouver(&s);
        let c = juger_algorithmes(&s, &t, Some((9, 6))).unwrap();
        assert!(!c.correctif.unwrap().automatique);
    }

    #[test]
    fn commandes_de_correction_valables_pour_bash() {
        let commandes = commandes_ajout(&[
            "Ciphers -3des-cbc".into(),
            "KexAlgorithms -gss-gex-sha1-ab+c/d==".into(),
        ]);
        for c in &commandes {
            let r = Command::new("bash").args(["-n", "-c", c]).status().unwrap();
            assert!(r.success(), "{c}");
        }
        assert!(commandes[2].starts_with("sudo sshd -t ||"));
        // Ce qu'écrit printf, sans sudo ni fichier : les lignes telles quelles.
        let printf = commandes[1].replace(&format!(" | sudo tee -a {SSHD_VANGUARD} >/dev/null"), "");
        let sortie = Command::new("bash").args(["-c", &printf]).output().unwrap();
        assert_eq!(
            String::from_utf8_lossy(&sortie.stdout),
            "Ciphers -3des-cbc\nKexAlgorithms -gss-gex-sha1-ab+c/d==\n"
        );
    }

    #[test]
    fn version_d_openssh() {
        assert_eq!(
            version_openssh("OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024\n"),
            Some((9, 6))
        );
        assert_eq!(
            version_openssh("sshd: illegal option -- V\nOpenSSH_7.4p1, OpenSSL 1.0.2k-fips\nusage: sshd"),
            Some((7, 4))
        );
        assert_eq!(version_openssh("rien"), None);
    }

    #[test]
    fn ordre_de_lecture_avec_include() {
        let s = ordonner(
            "Port 22\nInclude /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\nMatch User invite\n  Ciphers +arcfour\n",
            |m| {
                assert_eq!(m, "/etc/ssh/sshd_config.d/*.conf");
                Some(vec![("/etc/ssh/sshd_config.d/50-x.conf".into(), "X11Forwarding no\n".into())])
            },
        )
        .unwrap();
        let fichiers: Vec<&str> = s.iter().map(|(f, _)| f.as_str()).collect();
        assert_eq!(
            fichiers,
            [SSHD_PRINCIPAL, "/etc/ssh/sshd_config.d/50-x.conf", SSHD_PRINCIPAL]
        );
        // Le bloc Match ne vaut que pour certaines connexions.
        assert_eq!(trouver(&s), []);
        // Un fichier réservé à root : rien à conclure.
        assert!(ordonner("Include /etc/ssh/sshd_config.d/*.conf\n", |_| None).is_none());
    }
}

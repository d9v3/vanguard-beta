//! Les lectures croisées de Linux (`autotest::croisees`) : chaque lecture native qui décide d'un verdict du bilan,
//! comparée à l'outil du système qui dit la même chose. Les tests « X_comme_Y » de chaque module appellent ces
//! fonctions (`autotest::croisees::essayer`) : `cargo test` et l'autotest jugent avec le même code.
//!
//! L'outil absent alors que la lecture native n'a rien non plus (pas de dpkg sur Arch) : sans objet, dit. L'outil
//! absent alors que Vanguard lit quelque chose, ou une lecture qui échoue : sauté, jamais « pareil ».

use std::collections::HashMap;

use super::{dbus, ecoute, natif};
use crate::autotest::croisees::{self, Comparaison, Ecart, croisee};
use crate::machine::regles::Os;
use crate::modele::Raison;
use crate::tr;

/// La lecture de Vanguard n'a rien rendu alors que l'outil répond.
fn illisible() -> Comparaison {
    Comparaison::Different {
        en_plus: Vec::new(),
        en_moins: Vec::new(),
        differents: Vec::new(),
        genre: Ecart::ChampIllisible,
    }
}

/// L'outil absent : sans objet si la lecture native n'a rien non plus, sauté sinon.
fn absent_ou(raison: Raison, natif_vide: bool, pourquoi: &str) -> Comparaison {
    match raison {
        Raison::Absente(_) if natif_vide => Comparaison::SansObjet(pourquoi.to_string()),
        r => Comparaison::Saute(r),
    }
}

croisee!(
    "AUT-LNX-001",
    Os::Linux,
    (
        "paquets installés (base de pacman)",
        "installed packages (pacman database)"
    ),
    "pacman -Q",
    &["COM-LOG-001", "COM-DIS-001", "LNX-MAJ-006"],
    pacman
);

pub(super) fn pacman() -> Comparaison {
    let natif = natif::paquets_pacman();
    let sortie = match croisees::lancer("pacman -Q", &[]) {
        Ok(s) => s,
        Err(r) => return absent_ou(r, natif.is_none(), tr!("pas de pacman ici", "no pacman here")),
    };
    let Some(natif) = natif else { return illisible() };
    let outil = sortie
        .lines()
        .filter_map(|l| l.split_once(' '))
        .map(|(n, v)| (n.to_string(), v.to_string()));
    croisees::comparer(natif, outil)
}

croisee!(
    "AUT-LNX-002",
    Os::Linux,
    ("paquets installés (base de dpkg)", "installed packages (dpkg database)"),
    "dpkg-query -W",
    &["COM-LOG-001"],
    dpkg
);

pub(super) fn dpkg() -> Comparaison {
    let natif = natif::paquets_dpkg();
    let sortie = match croisees::lancer("dpkg-query -W -f=${db:Status-Status} ${Package} ${Version}\\n", &[]) {
        Ok(s) => s,
        Err(r) => return absent_ou(r, natif.is_none(), tr!("pas de dpkg ici", "no dpkg here")),
    };
    let Some(natif) = natif else { return illisible() };
    // Nom et version ensemble : un paquet de deux architectures peut paraître deux fois sous le même nom.
    let outil = sortie
        .lines()
        .filter_map(|l| l.strip_prefix("installed "))
        .filter_map(|l| l.split_once(' '))
        .map(|(n, v)| format!("{n} {v}"));
    croisees::comparer_noms(natif.into_iter().map(|(n, v)| format!("{n} {v}")), outil)
}

croisee!(
    "AUT-LNX-003",
    Os::Linux,
    (
        "paquets hors des dépôts (AUR)",
        "packages outside the repositories (AUR)"
    ),
    "pacman -Qmq",
    &["LNX-MAJ-006"],
    etrangers
);

pub(super) fn etrangers() -> Comparaison {
    let natif = super::maj::etrangers_lus();
    let sortie = match croisees::lancer("pacman -Qmq", &[]) {
        Ok(s) => s,
        Err(r) => return absent_ou(r, natif.is_none(), tr!("pas de pacman ici", "no pacman here")),
    };
    // Une base des dépôts en xz (que Vanguard ne lit pas) : pacman -Qmq sert alors au bilan lui-même.
    let Some(natif) = natif else {
        return Comparaison::Saute(Raison::Illisible(
            tr!(
                "bases des dépôts illisibles en Rust",
                "repository databases unreadable in Rust"
            )
            .into(),
        ));
    };
    croisees::comparer_noms(natif, sortie.lines().filter(|l| !l.is_empty()).map(str::to_string))
}

croisee!(
    "AUT-LNX-004",
    Os::Linux,
    ("services activés au démarrage", "services enabled at boot"),
    "systemctl list-unit-files",
    &["LNX-MAJ-002"],
    unites_activees
);

pub(super) fn unites_activees() -> Comparaison {
    let mut natif = Vec::new();
    let mut outil = Vec::new();
    let mut manque = None;
    for (ligne, utilisateur) in [
        (
            "systemctl list-unit-files --no-legend --plain --state=enabled,disabled,masked",
            false,
        ),
        (
            "systemctl --user list-unit-files --no-legend --plain --state=enabled,disabled,masked",
            true,
        ),
    ] {
        let sortie = match croisees::lancer(ligne, &[]) {
            Ok(s) => s,
            // Sans session de l'utilisateur (surveillance lancée hors session) : le système est comparé quand
            // même, mais un « pareil » sans les unités du compte serait un faux vert.
            Err(r) if utilisateur => {
                manque = Some(r);
                continue;
            }
            Err(r) => return Comparaison::Saute(r),
        };
        for l in sortie.lines() {
            let mut c = l.split_whitespace();
            let (Some(unite), Some(etat)) = (c.next(), c.next()) else {
                continue;
            };
            let cle = format!("{}{unite}", if utilisateur { "--user " } else { "" });
            let lu = match natif::unite_activee(unite, utilisateur) {
                Some(true) => "enabled",
                Some(false) => "disabled",
                None => "illisible",
            };
            natif.push((cle.clone(), lu.to_string()));
            outil.push((cle, if etat == "enabled" { "enabled" } else { "disabled" }.to_string()));
        }
    }
    sans_le_compte(croisees::comparer(natif, outil), manque)
}

/// La moitié du compte non lue : un écart trouvé côté système reste un écart, un « pareil » devient sauté.
fn sans_le_compte(c: Comparaison, manque: Option<Raison>) -> Comparaison {
    match (c, manque) {
        (Comparaison::Pareil { .. }, Some(r)) => Comparaison::Saute(r),
        (c, _) => c,
    }
}

croisee!(
    "AUT-LNX-005",
    Os::Linux,
    ("groupes du compte", "account's groups"),
    "id -nG",
    &["LNX-PRV-002"],
    groupes
);

pub(super) fn groupes() -> Comparaison {
    let sortie = match croisees::lancer("id -nG", &[]) {
        Ok(s) => s,
        Err(r) => return Comparaison::Saute(r),
    };
    let Some(natif) = natif::groupes() else {
        return illisible();
    };
    croisees::comparer_noms(natif, sortie.split_whitespace().map(str::to_string))
}

croisee!(
    "AUT-LNX-006",
    Os::Linux,
    ("ports en écoute", "listening ports"),
    "ss -tlnpe / -ulnpe",
    &["LNX-RES-001"],
    prises
);

/// Une prise peut s'ouvrir ou se fermer entre deux lectures : netlink est lu avant et après ss, et chaque prise de ss
/// doit se trouver dans l'une des deux lectures, au même port, à la même adresse, au même groupe.
pub(super) fn prises() -> Comparaison {
    let Some(avant) = ecoute::par_netlink() else {
        return Comparaison::Saute(Raison::Illisible("netlink".into()));
    };
    let (tcp, udp) = match (croisees::lancer("ss -Htlnpe", &[]), croisees::lancer("ss -Hulnpe", &[])) {
        (Ok(t), Ok(u)) => (t, u),
        (Err(r), _) | (_, Err(r)) => return Comparaison::Saute(r),
    };
    let apres = ecoute::par_netlink().unwrap_or_default();
    let natives: HashMap<u64, &ecoute::Ecoute> = avant.iter().chain(&apres).map(|e| (e.inode, e)).collect();
    comparer_prises(&natives, &tcp, &udp)
}

fn comparer_prises(natives: &HashMap<u64, &ecoute::Ecoute>, tcp: &str, udp: &str) -> Comparaison {
    let de_ss: Vec<ecoute::Ecoute> = ecoute::lire_ss(tcp, false)
        .into_iter()
        .chain(ecoute::lire_ss(udp, true))
        .collect();
    // ss -H n'écrit qu'une ligne par prise : une ligne non lue est un format que lire_ss ne connaît pas (colonne
    // déplacée, autre iproute2), pas un « pareil » sur ce qui reste.
    let lignes = tcp.lines().chain(udp.lines()).filter(|l| !l.trim().is_empty()).count();
    if de_ss.len() != lignes {
        return Comparaison::inattendue();
    }
    let nom = |e: &ecoute::Ecoute| format!("{}/{} {}", e.port, if e.udp { "udp" } else { "tcp" }, e.adresse);
    let mut en_moins = Vec::new();
    let mut differents = Vec::new();
    for e in &de_ss {
        match natives.get(&e.inode) {
            None => en_moins.push(nom(e)),
            Some(n) if (n.udp, n.adresse, n.port) != (e.udp, e.adresse, e.port) => {
                differents.push(format!("{} ≠ {}", nom(n), nom(e)));
            }
            // Un ss trop ancien (ou un noyau d'avant 5.7) ne donne pas le groupe : rien à comparer.
            Some(n) if e.groupe.is_some() && n.groupe != e.groupe => differents.push(nom(e)),
            Some(_) => {}
        }
    }
    if en_moins.is_empty() && differents.is_empty() {
        return Comparaison::Pareil { n: de_ss.len() };
    }
    let genre = if en_moins.is_empty() {
        Ecart::ValeurDifferente
    } else {
        Ecart::AbsentNatif
    };
    Comparaison::Different {
        en_plus: Vec::new(),
        en_moins,
        differents,
        genre,
    }
}

croisee!(
    "AUT-LNX-007",
    Os::Linux,
    ("services en échec", "failed services"),
    "systemctl --failed",
    &["LNX-SRV-001"],
    en_echec
);

pub(super) fn en_echec() -> Comparaison {
    let sortie = match croisees::lancer("systemctl --failed --no-legend --plain", &[]) {
        Ok(s) => s,
        Err(r) => return Comparaison::Saute(r),
    };
    let natif = match dbus::Bus::systeme().and_then(|mut b| dbus::unites_en_echec(&mut b)) {
        Ok(n) => n,
        Err(e) => return Comparaison::Saute(Raison::Illisible(e)),
    };
    // « ● unite.service » sur une console qui dessine les puces : le premier mot qui ressemble à une unité.
    let outil = sortie
        .lines()
        .filter_map(|l| l.split_whitespace().find(|m| m.contains('.')).map(str::to_string));
    croisees::comparer_noms(natif, outil)
}

croisee!(
    "AUT-LNX-008",
    Os::Linux,
    ("chiffrement de la racine", "root encryption"),
    "findmnt + lsblk",
    &["LNX-CHF-001"],
    racine_chiffree
);

pub(super) fn racine_chiffree() -> Comparaison {
    let Some(chiffree) = natif::racine()
        .filter(|(s, _)| s.starts_with("/dev/"))
        .and_then(|(s, _)| natif::chiffre(&s))
    else {
        return Comparaison::Saute(Raison::Illisible(
            tr!("chiffrement de la racine", "root encryption").into(),
        ));
    };
    let source = match croisees::lancer("findmnt -no SOURCE /", &[]) {
        Ok(s) => s,
        Err(r) => return Comparaison::Saute(r),
    };
    let peripherique = source.trim().split('[').next().unwrap_or_default().to_string();
    if !peripherique.starts_with("/dev/") {
        return Comparaison::inattendue();
    }
    let chaine = match croisees::lancer("lsblk -nso TYPE", &[&peripherique]) {
        Ok(s) => s,
        Err(r) => return Comparaison::Saute(r),
    };
    let oui_non = |b: bool| if b { "oui" } else { "non" };
    Comparaison::une_valeur(
        "racine chiffrée",
        oui_non(chiffree),
        oui_non(chaine.lines().any(|l| l.trim() == "crypt")),
    )
}

croisee!(
    "AUT-LNX-009",
    Os::Linux,
    ("version du serveur SSH", "SSH server version"),
    "sshd -V",
    &["LNX-SSH-006"],
    version_sshd
);

pub(super) fn version_sshd() -> Comparaison {
    let Some(sshd) = ["/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd"]
        .into_iter()
        .find(|p| std::path::Path::new(p).is_file())
    else {
        return Comparaison::SansObjet(tr!("pas de serveur SSH ici", "no SSH server here").into());
    };
    let texte = match croisees::lancer("sshd -V", &[]) {
        Ok(s) => s,
        Err(r) => return Comparaison::Saute(r),
    };
    let Some(attendue) = crate::machine::sshd::version_openssh(&texte) else {
        return Comparaison::inattendue();
    };
    let v = |(a, b): (u32, u32)| format!("{a}.{b}");
    let programme = std::fs::read(sshd)
        .ok()
        .and_then(|o| crate::machine::sshd::version_dans_le_programme(&o));
    let mut natif = vec![("programme".to_string(), programme.map_or_else(|| "illisible".into(), v))];
    let mut outil = vec![("programme".to_string(), v(attendue))];
    if let Some(p) = super::algorithmes_ssh::version_du_paquet() {
        natif.push(("paquet".into(), v(p)));
        outil.push(("paquet".into(), v(attendue)));
    }
    croisees::comparer(natif, outil)
}

croisee!(
    "AUT-LNX-010",
    Os::Linux,
    ("serveurs DNS de systemd-resolved", "systemd-resolved DNS servers"),
    "resolvectl dns",
    &["COM-DNS-001"],
    serveurs_dns
);

pub(super) fn serveurs_dns() -> Comparaison {
    use crate::machine::dns::{RESOLV_CONF_AMONT, lire_resolv_conf, lire_resolvectl};
    let conf = std::fs::read_to_string(RESOLV_CONF_AMONT).ok();
    let sortie = match croisees::lancer("resolvectl dns", &[]) {
        Ok(s) => s,
        Err(r) => {
            return absent_ou(
                r,
                conf.is_none(),
                tr!("pas de systemd-resolved ici", "no systemd-resolved here"),
            );
        }
    };
    let Some(conf) = conf else { return illisible() };
    // resolvectl (systemd 255, Ubuntu 24.04) nomme les interfaces de son espace réseau : dans un espace à part
    // (unshare -n, conteneur), il n'a que lo, et les serveurs des vraies interfaces lui manquent (vu sur la CI :
    // celui d'eth0). Le fichier, lui, est celui de tout l'ordinateur : sans autre interface que lo, pas de verdict.
    if !sortie.lines().any(|l| l.starts_with("Link ") && !l.contains("(lo)")) {
        return Comparaison::Saute(Raison::Illisible(
            tr!(
                "resolvectl ne voit aucune interface réseau d'ici",
                "resolvectl sees no network interface from here"
            )
            .into(),
        ));
    }
    // Même ensemble : resolved retire les doublons du fichier, et l'ordre des interfaces peut changer.
    croisees::comparer_noms(
        lire_resolv_conf(&conf).into_iter().map(|ip| ip.to_string()),
        lire_resolvectl(&sortie).into_iter().map(|ip| ip.to_string()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn une_ligne_de_ss_illisible_n_est_pas_un_pareil() {
        let prise = ecoute::Ecoute {
            udp: false,
            adresse: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            port: 22,
            inode: 4242,
            groupe: None,
            programme: None,
        };
        let natives = HashMap::from([(4242, &prise)]);
        let lue = "LISTEN 0 128 192.0.2.1:22 0.0.0.0:* ino:4242 sk:1 <->";
        assert_eq!(comparer_prises(&natives, lue, ""), Comparaison::Pareil { n: 1 });
        assert_eq!(
            comparer_prises(&natives, &format!("{lue}\nLISTEN 0 128\n"), ""),
            Comparaison::inattendue()
        );
    }

    #[test]
    fn le_compte_non_lu_n_est_pas_un_pareil() {
        assert!(matches!(
            sans_le_compte(Comparaison::Pareil { n: 3 }, Some(Raison::Delai)),
            Comparaison::Saute(Raison::Delai)
        ));
        assert_eq!(
            sans_le_compte(Comparaison::Pareil { n: 3 }, None),
            Comparaison::Pareil { n: 3 }
        );
        assert_eq!(
            sans_le_compte(Comparaison::inattendue(), Some(Raison::Delai)),
            Comparaison::inattendue()
        );
    }
}

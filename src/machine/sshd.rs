//! La lecture de sshd_config, commune à Linux, macOS et Windows (le serveur OpenSSH de Microsoft lit le même format,
//! dans %ProgramData%\ssh) : la partie qui vaut pour toutes les connexions et la valeur d'un réglage, telles que
//! sshd les retient ; la version d'OpenSSH lue sans le lancer ; et la liste d'échanges de clés que sshd ou ssh
//! retiennent vraiment (valeurs par défaut de la version, puis « + », « - », « ^ » ou liste écrite), pour dire si
//! l'échange post-quantique y est (`post_quantique`).

/// La partie d'un fichier de configuration de sshd qui vaut pour toutes les connexions : un bloc « Match » ne
/// s'applique qu'à certaines (un utilisateur, une adresse) et va jusqu'à la fin du fichier.
pub(crate) fn partie_globale_sshd(texte: &str) -> String {
    texte
        .lines()
        .take_while(|l| {
            !l.split_whitespace()
                .next()
                .is_some_and(|m| m.eq_ignore_ascii_case("match"))
        })
        .flat_map(|l| [l, "\n"])
        .collect()
}

/// Première valeur d'un réglage de sshd, en minuscules. Le nom et la valeur se séparent par des espaces ou par un
/// « = » (« PasswordAuthentication=no » est valable).
pub(crate) fn valeur_sshd(conf: &str, cle: &str) -> Option<String> {
    conf.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| {
            let (k, v) = l.split_once(|c: char| c.is_whitespace() || c == '=')?;
            let v = v.trim().trim_start_matches('=').trim().trim_matches('"');
            k.eq_ignore_ascii_case(cle).then(|| v.to_ascii_lowercase())
        })
}

/// sshd accepte-t-il un mot de passe ? Par « PasswordAuthentication » (oui par défaut), ou, avec PAM, par le mode
/// « clavier interactif » qui demande le même mot de passe (oui par défaut aussi).
pub(crate) fn mots_de_passe_sshd(conf: &str) -> bool {
    let valeur = |cle: &str| valeur_sshd(conf, cle);
    let clavier = valeur("KbdInteractiveAuthentication").or_else(|| valeur("ChallengeResponseAuthentication"));
    valeur("PasswordAuthentication").as_deref() != Some("no")
        || (valeur("UsePAM").as_deref() == Some("yes") && clavier.as_deref() != Some("no"))
}

/// sshd ouvre-t-il un compte sans mot de passe ? « PermitEmptyPasswords yes », quand les mots de passe sont permis.
pub(crate) fn mots_de_passe_vides_sshd(conf: &str) -> bool {
    valeur_sshd(conf, "PermitEmptyPasswords").as_deref() == Some("yes") && mots_de_passe_sshd(conf)
}

/// Le motif d'OpenSSH (« * » : n'importe quelle suite, « ? » : un caractère) correspond-il au nom ?
pub(crate) fn correspond(motif: &[u8], nom: &[u8]) -> bool {
    match (motif.split_first(), nom.split_first()) {
        (None, _) => nom.is_empty(),
        (Some((b'*', suite)), _) => {
            correspond(suite, nom) || nom.split_first().is_some_and(|(_, reste)| correspond(motif, reste))
        }
        (Some((b'?', suite)), Some((_, reste))) => correspond(suite, reste),
        (Some((m, suite)), Some((n, reste))) if m.eq_ignore_ascii_case(n) => correspond(suite, reste),
        _ => false,
    }
}

/// La première valeur d'un réglage dans la configuration lue dans l'ordre de sshd : (fichier lu, mot écrit, valeur
/// telle qu'écrite). La casse est gardée : les noms GSSAPI finissent par du base64.
pub(crate) fn premiere_valeur<'a>(
    segments: &'a [(String, String)],
    noms: &[&str],
) -> Option<(usize, &'a str, &'a str)> {
    segments.iter().enumerate().find_map(|(i, (_, texte))| {
        texte.lines().map(str::trim).find_map(|l| {
            if l.starts_with('#') {
                return None;
            }
            let (cle, valeur) = l.split_once(|c: char| c.is_whitespace() || c == '=')?;
            let valeur = valeur.trim().trim_start_matches('=').trim().trim_matches('"');
            noms.iter()
                .any(|n| cle.eq_ignore_ascii_case(n))
                .then_some((i, cle, valeur))
        })
    })
}

/// La version d'OpenSSH dans « OpenSSH_9.6p1 Ubuntu-3ubuntu13, OpenSSL 3.0.13 ».
pub(crate) fn version_openssh(texte: &str) -> Option<(u32, u32)> {
    let reste = &texte[texte.find("OpenSSH_")? + "OpenSSH_".len()..];
    let (majeure, reste) = reste.split_once('.')?;
    let mineure: String = reste.chars().take_while(char::is_ascii_digit).collect();
    Some((majeure.parse().ok()?, mineure.parse().ok()?))
}

/// La version écrite dans le programme sshd (« OpenSSH_9.6p1 », suivie d'un zéro ou d'une espace). Il y garde
/// aussi des motifs de compatibilité pour reconnaître les vieux clients (« OpenSSH_2.*,OpenSSH_3.0* ») : ceux-là
/// finissent par « * » ou « , » et ne comptent pas ; parmi les vraies, la plus haute.
pub(crate) fn version_dans_le_programme(octets: &[u8]) -> Option<(u32, u32)> {
    const MOTIF: &[u8] = b"OpenSSH_";
    octets
        .windows(MOTIF.len())
        .enumerate()
        .filter(|(_, f)| *f == MOTIF)
        .filter_map(|(i, _)| {
            // OpenSSH de Microsoft : « OpenSSH_for_Windows_9.5p1 » dans sshd.exe et ssh.exe.
            let reste = octets.get(i + MOTIF.len()..)?;
            let reste = reste.strip_prefix(b"for_Windows_").unwrap_or(reste);
            let longueur = reste
                .iter()
                .take_while(|o| o.is_ascii_alphanumeric() || **o == b'.')
                .count();
            if !matches!(reste.get(longueur), Some(0 | b' ')) {
                return None;
            }
            let texte = std::str::from_utf8(reste.get(..longueur)?).ok()?;
            // Une version commence par « chiffres.chiffres » ; « OpenSSH_for_Windows » n'en est pas une.
            texte.split('.').next()?.parse::<u32>().ok()?;
            version_openssh(&format!("OpenSSH_{texte}"))
        })
        .max()
}

// ── Échange de clés post-quantique (COM-PQC-001 et 002) ──

/// L'échange post-quantique historique d'OpenSSH (8.5, par défaut depuis 9.0) : le seul nom qu'un 8.5 à 9.8 connaît.
pub(crate) const SNTRUP_OPENSSH: &str = "sntrup761x25519-sha512@openssh.com";
const SNTRUP: &str = "sntrup761x25519-sha512";
const MLKEM: &str = "mlkem768x25519-sha256";
/// Vu dans « ssh -Q kex » d'OpenSSH 10.6 ; la version qui l'a ajouté n'est pas relue : 10.6 est la seule sûre.
const MLKEM_NIST: &str = "mlkem768nistp256-sha256";

/// Ce qu'une version d'OpenSSH sait faire en post-quantique.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Pq {
    /// Avant 8.5 : rien.
    Aucun,
    /// 8.5 à 9.8 : sntrup761x25519-sha512@openssh.com seul (coupé par défaut avant 9.0).
    Sntrup,
    /// 9.9 et après : ML-KEM et sntrup, sous leurs noms courts aussi.
    MlKem,
}

pub(crate) fn pq_selon_version(v: (u32, u32)) -> Pq {
    if v >= (9, 9) {
        Pq::MlKem
    } else if v >= (8, 5) {
        Pq::Sntrup
    } else {
        Pq::Aucun
    }
}

/// Les noms post-quantiques que cette version connaît : ceux qu'un motif (« sntrup* ») peut ouvrir.
fn noms_pq(v: (u32, u32)) -> &'static [&'static str] {
    match pq_selon_version(v) {
        Pq::MlKem if v >= (10, 6) => &[MLKEM, MLKEM_NIST, SNTRUP, SNTRUP_OPENSSH],
        Pq::MlKem => &[MLKEM, SNTRUP, SNTRUP_OPENSSH],
        Pq::Sntrup => &[SNTRUP_OPENSSH],
        Pq::Aucun => &[],
    }
}

/// Ceux qu'elle propose sans rien écrire. En 9.9, ML-KEM est « disponible par défaut » (release-9.9) ; le nom
/// court de sntrup n'y est pas dit par défaut : il est laissé de côté, pour qu'un « - » qui retire le reste ne
/// passe jamais pour protégé à tort.
fn defauts_pq(v: (u32, u32)) -> &'static [&'static str] {
    if v >= (10, 0) {
        &[MLKEM, SNTRUP, SNTRUP_OPENSSH]
    } else if v >= (9, 9) {
        &[MLKEM, SNTRUP_OPENSSH]
    } else if v >= (9, 0) {
        &[SNTRUP_OPENSSH]
    } else {
        &[]
    }
}

/// Un nom d'échange de clés post-quantique : tous ceux d'OpenSSH contiennent « mlkem » ou « sntrup ».
pub(crate) fn nom_pq(nom: &str) -> bool {
    let n = nom.to_ascii_lowercase();
    n.contains("mlkem") || n.contains("sntrup")
}

/// La liste d'échanges de clés que sshd ou ssh retiennent contient-elle un post-quantique ? `valeur` : le
/// KexAlgorithms écrit (`None` : rien d'écrit, les valeurs par défaut) ; `version` d'OpenSSH. Une liste sans préfixe
/// remplace les valeurs par défaut (ses motifs s'appliquent à tout ce que la version connaît), « + » et « ^ » y
/// ajoutent, « - » en retire. Un nom écrit en entier est connu de la version : sinon sshd refuserait de démarrer.
/// `None` : la réponse dépend de la version, illisible.
pub(crate) fn kex_post_quantique(valeur: Option<&str>, version: Option<(u32, u32)>) -> Option<bool> {
    let defaut = || version.map(|v| !defauts_pq(v).is_empty());
    let Some(valeur) = valeur.map(str::trim).filter(|v| !v.is_empty()) else {
        return defaut();
    };
    let (prefixe, liste) = match valeur.as_bytes().first() {
        Some(&p @ (b'+' | b'-' | b'^')) => (Some(p), &valeur[1..]),
        _ => (None, valeur),
    };
    let entrees: Vec<&str> = liste.split(',').map(str::trim).filter(|e| !e.is_empty()).collect();
    // Ce qu'une entrée ouvre parmi les noms post-quantiques : `None` quand un motif le demande à une version
    // illisible.
    let ouvre_pq = |e: &str| -> Option<bool> {
        if !e.contains(['*', '?']) {
            return Some(nom_pq(e));
        }
        let v = version?;
        Some(noms_pq(v).iter().any(|n| correspond(e.as_bytes(), n.as_bytes())))
    };
    let ajoutes = || -> Option<bool> {
        let mut inconnu = false;
        for e in &entrees {
            match ouvre_pq(e) {
                Some(true) => return Some(true),
                Some(false) => {}
                None => inconnu = true,
            }
        }
        (!inconnu).then_some(false)
    };
    match prefixe {
        None => ajoutes(),
        Some(b'-') => {
            let v = version?;
            Some(
                defauts_pq(v)
                    .iter()
                    .any(|n| !entrees.iter().any(|e| correspond(e.as_bytes(), n.as_bytes()))),
            )
        }
        _ => match ajoutes() {
            Some(true) => Some(true),
            _ => defaut(),
        },
    }
}

/// Une liste écrite qui retire elle-même l'échange post-quantique, plutôt qu'une version qui ne le propose pas :
/// une liste qui remplace les valeurs par défaut, ou un « - » sur une version qui en proposait par défaut (sur une
/// autre, un « - » n'a rien de post-quantique à retirer : la cause est la version).
pub(crate) fn liste_qui_retire(valeur: Option<&str>, version: Option<(u32, u32)>) -> bool {
    match valeur.map(str::trim).filter(|v| !v.is_empty()).map(str::as_bytes) {
        None | Some([b'+' | b'^', ..]) => false,
        Some([b'-', ..]) => version.is_some_and(|v| !defauts_pq(v).is_empty()),
        Some(_) => true,
    }
}

/// Les noms à mettre en tête de KexAlgorithms pour cette version, jamais un nom qu'elle ne connaît pas : sshd
/// refuse un nom inconnu et ne redémarre pas (sur un serveur à distance, c'est se fermer la porte). Version
/// illisible : le nom « @openssh.com », connu de toutes depuis 8.5. `None` : trop vieille, rien à ajouter.
pub(crate) fn noms_a_ajouter(version: Option<(u32, u32)>) -> Option<String> {
    match version.map(pq_selon_version) {
        Some(Pq::Aucun) => None,
        Some(Pq::MlKem) => Some(format!("{MLKEM},{SNTRUP_OPENSSH}")),
        Some(Pq::Sntrup) | None => Some(SNTRUP_OPENSSH.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_de_l_openssh_de_windows() {
        // Les textes du sshd.exe d'OpenSSH 9.5p2 livré avec Windows 11 : la version, son préfixe court, la même
        // en UTF-16 (ignorée) et les motifs de compatibilité des vieux clients.
        let mut programme = b"..OpenSSH_for_Windows_9.5p2\0..OpenSSH_for_Windows_9.5\0".to_vec();
        programme.extend("OpenSSH_9.5p2 for Windows".encode_utf16().flat_map(u16::to_le_bytes));
        programme.extend_from_slice(b"\0OpenSSH_2.*,OpenSSH_3.0*\0OpenSSH_7.6*\0");
        assert_eq!(version_dans_le_programme(&programme), Some((9, 5)));
    }

    #[test]
    fn versions_et_capacites() {
        assert_eq!(pq_selon_version((7, 4)), Pq::Aucun);
        assert_eq!(pq_selon_version((8, 5)), Pq::Sntrup);
        assert_eq!(pq_selon_version((9, 6)), Pq::Sntrup);
        assert_eq!(pq_selon_version((9, 9)), Pq::MlKem);
        assert_eq!(pq_selon_version((10, 6)), Pq::MlKem);
        // Sans rien d'écrit : la version décide (8.5 l'a, mais pas par défaut).
        for (v, attendu) in [
            ((7, 4), false),
            ((8, 5), false),
            ((8, 9), false),
            ((9, 0), true),
            ((9, 6), true),
        ] {
            assert_eq!(kex_post_quantique(None, Some(v)), Some(attendu), "{v:?}");
        }
        assert_eq!(kex_post_quantique(None, Some((9, 9))), Some(true));
        assert_eq!(kex_post_quantique(None, None), None);
        assert_eq!(kex_post_quantique(Some("  "), Some((9, 0))), Some(true));
    }

    #[test]
    fn listes_ecrites_plus_moins_chapeau() {
        // 8.5 avec le nom @openssh.com écrit : protégé ; sans : non.
        assert_eq!(
            kex_post_quantique(Some("+sntrup761x25519-sha512@openssh.com"), Some((8, 5))),
            Some(true)
        );
        assert_eq!(
            kex_post_quantique(Some("+curve25519-sha256"), Some((8, 5))),
            Some(false)
        );
        assert_eq!(kex_post_quantique(Some("^sntrup*"), Some((8, 7))), Some(true));
        // Liste remplacée : seulement ce qu'elle nomme.
        assert_eq!(
            kex_post_quantique(Some("curve25519-sha256,ecdh-sha2-nistp256"), None),
            Some(false)
        );
        assert_eq!(
            kex_post_quantique(Some("mlkem768x25519-sha256,curve25519-sha256"), None),
            Some(true)
        );
        assert_eq!(
            kex_post_quantique(Some("SNTRUP761X25519-SHA512@openssh.com"), None),
            Some(true)
        );
        // Un motif dans une liste remplacée : il faut savoir ce que la version connaît.
        assert_eq!(kex_post_quantique(Some("curve25519*,mlkem*"), Some((9, 9))), Some(true));
        assert_eq!(
            kex_post_quantique(Some("curve25519*,mlkem*"), Some((9, 6))),
            Some(false)
        );
        assert_eq!(kex_post_quantique(Some("curve25519*,mlkem*"), None), None);
        // « - » : ce qui reste des valeurs par défaut.
        assert_eq!(kex_post_quantique(Some("-sntrup*"), Some((9, 6))), Some(false));
        assert_eq!(kex_post_quantique(Some("-sntrup*"), Some((10, 0))), Some(true));
        assert_eq!(kex_post_quantique(Some("-sntrup*,mlkem*"), Some((10, 0))), Some(false));
        assert_eq!(
            kex_post_quantique(Some("-diffie-hellman-group14-sha1"), Some((9, 0))),
            Some(true)
        );
        assert_eq!(kex_post_quantique(Some("-*"), Some((10, 6))), Some(false));
        assert_eq!(kex_post_quantique(Some("-sntrup*"), None), None);
        let v = Some((9, 6));
        assert!(liste_qui_retire(Some("-sntrup*"), v) && liste_qui_retire(Some("curve25519-sha256"), v));
        assert!(!liste_qui_retire(Some("+x"), v) && !liste_qui_retire(Some("^x"), v) && !liste_qui_retire(None, v));
        // Un « - » sur une version sans post-quantique par défaut n'en retire aucun : la cause est la version.
        assert!(!liste_qui_retire(Some("-diffie-hellman-group1-sha1"), Some((8, 9))));
        assert!(!liste_qui_retire(Some("-sntrup*"), None));
    }

    /// Le conseil ne nomme jamais un algorithme inconnu de la version lue.
    #[test]
    fn conseil_selon_la_version() {
        assert_eq!(noms_a_ajouter(Some((7, 4))), None);
        for v in [(8, 5), (9, 0), (9, 6), (9, 8)] {
            let n = noms_a_ajouter(Some(v)).unwrap();
            assert_eq!(n, SNTRUP_OPENSSH, "{v:?}");
            assert!(n.split(',').all(|x| noms_pq(v).contains(&x)), "{v:?}");
        }
        for v in [(9, 9), (10, 0), (10, 6)] {
            let n = noms_a_ajouter(Some(v)).unwrap();
            assert!(n.starts_with("mlkem768x25519-sha256,"), "{v:?}");
            assert!(n.split(',').all(|x| noms_pq(v).contains(&x)), "{v:?}");
        }
        assert_eq!(noms_a_ajouter(None).as_deref(), Some(SNTRUP_OPENSSH));
    }

    #[test]
    fn version_de_microsoft() {
        let programme = b"..OpenSSH_for_Windows\0OpenSSH_for_Windows_9.5p1\0OpenSSH_7.0*\0";
        assert_eq!(version_dans_le_programme(programme), Some((9, 5)));
        assert_eq!(
            version_dans_le_programme(b"OpenSSH_for_Windows_8.1p1, LibreSSL\0"),
            None
        );
        assert_eq!(version_dans_le_programme(b"OpenSSH_for_Windows_8.1p1 \0"), Some((8, 1)));
    }
}

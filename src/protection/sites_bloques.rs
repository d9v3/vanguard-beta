//! Sites dangereux bloqués par le fichier hosts : les hôtes d'URLhaus (logiciels malveillants) et les domaines des
//! serveurs de commande de ThreatFox, avec la clé abuse.ch, envoyés vers 0.0.0.0 et ::. Posé à la demande
//! (`vanguard sites-dangereux on`), après accord ; le rafraîchir demande les mêmes droits, donc le bilan dit quand la
//! liste a plus d'une semaine. Le bloc de Vanguard est entre deux marques : `off` le retire exactement, le reste du
//! fichier ne change jamais. Contourné par un navigateur réglé en DNS chiffré ; un DNS qui protège (Bouclier canadien,
//! Quad9) couvre plus. Plus tard, avec la tâche système (après la signature du code), il se rafraîchira seul.
//!
//! L'écriture, seule étape en administrateur, recopie le fichier préparé dans un fichier de root et vérifie son
//! empreinte, puis celle du hosts lu au départ : un programme qui changerait l'un ou l'autre entre-temps ne fait rien
//! écrire.

use std::collections::BTreeSet;
use std::path::PathBuf;

use chrono::NaiveDate;

use crate::langue::Reponse;
use crate::machine::{Constat, alerte};
use crate::risk::Niveau;
use crate::ui::*;

const DEBUT: &str = "# >>> Vanguard";
const FIN: &str = "# <<< Vanguard <<<";
/// Dans la marque de début : le hosts ne finissait pas par une fin de ligne, Vanguard en a ajouté une, que `off` retire.
const FDL_AJOUTEE: &str = "(fin de ligne ajoutée)";
/// Au-delà, le bilan propose de rafraîchir : URLhaus et ThreatFox changent chaque jour.
const VIEILLE_JOURS: i64 = 7;
/// Sous Windows, un hosts de dizaines de milliers de lignes ralentit le client DNS : les noms au-delà ne sont pas
/// posés, et c'est dit.
#[cfg(windows)]
const MAX_NOMS: usize = 5000;
#[cfg(not(windows))]
// Sans systemd-resolved ni nscd, glibc relit tout le fichier à chaque nom demandé : 20 000 noms coûtent ~2 ms.
const MAX_NOMS: usize = 20_000;

fn fichier_hosts() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()))
            .join("System32\\drivers\\etc\\hosts")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/etc/hosts")
    }
}

const FIN_DE_LIGNE: &str = if cfg!(windows) { "\r\n" } else { "\n" };

/// Le hosts sans le bloc de Vanguard. `None` : une marque sans l'autre (bloc abîmé) ; rien n'est retiré à l'aveugle.
fn sans_bloc(hosts: &str) -> Option<String> {
    let mut sortie = String::with_capacity(hosts.len());
    let mut dedans = false;
    for l in hosts.split_inclusive('\n') {
        let t = l.trim_end();
        if t.starts_with(DEBUT) {
            if dedans {
                return None;
            }
            dedans = true;
            if t.contains(FDL_AJOUTEE) {
                let fin = sortie
                    .strip_suffix("\r\n")
                    .or_else(|| sortie.strip_suffix('\n'))
                    .map(str::len);
                if let Some(n) = fin {
                    sortie.truncate(n);
                }
            }
        } else if t == FIN {
            if !dedans {
                return None;
            }
            dedans = false;
        } else if !dedans {
            sortie.push_str(l);
        }
    }
    (!dedans).then_some(sortie)
}

/// Un nom qu'un fichier hosts peut tenir : lettres, chiffres, tirets, points ; ni une adresse IP (hosts ne bloque
/// que des noms), ni un nom sans point.
fn nom_valide(n: &str) -> bool {
    n.len() <= 253
        && n.contains('.')
        && n.parse::<std::net::IpAddr>().is_err()
        && n.split('.').all(|e| !e.is_empty() && e.len() <= 63)
        && n.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.' || b == b'_')
}

/// Le bloc de Vanguard : sa marque datée, chaque nom vers 0.0.0.0 et :: (sans la seconde ligne, une demande IPv6
/// passerait au DNS), la marque de fin.
fn bloc(noms: &BTreeSet<String>, date: NaiveDate) -> String {
    let mut b = format!(
        "{DEBUT} : sites dangereux bloqués le {date} (URLhaus, ThreatFox ; « vanguard sites-dangereux off » les retire) >>>{FIN_DE_LIGNE}"
    );
    for n in noms {
        for adresse in ["0.0.0.0", "::"] {
            for morceau in [adresse, " ", n, FIN_DE_LIGNE] {
                b.push_str(morceau);
            }
        }
    }
    b.push_str(FIN);
    b.push_str(FIN_DE_LIGNE);
    b
}

/// Le hosts sans bloc, puis le bloc ; une fin de ligne ajoutée à la dernière ligne est notée dans la marque.
fn avec_bloc(sans: &str, bloc: &str) -> String {
    let mut h = sans.to_string();
    if !h.is_empty() && !h.ends_with('\n') {
        h.push_str(FIN_DE_LIGNE);
        return h + &bloc.replacen(DEBUT, &format!("{DEBUT} {FDL_AJOUTEE}"), 1);
    }
    h + bloc
}

/// La date du bloc posé, et son nombre de noms ; `None` : pas de bloc.
fn bloc_pose(hosts: &str) -> Option<(Option<NaiveDate>, usize)> {
    let entete = hosts.lines().find(|l| l.starts_with(DEBUT))?;
    let date = entete
        .split_once(" le ")
        .and_then(|(_, r)| NaiveDate::parse_from_str(r.get(..10)?, "%Y-%m-%d").ok());
    let sans = sans_bloc(hosts).unwrap_or_default();
    let noms = hosts.lines().count().saturating_sub(sans.lines().count() + 2) / 2;
    Some((date, noms))
}

/// Le bloc de Vanguard est-il dans le hosts de cet ordinateur ? Illisible : non (rien à dire de plus).
pub(crate) fn bloc_present() -> bool {
    std::fs::read_to_string(fichier_hosts()).is_ok_and(|h| bloc_pose(&h).is_some())
}

fn empreinte(octets: &[u8]) -> String {
    use sha2::Digest;
    let e: [u8; 32] = sha2::Sha256::digest(octets).into();
    crate::protection::empreintes::hex(&e)
}

/// La commande en administrateur qui écrit `prepare` à la place du hosts, si leurs empreintes sont toujours celles
/// lues sans droits (`nouvelle`, `avant`). Le hosts est réécrit en place : ses droits, son propriétaire et un montage
/// éventuel restent. Réécrire vide le fichier d'abord : une écriture interrompue (disque plein) remet la copie prise
/// juste avant.
#[cfg(not(windows))]
fn commandes(prepare: &str, nouvelle: &str, avant: &str) -> Vec<String> {
    let (sha, vider) = if cfg!(target_os = "macos") {
        ("shasum -a 256", "dscacheutil -flushcache; killall -HUP mDNSResponder")
    } else {
        ("sha256sum", "resolvectl flush-caches")
    };
    vec![format!(
        "sudo sh -c 't=$(mktemp) && o=$(mktemp) && cat \"$1\" > \"$t\" && [ \"$({sha} < \"$t\" | cut -d\" \" -f1)\" = \"$2\" ] && [ \"$({sha} < /etc/hosts | cut -d\" \" -f1)\" = \"$3\" ] && cat /etc/hosts > \"$o\" && {{ cat \"$t\" > /etc/hosts || {{ cat \"$o\" > /etc/hosts; false; }}; }}; r=$?; rm -f \"$t\" \"$o\"; [ $r = 0 ] && {{ {vider}; }} 2>/dev/null; exit $r' sh {} {} {}",
        crate::commande::sh_chaine(prepare),
        crate::commande::sh_chaine(nouvelle),
        crate::commande::sh_chaine(avant)
    )]
}

#[cfg(windows)]
fn commandes(prepare: &str, nouvelle: &str, avant: &str) -> Vec<String> {
    vec![format!(
        "$e = {{ param($o) -join ([Security.Cryptography.SHA256]::Create().ComputeHash($o) | ForEach-Object {{ $_.ToString('x2') }}) }}; $p = [IO.File]::ReadAllBytes({}); $f = \"$env:SystemRoot\\System32\\drivers\\etc\\hosts\"; if ((& $e $p) -ne '{nouvelle}' -or (& $e ([IO.File]::ReadAllBytes($f))) -ne '{avant}') {{ throw 'hosts ou fichier préparé changé depuis la lecture : rien écrit' }}; $o = [IO.File]::ReadAllBytes($f); try {{ [IO.File]::WriteAllBytes($f, $p) }} catch {{ [IO.File]::WriteAllBytes($f, $o); throw }}; try {{ Clear-DnsClientCache }} catch {{ }}",
        crate::commande::ps_chaine(prepare)
    )]
}

/// Écrit `nouveau` à la place du hosts lu (`avant`), en administrateur, après l'avoir montré ; relit pour dire ce qui
/// est vraiment posé.
fn ecrire(avant: &[u8], nouveau: &str) -> bool {
    let dossier = crate::socle::dossier_local().join("sites-bloques");
    let prepare = dossier.join("hosts");
    if let Err(e) = std::fs::create_dir_all(&dossier).and_then(|()| std::fs::write(&prepare, nouveau)) {
        trp!(
            "  ✖ Fichier préparé pas écrit : {e}",
            "  ✖ Prepared file not written: {e}"
        );
        return false;
    }
    let ok = crate::machine::appliquer(&commandes(
        &prepare.to_string_lossy(),
        &empreinte(nouveau.as_bytes()),
        &empreinte(avant),
    ));
    let _ = std::fs::remove_file(&prepare);
    let apres = std::fs::read(fichier_hosts());
    let ecrit = apres.as_ref().is_ok_and(|h| h == nouveau.as_bytes());
    // Un échec qui a quand même changé le fichier (copie d'avant pas remise) : jamais « rien n'est changé ».
    if !ecrit && apres.as_ref().is_ok_and(|h| h != avant) {
        trp!(
            "  ⚠ {} a changé malgré l'échec : à vérifier à la main.",
            "  ⚠ {} changed despite the failure: to check by hand.",
            chemin_affichable(&fichier_hosts())
        );
    }
    ok && ecrit
}

/// Les noms à bloquer, et ce qui n'a pas pu être lu. Il en faut au moins une liste.
fn noms_a_bloquer() -> (BTreeSet<String>, Vec<String>) {
    let mut noms = BTreeSet::new();
    let mut manquent = Vec::new();
    match crate::protection::lien::hotes_urlhaus() {
        Ok((h, note)) => {
            noms.extend(h);
            manquent.extend(note.map(|n| trf!("liste d'URLhaus : {n}", "URLhaus list: {n}")));
        }
        Err(r) => manquent.push(r),
    }
    match crate::protection::sortantes::domaines_de_commande() {
        Ok(d) => noms.extend(d.into_iter().map(|n| n.trim_end_matches('.').to_lowercase())),
        Err(r) => manquent.push(r),
    }
    noms.retain(|n| nom_valide(n));
    (noms, manquent)
}

/// `vanguard sites-dangereux [on|off]`.
pub fn commande(etat: Option<&str>) {
    let chemin = fichier_hosts();
    let avant = match std::fs::read(&chemin) {
        Ok(a) => a,
        Err(e) => {
            trp!(
                "  ✖ {} illisible : {e}",
                "  ✖ {} unreadable: {e}",
                chemin_affichable(&chemin)
            );
            return;
        }
    };
    // Réécrit après une conversion, un accent enregistré en ANSI (ancien Bloc-notes) changerait hors du bloc.
    let Ok(texte) = String::from_utf8(avant.clone()) else {
        trp!(
            "  ✖ {} n'est pas en UTF-8 (un accent enregistré en ANSI ?) : rien n'est changé, pour ne pas le réécrire autrement.",
            "  ✖ {} is not UTF-8 (an accent saved as ANSI?): nothing is changed, so as not to rewrite it differently.",
            chemin_affichable(&chemin)
        );
        return;
    };
    let Some(sans) = sans_bloc(&texte) else {
        trp!(
            "  ✖ Le bloc de Vanguard dans {} est abîmé (une marque sans l'autre) : rien n'est changé. À corriger à la main, entre « {DEBUT} » et « {FIN} ».",
            "  ✖ Vanguard's block in {} is damaged (one marker without the other): nothing is changed. To fix by hand, between “{DEBUT}” and “{FIN}”.",
            chemin_affichable(&chemin)
        );
        return;
    };
    match etat {
        Some("on") => poser(&avant, &sans),
        Some("off") => {
            if sans == texte {
                trp!(
                    "  Aucun site bloqué par Vanguard : rien à retirer.",
                    "  No site blocked by Vanguard: nothing to remove."
                );
                return;
            }
            if ecrire(&avant, &sans) {
                trp!(
                    "  {VERT}✔{RESET} Sites dangereux débloqués : le bloc de Vanguard est retiré, le reste du fichier n'a pas changé.",
                    "  {VERT}✔{RESET} Dangerous sites unblocked: Vanguard's block is removed, the rest of the file has not changed."
                );
            } else {
                trp!("  ✖ Rien n'est retiré.", "  ✖ Nothing is removed.");
            }
        }
        _ => match bloc_pose(&texte) {
            Some((date, noms)) => {
                let date = date.map_or_else(|| "?".to_string(), |d| d.to_string());
                trp!(
                    "  {noms} sites dangereux bloqués depuis le {date} ({}). Rafraîchir : vanguard sites-dangereux on ; retirer : vanguard sites-dangereux off.",
                    "  {noms} dangerous sites blocked since {date} ({}). Refresh: vanguard dangerous-sites on; remove: vanguard dangerous-sites off.",
                    chemin_affichable(&chemin)
                );
            }
            None => trp!(
                "  Aucun site dangereux bloqué. Les bloquer : vanguard sites-dangereux on (clé abuse.ch, droits d'administrateur).",
                "  No dangerous site blocked. Block them: vanguard dangerous-sites on (abuse.ch key, administrator rights)."
            ),
        },
    }
}

/// Depuis le menu : l'état, puis bloquer (ou rafraîchir), retirer, ou rien.
pub fn menu() {
    commande(None);
    let choix = crate::selection::choisir_en_ligne(
        &[
            (
                "b",
                tr!("Bloquer, ou rafraîchir la liste", "Block, or refresh the list"),
            ),
            ("r", tr!("Retirer le blocage", "Remove the block")),
        ],
        tr!(
            "\n  B : bloquer ou rafraîchir · R : retirer · Entrée : rien. Choix : ",
            "\n  B: block or refresh · R: remove · Enter: nothing. Choice: "
        ),
    );
    match choix.as_deref() {
        Some("b") => commande(Some("on")),
        Some("r") => commande(Some("off")),
        _ => {}
    }
}

fn poser(avant: &[u8], sans: &str) {
    let (noms, manquent) = noms_a_bloquer();
    for raison in &manquent {
        afficher_aligne(&format!("  {GRIS}ℹ{RESET} "), raison, 4, GRIS);
    }
    if noms.is_empty() {
        trp!(
            "  ✖ Aucune liste lue : rien n'est bloqué. La clé abuse.ch (gratuite) se donne dans Paramètres.",
            "  ✖ No list read: nothing is blocked. The abuse.ch key (free) is given in Settings."
        );
        return;
    }
    let total = noms.len();
    let noms: BTreeSet<String> = noms.into_iter().take(MAX_NOMS).collect();
    if noms.len() < total {
        trp!(
            "  {GRIS}ℹ{RESET} {} noms sur {total} : au-delà, le fichier hosts ralentirait l'ordinateur.",
            "  {GRIS}ℹ{RESET} {} names out of {total}: beyond that, the hosts file would slow the computer down.",
            noms.len()
        );
    }
    let nouveau = avec_bloc(sans, &bloc(&noms, chrono::Local::now().date_naive()));
    trp!(
        "\n  {} sites dangereux vont être envoyés nulle part dans {} : le reste du fichier ne change pas, et « vanguard sites-dangereux off » les retire. Un navigateur réglé en DNS chiffré passe à côté.",
        "\n  {} dangerous sites will be sent nowhere in {}: the rest of the file does not change, and “vanguard dangerous-sites off” removes them. A browser set to encrypted DNS bypasses it.",
        noms.len(),
        chemin_affichable(&fichier_hosts())
    );
    if !demander(tr!("\n  Les bloquer ? [o/N] : ", "\n  Block them? [y/N]: ")).oui() {
        trp!("  Rien n'est bloqué.", "  Nothing is blocked.");
        return;
    }
    if ecrire(avant, &nouveau) {
        trp!(
            "  {VERT}✔{RESET} Sites dangereux bloqués.",
            "  {VERT}✔{RESET} Dangerous sites blocked."
        );
    } else {
        trp!("  ✖ Rien n'est bloqué.", "  ✖ Nothing is blocked.");
    }
}

/// Pour le bilan : un bloc posé il y a plus d'une semaine ne bloque pas les sites apparus depuis.
pub(crate) fn constat(categorie: &'static str) -> Option<Constat> {
    let hosts = std::fs::read_to_string(fichier_hosts()).ok()?;
    let jours = vieux_de(&hosts, chrono::Local::now().date_naive())?;
    let message = if jours == i64::MAX {
        tr!(
            "La liste des sites dangereux bloqués n'a pas de date lisible : ceux apparus depuis passent peut-être.",
            "The list of blocked dangerous sites has no readable date: those that appeared since may get through."
        )
        .to_string()
    } else {
        trf!(
            "La liste des sites dangereux bloqués date de {jours} jours : ceux apparus depuis passent.",
            "The list of blocked dangerous sites is {jours} days old: those that appeared since get through."
        )
    };
    Some(alerte(categorie, Niveau::Info, message).manuel(
        tr!(
            "La rafraîchir : vanguard sites-dangereux on (droits d'administrateur)",
            "Refresh it: vanguard dangerous-sites on (administrator rights)"
        ),
        &[],
    ))
}

/// L'âge du bloc s'il dépasse `VIEILLE_JOURS` ; une date illisible compte comme vieille (`i64::MAX`).
fn vieux_de(hosts: &str, aujourd_hui: NaiveDate) -> Option<i64> {
    let (date, _) = bloc_pose(hosts)?;
    let jours = date.map_or(i64::MAX, |d| (aujourd_hui - d).num_days());
    (jours > VIEILLE_JOURS).then_some(jours)
}

/// Les noms que ce hosts envoie nulle part (0.0.0.0, ::, boucle locale), le bloc de Vanguard compris : sous Windows,
/// la mémoire DNS les garde comme des noms demandés, alors qu'ils n'ont mené nulle part.
fn noms_detournes(hosts: &str) -> std::collections::HashSet<String> {
    hosts
        .lines()
        .map(|l| l.split('#').next().unwrap_or_default())
        .filter_map(|l| {
            let mut mots = l.split_whitespace();
            let ip: std::net::IpAddr = mots.next()?.parse().ok()?;
            (ip.is_unspecified() || ip.is_loopback()).then_some(mots)
        })
        .flatten()
        .map(|n| n.trim_end_matches('.').to_lowercase())
        .collect()
}

/// Ceux du hosts de cet ordinateur ; illisible, aucun.
pub(crate) fn noms_bloques_ici() -> std::collections::HashSet<String> {
    std::fs::read_to_string(fichier_hosts())
        .map(|h| noms_detournes(&h))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jour(d: &str) -> NaiveDate {
        NaiveDate::parse_from_str(d, "%Y-%m-%d").unwrap()
    }

    #[test]
    fn bloc_pose_puis_retire_exactement() {
        let hosts = "127.0.0.1 localhost\n# à moi\n192.0.2.5 imprimante.salon\n";
        let noms: BTreeSet<String> = ["piege-exemple.com", "c2.exemple.org"].map(String::from).into();
        let pose = avec_bloc(hosts, &bloc(&noms, jour("2026-10-22")));
        assert!(
            pose.starts_with(hosts) && pose.contains("0.0.0.0 piege-exemple.com") && pose.contains(":: c2.exemple.org")
        );
        // Retiré : le fichier d'origine, octet pour octet ; reposé : un seul bloc.
        assert_eq!(sans_bloc(&pose).as_deref(), Some(hosts));
        let repose = avec_bloc(&sans_bloc(&pose).unwrap(), &bloc(&noms, jour("2026-10-23")));
        assert_eq!(repose.matches(DEBUT).count(), 1);
        assert_eq!(bloc_pose(&pose), Some((Some(jour("2026-10-22")), 2)));
        assert_eq!(bloc_pose(hosts), None);
        // Un hosts sans fin de ligne finale garde sa dernière ligne entière, et `off` le rend tel quel.
        let sans_fin = "127.0.0.1 localhost";
        let pose = avec_bloc(sans_fin, &bloc(&noms, jour("2026-10-22")));
        assert!(pose.starts_with(&format!("127.0.0.1 localhost{FIN_DE_LIGNE}{DEBUT} {FDL_AJOUTEE}")));
        assert_eq!(sans_bloc(&pose).as_deref(), Some(sans_fin));
        assert_eq!(bloc_pose(&pose), Some((Some(jour("2026-10-22")), 2)));
        assert_eq!(
            avec_bloc("127.0.0.1 localhost", "B"),
            format!("127.0.0.1 localhost{FIN_DE_LIGNE}B")
        );
    }

    #[test]
    fn bloc_abime_jamais_retire_a_l_aveugle() {
        assert_eq!(sans_bloc("a\n# >>> Vanguard : x >>>\n0.0.0.0 x.org\n"), None);
        assert_eq!(sans_bloc("a\n# <<< Vanguard <<<\nb\n"), None);
        assert_eq!(sans_bloc("# >>> Vanguard\n# >>> Vanguard\n# <<< Vanguard <<<\n"), None);
    }

    #[test]
    fn noms_envoyes_nulle_part() {
        let h = "127.0.0.1 localhost\n::1 localhost ip6-localhost\n192.0.2.5 imprimante.salon\n0.0.0.0 Piege-Exemple.com # pub\n:: c2.exemple.org.\n# 0.0.0.0 commente.org\n";
        let n = noms_detournes(h);
        assert!(n.contains("piege-exemple.com") && n.contains("c2.exemple.org") && n.contains("localhost"));
        assert!(!n.contains("imprimante.salon") && !n.contains("commente.org"));
    }

    #[test]
    fn noms_que_hosts_peut_tenir() {
        for n in ["piege-exemple.com", "a.b-c.exemple.org", "x_y.exemple.net"] {
            assert!(nom_valide(n), "{n}");
        }
        for n in [
            "203.0.113.9",
            "localhost",
            "",
            "a..b",
            "Majuscule.com",
            "espace .com",
            "a.com\n0.0.0.0 banque.ca",
        ] {
            assert!(!nom_valide(n), "{n:?}");
        }
    }

    #[test]
    fn vieillesse_du_bloc() {
        let pose = avec_bloc("", &bloc(&BTreeSet::from(["x.org".to_string()]), jour("2026-10-01")));
        assert_eq!(vieux_de(&pose, jour("2026-10-08")), None);
        assert_eq!(vieux_de(&pose, jour("2026-10-22")), Some(21));
        assert_eq!(vieux_de("127.0.0.1 localhost\n", jour("2026-10-22")), None);
        // Date illisible : vieille, pour qu'on la rafraîchisse.
        assert!(
            vieux_de(
                "# >>> Vanguard : sans date >>>\n# <<< Vanguard <<<\n",
                jour("2026-10-22")
            )
            .is_some()
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn commande_d_ecriture_verifiee() {
        let c = commandes("/home/alice/.local/share/vanguard/sites-bloques/hosts", "aa", "bb");
        assert_eq!(c.len(), 1);
        assert!(
            c[0].starts_with("sudo sh -c '")
                && c[0].ends_with("sh '/home/alice/.local/share/vanguard/sites-bloques/hosts' 'aa' 'bb'"),
            "{}",
            c[0]
        );
        // Les deux empreintes sont vérifiées avant d'écrire ; écrit en place.
        assert!(c[0].contains("= \"$2\" ] && [") && c[0].contains("= \"$3\" ] && cat /etc/hosts > \"$o\" && { cat \"$t\" > /etc/hosts || { cat \"$o\" > /etc/hosts; false; }; }"));
    }
}

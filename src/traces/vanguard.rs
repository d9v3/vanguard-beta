//! Ce que Vanguard a lui-même vu et fait, versé dans les traces d'incident : ses alertes (surveillance, veilleur,
//! blocage), ses gestes (blocages, quarantaines) avec la preuve relevée avant chacun, ce qui est en quarantaine et
//! son empreinte, les alertes déclarées normales, l'état de ses sceaux. Ce sont les repères les mieux datés d'une
//! chronologie (l'alerte de la nuit, le programme arrêté, le fichier isolé) : ils entrent dans CHRONOLOGIE.txt, et
//! leurs fichiers d'origine sont recopiés tels quels (« 07-etat-… »), pour que le MANIFESTE prouve plus tard qu'ils
//! n'ont pas changé.
//!
//! Un fil relie un incident : l'objet dont parlent l'alerte, la preuve et le geste (le programme, son fichier,
//! l'adresse), tout ce qui le concerne remis dans l'ordre du temps.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use chrono::TimeZone;

use super::chronologie::{Evenement, Genre as GenreChrono, Source};
use super::{Bi, Partie, bi, champ, creer_fichier, entete, ouvrir_ordinaire};
use crate::modele::evenement::Genre;

/// Le fichier écrit.
const NOM: &str = "07-vanguard.txt";
/// Les fichiers d'état recopiés tels quels, 5 Mo au plus chacun.
const ETATS: [&str; 9] = [
    "surveillance-alertes.jsonl",
    crate::changements::RELEVE,
    "quarantaine/quarantaine.json",
    crate::sceau::NORMALES,
    crate::sceau::APPRIS,
    "sceaux.json",
    "blocage.json",
    crate::sceau::BOTNETS,
    "veilleur-etat.json",
];
const BORNE_ETAT: u64 = 5 << 20;

/// Une chose vue ou faite par Vanguard, datée : pour les fils et la chronologie.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Fait {
    /// « AAAA-MM-JJ HH:MM[:SS] », heure de cet ordinateur.
    pub date: String,
    /// La clé de ce dont il parle (alerte, menace) ; vide : rien à relier.
    pub cle: String,
    pub geste: bool,
    /// Ses lignes, la première dit ce que c'est.
    pub lignes: Vec<String>,
}

/// L'objet dont parle une clé, ce qui relie l'alerte, la preuve et le geste : le chemin d'un programme ou d'un
/// fichier, une adresse IP, l'appareil. « blocage|programme:4242:/tmp/x », « veilleur|raison|/tmp/x » et
/// « fichier:/tmp/x » parlent tous de /tmp/x.
pub(crate) fn objet(cle: &str) -> String {
    let cle = ["blocage|", "veilleur|"]
        .iter()
        .find_map(|p| cle.strip_prefix(p))
        .unwrap_or(cle);
    if let Some(r) = cle.strip_prefix("programme:") {
        // « programme:4242:/chemin » ou « programme:/chemin » (sans son numéro de processus).
        return match r.split_once(':') {
            Some((pid, chemin)) if pid.chars().all(|c| c.is_ascii_digit()) => chemin.to_string(),
            _ => r.to_string(),
        };
    }
    for p in ["fichier:", "connexion:", "permissions:"] {
        if let Some(r) = cle.strip_prefix(p) {
            return r.to_string();
        }
    }
    if let Some(r) = cle.strip_prefix("botnet|") {
        // « programme → 203.0.113.7:443 (famille, liste) » : l'adresse.
        let serveur = r.rsplit(" → ").next().unwrap_or(r);
        let adresse = serveur.split_whitespace().next().unwrap_or(serveur);
        return adresse
            .parse::<std::net::SocketAddr>()
            .map_or_else(|_| adresse.to_string(), |a| a.ip().to_string());
    }
    // Une alerte du veilleur : « raison|chemin », ou l'adresse et le port d'une connexion fermée avec un botnet
    // (« 203.0.113.7:443 »), qui se relie au blocage de l'adresse (« connexion:203.0.113.7 ») par l'adresse seule.
    let reste = cle.rsplit_once('|').map_or(cle, |(_, r)| r);
    reste
        .parse::<std::net::SocketAddr>()
        .map_or_else(|_| reste.to_string(), |a| a.ip().to_string())
}

/// Les fils d'incident : les faits regroupés par objet, dans l'ordre du temps ; seulement ceux qui comptent au
/// moins un geste, ou plusieurs faits (une alerte seule a déjà sa ligne).
pub(crate) fn fils(faits: &[Fait]) -> Vec<(String, Vec<&Fait>)> {
    let mut par: BTreeMap<String, Vec<&Fait>> = BTreeMap::new();
    for f in faits.iter().filter(|f| !f.cle.is_empty()) {
        par.entry(objet(&f.cle)).or_default().push(f);
    }
    par.into_iter()
        .filter(|(_, v)| v.len() > 1 || v.iter().any(|f| f.geste))
        .map(|(o, mut v)| {
            v.sort_by(|a, b| a.date.cmp(&b.date));
            (o, v)
        })
        .collect()
}

/// Les alertes du journal du tableau de bord, en faits.
fn faits_des_alertes(alertes: &[crate::reseau::tableau::Alerte]) -> Vec<Fait> {
    alertes
        .iter()
        .map(|a| Fait {
            date: a.date.clone(),
            cle: a.cle.clone().unwrap_or_default(),
            geste: false,
            lignes: vec![format!(
                "{}  {}  {} : {}",
                a.date,
                crate::reseau::tableau::libelle_genre(&a.genre),
                champ(&a.titre),
                champ(&a.texte)
            )],
        })
        .collect()
}

/// Les gestes notés dans « Ce que Vanguard a changé », avec leur preuve, en faits.
fn faits_des_gestes(gestes: &[(String, bool, crate::changements::Blocage)]) -> Vec<Fait> {
    gestes
        .iter()
        .map(|(date, reussi, b)| {
            let mut lignes = vec![format!(
                "{date}  {}{}  {}{}",
                if *reussi { "FAIT/DONE" } else { "ÉCHEC/FAILED" },
                if b.automatique { " (auto)" } else { "" },
                champ(&b.quoi),
                crate::changements::fin_du_blocage(b).unwrap_or_default()
            )];
            match &b.preuve {
                Some(p) => lignes.extend(p.lignes().iter().map(|l| format!("    {}", champ(l)))),
                None => lignes.push(
                    "    preuve/evidence : aucune (geste sans trace à garder, ou d'avant la 0.86) / none".to_string(),
                ),
            }
            Fait {
                date: date.clone(),
                cle: b.cle.clone(),
                geste: true,
                lignes,
            }
        })
        .collect()
}

/// Une date locale du journal (« AAAA-MM-JJ HH:MM[:SS] ») en secondes depuis 1970.
fn secondes(date: &str) -> Option<i64> {
    let n = chrono::NaiveDateTime::parse_from_str(date, "%Y-%m-%d %H:%M:%S")
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(date, "%Y-%m-%d %H:%M"))
        .ok()?;
    chrono::Local.from_local_datetime(&n).earliest().map(|d| d.timestamp())
}

/// Le texte de 07-vanguard.txt.
fn texte(faits: &[Fait], quarantaine: &[(String, String, String, Option<String>)], autres: &[String]) -> String {
    let titre = Bi::new("Ce que Vanguard a vu et fait", "What Vanguard saw and did");
    let mut t = entete(&titre);
    let _ = writeln!(t, "\n== Fils d'incident / Incident threads ==");
    let f = fils(faits);
    if f.is_empty() {
        let _ = writeln!(t, "(aucun / none)");
    }
    for (o, v) in &f {
        let _ = writeln!(t, "\n-- {} --", champ(o));
        for x in v {
            for l in &x.lignes {
                let _ = writeln!(t, "{l}");
            }
        }
    }
    let _ = writeln!(t, "\n== Gestes de Vanguard / Vanguard actions ==");
    for x in faits.iter().filter(|x| x.geste) {
        for l in &x.lignes {
            let _ = writeln!(t, "{l}");
        }
    }
    let _ = writeln!(t, "\n== Alertes de Vanguard / Vanguard alerts ==");
    for x in faits.iter().filter(|x| !x.geste) {
        for l in &x.lignes {
            let _ = writeln!(t, "{l}");
        }
    }
    let _ = writeln!(t, "\n== Quarantaine / Quarantine ==");
    for (date, origine, detection, sha) in quarantaine {
        let _ = writeln!(
            t,
            "{date}  {}  {}  SHA-256 {}",
            champ(origine),
            champ(detection),
            sha.as_deref().unwrap_or("?")
        );
    }
    let _ = writeln!(t, "\n== Divers / Other ==");
    for l in autres {
        let _ = writeln!(t, "{}", champ(l));
    }
    t
}

/// La partie « Vanguard » des traces : les données du compte qui a lancé Vanguard, même sous sudo (que le LISEZMOI
/// des traces conseille pour lire ce qui est réservé).
pub(super) fn partie(dossier: &Path) -> Partie {
    let (donnees, appelant) = crate::protection::temps_reel::dossier_local_appelant();
    partie_de(dossier, &donnees, appelant)
}

/// Un fichier d'état de Vanguard, lu sans suivre de lien et sans attendre sur un tube nommé, borné : `None` s'il
/// n'existe pas. Un programme du compte peut mettre n'importe quoi à sa place, et la collecte, juste après un
/// incident, peut tourner en administrateur.
fn lire_etat(chemin: &Path) -> Option<std::io::Result<Vec<u8>>> {
    use std::io::Read as _;
    std::fs::symlink_metadata(chemin).ok()?;
    Some(ouvrir_ordinaire(chemin, true).and_then(|f| {
        let mut o = Vec::new();
        f.take(BORNE_ETAT + 1).read_to_end(&mut o)?;
        if o.len() as u64 > BORNE_ETAT {
            return Err(std::io::Error::other(format!(
                "plus de {BORNE_ETAT} octets / over {BORNE_ETAT} bytes"
            )));
        }
        Ok(o)
    }))
}

/// Le texte d'un fichier d'état ; illisible ou étrange, c'est dit dans `autres`, et il compte pour vide.
fn texte_etat(donnees: &Path, nom: &str, autres: &mut Vec<String>) -> String {
    match lire_etat(&donnees.join(nom)) {
        None => String::new(),
        Some(Ok(o)) => String::from_utf8_lossy(&o).into_owned(),
        Some(Err(e)) => {
            autres.push(format!("{nom} : non lu / not read ({e})"));
            String::new()
        }
    }
}

fn partie_de(dossier: &Path, donnees: &Path, appelant: bool) -> Partie {
    let mut p = Partie::new(Bi::new("Vanguard", "Vanguard"));
    let mut autres = Vec::new();
    if appelant {
        autres.push(format!(
            "données lues / data read : {} (le compte qui a lancé Vanguard en administrateur / the account that ran Vanguard as administrator)",
            donnees.display()
        ));
    }
    // Les alertes du journal des événements, et celles de l'ancien journal qu'une version d'avant écrit encore.
    let (evenements, manques) = crate::modele::journal::lire_sans_juger(donnees);
    autres.extend(manques);
    let alertes = crate::reseau::tableau::reunir(
        crate::reseau::tableau::alertes_du_texte(&texte_etat(donnees, "surveillance-alertes.jsonl", &mut autres)),
        crate::reseau::tableau::alertes_des_evenements(&evenements),
    );
    autres.extend(
        evenements
            .iter()
            .filter(|e| {
                !matches!(
                    e.quoi,
                    Genre::Alerte { .. } | Genre::Action { .. } | Genre::Preuve { .. }
                )
            })
            .map(|e| {
                format!(
                    "evenement/event {} {} {}",
                    e.date_locale().unwrap_or_default(),
                    e.quoi.sorte(),
                    e.resume()
                )
            }),
    );
    let gestes = crate::changements::blocages_du_texte(&texte_etat(donnees, crate::changements::RELEVE, &mut autres));
    let mut faits = faits_des_alertes(&alertes);
    faits.extend(faits_des_gestes(&gestes));
    faits.sort_by(|a, b| a.date.cmp(&b.date));
    let quarantaine =
        crate::protection::quarantaine::pour_traces_dans(&donnees.join("quarantaine")).unwrap_or_else(|e| {
            autres.push(format!("quarantaine/quarantine : {e}"));
            Vec::new()
        });
    if appelant {
        // Les juger écrirait dans le dossier du compte en administrateur (sceaux.json, son verrou) : leurs fichiers
        // sont recopiés tels quels plus bas, sans être jugés.
        autres.push(
            "normales et sceaux / normal alerts and seals : non jugés en administrateur, recopiés tels quels / not judged as administrator, copied as they are"
                .to_string(),
        );
    } else {
        match crate::protection::normales::pour_traces() {
            Ok(n) => autres.extend(
                n.into_iter()
                    .map(|(cle, le, titre)| format!("normale/normal {le}  {titre}  [{cle}]")),
            ),
            Err(raison) => autres.push(format!("normales/normal : {raison}")),
        }
        let lu = crate::modele::journal::lire_dans(donnees);
        autres.push(format!(
            "journal des événements / event log : {}{}",
            lu.lecture.code(),
            match &lu.lecture {
                crate::modele::journal::Lecture::Incomplet(r) | crate::modele::journal::Lecture::Falsifie(r) =>
                    format!(" ({r})"),
                _ => String::new(),
            }
        ));
        // L'état de Vanguard changé hors de lui : à savoir avant de croire ce qui précède.
        autres.extend(
            crate::sceau::constat()
                .into_iter()
                .map(|c| format!("sceaux/seals : {}", c.message)),
        );
    }
    let n_fils = fils(&faits).len();
    if p.ecrire(
        dossier,
        NOM,
        &texte(&faits, &quarantaine, &autres),
        bi!(
            "ce que Vanguard a vu et fait : fils d'incident (l'alerte, la preuve relevée avant le geste et le geste, reliés par ce dont ils parlent), ses gestes (blocages, quarantaines) avec leur preuve (processus, ligne de commande, empreinte SHA-256, connexions), ses alertes, la quarantaine avec les empreintes, les alertes déclarées normales, l'état des sceaux ; les fichiers d'état de Vanguard sont recopiés tels quels dans les fichiers « 07-etat-… »",
            "what Vanguard saw and did: incident threads (the alert, the evidence recorded before the action and the action, linked by what they are about), its actions (blocks, quarantines) with their evidence (process, command line, SHA-256 fingerprint, connections), its alerts, the quarantine with fingerprints, alerts declared normal, the state of the seals; Vanguard's state files are copied as they are in the “07-etat-…” files"
        ),
    ) {
        p.compte = Some(bi!(
            "{} alertes, {} gestes, {n_fils} fils",
            "{} alerts, {} actions, {n_fils} threads",
            alertes.len(),
            gestes.len()
        ));
    }
    // La tête du journal, ses sceaux et ses segments, recopiés d'un même instant : pris entre deux étapes d'une
    // écriture, ils se reliraient falsifiés.
    let _journal = crate::modele::journal::tenir_pour_copie(donnees);
    for nom in ETATS {
        recopier(&mut p, dossier, donnees, nom);
    }
    for nom in crate::modele::journal::fichiers(donnees) {
        recopier(&mut p, dossier, donnees, &nom);
    }
    p.evenements = faits
        .iter()
        .filter_map(|f| {
            let genre = if f.geste {
                GenreChrono::GesteDeVanguard
            } else {
                GenreChrono::AlerteDeVanguard
            };
            let detail = f.lignes.first()?.split_once("  ").map_or("", |(_, r)| r).to_string();
            Some(Evenement::new(secondes(&f.date)?, Source::Vanguard, genre, detail))
        })
        .collect();
    p
}

/// Recopie un fichier d'état tel quel (« 07-etat-quarantaine-quarantaine.json ») ; absent, rien ; trop gros, un
/// lien, un tube ou illisible, c'est un manque (jamais suivi ni attendu).
fn recopier(p: &mut Partie, dossier: &Path, donnees: &Path, nom: &str) {
    use std::io::Write as _;
    let Some(lu) = lire_etat(&donnees.join(nom)) else {
        return;
    };
    let copie = format!("07-etat-{}", nom.replace('/', "-"));
    let ecrit = lu.and_then(|o| creer_fichier(&dossier.join(&copie))?.write_all(&o));
    p.noter(
        &copie,
        bi!(
            "{nom} de Vanguard, recopié tel quel",
            "Vanguard's {nom}, copied as it is"
        ),
        ecrit,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn objet_commun_aux_alertes_et_aux_gestes() {
        assert_eq!(objet("programme:4242:/tmp/x"), "/tmp/x");
        assert_eq!(objet("blocage|programme:/tmp/x"), "/tmp/x");
        assert_eq!(objet("veilleur|dossier temporaire|/tmp/x"), "/tmp/x");
        assert_eq!(objet("fichier:/tmp/x"), "/tmp/x");
        assert_eq!(objet("blocage|connexion:203.0.113.7"), "203.0.113.7");
        assert_eq!(
            objet("botnet|curl → 203.0.113.7:443 (Emotet, ThreatFox)"),
            "203.0.113.7"
        );
        assert_eq!(objet("appareil|00:1a:2b:3c:4d:5e"), "00:1a:2b:3c:4d:5e");
        // La connexion fermée par le veilleur et le blocage de la même adresse : un seul objet.
        assert_eq!(objet("veilleur|203.0.113.7:443"), "203.0.113.7");
        assert_eq!(objet("veilleur|[2001:db8::7]:443"), "2001:db8::7");
        // La clé normale d'un programme du blocage : sa raison et son script, le chemin en dernier.
        assert_eq!(
            objet("blocage|commande qui télécharge|/home/alice/outil.py|/usr/bin/python3"),
            "/usr/bin/python3"
        );
    }

    /// Un fil relie l'alerte de la nuit, le geste et sa preuve par l'objet dont ils parlent ; une alerte seule n'en
    /// fait pas un.
    #[test]
    fn un_fil_relie_alerte_et_geste() {
        let fait = |date: &str, cle: &str, geste: bool| Fait {
            date: date.into(),
            cle: cle.into(),
            geste,
            lignes: vec![format!("{date}  {cle}")],
        };
        let faits = vec![
            fait("2026-10-22 03:12:00", "programme:4242:/tmp/.x/mineur", true),
            fait("2026-10-22 03:11:58", "veilleur|outil offensif|/tmp/.x/mineur", false),
            fait("2026-10-22 04:00:00", "appareil|00:1a:2b:3c:4d:5e", false),
        ];
        let f = fils(&faits);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].0, "/tmp/.x/mineur");
        assert_eq!(f[0].1.len(), 2);
        assert!(!f[0].1[0].geste, "l'alerte d'abord, dans l'ordre du temps");
    }

    /// La partie écrit 07-vanguard.txt (alertes, gestes et leur preuve, fils), recopie les fichiers d'état tels
    /// quels, et met ses faits dans la chronologie.
    #[test]
    fn partie_des_traces() {
        let racine = std::env::temp_dir().join(format!("vanguard-traces-vanguard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&racine);
        let (dossier, donnees) = (racine.join("traces"), racine.join("donnees"));
        std::fs::create_dir_all(&dossier).unwrap();
        std::fs::create_dir_all(donnees.join("quarantaine")).unwrap();
        std::fs::write(donnees.join("quarantaine/quarantaine.json"), br#"{"fichiers":[]}"#).unwrap();
        let cle = format!("programme:4242:/tmp/essai-traces-{}", std::process::id());
        crate::changements::noter_blocage_dans(
            &donnees.join(crate::changements::RELEVE),
            vec!["kill 4242".into()],
            true,
            crate::changements::Blocage {
                id: crate::changements::nouvel_id(),
                cle: cle.clone(),
                quoi: "« essai » (PID 4242) : outil offensif".into(),
                automatique: true,
                annulation: None,
                annule: None,
                supprime: false,
                preuve: Some(crate::protection::preuve::Preuve {
                    date: "2026-10-22 03:12:00".into(),
                    impossible: vec![
                        "connexions : impossible (illisibles) / connections: not possible (unreadable)".into(),
                    ],
                    ..Default::default()
                }),
                evenement: None,
                origine: None,
            },
        );
        // L'alerte du même geste, dans le journal des événements : elle rejoint le fil, et le journal est recopié.
        crate::modele::journal::noter_dans(
            &donnees,
            crate::modele::evenement::Evenement::alerte(
                crate::modele::evenement::Source::Blocage,
                "blocage",
                "Vanguard a bloqué une menace",
                "outil offensif arrêté",
            )
            .cle(Some(&format!("blocage|{cle}"))),
            chrono::Utc::now(),
        )
        .unwrap();
        let p = partie_de(&dossier, &donnees, false);
        let t = std::fs::read_to_string(dossier.join(NOM)).unwrap();
        assert!(
            t.contains("« essai » (PID 4242)") && t.contains("connexions : impossible"),
            "{t}"
        );
        assert_eq!(
            std::fs::read(dossier.join("07-etat-quarantaine-quarantaine.json")).unwrap(),
            br#"{"fichiers":[]}"#
        );
        assert!(p.evenements.iter().any(|e| e.genre == GenreChrono::GesteDeVanguard));
        assert!(p.evenements.iter().any(|e| e.genre == GenreChrono::AlerteDeVanguard));
        assert!(t.contains("outil offensif arrêté"), "{t}");
        assert!(t.contains("journal des événements / event log : intact"), "{t}");
        let mois = chrono::Utc::now().format("%Y-%m").to_string();
        assert!(dossier.join(format!("07-etat-evenements-{mois}.jsonl")).exists());
        assert!(dossier.join("07-etat-evenements.tete").exists());
        let _ = std::fs::remove_dir_all(&racine);
    }
    /// Sous sudo, la partie lit les données du compte qui l'a lancé, et le dit ; un tube nommé ou un lien à la
    /// place d'un fichier d'état ne bloque pas la collecte et n'est pas suivi : c'est un manque.
    #[cfg(unix)]
    #[test]
    fn tube_ou_lien_a_la_place_d_un_etat() {
        let racine = std::env::temp_dir().join(format!("vanguard-traces-tube-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&racine);
        let (dossier, donnees) = (racine.join("traces"), racine.join("donnees"));
        std::fs::create_dir_all(&dossier).unwrap();
        std::fs::create_dir_all(&donnees).unwrap();
        let tube = std::ffi::CString::new(donnees.join("veilleur-etat.json").as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY : `tube` est une chaîne terminée par un zéro, vivante pendant l'appel ; mkfifo ne fait que la lire.
        assert_eq!(unsafe { libc::mkfifo(tube.as_ptr(), 0o600) }, 0);
        std::fs::write(racine.join("secret"), b"reserve").unwrap();
        std::os::unix::fs::symlink(racine.join("secret"), donnees.join("blocage.json")).unwrap();
        std::os::unix::fs::symlink(racine.join("secret"), donnees.join("surveillance-alertes.jsonl")).unwrap();
        let p = partie_de(&dossier, &donnees, true);
        let manquants: Vec<&str> = p.manques.iter().map(|m| m.quoi.fr.as_str()).collect();
        assert!(manquants.contains(&"07-etat-veilleur-etat.json"), "{manquants:?}");
        assert!(manquants.contains(&"07-etat-blocage.json"), "{manquants:?}");
        assert!(!dossier.join("07-etat-blocage.json").exists());
        let t = std::fs::read_to_string(dossier.join(NOM)).unwrap();
        assert!(t.contains("le compte qui a lancé Vanguard en administrateur"), "{t}");
        assert!(t.contains("surveillance-alertes.jsonl : non lu"), "{t}");
        let _ = std::fs::remove_dir_all(&racine);
    }
}

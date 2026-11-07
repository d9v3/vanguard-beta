//! Options de défense sous Linux : le pare-feu (ufw, firewalld, nftables), allumé ou coupé (plan §7, P8 élargi).
//!
//! Ici, sans droits, rien que des lectures : la configuration d'ufw (lisible par tous), l'état de systemd et la
//! présence de la note d'une coupure (`/var/lib/vanguard/avant/<id fixe du pare-feu>`, que root seul crée). Les règles
//! elles-mêmes (`ufw status`, `nft list`) demandent root : elles sont dites non vérifiées ici, et c'est l'enfant élevé
//! (`machine::defense_eleve::pare_feu`) qui les lit, juge, montre, avertit (SSH) et demande sur le terminal.
//!
//! Couper est une baisse : un seul geste par liste (`couper-pare-feu`), sa note d'« avant » écrite par root, notée
//! aussi dans « Ce que Vanguard a changé » (Défaire). Rallumer remet la note quand il y en a une, sinon allume le
//! pare-feu tel que sa configuration le décrit (renforcement, dit non annulable par l'enfant).

use std::path::Path;

use crate::machine::gestes_unix::{Defense, GesteUnix, PareFeu};
use crate::optimiser::{Geste, annulables};
use crate::selection::Ligne;
use crate::ui::{GRIS, RESET, VERT, afficher_aligne, ligne_titre};
use crate::{tr, trf, trp};

/// Où systemd range les unités, du plus prioritaire au moins prioritaire.
const DOSSIERS_UNITES: [&str; 5] = [
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
];

const UFW_CONF: &str = "/etc/ufw/ufw.conf";

/// L'état d'un pare-feu, tel qu'on peut le lire sans droits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EtatPf {
    Allume,
    Coupe,
    /// Lancé au démarrage mais arrêté, ou l'inverse.
    AMoitie,
    /// ufw : ENABLED=yes, son unité arrêtée. `ufw enable` charge ses règles sans lancer l'unité : il filtre
    /// peut-être (essai QEMU de D7c) ; seul `ufw status`, en root, le dit. Ni « allumé » ni « coupé ».
    AuDemarrage,
    /// Rien de sûr sans droits root (les règles de nftables, un état de systemd qui ne répond pas).
    NonVerifie,
}

impl EtatPf {
    fn mot(self) -> &'static str {
        match self {
            EtatPf::Allume => "allume",
            EtatPf::Coupe => "coupe",
            EtatPf::AMoitie => "a-moitie",
            EtatPf::AuDemarrage => "au-demarrage",
            EtatPf::NonVerifie => "non-verifie",
        }
    }
}

/// Ce qu'on mesure d'un pare-feu sans droits.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Mesures {
    /// /etc/ufw/ufw.conf, s'il se lit (ufw seulement).
    pub conf_ufw: Option<String>,
    /// Son unité de systemd existe.
    pub unite: bool,
    /// Lancé au démarrage (`None` : non lu).
    pub activee: Option<bool>,
    /// Tourne (`None` : non lu).
    pub active: Option<bool>,
    /// La note de sa coupure : `Some(Some(date))` présente (secondes depuis 1970), `Some(None)` absente, `None`
    /// illisible.
    #[allow(clippy::option_option)] // None : illisible ; Some(None) : absente
    pub note: Option<Option<u64>>,
}

/// Un pare-feu lu.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Lu {
    pub p: PareFeu,
    pub installe: bool,
    pub etat: EtatPf,
    #[allow(clippy::option_option)]
    pub note: Option<Option<u64>>,
    /// Ce que l'état ne dit pas seul (service de nftables, règles non lues).
    pub detail: Option<String>,
}

impl Lu {
    /// Coupé par le choix de la personne : la note de root est là.
    pub(crate) fn date_du_choix(&self) -> Option<u64> {
        self.note.flatten()
    }
}

/// La dernière ligne `ENABLED=` de ufw.conf, guillemets ôtés : `yes` ou `no`, rien d'autre.
pub(crate) fn ufw_enabled(conf: &str) -> Option<bool> {
    let v = conf
        .lines()
        .filter_map(|l| l.trim().strip_prefix("ENABLED="))
        .next_back()?
        .trim()
        .trim_matches(['"', '\'']);
    match v {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

/// Le jugement, pur : `m`, les mesures d'un pare-feu.
pub(crate) fn juger(p: PareFeu, m: &Mesures) -> Lu {
    let (installe, etat, detail) = match p {
        PareFeu::Ufw => {
            let installe = m.conf_ufw.is_some() || m.unite;
            let etat = match (m.conf_ufw.as_deref().and_then(ufw_enabled), m.active) {
                (Some(false), _) => EtatPf::Coupe,
                (Some(true), Some(true)) => EtatPf::Allume,
                (Some(true), Some(false)) => EtatPf::AuDemarrage,
                _ => EtatPf::NonVerifie,
            };
            (installe, etat, None)
        }
        PareFeu::Firewalld => {
            let etat = match (m.activee, m.active) {
                (Some(true), Some(true)) => EtatPf::Allume,
                (Some(false), Some(false)) => EtatPf::Coupe,
                (Some(_), Some(_)) => EtatPf::AMoitie,
                _ => EtatPf::NonVerifie,
            };
            (m.unite, etat, None)
        }
        // Ses règles ne se lisent qu'en root, et son service ne dit pas si des tables sont chargées.
        PareFeu::Nftables => {
            let service = match m.activee {
                Some(true) => tr!(
                    "son service se lance au démarrage ; règles lues seulement avec les droits root",
                    "its service starts at boot; rules read only with root rights"
                ),
                Some(false) => tr!(
                    "son service ne se lance pas au démarrage ; règles lues seulement avec les droits root",
                    "its service does not start at boot; rules read only with root rights"
                ),
                None => tr!(
                    "règles lues seulement avec les droits root",
                    "rules read only with root rights"
                ),
            };
            (m.unite, EtatPf::NonVerifie, Some(service.to_string()))
        }
    };
    Lu {
        p,
        installe,
        etat,
        note: m.note,
        detail,
    }
}

fn nom_unite(p: PareFeu) -> &'static str {
    match p {
        PareFeu::Ufw => "ufw.service",
        PareFeu::Firewalld => "firewalld.service",
        PareFeu::Nftables => "nftables.service",
    }
}

/// La note de la coupure de `p`, par un simple `stat` (le dossier des notes est en 0711 : son contenu ne se liste
/// pas, un nom connu se voit). Seule sa date sert ; son contenu, root seul le lit.
#[allow(clippy::option_option)]
fn note_de(p: PareFeu) -> Option<Option<u64>> {
    let chemin = Path::new(crate::machine::defense_eleve::DOSSIER_NOTES).join(p.note().as_str());
    match std::fs::symlink_metadata(&chemin) {
        Ok(m) => Some(Some(
            m.modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs()),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(None),
        Err(_) => None,
    }
}

fn mesurer(p: PareFeu) -> Mesures {
    let unite = nom_unite(p);
    let systemd = Path::new("/run/systemd/system").is_dir();
    Mesures {
        conf_ufw: (p == PareFeu::Ufw)
            .then(|| std::fs::read_to_string(UFW_CONF).ok())
            .flatten(),
        unite: DOSSIERS_UNITES
            .iter()
            .any(|d| std::fs::symlink_metadata(Path::new(d).join(unite)).is_ok()),
        activee: systemd
            .then(|| crate::machine::linux::natif::unite_activee(unite, false))
            .flatten(),
        active: systemd.then(|| crate::machine::linux::service_actif(unite)).flatten(),
        note: note_de(p),
    }
}

/// Les trois pare-feu, lus.
pub(crate) fn lire() -> Vec<Lu> {
    PareFeu::TOUS.iter().map(|&p| juger(p, &mesurer(p))).collect()
}

/// Les pare-feu coupés par le choix de la personne (leur note est là), pour le bilan (P9) : tous, car deux coupures
/// peuvent coexister (ufw coupé, puis firewalld installé et coupé à son tour).
pub(crate) fn coupes_par_choix() -> Vec<(PareFeu, u64)> {
    PareFeu::TOUS
        .iter()
        .filter_map(|&p| Some((p, note_de(p).flatten()?)))
        .collect()
}

/// La note de la coupure de `p` est-elle là ? `None` : illisible.
pub(crate) fn note_presente(p: PareFeu) -> Option<bool> {
    note_de(p).map(|n| n.is_some())
}

fn texte_etat(l: &Lu) -> String {
    if let Some(d) = l.date_du_choix() {
        return trf!(
            "coupé par votre choix le {}",
            "turned off by your choice on {}",
            crate::machine::choix_avant::date_note(d)
        );
    }
    match l.etat {
        EtatPf::Allume => tr!("allumé", "on").to_string(),
        EtatPf::Coupe => tr!("coupé", "off").to_string(),
        EtatPf::AMoitie => tr!(
            "à moitié (lancé au démarrage ou en marche, pas les deux)",
            "half (started at boot or running, not both)"
        )
        .to_string(),
        EtatPf::AuDemarrage => tr!(
            "lancé au démarrage ; en marche : lu seulement avec les droits root",
            "started at boot; running: read only with root rights"
        )
        .to_string(),
        EtatPf::NonVerifie => tr!("non vérifié", "not checked").to_string(),
    }
}

/// L'identifiant d'un pare-feu dans les commandes et le JSON : `pare-feu-ufw`, `pare-feu-firewalld`,
/// `pare-feu-nftables`.
pub(crate) fn id(p: PareFeu) -> String {
    format!("pare-feu-{}", p.mot())
}

pub(crate) fn de_l_id(texte: &str) -> Option<PareFeu> {
    PareFeu::depuis_mot(texte.strip_prefix("pare-feu-")?)
}

/// La commande « Rallumer » d'un pare-feu coupé par choix, proposée au bilan, jamais faite d'office.
pub(crate) fn commande_rallumer(p: PareFeu) -> String {
    format!("vanguard options-defense --rallumer {}", id(p))
}

/// Les lignes du rapport.
pub(crate) fn lignes(lus: &[Lu]) -> Vec<String> {
    let mut l = vec![trf!(
        "  {GRIS}Pare-feu de Linux{RESET}",
        "  {GRIS}Linux firewall{RESET}"
    )];
    let installes: Vec<&Lu> = lus
        .iter()
        .filter(|x| x.installe || x.date_du_choix().is_some())
        .collect();
    if installes.is_empty() {
        l.push(
            tr!(
                "  Aucun de ufw, firewalld ni nftables n'est installé.",
                "  None of ufw, firewalld or nftables is installed."
            )
            .to_string(),
        );
    }
    for x in installes {
        l.push(super::pointilles(x.p.mot(), &texte_etat(x), ""));
        if let Some(d) = &x.detail {
            l.push(format!("      {GRIS}{d}{RESET}"));
        }
        if x.note.is_none() {
            l.push(trf!(
                "      {GRIS}note de coupure illisible{RESET}",
                "      {GRIS}turn-off note unreadable{RESET}"
            ));
        }
    }
    l.push(String::new());
    l.push(
        tr!(
            "  Couper est une baisse : Vanguard, avec les droits root, relit les règles, montre ce qui change, avertit si une session SSH peut en dépendre, puis demande [o/N]. « Rallumer » remet l'état noté.",
            "  Turning off is lowering: Vanguard, with root rights, rereads the rules, shows what changes, warns if an SSH session may depend on them, then asks [y/N]. “Turn back on” puts back the noted state."
        )
        .to_string(),
    );
    l
}

/// Le JSON : des identifiants et des états, rien d'autre (ni règle, ni adresse, ni nom de table).
pub(crate) fn json(lus: &[Lu]) -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "systeme": "linux",
        "disponible": true,
        "lecture_seule": true,
        "pare_feu": lus.iter().map(|x| serde_json::json!({
            "id": id(x.p),
            "installe": x.installe,
            "etat": x.etat.mot(),
            "coupe_par_choix": x.note.map(|n| n.is_some()),
            "regles_lues": false,
        })).collect::<Vec<_>>(),
    })
}

/// Ce qu'on peut faire d'un pare-feu installé : couper (s'il n'est pas déjà coupé), rallumer (s'il n'est pas déjà
/// allumé sans note).
pub(crate) fn gestes_possibles(x: &Lu) -> (bool, bool) {
    if !x.installe {
        return (false, x.date_du_choix().is_some());
    }
    let par_choix = x.date_du_choix().is_some();
    let couper = !par_choix && x.etat != EtatPf::Coupe;
    let rallumer = par_choix || x.etat != EtatPf::Allume;
    (couper, rallumer)
}

/// Les touches du menu : « 1 » couper ufw, « 2 » rallumer ufw, « 3 » couper firewalld…
fn touche(p: PareFeu, rallumer: bool) -> String {
    let i = PareFeu::TOUS.iter().position(|x| *x == p).unwrap_or(0);
    i.saturating_mul(2)
        .saturating_add(usize::from(rallumer))
        .saturating_add(1)
        .to_string()
}

pub(crate) fn geste_de_touche(t: &str) -> Option<(PareFeu, bool)> {
    PareFeu::TOUS
        .iter()
        .flat_map(|&p| [(p, false), (p, true)])
        .find(|(p, r)| touche(*p, *r) == t)
}

pub(crate) fn menu(lus: &[Lu]) -> Vec<Ligne> {
    let mut l = vec![Ligne::Texte(String::new()), Ligne::Texte(ligne_titre(super::titre()))];
    l.extend(lignes(lus).into_iter().map(Ligne::Texte));
    l.push(Ligne::Texte(String::new()));
    for x in lus {
        let (couper, rallumer) = gestes_possibles(x);
        if couper {
            l.push(Ligne::choix(
                &touche(x.p, false),
                &trf!("Couper {}", "Turn off {}", x.p.mot()),
                tr!("baisse : question, note", "lowering: question, note"),
            ));
        }
        if rallumer {
            let precision = if x.date_du_choix().is_some() {
                tr!("remet l'état noté", "puts back the noted state")
            } else {
                tr!("selon sa configuration", "as configured")
            };
            l.push(Ligne::choix(
                &touche(x.p, true),
                &trf!("Rallumer {}", "Turn {} back on", x.p.mot()),
                precision,
            ));
        }
    }
    l
}

/// La ligne de la coupure de `p` : son identifiant de note est fixe, seul ce geste le prend.
pub(crate) fn ligne_couper(p: PareFeu) -> String {
    GesteUnix::Defense(Defense::CouperPareFeu(p), p.note()).ligne()
}

/// La ligne de « Rallumer » : la remise de la note quand elle est là, sinon l'allumage (sous un identifiant neuf).
pub(crate) fn ligne_rallumer(p: PareFeu, note: bool) -> Option<String> {
    if note {
        return Some(GesteUnix::Defense(Defense::Remettre, p.note()).ligne());
    }
    let id = crate::machine::defense::nouvel_id()?;
    Some(GesteUnix::Defense(Defense::RallumerPareFeu(p), id).ligne())
}

/// Coupe `p` : la ligne seule (liste pure), envoyée à l'enfant élevé, qui lit les règles, montre la baisse, avertit
/// et demande [o/N] sur le terminal, puis écrit la note d'« avant ». La note est aussi gardée dans « Ce que Vanguard a
/// changé » (Défaire), relevée et scellée avant : si elle ne peut pas être écrite, rien ne part. Si elle ne peut pas
/// être relevée (une note de root déjà là : coupé par votre choix, ou rallumé depuis hors de Vanguard ; ou le dossier
/// illisible), la ligne part sans elle : l'enfant juge sa propre note ; Défaire n'est alors pas noté une seconde fois,
/// « Rallumer » la remet.
pub(crate) fn couper(p: PareFeu) -> bool {
    let titre = trf!("Pare-feu {} coupé", "Firewall {} turned off", p.mot());
    let releve = annulables::relever(annulables::id_bilan(), &titre, &[Geste::defense(p.note())]);
    let id = match releve {
        Ok(r) => {
            if !annulables::noter(&[&r]) {
                trp!(
                    "  ✖ Valeurs d'avant non enregistrées : rien n'a été appliqué.",
                    "  ✖ Previous values not saved: nothing was applied."
                );
                return false;
            }
            Some(r.id)
        }
        Err(_) => None,
    };
    let ok = crate::machine::appliquer_annulables(&[vec![ligne_couper(p)]], std::slice::from_ref(&id))
        .first()
        .copied()
        .unwrap_or(false);
    if let Some(id) = id {
        annulables::apres_application(&[(id, ok)]);
    }
    ok
}

/// Rallume `p`. Avec la note de sa coupure : la remise de cette note, par « Défaire » quand les Options de défense
/// l'ont notée (la ligne de « Ce que Vanguard a changé » part avec elle), sinon par sa ligne seule. Sans note :
/// l'allumage, renforcement que l'enfant dit non annulable.
pub(crate) fn rallumer(p: PareFeu) -> bool {
    let Some(note) = note_presente(p) else {
        trp!(
            "  ✖ La note de la coupure ne se lit pas : rien n'est fait.",
            "  ✖ The turn-off note cannot be read: nothing is done."
        );
        return false;
    };
    if note {
        let ids = annulables::notes_du_geste(&Geste::defense(p.note()));
        if !ids.is_empty() {
            let (issues, _) = annulables::defaire(&ids, &[]);
            for (_, i) in &issues {
                annulables::dire_issue(i, "");
            }
            return issues.iter().any(|(_, i)| *i == annulables::Issue::Revenu);
        }
    }
    let Some(ligne) = ligne_rallumer(p, note) else {
        trp!(
            "  ✖ Le hasard du système manque : rien n'est fait.",
            "  ✖ The system's randomness is missing: nothing is done."
        );
        return false;
    };
    crate::machine::appliquer_annulables(&[vec![ligne]], &[None])
        .first()
        .copied()
        .unwrap_or(false)
}

/// `--choisir pare-feu-<outil> coupe|allume`, `--rallumer pare-feu-<outil>` : `None` si l'identifiant n'est pas un
/// pare-feu de Linux (la commande est alors refusée par l'appelant).
pub(crate) fn choisir(id_texte: &str, valeur: &str) -> Option<bool> {
    let p = de_l_id(id_texte)?;
    match valeur {
        "coupe" | "off" => Some(couper(p)),
        "allume" | "on" => Some(rallumer(p)),
        _ => None,
    }
}

pub(crate) fn aide() -> String {
    PareFeu::TOUS
        .iter()
        .map(|&p| format!("  {} : coupe, allume", id(p)))
        .collect::<Vec<_>>()
        .join("\n")
}

/// L'écran : l'état, puis Couper ou Rallumer, relu après chaque geste. Sortie qui n'est pas une console : le rapport,
/// sans rien demander.
pub(crate) fn ecran(console: bool) {
    if !console {
        crate::ui::titre(super::titre());
        for l in lignes(&lire()) {
            println!("{l}");
        }
        return;
    }
    loop {
        let lus = lire();
        let Some(t) = crate::selection::choisir(
            &menu(&lus),
            tr!("Votre choix", "Your choice"),
            "",
            tr!("Retour", "Back"),
        ) else {
            return;
        };
        let Some((p, rallume)) = geste_de_touche(&t) else {
            continue;
        };
        println!();
        let ok = if rallume { rallumer(p) } else { couper(p) };
        if ok {
            trp!("  {VERT}✔{RESET} Fait.", "  {VERT}✔{RESET} Done.");
        }
        afficher_aligne("  ", tr!("Entrée pour revenir.", "Enter to go back."), 2, GRIS);
        let _ = crate::ui::demander("");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(conf: Option<&str>, unite: bool, activee: Option<bool>, active: Option<bool>) -> Mesures {
        Mesures {
            conf_ufw: conf.map(str::to_string),
            unite,
            activee,
            active,
            note: Some(None),
        }
    }

    #[test]
    fn ufw_lu_de_sa_configuration() {
        assert_eq!(ufw_enabled("ENABLED=yes\n"), Some(true));
        assert_eq!(ufw_enabled("ENABLED=\"no\"\n"), Some(false));
        // La dernière ligne l'emporte, comme le lit ufw.
        assert_eq!(ufw_enabled("ENABLED=no\nENABLED=yes\n"), Some(true));
        assert_eq!(ufw_enabled("ENABLED=peut-être\n"), None);
        assert_eq!(ufw_enabled("# rien\n"), None);
        let j = |c, a| juger(PareFeu::Ufw, &m(c, true, None, a)).etat;
        assert_eq!(j(Some("ENABLED=yes"), Some(true)), EtatPf::Allume);
        assert_eq!(j(Some("ENABLED=no"), Some(true)), EtatPf::Coupe);
        // Unité arrêtée après un `ufw enable` : il filtre peut-être ; ni « à moitié », ni « allumé », ni « coupé ».
        assert_eq!(j(Some("ENABLED=yes"), Some(false)), EtatPf::AuDemarrage);
        // Non lu n'est jamais « allumé » ni « coupé ».
        assert_eq!(j(Some("ENABLED=yes"), None), EtatPf::NonVerifie);
        assert_eq!(j(None, Some(true)), EtatPf::NonVerifie);
        assert!(!juger(PareFeu::Ufw, &m(None, false, None, None)).installe);
    }

    #[test]
    fn firewalld_et_nftables() {
        let f = |e, a| juger(PareFeu::Firewalld, &m(None, true, e, a)).etat;
        assert_eq!(f(Some(true), Some(true)), EtatPf::Allume);
        assert_eq!(f(Some(false), Some(false)), EtatPf::Coupe);
        assert_eq!(f(Some(true), Some(false)), EtatPf::AMoitie);
        assert_eq!(f(None, Some(true)), EtatPf::NonVerifie);
        // nftables : ses règles ne se lisent pas sans droits, quel que soit son service.
        for e in [Some(true), Some(false), None] {
            let l = juger(PareFeu::Nftables, &m(None, true, e, Some(true)));
            assert_eq!(l.etat, EtatPf::NonVerifie);
            assert!(l.detail.is_some());
        }
    }

    #[test]
    fn gestes_selon_l_etat_et_la_note() {
        let mut l = juger(PareFeu::Ufw, &m(Some("ENABLED=yes"), true, None, Some(true)));
        assert_eq!(gestes_possibles(&l), (true, false));
        l.note = Some(Some(1_762_400_000));
        // Coupé par choix : seulement Rallumer, qui remet la note.
        assert_eq!(gestes_possibles(&l), (false, true));
        assert!(texte_etat(&l).contains("choix") || texte_etat(&l).contains("choice"));
        let coupe = juger(PareFeu::Firewalld, &m(None, true, Some(false), Some(false)));
        assert_eq!(gestes_possibles(&coupe), (false, true));
        let absent = juger(PareFeu::Firewalld, &m(None, false, None, None));
        assert_eq!(gestes_possibles(&absent), (false, false));
        let non_lu = juger(PareFeu::Nftables, &m(None, true, None, None));
        assert_eq!(gestes_possibles(&non_lu), (true, true));
    }

    /// La coupure part seule sous l'identifiant fixe du pare-feu ; Rallumer avec note = la remise de cette note ;
    /// sans note, l'allumage sous un identifiant neuf, jamais un identifiant fixe.
    #[test]
    fn lignes_des_gestes() {
        use crate::machine::gestes_unix::IdNote;
        for p in PareFeu::TOUS {
            let c = ligne_couper(p);
            assert_eq!(
                crate::machine::gestes_unix::analyser(&c),
                Some(GesteUnix::Defense(Defense::CouperPareFeu(p), p.note()))
            );
            assert_eq!(
                crate::machine::gestes_unix::analyser(&ligne_rallumer(p, true).unwrap()),
                Some(GesteUnix::Defense(Defense::Remettre, p.note()))
            );
            match crate::machine::gestes_unix::analyser(&ligne_rallumer(p, false).unwrap()) {
                Some(GesteUnix::Defense(Defense::RallumerPareFeu(q), id)) => {
                    assert_eq!(q, p);
                    assert!(PareFeu::de_la_note(id).is_none());
                    let _: IdNote = id;
                }
                autre => panic!("{autre:?}"),
            }
        }
    }

    #[test]
    fn identifiants_et_touches() {
        for p in PareFeu::TOUS {
            assert_eq!(de_l_id(&id(p)), Some(p));
            for r in [false, true] {
                assert_eq!(geste_de_touche(&touche(p, r)), Some((p, r)));
            }
        }
        assert_eq!(de_l_id("pare-feu-iptables"), None);
        assert_eq!(de_l_id("ufw"), None);
        assert_eq!(geste_de_touche("7"), None);
        // Une valeur inconnue ne fait rien (l'appelant refuse), sans rien lancer.
        assert_eq!(choisir("pare-feu-ufw", "peut-etre"), None);
        assert_eq!(choisir("pare-feu-domaine-actif", "coupe"), None);
    }

    /// Le JSON ne porte que des identifiants et des états.
    #[test]
    fn json_sans_regle() {
        let mut l = juger(PareFeu::Ufw, &m(Some("ENABLED=yes"), true, None, Some(true)));
        l.note = None;
        let v = json(&[l]);
        let pf = &v["pare_feu"][0];
        assert_eq!(pf["id"], "pare-feu-ufw");
        assert_eq!(pf["etat"], "allume");
        assert!(pf["coupe_par_choix"].is_null(), "illisible : ni oui ni non");
        assert_eq!(pf["regles_lues"], false);
    }

    /// Chaque ligne du menu tient dans 76 colonnes, sa précision dans 33 caractères.
    #[test]
    fn menu_tient_dans_l_ecran() {
        let lus: Vec<Lu> = PareFeu::TOUS
            .iter()
            .map(|&p| juger(p, &m(Some("ENABLED=yes"), true, Some(true), None)))
            .collect();
        for l in menu(&lus) {
            if let Ligne::Choix { texte, precision, .. } = l {
                assert!(precision.chars().count() <= 33, "{precision}");
                assert!(texte.chars().count() <= 40, "{texte}");
            }
        }
    }
}

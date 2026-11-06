//! Essais du lot D7c : le pare-feu de Linux (ufw, firewalld, nftables) coupé, remis, rallumé.

use std::cell::RefCell;
use std::rc::Rc;

use super::*;
use crate::machine::defense_eleve::pare_feu::{self, FICHIER_NFT, FIREWALLD, NFTABLES};
use crate::machine::gestes_unix::PareFeu;

/// Une table de nftables : famille, nom, corps (ses lignes, chacune finie par un saut de ligne).
type Table = (String, String, String);
type Tables = Rc<RefCell<Vec<Table>>>;

const UFW_CONF: &str = "/etc/ufw/ufw.conf";
const TCP_VIDE: &[u8] =
    b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
const TCP_SSH: &[u8] = b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0F02000A:0016 0202000A:D2F0 01 00000000:00000000 02:000A3F2B 00000000     0        0 31337 2 0000000000000000 20 4 30 10 -1\n";

/// ufw et nftables imités : l'état d'ufw, les tables (partagées avec le gestionnaire de services, dont
/// nftables.service les remplace), et les refus de `nft -c` ou de `nft -f`.
#[derive(Default)]
pub(super) struct FauxPareFeu {
    ufw_actif: bool,
    ufw_regles: Vec<String>,
    tables: Tables,
    nft_c_refuse: bool,
    /// `nft list tables` dit ceci au lieu des tables (une sortie forgée).
    liste_forgee: Option<String>,
}

fn table(f: &str, n: &str, corps: &str) -> Table {
    (f.into(), n.into(), corps.into())
}

/// Les lignes d'un script de nft appliquées aux tables, tout ou rien (comme une transaction de nft).
fn appliquer_script(tables: &[Table], script: &str) -> Option<Vec<Table>> {
    let mut t = tables.to_vec();
    let mut lignes = script.lines();
    while let Some(l) = lignes.next() {
        let mots: Vec<&str> = l.split(' ').collect();
        match mots.as_slice() {
            [] | [""] => {}
            ["add", "table", f, n] => {
                if !t.iter().any(|x| x.0 == *f && x.1 == *n) {
                    t.push(table(f, n, ""));
                }
            }
            ["delete", "table", f, n] => {
                let i = t.iter().position(|x| x.0 == *f && x.1 == *n)?;
                t.remove(i);
            }
            ["table", f, n, "{"] => {
                let mut corps = String::new();
                loop {
                    let c = lignes.next()?;
                    if c == "}" {
                        break;
                    }
                    corps.push_str(c);
                    corps.push('\n');
                }
                t.retain(|x| !(x.0 == *f && x.1 == *n));
                t.push(table(f, n, &corps));
            }
            _ => return None,
        }
    }
    Some(t)
}

fn sortie(code: i32, sortie: impl Into<String>) -> Sortie {
    Sortie {
        code: Some(code),
        sortie: sortie.into(),
        erreurs: if code == 0 { String::new() } else { "refusé\n".into() },
    }
}

/// ufw et nft imités ; `None` : un autre outil.
pub(super) fn imiter(f: &mut Faux, outil: &str, a: &[String]) -> Option<Sortie> {
    let a: Vec<&str> = a.iter().map(String::as_str).collect();
    let r = match (outil, a.as_slice()) {
        ("ufw", ["status"]) => sortie(
            0,
            if f.pf.ufw_actif {
                "Status: active\n\nTo                         Action      From\n"
            } else {
                "Status: inactive\n"
            },
        ),
        ("ufw", ["disable"]) => {
            f.pf.ufw_actif = false;
            f.poser(UFW_CONF, b"# /etc/ufw/ufw.conf\nENABLED=no\nLOGLEVEL=low\n", 0o644);
            sortie(0, "Firewall stopped and disabled on system startup\n")
        }
        ("ufw", ["--force", "enable"]) => {
            f.pf.ufw_actif = true;
            f.poser(UFW_CONF, b"# /etc/ufw/ufw.conf\nENABLED=yes\nLOGLEVEL=low\n", 0o644);
            sortie(0, "Firewall is active and enabled on system startup\n")
        }
        ("ufw", ["show", "added"]) => {
            let mut t = "Added user rules (see 'ufw status' for running firewall):\n".to_string();
            for r in &f.pf.ufw_regles {
                t.push_str(r);
                t.push('\n');
            }
            sortie(0, t)
        }
        ("nft", ["list", "tables"]) => {
            let t = f.pf.liste_forgee.clone().unwrap_or_else(|| {
                f.pf.tables.borrow().iter().fold(String::new(), |mut s, (fa, n, _)| {
                    let _ = writeln!(s, "table {fa} {n}");
                    s
                })
            });
            sortie(0, t)
        }
        ("nft", ["-s", "list", "table", fa, n]) => {
            let t = f.pf.tables.borrow().iter().find(|x| x.0 == *fa && x.1 == *n).cloned();
            match t {
                Some((fa, n, corps)) => sortie(0, format!("table {fa} {n} {{\n{corps}}}\n")),
                None => sortie(1, ""),
            }
        }
        ("nft", ["-c", "-f", p] | ["-f", p]) => {
            let Some(contenu) = f.fichiers.get(Path::new(p)).map(|x| x.contenu.clone()) else {
                return Some(sortie(1, ""));
            };
            let verifier = a[0] == "-c";
            let neuves = appliquer_script(&f.pf.tables.borrow(), &String::from_utf8_lossy(&contenu));
            match neuves {
                _ if verifier && f.pf.nft_c_refuse => sortie(1, ""),
                None => sortie(1, ""),
                Some(_) if verifier => sortie(0, ""),
                Some(t) => {
                    *f.pf.tables.borrow_mut() = t;
                    sortie(0, "")
                }
            }
        }
        ("ufw" | "nft", _) => sortie(2, ""),
        _ => return None,
    };
    Some(r)
}

/// Un gestionnaire de services avec un état par unité (absente : pas installée) ; nftables.service, démarré, vide
/// toutes les tables puis charge `conf_nft` (comme `flush ruleset` en tête de /etc/nftables.conf) ; arrêté, les vide.
struct ServicesPf {
    unites: BTreeMap<&'static str, (String, String)>,
    lignee: Vec<String>,
    sessions: Option<Vec<SessionVue>>,
    faits: Vec<String>,
    tables: Tables,
    conf_nft: Vec<Table>,
    /// Cette action (son mot) échoue, sans rien changer.
    echoue: Option<&'static str>,
}

impl ServicesPf {
    fn nouveau(tables: &Tables) -> Self {
        ServicesPf {
            unites: BTreeMap::new(),
            lignee: vec!["/user.slice/user-1000.slice/session-2.scope".into()],
            sessions: Some(Vec::new()),
            faits: Vec::new(),
            tables: Rc::clone(tables),
            conf_nft: Vec::new(),
            echoue: None,
        }
    }

    fn avec(mut self, u: &'static str, etat: &str, activite: &str) -> Self {
        self.unites.insert(u, (etat.into(), activite.into()));
        self
    }

    fn etat(&self, u: &str) -> (&str, &str) {
        let e = &self.unites[u];
        (e.0.as_str(), e.1.as_str())
    }
}

impl Services for ServicesPf {
    fn systemd(&self) -> bool {
        true
    }
    fn fichier_sur(&self, u: &str) -> Result<bool, Echec> {
        Ok(self.unites.contains_key(u))
    }
    fn arret_charge(&mut self, _: &str) -> Result<Option<ArretCharge>, Echec> {
        Ok(None)
    }
    fn etat_du_fichier(&mut self, u: &str) -> Result<Option<String>, Echec> {
        Ok(self.unites.get(u).map(|e| e.0.clone()))
    }
    fn etat_d_activite(&mut self, u: &str) -> Result<Option<String>, Echec> {
        Ok(Some(self.unites.get(u).map_or("inactive".into(), |e| e.1.clone())))
    }
    fn condition_refusee(&mut self, _: &str) -> Result<bool, Echec> {
        Ok(false)
    }
    fn unite(&mut self, action: ActionUnite, u: &str) -> Result<(), Echec> {
        self.faits.push(format!("{} {u}", action.mot()));
        if self.echoue == Some(action.mot()) {
            return Err(echoue("refusé"));
        }
        let e = self.unites.get_mut(u).ok_or_else(|| echoue("absente"))?;
        let (etat, activite) = match action {
            ActionUnite::Activer => ("enabled", "active"),
            ActionUnite::Desactiver => ("disabled", "inactive"),
            ActionUnite::Arreter => (e.0.as_str(), "inactive"),
            ActionUnite::DesactiverSansArreter => ("disabled", e.1.as_str()),
            ActionUnite::ActiverSansDemarrer => ("enabled", e.1.as_str()),
            ActionUnite::Demarrer | ActionUnite::Redemarrer => (e.0.as_str(), "active"),
            ActionUnite::Recharger => (e.0.as_str(), e.1.as_str()),
        };
        *e = (etat.to_string(), activite.to_string());
        if u == NFTABLES {
            match action {
                ActionUnite::Activer | ActionUnite::Demarrer | ActionUnite::Redemarrer => {
                    *self.tables.borrow_mut() = self.conf_nft.clone();
                }
                ActionUnite::Desactiver | ActionUnite::Arreter => self.tables.borrow_mut().clear(),
                _ => {}
            }
        }
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

/// Un ordinateur sans session SSH : /proc/net/tcp et tcp6 lisibles, sans connexion sur le port 22.
fn faux() -> Faux {
    let mut a = Faux::nouveau();
    a.outils.push("nft");
    a.poser("/proc/net/tcp", TCP_VIDE, 0o444);
    a.poser("/proc/net/tcp6", TCP_VIDE, 0o444);
    a
}

fn faux_ufw(enabled: bool, actif: bool) -> Faux {
    let mut a = faux();
    a.outils.push("ufw");
    let conf = format!(
        "# /etc/ufw/ufw.conf\nENABLED={}\nLOGLEVEL=low\n",
        if enabled { "yes" } else { "no" }
    );
    a.poser(UFW_CONF, conf.as_bytes(), 0o644);
    a.pf.ufw_actif = actif;
    a
}

const FILTRE: &str = "\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\tct state established,related accept\n\t\ttcp dport 22 accept\n\t}\n";
const BLOCAGE: &str = "\tset bloques4 {\n\t\ttype ipv4_addr\n\t\telements = { 203.0.113.9 }\n\t}\n";

/// Un ordinateur à nftables : la table de la personne, et le blocage de Vanguard.
fn faux_nft() -> (Faux, ServicesPf) {
    let a = faux();
    *a.pf.tables.borrow_mut() = vec![table("inet", "filter", FILTRE), table("inet", "vanguard", BLOCAGE)];
    let mut s = ServicesPf::nouveau(&a.pf.tables).avec(NFTABLES, "enabled", "active");
    s.conf_nft = vec![table("inet", "filter", FILTRE)];
    (a, s)
}

fn couper(p: PareFeu, a: &mut Faux, s: &mut ServicesPf) -> Resultat {
    faire(Defense::CouperPareFeu(p), p.note(), a, s)
}

fn remettre_pf(p: PareFeu, a: &mut Faux, s: &mut ServicesPf) -> Resultat {
    faire(Defense::Remettre, p.note(), a, s)
}

fn rallumer(p: PareFeu, a: &mut Faux, s: &mut ServicesPf) -> Resultat {
    faire(Defense::RallumerPareFeu(p), id(), a, s)
}

/// Rien de changé : ni note, ni outil qui change, ni service touché, ni fichier de règles laissé.
fn rien_change(a: &Faux, s: &ServicesPf, tables: &[Table]) {
    assert!(a.notes.is_empty(), "note écrite");
    assert!(
        !a.journal.iter().any(|l| l == "ufw disable"
            || l.starts_with("ufw --force")
            || l.starts_with("nft -f")
            || l.starts_with("ecrire")),
        "{:?}",
        a.journal
    );
    assert!(s.faits.is_empty(), "{:?}", s.faits);
    assert_eq!(*a.pf.tables.borrow(), tables);
    assert!(!a.fichiers.contains_key(Path::new(FICHIER_NFT)));
}

#[test]
fn ufw_couper_question_de_baisse_puis_defaire() {
    let mut a = faux_ufw(true, true).repondre("o");
    let mut s = ServicesPf::nouveau(&a.pf.tables);
    let r = couper(PareFeu::Ufw, &mut a, &mut s);
    assert!(r.reussi, "{}", r.raison);
    assert!(a.journal.contains(&"ufw disable".to_string()), "{:?}", a.journal);
    assert!(!a.pf.ufw_actif);
    assert!(a.notes.contains_key(PareFeu::Ufw.note().as_str()));
    let q = &a.questions[0];
    assert!(q.contains("allumé → COUPÉ"), "{q}");
    assert!(q.contains("MOINS protégé"), "{q}");
    assert!(q.contains("Si ce n'est pas vous, répondez N"), "{q}");
    assert!(q.contains("[o/N] (Entrée seule : non)"), "{q}");
    // Couper ufw retire des refus : aucune session ne peut s'en trouver coupée.
    assert!(!q.contains("AVERTISSEMENT"), "{q}");
    assert!(r.note.unwrap().contains("Défaire le remet comme avant"));
    let mut a = a.repondre("o");
    let r = remettre_pf(PareFeu::Ufw, &mut a, &mut s);
    assert!(r.reussi, "{}", r.raison);
    assert!(a.pf.ufw_actif);
    assert!(a.texte(UFW_CONF).contains("ENABLED=yes"));
    assert!(a.notes.is_empty(), "{:?}", a.notes);
}

/// Chaque question de ce lot : Entrée seule, « non », ou aucun terminal, et rien n'est changé.
#[test]
fn chaque_question_entree_dit_non() {
    for reponse in [Some(""), Some("n"), Some("non"), None] {
        let prendre = |a: Faux| match reponse {
            Some(r) => a.repondre(r),
            None => a,
        };
        let mut a = prendre(faux_ufw(true, true));
        let mut s = ServicesPf::nouveau(&a.pf.tables);
        assert!(!couper(PareFeu::Ufw, &mut a, &mut s).reussi);
        rien_change(&a, &s, &[]);
        assert!(a.pf.ufw_actif);

        let mut a = prendre(faux_ufw(false, false));
        let mut s = ServicesPf::nouveau(&a.pf.tables);
        assert!(!rallumer(PareFeu::Ufw, &mut a, &mut s).reussi);
        rien_change(&a, &s, &[]);

        let mut a = prendre(faux());
        let mut s = ServicesPf::nouveau(&a.pf.tables).avec(FIREWALLD, "enabled", "active");
        assert!(!couper(PareFeu::Firewalld, &mut a, &mut s).reussi);
        rien_change(&a, &s, &[]);
        let mut s = ServicesPf::nouveau(&a.pf.tables).avec(FIREWALLD, "disabled", "inactive");
        assert!(!rallumer(PareFeu::Firewalld, &mut a, &mut s).reussi);
        rien_change(&a, &s, &[]);

        let (a, mut s) = faux_nft();
        let mut a = prendre(a);
        let avant = a.pf.tables.borrow().clone();
        assert!(!couper(PareFeu::Nftables, &mut a, &mut s).reussi);
        rien_change(&a, &s, &avant);
    }
}

#[test]
fn ufw_a_moitie_allume_ou_illisible_refuse() {
    for (enabled, actif) in [(true, false), (false, true)] {
        let mut a = faux_ufw(enabled, actif).repondre("o");
        let mut s = ServicesPf::nouveau(&a.pf.tables);
        let r = couper(PareFeu::Ufw, &mut a, &mut s);
        assert!(!r.reussi);
        assert!(r.raison.contains("à moitié"), "{}", r.raison);
        assert!(a.questions.is_empty(), "{:?}", a.questions);
    }
    for conf in [
        &b"ENABLED=peut-etre\n"[..],
        b"LOGLEVEL=low\n",
        b"ENABLED=\"yes\nENABLED=autre\n",
    ] {
        let mut a = faux_ufw(true, true).repondre("o");
        a.poser(UFW_CONF, conf, 0o644);
        let mut s = ServicesPf::nouveau(&a.pf.tables);
        let r = couper(PareFeu::Ufw, &mut a, &mut s);
        assert!(!r.reussi);
        assert!(r.raison.contains("ne se lit pas"), "{}", r.raison);
        rien_change(&a, &s, &[]);
    }
    // Un état qui ne se reconnaît pas (« Status: » suivi d'autre chose) : refusé, jamais pris pour « coupé ».
    assert_eq!(pare_feu::ufw_statut("Status: active (forged)\n"), None);
    assert_eq!(pare_feu::ufw_statut("Statut: inactive\n"), None);
    assert_eq!(pare_feu::ufw_enabled("ENABLED='no'\n"), Some(false));
    assert_eq!(pare_feu::ufw_enabled("# ENABLED=yes\nENABLED=no\n"), Some(false));
}

#[test]
fn firewalld_couper_puis_defaire_remet_l_etat_d_avant() {
    for (etat, activite, remise) in [
        ("enabled", "active", "activer"),
        ("enabled", "inactive", "activer-sans-demarrer"),
        ("disabled", "active", "demarrer"),
    ] {
        let mut a = faux().repondre("o");
        let mut s = ServicesPf::nouveau(&a.pf.tables).avec(FIREWALLD, etat, activite);
        let r = couper(PareFeu::Firewalld, &mut a, &mut s);
        assert!(r.reussi, "{}", r.raison);
        assert_eq!(s.faits, ["desactiver firewalld.service"]);
        assert!(a.questions[0].contains("MOINS protégé"));
        let mut a = a.repondre("o");
        let r = remettre_pf(PareFeu::Firewalld, &mut a, &mut s);
        assert!(r.reussi, "{}", r.raison);
        assert_eq!(s.faits[1], format!("{remise} firewalld.service"));
        assert_eq!(s.etat(FIREWALLD).0 == "enabled", etat == "enabled");
        assert_eq!(s.etat(FIREWALLD).1 == "active", activite == "active");
        assert!(a.notes.is_empty(), "{:?}", a.notes);
    }
    // Déjà coupé : rien à faire, pas de question.
    let mut a = faux();
    let mut s = ServicesPf::nouveau(&a.pf.tables).avec(FIREWALLD, "disabled", "inactive");
    let r = couper(PareFeu::Firewalld, &mut a, &mut s);
    assert!(r.reussi && a.questions.is_empty() && a.notes.is_empty());
}

#[test]
fn rallumer_sans_note_est_non_annulable() {
    let mut a = faux().repondre("o");
    let mut s = ServicesPf::nouveau(&a.pf.tables).avec(FIREWALLD, "disabled", "inactive");
    let r = rallumer(PareFeu::Firewalld, &mut a, &mut s);
    assert!(r.reussi, "{}", r.raison);
    assert_eq!(s.faits, ["activer firewalld.service"]);
    assert!(a.questions[0].contains("non annulable"), "{}", a.questions[0]);
    assert!(a.questions[0].contains("ne le recoupera pas"), "{}", a.questions[0]);
    // Un renforcement : aucune note de coupure (le bilan ne le dit pas « coupé par votre choix ») ; Défaire le refuse.
    assert!(
        PareFeu::TOUS.iter().all(|p| !a.notes.contains_key(p.note().as_str())),
        "{:?}",
        a.notes
    );
    // Ni aucune autre : la note vide du geste, qui ne servirait à rien, est retirée (relecture de D7c, B1).
    assert!(a.notes.is_empty(), "{:?}", a.notes);
    // Défaire n'a donc rien à remettre : rien n'est fait (le pare-feu n'est pas recoupé).
    let mut a = a.repondre("o");
    let d = faire(Defense::Remettre, id(), &mut a, &mut s);
    assert!(
        d.note.as_deref().is_some_and(|n| n.contains("rien à remettre")),
        "{:?}",
        d.note
    );
    assert_eq!(a.questions.len(), 1, "{:?}", a.questions);
    assert_eq!(s.faits.len(), 1, "{:?}", s.faits);
    assert!(!r.note.unwrap().contains("Défaire"));

    // Masqué : Vanguard ne le démasque pas.
    let mut a = faux().repondre("o");
    let mut s = ServicesPf::nouveau(&a.pf.tables).avec(FIREWALLD, "masked", "inactive");
    assert!(!rallumer(PareFeu::Firewalld, &mut a, &mut s).reussi);
    assert!(s.faits.is_empty(), "{:?}", s.faits);
}

#[test]
fn rallumer_passe_par_la_note_d_une_coupure() {
    let mut a = faux_ufw(true, true).repondre("o");
    let mut s = ServicesPf::nouveau(&a.pf.tables);
    assert!(couper(PareFeu::Ufw, &mut a, &mut s).reussi);
    let mut a = a.repondre("o");
    let r = rallumer(PareFeu::Ufw, &mut a, &mut s);
    assert!(!r.reussi);
    assert!(r.raison.contains("passe par cette note"), "{}", r.raison);
    assert!(!a.pf.ufw_actif);
    assert_eq!(a.notes.len(), 1);
}

#[test]
fn deux_pare_feu_a_la_fois_refuses() {
    // Rallumer ufw quand firewalld tourne, ou l'inverse : refusé avant la question.
    let mut a = faux_ufw(false, false).repondre("o");
    let mut s = ServicesPf::nouveau(&a.pf.tables).avec(FIREWALLD, "enabled", "active");
    let r = rallumer(PareFeu::Ufw, &mut a, &mut s);
    assert!(!r.reussi && r.raison.contains("deux pare-feu"), "{}", r.raison);
    assert!(a.questions.is_empty(), "{:?}", a.questions);
    let mut a = faux_ufw(true, true).repondre("o");
    let mut s = ServicesPf::nouveau(&a.pf.tables).avec(FIREWALLD, "disabled", "inactive");
    let r = rallumer(PareFeu::Firewalld, &mut a, &mut s);
    assert!(!r.reussi && r.raison.contains("deux pare-feu"), "{}", r.raison);
    // nftables quand ufw ou firewalld tiennent les règles : refusé.
    for avec_ufw in [true, false] {
        let (a, s) = faux_nft();
        let mut a = a.repondre("o");
        let mut s = if avec_ufw {
            a.outils.push("ufw");
            a.poser(UFW_CONF, b"ENABLED=yes\n", 0o644);
            a.pf.ufw_actif = true;
            s
        } else {
            s.avec(FIREWALLD, "enabled", "active")
        };
        let avant = a.pf.tables.borrow().clone();
        let r = couper(PareFeu::Nftables, &mut a, &mut s);
        assert!(!r.reussi && r.raison.contains("deux pare-feu"), "{}", r.raison);
        rien_change(&a, &s, &avant);
    }
    let (a, mut s) = faux_nft();
    let mut a = a.repondre("o");
    a.pf.tables.borrow_mut().push(table("inet", "firewalld", ""));
    let r = couper(PareFeu::Nftables, &mut a, &mut s);
    assert!(!r.reussi && r.raison.contains("firewalld"), "{}", r.raison);
}

#[test]
fn nftables_couper_garde_vanguard_puis_defaire() {
    let (a, mut s) = faux_nft();
    let mut a = a.repondre("o");
    let r = couper(PareFeu::Nftables, &mut a, &mut s);
    assert!(r.reussi, "{}", r.raison);
    // La table de la personne part, celle de Vanguard reste ; le service n'est plus lancé au démarrage, sans être
    // arrêté (son arrêt viderait aussi le blocage).
    assert_eq!(*a.pf.tables.borrow(), [table("inet", "vanguard", BLOCAGE)]);
    assert_eq!(s.faits, ["desactiver-sans-arreter nftables.service"]);
    assert_eq!(s.etat(NFTABLES), ("disabled", "active"));
    // La sauvegarde vérifiée par nft -c avant tout retrait, le fichier de passage retiré.
    let c = a
        .journal
        .iter()
        .position(|l| l == &format!("nft -c -f {FICHIER_NFT}"))
        .unwrap();
    let f = a
        .journal
        .iter()
        .position(|l| l == &format!("nft -f {FICHIER_NFT}"))
        .unwrap();
    assert!(c < f, "{:?}", a.journal);
    assert!(!a.fichiers.contains_key(Path::new(FICHIER_NFT)));
    assert!(!a.journal.iter().any(|l| l.contains("flush")), "{:?}", a.journal);
    let q = &a.questions[0];
    assert!(q.contains("inet filter") && q.contains("MOINS protégé"), "{q}");
    assert!(!q.contains("inet vanguard"), "{q}");
    // Défaire : la table remise telle quelle, le service de nouveau lancé au démarrage.
    let mut a = a.repondre("o");
    let r = remettre_pf(PareFeu::Nftables, &mut a, &mut s);
    assert!(r.reussi, "{}", r.raison);
    let t = a.pf.tables.borrow().clone();
    assert!(t.contains(&table("inet", "filter", FILTRE)), "{t:?}");
    assert!(t.contains(&table("inet", "vanguard", BLOCAGE)), "{t:?}");
    assert_eq!(t.len(), 2);
    assert_eq!(s.etat(NFTABLES).0, "enabled");
    assert!(a.notes.is_empty(), "{:?}", a.notes);
    assert!(!a.fichiers.contains_key(Path::new(FICHIER_NFT)));
}

#[test]
fn nftables_suite_interrompue_note_gardee_puis_defaire() {
    // Les tables retirées, puis le service refuse d'être désactivé : la note d'avant reste, et Défaire remet les
    // tables (relecture de D7c, essai n° 2).
    let (a, mut s) = faux_nft();
    let mut a = a.repondre("o");
    s.echoue = Some(ActionUnite::DesactiverSansArreter.mot());
    let r = couper(PareFeu::Nftables, &mut a, &mut s);
    assert!(!r.reussi, "{}", r.raison);
    assert_eq!(*a.pf.tables.borrow(), [table("inet", "vanguard", BLOCAGE)]);
    assert_eq!(s.etat(NFTABLES), ("enabled", "active"));
    assert!(a.notes.contains_key(PareFeu::Nftables.note().as_str()), "{:?}", a.notes);
    s.echoue = None;
    let mut a = a.repondre("o");
    let r = remettre_pf(PareFeu::Nftables, &mut a, &mut s);
    assert!(r.reussi, "{}", r.raison);
    let t = a.pf.tables.borrow().clone();
    assert!(t.contains(&table("inet", "filter", FILTRE)) && t.len() == 2, "{t:?}");
    assert_eq!(s.etat(NFTABLES), ("enabled", "active"));
    assert!(a.notes.is_empty(), "{:?}", a.notes);
}

#[test]
fn nftables_sauvegarde_refusee_par_nft_c_rien_coupe() {
    let (a, mut s) = faux_nft();
    let mut a = a.repondre("o");
    a.pf.nft_c_refuse = true;
    let avant = a.pf.tables.borrow().clone();
    let r = couper(PareFeu::Nftables, &mut a, &mut s);
    assert!(!r.reussi);
    assert!(r.raison.contains("ne se reliraient pas"), "{}", r.raison);
    assert_eq!(*a.pf.tables.borrow(), avant);
    assert!(s.faits.is_empty(), "{:?}", s.faits);
    assert!(!a.journal.iter().any(|l| l.starts_with("nft -f")), "{:?}", a.journal);
    assert!(!a.fichiers.contains_key(Path::new(FICHIER_NFT)));
    // Rien n'a changé : la note ne reste pas.
    assert!(a.notes.is_empty(), "{:?}", a.notes);
}

#[test]
fn nftables_tables_tenues_par_un_programme_refusees() {
    for corps in [
        "\tflags owner\n\tchain c {\n\t}\n",
        "\tflags owner,persist\n",
        "\tcomment \"x\"\n\tflags persist\n",
        "# Warning: table ip filter is managed by iptables-nft, do not touch!\n\tchain INPUT {\n\t}\n",
    ] {
        let (a, mut s) = faux_nft();
        let mut a = a.repondre("o");
        a.pf.tables.borrow_mut().push(table("ip", "filter", corps));
        let avant = a.pf.tables.borrow().clone();
        let r = couper(PareFeu::Nftables, &mut a, &mut s);
        assert!(!r.reussi, "{corps}");
        rien_change(&a, &s, &avant);
    }
}

#[test]
fn nftables_table_d_iptables_nommee_meme_avertissement_en_tete() {
    // nft écrit son avertissement avant la ligne `table` : le refus dit iptables, pas « une forme » (relecture, B6).
    let r = sortie(
        0,
        "# Warning: table ip filter is managed by iptables-nft, do not touch!\ntable ip filter {\n\tchain INPUT {\n\t}\n}\n",
    );
    let e = pare_feu::juger_table("ip", "filter", &r).unwrap_err();
    assert!(format!("{e:?}").contains("celle d'iptables"), "{e:?}");
    // Une ligne « # » en tête sans iptables ne change pas le jugement de la table qui suit.
    let r = sortie(0, "# note\ntable inet filter {\n\tchain input {\n\t}\n}\n");
    assert!(pare_feu::juger_table("inet", "filter", &r).is_ok());
    let r = sortie(0, "# note\ntable inet autre {\n}\n");
    assert!(pare_feu::juger_table("inet", "filter", &r).is_err());
}

#[test]
fn nftables_nat_dit_dans_la_question() {
    let (a, mut s) = faux_nft();
    let mut a = a.repondre("");
    a.pf.tables.borrow_mut().push(table(
        "ip",
        "partage",
        "\tchain post {\n\t\toifname \"eth0\" masquerade\n\t}\n",
    ));
    assert!(!couper(PareFeu::Nftables, &mut a, &mut s).reussi);
    assert!(a.questions[0].contains("NAT"), "{}", a.questions[0]);
}

#[test]
fn nftables_liste_forgee_ou_nom_hostile_refuse() {
    for forgee in [
        "table inet filtre\x1b[31m\n",
        "table inet a\rb\n",
        "table inet  filter\n",
        "table inet filter extra\n",
        "table inet 9chiffre\n",
        "table inet -tiret\n",
        "table autre filter\n",
        "tables inet filter\n",
        "table inet filter;delete\n",
        &format!("table inet {}\n", "n".repeat(5000)),
    ] {
        let (a, mut s) = faux_nft();
        let mut a = a.repondre("o");
        a.pf.liste_forgee = Some(forgee.to_string());
        let avant = a.pf.tables.borrow().clone();
        let r = couper(PareFeu::Nftables, &mut a, &mut s);
        assert!(!r.reussi, "{forgee:?}");
        assert!(a.questions.is_empty(), "{forgee:?}");
        rien_change(&a, &s, &avant);
    }
    assert!(pare_feu::tables_de("table inet filter\ntable ip6 nat-6.v2\n").is_some());
    assert!(!pare_feu::nom_de_table(""));
    assert!(!pare_feu::nom_de_table(".cache"));
}

#[test]
fn nftables_rallumer_refuse_si_le_blocage_de_vanguard_est_la() {
    let (a, mut s) = faux_nft();
    let mut a = a.repondre("o");
    // Ses tables parties hors de Vanguard, le service n'est plus lancé : seul le blocage reste.
    a.pf.tables.borrow_mut().retain(|t| t.1 == "vanguard");
    s = s.avec(NFTABLES, "disabled", "inactive");
    let avant = a.pf.tables.borrow().clone();
    let r = rallumer(PareFeu::Nftables, &mut a, &mut s);
    assert!(!r.reussi);
    assert!(r.raison.contains("blocages de Vanguard"), "{}", r.raison);
    assert!(!r.raison.contains("Wi-Fi public"), "{}", r.raison);
    rien_change(&a, &s, &avant);
    // Le mode Wi-Fi public seul, puis les deux : le refus nomme ce qui est en place (relecture de D7c, B5).
    let blocage = a.pf.tables.borrow().clone();
    *a.pf.tables.borrow_mut() = vec![table("inet", "vanguard_public", "")];
    let avant_public = a.pf.tables.borrow().clone();
    let r = rallumer(PareFeu::Nftables, &mut a, &mut s);
    assert!(!r.reussi);
    assert!(
        r.raison.contains("mode Wi-Fi public") && !r.raison.contains("blocages"),
        "{}",
        r.raison
    );
    rien_change(&a, &s, &avant_public);
    a.pf.tables.borrow_mut().extend(blocage);
    let avant_deux = a.pf.tables.borrow().clone();
    let r = rallumer(PareFeu::Nftables, &mut a, &mut s);
    assert!(!r.reussi);
    assert!(r.raison.contains("blocages et le mode Wi-Fi public"), "{}", r.raison);
    rien_change(&a, &s, &avant_deux);
    // Sans blocage : la configuration du système est chargée, au démarrage aussi.
    a.pf.tables.borrow_mut().clear();
    let mut a = a.repondre("o");
    let r = rallumer(PareFeu::Nftables, &mut a, &mut s);
    assert!(r.reussi, "{}", r.raison);
    assert_eq!(
        s.faits,
        ["activer-sans-demarrer nftables.service", "demarrer nftables.service"]
    );
    assert_eq!(*a.pf.tables.borrow(), [table("inet", "filter", FILTRE)]);
    assert!(
        !a.notes.contains_key(PareFeu::Nftables.note().as_str()),
        "{:?}",
        a.notes
    );
}

/// Une session SSH ouverte (connexion établie sur le port 22, session distante, lignée dans sshd) ou rien qui
/// permette de dire le contraire : la question le dit, et Entrée seule ne fait rien.
#[test]
fn ssh_ouvert_avertit_et_entree_dit_non() {
    let cas: [fn(&mut Faux, &mut ServicesPf); 5] = [
        |a, _| a.poser("/proc/net/tcp", TCP_SSH, 0o444),
        |a, _| a.poser("/proc/net/tcp6", TCP_SSH, 0o444),
        |a, _| {
            a.fichiers.remove(Path::new("/proc/net/tcp"));
        },
        |_, s| {
            s.sessions = Some(vec![SessionVue {
                distante: true,
                service: "sshd".into(),
                groupes_du_meneur: Vec::new(),
            }]);
        },
        |_, s| s.lignee = vec!["/system.slice/sshd.service".into()],
    ];
    for (i, poser) in cas.iter().enumerate() {
        let (a, mut s) = faux_nft();
        let mut a = a.repondre("");
        poser(&mut a, &mut s);
        let avant = a.pf.tables.borrow().clone();
        assert!(!couper(PareFeu::Nftables, &mut a, &mut s).reussi, "{i}");
        assert!(a.questions[0].contains("AVERTISSEMENT"), "{i} : {}", a.questions[0]);
        assert!(a.questions[0].contains("session SSH"), "{i}");
        rien_change(&a, &s, &avant);
        // Rallumer ufw : l'avertissement aussi (les règles peuvent refuser SSH).
        let mut a = faux_ufw(false, false).repondre("");
        let mut s = ServicesPf::nouveau(&a.pf.tables);
        poser(&mut a, &mut s);
        assert!(!rallumer(PareFeu::Ufw, &mut a, &mut s).reussi);
        assert!(a.questions[0].contains("AVERTISSEMENT"), "{i}");
        assert!(!a.pf.ufw_actif);
    }
    // Sans session SSH : pas d'avertissement.
    let (a, mut s) = faux_nft();
    let mut a = a.repondre("");
    assert!(!couper(PareFeu::Nftables, &mut a, &mut s).reussi);
    assert!(!a.questions[0].contains("AVERTISSEMENT"), "{}", a.questions[0]);
    // Le port 22 comme port distant, ou une connexion qui n'est pas établie : pas une session SSH ici.
    assert!(!pare_feu::tcp_ssh_etabli(
        "en-tête\n   0: 0F02000A:D2F0 0202000A:0016 01 0:0 0:0 0 0 0 1\n   1: 00000000:0016 00000000:0000 0A 0:0 0:0 0 0 0 1\n"
    ));
    assert!(pare_feu::tcp_ssh_etabli(&String::from_utf8_lossy(TCP_SSH)));
    // sshd sur le port 2222 (08AE) : une connexion entrante venue d'ailleurs sur un port en écoute avertit, en IPv4
    // comme en IPv6 (adresse IPv4 vue en IPv6) ; une connexion sortante (port local hors écoute), ou venue de la boucle
    // locale, non (relecture de D7c, B3).
    let ecoute = "   0: 00000000:08AE 00000000:0000 0A 0:0 0:0 0 0 0 1\n";
    let entrante = format!("en-tête\n{ecoute}   1: 0F02000A:08AE 0202000A:D2F0 01 0:0 0:0 0 0 0 1\n");
    assert!(pare_feu::tcp_ssh_etabli(&entrante));
    let entrante6 = "en-tête\n   0: 00000000000000000000000000000000:08AE 00000000000000000000000000000000:0000 0A 0:0 0:0 0 0 0 1\n   1: 0000000000000000FFFF00000F02000A:08AE 0000000000000000FFFF00000202000A:D2F0 01 0:0 0:0 0 0 0 1\n";
    assert!(pare_feu::tcp_ssh_etabli(entrante6));
    let sortante = format!("en-tête\n{ecoute}   1: 0F02000A:D2F0 0202000A:08AE 01 0:0 0:0 0 0 0 1\n");
    assert!(!pare_feu::tcp_ssh_etabli(&sortante));
    let boucle = format!("en-tête\n{ecoute}   1: 0100007F:08AE 0100007F:D2F0 01 0:0 0:0 0 0 0 1\n");
    assert!(!pare_feu::tcp_ssh_etabli(&boucle));
    let boucle6 = "en-tête\n   0: 00000000000000000000000000000000:08AE 00000000000000000000000000000000:0000 0A 0:0 0:0 0 0 0 1\n   1: 00000000000000000000000001000000:08AE 00000000000000000000000001000000:D2F0 01 0:0 0:0 0 0 0 1\n";
    assert!(!pare_feu::tcp_ssh_etabli(boucle6));
}

#[test]
fn ufw_sans_regle_ssh_avertit_et_regles_echappees() {
    let mut a = faux_ufw(false, false).repondre("");
    a.pf.ufw_regles = vec!["ufw allow 80/tcp \x1b[31mrouge\r".into()];
    a.poser("/proc/net/tcp", TCP_SSH, 0o444);
    let mut s = ServicesPf::nouveau(&a.pf.tables);
    assert!(!rallumer(PareFeu::Ufw, &mut a, &mut s).reussi);
    let q = &a.questions[0];
    assert!(q.contains("ne semble ouvrir SSH"), "{q}");
    assert!(!q.contains('\x1b') && !q.contains('\r'), "{q:?}");
    assert!(q.contains("ufw allow 80/tcp"), "{q}");
}

/// Le pare-feu rallumé hors de Vanguard : la note restée est périmée, retirée, et la coupure se refait ; encore
/// coupé par ce choix : rien n'est refait.
#[test]
fn note_perimee_retiree_note_encore_juste_gardee() {
    let mut a = faux_ufw(true, true).repondre("o");
    let mut s = ServicesPf::nouveau(&a.pf.tables);
    assert!(couper(PareFeu::Ufw, &mut a, &mut s).reussi);
    let note = a.notes.clone();
    let mut a = a.repondre("o");
    let r = couper(PareFeu::Ufw, &mut a, &mut s);
    assert!(r.reussi && r.note.unwrap().contains("déjà coupé par votre choix"));
    assert_eq!(a.notes, note);
    assert_eq!(a.questions.len(), 1);
    // Rallumé à la main (ufw enable) : la coupure suivante repose sa question et écrit une note neuve.
    a.pf.ufw_actif = true;
    a.poser(UFW_CONF, b"ENABLED=yes\n", 0o644);
    let r = couper(PareFeu::Ufw, &mut a, &mut s);
    assert!(r.reussi, "{}", r.raison);
    assert_eq!(a.questions.len(), 2);
    assert!(!a.pf.ufw_actif);
}

/// Une note posée sous l'identifiant d'un pare-feu mais qui en nomme un autre, ou abîmée : refusée, rien remis.
#[test]
fn note_forgee_d_un_autre_pare_feu_refusee() {
    let mut a = faux_ufw(false, false).repondre("o").repondre("o");
    let mut s = ServicesPf::nouveau(&a.pf.tables).avec(FIREWALLD, "disabled", "inactive");
    let id_ufw = PareFeu::Ufw.note();
    let n = Note {
        geste: GesteUnix::Defense(Defense::CouperPareFeu(PareFeu::Firewalld), id_ufw).ligne(),
        date: 1,
        champs: vec![
            ("etat".into(), b"enabled".to_vec()),
            ("activite".into(), b"active".to_vec()),
        ],
    };
    a.notes
        .insert(id_ufw.as_str().into(), n.octets(id_ufw.as_str()).unwrap());
    assert!(!remettre_pf(PareFeu::Ufw, &mut a, &mut s).reussi);
    assert!(!couper(PareFeu::Ufw, &mut a, &mut s).reussi);
    assert!(s.faits.is_empty() && !a.pf.ufw_actif, "{:?}", s.faits);
    // Une note d'ufw aux champs changés (« enabled » ôté) : abîmée, rien remis.
    let n = Note {
        geste: GesteUnix::Defense(Defense::CouperPareFeu(PareFeu::Ufw), id_ufw).ligne(),
        date: 1,
        champs: vec![("actif".into(), b"active".to_vec())],
    };
    a.notes
        .insert(id_ufw.as_str().into(), n.octets(id_ufw.as_str()).unwrap());
    let r = remettre_pf(PareFeu::Ufw, &mut a, &mut s);
    assert!(!r.reussi, "{}", r.raison);
    assert!(!a.pf.ufw_actif);
    assert!(
        !a.journal.iter().any(|l| l.starts_with("ufw --force")),
        "{:?}",
        a.journal
    );
}

/// Une note de nftables dont la sauvegarde nomme une table de Vanguard, ou que nft -c refuse : rien n'est rechargé.
#[test]
fn nftables_note_forgee_ou_refusee_rien_recharge() {
    let (a, mut s) = faux_nft();
    let mut a = a.repondre("o");
    a.pf.tables.borrow_mut().retain(|t| t.1 == "vanguard");
    let id_nft = PareFeu::Nftables.note();
    let note = |tables: &str, sauve: &str| Note {
        geste: GesteUnix::Defense(Defense::CouperPareFeu(PareFeu::Nftables), id_nft).ligne(),
        date: 1,
        champs: vec![
            ("tables".into(), tables.as_bytes().to_vec()),
            ("sauvegarde".into(), sauve.as_bytes().to_vec()),
            ("service".into(), b"enabled".to_vec()),
        ],
    };
    let avant = a.pf.tables.borrow().clone();
    let n = note(
        "table inet vanguard\n",
        "add table inet vanguard\ndelete table inet vanguard\n",
    );
    a.notes
        .insert(id_nft.as_str().into(), n.octets(id_nft.as_str()).unwrap());
    assert!(!remettre_pf(PareFeu::Nftables, &mut a, &mut s).reussi);
    assert_eq!(*a.pf.tables.borrow(), avant);
    let n = note(
        "table inet filter\n",
        "add table inet filter\ndelete table inet filter\ntable inet filter {\n}\n",
    );
    a.notes
        .insert(id_nft.as_str().into(), n.octets(id_nft.as_str()).unwrap());
    a.pf.nft_c_refuse = true;
    let r = remettre_pf(PareFeu::Nftables, &mut a, &mut s);
    assert!(!r.reussi && r.raison.contains("ne se reliraient pas"), "{}", r.raison);
    assert_eq!(*a.pf.tables.borrow(), avant);
    assert!(!a.fichiers.contains_key(Path::new(FICHIER_NFT)));
    assert!(s.faits.is_empty(), "{:?}", s.faits);
}

/// Une coupure ne se fait que sous l'identifiant fixe de son pare-feu (ce que le parent lit pour le bilan) : sous
/// un autre, refusée par le fils avant tout regard.
#[test]
fn coupure_sous_un_autre_identifiant_refusee_par_le_fils() {
    let mut a = faux_ufw(true, true).repondre("o");
    let mut s = ServicesPf::nouveau(&a.pf.tables);
    for autre in [id(), PareFeu::Firewalld.note(), PareFeu::Nftables.note()] {
        let r = faire(Defense::CouperPareFeu(PareFeu::Ufw), autre, &mut a, &mut s);
        assert!(!r.reussi);
    }
    assert!(a.questions.is_empty() && a.notes.is_empty() && a.pf.ufw_actif);
    // Rallumer sous l'identifiant fixe : refusé aussi (il est réservé à la coupure).
    let r = faire(
        Defense::RallumerPareFeu(PareFeu::Ufw),
        PareFeu::Ufw.note(),
        &mut a,
        &mut s,
    );
    assert!(!r.reussi);
}

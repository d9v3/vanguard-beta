//! « Mes ordinateurs » : le tableau de bord de la clé VANGUARD. À la fin de chaque bilan complet, l'ordinateur où la
//! clé est branchée y note sa visite : surnom, système, modèle, notes, version de Vanguard, et ses problèmes restants
//! (catégorie et niveau seulement, les cinq plus graves). Le tableau vit sur VANGUARDLOG (`ordinateurs.json`), la
//! seule partition modifiable partout ; il voyage donc avec la clé, au contraire de l'historique des bilans, gardé
//! sur chaque ordinateur. VANGUARDLOG se lit en clair : jamais de nom de machine, de compte, d'adresse IP ou MAC, de
//! nom de Wi-Fi, de numéro de série ni de chemin. outils/deployer.sh n'en rapatrie que journal-erreurs.txt : ce
//! tableau ne part jamais sur GitHub (test `seul_le_journal_quitte_vanguardlog`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::machine::Audit;
use crate::reseau::Rapport;
use crate::risk::Niveau;
use crate::ui::*;

const FICHIER: &str = "ordinateurs.json";
/// Problèmes gardés par ordinateur : les plus graves, pas la liste entière.
const PROBLEMES_MAX: usize = 5;
/// Au-delà, une ligne est marquée « ! » : l'ordinateur n'a pas été revu depuis longtemps.
const JOURS_OUBLI: i64 = 90;

/// Un ordinateur vu par la clé.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Ordinateur {
    surnom: String,
    systeme: String,
    modele: String,
    /// AAAA-MM-JJ HH:MM.
    vu_le: String,
    note_machine: Option<u32>,
    note_reseau: Option<u32>,
    version: String,
    problemes: Vec<Probleme>,
}

/// Un problème restant : sa catégorie (nom interne, traduit à l'affichage) et son niveau, jamais son message (il peut
/// citer un appareil, un compte ou un chemin).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Probleme {
    categorie: String,
    niveau: Niveau,
}

/// Les ordinateurs, par empreinte de la machine (SHA-1 de son identifiant : elle retrouve l'entrée, elle ne dit pas
/// qui est la personne).
#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
struct Tableau {
    ordinateurs: BTreeMap<String, Ordinateur>,
}

/// Le tableau de la partition VANGUARDLOG branchée, s'il y en a une.
fn fichier() -> Option<PathBuf> {
    crate::journal::partition_de_la_cle().map(|p| p.join(FICHIER))
}

/// Un tableau illisible (écrit à moitié, clé arrachée) repart de zéro : il ne contient rien qu'un bilan ne refasse.
fn lire(chemin: &Path) -> Tableau {
    std::fs::read_to_string(chemin)
        .ok()
        .and_then(|t| serde_json::from_str(t.trim_start_matches('\u{feff}')).ok())
        .unwrap_or_default()
}

fn ecrire(t: &Tableau, chemin: &Path) -> std::io::Result<()> {
    let texte = serde_json::to_string_pretty(t).map_err(std::io::Error::other)?;
    crate::socle::ecrire_atomique(chemin, &texte)
}

/// Les problèmes restants d'un bilan : catégorie et niveau, du moyen au critique, une fois par catégorie (son pire
/// niveau), les cinq plus graves.
fn problemes(audit: &Audit) -> Vec<Probleme> {
    let mut pires: BTreeMap<&str, Niveau> = BTreeMap::new();
    for c in &audit.constats {
        if let Some(n) = c.probleme.filter(|n| *n >= Niveau::Moyen) {
            let pire = pires.entry(c.categorie).or_insert(n);
            *pire = (*pire).max(n);
        }
    }
    let mut liste: Vec<Probleme> = pires
        .into_iter()
        .map(|(categorie, niveau)| Probleme {
            categorie: categorie.to_string(),
            niveau,
        })
        .collect();
    liste.sort_by(|a, b| b.niveau.cmp(&a.niveau).then_with(|| a.categorie.cmp(&b.categorie)));
    liste.truncate(PROBLEMES_MAX);
    liste
}

/// Ce que l'entrée dit de cet ordinateur, passé par l'anonymisation du journal (nom de machine, compte, dossier
/// personnel) : il ne devrait rien y avoir à masquer, c'est une ceinture de plus.
fn propre(t: &str) -> String {
    affichable(&crate::journal::anonymiser(t))
}

/// Note la visite de cet ordinateur dans `chemin`. Le surnom d'une entrée existante (peut-être renommée) est gardé.
fn noter_dans(chemin: &Path, empreinte: &str, systeme: &str, modele: &str, audit: &Audit, reseau: Option<&Rapport>) {
    let mut t = lire(chemin);
    let (systeme, modele) = (propre(systeme), propre(modele));
    let surnom = t
        .ordinateurs
        .get(empreinte)
        .map_or_else(|| surnom_propose(&systeme, &modele), |o| o.surnom.clone());
    t.ordinateurs.insert(
        empreinte.to_string(),
        Ordinateur {
            surnom,
            systeme,
            modele,
            vu_le: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
            note_machine: audit.fiable().then_some(audit.score),
            note_reseau: reseau.map(|r| r.score_global),
            version: env!("CARGO_PKG_VERSION").to_string(),
            problemes: problemes(audit),
        },
    );
    if let Err(e) = ecrire(&t, chemin) {
        crate::journal::erreur("mes ordinateurs", &e.to_string());
    }
}

/// Le surnom d'un nouvel ordinateur : « système · modèle », renommable ensuite.
fn surnom_propose(systeme: &str, modele: &str) -> String {
    match (systeme.is_empty(), modele.is_empty()) {
        (false, false) => format!("{systeme} · {modele}"),
        (false, true) => systeme.to_string(),
        (true, false) => modele.to_string(),
        (true, true) => tr!("Ordinateur", "Computer").to_string(),
    }
}

/// À la fin d'un bilan complet : note cet ordinateur dans le tableau de la clé, si elle est branchée avec VANGUARDLOG.
pub fn noter(audit: Option<&Audit>, reseau: Option<&Rapport>) {
    if cfg!(test) {
        return;
    }
    let (Some(audit), Some(chemin), Some(empreinte)) = (audit, fichier(), crate::machine::empreinte_machine()) else {
        return;
    };
    let (systeme, modele) = systeme_et_modele();
    noter_dans(&chemin, &empreinte, &systeme, &modele, audit, reseau);
}

// ───────────────────────────── Système et modèle ─────────────────────────────

/// Le système (nom et version) et le modèle de l'ordinateur, lus sans rien lancer de lourd : ni nom de machine, ni
/// compte, ni numéro de série.
#[cfg(target_os = "linux")]
fn systeme_et_modele() -> (String, String) {
    let lire = |f: &str| std::fs::read_to_string(f).unwrap_or_default().trim().to_string();
    let systeme = crate::socle::systeme::nom();
    let modele = crate::fiche::avec_fabricant(
        &lire("/sys/class/dmi/id/sys_vendor"),
        &lire("/sys/class/dmi/id/product_name"),
    );
    (systeme, modele)
}

#[cfg(windows)]
fn systeme_et_modele() -> (String, String) {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let valeur = |cle: &str, nom: &str| {
        RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(cle)
            .and_then(|k| k.get_value::<String, _>(nom))
            .unwrap_or_default()
    };
    let version = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    (
        nom_windows(
            &valeur(version, "ProductName"),
            &valeur(version, "CurrentBuild"),
            &valeur(version, "DisplayVersion"),
        ),
        crate::fiche::avec_fabricant(
            &valeur(r"HARDWARE\DESCRIPTION\System\BIOS", "SystemManufacturer"),
            &valeur(r"HARDWARE\DESCRIPTION\System\BIOS", "SystemProductName"),
        ),
    )
}

/// « Windows 10 Pro » (le registre garde ce nom sous Windows 11), build 26100, « 24H2 » → « Windows 11 Pro 24H2 ».
#[cfg_attr(not(windows), allow(dead_code))]
fn nom_windows(produit: &str, build: &str, version: &str) -> String {
    let mut nom = produit.trim().to_string();
    if build.trim().parse::<u32>().is_ok_and(|b| b >= 22_000) {
        nom = nom.replacen("Windows 10", "Windows 11", 1);
    }
    let version = version.trim();
    if version.is_empty() {
        nom
    } else {
        format!("{nom} {version}")
    }
}

#[cfg(target_os = "macos")]
fn systeme_et_modele() -> (String, String) {
    use crate::machine::macos::{sysctl_texte, version_systeme};
    let systeme = format!(
        "{} {}",
        version_systeme("ProductName").unwrap_or_default(),
        version_systeme("ProductVersion").unwrap_or_default()
    );
    (systeme.trim().to_string(), sysctl_texte("hw.model").unwrap_or_default())
}

// ───────────────────────────── Tableau ─────────────────────────────

fn date(vu_le: &str) -> Option<chrono::NaiveDate> {
    chrono::NaiveDate::parse_from_str(vu_le.get(..10)?, "%Y-%m-%d").ok()
}

/// Les entrées, la plus récente d'abord.
fn triees(t: &Tableau) -> Vec<(&String, &Ordinateur)> {
    let mut l: Vec<(&String, &Ordinateur)> = t.ordinateurs.iter().collect();
    l.sort_by(|a, b| b.1.vu_le.cmp(&a.1.vu_le));
    l
}

/// Une ligne du tableau : surnom, note, problèmes restants, date ; « ! » si l'ordinateur n'a pas été revu depuis
/// plus de trois mois ; « ← ici » pour celui-ci.
fn ligne(o: &Ordinateur, aujourd_hui: chrono::NaiveDate, ici: bool) -> String {
    let note = o.note_machine.map_or("–", crate::risk::note);
    let problemes = match o.problemes.len() {
        0 => tr!("aucun problème", "no problem").to_string(),
        n => trf!("{n} problème(s)", "{n} problem(s)"),
    };
    let ancien = date(&o.vu_le).is_some_and(|d| (aujourd_hui - d).num_days() > JOURS_OUBLI);
    let marque = if ancien { "!" } else { " " };
    let jour = o.vu_le.get(..10).unwrap_or(&o.vu_le);
    let ici = if ici { tr!(" ← ici", " ← here") } else { "" };
    format!(
        "{marque}{} {note:<2} {} {jour}{ici}",
        ajuster(&o.surnom, 30),
        ajuster(&problemes, 15)
    )
}

/// Le détail d'un ordinateur : système, modèle, notes, version, et ses problèmes restants par catégorie.
fn detail(o: &Ordinateur) -> Vec<String> {
    let note = |n: Option<u32>| n.map_or_else(|| "–".to_string(), |n| format!("{} ({n}/100)", crate::risk::note(n)));
    let mut l = vec![
        trf!("Système : {}", "System: {}", o.systeme),
        trf!(
            "Modèle : {}",
            "Model: {}",
            if o.modele.is_empty() { "?" } else { &o.modele }
        ),
        trf!(
            "Note de la machine : {} · du réseau : {}",
            "Machine grade: {} · network: {}",
            note(o.note_machine),
            note(o.note_reseau)
        ),
        trf!(
            "Dernier bilan : {} (Vanguard {})",
            "Last check: {} (Vanguard {})",
            o.vu_le,
            o.version
        ),
    ];
    if o.problemes.is_empty() {
        l.push(tr!("Aucun problème restant.", "No problem left.").to_string());
    }
    for p in &o.problemes {
        let niveau = match p.niveau {
            Niveau::Critique => tr!("critique", "critical"),
            Niveau::Eleve => tr!("élevé", "high"),
            Niveau::Moyen => tr!("moyen", "medium"),
            Niveau::Info => tr!("faible", "low"),
        };
        l.push(format!("  – {} : {niveau}", crate::langue::categorie(&p.categorie)));
    }
    l
}

/// Menu Données › Mes ordinateurs, ou `vanguard ordinateurs`.
pub fn menu() {
    titre(tr!("Mes ordinateurs", "My computers"));
    let Some(chemin) = fichier() else {
        afficher_aligne(
            "  ",
            tr!(
                "Branchez la clé VANGUARD : le tableau est gardé sur sa partition VANGUARDLOG. Une clé qui n'en a pas se refait avec outils/preparer-cle.sh.",
                "Plug in the VANGUARD key: the table is kept on its VANGUARDLOG partition. A key without it is rebuilt with outils/preparer-cle.sh."
            ),
            2,
            "",
        );
        return;
    };
    let ici = crate::machine::empreinte_machine();
    loop {
        let mut t = lire(&chemin);
        if t.ordinateurs.is_empty() {
            afficher_aligne(
                "  ",
                tr!(
                    "Aucun ordinateur pour l'instant : chaque bilan complet fait avec cette clé y ajoute le sien.",
                    "No computer yet: each full check run with this key adds its own."
                ),
                2,
                "",
            );
            return;
        }
        let aujourd_hui = chrono::Local::now().date_naive();
        let liste: Vec<(String, Ordinateur)> = triees(&t).into_iter().map(|(e, o)| (e.clone(), o.clone())).collect();
        let mut lignes = vec![
            crate::selection::Ligne::Texte(String::new()),
            crate::selection::Ligne::Texte(trf!(
                "  {GRIS}Vus avec cette clé, du plus récent au plus ancien ; « ! » : pas revu depuis 3 mois.{RESET}",
                "  {GRIS}Seen with this key, most recent first; “!”: not seen for 3 months.{RESET}"
            )),
            crate::selection::Ligne::Texte(String::new()),
        ];
        for (i, (empreinte, o)) in liste.iter().enumerate() {
            let texte = ligne(o, aujourd_hui, ici.as_deref() == Some(empreinte.as_str()));
            lignes.push(crate::selection::Ligne::choix(&(i + 1).to_string(), &texte, ""));
        }
        lignes.push(crate::selection::Ligne::Texte(String::new()));
        lignes.push(crate::selection::Ligne::choix("↵", tr!("Revenir", "Back"), ""));
        let invite = tr!(
            "  Numéro pour le détail (Entrée pour revenir) : ",
            "  Number for details (Enter to go back): "
        );
        let Some(choix) = crate::selection::choisir(&lignes, invite, "1", tr!("revenir", "back")) else {
            return;
        };
        let Some((empreinte, o)) = choix
            .trim()
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|i| liste.get(i))
        else {
            return;
        };
        section(&o.surnom);
        for l in detail(o) {
            afficher_aligne("  ", &l, 4, "");
        }
        let reponse = crate::selection::demander_ou_revenir(tr!(
            "\n  [r]enommer, [o]ublier, Entrée pour revenir : ",
            "\n  [r]ename, [f]orget, Enter to go back: "
        ));
        match reponse.trim().to_lowercase().as_str() {
            "r" => {
                let nom = demander(tr!("  Nouveau surnom : ", "  New nickname: "));
                let nom: String = affichable(nom.trim()).chars().take(40).collect();
                if let Some(entree) = t.ordinateurs.get_mut(empreinte)
                    && !nom.is_empty()
                {
                    entree.surnom = nom;
                }
            }
            "o" | "f" => {
                t.ordinateurs.remove(empreinte);
            }
            _ => continue,
        }
        if let Err(e) = ecrire(&t, &chemin) {
            trp!("  ✖ Tableau non enregistré ({e}).", "  ✖ Table not saved ({e}).");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::Constat;

    fn constat(categorie: &'static str, niveau: Option<Niveau>, message: &str) -> Constat {
        Constat {
            categorie,
            probleme: niveau,
            message: message.into(),
            correctif: None,
            verifie: true,
            regle: "",
            objet: crate::modele::Objet::NonMigre,
            precision: crate::modele::Precision::Aucune,
        }
    }

    fn audit() -> Audit {
        Audit {
            systeme: "Linux",
            score: 72,
            constats: vec![
                constat("Pare-feu", Some(Niveau::Eleve), "Pare-feu inactif."),
                constat("Pare-feu", Some(Niveau::Critique), "Port 22 ouvert à tous."),
                constat("Mises à jour", Some(Niveau::Moyen), "3 mises à jour."),
                constat("Clés SSH", Some(Niveau::Info), "Clé id_ed25519 de alice@salon."),
                constat("Groupes", None, "Tout va bien."),
                constat("Santé", Some(Niveau::Moyen), "Disque /home/alice/x plein."),
                constat("DNS", Some(Niveau::Eleve), "DNS vers 10.0.0.5."),
                constat("Wi-Fi", Some(Niveau::Moyen), "« Chez Max » en WPA2."),
                constat("Comptes", Some(Niveau::Moyen), "Compte alice sans mot de passe."),
            ],
        }
    }

    fn dossier(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vanguard-ordinateurs-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    // Catégories et niveaux seulement, le pire de chaque catégorie, les cinq plus graves ; pas de niveau info.
    #[test]
    fn problemes_sans_messages() {
        let p = problemes(&audit());
        assert_eq!(p.len(), PROBLEMES_MAX);
        assert_eq!((p[0].categorie.as_str(), p[0].niveau), ("Pare-feu", Niveau::Critique));
        assert_eq!((p[1].categorie.as_str(), p[1].niveau), ("DNS", Niveau::Eleve));
        assert!(p.iter().all(|x| x.categorie != "Clés SSH" && x.categorie != "Groupes"));
    }

    // L'entrée écrite ne contient aucun message de constat : ni compte, ni chemin, ni adresse, ni nom de Wi-Fi.
    #[test]
    fn rien_de_personnel_dans_le_tableau() {
        let d = dossier("prive");
        let chemin = d.join(FICHIER);
        noter_dans(&chemin, "e1", "Arch Linux", "LENOVO 21AH", &audit(), None);
        let texte = std::fs::read_to_string(&chemin).unwrap();
        for interdit in [
            "alice",
            "/home",
            "10.0.0.5",
            "Chez Max",
            "Port 22",
            "id_ed25519",
            "salon",
        ] {
            assert!(!texte.contains(interdit), "{interdit} dans {texte}");
        }
        let t = lire(&chemin);
        let o = &t.ordinateurs["e1"];
        assert_eq!(o.surnom, "Arch Linux · LENOVO 21AH");
        assert_eq!(o.note_machine, Some(72));
        let _ = std::fs::remove_dir_all(&d);
    }

    // Une deuxième visite met l'entrée à jour sans toucher au surnom choisi ; un autre ordinateur a la sienne.
    #[test]
    fn surnom_garde_et_entrees_par_machine() {
        let d = dossier("visites");
        let chemin = d.join(FICHIER);
        noter_dans(&chemin, "e1", "Windows 11 Pro 24H2", "Dell XPS 13", &audit(), None);
        let mut t = lire(&chemin);
        t.ordinateurs.get_mut("e1").unwrap().surnom = "portable de maman".into();
        ecrire(&t, &chemin).unwrap();
        noter_dans(&chemin, "e1", "Windows 11 Pro 25H2", "Dell XPS 13", &audit(), None);
        noter_dans(&chemin, "e2", "macOS 15.1", "", &audit(), None);
        let t = lire(&chemin);
        assert_eq!(t.ordinateurs.len(), 2);
        assert_eq!(t.ordinateurs["e1"].surnom, "portable de maman");
        assert_eq!(t.ordinateurs["e1"].systeme, "Windows 11 Pro 25H2");
        assert_eq!(t.ordinateurs["e2"].surnom, "macOS 15.1");
        // Un tableau illisible repart de zéro au lieu de bloquer.
        std::fs::write(&chemin, "{ pas du json").unwrap();
        assert_eq!(lire(&chemin), Tableau::default());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn lignes_et_detail_dans_la_largeur() {
        let o = Ordinateur {
            surnom: "Windows 11 Professionnel 24H2 · Lenovo IdeaPad Slim 5".into(),
            systeme: "Windows 11 Professionnel 24H2".into(),
            modele: "Lenovo IdeaPad Slim 5".into(),
            vu_le: "2026-06-01 12:00".into(),
            note_machine: Some(81),
            note_reseau: None,
            version: "0.58.0".into(),
            problemes: problemes(&audit()),
        };
        let jour = chrono::NaiveDate::from_ymd_opt(2026, 10, 18).unwrap();
        let l = ligne(&o, jour, true);
        assert!(l.starts_with('!'), "{l}");
        assert!(largeur_affichee(&l) + 6 <= LARGEUR, "{l}");
        assert!(!ligne(&o, chrono::NaiveDate::from_ymd_opt(2026, 6, 20).unwrap(), false).starts_with('!'));
        assert!(detail(&o).iter().any(|t| t.contains("81/100")));
    }

    /// Les messages tiennent dans `LARGEUR` colonnes, dans les deux langues.
    #[test]
    fn messages_dans_la_largeur() {
        assert_eq!(
            crate::ui::textes_trop_larges(include_str!("ordinateurs.rs")),
            Vec::<String>::new()
        );
    }

    #[test]
    fn nom_de_windows() {
        assert_eq!(nom_windows("Windows 10 Pro", "26100", "24H2"), "Windows 11 Pro 24H2");
        assert_eq!(nom_windows("Windows 10 Home", "19045", "22H2"), "Windows 10 Home 22H2");
        assert_eq!(nom_windows("Windows 10 Pro", "", ""), "Windows 10 Pro");
    }

    /// VANGUARDLOG se lit en clair et voyage : outils/deployer.sh ne doit en rapatrier que journal-erreurs.txt (et
    /// toucher ses témoins, dont le jeton de la clé qu'il y recopie), jamais toute la partition ni
    /// ordinateurs.json, sans quoi le tableau pourrait partir avec le journal sur GitHub.
    #[test]
    fn seul_le_journal_quitte_vanguardlog() {
        let deployer = include_str!("../outils/deployer.sh");
        let permis = [
            "\"$JOURNAL/journal-erreurs.txt\"",
            "\"$JOURNAL/vanguard-journal.cle\"",
            "\"$JOURNAL/vanguard.jeton\"",
        ];
        for l in deployer.lines().filter(|l| l.contains("$JOURNAL")) {
            let sans_permis = permis.iter().fold(l.to_string(), |t, p| t.replace(p, ""));
            assert!(
                !sans_permis.contains("$JOURNAL/") && !sans_permis.contains("\"$JOURNAL\" "),
                "deployer.sh lit VANGUARDLOG au-delà du journal : {l}"
            );
        }
        assert!(deployer.contains("rapatrier_journal \"$JOURNAL/journal-erreurs.txt\""));
    }
}

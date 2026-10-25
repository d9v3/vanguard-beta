//! Intégrité des fichiers critiques (comptes, sudo, SSH, PAM, cron, services, démarrage automatique, hosts) :
//! une référence d'empreintes BLAKE3, puis la liste de ce qui a été modifié, ajouté ou supprimé depuis.
//! Les fichiers illisibles sans droits root sont suivis par leur taille et leur date de modification.
//! « --temps-reel » surveille ces fichiers en direct ; « --accepter » prend l'état actuel comme référence
//! (après une mise à jour du système, qui modifie légitimement certains d'entre eux).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::machine::Constat;
use crate::risk::Niveau;
use crate::ui::*;

/// Fichiers et dossiers suivis (un dossier : les fichiers qu'il contient directement).
fn cibles() -> Vec<PathBuf> {
    let maison = crate::socle::maison();
    #[cfg(target_os = "linux")]
    let systeme: &[&str] = &[
        "/etc/passwd",
        "/etc/group",
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/sudoers.d",
        "/etc/hosts",
        "/etc/ld.so.preload",
        "/etc/environment",
        "/etc/profile",
        "/etc/fstab",
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/ssh/sshd_config",
        "/etc/ssh/sshd_config.d",
        "/etc/pam.d",
        "/etc/systemd/system",
        "/etc/xdg/autostart",
    ];
    #[cfg(target_os = "linux")]
    let utilisateur: &[&str] = &[
        ".bashrc",
        ".bash_profile",
        ".profile",
        ".zshrc",
        ".ssh/authorized_keys",
        ".config/autostart",
        ".config/systemd/user",
    ];
    // macOS : /etc est un lien vers /private/etc ; les démons et agents de launchd sont le démarrage automatique.
    #[cfg(target_os = "macos")]
    let systeme: &[&str] = &[
        "/etc/hosts",
        "/etc/sudoers",
        "/etc/sudoers.d",
        "/etc/pam.d",
        "/etc/ssh/sshd_config",
        "/etc/ssh/sshd_config.d",
        "/etc/zshrc",
        "/etc/zprofile",
        "/etc/profile",
        "/etc/paths",
        "/etc/paths.d",
        "/etc/periodic/daily",
        "/Library/LaunchDaemons",
        "/Library/LaunchAgents",
    ];
    #[cfg(target_os = "macos")]
    let utilisateur: &[&str] = &[
        ".zshrc",
        ".zprofile",
        ".zshenv",
        ".bash_profile",
        ".profile",
        ".ssh/authorized_keys",
        "Library/LaunchAgents",
    ];
    // Profils PowerShell (relancés à chaque ouverture de PowerShell) et scripts des stratégies de groupe : des
    // endroits où un programme malveillant aime se faire relancer.
    #[cfg(windows)]
    let systeme: &[&str] = &[
        r"C:\Windows\System32\drivers\etc\hosts",
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
        r"C:\ProgramData\ssh\administrators_authorized_keys",
        r"C:\ProgramData\ssh\sshd_config",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1",
        r"C:\Program Files\PowerShell\7\profile.ps1",
        r"C:\Windows\System32\GroupPolicy\Machine\Scripts\scripts.ini",
        r"C:\Windows\System32\GroupPolicy\User\Scripts\scripts.ini",
    ];
    #[cfg(windows)]
    let utilisateur: &[&str] = &[
        r".ssh\authorized_keys",
        r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
        r"Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
        r"Documents\WindowsPowerShell\profile.ps1",
        r"Documents\PowerShell\Microsoft.PowerShell_profile.ps1",
        r"Documents\PowerShell\profile.ps1",
    ];
    systeme
        .iter()
        .map(PathBuf::from)
        .chain(utilisateur.iter().map(|u| maison.join(u)))
        .collect()
}

/// Fichiers réels derrière les cibles (dossiers développés d'un niveau), dans l'ordre.
fn fichiers(cibles: &[PathBuf]) -> Vec<PathBuf> {
    let mut liste = Vec::new();
    for c in cibles {
        if c.is_dir() {
            let mut contenu: Vec<PathBuf> = std::fs::read_dir(c)
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_file())
                .collect();
            contenu.sort();
            liste.extend(contenu);
        } else if c.is_file() {
            liste.push(c.clone());
        }
    }
    liste
}

/// Empreinte d'un fichier : « b3:<BLAKE3> » s'il est lisible, sinon « meta:<taille>:<date> ».
fn empreinte(f: &Path) -> Option<String> {
    if let Ok(octets) = std::fs::read(f) {
        return Some(format!("b3:{}", blake3::hash(&octets).to_hex()));
    }
    let m = std::fs::metadata(f).ok()?;
    let date = m.modified().ok()?.duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(format!("meta:{}:{date}", m.len()))
}

type Etat = BTreeMap<String, String>;

fn etat_actuel() -> Etat {
    fichiers(&cibles())
        .into_iter()
        .filter_map(|f| Some((f.display().to_string(), empreinte(&f)?)))
        .collect()
}

/// La référence des empreintes, telle que Vanguard la retrouve.
enum Reference {
    Absente,
    Valable(Etat),
    /// Scellée telle quelle au premier passage d'une version qui scelle (montée depuis une version d'avant les sceaux,
    /// ou `sceaux.json` effacé) : rien ne prouve qu'elle n'a pas été réécrite juste avant. Elle sert quand même à
    /// comparer, car un écart avec elle est un vrai changement : la refuser coupait la vérification et la
    /// surveillance de chaque poste mis à jour, jusqu'à un « --accepter » que personne ne lance. Son origine est dite
    /// (COM-ETA-001, et ici), et elle n'est jamais refaite sans accord.
    Adoptee(Etat),
    /// Là, mais elle ne peut pas servir : abîmée, ou changée hors de Vanguard (`sceau`). Un programme qui réécrit la
    /// référence rend son propre changement « de référence » : elle n'est alors ni crue, ni refaite sans accord.
    Douteuse(String),
}

fn reference() -> Reference {
    reference_lue(crate::sceau::lire(crate::sceau::INTEGRITE), || {
        crate::sceau::repris_dans(&crate::socle::dossier_local(), crate::sceau::INTEGRITE)
    })
}

/// `repris` : la référence, acceptée telle quelle, a-t-elle été reprise par une mise à jour connue
/// (`sceau::repris_dans`) ? Alors elle sert (dite adoptée) ; acceptée autrement (premier usage, sceaux refaits), elle a
/// pu être réécrite par qui a effacé les sceaux, avec le ~/.bashrc qu'il vient de changer : douteuse, elle ne sert à
/// rien juger (`sceau::juge`).
fn reference_lue(lu: crate::sceau::Lecture, repris: impl FnOnce() -> bool) -> Reference {
    use crate::sceau::Lecture;
    match lu {
        Lecture::Adopte(_) if !repris() => Reference::Douteuse(crate::sceau::Doute::Adopte.texte().to_string()),
        Lecture::Absent => Reference::Absente,
        Lecture::Intact(o) => serde_json::from_slice(&o).map_or_else(
            |_| Reference::Douteuse(tr!("elle ne se lit plus", "it can no longer be read").into()),
            Reference::Valable,
        ),
        Lecture::Adopte(o) => serde_json::from_slice(&o).map_or_else(
            |_| Reference::Douteuse(tr!("elle ne se lit plus", "it can no longer be read").into()),
            Reference::Adoptee,
        ),
        Lecture::Falsifie(_) => Reference::Douteuse(
            tr!(
                "elle a été changée ou supprimée hors de Vanguard",
                "it was changed or deleted outside Vanguard"
            )
            .into(),
        ),
        Lecture::Illisible(e) => Reference::Douteuse(e),
        // Les sceaux ont été refaits sans elle : peut-être supprimée pour que la prochaine soit prise sur des
        // fichiers déjà changés. Jamais « pas encore de référence ».
        Lecture::Inconnu => Reference::Douteuse(
            tr!(
                "elle manque alors que les sceaux de Vanguard ont été refaits : peut-être supprimée hors de Vanguard",
                "it is missing while Vanguard's seals were remade: perhaps deleted outside Vanguard"
            )
            .into(),
        ),
    }
}

fn enregistrer(etat: &Etat) -> bool {
    serde_json::to_string_pretty(etat).is_ok_and(|t| crate::sceau::ecrire(crate::sceau::INTEGRITE, t).is_ok())
}

/// Le constat d'une référence qui ne peut pas servir : rien n'est comparé, et c'est dit, jamais « pas encore de
/// référence » (qui ne compte pas comme un problème).
fn douteuse(pourquoi: &str) -> Constat {
    Constat {
        verifie: false,
        ..crate::machine::alerte(
            CAT,
            Niveau::Moyen,
            trf!(
                "La référence des fichiers critiques ne peut pas servir ({}) : leur intégrité n'est pas vérifiée. Après examen, « vanguard integrite --accepter » la refait.",
                "The critical file reference cannot be used ({}): their integrity is not checked. After a look, “vanguard integrity --accept” remakes it.",
                pourquoi
            ),
        )
    }
}

/// Différences avec la référence : (modifiés, ajoutés, supprimés).
#[derive(Debug, Default, PartialEq)]
struct Ecarts {
    modifies: Vec<String>,
    ajoutes: Vec<String>,
    supprimes: Vec<String>,
}

impl Ecarts {
    fn vide(&self) -> bool {
        self.modifies.is_empty() && self.ajoutes.is_empty() && self.supprimes.is_empty()
    }

    fn total(&self) -> usize {
        self.modifies.len() + self.ajoutes.len() + self.supprimes.len()
    }
}

fn comparer(reference: &Etat, actuel: &Etat) -> Ecarts {
    let mut e = Ecarts::default();
    for (f, h) in actuel {
        match reference.get(f) {
            None => e.ajoutes.push(f.clone()),
            Some(r) if r != h => e.modifies.push(f.clone()),
            Some(_) => {}
        }
    }
    e.supprimes = reference.keys().filter(|f| !actuel.contains_key(*f)).cloned().collect();
    e
}

/// Constat pour le bilan de la machine.
pub fn constat() -> Constat {
    constat_de(reference(), etat_actuel)
}

/// Le constat d'après la référence retrouvée ; l'état actuel n'est lu que s'il y a de quoi comparer.
fn constat_de(reference: Reference, actuel: impl FnOnce() -> Etat) -> Constat {
    let (reference, adoptee) = match reference {
        Reference::Valable(r) => (r, false),
        Reference::Adoptee(r) => (r, true),
        Reference::Douteuse(pourquoi) => return douteuse(&pourquoi),
        Reference::Absente => {
            return Constat {
                categorie: CAT,
                probleme: Some(Niveau::Info),
                message: tr!(
                    "Pas encore de référence pour les fichiers critiques : « vanguard integrite » la crée.",
                    "No reference yet for critical files: “vanguard integrity” creates it."
                )
                .into(),
                correctif: None,
                verifie: true,
                regle: "",
                objet: crate::modele::Objet::NonMigre,
                precision: crate::modele::Precision::Aucune,
            };
        }
    };
    let mut c = juger(reference.len(), &comparer(&reference, &actuel()));
    if adoptee {
        c.message += tr!(
            " Référence acceptée telle quelle, sans sceau d'avant (voir l'état de Vanguard).",
            " Reference accepted as it was, without an earlier seal (see Vanguard's state)."
        );
    }
    c
}

/// Catégorie du constat.
const CAT: &str = "Intégrité";

/// Le constat d'après les écarts avec une référence de `total` fichiers. Les chemins restent tels quels pour comparer ;
/// montrés, ils sont rendus inoffensifs : un fichier ajouté dans un dossier suivi porte le nom que son auteur a choisi.
fn juger(total: usize, e: &Ecarts) -> Constat {
    if e.vide() {
        return Constat {
            categorie: CAT,
            probleme: None,
            message: trf!(
                "{} fichiers critiques identiques à la référence.",
                "{} critical files identical to the reference.",
                total
            ),
            correctif: None,
            verifie: true,
            regle: "",
            objet: crate::modele::Objet::NonMigre,
            precision: crate::modele::Precision::Aucune,
        };
    }
    let exemples: Vec<String> = e
        .modifies
        .iter()
        .chain(&e.ajoutes)
        .chain(&e.supprimes)
        .map(|f| affichable(f))
        .collect();
    Constat {
        categorie: CAT,
        probleme: Some(Niveau::Moyen),
        message: trf!(
            "{} fichier(s) critique(s) changé(s) depuis la référence : {}. Normal après une mise à jour ; sinon, à examiner (« vanguard integrite »).",
            "{} critical file(s) changed since the reference: {}. Normal after an update; otherwise, worth a look (“vanguard integrity”).",
            e.total(),
            resume(&exemples, 3, ", ")
        ),
        correctif: None,
        verifie: true,
        regle: "",
        objet: crate::modele::Objet::NonMigre,
        precision: crate::modele::Precision::Aucune,
    }
}

/// Les changements déjà notifiés : chaque fichier avec l'état où il a été signalé (son empreinte, ou « - » s'il
/// manquait). Retenir le seul chemin laissait un fichier déjà signalé une fois se faire rechanger (un ~/.bashrc
/// réécrit après un premier changement légitime) sans plus rien notifier. Une liste changée hors de Vanguard (un
/// programme qui y écrit d'avance le fichier qu'il vient de changer), adoptée sans sceau d'avant, abîmée ou
/// illisible ne vaut rien : tout est redit. La forme d'avant (une liste de chemins, sans état) est lue une fois sans
/// état connu : réécrite à la passe même, avec les états.
fn deja_signales(lu: crate::sceau::Lecture) -> BTreeMap<String, Option<String>> {
    let crate::sceau::Lecture::Intact(o) = lu else {
        return BTreeMap::new();
    };
    if let Ok(etats) = serde_json::from_slice::<BTreeMap<String, String>>(&o) {
        return etats.into_iter().map(|(f, h)| (f, Some(h))).collect();
    }
    serde_json::from_slice::<Vec<String>>(&o)
        .unwrap_or_default()
        .into_iter()
        .map(|f| (f, None))
        .collect()
}

/// L'état d'un fichier changé, tel que la surveillance le retient : son empreinte actuelle, ou « - » s'il manque.
fn etat_signale(actuel: &Etat, f: &str) -> String {
    actuel.get(f).cloned().unwrap_or_else(|| "-".to_string())
}

/// Les changements à notifier : ceux pas encore signalés, ou signalés dans un autre état (rechangés depuis).
fn a_notifier(e: &Ecarts, actuel: &Etat, signales: &BTreeMap<String, Option<String>>) -> (Vec<String>, Etat) {
    let tous: Etat = e
        .modifies
        .iter()
        .chain(&e.ajoutes)
        .chain(&e.supprimes)
        .map(|f| (f.clone(), etat_signale(actuel, f)))
        .collect();
    let nouveaux = tous
        .iter()
        .filter(|(f, h)| match signales.get(*f) {
            None => true,
            Some(None) => false,
            Some(Some(avant)) => avant != *h,
        })
        .map(|(f, _)| f.clone())
        .collect();
    (nouveaux, tous)
}

/// Changements pas encore signalés par la surveillance horaire (pour ne prévenir qu'une fois par changement).
pub fn changements_a_signaler() -> Option<String> {
    // Une référence douteuse ne sert pas à juger : le bilan la signale (COM-INT-001), et les sceaux qui la disent
    // changée hors de Vanguard, la surveillance (COM-ETA-001).
    let (Reference::Valable(reference) | Reference::Adoptee(reference)) = reference() else {
        return None;
    };
    let actuel = etat_actuel();
    let e = comparer(&reference, &actuel);
    let signales = deja_signales(crate::sceau::lire(crate::sceau::INTEGRITE_SIGNALE));
    let (nouveaux, tous) = a_notifier(&e, &actuel, &signales);
    if let Ok(t) = serde_json::to_string(&tous) {
        let _ = crate::sceau::ecrire(crate::sceau::INTEGRITE_SIGNALE, t);
    }
    let nouveaux: Vec<String> = nouveaux.iter().map(|f| affichable(f)).collect();
    (!nouveaux.is_empty()).then(|| resume(&nouveaux, 3, ", "))
}

fn afficher(e: &Ecarts) {
    for (liste, marque, libelle) in [
        (&e.modifies, couleur(Niveau::Eleve), tr!("modifié", "modified")),
        (&e.ajoutes, couleur(Niveau::Moyen), tr!("ajouté", "added")),
        (&e.supprimes, couleur(Niveau::Moyen), tr!("supprimé", "removed")),
    ] {
        for f in liste {
            println!("  {marque}{}{RESET} {}", ajuster(libelle, 10), affichable(f));
        }
    }
}

/// « vanguard integrite » : crée la référence au premier passage, puis compare.
pub fn verifier(accepter: bool) {
    titre(tr!("Intégrité des fichiers critiques", "Critical file integrity"));
    let actuel = etat_actuel();
    let reference = reference();
    let adoptee = matches!(reference, Reference::Adoptee(_));
    match reference {
        Reference::Douteuse(pourquoi) if !accepter => trp!(
            "  ✖ La référence ne peut pas servir : rien n'est comparé ni remplacé.\n    {GRIS}{}{RESET}\n  {DISCRET}Après examen, « vanguard integrite --accepter » prend l'état\n  actuel comme référence.{RESET}",
            "  ✖ The reference cannot be used: nothing is compared or replaced.\n    {GRIS}{}{RESET}\n  {DISCRET}After a look, “vanguard integrity --accept” takes the current\n  state as the reference.{RESET}",
            affichable(&pourquoi)
        ),
        Reference::Valable(r) | Reference::Adoptee(r) if !accepter => {
            let e = comparer(&r, &actuel);
            if e.vide() {
                trp!(
                    "  {VERT}✔{RESET} {} fichiers identiques à la référence.",
                    "  {VERT}✔{RESET} {} files identical to the reference.",
                    actuel.len()
                );
            } else {
                afficher(&e);
                trp!(
                    "\n  {DISCRET}Après une mise à jour du système, c'est normal : « vanguard integrite --accepter » prend cet état comme nouvelle référence.{RESET}",
                    "\n  {DISCRET}After a system update, this is normal: “vanguard integrity --accept” takes this state as the new reference.{RESET}"
                );
            }
            // Jamais refaite toute seule : identique à l'état actuel, une référence réécrite par un programme serait
            // ainsi blanchie.
            if adoptee {
                trp!(
                    "  {DISCRET}Référence acceptée telle quelle au passage à cette version, sans sceau\n  d'avant : après examen, « vanguard integrite --accepter » en refait une.{RESET}",
                    "  {DISCRET}Reference accepted as it was when moving to this version, without an\n  earlier seal: after a look, “vanguard integrity --accept” makes a new one.{RESET}"
                );
            }
        }
        _ => {
            if enregistrer(&actuel) {
                trp!(
                    "  {VERT}✔{RESET} Référence enregistrée : {} fichiers critiques.",
                    "  {VERT}✔{RESET} Reference saved: {} critical files.",
                    actuel.len()
                );
                let illisibles = actuel.values().filter(|h| h.starts_with("meta:")).count();
                if illisibles > 0 {
                    trp!(
                        "  {DISCRET}{illisibles} fichier(s) illisible(s) sans droits root, suivi(s) par leur taille et leur date.{RESET}",
                        "  {DISCRET}{illisibles} file(s) unreadable without root rights, tracked by size and date.{RESET}"
                    );
                }
            } else {
                trp!(
                    "  ✖ Référence impossible à enregistrer.",
                    "  ✖ Could not save the reference."
                );
            }
        }
    }
}

/// « vanguard integrite --temps-reel » : surveille les fichiers critiques en direct jusqu'à Ctrl-C.
pub fn temps_reel() {
    use notify::{RecursiveMode, Watcher};
    titre(tr!("Intégrité en temps réel", "Real-time integrity"));
    let reference = match reference() {
        Reference::Valable(r) | Reference::Adoptee(r) => r,
        Reference::Absente => {
            trp!(
                "  Pas encore de référence : lancez d'abord « vanguard integrite ».",
                "  No reference yet: run “vanguard integrity” first."
            );
            return;
        }
        Reference::Douteuse(pourquoi) => {
            trp!(
                "  ✖ La référence ne peut pas servir : « vanguard integrite »\n    le détaille. {GRIS}({}){RESET}",
                "  ✖ The reference cannot be used: “vanguard integrity” details\n    it. {GRIS}({}){RESET}",
                affichable(&pourquoi)
            );
            return;
        }
    };
    let (envoi, reception) = std::sync::mpsc::channel();
    let Ok(mut veilleur) = notify::recommended_watcher(envoi) else {
        trp!(
            "  ✖ Surveillance en direct impossible ici.",
            "  ✖ Live watching not possible here."
        );
        return;
    };
    // On surveille les dossiers qui contiennent les cibles : un fichier remplacé (nouvelle copie) reste suivi.
    let mut dossiers: Vec<PathBuf> = cibles()
        .iter()
        .map(|c| {
            if c.is_dir() {
                c.clone()
            } else {
                c.parent().map(Path::to_path_buf).unwrap_or_default()
            }
        })
        .filter(|d| d.is_dir())
        .collect();
    dossiers.sort();
    dossiers.dedup();
    let suivis = dossiers
        .iter()
        .filter(|d| veilleur.watch(d, RecursiveMode::NonRecursive).is_ok())
        .count();
    trp!(
        "  {VERT}●{RESET} {} dossiers surveillés, {} fichiers de référence. Ctrl-C pour arrêter.\n",
        "  {VERT}●{RESET} {} folders watched, {} reference files. Ctrl-C to stop.\n",
        suivis,
        reference.len()
    );
    let cibles = cibles();
    let concerne = |p: &Path| cibles.iter().any(|c| p == c || p.parent() == Some(c.as_path()));
    // Dernier état signalé par fichier : lire un fichier pour calculer son empreinte produit lui-même un
    // événement ; sans ce garde-fou, la surveillance se relançait sans fin (vu en test : 1 500 alertes en 4 s).
    let mut signale: std::collections::HashMap<String, Option<String>> = std::collections::HashMap::new();
    for evenement in reception.into_iter().flatten() {
        // Seules les vraies modifications comptent : création, écriture, renommage, suppression.
        if matches!(evenement.kind, notify::EventKind::Access(_) | notify::EventKind::Other) {
            continue;
        }
        for p in evenement.paths.iter().filter(|p| concerne(p)) {
            let cle = p.display().to_string();
            let maintenant = empreinte(p);
            if signale.get(&cle) == Some(&maintenant) {
                continue;
            }
            let deja_vu = signale.insert(cle.clone(), maintenant.clone()).flatten().is_some();
            let etat = match (reference.get(&cle), &maintenant) {
                (Some(r), Some(h)) if r == h => continue,
                (Some(_), Some(_)) => tr!("modifié", "modified"),
                (None, Some(_)) if deja_vu => tr!("modifié", "modified"),
                (None, Some(_)) => tr!("ajouté", "added"),
                (Some(_), None) => tr!("supprimé", "removed"),
                (None, None) => continue,
            };
            let heure = chrono::Local::now().format("%H:%M:%S");
            let montre = affichable(&cle);
            println!(
                "  {}{heure}  {}{RESET} {montre}",
                couleur(Niveau::Eleve),
                ajuster(etat, 10)
            );
            crate::reseau::surveillance::notifier(
                &trf!("Vanguard : fichier critique {etat}", "Vanguard: critical file {etat}"),
                &montre,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecarts_avec_la_reference() {
        let reference: Etat = [
            ("/etc/hosts", "b3:aa"),
            ("/etc/passwd", "b3:bb"),
            ("/etc/shadow", "meta:10:1"),
        ]
        .into_iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
        let mut actuel = reference.clone();
        assert!(comparer(&reference, &actuel).vide());
        actuel.insert("/etc/passwd".into(), "b3:cc".into());
        actuel.insert("/etc/sudoers.d/x".into(), "b3:dd".into());
        actuel.remove("/etc/shadow");
        let e = comparer(&reference, &actuel);
        assert_eq!(e.modifies, ["/etc/passwd"]);
        assert_eq!(e.ajoutes, ["/etc/sudoers.d/x"]);
        assert_eq!(e.supprimes, ["/etc/shadow"]);
        assert_eq!(e.total(), 3);
        // Un fichier posé dans un dossier suivi (/etc/cron.d…) au nom piégé : comparé tel quel, montré inoffensif.
        actuel.insert(
            "/etc/cron.d/x\x1b]52;c;eA==\x07\x1b[2K\r\u{202e}".into(),
            "b3:ee".into(),
        );
        let e = comparer(&reference, &actuel);
        assert_eq!(e.ajoutes.len(), 2);
        let c = juger(reference.len(), &e);
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(!crate::ui::contient_un_piege(&c.message), "{}", c.message);
        assert_eq!(juger(3, &Ecarts::default()).probleme, None);
    }

    /// Une référence réécrite à côté de Vanguard (pour rendre un changement « de référence »), abîmée ou supprimée ne
    /// passe jamais pour saine ni pour « pas encore de référence » : non vérifié, et c'est dit.
    #[test]
    fn reference_douteuse_jamais_saine() {
        let c = douteuse("elle a été changée ou supprimée hors de Vanguard");
        assert_eq!((c.probleme, c.verifie), (Some(Niveau::Moyen), false));
        assert!(
            c.message.contains("--accepter") || c.message.contains("--accept"),
            "{}",
            c.message
        );
        let etat: Etat = [("/etc/hosts".to_string(), "b3:aa".to_string())].into_iter().collect();
        assert!(enregistrer(&etat));
        assert!(matches!(reference(), Reference::Valable(r) if r == etat));
        std::fs::write(crate::socle::dossier_local().join(crate::sceau::INTEGRITE), "{}").unwrap();
        assert!(matches!(reference(), Reference::Douteuse(_)));
        assert!(!constat().verifie);
        assert_eq!(changements_a_signaler(), None);
        std::fs::remove_file(crate::socle::dossier_local().join(crate::sceau::INTEGRITE)).unwrap();
        assert!(matches!(reference(), Reference::Douteuse(_)));
        crate::sceau::effacer(crate::sceau::INTEGRITE).unwrap();
        assert!(matches!(reference(), Reference::Absente));
        // Acceptée telle quelle mais abîmée : douteuse.
        let lu = crate::sceau::Lecture::Adopte(b"pas du json".to_vec());
        assert!(matches!(reference_lue(lu, || true), Reference::Douteuse(_)));
        // Manquante alors que les sceaux ont été refaits : douteuse, jamais « pas encore de référence ».
        assert!(matches!(
            reference_lue(crate::sceau::Lecture::Inconnu, || true),
            Reference::Douteuse(_)
        ));
    }

    /// Montée depuis une version d'avant les sceaux (vu dans la VM, de la 0.85.0) : la référence, acceptée telle
    /// quelle, sert encore à comparer. La refuser coupait la vérification, la surveillance horaire et le temps réel
    /// jusqu'à un « --accepter » ; son origine reste dite, et un écart avec elle reste un écart.
    #[test]
    fn reference_adoptee_au_passage_de_version_compare_encore() {
        let etat: Etat = [
            ("/etc/hosts".to_string(), "b3:aa".to_string()),
            ("/etc/passwd".to_string(), "b3:bb".to_string()),
        ]
        .into_iter()
        .collect();
        let lu = crate::sceau::Lecture::Adopte(serde_json::to_vec(&etat).unwrap());
        assert!(matches!(reference_lue(lu, || true), Reference::Adoptee(ref r) if *r == etat));
        // S2c : acceptée telle quelle autrement (premier usage, sceaux refaits : réécrite par qui les a effacés), elle
        // ne sert pas.
        let lu = crate::sceau::Lecture::Adopte(serde_json::to_vec(&etat).unwrap());
        assert!(matches!(reference_lue(lu, || false), Reference::Douteuse(_)));
        let c = constat_de(Reference::Adoptee(etat.clone()), || etat.clone());
        assert_eq!((c.probleme, c.verifie), (None, true), "{}", c.message);
        assert!(
            c.message.contains("identiques") || c.message.contains("identical"),
            "{}",
            c.message
        );
        assert!(
            c.message.contains("sceau") || c.message.contains("seal"),
            "{}",
            c.message
        );
        let mut change = etat.clone();
        change.insert("/etc/passwd".into(), "b3:cc".into());
        let c = constat_de(Reference::Adoptee(etat), || change);
        assert_eq!((c.probleme, c.verifie), (Some(Niveau::Moyen), true), "{}", c.message);
        assert!(c.message.contains("/etc/passwd"), "{}", c.message);
    }

    /// Un programme qui change ~/.bashrc et l'écrit d'avance dans la liste des changements déjà signalés : la liste,
    /// posée hors de Vanguard, ne tait rien.
    #[test]
    fn changements_signales_poses_a_cote_ne_taisent_rien() {
        use crate::sceau::Lecture;
        let liste = br#"{"/home/alice/.bashrc":"b3:aa"}"#.to_vec();
        let attendu: BTreeMap<String, Option<String>> =
            [("/home/alice/.bashrc".to_string(), Some("b3:aa".to_string()))].into();
        assert_eq!(deja_signales(Lecture::Intact(liste.clone())), attendu);
        assert!(deja_signales(Lecture::Falsifie(Some(liste.clone()))).is_empty());
        assert!(deja_signales(Lecture::Adopte(liste)).is_empty());
        assert!(deja_signales(Lecture::Absent).is_empty());
        assert!(deja_signales(Lecture::Inconnu).is_empty());
        // La forme d'avant : des chemins sans état.
        let ancienne = deja_signales(Lecture::Intact(br#"["/home/alice/.bashrc"]"#.to_vec()));
        assert_eq!(ancienne.get("/home/alice/.bashrc"), Some(&None));
    }

    /// Un ~/.bashrc déjà signalé une fois, puis rechangé par un autre programme : redit. Le même état : pas redit.
    #[test]
    fn un_fichier_rechange_se_renotifie() {
        let bashrc = "/home/alice/.bashrc".to_string();
        let reference: Etat = [(bashrc.clone(), "b3:00".to_string())].into();
        let premier: Etat = [(bashrc.clone(), "b3:aa".to_string())].into();
        let e = comparer(&reference, &premier);
        let (nouveaux, retenus) = a_notifier(&e, &premier, &BTreeMap::new());
        assert_eq!(nouveaux, vec![bashrc.clone()]);
        let signales: BTreeMap<String, Option<String>> = retenus.into_iter().map(|(f, h)| (f, Some(h))).collect();
        assert_eq!(a_notifier(&e, &premier, &signales).0, Vec::<String>::new());
        let second: Etat = [(bashrc.clone(), "b3:bb".to_string())].into();
        let e = comparer(&reference, &second);
        assert_eq!(a_notifier(&e, &second, &signales).0, vec![bashrc.clone()]);
        // Supprimé ensuite : un autre état, redit aussi.
        let e = comparer(&reference, &Etat::new());
        assert_eq!(a_notifier(&e, &Etat::new(), &signales).0, vec![bashrc.clone()]);
        // La forme d'avant (sans état) ne renotifie pas à la mise à jour ; la passe la réécrit avec les états.
        let ancienne: BTreeMap<String, Option<String>> = [(bashrc, None)].into();
        assert_eq!(a_notifier(&e, &Etat::new(), &ancienne).0, Vec::<String>::new());
    }

    #[test]
    fn empreinte_lisible() {
        let f = std::env::temp_dir().join(format!("vanguard-integrite-{}", std::process::id()));
        std::fs::write(&f, b"abc").unwrap();
        let h = empreinte(&f).unwrap();
        // BLAKE3 de « abc ».
        assert_eq!(h, "b3:6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85");
        let _ = std::fs::remove_file(&f);
    }
}

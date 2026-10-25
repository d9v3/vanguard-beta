//! Durcissement de macOS, lu sans droits d'administrateur : volume du système scellé et signé (SSV), signature du
//! code imposée au démarrage (AMFI), validation des bibliothèques, extensions du noyau et du système ajoutées par
//! d'autres qu'Apple, visibilité d'AirDrop, découverte automatique du proxy.

use std::process::Command;

use super::{Constat, alerte, impossible, ok, preference, sortie};
use crate::risk::Niveau;
use crate::{tr, trf};

/// « Authenticated Root status: enabled » : le volume du système est scellé ; la moindre modification casse le sceau.
fn lire_racine_authentifiee(texte: &str) -> Option<bool> {
    let etat = texte.split("status:").nth(1)?.trim();
    Some(etat.starts_with("enabled"))
}

/// Options de démarrage qui coupent la vérification des signatures du code (AMFI). Réservées au développement de
/// pilotes, elles laissent n'importe quel programme s'exécuter, même modifié.
fn options_dangereuses(boot_args: &str) -> Vec<&str> {
    const COUPENT_AMFI: [&str; 4] = [
        "amfi_get_out_of_my_way",
        "cs_enforcement_disable",
        "amfi_allow_any_signature",
        "amfi_unrestrict_task_for_pid",
    ];
    boot_args
        .split_whitespace()
        .filter(|o| COUPENT_AMFI.iter().any(|d| o.starts_with(d)))
        .collect()
}

/// Les options du prochain démarrage (NVRAM « boot-args ») : lues dans l'IORegistry, `nvram boot-args` en secours
/// tant que l'oracle de macos.yml n'a pas prouvé la lecture native. Vide : aucune option. `None` : illisibles.
fn options_prochain_demarrage() -> Option<String> {
    use super::noyau::OptionsNvram;
    match super::noyau::options_prochain_demarrage() {
        Some(OptionsNvram::Absentes) => Some(String::new()),
        Some(OptionsNvram::Posees(t)) => Some(t),
        // nvram répond en erreur « data was not found » quand boot-args n'existe pas : le cas normal. Toute autre
        // erreur (NVRAM non prise en charge, refus) est une lecture ratée, jamais « aucune option ».
        None => crate::commande::lancer(Command::new("nvram").arg("boot-args"), 10).and_then(|r| {
            if r.code == Some(0) {
                Some(
                    r.sortie
                        .trim()
                        .strip_prefix("boot-args")
                        .unwrap_or(&r.sortie)
                        .trim()
                        .to_string(),
                )
            } else {
                r.erreurs.contains("not found").then(String::new)
            }
        }),
    }
}

/// Les options qui coupent la signature du code, jugées au démarrage EN COURS (kern.bootargs : ce qui protège ce Mac
/// maintenant) et au PROCHAIN (la NVRAM : ce qu'un programme y a posé en attendant un redémarrage). Le constat dit
/// lequel ; une moitié illisible est dite, jamais comptée saine.
fn juger_options_demarrage(en_cours: Option<&str>, prochain: Option<&str>) -> Constat {
    let dangers_en_cours = en_cours.map(options_dangereuses).unwrap_or_default();
    let dangers_prochain = prochain.map(options_dangereuses).unwrap_or_default();
    if !dangers_en_cours.is_empty() || !dangers_prochain.is_empty() {
        let quand = match (dangers_en_cours.is_empty(), dangers_prochain.is_empty()) {
            (false, false) => trf!(
                "au démarrage en cours et au prochain : {}",
                "in the current startup and the next one: {}",
                dangers_en_cours.join(" ")
            ),
            (false, true) => trf!(
                "au démarrage en cours seulement : {}",
                "in the current startup only: {}",
                dangers_en_cours.join(" ")
            ),
            _ => trf!(
                "au prochain démarrage : {}",
                "at the next startup: {}",
                dangers_prochain.join(" ")
            ),
        };
        let constat = alerte(
            "Protection système",
            Niveau::Eleve,
            trf!(
                "Une option de démarrage coupe la vérification des signatures du code ({quand}) : n'importe quel programme peut s'exécuter, même modifié.",
                "A startup option turns code signature checks off ({quand}): any program can run, even modified."
            ),
        );
        // Plus dans la NVRAM (lue) : un redémarrage suffit.
        if dangers_prochain.is_empty() && prochain.is_some() {
            return constat.manuel(
                tr!(
                    "L'option n'est plus dans la NVRAM : redémarrer ce Mac suffit à remettre la vérification des signatures",
                    "The option is no longer in NVRAM: restarting this Mac is enough to turn signature checks back on"
                ),
                &[],
            );
        }
        return constat
        .manuel(
            tr!(
                "Retirer les options de démarrage : sudo nvram -d boot-args (sur Apple Silicon, depuis le Terminal du mode de secours), puis redémarrer",
                "Remove the startup options: sudo nvram -d boot-args (on Apple Silicon, from the Recovery Terminal), then restart"
            ),
            &["sudo nvram -d boot-args"],
        );
    }
    match (en_cours, prochain) {
        (Some(_), Some(_)) => ok(
            "Protection système",
            tr!(
                "Signature du code imposée dès le démarrage (aucune option ne la coupe, ni au démarrage en cours ni au prochain).",
                "Code signing enforced from startup (no option turns it off, in the current startup or the next one)."
            ),
        ),
        (None, Some(_)) => impossible(
            "Protection système",
            tr!(
                "options du démarrage en cours illisibles (kern.bootargs)",
                "current startup options unreadable (kern.bootargs)"
            ),
        ),
        (Some(_), None) => impossible(
            "Protection système",
            tr!(
                "options du prochain démarrage illisibles (nvram)",
                "next startup options unreadable (nvram)"
            ),
        ),
        (None, None) => impossible(
            "Protection système",
            tr!(
                "options de démarrage illisibles (kern.bootargs et nvram)",
                "startup options unreadable (kern.bootargs and nvram)"
            ),
        ),
    }
}

pub(super) fn systeme_signe() -> Vec<Constat> {
    let mut constats = Vec::new();
    match sortie("csrutil", &["authenticated-root", "status"])
        .as_deref()
        .and_then(lire_racine_authentifiee)
    {
        Some(true) => constats.push(ok(
            "Protection système",
            tr!(
                "Volume du système scellé et signé par Apple (SSV).",
                "System volume sealed and signed by Apple (SSV)."
            ),
        )),
        Some(false) => constats.push(
            alerte(
                "Protection système",
                Niveau::Eleve,
                tr!(
                    "Le sceau du volume du système (SSV) est désactivé : macOS lui-même peut être modifié sans que rien ne le remarque.",
                    "The system volume seal (SSV) is off: macOS itself can be modified without anything noticing."
                ),
            )
            .manuel(
                tr!(
                    "Redémarrer en mode de secours, Utilitaires > Terminal : csrutil authenticated-root enable, puis redémarrer",
                    "Restart in Recovery, Utilities > Terminal: csrutil authenticated-root enable, then restart"
                ),
                &[],
            ),
        ),
        None => constats.push(impossible(
            "Protection système",
            tr!(
                "état du sceau du système illisible (csrutil)",
                "system seal state unreadable (csrutil)"
            ),
        )),
    }
    constats.push(juger_options_demarrage(
        super::noyau::options_demarrage_en_cours().as_deref(),
        options_prochain_demarrage().as_deref(),
    ));
    // Clé absente : la validation est active (réglage d'origine).
    let validation = preference(
        "/Library/Preferences/com.apple.security.libraryvalidation",
        "DisableLibraryValidation",
    );
    constats.push(if validation.as_deref() == Some("1") {
        alerte(
            "Protection système",
            Niveau::Moyen,
            tr!(
                "La validation des bibliothèques est désactivée : un programme peut charger du code qui n'est signé ni par Apple ni par son éditeur.",
                "Library validation is off: a program can load code signed neither by Apple nor by its developer."
            ),
        )
        .corriger(
            tr!("Réactiver la validation des bibliothèques", "Turn library validation back on"),
            &["sudo defaults delete /Library/Preferences/com.apple.security.libraryvalidation DisableLibraryValidation"],
        )
        .protection()
    } else {
        ok(
            "Protection système",
            tr!(
                "Validation des bibliothèques active : seul du code signé se charge dans les programmes.",
                "Library validation on: only signed code loads into programs."
            ),
        )
    });
    constats
}

/// Un nom d'extension (« com.vmware.kext.vmx86 ») : commence par une lettre, au moins trois parties.
fn identifiant(mot: &str) -> bool {
    mot.starts_with(|c: char| c.is_ascii_alphabetic())
        && mot.split('.').count() >= 3
        && mot.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

/// `kmutil showloaded` : les extensions du noyau chargées, sans celles d'Apple.
fn extensions_noyau(texte: &str) -> Vec<String> {
    let mut l: Vec<String> = texte
        .lines()
        .filter_map(|ligne| ligne.split_whitespace().find(|m| identifiant(m)))
        .filter(|id| !id.starts_with("com.apple."))
        .map(str::to_string)
        .collect();
    l.sort_unstable();
    l.dedup();
    l
}

/// `systemextensionsctl list` : les extensions du système actives (VPN, antivirus, pilotes), « nom (identifiant) »,
/// prêtes à montrer (l'éditeur de l'extension choisit son nom).
fn extensions_systeme(texte: &str) -> Vec<String> {
    texte
        .lines()
        .filter(|l| l.contains("[activated enabled]"))
        .filter_map(|l| {
            let c: Vec<&str> = l.split('\t').map(str::trim).collect();
            let id = c.get(3)?.split_whitespace().next()?;
            let nom = c.get(4).copied().filter(|n| !n.is_empty()).unwrap_or(id);
            Some(crate::ui::affichable(&format!("{nom} ({id})")))
        })
        .collect()
}

pub(super) fn extensions_tierces() -> Constat {
    let (Some(noyau), Some(systeme)) = (
        sortie("kmutil", &["showloaded"]),
        sortie("systemextensionsctl", &["list"]),
    ) else {
        return impossible(
            "Pilotes",
            tr!(
                "extensions du noyau et du système illisibles (kmutil, systemextensionsctl)",
                "kernel and system extensions unreadable (kmutil, systemextensionsctl)"
            ),
        );
    };
    juger_extensions(&noyau, &systeme)
}

/// Le jugement des sorties de « kmutil showloaded » (`noyau`) et « systemextensionsctl list » (`systeme`) : séparé de
/// leur lecture pour que le corpus de détection l'exerce.
pub(super) fn juger_extensions(noyau: &str, systeme: &str) -> Constat {
    let tierces: Vec<String> = extensions_noyau(noyau)
        .into_iter()
        .chain(extensions_systeme(systeme))
        .collect();
    if tierces.is_empty() {
        return ok(
            "Pilotes",
            tr!(
                "Aucune extension du noyau ni du système ajoutée par un autre qu'Apple.",
                "No kernel or system extension added by anyone but Apple."
            ),
        );
    }
    alerte(
        "Pilotes",
        Niveau::Info,
        trf!(
            "Extensions ajoutées par d'autres qu'Apple : {}. Normal pour un VPN, un antivirus ou un pilote de matériel ; une inconnue est à vérifier (elle voit tout ce que fait le Mac).",
            "Extensions added by others than Apple: {}. Normal for a VPN, an antivirus or a hardware driver; an unknown one is worth checking (it sees everything the Mac does).",
            tierces.join(", ")
        ),
    )
    .manuel(
        tr!(
            "Réglages Système > Général > Éléments de connexion et extensions : retirer celle qu'on ne connaît pas (et son application)",
            "System Settings > General > Login Items & Extensions: remove the one you do not know (and its app)"
        ),
        &[],
    )
}

/// AirDrop ouvert à tous : des inconnus à portée (train, café) peuvent proposer des fichiers, et voient le nom du Mac.
pub(super) fn airdrop() -> Option<Constat> {
    let mode = preference("com.apple.sharingd", "DiscoverableMode")?;
    Some(if mode.starts_with("Everyone") {
        alerte(
            "AirDrop",
            Niveau::Info,
            tr!(
                "AirDrop est visible par tout le monde : des inconnus à proximité peuvent vous envoyer des fichiers et voient le nom de ce Mac.",
                "AirDrop is visible to everyone: strangers nearby can send you files and see this Mac's name."
            ),
        )
        .corriger(
            tr!("AirDrop pour les contacts seulement", "AirDrop for contacts only"),
            &[
                "defaults write com.apple.sharingd DiscoverableMode -string \"Contacts Only\"",
                "killall sharingd 2>/dev/null; true",
            ],
        )
        .annulable(vec![crate::optimiser::Geste::preference("com.apple.sharingd", "DiscoverableMode")])
    } else {
        ok("AirDrop", trf!("AirDrop : {mode}.", "AirDrop: {mode}."))
    })
}

/// Découverte automatique du proxy (WPAD), coupée par défaut sur Mac : allumée sur un service réseau, n'importe quel
/// appareil d'un Wi-Fi public peut répondre et faire passer la navigation par lui. `scutil --proxy` donne la réunion
/// des réglages en service. Changer un service réseau demande le mot de passe d'un administrateur et le nom du service
/// (« Wi-Fi ») : à faire soi-même, la commande montrée en exemple.
pub(super) fn juger_decouverte_proxy(scutil: &str) -> Option<Constat> {
    let allumee = scutil.lines().any(|l| {
        let mut c = l.split(':').map(str::trim);
        c.next() == Some("ProxyAutoDiscoveryEnable") && c.next() == Some("1")
    });
    allumee.then(|| {
        alerte(
            "Durcissement",
            Niveau::Moyen,
            tr!(
                "Le Mac cherche son proxy tout seul sur le réseau (WPAD) : sur un Wi-Fi public, un autre appareil peut répondre et faire passer votre navigation par lui.",
                "The Mac looks for its proxy by itself on the network (WPAD): on public Wi-Fi, another device can answer and route your browsing through itself."
            ),
        )
        .manuel(
            tr!(
                "Réglages Système > Réseau > votre connexion > Détails > Proxys : décochez « Découverte automatique du proxy »",
                "System Settings > Network > your connection > Details > Proxies: untick “Auto proxy discovery”"
            ),
            &["networksetup -setproxyautodiscovery Wi-Fi off"],
        )
    })
}

/// Le proxy en vigueur demandé à configd ; `scutil --proxy` en secours tant que l'oracle de macos.yml n'a pas prouvé
/// la lecture native.
pub(super) fn decouverte_proxy() -> Option<Constat> {
    let texte = super::config_reseau::proxy_comme_scutil().or_else(|| sortie("scutil", &["--proxy"]))?;
    juger_decouverte_proxy(&texte)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decouverte_automatique_du_proxy() {
        let coupee =
            "<dictionary> {\n  ExceptionsList : <array> {\n  }\n  FTPPassive : 1\n  ProxyAutoDiscoveryEnable : 0\n}\n";
        assert!(juger_decouverte_proxy(coupee).is_none() && juger_decouverte_proxy("").is_none());
        let allumee = juger_decouverte_proxy("<dictionary> {\n  ProxyAutoDiscoveryEnable : 1\n}\n").unwrap();
        assert_eq!(allumee.probleme, Some(Niveau::Moyen));
        assert!(!allumee.correctif.unwrap().automatique);
    }

    #[test]
    fn sceau_et_options_de_demarrage() {
        assert_eq!(
            lire_racine_authentifiee("Authenticated Root status: enabled\n"),
            Some(true)
        );
        assert_eq!(
            lire_racine_authentifiee("Authenticated Root status: disabled\n"),
            Some(false)
        );
        assert_eq!(lire_racine_authentifiee("autre"), None);
        assert_eq!(
            options_dangereuses("boot-args\t-v amfi_get_out_of_my_way=1"),
            ["amfi_get_out_of_my_way=1"]
        );
        assert_eq!(options_dangereuses("boot-args\t-v keepsyms=1"), Vec::<&str>::new());
    }

    /// Les deux démarrages jugés, et lequel est dit ; une moitié illisible n'est jamais saine.
    #[test]
    fn options_des_deux_demarrages() {
        let dangereuse = "amfi_get_out_of_my_way=1";
        let c = juger_options_demarrage(Some(""), Some(dangereuse));
        assert!(
            c.probleme.is_some() && c.message.contains(tr!("prochain", "next")),
            "{}",
            c.message
        );
        let c = juger_options_demarrage(Some(dangereuse), Some(""));
        assert!(
            c.probleme.is_some() && c.message.contains(tr!("en cours seulement", "current startup only")),
            "{}",
            c.message
        );
        let c = juger_options_demarrage(Some("-v"), Some(""));
        assert!(c.verifie && c.probleme.is_none());
        for (a, b) in [(None, Some("")), (Some(""), None), (None, None)] {
            assert!(!juger_options_demarrage(a, b).verifie, "{a:?} {b:?}");
        }
        // Une option dangereuse se voit même si l'autre moitié est illisible.
        assert!(juger_options_demarrage(None, Some(dangereuse)).probleme.is_some());
    }

    #[test]
    fn extensions_lues() {
        let kmutil = "Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>\n\
                        1  152 0                  0          0          com.apple.kpi.bsd (24.0.0) 0A1B <>\n\
                      182    0 0xfffffe0007b4c000 0x8000     0x8000     com.vmware.kext.vmx86 (17.5.2) 9C2D-11 <8 6 5 3 1>\n";
        assert_eq!(extensions_noyau(kmutil), ["com.vmware.kext.vmx86"]);
        let ctl = "2 extension(s)\n--- com.apple.system_extension.network_extension\n\
                   enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n\
                   *\t*\tABCDE12345\tcom.exemple.vpn.extension (1.0/1)\tExemple VPN\t[activated enabled]\n\
                   \t\tABCDE12345\tcom.exemple.vieux (0.9/1)\tVieux\t[terminated waiting to uninstall on reboot]\n";
        assert_eq!(extensions_systeme(ctl), ["Exemple VPN (com.exemple.vpn.extension)"]);
        let piege = "*\t*\tABCDE12345\tcom.exemple.vpn (1.0/1)\tVPN\x1b]0;t\x07\u{202e}\t[activated enabled]\n";
        assert_eq!(extensions_systeme(piege), ["VPN�]0;t�� (com.exemple.vpn)"]);
    }
}

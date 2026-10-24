//! Mots de passe enregistrés dans les navigateurs : combien, et par quoi ils sont protégés. Firefox (et ses cousins)
//! les garde dans logins.json, chiffrés avec key4.db ; sans mot de passe principal, la clé est sur le disque à côté et
//! qui ouvre ta session (ou un programme malveillant) les lit tous ; Vanguard ne peut pas voir si ce mot de passe
//! principal est défini, et le dit. Chrome, Edge, Brave, Vivaldi et Chromium les gardent dans la base « Login Data »,
//! protégés seulement par la session (DPAPI sous Windows, trousseau sous macOS, porte-clés ou rien sous Linux). Vanguard
//! compte les entrées sans en lire une seule : logins.json est compté dans sa structure, la base SQLite est parcourue
//! page par page pour compter les lignes de la table « logins », sans décoder leur contenu ni dépendre de SQLite.

use std::path::Path;

use super::{Constat, alerte, impossible, ok};
use crate::risk::Niveau;
use crate::ui::*;

const CAT: &str = "Navigateur";

/// Les identifiants d'un profil : combien, et ce qui les protège.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Profil {
    navigateur: &'static str,
    nom: String,
    identifiants: usize,
    firefox: bool,
}

/// logins.json de Firefox : le nombre d'entrées de « logins » (chacune porte un site et deux champs chiffrés, qu'on
/// ne touche pas).
pub(super) fn compter_firefox(texte: &str) -> Option<usize> {
    let v: serde_json::Value = serde_json::from_str(texte).ok()?;
    Some(v.get("logins")?.as_array()?.len())
}

// ───────────────────────────── Les profils ─────────────────────────────

/// La taille de logins.json lue au plus : quelques Ko par identifiant, des milliers d'identifiants tiennent dedans.
const LOGINS_MAX: u64 = 32 << 20;

/// Les profils des navigateurs installés et ce qu'ils gardent ; `Err` : le fichier existe mais ne se lit pas.
fn profils() -> Vec<Result<Profil, (String, String)>> {
    let mut liste = Vec::new();
    for (navigateur, racine, firefox) in super::extensions::racines() {
        for (nom, chemin) in super::extensions::profils(&racine, firefox) {
            if firefox {
                let f = chemin.join("logins.json");
                if !f.is_file() {
                    continue;
                }
                // Un simple fichier, borné : un fichier creux énorme ou un tube posé là par un programme du compte ne
                // remplit pas la mémoire et ne fige pas le bilan ; il est dit illisible.
                let texte = crate::socle::lire_texte_ordinaire(&f, LOGINS_MAX).ok();
                match texte.and_then(|t| compter_firefox(&t)) {
                    Some(n) => liste.push(Ok(Profil {
                        navigateur,
                        nom,
                        identifiants: n,
                        firefox: true,
                    })),
                    None => liste.push(Err((navigateur.to_string(), format!("{nom}/logins.json")))),
                }
            } else {
                let mut total = 0;
                let mut lus = 0;
                for base in ["Login Data", "Login Data For Account"] {
                    let f = chemin.join(base);
                    if !f.is_file() {
                        continue;
                    }
                    match compter_base(&f) {
                        Some(n) => {
                            total += n;
                            lus += 1;
                        }
                        None => liste.push(Err((navigateur.to_string(), format!("{nom}/{base}")))),
                    }
                }
                if lus > 0 {
                    liste.push(Ok(Profil {
                        navigateur,
                        nom,
                        identifiants: total,
                        firefox: false,
                    }));
                }
            }
        }
    }
    liste
}

/// Les lignes de « logins » d'une base, lue d'un coup (quelques Mo au plus : au-delà, on renonce).
fn compter_base(chemin: &Path) -> Option<usize> {
    let taille = std::fs::metadata(chemin).ok()?.len();
    if taille > 64 << 20 {
        return None;
    }
    crate::sqlite::compter_lignes(&std::fs::read(chemin).ok()?, "logins")
}

/// Ce qui protège les identifiants d'un navigateur Chromium sur ce système.
fn protection_chromium() -> &'static str {
    if cfg!(windows) {
        tr!(
            "protégés par votre session Windows seulement (DPAPI) : qui ouvre votre session, ou un programme qui tourne dedans, les lit",
            "protected by your Windows session only (DPAPI): whoever opens your session, or a program running in it, reads them"
        )
    } else if cfg!(target_os = "macos") {
        tr!(
            "la clé est dans le trousseau : un programme qui tourne dans votre session peut la demander",
            "the key is in the keychain: a program running in your session can ask for it"
        )
    } else {
        tr!(
            "la clé est dans le porte-clés du bureau, ou en clair s'il n'y en a pas : qui ouvre votre session les lit",
            "the key is in the desktop keyring, or in clear if there is none: whoever opens your session reads them"
        )
    }
}

pub(super) fn juger(profils: &[Result<Profil, (String, String)>]) -> Vec<Constat> {
    let mut constats = Vec::new();
    for (navigateur, fichier) in profils.iter().filter_map(|p| p.as_ref().err()) {
        constats.push(impossible(
            CAT,
            &trf!(
                "{navigateur} : {fichier} illisible",
                "{navigateur}: {fichier} unreadable"
            ),
        ));
    }
    let pleins: Vec<&Profil> = profils.iter().flatten().filter(|p| p.identifiants > 0).collect();
    let total: usize = pleins.iter().map(|p| p.identifiants).sum();
    if pleins.is_empty() {
        if profils.iter().any(Result::is_ok) {
            constats.push(ok(
                CAT,
                tr!(
                    "Aucun mot de passe enregistré dans les navigateurs.",
                    "No password saved in the browsers."
                ),
            ));
        }
        return constats;
    }
    let ou: Vec<String> = pleins
        .iter()
        .map(|p| {
            if p.nom == "Default" || p.nom == "default" {
                format!("{} ({})", p.navigateur, p.identifiants)
            } else {
                format!("{} « {} » ({})", p.navigateur, p.nom, p.identifiants)
            }
        })
        .collect();
    let firefox = pleins.iter().any(|p| p.firefox);
    let chromium = pleins.iter().any(|p| !p.firefox);
    let mut protection = Vec::new();
    if firefox {
        protection.push(tr!(
            "Firefox : Vanguard ne peut pas voir si un mot de passe principal les protège ; sans lui, qui ouvre votre session les lit tous",
            "Firefox: Vanguard cannot see whether a primary password protects them; without one, whoever opens your session reads them all"
        ).to_string());
    }
    if chromium {
        protection.push(trf!(
            "Chrome et cousins : {}",
            "Chrome and similar browsers: {}",
            protection_chromium()
        ));
    }
    constats.push(
        alerte(
            CAT,
            Niveau::Info,
            trf!(
                "{total} mot(s) de passe enregistré(s) dans {} : {}. Comptés seulement, jamais lus.",
                "{total} saved password(s) in {}: {}. Counted only, never read.",
                ou.join(", "),
                protection.join(" ; ")
            ),
        )
        .manuel(
            if firefox {
                tr!(
                    "Un gestionnaire de mots de passe (Bitwarden, KeePassXC), ou au moins le mot de passe principal de Firefox (Paramètres > Vie privée et sécurité > Identifiants)",
                    "A password manager (Bitwarden, KeePassXC), or at least Firefox's primary password (Settings > Privacy & Security > Logins)"
                )
            } else {
                tr!(
                    "Un gestionnaire de mots de passe (Bitwarden, KeePassXC) avec son propre mot de passe principal, et le verrouillage de l'écran quand vous vous éloignez",
                    "A password manager (Bitwarden, KeePassXC) with its own primary password, and the screen lock when you step away"
                )
            },
            &[],
        ),
    );
    constats
}

/// Au bilan.
pub fn constats() -> Vec<Constat> {
    juger(&profils())
}

// ───────────────────────────── La commande « navigateurs » ─────────────────────────────

/// La vérification intégrée d'un navigateur présent, à conseiller à la personne : c'est elle qui
/// trouve les mots de passe faibles, réutilisés ou compromis, en sécurité, dans le navigateur.
#[derive(Debug, PartialEq, Eq)]
enum Checkup {
    Firefox,
    Chrome,
    Edge,
    Autre(&'static str),
}

/// Quelles vérifications intégrées montrer, d'après les familles qui ont des mots de passe
/// enregistrés (sans doublon, dans l'ordre où elles apparaissent). Un profil illisible n'invente
/// pas une famille ; un profil vide non plus.
fn checkups(profils: &[Result<Profil, (String, String)>]) -> Vec<Checkup> {
    let mut v: Vec<Checkup> = Vec::new();
    for p in profils.iter().flatten().filter(|p| p.identifiants > 0) {
        let c = if p.firefox {
            Checkup::Firefox
        } else {
            match p.navigateur {
                "Chrome" | "Chromium" => Checkup::Chrome,
                "Edge" => Checkup::Edge,
                autre => Checkup::Autre(autre),
            }
        };
        if !v.contains(&c) {
            v.push(c);
        }
    }
    v
}

/// « vanguard mots-de-passe-navigateurs » : l'état des mots de passe enregistrés dans les navigateurs (comptés,
/// jamais lus), où lancer la vérification intégrée de chaque navigateur pour trouver les faibles,
/// réutilisés et compromis, puis la vérification HIBP d'un mot de passe tapé. Vanguard ne lit ni ne
/// déchiffre jamais un mot de passe enregistré : les lire, c'est le geste d'un voleur de mots de
/// passe, et un antivirus classerait alors Vanguard comme malveillant.
pub(crate) fn navigateurs() {
    titre(tr!("Mots de passe des navigateurs", "Browser passwords"));
    let profils = profils();
    // 1. L'état, repris du bilan : comptés, jamais lus.
    let constats = juger(&profils);
    if constats.is_empty() {
        trp!(
            "  Aucun navigateur avec des mots de passe enregistrés n'a été trouvé.",
            "  No browser with saved passwords was found."
        );
    } else {
        for constat in &constats {
            let puce = match constat.probleme {
                None => format!("{VERT}✔{RESET}"),
                Some(niveau) => format!("{}•{RESET}", couleur(niveau)),
            };
            // Un message long (plusieurs navigateurs) se coupe aux espaces, la suite sous le premier mot.
            for (i, ligne) in envelopper(&constat.message, LARGEUR - 4).into_iter().enumerate() {
                let marque = if i == 0 { puce.as_str() } else { " " };
                println!("  {marque} {ligne}");
            }
        }
    }
    // 2. Ce que Vanguard ne fait pas, et pourquoi : c'est une garantie, pas une limite.
    trp!(
        "\n  {GRIS}Vanguard ne lit ni ne déchiffre jamais vos mots de passe enregistrés : les lire, c'est le\n  geste d'un voleur de mots de passe. Il les compte seulement, et vous renvoie à votre navigateur.{RESET}",
        "\n  {GRIS}Vanguard never reads or decrypts your saved passwords: reading them is what a password\n  stealer does. It only counts them, and points you to your browser.{RESET}"
    );
    // 3. La vérification intégrée de chaque navigateur présent (faibles, réutilisés, compromis).
    let a_montrer = checkups(&profils);
    if !a_montrer.is_empty() {
        // Enveloppé ici, à 76 colonnes, sous le conseil : un retour à la ligne écrit dans le texte tombait au milieu
        // de la phrase une fois la première ligne recoupée par l'affichage.
        println!();
        let conseil = tr!(
            "Pour les mots de passe faibles, réutilisés ou compromis, ouvrez la vérification intégrée de votre navigateur, en copiant l'adresse dans sa barre :",
            "For weak, reused or compromised passwords, open your browser's built-in check (paste the address into its bar):"
        );
        for (i, ligne) in envelopper(conseil, LARGEUR - 5).into_iter().enumerate() {
            let marque = if i == 0 { ampoule() } else { "  " };
            println!("  {marque} {ligne}");
        }
        for c in a_montrer {
            let (quoi, adresse): (&str, &str) = match c {
                Checkup::Firefox => (tr!("Firefox et cousins", "Firefox and similar"), "about:logins"),
                Checkup::Chrome => ("Chrome / Chromium", "chrome://password-manager/checkup"),
                Checkup::Edge => ("Edge", "edge://settings/passwords"),
                Checkup::Autre(nom) => (
                    nom,
                    tr!(
                        "gestionnaire de mots de passe du navigateur",
                        "the browser's password manager"
                    ),
                ),
            };
            println!("       {quoi} : {GRIS}{adresse}{RESET}");
        }
    }
    // 4. Vérifier un mot de passe précis, tapé maintenant : jamais affiché, jamais écrit, seuls 5
    //    caractères de son empreinte partent (réutilise la vérification HIBP existante).
    trp!(
        "\n  Vous pouvez vérifier un mot de passe précis : il ne s'affiche pas, ne quitte pas cet\n  ordinateur, et seuls 5 caractères de son empreinte partent vers Have I Been Pwned.",
        "\n  You can also check a specific password: it is not shown, it does not leave this computer,\n  and only 5 characters of its fingerprint are sent to Have I Been Pwned."
    );
    if demander(tr!(
        "  Vérifier un mot de passe maintenant ? [o/N] : ",
        "  Check a password now? [y/N]: "
    ))
    .oui()
    {
        println!();
        crate::protection::fuites::verifier();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logins_de_firefox_comptes_sans_les_lire() {
        let texte = r#"{"nextId":3,"logins":[{"id":1,"hostname":"https://exemple.test","encryptedUsername":"MDoE","encryptedPassword":"MFIE","encType":1},{"id":2,"hostname":"https://autre.test","encryptedUsername":"MDoE","encryptedPassword":"MFIE","encType":1}],"potentiallyVulnerablePasswords":[],"dismissedBreachAlertsByLoginGUID":{},"version":3}"#;
        assert_eq!(compter_firefox(texte), Some(2));
        assert_eq!(compter_firefox(r#"{"nextId":1,"logins":[],"version":3}"#), Some(0));
        assert_eq!(compter_firefox("pas du json"), None);
        assert_eq!(compter_firefox(r#"{"version":3}"#), None);
    }

    #[test]
    fn jugement_selon_les_profils() {
        let profil = |navigateur, nom: &str, n, firefox| Profil {
            navigateur,
            nom: nom.into(),
            identifiants: n,
            firefox,
        };
        assert!(juger(&[]).is_empty());
        let rien = juger(&[Ok(profil("Chrome", "Default", 0, false))]);
        assert_eq!(rien.len(), 1);
        assert_eq!(rien[0].probleme, None);
        let c = juger(&[
            Ok(profil("Firefox", "abc.default-release", 12, true)),
            Ok(profil("Chrome", "Default", 3, false)),
            Ok(profil("Brave", "Default", 0, false)),
            Err(("Edge".into(), "Default/Login Data".into())),
        ]);
        assert_eq!(c.len(), 2);
        assert!(!c[0].verifie && c[0].message.contains("Edge"));
        assert_eq!(c[1].probleme, Some(Niveau::Info));
        assert!(c[1].message.starts_with("15 mot(s) de passe"), "{}", c[1].message);
        assert!(
            c[1].message
                .contains("Firefox « abc.default-release » (12), Chrome (3)"),
            "{}",
            c[1].message
        );
        assert!(c[1].message.contains("mot de passe principal") && c[1].message.contains("Chrome et cousins"));
        assert!(
            c[1].correctif
                .as_ref()
                .is_some_and(|k| !k.automatique && k.action.contains("Firefox"))
        );
    }

    #[test]
    fn checkups_selon_les_familles_presentes() {
        let lu = |navigateur, nom: &str, n, firefox| {
            Ok(Profil {
                navigateur,
                nom: nom.into(),
                identifiants: n,
                firefox,
            })
        };
        // Rien à montrer : aucun profil, ou seulement des profils vides.
        assert_eq!(checkups(&[]), Vec::<Checkup>::new());
        assert_eq!(checkups(&[lu("Firefox", "x.default", 0, true)]), Vec::<Checkup>::new());
        // Les familles sont dédoublonnées (Zen = Firefox, Chromium = Chrome) et gardent leur ordre ;
        // un profil illisible n'invente pas de famille.
        let c = checkups(&[
            lu("Firefox", "x.default-release", 3, true),
            lu("Zen", "y.default", 2, true),
            lu("Chrome", "Default", 5, false),
            lu("Chromium", "Default", 1, false),
            lu("Edge", "Default", 4, false),
            lu("Brave", "Default", 1, false),
            Err(("Vivaldi".into(), "Default/Login Data".into())),
        ]);
        assert_eq!(
            c,
            vec![
                Checkup::Firefox,
                Checkup::Chrome,
                Checkup::Edge,
                Checkup::Autre("Brave")
            ]
        );
    }
}

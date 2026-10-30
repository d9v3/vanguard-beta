//! Les lectures croisées : ce que Vanguard lit en Rust natif (base de pacman, unités systemd, prises réseau, profils du
//! pare-feu…), comparé à ce qu'en dit l'outil du système. Chaque lecture se déclare là où elle est écrite
//! (`croisee!`), comme une règle du bilan, et les tests « X_comme_Y » appellent la même fonction : un seul code pour
//! `cargo test` (sur l'ordinateur de l'auteur) et pour l'autotest (là où Vanguard travaille vraiment).
//!
//! « Pareil » veut dire « même avis que l'outil », pas « vrai » : les deux lisent souvent la même source. Un écart
//! n'emporte que des nombres et un genre hors de l'écran ; les valeurs (noms de paquets, d'unités, de comptes) ne
//! s'affichent qu'avec `--detail`, sur l'ordinateur où l'on est.

// Aucune lecture croisée sous macOS encore (lot macOS) : les outils de comparaison n'y servent pas.
#![cfg_attr(target_os = "macos", allow(dead_code))]

use std::collections::BTreeMap;

use crate::machine::regles::Os;
use crate::modele::Raison;

/// Le genre d'un écart : seul ce code, avec les nombres, sort de l'écran (`--json`, journal des erreurs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ecart {
    /// L'outil voit ce que la lecture de Vanguard ne voit pas.
    AbsentNatif,
    /// La lecture de Vanguard voit ce que l'outil ne voit pas.
    EnTropNatif,
    /// Même élément, valeur différente (version, état).
    ValeurDifferente,
    /// La lecture de Vanguard n'a rien pu lire alors que l'outil répond.
    ChampIllisible,
    /// L'outil a répondu dans une forme que la comparaison ne connaît pas.
    SortieInattendue,
}

impl Ecart {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Ecart::AbsentNatif => "absent-natif",
            Ecart::EnTropNatif => "en-trop-natif",
            Ecart::ValeurDifferente => "valeur-differente",
            Ecart::ChampIllisible => "champ-illisible",
            Ecart::SortieInattendue => "sortie-inattendue",
        }
    }
}

/// Le verdict d'une lecture croisée.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Comparaison {
    /// Même avis que l'outil, sur `n` éléments.
    Pareil { n: usize },
    /// Pas le même avis. Les listes portent les valeurs, pour l'écran (`--detail`) seulement.
    Different {
        en_plus: Vec<String>,
        en_moins: Vec<String>,
        differents: Vec<String>,
        genre: Ecart,
    },
    /// Rien à comparer ici, et c'est su (aucun dpkg ni base de dpkg sur cet ordinateur) : ni sain, ni manque.
    SansObjet(String),
    /// Pas comparé : pourquoi. Jamais compté « pareil ».
    Saute(Raison),
}

impl Comparaison {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Comparaison::Pareil { .. } => "pareil",
            Comparaison::Different { .. } => "different",
            Comparaison::SansObjet(_) => "sans-objet",
            Comparaison::Saute(_) => "saute",
        }
    }

    /// Un écart sur une seule valeur (oui ou non, un état) : rien en plus, rien en moins, une différence.
    pub(crate) fn une_valeur(quoi: &str, natif: &str, outil: &str) -> Comparaison {
        if natif == outil {
            Comparaison::Pareil { n: 1 }
        } else {
            Comparaison::Different {
                en_plus: Vec::new(),
                en_moins: Vec::new(),
                differents: vec![format!("{quoi} : {natif} ≠ {outil}")],
                genre: Ecart::ValeurDifferente,
            }
        }
    }

    /// Une sortie de l'outil que la comparaison ne sait pas lire.
    pub(crate) fn inattendue() -> Comparaison {
        Comparaison::Different {
            en_plus: Vec::new(),
            en_moins: Vec::new(),
            differents: Vec::new(),
            genre: Ecart::SortieInattendue,
        }
    }
}

/// Compare deux ensembles clé → valeur : ce que la lecture native a en plus, en moins, et ce qui diffère.
pub(crate) fn comparer(
    natif: impl IntoIterator<Item = (String, String)>,
    outil: impl IntoIterator<Item = (String, String)>,
) -> Comparaison {
    let natif: BTreeMap<String, String> = natif.into_iter().collect();
    let outil: BTreeMap<String, String> = outil.into_iter().collect();
    let en_plus: Vec<String> = natif.keys().filter(|k| !outil.contains_key(*k)).cloned().collect();
    let en_moins: Vec<String> = outil.keys().filter(|k| !natif.contains_key(*k)).cloned().collect();
    let differents: Vec<String> = natif
        .iter()
        .filter_map(|(k, v)| match outil.get(k) {
            Some(o) if o != v => Some(format!("{k} : {v} ≠ {o}")),
            _ => None,
        })
        .collect();
    if en_plus.is_empty() && en_moins.is_empty() && differents.is_empty() {
        return Comparaison::Pareil { n: natif.len() };
    }
    let genre = if !en_moins.is_empty() {
        Ecart::AbsentNatif
    } else if !en_plus.is_empty() {
        Ecart::EnTropNatif
    } else {
        Ecart::ValeurDifferente
    };
    Comparaison::Different {
        en_plus,
        en_moins,
        differents,
        genre,
    }
}

/// Comme `comparer`, pour des ensembles sans valeur (noms seuls).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn comparer_noms(
    natif: impl IntoIterator<Item = String>,
    outil: impl IntoIterator<Item = String>,
) -> Comparaison {
    comparer(
        natif.into_iter().map(|n| (n, String::new())),
        outil.into_iter().map(|n| (n, String::new())),
    )
}

/// Une lecture croisée.
pub(crate) struct Croisee {
    /// « AUT-LNX-001 » : stable, jamais repris (tests/regles-connues.txt).
    pub id: &'static str,
    pub systeme: Os,
    pub sujet: (&'static str, &'static str),
    /// L'outil du système, tel qu'on le tape (« pacman -Q »).
    pub outil: &'static str,
    /// Les règles du bilan qui décident d'après cette lecture : elles peuvent se tromper quand elle diverge.
    pub regles: &'static [&'static str],
    pub comparer: fn() -> Comparaison,
}

inventory::collect!(Croisee);

/// Déclare une lecture croisée : identifiant, système, sujet (français, anglais), outil, règles, comparaison. Un
/// identifiant mal formé ne compile pas.
#[cfg_attr(target_os = "macos", allow(unused_macros))] // aucune lecture croisée sous macOS encore
macro_rules! croisee {
    ($id:literal, $os:expr, $sujet:expr, $outil:literal, $regles:expr, $comparer:expr $(,)?) => {
        const _: () = assert!(
            $crate::modele::id::bien_forme($id),
            "identifiant de lecture croisée mal formé"
        );
        inventory::submit! {
            $crate::autotest::croisees::Croisee {
                id: $id,
                systeme: $os,
                sujet: $sujet,
                outil: $outil,
                regles: $regles,
                comparer: $comparer,
            }
        }
    };
}
#[cfg_attr(target_os = "macos", allow(unused_imports))]
pub(crate) use croisee;

/// Les lectures croisées de ce système, par identifiant.
pub(crate) fn croisees() -> Vec<&'static Croisee> {
    let mut toutes: Vec<&'static Croisee> = inventory::iter::<Croisee>
        .into_iter()
        .filter(|c| c.systeme == Os::actuel())
        .collect();
    toutes.sort_by_key(|c| c.id);
    toutes
}

/// Les commandes que les lectures croisées lancent : seulement celles-ci, toutes de lecture (un test le vérifie).
/// Une commande hors de la liste est refusée avant d'être lancée.
pub(crate) const LECTURES: &[&str] = &[
    "pacman -Q",
    "pacman -Qmq",
    "dpkg-query -W -f=${db:Status-Status} ${Package} ${Version}\\n",
    "systemctl list-unit-files --no-legend --plain --state=enabled,disabled,masked",
    "systemctl --user list-unit-files --no-legend --plain --state=enabled,disabled,masked",
    "systemctl --failed --no-legend --plain",
    "id -nG",
    "ss -Htlnpe",
    "ss -Hulnpe",
    "findmnt -no SOURCE /",
    "lsblk -nso TYPE",
    "sshd -V",
    "resolvectl dns",
    // Windows : des Get-* lus en JSON, jamais le texte traduit de la console.
    "Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,Enabled | ConvertTo-Json",
    "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,IsTamperProtected | ConvertTo-Json",
    "Get-CimInstance -Namespace root/cimv2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume -Filter \"DriveLetter='C:'\" | Select-Object ProtectionStatus | ConvertTo-Json",
    "Get-LocalUser | Select-Object Enabled,PasswordRequired,SID | ConvertTo-Json",
];

/// Au-delà, la sortie d'un outil n'est pas lue (une liste de paquets fait quelques centaines de Kio).
#[cfg(target_os = "linux")]
const SORTIE_MAX: usize = 32 << 20;

/// Lance une commande de `LECTURES` (programme et arguments séparés par des espaces, sauf la dernière forme de
/// dpkg-query, qui n'a qu'un argument après -W), plus des arguments `en_plus` qui ne sont jamais des options (un
/// chemin de périphérique). Rend sa sortie, ou la raison de ne pas comparer : outil absent, délai, échec.
#[cfg(target_os = "linux")]
pub(crate) fn lancer(ligne: &'static str, en_plus: &[&str]) -> Result<String, Raison> {
    if !LECTURES.contains(&ligne) || en_plus.iter().any(|a| a.starts_with('-')) {
        return Err(Raison::Refuse(format!("« {ligne} » hors des lectures permises")));
    }
    let (programme, reste) = ligne.split_once(' ').unwrap_or((ligne, ""));
    let args: Vec<&str> = match reste.strip_prefix("-W ") {
        Some(format) => vec!["-W", format],
        None => reste.split_whitespace().collect(),
    };
    let args: Vec<String> = args
        .into_iter()
        .map(|a| a.replace("\\n", "\n"))
        .chain(en_plus.iter().map(|a| (*a).to_string()))
        .collect();
    // sshd n'est pas toujours dans le PATH d'un compte (/usr/sbin).
    let chemin = if programme == "sshd" {
        ["/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd"]
            .into_iter()
            .map(std::path::PathBuf::from)
            .find(|p| p.is_file())
    } else {
        crate::machine::linux::natif::chemin(programme)
    };
    let Some(chemin) = chemin else {
        return Err(Raison::Absente(programme.to_string()));
    };
    let mut commande = std::process::Command::new(chemin);
    commande.args(&args);
    let Some(r) = crate::commande::lancer_en_anglais(&mut commande, 60) else {
        return Err(Raison::Delai);
    };
    if r.sortie.len() > SORTIE_MAX {
        return Err(Raison::Refuse(format!("sortie de « {ligne} » trop longue")));
    }
    // sshd -V écrit sa version sur la sortie d'erreur, et rend 1 (option inconnue des anciens OpenSSH).
    if programme == "sshd" {
        return Ok(format!("{}{}", r.erreurs, r.sortie));
    }
    match r.code {
        Some(0) => Ok(r.sortie),
        // pacman -Qmq rend 1 quand aucun paquet n'est étranger.
        Some(1) if ligne == "pacman -Qmq" && r.sortie.trim().is_empty() => Ok(String::new()),
        Some(c) => Err(Raison::Echoue(format!("{programme} : code {c}"))),
        None => Err(Raison::Echoue(format!("{programme} : arrêté"))),
    }
}

/// Lance un script PowerShell de `LECTURES` et rend son JSON (un objet seul devient une liste d'un élément).
#[cfg(windows)]
pub(crate) fn powershell(ligne: &'static str) -> Result<Vec<serde_json::Value>, Raison> {
    if !LECTURES.contains(&ligne) {
        return Err(Raison::Refuse(format!("« {ligne} » hors des lectures permises")));
    }
    if crate::journal::sous_wine() {
        return Err(Raison::Absente("PowerShell (Wine)".into()));
    }
    let Some(texte) = crate::machine::windows::ps(ligne) else {
        return Err(Raison::Echoue(
            "PowerShell n'a pas répondu (refusé, absent ou délai)".into(),
        ));
    };
    json_en_liste(&texte)
}

/// Le JSON de ConvertTo-Json : un objet seul ou une liste ; vide si rien n'est rendu.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
pub(crate) fn json_en_liste(texte: &str) -> Result<Vec<serde_json::Value>, Raison> {
    if texte.trim().is_empty() {
        return Ok(Vec::new());
    }
    match serde_json::from_str::<serde_json::Value>(texte.trim()) {
        Ok(serde_json::Value::Array(v)) => Ok(v),
        Ok(v @ serde_json::Value::Object(_)) => Ok(vec![v]),
        _ => Err(Raison::Illisible("JSON".into())),
    }
}

/// Pour les tests « X_comme_Y » : même avis que l'outil, ou sauté (dit, compté par verifier.sh).
// `cfg(test)` seul, puis le système : clippy ne reconnaît le code de test qu'à la forme exacte `#[cfg(test)]`.
#[cfg(test)]
#[cfg(target_os = "linux")]
#[track_caller]
pub(crate) fn essayer(id: &str) {
    let c = inventory::iter::<Croisee>
        .into_iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("{id} : lecture croisée inconnue"));
    match (c.comparer)() {
        Comparaison::Pareil { .. } => {}
        Comparaison::SansObjet(pourquoi) => crate::essais::saute(&pourquoi),
        Comparaison::Saute(r) => crate::essais::saute(&format!("{} : {}", c.outil, r.texte())),
        d @ Comparaison::Different { .. } => panic!("{id} ({}) : {d:?}", c.outil),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Les comparaisons sur des données inventées : pareil, en plus, en moins, valeur différente, sortie illisible.
    #[test]
    fn comparaisons_synthetiques() {
        let p = |v: &[(&str, &str)]| {
            v.iter()
                .map(|(a, b)| ((*a).to_string(), (*b).to_string()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            comparer(
                p(&[("bash", "5.2"), ("vim", "9.1")]),
                p(&[("vim", "9.1"), ("bash", "5.2")])
            ),
            Comparaison::Pareil { n: 2 }
        );
        let Comparaison::Different { en_moins, genre, .. } =
            comparer(p(&[("bash", "5.2")]), p(&[("bash", "5.2"), ("vim", "9.1")]))
        else {
            panic!()
        };
        assert_eq!((en_moins, genre), (vec!["vim".to_string()], Ecart::AbsentNatif));
        let Comparaison::Different { en_plus, genre, .. } =
            comparer(p(&[("bash", "5.2"), ("x", "1")]), p(&[("bash", "5.2")]))
        else {
            panic!()
        };
        assert_eq!((en_plus, genre), (vec!["x".to_string()], Ecart::EnTropNatif));
        let Comparaison::Different { differents, genre, .. } = comparer(p(&[("bash", "5.2")]), p(&[("bash", "5.3")]))
        else {
            panic!()
        };
        assert_eq!((differents.len(), genre), (1, Ecart::ValeurDifferente));
        assert_eq!(
            Comparaison::une_valeur("chiffrée", "oui", "oui"),
            Comparaison::Pareil { n: 1 }
        );
        assert_eq!(Comparaison::inattendue().code(), "different");
        assert_eq!(json_en_liste("{\"Name\":\"Public\"}").unwrap().len(), 1);
        assert_eq!(json_en_liste("[{},{}]").unwrap().len(), 2);
        assert_eq!(json_en_liste("").unwrap().len(), 0);
        assert!(matches!(
            json_en_liste("Get-NetFirewallProfile : accès refusé"),
            Err(Raison::Illisible(_))
        ));
    }

    /// Chaque lecture croisée : identifiant unique au préfixe AUT et au système voulu, sujet dans les deux langues,
    /// règles existantes (du registre de son système, lues dans les sources pour les autres systèmes).
    #[test]
    fn croisees_bien_declarees() {
        let mut vus = std::collections::HashSet::new();
        let regles = crate::machine::regles::regles(Os::actuel());
        for c in inventory::iter::<Croisee> {
            assert!(vus.insert(c.id), "{} déclarée deux fois", c.id);
            let attendu = match c.systeme {
                Os::Linux => "AUT-LNX-",
                Os::Windows => "AUT-WIN-",
                Os::MacOs => "AUT-MAC-",
                Os::Tous => "AUT-COM-",
            };
            assert!(c.id.starts_with(attendu), "{} : préfixe {attendu} attendu", c.id);
            assert!(!c.sujet.0.is_empty() && !c.sujet.1.is_empty() && !c.outil.is_empty());
            assert!(!c.regles.is_empty(), "{} : aucune règle", c.id);
            for r in c.regles {
                assert!(regles.iter().any(|x| x.id == *r), "{} : règle {r} inconnue", c.id);
            }
        }
        if cfg!(target_os = "linux") {
            assert!(
                croisees().len() >= 8,
                "{} lectures croisées seulement",
                croisees().len()
            );
        }
    }

    /// Aucune commande permise ne change le système : pas de verbe d'écriture, d'installation ni de service.
    #[test]
    fn lectures_sans_verbe_qui_change() {
        const INTERDITS: &[&str] = &[
            " -S", " -R", " -U", "--sync", " set", " enable", " disable", " start", " stop", " restart", " mask",
            " kill", " install", " remove", "Set-", "Enable-", "Disable-", "Remove-", "New-", "Start-", "Stop-",
            "Add-", "Invoke-", "Clear-", "Restart-", "Suspend-", "Resume-", "-Force", ">", ";",
        ];
        for l in LECTURES {
            for i in INTERDITS {
                assert!(!l.contains(i), "« {l} » contient « {i} »");
            }
        }
    }

    /// Une commande hors de la liste, ou une option glissée en plus, est refusée sans être lancée.
    #[cfg(target_os = "linux")]
    #[test]
    fn commande_hors_liste_refusee() {
        assert!(matches!(lancer("pacman -Q", &["--noconfirm"]), Err(Raison::Refuse(_))));
        // Une chaîne égale mais d'un autre endroit passe : seule la valeur compte (c'est une &'static str).
        assert!(!LECTURES.contains(&"pacman -Syu"));
    }
}

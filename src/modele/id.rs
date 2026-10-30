//! L'identité d'un constat : la règle qui l'a produit et l'objet qu'il juge (« LNX-PFE-001 » +
//! « port:8080/tcp:python3 »). Jamais de texte traduit dedans : c'est ce qui permet de reconnaître un problème d'un
//! bilan à l'autre, quelle que soit la langue ou la tournure du message.

use std::fmt;

use super::registre::PREFIXES;

/// Un identifiant bien formé : préfixe connu (`registre::PREFIXES`), trois majuscules, trois chiffres
/// (« LNX-PFE-001 »). `const` : la macro `regle!` le vérifie à la compilation, une faute de frappe ne passe pas.
pub(crate) const fn bien_forme(id: &str) -> bool {
    // Motifs de tranche plutôt qu'itérateurs : ceux-ci ne s'emploient pas dans une `const fn`.
    let [a, b, c, b'-', l1, l2, l3, b'-', c1, c2, c3] = *id.as_bytes() else {
        return false;
    };
    let lettres = l1.is_ascii_uppercase() && l2.is_ascii_uppercase() && l3.is_ascii_uppercase();
    let chiffres = c1.is_ascii_digit() && c2.is_ascii_digit() && c3.is_ascii_digit();
    if !lettres || !chiffres {
        return false;
    }
    let mut reste = PREFIXES;
    while let [(connu, _), suite @ ..] = reste {
        if let [x, y, z, ..] = *connu.as_bytes()
            && x == a
            && y == b
            && z == c
        {
            return true;
        }
        reste = suite;
    }
    false
}

/// Ce que juge un constat, à côté de sa règle. Pas de chaîne vide qui voudrait dire « rien » : chaque cas est nommé.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum Objet {
    /// La règle ne pose pas encore d'objet : on reconnaît ce constat à son texte, comme avant.
    #[default]
    NonMigre,
    /// La règle ne rend qu'un constat, qui ne dépend d'aucune valeur variable : la règle seule suffit.
    Seul,
    /// « genre:valeur » : ce qui distingue ce constat des autres de sa règle (port, chemin normalisé, paquet…).
    De(String),
}

impl Objet {
    /// « genre:valeur ». Une valeur vide ne distinguerait rien : l'objet reste alors non migré (repli sur le texte),
    /// jamais une clé qui couvrirait tous les constats de la règle.
    pub(crate) fn de(genre: &str, valeur: &str) -> Objet {
        let v = valeur.trim();
        if v.is_empty() {
            Objet::NonMigre
        } else {
            Objet::De(format!("{genre}:{v}"))
        }
    }

    /// Un port ouvert, avec le programme qui l'ouvre quand il est connu : accepter Python sur 8080 ne doit pas faire
    /// taire un autre programme qui prendrait ce port. Le nom du programme vient du système, jamais traduit.
    pub(crate) fn port(port: u16, proto: &str, programme: Option<&str>) -> Objet {
        match programme.map(str::trim).filter(|p| !p.is_empty()) {
            Some(p) => Objet::De(format!("port:{port}/{proto}:{p}")),
            None => Objet::De(format!("port:{port}/{proto}")),
        }
    }

    /// Un fichier ou un dossier, son chemin normalisé (`chemin`).
    #[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))] // les règles de macOS (parite.rs) et les tests
    pub(crate) fn fichier(chemin_brut: &str) -> Objet {
        Objet::de("fichier", &chemin(chemin_brut))
    }

    /// Un agent de démarrage : son fichier et ce qu'il lance (`None` : illisible ou fabriqué, rien de lisible). Le
    /// fichier seul ne suffit pas : accepter l'agent d'aujourd'hui ne doit pas faire taire un autre programme que ce
    /// même fichier lancerait demain. La commande, écrite par qui a posé l'agent et sans borne de longueur, n'entre
    /// dans la clé que par son empreinte (`trace`).
    #[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))] // agents de démarrage de macOS
    pub(crate) fn agent(chemin_brut: &str, lance: Option<&str>) -> Objet {
        let quoi = lance.map_or_else(|| "illisible".to_string(), trace);
        Objet::de("agent", &format!("{}#{quoi}", chemin(chemin_brut)))
    }

    /// Le texte de l'objet dans une clé : vide pour `Seul`, `None` pour `NonMigre`.
    pub(crate) fn texte(&self) -> Option<&str> {
        match self {
            Objet::NonMigre => None,
            Objet::Seul => Some(""),
            Objet::De(s) => Some(s),
        }
    }
}

/// La clé d'un constat : sa règle et son objet. Écrite « RÈGLE|objet » (ou « RÈGLE » seule) dans les fichiers.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Cle {
    pub regle: String,
    pub objet: String,
}

impl Cle {
    /// La clé d'un constat, s'il en a une : une règle connue et un objet posé.
    pub(crate) fn de(regle: &str, objet: &Objet) -> Option<Cle> {
        if regle.is_empty() {
            return None;
        }
        Some(Cle {
            regle: regle.to_string(),
            objet: objet.texte()?.to_string(),
        })
    }

    /// Relit une clé écrite par `Display`. La règle ne contient jamais « | » ; l'objet, s'il en contient, reste
    /// entier.
    #[cfg(test)] // les fichiers comparent le texte de la clé ; relire sert aux tests
    pub(crate) fn lire(texte: &str) -> Option<Cle> {
        let (regle, objet) = texte.split_once('|').unwrap_or((texte, ""));
        bien_forme(regle).then(|| Cle {
            regle: regle.to_string(),
            objet: objet.to_string(),
        })
    }
}

impl fmt::Display for Cle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.objet.is_empty() {
            f.write_str(&self.regle)
        } else {
            write!(f, "{}|{}", self.regle, self.objet)
        }
    }
}

/// L'empreinte courte d'un texte écrit par un tiers (une ligne lancée au démarrage, une commande) : ce qui change
/// dès que le texte change, sans mettre dans la clé un texte long ou fabriqué. Les blancs du bord ne comptent pas.
#[cfg_attr(not(any(target_os = "macos", target_os = "linux", test)), allow(dead_code))] // persistance Linux et macOS
pub(crate) fn trace(texte: &str) -> String {
    blake3::hash(texte.trim().as_bytes()).to_hex()[..12].to_string()
}

/// Un chemin tel qu'il entre dans une clé : le dossier personnel devient « ~ » (le même fichier sous deux comptes
/// ou deux noms de dossier reste reconnu) ; sous Windows, la casse et le sens des barres ne comptent pas.
pub(crate) fn chemin(brut: &str) -> String {
    let maison = if cfg!(windows) {
        std::env::var("USERPROFILE").ok()
    } else {
        std::env::var("HOME").ok()
    };
    chemin_sous(brut, maison.as_deref(), cfg!(windows))
}

/// `chemin`, le dossier personnel et le système donnés : la fonction que les tests essaient.
pub(crate) fn chemin_sous(brut: &str, maison: Option<&str>, windows: bool) -> String {
    let normal = |p: &str| {
        let p = p.trim();
        let p = if windows {
            p.replace('\\', "/").to_lowercase()
        } else {
            p.to_string()
        };
        // Une barre finale ne change pas le fichier ; la racine seule la garde.
        let sans = p.trim_end_matches('/');
        if sans.is_empty() && p.starts_with('/') {
            "/".to_string()
        } else {
            sans.to_string()
        }
    };
    let c = normal(brut);
    if let Some(m) = maison.map(normal).filter(|m| !m.is_empty() && m != "/") {
        if c == m {
            return "~".to_string();
        }
        if let Some(reste) = c.strip_prefix(&format!("{m}/")) {
            return format!("~/{reste}");
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formes_des_identifiants() {
        for bon in [
            "LNX-PFE-001",
            "COM-WIF-005",
            "PRO-MEM-001",
            "SUR-BOT-001",
            "VEI-PRG-001",
        ] {
            assert!(bien_forme(bon), "{bon}");
        }
        for mauvais in [
            "LNX-PF-001",
            "lnx-PFE-001",
            "XYZ-PFE-001",
            "LNX-PFE-01",
            "LNX_PFE_001",
            "",
            "LNX-PFE-0011",
        ] {
            assert!(!bien_forme(mauvais), "{mauvais}");
        }
    }

    #[test]
    fn cle_ecrite_puis_relue() {
        let c = Cle::de("LNX-PFE-001", &Objet::port(8080, "tcp", Some("python3"))).unwrap();
        assert_eq!(c.to_string(), "LNX-PFE-001|port:8080/tcp:python3");
        assert_eq!(Cle::lire(&c.to_string()), Some(c));
        let seule = Cle::de("COM-HEU-001", &Objet::Seul).unwrap();
        assert_eq!(seule.to_string(), "COM-HEU-001");
        assert_eq!(Cle::lire("COM-HEU-001"), Some(seule));
        // Un objet qui contient « | » reste entier.
        let pipe = Cle::de("COM-NAV-001", &Objet::de("extension", "a|b")).unwrap();
        assert_eq!(Cle::lire(&pipe.to_string()), Some(pipe));
        // Sans règle ou sans objet posé : pas de clé, on retombe sur le texte.
        assert_eq!(Cle::de("", &Objet::Seul), None);
        assert_eq!(Cle::de("LNX-PFE-001", &Objet::NonMigre), None);
        assert_eq!(Cle::lire("pas une clé"), None);
        // Une valeur vide ne fait jamais une clé qui couvrirait toute la règle.
        assert_eq!(Objet::de("paquet", "  "), Objet::NonMigre);
        assert_eq!(Objet::port(22, "tcp", Some(" ")), Objet::De("port:22/tcp".into()));
    }

    #[test]
    fn chemins_normalises() {
        let m = Some("/home/user");
        assert_eq!(chemin_sous("/home/user/.bashrc", m, false), "~/.bashrc");
        assert_eq!(chemin_sous("/home/user/", m, false), "~");
        assert_eq!(chemin_sous("/home/username/x", m, false), "/home/username/x");
        assert_eq!(chemin_sous("/etc/", m, false), "/etc");
        assert_eq!(chemin_sous("/", m, false), "/");
        // Linux : la casse compte.
        assert_eq!(chemin_sous("/home/user/A", m, false), "~/A");
        let w = Some(r"C:\Users\Alice");
        assert_eq!(
            chemin_sous(r"c:\users\alice\AppData\Run.exe", w, true),
            "~/appdata/run.exe"
        );
        assert_eq!(chemin_sous(r"C:\Windows\System32\", w, true), "c:/windows/system32");
        assert_eq!(chemin_sous("/tmp/x", None, false), "/tmp/x");
        assert_eq!(Objet::fichier("/etc/cron.d/"), Objet::De("fichier:/etc/cron.d".into()));
    }

    /// Un agent : même fichier, autre programme lancé (ou devenu illisible), autre objet ; même commande, même objet.
    #[test]
    fn agent_garde_ce_qu_il_lance() {
        let plist = "/Users/alice/Library/LaunchAgents/com.exemple.aide.plist";
        let aide = Objet::agent(plist, Some("/opt/exemple/aide "));
        assert_eq!(aide, Objet::agent(plist, Some("/opt/exemple/aide")));
        assert_ne!(aide, Objet::agent(plist, Some("/tmp/x")));
        assert_ne!(aide, Objet::agent(plist, None));
        assert_ne!(aide, Objet::fichier(plist));
        let texte = aide.texte().unwrap().to_string();
        assert!(
            texte.starts_with("agent:") && texte.contains("com.exemple.aide.plist#"),
            "{texte}"
        );
        assert_eq!(trace("a").len(), 12);
    }
}

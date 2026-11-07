//! La table fermée des logiciels suivis : pour chacun, où le trouver (chemins connus sous Windows), quelle version
//! lire, quelles sources le jugent et quelles lignes du catalogue de la CISA le concernent. Rien n'est rapproché par
//! ressemblance de nom : un logiciel absent de la table n'est pas jugé.

/// Les distributions de Java dont endoflife.date suit les versions ; les autres (Azul, IBM…) restent non vérifiées :
/// leur numéro n'est pas toujours celui de Java.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Distribution {
    Oracle,
    Temurin,
    Corretto,
    Microsoft,
    Autre,
}

impl Distribution {
    /// D'après la ligne `IMPLEMENTOR` du fichier `release`, telle que chaque éditeur l'écrit.
    pub(crate) fn depuis_implementor(texte: &str) -> Distribution {
        match texte.trim() {
            "Oracle Corporation" => Distribution::Oracle,
            "Eclipse Adoptium" => Distribution::Temurin,
            "Amazon.com Inc." => Distribution::Corretto,
            "Microsoft" => Distribution::Microsoft,
            _ => Distribution::Autre,
        }
    }
}

/// Un logiciel suivi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Produit {
    Chrome,
    Edge,
    Firefox,
    Brave,
    Office,
    Acrobat,
    Reader,
    Java(Distribution),
    SevenZip,
    PuTTY,
    Slack,
}

impl Produit {
    /// Son nom, en français et en anglais (les noms de marque ne se traduisent pas).
    pub(crate) fn noms(self) -> [&'static str; 2] {
        match self {
            Produit::Chrome => ["Google Chrome"; 2],
            Produit::Edge => ["Microsoft Edge"; 2],
            Produit::Firefox => ["Mozilla Firefox"; 2],
            Produit::Brave => ["Brave"; 2],
            Produit::Office => ["Microsoft Office"; 2],
            Produit::Acrobat => ["Adobe Acrobat"; 2],
            Produit::Reader => ["Adobe Acrobat Reader"; 2],
            Produit::Java(Distribution::Oracle) => ["Java (Oracle)"; 2],
            Produit::Java(Distribution::Temurin) => ["Java (Eclipse Temurin)"; 2],
            Produit::Java(Distribution::Corretto) => ["Java (Amazon Corretto)"; 2],
            Produit::Java(Distribution::Microsoft) => ["Java (Microsoft)"; 2],
            Produit::Java(Distribution::Autre) => ["Java (autre distribution)", "Java (other distribution)"],
            Produit::SevenZip => ["7-Zip"; 2],
            Produit::PuTTY => ["PuTTY"; 2],
            Produit::Slack => ["Slack"; 2],
        }
    }

    /// Son nom dans la langue de l'interface.
    pub(crate) fn nom(self) -> &'static str {
        let [fr, en] = self.noms();
        if crate::langue::anglais() { en } else { fr }
    }

    /// Sa fiche ; Java a une seule fiche pour toutes ses distributions.
    pub(crate) fn fiche(self) -> &'static Fiche {
        let cherche = match self {
            Produit::Java(_) => Produit::Java(Distribution::Autre),
            autre => autre,
        };
        let trouvee = FICHES.iter().find(|f| f.produit == cherche);
        // Repli jamais pris : l'essai `chaque_produit_a_son_nom` vérifie que chaque produit a sa fiche.
        #[expect(clippy::indexing_slicing, reason = "FICHES est une constante non vide")]
        let repli = &FICHES[0];
        trouvee.unwrap_or(repli)
    }
}

/// Une ligne de la table.
pub(crate) struct Fiche {
    /// Pour Java, `Java(Autre)` : la distribution se lit dans le fichier `release`.
    pub produit: Produit,
    /// Sous Windows, l'exécutable (ou le fichier de version) relatif à `Program Files`, `Program Files (x86)` et
    /// `AppData\Local` de chaque compte, par morceaux de chemin.
    pub windows: &'static [&'static [&'static str]],
    /// Les sources qui le jugent (identifiants de `sources::SOURCES`).
    pub sources: &'static [&'static str],
    /// Une ligne du catalogue de la CISA (éditeur, produit) le concerne : couples exacts, mesurés sur le catalogue
    /// du 21 oct. 2026.
    pub kev: fn(&str, &str) -> bool,
}

/// Chromium : les failles du moteur, que Chrome et Edge partagent. « Chrome for Android » n'est pas le Chrome d'un
/// ordinateur.
fn kev_chromium(editeur: &str, produit: &str) -> bool {
    editeur == "Google" && produit.starts_with("Chromium")
}

fn kev_chrome(editeur: &str, produit: &str) -> bool {
    kev_chromium(editeur, produit)
        || (editeur == "Google" && produit.starts_with("Chrome") && !produit.starts_with("Chrome for Android"))
}

/// Les lignes « Microsoft | Edge… » sont l'ancien Edge (EdgeHTML) : écartées. Edge d'aujourd'hui repose sur
/// Chromium.
fn kev_edge(editeur: &str, produit: &str) -> bool {
    kev_chromium(editeur, produit)
}

fn kev_firefox(editeur: &str, produit: &str) -> bool {
    editeur == "Mozilla" && produit.contains("Firefox")
}

/// WordPad seul n'est pas Office.
fn kev_office(editeur: &str, produit: &str) -> bool {
    editeur == "Microsoft"
        && matches!(
            produit,
            "Office" | "Word" | "Excel" | "PowerPoint" | "Outlook" | "Office Outlook" | "Office and WordPad"
        )
}

fn kev_adobe(editeur: &str, produit: &str) -> bool {
    editeur == "Adobe"
        && matches!(
            produit,
            "Acrobat" | "Reader" | "Acrobat and Reader" | "Reader and Acrobat" | "Acrobat and Reader, Flash Player"
        )
}

fn kev_java(editeur: &str, produit: &str) -> bool {
    editeur == "Oracle" && produit.starts_with("Java")
}

fn kev_7zip(editeur: &str, produit: &str) -> bool {
    editeur == "7-Zip" && produit == "7-Zip"
}

/// Brave, PuTTY et Slack n'ont aucune ligne au catalogue. Slack embarque Chromium (Electron), mais les failles de
/// Chromium ne se reportent pas sur lui par sa version : Electron corrige sans changer de version de Chromium (étude,
/// §10), et rien ne dirait si sa version en a.
fn kev_aucune(_: &str, _: &str) -> bool {
    false
}

const CHROME: &[&str] = &[
    "chrome-win-stable",
    "chrome-win-extended",
    "chrome-win64-stable",
    "chrome-win64-extended",
    "chrome-win_arm64-stable",
    "chrome-win_arm64-extended",
];

/// La table.
pub(crate) const FICHES: &[Fiche] = &[
    Fiche {
        produit: Produit::Chrome,
        windows: &[&["Google", "Chrome", "Application", "chrome.exe"]],
        sources: CHROME,
        kev: kev_chrome,
    },
    Fiche {
        produit: Produit::Edge,
        windows: &[&["Microsoft", "Edge", "Application", "msedge.exe"]],
        sources: &["edge"],
        kev: kev_edge,
    },
    Fiche {
        produit: Produit::Firefox,
        windows: &[&["Mozilla Firefox", "application.ini"]],
        sources: &["mozilla", "mfsa"],
        kev: kev_firefox,
    },
    Fiche {
        produit: Produit::Brave,
        windows: &[&["BraveSoftware", "Brave-Browser", "Application", "brave.exe"]],
        sources: &["brave-windows-x64", "brave-windows-arm64"],
        kev: kev_aucune,
    },
    // Sous Windows, Office Click-to-Run se lit dans le registre ; en MSI, il reste à `fin_de_support`.
    Fiche {
        produit: Produit::Office,
        windows: &[],
        sources: &["office"],
        kev: kev_office,
    },
    // Acrobat et Reader sous Windows : par leurs clés Uninstall (nom et éditeur exacts), puis l'exécutable.
    Fiche {
        produit: Produit::Acrobat,
        windows: &[],
        sources: &["adobe-acrobat"],
        kev: kev_adobe,
    },
    Fiche {
        produit: Produit::Reader,
        windows: &[],
        sources: &["adobe-reader"],
        kev: kev_adobe,
    },
    // Java : par son fichier `release`, dans les dossiers connus de chaque distribution.
    Fiche {
        produit: Produit::Java(Distribution::Autre),
        windows: &[],
        sources: &["eol"],
        kev: kev_java,
    },
    // 7-Zip et PuTTY : l'exécutable sous Windows (ressource de version). Leur dernière version vient de formula.json
    // (Homebrew suit l'amont).
    Fiche {
        produit: Produit::SevenZip,
        windows: &[&["7-Zip", "7z.exe"]],
        sources: &["formules"],
        kev: kev_7zip,
    },
    Fiche {
        produit: Produit::PuTTY,
        windows: &[&["PuTTY", "putty.exe"]],
        sources: &["formules"],
        kev: kev_aucune,
    },
    // Slack : par machine sous `Program Files\Slack` (MSI, sans mise à jour automatique), par compte sous
    // `AppData\Local\slack` (Squirrel, un dossier `app-<version>` par version) ; Windows ne distingue pas la casse.
    Fiche {
        produit: Produit::Slack,
        windows: &[&["slack", "slack.exe"]],
        sources: &["slack-windows"],
        kev: kev_aucune,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protection::perimes::sources::SOURCES;

    #[test]
    fn table_sans_double_et_sources_connues() {
        let mut chemins: Vec<String> = FICHES
            .iter()
            .flat_map(|f| f.windows.iter().map(|c| c.join("/").to_lowercase()))
            .collect();
        let n = chemins.len();
        chemins.sort_unstable();
        chemins.dedup();
        assert_eq!(chemins.len(), n, "chemin Windows en double");
        for f in FICHES {
            assert_eq!(
                FICHES.iter().filter(|g| g.produit == f.produit).count(),
                1,
                "{:?}",
                f.produit
            );
            assert!(!f.sources.is_empty(), "{:?}", f.produit);
            for s in f.sources.iter().copied() {
                assert!(SOURCES.iter().any(|x| x.id == s), "source inconnue : {s}");
            }
            assert!(
                f.windows
                    .iter()
                    .all(|c| !c.is_empty() && c.iter().all(|m| !m.is_empty()))
            );
            assert_eq!(f.produit.fiche().produit, f.produit);
        }
        assert_eq!(
            Produit::Java(Distribution::Temurin).fiche().produit,
            Produit::Java(Distribution::Autre)
        );
    }

    #[test]
    fn chaque_produit_a_son_nom() {
        use Distribution::*;
        for p in [
            Produit::Chrome,
            Produit::Edge,
            Produit::Firefox,
            Produit::Brave,
            Produit::Office,
            Produit::Acrobat,
            Produit::Reader,
            Produit::Java(Oracle),
            Produit::Java(Temurin),
            Produit::Java(Corretto),
            Produit::Java(Microsoft),
            Produit::Java(Autre),
            Produit::SevenZip,
            Produit::PuTTY,
            Produit::Slack,
        ] {
            let [fr, en] = p.noms();
            assert!(!fr.is_empty() && !en.is_empty(), "{p:?}");
            assert_eq!(p.nom(), fr);
            // Sa propre fiche (Java : la commune), jamais le repli de `fiche`.
            let attendu = if matches!(p, Produit::Java(_)) {
                Produit::Java(Autre)
            } else {
                p
            };
            assert!(FICHES.iter().any(|f| f.produit == attendu), "{p:?} sans fiche");
        }
        assert_ne!(Produit::Java(Autre).noms()[0], Produit::Java(Autre).noms()[1]);
    }

    #[test]
    fn distributions_de_java() {
        assert_eq!(
            Distribution::depuis_implementor("Eclipse Adoptium"),
            Distribution::Temurin
        );
        assert_eq!(
            Distribution::depuis_implementor(" Oracle Corporation "),
            Distribution::Oracle
        );
        assert_eq!(
            Distribution::depuis_implementor("Amazon.com Inc."),
            Distribution::Corretto
        );
        assert_eq!(Distribution::depuis_implementor("Microsoft"), Distribution::Microsoft);
        assert_eq!(
            Distribution::depuis_implementor("Azul Systems, Inc."),
            Distribution::Autre
        );
        assert_eq!(Distribution::depuis_implementor(""), Distribution::Autre);
    }

    /// Les couples du catalogue : « Chrome for Android », l'ancien Edge et WordPad seul écartés.
    #[test]
    fn lignes_du_catalogue() {
        let kev = |p: Produit, e: &str, n: &str| (p.fiche().kev)(e, n);
        assert!(kev(Produit::Chrome, "Google", "Chromium V8"));
        assert!(kev(Produit::Chrome, "Google", "Chrome"));
        assert!(!kev(Produit::Chrome, "Google", "Chrome for Android UI"));
        assert!(kev(Produit::Edge, "Google", "Chromium Mojo"));
        assert!(!kev(Produit::Edge, "Microsoft", "Edge and Internet Explorer"));
        assert!(kev(
            Produit::Firefox,
            "Mozilla",
            "Firefox, Firefox ESR, and Thunderbird"
        ));
        assert!(!kev(Produit::Firefox, "Mozilla", "Thunderbird"));
        assert!(kev(Produit::Office, "Microsoft", "Word"));
        assert!(!kev(Produit::Office, "Microsoft", "WordPad"));
        assert!(kev(Produit::Reader, "Adobe", "Reader and Acrobat"));
        assert!(!kev(Produit::Acrobat, "Adobe", "Flash Player"));
        assert!(kev(
            Produit::Java(Distribution::Oracle),
            "Oracle",
            "Java SE and JRockit"
        ));
        assert!(!kev(Produit::Brave, "Google", "Chromium V8"));
        assert!(kev(Produit::SevenZip, "7-Zip", "7-Zip"));
        assert!(!kev(Produit::SevenZip, "RARLAB", "WinRAR"));
        assert!(!kev(Produit::PuTTY, "PuTTY", "PuTTY"));
        // Slack embarque Chromium (Electron) : ses failles ne se reportent pas sur lui.
        assert!(!kev(Produit::Slack, "Google", "Chromium V8"));
    }

    /// Les logiciels jugés par formula.json sont ceux dont le lecteur des formules garde la version, et inversement.
    #[test]
    fn formules_de_homebrew() {
        use crate::protection::perimes::sources::homebrew::FORMULES_SUIVIES;
        let par_formule: Vec<Produit> = FICHES
            .iter()
            .filter(|f| f.sources.contains(&"formules"))
            .map(|f| f.produit)
            .collect();
        assert_eq!(par_formule, [Produit::SevenZip, Produit::PuTTY]);
        let mut suivies = FORMULES_SUIVIES.to_vec();
        suivies.sort_unstable();
        assert_eq!(suivies, ["putty", "sevenzip"]);
    }
}

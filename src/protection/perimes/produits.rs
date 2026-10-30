//! La table fermée des logiciels suivis : pour chacun, où le trouver (chemins connus sous Windows, identifiant
//! d'application exact sous macOS), quelle version lire, quelles sources le jugent et quelles lignes du catalogue de
//! la CISA le concernent. Rien n'est rapproché par ressemblance de nom : un logiciel absent de la table n'est pas
//! jugé, et un identifiant voisin (« com.google.Chrome.canary ») n'est pas pris pour un autre.

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

/// La clé de l'Info.plist qui porte la version comparable : selon l'éditeur, la version visible ou la build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CleMac {
    /// `CFBundleShortVersionString`.
    Courte,
    /// `CFBundleVersion` : Office la compare à « Update Version » de Microsoft AutoUpdate.
    Build,
}

impl CleMac {
    #[cfg_attr(windows, allow(dead_code))] // lu par l'inventaire de macOS
    pub(crate) fn nom(self) -> &'static str {
        match self {
            CleMac::Courte => "CFBundleShortVersionString",
            CleMac::Build => "CFBundleVersion",
        }
    }
}

/// Une application Mac suivie, reconnue à son identifiant exact.
#[derive(Debug)]
pub(crate) struct AppMac {
    pub bundle_id: &'static str,
    #[cfg_attr(windows, allow(dead_code))] // lu par l'inventaire de macOS
    pub cle: CleMac,
    /// Sa propre source, quand le produit en a une par application (Office : un manifeste MAU par application).
    pub source: Option<&'static str>,
}

/// Une ligne de la table.
pub(crate) struct Fiche {
    /// Pour Java, `Java(Autre)` : la distribution se lit dans le fichier `release`.
    pub produit: Produit,
    /// Sous Windows, l'exécutable (ou le fichier de version) relatif à `Program Files`, `Program Files (x86)` et
    /// `AppData\Local` de chaque compte, par morceaux de chemin.
    #[cfg_attr(target_os = "macos", allow(dead_code))] // lu par l'inventaire de Windows
    pub windows: &'static [&'static [&'static str]],
    #[cfg_attr(windows, allow(dead_code))] // lu par l'inventaire de macOS
    pub mac: &'static [AppMac],
    /// Les sources qui le jugent (identifiants de `sources::SOURCES`).
    pub sources: &'static [&'static str],
    /// Sous macOS, les formules de Homebrew qui l'installent (dossiers `Cellar/<formule>/<version>`), pour un
    /// logiciel sans application.
    #[cfg_attr(windows, allow(dead_code))] // lu par l'inventaire de macOS
    pub homebrew: &'static [&'static str],
    /// Une ligne du catalogue de la CISA (éditeur, produit) le concerne : couples exacts, mesurés sur le catalogue
    /// du 21 oct. 2026.
    pub kev: fn(&str, &str) -> bool,
}

const fn mac(bundle_id: &'static str, cle: CleMac) -> AppMac {
    AppMac {
        bundle_id,
        cle,
        source: None,
    }
}

const fn office(bundle_id: &'static str, source: &'static str) -> AppMac {
    AppMac {
        bundle_id,
        cle: CleMac::Build,
        source: Some(source),
    }
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
    "chrome-mac-stable",
    "chrome-mac-extended",
    "chrome-mac_arm64-stable",
    "chrome-mac_arm64-extended",
];

/// La table. Firefox ESR pour Mac garde l'identifiant de Firefox (`org.mozilla.firefox`) : un identifiant à part
/// n'est pas confirmé, la branche se lit dans `channel-prefs.js`.
pub(crate) const FICHES: &[Fiche] = &[
    Fiche {
        produit: Produit::Chrome,
        windows: &[&["Google", "Chrome", "Application", "chrome.exe"]],
        mac: &[mac("com.google.Chrome", CleMac::Courte)],
        sources: CHROME,
        homebrew: &[],
        kev: kev_chrome,
    },
    Fiche {
        produit: Produit::Edge,
        windows: &[&["Microsoft", "Edge", "Application", "msedge.exe"]],
        mac: &[mac("com.microsoft.edgemac", CleMac::Courte)],
        sources: &["edge"],
        homebrew: &[],
        kev: kev_edge,
    },
    Fiche {
        produit: Produit::Firefox,
        windows: &[&["Mozilla Firefox", "application.ini"]],
        mac: &[mac("org.mozilla.firefox", CleMac::Courte)],
        sources: &["mozilla", "mfsa"],
        homebrew: &[],
        kev: kev_firefox,
    },
    Fiche {
        produit: Produit::Brave,
        windows: &[&["BraveSoftware", "Brave-Browser", "Application", "brave.exe"]],
        mac: &[mac("com.brave.Browser", CleMac::Courte)],
        sources: &[
            "brave-windows-x64",
            "brave-windows-arm64",
            "brave-macos-arm64",
            "brave-macos-x64",
        ],
        homebrew: &[],
        kev: kev_aucune,
    },
    // Sous Windows, Office Click-to-Run se lit dans le registre ; en MSI, il reste à `fin_de_support`.
    Fiche {
        produit: Produit::Office,
        windows: &[],
        mac: &[
            office("com.microsoft.Word", "mau-MSWD2019"),
            office("com.microsoft.Excel", "mau-XCEL2019"),
            office("com.microsoft.Powerpoint", "mau-PPT32019"),
            office("com.microsoft.Outlook", "mau-OPIM2019"),
            office("com.microsoft.onenote.mac", "mau-ONMC2019"),
        ],
        sources: &[
            "office",
            "mau-MSWD2019",
            "mau-XCEL2019",
            "mau-PPT32019",
            "mau-OPIM2019",
            "mau-ONMC2019",
        ],
        homebrew: &[],
        kev: kev_office,
    },
    // Acrobat et Reader sous Windows : par leurs clés Uninstall (nom et éditeur exacts), puis l'exécutable.
    Fiche {
        produit: Produit::Acrobat,
        windows: &[],
        mac: &[mac("com.adobe.Acrobat.Pro", CleMac::Courte)],
        sources: &["adobe-acrobat"],
        homebrew: &[],
        kev: kev_adobe,
    },
    Fiche {
        produit: Produit::Reader,
        windows: &[],
        mac: &[mac("com.adobe.Reader", CleMac::Courte)],
        sources: &["adobe-reader"],
        homebrew: &[],
        kev: kev_adobe,
    },
    // Java : par son fichier `release`, dans les dossiers connus de chaque distribution.
    Fiche {
        produit: Produit::Java(Distribution::Autre),
        windows: &[],
        mac: &[],
        sources: &["eol"],
        homebrew: &[],
        kev: kev_java,
    },
    // 7-Zip et PuTTY : l'exécutable sous Windows (ressource de version) ; sous macOS, sans application, la formule
    // de Homebrew qui les installe. Leur dernière version vient de formula.json (Homebrew suit l'amont).
    Fiche {
        produit: Produit::SevenZip,
        windows: &[&["7-Zip", "7z.exe"]],
        mac: &[],
        sources: &["formules"],
        homebrew: &["sevenzip"],
        kev: kev_7zip,
    },
    Fiche {
        produit: Produit::PuTTY,
        windows: &[&["PuTTY", "putty.exe"]],
        mac: &[],
        sources: &["formules"],
        homebrew: &["putty"],
        kev: kev_aucune,
    },
    // Slack : par machine sous `Program Files\Slack` (MSI, sans mise à jour automatique), par compte sous
    // `AppData\Local\slack` (Squirrel, un dossier `app-<version>` par version) ; Windows ne distingue pas la casse.
    Fiche {
        produit: Produit::Slack,
        windows: &[&["slack", "slack.exe"]],
        mac: &[mac("com.tinyspeck.slackmacgap", CleMac::Courte)],
        sources: &["slack-windows", "slack-macos"],
        homebrew: &[],
        kev: kev_aucune,
    },
];

/// L'application Mac de cet identifiant exact, et son produit.
#[cfg_attr(windows, allow(dead_code))] // lu par l'inventaire de macOS
pub(crate) fn app_mac(bundle_id: &str) -> Option<(Produit, &'static AppMac)> {
    FICHES
        .iter()
        .find_map(|f| f.mac.iter().find(|a| a.bundle_id == bundle_id).map(|a| (f.produit, a)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protection::perimes::sources::SOURCES;

    #[test]
    fn table_sans_double_et_sources_connues() {
        let mut ids: Vec<&str> = FICHES.iter().flat_map(|f| f.mac.iter().map(|a| a.bundle_id)).collect();
        let n = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), n, "identifiant Mac en double");
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
            for s in f.sources.iter().copied().chain(f.mac.iter().filter_map(|a| a.source)) {
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
    fn identifiants_exacts() {
        assert_eq!(app_mac("com.google.Chrome").map(|(p, _)| p), Some(Produit::Chrome));
        assert!(app_mac("com.google.Chrome.canary").is_none());
        assert!(app_mac("com.google.chrome").is_none());
        let (p, app) = app_mac("com.microsoft.Excel").unwrap();
        assert_eq!(
            (p, app.cle, app.source),
            (Produit::Office, CleMac::Build, Some("mau-XCEL2019"))
        );
        assert_eq!(CleMac::Build.nom(), "CFBundleVersion");
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

    /// Les formules de Homebrew de la table sont celles que le lecteur de formula.json garde, et inversement.
    #[test]
    fn formules_de_homebrew() {
        use crate::protection::perimes::sources::homebrew::FORMULES_SUIVIES;
        let mut table: Vec<&str> = FICHES.iter().flat_map(|f| f.homebrew.iter().copied()).collect();
        table.sort_unstable();
        let mut suivies = FORMULES_SUIVIES.to_vec();
        suivies.sort_unstable();
        assert_eq!(table, suivies);
        assert_eq!(
            app_mac("com.tinyspeck.slackmacgap").map(|(p, _)| p),
            Some(Produit::Slack)
        );
    }
}

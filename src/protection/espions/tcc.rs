//! macOS : les autorisations qui permettent d'épier, dans la base des autorisations (TCC.db) : Surveillance de
//! l'entrée (lire les touches tapées partout), Accessibilité (lire et piloter les autres fenêtres) et Enregistrement
//! de l'écran. La base est lue par le lecteur SQLite de Vanguard (`crate::sqlite`), sans /usr/bin/sqlite3. Celle du
//! système demande l'accès complet au disque : sans lui, ce n'est pas vérifié, et c'est dit avec la marche à suivre.
//! Le journal WAL n'est pas lu : quand il existe et n'est pas vide, les changements récents peuvent manquer, et c'est
//! dit aussi.

use crate::risk::Niveau;

use super::echap::Indicateurs;

/// Les services qui permettent d'épier : (nom dans TCC.db, nom dans Réglages Système en français puis en anglais).
pub(super) const SERVICES: &[(&str, [&str; 2])] = &[
    (
        "kTCCServiceListenEvent",
        ["Surveillance de l'entrée", "Input Monitoring"],
    ),
    ("kTCCServiceAccessibility", ["Accessibilité", "Accessibility"]),
    (
        "kTCCServiceScreenCapture",
        ["Enregistrement de l'écran", "Screen Recording"],
    ),
];

/// Les applications qui demandent ces autorisations pour leur travail ordinaire : lanceurs et gestionnaires de
/// fenêtres, claviers et souris, gestionnaires de mots de passe, terminaux et éditeurs de code, navigateurs (partage
/// d'écran dans une visio) et visio, Steam, OBS. Un identifiant terminé par « . » couvre tout ce qui le suit ; un autre,
/// lui-même et ses sous-identifiants (« com.valvesoftware.steam.helper », pas « …steamhelper »). Montrées comme
/// reconnues, jamais cachées. L'identifiant est celui que l'application déclare, sans vérifier sa signature (la
/// colonne csreq n'est pas lue) : l'écran le dit.
const TCC_ATTENDUS: &[&str] = &[
    "com.valvesoftware.steam",
    "com.obsproject.obs-studio",
    "com.raycast.",
    "com.runningwithcrayons.alfred",
    "com.knollsoft.rectangle",
    // Karabiner-Elements : « org.pqrs.Karabiner-Core-Service », « …-EventViewer ».
    "org.pqrs.",
    "com.hegenberg.bettertouchtool",
    "com.1password.",
    "com.agilebits.",
    "com.bitwarden.",
    "org.keepassxc.",
    "com.logi.",
    "us.zoom.xos",
    "com.microsoft.teams",
    "com.microsoft.teams2",
    "com.google.chrome",
    "org.mozilla.firefox",
    "com.microsoft.edgemac",
    "com.brave.browser",
    "com.tinyspeck.slackmacgap",
    "cisco-systems.spark",
    "com.hnc.discord",
    "com.stairways.keyboardmaestro",
    "org.hammerspoon.hammerspoon",
    "com.elgato.",
    "com.googlecode.iterm2",
    "net.kovidgoyal.kitty",
    "com.mitchellh.ghostty",
    "dev.warp.",
    "com.microsoft.vscode",
    "com.jetbrains.",
];

/// Les applications d'Apple qui ont besoin de ces autorisations, nommées une à une : n'importe qui peut déclarer un
/// identifiant « com.apple.* ».
const APPLE_ATTENDUES: &[&str] = &[
    "com.apple.terminal",
    "com.apple.voiceover",
    "com.apple.screensharing",
    "com.apple.quicktimeplayerx",
    "com.apple.dt.xcode",
    "com.apple.scripteditor2",
    "com.apple.systemevents",
    "com.apple.automator",
    "com.apple.facetime",
    "com.apple.safari",
];

/// Une autorisation accordée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Autorisation {
    /// Indice dans `SERVICES`.
    pub service: usize,
    /// Identifiant d'application (« com.example.App ») ou chemin d'un programme.
    pub client: String,
    pub chemin: bool,
}

impl Autorisation {
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(super) fn service(&self) -> &'static str {
        let [fr, en] = SERVICES[self.service].1;
        if crate::langue::anglais() { en } else { fr }
    }
}

/// Les autorisations accordées d'une base TCC : `auth_value` 2 (Big Sur et après), ou `allowed` 1 (avant). `None` :
/// la base ne se lit pas.
pub(super) fn autorisations(octets: &[u8]) -> Option<Vec<Autorisation>> {
    let lignes = crate::sqlite::lignes(
        octets,
        "access",
        &["service", "client", "client_type", "auth_value", "allowed"],
    )?;
    Some(
        lignes
            .into_iter()
            .filter_map(|l| {
                let service = SERVICES.iter().position(|(s, _)| Some(*s) == l[0].texte())?;
                let accordee = l[3].entier() == Some(2) || (l[3].entier().is_none() && l[4].entier() == Some(1));
                accordee.then(|| Autorisation {
                    service,
                    client: crate::ui::affichable(l[1].texte().unwrap_or_default()),
                    chemin: l[2].entier() == Some(1),
                })
            })
            .collect(),
    )
}

/// Ce qu'une autorisation dit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Jugement {
    /// Une application qui en a besoin d'ordinaire.
    Attendue,
    /// Un logiciel de prise de contrôle à distance : renvoyé à « Mon ordinateur est-il contrôlé ? ».
    ADistance,
    Signe(Niveau, String),
}

/// Un chemin d'où un vrai programme ne se lance pas : Téléchargements, dossiers temporaires, dossier partagé par tous
/// les comptes, dossier caché.
fn chemin_louche(chemin: &str) -> bool {
    let bas = chemin.to_lowercase();
    [
        "/tmp/",
        "/private/tmp/",
        "/private/var/folders/",
        "/var/folders/",
        "/users/shared/",
    ]
    .iter()
    .any(|d| bas.starts_with(d))
        || bas.contains("/downloads/")
        || bas.contains("/téléchargements/")
        || chemin.split('/').any(|p| p.starts_with('.') && p.len() > 1)
}

pub(super) fn juger(a: &Autorisation, ind: Option<&Indicateurs>) -> Jugement {
    let nom = a.client.rsplit(['/', '.']).next().unwrap_or(&a.client);
    if crate::protection::distance::controle_a_distance(&a.client) {
        return Jugement::ADistance;
    }
    if let Some(s) = super::connus::reconnu(&a.client) {
        // Un contrôle parental ou une surveillance d'employeur peut être voulu : à regarder, pas « signes sérieux ».
        let niveau = if s.genre == super::connus::Genre::Espion {
            Niveau::Eleve
        } else {
            Niveau::Moyen
        };
        return Jugement::Signe(niveau, super::texte_genre(s));
    }
    if let Some(entree) = ind.and_then(|i| i.produit(nom)) {
        return Jugement::Signe(Niveau::Eleve, super::texte_echap(entree));
    }
    if a.chemin && chemin_louche(&a.client) {
        return Jugement::Signe(
            Niveau::Eleve,
            crate::tr!(
                "programme rangé dans un dossier d'où un vrai programme ne se lance pas",
                "program kept in a folder real programs are not run from"
            )
            .to_string(),
        );
    }
    let bas = a.client.to_lowercase();
    if !a.chemin && APPLE_ATTENDUES.contains(&bas.as_str()) {
        return Jugement::Attendue;
    }
    if !a.chemin && bas.starts_with("com.apple.") {
        return Jugement::Signe(
            Niveau::Moyen,
            crate::tr!(
                "se dit d'Apple, mais sa signature n'est pas vérifiée",
                "claims to be Apple, but its signature is not checked"
            )
            .to_string(),
        );
    }
    let couvert = |p: &str| match p.strip_suffix('.') {
        Some(prefixe) => bas.starts_with(p) || bas == prefixe,
        None => bas == p || bas.strip_prefix(p).is_some_and(|r| r.starts_with('.')),
    };
    if !a.chemin && TCC_ATTENDUS.iter().any(|p| couvert(p)) {
        return Jugement::Attendue;
    }
    Jugement::Signe(
        Niveau::Moyen,
        crate::tr!(
            "application inconnue : l'avez-vous autorisée vous-même ?",
            "unknown app: did you allow it yourself?"
        )
        .to_string(),
    )
}

/// Le relevé de macOS : les deux bases TCC, les applications installées, les processus et les agents lancés au
/// démarrage.
#[cfg(target_os = "macos")]
pub(super) fn relever(r: &mut super::Releve, ind: Option<&Indicateurs>) {
    use crate::{tr, trf};
    let maison = crate::socle::maison();
    let bases = [
        std::path::PathBuf::from("/Library/Application Support/com.apple.TCC/TCC.db"),
        maison.join("Library/Application Support/com.apple.TCC/TCC.db"),
    ];
    for base in &bases {
        match lire_base(base) {
            Some((autorisations, wal)) => {
                r.verifies += 1;
                if wal {
                    r.notes.push(
                        tr!(
                            "autorisations : changements récents peut-être absents (journal WAL non lu)",
                            "permissions: recent changes may be missing (WAL journal not read)"
                        )
                        .to_string(),
                    );
                }
                for a in autorisations {
                    let ou = trf!("{} : {}", "{}: {}", a.service(), a.client);
                    match juger(&a, ind) {
                        Jugement::Attendue => {
                            r.reconnus.push(ou);
                            let note = tr!(
                                "applications reconnues d'après l'identifiant qu'elles déclarent ; leur signature n'est pas vérifiée",
                                "apps recognized by the identifier they declare; their signature is not checked"
                            );
                            if !r.notes.iter().any(|n| n == note) {
                                r.notes.push(note.to_string());
                            }
                        }
                        Jugement::ADistance => r.renvoyer(&a.client),
                        Jugement::Signe(niveau, quoi) => {
                            let objet = format!("tcc:{}/{}", SERVICES[a.service].0, a.client);
                            r.signe(super::Section::Systeme, niveau, &objet, &format!("{} — {quoi}", a.client), ou);
                        }
                    }
                }
            }
            None => r.non_verifie(tr!(
                "autorisations protégées par macOS : Réglages Système › Confidentialité et sécurité › Accès complet au disque, ajoutez le Terminal",
                "permissions protected by macOS: System Settings › Privacy & Security › Full Disk Access, add Terminal"
            )),
        }
    }
    // Les applications installées.
    for dossier in [std::path::PathBuf::from("/Applications"), maison.join("Applications")] {
        for e in std::fs::read_dir(&dossier).into_iter().flatten().flatten() {
            let nom = e.file_name().to_string_lossy().into_owned();
            if let Some(app) = nom.strip_suffix(".app") {
                r.programme(app, crate::ui::chemin_affichable(&dossier.join(&nom)), false, ind);
            }
        }
    }
    // Les agents et services lancés au démarrage : leur nom de fichier et leur « Label ».
    for dossier in [
        maison.join("Library/LaunchAgents"),
        std::path::PathBuf::from("/Library/LaunchAgents"),
        std::path::PathBuf::from("/Library/LaunchDaemons"),
    ] {
        for e in std::fs::read_dir(&dossier).into_iter().flatten().flatten() {
            let chemin = e.path();
            let fichier = e.file_name().to_string_lossy().into_owned();
            let label = crate::plist::lire_fichier(&chemin)
                .ok()
                .and_then(crate::plist::Lu::valeur)
                .and_then(|v| v.cle("Label").and_then(|l| l.texte()).map(String::from));
            let ou = crate::ui::chemin_affichable(&chemin);
            for nom in std::iter::once(fichier.trim_end_matches(".plist").to_string()).chain(label) {
                r.programme(&nom, ou.clone(), true, ind);
            }
        }
    }
    // Les processus : leur chemin, demandé au noyau par la lecture commune (`socle::processus`), sans lancer ps.
    // Une liste illisible est dite, jamais comptée comme vérifiée.
    let pids = crate::socle::processus::pids();
    if pids.is_some() {
        r.verifies += 1;
    } else {
        r.non_verifie(tr!("processus illisibles", "processes unreadable"));
    }
    for pid in pids.unwrap_or_default() {
        let Some(chemin) = crate::socle::processus::programme(pid) else {
            continue;
        };
        let chemin = chemin.to_string_lossy().into_owned();
        let nom = chemin.rsplit('/').next().unwrap_or_default().to_string();
        if !nom.is_empty() {
            r.programme(
                &nom,
                format!("{} (pid {pid})", crate::ui::affichable(&chemin)),
                true,
                ind,
            );
        }
    }
    r.non_verifie(tr!(
        "connexions non vérifiées sous macOS",
        "connections not checked on macOS"
    ));
}

/// Une base TCC lue deux fois si elle a changé pendant la lecture (compteur de changements), et si un journal WAL non
/// vide l'accompagne (changements récents peut-être absents). `None` : illisible (accès complet au disque absent).
#[cfg(target_os = "macos")]
fn lire_base(base: &std::path::Path) -> Option<(Vec<Autorisation>, bool)> {
    lire_base_avec(base, autorisations)
}

/// Comme `lire_base`, avec la lecture des lignes choisie par l'appelant : la même pour les autorisations d'épier et
/// pour celles de la caméra, du micro et des contacts (protection/acces.rs).
#[cfg(target_os = "macos")]
pub(crate) fn lire_base_avec<T>(base: &std::path::Path, lecture: impl Fn(&[u8]) -> Option<T>) -> Option<(T, bool)> {
    // Une vraie TCC.db fait quelques centaines de Ko : au-delà, un fichier fabriqué, jamais chargé en mémoire.
    const TAILLE_MAX: u64 = 32 << 20;
    let lire = || {
        use std::io::Read;
        // Lu par `take` : un fichier qui grossit entre deux lectures reste borné.
        let mut octets = Vec::new();
        std::fs::File::open(base)
            .ok()?
            .take(TAILLE_MAX + 1)
            .read_to_end(&mut octets)
            .ok()?;
        if u64::try_from(octets.len()).unwrap_or(u64::MAX) > TAILLE_MAX {
            return None;
        }
        Some((crate::sqlite::compteur(&octets), lecture(&octets)?))
    };
    let (compteur, mut autorisations) = lire()?;
    if let Some((encore, nouvelles)) = lire()
        && encore != compteur
    {
        autorisations = nouvelles;
    }
    let mut wal = base.as_os_str().to_owned();
    wal.push("-wal");
    let wal = std::fs::metadata(wal).is_ok_and(|m| m.len() > 0);
    Some((autorisations, wal))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autorisations_lues_dans_les_deux_formats() {
        let base = include_bytes!("../../../assets/essais/tcc-bigsur.sqlite");
        let a = autorisations(base).unwrap();
        // Accordées seulement (auth_value 2), parmi les trois services : pas la caméra, pas le refus.
        let clients: Vec<&str> = a.iter().map(|a| a.client.as_str()).collect();
        assert_eq!(clients.len(), 4, "{clients:?}");
        assert_eq!(
            clients[..3],
            [
                "com.example.Clavier",
                "/Users/alice/Downloads/outil",
                "com.obsproject.obs-studio"
            ]
        );
        assert!(a[1].chemin && !a[0].chemin);
        let ancien = include_bytes!("../../../assets/essais/tcc-ancien.sqlite");
        let a = autorisations(ancien).unwrap();
        let clients: Vec<&str> = a.iter().map(|a| a.client.as_str()).collect();
        assert_eq!(clients, ["com.example.Ancien", "/tmp/clavier"]);
        assert_eq!(autorisations(&base[..1000]), None);
    }

    #[test]
    fn autorisations_jugees() {
        let a = |service, client: &str, chemin| Autorisation {
            service,
            client: client.into(),
            chemin,
        };
        let niveau = |j: Jugement| match j {
            Jugement::Signe(n, _) => Some(n),
            _ => None,
        };
        assert_eq!(
            niveau(juger(&a(0, "com.example.Clavier", false), None)),
            Some(Niveau::Moyen)
        );
        assert_eq!(
            niveau(juger(&a(1, "/Users/alice/Downloads/outil", true), None)),
            Some(Niveau::Eleve)
        );
        assert_eq!(
            niveau(juger(&a(0, "/Users/alice/.cache/x", true), None)),
            Some(Niveau::Eleve)
        );
        assert_eq!(
            niveau(juger(&a(0, "com.refog.monitor", false), None)),
            Some(Niveau::Eleve)
        );
        assert_eq!(
            juger(&a(2, "com.obsproject.obs-studio", false), None),
            Jugement::Attendue
        );
        assert_eq!(juger(&a(1, "com.apple.VoiceOver", false), None), Jugement::Attendue);
        assert_eq!(juger(&a(1, "com.1password.1password", false), None), Jugement::Attendue);
        assert_eq!(juger(&a(1, "com.philandro.anydesk", false), None), Jugement::ADistance);
        // L'identifiant se choisit à l'installation : « com.apple. » n'est attendu que pour des applications d'Apple
        // nommées, et un préfixe ne s'étend pas au-delà d'un point.
        assert_eq!(
            niveau(juger(&a(1, "com.apple.systemhelper", false), None)),
            Some(Niveau::Moyen)
        );
        assert_eq!(
            niveau(juger(&a(0, "com.valvesoftware.steamhelper", false), None)),
            Some(Niveau::Moyen)
        );
        assert_eq!(
            juger(&a(0, "com.valvesoftware.steam.helper", false), None),
            Jugement::Attendue
        );
        assert_eq!(juger(&a(1, "com.apple.Terminal", false), None), Jugement::Attendue);
        // Karabiner-Elements écrit ses identifiants avec un tiret : couverts par l'éditeur, pas un voisin.
        assert_eq!(
            juger(&a(1, "org.pqrs.Karabiner-Core-Service", false), None),
            Jugement::Attendue
        );
        assert_eq!(
            niveau(juger(&a(1, "org.pqrsx.Karabiner", false), None)),
            Some(Niveau::Moyen)
        );
        // Partager son écran dans une visio, depuis un navigateur.
        for client in ["com.google.Chrome", "org.mozilla.firefox", "com.tinyspeck.slackmacgap"] {
            assert_eq!(juger(&a(2, client, false), None), Jugement::Attendue, "{client}");
        }
        // Surveillance d'employeur : à regarder, pas « signes sérieux » ; un logiciel vendu pour épier, si.
        assert_eq!(
            niveau(juger(&a(1, "com.example.teramind", false), None)),
            Some(Niveau::Moyen)
        );
        assert_eq!(
            niveau(juger(&a(1, "com.example.spyrix", false), None)),
            Some(Niveau::Eleve)
        );
        // Un chemin n'est jamais « attendu » par son nom : n'importe qui peut nommer un dossier « com.apple. ».
        assert_eq!(
            niveau(juger(&a(1, "/Applications/com.apple.x/outil", true), None)),
            Some(Niveau::Moyen)
        );
    }
}

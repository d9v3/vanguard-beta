//! Bilan de confidentialité : quelles applications ont accès à la position, aux contacts, à la caméra et au micro,
//! et, quand le système le note, la dernière fois qu'elles s'en sont servies. En lecture seule : rien n'est retiré,
//! la marche à suivre est donnée. Sous Windows, le registre des autorisations (ConsentStore, lu par le module
//! `camera`) ; sous Linux, les permissions des applications Flatpak (portails et permissions fixées à
//! l'installation) et Snap ; sous macOS, la base des autorisations du compte (TCC.db), lisible seulement avec
//! l'accès complet au disque. Ce qui n'a pas pu être lu est dit « non vérifié », jamais compté comme sain.

use crate::ui::*;

/// Les quatre permissions, dans l'ordre de l'écran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Permission {
    Position,
    Contacts,
    Camera,
    Micro,
}

const PERMISSIONS: [Permission; 4] = [
    Permission::Position,
    Permission::Contacts,
    Permission::Camera,
    Permission::Micro,
];

impl Permission {
    fn titre(self) -> &'static str {
        match self {
            Permission::Position => tr!("POSITION", "LOCATION"),
            Permission::Contacts => tr!("CONTACTS", "CONTACTS"),
            Permission::Camera => tr!("CAMÉRA", "CAMERA"),
            Permission::Micro => tr!("MICRO", "MICROPHONE"),
        }
    }
}

/// Une application qui a la permission.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Acces {
    permission: Permission,
    application: String,
    /// D'où vient l'accès (« Store », « Flatpak : portail »…), déjà dans la langue de l'écran.
    source: String,
    /// Dernier usage ou date de l'autorisation, déjà rédigé ; `None` : rien de noté.
    quand: Option<String>,
    en_cours: bool,
}

/// Un fait sur une permission (ou sur toutes : `None`), vérifié ou non.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Remarque {
    permission: Option<Permission>,
    texte: String,
    verifie: bool,
}

#[derive(Debug, Default)]
struct Bilan {
    acces: Vec<Acces>,
    remarques: Vec<Remarque>,
}

impl Bilan {
    fn remarque(&mut self, permission: Option<Permission>, verifie: bool, texte: impl Into<String>) {
        self.remarques.push(Remarque {
            permission,
            texte: texte.into(),
            verifie,
        });
    }

    /// Ajoute les accès ; une même application vue deux fois pour la même permission (portail et permission fixe)
    /// ne fait qu'une ligne, les deux sources réunies.
    #[cfg_attr(windows, allow(dead_code))]
    fn ajouter(&mut self, nouveaux: Vec<Acces>) {
        for a in nouveaux {
            if let Some(deja) = self
                .acces
                .iter_mut()
                .find(|d| d.permission == a.permission && d.application == a.application)
            {
                if !deja.source.contains(&a.source) {
                    deja.source = format!("{}, {}", deja.source, a.source);
                }
            } else {
                self.acces.push(a);
            }
        }
    }

    fn non_verifies(&self) -> usize {
        self.remarques.iter().filter(|r| !r.verifie).count()
    }
}

/// `vanguard acces` et le menu Antivirus et protection.
pub fn afficher_tout() {
    titre(tr!(
        "Bilan de confidentialité : qui a accès à quoi ?",
        "Privacy check: which apps have access?"
    ));
    let bilan = lire();
    for p in PERMISSIONS {
        afficher_permission(&bilan, p);
    }
    let generales: Vec<&Remarque> = bilan.remarques.iter().filter(|r| r.permission.is_none()).collect();
    if !generales.is_empty() {
        println!();
        for r in generales {
            afficher_remarque(r);
        }
    }
    conclure(&bilan);
}

fn afficher_permission(bilan: &Bilan, p: Permission) {
    section(p.titre());
    let acces: Vec<&Acces> = bilan.acces.iter().filter(|a| a.permission == p).collect();
    let remarques: Vec<&Remarque> = bilan.remarques.iter().filter(|r| r.permission == Some(p)).collect();
    if acces.is_empty() && remarques.is_empty() {
        trp!("  {GRIS}Aucune application.{RESET}", "  {GRIS}No app.{RESET}");
        return;
    }
    for a in acces.iter().take(25) {
        let marque = if super::camera::lieu_suspect(&a.application) {
            format!("{}⚠{RESET}", couleur(crate::risk::Niveau::Eleve))
        } else if a.en_cours {
            format!("{}●{RESET}", couleur(crate::risk::Niveau::Moyen))
        } else {
            format!("{GRIS}·{RESET}")
        };
        afficher_aligne(&format!("  {marque} "), &affichable(&a.application), 4, "");
        let quand = if a.en_cours {
            Some(tr!("en ce moment", "right now").to_string())
        } else {
            a.quand.clone()
        };
        let detail = match quand {
            Some(q) => format!("{} ; {q}", a.source),
            None => a.source.clone(),
        };
        afficher_aligne("    ", &detail, 4, GRIS);
    }
    if acces.len() > 25 {
        trp!(
            "  {GRIS}… et {} autre(s).{RESET}",
            "  {GRIS}… and {} more.{RESET}",
            acces.len() - 25
        );
    }
    for r in remarques {
        afficher_remarque(r);
    }
}

fn afficher_remarque(r: &Remarque) {
    if r.verifie {
        afficher_aligne(&format!("  {GRIS}·{RESET} "), &r.texte, 4, GRIS);
    } else {
        let debut = format!(
            "  {}?{RESET} {}",
            couleur(crate::risk::Niveau::Moyen),
            tr!("Non vérifié : ", "Not checked: ")
        );
        afficher_aligne(&debut, &r.texte, 4, "");
    }
}

fn conclure(bilan: &Bilan) {
    println!();
    let suspects = bilan
        .acces
        .iter()
        .filter(|a| super::camera::lieu_suspect(&a.application))
        .count();
    let mut lignes = Vec::new();
    if suspects > 0 {
        lignes.push(tr!(
            "⚠ Un programme lancé depuis un dossier temporaire ou Téléchargements a l'un de ces accès : un logiciel espion se cache souvent là. Faites vérifier le fichier (Vérifier un fichier téléchargé, Analyse YARA) avant tout.",
            "⚠ A program started from a temporary folder or Downloads has one of these accesses: spyware often hides there. Have the file checked (Check a downloaded file, YARA scan) first."
        ));
    }
    let n = bilan.non_verifies();
    let non_verifie = trf!(
        "{n} point(s) non vérifié(s) : rien n'est conclu pour eux.",
        "{n} point(s) not checked: nothing is concluded for them."
    );
    if n > 0 {
        lignes.push(&non_verifie);
    }
    lignes.push(marche_a_suivre());
    lignes.push(tr!("Rien n'a été changé.", "Nothing was changed."));
    for (i, texte) in lignes.iter().enumerate() {
        if i > 0 {
            println!();
        }
        for l in envelopper(texte, LARGEUR - 2) {
            println!("  {l}");
        }
    }
}

/// Comment retirer un accès, à la main : Vanguard ne le fait pas lui-même.
fn marche_a_suivre() -> &'static str {
    if cfg!(windows) {
        tr!(
            "Pour retirer un accès : Paramètres › Confidentialité et sécurité › Position (ou Contacts, Caméra, Microphone). Un programme classique n'a pas d'interrupteur à lui : « Autoriser les applications de bureau » les coupe tous, sinon désinstallez-le (Logiciels).",
            "To remove an access: Settings › Privacy & security › Location (or Contacts, Camera, Microphone). A classic program has no switch of its own: “Let desktop apps access” turns them all off, otherwise uninstall it (Software)."
        )
    } else if cfg!(target_os = "macos") {
        tr!(
            "Pour retirer un accès : Réglages Système › Confidentialité et sécurité › Service de localisation (ou Contacts, Caméra, Micro), puis décochez l'application que vous ne reconnaissez pas.",
            "To remove an access: System Settings › Privacy & Security › Location Services (or Contacts, Camera, Microphone), then untick the app you do not recognize."
        )
    } else {
        tr!(
            "Pour retirer un accès : Flatpak, avec Flatseal ou « flatpak override --user --nodevice=all --nosocket=pulseaudio <application> » ; une autorisation de portail, « flatpak permission-remove <table> <objet> <application> ». Snap : « snap disconnect <snap>:camera » (ou audio-record, location-observe).",
            "To remove an access: Flatpak, with Flatseal or “flatpak override --user --nodevice=all --nosocket=pulseaudio <app>”; a portal permission, “flatpak permission-remove <table> <object> <app>”. Snap: “snap disconnect <snap>:camera” (or audio-record, location-observe)."
        )
    }
}

fn lire() -> Bilan {
    let mut bilan = Bilan::default();
    #[cfg(windows)]
    windows::lire(&mut bilan);
    #[cfg(target_os = "linux")]
    linux::lire(&mut bilan);
    #[cfg(target_os = "macos")]
    macos::lire(&mut bilan);
    bilan
}

// ───────────────────────────────────────── Windows ─────────────────────────────────────────

#[cfg(any(windows, test))]
use super::camera::Consentement;

/// Nom de la capacité dans le registre.
#[cfg(any(windows, test))]
fn capacite(p: Permission) -> &'static str {
    match p {
        Permission::Position => "location",
        Permission::Contacts => "contacts",
        Permission::Camera => "webcam",
        Permission::Micro => "microphone",
    }
}

/// Les accès d'une permission d'après le registre de ce compte (`compte`) et de l'ordinateur (`machine`) ; `None` :
/// clé illisible. Une application du Store a accès si elle est autorisée (« Allow ») et que l'interrupteur du compte
/// n'est pas coupé ; un programme classique, tant que ni l'interrupteur du compte ni celui des applications de bureau
/// ne le sont. L'interrupteur de l'appareil (HKLM) coupé l'emporte sur tout.
#[cfg(any(windows, test))]
fn juger_windows(p: Permission, compte: Option<&Consentement>, machine: Option<&Consentement>, b: &mut Bilan) {
    let est = |v: &Option<String>, quoi: &str| v.as_deref().is_some_and(|v| v.eq_ignore_ascii_case(quoi));
    if machine.is_some_and(|m| est(&m.global, "Deny")) {
        b.remarque(
            Some(p),
            true,
            tr!(
                "Coupée pour tout l'ordinateur : aucune application n'y a accès.",
                "Turned off for the whole computer: no app has access."
            ),
        );
        return;
    }
    let Some(compte) = compte else {
        b.remarque(
            Some(p),
            false,
            tr!(
                "les réglages de ce compte sont illisibles dans le registre.",
                "this account's settings cannot be read from the registry."
            ),
        );
        return;
    };
    let compte_coupe = est(&compte.global, "Deny");
    let bureau_coupe = compte_coupe || est(&compte.hors_store, "Deny");
    if compte_coupe {
        b.remarque(
            Some(p),
            true,
            tr!(
                "Coupée pour toutes les applications de ce compte.",
                "Turned off for all of this account's apps."
            ),
        );
    } else if bureau_coupe {
        b.remarque(
            Some(p),
            true,
            tr!(
                "Coupée pour les programmes classiques (hors Store).",
                "Turned off for classic programs (outside the Store)."
            ),
        );
    }
    let mut vus = std::collections::HashSet::new();
    let mut trouves: Vec<(u64, Acces)> = Vec::new();
    let entrees = compte
        .entrees
        .iter()
        .chain(machine.into_iter().flat_map(|m| m.entrees.iter()));
    for e in entrees {
        if !vus.insert(e.nom.to_lowercase()) {
            continue;
        }
        let a_acces = if e.hors_store {
            !bureau_coupe && !est(&e.valeur, "Deny")
        } else {
            // Sans valeur, une application du Store qui s'en est déjà servie l'avait.
            !compte_coupe && (est(&e.valeur, "Allow") || (e.valeur.is_none() && e.debut != 0))
        };
        if !a_acces {
            continue;
        }
        let (application, source) = if e.hors_store {
            (
                super::camera::nom_programme(&e.nom),
                tr!("programme classique", "classic program"),
            )
        } else {
            // « Microsoft.WindowsCamera_8wekyb3d8bbwe » : la fin désigne l'éditeur, illisible.
            let nom = e.nom.rsplit_once('_').map_or(e.nom.as_str(), |(n, _)| n);
            (nom.to_string(), tr!("application du Store", "Store app"))
        };
        let dernier = e.debut.max(e.fin);
        let quand = super::camera::date_filetime(dernier).map_or_else(
            || tr!("aucun usage noté", "no use recorded").to_string(),
            |d| trf!("dernier usage {d}", "last used {d}"),
        );
        trouves.push((
            dernier,
            Acces {
                permission: p,
                application,
                source: source.to_string(),
                quand: Some(quand),
                en_cours: e.debut != 0 && e.fin == 0,
            },
        ));
    }
    // En cours d'abord, puis du plus récent au plus ancien.
    trouves.sort_by(|(t1, a1), (t2, a2)| {
        (!a1.en_cours, std::cmp::Reverse(*t1), &a1.application).cmp(&(
            !a2.en_cours,
            std::cmp::Reverse(*t2),
            &a2.application,
        ))
    });
    b.acces.extend(trouves.into_iter().map(|(_, a)| a));
}

#[cfg(windows)]
mod windows {
    use super::{Bilan, PERMISSIONS, capacite, juger_windows};
    use crate::protection::camera::windows::consentement;
    use crate::tr;

    pub(super) fn lire(b: &mut Bilan) {
        for p in PERMISSIONS {
            let compte = consentement(false, capacite(p));
            let machine = consentement(true, capacite(p));
            juger_windows(p, compte.as_ref(), machine.as_ref(), b);
        }
        b.remarque(
            None,
            true,
            tr!(
                "Les programmes classiques ne demandent pas d'autorisation une à une : Windows note seulement ceux qui se sont déjà servis de la position, de la caméra ou du micro. Un programme jamais lancé y aurait accès lui aussi.",
                "Classic programs do not ask for permission one by one: Windows only records those that already used the location, camera or microphone. A program never started would have access too."
            ),
        );
    }
}

// ───────────────────────────────────────── Linux ─────────────────────────────────────────

/// Les colonnes d'une ligne : séparées par des tabulations sans terminal, sinon par des espaces.
#[cfg(any(target_os = "linux", test))]
fn colonnes(ligne: &str) -> Vec<&str> {
    if ligne.contains('\t') {
        ligne.split('\t').map(str::trim).collect()
    } else {
        ligne.split_whitespace().collect()
    }
}

/// `flatpak permissions` : les autorisations données par les portails (table, objet, application, permissions,
/// données).
#[cfg(any(target_os = "linux", test))]
fn lire_flatpak_portails(texte: &str) -> Vec<Acces> {
    texte
        .lines()
        .filter_map(|ligne| {
            let c = colonnes(ligne);
            let [table, objet, application, permissions, ..] = c.as_slice() else {
                return None;
            };
            if *table == "Table" {
                return None;
            }
            acces_portail(table, objet, application, permissions.split(',').next().unwrap_or(""))
        })
        .collect()
}

/// Ce qu'ouvre une autorisation d'un portail, d'après sa première permission. Position : la précision accordée
/// (NONE : refusée), suivie d'une date ; caméra et micro : « yes ».
#[cfg(any(target_os = "linux", test))]
fn acces_portail(table: &str, objet: &str, application: &str, premiere: &str) -> Option<Acces> {
    if application.is_empty() {
        return None;
    }
    let premiere = premiere.trim().to_ascii_uppercase();
    let (permission, source) = match (table, objet) {
        ("location", "location") => {
            let precision = match premiere.as_str() {
                "" | "NONE" => return None,
                "COUNTRY" => tr!("pays", "country"),
                "CITY" => tr!("ville", "city"),
                "NEIGHBORHOOD" => tr!("quartier", "neighborhood"),
                "STREET" => tr!("rue", "street"),
                _ => tr!("précise", "exact"),
            };
            (
                Permission::Position,
                trf!("Flatpak : portail, {precision}", "Flatpak: portal, {precision}"),
            )
        }
        ("devices", "camera") if premiere == "YES" => (
            Permission::Camera,
            tr!("Flatpak : portail", "Flatpak: portal").to_string(),
        ),
        ("devices", "microphone") if premiere == "YES" => (
            Permission::Micro,
            tr!("Flatpak : portail", "Flatpak: portal").to_string(),
        ),
        _ => return None,
    };
    Some(Acces {
        permission,
        application: application.to_string(),
        source,
        quand: None,
        en_cours: false,
    })
}

/// `flatpak info --show-permissions <application>` : les permissions fixées à l'installation (et les réglages
/// ajoutés), qui passent outre les portails. Tous les appareils : la caméra ; le son de PulseAudio ou PipeWire : le
/// micro ; le carnet d'adresses (Evolution, Akonadi) ; GeoClue : la position.
/// Une permission Flatpak qui ouvre tout le dossier personnel, ou toutes ses données (« home », « host »,
/// « xdg-data », « ~/.local/share »…), en lecture ou en écriture (« :ro », « :rw », « :create » n'y changent rien).
#[cfg(any(target_os = "linux", test))]
fn dossier_personnel(valeur: &str) -> bool {
    let sans_mode = valeur.split(':').next().unwrap_or(valeur).trim_end_matches('/');
    matches!(
        sans_mode,
        "home" | "host" | "xdg-data" | "~" | "~/.local" | "~/.local/share" | "xdg-config"
    )
}

#[cfg(any(target_os = "linux", test))]
fn lire_flatpak_statiques(application: &str, texte: &str) -> Vec<Acces> {
    let mut trouvees: Vec<(Permission, &'static str)> = Vec::new();
    let mut groupe = "";
    for ligne in texte.lines().map(str::trim) {
        if let Some(g) = ligne.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            groupe = g;
            continue;
        }
        let Some((cle, valeur)) = ligne.split_once('=') else {
            continue;
        };
        let valeurs = || valeur.split(';').map(str::trim);
        match (groupe, cle.trim()) {
            // Tous les appareils : /dev/video* et /dev/snd, donc la caméra et le micro.
            ("Context", "devices") if valeurs().any(|v| v == "all") => {
                trouvees.push((Permission::Camera, tr!("tous les appareils", "all devices")));
                trouvees.push((Permission::Micro, tr!("tous les appareils", "all devices")));
            }
            ("Context", "sockets") if valeurs().any(|v| v == "pulseaudio") => {
                trouvees.push((Permission::Micro, tr!("son (pulseaudio)", "sound (pulseaudio)")));
            }
            ("Context", "filesystems") => {
                for v in valeurs() {
                    if v.starts_with("xdg-run/pipewire-0") {
                        trouvees.push((Permission::Micro, "PipeWire"));
                        trouvees.push((Permission::Camera, "PipeWire"));
                    } else if v.starts_with("xdg-data/evolution") || v.starts_with("~/.local/share/evolution") {
                        trouvees.push((Permission::Contacts, tr!("fichiers d'Evolution", "Evolution files")));
                    } else if dossier_personnel(v) {
                        // Tout le dossier personnel (ou toutes ses données) contient le carnet d'adresses.
                        trouvees.push((
                            Permission::Contacts,
                            tr!("fichiers du dossier personnel", "home folder files"),
                        ));
                    }
                }
            }
            ("Session Bus Policy", nom)
                if valeur.trim() != "none"
                    && (nom.contains("AddressBook")
                        || nom.contains("evolution.dataserver")
                        || nom.starts_with("org.freedesktop.Akonadi")) =>
            {
                trouvees.push((Permission::Contacts, tr!("carnet d'adresses", "address book")));
            }
            ("System Bus Policy", nom) if valeur.trim() != "none" && nom.starts_with("org.freedesktop.GeoClue2") => {
                trouvees.push((Permission::Position, "GeoClue"));
            }
            _ => {}
        }
    }
    let mut acces: Vec<Acces> = Vec::new();
    for (permission, quoi) in trouvees {
        if acces.iter().any(|a| a.permission == permission) {
            continue;
        }
        acces.push(Acces {
            permission,
            application: application.to_string(),
            source: trf!("Flatpak : {quoi}", "Flatpak: {quoi}"),
            quand: None,
            en_cours: false,
        });
    }
    acces
}

/// `snap connections` : les interfaces branchées (interface, prise « snap:nom », sortie, notes). Une prise sans
/// sortie (« - ») est débranchée.
#[cfg(any(target_os = "linux", test))]
fn lire_snap(texte: &str) -> Vec<Acces> {
    let mut acces = Vec::new();
    for ligne in texte.lines() {
        let c = colonnes(ligne);
        let [interface, prise, sortie, ..] = c.as_slice() else {
            continue;
        };
        if *interface == "Interface" || *sortie == "-" {
            continue;
        }
        let permission = match *interface {
            "camera" => Permission::Camera,
            "audio-record" | "pulseaudio" => Permission::Micro,
            "location-observe" | "location-control" => Permission::Position,
            "contacts-service" => Permission::Contacts,
            _ => continue,
        };
        let snap = prise.split(':').next().unwrap_or("");
        if snap.is_empty() {
            continue;
        }
        acces.push(Acces {
            permission,
            application: snap.to_string(),
            source: format!("Snap ({interface})"),
            quand: None,
            en_cours: false,
        });
    }
    acces
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{
        Acces, Bilan, PERMISSIONS, Permission, acces_portail, lire_flatpak_portails, lire_flatpak_statiques, lire_snap,
    };
    use crate::machine::linux::gvdb::{Genre, Gvdb, Variante};
    use crate::machine::linux::natif;
    use crate::{tr, trf};
    use std::fmt::Write;
    use std::path::PathBuf;
    use std::process::Command;

    fn sortie(programme: &str, args: &[&str]) -> Option<String> {
        crate::commande::lancer_en_anglais(Command::new(programme).args(args), 20)
            .filter(|r| r.code == Some(0))
            .map(|r| r.sortie)
    }

    /// Une lecture en échec se redit sous chaque permission qu'elle touchait : sinon « Aucune application » y
    /// passerait pour vérifié.
    fn non_verifie(b: &mut Bilan, permissions: &[Permission], texte: &str) {
        for p in permissions {
            b.remarque(Some(*p), false, texte);
        }
    }

    /// Applications Flatpak examinées au plus (un `flatpak info` chacune, ~0,1 s) : une installation ordinaire en a
    /// quelques dizaines.
    const APPLICATIONS_MAX: usize = 300;

    /// Les autorisations des portails, lues dans les fichiers du magasin des permissions (`flatpak/db/devices`,
    /// `flatpak/db/location` des données de l'utilisateur), ceux que `flatpak permissions` fait lire au service :
    /// une table absente n'a rien accordé. `None` si une table ne se lit pas : la commande prend le relais.
    pub(super) fn lire_magasin_flatpak(dossier: &std::path::Path) -> Option<Vec<Acces>> {
        let mut acces = Vec::new();
        for table in ["devices", "location"] {
            let Some(base) = Gvdb::ouvrir(&dossier.join(table)).ok()? else {
                continue;
            };
            // Chaque objet (« camera », « location ») : ses données, puis la liste des permissions par application.
            let Some(principale) = base.racine()?.table("main").ok()? else {
                continue;
            };
            for objet in principale.noms_des_valeurs()? {
                let Variante::Tuple(m) = principale.valeur(&objet)? else {
                    return None;
                };
                let [Variante::Boite(_), Variante::Tableau(Genre::Entree(..), applications)] = m.as_slice() else {
                    return None;
                };
                for a in applications {
                    let Variante::Entree(application, permissions) = a else {
                        return None;
                    };
                    let premiere = permissions.chaines()?.first().copied().unwrap_or("");
                    acces.extend(acces_portail(table, &objet, application.chaine()?, premiere));
                }
            }
        }
        Some(acces)
    }

    /// Le dossier du magasin des permissions ; `None` s'il serait relatif (HOME vide, XDG_DATA_HOME relatif) : lu
    /// depuis le dossier courant, il y manquerait, et « rien n'a été accordé » passerait pour vérifié.
    pub(super) fn dossier_magasin_flatpak(
        donnees: Option<std::ffi::OsString>,
        maison: &std::path::Path,
    ) -> Option<std::path::PathBuf> {
        let dossier = donnees
            .filter(|d| !d.is_empty())
            .map_or_else(|| maison.join(".local/share"), PathBuf::from)
            .join("flatpak/db");
        dossier.is_absolute().then_some(dossier)
    }

    fn flatpak(b: &mut Bilan) {
        match dossier_magasin_flatpak(std::env::var_os("XDG_DATA_HOME"), &crate::socle::maison())
            .and_then(|d| lire_magasin_flatpak(&d))
            .or_else(|| sortie("flatpak", &["permissions"]).map(|t| lire_flatpak_portails(&t)))
        {
            Some(a) => b.ajouter(a),
            None => non_verifie(
                b,
                &[Permission::Position, Permission::Camera, Permission::Micro],
                tr!(
                    "les autorisations des portails Flatpak sont illisibles : ni leur base (flatpak/db) ni la commande flatpak permissions n'ont répondu.",
                    "the Flatpak portal permissions cannot be read: neither their database (flatpak/db) nor the flatpak permissions command answered."
                ),
            ),
        }
        // Lues dans les dossiers de Flatpak ; sa commande en secours, quand d'autres installations sont réglées.
        let Some(liste) = crate::machine::linux::paquets::applications_flatpak() else {
            non_verifie(
                b,
                &PERMISSIONS,
                tr!(
                    "la liste des applications Flatpak est illisible.",
                    "the list of Flatpak apps cannot be read."
                ),
            );
            return;
        };
        let mut applications: Vec<&str> = liste.iter().map(String::as_str).collect();
        applications.sort_unstable();
        applications.dedup();
        if applications.is_empty() {
            b.remarque(
                None,
                true,
                tr!("Flatpak : aucune application installée.", "Flatpak: no app installed."),
            );
        }
        let mut illisibles = 0;
        for a in applications.iter().take(APPLICATIONS_MAX) {
            match permissions(a) {
                Some(t) => b.ajouter(lire_flatpak_statiques(a, &t)),
                None => illisibles += 1,
            }
        }
        // Au-delà de la borne, les applications restantes ne sont pas examinées : le dire, sinon elles
        // passeraient pour vérifiées.
        if applications.len() > APPLICATIONS_MAX {
            let restantes = applications.len() - APPLICATIONS_MAX;
            non_verifie(
                b,
                &PERMISSIONS,
                &trf!(
                    "{restantes} application(s) Flatpak non examinée(s) : seules les {APPLICATIONS_MAX} premières le sont.",
                    "{restantes} Flatpak app(s) not examined: only the first {APPLICATIONS_MAX} are."
                ),
            );
        }
        if illisibles > 0 {
            non_verifie(
                b,
                &PERMISSIONS,
                &trf!(
                    "les permissions de {illisibles} application(s) Flatpak sont illisibles.",
                    "the permissions of {illisibles} Flatpak app(s) cannot be read."
                ),
            );
        }
    }

    /// Les permissions statiques d'une application, ce que montre `flatpak info --show-permissions` : son fichier
    /// metadata, puis les surcharges posées par `flatpak override` (pour toutes les applications, « global », puis
    /// pour elle ; celles du système, puis celles du compte). La commande ne sert qu'en secours : installations
    /// réglées ailleurs, ou application dont le metadata manque.
    pub(super) fn permissions(id: &str) -> Option<String> {
        if crate::machine::linux::paquets::flatpak_par_defaut()
            && let Some(metadata) = natif::flatpak_metadata(id)
        {
            let donnees = std::env::var_os("XDG_DATA_HOME")
                .map_or_else(|| crate::socle::maison().join(".local/share"), PathBuf::from);
            let surcharges: Vec<String> = [PathBuf::from("/var/lib/flatpak"), donnees.join("flatpak")]
                .iter()
                .flat_map(|i| [i.join("overrides/global"), i.join("overrides").join(id)])
                // Celles du compte se posent sans droits : un tube nommé ou un lien vers /dev/zero ne doit ni
                // bloquer ni remplir la mémoire. Un vrai fichier de surcharge fait quelques centaines d'octets.
                .filter_map(|f| natif::lire_borne(&f, 1 << 20))
                .collect();
            return Some(fusionner(&metadata, &surcharges));
        }
        sortie("flatpak", &["info", "--show-permissions", id])
    }

    /// Le metadata et ses surcharges réunis comme Flatpak le fait, en un texte que `lire_flatpak_statiques` lit.
    /// Dans [Context], chaque clé est une liste (« sockets=x11;pulseaudio; ») : une surcharge ajoute ses valeurs, et
    /// « !valeur » en retire une (« !home » retire aussi « home:ro »). Dans les politiques de bus, la dernière valeur
    /// d'un nom l'emporte (« none » retire l'accès).
    pub(super) fn fusionner(metadata: &str, surcharges: &[String]) -> String {
        let nom = |v: &str| {
            v.rsplit_once(':')
                .filter(|(_, mode)| ["ro", "rw", "create"].contains(mode))
                .map_or(v, |(n, _)| n)
                .to_string()
        };
        let mut contexte: Vec<(String, Vec<String>)> = Vec::new();
        let mut bus: Vec<(&str, String, String)> = Vec::new();
        for texte in std::iter::once(metadata).chain(surcharges.iter().map(String::as_str)) {
            for (cle, valeur) in natif::section_ini(texte, "Context") {
                let i = contexte.iter().position(|(c, _)| c == cle).unwrap_or_else(|| {
                    contexte.push((cle.to_string(), Vec::new()));
                    contexte.len() - 1
                });
                let liste = &mut contexte[i].1;
                for v in valeur.split(';').map(str::trim).filter(|v| !v.is_empty()) {
                    if let Some(retire) = v.strip_prefix('!') {
                        liste.retain(|x| nom(x) != nom(retire));
                    } else if !liste.iter().any(|x| x == v) {
                        liste.push(v.to_string());
                    }
                }
            }
            for groupe in ["Session Bus Policy", "System Bus Policy"] {
                for (cle, valeur) in natif::section_ini(texte, groupe) {
                    bus.retain(|(g, c, _)| *g != groupe || c != cle);
                    bus.push((groupe, cle.to_string(), valeur.to_string()));
                }
            }
        }
        let mut texte = String::from("[Context]\n");
        for (cle, valeurs) in contexte.iter().filter(|(_, v)| !v.is_empty()) {
            let _ = writeln!(texte, "{cle}={};", valeurs.join(";"));
        }
        for groupe in ["Session Bus Policy", "System Bus Policy"] {
            let _ = writeln!(texte, "\n[{groupe}]");
            for (_, cle, valeur) in bus.iter().filter(|(g, _, _)| *g == groupe) {
                let _ = writeln!(texte, "{cle}={valeur}");
            }
        }
        texte
    }

    pub(super) fn lire(b: &mut Bilan) {
        // Le programme est-il installé ? Distingue « absent » de « en panne », qui se dit non vérifié.
        let flatpak = natif::present("flatpak");
        let snap = natif::present("snap");
        if flatpak {
            self::flatpak(b);
        }
        if snap {
            match sortie("snap", &["connections"]) {
                Some(t) => b.ajouter(lire_snap(&t)),
                None => non_verifie(
                    b,
                    &PERMISSIONS,
                    tr!(
                        "les interfaces des applications Snap sont illisibles : la commande snap connections a échoué.",
                        "the Snap apps' interfaces cannot be read: the snap connections command failed."
                    ),
                ),
            }
        }
        if !flatpak && !snap {
            b.remarque(
                None,
                true,
                tr!(
                    "Ni Flatpak ni Snap ici : aucune application n'a de permissions à part.",
                    "Neither Flatpak nor Snap here: no app has separate permissions."
                ),
            );
        }
        b.remarque(
            None,
            true,
            tr!(
                "Les programmes installés hors Flatpak et Snap ne demandent aucune permission : ils peuvent tous se servir de la caméra, du micro et des contacts de ce compte. Ce qui s'en sert en ce moment : l'outil « Caméra et micro ».",
                "Programs installed outside Flatpak and Snap ask for no permission: they can all use this account's camera, microphone and contacts. What uses them right now: the “Camera and mic” tool."
            ),
        );
    }
}

// ───────────────────────────────────────── macOS ─────────────────────────────────────────

/// Les accès d'une base TCC, lue par le lecteur SQLite de Vanguard (comme les autorisations d'épier, voir
/// espions/tcc.rs) : caméra, micro et contacts autorisés (`auth_value` 2) ou autorisés en partie (3), avec la date du
/// réglage. Avant Big Sur, la colonne s'appelait `allowed` (0 ou 1) : 1 vaut alors une autorisation pleine. `None` :
/// la base ne se lit pas.
#[cfg(any(target_os = "macos", test))]
fn lire_tcc(octets: &[u8]) -> Option<Vec<Acces>> {
    let lignes = crate::sqlite::lignes(
        octets,
        "access",
        &["service", "client", "auth_value", "allowed", "last_modified"],
    )?;
    Some(
        lignes
            .into_iter()
            .filter_map(|l| {
                let permission = match l[0].texte()? {
                    "kTCCServiceCamera" => Permission::Camera,
                    "kTCCServiceMicrophone" => Permission::Micro,
                    "kTCCServiceAddressBook" => Permission::Contacts,
                    _ => return None,
                };
                let source = match l[2].entier().or_else(|| l[3].entier().map(|a| a.saturating_mul(2)))? {
                    2 => tr!("autorisée", "allowed"),
                    3 => tr!("autorisée en partie", "partly allowed"),
                    _ => return None,
                };
                let quand = l[4]
                    .entier()
                    .filter(|s| *s > 0)
                    .and_then(|s| chrono::DateTime::from_timestamp(s, 0))
                    .map(|d| {
                        let jour = d.with_timezone(&chrono::Local).format("%Y-%m-%d").to_string();
                        trf!("réglée le {jour}", "set on {jour}")
                    });
                Some(Acces {
                    permission,
                    application: l[1].texte().unwrap_or_default().to_string(),
                    source: source.to_string(),
                    quand,
                    en_cours: false,
                })
            })
            .collect(),
    )
}

#[cfg(target_os = "macos")]
mod macos {
    use super::{Bilan, Permission, lire_tcc};
    use crate::tr;

    pub(super) fn lire(b: &mut Bilan) {
        let base = crate::socle::maison().join("Library/Application Support/com.apple.TCC/TCC.db");
        match crate::protection::espions::tcc::lire_base_avec(&base, lire_tcc) {
            Some((acces, wal)) => {
                b.ajouter(acces);
                if wal {
                    b.remarque(
                        None,
                        true,
                        tr!(
                            "Caméra, micro et contacts : changements récents peut-être absents (journal WAL non lu).",
                            "Camera, microphone and contacts: recent changes may be missing (WAL journal not read)."
                        ),
                    );
                }
            }
            None => {
                for p in [Permission::Contacts, Permission::Camera, Permission::Micro] {
                    b.remarque(
                        Some(p),
                        false,
                        tr!(
                            "la liste est protégée par macOS. Pour que Vanguard la lise : Réglages Système › Confidentialité et sécurité › Accès complet au disque, ajoutez le Terminal, puis relancez. Sinon, regardez-la à la même page.",
                            "macOS protects the list. For Vanguard to read it: System Settings › Privacy & Security › Full Disk Access, add Terminal, then run again. Otherwise, look at it on the same page."
                        ),
                    );
                }
            }
        }
        b.remarque(
            Some(Permission::Position),
            false,
            tr!(
                "macOS garde ces autorisations hors de portée des programmes. Regardez-les dans Réglages Système › Confidentialité et sécurité › Service de localisation.",
                "macOS keeps these permissions out of programs' reach. See them in System Settings › Privacy & Security › Location Services."
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protection::camera::Entree;

    fn noms(b: &Bilan, p: Permission) -> Vec<&str> {
        b.acces
            .iter()
            .filter(|a| a.permission == p)
            .map(|a| a.application.as_str())
            .collect()
    }

    fn entree(nom: &str, valeur: Option<&str>, debut: u64, fin: u64, hors_store: bool) -> Entree {
        Entree {
            nom: nom.into(),
            valeur: valeur.map(Into::into),
            debut,
            fin,
            hors_store,
        }
    }

    #[test]
    fn registre_de_windows() {
        // 2026-10-18 01:00:00 UTC en FILETIME, et une heure plus tard.
        let t = (1_792_285_200 + 11_644_473_600) * 10_000_000_u64;
        let h = 3600 * 10_000_000_u64;
        let compte = Consentement {
            global: Some("Allow".into()),
            hors_store: Some("Allow".into()),
            entrees: vec![
                entree("Microsoft.WindowsMaps_8wekyb3d8bbwe", Some("Allow"), t, t + h, false),
                entree("Contoso.Meteo_abcdefghijklm", Some("Deny"), t, t + h, false),
                entree("Fabrikam.Notes_abcdefghijklm", Some("Allow"), 0, 0, false),
                entree("C:#Users#alice#Downloads#outil.exe", None, t + 2 * h, 0, true),
            ],
        };
        // L'ordinateur ajoute une application déjà vue (ignorée) et une autre.
        let machine = Consentement {
            global: Some("Allow".into()),
            hors_store: None,
            entrees: vec![
                entree("Microsoft.WindowsMaps_8wekyb3d8bbwe", Some("Deny"), 0, 0, false),
                entree("Litware.Carte_abcdefghijklm", Some("Allow"), t + h, t + h, false),
            ],
        };
        let mut b = Bilan::default();
        juger_windows(Permission::Position, Some(&compte), Some(&machine), &mut b);
        // En cours d'abord, puis du plus récent au plus ancien ; la refusée n'y est pas.
        assert_eq!(
            noms(&b, Permission::Position),
            [
                r"C:\Users\alice\Downloads\outil.exe",
                "Litware.Carte",
                "Microsoft.WindowsMaps",
                "Fabrikam.Notes"
            ]
        );
        assert!(b.acces[0].en_cours && super::super::camera::lieu_suspect(&b.acces[0].application));
        assert!(b.acces[2].quand.as_deref().is_some_and(|q| q.contains("2026-10-1")));
        assert_eq!(b.acces[3].quand.as_deref(), Some("aucun usage noté"));
        assert_eq!(b.non_verifies(), 0);

        // Les programmes classiques coupés : seules les applications du Store restent.
        let mut coupe = compte.clone();
        coupe.hors_store = Some("Deny".into());
        let mut b = Bilan::default();
        juger_windows(Permission::Camera, Some(&coupe), None, &mut b);
        assert_eq!(
            noms(&b, Permission::Camera),
            ["Microsoft.WindowsMaps", "Fabrikam.Notes"]
        );
        assert!(b.remarques.iter().all(|r| r.verifie));

        // Tout le compte coupé : rien.
        coupe.global = Some("Deny".into());
        let mut b = Bilan::default();
        juger_windows(Permission::Micro, Some(&coupe), None, &mut b);
        assert!(b.acces.is_empty() && b.remarques.len() == 1);

        // L'appareil coupé l'emporte, même si le compte est illisible.
        let mut b = Bilan::default();
        let appareil = Consentement {
            global: Some("Deny".into()),
            ..Consentement::default()
        };
        juger_windows(Permission::Contacts, None, Some(&appareil), &mut b);
        assert!(b.acces.is_empty() && b.non_verifies() == 0);

        // Le compte illisible : non vérifié, jamais « aucune application ».
        let mut b = Bilan::default();
        juger_windows(Permission::Contacts, None, None, &mut b);
        assert_eq!(b.non_verifies(), 1);
        assert_eq!(capacite(Permission::Camera), "webcam");
    }

    #[test]
    fn portails_de_flatpak() {
        let sortie = "Table\tObject\tApp\tPermissions\tData\n\
                      location\tlocation\torg.exemple.Cartes\tEXACT,1792285200\t\n\
                      location\tlocation\torg.exemple.Meteo\tCITY,1792285200\t\n\
                      location\tlocation\torg.exemple.Refuse\tNONE,0\t\n\
                      devices\tcamera\torg.exemple.Visio\tyes\t0x00\n\
                      devices\tcamera\torg.exemple.Non\tno\t0x00\n\
                      devices\tmicrophone\torg.exemple.Visio\tyes\t\n\
                      devices\tspeakers\torg.exemple.Visio\tyes\t\n\
                      background\tbackground\torg.exemple.Visio\tyes\t\n\
                      notifications\tnotification\t\tyes\t\n";
        let a = lire_flatpak_portails(sortie);
        let resume: Vec<(Permission, &str)> = a.iter().map(|x| (x.permission, x.application.as_str())).collect();
        assert_eq!(
            resume,
            [
                (Permission::Position, "org.exemple.Cartes"),
                (Permission::Position, "org.exemple.Meteo"),
                (Permission::Camera, "org.exemple.Visio"),
                (Permission::Micro, "org.exemple.Visio"),
            ]
        );
        assert!(a[0].source.contains("précise") && a[1].source.contains("ville"));
        // Dans un terminal, les colonnes sont alignées par des espaces.
        let alignee = "Table    Object   App                 Permissions Data\n\
                       devices  camera   org.exemple.Visio   yes         0x00\n";
        assert_eq!(lire_flatpak_portails(alignee).len(), 1);
        assert_eq!(lire_flatpak_portails(""), Vec::<Acces>::new());
    }

    /// Le magasin des permissions lu dans ses fichiers : une table écrite par xdg-permission-store lui-même
    /// (`flatpak permission-set` dans une session D-Bus à part), et des tables fabriquées ici.
    #[cfg(target_os = "linux")]
    #[test]
    fn magasin_des_permissions_de_flatpak() {
        use crate::machine::linux::gvdb::fabrique::{Contenu, chaines, fichier, hexa, valeur};
        use crate::machine::linux::gvdb::{Genre, Variante};
        let dossier = std::env::temp_dir().join(format!("vanguard-acces-magasin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).unwrap();
        let resume = |a: &[Acces]| -> Vec<(Permission, String)> {
            a.iter().map(|x| (x.permission, x.application.clone())).collect()
        };
        // Aucune table : rien n'a été accordé.
        assert_eq!(linux::lire_magasin_flatpak(&dossier), Some(Vec::new()));
        // camera : org.exemple.Camera et org.exemple.Deux « yes » ; microphone : org.exemple.Micro « no ».
        std::fs::write(dossier.join("devices"), hexa(MAGASIN_DEVICES)).unwrap();
        assert_eq!(
            resume(&linux::lire_magasin_flatpak(&dossier).unwrap()),
            [
                (Permission::Camera, "org.exemple.Camera".to_string()),
                (Permission::Camera, "org.exemple.Deux".to_string())
            ]
        );
        let entree = |app: &str, permissions: &[&str]| {
            Variante::Entree(Box::new(Variante::Chaine(app.into())), Box::new(chaines(permissions)))
        };
        let objet = |entrees: Vec<Variante>| {
            Variante::Tuple(vec![
                Variante::Boite(Box::new(Variante::Octet(0))),
                Variante::Tableau(
                    Genre::Entree(
                        Box::new(Genre::Simple(b's')),
                        Box::new(Genre::Tableau(Box::new(Genre::Simple(b's')))),
                    ),
                    entrees,
                ),
            ])
        };
        let location = fichier(
            &[(
                "main".into(),
                Contenu::Table(vec![valeur(
                    "location",
                    objet(vec![
                        entree("org.exemple.Cartes", &["EXACT", "1792285200"]),
                        entree("org.exemple.Meteo", &["CITY", "1792285200"]),
                        entree("org.exemple.Refuse", &["NONE", "0"]),
                        entree("org.exemple.Vide", &[]),
                    ]),
                )]),
            )],
            false,
        );
        std::fs::write(dossier.join("location"), location).unwrap();
        let a = linux::lire_magasin_flatpak(&dossier).unwrap();
        assert_eq!(
            resume(&a)[2..],
            [
                (Permission::Position, "org.exemple.Cartes".to_string()),
                (Permission::Position, "org.exemple.Meteo".to_string())
            ]
        );
        assert!(a[2].source.contains("précise") && a[3].source.contains("ville"));
        // Une table qui ne se lit pas : la commande prendra le relais.
        std::fs::write(dossier.join("location"), b"GVariant mais tronque").unwrap();
        assert_eq!(linux::lire_magasin_flatpak(&dossier), None);
        let abimee = fichier(
            &[(
                "main".into(),
                Contenu::Table(vec![valeur("location", Variante::Booleen(true))]),
            )],
            false,
        );
        std::fs::write(dossier.join("location"), abimee).unwrap();
        assert_eq!(linux::lire_magasin_flatpak(&dossier), None);
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Le magasin n'est cherché que dans un dossier absolu : HOME vide le ferait chercher dans le dossier courant.
    #[cfg(target_os = "linux")]
    #[test]
    fn dossier_du_magasin_absolu() {
        let d = |x: Option<&str>, maison: &str| {
            linux::dossier_magasin_flatpak(x.map(Into::into), std::path::Path::new(maison))
        };
        assert_eq!(d(None, ""), None);
        assert_eq!(d(Some(""), ""), None);
        assert_eq!(d(Some("donnees"), "/home/alice"), None);
        assert_eq!(
            d(None, "/home/alice"),
            Some(std::path::PathBuf::from("/home/alice/.local/share/flatpak/db"))
        );
        assert_eq!(
            d(Some("/srv/d"), ""),
            Some(std::path::PathBuf::from("/srv/d/flatpak/db"))
        );
    }

    /// `~/.local/share/flatpak/db/devices` écrit par le xdg-permission-store de xdg-desktop-portal 1.22 (applications inventées).
    #[cfg(target_os = "linux")]
    const MAGASIN_DEVICES: &str = "
    4756617269616e7400000000000000001800000058000000000000280200000000000000010000006a7f9a7cffffffff5800000004004800
    5c0000009c000000992b947cffffffff2e0100000400480034010000900100006d61696e00000028020000000000000001000000ee85e6f5
    ffffffff9c00000006007600a8000000fb00000019a92e65fffffffffb0000000a007600080100002e01000063616d657261000000000000
    7800000000000000010000000069020f00617b73767d6f72672e6578656d706c652e43616d657261007965730004136f72672e6578656d70
    6c652e4465757800796573000411193016002876617b7361737d296d6963726f70686f6e650000000000796f72672e6578656d706c652e4d
    6963726f006e6f0003121703002876617b7361737d296170707300000000002803000000000000000100000003000000826f5084ffffffff
    9001000012007600a8010000b301000033be37f5ffffffffb301000011007600c8010000d70100002f1790a2ffffffffd701000010007600
    e8010000f30100006f72672e6578656d706c652e43616d65726100000000000063616d65726100070061736f72672e6578656d706c652e4d
    6963726f000000006d6963726f70686f6e65000b0061736f72672e6578656d706c652e446575780063616d6572610007006173";

    /// Les surcharges de `flatpak override` ajoutent et retirent des permissions au metadata, comme Flatpak.
    #[cfg(target_os = "linux")]
    #[test]
    fn surcharges_de_flatpak_reunies() {
        let metadata = "[Application]\nname=org.exemple.Visio\n\n[Context]\nsockets=x11;pulseaudio;\n\
                        filesystems=home:ro;xdg-download;\n\n[Session Bus Policy]\norg.exemple.Carnet=talk\n";
        let global = "[Context]\ndevices=all;\n".to_string();
        let app = "[Context]\nsockets=!pulseaudio;\nfilesystems=!home;\n\n\
                   [Session Bus Policy]\norg.exemple.Carnet=none\n\n\
                   [System Bus Policy]\norg.freedesktop.GeoClue2=talk\n"
            .to_string();
        let t = linux::fusionner(metadata, &[global, app]);
        assert_eq!(
            t,
            "[Context]\nsockets=x11;\nfilesystems=xdg-download;\ndevices=all;\n\n\
             [Session Bus Policy]\norg.exemple.Carnet=none\n\n\
             [System Bus Policy]\norg.freedesktop.GeoClue2=talk\n"
        );
        let p: Vec<Permission> = lire_flatpak_statiques("org.exemple.Visio", &t)
            .iter()
            .map(|a| a.permission)
            .collect();
        assert_eq!(p, [Permission::Camera, Permission::Micro, Permission::Position]);
        // Sans surcharge, le metadata seul.
        let seul = linux::fusionner(metadata, &[]);
        assert!(
            seul.contains("sockets=x11;pulseaudio;") && seul.contains("org.exemple.Carnet=talk"),
            "{seul}"
        );
    }

    /// Sur cet ordinateur, les permissions lues donnent les mêmes accès que `flatpak info --show-permissions`.
    #[cfg(target_os = "linux")]
    #[test]
    fn permissions_comme_flatpak_info() {
        let Some(apps) = crate::machine::linux::paquets::applications_flatpak() else {
            return crate::essais::saute("flatpak absent");
        };
        for a in apps.iter().take(20) {
            let Some(r) = crate::commande::lancer_en_anglais(
                std::process::Command::new("flatpak").args(["info", "--show-permissions", a]),
                20,
            )
            .filter(|r| r.code == Some(0)) else {
                continue;
            };
            let Some(lu) = linux::permissions(a) else {
                continue;
            };
            assert_eq!(
                lire_flatpak_statiques(a, &lu),
                lire_flatpak_statiques(a, &r.sortie),
                "{a}"
            );
        }
    }

    #[test]
    fn permissions_fixes_de_flatpak() {
        let info = "[Context]\nshared=network;ipc;\nsockets=x11;wayland;pulseaudio;\ndevices=dri;all;\n\
                    filesystems=xdg-download;xdg-run/pipewire-0:ro;xdg-data/evolution;\n\n\
                    [Session Bus Policy]\norg.gnome.evolution.dataserver.AddressBook10=talk\n\
                    org.freedesktop.Notifications=talk\n\n\
                    [System Bus Policy]\norg.freedesktop.GeoClue2=talk\n";
        let a = lire_flatpak_statiques("org.exemple.Visio", info);
        let permissions: Vec<Permission> = a.iter().map(|x| x.permission).collect();
        assert_eq!(
            permissions,
            [
                Permission::Micro,
                Permission::Camera,
                Permission::Contacts,
                Permission::Position
            ]
        );
        assert!(a.iter().all(|x| x.application == "org.exemple.Visio"));
        // Tout le dossier personnel (très courant : filesystems=home) donne le carnet d'adresses ; tous les
        // appareils donnent aussi le micro (/dev/snd).
        let large = "[Context]\nfilesystems=home:ro;xdg-download;\ndevices=all;\n";
        let p: Vec<Permission> = lire_flatpak_statiques("org.exemple.Editeur", large)
            .iter()
            .map(|x| x.permission)
            .collect();
        assert!(p.contains(&Permission::Contacts) && p.contains(&Permission::Micro) && p.contains(&Permission::Camera));
        assert!(
            dossier_personnel("host") && dossier_personnel("xdg-data:create") && dossier_personnel("~/.local/share/")
        );
        assert!(!dossier_personnel("xdg-download") && !dossier_personnel("xdg-data/evolution"));
        // Un réglage qui retire (« !pulseaudio ») ou des appareils limités ne donnent rien.
        let sobre = "[Context]\nsockets=wayland;!pulseaudio;\ndevices=dri;\n\n[Session Bus Policy]\n\
                     org.gnome.evolution.dataserver.AddressBook10=none\n";
        assert_eq!(lire_flatpak_statiques("org.exemple.Sobre", sobre), Vec::<Acces>::new());

        // Le même accès vu par le portail et par la permission fixe : une ligne, deux sources.
        let mut b = Bilan::default();
        b.ajouter(lire_flatpak_portails("devices\tcamera\torg.exemple.Visio\tyes\t\n"));
        b.ajouter(a);
        let camera: Vec<&Acces> = b.acces.iter().filter(|x| x.permission == Permission::Camera).collect();
        assert_eq!(camera.len(), 1);
        assert_eq!(camera[0].source, "Flatpak : portail, Flatpak : tous les appareils");
    }

    #[test]
    fn interfaces_de_snap() {
        let sortie = "Interface         Plug                      Slot               Notes\n\
                      audio-playback    visio:audio-playback      :audio-playback    -\n\
                      audio-record      visio:audio-record        :audio-record      -\n\
                      camera            visio:camera              :camera            manual\n\
                      camera            autre:camera              -                  -\n\
                      location-observe  cartes:location-observe   :location-observe  manual\n\
                      contacts-service  courrier:contacts-service :contacts-service  -\n\
                      network           visio:network             :network           -\n";
        let a = lire_snap(sortie);
        let resume: Vec<(Permission, &str)> = a.iter().map(|x| (x.permission, x.application.as_str())).collect();
        assert_eq!(
            resume,
            [
                (Permission::Micro, "visio"),
                (Permission::Camera, "visio"),
                (Permission::Position, "cartes"),
                (Permission::Contacts, "courrier"),
            ]
        );
        assert_eq!(a[1].source, "Snap (camera)");
        assert_eq!(lire_snap(""), Vec::<Acces>::new());
    }

    /// La base TCC lue par le lecteur SQLite de Vanguard, dans les deux formats (bases inventées) : seulement la
    /// caméra, le micro et les contacts autorisés ; une tabulation dans un nom ne décale plus les colonnes.
    #[test]
    fn base_tcc_de_macos() {
        let base = include_bytes!("../../assets/essais/tcc-acces.sqlite");
        let a = lire_tcc(base).unwrap();
        let resume: Vec<(Permission, &str)> = a.iter().map(|x| (x.permission, x.application.as_str())).collect();
        assert_eq!(
            resume,
            [
                (Permission::Camera, "com.example.Visio"),
                (Permission::Contacts, "com.example.Courrier"),
                (Permission::Micro, "/Users/alice/Downloads/outil"),
                (Permission::Camera, "com.example.Avec\ttabulation"),
            ]
        );
        assert!(
            a[0].quand
                .as_deref()
                .is_some_and(|q| q.starts_with("réglée le 2026-10-1"))
        );
        assert_eq!(a[1].quand, None);
        assert_eq!(a[1].source, "autorisée en partie");
        assert_eq!(a[3].source, "autorisée");
        assert!(super::super::camera::lieu_suspect(&a[2].application));
        // Avant Big Sur : « allowed » 1 vaut une autorisation pleine, sans date.
        let ancien = lire_tcc(include_bytes!("../../assets/essais/tcc-acces-ancien.sqlite")).unwrap();
        let resume: Vec<(Permission, &str, &str)> = ancien
            .iter()
            .map(|x| (x.permission, x.application.as_str(), x.source.as_str()))
            .collect();
        assert_eq!(resume, [(Permission::Camera, "com.example.Ancien", "autorisée")]);
        assert_eq!(ancien[0].quand, None);
        // Les bases des autorisations d'épier : rien de la caméra, du micro ni des contacts n'y est permis.
        assert_eq!(
            lire_tcc(include_bytes!("../../assets/essais/tcc-bigsur.sqlite")),
            Some(Vec::new())
        );
        assert_eq!(
            lire_tcc(include_bytes!("../../assets/essais/tcc-ancien.sqlite")),
            Some(Vec::new())
        );
        // Une base coupée ne se lit pas : jamais une liste vide à sa place.
        assert_eq!(lire_tcc(&base[..1000]), None);
    }
}

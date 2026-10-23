//! Logiciels : les meilleurs de chaque usage, libres pour la plupart, pour préparer un ordinateur neuf (ou celui
//! d'un ami) en quelques choix. Chaque logiciel est montré installé ou non, puis installé seulement après accord,
//! depuis la source officielle du système, qui vérifie chaque téléchargement (empreinte ou signature) : paquets de
//! la distribution ou Flathub sous Linux, winget sous Windows, Homebrew sous macOS. Rien n'est désinstallé ici.

mod catalogue;

use catalogue::{CATALOGUE, Categorie, FLATHUB_PAS_LIBRE, Logiciel};

use crate::selection::{Case, Ligne, choisir, cocher};
use crate::ui::*;

/// Un logiciel tel qu'il se présente sur cette machine.
struct Offre {
    logiciel: &'static Logiciel,
    installe: bool,
    /// Commandes qui l'installent, dans l'ordre.
    commandes: Vec<String>,
    /// D'où il vient : « Flathub, org.mozilla.firefox », « winget, Mozilla.Firefox »…
    source: String,
    /// Passe par Flatpak (Linux) : Flatpak doit être là.
    flatpak: bool,
}

/// Ce qu'il faut installer avant les logiciels, s'il manque : Flatpak (Linux), Homebrew (macOS), winget (Windows,
/// qui vient du Microsoft Store : on ouvre sa page).
struct Prealable {
    nom: &'static str,
    commandes: Vec<String>,
    lien: Option<&'static str>,
    /// Seulement pour les logiciels qui passent par Flatpak.
    pour_flatpak: bool,
}

struct Etat {
    offres: Vec<Offre>,
    prealable: Option<Prealable>,
}

/// Ce qui suit un choix du menu.
#[derive(PartialEq, Eq)]
enum Suite {
    /// Revenu sans rien faire (Échap, rien coché, refus) : le menu revient tout de suite.
    Rien,
    /// Un message à lire avant de revenir au menu.
    Message,
    /// Une installation a été lancée : l'état est relu.
    Installation,
}

/// `nom` commence par `motif` (sans tenir compte des majuscules), suivi de rien ou d'un séparateur : « Git » et
/// « Git 2.44 » sont Git, « GitHub Desktop » ne l'est pas.
#[cfg(any(windows, target_os = "macos", test))]
fn correspond(nom: &str, motif: &str) -> bool {
    let (nom, motif) = (nom.to_lowercase(), motif.to_lowercase());
    nom.strip_prefix(&motif)
        .is_some_and(|reste| !reste.starts_with(char::is_alphanumeric))
}

#[cfg(target_os = "linux")]
fn rang(gestion: crate::machine::linux::Paquets) -> usize {
    use crate::machine::linux::Paquets;
    match gestion {
        Paquets::Pacman => 0,
        Paquets::Apt => 1,
        Paquets::Dnf => 2,
        Paquets::Zypper => 3,
    }
}

/// Programme présent dans le PATH ou parmi les Snap (/snap/bin n'est pas toujours dans le PATH).
#[cfg(target_os = "linux")]
fn dans_le_path(commande: &str) -> bool {
    use crate::machine::linux::natif::present;
    present(commande) || present(&format!("/snap/bin/{commande}"))
}

/// Linux : le paquet de la distribution quand elle a le logiciel, sinon Flathub. Un logiciel installé autrement
/// (AUR, paquet de l'éditeur, Snap) compte aussi : son programme est là.
#[cfg(target_os = "linux")]
fn lire() -> Result<Etat, String> {
    use crate::machine::linux::Paquets;
    use crate::machine::linux::natif::present;
    use crate::machine::linux::paquets::{applications_flatpak, installer_flatpak, installes_parmi, noms_installes};
    let gestion = Paquets::detecter();
    let flatpak = present("flatpak");
    if gestion.is_none() && !flatpak {
        return Err(tr!(
            "ni gestionnaire de paquets reconnu, ni Flatpak",
            "no known package manager, and no Flatpak"
        )
        .into());
    }
    // Lues dans les dossiers de Flatpak (sa commande en secours) ; illisibles, elles ne cachent rien : chaque
    // logiciel se cherche encore par son programme et par son paquet.
    let flatpaks = if flatpak {
        applications_flatpak().unwrap_or_default()
    } else {
        Vec::new()
    };
    // Debian n'a que firefox-esr ; Ubuntu et ses dérivées ont firefox.
    let ubuntu = gestion == Some(Paquets::Apt) && crate::machine::linux::famille_ubuntu();
    // La base des paquets lue une fois, au premier logiciel qui n'est pas dans le PATH, et non à chacun.
    let noms = std::cell::OnceCell::new();
    let mut offres = Vec::new();
    for l in CATALOGUE {
        let paquets: &[&str] = match gestion {
            Some(g) if ubuntu && l.paquets[rang(g)] == ["firefox-esr"] => &["firefox"],
            Some(g) => l.paquets[rang(g)],
            None => &[],
        };
        let vu =
            l.commandes.iter().any(|c| dans_le_path(c)) || l.flatpak.is_some_and(|id| flatpaks.iter().any(|f| f == id));
        match (gestion, l.flatpak) {
            (Some(g), _) if !paquets.is_empty() => offres.push(Offre {
                logiciel: l,
                installe: vu || installes_parmi(noms.get_or_init(|| noms_installes(g)).as_ref(), g, paquets),
                commandes: vec![g.installer(&paquets.join(" "))],
                source: trf!(
                    "paquet de la distribution, {}",
                    "distribution package, {}",
                    paquets.join(" ")
                ),
                flatpak: false,
            }),
            (_, Some(id)) => offres.push(Offre {
                logiciel: l,
                installe: vu,
                commandes: installer_flatpak(id),
                source: format!("Flathub, {id}"),
                flatpak: true,
            }),
            _ => {}
        }
    }
    // Sans Flatpak, on l'installe d'abord depuis la distribution (il y est partout).
    let prealable = gestion.filter(|_| !flatpak).map(|g| Prealable {
        nom: "Flatpak",
        commandes: vec![g.installer("flatpak")],
        lien: None,
        pour_flatpak: true,
    });
    Ok(Etat { offres, prealable })
}

#[cfg(windows)]
#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct Lu {
    winget: bool,
    noms: Vec<String>,
}

/// Windows : winget, et les noms du panneau « Applications installées » plus ceux des applications du Store, lus
/// dans le registre ; PowerShell seulement si la clé des programmes de la machine ne s'ouvre pas.
#[cfg(windows)]
fn lire() -> Result<Etat, String> {
    use crate::machine::windows::installes;
    let lu = match installes::noms() {
        Some(mut noms) => {
            noms.extend(installes::paquets_store());
            Lu {
                winget: installes::winget_present(),
                noms,
            }
        }
        None => lire_par_powershell()?,
    };
    let offres = CATALOGUE
        .iter()
        .filter_map(|l| {
            let (id, motif) = l.winget?;
            Some(Offre {
                logiciel: l,
                installe: lu.noms.iter().any(|n| correspond(n, motif)),
                commandes: vec![crate::machine::windows::winget_installer(id)],
                source: format!("winget, {id}"),
                flatpak: false,
            })
        })
        .collect();
    // winget vient avec « Programme d'installation d'application », du Microsoft Store : on ne peut qu'ouvrir sa page.
    let prealable = (!lu.winget).then_some(Prealable {
        nom: "winget",
        commandes: Vec::new(),
        lien: Some("ms-windows-store://pdp/?ProductId=9NBLGGH4NNS1"),
        pour_flatpak: false,
    });
    Ok(Etat { offres, prealable })
}

#[cfg(windows)]
fn lire_par_powershell() -> Result<Lu, String> {
    let json = crate::machine::windows::ps(
        r"$noms = @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.DisplayName } | Where-Object { $_ })
          $appx = @(Get-AppxPackage -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.Name })
          [pscustomobject]@{ winget = [bool](Get-Command winget -ErrorAction SilentlyContinue); noms = @($noms + $appx) } | ConvertTo-Json -Compress",
    )
    .ok_or_else(|| tr!("PowerShell ne répond pas", "PowerShell is not responding").to_string())?;
    serde_json::from_str(&json).map_err(|e| e.to_string())
}

/// Noms des applications de /Applications et ~/Applications, sans « .app ».
#[cfg(target_os = "macos")]
fn applications_mac() -> Vec<String> {
    let maison = crate::socle::maison();
    [std::path::PathBuf::from("/Applications"), maison.join("Applications")]
        .iter()
        .flat_map(|d| std::fs::read_dir(d).into_iter().flatten().flatten())
        .filter_map(|e| e.file_name().to_str()?.strip_suffix(".app").map(str::to_string))
        .collect()
}

/// macOS : Homebrew ; une application déjà dans /Applications (installée par Homebrew ou à la main) compte.
#[cfg(target_os = "macos")]
#[allow(clippy::unnecessary_wraps)] // même signature que sous Linux et Windows, où la lecture peut échouer
fn lire() -> Result<Etat, String> {
    use crate::machine::macos::{INSTALLER_HOMEBREW, brew, homebrew};
    let apps = applications_mac();
    let offres = CATALOGUE
        .iter()
        .filter_map(|l| {
            let (cask, app) = l.mac?;
            Some(Offre {
                logiciel: l,
                installe: apps.iter().any(|a| correspond(a, app)),
                commandes: vec![format!("{} install --cask {cask}", brew())],
                source: format!("Homebrew, {cask}"),
                flatpak: false,
            })
        })
        .collect();
    let prealable = homebrew().is_none().then(|| Prealable {
        nom: "Homebrew",
        commandes: vec![INSTALLER_HOMEBREW.into()],
        lien: None,
        pour_flatpak: false,
    });
    Ok(Etat { offres, prealable })
}

fn role(l: &Logiciel) -> &'static str {
    if crate::langue::anglais() { l.role.1 } else { l.role.0 }
}

/// La licence de ce qui s'installe par cette source : la version d'un éditeur sur Flathub peut ne pas être libre.
fn licence_installee(o: &Offre) -> Option<&'static str> {
    let commerciale = o.flatpak && o.logiciel.flatpak.is_some_and(|id| FLATHUB_PAS_LIBRE.contains(&id));
    if commerciale { None } else { o.logiciel.licence }
}

fn licence(o: &Offre) -> String {
    match licence_installee(o) {
        Some(nom) => trf!("Logiciel libre ({nom}).", "Free and open source ({nom})."),
        None => tr!("Gratuit, mais pas libre.", "Free of charge, but not open source.").into(),
    }
}

/// Ce qui s'affiche sous la liste pour la ligne en cours : à quoi il sert, sa licence, d'où il vient.
fn detail(o: &Offre) -> String {
    trf!(
        "{} {} Source : {}.",
        "{} {} Source: {}.",
        role(o.logiciel),
        licence(o),
        o.source
    )
}

fn precision(o: &Offre) -> String {
    if o.installe {
        tr!("installé", "installed").into()
    } else {
        licence_installee(o)
            .unwrap_or(tr!("gratuit, pas libre", "free, not open source"))
            .into()
    }
}

fn lire_en_parlant() -> Option<Etat> {
    trp!(
        "  {GRIS}Lecture des logiciels installés…{RESET}",
        "  {GRIS}Reading installed software…{RESET}"
    );
    match lire() {
        Ok(e) if !e.offres.is_empty() => Some(e),
        Ok(_) => {
            trp!(
                "  ✖ Aucun logiciel à proposer sur ce système.",
                "  ✖ No software to offer on this system."
            );
            None
        }
        Err(raison) => {
            trp!(
                "  ✖ Impossible de lire les logiciels installés ({raison}).",
                "  ✖ Could not read installed software ({raison})."
            );
            None
        }
    }
}

/// Montre ce qui va être installé et d'où, demande l'accord, installe (le préalable d'abord), puis relit l'état
/// pour dire ce qui est vraiment là.
fn installer(etat: &Etat, choisis: &[&Offre]) -> Suite {
    let prealable = etat
        .prealable
        .as_ref()
        .filter(|p| !p.pour_flatpak || choisis.iter().any(|o| o.flatpak));
    if let Some(lien) = prealable.and_then(|p| p.lien) {
        let manque = tr!(
            "winget manque : il vient avec « Programme d'installation d'application », dans le Microsoft Store. J'ouvre sa page ; reviens ici une fois installé.",
            "winget is missing: it comes with “App Installer”, in the Microsoft Store. I am opening its page; come back here once it is installed."
        );
        println!();
        afficher_aligne("  ✖ ", manque, 4, "");
        crate::machine::ouvrir(lien);
        return Suite::Message;
    }
    trp!("\n  {GRAS}À installer{RESET}", "\n  {GRAS}To install{RESET}");
    if let Some(p) = prealable {
        trp!(
            "    {VERT}+{RESET} {}  {GRIS}(nécessaire d'abord){RESET}",
            "    {VERT}+{RESET} {}  {GRIS}(needed first){RESET}",
            p.nom
        );
        for c in &p.commandes {
            println!("        {GRIS}{}{RESET}", crate::ui::commande_affichable(c));
        }
    }
    for o in choisis {
        println!("    {VERT}+{RESET} {}  {GRIS}{}{RESET}", o.logiciel.nom, o.source);
        for c in &o.commandes {
            println!("        {GRIS}{}{RESET}", crate::ui::commande_affichable(c));
        }
    }
    let verifie = tr!(
        "La source vérifie chaque téléchargement (empreinte ou signature) avant de l'installer.",
        "The source checks each download (hash or signature) before installing it."
    );
    afficher_aligne("  ", verifie, 2, GRIS);
    if !demander(tr!("\n  Installer ? [o/N] : ", "\n  Install? [y/N]: ")).oui() {
        trp!("  Annulé.", "  Cancelled.");
        return Suite::Rien;
    }
    let mut groupes: Vec<Vec<String>> = prealable.map(|p| p.commandes.clone()).into_iter().collect();
    let decalage = groupes.len();
    groupes.extend(choisis.iter().map(|o| o.commandes.clone()));
    let resultats = crate::machine::appliquer_chacune(&groupes);
    // L'état relu après coup : c'est lui qui dit si le logiciel est là.
    let apres = lire().ok();
    println!();
    for (i, o) in choisis.iter().enumerate() {
        let present = apres
            .as_ref()
            .is_some_and(|e| e.offres.iter().any(|a| a.logiciel.nom == o.logiciel.nom && a.installe));
        let reussi = resultats.get(i + decalage).copied().unwrap_or(false);
        if present {
            println!("  {VERT}✔{RESET} {}", o.logiciel.nom);
        } else if reussi {
            let pas_encore = trf!(
                "{} : l'installation dit avoir réussi, mais je ne le vois pas encore (relance pour vérifier).",
                "{}: the installer reports success, but I cannot see it yet (run again to check).",
                o.logiciel.nom
            );
            afficher_aligne("  ⚠ ", &pas_encore, 4, "");
        } else {
            trp!(
                "  ✖ {} : pas installé, voir le message ci-dessus.",
                "  ✖ {}: not installed, see the message above.",
                o.logiciel.nom
            );
        }
    }
    Suite::Installation
}

/// Le pack de départ : ce qui en manque, en une fois.
fn pack(etat: &Etat) -> Suite {
    titre(tr!("Pack de départ", "Starter pack"));
    let a_faire: Vec<&Offre> = etat
        .offres
        .iter()
        .filter(|o| o.logiciel.recommande && !o.installe)
        .collect();
    if a_faire.is_empty() {
        trp!(
            "  {VERT}✔{RESET} Le pack de départ est déjà installé.",
            "  {VERT}✔{RESET} The starter pack is already installed."
        );
        return Suite::Message;
    }
    let contenu = tr!(
        "Un navigateur, un gestionnaire de mots de passe, la vidéo, la bureautique et les archives : de quoi bien démarrer.",
        "A browser, a password manager, video, office and archives: everything to get started."
    );
    afficher_aligne("  ", contenu, 2, "");
    installer(etat, &a_faire)
}

/// Une catégorie : liste à cocher ; ce qui est coché s'installe.
fn categorie(etat: &Etat, c: Categorie) -> Suite {
    let offres: Vec<&Offre> = etat.offres.iter().filter(|o| o.logiciel.categorie == c).collect();
    let cases: Vec<Case> = offres
        .iter()
        .map(|o| Case {
            texte: o.logiciel.nom.to_string(),
            precision: precision(o),
            detail: detail(o),
            cochee: false,
            recommandee: o.logiciel.recommande,
            fixe: o.installe,
        })
        .collect();
    let entete = vec![
        String::new(),
        ligne_titre(c.titre()),
        trf!(
            "  {GRIS}Coche ce que tu veux installer ; [✔] = déjà installé.{RESET}",
            "  {GRIS}Check what you want to install; [✔] = already installed.{RESET}"
        ),
        String::new(),
    ];
    let Some(voulu) = cocher(&entete, &cases) else {
        return Suite::Rien;
    };
    let choisis: Vec<&Offre> = offres
        .iter()
        .zip(&voulu)
        .filter(|(o, v)| **v && !o.installe)
        .map(|(o, _)| *o)
        .collect();
    if choisis.is_empty() {
        return Suite::Rien;
    }
    installer(etat, &choisis)
}

/// « installés / total » d'une liste, pour la précision du menu.
fn compte<'a>(offres: impl Iterator<Item = &'a Offre>) -> String {
    let (faits, total) = offres.fold((0, 0), |(f, t), o| (f + usize::from(o.installe), t + 1));
    if faits == total {
        tr!("✔ tout est installé", "✔ all installed").into()
    } else {
        trf!("{faits} sur {total} installés", "{faits} of {total} installed")
    }
}

/// « vanguard logiciels » : le pack de départ, puis une liste à cocher par catégorie.
pub fn menu() {
    let Some(mut etat) = lire_en_parlant() else {
        return;
    };
    let mut dernier = String::from("1");
    loop {
        let categories: Vec<Categorie> = Categorie::TOUTES
            .into_iter()
            .filter(|c| etat.offres.iter().any(|o| o.logiciel.categorie == *c))
            .collect();
        let mut lignes = vec![
            Ligne::Texte(String::new()),
            Ligne::Texte(ligne_titre(tr!("Logiciels", "Software"))),
            Ligne::Texte(trf!(
                "  {GRIS}Libres pour la plupart, installés depuis la source officielle du système.{RESET}",
                "  {GRIS}Mostly open source, installed from the system's official source.{RESET}"
            )),
            Ligne::Texte(String::new()),
            Ligne::choix(
                "1",
                tr!("Pack de départ", "Starter pack"),
                &compte(etat.offres.iter().filter(|o| o.logiciel.recommande)),
            ),
        ];
        for (i, c) in categories.iter().enumerate() {
            lignes.push(Ligne::choix(
                &(i + 2).to_string(),
                c.titre(),
                &compte(etat.offres.iter().filter(|o| o.logiciel.categorie == *c)),
            ));
        }
        lignes.push(Ligne::Texte(String::new()));
        lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
        lignes.push(Ligne::Texte(String::new()));
        let Some(choix) = choisir(
            &lignes,
            tr!("Choix (Entrée pour revenir) : ", "Choice (Enter to go back): "),
            &dernier,
            tr!("revenir", "back"),
        ) else {
            return;
        };
        let choix = choix.trim().to_string();
        let suite = if choix == "1" {
            pack(&etat)
        } else {
            match choix
                .parse::<usize>()
                .ok()
                .and_then(|n| n.checked_sub(2))
                .and_then(|i| categories.get(i))
            {
                Some(&c) => categorie(&etat, c),
                None => return,
            }
        };
        dernier = choix;
        if suite == Suite::Rien {
            continue;
        }
        if suite == Suite::Installation
            && let Some(e) = lire().ok().filter(|e| !e.offres.is_empty())
        {
            etat = e;
        }
        crate::selection::attendre_retour(&trf!(
            "\n{GRIS}Entrée pour revenir…{RESET}",
            "\n{GRIS}Enter to go back…{RESET}"
        ));
    }
}

/// « vanguard logiciels --liste » : chaque logiciel proposé sur ce système, par catégorie, avec son état et sa
/// source. Rien n'est installé.
pub fn liste() {
    let Some(etat) = lire_en_parlant() else {
        return;
    };
    titre(tr!("Logiciels", "Software"));
    for c in Categorie::TOUTES {
        let offres: Vec<&Offre> = etat.offres.iter().filter(|o| o.logiciel.categorie == c).collect();
        if offres.is_empty() {
            continue;
        }
        println!("\n  {GRAS}{}{RESET}", c.titre());
        for o in offres {
            let (marque, mot) = if o.installe {
                (format!("{VERT}✔{RESET}"), tr!("installé", "installed"))
            } else {
                ("·".to_string(), tr!("à installer", "not installed"))
            };
            println!(
                "    {marque} {}{}{GRIS}{}{RESET}",
                ajuster(o.logiciel.nom, 18),
                ajuster(mot, 14),
                o.source
            );
        }
    }
    let installes = etat.offres.iter().filter(|o| o.installe).count();
    trp!(
        "\n  {} logiciels proposés ici : {installes} installés, {} à installer.",
        "\n  {} programs offered here: {installes} installed, {} to install.",
        etat.offres.len(),
        etat.offres.len() - installes
    );
}

/// « vanguard logiciels --recommandes » : le pack de départ, directement.
pub fn recommandes() {
    if let Some(etat) = lire_en_parlant() {
        pack(&etat);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valide(texte: &str, autres: &str) -> bool {
        !texte.is_empty() && texte.chars().all(|c| c.is_ascii_alphanumeric() || autres.contains(c))
    }

    #[test]
    fn catalogue_complet_et_sur() {
        let mut noms: Vec<&str> = CATALOGUE.iter().map(|l| l.nom).collect();
        let n = noms.len();
        noms.sort_unstable();
        noms.dedup();
        assert_eq!(noms.len(), n, "deux logiciels ont le même nom");
        for l in CATALOGUE {
            assert!(!l.role.0.is_empty() && !l.role.1.is_empty(), "{}", l.nom);
            let linux = l.paquets.iter().any(|p| !p.is_empty()) || l.flatpak.is_some();
            assert!(
                linux || l.winget.is_some() || l.mac.is_some(),
                "{} ne s'installe nulle part",
                l.nom
            );
            // Tout finit dans une commande : seulement des caractères sans effet dans un shell ou PowerShell.
            for p in l.paquets.iter().flat_map(|p| p.iter()) {
                assert!(valide(p, "+._-"), "{} : paquet {p}", l.nom);
            }
            if let Some(id) = l.flatpak {
                assert!(
                    valide(id, "._-") && id.split('.').count() >= 3,
                    "{} : Flathub {id}",
                    l.nom
                );
            }
            if let Some((id, motif)) = l.winget {
                assert!(
                    valide(id, "+._-") && id.contains('.') && !motif.is_empty(),
                    "{} : winget {id}",
                    l.nom
                );
            }
            if let Some((cask, app)) = l.mac {
                assert!(valide(cask, "@._-") && !app.is_empty(), "{} : cask {cask}", l.nom);
            }
            for c in l.commandes {
                assert!(valide(c, "._-"), "{} : programme {c}", l.nom);
            }
            assert!(l.licence.is_none_or(|s| !s.is_empty() && s.len() <= 33));
            assert!(largeur_affichee(l.nom) <= 28, "{} : nom trop long pour la liste", l.nom);
        }
    }

    /// Le logiciel est-il proposé sur ce système ?
    fn propose(systeme: &str, l: &Logiciel) -> bool {
        match systeme {
            "Linux" => l.paquets.iter().any(|p| !p.is_empty()) || l.flatpak.is_some(),
            "Windows" => l.winget.is_some(),
            _ => l.mac.is_some(),
        }
    }

    #[test]
    fn chaque_systeme_a_son_pack_et_ses_categories() {
        for systeme in ["Linux", "Windows", "macOS"] {
            let pack = CATALOGUE.iter().filter(|l| l.recommande && propose(systeme, l)).count();
            assert_eq!(pack, 5, "{systeme} : pack de départ de {pack} logiciels");
            for c in Categorie::TOUTES {
                let n = CATALOGUE
                    .iter()
                    .filter(|l| l.categorie == c && propose(systeme, l))
                    .count();
                // Une catégorie doit tenir dans la fenêtre avec sa liste à cocher.
                assert!(n <= 9, "{systeme} : {n} logiciels dans {c:?}");
            }
        }
    }

    #[test]
    fn noms_reconnus_sans_confusion() {
        assert!(correspond("Mozilla Firefox (x64 fr)", "Mozilla Firefox"));
        assert!(correspond("Git", "Git") && correspond("Git version 2.44", "Git"));
        assert!(!correspond("GitHub Desktop", "Git"));
        assert!(correspond("blender", "Blender") && correspond("Audacity 4", "Audacity"));
        assert!(!correspond(
            "Microsoft.WindowsTerminalPreview",
            "Microsoft.WindowsTerminal"
        ));
        assert!(!correspond("VLC", "VLC media player"));
    }

    /// Les messages de Logiciels tiennent dans `LARGEUR` colonnes, dans les deux langues.
    #[test]
    fn messages_dans_la_largeur() {
        let larges = crate::ui::textes_trop_larges(include_str!("mod.rs"));
        assert_eq!(larges, Vec::<String>::new());
    }

    #[test]
    fn bitwarden_de_flathub_n_est_pas_dit_libre() {
        let l = CATALOGUE.iter().find(|l| l.nom == "Bitwarden").unwrap();
        let offre = |flatpak| Offre {
            logiciel: l,
            installe: false,
            commandes: Vec::new(),
            source: String::new(),
            flatpak,
        };
        assert_eq!(licence_installee(&offre(true)), None);
        assert_eq!(licence_installee(&offre(false)), Some("GPL-3.0"));
        for id in FLATHUB_PAS_LIBRE {
            assert!(
                CATALOGUE.iter().any(|l| l.flatpak == Some(*id)),
                "{id} : absent du catalogue"
            );
        }
    }

    #[test]
    fn detail_tient_sous_la_liste() {
        for l in CATALOGUE {
            let o = Offre {
                logiciel: l,
                installe: false,
                commandes: Vec::new(),
                source: "Flathub, org.exemple.UnNomAssezLongPourLeTest".into(),
                flatpak: true,
            };
            // Trois lignes sous la liste à cocher (selection::cocher).
            assert!(
                envelopper(&detail(&o), LARGEUR - 4).len() <= 3,
                "{} : détail trop long",
                l.nom
            );
            assert!(largeur_affichee(&precision(&o)) <= 33, "{}", l.nom);
        }
    }
}

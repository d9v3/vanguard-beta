//! Mises à jour Linux : paquets, Flatpak, Snap, AUR, firmware, failles connues, noyau et pilotes DKMS.

use super::*;

/// Paquets à mettre à jour, un par ligne commençant par son nom ; `None` si on ne peut pas savoir.
pub(super) fn liste_mises_a_jour(gestion: Paquets) -> Option<Vec<String>> {
    // Ces outils interrogent les dépôts : hors ligne ou serveur lent, ils ne doivent pas figer l'audit.
    let lancer =
        |cmd: &str, args: &[&str]| crate::commande::lancer(Command::new(cmd).args(args).env("LC_ALL", "C"), 120);
    let lignes = |t: &str| t.lines().map(str::to_string).collect::<Vec<_>>();
    match gestion {
        // checkupdates : 0 = mises à jour listées, 2 = rien à faire, autre = erreur (hors ligne…).
        Paquets::Pacman => {
            let r = lancer("checkupdates", &[])?;
            match r.code {
                Some(0) => Some(lignes(&r.sortie)),
                Some(2) => Some(vec![]),
                _ => None,
            }
        }
        // Sorties en anglais (LC_ALL=C) : sinon les mots cherchés changent selon la langue du système.
        // Lit le cache d'apt sans le rafraîchir (il faudrait sudo) : il date du dernier « apt update ».
        // Sans cache, « rien à mettre à jour » ne voudrait rien dire.
        Paquets::Apt => {
            age_cache_apt()?;
            let r = lancer("apt", &["list", "--upgradable"])?;
            (r.code == Some(0)).then(|| {
                lignes(&r.sortie)
                    .into_iter()
                    .filter(|l| l.contains("[upgradable"))
                    .collect()
            })
        }
        // dnf check-update : 100 = mises à jour disponibles, 0 = rien, autre = erreur.
        Paquets::Dnf => {
            let r = lancer("dnf", &["-q", "check-update"])?;
            match r.code {
                Some(100) => Some(
                    lignes(&r.sortie)
                        .into_iter()
                        .filter(|l| !l.trim().is_empty() && !l.starts_with(' '))
                        .collect(),
                ),
                Some(0) => Some(vec![]),
                _ => None,
            }
        }
        Paquets::Zypper => {
            let r = lancer("zypper", &["-q", "list-updates"])?;
            (r.code == Some(0)).then(|| lignes(&r.sortie).into_iter().filter(|l| l.starts_with("v ")).collect())
        }
    }
}

/// Logiciels installés hors du gestionnaire de paquets principal : Flatpak, Snap, AUR et firmware.
pub(super) fn autres_mises_a_jour() -> Vec<Constat> {
    let present = |c: &str| {
        ["/usr/bin", "/bin", "/usr/local/bin"]
            .iter()
            .any(|d| Path::new(d).join(c).exists())
    };
    let lignes = |t: &str| t.lines().filter(|l| !l.trim().is_empty()).count();
    let mut constats = Vec::new();
    std::thread::scope(|portee| {
        let flatpak = present("flatpak").then(|| {
            portee.spawn(|| {
                sortie_delai(
                    "flatpak",
                    &["remote-ls", "--updates", "--columns=application"],
                    40,
                    &[0],
                )
            })
        });
        // snapd par son API (/run/snapd.socket) ; la CLI si la prise ne répond pas. Un nombre de snaps à mettre à
        // jour ; `None` : impossible à savoir.
        let snap = present("snap").then(|| {
            portee.spawn(|| {
                match super::http_unix::snaps_a_mettre_a_jour(Path::new(super::http_unix::SNAPD)) {
                    Ok(l) => return Some(l.len()),
                    // snapd a répondu par une erreur (magasin injoignable…) : la CLI dirait la même chose.
                    Err(e) if e.to_string().contains("snapd") || e.to_string().starts_with("HTTP ") => return None,
                    Err(_) => {}
                }
                // « All snaps up to date » part sur la sortie d'erreur : sortie vide = à jour. Une ligne d'en-tête
                // sinon.
                sortie_delai("snap", &["refresh", "--list"], 30, &[0])
                    .map(|l| l.lines().filter(|x| !x.trim().is_empty()).count().saturating_sub(1))
            })
        });
        // L'assistant AUR ne sert plus qu'à nommer la commande proposée : la liste vient de l'AUR lui-même.
        let aur = ["yay", "paru"]
            .into_iter()
            .find(|c| present(c))
            .map(|c| (c, portee.spawn(aur_a_mettre_a_jour)));
        // fwupd par D-Bus d'abord ; fwupdmgr en secours si le bus ne répond pas.
        let firmware = present("fwupdmgr").then(|| {
            portee.spawn(|| {
                match firmwares_par_dbus() {
                    Ok(v) => return Some(v),
                    // fwupd a répondu par une erreur (métadonnées absentes…) : fwupdmgr la tairait.
                    Err(e) if e.to_string().starts_with("org.freedesktop.fwupd.") => return None,
                    Err(_) => {}
                }
                sortie_delai(
                    "fwupdmgr",
                    &["get-updates", "--json", "--no-unreported-check"],
                    40,
                    &[0, 2],
                )
                .and_then(|j| serde_json::from_str::<serde_json::Value>(&j).ok())
                .map(|v| firmwares_proposes(&v))
            })
        });

        if let Some(t) = flatpak {
            constats.push(match t.join().ok().flatten() {
                None => impossible("Flatpak", tr!("hors ligne ?", "offline?")),
                Some(l) if lignes(&l) == 0 => ok(
                    "Flatpak",
                    tr!("Applications Flatpak à jour.", "Flatpak apps up to date."),
                ),
                Some(l) => alerte(
                    "Flatpak",
                    Niveau::Moyen,
                    trf!(
                        "{} application(s) Flatpak à mettre à jour.",
                        "{} Flatpak app(s) to update.",
                        lignes(&l)
                    ),
                )
                .corriger(
                    tr!("Mettre à jour les applications Flatpak", "Update the Flatpak apps"),
                    &["flatpak update -y"],
                ),
            });
        }
        if let Some(t) = snap {
            constats.push(match t.join().ok().flatten() {
                None => impossible("Snap", tr!("snapd injoignable", "snapd unreachable")),
                Some(0) => ok("Snap", tr!("Paquets Snap à jour.", "Snap packages up to date.")),
                Some(n) => alerte(
                    "Snap",
                    Niveau::Moyen,
                    trf!("{n} paquet(s) Snap à mettre à jour.", "{n} Snap package(s) to update."),
                )
                .corriger(
                    tr!("Mettre à jour les paquets Snap", "Update the Snap packages"),
                    &["sudo snap refresh"],
                ),
            });
        }
        if let Some((outil, t)) = aur {
            constats.push(match t.join().ok().flatten() {
                None => impossible("AUR", tr!("hors ligne ?", "offline?")),
                Some(0) => ok("AUR", tr!("Paquets AUR à jour.", "AUR packages up to date.")),
                Some(n) => alerte(
                    "AUR",
                    Niveau::Moyen,
                    trf!("{} paquet(s) AUR à mettre à jour.", "{} AUR package(s) to update.", n),
                )
                .manuel(
                    tr!(
                        "Les paquets AUR se compilent : mettez-les à jour vous-même et relisez ce qui change",
                        "AUR packages are compiled: update them yourself and read what changes"
                    ),
                    &[&format!("{outil} -Sua")],
                ),
            });
        }
        if let Some(t) = firmware {
            constats.push(match t.join().ok().flatten() {
                None => impossible(
                    "Firmware",
                    tr!(
                        "métadonnées fwupd absentes : fwupdmgr refresh",
                        "fwupd metadata missing: fwupdmgr refresh"
                    ),
                ),
                Some(appareils) => {
                    if appareils.is_empty() {
                        ok(
                            "Firmware",
                            tr!(
                                "Firmwares à jour (BIOS, SSD, périphériques).",
                                "Firmware up to date (BIOS, SSD, devices)."
                            ),
                        )
                    } else {
                        alerte(
                            "Firmware",
                            Niveau::Moyen,
                            trf!(
                                "Mise à jour de firmware disponible : {}.",
                                "Firmware update available: {}.",
                                appareils.join(", ")
                            ),
                        )
                        .manuel(
                            tr!(
                                "Installer les firmwares (un redémarrage peut être demandé)",
                                "Install the firmware (a restart may be requested)"
                            ),
                            &["fwupdmgr update"],
                        )
                    }
                }
            });
        }
    });
    constats
}

/// Le bit « se met à jour » des drapeaux d'un appareil de fwupd (FWUPD_DEVICE_FLAG_UPDATABLE,
/// libfwupd/fwupd-device-struct.h).
const APPAREIL_MAJ: u64 = 1 << 1;

/// Les appareils de fwupd à interroger : (identifiant, nom), ceux qui se mettent à jour seulement, comme fwupdmgr
/// get-updates.
fn appareils_a_jour(liste: &dbus::Valeur) -> Vec<(String, String)> {
    liste
        .elements()
        .iter()
        .filter(|d| d.champ("Flags").and_then(dbus::Valeur::entier).unwrap_or(0) & APPAREIL_MAJ != 0)
        .filter_map(|d| {
            let id = d.champ("DeviceId")?.texte()?.to_string();
            let nom = d
                .champ("Name")
                .and_then(dbus::Valeur::texte)
                .unwrap_or_default()
                .to_string();
            Some((id, nom))
        })
        .collect()
}

/// Ce que dit GetUpgrades d'un appareil : `Ok(true)` s'il a une version plus récente, `Ok(false)` pour « rien à
/// faire » (NothingToDo : aucune version plus récente, appareil qui ne se met pas à jour) ou pour un appareil parti
/// entre la liste et la question (NotFound). NotSupported (« no components in silo » : métadonnées jamais
/// téléchargées) et toute autre erreur restent des erreurs : fwupdmgr les taisait et disait « à jour ».
fn reponse_upgrades(r: Result<Vec<dbus::Valeur>, String>) -> Result<bool, crate::modele::Echec> {
    match r {
        Ok(corps) => Ok(corps.first().is_some_and(|l| !l.elements().is_empty())),
        Err(e)
            if e.starts_with("org.freedesktop.fwupd.NothingToDo ")
                || e.starts_with("org.freedesktop.fwupd.NotFound ") =>
        {
            Ok(false)
        }
        Err(e) => Err(echec_fwupd(e)),
    }
}

/// Une erreur de fwupd ou du bus dans le canal d'erreur commun (son texte reste celui du bus).
fn echec_fwupd(e: String) -> crate::modele::Echec {
    crate::modele::Echec::echoue("maj/fwupd", e)
}

/// Les appareils à qui fwupd propose un nouveau firmware, lus par le client D-Bus maison (GetDevices puis GetUpgrades
/// pour chacun) au lieu de `fwupdmgr get-updates`. Une réponse d'un autre genre que « rien à faire » rend toute la
/// lecture impossible : jamais « à jour » sur une erreur.
fn firmwares_par_dbus() -> Result<Vec<String>, crate::modele::Echec> {
    if std::fs::read_to_string("/proc/self/uid_map").is_ok_and(|m| !crate::machine::bluetooth::identite(&m)) {
        return Err(echec_fwupd("espace de noms isolé".into()));
    }
    let mut bus = dbus::Bus::systeme().map_err(echec_fwupd)?;
    let corps = bus
        .appeler(
            "org.freedesktop.fwupd",
            "/",
            "org.freedesktop.fwupd",
            "GetDevices",
            "",
            Vec::new(),
        )
        .map_err(echec_fwupd)?;
    let mut proposes = Vec::new();
    for (id, nom) in appareils_a_jour(corps.first().ok_or_else(|| echec_fwupd("réponse vide".into()))?) {
        let r = bus.appeler(
            "org.freedesktop.fwupd",
            "/",
            "org.freedesktop.fwupd",
            "GetUpgrades",
            "s",
            vec![dbus::Valeur::Texte(id)],
        );
        if reponse_upgrades(r)? {
            proposes.push(crate::ui::affichable(&nom));
        }
    }
    Ok(proposes)
}

/// Appareils à qui fwupd propose un nouveau firmware (`fwupdmgr get-updates --json`). Le nom vient souvent de
/// l'appareil lui-même (la chaîne que le fabricant d'une clé USB ou d'une souris y a gravée) : prêt à montrer.
fn firmwares_proposes(v: &serde_json::Value) -> Vec<String> {
    v["Devices"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|d| d["Releases"].as_array().is_some_and(|r| !r.is_empty()))
        .filter_map(|d| d["Name"].as_str().map(crate::ui::affichable))
        .collect()
}

/// Âge en jours de la liste des paquets d'apt, `None` si elle n'a jamais été téléchargée.
pub(super) fn age_cache_apt() -> Option<u64> {
    let plus_recent = std::fs::read_dir("/var/lib/apt/lists")
        .ok()?
        .flatten()
        .filter(|f| {
            f.file_name().to_string_lossy().ends_with("Packages")
                || f.file_name().to_string_lossy().contains("Packages.")
        })
        .filter_map(|f| f.metadata().ok()?.modified().ok())
        .max()?;
    Some(plus_recent.elapsed().map_or(0, |d| d.as_secs() / 86_400))
}

pub(super) fn mises_a_jour() -> Constat {
    let Some(gestion) = Paquets::detecter() else {
        return impossible(
            "Mises à jour",
            tr!("gestionnaire de paquets non reconnu", "package manager not recognized"),
        );
    };
    let Some(liste) = liste_mises_a_jour(gestion) else {
        let raison = if gestion == Paquets::Apt {
            tr!("liste des paquets jamais téléchargée", "package list never downloaded")
        } else {
            tr!("outil absent ou hors ligne", "tool missing or offline")
        };
        return impossible("Mises à jour", raison).corriger(
            tr!(
                "Télécharger la liste des paquets et mettre à jour",
                "Download the package list and update"
            ),
            &[gestion.mise_a_jour()],
        );
    };
    // apt ne connaît que les mises à jour vues à son dernier « apt update » : une vieille liste en cache tout.
    let vieux = (gestion == Paquets::Apt)
        .then(age_cache_apt)
        .flatten()
        .filter(|&j| j > 7);
    if liste.is_empty() {
        return match vieux {
            Some(j) => alerte(
                "Mises à jour",
                Niveau::Moyen,
                trf!(
                    "Aucune mise à jour connue, mais la liste date de {j} jours.",
                    "No known update, but the list is {j} days old."
                ),
            )
            .corriger(
                tr!("Rafraîchir la liste et mettre à jour", "Refresh the list and update"),
                &[gestion.mise_a_jour()],
            ),
            None => ok("Mises à jour", tr!("Système à jour.", "System up to date.")),
        };
    }
    let n = liste.len();
    let sensibles = liste.iter().filter(|l| paquet_sensible(gestion, l)).count();
    let niveau = if n > 50 || sensibles > 0 {
        Niveau::Eleve
    } else {
        Niveau::Moyen
    };
    alerte(
        "Mises à jour",
        niveau,
        // Sans paquet sensible, on ne cite pas « noyau, openssl… » : la phrase laissait croire qu'ils étaient touchés.
        if sensibles == 0 {
            trf!("{n} paquet(s) à mettre à jour.", "{n} package(s) to update.")
        } else {
            trf!(
                "{n} paquet(s) à mettre à jour, dont {sensibles} sensible(s) (noyau, openssl, navigateur…).",
                "{n} package(s) to update, {sensibles} of them sensitive (kernel, openssl, browser…)."
            )
        },
    )
    .corriger(
        tr!("Mettre le système à jour", "Update the system"),
        &[gestion.mise_a_jour()],
    )
}

/// Une ligne de la liste des mises à jour touche-t-elle un paquet sensible (noyau, chiffrement, navigateur…) ?
/// zypper écrit un tableau « v | dépôt | nom | … » : le nom est dans la 3e colonne. Le noyau s'appelle « linux »
/// sur Arch et Debian, « kernel » sur Fedora et openSUSE.
pub(super) fn paquet_sensible(gestion: Paquets, ligne: &str) -> bool {
    let nom = match gestion {
        Paquets::Zypper => ligne.split('|').nth(2).unwrap_or(ligne),
        _ => ligne,
    }
    .trim()
    .to_ascii_lowercase();
    [
        "linux", "kernel", "openssl", "libssl", "openssh", "glibc", "libc6", "sudo", "firefox", "chromium", "nvidia",
    ]
    .iter()
    .any(|p| nom.starts_with(p))
}

/// Paquet installé touché par une faille publiée (CVE, avis de sécurité de la distribution).
#[derive(Debug, PartialEq)]
pub(super) struct Faille {
    paquet: String,
    gravite: Niveau,
    /// Une version corrigée est déjà dans les dépôts : la mise à jour suffit.
    corrigee: bool,
    /// Ses CVE, quand le suivi les donne (Arch) : comparées au catalogue des failles exploitées.
    cves: Vec<String>,
}

/// Gravité écrite par les distributions (anglais), en niveau de Vanguard. Inconnue : on ne minimise pas.
pub(super) fn gravite(texte: &str) -> Niveau {
    match texte.trim().to_ascii_lowercase().as_str() {
        "critical" => Niveau::Critique,
        "high" | "important" => Niveau::Eleve,
        "low" | "unknown" | "none" => Niveau::Info,
        _ => Niveau::Moyen,
    }
}

/// arch-audit --json : groupes de failles avec la liste des paquets installés touchés.
pub(super) fn failles_arch(json: &serde_json::Value) -> Vec<Faille> {
    json.as_array()
        .into_iter()
        .flatten()
        .flat_map(|g| {
            let gravite = gravite(g["severity"].as_str().unwrap_or("unknown"));
            let corrigee = g["fixed"].as_str().is_some_and(|v| !v.is_empty());
            let cves: Vec<String> = g["issues"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|c| Some(c.as_str()?.trim().to_uppercase()))
                .collect();
            g["packages"].as_array().into_iter().flatten().filter_map(move |p| {
                Some(Faille {
                    paquet: p.as_str()?.to_string(),
                    gravite,
                    corrigee,
                    cves: cves.clone(),
                })
            })
        })
        .collect()
}

/// apt list --upgradable : une mise à jour venue d'un dépôt « -security » (noble-security, stable-security…)
/// corrige une faille. apt ne donne pas la gravité.
pub(super) fn failles_apt(lignes: &[String]) -> Vec<Faille> {
    lignes
        .iter()
        .filter_map(|l| {
            let (nom, reste) = l.split_once('/')?;
            let depots = reste.split_whitespace().next()?;
            depots.split(',').any(|d| d.ends_with("-security")).then(|| Faille {
                paquet: nom.to_string(),
                gravite: Niveau::Eleve,
                corrigee: true,
                cves: Vec::new(),
            })
        })
        .collect()
}

/// dnf updateinfo list --security. dnf 4 : « FEDORA-2024-1a2b Important/Sec. curl-8.6.0-7.fc40.x86_64 » ;
/// dnf 5 : « FEDORA-2024-1a2b security Important curl-8.6.0-7.fc40.x86_64 2024-04-01 00:43:20 ».
pub(super) fn failles_dnf(texte: &str) -> Vec<Faille> {
    texte
        .lines()
        .filter_map(|l| {
            let mots: Vec<&str> = l.split_whitespace().collect();
            let (gravite_txt, paquet) = match mots.as_slice() {
                [_, g, p, ..] if g.ends_with("/Sec.") => (g.trim_end_matches("/Sec."), *p),
                [_, "security", g, p, ..] => (*g, *p),
                _ => return None,
            };
            // nom-version-révision.arch → nom
            let nom = paquet.rsplitn(3, '-').nth(2)?;
            Some(Faille {
                paquet: nom.to_string(),
                gravite: gravite(gravite_txt),
                corrigee: true,
                cves: Vec::new(),
            })
        })
        .collect()
}

/// zypper list-patches --category security : tableau « dépôt | nom | catégorie | gravité | interactif | état | résumé ».
pub(super) fn failles_zypper(texte: &str) -> Vec<Faille> {
    texte
        .lines()
        .filter_map(|l| {
            let c: Vec<&str> = l.split('|').map(str::trim).collect();
            (c.len() >= 6 && c[2] == "security" && c[5].starts_with("needed")).then(|| Faille {
                paquet: c[1].to_string(),
                gravite: gravite(c[3]),
                corrigee: true,
                cves: Vec::new(),
            })
        })
        .collect()
}

/// Failles connues des paquets installés, d'après le suivi de sécurité de la distribution.
pub(super) fn failles_connues() -> Constat {
    const CAT: &str = "Failles connues";
    let Some(gestion) = Paquets::detecter() else {
        return impossible(
            CAT,
            tr!("gestionnaire de paquets non reconnu", "package manager not recognized"),
        );
    };
    let failles = match gestion {
        Paquets::Pacman => {
            if !Path::new("/usr/bin/arch-audit").exists() {
                return impossible(CAT, tr!("arch-audit absent", "arch-audit missing")).corriger(
                    tr!(
                        "Installer arch-audit, qui lit le suivi de sécurité d'Arch (security.archlinux.org)",
                        "Install arch-audit, which reads the Arch security tracker (security.archlinux.org)"
                    ),
                    &[&gestion.installer("arch-audit")],
                );
            }
            match sortie_delai("arch-audit", &["--json"], 40, &[0])
                .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
            {
                Some(json) => failles_arch(&json),
                None => {
                    return impossible(
                        CAT,
                        tr!(
                            "suivi de sécurité injoignable, hors ligne ?",
                            "security tracker unreachable, offline?"
                        ),
                    );
                }
            }
        }
        Paquets::Apt => match liste_mises_a_jour(gestion) {
            Some(l) => failles_apt(&l),
            None => {
                return impossible(
                    CAT,
                    tr!("liste des paquets jamais téléchargée", "package list never downloaded"),
                );
            }
        },
        Paquets::Dnf => {
            match crate::commande::lancer(
                Command::new("dnf")
                    .args(["-q", "updateinfo", "list", "--security"])
                    .env("LC_ALL", "C"),
                120,
            ) {
                Some(r) if r.code == Some(0) => failles_dnf(&r.sortie),
                _ => {
                    return impossible(
                        CAT,
                        tr!(
                            "avis de sécurité de dnf injoignables, hors ligne ?",
                            "dnf security advisories unreachable, offline?"
                        ),
                    );
                }
            }
        }
        Paquets::Zypper => {
            match crate::commande::lancer(
                Command::new("zypper")
                    .args(["-q", "list-patches", "--category", "security"])
                    .env("LC_ALL", "C"),
                120,
            ) {
                Some(r) if r.code == Some(0) => failles_zypper(&r.sortie),
                _ => {
                    return impossible(
                        CAT,
                        tr!(
                            "avis de sécurité de zypper injoignables, hors ligne ?",
                            "zypper security advisories unreachable, offline?"
                        ),
                    );
                }
            }
        }
    };
    let mut constat = bilan_failles(gestion, &failles);
    // Les ports et le catalogue ne sont lus que s'il y a des failles à juger.
    if failles.is_empty() {
        return constat;
    }
    constat = avec_exposees(constat, &failles, &paquets_exposes(gestion));
    if failles.iter().all(|f| f.cves.is_empty()) {
        return constat;
    }
    avec_exploitees(constat, &failles, crate::protection::kev::exploitees())
}

/// Les CVE des failles connues des paquets installés, quand le suivi de la distribution les donne (Arch, par
/// arch-audit) ; `None` ailleurs ou sans réponse.
pub(super) fn cves_des_paquets() -> Option<std::collections::HashSet<String>> {
    if Paquets::detecter()? != Paquets::Pacman || !Path::new("/usr/bin/arch-audit").exists() {
        return None;
    }
    let json = serde_json::from_str::<serde_json::Value>(&sortie_delai("arch-audit", &["--json"], 40, &[0])?).ok()?;
    Some(failles_arch(&json).into_iter().flat_map(|f| f.cves).collect())
}

/// Le fichier d'une unité systemd (« php-fpm.service » ; une instance d'un modèle, nom@instance, a pour fichier celui
/// du modèle, nom@.service), là où les paquets les posent.
fn fichier_d_unite(unite: &str) -> Option<PathBuf> {
    let modele = match unite.split_once('@') {
        Some((debut, _)) => format!("{debut}@.service"),
        None => unite.to_string(),
    };
    ["/usr/lib/systemd/system", "/lib/systemd/system"]
        .into_iter()
        .map(|d| Path::new(d).join(&modele))
        .find(|c| c.is_file())
}

/// Les paquets des programmes joignables depuis un autre appareil (même critère que « Ports en écoute »), avec un
/// de leurs ports. Le programme quand il
/// est de ce compte (/proc/<pid>/exe) ; sinon, sans root, le fichier de son service systemd, posé par le même paquet
/// (php-fpm.service par php-fpm). Une bibliothèque qu'un serveur charge (openssl) n'est pas vue ici.
fn paquets_exposes(gestion: Paquets) -> HashMap<String, u16> {
    let Some(prises) = super::ecoute::prises_ou_ss() else {
        return HashMap::new();
    };
    let pids = crate::protection::sortantes::proprietaires();
    let adresses = super::adresses_exposees();
    let mut fichiers: Vec<(PathBuf, u16)> = Vec::new();
    for p in prises.iter().filter(|p| super::prise_exposee(p, &adresses)) {
        let programme = pids
            .get(&p.inode)
            .and_then(|pid| crate::socle::processus::programme(*pid));
        let unite = || {
            let groupe = p.groupe.as_deref()?;
            fichier_d_unite(groupe.rsplit('/').next().filter(|u| u.ends_with(".service"))?)
        };
        if let Some(f) = programme.or_else(unite) {
            fichiers.push((f, p.port));
        }
    }
    let chemins: Vec<PathBuf> = fichiers.iter().map(|(f, _)| f.clone()).collect();
    let mut exposes = HashMap::new();
    for (paquet, (_, port)) in gestion.proprietaires(&chemins).into_iter().zip(&fichiers) {
        if let Some(paquet) = paquet {
            exposes.entry(paquet).or_insert(*port);
        }
    }
    exposes
}

/// Les failles des paquets exposés au réseau, « paquet (port N) », chacune une fois.
fn exposees(failles: &[Faille], exposes: &HashMap<String, u16>) -> Vec<String> {
    let mut v: Vec<String> = failles
        .iter()
        .filter_map(|f| exposes.get(&f.paquet).map(|port| format!("{} (port {port})", f.paquet)))
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// Une faille dans un paquet dont un programme écoute au-delà de cet ordinateur : on la dit en tête, et le constat est
/// au moins élevé. Pas critique d'office : un gros paquet (systemd) a d'autres programmes que celui qui écoute, et la
/// faille peut être ailleurs ; une faille exploitée (catalogue KEV), elle, le rend critique.
fn avec_exposees(mut constat: Constat, failles: &[Faille], exposes: &HashMap<String, u16>) -> Constat {
    let ex = exposees(failles, exposes);
    if !ex.is_empty() {
        constat.message = trf!(
            "Paquet dont un programme écoute sur le réseau : {}. {}",
            "Package with a program listening on the network: {}. {}",
            crate::ui::resume(&ex, 5, ", "),
            constat.message
        );
        constat.probleme = constat.probleme.max(Some(Niveau::Eleve));
    }
    constat
}

/// Le catalogue des failles exploitées : CVE → jour de son ajout.
type Kev = HashMap<String, Option<chrono::NaiveDate>>;

/// Les failles que la CISA sait exploitées, « paquet (CVE-…, au catalogue depuis le …) », chacune une fois.
fn exploitees(failles: &[Faille], kev: &Kev) -> Vec<String> {
    let mut v: Vec<String> = failles
        .iter()
        .flat_map(|f| {
            f.cves.iter().filter_map(move |c| {
                let ajoutee = kev.get(c)?;
                Some(match ajoutee {
                    Some(d) => trf!(
                        "{} ({c}, au catalogue depuis le {d})",
                        "{} ({c}, in the catalog since {d})",
                        f.paquet
                    ),
                    None => format!("{} ({c})", f.paquet),
                })
            })
        })
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// Une faille exploitée passe en tête et rend le constat critique, avec ou sans correctif publié ; sans le catalogue,
/// c'est dit, sans rien conclure.
fn avec_exploitees(mut constat: Constat, failles: &[Faille], kev: Result<Kev, String>) -> Constat {
    match kev {
        Ok(kev) => {
            let ex = exploitees(failles, &kev);
            if !ex.is_empty() {
                constat.message = trf!(
                    "Activement exploitée (catalogue KEV de la CISA) : {}. {}",
                    "Actively exploited (CISA KEV catalog): {}. {}",
                    crate::ui::resume(&ex, 5, ", "),
                    constat.message
                );
                constat.probleme = Some(Niveau::Critique);
            }
        }
        Err(raison) => {
            constat.message = trf!(
                "{} Failles exploitées (catalogue KEV) pas vérifiées : {raison}.",
                "{} Exploited flaws (KEV catalog) not checked: {raison}.",
                constat.message
            );
        }
    }
    constat
}

pub(super) fn bilan_failles(gestion: Paquets, failles: &[Faille]) -> Constat {
    const CAT: &str = "Failles connues";
    let noms = |corrigee: bool| {
        let mut n: Vec<&str> = failles
            .iter()
            .filter(|f| f.corrigee == corrigee)
            .map(|f| f.paquet.as_str())
            .collect();
        n.sort_unstable();
        n.dedup();
        n
    };
    let (a_corriger, sans_correctif) = (noms(true), noms(false));
    let resume = |n: &[&str]| crate::ui::resume(n, 8, ", ");
    // Une faille sans correctif publié : rien à faire de ton côté, la mise à jour viendra. Le suivi d'Arch garde
    // souvent des failles corrigées en amont : on le dit, sans baisser la note.
    let attente = (!sans_correctif.is_empty()).then(|| {
        trf!(
            "{} paquet(s) touché(s) par une faille encore sans correctif publié : {}.",
            "{} package(s) affected by a flaw with no published fix yet: {}.",
            sans_correctif.len(),
            resume(&sans_correctif)
        )
    });
    if a_corriger.is_empty() {
        return match attente {
            Some(t) => alerte(
                CAT,
                Niveau::Info,
                trf!("Aucune faille corrigée en attente. {t}", "No fixed flaw pending. {t}"),
            ),
            None => ok(
                CAT,
                tr!(
                    "Aucun paquet installé n'a de faille connue.",
                    "No installed package has a known flaw."
                ),
            ),
        };
    }
    let pire = failles
        .iter()
        .filter(|f| f.corrigee)
        .map(|f| f.gravite)
        .max()
        .unwrap_or(Niveau::Moyen)
        .max(Niveau::Moyen);
    let mut message = trf!(
        "{} paquet(s) avec une faille connue, déjà corrigée dans les dépôts : {}.",
        "{} package(s) with a known flaw, already fixed in the repositories: {}.",
        a_corriger.len(),
        resume(&a_corriger)
    );
    if let Some(t) = attente {
        let _ = write!(message, " {t}");
    }
    alerte(CAT, pire, message).corriger(
        tr!("Installer les correctifs de sécurité", "Install the security fixes"),
        &[gestion.mise_a_jour()],
    )
}

/// Version du noyau qui tourne (« 7.2.5-3-omarchy »). /proc/sys/kernel/osrelease est ce que uname lit : sans
/// lui, /proc n'est pas monté et uname ne saurait rien de plus.
pub(super) fn noyau_en_cours() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Dossiers des noyaux installés, un par version. Un vrai noyau a son image (dans son dossier, ou /boot sous Debian)
/// ou ses modules ; on écarte les restes vides. /lib/modules est souvent le même dossier que /usr/lib/modules.
pub(super) fn noyaux_installes() -> Vec<std::path::PathBuf> {
    let mut noyaux: Vec<std::path::PathBuf> = ["/usr/lib/modules", "/lib/modules"]
        .iter()
        .filter_map(|d| std::fs::read_dir(d).ok())
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            let nom = p.file_name().unwrap_or_default().to_string_lossy();
            p.join("modules.dep").exists()
                || p.join("vmlinuz").exists()
                || Path::new(&format!("/boot/vmlinuz-{nom}")).exists()
        })
        .collect();
    noyaux.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    noyaux.dedup_by(|a, b| a.file_name() == b.file_name());
    noyaux
}

pub(super) fn redemarrage() -> Constat {
    let noyau = noyau_en_cours();
    let installes = noyaux_installes();
    // Aucun noyau ici (conteneur, noyau fourni par l'hôte) : rien à comparer.
    if installes.is_empty() {
        return impossible(
            "Noyau",
            tr!(
                "aucun noyau installé ici, conteneur ?",
                "no kernel installed here, container?"
            ),
        );
    }
    let en_cours = installes
        .iter()
        .any(|p| p.file_name().is_some_and(|n| n.to_string_lossy() == noyau));
    // Fedora, openSUSE et Debian gardent plusieurs noyaux : le plus récemment installé doit être celui qui tourne.
    let plus_recent = installes
        .iter()
        .max_by_key(|p| p.metadata().and_then(|m| m.modified()).ok())
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned());
    // Arch efface le dossier de l'ancien noyau à la mise à jour : s'il existe encore, le noyau chargé est le bon.
    // La date n'y veut rien dire : avec linux + linux-lts (ou DKMS qui recompile pour chacun), le dernier
    // dossier touché n'est pas forcément celui qui devrait tourner.
    let dernier_installe =
        Paquets::detecter() == Some(Paquets::Pacman) || plus_recent.as_deref() == Some(noyau.as_str());
    let a_jour = en_cours && dernier_installe && !Path::new("/var/run/reboot-required").exists();
    if a_jour {
        ok(
            "Noyau",
            trf!(
                "Le noyau en cours ({noyau}) est le plus récent installé.",
                "The running kernel ({noyau}) is the newest installed."
            ),
        )
    } else {
        let nouveau = plus_recent
            .filter(|n| *n != noyau)
            .map(|n| format!(" ({n})"))
            .unwrap_or_default();
        alerte(
            "Noyau",
            Niveau::Moyen,
            trf!(
                "Noyau plus récent installé{nouveau} mais pas encore chargé : les correctifs ne sont pas actifs.",
                "Newer kernel installed{nouveau} but not loaded yet: its fixes are not active."
            ),
        )
        .manuel(
            tr!("Redémarrer quand c'est pratique", "Restart when convenient"),
            &["systemctl reboot"],
        )
    }
}

const DKMS: &str = "/var/lib/dkms";

/// Le texte de « dkms status », refait d'après son arbre : /var/lib/dkms/<module>/<version>/source pour un module
/// ajouté, <version>/<noyau>/<arch> une fois compilé pour ce noyau, et le lien <module>/kernel-<noyau>-<arch> vers
/// ce dossier quand il est installé (c'est ce lien que dkms consulte). « original_module » garde les modules du
/// noyau remplacés : ce n'est pas une version. `None` si l'arbre ne se lit pas.
fn status_dkms_dans(racine: &Path) -> Option<String> {
    let dossiers = |d: &Path| -> Vec<std::path::PathBuf> {
        let mut v: Vec<_> = std::fs::read_dir(d)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .map(|e| e.path())
            .collect();
        v.sort();
        v
    };
    let nom = |p: &Path| {
        p.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    };
    std::fs::read_dir(racine).ok()?;
    let mut lignes = Vec::new();
    for module in dossiers(racine) {
        let m = nom(&module);
        for version in dossiers(&module).into_iter().filter(|v| nom(v) != "original_module") {
            let v = nom(&version);
            let mut compile = false;
            for noyau in dossiers(&version).into_iter().filter(|k| nom(k) != "source") {
                let k = nom(&noyau);
                for arch in dossiers(&noyau) {
                    let a = nom(&arch);
                    compile = true;
                    let lien = std::fs::read_link(module.join(format!("kernel-{k}-{a}"))).ok();
                    let installe = lien.is_some_and(|l| l.ends_with(Path::new(&v).join(&k).join(&a)));
                    let etat = if installe { "installed" } else { "built" };
                    lignes.push(format!("{m}/{v}, {k}, {a}: {etat}"));
                }
            }
            if !compile && version.join("source").exists() {
                lignes.push(format!("{m}/{v}: added"));
            }
        }
    }
    Some(lignes.join("\n"))
}

/// Modules de « dkms status » et, pour chacun, les noyaux de `noyaux` où il n'est pas installé.
/// Lignes « nvidia/610.57, 7.2.5-arch1, x86_64: installed » (ancien format : « nvidia, 610.57, 7.2.5, x86_64: »).
pub(super) fn dkms_manquants(status: &str, noyaux: &[String]) -> Vec<(String, Vec<String>)> {
    // Chaque module, dans l'ordre de « dkms status », avec les noyaux où il est installé.
    let mut modules: Vec<(String, Vec<String>)> = Vec::new();
    for l in status.lines() {
        let Some((gauche, etat)) = l.split_once(": ") else {
            continue;
        };
        let parties: Vec<&str> = gauche.split(", ").map(str::trim).collect();
        let (nom, noyau) = match parties.first() {
            Some(p) if p.contains('/') => (p.split('/').next().unwrap_or(p), parties.get(1)),
            Some(p) => (*p, parties.get(2)),
            None => continue,
        };
        if nom.is_empty() {
            continue;
        }
        let i = modules.iter().position(|(m, _)| m == nom).unwrap_or_else(|| {
            modules.push((nom.to_string(), Vec::new()));
            modules.len() - 1
        });
        if let Some(k) = noyau
            && etat.trim_start().starts_with("installed")
        {
            modules[i].1.push((*k).to_string());
        }
    }
    modules
        .into_iter()
        .map(|(m, installes)| (m, noyaux.iter().filter(|k| !installes.contains(k)).cloned().collect()))
        .collect()
}

/// Pilotes DKMS (NVIDIA, manette, VirtualBox…) : recompilés pour chaque noyau. S'il en manque un pour le noyau
/// qu'on va démarrer, c'est l'écran noir ou un périphérique muet au prochain démarrage.
pub(super) fn pilotes_dkms() -> Option<Constat> {
    // Sans dkms, rien ne recompile : un arbre resté après sa désinstallation ne dit rien. L'arbre se lit
    // directement ; la commande seulement s'il ne se lit pas.
    if !natif::present("dkms") {
        return None;
    }
    let status = match status_dkms_dans(Path::new(DKMS)) {
        Some(s) => s,
        None if Path::new(DKMS).exists() => sortie("dkms", &["status"])?,
        None => return None,
    };
    let mut noyaux: Vec<String> = noyaux_installes()
        .iter()
        .filter_map(|p| Some(p.file_name()?.to_string_lossy().into_owned()))
        .collect();
    let en_cours = noyau_en_cours();
    if !en_cours.is_empty() && !noyaux.contains(&en_cours) {
        noyaux.push(en_cours);
    }
    let modules = dkms_manquants(&status, &noyaux);
    if modules.is_empty() {
        return None;
    }
    let mut a_refaire: Vec<String> = modules.iter().flat_map(|(_, k)| k.clone()).collect();
    a_refaire.sort();
    a_refaire.dedup();
    if a_refaire.is_empty() {
        return Some(ok(
            "Pilotes DKMS",
            trf!(
                "{} compilé(s) pour chaque noyau installé.",
                "{} built for every installed kernel.",
                modules.iter().map(|(m, _)| m.as_str()).collect::<Vec<_>>().join(", ")
            ),
        ));
    }
    let detail: Vec<String> = modules
        .iter()
        .filter(|(_, k)| !k.is_empty())
        .map(|(m, k)| trf!("{m} (noyau {})", "{m} (kernel {})", k.join(", ")))
        .collect();
    Some(
        alerte(
            "Pilotes DKMS",
            Niveau::Eleve,
            trf!(
                "Pilote pas compilé : {}. Écran noir ou périphérique muet possible au prochain démarrage.",
                "Driver not built: {}. Black screen or silent device possible at the next boot.",
                detail.join(", ")
            ),
        )
        .corriger(
            tr!(
                "Recompiler les pilotes DKMS (les en-têtes du noyau doivent être installés)",
                "Rebuild the DKMS drivers (the kernel headers must be installed)"
            ),
            &a_refaire
                .iter()
                .map(|k| format!("sudo dkms autoinstall -k {k}"))
                .collect::<Vec<_>>(),
        ),
    )
}

/// Tout ce qui doit être à jour : paquets, Flatpak, Snap, AUR, firmware, pilotes DKMS, noyau chargé. En parallèle :
/// la liste des paquets interroge les dépôts (jusqu'à 30 s) pendant que le reste se vérifie.
/// `seulement` : les catégories à revérifier (après une installation) ; le noyau chargé est toujours vérifié.
pub fn mises_a_jour_completes(seulement: Option<&[&str]>) -> Vec<Constat> {
    let voulu = |categories: &[&str]| seulement.is_none_or(|s| categories.iter().any(|c| s.contains(c)));
    std::thread::scope(|portee| {
        let paquets = voulu(&["Mises à jour"]).then(|| portee.spawn(mises_a_jour));
        let autres = voulu(&["Flatpak", "Snap", "AUR", "Firmware"]).then(|| portee.spawn(autres_mises_a_jour));
        let dkms = voulu(&["Pilotes DKMS"]).then(|| portee.spawn(pilotes_dkms));
        let noyau = redemarrage();
        let mut constats: Vec<Constat> = paquets
            .map(|t| {
                t.join().unwrap_or_else(|_| {
                    impossible("Mises à jour", tr!("vérification interrompue", "check interrupted"))
                })
            })
            .into_iter()
            .collect();
        constats.extend(autres.map(|t| t.join().unwrap_or_default()).unwrap_or_default());
        constats.extend(dkms.and_then(|t| t.join().ok().flatten()));
        constats.push(noyau);
        constats
    })
}

/// Paquets AUR introuvables dans la réponse de l'AUR (retirés ou construits à la main) et paquets orphelins.
pub(super) fn etat_aur(installes: &[&str], reponse: &serde_json::Value) -> (Vec<String>, Vec<String>) {
    let resultats: Vec<&serde_json::Value> = reponse["results"].as_array().into_iter().flatten().collect();
    let absents = installes
        .iter()
        .filter(|n| !resultats.iter().any(|r| r["Name"].as_str() == Some(**n)))
        .map(std::string::ToString::to_string)
        .collect();
    let orphelins = resultats
        .iter()
        .filter(|r| r["Maintainer"].is_null())
        .filter_map(|r| r["Name"].as_str().map(str::to_string))
        .collect();
    (absents, orphelins)
}

/// Encode un nom pour une adresse web : « libc++ » doit devenir « libc%2B%2B », sinon « + » est lu comme une
/// espace et le paquet passe pour absent de l'AUR (vérifié sur aewm++).
pub(super) fn encoder_url(texte: &str) -> String {
    texte
        .bytes()
        .map(|o| match o {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (o as char).to_string(),
            _ => format!("%{o:02X}"),
        })
        .collect()
}

/// Le nombre de paquets AUR dont l'AUR a une version plus récente que celle installée, ce que listait
/// « yay -Qua » : la même requête que la règle des paquets AUR (seuls les noms partent), comparée aux versions de
/// la base locale comme pacman les compare. `None` si on ne peut pas savoir (dépôts jamais lus, AUR injoignable).
fn aur_a_mettre_a_jour() -> Option<usize> {
    if Paquets::detecter() != Some(Paquets::Pacman) || !depots_pacman_lus() {
        return None;
    }
    aur_selon(&paquets_etrangers()?, fiches_aur, natif::paquets_pacman)
}

/// Le compte, l'AUR et la base locale passés en paramètres pour que les tests n'aillent ni sur le réseau ni dans
/// /var/lib/pacman. Aucun paquet étranger : tout est à jour, sans rien demander à l'AUR.
fn aur_selon(
    etrangers: &[String],
    fiches: impl FnOnce(&[&str]) -> Option<Vec<serde_json::Value>>,
    locaux: impl FnOnce() -> Option<Vec<(String, String)>>,
) -> Option<usize> {
    let installes: Vec<&str> = etrangers.iter().map(String::as_str).collect();
    if installes.is_empty() {
        return Some(0);
    }
    let fiches = fiches(&installes)?;
    let locales: HashMap<String, String> = locaux()?.into_iter().collect();
    Some(plus_recents_dans_l_aur(&locales, &fiches))
}

/// Les fiches de l'AUR dont la version (« Version ») dépasse celle installée.
fn plus_recents_dans_l_aur(locales: &HashMap<String, String>, fiches: &[serde_json::Value]) -> usize {
    fiches
        .iter()
        .filter(|f| {
            let (Some(nom), Some(aur)) = (f["Name"].as_str(), f["Version"].as_str()) else {
                return false;
            };
            locales
                .get(nom)
                .is_some_and(|installee| vercmp(installee, aur) == std::cmp::Ordering::Less)
        })
        .count()
}

/// Deux versions de paquet comparées comme pacman (alpm_pkg_vercmp) : « époque:version-révision », l'époque
/// d'abord (0 si absente), puis la version, puis la révision quand les deux en ont une.
pub(super) fn vercmp(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    if a == b {
        return Ordering::Equal;
    }
    // Les chiffres de tête suivis de « : » sont l'époque ; la révision suit le dernier tiret de ce qui reste.
    let decouper = |evr: &str| -> (String, String, Option<String>) {
        let chiffres = evr.bytes().take_while(u8::is_ascii_digit).count();
        let (epoque, reste) = match evr[chiffres..].strip_prefix(':') {
            Some(reste) if chiffres > 0 => (evr[..chiffres].to_string(), reste),
            Some(reste) => ("0".to_string(), reste),
            None => ("0".to_string(), evr),
        };
        match reste.rsplit_once('-') {
            Some((v, r)) => (epoque, v.to_string(), Some(r.to_string())),
            None => (epoque, reste.to_string(), None),
        }
    };
    let (e1, v1, r1) = decouper(a);
    let (e2, v2, r2) = decouper(b);
    rpmvercmp(&e1, &e2)
        .then_with(|| rpmvercmp(&v1, &v2))
        .then_with(|| match (r1, r2) {
            (Some(r1), Some(r2)) => rpmvercmp(&r1, &r2),
            _ => Ordering::Equal,
        })
}

/// La comparaison de rpm que pacman reprend : des segments de chiffres ou de lettres, séparés par le reste. Un
/// segment numérique bat un segment de lettres ; les nombres se comparent sans leurs zéros de tête ; à la fin, ce
/// qui reste gagne, sauf des lettres (« 1.0 » est plus récent que « 1.0beta »).
fn rpmvercmp(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    if a == b {
        return Ordering::Equal;
    }
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() && j < b.len() {
        let (debut_i, debut_j) = (i, j);
        while i < a.len() && !a[i].is_ascii_alphanumeric() {
            i += 1;
        }
        while j < b.len() && !b[j].is_ascii_alphanumeric() {
            j += 1;
        }
        if i == a.len() || j == b.len() {
            break;
        }
        // Des séparateurs de longueurs différentes décident à eux seuls.
        if i - debut_i != j - debut_j {
            return (i - debut_i).cmp(&(j - debut_j));
        }
        let (fin_i, fin_j, nombre) = if a[i].is_ascii_digit() {
            (
                i + a[i..].iter().take_while(|o| o.is_ascii_digit()).count(),
                j + b[j..].iter().take_while(|o| o.is_ascii_digit()).count(),
                true,
            )
        } else {
            (
                i + a[i..].iter().take_while(|o| o.is_ascii_alphabetic()).count(),
                j + b[j..].iter().take_while(|o| o.is_ascii_alphabetic()).count(),
                false,
            )
        };
        // Deux segments de genres différents : les chiffres sont plus récents.
        if fin_j == j {
            return if nombre { Ordering::Greater } else { Ordering::Less };
        }
        let (mut s1, mut s2) = (&a[i..fin_i], &b[j..fin_j]);
        if nombre {
            while s1.first() == Some(&b'0') {
                s1 = &s1[1..];
            }
            while s2.first() == Some(&b'0') {
                s2 = &s2[1..];
            }
            if s1.len() != s2.len() {
                return s1.len().cmp(&s2.len());
            }
        }
        if s1 != s2 {
            return s1.cmp(s2);
        }
        i = fin_i;
        j = fin_j;
    }
    if i >= a.len() && j >= b.len() {
        return Ordering::Equal;
    }
    let lettre = |s: &[u8], k: usize| s.get(k).is_some_and(u8::is_ascii_alphabetic);
    if (i >= a.len() && !lettre(b, j)) || lettre(a, i) {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

/// Les paquets installés qu'aucun dépôt de pacman.conf ne fournit, ce que liste « pacman -Qmq » : les noms de la
/// base locale absents de toutes les bases sync/*.db. La commande ne reste qu'en secours, quand une base ne se lit
/// pas en Rust (abîmée, ou compressée en xz, que rien ici ne sait ouvrir) : compter un paquet comme étranger parce que
/// sa base est illisible ferait interroger l'AUR pour un paquet qui n'y est pas.
fn paquets_etrangers() -> Option<Vec<String>> {
    static ETRANGERS: std::sync::OnceLock<Option<Vec<String>>> = std::sync::OnceLock::new();
    ETRANGERS
        .get_or_init(|| etrangers_lus().or_else(etrangers_selon_pacman))
        .clone()
}

/// La lecture native ; `None` dès qu'un dépôt configuré manque ou ne se lit pas.
pub(super) fn etrangers_lus() -> Option<Vec<String>> {
    let depots = depots_configures(&std::fs::read_to_string("/etc/pacman.conf").ok()?);
    if depots.is_empty() {
        return None;
    }
    let mut fournis = std::collections::HashSet::new();
    for depot in &depots {
        let octets = std::fs::read(format!("/var/lib/pacman/sync/{depot}.db")).ok()?;
        fournis.extend(noms_base_sync(&octets)?);
    }
    Some(etrangers(&natif::paquets_pacman()?, &fournis))
}

/// Le secours : « pacman -Qmq » rend le code 1 quand aucun paquet ne passe le filtre (query.c : `if(!match) ret =
/// 1`) ; ce code avec une sortie vide veut dire « aucun paquet étranger », pas « on ne sait pas ».
fn etrangers_selon_pacman() -> Option<Vec<String>> {
    etrangers_selon_sortie(&crate::commande::lancer_en_anglais(
        Command::new("pacman").arg("-Qmq"),
        30,
    )?)
}

fn etrangers_selon_sortie(r: &crate::commande::Resultat) -> Option<Vec<String>> {
    matches!(r.code, Some(0 | 1)).then(|| r.sortie.lines().filter(|l| !l.is_empty()).map(str::to_string).collect())
}

/// Les noms installés absents des dépôts, dans l'ordre de la base locale (celui de pacman).
fn etrangers(locaux: &[(String, String)], fournis: &std::collections::HashSet<String>) -> Vec<String> {
    locaux
        .iter()
        .filter(|(nom, _)| !fournis.contains(nom))
        .map(|(nom, _)| nom.clone())
        .collect()
}

/// Les dépôts de pacman.conf : chaque section sauf [options]. Les seules bases à compter : une base restée dans
/// sync/ après qu'on a retiré son dépôt (offline.db d'une installation, community.db d'avant la fusion) ne fournit
/// plus rien pour pacman, et la compter cacherait des paquets étrangers.
fn depots_configures(conf: &str) -> Vec<String> {
    conf.lines()
        .filter_map(|l| {
            let l = l.split('#').next().unwrap_or_default().trim();
            l.strip_prefix('[')?.strip_suffix(']').map(str::trim)
        })
        .filter(|s| !s.is_empty() && *s != "options")
        .map(str::to_string)
        .collect()
}

/// Les noms des paquets d'une base sync (une archive tar, en gzip, en zstd ou sans compression), lus dans le %NAME%
/// de chaque « desc » comme pour la base locale. `None` pour un autre format (xz) ou une archive abîmée.
fn noms_base_sync(octets: &[u8]) -> Option<Vec<String>> {
    let tar = if octets.starts_with(&[0x1f, 0x8b]) {
        crate::archives::gzip::degzip(octets, 256 << 20)?
    } else if super::zstd::est_zstd(octets) {
        // repo-add écrit en zstd quand on le lui demande (omarchy.db) ; la base d'extra fait 10 Mo décompressée, la
        // borne de degzip vaut ici aussi.
        super::zstd::decompresser(octets, 256 << 20)?
    } else if octets.get(257..262) == Some(b"ustar") {
        octets.to_vec()
    } else {
        return None;
    };
    noms_tar(&tar)
}

/// Les noms des paquets d'une archive tar de base sync, lus dans le %NAME% de chaque « …/desc » comme pour la base
/// locale (le nom complet d'un en-tête pax ou GNU n'importe pas, puisque le nom du paquet vient du contenu). `None` :
/// archive coupée avant ses blocs de fin (bsdtar et repo-add les écrivent toujours) : ce qui a été lu ne dit pas tout,
/// et un paquet de la partie perdue passerait pour étranger.
fn noms_tar(tar: &[u8]) -> Option<Vec<String>> {
    // La base d'extra a des dizaines de milliers d'entrées (un dossier et un desc par paquet, et leurs en-têtes pax) ;
    // seuls les desc, de quelques Kio, sont gardés.
    const BORNES: crate::archives::Bornes = crate::archives::Bornes {
        entrees: 2_000_000,
        fichier: 1 << 20,
        total: 256 << 20,
    };
    let lus = crate::archives::tar::fichiers(tar, &BORNES, |nom| nom.ends_with("/desc"))?;
    Some(
        lus.fichiers
            .iter()
            .filter_map(|(_, contenu)| {
                natif::champs_pacman(&String::from_utf8_lossy(contenu))
                    .get("NAME")
                    .and_then(|v| v.first())
                    .cloned()
            })
            .collect(),
    )
}

/// Les bases des dépôts ont-elles été téléchargées ? Sans elles, pacman -Qm prend chaque paquet pour un paquet de
/// l'AUR et toute la base serait déclarée « absente de l'AUR » (vu dans un conteneur Arch neuf).
fn depots_pacman_lus() -> bool {
    std::fs::read_dir("/var/lib/pacman/sync")
        .into_iter()
        .flatten()
        .flatten()
        .any(|f| f.path().extension().is_some_and(|e| e == "db"))
}

/// Les fiches de ces paquets dans l'AUR. Même requête que yay ou paru : seuls les noms partent vers
/// aur.archlinux.org, par lots de 100 pour ne pas dépasser la longueur maximale d'une adresse. `None` : injoignable.
fn fiches_aur(installes: &[&str]) -> Option<Vec<serde_json::Value>> {
    let mut resultats = Vec::new();
    for lot in installes.chunks(100) {
        let requete = format!(
            "https://aur.archlinux.org/rpc/v5/info?{}",
            lot.iter()
                .map(|n| format!("arg[]={}", encoder_url(n)))
                .collect::<Vec<_>>()
                .join("&")
        );
        let json = crate::http::texte(&requete, std::time::Duration::from_secs(20))
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())?;
        resultats.extend(json["results"].as_array().cloned().unwrap_or_default());
    }
    Some(resultats)
}

/// Un paquet retiré de l'AUR ne reçoit plus jamais de mise à jour, sans que rien ne prévienne.
pub(super) fn paquets_aur() -> Option<Constat> {
    if Paquets::detecter() != Some(Paquets::Pacman) {
        return None;
    }
    if !depots_pacman_lus() {
        return Some(impossible(
            "Paquets AUR",
            tr!(
                "liste des dépôts jamais téléchargée (sudo pacman -Sy)",
                "repository list never downloaded (sudo pacman -Sy)"
            ),
        ));
    }
    let liste = paquets_etrangers()?;
    let installes: Vec<&str> = liste.iter().map(String::as_str).collect();
    if installes.is_empty() {
        return None;
    }
    let Some(resultats) = fiches_aur(&installes) else {
        return Some(impossible(
            "Paquets AUR",
            tr!("AUR injoignable, hors ligne ?", "AUR unreachable, offline?"),
        ));
    };
    let (absents, orphelins) = etat_aur(&installes, &serde_json::json!({ "results": resultats }));
    Some(if !absents.is_empty() {
        alerte(
            "Paquets AUR",
            Niveau::Moyen,
            trf!(
                "Absent(s) de l'AUR : {} (retiré, ou construit à la main) : plus aucune mise à jour automatique.",
                "Missing from the AUR: {} (removed, or built by hand): no more automatic updates.",
                absents.join(", ")
            ),
        )
        .manuel(
            tr!(
                "Vérifier si un paquet de remplacement existe, sinon le désinstaller s'il n'est plus utile",
                "Check whether a replacement package exists, otherwise uninstall it if no longer needed"
            ),
            &["pacman -Qm"],
        )
    } else if !orphelins.is_empty() {
        alerte(
            "Paquets AUR",
            Niveau::Info,
            trf!(
                "Paquet(s) AUR sans mainteneur : {} (les mises à jour risquent de s'arrêter).",
                "Orphaned AUR package(s): {} (updates may stop).",
                orphelins.join(", ")
            ),
        )
    } else {
        ok(
            "Paquets AUR",
            trf!(
                "Les {} paquets AUR installés sont tous suivis dans l'AUR.",
                "The {} installed AUR packages are all tracked in the AUR.",
                installes.len()
            ),
        )
    })
}

#[cfg(test)]
mod tests {
    /// Un en-tête tar ustar minimal : nom, mode, taille en octal, type, somme de contrôle comprise.
    fn entete_tar(nom: &str, taille: usize, type_: u8) -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[..nom.len()].copy_from_slice(nom.as_bytes());
        h[100..107].copy_from_slice(b"0000644");
        h[124..135].copy_from_slice(format!("{taille:011o}").as_bytes());
        h[156] = type_;
        h[257..263].copy_from_slice(b"ustar\0");
        h[148..156].copy_from_slice(b"        ");
        let somme: u32 = h.iter().map(|&o| u32::from(o)).sum();
        h[148..155].copy_from_slice(format!("{somme:06o}\0").as_bytes());
        h
    }

    /// Une archive comme une base sync : un dossier et un « desc » par paquet, un « files » à ignorer, un en-tête
    /// pax devant le second paquet (bsdtar en écrit pour les noms longs), puis les deux blocs de fin.
    fn base_inventee() -> Vec<u8> {
        let mut tar = Vec::new();
        let fichier = |tar: &mut Vec<u8>, nom: &str, contenu: &[u8], type_: u8| {
            tar.extend(entete_tar(nom, contenu.len(), type_));
            tar.extend(contenu);
            tar.resize(tar.len().div_ceil(512) * 512, 0);
        };
        fichier(&mut tar, "zorglub-1.0-1/", b"", b'5');
        fichier(
            &mut tar,
            "zorglub-1.0-1/desc",
            b"%FILENAME%\nzorglub.pkg\n\n%NAME%\nzorglub\n\n",
            b'0',
        );
        fichier(&mut tar, "zorglub-1.0-1/files", b"%FILES%\nusr/\n", b'0');
        fichier(&mut tar, "PaxHeader/x", b"30 path=python-3to2-1.1.1-1/desc\n", b'x');
        fichier(
            &mut tar,
            "python-3to2-1.1.1-1/desc",
            b"%NAME%\npython-3to2\n\n%VERSION%\n1.1.1-1\n",
            b'0',
        );
        tar.extend([0u8; 1024]);
        tar
    }

    #[test]
    fn base_sync_lue_en_tar_et_en_gzip() {
        let tar = base_inventee();
        let attendu = vec!["zorglub".to_string(), "python-3to2".to_string()];
        assert_eq!(noms_base_sync(&tar), Some(attendu.clone()));
        // Un gzip à la main : en-tête de 10 octets, flux deflate, puis CRC et taille (que `degzip` ne lit pas).
        let mut gz = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
        gz.extend(miniz_oxide::deflate::compress_to_vec(&tar, 6));
        gz.extend([0u8; 8]);
        assert_eq!(noms_base_sync(&gz), Some(attendu.clone()));
        // Une trame zstd à la main (un seul bloc en clair), comme repo-add en écrit avec --zstd.
        let mut zst = vec![0x28, 0xb5, 0x2f, 0xfd, 0, 0x50];
        zst.extend(&(1 | (u32::try_from(tar.len()).unwrap() << 3)).to_le_bytes()[..3]);
        zst.extend(&tar);
        assert_eq!(noms_base_sync(&zst), Some(attendu.clone()));
        // La même, précédée d'une trame à sauter (pzstd en écrit une en tête).
        let mut sautee = vec![0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0];
        sautee.extend(&zst);
        assert_eq!(noms_base_sync(&sautee), Some(attendu));
    }

    #[test]
    fn base_sync_illisible_dit_qu_on_ne_sait_pas() {
        // zstd abîmé (omarchy.db coupée) : la commande prendra le relais.
        assert_eq!(noms_base_sync(&[0x28, 0xb5, 0x2f, 0xfd, 4, 0x58]), None);
        // xz : aucun décodeur ici.
        assert_eq!(noms_base_sync(&[0xfd, b'7', b'z', b'X', b'Z', 0]), None);
        // Archive coupée au milieu d'un contenu.
        let tar = base_inventee();
        assert_eq!(noms_base_sync(&tar[..512 * 3 + 10]), None);
        // Coupée entre deux entrées, sans blocs de fin : ce qui manque pourrait fournir un paquet.
        assert_eq!(noms_tar(&tar[..512]), None);
    }

    #[test]
    fn depots_de_pacman_conf_sans_options() {
        let conf = "[options]\nHoldPkg = pacman\n#[testing]\n[omarchy]\nServer = x\n [core] # principal\n\
                    [extra]\nInclude = /etc/pacman.d/mirrorlist\n";
        assert_eq!(depots_configures(conf), ["omarchy", "core", "extra"]);
        assert_eq!(depots_configures("[options]\n"), Vec::<String>::new());
    }

    #[test]
    fn etrangers_selon_les_depots() {
        let locaux = vec![
            ("bash".to_string(), "5.2-1".to_string()),
            ("zorglub-git".to_string(), "r12-1".to_string()),
        ];
        let fournis: std::collections::HashSet<String> = ["bash".to_string()].into();
        assert_eq!(etrangers(&locaux, &fournis), ["zorglub-git"]);
        let tous: std::collections::HashSet<String> = ["bash".into(), "zorglub-git".into()].into();
        assert_eq!(etrangers(&locaux, &tous), Vec::<String>::new());
    }

    /// Le défaut relevé : sans paquet étranger, pacman -Qmq rend le code 1 ; c'est « à jour », pas « hors ligne ».
    #[test]
    fn aucun_paquet_etranger_veut_dire_a_jour() {
        let r = |code, sortie: &str| crate::commande::Resultat {
            code,
            sortie: sortie.to_string(),
            erreurs: String::new(),
        };
        assert_eq!(etrangers_selon_sortie(&r(Some(1), "")), Some(vec![]));
        assert_eq!(
            etrangers_selon_sortie(&r(Some(0), "yay-bin\n")),
            Some(vec!["yay-bin".to_string()])
        );
        assert_eq!(etrangers_selon_sortie(&r(None, "")), None);
        assert_eq!(etrangers_selon_sortie(&r(Some(2), "")), None);
        // Liste vide : Some(0) sans toucher à l'AUR ni à la base locale.
        assert_eq!(aur_selon(&[], |_| unreachable!(), || unreachable!()), Some(0));
        // Un paquet plus ancien que l'AUR est compté.
        let fiches = vec![serde_json::json!({ "Name": "zorglub-git", "Version": "r13-1" })];
        let locaux = vec![("zorglub-git".to_string(), "r12-1".to_string())];
        assert_eq!(
            aur_selon(&["zorglub-git".into()], |_| Some(fiches), || Some(locaux)),
            Some(1)
        );
    }

    /// Sur cet ordinateur, chaque base sync lue en Rust (gzip ou zstd) donne les mêmes noms que « pacman -Slq », quand
    /// les deux sont là.
    #[test]
    fn base_sync_comme_pacman_sl() {
        let Ok(conf) = std::fs::read_to_string("/etc/pacman.conf") else {
            return crate::essais::saute("pas de /etc/pacman.conf");
        };
        for depot in depots_configures(&conf) {
            let Ok(octets) = std::fs::read(format!("/var/lib/pacman/sync/{depot}.db")) else {
                continue;
            };
            let Some(r) = crate::commande::lancer_en_anglais(Command::new("pacman").args(["-Slq", &depot]), 30)
                .filter(|r| r.code == Some(0))
            else {
                continue;
            };
            let mut attendu: Vec<&str> = r.sortie.lines().collect();
            attendu.sort_unstable();
            // Une base dans un format qu'on ne lit pas (xz, bzip2…) rend None, et pacman -Qmq prend le relais : c'est
            // prévu. Une base en gzip, en zstd ou en clair, elle, doit se lire.
            let lue = octets.starts_with(&[0x1f, 0x8b])
                || super::super::zstd::est_zstd(&octets)
                || octets.get(257..262) == Some(b"ustar");
            if !lue {
                assert_eq!(noms_base_sync(&octets), None, "{depot}");
                continue;
            }
            let mut noms = noms_base_sync(&octets).unwrap_or_else(|| panic!("{depot}.db illisible"));
            noms.sort();
            assert_eq!(noms, attendu, "{depot}");
        }
    }

    /// Sur cet ordinateur, les paquets étrangers lus en Rust sont ceux de « pacman -Qmq », quand la lecture native
    /// est possible (aucune base en xz) et que pacman est là.
    #[test]
    fn etrangers_comme_pacman_qm() {
        crate::autotest::croisees::essayer("AUT-LNX-003");
    }

    use super::*;

    #[test]
    fn dnf_automatic_qui_installe() {
        let telecharge = "[commands]\nupgrade_type = security\napply_updates = no\n";
        let installe = "[commands]\napply_updates = yes\n";
        assert!(!juger_dnf_auto(false, true, telecharge));
        assert!(!juger_dnf_auto(false, true, ""));
        assert!(juger_dnf_auto(false, true, installe));
        assert!(juger_dnf_auto(true, false, ""));
        assert!(!juger_dnf_auto(false, false, installe));
        // Une autre section ne compte pas.
        assert!(!juger_dnf_auto(false, true, "[emitters]\napply_updates = yes\n"));
    }

    #[test]
    fn paquets_sensibles() {
        assert!(paquet_sensible(Paquets::Pacman, "linux 7.2.5.arch1-1 -> 7.2.6.arch1-1"));
        assert!(paquet_sensible(Paquets::Dnf, "kernel.x86_64 6.11.4-301.fc41 updates"));
        assert!(paquet_sensible(
            Paquets::Zypper,
            "v | Main Update Repository | kernel-default | 6.11.1-1.1 | 6.11.2-1.1 | x86_64"
        ));
        assert!(!paquet_sensible(
            Paquets::Zypper,
            "v | Main Update Repository | vim | 9.1.0-1.1 | 9.1.1-1.1 | x86_64"
        ));
        assert!(!paquet_sensible(
            Paquets::Apt,
            "vim/noble-updates 2:9.1 amd64 [upgradable from: 2:9.0]"
        ));
    }

    #[test]
    fn modules_dkms_par_noyau() {
        let noyaux = ["7.2.5-arch1".to_string(), "7.3.0-arch1".to_string()];
        let status = "nvidia/610.57.04, 7.2.5-arch1, x86_64: installed\n\
                      nvidia/610.57.04, 7.3.0-arch1, x86_64: built\n\
                      hid-xpadneo/v0.10.4, 7.2.5-arch1, x86_64: installed\n\
                      hid-xpadneo/v0.10.4, 7.3.0-arch1, x86_64: installed (WARNING! Diff between built and installed module!)\n\
                      vboxhost/7.1: added\n\
                      ancien, 1.0, 7.2.5-arch1, x86_64: installed\n";
        assert_eq!(
            dkms_manquants(status, &noyaux),
            [
                ("nvidia".to_string(), vec!["7.3.0-arch1".to_string()]),
                ("hid-xpadneo".to_string(), vec![]),
                ("vboxhost".to_string(), noyaux.to_vec()),
                ("ancien".to_string(), vec!["7.3.0-arch1".to_string()]),
            ]
        );
    }

    #[test]
    fn arbre_de_dkms() {
        let racine = std::env::temp_dir().join(format!("vanguard-dkms-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&racine);
        let dossier = |c: &str| std::fs::create_dir_all(racine.join(c)).unwrap();
        dossier("nvidia/610.57/source");
        dossier("nvidia/610.57/7.2.5-arch1/x86_64/module");
        dossier("nvidia/610.57/7.3.0-arch1/x86_64/module");
        dossier("nvidia/original_module/7.2.5-arch1/x86_64");
        dossier("vboxhost/7.1/source");
        std::os::unix::fs::symlink(
            "610.57/7.2.5-arch1/x86_64",
            racine.join("nvidia/kernel-7.2.5-arch1-x86_64"),
        )
        .unwrap();
        std::fs::write(racine.join("mok.pub"), "clé publique").unwrap();
        let status = status_dkms_dans(&racine).unwrap();
        assert_eq!(
            status,
            "nvidia/610.57, 7.2.5-arch1, x86_64: installed\n\
             nvidia/610.57, 7.3.0-arch1, x86_64: built\n\
             vboxhost/7.1: added"
        );
        let noyaux = ["7.2.5-arch1".to_string(), "7.3.0-arch1".to_string()];
        assert_eq!(
            dkms_manquants(&status, &noyaux),
            [
                ("nvidia".to_string(), vec!["7.3.0-arch1".to_string()]),
                ("vboxhost".to_string(), noyaux.to_vec()),
            ]
        );
        assert!(status_dkms_dans(&racine.join("absent")).is_none());
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// Sur cet ordinateur, l'arbre de dkms donne les mêmes modules manquants que « dkms status », quand dkms est là.
    #[test]
    fn dkms_comme_dkms_status() {
        let Some(natif) = status_dkms_dans(Path::new(DKMS)) else {
            return crate::essais::saute("pas d'arbre dkms");
        };
        let Some(r) = crate::commande::lancer(Command::new("dkms").arg("status"), 60).filter(|r| r.code == Some(0))
        else {
            return crate::essais::saute("dkms absent");
        };
        let noyaux: Vec<String> = noyaux_installes()
            .iter()
            .filter_map(|p| Some(p.file_name()?.to_string_lossy().into_owned()))
            .collect();
        let trier = |mut v: Vec<(String, Vec<String>)>| {
            v.sort();
            v
        };
        assert_eq!(
            trier(dkms_manquants(&natif, &noyaux)),
            trier(dkms_manquants(&r.sortie, &noyaux)),
            "natif : {natif}\ndkms : {}",
            r.sortie
        );
    }

    #[test]
    fn versions_comparees_comme_pacman() {
        use std::cmp::Ordering::{Equal, Greater, Less};
        for (a, b, attendu) in [
            ("1.0-1", "1.0-1", Equal),
            ("1.0-1", "1.0-2", Less),
            ("1.0.1-1", "1.0-9", Greater),
            ("1:1.0-1", "2.0-1", Greater),
            ("0:2.0-1", "2.0-1", Equal),
            ("1.0a-1", "1.0-1", Less),
            ("1.0.a-1", "1.0.1-1", Less),
            ("1.0", "1.0-5", Equal),
            ("010", "10", Equal),
            ("1.0.r9.g54d9411-3", "1.0.r10.gabc-1", Less),
            ("2.0+git", "2.0", Greater),
            ("1..0", "1.0", Greater),
            // pacman ne connaît pas le tilde de Debian : ce qui reste après « 1.0 » gagne.
            ("1.0~rc1", "1.0", Greater),
            ("6.1.arch1-1", "6.1.arch2-1", Less),
        ] {
            assert_eq!(vercmp(a, b), attendu, "{a} {b}");
            assert_eq!(vercmp(b, a), attendu.reverse(), "{b} {a}");
        }
    }

    /// Sur cet ordinateur, les mêmes réponses que vercmp (le programme de pacman), quand il est là.
    #[test]
    fn versions_comme_vercmp() {
        let paires = [
            ("1.0-1", "1.0-2"),
            ("1:1.0", "2.0"),
            ("1.0a", "1.0"),
            ("1.0.a", "1.0.1"),
            ("1..0", "1.0"),
            ("1.0~rc1", "1.0"),
            ("2.0+git", "2.0"),
            ("7.1.0.r9.g54d9411-3", "7.1.0-1"),
            ("1.0alpha", "1.0.1"),
            ("1.0", "1.0-5"),
        ];
        for (a, b) in paires {
            let Some(r) = crate::commande::lancer(Command::new("vercmp").args([a, b]), 5).filter(|r| r.code == Some(0))
            else {
                return crate::essais::saute("vercmp absent");
            };
            let attendu = r.sortie.trim().parse::<i32>().unwrap().cmp(&0);
            assert_eq!(vercmp(a, b), attendu, "{a} {b}");
        }
    }

    #[test]
    fn paquets_aur_plus_recents() {
        let locales: HashMap<String, String> = [("yay", "12.4.2-1"), ("spotify", "1:1.2.3-1"), ("vieux", "1.0-1")]
            .into_iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        let fiches = serde_json::json!([
            {"Name": "yay", "Version": "12.5.0-1"},
            {"Name": "spotify", "Version": "1.9.9-1"},
            {"Name": "vieux", "Version": "1.0-1"},
            {"Name": "inconnu", "Version": "9-1"},
            {"Name": "sans-version"}
        ]);
        assert_eq!(plus_recents_dans_l_aur(&locales, fiches.as_array().unwrap()), 1);
    }

    /// Un appareil branché choisit le nom que fwupd rapporte : piégé, il arrive inoffensif dans le constat.
    #[test]
    fn firmware_d_un_appareil_piege() {
        let v = serde_json::json!({"Devices": [
            {"Name": "Souris\u{1b}]52;c;eA==\u{7}\u{1b}[2K\r\u{202e}", "Releases": [{"Version": "1.2"}]},
            {"Name": "Disque", "Releases": []}
        ]});
        assert_eq!(firmwares_proposes(&v), ["Souris�]52;c;eA==��[2K��"]);
    }

    /// GetDevices fabriqué : seuls les appareils qui se mettent à jour sont interrogés ; « rien à faire » n'est pas
    /// une erreur, toute autre réponse d'erreur l'est (jamais « à jour » sur une erreur).
    #[test]
    fn firmwares_par_fwupd_fabrique() {
        use dbus::Valeur as V;
        let p = |k: &str, v: V| (V::texte_de(k), V::Variante(String::new(), Box::new(v)));
        let liste = V::Tableau(vec![
            V::Dictionnaire(vec![
                p("DeviceId", V::texte_de("a1")),
                p("Name", V::texte_de("SSD")),
                p("Flags", V::U64(APPAREIL_MAJ | 1)),
            ]),
            V::Dictionnaire(vec![p("DeviceId", V::texte_de("b2")), p("Flags", V::U64(1))]),
            V::Dictionnaire(vec![p("DeviceId", V::U32(3)), p("Flags", V::U64(APPAREIL_MAJ))]),
        ]);
        assert_eq!(appareils_a_jour(&liste), [("a1".to_string(), "SSD".to_string())]);
        let erreur = |e: &str| Err(e.to_string());
        assert_eq!(
            reponse_upgrades(erreur("org.freedesktop.fwupd.NothingToDo : No releases found")),
            Ok(false)
        );
        assert!(reponse_upgrades(erreur("org.freedesktop.fwupd.Internal : boom")).is_err());
        assert!(reponse_upgrades(erreur("org.freedesktop.fwupd.NotSupported : no components in silo")).is_err());
        assert_eq!(
            reponse_upgrades(erreur("org.freedesktop.fwupd.NotFound : gone")),
            Ok(false)
        );
        assert!(reponse_upgrades(erreur("le bus n'a pas répondu à temps")).is_err());
        assert_eq!(reponse_upgrades(Ok(vec![V::Tableau(Vec::new())])), Ok(false));
        assert_eq!(
            reponse_upgrades(Ok(vec![V::Tableau(vec![V::Dictionnaire(Vec::new())])])),
            Ok(true)
        );
    }

    /// L'oracle : les firmwares proposés par D-Bus contre `fwupdmgr get-updates --json`, sur cet ordinateur (des
    /// nombres seulement dans le message).
    #[test]
    fn firmwares_par_dbus_comme_fwupdmgr() {
        let natif = match firmwares_par_dbus() {
            Ok(n) => n,
            Err(e) => return crate::essais::saute(&format!("fwupd injoignable ({e})")),
        };
        let Some(json) = sortie_delai(
            "fwupdmgr",
            &["get-updates", "--json", "--no-unreported-check"],
            60,
            &[0, 2],
        )
        .and_then(|j| serde_json::from_str::<serde_json::Value>(&j).ok()) else {
            return crate::essais::saute("fwupdmgr absent, muet ou sans métadonnées");
        };
        let mut outil = firmwares_proposes(&json);
        let mut lus = natif;
        outil.sort();
        lus.sort();
        assert!(lus == outil, "{} par D-Bus, {} par fwupdmgr", lus.len(), outil.len());
    }

    #[test]
    fn noms_encodes_pour_l_aur() {
        assert_eq!(encoder_url("aewm++"), "aewm%2B%2B");
        assert_eq!(encoder_url("python-foo_bar.1"), "python-foo_bar.1");
        assert_eq!(encoder_url("a@b"), "a%40b");
    }

    #[test]
    fn suivi_aur() {
        let reponse = serde_json::json!({"results": [
            {"Name": "nextdns-bin", "Maintainer": "quelquun"},
            {"Name": "vieux-outil", "Maintainer": null}
        ]});
        let (absents, orphelins) = etat_aur(&["nextdns-bin", "vieux-outil", "fait-maison"], &reponse);
        assert_eq!(absents, vec!["fait-maison"]);
        assert_eq!(orphelins, vec!["vieux-outil"]);
    }

    #[test]
    fn failles_des_distributions() {
        let arch = serde_json::json!([
            {"packages": ["openssl", "lib32-openssl"], "severity": "High", "fixed": "3.5.1-1", "status": "Fixed"},
            {"packages": ["pam"], "severity": "High", "fixed": null, "status": "Vulnerable"},
            {"packages": ["lua51"], "severity": "Low", "fixed": null}
        ]);
        let f = failles_arch(&arch);
        assert_eq!(f.len(), 4);
        assert!(f[0].corrigee && f[0].gravite == Niveau::Eleve && f[1].paquet == "lib32-openssl");
        assert!(!f[2].corrigee && f[3].gravite == Niveau::Info);

        let apt = [
            "libssl3t64/noble-updates,noble-security 3.0.13-0ubuntu3.4 amd64 [upgradable from: 3.0.13-0ubuntu3.1]",
            "firefox/noble-updates 1:1snap1 amd64 [upgradable from: 1:1snap0]",
            "openssl/stable-security 3.0.15-1~deb12u1 amd64 [upgradable from: 3.0.14-1~deb12u2]",
        ]
        .map(String::from);
        let noms: Vec<String> = failles_apt(&apt).into_iter().map(|f| f.paquet).collect();
        assert_eq!(noms, ["libssl3t64", "openssl"]);

        let dnf4 = "FEDORA-2024-1a2b Important/Sec. curl-8.6.0-7.fc40.x86_64\nFEDORA-2024-9f9f bugfix   bash-5.2-1.fc40.x86_64\n";
        assert_eq!(
            failles_dnf(dnf4),
            [Faille {
                paquet: "curl".into(),
                gravite: Niveau::Eleve,
                corrigee: true,
                cves: Vec::new()
            }]
        );
        let dnf5 = "Name             Type     Severity  Package                         Issued\n\
                    FEDORA-2024-1a2b security Critical  python3-libs-3.12.4-1.fc40.x86_64 2024-04-01 00:43:20\n";
        let f = failles_dnf(dnf5);
        assert_eq!((f[0].paquet.as_str(), f[0].gravite), ("python3-libs", Niveau::Critique));

        let zypper = "Repository | Name                  | Category    | Severity  | Interactive | Status     | Summary\n\
                      -----------+-----------------------+-------------+-----------+-------------+------------+--------\n\
                      Update     | openSUSE-2024-123     | security    | important | ---         | needed     | openssl\n\
                      Update     | openSUSE-2024-124     | security    | low       | ---         | applied    | curl\n\
                      Update     | openSUSE-2024-125     | recommended | moderate  | ---         | needed     | vim\n";
        let f = failles_zypper(zypper);
        assert_eq!(f.len(), 1);
        assert_eq!(
            (f[0].paquet.as_str(), f[0].gravite),
            ("openSUSE-2024-123", Niveau::Eleve)
        );
    }

    #[test]
    fn bilan_des_failles() {
        let f = |paquet: &str, gravite, corrigee| Faille {
            paquet: paquet.into(),
            gravite,
            corrigee,
            cves: Vec::new(),
        };
        assert!(bilan_failles(Paquets::Pacman, &[]).probleme.is_none());
        // Faille sans correctif : signalée, sans baisser la note ni proposer de correction.
        let c = bilan_failles(Paquets::Pacman, &[f("pam", Niveau::Eleve, false)]);
        assert_eq!(c.probleme, Some(Niveau::Info));
        assert!(c.correctif.is_none() && c.message.contains("pam"));
        // La pire gravité des failles corrigées donne le niveau ; jamais moins que Moyen.
        let c = bilan_failles(
            Paquets::Dnf,
            &[
                f("curl", Niveau::Info, true),
                f("curl", Niveau::Critique, true),
                f("pam", Niveau::Eleve, false),
            ],
        );
        assert_eq!(c.probleme, Some(Niveau::Critique));
        assert!(c.message.starts_with("1 paquet(s)") && c.message.contains("pam") && c.correctif.is_some());
        assert_eq!(
            bilan_failles(Paquets::Apt, &[f("vim", Niveau::Info, true)]).probleme,
            Some(Niveau::Moyen)
        );
    }

    #[test]
    fn failles_exposees_en_tete() {
        let f = |paquet: &str, corrigee| Faille {
            paquet: paquet.into(),
            gravite: Niveau::Moyen,
            corrigee,
            cves: Vec::new(),
        };
        let failles = [f("php-fpm", true), f("libtiff", false)];
        let exposes: HashMap<String, u16> = [("php-fpm".to_string(), 9000), ("nginx".to_string(), 80)].into();
        assert_eq!(exposees(&failles, &exposes), ["php-fpm (port 9000)"]);
        let c = avec_exposees(bilan_failles(Paquets::Pacman, &failles), &failles, &exposes);
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(
            c.message
                .starts_with("Paquet dont un programme écoute sur le réseau : php-fpm (port 9000)")
                && c.correctif.is_some()
        );
        // Rien d'exposé : le constat ne change pas.
        let avant = bilan_failles(Paquets::Pacman, &failles);
        let c = avec_exposees(bilan_failles(Paquets::Pacman, &failles), &failles, &HashMap::new());
        assert_eq!((c.probleme, c.message), (avant.probleme, avant.message));
    }

    #[test]
    fn failles_exploitees_en_tete() {
        let php = Faille {
            paquet: "php".into(),
            gravite: Niveau::Eleve,
            corrigee: true,
            cves: vec!["CVE-2026-109618".into(), "CVE-2026-109619".into()],
        };
        let pam = Faille {
            paquet: "pam".into(),
            gravite: Niveau::Eleve,
            corrigee: false,
            cves: vec!["CVE-2025-6020".into()],
        };
        let failles = [php, pam];
        let kev: Kev = [(
            "CVE-2026-109618".to_string(),
            chrono::NaiveDate::from_ymd_opt(2026, 10, 21),
        )]
        .into();
        assert_eq!(
            exploitees(&failles, &kev),
            ["php (CVE-2026-109618, au catalogue depuis le 2026-10-21)"]
        );
        // Exploitée : critique, en tête, la correction gardée.
        let c = avec_exploitees(bilan_failles(Paquets::Pacman, &failles), &failles, Ok(kev));
        assert_eq!(c.probleme, Some(Niveau::Critique));
        assert!(
            c.message.starts_with("Activement exploitée")
                && c.message
                    .contains("php (CVE-2026-109618, au catalogue depuis le 2026-10-21)")
        );
        assert!(c.correctif.is_some());
        // Rien d'exploité : le constat ne change pas ; sans le catalogue : dit, sans changer le niveau.
        let avant = bilan_failles(Paquets::Pacman, &failles);
        let c = avec_exploitees(bilan_failles(Paquets::Pacman, &failles), &failles, Ok(Kev::default()));
        assert_eq!(
            (c.probleme, c.message.as_str()),
            (avant.probleme, avant.message.as_str())
        );
        let c = avec_exploitees(
            bilan_failles(Paquets::Pacman, &failles),
            &failles,
            Err("pas d'Internet ?".into()),
        );
        assert_eq!(c.probleme, avant.probleme);
        assert!(c.message.contains("pas vérifiées : pas d'Internet ?"));
    }
}

/// Les mises à jour de sécurité installées toutes seules : unattended-upgrades sous Debian et Ubuntu, dnf-automatic
/// sous Fedora. Ailleurs (Arch, openSUSE, systèmes atomiques), rien à dire : la mise à jour se fait autrement, ou
/// l'outil met déjà le système entier à jour. Une information, avec la commande pour l'activer.
/// dnf-automatic installe-t-il vraiment ? Le minuteur « -install » toujours ; le minuteur ordinaire seulement si
/// automatic.conf dit « apply_updates = yes » dans [commands] (sinon il télécharge, sans rien installer : le réglage
/// livré par Fedora).
pub(super) fn juger_dnf_auto(minuteur_install: bool, minuteur: bool, conf: &str) -> bool {
    minuteur_install
        || (minuteur
            && super::valeur_ini(conf, |s| s == "commands", "apply_updates")
                .is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "yes" | "true" | "1" | "on")))
}

pub(super) fn maj_automatiques() -> Option<Constat> {
    if atomique().is_some() {
        return None;
    }
    let apt = std::path::Path::new("/usr/bin/apt-get").exists();
    let dnf = std::path::Path::new("/usr/bin/dnf").exists();
    let actives = if apt {
        // L'ordre d'APT : apt.conf.d trié, puis apt.conf ; la dernière valeur l'emporte.
        let mut fichiers: Vec<std::path::PathBuf> = std::fs::read_dir("/etc/apt/apt.conf.d")
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .collect();
        fichiers.sort();
        fichiers.push("/etc/apt/apt.conf".into());
        let conf = fichiers
            .iter()
            .filter_map(|p| std::fs::read_to_string(p).ok())
            .collect::<Vec<_>>()
            .join("\n");
        juger_apt_auto(&conf, std::path::Path::new("/usr/bin/unattended-upgrade").exists())
    } else if dnf {
        // Les liens d'activation se lisent dans /etc/systemd ; systemctl seulement sans dossier de systemd.
        let actif = |t: &str| {
            natif::unite_activee(t, false)
                .unwrap_or_else(|| sortie("systemctl", &["is-enabled", t]).is_some_and(|s| s.trim() == "enabled"))
        };
        let conf = ["/etc/dnf/automatic.conf", "/etc/dnf/dnf5-plugins/automatic.conf"]
            .iter()
            .filter_map(|c| std::fs::read_to_string(c).ok())
            .collect::<Vec<_>>()
            .join("\n");
        juger_dnf_auto(
            actif("dnf-automatic-install.timer"),
            actif("dnf-automatic.timer") || actif("dnf5-automatic.timer"),
            &conf,
        )
    } else {
        return None;
    };
    Some(if actives {
        ok(
            "Mises à jour",
            tr!(
                "Les mises à jour de sécurité s'installent toutes seules.",
                "Security updates install by themselves."
            ),
        )
    } else if apt {
        alerte(
            "Mises à jour",
            Niveau::Info,
            tr!(
                "Les mises à jour de sécurité ne s'installent pas toutes seules : une faille corrigée reste ouverte ici jusqu'à la prochaine mise à jour faite à la main.",
                "Security updates do not install by themselves: a fixed flaw stays open here until the next update done by hand."
            ),
        )
        .manuel(
            tr!(
                "Activer les mises à jour de sécurité automatiques (unattended-upgrades)",
                "Turn on automatic security updates (unattended-upgrades)"
            ),
            &["sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades"],
        )
    } else {
        alerte(
            "Mises à jour",
            Niveau::Info,
            tr!(
                "Les mises à jour de sécurité ne s'installent pas toutes seules : une faille corrigée reste ouverte ici jusqu'à la prochaine mise à jour faite à la main.",
                "Security updates do not install by themselves: a fixed flaw stays open here until the next update done by hand."
            ),
        )
        .manuel(
            tr!(
                "Activer dnf-automatic en mode installation (le minuteur ordinaire ne fait que télécharger) : la commande ci-dessous jusqu'à Fedora 40 ; à partir de Fedora 41 (dnf5), « apply_updates = yes » dans la section [commands] de /etc/dnf/automatic.conf, puis sudo systemctl enable --now dnf5-automatic.timer",
                "Turn on dnf-automatic in install mode (the plain timer only downloads): the command below up to Fedora 40; from Fedora 41 (dnf5), “apply_updates = yes” in the [commands] section of /etc/dnf/automatic.conf, then sudo systemctl enable --now dnf5-automatic.timer"
            ),
            &["sudo dnf install dnf-automatic && sudo systemctl enable --now dnf-automatic-install.timer"],
        )
    })
}

/// apt : `APT::Periodic::Unattended-Upgrade "1";` dans la configuration, et l'outil installé.
fn juger_apt_auto(conf: &str, outil: bool) -> bool {
    // La dernière valeur l'emporte : un « 0 » dans un fichier lu après annule un « 1 » d'avant.
    outil
        && conf
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with("//") && l.starts_with("APT::Periodic::Unattended-Upgrade"))
            .filter_map(|l| l.split('"').nth(1))
            .next_back()
            .is_some_and(|v| v.trim() != "0")
}

#[cfg(test)]
mod tests_maj_automatiques {
    use super::*;

    #[test]
    fn configuration_d_apt() {
        let actif = "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n";
        assert!(juger_apt_auto(actif, true));
        assert!(!juger_apt_auto(actif, false));
        assert!(!juger_apt_auto("APT::Periodic::Unattended-Upgrade \"0\";\n", true));
        assert!(!juger_apt_auto("// APT::Periodic::Unattended-Upgrade \"1\";\n", true));
        assert!(!juger_apt_auto("", true));
        // Annulé par un fichier lu après ; réactivé encore après.
        assert!(!juger_apt_auto(
            "APT::Periodic::Unattended-Upgrade \"1\";\nAPT::Periodic::Unattended-Upgrade \"0\";\n",
            true
        ));
        assert!(juger_apt_auto(
            "APT::Periodic::Unattended-Upgrade \"0\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n",
            true
        ));
    }
}

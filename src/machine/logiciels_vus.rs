//! Les logiciels installés, gardés d'un bilan à l'autre sur cet ordinateur (logiciels-vus.json, scellé) : un
//! logiciel apparu depuis le bilan d'avant se signale pendant une semaine. C'est ainsi qu'on repère un logiciel
//! espion ou un programme installé à son insu (souvent par un autre installateur). L'inventaire ne quitte jamais
//! l'ordinateur : il reste dans le dossier de Vanguard, jamais envoyé ni noté au journal des erreurs.
//!
//! Ce qui est lu : sous Windows, le panneau « Applications installées » (machine et ce compte ; pas les autres
//! sessions ouvertes, qui vont et viennent : leurs logiciels reviendraient « nouveaux » à chaque reconnexion) ;
//! sous Linux, les paquets (pacman, dpkg, rpm en secours) et les applications Flatpak ; sous macOS, les applications
//! de /Applications et ~/Applications. Une source qui ne se lit pas rend tout le bilan non vérifié : une liste sans
//! elle oublierait ses logiciels, qui reviendraient ensuite comme nouveaux. Ceux du premier passage sont connus
//! d'avant. La surveillance horaire voit l'alerte apparaître comme tout nouveau problème.
//!
//! Chaque logiciel est gardé sous une clé sans ses numéros de version (« Outil # (x64) ») : sous Windows, le nom
//! affiché en contient souvent un, et chaque mise à jour serait prise pour une nouvelle installation.

use std::collections::{BTreeMap, BTreeSet};

use chrono::NaiveDate;

use super::{Constat, alerte, impossible_par, ok};
use crate::modele::{Objet, Raison};
use crate::risk::Niveau;
use crate::ui::{affichable, resume};
use crate::{tr, trf};

const CAT: &str = "Logiciels";
/// Combien de jours un logiciel arrivé reste signalé : le bilan d'une semaine plus tard le voit encore, même si la
/// surveillance horaire a fait plusieurs bilans entre-temps.
const RECENT_JOURS: i64 = 7;
/// Au-delà, ce n'est pas un inventaire d'ordinateur : rien n'est gardé (le sceau refuserait le fichier).
const LOGICIELS_MAX: usize = 20_000;

#[derive(serde::Serialize, serde::Deserialize, Default, Debug, PartialEq, Eq, Clone)]
struct Vu {
    /// La première fois vu (« AAAA-MM-JJ ») ; vide pour ceux du premier passage.
    #[serde(default)]
    date: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    version: String,
    /// Le nom tel qu'affiché la dernière fois, quand il diffère de la clé (il contient une version).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    nom: String,
}

/// La clé d'un logiciel : son nom sans les mots qui ne sont qu'une version (« 566.36 », « v2.1 », « (24.08) »),
/// pour qu'une mise à jour qui change le nom affiché ne passe pas pour une installation. Seuls les mots entiers
/// changent : « python3 » ou « 7-Zip » restent tels quels (un paquet Linux n'a pas d'espace dans son nom).
fn cle(nom: &str) -> String {
    nom.split(' ')
        .map(|mot| {
            let coeur = mot.trim_matches(|c| matches!(c, '(' | ')' | '[' | ']' | ','));
            let chiffres = coeur.strip_prefix(['v', 'V']).unwrap_or(coeur);
            if chiffres.starts_with(|c: char| c.is_ascii_digit())
                && chiffres.chars().all(|c| c.is_ascii_digit() || c == '.')
            {
                mot.replacen(coeur, "#", 1)
            } else {
                mot.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(serde::Serialize, serde::Deserialize, Default, Debug, PartialEq, Eq)]
struct Vus {
    logiciels: BTreeMap<String, Vu>,
}

/// Au-delà de tant de clés sans nom affiché dans le panneau, la liste n'est pas normale (une vraie en a quelques
/// dizaines) : elle est dite non vérifiée plutôt que crue entière.
#[cfg(windows)]
const SANS_NOM_MAX: usize = 1000;

/// Ce qui a été lu : (nom, version, vide si inconnue), et pourquoi la liste n'est pas entière quand une borne de
/// lecture a été atteinte (sous-clés, entrées d'un dossier). Une liste coupée n'est jamais jugée : ce qui manque
/// serait oublié, puis redit « nouveau », et un programme caché derrière la borne ne serait jamais vu.
struct Lu {
    logiciels: Vec<(String, String)>,
    coupe: Option<String>,
}

/// Les logiciels installés ; `None` : la liste ne se lit pas.
#[cfg(windows)]
fn lire() -> Option<Lu> {
    // Le panneau de la machine qui ne s'ouvre pas : aucune lecture ne vaut (`installes::noms` le dit de même).
    super::windows::installes::noms()?;
    let (programmes, laisses) = super::windows::installes::programmes_et_laisses();
    Some(Lu {
        logiciels: stables(programmes),
        coupe: coupe_stable(&laisses),
    })
}

/// Pourquoi la lecture de la machine et de ce compte n'est pas entière (les autres sessions ne comptent pas, comme
/// dans `stables`) : une clé coupée à sa borne, ou trop de clés sans nom affiché.
#[cfg(windows)]
fn coupe_stable(laisses: &super::windows::installes::Laisses) -> Option<String> {
    use super::windows::installes::Portee;
    let stable = |p: &Portee| !matches!(p, Portee::Compte(_));
    if let Some((_, cle)) = laisses.coupees.iter().find(|(p, _)| stable(p)) {
        return Some(trf!("trop de sous-clés dans {cle}", "too many subkeys in {cle}"));
    }
    let sans_nom: usize = laisses.sans_nom.iter().filter(|(p, _)| stable(p)).map(|(_, n)| n).sum();
    (sans_nom > SANS_NOM_MAX).then(|| {
        trf!(
            "{sans_nom} clés sans nom affiché",
            "{sans_nom} keys without a display name"
        )
    })
}

/// Ceux de la machine et de ce compte : les ruches des autres sessions ne sont lues que pendant qu'elles sont
/// ouvertes, et leurs logiciels seraient oubliés à chaque déconnexion, puis redits « nouveaux ».
#[cfg(windows)]
fn stables(programmes: Vec<super::windows::installes::Programme>) -> Vec<(String, String)> {
    use super::windows::installes::Portee;
    programmes
        .into_iter()
        .filter(|p| !matches!(p.portee, Portee::Compte(_)))
        .map(|p| (p.nom, p.version))
        .collect()
}

#[cfg(target_os = "linux")]
fn lire() -> Option<Lu> {
    use super::linux::natif;
    let rpm = || {
        let r = crate::commande::lancer(
            std::process::Command::new("rpm").args(["-qa", "--qf", "%{NAME} %{VERSION}\\n"]),
            60,
        )?;
        (r.code == Some(0)).then(|| {
            r.sortie
                .lines()
                .filter_map(|l| l.split_once(' '))
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect::<Vec<_>>()
        })
    };
    let l = natif::paquets_pacman().or_else(natif::paquets_dpkg).or_else(rpm)?;
    let logiciels = avec_flatpak(
        l,
        super::linux::paquets::applications_flatpak(),
        natif::present("flatpak"),
    )?;
    Some(Lu { logiciels, coupe: None })
}

/// Les paquets et les applications Flatpak. Flatpak installé mais muet (`flatpak list` en échec, trop lent) : rien
/// ne vaut lecture, car une liste sans ses applications les ferait oublier, puis revenir comme « nouvelles ».
#[cfg(target_os = "linux")]
fn avec_flatpak(
    mut l: Vec<(String, String)>,
    apps: Option<Vec<String>>,
    flatpak_present: bool,
) -> Option<Vec<(String, String)>> {
    match apps {
        Some(apps) => l.extend(apps.into_iter().map(|id| (format!("flatpak:{id}"), String::new()))),
        None if flatpak_present => return None,
        None => {}
    }
    Some(l)
}

/// Entrées lues au plus par dossier d'applications.
#[cfg(target_os = "macos")]
const ENTREES_MAX: usize = 5_000;

#[cfg(target_os = "macos")]
fn lire() -> Option<Lu> {
    use std::path::PathBuf;
    let version = |app: &std::path::Path| match crate::plist::lire_fichier(&app.join("Contents/Info.plist")) {
        Ok(crate::plist::Lu::Plist(v)) => v
            .cle("CFBundleShortVersionString")
            .and_then(crate::plist::Valeur::texte)
            .unwrap_or_default()
            .to_string(),
        _ => String::new(),
    };
    let dossiers = [
        PathBuf::from("/Applications"),
        PathBuf::from("/Applications/Utilities"),
        crate::socle::maison().join("Applications"),
    ];
    // /Applications illisible : rien ne vaut lecture. Un autre dossier là mais illisible non plus : ses applications
    // seraient oubliées, puis redites « nouvelles ».
    std::fs::read_dir(&dossiers[0]).ok()?;
    let mut l = Vec::new();
    let mut coupe = None;
    for d in &dossiers {
        let entrees = match std::fs::read_dir(d) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        };
        // Une entrée de plus que la borne est demandée pour savoir qu'elle est atteinte : la liste est alors dite
        // coupée, jamais prise pour entière.
        let mut n = 0;
        for e in entrees.flatten() {
            n += 1;
            if n > ENTREES_MAX {
                coupe = Some(trf!(
                    "plus de {ENTREES_MAX} entrées dans {}",
                    "more than {ENTREES_MAX} entries in {}",
                    affichable(&d.to_string_lossy())
                ));
                break;
            }
            let p = e.path();
            if p.extension().is_some_and(|x| x == "app") {
                let nom = p
                    .file_stem()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                l.push((nom, version(&p)));
            }
        }
    }
    Some(Lu { logiciels: l, coupe })
}

fn juger(lus: &[(String, String)], avant: Option<&Vus>, aujourd_hui: NaiveDate) -> (Constat, Vus) {
    // Les clés d'avant repassées par `cle` : un inventaire écrit avec les noms entiers ne fait pas redire « nouveau »
    // chaque nom qui contient une version. Deux anciens noms sur la même clé : la date la plus ancienne (vide, celle
    // du premier passage, passe avant toute autre).
    let mut vus: BTreeMap<String, Vu> = BTreeMap::new();
    for (nom, vu) in avant.iter().flat_map(|a| &a.logiciels) {
        let k = cle(nom);
        if vus.get(&k).is_some_and(|v| v.date <= vu.date) {
            continue;
        }
        let mut vu = vu.clone();
        if vu.nom.is_empty() && k != *nom {
            vu.nom.clone_from(nom);
        }
        vus.insert(k, vu);
    }
    // Un logiciel retiré est oublié : réinstallé plus tard, il se signale de nouveau. Une liste vide n'efface rien
    // (une lecture incomplète ferait signaler chacun comme nouveau au bilan suivant).
    if !lus.is_empty() {
        let presents: BTreeSet<String> = lus.iter().map(|(n, _)| cle(n)).collect();
        vus.retain(|k, _| presents.contains(k));
    }
    let date = if avant.is_some() {
        aujourd_hui.format("%Y-%m-%d").to_string()
    } else {
        String::new()
    };
    for (nom, version) in lus {
        let k = cle(nom);
        let affiche = if k == *nom { String::new() } else { nom.clone() };
        let vu = vus.entry(k).or_insert_with(|| Vu {
            date: date.clone(),
            ..Vu::default()
        });
        vu.version.clone_from(version);
        vu.nom = affiche;
    }
    let mut recents: Vec<(&String, &Vu)> = vus
        .iter()
        .filter(|(_, v)| {
            NaiveDate::parse_from_str(&v.date, "%Y-%m-%d").is_ok_and(|d| (aujourd_hui - d).num_days() < RECENT_JOURS)
        })
        .collect();
    recents.sort_by(|a, b| b.1.date.cmp(&a.1.date).then_with(|| a.0.cmp(b.0)));
    let constat = if avant.is_none() {
        ok(
            CAT,
            trf!(
                "Inventaire des logiciels noté sur cet ordinateur ({} logiciels) : les prochains bilans diront ceux qui arrivent.",
                "Software inventory recorded on this computer ({} programs): the next checks will tell which ones arrive.",
                vus.len()
            ),
        )
    } else if recents.is_empty() {
        ok(
            CAT,
            trf!(
                "Aucun nouveau logiciel installé depuis les bilans de la semaine ({} logiciels connus).",
                "No new software installed since this week's checks ({} known programs).",
                vus.len()
            ),
        )
    } else {
        let noms: Vec<String> = recents
            .iter()
            .map(|(k, v)| {
                let n = if v.nom.is_empty() { k.as_str() } else { v.nom.as_str() };
                if v.version.is_empty() {
                    affichable(n)
                } else {
                    format!("{} {}", affichable(n), affichable(&v.version))
                }
            })
            .collect();
        let mut cles: Vec<&str> = recents.iter().map(|(n, _)| n.as_str()).collect();
        cles.sort_unstable();
        alerte(
            CAT,
            Niveau::Info,
            trf!(
                "Nouveau logiciel installé depuis le dernier bilan (cette semaine) : {}. Si vous ne reconnaissez pas l'un d'eux, cherchez d'où il vient avant de vous en servir : un logiciel espion s'installe souvent ainsi, ou avec un autre programme.",
                "New software installed since the last check (this week): {}. If you do not recognize one of them, find out where it comes from before using it: stalkerware often gets installed this way, or along with another program.",
                resume(&noms, 8, ", ")
            ),
        )
        // Les logiciels arrivés eux-mêmes : un autre qui arrive plus tard est un autre objet.
        .avec_objet(Objet::de("logiciels", &cles.join(",")))
        .manuel(
            tr!(
                "S'il n'est pas à vous : le désinstaller, puis lancer l'antivirus et « Logiciels espions : en ai-je un ? »",
                "If it is not yours: uninstall it, then run the antivirus and “Stalkerware: do I have one?”"
            ),
            &[],
        )
    };
    (constat, Vus { logiciels: vus })
}

/// L'inventaire d'avant selon la lecture de son fichier, et s'il a été changé hors de Vanguard. `None` : premier
/// passage, ce qui est là est connu d'avant.
fn depart(lecture: crate::sceau::Juge) -> (Option<Vus>, bool) {
    use crate::sceau::{Doute, Juge};
    match lecture {
        // Scellé mais qui ne se relit pas : un état vide aussi, pas un premier passage qui tairait tout.
        Juge::Cru(o) => (Some(serde_json::from_slice::<Vus>(&o).unwrap_or_default()), false),
        // Le seul vrai premier passage : ce qui est là est connu d'avant.
        Juge::Absent => (None, false),
        // Les sceaux refaits sans lui (peut-être effacé pour taire un nouveau venu), ou avec lui accepté tel quel (un
        // nouveau venu inscrit d'avance) : un état vide, jamais un premier passage ; tout ce qui est installé est daté
        // du jour et redit, et le bilan dit les sceaux refaits.
        Juge::Douteux(Doute::Inconnu | Doute::Adopte, _) => (Some(Vus::default()), false),
        // Falsifié ou illisible : rien n'est cru, et rien n'est tu non plus.
        Juge::Douteux(Doute::HorsVanguard, _) | Juge::Illisible(_) => (Some(Vus::default()), true),
    }
}

/// COM-LOG-001.
pub fn constat() -> Constat {
    constat_de(lire())
}

fn constat_de(lu: Option<Lu>) -> Constat {
    let Some(Lu {
        logiciels: mut lus,
        coupe,
    }) = lu
    else {
        return impossible_par(
            CAT,
            Raison::Illisible(tr!("liste des logiciels installés", "list of installed software").into()),
            tr!(
                "Impossible de vérifier les logiciels arrivés depuis le dernier bilan : la liste des logiciels installés ne se lit pas.",
                "Could not check the software that arrived since the last check: the list of installed software cannot be read."
            ),
        );
    };
    lus.sort();
    lus.dedup_by(|a, b| a.0 == b.0);
    // Une borne atteinte : non vérifié, et l'inventaire gardé n'est pas touché. Tronquée en silence, la liste
    // oubliait ce qui dépassait (redit « nouveau » ensuite), et un programme caché derrière la borne n'était jamais vu.
    let coupe = coupe.or_else(|| {
        (lus.len() > LOGICIELS_MAX).then(|| {
            trf!(
                "plus de {LOGICIELS_MAX} logiciels",
                "more than {LOGICIELS_MAX} programs"
            )
        })
    });
    if let Some(raison) = coupe {
        return impossible_par(
            CAT,
            Raison::Illisible(trf!("liste tronquée : {raison}", "list truncated: {raison}")),
            trf!(
                "Impossible de dire quels logiciels sont arrivés : la liste des logiciels installés n'a pas pu être lue en entier ({raison}).",
                "Could not tell which software arrived: the list of installed software could not be read in full ({raison})."
            ),
        );
    }
    let (avant, falsifie) = depart(crate::sceau::juge(crate::sceau::LOGICIELS));
    let (c, apres) = juger(&lus, avant.as_ref(), chrono::Local::now().date_naive());
    if avant.as_ref() != Some(&apres)
        && let Ok(texte) = serde_json::to_vec(&apres)
    {
        let _ = std::fs::create_dir_all(crate::socle::dossier_local());
        let _ = crate::sceau::ecrire(crate::sceau::LOGICIELS, texte);
    }
    if falsifie {
        // Réécrit hors de Vanguard (un programme qui s'y ajoute se cacherait) : rien n'est cru, l'inventaire repart.
        return impossible_par(
            CAT,
            Raison::Illisible(
                tr!(
                    "inventaire changé hors de Vanguard",
                    "inventory changed outside Vanguard"
                )
                .into(),
            ),
            tr!(
                "Impossible de dire quels logiciels sont arrivés : l'inventaire gardé a été changé hors de Vanguard. Il repart de ce qui est installé aujourd'hui.",
                "Could not tell which software arrived: the kept inventory was changed outside Vanguard. It starts again from what is installed today."
            ),
        );
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modele::Etat;

    fn jour(j: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 10, j).unwrap()
    }

    fn l(noms: &[(&str, &str)]) -> Vec<(String, String)> {
        noms.iter().map(|(n, v)| ((*n).to_string(), (*v).to_string())).collect()
    }

    #[test]
    fn premier_passage_puis_nouveau_logiciel() {
        let (c, vus) = juger(&l(&[("Firefox", "131.0"), ("7-Zip", "24.08")]), None, jour(1));
        assert_eq!(c.etat(), Etat::Sain);
        assert!(vus.logiciels.values().all(|v| v.date.is_empty()));
        // Rien de neuf, une mise à jour seulement : rien à signaler, la version suit.
        let (c, vus) = juger(&l(&[("Firefox", "132.0"), ("7-Zip", "24.08")]), Some(&vus), jour(2));
        assert_eq!(c.etat(), Etat::Sain);
        assert_eq!(vus.logiciels["Firefox"].version, "132.0");
        // Un logiciel arrive : signalé (information), avec sa version, la semaine durant.
        let (c, vus) = juger(
            &l(&[("Firefox", "132.0"), ("7-Zip", "24.08"), ("Moniteur Discret", "2.1")]),
            Some(&vus),
            jour(3),
        );
        assert_eq!(c.probleme, Some(Niveau::Info));
        assert!(c.message.contains("Moniteur Discret 2.1") && c.message.contains("depuis le dernier bilan"));
        assert_eq!(c.objet, Objet::de("logiciels", "Moniteur Discret"));
        assert!(c.coherent());
        let tout = l(&[("Firefox", "132.0"), ("7-Zip", "24.08"), ("Moniteur Discret", "2.1")]);
        let (c, vus) = juger(&tout, Some(&vus), jour(9));
        assert_eq!(c.probleme, Some(Niveau::Info), "encore signalé six jours après");
        let (c, _) = juger(&tout, Some(&vus), jour(10));
        assert_eq!(c.etat(), Etat::Sain, "plus après une semaine");
    }

    /// Inventaire effacé (sceaux refaits sans lui) : un état vide, pas un premier passage. Le logiciel installé
    /// entre-temps est redit, rien n'est tu.
    #[test]
    fn inventaire_efface_rien_n_est_tu() {
        let (c, vus) = juger(
            &l(&[("Moniteur Discret", "2.1"), ("vim", "9.1")]),
            Some(&Vus::default()),
            jour(1),
        );
        assert_eq!(c.probleme, Some(Niveau::Info));
        assert!(c.message.contains("Moniteur Discret"));
        assert!(vus.logiciels.values().all(|v| v.date == "2026-10-01"));
    }

    /// Une version dans le nom affiché (Windows) : la mise à jour n'est pas une installation, le nom suit.
    /// Seul un fichier vraiment absent fait un premier passage ; effacé (sceaux refaits sans lui), falsifié ou
    /// illisible, l'inventaire repart vide et tout ce qui est installé est redit.
    #[test]
    fn seul_l_absent_est_un_premier_passage() {
        use crate::sceau::{Doute, Juge};
        assert_eq!(depart(Juge::Absent), (None, false));
        assert_eq!(
            depart(Juge::Douteux(Doute::Inconnu, None)),
            (Some(Vus::default()), false)
        );
        assert_eq!(
            depart(Juge::Douteux(Doute::HorsVanguard, None)),
            (Some(Vus::default()), true)
        );
        assert_eq!(depart(Juge::Illisible("x".into())), (Some(Vus::default()), true));
        assert_eq!(depart(Juge::Cru(b"{".to_vec())), (Some(Vus::default()), false));
        // S2c : un inventaire accepté tel quel après des sceaux refaits ne tait aucun nouveau venu.
        let forge = br#"{"logiciels":{"moniteur":{"date":"2026-01-01"}}}"#.to_vec();
        assert_eq!(
            depart(Juge::Douteux(Doute::Adopte, Some(forge))),
            (Some(Vus::default()), false)
        );
    }

    #[test]
    fn version_dans_le_nom_pas_un_nouveau() {
        assert_eq!(cle("Outil 1.2 (x64)"), "Outil # (x64)");
        assert_eq!(cle("Python 3.12.1 (64-bit)"), "Python # (64-bit)");
        assert_eq!(cle("Pilote v566.36"), "Pilote #");
        assert_eq!(cle("Outil (24.08)"), "Outil (#)");
        assert_eq!(cle("7-Zip"), "7-Zip");
        assert_eq!(cle("python3"), "python3");
        let (_, vus) = juger(&l(&[("Outil 1.2 (x64)", "1.2")]), None, jour(1));
        let (c, vus) = juger(&l(&[("Outil 1.3 (x64)", "1.3")]), Some(&vus), jour(2));
        assert_eq!(c.etat(), Etat::Sain);
        assert_eq!(vus.logiciels["Outil # (x64)"].nom, "Outil 1.3 (x64)");
        // Un vrai nouveau s'affiche sous son nom, pas sous sa clé.
        let (c, _) = juger(
            &l(&[("Outil 1.3 (x64)", "1.3"), ("Moniteur 2.1", "")]),
            Some(&vus),
            jour(3),
        );
        assert!(
            c.message.contains("Moniteur 2.1") && !c.message.contains('#'),
            "{}",
            c.message
        );
        assert_eq!(c.objet, Objet::de("logiciels", "Moniteur #"));
    }

    /// Un inventaire écrit avant les clés : ses noms entiers sont repris sous leur clé, la plus ancienne date gardée.
    #[test]
    fn ancien_inventaire_repris_sous_ses_cles() {
        let ancien = Vus {
            logiciels: BTreeMap::from([
                ("Outil 1.2 (x64)".into(), Vu::default()),
                (
                    "Outil 1.1 (x64)".into(),
                    Vu {
                        date: "2026-09-01".into(),
                        ..Vu::default()
                    },
                ),
            ]),
        };
        let (c, vus) = juger(&l(&[("Outil 1.3 (x64)", "")]), Some(&ancien), jour(2));
        assert_eq!(c.etat(), Etat::Sain);
        assert_eq!(vus.logiciels.len(), 1);
        assert_eq!(vus.logiciels["Outil # (x64)"].date, "");
    }

    /// Flatpak installé mais muet : rien ne vaut lecture (ses applications seraient oubliées, puis redites
    /// nouvelles) ; sans Flatpak, les paquets seuls.
    #[cfg(target_os = "linux")]
    #[test]
    fn flatpak_muet_rien_ne_vaut_lecture() {
        assert_eq!(avec_flatpak(l(&[("vim", "9.1")]), None, true), None);
        assert_eq!(
            avec_flatpak(l(&[("vim", "9.1")]), None, false),
            Some(l(&[("vim", "9.1")]))
        );
        let lu = avec_flatpak(l(&[("vim", "9.1")]), Some(vec!["org.exemple.App".into()]), true).unwrap();
        assert!(lu.iter().any(|(n, _)| n == "flatpak:org.exemple.App"));
    }

    /// Les logiciels d'une autre session ouverte ne comptent pas : ils iraient et viendraient avec elle.
    #[cfg(windows)]
    #[test]
    fn autres_sessions_ignorees() {
        use super::super::windows::installes::{Portee, Programme};
        let p = |nom: &str, portee| Programme {
            nom: nom.into(),
            version: String::new(),
            editeur: String::new(),
            emplacement: None,
            portee,
            cle: String::new(),
        };
        let lus = stables(vec![
            p("Outil", Portee::Machine),
            p("Perso", Portee::CompteCourant),
            p("Chez bob", Portee::Compte("S-1-5-21-1-2-3-1002".into())),
        ]);
        assert_eq!(lus, l(&[("Outil", ""), ("Perso", "")]));
    }

    /// Une liste coupée à sa borne n'est jamais jugée ni gardée : non vérifié, jamais tronquée en silence (ce qui
    /// dépassait serait oublié, et un programme caché derrière la borne jamais vu).
    #[test]
    fn borne_atteinte_non_verifie() {
        let trop: Vec<(String, String)> = (0..=LOGICIELS_MAX)
            .map(|i| (format!("paquet-{i}"), String::new()))
            .collect();
        let c = constat_de(Some(Lu {
            logiciels: trop,
            coupe: None,
        }));
        assert!(matches!(c.etat(), Etat::NonVerifie(_)), "{:?}", c.etat());
        assert!(c.message.contains(&LOGICIELS_MAX.to_string()), "{}", c.message);
        let c = constat_de(Some(Lu {
            logiciels: l(&[("Firefox", "")]),
            coupe: Some("plus de 5000 entrées dans /Applications".into()),
        }));
        assert!(matches!(c.etat(), Etat::NonVerifie(_)), "{:?}", c.etat());
    }

    /// Sous Windows : une clé de la machine ou de ce compte coupée à sa borne, ou trop de clés sans nom affiché,
    /// rend la liste coupée ; celles d'une autre session ne comptent pas (comme `stables`).
    #[cfg(windows)]
    #[test]
    fn cles_coupees_ou_sans_nom() {
        use super::super::windows::installes::{Laisses, Portee};
        let mut laisses = Laisses::default();
        assert_eq!(coupe_stable(&laisses), None);
        laisses
            .coupees
            .push((Portee::Compte("S-1-5-21-1-2-3-1002".into()), "HKU".into()));
        laisses.sans_nom.push((Portee::Machine, 12));
        assert_eq!(coupe_stable(&laisses), None);
        laisses.coupees.push((Portee::CompteCourant, r"HKCU\Uninstall".into()));
        assert!(coupe_stable(&laisses).is_some());
        let beaucoup = Laisses {
            coupees: Vec::new(),
            sans_nom: vec![(Portee::Machine, SANS_NOM_MAX), (Portee::CompteCourant, 1)],
        };
        assert!(coupe_stable(&beaucoup).is_some());
    }

    #[test]
    fn retire_puis_remis_et_lecture_vide() {
        let (_, vus) = juger(&l(&[("Firefox", ""), ("Ancien", "")]), None, jour(1));
        // Une lecture vide n'efface rien : sinon tout reviendrait comme nouveau.
        let (_, vus) = juger(&[], Some(&vus), jour(2));
        assert_eq!(vus.logiciels.len(), 2);
        let (_, vus) = juger(&l(&[("Firefox", "")]), Some(&vus), jour(3));
        assert!(!vus.logiciels.contains_key("Ancien"));
        let (c, _) = juger(&l(&[("Firefox", ""), ("Ancien", "")]), Some(&vus), jour(4));
        assert_eq!(c.probleme, Some(Niveau::Info), "remis par quelqu'un : un nouveau");
    }

    /// Le fichier gardé : écrit scellé dans le dossier jetable des tests, relu au bilan suivant.
    #[test]
    fn inventaire_garde_et_relu() {
        let vus = Vus {
            logiciels: BTreeMap::from([(
                "Firefox".into(),
                Vu {
                    date: String::new(),
                    version: "131.0".into(),
                    nom: String::new(),
                },
            )]),
        };
        let texte = serde_json::to_vec(&vus).unwrap();
        let relu: Vus = serde_json::from_slice(&texte).unwrap();
        assert_eq!(relu, vus);
        // Champs manquants (version plus ancienne du fichier) : pris par défaut.
        let ancien: Vus = serde_json::from_str(r#"{"logiciels":{"Firefox":{}}}"#).unwrap();
        assert_eq!(ancien.logiciels["Firefox"], Vu::default());
    }
}

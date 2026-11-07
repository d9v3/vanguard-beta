//! Le verdict de chaque logiciel installé, une règle par produit (étude §6, contre-vérification §10) : à jour,
//! dépassé, branche finie, ou non vérifié avec sa raison. Rien n'est deviné : une source absente, une copie trop
//! vieille pour dire « à jour », un canal sans source fixe (Edge Extended Stable, Acrobat Classic) ou une
//! version d'une forme inconnue donnent « non vérifié », jamais « à jour ».
//!
//! Les fichiers sont lus une fois (`Faits::de`) ; les règles ne font ensuite aucune lecture, ce qui les rend
//! testables sur des faits inventés.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::collections::HashMap;
use std::time::Duration;

use chrono::{NaiveDate, NaiveDateTime};

use super::inventaire::{Branche, Installe, Plateforme};
use super::mozilla_avis::{self, BrancheFx};
use super::produits::{Distribution, Produit};
use super::sources::editeurs::{self, CanalOffice, EdgeStable, Firefox};
use super::sources::eol::{self, ProduitEol};
use super::sources::homebrew;
use super::sources::{A_JOUR_MAX, Lecteur, Releve, Systeme};
use super::version::{self, FormeJava, Version};
use crate::{tr, trf};

/// Un déploiement d'Edge prend quelques jours : une version publiée depuis moins longtemps n'est pas encore due.
const EDGE_DEPLOIEMENT: chrono::TimeDelta = chrono::TimeDelta::days(3);
/// Un déploiement d'Office (Click-to-Run) prend jusqu'à une semaine.
const OFFICE_DEPLOIEMENT: chrono::TimeDelta = chrono::TimeDelta::days(7);

/// Ce qu'une source a donné, et l'âge de la copie.
#[derive(Debug, Clone)]
pub(crate) struct Lu<T> {
    pub valeur: T,
    pub age: Duration,
}

/// Une source lue, ou pourquoi elle ne l'est pas.
pub(crate) type Fait<T> = Result<Lu<T>, String>;

/// Tout ce que les sources du système disent, lu une fois.
pub(crate) struct Faits {
    pub systeme: Systeme,
    pub maintenant: NaiveDateTime,
    pub firefox: Fait<Firefox>,
    /// (plateforme, canal, versions servies).
    pub chrome: Vec<(&'static str, &'static str, Fait<Vec<Version>>)>,
    pub edge: Fait<Vec<EdgeStable>>,
    pub office: Fait<Vec<CanalOffice>>,
    /// Les sources d'une seule version (Adobe, Brave, Slack), par identifiant de source.
    pub versions: Vec<(&'static str, Fait<Version>)>,
    pub eol: Fait<Vec<ProduitEol>>,
    /// Les versions des formules suivies de Homebrew (7-Zip, PuTTY), telles qu'écrites.
    pub formules: Fait<HashMap<String, String>>,
    pub avis: Fait<mozilla_avis::Index>,
}

/// La raison d'un fichier gardé qui ne se relit plus (il a pourtant passé la validation à sa réception).
fn illisible() -> String {
    tr!("copie illisible", "unreadable copy").to_string()
}

impl Faits {
    /// Les faits d'un relevé : chaque copie lue par son lecteur.
    pub(crate) fn de(releve: &Releve, systeme: Systeme, maintenant: NaiveDateTime) -> Faits {
        fn lire<T>(releve: &Releve, id: &str, f: impl Fn(&[u8]) -> Option<T>) -> Fait<T> {
            let copie = releve.copie(id)?;
            let valeur = f(&copie.octets).ok_or_else(illisible)?;
            Ok(Lu { valeur, age: copie.age })
        }
        let mut faits = Faits {
            systeme,
            maintenant,
            firefox: lire(releve, "mozilla", editeurs::firefox),
            chrome: Vec::new(),
            edge: lire(releve, "edge", editeurs::edge),
            office: lire(releve, "office", editeurs::office),
            versions: Vec::new(),
            eol: lire(releve, "eol", eol::lire),
            formules: lire(releve, "formules", homebrew::formules),
            avis: lire(releve, "mfsa", super::avis_de_l_archive),
        };
        for (source, _) in &releve.sources {
            let id = source.id;
            match source.lecteur {
                Lecteur::Chrome(p, c) => faits
                    .chrome
                    .push((p, c, lire(releve, id, |o| editeurs::chrome(o, p, c)))),
                Lecteur::Adobe => faits.versions.push((id, lire(releve, id, editeurs::adobe))),
                Lecteur::Brave => faits.versions.push((id, lire(releve, id, editeurs::brave))),
                Lecteur::Slack(p) => faits.versions.push((id, lire(releve, id, |o| editeurs::slack(o, p)))),
                _ => {}
            }
        }
        faits
    }

    fn version(&self, id: &str) -> Fait<Version> {
        self.versions.iter().find(|(i, _)| *i == id).map_or_else(
            || Err(tr!("source absente", "missing source").to_string()),
            |(_, f)| f.clone(),
        )
    }
}

/// Le verdict d'un logiciel installé.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Verdict {
    AJour {
        derniere: Version,
        source: &'static str,
    },
    /// Une version plus récente est publiée sur sa piste.
    Depassee {
        derniere: Version,
        source: &'static str,
    },
    /// Sa branche ne reçoit plus de correctifs (Java, un canal LTSC d'Office), depuis ce jour si on le sait.
    BrancheFinie {
        depuis: Option<NaiveDate>,
        source: &'static str,
    },
    /// La raison, prête à suivre « non vérifié : ».
    NonVerifie(String),
}

impl Verdict {
    /// Pour comparer deux verdicts : plus c'est grand, pire c'est.
    #[cfg(test)]
    fn gravite(&self) -> u8 {
        match self {
            Verdict::AJour { .. } => 0,
            Verdict::NonVerifie(_) => 1,
            Verdict::Depassee { .. } | Verdict::BrancheFinie { .. } => 2,
        }
    }
}

/// « À jour », seulement si la copie qui le dit n'a pas plus de trois jours.
fn a_jour(derniere: Version, source: &'static str, age: Duration) -> Verdict {
    if age > A_JOUR_MAX {
        return Verdict::NonVerifie(trf!(
            "copie de {} jours, trop vieille pour dire « à jour »",
            "{}-day-old copy, too old to say “up to date”",
            age.as_secs() / 86_400
        ));
    }
    Verdict::AJour { derniere, source }
}

/// Une raison de non-vérification préfixée du nom de la source.
fn sans_source(nom: &str, raison: &str) -> Verdict {
    Verdict::NonVerifie(trf!("{nom} : {raison}", "{nom}: {raison}"))
}

/// Le verdict de `i` d'après les faits.
pub(crate) fn juger(i: &Installe, f: &Faits) -> Verdict {
    let Some(v) = i.version else {
        return Verdict::NonVerifie(if i.brute.is_empty() {
            tr!("version illisible", "unreadable version").to_string()
        } else {
            trf!(
                "version « {} » d'une forme inconnue",
                "version “{}” of an unknown form",
                i.brute
            )
        });
    };
    match i.produit {
        Produit::Chrome => chrome(i, v, f),
        Produit::Edge => edge(i, v, f),
        Produit::Firefox => firefox(i, v, f),
        Produit::Brave => brave(i, v, f),
        Produit::Office => office(i, v, f),
        Produit::Acrobat | Produit::Reader => adobe(i, v, f),
        Produit::Java(d) => java(d, v, f),
        Produit::SevenZip => formule(v, f, "sevenzip"),
        Produit::PuTTY => formule(v, f, "putty"),
        Produit::Slack => simple(v, f.version("slack-windows"), "Slack"),
    }
}

/// 7-Zip et PuTTY : comparés à la version stable de leur formule de Homebrew, qui suit celle de l'amont (la même
/// que celle de Windows). Homebrew peut retarder de quelques jours : une version plus récente que la sienne est à jour.
fn formule(v: Version, f: &Faits, nom: &str) -> Verdict {
    const SOURCE: &str = "Homebrew";
    let lu = match &f.formules {
        Ok(lu) => lu,
        Err(raison) => return sans_source(SOURCE, raison),
    };
    let Some(texte) = lu.valeur.get(nom) else {
        return sans_source(SOURCE, &trf!("formule {nom} absente", "formula {nom} missing"));
    };
    let Some(derniere) = Version::lire(texte) else {
        return sans_source(
            SOURCE,
            &trf!(
                "version « {} » d'une forme inconnue",
                "version “{}” of an unknown form",
                crate::ui::affichable(texte)
            ),
        );
    };
    simple(
        v,
        Ok(Lu {
            valeur: derniere,
            age: lu.age,
        }),
        SOURCE,
    )
}

/// Edge Stable dont le canal est sûr : pas Extended Stable ni un autre canal réglé. L'Extended Stable reçoit les
/// correctifs sous d'autres numéros : une version Stable plus récente ne dit rien de lui.
fn edge_stable_sur(i: &Installe) -> bool {
    !matches!(&i.branche, Branche::Canal(c) if c != "stable")
}

/// Les Edge Stable de la plateforme d'un Edge installé (toutes les architectures du système si la sienne n'est pas
/// sue).
fn edge_de_sa_plateforme<'a>(i: &Installe, systeme: Systeme, stables: &'a [EdgeStable]) -> Vec<&'a EdgeStable> {
    let architecture = match i.plateforme {
        Plateforme::X86 => Some("x86"),
        Plateforme::X64 => Some("x64"),
        Plateforme::Arm64 => Some("arm64"),
        Plateforme::Inconnue => None,
    };
    stables
        .iter()
        .filter(|s| match systeme {
            Systeme::Windows => {
                s.plateforme == "Windows" && architecture.is_none_or(|a| s.architecture.eq_ignore_ascii_case(a))
            }
        })
        .collect()
}

/// Edge, faille par faille : chaque CVE de `exploitees` (catalogue de la CISA) dont le correctif, la plus ancienne
/// version Stable de sa plateforme que Microsoft dit la corriger, est plus récent que `v`. Le texte qui en est
/// tiré dit « antérieure au correctif », jamais « touchée » : on ne sait pas quand la faille est apparue. `Err` :
/// pourquoi ce n'est pas jugé (liste des CVE absente) ; la raison est vide quand le verdict de version dit déjà
/// tout (source absente, canal incertain).
pub(crate) fn failles_edge(
    i: &Installe,
    v: Version,
    f: &Faits,
    exploitees: &dyn Fn(&str) -> bool,
) -> Result<Vec<(String, Version)>, String> {
    // Sans la source, le verdict de version le dit déjà.
    let Ok(lu) = &f.edge else {
        return Err(String::new());
    };
    let stables = edge_de_sa_plateforme(i, f.systeme, &lu.valeur);
    if stables.is_empty() || !edge_stable_sur(i) {
        return Err(String::new());
    }
    // Le correctif d'une CVE est la plus ancienne version qui la cite : listée aussi par une version déjà installée
    // ou plus ancienne, elle est corrigée chez lui.
    let mut correctifs: Vec<(String, Version)> = Vec::new();
    let mut sans_liste = false;
    for c in stables.iter().flat_map(|s| &s.correctifs) {
        let Some(cves) = &c.cves else {
            sans_liste |= c.version > v;
            continue;
        };
        for cve in cves.iter().filter(|c| exploitees(c)) {
            match correctifs.iter_mut().find(|(x, _)| x == cve) {
                Some((_, z)) if *z <= c.version => {}
                Some((_, z)) => *z = c.version,
                None => correctifs.push((cve.clone(), c.version)),
            }
        }
    }
    let mut failles: Vec<(String, Version)> = correctifs.into_iter().filter(|(_, z)| *z > v).collect();
    if failles.is_empty() && sans_liste {
        return Err(tr!(
            "liste des failles corrigées absente de la source de Microsoft",
            "list of fixed flaws missing from Microsoft's source"
        )
        .to_string());
    }
    failles.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    Ok(failles)
}

/// Comparé à une seule version publiée.
fn simple(v: Version, fait: Fait<Version>, source: &'static str) -> Verdict {
    match fait {
        Ok(lu) if v >= lu.valeur => a_jour(lu.valeur, source, lu.age),
        Ok(lu) => Verdict::Depassee {
            derniere: lu.valeur,
            source,
        },
        Err(raison) => sans_source(source, &raison),
    }
}

/// Chrome : les versions servies de stable et d'extended pour sa plateforme (toutes celles du système si elle n'est
/// pas sue : la plus indulgente). À jour s'il atteint la plus haute, ou une version servie de son majeur (extended,
/// déploiement par étapes). Dépassé seulement si les deux canaux ont été lus : sinon un Chrome d'entreprise
/// (extended) serait dit dépassé à tort.
fn chrome(i: &Installe, v: Version, f: &Faits) -> Verdict {
    let plateformes: &[&str] = match (f.systeme, i.plateforme) {
        (Systeme::Windows, Plateforme::X86) => &["win"],
        (Systeme::Windows, Plateforme::X64) => &["win64"],
        (Systeme::Windows, Plateforme::Arm64) => &["win_arm64"],
        (Systeme::Windows, _) => &["win", "win64", "win_arm64"],
    };
    let (mut stable, mut extended, mut age) = (Vec::new(), Vec::new(), Duration::ZERO);
    let mut manque: Option<(&str, String)> = None;
    for (p, c, fait) in &f.chrome {
        if !plateformes.contains(p) {
            continue;
        }
        match fait {
            Ok(lu) => {
                age = age.max(lu.age);
                if *c == "stable" {
                    stable.extend(&lu.valeur);
                } else {
                    extended.extend(&lu.valeur);
                }
            }
            Err(raison) => manque = manque.or(Some((c, raison.clone()))),
        }
    }
    let servies: Vec<Version> = stable.iter().chain(&extended).copied().collect();
    let Some(&plus_haute) = servies.iter().max() else {
        return sans_source(
            "Google",
            &manque.map_or_else(
                || tr!("aucune version servie", "no version served").to_string(),
                |m| m.1,
            ),
        );
    };
    let du_majeur = servies.iter().filter(|s| s.majeur() == v.majeur() && v >= **s).max();
    if v >= plus_haute || du_majeur.is_some() {
        return a_jour(du_majeur.copied().unwrap_or(plus_haute), "Google", age);
    }
    match (stable.iter().max(), extended.is_empty(), manque) {
        (Some(&derniere), false, _) => Verdict::Depassee {
            derniere,
            source: "Google",
        },
        (_, _, Some((canal, raison))) => Verdict::NonVerifie(trf!(
            "canal {canal} de Chrome non lu : {raison}",
            "Chrome {canal} channel not read: {raison}"
        )),
        _ => sans_source(
            "Google",
            tr!("un canal ne sert aucune version", "a channel serves no version"),
        ),
    }
}

/// Edge : comparé au Stable de sa plateforme. Le canal Extended Stable n'a aucune source fixe ; un Stable publié il
/// y a moins de trois jours est encore en déploiement.
fn edge(i: &Installe, v: Version, f: &Faits) -> Verdict {
    match &i.branche {
        Branche::Canal(c) if c == "extended" => {
            return Verdict::NonVerifie(
                tr!(
                    "canal Extended Stable : aucune source fixe",
                    "Extended Stable channel: no fixed source"
                )
                .to_string(),
            );
        }
        Branche::Canal(c) if c != "stable" => {
            return Verdict::NonVerifie(trf!("canal {c} : non suivi", "{c} channel: not followed"));
        }
        _ => {}
    }
    let lu = match &f.edge {
        Ok(lu) => lu,
        Err(raison) => return sans_source("Microsoft", raison),
    };
    let stable = edge_de_sa_plateforme(i, f.systeme, &lu.valeur)
        .into_iter()
        .max_by_key(|s| s.version);
    let Some(stable) = stable else {
        return sans_source(
            "Microsoft",
            tr!("aucun Stable pour cette plateforme", "no Stable for this platform"),
        );
    };
    let derniere = stable.version;
    if v >= derniere {
        return a_jour(derniere, "Microsoft", lu.age);
    }
    let ecart = derniere.majeur().saturating_sub(v.majeur());
    let recente = stable
        .publiee
        .is_none_or(|p| f.maintenant.signed_duration_since(p) < EDGE_DEPLOIEMENT);
    if recente && ecart <= 1 {
        return Verdict::NonVerifie(trf!(
            "déploiement de la {derniere} en cours",
            "rollout of {derniere} in progress"
        ));
    }
    Verdict::Depassee {
        derniere,
        source: "Microsoft",
    }
}

/// La branche de Firefox : celle que `channel-prefs.js` dit, sinon ESR si son majeur est celui d'une ESR servie et
/// pas celui de la release ; sans la liste de Mozilla, inconnue. `Err` : un canal non suivi (bêta, Nightly).
pub(crate) fn branche_firefox(i: &Installe, v: Version, ff: Option<&Firefox>) -> Result<BrancheFx, String> {
    match &i.branche {
        Branche::Esr => Ok(BrancheFx::Esr(v.majeur())),
        Branche::Canal(c) => Err(c.clone()),
        Branche::Release | Branche::Classic => Ok(BrancheFx::Release),
        Branche::Inconnue => Ok(match ff {
            Some(f) if f.release.majeur() != v.majeur() && f.esr.iter().any(|e| e.majeur() == v.majeur()) => {
                BrancheFx::Esr(v.majeur())
            }
            Some(_) => BrancheFx::Release,
            None => BrancheFx::Inconnue,
        }),
    }
}

/// Firefox : la release comparée à `LATEST_FIREFOX_VERSION`, une ESR à l'ESR servie de son majeur ; une ESR finie
/// est dépassée par la plus récente.
fn firefox(i: &Installe, v: Version, f: &Faits) -> Verdict {
    let lu = match &f.firefox {
        Ok(lu) => lu,
        Err(raison) => return sans_source("Mozilla", raison),
    };
    let ff = &lu.valeur;
    match branche_firefox(i, v, Some(ff)) {
        Err(c) => Verdict::NonVerifie(trf!("canal {c} : non suivi", "{c} channel: not followed")),
        Ok(BrancheFx::Esr(m)) => {
            if let Some(&e) = ff.esr.iter().find(|e| e.majeur() == m) {
                return simple(v, Ok(Lu { valeur: e, age: lu.age }), "Mozilla");
            }
            match ff.esr.first() {
                Some(&recente) if recente.majeur() > m => Verdict::Depassee {
                    derniere: recente,
                    source: "Mozilla",
                },
                _ => Verdict::NonVerifie(trf!(
                    "branche ESR {m} inconnue de Mozilla",
                    "ESR branch {m} unknown to Mozilla"
                )),
            }
        }
        Ok(_) => simple(
            v,
            Ok(Lu {
                valeur: ff.release,
                age: lu.age,
            }),
            "Mozilla",
        ),
    }
}

/// Brave : la version publiée pour sa plateforme (les deux du système si elle n'est pas sue : la plus basse).
fn brave(i: &Installe, v: Version, f: &Faits) -> Verdict {
    let ids: &[&str] = match (f.systeme, i.plateforme) {
        (Systeme::Windows, Plateforme::X64) => &["brave-windows-x64"],
        (Systeme::Windows, Plateforme::Arm64) => &["brave-windows-arm64"],
        (Systeme::Windows, Plateforme::X86) => {
            return sans_source("Brave", tr!("aucune source pour 32 bits", "no source for 32-bit"));
        }
        (Systeme::Windows, _) => &["brave-windows-x64", "brave-windows-arm64"],
    };
    let mut lues: Vec<Lu<Version>> = Vec::new();
    let mut manque = None;
    for id in ids {
        match f.version(id) {
            Ok(lu) => lues.push(lu),
            Err(r) => manque = manque.or(Some(r)),
        }
    }
    let Some(plus_basse) = lues.iter().map(|l| l.valeur).min() else {
        return sans_source("Brave", &manque.unwrap_or_default());
    };
    let age = lues.iter().map(|l| l.age).max().unwrap_or_default();
    simple(
        v,
        Ok(Lu {
            valeur: plus_basse,
            age,
        }),
        "Brave",
    )
}

/// Le canal d'Office dans OfficeReleases : par le GUID de son adresse (pris dans la source elle-même), ou par son
/// nom, l'un de ses autres noms compris.
fn canal_office<'a>(canaux: &'a [CanalOffice], nom: &str) -> Option<&'a CanalOffice> {
    canaux.iter().find(|k| {
        k.guids.iter().any(|g| g.eq_ignore_ascii_case(nom))
            || k.id.eq_ignore_ascii_case(nom)
            || k.noms.iter().any(|n| n.eq_ignore_ascii_case(nom))
    })
}

/// Office Click-to-Run : comparé aux versions servies de son canal. Une build servie avec une fin de support
/// annoncée et pas passée est à jour à sa dernière révision (Entreprise mensuel, Semi-annuel : plusieurs builds
/// servies à la fois). Sans fin annoncée (Actuel, LTSC 2024), seule la dernière est à jour, sauf pendant la semaine
/// de son déploiement pour la version d'avant. Un canal dont la dernière build a passé sa fin (LTSC 2021 et 2019 :
/// une seule build servie, avec sa fin) n'est plus corrigé, même à sa dernière version.
fn office(i: &Installe, v: Version, f: &Faits) -> Verdict {
    let Branche::Canal(nom) = &i.branche else {
        return Verdict::NonVerifie(tr!("canal d'Office inconnu", "unknown Office channel").to_string());
    };
    let lu = match &f.office {
        Ok(lu) => lu,
        Err(raison) => return sans_source("Microsoft", raison),
    };
    let Some(canal) = canal_office(&lu.valeur, nom) else {
        return Verdict::NonVerifie(trf!(
            "canal d'Office « {} » absent des publications de Microsoft",
            "Office channel “{}” missing from Microsoft's releases",
            crate::ui::affichable(nom)
        ));
    };
    let depassee = |derniere| Verdict::Depassee {
        derniere,
        source: "Microsoft",
    };
    let aujourd_hui = f.maintenant.date();
    let fin_du_canal = canal
        .versions
        .iter()
        .find(|x| x.version == canal.derniere)
        .and_then(|x| x.fin)
        .filter(|fin| *fin <= aujourd_hui);
    if let Some(fin) = fin_du_canal {
        return Verdict::BrancheFinie {
            depuis: Some(fin),
            source: "Microsoft",
        };
    }
    if v >= canal.derniere {
        return a_jour(canal.derniere, "Microsoft", lu.age);
    }
    let build = v.champs().get(2).copied();
    let meme_build = canal
        .versions
        .iter()
        .filter(|x| x.version.champs().get(2).copied() == build)
        .max_by_key(|x| x.version);
    if let Some(x) = meme_build
        && let Some(fin) = x.fin
    {
        return if fin <= aujourd_hui {
            depassee(canal.derniere)
        } else if v >= x.version {
            a_jour(x.version, "Microsoft", lu.age)
        } else {
            depassee(x.version)
        };
    }
    // La version d'avant la dernière, pendant le déploiement de la dernière.
    let derniere = canal.versions.iter().find(|x| x.version == canal.derniere);
    let precedente = canal
        .versions
        .iter()
        .map(|x| x.version)
        .filter(|x| *x < canal.derniere)
        .max();
    let en_cours = derniere
        .and_then(|d| d.disponible)
        .is_some_and(|d| aujourd_hui.signed_duration_since(d) < OFFICE_DEPLOIEMENT);
    if en_cours && precedente.is_some_and(|p| v >= p) {
        return Verdict::NonVerifie(trf!(
            "déploiement de la {} en cours",
            "rollout of {} in progress",
            canal.derniere
        ));
    }
    depassee(canal.derniere)
}

/// Acrobat et Reader : la piste Continuous comparée au `current_version.txt` d'Adobe ; les pistes Classic (2020,
/// 2024) n'ont aucune source fixe.
fn adobe(i: &Installe, v: Version, f: &Faits) -> Verdict {
    if i.branche == Branche::Classic {
        return Verdict::NonVerifie(
            tr!("piste Classic : aucune source fixe", "Classic track: no fixed source").to_string(),
        );
    }
    let id = if i.produit == Produit::Reader {
        "adobe-reader"
    } else {
        "adobe-acrobat"
    };
    simple(v.tronquee(3), f.version(id), "Adobe")
}

/// Java : les trois premiers champs comparés à la dernière version de sa branche (son majeur) pour sa distribution,
/// selon endoflife.date, seule source prise pour Java. Une branche finie le dit, quelle que soit la version.
fn java(d: Distribution, v: Version, f: &Faits) -> Verdict {
    const SOURCE: &str = "endoflife.date";
    let (produit, forme) = match d {
        Distribution::Oracle => ("oracle-jdk", FormeJava::Oracle),
        Distribution::Temurin => ("eclipse-temurin", FormeJava::Temurin),
        Distribution::Corretto => ("amazon-corretto", FormeJava::Corretto),
        Distribution::Microsoft => ("microsoft-build-of-openjdk", FormeJava::Microsoft),
        Distribution::Autre => {
            return Verdict::NonVerifie(
                tr!(
                    "distribution non suivie : sa version n'est pas toujours celle de Java",
                    "distribution not followed: its version is not always Java's"
                )
                .to_string(),
            );
        }
    };
    let lu = match &f.eol {
        Ok(lu) => lu,
        Err(raison) => return sans_source(SOURCE, raison),
    };
    let nom = v.majeur().to_string();
    let Some(branche) = lu
        .valeur
        .iter()
        .find(|p| p.nom == produit)
        .and_then(|p| p.branches.iter().find(|b| b.nom == nom))
    else {
        return sans_source(SOURCE, &trf!("branche {nom} absente", "branch {nom} missing"));
    };
    if branche.finie == Some(true) {
        return Verdict::BrancheFinie {
            depuis: branche.fin,
            source: SOURCE,
        };
    }
    let derniere = branche.derniere.as_deref().and_then(|t| version::java_eol(t, forme));
    let Some(derniere) = derniere else {
        return sans_source(SOURCE, tr!("dernière version illisible", "unreadable latest version"));
    };
    simple(
        v.tronquee(3),
        Ok(Lu {
            valeur: derniere,
            age: lu.age,
        }),
        SOURCE,
    )
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
pub(crate) mod tests {
    use std::path::Path;

    use super::*;
    use crate::protection::perimes::sources::editeurs::{CorrectifEdge, VersionOffice};
    use crate::protection::perimes::sources::eol::BrancheEol;

    fn v(t: &str) -> Version {
        Version::lire(t).unwrap()
    }

    #[allow(clippy::unnecessary_wraps)] // les champs des faits sont des `Fait<T>`
    fn lu<T>(valeur: T) -> Fait<T> {
        Ok(Lu {
            valeur,
            age: Duration::from_hours(3),
        })
    }

    fn date(t: &str) -> NaiveDate {
        NaiveDate::parse_from_str(t, "%Y-%m-%d").unwrap()
    }

    /// Des faits inventés, proches des vrais du 23 oct. 2026.
    pub(crate) fn faits(systeme: Systeme) -> Faits {
        let c = |p, canal, vs: &[&str]| (p, canal, lu(vs.iter().map(|t| v(t)).collect::<Vec<_>>()));
        let edge = |p: &str, a: &str, ver: &str, jour: &str| EdgeStable {
            plateforme: p.into(),
            architecture: a.into(),
            version: v(ver),
            publiee: NaiveDateTime::parse_from_str(&format!("{jour}T19:20:00"), "%Y-%m-%dT%H:%M:%S").ok(),
            correctifs: vec![CorrectifEdge {
                version: v(ver),
                cves: Some(vec![]),
            }],
        };
        let vo = |ver: &str, dispo: Option<&str>, fin: Option<&str>| VersionOffice {
            version: v(ver),
            disponible: dispo.map(date),
            fin: fin.map(date),
        };
        let branche = |nom: &str, finie: bool, derniere: &str| BrancheEol {
            nom: nom.into(),
            finie: Some(finie),
            fin: finie.then(|| date("2025-09-16")),
            derniere: Some(derniere.into()),
            date: None,
        };
        Faits {
            systeme,
            maintenant: NaiveDateTime::parse_from_str("2026-10-23T12:00:00", "%Y-%m-%dT%H:%M:%S").unwrap(),
            firefox: lu(Firefox {
                release: v("158.0.1"),
                esr: vec![v("153.5.1"), v("140.12.1")],
            }),
            chrome: vec![
                c("win64", "stable", &["156.0.8078.47", "156.0.8078.48"]),
                c("win64", "extended", &["152.0.7977.169", "156.0.8078.48"]),
                c("win", "stable", &["156.0.8078.48"]),
                ("win", "extended", Err("pas d'Internet ?".into())),
            ],
            edge: lu(vec![
                edge("Windows", "x64", "156.0.4314.42", "2026-10-22"),
                edge("Windows", "arm64", "155.0.4283.61", "2026-10-10"),
            ]),
            office: lu(vec![
                CanalOffice {
                    id: "Current".into(),
                    noms: vec!["Monthly".into()],
                    derniere: v("16.0.20527.20088"),
                    versions: vec![
                        vo("16.0.20527.20088", Some("2026-10-21"), None),
                        vo("16.0.20430.20182", Some("2026-10-07"), None),
                    ],
                    guids: vec!["492350f6-3a01-4f97-b9c0-c7c6ddf67d60".into()],
                },
                CanalOffice {
                    id: "SemiAnnual".into(),
                    noms: vec!["SAC".into(), "Deferred".into()],
                    derniere: v("16.0.20430.20178"),
                    versions: vec![
                        vo("16.0.20430.20178", None, Some("2027-04-13")),
                        vo("16.0.20326.20230", None, Some("2027-03-09")),
                        vo("16.0.19127.20300", None, Some("2026-10-13")),
                    ],
                    guids: vec!["7ffbc6bf-bc32-4f92-8982-f9dd17fd3114".into()],
                },
                CanalOffice {
                    id: "PerpetualVL2024".into(),
                    noms: vec!["LTSB2024".into()],
                    derniere: v("16.0.17932.21056"),
                    versions: vec![vo("16.0.17932.21056", Some("2026-09-01"), None)],
                    guids: vec![],
                },
            ]),
            versions: vec![
                ("adobe-acrobat", lu(v("26.2.22031"))),
                ("adobe-reader", lu(v("26.2.22031"))),
                ("brave-windows-x64", lu(v("1.98.60"))),
                ("brave-windows-arm64", Err("le serveur a répondu 503".into())),
                ("slack-windows", lu(v("4.52.182"))),
            ],
            eol: lu(vec![
                ProduitEol {
                    nom: "eclipse-temurin".into(),
                    branches: vec![branche("21", false, "21.0.13+9"), branche("8", false, "8u504-b01")],
                },
                ProduitEol {
                    nom: "oracle-jdk".into(),
                    branches: vec![branche("21", false, "21.0.13.0.2"), branche("22", true, "22.0.2")],
                },
            ]),
            formules: lu([("sevenzip", "26.05"), ("putty", "0.85")]
                .into_iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect()),
            avis: Err("tests".into()),
        }
    }

    fn installe(produit: Produit, version: &str, branche: Branche, plateforme: Plateforme) -> Installe {
        let normale = match produit {
            Produit::Java(_) => version::java_release(version),
            Produit::Firefox => version::firefox(version),
            _ => Version::lire(version),
        };
        let mut i = Installe::nouveau(produit, version, normale, Path::new("/essai"));
        i.branche = branche;
        i.plateforme = plateforme;
        i
    }

    fn est_a_jour(verdict: &Verdict) -> bool {
        matches!(verdict, Verdict::AJour { .. })
    }

    fn est_depassee(verdict: &Verdict) -> bool {
        matches!(verdict, Verdict::Depassee { .. })
    }

    fn raison(verdict: &Verdict) -> &str {
        match verdict {
            Verdict::NonVerifie(r) => r,
            autre => panic!("{autre:?}"),
        }
    }

    #[test]
    fn chrome_stable_extended_et_deploiement() {
        let f = faits(Systeme::Windows);
        let j = |ver: &str, p| juger(&installe(Produit::Chrome, ver, Branche::Release, p), &f);
        assert!(est_a_jour(&j("156.0.8078.48", Plateforme::X64)));
        assert!(est_a_jour(&j("157.0.1.0", Plateforme::X64)));
        // Déploiement par étapes : la .47 est encore servie.
        assert!(est_a_jour(&j("156.0.8078.47", Plateforme::X64)));
        // Extended : la 152 servie, à jour ; la 152 d'avant, dépassée.
        assert_eq!(
            j("152.0.7977.169", Plateforme::X64),
            Verdict::AJour {
                derniere: v("152.0.7977.169"),
                source: "Google"
            }
        );
        assert_eq!(
            j("152.0.7977.100", Plateforme::X64),
            Verdict::Depassee {
                derniere: v("156.0.8078.48"),
                source: "Google"
            }
        );
        assert!(est_depassee(&j("150.0.1.2", Plateforme::X64)));
        // 32 bits : extended non lu, rien n'est dit dépassé.
        assert!(raison(&j("152.0.7977.169", Plateforme::X86)).contains("extended"));
        assert!(est_a_jour(&j("156.0.8078.48", Plateforme::X86)));
        // ARM : aucune source lue.
        assert!(raison(&j("156.0.8078.48", Plateforme::Arm64)).contains("Google"));
        // Plateforme inconnue : toutes celles du système, la lecture la plus indulgente.
        assert!(est_a_jour(&j("152.0.7977.169", Plateforme::Inconnue)));
    }

    #[test]
    fn edge_canaux_et_deploiement() {
        let f = faits(Systeme::Windows);
        let j = |ver: &str, b: Branche, p| juger(&installe(Produit::Edge, ver, b, p), &f);
        assert!(est_a_jour(&j("156.0.4314.42", Branche::Release, Plateforme::X64)));
        // Stable publiée hier : la version d'avant n'est pas encore due.
        assert!(raison(&j("155.0.4283.61", Branche::Release, Plateforme::X64)).contains("156.0.4314.42"));
        assert!(est_depassee(&j("153.0.1.2", Branche::Release, Plateforme::X64)));
        // Publiée il y a 13 jours (ARM) : même majeur, dépassée.
        assert!(est_depassee(&j("155.0.4283.50", Branche::Release, Plateforme::Arm64)));
        assert!(raison(&j("150.0.1.2", Branche::Canal("extended".into()), Plateforme::X64)).contains("Extended"));
        assert!(raison(&j("157.0.1.2", Branche::Canal("beta".into()), Plateforme::X64)).contains("beta"));
    }

    #[test]
    fn firefox_release_esr_et_esr_finie() {
        let f = faits(Systeme::Windows);
        let j = |ver: &str, b: Branche| juger(&installe(Produit::Firefox, ver, b, Plateforme::X64), &f);
        assert!(est_a_jour(&j("158.0.1", Branche::Inconnue)));
        assert!(est_depassee(&j("158.0", Branche::Release)));
        // Le majeur d'une ESR, sans channel-prefs.js : comparée à son ESR.
        assert!(est_a_jour(&j("153.5.1esr", Branche::Inconnue)));
        assert_eq!(
            j("153.4.0esr", Branche::Inconnue),
            Verdict::Depassee {
                derniere: v("153.5.1"),
                source: "Mozilla"
            }
        );
        assert!(est_a_jour(&j("140.12.1", Branche::Esr)));
        // ESR finie : dépassée par la plus récente.
        assert_eq!(
            j("128.14.0", Branche::Esr),
            Verdict::Depassee {
                derniere: v("153.5.1"),
                source: "Mozilla"
            }
        );
        assert!(raison(&j("170.0", Branche::Esr)).contains("170"));
        assert!(raison(&j("159.0", Branche::Canal("beta".into()))).contains("beta"));
        assert!(raison(&j("159.0b5", Branche::Inconnue)).contains("159.0b5"));
    }

    #[test]
    fn office_windows_par_canal() {
        let f = faits(Systeme::Windows);
        let j = |ver: &str, canal: &str| {
            juger(
                &installe(Produit::Office, ver, Branche::Canal(canal.into()), Plateforme::X64),
                &f,
            )
        };
        let actuel = "492350f6-3a01-4f97-b9c0-c7c6ddf67d60";
        assert!(est_a_jour(&j("16.0.20527.20088", actuel)));
        // La dernière, servie depuis deux jours : celle d'avant n'est pas encore due ; plus vieille, dépassée.
        assert!(raison(&j("16.0.20430.20182", actuel)).contains("20527"));
        assert!(est_depassee(&j("16.0.20326.20230", actuel)));
        // Semi-annuel : plusieurs builds servies, chacune à jour à sa dernière révision.
        assert!(est_a_jour(&j("16.0.20326.20230", "Deferred")));
        assert_eq!(
            j("16.0.20326.20100", "7FFBC6BF-BC32-4F92-8982-F9DD17FD3114"),
            Verdict::Depassee {
                derniere: v("16.0.20326.20230"),
                source: "Microsoft"
            }
        );
        // Une build dont le support a pris fin le 13 oct., ou absente du canal : dépassée.
        assert!(est_depassee(&j("16.0.19127.20300", "SemiAnnual")));
        assert!(est_depassee(&j("16.0.20400.20000", "SemiAnnual")));
        // LTSC : seule la dernière.
        assert!(est_depassee(&j("16.0.17932.21000", "PerpetualVL2024")));
        assert!(raison(&j("16.0.20527.20088", "InsiderFast")).contains("InsiderFast"));
        let sans = installe(Produit::Office, "16.0.20527.20088", Branche::Inconnue, Plateforme::X64);
        assert!(raison(&juger(&sans, &f)).contains("canal"));
    }

    /// LTSC 2021 : une seule build servie, avec sa fin. À jour avant, plus corrigée après, même à sa dernière.
    #[test]
    fn office_ltsc_apres_sa_fin() {
        let mut f = faits(Systeme::Windows);
        f.office.as_mut().unwrap().valeur.push(CanalOffice {
            id: "PerpetualVL2021".into(),
            noms: vec!["LTSC2021".into()],
            derniere: v("16.0.14334.20974"),
            versions: vec![VersionOffice {
                version: v("16.0.14334.20974"),
                disponible: Some(date("2026-10-14")),
                fin: Some(date("2026-11-10")),
            }],
            guids: vec![],
        });
        let ltsc = installe(
            Produit::Office,
            "16.0.14334.20974",
            Branche::Canal("PerpetualVL2021".into()),
            Plateforme::X64,
        );
        assert!(est_a_jour(&juger(&ltsc, &f)));
        f.maintenant = NaiveDateTime::parse_from_str("2026-12-01T12:00:00", "%Y-%m-%dT%H:%M:%S").unwrap();
        assert_eq!(
            juger(&ltsc, &f),
            Verdict::BrancheFinie {
                depuis: Some(date("2026-11-10")),
                source: "Microsoft"
            }
        );
    }

    #[test]
    fn adobe_brave_java() {
        let win = faits(Systeme::Windows);
        let acro = |ver: &str, b: Branche| juger(&installe(Produit::Reader, ver, b, Plateforme::X64), &win);
        assert!(est_a_jour(&acro("26.2.22031.0", Branche::Release)));
        assert!(est_depassee(&acro("26.1.21662", Branche::Release)));
        assert!(raison(&acro("24.1.30200", Branche::Classic)).contains("Classic"));

        let brv = |ver: &str, p, faits: &Faits| juger(&installe(Produit::Brave, ver, Branche::Release, p), faits);
        assert!(est_a_jour(&brv("1.98.60", Plateforme::X64, &win)));
        assert!(est_depassee(&brv("1.98.59", Plateforme::X64, &win)));
        assert!(raison(&brv("1.98.60", Plateforme::Arm64, &win)).contains("503"));
        assert!(raison(&brv("1.98.60", Plateforme::X86, &win)).contains("32"));

        let j = |d, ver: &str| {
            juger(
                &installe(Produit::Java(d), ver, Branche::Release, Plateforme::X64),
                &win,
            )
        };
        assert!(est_a_jour(&j(Distribution::Temurin, "21.0.13")));
        assert!(est_depassee(&j(Distribution::Temurin, "1.8.0_481")));
        assert!(est_a_jour(&j(Distribution::Oracle, "21.0.13")));
        assert_eq!(
            j(Distribution::Oracle, "22.0.2"),
            Verdict::BrancheFinie {
                depuis: Some(date("2025-09-16")),
                source: "endoflife.date"
            }
        );
        assert!(raison(&j(Distribution::Oracle, "17.0.2")).contains("17"));
        assert!(raison(&j(Distribution::Corretto, "21.0.13")).contains("endoflife.date"));
        assert!(raison(&j(Distribution::Autre, "21.0.13")).contains("distribution"));
    }

    /// 7-Zip et PuTTY comparés à leur formule de Homebrew ; Slack à la réponse de Slack pour son système.
    #[test]
    fn sept_zip_putty_slack() {
        let mut f = faits(Systeme::Windows);
        let j = |p: Produit, ver: &str, f: &Faits| {
            let mut i = installe(p, ver, Branche::Release, Plateforme::X64);
            i.version = crate::protection::perimes::windows::normaliser(p, ver);
            juger(&i, f)
        };
        // L'exécutable de 7-Zip dit « 26.5.0.0 » : la même que « 26.05 ».
        assert_eq!(
            j(Produit::SevenZip, "26.5.0.0", &f),
            Verdict::AJour {
                derniere: v("26.5"),
                source: "Homebrew"
            }
        );
        assert!(est_a_jour(&j(Produit::SevenZip, "26.06", &f)));
        assert_eq!(
            j(Produit::SevenZip, "24.09", &f),
            Verdict::Depassee {
                derniere: v("26.5"),
                source: "Homebrew"
            }
        );
        assert!(est_a_jour(&j(Produit::PuTTY, "0.85.0.0", &f)));
        assert!(est_depassee(&j(Produit::PuTTY, "0.81.0.0", &f)));
        assert!(est_a_jour(&j(Produit::Slack, "4.52.182.0", &f)));
        assert!(est_depassee(&j(Produit::Slack, "4.41.105.0", &f)));
        // Formule absente, d'une forme inconnue, ou fichier manquant : non vérifié, jamais à jour.
        if let Ok(lu) = &mut f.formules {
            lu.valeur.remove("putty");
            lu.valeur.insert("sevenzip".into(), "26.05-beta".into());
        }
        assert!(raison(&j(Produit::PuTTY, "0.85.0.0", &f)).contains("putty"));
        assert!(raison(&j(Produit::SevenZip, "26.5.0.0", &f)).contains("26.05-beta"));
        f.formules = Err("pas d'Internet ?".into());
        assert!(raison(&j(Produit::SevenZip, "26.5.0.0", &f)).contains("Homebrew"));
        // Une copie de quatre jours ne suffit plus pour « à jour ».
        let mut f = faits(Systeme::Windows);
        if let Ok(lu) = &mut f.formules {
            lu.age = Duration::from_hours(96);
        }
        assert!(matches!(j(Produit::SevenZip, "26.5.0.0", &f), Verdict::NonVerifie(_)));
    }

    /// Edge faille par faille, sur une liste de Microsoft inventée : chaque CVE exploitée corrigée par une version
    /// Stable plus récente de sa plateforme, avec la plus ancienne de ces versions ; rien pour un canal incertain.
    #[test]
    fn edge_faille_par_faille() {
        let mut f = faits(Systeme::Windows);
        let correctif = |ver: &str, cves: Option<&[&str]>| CorrectifEdge {
            version: v(ver),
            cves: cves.map(|c| c.iter().map(|x| (*x).to_string()).collect()),
        };
        if let Ok(lu) = &mut f.edge {
            lu.valeur[0].correctifs = vec![
                correctif("155.0.4283.61", Some(&["CVE-2099-0001", "CVE-2099-0003"])),
                correctif(
                    "156.0.4314.42",
                    Some(&["CVE-2099-0002", "CVE-2099-0003", "CVE-2099-0009"]),
                ),
            ];
            lu.valeur[1].correctifs = vec![correctif("155.0.4283.61", Some(&["CVE-2099-0004"]))];
        }
        let exploitees = |c: &str| ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003", "CVE-2099-0004"].contains(&c);
        let fe = |ver: &str, b: Branche, p, f: &Faits| {
            let i = installe(Produit::Edge, ver, b, p);
            failles_edge(&i, i.version.unwrap(), f, &exploitees)
        };
        assert_eq!(
            fe("155.0.4283.10", Branche::Inconnue, Plateforme::X64, &f),
            Ok(vec![
                ("CVE-2099-0001".into(), v("155.0.4283.61")),
                ("CVE-2099-0003".into(), v("155.0.4283.61")),
                ("CVE-2099-0002".into(), v("156.0.4314.42")),
            ])
        );
        assert_eq!(
            fe("155.0.4283.61", Branche::Canal("stable".into()), Plateforme::X64, &f),
            Ok(vec![("CVE-2099-0002".into(), v("156.0.4314.42"))])
        );
        assert_eq!(fe("156.0.4314.42", Branche::Inconnue, Plateforme::X64, &f), Ok(vec![]));
        // Une autre architecture a sa propre liste ; inconnue, toutes celles du système.
        assert_eq!(
            fe("155.0.1.0", Branche::Inconnue, Plateforme::Arm64, &f),
            Ok(vec![("CVE-2099-0004".into(), v("155.0.4283.61"))])
        );
        assert_eq!(
            fe("155.0.1.0", Branche::Inconnue, Plateforme::Inconnue, &f).map(|l| l.len()),
            Ok(4)
        );
        // Extended Stable, ou un autre canal réglé : rien de jugé, sans autre raison que le verdict.
        assert_eq!(
            fe("150.0.1.2", Branche::Canal("extended".into()), Plateforme::X64, &f),
            Err(String::new())
        );
        assert_eq!(
            fe("150.0.1.2", Branche::Canal("beta".into()), Plateforme::X64, &f),
            Err(String::new())
        );
        assert_eq!(
            fe("150.0.1.2", Branche::Inconnue, Plateforme::X86, &f),
            Err(String::new())
        );
        // Une version plus récente sans liste : dit, si rien d'autre n'est trouvé.
        if let Ok(lu) = &mut f.edge {
            lu.valeur[0].correctifs[1].cves = None;
        }
        assert_eq!(
            fe("155.0.4283.10", Branche::Inconnue, Plateforme::X64, &f).map(|l| l.len()),
            Ok(2)
        );
        assert!(
            fe("155.0.4283.61", Branche::Inconnue, Plateforme::X64, &f)
                .unwrap_err()
                .contains("Microsoft")
        );
        // La liste de la seule version plus récente a changé de forme (objets au lieu de textes) : rien n'est jugé
        // faille par faille, et c'est dit, jamais pris pour « aucune faille ».
        let json = br#"[{"Product": "Stable", "Releases": [
            {"Platform": "Windows", "Architecture": "x64", "ProductVersion": "155.0.4283.61",
             "CVEs": ["CVE-2099-0001"]},
            {"Platform": "Windows", "Architecture": "x64", "ProductVersion": "156.0.4314.42",
             "CVEs": [{"id": "CVE-2099-0002"}]}]}]"#;
        let mut g = faits(Systeme::Windows);
        g.edge = lu(editeurs::edge(json).unwrap());
        assert!(
            fe("155.0.4283.61", Branche::Inconnue, Plateforme::X64, &g)
                .unwrap_err()
                .contains("Microsoft")
        );
    }

    /// Les faits d'un relevé : chaque copie lue par son lecteur, la raison d'une source manquante gardée.
    #[test]
    fn faits_d_un_releve() {
        use crate::protection::perimes::sources::{Copie, SOURCES};
        let source = |id: &str| SOURCES.iter().find(|s| s.id == id).unwrap();
        let copie = |octets: &[u8]| {
            Ok(Copie {
                octets: octets.to_vec(),
                age: Duration::from_hours(5),
                manque: None,
            })
        };
        let releve = Releve {
            sources: vec![
                (
                    source("mozilla"),
                    copie(br#"{"LATEST_FIREFOX_VERSION": "158.0.1", "FIREFOX_ESR": "153.5.1esr"}"#),
                ),
                (source("brave-windows-x64"), copie(b"1.98.60")),
                (source("adobe-reader"), copie(b"<html>")),
                (source("edge"), Err("le serveur a répondu 503".into())),
                (
                    source("slack-windows"),
                    copie(br#"{"ok":true,"version":"4.52.182","platform":"win32","arch":"x64"}"#),
                ),
            ],
        };
        let f = Faits::de(&releve, Systeme::Windows, faits(Systeme::Windows).maintenant);
        let ff = f.firefox.as_ref().unwrap();
        assert_eq!((ff.valeur.release, ff.age), (v("158.0.1"), Duration::from_hours(5)));
        assert_eq!(f.version("brave-windows-x64").unwrap().valeur, v("1.98.60"));
        assert_eq!(f.version("slack-windows").unwrap().valeur, v("4.52.182"));
        let illisible = f.version("adobe-reader").unwrap_err();
        assert!(illisible.contains("illisible") || illisible.contains("unreadable"));
        assert!(f.version("adobe-acrobat").is_err());
        assert_eq!(f.edge.unwrap_err(), "le serveur a répondu 503");
        assert!(f.office.is_err() && f.eol.is_err() && f.avis.is_err() && f.formules.is_err() && f.chrome.is_empty());
    }

    /// Une copie de quatre jours ne suffit plus pour « à jour », mais une version dépassée l'est toujours.
    #[test]
    fn copie_trop_vieille() {
        let mut f = faits(Systeme::Windows);
        if let Ok(lu) = &mut f.firefox {
            lu.age = Duration::from_hours(96);
        }
        let j = |ver: &str| juger(&installe(Produit::Firefox, ver, Branche::Release, Plateforme::X64), &f);
        assert!(raison(&j("158.0.1")).contains('4'));
        assert!(est_depassee(&j("150.0")));
        let i = installe(Produit::Chrome, "", Branche::Release, Plateforme::X64);
        assert!(raison(&juger(&i, &f)).contains("illisible") || raison(&juger(&i, &f)).contains("unreadable"));
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 500, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        /// Dans un même majeur, une version plus grande ne donne jamais un verdict pire. (D'un majeur à l'autre, si : un
        /// majeur que l'éditeur ne sert pas est dépassé, même plus récent qu'une branche servie ; Office de même par
        /// build.)
        #[test]
        fn plus_grande_jamais_pire(majeur in proptest::sample::select(vec![0u32, 4, 8, 21, 22, 26, 128, 140, 152, 153, 155, 156, 158]), a in proptest::collection::vec(0u32..30_000, 3), b in proptest::collection::vec(0u32..30_000, 3), produit in 0usize..9) {
            let f = faits(Systeme::Windows);
            let (petite, grande) = if a <= b { (a, b) } else { (b, a) };
            let produit = [
                Produit::Chrome, Produit::Edge, Produit::Firefox, Produit::Reader,
                Produit::Brave, Produit::Java(Distribution::Temurin),
                Produit::SevenZip, Produit::PuTTY, Produit::Slack,
            ][produit];
            let complete = |c: &[u32]| [&[majeur][..], c].concat();
            let (petite, grande) = (complete(&petite), complete(&grande));
            let verdict = |champs: &[u32]| {
                let champs = if matches!(produit, Produit::Brave | Produit::Reader | Produit::Java(_)) { &champs[..3] } else { champs };
                let mut i = installe(produit, "x", Branche::Release, Plateforme::X64);
                i.version = Version::depuis(champs);
                juger(&i, &f).gravite()
            };
            proptest::prop_assert!(verdict(&grande) <= verdict(&petite), "{petite:?} {grande:?}");
        }
    }
}

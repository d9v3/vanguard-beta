//! L'écran et le bilan des logiciels pas à jour : chaque logiciel trouvé, jugé (`verdicts`), avec ce qui l'expose.
//! Firefox l'est faille par faille (avis de Mozilla), Edge aussi (les CVE que Microsoft dit corrigées par chaque
//! version Stable) ; pour les autres, le catalogue de la CISA dit combien de failles exploitées leur produit compte,
//! sans conclure pour la version installée. Un navigateur qui ne se compare pas reprend l'âge de son fichier (plus de
//! 60 jours : sa mise à jour automatique ne se fait plus), comme le faisait la fin de support, qui ne le juge plus :
//! un seul constat par navigateur.
//!
//! Au bilan : un seul constat pour tous les logiciels dépassés (la note additionne les pénalités, un par logiciel la
//! ferait chuter), un constat critique à part pour Firefox ou Edge antérieur au correctif d'une faille exploitée, et un
//! seul « impossible » qui donne tout ce qui n'a pas pu être vérifié, jamais compté comme sain.

use std::time::Duration;

use super::inventaire::{Installe, NonLu};
use super::mozilla_avis::{self, Jugement};
use super::produits::Produit;
use super::verdicts::{self, Faits, Verdict};
use super::version::Version;
use crate::machine::{Constat, alerte, impossible, ok};
use crate::protection::kev::Exploitee;
use crate::risk::Niveau;
use crate::ui::*;
use crate::{tr, trf};

const CAT: &str = "Logiciels pas à jour";

/// Un logiciel jugé.
pub(crate) struct Juge {
    pub installe: Installe,
    pub verdict: Verdict,
    /// Non vérifié, mais pas mis à jour depuis tant de jours (un navigateur, au-delà de 60).
    pub vieux: Option<u64>,
    /// Firefox et Edge : les failles exploitées corrigées dans une version plus récente que la sienne (CVE,
    /// correctif).
    pub failles: Vec<(String, Version)>,
    /// Firefox et Edge : pourquoi des failles exploitées n'ont pas été jugées une à une.
    pub failles_non_jugees: Option<String>,
}

impl Juge {
    fn touche(&self) -> bool {
        !self.failles.is_empty()
    }

    fn depasse(&self) -> bool {
        !self.touche() && matches!(self.verdict, Verdict::Depassee { .. } | Verdict::BrancheFinie { .. })
    }

    fn a_jour(&self) -> bool {
        !self.touche() && matches!(self.verdict, Verdict::AJour { .. })
    }

    pub(super) fn non_verifie(&self) -> bool {
        !self.touche() && self.vieux.is_none() && matches!(self.verdict, Verdict::NonVerifie(_))
    }
}

/// Tout ce que l'écran et le bilan montrent.
pub(crate) struct Bilan {
    pub juges: Vec<Juge>,
    pub non_lus: Vec<NonLu>,
    pub kev: Result<Vec<Exploitee>, String>,
    /// L'âge de la plus vieille copie qui a servi.
    pub age: Option<Duration>,
    /// Pourquoi des copies n'ont pas été rafraîchies (la copie d'avant a servi).
    pub manques: Vec<String>,
}

fn navigateur(produit: Produit) -> bool {
    matches!(
        produit,
        Produit::Chrome | Produit::Edge | Produit::Firefox | Produit::Brave
    )
}

/// Les failles exploitées de Firefox (catalogue de la CISA) jugées une à une contre sa version et sa branche.
fn failles_firefox(
    i: &Installe,
    faits: &Faits,
    kev: &Result<Vec<Exploitee>, String>,
) -> (Vec<(String, Version)>, Option<String>) {
    let Some(v) = i.version else {
        return (Vec::new(), None);
    };
    let kev = match kev {
        Ok(k) => k,
        Err(r) => {
            return (
                Vec::new(),
                Some(trf!("catalogue de la CISA : {r}", "CISA catalog: {r}")),
            );
        }
    };
    let index = match &faits.avis {
        Ok(lu) => &lu.valeur,
        Err(r) => {
            return (
                Vec::new(),
                Some(trf!("avis de Mozilla : {r}", "Mozilla advisories: {r}")),
            );
        }
    };
    let ff = faits.firefox.as_ref().ok().map(|l| &l.valeur);
    let Ok(branche) = verdicts::branche_firefox(i, v, ff) else {
        return (Vec::new(), None);
    };
    let regle = Produit::Firefox.fiche().kev;
    let (mut failles, mut inconnues) = (Vec::new(), 0usize);
    for e in kev.iter().filter(|e| regle(&e.editeur, &e.produit)) {
        match mozilla_avis::juger(index, &e.cve, v, branche) {
            Jugement::Anterieure(z) => failles.push((e.cve.clone(), z)),
            Jugement::Corrigee => {}
            Jugement::Inconnu => inconnues += 1,
        }
    }
    let non_jugees = (inconnues > 0).then(|| {
        trf!(
            "{inconnues} faille(s) exploitée(s) sans correctif connu pour votre branche dans les avis de Mozilla",
            "{inconnues} exploited flaw(s) without a known fix for your branch in Mozilla's advisories"
        )
    });
    (failles, non_jugees)
}

/// Les failles exploitées d'Edge (catalogue de la CISA) jugées une à une, d'après les CVE que Microsoft dit corrigées
/// par chaque version Stable de sa plateforme.
fn failles_edge(
    i: &Installe,
    faits: &Faits,
    kev: &Result<Vec<Exploitee>, String>,
) -> (Vec<(String, Version)>, Option<String>) {
    let Some(v) = i.version else {
        return (Vec::new(), None);
    };
    let kev = match kev {
        Ok(k) => k,
        Err(r) => {
            return (
                Vec::new(),
                Some(trf!("catalogue de la CISA : {r}", "CISA catalog: {r}")),
            );
        }
    };
    let exploitees: std::collections::HashSet<&str> = kev.iter().map(|e| e.cve.as_str()).collect();
    match verdicts::failles_edge(i, v, faits, &|c| exploitees.contains(c)) {
        Ok(failles) => (failles, None),
        Err(r) if r.is_empty() => (Vec::new(), None),
        Err(r) => (Vec::new(), Some(r)),
    }
}

/// Chaque logiciel de l'inventaire jugé ; `age_fichier` donne l'âge du fichier d'un navigateur, en jours.
pub(crate) fn juger_tout(
    installes: Vec<Installe>,
    faits: &Faits,
    kev: &Result<Vec<Exploitee>, String>,
    age_fichier: &dyn Fn(&Installe) -> Option<u64>,
) -> Vec<Juge> {
    installes
        .into_iter()
        .map(|i| {
            let verdict = verdicts::juger(&i, faits);
            let vieux = (matches!(verdict, Verdict::NonVerifie(_)) && navigateur(i.produit))
                .then(|| age_fichier(&i))
                .flatten()
                .filter(|j| *j > crate::machine::fin_de_support::NAVIGATEUR_JOURS);
            let (failles, failles_non_jugees) = match i.produit {
                Produit::Firefox => failles_firefox(&i, faits, kev),
                Produit::Edge => failles_edge(&i, faits, kev),
                _ => (Vec::new(), None),
            };
            Juge {
                installe: i,
                verdict,
                vieux,
                failles,
                failles_non_jugees,
            }
        })
        .collect()
}

// ───────────────────────────── Textes ─────────────────────────────

/// Le nom montré : celui de l'application pour Office sous macOS (une par application), sinon celui du produit.
fn nom_app(i: &Installe) -> &'static str {
    match i.app.map(|a| a.bundle_id) {
        Some("com.microsoft.Word") => "Microsoft Word",
        Some("com.microsoft.Excel") => "Microsoft Excel",
        Some("com.microsoft.Powerpoint") => "Microsoft PowerPoint",
        Some("com.microsoft.Outlook") => "Microsoft Outlook",
        Some("com.microsoft.onenote.mac") => "Microsoft OneNote",
        _ => i.produit.nom(),
    }
}

/// « Google Chrome 156.0.8078.48 (compte alice) ».
fn nomme(i: &Installe) -> String {
    let mut t = nom_app(i).to_string();
    if !i.brute.is_empty() {
        t = format!("{t} {}", i.brute);
    }
    match &i.compte {
        Some(c) if !c.is_empty() => trf!("{t} (compte {c})", "{t} (account {c})"),
        _ => t,
    }
}

/// Le nom d'une source tel qu'il est montré : Adobe ne publie que le fichier de sa piste Continuous.
fn nom_source(source: &str) -> String {
    if source == "Adobe" {
        tr!("Adobe, piste Continuous", "Adobe, Continuous track").to_string()
    } else {
        source.to_string()
    }
}

/// La ligne d'un logiciel jugé.
fn ligne(j: &Juge) -> String {
    let i = &j.installe;
    let nom = nomme(i);
    if let Some((cve, z)) = j.failles.first() {
        let court = match i.produit {
            Produit::Edge => "Edge",
            _ => "Firefox",
        };
        let mut t = trf!(
            "{nom} : la faille exploitée {cve} (catalogue de la CISA) est corrigée dans {court} {z}, et votre version est antérieure.",
            "{nom}: the exploited flaw {cve} (CISA catalog) is fixed in {court} {z}, and your version is older."
        );
        if j.failles.len() > 1 {
            let autres: Vec<&str> = j.failles[1..].iter().map(|(c, _)| c.as_str()).collect();
            t += &trf!(" Et aussi : {}.", " Also: {}.", resume(&autres, 4, ", "));
        }
        return t;
    }
    if let (Some(jours), Verdict::NonVerifie(raison)) = (j.vieux, &j.verdict) {
        return trf!(
            "{nom} — pas mis à jour depuis {jours} jours (version non comparée : {raison})",
            "{nom} — not updated for {jours} days (version not compared: {raison})"
        );
    }
    let mut t = match &j.verdict {
        Verdict::AJour { source, .. } => format!("{nom} ({})", nom_source(source)),
        Verdict::Depassee { derniere, source } => {
            let mut t = trf!(
                "{nom} — dernière : {derniere} ({})",
                "{nom} — latest: {derniere} ({})",
                nom_source(source)
            );
            if i.attente {
                t += tr!(
                    " ; mise à jour posée, appliquée en redémarrant le navigateur",
                    "; update downloaded, applied when the browser restarts"
                );
            }
            t
        }
        Verdict::BrancheFinie {
            depuis: Some(d),
            source,
        } => trf!(
            "{nom} — branche plus corrigée depuis le {d} ({source})",
            "{nom} — branch no longer fixed since {d} ({source})"
        ),
        Verdict::BrancheFinie { depuis: None, source } => trf!(
            "{nom} — branche plus corrigée ({source})",
            "{nom} — branch no longer fixed ({source})"
        ),
        Verdict::NonVerifie(raison) => format!("{nom} ({raison})"),
    };
    // L'exécutable et le dossier de version d'un navigateur ne disent pas la même chose : la plus haute a été
    // gardée, l'autre se dit.
    if let Some(e) = i.ecart {
        t += &trf!(
            " ; autre version vue au même endroit : {e}",
            "; other version seen in the same place: {e}"
        );
    }
    t
}

/// Le nom d'un produit au catalogue de la CISA (ses lignes couvrent toutes ses éditions).
fn nom_kev(produit: Produit) -> &'static str {
    match produit {
        Produit::Chrome => tr!("Chrome et Chromium", "Chrome and Chromium"),
        Produit::Edge => tr!("Chromium, sur lequel Edge repose,", "Chromium, on which Edge is built,"),
        Produit::Firefox => "Firefox",
        Produit::Office => "Office",
        Produit::Acrobat | Produit::Reader => tr!("Acrobat et Reader", "Acrobat and Reader"),
        Produit::Java(_) => "Java",
        Produit::Brave => "Brave",
        Produit::SevenZip => "7-Zip",
        Produit::PuTTY => "PuTTY",
        Produit::Slack => "Slack",
    }
}

/// Les failles exploitées du produit au catalogue : leur nombre et le jour de la dernière ajoutée.
fn exposition(produit: Produit, kev: &[Exploitee]) -> (usize, Option<chrono::NaiveDate>) {
    let regle = produit.fiche().kev;
    let liste: Vec<&Exploitee> = kev.iter().filter(|e| regle(&e.editeur, &e.produit)).collect();
    (liste.len(), liste.iter().filter_map(|e| e.ajoutee).max())
}

/// « Chrome et Chromium compte 71 faille(s) exploitée(s) au catalogue de la CISA (la dernière ajoutée le …) ; rien
/// ne dit si ta version en a. » ; `None` si le produit n'en compte aucune.
fn ligne_kev(produit: Produit, kev: &[Exploitee]) -> Option<String> {
    let (n, derniere) = exposition(produit, kev);
    if n == 0 {
        return None;
    }
    let nom = nom_kev(produit);
    Some(match derniere {
        Some(d) => trf!(
            "{nom} compte {n} faille(s) exploitée(s) au catalogue de la CISA (la dernière ajoutée le {d}) ; rien ne dit si votre version en a.",
            "{nom} has {n} exploited flaw(s) in CISA's catalog (latest added {d}); nothing says whether your version has any."
        ),
        None => trf!(
            "{nom} compte {n} faille(s) exploitée(s) au catalogue de la CISA ; rien ne dit si votre version en a.",
            "{nom} has {n} exploited flaw(s) in CISA's catalog; nothing says whether your version has any."
        ),
    })
}

/// L'âge d'une copie, tel qu'il est montré.
fn age_montre(age: Duration) -> String {
    match age.as_secs() / 3600 {
        0 => tr!("moins d'une heure", "less than an hour").to_string(),
        h @ 1..48 => trf!("{h} h", "{h} h"),
        h => trf!("{} jours", "{} days", h / 24),
    }
}

/// D'où viennent les verdicts, leurs licences, et ce qui part de l'ordinateur (rien de lui).
pub(crate) fn mention(age: Option<Duration>) -> String {
    let copies = age.map_or_else(String::new, |a| {
        trf!(" ; copies de {}", "; copies {} old", age_montre(a))
    });
    trf!(
        "Versions : sites des éditeurs, endoflife.date (MIT), formules de Homebrew (BSD-2-Clause) pour 7-Zip et PuTTY ; avis de Mozilla (MPL-2.0) ; failles exploitées : CISA KEV (CC0). Fichiers publics téléchargés en entier, les mêmes pour tous : rien de cet ordinateur n'est envoyé{copies}. Couper : vanguard parametres versions-logiciels non.",
        "Versions: publishers' sites, endoflife.date (MIT), Homebrew formulae (BSD-2-Clause) for 7-Zip and PuTTY; Mozilla advisories (MPL-2.0); exploited flaws: CISA KEV (CC0). Public files downloaded in full, the same for everyone: nothing about this computer is sent{copies}. Turn off: vanguard settings software-versions no."
    )
}

/// La mention, courte, reprise au bilan.
fn mention_bilan() -> &'static str {
    tr!(
        "Versions : sites des éditeurs, endoflife.date et Homebrew ; failles : catalogue de la CISA. Détail : vanguard logiciels-perimes",
        "Versions: publishers' sites, endoflife.date and Homebrew; flaws: CISA's catalog. Details: vanguard outdated-software"
    )
}

/// Les raisons de tout ce qui n'a pas été vérifié : logiciels non jugés, comptes et dossiers non lus.
pub(super) fn non_verifies(b: &Bilan) -> Vec<String> {
    b.juges
        .iter()
        .filter(|j| j.non_verifie())
        .map(ligne)
        .chain(b.non_lus.iter().map(NonLu::texte))
        .collect()
}

// ───────────────────────────── Bilan ─────────────────────────────

/// L'objet d'un constat des logiciels périmés : chaque logiciel jugé, son produit et sa version lue (« firefox@128.0 »),
/// sans langue. Une autre version encore périmée est un autre objet : déclarer normal une version ne tait jamais la
/// suivante.
fn objet_des(juges: &[&Juge], genre: &str) -> crate::modele::Objet {
    let mut tous: Vec<String> = juges
        .iter()
        .map(|j| format!("{:?}@{}", j.installe.produit, j.installe.brute).to_lowercase())
        .collect();
    tous.sort();
    tous.dedup();
    crate::modele::Objet::de(genre, &tous.join(","))
}

/// Les constats du bilan, d'après un relevé.
pub(crate) fn constats_de(b: &Bilan) -> Vec<Constat> {
    let mut constats = Vec::new();
    // Un constat critique par produit, chacun avec sa façon de se mettre à jour.
    for (produit, manuel) in [
        (
            Produit::Firefox,
            tr!(
                "Mettre Firefox à jour : Menu › Aide › À propos de Firefox ; sinon le réinstaller depuis mozilla.org",
                "Update Firefox: Menu › Help › About Firefox; otherwise reinstall it from mozilla.org"
            ),
        ),
        (
            Produit::Edge,
            tr!(
                "Mettre Edge à jour : Menu › Aide et commentaires › À propos de Microsoft Edge ; sinon le réinstaller depuis microsoft.com/edge",
                "Update Edge: Menu › Help and feedback › About Microsoft Edge; otherwise reinstall it from microsoft.com/edge"
            ),
        ),
    ] {
        let juges: Vec<&Juge> = b
            .juges
            .iter()
            .filter(|j| j.touche() && j.installe.produit == produit)
            .collect();
        let touches: Vec<String> = juges.iter().map(|j| ligne(j)).collect();
        if !touches.is_empty() {
            constats.push(
                alerte(
                    CAT,
                    Niveau::Critique,
                    format!("{} {}", touches.join(" "), mention_bilan()),
                )
                .avec_objet(objet_des(&juges, "exploite"))
                .manuel(manuel, &[]),
            );
        }
    }
    let depasses: Vec<&Juge> = b.juges.iter().filter(|j| j.depasse()).collect();
    if !depasses.is_empty() {
        let lignes: Vec<String> = depasses.iter().map(|j| ligne(j)).collect();
        let mut message = trf!(
            "{} logiciel(s) pas à jour : {}.",
            "{} outdated program(s): {}.",
            depasses.len(),
            resume(&lignes, 5, " ; ")
        );
        match &b.kev {
            Ok(kev) => {
                let plus_expose = depasses
                    .iter()
                    .map(|j| (exposition(j.installe.produit, kev).0, j.installe.produit))
                    .max_by_key(|(n, _)| *n);
                if let Some(t) = plus_expose.and_then(|(_, p)| ligne_kev(p, kev)) {
                    message = format!("{message} {t}");
                }
            }
            Err(r) => {
                message += &trf!(
                    " Failles exploitées (catalogue de la CISA) pas vérifiées : {r}.",
                    " Exploited flaws (CISA catalog) not checked: {r}."
                );
            }
        }
        constats.push(
            alerte(CAT, Niveau::Moyen, format!("{message} {}", mention_bilan()))
                .avec_objet(objet_des(&depasses, "perimes"))
                .manuel(
                tr!(
                    "Ouvrir chacun, puis Aide › À propos (navigateurs) ou Fichier › Compte › Options de mise à jour (Office) ; sinon le réinstaller depuis le site de son éditeur. Détail : vanguard logiciels-perimes",
                    "Open each one, then Help › About (browsers) or File › Account › Update Options (Office); otherwise reinstall it from its publisher's site. Details: vanguard outdated-software"
                ),
                &[],
            ),
        );
    }
    for j in b.juges.iter().filter(|j| !j.touche()) {
        if let Some(jours) = j.vieux {
            constats.push(crate::machine::fin_de_support::constat_navigateur(
                nom_app(&j.installe),
                jours,
            ));
        }
    }
    let alertes = !constats.is_empty();
    let a_jour: Vec<String> = b
        .juges
        .iter()
        .filter(|j| j.a_jour())
        .map(|j| nomme(&j.installe))
        .collect();
    if !alertes && !a_jour.is_empty() {
        constats.push(ok(
            CAT,
            trf!(
                "À jour : {}. {}",
                "Up to date: {}. {}",
                resume(&a_jour, 5, ", "),
                mention_bilan()
            ),
        ));
    }
    let raisons = non_verifies(b);
    if !alertes && b.juges.is_empty() {
        constats.push(ok(CAT, aucun()));
    }
    if !raisons.is_empty() {
        constats.push(impossible(CAT, &resume(&raisons, 5, " ; ")));
    }
    constats
}

pub(super) fn aucun() -> &'static str {
    tr!(
        "Aucun des logiciels suivis (navigateurs, Office, Acrobat, Java, 7-Zip, PuTTY, Slack) aux emplacements connus ; un logiciel portable ou installé ailleurs n'est pas vu.",
        "None of the followed programs (browsers, Office, Acrobat, Java, 7-Zip, PuTTY, Slack) in the usual places; a portable program or one installed elsewhere is not seen."
    )
}

// ───────────────────────────── Écran ─────────────────────────────

/// L'écran, d'après un relevé.
#[cfg(test)]
fn ecran(b: &Bilan) {
    entete();
    corps(b);
}

/// Le titre et ce que l'écran fait.
fn entete() {
    titre(tr!("Logiciels pas à jour", "Outdated software"));
    for l in envelopper(
        tr!(
            "La version installée des navigateurs, d'Office, d'Acrobat, de Java, de 7-Zip, de PuTTY et de Slack, comparée à la dernière publiée. Lecture seule : rien n'est mis à jour ici.",
            "The installed version of browsers, Office, Acrobat, Java, 7-Zip, PuTTY and Slack, compared with the latest published. Read-only: nothing is updated here."
        ),
        LARGEUR - 2,
    ) {
        println!("  {l}");
    }
}

/// Les logiciels jugés, ce qui n'a pas été vérifié, et d'où viennent les verdicts.
fn corps(b: &Bilan) {
    println!();
    let lieu = |i: &Installe| afficher_aligne("      ", &chemin_affichable(&i.lieu), 6, GRIS);
    for j in b.juges.iter().filter(|j| j.touche()) {
        afficher_aligne(&format!("  {}✖{RESET} ", couleur(Niveau::Critique)), &ligne(j), 4, "");
        lieu(&j.installe);
    }
    for j in b
        .juges
        .iter()
        .filter(|j| j.depasse() || (!j.touche() && j.vieux.is_some()))
    {
        afficher_aligne(&format!("  {}⚠{RESET} ", couleur(Niveau::Moyen)), &ligne(j), 4, "");
        lieu(&j.installe);
        if j.depasse() {
            let kev = match &b.kev {
                Ok(kev) => ligne_kev(j.installe.produit, kev),
                Err(r) => Some(trf!(
                    "Failles exploitées (catalogue de la CISA) pas vérifiées : {r}.",
                    "Exploited flaws (CISA catalog) not checked: {r}."
                )),
            };
            if let Some(t) = kev {
                afficher_aligne("      ", &t, 6, GRIS);
            }
        }
        if let Some(r) = &j.failles_non_jugees {
            afficher_aligne(
                "      ",
                &trf!("Failles une à une : {r}.", "Flaw by flaw: {r}."),
                6,
                GRIS,
            );
        }
    }
    let a_jour: Vec<String> = b.juges.iter().filter(|j| j.a_jour()).map(ligne).collect();
    if !a_jour.is_empty() {
        afficher_aligne(
            &format!("  {VERT}✔{RESET} "),
            &trf!("À jour : {}", "Up to date: {}", a_jour.join(", ")),
            4,
            "",
        );
    }
    if b.juges.is_empty() {
        afficher_aligne(&format!("  {VERT}✔{RESET} "), aucun(), 4, "");
    }
    let raisons = non_verifies(b);
    if !raisons.is_empty() {
        afficher_aligne(
            &format!("  {GRIS}?{RESET} "),
            &trf!("Non vérifiés : {}", "Not checked: {}", raisons.join(" ; ")),
            4,
            GRIS,
        );
    }
    println!();
    afficher_aligne(
        "  ",
        tr!(
            "Pour mettre à jour : ouvrir le logiciel (Aide › À propos pour un navigateur), ou Cet ordinateur › Mises à jour du système (vanguard maj).",
            "To update: open the program (Help › About for a browser), or This computer › System updates (vanguard update)."
        ),
        2,
        GRIS,
    );
    afficher_aligne("  ", &mention(b.age), 2, DISCRET);
    if !b.manques.is_empty() {
        afficher_aligne(
            "  ",
            &trf!(
                "Copies d'avant gardées : {}",
                "Previous copies kept: {}",
                b.manques.join(" ; ")
            ),
            2,
            DISCRET,
        );
    }
}

// ───────────────────────────── Lectures ─────────────────────────────

/// L'âge, en jours, du fichier qui change à chaque mise à jour d'un navigateur : son exécutable sous Windows, son
/// Info.plist sous macOS.
#[cfg(any(windows, target_os = "macos"))]
fn age_fichier(i: &Installe) -> Option<u64> {
    let chemin = if cfg!(windows) {
        let exe = match i.produit {
            Produit::Chrome => "chrome.exe",
            Produit::Edge => "msedge.exe",
            Produit::Brave => "brave.exe",
            Produit::Firefox => "firefox.exe",
            _ => return None,
        };
        i.lieu.join(exe)
    } else {
        i.lieu.join("Contents").join("Info.plist")
    };
    crate::machine::fin_de_support::age_jours(&chemin)
}

/// Le relevé de cet ordinateur : l'inventaire, les sources et le catalogue de la CISA lus en même temps (une minute
/// au pire), puis chaque logiciel jugé.
#[cfg(any(windows, target_os = "macos"))]
fn relever() -> Bilan {
    use super::sources::{self, Systeme};
    let systeme = if cfg!(windows) {
        Systeme::Windows
    } else {
        Systeme::MacOs
    };
    let coupure = sources::coupure();
    let (inventaire, releve, kev) = std::thread::scope(|portee| {
        let releve = portee.spawn(|| sources::rafraichir(systeme));
        let kev = portee.spawn(|| crate::protection::kev::catalogue_selon(coupure.as_deref()));
        #[cfg(windows)]
        let inventaire = super::windows::inventaire();
        #[cfg(target_os = "macos")]
        let inventaire = super::macos::inventaire();
        let releve = releve
            .join()
            .unwrap_or_else(|_| sources::Releve { sources: Vec::new() });
        let kev = kev
            .join()
            .unwrap_or_else(|_| Err(tr!("lecture interrompue", "reading interrupted").to_string()));
        (inventaire, releve, kev)
    });
    let faits = Faits::de(&releve, systeme, chrono::Utc::now().naive_utc());
    let mut age: Option<Duration> = None;
    let mut manques: Vec<String> = Vec::new();
    for (_, copie) in &releve.sources {
        if let Ok(c) = copie {
            age = Some(age.map_or(c.age, |a| a.max(c.age)));
            if let Some(m) = &c.manque
                && !manques.contains(m)
            {
                manques.push(m.clone());
            }
        }
    }
    Bilan {
        juges: juger_tout(inventaire.installes, &faits, &kev, &age_fichier),
        non_lus: inventaire.non_lus,
        kev,
        age,
        manques,
    }
}

/// `vanguard logiciels-perimes`.
#[cfg(any(windows, target_os = "macos"))]
pub(crate) fn afficher() {
    entete();
    afficher_aligne(
        "  ",
        tr!(
            "Lecture des versions installées et publiées (une minute au plus)…",
            "Reading installed and published versions (one minute at most)…"
        ),
        2,
        GRIS,
    );
    let debut = (chrono::Utc::now(), std::time::Instant::now());
    let b = relever();
    crate::modele::resultat::verser(&super::resultat::resultat(&b, debut));
    corps(&b);
}

/// Le relevé jugé en résultat, versé au rapport et au journal (`--json`).
#[cfg(any(windows, target_os = "macos"))]
pub(super) fn resultat_verse(
    debut: (chrono::DateTime<chrono::Utc>, std::time::Instant),
) -> crate::modele::resultat::Resultat {
    let r = super::resultat::resultat(&relever(), debut);
    crate::modele::resultat::verser(&r);
    r
}

/// Les constats du bilan : le même relevé que l'écran (téléchargé une fois par jour, sauf réglage coupé).
#[cfg(any(windows, target_os = "macos"))]
pub(crate) fn constats() -> Vec<Constat> {
    constats_de(&relever())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::protection::perimes::inventaire::{Branche, Plateforme};
    use crate::protection::perimes::sources::Systeme;
    use crate::protection::perimes::verdicts::{Lu, tests::faits};

    fn kev() -> Vec<Exploitee> {
        crate::protection::kev::analyser(include_bytes!("../../../assets/essais/kev-extrait.json")).unwrap()
    }

    fn installe(produit: Produit, version: &str, branche: Branche) -> Installe {
        let normale = match produit {
            Produit::Firefox => super::super::version::firefox(version),
            Produit::Java(_) => super::super::version::java_release(version),
            _ => Version::lire(version),
        };
        let mut i = Installe::nouveau(produit, version, normale, Path::new("/Applications/Essai.app"));
        i.branche = branche;
        i.plateforme = Plateforme::X64;
        i
    }

    /// Les couples exacts du catalogue, sur une copie réduite du vrai : Chrome for Android, l'ancien Edge et WordPad
    /// écartés.
    #[test]
    fn rapprochement_du_catalogue() {
        let kev = kev();
        let n = |p| exposition(p, &kev).0;
        assert_eq!(n(Produit::Chrome), 3);
        assert_eq!(n(Produit::Edge), 3);
        assert_eq!(n(Produit::Firefox), 3);
        assert_eq!(n(Produit::Office), 2);
        assert_eq!(n(Produit::Reader), 2);
        assert_eq!(n(Produit::Acrobat), 2);
        assert_eq!(n(Produit::Java(super::super::produits::Distribution::Temurin)), 2);
        assert_eq!(n(Produit::Brave), 0);
        assert_eq!(n(Produit::SevenZip), 1);
        assert_eq!(n(Produit::PuTTY), 0);
        // Slack embarque Chromium, mais les failles de Chromium ne se reportent pas sur lui.
        assert_eq!(n(Produit::Slack), 0);
        assert!(ligne_kev(Produit::SevenZip, &kev).is_some_and(|t| t.starts_with("7-Zip compte 1")));
        assert_eq!(
            exposition(Produit::Chrome, &kev).1,
            chrono::NaiveDate::from_ymd_opt(2026, 9, 9)
        );
        let t = ligne_kev(Produit::Edge, &kev).unwrap();
        assert!(t.contains("Edge") && t.contains('3') && t.contains("2026-09-09"), "{t}");
        assert!(ligne_kev(Produit::Brave, &kev).is_none());
    }

    /// Un index des avis inventé : la CVE de Firefox du catalogue (CVE-2024-9680) corrigée en 131.0.2 et ESR 128.3.1.
    fn faits_avec_avis() -> Faits {
        let mut f = faits(Systeme::Windows);
        let mut index = mozilla_avis::Index::default();
        let avis = mozilla_avis::avis(
            "mfsa.yml",
            b"fixed_in:\n- Firefox 131.0.2\n- Firefox ESR 128.3.1\nadvisories:\n  CVE-2024-9680:\n",
        )
        .unwrap();
        index.ajouter(&avis);
        f.avis = Ok(Lu {
            valeur: index,
            age: Duration::ZERO,
        });
        f
    }

    #[test]
    fn firefox_faille_par_faille() {
        let f = faits_avec_avis();
        let kev = Ok(kev());
        let jugés = juger_tout(
            vec![
                installe(Produit::Firefox, "131.0.1", Branche::Release),
                installe(Produit::Firefox, "128.3.1", Branche::Esr),
                installe(Produit::Firefox, "158.0.1", Branche::Inconnue),
            ],
            &f,
            &kev,
            &|_| None,
        );
        assert_eq!(
            jugés[0].failles,
            [("CVE-2024-9680".to_string(), Version::lire("131.0.2").unwrap())]
        );
        // Les deux autres failles de Firefox de la copie n'ont pas d'avis ici : dites non jugées.
        assert!(
            jugés[0]
                .failles_non_jugees
                .as_deref()
                .is_some_and(|t| t.starts_with('2'))
        );
        assert_eq!(jugés[1].failles, []);
        assert!(jugés[2].failles.is_empty() && jugés[2].a_jour());
        let t = ligne(&jugés[0]);
        assert!(
            t.contains("CVE-2024-9680") && t.contains("131.0.2") && t.contains("antérieure"),
            "{t}"
        );
        // Sans l'archive : la version seule, et pourquoi pas faille par faille.
        let sans = juger_tout(
            vec![installe(Produit::Firefox, "131.0.1", Branche::Release)],
            &faits(Systeme::Windows),
            &kev,
            &|_| None,
        );
        assert!(sans[0].failles.is_empty() && sans[0].depasse());
        assert!(
            sans[0]
                .failles_non_jugees
                .as_deref()
                .is_some_and(|t| t.contains("Mozilla"))
        );
    }

    /// Edge faille par faille, sur une liste de Microsoft inventée qui dit corrigée dans la 156 une faille de
    /// Chromium de la copie réduite du catalogue : antérieure au correctif, critique, à part de Firefox et avec sa
    /// propre façon de se mettre à jour ; l'Extended Stable n'est jamais jugé ainsi.
    #[test]
    fn edge_faille_par_faille() {
        use crate::protection::perimes::sources::editeurs::CorrectifEdge;
        let mut f = faits_avec_avis();
        if let Ok(lu) = &mut f.edge {
            lu.valeur[0].correctifs = vec![CorrectifEdge {
                version: Version::lire("156.0.4314.42").unwrap(),
                cves: Some(vec!["CVE-2099-0001".into(), "CVE-2026-87491".into()]),
            }];
        }
        let kev = Ok(kev());
        let jugés = juger_tout(
            vec![
                installe(Produit::Edge, "153.0.1.2", Branche::Inconnue),
                installe(Produit::Edge, "153.0.1.2", Branche::Canal("extended".into())),
                installe(Produit::Firefox, "131.0.1", Branche::Release),
                installe(Produit::Edge, "156.0.4314.42", Branche::Inconnue),
            ],
            &f,
            &kev,
            &|_| None,
        );
        assert_eq!(
            jugés[0].failles,
            [("CVE-2026-87491".to_string(), Version::lire("156.0.4314.42").unwrap())]
        );
        assert!(jugés[1].failles.is_empty() && jugés[1].failles_non_jugees.is_none());
        assert!(jugés[3].failles.is_empty() && jugés[3].a_jour());
        let t = ligne(&jugés[0]);
        assert!(
            t.contains("CVE-2026-87491") && t.contains("Edge 156.0.4314.42") && t.contains("antérieure"),
            "{t}"
        );
        let b = Bilan {
            juges: jugés,
            non_lus: vec![],
            kev,
            age: None,
            manques: vec![],
        };
        let c = constats_de(&b);
        let critiques: Vec<&Constat> = c.iter().filter(|c| c.probleme == Some(Niveau::Critique)).collect();
        assert_eq!(
            critiques.len(),
            2,
            "{:?}",
            c.iter().map(|c| &c.message).collect::<Vec<_>>()
        );
        assert!(critiques[0].message.contains("Firefox") && !critiques[0].message.contains("Edge 1"));
        assert!(critiques[1].message.contains("Microsoft Edge 153.0.1.2"));
        // Sans le catalogue : pas faille par faille, et pourquoi.
        let sans = juger_tout(
            vec![installe(Produit::Edge, "153.0.1.2", Branche::Inconnue)],
            &f,
            &Err("pas d'Internet ?".into()),
            &|_| None,
        );
        assert!(sans[0].failles.is_empty() && sans[0].depasse());
        assert!(
            sans[0]
                .failles_non_jugees
                .as_deref()
                .is_some_and(|t| t.contains("CISA"))
        );
    }

    fn bilan(installes: Vec<Installe>, non_lus: Vec<NonLu>, age_fichier: &dyn Fn(&Installe) -> Option<u64>) -> Bilan {
        let f = faits_avec_avis();
        let kev = Ok(kev());
        Bilan {
            juges: juger_tout(installes, &f, &kev, age_fichier),
            non_lus,
            kev,
            age: Some(Duration::from_hours(3)),
            manques: vec!["pas d'Internet ?".into()],
        }
    }

    #[test]
    fn constats_du_bilan() {
        // Tout à jour : un seul « ok » qui les nomme.
        let b = bilan(
            vec![
                installe(Produit::Chrome, "156.0.8078.48", Branche::Release),
                installe(
                    Produit::Java(super::super::produits::Distribution::Temurin),
                    "21.0.13",
                    Branche::Release,
                ),
            ],
            vec![],
            &|_| None,
        );
        let c = constats_de(&b);
        assert_eq!(c.len(), 1);
        assert!(c[0].probleme.is_none() && c[0].message.contains("Google Chrome 156.0.8078.48"));
        // Dépassés : un seul constat moyen, avec le plus exposé au catalogue ; Firefox antérieur au correctif d'une
        // faille exploitée : critique à part ; non vérifiés et comptes non lus : un seul « impossible ».
        let mut chrome = installe(Produit::Chrome, "150.0.1.2", Branche::Release);
        chrome.compte = Some("alice".into());
        let b = bilan(
            vec![
                chrome,
                installe(Produit::Reader, "26.1.21662", Branche::Release),
                installe(Produit::Firefox, "131.0.1", Branche::Release),
                installe(Produit::Edge, "150.0.1.2", Branche::Canal("extended".into())),
                installe(Produit::Acrobat, "24.1.30200", Branche::Classic),
            ],
            vec![NonLu::Comptes(2)],
            &|_| Some(10),
        );
        let c = constats_de(&b);
        let niveaux: Vec<Option<Niveau>> = c.iter().map(|c| c.probleme).collect();
        assert_eq!(
            niveaux,
            [Some(Niveau::Critique), Some(Niveau::Moyen), Some(Niveau::Info)],
            "{:?}",
            c.iter().map(|c| &c.message).collect::<Vec<_>>()
        );
        assert!(c[0].message.contains("CVE-2024-9680"));
        assert!(c[1].message.starts_with("2 logiciel(s)"), "{}", c[1].message);
        assert!(c[1].message.contains("(compte alice)") && c[1].message.contains("Chrome et Chromium compte 3"));
        assert!(
            !c[1].message.contains("Firefox"),
            "Firefox est dans le constat critique"
        );
        assert!(!c[2].verifie && c[2].message.contains("Extended") && c[2].message.contains("Classic"));
        assert!(c[2].message.contains("2 autre(s) compte(s)"));
        // Un navigateur non comparé mais vieux de 90 jours : le constat de la fin de support, un seul.
        let b = bilan(
            vec![installe(Produit::Edge, "150.0.1.2", Branche::Canal("extended".into()))],
            vec![],
            &|_| Some(90),
        );
        let c = constats_de(&b);
        assert_eq!(c.len(), 1, "{:?}", c.iter().map(|c| &c.message).collect::<Vec<_>>());
        assert!(c[0].categorie == "Navigateur" && c[0].message.contains("90"));
        // Rien de suivi : « ok » qui le dit, avec sa limite ; comptes non lus en plus : « impossible » aussi.
        let c = constats_de(&bilan(vec![], vec![], &|_| None));
        assert!(c.len() == 1 && c[0].message.contains("portable"));
        let c = constats_de(&bilan(vec![], vec![NonLu::Comptes(1)], &|_| None));
        assert_eq!(c.len(), 2);
        // Seulement des non vérifiés : jamais « ok ».
        let c = constats_de(&bilan(
            vec![installe(Produit::Office, "16.0.1.2", Branche::Inconnue)],
            vec![],
            &|_| None,
        ));
        assert!(c.len() == 1 && !c[0].verifie);
    }

    /// Sur de vraies copies, gardées à la main hors du dépôt (jamais versionnées : sources sans licence publiée ou
    /// MPL-2.0), si `VANGUARD_ESSAI_PERIMES` donne leur dossier : `firefox_versions.json`, `products` (Edge),
    /// `OfficeReleases`, `chrome-win-stable.json`, `foundation-security-advisories.tar.gz`, `kev.json`, et s'ils y
    /// sont `slack-windows.json` et `slack-macos.json`. Sans lui, rien.
    #[test]
    fn vraies_copies_si_presentes() {
        use crate::protection::perimes::sources::editeurs;
        let Some(dossier) = std::env::var_os("VANGUARD_ESSAI_PERIMES").map(std::path::PathBuf::from) else {
            return crate::essais::saute("VANGUARD_ESSAI_PERIMES non donné");
        };
        let lire = |nom: &str| std::fs::read(dossier.join(nom)).unwrap();
        let ff = editeurs::firefox(&lire("firefox_versions.json")).unwrap();
        assert!(ff.release.majeur() > 100 && !ff.esr.is_empty());
        assert!(
            editeurs::edge(&lire("products"))
                .unwrap()
                .iter()
                .any(|e| e.plateforme == "Windows")
        );
        // Chaque Edge Stable de Windows a sa liste de CVE corrigées, à leur forme.
        let edge = editeurs::edge(&lire("products")).unwrap();
        for e in edge.iter().filter(|e| e.plateforme == "Windows") {
            assert!(
                e.correctifs
                    .iter()
                    .all(|c| c.cves.as_ref().is_some_and(|l| !l.is_empty())),
                "{e:?}"
            );
        }
        let office = editeurs::office(&lire("OfficeReleases")).unwrap();
        assert!(office.iter().all(|c| !c.guids.is_empty()), "chaque canal a son GUID");
        assert!(editeurs::chrome(&lire("chrome-win-stable.json"), "win", "stable").is_some());
        for (nom, plateforme) in [("slack-windows.json", "win32"), ("slack-macos.json", "darwin")] {
            if let Ok(o) = std::fs::read(dossier.join(nom)) {
                assert!(editeurs::slack(&o, plateforme).is_some(), "{nom}");
            }
        }
        let tar =
            crate::archives::gzip::degzip_controle(&lire("foundation-security-advisories.tar.gz"), 64 << 20).unwrap();
        let index = super::super::avis_de_l_archive(&tar).unwrap();
        let kev = crate::protection::kev::analyser(&lire("kev.json")).unwrap();
        let firefox: Vec<&Exploitee> = kev
            .iter()
            .filter(|e| (Produit::Firefox.fiche().kev)(&e.editeur, &e.produit))
            .collect();
        let connues = firefox.iter().filter(|e| index.cves.contains_key(&e.cve)).count();
        println!(
            "{} avis ; {connues} des {} failles exploitées de Firefox dans l'index",
            index.avis,
            firefox.len()
        );
        assert!(index.avis > 1000 && connues * 2 > firefox.len());
        // Le Firefox d'aujourd'hui n'est antérieur à aucun correctif ; un Firefox 115.0 l'est.
        let jugés = |v: &str| {
            let v = Version::lire(v).unwrap();
            firefox
                .iter()
                .filter(|e| {
                    matches!(
                        mozilla_avis::juger(&index, &e.cve, v, mozilla_avis::BrancheFx::Release),
                        Jugement::Anterieure(_)
                    )
                })
                .count()
        };
        assert_eq!(jugés(&ff.release.to_string()), 0);
        assert!(jugés("115.0") > 0);
    }

    /// L'écran se dessine pour chaque cas sans paniquer ; la mention dit les licences et que rien ne part.
    #[test]
    fn ecran_et_mention() {
        let b = bilan(
            vec![
                installe(Produit::Chrome, "150.0.1.2", Branche::Release),
                installe(Produit::Firefox, "131.0.1", Branche::Release),
                installe(Produit::Edge, "156.0.4314.42", Branche::Release),
                installe(Produit::Brave, "", Branche::Release),
            ],
            vec![NonLu::Comptes(1)],
            &|_| Some(61),
        );
        ecran(&b);
        ecran(&bilan(vec![], vec![], &|_| None));
        let m = mention(Some(Duration::from_hours(3)));
        for attendu in [
            "endoflife.date (MIT)",
            "Homebrew (BSD-2-Clause)",
            "MPL-2.0",
            "CC0",
            "rien de cet ordinateur",
            "3 h",
            "versions-logiciels non",
        ] {
            assert!(m.contains(attendu), "{attendu} : {m}");
        }
        assert!(mention(Some(Duration::from_hours(80))).contains("3 jours"));
        assert!(!mention(None).contains("copies"));
    }

    /// T4 : le produit et la version lus, sans langue ; une autre version est une autre clé.
    #[test]
    fn cles_sans_langue() {
        let b = bilan(
            vec![
                installe(Produit::Chrome, "150.0.1.2", Branche::Release),
                installe(Produit::Firefox, "131.0.1", Branche::Release),
            ],
            vec![],
            &|_| Some(10),
        );
        let cles = crate::machine::controler_regle("WIN-MAJ-002", || constats_de(&b));
        assert_eq!(
            cles,
            [
                "WIN-MAJ-002|exploite:firefox@131.0.1",
                "WIN-MAJ-002|perimes:chrome@150.0.1.2"
            ]
        );
    }
}

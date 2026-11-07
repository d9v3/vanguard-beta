//! L'écran des Options de défense qui change les réglages (plan §3.2, §3.3) : chaque ligne montre ses valeurs et ce
//! qu'une baisse change ; les changements choisis s'accumulent, puis partent ensemble, sous une seule demande
//! d'administrateur (P7 : « Rallumer » dans la liste des renforcements, les choix dans la leur). Une baisse y est
//! montrée, puis confirmée par un oui dans la fenêtre administrateur (`eleve.rs`), jamais ici : rien de ce qui est
//! choisi à l'écran n'agit sans elle. Le résultat est relu ligne à ligne.
//!
//! Le modèle (lignes du menu et des sous-écrans, changements, textes) est pur et testé sur tous les systèmes ; la
//! boucle, qui lit Windows et demande l'administrateur, est sous `#[cfg(windows)]`.

use super::*;
use crate::machine::choix_avant::{self, Lecture, Note};
use crate::machine::gestes::{self, ChoixAsr, EmpreinteElement, Sens};
use crate::selection::Ligne;
use crate::ui::{GRAS, LARGEUR, couper, envelopper, ligne_titre};

mod pare_feu;
// Hors de Windows, seuls les essais lisent l'écran du pare-feu.
#[cfg_attr(not(windows), allow(unused_imports))]
use pare_feu::*;

/// Les notes « avant » lues (`choix_avant::notes`).
pub(super) type Notes = [(IdChoix, Option<Note>)];

/// Un changement choisi à l'écran, pas encore fait.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Change {
    pub(super) id: IdChoix,
    /// La ligne envoyée au processus élevé.
    pub(super) ligne: String,
    /// Ce qui est montré au récapitulatif et au résultat, prêt à afficher.
    pub(super) texte: String,
    /// La valeur visée, pour l'écran ; `None` pour « C'est moi », qui ne change pas la valeur.
    pub(super) cible: Option<i64>,
}

/// Ajoute un changement ; un autre déjà choisi pour le même réglage est remplacé (le dernier choix compte).
pub(super) fn ajouter(changes: &mut Vec<Change>, c: Change) {
    changes.retain(|x| x.id != c.id);
    changes.push(c);
}

/// Ce que fait un choix dans un sous-écran.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Suite {
    Ajouter(Change),
    /// La valeur actuelle choisie de nouveau : un changement déjà choisi pour ce réglage est oublié.
    Retirer(IdChoix),
    Rien,
}

pub(super) fn suivre(changes: &mut Vec<Change>, s: Suite) {
    match s {
        Suite::Ajouter(c) => ajouter(changes, c),
        Suite::Retirer(id) => changes.retain(|x| x.id != id),
        Suite::Rien => {}
    }
}

fn id_opt(o: Opt) -> IdChoix {
    IdChoix::Defender(reglage_de(o))
}

/// La valeur d'une option, comme la note la compare : pour le temps réel, l'effet relu passe avant la préférence
/// (0 allumée, 1 coupée), comme à l'écran.
pub(super) fn valeur(e: &Etat, o: Opt) -> Option<i64> {
    if o == Opt::TempsReel
        && let Some(effet) = e.statut.as_ref().and_then(|s| s.temps_reel)
    {
        return Some(i64::from(!effet));
    }
    e.preferences.as_ref().and_then(|p| p.valeur(o))
}

/// La protection contre les falsifications est-elle active (lue, pas supposée) ?
pub(super) fn tamper(e: &Etat) -> bool {
    e.statut.as_ref().and_then(|s| s.falsifications) == Some(true)
}

/// Les options que la protection contre les falsifications protège (plan §2.1 ; l'essai reste permis, la relecture
/// tranche, la liste de Microsoft change d'une version à l'autre).
pub(super) fn protegee(o: Opt) -> bool {
    matches!(
        o,
        Opt::TempsReel | Opt::Cloud | Opt::Comportement | Opt::Telechargements
    )
}

fn protegee_id(id: IdChoix) -> bool {
    Opt::TOUTES.iter().any(|o| protegee(*o) && id_opt(*o) == id)
}

/// Ce que dit la note d'une option, relue avec sa valeur actuelle ; `None` sans note.
pub(super) fn lecture(e: &Etat, o: Opt, notes: &Notes) -> Option<Lecture> {
    let id = id_opt(o);
    choix_avant::note_de(notes, id).map(|n| choix_avant::lecture_note(id, n, valeur(e, o).map(Some)))
}

/// Un élément de liste (exclusion, programme permis) présent et noté par Vanguard.
fn par_choix_element(id: IdChoix, notes: &Notes) -> Option<u64> {
    match choix_avant::lecture_note(id, choix_avant::note_de(notes, id)?, Some(Some(1))) {
        Lecture::ParChoix(d) => Some(d),
        Lecture::Remontee | Lecture::Autre => None,
    }
}

fn majuscule(t: &str) -> String {
    let mut c = t.chars();
    c.next()
        .map(|p| p.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

/// Un texte en gris, coupé à la largeur de l'écran sous un retrait de deux colonnes.
fn paragraphe(l: &mut Vec<Ligne>, texte: &str, style: &str) {
    for x in envelopper(texte, LARGEUR - 2) {
        l.push(Ligne::Texte(format!("  {style}{x}{RESET}")));
    }
}

/// La liste d'une liste lue est-elle cachée (« N/A: Must be an administrator… ») ?
fn masquee(listes: &[Vec<String>; 3]) -> bool {
    listes.iter().flatten().any(|x| x.trim_start().starts_with("N/A"))
}

/// L'en-tête : l'antivirus et la protection contre les falsifications, sur deux lignes (une seule dépasserait la
/// largeur de l'écran), puis ce qui empêche les options d'agir.
pub(super) fn en_tete(e: &Etat) -> Vec<String> {
    let (mode, s1) = match e.mode() {
        ModeDefender::Actif => (tr!("antivirus actif", "active antivirus"), VERT),
        ModeDefender::Passif => (tr!("en mode passif", "in passive mode"), ACCENT),
        ModeDefender::BlocageEdr => (tr!("passif, blocage EDR", "passive, EDR block mode"), ACCENT),
        ModeDefender::Coupe => (tr!("antivirus coupé", "antivirus off"), ACCENT),
        ModeDefender::Illisible => (
            tr!("état non vérifié (illisible)", "state not checked (unreadable)"),
            "",
        ),
    };
    let statut = e.statut.as_ref();
    let (falsif, s2) = match statut.and_then(|s| s.falsifications) {
        Some(true) => (tr!("ACTIVE", "ON"), VERT),
        Some(false) => (tr!("coupée", "off"), ACCENT),
        None => (tr!("non vérifiée", "not checked"), ""),
    };
    let mut l = vec![
        format!("  Microsoft Defender — {s1}{mode}{RESET}"),
        format!(
            "  {}{s2}{falsif}{RESET}",
            tr!("Protection contre les falsifications : ", "Tamper protection: ")
        ),
    ];
    let mut notes = Vec::new();
    if tamper(e) && statut.and_then(|s| s.source) == Some(SourceFalsif::Organisation) {
        notes.push(
            tr!(
                "Imposée par votre organisation : vous ne pouvez pas la couper vous-même.",
                "Enforced by your organization: you cannot turn it off yourself."
            )
            .to_string(),
        );
    }
    notes.extend(texte_mode(e));
    if e.gestion.geree() == Some(true) {
        notes.push(
            tr!(
                "Ce PC est géré par une organisation : elle peut remettre ses propres valeurs. Pour les changer pour de bon, voyez votre service informatique.",
                "This PC is managed by an organization: it may put its own values back. To change them for good, see your IT department."
            )
            .to_string(),
        );
    }
    for n in notes {
        note(&mut l, &n, GRIS);
    }
    l
}

/// La ligne « Exclusions » du menu : combien, dont combien posées par votre choix et combien inconnues (R8), les
/// programmes permis de l'accès contrôlé aux dossiers compris. `listes` : `None` si elles ne se lisent pas ;
/// `permis` : `None` si la liste est muette (elle ne compte alors pas, comme une liste cachée « N/A… »).
pub(super) fn resume_exclusions(listes: Option<&[Vec<String>; 3]>, permis: Option<&[String]>, notes: &Notes) -> String {
    let par_choix = notes
        .iter()
        .filter(|(id, n)| matches!(id, IdChoix::Exclusion(..) | IdChoix::DossiersAutorise(_)) && n.is_some())
        .count();
    let Some(l) = listes else {
        return if par_choix > 0 {
            trf!(
                "non vérifiées · {par_choix} par votre choix",
                "not checked · {par_choix} your choice"
            )
        } else {
            tr!("non vérifiées (illisibles)", "not checked (unreadable)").to_string()
        };
    };
    if masquee(l) {
        return if par_choix > 0 {
            trf!(
                "accord admin. requis · {par_choix} par votre choix",
                "admin approval needed · {par_choix} your choice"
            )
        } else {
            tr!("visibles avec l'accord admin.", "visible with admin approval").to_string()
        };
    }
    let permis_lus = permis
        .filter(|p| !p.iter().any(|x| x.trim_start().starts_with("N/A")))
        .unwrap_or_default()
        .iter()
        .filter(|x| !x.trim().is_empty())
        .map(|x| IdChoix::DossiersAutorise(EmpreinteElement::de(x)));
    let exclusions = GenreExclusion::TOUS.into_iter().zip(l).flat_map(|(g, liste)| {
        liste
            .iter()
            .filter(|x| !x.trim().is_empty())
            .map(move |x| IdChoix::Exclusion(g, EmpreinteElement::de(x)))
    });
    let (mut choix, mut inconnues) = (0usize, 0usize);
    for id in exclusions.chain(permis_lus) {
        if par_choix_element(id, notes).is_some() {
            choix = choix.saturating_add(1);
        } else {
            inconnues = inconnues.saturating_add(1);
        }
    }
    let inconnue = |i: usize| {
        if i > 1 {
            tr!("inconnues", "unknown")
        } else {
            tr!("inconnue", "unknown")
        }
    };
    match (choix, inconnues) {
        (0, 0) => tr!("aucune", "none").to_string(),
        (c, 0) => trf!("{c} (par votre choix)", "{c} (your choice)"),
        (0, i) => trf!("{i} ({} ⚠)", "{i} ({} ⚠)", inconnue(i)),
        (c, i) => trf!(
            "{} ({c} votre choix, {i} {} ⚠)",
            "{} ({c} your choice, {i} {} ⚠)",
            c.saturating_add(i),
            inconnue(i)
        ),
    }
}

/// La ligne « Règles ASR » du menu.
pub(super) fn resume_asr(e: &Etat) -> String {
    let Some(p) = e.preferences.as_ref() else {
        return tr!("non vérifiées (illisibles)", "not checked (unreadable)").to_string();
    };
    let compte = |a: ActionAsr| p.asr.regles.iter().filter(|(_, x)| *x == a).count();
    let (b, au, av) = (
        compte(ActionAsr::Bloque),
        compte(ActionAsr::Audit),
        compte(ActionAsr::Avertit),
    );
    // « coupées » (désactivées ou absentes) : le mot court qui tient dans les 33 caractères d'une précision.
    let coupees = ASR_TOUTES.len().saturating_sub(b.saturating_add(au).saturating_add(av));
    if av > 0 {
        trf!(
            "{b} bloquent · {au} audit · {av} avertissent · {coupees} coupées",
            "{b} block · {au} audit · {av} warn · {coupees} off"
        )
    } else {
        trf!(
            "{b} bloquent · {au} audit · {coupees} coupées",
            "{b} block · {au} audit · {coupees} off"
        )
    }
}

/// La ligne « Pare-feu » du menu : allumé partout, ou les profils coupés ; le réseau actuel nommé.
pub(super) fn resume_pare_feu(e: &Etat) -> String {
    let Some(f) = e.pare_feu else {
        return tr!("non vérifié (ne répond pas)", "not checked (no answer)").to_string();
    };
    let nom = |i: usize| {
        let courant = f.courants.is_some_and(|c| c & PROFILS.get(i).map_or(0, |p| p.1) != 0);
        if courant {
            trf!("{} (actuel)", "{} (current)", nom_profil(i))
        } else {
            nom_profil(i).to_string()
        }
    };
    let coupes: Vec<String> = (0..3)
        .filter(|&i| f.profils.get(i).and_then(|p| p.actif) == Some(false))
        .map(nom)
        .collect();
    let illisibles = f.profils.iter().filter(|p| p.actif.is_none()).count();
    if coupes.len() == 3 {
        return tr!("coupé partout", "off everywhere").to_string();
    }
    if !coupes.is_empty() {
        let t = trf!("coupé : {}", "off: {}", coupes.join(", "));
        // Une précision de menu fait 33 caractères : au-delà, le compte, et si le réseau actuel en est.
        if largeur_affichee(&t) <= 33 {
            return t;
        }
        let n = coupes.len();
        let actuel = (0..3).any(|i| {
            f.profils.get(i).and_then(|p| p.actif) == Some(false)
                && f.courants.is_some_and(|c| c & PROFILS.get(i).map_or(0, |p| p.1) != 0)
        });
        return if actuel {
            trf!("coupé : {n} profils, dont l'actuel", "off: {n} profiles, incl. current")
        } else {
            trf!("coupé : {n} profils", "off: {n} profiles")
        };
    }
    if illisibles > 0 {
        return tr!("non vérifié", "not checked").to_string();
    }
    match (0..3).find(|&i| f.courants.is_some_and(|c| c & PROFILS.get(i).map_or(0, |p| p.1) != 0)) {
        Some(i) => trf!("allumé (réseau actuel : {})", "on (current network: {})", nom_profil(i)),
        None => tr!("allumé partout", "on everywhere").to_string(),
    }
}

/// Ce que vise un changement, en mots.
fn texte_cible(c: &Change) -> String {
    match c.cible {
        Some(v) => texte_choix(c.id, Some(Some(v))),
        None => tr!("noter « votre choix »", "note “your choice”").to_string(),
    }
}

/// Les lignes `Choix` d'un menu, bornées pour que chaque rangée tienne dans `ui::LARGEUR` : la colonne des
/// précisions est celle de `selection` (le plus long texte des lignes qui ont une précision + 2, entre 36 et 48),
/// après « ► touche ».
pub(super) fn borner(lignes: &mut [Ligne]) {
    let colonne = crate::selection::colonne(lignes);
    for l in lignes.iter_mut() {
        if let Ligne::Choix {
            touche,
            texte,
            precision,
            ..
        } = l
        {
            let debut = largeur_affichee(touche).max(2).saturating_add(5);
            if precision.is_empty() {
                *texte = couper(texte, LARGEUR.saturating_sub(debut));
            } else {
                *texte = couper(texte, colonne.saturating_sub(1));
                *precision = couper(precision, LARGEUR.saturating_sub(debut.saturating_add(colonne)));
            }
        }
    }
}

/// Le menu principal (plan §3.2) : les dix options, les exclusions, les règles ASR, le pare-feu, puis Appliquer.
pub(super) fn menu(
    e: &Etat,
    notes: &Notes,
    listes: Option<&[Vec<String>; 3]>,
    permis: Option<&[String]>,
    changes: &[Change],
) -> Vec<Ligne> {
    let mut l = vec![Ligne::Texte(String::new()), Ligne::Texte(ligne_titre(titre()))];
    l.extend(en_tete(e).into_iter().map(Ligne::Texte));
    l.push(Ligne::Texte(String::new()));
    let tamper = tamper(e);
    let (mut dague, mut etoile, mut double) = (false, false, false);
    for (i, &o) in Opt::TOUTES.iter().enumerate() {
        let mut marques = String::new();
        if tamper && protegee(o) {
            marques.push('†');
            dague = true;
        }
        if e.strategies.option(o) == Some(true) {
            marques.push('*');
            etoile = true;
        }
        if matches!(lecture(e, o, notes), Some(Lecture::ParChoix(_))) {
            marques.push('‡');
            double = true;
        }
        let texte = if marques.is_empty() {
            o.libelle().to_string()
        } else {
            format!("{} {marques}", o.libelle())
        };
        let precision = match changes.iter().find(|c| c.id == id_opt(o)) {
            Some(c) => format!("→ {}", texte_cible(c)),
            None => e.etat_opt(o).texte(o.masculin()),
        };
        l.push(Ligne::choix(&i.saturating_add(1).to_string(), &texte, &precision));
    }
    let en_liste = changes.iter().filter(|c| c.id.element()).count();
    let exclusions = if en_liste > 0 {
        trf!("{en_liste} à appliquer", "{en_liste} to apply")
    } else {
        resume_exclusions(listes, permis, notes)
    };
    l.push(Ligne::choix(
        "11",
        tr!("Exclusions et programmes permis ›", "Exclusions and allowed apps ›"),
        &exclusions,
    ));
    // Court : la précision d'une ligne du menu a 33 colonnes (« changement(s) choisi(s) » y était coupé).
    let en_asr = changes.iter().filter(|c| matches!(c.id, IdChoix::Asr(_))).count();
    let asr = if en_asr > 0 {
        trf!("{en_asr} à appliquer", "{en_asr} to apply")
    } else {
        resume_asr(e)
    };
    l.push(Ligne::choix("12", tr!("Règles ASR ›", "ASR rules ›"), &asr));
    let en_pare_feu = changes.iter().filter(|c| c.id.pare_feu()).count();
    let pare_feu = if en_pare_feu > 0 {
        trf!("{en_pare_feu} à appliquer", "{en_pare_feu} to apply")
    } else {
        resume_pare_feu(e)
    };
    l.push(Ligne::choix(
        "13",
        tr!("Pare-feu Windows ›", "Windows Firewall ›"),
        &pare_feu,
    ));
    l.push(Ligne::Texte(String::new()));
    if !changes.is_empty() {
        l.push(Ligne::choix(
            "a",
            &trf!(
                "Appliquer les changements choisis ({})",
                "Apply the chosen changes ({})",
                changes.len()
            ),
            "",
        ));
        l.push(Ligne::choix(
            "x",
            tr!("Oublier les changements choisis", "Forget the chosen changes"),
            "",
        ));
    }
    l.push(Ligne::choix(
        "v",
        tr!(
            "Tout voir (détail, stratégies, gestion du PC)",
            "See everything (details, policies, PC management)"
        ),
        "",
    ));
    l.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
    let mut bas = Vec::new();
    if dague {
        bas.push(tr!(
            "† Windows refusera tant que la protection contre les falsifications est active.",
            "† Windows will refuse while tamper protection is on."
        ));
    }
    if etoile {
        bas.push(tr!(
            "* imposée par une stratégie (GPO ou Intune) : Windows garde sa valeur.",
            "* enforced by a policy (GPO or Intune): Windows keeps its value."
        ));
    }
    if double {
        bas.push(tr!(
            "‡ baissée par votre choix ; « Rallumer » dans sa ligne.",
            "‡ lowered by your choice; “Turn back on” in its line."
        ));
    }
    if !bas.is_empty() {
        l.push(Ligne::Texte(String::new()));
        for b in bas {
            paragraphe(&mut l, b, GRIS);
        }
    }
    borner(&mut l);
    l
}

/// L'option désignée par une touche du menu (« 1 » à « 10 »).
pub(super) fn opt_de_touche(touche: &str) -> Option<Opt> {
    let n: usize = touche.trim().parse().ok()?;
    Opt::TOUTES.get(n.checked_sub(1)?).copied()
}

/// « Rallumer » est-il proposé ? Avec une note, ou quand la valeur protège moins que la valeur sûre ; jamais quand
/// la cible est déjà la valeur actuelle.
fn rallumable(e: &Etat, o: Opt, notes: &Notes) -> Option<i64> {
    let id = id_opt(o);
    let note = choix_avant::note_de(notes, id);
    let v = valeur(e, o);
    let cible = gestes::cible_rallumer(id, note.map(|n| n.avant));
    let sous = v.is_some_and(|v| id.baissee(Some(v)));
    ((note.is_some() || sous) && v != Some(cible)).then_some(cible)
}

/// « C'est moi » (P11) est-il proposé ? Pour une valeur lue sous la valeur sûre, pas encore notée telle quelle.
fn notable(e: &Etat, o: Opt, notes: &Notes) -> bool {
    let id = id_opt(o);
    let v = valeur(e, o);
    v.is_some() && choix_avant::sens_noter(id, Some(v), choix_avant::note_de(notes, id)) == Sens::Baisse
}

/// Pourquoi le service de Defender, le pare-feu et le moteur de filtrage ne s'arrêtent pas (plan §2.1).
pub(super) fn texte_windefend() -> &'static str {
    tr!(
        "Vanguard ne propose pas d'arrêter le service de Defender (WinDefend) : Windows le protège et le redémarre, et l'arrêter laisserait le PC sans aucun antivirus. Pour un faux positif, une exclusion (ligne 11) vise mieux. Le service du pare-feu (mpssvc) et le moteur de filtrage (BFE) ne s'arrêtent pas non plus : le réseau serait coupé.",
        "Vanguard does not offer to stop Defender's service (WinDefend): Windows protects and restarts it, and stopping it would leave the PC with no antivirus at all. For a false positive, an exclusion (line 11) is more precise. The firewall service (mpssvc) and the filtering engine (BFE) are not stopped either: the network would be cut."
    )
}

/// Le sous-écran d'une option : son état, ce qui l'empêche d'agir, ses valeurs, « Rallumer », « C'est moi », et ce
/// qu'une baisse change (plan §3.2).
pub(super) fn lignes_option(e: &Etat, o: Opt, notes: &Notes, changes: &[Change]) -> Vec<Ligne> {
    let id = id_opt(o);
    let reglage = reglage_de(o);
    let lue = valeur(e, o);
    let masc = o.masculin();
    let mut l = vec![
        Ligne::Texte(String::new()),
        Ligne::Texte(ligne_titre(titre())),
        Ligne::Texte(format!(
            "  {GRAS}{} : {}{RESET}",
            o.libelle(),
            e.etat_opt(o).texte(masc)
        )),
    ];
    let mut infos: Vec<String> = Vec::new();
    if e.mode() != ModeDefender::Actif && e.mode() != ModeDefender::Illisible {
        infos.push(
            tr!(
                "Defender n'est pas l'antivirus actif : ce réglage n'a pas d'effet pour l'instant.",
                "Defender is not the active antivirus: this setting has no effect for now."
            )
            .to_string(),
        );
    }
    if tamper(e) && protegee(o) {
        infos.push(
            tr!(
                "(Windows refusera tant que la protection contre les falsifications est active.)",
                "(Windows will refuse while tamper protection is on.)"
            )
            .to_string(),
        );
    }
    match e.strategies.option(o) {
        Some(true) => infos.push(
            tr!(
                "Imposé par une stratégie (GPO ou Intune) : Windows garde la valeur de la stratégie, quoi que Vanguard écrive.",
                "Enforced by a policy (GPO or Intune): Windows keeps the policy's value, whatever Vanguard writes."
            )
            .to_string(),
        ),
        None => infos.push(tr!("Stratégie (GPO ou Intune) : non vérifiée.", "Policy (GPO or Intune): not checked.").to_string()),
        Some(false) => {}
    }
    match lecture(e, o, notes) {
        Some(Lecture::ParChoix(d)) => infos.push(trf!(
            "Baissée par votre choix le {}. « Rallumer » la remet.",
            "Lowered by your choice on {}. “Turn back on” restores it.",
            choix_avant::date_note(d)
        )),
        Some(Lecture::Remontee) => infos.push(
            tr!(
                "Rallumée depuis votre choix, par Windows ou par quelqu'un.",
                "Turned back on since your choice, by Windows or by someone."
            )
            .to_string(),
        ),
        Some(Lecture::Autre) | None => {}
    }
    if let Some(c) = changes.iter().find(|c| c.id == id) {
        infos.push(trf!("Déjà choisi : {}", "Already chosen: {}", c.texte));
    }
    for i in infos {
        paragraphe(&mut l, &i, GRIS);
    }
    l.push(Ligne::Texte(String::new()));
    for (k, c) in reglage.choix().iter().enumerate() {
        let cv = reglage.valeur_choix(*c);
        let precision = if lue.is_some() && cv == lue {
            tr!("(actuelle)", "(current)")
        } else if cv == Some(reglage.sure()) {
            tr!("(la valeur sûre)", "(the safe value)")
        } else {
            ""
        };
        l.push(Ligne::choix(
            &k.saturating_add(1).to_string(),
            &majuscule(&o.etat(cv).texte(masc)),
            precision,
        ));
    }
    if let Some(cible) = rallumable(e, o, notes) {
        l.push(Ligne::choix(
            "r",
            &trf!("Rallumer ({})", "Turn back on ({})", o.etat(Some(cible)).texte(masc)),
            "",
        ));
    }
    if notable(e, o, notes) {
        l.push(Ligne::choix(
            "m",
            tr!("C'est moi : noter « par votre choix »", "It was me: note “your choice”"),
            tr!("le bilan n'alertera plus", "the check stops alerting"),
        ));
    }
    l.push(Ligne::Texte(String::new()));
    paragraphe(&mut l, &effet_baisse(id), GRIS);
    if o == Opt::TempsReel {
        paragraphe(&mut l, texte_windefend(), GRIS);
    }
    l.push(Ligne::Texte(String::new()));
    l.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
    borner(&mut l);
    l
}

/// Ce que fait une touche du sous-écran d'une option.
pub(super) fn suite_option(e: &Etat, o: Opt, notes: &Notes, touche: &str) -> Suite {
    let id = id_opt(o);
    let reglage = reglage_de(o);
    let lue = valeur(e, o);
    let masc = o.masculin();
    let actuel = e.etat_opt(o).texte(masc);
    match touche.trim() {
        "r" => match rallumable(e, o, notes) {
            Some(cible) => Suite::Ajouter(Change {
                id,
                ligne: gestes::ligne_rallumer(id),
                texte: trf!(
                    "{} : {actuel} → rallumer ({})",
                    "{}: {actuel} → turn back on ({})",
                    o.libelle(),
                    o.etat(Some(cible)).texte(masc)
                ),
                cible: Some(cible),
            }),
            None => Suite::Rien,
        },
        "m" if notable(e, o, notes) => Suite::Ajouter(Change {
            id,
            ligne: gestes::ligne_noter(id),
            texte: trf!(
                "{} : {actuel}, noter « par votre choix »",
                "{}: {actuel}, note “your choice”",
                o.libelle()
            ),
            cible: None,
        }),
        t => {
            let Some(c) = t
                .parse::<usize>()
                .ok()
                .and_then(|n| n.checked_sub(1))
                .and_then(|k| reglage.choix().get(k))
            else {
                return Suite::Rien;
            };
            let cv = reglage.valeur_choix(*c);
            if lue.is_some() && cv == lue {
                return Suite::Retirer(id);
            }
            match gestes::ligne_baisse_defender(reglage, *c) {
                Some(ligne) => Suite::Ajouter(Change {
                    id,
                    ligne,
                    texte: format!("{} : {actuel} → {}", o.libelle(), o.etat(cv).texte(masc)),
                    cible: cv,
                }),
                None => Suite::Rien,
            }
        }
    }
}

// ------------------------------------------------------------------ les règles ASR (plan §2.2)

/// La valeur d'une règle ASR, comme la note la compare : `None` illisible (préférences muettes, ou action manquante),
/// `Some(None)` absente de la liste, sinon son action (0 désactivée, 1 bloque, 2 audit, 6 avertit…).
#[allow(clippy::option_option)] // None : illisible ; Some(None) : règle absente
pub(super) fn valeur_asr(e: &Etat, id: &str) -> Option<Option<i64>> {
    let p = e.preferences.as_ref()?;
    match p.asr.action(id) {
        None => Some(None),
        Some(ActionAsr::Illisible) => None,
        Some(a) => Some(a.valeur()),
    }
}

/// L'état court d'une règle, pour la colonne de la liste.
#[allow(clippy::option_option)] // None : illisible ; Some(None) : règle absente
fn etat_asr(v: Option<Option<i64>>) -> String {
    match v {
        None => tr!("non vérifiée", "not checked").to_string(),
        Some(None) => tr!("absente", "not listed").to_string(),
        Some(v) => ActionAsr::depuis(v).texte(),
    }
}

/// Ce que dit la note d'une règle, relue avec sa valeur actuelle ; `None` sans note.
fn lecture_asr(e: &Etat, id: &'static str, notes: &Notes) -> Option<Lecture> {
    let idc = IdChoix::Asr(id);
    choix_avant::note_de(notes, idc).map(|n| choix_avant::lecture_note(idc, n, valeur_asr(e, id)))
}

/// La règle est-elle imposée par une stratégie (GPO ou Intune) ? `None` : les stratégies ne se lisent pas.
fn asr_imposee(e: &Etat, id: &str) -> Option<bool> {
    e.strategies.asr.as_ref().map(|l| l.contains(&id))
}

/// « Rallumer » d'une règle : seulement avec une note (sans elle, « Bloquer » fait la même chose), et jamais vers la
/// valeur actuelle. La cible est la valeur d'avant notée, au moins audit (`gestes::cible_rallumer`).
fn rallumable_asr(e: &Etat, id: &'static str, notes: &Notes) -> Option<i64> {
    let idc = IdChoix::Asr(id);
    let note = choix_avant::note_de(notes, idc)?;
    // Illisible : proposé quand même, comme pour les options ; le processus élevé relit avant d'écrire.
    let v = valeur_asr(e, id);
    let cible = gestes::cible_rallumer(idc, Some(note.avant));
    (v != Some(Some(cible))).then_some(cible)
}

/// « C'est moi » d'une règle : listée sous « bloque » (désactivée, audit, avertit) et pas encore notée telle quelle.
/// Une règle absente n'a rien à noter : le bilan ne la signale pas.
fn notable_asr(e: &Etat, id: &'static str, notes: &Notes) -> bool {
    let idc = IdChoix::Asr(id);
    let v = valeur_asr(e, id);
    v.is_some() && choix_avant::sens_noter(idc, v, choix_avant::note_de(notes, idc)) == Sens::Baisse
}

/// Les trois groupes de la liste : les règles de base (sans revers selon Microsoft), celles des documents piégés,
/// puis les 8 que les Réglages recommandés écartent (⚠, P4).
fn groupes_asr() -> [(&'static str, &'static [&'static str]); 3] {
    [
        (
            tr!(
                "De base (sans revers, selon Microsoft)",
                "Basic (no side effects, says Microsoft)"
            ),
            &ASR_TOUTES[..3],
        ),
        (
            tr!(
                "Documents et pièces jointes piégés",
                "Booby-trapped documents and attachments"
            ),
            &ASR_TOUTES[3..11],
        ),
        (
            tr!(
                "Plus strictes (peuvent gêner, Vanguard compris)",
                "Stricter (may get in the way, Vanguard included)"
            ),
            &ASR_TOUTES[11..],
        ),
    ]
}

/// Les règles d'un groupe qu'un raccourci mettrait en blocage : celles qui ne bloquent pas déjà. Une règle imposée
/// par une stratégie est laissée (Windows garderait sa valeur : « pas fait ») ; un « C'est moi » déjà choisi aussi,
/// pour qu'un raccourci ne remplace pas en silence un choix fait règle par règle.
fn a_bloquer(e: &Etat, groupe: &[&'static str], changes: &[Change]) -> Vec<&'static str> {
    groupe
        .iter()
        .copied()
        .filter(|id| {
            let deja = changes.iter().find(|c| c.id == IdChoix::Asr(id)).map_or_else(
                || valeur_asr(e, id) == Some(Some(1)),
                |c| c.cible != Some(0) && c.cible != Some(2),
            );
            !deja && asr_imposee(e, id) != Some(true)
        })
        .collect()
}

/// La règle d'une touche de la liste (« 1 » à « 19 »).
pub(super) fn regle_de_touche(touche: &str) -> Option<&'static str> {
    let n: usize = touche.trim().parse().ok()?;
    ASR_TOUTES.get(n.checked_sub(1)?).copied()
}

/// L'écran des règles ASR : ce qui les laisse agir, les 19 règles par groupe avec leur état (ou le changement
/// choisi), deux raccourcis pour bloquer un groupe, et les marques.
pub(super) fn lignes_asr(e: &Etat, notes: &Notes, changes: &[Change]) -> Vec<Ligne> {
    let mut l = vec![
        Ligne::Texte(String::new()),
        Ligne::Texte(ligne_titre(titre())),
        Ligne::Texte(format!(
            "  {GRAS}{}{RESET}",
            tr!(
                "Règles ASR (réduction de la surface d'attaque)",
                "ASR rules (attack surface reduction)"
            )
        )),
    ];
    if e.preferences.is_none() {
        paragraphe(
            &mut l,
            tr!(
                "Non vérifiées : la liste des règles ne se lit pas. Un choix reste possible : la fenêtre administrateur relit avant d'écrire.",
                "Not checked: the rule list cannot be read. A choice is still possible: the administrator window rereads before writing."
            ),
            GRIS,
        );
    } else {
        paragraphe(&mut l, &texte_effet_asr(e), GRIS);
    }
    if let Some(n) = e.preferences.as_ref().map(|p| p.asr.inconnues).filter(|n| *n > 0) {
        paragraphe(
            &mut l,
            &trf!(
                "{n} autre(s) règle(s) que Vanguard ne connaît pas encore : laissées telles quelles.",
                "{n} other rule(s) Vanguard does not know yet: left as they are."
            ),
            GRIS,
        );
    }
    let (mut avert, mut etoile, mut double) = (false, false, false);
    let mut k = 0usize;
    for (titre_groupe, groupe) in groupes_asr() {
        l.push(Ligne::Texte(String::new()));
        l.push(Ligne::Texte(format!("  {GRIS}{titre_groupe}{RESET}")));
        for id in groupe {
            k = k.saturating_add(1);
            let mut texte = String::new();
            if avertissement_asr(id).is_some() {
                texte.push_str("⚠ ");
                avert = true;
            }
            texte.push_str(&majuscule(nom_asr(id).unwrap_or("?")));
            let mut marques = String::new();
            if asr_imposee(e, id) == Some(true) {
                marques.push('*');
                etoile = true;
            }
            if matches!(lecture_asr(e, id, notes), Some(Lecture::ParChoix(_))) {
                marques.push('‡');
                double = true;
            }
            if !marques.is_empty() {
                texte = format!("{texte} {marques}");
            }
            let precision = match changes.iter().find(|c| c.id == IdChoix::Asr(id)) {
                Some(c) => format!("→ {}", texte_cible(c)),
                None => etat_asr(valeur_asr(e, id)),
            };
            l.push(Ligne::choix(&k.to_string(), &texte, &precision));
        }
    }
    l.push(Ligne::Texte(String::new()));
    let base = a_bloquer(e, &ASR_TOUTES[..3], changes).len();
    if base > 0 {
        l.push(Ligne::choix(
            "b",
            &trf!("Bloquer les règles de base ({base})", "Block the basic rules ({base})"),
            "",
        ));
    }
    let bureau = a_bloquer(e, &ASR_TOUTES[3..11], changes).len();
    if bureau > 0 {
        l.push(Ligne::choix(
            "o",
            &trf!(
                "Bloquer les règles des documents ({bureau})",
                "Block the document rules ({bureau})"
            ),
            "",
        ));
    }
    let mut bas = Vec::new();
    if avert {
        bas.push(tr!(
            "⚠ écartée des Réglages recommandés : elle peut gêner un programme légitime. Son avertissement est dans sa ligne ; essayez d'abord Audit.",
            "⚠ left out of the Recommended settings: it may get in the way of a legitimate program. Its warning is in its line; try Audit first."
        ));
    }
    if etoile {
        bas.push(tr!(
            "* imposée par une stratégie (GPO ou Intune) : Windows garde sa valeur.",
            "* enforced by a policy (GPO or Intune): Windows keeps its value."
        ));
    }
    if double {
        bas.push(tr!(
            "‡ baissée par votre choix ; « Rallumer » dans sa ligne.",
            "‡ lowered by your choice; “Turn back on” in its line."
        ));
    }
    bas.push(tr!(
        "Avertir (l'utilisateur peut passer outre) se lit, mais Vanguard ne le propose pas : Bloquer, Audit ou Désactiver.",
        "Warn (the user may override) is read, but Vanguard does not offer it: Block, Audit or Disable."
    ));
    l.push(Ligne::Texte(String::new()));
    for b in bas {
        paragraphe(&mut l, b, GRIS);
    }
    l.push(Ligne::Texte(String::new()));
    l.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
    borner(&mut l);
    l
}

/// Ce que fait une touche de la liste des règles.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum SuiteAsr {
    /// Ouvrir le sous-écran de cette règle.
    Regle(&'static str),
    /// Bloquer un groupe : un changement par règle (des renforcements).
    Ajouter(Vec<Change>),
    Rien,
}

/// Le changement qui met une règle à `c`, depuis sa valeur lue.
fn change_asr(e: &Etat, id: &'static str, c: ChoixAsr) -> Option<Change> {
    let idc = IdChoix::Asr(id);
    let cv = c.action();
    Some(Change {
        id: idc,
        ligne: gestes::ligne_baisse_asr(id, c)?,
        texte: format!(
            "{} : {} → {}",
            nom_choix(idc),
            etat_asr(valeur_asr(e, id)),
            texte_choix(idc, Some(Some(cv)))
        ),
        cible: Some(cv),
    })
}

pub(super) fn suite_asr(e: &Etat, changes: &[Change], touche: &str) -> SuiteAsr {
    let groupe = match touche.trim() {
        "b" => &ASR_TOUTES[..3],
        "o" => &ASR_TOUTES[3..11],
        t => return regle_de_touche(t).map_or(SuiteAsr::Rien, SuiteAsr::Regle),
    };
    let l: Vec<Change> = a_bloquer(e, groupe, changes)
        .into_iter()
        .filter_map(|id| change_asr(e, id, ChoixAsr::Bloquer))
        .collect();
    if l.is_empty() {
        SuiteAsr::Rien
    } else {
        SuiteAsr::Ajouter(l)
    }
}

/// Le nom d'un choix d'une règle, au menu.
fn nom_choix_asr(c: ChoixAsr) -> &'static str {
    match c {
        ChoixAsr::Bloquer => tr!("Bloquer", "Block"),
        ChoixAsr::Audit => tr!("Audit (noter sans bloquer)", "Audit (log without blocking)"),
        ChoixAsr::Desactiver => tr!("Désactiver", "Disable"),
    }
}

/// Le sous-écran d'une règle : son état, ce qui la laisse agir, son avertissement (les 8 écartées), ses trois
/// choix, « Rallumer », « C'est moi », et ce qu'une baisse change.
pub(super) fn lignes_regle(e: &Etat, id: &'static str, notes: &Notes, changes: &[Change]) -> Vec<Ligne> {
    let idc = IdChoix::Asr(id);
    let lue = valeur_asr(e, id);
    let mut l = vec![
        Ligne::Texte(String::new()),
        Ligne::Texte(ligne_titre(titre())),
        Ligne::Texte(format!("  {GRAS}{} : {}{RESET}", nom_choix(idc), etat_asr(lue))),
        Ligne::Texte(format!("  {GRIS}{id}{RESET}")),
    ];
    let mut infos: Vec<String> = Vec::new();
    if e.preferences.is_some() && effet_asr(e) != EffetAsr::SAppliquent {
        infos.push(texte_effet_asr(e));
    }
    if asr_avec_cloud(id) && e.etat_opt(Opt::Cloud) == EtatOpt::Coupee {
        infos.push(
            tr!(
                "La protection par le cloud (ligne 2) est coupée : cette règle en a besoin, elle ne bloque rien.",
                "Cloud-delivered protection (line 2) is off: this rule needs it, it blocks nothing."
            )
            .to_string(),
        );
    }
    match asr_imposee(e, id) {
        Some(true) => infos.push(
            tr!(
                "Imposée par une stratégie (GPO ou Intune) : Windows garde la valeur de la stratégie, quoi que Vanguard écrive.",
                "Enforced by a policy (GPO or Intune): Windows keeps the policy's value, whatever Vanguard writes."
            )
            .to_string(),
        ),
        None => infos.push(tr!("Stratégie (GPO ou Intune) : non vérifiée.", "Policy (GPO or Intune): not checked.").to_string()),
        Some(false) => {}
    }
    if lue == Some(Some(6)) {
        infos.push(
            tr!(
                "En mode Avertir : Windows montre un avertissement que l'utilisateur peut passer. Vanguard le lit sans le proposer.",
                "In Warn mode: Windows shows a warning the user can skip. Vanguard reads it without offering it."
            )
            .to_string(),
        );
    }
    match lecture_asr(e, id, notes) {
        Some(Lecture::ParChoix(d)) => infos.push(trf!(
            "Baissée par votre choix le {}. « Rallumer » la remet.",
            "Lowered by your choice on {}. “Turn back on” restores it.",
            choix_avant::date_note(d)
        )),
        Some(Lecture::Remontee) => infos.push(
            tr!(
                "Rallumée depuis votre choix, par Windows ou par quelqu'un.",
                "Turned back on since your choice, by Windows or by someone."
            )
            .to_string(),
        ),
        Some(Lecture::Autre) | None => {}
    }
    if let Some(c) = changes.iter().find(|c| c.id == idc) {
        infos.push(trf!("Déjà choisi : {}", "Already chosen: {}", c.texte));
    }
    for i in infos {
        paragraphe(&mut l, &i, GRIS);
    }
    if let Some(a) = avertissement_asr(id) {
        l.push(Ligne::Texte(String::new()));
        paragraphe(&mut l, &format!("⚠ {a}"), ACCENT);
    }
    l.push(Ligne::Texte(String::new()));
    for (k, c) in ChoixAsr::TOUS.iter().enumerate() {
        let precision = if lue == Some(Some(c.action())) {
            tr!("(actuelle)", "(current)")
        } else if *c == ChoixAsr::Desactiver && lue == Some(None) {
            tr!("(absente : sans effet déjà)", "(not listed: no effect already)")
        } else if *c == ChoixAsr::Desactiver && lue == Some(Some(5)) {
            tr!("(non réglée : sans effet déjà)", "(not set: no effect already)")
        } else if c.action() == idc.sure() && avertissement_asr(id).is_none() {
            tr!("(la valeur sûre)", "(the safe value)")
        } else {
            ""
        };
        l.push(Ligne::choix(
            &k.saturating_add(1).to_string(),
            nom_choix_asr(*c),
            precision,
        ));
    }
    if let Some(cible) = rallumable_asr(e, id, notes) {
        l.push(Ligne::choix(
            "r",
            &trf!(
                "Rallumer ({})",
                "Turn back on ({})",
                texte_choix(idc, Some(Some(cible)))
            ),
            "",
        ));
    }
    if notable_asr(e, id, notes) {
        l.push(Ligne::choix(
            "m",
            tr!("C'est moi : noter « par votre choix »", "It was me: note “your choice”"),
            // Le bilan ne juge que les règles de base et celles que Vanguard a posées : pour les autres, la note ne
            // fait taire aucune alerte, elle fait seulement dire « par votre choix ».
            tr!("le bilan dira « votre choix »", "the check says “your choice”"),
        ));
    }
    l.push(Ligne::Texte(String::new()));
    paragraphe(&mut l, &effet_baisse(idc), GRIS);
    l.push(Ligne::Texte(String::new()));
    l.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
    borner(&mut l);
    l
}

/// Ce que fait une touche du sous-écran d'une règle.
pub(super) fn suite_regle(e: &Etat, id: &'static str, notes: &Notes, touche: &str) -> Suite {
    let idc = IdChoix::Asr(id);
    let lue = valeur_asr(e, id);
    match touche.trim() {
        "r" => match rallumable_asr(e, id, notes) {
            Some(cible) => Suite::Ajouter(Change {
                id: idc,
                ligne: gestes::ligne_rallumer(idc),
                texte: trf!(
                    "{} : {} → rallumer ({})",
                    "{}: {} → turn back on ({})",
                    nom_choix(idc),
                    etat_asr(lue),
                    texte_choix(idc, Some(Some(cible)))
                ),
                cible: Some(cible),
            }),
            None => Suite::Rien,
        },
        "m" if notable_asr(e, id, notes) => Suite::Ajouter(Change {
            id: idc,
            ligne: gestes::ligne_noter(idc),
            texte: trf!(
                "{} : {}, noter « par votre choix »",
                "{}: {}, note “your choice”",
                nom_choix(idc),
                etat_asr(lue)
            ),
            cible: None,
        }),
        t => {
            let Some(c) = t
                .parse::<usize>()
                .ok()
                .and_then(|n| n.checked_sub(1))
                .and_then(|k| ChoixAsr::TOUS.get(k))
            else {
                return Suite::Rien;
            };
            if lue == Some(Some(c.action())) {
                return Suite::Retirer(idc);
            }
            change_asr(e, id, *c).map_or(Suite::Rien, Suite::Ajouter)
        }
    }
}

/// Ce que fait une touche du sous-écran des exclusions.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum ActionListe {
    /// Demander le texte d'une exclusion de ce genre.
    Ajouter(GenreExclusion),
    /// Demander un programme à permettre malgré l'accès contrôlé aux dossiers.
    Permettre,
    /// Retirer un élément posé par votre choix (« Rallumer » d'un élément : l'absence).
    Retirer(IdChoix, String),
    /// « C'est moi » pour un élément inconnu.
    Noter(IdChoix, String),
}

/// Un élément noté, quand la liste ne se lit pas : son genre et le début de son empreinte (jamais le chemin, que la
/// note ne garde pas).
fn nom_note(id: IdChoix) -> String {
    let (genre, hex) = match id {
        IdChoix::Exclusion(g, e) => (nom_genre(g).to_string(), e.hex()),
        IdChoix::DossiersAutorise(e) => (tr!("programme permis", "allowed app").to_string(), e.hex()),
        IdChoix::PareFeuRegle(_, e) => (tr!("règle du pare-feu", "firewall rule").to_string(), e.hex()),
        IdChoix::Defender(_) | IdChoix::Asr(_) | IdChoix::PareFeu(..) => return nom_choix(id),
    };
    format!("{genre} n° {}", hex.get(..8).unwrap_or(&hex))
}

/// La précision d'une note dont l'élément n'a pas pu être relu (liste cachée hors administrateur, ou jamais relue) :
/// il a pu être retiré ailleurs depuis, la note ne s'efface qu'au prochain passage en administrateur.
fn a_verifier() -> &'static str {
    tr!("à vérifier · retirer", "to check · remove")
}

/// Le sous-écran des exclusions et des programmes permis : ce qui est noté (à retirer), ce qui est inconnu (⚠, « C'est
/// moi »), puis ajouter. `listes` : les trois listes lues (`None` : illisibles).
pub(super) fn lignes_exclusions(
    listes: Option<&[Vec<String>; 3]>,
    permis: Option<&[String]>,
    notes: &Notes,
    changes: &[Change],
) -> (Vec<Ligne>, Vec<(String, ActionListe)>) {
    let mut l = vec![
        Ligne::Texte(String::new()),
        Ligne::Texte(ligne_titre(titre())),
        Ligne::Texte(format!(
            "  {GRAS}{}{RESET}",
            tr!(
                "Exclusions de l'analyse et programmes permis",
                "Scan exclusions and allowed apps"
            )
        )),
        Ligne::Texte(String::new()),
    ];
    let mut actions = Vec::new();
    let n = std::cell::Cell::new(0usize);
    let touche = |prefixe: &str| {
        n.set(n.get().saturating_add(1));
        format!("{prefixe}{}", n.get())
    };
    let lisibles = listes.filter(|x| !masquee(x));
    let mut inconnue = false;
    if let Some(listes) = lisibles {
        for (g, liste) in GenreExclusion::TOUS.into_iter().zip(listes) {
            for x in liste.iter().filter(|x| !x.trim().is_empty()) {
                let id = IdChoix::Exclusion(g, EmpreinteElement::de(x));
                let montre = format!("{} : {}", majuscule(nom_genre(g)), externe(x));
                if let Some(d) = par_choix_element(id, notes) {
                    let t = touche("r");
                    l.push(Ligne::choix(
                        &t,
                        &montre,
                        &trf!(
                            "votre choix ({}) · retirer",
                            "your choice ({}) · remove",
                            choix_avant::date_note(d)
                        ),
                    ));
                    actions.push((t, ActionListe::Retirer(id, externe(x))));
                } else {
                    inconnue = true;
                    let t = touche("m");
                    l.push(Ligne::choix(
                        &t,
                        &format!("⚠ {montre}"),
                        tr!("inconnue · c'est moi ?", "unknown · was it me?"),
                    ));
                    actions.push((t, ActionListe::Noter(id, externe(x))));
                }
            }
        }
        if n.get() == 0 {
            l.push(Ligne::Texte(format!(
                "  {GRIS}{}{RESET}",
                tr!("Aucune exclusion de l'analyse.", "No scan exclusion.")
            )));
        }
    } else {
        let texte = if listes.is_some() {
            tr!(
                "Liste visible seulement avec l'accord administrateur : les exclusions posées hors de Vanguard ne se voient pas ici (le bilan en administrateur les signale). Celles notées par votre choix sont listées sans leur chemin, « à vérifier » : retirées ailleurs, leur note ne s'efface qu'au prochain passage en administrateur.",
                "List visible only with administrator approval: exclusions added outside Vanguard are not shown here (the check as administrator reports them). Those noted as your choice are listed without their path, “to check”: removed elsewhere, their note is only cleared at the next run as administrator."
            )
        } else {
            tr!(
                "Les exclusions ne se lisent pas (Defender ne répond pas). Celles notées par votre choix sont listées sans leur chemin, « à vérifier ».",
                "Exclusions cannot be read (Defender does not answer). Those noted as your choice are listed without their path, “to check”."
            )
        };
        paragraphe(&mut l, texte, GRIS);
        for (id, note) in notes {
            if let (IdChoix::Exclusion(..), Some(_)) = (id, note) {
                let t = touche("r");
                l.push(Ligne::choix(&t, &nom_note(*id), a_verifier()));
                actions.push((t, ActionListe::Retirer(*id, nom_note(*id))));
            }
        }
    }
    // Les programmes permis de l'accès contrôlé aux dossiers, relus comme les exclusions (M2 de la relecture D3) :
    // chacun se retire s'il est noté, se note sinon. Cachée (« N/A… ») ou muette, la liste laisse les notes « à
    // vérifier », comme avant.
    let permis_lus = permis.filter(|p| !p.iter().any(|x| x.trim_start().starts_with("N/A")));
    let mut permis_inconnu = false;
    if let Some(p) = permis_lus {
        for x in p.iter().filter(|x| !x.trim().is_empty()) {
            let id = IdChoix::DossiersAutorise(EmpreinteElement::de(x));
            let montre = trf!("Programme permis : {}", "Allowed app: {}", externe(x));
            if let Some(d) = par_choix_element(id, notes) {
                let t = touche("r");
                l.push(Ligne::choix(
                    &t,
                    &montre,
                    &trf!(
                        "votre choix ({}) · retirer",
                        "your choice ({}) · remove",
                        choix_avant::date_note(d)
                    ),
                ));
                actions.push((t, ActionListe::Retirer(id, externe(x))));
            } else {
                permis_inconnu = true;
                let t = touche("m");
                l.push(Ligne::choix(
                    &t,
                    &format!("⚠ {montre}"),
                    tr!("inconnu · c'est moi ?", "unknown · was it me?"),
                ));
                actions.push((t, ActionListe::Noter(id, externe(x))));
            }
        }
    } else {
        for (id, note) in notes {
            if let (IdChoix::DossiersAutorise(_), Some(_)) = (id, note) {
                let t = touche("r");
                l.push(Ligne::choix(&t, &nom_note(*id), a_verifier()));
                actions.push((t, ActionListe::Retirer(*id, nom_note(*id))));
            }
        }
    }
    if inconnue {
        paragraphe(
            &mut l,
            tr!(
                "⚠ inconnue : posée hors de Vanguard. Si c'est vous, « c'est moi » la note et le bilan cesse de la signaler. Sinon, retirez-la dans Sécurité Windows (Protection contre les virus et menaces › Gérer les paramètres › Exclusions), puis lancez une analyse complète.",
                "⚠ unknown: added outside Vanguard. If it was you, “was it me” notes it and the check stops reporting it. Otherwise, remove it in Windows Security (Virus & threat protection › Manage settings › Exclusions), then run a full scan."
            ),
            GRIS,
        );
    }
    if permis_inconnu {
        paragraphe(
            &mut l,
            tr!(
                "⚠ programme permis inconnu : il écrit dans les dossiers protégés malgré la protection contre les rançongiciels. Si c'est vous, « c'est moi » le note. Sinon, retirez-le dans Sécurité Windows (Protection contre les rançongiciels › Autoriser une application via l'accès contrôlé aux dossiers).",
                "⚠ unknown allowed app: it writes to protected folders despite ransomware protection. If it was you, “was it me” notes it. Otherwise, remove it in Windows Security (Ransomware protection › Allow an app through Controlled folder access)."
            ),
            GRIS,
        );
    }
    // Les limites de l'empreinte (F7 de la relecture D3), dites plutôt que tues.
    paragraphe(
        &mut l,
        tr!(
            "Limites : deux éléments au même texte (sans tenir compte des majuscules) partagent une seule note. Windows peut réécrire un chemin (nom court, variable comme %USERPROFILE%) : la note ne le reconnaît plus, et il revient « inconnu ». Sans droits administrateur, les listes sont invisibles.",
            "Limits: two items with the same text (ignoring case) share one note. Windows may rewrite a path (short name, variable like %USERPROFILE%): the note no longer recognizes it, and it comes back “unknown”. Without administrator rights, the lists are invisible."
        ),
        GRIS,
    );
    let a_faire: Vec<&Change> = changes.iter().filter(|c| c.id.element()).collect();
    if !a_faire.is_empty() {
        l.push(Ligne::Texte(String::new()));
        l.push(Ligne::Texte(format!("  {}", tr!("Déjà choisis :", "Already chosen:"))));
        for c in a_faire {
            for (k, x) in envelopper(&c.texte, LARGEUR - 6).into_iter().enumerate() {
                let puce = if k == 0 { "  · " } else { "    " };
                l.push(Ligne::Texte(format!("  {puce}{x}")));
            }
        }
    }
    l.push(Ligne::Texte(String::new()));
    for (t, texte, a) in [
        (
            "a",
            tr!("Exclure un dossier ou un fichier", "Exclude a folder or file"),
            ActionListe::Ajouter(GenreExclusion::Chemin),
        ),
        (
            "p",
            tr!(
                "Exclure un programme (par son nom ou son chemin)",
                "Exclude a program (by name or path)"
            ),
            ActionListe::Ajouter(GenreExclusion::Processus),
        ),
        (
            "t",
            tr!(
                "Exclure un type de fichier (extension)",
                "Exclude a file type (extension)"
            ),
            ActionListe::Ajouter(GenreExclusion::Extension),
        ),
        (
            "d",
            tr!(
                "Permettre un programme (accès contrôlé aux dossiers)",
                "Allow an app (controlled folder access)"
            ),
            ActionListe::Permettre,
        ),
    ] {
        l.push(Ligne::choix(t, texte, ""));
        actions.push((t.to_string(), a));
    }
    l.push(Ligne::Texte(String::new()));
    paragraphe(
        &mut l,
        &effet_baisse(IdChoix::Exclusion(GenreExclusion::Chemin, EmpreinteElement::de(""))),
        GRIS,
    );
    l.push(Ligne::Texte(String::new()));
    l.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
    borner(&mut l);
    (l, actions)
}

/// Le changement d'un élément de liste choisi au sous-écran des exclusions ; `texte`, ce que la personne a tapé
/// pour un ajout. `None` pour un texte refusé (vide, trop long, caractère de contrôle).
pub(super) fn change_liste(a: &ActionListe, texte: &str) -> Option<Change> {
    match a {
        ActionListe::Ajouter(g) => {
            let t = texte_exclusion(*g, texte);
            Some(Change {
                id: IdChoix::Exclusion(*g, EmpreinteElement::de(t)),
                ligne: ligne_exclusion(*g, t)?,
                texte: texte_ajout_exclusion(*g, t),
                cible: Some(1),
            })
        }
        ActionListe::Permettre => {
            let t = texte.trim();
            Some(Change {
                id: IdChoix::DossiersAutorise(EmpreinteElement::de(t)),
                ligne: ligne_permettre(t)?,
                texte: texte_autoriser_dossiers(t),
                cible: Some(1),
            })
        }
        ActionListe::Retirer(id, montre) => Some(Change {
            id: *id,
            ligne: gestes::ligne_rallumer(*id),
            texte: trf!("{} « {montre} » : RETIRER", "{} “{montre}”: REMOVE", nom_choix(*id)),
            cible: Some(0),
        }),
        ActionListe::Noter(id, montre) => Some(Change {
            id: *id,
            ligne: gestes::ligne_noter(*id),
            texte: trf!(
                "{} « {montre} » : noter « par votre choix »",
                "{} “{montre}”: note “your choice”",
                nom_choix(*id)
            ),
            cible: None,
        }),
    }
}

/// Faut-il dire l'avertissement d'une exclusion large avant de l'ajouter (R8) ?
pub(super) fn large(a: &ActionListe, texte: &str) -> bool {
    match a {
        ActionListe::Ajouter(g) => gestes::exclusion_large(*g, texte_exclusion(*g, texte)),
        // Permettre un interpréteur (PowerShell, cmd…) ou un joker ouvre vos dossiers à tout ce qu'il lance.
        ActionListe::Permettre => gestes::exclusion_large(GenreExclusion::Processus, texte),
        ActionListe::Retirer(..) | ActionListe::Noter(..) => false,
    }
}

/// Le récapitulatif de tous les changements choisis, avant la demande d'administrateur (plan §3.2).
pub(super) fn recapitulatif(changes: &[Change]) -> Vec<String> {
    let mut l = vec![format!(
        "  {GRAS}{}{RESET}",
        trf!("Les {} changements choisis :", "The {} chosen changes:", changes.len())
    )];
    for c in changes {
        for (k, x) in envelopper(&c.texte, LARGEUR - 4).into_iter().enumerate() {
            let puce = if k == 0 { "  · " } else { "    " };
            l.push(format!("{puce}{x}"));
        }
    }
    let baisses = changes.iter().any(|c| {
        // Comme le processus élevé (`gestes::sens`), qui demande aussi pour « toujours demander » des échantillons :
        // un changement vers plus bas que la valeur sûre est montré, puis demandé.
        c.cible
            .is_none_or(|v| c.id.rang(Some(v)) < c.id.rang(Some(c.id.sure())))
    });
    if baisses {
        for x in envelopper(
            tr!(
                "Ce qui baisse votre protection vous sera montré, puis demandé (o/N), dans la fenêtre administrateur.",
                "What lowers your protection will be shown, then asked (y/N), in the administrator window."
            ),
            LARGEUR - 2,
        ) {
            l.push(format!("  {GRIS}{x}{RESET}"));
        }
    }
    l.push(format!(
        "  {}",
        tr!(
            "Il faut l'accord d'un administrateur (fenêtre de Windows).",
            "An administrator's approval is needed (Windows prompt)."
        )
    ));
    l
}

/// L'issue d'un changement, d'après la réponse du processus élevé (qui relit après avoir écrit).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Issue {
    Fait,
    /// Déjà à la valeur demandée : rien d'écrit.
    Deja,
    PasFait,
    /// Pas fait, à la demande de la personne : « non » à la question, ou demande d'administrateur refusée.
    Arretee,
    /// Pas fait, sur une option que la protection contre les falsifications protège, alors qu'elle est active.
    Tamper,
}

/// Ce que le passage élevé rend pour un changement : réussi ; réussi sans rien écrire (déjà ainsi) ; arrêté à la
/// demande de la personne.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Rendu {
    pub(super) reussi: bool,
    pub(super) rien: bool,
    pub(super) arrete: bool,
}

/// `tamper` : la protection contre les falsifications peut être la cause d'un refus (`tamper_en_cause`). Un refus
/// de la personne n'est jamais un refus de Windows : la page de la protection ne s'ouvre pas pour lui.
pub(super) fn issue(c: &Change, r: Rendu, tamper: bool) -> Issue {
    if r.reussi {
        if r.rien { Issue::Deja } else { Issue::Fait }
    } else if r.arrete {
        Issue::Arretee
    } else if tamper && protegee_id(c.id) {
        Issue::Tamper
    } else {
        Issue::PasFait
    }
}

/// La protection contre les falsifications peut-elle avoir refusé ce changement ? Active avant ou après, et l'option
/// n'est pas imposée par une stratégie (GPO ou Intune) : là, c'est la stratégie qui garde la valeur.
pub(super) fn tamper_en_cause(avant: &Etat, apres: &Etat, id: IdChoix) -> bool {
    let imposee = Opt::TOUTES.iter().any(|o| {
        id_opt(*o) == id && (apres.strategies.option(*o) == Some(true) || avant.strategies.option(*o) == Some(true))
    });
    (tamper(avant) || tamper(apres)) && !imposee
}

pub(super) fn texte_issue(c: &Change, i: Issue) -> String {
    match i {
        Issue::Fait => trf!("  {VERT}✔{RESET} {} : fait", "  {VERT}✔{RESET} {}: done", c.texte),
        Issue::Deja => trf!(
            "  {VERT}✔{RESET} {} : déjà ainsi, rien d'écrit",
            "  {VERT}✔{RESET} {}: already so, nothing written",
            c.texte
        ),
        Issue::PasFait => trf!(
            "  {ACCENT}✖{RESET} {} : pas fait (Windows a refusé, ou la relecture n'a pas suivi : voir la fenêtre administrateur)",
            "  {ACCENT}✖{RESET} {}: not done (Windows refused, or the reread did not follow: see the administrator window)",
            c.texte
        ),
        Issue::Arretee => trf!(
            "  {GRIS}–{RESET} {} : pas fait, à votre demande (réponse non, ou demande d'administrateur refusée)",
            "  {GRIS}–{RESET} {}: not done, as you asked (answer no, or administrator prompt declined)",
            c.texte
        ),
        Issue::Tamper => trf!(
            "  {ACCENT}✖{RESET} {} : Windows a refusé (protection contre les falsifications)",
            "  {ACCENT}✖{RESET} {}: Windows refused (tamper protection)",
            c.texte
        ),
    }
}

/// Le texte d'un refus dû à la protection contre les falsifications (plan §3.3).
pub(super) fn texte_tamper() -> &'static str {
    tr!(
        "Windows a refusé ce changement : la protection contre les falsifications est active. Elle empêche tout programme, Vanguard compris, de toucher à ce réglage de Defender. Seule une personne peut la couper, à la main. Vanguard ouvre la page où elle se trouve (Sécurité Windows › Protection contre les virus et menaces › Gérer les paramètres › Protection contre les falsifications). Coupez-la, revenez ici et refaites votre choix. Pensez à la rallumer ensuite : elle protège Defender contre les virus qui veulent le couper.",
        "Windows refused this change: tamper protection is on. It stops any program, Vanguard included, from changing this Defender setting. Only a person can turn it off, by hand. Vanguard opens the page where it lives (Windows Security › Virus & threat protection › Manage settings › Tamper Protection). Turn it off, come back here and make your choice again. Remember to turn it back on afterwards: it protects Defender from viruses that try to turn it off."
    )
}

/// La page de Sécurité Windows où se coupe la protection contre les falsifications, la seule que ce lot ouvre.
pub(super) const PAGE_TAMPER: &str = "windowsdefender://threatsettings";

// ------------------------------------------------------------------ la boucle (Windows)

#[cfg(windows)]
mod boucle {
    use super::*;

    /// Tout ce que l'écran lit, relu après chaque application.
    struct Lu {
        etat: Etat,
        notes: Vec<(IdChoix, Option<Note>)>,
        listes: Option<[Vec<String>; 3]>,
        /// Les programmes permis de l'accès contrôlé aux dossiers, par WMI (`None` : muet).
        permis: Option<Vec<String>>,
    }

    fn lire() -> Lu {
        Lu {
            etat: crate::machine::windows::defense_etat::lire(),
            notes: choix_avant::notes(),
            // Comme l'audit : WMI d'abord, PowerShell en secours si Defender ne répond pas par WMI.
            listes: crate::machine::windows::exclusions::lecture().map(|(l, _)| l),
            permis: crate::machine::windows::exclusions::programmes_permis(),
        }
    }

    fn invite() -> &'static str {
        tr!("  Votre choix (Entrée : revenir) : ", "  Your choice (Enter: back): ")
    }

    fn retour(c: &str) -> bool {
        c.is_empty() || c == "↵" || c.eq_ignore_ascii_case("q")
    }

    /// L'écran, jusqu'à ce que la personne revienne ; des changements choisis et pas faits sont proposés une dernière
    /// fois (jamais faits sans qu'elle le dise).
    pub(in crate::options_defense) fn ecran() {
        let mut lu = lire();
        let mut changes: Vec<Change> = Vec::new();
        let mut depart = "1".to_string();
        loop {
            let lignes = menu(&lu.etat, &lu.notes, lu.listes.as_ref(), lu.permis.as_deref(), &changes);
            let choix = crate::selection::choisir(&lignes, invite(), &depart, tr!("revenir", "back"));
            let c = choix.as_deref().map_or("", str::trim);
            if retour(c) {
                if !changes.is_empty() {
                    let q = trf!(
                        "\n  Appliquer les {} changements choisis avant de revenir ? [o/N] : ",
                        "\n  Apply the {} chosen changes before going back? [y/N]: ",
                        changes.len()
                    );
                    if crate::langue::oui(&crate::ui::demander_ou_defaut(&q)) {
                        appliquer(&mut changes, &lu);
                    }
                }
                return;
            }
            depart = c.to_string();
            match c {
                "a" if !changes.is_empty() => {
                    appliquer(&mut changes, &lu);
                    lu = lire();
                }
                "x" => changes.clear(),
                "v" => voir(&lu.etat),
                "11" => exclusions(&lu, &mut changes),
                "12" => asr(&lu, &mut changes),
                "13" => pare_feu(&lu, &mut changes),
                t => {
                    if let Some(o) = opt_de_touche(t) {
                        option(&lu, o, &mut changes);
                    }
                }
            }
        }
    }

    fn option(lu: &Lu, o: Opt, changes: &mut Vec<Change>) {
        let lignes = lignes_option(&lu.etat, o, &lu.notes, changes);
        let Some(c) = crate::selection::choisir(&lignes, invite(), "", tr!("revenir", "back")) else {
            return;
        };
        if !retour(c.trim()) {
            suivre(changes, suite_option(&lu.etat, o, &lu.notes, &c));
        }
    }

    fn exclusions(lu: &Lu, changes: &mut Vec<Change>) {
        let (lignes, actions) = lignes_exclusions(lu.listes.as_ref(), lu.permis.as_deref(), &lu.notes, changes);
        let Some(c) = crate::selection::choisir(&lignes, invite(), "", tr!("revenir", "back")) else {
            return;
        };
        let Some((_, a)) = actions.iter().find(|(t, _)| *t == c.trim()) else {
            return;
        };
        let texte = match a {
            ActionListe::Ajouter(g) => crate::ui::demander_ou_defaut(&trf!(
                "\n  {} à exclure (Entrée : rien) : ",
                "\n  {} to exclude (Enter: nothing): ",
                majuscule(nom_genre(*g))
            )),
            ActionListe::Permettre => crate::ui::demander_ou_defaut(tr!(
                "\n  Chemin complet du programme à permettre (Entrée : rien) : ",
                "\n  Full path of the app to allow (Enter: nothing): "
            )),
            ActionListe::Retirer(..) | ActionListe::Noter(..) => String::new(),
        };
        if matches!(a, ActionListe::Ajouter(_) | ActionListe::Permettre) && texte.trim().is_empty() {
            return;
        }
        if large(a, &texte) {
            println!();
            crate::ui::afficher_aligne("  ", avertissement_large(), 2, ACCENT);
            let q = tr!(
                "  La garder dans les changements choisis ? [o/N] : ",
                "  Keep it in the chosen changes? [y/N]: "
            );
            if !crate::langue::oui(&crate::ui::demander_ou_defaut(q)) {
                return;
            }
        }
        if let Some(ch) = change_liste(a, &texte) {
            ajouter(changes, ch);
        } else {
            crate::trp!(
                "  {ACCENT}Texte refusé (vide, trop long ou avec un caractère de contrôle).{RESET}",
                "  {ACCENT}Text refused (empty, too long or with a control character).{RESET}"
            );
            crate::selection::attendre_retour(tr!("  Entrée pour revenir… ", "  Enter to go back… "));
        }
    }

    fn voir(e: &Etat) {
        crate::ui::titre(titre());
        for l in lignes(e) {
            println!("{l}");
        }
        println!();
        crate::selection::attendre_retour(tr!("  Entrée pour revenir… ", "  Enter to go back… "));
    }

    /// Les règles ASR : la liste, puis le sous-écran d'une règle, jusqu'au retour. Les choix rejoignent les
    /// changements du menu et partent avec eux, sous la même demande d'administrateur.
    fn asr(lu: &Lu, changes: &mut Vec<Change>) {
        let mut depart = String::new();
        loop {
            let lignes = lignes_asr(&lu.etat, &lu.notes, changes);
            let Some(c) = crate::selection::choisir(&lignes, invite(), &depart, tr!("revenir", "back")) else {
                return;
            };
            let c = c.trim();
            if retour(c) {
                return;
            }
            depart = c.to_string();
            match suite_asr(&lu.etat, changes, c) {
                SuiteAsr::Regle(id) => regle(lu, id, changes),
                SuiteAsr::Ajouter(l) => {
                    for ch in l {
                        ajouter(changes, ch);
                    }
                }
                SuiteAsr::Rien => {}
            }
        }
    }

    fn regle(lu: &Lu, id: &'static str, changes: &mut Vec<Change>) {
        let lignes = lignes_regle(&lu.etat, id, &lu.notes, changes);
        let Some(c) = crate::selection::choisir(&lignes, invite(), "", tr!("revenir", "back")) else {
            return;
        };
        if !retour(c.trim()) {
            suivre(changes, suite_regle(&lu.etat, id, &lu.notes, &c));
        }
    }

    /// Le pare-feu (D5) : les réglages des trois profils, puis les règles trouvées par une recherche. Les choix
    /// rejoignent les changements du menu et partent avec eux, sous la même demande d'administrateur.
    fn pare_feu(lu: &Lu, changes: &mut Vec<Change>) {
        let mut depart = String::new();
        loop {
            let lignes = lignes_pare_feu(&lu.etat, &lu.notes, changes);
            let Some(c) = crate::selection::choisir(&lignes, invite(), &depart, tr!("revenir", "back")) else {
                return;
            };
            let c = c.trim();
            if retour(c) {
                return;
            }
            depart = c.to_string();
            match suite_pare_feu(&lu.etat, &lu.notes, c) {
                SuitePf::Reglage(p, r) => {
                    let lignes = lignes_reglage_pf(&lu.etat, p, r, &lu.notes, changes);
                    if let Some(t) = crate::selection::choisir(&lignes, invite(), "", tr!("revenir", "back"))
                        && !retour(t.trim())
                    {
                        suivre(changes, suite_reglage_pf(&lu.etat, p, r, &lu.notes, &t));
                    }
                }
                SuitePf::Regles => regles(lu, changes),
                SuitePf::Voir => voir_pare_feu(&lu.etat),
                SuitePf::Ajouter(l) => {
                    for ch in l {
                        ajouter(changes, ch);
                    }
                }
                SuitePf::Rien => {}
            }
        }
    }

    /// Les règles existantes : une recherche, la liste (20 au plus), puis une règle choisie se bascule. Les règles
    /// sont relues à chaque recherche.
    fn regles(lu: &Lu, changes: &mut Vec<Change>) {
        let recherche = crate::ui::demander_ou_defaut(tr!(
            "\n  Chercher (nom, programme, groupe ou port ; Entrée : revenir) : ",
            "\n  Search (name, program, group or port; Enter: back): "
        ));
        if recherche.trim().is_empty() {
            return;
        }
        let lues = crate::machine::windows::pare_feu::regles_lues();
        loop {
            let lignes = lignes_regles(lues.as_deref(), &recherche, &lu.notes, changes);
            let Some(c) = crate::selection::choisir(&lignes, invite(), "", tr!("revenir", "back")) else {
                return;
            };
            if retour(c.trim()) {
                return;
            }
            let Some(l) = lues.as_deref() else {
                return;
            };
            suivre(changes, suite_regles(l, &recherche, changes, &c));
        }
    }

    /// Le détail du pare-feu en lecture : les profils, le Centre de sécurité, la gestion du PC.
    fn voir_pare_feu(e: &Etat) {
        crate::ui::titre(titre());
        let mut l = Vec::new();
        section_pare_feu(&mut l, e);
        section_centre(&mut l, e);
        section_gestion(&mut l, e);
        for x in l {
            println!("{x}");
        }
        println!();
        crate::selection::attendre_retour(tr!("  Entrée pour revenir… ", "  Enter to go back… "));
    }

    /// Le récapitulatif, une seule demande d'administrateur pour tous les changements (un correctif par changement :
    /// le processus élevé met « Rallumer » dans la liste des renforcements et les choix dans la leur, P7), puis le
    /// résultat relu ligne à ligne. Les changements sont oubliés ensuite, faits ou non : l'écran relu montre où en
    /// est chacun.
    fn appliquer(changes: &mut Vec<Change>, lu: &Lu) {
        crate::ui::titre(titre());
        for l in recapitulatif(changes) {
            println!("{l}");
        }
        println!();
        let correctifs: Vec<Vec<String>> = changes.iter().map(|c| vec![c.ligne.clone()]).collect();
        let (reussis, notes) = crate::machine::appliquer_chacune_notees(&correctifs);
        // Un correctif par ligne élevée, sans point de restauration : le passage élevé les reçoit dans cet ordre. S'il
        // n'a rien reçu (lancement impossible), rien n'est imputé à la protection contre les falsifications.
        let arretes = crate::machine::windows::correctifs_arretes();
        let passe = arretes.len() == changes.len();
        let apres = crate::machine::windows::defense_etat::lire();
        println!();
        let mut refus_tamper = false;
        for (k, c) in changes.iter().enumerate() {
            let reussi = reussis.get(k).copied().unwrap_or(false);
            let rendu = Rendu {
                reussi,
                rien: reussi && notes.get(k).is_some_and(Vec::is_empty),
                arrete: if passe {
                    arretes.get(k).copied().unwrap_or(false)
                } else {
                    crate::machine::arretee_a_votre_demande()
                },
            };
            let i = issue(c, rendu, passe && tamper_en_cause(&lu.etat, &apres, c.id));
            refus_tamper |= i == Issue::Tamper;
            println!("{}", texte_issue(c, i));
        }
        if refus_tamper {
            println!();
            crate::ui::afficher_aligne("  ", texte_tamper(), 2, "");
            crate::machine::ouvrir(PAGE_TAMPER);
        }
        changes.clear();
        println!();
        crate::selection::attendre_retour(tr!("  Entrée pour revenir… ", "  Enter to go back… "));
    }
}

#[cfg(windows)]
pub(super) use boucle::ecran;

#[cfg(test)]
mod tests {
    use super::super::tests::courant;
    use super::*;

    fn note(id: IdChoix, avant: Option<i64>, posee: i64) -> (IdChoix, Option<Note>) {
        (
            id,
            Some(Note {
                id: id.texte(),
                avant,
                posee,
                date: 1_793_000_000,
            }),
        )
    }

    /// La largeur d'une rangée telle que `selection` la dessine : « ► touche  » puis le texte, complété jusqu'à la
    /// colonne des précisions s'il y en a une.
    fn largeurs(l: &[Ligne]) -> Vec<(usize, String)> {
        let colonne = crate::selection::colonne(l);
        l.iter()
            .filter_map(|x| match x {
                Ligne::Texte(t) => Some((largeur_affichee(t), t.clone())),
                Ligne::Choix {
                    touche,
                    texte,
                    precision,
                    ..
                } => {
                    let debut = 5 + largeur_affichee(touche).max(2);
                    let w = if precision.is_empty() {
                        debut + largeur_affichee(texte)
                    } else {
                        debut + largeur_affichee(texte).max(colonne) + largeur_affichee(precision)
                    };
                    Some((w, format!("{touche} {texte} {precision}")))
                }
                Ligne::Cachee { .. } => None,
            })
            .collect()
    }

    fn dans_l_ecran(l: &[Ligne]) {
        for (w, t) in largeurs(l) {
            assert!(w <= LARGEUR, "{w} > {LARGEUR} : {t}");
        }
    }

    fn touches(l: &[Ligne]) -> Vec<String> {
        l.iter()
            .filter_map(|x| match x {
                Ligne::Choix { touche, .. } => Some(touche.clone()),
                _ => None,
            })
            .collect()
    }

    fn tout_texte(l: &[Ligne]) -> String {
        l.iter()
            .map(|x| match x {
                Ligne::Texte(t) => t.clone(),
                Ligne::Choix { texte, precision, .. } | Ligne::Cachee { texte, precision, .. } => {
                    format!("{texte} {precision}")
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Le texte des paragraphes remis sur une ligne, sans couleurs : pour y chercher une phrase coupée.
    fn a_plat(t: &str) -> String {
        t.replace(GRIS, "")
            .replace(RESET, "")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn dans_les_deux_langues(f: impl Fn()) {
        f();
        crate::langue::en_anglais(&f);
    }

    #[test]
    fn le_menu_tient_dans_l_ecran_et_dit_tout() {
        dans_les_deux_langues(|| {
            let e = courant();
            let tr = IdChoix::Defender(ReglageDefender::Pua);
            let notes = vec![note(tr, Some(1), 0)];
            let listes = [
                vec![
                    r"C:\Jeux\Un très long dossier de jeu qui dépasse largement la largeur de l'écran\bin".to_string(),
                ],
                vec![],
                vec!["log".to_string()],
            ];
            let changes = vec![Change {
                id: IdChoix::Defender(ReglageDefender::TempsReel),
                ligne: gestes::ligne_rallumer(IdChoix::Defender(ReglageDefender::TempsReel)),
                texte: "x".into(),
                cible: Some(1),
            }];
            let m = menu(&e, &notes, Some(&listes), None, &changes);
            dans_l_ecran(&m);
            let t = touches(&m);
            for k in 1..=13 {
                assert!(t.contains(&k.to_string()), "{k}");
            }
            assert!(t.contains(&"a".to_string()) && t.contains(&"x".to_string()) && t.contains(&"↵".to_string()));
            // Tamper active (courant) : † sur les quatre options qu'elle protège.
            let texte = tout_texte(&m);
            assert!(texte.contains('†'));
            // Sans changement : ni « Appliquer » ni « Oublier ».
            let m = menu(&e, &notes, Some(&listes), None, &[]);
            let t = touches(&m);
            assert!(!t.contains(&"a".to_string()) && !t.contains(&"x".to_string()));
        });
    }

    #[test]
    fn marques_du_menu() {
        let mut e = courant();
        // PUA coupée (0), notée par votre choix ; réseau imposé par une stratégie (courant : options[4]).
        if let Some(p) = e.preferences.as_mut() {
            p.valeurs[3] = Some(0);
        }
        let pua = IdChoix::Defender(ReglageDefender::Pua);
        let notes = vec![note(pua, Some(1), 0)];
        let m = menu(&e, &notes, None, None, &[]);
        let ligne = |k: &str| {
            m.iter()
                .find_map(|x| match x {
                    Ligne::Choix {
                        touche,
                        texte,
                        precision,
                        ..
                    } if touche == k => Some((texte.clone(), precision.clone())),
                    _ => None,
                })
                .expect("ligne")
        };
        assert!(ligne("1").0.ends_with('†'), "{:?}", ligne("1"));
        assert!(ligne("4").0.contains('‡'), "{:?}", ligne("4"));
        assert!(ligne("5").0.contains('*'), "{:?}", ligne("5"));
        assert!(!ligne("4").0.contains('†'));
        // Sans Tamper : plus de †.
        if let Some(s) = e.statut.as_mut() {
            s.falsifications = Some(false);
        }
        let m = menu(&e, &notes, None, None, &[]);
        assert!(!tout_texte(&m).contains('†'));
    }

    #[test]
    fn resume_des_exclusions() {
        let chemin = r"C:\Outils\scanner";
        let id = IdChoix::Exclusion(GenreExclusion::Chemin, EmpreinteElement::de(chemin));
        let notes = vec![note(id, Some(0), 1)];
        let listes = [vec![chemin.to_string(), r"D:\inconnu".to_string()], vec![], vec![]];
        assert_eq!(
            resume_exclusions(Some(&listes), None, &notes),
            "2 (1 votre choix, 1 inconnue ⚠)"
        );
        // La casse ne compte pas (Windows compare sans casse ; l'empreinte se prend en minuscules).
        let listes_maj = [vec![chemin.to_uppercase()], vec![], vec![]];
        assert_eq!(
            resume_exclusions(Some(&listes_maj), None, &notes),
            "1 (par votre choix)"
        );
        assert_eq!(resume_exclusions(Some(&Default::default()), None, &[]), "aucune");
        let n_a = [
            vec!["N/A: Must be an administrator to view exclusions".to_string()],
            vec![],
            vec![],
        ];
        assert_eq!(
            resume_exclusions(Some(&n_a), None, &[]),
            "visibles avec l'accord admin."
        );
        assert!(resume_exclusions(Some(&n_a), None, &notes).contains("1 par votre choix"));
        assert_eq!(resume_exclusions(None, None, &[]), "non vérifiées (illisibles)");
        let deux = [vec!["a".into(), "b".into()], vec![], vec![]];
        assert_eq!(resume_exclusions(Some(&deux), None, &[]), "2 (inconnues ⚠)");
        assert_eq!(
            crate::langue::en_anglais(|| resume_exclusions(Some(&listes), None, &notes)),
            "2 (1 your choice, 1 unknown ⚠)"
        );
        // Les programmes permis comptent aussi (note de D4) : l'inconnu se voit, le noté est « votre choix » ;
        // une liste cachée ou muette ne compte pas.
        let copie = r"C:\Outils\copie.exe";
        let permis = vec![copie.to_string(), r"C:\Autre\b.exe".to_string()];
        let notes_permis = vec![note(IdChoix::DossiersAutorise(EmpreinteElement::de(copie)), Some(0), 1)];
        let vides: [Vec<String>; 3] = Default::default();
        assert_eq!(
            resume_exclusions(Some(&vides), Some(&permis), &notes_permis),
            "2 (1 votre choix, 1 inconnue ⚠)"
        );
        assert_eq!(
            resume_exclusions(Some(&vides), Some(&permis[1..]), &[]),
            "1 (inconnue ⚠)"
        );
        let cache = vec!["N/A: Must be an administrator".to_string()];
        assert_eq!(resume_exclusions(Some(&vides), Some(&cache), &[]), "aucune");
        assert!(resume_exclusions(None, None, &notes_permis).contains("1 par votre choix"));
    }

    #[test]
    fn resume_asr_et_pare_feu() {
        let e = courant();
        // Deux connues bloquent, une en audit (l'inconnue n'est pas comptée).
        assert_eq!(resume_asr(&e), "2 bloquent · 1 audit · 16 coupées");
        // Courant : réseau actuel public, domaine coupé.
        assert_eq!(resume_pare_feu(&e), "coupé : Domaine");
        let mut e2 = courant();
        if let Some(f) = e2.pare_feu.as_mut() {
            f.profils[0].actif = Some(true);
        }
        assert_eq!(resume_pare_feu(&e2), "allumé (réseau actuel : Public)");
        let vide = Etat::default();
        assert!(resume_asr(&vide).contains("non vérifiées"));
        assert!(resume_pare_feu(&vide).contains("non vérifié"));
    }

    #[test]
    fn sous_ecran_d_une_option() {
        dans_les_deux_langues(|| {
            let e = courant();
            for o in Opt::TOUTES {
                let l = lignes_option(&e, o, &[], &[]);
                dans_l_ecran(&l);
                let t = touches(&l);
                // Une touche par valeur admise, plus « Revenir ».
                for k in 1..=reglage_de(o).choix().len() {
                    assert!(t.contains(&k.to_string()), "{} {k}", o.id());
                }
                assert!(t.contains(&"↵".to_string()));
                // L'effet d'une baisse et ce qui protège encore sont dits.
                let texte = tout_texte(&l);
                assert!(a_plat(&texte).contains(protege_encore(id_opt(o))), "{}", o.id());
            }
            // Temps réel : la raison de ne pas arrêter WinDefend.
            let l = tout_texte(&lignes_option(&e, Opt::TempsReel, &[], &[]));
            assert!(l.contains("WinDefend"));
            // Tamper active : la note à côté des options qu'elle protège, pas des autres.
            let refusera = tr!("Windows refusera", "Windows will refuse");
            assert!(l.contains(refusera));
            assert!(!tout_texte(&lignes_option(&e, Opt::Pua, &[], &[])).contains(refusera));
        });
    }

    #[test]
    fn choisir_une_valeur_baisse_ou_annule() {
        let e = courant();
        // Temps réel allumé : « 2 » (coupée) est une baisse, « 1 » (allumée, l'actuelle) oublie le choix.
        let s = suite_option(&e, Opt::TempsReel, &[], "2");
        let Suite::Ajouter(c) = s else { panic!("{s:?}") };
        assert_eq!(c.id, IdChoix::Defender(ReglageDefender::TempsReel));
        assert_eq!(c.cible, Some(1));
        assert_eq!(
            Some(c.ligne.clone()),
            gestes::ligne_baisse_defender(ReglageDefender::TempsReel, ChoixDefender::Coupe)
        );
        assert!(c.texte.contains("allumée → coupée"), "{}", c.texte);
        assert_eq!(
            suite_option(&e, Opt::TempsReel, &[], "1"),
            Suite::Retirer(IdChoix::Defender(ReglageDefender::TempsReel))
        );
        assert_eq!(suite_option(&e, Opt::TempsReel, &[], "9"), Suite::Rien);
        assert_eq!(suite_option(&e, Opt::TempsReel, &[], "0"), Suite::Rien);
        // Rien à rallumer ni à noter : la valeur est sûre, sans note.
        assert_eq!(suite_option(&e, Opt::TempsReel, &[], "r"), Suite::Rien);
        assert_eq!(suite_option(&e, Opt::TempsReel, &[], "m"), Suite::Rien);
        // Le dernier choix d'un réglage remplace le précédent ; la valeur actuelle choisie l'oublie.
        let mut changes = Vec::new();
        suivre(&mut changes, suite_option(&e, Opt::Cloud, &[], "2"));
        suivre(&mut changes, suite_option(&e, Opt::Cloud, &[], "3"));
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].cible, Some(0));
        suivre(&mut changes, suite_option(&e, Opt::Cloud, &[], "1"));
        assert_eq!(changes, Vec::<Change>::new());
    }

    #[test]
    fn rallumer_et_c_est_moi() {
        let mut e = courant();
        if let Some(p) = e.preferences.as_mut() {
            p.valeurs[3] = Some(0); // PUA coupée
            p.valeurs[2] = Some(2); // échantillons : jamais
        }
        let pua = IdChoix::Defender(ReglageDefender::Pua);
        // Sans note : « Rallumer » vise la valeur sûre (bloque), « C'est moi » est proposé.
        let t = touches(&lignes_option(&e, Opt::Pua, &[], &[]));
        assert!(t.contains(&"r".to_string()) && t.contains(&"m".to_string()));
        let Suite::Ajouter(c) = suite_option(&e, Opt::Pua, &[], "r") else {
            panic!()
        };
        assert_eq!(c.ligne, gestes::ligne_rallumer(pua));
        assert_eq!(c.cible, Some(1));
        let Suite::Ajouter(c) = suite_option(&e, Opt::Pua, &[], "m") else {
            panic!()
        };
        assert_eq!(c.ligne, gestes::ligne_noter(pua));
        assert_eq!(c.cible, None);
        // Notée par votre choix (avant : audit) : « Rallumer » remet l'audit ; plus de « C'est moi ».
        let notes = vec![note(pua, Some(2), 0)];
        let t = touches(&lignes_option(&e, Opt::Pua, &notes, &[]));
        assert!(t.contains(&"r".to_string()) && !t.contains(&"m".to_string()));
        let Suite::Ajouter(c) = suite_option(&e, Opt::Pua, &notes, "r") else {
            panic!()
        };
        assert_eq!(c.cible, Some(2));
        assert!(tout_texte(&lignes_option(&e, Opt::Pua, &notes, &[])).contains("par votre choix le"));
        // Une note forgée qui dit « avant : coupée » ne fait jamais rallumer plus faible qu'allumé.
        let forgee = vec![note(pua, Some(0), 0)];
        let Suite::Ajouter(c) = suite_option(&e, Opt::Pua, &forgee, "r") else {
            panic!()
        };
        assert_eq!(c.cible, Some(1));
        // Échantillons « jamais » : un choix de vie privée, « Rallumer » vise « fichiers sûrs ».
        let Suite::Ajouter(c) = suite_option(&e, Opt::Echantillons, &[], "r") else {
            panic!()
        };
        assert_eq!(c.cible, Some(1));
        // Échantillons « toujours demander » : un choix de vie privée, pas une baisse (plan §2.1) : ni « Rallumer »
        // ni « C'est moi ».
        let mut demander = e.clone();
        if let Some(p) = demander.preferences.as_mut() {
            p.valeurs[2] = Some(0);
        }
        let t = touches(&lignes_option(&demander, Opt::Echantillons, &[], &[]));
        assert!(!t.contains(&"r".to_string()) && !t.contains(&"m".to_string()), "{t:?}");
        // Illisible : ni l'un ni l'autre.
        let vide = Etat::default();
        let t = touches(&lignes_option(&vide, Opt::Pua, &[], &[]));
        assert!(!t.contains(&"r".to_string()) && !t.contains(&"m".to_string()));
    }

    #[test]
    fn temps_reel_lu_par_son_effet() {
        let mut e = courant();
        if let Some(s) = e.statut.as_mut() {
            s.temps_reel = Some(false);
        }
        // La préférence dit allumé (0), l'effet dit coupé : la note se compare à l'effet.
        assert_eq!(valeur(&e, Opt::TempsReel), Some(1));
        let tr = IdChoix::Defender(ReglageDefender::TempsReel);
        let notes = vec![note(tr, Some(0), 1)];
        assert!(matches!(
            lecture(&e, Opt::TempsReel, &notes),
            Some(Lecture::ParChoix(_))
        ));
        if let Some(s) = e.statut.as_mut() {
            s.temps_reel = Some(true);
        }
        assert_eq!(lecture(&e, Opt::TempsReel, &notes), Some(Lecture::Remontee));
    }

    #[test]
    fn sous_ecran_des_exclusions() {
        dans_les_deux_langues(|| {
            let chemin = r"C:\Outils\scanner";
            let id = IdChoix::Exclusion(GenreExclusion::Chemin, EmpreinteElement::de(chemin));
            let permis = IdChoix::DossiersAutorise(EmpreinteElement::de(r"C:\Outils\copie.exe"));
            let notes = vec![note(id, Some(0), 1), note(permis, Some(0), 1)];
            let piege = "D:\\inconnu\u{1b}[31m\u{202e}exe.txt";
            let listes = [
                vec![chemin.to_string(), piege.to_string()],
                vec![],
                vec!["log".to_string()],
            ];
            let (l, actions) = lignes_exclusions(Some(&listes), None, &notes, &[]);
            dans_l_ecran(&l);
            let texte = tout_texte(&l);
            // R13 : un texte venu d'ailleurs ne porte ni échappement ni inversion.
            assert!(!texte.contains("\u{1b}[31m"));
            assert!(!texte.contains('\u{202e}'));
            let a = |t: &str| actions.iter().find(|(k, _)| k == t).map(|(_, a)| a.clone());
            assert!(matches!(a("r1"), Some(ActionListe::Retirer(i, _)) if i == id));
            assert!(matches!(a("m2"), Some(ActionListe::Noter(..))));
            assert!(matches!(
                a("m3"),
                Some(ActionListe::Noter(IdChoix::Exclusion(GenreExclusion::Extension, _), _))
            ));
            assert!(matches!(a("r4"), Some(ActionListe::Retirer(i, _)) if i == permis));
            for k in ["a", "p", "t", "d"] {
                assert!(a(k).is_some(), "{k}");
            }
            // Liste cachée : les notes, sans chemin.
            let n_a = [vec!["N/A: Must be an administrator".to_string()], vec![], vec![]];
            let (l, actions) = lignes_exclusions(Some(&n_a), None, &notes, &[]);
            dans_l_ecran(&l);
            assert!(!tout_texte(&l).contains("Outils"));
            // Non relue, la note peut être périmée : dite « à vérifier ».
            assert!(
                tout_texte(&l).contains(tr!("à vérifier", "to check")),
                "{}",
                tout_texte(&l)
            );
            assert!(
                actions
                    .iter()
                    .any(|(_, a)| matches!(a, ActionListe::Retirer(i, _) if *i == id))
            );
        });
    }

    #[test]
    fn changements_des_listes() {
        // Une extension s'écrit sans son point ; l'empreinte est celle du texte envoyé.
        let c = change_liste(&ActionListe::Ajouter(GenreExclusion::Extension), " .log ").expect("ajout");
        assert_eq!(
            c.id,
            IdChoix::Exclusion(GenreExclusion::Extension, EmpreinteElement::de("log"))
        );
        assert_eq!(
            Some(c.ligne.clone()),
            gestes::ligne_ajout_exclusion(GenreExclusion::Extension, "log")
        );
        assert_eq!(c.cible, Some(1));
        let c = change_liste(&ActionListe::Permettre, r" C:\Outils\copie.exe ").expect("permis");
        assert_eq!(
            c.id,
            IdChoix::DossiersAutorise(EmpreinteElement::de(r"C:\Outils\copie.exe"))
        );
        assert_eq!(Some(c.ligne), gestes::ligne_autoriser_dossiers(r"C:\Outils\copie.exe"));
        // Refusés : vide, caractère de contrôle.
        assert!(change_liste(&ActionListe::Ajouter(GenreExclusion::Chemin), "   ").is_none());
        assert!(change_liste(&ActionListe::Ajouter(GenreExclusion::Chemin), "C:\\a\nb").is_none());
        assert!(change_liste(&ActionListe::Permettre, "").is_none());
        // Retirer : « Rallumer » de l'élément (son absence).
        let id = IdChoix::Exclusion(GenreExclusion::Chemin, EmpreinteElement::de("c:\\x"));
        let c = change_liste(&ActionListe::Retirer(id, "c:\\x".into()), "").expect("retirer");
        assert_eq!(c.ligne, gestes::ligne_rallumer(id));
        let c = change_liste(&ActionListe::Noter(id, "c:\\x".into()), "").expect("noter");
        assert_eq!(c.ligne, gestes::ligne_noter(id));
        // L'avertissement d'une exclusion large (R8).
        assert!(large(&ActionListe::Ajouter(GenreExclusion::Chemin), "C:\\"));
        assert!(large(&ActionListe::Ajouter(GenreExclusion::Extension), ".exe"));
        assert!(!large(&ActionListe::Ajouter(GenreExclusion::Chemin), r"C:\Jeux\Un jeu"));
        assert!(large(
            &ActionListe::Permettre,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        ));
        assert!(large(&ActionListe::Permettre, r"C:\Outils\*"));
        assert!(!large(&ActionListe::Permettre, r"C:\Windows\System32\notepad.exe"));
    }

    #[test]
    fn recapitulatif_et_issues() {
        dans_les_deux_langues(|| {
            let e = courant();
            let mut changes = Vec::new();
            suivre(&mut changes, suite_option(&e, Opt::TempsReel, &[], "2"));
            suivre(&mut changes, suite_option(&e, Opt::Pua, &[], "3"));
            let r = recapitulatif(&changes);
            for x in &r {
                assert!(largeur_affichee(x) <= LARGEUR, "{x}");
            }
            let tout = r.join("\n");
            assert!(tout.contains(tr!("accord d'un administrateur", "administrator's approval")));
            assert!(tout.contains(tr!("demandé (o/N)", "asked (y/N)")));
            // Un renforcement seul : pas d'annonce de question.
            let mut e2 = courant();
            if let Some(p) = e2.preferences.as_mut() {
                p.valeurs[3] = Some(0);
            }
            let seul = vec![match suite_option(&e2, Opt::Pua, &[], "1") {
                Suite::Ajouter(c) => c,
                s => panic!("{s:?}"),
            }];
            assert!(
                !recapitulatif(&seul)
                    .join("\n")
                    .contains(tr!("demandé (o/N)", "asked (y/N)"))
            );
            let tr = &changes[0];
            let pua = &changes[1];
            let fait = Rendu {
                reussi: true,
                ..Rendu::default()
            };
            let refuse = Rendu::default();
            let arrete = Rendu {
                arrete: true,
                ..Rendu::default()
            };
            assert_eq!(issue(tr, fait, true), Issue::Fait);
            assert_eq!(issue(tr, Rendu { rien: true, ..fait }, true), Issue::Deja);
            assert_eq!(issue(tr, refuse, true), Issue::Tamper);
            assert_eq!(issue(tr, refuse, false), Issue::PasFait);
            // Un « non » ou une demande d'administrateur refusée n'est jamais un refus de la protection.
            assert_eq!(issue(tr, arrete, true), Issue::Arretee);
            // PUA n'est pas protégée par Tamper : un refus reste un refus ordinaire.
            assert_eq!(issue(pua, refuse, true), Issue::PasFait);
            // Tamper en cause : active avant ou après, et l'option pas imposée par une stratégie.
            let e = courant();
            assert!(tamper_en_cause(&e, &e, tr.id));
            let mut sans = courant();
            if let Some(s) = sans.statut.as_mut() {
                s.falsifications = Some(false);
            }
            assert!(!tamper_en_cause(&sans, &sans, tr.id));
            assert!(tamper_en_cause(&sans, &e, tr.id));
            // Imposée par une stratégie (le réseau, dans cet état) : c'est la stratégie qui garde la valeur.
            assert!(!tamper_en_cause(&e, &e, id_opt(Opt::Reseau)));
            for i in [Issue::Fait, Issue::Deja, Issue::PasFait, Issue::Arretee, Issue::Tamper] {
                assert!(texte_issue(tr, i).contains(&tr.texte));
            }
            assert!(texte_tamper().contains(tr!("falsifications", "tamper")));
        });
        assert_eq!(PAGE_TAMPER, "windowsdefender://threatsettings");
    }

    #[test]
    fn touches_du_menu() {
        assert_eq!(opt_de_touche("1"), Some(Opt::TempsReel));
        assert_eq!(opt_de_touche("10"), Some(Opt::PremiereVue));
        assert_eq!(opt_de_touche("0"), None);
        assert_eq!(opt_de_touche("11"), None);
        assert_eq!(opt_de_touche("a"), None);
    }

    // ------------------------------------------------------------------ règles ASR (D4)

    fn choix_de<'a>(l: &'a [Ligne], k: &str) -> Option<(&'a str, &'a str)> {
        l.iter().find_map(|x| match x {
            Ligne::Choix {
                touche,
                texte,
                precision,
                ..
            } if touche == k => Some((texte.as_str(), precision.as_str())),
            _ => None,
        })
    }

    /// Le PC courant, une règle de plus à l'action `v` (les autres comme `courant`).
    fn avec_regle(id: &str, v: i64) -> Etat {
        let mut e = courant();
        let p = e.preferences.as_mut().unwrap();
        p.asr = Asr::depuis(
            &super::super::tests::textes(&[
                "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2",
                "{56a863a9-875e-4185-98a7-b882c64b5ce5}",
                "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
                "00000000-0000-0000-0000-000000000000",
                id,
            ]),
            &[Some(1), Some(1), Some(2), Some(1), Some(v)],
        );
        e
    }

    /// Les groupes de l'écran suivent les listes de `gestes` : les règles de base et des documents d'abord, les 8
    /// écartées des Réglages recommandés ensuite, chacune avec son avertissement.
    #[test]
    fn groupes_asr_dans_l_ordre_des_listes() {
        let g = groupes_asr();
        assert_eq!(g[0].1, &gestes::ASR_BASE[..]);
        assert_eq!(g[1].1, &gestes::ASR_BUREAUTIQUE[..]);
        assert_eq!(g[2].1.len(), 8);
        for id in g[2].1 {
            assert!(avertissement_asr(id).is_some(), "{id}");
        }
        for id in g[0].1.iter().chain(g[1].1) {
            assert!(avertissement_asr(id).is_none(), "{id}");
        }
        assert_eq!(g.iter().map(|x| x.1.len()).sum::<usize>(), ASR_TOUTES.len());
    }

    /// La liste : les 19 règles, ⚠ sur les 8 écartées, * sur l'imposée, leur état ; l'effet dit ; les raccourcis.
    #[test]
    fn asr_liste_les_19_regles() {
        dans_les_deux_langues(|| {
            let e = courant();
            let l = lignes_asr(&e, &[], &[]);
            dans_l_ecran(&l);
            let mut attendues: Vec<String> = (1..=19).map(|k| k.to_string()).collect();
            attendues.extend(["b", "o", "↵"].map(String::from));
            assert_eq!(touches(&l), attendues);
            let avert: Vec<String> = (1..=19)
                .filter(|k| choix_de(&l, &k.to_string()).unwrap().0.starts_with("⚠ "))
                .map(|k| k.to_string())
                .collect();
            assert_eq!(avert, (12..=19).map(|k| k.to_string()).collect::<Vec<_>>());
            assert!(choix_de(&l, "1").unwrap().0.ends_with('*'));
            assert_eq!(choix_de(&l, "2").unwrap().1, ActionAsr::Bloque.texte());
            assert_eq!(choix_de(&l, "3").unwrap().1, tr!("absente", "not listed"));
            assert_eq!(choix_de(&l, "4").unwrap().1, ActionAsr::Audit.texte());
            let t = a_plat(&tout_texte(&l));
            assert!(t.contains(&a_plat(&texte_effet_asr(&e))), "{t}");
            assert!(t.contains(tr!("1 autre(s) règle(s)", "1 other rule(s)")), "{t}");
            // Avertir : lu, jamais proposé.
            assert!(
                t.contains(tr!("Vanguard ne le propose pas", "Vanguard does not offer it")),
                "{t}"
            );
        });
    }

    /// Bloquer un groupe : un changement par règle qui ne bloque pas encore, vers 1, par la ligne du choix exact.
    #[test]
    fn asr_raccourcis_de_groupe() {
        let e = courant();
        let SuiteAsr::Ajouter(base) = suite_asr(&e, &[], "b") else {
            panic!("b")
        };
        assert_eq!(base.len(), 1);
        let id = gestes::ASR_BASE[2];
        assert_eq!(base[0].id, IdChoix::Asr(id));
        assert_eq!(base[0].cible, Some(1));
        assert_eq!(
            Some(base[0].ligne.clone()),
            gestes::ligne_baisse_asr(id, ChoixAsr::Bloquer)
        );
        let SuiteAsr::Ajouter(bureau) = suite_asr(&e, &[], "o") else {
            panic!("o")
        };
        assert_eq!(bureau.len(), 8);
        let mut changes = Vec::new();
        for c in base.into_iter().chain(bureau) {
            ajouter(&mut changes, c);
        }
        let l = lignes_asr(&e, &[], &changes);
        dans_l_ecran(&l);
        assert!(!touches(&l).contains(&"b".to_string()) && !touches(&l).contains(&"o".to_string()));
        assert!(choix_de(&l, "3").unwrap().1.starts_with("→ "));
        assert_eq!(suite_asr(&e, &changes, "b"), SuiteAsr::Rien);
        assert_eq!(suite_asr(&e, &[], "12"), SuiteAsr::Regle(ASR_TOUTES[11]));
        for t in ["0", "20", "x", "-1", ""] {
            assert_eq!(suite_asr(&e, &[], t), SuiteAsr::Rien, "{t}");
        }
    }

    /// Une règle écartée : son avertissement (« Essayez d'abord Audit »), ses trois choix, ni « Rallumer » ni « C'est
    /// moi » sans valeur à noter ; la protection par le cloud coupée est dite pour les règles qui en ont besoin.
    #[test]
    fn asr_regle_ecartee_avec_avertissement() {
        dans_les_deux_langues(|| {
            let id = "01443614-cd74-433a-b99e-2ecdc07bfc25";
            let mut e = courant();
            let l = lignes_regle(&e, id, &[], &[]);
            dans_l_ecran(&l);
            assert_eq!(touches(&l), ["1", "2", "3", "↵"]);
            // L'avertissement est en couleur d'alerte : retirée pour y chercher la phrase.
            let t = a_plat(&tout_texte(&l).replace(ACCENT, ""));
            assert!(t.contains(tr!("Essayez d'abord Audit.", "Try Audit first.")), "{t}");
            assert!(!t.contains(tr!("cloud (ligne 2) est coupée", "(line 2) is off")), "{t}");
            // Absente : Désactiver ne change rien, Bloquer n'est pas dit « la valeur sûre » pour une règle écartée.
            assert!(!choix_de(&l, "1").unwrap().1.contains(tr!("sûre", "safe")));
            assert_eq!(
                choix_de(&l, "3").unwrap().1,
                tr!("(absente : sans effet déjà)", "(not listed: no effect already)")
            );
            e.preferences.as_mut().unwrap().valeurs[1] = Some(0);
            let t = a_plat(&tout_texte(&lignes_regle(&e, id, &[], &[])));
            assert!(t.contains(tr!("cloud (ligne 2) est coupée", "(line 2) is off")), "{t}");
            // Choisir Audit : la ligne du choix exact, vers 2.
            let Suite::Ajouter(c) = suite_regle(&e, id, &[], "2") else {
                panic!("2")
            };
            assert_eq!(Some(c.ligne.clone()), gestes::ligne_baisse_asr(id, ChoixAsr::Audit));
            assert_eq!(c.cible, Some(2));
        });
    }

    /// Une règle de base : l'action actuelle est dite, la choisir retire le changement ; l'imposée est dite.
    #[test]
    fn asr_regle_de_base_actuelle_et_imposee() {
        dans_les_deux_langues(|| {
            let e = courant();
            let id = gestes::ASR_BASE[1];
            let l = lignes_regle(&e, id, &[], &[]);
            dans_l_ecran(&l);
            assert_eq!(choix_de(&l, "1").unwrap().1, tr!("(actuelle)", "(current)"));
            assert_eq!(suite_regle(&e, id, &[], "1"), Suite::Retirer(IdChoix::Asr(id)));
            assert_eq!(suite_regle(&e, id, &[], "9"), Suite::Rien);
            let Suite::Ajouter(c) = suite_regle(&e, id, &[], "3") else {
                panic!("3")
            };
            assert_eq!(c.cible, Some(0));
            assert_eq!(Some(c.ligne), gestes::ligne_baisse_asr(id, ChoixAsr::Desactiver));
            let t = a_plat(&tout_texte(&lignes_regle(&e, gestes::ASR_BASE[0], &[], &[])));
            assert!(
                t.contains(tr!("Imposée par une stratégie", "Enforced by a policy")),
                "{t}"
            );
            // Absente : Bloquer est la valeur sûre.
            let l = lignes_regle(&e, gestes::ASR_BASE[2], &[], &[]);
            assert_eq!(
                choix_de(&l, "1").unwrap().1,
                tr!("(la valeur sûre)", "(the safe value)")
            );
        });
    }

    /// Avertir (6) se lit et se dit, sans être proposé ; « C'est moi » le note (il ne bloque pas).
    #[test]
    fn asr_avertir_lu_seulement() {
        dans_les_deux_langues(|| {
            let id = "d3e037e1-3eb8-44c8-a917-57927947596d";
            let e = avec_regle(id, 6);
            assert_eq!(valeur_asr(&e, id), Some(Some(6)));
            let l = lignes_regle(&e, id, &[], &[]);
            dans_l_ecran(&l);
            assert_eq!(touches(&l), ["1", "2", "3", "m", "↵"]);
            let t = a_plat(&tout_texte(&l));
            assert!(t.contains(tr!("En mode Avertir", "In Warn mode")), "{t}");
            assert!(t.contains(&ActionAsr::Avertit.texte()), "{t}");
            let l = lignes_asr(&e, &[], &[]);
            assert_eq!(choix_de(&l, "11").unwrap().1, ActionAsr::Avertit.texte());
        });
    }

    /// « C'est moi » pour une règle sous « bloque » sans note ; noté, « Rallumer » vers la valeur d'avant, ‡ en liste.
    #[test]
    fn asr_rallumer_et_c_est_moi() {
        dans_les_deux_langues(|| {
            let e = courant();
            let id = gestes::ASR_BUREAUTIQUE[0];
            let idc = IdChoix::Asr(id);
            assert_eq!(touches(&lignes_regle(&e, id, &[], &[])), ["1", "2", "3", "m", "↵"]);
            let Suite::Ajouter(c) = suite_regle(&e, id, &[], "m") else {
                panic!("m")
            };
            assert_eq!(c.ligne, gestes::ligne_noter(idc));
            assert_eq!(c.cible, None);
            assert_eq!(suite_regle(&e, id, &[], "r"), Suite::Rien);
            let notes = vec![note(idc, Some(1), 2)];
            let l = lignes_regle(&e, id, &notes, &[]);
            dans_l_ecran(&l);
            assert_eq!(touches(&l), ["1", "2", "3", "r", "↵"]);
            assert_eq!(suite_regle(&e, id, &notes, "m"), Suite::Rien);
            let Suite::Ajouter(c) = suite_regle(&e, id, &notes, "r") else {
                panic!("r")
            };
            assert_eq!(c.ligne, gestes::ligne_rallumer(idc));
            assert_eq!(c.cible, Some(1));
            assert!(choix_de(&lignes_asr(&e, &notes, &[]), "4").unwrap().0.contains('‡'));
            // Absente : rien à noter.
            assert!(!touches(&lignes_regle(&e, gestes::ASR_BASE[2], &[], &[])).contains(&"m".to_string()));
        });
    }

    /// Temps réel coupé : « les règles ne s'appliquent pas », et les choix restent possibles ; préférences muettes :
    /// « non vérifiées », choix possibles aussi (la fenêtre administrateur relit).
    #[test]
    fn asr_sans_effet_dit_et_choix_gardes() {
        dans_les_deux_langues(|| {
            let mut e = courant();
            e.statut.as_mut().unwrap().temps_reel = Some(false);
            let l = lignes_asr(&e, &[], &[]);
            dans_l_ecran(&l);
            let t = a_plat(&tout_texte(&l));
            assert!(
                t.contains(tr!("les règles ne s'appliquent pas", "the rules do not apply")),
                "{t}"
            );
            let id = gestes::ASR_BASE[2];
            let t = a_plat(&tout_texte(&lignes_regle(&e, id, &[], &[])));
            assert!(t.contains(tr!("les règles ne s'appliquent pas", "the rules do not apply")));
            assert!(matches!(suite_regle(&e, id, &[], "1"), Suite::Ajouter(_)));
            e.preferences = None;
            let l = lignes_asr(&e, &[], &[]);
            dans_l_ecran(&l);
            assert_eq!(choix_de(&l, "1").unwrap().1, tr!("non vérifiée", "not checked"));
            assert!(matches!(suite_regle(&e, id, &[], "1"), Suite::Ajouter(_)));
            assert_eq!(touches(&lignes_regle(&e, id, &[], &[])), ["1", "2", "3", "↵"]);
        });
    }

    /// Relecture D4 : préférences illisibles, une règle notée se rallume quand même (le processus élevé relit).
    #[test]
    fn asr_rallumer_sans_preferences_lues() {
        let mut e = courant();
        e.preferences = None;
        let id = gestes::ASR_BUREAUTIQUE[0];
        let idc = IdChoix::Asr(id);
        let notes = vec![note(idc, Some(1), 0)];
        let l = lignes_regle(&e, id, &notes, &[]);
        dans_l_ecran(&l);
        assert_eq!(touches(&l), ["1", "2", "3", "r", "↵"]);
        let Suite::Ajouter(c) = suite_regle(&e, id, &notes, "r") else {
            panic!("r")
        };
        assert_eq!(c.ligne, gestes::ligne_rallumer(idc));
        assert_eq!(c.cible, Some(1));
    }

    /// Relecture D4 : « C'est moi » d'une règle que le bilan ne juge pas ne promet pas que le bilan cessera d'alerter.
    #[test]
    fn asr_c_est_moi_ne_promet_pas_le_silence() {
        dans_les_deux_langues(|| {
            let e = avec_regle(ASR_TOUTES[11], 2);
            let l = lignes_regle(&e, ASR_TOUTES[11], &[], &[]);
            dans_l_ecran(&l);
            let (_, precision) = choix_de(&l, "m").unwrap();
            assert_eq!(
                precision,
                tr!("le bilan dira « votre choix »", "the check says “your choice”")
            );
            assert!(!a_plat(&tout_texte(&l)).contains(tr!("n'alertera plus", "stops alerting")));
        });
    }

    /// Relecture D4 : une règle « non réglée » (5) est déjà sans effet ; « Désactiver » le dit, comme pour l'absente.
    #[test]
    fn asr_non_reglee_dite_sans_effet() {
        dans_les_deux_langues(|| {
            let id = gestes::ASR_BUREAUTIQUE[1];
            let e = avec_regle(id, 5);
            let l = lignes_regle(&e, id, &[], &[]);
            dans_l_ecran(&l);
            assert_eq!(
                choix_de(&l, "3").unwrap().1,
                tr!("(non réglée : sans effet déjà)", "(not set: no effect already)")
            );
        });
    }

    /// Relecture D4 : un raccourci de groupe laisse la règle imposée par une stratégie (Windows garderait sa valeur)
    /// et ne remplace pas un « C'est moi » choisi règle par règle.
    #[test]
    fn asr_raccourci_laisse_imposee_et_c_est_moi() {
        let mut e = courant();
        let SuiteAsr::Ajouter(tous) = suite_asr(&e, &[], "o") else {
            panic!("o")
        };
        assert_eq!(tous.len(), 8);
        let imposee = gestes::ASR_BUREAUTIQUE[1];
        e.strategies.asr = Some(vec![imposee]);
        let notee = gestes::ASR_BUREAUTIQUE[0];
        let Suite::Ajouter(moi) = suite_regle(&e, notee, &[], "m") else {
            panic!("m")
        };
        let changes = vec![moi];
        let SuiteAsr::Ajouter(l) = suite_asr(&e, &changes, "o") else {
            panic!("o")
        };
        assert_eq!(l.len(), 6);
        assert!(
            l.iter()
                .all(|c| c.id != IdChoix::Asr(imposee) && c.id != IdChoix::Asr(notee))
        );
    }

    /// Au menu, la ligne 12 compte les changements de règles choisis.
    #[test]
    fn menu_compte_les_changements_asr() {
        let e = courant();
        let SuiteAsr::Ajouter(l) = suite_asr(&e, &[], "o") else {
            panic!("o")
        };
        let m = menu(&e, &[], None, None, &l);
        dans_l_ecran(&m);
        assert_eq!(choix_de(&m, "12").unwrap().1, "8 à appliquer");
    }

    /// Les programmes permis de l'accès contrôlé aux dossiers, relus (M2) : l'inconnu se note, le noté se retire ;
    /// cachée, la liste laisse les notes « à vérifier ». Les limites de l'empreinte sont dites (F7).
    #[test]
    fn exclusions_programmes_permis_relus() {
        dans_les_deux_langues(|| {
            let vides: [Vec<String>; 3] = Default::default();
            let chemin = r"C:\Outils\copie.exe";
            let id = IdChoix::DossiersAutorise(EmpreinteElement::de(chemin));
            let permis = vec![chemin.to_string(), r"C:\Autre\b.exe".to_string()];
            let (l, actions) = lignes_exclusions(Some(&vides), Some(&permis), &[], &[]);
            dans_l_ecran(&l);
            let t = a_plat(&tout_texte(&l));
            assert!(
                t.contains(tr!("programme permis inconnu", "unknown allowed app")),
                "{t}"
            );
            assert!(t.contains(tr!("partagent une seule note", "share one note")), "{t}");
            assert!(t.contains(tr!("listes sont invisibles", "lists are invisible")), "{t}");
            assert!(matches!(&actions[0], (k, ActionListe::Noter(i, _)) if k == "m1" && *i == id));
            assert!(matches!(&actions[1], (k, ActionListe::Noter(..)) if k == "m2"));
            let notes = vec![note(id, Some(0), 1)];
            let (l, actions) = lignes_exclusions(Some(&vides), Some(&permis), &notes, &[]);
            dans_l_ecran(&l);
            assert!(matches!(&actions[0], (k, ActionListe::Retirer(i, _)) if k == "r1" && *i == id));
            assert!(!tout_texte(&l).contains(tr!("à vérifier", "to check")));
            // Cachée sans droits administrateur : la note, « à vérifier », sans chemin.
            let n_a = vec!["N/A: Must be an administrator".to_string()];
            let (l, actions) = lignes_exclusions(Some(&vides), Some(&n_a), &notes, &[]);
            assert!(tout_texte(&l).contains(tr!("à vérifier", "to check")));
            assert!(!tout_texte(&l).contains("copie.exe"));
            assert!(matches!(&actions[0], (_, ActionListe::Retirer(i, _)) if *i == id));
        });
    }

    // ------------------------------------------------------------ le pare-feu (D5)

    use crate::machine::gestes::RegleLue;

    fn regle_essai(nom: &str, bloque: bool, active: bool) -> RegleLue {
        RegleLue {
            nom: nom.into(),
            entrante: true,
            bloque,
            active,
            profils: 7,
            protocole: 6,
            ports_locaux: "8080".into(),
            ..RegleLue::default()
        }
    }

    /// L'écran du pare-feu, chacun des douze sous-écrans et la liste des règles tiennent dans 76 colonnes, dans les
    /// deux langues, avec des noms de règle très longs.
    #[test]
    fn ecrans_du_pare_feu_dans_l_ecran() {
        dans_les_deux_langues(|| {
            let e = courant();
            let l = lignes_pare_feu(&e, &[], &[]);
            dans_l_ecran(&l);
            let t = touches(&l);
            for k in 1..=12 {
                assert!(t.contains(&k.to_string()), "{k}");
            }
            for k in ["f", "r", "v", "↵"] {
                assert!(t.iter().any(|x| x == k), "{k}");
            }
            for p in ProfilPareFeu::TOUS {
                for r in ReglagePareFeu::TOUS {
                    dans_l_ecran(&lignes_reglage_pf(&e, p, r, &[], &[]));
                }
            }
            let long = "Une règle au nom très long qui déborderait de l'écran sans être coupée proprement";
            let regles: Vec<RegleLue> = (0..30)
                .map(|i| regle_essai(&format!("{long} {i}"), i % 2 == 0, true))
                .collect();
            let l = lignes_regles(Some(&regles), "regle", &[], &[]);
            dans_l_ecran(&l);
            // Vingt au plus, puis Revenir.
            assert_eq!(touches(&l).len(), REGLES_MONTREES + 1);
            dans_l_ecran(&lignes_regles(None, "x", &[], &[]));
            // Une recherche vide ne montre aucune règle.
            assert_eq!(touches(&lignes_regles(Some(&regles), "", &[], &[])).len(), 1);
        });
    }

    /// Les touches de l'écran du pare-feu : un réglage par chiffre, « r » rallume le domaine coupé, un réglage déjà
    /// à la valeur choisie se retire.
    #[test]
    fn suites_du_pare_feu() {
        let e = courant();
        assert_eq!(
            suite_pare_feu(&e, &[], "5"),
            SuitePf::Reglage(ProfilPareFeu::Prive, ReglagePareFeu::Actif)
        );
        assert_eq!(
            suite_pare_feu(&e, &[], "12"),
            SuitePf::Reglage(ProfilPareFeu::Public, ReglagePareFeu::ToutBloquer)
        );
        assert_eq!(suite_pare_feu(&e, &[], "13"), SuitePf::Rien);
        assert_eq!(suite_pare_feu(&e, &[], "0"), SuitePf::Rien);
        assert_eq!(suite_pare_feu(&e, &[], "f"), SuitePf::Regles);
        let domaine = IdChoix::PareFeu(ProfilPareFeu::Domaine, ReglagePareFeu::Actif);
        match suite_pare_feu(&e, &[], "r") {
            SuitePf::Ajouter(l) => {
                assert!(l.iter().any(|c| c.id == domaine && c.cible == Some(1)));
                assert!(l.iter().all(|c| c.ligne.starts_with("vanguard:rallumer ")), "{l:?}");
            }
            s => panic!("{s:?}"),
        }
        let prive = IdChoix::PareFeu(ProfilPareFeu::Prive, ReglagePareFeu::Actif);
        // Privé allumé : « 1 » (allumé) est l'actuelle, « 2 » coupe, ligne de baisse exacte.
        assert_eq!(
            suite_reglage_pf(&e, ProfilPareFeu::Prive, ReglagePareFeu::Actif, &[], "1"),
            Suite::Retirer(prive)
        );
        match suite_reglage_pf(&e, ProfilPareFeu::Prive, ReglagePareFeu::Actif, &[], "2") {
            Suite::Ajouter(c) => {
                assert_eq!(
                    c.ligne,
                    gestes::ligne_baisse_pare_feu(ProfilPareFeu::Prive, ReglagePareFeu::Actif, false)
                );
                assert_eq!(c.cible, Some(0));
            }
            s => panic!("{s:?}"),
        }
        // Le domaine coupé : « r » le rallume, « m » le note.
        assert!(matches!(
            suite_reglage_pf(&e, ProfilPareFeu::Domaine, ReglagePareFeu::Actif, &[], "r"),
            Suite::Ajouter(Change { cible: Some(1), .. })
        ));
        assert!(matches!(
            suite_reglage_pf(&e, ProfilPareFeu::Domaine, ReglagePareFeu::Actif, &[], "m"),
            Suite::Ajouter(Change { cible: None, .. })
        ));
        // Noté par choix : plus de « C'est moi », la ligne porte ‡.
        let notes = vec![note(domaine, Some(1), 0)];
        assert_eq!(
            suite_reglage_pf(&e, ProfilPareFeu::Domaine, ReglagePareFeu::Actif, &notes, "m"),
            Suite::Rien
        );
        assert!(tout_texte(&lignes_pare_feu(&e, &notes, &[])).contains('‡'));
    }

    /// Les règles : une recherche vide ne trouve rien, vingt au plus ; choisir bascule, choisir encore retire ; une
    /// règle notée est proposée par « Rallumer ».
    #[test]
    fn regles_du_pare_feu() {
        let regles: Vec<RegleLue> = (0..30).map(|i| regle_essai(&format!("Jeu {i}"), false, true)).collect();
        assert_eq!(trouver_regles(&regles, "  ").len(), 0);
        assert_eq!(trouver_regles(&regles, "jeu").len(), REGLES_MONTREES);
        assert_eq!(trouver_regles(&regles, "JEU 29").len(), 1);
        assert_eq!(trouver_regles(&regles, "8080").len(), REGLES_MONTREES);
        let Suite::Ajouter(c) = suite_regles(&regles, "jeu 3", &[], "1") else {
            panic!()
        };
        assert_eq!(c.id, regles[3].id());
        assert_eq!(c.cible, Some(0));
        assert_eq!(c.ligne, gestes::ligne_regle_etat(&regles[3], false));
        assert_eq!(
            suite_regles(&regles, "jeu 3", std::slice::from_ref(&c), "1"),
            Suite::Retirer(c.id)
        );
        assert_eq!(suite_regles(&regles, "jeu 3", &[], "2"), Suite::Rien);
        let e = courant();
        let notes = vec![note(regles[3].id(), Some(1), 0)];
        let r = rallumer_tout_pf(&e, &notes);
        assert!(r.iter().any(|x| x.id == regles[3].id() && x.cible == Some(0)), "{r:?}");
    }

    /// La précision du pare-feu dans le menu tient en 33 caractères, quels que soient les profils coupés.
    #[test]
    fn resume_du_pare_feu_borne() {
        dans_les_deux_langues(|| {
            for coupes in 0u8..8 {
                for courants in [None, Some(1), Some(3), Some(7)] {
                    let mut e = courant();
                    if let Some(f) = e.pare_feu.as_mut() {
                        f.courants = courants;
                        for (i, p) in f.profils.iter_mut().enumerate() {
                            p.actif = Some(coupes & (1 << i) == 0);
                        }
                    }
                    let t = resume_pare_feu(&e);
                    assert!(largeur_affichee(&t) <= 33, "{t}");
                }
            }
        });
        let mut e = courant();
        if let Some(f) = e.pare_feu.as_mut() {
            f.courants = Some(2);
            for p in &mut f.profils[..2] {
                p.actif = Some(false);
            }
        }
        assert_eq!(resume_pare_feu(&e), "coupé : Domaine, Privé (actuel)");
        if let Some(f) = e.pare_feu.as_mut() {
            f.profils[2].actif = Some(false);
        }
        assert_eq!(resume_pare_feu(&e), "coupé partout");
    }
}

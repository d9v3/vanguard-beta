//! Le Pare-feu Windows dans l'écran des Options de défense (plan §2.3, sous-lot D5) : les quatre réglages de chaque
//! profil, chacun avec ses valeurs, ce qu'une baisse change, « Rallumer » et « C'est moi » ; puis les règles
//! existantes, trouvées par une recherche et activées ou désactivées (jamais effacées). Comme le reste de l'écran,
//! rien n'agit ici : une baisse est montrée puis confirmée dans la fenêtre administrateur, qui relit, rejuge et
//! garde la session à distance en cours (`machine::windows::pare_feu::ecrire_choix`).
//!
//! Le modèle est pur et testé sur tous les systèmes ; la boucle, sous Windows, est dans `ecran::boucle`.

use super::*;
use crate::machine::gestes::{ActionRegle, RegleLue};

/// Au plus tant de règles montrées pour une recherche : une rangée par règle, l'écran ne défile pas.
pub(in crate::options_defense) const REGLES_MONTREES: usize = 20;

fn indice(p: ProfilPareFeu) -> usize {
    match p {
        ProfilPareFeu::Domaine => 0,
        ProfilPareFeu::Prive => 1,
        ProfilPareFeu::Public => 2,
    }
}

fn position(r: ReglagePareFeu) -> usize {
    ReglagePareFeu::TOUS.iter().position(|x| *x == r).unwrap_or(0)
}

/// La valeur lue d'un réglage d'un profil, comme la note la compare : 1 la plus fermée (allumé, bloquer, tout
/// bloquer), 0 l'autre ; `None` illisible.
pub(in crate::options_defense) fn valeur_pf(e: &Etat, p: ProfilPareFeu, r: ReglagePareFeu) -> Option<i64> {
    let f = e.pare_feu?;
    let pr = f.profils.get(indice(p))?;
    let ferme = match r {
        ReglagePareFeu::Actif => pr.actif,
        ReglagePareFeu::Entrant => pr.entrees_bloquees,
        ReglagePareFeu::Sortant => pr.sorties_bloquees,
        ReglagePareFeu::ToutBloquer => pr.tout_bloquer,
    }?;
    Some(i64::from(ferme))
}

/// Le profil est-il celui d'un réseau actuel ? Illisible : oui, comme la garde de session le compte.
fn courant(e: &Etat, p: ProfilPareFeu) -> bool {
    e.pare_feu.and_then(|f| f.courants).is_none_or(|c| c & p.bit() != 0)
}

fn courant_lu(e: &Etat, p: ProfilPareFeu) -> bool {
    e.pare_feu.and_then(|f| f.courants).is_some_and(|c| c & p.bit() != 0)
}

fn texte_pf(id: IdChoix, v: Option<i64>) -> String {
    texte_choix(id, v.map(Some))
}

/// La touche d'un réglage dans l'écran du pare-feu : « 1 » à « 4 » pour Domaine, « 5 » à « 8 » pour Privé, « 9 » à
/// « 12 » pour Public.
pub(in crate::options_defense) fn touche_pf(p: ProfilPareFeu, r: ReglagePareFeu) -> String {
    indice(p)
        .saturating_mul(4)
        .saturating_add(position(r))
        .saturating_add(1)
        .to_string()
}

/// Le réglage désigné par une touche de l'écran du pare-feu.
pub(in crate::options_defense) fn reglage_de_touche_pf(touche: &str) -> Option<(ProfilPareFeu, ReglagePareFeu)> {
    let n: usize = touche.trim().parse().ok()?;
    let k = n.checked_sub(1)?;
    Some((*ProfilPareFeu::TOUS.get(k / 4)?, *ReglagePareFeu::TOUS.get(k % 4)?))
}

fn lecture_pf(id: IdChoix, v: Option<i64>, notes: &Notes) -> Option<Lecture> {
    choix_avant::note_de(notes, id).map(|n| choix_avant::lecture_note(id, n, v.map(Some)))
}

/// « Rallumer » d'un réglage : avec une note, ou quand la valeur protège moins que la valeur sûre ; jamais quand la
/// cible est déjà la valeur actuelle (comme `rallumable` des options).
fn rallumable_pf(e: &Etat, p: ProfilPareFeu, r: ReglagePareFeu, notes: &Notes) -> Option<i64> {
    let id = IdChoix::PareFeu(p, r);
    let note = choix_avant::note_de(notes, id);
    let v = valeur_pf(e, p, r);
    let cible = gestes::cible_rallumer(id, note.map(|n| n.avant));
    let sous = v.is_some_and(|v| id.baissee(Some(v)));
    ((note.is_some() || sous) && v != Some(cible)).then_some(cible)
}

/// « C'est moi » d'un réglage (P11) : une valeur lue sous la valeur sûre, pas encore notée telle quelle.
fn notable_pf(e: &Etat, p: ProfilPareFeu, r: ReglagePareFeu, notes: &Notes) -> bool {
    let id = IdChoix::PareFeu(p, r);
    let v = valeur_pf(e, p, r);
    v.is_some() && choix_avant::sens_noter(id, Some(v), choix_avant::note_de(notes, id)) == Sens::Baisse
}

/// Les règles notées « par votre choix » : leur valeur ne se lit qu'en les cherchant, « Rallumer » les propose
/// toutes ; le processus élevé relit et ne baisse jamais.
fn regles_notees(notes: &Notes) -> Vec<IdChoix> {
    notes
        .iter()
        .filter(|(id, n)| matches!(id, IdChoix::PareFeuRegle(..)) && n.is_some())
        .map(|(id, _)| *id)
        .collect()
}

/// Les « Rallumer » de l'écran du pare-feu : les réglages baissés ou notés, puis les règles notées.
pub(in crate::options_defense) fn rallumer_tout_pf(e: &Etat, notes: &Notes) -> Vec<Change> {
    let mut l = Vec::new();
    for p in ProfilPareFeu::TOUS {
        for r in ReglagePareFeu::TOUS {
            if let Some(cible) = rallumable_pf(e, p, r, notes) {
                let id = IdChoix::PareFeu(p, r);
                let actuel = texte_pf(id, valeur_pf(e, p, r));
                l.push(Change {
                    id,
                    ligne: gestes::ligne_rallumer(id),
                    texte: trf!(
                        "{} : {actuel} → rallumer ({})",
                        "{}: {actuel} → turn back on ({})",
                        nom_choix(id),
                        texte_pf(id, Some(cible))
                    ),
                    cible: Some(cible),
                });
            }
        }
    }
    for id in regles_notees(notes) {
        let avant = choix_avant::note_de(notes, id).map(|n| n.avant);
        let cible = gestes::cible_rallumer(id, avant);
        l.push(Change {
            id,
            ligne: gestes::ligne_rallumer(id),
            texte: trf!(
                "{} ({}) → rallumer ({})",
                "{} ({}) → turn back on ({})",
                nom_choix(id),
                nom_note(id),
                texte_pf(id, Some(cible))
            ),
            cible: Some(cible),
        });
    }
    l
}

/// Le texte de ce qui empêche le service du pare-feu de s'arrêter (plan §2.3).
pub(in crate::options_defense) fn texte_services_pf() -> &'static str {
    tr!(
        "Vanguard ne propose pas d'arrêter le service du pare-feu (mpssvc) ni le moteur de filtrage (BFE) : le réseau, IPsec et le partage de connexion seraient cassés. Couper le pare-feu d'un profil fait le même effet, proprement, et « Rallumer » le remet.",
        "Vanguard does not offer to stop the firewall service (mpssvc) or the filtering engine (BFE): the network, IPsec and connection sharing would break. Turning off a profile's firewall has the same effect, cleanly, and “Turn back on” restores it."
    )
}

/// Ce que dit la garde de la session à distance pour un réglage d'un profil actuel.
fn texte_session_pf(r: ReglagePareFeu) -> Option<&'static str> {
    match r {
        ReglagePareFeu::Sortant | ReglagePareFeu::ToutBloquer => Some(tr!(
            "Pendant une session à distance (Bureau à distance, SSH, AnyDesk, VPN…), la fenêtre administrateur refuse de le fermer sur le profil d'un réseau actuel : la session ne serait jamais coupée.",
            "During a remote session (Remote Desktop, SSH, AnyDesk, VPN…), the administrator window refuses to close it on a current network's profile: the session would never be cut."
        )),
        ReglagePareFeu::Entrant => Some(tr!(
            "Pendant une session à distance, bloquer les entrées reste permis tant que la session garde une règle qui l'autorise ; sinon, la fenêtre administrateur refuse.",
            "During a remote session, blocking inbound stays allowed as long as the session keeps a rule that allows it; otherwise the administrator window refuses."
        )),
        ReglagePareFeu::Actif => None,
    }
}

/// Le pare-feu d'un autre programme, nommé (plan §3.3).
fn texte_tiers(e: &Etat) -> Option<String> {
    e.centre.pare_feu_tiers().map(|p| {
        let n = crate::ui::affichable(&p.nom);
        trf!(
            "{n} gère le pare-feu ; le pare-feu de Windows peut être coupé par lui, c'est voulu.",
            "{n} manages the firewall; Windows Firewall may be turned off by it, on purpose."
        )
    })
}

/// L'écran du pare-feu : les douze réglages (quatre par profil), les règles, « Rallumer », le détail.
pub(in crate::options_defense) fn lignes_pare_feu(e: &Etat, notes: &Notes, changes: &[Change]) -> Vec<Ligne> {
    let mut l = vec![
        Ligne::Texte(String::new()),
        Ligne::Texte(ligne_titre(tr!("Pare-feu Windows", "Windows Firewall"))),
    ];
    let mut infos: Vec<String> = Vec::new();
    if let Some(t) = texte_tiers(e) {
        infos.push(t);
    }
    match e.pare_feu {
        None => infos.push(
            tr!(
                "Non vérifié : le Pare-feu Windows ne répond pas (service arrêté ?). La fenêtre administrateur relit avant d'écrire.",
                "Not checked: Windows Firewall does not answer (service stopped?). The administrator window reads it again before writing."
            )
            .to_string(),
        ),
        Some(f) if f.modification == Some(1) => infos.push(
            tr!(
                "Une stratégie (GPO ou Intune) l'emporte sur le profil actuel : Windows garde sa valeur, quoi que Vanguard écrive.",
                "A policy (GPO or Intune) wins on the current profile: Windows keeps its value, whatever Vanguard writes."
            )
            .to_string(),
        ),
        Some(_) => {}
    }
    for i in infos {
        paragraphe(&mut l, &i, GRIS);
    }
    let (mut etoile, mut double) = (false, false);
    for p in ProfilPareFeu::TOUS {
        let mut titre_profil = if courant_lu(e, p) {
            trf!("{} (réseau actuel)", "{} (current network)", nom_profil_pare_feu(p))
        } else {
            nom_profil_pare_feu(p).to_string()
        };
        if e.pare_feu_impose().get(indice(p)).copied().flatten() == Some(true) {
            titre_profil.push_str(" *");
            etoile = true;
        }
        l.push(Ligne::Texte(String::new()));
        l.push(Ligne::Texte(format!("  {GRAS}{titre_profil}{RESET}")));
        for r in ReglagePareFeu::TOUS {
            let id = IdChoix::PareFeu(p, r);
            let v = valeur_pf(e, p, r);
            let mut texte = nom_reglage_pare_feu(r).to_string();
            if matches!(lecture_pf(id, v, notes), Some(Lecture::ParChoix(_))) {
                texte.push_str(" ‡");
                double = true;
            }
            let precision = match changes.iter().find(|c| c.id == id) {
                Some(c) => format!("→ {}", texte_cible(c)),
                None => texte_pf(id, v),
            };
            l.push(Ligne::choix(&touche_pf(p, r), &texte, &precision));
        }
    }
    l.push(Ligne::Texte(String::new()));
    let en_regles = changes
        .iter()
        .filter(|c| matches!(c.id, IdChoix::PareFeuRegle(..)))
        .count();
    let regles = if en_regles > 0 {
        trf!("{en_regles} à appliquer", "{en_regles} to apply")
    } else {
        match e.pare_feu.and_then(|f| f.regles) {
            Some(n) => trf!("{n} règles", "{n} rules"),
            None => String::new(),
        }
    };
    l.push(Ligne::choix(
        "f",
        tr!("Chercher une règle existante ›", "Find an existing rule ›"),
        &regles,
    ));
    let a_rallumer = rallumer_tout_pf(e, notes).len();
    if a_rallumer > 0 {
        l.push(Ligne::choix(
            "r",
            &trf!(
                "Rallumer ce qui est baissé ({a_rallumer})",
                "Turn back on what is lowered ({a_rallumer})"
            ),
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
    l.push(Ligne::Texte(String::new()));
    if etoile {
        paragraphe(
            &mut l,
            tr!(
                "* imposé par une stratégie (GPO ou Intune) : Windows garde sa valeur.",
                "* enforced by a policy (GPO or Intune): Windows keeps its value."
            ),
            GRIS,
        );
    }
    if double {
        paragraphe(
            &mut l,
            tr!(
                "‡ baissé par votre choix ; « Rallumer » dans sa ligne.",
                "‡ lowered by your choice; “Turn back on” in its line."
            ),
            GRIS,
        );
    }
    paragraphe(&mut l, texte_services_pf(), GRIS);
    borner(&mut l);
    l
}

/// Ce que fait une touche de l'écran du pare-feu.
#[derive(Clone, Debug, PartialEq)]
pub(in crate::options_defense) enum SuitePf {
    Reglage(ProfilPareFeu, ReglagePareFeu),
    Regles,
    Voir,
    Ajouter(Vec<Change>),
    Rien,
}

pub(in crate::options_defense) fn suite_pare_feu(e: &Etat, notes: &Notes, touche: &str) -> SuitePf {
    match touche.trim() {
        "f" => SuitePf::Regles,
        "v" => SuitePf::Voir,
        "r" => match rallumer_tout_pf(e, notes) {
            l if l.is_empty() => SuitePf::Rien,
            l => SuitePf::Ajouter(l),
        },
        t => reglage_de_touche_pf(t).map_or(SuitePf::Rien, |(p, r)| SuitePf::Reglage(p, r)),
    }
}

/// Le sous-écran d'un réglage d'un profil : sa valeur, ce qui l'empêche d'agir, ses deux valeurs, « Rallumer »,
/// « C'est moi », ce qu'une baisse change et ce que la garde de session refuse.
pub(in crate::options_defense) fn lignes_reglage_pf(
    etat: &Etat,
    p: ProfilPareFeu,
    r: ReglagePareFeu,
    notes: &Notes,
    changes: &[Change],
) -> Vec<Ligne> {
    let id = IdChoix::PareFeu(p, r);
    let lue = valeur_pf(etat, p, r);
    let mut l = vec![
        Ligne::Texte(String::new()),
        Ligne::Texte(ligne_titre(tr!("Pare-feu Windows", "Windows Firewall"))),
        // Le profil puis le réglage, plus court que `nom_choix` : la valeur illisible y tient encore en 76 colonnes.
        Ligne::Texte(format!(
            "  {GRAS}{} › {} : {}{RESET}",
            nom_profil_pare_feu(p),
            nom_reglage_pare_feu(r),
            texte_pf(id, lue)
        )),
    ];
    let mut infos: Vec<String> = Vec::new();
    if courant_lu(etat, p) {
        infos.push(tr!("Le profil du réseau actuel.", "The current network's profile.").to_string());
    }
    if r != ReglagePareFeu::Actif && valeur_pf(etat, p, ReglagePareFeu::Actif) == Some(0) {
        infos.push(
            tr!(
                "Le pare-feu de ce profil est coupé : ce réglage n'a pas d'effet tant qu'il l'est.",
                "This profile's firewall is off: this setting has no effect while it is."
            )
            .to_string(),
        );
    }
    match etat.pare_feu_impose().get(indice(p)).copied().flatten() {
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
    if let Some(t) = texte_tiers(etat) {
        infos.push(t);
    }
    match lecture_pf(id, lue, notes) {
        Some(Lecture::ParChoix(d)) => infos.push(trf!(
            "Baissé par votre choix le {}. « Rallumer » le remet.",
            "Lowered by your choice on {}. “Turn back on” restores it.",
            choix_avant::date_note(d)
        )),
        Some(Lecture::Remontee) => infos.push(
            tr!(
                "Rallumé depuis votre choix, par Windows ou par quelqu'un.",
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
    for (k, fermee) in [true, false].into_iter().enumerate() {
        let cv = i64::from(fermee);
        let precision = if lue == Some(cv) {
            tr!("(actuelle)", "(current)")
        } else if cv == r.sure() {
            tr!("(la valeur sûre)", "(the safe value)")
        } else {
            ""
        };
        l.push(Ligne::choix(
            &k.saturating_add(1).to_string(),
            &majuscule(mot_valeur_pare_feu(r, fermee)),
            precision,
        ));
    }
    if let Some(cible) = rallumable_pf(etat, p, r, notes) {
        l.push(Ligne::choix(
            "r",
            &trf!("Rallumer ({})", "Turn back on ({})", texte_pf(id, Some(cible))),
            "",
        ));
    }
    if notable_pf(etat, p, r, notes) {
        l.push(Ligne::choix(
            "m",
            tr!("C'est moi : noter « par votre choix »", "It was me: note “your choice”"),
            tr!("le bilan n'alertera plus", "the check stops alerting"),
        ));
    }
    l.push(Ligne::Texte(String::new()));
    paragraphe(&mut l, &effet_baisse(id), GRIS);
    if courant(etat, p)
        && let Some(t) = texte_session_pf(r)
    {
        paragraphe(&mut l, t, GRIS);
    }
    if r == ReglagePareFeu::Actif {
        paragraphe(&mut l, texte_services_pf(), GRIS);
    }
    l.push(Ligne::Texte(String::new()));
    l.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
    borner(&mut l);
    l
}

/// Ce que fait une touche du sous-écran d'un réglage.
pub(in crate::options_defense) fn suite_reglage_pf(
    etat: &Etat,
    p: ProfilPareFeu,
    r: ReglagePareFeu,
    notes: &Notes,
    touche: &str,
) -> Suite {
    let id = IdChoix::PareFeu(p, r);
    let lue = valeur_pf(etat, p, r);
    let actuel = texte_pf(id, lue);
    match touche.trim() {
        "r" => match rallumable_pf(etat, p, r, notes) {
            Some(cible) => Suite::Ajouter(Change {
                id,
                ligne: gestes::ligne_rallumer(id),
                texte: trf!(
                    "{} : {actuel} → rallumer ({})",
                    "{}: {actuel} → turn back on ({})",
                    nom_choix(id),
                    texte_pf(id, Some(cible))
                ),
                cible: Some(cible),
            }),
            None => Suite::Rien,
        },
        "m" if notable_pf(etat, p, r, notes) => Suite::Ajouter(Change {
            id,
            ligne: gestes::ligne_noter(id),
            texte: trf!(
                "{} : {actuel}, noter « par votre choix »",
                "{}: {actuel}, note “your choice”",
                nom_choix(id)
            ),
            cible: None,
        }),
        t => {
            let fermee = match t {
                "1" => true,
                "2" => false,
                _ => return Suite::Rien,
            };
            let cv = i64::from(fermee);
            if lue == Some(cv) {
                return Suite::Retirer(id);
            }
            Suite::Ajouter(Change {
                id,
                ligne: gestes::ligne_baisse_pare_feu(p, r, fermee),
                texte: format!("{} : {actuel} → {}", nom_choix(id), mot_valeur_pare_feu(r, fermee)),
                cible: Some(cv),
            })
        }
    }
}

// ------------------------------------------------------------------ les règles existantes

/// Une règle trouvée par la recherche : le nom, le programme, le groupe ou les ports locaux, sans accents ni
/// majuscules. Une recherche vide ne trouve rien (des centaines de règles).
pub(in crate::options_defense) fn trouver_regles<'a>(regles: &'a [RegleLue], recherche: &str) -> Vec<&'a RegleLue> {
    let r = crate::selection::simplifier(recherche.trim());
    if r.is_empty() {
        return Vec::new();
    }
    regles
        .iter()
        .filter(|x| {
            [&x.nom, &x.programme, &x.groupe, &x.ports_locaux]
                .iter()
                .any(|t| crate::selection::simplifier(t).contains(&r))
        })
        .take(REGLES_MONTREES)
        .collect()
}

/// Le sens, l'action, les ports et l'état d'une règle, en court (la précision d'une rangée).
fn resume_regle(x: &RegleLue) -> String {
    let sens = if x.entrante {
        tr!("entrée", "in")
    } else {
        tr!("sortie", "out")
    };
    let action = if x.bloque {
        tr!("bloque", "blocks")
    } else {
        tr!("autorise", "allows")
    };
    let etat = if x.active {
        tr!("active", "on")
    } else {
        tr!("inactive", "off")
    };
    let ports = x.ports_locaux.trim();
    if ports.is_empty() || ports == "*" {
        format!("{sens} · {action} · {etat}")
    } else {
        format!("{sens} · {action} · {} · {etat}", crate::ui::affichable(ports))
    }
}

/// Le changement qui bascule une règle (active devient inactive, et l'inverse).
fn change_regle(x: &RegleLue) -> Change {
    let id = x.id();
    let nom = crate::ui::affichable(&x.nom);
    let (avant, apres) = (i64::from(x.active), i64::from(!x.active));
    Change {
        id,
        ligne: gestes::ligne_regle_etat(x, !x.active),
        texte: format!(
            "{} « {nom} » : {} → {}",
            nom_choix(id),
            texte_pf(id, Some(avant)),
            texte_pf(id, Some(apres))
        ),
        cible: Some(apres),
    }
}

/// La liste des règles trouvées : une touche par règle (« 1 » à « 20 »), qui la bascule ; une règle déjà choisie se
/// retire en la choisissant de nouveau. `regles` : `None` si le pare-feu ne les a pas données.
pub(in crate::options_defense) fn lignes_regles(
    regles: Option<&[RegleLue]>,
    recherche: &str,
    notes: &Notes,
    changes: &[Change],
) -> Vec<Ligne> {
    let mut l = vec![
        Ligne::Texte(String::new()),
        Ligne::Texte(ligne_titre(tr!("Règles du pare-feu", "Firewall rules"))),
    ];
    let Some(regles) = regles else {
        paragraphe(
            &mut l,
            tr!(
                "Les règles ne se lisent pas (le pare-feu ne répond pas) : rien à montrer.",
                "The rules cannot be read (the firewall does not answer): nothing to show."
            ),
            GRIS,
        );
        l.push(Ligne::Texte(String::new()));
        l.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
        borner(&mut l);
        return l;
    };
    let trouvees = trouver_regles(regles, recherche);
    let r = crate::ui::affichable(recherche.trim());
    let entete = if trouvees.is_empty() {
        trf!("Aucune règle pour « {r} ».", "No rule for “{r}”.")
    } else if trouvees.len() == REGLES_MONTREES {
        trf!(
            "Les {REGLES_MONTREES} premières règles pour « {r} » (précisez la recherche pour en voir d'autres).",
            "The first {REGLES_MONTREES} rules for “{r}” (narrow the search to see others)."
        )
    } else {
        trf!("Règles pour « {r} » :", "Rules for “{r}”:")
    };
    paragraphe(&mut l, &entete, GRIS);
    l.push(Ligne::Texte(String::new()));
    let mut double = false;
    for (k, x) in trouvees.iter().enumerate() {
        let id = x.id();
        let mut texte = crate::ui::affichable(&x.nom);
        if let Some(n) = choix_avant::note_de(notes, id)
            && matches!(
                choix_avant::lecture_note(id, n, Some(Some(i64::from(x.active)))),
                Lecture::ParChoix(_)
            )
        {
            texte.push_str(" ‡");
            double = true;
        }
        let precision = match changes.iter().find(|c| c.id == id) {
            Some(c) => format!("→ {}", texte_cible(c)),
            None => resume_regle(x),
        };
        l.push(Ligne::choix(&k.saturating_add(1).to_string(), &texte, &precision));
    }
    l.push(Ligne::Texte(String::new()));
    l.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
    l.push(Ligne::Texte(String::new()));
    if double {
        paragraphe(
            &mut l,
            tr!(
                "‡ changée par votre choix ; « Rallumer » dans l'écran du pare-feu.",
                "‡ changed by your choice; “Turn back on” in the firewall screen."
            ),
            GRIS,
        );
    }
    paragraphe(
        &mut l,
        tr!(
            "Choisir une règle la bascule : active devient inactive, et l'inverse. Aucune règle n'est jamais effacée.",
            "Choosing a rule toggles it: enabled becomes disabled, and the reverse. No rule is ever deleted."
        ),
        GRIS,
    );
    paragraphe(
        &mut l,
        &effet_baisse(IdChoix::PareFeuRegle(ActionRegle::Bloque, EmpreinteElement::de(""))),
        GRIS,
    );
    paragraphe(
        &mut l,
        &effet_baisse(IdChoix::PareFeuRegle(ActionRegle::Autorise, EmpreinteElement::de(""))),
        GRIS,
    );
    paragraphe(
        &mut l,
        tr!(
            "Pendant une session à distance, la fenêtre administrateur refuse de désactiver une règle entrante qui autorise sur le profil d'un réseau actuel, celle du Bureau à distance (3389) ou de SSH (22), et d'activer une règle qui bloquerait la session.",
            "During a remote session, the administrator window refuses to disable an inbound allow rule on a current network's profile, the Remote Desktop (3389) or SSH (22) rule, and to enable a rule that would block the session."
        ),
        GRIS,
    );
    borner(&mut l);
    l
}

/// Ce que fait une touche de la liste des règles trouvées.
pub(in crate::options_defense) fn suite_regles(
    regles: &[RegleLue],
    recherche: &str,
    changes: &[Change],
    touche: &str,
) -> Suite {
    let trouvees = trouver_regles(regles, recherche);
    let Some(x) = touche
        .trim()
        .parse::<usize>()
        .ok()
        .and_then(|n| n.checked_sub(1))
        .and_then(|k| trouvees.get(k))
    else {
        return Suite::Rien;
    };
    let id = x.id();
    if changes.iter().any(|c| c.id == id) {
        Suite::Retirer(id)
    } else {
        Suite::Ajouter(change_regle(x))
    }
}

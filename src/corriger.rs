//! Application interactive des correctifs : chaque action est montrée puis confirmée.

use crate::amelioration::{Choisi, Issue};
use crate::machine::{self, Audit, Constat, Correctif, Defaire};
use crate::optimiser::annulables;
use crate::reseau::{Hote, Rapport};
use crate::risk::Niveau;
use crate::ui::*;

/// Ce que `proposer` a fait des corrections proposées : de quoi dire le code de sortie de « vanguard corriger ».
#[derive(Debug, Default)]
pub struct Bilan {
    /// Les catégories des corrections appliquées.
    pub appliquees: Vec<&'static str>,
    /// Refusées dans la liste (« n », ou Entrée seule) : la personne n'en voulait pas.
    pub refusees: usize,
    /// Acceptées (« o », « t ») mais pas faites : « N » ou Entrée dans la fenêtre administrateur, UAC refusée,
    /// échec de la commande, point de restauration refusé, valeurs d'avant non enregistrées.
    pub non_faites: usize,
}

impl Bilan {
    /// 0 : tout ce qui a été accepté est fait et rien n'a été refusé (ou il n'y avait rien à faire) ; 1 : une
    /// correction acceptée n'est pas faite ; 2 : des corrections refusées dans la liste, les acceptées faites.
    /// Avant, « vanguard corriger » rendait toujours 0 : un script (un banc d'essai) le croyait fait (D6b, étape 2).
    /// « `[i]gnorer` » ne compte pas : c'est dire que l'état est normal ici, pas refuser une correction.
    pub fn code(&self) -> i32 {
        if self.non_faites > 0 {
            1
        } else if self.refusees > 0 {
            2
        } else {
            0
        }
    }
}

/// Propose chaque correction automatique, puis liste celles à faire soi-même. « `[t]out` » applique la correction
/// en cours et toutes les suivantes en une seule exécution : une seule fenêtre administrateur sous Windows.
/// Retourne ce qui a été fait (le `Bilan`). `contexte` nomme le point de restauration créé automatiquement avant
/// la première correction appliquée (« corrections », « mises à jour »).
pub fn proposer(constats: &[Constat], contexte: &str) -> Bilan {
    let mut point_cree = false;
    let auto: Vec<_> = constats
        .iter()
        .filter_map(|c| Some((c, c.correctif.as_ref().filter(|k| k.automatique)?)))
        .collect();
    let mut bilan = Bilan::default();
    // Ce que l'Agent Vanguard sait des corrections d'ici (R6) : de l'information seulement, rien n'est retiré.
    let avis = crate::agent::avis_corrections();
    let fragile = |c: &Constat| avis.de(c.regle).fragile.is_some();
    // Les corrections déjà appliquées par un « tout » : celles qui restent (les fragiles) se proposent une à une.
    let mut par_le_lot = vec![false; auto.len()];
    if auto.is_empty() {
        trp!(
            "  {VERT}✔{RESET} Rien à corriger automatiquement.",
            "  {VERT}✔{RESET} Nothing to fix automatically."
        );
    } else {
        trp!(
            "  {} correction(s) possible(s). Chacune vous sera montrée avant d'être appliquée.",
            "  {} fix(es) available. Each one will be shown to you before it is applied.",
            auto.len()
        );
        for (i, (c, k)) in auto.iter().enumerate() {
            if par_le_lot.get(i) == Some(&true) {
                continue;
            }
            let n = c.probleme.unwrap_or(Niveau::Info);
            println!(
                "\n  {}[{}]{RESET} {GRAS}{}{RESET} — {}",
                couleur(n),
                n.libelle(),
                crate::langue::categorie(c.categorie),
                c.message
            );
            println!("  {} {}", cle_a_molette(), k.action);
            for cmd in &k.commandes {
                println!("    {GRIS}{cmd}{RESET}");
            }
            dire_si_annulable(k);
            dire_l_avis(avis.de(c.regle));
            crate::amelioration::noter_correction(c.regle, Issue::Proposee);
            // « [i]gnorer » seulement pour une alerte qui peut se déclarer normale ; refusé ou annulé à la
            // confirmation, la question revient.
            let declarable = crate::apprentissage::declarable(c);
            if let Err(raison) = &declarable {
                afficher_aligne(
                    "    ",
                    &trf!(
                        "Ne peut pas être déclarée normale : {raison}.",
                        "Cannot be declared normal: {raison}."
                    ),
                    4,
                    GRIS,
                );
            }
            let rep = loop {
                let rep = demander(if declarable.is_ok() {
                    tr!(
                        "  Appliquer ? [o]ui / [n]on / [t]out appliquer / [i]gnorer, c'est normal chez moi : ",
                        "  Apply? [y]es / [n]o / [a]ll / [i]gnore, this is normal for me: "
                    )
                } else {
                    tr!(
                        "  Appliquer ? [o]ui / [n]on / [t]out appliquer : ",
                        "  Apply? [y]es / [n]o / [a]ll: "
                    )
                })
                .to_lowercase();
                if rep.trim() != "i" || declarable.is_err() {
                    break Some(rep);
                }
                if crate::apprentissage::declarer_normale(c) {
                    break None;
                }
            };
            let Some(rep) = rep else {
                continue;
            };
            let tout = crate::langue::tout(&rep);
            // « Tout » ne prend pas d'avance une correction fragile (échouée deux fois ici) : elle reste proposée, une
            // à une, après le lot. Celle qui vient d'être montrée, si : la personne l'a vue.
            let places: Vec<usize> = if tout {
                places_du_lot(
                    i,
                    auto.len(),
                    &|j| auto.get(j).is_some_and(|(c, _)| fragile(c)),
                    &par_le_lot,
                )
            } else {
                vec![i]
            };
            let lot: Vec<(&Constat, &Correctif)> = if tout {
                places.iter().filter_map(|&j| auto.get(j).copied()).collect()
            } else if crate::langue::oui(&rep) {
                vec![(c, k)]
            } else {
                crate::amelioration::noter_correction(c.regle, Issue::Refusee);
                crate::amelioration::noter_choix(c.regle, Choisi::Refus);
                bilan.refusees = bilan.refusees.saturating_add(1);
                trp!("    {GRIS}ignoré{RESET}", "    {GRIS}skipped{RESET}");
                continue;
            };
            // « Tout » : les suivantes sont proposées et acceptées d'un coup, sans avoir été montrées une à une.
            for (j, (c, _)) in lot.iter().enumerate() {
                if j > 0 {
                    crate::amelioration::noter_correction(c.regle, Issue::Proposee);
                }
                crate::amelioration::noter_correction(c.regle, Issue::Acceptee);
            }
            let fragiles_ensuite = if tout {
                (i..auto.len())
                    .filter(|j| !places.contains(j) && par_le_lot.get(*j) != Some(&true))
                    .count()
            } else {
                0
            };
            if lot.len() > 1 {
                trp!(
                    "    {GRIS}Les {} corrections restantes, en une fois.{RESET}",
                    "    {GRIS}The {} remaining fixes, in one go.{RESET}",
                    lot.len()
                );
                // Les suivantes n'ont pas été montrées une à une : ce qui ne s'annulera pas est dit avant.
                for (_, k) in lot.iter().skip(1) {
                    afficher_aligne("    • ", &k.action, 6, "");
                    dire_si_annulable(k);
                }
            }
            // Une liste de commandes par correction : chacune réussit ou échoue pour elle-même.
            #[cfg_attr(not(windows), allow(unused_mut))]
            let mut groupes: Vec<Vec<String>> = lot.iter().map(|(_, k)| k.commandes.clone()).collect();
            if !point_cree {
                point_cree = true;
                match crate::reparer::point_restauration(contexte) {
                    Some((outil, point)) => {
                        trp!(
                            "    {GRIS}Point de restauration d'abord ({outil}), pour pouvoir revenir en arrière.{RESET}",
                            "    {GRIS}Restore point first ({outil}), so you can go back.{RESET}"
                        );
                        // Windows : dans la même fenêtre administrateur que la correction (une seule demande).
                        #[cfg(windows)]
                        groupes.insert(0, vec![point]);
                        #[cfg(not(windows))]
                        if !machine::appliquer(&[point])
                            && !demander(tr!(
                                "    ✖ Point de restauration impossible. Continuer quand même ? [o/N] : ",
                                "    ✖ Restore point not possible. Continue anyway? [y/N]: "
                            ))
                            .oui()
                        {
                            // Pas de correction sans point de restauration : on le retentera avant la prochaine
                            // correction acceptée, au lieu de l'appliquer sans rien dire.
                            point_cree = false;
                            bilan.non_faites = bilan.non_faites.saturating_add(lot.len());
                            trp!("    {GRIS}ignoré{RESET}", "    {GRIS}skipped{RESET}");
                            continue;
                        }
                    }
                    None => trp!(
                        "    {GRIS}Pas de snapper ni de timeshift configuré : pas de point de restauration possible.{RESET}",
                        "    {GRIS}No snapper or timeshift configured: no restore point possible.{RESET}"
                    ),
                }
            }
            // Les valeurs d'avant, relevées juste avant d'appliquer et notées (scellées) : sans note enregistrée, une
            // correction annoncée annulable ne le serait plus, rien n'est appliqué.
            // Celles du lot qui touchent la même chose partagent une note : leur état d'avant n'existe qu'une fois.
            let (releves, ids_lot) = annulables::regrouper(lot.iter().map(|(_, k)| relever(k).ok()).collect());
            let a_noter: Vec<&annulables::Releve> = releves.iter().flatten().collect();
            if !a_noter.is_empty() && !annulables::noter(&a_noter) {
                trp!(
                    "    ✖ Valeurs d'avant non enregistrées : rien n'a été appliqué.",
                    "    ✖ Previous values not saved: nothing was applied."
                );
                bilan.non_faites = bilan.non_faites.saturating_add(lot.len());
                continue;
            }
            let mut ids = ids_lot;
            if groupes.len() > lot.len() {
                ids.insert(0, None);
            }
            let mut resultats = machine::appliquer_annulables(&groupes, &ids);
            // Windows : le point de restauration est passé en premier dans la fenêtre administrateur. Refusé là, ou
            // fenêtre refusée : rien n'a été fait, il sera retenté avant la prochaine correction acceptée.
            if groupes.len() > lot.len() && !resultats.remove(0) {
                point_cree = false;
            }
            let decale = usize::from(groupes.len() > lot.len());
            annulables::apres_application(
                &ids.iter()
                    .skip(decale)
                    .zip(&resultats)
                    .filter_map(|(id, ok)| Some((id.clone()?, *ok)))
                    .collect::<Vec<_>>(),
            );
            // Arrêtée à la demande de la personne, une correction n'a ni réussi ni échoué : l'agent n'en dit rien.
            let noter_pour_l_agent = !machine::arretee_a_votre_demande();
            for ((c, k), reussi) in lot.iter().zip(resultats) {
                if noter_pour_l_agent {
                    crate::agent::noter_correction(
                        c.regle,
                        reussi,
                        c.cle().map(|cle| crate::amelioration::empreinte(&cle)),
                    );
                }
                let issue = if reussi {
                    Issue::Reussie(c.cle())
                } else {
                    Issue::Echouee
                };
                crate::amelioration::noter_correction(c.regle, issue);
                if reussi {
                    machine::retenir_blocage(k);
                    // Une protection de Defender n'a pas de note d'annulation : seule la marque qu'il l'a posée
                    // reste, pour que le bilan dise plus fort qu'elle a été coupée ensuite.
                    #[cfg(windows)]
                    if let crate::modele::Objet::De(o) = &c.objet
                        && let Some(id) = o.strip_prefix("defender:")
                    {
                        crate::optimiser::retenir_protection(id);
                    }
                    bilan.appliquees.push(c.categorie);
                } else {
                    bilan.non_faites = bilan.non_faites.saturating_add(1);
                }
                let cat = crate::langue::categorie(c.categorie);
                // Sans ces lignes, un échec (UAC refusée, commande en erreur) passait sans un mot de Vanguard.
                match (lot.len() > 1, reussi) {
                    (false, true) => trp!("    {VERT}✔ fait{RESET}", "    {VERT}✔ done{RESET}"),
                    (false, false) => trp!(
                        "    ✖ non appliqué : voir le message ci-dessus",
                        "    ✖ not applied: see the message above"
                    ),
                    (true, true) => trp!("    {VERT}✔ {cat}{RESET}", "    {VERT}✔ {cat}{RESET}"),
                    (true, false) => trp!(
                        "    ✖ {cat} : non appliqué, voir le message ci-dessus",
                        "    ✖ {cat}: not applied, see the message above"
                    ),
                }
            }
            if tout {
                for j in &places {
                    if let Some(p) = par_le_lot.get_mut(*j) {
                        *p = true;
                    }
                }
                if fragiles_ensuite == 0 {
                    break;
                }
                trp!(
                    "\n    {GRIS}{} correction(s) fragile(s) hors du lot, proposée(s) à part.{RESET}",
                    "\n    {GRIS}{} fragile fix(es) left out of the batch, offered separately.{RESET}",
                    fragiles_ensuite
                );
            }
        }
    }

    let manuels: Vec<_> = constats
        .iter()
        .filter_map(|c| Some((c, c.correctif.as_ref().filter(|k| !k.automatique)?)))
        .collect();
    if !manuels.is_empty() {
        titre(tr!("À faire vous-même", "To do yourself"));
        for (c, k) in &manuels {
            let cat = crate::langue::categorie(c.categorie);
            let ampoule = ampoule();
            trp!(
                "  {ampoule} {GRAS}{cat}{RESET} : {}",
                "  {ampoule} {GRAS}{cat}{RESET}: {}",
                k.action
            );
            for cmd in &k.commandes {
                println!("     {GRIS}{cmd}{RESET}");
            }
            proposer_normale(c);
        }
    }
    bilan
}

/// Dans la liste « À faire vous-même » : « c'est normal chez moi » pour une alerte dont la règle relève ce que le
/// choix lierait (`machine::temoins`), ou pourquoi elle ne peut pas l'être. Entrée (ou la fin de l'entrée) passe.
fn proposer_normale(c: &Constat) {
    use crate::machine::temoins::Temoins;
    match (crate::apprentissage::declarable(c), c.temoins()) {
        (Ok(()), _) => {
            let rep = demander_ou_defaut(tr!(
                "     [i]gnorer, c'est normal chez moi ; Entrée pour passer : ",
                "     [i]gnore, this is normal for me; Enter to skip: "
            ));
            if rep.trim().eq_ignore_ascii_case("i") {
                crate::apprentissage::declarer_normale(c);
            }
        }
        (Err(raison), Temoins::Refuse(_)) => afficher_aligne(
            "     ",
            &trf!(
                "Ne peut pas être déclarée normale : {raison}.",
                "Cannot be declared normal: {raison}."
            ),
            5,
            GRIS,
        ),
        (Err(_), _) => {}
    }
}

/// Relève l'état d'avant d'une correction : erreur, pourquoi elle ne s'annulera pas.
fn relever(k: &Correctif) -> Result<annulables::Releve, annulables::PourquoiPas> {
    match k.comment_defaire() {
        Defaire::Gestes(g) => annulables::relever(annulables::id_bilan(), &k.action, &g),
        _ => Err(k.pourquoi_pas().unwrap_or(annulables::PourquoiPas::NonReleve)),
    }
}

/// Ce que prend un « tout » répondu à la correction `i` (sur `n`) : elle, et celles qui suivent, sauf les fragiles
/// (`fragile`), qui restent proposées une à une, et celles déjà appliquées par un lot d'avant (`deja`).
fn places_du_lot(i: usize, n: usize, fragile: &dyn Fn(usize) -> bool, deja: &[bool]) -> Vec<usize> {
    (i..n)
        .filter(|&j| j == i || (!fragile(j) && deja.get(j) != Some(&true)))
        .collect()
}

/// L'avis de l'Agent Vanguard sur une correction (R6) : échouée deux fois au moins ici, ou revenue après avoir été
/// appliquée. De l'information seulement : la correction reste proposée, la personne choisit.
fn dire_l_avis(avis: crate::agent::Avis) {
    if let Some((n, code)) = avis.fragile {
        trp!(
            "    ⚠ a échoué {n} fois sur cet ordinateur (code {code})",
            "    ⚠ failed {n} times on this computer (code {code})"
        );
    }
    if avis.ne_tient_pas {
        trp!(
            "    ⚠ ne tient pas : le problème est revenu après la correction",
            "    ⚠ does not hold: the problem came back after the fix"
        );
    }
}

/// Dit, avant d'appliquer, si la correction pourra se défaire : son état d'avant relevé, ou pourquoi pas.
fn dire_si_annulable(k: &Correctif) {
    match relever(k) {
        Ok(_) => trp!(
            "    {GRIS}↩ annulable ensuite depuis « Ce que Vanguard a changé »{RESET}",
            "    {GRIS}↩ can be undone later from “What Vanguard changed”{RESET}"
        ),
        Err(e) => afficher_aligne(
            "    ⚠ ",
            &trf!("Non annulable : {}.", "Not undoable: {}.", e.texte()),
            6,
            "",
        ),
    }
}

/// Propose les corrections de la machine, puis la marche à suivre pour le reste. Retourne le nouvel audit (si une
/// correction a été appliquée) et le code de sortie (`Bilan::code`).
pub fn corriger(audit: &Audit, reseau: Option<&Rapport>) -> (Option<Audit>, i32) {
    titre(tr!("Corrections", "Fixes"));
    let bilan = proposer(&audit.constats, tr!("corrections", "fixes"));
    let applique = !bilan.appliquees.is_empty();

    if let Some(r) = reseau {
        let exposes: Vec<_> = r
            .hotes
            .iter()
            .filter(|h| h.role != Some("cette machine") && !h.alertes.is_empty())
            .collect();
        if !exposes.is_empty() {
            titre(tr!(
                "Autres appareils du réseau (à corriger sur l'appareil lui-même)",
                "Other devices on the network (to fix on the device itself)"
            ));
            for h in exposes {
                println!("  {GRAS}{}{RESET} {}", h.ip, h.titre());
                for (n, msg) in &h.alertes {
                    println!("    {}→{RESET} {msg}", couleur(*n));
                }
                if let Some(lien) = interface_admin(h) {
                    trp!(
                        "    {GRIS}interface d'admin : {lien}{RESET}",
                        "    {GRIS}admin interface: {lien}{RESET}"
                    );
                }
                if h.ports.iter().any(|p| !p.udp && [135, 139, 445].contains(&p.port)) {
                    trp!(
                        "    {GRIS}PC Windows : Paramètres > Réseau > Propriétés > profil « Public », et dans PowerShell admin :{RESET}",
                        "    {GRIS}Windows PC: Settings > Network > Properties > “Public” profile, and in an admin PowerShell:{RESET}"
                    );
                    println!("    {GRIS}  Set-SmbServerConfiguration -EnableSMB1Protocol $false{RESET}");
                }
            }
        }
    }

    if applique {
        trp!(
            "\n{GRIS}Nouvelle vérification…{RESET}",
            "\n{GRIS}Checking again…{RESET}"
        );
        let nouveau = machine::auditer(false);
        afficher_note(tr!("Avant", "Before"), audit.score);
        afficher_note(tr!("Après", "After"), nouveau.score);
        return (Some(nouveau), bilan.code());
    }
    (None, bilan.code())
}

/// Adresse de la page d'administration d'un appareil, d'après ses ports ouverts (http d'abord). Hors des ports
/// habituels (80, 443), le port fait partie de l'adresse : sans lui, le lien viserait un port fermé.
fn interface_admin(h: &Hote) -> Option<String> {
    [
        (80, "http", ""),
        (8080, "http", ":8080"),
        (443, "https", ""),
        (8443, "https", ":8443"),
    ]
    .into_iter()
    .find(|&(port, ..)| h.ports.iter().any(|p| !p.udp && p.port == port))
    .map(|(_, schema, port)| format!("{schema}://{}{port}", h.ip))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reseau::PortOuvert;

    #[test]
    fn code_de_sortie_de_corriger() {
        let b = |appliquees: usize, refusees, non_faites| Bilan {
            appliquees: vec!["pare-feu"; appliquees],
            refusees,
            non_faites,
        };
        // Rien à faire, ou tout ce qui a été accepté est fait.
        assert_eq!(b(0, 0, 0).code(), 0);
        assert_eq!(b(3, 0, 0).code(), 0);
        // Des refus dans la liste, le reste fait (ou rien d'accepté) : 2, pas le faux vert d'avant.
        assert_eq!(b(1, 2, 0).code(), 2);
        assert_eq!(b(0, 4, 0).code(), 2);
        // Une acceptée non faite l'emporte sur tout : 1.
        assert_eq!(b(0, 0, 1).code(), 1);
        assert_eq!(b(2, 3, 1).code(), 1);
    }

    /// R6 : un « tout » laisse les corrections fragiles hors du lot, pour être proposées une à une ; répondu « tout »
    /// à chacune ensuite, chaque correction est appliquée une fois, aucune n'est perdue.
    #[test]
    fn tout_laisse_les_fragiles_a_part_sans_en_perdre() {
        let fragile = |j: usize| j == 2 || j == 4;
        assert_eq!(places_du_lot(0, 6, &fragile, &[false; 6]), [0, 1, 3, 5]);
        // La fragile montrée elle-même entre dans son lot : la personne l'a vue.
        assert_eq!(places_du_lot(2, 6, &fragile, &[false; 6]), [2, 3, 5]);
        for n in 0..8 {
            for masque in 0u32..(1 << n) {
                let fragile = |j: usize| masque & (1 << j) != 0;
                let mut faites = vec![false; n];
                let mut fois = vec![0; n];
                for i in 0..n {
                    if faites[i] {
                        continue;
                    }
                    for j in places_du_lot(i, n, &fragile, &faites) {
                        fois[j] += 1;
                        faites[j] = true;
                    }
                }
                assert!(fois.iter().all(|f| *f == 1), "{n} {masque:b} {fois:?}");
            }
        }
    }

    #[test]
    fn lien_d_administration_avec_son_port() {
        let port = |port| PortOuvert {
            port,
            service: "",
            niveau: Niveau::Info,
            banniere: None,
            conseil: "",
            nouveau: false,
            programme: None,
            udp: false,
        };
        let hote = |ports| Hote {
            ip: "192.168.1.20".parse().unwrap(),
            nom: None,
            mac: None,
            fabricant: None,
            surnom: None,
            premier_vu: None,
            role: None,
            nouvelle: false,
            ports,
            alertes: Vec::new(),
            score: 100,
        };
        let lien = |ports| interface_admin(&hote(ports));
        assert_eq!(lien(vec![port(8080)]).as_deref(), Some("http://192.168.1.20:8080"));
        assert_eq!(lien(vec![port(8443), port(80)]).as_deref(), Some("http://192.168.1.20"));
        assert_eq!(lien(vec![port(8443)]).as_deref(), Some("https://192.168.1.20:8443"));
        assert_eq!(lien(vec![port(22)]), None);
    }
}

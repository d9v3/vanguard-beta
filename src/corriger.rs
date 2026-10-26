//! Application interactive des correctifs : chaque action est montrée puis confirmée.

use crate::machine::{self, Audit, Constat, Correctif, Defaire};
use crate::optimiser::annulables;
use crate::reseau::{Hote, Rapport};
use crate::risk::Niveau;
use crate::ui::*;

/// Propose chaque correction automatique, puis liste celles à faire soi-même. « `[t]out` » applique la correction
/// en cours et toutes les suivantes en une seule exécution : une seule fenêtre administrateur sous Windows.
/// Retourne les catégories des corrections appliquées. `contexte` nomme le point de restauration créé
/// automatiquement avant la première correction appliquée (« corrections », « mises à jour »).
pub fn proposer(constats: &[Constat], contexte: &str) -> Vec<&'static str> {
    let mut point_cree = false;
    let auto: Vec<_> = constats
        .iter()
        .filter_map(|c| Some((c, c.correctif.as_ref().filter(|k| k.automatique)?)))
        .collect();
    let mut appliquees = Vec::new();
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
            let rep = demander(tr!(
                "  Appliquer ? [o]ui / [n]on / [t]out appliquer / [i]gnorer, c'est normal chez moi : ",
                "  Apply? [y]es / [n]o / [a]ll / [i]gnore, this is normal for me: "
            ))
            .to_lowercase();
            if rep.trim() == "i" {
                crate::apprentissage::accepter(c);
                continue;
            }
            let tout = crate::langue::tout(&rep);
            let lot: Vec<(&Constat, &Correctif)> = if tout {
                auto[i..].to_vec()
            } else if crate::langue::oui(&rep) {
                vec![(c, k)]
            } else {
                trp!("    {GRIS}ignoré{RESET}", "    {GRIS}skipped{RESET}");
                continue;
            };
            if lot.len() > 1 {
                trp!(
                    "    {GRIS}Les {} corrections restantes, en une fois.{RESET}",
                    "    {GRIS}The {} remaining fixes, in one go.{RESET}",
                    lot.len()
                );
                // Les suivantes n'ont pas été montrées une à une : ce qui ne s'annulera pas est dit avant.
                for (_, k) in &lot[1..] {
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
                &ids[decale..]
                    .iter()
                    .zip(&resultats)
                    .filter_map(|(id, ok)| Some((id.clone()?, *ok)))
                    .collect::<Vec<_>>(),
            );
            for ((c, k), reussi) in lot.iter().zip(resultats) {
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
                    appliquees.push(c.categorie);
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
                break;
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
        }
    }
    appliquees
}

/// Relève l'état d'avant d'une correction : erreur, pourquoi elle ne s'annulera pas.
fn relever(k: &Correctif) -> Result<annulables::Releve, annulables::PourquoiPas> {
    match k.comment_defaire() {
        Defaire::Gestes(g) => annulables::relever(annulables::id_bilan(), &k.action, &g),
        _ => Err(k.pourquoi_pas().unwrap_or(annulables::PourquoiPas::NonReleve)),
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

/// Propose les corrections de la machine, puis la marche à suivre pour le reste. Retourne le nouvel audit.
pub fn corriger(audit: &Audit, reseau: Option<&Rapport>) -> Option<Audit> {
    titre(tr!("Corrections", "Fixes"));
    let applique = !proposer(&audit.constats, tr!("corrections", "fixes")).is_empty();

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
        return Some(nouveau);
    }
    None
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

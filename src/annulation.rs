//! « Tout remettre comme avant » : ce que Vanguard a changé sur cet ordinateur et sait défaire exactement — les
//! corrections du bilan, les réglages d'Optimiser et de Gaming (leurs valeurs d'avant, dans reglages.json, scellé),
//! les blocages en place (changements.jsonl) et le mode Wi-Fi public —, montré d'abord, puis défait après un seul
//! accord, du plus récent au plus ancien, en une seule demande administrateur pour les réglages et les blocages.
//! Chaque réglage est relu après coup : ce qui n'est pas revenu est dit, et sa note reste pour réessayer.

use crate::changements::{Annulation, Blocage};
use crate::optimiser::annulables::{self, Issue, Note, Origine};
use crate::ui::*;

/// Ce qui se défait, rangé par date.
enum Element {
    Note(Note),
    Blocage(String, Box<Blocage>),
}

impl Element {
    fn date(&self) -> &str {
        match self {
            Element::Note(n) => &n.date,
            Element::Blocage(d, _) => d,
        }
    }
}

/// Les notes et les blocages, du plus récent au plus ancien : l'ordre où ils se défont. Un blocage qui a retiré un
/// programme du démarrage n'y est pas : sa note d'Optimiser (« demarrage:… ») le défait.
fn a_defaire(notes: Vec<Note>, blocages: Vec<(String, Blocage)>) -> Vec<Element> {
    let mut l: Vec<Element> = notes.into_iter().map(Element::Note).collect();
    l.extend(
        blocages
            .into_iter()
            .filter(|(_, b)| !matches!(b.annulation, Some(Annulation::Demarrage { .. })))
            .map(|(d, b)| Element::Blocage(d, Box::new(b))),
    );
    // Tri stable : à la même minute, l'ordre de chaque liste (déjà du plus récent au plus ancien) reste.
    l.sort_by(|a, b| b.date().cmp(a.date()));
    l
}

/// La ligne d'un élément, avant de demander.
fn ligne(e: &Element) -> String {
    match e {
        Element::Note(n) => {
            let refus = if n.admise {
                String::new()
            } else if n.origine == Origine::Optimiser {
                trf!(
                    " {GRIS}(note refusée : valeurs d'un système neuf){RESET}",
                    " {GRIS}(note refused: values of a fresh system){RESET}"
                )
            } else {
                trf!(
                    " {GRIS}(note refusée : rien ne sera remis){RESET}",
                    " {GRIS}(note refused: nothing will be put back){RESET}"
                )
            };
            format!("[{}] {}{refus}", n.origine.nom(), affichable(&n.titre))
        }
        Element::Blocage(_, b) => format!("[{}] {}", tr!("Blocage", "Block"), affichable(&b.quoi)),
    }
}

/// `vanguard optimiser annuler` et « Tout remettre comme avant » : tout ce que Vanguard sait défaire, montré, puis
/// défait après accord.
pub fn tout_remettre() {
    titre(tr!("Tout remettre comme avant", "Put everything back"));
    // Le mode Wi-Fi public d'abord : allumé, il tient le DNS et garde ses propres valeurs d'avant, prises sur l'état
    // que le reste a laissé ; c'est la couche la plus récente, qui s'enlève en premier.
    crate::reseau::wifi_public::proposer_d_eteindre();
    let tient = crate::reseau::wifi_public::tient_le_dns();
    let mut blocages = crate::changements::blocages_en_place();
    blocages.reverse();
    let elements = a_defaire(annulables::notes(None), blocages);
    if elements.is_empty() {
        trp!(
            "  {GRIS}Vanguard n'a rien changé qu'il sache défaire sur cet ordinateur.{RESET}",
            "  {GRIS}Vanguard has changed nothing it can undo on this computer.{RESET}"
        );
        return;
    }
    trp!(
        "\n  {GRAS}À défaire, du plus récent au plus ancien{RESET}",
        "\n  {GRAS}To undo, most recent first{RESET}"
    );
    for e in &elements {
        afficher_aligne(&format!("    − {GRIS}{}{RESET}  ", e.date()), &ligne(e), 22, "");
    }
    if tient {
        afficher_aligne(
            "  ",
            tr!(
                "Le mode Wi-Fi public tient le DNS : le DNS noté par Vanguard est laissé tant que le mode reste allumé.",
                "Public Wi-Fi mode holds the DNS: the DNS noted by Vanguard is left as long as the mode stays on."
            ),
            2,
            GRIS,
        );
    }
    afficher_aligne(
        "  ",
        tr!(
            "Une correction du bilan qui remettait une protection en marche (pare-feu, antivirus, UAC…) n'est jamais défaite, et une correction non annulable reste comme elle est.",
            "A check-up fix that turned a protection back on (firewall, antivirus, UAC…) is never undone, and a fix that cannot be undone stays as it is."
        ),
        2,
        GRIS,
    );
    if !demander(tr!(
        "\n  Tout remettre comme avant ? [o/N] : ",
        "\n  Put everything back? [y/N]: "
    ))
    .oui()
    {
        trp!("  Rien n'a été changé.", "  Nothing was changed.");
        return;
    }
    remettre(&elements);
}

/// Les commandes refaites d'un blocage et le port retenu à oublier, ou le refus.
type Prepare = Result<(Vec<String>, Option<String>), crate::modele::Echec>;

/// Ce que défait un blocage par commandes, refait depuis ses champs typés. changements.jsonl n'est pas scellé :
/// n'importe quel programme du compte peut y écrire un blocage « en place » dont l'annulation est sa propre commande
/// sudo ; rejouée telle quelle dans la demande administrateur, elle lui donnerait root. Le même chemin que
/// `gestes::defaire`, donc, jamais le texte relu ; `None` pour un blocage qui ne se défait pas par commandes.
fn preparer(b: &Blocage) -> Option<Prepare> {
    use crate::protection::blocage::gestes;
    match &b.annulation {
        Some(Annulation::Commandes {
            commandes,
            port,
            inverse,
        }) => Some(
            gestes::commandes_d_annulation(commandes, port.as_deref(), *inverse).ok_or_else(|| {
                crate::modele::Echec::refuse("annulation/remettre", gestes::refus_d_annulation(commandes))
            }),
        ),
        _ => None,
    }
}

/// Les blocages par commandes préparés (`preparer`), dans l'ordre des éléments, et les groupes à lancer dans la
/// demande administrateur : seulement les commandes refaites, une par blocage admis, dans le même ordre.
fn blocages_prepares(elements: &[Element]) -> (Vec<(&Blocage, Prepare)>, Vec<Vec<String>>) {
    let prepares: Vec<(&Blocage, Prepare)> = elements
        .iter()
        .filter_map(|e| match e {
            Element::Blocage(_, b) => preparer(b).map(|p| (&**b, p)),
            Element::Note(_) => None,
        })
        .collect();
    let groupes = prepares
        .iter()
        .filter_map(|(_, p)| p.as_ref().ok().map(|(c, _)| c.clone()))
        .collect();
    (prepares, groupes)
}

/// Défait les éléments, dans leur ordre : les réglages et les blocages par commandes en une seule demande
/// administrateur, puis ce qui se défait sans elle (fichier remis de la quarantaine, copie d'avant).
fn remettre(elements: &[Element]) {
    let ids: Vec<String> = elements
        .iter()
        .filter_map(|e| match e {
            Element::Note(n) => Some(n.id.clone()),
            Element::Blocage(..) => None,
        })
        .collect();
    let (prepares, groupes) = blocages_prepares(elements);
    // Le rang de chaque blocage admis dans `groupes`, donc dans les réussites rendues.
    let admis: Vec<(&str, Option<&String>)> = prepares
        .iter()
        .filter_map(|(b, p)| p.as_ref().ok().map(|(_, port)| (b.id.as_str(), port.as_ref())))
        .collect();
    let (issues, plus) = annulables::defaire(&ids, &groupes);
    println!();
    for e in elements {
        match e {
            Element::Note(n) => {
                let issue = issues
                    .iter()
                    .find(|(id, _)| id == &n.id)
                    .map_or(&Issue::Absent, |(_, i)| i);
                annulables::dire_issue(issue, &n.titre);
                if n.origine == Origine::Bilan && matches!(issue, Issue::Revenu) {
                    crate::changements::marquer_defaite(&n.id);
                }
            }
            Element::Blocage(_, b) => {
                let prepare = prepares.iter().find(|(x, _)| x.id == b.id).map(|(_, p)| p);
                let rang = admis.iter().position(|(id, _)| *id == b.id);
                let resultat = match (prepare, rang) {
                    // Refusé : rien n'a été lancé pour lui, sa note reste.
                    (Some(Err(refus)), _) => Err(String::from(refus.clone())),
                    (Some(Ok(_)), Some(i)) if plus.get(i) == Some(&true) => {
                        // Le port refait depuis les champs typés, pas celui relu du relevé.
                        if let Some(p) = admis[i].1 {
                            crate::machine::oublier_port(p);
                        }
                        crate::changements::marquer_annule(&b.id);
                        Ok(())
                    }
                    (Some(Ok(_)), _) => Err(tr!(
                        "la commande inverse a échoué (voir le message ci-dessus)",
                        "the reverse command failed (see the message above)"
                    )
                    .to_string()),
                    (None, _) => crate::protection::blocage::gestes::defaire(b)
                        .map(|_| ())
                        .map_err(String::from),
                };
                match resultat {
                    Ok(()) => trp!(
                        "  {VERT}✔{RESET} {} : défait.",
                        "  {VERT}✔{RESET} {}: undone.",
                        affichable(&b.quoi)
                    ),
                    Err(e) => afficher_aligne("  ✖ ", &trf!("{} : {e}.", "{}: {e}.", affichable(&b.quoi)), 4, ""),
                }
            }
        }
    }
    // Un programme retiré du démarrage par un blocage : sa note d'Optimiser défaite, le blocage l'est aussi.
    let restantes: std::collections::HashSet<String> = annulables::notes(None).into_iter().map(|n| n.id).collect();
    for (_, b) in crate::changements::blocages_en_place() {
        if let Some(Annulation::Demarrage { id }) = &b.annulation
            && !restantes.contains(id)
        {
            crate::changements::marquer_annule(&b.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(id: &str, date: &str, origine: Origine) -> Note {
        Note {
            id: id.into(),
            date: date.into(),
            titre: id.into(),
            origine,
            admise: true,
        }
    }

    fn blocage(id: &str, annulation: Annulation) -> Blocage {
        Blocage {
            id: id.into(),
            cle: format!("connexion:{id}"),
            quoi: format!("Règle sortante {id}"),
            automatique: false,
            annulation: Some(annulation),
            annule: None,
            supprime: false,
            evenement: None,
            preuve: None,
        }
    }

    /// Tout se défait du plus récent au plus ancien, notes et blocages mêlés ; un blocage qui a retiré un programme
    /// du démarrage passe par sa note d'Optimiser, pas deux fois.
    #[test]
    fn du_plus_recent_au_plus_ancien() {
        let notes = vec![
            note("bilan:b", "2026-10-22 09:00", Origine::Bilan),
            note("jeux:hags", "2026-10-20 21:00", Origine::Jeux),
            note("dns_rapide", "2026-10-19 08:00", Origine::Optimiser),
        ];
        let regle = Annulation::Commandes {
            commandes: vec!["sudo ufw delete deny out to 203.0.113.7".into()],
            port: None,
            inverse: None,
        };
        let blocages = vec![
            ("2026-10-21 12:00".to_string(), blocage("x", regle)),
            (
                "2026-10-23 07:00".to_string(),
                blocage(
                    "y",
                    Annulation::Demarrage {
                        id: "demarrage:autostart|/home/alice/.config/autostart/x.desktop".into(),
                    },
                ),
            ),
        ];
        let ordre: Vec<String> = a_defaire(notes, blocages)
            .iter()
            .map(|e| match e {
                Element::Note(n) => n.id.clone(),
                Element::Blocage(_, b) => b.id.clone(),
            })
            .collect();
        assert_eq!(ordre, ["bilan:b", "x", "jeux:hags", "dns_rapide"]);
    }

    /// Un programme du compte écrit dans changements.jsonl un blocage « en place » dont l'annulation est sa propre
    /// commande sudo : « Tout remettre comme avant » ne la met jamais dans la demande administrateur. Seules les
    /// commandes refaites depuis les champs typés y vont ; le blocage forgé est refusé comme par `gestes::defaire`.
    #[test]
    fn blocage_forge_jamais_rejoue() {
        use crate::changements::Inverse;
        use crate::protection::blocage::pare_feu::PareFeu;
        let forgee = "sudo sh -c 'id > /tmp/vanguard-preuve-root'".to_string();
        let forge = Annulation::Commandes {
            commandes: vec![forgee.clone()],
            port: None,
            inverse: None,
        };
        // Des champs typés justes, mais des commandes relues changées : les champs l'emportent.
        let champs = Annulation::Commandes {
            commandes: vec![forgee.clone()],
            port: Some("22/tcp".into()),
            inverse: Some(Inverse::Sortante {
                pare_feu: PareFeu::Ufw,
                adresse: "203.0.113.7".parse().unwrap(),
            }),
        };
        let elements = a_defaire(
            Vec::new(),
            vec![
                ("2026-10-23 07:00".to_string(), blocage("forge", forge)),
                ("2026-10-22 07:00".to_string(), blocage("type", champs)),
            ],
        );
        let (prepares, groupes) = blocages_prepares(&elements);
        assert_eq!(groupes, [vec!["vanguard:debloquer-sortie ufw 203.0.113.7".to_string()]]);
        assert!(groupes.iter().flatten().all(|c| !c.contains("sh -c")), "{groupes:?}");
        let refus = prepares.iter().find(|(b, _)| b.id == "forge").map(|(_, p)| p.clone());
        let refus = refus.and_then(Result::err).map(String::from).unwrap_or_default();
        assert!(refus.contains("à la main") || refus.contains("by hand"), "{refus}");
        // Le port à oublier vient des champs typés (une règle sortante n'en retient pas), pas du relevé.
        let typee = prepares.iter().find(|(b, _)| b.id == "type").map(|(_, p)| p.clone());
        assert!(matches!(typee, Some(Ok((_, None)))), "{typee:?}");
    }

    /// Les textes de « Tout remettre comme avant » tiennent dans `LARGEUR` colonnes, dans les deux langues.
    #[test]
    fn messages_dans_la_largeur() {
        assert_eq!(
            crate::ui::textes_trop_larges(include_str!("annulation.rs")),
            Vec::<String>::new()
        );
    }
}

//! L'écran du démarrage (lot 2a) : chaque programme sur sa ligne, avec son état. Un programme ordinaire qui se lance
//! a « Retirer du démarrage », un programme retiré par Vanguard a « Remettre » ; un programme à garder ou un pare-feu
//! n'a aucun bouton, sa raison est dans sa ligne. Un clic n'ouvre que la confirmation (`Appli::proposer`), dans la
//! fenêtre ; seul « Accepter » lance le changement (`Appli::accepter`). Les boutons restent grisés tant qu'une
//! commande tourne : un changement à la fois.

use eframe::egui::{Margin, RichText, Sense, Stroke, Ui, pos2, vec2};

use super::{bouton, carte, icones, mono, moyenne, pal, petit, texte, texte_et_boutons, titre_section};
use crate::appli::Appli;
use crate::commandes::Sorte;
use crate::donnees::bilan::{Geste, Rang, Vue};

/// La liste du démarrage, la confirmation ouverte au-dessus.
pub fn liste(appli: &mut Appli, ui: &mut Ui, v: &Vue) {
    let p = pal();
    if let Some(g) = appli.confirmation().cloned() {
        confirmation(appli, ui, &g);
        ui.add_space(20.0);
    }
    ui.label(texte(&v.resume(), 14.0, p.doux));
    ui.add_space(16.0);
    let possible = appli.changement_possible();
    carte(ui, 20, 16, |ui| {
        ui.set_width(ui.available_width());
        if v.constats.is_empty() {
            ui.label(texte(
                crate::tr!("Vanguard n'a rien listé.", "Vanguard listed nothing."),
                14.0,
                p.doux,
            ));
        }
        for (i, c) in v.constats.iter().enumerate() {
            super::mouvement::ligne(ui, vec2(8.0, 3.0), 6.0, |ui| texte_et_boutons(
                ui,
                &format!("demarrage-{i}"),
                |ui| {
                    ui.horizontal_top(|ui| {
                        ui.spacing_mut().item_spacing.x = 8.0;
                        let (r, _) = ui.allocate_exact_size(vec2(14.0, 16.0), Sense::hover());
                        match c.rang {
                            Rang::Sain => icones::coche(ui.painter(), r, p.bon),
                            Rang::NonVerifie => {
                                ui.painter()
                                    .circle_filled(pos2(r.left() + 5.0, r.center().y), 4.0, p.moyen);
                            }
                            _ => {
                                ui.painter()
                                    .circle_filled(pos2(r.left() + 5.0, r.center().y), 4.0, p.jaune);
                            }
                        }
                        ui.label(texte(&c.message, 13.0, p.encre));
                    });
                },
                |ui| {
                    let Some(g) = &c.geste else {
                        return;
                    };
                    ui.push_id(("geste", i), |ui| {
                        let t = match g.changement.sorte {
                            Sorte::Retirer => crate::tr!("Retirer du démarrage", "Remove from startup"),
                            Sorte::Remettre => crate::tr!("Remettre", "Put back"),
                        };
                        let rep = petit(ui, t, possible).on_disabled_hover_text(crate::tr!(
                            "Une commande tourne ou une confirmation est ouverte : un changement à la fois.",
                            "A command is running or a confirmation is open: one change at a time."
                        ));
                        if rep.clicked() {
                            appli.proposer(g);
                        }
                    });
                },
            ));
            ui.add_space(6.0);
        }
    });
    let mut manques: Vec<String> = v.manques.clone();
    if v.illisibles > 0 {
        manques.push(crate::trf!(
            "{} ligne(s) que cette fenêtre n'a pas su lire",
            "{} line(s) this window could not read",
            v.illisibles
        ));
    }
    if !manques.is_empty() {
        ui.add_space(16.0);
        titre_section(
            ui,
            crate::tr!("Pas pu vérifier", "Could not check"),
            Some(manques.len()),
        );
        carte(ui, 20, 16, |ui| {
            ui.set_width(ui.available_width());
            for m in &manques {
                ui.label(texte(m, 13.0, p.moyen));
            }
        });
    }
}

/// La confirmation, dans la fenêtre : le nom, la commande, ce qui va se passer ; « Accepter » ou « Annuler ».
fn confirmation(appli: &mut Appli, ui: &mut Ui, g: &Geste) {
    let p = pal();
    eframe::egui::Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(2.0, p.accent))
        .corner_radius(16)
        .inner_margin(Margin::same(22))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            let question = match g.changement.sorte {
                Sorte::Retirer => crate::trf!(
                    "Retirer « {} » du démarrage ?",
                    "Remove “{}” from startup?",
                    g.nom
                ),
                Sorte::Remettre => crate::trf!(
                    "Remettre « {} » au démarrage ?",
                    "Put “{}” back at startup?",
                    g.nom
                ),
            };
            ui.label(RichText::new(question).font(moyenne(18.0)).color(p.encre));
            ui.add_space(6.0);
            if !g.commande.is_empty() {
                ui.label(RichText::new(&g.commande).font(mono(12.0)).color(p.doux));
                ui.add_space(6.0);
            }
            let ce_qui_se_passe = match g.changement.sorte {
                Sorte::Retirer => crate::tr!(
                    "Il ne se lancera plus à l'ouverture de session. Il reste installé ; « Remettre » le remet exactement comme avant.",
                    "It will no longer start at login. It stays installed; “Put back” restores it exactly as before."
                ),
                Sorte::Remettre => crate::tr!(
                    "Vanguard le remet exactement comme il l'avait noté avant de le retirer.",
                    "Vanguard restores it exactly as it noted it before removing it."
                ),
            };
            ui.label(texte(ce_qui_se_passe, 14.0, p.doux));
            if g.machine {
                ui.add_space(4.0);
                ui.label(texte(
                    crate::tr!(
                        "Il est de tout l'ordinateur : la fenêtre administrateur du système s'ouvrira.",
                        "It belongs to the whole computer: the system's administrator window will open."
                    ),
                    14.0,
                    p.jaune,
                ));
            }
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                let libre = appli.en_cours().is_none() && appli.taches() == 0;
                let accepter = bouton(ui, crate::tr!("Accepter", "Accept"), true, libre).on_disabled_hover_text(
                    crate::tr!(
                        "Une commande tourne encore : attendez sa fin.",
                        "A command is still running: wait for it to end."
                    ),
                );
                if accepter.clicked() {
                    appli.accepter();
                }
                if bouton(ui, crate::tr!("Annuler", "Cancel"), false, true).clicked() {
                    appli.annuler();
                }
            });
        });
}

//! Les écrans sans données : une carte calme, l'icône de la rubrique, une phrase qui dit quoi faire et, quand c'est
//! une lecture, le bouton qui la lance. Jamais un changement de l'ordinateur ici : le bouton passe par
//! `Appli::demander`, qui ne connaît que la liste fermée des lectures.

use eframe::egui::{Align, Align2, Color32, Label, Ui, vec2};

use super::{carte, icones, moyenne, pal, texte};
use crate::commandes::Rubrique;

/// La largeur où la phrase va à la ligne : plus large, l'œil perd la ligne suivante.
const LARGEUR_PHRASE: f32 = 440.0;
/// Le diamètre de la pastille de l'icône.
const PASTILLE: f32 = 44.0;

/// Une carte d'état vide, centrée : l'icône de `rubrique`, un titre court, une phrase, puis `geste` (le bouton qui
/// lance la lecture, ou rien).
pub fn carte_vide(ui: &mut Ui, rubrique: Rubrique, titre: &str, phrase: &str, geste: impl FnOnce(&mut Ui)) {
    let p = pal();
    carte(ui, 32, |ui| {
        ui.set_width(ui.available_width());
        ui.vertical_centered(|ui| {
            let (r, _) = ui.allocate_exact_size(vec2(PASTILLE, PASTILLE), eframe::egui::Sense::hover());
            let peintre = ui.painter();
            peintre.circle_filled(r.center(), PASTILLE / 2.0, super::melange(p.accent, p.surface, 0.12));
            icones::rubrique(peintre, r.center(), rubrique, p.accent);
            ui.add_space(14.0);
            ui.label(texte(titre, 16.0, p.encre).font(moyenne(16.0)));
            ui.add_space(4.0);
            ui.scope(|ui| {
                ui.set_max_width(LARGEUR_PHRASE.min(ui.available_width()));
                ui.add(Label::new(texte(phrase, 13.0, p.doux)).halign(Align::Center));
            });
            ui.add_space(18.0);
            geste(ui);
        });
    });
}

/// « Rien à signaler » : une coche verte et une phrase, sans carte (c'est une bonne nouvelle, pas un écran à remplir).
pub fn rien_a_signaler(ui: &mut Ui, phrase: &str) {
    let p = pal();
    ui.horizontal(|ui| {
        let (r, _) = ui.allocate_exact_size(vec2(18.0, 18.0), eframe::egui::Sense::hover());
        icones::coche(ui.painter(), r, p.bon);
        ui.label(texte(phrase, 14.0, p.doux));
    });
}

/// Une phrase posée dans un panneau peint à la main (le journal vide des Coulisses).
pub fn phrase_peinte(ui: &Ui, coin: eframe::egui::Pos2, phrase: &str, couleur: Color32) {
    ui.painter()
        .text(coin, Align2::LEFT_TOP, phrase, super::police(12.0), couleur);
}

#[cfg(test)]
mod tests {
    use eframe::egui::{self, Pos2, RawInput, Rect, vec2};

    use crate::commandes::Rubrique;

    /// Le bouton de la carte vide est centré sous la phrase, et une phrase longue va à la ligne sans élargir la carte.
    #[test]
    fn la_carte_vide_centre_son_bouton() {
        let ctx = egui::Context::default();
        super::super::polices(&ctx);
        let mut vu = None;
        ctx.run_ui(
            RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(900.0, 600.0))),
                ..Default::default()
            },
            |ui| {
                let carte = ui.available_rect_before_wrap();
                let mut bouton = None;
                super::carte_vide(
                    ui,
                    Rubrique::Reseau,
                    "Pas encore de scan",
                    &"une phrase longue ".repeat(20),
                    |ui| {
                        bouton = Some(super::super::bouton(ui, "Lancer", true, true).rect);
                    },
                );
                vu = Some((carte, bouton, ui.min_rect()));
            },
        )
        .textures_delta
        .clear();
        let (carte, bouton, occupe) = vu.unwrap();
        let bouton = bouton.expect("le geste n'a pas été dessiné");
        assert!(
            (bouton.center().x - carte.center().x).abs() < 1.0,
            "{bouton:?} dans {carte:?}"
        );
        assert!(occupe.width() <= carte.width() + 0.5, "{occupe:?} déborde de {carte:?}");
    }
}

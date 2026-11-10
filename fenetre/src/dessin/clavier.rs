//! Le contour du focus au clavier : Tab et Maj+Tab (ou les flèches) passent d'un élément à l'autre, et l'élément qui a
//! le focus porte un anneau net, partout le même (couleur d'accent, 2 points, à 2 points de son bord, au rayon de
//! l'élément). Jamais au simple clic : l'anneau ne se montre que si le dernier geste était une touche de
//! déplacement, pas un bouton de la souris.

use eframe::egui::{Context, Event, Id, Key, Rect, Response, Stroke, StrokeKind, Ui};

/// L'épaisseur de l'anneau, et son écart au bord de l'élément (il ne touche pas un bouton plein d'accent).
const EPAISSEUR: f32 = 2.0;
const ECART: f32 = 2.0;

fn id_clavier() -> Id {
    Id::unique("focus-au-clavier")
}

/// Le dernier geste était-il une touche de déplacement du focus ? Lu dans les événements de cette image : une touche
/// Tab ou une flèche l'allume, un bouton de souris pressé l'éteint ; sans l'un ni l'autre, rien ne change. Le même
/// résultat à chaque appel de la même image.
fn au_clavier(ctx: &Context) -> bool {
    let geste = ctx.input(|i| {
        i.events.iter().rev().find_map(|e| match e {
            Event::Key {
                key: Key::Tab | Key::ArrowUp | Key::ArrowDown | Key::ArrowLeft | Key::ArrowRight,
                pressed: true,
                ..
            } => Some(true),
            Event::PointerButton { pressed: true, .. } => Some(false),
            _ => None,
        })
    });
    match geste {
        Some(g) => {
            ctx.data_mut(|d| d.insert_temp(id_clavier(), g));
            g
        }
        None => ctx.data(|d| d.get_temp(id_clavier())).unwrap_or(false),
    }
}

/// L'anneau autour de `zone` (au rayon `rayon` de l'élément) si `rep` a le focus et qu'on y est venu au clavier.
pub fn anneau_zone(ui: &Ui, rep: &Response, zone: Rect, rayon: f32) {
    if rep.has_focus() && au_clavier(ui.ctx()) {
        ui.painter().rect_stroke(
            zone.expand(ECART),
            rayon + ECART,
            Stroke::new(EPAISSEUR, super::pal().accent),
            StrokeKind::Outside,
        );
    }
}

/// L'anneau autour de l'élément `rep` lui-même.
pub fn anneau(ui: &Ui, rep: &Response, rayon: f32) {
    anneau_zone(ui, rep, rep.rect, rayon);
}

#[cfg(test)]
mod tests {
    use eframe::egui;

    /// Une image : deux boutons de la fenêtre, et les événements donnés. Rend l'identifiant qui a le focus et si un
    /// anneau d'accent de 2 points est peint.
    fn image(ctx: &egui::Context, temps: f64, evenements: Vec<egui::Event>) -> (Option<egui::Id>, bool) {
        let mut entree = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(800.0, 600.0))),
            time: Some(temps),
            ..Default::default()
        };
        entree.events = evenements;
        let mut sortie = ctx.run_ui(entree, |ui| {
            super::super::bouton(ui, "Lancer", true, true);
            super::super::petit(ui, "Voir", true);
        });
        sortie.textures_delta.clear();
        let accent = super::super::pal().accent;
        let anneau = sortie.shapes.iter().any(|c| {
            matches!(&c.shape, egui::Shape::Rect(r)
                if r.stroke.color == accent && (r.stroke.width - super::EPAISSEUR).abs() < f32::EPSILON)
        });
        (ctx.memory(egui::Memory::focused), anneau)
    }

    fn touche(key: egui::Key, shift: bool) -> egui::Event {
        egui::Event::Key {
            key,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: if shift {
                egui::Modifiers::SHIFT
            } else {
                egui::Modifiers::NONE
            },
        }
    }

    /// Tab donne le focus au premier bouton, avec l'anneau ; Maj+Tab revient ; un clic de souris, même sur le bouton
    /// qui a le focus, éteint l'anneau ; Tab le rallume.
    #[test]
    fn tab_montre_l_anneau_et_le_clic_l_eteint() {
        let ctx = egui::Context::default();
        super::super::polices(&ctx);
        let (focus, anneau) = image(&ctx, 1.0, vec![]);
        assert!(focus.is_none() && !anneau, "un anneau sans rien au clavier");
        image(&ctx, 1.1, vec![touche(egui::Key::Tab, false)]);
        let (premier, anneau) = image(&ctx, 1.2, vec![]);
        assert!(premier.is_some() && anneau, "Tab ne montre pas l'anneau");
        image(&ctx, 1.3, vec![touche(egui::Key::Tab, false)]);
        let (second, _) = image(&ctx, 1.4, vec![]);
        assert!(second.is_some() && second != premier, "Tab ne passe pas au suivant");
        image(&ctx, 1.5, vec![touche(egui::Key::Tab, true)]);
        assert_eq!(image(&ctx, 1.6, vec![]).0, premier, "Maj+Tab ne revient pas");
        // Un clic de souris : plus d'anneau, que le focus reste ou non.
        let ici = egui::pos2(400.0, 500.0);
        let clic = |pressed| egui::Event::PointerButton {
            pos: ici,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        image(&ctx, 1.7, vec![egui::Event::PointerMoved(ici), clic(true), clic(false)]);
        assert!(!image(&ctx, 1.8, vec![]).1, "l'anneau reste après un clic");
        image(&ctx, 1.9, vec![touche(egui::Key::Tab, false)]);
        assert!(image(&ctx, 2.0, vec![]).1, "Tab ne rallume pas l'anneau");
    }
}

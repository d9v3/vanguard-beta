//! Le mouvement de la fenêtre, en un seul endroit : le fondu d'arrivée d'un écran. Toutes les durées viennent d'une
//! seule réglette, `ALLURE` : à 0, plus rien ne bouge (chaque fondu saute à sa fin), le reste de la fenêtre ne change
//! pas. Aucun réglage « réduire les animations » n'est lu du système pour l'instant : la fenêtre, dans son bac à
//! sable, ne lit ni les réglages du bureau ni ceux de Windows ; le jour où elle le pourra, il se branchera ici.

use std::time::Duration;

use eframe::egui::{Context, Id, Sense, Ui, emath::TSTransform, vec2};

use crate::appli::Ecran;

/// La réglette de tout le mouvement : 1, les durées prévues ; 0, aucun mouvement.
pub const ALLURE: f32 = 1.0;

/// Une durée de la fenêtre, en secondes, passée par la réglette.
pub const fn duree(secondes: f32) -> f32 {
    secondes * ALLURE
}

/// Le survol d'un bouton ou d'une ligne : assez court pour suivre la souris, assez long pour que l'œil voie un fondu.
pub const SURVOL: f32 = duree(0.12);
/// L'arrivée d'un écran : un fondu court, à peine un glissement.
const ARRIVEE: f32 = duree(0.15);
/// Le glissement de l'arrivée, en points, du bas vers sa place.
const GLISSEMENT: f32 = 6.0;
/// L'intervalle des images tant que quelque chose bouge (environ 60 par seconde).
const IMAGE: Duration = Duration::from_millis(16);

/// L'avancement de 0 à 1 d'un mouvement de `d` secondes parti à `debut` (l'heure d'egui) ; une durée nulle est finie.
fn avancement(maintenant: f64, debut: f64, d: f32) -> f32 {
    if d <= 0.0 {
        return 1.0;
    }
    super::cadre::phase_f32((maintenant - debut) / f64::from(d))
}

/// Part d'avancement qui ralentit à la fin (ease-out cubique).
fn sortie(x: f32) -> f32 {
    let r = 1.0 - x.clamp(0.0, 1.0);
    1.0 - r * r * r
}

/// L'arrivée de l'écran montré : où en est son fondu.
#[derive(Clone, Copy)]
pub struct Arrivee {
    /// De 0 (l'écran vient de changer) à 1 (fini).
    pub part: f32,
    /// L'écran a changé à cette image : il part du haut.
    pub nouvel_ecran: bool,
}

fn id_arrivee() -> Id {
    Id::unique("arrivee-ecran")
}

/// Où en est l'arrivée de l'écran `ecran` : un changement d'écran (`Appli::aller`, onglet, rail, Retour) relance le
/// fondu. À la première image, rien : l'ouverture s'en charge.
pub fn arrivee(ctx: &Context, ecran: Ecran) -> Arrivee {
    let maintenant = ctx.input(|i| i.time);
    let avant = ctx.data(|d| d.get_temp::<(Ecran, f64)>(id_arrivee()));
    let (debut, nouvel_ecran) = match avant {
        Some((e, debut)) if e == ecran => (debut, false),
        Some(_) => (maintenant, true),
        None => (f64::NEG_INFINITY, false),
    };
    if avant.is_none() || nouvel_ecran {
        ctx.data_mut(|d| d.insert_temp(id_arrivee(), (ecran, debut)));
    }
    Arrivee {
        part: avancement(maintenant, debut, ARRIVEE),
        nouvel_ecran,
    }
}

/// Le contenu central pendant son arrivée : il apparaît en fondu et glisse de quelques points vers sa place. Pendant
/// ce temps, un voile transparent posé au-dessus prend les clics : rien ne se clique sur un écran encore à peine
/// visible (un double-clic sur le rail n'atteint pas le bouton qui arrive dessous).
pub fn montrer_en_arrivant<R>(ui: &mut Ui, a: Arrivee, contenu: impl FnOnce(&mut Ui) -> R) -> R {
    if a.part >= 1.0 {
        return contenu(ui);
    }
    let s = sortie(a.part);
    let zone = ui.max_rect();
    ui.multiply_opacity(s);
    let r = ui
        .with_visual_transform(
            TSTransform::from_translation(vec2(0.0, GLISSEMENT * (1.0 - s))),
            contenu,
        )
        .inner;
    // Ni focus ni clic ni glisser : le voile ne fait qu'arrêter la souris.
    let _ = ui.interact(zone, Id::unique("voile-arrivee"), Sense::CLICK | Sense::DRAG);
    ui.ctx().request_repaint_after(IMAGE);
    r
}

#[cfg(test)]
mod tests {
    use eframe::egui;

    use super::{ARRIVEE, Arrivee};
    use crate::appli::{Appli, Ecran};
    use crate::commandes::Rubrique;

    /// Une image de toute la fenêtre à l'instant `temps`, la souris à `souris` et un clic s'il le faut.
    fn image(ctx: &egui::Context, appli: &mut Appli, temps: f64, souris: egui::Pos2, clic: bool) {
        let mut entree = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1280.0, 800.0))),
            time: Some(temps),
            ..Default::default()
        };
        entree.events.push(egui::Event::PointerMoved(souris));
        if clic {
            for pressed in [true, false] {
                entree.events.push(egui::Event::PointerButton {
                    pos: souris,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                });
            }
        }
        ctx.run_ui(entree, |ui| super::super::cadre::tout(appli, ui))
            .textures_delta
            .clear();
    }

    /// L'arrivée part de 0 au changement d'écran, monte, et finit à 1 en `ARRIVEE` ; revenir au même écran ne la
    /// relance pas.
    #[test]
    fn l_arrivee_part_du_changement_d_ecran() {
        let ctx = egui::Context::default();
        let mut temps = 10.0;
        let mut voir = |e: Ecran, dt: f64| {
            temps += dt;
            let mut vu = None;
            ctx.run_ui(
                egui::RawInput {
                    time: Some(temps),
                    ..Default::default()
                },
                |ui| vu = Some(super::arrivee(ui.ctx(), e)),
            )
            .textures_delta
            .clear();
            vu.unwrap()
        };
        let Arrivee { part, nouvel_ecran } = voir(Ecran::Accueil, 0.0);
        assert!(
            (part - 1.0).abs() < f32::EPSILON && !nouvel_ecran,
            "première image : aucun fondu"
        );
        let a = voir(Ecran::Bilan, 0.0);
        assert!(a.part < f32::EPSILON && a.nouvel_ecran);
        let a = voir(Ecran::Bilan, f64::from(ARRIVEE) / 2.0);
        assert!(a.part > 0.3 && a.part < 0.7 && !a.nouvel_ecran, "{}", a.part);
        let a = voir(Ecran::Bilan, f64::from(ARRIVEE));
        assert!((a.part - 1.0).abs() < f32::EPSILON);
    }

    /// Pendant l'arrivée, un clic sur le centre ne touche pas l'écran qui arrive ; une fois arrivé, si.
    #[test]
    fn rien_ne_se_clique_pendant_l_arrivee() {
        let ctx = egui::Context::default();
        super::super::polices(&ctx);
        let mut appli = Appli::pour_captures();
        // Le premier écran se pose sans fondu ; on va à une rubrique, puis on revient cliquer sur la tuile du Bilan…
        image(&ctx, &mut appli, 1.0, egui::Pos2::ZERO, false);
        appli.aller(Ecran::Rubrique(Rubrique::Ordinateur));
        image(&ctx, &mut appli, 1.5, egui::Pos2::ZERO, false);
        appli.revenir();
        // … revenue à l'instant : le clic tombe pendant l'arrivée de l'accueil.
        let tuile = egui::pos2(300.0, 420.0);
        image(&ctx, &mut appli, 1.51, tuile, false);
        image(&ctx, &mut appli, 1.52, tuile, true);
        assert_eq!(appli.ecran, Ecran::Accueil, "un clic a traversé le voile");
        // Arrivé : le même clic ouvre le Bilan (sinon l'essai d'au-dessus ne prouve rien).
        image(&ctx, &mut appli, 2.0, tuile, false);
        image(&ctx, &mut appli, 2.1, tuile, true);
        assert_eq!(appli.ecran, Ecran::Bilan, "la tuile n'était pas sous la souris");
    }
}

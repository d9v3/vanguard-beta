//! Le cadre : le rail des rubriques à gauche, la barre en haut, la console dessous, l'écran au centre.

use std::time::Duration;

use eframe::egui::{self, Align2, Frame, Margin, Rect, RichText, Sense, Stroke, Ui, pos2, vec2};

use super::{icones, melange, moyenne, n_f32, pal, police, survol};
use crate::appli::{Appli, Ecran};
use crate::commandes::{Commande, Rubrique};
use crate::donnees::protection::Allure;

pub fn tout(appli: &mut Appli, ui: &mut Ui) {
    let p = pal();
    super::mouvement::regler(ui.ctx(), appli.animations_reduites);
    // Sans contour : celui d'un cadre fait les quatre côtés, et il se voyait en haut, en bas et à gauche, sur le bord
    // de la fenêtre. Seul le bord droit garde un trait, tracé à la fin.
    let rail_rect = egui::Panel::left("rail")
        .exact_size(88.0)
        .resizable(false)
        .show_separator_line(false)
        .frame(Frame::new().fill(p.fond).inner_margin(Margin::symmetric(8, 0)))
        .show(ui, |ui| {
            let aise = aisance_du_rail(ui.available_height());
            egui::ScrollArea::vertical().show(ui, |ui| rail(appli, ui, aise));
        })
        .response
        .rect;
    egui::Panel::top("barre")
        .exact_size(64.0)
        .resizable(false)
        .show_separator_line(false)
        .frame(Frame::new().fill(p.fond))
        .show(ui, |ui| barre(appli, ui));
    let lignes = super::console::lignes(ui.ctx());
    egui::Panel::top("console")
        .exact_size(super::console::hauteur(lignes))
        .resizable(false)
        .show_separator_line(false)
        .frame(Frame::new().fill(p.surface))
        .show(ui, |ui| super::console::bande(appli, ui, lignes));
    // Les coulisses : une fenêtre à part, ou un panneau à droite (avant le panneau central, qui prend le reste).
    super::coulisses::montrer(appli, ui);
    // L'écran arrive en fondu ; un écran nouveau part du haut (sinon il s'ouvrait à la hauteur où était l'autre).
    let arrivee = super::mouvement::arrivee(ui.ctx(), appli.ecran);
    egui::CentralPanel::default()
        .frame(Frame::new().fill(p.fond))
        .show(ui, |ui| {
            super::mouvement::montrer_en_arrivant(ui, arrivee, |ui| {
                let mut defile = egui::ScrollArea::vertical().auto_shrink(false);
                if arrivee.nouvel_ecran {
                    defile = defile.vertical_scroll_offset(0.0);
                }
                defile.show(ui, |ui| {
                    Frame::new()
                        .inner_margin(Margin {
                            left: 32,
                            right: 32,
                            top: 32,
                            bottom: 64,
                        })
                        .show(ui, |ui| {
                            // Une borne, jamais un élargissement : `set_max_width` pose la largeur telle quelle, et 1 520
                            // dans une fenêtre plus étroite poussait les cartes et leurs boutons hors de l'écran.
                            ui.set_max_width(ui.available_width().min(1520.0));
                            super::ecrans::montrer(appli, ui);
                        });
                });
            });
        });
    // Le trait du bord droit du rail, après les autres panneaux (leur fond ne le recouvre pas) : un pixel de l'écran,
    // posé sur un pixel entier. À 88 points et une échelle de 1,6, le bord tombe à 140,8 pixels : un trait non calé
    // se partageait entre deux pixels et ne se voyait presque plus.
    let peintre = ui.painter();
    let pixel = 1.0 / peintre.pixels_per_point();
    let x = peintre.round_to_pixel_center(rail_rect.right() - pixel);
    peintre.vline(x, rail_rect.y_range(), Stroke::new(pixel, p.trait_));
}

/// La rubrique allumée dans le rail pour l'écran montré.
fn rubrique_de(e: Ecran) -> Rubrique {
    match e {
        Ecran::Accueil => Rubrique::Accueil,
        Ecran::Bilan => Rubrique::Ordinateur,
        Ecran::Alertes => Rubrique::Bloquer,
        Ecran::Appareils => Rubrique::Reseau,
        Ecran::Rubrique(r) => r,
        Ecran::Commande(c) => c.rubrique(),
        Ecran::Guide => Rubrique::Guide,
    }
}

/// Le rail à l'aise (1) et serré (0) : à l'aise, le pas d'une rubrique laisse de l'air autour de l'icône ; serré,
/// les onze tiennent en moins de 690 pt. Entre les deux, le pas suit la hauteur de la fenêtre, pour que rien ne soit coupé
/// à 800 px ; plus bas encore, le rail défile.
const RAIL_AISE: [f32; 4] = [76.0, 18.0, 32.0, 12.0];
const RAIL_SERRE: [f32; 4] = [48.0, 13.0, 26.0, 2.0];

/// La hauteur du rail selon son aisance : l'en-tête du V, puis chaque rubrique (icône, nom, écart).
fn hauteur_du_rail(aise: f32) -> f32 {
    let [tete, _, nom, ecart] = pas_du_rail(aise);
    let lignes: usize = Rubrique::TOUTES.iter().map(|r| r.nom_court().lines().count()).sum();
    tete + n_f32(Rubrique::TOUTES.len()) * (nom + 2.0 + ecart) + 14.0 * n_f32(lignes)
}

fn pas_du_rail(aise: f32) -> [f32; 4] {
    let mut pas = RAIL_SERRE;
    for (s, a) in pas.iter_mut().zip(RAIL_AISE) {
        *s += (a - *s) * aise;
    }
    pas
}

/// L'aisance qui fait tenir le rail dans `haut` (8 pt gardés en bas), entre serré et à l'aise.
fn aisance_du_rail(haut: f32) -> f32 {
    let (serre, aise) = (hauteur_du_rail(0.0), hauteur_du_rail(1.0));
    ((haut - 8.0 - serre) / (aise - serre)).clamp(0.0, 1.0)
}

fn rail(appli: &mut Appli, ui: &mut Ui, aise: f32) {
    let p = pal();
    let [tete, icone, nom_y, ecart] = pas_du_rail(aise);
    // Les écarts sont posés à la main : celui des éléments d'egui s'y ajouterait.
    ui.spacing_mut().item_spacing.y = 0.0;
    // L'en-tête : le V au milieu de sa bande, un peu d'air au-dessus.
    let (r, _) = ui.allocate_exact_size(vec2(72.0, tete), Sense::hover());
    ui.painter().text(
        pos2(r.center().x, r.top() + tete * 0.5 - 2.0),
        Align2::CENTER_CENTER,
        "V",
        moyenne(26.0),
        p.encre.gamma_multiply(super::ouverture::v_du_rail(ui.ctx())),
    );
    let allumee = rubrique_de(appli.ecran);
    for rub in Rubrique::TOUTES {
        let nom = rub.nom_court();
        let lignes = n_f32(nom.lines().count());
        let (r, rep) = ui.allocate_exact_size(vec2(72.0, nom_y + 2.0 + 14.0 * lignes), Sense::click());
        let actif = allumee == rub;
        // La rubrique allumée l'est en plein ; une autre s'allume en fondu sous la souris.
        let vif = if actif { 1.0 } else { survol(ui, rep.id, rep.hovered()) };
        let peintre = ui.painter();
        if vif > 0.0 {
            peintre.rect_filled(r, 10, p.s2.gamma_multiply(vif));
        }
        icones::rubrique(
            peintre,
            pos2(r.center().x, r.top() + icone),
            rub,
            p.doux.lerp_to_gamma(p.accent, vif),
        );
        // Chaque ligne centrée sous l'icône : `text` centre le bloc, mais aligne ses lignes à gauche.
        let encre = p.doux.lerp_to_gamma(p.encre, vif);
        let mut job = egui::text::LayoutJob::simple(nom.to_owned(), police(11.0), encre, f32::INFINITY);
        job.halign = egui::Align::Center;
        let bloc = peintre.layout_job(job);
        peintre.galley(pos2(r.center().x, r.top() + nom_y), bloc, encre);
        super::clavier::anneau(ui, &rep, 10.0);
        if rep.clicked() {
            appli.aller(match rub {
                Rubrique::Accueil => Ecran::Accueil,
                Rubrique::Guide => Ecran::Guide,
                r => Ecran::Rubrique(r),
            });
        }
        rep.on_hover_cursor(egui::CursorIcon::PointingHand)
            .on_hover_ui(|ui| bulle_rubrique(ui, rub));
        ui.add_space(ecart);
    }
}

/// L'infobulle d'une rubrique du rail : son nom sur une ligne, puis ce qu'on y trouve.
fn bulle_rubrique(ui: &mut Ui, rub: Rubrique) {
    let p = pal();
    let quoi = match rub {
        Rubrique::Accueil => crate::tr!(
            "Le bilan, la protection et le journal, d'un coup d'œil.",
            "The check, protection and journal at a glance."
        )
        .to_owned(),
        Rubrique::Guide => crate::tr!(
            "Toutes les commandes que la fenêtre sait lancer, et ce que chacune fait.",
            "Every command this window can run, and what each one does."
        )
        .to_owned(),
        _ => rub.commandes().map(Commande::titre).collect::<Vec<_>>().join(" · "),
    };
    ui.label(RichText::new(rub.nom()).font(moyenne(13.0)).color(p.encre));
    if !quoi.is_empty() {
        ui.label(RichText::new(quoi).font(police(12.0)).color(p.doux));
    }
}

/// Ce que dit l'infobulle du point de veille, pour chacun de ses trois états.
fn bulle_veille(appli: &Appli) -> String {
    if appli.protection().is_none() {
        return crate::tr!(
            "La protection n'a pas encore été lue : rien n'est supposé tant qu'elle ne l'est pas.",
            "Protection has not been read yet: nothing is assumed until it is."
        )
        .to_owned();
    }
    let ou = Commande::Protection.rubrique().nom();
    if veille(appli).1 {
        crate::trf!(
            "La veille en temps réel est allumée sur cet ordinateur (détail : {}).",
            "Real-time watch is on for this computer (details: {}).",
            ou
        )
    } else {
        crate::trf!(
            "Aucune veille en temps réel n'est allumée sur cet ordinateur (détail : {}).",
            "No real-time watch is on for this computer (details: {}).",
            ou
        )
    }
}

/// Les onglets de la barre et l'écran de chacun.
fn onglets() -> [(&'static str, Ecran); 6] {
    [
        (crate::tr!("Vue d'ensemble", "Overview"), Ecran::Accueil),
        (crate::tr!("Bilan", "Check"), Ecran::Bilan),
        (crate::tr!("Alertes", "Alerts"), Ecran::Alertes),
        (crate::tr!("Appareils", "Devices"), Ecran::Appareils),
        (
            crate::tr!("Connexions", "Connections"),
            Ecran::Commande(Commande::ConnexionsSortantes),
        ),
        (crate::tr!("Toutes les fonctions", "All features"), Ecran::Guide),
    ]
}

/// Ce que la barre dit de la protection : seulement ce que `protection --json` a lu, jamais supposé.
pub(super) fn veille(appli: &Appli) -> (&'static str, bool, egui::Color32) {
    let p = pal();
    match appli.protection() {
        None => (crate::tr!("Protection pas lue", "Protection not read"), false, p.gris),
        Some(v) => {
            let veille = v
                .interrupteurs
                .iter()
                .any(|i| matches!(i.id.as_str(), "temps-reel" | "surveillance") && i.allure == Allure::Allume);
            if veille {
                (crate::tr!("En veille", "Watching"), true, p.accent)
            } else {
                (crate::tr!("Veille éteinte", "Watch off"), false, p.moyen)
            }
        }
    }
}

fn barre(appli: &mut Appli, ui: &mut Ui) {
    let p = pal();
    let r = ui.max_rect();
    let mut job = egui::text::LayoutJob::default();
    job.append(
        "VANGUARD",
        0.0,
        egui::TextFormat {
            font_id: moyenne(14.0),
            color: p.encre,
            extra_letter_spacing: 3.4,
            ..Default::default()
        },
    );
    let g = ui.fonts_mut(|f| f.layout_job(job));
    ui.painter()
        .galley(pos2(r.left() + 32.0, r.center().y - g.size().y / 2.0), g, p.encre);
    let large = r.width() >= 720.0;
    let limite = r.right() - 32.0 - 124.0 - if large { 32.0 + 120.0 + 32.0 } else { 24.0 };
    let mut x = r.left() + 186.0;
    for (i, (nom, ecran)) in onglets().into_iter().enumerate() {
        let actif = appli.ecran == ecran;
        let g = ui.painter().layout_no_wrap(nom.into(), police(14.0), p.doux);
        let w = g.size().x + 32.0;
        // Ceux qui ne tiennent pas restent dans le rail.
        if x + w > limite {
            break;
        }
        let zone = Rect::from_min_size(pos2(x, r.top()), vec2(w, r.height()));
        let rep = ui.interact(zone, ui.scope_id().with(("onglet", i)), Sense::click());
        let vif = if actif { 1.0 } else { survol(ui, rep.id, rep.hovered()) };
        let col = p.doux.lerp_to_gamma(p.encre, vif);
        ui.painter()
            .text(zone.center(), Align2::CENTER_CENTER, nom, police(14.0), col);
        if actif {
            ui.painter().rect_filled(
                Rect::from_min_max(pos2(zone.left(), zone.bottom() - 2.0), zone.right_bottom()),
                0,
                p.accent,
            );
        }
        super::clavier::anneau_zone(ui, &rep, zone.shrink2(vec2(4.0, 14.0)), 8.0);
        if rep.clicked() {
            appli.aller(ecran);
        }
        rep.on_hover_cursor(egui::CursorIcon::PointingHand);
        x += w;
    }
    let bouton = Rect::from_min_size(pos2(r.right() - 32.0 - 124.0, r.center().y - 18.0), vec2(124.0, 36.0));
    let rep = ui.interact(bouton, ui.scope_id().with("voir-alertes"), Sense::click());
    let fond = if rep.is_pointer_button_down_on() {
        melange(p.accent, p.fond, 0.85)
    } else {
        melange(p.accent, p.encre, 1.0 - 0.16 * survol(ui, rep.id, rep.hovered()))
    };
    ui.painter().rect_filled(bouton, 10, fond);
    ui.painter().text(
        bouton.center(),
        Align2::CENTER_CENTER,
        crate::tr!("Voir les alertes", "See alerts"),
        moyenne(13.0),
        p.sur_vif,
    );
    super::clavier::anneau(ui, &rep, 10.0);
    if rep.clicked() {
        appli.aller(Ecran::Alertes);
    }
    rep.on_hover_cursor(egui::CursorIcon::PointingHand);
    if !large {
        return;
    }
    let (mot, respire, couleur) = veille(appli);
    let point = pos2(bouton.left() - 32.0 - 120.0, r.center().y);
    let temps = ui.ctx().input(|i| i.time);
    let periode = if respire { super::mouvement::POULS_VEILLE } else { 0.0 };
    super::mouvement::pouls(ui.painter(), temps, point, 4.0, couleur, periode);
    let ecrit = ui
        .painter()
        .text(point + vec2(12.0, 0.0), Align2::LEFT_CENTER, mot, police(13.0), p.doux);
    let zone = ecrit.union(Rect::from_center_size(point, vec2(12.0, 12.0)));
    ui.interact(zone, ui.scope_id().with("veille"), Sense::hover())
        .on_hover_text(bulle_veille(appli));
}

/// Une phase entre 0 et 1, de f64 en f32.
// raison : une valeur bornée à 0..=1 par l'appelant ; la perte de précision de f64 à f32 est voulue (un dessin).
#[allow(clippy::cast_possible_truncation)]
pub fn phase_f32(x: f64) -> f32 {
    x.clamp(0.0, 1.0) as f32
}

/// L'état de la file, dans l'en-tête de la console : « aucune tâche en cours », ou la commande qui tourne, depuis
/// combien de secondes, avec un point d'accent qui pulse (et les images qu'il faut, seulement tant qu'elle tourne).
/// Rend la place du texte écrit.
pub(super) fn tache_en_tete(
    ui: &Ui,
    peintre: &egui::Painter,
    tete: Rect,
    en_cours: Option<(Commande, Duration)>,
    taches: usize,
) -> Rect {
    let p = pal();
    let point = pos2(tete.left() + 98.0, tete.center().y);
    if en_cours.is_some() {
        let temps = ui.ctx().input(|i| i.time);
        super::mouvement::pouls(peintre, temps, point, 3.0, p.accent, super::mouvement::POULS_TACHE);
        super::mouvement::tourne(ui.ctx());
    } else {
        peintre.circle_filled(point, 3.0, p.gris);
    }
    let etat = match (en_cours, taches) {
        (Some((c, d)), n) if n > 1 => crate::trf!(
            "{} en cours depuis {} s · {} en attente",
            "{} running for {} s · {} queued",
            c.nom_affiche(),
            d.as_secs(),
            n - 1
        ),
        (Some((c, d)), _) => {
            crate::trf!(
                "{} en cours depuis {} s",
                "{} running for {} s",
                c.nom_affiche(),
                d.as_secs()
            )
        }
        (None, _) => crate::tr!("aucune tâche en cours", "no task running").into(),
    };
    peintre.text(
        pos2(tete.left() + 110.0, tete.center().y),
        Align2::LEFT_CENTER,
        etat,
        police(12.0),
        if en_cours.is_some() { p.doux } else { p.discret },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use eframe::egui;

    use crate::appli::Appli;
    use crate::commandes::Rubrique;

    /// Une image de la fenêtre entière, la souris posée en `souris` (un mouvement à la première image seulement : egui
    /// compte le délai d'une bulle depuis le dernier) ; rend le cadre de l'infobulle qui dit `texte`, s'il y en a une.
    fn image(
        ctx: &egui::Context,
        appli: &mut Appli,
        temps: f64,
        souris: egui::Pos2,
        texte: &str,
    ) -> Option<egui::Rect> {
        let entree = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1280.0, 800.0))),
            time: Some(temps),
            events: if temps <= 1.0 {
                vec![egui::Event::PointerMoved(souris)]
            } else {
                vec![]
            },
            ..Default::default()
        };
        let mut sortie = ctx.run_ui(entree, |ui| super::tout(appli, ui));
        sortie.textures_delta.clear();
        let p = super::pal();
        let ecrit = sortie.shapes.iter().find_map(|c| match &c.shape {
            egui::Shape::Text(t) if t.galley.text() == texte => Some(t.pos),
            _ => None,
        })?;
        // Le cadre d'une bulle vient avec son ombre : un `Shape::Vec`.
        let feuilles = sortie.shapes.iter().flat_map(|c| match &c.shape {
            egui::Shape::Vec(v) => v.iter().collect::<Vec<_>>(),
            s => vec![s],
        });
        feuilles
            .filter_map(|s| match s {
                egui::Shape::Rect(r) => Some(r),
                _ => None,
            })
            .find(|r| {
                r.rect.contains(ecrit)
                    && r.fill == p.surface
                    && r.stroke.color == p.trait_
                    && r.corner_radius == egui::CornerRadius::same(16)
                    && r.rect.width() < 420.0
            })
            .map(|r| r.rect)
    }

    /// Une rubrique du rail dit son nom en entier dans une infobulle, au fond, au contour et au rayon des cartes ; pas
    /// tout de suite (la souris qui passe ne fait rien surgir), mais en moins d'une demi-seconde.
    #[test]
    fn le_rail_dit_sa_rubrique_dans_une_bulle() {
        let ctx = egui::Context::default();
        super::super::polices(&ctx);
        super::super::appliquer_theme(&ctx, true);
        let mut appli = Appli::pour_captures();
        // « Réseau et Internet », troisième du rail (sur deux lignes dans le rail, sur une dans la bulle).
        let souris = egui::pos2(44.0, 255.0);
        let nom = Rubrique::Reseau.nom();
        assert!(
            image(&ctx, &mut appli, 1.0, souris, nom).is_none(),
            "une bulle sans attendre"
        );
        assert!(image(&ctx, &mut appli, 1.1, souris, nom).is_none(), "une bulle à 0,1 s");
        let mut bulle = None;
        for k in 0..6 {
            bulle = bulle.or(image(&ctx, &mut appli, 1.2 + 0.05 * f64::from(k), souris, nom));
        }
        assert!(bulle.is_some(), "pas de bulle en une demi-seconde");
    }

    /// À 800 px de haut, les onze rubriques tiennent sans défiler ; à 1080, le rail est à l'aise ; plus bas que le
    /// rail serré, il défile (l'aisance ne descend pas sous zéro).
    #[test]
    fn le_rail_tient_a_800_de_haut() {
        let aise = aisance_du_rail(800.0);
        assert!(aise > 0.0 && aise < 1.0);
        assert!(hauteur_du_rail(aise) <= 792.0 + 0.01);
        assert!((aisance_du_rail(1080.0) - 1.0).abs() < f32::EPSILON);
        assert!(aisance_du_rail(640.0).abs() < f32::EPSILON);
        assert!(hauteur_du_rail(0.0) < 690.0);
    }
}

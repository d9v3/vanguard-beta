//! Les icônes du rail, tracées comme celles de la maquette (grille 24 × 24, trait 1,5) : aucun fichier d'image.

use std::f32::consts::PI;

use eframe::egui::{Color32, CornerRadius, Painter, Pos2, Rect, Shape, Stroke, StrokeKind, vec2};

use crate::commandes::Rubrique;

const ECHELLE: f32 = 0.75;

pub fn rubrique(p: &Painter, centre: Pos2, r: Rubrique, couleur: Color32) {
    let s = ECHELLE;
    let o = centre - vec2(12.0 * s, 12.0 * s);
    let pt = |x: f32, y: f32| o + vec2(x * s, y * s);
    let st = Stroke::new(1.5, couleur);
    let ligne = |pts: &[(f32, f32)]| {
        p.add(Shape::line(pts.iter().map(|&(x, y)| pt(x, y)).collect(), st));
    };
    let arc = |cx: f32, cy: f32, rayon: f32, a0: f32, a1: f32| {
        let pts: Vec<Pos2> = (0..=16u8)
            .map(|i| {
                let a = a0 + (a1 - a0) * f32::from(i) / 16.0;
                pt(cx + rayon * a.cos(), cy + rayon * a.sin())
            })
            .collect();
        p.add(Shape::line(pts, st));
    };
    let rect = |x: f32, y: f32, w: f32, h: f32| {
        p.rect_stroke(
            Rect::from_min_size(pt(x, y), vec2(w * s, h * s)),
            CornerRadius::same(1),
            st,
            StrokeKind::Middle,
        );
    };
    let bouclier = || {
        ligne(&[
            (12., 3.),
            (4.5, 6.),
            (4.5, 11.5),
            (6., 16.),
            (12., 21.),
            (18., 16.),
            (19.5, 11.5),
            (19.5, 6.),
            (12., 3.),
        ]);
    };
    match r {
        Rubrique::Accueil => {
            rect(3., 3., 7., 7.);
            rect(14., 3., 7., 7.);
            rect(3., 14., 7., 7.);
            rect(14., 14., 7., 7.);
        }
        Rubrique::Ordinateur => {
            rect(3., 4., 18., 12.);
            ligne(&[(8., 20.), (16., 20.)]);
            ligne(&[(12., 16.), (12., 20.)]);
        }
        Rubrique::Reseau => {
            arc(12., 19.5, 13.5, -PI * 0.78, -PI * 0.22);
            arc(12., 19.5, 9.0, -PI * 0.78, -PI * 0.22);
            arc(12., 19.5, 4.5, -PI * 0.78, -PI * 0.22);
        }
        Rubrique::Virus => {
            rect(8., 7., 8., 13.);
            ligne(&[(12., 11.), (12., 20.)]);
            ligne(&[(4., 13.), (8., 13.)]);
            ligne(&[(16., 13.), (20., 13.)]);
            arc(12., 7., 2., PI, 2. * PI);
        }
        Rubrique::Arnaques => {
            rect(3., 5., 18., 14.);
            ligne(&[(3.5, 7.), (12., 13.), (20.5, 7.)]);
        }
        Rubrique::Bloquer => {
            bouclier();
            ligne(&[(9.5, 9.5), (14.5, 14.5)]);
            ligne(&[(14.5, 9.5), (9.5, 14.5)]);
        }
        Rubrique::Donnees => {
            p.add(Shape::ellipse_stroke(pt(12., 5.5), vec2(7.5 * s, 2.5 * s), st));
            ligne(&[(4.5, 5.5), (4.5, 18.5)]);
            ligne(&[(19.5, 5.5), (19.5, 18.5)]);
            arc(12., 12., 7.5, 0., PI);
            arc(12., 18.5, 7.5, 0., PI);
        }
        Rubrique::Guide => {
            ligne(&[(12., 7.5), (12., 20.)]);
            ligne(&[(3.5, 5.), (9.5, 5.), (12., 7.5)]);
            ligne(&[(20.5, 5.), (14.5, 5.), (12., 7.5)]);
            ligne(&[(3.5, 5.), (3.5, 18.), (10., 18.), (12., 20.)]);
            ligne(&[(20.5, 5.), (20.5, 18.), (14., 18.), (12., 20.)]);
        }
        Rubrique::Depanner => {
            ligne(&[(5., 19.), (12., 12.)]);
            arc(15.5, 8.5, 4.5, -PI * 0.25, PI * 1.25);
        }
        Rubrique::Optimiser => {
            arc(12., 18., 8., PI, 2. * PI);
            ligne(&[(12., 18.), (16.5, 12.5)]);
        }
        Rubrique::Vanguard => {
            bouclier();
            ligne(&[(8.5, 9.), (12., 16.), (15.5, 9.)]);
        }
    }
}

/// Une coche (« ça va »), tracée : aucune des deux polices n'a le même signe.
pub fn coche(p: &Painter, r: Rect, couleur: Color32) {
    let pt = |x: f32, y: f32| r.min + vec2(x, y) * (r.width() / 24.0);
    p.add(Shape::line(
        vec![pt(5., 12.5), pt(9.5, 17.), pt(19., 7.5)],
        Stroke::new(1.8, couleur),
    ));
}

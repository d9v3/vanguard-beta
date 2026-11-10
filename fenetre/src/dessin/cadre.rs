//! Le cadre : le rail des rubriques à gauche, la barre en haut, la console dessous, l'écran au centre.

use eframe::egui::{
    self, Align2, Frame, Key, Margin, Rect, RichText, Sense, Stroke, StrokeKind, TextEdit, Ui, pos2, vec2,
};

use super::{f32_n, icones, melange, mono, moyenne, n_f32, pal, police};
use crate::appli::{Appli, Ecran, Ton};
use crate::commandes::{Commande, Rubrique};
use crate::donnees::protection::Allure;

/// Lignes de la console montrées, repliée et dépliée.
const LIGNES_REPLIEE: usize = 6;
const LIGNES_DEPLIEE: usize = 16;
const HAUTEUR_LIGNE: f32 = 20.0;

pub fn tout(appli: &mut Appli, ui: &mut Ui) {
    let p = pal();
    egui::Panel::left("rail")
        .exact_size(88.0)
        .resizable(false)
        .show_separator_line(false)
        .frame(
            Frame::new()
                .fill(p.fond)
                .stroke(Stroke::new(1.0, p.trait_))
                .inner_margin(Margin::symmetric(8, 0)),
        )
        .show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| rail(appli, ui));
        });
    egui::Panel::top("barre")
        .exact_size(64.0)
        .resizable(false)
        .show_separator_line(false)
        .frame(Frame::new().fill(p.fond))
        .show(ui, |ui| barre(appli, ui));
    let lignes = if console_depliee(ui) {
        LIGNES_DEPLIEE
    } else {
        LIGNES_REPLIEE
    };
    egui::Panel::top("console")
        .exact_size(36.0 + 12.0 + HAUTEUR_LIGNE * n_f32(lignes) + 44.0)
        .resizable(false)
        .show_separator_line(false)
        .frame(Frame::new().fill(p.surface))
        .show(ui, |ui| console(appli, ui, lignes));
    egui::CentralPanel::default()
        .frame(Frame::new().fill(p.fond))
        .show(ui, |ui| {
            egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                Frame::new()
                    .inner_margin(Margin {
                        left: 32,
                        right: 32,
                        top: 32,
                        bottom: 64,
                    })
                    .show(ui, |ui| {
                        ui.set_max_width(1520.0);
                        super::ecrans::montrer(appli, ui);
                    });
            });
        });
}

fn id_depliee() -> egui::Id {
    egui::Id::unique("console-depliee")
}

fn console_depliee(ui: &Ui) -> bool {
    ui.ctx().data(|d| d.get_temp::<bool>(id_depliee())).unwrap_or(false)
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

fn rail(appli: &mut Appli, ui: &mut Ui) {
    let p = pal();
    ui.add_space(16.0);
    let (r, _) = ui.allocate_exact_size(vec2(72.0, 40.0), Sense::hover());
    ui.painter()
        .text(r.center(), Align2::CENTER_CENTER, "V", moyenne(26.0), p.encre);
    ui.add_space(12.0);
    let allumee = rubrique_de(appli.ecran);
    for rub in Rubrique::TOUTES {
        let nom = rub.nom_court();
        let lignes = n_f32(nom.lines().count());
        let (r, rep) = ui.allocate_exact_size(vec2(72.0, 34.0 + 14.0 * lignes), Sense::click());
        let actif = allumee == rub;
        let vif = actif || rep.hovered();
        let peintre = ui.painter();
        if vif {
            peintre.rect_filled(r, 10, p.s2);
        }
        icones::rubrique(
            peintre,
            pos2(r.center().x, r.top() + 18.0),
            rub,
            if vif { p.accent } else { p.doux },
        );
        peintre.text(
            pos2(r.center().x, r.top() + 32.0),
            Align2::CENTER_TOP,
            nom,
            police(11.0),
            if vif { p.encre } else { p.doux },
        );
        if rep.clicked() {
            appli.ecran = match rub {
                Rubrique::Accueil => Ecran::Accueil,
                Rubrique::Guide => Ecran::Guide,
                r => Ecran::Rubrique(r),
            };
        }
        rep.on_hover_cursor(egui::CursorIcon::PointingHand);
        ui.add_space(4.0);
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
fn veille(appli: &Appli) -> (&'static str, bool, egui::Color32) {
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
        let col = if actif || rep.hovered() { p.encre } else { p.doux };
        ui.painter()
            .text(zone.center(), Align2::CENTER_CENTER, nom, police(14.0), col);
        if actif {
            ui.painter().rect_filled(
                Rect::from_min_max(pos2(zone.left(), zone.bottom() - 2.0), zone.right_bottom()),
                0,
                p.accent,
            );
        }
        if rep.clicked() {
            appli.ecran = ecran;
        }
        rep.on_hover_cursor(egui::CursorIcon::PointingHand);
        x += w;
    }
    let bouton = Rect::from_min_size(pos2(r.right() - 32.0 - 124.0, r.center().y - 18.0), vec2(124.0, 36.0));
    let rep = ui.interact(bouton, ui.scope_id().with("voir-alertes"), Sense::click());
    let fond = if rep.hovered() {
        melange(p.accent, p.encre, 0.85)
    } else {
        p.accent
    };
    ui.painter().rect_filled(bouton, 10, fond);
    ui.painter().text(
        bouton.center(),
        Align2::CENTER_CENTER,
        crate::tr!("Voir les alertes", "See alerts"),
        moyenne(13.0),
        p.sur_vif,
    );
    if rep.clicked() {
        appli.ecran = Ecran::Alertes;
    }
    rep.on_hover_cursor(egui::CursorIcon::PointingHand);
    if !large {
        return;
    }
    let (mot, respire, couleur) = veille(appli);
    let point = pos2(bouton.left() - 32.0 - 120.0, r.center().y);
    if respire {
        let temps = ui.ctx().input(|i| i.time);
        let phase = phase_f32((temps % 2.4) / 2.4);
        ui.painter()
            .circle_filled(point, 4.0 + 6.0 * phase, couleur.gamma_multiply(0.45 * (1.0 - phase)));
    }
    ui.painter().circle_filled(point, 4.0, couleur);
    ui.painter()
        .text(point + vec2(12.0, 0.0), Align2::LEFT_CENTER, mot, police(13.0), p.doux);
}

/// Une phase entre 0 et 1, de f64 en f32.
// raison : une valeur bornée à 0..=1 par l'appelant ; la perte de précision de f64 à f32 est voulue (un dessin).
#[allow(clippy::cast_possible_truncation)]
pub fn phase_f32(x: f64) -> f32 {
    x.clamp(0.0, 1.0) as f32
}

fn console(appli: &mut Appli, ui: &mut Ui, montrees: usize) {
    let p = pal();
    let r = ui.max_rect();
    let peintre = ui.painter().clone();
    let tete = Rect::from_min_size(r.min, vec2(r.width(), 36.0));
    peintre.line_segment([tete.left_bottom(), tete.right_bottom()], Stroke::new(1.0, p.trait_));
    peintre.text(
        pos2(tete.left() + 32.0, tete.center().y),
        Align2::LEFT_CENTER,
        "Console",
        moyenne(12.0),
        p.encre,
    );
    let en_cours = appli.en_cours();
    peintre.circle_filled(
        pos2(tete.left() + 98.0, tete.center().y),
        3.0,
        if en_cours.is_some() { p.accent } else { p.gris },
    );
    let etat = match (en_cours, appli.taches()) {
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
        p.discret,
    );
    // Déplier ou replier la console.
    let depliee = montrees == LIGNES_DEPLIEE;
    let zone = Rect::from_min_size(pos2(tete.right() - 32.0 - 90.0, tete.top()), vec2(90.0, tete.height()));
    let rep = ui.interact(zone, ui.scope_id().with("deplier"), Sense::click());
    peintre.text(
        pos2(zone.right(), zone.center().y),
        Align2::RIGHT_CENTER,
        if depliee {
            crate::tr!("Replier", "Collapse")
        } else {
            crate::tr!("Déplier", "Expand")
        },
        police(12.0),
        if rep.hovered() { p.encre } else { p.doux },
    );
    if rep.clicked() {
        ui.ctx().data_mut(|d| d.insert_temp(id_depliee(), !depliee));
    }
    rep.on_hover_cursor(egui::CursorIcon::PointingHand);
    let flux = Rect::from_min_max(
        pos2(r.left(), tete.bottom()),
        pos2(r.right(), tete.bottom() + 12.0 + HAUTEUR_LIGNE * n_f32(montrees)),
    );
    let total = appli.console.len();
    let debut = total.saturating_sub(montrees);
    let largeur_max = f32_n((flux.width() - 260.0) / 7.9).max(10);
    for (k, l) in appli.console.iter().skip(debut).enumerate() {
        // 1 : la plus récente ; les plus anciennes s'effacent vers le haut.
        let rang = total - debut - k;
        let alpha = if rang >= montrees {
            0.35
        } else if rang + 1 == montrees {
            0.6
        } else {
            1.0
        };
        let y = flux.bottom() - 12.0 - HAUTEUR_LIGNE * (n_f32(rang) - 0.5);
        let col = match l.ton {
            Ton::Normal => p.encre,
            Ton::Commande => p.accent,
            Ton::Bon => p.bon,
            Ton::Attention => p.moyen,
            Ton::Grave => p.grave,
            Ton::Discret => p.doux,
        };
        let col_source = if l.ton == Ton::Commande { p.accent } else { p.doux };
        peintre.text(
            pos2(flux.left() + 32.0, y),
            Align2::LEFT_CENTER,
            &l.heure,
            mono(13.0),
            p.discret.gamma_multiply(alpha),
        );
        peintre.text(
            pos2(flux.left() + 116.0, y),
            Align2::LEFT_CENTER,
            &l.source,
            mono(13.0),
            col_source.gamma_multiply(alpha),
        );
        let t = crate::nettoyage::couper(&l.texte, largeur_max);
        let g = peintre.text(
            pos2(flux.left() + 220.0, y),
            Align2::LEFT_CENTER,
            &t,
            mono(13.0),
            col.gamma_multiply(alpha),
        );
        if rang == 1 && en_cours.is_some() && (ui.ctx().input(|i| i.time) % 1.0) < 0.5 {
            peintre.rect_filled(
                Rect::from_min_size(pos2(g.right() + 3.0, y - 7.0), vec2(7.0, 14.0)),
                0,
                p.accent,
            );
        }
    }
    // La saisie : un nom de la liste fermée, rien d'autre ne part (commandes::comprendre).
    let saisie = Rect::from_min_max(pos2(r.left(), flux.bottom()), pos2(r.right(), flux.bottom() + 44.0));
    peintre.line_segment([saisie.left_top(), saisie.right_top()], Stroke::new(1.0, p.trait_));
    peintre.line_segment(
        [saisie.left_bottom(), saisie.right_bottom()],
        Stroke::new(1.0, p.trait_),
    );
    peintre.text(
        pos2(saisie.left() + 32.0, saisie.center().y),
        Align2::LEFT_CENTER,
        "vanguard ›",
        mono(13.0),
        p.accent,
    );
    let mut x = saisie.right() - 32.0;
    for k in [crate::tr!("Entrée", "Enter"), "↑", "Tab"] {
        let g = peintre.layout_no_wrap(k.into(), police(11.0), p.doux);
        let w = g.size().x + 12.0;
        let cap = Rect::from_min_size(pos2(x - w, saisie.center().y - 10.0), vec2(w, 20.0));
        peintre.rect_stroke(cap, 4, Stroke::new(1.0, p.trait_), StrokeKind::Inside);
        peintre.galley(cap.center() - g.size() / 2.0, g, p.doux);
        x -= w + 8.0;
    }
    let champ = Rect::from_min_max(
        pos2(saisie.left() + 128.0, saisie.top() + 8.0),
        pos2(x - 16.0, saisie.bottom() - 8.0),
    );
    // Tab et ↑ ↓ sont pris avant le champ : Tab ne doit pas sortir du champ, ↑ ne doit pas bouger le curseur.
    let id_saisie = ui.make_persistent_id("saisie");
    let a_le_focus = ui.ctx().memory(egui::Memory::focused) == Some(id_saisie);
    if a_le_focus {
        let (tab, haut, bas) = ui.input_mut(|i| {
            (
                i.consume_key(egui::Modifiers::NONE, Key::Tab),
                i.consume_key(egui::Modifiers::NONE, Key::ArrowUp),
                i.consume_key(egui::Modifiers::NONE, Key::ArrowDown),
            )
        });
        if tab {
            appli.completer();
        }
        if haut {
            appli.rappeler(true);
        }
        if bas {
            appli.rappeler(false);
        }
    }
    let rep = ui
        .scope_builder(egui::UiBuilder::new().max_rect(champ), |ui| {
            ui.add(
                TextEdit::singleline(&mut appli.saisie)
                    .id(id_saisie)
                    .frame(Frame::NONE)
                    .font(mono(13.0))
                    .text_color(p.encre)
                    .char_limit(200)
                    .hint_text(
                        RichText::new(crate::tr!(
                            "Tapez une commande de Vanguard (bilan, aide…)",
                            "Type a Vanguard command (check, help…)"
                        ))
                        .font(mono(13.0))
                        .color(p.discret),
                    )
                    .desired_width(champ.width()),
            )
        })
        .inner;
    if rep.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
        appli.saisir();
        rep.request_focus();
    }
}

//! La fenêtre « Vanguard — Coulisses » : ce que fait la fenêtre, pour qui veut le voir (`crate::coulisses` prend les
//! notes). Une seconde fenêtre du même processus ; si le système n'en permet pas, le même contenu dans un panneau à
//! droite de la fenêtre principale.
//!
//! En lecture seule : la vue ne reçoit qu'un `&Appli`, elle ne peut rien demander, rien lancer, rien changer (un essai
//! clique partout pour s'en assurer). Aucun droit de plus, aucun réseau, rien d'écrit : tout est en mémoire.

use eframe::egui::{self, Align2, Frame, Id, Label, Margin, Rect, RichText, Sense, Stroke, Ui, ViewportId, pos2, vec2};

use super::defile::{self, Colonnes, Rangee};
use super::{mono, moyenne, pal, police, survol};
use crate::appli::Appli;
use crate::coulisses::{Chemin, Coulisses, Note, Passage, Sorte};

/// Les colonnes du journal : l'heure, la sorte, le texte.
const COLONNES: Colonnes = Colonnes {
    heure: 20.0,
    source: 92.0,
    texte: 184.0,
    droite: 20.0,
    dessous: 8.0,
};

fn id_ouvertes() -> Id {
    Id::unique("coulisses-ouvertes")
}

pub fn ouvertes(ctx: &egui::Context) -> bool {
    ctx.data(|d| d.get_temp::<bool>(id_ouvertes())).unwrap_or(false)
}

pub fn basculer(ctx: &egui::Context) {
    let o = ouvertes(ctx);
    ctx.data_mut(|d| d.insert_temp(id_ouvertes(), !o));
}

fn fermer(ctx: &egui::Context) {
    ctx.data_mut(|d| d.insert_temp(id_ouvertes(), false));
}

/// Les coulisses, si elles sont ouvertes : une seconde fenêtre, ou un panneau quand le système n'en permet pas (à
/// appeler avant le panneau central).
pub fn montrer(appli: &Appli, ui: &mut Ui) {
    if !ouvertes(ui.ctx()) {
        return;
    }
    let p = pal();
    let c = &appli.coulisses;
    if ui.ctx().embed_viewports() {
        let r = egui::Panel::right("coulisses")
            .exact_size(460.0)
            .resizable(false)
            .show_separator_line(false)
            .frame(Frame::new().fill(p.surface))
            .show(ui, |ui| contenu(c, ui, true))
            .response
            .rect;
        let peintre = ui.painter();
        let pixel = 1.0 / peintre.pixels_per_point();
        let x = peintre.round_to_pixel_center(r.left() + pixel);
        peintre.vline(x, r.y_range(), Stroke::new(pixel, p.trait_));
        return;
    }
    let titre = crate::tr!("Vanguard — Coulisses", "Vanguard — Behind the scenes");
    let constructeur = egui::ViewportBuilder::default()
        .with_title(titre)
        .with_app_id("vanguard")
        .with_inner_size([760.0, 680.0])
        .with_min_inner_size([480.0, 400.0]);
    let ctx = ui.ctx().clone();
    ctx.show_viewport_immediate(ViewportId::from_hash_of("vanguard-coulisses"), constructeur, |ui, _| {
        if ui.ctx().input(|i| i.viewport().close_requested()) {
            fermer(ui.ctx());
        }
        egui::CentralPanel::default()
            .frame(Frame::new().fill(pal().fond))
            .show(ui, |ui| contenu(c, ui, false));
    });
}

/// Le contenu, le même dans la fenêtre et dans le panneau. `panneau` : un bouton pour fermer (une fenêtre a le sien).
fn contenu(c: &Coulisses, ui: &mut Ui, panneau: bool) {
    let p = pal();
    let r = ui.max_rect();
    // L'en-tête.
    let tete = Rect::from_min_size(r.min, vec2(r.width(), 64.0));
    let peintre = ui.painter().clone();
    peintre.text(
        pos2(tete.left() + 20.0, tete.top() + 22.0),
        Align2::LEFT_CENTER,
        crate::tr!("Coulisses", "Behind the scenes"),
        moyenne(16.0),
        p.encre,
    );
    peintre.text(
        pos2(tete.left() + 20.0, tete.top() + 44.0),
        Align2::LEFT_CENTER,
        crate::tr!(
            "Ce que fait la fenêtre, en mémoire seulement. Rien ne se lance d'ici.",
            "What the window does, in memory only. Nothing can be started from here."
        ),
        police(12.0),
        p.discret,
    );
    if panneau {
        let zone = Rect::from_min_size(pos2(tete.right() - 20.0 - 60.0, tete.top()), vec2(60.0, 44.0));
        let rep = ui.interact(zone, ui.scope_id().with("fermer"), Sense::click());
        peintre.text(
            pos2(zone.right(), tete.top() + 22.0),
            Align2::RIGHT_CENTER,
            crate::tr!("Fermer", "Close"),
            police(12.0),
            p.doux.lerp_to_gamma(p.encre, survol(ui, rep.id, rep.hovered())),
        );
        if rep.clicked() {
            fermer(ui.ctx());
        }
        rep.on_hover_cursor(egui::CursorIcon::PointingHand);
    }
    peintre.line_segment([tete.left_bottom(), tete.right_bottom()], Stroke::new(1.0, p.trait_));
    // Le bac à sable, les commandes, puis le journal dans le reste.
    let haut = Rect::from_min_max(pos2(r.left(), tete.bottom()), pos2(r.right(), tete.bottom() + 252.0));
    ui.scope_builder(egui::UiBuilder::new().max_rect(haut), |ui| {
        Frame::new()
            .inner_margin(Margin::symmetric(20, 12))
            .show(ui, |ui| resume(c, ui));
    });
    peintre.line_segment([haut.left_bottom(), haut.right_bottom()], Stroke::new(1.0, p.trait_));
    let titre = Rect::from_min_max(pos2(r.left(), haut.bottom()), pos2(r.right(), haut.bottom() + 36.0));
    peintre.text(
        pos2(titre.left() + 20.0, titre.center().y),
        Align2::LEFT_CENTER,
        crate::tr!("Journal", "Log"),
        moyenne(12.0),
        p.encre,
    );
    peintre.text(
        pos2(titre.right() - 20.0, titre.center().y),
        Align2::RIGHT_CENTER,
        crate::trf!(
            "{} ligne(s) · {} saisie(s) refusée(s)",
            "{} line(s) · {} refused input(s)",
            c.notes().len(),
            c.refus()
        ),
        mono(12.0),
        p.discret,
    );
    let flux = Rect::from_min_max(pos2(r.left(), titre.bottom()), r.max);
    let notes = c.notes();
    ui.scope_builder(egui::UiBuilder::new().max_rect(flux), |ui| {
        defile::journal(
            ui,
            Id::unique("coulisses-flux"),
            notes.len(),
            |i| notes.get(i).map(rangee),
            COLONNES,
            false,
        )
    });
}

/// L'état du bac à sable et les commandes lancées, la plus récente en haut.
fn resume(c: &Coulisses, ui: &mut Ui) {
    let p = pal();
    let (bac, souligner) = &c.bac;
    ui.label(
        RichText::new(crate::tr!("Bac à sable", "Sandbox"))
            .font(moyenne(12.0))
            .color(p.encre),
    );
    ui.add(
        Label::new(
            RichText::new(bac)
                .font(police(12.0))
                .color(if *souligner { p.moyen } else { p.doux }),
        )
        .wrap(),
    );
    ui.add_space(8.0);
    ui.label(
        RichText::new(crate::trf!(
            "Commandes ({}, les {} dernières gardées)",
            "Commands ({}, the last {} kept)",
            c.passages().len(),
            crate::coulisses::PASSAGES_MAX
        ))
        .font(moyenne(12.0))
        .color(p.encre),
    );
    egui::ScrollArea::vertical()
        .id_salt("coulisses-commandes")
        .auto_shrink(false)
        .show(ui, |ui| {
            if c.passages().is_empty() {
                ui.label(
                    RichText::new(crate::tr!(
                        "Aucune commande lancée pour l'instant.",
                        "No command started yet."
                    ))
                    .font(police(12.0))
                    .color(p.discret),
                );
            }
            for passage in c.passages().iter().rev() {
                ui.add(
                    Label::new(
                        RichText::new(format!("{}  {}", passage.heure, passage.ligne))
                            .font(mono(12.0))
                            .color(p.accent),
                    )
                    .wrap(),
                );
                ui.add(Label::new(RichText::new(details(passage)).font(mono(12.0)).color(p.doux)).wrap());
                ui.add_space(6.0);
            }
        });
}

/// Le chemin, le processus et la fin d'une commande, en une ligne.
fn details(passage: &Passage) -> String {
    let chemin = match passage.chemin {
        Chemin::Relais => crate::tr!("par le relais", "through the relay"),
        Chemin::Direct => crate::tr!("par la fenêtre", "by the window"),
    };
    let pid = passage.pid.map_or_else(
        || crate::tr!("pid inconnu", "pid unknown").to_owned(),
        |n| format!("pid {n}"),
    );
    let fin = passage.fin.as_ref().map_or_else(
        || crate::tr!("en cours", "running").to_owned(),
        |f| {
            let code = f.code.map_or_else(
                || crate::tr!("sans code", "no code").to_owned(),
                |c| format!("code {c}"),
            );
            crate::trf!(
                "{:.1} s · {} · {} octet(s) · {}",
                "{:.1} s · {} · {} byte(s) · {}",
                f.duree.as_secs_f32(),
                code,
                f.taille,
                f.issue
            )
        },
    );
    format!("    {chemin} · {pid} · {fin}")
}

/// Une note pour le journal.
fn rangee(n: &Note) -> Rangee<'_> {
    let p = pal();
    let (source, couleur_source, couleur) = match n.sorte {
        Sorte::Lancement => (crate::tr!("lance", "start"), p.accent, p.accent),
        Sorte::Processus => (crate::tr!("processus", "process"), p.doux, p.encre),
        Sorte::Erreur => ("stderr", p.doux, p.doux),
        Sorte::Sortie => ("stdout", p.doux, p.encre),
        Sorte::Fin => (crate::tr!("fin", "end"), p.doux, p.encre),
        Sorte::Refus => (crate::tr!("refus", "refused"), p.moyen, p.moyen),
    };
    Rangee {
        numero: n.numero,
        heure: &n.heure,
        source,
        couleur_source,
        texte: &n.texte,
        couleur,
    }
}

#[cfg(test)]
mod tests {
    use eframe::egui::{self, Event, Modifiers, PointerButton, Pos2, RawInput, Rect, pos2};

    use crate::appli::Appli;
    use crate::commandes::{Commande, Fin, Issue};
    use crate::coulisses::Chemin;

    const ECRAN: Rect = Rect::from_min_max(Pos2::ZERO, pos2(1440.0, 900.0));

    fn image(ctx: &egui::Context, temps: &mut f64, evenements: Vec<Event>, f: impl FnMut(&mut egui::Ui)) {
        *temps += 0.05;
        let entree = RawInput {
            screen_rect: Some(ECRAN),
            time: Some(*temps),
            events: evenements,
            ..Default::default()
        };
        ctx.run_ui(entree, f).textures_delta.clear();
    }

    fn clic(ou: Pos2) -> Vec<Vec<Event>> {
        let bouton = |pressed| Event::PointerButton {
            pos: ou,
            button: PointerButton::Primary,
            pressed,
            modifiers: Modifiers::NONE,
        };
        vec![vec![Event::PointerMoved(ou)], vec![bouton(true)], vec![bouton(false)]]
    }

    /// Une fenêtre sans programme (rien ne peut partir) et des coulisses remplies.
    fn appli() -> Appli {
        let mut a = Appli::nouvelle(Err("absent".into()), std::sync::Arc::new(|| {}));
        a.coulisses.lancee(Commande::Bilan.into(), Chemin::Direct);
        a.coulisses.processus(4242);
        a.coulisses.erreur("une ligne d'erreur");
        a.coulisses.finie(&Fin {
            lancement: Commande::Bilan.into(),
            code: Some(0),
            sortie: b"{\"score\": 90}\n".to_vec(),
            issue: Issue::Terminee,
            duree: std::time::Duration::from_millis(1200),
        });
        a.coulisses.refusee("bilan; rm -rf ~");
        a
    }

    /// Le bouton de l'en-tête de la console ouvre les coulisses (ici dans un panneau : sans système de fenêtres, egui
    /// n'en ouvre pas d'autre), puis un clic partout dans le panneau ne lance rien, ne demande rien, ne change rien.
    #[test]
    fn rien_ne_se_lance_depuis_les_coulisses() {
        let ctx = egui::Context::default();
        super::super::polices(&ctx);
        let mut temps = 0.0;
        let mut a = appli();
        let console = a.console.len();
        let notes = a.coulisses.notes().len();
        image(&ctx, &mut temps, Vec::new(), |ui| super::super::cadre::tout(&mut a, ui));
        assert!(!super::ouvertes(&ctx));
        // « Coulisses » finit 24 points à gauche de « Déplier » (90 points, à 32 du bord).
        for e in clic(pos2(ECRAN.right() - 32.0 - 90.0 - 24.0 - 8.0, 64.0 + 18.0)) {
            image(&ctx, &mut temps, e, |ui| super::super::cadre::tout(&mut a, ui));
        }
        assert!(super::ouvertes(&ctx), "le bouton n'ouvre pas les coulisses");
        assert!(ctx.embed_viewports());
        let mut y = 0.0;
        while y < ECRAN.bottom() {
            let mut x = 0.0;
            while x < ECRAN.right() {
                if !super::ouvertes(&ctx) {
                    super::basculer(&ctx);
                }
                for e in clic(pos2(x, y)) {
                    // La vue seule : elle ne reçoit qu'un `&Appli`.
                    image(&ctx, &mut temps, e, |ui| super::montrer(&a, ui));
                }
                x += 48.0;
            }
            y += 36.0;
        }
        assert_eq!(a.taches(), 0);
        assert_eq!(a.console.len(), console);
        assert_eq!(a.coulisses.notes().len(), notes);
        assert_eq!(a.coulisses.passages().len(), 1);
    }

    /// Le bouton « Fermer » du panneau ferme les coulisses.
    #[test]
    fn le_panneau_se_ferme() {
        let ctx = egui::Context::default();
        super::super::polices(&ctx);
        let mut temps = 0.0;
        let a = appli();
        super::basculer(&ctx);
        image(&ctx, &mut temps, Vec::new(), |ui| super::montrer(&a, ui));
        for e in clic(pos2(ECRAN.right() - 20.0 - 20.0, 22.0)) {
            image(&ctx, &mut temps, e, |ui| super::montrer(&a, ui));
        }
        assert!(!super::ouvertes(&ctx));
    }
}

//! La deuxième rangée de la Vue d'ensemble, sur un grand écran seulement : le dernier bilan, sujet par sujet, en
//! barres compactes, et les dernières alertes du journal. Du vrai contenu déjà lu (rien n'est lancé, rien n'est
//! inventé) : sans bilan ni journal lus, la rangée n'existe pas. Sur un écran plus petit (1280 × 800), rien de plus :
//! les trois tuiles et « Relire » remplissent déjà la fenêtre.
//!
//! Comme partout : un mot ne s'écrit jamais dans une couleur de gravité (réglable, elle peut se confondre avec le
//! fond) ; elle ne marque que le trait ou le point, le mot est à l'encre.

use eframe::egui::{
    Color32, FontId, Rect, RichText, Sense, Stroke, StrokeKind, Ui, UiBuilder, pos2,
    text::{LayoutJob, TextFormat, TextWrapping},
    vec2,
};

use super::bilan::{couleur_gravite, couleur_rang};
use super::{mono, moyenne, n_f32, pal, police, texte};
use crate::appli::Appli;
use crate::commandes::Commande;
use crate::donnees::bilan::{Gravite, Rang, Vue};
use crate::donnees::evenements;

/// La fenêtre à partir de laquelle la rangée se montre : elle y tient sans défiler, la console à sa hauteur de départ.
const LARGEUR_MIN: f32 = 1600.0;
const HAUTEUR_MIN: f32 = 960.0;
/// Sujets du bilan montrés au plus (les sujets à corriger d'abord), et alertes montrées au plus.
const SUJETS_MAX: usize = 5;
const ALERTES_MAX: usize = 3;
/// La hauteur d'un sujet et celle d'une alerte (deux lignes) : 5 sujets et 3 alertes font la même hauteur de carte.
const SUJET: f32 = 24.0;
const ALERTE: f32 = 40.0;
/// La hauteur du contenu des deux cartes, sous leur titre : la même, pour que leurs bords s'alignent.
const CONTENU: f32 = SUJET * 5.0;
/// L'écart entre deux cartes : celui des tuiles du dessus, sur lesquelles la rangée s'aligne.
const ECART: f32 = 16.0;

/// La rangée a-t-elle sa place ? Seulement dans une grande fenêtre, et seulement avec quelque chose de lu.
pub fn a_sa_place(appli: &Appli, fenetre: Rect) -> bool {
    fenetre.width() >= LARGEUR_MIN
        && fenetre.height() >= HAUTEUR_MIN
        && (appli.bilan().is_some() || appli.journal().is_some())
}

/// La rangée : le dernier bilan sous les deux premières tuiles, les dernières alertes sous la troisième.
pub fn rangee(appli: &Appli, ui: &mut Ui) {
    let large = ui.available_width();
    let colonne = (large - 2.0 * ECART) / 3.0;
    let haut = ui.cursor().min;
    let gauche = Rect::from_min_size(haut, vec2(2.0 * colonne + ECART, 0.0));
    let droite = Rect::from_min_size(pos2(gauche.right() + ECART, haut.y), vec2(colonne, 0.0));
    let mut bas = haut.y;
    for (zone, bilan) in [(gauche, true), (droite, false)] {
        let zone = Rect::from_min_max(zone.min, pos2(zone.right(), f32::INFINITY));
        let r = ui
            .scope_builder(UiBuilder::new().max_rect(zone), |ui| {
                super::carte(ui, 20, |ui| {
                    ui.set_width(ui.available_width());
                    if bilan {
                        dernier_bilan(appli, ui);
                    } else {
                        dernieres_alertes(appli, ui);
                    }
                });
            })
            .response
            .rect;
        bas = bas.max(r.bottom());
    }
    // Les deux cartes sont posées côte à côte à la main : la place prise est dite ici, d'un seul bloc.
    ui.allocate_rect(Rect::from_min_max(haut, pos2(haut.x + large, bas)), Sense::hover());
}

/// Le titre d'une carte (comme celui d'une tuile) et, à droite, une précision discrète.
fn titre(ui: &mut Ui, t: &str, droite: &str) {
    let p = pal();
    ui.horizontal(|ui| {
        ui.label(texte(t, 13.0, p.doux));
        ui.with_layout(eframe::egui::Layout::right_to_left(eframe::egui::Align::Center), |ui| {
            ui.label(RichText::new(droite).font(mono(12.0)).color(p.discret));
        });
    });
    ui.add_space(8.0);
}

/// Un texte sur une seule ligne, coupé d'un « … » à `largeur`.
fn coupe(ui: &Ui, t: &str, font: FontId, couleur: Color32, largeur: f32) -> std::sync::Arc<eframe::egui::Galley> {
    let mut job = LayoutJob::single_section(t.to_owned(), TextFormat::simple(font, couleur));
    job.wrap = TextWrapping {
        max_width: largeur.max(20.0),
        max_rows: 1,
        break_anywhere: false,
        overflow_character: Some('…'),
    };
    ui.fonts_mut(|f| f.layout_job(job))
}

/// Les sujets du bilan, ceux qui demandent un geste d'abord : à corriger, puis pas vérifiés, puis le reste, chacun
/// dans l'ordre du bilan.
fn sujets(v: &Vue) -> Vec<(String, Vec<Rang>)> {
    let mut g = v.groupes();
    g.sort_by_key(|(_, rangs)| {
        if rangs.contains(&Rang::Corriger) {
            0
        } else if rangs.contains(&Rang::NonVerifie) {
            1
        } else {
            2
        }
    });
    g
}

/// Ce qu'un sujet demande, en mots : ce qui est à corriger, ce qui n'a pas pu être vérifié, sinon que tout va.
fn mot_du_sujet(rangs: &[Rang]) -> String {
    let compte = |r: Rang| rangs.iter().filter(|&&e| e == r).count();
    let (corriger, non_verifies) = (compte(Rang::Corriger), compte(Rang::NonVerifie));
    let mut mots = Vec::new();
    if corriger > 0 {
        mots.push(crate::trf!("{} à corriger", "{} to fix", corriger));
    }
    if non_verifies > 0 {
        mots.push(crate::trn!(
            non_verifies,
            "pas vérifié",
            "pas vérifiés",
            "not verified",
            "not verified"
        ));
    }
    if mots.is_empty() {
        return crate::tr!("rien à corriger", "nothing to fix").to_owned();
    }
    mots.join(" · ")
}

fn dernier_bilan(appli: &Appli, ui: &mut Ui) {
    let p = pal();
    let heure = appli
        .resultat(Commande::Bilan)
        .map(|r| crate::trf!("à {}", "at {}", r.heure))
        .unwrap_or_default();
    titre(
        ui,
        crate::tr!("Dernier bilan, par sujet", "Last check, by topic"),
        &heure,
    );
    let Some(v) = appli.bilan().filter(|v| !v.constats.is_empty()) else {
        ui.allocate_ui(vec2(ui.available_width(), CONTENU), |ui| {
            ui.label(texte(
                crate::tr!(
                    "Pas encore de bilan : ses vérifications se rangeront ici, sujet par sujet.",
                    "No check yet: its checks will line up here, topic by topic."
                ),
                13.0,
                p.discret,
            ));
        });
        return;
    };
    let tous = sujets(v);
    // Cinq rangées : cinq sujets, ou quatre et « + N autres sujets ».
    let montres = if tous.len() > SUJETS_MAX {
        SUJETS_MAX - 1
    } else {
        tous.len()
    };
    let (zone, _) = ui.allocate_exact_size(vec2(ui.available_width(), CONTENU), Sense::hover());
    // Trois colonnes, lues comme une phrase : le sujet, ce qu'il demande, puis ses traits (un par vérification).
    let noms = (zone.width() * 0.26).clamp(150.0, 250.0);
    let mots = 170.0;
    let traits = Rect::from_x_y_ranges((zone.left() + noms + mots + 32.0)..=zone.right(), zone.y_range());
    for (k, (sujet, rangs)) in tous.iter().take(montres).enumerate() {
        let rangee = Rect::from_min_size(
            pos2(zone.left(), zone.top() + SUJET * n_f32(k)),
            vec2(zone.width(), SUJET),
        );
        let milieu = rangee.center().y;
        let peintre = ui.painter();
        let nom = coupe(ui, sujet, police(13.0), p.encre, noms);
        peintre.galley(pos2(rangee.left(), milieu - nom.size().y / 2.0), nom, p.encre);
        barres(ui, pos2(traits.left(), milieu), traits.width(), rangs);
        let demande = rangs.iter().any(|&e| e == Rang::Corriger || e == Rang::NonVerifie);
        let encre = if demande { p.encre } else { p.doux };
        let mot = coupe(ui, &mot_du_sujet(rangs), police(12.0), encre, mots);
        ui.painter().galley(
            pos2(rangee.left() + noms + 16.0, milieu - mot.size().y / 2.0),
            mot,
            encre,
        );
        ui.interact(rangee, ui.scope_id().with(("sujet", k)), Sense::hover())
            .on_hover_text(format!(
                "{} — {}, {}",
                sujet,
                crate::trn!(rangs.len(), "vérification", "vérifications", "check", "checks"),
                mot_du_sujet(rangs)
            ));
    }
    if tous.len() > montres {
        let reste = tous.len() - montres;
        let a_voir = tous
            .iter()
            .skip(montres)
            .filter(|(_, r)| r.contains(&Rang::Corriger))
            .count();
        let mot = if a_voir > 0 {
            crate::trf!(
                "+ {} autres sujets, dont {} à corriger : tout est dans le Bilan.",
                "+ {} more topics, {} of them to fix: everything is in the Check.",
                reste,
                a_voir
            )
        } else {
            crate::trf!(
                "+ {} autres sujets, sans rien à corriger : tout est dans le Bilan.",
                "+ {} more topics, with nothing to fix: everything is in the Check.",
                reste
            )
        };
        let y = zone.top() + SUJET * n_f32(montres) + SUJET / 2.0;
        let g = coupe(ui, &mot, police(12.0), p.discret, zone.width());
        ui.painter()
            .galley(pos2(zone.left(), y - g.size().y / 2.0), g, p.discret);
    }
}

/// Les traits d'un sujet, un par vérification, sur une ligne : 6 points de large et 12 de haut, plus fins quand le
/// sujet en a trop pour la largeur. Les couleurs et les hachures sont celles de la bande du Bilan.
fn barres(ui: &Ui, gauche_milieu: eframe::egui::Pos2, largeur: f32, rangs: &[Rang]) {
    let p = pal();
    let n = n_f32(rangs.len().max(1));
    let pas = (largeur / n).clamp(3.0, 9.0);
    let w = (pas * 2.0 / 3.0).round().max(2.0);
    let peintre = ui.painter();
    for (i, &e) in rangs.iter().enumerate() {
        let x = gauche_milieu.x + pas * n_f32(i);
        if x + w > gauche_milieu.x + largeur {
            break;
        }
        let trait_ = Rect::from_min_size(pos2(x, gauche_milieu.y - 6.0), vec2(w, 12.0));
        if e == Rang::NonVerifie {
            peintre.rect_filled(trait_, 2, p.fond);
            peintre.rect_stroke(trait_, 2, Stroke::new(1.0, p.gris), StrokeKind::Inside);
        } else {
            peintre.rect_filled(trait_, 2, couleur_rang(e));
        }
    }
}

fn dernieres_alertes(appli: &Appli, ui: &mut Ui) {
    let p = pal();
    let Some(j) = appli.journal() else {
        titre(ui, crate::tr!("Dernières alertes", "Latest alerts"), "");
        ui.allocate_ui(vec2(ui.available_width(), CONTENU), |ui| {
            ui.label(texte(
                crate::tr!(
                    "Journal pas encore lu : ses alertes se rangeront ici.",
                    "Log not read yet: its alerts will line up here."
                ),
                13.0,
                p.discret,
            ));
        });
        return;
    };
    let alertes: Vec<&evenements::Evenement> = j.alertes().collect();
    let compte = if alertes.len() > ALERTES_MAX {
        crate::trf!("{} sur {}", "{} of {}", ALERTES_MAX, alertes.len())
    } else {
        String::new()
    };
    titre(ui, crate::tr!("Dernières alertes", "Latest alerts"), &compte);
    let (zone, _) = ui.allocate_exact_size(vec2(ui.available_width(), CONTENU), Sense::hover());
    if alertes.is_empty() {
        let coche = Rect::from_min_size(zone.min, vec2(18.0, 18.0));
        super::icones::coche(ui.painter(), coche, p.bon);
        let g = ui.painter().layout(
            crate::tr!(
                "Aucune alerte notée : Vanguard n'a rien vu d'inquiétant.",
                "No alert recorded: Vanguard has seen nothing worrying."
            )
            .to_owned(),
            police(13.0),
            p.doux,
            zone.width() - 26.0,
        );
        ui.painter().galley(pos2(zone.left() + 26.0, zone.top()), g, p.doux);
        return;
    }
    let maintenant = chrono::Utc::now();
    for (k, e) in alertes.iter().take(ALERTES_MAX).enumerate() {
        let rangee = Rect::from_min_size(
            pos2(zone.left(), zone.top() + ALERTE * n_f32(k)),
            vec2(zone.width(), ALERTE),
        );
        let peintre = ui.painter();
        // Le point porte la gravité ; le titre et le reste sont à l'encre.
        peintre.circle_filled(
            pos2(rangee.left() + 4.0, rangee.top() + 10.0),
            4.0,
            couleur_gravite(e.gravite.or(Some(Gravite::Moyenne))),
        );
        let large = rangee.width() - 18.0;
        let titre = coupe(ui, &e.titre, moyenne(13.0), p.encre, large);
        peintre.galley(pos2(rangee.left() + 18.0, rangee.top() + 1.0), titre, p.encre);
        let sous = format!("{} · {}", crate::temps::age(&e.quand, maintenant), e.source);
        let sous = coupe(ui, &sous, mono(11.0), p.discret, large);
        ui.painter()
            .galley(pos2(rangee.left() + 18.0, rangee.top() + 20.0), sous, p.discret);
        if !e.detail.is_empty() {
            ui.interact(rangee, ui.scope_id().with(("alerte", k)), Sense::hover())
                .on_hover_text(&e.detail);
        }
    }
}

#[cfg(test)]
mod tests {
    use eframe::egui;

    /// Les textes peints par toute la fenêtre à cette taille.
    fn textes(taille: egui::Vec2) -> Vec<String> {
        let ctx = egui::Context::default();
        super::super::polices(&ctx);
        let mut appli = super::super::captures::appli_remplie(false, true);
        let mut peints = Vec::new();
        for k in 0..3 {
            let entree = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, taille)),
                time: Some(1.0 + f64::from(k)),
                ..Default::default()
            };
            let mut sortie = ctx.run_ui(entree, |ui| super::super::cadre::tout(&mut appli, ui));
            sortie.textures_delta.clear();
            peints = sortie
                .shapes
                .iter()
                .filter_map(|c| match &c.shape {
                    egui::Shape::Text(t) => Some(t.galley.text().to_owned()),
                    _ => None,
                })
                .collect();
        }
        peints
    }

    /// La deuxième rangée existe à 1920 × 1080, avec le bilan par sujet et les alertes ; à 1280 × 800, rien de plus.
    #[test]
    fn la_deuxieme_rangee_ne_vient_que_sur_un_grand_ecran() {
        let bilan = crate::tr!("Dernier bilan, par sujet", "Last check, by topic");
        let alertes = crate::tr!("Dernières alertes", "Latest alerts");
        let grand = textes(egui::vec2(1920.0, 1080.0));
        assert!(grand.iter().any(|t| t == bilan), "pas de bilan par sujet : {grand:?}");
        assert!(grand.iter().any(|t| t == alertes), "pas d'alertes");
        let petit = textes(egui::vec2(1280.0, 800.0));
        assert!(
            !petit.iter().any(|t| t == bilan || t == alertes),
            "la rangée déborde à 1280"
        );
    }
}

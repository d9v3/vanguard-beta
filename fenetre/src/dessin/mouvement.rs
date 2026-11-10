//! Le mouvement de la fenêtre, en un seul endroit : le fondu d'arrivée d'un écran, les lignes de liste qui
//! s'éclairent au survol, le point qui pulse pendant qu'une commande tourne, les chiffres du Bilan qui montent.
//! Toutes les durées viennent d'une
//! seule réglette, `ALLURE` : à 0, plus rien ne bouge (chaque fondu saute à sa fin), le reste de la fenêtre ne change
//! pas. Aucun réglage « réduire les animations » n'est lu du système pour l'instant : la fenêtre, dans son bac à
//! sable, ne lit ni les réglages du bureau ni ceux de Windows ; le jour où elle le pourra, il se branchera ici.

use std::time::Duration;

use eframe::egui::{
    Color32, Context, FontId, Id, Painter, Pos2, Rect, Response, Role, Sense, Shape, Ui, Vec2, WidgetInfo,
    emath::TSTransform, pos2, vec2,
};

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

/// La montée des chiffres d'un résultat, de 0 à leur valeur.
const MONTEE: f32 = duree(0.6);
/// L'intervalle des images pendant qu'une commande tourne : le point qui pulse et les secondes qui passent n'ont pas
/// besoin de plus (environ 30 par seconde).
const TOURNE: Duration = Duration::from_millis(33);
/// Un tour de pouls d'une commande qui tourne, en secondes.
pub const POULS_TACHE: f32 = 1.2;
/// Une respiration du point « En veille », plus lente : rien ne presse.
pub const POULS_VEILLE: f32 = 2.4;

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

/// Une ligne de liste (un constat, un appareil, une alerte, une commande…) qui s'éclaire doucement sous la souris :
/// le fond seulement, peint sous son contenu, sur toute la largeur de la liste et débordant de `marge` (pris dans les
/// espaces entre les lignes ou la marge de la carte). Rien ne bouge, aucune taille ne change : la ligne prend la place
/// de son contenu, survolée ou non. Les boutons de la ligne gardent leur propre survol par-dessus.
pub fn ligne<R>(ui: &mut Ui, marge: Vec2, rayon: f32, contenu: impl FnOnce(&mut Ui) -> R) -> R {
    let id = ui.next_auto_id().with("ligne");
    // Une place réservée sous le contenu, remplie une fois sa hauteur connue.
    let fond = ui.painter().add(Shape::Noop);
    let r = ui.scope(contenu);
    let large = ui.max_rect();
    let zone = Rect::from_x_y_ranges(large.x_range(), r.response.rect.y_range()).expand2(marge);
    let s = super::survol(ui, id, ui.rect_contains_pointer(zone));
    if s > 0.0 {
        ui.painter()
            .set(fond, Shape::rect_filled(zone, rayon, super::pal().s2.gamma_multiply(s)));
    }
    r.inner
}

/// Un point qui pulse : un halo de sa couleur s'élargit jusqu'à 2,5 fois son rayon et s'efface, toutes les `periode`
/// secondes (passées par la réglette : à 0, le point reste seul, immobile). Ne demande aucune image : un point qui
/// pulse au repos (la veille) vit des images de la fenêtre, un point de travail appelle `tourne`.
pub fn pouls(peintre: &Painter, temps: f64, centre: Pos2, rayon: f32, couleur: Color32, periode: f32) {
    let periode = f64::from(duree(periode));
    if periode > 0.0 {
        let phase = super::cadre::phase_f32((temps % periode) / periode);
        peintre.circle_filled(
            centre,
            rayon * (1.0 + 1.5 * phase),
            couleur.gamma_multiply(0.45 * (1.0 - phase)),
        );
    }
    peintre.circle_filled(centre, rayon, couleur);
}

/// Quelque chose tourne et se montre en train de tourner : les images suivent, à 30 par seconde, et seulement tant
/// qu'on l'appelle (au repos, aucune).
pub fn tourne(ctx: &Context) {
    ctx.request_repaint_after(TOURNE);
}

/// Où en est la montée des chiffres du résultat `cle` (de 0 à 1, ralentie à la fin) : elle part la première fois
/// que ce résultat est montré, et une fois finie le reste (revenir sur l'écran ne la relance pas ; un nouveau
/// résultat, autre clé, la relance).
pub fn montee(ctx: &Context, cle: Id) -> f32 {
    let maintenant = ctx.input(|i| i.time);
    let debut = ctx.data_mut(|d| *d.get_temp_mut_or_insert_with(cle.with("montee"), || maintenant));
    let part = avancement(maintenant, debut, MONTEE);
    if part < 1.0 {
        ctx.request_repaint_after(IMAGE);
    }
    sortie(part)
}

/// Un nombre qui monte : `valeur` multipliée par `part` (de `montee`), écrit par `ecrire`. La place est celle du
/// texte final, prise dès la première image (rien ne bouge autour), le nombre calé à sa droite ; un lecteur d'écran
/// lit tout de suite le texte final, jamais un chiffre de passage.
pub fn nombre(
    ui: &mut Ui,
    part: f32,
    valeur: usize,
    ecrire: impl Fn(usize) -> String,
    police: &FontId,
    couleur: Color32,
) -> Response {
    let fin = ecrire(valeur);
    let montre = if part >= 1.0 {
        valeur
    } else {
        super::f32_n((super::n_f32(valeur) * part).round())
    };
    let peintre = ui.painter();
    let place = peintre.layout_no_wrap(fin.clone(), police.clone(), couleur);
    let (zone, rep) = ui.allocate_exact_size(place.size(), Sense::hover());
    let texte = if montre == valeur {
        place
    } else {
        ui.painter().layout_no_wrap(ecrire(montre), police.clone(), couleur)
    };
    let coin = pos2(zone.right() - texte.size().x, zone.top());
    ui.painter().galley(coin, texte, couleur);
    rep.widget_info(|| WidgetInfo::labeled(Role::Label, true, &fin));
    rep
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

    /// Une ligne survolée s'éclaire (son fond apparaît en fondu, à la couleur `s2` une fois fini) sans changer de
    /// taille ni de place.
    #[test]
    fn une_ligne_survolee_s_eclaire_sans_bouger() {
        let ctx = egui::Context::default();
        super::super::polices(&ctx);
        let fond = super::super::pal().s2;
        let voir = |temps: f64, souris: egui::Pos2| {
            let mut entree = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(800.0, 600.0))),
                time: Some(temps),
                ..Default::default()
            };
            entree.events.push(egui::Event::PointerMoved(souris));
            let mut place = egui::Rect::NOTHING;
            let mut sortie = ctx.run_ui(entree, |ui| {
                ui.add_space(40.0);
                place = super::ligne(ui, egui::vec2(8.0, 3.0), 6.0, |ui| ui.label("Lecteur · alice")).rect;
            });
            sortie.textures_delta.clear();
            let eclairee = sortie
                .shapes
                .iter()
                .any(|c| matches!(&c.shape, egui::Shape::Rect(r) if r.fill == fond && r.rect.width() > 700.0));
            (place, eclairee)
        };
        let (avant, eclairee) = voir(1.0, egui::pos2(400.0, 500.0));
        assert!(!eclairee, "éclairée sans la souris");
        // La souris arrive sur la ligne (bord gauche du texte : dans la ligne) ; le fondu fini, le fond est là.
        let dessus = avant.left_center() + egui::vec2(2.0, 0.0);
        let (pendant, _) = voir(1.01, dessus);
        let (apres, eclairee) = voir(1.5, dessus);
        assert!(eclairee, "la ligne survolée ne s'éclaire pas");
        assert_eq!(avant, pendant, "la ligne a bougé au survol");
        assert_eq!(avant, apres, "la ligne a bougé au survol");
        // La souris dans la marge, entre deux lignes, éclaire encore : pas de trou qui clignote entre les lignes.
        let (_, eclairee) = voir(2.0, egui::pos2(avant.left() + 2.0, avant.top() - 2.0));
        assert!(eclairee, "la marge de la ligne ne compte pas comme survolée");
    }

    /// Une image d'un nombre qui monte (82, clé du résultat `cle`), à l'instant `temps` : le texte peint, la place
    /// prise, et ce qu'un lecteur d'écran en lit.
    fn image_nombre(ctx: &egui::Context, cle: egui::Id, temps: f64) -> (Vec<String>, egui::Rect, Vec<String>) {
        let mut place = egui::Rect::NOTHING;
        let mut sortie = ctx.run_ui(
            egui::RawInput {
                time: Some(temps),
                ..Default::default()
            },
            |ui| {
                let part = super::montee(ui.ctx(), cle);
                let police = egui::FontId::proportional(72.0);
                place = super::nombre(ui, part, 82, |k| k.to_string(), &police, egui::Color32::WHITE).rect;
            },
        );
        sortie.textures_delta.clear();
        let peints = sortie
            .shapes
            .iter()
            .filter_map(|c| match &c.shape {
                egui::Shape::Text(t) => Some(t.galley.text().to_owned()),
                _ => None,
            })
            .collect();
        let lus = sortie
            .platform_output
            .accesskit_update
            .map(|u| {
                u.nodes
                    .iter()
                    .filter_map(|(_, n)| n.value().or(n.label()).map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        (peints, place, lus)
    }

    /// Le score monte de 0 à 82 en `MONTEE`, à la place du texte final dès la première image ; un lecteur d'écran lit
    /// 82 tout de suite ; revenir sur le même résultat ne relance rien, un nouveau résultat si.
    #[test]
    fn les_chiffres_montent_une_fois_par_resultat() {
        let ctx = egui::Context::default();
        super::super::polices(&ctx);
        ctx.enable_accesskit();
        let premier = egui::Id::unique(("essai", 1));
        let (peints, debut, lus) = image_nombre(&ctx, premier, 1.0);
        assert_eq!(peints, ["0"], "la montée ne part pas de 0");
        assert!(
            lus.iter().any(|l| l == "82"),
            "le lecteur d'écran ne lit pas 82 : {lus:?}"
        );
        let (peints, milieu, _) = image_nombre(&ctx, premier, 1.0 + f64::from(super::MONTEE) / 2.0);
        let n: u32 = peints[0].parse().unwrap();
        assert!(n > 41 && n < 82, "à mi-chemin (ease-out) : {n}");
        let (peints, fin, _) = image_nombre(&ctx, premier, 1.0 + f64::from(super::MONTEE));
        assert_eq!(peints, ["82"]);
        assert_eq!(debut, milieu, "la place a changé pendant la montée");
        assert_eq!(debut, fin, "la place a changé pendant la montée");
        // Plus tard, le même résultat : tout de suite 82. Un autre résultat : de nouveau 0.
        assert_eq!(image_nombre(&ctx, premier, 30.0).0, ["82"]);
        assert_eq!(image_nombre(&ctx, egui::Id::unique(("essai", 2)), 31.0).0, ["0"]);
    }

    /// Le délai avant l'image suivante qu'egui a noté.
    fn delai(sortie: &egui::FullOutput) -> std::time::Duration {
        sortie.viewport_output[&egui::ViewportId::ROOT].repaint_delay
    }

    /// Au repos (rien ne tourne, aucun fondu), la fenêtre entière ne demande aucune image : pas de boucle cachée.
    /// Pendant qu'une commande tourne, l'en-tête de la console en demande 30 par seconde, et son point pulse.
    #[test]
    fn les_images_suivent_seulement_ce_qui_tourne() {
        let ctx = egui::Context::default();
        super::super::polices(&ctx);
        let mut appli = Appli::pour_captures();
        let ecran = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1280.0, 800.0));
        let mut derniere = std::time::Duration::ZERO;
        for k in 0..40 {
            let entree = egui::RawInput {
                screen_rect: Some(ecran),
                time: Some(1.0 + 0.1 * f64::from(k)),
                ..Default::default()
            };
            let mut sortie = ctx.run_ui(entree, |ui| super::super::cadre::tout(&mut appli, ui));
            sortie.textures_delta.clear();
            derniere = delai(&sortie);
        }
        assert!(
            derniere >= std::time::Duration::from_secs(1),
            "au repos, une image est demandée dans {derniere:?}"
        );
        // Une commande tourne depuis 3 s : des images à 30 par seconde, et un halo d'accent plus grand que le point.
        let accent = super::super::pal().accent;
        let mut halo = false;
        let mut derniere = std::time::Duration::MAX;
        for k in 0..12 {
            let entree = egui::RawInput {
                screen_rect: Some(ecran),
                time: Some(10.0 + 0.1 * f64::from(k)),
                ..Default::default()
            };
            let mut sortie = ctx.run_ui(entree, |ui| {
                let tete = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1280.0, 36.0));
                let peintre = ui.painter().clone();
                super::super::cadre::tache_en_tete(
                    ui,
                    &peintre,
                    tete,
                    Some((crate::commandes::Commande::Bilan, std::time::Duration::from_secs(3))),
                    1,
                );
            });
            sortie.textures_delta.clear();
            halo |= sortie.shapes.iter().any(
                |c| matches!(&c.shape, egui::Shape::Circle(r) if r.radius > 3.5 && r.fill != accent && r.fill.a() > 0),
            );
            derniere = derniere.min(delai(&sortie));
        }
        assert!(
            derniere <= super::TOURNE,
            "pendant une commande : une image dans {derniere:?}"
        );
        assert!(halo, "le point de la commande ne pulse pas");
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

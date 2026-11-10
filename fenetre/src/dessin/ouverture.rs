//! L'ouverture de la fenêtre : moins d'une seconde, une seule fois. Un grand V d'accent, avec sa lueur ; il se fend
//! en son milieu, et chaque branche glisse comme une porte en emportant sa moitié du fond, ce qui découvre le menu ;
//! puis le petit V du rail apparaît à sa place. Rien ne l'attend : `vanguard` a reçu ses premières commandes avant
//! la première image, et leurs réponses arrivent pendant qu'elle joue. Un clic ou une touche la saute.
//!
//! Le dessin ne dépend que du temps passé (`peindre`) : il s'essaie image par image et se rend en PNG (`captures`).
//! Les couleurs sont relues dans la palette à chaque image : un thème changé entre-temps est suivi.

use eframe::egui::{self, Color32, Context, Event, Id, Mesh, Order, Painter, Pos2, Rect, Sense, Stroke, pos2, vec2};

use super::{Palette, pal};

/// Le V seul, dont la lueur monte.
const V_SEUL: f32 = 0.25;
/// Les portes sont sorties de la fenêtre.
const PORTES: f32 = 0.8;
/// Le petit V du rail est là : l'ouverture est finie.
pub const FIN: f32 = 0.9;

/// Le côté du grand V : une part du plus petit côté de la fenêtre.
const PART_DU_COTE: f32 = 0.45;
/// L'angle de chaque branche avec la verticale (tangente de 22 degrés).
const PENTE: f32 = 0.404;
/// L'épaisseur d'une branche, en part de la hauteur du V.
const EPAISSEUR: f32 = 0.15;

pub struct Ouverture {
    /// L'heure d'egui à la première image : le temps de l'animation part de là, pas du lancement du programme.
    debut: Option<f64>,
    finie: bool,
}

impl Ouverture {
    pub fn nouvelle() -> Ouverture {
        Ouverture {
            debut: None,
            finie: false,
        }
    }

    /// À chaque image, avant les écrans : le temps passé depuis la première image, tant que l'ouverture dure ; ensuite
    /// toujours `None` (elle ne rejoue jamais). Un clic ou une touche la finit. Tant que les portes couvrent la
    /// fenêtre, la touche ne va pas plus loin (Échap ne ferait pas « Retour ») ; le clic, lui, est arrêté par le voile
    /// de `dessiner`, posé au-dessus de tout, qu'egui touche avant les boutons du dessous.
    pub fn avancer(&mut self, ctx: &Context) -> Option<f32> {
        if self.finie {
            return None;
        }
        let maintenant = ctx.input(|i| i.time);
        let debut = *self.debut.get_or_insert(maintenant);
        // Bornée à 0..=1 : l'ouverture finit à FIN, avant.
        let t = super::cadre::phase_f32(maintenant - debut);
        let geste = ctx.input_mut(|i| {
            let touche = |e: &Event| matches!(e, Event::Key { pressed: true, .. } | Event::Text(_));
            let geste = i.pointer.any_pressed() || i.events.iter().any(touche);
            if t < PORTES {
                i.events.retain(|e| !matches!(e, Event::Key { .. } | Event::Text(_)));
            }
            geste
        });
        if geste || t >= FIN {
            self.finie = true;
            ctx.data_mut(|d| d.remove::<f32>(id_v_du_rail()));
            return None;
        }
        ctx.data_mut(|d| d.insert_temp(id_v_du_rail(), part_du_petit_v(t)));
        Some(t)
    }
}

fn id_v_du_rail() -> Id {
    Id::unique("ouverture-v-du-rail")
}

/// Ce qui se voit du petit V du rail (1 : tout), lu par le rail à chaque image.
pub fn v_du_rail(ctx: &Context) -> f32 {
    ctx.data(|d| d.get_temp::<f32>(id_v_du_rail())).unwrap_or(1.0)
}

/// Le petit V du rail : caché sous les portes, puis en fondu de PORTES à FIN.
fn part_du_petit_v(t: f32) -> f32 {
    douce(((t - PORTES) / (FIN - PORTES)).clamp(0.0, 1.0))
}

/// Part d'avancement qui ralentit à la fin (ease-out cubique).
fn sortie(x: f32) -> f32 {
    let r = 1.0 - x.clamp(0.0, 1.0);
    1.0 - r * r * r
}

/// Départ et arrivée en douceur (smoothstep).
fn douce(x: f32) -> f32 {
    x * x * (3.0 - 2.0 * x)
}

/// Dessine l'image de l'instant `t` par-dessus tout le reste, avec un voile qui prend la souris : un clic sur les
/// portes ne touche pas le bouton du dessous. Plus rien après PORTES : seul le petit V du rail finit son fondu.
pub fn dessiner(ctx: &Context, t: f32) {
    if t >= PORTES {
        return;
    }
    let ecran = ctx.content_rect();
    egui::Area::new(Id::unique("ouverture"))
        .order(Order::Foreground)
        .fixed_pos(ecran.min)
        .constrain(false)
        .movable(false)
        .interactable(true)
        // Opaque dès la première image : le fondu d'apparition d'egui laisserait voir le menu à travers les portes.
        .fade_in(false)
        .show(ctx, |ui| {
            let (_, voile) = ui.allocate_exact_size(ecran.size(), Sense::click());
            voile.on_hover_cursor(egui::CursorIcon::Default);
            peindre(&ui.painter().with_clip_rect(ecran), ecran, t, pal());
        });
}

/// Une coordonnée en points posée sur un bord de pixel : les coupes des portes sont des ciseaux d'un pixel entier, sans
/// fondu, pour que les deux moitiés se touchent sans fente tant qu'elles sont jointes.
fn au_pixel(x: f32, ppp: f32) -> f32 {
    (x * ppp).round() / ppp
}

/// L'image de l'instant `t` (0 ≤ t < PORTES) sur `ecran`.
pub fn peindre(peintre: &Painter, ecran: Rect, t: f32, p: &Palette) {
    let ppp = peintre.pixels_per_point();
    // Le V seul : il finit de grandir et sa lueur monte ; puis les portes s'ouvrent, vite d'abord.
    let monte = sortie(t / V_SEUL);
    let ouvre = if t < V_SEUL {
        0.0
    } else {
        sortie((t - V_SEUL) / (PORTES - V_SEUL))
    };
    let hauteur = ecran.width().min(ecran.height()) * PART_DU_COTE * (0.96 + 0.04 * monte);
    let centre = ecran.center();
    let haut = au_pixel(centre.y - hauteur / 2.0, ppp);
    let milieu = au_pixel(centre.x, ppp);
    // Chaque porte emporte sa branche et sa lueur ; son bord intérieur atteint le bord de la fenêtre à PORTES.
    let course = ouvre * ecran.width() / 2.0;
    for gauche in [true, false] {
        let signe = if gauche { -1.0 } else { 1.0 };
        let dx = au_pixel(signe * course, ppp);
        let bord = milieu + dx;
        let porte = if gauche {
            Rect::from_min_max(ecran.min, pos2(bord, ecran.max.y))
        } else {
            Rect::from_min_max(pos2(bord, ecran.min.y), ecran.max)
        };
        if porte.width() <= 0.0 {
            continue;
        }
        let pp = peintre.with_clip_rect(porte);
        // Le fond déborde de la coupe : seul le ciseau fait le bord, net.
        pp.rect_filled(porte.expand(2.0), 0, p.fond);
        lueur(&pp, pos2(centre.x + dx, centre.y), hauteur, p.accent, monte);
        // La lumière qui passe par la fente, de plus en plus faible à mesure que les portes s'écartent.
        if ouvre > 0.0 {
            fente(&pp, bord, signe, ecran, p.accent, 1.0 - ouvre);
        }
        let branche = peintre.with_clip_rect(Rect::from_min_max(pos2(porte.min.x, haut), porte.max));
        let encre = p.accent.gamma_multiply(0.5 + 0.5 * sortie(t / 0.1));
        let (a, b) = branche_du_v(milieu + dx, haut, hauteur, gauche);
        branche.line_segment([a, b], Stroke::new(hauteur * EPAISSEUR, encre));
    }
}

/// L'axe d'une branche du V, prolongé au-delà du haut et du milieu : les ciseaux en font la coupe horizontale du
/// haut et la coupe verticale du milieu. Les bords extérieurs des deux branches se joignent au bas du V.
fn branche_du_v(milieu: f32, haut: f32, hauteur: f32, gauche: bool) -> (Pos2, Pos2) {
    let demi = hauteur * EPAISSEUR / 2.0;
    // Le bord extérieur rejoint le milieu à `haut + hauteur` ; l'axe, plus haut, de la demi-épaisseur portée sur la
    // verticale (demi / sinus de l'angle).
    let sinus = PENTE / (1.0 + PENTE * PENTE).sqrt();
    let y_axe = haut + hauteur - demi / sinus;
    let signe = if gauche { -1.0 } else { 1.0 };
    let pied = pos2(milieu, y_axe);
    // Vers le haut et l'extérieur, la pente de la branche ; prolongé d'une épaisseur en haut, et de deux en bas : le
    // bord extérieur n'atteint le milieu qu'à demi / tangente (2,5 demi-épaisseurs) au-delà du pied, et la fin du
    // trait couperait sinon la pointe du V.
    let dir = vec2(signe * PENTE, -1.0).normalized();
    let long = (y_axe - haut) / dir.y.abs();
    let marge = hauteur * EPAISSEUR;
    (pied + dir * (long + marge), pied - dir * (2.0 * marge))
}

/// Un halo doux autour du V : un disque dont l'accent s'efface vers le bord (couleurs prémultipliées, interpolées
/// par la carte graphique). `monte` : de 0 à 1 pendant que le V est seul.
fn lueur(peintre: &Painter, centre: Pos2, hauteur: f32, accent: Color32, monte: f32) {
    const COTES: u16 = 72;
    // Du centre au bord : l'intensité décroît en carré, assez d'anneaux pour que la pente ne se voie pas.
    const ANNEAUX: u16 = 5;
    if monte <= 0.0 {
        return;
    }
    let rayon = hauteur * 1.05;
    let mut m = Mesh::default();
    m.colored_vertex(centre, accent.gamma_multiply(0.30 * monte));
    for k in 1..=ANNEAUX {
        let r = f32::from(k) / f32::from(ANNEAUX);
        let couleur = accent.gamma_multiply((1.0 - r) * (1.0 - r) * 0.30 * monte);
        for i in 0..COTES {
            let a = std::f32::consts::TAU * f32::from(i) / f32::from(COTES);
            m.colored_vertex(centre + vec2(a.cos(), a.sin()) * rayon * r, couleur);
        }
    }
    let point = |k: u16, i: u16| 1 + u32::from(k - 1) * u32::from(COTES) + u32::from(i % COTES);
    for i in 0..COTES {
        m.add_triangle(0, point(1, i), point(1, i + 1));
        for k in 1..ANNEAUX {
            m.add_triangle(point(k, i), point(k + 1, i), point(k + 1, i + 1));
            m.add_triangle(point(k, i), point(k + 1, i + 1), point(k, i + 1));
        }
    }
    peintre.add(m);
}

/// La lumière au bord d'une porte qui s'ouvre : l'accent sur le bord, effacé vers l'intérieur.
fn fente(peintre: &Painter, bord: f32, signe: f32, ecran: Rect, accent: Color32, force: f32) {
    let large = 36.0;
    let vif = accent.gamma_multiply(0.45 * force);
    let interieur = bord - signe * large;
    let mut m = Mesh::default();
    m.colored_vertex(pos2(bord, ecran.min.y), vif);
    m.colored_vertex(pos2(bord, ecran.max.y), vif);
    m.colored_vertex(pos2(interieur, ecran.max.y), Color32::TRANSPARENT);
    m.colored_vertex(pos2(interieur, ecran.min.y), Color32::TRANSPARENT);
    m.add_triangle(0, 1, 2);
    m.add_triangle(0, 2, 3);
    peintre.add(m);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Une image sans fenêtre à l'heure `temps`, avec ses événements ; rend ce que l'ouverture a dit et ce qui a été
    /// peint.
    fn image(ctx: &Context, o: &mut Ouverture, temps: f64, evenements: Vec<Event>) -> (Option<f32>, usize) {
        let entree = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(800.0, 500.0))),
            time: Some(temps),
            events: evenements,
            ..Default::default()
        };
        let mut vu = None;
        let mut sortie = ctx.run_ui(entree, |ui| {
            let t = o.avancer(ui.ctx());
            if let Some(t) = t {
                dessiner(ui.ctx(), t);
            }
            vu = t;
        });
        sortie.textures_delta.clear();
        (vu, sortie.shapes.len())
    }

    /// Image par image, à 60 par seconde : elle dessine, finit avant une seconde, et après plus rien d'elle ;
    /// ni le temps ni un autre écran ne la relancent.
    #[test]
    fn finit_avant_une_seconde_et_ne_rejoue_pas() {
        let ctx = Context::default();
        let mut o = Ouverture::nouvelle();
        let debut = 12.5;
        let mut fin = None;
        for k in 0..120 {
            let temps = debut + f64::from(k) / 60.0;
            let (t, peint) = image(&ctx, &mut o, temps, Vec::new());
            if let Some(t) = t {
                assert!(fin.is_none(), "l'ouverture a repris après sa fin");
                // Les portes : bien visibles jusqu'à 0,6 s ; après, leurs derniers pixels sortent.
                if t < 0.6 {
                    assert!(peint > 0, "rien de peint à {t}");
                }
            } else {
                fin.get_or_insert(temps - debut);
                assert_eq!(peint, 0, "l'ouverture peint encore après sa fin");
                assert!((v_du_rail(&ctx) - 1.0).abs() < f32::EPSILON);
            }
        }
        let fin = fin.expect("l'ouverture ne finit pas");
        assert!(fin < 1.0, "finie après {fin} s");
        assert!(fin >= f64::from(FIN) - 0.02, "finie trop tôt : {fin} s");
    }

    #[test]
    fn un_clic_ou_une_touche_la_saute() {
        let ctx = Context::default();
        let clic = Event::PointerButton {
            pos: pos2(400.0, 250.0),
            button: egui::PointerButton::Primary,
            pressed: true,
            modifiers: egui::Modifiers::NONE,
        };
        let touche = Event::Key {
            key: egui::Key::Escape,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        };
        for (k, geste) in [vec![Event::PointerMoved(pos2(400.0, 250.0)), clic], vec![touche]]
            .into_iter()
            .enumerate()
        {
            // Une autre ouverture, plus tard : l'heure d'egui ne recule jamais.
            let debut = 1.0 + 10.0 * f64::from(super::super::n_f32(k));
            let mut o = Ouverture::nouvelle();
            assert!(image(&ctx, &mut o, debut, Vec::new()).0.is_some());
            assert!(image(&ctx, &mut o, debut + 0.1, Vec::new()).0.is_some());
            let (t, peint) = image(&ctx, &mut o, debut + 0.15, geste);
            assert_eq!((t, peint), (None, 0));
            assert!((v_du_rail(&ctx) - 1.0).abs() < f32::EPSILON);
            assert_eq!(image(&ctx, &mut o, debut + 0.2, Vec::new()).0, None);
        }
    }

    /// Le clic qui saute l'ouverture ne touche pas le bouton du dessous : pressé sur le voile, relâché une fois les
    /// portes parties, il n'est le clic de personne (un écran ne lance rien par surprise).
    #[test]
    fn le_clic_qui_la_saute_ne_touche_pas_le_dessous() {
        let ctx = Context::default();
        let mut o = Ouverture::nouvelle();
        let mut clique = false;
        let pos = pos2(400.0, 250.0);
        let bouton = |e: egui::PointerButton, presse: bool| Event::PointerButton {
            pos,
            button: e,
            pressed: presse,
            modifiers: egui::Modifiers::NONE,
        };
        let images = [
            (5.0, vec![]),
            (5.1, vec![Event::PointerMoved(pos)]),
            (5.15, vec![bouton(egui::PointerButton::Primary, true)]),
            (5.2, vec![bouton(egui::PointerButton::Primary, false)]),
            (5.3, vec![]),
        ];
        for (temps, evenements) in images {
            let entree = egui::RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(800.0, 500.0))),
                time: Some(temps),
                events: evenements,
                ..Default::default()
            };
            ctx.run_ui(entree, |ui| {
                let t = o.avancer(ui.ctx());
                let r = ui.allocate_rect(ui.max_rect(), Sense::click());
                clique |= r.clicked();
                if let Some(t) = t {
                    dessiner(ui.ctx(), t);
                }
            })
            .textures_delta
            .clear();
        }
        assert_eq!(o.avancer(&ctx), None, "le clic n'a pas sauté l'ouverture");
        assert!(!clique, "le clic a traversé les portes");
    }

    /// Une touche tapée sous les portes s'arrête là : elle ne va pas aux écrans (Échap y ferait « Retour »).
    #[test]
    fn une_touche_sous_les_portes_ne_passe_pas() {
        let ctx = Context::default();
        let mut o = Ouverture::nouvelle();
        let _ = image(&ctx, &mut o, 3.0, Vec::new());
        let entree = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(800.0, 500.0))),
            time: Some(3.1),
            events: vec![Event::Key {
                key: egui::Key::Escape,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            }],
            ..Default::default()
        };
        let mut passee = true;
        ctx.run_ui(entree, |ui| {
            let _ = o.avancer(ui.ctx());
            passee = ui.input(|i| i.key_pressed(egui::Key::Escape));
        })
        .textures_delta
        .clear();
        assert!(!passee);
    }

    /// Le petit V du rail : caché sous les portes, en fondu ensuite, entier à la fin ; les portes s'ouvrent sans
    /// revenir en arrière.
    #[test]
    fn le_petit_v_et_les_portes_suivent_le_temps() {
        assert!(part_du_petit_v(0.0) < f32::EPSILON);
        assert!(part_du_petit_v(PORTES) < f32::EPSILON);
        let mi = part_du_petit_v(f32::midpoint(PORTES, FIN));
        assert!(mi > 0.2 && mi < 0.8, "{mi}");
        assert!((part_du_petit_v(FIN) - 1.0).abs() < f32::EPSILON);
        let mut avant = -1.0;
        for k in 0..=100 {
            let x = sortie(super::super::n_f32(k) / 100.0);
            assert!(x >= avant);
            avant = x;
        }
        assert!((sortie(1.0) - 1.0).abs() < f32::EPSILON);
    }

    /// Les bords extérieurs des deux branches se joignent au bas du V, sur le milieu.
    #[test]
    fn les_branches_se_joignent_au_milieu() {
        let (h, b) = (100.0, 400.0);
        for gauche in [true, false] {
            let (a, pied) = branche_du_v(500.0, h, b, gauche);
            let dir = (pied - a).normalized();
            // Le bord extérieur : l'axe décalé d'une demi-épaisseur vers le bas.
            let normale = if gauche {
                vec2(-dir.y, dir.x)
            } else {
                vec2(dir.y, -dir.x)
            };
            let bord = a + normale * (b * EPAISSEUR / 2.0);
            let k = (500.0 - bord.x) / dir.x;
            let y = bord.y + dir.y * k;
            assert!((y - (h + b)).abs() < 0.5, "{gauche} : {y}");
        }
    }
}

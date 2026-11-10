//! Le dessin : le seul endroit qui connaît egui et eframe. Le reste de la fenêtre (l'état dans `appli`, les commandes,
//! le lanceur, la lecture des sorties) n'en dépend pas : changer de toile ne toucherait qu'ici (un essai le garde).
//! Rien d'ici ne lance un programme : chaque geste passe par `Appli` (`demander`, `arreter`, `saisir`, et pour un
//! changement `proposer` puis `accepter`).

mod bilan;
mod cadre;
mod coulisses;
mod defile;
mod demarrage;
mod ecrans;
mod icones;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use eframe::egui::{
    self, Color32, FontData, FontDefinitions, FontFamily, FontId, Frame, Margin, RichText, Stroke, Ui, vec2,
};

use crate::appli::Appli;
use crate::lanceur::Programme;

/// Les couleurs d'un thème (les mêmes que la maquette acceptée).
pub struct Palette {
    pub fond: Color32,
    pub surface: Color32,
    pub s2: Color32,
    pub s3: Color32,
    pub encre: Color32,
    pub doux: Color32,
    pub discret: Color32,
    pub trait_: Color32,
    pub accent: Color32,
    pub sur_vif: Color32,
    pub grave: Color32,
    pub moyen: Color32,
    pub jaune: Color32,
    pub bon: Color32,
    pub gris: Color32,
}

const fn c(r: u8, g: u8, b: u8) -> Color32 {
    Color32::from_rgb(r, g, b)
}

const SOMBRE: Palette = Palette {
    fond: c(0, 0, 0),
    surface: c(0x0a, 0x0c, 0x0f),
    s2: c(0x12, 0x16, 0x1b),
    s3: c(0x1a, 0x20, 0x27),
    encre: c(0xe8, 0xee, 0xf4),
    doux: c(0x93, 0xa1, 0xaf),
    discret: c(0x5f, 0x6b, 0x77),
    // rgba(220, 235, 255, 0.08), prémultiplié.
    trait_: Color32::from_rgba_premultiplied(17, 18, 20, 20),
    accent: c(0x38, 0xc6, 0xf4),
    sur_vif: c(0x02, 0x10, 0x18),
    grave: c(0xf0, 0x55, 0x5a),
    moyen: c(0xf0, 0x8c, 0x2e),
    jaune: c(0xd9, 0xc9, 0x4a),
    bon: c(0x3f, 0xb9, 0x50),
    gris: c(0x5f, 0x6b, 0x77),
};

const CLAIR: Palette = Palette {
    fond: c(0xf3, 0xf5, 0xf7),
    surface: c(0xff, 0xff, 0xff),
    s2: c(0xee, 0xf1, 0xf4),
    s3: c(0xe3, 0xe8, 0xed),
    encre: c(0x0b, 0x15, 0x20),
    doux: c(0x4a, 0x58, 0x68),
    discret: c(0x6b, 0x77, 0x85),
    // rgba(10, 25, 40, 0.10), prémultiplié.
    trait_: Color32::from_rgba_premultiplied(1, 3, 4, 26),
    accent: c(0x0a, 0x7f, 0xb6),
    sur_vif: c(0xff, 0xff, 0xff),
    grave: c(0xc6, 0x28, 0x28),
    moyen: c(0xc2, 0x41, 0x0c),
    jaune: c(0xa1, 0x62, 0x07),
    bon: c(0x15, 0x80, 0x3d),
    gris: c(0x94, 0xa3, 0xb8),
};

static THEME_CLAIR: AtomicBool = AtomicBool::new(false);

/// La palette du thème montré.
pub fn pal() -> &'static Palette {
    if THEME_CLAIR.load(Ordering::Relaxed) {
        &CLAIR
    } else {
        &SOMBRE
    }
}

/// Mélange deux couleurs (`t` : la part de `a`).
pub fn melange(a: Color32, b: Color32, t: f32) -> Color32 {
    let m = |x: u8, y: u8| octet(f32::from(x) * t + f32::from(y) * (1.0 - t));
    Color32::from_rgb(m(a.r(), b.r()), m(a.g(), b.g()), m(a.b(), b.b()))
}

// raison : une composante de couleur, déjà bornée à 0..=255 par clamp ; aucune conversion de std ne le fait sans perte.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn octet(x: f32) -> u8 {
    x.round().clamp(0.0, 255.0) as u8
}

/// Un compte en nombre à virgule, pour les mesures (borné : aucun écran n'a 65 535 traits).
pub fn n_f32(n: usize) -> f32 {
    f32::from(u16::try_from(n).unwrap_or(u16::MAX))
}

/// Une mesure en compte entier, bornée à 0..=10 000.
// raison : une mesure de dessin déjà bornée par clamp ; la conversion ne peut ni déborder ni changer de signe.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn f32_n(x: f32) -> usize {
    x.clamp(0.0, 10_000.0) as usize
}

pub fn police(taille: f32) -> FontId {
    FontId::new(taille, FontFamily::Proportional)
}

pub fn moyenne(taille: f32) -> FontId {
    FontId::new(taille, FontFamily::Name("m".into()))
}

pub fn mono(taille: f32) -> FontId {
    FontId::new(taille, FontFamily::Monospace)
}

pub fn texte(t: &str, taille: f32, couleur: Color32) -> RichText {
    RichText::new(t).size(taille).color(couleur)
}

/// Une carte : surface, bord fin, coins ronds.
pub fn carte<R>(ui: &mut Ui, marge: i8, rayon: u8, f: impl FnOnce(&mut Ui) -> R) -> R {
    Frame::new()
        .fill(pal().surface)
        .stroke(Stroke::new(1.0, pal().trait_))
        .corner_radius(rayon)
        .inner_margin(Margin::same(marge))
        .show(ui, f)
        .inner
}

/// La durée du survol : assez courte pour suivre la souris, assez longue pour que l'œil voie un fondu.
const DUREE_SURVOL: f32 = 0.12;

/// La part de survol d'un élément, de 0 à 1, qui glisse en `DUREE_SURVOL` : la couleur change en douceur, la taille
/// jamais (un bouton qui bouge sous la souris fait brouillon).
pub fn survol(ui: &Ui, id: egui::Id, survole: bool) -> f32 {
    ui.ctx()
        .animate_bool_with_time(id.with("survol"), survole, DUREE_SURVOL)
}

/// La part de survol d'un bouton d'egui, dessiné avant qu'on sache s'il est survolé : son état à l'image d'avant
/// (même identifiant), et s'il est pressé. Le fondu demande lui-même les images qui suivent.
fn survol_bouton(ui: &Ui, actif: bool) -> (f32, bool) {
    let id = ui.next_auto_id();
    let avant = ui.ctx().read_response(id);
    let survole = actif && avant.as_ref().is_some_and(egui::Response::hovered);
    let presse = actif && avant.as_ref().is_some_and(egui::Response::is_pointer_button_down_on);
    (survol(ui, id, survole), presse)
}

/// Le contour d'un bouton survolé : le trait fin du repos qui glisse vers l'accent, adouci.
fn bord_survole(p: &Palette, t: f32) -> Color32 {
    p.trait_.lerp_to_gamma(p.accent.gamma_multiply(0.7), t)
}

/// Un bouton ; `actif` faux : grisé, sans effet (un geste qui n'existe pas encore). Au survol, le fond s'éclaire
/// et le contour prend l'accent, en fondu ; pressé, il fonce un peu.
pub fn bouton(ui: &mut Ui, t: &str, plein: bool, actif: bool) -> egui::Response {
    let p = pal();
    let (s, presse) = survol_bouton(ui, actif);
    let (fond, encre, bord) = if plein {
        let fond = if presse {
            melange(p.accent, p.fond, 0.85)
        } else {
            melange(p.accent, p.encre, 1.0 - 0.16 * s)
        };
        (fond, p.sur_vif, fond)
    } else {
        let fond = if presse { p.s3 } else { p.s2.gamma_multiply(s) };
        (fond, p.encre, bord_survole(p, s))
    };
    let r = ui.add_enabled(
        actif,
        egui::Button::new(RichText::new(t).font(moyenne(13.0)).color(encre))
            .fill(fond)
            .stroke(Stroke::new(1.0, bord))
            .corner_radius(10)
            .min_size(vec2(0.0, 36.0)),
    );
    if actif {
        r.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        r
    }
}

/// Un petit bouton (Retour, Voir la correction…) : même survol en fondu que `bouton`.
pub fn petit(ui: &mut Ui, t: &str, actif: bool) -> egui::Response {
    let p = pal();
    let (s, presse) = survol_bouton(ui, actif);
    let fond = if !actif {
        Color32::TRANSPARENT
    } else if presse {
        melange(p.s3, p.fond, 0.7)
    } else {
        p.s2.lerp_to_gamma(p.s3, s)
    };
    ui.add_enabled(
        actif,
        egui::Button::new(texte(t, 13.0, if actif { p.encre } else { p.doux }))
            .fill(fond)
            .stroke(Stroke::new(1.0, if actif { bord_survole(p, s) } else { p.trait_ }))
            .corner_radius(8)
            .min_size(vec2(0.0, 32.0)),
    )
}

pub fn titre_section(ui: &mut Ui, t: &str, n: Option<usize>) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(t).font(moyenne(16.0)).color(pal().encre));
        if let Some(n) = n {
            ui.label(RichText::new(n.to_string()).font(mono(12.0)).color(pal().discret));
        }
    });
    ui.add_space(4.0);
}

/// Le titre d'un écran et sa phrase.
pub fn entete(ui: &mut Ui, titre: &str, sous: &str) {
    ui.label(RichText::new(titre).font(moyenne(28.0)).color(pal().encre));
    if !sous.is_empty() {
        ui.label(texte(sous, 14.0, pal().doux));
    }
}

/// Largeur supposée des boutons tant qu'aucune image ne l'a mesurée.
const BOUTONS_AU_DEPART: f32 = 240.0;

/// Un texte à gauche, des boutons à droite sur la même rangée. Les boutons gardent leur largeur (mesurée à l'image
/// d'avant) et le texte va à la ligne dans le reste : placé d'abord sans borne, une longue phrase prenait toute la
/// rangée et poussait les boutons hors de la carte. `cle` : propre à la rangée, pour garder sa mesure.
pub fn texte_et_boutons(ui: &mut Ui, cle: &str, gauche: impl FnOnce(&mut Ui), droite: impl FnOnce(&mut Ui)) {
    let id = ui.scope_id().with(("largeur-boutons", cle));
    let boutons = ui.ctx().data(|d| d.get_temp::<f32>(id)).unwrap_or(BOUTONS_AU_DEPART);
    ui.horizontal(|ui| {
        let ecart = ui.spacing().item_spacing.x;
        let reste = (ui.available_width() - boutons - 2.0 * ecart).max(160.0);
        ui.vertical(|ui| {
            ui.set_max_width(reste);
            gauche(ui);
        });
        let mesure = ui
            .with_layout(egui::Layout::right_to_left(egui::Align::Center), droite)
            .response
            .rect
            .width();
        if (mesure - boutons).abs() > 0.5 {
            ui.ctx().data_mut(|d| d.insert_temp(id, mesure));
            // Les boutons ont changé de largeur (Lancer → Arrêter) : cette image est refaite, sans saut visible.
            ui.ctx().request_discard("largeur des boutons");
        }
    });
}

fn polices(ctx: &egui::Context) {
    let mut f = FontDefinitions::empty();
    for (nom, octets) in [
        ("inter", &include_bytes!("../../polices/Inter-Regular.ttf")[..]),
        ("inter-m", &include_bytes!("../../polices/Inter-Medium.ttf")[..]),
        ("mono", &include_bytes!("../../polices/JetBrainsMono-Regular.ttf")[..]),
    ] {
        f.font_data.insert(nom.into(), Arc::new(FontData::from_static(octets)));
    }
    // Chaque famille se replie sur les deux autres polices pour un signe qui lui manque.
    f.families
        .insert(FontFamily::Proportional, vec!["inter".into(), "mono".into()]);
    f.families
        .insert(FontFamily::Monospace, vec!["mono".into(), "inter".into()]);
    f.families.insert(
        FontFamily::Name("m".into()),
        vec!["inter-m".into(), "inter".into(), "mono".into()],
    );
    ctx.set_fonts(f);
}

/// Applique le thème montré.
pub fn appliquer_theme(ctx: &egui::Context, sombre: bool) {
    THEME_CLAIR.store(!sombre, Ordering::Relaxed);
    let p = pal();
    ctx.set_visuals(if sombre {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    });
    ctx.global_style_mut(|s| {
        s.visuals.panel_fill = p.fond;
        s.visuals.window_fill = p.surface;
        s.visuals.override_text_color = Some(p.encre);
        s.visuals.selection.bg_fill = p.accent.gamma_multiply(0.35);
        s.visuals.text_cursor.stroke = Stroke::new(2.0, p.accent);
        s.spacing.item_spacing = vec2(8.0, 8.0);
        meme_contour_au_survol(&mut s.visuals);
    });
}

/// Un bouton garde sa taille sous la souris. egui retire de la marge intérieure l'épaisseur du contour de l'état
/// (aucun au repos, 1 point survolé ou pressé), pour qu'un contour qui apparaît ne déplace rien ; mais nos
/// boutons imposent leur propre contour de 1 point dans tous les états, si bien que seule la marge bougeait :
/// 2 points de moins en largeur au survol. Le même contour pour chaque état garde la même marge ; au repos, il
/// reste transparent, donc invisible.
fn meme_contour_au_survol(v: &mut egui::Visuals) {
    let w = &mut v.widgets;
    for e in [&mut w.inactive, &mut w.hovered, &mut w.active, &mut w.open] {
        e.bg_stroke.width = 1.0;
        e.expansion = 0.0;
    }
}

struct Fenetre {
    appli: Appli,
    /// La poignée de main avec `vanguard` : dite une fois, à la première image.
    annoncer: bool,
    sombre_applique: bool,
}

impl eframe::App for Fenetre {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        self.appli.avancer();
        if veut_revenir(ui.ctx()) {
            self.appli.revenir();
        }
        if self.sombre_applique != self.appli.sombre {
            appliquer_theme(ui.ctx(), self.appli.sombre);
            self.sombre_applique = self.appli.sombre;
        }
        cadre::tout(&mut self.appli, ui);
        if self.annoncer {
            self.annoncer = false;
            annoncer_ouverte();
        }
        let delai = if self.appli.en_cours().is_some() { 33 } else { 100 };
        ui.ctx().request_repaint_after(Duration::from_millis(delai));
    }
}

/// Alt+←, le bouton Précédent de la souris, ou Échap quand rien n'a le curseur (Échap dans la console la quitte
/// d'abord) : comme Échap dans les menus du terminal.
fn veut_revenir(ctx: &egui::Context) -> bool {
    let libre = ctx.memory(|m| m.focused().is_none());
    ctx.input_mut(|i| {
        i.consume_key(egui::Modifiers::ALT, egui::Key::ArrowLeft)
            || i.pointer.button_pressed(egui::PointerButton::Extra1)
            || (libre && i.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
    })
}

/// Dit à `vanguard`, qui attend sur notre sortie, que la fenêtre s'est ouverte : il ne montre pas son menu. Rien
/// d'autre n'est jamais écrit sur la sortie, qui devient aussitôt le néant (`sortie`) : `vanguard` va fermer le
/// tuyau, et une écriture de plus ne doit pas faire tomber la fenêtre.
fn annoncer_ouverte() {
    use std::io::Write;
    let mut s = std::io::stdout();
    let _ = s.write_all(b"vanguard-fenetre:ouverte\n");
    let _ = s.flush();
    let _ = crate::sortie::vers_le_neant();
}

/// Ouvre la fenêtre et rend la main quand elle se ferme.
pub fn ouvrir(programme: Result<Programme, String>, depuis_vanguard: bool) -> Result<(), String> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Vanguard")
            .with_app_id("vanguard")
            .with_inner_size([1440.0, 900.0])
            .with_min_inner_size([960.0, 640.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Vanguard",
        options,
        Box::new(move |cc| {
            polices(&cc.egui_ctx);
            let sombre = cc.egui_ctx.system_theme() != Some(egui::Theme::Light);
            appliquer_theme(&cc.egui_ctx, sombre);
            let ctx = cc.egui_ctx.clone();
            let mut appli = Appli::nouvelle(programme, Arc::new(move || ctx.request_repaint()));
            appli.sombre = sombre;
            Ok(Box::new(Fenetre {
                appli,
                annoncer: depuis_vanguard,
                sombre_applique: sombre,
            }))
        }),
    )
    .map_err(|e| crate::nettoyage::nom(&e.to_string(), 200))
}

#[cfg(test)]
mod tests {
    use eframe::egui;

    /// Mesure pour de vrai, image par image sans fenêtre, un bouton au repos puis sous la souris.
    fn mesurer(regle: bool) -> (egui::Vec2, egui::Vec2) {
        let ctx = egui::Context::default();
        super::polices(&ctx);
        if regle {
            ctx.global_style_mut(|s| super::meme_contour_au_survol(&mut s.visuals));
        }
        let image = |souris: Option<egui::Pos2>| {
            let mut entree = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(400.0, 200.0))),
                ..Default::default()
            };
            if let Some(p) = souris {
                entree.events.push(egui::Event::PointerMoved(p));
            }
            let mut vu = None;
            // Pas de carte graphique ici : les textures (polices) préparées sont jetées, comme egui le demande.
            ctx.run_ui(entree, |ui| {
                let r = super::petit(ui, "← Retour", true);
                vu = Some((r.rect, r.hovered()));
            })
            .textures_delta
            .clear();
            vu.unwrap()
        };
        let (repos, _) = image(None);
        let _ = image(Some(repos.center()));
        let (survole, sous_la_souris) = image(Some(repos.center()));
        assert!(
            sous_la_souris,
            "la souris n'est pas sur le bouton : l'essai ne mesure rien"
        );
        (repos.size(), survole.size())
    }

    #[test]
    fn un_bouton_garde_sa_taille_sous_la_souris() {
        let (repos, survole) = mesurer(true);
        assert_eq!(repos, survole);
    }

    /// Le fondu lit l'état du bouton à l'image d'avant par l'identifiant qu'egui lui donnera : s'il en changeait,
    /// le survol ne s'allumerait plus, sans rien casser d'autre. Puis le fondu monte bien de 0 à 1 sous la souris.
    #[test]
    fn le_fondu_suit_le_bouton_survole() {
        let ctx = egui::Context::default();
        super::polices(&ctx);
        let mut temps = 0.0;
        let mut image = |souris: Option<egui::Pos2>| {
            temps += 0.05;
            let mut entree = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(400.0, 200.0))),
                time: Some(temps),
                ..Default::default()
            };
            if let Some(p) = souris {
                entree.events.push(egui::Event::PointerMoved(p));
            }
            let mut vu = None;
            ctx.run_ui(entree, |ui| {
                let prevu = ui.next_auto_id();
                let (part, _) = super::survol_bouton(ui, true);
                let r = super::petit(ui, "← Retour", true);
                assert_eq!(prevu, r.id, "egui ne nomme plus le bouton comme prévu");
                vu = Some((r.rect, part));
            })
            .textures_delta
            .clear();
            vu.unwrap()
        };
        let (zone, part) = image(None);
        assert!(part < f32::EPSILON);
        let mut parts = Vec::new();
        for _ in 0..8 {
            parts.push(image(Some(zone.center())).1);
        }
        assert!(parts.windows(2).all(|w| w[1] >= w[0]), "{parts:?}");
        assert!(parts[1] > 0.0 && parts[1] < 1.0, "pas de fondu : {parts:?}");
        assert!((parts[7] - 1.0).abs() < f32::EPSILON, "{parts:?}");
    }

    /// Le témoin : sans le réglage, la même mesure voit le bouton rétrécir (sinon l'essai d'au-dessus ne prouve rien).
    #[test]
    fn sans_le_reglage_le_bouton_retrecit() {
        let (repos, survole) = mesurer(false);
        assert!(survole.x < repos.x, "{repos:?} → {survole:?}");
    }

    /// egui et eframe ne sont nommés que dans `dessin/` : le reste ne dépend pas de la toile.
    #[test]
    fn la_toile_reste_dans_dessin() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut a_voir = vec![src.clone()];
        let mut vus = 0;
        while let Some(d) = a_voir.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    if p != src.join("dessin") {
                        a_voir.push(p);
                    }
                } else if p.extension().is_some_and(|x| x == "rs") {
                    vus += 1;
                    let t = std::fs::read_to_string(&p).unwrap();
                    for mot in ["egui", "eframe"] {
                        let ok = t
                            .lines()
                            .filter(|l| l.contains(mot))
                            .all(|l| l.trim_start().starts_with("//"));
                        assert!(ok, "{} nomme {mot}", p.display());
                    }
                }
            }
        }
        assert!(vus >= 8, "{vus} fichiers seulement");
    }

    /// Pour de vrai, sans rien montrer : dans le bac à sable, la fenêtre joint son bureau (Wayland ou X11), en reçoit
    /// les premiers événements (le clavier et son plan de touches) et ouvre OpenGL comme eframe (EGL : la bibliothèque
    /// du pilote, ses fichiers de glvnd, /dev/dri ou /dev/nvidia*), sans créer de fenêtre ni de surface. Un fichier
    /// du système que le bac refuserait et dont le dessin a besoin ferait échouer ici. Dans un processus d'essai à part,
    /// comme celui du relais : le bac ne se retire pas. Sauté sans bureau (la CI) ou sans Landlock.
    #[cfg(target_os = "linux")]
    #[test]
    fn le_bureau_et_opengl_s_ouvrent_dans_le_bac() {
        const ESSAI: &str = "VANGUARD_FENETRE_ESSAI_BUREAU";
        if std::env::var_os(ESSAI).is_some() {
            return dans_le_bac();
        }
        let nom = "dessin::tests::le_bureau_et_opengl_s_ouvrent_dans_le_bac";
        let sortie = std::process::Command::new(std::env::current_exe().unwrap())
            .args([nom, "--exact", "--nocapture", "--test-threads=1"])
            .env(ESSAI, "1")
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        let texte = String::from_utf8_lossy(&sortie.stdout).into_owned() + &String::from_utf8_lossy(&sortie.stderr);
        if let Some(raison) = texte
            .lines()
            .find_map(|l| l.split_once("BUREAU-SAUTÉ ").map(|(_, r)| r))
        {
            return crate::essais::sauter(raison);
        }
        assert!(sortie.status.success() && texte.contains("BUREAU-OK"), "{texte}");
    }

    #[cfg(target_os = "linux")]
    // raison : glutin (EGL) et glow n'ont que des appels unsafe ; ils ne servent ici qu'à l'essai.
    #[allow(unsafe_code)]
    fn dans_le_bac() {
        use eframe::glow::{self, HasContext};
        use glutin::config::ConfigTemplateBuilder;
        use glutin::context::ContextAttributesBuilder;
        use glutin::display::GlDisplay;
        use winit::platform::pump_events::EventLoopExtPumpEvents;
        use winit::raw_window_handle::HasDisplayHandle;

        struct Rien;
        impl winit::application::ApplicationHandler for Rien {
            fn resumed(&mut self, _: &winit::event_loop::ActiveEventLoop) {}
            fn window_event(
                &mut self,
                _: &winit::event_loop::ActiveEventLoop,
                _: winit::window::WindowId,
                _: winit::event::WindowEvent,
            ) {
            }
        }

        if crate::bac_a_sable::bureau() == crate::bac_a_sable::Bureau::Aucun {
            println!("BUREAU-SAUTÉ pas de bureau (ni WAYLAND_DISPLAY ni DISPLAY)");
            return;
        }
        assert!(crate::bac_a_sable::sans_nouveaux_droits());
        if let Err(e) = crate::bac_a_sable::poser() {
            println!("BUREAU-SAUTÉ Landlock absent ({e})");
            return;
        }
        let mut constructeur = winit::event_loop::EventLoop::builder();
        // Le même réglage pour les deux bureaux : l'essai ne tourne pas sur le fil principal.
        winit::platform::wayland::EventLoopBuilderExtWayland::with_any_thread(&mut constructeur, true);
        let mut boucle = constructeur.build().expect("le bureau ne s'ouvre pas dans le bac");
        for _ in 0..3 {
            let _ = boucle.pump_app_events(Some(std::time::Duration::from_millis(100)), &mut Rien);
        }
        let brut = boucle.display_handle().unwrap().as_raw();
        // SAFETY: l'affichage vient de la boucle de winit, vivante jusqu'à la fin de l'essai, après tout ce qu'EGL crée.
        let affichage =
            unsafe { glutin::api::egl::display::Display::new(brut) }.expect("EGL ne s'ouvre pas dans le bac");
        // SAFETY: un modèle de configuration par défaut, sans pointeur ; l'affichage est vivant.
        let config = unsafe { affichage.find_configs(ConfigTemplateBuilder::new().build()) }
            .expect("configurations d'EGL")
            .next()
            .expect("aucune configuration d'EGL");
        // SAFETY: des attributs par défaut, sans fenêtre ; la configuration vient de cet affichage.
        let contexte = unsafe { affichage.create_context(&config, &ContextAttributesBuilder::new().build(None)) }
            .expect("contexte d'OpenGL");
        let contexte = contexte.make_current_surfaceless().expect("contexte courant");
        // SAFETY: les fonctions viennent du contexte courant sur ce fil, qui vit jusqu'après leur dernier appel.
        let gl = unsafe { glow::Context::from_loader_function_cstr(|s| affichage.get_proc_address(s)) };
        // SAFETY: glGetString(GL_VERSION) sur le contexte courant ; la valeur n'est pas montrée (elle nomme la carte).
        let version = unsafe { gl.get_parameter_string(glow::VERSION) };
        assert_ne!(version, "");
        drop(gl);
        drop(contexte);
        println!("BUREAU-OK");
    }
}

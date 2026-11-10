//! Le dessin : le seul endroit qui connaît egui et eframe. Le reste de la fenêtre (l'état dans `appli`, les commandes,
//! le lanceur, la lecture des sorties) n'en dépend pas : changer de toile ne toucherait qu'ici (un essai le garde).
//! Rien d'ici ne lance un programme : chaque geste passe par `Appli` (`demander`, `arreter`, `saisir`).

mod bilan;
mod cadre;
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

/// Un bouton ; `actif` faux : grisé, sans effet (un geste qui n'existe pas encore).
pub fn bouton(ui: &mut Ui, t: &str, plein: bool, actif: bool) -> egui::Response {
    let p = pal();
    let (fond, encre, bord) = if plein {
        (p.accent, p.sur_vif, p.accent)
    } else {
        (Color32::TRANSPARENT, p.encre, p.trait_)
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

pub fn petit(ui: &mut Ui, t: &str, actif: bool) -> egui::Response {
    let p = pal();
    ui.add_enabled(
        actif,
        egui::Button::new(texte(t, 13.0, if actif { p.encre } else { p.doux }))
            .fill(if actif { p.s2 } else { Color32::TRANSPARENT })
            .stroke(Stroke::new(1.0, p.trait_))
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
    });
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

/// Dit à `vanguard`, qui attend sur notre sortie, que la fenêtre s'est ouverte : il ne montre pas son menu. Rien
/// d'autre n'est jamais écrit sur la sortie.
fn annoncer_ouverte() {
    use std::io::Write;
    let mut s = std::io::stdout();
    let _ = s.write_all(b"vanguard-fenetre:ouverte\n");
    let _ = s.flush();
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
}

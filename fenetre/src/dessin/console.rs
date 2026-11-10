//! La bande Console, sous la barre : l'en-tête (état, Arrêter, filtres, recherche, Coulisses, Déplier), les places de
//! la console (lignes simples et blocs de commande, `console::Console::places`), la saisie et sa liste de
//! suggestions. Rien ici ne lance autre chose qu'une commande de la liste fermée, par `Appli::demander` ou
//! `Appli::saisir` : jamais un changement, jamais un argument libre.

use std::sync::Arc;
use std::time::Duration;

use eframe::egui::text::{LayoutJob, TextFormat, TextWrapping};
use eframe::egui::{
    self, Align, Align2, Color32, FontId, Frame, Galley, Id, Key, Label, Modifiers, Rect, RichText, ScrollArea, Sense,
    Stroke, StrokeKind, TextEdit, Ui, UiBuilder, pos2, vec2,
};

use super::defile::HAUTEUR_LIGNE;
use super::{f32_n, melange, mono, moyenne, n_f32, pal, police, survol};
use crate::appli::{Appli, Ton, ecran_de};
use crate::commandes::{self, Commande, Lancement};
use crate::console::{Bloc, Entree, Etat, Filtre, Marque, Place};

/// Lignes montrées, repliée et dépliée ; la plus petite hauteur qu'on peut tirer.
pub const LIGNES_REPLIEE: usize = 6;
pub const LIGNES_DEPLIEE: usize = 16;
const LIGNES_MIN: usize = 3;
/// L'en-tête, le vide sous la dernière place, la saisie.
const TETE: f32 = 36.0;
const DESSOUS: f32 = 12.0;
const SAISIE: f32 = 44.0;
/// Les colonnes, depuis le bord gauche : l'heure, la source (ou l'état d'un bloc), le texte ; la marge à droite.
const X_HEURE: f32 = 32.0;
const X_SOURCE: f32 = 116.0;
const X_TEXTE: f32 = 220.0;
const DROITE: f32 = 32.0;
/// Une suggestion : son nom et sa rubrique, puis sa description.
const HAUTEUR_SUGGESTION: f32 = 42.0;

/// L'état de la bande, gardé le temps de la session dans la mémoire d'egui (jamais écrit sur le disque). Des
/// réglages indépendants (une liste masquée, un mode historique, la souris sur la liste…) : pas une machine à états.
#[derive(Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
struct Bande {
    /// Lignes choisies (Déplier, ou le bord tiré) ; 0 : la hauteur repliée.
    lignes: usize,
    /// La hauteur pendant qu'on tire le bord.
    tiree: f32,
    filtre: Filtre,
    /// Ouverte par Ctrl+F : le texte cherché.
    cherche: Option<String>,
    /// La suggestion choisie avec ↑ ↓ (rien n'est lancé sans Entrée ou un clic sur elle).
    choix: Option<usize>,
    /// La liste fermée par Échap, jusqu'à la frappe suivante.
    masquee: bool,
    /// La saisie à l'image d'avant : une frappe rouvre la liste.
    vue: String,
    /// Ctrl+R : la saisie cherche dans l'historique ; Entrée reprend la saisie choisie, sans la lancer.
    historique: bool,
    /// La souris était sur la liste : elle reste ouverte le temps du clic (le champ perd le curseur au clic).
    sur_la_liste: bool,
    /// La dernière place vue en bas ; celles d'après sont nouvelles.
    vu: u64,
    montre: usize,
    descendre: bool,
}

fn id_bande() -> Id {
    Id::unique("console-bande")
}

fn bande_de(ctx: &egui::Context) -> Bande {
    ctx.data(|d| d.get_temp::<Bande>(id_bande())).unwrap_or_default()
}

fn garder(ctx: &egui::Context, b: Bande) {
    ctx.data_mut(|d| d.insert_temp(id_bande(), b));
}

/// Pour les captures : la hauteur (en lignes), le filtre et la recherche ouverte, comme si on les avait choisis.
#[cfg(test)]
pub(super) fn regler(ctx: &egui::Context, lignes: usize, filtre: Filtre, cherche: Option<&str>) {
    let mut b = bande_de(ctx);
    b.lignes = lignes;
    b.filtre = filtre;
    b.cherche = cherche.map(str::to_owned);
    garder(ctx, b);
}

/// Les lignes que la bande montre, bornées par la hauteur de la fenêtre (l'écran garde au moins 240 points).
pub fn lignes(ctx: &egui::Context) -> usize {
    let haut = ctx.content_rect().height() - 64.0 - TETE - DESSOUS - SAISIE - 240.0;
    let max = f32_n(haut / HAUTEUR_LIGNE).max(LIGNES_REPLIEE);
    let b = bande_de(ctx);
    let n = if b.lignes == 0 { LIGNES_REPLIEE } else { b.lignes };
    n.clamp(LIGNES_MIN, max)
}

/// La hauteur de la bande pour `n` lignes.
pub fn hauteur(n: usize) -> f32 {
    TETE + DESSOUS + HAUTEUR_LIGNE * n_f32(n) + SAISIE
}

/// La bande entière dans `ui.max_rect()`.
pub fn bande(appli: &mut Appli, ui: &mut Ui, montrees: usize) {
    let p = pal();
    let r = ui.max_rect();
    let mut b = bande_de(ui.ctx());
    let peintre = ui.painter().clone();
    let tete = Rect::from_min_size(r.min, vec2(r.width(), TETE));
    peintre.line_segment([tete.left_bottom(), tete.right_bottom()], Stroke::new(1.0, p.trait_));
    peintre.text(
        pos2(tete.left() + 32.0, tete.center().y),
        Align2::LEFT_CENTER,
        "Console",
        moyenne(12.0),
        p.encre,
    );
    if ui.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::F)) {
        b.cherche.get_or_insert_with(String::new);
        ui.memory_mut(|m| m.request_focus(id_cherche()));
    }
    let gauche_des_boutons = boutons_de_droite(ui, &peintre, tete, montrees, &mut b);
    let gauche_des_filtres = filtres(ui, &peintre, tete, gauche_des_boutons - 24.0, &mut b);
    let limite = gauche_des_filtres - 24.0;
    if b.cherche.is_some() {
        recherche(ui, tete, limite, &mut b);
    } else {
        etat(appli, ui, &peintre, tete, limite);
    }
    let flux = Rect::from_min_max(
        pos2(r.left(), tete.bottom()),
        pos2(r.right(), tete.bottom() + DESSOUS + HAUTEUR_LIGNE * n_f32(montrees)),
    );
    let cherche = b.cherche.clone().unwrap_or_default();
    let places = appli.console.places(b.filtre, &cherche);
    ui.scope_builder(UiBuilder::new().max_rect(flux), |ui| {
        defiler(appli, ui, &places, &mut b);
    });
    saisie(appli, ui, &peintre, flux.bottom(), &mut b);
    tirer(ui, r, montrees, &mut b);
    garder(ui.ctx(), b);
}

fn id_cherche() -> Id {
    Id::unique("console-cherche")
}

/// Un mot cliquable de l'en-tête, aligné à droite sur `droite` ; rend sa réponse et le bord gauche de sa zone.
fn mot_cliquable(ui: &Ui, tete: Rect, droite: f32, mot: &str, cle: &str, allume: bool) -> (egui::Response, f32) {
    let p = pal();
    let peintre = ui.painter();
    let largeur = peintre.layout_no_wrap(mot.into(), police(12.0), p.doux).size().x;
    let zone = Rect::from_min_size(pos2(droite - largeur, tete.top()), vec2(largeur, tete.height()));
    let rep = ui.interact(zone, ui.scope_id().with(cle), Sense::click());
    let vif = if allume { 1.0 } else { survol(ui, rep.id, rep.hovered()) };
    peintre.text(
        pos2(zone.right(), zone.center().y),
        Align2::RIGHT_CENTER,
        mot,
        police(12.0),
        p.doux.lerp_to_gamma(if allume { p.accent } else { p.encre }, vif),
    );
    super::clavier::anneau_zone(ui, &rep, zone.shrink2(vec2(0.0, 10.0)).expand2(vec2(6.0, 0.0)), 6.0);
    (rep.on_hover_cursor(egui::CursorIcon::PointingHand), zone.left())
}

/// Déplier et Coulisses, à droite ; rend le bord gauche de Coulisses.
fn boutons_de_droite(ui: &Ui, peintre: &egui::Painter, tete: Rect, montrees: usize, b: &mut Bande) -> f32 {
    let p = pal();
    let depliee = montrees >= LIGNES_DEPLIEE;
    let zone = Rect::from_min_size(pos2(tete.right() - 32.0 - 90.0, tete.top()), vec2(90.0, tete.height()));
    let rep = ui.interact(zone, ui.scope_id().with("deplier"), Sense::click());
    let mot = peintre.text(
        pos2(zone.right(), zone.center().y),
        Align2::RIGHT_CENTER,
        if depliee {
            crate::tr!("Replier", "Collapse")
        } else {
            crate::tr!("Déplier", "Expand")
        },
        police(12.0),
        p.doux.lerp_to_gamma(p.encre, survol(ui, rep.id, rep.hovered())),
    );
    super::clavier::anneau_zone(ui, &rep, mot.expand2(vec2(6.0, 4.0)), 6.0);
    if rep.clicked() {
        b.lignes = if depliee { LIGNES_REPLIEE } else { LIGNES_DEPLIEE };
    }
    rep.on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text(crate::trf!(
            "Montrer {} lignes de la console (ou tirer son bord du bas)",
            "Show {} console lines (or drag its bottom edge)",
            if depliee { LIGNES_REPLIEE } else { LIGNES_DEPLIEE }
        ));
    let ouvertes = super::coulisses::ouvertes(ui.ctx());
    let (rep, gauche) = mot_cliquable(
        ui,
        tete,
        zone.left() - 24.0,
        crate::tr!("Coulisses", "Behind the scenes"),
        "coulisses",
        ouvertes,
    );
    if rep.clicked() {
        super::coulisses::basculer(ui.ctx());
    }
    rep.on_hover_text(crate::tr!(
        "Ce que fait la fenêtre, en direct et en lecture seule : chaque commande lancée, ses arguments exacts, son bac à sable, sa durée.",
        "What the window does, live and read-only: each command run, its exact arguments, its sandbox, its duration."
    ));
    gauche
}

/// Les filtres, en pastilles, finissant à `droite` ; rend leur bord gauche.
fn filtres(ui: &Ui, peintre: &egui::Painter, tete: Rect, droite: f32, b: &mut Bande) -> f32 {
    let p = pal();
    let mut x = droite;
    for f in Filtre::TOUS.into_iter().rev() {
        let g = peintre.layout_no_wrap(f.nom().into(), police(12.0), p.doux);
        let w = g.size().x + 20.0;
        let zone = Rect::from_min_size(pos2(x - w, tete.center().y - 11.0), vec2(w, 22.0));
        let rep = ui.interact(zone, ui.scope_id().with(("filtre", f.nom())), Sense::click());
        let choisi = b.filtre == f;
        let s = survol(ui, rep.id, rep.hovered());
        if choisi {
            peintre.rect_filled(zone, 11, p.s2);
        } else if s > 0.0 {
            peintre.rect_filled(zone, 11, p.s2.gamma_multiply(0.5 * s));
        }
        let couleur = if choisi {
            p.encre
        } else {
            p.doux.lerp_to_gamma(p.encre, s)
        };
        peintre.galley(zone.center() - g.size() / 2.0, g, couleur);
        super::clavier::anneau(ui, &rep, 11.0);
        if rep.clicked() {
            b.filtre = f;
        }
        rep.on_hover_cursor(egui::CursorIcon::PointingHand)
            .on_hover_text(match f {
                Filtre::Tout => crate::tr!("Tout ce que dit la console", "Everything the console says"),
                Filtre::Problemes => crate::tr!(
                    "Les commandes qui ont trouvé quelque chose, et les avertissements",
                    "Commands that found something, and warnings"
                ),
                Filtre::CePc => crate::tr!(
                    "Les commandes qui lisent cet ordinateur",
                    "Commands that read this computer"
                ),
                Filtre::Reseau => crate::tr!("Les commandes du réseau", "Network commands"),
            });
        x -= w + 4.0;
    }
    x
}

/// Le champ `id` a le clavier. egui le lui retire au début de l'image où Échap est pressé : cette image-là, on
/// regarde l'image d'avant, pour qu'Échap ferme d'abord ce que le champ a d'ouvert.
fn garde_le_focus(ctx: &egui::Context, id: Id) -> bool {
    ctx.memory(|m| m.has_focus(id))
        || (ctx.input(|i| i.key_pressed(Key::Escape)) && ctx.memory(|m| m.had_focus_last_frame(id)))
}

/// Le champ de recherche (Ctrl+F), entre « Console » et les filtres ; Échap le ferme.
fn recherche(ui: &mut Ui, tete: Rect, limite: f32, b: &mut Bande) {
    let p = pal();
    let champ = Rect::from_min_max(
        pos2(tete.left() + 110.0, tete.center().y - 11.0),
        pos2(
            limite.min(tete.left() + 520.0).max(tete.left() + 200.0),
            tete.center().y + 11.0,
        ),
    );
    ui.painter().rect_stroke(
        champ,
        11,
        Stroke::new(1.0, p.accent.gamma_multiply(0.6)),
        StrokeKind::Inside,
    );
    if garde_le_focus(ui.ctx(), id_cherche()) && ui.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Escape)) {
        b.cherche = None;
        return;
    }
    let Some(cherche) = b.cherche.as_mut() else {
        return;
    };
    let dedans = champ.shrink2(vec2(12.0, 3.0));
    let dedans = Rect::from_min_max(dedans.min, pos2(dedans.right() - 18.0, dedans.bottom()));
    ui.scope_builder(UiBuilder::new().max_rect(dedans), |ui| {
        ui.add(
            TextEdit::singleline(cherche)
                .id(id_cherche())
                .frame(Frame::NONE)
                .font(police(12.0))
                .text_color(p.encre)
                .char_limit(60)
                .hint_text(
                    RichText::new(crate::tr!("Chercher dans la console", "Search the console"))
                        .font(police(12.0))
                        .color(p.discret),
                )
                .desired_width(dedans.width()),
        )
    });
    let fermer = Rect::from_center_size(pos2(champ.right() - 14.0, champ.center().y), vec2(16.0, 16.0));
    let rep = ui.interact(fermer, ui.scope_id().with("fermer-cherche"), Sense::click());
    croix(
        ui.painter(),
        fermer.shrink(4.0),
        p.doux.lerp_to_gamma(p.encre, survol(ui, rep.id, rep.hovered())),
    );
    if rep.clicked() {
        b.cherche = None;
    }
    rep.on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text(crate::tr!("Fermer la recherche (Échap)", "Close the search (Esc)"));
}

/// L'état, après « Console » : la commande en cours (avec ■ Arrêter), sinon la dernière lecture de chaque sujet, les
/// alertes et la veille.
fn etat(appli: &mut Appli, ui: &Ui, peintre: &egui::Painter, tete: Rect, limite: f32) {
    let p = pal();
    let en_cours = appli.en_cours();
    if en_cours.is_some() {
        let ecrit = super::cadre::tache_en_tete(ui, peintre, tete, en_cours, appli.taches());
        let mot = crate::tr!("Arrêter", "Stop");
        let g = peintre.layout_no_wrap(mot.into(), police(12.0), p.encre);
        let zone = Rect::from_min_size(
            pos2(ecrit.right() + 16.0, tete.center().y - 11.0),
            vec2(g.size().x + 34.0, 22.0),
        );
        if zone.right() > limite {
            return;
        }
        let rep = ui.interact(zone, ui.scope_id().with("arreter"), Sense::click());
        let s = survol(ui, rep.id, rep.hovered());
        peintre.rect_stroke(
            zone,
            11,
            Stroke::new(1.0, p.trait_.lerp_to_gamma(p.grave, s)),
            StrokeKind::Inside,
        );
        peintre.rect_filled(
            Rect::from_center_size(pos2(zone.left() + 14.0, zone.center().y), vec2(8.0, 8.0)),
            1,
            p.grave,
        );
        peintre.galley(pos2(zone.left() + 24.0, zone.center().y - g.size().y / 2.0), g, p.encre);
        super::clavier::anneau(ui, &rep, 11.0);
        if rep.clicked() {
            appli.arreter();
        }
        rep.on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text(crate::tr!(
            "Arrête la commande en cours et vide la file (Échap dans la saisie). Un changement ne s'interrompt pas.",
            "Stops the running command and empties the queue (Esc in the input). A change is not interrupted."
        ));
        return;
    }
    let lu = |c: Commande, nom: &str| match appli.resultat(c) {
        Some(r) => crate::trf!("{} {}", "{} {}", nom, depuis(r.fin.elapsed())),
        None => crate::trf!("{} jamais", "{} never", nom),
    };
    let mut morceaux = vec![
        lu(Commande::Bilan, crate::tr!("Bilan", "Check")),
        lu(Commande::Appareils, crate::tr!("Réseau", "Network")),
    ];
    if let Some(j) = appli.journal() {
        let n = j.alertes().count();
        if n > 0 {
            morceaux.push(crate::trf!(
                "{} {}",
                "{} {}",
                n,
                crate::langue::accord(n, ["alerte", "alertes"], ["alert", "alerts"])
            ));
        }
    }
    morceaux.push(super::cadre::veille(appli).0.to_owned());
    let point = pos2(tete.left() + 98.0, tete.center().y);
    peintre.circle_filled(point, 3.0, p.gris);
    let g = coupee(
        ui,
        &morceaux.join(" · "),
        police(12.0),
        p.discret,
        limite - tete.left() - 110.0,
    );
    peintre.galley(
        pos2(tete.left() + 110.0, tete.center().y - g.size().y / 2.0),
        g,
        p.discret,
    );
}

/// « il y a 3 min » : depuis quand, en mots, arrondi.
fn depuis(d: Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        crate::tr!("à l'instant", "just now").to_owned()
    } else if s < 3600 {
        crate::trf!("il y a {} min", "{} min ago", s / 60)
    } else if s < 86_400 {
        crate::trf!("il y a {} h", "{} h ago", s / 3600)
    } else {
        crate::trf!("il y a {} j", "{} d ago", s / 86_400)
    }
}

/// Un texte sur une seule ligne, coupé d'un « … » à `largeur`.
fn coupee(ui: &Ui, texte: &str, font: FontId, couleur: Color32, largeur: f32) -> Arc<Galley> {
    let mut job = LayoutJob::single_section(texte.to_owned(), TextFormat::simple(font, couleur));
    job.wrap = TextWrapping {
        max_width: largeur.max(20.0),
        max_rows: 1,
        break_anywhere: true,
        overflow_character: Some('…'),
    };
    ui.fonts_mut(|f| f.layout_job(job))
}

/// Un ✕ tracé.
fn croix(peintre: &egui::Painter, r: Rect, couleur: Color32) {
    let s = Stroke::new(1.5, couleur);
    peintre.line_segment([r.left_top(), r.right_bottom()], s);
    peintre.line_segment([r.right_top(), r.left_bottom()], s);
}

fn couleur_ton(t: Ton) -> Color32 {
    let p = pal();
    match t {
        Ton::Normal => p.encre,
        Ton::Commande => p.accent,
        Ton::Bon => p.bon,
        Ton::Attention => p.moyen,
        Ton::Grave => p.grave,
        Ton::Discret => p.doux,
    }
}

/// L'encre d'un texte selon son ton : jamais une couleur de gravité (réglable), seulement l'encre, l'accent d'une
/// commande ou le doux.
fn encre_ton(t: Ton) -> Color32 {
    let p = pal();
    match t {
        Ton::Normal | Ton::Bon | Ton::Attention | Ton::Grave => p.encre,
        Ton::Commande => p.accent,
        Ton::Discret => p.doux,
    }
}

/// La couleur d'un bloc (sa bande à gauche, son icône) : l'attente en gris, le travail en accent, la fin selon ce
/// qu'elle a trouvé, l'échec en grave.
fn couleur_bloc(b: &Bloc) -> Color32 {
    let p = pal();
    match b.etat {
        Etat::EnAttente => p.gris,
        Etat::EnCours => p.accent,
        Etat::Fini => match b.ton {
            Ton::Commande | Ton::Normal => p.doux,
            t => couleur_ton(t),
        },
        Etat::Echec => p.grave,
    }
}

fn couleur_point(pt: &crate::console::Point) -> Color32 {
    let p = pal();
    match pt.marque {
        Marque::Corriger | Marque::Alerte => super::bilan::couleur_gravite(pt.gravite),
        Marque::NonVerifie => p.gris,
        Marque::Savoir => p.doux,
        Marque::Eteint | Marque::Appareil => p.moyen,
    }
}

/// Le numéro d'une entrée (les nouvelles se comptent par lui).
fn numero(appli: &Appli, i: usize) -> u64 {
    appli.console.get(i).map_or(0, Entree::numero)
}

/// Les places, du plus ancien en haut au plus récent en bas, collées en bas tant que la personne ne remonte pas.
fn defiler(appli: &mut Appli, ui: &mut Ui, places: &[Place], b: &mut Bande) {
    let p = pal();
    let zone = ui.max_rect();
    let n = places.len();
    let total = HAUTEUR_LIGNE * n_f32(n) + DESSOUS;
    let descendre = std::mem::take(&mut b.descendre);
    let mut action = None;
    let sortie = ScrollArea::vertical()
        .id_salt("console-places")
        .stick_to_bottom(true)
        .auto_shrink(false)
        .show_viewport(ui, |ui, vue| {
            // Peu de places : posées en bas, la plus récente juste au-dessus de la saisie, comme dans un terminal.
            let vide = (vue.height() - total).max(0.0);
            ui.set_height(vide + total);
            let origine = ui.max_rect().top() + vide;
            let x0 = ui.max_rect().left();
            let largeur = ui.max_rect().width();
            let premiere = f32_n((vue.min.y - vide) / HAUTEUR_LIGNE);
            let derniere = f32_n((vue.max.y - vide) / HAUTEUR_LIGNE + 1.0).min(n);
            for k in premiere..derniere {
                let Some(place) = places.get(k) else {
                    continue;
                };
                let rangee = Rect::from_min_size(
                    pos2(x0, origine + HAUTEUR_LIGNE * n_f32(k)),
                    vec2(largeur, HAUTEUR_LIGNE),
                );
                if let Some(a) = dessiner_place(appli, ui, *place, rangee) {
                    action = Some(a);
                }
            }
            if descendre {
                let bas = Rect::from_min_size(pos2(x0, origine + total - 1.0), vec2(1.0, 1.0));
                ui.scroll_to_rect(bas, Some(Align::BOTTOM));
            }
        });
    if let Some(a) = action {
        agir(appli, ui, a);
    }
    if n == 0 {
        let mot = if appli.console.is_empty() {
            crate::tr!(
                "La console est vide. Tapez une commande dessous, ou « aide ».",
                "The console is empty. Type a command below, or “help”."
            )
        } else {
            crate::tr!("Rien ici pour ce filtre.", "Nothing here for this filter.")
        };
        ui.painter()
            .text(zone.center(), Align2::CENTER_CENTER, mot, police(13.0), p.discret);
    }
    // Les places arrivées depuis que la personne a remonté : une pastille les compte et ramène en bas.
    let max = (sortie.content_size.y - sortie.inner_rect.height()).max(0.0);
    let en_bas = !descendre && sortie.state.clamped_offset().y >= max - 0.5;
    let derniere = places.last().map_or(0, |pl| numero(appli, pl.entree()));
    if en_bas {
        b.vu = derniere;
    }
    let nouvelles = places.iter().filter(|pl| numero(appli, pl.entree()) > b.vu).count();
    if super::defile::pastille(
        ui,
        Id::unique("console-places"),
        zone,
        DESSOUS,
        nouvelles,
        &mut b.montre,
    ) {
        b.descendre = true;
    }
}

/// Ce qu'un clic dans les places demande : appliqué après le dessin (la console ne change pas pendant qu'on la
/// parcourt).
enum Action {
    Basculer(u64),
    Deplier(u64),
    Retirer(Commande),
    Voir(Commande),
    Relancer(Commande),
    Copier(String),
}

fn agir(appli: &mut Appli, ui: &Ui, a: Action) {
    match a {
        Action::Basculer(n) => appli.console.basculer(n),
        Action::Deplier(n) => appli.console.deplier(n),
        Action::Retirer(c) => appli.retirer(c),
        Action::Voir(c) => appli.aller(ecran_de(c)),
        Action::Relancer(c) => appli.demander(c),
        Action::Copier(t) => {
            ui.ctx().copy_text(t);
            let maintenant = ui.input(|i| i.time);
            ui.ctx()
                .data_mut(|d| d.insert_temp(Id::unique("console-copie"), maintenant));
        }
    }
}

/// Le fond d'une rangée sous la souris, en fondu.
fn fond_survole(ui: &Ui, rep: &egui::Response, rangee: Rect) {
    let s = survol(ui, rep.id, rep.hovered());
    if s > 0.0 {
        ui.painter()
            .rect_filled(rangee.shrink2(vec2(16.0, 0.0)), 4, pal().s2.gamma_multiply(s));
    }
}

/// Un texte sélectionnable sur une ligne, coupé à la largeur (la bulle le montre en entier).
fn texte_selectionnable(ui: &mut Ui, id: Id, place: Rect, g: Arc<Galley>) {
    ui.scope_builder(UiBuilder::new().id_salt(id).max_rect(place), |ui| {
        ui.add(Label::new(g).selectable(true).show_tooltip_when_elided(true))
    });
}

fn dessiner_place(appli: &Appli, ui: &mut Ui, place: Place, rangee: Rect) -> Option<Action> {
    let p = pal();
    let entree = appli.console.get(place.entree())?;
    let x0 = rangee.left();
    let milieu = rangee.center().y;
    let peintre = ui.painter().clone();
    let largeur_texte = (rangee.width() - X_TEXTE - DROITE).max(40.0);
    match (place, entree) {
        (Place::Ligne(_), Entree::Ligne(l)) => {
            peintre.text(
                pos2(x0 + X_HEURE, milieu),
                Align2::LEFT_CENTER,
                &l.heure,
                mono(13.0),
                p.discret,
            );
            let source = coupee(
                ui,
                &l.source,
                mono(13.0),
                if l.ton == Ton::Commande { p.accent } else { p.doux },
                X_TEXTE - X_SOURCE - 8.0,
            );
            peintre.galley(pos2(x0 + X_SOURCE, milieu - source.size().y / 2.0), source, p.doux);
            // Un ton d'état : un point de sa couleur dans la marge, le texte à l'encre. Les couleurs de gravité se
            // règlent : elles repèrent, elles ne portent jamais seules un mot (lot couleurs, relecture C1).
            if matches!(l.ton, Ton::Bon | Ton::Attention | Ton::Grave) {
                peintre.circle_filled(pos2(x0 + X_HEURE - 11.0, milieu), 3.0, couleur_ton(l.ton));
            }
            let g = coupee(ui, &l.texte, mono(13.0), encre_ton(l.ton), largeur_texte);
            let place = Rect::from_min_size(pos2(x0 + X_TEXTE, milieu - g.size().y / 2.0), g.size());
            texte_selectionnable(ui, Id::unique(("console-ligne", l.numero)), place, g);
            None
        }
        (_, Entree::Bloc(b)) => {
            // La bande de couleur, à gauche, sur toute la hauteur du bloc.
            peintre.rect_filled(
                Rect::from_min_size(pos2(x0 + 20.0, rangee.top()), vec2(3.0, rangee.height())),
                0,
                couleur_bloc(b),
            );
            dessiner_bloc(ui, &peintre, place, b, rangee, largeur_texte)
        }
        _ => None,
    }
}

/// L'icône de l'état d'un bloc, tracée (aucune police n'a les mêmes signes partout).
fn icone_etat(ui: &Ui, peintre: &egui::Painter, b: &Bloc, centre: egui::Pos2) {
    let p = pal();
    let c = couleur_bloc(b);
    match b.etat {
        Etat::EnAttente => {
            peintre.circle_stroke(centre, 4.5, Stroke::new(1.5, c));
        }
        Etat::EnCours => {
            let temps = ui.ctx().input(|i| i.time);
            super::mouvement::pouls(peintre, temps, centre, 3.5, p.accent, super::mouvement::POULS_TACHE);
            super::mouvement::tourne(ui.ctx());
        }
        Etat::Fini => super::icones::coche(peintre, Rect::from_center_size(centre, vec2(14.0, 14.0)), c),
        Etat::Echec => croix(peintre, Rect::from_center_size(centre, vec2(8.0, 8.0)), c),
    }
}

fn dessiner_bloc(
    ui: &mut Ui,
    peintre: &egui::Painter,
    place: Place,
    b: &Bloc,
    rangee: Rect,
    largeur_texte: f32,
) -> Option<Action> {
    let p = pal();
    let x0 = rangee.left();
    let milieu = rangee.center().y;
    let id = Id::unique(("console-bloc", b.numero));
    let commande = b.lancement.commande();
    match place {
        Place::Tete(_) => {
            let rep = ui.interact(rangee, id.with("tete"), Sense::click());
            if b.etat != Etat::EnAttente {
                fond_survole(ui, &rep, rangee);
            }
            peintre.text(
                pos2(x0 + X_HEURE, milieu),
                Align2::LEFT_CENTER,
                &b.heure,
                mono(13.0),
                p.discret,
            );
            icone_etat(ui, peintre, b, pos2(x0 + X_SOURCE + 5.0, milieu));
            let cmd = peintre.text(
                pos2(x0 + X_SOURCE + 18.0, milieu),
                Align2::LEFT_CENTER,
                b.ligne_de_commande(),
                mono(13.0),
                if b.etat == Etat::EnAttente { p.doux } else { p.accent },
            );
            let (texte, couleur) = match b.etat {
                Etat::EnAttente => (crate::tr!("en attente", "queued").to_owned(), p.discret),
                Etat::EnCours => {
                    let d = b.debut.map_or(0.0, |d| d.elapsed().as_secs_f32());
                    (
                        crate::trf!("en cours · {}", "running · {}", crate::langue::secondes(d)),
                        p.doux,
                    )
                }
                Etat::Fini | Etat::Echec => {
                    let d = b
                        .duree
                        .map(|d| crate::langue::secondes(d.as_secs_f32()))
                        .unwrap_or_default();
                    // Le résumé à l'encre : la couleur du bloc est déjà dans sa bande et son icône.
                    (format!("{d} · {}", b.resume), encre_ton(b.ton))
                }
            };
            let x = cmd.right().max(x0 + X_TEXTE - 16.0) + 16.0;
            let g = coupee(ui, &texte, police(13.0), couleur, rangee.right() - DROITE - 28.0 - x);
            peintre.galley(pos2(x, milieu - g.size().y / 2.0), g, couleur);
            let droite = Rect::from_center_size(pos2(rangee.right() - DROITE - 6.0, milieu), vec2(12.0, 12.0));
            if b.etat == Etat::EnAttente {
                let r = ui.interact(droite.expand(4.0), id.with("retirer"), Sense::click());
                croix(
                    peintre,
                    droite.shrink(2.0),
                    p.doux.lerp_to_gamma(p.grave, survol(ui, r.id, r.hovered())),
                );
                let clic = r.clicked();
                r.on_hover_cursor(egui::CursorIcon::PointingHand)
                    .on_hover_text(crate::tr!(
                        "Retirer de la file (rien n'a été lancé)",
                        "Remove from the queue (nothing was run)"
                    ));
                return clic.then_some(Action::Retirer(commande));
            }
            // Le chevron : ouvert vers le bas, replié vers la droite.
            let c = droite.center();
            let pts = if b.replie {
                vec![c + vec2(-2.0, -4.0), c + vec2(2.0, 0.0), c + vec2(-2.0, 4.0)]
            } else {
                vec![c + vec2(-4.0, -2.0), c + vec2(0.0, 2.0), c + vec2(4.0, -2.0)]
            };
            peintre.add(egui::Shape::line(pts, Stroke::new(1.5, p.discret)));
            let clic = rep.clicked();
            rep.on_hover_cursor(egui::CursorIcon::PointingHand)
                .on_hover_text(if b.replie {
                    crate::tr!("Déplier ce bloc", "Expand this block")
                } else {
                    crate::tr!("Replier ce bloc", "Collapse this block")
                });
            clic.then_some(Action::Basculer(b.numero))
        }
        Place::Etape(_) => {
            let x = x0 + X_TEXTE;
            let barre = Rect::from_min_size(pos2(x, milieu - 2.0), vec2(160.0, 4.0));
            peintre.rect_filled(barre, 2, p.s3);
            let mot = if let Some(e) = &b.etape {
                let plein = Rect::from_min_size(barre.min, vec2(barre.width() * e.part(), barre.height()));
                peintre.rect_filled(plein, 2, p.accent);
                crate::trf!("étape {} sur {} · {}", "step {} of {} · {}", e.fait, e.total, e.libelle)
            } else {
                // Sans étape lue : un trait qui va et vient (la commande ne dit pas où elle en est).
                let t = super::cadre::phase_f32((ui.input(|i| i.time) % 1.6) / 1.6);
                let aller = if t < 0.5 { t * 2.0 } else { 2.0 - t * 2.0 };
                let seg = Rect::from_min_size(pos2(barre.left() + 120.0 * aller, barre.top()), vec2(40.0, 4.0));
                peintre.rect_filled(seg, 2, p.accent.gamma_multiply(0.8));
                crate::tr!("lecture en cours…", "reading…").to_owned()
            };
            let g = coupee(ui, &mot, police(12.0), p.doux, largeur_texte - 176.0);
            peintre.galley(pos2(barre.right() + 16.0, milieu - g.size().y / 2.0), g, p.doux);
            None
        }
        Place::Point(_, k) => {
            let pt = b.points.get(k)?;
            let rep = ui.interact(rangee, id.with(("point", k)), Sense::click());
            fond_survole(ui, &rep, rangee);
            let couleur = couleur_point(pt);
            peintre.circle_filled(pos2(x0 + X_SOURCE + 5.0, milieu), 3.0, couleur);
            // Le mot de gravité à l'encre ; sa couleur réglable reste au point.
            let mot = coupee(ui, pt.mot(), police(12.0), p.encre, X_TEXTE - X_SOURCE - 26.0);
            peintre.galley(pos2(x0 + X_SOURCE + 18.0, milieu - mot.size().y / 2.0), mot, p.encre);
            let mut job = LayoutJob::default();
            job.append(&pt.sujet, 0.0, TextFormat::simple(moyenne(13.0), p.encre));
            job.append(" — ", 0.0, TextFormat::simple(police(13.0), p.discret));
            job.append(&pt.message, 0.0, TextFormat::simple(police(13.0), p.doux));
            job.wrap = TextWrapping {
                max_width: largeur_texte,
                max_rows: 1,
                break_anywhere: true,
                overflow_character: Some('…'),
            };
            let g = ui.fonts_mut(|f| f.layout_job(job));
            let coupe = g.elided;
            peintre.galley(pos2(x0 + X_TEXTE, milieu - g.size().y / 2.0), g, p.encre);
            let clic = rep.clicked();
            let rep = rep.on_hover_cursor(egui::CursorIcon::PointingHand);
            let bulle = crate::trf!("Ouvrir l'écran {}", "Open the {} screen", commande.nom_affiche());
            if coupe {
                rep.on_hover_text(format!("{} — {}\n\n{bulle}", pt.sujet, pt.message));
            } else {
                rep.on_hover_text(bulle);
            }
            clic.then_some(Action::Voir(commande))
        }
        Place::Message(_, k) => {
            let m = b.messages.get(k)?;
            let g = coupee(ui, m, mono(12.0), p.doux, largeur_texte);
            let place = Rect::from_min_size(pos2(x0 + X_TEXTE, milieu - g.size().y / 2.0), g.size());
            texte_selectionnable(ui, id.with(("message", k)), place, g);
            None
        }
        Place::Autres(_) => {
            let mot = if b.deplie {
                crate::tr!("Replier", "Fold").to_owned()
            } else {
                crate::trf!("+ {} autres", "+ {} more", b.autres())
            };
            let (rep, _) = lien(ui, peintre, pos2(x0 + X_TEXTE, milieu), &mot, id.with("autres"));
            let clic = rep.clicked();
            rep.on_hover_text(if b.deplie {
                crate::tr!("Montrer seulement les premiers", "Show only the first ones")
            } else {
                crate::tr!(
                    "Tout ce que la console a gardé (l'écran a le reste)",
                    "Everything the console kept (the screen has the rest)"
                )
            });
            clic.then_some(Action::Deplier(b.numero))
        }
        Place::Suites(_) => {
            let mut x = x0 + X_TEXTE;
            let mut action = None;
            let (rep, fin) = lien(
                ui,
                peintre,
                pos2(x, milieu),
                crate::tr!("Voir dans l'écran", "See on the screen"),
                id.with("voir"),
            );
            if rep.clicked() {
                action = Some(Action::Voir(commande));
            }
            x = fin + 20.0;
            if let Lancement::Commande(c) = b.lancement {
                let (rep, fin) = lien(
                    ui,
                    peintre,
                    pos2(x, milieu),
                    crate::tr!("Relancer", "Run again"),
                    id.with("relancer"),
                );
                if rep.clicked() {
                    action = Some(Action::Relancer(c));
                }
                rep.on_hover_text(crate::trf!(
                    "Relance « {} » (lecture seule)",
                    "Runs “{}” again (read-only)",
                    b.ligne_de_commande()
                ));
                x = fin + 20.0;
            }
            let copie = ui
                .ctx()
                .data(|d| d.get_temp::<f64>(Id::unique("console-copie")))
                .is_some_and(|t| ui.input(|i| i.time) - t < 1.5);
            let (rep, _) = lien(
                ui,
                peintre,
                pos2(x, milieu),
                crate::tr!("Copier", "Copy"),
                id.with("copier"),
            );
            if rep.clicked() {
                action = Some(Action::Copier(b.texte()));
            }
            rep.on_hover_text(if copie {
                crate::tr!("Copié.", "Copied.")
            } else {
                crate::tr!("Copie ce bloc en texte", "Copies this block as text")
            });
            action
        }
        Place::Ligne(_) => None,
    }
}

/// Un lien de texte (accent, plus vif au survol), commençant à `debut` ; rend sa réponse et son bord droit.
fn lien(ui: &Ui, peintre: &egui::Painter, debut: egui::Pos2, mot: &str, id: Id) -> (egui::Response, f32) {
    let p = pal();
    let g = peintre.layout_no_wrap(mot.to_owned(), police(12.0), p.accent);
    let zone = Rect::from_min_size(pos2(debut.x, debut.y - 9.0), vec2(g.size().x, 18.0));
    let rep = ui.interact(zone, id, Sense::click());
    let s = survol(ui, rep.id, rep.hovered());
    let couleur = melange(p.accent, p.encre, 1.0 - 0.3 * s);
    peintre.galley(pos2(zone.left(), debut.y - g.size().y / 2.0), g, couleur);
    if s > 0.0 {
        peintre.line_segment(
            [
                pos2(zone.left(), zone.bottom() - 2.0),
                pos2(zone.right(), zone.bottom() - 2.0),
            ],
            Stroke::new(1.0, couleur.gamma_multiply(s)),
        );
    }
    super::clavier::anneau_zone(ui, &rep, zone.expand2(vec2(4.0, 1.0)), 4.0);
    (rep.on_hover_cursor(egui::CursorIcon::PointingHand), zone.right())
}

/// Les choix de la liste sous la saisie : des commandes (suggestions), ou des saisies d'avant (Ctrl+R).
enum Liste {
    Rien,
    Commandes(Vec<Commande>),
    Historique(Vec<String>),
}

impl Liste {
    fn len(&self) -> usize {
        match self {
            Liste::Rien => 0,
            Liste::Commandes(v) => v.len(),
            Liste::Historique(v) => v.len(),
        }
    }
}

/// Les saisies d'avant qui contiennent `motif`, la plus récente d'abord, sans doublon.
fn dans_l_historique(appli: &Appli, motif: &str) -> Vec<String> {
    let motif = motif.trim().to_lowercase();
    let mut v: Vec<String> = Vec::new();
    for h in appli.historique().iter().rev() {
        if v.len() >= commandes::SUGGESTIONS_MAX {
            break;
        }
        if h.to_lowercase().contains(&motif) && !v.contains(h) {
            v.push(h.clone());
        }
    }
    v
}

/// La saisie d'une commande choisie dans la liste : son nom, après « aide » si la saisie commençait ainsi.
fn saisie_de(saisie: &str, c: Commande) -> String {
    let mots: Vec<&str> = saisie.split_whitespace().collect();
    match mots.as_slice() {
        [a, _] if ["aide", "help", "?"].contains(&a.to_lowercase().as_str()) => format!("{a} {}", c.nom_affiche()),
        _ => c.nom_affiche().to_owned(),
    }
}

/// La saisie, au bas de la bande : un nom de la liste fermée, rien d'autre ne part (`commandes::comprendre`).
fn saisie(appli: &mut Appli, ui: &mut Ui, peintre: &egui::Painter, haut: f32, b: &mut Bande) {
    let p = pal();
    let r = ui.max_rect();
    let saisie = Rect::from_min_max(pos2(r.left(), haut), pos2(r.right(), haut + SAISIE));
    peintre.line_segment([saisie.left_top(), saisie.right_top()], Stroke::new(1.0, p.trait_));
    peintre.line_segment(
        [saisie.left_bottom(), saisie.right_bottom()],
        Stroke::new(1.0, p.trait_),
    );
    peintre.text(
        pos2(saisie.left() + 32.0, saisie.center().y),
        Align2::LEFT_CENTER,
        if b.historique {
            "(historique) ›"
        } else {
            "vanguard ›"
        },
        mono(13.0),
        p.accent,
    );
    let mut x = saisie.right() - 32.0;
    let touches = [
        (
            crate::tr!("Entrée", "Enter"),
            crate::tr!(
                "Lance la commande tapée, ou celle choisie dans la liste, si elle est dans la liste fermée",
                "Runs the typed command, or the one picked in the list, if it is on the closed list"
            ),
        ),
        (
            "↑",
            crate::tr!(
                "Rappelle la saisie d'avant (↓ revient) ; dans la liste, choisit une suggestion. Ctrl+R cherche dans les saisies d'avant.",
                "Recalls the previous entry (↓ goes back); in the list, picks a suggestion. Ctrl+R searches past entries."
            ),
        ),
        (
            "Tab",
            crate::tr!(
                "Complète le nom quand une seule commande convient, ou prend la suggestion choisie",
                "Completes the name when only one command fits, or takes the picked suggestion"
            ),
        ),
    ];
    for (i, (k, aide)) in touches.into_iter().enumerate() {
        let g = peintre.layout_no_wrap(k.into(), police(11.0), p.doux);
        let w = g.size().x + 12.0;
        let cap = Rect::from_min_size(pos2(x - w, saisie.center().y - 10.0), vec2(w, 20.0));
        peintre.rect_stroke(cap, 4, Stroke::new(1.0, p.trait_), StrokeKind::Inside);
        peintre.galley(cap.center() - g.size() / 2.0, g, p.doux);
        ui.interact(cap, ui.scope_id().with(("touche", i)), Sense::hover())
            .on_hover_text(aide);
        x -= w + 8.0;
    }
    let champ = Rect::from_min_max(
        pos2(
            saisie.left() + 128.0 + if b.historique { 40.0 } else { 0.0 },
            saisie.top() + 8.0,
        ),
        pos2(x - 16.0, saisie.bottom() - 8.0),
    );
    let id_saisie = ui.make_persistent_id("saisie");
    let a_le_focus = garde_le_focus(ui.ctx(), id_saisie);
    if b.vue != appli.saisie {
        b.masquee = false;
        b.choix = None;
    }
    let liste = |appli: &Appli, b: &Bande| -> Liste {
        if b.historique {
            Liste::Historique(dans_l_historique(appli, &appli.saisie))
        } else if b.masquee || appli.en_rappel() || appli.saisie.trim().is_empty() {
            Liste::Rien
        } else {
            Liste::Commandes(commandes::suggestions(&appli.saisie))
        }
    };
    // Les touches sont prises avant le champ : Tab ne doit pas en sortir, ↑ ne doit pas bouger le curseur, Échap ne
    // doit pas le quitter quand il a encore quelque chose à fermer ou à arrêter.
    if a_le_focus {
        let n = liste(appli, b).len();
        let (tab, haut, bas, rappel) = ui.input_mut(|i| {
            (
                i.consume_key(Modifiers::NONE, Key::Tab),
                i.consume_key(Modifiers::NONE, Key::ArrowUp),
                i.consume_key(Modifiers::NONE, Key::ArrowDown),
                i.consume_key(Modifiers::COMMAND, Key::R),
            )
        });
        if rappel {
            b.historique = !b.historique;
            b.choix = None;
        }
        if haut {
            match b.choix {
                Some(0) => b.choix = None,
                Some(k) => b.choix = Some(k - 1),
                None if b.historique && n > 0 => b.choix = Some(0),
                None => appli.rappeler(true),
            }
        }
        if bas {
            if n > 0 {
                b.choix = Some(b.choix.map_or(0, |k| (k + 1).min(n - 1)));
            } else {
                appli.rappeler(false);
            }
        }
        if tab {
            match (liste(appli, b), b.choix) {
                (Liste::Commandes(v), Some(k)) => {
                    if let Some(c) = v.get(k) {
                        appli.saisie = saisie_de(&appli.saisie, *c);
                    }
                }
                _ => appli.completer(),
            }
        }
        let echap = ui.input(|i| i.key_pressed(Key::Escape));
        if echap {
            let pris = if b.historique {
                b.historique = false;
                true
            } else if n > 0 {
                b.masquee = true;
                true
            } else if appli.en_cours().is_some() {
                appli.arreter();
                true
            } else {
                false
            };
            if pris {
                ui.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Escape));
                b.choix = None;
                // egui a retiré le focus au début de l'image ; Échap n'a fermé que la liste : le curseur reste.
                ui.memory_mut(|m| m.request_focus(id_saisie));
            }
        }
    }
    let rep = ui
        .scope_builder(UiBuilder::new().max_rect(champ), |ui| {
            ui.add(
                TextEdit::singleline(&mut appli.saisie)
                    .id(id_saisie)
                    .frame(Frame::NONE)
                    .font(mono(13.0))
                    .text_color(p.encre)
                    .char_limit(200)
                    .hint_text(
                        RichText::new(if b.historique {
                            crate::tr!(
                                "Cherchez dans vos saisies d'avant (Entrée reprend, Échap revient)",
                                "Search your past entries (Enter takes it, Esc goes back)"
                            )
                        } else {
                            crate::tr!(
                                "Tapez une commande de Vanguard (bilan, aide…)",
                                "Type a Vanguard command (check, help…)"
                            )
                        })
                        .font(mono(13.0))
                        .color(p.discret),
                    )
                    .desired_width(champ.width()),
            )
        })
        .inner;
    if rep.changed() {
        // Une frappe rouvre la liste fermée par Échap, et la remet à jour.
        b.masquee = false;
        b.choix = None;
    }
    let mut choisie: Option<usize> = None;
    let l = liste(appli, b);
    if l.len() > 0 && (a_le_focus || rep.has_focus() || b.sur_la_liste) {
        let (clic, dessus) = montrer_liste(ui, &l, b.choix, pos2(champ.left() - 12.0, saisie.bottom() + 4.0));
        b.sur_la_liste = dessus;
        choisie = clic;
    } else {
        b.sur_la_liste = false;
    }
    let entree = rep.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
    if entree && choisie.is_none() {
        choisie = b.choix;
        if choisie.is_none() && !b.historique {
            appli.saisir();
        }
        rep.request_focus();
    }
    if let Some(k) = choisie {
        match l {
            Liste::Commandes(v) => {
                if let Some(c) = v.get(k) {
                    // Le nom choisi passe par la même porte que la saisie tapée : `comprendre`, liste fermée.
                    appli.saisie = saisie_de(&appli.saisie, *c);
                    appli.saisir();
                }
            }
            Liste::Historique(v) => {
                if let Some(h) = v.get(k) {
                    appli.saisie.clone_from(h);
                }
                b.historique = false;
            }
            Liste::Rien => {}
        }
        b.choix = None;
        rep.request_focus();
    } else if entree && b.historique {
        b.historique = false;
    }
    b.vue.clone_from(&appli.saisie);
}

/// La liste sous la saisie ; rend le choix cliqué et si la souris est dessus.
fn montrer_liste(ui: &Ui, l: &Liste, choix: Option<usize>, coin: egui::Pos2) -> (Option<usize>, bool) {
    let p = pal();
    let largeur = 520.0;
    let n = l.len();
    let mut clic = None;
    let sortie = egui::Area::new(Id::unique("console-suggestions"))
        .order(egui::Order::Foreground)
        .fixed_pos(coin)
        .show(ui.ctx(), |ui| {
            Frame::new()
                .fill(p.surface)
                .stroke(Stroke::new(1.0, p.trait_))
                .shadow(super::ombre())
                .corner_radius(10)
                .inner_margin(egui::Margin::same(6))
                .show(ui, |ui| {
                    ui.set_width(largeur);
                    for k in 0..n {
                        let (rect, rep) = ui.allocate_exact_size(vec2(largeur, HAUTEUR_SUGGESTION), Sense::click());
                        let choisi = choix == Some(k);
                        let s = survol(ui, rep.id, rep.hovered());
                        if choisi || s > 0.0 {
                            ui.painter()
                                .rect_filled(rect, 6, p.s2.gamma_multiply(if choisi { 1.0 } else { s }));
                        }
                        let (nom, droite, dessous) = match l {
                            Liste::Commandes(v) => match v.get(k) {
                                Some(c) => (c.nom_affiche().to_owned(), c.rubrique().nom(), c.description()),
                                None => continue,
                            },
                            Liste::Historique(v) => match v.get(k) {
                                Some(h) => (h.clone(), "", crate::tr!("saisie d'avant", "past entry")),
                                None => continue,
                            },
                            Liste::Rien => continue,
                        };
                        let peintre = ui.painter();
                        peintre.text(
                            pos2(rect.left() + 10.0, rect.top() + 12.0),
                            Align2::LEFT_CENTER,
                            &nom,
                            mono(13.0),
                            if choisi { p.accent } else { p.encre },
                        );
                        peintre.text(
                            pos2(rect.right() - 10.0, rect.top() + 12.0),
                            Align2::RIGHT_CENTER,
                            droite,
                            police(11.0),
                            p.discret,
                        );
                        let g = coupee(ui, dessous, police(12.0), p.doux, largeur - 20.0);
                        peintre.galley(pos2(rect.left() + 10.0, rect.top() + 22.0), g, p.doux);
                        if rep.clicked() {
                            clic = Some(k);
                        }
                        rep.on_hover_cursor(egui::CursorIcon::PointingHand);
                    }
                    let note = match l {
                        Liste::Historique(_) => crate::tr!(
                            "↑ ↓ choisir · Entrée reprendre (sans lancer) · Échap revenir",
                            "↑ ↓ pick · Enter take (without running) · Esc go back"
                        ),
                        _ => crate::tr!(
                            "↑ ↓ choisir · Entrée lancer la suggestion choisie · Échap fermer",
                            "↑ ↓ pick · Enter run the picked suggestion · Esc close"
                        ),
                    };
                    ui.add_space(2.0);
                    ui.label(RichText::new(note).font(police(11.0)).color(p.discret));
                });
        });
    let dessus = sortie.response.contains_pointer();
    (clic, dessus)
}

/// Le bord du bas se tire pour régler la hauteur (gardée le temps de la session).
fn tirer(ui: &Ui, r: Rect, montrees: usize, b: &mut Bande) {
    let p = pal();
    let bord = Rect::from_min_max(pos2(r.left(), r.bottom() - 5.0), r.right_bottom());
    let rep = ui.interact(bord, ui.scope_id().with("tirer"), Sense::drag());
    if rep.drag_started() {
        b.tiree = HAUTEUR_LIGNE * n_f32(montrees);
    }
    if rep.dragged() {
        b.tiree += rep.drag_delta().y;
        b.lignes = f32_n((b.tiree / HAUTEUR_LIGNE).round()).max(LIGNES_MIN);
    }
    let s = survol(ui, rep.id, rep.hovered() || rep.dragged());
    if s > 0.0 {
        ui.painter().line_segment(
            [pos2(r.left(), r.bottom() - 1.0), pos2(r.right(), r.bottom() - 1.0)],
            Stroke::new(2.0, p.accent.gamma_multiply(s)),
        );
    }
    rep.on_hover_cursor(egui::CursorIcon::ResizeVertical);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Une image de la fenêtre entière.
    fn image(ctx: &egui::Context, appli: &mut Appli, t: f64, evenements: Vec<egui::Event>) -> egui::FullOutput {
        let entree = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(1280.0, 800.0))),
            time: Some(t),
            events: evenements,
            ..Default::default()
        };
        let mut sortie = ctx.run_ui(entree, |ui| super::super::cadre::tout(appli, ui));
        sortie.textures_delta.clear();
        sortie
    }

    fn touche(key: Key, modifiers: Modifiers) -> egui::Event {
        egui::Event::Key {
            key,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers,
        }
    }

    fn textes(sortie: &egui::FullOutput) -> Vec<String> {
        sortie
            .shapes
            .iter()
            .filter_map(|c| match &c.shape {
                egui::Shape::Text(t) => Some(t.galley.text().to_owned()),
                _ => None,
            })
            .collect()
    }

    /// Une faute dans la saisie propose la commande proche, sans rien lancer ; Échap ferme la liste sans quitter le
    /// champ ; ↓ puis Entrée prend la suggestion et la fait passer par `saisir` (la liste fermée). Sans programme :
    /// rien ne tourne jamais, la console le dit.
    #[test]
    fn une_faute_propose_sans_lancer() {
        let ctx = egui::Context::default();
        super::super::polices(&ctx);
        let mut a = Appli::nouvelle(Err("absent".into()), std::sync::Arc::new(|| {}));
        let mut t = 1.0;
        let mut pas = |a: &mut Appli, e: Vec<egui::Event>| {
            t += 0.05;
            textes(&image(&ctx, a, t, e))
        };
        pas(&mut a, Vec::new());
        // La saisie : sous l'en-tête (36), les six lignes et leur vide (132), à 64 du haut de la fenêtre.
        let champ = egui::pos2(400.0, 64.0 + 36.0 + 132.0 + 22.0);
        let bouton = |pressed| egui::Event::PointerButton {
            pos: champ,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: Modifiers::NONE,
        };
        pas(&mut a, vec![egui::Event::PointerMoved(champ)]);
        pas(&mut a, vec![bouton(true)]);
        pas(&mut a, vec![bouton(false)]);
        pas(&mut a, vec![egui::Event::Text("bilna".into())]);
        let vu = pas(&mut a, Vec::new());
        let bilan = Commande::Bilan.nom_affiche().to_owned();
        assert_eq!(a.saisie, "bilna");
        assert!(vu.contains(&bilan), "pas de suggestion : {vu:?}");
        assert_eq!(a.taches(), 0);
        assert!(a.historique().is_empty(), "rien n'est saisi sans Entrée");
        // Échap : la liste se ferme, le champ garde le curseur et le texte.
        pas(&mut a, vec![touche(Key::Escape, Modifiers::NONE)]);
        let vu = pas(&mut a, Vec::new());
        assert!(!vu.contains(&bilan), "la liste reste ouverte");
        assert!(ctx.memory(|m| m.focused().is_some()));
        assert_eq!(a.saisie, "bilna");
        // Une frappe la rouvre ; ↓ choisit, Entrée la prend : la saisie passe par `saisir`.
        pas(&mut a, vec![egui::Event::Text("n".into())]);
        pas(&mut a, vec![touche(Key::Backspace, Modifiers::NONE)]);
        pas(&mut a, vec![touche(Key::ArrowDown, Modifiers::NONE)]);
        pas(&mut a, vec![touche(Key::Enter, Modifiers::NONE)]);
        pas(&mut a, Vec::new());
        assert_eq!(a.historique(), [bilan.as_str()]);
        assert_eq!(a.taches(), 0);
        assert!(a.console.dit("absent"));
    }

    /// Ctrl+F ouvre la recherche, Échap la ferme ; un filtre cliqué ne garde que ses places ; rien ne se lance.
    #[test]
    fn la_recherche_et_les_filtres() {
        let ctx = egui::Context::default();
        super::super::polices(&ctx);
        let mut a = Appli::pour_captures();
        let mut t = 1.0;
        let mut pas = |a: &mut Appli, e: Vec<egui::Event>| {
            t += 0.05;
            textes(&image(&ctx, a, t, e))
        };
        pas(&mut a, Vec::new());
        pas(&mut a, vec![touche(Key::F, Modifiers::COMMAND)]);
        pas(&mut a, Vec::new());
        assert!(bande_de(&ctx).cherche.is_some());
        assert_eq!(ctx.memory(egui::Memory::focused), Some(id_cherche()));
        pas(&mut a, vec![touche(Key::Escape, Modifiers::NONE)]);
        assert!(bande_de(&ctx).cherche.is_none());
        assert_eq!(a.taches(), 0);
    }

    #[test]
    fn depuis_dit_le_temps_en_mots() {
        crate::langue::choisir(Some(false));
        assert_eq!(depuis(Duration::from_secs(5)), "à l'instant");
        assert_eq!(depuis(Duration::from_secs(180)), "il y a 3 min");
        assert_eq!(depuis(Duration::from_secs(7200)), "il y a 2 h");
    }

    #[test]
    fn une_suggestion_choisie_garde_aide() {
        assert_eq!(
            saisie_de("aide bilna", Commande::Bilan),
            format!("aide {}", Commande::Bilan.nom_affiche())
        );
        assert_eq!(saisie_de("bilna", Commande::Bilan), Commande::Bilan.nom_affiche());
    }
}

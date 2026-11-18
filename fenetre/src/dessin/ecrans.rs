//! Les écrans : chacun lit l'état d'`Appli` et ne demande que ses gestes (`demander`, `arreter`). Ce qui n'existe
//! pas encore dans la fenêtre le dit, au lieu d'un bouton qui ne ferait rien.

use eframe::egui::{
    Align, Color32, Frame, Id, Layout, Margin, Response, RichText, Role, Sense, Stroke, TextStyle, TextWrapMode, Ui,
    WidgetInfo, WidgetText, pos2, vec2,
};

use super::bilan::{self, couleur_gravite};
use super::vide;
use super::{
    bouton, carte, entete, mono, moyenne, pal, petit, signale, signale_avec, texte, texte_et_boutons, titre_section,
};
use crate::appli::{Appli, Contenu, Ecran, ecran_de};
use crate::commandes::{Commande, Rubrique};
use crate::donnees::appareils::{self as scan, Empoisonnement, Upnp};
use crate::donnees::changements::{self, Etat};
use crate::donnees::evenements;
use crate::donnees::libre;
use crate::donnees::protection::{self, Allure};

/// Événements du journal montrés au plus (les plus récents).
const EVENEMENTS_MAX: usize = 200;

/// Appareils et redirections montrés au plus : un réseau de maison en a bien moins ; au-delà, l'écran resterait
/// lisible mais lent à dessiner à chaque image.
const APPAREILS_MAX: usize = 300;

/// La largeur utile (à droite du rail et hors des coulisses) d'où une rubrique montre sa liste et sa page côte à
/// côte ; en dessous, ses cartes.
pub const LARGEUR_LISTE_ET_PAGE: f32 = 900.0;
/// La largeur de la liste d'une rubrique, à gauche de sa page.
pub const LARGEUR_LISTE: f32 = 260.0;

/// L'écran montré ; `detail` : la page d'une commande à côté de la liste de sa rubrique (fenêtre large).
pub fn montrer(appli: &mut Appli, ui: &mut Ui, detail: Option<Commande>) {
    if appli.retour().is_some() {
        let rep = petit(ui, crate::tr!("← Retour", "← Back"), true)
            .on_hover_text(crate::tr!(
                "L'écran d'avant (Alt+←, Échap, ou le bouton Précédent de la souris)",
                "The previous screen (Alt+←, Esc, or the mouse Back button)"
            ))
            .on_hover_cursor(eframe::egui::CursorIcon::PointingHand);
        if rep.clicked() {
            appli.revenir();
            return;
        }
        ui.add_space(12.0);
    }
    if let Some(c) = detail {
        return page(appli, ui, c);
    }
    match appli.ecran {
        Ecran::Accueil => accueil(appli, ui),
        Ecran::Bilan | Ecran::Commande(Commande::Bilan) => bilan::ecran(appli, ui),
        Ecran::Alertes | Ecran::Commande(Commande::Evenements) => alertes(appli, ui),
        Ecran::Appareils | Ecran::Commande(Commande::Appareils) => appareils(appli, ui),
        Ecran::Rubrique(Rubrique::Vanguard) => reglages(appli, ui),
        Ecran::Rubrique(r) => rubrique(appli, ui, r),
        Ecran::Commande(c) => commande(appli, ui, c),
        Ecran::Guide => guide(appli, ui),
    }
}

/// La page d'une commande, seule ou à côté de la liste de sa rubrique : la même dans les deux cas.
fn page(appli: &mut Appli, ui: &mut Ui, c: Commande) {
    match c {
        Commande::Bilan => bilan::ecran(appli, ui),
        Commande::Evenements => alertes(appli, ui),
        Commande::Appareils => appareils(appli, ui),
        c => commande(appli, ui, c),
    }
}

/// La liste d'une rubrique, à gauche de la page de `montree` (fenêtre large) : une ligne par commande, son titre et
/// son état en court. Un clic montre sa page à droite (`Appli::choisir` : rien de plus dans « Retour ») ; un
/// double-clic la montre et la relance.
pub fn liste_rubrique(appli: &mut Appli, ui: &mut Ui, montree: Commande) {
    let p = pal();
    let r = montree.rubrique();
    ui.spacing_mut().item_spacing.y = 4.0;
    ui.label(RichText::new(r.nom()).font(moyenne(18.0)).color(p.encre));
    ui.add_space(14.0);
    let largeur = ui.available_width() - 16.0;
    for c in r.commandes() {
        let choisie = c == montree;
        let tourne = tourne(appli, c);
        let titre = ui
            .painter()
            .layout(c.titre().to_owned(), moyenne(14.0), p.encre, largeur - 24.0);
        let etat_couleur = if tourne { p.accent } else { p.discret };
        let etat = ui
            .painter()
            .layout(etat_court(appli, c), super::police(12.0), etat_couleur, largeur - 24.0);
        let hauteur = 10.0 + titre.size().y + 2.0 + etat.size().y + 10.0;
        let zone = ui.allocate_space(vec2(largeur, hauteur)).1;
        let rep = ui.interact(zone, id_de_ligne(c), Sense::click());
        let vif = if choisie {
            1.0
        } else {
            super::survol(ui, rep.id, rep.hovered())
        };
        let peintre = ui.painter();
        if vif > 0.0 {
            peintre.rect_filled(zone, 8, p.s2.gamma_multiply(vif));
        }
        if choisie {
            let trait_ =
                eframe::egui::Rect::from_min_size(zone.left_top() + vec2(0.0, 10.0), vec2(3.0, hauteur - 20.0));
            peintre.rect_filled(trait_, 2, p.accent);
        }
        let encre = if choisie {
            p.encre
        } else {
            p.doux.lerp_to_gamma(p.encre, vif)
        };
        let haut_etat = zone.top() + 10.0 + titre.size().y + 2.0;
        peintre.galley(zone.left_top() + vec2(12.0, 10.0), titre, encre);
        peintre.galley(pos2(zone.left() + 12.0, haut_etat), etat, etat_couleur);
        rep.widget_info(|| WidgetInfo::selected(Role::Button, true, choisie, c.titre()));
        super::clavier::anneau(ui, &rep, 8.0);
        if rep.double_clicked() {
            appli.choisir(c);
            appli.relancer(c);
        } else if rep.clicked() {
            appli.choisir(c);
        }
        rep.on_hover_cursor(eframe::egui::CursorIcon::PointingHand)
            .on_hover_text(crate::trf!(
                "Montrer {} à droite · double-clic : la relancer · ↑ ↓ : une autre commande · Entrée ou F5 : relancer",
                "Show {} on the right · double-click: run it again · ↑ ↓: another command · Enter or F5: run again",
                c.titre()
            ));
    }
}

/// L'identifiant de la ligne d'une commande dans la liste : le même d'une image à l'autre, pour y garder le focus.
fn id_de_ligne(c: Commande) -> Id {
    Id::unique(("ligne-de-la-liste", c))
}

/// L'état d'une commande dans la liste, en court : en cours, en attente, ou depuis quand elle est lue.
fn etat_court(appli: &Appli, c: Commande) -> String {
    if tourne(appli, c) {
        return crate::tr!("En cours", "Running").into();
    }
    if appli.en_attente(c) {
        return crate::tr!("En attente", "Queued").into();
    }
    match appli.resultat(c) {
        Some(r) if matches!(r.contenu, Contenu::Erreur(_)) => {
            crate::trf!("Échec {}", "Failed {}", super::console::depuis(r.fin.elapsed()))
        }
        Some(r) => crate::trf!("Lu {}", "Read {}", super::console::depuis(r.fin.elapsed())),
        None => crate::tr!("Pas encore lancée", "Not run yet").into(),
    }
}

/// Le clavier de la liste d'une rubrique, quand rien n'a le focus ou qu'il est sur une ligne de la liste (pas sur la
/// saisie de la console ni sur un bouton : ses flèches et Entrée sont à lui) et qu'aucune confirmation n'est
/// ouverte : ↑ et ↓ montrent la commande d'avant ou d'après (le focus suit, s'il était sur la liste), Entrée ou F5
/// relance celle montrée (la garde du bouton : `Appli::relancer`). F5 vaut aussi quand un bouton a le focus, jamais
/// pendant une saisie.
///
/// `champ_au_debut` : un champ de texte (la saisie de la console, sa recherche) avait le focus au début de l'image.
/// Un champ d'une ligne lâche le focus sur Entrée sans manger la touche : sans cette mémoire, l'Entrée qui valide la
/// saisie ou la recherche relançait aussi la page. Dans une telle image, ni flèche, ni Entrée, ni F5 ne sont pris.
pub fn clavier_de_la_liste(appli: &mut Appli, ctx: &eframe::egui::Context, montree: Commande, champ_au_debut: bool) {
    use eframe::egui::{Key, Modifiers};
    if appli.feuille_correction().is_some() || appli.confirmation().is_some() || appli.confirmation_couleurs().is_some()
    {
        return;
    }
    let liste: Vec<Commande> = montree.rubrique().commandes().collect();
    let sur_la_liste = ctx.memory(|m| m.focused().map(|f| liste.iter().any(|c| id_de_ligne(*c) == f)));
    let saisie = champ_au_debut || ctx.text_edit_focused();
    let libre = !saisie && sur_la_liste != Some(false);
    let (haut, bas, entree, f5) = ctx.input_mut(|i| {
        (
            libre && i.consume_key(Modifiers::NONE, Key::ArrowUp),
            libre && i.consume_key(Modifiers::NONE, Key::ArrowDown),
            libre && i.consume_key(Modifiers::NONE, Key::Enter),
            !saisie && i.consume_key(Modifiers::NONE, Key::F5),
        )
    });
    let ici = liste.iter().position(|c| *c == montree).unwrap_or(0);
    let voisine = if haut {
        ici.checked_sub(1)
    } else if bas {
        Some(ici + 1)
    } else {
        None
    };
    if let Some(c) = voisine.and_then(|k| liste.get(k)) {
        appli.choisir(*c);
        if sur_la_liste == Some(true) {
            ctx.memory_mut(|m| m.request_focus(id_de_ligne(*c)));
        }
    }
    if entree || f5 {
        appli.relancer(montree);
    }
}

/// Une carte qu'on clique toute entière pour ouvrir un écran, d'un seul geste : au survol, son contour prend
/// l'accent en fondu et la souris devient une main ; au clavier, Tab s'y arrête (l'anneau du focus) et Entrée ou
/// Espace l'ouvre. `contenu` reçoit la part de survol (de 0 à 1) pour éclairer son « Ouvrir → » ; `nom` est ce qu'un
/// lecteur d'écran en dit.
fn carte_qui_ouvre(ui: &mut Ui, id: Id, nom: &str, contenu: impl FnOnce(&mut Ui, f32)) -> Response {
    let p = pal();
    let s = super::survol(ui, id, ui.ctx().read_response(id).is_some_and(|r| r.hovered()));
    let cadre = Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(1.0, super::bord_survole(&p, s)))
        .shadow(super::ombre())
        .corner_radius(super::RAYON_CARTE)
        .inner_margin(Margin::same(20))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            contenu(ui, s);
        })
        .response
        .rect;
    let rep = ui
        .interact(cadre, id, Sense::click())
        .on_hover_cursor(eframe::egui::CursorIcon::PointingHand);
    rep.widget_info(|| WidgetInfo::labeled(Role::Button, true, nom));
    super::clavier::anneau(ui, &rep, f32::from(super::RAYON_CARTE));
    rep
}

/// « Ouvrir → », le mot d'une carte qui s'ouvre : discret au repos, à l'encre sous la souris.
fn mot_ouvrir(s: f32) -> RichText {
    let p = pal();
    texte(
        &format!("{} →", crate::tr!("Ouvrir", "Open")),
        12.0,
        p.discret.lerp_to_gamma(p.encre, s),
    )
}

/// Une tuile de la vue d'ensemble : « Ouvrir → » en bas le dit.
fn tuile(appli: &mut Appli, ui: &mut Ui, titre: &str, valeur: &str, phrase: &str, couleur: Color32, vers: Ecran) {
    let p = pal();
    let id = ui.make_persistent_id(("tuile", titre));
    let rep = carte_qui_ouvre(ui, id, titre, |ui, s| {
        ui.label(texte(titre, 13.0, p.doux));
        ui.add_space(4.0);
        // La valeur s'écrit à l'encre ; un état à signaler (couleur vive) met un point devant.
        let valeur = RichText::new(valeur).font(moyenne(24.0)).color(p.encre);
        if couleur == p.encre {
            // La hauteur de la ligne signalée (`signale_avec`) : avec ou sans point, les tuiles ont la même.
            ui.horizontal_top(|ui| {
                ui.set_min_height(24.0 * 1.3);
                ui.label(valeur);
            });
        } else {
            signale_avec(ui, couleur, 24.0, |ui| {
                ui.label(valeur);
            });
        }
        ui.add_space(4.0);
        ui.label(texte(phrase, 13.0, p.doux));
        ui.add_space(16.0);
        ui.label(mot_ouvrir(s));
    });
    if rep.clicked() {
        appli.aller(vers);
    }
}

fn accueil(appli: &mut Appli, ui: &mut Ui) {
    let p = pal();
    entete(
        ui,
        crate::tr!("Vue d'ensemble", "Overview"),
        crate::tr!(
            "Ce que Vanguard a lu sur cet ordinateur. Rien n'est changé d'ici.",
            "What Vanguard read on this computer. Nothing is changed from here."
        ),
    );
    ui.add_space(24.0);
    let (bilan_v, bilan_p, bilan_c) = match (appli.bilan(), appli.en_cours()) {
        (_, Some((Commande::Bilan, _))) => (crate::tr!("En cours", "Running").to_string(), String::new(), p.accent),
        (Some(v), _) => (
            v.note.map_or_else(
                || crate::tr!("Sans note", "No score").to_string(),
                |n| format!("{n}/100"),
            ),
            v.resume(),
            // Des points non vérifiés : la note en couleur d'alerte, comme dans le bilan.
            if v.note_incomplete().is_some() {
                p.moyen
            } else {
                p.encre
            },
        ),
        (None, _) => (
            crate::tr!("Pas encore", "Not yet").to_string(),
            crate::tr!(
                "Une note sur 100, en quelques secondes.",
                "A score out of 100, in a few seconds."
            )
            .to_string(),
            p.gris,
        ),
    };
    let (prot_v, prot_p, prot_c) = match appli.protection() {
        None => (
            crate::tr!("Pas lue", "Not read").to_string(),
            crate::tr!(
                "Pare-feu, antivirus et gardes du système.",
                "Firewall, antivirus and system guards."
            )
            .to_string(),
            p.gris,
        ),
        Some(v) => (
            crate::trn!(v.compte(Allure::Allume), "allumé", "allumés", "on", "on"),
            format!(
                "{}, {}",
                crate::trn!(v.compte(Allure::Eteint), "éteint", "éteints", "off", "off"),
                crate::trn!(
                    v.compte(Allure::Nuance),
                    "autre état",
                    "autres états",
                    "other state",
                    "other states"
                )
            ),
            if v.compte(Allure::Eteint) > 0 { p.moyen } else { p.encre },
        ),
    };
    let (jour_v, jour_p, jour_c) = match appli.journal() {
        None => (
            crate::tr!("Pas lu", "Not read").to_string(),
            crate::tr!(
                "Les alertes et les gestes de Vanguard.",
                "Vanguard's alerts and actions."
            )
            .to_string(),
            p.gris,
        ),
        Some(j) => (
            crate::trn!(j.alertes().count(), "alerte", "alertes", "alert", "alerts"),
            j.etat.phrase().to_string(),
            j.etat.gravite().map_or(p.encre, |g| couleur_gravite(Some(g))),
        ),
    };
    let tuiles = [
        (crate::tr!("Bilan", "Check"), bilan_v, bilan_p, bilan_c, Ecran::Bilan),
        (
            crate::tr!("Protection", "Protection"),
            prot_v,
            prot_p,
            prot_c,
            Ecran::Commande(Commande::Protection),
        ),
        (crate::tr!("Journal", "Log"), jour_v, jour_p, jour_c, Ecran::Alertes),
    ];
    let large = ui.available_width() >= 900.0;
    // Entre deux tuiles, le même écart que sous elles (16) : à 8, les trois cartes se touchaient presque.
    if large {
        ui.scope(|ui| {
            ui.spacing_mut().item_spacing.x = 16.0;
            ui.columns(3, |cols| {
                for (col, (t, v, ph, c, e)) in cols.iter_mut().zip(tuiles) {
                    tuile(appli, col, t, &v, &ph, c, e);
                }
            });
        });
    } else {
        for (t, v, ph, c, e) in tuiles {
            tuile(appli, ui, t, &v, &ph, c, e);
            ui.add_space(16.0);
        }
    }
    // Dans une grande fenêtre, une deuxième rangée : le dernier bilan par sujet et les dernières alertes.
    if large && super::ensemble::a_sa_place(appli, ui.ctx().content_rect()) {
        ui.add_space(8.0);
        super::ensemble::rangee(appli, ui);
    }
    ui.add_space(32.0);
    titre_section(ui, crate::tr!("Relire", "Read again"), None);
    ui.horizontal_wrapped(|ui| {
        for c in [
            Commande::Bilan,
            Commande::Protection,
            Commande::Evenements,
            Commande::Diagnostic,
        ] {
            if bouton(ui, c.titre(), false, appli.programme_trouve()).clicked() {
                appli.demander(c);
                appli.aller(ecran_de(c));
            }
        }
    });
    ui.add_space(16.0);
    ui.label(texte(
        crate::tr!(
            "Ici : le démarrage, les corrections du compte et leur remise comme avant, la mise à jour. Le reste de ce qui change l'ordinateur (corrections de tout l'ordinateur, réglages, quarantaine) reste dans le menu de Vanguard pour l'instant : il arrive ici lot par lot, avec les mêmes garde-fous.",
            "Here: startup, account fixes and putting them back, the update. The rest of what changes the computer (whole-computer fixes, settings, quarantine) stays in Vanguard's menu for now: it comes here batch by batch, with the same safeguards."
        ),
        13.0,
        p.discret,
    ));
}

/// Une ligne d'état sous un titre : en cours, en attente, ou l'heure du dernier résultat.
pub(super) fn etat_commande(appli: &Appli, c: Commande) -> String {
    match appli.en_cours() {
        Some((e, d)) if e == c => {
            return crate::trf!("En cours depuis {:.0} s", "Running for {:.0} s", d.as_secs_f32());
        }
        _ => {}
    }
    if appli.en_attente(c) {
        return crate::tr!("En attente de son tour", "Waiting for its turn").into();
    }
    match appli.resultat(c) {
        Some(r) => crate::trf!(
            "Fini à {} en {}",
            "Finished at {} in {}",
            r.heure,
            crate::langue::secondes(r.duree.as_secs_f32())
        ),
        None => crate::tr!("Pas encore lancée", "Not run yet").into(),
    }
}

/// La commande `c` est-elle celle qui tourne ?
fn tourne(appli: &Appli, c: Commande) -> bool {
    appli.en_cours().is_some_and(|(e, _)| e == c)
}

/// L'état d'une commande (`etat_commande`), en une ligne : pendant qu'elle tourne, un point d'accent qui pulse devant, et l'état en
/// couleur d'accent (les images suivent, seulement tant qu'elle tourne).
fn ligne_etat(ui: &mut Ui, etat: String, tourne: bool) {
    let p = pal();
    if !tourne {
        ui.label(RichText::new(etat).font(mono(12.0)).color(p.discret));
        return;
    }
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        let (z, _) = ui.allocate_exact_size(vec2(10.0, 14.0), Sense::hover());
        let temps = ui.ctx().input(|i| i.time);
        super::mouvement::pouls(
            ui.painter(),
            temps,
            z.center(),
            3.0,
            p.accent,
            super::mouvement::POULS_TACHE,
        );
        super::mouvement::tourne(ui.ctx());
        ui.label(RichText::new(etat).font(mono(12.0)).color(p.encre));
    });
}

/// Le titre d'une commande, son bouton et son état. Jamais lancée et pas en route : ni bouton ni état ici, la carte
/// vide en dessous les porte (un seul « Lancer » à l'écran).
fn entete_commande(appli: &mut Appli, ui: &mut Ui, c: Commande) {
    let vierge = appli.resultat(c).is_none() && !tourne(appli, c) && !appli.en_attente(c);
    texte_et_boutons(
        ui,
        c.nom(),
        |ui| entete(ui, c.titre(), c.description()),
        |ui| {
            if !vierge {
                lancer_arreter(appli, ui, c);
            }
        },
    );
    if !vierge {
        ligne_etat(ui, etat_commande(appli, c), tourne(appli, c));
    }
}

/// Lancer (« quelques minutes » pour une lecture longue jamais lue), Relancer, ou Arrêter si c'est elle qui tourne.
fn lancer_arreter(appli: &mut Appli, ui: &mut Ui, c: Commande) {
    let tourne = appli.en_cours().is_some_and(|(e, _)| e == c);
    if tourne {
        if bouton(ui, crate::tr!("Arrêter", "Stop"), false, true).clicked() {
            appli.arreter();
        }
    } else {
        // Jamais lue : une lecture qui dure (plus de `LECTURE_RAPIDE`) le dit, puisqu'elle ne part pas seule ; un scan
        // du réseau, court, ne part pas seul non plus mais dit simplement « Lancer » (sa page dit sa durée).
        let t = if appli.resultat(c).is_some() {
            crate::tr!("Relancer", "Run again")
        } else if c.delai() > crate::appli::LECTURE_RAPIDE {
            crate::tr!("Lancer (quelques minutes)", "Run (a few minutes)")
        } else {
            crate::tr!("Lancer", "Run")
        };
        if bouton(ui, t, true, appli.programme_trouve() && !appli.en_attente(c)).clicked() {
            appli.demander(c);
        }
    }
}

fn rubrique(appli: &mut Appli, ui: &mut Ui, r: Rubrique) {
    let p = pal();
    entete(ui, r.nom(), "");
    ui.add_space(24.0);
    let commandes: Vec<Commande> = r.commandes().collect();
    if commandes.is_empty() {
        carte(ui, 24, |ui| {
            ui.set_width(ui.available_width());
            ui.label(texte(
                crate::tr!(
                    "Cette rubrique arrive dans un prochain lot. Pour l'instant : le menu de Vanguard.",
                    "This section comes in a later batch. For now: Vanguard's menu."
                ),
                14.0,
                p.doux,
            ));
        });
        return;
    }
    cartes_commandes(appli, ui, commandes);
}

/// Une carte par commande : son titre, ce qu'elle fait et son état ; toute la carte ouvre la page de la commande
/// (`carte_qui_ouvre`), qui seule porte Lancer, Relancer ou Arrêter : un geste par carte, pas deux boutons côte à
/// côte.
fn cartes_commandes(appli: &mut Appli, ui: &mut Ui, commandes: Vec<Commande>) {
    let p = pal();
    for c in commandes {
        let (etat, tourne) = (etat_commande(appli, c), tourne(appli, c));
        let id = ui.make_persistent_id(("carte-commande", c.nom()));
        let rep = carte_qui_ouvre(ui, id, c.titre(), |ui, s| {
            let fleche = WidgetText::from(mot_ouvrir(s)).into_galley(
                ui,
                Some(TextWrapMode::Extend),
                f32::INFINITY,
                TextStyle::Body,
            );
            ui.horizontal(|ui| {
                let ecart = 16.0 + 2.0 * ui.spacing().item_spacing.x;
                ui.vertical(|ui| {
                    ui.set_width((ui.available_width() - fleche.size().x - ecart).max(160.0));
                    ui.label(RichText::new(c.titre()).font(moyenne(16.0)).color(p.encre));
                    ui.label(texte(c.description(), 13.0, p.doux));
                    ligne_etat(ui, etat, tourne);
                });
                ui.add_space(16.0);
                ui.label(fleche);
            });
        });
        let rep = rep.on_hover_text(crate::trf!(
            "Ouvrir la page {} : on l'y lance ; une lecture rapide pas lue depuis une heure s'y relance seule",
            "Open the {} page: run it from there; a quick read not done in the last hour runs again by itself",
            c.titre()
        ));
        if rep.clicked() {
            appli.aller(ecran_de(c));
        }
        ui.add_space(12.0);
    }
}

fn commande(appli: &mut Appli, ui: &mut Ui, c: Commande) {
    let p = pal();
    entete_commande(appli, ui, c);
    ui.add_space(24.0);
    let Some(r) = appli.resultat(c).cloned() else {
        vide::carte_vide(
            ui,
            c.rubrique(),
            crate::tr!("Rien de lu pour l'instant", "Nothing read yet"),
            crate::tr!(
                "Une lecture seule : rien n'est changé sur cet ordinateur. Ce qu'elle trouve s'affiche ici et dans la console.",
                "Read only: nothing on this computer is changed. What it finds shows here and in the console."
            ),
            |ui| lancer_arreter(appli, ui, c),
        );
        return;
    };
    match &r.contenu {
        Contenu::Constats(v) if c == Commande::Demarrage => super::demarrage::liste(appli, ui, v),
        Contenu::Constats(v) => {
            ui.label(texte(&v.resume(), 14.0, p.doux));
            ui.add_space(16.0);
            // Les outils n'offrent pas de geste : seul l'écran du bilan voit une correction.
            let _ = bilan::constats(ui, v, false);
        }
        Contenu::Protection(v) => protection_liste(ui, v),
        Contenu::Libre(v) => libre_liste(ui, v),
        Contenu::Changements(v) => changements_liste(appli, ui, v),
        Contenu::Evenements(v) => journal(ui, v),
        Contenu::Appareils(v) => appareils_liste(ui, v),
        Contenu::Erreur(e) => erreur(ui, e),
    }
}

/// « Ce que Vanguard a changé » : les lignes du relevé, les plus récentes d'abord, chacune avec son état ; « Remettre
/// comme avant » sur celles que Vanguard offre d'annuler d'ici (une feuille d'aperçu s'ouvre : rien ne change avant
/// d'y accepter).
fn changements_liste(appli: &mut Appli, ui: &mut Ui, v: &changements::Vue) {
    let p = pal();
    ui.label(texte(&v.resume(), 14.0, p.doux));
    ui.add_space(12.0);
    if !v.releve_sain() {
        signale(
            ui,
            p.jaune,
            crate::tr!(
                "Le relevé ne s'est pas relu tel que Vanguard l'a scellé : ses lignes sont à prendre avec prudence.",
                "The record did not read back as Vanguard sealed it: take its lines with care."
            ),
            14.0,
        );
        ui.add_space(8.0);
    }
    let mut voir = None;
    carte(ui, 20, |ui| {
        ui.set_width(ui.available_width());
        if v.lignes.is_empty() {
            ui.label(texte(
                crate::tr!(
                    "Vanguard n'a encore rien changé.",
                    "Vanguard has not changed anything yet."
                ),
                14.0,
                p.doux,
            ));
        }
        for (i, l) in v.lignes.iter().enumerate() {
            if i > 0 {
                ui.add_space(10.0);
            }
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(&l.date).font(mono(12.0)).color(p.discret));
                let couleur = match l.etat {
                    Etat::Interrompue | Etat::Echoue | Etat::Inconnu => p.jaune,
                    Etat::Annulable | Etat::EnPlace | Etat::Fait => p.bon,
                    _ => p.discret,
                };
                ui.label(RichText::new(l.etat.nom()).font(moyenne(12.0)).color(couleur));
            });
            ui.label(texte(&l.texte, 14.0, p.encre));
            if l.douteuse {
                signale(
                    ui,
                    p.jaune,
                    crate::tr!(
                        "Changée hors de Vanguard, ou d'avant son sceau : rien ne s'y offre d'ici.",
                        "Changed outside Vanguard, or from before its seal: nothing is offered here."
                    ),
                    13.0,
                );
            }
            if let Some(j) = l.annulation
                && bouton(ui, crate::tr!("Remettre comme avant", "Restore as before"), false, true).clicked()
            {
                voir = Some(j);
            }
        }
        if v.illisibles > 0 {
            ui.add_space(10.0);
            signale(
                ui,
                p.jaune,
                &crate::trf!(
                    "{} ne se lit pas : non montré.",
                    "{} could not be read: not shown.",
                    crate::trn!(v.illisibles, "ligne", "lignes", "line", "lines")
                ),
                13.0,
            );
        }
        if v.plus_anciens > 0 {
            ui.add_space(10.0);
            ui.label(texte(
                &crate::trf!(
                    "Et {} plus anciens, dans « vanguard changements » au terminal.",
                    "And {} older ones, in “vanguard changements” in the terminal.",
                    v.plus_anciens
                ),
                13.0,
                p.discret,
            ));
        }
    });
    if let Some(j) = voir {
        appli.voir_annulation(j);
    }
}

/// L'écran des appareils : le dernier scan du réseau local, appareil par appareil.
fn appareils(appli: &mut Appli, ui: &mut Ui) {
    let c = Commande::Appareils;
    entete_commande(appli, ui, c);
    ui.add_space(24.0);
    match appli.resultat(c).map(|r| r.contenu.clone()) {
        Some(Contenu::Appareils(v)) => appareils_liste(ui, &v),
        Some(Contenu::Erreur(e)) => erreur(ui, &e),
        // Une autre forme ne vient pas d'`appareils` : rien à en montrer ici.
        Some(_) | None => vide::carte_vide(
            ui,
            c.rubrique(),
            crate::tr!("Pas encore de scan", "No scan yet"),
            crate::tr!(
                "Le scan liste les appareils de votre réseau local et leurs ports ouverts, en une dizaine de secondes. Rien n'est changé.",
                "The scan lists the devices on your local network and their open ports, in about ten seconds. Nothing is changed."
            ),
            |ui| lancer_arreter(appli, ui, c),
        ),
    }
}

fn appareils_liste(ui: &mut Ui, v: &scan::Vue) {
    let p = pal();
    ui.label(texte(&v.resume(), 14.0, p.doux));
    if !v.reseau.is_empty() {
        ui.label(RichText::new(&v.reseau).font(mono(12.0)).color(p.discret));
    }
    ui.add_space(16.0);
    let manques = v.manques();
    if !manques.is_empty() {
        carte(ui, 20, |ui| {
            ui.set_width(ui.available_width());
            signale_avec(ui, p.moyen, 15.0, |ui| {
                ui.label(
                    RichText::new(crate::tr!("Pas pu vérifier", "Could not check"))
                        .font(moyenne(15.0))
                        .color(p.encre),
                );
            });
            for m in &manques {
                ui.label(texte(m, 13.0, p.doux));
            }
        });
        ui.add_space(16.0);
    }
    reseau_entier(ui, v);
    titre_section(ui, crate::tr!("Appareils", "Devices"), Some(v.appareils.len()));
    if v.appareils.is_empty() {
        vide::carte_vide(
            ui,
            Rubrique::Reseau,
            crate::tr!("Aucun appareil trouvé", "No device found"),
            crate::tr!(
                "Rien d'autre n'a répondu sur ce réseau. Un appareil éteint ou en veille ne répond pas : relancez quand il est allumé.",
                "Nothing else answered on this network. A device that is off or asleep does not answer: run again once it is on."
            ),
            |_| {},
        );
    } else {
        carte(ui, 20, |ui| {
            ui.set_width(ui.available_width());
            for (k, a) in v.appareils.iter().take(APPAREILS_MAX).enumerate() {
                if k > 0 {
                    ui.separator();
                }
                ui.push_id(k, |ui| {
                    super::mouvement::ligne(ui, vec2(8.0, 2.0), 6.0, |ui| appareil(ui, a));
                });
            }
        });
    }
    if v.appareils.len() > APPAREILS_MAX {
        ui.label(texte(
            &crate::trf!(
                "Les {} premiers seulement : le reste, dans le menu de Vanguard.",
                "The first {} only: the rest, in Vanguard's menu.",
                APPAREILS_MAX
            ),
            13.0,
            p.discret,
        ));
    }
    if !v.absents.is_empty() {
        ui.add_space(24.0);
        titre_section(
            ui,
            crate::tr!("Absents de ce scan", "Missing from this scan"),
            Some(v.absents.len()),
        );
        for a in v.absents.iter().take(APPAREILS_MAX) {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(&a.titre).font(moyenne(14.0)).color(p.encre));
                let vu = if a.dernier_vu.is_empty() {
                    a.ip.clone()
                } else {
                    crate::trf!("{} · vu le {}", "{} · seen {}", a.ip, a.dernier_vu)
                };
                ui.label(RichText::new(vu).font(mono(12.0)).color(p.discret));
            });
        }
    }
    ui.add_space(12.0);
    ui.label(texte(
        crate::tr!(
            "Lecture seule : nommer un appareil, le déclarer connu ou fermer un port se fait dans le menu de Vanguard.",
            "Read-only: naming a device, marking it known or closing a port is done in Vanguard's menu."
        ),
        13.0,
        p.discret,
    ));
}

/// Les deux contrôles du réseau entier : les redirections UPnP de la box et les faux noms. Ce qui n'a pas pu être
/// vu est déjà dans la carte « Pas pu vérifier » : ici, seulement ce qui a été vu.
fn reseau_entier(ui: &mut Ui, v: &scan::Vue) {
    let p = pal();
    let mut lignes: Vec<(String, Color32)> = Vec::new();
    match &v.upnp {
        Upnp::Absent => lignes.push((
            crate::tr!(
                "UPnP de la box : coupé ou absent (le mieux).",
                "Router UPnP: off or absent (best)."
            )
            .into(),
            p.bon,
        )),
        Upnp::Actif {
            redirections,
            lues,
            tronquees,
            illisibles,
            ..
        } => {
            let actives: Vec<&scan::Redirection> = redirections.iter().filter(|r| r.active).collect();
            // Une liste que la box n'a pas rendue en entier : son compte n'est qu'un minimum, jamais un fait.
            let entiere = *lues && !*tronquees && *illisibles == 0;
            lignes.push((
                if entiere {
                    crate::trf!(
                        "UPnP de la box : actif, {} {} vers Internet.",
                        "Router UPnP: on, {} {} to the Internet.",
                        crate::trn!(actives.len(), "port", "ports", "port", "ports"),
                        crate::tra!(actives.len(), "ouvert", "ouverts", "open", "open")
                    )
                } else {
                    crate::trf!(
                        "UPnP de la box : actif, au moins {} {} vers Internet ; la liste n'a pas pu être lue en entier (non vérifié).",
                        "Router UPnP: on, at least {} {} to the Internet; the list could not be read in full (not checked).",
                        crate::trn!(actives.len(), "port", "ports", "port", "ports"),
                        crate::tra!(actives.len(), "ouvert", "ouverts", "open", "open")
                    )
                },
                if actives.is_empty() && entiere { p.encre } else { p.moyen },
            ));
            for r in actives.into_iter().take(APPAREILS_MAX) {
                let port = |n: Option<u16>| n.map_or_else(|| "?".to_string(), |n| n.to_string());
                let depuis = if r.hote_distant.is_empty() {
                    crate::tr!("tout Internet", "the whole Internet").to_string()
                } else {
                    r.hote_distant.clone()
                };
                lignes.push((
                    format!(
                        "  {} {} → {}:{} · {} · {}",
                        r.protocole,
                        port(r.port_public),
                        r.appareil,
                        port(r.port_appareil),
                        r.description,
                        depuis
                    ),
                    p.doux,
                ));
            }
        }
        // Dit dans « Pas pu vérifier ».
        Upnp::OutilAbsent | Upnp::OutilEnEchec | Upnp::Usurpee(_) | Upnp::NonLu => {}
    }
    if let Empoisonnement::Teste { empoisonneurs, .. } = &v.empoisonnement {
        if empoisonneurs.is_empty() {
            lignes.push((
                crate::tr!(
                    "Faux noms : aucun appareil ne répond à un nom inventé.",
                    "Fake names: no device answers an invented name."
                )
                .into(),
                p.bon,
            ));
        }
        for (ip, protocoles) in empoisonneurs.iter().take(APPAREILS_MAX) {
            lignes.push((
                crate::trf!(
                    "Faux noms : {} répond à un nom inventé ({}) et peut détourner des connexions.",
                    "Fake names: {} answers an invented name ({}) and can divert connections.",
                    ip,
                    protocoles
                ),
                p.grave,
            ));
        }
    }
    if lignes.is_empty() {
        return;
    }
    carte(ui, 20, |ui| {
        ui.set_width(ui.available_width());
        for (l, couleur) in lignes {
            // Une redirection (« TCP 3074 → … ») se range sous sa ligne UPnP, en retrait de 16 : deux espaces
            // dans le texte ne tombaient sur aucune colonne.
            match l.strip_prefix("  ") {
                Some(reste) => {
                    ui.horizontal(|ui| {
                        ui.add_space(16.0 - ui.spacing().item_spacing.x);
                        ligne_signalee(ui, couleur, reste);
                    });
                }
                None => ligne_signalee(ui, couleur, &l),
            }
        }
    });
    ui.add_space(16.0);
}

/// Une ligne du diagnostic du réseau : à l'encre ; un point de sa couleur devant si elle dit un état.
fn ligne_signalee(ui: &mut Ui, couleur: Color32, l: &str) {
    if couleur == pal().encre {
        ui.label(texte(l, 13.0, couleur));
    } else {
        signale(ui, couleur, l, 13.0);
    }
}

/// Une ligne par appareil : son nom, son adresse, ses ports ; ce qui est nouveau ou risqué en couleur.
fn appareil(ui: &mut Ui, a: &scan::Appareil) {
    let p = pal();
    ui.horizontal_top(|ui| {
        let (z, _) = ui.allocate_exact_size(vec2(12.0, 18.0), Sense::hover());
        let couleur = match a.gravite() {
            Some(g) if g >= crate::donnees::bilan::Gravite::Moyenne => couleur_gravite(Some(g)),
            _ if a.nouveau => p.accent,
            _ => p.bon,
        };
        ui.painter()
            .circle_filled(pos2(z.left() + 4.0, z.center().y), 4.0, couleur);
        ui.vertical(|ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(&a.titre).font(moyenne(14.0)).color(p.encre));
                if a.nouveau {
                    ui.label(texte(crate::tr!("nouveau", "new"), 12.0, p.encre));
                }
                if a.passerelle() {
                    ui.label(texte(crate::tr!("la box", "the router"), 12.0, p.doux));
                } else if a.role == "cette machine" {
                    ui.label(texte(crate::tr!("cet ordinateur", "this computer"), 12.0, p.doux));
                }
                let mut ici = a.ip.clone();
                if !a.mac.is_empty() {
                    ici = format!("{ici} · {}", a.mac);
                }
                ui.label(RichText::new(ici).font(mono(12.0)).color(p.discret));
            });
            if !a.ports.is_empty() {
                let ports: Vec<String> = a
                    .ports
                    .iter()
                    .take(APPAREILS_MAX)
                    .map(|o| {
                        let n = o.numero.map_or_else(|| "?".to_string(), |n| n.to_string());
                        let mut t = format!("{n}{}", if o.udp { "/udp" } else { "" });
                        if !o.service.is_empty() {
                            t = format!("{t} {}", o.service);
                        }
                        if o.nouveau {
                            t = crate::trf!("{} (nouveau)", "{} (new)", t);
                        }
                        t
                    })
                    .collect();
                ui.label(texte(
                    &crate::trf!("Ports ouverts : {}", "Open ports: {}", ports.join(", ")),
                    13.0,
                    p.doux,
                ));
            }
            for (g, t) in a.alertes.iter().take(APPAREILS_MAX) {
                signale(ui, couleur_gravite(*g), t, 13.0);
            }
            if a.illisibles > 0 {
                signale(
                    ui,
                    p.moyen,
                    &crate::trn!(
                        a.illisibles,
                        "détail illisible : non vérifié.",
                        "détails illisibles : non vérifiés.",
                        "unreadable detail: not verified.",
                        "unreadable details: not verified."
                    ),
                    13.0,
                );
            }
        });
    });
}

fn erreur(ui: &mut Ui, e: &str) {
    carte(ui, 20, |ui| {
        ui.set_width(ui.available_width());
        signale(
            ui,
            pal().moyen,
            &crate::trf!("Pas de résultat lisible : {}", "No readable result: {}", e),
            14.0,
        );
    });
}

fn protection_liste(ui: &mut Ui, v: &protection::Vue) {
    let p = pal();
    carte(ui, 20, |ui| {
        ui.set_width(ui.available_width());
        for (k, i) in v.interrupteurs.iter().enumerate() {
            if k > 0 {
                ui.separator();
            }
            super::mouvement::ligne(ui, vec2(8.0, 2.0), 6.0, |ui| {
                ui.horizontal(|ui| {
                    let couleur = match i.allure {
                        Allure::Allume => p.bon,
                        Allure::Eteint => p.moyen,
                        Allure::Nuance => p.gris,
                    };
                    let (z, _) = ui.allocate_exact_size(vec2(12.0, 16.0), Sense::hover());
                    ui.painter()
                        .circle_filled(pos2(z.left() + 4.0, z.center().y), 4.0, couleur);
                    ui.label(RichText::new(&i.nom).font(moyenne(14.0)).color(p.encre));
                    // Le mot d'état à l'encre : la couleur de gravité ne marque que son point.
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(texte(&i.etat, 13.0, p.doux));
                    });
                })
            });
        }
        if v.interrupteurs.is_empty() {
            ui.label(texte(
                crate::tr!("Aucun interrupteur lu.", "No switch read."),
                14.0,
                p.doux,
            ));
        }
        if v.illisibles > 0 {
            signale(
                ui,
                p.moyen,
                &crate::trn!(
                    v.illisibles,
                    "interrupteur que cette fenêtre n'a pas su lire : non vérifié.",
                    "interrupteurs que cette fenêtre n'a pas su lire : non vérifiés.",
                    "switch this window could not read: not verified.",
                    "switches this window could not read: not verified."
                ),
                13.0,
            );
        }
    });
    ui.add_space(12.0);
    ui.label(texte(
        crate::tr!(
            "Allumer ou éteindre se fait dans le menu de Vanguard pour l'instant (montré, puis confirmé).",
            "Turning on or off is done in Vanguard's menu for now (shown, then confirmed)."
        ),
        13.0,
        p.discret,
    ));
}

fn libre_liste(ui: &mut Ui, v: &libre::Vue) {
    let p = pal();
    carte(ui, 20, |ui| {
        ui.set_width(ui.available_width());
        for l in &v.lignes {
            ui.horizontal(|ui| {
                ui.add_space(super::n_f32(l.retrait) * 16.0);
                if l.valeur.is_empty() {
                    ui.label(RichText::new(&l.cle).font(moyenne(14.0)).color(p.encre));
                } else {
                    if !l.cle.is_empty() {
                        ui.label(RichText::new(&l.cle).font(mono(12.0)).color(p.discret));
                    }
                    ui.label(texte(&l.valeur, 14.0, p.encre));
                }
            });
        }
        if v.lignes.is_empty() {
            ui.label(texte(
                crate::tr!(
                    "La commande n'a rien renvoyé à montrer.",
                    "The command returned nothing to show."
                ),
                14.0,
                p.doux,
            ));
        }
        if v.coupe {
            signale(
                ui,
                p.moyen,
                crate::tr!(
                    "Coupé : tout n'est pas montré ici (trop long ou trop imbriqué).",
                    "Cut: not everything is shown here (too long or too nested)."
                ),
                13.0,
            );
        }
    });
}

fn alertes(appli: &mut Appli, ui: &mut Ui) {
    let p = pal();
    let c = Commande::Evenements;
    entete_commande(appli, ui, c);
    ui.label(texte(
        &crate::trf!(
            "Relu toutes les {} s quand rien d'autre ne tourne ; une alerte nouvelle se dit dans la console.",
            "Read again every {} s when nothing else runs; a new alert shows in the console.",
            crate::appli::SONDAGE.as_secs()
        ),
        13.0,
        p.discret,
    ));
    ui.add_space(24.0);
    if let Some(Contenu::Erreur(e)) = appli.resultat(c).map(|r| &r.contenu) {
        erreur(ui, e);
        ui.add_space(16.0);
    }
    match appli.journal().cloned() {
        Some(j) => journal(ui, &j),
        None => vide::carte_vide(
            ui,
            c.rubrique(),
            crate::tr!("Journal pas encore lu", "Log not read yet"),
            crate::tr!(
                "Vanguard y note ses alertes et ce qu'il a fait, dans un journal scellé ; la lecture vérifie aussi qu'il est intact.",
                "Vanguard records its alerts and what it did there, in a sealed journal; reading it also checks it is intact."
            ),
            |ui| lancer_arreter(appli, ui, c),
        ),
    }
}

fn journal(ui: &mut Ui, j: &evenements::Vue) {
    let p = pal();
    carte(ui, 20, |ui| {
        ui.set_width(ui.available_width());
        let couleur = j.etat.gravite().map_or(p.bon, |g| couleur_gravite(Some(g)));
        signale_avec(ui, couleur, 15.0, |ui| {
            ui.label(RichText::new(j.etat.phrase()).font(moyenne(15.0)).color(p.encre));
        });
        if !j.raison.is_empty() {
            ui.label(texte(&j.raison, 13.0, p.doux));
        }
        if j.illisibles > 0 {
            signale(
                ui,
                p.moyen,
                &crate::trn!(
                    j.illisibles,
                    "ligne illisible : non vérifiée.",
                    "lignes illisibles : non vérifiées.",
                    "unreadable line: not verified.",
                    "unreadable lines: not verified."
                ),
                13.0,
            );
        }
    });
    ui.add_space(24.0);
    let maintenant = chrono::Utc::now();
    let alertes: Vec<&evenements::Evenement> = j.alertes().collect();
    titre_section(ui, crate::tr!("Alertes", "Alerts"), Some(alertes.len()));
    if alertes.is_empty() {
        vide::rien_a_signaler(
            ui,
            crate::tr!(
                "Aucune alerte notée : Vanguard n'a rien vu d'inquiétant.",
                "No alert recorded: Vanguard has seen nothing worrying."
            ),
        );
    }
    for e in alertes.iter().take(EVENEMENTS_MAX) {
        evenement(ui, e, maintenant);
    }
    ui.add_space(24.0);
    let autres: Vec<&evenements::Evenement> = j.evenements.iter().filter(|e| !e.alerte).collect();
    titre_section(ui, crate::tr!("Autres événements", "Other events"), Some(autres.len()));
    for e in autres.iter().take(EVENEMENTS_MAX) {
        evenement(ui, e, maintenant);
    }
    if autres.len() > EVENEMENTS_MAX || alertes.len() > EVENEMENTS_MAX {
        ui.label(texte(
            &crate::trf!(
                "Les {} plus récents seulement : le reste, dans le menu de Vanguard.",
                "The {} most recent only: the rest, in Vanguard's menu.",
                EVENEMENTS_MAX
            ),
            13.0,
            p.discret,
        ));
    }
}

fn evenement(ui: &mut Ui, e: &evenements::Evenement, maintenant: chrono::DateTime<chrono::Utc>) {
    let p = pal();
    super::mouvement::ligne(ui, vec2(8.0, 3.0), 6.0, |ui| {
        ui.horizontal_top(|ui| {
            let (z, _) = ui.allocate_exact_size(vec2(12.0, 18.0), Sense::hover());
            let couleur = if e.alerte {
                couleur_gravite(e.gravite.or(Some(crate::donnees::bilan::Gravite::Moyenne)))
            } else {
                p.gris
            };
            ui.painter()
                .circle_filled(pos2(z.left() + 4.0, z.center().y), 4.0, couleur);
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&e.titre).font(moyenne(14.0)).color(p.encre));
                    ui.label(
                        RichText::new(format!("{} · {}", crate::temps::age(&e.quand, maintenant), e.source))
                            .font(mono(12.0))
                            .color(p.discret),
                    );
                });
                if !e.detail.is_empty() {
                    ui.label(texte(&e.detail, 13.0, p.doux));
                }
            });
        })
    });
    ui.add_space(6.0);
}

fn reglages(appli: &mut Appli, ui: &mut Ui) {
    let p = pal();
    entete(
        ui,
        "Vanguard",
        crate::tr!(
            "Les réglages de cette fenêtre : le thème, la langue et les animations pour cette fois, les couleurs gardées par Vanguard.",
            "This window's settings: theme, language and animations for this time, colors kept by Vanguard."
        ),
    );
    ui.add_space(24.0);
    carte(ui, 20, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(crate::tr!("Thème", "Theme"))
                    .font(moyenne(14.0))
                    .color(p.encre),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if petit(ui, crate::tr!("Clair", "Light"), appli.sombre).clicked() {
                    appli.sombre = false;
                }
                if petit(ui, crate::tr!("Sombre", "Dark"), !appli.sombre).clicked() {
                    appli.sombre = true;
                }
            });
        });
        ui.separator();
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(crate::tr!("Langue", "Language"))
                    .font(moyenne(14.0))
                    .color(p.encre),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let anglais = crate::langue::anglais();
                let en = petit(ui, "English", !anglais).clicked();
                let fr = petit(ui, "Français", anglais).clicked();
                if en || fr {
                    crate::langue::basculer();
                }
            });
        });
        ui.separator();
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(crate::tr!("Animations", "Animations"))
                    .font(moyenne(14.0))
                    .color(p.encre),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let reduites = appli.animations_reduites;
                let bulle = crate::tr!(
                    "Réduites : plus de fondu entre les écrans, de chiffres qui montent, de points qui pulsent ni d'ouverture animée. Tout s'affiche tout de suite, rien d'autre ne change. Vanguard garde ce choix pour les prochaines ouvertures.",
                    "Reduced: no more fade between screens, numbers counting up, pulsing dots or animated opening. Everything shows at once, nothing else changes. Vanguard keeps this choice for the next openings."
                );
                if petit(ui, crate::tr!("Réduites", "Reduced"), !reduites)
                    .on_hover_text(bulle)
                    .clicked()
                {
                    appli.regler_animations(true);
                }
                if petit(ui, crate::tr!("Toutes", "All"), reduites)
                    .on_hover_text(bulle)
                    .clicked()
                {
                    appli.regler_animations(false);
                }
            });
        });
    });
    ui.add_space(12.0);
    ui.label(texte(
        crate::tr!(
            "Le thème et la langue valent pour cette fois : à la prochaine ouverture, la fenêtre reprend le thème du système et la langue de Vanguard. Les animations, elles, sont gardées par Vanguard. Les résultats déjà lus gardent leur langue jusqu'à la prochaine lecture.",
            "Theme and language are for this time: next time, the window takes the system theme and Vanguard's language again. Animations are kept by Vanguard. Results already read keep their language until read again."
        ),
        13.0,
        p.discret,
    ));
    ui.add_space(24.0);
    titre_section(ui, crate::tr!("Couleurs", "Colors"), None);
    super::couleurs::section(appli, ui);
    ui.add_space(24.0);
    titre_section(ui, crate::tr!("Vérifier Vanguard", "Check Vanguard"), None);
    cartes_commandes(appli, ui, Rubrique::Vanguard.commandes().collect());
    carte_mise_a_jour(appli, ui);
}

/// « Mettre à jour Vanguard » : un geste, toute la carte. Elle ouvre la feuille de l'aperçu (d'où vient la mise à
/// jour, sa version, ce qu'elle remplacerait) ; rien ne s'installe avant « Installer cette mise à jour » dans cette
/// feuille, avec l'accord de ce qui y est montré.
fn carte_mise_a_jour(appli: &mut Appli, ui: &mut Ui) {
    let p = pal();
    let titre = crate::tr!("Mettre à jour Vanguard", "Update Vanguard");
    let id = ui.make_persistent_id("carte-mise-a-jour");
    let rep = carte_qui_ouvre(ui, id, titre, |ui, s| {
        // Comme les autres cartes de commande : le texte à gauche, le mot qui ouvre à droite.
        let fleche = WidgetText::from(texte(
            &format!("{} →", crate::tr!("Voir", "See")),
            12.0,
            p.discret.lerp_to_gamma(p.encre, s),
        ))
        .into_galley(ui, Some(TextWrapMode::Extend), f32::INFINITY, TextStyle::Body);
        ui.horizontal(|ui| {
            let ecart = 16.0 + 2.0 * ui.spacing().item_spacing.x;
            ui.vertical(|ui| {
                ui.set_width((ui.available_width() - fleche.size().x - ecart).max(160.0));
                ui.label(RichText::new(titre).font(moyenne(16.0)).color(p.encre));
                ui.label(texte(
                    crate::tr!(
                        "Montre d'abord d'où vient la mise à jour (la clé VANGUARD, ou GitHub signée par l'auteur), sa version et chaque programme qu'elle remplacerait. Rien ne change avant votre accord.",
                        "First shows where the update comes from (the VANGUARD key, or GitHub signed by the author), its version and each program it would replace. Nothing changes before your consent."
                    ),
                    13.0,
                    p.doux,
                ));
            });
            ui.add_space(16.0);
            ui.label(fleche);
        });
    });
    let rep = rep.on_hover_text(crate::tr!(
        "Voir l'aperçu : rien ne s'installe d'ici",
        "See the preview: nothing is installed from here"
    ));
    if rep.clicked() {
        appli.voir_mise_a_jour();
    }
    ui.add_space(12.0);
}

fn guide(appli: &mut Appli, ui: &mut Ui) {
    let p = pal();
    entete(
        ui,
        crate::tr!("Toutes les fonctions de cette fenêtre", "All features of this window"),
        crate::tr!(
            "La liste fermée : les seules commandes que la fenêtre sait lancer, à cliquer ou à taper dans la console (nom français ou anglais).",
            "The closed list: the only commands this window can run, to click or type in the console (French or English name)."
        ),
    );
    ui.add_space(24.0);
    for c in Commande::ici() {
        super::mouvement::ligne(ui, vec2(8.0, 2.0), 6.0, |ui| {
            ui.horizontal(|ui| {
                ui.push_id(c.nom(), |ui| {
                    ui.set_width(ui.available_width());
                    let rep = ui.add(
                        eframe::egui::Label::new(RichText::new(c.titre()).font(moyenne(14.0)).color(p.encre))
                            .sense(Sense::click()),
                    );
                    super::clavier::anneau_zone(ui, &rep, rep.rect.expand2(vec2(4.0, 2.0)), 6.0);
                    if rep.on_hover_cursor(eframe::egui::CursorIcon::PointingHand).clicked() {
                        appli.aller(ecran_de(c));
                    }
                    ui.label(
                        RichText::new(format!("{} · {}", c.nom(), c.nom_anglais()))
                            .font(mono(12.0))
                            .color(p.discret),
                    );
                    ui.label(texte(c.description(), 13.0, p.doux));
                });
            })
        });
        ui.add_space(4.0);
    }
    ui.add_space(16.0);
    ui.label(texte(
        crate::tr!(
            "Le reste de Vanguard (corrections, réglages, quarantaine, clé USB) est dans son menu, en attendant d'arriver ici.",
            "The rest of Vanguard (fixes, settings, quarantine, USB key) is in its menu, until it comes here."
        ),
        13.0,
        p.discret,
    ));
}

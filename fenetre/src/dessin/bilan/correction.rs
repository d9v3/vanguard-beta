//! La feuille « Voir la correction » : ce que Vanguard ferait pour un constat, lu par `vanguard correction --voir`,
//! montré en lecture seule. Rien ne s'y accepte dans ce lot : le seul geste est « Annuler » (et copier la commande
//! du terminal), pour que la personne voie avant d'avoir à décider, sans bouton qui ferait semblant.

use eframe::egui::{self, Frame, Margin, RichText, ScrollArea, Stroke, Ui};

use crate::appli::{Appli, EtatFeuille, FeuilleCorrection};
use crate::dessin::{RAYON_CARTE, bouton, mono, moyenne, ombre, pal, signale, texte};
use crate::donnees::correction::{Apercu, Droits, Lecture};

/// Largeur de la feuille, et la marge gardée autour sur un petit écran.
const LARGEUR: f32 = 760.0;
const MARGE: f32 = 32.0;
/// Ce que prennent le titre et le pied (boutons) : le corps défile dans le reste, le pied reste toujours visible.
const TITRE_ET_PIED: f32 = 190.0;

/// Ce que la personne copie pour faire la correction elle-même, dans un terminal.
const COMMANDE_TERMINAL: &str = "vanguard corriger";

/// Dessine la feuille au-dessus de l'écran ; Échap, un clic à côté ou « Annuler » la ferment.
pub fn feuille(appli: &mut Appli, ctx: &egui::Context, f: &FeuilleCorrection) {
    let p = pal();
    let ecran = ctx.content_rect();
    let largeur = (ecran.width() - 2.0 * MARGE).clamp(280.0, LARGEUR);
    let corps_max = (ecran.height() - 2.0 * MARGE - TITRE_ET_PIED).max(120.0);
    let cadre = Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(2.0, p.accent))
        .shadow(ombre())
        .corner_radius(RAYON_CARTE)
        .inner_margin(Margin::same(22));
    let reponse = egui::Modal::new(egui::Id::unique("feuille-correction"))
        .frame(cadre)
        .backdrop_color(p.fond.gamma_multiply(0.7))
        .show(ctx, |ui| {
            ui.set_width(largeur);
            ui.label(
                RichText::new(crate::tr!("Voir la correction", "See the fix"))
                    .font(moyenne(20.0))
                    .color(p.encre),
            );
            ui.label(texte(
                crate::tr!(
                    "Lecture seule : rien n'a changé sur l'ordinateur.",
                    "Read only: nothing changed on the computer."
                ),
                13.0,
                p.doux,
            ));
            ui.add_space(12.0);
            // La feuille est une `Area` : sa place est celle de l'image d'avant. Sans hauteur minimale, le corps ne
            // grandirait que de quelques points par image ; avec elle, il prend tout de suite sa hauteur.
            ScrollArea::vertical()
                .max_height(corps_max)
                .min_scrolled_height(corps_max)
                .auto_shrink([false, true])
                .show(ui, |ui| corps(ui, &f.etat));
            ui.add_space(14.0);
            pied(ui, &f.etat)
        });
    let annuler = reponse.inner || reponse.should_close();
    if annuler {
        appli.annuler();
    }
}

/// Le pied : « Annuler », et « Copier la commande » quand la correction se fait dans le terminal. Vrai : annuler.
fn pied(ui: &mut Ui, etat: &EtatFeuille) -> bool {
    let mut annuler = false;
    ui.horizontal(|ui| {
        if bouton(ui, crate::tr!("Annuler", "Cancel"), true, true).clicked() {
            annuler = true;
        }
        let terminal = matches!(etat, EtatFeuille::Lue(Lecture::Lue(a)) if a.droits != Droits::Compte);
        if terminal && bouton(ui, crate::tr!("Copier la commande", "Copy the command"), false, true).clicked() {
            ui.ctx().copy_text(COMMANDE_TERMINAL.to_owned());
        }
    });
    annuler
}

fn corps(ui: &mut Ui, etat: &EtatFeuille) {
    let p = pal();
    match etat {
        EtatFeuille::Attente { .. } => {
            ui.label(texte(
                crate::tr!("Lecture de la correction…", "Reading the fix…"),
                14.0,
                p.doux,
            ));
        }
        EtatFeuille::Lue(Lecture::Lue(a)) => apercu(ui, a),
        EtatFeuille::Lue(Lecture::Refusee(r) | Lecture::Illisible(r)) | EtatFeuille::Echec(r) => {
            signale(
                ui,
                p.jaune,
                &crate::trf!("Pas d'aperçu : {}", "No preview: {}", r),
                14.0,
            );
        }
    }
}

fn apercu(ui: &mut Ui, a: &Apercu) {
    let p = pal();
    let fort = |ui: &mut Ui, t: &str| {
        ui.add_space(12.0);
        ui.label(RichText::new(t).font(moyenne(15.0)).color(p.encre));
        ui.add_space(2.0);
    };
    ui.horizontal(|ui| {
        ui.label(texte(&a.categorie, 12.0, p.discret));
        ui.label(texte(a.gravite.nom(), 12.0, p.encre));
        ui.label(RichText::new(&a.regle).font(mono(12.0)).color(p.discret));
    });
    ui.add_space(4.0);
    ui.label(texte(&a.message, 15.0, p.encre));
    if a.retouche {
        ui.add_space(6.0);
        signale(
            ui,
            p.jaune,
            crate::tr!(
                "Des caractères invisibles ou de contrôle ont été retirés de ce texte avant de l'afficher.",
                "Invisible or control characters were removed from this text before showing it."
            ),
            13.0,
        );
    }
    if a.coupe {
        ui.add_space(6.0);
        signale(
            ui,
            p.jaune,
            crate::tr!(
                "Un texte trop long a été coupé : la suite n'est pas montrée.",
                "A text that was too long was cut: the rest is not shown."
            ),
            13.0,
        );
    }

    fort(ui, crate::tr!("Ce que Vanguard va faire", "What Vanguard will do"));
    ui.label(texte(&a.action, 14.0, p.doux));
    if !a.automatique {
        ui.label(texte(
            crate::tr!(
                "Pas de geste automatique : la marche à suivre est expliquée, à faire vous-même.",
                "No automatic step: the way to do it is explained, for you to do."
            ),
            13.0,
            p.discret,
        ));
    }
    // Ce qui compte pour décider (droits, annulation) avant la liste des commandes, qui peut être longue.
    fort(ui, crate::tr!("À savoir", "Good to know"));
    if a.annulable {
        signale(
            ui,
            p.bon,
            crate::tr!(
                "S'annule : la valeur d'avant est notée, elle se remet exactement.",
                "Can be undone: the value before is noted and is put back exactly."
            ),
            13.0,
        );
    } else {
        let pourquoi = if a.pourquoi_pas.is_empty() {
            crate::tr!(
                "Vanguard ne note pas de valeur d'avant pour ce geste.",
                "Vanguard notes no value before for this step."
            )
        } else {
            a.pourquoi_pas.as_str()
        };
        signale(
            ui,
            p.moyen,
            &crate::trf!("Ne s'annule pas : {}", "Cannot be undone: {}", pourquoi),
            13.0,
        );
    }
    match a.droits {
        Droits::Compte => signale(
            ui,
            p.bon,
            crate::tr!(
                "Avec les droits de votre compte, sans mot de passe d'administrateur.",
                "With your account's rights, without an administrator password."
            ),
            13.0,
        ),
        Droits::Admin => signale(
            ui,
            p.jaune,
            crate::tr!(
                "Cette correction demande les droits d'administrateur. Elle arrivera ici avec le prochain lot. D'ici là : vanguard corriger dans un terminal.",
                "This fix needs administrator rights. It will come here with the next batch. Until then: vanguard corriger in a terminal."
            ),
            13.0,
        ),
        Droits::Terminal => signale(
            ui,
            p.jaune,
            crate::tr!(
                "Cette correction pose une question : elle se fait dans le terminal (vanguard corriger).",
                "This fix asks a question: it is done in the terminal (vanguard corriger)."
            ),
            13.0,
        ),
    }
    if !a.point_de_restauration {
        signale(
            ui,
            p.discret,
            crate::tr!(
                "Pas de point de restauration : il demanderait les droits d'administrateur.",
                "No restore point: it would need administrator rights."
            ),
            13.0,
        );
    }
    if !a.commandes.is_empty() {
        fort(ui, crate::tr!("Commandes", "Commands"));
        // Chaque commande dans son propre cadre : une longue commande repliée sur deux lignes ne peut pas passer pour
        // deux commandes.
        for c in &a.commandes {
            Frame::new()
                .fill(p.fond)
                .stroke(Stroke::new(1.0, p.discret.gamma_multiply(0.5)))
                .corner_radius(4)
                .inner_margin(Margin::symmetric(8, 4))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new(c).font(mono(12.0)).color(p.doux));
                });
            ui.add_space(4.0);
        }
    }
    if !a.avant.is_empty() {
        fort(ui, crate::tr!("Valeurs d'avant, notées", "Values before, noted"));
        // Une valeur entre « » ; une valeur absente en italique, sans guillemets : le texte « (absente) » écrit dans
        // un fichier ne peut pas passer pour une absence.
        for v in &a.avant {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(&v.geste).font(mono(12.0)).color(p.discret));
                ui.label(RichText::new("=").font(mono(12.0)).color(p.discret));
                match v.valeur.as_deref() {
                    Some(valeur) => ui.label(RichText::new(format!("«{valeur}»")).font(mono(12.0)).color(p.encre)),
                    None => ui.label(
                        texte(
                            crate::tr!("absente, rien de noté", "absent, nothing noted"),
                            12.0,
                            p.discret,
                        )
                        .italics(),
                    ),
                };
            });
        }
    }
}

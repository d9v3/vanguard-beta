//! La feuille « Voir la correction » : ce que Vanguard ferait pour un constat, lu par `vanguard correction --voir`,
//! montré en lecture seule. Rien ne s'y accepte dans ce lot : le seul geste est « Annuler » (et copier la commande
//! du terminal), pour que la personne voie avant d'avoir à décider, sans bouton qui ferait semblant.
//!
//! Chaque texte de Vanguard (ceux que l'accord engage, et sa raison de refus) est dessiné signe par signe
//! (`dessin::signe_par_signe`) : les ligatures des polices ne lient jamais deux de ses signes, « -> » ne se dessine
//! pas comme « → » ; et chaque nom ou valeur est dans son propre cadre, dessiné par la fenêtre, pour qu'aucun signe
//! d'un nom (guillemet, chevron, signe égal) n'imite la frontière entre deux champs.

use eframe::egui::{self, Color32, Frame, Margin, RichText, ScrollArea, Stroke, Ui, text::LayoutJob};

use crate::appli::{Appli, EtatFeuille, FeuilleCorrection};
use crate::dessin::{
    RAYON_CARTE, ajouter_signe_par_signe, bouton, mono, moyenne, ombre, pal, police, signale, signale_avec,
    signe_par_signe, texte,
};
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
        // La raison d'un refus est un texte de Vanguard : signe par signe. Les autres raisons sont celles de la fenêtre.
        EtatFeuille::Lue(Lecture::Refusee(r)) => signale_avec(ui, p.jaune, 14.0, |ui| {
            ui.label(phrase(crate::tr!("Pas d'aperçu : ", "No preview: "), r, 14.0, p.encre));
        }),
        EtatFeuille::Lue(Lecture::Illisible(r)) | EtatFeuille::Echec(r) => {
            signale(
                ui,
                p.jaune,
                &crate::trf!("Pas d'aperçu : {}", "No preview: {}", r),
                14.0,
            );
        }
    }
}

/// Notre début de phrase, puis un texte de Vanguard dessiné signe par signe, à la suite, dans la police d'Inter.
fn phrase(debut: &str, de_vanguard: &str, taille: f32, couleur: Color32) -> LayoutJob {
    let format = egui::TextFormat::simple(police(taille), couleur);
    let mut job = LayoutJob::default();
    job.append(debut, 0.0, format.clone());
    ajouter_signe_par_signe(&mut job, de_vanguard, &format);
    job
}

/// Un texte de Vanguard dans son propre cadre, à chasse fixe, signe par signe : une commande, un geste, une valeur.
fn cadre(ui: &mut Ui, t: &str, couleur: Color32) {
    let p = pal();
    Frame::new()
        .fill(p.fond)
        .stroke(Stroke::new(1.0, p.discret.gamma_multiply(0.5)))
        .corner_radius(4)
        .inner_margin(Margin::symmetric(8, 4))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.add(egui::Label::new(signe_par_signe(t, mono(12.0), couleur)).wrap());
        });
}

fn apercu(ui: &mut Ui, a: &Apercu) {
    let p = pal();
    let fort = |ui: &mut Ui, t: &str| {
        ui.add_space(12.0);
        ui.label(RichText::new(t).font(moyenne(15.0)).color(p.encre));
        ui.add_space(2.0);
    };
    ui.horizontal(|ui| {
        ui.label(signe_par_signe(&a.categorie, police(12.0), p.discret));
        ui.label(texte(a.gravite.nom(), 12.0, p.encre));
        ui.label(signe_par_signe(&a.regle, mono(12.0), p.discret));
    });
    ui.add_space(4.0);
    ui.label(signe_par_signe(&a.message, police(15.0), p.encre));
    if a.retouche {
        ui.add_space(6.0);
        signale(
            ui,
            p.jaune,
            crate::tr!(
                "Ce texte a été retouché avant de l'afficher (caractères invisibles, de contrôle, que la fenêtre ne sait pas dessiner ou qui en imitent un autre, remplacés par « \u{fffd} » ou retirés ; sauts de ligne, espaces en tête ou longues suites d'espaces resserrés) : il n'est pas exactement celui de Vanguard.",
                "This text was altered before showing it (invisible or control characters, or ones this window cannot draw or that mimic another, replaced by “\u{fffd}” or removed; line breaks, leading spaces or long runs of spaces tightened): it is not exactly Vanguard's."
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
    ui.label(signe_par_signe(&a.action, police(14.0), p.doux));
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
        // Un aperçu non annulable a toujours son « pourquoi pas » (`donnees::correction::coherent`) ; vide, la phrase
        // est celle de la fenêtre.
        let pourquoi = if a.pourquoi_pas.is_empty() {
            phrase(
                crate::tr!(
                    "Ne s'annule pas : Vanguard ne note pas de valeur d'avant pour ce geste.",
                    "Cannot be undone: Vanguard notes no value before for this step."
                ),
                "",
                13.0,
                p.encre,
            )
        } else {
            phrase(
                crate::tr!("Ne s'annule pas : ", "Cannot be undone: "),
                &a.pourquoi_pas,
                13.0,
                p.encre,
            )
        };
        signale_avec(ui, p.moyen, 13.0, |ui| {
            ui.label(pourquoi);
        });
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
            cadre(ui, c, p.doux);
            ui.add_space(4.0);
        }
    }
    if !a.avant.is_empty() {
        fort(ui, crate::tr!("Valeurs d'avant, notées", "Values before, noted"));
        // Le geste dans son cadre, puis sa valeur dans le sien, sous « valeur notée » écrit par la fenêtre : un nom
        // qui contient « = », des guillemets ou des chevrons reste dans son cadre et n'imite pas une seconde valeur.
        // Une valeur absente est dite en italique, sans cadre : le texte « absente » écrit dans un fichier, lui, est
        // dans un cadre et ne passe pas pour une absence.
        for v in &a.avant {
            cadre(ui, &v.geste, p.discret);
            ui.horizontal_top(|ui| {
                ui.add_space(12.0);
                ui.label(texte(crate::tr!("valeur notée :", "value noted:"), 12.0, p.discret));
                match v.valeur.as_deref() {
                    Some(valeur) => {
                        ui.vertical(|ui| cadre(ui, valeur, p.encre));
                    }
                    None => {
                        ui.label(
                            texte(
                                crate::tr!("absente, rien de noté", "absent, nothing noted"),
                                12.0,
                                p.discret,
                            )
                            .italics(),
                        );
                    }
                }
            });
            ui.add_space(6.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use eframe::egui::{FontFamily, Shape, epaint::Galley};

    use super::*;
    use crate::commandes::Accord;
    use crate::donnees::bilan::Gravite;
    use crate::donnees::correction::Avant;

    /// Un aperçu inventé (maison « alice ») dont chaque texte de Vanguard contient des suites que les polices lient.
    fn exemple(annulable: bool) -> Apercu {
        Apercu {
            version: "0.93.0".into(),
            regle: "LNX=>SSH..003".into(),
            categorie: "Clés -> SSH".into(),
            gravite: Gravite::Critique,
            message: "Clé privée ~/.ssh/id_<a> lisible par d'autres -> x".into(),
            action: "Protéger la clé id_<a> => x..y".into(),
            commandes: vec!["chmod 600 ~/.ssh/'id_<a>' -> x".into(), "a != b >= c <= www".into()],
            automatique: true,
            droits: Droits::Compte,
            annulable,
            pourquoi_pas: if annulable {
                String::new()
            } else {
                "Vanguard ne sait pas relever <- l'état => d'avant".into()
            },
            avant: if annulable {
                vec![Avant {
                    geste: "droits|/home/alice/.ssh/id_x = «y» -> z".into(),
                    valeur: Some("0644 => «700»".into()),
                }]
            } else {
                Vec::new()
            },
            point_de_restauration: false,
            accord: Accord::lire(&"ab".repeat(32)).unwrap(),
            retouche: false,
            coupe: false,
        }
    }

    fn galeries(forme: &Shape, sortie: &mut Vec<Arc<Galley>>) {
        match forme {
            Shape::Text(t) => sortie.push(t.galley.clone()),
            Shape::Vec(v) => v.iter().for_each(|f| galeries(f, sortie)),
            _ => {}
        }
    }

    /// Une image sans écran (`run_ui`) de ce que `dessin` peint : les textes qu'elle a mis en page.
    fn textes_peints(ctx: &egui::Context, dessin: impl FnMut(&mut Ui)) -> Vec<Arc<Galley>> {
        let entree = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(800.0, 3000.0))),
            ..Default::default()
        };
        let mut sortie = ctx.run_ui(entree, dessin);
        sortie.textures_delta.clear();
        let mut g = Vec::new();
        for c in &sortie.shapes {
            galeries(&c.shape, &mut g);
        }
        g
    }

    /// Vrai si `t` est peint dans un texte de l'image, chaque signe dans sa propre section (façonné seul : aucune
    /// ligature avec son voisin), dans une police que les essais de `dessin::encre` couvrent (Inter ou JetBrains
    /// Mono, de 12 à 15 points).
    fn peint_signe_par_signe(peints: &[Arc<Galley>], t: &str) -> bool {
        peints.iter().any(|g| {
            g.job.text.match_indices(t).any(|(o, _)| {
                t.char_indices().all(|(i, c)| {
                    g.job.sections.iter().any(|s| {
                        s.byte_range.start.0 == o + i
                            && s.byte_range.end.0 == o + i + c.len_utf8()
                            && matches!(
                                s.format.font_id.family,
                                FontFamily::Proportional | FontFamily::Monospace
                            )
                            && (12.0..=15.0).contains(&s.format.font_id.size)
                    })
                })
            })
        })
    }

    /// Vérification de Fable n° 3, A1 et A2 : chaque texte de Vanguard de la feuille (catégorie, règle, message,
    /// action, commandes, geste et valeur d'avant, « pourquoi pas », raison d'un refus) est peint signe par signe, dans
    /// une police et une taille dont la liste des signes permis est vérifiée. Un seul texte peint d'un bloc (ligatures
    /// permises) fait échouer cet essai.
    #[test]
    fn chaque_texte_de_vanguard_est_peint_signe_par_signe() {
        let ctx = egui::Context::default();
        crate::dessin::polices(&ctx);
        for annulable in [true, false] {
            let a = exemple(annulable);
            let peints = textes_peints(&ctx, |ui| apercu(ui, &a));
            let mut textes = vec![&a.categorie, &a.regle, &a.message, &a.action];
            textes.extend(&a.commandes);
            for v in &a.avant {
                textes.push(&v.geste);
                textes.extend(&v.valeur);
            }
            if !annulable {
                textes.push(&a.pourquoi_pas);
            }
            for t in textes {
                assert!(
                    peint_signe_par_signe(&peints, t),
                    "{t:?} n'est pas peint signe par signe"
                );
            }
        }
        let raison = "ce problème a disparu -> refaites le bilan".to_string();
        let peints = textes_peints(&ctx, |ui| {
            corps(ui, &EtatFeuille::Lue(Lecture::Refusee(raison.clone())));
        });
        assert!(peint_signe_par_signe(&peints, &raison));
    }

    /// A1, par l'image : dans la feuille, une suite de deux signes (« -> », « => », « <- ») ne se peint pas comme la
    /// flèche qu'une ligature d'Inter en ferait, ni dans le message (15 points) ni dans l'action (14 points).
    #[test]
    fn une_suite_ne_se_peint_pas_comme_un_signe() {
        let ctx = egui::Context::default();
        crate::dessin::polices(&ctx);
        let image = |t: &str| {
            let mut a = exemple(true);
            a.message = format!("message {t}");
            a.action = format!("action {t}");
            let peints = textes_peints(&ctx, |ui| apercu(ui, &a));
            let atlas = ctx.fonts_mut(|f| f.image());
            [&a.message, &a.action].map(|t| {
                let g = peints.iter().find(|g| g.job.text == *t).unwrap();
                crate::dessin::encre::image(&atlas, g, egui::Vec2::ZERO)
            })
        };
        for (suite, signe) in [("x->y", "x\u{2192}y"), ("x=>y", "x\u{21d2}y"), ("x<-y", "x\u{2190}y")] {
            let (deux, un) = (image(suite), image(signe));
            assert_ne!(deux[0], un[0], "message : {suite} se peint comme {signe}");
            assert_ne!(deux[1], un[1], "action : {suite} se peint comme {signe}");
        }
    }
}

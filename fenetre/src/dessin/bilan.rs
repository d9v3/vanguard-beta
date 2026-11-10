//! L'écran Bilan (la maquette acceptée) et le détail des constats, repris par les écrans des outils.

use eframe::egui::{
    self, Align, Color32, Frame, Layout, Margin, Rect, RichText, Sense, Stroke, StrokeKind, Ui, pos2, vec2,
};

use super::{bouton, carte, entete, icones, melange, mono, moyenne, n_f32, pal, petit, texte, titre_section};
use crate::appli::{Appli, Contenu};
use crate::commandes::Commande;
use crate::donnees::bilan::{Constat, Gravite, Rang, Vue};

/// Constats montrés au plus dans une carte de côté ; le reste est compté.
const COTE_MAX: usize = 6;
/// Constats à corriger montrés au plus (une carte chacun).
const CORRIGER_MAX: usize = 60;
/// Lignes d'un inventaire sain montrées d'emblée ; le reste se déplie.
const LISTE_MAX: usize = 40;

fn couleur_rang(r: Rang) -> Color32 {
    let p = pal();
    match r {
        Rang::Corriger => p.accent,
        Rang::Savoir => melange(p.jaune, p.s3, 0.55),
        Rang::Sain => melange(p.bon, p.s3, 0.38),
        Rang::SansObjet => p.s3,
        Rang::NonVerifie => p.gris,
    }
}

pub fn couleur_gravite(g: Option<Gravite>) -> Color32 {
    match g {
        Some(Gravite::Critique | Gravite::Elevee) => pal().grave,
        Some(Gravite::Info) => pal().jaune,
        _ => pal().moyen,
    }
}

/// La bande : un trait par vérification, rangés par sujet. Pendant un bilan, un balayage passe sur les traits du
/// dernier (aucun compte inventé : on ne sait pas encore combien sont faites).
fn bande(ui: &mut Ui, vue: Option<&Vue>, en_cours: Option<f32>) {
    let p = pal();
    let largeur = ui.available_width();
    let (r, _) = ui.allocate_exact_size(vec2(largeur, 60.0), Sense::hover());
    let groupes: Vec<(String, Vec<Rang>)> = match vue {
        Some(v) if !v.constats.is_empty() => v.groupes(),
        _ => (0..32usize)
            .map(|i| (String::new(), vec![Rang::Sain; 1 + i % 4]))
            .collect(),
    };
    let reel = vue.is_some_and(|v| !v.constats.is_empty());
    let n: usize = groupes.iter().map(|g| g.1.len()).sum();
    // Les traits s'amincissent pour que la bande tienne toujours dans sa largeur.
    let g = n_f32(groupes.len().max(2));
    let w = (r.width() / (n_f32(n) * 1.5 + g * 2.0)).clamp(2.0, 6.0);
    let pas = (w * 0.5).max(1.0);
    let naturel = n_f32(n) * (w + pas) - pas * g;
    let ecart = ((r.width() - naturel) / (g - 1.0)).clamp(w, 24.0);
    let mut x = r.left();
    let peintre = ui.painter().clone();
    for (gi, (cat, rangs)) in groupes.iter().enumerate() {
        let x0 = x;
        for &e in rangs {
            if x + w > r.right() {
                break;
            }
            let fini = en_cours.is_none() && reel;
            let haut = if e == Rang::Corriger && fini { 56.0 } else { 44.0 };
            let trait_ = Rect::from_min_max(pos2(x, r.bottom() - haut), pos2(x + w, r.bottom()));
            let mut col = if fini { couleur_rang(e) } else { p.s3 };
            if let Some(t) = en_cours {
                let pos = (t * 0.45) % 1.3 - 0.15;
                let d = ((x - r.left()) / r.width() - pos).abs();
                if d < 0.04 {
                    col = p.accent.gamma_multiply(1.0 - d / 0.04 * 0.6);
                }
            }
            if e == Rang::Corriger && fini {
                for k in 1..=3u8 {
                    peintre.rect_filled(trait_.expand(f32::from(k) * 2.0), 6, p.accent.gamma_multiply(0.08));
                }
            }
            if e == Rang::NonVerifie && fini {
                peintre.rect_filled(trait_, 3, p.fond);
                peintre.rect_stroke(trait_, 3, Stroke::new(1.0, p.gris), StrokeKind::Inside);
                let mut y = trait_.top() + 2.0;
                while y < trait_.bottom() - 2.0 {
                    peintre.line_segment(
                        [pos2(trait_.left() + 1.0, y + 4.0), pos2(trait_.right() - 1.0, y)],
                        Stroke::new(1.0, p.gris),
                    );
                    y += 5.0;
                }
            } else {
                peintre.rect_filled(trait_, 3, col);
            }
            x += w + pas;
        }
        x -= pas;
        if reel && !cat.is_empty() {
            let zone = Rect::from_min_max(pos2(x0 - 2.0, r.top()), pos2(x + 2.0, r.bottom()));
            let corriger = rangs.iter().filter(|&&e| e == Rang::Corriger).count();
            let detail = if corriger > 0 {
                crate::trf!(
                    "{} — {} vérification(s), {} à corriger",
                    "{} — {} check(s), {} to fix",
                    cat,
                    rangs.len(),
                    corriger
                )
            } else {
                crate::trf!("{} — {} vérification(s)", "{} — {} check(s)", cat, rangs.len())
            };
            ui.interact(zone, ui.scope_id().with(("groupe", gi)), Sense::hover())
                .on_hover_text(detail);
        }
        x += ecart;
    }
}

pub fn ecran(appli: &mut Appli, ui: &mut Ui) {
    let p = pal();
    let temps = ui.ctx().input(|i| i.time);
    let en_cours = appli
        .en_cours()
        .filter(|(c, _)| *c == Commande::Bilan)
        .map(|(_, d)| d.as_secs_f32());
    let resultat = appli.resultat(Commande::Bilan).cloned();
    let vue = appli.bilan().cloned();
    let erreur = match resultat.as_ref().map(|r| &r.contenu) {
        Some(Contenu::Erreur(e)) => Some(e.clone()),
        _ => None,
    };
    let sous = match (&resultat, en_cours) {
        (_, Some(t)) => crate::trf!(
            "En cours depuis {:.0} s · rien n'est envoyé, tout se lit sur cet ordinateur",
            "Running for {:.0} s · nothing is sent, everything is read on this computer",
            t
        ),
        (Some(r), None) => crate::trf!(
            "Fini à {} · {} vérification(s) en {:.0} s · rien n'est envoyé, tout se lit sur cet ordinateur",
            "Finished at {} · {} check(s) in {:.0} s · nothing is sent, everything is read on this computer",
            r.heure,
            vue.as_ref().map_or(0, |v| v.constats.len()),
            r.duree.as_secs_f32()
        ),
        (None, None) => crate::tr!("Aucun bilan encore", "No check yet").into(),
    };
    let actions = |appli: &mut Appli, ui: &mut Ui| {
        if en_cours.is_none() {
            if bouton(ui, crate::tr!("Refaire le bilan", "Run the check again"), true, true).clicked() {
                appli.demander(Commande::Bilan);
            }
            bouton(ui, crate::tr!("Rapport à laisser", "Report to leave"), false, false)
                .on_disabled_hover_text(crate::tr!("Arrive dans un prochain lot.", "Coming in a later batch."));
        } else if bouton(ui, crate::tr!("Arrêter", "Stop"), false, true).clicked() {
            appli.arreter();
        }
    };
    let titre = Commande::Bilan.titre();
    if ui.available_width() >= 900.0 {
        super::texte_et_boutons(ui, "bilan", |ui| entete(ui, titre, &sous), |ui| actions(appli, ui));
    } else {
        entete(ui, titre, &sous);
        ui.add_space(12.0);
        ui.horizontal(|ui| actions(appli, ui));
    }
    ui.add_space(24.0);
    if let Some(e) = &erreur {
        carte(ui, 20, 16, |ui| {
            ui.set_width(ui.available_width());
            ui.label(texte(
                &crate::trf!("Le bilan n'a pas abouti : {}", "The check did not finish: {}", e),
                14.0,
                p.moyen,
            ));
        });
        ui.add_space(16.0);
    }
    let finie = if en_cours.is_some() { None } else { vue.as_ref() };
    carte(ui, 32, 20, |ui| {
        ui.set_width(ui.available_width());
        let etroit = ui.available_width() < 760.0;
        let note = |ui: &mut Ui| {
            ui.vertical(|ui| {
                if !etroit {
                    ui.set_width(260.0);
                }
                match (finie, en_cours) {
                    (_, Some(t)) => {
                        let points = ".".repeat(1 + super::f32_n(super::cadre::phase_f32((temps % 1.5) / 1.5) * 3.0) % 3);
                        ui.label(RichText::new(format!("{t:.0} s")).font(moyenne(72.0)).color(p.encre));
                        ui.label(texte(&format!("{}{points}", crate::tr!("en cours", "running")), 15.0, p.encre));
                        ui.add_space(8.0);
                        ui.label(texte(
                            crate::tr!(
                                "La note vient à la fin. Rien n'est compté avant d'être vérifié.",
                                "The score comes at the end. Nothing counts before it is checked."
                            ),
                            13.0,
                            p.doux,
                        ));
                    }
                    (Some(v), None) => {
                        let incomplete = v.note_incomplete();
                        ui.horizontal(|ui| {
                            let n = v.note.map_or_else(|| "—".to_string(), |s| s.to_string());
                            // Des points non vérifiés : la note en couleur d'alerte, et leur nombre à côté, aussi
                            // visible qu'elle. Ils ne comptent pas comme sains.
                            let couleur = if incomplete.is_some() { p.moyen } else { p.encre };
                            ui.label(RichText::new(n).font(moyenne(72.0)).color(couleur));
                            ui.label(texte("/100", 20.0, p.discret));
                        });
                        if let Some(k) = incomplete {
                            ui.label(
                                RichText::new(crate::trf!("{} pas pu vérifier", "{} could not check", k))
                                    .font(moyenne(28.0))
                                    .color(p.moyen),
                            );
                        }
                        ui.add_space(8.0);
                        if v.note.is_none() {
                            ui.label(texte(
                                if v.note_retenue {
                                    crate::tr!(
                                        "Pas de note : trop de points n'ont pas pu être vérifiés pour qu'elle veuille dire quelque chose.",
                                        "No score: too many points could not be checked for it to mean anything."
                                    )
                                } else {
                                    crate::tr!("Pas de note pour ce bilan.", "No score for this check.")
                                },
                                13.0,
                                p.moyen,
                            ));
                        }
                        ui.label(texte(
                            &crate::trf!(
                                "{} point(s) à corriger. {} vérification(s) n'ont pas pu se faire : elles ne comptent pas comme saines.",
                                "{} point(s) to fix. {} check(s) could not be done: they do not count as healthy.",
                                v.compte(Rang::Corriger),
                                v.compte(Rang::NonVerifie)
                            ),
                            13.0,
                            p.doux,
                        ));
                    }
                    (None, None) => {
                        ui.label(RichText::new("—").font(moyenne(72.0)).color(p.discret));
                        ui.label(texte(
                            crate::tr!("Lancez le bilan pour une note.", "Run the check for a score."),
                            13.0,
                            p.doux,
                        ));
                    }
                }
            });
        };
        let traits = |ui: &mut Ui| {
            ui.vertical(|ui| {
                let n = finie.map_or(0, |v| v.constats.len());
                ui.horizontal(|ui| {
                    let t = if n > 0 {
                        crate::trf!("Les {} vérifications, par sujet", "The {} checks, by topic", n)
                    } else {
                        crate::tr!("Les vérifications, par sujet", "The checks, by topic").into()
                    };
                    ui.label(texte(&t, 13.0, p.doux));
                    if !etroit && n > 0 {
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(
                                RichText::new(crate::tr!(
                                    "survolez un groupe pour son nom",
                                    "hover a group for its name"
                                ))
                                .font(mono(12.0))
                                .color(p.discret),
                            );
                        });
                    }
                });
                ui.add_space(12.0);
                bande(ui, if en_cours.is_some() { vue.as_ref() } else { finie }, en_cours);
                ui.add_space(12.0);
                if let Some(v) = finie {
                    legende(ui, v);
                } else if en_cours.is_some() {
                    ui.label(texte(
                        crate::tr!(
                            "Lecture de cet ordinateur : pare-feu, comptes, mises à jour, persistance, navigateur…",
                            "Reading this computer: firewall, accounts, updates, persistence, browser…"
                        ),
                        13.0,
                        p.doux,
                    ));
                }
            });
        };
        if etroit {
            note(ui);
            ui.add_space(24.0);
            traits(ui);
        } else {
            ui.horizontal_top(|ui| {
                note(ui);
                ui.add_space(40.0);
                traits(ui);
            });
        }
    });
    ui.add_space(32.0);
    if let Some(v) = finie {
        constats(ui, v);
    }
}

fn legende(ui: &mut Ui, v: &Vue) {
    let p = pal();
    ui.horizontal_wrapped(|ui| {
        for r in Rang::TOUS {
            let k = v.compte(r);
            if r == Rang::SansObjet && k == 0 {
                continue;
            }
            let (z, _) = ui.allocate_exact_size(vec2(6.0, 14.0), Sense::hover());
            if r == Rang::NonVerifie {
                ui.painter()
                    .rect_stroke(z, 3, Stroke::new(1.0, p.gris), StrokeKind::Inside);
            } else {
                ui.painter().rect_filled(z, 3, couleur_rang(r));
            }
            ui.label(RichText::new(k.to_string()).font(moyenne(13.0)).color(p.encre));
            ui.label(texte(r.nom(), 13.0, p.doux));
            ui.add_space(16.0);
        }
    });
}

/// Le détail : à corriger (une carte chacun), ce qui va bien (une puce par sujet), et sur le côté ce qui n'a pas pu
/// être vérifié et ce qui est bon à savoir.
pub fn constats(ui: &mut Ui, v: &Vue) {
    let p = pal();
    let total = ui.available_width();
    let droite = 360.0_f32.min(total * 0.32);
    let gauche = |ui: &mut Ui, largeur: f32| {
        ui.vertical(|ui| {
            ui.set_width(largeur);
            let a_corriger = v.de_rang(Rang::Corriger);
            titre_section(ui, crate::tr!("À corriger", "To fix"), Some(a_corriger.len()));
            for (i, c) in a_corriger.iter().take(CORRIGER_MAX).enumerate() {
                carte_constat(ui, c, i);
                ui.add_space(12.0);
            }
            if a_corriger.len() > CORRIGER_MAX {
                ui.label(texte(
                    &crate::trf!("et {} autre(s)", "and {} more", a_corriger.len() - CORRIGER_MAX),
                    13.0,
                    p.discret,
                ));
            }
            if a_corriger.is_empty() {
                ui.label(texte(crate::tr!("Rien à corriger.", "Nothing to fix."), 14.0, p.doux));
            }
            ui.add_space(20.0);
            let sains = v.sains_par_categorie();
            titre_section(
                ui,
                crate::tr!("Ce qui va bien", "What is fine"),
                Some(v.compte(Rang::Sain)),
            );
            if sains.is_empty() {
                ui.label(texte(
                    crate::tr!("Rien de vérifié sain.", "Nothing checked healthy."),
                    14.0,
                    p.doux,
                ));
            }
            if let Some(liste) = v.sains_en_liste() {
                liste_saine(ui, &liste);
                return;
            }
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = vec2(8.0, 8.0);
                for (cat, k) in &sains {
                    Frame::new()
                        .fill(p.surface)
                        .stroke(Stroke::new(1.0, p.trait_))
                        .corner_radius(8)
                        .inner_margin(Margin::symmetric(12, 6))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 6.0;
                                let (r, _) = ui.allocate_exact_size(vec2(14.0, 14.0), Sense::hover());
                                icones::coche(ui.painter(), r, p.bon);
                                ui.label(texte(cat, 13.0, p.doux));
                                if *k > 1 {
                                    ui.label(RichText::new(k.to_string()).font(mono(12.0)).color(p.discret));
                                }
                            });
                        });
                }
            });
        });
    };
    let cote = |ui: &mut Ui, largeur: f32| {
        ui.vertical(|ui| {
            ui.set_width(largeur);
            let nv = v.de_rang(Rang::NonVerifie);
            let mut lignes: Vec<(String, String)> =
                nv.iter().map(|c| (c.categorie.clone(), c.message.clone())).collect();
            lignes.extend(
                v.manques
                    .iter()
                    .map(|m| (crate::tr!("Couverture", "Coverage").to_string(), m.clone())),
            );
            if v.illisibles > 0 {
                lignes.push((
                    crate::tr!("Illisible", "Unreadable").into(),
                    crate::trf!(
                        "{} constat(s) que cette fenêtre n'a pas su lire",
                        "{} finding(s) this window could not read",
                        v.illisibles
                    ),
                ));
            }
            liste_cote(ui, crate::tr!("Pas pu vérifier", "Could not check"), &lignes, p.gris);
            ui.add_space(16.0);
            let savoir: Vec<(String, String)> = v
                .de_rang(Rang::Savoir)
                .iter()
                .map(|c| (c.categorie.clone(), c.message.clone()))
                .collect();
            liste_cote(ui, crate::tr!("Bon à savoir", "Good to know"), &savoir, p.jaune);
        });
    };
    if total >= 1000.0 {
        ui.horizontal_top(|ui| {
            gauche(ui, total - droite - 24.0);
            ui.add_space(24.0);
            cote(ui, droite);
        });
    } else {
        gauche(ui, total);
        ui.add_space(24.0);
        cote(ui, total);
    }
}

fn carte_constat(ui: &mut Ui, c: &Constat, i: usize) {
    let p = pal();
    carte(ui, 22, 16, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal_top(|ui| {
            let (r, _) = ui.allocate_exact_size(vec2(12.0, 16.0), Sense::hover());
            ui.painter()
                .circle_filled(pos2(r.left() + 4.0, r.center().y), 4.0, couleur_gravite(c.gravite));
            ui.add_space(8.0);
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(texte(&c.categorie, 12.0, p.discret));
                    if let Some(g) = c.gravite {
                        ui.label(texte(g.nom(), 12.0, couleur_gravite(Some(g))));
                    }
                    ui.label(RichText::new(&c.regle).font(mono(12.0)).color(p.discret));
                });
                ui.add_space(4.0);
                ui.label(texte(&c.message, 15.0, p.encre));
                if !c.objet.is_empty() {
                    ui.label(RichText::new(&c.objet).font(mono(12.0)).color(p.doux));
                }
                if !c.action.is_empty() {
                    ui.add_space(8.0);
                    let rep = Frame::new()
                        .inner_margin(Margin {
                            left: 12,
                            right: 0,
                            top: 2,
                            bottom: 2,
                        })
                        .show(ui, |ui| {
                            ui.label(texte(&c.action, 13.0, p.doux));
                        });
                    let r = rep.response.rect;
                    ui.painter()
                        .line_segment([r.left_top(), r.left_bottom()], Stroke::new(2.0, p.trait_));
                }
                ui.add_space(14.0);
                ui.push_id(i, |ui| {
                    petit(ui, crate::tr!("Voir la correction", "See the fix"), false).on_disabled_hover_text(
                        crate::tr!(
                            "Les corrections arrivent dans un prochain lot : montrées, puis acceptées.",
                            "Fixes come in a later batch: shown, then accepted."
                        ),
                    );
                });
            });
        });
    });
}

/// Un inventaire sain, une ligne par élément (`Vue::sains_en_liste`) ; au-delà de `LISTE_MAX`, le reste se déplie.
fn liste_saine(ui: &mut Ui, liste: &[&Constat]) {
    let p = pal();
    let ligne = |ui: &mut Ui, c: &Constat| {
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            let (r, _) = ui.allocate_exact_size(vec2(14.0, 16.0), Sense::hover());
            icones::coche(ui.painter(), r, p.bon);
            ui.label(texte(&c.message, 13.0, p.doux));
        });
    };
    carte(ui, 20, 16, |ui| {
        ui.set_width(ui.available_width());
        for c in liste.iter().take(LISTE_MAX) {
            ligne(ui, c);
            ui.add_space(6.0);
        }
        if liste.len() > LISTE_MAX {
            let reste = liste.len() - LISTE_MAX;
            egui::CollapsingHeader::new(texte(&crate::trf!("{} autre(s)", "{} more", reste), 13.0, p.discret))
                .id_salt("liste-saine")
                .show(ui, |ui| {
                    for c in liste.iter().skip(LISTE_MAX) {
                        ligne(ui, c);
                        ui.add_space(6.0);
                    }
                });
        }
    });
}

fn liste_cote(ui: &mut Ui, titre: &str, lignes: &[(String, String)], col: Color32) {
    let p = pal();
    carte(ui, 20, 16, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.label(RichText::new(titre).font(moyenne(14.0)).color(p.encre));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(
                    RichText::new(lignes.len().to_string())
                        .font(mono(12.0))
                        .color(p.discret),
                );
            });
        });
        ui.add_space(4.0);
        if lignes.is_empty() {
            ui.label(texte(crate::tr!("Rien.", "Nothing."), 13.0, p.doux));
        }
        for (k, (cat, message)) in lignes.iter().take(COTE_MAX).enumerate() {
            if k > 0 {
                let y = ui.cursor().top();
                let r = ui.max_rect();
                ui.painter()
                    .line_segment([pos2(r.left(), y), pos2(r.right(), y)], Stroke::new(1.0, p.trait_));
            }
            ui.add_space(8.0);
            ui.horizontal_top(|ui| {
                let (r, _) = ui.allocate_exact_size(vec2(12.0, 16.0), Sense::hover());
                ui.painter().circle_filled(pos2(r.left() + 3.0, r.center().y), 3.0, col);
                ui.vertical(|ui| {
                    ui.label(RichText::new(cat).font(moyenne(13.0)).color(p.encre));
                    ui.label(texte(message, 13.0, p.doux));
                });
            });
            ui.add_space(4.0);
        }
        if lignes.len() > COTE_MAX {
            let reste = lignes.len() - COTE_MAX;
            egui::CollapsingHeader::new(texte(&crate::trf!("{} autre(s)", "{} more", reste), 13.0, p.discret))
                .id_salt(titre)
                .show(ui, |ui| {
                    for (cat, message) in lignes.iter().skip(COTE_MAX) {
                        ui.label(texte(&format!("{cat} · {message}"), 13.0, p.doux));
                    }
                });
        }
    });
}

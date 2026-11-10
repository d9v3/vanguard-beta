//! L'écran Bilan (la maquette acceptée) et le détail des constats, repris par les écrans des outils.

use eframe::egui::{
    self, Align, Color32, Frame, Layout, Margin, Rect, RichText, Sense, Stroke, StrokeKind, Ui, pos2, vec2,
};

use super::{
    bouton, carte, entete, icones, melange, mono, moyenne, n_f32, pal, signale, signale_avec, texte, titre_section,
};
use crate::appli::{Appli, Contenu};
use crate::commandes::Commande;
use crate::donnees::bilan::{Constat, Gravite, Rang, Vue};

/// Constats montrés au plus dans une carte de côté ; le reste est compté.
const COTE_MAX: usize = 6;
/// Constats à corriger montrés au plus (une carte chacun).
const CORRIGER_MAX: usize = 60;
/// Lignes d'un inventaire sain montrées d'emblée ; le reste se déplie.
const LISTE_MAX: usize = 40;

pub(super) fn couleur_rang(r: Rang) -> Color32 {
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
/// dernier (aucun compte inventé : on ne sait pas encore combien sont faites). `hauteur` : celle des traits (60 au
/// moins), pour que la bande remplisse la carte à côté de la note.
fn bande(ui: &mut Ui, vue: Option<&Vue>, en_cours: Option<f32>, hauteur: f32) {
    let p = pal();
    let largeur = ui.available_width();
    let groupes: Vec<(String, Vec<Rang>)> = match vue {
        Some(v) if !v.constats.is_empty() => v.groupes(),
        _ => (0..32usize)
            .map(|i| (String::new(), vec![Rang::Sain; 1 + i % 4]))
            .collect(),
    };
    let reel = vue.is_some_and(|v| !v.constats.is_empty());
    let n: usize = groupes.iter().map(|g| g.1.len()).sum();
    let g = n_f32(groupes.len().max(2));
    // Un vrai bilan : chaque sujet a sa part égale de la largeur, son nom dessous quand il y tient. Sinon (l'attente,
    // ou trop de sujets), les traits se serrent pour que la bande tienne toujours dans sa largeur.
    let fente = largeur / g;
    let noms = reel && fente >= 64.0;
    let (r, _) = ui.allocate_exact_size(vec2(largeur, hauteur + if noms { 22.0 } else { 0.0 }), Sense::hover());
    let barres = Rect::from_min_size(r.min, vec2(largeur, hauteur));
    let (w, pas, ecart) = if noms {
        let plus = groupes.iter().map(|g| g.1.len()).max().unwrap_or(1);
        let w = ((fente - 16.0) / (n_f32(plus) * 1.5)).clamp(4.0, 12.0);
        (w, w * 0.5, 0.0)
    } else {
        let w = (largeur / (n_f32(n) * 1.5 + g * 2.0)).clamp(2.0, 6.0);
        let pas = (w * 0.5).max(1.0);
        let naturel = n_f32(n) * (w + pas) - pas * g;
        (w, pas, ((largeur - naturel) / (g - 1.0)).clamp(w, 24.0))
    };
    let mut x = r.left();
    let peintre = ui.painter().clone();
    for (gi, (cat, rangs)) in groupes.iter().enumerate() {
        if noms {
            x = r.left() + fente * n_f32(gi);
        }
        let x0 = x;
        for &e in rangs {
            if x + w > r.right() {
                break;
            }
            let fini = en_cours.is_none() && reel;
            // À 60 : 56 pour ce qui est à corriger, 44 pour le reste ; plus haut, les mêmes proportions.
            let haut = hauteur
                * if e == Rang::Corriger && fini {
                    56.0 / 60.0
                } else {
                    44.0 / 60.0
                };
            let trait_ = Rect::from_min_max(pos2(x, barres.bottom() - haut), pos2(x + w, barres.bottom()));
            let mut col = if fini { couleur_rang(e) } else { p.s3 };
            // Le balayage : un mouvement, pas une information (animations réduites : les traits attendent, immobiles).
            if let Some(t) = en_cours.filter(|_| !super::mouvement::reduit()) {
                let pos = (t * 0.45) % 1.3 - 0.15;
                let d = ((x - r.left()) / r.width() - pos).abs();
                if d < 0.04 {
                    col = p.accent.gamma_multiply(1.0 - d / 0.04 * 0.6);
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
            if noms {
                let mut job = egui::text::LayoutJob::simple(cat.clone(), super::police(11.0), p.discret, fente - 12.0);
                job.wrap.max_rows = 1;
                job.wrap.overflow_character = Some('…');
                let nom = ui.fonts_mut(|f| f.layout_job(job));
                peintre.galley(pos2(x0, barres.bottom() + 8.0), nom, p.discret);
            }
            let fin = if noms { x0 + fente - 8.0 } else { x + 2.0 };
            let zone = Rect::from_min_max(pos2(x0 - 2.0, r.top()), pos2(fin, r.bottom()));
            let corriger = rangs.iter().filter(|&&e| e == Rang::Corriger).count();
            let detail = if corriger > 0 {
                crate::trf!(
                    "{} — {}, {} à corriger",
                    "{} — {}, {} to fix",
                    cat,
                    crate::trn!(rangs.len(), "vérification", "vérifications", "check", "checks"),
                    corriger
                )
            } else {
                format!(
                    "{} — {}",
                    cat,
                    crate::trn!(rangs.len(), "vérification", "vérifications", "check", "checks")
                )
            };
            ui.interact(zone, ui.scope_id().with(("groupe", gi)), Sense::hover())
                .on_hover_text(detail);
        }
        x += ecart;
    }
}

/// Les noms des sujets tiennent-ils sous la bande ? (Sinon, chaque groupe dit le sien au survol.)
fn noms_sous_la_bande(largeur: f32, v: &Vue) -> bool {
    largeur / n_f32(v.groupes().len().max(2)) >= 64.0
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
            "Fini à {} · {} en {} · rien n'est envoyé, tout se lit sur cet ordinateur",
            "Finished at {} · {} in {} · nothing is sent, everything is read on this computer",
            r.heure,
            crate::trn!(
                vue.as_ref().map_or(0, |v| v.constats.len()),
                "vérification",
                "vérifications",
                "check",
                "checks"
            ),
            crate::langue::secondes(r.duree.as_secs_f32())
        ),
        (None, None) => crate::tr!(
            "Pas encore lancé · tout se lit sur cet ordinateur, rien n'est changé ni envoyé",
            "Not run yet · everything is read on this computer, nothing is changed or sent"
        )
        .into(),
    };
    let actions = |appli: &mut Appli, ui: &mut Ui| {
        if en_cours.is_none() {
            let t = if appli.bilan().is_some() {
                crate::tr!("Refaire le bilan", "Run the check again")
            } else {
                crate::tr!("Lancer le bilan", "Run the check")
            };
            if bouton(
                ui,
                t,
                true,
                appli.programme_trouve() && !appli.en_attente(Commande::Bilan),
            )
            .clicked()
            {
                appli.demander(Commande::Bilan);
            }
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
        carte(ui, 20, |ui| {
            ui.set_width(ui.available_width());
            signale(
                ui,
                p.moyen,
                &crate::trf!("Le bilan n'a pas abouti : {}", "The check did not finish: {}", e),
                14.0,
            );
        });
        ui.add_space(16.0);
    }
    let finie = if en_cours.is_some() { None } else { vue.as_ref() };
    // Les chiffres d'un bilan montent de 0 la première fois qu'il est montré (un bilan : son heure et sa durée).
    let part = match (finie, &resultat) {
        (Some(_), Some(r)) => super::mouvement::montee(ui.ctx(), egui::Id::unique(("bilan", &r.heure, r.duree))),
        _ => 1.0,
    };
    carte(ui, 32, |ui| {
        ui.set_width(ui.available_width());
        let etroit = ui.available_width() < 760.0;
        // La note rend sa hauteur : la bande des traits, à côté, s'y ajuste.
        let note = |ui: &mut Ui| -> f32 {
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
                            // Des points non vérifiés : leur nombre sous la note, aussi visible qu'elle, avec un
                            // point d'alerte. Ils ne comptent pas comme sains. À l'encre : les couleurs vives se
                            // règlent et ne portent jamais seules un mot.
                            let couleur = p.encre;
                            match v.note.and_then(|n| usize::try_from(n).ok()) {
                                Some(n) => {
                                    super::mouvement::nombre(ui, part, n, |k| k.to_string(), &moyenne(72.0), couleur);
                                }
                                None => {
                                    ui.label(RichText::new("—").font(moyenne(72.0)).color(couleur));
                                }
                            }
                            ui.label(texte("/100", 20.0, p.discret));
                        });
                        if let Some(k) = incomplete {
                            let ecrire = |k| crate::trf!("{} pas pu vérifier", "{} could not check", k);
                            signale_avec(ui, p.moyen, 28.0, |ui| {
                                super::mouvement::nombre(ui, part, k, ecrire, &moyenne(28.0), p.encre);
                            });
                        }
                        ui.add_space(8.0);
                        if v.note.is_none() {
                            signale(
                                ui,
                                p.moyen,
                                if v.note_retenue {
                                    crate::tr!(
                                        "Pas de note : trop de points n'ont pas pu être vérifiés pour qu'elle veuille dire quelque chose.",
                                        "No score: too many points could not be checked for it to mean anything."
                                    )
                                } else {
                                    crate::tr!("Pas de note pour ce bilan.", "No score for this check.")
                                },
                                13.0,
                            );
                        }
                        ui.label(texte(
                            &phrase_note(v.compte(Rang::Corriger), v.compte(Rang::NonVerifie)),
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
            })
            .response
            .rect
            .height()
        };
        let traits = |ui: &mut Ui, hauteur: f32| {
            ui.vertical(|ui| {
                let n = finie.map_or(0, |v| v.constats.len());
                ui.horizontal(|ui| {
                    let t = if n > 0 {
                        crate::trf!(
                            "{}, par sujet",
                            "{}, by topic",
                            crate::trn!(n, "vérification", "vérifications", "check", "checks")
                        )
                    } else {
                        crate::tr!("Les vérifications, par sujet", "The checks, by topic").into()
                    };
                    ui.label(texte(&t, 13.0, p.doux));
                    // Les noms sous la bande quand ils y tiennent ; sinon, le survol les dit.
                    if let Some(v) = finie
                        && n > 0
                        && !noms_sous_la_bande(ui.available_width(), v)
                    {
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(texte(
                                crate::tr!("Survolez un groupe pour son nom", "Hover a group for its name"),
                                12.0,
                                p.discret,
                            ));
                        });
                    }
                });
                ui.add_space(12.0);
                bande(
                    ui,
                    if en_cours.is_some() { vue.as_ref() } else { finie },
                    en_cours,
                    hauteur,
                );
                ui.add_space(12.0);
                if let Some(v) = finie {
                    legende(ui, v, part);
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
            traits(ui, 60.0);
        } else {
            ui.horizontal_top(|ui| {
                // Le titre, les espaces et la légende prennent environ 80 : le reste de la hauteur de la note va
                // aux traits, entre 60 et 140.
                let h = note(ui);
                ui.add_space(40.0);
                traits(ui, (h - 80.0).clamp(60.0, 140.0));
            });
        }
    });
    ui.add_space(32.0);
    if let Some(v) = finie {
        constats(ui, v);
    }
}

/// Sous la note : ce qui est à corriger, et ce qui n'a pas pu se faire (seulement s'il y en a).
fn phrase_note(corriger: usize, non_verifies: usize) -> String {
    let corriger = crate::trf!(
        "{} à corriger.",
        "{} to fix.",
        crate::trn!(corriger, "point", "points", "point", "points")
    );
    match non_verifies {
        0 => corriger,
        1 => crate::trf!(
            "{} Une vérification n'a pas pu se faire : elle ne compte pas comme saine.",
            "{} One check could not be done: it does not count as healthy.",
            corriger
        ),
        n => crate::trf!(
            "{} {} vérifications n'ont pas pu se faire : elles ne comptent pas comme saines.",
            "{} {} checks could not be done: they do not count as healthy.",
            corriger,
            n
        ),
    }
}

fn legende(ui: &mut Ui, v: &Vue, part: f32) {
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
            super::mouvement::nombre(ui, part, k, |k| k.to_string(), &moyenne(13.0), p.encre);
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
    // Le haut de la première carte à corriger : la colonne de droite s'y aligne, pas sur le titre de la section.
    let premiere_carte = std::cell::Cell::new(None::<f32>);
    let gauche = |ui: &mut Ui, largeur: f32| {
        ui.vertical(|ui| {
            ui.set_width(largeur);
            let a_corriger = v.de_rang(Rang::Corriger);
            titre_section(ui, crate::tr!("À corriger", "To fix"), Some(a_corriger.len()));
            premiere_carte.set(Some(ui.cursor().top()));
            for c in a_corriger.iter().take(CORRIGER_MAX) {
                carte_constat(ui, c);
                ui.add_space(12.0);
            }
            if a_corriger.len() > CORRIGER_MAX {
                ui.label(texte(
                    &format!(
                        "{} {}",
                        crate::tr!("et", "and"),
                        autres(a_corriger.len() - CORRIGER_MAX)
                    ),
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
                        "{} que cette fenêtre n'a pas su lire",
                        "{} this window could not read",
                        crate::trn!(v.illisibles, "constat", "constats", "finding", "findings")
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
            // L'écart entre les éléments s'ajoute aux 24 points : sans le compter, la colonne de droite dépassait la
            // carte du dessus.
            let ecart = ui.spacing().item_spacing.x;
            gauche(ui, total - droite - 24.0 - ecart);
            ui.add_space(24.0);
            ui.vertical(|ui| {
                if let Some(y) = premiere_carte.get() {
                    ui.add_space((y - ui.cursor().top()).max(0.0));
                }
                cote(ui, droite);
            });
        });
    } else {
        gauche(ui, total);
        ui.add_space(24.0);
        cote(ui, total);
    }
}

fn carte_constat(ui: &mut Ui, c: &Constat) {
    let p = pal();
    carte(ui, 22, |ui| {
        ui.set_width(ui.available_width());
        // Toute la carte s'éclaire : jusqu'à son trait, sous un point de bord.
        super::mouvement::ligne(ui, vec2(21.0, 21.0), 15.0, |ui| {
            ui.horizontal_top(|ui| {
                let (r, _) = ui.allocate_exact_size(vec2(12.0, 16.0), Sense::hover());
                ui.painter()
                    .circle_filled(pos2(r.left() + 4.0, r.center().y), 4.0, couleur_gravite(c.gravite));
                ui.add_space(8.0);
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(texte(&c.categorie, 12.0, p.discret));
                        if let Some(g) = c.gravite {
                            ui.label(texte(g.nom(), 12.0, p.encre));
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
                    // Pas de bouton mort : la correction se fera ici, plus tard, et la carte le dit.
                    ui.add_space(10.0);
                    ui.label(texte(
                        crate::tr!(
                            "La correction viendra ici dans un prochain lot : montrée, puis acceptée.",
                            "The fix will come here in a later batch: shown, then accepted."
                        ),
                        12.0,
                        p.discret,
                    ));
                });
            })
        });
    });
}

/// Un inventaire sain, une ligne par élément (`Vue::sains_en_liste`) ; au-delà de `LISTE_MAX`, le reste se déplie.
fn liste_saine(ui: &mut Ui, liste: &[&Constat]) {
    let p = pal();
    let ligne = |ui: &mut Ui, c: &Constat| {
        super::mouvement::ligne(ui, vec2(8.0, 3.0), 6.0, |ui| {
            ui.horizontal_top(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                let (r, _) = ui.allocate_exact_size(vec2(14.0, 16.0), Sense::hover());
                icones::coche(ui.painter(), r, p.bon);
                ui.label(texte(&c.message, 13.0, p.doux));
            });
        });
    };
    carte(ui, 20, |ui| {
        ui.set_width(ui.available_width());
        for c in liste.iter().take(LISTE_MAX) {
            ligne(ui, c);
            ui.add_space(6.0);
        }
        if liste.len() > LISTE_MAX {
            let reste = liste.len() - LISTE_MAX;
            egui::CollapsingHeader::new(texte(&autres(reste), 13.0, p.discret))
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

/// « 3 autres », « 3 more ».
fn autres(n: usize) -> String {
    crate::trn!(n, "autre", "autres", "more", "more")
}

fn liste_cote(ui: &mut Ui, titre: &str, lignes: &[(String, String)], col: Color32) {
    let p = pal();
    carte(ui, 20, |ui| {
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
            super::mouvement::ligne(ui, vec2(8.0, 4.0), 6.0, |ui| {
                ui.horizontal_top(|ui| {
                    let (r, _) = ui.allocate_exact_size(vec2(12.0, 16.0), Sense::hover());
                    ui.painter().circle_filled(pos2(r.left() + 3.0, r.center().y), 3.0, col);
                    ui.vertical(|ui| {
                        ui.label(RichText::new(cat).font(moyenne(13.0)).color(p.encre));
                        ui.label(texte(message, 13.0, p.doux));
                    });
                })
            });
            ui.add_space(4.0);
        }
        if lignes.len() > COTE_MAX {
            let reste = lignes.len() - COTE_MAX;
            egui::CollapsingHeader::new(texte(&autres(reste), 13.0, p.discret))
                .id_salt(titre)
                .show(ui, |ui| {
                    for (cat, message) in lignes.iter().skip(COTE_MAX) {
                        ui.label(texte(&format!("{cat} · {message}"), 13.0, p.doux));
                    }
                });
        }
    });
}

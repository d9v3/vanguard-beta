//! Les écrans : chacun lit l'état d'`Appli` et ne demande que ses gestes (`demander`, `arreter`). Ce qui n'existe
//! pas encore dans la fenêtre le dit, au lieu d'un bouton qui ne ferait rien.

use eframe::egui::{Align, Color32, Frame, Layout, Margin, RichText, Sense, Stroke, Ui, pos2, vec2};

use super::bilan::{self, couleur_gravite};
use super::{bouton, carte, entete, mono, moyenne, pal, petit, texte, titre_section};
use crate::appli::{Appli, Contenu, Ecran, ecran_de};
use crate::commandes::{Commande, Rubrique};
use crate::donnees::evenements;
use crate::donnees::libre;
use crate::donnees::protection::{self, Allure};

/// Événements du journal montrés au plus (les plus récents).
const EVENEMENTS_MAX: usize = 200;

pub fn montrer(appli: &mut Appli, ui: &mut Ui) {
    match appli.ecran {
        Ecran::Accueil => accueil(appli, ui),
        Ecran::Bilan | Ecran::Commande(Commande::Bilan) => bilan::ecran(appli, ui),
        Ecran::Alertes | Ecran::Commande(Commande::Evenements) => alertes(appli, ui),
        Ecran::Appareils => bientot(
            ui,
            crate::tr!("Appareils", "Devices"),
            crate::tr!(
                "Les appareils de votre réseau (le scan) arrivent dans un prochain lot. Pour l'instant : le menu de Vanguard, « Réseau et Internet ».",
                "The devices on your network (the scan) come in a later batch. For now: Vanguard's menu, “Network and Internet”."
            ),
        ),
        Ecran::Rubrique(Rubrique::Vanguard) => reglages(appli, ui),
        Ecran::Rubrique(r) => rubrique(appli, ui, r),
        Ecran::Commande(c) => commande(appli, ui, c),
        Ecran::Guide => guide(appli, ui),
    }
}

fn bientot(ui: &mut Ui, titre: &str, phrase: &str) {
    entete(ui, titre, "");
    ui.add_space(24.0);
    carte(ui, 24, 16, |ui| {
        ui.set_width(ui.available_width());
        ui.label(texte(phrase, 14.0, pal().doux));
    });
}

/// Une carte qu'on clique pour ouvrir un écran.
fn tuile(appli: &mut Appli, ui: &mut Ui, titre: &str, valeur: &str, phrase: &str, couleur: Color32, vers: Ecran) {
    let p = pal();
    let rep = Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(1.0, p.trait_))
        .corner_radius(16)
        .inner_margin(Margin::same(20))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.set_min_height(120.0);
            ui.label(texte(titre, 13.0, p.doux));
            ui.add_space(4.0);
            ui.label(RichText::new(valeur).font(moyenne(24.0)).color(couleur));
            ui.add_space(4.0);
            ui.label(texte(phrase, 13.0, p.doux));
        })
        .response
        .interact(Sense::click())
        .on_hover_cursor(eframe::egui::CursorIcon::PointingHand);
    if rep.clicked() {
        appli.ecran = vers;
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
            p.encre,
        ),
        (None, _) => (crate::tr!("Pas encore", "Not yet").to_string(), String::new(), p.gris),
    };
    let (prot_v, prot_p, prot_c) = match appli.protection() {
        None => (crate::tr!("Pas lue", "Not read").to_string(), String::new(), p.gris),
        Some(v) => (
            crate::trf!("{} allumé(s)", "{} on", v.compte(Allure::Allume)),
            crate::trf!(
                "{} éteint(s), {} autre(s) état(s)",
                "{} off, {} other state(s)",
                v.compte(Allure::Eteint),
                v.compte(Allure::Nuance)
            ),
            if v.compte(Allure::Eteint) > 0 { p.moyen } else { p.encre },
        ),
    };
    let (jour_v, jour_p, jour_c) = match appli.journal() {
        None => (crate::tr!("Pas lu", "Not read").to_string(), String::new(), p.gris),
        Some(j) => (
            crate::trf!("{} alerte(s)", "{} alert(s)", j.alertes().count()),
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
        (crate::tr!("Journal", "Journal"), jour_v, jour_p, jour_c, Ecran::Alertes),
    ];
    let large = ui.available_width() >= 900.0;
    if large {
        ui.columns(3, |cols| {
            for (col, (t, v, ph, c, e)) in cols.iter_mut().zip(tuiles) {
                tuile(appli, col, t, &v, &ph, c, e);
            }
        });
    } else {
        for (t, v, ph, c, e) in tuiles {
            tuile(appli, ui, t, &v, &ph, c, e);
            ui.add_space(12.0);
        }
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
                appli.ecran = ecran_de(c);
            }
        }
    });
    ui.add_space(16.0);
    ui.label(texte(
        crate::tr!(
            "Les corrections, les réglages et l'antivirus restent dans le menu de Vanguard pour l'instant : ils arrivent ici lot par lot, toujours montrés puis acceptés.",
            "Fixes, settings and the antivirus stay in Vanguard's menu for now: they come here batch by batch, always shown then accepted."
        ),
        13.0,
        p.discret,
    ));
}

/// Une ligne d'état sous un titre : en cours, en attente, ou l'heure du dernier résultat.
fn etat_commande(appli: &Appli, c: Commande) -> String {
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
            "Fini à {} en {:.1} s",
            "Finished at {} in {:.1} s",
            r.heure,
            r.duree.as_secs_f32()
        ),
        None => crate::tr!("Pas encore lancée", "Not run yet").into(),
    }
}

/// Lancer, ou Arrêter si c'est elle qui tourne.
fn lancer_arreter(appli: &mut Appli, ui: &mut Ui, c: Commande) {
    let tourne = appli.en_cours().is_some_and(|(e, _)| e == c);
    if tourne {
        if bouton(ui, crate::tr!("Arrêter", "Stop"), false, true).clicked() {
            appli.arreter();
        }
    } else {
        let deja = appli.resultat(c).is_some();
        let t = if deja {
            crate::tr!("Relancer", "Run again")
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
        carte(ui, 24, 16, |ui| {
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
    for c in commandes {
        carte(ui, 20, 16, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(RichText::new(c.titre()).font(moyenne(16.0)).color(p.encre));
                    ui.label(texte(c.description(), 13.0, p.doux));
                    ui.label(RichText::new(etat_commande(appli, c)).font(mono(12.0)).color(p.discret));
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.push_id(c.nom(), |ui| {
                        if petit(ui, crate::tr!("Voir", "Open"), true).clicked() {
                            appli.ecran = ecran_de(c);
                        }
                        lancer_arreter(appli, ui, c);
                    });
                });
            });
        });
        ui.add_space(12.0);
    }
}

fn commande(appli: &mut Appli, ui: &mut Ui, c: Commande) {
    let p = pal();
    ui.horizontal(|ui| {
        ui.vertical(|ui| entete(ui, c.titre(), c.description()));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| lancer_arreter(appli, ui, c));
    });
    ui.label(RichText::new(etat_commande(appli, c)).font(mono(12.0)).color(p.discret));
    ui.add_space(24.0);
    let Some(r) = appli.resultat(c).cloned() else {
        ui.label(texte(
            crate::tr!("Lancez-la pour voir ce qu'elle trouve.", "Run it to see what it finds."),
            14.0,
            p.doux,
        ));
        return;
    };
    match &r.contenu {
        Contenu::Constats(v) => {
            ui.label(texte(&v.resume(), 14.0, p.doux));
            ui.add_space(16.0);
            bilan::constats(ui, v);
        }
        Contenu::Protection(v) => protection_liste(ui, v),
        Contenu::Libre(v) => libre_liste(ui, v),
        Contenu::Evenements(v) => journal(ui, v),
        Contenu::Erreur(e) => erreur(ui, e),
    }
}

fn erreur(ui: &mut Ui, e: &str) {
    carte(ui, 20, 16, |ui| {
        ui.set_width(ui.available_width());
        ui.label(texte(
            &crate::trf!("Pas de résultat lisible : {}", "No readable result: {}", e),
            14.0,
            pal().moyen,
        ));
    });
}

fn protection_liste(ui: &mut Ui, v: &protection::Vue) {
    let p = pal();
    carte(ui, 20, 16, |ui| {
        ui.set_width(ui.available_width());
        for (k, i) in v.interrupteurs.iter().enumerate() {
            if k > 0 {
                ui.separator();
            }
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
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(texte(&i.etat, 13.0, couleur));
                });
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
            ui.label(texte(
                &crate::trf!(
                    "{} interrupteur(s) que cette fenêtre n'a pas su lire : non vérifiés.",
                    "{} switch(es) this window could not read: not verified.",
                    v.illisibles
                ),
                13.0,
                p.moyen,
            ));
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
    carte(ui, 20, 16, |ui| {
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
            ui.label(texte(crate::tr!("Rien à montrer.", "Nothing to show."), 14.0, p.doux));
        }
        if v.coupe {
            ui.label(texte(
                crate::tr!(
                    "Coupé : tout n'est pas montré ici (trop long ou trop imbriqué).",
                    "Cut: not everything is shown here (too long or too nested)."
                ),
                13.0,
                p.moyen,
            ));
        }
    });
}

fn alertes(appli: &mut Appli, ui: &mut Ui) {
    let p = pal();
    let c = Commande::Evenements;
    ui.horizontal(|ui| {
        ui.vertical(|ui| entete(ui, c.titre(), c.description()));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| lancer_arreter(appli, ui, c));
    });
    ui.label(RichText::new(etat_commande(appli, c)).font(mono(12.0)).color(p.discret));
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
        None => {
            ui.label(texte(
                crate::tr!("Journal pas encore lu.", "Journal not read yet."),
                14.0,
                p.doux,
            ));
        }
    }
}

fn journal(ui: &mut Ui, j: &evenements::Vue) {
    let p = pal();
    carte(ui, 20, 16, |ui| {
        ui.set_width(ui.available_width());
        let couleur = j.etat.gravite().map_or(p.bon, |g| couleur_gravite(Some(g)));
        ui.label(RichText::new(j.etat.phrase()).font(moyenne(15.0)).color(couleur));
        if !j.raison.is_empty() {
            ui.label(texte(&j.raison, 13.0, p.doux));
        }
        if j.illisibles > 0 {
            ui.label(texte(
                &crate::trf!(
                    "{} ligne(s) illisible(s) : non vérifiées.",
                    "{} unreadable line(s): not verified.",
                    j.illisibles
                ),
                13.0,
                p.moyen,
            ));
        }
    });
    ui.add_space(24.0);
    let maintenant = chrono::Utc::now();
    let alertes: Vec<&evenements::Evenement> = j.alertes().collect();
    titre_section(ui, crate::tr!("Alertes", "Alerts"), Some(alertes.len()));
    if alertes.is_empty() {
        ui.label(texte(
            crate::tr!("Aucune alerte notée.", "No alert recorded."),
            14.0,
            p.doux,
        ));
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
    });
    ui.add_space(6.0);
}

fn reglages(appli: &mut Appli, ui: &mut Ui) {
    let p = pal();
    entete(
        ui,
        "Vanguard",
        crate::tr!(
            "Les réglages de cette fenêtre, pour cette fois.",
            "This window's settings, for this time."
        ),
    );
    ui.add_space(24.0);
    carte(ui, 20, 16, |ui| {
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
    });
    ui.add_space(12.0);
    ui.label(texte(
        crate::tr!(
            "Rien n'est enregistré : à la prochaine ouverture, la fenêtre reprend le thème du système et la langue de Vanguard. Les résultats déjà lus gardent leur langue jusqu'à la prochaine lecture.",
            "Nothing is saved: next time, the window takes the system theme and Vanguard's language again. Results already read keep their language until read again."
        ),
        13.0,
        p.discret,
    ));
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
    for c in Commande::TOUTES {
        ui.horizontal(|ui| {
            ui.push_id(c.nom(), |ui| {
                ui.set_width(ui.available_width());
                let rep = ui.add(
                    eframe::egui::Label::new(RichText::new(c.titre()).font(moyenne(14.0)).color(p.encre))
                        .sense(Sense::click()),
                );
                if rep.on_hover_cursor(eframe::egui::CursorIcon::PointingHand).clicked() {
                    appli.ecran = ecran_de(c);
                }
                ui.label(
                    RichText::new(format!("{} · {}", c.nom(), c.nom_anglais()))
                        .font(mono(12.0))
                        .color(p.discret),
                );
                ui.label(texte(c.description(), 13.0, p.doux));
            });
        });
        ui.add_space(4.0);
    }
    ui.add_space(16.0);
    ui.label(texte(
        crate::tr!(
            "Le reste de Vanguard (corrections, réglages, antivirus, clé USB) est dans son menu, en attendant d'arriver ici.",
            "The rest of Vanguard (fixes, settings, antivirus, USB key) is in its menu, until it comes here."
        ),
        13.0,
        p.discret,
    ));
}

//! Les écrans : chacun lit l'état d'`Appli` et ne demande que ses gestes (`demander`, `arreter`). Ce qui n'existe
//! pas encore dans la fenêtre le dit, au lieu d'un bouton qui ne ferait rien.

use eframe::egui::{Align, Color32, Frame, Layout, Margin, RichText, Sense, Stroke, Ui, pos2, vec2};

use super::bilan::{self, couleur_gravite};
use super::{bouton, carte, entete, mono, moyenne, pal, petit, texte, texte_et_boutons, titre_section};
use crate::appli::{Appli, Contenu, Ecran, ecran_de};
use crate::commandes::{Commande, Rubrique};
use crate::donnees::appareils::{self as scan, Empoisonnement, Upnp};
use crate::donnees::evenements;
use crate::donnees::libre;
use crate::donnees::protection::{self, Allure};

/// Événements du journal montrés au plus (les plus récents).
const EVENEMENTS_MAX: usize = 200;

/// Appareils et redirections montrés au plus : un réseau de maison en a bien moins ; au-delà, l'écran resterait
/// lisible mais lent à dessiner à chaque image.
const APPAREILS_MAX: usize = 300;

pub fn montrer(appli: &mut Appli, ui: &mut Ui) {
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

/// Une carte qu'on clique pour ouvrir un écran.
fn tuile(appli: &mut Appli, ui: &mut Ui, titre: &str, valeur: &str, phrase: &str, couleur: Color32, vers: Ecran) {
    let p = pal();
    let rep = Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(1.0, p.trait_))
        .shadow(super::ombre())
        .corner_radius(super::RAYON_CARTE)
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
    super::clavier::anneau(ui, &rep, 16.0);
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
        (None, _) => (crate::tr!("Pas encore", "Not yet").to_string(), String::new(), p.gris),
    };
    let (prot_v, prot_p, prot_c) = match appli.protection() {
        None => (crate::tr!("Pas lue", "Not read").to_string(), String::new(), p.gris),
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
        None => (crate::tr!("Pas lu", "Not read").to_string(), String::new(), p.gris),
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
                appli.aller(ecran_de(c));
            }
        }
    });
    ui.add_space(16.0);
    ui.label(texte(
        crate::tr!(
            "Ce qui change l'ordinateur (corrections, réglages, quarantaine) reste dans le menu de Vanguard pour l'instant : il arrive ici lot par lot, toujours montré puis accepté.",
            "What changes the computer (fixes, settings, quarantine) stays in Vanguard's menu for now: it comes here batch by batch, always shown then accepted."
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
        ui.label(RichText::new(etat).font(mono(12.0)).color(p.accent));
    });
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

/// Une carte par commande : son titre, ce qu'elle fait, son état, Voir et Lancer.
fn cartes_commandes(appli: &mut Appli, ui: &mut Ui, commandes: Vec<Commande>) {
    let p = pal();
    for c in commandes {
        let (etat, tourne) = (etat_commande(appli, c), tourne(appli, c));
        carte(ui, 20, |ui| {
            ui.set_width(ui.available_width());
            super::mouvement::ligne(ui, vec2(19.0, 19.0), 15.0, |ui| {
                texte_et_boutons(
                    ui,
                    c.nom(),
                    |ui| {
                        ui.label(RichText::new(c.titre()).font(moyenne(16.0)).color(p.encre));
                        ui.label(texte(c.description(), 13.0, p.doux));
                        ligne_etat(ui, etat, tourne);
                    },
                    |ui| {
                        ui.push_id(c.nom(), |ui| {
                            if petit(ui, crate::tr!("Voir", "Open"), true).clicked() {
                                appli.aller(ecran_de(c));
                            }
                            lancer_arreter(appli, ui, c);
                        });
                    },
                );
            });
        });
        ui.add_space(12.0);
    }
}

fn commande(appli: &mut Appli, ui: &mut Ui, c: Commande) {
    let p = pal();
    texte_et_boutons(
        ui,
        c.nom(),
        |ui| entete(ui, c.titre(), c.description()),
        |ui| lancer_arreter(appli, ui, c),
    );
    ligne_etat(ui, etat_commande(appli, c), tourne(appli, c));
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
        Contenu::Constats(v) if c == Commande::Demarrage => super::demarrage::liste(appli, ui, v),
        Contenu::Constats(v) => {
            ui.label(texte(&v.resume(), 14.0, p.doux));
            ui.add_space(16.0);
            bilan::constats(ui, v);
        }
        Contenu::Protection(v) => protection_liste(ui, v),
        Contenu::Libre(v) => libre_liste(ui, v),
        Contenu::Evenements(v) => journal(ui, v),
        Contenu::Appareils(v) => appareils_liste(ui, v),
        Contenu::Erreur(e) => erreur(ui, e),
    }
}

/// L'écran des appareils : le dernier scan du réseau local, appareil par appareil.
fn appareils(appli: &mut Appli, ui: &mut Ui) {
    let p = pal();
    let c = Commande::Appareils;
    texte_et_boutons(
        ui,
        c.nom(),
        |ui| entete(ui, c.titre(), c.description()),
        |ui| lancer_arreter(appli, ui, c),
    );
    ligne_etat(ui, etat_commande(appli, c), tourne(appli, c));
    ui.add_space(24.0);
    match appli.resultat(c).map(|r| r.contenu.clone()) {
        Some(Contenu::Appareils(v)) => appareils_liste(ui, &v),
        Some(Contenu::Erreur(e)) => erreur(ui, &e),
        // Une autre forme ne vient pas d'`appareils` : rien à en montrer ici.
        Some(_) | None => {
            ui.label(texte(
                crate::tr!(
                    "Lancez le scan pour voir les appareils de votre réseau (une dizaine de secondes).",
                    "Run the scan to see the devices on your network (about ten seconds)."
                ),
                14.0,
                p.doux,
            ));
        }
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
            ui.label(
                RichText::new(crate::tr!("Pas pu vérifier", "Could not check"))
                    .font(moyenne(15.0))
                    .color(p.moyen),
            );
            for m in &manques {
                ui.label(texte(m, 13.0, p.doux));
            }
        });
        ui.add_space(16.0);
    }
    reseau_entier(ui, v);
    titre_section(ui, crate::tr!("Appareils", "Devices"), Some(v.appareils.len()));
    if v.appareils.is_empty() {
        ui.label(texte(
            crate::tr!("Aucun appareil trouvé.", "No device found."),
            14.0,
            p.doux,
        ));
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
            ui.label(texte(&l, 13.0, couleur));
        }
    });
    ui.add_space(16.0);
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
                    ui.label(texte(crate::tr!("nouveau", "new"), 12.0, p.accent));
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
                ui.label(texte(t, 13.0, couleur_gravite(*g)));
            }
            if a.illisibles > 0 {
                ui.label(texte(
                    &crate::trn!(
                        a.illisibles,
                        "détail illisible : non vérifié.",
                        "détails illisibles : non vérifiés.",
                        "unreadable detail: not verified.",
                        "unreadable details: not verified."
                    ),
                    13.0,
                    p.moyen,
                ));
            }
        });
    });
}

fn erreur(ui: &mut Ui, e: &str) {
    carte(ui, 20, |ui| {
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
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(texte(&i.etat, 13.0, couleur));
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
            ui.label(texte(
                &crate::trn!(
                    v.illisibles,
                    "interrupteur que cette fenêtre n'a pas su lire : non vérifié.",
                    "interrupteurs que cette fenêtre n'a pas su lire : non vérifiés.",
                    "switch this window could not read: not verified.",
                    "switches this window could not read: not verified."
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
    texte_et_boutons(
        ui,
        c.nom(),
        |ui| entete(ui, c.titre(), c.description()),
        |ui| lancer_arreter(appli, ui, c),
    );
    ligne_etat(ui, etat_commande(appli, c), tourne(appli, c));
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
    carte(ui, 20, |ui| {
        ui.set_width(ui.available_width());
        let couleur = j.etat.gravite().map_or(p.bon, |g| couleur_gravite(Some(g)));
        ui.label(RichText::new(j.etat.phrase()).font(moyenne(15.0)).color(couleur));
        if !j.raison.is_empty() {
            ui.label(texte(&j.raison, 13.0, p.doux));
        }
        if j.illisibles > 0 {
            ui.label(texte(
                &crate::trn!(
                    j.illisibles,
                    "ligne illisible : non vérifiée.",
                    "lignes illisibles : non vérifiées.",
                    "unreadable line: not verified.",
                    "unreadable lines: not verified."
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
            "Les réglages de cette fenêtre, pour cette fois.",
            "This window's settings, for this time."
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
    ui.add_space(24.0);
    titre_section(ui, crate::tr!("Vérifier Vanguard", "Check Vanguard"), None);
    cartes_commandes(appli, ui, Rubrique::Vanguard.commandes().collect());
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

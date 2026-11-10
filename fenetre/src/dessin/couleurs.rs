//! La section « Couleurs » de l'écran Vanguard : les six préréglages et les couleurs du système, les cinq couleurs
//! vives à choisir (une pastille ouvre le sélecteur d'egui), leurs remarques de lisibilité, l'aperçu en direct dans
//! toute la fenêtre (`Appli::jeu`). Rien ne s'enregistre ici : « Enregistrer » n'ouvre que la confirmation (`Appli::
//! proposer_couleurs`), avec les couleurs d'avant et d'après ; seul « Accepter » lance `vanguard couleurs`, qui
//! revérifie et écrit. Après un changement, « Revenir à celles d'avant » propose de remettre exactement l'ancien.

use eframe::egui::{self, Color32, CornerRadius, Margin, RichText, Sense, Stroke, Ui, vec2};

use super::{bouton, carte, mono, moyenne, pal, petit, texte};
use crate::appli::Appli;
use crate::commandes::ChangementCouleurs;
use crate::couleurs::{
    Base, CONTRASTE_CONSEILLE, CONTRASTE_MIN, Choix, Jeu, Remarque, Rgb, Theme, Vif, contraste_sur_fonds,
    depuis_le_systeme, hex, remarques, verifier,
};
use crate::donnees::couleurs::Source;

fn c32(x: Rgb) -> Color32 {
    Color32::from_rgb(x[0], x[1], x[2])
}

fn nom_base(b: Base) -> &'static str {
    match b {
        Base::Vanguard => "Vanguard",
        Base::Braise => crate::tr!("Braise", "Ember"),
        Base::Emeraude => crate::tr!("Émeraude", "Emerald"),
        Base::Ambre => crate::tr!("Ambre", "Amber"),
        Base::Violet => "Violet",
        Base::Glacier => "Glacier",
        Base::Systeme => crate::tr!("Système", "System"),
    }
}

pub fn nom_vif(v: Vif) -> &'static str {
    match v {
        Vif::Accent => "Accent",
        Vif::Grave => crate::tr!("Grave", "Severe"),
        Vif::Moyen => crate::tr!("Moyen", "Medium"),
        Vif::Jaune => crate::tr!("À surveiller", "Watch"),
        Vif::Bon => crate::tr!("Sain", "Healthy"),
    }
}

fn role_vif(v: Vif) -> &'static str {
    match v {
        Vif::Accent => crate::tr!("boutons, liens, ce qui a le focus", "buttons, links, what has focus"),
        Vif::Grave => crate::tr!("alertes élevées et critiques", "high and critical alerts"),
        Vif::Moyen => crate::tr!("à corriger, gravité moyenne", "to fix, medium severity"),
        Vif::Jaune => crate::tr!("informations, à surveiller", "information, to watch"),
        Vif::Bon => crate::tr!("ce qui a été vérifié et va bien", "what was checked and is fine"),
    }
}

/// Une pastille de couleur, au rayon des boutons.
fn pastille(ui: &mut Ui, couleur: Rgb, taille: f32) {
    let (zone, _) = ui.allocate_exact_size(vec2(taille, taille), Sense::hover());
    ui.painter().rect_filled(zone, CornerRadius::same(5), c32(couleur));
    ui.painter().rect_stroke(
        zone,
        CornerRadius::same(5),
        Stroke::new(1.0, pal().trait_),
        egui::StrokeKind::Inside,
    );
}

/// Un choix en une ligne : son nom et ses cinq pastilles (rien : les couleurs de Vanguard).
fn rangee(ui: &mut Ui, etiquette: &str, theme: Theme, choix: Option<&Choix>) {
    let p = pal();
    let jeu = Jeu::de(theme, choix);
    ui.horizontal(|ui| {
        ui.add_sized(vec2(64.0, 20.0), egui::Label::new(texte(etiquette, 13.0, p.doux)));
        for v in Vif::TOUS {
            pastille(ui, jeu.vif(v), 18.0);
        }
        let nom = choix.map_or(crate::tr!("celles de Vanguard", "Vanguard's"), |c| nom_base(c.base));
        ui.label(texte(nom, 13.0, p.encre));
    });
}

/// La section entière, dans sa carte, la confirmation ouverte au-dessus.
pub fn section(appli: &mut Appli, ui: &mut Ui) {
    let p = pal();
    let theme = Theme::depuis_sombre(appli.sombre);
    if let Some((cc, avant)) = appli.confirmation_couleurs() {
        confirmation(appli, ui, cc, avant);
        ui.add_space(16.0);
    }
    let reglee = appli.couleurs().de(theme);
    let choix = appli
        .brouillon_de(theme)
        .or(reglee)
        .unwrap_or(Choix::du_prereglage(Base::Vanguard, theme));
    let mut nouveau = choix;
    carte(ui, 20, |ui| {
        ui.set_width(ui.available_width());
        let titre = match theme {
            Theme::Sombre => crate::tr!("Couleurs du thème sombre", "Dark theme colors"),
            Theme::Clair => crate::tr!("Couleurs du thème clair", "Light theme colors"),
        };
        ui.label(RichText::new(titre).font(moyenne(16.0)).color(p.encre));
        ui.label(texte(
            crate::tr!(
                "Enregistrées par Vanguard pour les prochaines ouvertures, une fois acceptées ; l'autre thème garde les siennes. En attendant, la fenêtre les montre seulement.",
                "Saved by Vanguard for next time, once accepted; the other theme keeps its own. Until then, the window only shows them."
            ),
            13.0,
            p.doux,
        ));
        if let Some(d) = appli.couleurs().doute {
            ui.add_space(4.0);
            super::signale(ui, p.encre, d.texte(), 13.0);
        }
        ui.add_space(12.0);
        prereglages(appli, ui, theme, &mut nouveau);
        ui.add_space(12.0);
        ui.separator();
        for v in Vif::TOUS {
            ligne_vif(ui, theme, &mut nouveau, v);
        }
        ui.separator();
        lisibilite(ui, theme, &nouveau, true);
        ui.add_space(12.0);
        gestes(appli, ui, theme, reglee, &nouveau);
    });
    if nouveau != choix {
        appli.brouillon = Some((theme, nouveau));
    }
}

/// Les préréglages : un clic pose ses neutres et ses cinq couleurs dans le brouillon.
fn prereglages(appli: &Appli, ui: &mut Ui, theme: Theme, choix: &mut Choix) {
    let p = pal();
    let systeme = appli.couleurs().systeme;
    // Une seule rangée (pas de rangée dans la rangée : egui les décalerait en escalier), haute dès le début pour
    // que la première pastille se centre comme les autres.
    ui.horizontal(|ui| {
        ui.set_min_height(32.0);
        ui.spacing_mut().item_spacing.x = 6.0;
        for b in Base::TOUTES {
            let accent = match (b, systeme) {
                (Base::Systeme, Some(s)) => depuis_le_systeme(theme, &s.vifs).0.vif(Vif::Accent),
                _ => b.prereglage(theme).vifs[0],
            };
            {
                pastille(ui, accent, 12.0);
                let dispo = b != Base::Systeme || systeme.is_some();
                let pose = choix.base == b;
                let r = petit(ui, nom_base(b), dispo && !pose);
                let r = match (b, systeme) {
                    (Base::Systeme, None) => r.on_disabled_hover_text(crate::tr!(
                        "Aucune couleur du système trouvée : ni thème d'Omarchy, ni couleur d'accentuation de Windows.",
                        "No system colors found: no Omarchy theme, no Windows accent color."
                    )),
                    (Base::Systeme, Some(s)) => r.on_hover_text(match s.source {
                        Source::Omarchy => crate::tr!(
                            "Les couleurs du thème d'Omarchy, lues par Vanguard, sur les neutres de Vanguard.",
                            "The Omarchy theme's colors, read by Vanguard, on Vanguard's neutrals."
                        ),
                        Source::Windows => crate::tr!(
                            "La couleur d'accentuation de Windows, lue par Vanguard ; les autres restent celles de Vanguard.",
                            "Windows' accent color, read by Vanguard; the others stay Vanguard's."
                        ),
                    }),
                    _ => r,
                };
                if r.clicked() {
                    *choix = match (b, systeme) {
                        (Base::Systeme, Some(s)) => depuis_le_systeme(theme, &s.vifs).0,
                        _ => Choix::du_prereglage(b, theme),
                    };
                }
            }
            ui.add_space(10.0);
        }
    });
    if let (Base::Systeme, Some(s)) = (choix.base, systeme) {
        let gardees = depuis_le_systeme(theme, &s.vifs).1;
        if !gardees.is_empty() {
            let noms: Vec<&str> = gardees.into_iter().map(nom_vif).collect();
            ui.label(texte(
                &crate::trf!(
                    "Gardées de Vanguard, celles du système se verraient à peine sur ce thème : {}.",
                    "Kept from Vanguard, the system's would barely show on this theme: {}.",
                    noms.join(", ")
                ),
                13.0,
                p.doux,
            ));
        }
    }
}

/// Une couleur vive : sa pastille (le sélecteur), son nom et son rôle, sa valeur, son contraste, « Par défaut ».
fn ligne_vif(ui: &mut Ui, theme: Theme, choix: &mut Choix, v: Vif) {
    let p = pal();
    let neutres = choix.base.prereglage(theme).neutres;
    let defaut = Choix::du_prereglage(choix.base, theme).vif(v);
    let mut c = choix.vif(v);
    ui.push_id(v.mot(), |ui| {
        ui.horizontal(|ui| {
            let r = egui::widgets::color_picker::color_edit_button_srgb(ui, &mut c)
                .on_hover_text(crate::tr!("Choisir la couleur", "Choose the color"));
            super::clavier::anneau(ui, &r, 4.0);
            ui.vertical(|ui| {
                ui.label(RichText::new(nom_vif(v)).font(moyenne(14.0)).color(p.encre));
                ui.label(texte(role_vif(v), 12.0, p.discret));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if petit(ui, crate::tr!("Par défaut", "Default"), c != defaut)
                    .on_hover_text(crate::trf!(
                        "Remet {} de « {} »",
                        "Puts back {} from “{}”",
                        hex(defaut),
                        nom_base(choix.base)
                    ))
                    .clicked()
                {
                    c = defaut;
                }
                let ratio = contraste_sur_fonds(&neutres, c);
                // L'encre, jamais une couleur réglable : la remarque doit se lire même si la couleur jugée ne se
                // voit pas.
                let couleur = if ratio < CONTRASTE_CONSEILLE {
                    p.encre
                } else {
                    p.discret
                };
                ui.label(
                    RichText::new(format!("{}:1", ratio_sous(ratio, CONTRASTE_CONSEILLE)))
                        .font(mono(12.0))
                        .color(couleur),
                )
                .on_hover_text(crate::tr!(
                    "Contraste sur le fond (WCAG) : 3:1 au moins est conseillé",
                    "Contrast on the background (WCAG): at least 3:1 is advised"
                ));
                ui.label(RichText::new(format!("#{}", hex(c))).font(mono(12.0)).color(p.doux));
            });
        });
    });
    choix.poser(v, c);
}

/// Ce que la lisibilité d'un choix fait dire : le refus s'il y en a un, puis chaque remarque, avec vrai pour la plus
/// lourde (« grave » pris pour « sain »), montrée en gras. La section et la confirmation disent les mêmes.
fn avis_lisibilite(theme: Theme, choix: &Choix) -> (Option<String>, Vec<(String, bool)>) {
    let refus = verifier(theme, choix).err();
    let dit = refus.map(|r| {
        crate::trf!(
            "{} se verrait à peine sur le fond (contraste {}:1, il faut au moins {}:1) : Vanguard refuserait de l'enregistrer, et la fenêtre ne la montre pas.",
            "{} would barely show on the background (contrast {}:1, at least {}:1 is needed): Vanguard would refuse to save it, and the window does not show it.",
            nom_vif(r.vif),
            ratio_sous(r.ratio, CONTRASTE_MIN),
            crate::langue::nombre(CONTRASTE_MIN, 1)
        )
    });
    // La couleur refusée l'est déjà : pas une deuxième fois en remarque.
    let remarques = remarques(theme, choix)
        .into_iter()
        .filter(|m| !matches!((m, refus), (Remarque::Contraste { vif, .. }, Some(f)) if *vif == f.vif))
        .map(|m| {
            let phrase = match m {
                Remarque::Contraste { vif, ratio } => crate::trf!(
                    "{} : peu de contraste avec le fond ({}:1, {}:1 conseillé).",
                    "{}: little contrast with the background ({}:1, {}:1 advised).",
                    nom_vif(vif),
                    ratio_sous(ratio, CONTRASTE_CONSEILLE),
                    crate::langue::nombre(CONTRASTE_CONSEILLE, 0)
                ),
                Remarque::Proches {
                    a: Vif::Grave,
                    b: Vif::Bon,
                    ..
                } => crate::trf!(
                    "{} et {} se ressemblent : une alerte risque de passer pour ce qui va bien.",
                    "{} and {} look alike: an alert may pass for what is fine.",
                    nom_vif(Vif::Grave),
                    nom_vif(Vif::Bon)
                ),
                Remarque::Proches { a: Vif::Accent, b, .. } => crate::trf!(
                    "{} et {} se ressemblent : un bouton ou « à corriger » risque de passer pour une gravité.",
                    "{} and {} look alike: a button or “to fix” may pass for a severity.",
                    nom_vif(Vif::Accent),
                    nom_vif(b)
                ),
                Remarque::Proches { a, b, .. } => crate::trf!(
                    "{} et {} se ressemblent : deux gravités risquent de se confondre.",
                    "{} and {} look alike: two severities may be confused.",
                    nom_vif(a),
                    nom_vif(b)
                ),
            };
            (phrase, m.grave_comme_sain())
        })
        .collect();
    (dit, remarques)
}

/// Un contraste à une décimale, jamais arrondi jusqu'au seuil qu'il manque : 1,496 se dit « 1,4 » sous 1,5, pas
/// « 1,5 » (qui contredirait « il faut au moins 1,5 »).
fn ratio_sous(ratio: f64, seuil: f64) -> String {
    let dixiemes = (ratio * 10.0).floor() / 10.0;
    let montre = if ratio < seuil { dixiemes } else { ratio };
    crate::langue::nombre(montre, 1)
}

/// Le refus et les remarques, à l'encre avec une marque à l'encre : jamais dans une couleur réglable, qui pourrait
/// être justement celle qui ne se voit pas. Rien à dire : « Lisible », si `lisible_dit`.
fn lisibilite(ui: &mut Ui, theme: Theme, choix: &Choix, lisible_dit: bool) {
    let p = pal();
    let (refus, remarques) = avis_lisibilite(theme, choix);
    if refus.is_none() && remarques.is_empty() {
        if lisible_dit {
            ui.label(texte(
                crate::tr!(
                    "Lisible : chaque couleur contraste avec le fond, et les gravités se distinguent.",
                    "Readable: each color contrasts with the background, and severities stand apart."
                ),
                13.0,
                p.discret,
            ));
        }
        return;
    }
    if let Some(r) = refus {
        super::signale(ui, p.encre, &r, 13.0);
    }
    for (phrase, lourde) in remarques {
        if lourde {
            super::signale_avec(ui, p.encre, 13.0, |ui| {
                ui.label(RichText::new(phrase).font(moyenne(13.0)).color(p.encre));
            });
        } else {
            super::signale(ui, p.encre, &phrase, 13.0);
        }
    }
}

/// Enregistrer, tout remettre, abandonner, revenir à celles d'avant.
fn gestes(appli: &mut Appli, ui: &mut Ui, theme: Theme, reglee: Option<Choix>, choix: &Choix) {
    let possible = appli.changement_possible();
    let lisible = verifier(theme, choix).is_ok();
    let change = reglee != Some(*choix) && !(reglee.is_none() && *choix == Choix::du_prereglage(Base::Vanguard, theme));
    ui.horizontal_wrapped(|ui| {
        let r = bouton(
            ui,
            crate::tr!("Enregistrer…", "Save…"),
            true,
            possible && lisible && change,
        )
        .on_disabled_hover_text(if !possible {
            crate::tr!(
                "Une commande tourne ou une confirmation est ouverte : un changement à la fois.",
                "A command is running or a confirmation is open: one change at a time."
            )
        } else if !lisible {
            crate::tr!("Une couleur se verrait à peine.", "A color would barely show.")
        } else {
            crate::tr!("Rien de changé.", "Nothing changed.")
        });
        if r.clicked() {
            appli.proposer_couleurs(ChangementCouleurs {
                theme,
                choix: Some(*choix),
            });
        }
        if bouton(
            ui,
            crate::tr!("Tout par défaut…", "All to default…"),
            false,
            possible && reglee.is_some(),
        )
        .on_hover_text(crate::tr!(
            "Propose de remettre les couleurs de Vanguard pour ce thème.",
            "Offers to put back Vanguard's colors for this theme."
        ))
        .clicked()
        {
            appli.proposer_couleurs(ChangementCouleurs { theme, choix: None });
        }
        if appli.brouillon_de(theme).is_some()
            && bouton(ui, crate::tr!("Abandonner", "Discard"), false, true)
                .on_hover_text(crate::tr!(
                    "Revient aux couleurs réglées, sans rien enregistrer.",
                    "Goes back to the saved colors, without saving anything."
                ))
                .clicked()
        {
            appli.abandonner_brouillon();
        }
        if let Some(cc) = appli.revenir_couleurs().filter(|cc| cc.theme == theme)
            && bouton(
                ui,
                crate::tr!("Revenir à celles d'avant…", "Back to the previous ones…"),
                false,
                possible,
            )
            .on_hover_text(crate::tr!(
                "Propose de remettre exactement les couleurs d'avant le dernier changement.",
                "Offers to put back exactly the colors from before the last change."
            ))
            .clicked()
        {
            appli.proposer_couleurs(cc);
        }
    });
}

/// La confirmation : avant, après, ce qui va se passer ; « Accepter » ou « Annuler ».
fn confirmation(appli: &mut Appli, ui: &mut Ui, cc: ChangementCouleurs, avant: Option<Choix>) {
    let p = pal();
    egui::Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(2.0, p.accent))
        .shadow(super::ombre())
        .corner_radius(super::RAYON_CARTE)
        .inner_margin(Margin::same(22))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            let question = match cc.theme {
                Theme::Sombre => crate::tr!(
                    "Enregistrer ces couleurs pour le thème sombre ?",
                    "Save these colors for the dark theme?"
                ),
                Theme::Clair => crate::tr!(
                    "Enregistrer ces couleurs pour le thème clair ?",
                    "Save these colors for the light theme?"
                ),
            };
            ui.label(RichText::new(question).font(moyenne(18.0)).color(p.encre));
            ui.add_space(10.0);
            rangee(ui, crate::tr!("Avant", "Before"), cc.theme, avant.as_ref());
            rangee(ui, crate::tr!("Après", "After"), cc.theme, cc.choix.as_ref());
            // Ce qui se lirait mal se redit ici, au moment d'accepter : prévenu, pas seulement plus haut.
            if let Some(apres) = cc.choix {
                ui.add_space(6.0);
                lisibilite(ui, cc.theme, &apres, false);
            }
            ui.add_space(8.0);
            ui.label(texte(
                crate::tr!(
                    "Vanguard les revérifie puis les garde dans ses réglages scellés. « Revenir à celles d'avant » les remet ensuite exactement.",
                    "Vanguard checks them again then keeps them in its sealed settings. “Back to the previous ones” then puts them back exactly."
                ),
                14.0,
                p.doux,
            ));
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                let libre = appli.en_cours().is_none() && appli.taches() == 0;
                let accepter = bouton(ui, crate::tr!("Accepter", "Accept"), true, libre).on_disabled_hover_text(
                    crate::tr!(
                        "Une commande tourne encore : attendez sa fin.",
                        "A command is still running: wait for it to end."
                    ),
                );
                if accepter.clicked() {
                    appli.accepter();
                }
                if bouton(ui, crate::tr!("Annuler", "Cancel"), false, true).clicked() {
                    appli.annuler();
                }
            });
        });
}

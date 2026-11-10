//! Un journal qui défile : la console et les coulisses. Il reste collé à la ligne la plus récente tant que la personne
//! ne remonte pas ; si elle remonte, une pastille « ↓ N nouvelles lignes » compte ce qui est arrivé depuis et la ramène
//! en bas d'un clic. Chaque ligne est complète, repliée à la largeur, et son texte se sélectionne. Seules les lignes
//! visibles sont mises en page et dessinées : la hauteur de chacune est mesurée une fois, à son arrivée, et gardée.

use std::collections::VecDeque;
use std::sync::Arc;

use eframe::egui::text::{LayoutJob, TextFormat};
use eframe::egui::{
    self, Align, Align2, Color32, Galley, Id, Label, Rect, ScrollArea, Sense, Ui, UiBuilder, pos2, vec2,
};

use super::{melange, mono, pal, police, survol};

/// La hauteur d'une ligne de texte ; une ligne repliée en prend plusieurs.
pub const HAUTEUR_LIGNE: f32 = 20.0;

/// Une ligne du journal, telle que l'appelant la donne.
pub struct Rangee<'a> {
    /// Croissant, jamais réutilisé : la mesure de la ligne et le compte des nouvelles s'y accrochent.
    pub numero: u64,
    pub heure: &'a str,
    pub source: &'a str,
    pub couleur_source: Color32,
    pub texte: &'a str,
    pub couleur: Color32,
}

/// Où commencent les colonnes depuis le bord gauche, la marge à droite et le vide sous la dernière ligne.
#[derive(Clone, Copy)]
pub struct Colonnes {
    pub heure: f32,
    pub source: f32,
    pub texte: f32,
    pub droite: f32,
    pub dessous: f32,
}

/// Ce que le journal a vu à cette image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vu {
    /// Collé à la ligne la plus récente.
    pub en_bas: bool,
    /// Les lignes arrivées depuis que la personne a remonté.
    pub nouvelles: usize,
}

/// Les hauteurs mesurées, dans l'ordre des lignes, pour une largeur de texte.
#[derive(Clone, Default)]
struct Mesures {
    largeur: f32,
    hauteurs: VecDeque<(u64, f32)>,
}

#[derive(Clone, Copy, Default)]
struct Suivi {
    /// La dernière ligne vue en bas : celles d'après sont nouvelles.
    vu: u64,
    /// Le dernier compte montré, gardé pendant le fondu de sortie de la pastille.
    montre: usize,
    /// Un clic sur la pastille : redescendre à l'image suivante.
    descendre: bool,
}

/// Le journal de `n` lignes dans `ui.max_rect()`. `curseur` : le curseur clignotant après la dernière ligne, allumé à
/// cette image.
pub fn journal<'a>(
    ui: &mut Ui,
    id: Id,
    n: usize,
    rangee: impl Fn(usize) -> Option<Rangee<'a>>,
    col: Colonnes,
    curseur: bool,
) -> Vu {
    let p = pal();
    let zone = ui.max_rect();
    let largeur = (zone.width() - col.texte - col.droite).max(80.0);
    let cle_mesures = id.with("mesures");
    let cle_suivi = id.with("suivi");
    let mut m: Mesures = ui
        .ctx()
        .data_mut(|d| std::mem::take(d.get_temp_mut_or_default::<Mesures>(cle_mesures)));
    let mut suivi: Suivi = ui.ctx().data(|d| d.get_temp(cle_suivi)).unwrap_or_default();
    if (m.largeur - largeur).abs() > 0.5 {
        m.hauteurs.clear();
        m.largeur = largeur;
    }
    accorder(&mut m.hauteurs, n, |i| rangee(i).map_or(0, |r| r.numero));
    for i in m.hauteurs.len()..n {
        let Some(r) = rangee(i) else {
            break;
        };
        let g = mise_en_page(ui, r.texte, r.couleur, largeur);
        m.hauteurs.push_back((r.numero, g.size().y.max(HAUTEUR_LIGNE)));
    }
    // Ce qui est mesuré est ce qui se montre (toujours toutes, sauf un appelant qui mentirait sur `n`).
    let n = m.hauteurs.len();
    // Le haut de chaque ligne, puis le bas de la dernière.
    let mut haut = Vec::with_capacity(n + 1);
    let mut y = 0.0;
    haut.push(y);
    for (_, h) in &m.hauteurs {
        y += h;
        haut.push(y);
    }
    let total = y + col.dessous;
    let descendre = std::mem::take(&mut suivi.descendre);
    let sortie = ScrollArea::vertical()
        .id_salt(id)
        .stick_to_bottom(true)
        .auto_shrink(false)
        .show_viewport(ui, |ui, vue| {
            // Peu de lignes : posées en bas, la plus récente juste au-dessus de la saisie, comme dans un terminal.
            let vide = (vue.height() - total).max(0.0);
            ui.set_height(vide + total);
            let origine = ui.max_rect().top() + vide;
            let x0 = ui.max_rect().left();
            let premiere = haut
                .get(1..)
                .map_or(0, |b| b.partition_point(|b| b + vide <= vue.min.y));
            let derniere = haut.get(..n).map_or(0, |t| t.partition_point(|t| t + vide < vue.max.y));
            // Les plus anciennes s'effacent vers le haut quand d'autres sont cachées au-dessus.
            let estompe = vue.min.y > 0.5;
            let peintre = ui.painter().clone();
            for i in premiere..derniere {
                let (Some(r), Some(h)) = (rangee(i), haut.get(i)) else {
                    continue;
                };
                let y = origine + h;
                let rel = y - (ui.max_rect().top() + vue.min.y);
                let a = if estompe && rel < HAUTEUR_LIGNE - 0.5 {
                    0.35
                } else if estompe && rel < 2.0 * HAUTEUR_LIGNE - 0.5 {
                    0.6
                } else {
                    1.0
                };
                let milieu = y + HAUTEUR_LIGNE / 2.0;
                peintre.text(
                    pos2(x0 + col.heure, milieu),
                    Align2::LEFT_CENTER,
                    r.heure,
                    mono(13.0),
                    p.discret.gamma_multiply(a),
                );
                peintre.text(
                    pos2(x0 + col.source, milieu),
                    Align2::LEFT_CENTER,
                    r.source,
                    mono(13.0),
                    r.couleur_source.gamma_multiply(a),
                );
                let g = mise_en_page(ui, r.texte, r.couleur.gamma_multiply(a), largeur);
                let place = Rect::from_min_size(pos2(x0 + col.texte, y), g.size());
                let fin = g.rows.last().map(|l| l.rect().translate(place.min.to_vec2()));
                // Un identifiant par ligne, pas par place : une sélection en cours tient pendant le défilement.
                ui.scope_builder(
                    UiBuilder::new().scope_id(id.with(("ligne", r.numero))).max_rect(place),
                    |ui| ui.add(Label::new(g).selectable(true)),
                );
                if i + 1 == n
                    && curseur
                    && let Some(f) = fin
                {
                    peintre.rect_filled(
                        Rect::from_min_size(pos2(f.right() + 3.0, f.center().y - 7.0), vec2(7.0, 14.0)),
                        0,
                        p.accent,
                    );
                }
            }
            if descendre {
                let bas = Rect::from_min_size(pos2(x0, origine + total - 1.0), vec2(1.0, 1.0));
                ui.scroll_to_rect(bas, Some(Align::BOTTOM));
            }
        });
    let max = (sortie.content_size.y - sortie.inner_rect.height()).max(0.0);
    let en_bas = !descendre && sortie.state.clamped_offset().y >= max - 0.5;
    let derniere = m.hauteurs.back().map_or(0, |(k, _)| *k);
    if en_bas {
        suivi.vu = derniere;
    }
    let nouvelles = n - m.hauteurs.partition_point(|(k, _)| *k <= suivi.vu);
    pastille(ui, id, zone, col, nouvelles, &mut suivi);
    ui.ctx().data_mut(|d| {
        d.insert_temp(cle_mesures, m);
        d.insert_temp(cle_suivi, suivi);
    });
    Vu { en_bas, nouvelles }
}

/// La pastille « ↓ N nouvelles lignes », en fondu, en bas au centre du journal.
fn pastille(ui: &mut Ui, id: Id, zone: Rect, col: Colonnes, nouvelles: usize, suivi: &mut Suivi) {
    let p = pal();
    if nouvelles > 0 {
        suivi.montre = nouvelles;
    }
    let t = ui
        .ctx()
        .animate_bool_with_time(id.with("pastille-fondu"), nouvelles > 0, super::mouvement::SURVOL);
    if t <= 0.0 || suivi.montre == 0 {
        return;
    }
    let mot = if suivi.montre == 1 {
        crate::tr!("↓ 1 nouvelle ligne", "↓ 1 new line").to_owned()
    } else {
        crate::trf!("↓ {} nouvelles lignes", "↓ {} new lines", suivi.montre)
    };
    let g = ui.painter().layout_no_wrap(mot, police(12.0), p.sur_vif);
    let taille = vec2(g.size().x + 28.0, 26.0);
    let rect = Rect::from_min_size(
        pos2(
            zone.center().x - taille.x / 2.0,
            zone.bottom() - col.dessous - taille.y - 4.0,
        ),
        taille,
    );
    // Cliquable seulement quand elle a quelque chose à dire : en sortant, elle ne fait que s'effacer.
    let rep = (nouvelles > 0).then(|| ui.interact(rect, id.with("pastille"), Sense::click()));
    let s = if let Some(rep) = &rep {
        if rep.clicked() {
            suivi.descendre = true;
            ui.ctx().request_repaint();
        }
        let s = survol(ui, rep.id, rep.hovered());
        rep.clone().on_hover_cursor(egui::CursorIcon::PointingHand);
        s
    } else {
        0.0
    };
    let fond = melange(p.accent, p.encre, 1.0 - 0.16 * s);
    ui.painter().rect_filled(rect, 13, fond.gamma_multiply(t));
    ui.painter()
        .galley(rect.center() - g.size() / 2.0, g, p.sur_vif.gamma_multiply(t));
    if let Some(rep) = &rep {
        super::clavier::anneau(ui, rep, 13.0);
    }
}

/// Le texte d'une ligne, replié à `largeur`, une ligne de texte tous les `HAUTEUR_LIGNE` points.
fn mise_en_page(ui: &Ui, texte: &str, couleur: Color32, largeur: f32) -> Arc<Galley> {
    let mut job = LayoutJob::single_section(
        texte.to_owned(),
        TextFormat {
            font_id: mono(13.0),
            color: couleur,
            line_height: Some(HAUTEUR_LIGNE),
            ..Default::default()
        },
    );
    job.wrap.max_width = largeur;
    ui.fonts_mut(|f| f.layout_job(job))
}

/// Garde les mesures alignées sur les lignes : les plus anciennes parties sont oubliées ; si rien ne concorde plus
/// (la console effacée), tout est remesuré.
fn accorder(h: &mut VecDeque<(u64, f32)>, n: usize, numero: impl Fn(usize) -> u64) {
    if n == 0 {
        h.clear();
        return;
    }
    let premier = numero(0);
    while h.front().is_some_and(|(k, _)| *k < premier) {
        h.pop_front();
    }
    let concorde = h.len() <= n
        && h.front().is_none_or(|(k, _)| *k == premier)
        && h.back().is_none_or(|(k, _)| *k == numero(h.len() - 1));
    if !concorde {
        h.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eframe::egui::{Event, Modifiers, MouseWheelSource, MouseWheelUnit, PointerButton, Pos2, RawInput, TouchPhase};

    const COL: Colonnes = Colonnes {
        heure: 32.0,
        source: 116.0,
        texte: 220.0,
        droite: 32.0,
        dessous: 12.0,
    };

    /// Un journal de six lignes de haut, image par image, sans fenêtre.
    struct Banc {
        ctx: egui::Context,
        temps: f64,
        lignes: Vec<(u64, String)>,
    }

    impl Banc {
        fn nouveau(n: u64) -> Banc {
            let ctx = egui::Context::default();
            super::super::polices(&ctx);
            let mut b = Banc {
                ctx,
                temps: 0.0,
                lignes: Vec::new(),
            };
            b.ajouter(n);
            b
        }

        fn zone() -> Rect {
            Rect::from_min_size(pos2(0.0, 40.0), vec2(800.0, 12.0 + HAUTEUR_LIGNE * 6.0))
        }

        fn ajouter(&mut self, n: u64) {
            let debut = self.lignes.last().map_or(1, |(k, _)| k + 1);
            for k in debut..debut + n {
                self.lignes.push((k, format!("ligne {k}")));
            }
        }

        fn image(&mut self, evenements: Vec<Event>) -> Vu {
            self.temps += 0.05;
            let entree = RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(800.0, 400.0))),
                time: Some(self.temps),
                events: evenements,
                ..Default::default()
            };
            let lignes = &self.lignes;
            let mut vu = None;
            self.ctx
                .run_ui(entree, |ui| {
                    let r = ui.scope_builder(UiBuilder::new().max_rect(Banc::zone()), |ui| {
                        journal(
                            ui,
                            Id::unique("essai"),
                            lignes.len(),
                            |i| {
                                lignes.get(i).map(|(k, t)| Rangee {
                                    numero: *k,
                                    heure: "12:00:00",
                                    source: "essai",
                                    couleur_source: Color32::GRAY,
                                    texte: t,
                                    couleur: Color32::WHITE,
                                })
                            },
                            COL,
                            false,
                        )
                    });
                    vu = Some(r.inner);
                })
                .textures_delta
                .clear();
            vu.unwrap()
        }

        fn souris(&mut self) -> Vu {
            self.image(vec![Event::PointerMoved(Banc::zone().center())])
        }

        fn molette(&mut self, points: f32) -> Vu {
            self.image(vec![
                Event::PointerMoved(Banc::zone().center()),
                Event::MouseWheel {
                    unit: MouseWheelUnit::Point,
                    delta: vec2(0.0, points),
                    phase: TouchPhase::Move,
                    source: MouseWheelSource::Unknown,
                    modifiers: Modifiers::NONE,
                },
            ])
        }

        fn clic(&mut self, ou: Pos2) {
            let bouton = |pressed| Event::PointerButton {
                pos: ou,
                button: PointerButton::Primary,
                pressed,
                modifiers: Modifiers::NONE,
            };
            self.image(vec![Event::PointerMoved(ou)]);
            self.image(vec![bouton(true)]);
            self.image(vec![bouton(false)]);
        }
    }

    /// Collé en bas par défaut, même quand des lignes arrivent.
    #[test]
    fn collee_en_bas_par_defaut() {
        let mut b = Banc::nouveau(40);
        for _ in 0..3 {
            assert_eq!(
                b.souris(),
                Vu {
                    en_bas: true,
                    nouvelles: 0
                }
            );
        }
        b.ajouter(7);
        for _ in 0..3 {
            assert_eq!(
                b.souris(),
                Vu {
                    en_bas: true,
                    nouvelles: 0
                }
            );
        }
    }

    /// Remontée à la molette : la pastille compte les lignes arrivées depuis ; un clic la ramène en bas.
    #[test]
    fn remontee_pastille_et_retour() {
        let mut b = Banc::nouveau(40);
        b.souris();
        b.souris();
        let mut vu = b.souris();
        for _ in 0..20 {
            vu = b.molette(60.0);
        }
        for _ in 0..10 {
            vu = b.souris();
        }
        assert_eq!(
            vu,
            Vu {
                en_bas: false,
                nouvelles: 0
            }
        );
        b.ajouter(5);
        for _ in 0..3 {
            vu = b.souris();
        }
        assert_eq!(
            vu,
            Vu {
                en_bas: false,
                nouvelles: 5
            }
        );
        b.ajouter(1);
        assert_eq!(b.souris().nouvelles, 6);
        // La pastille : en bas au centre du journal.
        let z = Banc::zone();
        b.clic(pos2(z.center().x, z.bottom() - COL.dessous - 4.0 - 13.0));
        for _ in 0..20 {
            vu = b.souris();
        }
        assert_eq!(
            vu,
            Vu {
                en_bas: true,
                nouvelles: 0
            }
        );
        // Et elle y reste : de nouvelles lignes ne comptent plus comme nouvelles.
        b.ajouter(3);
        for _ in 0..3 {
            vu = b.souris();
        }
        assert_eq!(
            vu,
            Vu {
                en_bas: true,
                nouvelles: 0
            }
        );
    }

    /// Peu de lignes : rien ne défile, tout est « en bas ».
    #[test]
    fn peu_de_lignes() {
        let mut b = Banc::nouveau(2);
        b.molette(60.0);
        assert_eq!(
            b.souris(),
            Vu {
                en_bas: true,
                nouvelles: 0
            }
        );
        let mut vide = Banc::nouveau(0);
        assert_eq!(
            vide.souris(),
            Vu {
                en_bas: true,
                nouvelles: 0
            }
        );
    }

    #[test]
    fn les_mesures_suivent_les_lignes() {
        let mut h: VecDeque<(u64, f32)> = (1..=5).map(|k| (k, 20.0)).collect();
        // Deux parties devant, trois arrivées derrière : les trois restantes gardent leur mesure.
        accorder(&mut h, 6, |i| 3 + i as u64);
        assert_eq!(h.iter().map(|(k, _)| *k).collect::<Vec<_>>(), [3, 4, 5]);
        // Effacée puis remplie : rien ne concorde, tout est remesuré.
        accorder(&mut h, 2, |i| 40 + i as u64);
        assert!(h.is_empty());
        let mut h: VecDeque<(u64, f32)> = (1..=3).map(|k| (k, 20.0)).collect();
        accorder(&mut h, 0, |_| 0);
        assert!(h.is_empty());
    }
}

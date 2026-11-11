//! Ce que les polices embarquées dessinent vraiment, mesuré par la mise en page d'egui sans fenêtre : chaque signe
//! que le nettoyage laisse passer (`nettoyage::dessin`) laisse de l'encre, avec une largeur, et n'est pas la case
//! vide d'un signe absent ; chaque marque permise se voit sur sa lettre, seule ou à deux.

use std::collections::{BTreeMap, HashSet};

use eframe::egui::{self, FontFamily, FontId};

use crate::nettoyage::{Dessin, dessin};

fn contexte() -> egui::Context {
    let ctx = egui::Context::default();
    super::polices(&ctx);
    // Une image pour charger les polices ; ses textures ne vont nulle part.
    let mut sortie = ctx.run_ui(egui::RawInput::default(), |_| {});
    sortie.textures_delta.clear();
    ctx
}

const FAMILLES: [fn() -> FontFamily; 3] = [
    || FontFamily::Proportional,
    || FontFamily::Monospace,
    || FontFamily::Name("m".into()),
];

/// Les glyphes de `texte` qui laissent de l'encre : le premier caractère de leur grappe, leur place et leur image.
fn glyphes(ctx: &egui::Context, famille: &FontFamily, texte: String) -> Vec<egui::epaint::text::Glyph> {
    let galerie = ctx.fonts_mut(|f| f.layout_no_wrap(texte, FontId::new(14.0, famille.clone()), egui::Color32::WHITE));
    galerie.rows.iter().flat_map(|r| r.row.glyphs.iter().copied()).collect()
}

/// Les signes de `signes` que les polices de cette famille ont (pas la case vide d'un signe absent) et qui, mis entre
/// « x » et une espace, se dessinent eux-mêmes : un glyphe à eux, de l'encre et une largeur.
fn dessines(ctx: &egui::Context, famille: &FontFamily, signes: &[char]) -> HashSet<char> {
    let police = FontId::new(14.0, famille.clone());
    let presents: Vec<char> = ctx.fonts_mut(|f| signes.iter().copied().filter(|&c| f.has_glyph(&police, c)).collect());
    let mut vus = HashSet::new();
    for morceau in presents.chunks(2048) {
        let texte: String = morceau.iter().flat_map(|&c| ['x', c, ' ']).collect();
        for g in glyphes(ctx, famille, texte) {
            if !g.uv_rect.is_nothing() && g.advance_width > 0.0 {
                vus.insert(g.chr);
            }
        }
    }
    let presents: HashSet<char> = presents.into_iter().collect();
    vus.retain(|c| presents.contains(c));
    vus
}

fn tous() -> impl Iterator<Item = char> {
    (0..=u32::from(char::MAX)).filter_map(char::from_u32)
}

/// P1 : chaque signe que le nettoyage montre tel quel se dessine, dans les trois familles de la fenêtre. Une police
/// changée qui perdrait un signe fait échouer ce test (le signe devient « � » dans `nettoyage::ENCRE`).
#[test]
fn chaque_signe_montre_se_dessine() {
    let ctx = contexte();
    let encre: Vec<char> = tous().filter(|&c| dessin(c) == Dessin::Encre).collect();
    assert!(encre.len() > 1000, "{}", encre.len());
    for famille in FAMILLES.map(|f| f()) {
        let vus = dessines(&ctx, &famille, &encre);
        let manque: Vec<String> = encre
            .iter()
            .filter(|c| !vus.contains(c))
            .map(|&c| format!("U+{:04X}", u32::from(c)))
            .collect();
        assert!(manque.is_empty(), "{famille:?} : {manque:?}");
    }
}

/// L'image de chaque texte comme egui la peindrait (un point, un pixel) : l'encre de chaque pixel, glyphe par glyphe.
/// L'atlas des polices est lu une fois, après toutes les mises en page (il grandit à chaque glyphe nouveau).
fn images(ctx: &egui::Context, famille: &FontFamily, textes: &[String]) -> Vec<BTreeMap<(i32, i32), u32>> {
    let police = FontId::new(14.0, famille.clone());
    let galeries: Vec<_> = textes
        .iter()
        .map(|t| ctx.fonts_mut(|f| f.layout_no_wrap(t.clone(), police.clone(), egui::Color32::WHITE)))
        .collect();
    let atlas = ctx.fonts_mut(|f| f.image());
    galeries
        .iter()
        .map(|g| {
            let mut image = BTreeMap::new();
            for r in &g.rows {
                for gl in r.row.glyphs.iter().filter(|gl| !gl.uv_rect.is_nothing()) {
                    let u = gl.uv_rect;
                    // raison : des positions de quelques centaines de points, arrondies au pixel.
                    #[allow(clippy::cast_possible_truncation)]
                    let (x0, y0) = (
                        (r.pos.x + gl.pos.x + u.offset.x).round() as i32,
                        (r.pos.y + gl.pos.y + u.offset.y).round() as i32,
                    );
                    for y in u.min[1]..u.max[1] {
                        for x in u.min[0]..u.max[0] {
                            let encre = atlas.pixels[usize::from(y) * atlas.size[0] + usize::from(x)].a();
                            if encre > 0 {
                                let p = (x0 + i32::from(x - u.min[0]), y0 + i32::from(y - u.min[1]));
                                *image.entry(p).or_insert(0) += u32::from(encre);
                            }
                        }
                    }
                }
            }
            image
        })
        .collect()
}

/// P1 : chaque marque permise change l'image de sa lettre, sur des lettres de trois alphabets (dont « i » et « j »,
/// dont le point fait place à certaines marques), dans les trois familles ; et deux marques différentes sur la même
/// lettre se voient chacune (l'image des deux n'est celle d'aucune des deux seule).
#[test]
fn chaque_marque_permise_se_voit() {
    let ctx = contexte();
    let marques: Vec<char> = tous().filter(|&c| dessin(c) == Dessin::Marque).collect();
    assert!(marques.contains(&'\u{301}') && marques.len() < 40, "{marques:?}");
    let lettres: Vec<char> = ('a'..='z')
        .chain('A'..='Z')
        .chain("0ıȷжЖиωΩα\u{fffd}".chars())
        .collect();
    let nom = |t: &str| {
        t.chars()
            .map(|c| format!("U+{:04X}", u32::from(c)))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let mut caches = Vec::new();
    for famille in FAMILLES.map(|f| f()) {
        let mut textes: Vec<String> = Vec::new();
        for &l in &lettres {
            textes.push(l.to_string());
            textes.extend(marques.iter().map(|m| format!("{l}{m}")));
        }
        let vus = images(&ctx, &famille, &textes);
        let image: std::collections::HashMap<&str, &BTreeMap<(i32, i32), u32>> =
            textes.iter().map(String::as_str).zip(vus.iter()).collect();
        for &l in &lettres {
            let seule = image[l.to_string().as_str()];
            assert!(!seule.is_empty(), "{famille:?} {}", nom(&l.to_string()));
            for m in &marques {
                let t = format!("{l}{m}");
                if image[t.as_str()] == seule {
                    caches.push(format!("{famille:?} {}", nom(&t)));
                }
            }
        }
        let mut deux: Vec<String> = Vec::new();
        for m in &marques {
            for n in marques.iter().filter(|&n| n != m) {
                deux.extend([format!("x{m}"), format!("x{n}"), format!("x{m}{n}")]);
            }
        }
        let vus = images(&ctx, &famille, &deux);
        for (i, trois) in vus.chunks(3).enumerate() {
            if trois[2] == trois[0] || trois[2] == trois[1] {
                caches.push(format!("{famille:?} {}", nom(&deux[i * 3 + 2])));
            }
        }
    }
    assert!(caches.is_empty(), "une marque qui ne se voit pas : {caches:?}");
}

/// Refait la liste `nettoyage::ENCRE` d'après les polices (à lancer quand une police change, en mode optimisé) :
/// `cargo test --release --manifest-path fenetre/Cargo.toml encre::refaire_la_liste -- --ignored --nocapture`.
#[test]
#[ignore = "outil : refait la liste des signes dessinés"]
fn refaire_la_liste() {
    use std::fmt::Write as _;

    use unicode_general_category::{GeneralCategory as G, get_general_category};
    let ctx = contexte();
    let candidats: Vec<char> = tous()
        .filter(|&c| {
            !matches!(
                get_general_category(c),
                G::Control
                    | G::Format
                    | G::Unassigned
                    | G::PrivateUse
                    | G::Surrogate
                    | G::LineSeparator
                    | G::ParagraphSeparator
                    | G::SpaceSeparator
                    | G::NonspacingMark
                    | G::SpacingMark
                    | G::EnclosingMark
            )
        })
        .collect();
    let mut communs: Option<HashSet<char>> = None;
    for famille in FAMILLES.map(|f| f()) {
        let vus = dessines(&ctx, &famille, &candidats);
        communs = Some(match communs {
            None => vus,
            Some(avant) => avant.intersection(&vus).copied().collect(),
        });
    }
    let mut signes: Vec<u32> = communs.unwrap_or_default().into_iter().map(u32::from).collect();
    signes.sort_unstable();
    let mut plages: Vec<(u32, u32)> = Vec::new();
    for s in signes {
        match plages.last_mut() {
            Some((_, fin)) if *fin + 1 == s => *fin = s,
            _ => plages.push((s, s)),
        }
    }
    let mut sortie = String::new();
    for (debut, fin) in &plages {
        if debut == fin {
            let _ = write!(sortie, "(0x{debut:04X}, 0x{debut:04X}), ");
        } else {
            let _ = write!(sortie, "(0x{debut:04X}, 0x{fin:04X}), ");
        }
    }
    println!("{} plages\n{sortie}", plages.len());
}

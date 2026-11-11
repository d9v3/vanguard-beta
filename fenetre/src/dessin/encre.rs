//! Ce que les polices embarquées dessinent vraiment, mesuré par la mise en page d'egui sans fenêtre : chaque signe
//! que le nettoyage laisse passer (`nettoyage::dessin`) laisse de l'encre, avec une largeur, et n'est pas la case
//! vide d'un signe absent ; chaque marque permise se voit sur sa lettre, seule ou à deux ; deux signes montrés ne
//! se dessinent pas pareil (sauf des lettres d'alphabets différents), et aucun ne se dessine comme une suite de
//! signes dans la feuille de correction.

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
fn images(ctx: &egui::Context, famille: &FontFamily, textes: &[String]) -> Vec<Image> {
    let police = FontId::new(14.0, famille.clone());
    let galeries: Vec<_> = textes
        .iter()
        .map(|t| ctx.fonts_mut(|f| f.layout_no_wrap(t.clone(), police.clone(), egui::Color32::WHITE)))
        .collect();
    let atlas = ctx.fonts_mut(|f| f.image());
    galeries.iter().map(|g| image(&atlas, g, egui::Vec2::ZERO)).collect()
}

/// Une image de texte : l'encre cumulée de chaque pixel, par position (x, y).
pub type Image = BTreeMap<(i32, i32), u32>;

/// L'image d'une mise en page placée en `ou` : l'encre de chaque pixel, glyphe par glyphe, lue dans l'atlas `atlas`
/// (lu après la mise en page : il grandit à chaque glyphe nouveau).
pub fn image(atlas: &egui::ColorImage, g: &egui::Galley, ou: egui::Vec2) -> Image {
    let mut image = BTreeMap::new();
    for r in &g.rows {
        for gl in r.row.glyphs.iter().filter(|gl| !gl.uv_rect.is_nothing()) {
            let u = gl.uv_rect;
            // raison : des positions de quelques milliers de points au plus, arrondies au pixel.
            #[allow(clippy::cast_possible_truncation)]
            let (x0, y0) = (
                (ou.x + r.pos.x + gl.pos.x + u.offset.x).round() as i32,
                (ou.y + r.pos.y + gl.pos.y + u.offset.y).round() as i32,
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
        let image: std::collections::HashMap<&str, &Image> =
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

/// Les signes que les polices dessinent mais que `nettoyage::ENCRE` ne montre pas tels quels (ils deviennent « � ») :
/// ceux qui se dessinent exactement comme un autre signe de la liste (chiffres romains, tirets, points et
/// apostrophes en double, lettres grecques avec l'oxia, doubles de « K », « Å », « Ω », pièces de crochets, cercles
/// et flèches en double…), ou comme une suite (« ‥ », « ․ », « Ѹ »), et les sosies très proches que le terminal écrit
/// aussi `\u{…}` (`machine::apercu::se_montre` : « Đ », « ı », « ſ », « ĸ », « Ĳ », « ĳ », « Ŀ », « ŀ », « ŉ »). Pour
/// chaque paire, celui que Vanguard écrit reste (« ► », « ♥ », « Ð »). Tenus par
/// `deux_signes_montres_ne_se_dessinent_pas_pareil` et `aucune_suite_ne_dessine_un_signe`.
#[rustfmt::skip]
const ECARTES: &[(u32, u32)] = &[
    (0x0110, 0x0110), (0x0131, 0x0133), (0x0138, 0x0138), (0x013F, 0x0140), (0x0149, 0x0149), (0x017F, 0x017F),
    (0x0189, 0x0189), (0x019E, 0x019E), (0x01C3, 0x01C3), (0x01DD, 0x01DD), (0x0261, 0x0261), (0x02B9, 0x02B9),
    (0x02BC, 0x02BC), (0x02C9, 0x02C9), (0x02D3, 0x02D3), (0x02EE, 0x02EE), (0x0375, 0x0375), (0x037E, 0x037E),
    (0x0387, 0x0387), (0x03FA, 0x03FA), (0x0472, 0x0472), (0x0478, 0x0479), (0x048C, 0x048C), (0x04C0, 0x04C0),
    (0x04CF, 0x04CF), (0x1D0D, 0x1D0D), (0x1D1B, 0x1D1B), (0x1F71, 0x1F71), (0x1F73, 0x1F73), (0x1F75, 0x1F75),
    (0x1F77, 0x1F77), (0x1F79, 0x1F79), (0x1F7B, 0x1F7B), (0x1F7D, 0x1F7D), (0x1FBE, 0x1FC0), (0x1FC9, 0x1FC9),
    (0x1FCB, 0x1FCB), (0x1FD3, 0x1FD3), (0x1FDB, 0x1FDB), (0x1FE3, 0x1FE3), (0x1FEB, 0x1FEB), (0x1FEE, 0x1FEE),
    (0x1FF9, 0x1FF9), (0x1FFB, 0x1FFB), (0x1FFD, 0x1FFD), (0x2010, 0x2011), (0x2015, 0x2015), (0x2024, 0x2025),
    (0x2027, 0x2027), (0x2126, 0x2126), (0x212A, 0x212B), (0x2160, 0x217F), (0x2183, 0x2186), (0x2206, 0x2206),
    (0x2215, 0x2215), (0x2218, 0x2219), (0x222B, 0x222B), (0x2236, 0x2236), (0x223C, 0x223C), (0x227A, 0x227B),
    (0x22C2, 0x22C3), (0x2373, 0x2373), (0x239B, 0x23AD), (0x25B6, 0x25B7), (0x25C0, 0x25C1), (0x25EF, 0x25EF),
    (0x2764, 0x2764), (0x2780, 0x2788), (0x2A00, 0x2A00), (0xFF5B, 0xFF5B), (0xFF5D, 0xFF5D),
];

/// Refait la liste `nettoyage::ENCRE` d'après les polices, sans `ECARTES` (à lancer quand une police change, en mode
/// optimisé) : `cargo test --release --manifest-path fenetre/Cargo.toml encre::refaire_la_liste -- --ignored
/// --nocapture`.
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
    let mut signes: Vec<u32> = communs
        .unwrap_or_default()
        .into_iter()
        .map(u32::from)
        .filter(|s| !ECARTES.iter().any(|&(debut, fin)| (debut..=fin).contains(s)))
        .collect();
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

/// Les tailles des textes de Vanguard dans la feuille « Voir la correction » (catégorie et commandes : 12 ; raison
/// et « pourquoi pas » : 13 ; action : 14 ; message : 15).
const TAILLES: [f32; 4] = [12.0, 13.0, 14.0, 15.0];

/// Les signes montrés tels quels (`Dessin::Encre`).
fn encre() -> Vec<char> {
    tous().filter(|&c| dessin(c) == Dessin::Encre).collect()
}

/// L'empreinte de l'image de chaque texte, dessiné signe par signe (`dessin::signe_par_signe`), par lots : l'atlas
/// est lu après chaque lot (ses glyphes déjà placés ne bougent pas).
fn empreintes(ctx: &egui::Context, police: &FontId, textes: &[String]) -> Vec<u64> {
    use std::hash::{Hash, Hasher};
    let mut sortie = Vec::with_capacity(textes.len());
    for lot in textes.chunks(4096) {
        let galeries: Vec<_> = lot
            .iter()
            .map(|t| ctx.fonts_mut(|f| f.layout_job(super::signe_par_signe(t, police.clone(), egui::Color32::WHITE))))
            .collect();
        let atlas = ctx.fonts_mut(|f| f.image());
        sortie.extend(galeries.iter().map(|g| {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            image(&atlas, g, egui::Vec2::ZERO).hash(&mut h);
            h.finish()
        }));
    }
    sortie
}

/// L'image exacte d'un texte dessiné signe par signe (pour confirmer deux empreintes égales).
fn image_exacte(ctx: &egui::Context, police: &FontId, t: &str) -> Image {
    let g = ctx.fonts_mut(|f| f.layout_job(super::signe_par_signe(t, police.clone(), egui::Color32::WHITE)));
    let atlas = ctx.fonts_mut(|f| f.image());
    image(&atlas, &g, egui::Vec2::ZERO)
}

/// Les suites comparées à chaque signe : toutes les paires de signes ASCII visibles, les paires d'un signe ASCII et
/// d'une lettre latine accentuée (dans les deux ordres : « ǅ » et « Dž »), et les triplets de ponctuation et de
/// symboles ASCII (une espace permise au milieu : en tête ou en bout, le nettoyage la retire et le dit).
fn suites() -> Vec<String> {
    let visibles: Vec<char> = ('!'..='~').collect();
    let ponctuation: Vec<char> = visibles.iter().copied().filter(char::is_ascii_punctuation).collect();
    let latines: Vec<char> = ('\u{c0}'..='\u{17f}')
        .filter(|&c| c.is_alphabetic() && dessin(c) == Dessin::Encre)
        .collect();
    let mut milieu = ponctuation.clone();
    milieu.push(' ');
    let mut s = Vec::new();
    for &a in &visibles {
        for &b in &visibles {
            s.push(format!("{a}{b}"));
        }
        for &b in &latines {
            s.push(format!("{a}{b}"));
            s.push(format!("{b}{a}"));
        }
    }
    for &a in &ponctuation {
        for &b in &milieu {
            for &c in &ponctuation {
                s.push(format!("{a}{b}{c}"));
            }
        }
    }
    s
}

/// Les empreintes d'une liste de textes dans chaque police, chaque police dans son propre fil (et son propre
/// contexte : un atlas par fil).
fn empreintes_par_police(polices: &[FontId], textes: &[String]) -> Vec<Vec<u64>> {
    std::thread::scope(|portee| {
        let fils: Vec<_> = polices
            .iter()
            .map(|police| portee.spawn(move || empreintes(&contexte(), police, textes)))
            .collect();
        fils.into_iter().map(|f| f.join().unwrap()).collect()
    })
}

/// Les polices où la feuille de correction montre les textes de Vanguard : Inter (catégorie, message, action,
/// « pourquoi pas », raison) et JetBrains Mono (règle, commandes, valeurs d'avant), aux tailles de `TAILLES`.
fn polices_de_la_feuille() -> Vec<FontId> {
    [FontFamily::Proportional, FontFamily::Monospace]
        .iter()
        .flat_map(|f| TAILLES.map(|t| FontId::new(t, f.clone())))
        .collect()
}

/// Vérification de Fable n° 3, A1 : dans la feuille de correction, aucun signe montré tel quel ne se dessine
/// exactement comme une suite de signes (`suites`), dans les polices et tailles où la feuille montre les textes de
/// Vanguard. Sans le dessin signe par signe (`dessin::signe_par_signe`), les ligatures d'Inter en feraient : « -> »
/// comme « → », « => » comme « ⇒ » ; avec lui, restaient les signes qui sont eux-mêmes une suite (« ‥ » et « .. »,
/// « ⅺ » et « xi »), retirés de la liste (`ECARTES`). La famille « m » (Inter Medium) n'y est pas : la feuille n'y
/// écrit que ses propres titres ; « … » y a le dessin de « ... » à 14 points (la fenêtre l'écrit elle-même en coupant
/// un texte, `nettoyage::couper`).
#[test]
fn aucune_suite_ne_dessine_un_signe() {
    let signes: Vec<String> = encre().into_iter().map(String::from).collect();
    let suites = suites();
    let polices = polices_de_la_feuille();
    let mut tous = signes.clone();
    tous.extend(suites.iter().cloned());
    let empreintes = empreintes_par_police(&polices, &tous);
    let ctx = contexte();
    let mut collisions = Vec::new();
    for (police, e) in polices.iter().zip(&empreintes) {
        let (de_signes, de_suites) = e.split_at(signes.len());
        let par_suite: std::collections::HashMap<u64, usize> = de_suites.iter().copied().zip(0..).collect();
        for (signe, h) in signes.iter().zip(de_signes) {
            if let Some(&j) = par_suite.get(h)
                && image_exacte(&ctx, police, signe) == image_exacte(&ctx, police, &suites[j])
            {
                collisions.push(format!("{police:?} : {signe:?} = {:?}", suites[j]));
            }
        }
    }
    assert!(
        collisions.is_empty(),
        "un signe montré se dessine comme une suite : {collisions:?}"
    );
}

/// L'alphabet d'une lettre ou d'un chiffre : latin (chiffres ASCII compris), grec ou cyrillique ; `None` ailleurs.
fn alphabet(c: char) -> Option<u8> {
    if !c.is_alphanumeric() {
        return None;
    }
    match u32::from(c) {
        0..=0x36F | 0x1D00..=0x1DBF | 0x1E00..=0x1EFF | 0x2C60..=0x2C7F | 0xA720..=0xA7FF => Some(0),
        0x370..=0x3FF | 0x1F00..=0x1FFF => Some(1),
        0x400..=0x52F => Some(2),
        _ => None,
    }
}

/// Vérification de Fable n° 3, A5 : deux signes montrés tels quels ne se dessinent jamais exactement pareil, dans
/// les trois familles et aux tailles de la feuille, sauf des lettres (ou chiffres) d'alphabets différents (« A »,
/// « Α », « А » ; « 3 » et « З ») : chacune est la lettre de son alphabet, c'est la limite dite dans `ENCRE`. Les
/// jumeaux gardés (`nettoyage::JUMEAUX_GARDES`, montrés « � » dans un aperçu) ne comptent pas. Une police changée
/// qui ferait un nouveau sosie fait échouer ce test (le signe va dans `ECARTES`).
#[test]
fn deux_signes_montres_ne_se_dessinent_pas_pareil() {
    let signes = encre();
    let textes: Vec<String> = signes.iter().copied().map(String::from).collect();
    let polices: Vec<FontId> = FAMILLES
        .iter()
        .flat_map(|f| TAILLES.map(|t| FontId::new(t, f())))
        .collect();
    let empreintes = empreintes_par_police(&polices, &textes);
    let ctx = contexte();
    let mut fautes = Vec::new();
    for (police, e) in polices.iter().zip(&empreintes) {
        let mut classes: BTreeMap<u64, Vec<char>> = BTreeMap::new();
        for (&c, &h) in signes.iter().zip(e) {
            if !crate::nettoyage::JUMEAUX_GARDES.contains(&c) {
                classes.entry(h).or_default().push(c);
            }
        }
        for classe in classes.values().filter(|c| c.len() > 1) {
            // Même empreinte : regroupés par image exacte.
            let mut images: Vec<(Image, Vec<char>)> = Vec::new();
            for &c in classe {
                let i = image_exacte(&ctx, police, &c.to_string());
                match images.iter_mut().find(|(j, _)| *j == i) {
                    Some((_, v)) => v.push(c),
                    None => images.push((i, vec![c])),
                }
            }
            for (_, jumeaux) in images.into_iter().filter(|(_, v)| v.len() > 1) {
                let alphabets: Option<HashSet<u8>> = jumeaux.iter().map(|&c| alphabet(c)).collect();
                if alphabets.is_none_or(|a| a.len() < jumeaux.len()) {
                    let noms: Vec<String> = jumeaux.iter().map(|&c| format!("U+{:04X} {c}", u32::from(c))).collect();
                    fautes.push(format!("{police:?} : {}", noms.join(", ")));
                }
            }
        }
    }
    assert!(
        fautes.is_empty(),
        "des signes montrés qui se dessinent pareil : {fautes:#?}"
    );
}

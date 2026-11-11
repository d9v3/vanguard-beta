//! Ce que les polices embarquées dessinent vraiment, mesuré par la mise en page d'egui sans fenêtre : chaque signe
//! que le nettoyage laisse passer (`nettoyage::dessin`) laisse de l'encre, avec une largeur, et n'est pas la case
//! vide d'un signe absent ; chaque marque gardée dessine exactement la lettre composée qu'elle forme avec sa lettre ;
//! deux signes (ou grappes) montrés ne se dessinent pas pareil (sauf des lettres d'alphabets différents), et aucun ne
//! se dessine comme une suite de signes dans la feuille de correction.

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
    (0x0189, 0x0189), (0x019E, 0x019E), (0x01C3, 0x01C3), (0x01DD, 0x01DD), (0x0237, 0x0237), (0x0249, 0x0249),
    (0x025F, 0x025F), (0x0261, 0x0261), (0x02B9, 0x02B9), (0x02BC, 0x02BC), (0x02C9, 0x02C9), (0x02D3, 0x02D3),
    (0x02EE, 0x02EE), (0x0375, 0x0375), (0x037E, 0x037E), (0x0387, 0x0387), (0x03FA, 0x03FA), (0x0472, 0x0472),
    (0x0478, 0x0479), (0x048C, 0x048C), (0x04C0, 0x04C0), (0x04CF, 0x04CF), (0x1D0D, 0x1D0D), (0x1D1B, 0x1D1B),
    (0x1F71, 0x1F71), (0x1F73, 0x1F73), (0x1F75, 0x1F75), (0x1F77, 0x1F77), (0x1F79, 0x1F79), (0x1F7B, 0x1F7B),
    (0x1F7D, 0x1F7D), (0x1FBE, 0x1FC0), (0x1FC9, 0x1FC9), (0x1FCB, 0x1FCB), (0x1FD3, 0x1FD3), (0x1FDB, 0x1FDB),
    (0x1FE3, 0x1FE3), (0x1FEB, 0x1FEB), (0x1FEE, 0x1FEE), (0x1FF9, 0x1FF9), (0x1FFB, 0x1FFB), (0x1FFD, 0x1FFD),
    (0x2010, 0x2011), (0x2015, 0x2015), (0x2024, 0x2025), (0x2027, 0x2027), (0x2126, 0x2126), (0x212A, 0x212B),
    (0x2160, 0x217F), (0x2183, 0x2186), (0x2206, 0x2206), (0x2215, 0x2215), (0x2218, 0x2219), (0x222B, 0x222B),
    (0x2236, 0x2236), (0x223C, 0x223C), (0x227A, 0x227B), (0x22C2, 0x22C3), (0x2373, 0x2373), (0x239B, 0x23AD),
    (0x25B6, 0x25B7), (0x25C0, 0x25C1), (0x25EF, 0x25EF), (0x2764, 0x2764), (0x2780, 0x2788), (0x2A00, 0x2A00),
    (0xFF5B, 0xFF5B), (0xFF5D, 0xFF5D),
];

/// Aucun signe écarté ne se montre tel quel : un sosie remis par mégarde dans `nettoyage::ENCRE` redeviendrait un
/// jumeau sans retouche. `refaire_la_liste` le garantit aussi, mais il ne tourne qu'à la main ; celui-ci tourne
/// toujours. (Pour « ȷ », « ɉ » et « ɟ » sous une marque, `nettoyage::composee` ferme déjà la porte : aucune lettre
/// composée ne les a pour base.)
#[test]
fn aucun_signe_ecarte_ne_se_montre() {
    let montres: Vec<String> = ECARTES
        .iter()
        .flat_map(|&(debut, fin)| debut..=fin)
        .filter_map(char::from_u32)
        .filter(|&c| dessin(c) == Dessin::Encre)
        .map(|c| format!("U+{:04X}", u32::from(c)))
        .collect();
    assert!(montres.is_empty(), "signes écartés montrés tels quels : {montres:?}");
}

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

/// La mise en page d'un texte dessiné signe par signe (`dessin::signe_par_signe`), comme dans la feuille.
fn mise_en_page(ctx: &egui::Context, police: &FontId, t: &str) -> std::sync::Arc<egui::Galley> {
    ctx.fonts_mut(|f| f.layout_job(super::signe_par_signe(t, police.clone(), egui::Color32::WHITE)))
}

/// L'empreinte de l'image de chaque texte, dessiné signe par signe, par lots : l'atlas est lu après chaque lot (ses
/// glyphes déjà placés ne bougent pas).
fn empreintes(ctx: &egui::Context, police: &FontId, textes: &[String]) -> Vec<u64> {
    use std::hash::{Hash, Hasher};
    let mut sortie = Vec::with_capacity(textes.len());
    for lot in textes.chunks(4096) {
        let galeries: Vec<_> = lot.iter().map(|t| mise_en_page(ctx, police, t)).collect();
        let atlas = ctx.fonts_mut(|f| f.image());
        sortie.extend(galeries.iter().map(|g| {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            image(&atlas, g, egui::Vec2::ZERO).hash(&mut h);
            h.finish()
        }));
    }
    sortie
}

/// Pour chaque paire de textes, s'ils se dessinent exactement pareil (signe par signe), par lots.
fn pareilles(ctx: &egui::Context, police: &FontId, paires: &[(String, String)]) -> Vec<bool> {
    let mut sortie = Vec::with_capacity(paires.len());
    for lot in paires.chunks(2048) {
        let galeries: Vec<_> = lot
            .iter()
            .map(|(a, b)| (mise_en_page(ctx, police, a), mise_en_page(ctx, police, b)))
            .collect();
        let atlas = ctx.fonts_mut(|f| f.image());
        sortie.extend(
            galeries
                .iter()
                .map(|(a, b)| image(&atlas, a, egui::Vec2::ZERO) == image(&atlas, b, egui::Vec2::ZERO)),
        );
    }
    sortie
}

/// L'image exacte d'un texte dessiné signe par signe (pour confirmer deux empreintes égales).
fn image_exacte(ctx: &egui::Context, police: &FontId, t: &str) -> Image {
    let g = mise_en_page(ctx, police, t);
    let atlas = ctx.fonts_mut(|f| f.image());
    image(&atlas, &g, egui::Vec2::ZERO)
}

/// Les suites comparées à chaque signe : toutes les paires de signes ASCII visibles, les paires d'un signe ASCII et
/// d'une lettre latine accentuée (dans les deux ordres : « ǅ » et « Dž »), les triplets de ponctuation et de
/// symboles ASCII (une espace permise au milieu : en tête ou en bout, le nettoyage la retire et le dit), et chaque
/// signe montré non ASCII doublé (vérification de Fable n° 4, N4 : « –– » se dessinait comme « — » dans Inter à 12
/// et 14 points ; « – » est devenu un jumeau gardé, `nettoyage::JUMEAUX_GARDES`, montré « � » dans un aperçu, et ses
/// doubles ne sont donc plus comparés).
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
    s.extend(
        encre()
            .into_iter()
            .filter(|c| !c.is_ascii() && !crate::nettoyage::JUMEAUX_GARDES.contains(c))
            .map(|c| format!("{c}{c}")),
    );
    s
}

/// Un travail fait pour chaque police, chaque police dans son propre fil (et son propre contexte : un atlas par fil).
fn par_police<T: Send>(polices: &[FontId], travail: impl Fn(&egui::Context, &FontId) -> T + Sync) -> Vec<T> {
    let travail = &travail;
    std::thread::scope(|portee| {
        let fils: Vec<_> = polices
            .iter()
            .map(|police| portee.spawn(move || travail(&contexte(), police)))
            .collect();
        fils.into_iter().map(|f| f.join().unwrap()).collect()
    })
}

/// Les empreintes d'une liste de textes dans chaque police (`par_police`).
fn empreintes_par_police(polices: &[FontId], textes: &[String]) -> Vec<Vec<u64>> {
    par_police(polices, |ctx, police| empreintes(ctx, police, textes))
}

/// Les polices des trois familles de la fenêtre, aux tailles de la feuille.
fn polices_des_trois_familles() -> Vec<FontId> {
    FAMILLES
        .iter()
        .flat_map(|f| TAILLES.map(|t| FontId::new(t, f())))
        .collect()
}

/// Les grappes que le nettoyage garde telles quelles (`nettoyage::ligne`) : chaque signe montré suivi d'une marque
/// permise ; puis, après chaque grappe d'une marque qui forme une lettre composée, d'une seconde marque. Chacune avec
/// la lettre composée qu'elle forme (`nettoyage::composee`), ou `None` (le nettoyage l'aurait gardée sans elle).
fn grappes_gardees() -> Vec<(String, Option<char>)> {
    use crate::nettoyage::{composee, ligne};
    let marques: Vec<char> = tous().filter(|&c| dessin(c) == Dessin::Marque).collect();
    let mut grappes = Vec::new();
    for b in encre() {
        for &m in &marques {
            let t = format!("{b}{m}");
            if ligne(&t) != t {
                continue;
            }
            let faite = composee(b, m);
            if let Some(c) = faite {
                for &n in &marques {
                    let t2 = format!("{t}{n}");
                    if ligne(&t2) == t2 {
                        grappes.push((t2, composee(c, n)));
                    }
                }
            }
            grappes.push((t, faite));
        }
    }
    // Une grappe d'une marque est une paire de `COMPOSEES` ; une de deux marques prolonge l'une d'elles par une autre
    // paire : au plus deux fois leur nombre. Au-delà, le nettoyage garde des marques hors de la table, et les essais
    // qui dessinent chaque grappe (des centaines de milliers) s'emballeraient au lieu d'échouer.
    let paires: usize = crate::nettoyage::COMPOSEES
        .iter()
        .map(|(_, s)| s.chars().count() / 2)
        .sum();
    assert!(
        grappes.len() <= 2 * paires,
        "{} grappes gardées pour {paires} lettres composées, dont : {:?}",
        grappes.len(),
        &grappes[..grappes.len().min(20)]
    );
    grappes
}

/// Ce qu'un nom piégé écrirait à la place d'une marque pour imiter une lettre composée : les signes espacés qui
/// ressemblent aux marques permises (accents, tréma, rond, caron, apostrophes et virgules, point, cédille, ogonek).
const ESPACES_DES_MARQUES: &str = "`ˋ´ˊ΄^ˆ~˜¯ˉ‾˘¨ˀ˚°ºˇ˵\"'’‘.,‚¸˛";

/// Vérification de Fable n° 4, N2 : chaque grappe que le nettoyage garde (une marque ou deux, après chaque signe
/// montré) forme une lettre composée, et se dessine exactement comme elle, en fin de texte et suivie d'un signe,
/// dans les trois familles et aux tailles de la feuille. Et cette lettre composée ne se dessine ni comme la lettre
/// d'avant seule, ni comme la lettre d'avant suivie d'un signe espacé (`ESPACES_DES_MARQUES`) : Inter dessinait
/// « 1 » et l'accent grave combinant exactement comme « 1` », la marque à côté, faute d'ancre. Remplace « la marque
/// se voit » par « la marque se distingue de ce qu'un nom piégé écrirait à la place ».
#[test]
fn chaque_marque_gardee_dessine_sa_lettre_composee() {
    let grappes = grappes_gardees();
    let sans: Vec<&str> = grappes
        .iter()
        .filter(|(_, c)| c.is_none())
        .map(|(t, _)| t.as_str())
        .collect();
    assert!(
        sans.is_empty(),
        "{} grappes gardées sans lettre composée, dont : {:?}",
        sans.len(),
        &sans[..sans.len().min(20)]
    );
    assert!(grappes.len() > 400, "{}", grappes.len());
    let espaces: Vec<char> = ESPACES_DES_MARQUES
        .chars()
        .filter(|&c| dessin(c) == Dessin::Encre)
        .collect();
    let mut egales: Vec<(String, String)> = Vec::new();
    let mut distinctes: Vec<(String, String)> = Vec::new();
    for (t, faite) in &grappes {
        let faite = faite.unwrap().to_string();
        let signes: Vec<char> = t.chars().collect();
        let marques = &signes[1..signes.len() - 1];
        let avant = marques
            .iter()
            .fold(signes[0], |l, &m| crate::nettoyage::composee(l, m).unwrap());
        egales.push((t.clone(), faite.clone()));
        egales.push((format!("{t}x"), format!("{faite}x")));
        distinctes.push((faite.clone(), avant.to_string()));
        distinctes.extend(espaces.iter().map(|e| (faite.clone(), format!("{avant}{e}"))));
    }
    let fautes: Vec<String> = par_police(&polices_des_trois_familles(), |ctx, police| {
        let mut fautes = Vec::new();
        for ((a, b), pareil) in egales.iter().zip(pareilles(ctx, police, &egales)) {
            if !pareil {
                fautes.push(format!("{police:?} : {a:?} ne se dessine pas comme {b:?}"));
            }
        }
        for ((a, b), pareil) in distinctes.iter().zip(pareilles(ctx, police, &distinctes)) {
            if pareil {
                fautes.push(format!("{police:?} : {a:?} se dessine comme {b:?}"));
            }
        }
        fautes
    })
    .concat();
    assert!(
        fautes.is_empty(),
        "{} fautes, dont : {:#?}",
        fautes.len(),
        &fautes[..fautes.len().min(30)]
    );
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
///
/// Vérification de Fable n° 4, N3 : les grappes gardées (signe et marque, `grappes_gardees`) en sont aussi ; chacune
/// ne peut se dessiner que comme sa propre lettre composée. « j » et une marque du dessus se dessinaient comme « ȷ »
/// (U+0237, sans point) et la même marque : ni l'une ni l'autre n'est plus gardée, et U+0237, U+0249 et U+025F sont
/// écartés.
#[test]
fn deux_signes_montres_ne_se_dessinent_pas_pareil() {
    let mut textes: Vec<String> = encre()
        .into_iter()
        .filter(|c| !crate::nettoyage::JUMEAUX_GARDES.contains(c))
        .map(String::from)
        .collect();
    // Ce que chaque texte doit dessiner : le signe lui-même, ou la lettre composée de la grappe (une grappe sans
    // lettre composée n'a que son propre dessin).
    let mut dessins: Vec<String> = textes.clone();
    for (t, faite) in grappes_gardees() {
        dessins.push(faite.map_or_else(|| t.clone(), String::from));
        textes.push(t);
    }
    let polices = polices_des_trois_familles();
    let empreintes = empreintes_par_police(&polices, &textes);
    let ctx = contexte();
    let mut fautes = Vec::new();
    for (police, e) in polices.iter().zip(&empreintes) {
        let mut classes: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        for (i, &h) in e.iter().enumerate() {
            classes.entry(h).or_default().push(i);
        }
        // Même empreinte et deux dessins attendus différents au moins : regroupés par image exacte.
        for classe in classes.values() {
            let attendus: HashSet<&str> = classe.iter().map(|&i| dessins[i].as_str()).collect();
            if attendus.len() < 2 {
                continue;
            }
            let mut images: Vec<(Image, Vec<usize>)> = Vec::new();
            for &i in classe {
                let image = image_exacte(&ctx, police, &textes[i]);
                match images.iter_mut().find(|(j, _)| *j == image) {
                    Some((_, v)) => v.push(i),
                    None => images.push((image, vec![i])),
                }
            }
            for (_, jumeaux) in images {
                let attendus: HashSet<&str> = jumeaux.iter().map(|&i| dessins[i].as_str()).collect();
                if attendus.len() < 2 {
                    continue;
                }
                let alphabets: Option<HashSet<u8>> = attendus
                    .iter()
                    .map(|d| {
                        let mut signes = d.chars();
                        match (signes.next(), signes.next()) {
                            (Some(c), None) => alphabet(c),
                            _ => None,
                        }
                    })
                    .collect();
                if alphabets.is_none_or(|a| a.len() < attendus.len()) {
                    let noms: Vec<String> = jumeaux
                        .iter()
                        .map(|&i| {
                            let t = &textes[i];
                            let points: Vec<String> = t.chars().map(|c| format!("U+{:04X}", u32::from(c))).collect();
                            format!("{} {t}", points.join(" "))
                        })
                        .collect();
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

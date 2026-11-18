//! Essais de la lecture des sources (le vocabulaire de la porte MCP), sur des sources inventées.

use super::*;

/// Une source inventée : « TR( » et « TRF( » y deviennent les appels des macros de texte (écrits ainsi, ils n'en sont
/// pas pour outils/textes.py ni pour la lecture de ce fichier-ci).
fn source(texte: &str) -> String {
    texte
        .replace("TRF(", concat!("t", "rf!("))
        .replace("TR(", concat!("t", "r!("))
}

fn lecture(fichiers: &[(&str, &str)]) -> Result<BTreeSet<String>, Illisible> {
    let sources: Vec<(PathBuf, String)> = fichiers.iter().map(|(c, t)| (PathBuf::from(c), source(t))).collect();
    vocabulaire(&sources)
}

fn mots(fichiers: &[(&str, &str)]) -> BTreeSet<String> {
    match lecture(fichiers) {
        Ok(mots) => mots,
        Err(Illisible(e)) => panic!("{e}"),
    }
}

/// Un programme d'un seul fichier, src/main.rs.
fn un(texte: &str) -> BTreeSet<String> {
    mots(&[("src/main.rs", texte)])
}

/// La lecture doit arrêter la compilation, avec ce mot dans son message.
fn refuse(fichiers: &[(&str, &str)], attendu: &str) {
    match lecture(fichiers) {
        Ok(mots) => panic!("lu sans erreur ({attendu} attendu) : {mots:?}"),
        Err(Illisible(e)) => assert!(e.contains(attendu), "{e}"),
    }
}

fn attendus(liste: &[&str]) -> BTreeSet<String> {
    liste.iter().map(|m| (*m).to_string()).collect()
}

#[test]
fn le_code_d_apres_un_module_d_essais_reste_lu() {
    // LB-COMPILATION-1 : « mod tests; » ne retire que sa ligne, et le code qui suit « mod tests { … } » est lu.
    let texte = "#[cfg(test)]\nmod tests;\nfn a() { TR(\"minuteur\", \"timer\"); }\n\
                 #[cfg(test)]\nmod essais {\n    fn b() { TR(\"alice\", \"alice\"); }\n}\n\
                 fn c() { TR(\"unsent\", \"unsent\"); }\n";
    assert_eq!(un(texte), attendus(&["minuteur", "timer", "unsent"]));
}

#[test]
fn chaque_forme_d_essai_est_retiree() {
    // LB-COMPILATION-2 : tout élément sous cfg(test) ou cfg(all(…, test, …)), quels que soient son nom et son
    // retrait ; cfg(any(…, test)) et cfg(not(test)) sont du programme.
    let essais = [
        "#[cfg(test)]\npub(crate) mod corpus {\n    fn a() { TR(\"salon\", \"x\"); }\n}\n",
        "impl A {\n    #[cfg(test)]\n    fn a() { TR(\"salon\", \"x\"); }\n}\n",
        "#[cfg(all(test, unix))]\nfn a() { TR(\"salon\", \"x\"); }\n",
        "#[cfg(all(unix, test))]\n/// doc\n#[allow(dead_code)]\nfn a() { TR(\"salon\", \"x\"); }\n",
        "#[cfg( all( target_os = \"linux\", test ) )]\nmod m { fn a() { TR(\"salon\", \"x\"); } }\n",
        "#[cfg(all(test, any(unix, windows)))]\nfn a() { TR(\"salon\", \"x\"); }\n",
        "#[cfg(test)] // essai\n/* bloc /* imbriqué */ */ static A: &str = TR(\"salon\", \"x\");\n",
        "fn f() {\n    #[cfg(test)]\n    let x = if a { 1 } else { TR(\"salon\", \"x\") };\n}\n",
        "#[cfg(test)]\nconst A: S = S { a: 1, b: TR(\"salon\", \"x\") };\n",
        "#[cfg(test)]\nconst fn a() -> u8 { 1 }\nfn b() { TR(\"programme\", \"program\"); }\n",
        // R2-COMPILATION-1 : #[test] et #[bench] seuls (sans cfg(test) autour), un proptest! hors des essais.
        "#[test]\nfn f() { assert_eq!(TR(\"alice\", \"salon\"), \"\"); }\n",
        "#[bench]\nfn f(b: &mut B) { b.iter(|| TR(\"salon\", \"x\")); }\n",
        "#[tokio::test]\nasync fn f() { TR(\"salon\", \"x\"); }\n",
        "proptest! {\n    #[test]\n    fn f(x in 0u8..) { TR(\"salon\", \"x\"); }\n}\n",
        // R2-COMPILATION-4 : écritures rares de cfg(test).
        "#[cfg(all(unix, all(test)))]\nfn a() { TR(\"salon\", \"x\"); }\n",
        "#[cfg(test,)]\nfn a() { TR(\"salon\", \"x\"); }\n",
        "#[cfg(/* x */ test)]\nfn a() { TR(\"salon\", \"x\"); }\n",
        "#[cfg_attr(all(), cfg(test))]\nfn a() { TR(\"salon\", \"x\"); }\n",
        "#[cfg_attr(unix, test)]\nfn a() { TR(\"salon\", \"x\"); }\n",
        "#[cfg(kani)]\nfn a() { TR(\"salon\", \"x\"); }\n",
        "#[cfg(not(any(unix, not(test))))]\nfn a() { TR(\"salon\", \"x\"); }\n",
        // R2-COMPILATION-2 : la fin de l'élément est celle de l'arbre, pas la première accolade.
        "#[cfg(test)]\nfn f() -> T<{ N }> { TR(\"salon\", \"x\") }\nfn b() { TR(\"programme\", \"program\"); }\n",
    ];
    for texte in essais {
        let lu = un(texte);
        assert!(!lu.contains("salon"), "{texte}");
        assert!(
            lu.is_empty() || lu == attendus(&["programme", "program"]),
            "{texte} : {lu:?}"
        );
    }
    let programme = [
        "#[cfg(any(unix, test))]\nfn a() { TR(\"salon\", \"x\"); }\n",
        "#[cfg(all(unix, not(test)))]\nfn a() { TR(\"salon\", \"x\"); }\n",
        "#[cfg_attr(test, allow(dead_code))]\nfn a() { TR(\"salon\", \"x\"); }\n",
        "#[cfg(all(unix, tests))]\nfn a() { TR(\"salon\", \"x\"); }\n",
        "#[cfg_attr(test, test)]\nfn a() { TR(\"salon\", \"x\"); }\n",
        "#[cfg(not(all(unix, test)))]\nfn a() { TR(\"salon\", \"x\"); }\n",
    ];
    for texte in programme {
        assert!(un(texte).contains("salon"), "{texte}");
    }
}

#[test]
fn la_fin_d_un_essai_ne_se_trompe_pas_de_paire() {
    // Accolades, crochets et parenthèses dans les chaînes, caractères, commentaires et durées de vie ne comptent
    // pas ; un champ ou un bras sous cfg(test) s'arrête avant la fermante du bloc qui l'entoure.
    let texte = "#[cfg(test)]\nfn a<'b>(x: &'b str) -> char {\n    let _ = \"}}}\";\n    let _ = r#\"}\"\"#;\n    \
                 let _ = b\"}\";\n    // }\n    /* } */\n    let _ = '}';\n    TR(\"dedans\", \"inside\");\n    let _ = '\\'';\n    '{'\n}\n\
                 fn b() { TR(\"garde\", \"kept\"); }\n\
                 struct S {\n    #[cfg(test)]\n    a: u8\n}\nfn c() { TR(\"aussi\", \"also\"); }\n";
    assert_eq!(un(texte), attendus(&["garde", "kept", "aussi", "also"]));
}

#[test]
fn un_bras_un_champ_ou_un_element_d_essai_finit_a_sa_place() {
    // R2-COMPILATION-2 et 5a : le bras, l'instruction, le champ ou l'élément de tableau sous cfg(test) est retiré
    // seul ; ce qui le suit dans le même bloc reste lu.
    let textes = [
        "fn f(e: E) -> &'static str {\n    match e {\n        #[cfg(test)]\n        E::Essai { texte } => TR(\"salon\", \"x\"),\n        \
         E::A(t) => t,\n        E::B => TR(\"vrai\", \"real\"),\n    }\n}\n",
        "fn f() {\n    #[cfg(test)]\n    S { a: 1 }.dire(TR(\"salon\", \"x\"));\n    TR(\"vrai\", \"real\");\n}\n",
        "const A: &[&str] = &[\n    #[cfg(test)]\n    \"x\",\n    TR(\"vrai\", \"real\"),\n];\n",
        "fn f() -> S {\n    S {\n        #[cfg(test)]\n        a: TR(\"salon\", \"x\"),\n        b: TR(\"vrai\", \"real\"),\n    }\n}\n",
        "fn f() {\n    #[cfg(test)]\n    let x = TR(\"salon\", \"x\");\n    TR(\"vrai\", \"real\");\n}\n",
    ];
    for texte in textes {
        assert_eq!(un(texte), attendus(&["vrai", "real"]), "{texte}");
    }
}

#[test]
fn les_commentaires_ne_sont_pas_du_code() {
    // R2-COMPILATION-4 et 7 : un appel de texte dans un commentaire n'est pas lu ; une parenthèse ou un guillemet
    // dans un commentaire ou un caractère ne fait pas lire la suite du fichier.
    let texte = "//! TR(\"alice\", \"salon\")\n/// Exemple : TR(\"alice\", \"salon\")\nfn f(x: u8) {\n    \
                 // TR(\"alice\", \"salon\")\n    /* TR(\"alice\", \"salon\") */\n    \
                 TRF(\"vrai {}\", \"real {}\", x, // (ancien\n    );\n    let secret = \"motdecode\";\n    \
                 let c = TRF(\"un {}\", \"one {}\", '\\\"');\n    let s = \"autre\";\n}\n";
    assert_eq!(un(texte), attendus(&["vrai", "real", "un", "one"]));
}

#[test]
fn les_chemins_d_essais_sont_suivis_comme_rustc() {
    // R2-COMPILATION-3 : #[path] écrit avant #[cfg(test)], et les modules déclarés par un fichier d'essais atteint
    // par #[path] (cherchés à côté de lui), sont des essais.
    let essai = "fn a() { TR(\"alice\", \"salon\"); }\n";
    let lu = mots(&[
        ("src/main.rs", "mod a;\n"),
        (
            "src/a.rs",
            "#[path = \"jeu.rs\"]\n#[cfg(test)]\nmod essais;\n#[cfg(test)]\n#[path = \"x/outil.rs\"]\nmod outil;\n\
             fn f() { TR(\"vrai\", \"real\"); }\n",
        ),
        ("src/jeu.rs", essai),
        ("src/x/outil.rs", "mod aide;\n"),
        ("src/x/aide.rs", essai),
    ]);
    assert_eq!(lu, attendus(&["vrai", "real"]));
    // Un #[path] du programme est suivi, dans un module en ligne relatif au dossier de ce module.
    let lu = mots(&[
        ("src/main.rs", "mod a;\n"),
        (
            "src/a.rs",
            "mod b {\n    #[path = \"autre.rs\"]\n    mod c;\n}\n#[path = \"z/mod.rs\"]\nmod d;\n",
        ),
        ("src/a/b/autre.rs", "fn a() { TR(\"vrai\", \"real\"); }\n"),
        ("src/z/mod.rs", "mod e;\n"),
        ("src/z/e.rs", "fn a() { TR(\"aussi\", \"also\"); }\n"),
    ]);
    assert_eq!(lu, attendus(&["vrai", "real", "aussi", "also"]));
}

#[test]
fn les_identifiants_bruts_sont_lus_comme_rustc() {
    // 3e re-contrôle : rustc lit `r#test`, `r#cfg` ou `r#println!` comme `test`, `cfg` ou `println!` (vérifié
    // avec rustc 1.99) ; la lecture aussi, sinon un mot d'essai entrait dans la liste blanche.
    let essais = [
        "#[cfg(r#test)]\nfn a() { TR(\"salon\", \"x\"); }\n",
        "#[r#test]\nfn a() { TR(\"salon\", \"x\"); }\n",
        "#[r#cfg(test)]\nfn a() { TR(\"salon\", \"x\"); }\n",
        "#[cfg(all(unix, r#test))]\nfn a() { TR(\"salon\", \"x\"); }\n",
        "#[r#cfg_attr(unix, r#test)]\nfn a() { TR(\"salon\", \"x\"); }\n",
        "r#proptest! {\n    fn f(x in 0u8..) { TR(\"salon\", \"x\"); }\n}\n",
    ];
    for texte in essais {
        assert!(!un(texte).contains("salon"), "{texte}");
    }
    assert!(un("#[cfg(not(r#test))]\nfn a() { TR(\"salon\", \"x\"); }\n").contains("salon"));
}

#[test]
fn un_path_sur_un_module_en_ligne_part_du_dossier_du_fichier() {
    // 3e re-contrôle : dans src/a.rs (pas un mod.rs), `#[path = "foo"] mod en_ligne { mod b; }` compile src/foo/b.rs
    // pour rustc 1.99, pas src/a/foo/b.rs. Avant, le premier cas arrêtait la compilation d'un code juste, et le
    // second lisait comme programme le fichier d'essais src/a/foo/b.rs.
    let a = "#[path = \"foo\"]\npub mod en_ligne {\n    pub mod b;\n}\n";
    let vrai = "fn a() { TR(\"vrai\", \"real\"); }\n";
    let lu = mots(&[("src/main.rs", "mod a;\n"), ("src/a.rs", a), ("src/foo/b.rs", vrai)]);
    assert_eq!(lu, attendus(&["vrai", "real"]));
    let avec_essai = format!("{a}#[cfg(test)]\n#[path = \"a/foo/b.rs\"]\nmod z;\n");
    let lu = mots(&[
        ("src/main.rs", "mod a;\n"),
        ("src/a.rs", &avec_essai),
        ("src/foo/b.rs", vrai),
        ("src/a/foo/b.rs", "fn a() { TR(\"alice\", \"salon\"); }\n"),
    ]);
    assert_eq!(lu, attendus(&["vrai", "real"]));
}

#[test]
fn un_essai_en_ligne_ne_retire_que_son_module() {
    // R2-COMPILATION-5b : « mod sous { #![cfg(test)] … } » retire ce module seul, pas le fichier ni son dossier.
    let lu = mots(&[
        ("src/main.rs", "mod a;\n"),
        (
            "src/a/mod.rs",
            "mod sous {\n    #![cfg(test)]\n    fn f() { TR(\"alice\", \"salon\"); }\n}\n\
             fn g() { TR(\"vrai\", \"real\"); }\nmod voisin;\n",
        ),
        ("src/a/voisin.rs", "fn a() { TR(\"aussi\", \"also\"); }\n"),
    ]);
    assert_eq!(lu, attendus(&["vrai", "real", "aussi", "also"]));
}

#[test]
fn ce_que_la_lecture_ne_sait_pas_juger_arrete_la_compilation() {
    // Un fichier illisible, une forme que syn garde sans la comprendre, un cfg illisible, un attribut d'essai dans
    // des jetons de macro, un module du programme absent, un fichier qu'aucun module ne déclare.
    refuse(&[("src/main.rs", "fn (\n")], "illisible pour syn");
    refuse(&[("src/main.rs", "macro m() {}\n")], "Verbatim");
    refuse(&[("src/main.rs", "#[cfg(unix windows)]\nfn a() {}\n")], "cfg");
    refuse(
        &[("src/main.rs", "#[cfg(test, unix)]\nfn a() {}\n")],
        "exactement une condition",
    );
    refuse(
        &[("src/main.rs", "m! { #[cfg(test)] => TR(\"alice\", \"salon\") }\n")],
        "attribut d'essai",
    );
    refuse(&[("src/main.rs", "mod perdu;\n")], "perdu");
    refuse(
        &[("src/main.rs", "fn a() {}\n"), ("src/orphelin.rs", "fn b() {}\n")],
        "orphelin",
    );
    refuse(&[("src/a.rs", "fn b() {}\n")], "src/main.rs");
    // Hors de src/ (le modèle partagé avec fenetre/) : pas lu, sans erreur ; un module d'essais absent non plus.
    let lu = mots(&[(
        "src/main.rs",
        "#[path = \"../fenetre/src/couleurs.rs\"]\nmod modele;\n#[cfg(test)]\nmod tests;\n\
         fn a() { TR(\"vrai\", \"real\"); }\n",
    )]);
    assert_eq!(lu, attendus(&["vrai", "real"]));
}

#[test]
fn les_fichiers_des_modules_d_essais_sont_ecartes() {
    let essai = "fn a() { TR(\"alice\", \"bob\"); }\n";
    let vrai = "fn a() { TR(\"alerte\", \"alert\"); }\n";
    let lu = mots(&[
        (
            "src/main.rs",
            "#[cfg(test)]\nmod essais;\nmod vrai;\nmod b;\nmod tout;\n",
        ),
        ("src/essais.rs", "mod sous;\n"),
        ("src/essais/sous.rs", essai),
        (
            "src/vrai.rs",
            "#[cfg(all(test, unix))]\npub(crate) mod corpus;\n#[cfg(test)]\nmod jeu {\n    mod x;\n}\nmod corpus_bis;\n",
        ),
        ("src/vrai/corpus.rs", essai),
        ("src/vrai/jeu/x.rs", essai),
        ("src/vrai/corpus_bis.rs", vrai),
        (
            "src/b/mod.rs",
            "#[cfg(test)]\n#[path = \"../autre/fixe.rs\"]\nmod fixe;\n",
        ),
        ("src/autre/fixe.rs", essai),
        (
            "src/tout.rs",
            "#![cfg(test)]\nmod sous;\nfn a() { TR(\"alice\", \"bob\"); }\n",
        ),
        ("src/tout/sous.rs", essai),
    ]);
    assert_eq!(lu, attendus(&["alerte", "alert"]));
}

#[test]
fn une_fin_de_ligne_echappee_colle_les_deux_bouts() {
    // LB-COMPILATION-5 : comme Rust, « \ » en fin de ligne ne laisse rien, ni les blancs de la ligne suivante.
    // Un caractère de contrôle (« \x1b » d'une couleur de terminal) sépare deux mots.
    let texte = "fn a() { TR(\"le pare-\\\n        feu est coupé\\n\\\n        ici\\x1b[K\", \"x\"); }\n";
    assert_eq!(
        un(texte),
        attendus(&["coupé", "est", "ici", "le", "pare-feu", "x", "[K"])
    );
}

/// 4e re-contrôle SOURCES-1 : `cfg_select!` (ou `cfg_match!`) choisit ses bras par `cfg` ; la lecture ne les juge pas
/// et arrête la compilation, en élément, en expression, renommée par un `use` ou dans des jetons de macro.
#[test]
fn r4_sources_1_cfg_select_arrete_la_compilation() {
    for texte in [
        "cfg_select! { test => { fn a() { TR(\"alice\", \"salon\"); } } _ => { fn a() { TR(\"vrai\", \"real\"); } } }\n",
        "fn a() { let _ = cfg_select! { test => { TR(\"alice\", \"salon\") } _ => { TR(\"vrai\", \"real\") } }; }\n",
        "cfg_select! { not(test) => { fn a() { TR(\"vrai\", \"real\"); } } _ => { fn a() { TR(\"alice\", \"salon\"); } } }\n",
        "core::cfg_match! { test => { fn a() { TR(\"alice\", \"salon\"); } } _ => {} }\n",
        "r#cfg_select! { test => { fn a() { TR(\"alice\", \"salon\"); } } _ => {} }\n",
        "use core::cfg_select as choix;\nchoix! { test => { fn a() { TR(\"alice\", \"salon\"); } } _ => {} }\n",
        "m! { => cfg_select! { test => { TR(\"alice\", \"salon\") } } }\n",
    ] {
        match lecture(&[("src/main.rs", texte)]) {
            Ok(mots) => panic!("lu sans erreur : {mots:?} ({texte})"),
            Err(Illisible(e)) => assert!(e.contains("forme non jugée") && e.contains("cfg_"), "{e} ({texte})"),
        }
    }
}

/// 4e re-contrôle SOURCES-2 : un `path` posé par `cfg_attr` sur un module (à fichier ou en ligne) arrête la
/// compilation, à toute profondeur.
#[test]
fn r4_sources_2_un_path_pose_par_cfg_attr_arrete_la_compilation() {
    let horloge = ("src/horloge.rs", "fn g() { TR(\"alice\", \"salon\"); }\n");
    refuse(
        &[
            (
                "src/main.rs",
                "#[cfg_attr(not(test), path = \"../commun/horloge.rs\")]\nmod horloge;\n",
            ),
            horloge,
        ],
        "path posé par cfg_attr",
    );
    refuse(
        &[
            (
                "src/main.rs",
                "#[cfg_attr(not(test), path = \"vrai.rs\")]\nmod horloge;\n#[cfg(test)]\nmod vrai;\n",
            ),
            horloge,
            ("src/vrai.rs", "fn v() { TR(\"vrai\", \"real\"); }\n"),
        ],
        "path posé par cfg_attr",
    );
    refuse(
        &[
            (
                "src/main.rs",
                "#[cfg_attr(unix, cfg_attr(all(), path = \"horloge.rs\"))]\nmod h;\n",
            ),
            horloge,
        ],
        "path posé par cfg_attr",
    );
    refuse(
        &[
            (
                "src/main.rs",
                "#[cfg_attr(test, path = \"ailleurs\")]\nmod en_ligne {\n    mod horloge;\n}\n",
            ),
            horloge,
        ],
        "path posé par cfg_attr",
    );
}

/// 4e re-contrôle SOURCES-3 : un module à fichier déclaré dans un bloc (corps de fonction, `const _`) arrête la
/// compilation : rustc le cherche depuis un dossier que la lecture ne suit pas.
#[test]
fn r4_sources_3_un_module_a_fichier_dans_un_bloc_arrete_la_compilation() {
    let p = ("src/x/p.rs", "pub fn g() { TR(\"vrai\", \"real\"); }\n");
    let faux = ("src/a/x/p.rs", "pub fn g() { TR(\"alice\", \"salon\"); }\n");
    for a in [
        "pub fn f() { mod x { #[path = \"p.rs\"] pub mod m; } x::m::g(); }\n",
        "pub const _: () = { mod x { #[path = \"p.rs\"] pub mod m; } };\n",
        "pub fn f() { #[path = \"x/p.rs\"] mod m; }\n",
        "#[cfg(test)]\npub fn f() { mod x { #[path = \"p.rs\"] pub mod m; } }\n",
    ] {
        refuse(
            &[("src/main.rs", "mod a;\n"), ("src/a.rs", a), p, faux],
            "déclaré dans un bloc",
        );
    }
    // Un module en ligne dans un bloc, sans fichier, reste lu.
    assert_eq!(
        un("fn f() { mod x { pub fn g() { TR(\"vrai\", \"real\"); } } }\n"),
        attendus(&["vrai", "real"])
    );
}

/// 4e re-contrôle SOURCES-4 : `cfg(fuzzing)` et `cfg(miri)`, employés dans le dépôt, sont faux dans le programme
/// comme `cfg(test)` et `cfg(kani)`.
#[test]
fn r4_sources_4_fuzzing_et_miri_sont_faux_dans_le_programme() {
    let texte = "#[cfg(fuzzing)]\nfn a() { TR(\"alice\", \"salon\"); }\n\
                 #[cfg(any(test, fuzzing))]\nfn b() { TR(\"maison\", \"rouge\"); }\n\
                 #[cfg(miri)]\nfn c() { TR(\"bureau\", \"desk\"); }\n\
                 #[cfg(not(miri))]\nfn d() { TR(\"vrai\", \"real\"); }\n";
    assert_eq!(un(texte), attendus(&["vrai", "real"]));
}

/// 5e re-contrôle SOURCES-1 : une macro inconnue (une enveloppe hors de src/, une macro d'une dépendance, `cfg_if!`)
/// peut choisir un seul de ses bras par `cfg` ; lus jeton par jeton, tous seraient pris pour du programme. Un corps
/// à bras (« => » ou « else » à son premier niveau, « if #[…] » partout) avec un appel de texte arrête la compilation,
/// aussi pour une macro appelée dans les règles d'un `macro_rules!`.
#[test]
fn r5_sources_1_une_macro_a_bras_avec_un_texte_arrete_la_compilation() {
    for texte in [
        "use autre::choix;\nchoix! { test => { fn a() { TR(\"alice\", \"salon\"); } } _ => { fn a() { TR(\"vrai\", \
         \"real\"); } } }\n",
        "fn a() { let _ = autre::choix! { test => { TR(\"alice\", \"salon\") } _ => { TR(\"vrai\", \"real\") } }; }\n",
        "cfg_if::cfg_if! { if #[cfg(not(test))] { fn a() { TR(\"vrai\", \"real\"); } } else { fn a() { TR(\"alice\", \
         \"salon\"); } } }\n",
        "cfg_if! { if #[cfg(unix)] {} else { fn a() { TR(\"alice\", \"salon\"); } } }\n",
        "m! { @ [ cfg_if! { if #[cfg(not(test))] {} else { TR(\"alice\", \"salon\") } } ] }\n",
        "choix! { not(test) => {} else { TR(\"alice\", \"salon\") } }\n",
        "m! { @ [ if #[cfg(not(test))] {} else { TR(\"alice\", \"salon\") } ] }\n",
        "macro_rules! m { () => { cfg_if::cfg_if! { if #[cfg(not(test))] {} else { TR(\"alice\", \"salon\") } } } }\n",
        "macro_rules! m { () => { [ choix! { test => { TR(\"alice\", \"salon\") } } ] } }\n",
    ] {
        match lecture(&[("src/main.rs", texte)]) {
            Ok(mots) => panic!("lu sans erreur : {mots:?} ({texte})"),
            Err(Illisible(e)) => assert!(e.contains("hors de la liste blanche"), "{e} ({texte})"),
        }
    }
    // Restent lus : les règles d'un `macro_rules!`, un `match` relu comme du code dans une macro admise, une macro
    // inconnue sans texte, un `if` ou un `match` du programme plus bas dans une macro admise qui n'est pas relue comme
    // du code (`json!`).
    assert_eq!(
        un("macro_rules! m { () => { TR(\"vrai\", \"real\") }; (un) => { TR(\"maison\", \"rouge\") }; }\n"),
        attendus(&["vrai", "real", "maison", "rouge"])
    );
    assert_eq!(
        un(
            "fn a(x: u8) { vec![match x { 0 => TR(\"vrai\", \"real\"), _ => TR(\"maison\", \"rouge\") }]; }\n\
            fn b() { choix! { test => { 1 } _ => { 2 } } }\n"
        ),
        attendus(&["vrai", "real", "maison", "rouge"])
    );
    assert_eq!(
        un(
            "fn a(x: bool) { let _ = json!({ \"a\": if x { TR(\"vrai\", \"real\") } else { TR(\"maison\", \"rouge\") }, \
            \"b\": match x { true => 1, false => 2 } }); }\n"
        ),
        attendus(&["vrai", "real", "maison", "rouge"])
    );
}

#[test]
fn r6_sources_1_une_macro_hors_de_la_liste_blanche_autour_d_un_texte_arrete_la_compilation() {
    // Les quatre formes de la 6e passe : une macro inconnue qui choisit par `cfg` dans un appel de texte, à toute
    // profondeur, quelle que soit la forme de ses bras.
    for texte in [
        "fn a() -> String { TRF(\"vrai {}\", \"real {}\", autre::choix! { test => { \"alice salon\" } _ => { \"maison\" } }) }\n",
        "fn a() -> String { TRF(\"vrai {}\", \"real {}\", choix! { if #[cfg(not(test))] { \"maison\" } else { \"alice \
         salon\" } }) }\n",
        "fn a() -> String { TRF(\"vrai {}\", \"real {}\", choix! { not(test) => \"maison\", else => \"alice salon\" }) }\n",
        "m! { @ [ TRF(\"vrai {}\", \"real {}\", choix! { test => { \"alice salon\" } _ => { \"maison\" } }) ] }\n",
        // Une macro inconnue sous un nom admis : par son chemin, dans du code ou dans des jetons.
        "fn a() -> String { TRF(\"vrai {}\", \"real {}\", autre::format! { test => { \"alice salon\" } }) }\n",
        "macro_rules! m { () => { TRF(\"vrai {}\", \"real {}\", autre::format! { test => { \"alice salon\" } }) } }\n",
        "macro_rules! m { () => { TRF(\"vrai {}\", \"real {}\", ::format! { test => { \"alice salon\" } }) } }\n",
    ] {
        match lecture(&[("src/main.rs", texte)]) {
            Ok(mots) => panic!("lu sans erreur : {mots:?} ({texte})"),
            Err(Illisible(e)) => assert!(e.contains("hors de la liste blanche"), "{e} ({texte})"),
        }
    }
    // Un nom admis donné à une autre macro : par un `use` ou par une définition.
    for texte in [
        "use autre::choix as format;\n",
        "use autre::format;\n",
        "use std::println as format;\n",
        "use autre::{x, choix as vec};\n",
    ] {
        match lecture(&[("src/main.rs", texte)]) {
            Ok(mots) => panic!("lu sans erreur : {mots:?} ({texte})"),
            Err(Illisible(e)) => assert!(e.contains("donne le nom d'une macro admise"), "{e} ({texte})"),
        }
    }
    refuse(
        &[("src/main.rs", "macro_rules! format { (test => $a:expr) => { $a }; }\n")],
        "définie sous le nom d'une macro admise",
    );
    // Restent lus : les importations admises, et un nom admis du paquet même (une fonction `json`).
    assert_eq!(
        un(
            "use serde_json::json;\nuse std::format;\nuse super::json;\nuse crate::x::json as y;\n\
            fn a() { let _ = serde_json::json!({ \"a\": TR(\"vrai\", \"real\") }); }\n"
        ),
        attendus(&["vrai", "real"])
    );
}

#[test]
fn r6_sources_2_un_if_dans_une_macro_admise_dans_une_autre_est_lu() {
    // Deux formes que la détection des bras refusait à tort : un `if` du programme dans `format!` dans `json!`, et
    // dans `write!` dans un `macro_rules!`.
    assert_eq!(
        un(
            "fn a(x: bool) { let _ = json!({ \"a\": format!(\"{}\", if x { TR(\"vrai\", \"real\") } else { TR(\"maison\", \
             \"rouge\") }) }); }\n"
        ),
        attendus(&["vrai", "real", "maison", "rouge"])
    );
    assert_eq!(
        un(
            "macro_rules! m { () => { write!(f, \"{}\", if a { TR(\"vrai\", \"real\") } else { TR(\"maison\", \
             \"rouge\") }) } }\n"
        ),
        attendus(&["vrai", "real", "maison", "rouge"])
    );
}

#[test]
fn r7_sources_1_une_macro_nommee_par_une_metavariable_autour_d_un_texte_arrete_la_compilation() {
    // La preuve de la 7e passe : `$format!` est la macro passée à l'appel (`jette`), pas `format!`. Puis le même par
    // un chemin : une métavariable devant `::` n'est pas plus un paquet admis.
    for texte in [
        "macro_rules! jette { ($($t:tt)*) => { \"\" }; }\nmacro_rules! via { ($format:ident) => { $format!{ \
         TR(\"motsecret\", \"secretword\") } }; }\nfn main() { let x: &str = via!(jette); println!(\"bonjour{x}\"); }\n",
        "macro_rules! via { ($std:ident) => { $std::format!(\"{}\", TR(\"motsecret\", \"secretword\")) }; }\n",
        "macro_rules! via { ($m:ident) => { $m::format!(\"{}\", TR(\"motsecret\", \"secretword\")) }; }\n",
        "macro_rules! via { () => { $crate::format!(\"{}\", TR(\"motsecret\", \"secretword\")) }; }\n",
    ] {
        // Depuis la 8e passe, la règle d'ensemble les arrête toutes : aucune métavariable près d'un texte.
        refuse(&[("src/main.rs", texte)], "métavariable");
    }
    // Témoins : une métavariable appelée dans une macro sans texte reste lue, et `format!` écrit en toutes lettres
    // dans une autre aussi.
    assert_eq!(
        un(
            "macro_rules! via { ($m:ident) => { $m!(x) }; }\nmacro_rules! fmt { () => { format!(\"{}\", TR(\"vrai\", \
            \"real\")) }; }\n"
        ),
        attendus(&["vrai", "real"])
    );
}

#[test]
fn r7_sources_2_un_attribut_ecrit_par_une_metavariable_pres_d_un_texte_arrete_la_compilation() {
    // Les trois formes de la 7e passe : l'attribut n'est connu qu'à l'appel (`cfg(test)` en ferait un essai).
    for texte in [
        "macro_rules! outil { ($(#[$m:meta])* $nom:ident) => { $(#[$m])* fn $nom() -> &'static str { \
         TR(\"motsecret\", \"secretword\") } }; }\noutil!(#[cfg(test)] secret);\n",
        "macro_rules! outil { ($m:meta) => { #[$m] fn f() -> &'static str { TR(\"motsecret\", \"secretword\") } }; \
         }\noutil!(cfg(test));\n",
        "macro_rules! outil { ($a:tt) => { # $a fn f() -> &'static str { TR(\"motsecret\", \"secretword\") } }; \
         }\noutil!([cfg(test)]);\n",
        "macro_rules! outil { ($a:tt) => { #! $a fn f() -> &'static str { TR(\"motsecret\", \"secretword\") } }; }\n",
    ] {
        // Le message de la règle d'ensemble (8e passe), pas celui du « # » illisible : elle les couvre seule.
        refuse(&[("src/main.rs", texte)], "elle peut valoir n'importe quel jeton");
    }
    // Un « # » sans attribut lisible et sans métavariable près d'un texte garde son propre refus.
    refuse(
        &[(
            "src/main.rs",
            "macro_rules! outil { () => { # x fn f() -> &'static str { TR(\"alice\", \"salon\") } }; }\n",
        )],
        "sans attribut lisible",
    );
    // Un attribut d'essai écrit en toutes lettres reste refusé par son propre message.
    refuse(
        &[(
            "src/main.rs",
            "macro_rules! outil { () => { #[cfg(test)] fn f() -> &'static str { TR(\"alice\", \"salon\") } }; }\n",
        )],
        "attribut d'essai",
    );
    // Témoins : l'idiome du programme (la documentation d'un type passée par `$(#[$doc])*`) dans un corps sans
    // texte, et un attribut lisible près d'un texte.
    assert_eq!(
        un(
            "macro_rules! chaine { ($(#[$doc:meta])* $nom:ident) => { $(#[$doc])* pub struct $nom(String); }; }\n\
             macro_rules! m { () => { #[derive(Debug)] struct S; fn f() -> &'static str { TR(\"vrai\", \"real\") } \
             }; }\n"
        ),
        attendus(&["vrai", "real"])
    );
}

#[test]
fn r7_sources_3_un_nom_de_paquet_ou_de_macro_admis_cache_par_une_declaration_arrete_la_compilation() {
    // La preuve de la 7e passe : `mod alloc` posé par une macro, puis `alloc::vec!` (la macro `jette`).
    let preuve = "macro_rules! jette { ($a:expr) => { \"\" }; }\nmacro_rules! pose { () => { mod alloc { pub(crate) \
                  use jette as vec; } }; }\npose!();\nfn main() { let x: &str = alloc::vec!(TR(\"motsecret\", \
                  \"secretword\")); println!(\"bonjour{x}\"); }\n";
    // Toute déclaration dans des jetons : le nom qu'elle donne peut venir d'une métavariable.
    for texte in [
        preuve,
        "macro_rules! pose { () => { macro_rules! format { ($a:expr) => { \"\" }; } }; }\n",
        "macro_rules! pose { ($n:ident) => { mod $n {} }; }\n",
        "macro_rules! pose { ($p:path, $n:ident) => { use $p as $n; }; }\n",
        "macro_rules! pose { () => { extern crate autre as std; }; }\n",
    ] {
        refuse(&[("src/main.rs", texte)], "lu jeton par jeton");
    }
    // Dans du code : un module, un `use` ou un `extern crate` au nom d'un paquet admis.
    refuse(
        &[(
            "src/main.rs",
            "mod alloc {}\nfn main() { let _ = alloc::vec!(TR(\"motsecret\", \"secretword\")); }\n",
        )],
        "module « alloc » au nom d'un paquet admis",
    );
    for texte in [
        "use autre as std;\n",
        "use autre::serde_json;\n",
        "use crate::m as alloc;\n",
    ] {
        refuse(&[("src/main.rs", texte)], "donne le nom d'un paquet admis");
    }
    refuse(
        &[("src/main.rs", "extern crate autre as core;\n")],
        "donne le nom d'un paquet admis",
    );
    // Témoins : le paquet sous son propre nom, un module d'un autre nom, `r#mod` (un nom ordinaire) dans des jetons.
    assert_eq!(
        un(
            "use serde_json;\nextern crate alloc;\nextern crate alloc as alloc;\nmod stdx {}\nmacro_rules! m { () => { \
             let r#mod = 1; format!(\"{}\", TR(\"vrai\", \"real\")) }; }\n"
        ),
        attendus(&["vrai", "real"])
    );
}

#[test]
fn r7_sources_4_un_use_refuse_dit_quoi_ecrire_a_la_place() {
    for (texte, complet) in [
        ("use libc::write;\n", "libc::write"),
        ("use tokio::fs::{read, write};\n", "tokio::fs::write"),
    ] {
        refuse(
            &[("src/main.rs", texte)],
            &format!("le chemin complet à l'appel (« {complet}(…) »)"),
        );
        refuse(&[("src/main.rs", texte)], &format!("« use {complet} as autre_nom; »"));
    }
    // Les deux formes conseillées sont lues.
    assert_eq!(
        un(
            "use libc::write as ecrire;\nfn a() { let _ = libc::write(1, p, n); let _ = ecrire(1, p, n); \
             TR(\"vrai\", \"real\"); }\n"
        ),
        attendus(&["vrai", "real"])
    );
}

/// 8e passe, règle d'ensemble : une métavariable (`$x:tt`) peut valoir n'importe quel jeton. Le corps d'une macro qui
/// contient un texte n'en a donc aucune : ni le nom de la macro autour (`$($p)::+ !`), ni le « ! » qui en fait un
/// appel (`$m $b`).
#[test]
fn r8_sources_1_une_macro_ecrite_par_des_metavariables_autour_d_un_texte_arrete_la_compilation() {
    for texte in [
        "macro_rules! jette { ($($t:tt)*) => { \"\" }; }\nmacro_rules! par { ($($p:ident)::+) => { $($p)::+ ! { \
         TR(\"motsecret\", \"secretword\") } }; }\nfn main() { let x: &str = par!(jette); println!(\"bonjour{x}\"); }\n",
        "macro_rules! jette { ($($t:tt)*) => { \"\" }; }\nmacro_rules! par { ($m:ident $b:tt) => { $m $b { \
         TR(\"motsecret\", \"secretword\") } }; }\nfn main() { let x: &str = par!(jette !); println!(\"bonjour{x}\"); }\n",
        // Une métavariable seulement dans les règles d'appel (le côté gauche) suffit aussi : la règle est simple.
        "macro_rules! m { ($x:expr) => { TR(\"motsecret\", \"secretword\") }; }\n",
    ] {
        refuse(&[("src/main.rs", texte)], "métavariable");
    }
    // Témoins : des métavariables dans une macro sans texte, et un texte dans une macro sans métavariable.
    assert_eq!(
        un(
            "macro_rules! par { ($($p:ident)::+) => { $($p)::+ ! {} }; ($m:ident $b:tt) => { $m $b {} }; }\n\
             macro_rules! m { () => { format!(\"{}\", TR(\"vrai\", \"real\")) }; (un) => { TR(\"maison\", \"rouge\") }; }\n"
        ),
        attendus(&["vrai", "real", "maison", "rouge"])
    );
}

/// 8e passe : le « # » d'un attribut d'essai venu d'une métavariable (`outil!(#)`).
#[test]
fn r8_sources_2_un_diese_venu_d_une_metavariable_pres_d_un_texte_arrete_la_compilation() {
    refuse(
        &[(
            "src/main.rs",
            "macro_rules! outil { ($h:tt) => { $h[cfg(test)] fn f() -> &'static str { TR(\"motsecret\", \
             \"secretword\") } }; }\noutil!(#);\n",
        )],
        "métavariable",
    );
}

/// 8e passe : un mot qui lie un nom ou tire un fichier (`mod`, `use`, `extern`, `macro_rules`, `include`), passé
/// dans l'appel d'une macro hors de la liste blanche, qui pourrait le recombiner ; ou écrit dans des jetons.
#[test]
fn r8_sources_3_un_mot_qui_lie_dans_l_appel_d_une_macro_maison_arrete_la_compilation() {
    for texte in [
        "macro_rules! jette { ($a:expr) => { \"\" }; }\nmacro_rules! pose { ($($t:tt)*) => { $($t)* }; }\n\
         pose!(mod alloc { pub(crate) use jette as vec; });\nfn main() { let x: &str = alloc::vec!(TR(\"motsecret\", \
         \"secretword\")); println!(\"bonjour{x}\"); }\n",
        "pose!(mod x {} use y;);\n",
        "pose!(use autre::choix as format;);\n",
        "pose!(extern crate autre as std;);\n",
        "pose!(macro_rules! format { ($a:expr) => { \"\" }; });\n",
        "autre::pose! { include!(\"definitions.inc\"); }\n",
        "fn a() { pose!(r#include); }\n",
    ] {
        refuse(&[("src/main.rs", texte)], "dans l'appel de la macro");
    }
    for texte in [
        "macro_rules! m { () => { include!(\"definitions.inc\") }; }\n",
        "macro_rules! m { () => { extern { fn f(); } }; }\n",
        "macro_rules! m { () => { macro_rules! n { () => {} } }; }\n",
        "macro_rules! m { () => { r#macro_rules! n { () => {} } }; }\n",
    ] {
        refuse(&[("src/main.rs", texte)], "lu jeton par jeton");
    }
    // Témoins : une macro maison appelée avec des mots ordinaires (`r#mod` en est un), et une macro admise.
    assert_eq!(
        un(
            "fn a() { pose!(x y z); pose!(r#mod); let _ = format!(\"{}\", TR(\"vrai\", \"real\")); \
             let _ = vec![1, 2]; }\n"
        ),
        attendus(&["vrai", "real"])
    );
}

/// 8e passe : un fichier que la lecture ne suivrait pas arrête la compilation : un module du programme hors de src/,
/// `#[macro_use]`, un `include!` autre que celui de la base des fabricants, et les détours par `use` vers eux.
#[test]
fn r8_sources_4_un_fichier_non_lu_arrete_la_compilation() {
    refuse(
        &[("src/main.rs", "#[path = \"../hors/m.rs\"]\nmod m;\n")],
        "hors de src/",
    );
    refuse(
        &[
            ("src/main.rs", "mod a;\n"),
            ("src/a.rs", "#[path = \"../../hors/m.rs\"]\nmod m;\n"),
        ],
        "hors de src/",
    );
    for texte in [
        "#[macro_use]\nmod m {}\n",
        "#[cfg_attr(unix, macro_use)]\nmod m {}\n",
        "#[macro_use]\nextern crate autre;\n",
        "#![macro_use]\nfn a() {}\n",
    ] {
        refuse(&[("src/main.rs", texte)], "macro_use");
    }
    for texte in [
        "include!(\"definitions.inc\");\n",
        "fn a() -> &'static str { include!(\"texte.inc\") }\n",
        "mod base { include!(concat!(env!(\"OUT_DIR\"), \"/autre.rs\")); }\n",
        "mod base { std::include!(concat!(env!(\"OUT_DIR\"), \"/autre.rs\")); }\n",
    ] {
        refuse(&[("src/main.rs", texte)], "include!");
    }
    refuse(&[("src/main.rs", "use std::include as i;\n")], "renomme include!");
    refuse(
        &[("src/main.rs", "use m::alloc::{self};\n")],
        "donne le nom d'un paquet admis",
    );
    // Témoins : la forme connue de src/reseau/scan.rs, un module hors de src/ sous `#[cfg(kani)]` (une preuve), et
    // un `#[macro_use]` dans un module d'essais.
    assert_eq!(
        un(
            "mod base {\n    include!(concat!(env!(\"OUT_DIR\"), \"/fabricants.rs\"));\n}\n\
             #[cfg(kani)]\n#[path = \"../outils/preuves/p.rs\"]\nmod preuve;\n\
             #[cfg(test)]\n#[macro_use]\nmod essais {}\nfn a() { TR(\"vrai\", \"real\"); }\n"
        ),
        attendus(&["vrai", "real"])
    );
}

/// 8e passe : `use std::alloc;` et `use core::alloc;` importent le paquet sous son propre nom ; ils passent. Un refus
/// dit quoi écrire à la place.
#[test]
fn r8_sources_5_un_paquet_admis_importe_sous_son_nom_est_lu() {
    for texte in [
        "use std::alloc;\n",
        "use core::alloc;\n",
        "use std::alloc::{self};\n",
        "use std::{alloc, fmt};\n",
    ] {
        assert_eq!(
            un(&format!("{texte}fn a() {{ TR(\"vrai\", \"real\"); }}\n")),
            attendus(&["vrai", "real"]),
            "{texte}"
        );
    }
    for (texte, complet) in [
        ("use autre as std;\n", "autre"),
        ("use crate::m::alloc;\n", "crate::m::alloc"),
    ] {
        refuse(&[("src/main.rs", texte)], &format!("« use {complet} as autre_nom; »"));
    }
}

/// Le modèle des couleurs partagé avec fenetre/ n'est pas lu au build (hors de src/) : cet essai le passe aux mêmes
/// règles que src/, pour qu'il ne cache rien (ni `macro_rules! format`, ni `mod alloc`, ni texte).
#[test]
fn le_modele_partage_hors_de_src_suit_les_regles() {
    let modele = include_str!("../../../fenetre/src/couleurs.rs");
    let sources = vec![
        (PathBuf::from("src/main.rs"), String::from("mod modele;\n")),
        (PathBuf::from("src/modele.rs"), modele.to_string()),
    ];
    match vocabulaire(&sources) {
        Ok(mots) => assert!(mots.is_empty(), "le modèle a des textes : {mots:?}"),
        Err(Illisible(e)) => panic!("{e}"),
    }
}

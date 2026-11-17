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

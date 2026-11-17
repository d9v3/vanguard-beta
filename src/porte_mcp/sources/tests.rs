//! Essais de la lecture des sources (le vocabulaire de la porte MCP), sur des sources inventées.

use super::*;

/// Une source inventée : « TR( » y devient l'appel de la macro de texte (écrit ainsi, il n'en est pas un pour
/// outils/textes.py ni pour la lecture de ce fichier-ci).
fn source(texte: &str) -> String {
    texte.replace("TR(", concat!("t", "r!("))
}

fn mots(fichiers: &[(&str, &str)]) -> BTreeSet<String> {
    let sources: Vec<(PathBuf, String)> = fichiers.iter().map(|(c, t)| (PathBuf::from(c), source(t))).collect();
    vocabulaire(&sources)
}

fn un(texte: &str) -> BTreeSet<String> {
    mots(&[("src/a.rs", texte)])
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
fn les_fichiers_des_modules_d_essais_sont_ecartes() {
    let essai = "fn a() { TR(\"alice\", \"bob\"); }\n";
    let vrai = "fn a() { TR(\"alerte\", \"alert\"); }\n";
    let lu = mots(&[
        ("src/main.rs", "#[cfg(test)]\nmod essais;\nmod vrai;\n"),
        ("src/essais.rs", essai),
        ("src/essais/sous.rs", essai),
        (
            "src/vrai.rs",
            "#[cfg(all(test, unix))]\npub(crate) mod corpus;\n#[cfg(test)]\nmod jeu {\n    mod x;\n}\n",
        ),
        ("src/vrai/corpus.rs", essai),
        ("src/vrai/jeu/x.rs", essai),
        ("src/vrai/corpus_bis.rs", vrai),
        (
            "src/b/mod.rs",
            "#[cfg(test)]\n#[path = \"../autre/fixe.rs\"]\nmod fixe;\n",
        ),
        ("src/autre/fixe.rs", essai),
        ("src/tout.rs", "#![cfg(test)]\nfn a() { TR(\"alice\", \"bob\"); }\n"),
        ("src/tout/sous.rs", essai),
    ]);
    assert_eq!(lu, attendus(&["alerte", "alert"]));
}

#[test]
fn une_fin_de_ligne_echappee_colle_les_deux_bouts() {
    // LB-COMPILATION-5 : comme Rust, « \ » en fin de ligne ne laisse rien, ni les blancs de la ligne suivante.
    let texte = "fn a() { TR(\"le pare-\\\n        feu est coupé\\n\\\n        ici\", \"x\"); }\n";
    assert_eq!(un(texte), attendus(&["coupé", "est", "ici", "le", "pare-feu", "x"]));
}

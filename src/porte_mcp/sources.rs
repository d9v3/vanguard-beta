//! Le vocabulaire de la porte MCP tiré des sources : les morceaux (suites sans espace) des chaînes que Vanguard passe
//! à ses macros de texte, sans les essais. Inclus par build.rs (par son chemin), qui lit les fichiers et écrit le
//! résultat ; déclaré dans le programme sous `cfg(test)` seulement, pour que ses essais le mettent à l'épreuve sur des
//! sources inventées. Rien ici ne lit le disque : build.rs seul choisit les fichiers (outils/essais-signature.sh le
//! garde).
//!
//! La lecture passe par l'arbre syntaxique de `syn`, comme le compilateur, et plus par une lecture du texte faite à la
//! main (trois rondes de relecture y ont trouvé des formes oubliées). Elle suit les modules comme rustc : depuis
//! src/main.rs (et src/lib.rs, src/bin/), chaque `mod nom;` du programme mène à son fichier (`nom.rs`, `nom/mod.rs`
//! ou le chemin d'un attribut `path`, relatif comme pour rustc, modules écrits en ligne compris). Un fichier qu'aucun
//! module du programme ne déclare n'est donc jamais lu.
//!
//! Les essais n'y entrent pas : leurs valeurs inventées (« alice », « Salon ») ne sont pas des mots de Vanguard. Est un
//! essai tout nœud de l'arbre (élément, module, `impl`, champ, variante, bras, instruction, expression, argument,
//! motif…) que rustc retire vraiment du programme : un attribut `#[test]` ou `#[bench]` d'un seul segment, ou un `cfg`
//! faux quand `test` (et `kani`, les preuves de outils/preuves/) sont faux : `cfg(test)`, `cfg(all(…, test))` à toute
//! profondeur, `cfg(test,)`, `cfg(any())`, `cfg(false)`, et un `cfg_attr(c, test)` ou `cfg_attr(c, cfg(test))` dont la
//! condition `c` est sûrement vraie. `cfg(any(unix, test))`, `cfg(not(test))`, un `cfg_attr(unix, test)` et tout
//! attribut à plusieurs segments (`#[tokio::test]`, `#[rust_analyzer::test]`) restent du programme : un attribut
//! d'outil n'enlève rien, et une macro d'attribut garde le corps (9e passe, R9-SOURCES-1). Un module d'essais n'est lu
//! que pour suivre ses propres modules, comme essais eux aussi. Un appel `proptest!` ou `quickcheck!` est un essai.
//!
//! Le programme publié est compilé sans la fonctionnalité `reception` : `cfg(feature = "x")` est jugé avec celles de
//! cette compilation (build.rs les lit de Cargo), comme rustc. Trois formes de code compilé que le programme n'exécute
//! jamais gardent leurs règles (jugées comme le reste) mais pas leurs textes : la branche qu'un `cfg!` fixe écarte, un
//! élément dit mort (`allow(dead_code)`, `expect(dead_code)`, même par un `cfg_attr` dont la condition n'est pas
//! fausse) et les fonctions de TEXTES_MORTS, une cause par ligne. C'est le sens sûr : un mot de moins est masqué, et
//! chaque mot qui reste doit se trouver dans un programme publié (contrôle croisé V1, outils/vocabulaire-binaire.py).
//!
//! Tout nom que la lecture reconnaît à son nom (`NOMS_RESERVES` : les macros de texte, la liste blanche, les macros
//! d'essais, `concat`, `include`, `test`, `bench`) ne se reprend pas : aucune définition (`macro_rules!`, `macro`) sous
//! ce nom, aucun `use` qui le donne à autre chose, aucun appel par le chemin d'un autre paquet (9e passe,
//! R9-SOURCES-2 et 3). Seule exception, nommée par son chemin : les macros de texte elles-mêmes, au premier niveau de
//! src/langue.rs.
//!
//! Ne sont lues que les chaînes des appels aux macros de texte (tr!, trf!, trp!, tre!, trw!, trwln!, trpr!, comme
//! outils/textes.py), à toute profondeur dans leurs arguments ; jamais un commentaire ni une documentation (syn ne
//! les garde pas comme du code), ni les arguments de `env!` et `cfg!` (un nom de variable, une condition : pas un
//! texte du programme ; chaque mot du vocabulaire doit se trouver dans un programme publié, contrôle croisé V1 de
//! outils/vocabulaire-binaire.py). Le corps d'une macro est relu comme une liste d'expressions ou d'instructions ; s'il
//! n'en est pas une (`macro_rules!`, `matches!`), ses jetons sont parcourus pour trouver les appels de texte.
//!
//! Une macro autre que de texte, appelée dans un appel de texte ou dont le corps en contient un, doit être de la liste
//! blanche (MACROS_ADMISES : `format!`, `write!`, `json!`, `vec!`…), chacune jugée : elle ne choisit rien par `cfg`.
//! Une macro inconnue pourrait garder un seul de ses bras (`cfg_if!`, ou une macro maison qui choisit par `cfg`) quand
//! la lecture les prendrait tous pour du programme ; plutôt que de deviner ses bras, la compilation s'arrête et dit de
//! l'ajouter à la liste après l'avoir jugée (6e passe, R6-SOURCES-1).
//!
//! Une métavariable peut valoir n'importe quel jeton (le nom d'une macro, « ! », « # », `mod`) : refuser des jetons
//! écrits en clair laisse toujours un voisin. Deux règles d'ensemble, donc (8e passe) :
//! - le corps lu jeton par jeton d'une macro qui contient un texte n'a aucune métavariable ;
//! - un mot qui lie un nom ou tire un fichier (`use`, `mod`, `extern`, `macro`, `macro_rules`, `include`) n'est
//!   jamais dans des jetons, ni dans l'appel d'une macro hors de la liste blanche (elle pourrait le recombiner).
//!
//! Dans le code, un module, un `use` ou un `extern crate` ne prend pas le nom d'un paquet admis (`mod alloc`) ; un
//! module du programme hors de src/, un `#[macro_use]` et un `include!` autre que celui d'OUT_DIR arrêtent la
//! compilation : ils feraient entrer des macros ou des modules que la lecture ne lit pas.
//!
//! Rien n'est ignoré en silence, la compilation s'arrête : un fichier que syn ne sait pas lire, une forme qu'il garde
//! sans la comprendre (`Verbatim`), un `cfg` mal écrit, un module du programme sans fichier, un attribut d'essai dans
//! le corps d'une macro qui n'est pas relu comme du code, une macro hors de la liste blanche autour d'un texte, un nom
//! réservé pris par une autre macro (`macro_rules!`, `macro`, `use … as`, `use autre::nom`, chemin d'un autre paquet),
//! un nom de paquet admis pris par autre chose, un fichier .rs de la liste qu'aucun module ne déclare.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{Attribute, Expr, ForeignItem, ImplItem, Item, Lit, Meta, Pat, Token, TraitItem, Type};

/// Les macros de texte de Vanguard (src/langue.rs).
const MACROS_DE_TEXTE: [&str; 7] = ["tr", "trf", "trp", "tre", "trw", "trwln", "trpr"];
/// Les macros qui n'écrivent que des essais.
const MACROS_D_ESSAIS: [&str; 2] = ["proptest", "quickcheck"];
/// Les attributs qui font d'une fonction un essai, écrits seuls (`#[test]`, `#[bench]`) : rustc ne retire du programme
/// que ceux-là (et un `cfg` faux). Un autre chemin qui finit par le même nom (`#[rust_analyzer::test]`,
/// `#[rustfmt::test]`, `#[tokio::test]`) est un attribut d'outil ou d'un autre paquet : rustc garde l'élément, la
/// lecture aussi (9e passe, R9-SOURCES-1).
const ATTRIBUTS_D_ESSAIS: [&str; 2] = ["test", "bench"];
/// Les `cfg` faux dans le programme : ses essais, les preuves de Kani (outils/preuves.sh), le banc de fuzzing (fuzz/)
/// et Miri (outils/preuves.sh) ; aucun n'est posé par la compilation du programme (4e re-contrôle, SOURCES-4).
const CFG_FAUX: [&str; 4] = ["test", "kani", "fuzzing", "miri"];
/// Les macros qui choisissent leur code par `cfg` (`cfg_select!`, et son ancien nom `cfg_match!`) : la lecture ne
/// juge pas leurs bras, la compilation s'arrête sur elles, même renommées par un `use` (4e re-contrôle, SOURCES-1).
const MACROS_DE_CFG: [&str; 2] = ["cfg_select", "cfg_match"];
/// Les macros admises autour des textes : dans un appel de texte, ou avec un appel de texte dans leur corps. Chacune a
/// été jugée : elle ne choisit rien par `cfg` (une enveloppe comme `cfg_if!` en garderait un seul bras, la lecture
/// les prendrait tous pour du programme). Toute autre macro à cet endroit arrête la compilation, quelle que soit sa
/// forme (6e passe, R6-SOURCES-1) ; liste tirée des macros que le programme emploie vraiment autour de ses textes.
/// `cfg!` ne rend qu'un booléen : les deux branches d'un `if cfg!(…)` sont compilées (leurs règles jugées), mais
/// celle que la valeur fixe écarte (`if cfg!(test)`) ne garde pas ses textes (contrôle croisé V1).
/// `env!` rend une chaîne fixée à la compilation, `macro_rules!` définit une macro sans rien choisir (ses bras sont
/// tous lus, et un attribut d'essai dedans arrête la compilation).
const MACROS_ADMISES: [&str; 11] = [
    "cfg",
    "env",
    "eprintln",
    "format",
    "json",
    "macro_rules",
    "print",
    "println",
    "vec",
    "write",
    "writeln",
];
/// Les macros admises dont les arguments ne sont pas des textes du programme : `cfg!` lit une condition
/// (`target_os = "windows"`), `env!` le nom d'une variable de la compilation (c'est sa valeur, pas son nom, qui entre
/// dans le programme). Leurs chaînes ne vont pas au vocabulaire : chaque mot du vocabulaire doit se trouver dans un
/// programme publié (contrôle croisé V1, outils/vocabulaire-binaire.py), et « CARGO_PKG_VERSION » n'y est pas. Les
/// autres macros qui ne prennent pas de texte (`option_env!`, `include_str!`, `concat!`…) ne sont pas admises autour
/// d'un texte : leur appel y arrête déjà la compilation.
const MACROS_SANS_TEXTE: [&str; 2] = ["cfg", "env"];
/// Les fonctions compilées dont l'optimisation retire les textes (contrôle croisé V1, outils/vocabulaire-binaire.py) :
/// le programme ne peut pas les écrire, par une constante ou un type que la lecture ne juge pas. Une cause par ligne,
/// jamais un mot : leurs textes ne vont pas au vocabulaire (le sens sûr, ils sont masqués), leurs règles restent
/// jugées. Une fonction est nommée par son fichier et son nom (`Type::nom` dans un `impl`) ; une ligne qui ne trouve
/// plus sa fonction dans un fichier lu arrête la compilation (et un essai garde que chaque fichier existe).
const TEXTES_MORTS: [(&str, &str, &str); 5] = [
    (
        "src/protection/sortantes.rs",
        "service",
        "le nom du service n'est jamais affiché : seul `service(…).is_none()` est lu",
    ),
    (
        "src/chiffrement.rs",
        "Refus::fmt",
        "chaque appel du programme écrit lui-même le refus `Authentification` (« Phrase incorrecte »)",
    ),
    (
        "src/copier.rs",
        "empreinte_relue",
        "`align_offset` d'un tampon d'octets ne peut pas échouer : l'erreur « impossible à aligner » est un filet",
    ),
    (
        "src/parametres/partage.rs",
        "au_menu",
        "l'avis du partage attend le relais (`envoi::RELAIS` vaut `None`)",
    ),
    (
        "src/verifier_cle.rs",
        "annoncer",
        "les fichiers de l'essai font 1 Gio (constante) : jamais la limite de 4 Go de FAT32",
    ),
];
/// Les seuls paquets d'où une macro admise peut venir quand elle est appelée par un chemin (`std::format!`,
/// `serde_json::json!`) ou importée par un `use` : `autre::format!` est une autre macro, qui pourrait choisir par
/// `cfg` sous un nom admis.
const RACINES_ADMISES: [&str; 4] = ["std", "core", "alloc", "serde_json"];
/// Les seuls modules du programme hors de src/ : build.rs ne les lit pas, un essai les passe aux règles de la lecture.
const HORS_DE_SRC: [&str; 1] = ["fenetre/src/couleurs.rs"];
/// Les macros que la lecture reconnaît par l'écriture de leur appel : `include!(concat!(env!("OUT_DIR"), …))`
/// (`inclusion_connue`). `env` est déjà parmi les macros admises.
const MACROS_ECRITES: [&str; 2] = ["concat", "include"];
/// Les noms réservés : tout ce que la lecture reconnaît par son nom (macros de texte, admises, d'essais, écrites,
/// attributs d'essais). Un nom ne désigne ce que la lecture croit que si personne d'autre ne le porte : aucune
/// définition (`macro_rules!`) ni aucun import (`use … as nom`, `use autre::nom`) sous ces noms dans le programme,
/// et un appel par un chemin ne vient que d'une origine permise (`origine_permise`), sauf les définitions des
/// macros de texte dans `DEFINITIONS_DE_TEXTE` (9e passe, R9-SOURCES-2 et 3). Une liste de listes : un nom ajouté à
/// l'une d'elles est réservé du même coup.
const NOMS_RESERVES: [&[&str]; 5] = [
    &MACROS_DE_TEXTE,
    &MACROS_ADMISES,
    &MACROS_D_ESSAIS,
    &MACROS_ECRITES,
    &ATTRIBUTS_D_ESSAIS,
];
/// Le seul fichier où les macros de texte sont définies (`macro_rules! tr`…, à son premier niveau) : la vraie
/// définition, celle dont les arguments sont écrits dans le programme.
const DEFINITIONS_DE_TEXTE: &str = "src/langue.rs";

/// Une forme que la lecture ne sait pas juger, avec ce qu'elle a vu : build.rs arrête la compilation sur elle. Un type
/// à part plutôt que `Echec` du programme, que build.rs ne peut pas atteindre.
#[derive(Debug)]
pub struct Illisible(pub String);

/// Le vocabulaire de ces sources (chemin et texte de chaque fichier), trié et sans doublon ; une erreur (qui arrête
/// la compilation) pour toute forme que la lecture ne sait pas juger.
pub fn vocabulaire(
    sources: &[(PathBuf, String)],
    fonctionnalites: &BTreeSet<String>,
) -> Result<BTreeSet<String>, Illisible> {
    let textes: BTreeMap<PathBuf, &str> = sources.iter().map(|(c, t)| (propre(c), t.as_str())).collect();
    let mut a_lire: Vec<Declare> = textes
        .keys()
        .filter(|f| est_racine(f))
        .map(|f| Declare {
            fichier: f.clone(),
            enfants: f.parent().unwrap_or(Path::new("")).to_path_buf(),
            essai: false,
            par: String::from("racine"),
        })
        .collect();
    if a_lire.is_empty() {
        return Err(Illisible(String::from(
            "vocabulaire : ni src/main.rs, ni src/lib.rs, ni src/bin/ parmi les sources",
        )));
    }
    // Pour chaque fichier lu : vrai s'il l'a été comme programme.
    let mut lus: BTreeMap<PathBuf, bool> = BTreeMap::new();
    let mut morceaux = BTreeSet::new();
    let mut morts_vus: BTreeSet<(PathBuf, &str)> = BTreeSet::new();
    while let Some(module) = a_lire.pop() {
        match lus.get(&module.fichier) {
            Some(true) => continue,
            Some(false) if module.essai => continue,
            _ => {}
        }
        if !module.fichier.starts_with("src") {
            // Un module d'essais (ou de preuves) hors de src/ (outils/preuves/) : rien à lire. Le modèle des couleurs
            // partagé avec fenetre/ : ses mots ne sont pas retenus (le sens sûr, un mot de moins est masqué), et un
            // essai le passe aux mêmes règles que src/ (`le_modele_partage_hors_de_src_suit_les_regles`).
            if module.essai || HORS_DE_SRC.iter().any(|f| module.fichier == Path::new(f)) {
                continue;
            }
            // Un autre module du programme hors de src/ ne serait pas lu (build.rs ne lit que src/) : un
            // `macro_rules! format` ou un `mod alloc` posé là cacherait une macro admise (8e passe, R8-SOURCES-4).
            return Err(Illisible(format!(
                "vocabulaire : {} déclare un module du programme hors de src/ ({}) : il ne serait pas lu, forme non \
                 jugée",
                module.par,
                module.fichier.display()
            )));
        }
        let Some(texte) = textes.get(&module.fichier) else {
            if module.essai {
                // Un module d'essais hors de la liste (tests.rs, tests/, preuves de outils/) : rien à lire.
                continue;
            }
            return Err(Illisible(format!(
                "vocabulaire : {} déclare un module du programme dont le fichier {} n'est pas parmi les sources",
                module.par,
                module.fichier.display()
            )));
        };
        lus.insert(module.fichier.clone(), !module.essai);
        let arbre = syn::parse_file(texte).map_err(|e| {
            Illisible(format!(
                "vocabulaire : {} illisible pour syn : {e}",
                module.fichier.display()
            ))
        })?;
        let mut lecteur = Lecteur {
            textes: &textes,
            fonctionnalites,
            fichier: &module.fichier,
            enfants: module.enfants,
            en_ligne: 0,
            essai: module.essai,
            texte: 0,
            sans_texte: 0,
            mort: 0,
            impl_de: None,
            morts_vus: Vec::new(),
            bloc: 0,
            texte_au_corps: false,
            chaines: Vec::new(),
            modules: Vec::new(),
            erreurs: Vec::new(),
        };
        lecteur.sous(&arbre.attrs, |l| {
            for element in &arbre.items {
                l.visit_item(element);
            }
        });
        if let Some(erreur) = lecteur.erreurs.into_iter().next() {
            return Err(Illisible(erreur));
        }
        morts_vus.extend(lecteur.morts_vus.iter().map(|nom| (module.fichier.clone(), *nom)));
        for chaine in lecteur.chaines {
            morceaux.extend(sans_marques(&chaine).split_whitespace().map(str::to_string));
        }
        a_lire.extend(lecteur.modules);
    }
    let oublies: Vec<String> = textes
        .keys()
        .filter(|f| !lus.contains_key(*f))
        .map(|f| f.display().to_string())
        .collect();
    // Une ligne de TEXTES_MORTS dont le fichier est lu doit y trouver sa fonction : renommée, elle ne retirerait plus
    // rien (le contrôle croisé le dirait), déplacée ailleurs, elle pourrait retirer autre chose.
    for (fichier, nom, _) in TEXTES_MORTS {
        if lus.get(Path::new(fichier)) == Some(&true) && !morts_vus.contains(&(PathBuf::from(fichier), nom)) {
            return Err(Illisible(format!(
                "vocabulaire : TEXTES_MORTS nomme « {nom} » dans {fichier}, qui n'y est plus"
            )));
        }
    }
    if !oublies.is_empty() {
        return Err(Illisible(format!(
            "vocabulaire : fichiers .rs qu'aucun module ne déclare (ni programme, ni essai) : {}",
            oublies.join(", ")
        )));
    }
    Ok(morceaux)
}

/// Une racine du programme : src/main.rs, src/lib.rs, src/bin/x.rs ou src/bin/x/main.rs.
fn est_racine(fichier: &Path) -> bool {
    let morceaux: Vec<&str> = fichier.iter().filter_map(|m| m.to_str()).collect();
    matches!(
        morceaux.as_slice(),
        ["src", "main.rs" | "lib.rs"] | ["src", "bin", _] | ["src", "bin", _, "main.rs"]
    ) && fichier.extension().is_some_and(|e| e == "rs")
}

/// Le chemin sans « . » ni « .. » (sans lire le disque), pour comparer un chemin d'attribut aux fichiers lus.
fn propre(chemin: &Path) -> PathBuf {
    let mut sortie = PathBuf::new();
    for morceau in chemin.components() {
        match morceau {
            Component::CurDir => {}
            Component::ParentDir => {
                sortie.pop();
            }
            autre => sortie.push(autre),
        }
    }
    sortie
}

/// Un module à fichier déclaré par un fichier lu : son fichier, le dossier de ses propres modules, s'il est un essai.
struct Declare {
    fichier: PathBuf,
    enfants: PathBuf,
    essai: bool,
    /// Qui le déclare, pour le message d'erreur.
    par: String,
}

/// La lecture d'un fichier : son arbre parcouru nœud par nœud, avec ce qu'on sait du nœud courant.
struct Lecteur<'a> {
    textes: &'a BTreeMap<PathBuf, &'a str>,
    /// Les fonctionnalités (`feature`) de cette compilation, données par build.rs.
    fonctionnalites: &'a BTreeSet<String>,
    fichier: &'a Path,
    /// Le dossier des modules à fichier déclarés au niveau courant.
    enfants: PathBuf,
    /// La profondeur des modules écrits en ligne (`mod a { … }`) autour du nœud courant.
    en_ligne: usize,
    /// Le nœud courant n'existe qu'aux essais.
    essai: bool,
    /// La profondeur des appels aux macros de texte autour du nœud courant.
    texte: usize,
    /// La profondeur des appels aux macros dont les arguments ne sont pas des textes (`MACROS_SANS_TEXTE`).
    sans_texte: usize,
    /// La profondeur des nœuds compilés dont le programme n'écrit jamais les textes (`TEXTES_MORTS`) : leurs règles
    /// restent jugées (le code est compilé, une macro qu'il définit compte), leurs chaînes ne vont pas au vocabulaire.
    mort: usize,
    /// Le type de l'`impl` autour du nœud courant (`Refus` pour `impl Display for Refus`).
    impl_de: Option<String>,
    /// Les lignes de `TEXTES_MORTS` trouvées dans ce fichier.
    morts_vus: Vec<&'static str>,
    /// La profondeur des blocs (corps de fonction, `const _: () = { … }`) autour du nœud courant.
    bloc: usize,
    /// Le corps de macro lu jeton par jeton contient un appel de texte (ou est dans un) : un attribut qu'on ne sait
    /// pas lire y arrête la compilation.
    texte_au_corps: bool,
    chaines: Vec<String>,
    modules: Vec<Declare>,
    erreurs: Vec<String>,
}

impl Lecteur<'_> {
    fn erreur(&mut self, quoi: &str) {
        self.erreurs
            .push(format!("vocabulaire : {} : {quoi}", self.fichier.display()));
    }

    /// Parcourt un nœud portant ces attributs : en essai s'ils en font un essai (ou si on y est déjà).
    fn sous(&mut self, attributs: &[Attribute], suite: impl FnOnce(&mut Self)) {
        let avant = self.essai;
        match essai_par(attributs.iter().map(|a| &a.meta), self.fonctionnalites) {
            Ok(true) => self.essai = true,
            Ok(false) => {}
            Err(Illisible(e)) => self.erreur(&e),
        }
        // Un élément que le code dit mort (`allow(dead_code)`, `expect(dead_code)`, même par un `cfg_attr`) : rustc le
        // compile, l'optimisation le retire s'il n'est appelé nulle part ; ses textes ne vont pas au vocabulaire (le
        // sens sûr : un mot de moins, masqué), ses règles restent jugées.
        let mort = attributs.iter().any(|a| dit_mort(&a.meta, self.fonctionnalites));
        self.mort += usize::from(mort);
        // `#[macro_use]` répand les macros d'un module ou d'un paquet sous leur nom : un `format` venu de là (d'un
        // fichier non lu, ou d'un autre paquet) cacherait la macro admise (8e passe, R8-SOURCES-4). Le programme n'en
        // a aucun.
        if !self.essai && attributs.iter().any(|a| nomme(&a.meta, "macro_use")) {
            self.erreur("attribut « macro_use » : il répand des macros que la lecture ne suit pas, forme non jugée");
        }
        suite(self);
        self.mort -= usize::from(mort);
        self.essai = avant;
    }

    /// Cette fonction (`nom`, ou `Type::nom`) est-elle de `TEXTES_MORTS` pour ce fichier ? Notée comme trouvée.
    fn texte_mort(&mut self, nom: &str) -> bool {
        let ligne = TEXTES_MORTS
            .iter()
            .find(|(fichier, element, _)| self.fichier == Path::new(fichier) && *element == nom);
        match ligne {
            Some((_, element, _)) if !self.essai => {
                self.morts_vus.push(element);
                true
            }
            _ => false,
        }
    }

    /// La valeur d'une condition `cfg!(c)`, `!cfg!(c)` ou `(cfg!(c))` ; inconnue pour toute autre.
    fn valeur_de_cfg(&self, condition: &Expr) -> Tri {
        match condition {
            Expr::Macro(m) if m.attrs.is_empty() => {
                let chemin: Vec<String> = m
                    .mac
                    .path
                    .segments
                    .iter()
                    .map(|s| sans_r(&s.ident.to_string()).to_string())
                    .collect();
                if sans_texte(&chemin) && chemin.last().is_some_and(|n| n == "cfg") {
                    un_seul(m.mac.tokens.clone(), self.fonctionnalites).unwrap_or(Tri::Inconnu)
                } else {
                    Tri::Inconnu
                }
            }
            Expr::Unary(u) if u.attrs.is_empty() && matches!(u.op, syn::UnOp::Not(_)) => {
                non(self.valeur_de_cfg(&u.expr))
            }
            Expr::Paren(p) if p.attrs.is_empty() => self.valeur_de_cfg(&p.expr),
            _ => Tri::Inconnu,
        }
    }

    /// Le corps d'une macro : relu comme une liste d'expressions, sinon comme des instructions, sinon jeton par jeton.
    fn corps(&mut self, flux: &TokenStream) {
        if let Ok(liste) = Punctuated::<Expr, Token![,]>::parse_terminated.parse2(flux.clone()) {
            for expression in &liste {
                self.visit_expr(expression);
            }
        } else if let Ok(instructions) = syn::Block::parse_within.parse2(flux.clone()) {
            for instruction in &instructions {
                self.visit_stmt(instruction);
            }
        } else {
            let avant = self.texte_au_corps;
            self.texte_au_corps = self.texte > 0 || un_texte(flux);
            // Une métavariable peut valoir n'importe quel jeton : le nom d'une autre macro (`$m!`, `$($p)::+ !`), le
            // « ! » lui-même, un « # » devant des crochets écrits en clair (`$h[cfg(test)]`). Refuser des jetons
            // écrits en clair laisserait toujours un voisin (7e et 8e passes) : près d'un texte, aucune métavariable
            // (8e passe, R8-SOURCES-1 et 2). Le programme n'en a aucune là : ses macros à texte sont sans « $ ».
            if self.texte_au_corps && un_dollar(flux) {
                self.erreur(
                    "métavariable (« $… ») dans le corps d'une macro qui contient un texte : elle peut valoir \
                     n'importe quel jeton (le nom d'une autre macro, « ! », « # »), la lecture ne sait pas ce qui \
                     entoure le texte, forme non jugée ; écrire le texte hors de la macro, ou la macro sans \
                     métavariable",
                );
            }
            self.jetons(flux.clone());
            self.texte_au_corps = avant;
        }
    }

    /// Une macro qui n'est pas de texte, appelée dans un appel de texte ou dont le corps en contient un : elle doit
    /// être de la liste blanche. Jugée après son corps, pour qu'une erreur plus précise trouvée dedans (attribut
    /// d'essai, `cfg_select!`) soit dite la première.
    fn admise(&mut self, chemin: &[String], flux: &TokenStream) {
        if !admise(chemin) && (self.texte > 0 || un_texte(flux)) {
            self.erreur(&format!(
                "macro « {}! » autour d'un texte, hors de la liste blanche (MACROS_ADMISES, \
                 src/porte_mcp/sources.rs) : vérifier qu'elle ne choisit rien par cfg, puis l'ajouter à la liste",
                chemin.join("::")
            ));
        }
    }

    /// Les jetons d'une macro que syn ne relit pas comme du code : les chaînes des appels de texte qu'ils contiennent.
    /// Un attribut d'essai n'y aurait pas de portée connue : la compilation s'arrête.
    fn jetons(&mut self, flux: TokenStream) {
        let arbres: Vec<TokenTree> = flux.into_iter().collect();
        let mut i = 0;
        while let Some(arbre) = arbres.get(i) {
            let suivant = arbres.get(i + 1);
            match arbre {
                TokenTree::Punct(p) if p.as_char() == '#' => {
                    let crochets = match suivant {
                        Some(TokenTree::Punct(b)) if b.as_char() == '!' => arbres.get(i + 2),
                        autre => autre,
                    };
                    // Un attribut écrit par une métavariable (`#[$m]`, `# $a`, `$(#[$m])*`) n'est connu qu'à l'appel :
                    // `cfg(test)` y ferait un essai que la lecture prendrait pour du programme (7e passe,
                    // R7-SOURCES-2). Sans texte dans le corps, il n'y a rien à cacher : l'idiome qui passe la
                    // documentation d'un type (`$(#[$doc])*`) reste permis là.
                    let lu = match crochets {
                        Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Bracket && !un_dollar(&g.stream()) => {
                            syn::parse2::<Meta>(g.stream()).ok().map(|meta| (g, meta))
                        }
                        _ => None,
                    };
                    match lu {
                        Some((g, meta)) if !matches!(essai_par(std::iter::once(&meta), self.fonctionnalites), Ok(false)) => {
                            self.erreur(&format!(
                                "attribut d'essai (ou cfg illisible) « {} » dans le corps d'une macro que syn ne \
                                 relit pas comme du code",
                                g.stream()
                            ));
                        }
                        None if self.texte_au_corps => self.erreur(
                            "« # » sans attribut lisible (métavariable : « #[$m] », « # $a ») dans le corps d'une \
                             macro qui contient un texte : la lecture ne sait pas s'il en fait un essai, forme non jugée",
                        ),
                        _ => {}
                    }
                }
                TokenTree::Ident(ident) => {
                    let brut = ident.to_string();
                    let nom = sans_r(&brut).to_string();
                    if MACROS_DE_CFG.contains(&nom.as_str()) {
                        self.erreur(&format!(
                            "« {nom} » dans le corps d'une macro : bras choisis par cfg, forme non jugée"
                        ));
                    }
                    // Un mot qui lie un nom (`mod alloc { use jette as vec; }` ferait de `alloc::vec!` une macro
                    // inconnue sous un chemin admis) ou qui tire un fichier non lu (`include!`) : la lecture ne le
                    // suit pas dans des jetons, où une métavariable peut aussi donner le nom (7e passe,
                    // R7-SOURCES-3 ; 8e passe, R8-SOURCES-3 et 4).
                    if mot_qui_lie(ident) {
                        self.erreur(&format!(
                            "« {brut} » dans le corps d'une macro lu jeton par jeton : le nom qu'il donne (ou le \
                             fichier qu'il tire) n'est pas suivi, il pourrait cacher une macro ou un paquet admis, \
                             forme non jugée"
                        ));
                    }
                    if let (Some(TokenTree::Punct(b)), Some(TokenTree::Group(g))) = (suivant, arbres.get(i + 2))
                        && b.as_char() == '!'
                    {
                        let chemin = chemin_de(&arbres, i);
                        if appel_d_ailleurs(&chemin) {
                            self.erreur(&format!(
                                "« {}! » dans le corps d'une macro : un nom réservé (NOMS_RESERVES) appelé par le \
                                 chemin d'un autre paquet, forme non jugée",
                                chemin.join("::")
                            ));
                        }
                        if MACROS_D_ESSAIS.contains(&nom.as_str()) {
                            i += 3;
                            continue;
                        }
                        if MACROS_DE_TEXTE.contains(&nom.as_str()) {
                            self.texte += 1;
                            self.jetons(g.stream());
                            self.texte -= 1;
                            i += 3;
                            continue;
                        }
                        // Une autre macro appelée ici : lue comme un corps, puis jugée par la liste blanche.
                        let sans_texte = sans_texte(&chemin);
                        self.sans_texte += usize::from(sans_texte);
                        self.jetons(g.stream());
                        self.sans_texte -= usize::from(sans_texte);
                        self.admise(&chemin, &g.stream());
                        i += 3;
                        continue;
                    }
                }
                TokenTree::Group(g) => self.jetons(g.stream()),
                TokenTree::Literal(l) => {
                    if let Lit::Str(s) = Lit::new(l.clone()) {
                        self.chaine(&s.value());
                    }
                }
                TokenTree::Punct(_) => {}
            }
            i += 1;
        }
    }

    /// Une chaîne rencontrée : gardée seulement dans un appel de texte du programme. Un caractère de contrôle (« \n »,
    /// « \0 ») sépare deux mots.
    fn chaine(&mut self, valeur: &str) {
        if self.texte > 0 && self.sans_texte == 0 && self.mort == 0 && !self.essai {
            self.chaines
                .push(valeur.chars().map(|x| if x.is_control() { ' ' } else { x }).collect());
        }
    }

    /// Un `use` du programme : un nom admis n'est importé que sous son propre nom, du paquet même ou d'un paquet admis.
    /// Sinon `use autre::choix as format;` ferait passer une macro inconnue sous un nom de la liste blanche.
    fn importe(&mut self, chemin: &mut Vec<String>, arbre: &syn::UseTree) {
        // Le nom donné dans ce fichier, et le chemin complet de ce qu'il désigne.
        let juge = |l: &mut Self, chemin: &[String], nom: &syn::Ident, origine: &syn::Ident| {
            let mut chemin = chemin.to_vec();
            let mut nom = sans_r(&nom.to_string()).to_string();
            let mut origine = sans_r(&origine.to_string()).to_string();
            // `use m::alloc::{self};` donne le nom « alloc » : jugé par le dernier segment (8e passe, R8-SOURCES-4).
            if origine == "self"
                && let Some(dernier) = chemin.pop()
            {
                if nom == "self" {
                    nom.clone_from(&dernier);
                }
                origine = dernier;
            }
            let mut complet = chemin.clone();
            complet.push(origine.clone());
            // Le nom d'un paquet admis donné à autre chose (`use autre as std;`) : `std::format!` serait une macro
            // inconnue sous un chemin admis (7e passe, R7-SOURCES-3). Il reste donné au paquet même (`use
            // serde_json;`) ou à un module d'un paquet admis sous son propre nom (`use std::alloc;`), qui n'a pas
            // d'autre macro admise que celles du paquet (8e passe, R8-SOURCES-5).
            let d_un_admis = chemin.len() <= 1 && chemin.iter().all(|r| RACINES_ADMISES.contains(&r.as_str()));
            if RACINES_ADMISES.contains(&nom.as_str()) && !(d_un_admis && nom == origine) {
                l.erreur(&format!(
                    "« use {complet} » donne le nom d'un paquet admis (« {nom} ») à autre chose : il cacherait le \
                     paquet, forme non jugée ; importer sous un autre nom (« use {complet} as autre_nom; »)",
                    complet = complet.join("::")
                ));
            }
            // `include` renommé (`use std::include as i;`) tirerait un fichier sous un autre nom, sans être vu.
            if origine == "include" && nom != origine {
                l.erreur(&format!(
                    "« use {} as {nom} » renomme include! : le fichier qu'il tirerait ne serait pas lu, forme non \
                     jugée",
                    complet.join("::")
                ));
            }
            // Un nom réservé (macro de texte, admise, d'essais, écrite, attribut d'essai) n'est importé que sous son
            // propre nom, d'une origine permise : du programme même (`use crate::tr;`, `use super::json`, une
            // fonction ; une macro de ce nom y serait définie par un `macro_rules!`, refusé plus bas), d'un paquet
            // admis, ou de son paquet pour une macro d'essais (7e passe ; 9e passe, R9-SOURCES-2 et 3 :
            // `use m::jette as tr;`, `use m::chemin as concat;`).
            if reserve(&nom) {
                let racine = complet.first().map(String::as_str).unwrap_or_default();
                // Le message dit quoi faire : les deux formes qu'il propose sont lues (7e passe, R7-SOURCES-4).
                if nom != origine || complet.len() < 2 || !origine_permise(&nom, racine) {
                    l.erreur(&format!(
                        "« use {complet} » donne un nom réservé (« {nom} » : une macro que la lecture reconnaît par \
                         son nom, NOMS_RESERVES) à ce qui ne vient pas d'où la lecture l'attend (elle le prendrait \
                         pour le vrai) : écrire plutôt le chemin complet à l'appel (« {complet}(…) ») ou importer \
                         sous un autre nom (« use {complet} as autre_nom; »)",
                        complet = complet.join("::")
                    ));
                }
            }
        };
        match arbre {
            syn::UseTree::Path(p) => {
                chemin.push(sans_r(&p.ident.to_string()).to_string());
                self.importe(chemin, &p.tree);
                chemin.pop();
            }
            syn::UseTree::Name(n) => juge(self, chemin, &n.ident, &n.ident),
            syn::UseTree::Rename(r) => juge(self, chemin, &r.rename, &r.ident),
            syn::UseTree::Group(g) => {
                for arbre in &g.items {
                    self.importe(chemin, arbre);
                }
            }
            syn::UseTree::Glob(_) => {}
        }
    }

    /// Un module à fichier (`nom;`) : son fichier et le dossier de ses modules, comme rustc les cherche.
    fn declare(&mut self, nom: &str, chemin: Option<String>) {
        // Dans un bloc, rustc cherche le fichier depuis un dossier que la lecture ne suit pas (le nom du fichier
        // courant, puis les modules en ligne) : elle lirait le mauvais fichier, même en essai (4e re-contrôle,
        // SOURCES-3).
        if self.bloc > 0 {
            self.erreur(&format!(
                "module à fichier « {nom} » déclaré dans un bloc (fonction, const) : forme non jugée"
            ));
            return;
        }
        let (fichier, enfants) = if let Some(chemin) = chemin {
            // Hors module en ligne, relatif au dossier du fichier ; dedans, au dossier des modules en ligne. Le
            // fichier ainsi nommé cherche ses modules à côté de lui (comme un mod.rs).
            let base = if self.en_ligne == 0 {
                self.fichier.parent().unwrap_or(Path::new("")).to_path_buf()
            } else {
                self.enfants.clone()
            };
            let fichier = propre(&base.join(chemin));
            let enfants = fichier.parent().unwrap_or(Path::new("")).to_path_buf();
            (fichier, enfants)
        } else {
            let seul = propre(&self.enfants.join(format!("{nom}.rs")));
            let dossier = propre(&self.enfants.join(nom));
            let fichier = if self.textes.contains_key(&seul) {
                seul
            } else {
                dossier.join("mod.rs")
            };
            (fichier, dossier)
        };
        self.modules.push(Declare {
            fichier,
            enfants,
            essai: self.essai,
            par: format!("{} (module « {nom} »)", self.fichier.display()),
        });
    }
}

/// Vrai si cette macro (son chemin, dernier nom compris) est de la liste blanche : un nom admis, seul ou sous un
/// paquet admis.
fn admise(chemin: &[String]) -> bool {
    let nom = chemin.last().map(String::as_str).unwrap_or_default();
    MACROS_ADMISES.contains(&nom) && (chemin.len() == 1 || RACINES_ADMISES.contains(&chemin[0].as_str()))
}

/// Une macro admise dont les arguments ne sont pas des textes (`MACROS_SANS_TEXTE`) ?
fn sans_texte(chemin: &[String]) -> bool {
    admise(chemin)
        && chemin
            .last()
            .is_some_and(|nom| MACROS_SANS_TEXTE.contains(&nom.as_str()))
}

/// Un nom réservé (`NOMS_RESERVES`) ?
fn reserve(nom: &str) -> bool {
    NOMS_RESERVES.iter().any(|liste| liste.contains(&nom))
}

/// D'où un nom réservé peut venir quand il est appelé par un chemin (`std::format!`) ou importé (`use crate::tr;`) :
/// du programme même (`crate`, `self`, `super` : son nom y est jugé, définition comme import) ; d'un paquet admis
/// pour les macros admises, écrites et les attributs d'essais (`std::concat`) ; de son propre paquet pour une macro
/// d'essais (`proptest::proptest!`). Jamais d'ailleurs : la macro d'un autre paquet sous un nom réservé n'a pas été
/// jugée (9e passe, R9-SOURCES-2 et 3).
fn origine_permise(nom: &str, racine: &str) -> bool {
    let texte = MACROS_DE_TEXTE.contains(&nom);
    let essais = MACROS_D_ESSAIS.contains(&nom);
    ["crate", "self", "super"].contains(&racine)
        || !texte && !essais && RACINES_ADMISES.contains(&racine)
        || essais && racine == nom
}

/// Un appel par un chemin (`autre::tr!`) d'un nom réservé : vrai s'il ne vient pas d'une origine permise. Un chemin
/// absolu (`::std::format!`) nomme un paquet, jugé par son premier nom.
fn appel_d_ailleurs(chemin: &[String]) -> bool {
    let chemin: Vec<&str> = chemin.iter().map(String::as_str).filter(|s| *s != "::").collect();
    match chemin.as_slice() {
        [racine, .., nom] => reserve(nom) && !origine_permise(nom, racine),
        _ => false,
    }
}

/// Le chemin d'une macro appelée dans des jetons, nom compris (`a::b::c` pour `c!` au jeton `i`). Une métavariable
/// (`$m!`, `$m::format!`) n'y arrive pas près d'un texte : le corps est refusé avant (8e passe).
fn chemin_de(arbres: &[TokenTree], mut i: usize) -> Vec<String> {
    let nom = match arbres.get(i) {
        Some(TokenTree::Ident(nom)) => sans_r(&nom.to_string()).to_string(),
        _ => String::from("?"),
    };
    let mut chemin = vec![nom];
    while i >= 2
        && matches!(&arbres[i - 1], TokenTree::Punct(p) if p.as_char() == ':')
        && matches!(&arbres[i - 2], TokenTree::Punct(p) if p.as_char() == ':')
    {
        match arbres.get(i.wrapping_sub(3)) {
            Some(TokenTree::Ident(segment)) if i >= 3 => {
                chemin.insert(0, sans_r(&segment.to_string()).to_string());
                i -= 3;
            }
            // `::format!` : une racine qui n'est pas un paquet admis.
            _ => {
                chemin.insert(0, String::from("::"));
                return chemin;
            }
        }
    }
    chemin
}

/// Un mot qui lie un nom (`use`, `mod`, `extern`, `macro`, `macro_rules`) ou qui tire un fichier (`include`) : là où la
/// lecture ne relit pas le code (jetons, appel d'une macro maison qui peut les recombiner), elle ne suit pas le nom
/// qu'il donne. Un mot-clé l'est écrit tel quel (`r#mod` est un nom ordinaire) ; `macro_rules` et `include` sont des
/// noms, que `r#` ne change pas.
fn mot_qui_lie(ident: &proc_macro2::Ident) -> bool {
    let brut = ident.to_string();
    ["use", "mod", "extern", "macro"].contains(&brut.as_str()) || ["macro_rules", "include"].contains(&sans_r(&brut))
}

/// Le premier mot qui lie un nom dans ces jetons, à toute profondeur.
fn un_mot_qui_lie(flux: &TokenStream) -> Option<String> {
    flux.clone().into_iter().find_map(|arbre| match arbre {
        TokenTree::Ident(i) if mot_qui_lie(&i) => Some(i.to_string()),
        TokenTree::Group(g) => un_mot_qui_lie(&g.stream()),
        _ => None,
    })
}

/// La seule forme d'`include!` du programme (src/reseau/scan.rs) : un fichier écrit par build.rs dans OUT_DIR. Tout
/// autre fichier inclus ne serait pas lu par la lecture (8e passe, R8-SOURCES-4).
fn inclusion_connue(flux: &TokenStream) -> bool {
    let sans_blanc: String = flux.to_string().chars().filter(|x| !x.is_whitespace()).collect();
    sans_blanc == "concat!(env!(\"OUT_DIR\"),\"/fabricants.rs\")"
}

/// Ces jetons contiennent-ils un « $ » (une métavariable), à toute profondeur ?
fn un_dollar(flux: &TokenStream) -> bool {
    flux.clone().into_iter().any(|arbre| match arbre {
        TokenTree::Punct(p) => p.as_char() == '$',
        TokenTree::Group(g) => un_dollar(&g.stream()),
        _ => false,
    })
}

/// Un identifiant sans son préfixe brut : rustc lit `r#test` comme `test` (3e re-contrôle).
fn sans_r(nom: &str) -> &str {
    nom.strip_prefix("r#").unwrap_or(nom)
}

/// Le chemin est-il le seul identifiant `nom`, brut ou non (`cfg`, `r#cfg`) ?
fn est(chemin: &syn::Path, nom: &str) -> bool {
    chemin.leading_colon.is_none()
        && chemin.segments.len() == 1
        && chemin
            .segments
            .first()
            .is_some_and(|s| s.arguments.is_none() && sans_r(&s.ident.to_string()) == nom)
}

/// L'attribut est-il `nom`, seul ou posé par un `cfg_attr` à n'importe quelle profondeur ? Dans le doute (le mot
/// qui serait autre chose dans un `cfg_attr`), oui.
fn nomme(meta: &Meta, nom: &str) -> bool {
    fn dedans(flux: TokenStream, nom: &str) -> bool {
        flux.into_iter().any(|arbre| match arbre {
            TokenTree::Ident(i) => sans_r(&i.to_string()) == nom,
            TokenTree::Group(g) => dedans(g.stream(), nom),
            _ => false,
        })
    }
    meta.path()
        .segments
        .last()
        .is_some_and(|s| sans_r(&s.ident.to_string()) == nom)
        || matches!(meta, Meta::List(liste) if est(&liste.path, "cfg_attr") && dedans(liste.tokens.clone(), nom))
}

/// L'attribut dit-il l'élément mort : `allow(…dead_code…)` ou `expect(…dead_code…)`, seul ou posé par un `cfg_attr` à
/// n'importe quelle profondeur ? Un `cfg_attr` dont la condition est fausse dans le programme (`test`) ne pose rien :
/// l'élément y est vivant (rustc l'y dirait mort sinon). Dans le doute (condition inconnue, illisible), oui : un mot de
/// moins.
fn dit_mort(meta: &Meta, fonctionnalites: &BTreeSet<String>) -> bool {
    fn nomme_dead_code(flux: TokenStream) -> bool {
        flux.into_iter().any(|arbre| match arbre {
            TokenTree::Ident(i) => sans_r(&i.to_string()) == "dead_code",
            TokenTree::Group(g) => nomme_dead_code(g.stream()),
            _ => false,
        })
    }
    match meta {
        Meta::List(liste) if est(&liste.path, "allow") || est(&liste.path, "expect") => {
            nomme_dead_code(liste.tokens.clone())
        }
        Meta::List(liste) if est(&liste.path, "cfg_attr") => {
            let mut condition = TokenStream::new();
            let mut reste = TokenStream::new();
            let mut apres = false;
            for arbre in liste.tokens.clone() {
                match &arbre {
                    TokenTree::Punct(p) if p.as_char() == ',' && !apres => apres = true,
                    _ if apres => reste.extend([arbre]),
                    _ => condition.extend([arbre]),
                }
            }
            !matches!(un_seul(condition, fonctionnalites), Ok(Tri::Faux)) && nomme_dead_code(reste)
        }
        _ => false,
    }
}

/// L'attribut est-il un `cfg_attr` qui nomme `path`, à n'importe quelle profondeur (`cfg_attr(a, cfg_attr(b, path =
/// "…"))`) ? Dans le doute (un `path` qui serait autre chose), il est refusé.
fn path_par_cfg_attr(attribut: &Attribute) -> bool {
    fn nomme_path(flux: TokenStream) -> bool {
        flux.into_iter().any(|arbre| match arbre {
            TokenTree::Ident(i) => sans_r(&i.to_string()) == "path",
            TokenTree::Group(g) => nomme_path(g.stream()),
            _ => false,
        })
    }
    match &attribut.meta {
        Meta::List(liste) if est(&liste.path, "cfg_attr") => nomme_path(liste.tokens.clone()),
        _ => false,
    }
}

/// Le chemin d'un attribut `path = "…"`, s'il y en a un.
fn chemin_d_attribut(attributs: &[Attribute]) -> Option<String> {
    attributs.iter().find_map(|a| match &a.meta {
        Meta::NameValue(nv) if est(&nv.path, "path") => match &nv.value {
            Expr::Lit(l) => match &l.lit {
                Lit::Str(s) => Some(s.value()),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    })
}

/// Ces attributs font-ils du nœud un essai ? Une erreur pour un `cfg` que la lecture ne sait pas juger.
fn essai_par<'m>(
    attributs: impl Iterator<Item = &'m Meta>,
    fonctionnalites: &BTreeSet<String>,
) -> Result<bool, Illisible> {
    for meta in attributs {
        let chemin = meta.path();
        // Un seul segment : `#[rust_analyzer::test]` finit par « test », mais rustc garde l'élément (9e passe,
        // R9-SOURCES-1). Le nom seul ne peut pas être repris : `test` et `bench` sont réservés (`NOMS_RESERVES`).
        if ATTRIBUTS_D_ESSAIS.iter().any(|nom| est(chemin, nom)) {
            return Ok(true);
        }
        if est(chemin, "cfg") {
            let Meta::List(liste) = meta else {
                return Err(Illisible(String::from("cfg sans parenthèses")));
            };
            if un_seul(liste.tokens.clone(), fonctionnalites)? == Tri::Faux {
                return Ok(true);
            }
        } else if est(chemin, "cfg_attr") {
            let Meta::List(liste) = meta else {
                return Err(Illisible(String::from("cfg_attr sans parenthèses")));
            };
            if cfg_attr_essai(liste.tokens.clone(), fonctionnalites)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// `cfg_attr(condition, attr, …)` : un essai si la condition est toujours vraie et qu'un des attributs en fait un.
/// Sous une condition inconnue (`cfg_attr(unix, test)`), l'élément reste au programme d'une autre cible : il en est
/// (9e passe, comme `cfg(any(unix, test))`).
fn cfg_attr_essai(flux: TokenStream, fonctionnalites: &BTreeSet<String>) -> Result<bool, Illisible> {
    let mut condition = TokenStream::new();
    let mut reste = TokenStream::new();
    let mut apres = false;
    for arbre in flux {
        match &arbre {
            TokenTree::Punct(p) if p.as_char() == ',' && !apres => apres = true,
            _ if apres => reste.extend([arbre]),
            _ => condition.extend([arbre]),
        }
    }
    if un_seul(condition, fonctionnalites)? != Tri::Vrai {
        return Ok(false);
    }
    let attributs = Punctuated::<Meta, Token![,]>::parse_terminated
        .parse2(reste)
        .map_err(|e| Illisible(format!("cfg_attr illisible : {e}")))?;
    essai_par(attributs.iter(), fonctionnalites)
}

/// La valeur d'un `cfg` dans le programme (`test` et `kani` faux, le reste inconnu).
#[derive(Clone, Copy, Debug, PartialEq)]
enum Tri {
    Vrai,
    Faux,
    Inconnu,
}

/// Exactement une condition (virgule finale permise), comme dans `cfg(…)` et `not(…)`.
fn un_seul(flux: TokenStream, fonctionnalites: &BTreeSet<String>) -> Result<Tri, Illisible> {
    let texte = flux.to_string();
    let conditions = conditions(flux, fonctionnalites)?;
    match conditions.as_slice() {
        [une] => Ok(*une),
        _ => Err(Illisible(format!(
            "cfg qui n'a pas exactement une condition : « {texte} »"
        ))),
    }
}

/// Les conditions d'une liste (`a, all(b, c), feature = "x"`), chacune jugée.
fn conditions(flux: TokenStream, fonctionnalites: &BTreeSet<String>) -> Result<Vec<Tri>, Illisible> {
    let texte = flux.to_string();
    let illisible = || Illisible(format!("cfg illisible : « {texte} »"));
    let mut sortie = Vec::new();
    let mut arbres = flux.into_iter().peekable();
    while let Some(arbre) = arbres.next() {
        let TokenTree::Ident(nom) = arbre else {
            return Err(illisible());
        };
        let nom = sans_r(&nom.to_string()).to_string();
        let valeur = match arbres.peek() {
            Some(TokenTree::Punct(p)) if p.as_char() == '=' => {
                arbres.next();
                let Some(TokenTree::Literal(litteral)) = arbres.next() else {
                    return Err(illisible());
                };
                // `feature = "x"` : vrai si et seulement si cette compilation a la fonctionnalité (rustc la reçoit
                // ainsi, `--cfg feature="x"`) ; toute autre clé (`target_os`…) reste inconnue.
                match Lit::new(litteral) {
                    Lit::Str(s) if nom == "feature" => {
                        if fonctionnalites.contains(&s.value()) {
                            Tri::Vrai
                        } else {
                            Tri::Faux
                        }
                    }
                    _ => Tri::Inconnu,
                }
            }
            Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Parenthesis => {
                let dedans = g.stream();
                arbres.next();
                match nom.as_str() {
                    "all" => conditions(dedans, fonctionnalites)?.into_iter().fold(Tri::Vrai, et),
                    "any" => conditions(dedans, fonctionnalites)?.into_iter().fold(Tri::Faux, ou),
                    "not" => non(un_seul(dedans, fonctionnalites)?),
                    _ => return Err(illisible()),
                }
            }
            _ => match nom.as_str() {
                "true" => Tri::Vrai,
                "false" => Tri::Faux,
                n if CFG_FAUX.contains(&n) => Tri::Faux,
                _ => Tri::Inconnu,
            },
        };
        sortie.push(valeur);
        match arbres.next() {
            None => break,
            Some(TokenTree::Punct(p)) if p.as_char() == ',' => {}
            Some(_) => return Err(illisible()),
        }
    }
    Ok(sortie)
}

fn et(a: Tri, b: Tri) -> Tri {
    match (a, b) {
        (Tri::Faux, _) | (_, Tri::Faux) => Tri::Faux,
        (Tri::Vrai, Tri::Vrai) => Tri::Vrai,
        _ => Tri::Inconnu,
    }
}

fn ou(a: Tri, b: Tri) -> Tri {
    match (a, b) {
        (Tri::Vrai, _) | (_, Tri::Vrai) => Tri::Vrai,
        (Tri::Faux, Tri::Faux) => Tri::Faux,
        _ => Tri::Inconnu,
    }
}

fn non(a: Tri) -> Tri {
    match a {
        Tri::Vrai => Tri::Faux,
        Tri::Faux => Tri::Vrai,
        Tri::Inconnu => Tri::Inconnu,
    }
}

/// Les attributs d'une expression ; `None` pour une forme que syn garde sans la comprendre.
fn attributs_expr(e: &Expr) -> Option<&[Attribute]> {
    Some(match e {
        Expr::Array(x) => &x.attrs,
        Expr::Assign(x) => &x.attrs,
        Expr::Async(x) => &x.attrs,
        Expr::Await(x) => &x.attrs,
        Expr::Binary(x) => &x.attrs,
        Expr::Block(x) => &x.attrs,
        Expr::Break(x) => &x.attrs,
        Expr::Call(x) => &x.attrs,
        Expr::Cast(x) => &x.attrs,
        Expr::Closure(x) => &x.attrs,
        Expr::Const(x) => &x.attrs,
        Expr::Continue(x) => &x.attrs,
        Expr::Field(x) => &x.attrs,
        Expr::ForLoop(x) => &x.attrs,
        Expr::Group(x) => &x.attrs,
        Expr::If(x) => &x.attrs,
        Expr::Index(x) => &x.attrs,
        Expr::Infer(x) => &x.attrs,
        Expr::Let(x) => &x.attrs,
        Expr::Lit(x) => &x.attrs,
        Expr::Loop(x) => &x.attrs,
        Expr::Macro(x) => &x.attrs,
        Expr::Match(x) => &x.attrs,
        Expr::MethodCall(x) => &x.attrs,
        Expr::Paren(x) => &x.attrs,
        Expr::Path(x) => &x.attrs,
        Expr::Range(x) => &x.attrs,
        Expr::RawAddr(x) => &x.attrs,
        Expr::Reference(x) => &x.attrs,
        Expr::Repeat(x) => &x.attrs,
        Expr::Return(x) => &x.attrs,
        Expr::Struct(x) => &x.attrs,
        Expr::Try(x) => &x.attrs,
        Expr::TryBlock(x) => &x.attrs,
        Expr::Tuple(x) => &x.attrs,
        Expr::Unary(x) => &x.attrs,
        Expr::Unsafe(x) => &x.attrs,
        Expr::While(x) => &x.attrs,
        Expr::Yield(x) => &x.attrs,
        _ => return None,
    })
}

fn attributs_motif(p: &Pat) -> Option<&[Attribute]> {
    Some(match p {
        Pat::Const(x) => &x.attrs,
        Pat::Guard(x) => &x.attrs,
        Pat::Ident(x) => &x.attrs,
        Pat::Lit(x) => &x.attrs,
        Pat::Macro(x) => &x.attrs,
        Pat::Or(x) => &x.attrs,
        Pat::Paren(x) => &x.attrs,
        Pat::Path(x) => &x.attrs,
        Pat::Range(x) => &x.attrs,
        Pat::Reference(x) => &x.attrs,
        Pat::Rest(x) => &x.attrs,
        Pat::Slice(x) => &x.attrs,
        Pat::Struct(x) => &x.attrs,
        Pat::Tuple(x) => &x.attrs,
        Pat::TupleStruct(x) => &x.attrs,
        Pat::Type(x) => &x.attrs,
        Pat::Wild(x) => &x.attrs,
        _ => return None,
    })
}

fn attributs_type(t: &Type) -> Option<&[Attribute]> {
    Some(match t {
        Type::Array(x) => &x.attrs,
        Type::FnPtr(x) => &x.attrs,
        Type::Group(x) => &x.attrs,
        Type::ImplTrait(x) => &x.attrs,
        Type::Infer(x) => &x.attrs,
        Type::Macro(x) => &x.attrs,
        Type::Never(x) => &x.attrs,
        Type::Paren(x) => &x.attrs,
        Type::Path(x) => &x.attrs,
        Type::Ptr(x) => &x.attrs,
        Type::Reference(x) => &x.attrs,
        Type::Slice(x) => &x.attrs,
        Type::TraitObject(x) => &x.attrs,
        Type::Tuple(x) => &x.attrs,
        _ => return None,
    })
}

fn attributs_element(i: &Item) -> Option<&[Attribute]> {
    Some(match i {
        Item::Const(x) => &x.attrs,
        Item::Enum(x) => &x.attrs,
        Item::ExternCrate(x) => &x.attrs,
        Item::Fn(x) => &x.attrs,
        Item::ForeignMod(x) => &x.attrs,
        Item::Impl(x) => &x.attrs,
        Item::Macro(x) => &x.attrs,
        Item::Mod(x) => &x.attrs,
        Item::Static(x) => &x.attrs,
        Item::Struct(x) => &x.attrs,
        Item::Trait(x) => &x.attrs,
        Item::TraitAlias(x) => &x.attrs,
        Item::Type(x) => &x.attrs,
        Item::Union(x) => &x.attrs,
        Item::Use(x) => &x.attrs,
        _ => return None,
    })
}

fn attributs_impl(i: &ImplItem) -> Option<&[Attribute]> {
    Some(match i {
        ImplItem::Const(x) => &x.attrs,
        ImplItem::Fn(x) => &x.attrs,
        ImplItem::Type(x) => &x.attrs,
        ImplItem::Macro(x) => &x.attrs,
        _ => return None,
    })
}

fn attributs_trait(i: &TraitItem) -> Option<&[Attribute]> {
    Some(match i {
        TraitItem::Const(x) => &x.attrs,
        TraitItem::Fn(x) => &x.attrs,
        TraitItem::Type(x) => &x.attrs,
        TraitItem::Macro(x) => &x.attrs,
        _ => return None,
    })
}

fn attributs_etranger(i: &ForeignItem) -> Option<&[Attribute]> {
    Some(match i {
        ForeignItem::Fn(x) => &x.attrs,
        ForeignItem::Static(x) => &x.attrs,
        ForeignItem::Type(x) => &x.attrs,
        ForeignItem::Macro(x) => &x.attrs,
        _ => return None,
    })
}

/// Chaque nœud qui peut porter un attribut passe par `sous` : un essai l'est avec tout ce qu'il contient. Une forme
/// que syn garde sans la comprendre arrête la compilation.
impl<'ast> Visit<'ast> for Lecteur<'_> {
    fn visit_item(&mut self, i: &'ast Item) {
        match attributs_element(i) {
            Some(a) => self.sous(a, |l| visit::visit_item(l, i)),
            None => self.erreur("élément que syn ne comprend pas (Verbatim)"),
        }
    }

    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        let nom = sans_r(&m.ident.to_string()).to_string();
        // Un module au nom d'un paquet admis le cache : `alloc::vec!` serait la macro qu'il contient, inconnue (7e
        // passe, R7-SOURCES-3).
        if !self.essai && RACINES_ADMISES.contains(&nom.as_str()) {
            self.erreur(&format!(
                "module « {nom} » au nom d'un paquet admis : il cacherait le paquet, forme non jugée"
            ));
        }
        // Un `path` posé par `cfg_attr` changerait le fichier selon la condition : la lecture ne le suit pas (4e
        // re-contrôle, SOURCES-2).
        if m.attrs.iter().any(path_par_cfg_attr) {
            self.erreur(&format!(
                "path posé par cfg_attr sur le module « {nom} » : forme non jugée"
            ));
        }
        let chemin = chemin_d_attribut(&m.attrs);
        match &m.content {
            None => self.declare(&nom, chemin),
            Some((_, elements)) => {
                let avant = self.enfants.clone();
                // Comme rustc (3e re-contrôle) : un `#[path]` sur un module en ligne qui n'est dans aucun autre est
                // relatif au dossier du fichier, même hors mod.rs ; dedans, au dossier des modules en ligne.
                self.enfants = match chemin {
                    Some(chemin) if self.en_ligne == 0 => {
                        propre(&self.fichier.parent().unwrap_or(Path::new("")).join(chemin))
                    }
                    Some(chemin) => propre(&self.enfants.join(chemin)),
                    None => propre(&self.enfants.join(nom)),
                };
                self.en_ligne += 1;
                for element in elements {
                    self.visit_item(element);
                }
                self.en_ligne -= 1;
                self.enfants = avant;
            }
        }
    }

    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        let avant = self.impl_de.take();
        self.impl_de = match &*i.self_ty {
            Type::Path(t) => t.path.segments.last().map(|s| sans_r(&s.ident.to_string()).to_string()),
            _ => None,
        };
        visit::visit_item_impl(self, i);
        self.impl_de = avant;
    }

    fn visit_item_fn(&mut self, i: &'ast syn::ItemFn) {
        let mort = self.texte_mort(sans_r(&i.sig.ident.to_string()));
        self.mort += usize::from(mort);
        visit::visit_item_fn(self, i);
        self.mort -= usize::from(mort);
    }

    fn visit_impl_item_fn(&mut self, i: &'ast syn::ImplItemFn) {
        let nom = sans_r(&i.sig.ident.to_string()).to_string();
        let mort = match &self.impl_de {
            Some(type_) => self.texte_mort(&format!("{type_}::{nom}")),
            None => false,
        };
        self.mort += usize::from(mort);
        visit::visit_impl_item_fn(self, i);
        self.mort -= usize::from(mort);
    }

    fn visit_impl_item(&mut self, i: &'ast ImplItem) {
        match attributs_impl(i) {
            Some(a) => self.sous(a, |l| visit::visit_impl_item(l, i)),
            None => self.erreur("élément d'impl que syn ne comprend pas (Verbatim)"),
        }
    }

    fn visit_trait_item(&mut self, i: &'ast TraitItem) {
        match attributs_trait(i) {
            Some(a) => self.sous(a, |l| visit::visit_trait_item(l, i)),
            None => self.erreur("élément de trait que syn ne comprend pas (Verbatim)"),
        }
    }

    fn visit_foreign_item(&mut self, i: &'ast ForeignItem) {
        match attributs_etranger(i) {
            Some(a) => self.sous(a, |l| visit::visit_foreign_item(l, i)),
            None => self.erreur("élément extern que syn ne comprend pas (Verbatim)"),
        }
    }

    fn visit_expr(&mut self, e: &'ast Expr) {
        match attributs_expr(e) {
            Some(a) => self.sous(a, |l| visit::visit_expr(l, e)),
            None => self.erreur("expression que syn ne comprend pas (Verbatim)"),
        }
    }

    fn visit_pat(&mut self, p: &'ast Pat) {
        match attributs_motif(p) {
            Some(a) => self.sous(a, |l| visit::visit_pat(l, p)),
            None => self.erreur("motif que syn ne comprend pas (Verbatim)"),
        }
    }

    // Une instruction n'a pas d'attributs à elle : ce sont ceux de son élément, de son `let`, de son expression ou de
    // sa macro, chacun jugé ci-dessous.
    fn visit_local(&mut self, i: &'ast syn::Local) {
        self.sous(&i.attrs, |l| visit::visit_local(l, i));
    }

    fn visit_stmt_macro(&mut self, i: &'ast syn::StmtMacro) {
        self.sous(&i.attrs, |l| visit::visit_stmt_macro(l, i));
    }

    fn visit_field(&mut self, i: &'ast syn::Field) {
        self.sous(&i.attrs, |l| visit::visit_field(l, i));
    }

    fn visit_variant(&mut self, i: &'ast syn::Variant) {
        self.sous(&i.attrs, |l| visit::visit_variant(l, i));
    }

    fn visit_arm(&mut self, i: &'ast syn::Arm) {
        self.sous(&i.attrs, |l| visit::visit_arm(l, i));
    }

    fn visit_field_value(&mut self, i: &'ast syn::FieldValue) {
        self.sous(&i.attrs, |l| visit::visit_field_value(l, i));
    }

    fn visit_field_pat(&mut self, i: &'ast syn::FieldPat) {
        self.sous(&i.attrs, |l| visit::visit_field_pat(l, i));
    }

    fn visit_pat_type(&mut self, i: &'ast syn::PatType) {
        self.sous(&i.attrs, |l| visit::visit_pat_type(l, i));
    }

    fn visit_receiver(&mut self, i: &'ast syn::Receiver) {
        self.sous(&i.attrs, |l| visit::visit_receiver(l, i));
    }

    fn visit_variadic(&mut self, i: &'ast syn::Variadic) {
        self.sous(&i.attrs, |l| visit::visit_variadic(l, i));
    }

    fn visit_named_arg(&mut self, i: &'ast syn::NamedArg) {
        self.sous(&i.attrs, |l| visit::visit_named_arg(l, i));
    }

    fn visit_fn_ptr_variadic(&mut self, i: &'ast syn::FnPtrVariadic) {
        self.sous(&i.attrs, |l| visit::visit_fn_ptr_variadic(l, i));
    }

    fn visit_predicate_lifetime(&mut self, i: &'ast syn::PredicateLifetime) {
        self.sous(&i.attrs, |l| visit::visit_predicate_lifetime(l, i));
    }

    fn visit_predicate_type(&mut self, i: &'ast syn::PredicateType) {
        self.sous(&i.attrs, |l| visit::visit_predicate_type(l, i));
    }

    fn visit_type(&mut self, t: &'ast Type) {
        match attributs_type(t) {
            Some(a) => self.sous(a, |l| visit::visit_type(l, t)),
            None => self.erreur("type que syn ne comprend pas (Verbatim)"),
        }
    }

    fn visit_type_param(&mut self, i: &'ast syn::TypeParam) {
        self.sous(&i.attrs, |l| visit::visit_type_param(l, i));
    }

    fn visit_lifetime_param(&mut self, i: &'ast syn::LifetimeParam) {
        self.sous(&i.attrs, |l| visit::visit_lifetime_param(l, i));
    }

    fn visit_const_param(&mut self, i: &'ast syn::ConstParam) {
        self.sous(&i.attrs, |l| visit::visit_const_param(l, i));
    }

    /// `if cfg!(test) { … }` : rustc compile les deux branches, mais celle qu'une condition fixe écarte n'est jamais
    /// exécutée, et l'optimisation la retire du programme publié ; ses textes ne vont pas au vocabulaire (le sens sûr),
    /// ses règles restent jugées (le code est compilé).
    fn visit_expr_if(&mut self, i: &'ast syn::ExprIf) {
        for attribut in &i.attrs {
            self.visit_attribute(attribut);
        }
        let valeur = self.valeur_de_cfg(&i.cond);
        self.visit_expr(&i.cond);
        let alors = valeur == Tri::Faux;
        self.mort += usize::from(alors);
        self.visit_block(&i.then_branch);
        self.mort -= usize::from(alors);
        if let Some((_, sinon)) = &i.else_branch {
            let sinon_mort = valeur == Tri::Vrai;
            self.mort += usize::from(sinon_mort);
            self.visit_expr(sinon);
            self.mort -= usize::from(sinon_mort);
        }
    }

    fn visit_block(&mut self, b: &'ast syn::Block) {
        self.bloc += 1;
        visit::visit_block(self, b);
        self.bloc -= 1;
    }

    fn visit_ident(&mut self, i: &'ast proc_macro2::Ident) {
        let nom = i.to_string();
        if MACROS_DE_CFG.contains(&sans_r(&nom)) {
            self.erreur(&format!("« {nom} » : bras choisis par cfg, forme non jugée"));
        }
    }

    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        // Avant le retour des essais : le nom de la macro n'est pas visité ailleurs.
        for segment in &m.path.segments {
            self.visit_ident(&segment.ident);
        }
        if self.essai {
            return;
        }
        let nom = m.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
        let nom = sans_r(&nom);
        let chemin: Vec<String> = m
            .path
            .segments
            .iter()
            .map(|s| sans_r(&s.ident.to_string()).to_string())
            .collect();
        // Un nom réservé appelé par le chemin d'un autre paquet (`autre::tr!`, `autre::include!`) : une macro que
        // personne n'a jugée, prise pour la vraie par son nom (9e passe, R9-SOURCES-2 et 3).
        if appel_d_ailleurs(&chemin) {
            self.erreur(&format!(
                "« {}! » : un nom réservé (NOMS_RESERVES) appelé par le chemin d'un autre paquet, la lecture le \
                 prendrait pour le vrai, forme non jugée",
                chemin.join("::")
            ));
        }
        if MACROS_D_ESSAIS.contains(&nom) {
            return;
        }
        let texte = MACROS_DE_TEXTE.contains(&nom);
        // Un fichier inclus n'est pas lu : seule la forme connue (OUT_DIR, écrit par build.rs) passe.
        if nom == "include" && !inclusion_connue(&m.tokens) {
            self.erreur(&format!(
                "« include!({}) » : le fichier inclus n'est pas lu (il pourrait poser un module ou une macro au nom \
                 d'un admis), forme non jugée ; seule la forme connue (OUT_DIR, src/reseau/scan.rs) passe",
                m.tokens
            ));
        }
        // Une macro maison peut recombiner ce qu'on lui passe : `pose!(mod x {} use y;)` se lit comme deux éléments
        // permis, mais la macro peut en faire `mod alloc { use jette as vec; }` (8e passe, R8-SOURCES-3). Hors de la
        // liste blanche (qui ne recombine rien), aucun mot qui lie un nom dans ses arguments.
        if !texte
            && !admise(&chemin)
            && let Some(mot) = un_mot_qui_lie(&m.tokens)
        {
            self.erreur(&format!(
                "« {mot} » dans l'appel de la macro « {}! », hors de la liste blanche : elle pourrait le recombiner \
                 avec un autre nom (un module ou une macro au nom d'un admis), forme non jugée",
                chemin.join("::")
            ));
        }
        if texte {
            self.texte += 1;
        }
        let sans_texte = sans_texte(&chemin);
        self.sans_texte += usize::from(sans_texte);
        self.corps(&m.tokens);
        self.sans_texte -= usize::from(sans_texte);
        if texte {
            self.texte -= 1;
        } else {
            self.admise(&chemin, &m.tokens);
        }
    }

    fn visit_item_macro(&mut self, i: &'ast syn::ItemMacro) {
        // Une macro du programme sous un nom réservé cacherait la vraie : une macro admise passerait la liste blanche
        // sans avoir été jugée, un `tr` maison qui jette ses arguments les ferait lire comme du texte, un `concat`
        // maison tromperait `inclusion_connue` (9e passe, R9-SOURCES-2 et 3). Seules les vraies macros de texte, au
        // premier niveau de leur fichier, sont définies sous leur nom.
        if let Some(nom) = &i.ident
            && !self.essai
        {
            let nom = sans_r(&nom.to_string()).to_string();
            let vraie = MACROS_DE_TEXTE.contains(&nom.as_str())
                && self.fichier == Path::new(DEFINITIONS_DE_TEXTE)
                && self.en_ligne == 0
                && self.bloc == 0;
            if reserve(&nom) && !vraie {
                self.erreur(&format!(
                    "macro « {nom}! » définie sous un nom réservé (NOMS_RESERVES : une macro que la lecture \
                     reconnaît par son nom ; les macros de texte, seulement au premier niveau de \
                     {DEFINITIONS_DE_TEXTE}) : forme non jugée"
                ));
            }
        }
        visit::visit_item_macro(self, i);
    }

    fn visit_item_extern_crate(&mut self, i: &'ast syn::ItemExternCrate) {
        // `extern crate autre as std;` cacherait le paquet admis, comme un `use` (7e passe, R7-SOURCES-3).
        let paquet = sans_r(&i.ident.to_string()).to_string();
        if let Some((_, nom)) = &i.rename {
            let nom = sans_r(&nom.to_string()).to_string();
            if !self.essai && nom != paquet && RACINES_ADMISES.contains(&nom.as_str()) {
                self.erreur(&format!(
                    "« extern crate {paquet} as {nom} » donne le nom d'un paquet admis à un autre : forme non jugée"
                ));
            }
        }
        visit::visit_item_extern_crate(self, i);
    }

    fn visit_item_use(&mut self, i: &'ast syn::ItemUse) {
        if !self.essai {
            self.importe(&mut Vec::new(), &i.tree);
        }
        visit::visit_item_use(self, i);
    }

    fn visit_lit_str(&mut self, s: &'ast syn::LitStr) {
        self.chaine(&s.value());
    }
}

/// Vrai si ces jetons appellent une macro de texte, à toute profondeur (hors des macros d'essais).
fn un_texte(flux: &TokenStream) -> bool {
    let arbres: Vec<TokenTree> = flux.clone().into_iter().collect();
    let mut i = 0;
    while let Some(arbre) = arbres.get(i) {
        match arbre {
            TokenTree::Ident(nom) if matches!(arbres.get(i + 1), Some(TokenTree::Punct(b)) if b.as_char() == '!') => {
                let nom = nom.to_string();
                if MACROS_DE_TEXTE.contains(&sans_r(&nom)) {
                    return true;
                }
                if MACROS_D_ESSAIS.contains(&sans_r(&nom)) {
                    i += 3;
                    continue;
                }
            }
            TokenTree::Group(g) if un_texte(&g.stream()) => return true,
            _ => {}
        }
        i += 1;
    }
    false
}

/// La chaîne sans ses marques de format : « {} », « {nom} », « {:?} » deviennent une espace (« {{ » et « }} » aussi).
fn sans_marques(chaine: &str) -> String {
    let mut sortie = String::with_capacity(chaine.len());
    let mut dans = false;
    for x in chaine.chars() {
        match x {
            '{' => {
                dans = !dans;
                sortie.push(' ');
            }
            '}' => {
                dans = false;
                sortie.push(' ');
            }
            x if !dans => sortie.push(x),
            _ => {}
        }
    }
    sortie
}

#[cfg(test)]
mod tests;

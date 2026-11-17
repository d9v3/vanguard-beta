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
//! motif…) qui porte un attribut `test`, `bench` (`#[tokio::test]` compris), ou un `cfg` faux quand `test` (et `kani`,
//! les preuves de outils/preuves/) sont faux : `cfg(test)`, `cfg(all(…, test))` à toute profondeur, `cfg(test,)`,
//! `cfg(any())`, `cfg(false)`, et un `cfg_attr(…, cfg(test))`. `cfg(any(unix, test))` et `cfg(not(test))` restent du
//! programme. Un module d'essais n'est lu que pour suivre ses propres modules, comme essais eux aussi. Un appel
//! `proptest!` ou `quickcheck!` est un essai.
//!
//! Ne sont lues que les chaînes des appels aux macros de texte (tr!, trf!, trp!, tre!, trw!, trwln!, trpr!, comme
//! outils/textes.py), à toute profondeur dans leurs arguments ; jamais un commentaire ni une documentation (syn ne
//! les garde pas comme du code). Le corps d'une macro est relu comme une liste d'expressions ou d'instructions ; s'il
//! n'en est pas une (`macro_rules!`, `matches!`), ses jetons sont parcourus pour trouver les appels de texte.
//!
//! Rien n'est ignoré en silence, la compilation s'arrête : un fichier que syn ne sait pas lire, une forme qu'il garde
//! sans la comprendre (`Verbatim`), un `cfg` mal écrit, un module du programme sans fichier, un attribut d'essai dans
//! le corps d'une macro qui n'est pas relu comme du code, un fichier .rs de la liste qu'aucun module ne déclare.

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
/// Les attributs qui font d'une fonction un essai (dernier nom du chemin : `test`, `tokio::test`).
const ATTRIBUTS_D_ESSAIS: [&str; 2] = ["test", "bench"];
/// Les `cfg` faux dans le programme : ses essais, et les preuves de Kani (outils/preuves.sh).
const CFG_FAUX: [&str; 2] = ["test", "kani"];

/// Une forme que la lecture ne sait pas juger, avec ce qu'elle a vu : build.rs arrête la compilation sur elle. Un type
/// à part plutôt que `Echec` du programme, que build.rs ne peut pas atteindre.
#[derive(Debug)]
pub struct Illisible(pub String);

/// Le vocabulaire de ces sources (chemin et texte de chaque fichier), trié et sans doublon ; une erreur (qui arrête
/// la compilation) pour toute forme que la lecture ne sait pas juger.
pub fn vocabulaire(sources: &[(PathBuf, String)]) -> Result<BTreeSet<String>, Illisible> {
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
    while let Some(module) = a_lire.pop() {
        match lus.get(&module.fichier) {
            Some(true) => continue,
            Some(false) if module.essai => continue,
            _ => {}
        }
        if !module.fichier.starts_with("src") {
            // Un fichier hors de src/ (le modèle des couleurs partagé avec fenetre/) : ses mots ne sont pas
            // retenus. Le sens sûr : un mot de moins dans la liste blanche est masqué, jamais laissé en clair.
            continue;
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
            fichier: &module.fichier,
            enfants: module.enfants,
            en_ligne: 0,
            essai: module.essai,
            texte: 0,
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
    fichier: &'a Path,
    /// Le dossier des modules à fichier déclarés au niveau courant.
    enfants: PathBuf,
    /// La profondeur des modules écrits en ligne (`mod a { … }`) autour du nœud courant.
    en_ligne: usize,
    /// Le nœud courant n'existe qu'aux essais.
    essai: bool,
    /// La profondeur des appels aux macros de texte autour du nœud courant.
    texte: usize,
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
        match essai_par(attributs.iter().map(|a| &a.meta)) {
            Ok(true) => self.essai = true,
            Ok(false) => {}
            Err(Illisible(e)) => self.erreur(&e),
        }
        suite(self);
        self.essai = avant;
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
            self.jetons(flux.clone());
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
                    if let Some(TokenTree::Group(g)) = crochets
                        && g.delimiter() == Delimiter::Bracket
                        && let Ok(meta) = syn::parse2::<Meta>(g.stream())
                        && !matches!(essai_par(std::iter::once(&meta)), Ok(false))
                    {
                        self.erreur(&format!(
                            "attribut d'essai (ou cfg illisible) « {} » dans le corps d'une macro que syn ne relit \
                             pas comme du code",
                            g.stream()
                        ));
                    }
                }
                TokenTree::Ident(nom) => {
                    let nom = sans_r(&nom.to_string()).to_string();
                    if let (Some(TokenTree::Punct(b)), Some(TokenTree::Group(g))) = (suivant, arbres.get(i + 2))
                        && b.as_char() == '!'
                    {
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
        if self.texte > 0 && !self.essai {
            self.chaines
                .push(valeur.chars().map(|x| if x.is_control() { ' ' } else { x }).collect());
        }
    }

    /// Un module à fichier (`nom;`) : son fichier et le dossier de ses modules, comme rustc les cherche.
    fn declare(&mut self, nom: &str, chemin: Option<String>) {
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
fn essai_par<'m>(attributs: impl Iterator<Item = &'m Meta>) -> Result<bool, Illisible> {
    for meta in attributs {
        let chemin = meta.path();
        let dernier = chemin.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
        if ATTRIBUTS_D_ESSAIS.contains(&sans_r(&dernier)) {
            return Ok(true);
        }
        if est(chemin, "cfg") {
            let Meta::List(liste) = meta else {
                return Err(Illisible(String::from("cfg sans parenthèses")));
            };
            if un_seul(liste.tokens.clone())? == Tri::Faux {
                return Ok(true);
            }
        } else if est(chemin, "cfg_attr") {
            let Meta::List(liste) = meta else {
                return Err(Illisible(String::from("cfg_attr sans parenthèses")));
            };
            if cfg_attr_essai(liste.tokens.clone())? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// `cfg_attr(condition, attr, …)` : un essai si la condition peut être vraie et qu'un des attributs en fait un.
fn cfg_attr_essai(flux: TokenStream) -> Result<bool, Illisible> {
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
    if un_seul(condition)? == Tri::Faux {
        return Ok(false);
    }
    let attributs = Punctuated::<Meta, Token![,]>::parse_terminated
        .parse2(reste)
        .map_err(|e| Illisible(format!("cfg_attr illisible : {e}")))?;
    essai_par(attributs.iter())
}

/// La valeur d'un `cfg` dans le programme (`test` et `kani` faux, le reste inconnu).
#[derive(Clone, Copy, Debug, PartialEq)]
enum Tri {
    Vrai,
    Faux,
    Inconnu,
}

/// Exactement une condition (virgule finale permise), comme dans `cfg(…)` et `not(…)`.
fn un_seul(flux: TokenStream) -> Result<Tri, Illisible> {
    let texte = flux.to_string();
    let conditions = conditions(flux)?;
    match conditions.as_slice() {
        [une] => Ok(*une),
        _ => Err(Illisible(format!(
            "cfg qui n'a pas exactement une condition : « {texte} »"
        ))),
    }
}

/// Les conditions d'une liste (`a, all(b, c), feature = "x"`), chacune jugée.
fn conditions(flux: TokenStream) -> Result<Vec<Tri>, Illisible> {
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
                let Some(TokenTree::Literal(_)) = arbres.next() else {
                    return Err(illisible());
                };
                Tri::Inconnu
            }
            Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Parenthesis => {
                let dedans = g.stream();
                arbres.next();
                match nom.as_str() {
                    "all" => conditions(dedans)?.into_iter().fold(Tri::Vrai, et),
                    "any" => conditions(dedans)?.into_iter().fold(Tri::Faux, ou),
                    "not" => non(un_seul(dedans)?),
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

    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        if self.essai {
            return;
        }
        let nom = m.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
        let nom = sans_r(&nom);
        if MACROS_D_ESSAIS.contains(&nom) {
            return;
        }
        let texte = MACROS_DE_TEXTE.contains(&nom);
        if texte {
            self.texte += 1;
        }
        self.corps(&m.tokens);
        if texte {
            self.texte -= 1;
        }
    }

    fn visit_lit_str(&mut self, s: &'ast syn::LitStr) {
        self.chaine(&s.value());
    }
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

//! Le vocabulaire de la porte MCP tiré des sources : les morceaux (suites sans espace) des chaînes que Vanguard passe
//! à ses macros de texte, sans les essais. Inclus par build.rs (par son chemin), qui lit les fichiers et écrit le
//! résultat ; déclaré dans le programme sous `cfg(test)` seulement, pour que ses essais le mettent à l'épreuve sur des
//! sources inventées. Rien ici ne lit le disque : build.rs seul choisit les fichiers (outils/essais-signature.sh le
//! garde).
//!
//! Les essais n'y entrent pas : leurs valeurs inventées (« alice », « Salon ») ne sont pas des mots de Vanguard. Est un
//! essai tout élément qui suit un attribut `cfg(test)` ou `cfg(all(…, test, …))`, quels que soient son nom, son retrait
//! et sa place (module, fonction, `impl`, instruction), retiré jusqu'à sa fin réelle (accolades, crochets et
//! parenthèses appariés hors des chaînes, caractères et commentaires) ; le fichier d'un module déclaré ainsi
//! (`mod nom;`, ou `#[path = …]`) ; un fichier marqué `#![cfg(test)]`. `cfg(any(…, test))` n'en est pas un : ce code
//! est aussi dans le programme. Limites : un module d'essais déclaré dans un module écrit en ligne (`mod a { mod b; }`)
//! est cherché à côté du fichier, pas dans `a/` (le nom tests.rs et les dossiers tests/, écartés par build.rs, couvrent
//! le cas courant) ; un `#[path]` hors des essais n'est pas suivi (son fichier, s'il est sous src/, est lu comme un
//! autre).

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

/// Le vocabulaire de ces sources (chemin et texte de chaque fichier), trié et sans doublon.
pub fn vocabulaire(sources: &[(PathBuf, String)]) -> BTreeSet<String> {
    let mut ecartes = Vec::new();
    let mut gardes = Vec::new();
    for (fichier, texte) in sources {
        let lu = hors_essais(texte);
        let dossier = dossier_des_modules(fichier);
        if lu.tout_essai {
            ecartes.push(fichier.clone());
            ecartes.push(dossier);
            continue;
        }
        for module in &lu.modules {
            if let Some(chemin) = &module.chemin {
                ecartes.push(propre(&fichier.parent().unwrap_or(Path::new("")).join(chemin)));
            } else {
                ecartes.push(dossier.join(format!("{}.rs", module.nom)));
                ecartes.push(dossier.join(&module.nom));
            }
        }
        gardes.push((fichier, lu.code));
    }
    let mut morceaux = BTreeSet::new();
    for (fichier, code) in gardes {
        let fichier = propre(fichier);
        if ecartes.iter().any(|e| fichier.starts_with(propre(e))) {
            continue;
        }
        for chaine in chaines_de_texte(&code) {
            morceaux.extend(sans_marques(&chaine).split_whitespace().map(str::to_string));
        }
    }
    morceaux
}

/// Le dossier où vivent les fichiers des modules que déclare `fichier` : le sien pour mod.rs, main.rs et lib.rs,
/// sinon un dossier à son nom (« a/b.rs » déclare « a/b/c.rs »).
fn dossier_des_modules(fichier: &Path) -> PathBuf {
    let parent = fichier.parent().unwrap_or(Path::new(""));
    let nom = fichier.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    if matches!(nom, "mod.rs" | "main.rs" | "lib.rs") {
        parent.to_path_buf()
    } else {
        parent.join(fichier.file_stem().unwrap_or_default())
    }
}

/// Le chemin sans « . » ni « .. » (sans lire le disque), pour comparer un `#[path = "../x.rs"]` aux fichiers lus.
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

/// Un module déclaré sous `cfg(test)` : son nom, et le chemin donné par `#[path = …]` s'il y en a un.
#[derive(Debug, PartialEq)]
struct Module {
    nom: String,
    chemin: Option<String>,
}

/// Un fichier sans ses essais.
#[derive(Debug)]
struct SansEssais {
    /// Le texte, chaque élément d'essai remplacé par une espace.
    code: String,
    /// Les modules déclarés sous `cfg(test)` (leurs fichiers sont des essais).
    modules: Vec<Module>,
    /// Le fichier entier est un essai (`#![cfg(test)]`).
    tout_essai: bool,
}

/// Le texte sans ses éléments d'essais, et ce qu'il dit des autres fichiers.
fn hors_essais(texte: &str) -> SansEssais {
    let c: Vec<char> = texte.chars().collect();
    let mut code = String::with_capacity(texte.len());
    let mut modules = Vec::new();
    let mut i = 0;
    let mut garde_depuis = 0;
    while i < c.len() {
        if let Some(j) = apres_litteral(&c, i) {
            i = j.max(i + 1);
            continue;
        }
        let interne = c.get(i + 1) == Some(&'!');
        let ouvre = i + 1 + usize::from(interne);
        if c[i] != '#' || c.get(ouvre) != Some(&'[') {
            i += 1;
            continue;
        }
        let fin = fin_de_groupe(&c, ouvre);
        let contenu: String = c[ouvre + 1..fin.saturating_sub(1).max(ouvre + 1)].iter().collect();
        if !seulement_essais(&contenu) {
            i = fin;
            continue;
        }
        if interne {
            return SansEssais {
                code: String::new(),
                modules: Vec::new(),
                tout_essai: true,
            };
        }
        let element = fin_d_element(&c, fin);
        if let Some(nom) = module_declare(&c[element.debut..element.fin]) {
            let chemin = element.attributs.iter().find_map(|a| chemin_d_attribut(a));
            modules.push(Module { nom, chemin });
        }
        code.extend(&c[garde_depuis..i]);
        code.push(' ');
        garde_depuis = element.fin;
        i = element.fin;
    }
    code.extend(&c[garde_depuis.min(c.len())..]);
    SansEssais {
        code,
        modules,
        tout_essai: false,
    }
}

/// Le contenu d'un attribut (entre ses crochets) ne garde l'élément qu'aux essais : `cfg(test)`, ou `cfg(all(…))` dont
/// un des termes est `test` (pas `not(test)`, ni `any(…, test)`).
fn seulement_essais(contenu: &str) -> bool {
    let serre: String = contenu.chars().filter(|x| !x.is_whitespace()).collect();
    if serre == "cfg(test)" {
        return true;
    }
    let Some(dedans) = serre.strip_prefix("cfg(all(").and_then(|r| r.strip_suffix("))")) else {
        return false;
    };
    let mut profondeur = 0usize;
    let mut terme = String::new();
    for x in dedans.chars().chain(std::iter::once(',')) {
        match x {
            '(' => profondeur += 1,
            ')' => profondeur = profondeur.saturating_sub(1),
            ',' if profondeur == 0 => {
                if terme == "test" {
                    return true;
                }
                terme.clear();
                continue;
            }
            _ => {}
        }
        terme.push(x);
    }
    false
}

/// Un élément d'essai : ses attributs suivants (contenus), puis le début et la fin (exclue) de son corps.
struct Element {
    attributs: Vec<String>,
    debut: usize,
    fin: usize,
}

/// L'élément qui suit un attribut fermé en `depuis` : les attributs et commentaires suivants sont sautés, puis le
/// corps va jusqu'à son « ; » (hors de toute paire), jusqu'à l'accolade qui referme sa première paire, ou s'arrête
/// avant une fermante qui n'est pas à lui (champ ou bras d'un bloc qui l'entoure). Une instruction `let`, `static`,
/// `use`, `type` ou `const` (pas `const fn`) ne finit qu'à son « ; » : `let x = if a { 1 } else { 2 };` en entier.
fn fin_d_element(c: &[char], depuis: usize) -> Element {
    let mut attributs = Vec::new();
    let mut j = depuis;
    loop {
        while c.get(j).is_some_and(|x| x.is_whitespace()) {
            j += 1;
        }
        if c.get(j) == Some(&'/') && matches!(c.get(j + 1), Some('/' | '*')) {
            j = apres_litteral(c, j).unwrap_or(j + 1);
            continue;
        }
        let ouvre = if c.get(j + 1) == Some(&'!') { j + 2 } else { j + 1 };
        if c.get(j) == Some(&'#') && c.get(ouvre) == Some(&'[') {
            let fin = fin_de_groupe(c, ouvre);
            attributs.push(c[ouvre + 1..fin.saturating_sub(1).max(ouvre + 1)].iter().collect());
            j = fin;
            continue;
        }
        break;
    }
    let debut = j;
    let point_virgule_seul = point_virgule_seul(c, debut);
    let mut profondeur = 0usize;
    while j < c.len() {
        if let Some(k) = apres_litteral(c, j) {
            j = k.max(j + 1);
            continue;
        }
        match c[j] {
            '(' | '[' | '{' => profondeur += 1,
            ')' | ']' | '}' if profondeur == 0 => {
                return Element {
                    attributs,
                    debut,
                    fin: j,
                };
            }
            ')' | ']' => profondeur -= 1,
            '}' => {
                profondeur -= 1;
                if profondeur == 0 && !point_virgule_seul {
                    return Element {
                        attributs,
                        debut,
                        fin: j + 1,
                    };
                }
            }
            ';' if profondeur == 0 => {
                return Element {
                    attributs,
                    debut,
                    fin: j + 1,
                };
            }
            _ => {}
        }
        j += 1;
    }
    Element {
        attributs,
        debut,
        fin: c.len(),
    }
}

/// L'élément qui commence en `debut` ne finit qu'à son « ; » (`let`, `static`, `use`, `type`, `const` sans `fn`).
fn point_virgule_seul(c: &[char], debut: usize) -> bool {
    let texte: String = c[debut..c.len().min(debut + 40)].iter().collect();
    let mut mots = texte
        .split(|x: char| !x.is_alphanumeric() && x != '_')
        .filter(|m| !m.is_empty())
        .skip_while(|m| matches!(*m, "pub" | "crate" | "super" | "self" | "in"));
    let premier = mots.next().unwrap_or_default();
    match premier {
        "let" | "static" | "use" | "type" => true,
        "const" => !matches!(mots.next(), Some("fn" | "unsafe" | "async" | "extern")),
        _ => false,
    }
}

/// Le nom du module que déclare cet élément (`mod nom;`, `pub(crate) mod nom { … }`), s'il en déclare un.
fn module_declare(element: &[char]) -> Option<String> {
    let texte: String = element.iter().collect();
    let mut reste = texte.trim_start();
    if let Some(r) = reste.strip_prefix("pub") {
        reste = r.trim_start();
        if let Some(r) = reste.strip_prefix('(') {
            reste = r.split_once(')')?.1.trim_start();
        }
    }
    let reste = reste.strip_prefix("mod")?;
    if !reste.starts_with(char::is_whitespace) {
        return None;
    }
    let nom: String = reste
        .trim_start()
        .chars()
        .take_while(|x| x.is_alphanumeric() || *x == '_')
        .collect();
    (!nom.is_empty()).then_some(nom)
}

/// Le chemin d'un attribut `path = "…"`, s'il en est un.
fn chemin_d_attribut(attribut: &str) -> Option<String> {
    let reste = attribut
        .trim_start()
        .strip_prefix("path")?
        .trim_start()
        .strip_prefix('=')?
        .trim();
    Some(reste.strip_prefix('"')?.strip_suffix('"')?.to_string())
}

/// L'indice qui suit la fermante appariée à l'ouvrante en `ouvre`, hors des chaînes, caractères et commentaires ; la
/// fin du texte si elle manque.
fn fin_de_groupe(c: &[char], ouvre: usize) -> usize {
    let mut profondeur = 0usize;
    let mut j = ouvre;
    while j < c.len() {
        if let Some(k) = apres_litteral(c, j) {
            j = k.max(j + 1);
            continue;
        }
        match c[j] {
            '(' | '[' | '{' => profondeur += 1,
            ')' | ']' | '}' => {
                profondeur = profondeur.saturating_sub(1);
                if profondeur == 0 {
                    return j + 1;
                }
            }
            _ => {}
        }
        j += 1;
    }
    c.len()
}

/// Si une chaîne (ordinaire, d'octets, brute r"…" ou r#"…"#), un caractère ou un commentaire (`//`, `/* */`
/// imbriqués) commence en `i`, l'indice qui le suit. Une durée de vie (`'a`) n'est pas un caractère : seul son
/// apostrophe est sauté.
fn apres_litteral(c: &[char], i: usize) -> Option<usize> {
    let signe = *c.get(i)?;
    let dans_un_mot = i > 0 && c.get(i - 1).is_some_and(|y| y.is_alphanumeric() || *y == '_');
    match signe {
        '/' if c.get(i + 1) == Some(&'/') => Some(c[i..].iter().position(|y| *y == '\n').map_or(c.len(), |p| i + p)),
        '/' if c.get(i + 1) == Some(&'*') => {
            let mut profondeur = 0usize;
            let mut j = i;
            while j < c.len() {
                if c[j] == '/' && c.get(j + 1) == Some(&'*') {
                    profondeur += 1;
                    j += 2;
                } else if c[j] == '*' && c.get(j + 1) == Some(&'/') {
                    profondeur -= 1;
                    j += 2;
                    if profondeur == 0 {
                        return Some(j);
                    }
                } else {
                    j += 1;
                }
            }
            Some(c.len())
        }
        '"' => {
            let mut k = i + 1;
            while k < c.len() && c[k] != '"' {
                k += if c[k] == '\\' { 2 } else { 1 };
            }
            Some((k + 1).min(c.len()))
        }
        'r' | 'b' | 'c' if !dans_un_mot => {
            let mut j = i + 1;
            if signe != 'r' {
                if c.get(j) != Some(&'r') {
                    return None;
                }
                j += 1;
            }
            let dieses = c[j..].iter().take_while(|y| **y == '#').count();
            if c.get(j + dieses) != Some(&'"') {
                return None;
            }
            let mut k = j + dieses + 1;
            while k < c.len()
                && !(c[k] == '"' && c[k + 1..].iter().take(dieses).filter(|y| **y == '#').count() == dieses)
            {
                k += 1;
            }
            Some((k + 1 + dieses).min(c.len()))
        }
        '\'' if c.get(i + 1) == Some(&'\\') => Some(
            c.get(i + 3..)?
                .iter()
                .position(|y| *y == '\'')
                .map_or(c.len(), |p| i + 4 + p),
        ),
        '\'' if c.get(i + 2) == Some(&'\'') => Some(i + 3),
        '\'' => Some(i + 1),
        _ => None,
    }
}

/// Les chaînes (décodées) de chaque appel aux macros de texte, jusqu'à sa parenthèse fermante : chaînes brutes
/// (r"…", r#"…"#) comprises ; un caractère '"', '(' ou ')' n'est ni une chaîne ni une parenthèse.
fn chaines_de_texte(texte: &str) -> Vec<String> {
    let lettres: Vec<char> = texte.chars().collect();
    let mut trouvees = Vec::new();
    let mut pos = 0;
    while pos < lettres.len() {
        let Some(debut) = appel_de_macro(&lettres, pos) else {
            pos += 1;
            continue;
        };
        let mut profondeur = 1usize;
        let mut j = debut;
        while j < lettres.len() && profondeur > 0 {
            let lu = lettres[j];
            if lu == 'r' && (j == 0 || !lettres[j - 1].is_alphanumeric()) {
                let dieses = lettres[j + 1..].iter().take_while(|y| **y == '#').count();
                if lettres.get(j + 1 + dieses) == Some(&'"') {
                    let corps = j + 2 + dieses;
                    let mut k = corps;
                    while k < lettres.len()
                        && !(lettres[k] == '"' && lettres[k + 1..].iter().take(dieses).all(|y| *y == '#'))
                    {
                        k += 1;
                    }
                    trouvees.push(lettres[corps..k.min(lettres.len())].iter().collect());
                    j = k + 1 + dieses;
                    continue;
                }
            }
            if lu == '"' {
                let mut k = j + 1;
                let mut chaine = String::new();
                while k < lettres.len() && lettres[k] != '"' {
                    if lettres[k] == '\\' {
                        k = echappement(&lettres, k, &mut chaine);
                    } else {
                        chaine.push(lettres[k]);
                        k += 1;
                    }
                }
                trouvees.push(chaine);
                j = k + 1;
                continue;
            }
            if lu == '\'' && lettres.get(j + 2) == Some(&'\'') && matches!(lettres.get(j + 1), Some('"' | '(' | ')')) {
                j += 3;
                continue;
            }
            if lu == '(' {
                profondeur += 1;
            } else if lu == ')' {
                profondeur -= 1;
            }
            j += 1;
        }
        pos = j;
    }
    trouvees
}

/// Si un appel aux macros de texte commence en `i` (après une limite de mot), l'indice qui suit sa parenthèse.
fn appel_de_macro(c: &[char], i: usize) -> Option<usize> {
    if c.get(i..i + 2)? != ['t', 'r'] || (i > 0 && (c[i - 1].is_alphanumeric() || c[i - 1] == '_')) {
        return None;
    }
    let mut j = i + 2;
    let suite: String = c[j..].iter().take_while(|x| x.is_ascii_lowercase()).collect();
    if !["", "f", "p", "e", "w", "wln", "pr"].contains(&suite.as_str()) {
        return None;
    }
    j += suite.len();
    if c.get(j) != Some(&'!') {
        return None;
    }
    j += 1;
    while c.get(j).is_some_and(|x| x.is_whitespace()) {
        j += 1;
    }
    (c.get(j) == Some(&'(')).then_some(j + 1)
}

/// Décode l'échappement qui commence en `k` (« \n », « \u{e9} », fin de ligne échappée…) ; rend l'indice qui suit.
/// Les sauts de ligne et tabulations écrits « \n », « \t » deviennent une espace : ils séparent des mots. Une fin de
/// ligne échappée (« \ » en fin de ligne) ne laisse rien, ni elle ni les blancs du début de la ligne suivante, comme
/// en Rust : « pare-\ » puis « feu » donne « pare-feu ».
fn echappement(c: &[char], k: usize, chaine: &mut String) -> usize {
    match c.get(k + 1) {
        Some('n' | 't' | 'r' | '0') => {
            chaine.push(' ');
            k + 2
        }
        Some('u') => {
            let fin = c[k..].iter().position(|x| *x == '}').map_or(c.len(), |p| k + p);
            let hexa: String = c.get(k + 3..fin).unwrap_or_default().iter().collect();
            if let Some(x) = u32::from_str_radix(&hexa, 16).ok().and_then(char::from_u32) {
                chaine.push(x);
            }
            fin + 1
        }
        Some('x') => {
            let hexa: String = c.get(k + 2..k + 4).unwrap_or_default().iter().collect();
            if let Some(x) = u32::from_str_radix(&hexa, 16).ok().and_then(char::from_u32) {
                chaine.push(x);
            }
            k + 4
        }
        Some('\n') => {
            let mut j = k + 1;
            while c.get(j).is_some_and(|x| x.is_whitespace()) {
                j += 1;
            }
            j
        }
        Some(x) => {
            chaine.push(*x);
            k + 2
        }
        None => k + 1,
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

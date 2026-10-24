//! Préparé à la compilation : la base des fabricants (assets/oui.tsv) rangée en tableaux triés, les règles YARA
//! allégées, et, pour Windows, la fiche d'identité de vanguard.exe (onglet « Détails » des propriétés du fichier), son
//! icône et son manifeste.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::Path;

fn main() {
    date_compilation();
    fabricants();
    regles_yara();
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        ressources_windows();
    }
}

/// Date du dernier commit, pour « cette copie a N mois » (src/protection/manifeste.rs) : jamais l'horloge, pour qu'un
/// même code donne le même programme (outils/deployer.sh ne recopie que ce qui change, et une compilation
/// reproductible reste possible). SOURCE_DATE_EPOCH d'abord, sinon git ; sans git (archive du code), pas de date.
fn date_compilation() {
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    // HEAD change à chaque changement de branche, le journal des références à chaque commit (y compris dans un
    // worktree, où .git est un fichier qui ne bouge pas).
    for fichier in ["HEAD", "logs/HEAD"] {
        if let Some(chemin) = git(&["rev-parse", "--git-path", fichier]) {
            println!("cargo:rerun-if-changed={chemin}");
        }
    }
    let secondes = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .or_else(|| git(&["log", "-1", "--format=%ct"]).and_then(|s| s.parse().ok()));
    let date = secondes.map(date_civile).unwrap_or_default();
    println!("cargo:rustc-env=VANGUARD_COMPILE={date}");
    // Le même instant, en secondes, gravé dans le programme avec sa version (src/mise_a_jour.rs) : deux compilations
    // d'une même version, entre deux publications, se départagent par lui. 0 sans git.
    println!("cargo:rustc-env=VANGUARD_COMMIT_SECONDES={}", secondes.unwrap_or(0));
}

/// La sortie de git, `None` s'il manque ou échoue (archive du code sans dépôt).
fn git(args: &[&str]) -> Option<String> {
    let sortie = std::process::Command::new("git").args(args).output().ok()?;
    let texte = String::from_utf8_lossy(&sortie.stdout).trim().to_string();
    (sortie.status.success() && !texte.is_empty()).then_some(texte)
}

/// « AAAA-MM-JJ » (UTC) d'un instant en secondes depuis 1970 (algorithme civil de Howard Hinnant).
fn date_civile(secondes: i64) -> String {
    let z = secondes.div_euclid(86400) + 719_468;
    let ere = z.div_euclid(146_097);
    let jour_ere = z.rem_euclid(146_097);
    let an_ere = (jour_ere - jour_ere / 1460 + jour_ere / 36524 - jour_ere / 146_096) / 365;
    let jour_an = jour_ere - (365 * an_ere + an_ere / 4 - an_ere / 100);
    let mois_decale = (5 * jour_an + 2) / 153;
    let jour = jour_an - (153 * mois_decale + 2) / 5 + 1;
    let mois = if mois_decale < 10 {
        mois_decale + 3
    } else {
        mois_decale - 9
    };
    let an = an_ere + ere * 400 + i64::from(mois <= 2);
    format!("{an:04}-{mois:02}-{jour:02}")
}

/// La base des fabricants, rangée une fois pour toutes : pour chaque longueur de préfixe (6, 7 ou 9 chiffres
/// hexadécimaux), les préfixes triés et le numéro de leur nom ; chaque nom n'est écrit qu'une fois (« Apple, Inc. »
/// revient plus de 1500 fois). Le programme y cherche par dichotomie, sans rien lire ni allouer : avant, chaque scan
/// recopiait les 58 000 lignes dans une table de hachage de plusieurs Mo.
fn fabricants() {
    println!("cargo:rerun-if-changed=assets/oui.tsv");
    let texte = std::fs::read_to_string("assets/oui.tsv").expect("assets/oui.tsv illisible");
    let mut noms: Vec<&str> = Vec::new();
    let mut numeros: HashMap<&str, u16> = HashMap::new();
    let mut tables: [Vec<(u64, u16)>; 3] = Default::default();
    for ligne in texte.lines() {
        let Some((prefixe, nom)) = ligne.split_once('\t') else {
            continue;
        };
        let rang = match prefixe.len() {
            6 => 0,
            7 => 1,
            9 => 2,
            _ => continue,
        };
        let Ok(valeur) = u64::from_str_radix(prefixe, 16) else {
            continue;
        };
        let numero = *numeros.entry(nom).or_insert_with(|| {
            noms.push(nom);
            u16::try_from(noms.len() - 1).expect("plus de 65 536 fabricants : passer les numéros en u32")
        });
        tables[rang].push((valeur, numero));
    }
    let mut rs = String::from("// Fichier produit par build.rs à partir de assets/oui.tsv : ne pas modifier.\n");
    let mut tous = String::new();
    let mut debuts = vec![0u32];
    for nom in &noms {
        tous.push_str(nom);
        debuts.push(u32::try_from(tous.len()).expect("noms trop longs"));
    }
    let _ = writeln!(rs, "pub static NOMS: &str = {tous:?};");
    let _ = writeln!(rs, "pub static DEBUTS: [u32; {}] = {debuts:?};", debuts.len());
    for (table, (longueur, entier)) in tables.iter_mut().zip([("6", "u32"), ("7", "u32"), ("9", "u64")]) {
        table.sort_unstable();
        table.dedup_by_key(|e| e.0);
        let prefixes: Vec<String> = table.iter().map(|e| e.0.to_string()).collect();
        let numeros: Vec<String> = table.iter().map(|e| e.1.to_string()).collect();
        let n = table.len();
        let _ = writeln!(
            rs,
            "pub static PREFIXES_{longueur}: [{entier}; {n}] = [{}];",
            prefixes.join(",")
        );
        let _ = writeln!(rs, "pub static NOMS_{longueur}: [u16; {n}] = [{}];", numeros.join(","));
    }
    let sortie = std::env::var("OUT_DIR").expect("OUT_DIR");
    std::fs::write(Path::new(&sortie).join("fabricants.rs"), rs).expect("fabricants.rs non écrit");
}

/// Les règles YARA (assets/yara, 2,7 Mo de texte), allégées pour le programme sans en changer le sens : sans les blocs
/// « meta: » (auteur, description… que Vanguard n'affiche pas), sans indentation, un import de module une seule fois,
/// les octets des chaînes hexadécimales collés (« 4D5A ») et chaque suite de « ?? » écrite en saut (« [6] » vaut six
/// « ?? », documentation de YARA). Le moteur YARA de Vanguard, comme YARA-X qui lui sert d'oracle dans les tests, les
/// lit comme les règles d'origine ; l'en-tête (source et licence) reste.
fn regles_yara() {
    println!("cargo:rerun-if-changed=assets/yara/reversinglabs.yara");
    let texte = std::fs::read_to_string("assets/yara/reversinglabs.yara").expect("règles YARA illisibles");
    let sortie = std::env::var("OUT_DIR").expect("OUT_DIR");
    std::fs::write(Path::new(&sortie).join("reversinglabs.yara"), alleger_yara(&texte))
        .expect("règles YARA allégées non écrites");
}

/// Un morceau du texte des règles.
#[derive(Debug, PartialEq)]
enum Jeton {
    /// Mot : mot-clé, nom, nombre, identifiant de chaîne (« $a », « #a »), champ d'un module (« pe.is_dll »).
    Mot(String),
    /// Chaîne de texte, guillemets compris, recopiée telle quelle.
    Texte(String),
    /// Chaîne hexadécimale déjà allégée, accolades comprises ; ou expression régulière, telle quelle.
    Motif(String),
    Signe(char),
    Espace,
}

/// Découpe le texte des règles ; les commentaires disparaissent.
fn jetons(texte: &str) -> Vec<Jeton> {
    let c: Vec<char> = texte.chars().collect();
    let mut liste = Vec::new();
    let mut i = 0;
    // Après « = », une accolade ouvre une chaîne hexadécimale, une barre oblique une expression régulière.
    let apres_egal = |liste: &Vec<Jeton>| {
        liste
            .iter()
            .rev()
            .find(|j| **j != Jeton::Espace)
            .is_some_and(|j| *j == Jeton::Signe('='))
    };
    while i < c.len() {
        let x = c[i];
        if x.is_whitespace() {
            while i < c.len() && c[i].is_whitespace() {
                i += 1;
            }
            liste.push(Jeton::Espace);
        } else if x == '/' && c.get(i + 1) == Some(&'/') {
            while i < c.len() && c[i] != '\n' {
                i += 1;
            }
        } else if x == '/' && c.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < c.len() && !(c[i] == '*' && c[i + 1] == '/') {
                i += 1;
            }
            i += 2;
        } else if x == '"' {
            let debut = i;
            i += 1;
            while i < c.len() && c[i] != '"' {
                i += if c[i] == '\\' { 2 } else { 1 };
            }
            i += 1;
            liste.push(Jeton::Texte(c[debut..i.min(c.len())].iter().collect()));
        } else if x == '{' && apres_egal(&liste) {
            let debut = i;
            while i < c.len() && c[i] != '}' {
                i += 1;
            }
            i += 1;
            let dedans: String = c[debut + 1..i - 1].iter().collect();
            liste.push(Jeton::Motif(format!("{{{}}}", hexadecimal(&dedans))));
        } else if x == '/' && apres_egal(&liste) {
            let debut = i;
            i += 1;
            while i < c.len() && c[i] != '/' {
                i += if c[i] == '\\' { 2 } else { 1 };
            }
            i += 1;
            while i < c.len() && c[i].is_ascii_alphabetic() {
                i += 1;
            }
            liste.push(Jeton::Motif(c[debut..i.min(c.len())].iter().collect()));
        } else if x.is_alphanumeric() || "_$#@!.*".contains(x) {
            let debut = i;
            while i < c.len() && (c[i].is_alphanumeric() || "_$#@!.*".contains(c[i])) {
                i += 1;
            }
            liste.push(Jeton::Mot(c[debut..i].iter().collect()));
        } else {
            liste.push(Jeton::Signe(x));
            i += 1;
        }
    }
    liste
}

/// Le contenu d'une chaîne hexadécimale, allégé : sans espaces ni commentaires, et chaque suite d'au moins deux
/// « ?? » entre deux octets connus, hors d'une alternative « ( … | … ) », écrite en saut « [n] ».
fn hexadecimal(dedans: &str) -> String {
    let mut sans_commentaires = String::new();
    for ligne in dedans.lines() {
        sans_commentaires.push_str(ligne.split("//").next().unwrap_or_default());
        sans_commentaires.push(' ');
    }
    let c: Vec<char> = sans_commentaires.chars().filter(|x| !x.is_whitespace()).collect();
    // Les morceaux : un octet (deux signes, « ?? » compris), un saut « […] », ou « ( », « | », « ) ».
    let mut morceaux: Vec<String> = Vec::new();
    let mut i = 0;
    while i < c.len() {
        let fin = match c[i] {
            '[' => c[i..].iter().position(|x| *x == ']').map_or(c.len(), |p| i + p + 1),
            '(' | '|' | ')' => i + 1,
            '~' => (i + 3).min(c.len()),
            _ => (i + 2).min(c.len()),
        };
        morceaux.push(c[i..fin].iter().collect());
        i = fin;
    }
    let octet = |m: &str| m.len() == 2 && m != "??" && m.chars().all(|x| x.is_ascii_hexdigit() || x == '?');
    let mut sortie = String::new();
    let mut profondeur = 0usize;
    let mut i = 0;
    while i < morceaux.len() {
        let m = morceaux[i].as_str();
        match m {
            "(" => profondeur += 1,
            ")" => profondeur = profondeur.saturating_sub(1),
            _ => {}
        }
        if m == "??" && profondeur == 0 {
            let n = morceaux[i..].iter().take_while(|x| *x == "??").count();
            let entoure = i > 0 && octet(&morceaux[i - 1]) && morceaux.get(i + n).is_some_and(|x| octet(x));
            if n >= 2 && entoure {
                let _ = write!(sortie, "[{n}]");
            } else {
                sortie.push_str(&"??".repeat(n));
            }
            i += n;
            continue;
        }
        sortie.push_str(m);
        i += 1;
    }
    sortie
}

/// Les règles allégées : l'en-tête (les commentaires du début : source, licence), puis une règle par ligne.
fn alleger_yara(texte: &str) -> String {
    let mut sortie = String::new();
    for l in texte.lines().take_while(|l| l.trim_start().starts_with("//")) {
        let _ = writeln!(sortie, "{l}");
    }
    let jetons = jetons(texte);
    let mut profondeur = 0usize;
    let mut dans_meta = false;
    let mut imports: Vec<String> = Vec::new();
    let mut ligne = String::new();
    let mut i = 0;
    // Le prochain jeton qui n'est pas un espace.
    let suivant = |i: usize| jetons[i + 1..].iter().find(|j| **j != Jeton::Espace);
    let mut finir_ligne = |ligne: &mut String, sortie: &mut String| {
        let l = ligne.trim();
        if !l.is_empty() {
            // Un module importé une seule fois : chaque fichier d'origine refaisait « import "pe" ».
            if l.starts_with("import ") {
                if imports.iter().any(|x| x == l) {
                    ligne.clear();
                    return;
                }
                imports.push(l.to_string());
            }
            sortie.push_str(l);
            sortie.push('\n');
        }
        ligne.clear();
    };
    while i < jetons.len() {
        let j = &jetons[i];
        let deux_points = suivant(i) == Some(&Jeton::Signe(':'));
        if profondeur == 1
            && deux_points
            && let Jeton::Mot(m) = j
        {
            match m.as_str() {
                "meta" => dans_meta = true,
                "strings" | "condition" => dans_meta = false,
                _ => {}
            }
        }
        match j {
            Jeton::Signe('{') => profondeur += 1,
            Jeton::Signe('}') => profondeur = profondeur.saturating_sub(1),
            _ => {}
        }
        if dans_meta {
            i += 1;
            continue;
        }
        if profondeur == 0
            && matches!(j, Jeton::Mot(m) if m == "rule" || m == "import" || m == "private" || m == "global")
        {
            // Une règle ou un import par ligne ; « private rule » reste sur une seule.
            let deja = ligne.trim_end().ends_with("private") || ligne.trim_end().ends_with("global");
            if !deja {
                finir_ligne(&mut ligne, &mut sortie);
            }
        }
        match j {
            Jeton::Espace => {
                if !ligne.is_empty() && !ligne.ends_with(' ') {
                    ligne.push(' ');
                }
            }
            Jeton::Mot(t) | Jeton::Texte(t) | Jeton::Motif(t) => ligne.push_str(t),
            Jeton::Signe(s) => ligne.push(*s),
        }
        i += 1;
    }
    finir_ligne(&mut ligne, &mut sortie);
    sortie
}

fn ressources_windows() {
    println!("cargo:rerun-if-changed=assets/vanguard.ico");
    let mut res = winresource::WindowsResource::new();
    // Compilation croisée depuis Linux : outils de MinGW.
    if !cfg!(windows) {
        res.set_windres_path("x86_64-w64-mingw32-windres");
        res.set_ar_path("x86_64-w64-mingw32-ar");
    }
    res.set("ProductName", "Vanguard")
        .set("FileDescription", "Vanguard - Cyberdéfense portable des postes et des réseaux (bilan, antivirus, réglages)")
        .set("CompanyName", "Projet personnel Vanguard")
        .set("LegalCopyright", "© 2026 d9v3, licence GPL-3.0-or-later")
        .set("OriginalFilename", "vanguard.exe")
        // Icône de l'Explorateur et de la barre des tâches (16 à 256 px, voir assets/).
        .set_icon("assets/vanguard.ico")
        // asInvoker : Vanguard démarre sans droits admin ; seules les corrections les demandent, une à une.
        .set_manifest(
            r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security>
  </trustInfo>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings><activeCodePage xmlns="http://schemas.microsoft.com/SMI/2019/WindowsSettings">UTF-8</activeCodePage></windowsSettings>
  </application>
</assembly>"#,
        );
    if let Err(e) = res.compile() {
        // Le programme livré doit porter son manifeste (page de code UTF-8, accents et chemins justes ; asInvoker) :
        // en version publiée, son absence arrête la compilation au lieu d'un avertissement que personne ne lit
        // (`vanguard deploiement verifier-pe` le revérifie sur le .exe, avant qu'il parte). Les tests, eux, s'en passent.
        assert!(
            std::env::var("PROFILE").as_deref() != Ok("release"),
            "ressources Windows non intégrées (manifeste UTF-8, asInvoker, icône) : {e}"
        );
        println!("cargo:warning=ressources Windows non intégrées : {e}");
    }
    // L'éditeur de liens de MinGW écrit l'heure de la compilation dans l'en-tête PE : sans elle, un même code donne le
    // même .exe (travail « reproductible » de la CI). Ici et non dans les rustflags de la cible, qui remplaceraient
    // ceux de [build] (--remap-path-prefix).
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu") {
        println!("cargo:rustc-link-arg=-Wl,--no-insert-timestamp");
        // La garde contre une DLL posée à côté du programme (src/machine/windows/chargement.rs) n'est référencée par
        // aucun code : `#[used]` ne suffit pas toujours, et l'éditeur de liens jetait sa section dans certains
        // découpages de la compilation (vu le 21 oct. : programme sans « Load Config »). Exigée ici, elle reste, et
        // son absence fait échouer la compilation au lieu de passer en silence. Le programme seulement : les tests
        // d'intégration n'ont pas ce module.
        println!("cargo:rustc-link-arg-bins=-Wl,--require-defined=_load_config_used");
    }
}

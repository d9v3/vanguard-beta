//! Un lecteur minimal de JSON Schema et de motifs, écrit pour l'essai : prouver que `schema-envoi.json` et les types
//! Rust disent la même chose, sans dépendance nouvelle. Il ne connaît que les mots-clés et la syntaxe de motif que le
//! schéma emploie, et panique sur tout le reste : le schéma ne peut pas grandir (un `\d`, un `format`, un mot-clé
//! nouveau) sans que l'essai le lise, ni sortir du sous-ensemble que JavaScript et Python lisent de la même façon.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

#[derive(Clone, Debug)]
enum Noeud {
    Debut,
    Fin,
    /// Un caractère dans l'une des plages, ou hors de toutes (`true`).
    Classe(Vec<(char, char)>, bool),
    Groupe(Vec<Vec<Noeud>>),
    Anticipe(Vec<Vec<Noeud>>),
    Repete(Box<Noeud>, usize, Option<usize>),
}

/// Un motif lu : alternatives de suites de nœuds.
pub(super) struct Motif(Vec<Vec<Noeud>>);

impl Motif {
    pub(super) fn new(motif: &str) -> Motif {
        let mut l = Lecteur {
            c: motif.chars().collect(),
            i: 0,
        };
        let alts = l.alternatives();
        assert_eq!(l.i, l.c.len(), "motif mal fermé : {motif}");
        Motif(alts)
    }

    /// Comme `pattern` en JSON Schema (`RegExp.test`) : le motif peut s'accrocher n'importe où, ses ancres le bornent.
    pub(super) fn accepte(&self, s: &str) -> bool {
        let c: Vec<char> = s.chars().collect();
        (0..=c.len()).any(|debut| alternatives(&self.0, &c, debut, &mut |_| true))
    }
}

struct Lecteur {
    c: Vec<char>,
    i: usize,
}

impl Lecteur {
    fn voir(&self) -> Option<char> {
        self.c.get(self.i).copied()
    }

    fn prendre(&mut self) -> char {
        let x = *self.c.get(self.i).expect("motif coupé");
        self.i += 1;
        x
    }

    fn attendre(&mut self, x: char) {
        assert_eq!(self.prendre(), x, "motif : « {x} » attendu");
    }

    fn alternatives(&mut self) -> Vec<Vec<Noeud>> {
        let mut alts = vec![self.suite()];
        while self.voir() == Some('|') {
            self.i += 1;
            alts.push(self.suite());
        }
        alts
    }

    fn suite(&mut self) -> Vec<Noeud> {
        let mut suite = Vec::new();
        while let Some(x) = self.voir() {
            if x == '|' || x == ')' {
                break;
            }
            let atome = self.atome();
            suite.push(self.quantifie(atome));
        }
        suite
    }

    fn atome(&mut self) -> Noeud {
        match self.prendre() {
            '^' => Noeud::Debut,
            '$' => Noeud::Fin,
            '(' => {
                self.attendre('?');
                let sorte = self.prendre();
                let alts = self.alternatives();
                self.attendre(')');
                match sorte {
                    ':' => Noeud::Groupe(alts),
                    '=' => Noeud::Anticipe(alts),
                    x => panic!("groupe « (?{x} » hors du sous-ensemble portable"),
                }
            }
            '[' => self.classe(),
            '\\' => {
                let x = self.echappe(false);
                Noeud::Classe(vec![(x, x)], false)
            }
            x @ ('.' | '*' | '+' | '?' | '{' | '}' | ']') => {
                panic!("« {x} » nu dans un motif : hors du sous-ensemble portable")
            }
            x => Noeud::Classe(vec![(x, x)], false),
        }
    }

    fn quantifie(&mut self, n: Noeud) -> Noeud {
        let (min, max) = match self.voir() {
            Some('?') => (0, Some(1)),
            Some('*') => (0, None),
            Some('+') => (1, None),
            Some('{') => {
                self.i += 1;
                let min = self.nombre();
                let max = if self.voir() == Some(',') {
                    self.i += 1;
                    self.nombre()
                } else {
                    min
                };
                assert_eq!(self.voir(), Some('}'), "quantificateur mal fermé");
                assert!(min <= max, "quantificateur à l'envers");
                (min, Some(max))
            }
            _ => return n,
        };
        self.i += 1;
        assert!(
            !matches!(n, Noeud::Debut | Noeud::Fin | Noeud::Anticipe(_)),
            "ancre ou anticipation quantifiée : refusée par JavaScript en mode u"
        );
        Noeud::Repete(Box::new(n), min, max)
    }

    fn nombre(&mut self) -> usize {
        let debut = self.i;
        while self.voir().is_some_and(|x| x.is_ascii_digit()) {
            self.i += 1;
        }
        let texte: String = self.c[debut..self.i].iter().collect();
        texte.parse().expect("nombre attendu dans un quantificateur")
    }

    fn classe(&mut self) -> Noeud {
        let nie = self.voir() == Some('^');
        if nie {
            self.i += 1;
        }
        let mut plages = Vec::new();
        loop {
            let a = match self.prendre() {
                ']' => break,
                '\\' => self.echappe(true),
                '[' => panic!("« [ » nu dans une classe"),
                x => x,
            };
            let plage = self.voir() == Some('-') && self.c.get(self.i + 1) != Some(&']');
            if plage {
                self.i += 1;
                let b = match self.prendre() {
                    '\\' => self.echappe(true),
                    x => x,
                };
                assert!(a <= b, "plage à l'envers : {a:?}-{b:?}");
                plages.push((a, b));
                assert!(
                    !(self.voir() == Some('-') && self.c.get(self.i + 1) != Some(&']')),
                    "plage suivie d'un trait d'union : lue autrement d'un moteur à l'autre"
                );
            } else {
                plages.push((a, a));
            }
        }
        assert!(!plages.is_empty(), "classe vide");
        Noeud::Classe(plages, nie)
    }

    fn echappe(&mut self, dans_classe: bool) -> char {
        match self.prendre() {
            'u' => self.hexa(4),
            'x' => self.hexa(2),
            x @ ('\\' | '.' | '^' | '$' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '*' | '+' | '?' | '/') => x,
            '-' if dans_classe => '-',
            x => panic!(
                "échappement « \\{x} » hors du sous-ensemble portable (\\d, \\w, \\s et \\p diffèrent d'un moteur à l'autre)"
            ),
        }
    }

    fn hexa(&mut self, n: usize) -> char {
        let texte: String = (0..n).map(|_| self.prendre()).collect();
        let code = u32::from_str_radix(&texte, 16).expect("échappement hexadécimal");
        char::from_u32(code).expect("échappement hors de l'Unicode (moitié de paire ?)")
    }
}

/// La suite du motif à partir de `i`, puis `k` (ce qui vient après) : retour arrière par continuations.
fn alternatives(alts: &[Vec<Noeud>], c: &[char], i: usize, k: &mut dyn FnMut(usize) -> bool) -> bool {
    alts.iter().any(|suite_| suite(suite_, c, i, &mut *k))
}

fn suite(noeuds: &[Noeud], c: &[char], i: usize, k: &mut dyn FnMut(usize) -> bool) -> bool {
    match noeuds.split_first() {
        None => k(i),
        Some((n, reste)) => un(n, c, i, &mut |j| suite(reste, c, j, &mut *k)),
    }
}

fn un(noeud: &Noeud, c: &[char], i: usize, ensuite: &mut dyn FnMut(usize) -> bool) -> bool {
    match noeud {
        Noeud::Debut => i == 0 && ensuite(i),
        Noeud::Fin => i == c.len() && ensuite(i),
        Noeud::Classe(plages, nie) => match c.get(i) {
            Some(x) if plages.iter().any(|(de, a)| (de..=a).contains(&x)) != *nie => ensuite(i + 1),
            _ => false,
        },
        Noeud::Groupe(alts) => alternatives(alts, c, i, ensuite),
        Noeud::Anticipe(alts) => alternatives(alts, c, i, &mut |_| true) && ensuite(i),
        Noeud::Repete(sous, min, max) => repete(sous, *min, *max, c, i, ensuite),
    }
}

/// Gourmand : un tour de plus d'abord, puis s'arrêter si le minimum est atteint. Un tour qui n'avance pas ne compte
/// pas (sans quoi `(?:x?)*` tournerait sans fin).
fn repete(n: &Noeud, min: usize, max: Option<usize>, c: &[char], i: usize, k: &mut dyn FnMut(usize) -> bool) -> bool {
    if max != Some(0)
        && un(n, c, i, &mut |j| {
            j != i && repete(n, min.saturating_sub(1), max.map(|m| m - 1), c, j, &mut *k)
        })
    {
        return true;
    }
    min == 0 && k(i)
}

/// Un pas dans un lot : clé d'objet ou rang dans un tableau.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Pas {
    Clef(String),
    Rang(usize),
}

/// Les mots-clés qui ne valident rien : annotations, ou vérifiés seulement par Rust (« x-verifie-en-rust »).
pub(super) const ANNOTATIONS: &[&str] = &[
    "$comment",
    "$id",
    "title",
    "description",
    "$defs",
    "x-voie",
    "x-verifie-en-rust",
    "x-lot-octets-max",
    "x-corps-octets-max",
];

/// Chaque motif du schéma, compilé une fois.
fn recueillir(v: &Value, motifs: &mut BTreeMap<String, Motif>) {
    match v {
        Value::Object(o) => {
            for (k, x) in o {
                if k == "pattern" {
                    let p = x.as_str().expect("pattern textuel");
                    motifs.insert(p.to_string(), Motif::new(p));
                } else {
                    recueillir(x, motifs);
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|x| recueillir(x, motifs)),
        _ => {}
    }
}

fn egaux(a: &Value, b: &Value) -> bool {
    match (a.as_f64(), b.as_f64()) {
        // Égalité exacte voulue : 2 et 2.0 sont le même nombre, 2 et 2.0000001 non.
        (Some(x), Some(y)) => x.total_cmp(&y).is_eq(),
        _ => a == b,
    }
}

/// Le schéma lu, motifs compilés une fois.
pub(super) struct Schema {
    pub(super) racine: Value,
    motifs: BTreeMap<String, Motif>,
}

impl Schema {
    pub(super) fn new(texte: &str) -> Schema {
        let racine: Value = serde_json::from_str(texte).expect("schema-envoi.json n'est pas du JSON");
        let mut motifs = BTreeMap::new();
        recueillir(&racine, &mut motifs);
        Schema { racine, motifs }
    }

    pub(super) fn def(&self, nom: &str) -> &Value {
        self.racine["$defs"]
            .get(nom)
            .unwrap_or_else(|| panic!("$defs/{nom} absent"))
    }

    pub(super) fn defs(&self) -> &serde_json::Map<String, Value> {
        self.racine["$defs"].as_object().expect("$defs")
    }

    pub(super) fn motif(&self, p: &str) -> &Motif {
        &self.motifs[p]
    }

    fn reference(&self, r: &Value) -> &Value {
        let r = r.as_str().expect("$ref textuel");
        let nom = r
            .strip_prefix("#/$defs/")
            .unwrap_or_else(|| panic!("$ref hors de $defs : {r}"));
        self.def(nom)
    }

    pub(super) fn valide(&self, v: &Value) -> bool {
        self.contre(&self.racine, v)
    }

    pub(super) fn valide_def(&self, nom: &str, v: &Value) -> bool {
        self.contre(self.def(nom), v)
    }

    /// Le schéma du dernier pas d'un chemin, avec les définitions qu'il désigne (`$ref` suivis).
    pub(super) fn feuille(&self, chemin: &[Pas]) -> Vec<&Value> {
        let mut courant = vec![&self.racine];
        for pas in chemin {
            let mut s = *courant.last().expect("chemin");
            while let Some(r) = s.get("$ref") {
                s = self.reference(r);
            }
            let suivant = match pas {
                Pas::Clef(k) => &s["properties"][k.as_str()],
                Pas::Rang(_) => &s["items"],
            };
            assert!(suivant.is_object(), "chemin hors du schéma : {chemin:?}");
            courant = vec![suivant];
        }
        while let Some(r) = courant.last().and_then(|s| s.get("$ref")) {
            courant.push(self.reference(r));
        }
        courant
    }

    fn contre(&self, s: &Value, v: &Value) -> bool {
        let o = s.as_object().expect("un schéma est un objet");
        o.iter().all(|(k, regle)| self.mot_cle(k, regle, o, v))
    }

    fn mot_cle(&self, k: &str, regle: &Value, o: &serde_json::Map<String, Value>, v: &Value) -> bool {
        let entier = |r: &Value| r.as_u64().expect("borne entière");
        // Les bornes du schéma tiennent dans 32 bits : exactes en f64.
        let reel = |r: &Value| f64::from(u32::try_from(entier(r)).expect("borne de 32 bits"));
        match k {
            _ if ANNOTATIONS.contains(&k) => true,
            "$ref" => self.contre(self.reference(regle), v),
            "type" => match regle.as_str().expect("type textuel") {
                // JSON Schema : un nombre sans partie fractionnaire est un entier, même écrit 1.0 (Rust, lui, le refuse).
                "integer" => v.as_f64().is_some_and(|f| f.fract() == 0.0),
                "string" => v.is_string(),
                "boolean" => v.is_boolean(),
                "object" => v.is_object(),
                "array" => v.is_array(),
                t => panic!("type {t} inconnu de l'essai"),
            },
            // Comme ajv et python-jsonschema : deux nombres égaux sont égaux, même écrits 2 et 2.0.
            "const" => egaux(v, regle),
            "enum" => regle.as_array().expect("enum").iter().any(|x| egaux(v, x)),
            "pattern" => v
                .as_str()
                .is_none_or(|t| self.motifs[regle.as_str().unwrap_or("")].accepte(t)),
            "maxLength" => v.as_str().is_none_or(|t| t.chars().count() as u64 <= entier(regle)),
            "minLength" => v.as_str().is_none_or(|t| t.chars().count() as u64 >= entier(regle)),
            "x-octets-max" => v.as_str().is_none_or(|t| t.len() as u64 <= entier(regle)),
            "minimum" => v.as_f64().is_none_or(|f| f >= reel(regle)),
            "maximum" => v.as_f64().is_none_or(|f| f <= reel(regle)),
            "minItems" => v.as_array().is_none_or(|a| a.len() as u64 >= entier(regle)),
            "maxItems" => v.as_array().is_none_or(|a| a.len() as u64 <= entier(regle)),
            "items" => v.as_array().is_none_or(|a| a.iter().all(|x| self.contre(regle, x))),
            "x-cle-unique" => v.as_array().is_none_or(|a| {
                let clefs: Vec<&str> = regle
                    .as_array()
                    .expect("x-cle-unique")
                    .iter()
                    .filter_map(Value::as_str)
                    .collect();
                let mut vues = BTreeSet::new();
                a.iter().all(|x| {
                    // Un champ absent compte comme une valeur : « null » (jamais écrit, refusé ailleurs).
                    let clef: Vec<String> = clefs
                        .iter()
                        .map(|c| x.get(*c).unwrap_or(&Value::Null).to_string())
                        .collect();
                    vues.insert(clef)
                })
            }),
            "properties" => v.as_object().is_none_or(|x| {
                let props = regle.as_object().expect("properties");
                x.iter()
                    .all(|(c, val)| props.get(c).is_none_or(|p| self.contre(p, val)))
            }),
            "additionalProperties" => {
                assert_eq!(
                    regle,
                    &Value::Bool(false),
                    "additionalProperties : seul false est permis"
                );
                v.as_object().is_none_or(|x| {
                    let props = o.get("properties").and_then(Value::as_object);
                    x.keys().all(|c| props.is_some_and(|p| p.contains_key(c)))
                })
            }
            "required" => v.as_object().is_none_or(|x| {
                regle
                    .as_array()
                    .expect("required")
                    .iter()
                    .all(|c| x.contains_key(c.as_str().unwrap_or("")))
            }),
            "minProperties" => v.as_object().is_none_or(|x| x.len() as u64 >= entier(regle)),
            autre => panic!("mot-clé « {autre} » inconnu de l'essai : à lui apprendre avant de l'employer"),
        }
    }
}

#[test]
fn le_lecteur_de_motifs_lit_comme_un_moteur() {
    let cas: &[(&str, &[&str], &[&str])] = &[
        (
            r"^[A-Z]{3}-[0-9]{3}$",
            &["ABC-123"],
            &["ABC-12", "abc-123", "ABC-1234", "ABC-123\n"],
        ),
        (r"^a(?:b|cd)*e?$", &["a", "abe", "acdbcd", "ae"], &["ac", "aee", "ba"]),
        (r"^(?=[^:]{1,3}:)[a-z]+:[0-9]$", &["ab:1", "abc:2"], &["abcd:1", ":1"]),
        (r"^[^\u0000-\u001f<>]+$", &["é a", "x"], &["", "a<b", "a\tb"]),
        (r"^(?:[a-z0-9-]{0,2}[a-z])?$", &["", "a", "a-b", "12z"], &["-", "abcd"]),
        (r"^\.\\\x41$", &[".\\A"], &["a\\A"]),
    ];
    for (motif, oui, non) in cas {
        let m = Motif::new(motif);
        for s in *oui {
            assert!(m.accepte(s), "{motif} devrait accepter {s:?}");
        }
        for s in *non {
            assert!(!m.accepte(s), "{motif} devrait refuser {s:?}");
        }
    }
    for hors in [r"\d", r"\w", r"a{2,}", r".", r"(a)", r"[a-b-c]", r"\-", "^?"] {
        assert!(
            std::panic::catch_unwind(|| Motif::new(hors)).is_err(),
            "{hors} devrait être refusé"
        );
    }
}

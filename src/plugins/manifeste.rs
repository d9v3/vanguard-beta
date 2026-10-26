//! Le manifeste d'un plugin (`plugin.toml`) : un petit sous-ensemble de TOML, lu par un analyseur maison borné. Pas de
//! dépendance de plus pour une dizaine de clés ; et un analyseur qui ne connaît que ces clés refuse tout le reste au
//! lieu de l'ignorer : une faute de frappe (« comande ») se voit, elle ne lance pas autre chose que prévu.
//!
//! Reconnu : commentaires `#`, clés nues, chaînes "…" (échappements \" \\ \n \t \r \uXXXX \UXXXXXXXX) et '…', entiers,
//! tableaux de chaînes (sur plusieurs lignes, virgule finale permise), sections `[linux]`, `[windows]`, `[macos]`.

use crate::modele::Echec;
use crate::{tr, trf};

/// Taille, lignes, longueur d'une chaîne et d'un tableau au plus : un manifeste en fait une fraction.
pub const OCTETS_MAX: usize = 16 << 10;
const LIGNES_MAX: usize = 200;
const CHAINE_MAX: usize = 1000;
const TABLEAU_MAX: usize = 32;
/// Délai d'un plugin, en secondes : par défaut, et au plus.
const DELAI_DEFAUT: u64 = 60;
const DELAI_MAX: u64 = 600;

/// Les mots de `vanguard plugins …` : un plugin ne peut pas porter leur nom.
pub const RESERVES: [&str; 10] = [
    "ajouter",
    "add",
    "approuver",
    "approve",
    "liste",
    "list",
    "retirer",
    "remove",
    "labo",
    "lab",
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Systeme {
    Linux,
    Windows,
    Macos,
}

impl Systeme {
    pub fn ici() -> Systeme {
        if cfg!(windows) {
            Systeme::Windows
        } else if cfg!(target_os = "macos") {
            Systeme::Macos
        } else {
            Systeme::Linux
        }
    }

    fn depuis(nom: &str) -> Option<Systeme> {
        match nom {
            "linux" => Some(Systeme::Linux),
            "windows" => Some(Systeme::Windows),
            "macos" => Some(Systeme::Macos),
            _ => None,
        }
    }

    pub fn nom(self) -> &'static str {
        match self {
            Systeme::Linux => "linux",
            Systeme::Windows => "windows",
            Systeme::Macos => "macos",
        }
    }
}

/// Le programme d'un système : son chemin relatif au sous-dossier et ses arguments fixes.
#[derive(Clone, Debug, PartialEq)]
pub struct Commande {
    pub programme: String,
    pub arguments: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Manifeste {
    pub nom: String,
    pub titre: [String; 2],
    pub description: [String; 2],
    pub systemes: Vec<Systeme>,
    pub delai: u64,
    /// `confiance = "totale"` : ce plugin tourne sans restrictions (voir `reglages`), comme si l'interrupteur était
    /// coupé pour lui seul.
    pub confiance_totale: bool,
    /// Sans restrictions seulement : il tourne aussi avec le bilan complet, ou avec la surveillance.
    pub dans_le_bilan: bool,
    pub dans_la_surveillance: bool,
    /// Qui l'a écrit et d'où il vient, tels que le manifeste les dit : jamais vérifiés.
    pub auteur: Option<String>,
    pub source: Option<String>,
    /// `cle_auteur` : la clé publique Ed25519 de l'auteur (64 chiffres hexadécimaux). Avec elle, le dossier doit porter
    /// `plugin.sig`, sa signature : l'auteur est alors vérifié (voir `plugins::auteur_verifie`), et une mise à jour
    /// signée par une autre clé se voit à l'approbation.
    pub cle_auteur: Option<[u8; 32]>,
    /// La commande commune, puis celle de chaque section `[système]`.
    commune: Option<Commande>,
    par_systeme: Vec<(Systeme, Commande)>,
}

impl Manifeste {
    /// Le titre dans la langue de l'interface.
    pub fn titre(&self) -> &str {
        &self.titre[usize::from(crate::langue::anglais())]
    }

    pub fn description(&self) -> &str {
        &self.description[usize::from(crate::langue::anglais())]
    }

    /// La commande à lancer sur `s` : celle de sa section, sinon la commune ; aucune si le plugin ne vise pas `s`.
    pub fn commande(&self, s: Systeme) -> Option<&Commande> {
        if !self.systemes.contains(&s) {
            return None;
        }
        self.par_systeme
            .iter()
            .find(|(x, _)| *x == s)
            .map(|(_, c)| c)
            .or(self.commune.as_ref())
    }
}

/// Une clé lue : sa section, son nom, sa valeur, sa ligne.
type Paire = (Option<String>, String, Valeur, usize);
/// La commande d'une section : son système (aucun : la commune), son programme, ses arguments.
type CommandeLue = (Option<Systeme>, Option<String>, Option<Vec<String>>);

#[derive(Debug, PartialEq)]
enum Valeur {
    Chaine(String),
    Entier(i64),
    Booleen(bool),
    Tableau(Vec<String>),
}

/// Le nom d'un plugin : une à 32 lettres minuscules, chiffres ou tirets, commençant par une lettre, et pas un mot de
/// la commande. Il sert de nom de dossier et d'argument : rien d'autre ne passe.
pub fn nom_valide(nom: &str) -> bool {
    (1..=32).contains(&nom.len())
        && nom.starts_with(|c: char| c.is_ascii_lowercase())
        && nom
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !RESERVES.contains(&nom)
}

/// Un chemin de programme relatif au sous-dossier, qui ne peut pas en sortir : ni absolu, ni lecteur (« C:x »), ni
/// « .. », ni « . », ni partie vide. Lu avec les deux séparateurs : un manifeste écrit sous Windows vaut ailleurs.
pub fn chemin_valide(chemin: &str) -> bool {
    !chemin.is_empty()
        && chemin.len() <= 200
        && !chemin.contains([':', '\0'])
        && !chemin.starts_with(['/', '\\'])
        && chemin
            .split(['/', '\\'])
            .all(|p| !p.is_empty() && p != "." && p != ".." && !nom_reserve(p))
}

/// Un nom que Windows prend pour un périphérique (CON, NUL, COM1…, aussi avec une extension : « CON.txt »), ou qui finit
/// par « . » ou une espace (Windows les retire, et deux noms deviennent un) : écrire dedans écrirait sur la console ou
/// sur un port, avant tout récapitulatif.
fn nom_reserve(partie: &str) -> bool {
    let base = partie.split('.').next().unwrap_or("").trim_end().to_ascii_uppercase();
    let peripherique = matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        || ((base.starts_with("COM") || base.starts_with("LPT"))
            && base.len() == 4
            && base[3..].chars().all(|c| c.is_ascii_digit() || "¹²³".contains(c)));
    peripherique || partie.ends_with(['.', ' '])
}

/// Le texte du manifeste, analysé et vérifié. L'erreur dit quoi et où, dans la langue de l'interface.
pub fn lire(texte: &str) -> Result<Manifeste, String> {
    if texte.len() > OCTETS_MAX {
        return Err(trf!(
            "manifeste trop long (plus de {} Kio)",
            "manifest too long (over {} KiB)",
            OCTETS_MAX >> 10
        ));
    }
    if texte.lines().count() > LIGNES_MAX {
        return Err(trf!(
            "manifeste trop long (plus de {LIGNES_MAX} lignes)",
            "manifest too long (over {LIGNES_MAX} lines)"
        ));
    }
    let paires = analyser(texte)?;
    construire(paires)
}

/// Les (section, clé, valeur, ligne) du texte, dans l'ordre.
fn analyser(texte: &str) -> Result<Vec<Paire>, String> {
    let mut l = Lecteur {
        c: texte.chars().collect(),
        i: 0,
        ligne: 1,
    };
    let mut section = None;
    let mut paires = Vec::new();
    loop {
        l.blancs(true);
        let Some(c) = l.voir() else { break };
        if c == '[' {
            l.i += 1;
            let nom = l.mot();
            l.blancs(false);
            if l.voir() != Some(']') || nom.is_empty() {
                return Err(l.erreur(tr!("section mal fermée", "badly closed section")));
            }
            l.i += 1;
            section = Some(nom);
        } else {
            let ligne = l.ligne;
            let cle = l.mot();
            if cle.is_empty() {
                return Err(l.erreur(tr!("clé attendue", "key expected")));
            }
            l.blancs(false);
            if l.voir() != Some('=') {
                return Err(l.erreur(tr!("« = » attendu", "“=” expected")));
            }
            l.i += 1;
            l.blancs(false);
            let valeur = l.valeur()?;
            paires.push((section.clone(), cle, valeur, ligne));
        }
        l.fin_de_ligne()?;
    }
    Ok(paires)
}

struct Lecteur {
    c: Vec<char>,
    i: usize,
    ligne: usize,
}

impl Lecteur {
    fn voir(&self) -> Option<char> {
        self.c.get(self.i).copied()
    }

    fn erreur(&self, quoi: &str) -> String {
        trf!("ligne {} : {quoi}", "line {}: {quoi}", self.ligne)
    }

    /// Passe les espaces et les commentaires ; aussi les sauts de ligne si `lignes`.
    fn blancs(&mut self, lignes: bool) {
        while let Some(c) = self.voir() {
            match c {
                ' ' | '\t' | '\r' => self.i += 1,
                '\n' if lignes => {
                    self.ligne += 1;
                    self.i += 1;
                }
                '#' => {
                    while self.voir().is_some_and(|c| c != '\n') {
                        self.i += 1;
                    }
                }
                _ => break,
            }
        }
    }

    /// Après une valeur ou une section : rien d'autre que des espaces et un commentaire jusqu'au saut de ligne.
    fn fin_de_ligne(&mut self) -> Result<(), String> {
        self.blancs(false);
        match self.voir() {
            None => Ok(()),
            Some('\n') => {
                self.i += 1;
                self.ligne += 1;
                Ok(())
            }
            Some(_) => Err(self.erreur(tr!("texte en trop", "unexpected text"))),
        }
    }

    fn mot(&mut self) -> String {
        let debut = self.i;
        while self
            .voir()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            self.i += 1;
        }
        self.c[debut..self.i].iter().collect()
    }

    fn valeur(&mut self) -> Result<Valeur, String> {
        match self.voir() {
            Some('"' | '\'') => self.chaine().map(Valeur::Chaine),
            Some('[') => {
                self.i += 1;
                let mut liste = Vec::new();
                loop {
                    self.blancs(true);
                    match self.voir() {
                        Some(']') => {
                            self.i += 1;
                            break;
                        }
                        Some('"' | '\'') => {
                            if liste.len() == TABLEAU_MAX {
                                return Err(self.erreur(&trf!(
                                    "tableau de plus de {TABLEAU_MAX} éléments",
                                    "array of more than {TABLEAU_MAX} items"
                                )));
                            }
                            liste.push(self.chaine()?);
                            self.blancs(true);
                            match self.voir() {
                                Some(',') => self.i += 1,
                                Some(']') => {}
                                _ => return Err(self.erreur(tr!("« , » ou « ] » attendu", "“,” or “]” expected"))),
                            }
                        }
                        _ => {
                            return Err(self.erreur(tr!(
                                "un tableau ne contient que des chaînes",
                                "an array holds only strings"
                            )));
                        }
                    }
                }
                Ok(Valeur::Tableau(liste))
            }
            Some('t' | 'f') => match self.mot().as_str() {
                "true" => Ok(Valeur::Booleen(true)),
                "false" => Ok(Valeur::Booleen(false)),
                _ => Err(self.erreur(tr!("true ou false attendu", "true or false expected"))),
            },
            Some(c) if c.is_ascii_digit() || c == '-' || c == '+' => {
                let debut = self.i;
                self.i += 1;
                while self.voir().is_some_and(|c| c.is_ascii_digit() || c == '_') {
                    self.i += 1;
                }
                let texte: String = self.c[debut..self.i].iter().filter(|c| **c != '_').collect();
                texte
                    .parse()
                    .map(Valeur::Entier)
                    .map_err(|_| self.erreur(tr!("nombre illisible", "unreadable number")))
            }
            _ => Err(self.erreur(tr!(
                "valeur attendue (chaîne, nombre ou tableau)",
                "value expected (string, number or array)"
            ))),
        }
    }

    fn chaine(&mut self) -> Result<String, String> {
        let guillemet = self.voir().unwrap_or('"');
        self.i += 1;
        let mut lu = String::new();
        loop {
            let Some(c) = self.voir() else {
                return Err(self.erreur(tr!("chaîne non fermée", "unclosed string")));
            };
            self.i += 1;
            match c {
                '\n' => return Err(self.erreur(tr!("chaîne non fermée", "unclosed string"))),
                _ if c == guillemet => break,
                '\\' if guillemet == '"' => {
                    let echappe = self.voir();
                    self.i += 1;
                    match echappe {
                        Some('"') => lu.push('"'),
                        Some('\\') => lu.push('\\'),
                        Some('n') => lu.push('\n'),
                        Some('t') => lu.push('\t'),
                        Some('r') => lu.push('\r'),
                        Some(u @ ('u' | 'U')) => {
                            let n = if u == 'u' { 4 } else { 8 };
                            let hex: String = self.c.iter().skip(self.i).take(n).collect();
                            self.i += n;
                            let car = (hex.len() == n)
                                .then(|| u32::from_str_radix(&hex, 16).ok())
                                .flatten()
                                .and_then(char::from_u32)
                                .ok_or_else(|| self.erreur(tr!("échappement illisible", "unreadable escape")))?;
                            lu.push(car);
                        }
                        _ => return Err(self.erreur(tr!("échappement inconnu", "unknown escape"))),
                    }
                }
                _ => lu.push(c),
            }
            if lu.chars().count() > CHAINE_MAX {
                return Err(self.erreur(&trf!(
                    "chaîne de plus de {CHAINE_MAX} caractères",
                    "string longer than {CHAINE_MAX} characters"
                )));
            }
        }
        if lu.contains('\0') {
            return Err(self.erreur(tr!("caractère nul", "null character")));
        }
        Ok(lu)
    }
}

/// Le contexte des refus du manifeste (`Echec`), rendus en texte par `construire`.
const CONTEXTE: &str = "plugins/manifeste";

/// Le texte d'une clé obligatoire qui manque.
fn manque(cle: &str) -> String {
    trf!("« {cle} » manque", "“{cle}” is missing")
}

/// Ce que les paires disent, avant les vérifications d'ensemble.
#[derive(Default)]
struct Lus {
    nom: Option<String>,
    titre: [Option<String>; 2],
    description: [Option<String>; 2],
    systemes: Option<Vec<String>>,
    delai: Option<i64>,
    auteur: Option<String>,
    source: Option<String>,
    cle_auteur: Option<[u8; 32]>,
    confiance_totale: bool,
    dans_le_bilan: bool,
    dans_la_surveillance: bool,
    commandes: Vec<CommandeLue>,
}

/// Les paires lues, vérifiées une à une, en manifeste.
fn construire(paires: Vec<Paire>) -> Result<Manifeste, String> {
    let lus = lire_paires(paires)?;
    let nom = lus.nom.ok_or_else(|| manque("nom"))?;
    if !nom_valide(&nom) {
        return Err(trf!(
            "nom « {} » refusé : 1 à 32 lettres minuscules, chiffres ou tirets, commençant par une lettre",
            "name “{}” refused: 1 to 32 lowercase letters, digits or dashes, starting with a letter",
            crate::ui::affichable(&nom)
        ));
    }
    let (titre, description) = textes_lus(lus.titre, lus.description, lus.auteur.as_ref(), lus.source.as_ref())?;
    let systemes = systemes_lus(lus.systemes)?;
    let delai = delai_lu(lus.delai)?;
    let (commune, par_systeme) = commandes_lues(lus.commandes)?;
    let m = Manifeste {
        nom,
        titre,
        description,
        systemes,
        delai,
        confiance_totale: lus.confiance_totale,
        dans_le_bilan: lus.dans_le_bilan,
        dans_la_surveillance: lus.dans_la_surveillance,
        auteur: lus.auteur,
        source: lus.source,
        cle_auteur: lus.cle_auteur,
        commune,
        par_systeme,
    };
    if let Some(s) = m.systemes.iter().find(|s| m.commande(**s).is_none()) {
        return Err(trf!("aucune commande pour {}", "no command for {}", s.nom()));
    }
    Ok(m)
}

/// Chaque paire rangée à sa place : une clé en double, une section ou une clé inconnue, une valeur du mauvais type
/// sont refusées, avec leur ligne.
fn lire_paires(paires: Vec<Paire>) -> Result<Lus, Echec> {
    let mut vues: Vec<(Option<String>, String)> = Vec::new();
    let mut lus = Lus::default();
    for (section, cle, valeur, ligne) in paires {
        let erreur = |quoi: &str| trf!("ligne {ligne} : {quoi}", "line {ligne}: {quoi}");
        if vues.contains(&(section.clone(), cle.clone())) {
            return Err(Echec::refuse(
                CONTEXTE,
                erreur(&trf!("« {cle} » en double", "“{cle}” given twice")),
            ));
        }
        vues.push((section.clone(), cle.clone()));
        let systeme = match &section {
            None => None,
            Some(s) => Some(Systeme::depuis(s).ok_or_else(|| {
                Echec::refuse(
                    CONTEXTE,
                    erreur(&trf!(
                        "section inconnue « {s} » (linux, windows ou macos)",
                        "unknown section “{s}” (linux, windows or macos)"
                    )),
                )
            })?),
        };
        let place = if let Some(i) = lus.commandes.iter().position(|(s, _, _)| *s == systeme) {
            i
        } else {
            lus.commandes.push((systeme, None, None));
            lus.commandes.len() - 1
        };
        ranger(&mut lus, systeme.is_some(), &cle, valeur, place)
            .map_err(|quoi| Echec::refuse(CONTEXTE, erreur(&String::from(quoi))))?;
    }
    Ok(lus)
}

/// Une paire à sa place dans `lus` (`place` : la commande de sa section) ; l'erreur sans sa ligne.
fn ranger(lus: &mut Lus, dans_une_section: bool, cle: &str, valeur: Valeur, place: usize) -> Result<(), Echec> {
    let chaine = |v: Valeur| match v {
        Valeur::Chaine(s) => Ok(s),
        _ => Err(Echec::refuse(
            CONTEXTE,
            trf!("« {cle} » doit être une chaîne", "“{cle}” must be a string"),
        )),
    };
    match (dans_une_section, cle) {
        (_, "commande") => lus.commandes[place].1 = Some(chaine(valeur)?),
        (_, "arguments") => match valeur {
            Valeur::Tableau(t) => lus.commandes[place].2 = Some(t),
            _ => {
                return Err(Echec::refuse(
                    CONTEXTE,
                    tr!(
                        "« arguments » doit être un tableau de chaînes",
                        "“arguments” must be an array of strings"
                    )
                    .to_string(),
                ));
            }
        },
        (false, "nom") => lus.nom = Some(chaine(valeur)?),
        (false, "titre_fr") => lus.titre[0] = Some(chaine(valeur)?),
        (false, "titre_en") => lus.titre[1] = Some(chaine(valeur)?),
        (false, "description_fr") => lus.description[0] = Some(chaine(valeur)?),
        (false, "description_en") => lus.description[1] = Some(chaine(valeur)?),
        (false, "confiance") => match chaine(valeur)?.as_str() {
            "totale" => lus.confiance_totale = true,
            "normale" => lus.confiance_totale = false,
            _ => {
                return Err(Echec::refuse(
                    CONTEXTE,
                    tr!(
                        "« confiance » : \"totale\" ou \"normale\"",
                        "“confiance”: \"totale\" or \"normale\""
                    )
                    .to_string(),
                ));
            }
        },
        (false, cle @ ("dans_le_bilan" | "dans_la_surveillance")) => {
            let Valeur::Booleen(b) = valeur else {
                return Err(Echec::refuse(
                    CONTEXTE,
                    trf!("« {cle} » : true ou false", "“{cle}”: true or false"),
                ));
            };
            if cle == "dans_le_bilan" {
                lus.dans_le_bilan = b;
            } else {
                lus.dans_la_surveillance = b;
            }
        }
        (false, "auteur") => lus.auteur = Some(chaine(valeur)?),
        (false, "source") => lus.source = Some(chaine(valeur)?),
        (false, "cle_auteur") => lus.cle_auteur = Some(cle_publique(&chaine(valeur)?)?),
        (false, "systemes") => match valeur {
            Valeur::Tableau(t) => lus.systemes = Some(t),
            _ => {
                return Err(Echec::refuse(
                    CONTEXTE,
                    tr!("« systemes » doit être un tableau", "“systemes” must be an array").to_string(),
                ));
            }
        },
        (false, "delai") => match valeur {
            Valeur::Entier(n) => lus.delai = Some(n),
            _ => {
                return Err(Echec::refuse(
                    CONTEXTE,
                    tr!("« delai » doit être un nombre", "“delai” must be a number").to_string(),
                ));
            }
        },
        _ => {
            return Err(Echec::refuse(
                CONTEXTE,
                trf!("clé inconnue « {cle} »", "unknown key “{cle}”"),
            ));
        }
    }
    Ok(())
}

/// La clé publique Ed25519 de l'auteur, en 64 chiffres hexadécimaux.
fn cle_publique(hex: &str) -> Result<[u8; 32], Echec> {
    let mut cle = [0u8; 32];
    let lue = hex.len() == 64
        && cle.iter_mut().enumerate().all(|(i, o)| {
            hex.get(2 * i..2 * i + 2)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .map(|v| *o = v)
                .is_some()
        });
    if lue {
        Ok(cle)
    } else {
        Err(Echec::refuse(
            CONTEXTE,
            tr!(
                "« cle_auteur » : la clé publique Ed25519, en 64 chiffres hexadécimaux",
                "“cle_auteur”: the Ed25519 public key, as 64 hexadecimal digits"
            )
            .to_string(),
        ))
    }
}

/// Les titres et descriptions dans les deux langues, présents et pas trop longs ; l'auteur et la source pas trop
/// longs non plus.
fn textes_lus(
    titre: [Option<String>; 2],
    description: [Option<String>; 2],
    auteur: Option<&String>,
    source: Option<&String>,
) -> Result<([String; 2], [String; 2]), Echec> {
    let [Some(titre_fr), Some(titre_en)] = titre else {
        return Err(Echec::refuse(
            CONTEXTE,
            manque(if titre[0].is_none() { "titre_fr" } else { "titre_en" }),
        ));
    };
    let [Some(description_fr), Some(description_en)] = description else {
        return Err(Echec::refuse(
            CONTEXTE,
            manque(if description[0].is_none() {
                "description_fr"
            } else {
                "description_en"
            }),
        ));
    };
    for (cle, texte, max) in [
        ("titre_fr", &titre_fr, 60),
        ("titre_en", &titre_en, 60),
        ("description_fr", &description_fr, 300),
        ("description_en", &description_en, 300),
    ] {
        if texte.trim().is_empty() || texte.chars().count() > max {
            return Err(Echec::refuse(
                CONTEXTE,
                trf!(
                    "« {cle} » vide ou de plus de {max} caractères",
                    "“{cle}” empty or longer than {max} characters"
                ),
            ));
        }
    }
    for (cle, texte, max) in [("auteur", auteur, 100), ("source", source, 300)] {
        if texte.is_some_and(|t| t.chars().count() > max) {
            return Err(Echec::refuse(
                CONTEXTE,
                trf!(
                    "« {cle} » de plus de {max} caractères",
                    "“{cle}” longer than {max} characters"
                ),
            ));
        }
    }
    Ok(([titre_fr, titre_en], [description_fr, description_en]))
}

/// Les systèmes nommés, connus, sans doublon, au moins un.
fn systemes_lus(systemes: Option<Vec<String>>) -> Result<Vec<Systeme>, Echec> {
    let mut liste = Vec::new();
    for s in systemes.ok_or_else(|| Echec::refuse(CONTEXTE, manque("systemes")))? {
        let s = Systeme::depuis(&s).ok_or_else(|| {
            Echec::refuse(
                CONTEXTE,
                trf!(
                    "système inconnu « {} » (linux, windows ou macos)",
                    "unknown system “{}” (linux, windows or macos)",
                    crate::ui::affichable(&s)
                ),
            )
        })?;
        if !liste.contains(&s) {
            liste.push(s);
        }
    }
    if liste.is_empty() {
        return Err(Echec::refuse(
            CONTEXTE,
            tr!("« systemes » est vide", "“systemes” is empty").to_string(),
        ));
    }
    Ok(liste)
}

/// Le délai donné (de 1 à `DELAI_MAX` secondes), ou celui par défaut.
fn delai_lu(delai: Option<i64>) -> Result<u64, Echec> {
    match delai {
        None => Ok(DELAI_DEFAUT),
        Some(n) => u64::try_from(n)
            .ok()
            .filter(|n| (1..=DELAI_MAX).contains(n))
            .ok_or_else(|| {
                Echec::refuse(
                    CONTEXTE,
                    trf!(
                        "« delai » : de 1 à {DELAI_MAX} secondes",
                        "“delai”: from 1 to {DELAI_MAX} seconds"
                    ),
                )
            }),
    }
}

/// La commande commune, et celles propres à un système.
type Commandes = (Option<Commande>, Vec<(Systeme, Commande)>);

/// La commande commune et celles de chaque système : un chemin relatif au dossier du plugin, sans « .. » ; des
/// arguments sans commande sont refusés.
fn commandes_lues(commandes: Vec<CommandeLue>) -> Result<Commandes, Echec> {
    let mut commune = None;
    let mut par_systeme = Vec::new();
    for (systeme, programme, arguments) in commandes {
        let Some(programme) = programme else {
            if arguments.is_some() {
                return Err(Echec::refuse(CONTEXTE, manque("commande")));
            }
            continue;
        };
        if !chemin_valide(&programme) {
            return Err(Echec::refuse(
                CONTEXTE,
                trf!(
                    "commande « {} » refusée : un chemin relatif au dossier du plugin, sans « .. »",
                    "command “{}” refused: a path relative to the plugin's folder, without “..”",
                    crate::ui::affichable(&programme)
                ),
            ));
        }
        let c = Commande {
            programme,
            arguments: arguments.unwrap_or_default(),
        };
        match systeme {
            None => commune = Some(c),
            Some(s) => par_systeme.push((s, c)),
        }
    }
    Ok((commune, par_systeme))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXEMPLE: &str = r#"
# Un plugin d'essai.
nom = "salon-test"
titre_fr = "Essai du salon"
titre_en = 'Living room test'
description_fr = "Deux constats inventés \u00e9crits \"ici\"."
description_en = "Two made-up findings."
auteur = "alice"
source = "https://exemple.org/salon"
systemes = [
  "linux",   # le script shell
  "macos",
  "windows",
]
delai = 20
commande = "essai.sh"
arguments = ["--bonjour", "alice"]

[windows]
commande = 'essai.ps1'
"#;

    #[test]
    fn un_manifeste_complet_se_lit() {
        let m = lire(EXEMPLE).unwrap();
        assert_eq!(m.nom, "salon-test");
        assert_eq!(m.titre, ["Essai du salon".to_string(), "Living room test".to_string()]);
        assert_eq!(m.description[0], "Deux constats inventés écrits \"ici\".");
        assert_eq!(m.systemes, [Systeme::Linux, Systeme::Macos, Systeme::Windows]);
        assert_eq!(m.delai, 20);
        assert!(!m.confiance_totale && !m.dans_le_bilan);
        let m2 =
            lire(&EXEMPLE.replace("delai = 20", "delai = 20\nconfiance = \"totale\"\ndans_le_bilan = true")).unwrap();
        assert!(m2.confiance_totale && m2.dans_le_bilan && !m2.dans_la_surveillance);
        assert!(lire(&EXEMPLE.replace("delai = 20", "dans_le_bilan = vrai")).is_err());
        assert!(lire(&EXEMPLE.replace("delai = 20", "confiance = \"aveugle\"")).is_err());
        assert_eq!(
            (m.auteur.as_deref(), m.source.as_deref()),
            (Some("alice"), Some("https://exemple.org/salon"))
        );
        let linux = m.commande(Systeme::Linux).unwrap();
        assert_eq!(linux.programme, "essai.sh");
        assert_eq!(linux.arguments, ["--bonjour", "alice"]);
        // La section remplace la commande commune, arguments compris.
        let windows = m.commande(Systeme::Windows).unwrap();
        assert_eq!((windows.programme.as_str(), windows.arguments.len()), ("essai.ps1", 0));
    }

    #[test]
    fn un_chemin_qui_sort_du_dossier_est_refuse() {
        for refuse in [
            "/bin/sh",
            "\\\\serveur\\x.exe",
            "C:\\Windows\\x.exe",
            "C:x.exe",
            "../x.sh",
            "a/../../x",
            "a\\..\\x",
            "./x.sh",
            "a//x",
            "",
        ] {
            assert!(!chemin_valide(refuse), "{refuse}");
            let texte = EXEMPLE.replace("commande = \"essai.sh\"", &format!("commande = '{refuse}'"));
            assert!(lire(&texte).is_err(), "{refuse}");
        }
        assert!(chemin_valide("bin/essai.sh") && chemin_valide("outils\\essai.exe"));
        for reserve in ["CON", "x/nul", "con.txt", "a/COM1", "LPT9.log", "CONOUT$", "a.", "b "] {
            assert!(!chemin_valide(reserve), "{reserve}");
        }
        assert!(chemin_valide("console.sh") && chemin_valide("com10/x") && chemin_valide("nullite.txt"));
    }

    #[test]
    fn noms_refuses() {
        for refuse in [
            "",
            "Salon",
            "1salon",
            "-x",
            "salon_test",
            "ajouter",
            "list",
            "a b",
            "é",
            &"a".repeat(33),
        ] {
            assert!(!nom_valide(refuse), "{refuse}");
        }
        assert!(nom_valide("salon-2"));
    }

    #[test]
    fn un_manifeste_douteux_est_refuse_avec_sa_ligne() {
        let avant = |ajout: &str| EXEMPLE.replace("[windows]", &format!("{ajout}\n[windows]"));
        let delai = |d: &str| EXEMPLE.replace("delai = 20", d);
        let cas = [
            (avant("comande = \"x\""), "clé inconnue"),
            (delai("delai = 0"), "delai"),
            (delai("delai = 601"), "delai"),
            (delai("delai = \"20\""), "nombre"),
            (avant("nom = \"autre\""), "double"),
            (avant("[bsd]\ncommande = \"x\""), "section inconnue"),
            (avant("systemes2 = []"), "clé inconnue"),
            (format!("{EXEMPLE}\nnom = \"x\"\n"), "clé inconnue"),
            (avant("x = \"non fermée"), "non fermée"),
            (avant("x = \"\\q\""), "échappement"),
            (avant("[windows"), "section"),
            (avant("titre_fr = \"a\" b"), "en trop"),
        ];
        for (texte, attendu) in cas {
            let e = lire(&texte).unwrap_err();
            assert!(e.contains(attendu), "{texte} → {e}");
        }
        // Une erreur de syntaxe dit sa ligne.
        assert!(
            lire("nom = \"salon\"\n\ncomande = \"x\"")
                .unwrap_err()
                .starts_with("ligne 3 : ")
        );
        // Un système visé sans commande, une clé manquante, un système inconnu, trop long.
        let sans_commune = EXEMPLE
            .replace("commande = \"essai.sh\"\n", "")
            .replace("arguments = [\"--bonjour\", \"alice\"]\n", "");
        assert!(lire(&sans_commune).unwrap_err().contains("aucune commande pour linux"));
        assert!(
            lire(&EXEMPLE.replace("titre_en", "# titre_en"))
                .unwrap_err()
                .contains("titre_en")
        );
        assert!(
            lire(&EXEMPLE.replace("\"macos\"", "\"bsd\""))
                .unwrap_err()
                .contains("bsd")
        );
        assert!(lire(&format!("{EXEMPLE}{}", "#\n".repeat(LIGNES_MAX))).is_err());
        let long = format!("{EXEMPLE}x = \"{}\"\n", "a".repeat(OCTETS_MAX));
        assert!(lire(&long).unwrap_err().contains("trop long"));
        let tableau = format!("[linux]\narguments = [{}]", vec!["\"a\""; TABLEAU_MAX + 1].join(","));
        assert!(lire(&format!("{EXEMPLE}{tableau}")).unwrap_err().contains("tableau"));
    }

    #[test]
    fn un_systeme_non_vise_n_a_pas_de_commande() {
        let m = lire(&EXEMPLE.replace("  \"macos\",\n", "")).unwrap();
        assert!(m.commande(Systeme::Macos).is_none());
        assert!(m.commande(Systeme::Linux).is_some());
    }
}

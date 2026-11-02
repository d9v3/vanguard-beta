//! La voie ouverte de l'auto-amélioration (plan, §0 et §1) : noms et versions de logiciels, textes d'erreur. Elle est
//! gardée, envoyée et lue par l'auteur, mais elle vient de l'ordinateur : un texte d'erreur peut porter un chemin, une
//! adresse, un jeton collé dans une commande, ou une phrase écrite pour piloter une IA. Rien n'en sort sans passer ici.
//!
//! Pourquoi un fichier à part, pur et sans aucun `crate::` : il entre tel quel dans le banc de fuzzing (fuzz/). Le
//! retrait des noms de la personne et de la machine (`journal::anonymiser`, qui lit la base des appareils) se fait
//! avant, dans `amelioration::texte`.
//!
//! Le principe : rien n'est gardé parce qu'il « a l'air sain ». Ce qui ressemble à un secret est remplacé ; un texte
//! où le détecteur sonne trop, ou qui n'est presque plus fait de mots, est jeté en entier (seul le compte des refus
//! monte) ; ce qui reste n'a que des lettres, des chiffres et une ponctuation sans effet dans le Markdown, le HTML ou
//! un terminal.
//!
//! Ce que ce nettoyage ne fait pas, et que l'usage doit porter :
//! - Une consigne écrite en clair (« ignore les instructions précédentes ») reste une phrase permise. Qui présente
//!   ces textes à une IA les donne comme des données, entre délimiteurs ou dans un bloc de code, avec la consigne de
//!   ne jamais les suivre ; jamais en début de ligne Markdown, où « # », « - » ou « 1. » prendraient un sens.
//! - Un secret sans mot-clé ni forme reconnaissable passe : une phrase de passe en mots ordinaires, un mot de passe
//!   d'application en quatre mots de quatre lettres séparés par des espaces, un mot de passe fait de lettres seules
//!   après une option sans `=` (`-p motdepasse`, pris pour un mot de la phrase), un mot de passe collé à son option (`mysql -pXXXX`), donné à `net use` sans option, ou lu
//!   dans un fichier `.pgpass` ou `.netrc` (« hôte:port:base:nom:mdp »).
//! - Les signes combinants hors du bloc U+0300 à U+036F sont remplacés par une espace, pas comptés à part.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

/// Bornes des types, en octets (plan, §1).
pub(crate) const TEXTE_MAX: usize = 300;
pub(crate) const NOM_MAX: usize = 64;
pub(crate) const VERSION_MAX: usize = 32;

/// Ce qui est lu d'un texte brut : au-delà, le reste n'atteindrait jamais les 300 octets gardés, et le coût du
/// nettoyage reste borné quoi qu'on lui donne.
const ENTREE_MAX: usize = 8192;
/// Un texte où le détecteur de secrets a sonné plus de fois que cela est jeté en entier (plan, §1, étape 6).
const ALERTES_MAX: u32 = 3;
/// Le nettoyage est refait jusqu'à ne plus rien changer : une sortie relue donne la même sortie. Au-delà de ce nombre
/// de passes sans point fixe, le texte est jeté.
const PASSES_MAX: usize = 4;
/// Une suite d'au moins cette longueur, d'entropie au-dessus du seuil (bits par caractère), passe pour un jeton.
const ENTROPIE_LONGUEUR: usize = 20;
const ENTROPIE_SEUIL: f64 = 3.5;
/// Un segment de chemin peut contenir des espaces (« Mes Documents ») jusqu'à cette longueur.
const SEGMENT_MAX: usize = 64;

/// Les textes, noms et versions jetés depuis le lancement : le seul signe qu'un refus laisse (plan, `refus_locaux`).
static REFUS: AtomicU64 = AtomicU64::new(0);

/// Le nombre de refus depuis le lancement du programme.
pub(crate) fn refus_locaux() -> u64 {
    REFUS.load(Ordering::Relaxed)
}

/// Compte un refus et le rend. Un texte vide n'est pas un refus : il n'y avait rien à garder.
pub(crate) fn compter(rejet: Rejet) -> Rejet {
    if rejet != Rejet::Vide {
        REFUS.fetch_add(1, Ordering::Relaxed);
    }
    rejet
}

/// Pourquoi un texte de la voie ouverte n'est pas gardé.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Rejet {
    /// Rien ne reste après le nettoyage.
    Vide,
    /// Le détecteur de secrets a sonné plus de `ALERTES_MAX` fois : le reste du texte n'est plus digne de confiance.
    Secrets,
    /// Moins de la moitié de lettres : un vidage, du binaire ou du code, pas un message.
    PeuDeLettres,
    /// Le nettoyage ne trouve pas son point fixe : jeté plutôt que gardé à moitié nettoyé.
    Instable,
    /// Un nom sans lettre, une version qui ne commence pas par un chiffre ou qui porte autre chose qu'une version.
    Forme,
}

/// Les quatre types de la voie ouverte : une chaîne qu'on ne construit que par `nettoyer` ou `lire`, et que serde ne
/// relit qu'après la même vérification (un lot relu chez l'auteur repasse le contrôle).
macro_rules! chaine_verifiee {
    ($(#[$doc:meta])* $nom:ident, $quoi:literal) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub(crate) struct $nom(String);

        impl $nom {
            pub(crate) fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $nom {
            type Error = &'static str;
            fn try_from(s: String) -> Result<Self, Self::Error> {
                Self::lire(&s).ok_or($quoi)
            }
        }

        impl From<$nom> for String {
            fn from(t: $nom) -> String {
                t.0
            }
        }
    };
}

chaine_verifiee!(
    /// Un texte d'erreur nettoyé : 300 octets au plus, aucun secret reconnu, caractères permis seulement.
    TexteNettoye,
    "texte non nettoyé"
);
chaine_verifiee!(
    /// Le nom d'un logiciel, d'un service ou d'un pilote : 64 octets au plus, au moins une lettre, nettoyé comme un texte.
    NomLogiciel,
    "nom de logiciel non nettoyé"
);
chaine_verifiee!(
    /// La version d'un logiciel tiers : 32 octets au plus, commence par un chiffre, chiffres, lettres ASCII et `.-+_:`.
    VersionTierce,
    "version tierce non valide"
);
chaine_verifiee!(
    /// L'empreinte d'un texte nettoyé, chiffres remplacés : 16 caractères hexadécimaux. Elle regroupe les erreurs de même
    /// forme (« délai de 30 s » et « délai de 45 s ») et voyage en voie fermée.
    Gabarit,
    "gabarit non valide"
);

impl TexteNettoye {
    /// Un texte brut, déjà passé par `journal::anonymiser`, nettoyé ; un refus est compté.
    pub(crate) fn nettoyer(brut: &str) -> Result<TexteNettoye, Rejet> {
        passer(brut, TEXTE).map(TexteNettoye).map_err(compter)
    }

    /// Un texte déjà nettoyé, relu (lot, fichier) : gardé seulement si le nettoyage le rendrait tel quel.
    pub(crate) fn lire(s: &str) -> Option<TexteNettoye> {
        passer(s, TEXTE).ok().filter(|t| t == s).map(TexteNettoye)
    }
}

impl NomLogiciel {
    pub(crate) fn nettoyer(brut: &str) -> Result<NomLogiciel, Rejet> {
        passer(brut, NOM).map(NomLogiciel).map_err(compter)
    }

    pub(crate) fn lire(s: &str) -> Option<NomLogiciel> {
        passer(s, NOM).ok().filter(|t| t == s).map(NomLogiciel)
    }
}

impl VersionTierce {
    /// Le premier mot du texte, sans « v » devant ; `~` (versions de Debian) devient `-`, qui ne barre rien dans le
    /// Markdown. Coupée à 32 octets. Refusée si elle ne commence pas par un chiffre, ou si le nettoyage d'un texte y
    /// changerait quoi que ce soit (jeton, longue suite hexadécimale, adresse).
    pub(crate) fn nettoyer(brut: &str) -> Result<VersionTierce, Rejet> {
        let mot = brut.split_whitespace().next().unwrap_or("");
        let mot = match mot.strip_prefix(['v', 'V']) {
            Some(reste) if reste.starts_with(|x: char| x.is_ascii_digit()) => reste,
            _ => mot,
        };
        if mot.is_empty() {
            return Err(Rejet::Vide);
        }
        let mot: String = mot
            .chars()
            .map(|x| if x == '~' { '-' } else { x })
            .take(VERSION_MAX)
            .collect();
        let mot = mot.trim_end_matches(['.', '-', '+', '_', ':']);
        if !mot.starts_with(|x: char| x.is_ascii_digit())
            || !mot.chars().all(version_permis)
            || !lettres_de_version(mot)
        {
            return Err(compter(Rejet::Forme));
        }
        match passer(mot, VERSION) {
            Ok(t) if t == mot => Ok(VersionTierce(t)),
            _ => Err(compter(Rejet::Forme)),
        }
    }

    pub(crate) fn lire(s: &str) -> Option<VersionTierce> {
        let v = s.len() <= VERSION_MAX
            && s.starts_with(|x: char| x.is_ascii_digit())
            && s.chars().all(version_permis)
            && lettres_de_version(s)
            && !s.ends_with(['.', '-', '+', '_', ':']);
        (v && passer(s, VERSION).ok().as_deref() == Some(s)).then(|| VersionTierce(s.to_string()))
    }
}

/// Au plus 10 lettres de suite et 16 en tout : « 1.2.3-beta.4+build » passe, une phrase ou un secret en lettres
/// déguisé en version (« 1-motdepassesecret… ») non.
fn lettres_de_version(s: &str) -> bool {
    let (mut suite, mut total) = (0usize, 0usize);
    for x in s.chars() {
        if x.is_ascii_alphabetic() {
            suite = suite.saturating_add(1);
            total = total.saturating_add(1);
            if suite > 10 || total > 16 {
                return false;
            }
        } else {
            suite = 0;
        }
    }
    true
}

fn version_permis(x: char) -> bool {
    x.is_ascii_alphanumeric() || ".-+_:".contains(x)
}

impl Gabarit {
    /// Chaque suite de chiffres devient un seul 0, puis SHA-256, dont on garde 8 octets : stable d'une version et d'une
    /// machine à l'autre (pas le hachage de la bibliothèque standard, qui change), et sans retour possible au texte.
    pub(crate) fn de(t: &TexteNettoye) -> Gabarit {
        let mut forme = String::with_capacity(t.0.len());
        let mut dans_nombre = false;
        for x in t.0.chars() {
            if x.is_ascii_digit() {
                if !dans_nombre {
                    forme.push('0');
                }
                dans_nombre = true;
            } else {
                dans_nombre = false;
                forme.push(x);
            }
        }
        let empreinte = sha2::Sha256::digest(forme.as_bytes());
        Gabarit(empreinte.iter().take(8).fold(String::with_capacity(16), |mut s, o| {
            let _ = write!(s, "{o:02x}");
            s
        }))
    }

    pub(crate) fn lire(s: &str) -> Option<Gabarit> {
        (s.len() == 16 && s.bytes().all(|o| o.is_ascii_digit() || (b'a'..=b'f').contains(&o)))
            .then(|| Gabarit(s.to_string()))
    }
}

/// Ce que demande chaque type : sa borne, si les adresses IP sont masquées, la part de lettres exigée.
#[derive(Clone, Copy)]
struct Forme {
    max: usize,
    ip: bool,
    lettres: Lettres,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Lettres {
    /// Au moins la moitié des caractères visibles (plan, étape 6).
    Moitie,
    /// Au moins une : un nom court comme « 7-Zip » n'en a pas la moitié.
    Une,
    /// Une version n'en a pas besoin.
    Aucune,
}

const TEXTE: Forme = Forme {
    max: TEXTE_MAX,
    ip: true,
    lettres: Lettres::Moitie,
};
const NOM: Forme = Forme {
    max: NOM_MAX,
    ip: true,
    lettres: Lettres::Une,
};
// « 10.0.19041.1 » a la forme d'une adresse IPv4 : une version ne passe pas par ce masque.
const VERSION: Forme = Forme {
    max: VERSION_MAX,
    ip: false,
    lettres: Lettres::Aucune,
};

/// Le nettoyage complet, sans compter le refus : passes jusqu'au point fixe, puis les deux jugements de l'étape 6.
fn passer(brut: &str, forme: Forme) -> Result<String, Rejet> {
    let mut t = normaliser(borne_entree(brut));
    let mut alertes: u32 = 0;
    let mut stable = false;
    for _ in 0..PASSES_MAX {
        let (s, a) = passe(&t, forme);
        alertes = alertes.saturating_add(a);
        if s == t {
            stable = true;
            break;
        }
        t = s;
    }
    if !stable {
        return Err(Rejet::Instable);
    }
    if t.is_empty() {
        return Err(Rejet::Vide);
    }
    if alertes > ALERTES_MAX {
        return Err(Rejet::Secrets);
    }
    if t.split(|x| x.is_whitespace()).any(ecritures_melees) {
        return Err(Rejet::Forme);
    }
    let lettres = t.iter().filter(|x| x.is_alphabetic()).count();
    let visibles = t.iter().filter(|x| !x.is_whitespace()).count();
    let assez = match forme.lettres {
        Lettres::Moitie => lettres.saturating_mul(2) >= visibles,
        Lettres::Une => lettres > 0,
        Lettres::Aucune => true,
    };
    if !assez {
        return Err(Rejet::PeuDeLettres);
    }
    Ok(t.into_iter().collect())
}

/// Une passe : les étapes 2 à 5 du plan, puis la coupe. Les couches précises du détecteur (blocs PEM, préfixes
/// connus, `clé = valeur`) tournent aussi avant les chemins et les adresses : un masque de chemin ou d'adresse ne
/// coupe ainsi jamais un secret en deux en laissant un morceau en clair. L'entropie vient après, quand chemins,
/// adresses et suites hexadécimales sont déjà des marqueurs (sinon un long chemin passerait pour un jeton).
fn passe(c: &[char], forme: Forme) -> (Vec<char>, u32) {
    let mut alertes = 0;
    let c = couche_precise(c, &mut alertes);
    let c = masquer_arobases(&c);
    let c = masquer_formes(&c, forme.ip);
    let c = couche_precise(&c, &mut alertes);
    let c = couche_entropie(&c, &mut alertes);
    let c = filtrer(&c);
    (couper(&c, forme.max), alertes)
}

/// Un mot qui mêle des lettres latines à des lettres cyrilliques ou grecques : « pаssword » avec un а cyrillique
/// échappe aux mots-clés tout en se lisant comme l'original. Un mot entièrement grec ou cyrillique passe.
fn ecritures_melees(mot: &[char]) -> bool {
    let latin = |x: &char| {
        x.is_ascii_alphabetic() || ('\u{00C0}'..='\u{024F}').contains(x) || ('\u{1E00}'..='\u{1EFF}').contains(x)
    };
    let autre = |x: &char| {
        ('\u{0370}'..='\u{03FF}').contains(x)
            || ('\u{0400}'..='\u{052F}').contains(x)
            || ('\u{1F00}'..='\u{1FFF}').contains(x)
    };
    mot.iter().any(latin) && mot.iter().any(autre)
}

// --- Outils de lecture -------------------------------------------------------------------------------------------

fn car(c: &[char], i: usize) -> Option<char> {
    c.get(i).copied()
}

fn avant(c: &[char], i: usize) -> Option<char> {
    i.checked_sub(1).and_then(|j| car(c, j))
}

/// L'indice suivant : jamais au-delà de la longueur du texte, qui tient en mémoire, donc jamais près de `usize::MAX`.
fn suivant(i: usize) -> usize {
    i.saturating_add(1)
}

fn plus(i: usize, n: usize) -> usize {
    i.saturating_add(n)
}

/// La longueur de `debut..fin` (fin ≥ debut partout où elle sert).
fn entre(debut: usize, fin: usize) -> usize {
    fin.saturating_sub(debut)
}

fn commence_par(c: &[char], i: usize, motif: &str) -> bool {
    let mut j = i;
    for m in motif.chars() {
        if car(c, j) != Some(m) {
            return false;
        }
        j = suivant(j);
    }
    true
}

fn commence_par_sans_casse(c: &[char], i: usize, motif: &str) -> bool {
    let mut j = i;
    for m in motif.chars() {
        if car(c, j).is_none_or(|x| x.to_ascii_lowercase() != m) {
            return false;
        }
        j = suivant(j);
    }
    true
}

fn fin_tant_que(c: &[char], i: usize, p: impl Fn(char) -> bool) -> usize {
    let mut j = i;
    while car(c, j).is_some_and(&p) {
        j = suivant(j);
    }
    j
}

fn chercher(c: &[char], depuis: usize, motif: &str) -> Option<usize> {
    let mut i = depuis;
    while i < c.len() {
        if commence_par_sans_casse(c, i, motif) {
            return Some(i);
        }
        i = suivant(i);
    }
    None
}

fn morceau(c: &[char], debut: usize, fin: usize) -> &[char] {
    c.get(debut..fin).unwrap_or(&[])
}

fn chaine(c: &[char], debut: usize, fin: usize) -> String {
    morceau(c, debut, fin).iter().collect()
}

/// L'alphabet des jetons (base64, base64url, hexadécimal) : celui de la couche d'entropie du plan. Aucune autre étape
/// ne commence ni ne finit un masque au milieu d'une telle suite : elle est masquée entière ou pas du tout.
fn jeton(x: char) -> bool {
    x.is_ascii_alphanumeric() || "+/=_-".contains(x)
}

/// Le même, avec le point : un JWT (« eyJ….….… ») ou « ya29.… » est un seul jeton pour les préfixes connus.
fn jeton_etendu(x: char) -> bool {
    jeton(x) || x == '.'
}

/// Le texte où chaque passage trouvé est remplacé : `trouver(c, i)` rend la fin (exclue) d'un passage qui commence
/// en `i` et son remplaçant. Les marqueurs déjà posés sont recopiés tels quels, sans rien chercher dedans.
fn remplacer(c: &[char], mut trouver: impl FnMut(&[char], usize) -> Option<(usize, String)>) -> Vec<char> {
    let mut sortie = Vec::with_capacity(c.len());
    let mut i = 0;
    while let Some(x) = car(c, i) {
        if let Some(fin) = marqueur(c, i) {
            sortie.extend_from_slice(morceau(c, i, fin));
            i = fin;
        } else if let Some((fin, par)) = trouver(c, i).filter(|(fin, _)| *fin > i) {
            sortie.extend(par.chars());
            i = fin;
        } else {
            sortie.push(x);
            i = suivant(i);
        }
    }
    sortie
}

// --- Marqueurs ---------------------------------------------------------------------------------------------------

/// Les marqueurs que pose ce nettoyage, puis ceux de `journal::anonymiser`. Seuls ceux-là gardent leurs chevrons à
/// la sortie : un « `<system>` » ou un « `<img …>` » écrit dans un texte perd les siens (étape 5).
pub(crate) const MARQUEURS: [&str; 19] = [
    "<chemin>",
    "<numéro>",
    "<url>",
    "<ip>",
    "<mac>",
    "<guid>",
    "<hex>",
    "<jeton>",
    "<secret>",
    "<clé>",
    "<adresse>",
    "<utilisateur>",
    "<machine>",
    "<réseau>",
    "<appareil>",
    "<compte>",
    "<courriel>",
    "<numéro>",
    "<wifi>",
];

/// L'extension gardée d'un chemin (« `<chemin .docx>` ») : 1 à 5 lettres ou chiffres ASCII, en minuscules.
pub(crate) const EXTENSION_MAX: usize = 5;

/// La fin d'un marqueur qui commence en `i`.
fn marqueur(c: &[char], i: usize) -> Option<usize> {
    const CHEMIN: &str = "<chemin .";
    if car(c, i) != Some('<') {
        return None;
    }
    if let Some(m) = MARQUEURS.iter().find(|m| commence_par(c, i, m)) {
        return Some(plus(i, m.chars().count()));
    }
    if commence_par(c, i, CHEMIN) {
        let debut = plus(i, CHEMIN.chars().count());
        let fin = fin_tant_que(c, debut, |x| x.is_ascii_lowercase() || x.is_ascii_digit());
        if (1..=EXTENSION_MAX).contains(&entre(debut, fin)) && car(c, fin) == Some('>') {
            return Some(suivant(fin));
        }
    }
    None
}

// --- Normalisation et borne de l'entrée --------------------------------------------------------------------------

/// Au plus `ENTREE_MAX` octets, coupés à une espace : un jeton à cheval sur la coupe disparaît entier au lieu de
/// laisser son début.
fn borne_entree(texte: &str) -> &str {
    if texte.len() <= ENTREE_MAX {
        return texte;
    }
    let mut coupe = ENTREE_MAX;
    while !texte.is_char_boundary(coupe) {
        coupe = coupe.saturating_sub(1);
    }
    let debut = texte.get(..coupe).unwrap_or("");
    debut
        .rfind(char::is_whitespace)
        .and_then(|i| debut.get(..i))
        .unwrap_or("")
}

/// Mise en forme invisible, retirée avant toute recherche : glissée dans « gh​p_… », elle cacherait un préfixe au
/// détecteur, puis disparaîtrait à l'étape 5 en le recollant. Sens d'écriture bidi, largeur nulle, marque d'ordre des
/// octets, trait d'union conditionnel, séparateur mongol, étiquettes, remplissages coréens (des lettres invisibles,
/// qui passeraient pour des lettres), sélecteurs de variante, liant de graphèmes.
fn invisible(x: char) -> bool {
    matches!(
        u32::from(x),
        0xAD | 0x034F
            | 0x061C
            | 0x115F..=0x1160
            | 0x17B4..=0x17B5
            | 0x180B..=0x180F
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x206F
            | 0x3164
            | 0xFE00..=0xFE0F
            | 0xFEFF
            | 0xFFA0
            | 0xE0000..=0xE0FFF
    )
}

/// Le texte en caractères : invisibles retirés, formes pleine chasse (« ｇｈｐ＿ ») ramenées à l'ASCII, fins de ligne
/// unifiées (une valeur de `Cookie:` court jusqu'à la fin de sa ligne), autres contrôles et espaces en espace simple,
/// guillemets et apostrophes typographiques en guillemet et apostrophe droits (« password : « … » » est une valeur
/// entre guillemets, comme `password: "…"`).
/// Le texte brut sans chevrons, pleine chasse comprise : à appliquer avant `journal::anonymiser`, qui pose ses
/// propres marqueurs. Sans cela, « `<secret>` » écrit dans un message d'erreur passerait pour un marqueur posé par
/// le nettoyage, et ce qui le suit ou l'entoure échapperait à la recherche.
pub(crate) fn sans_chevrons(brut: &str) -> String {
    brut.chars()
        .map(|x| if matches!(pleine_chasse(x), '<' | '>') { ' ' } else { x })
        .collect()
}

fn normaliser(texte: &str) -> Vec<char> {
    let mut c = Vec::with_capacity(texte.len());
    for x in texte.chars() {
        let x = pleine_chasse(x);
        match x {
            '\r' | '\n' | '\u{85}' | '\u{2028}' | '\u{2029}' => c.push('\n'),
            x if invisible(x) => {}
            x if x.is_control() || x.is_whitespace() => c.push(' '),
            '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}' | '\u{2039}' | '\u{203A}' | '\u{02BC}' | '\u{2032}' => {
                c.push('\'');
            }
            '\u{201C}' | '\u{201D}' | '\u{201E}' | '\u{201F}' | '\u{00AB}' | '\u{00BB}' | '\u{2033}' => c.push('"'),
            x => c.push(x),
        }
    }
    c
}

fn pleine_chasse(x: char) -> char {
    match x {
        '\u{FF01}'..='\u{FF5E}' => u32::from(x).checked_sub(0xFEE0).and_then(char::from_u32).unwrap_or(' '),
        '\u{3000}' => ' ',
        x => x,
    }
}

// --- Détecteur, couches précises ---------------------------------------------------------------------------------

/// Préfixes de jetons connus et le nombre de caractères qui doivent les suivre. Tout le jeton (lettres, chiffres,
/// `+/=_-.`) est remplacé.
const PREFIXES: [(&str, usize); 34] = [
    ("ghp_", 16),
    ("gho_", 16),
    ("ghu_", 16),
    ("ghs_", 16),
    ("ghr_", 16),
    ("github_pat_", 16),
    ("glpat-", 16),
    ("glptt-", 16),
    ("gldt-", 16),
    ("glrt-", 16),
    ("xoxa-", 8),
    ("xoxb-", 8),
    ("xoxe-", 8),
    ("xoxo-", 8),
    ("xoxp-", 8),
    ("xoxr-", 8),
    ("xoxs-", 8),
    ("xapp-", 8),
    ("sk-", 16),
    ("sk_live_", 16),
    ("sk_test_", 16),
    ("rk_live_", 16),
    ("rk_test_", 16),
    ("whsec_", 16),
    ("AKIA", 16),
    ("ASIA", 16),
    ("AIza", 30),
    ("ya29.", 20),
    ("eyJ", 10),
    ("npm_", 20),
    ("hf_", 20),
    ("pypi-", 20),
    ("dop_v1_", 20),
    // Le corps d'une clé publique SSH : « ssh-rsa AAAAB3NzaC1yc2E… », « ssh-ed25519 AAAAC3NzaC1lZDI1NTE5… ».
    ("AAAA", 40),
];

/// Les couches 1 et 2 du détecteur : blocs PEM et fichiers de clé de PuTTY, préfixes connus, puis valeurs de clés.
fn couche_precise(c: &[char], alertes: &mut u32) -> Vec<char> {
    let c = remplacer(c, |c, i| {
        let (fin, par) = bloc_de_cle(c, i)
            .map(|f| (f, "<clé>"))
            .or_else(|| prefixe_connu(c, i).map(|f| (f, "<jeton>")))?;
        *alertes = alertes.saturating_add(1);
        Some((fin, par.to_string()))
    });
    remplacer(&c, |c, i| {
        let fin = valeur_de_cle(c, i).or_else(|| apres_porteur(c, i))?;
        *alertes = alertes.saturating_add(1);
        Some((fin, "<secret>".to_string()))
    })
}

/// « -----BEGIN … » jusqu'après « -----END …----- », ou jusqu'à la fin du texte si la fin manque (texte coupé).
fn bloc_de_cle(c: &[char], i: usize) -> Option<usize> {
    if commence_par_sans_casse(c, i, "putty-user-key-file-") {
        return Some(c.len());
    }
    if !commence_par_sans_casse(c, i, "-----begin") {
        return None;
    }
    let Some(fin) = chercher(c, plus(i, 10), "-----end") else {
        return Some(c.len());
    };
    Some(chercher(c, plus(fin, 8), "-----").map_or(c.len(), |k| plus(k, 5)))
}

fn prefixe_connu(c: &[char], i: usize) -> Option<usize> {
    if !car(c, i).is_some_and(jeton_etendu) || avant(c, i).is_some_and(|p| p.is_ascii_alphanumeric()) {
        return None;
    }
    // Le préfixe d'abord : mesurer la suite à chaque position rendrait une longue suite de points quadratique.
    let (p, min) = PREFIXES.iter().find(|(p, _)| commence_par(c, i, p))?;
    let fin = fin_tant_que(c, i, jeton_etendu);
    (entre(plus(i, p.chars().count()), fin) >= *min).then_some(fin)
}

/// Mots qui annoncent un secret devant `:` ou `=` (plan, couche 2), cherchés dans le mot qui précède : `db_password=`,
/// `client_secret:`, `X-Auth-Token:`, `"api_key": "…"`.
const CLES: [&str; 18] = [
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "secret",
    "token",
    "jeton",
    "apikey",
    "api_key",
    "api-key",
    "authorization",
    "bearer",
    "cookie",
    "credential",
    "private_key",
    "privatekey",
    "private-key",
    "access_key",
];

/// Mots courts qui annoncent un secret seulement comme mot entier ou comme dernier morceau d'un nom (`DB_PASS`,
/// `wifi-psk`, « Clé : ») : cherchés dans un mot, ils sonneraient partout (« compass », « keyboard »).
const CLES_COURTES: [&str; 9] = ["pass", "pw", "psk", "mdp", "cle", "clé", "key", "passe", "pin"];

/// Mots qui annoncent un secret même quelques mots avant le séparateur : « Mot de passe Wi-Fi : … », « Clé de
/// sécurité réseau : … », « Invalid API key: … ».
const CLES_FORTES: [&str; 8] = ["passe", "clé", "cle", "password", "passwd", "passphrase", "mdp", "psk"];

/// Clés dont la valeur court jusqu'à la fin de la ligne : « Authorization: Basic … », « Cookie: a=1; b=2 ».
const CLES_LIGNE: [&str; 2] = ["authorization", "cookie"];

/// Les mots qui annoncent un jeton à la suite (« Bearer abc… »).
const SCHEMAS: [&str; 5] = ["bearer", "basic", "token", "digest", "negotiate"];

/// Les options de ligne de commande et les mots suivis du secret après une simple espace : `--password x`,
/// `-Password x`, `/pass x`, `-p x`, « mot de passe x », `sshpass -p x`. Sans `-`, « p » et « u » ne comptent pas.
const CLES_SANS_SEPARATEUR: [&str; 13] = [
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "pass",
    "mdp",
    "passe",
    "psk",
    "secret",
    "token",
    "jeton",
    "apikey",
    "p",
];

fn mot_de_cle(x: char) -> bool {
    x.is_alphanumeric() || x == '_' || x == '-'
}

fn entre_cle_et_valeur(x: char) -> bool {
    x == ' ' || x == '\t' || x == '"' || x == '\''
}

/// Si ce mot (en minuscules) annonce un secret : un mot-clé dedans, ou un mot court entier ou en dernier morceau.
fn mot_annonce_un_secret(mot: &str) -> bool {
    CLES.iter().any(|cle| mot.contains(cle))
        || CLES_COURTES.iter().any(|cle| {
            mot == *cle
                || mot
                    .strip_suffix(cle)
                    .is_some_and(|tete| tete.ends_with('_') || tete.ends_with('-'))
        })
}

/// Les quatre derniers mots avant `fin` (lettres, chiffres, `_`, `-`), en minuscules, le plus proche en premier.
fn mots_avant(c: &[char], fin: usize) -> Vec<String> {
    let mut mots = Vec::new();
    let mut k = fin;
    while mots.len() < 4 {
        while avant(c, k).is_some_and(|y| y == ' ' || y == '\t') {
            k = k.saturating_sub(1);
        }
        let mut debut = k;
        while avant(c, debut).is_some_and(mot_de_cle) {
            debut = debut.saturating_sub(1);
        }
        if debut == k {
            break;
        }
        mots.push(chaine(c, debut, k).to_lowercase());
        k = debut;
    }
    mots
}

/// Une valeur qui a l'air d'un mot de la langue (« incorrect », « Partagé ») : après une simple espace, ce n'est pas un
/// secret (« mot de passe incorrect »). Un secret fait de minuscules seules passe donc là, et seulement là.
fn mot_de_la_langue(v: &[char]) -> bool {
    match v {
        [] => true,
        [premier, reste @ ..] => premier.is_alphabetic() && reste.iter().all(|y| y.is_alphabetic() && y.is_lowercase()),
    }
}

/// Si une valeur de clé secrète commence en `i` : sa fin. On remonte depuis `i` : espaces et guillemets, puis `:` ou
/// `=` (pas « :: »), puis espaces et guillemets, puis les mots de la clé. Sans séparateur, une simple espace après
/// une option connue (`-p`, `--password`) suffit.
fn valeur_de_cle(c: &[char], i: usize) -> Option<usize> {
    let premier = car(c, i)?;
    if premier.is_whitespace() || "\"'=:".contains(premier) {
        return None;
    }
    let mut j = i;
    while avant(c, j).is_some_and(entre_cle_et_valeur) {
        j = j.checked_sub(1)?;
    }
    let separateur = j.checked_sub(1)?;
    let sep = car(c, separateur)?;
    if !(sep == ':' || sep == '=') || (sep == ':' && (avant(c, separateur) == Some(':') || premier == ':')) {
        return apres_option(c, i, j);
    }
    let mut k = separateur;
    while avant(c, k).is_some_and(|y| entre_cle_et_valeur(y) || y == '=' || y == ':') {
        k = k.checked_sub(1)?;
    }
    let mots = mots_avant(c, k);
    let dernier = mots.first().map_or("", String::as_str);
    let devant = chaine(c, k.saturating_sub(48), k).to_lowercase();
    let annonce = mot_annonce_un_secret(dernier)
        || mots.iter().any(|m| CLES_FORTES.contains(&m.as_str()))
        || ["mot de passe", "mot-de-passe", "mot_de_passe", "motdepasse"]
            .iter()
            .any(|m| devant.contains(m));
    if !annonce {
        return None;
    }
    // Entre guillemets si un guillemet sépare la clé de la valeur : jusqu'au même guillemet, espaces comprises.
    let guillemet = morceau(c, suivant(separateur), i)
        .iter()
        .rev()
        .find(|q| **q == '"' || **q == '\'')
        .copied();
    let fin = if let Some(q) = guillemet {
        fin_tant_que(c, i, |y| y != q && y != '\n')
    } else if CLES_LIGNE.iter().any(|cle| dernier.contains(cle)) {
        fin_tant_que(c, i, |y| y != '\n')
    } else {
        // Jusqu'à une espace seulement : un mot de passe peut contenir `(`, `,`, `;`, `&` ou commencer par eux.
        let fin = fin_tant_que(c, i, |y| !y.is_whitespace());
        apres_schema(c, i, fin)
    };
    (fin > i).then_some(fin)
}

/// La valeur qui suit une option ou un mot connu après une simple espace (`j` : début des espaces) : `-p x`,
/// `--password x`, « mot de passe x », `-u alice:x`. Un mot de la langue n'est pas pris.
fn apres_option(c: &[char], i: usize, j: usize) -> Option<usize> {
    if j == i || morceau(c, j, i).iter().any(|y| *y == '"' || *y == '\'') {
        return None;
    }
    let mut debut = j;
    while avant(c, debut).is_some_and(|y| mot_de_cle(y) || y == '/') {
        debut = debut.checked_sub(1)?;
    }
    let brut = chaine(c, debut, j).to_lowercase();
    let option = brut.starts_with(['-', '/']);
    let mot = brut.trim_start_matches(['-', '/']);
    let fin = fin_tant_que(c, i, |y| !y.is_whitespace());
    let valeur = morceau(c, i, fin);
    let utilisateur = option && matches!(mot, "u" | "user") && valeur.iter().any(|y| *y == ':' || *y == '%');
    let cle = CLES_SANS_SEPARATEUR.contains(&mot) && (option || mot.len() > 1);
    ((cle && !mot_de_la_langue(valeur)) || utilisateur).then_some(fin)
}

/// Une valeur qui n'est qu'un schéma (« Bearer », « Basic ») : le jeton qui le suit en fait partie.
fn apres_schema(c: &[char], debut: usize, fin: usize) -> usize {
    let mot = chaine(c, debut, fin).to_lowercase();
    if !SCHEMAS.contains(&mot.as_str()) {
        return fin;
    }
    let suite = fin_tant_que(c, fin, |y| y == ' ' || y == '\t');
    if suite == fin {
        return fin;
    }
    let bout = fin_tant_que(c, suite, |y| !y.is_whitespace());
    if bout > suite { bout } else { fin }
}

/// « Bearer abc… » sans deux-points : le jeton qui suit le mot, s'il a au moins 8 caractères.
fn apres_porteur(c: &[char], i: usize) -> Option<usize> {
    if !car(c, i).is_some_and(jeton) || avant(c, i).is_some_and(jeton) {
        return None;
    }
    let mut j = i;
    while avant(c, j).is_some_and(|y| y == ' ' || y == '\t') {
        j = j.checked_sub(1)?;
    }
    let debut = j.checked_sub(6)?;
    if j == i || !commence_par_sans_casse(c, debut, "bearer") || avant(c, debut).is_some_and(char::is_alphanumeric) {
        return None;
    }
    let fin = fin_tant_que(c, i, jeton_etendu);
    (entre(i, fin) >= 8).then_some(fin)
}

// --- Étapes 2 et 3 : adresses, chemins, identifiants -------------------------------------------------------------

/// Tout mot (entre deux espaces) qui contient `@` : courriel, « nom:mot-de-passe@hôte », mention « @quelqu'un ».
fn masquer_arobases(c: &[char]) -> Vec<char> {
    let mut sortie = Vec::with_capacity(c.len());
    let mut i = 0;
    while i < c.len() {
        let fin = fin_tant_que(c, i, |x| !x.is_whitespace());
        if fin == i {
            sortie.extend(car(c, i));
            i = suivant(i);
            continue;
        }
        let mot = morceau(c, i, fin);
        if mot.contains(&'@') {
            sortie.extend("<adresse>".chars());
        } else {
            sortie.extend_from_slice(mot);
        }
        i = fin;
    }
    sortie
}

/// Les étapes 2 et 3, en une lecture et dans cet ordre de priorité : adresse web (avant le chemin : « https://h/x »
/// n'est pas le chemin « //h/x »), chemin absolu, GUID, adresse MAC, adresse IP, longue suite hexadécimale.
fn masquer_formes(c: &[char], ip: bool) -> Vec<char> {
    remplacer(c, |c, i| {
        if let Some(fin) = adresse_web(c, i) {
            return Some((fin, "<url>".to_string()));
        }
        if let Some((fin, extension)) = chemin(c, i) {
            return Some((
                fin,
                extension.map_or_else(|| "<chemin>".to_string(), |e| format!("<chemin .{e}>")),
            ));
        }
        if let Some(fin) = guid(c, i) {
            return Some((fin, "<guid>".to_string()));
        }
        if let Some(fin) = mac(c, i) {
            return Some((fin, "<mac>".to_string()));
        }
        if ip && let Some(fin) = ipv6(c, i).or_else(|| ipv4(c, i)) {
            return Some((fin, "<ip>".to_string()));
        }
        if let Some(fin) = groupes_de_chiffres(c, i) {
            return Some((fin, "<numéro>".to_string()));
        }
        hexa(c, i).map(|fin| (fin, "<hex>".to_string()))
    })
}

/// Trois groupes ou plus de 2 à 8 chiffres séparés par une espace ou un tiret, 12 chiffres ou plus en tout : une clé
/// de récupération BitLocker, un numéro de carte, un code de secours. L'entropie ne les voit pas (dix symboles
/// seulement) ; une date (« 2026-11-02 ») ou un numéro de téléphone n'en ont pas assez pour être pris.
fn groupes_de_chiffres(c: &[char], i: usize) -> Option<usize> {
    if avant(c, i).is_some_and(char::is_alphanumeric) {
        return None;
    }
    let (mut debut, mut fin, mut groupes, mut total) = (i, i, 0usize, 0usize);
    loop {
        let bout = fin_tant_que(c, debut, |x| x.is_ascii_digit());
        let n = entre(debut, bout);
        if !(2..=8).contains(&n) {
            break;
        }
        groupes = groupes.saturating_add(1);
        total = total.saturating_add(n);
        fin = bout;
        if car(c, bout).is_some_and(|x| x == ' ' || x == '-')
            && car(c, suivant(bout)).is_some_and(|x| x.is_ascii_digit())
        {
            debut = suivant(bout);
        } else {
            break;
        }
    }
    (groupes >= 3 && total >= 12 && !car(c, fin).is_some_and(char::is_alphanumeric)).then_some(fin)
}

/// `0x` suivi d'exactement 8 chiffres hexadécimaux, seul : un code d'erreur Windows (HRESULT).
fn mot_de_32_bits(c: &[char], i: usize) -> Option<usize> {
    if !matches!((car(c, i), car(c, suivant(i))), (Some('0'), Some('x' | 'X'))) || avant(c, i).is_some_and(jeton) {
        return None;
    }
    let debut = plus(i, 2);
    let fin = fin_tant_que(c, debut, jeton);
    (entre(debut, fin) == 8 && morceau(c, debut, fin).iter().all(char::is_ascii_hexdigit)).then_some(fin)
}

/// Un mot de 32 bits voisin, avant ou après, séparé seulement par des espaces, virgules ou points-virgules : une clé
/// écrite en mots de 32 bits (« 0x1A2B3C4D 0x5E6F7A8B … ») n'est pas une suite de codes d'erreur.
fn voisin_de_32_bits(c: &[char], i: usize, fin: usize) -> bool {
    let separateur = |x: char| matches!(x, ' ' | ',' | ';');
    let apres = fin_tant_que(c, fin, separateur);
    if apres > fin && mot_de_32_bits(c, apres).is_some() {
        return true;
    }
    let mut j = i;
    while let Some(k) = j.checked_sub(1).filter(|k| car(c, *k).is_some_and(separateur)) {
        j = k;
    }
    let fin_avant = j;
    while let Some(k) = j.checked_sub(1).filter(|k| car(c, *k).is_some_and(jeton)) {
        j = k;
    }
    fin_avant < i && mot_de_32_bits(c, j) == Some(fin_avant)
}

/// Des schémas sans « // » qui portent du code ou des données.
const SCHEMAS_SANS_BARRES: [&str; 5] = ["javascript", "vbscript", "data", "mailto", "file"];

fn fin_d_adresse(x: char) -> bool {
    x.is_whitespace() || "\"'<>`|".contains(x)
}

fn adresse_web(c: &[char], i: usize) -> Option<usize> {
    if !car(c, i)?.is_ascii_alphabetic() || avant(c, i).is_some_and(jeton_etendu) {
        return None;
    }
    let s = fin_tant_que(c, i, |x| x.is_ascii_alphanumeric() || "+.-".contains(x));
    if entre(i, s) > 24 {
        return None;
    }
    let schema = chaine(c, i, s).to_lowercase();
    let apres = |j: usize| fin_tant_que(c, j, |x| !fin_d_adresse(x));
    if commence_par(c, s, "://") {
        return Some(apres(s));
    }
    if car(c, s) == Some(':')
        && SCHEMAS_SANS_BARRES.contains(&schema.as_str())
        && car(c, suivant(s)).is_some_and(|x| !x.is_whitespace())
    {
        return Some(apres(s));
    }
    (schema.starts_with("www.") && schema.len() > 4).then(|| apres(i))
}

/// Ce qui peut précéder le début d'un chemin absolu. Ni lettre, ni chiffre, ni `+`, `/`, `-`, `_`, `.` : un « / »
/// au milieu d'un jeton base64 n'ouvre pas un chemin qui le couperait en deux.
fn avant_chemin(p: Option<char>) -> bool {
    p.is_none_or(|p| p.is_whitespace() || "(\"'=,;:[{>".contains(p))
}

/// Ce qui arrête un chemin.
fn arret_de_chemin(x: char) -> bool {
    "\"'<>|`*?,;:\n".contains(x)
}

fn caractere_de_chemin(x: char) -> bool {
    x.is_alphanumeric() || "._-~$%".contains(x)
}

/// Un chemin absolu qui commence en `i` : sa fin, et l'extension de son dernier élément. Windows (« C:\ », « \\nas\ »,
/// « \\?\C:\ », « %APPDATA%\ », « \Device\… »), Unix (« /… », « ~/… », « $HOME/… »).
fn chemin(c: &[char], i: usize) -> Option<(usize, Option<String>)> {
    if !avant_chemin(avant(c, i)) {
        return None;
    }
    let tete = car(c, i)?;
    let un = car(c, suivant(i));
    let deux = car(c, plus(i, 2));
    let barre = |y: Option<char>| y == Some('\\') || y == Some('/');
    // (début du premier élément, séparateurs permis, séparateurs exigés en plus du premier)
    let (debut, windows, exiges) = if tete.is_ascii_alphabetic() && un == Some(':') && barre(deux) {
        (plus(i, 3), true, 0)
    } else if commence_par(c, i, "\\\\?\\") && car(c, plus(i, 5)) == Some(':') {
        (plus(i, 7), true, 0)
    } else if tete == '\\' && un == Some('\\') && deux.is_some_and(caractere_de_chemin) {
        (plus(i, 2), true, 0)
    } else if tete == '\\' && un.is_some_and(char::is_alphanumeric) {
        // « \Device\HarddiskVolume3\… », mais pas « \n » : deux séparateurs au moins.
        (suivant(i), true, 1)
    } else if tete == '~' && barre(un) {
        (plus(i, 2), un == Some('\\'), 0)
    } else if tete == '%' {
        let fin = fin_tant_que(c, suivant(i), |y| y.is_ascii_alphanumeric() || y == '_');
        if fin == suivant(i) || car(c, fin) != Some('%') || !barre(car(c, suivant(fin))) {
            return None;
        }
        (plus(fin, 2), true, 0)
    } else if tete == '$' {
        let fin = fin_tant_que(c, suivant(i), |y| y.is_ascii_alphanumeric() || y == '_');
        if fin == suivant(i) || car(c, fin) != Some('/') {
            return None;
        }
        (suivant(fin), false, 0)
    } else if tete == '/' && un.is_some_and(|y| caractere_de_chemin(y) || y == '/' || y == '<') {
        (suivant(i), false, 0)
    } else {
        return None;
    };
    let separateur = |y: char| y == '/' || (windows && y == '\\');
    let mut pos = debut;
    let mut separateurs = 0usize;
    loop {
        // L'élément qui commence en `pos` : jusqu'au prochain séparateur ou arrêt ; un marqueur de l'anonymisation
        // (« C:\Users\<utilisateur>\… ») en fait partie.
        let mut bout = pos;
        while let Some(y) = car(c, bout) {
            if let Some(fin) = marqueur(c, bout) {
                bout = fin;
            } else if separateur(y) || arret_de_chemin(y) {
                break;
            } else {
                bout = suivant(bout);
            }
        }
        let element = morceau(c, pos, bout);
        let espace = element.iter().position(|y| y.is_whitespace());
        let franchit = car(c, bout).is_some_and(separateur)
            && (espace.is_none() || (element.len() <= SEGMENT_MAX && !avant(c, bout).is_some_and(char::is_whitespace)));
        if franchit {
            separateurs = suivant(separateurs);
            pos = suivant(bout);
            continue;
        }
        let fin = fin_du_dernier(c, pos, bout, espace);
        if separateurs < exiges || (fin == pos && separateurs == 0 && pos == debut && pos == suivant(i)) {
            return None;
        }
        let fin = if fin == pos && entre(i, pos) <= 1 {
            return None;
        } else {
            fin
        };
        let dernier = morceau(c, pos, fin);
        let extension = dernier.iter().rposition(|y| *y == '.').and_then(|p| {
            let ext: String = dernier.get(suivant(p)..)?.iter().collect();
            ((1..=EXTENSION_MAX).contains(&ext.len()) && ext.chars().all(|y| y.is_ascii_alphanumeric()))
                .then(|| ext.to_ascii_lowercase())
        });
        return Some((fin, extension));
    }
}

/// La fin du dernier élément d'un chemin, qui va de `pos` à `k` (arrêt ou fin) : jusqu'à la première espace, sauf si
/// un mot proche finit par une extension (« Rapport annuel.docx introuvable »). Les points de fin de phrase n'en
/// font pas partie.
fn fin_du_dernier(c: &[char], pos: usize, k: usize, espace: Option<usize>) -> usize {
    let premiere = espace.map_or(k, |e| plus(pos, e));
    let mut fin = premiere;
    if espace.is_some() {
        let mut debut_mot = pos;
        while debut_mot < k && entre(pos, debut_mot) <= SEGMENT_MAX {
            // Un marqueur (« <utilisateur> ») fait partie du mot ; ses chevrons ne l'arrêtent pas.
            let mut fin_mot = debut_mot;
            while fin_mot < k {
                if let Some(f) = marqueur(c, fin_mot) {
                    fin_mot = f;
                } else if car(c, fin_mot).is_some_and(|y| !y.is_whitespace()) {
                    fin_mot = suivant(fin_mot);
                } else {
                    break;
                }
            }
            let fin_mot = fin_mot.min(k);
            let mot = morceau(c, debut_mot, fin_mot);
            let net = mot
                .len()
                .saturating_sub(mot.iter().rev().take_while(|y| **y == '.' || **y == ')').count());
            let mot = mot.get(..net).unwrap_or(&[]);
            let a_extension = mot.iter().rposition(|y| *y == '.').is_some_and(|p| {
                let e = mot.get(suivant(p)..).unwrap_or(&[]);
                (1..=EXTENSION_MAX).contains(&e.len()) && e.iter().all(char::is_ascii_alphanumeric)
            });
            if a_extension {
                fin = plus(debut_mot, net);
                break;
            }
            debut_mot = fin_tant_que(c, fin_mot, char::is_whitespace);
        }
    }
    while fin > pos && avant(c, fin) == Some('.') {
        fin = fin.saturating_sub(1);
    }
    fin
}

fn hexadecimaux(c: &[char], i: usize, n: usize) -> Option<usize> {
    let fin = plus(i, n);
    morceau(c, i, fin)
        .iter()
        .all(char::is_ascii_hexdigit)
        .then_some(fin)
        .filter(|f| *f <= c.len())
}

fn guid(c: &[char], i: usize) -> Option<usize> {
    if avant(c, i).is_some_and(jeton) {
        return None;
    }
    let accolade = car(c, i) == Some('{');
    let mut j = if accolade { suivant(i) } else { i };
    for (rang, n) in [8, 4, 4, 4, 12].into_iter().enumerate() {
        if rang > 0 {
            if car(c, j) != Some('-') {
                return None;
            }
            j = suivant(j);
        }
        j = hexadecimaux(c, j, n)?;
    }
    if accolade && car(c, j) == Some('}') {
        j = suivant(j);
    }
    (!car(c, j).is_some_and(jeton)).then_some(j)
}

fn mac(c: &[char], i: usize) -> Option<usize> {
    if avant(c, i).is_some_and(|p| jeton(p) || p == ':') {
        return None;
    }
    let s = car(c, plus(i, 2)).filter(|s| *s == ':' || *s == '-')?;
    let mut j = i;
    for rang in 0..6 {
        if rang > 0 {
            if car(c, j) != Some(s) {
                return None;
            }
            j = suivant(j);
        }
        j = hexadecimaux(c, j, 2)?;
    }
    (!car(c, j).is_some_and(|y| jeton(y) || y == ':')).then_some(j)
}

fn ipv4(c: &[char], i: usize) -> Option<usize> {
    if avant(c, i).is_some_and(|p| p.is_ascii_alphanumeric() || p == '.') {
        return None;
    }
    let mut j = i;
    for rang in 0..4 {
        if rang > 0 {
            if car(c, j) != Some('.') {
                return None;
            }
            j = suivant(j);
        }
        let fin = fin_tant_que(c, j, |y| y.is_ascii_digit());
        let n = entre(j, fin);
        if !(1..=3).contains(&n) || chaine(c, j, fin).parse::<u16>().ok()? > 255 {
            return None;
        }
        j = fin;
    }
    if car(c, j).is_some_and(|y| y.is_ascii_alphanumeric())
        || (car(c, j) == Some('.') && car(c, suivant(j)).is_some_and(|y| y.is_ascii_digit()))
    {
        return None;
    }
    // Port et préfixe : « 10.0.0.1:8080 », « 10.0.0.0/8 ».
    for marque in [':', '/'] {
        if car(c, j) == Some(marque) {
            let fin = fin_tant_que(c, suivant(j), |y| y.is_ascii_digit());
            if (1..=5).contains(&entre(suivant(j), fin)) {
                j = fin;
            }
        }
    }
    Some(j)
}

fn ipv6(c: &[char], i: usize) -> Option<usize> {
    if avant(c, i).is_some_and(|p| p.is_ascii_alphanumeric() || p == ':' || p == '.') {
        return None;
    }
    let crochet = car(c, i) == Some('[');
    let debut = if crochet { suivant(i) } else { i };
    let fin = fin_tant_que(c, debut, |y| y.is_ascii_hexdigit() || y == ':');
    let corps = chaine(c, debut, fin);
    let deux_points = corps.matches(':').count();
    let groupes_courts = corps.split(':').all(|g| g.len() <= 4);
    let pleine = deux_points == 7 && corps.split(':').all(|g| !g.is_empty());
    let abregee = corps.contains("::") && corps.split(':').any(|g| !g.is_empty()) && corps.matches("::").count() == 1;
    if !groupes_courts || !(pleine || abregee) || !corps.chars().any(|y| y.is_ascii_digit()) {
        return None;
    }
    let mut j = fin;
    if car(c, j) == Some('%') {
        j = fin_tant_que(c, suivant(j), |y| y.is_ascii_alphanumeric());
    }
    if car(c, j) == Some('/') {
        let f = fin_tant_que(c, suivant(j), |y| y.is_ascii_digit());
        if (1..=3).contains(&entre(suivant(j), f)) {
            j = f;
        }
    }
    if crochet {
        if car(c, j) != Some(']') {
            return None;
        }
        j = suivant(j);
        if car(c, j) == Some(':') {
            j = fin_tant_que(c, suivant(j), |y| y.is_ascii_digit());
        }
    }
    (!car(c, j).is_some_and(|y| y.is_ascii_alphanumeric() || y == ':')).then_some(j)
}

/// Une suite hexadécimale de 8 caractères ou plus, prise seulement si elle forme une suite de l'alphabet des jetons
/// à elle seule (« sha256:… », « commit … »), jamais au milieu d'un jeton. Exception : « 0x » suivi d'exactement 8
/// chiffres, un code d'erreur de Windows (HRESULT, NTSTATUS) : 32 bits sans secret possible, et c'est ce qui dit
/// l'erreur.
fn hexa(c: &[char], i: usize) -> Option<usize> {
    if !car(c, i).is_some_and(jeton) || avant(c, i).is_some_and(jeton) {
        return None;
    }
    let fin = fin_tant_que(c, i, jeton);
    let suite = morceau(c, i, fin);
    let (corps, code) = match suite {
        ['0', 'x' | 'X', reste @ ..] => (reste, true),
        _ => (suite, false),
    };
    if !corps.iter().all(char::is_ascii_hexdigit) || corps.len() < 8 {
        return None;
    }
    if code && corps.len() == 8 && !voisin_de_32_bits(c, i, fin) {
        return None;
    }
    Some(fin)
}

// --- Détecteur, couche 3 : l'entropie ----------------------------------------------------------------------------

fn couche_entropie(c: &[char], alertes: &mut u32) -> Vec<char> {
    remplacer(c, |c, i| {
        if !car(c, i).is_some_and(jeton) || avant(c, i).is_some_and(jeton) {
            return None;
        }
        let fin = fin_tant_que(c, i, jeton);
        let suite = morceau(c, i, fin);
        let banal = suite.len() < ENTROPIE_LONGUEUR || forme_de_mots(suite) || entropie(suite) <= ENTROPIE_SEUIL;
        if banal && !code_par_quatre(suite) {
            return None;
        }
        *alertes = alertes.saturating_add(1);
        Some((fin, "<jeton>".to_string()))
    })
}

/// Bits par caractère (Shannon) d'une suite de l'alphabet des jetons (ASCII seulement).
fn entropie(suite: &[char]) -> f64 {
    let mut comptes = [0u32; 128];
    for x in suite {
        if let Some(n) = usize::try_from(u32::from(*x)).ok().and_then(|k| comptes.get_mut(k)) {
            *n = n.saturating_add(1);
        }
    }
    let total = f64::from(u32::try_from(suite.len()).unwrap_or(u32::MAX));
    comptes
        .iter()
        .filter(|n| **n > 0)
        .map(|n| {
            let p = f64::from(*n) / total;
            -p * p.log2()
        })
        .sum()
}

/// Des mots liés par `_`, `-` ou `/` (« ERROR_ACCESS_DENIED », « x86_64-unknown-linux-musl »,
/// « read/write/execute ») : chaque morceau est un mot (minuscules, majuscules ou majuscule initiale), suivi au
/// besoin de chiffres, ou un petit nombre. Un jeton tiré au hasard n'a presque jamais cette forme.
/// Quatre morceaux ou plus de 4 lettres ou chiffres joints par des tirets (« abcd-efgh-ijkl-mnop ») : la forme des
/// mots de passe d'application et des codes de secours, trop courte pour la borne de l'entropie.
fn code_par_quatre(suite: &[char]) -> bool {
    let morceaux: Vec<&[char]> = suite.split(|x| *x == '-').collect();
    morceaux.len() >= 4
        && morceaux
            .iter()
            .all(|m| m.len() == 4 && m.iter().all(char::is_ascii_alphanumeric))
}

fn forme_de_mots(suite: &[char]) -> bool {
    let morceaux: Vec<&[char]> = suite.split(|x| matches!(x, '_' | '-' | '/')).collect();
    // Des codes de secours (« Abc123-Def456-… ») ou une phrase de passe en morceaux réguliers (« abcd-efgh-… ») ont
    // la forme de mots : ils restent à l'entropie.
    let finis_par_chiffre = morceaux
        .iter()
        .filter(|m| m.last().is_some_and(char::is_ascii_digit))
        .count();
    let quatre_lettres = morceaux
        .iter()
        .filter(|m| m.len() == 4 && m.iter().all(char::is_ascii_alphabetic))
        .count();
    morceaux.len() >= 2
        && finis_par_chiffre < 3
        && quatre_lettres < 4
        && morceaux.iter().all(|m| {
            let lettres = m.iter().take_while(|x| x.is_ascii_alphabetic()).count();
            let (mot, chiffres) = m.split_at_checked(lettres).unwrap_or((m, &[]));
            let mot_ok = match mot {
                [] => (1..=4).contains(&chiffres.len()),
                [premier, reste @ ..] => {
                    reste.iter().all(char::is_ascii_lowercase)
                        || (premier.is_ascii_uppercase() && reste.iter().all(char::is_ascii_uppercase))
                }
            };
            !m.is_empty() && m.len() <= 16 && mot_ok && chiffres.iter().all(char::is_ascii_digit)
        })
}

// --- Étape 5 : caractères permis, puis la coupe ------------------------------------------------------------------

/// Les caractères permis (plan, étape 5) : lettres Unicode, chiffres, espace et `.,:;'()[]#%/_-+=`. Les chevrons ne
/// restent que dans les marqueurs connus.
pub(crate) fn permis(x: char) -> bool {
    (x.is_alphabetic() && !invisible(x)) || x.is_ascii_digit() || " .,:;'()[]#%/_-+=".contains(x)
}

/// Accents écrits à part (« e » puis U+0301, comme les noms de fichier de macOS) : gardés après une lettre, deux au
/// plus, pour qu'un mot accentué ne soit pas coupé en deux, sans laisser empiler des signes sur une lettre.
fn accent_combinant(x: char) -> bool {
    ('\u{0300}'..='\u{036F}').contains(&x)
}

fn filtrer(c: &[char]) -> Vec<char> {
    let mut sortie: Vec<char> = Vec::with_capacity(c.len());
    let mut accents = 0u8;
    let mut i = 0;
    while let Some(x) = car(c, i) {
        if let Some(fin) = marqueur(c, i) {
            sortie.extend_from_slice(morceau(c, i, fin));
            accents = 0;
            i = fin;
            continue;
        }
        let y = if renvoi(c, i, &sortie) {
            accents = 0;
            ' '
        } else if permis(x) {
            accents = 0;
            x
        } else if accent_combinant(x)
            && accents < 2
            && sortie.last().is_some_and(|p| p.is_alphabetic() || accent_combinant(*p))
        {
            accents = accents.saturating_add(1);
            x
        } else {
            accents = 0;
            ' '
        };
        if y != ' ' || sortie.last().is_some_and(|p| *p != ' ') {
            sortie.push(y);
        }
        i = suivant(i);
    }
    while sortie.last() == Some(&' ') {
        sortie.pop();
    }
    sortie
}

/// Le `#` de « #12 », « dépôt#12 », « Fixes #12 » et le tiret de « GH-12 » : un renvoi vers un ticket ou une
/// demande de fusion, qu'une IA pourrait suivre ou qu'une page GitHub transformerait en lien. Le nombre reste.
fn renvoi(c: &[char], i: usize, sortie: &[char]) -> bool {
    let chiffre_apres = car(c, suivant(i)).is_some_and(|x| x.is_ascii_digit());
    match car(c, i) {
        Some('#') => chiffre_apres,
        Some('-') => {
            let en_arriere = |recul: usize| sortie.len().checked_sub(recul).and_then(|k| sortie.get(k)).copied();
            chiffre_apres
                && en_arriere(2).is_some_and(|x| x.eq_ignore_ascii_case(&'g'))
                && en_arriere(1).is_some_and(|x| x.eq_ignore_ascii_case(&'h'))
                && !en_arriere(3).is_some_and(char::is_alphanumeric)
        }
        _ => false,
    }
}

/// Au plus `max` octets, sans couper un marqueur ni un caractère.
fn couper(c: &[char], max: usize) -> Vec<char> {
    let mut sortie = Vec::with_capacity(c.len().min(max));
    let mut octets = 0usize;
    let mut i = 0;
    while i < c.len() {
        let fin = marqueur(c, i).unwrap_or_else(|| suivant(i));
        let bout = morceau(c, i, fin);
        let taille = bout.iter().map(|x| x.len_utf8()).sum::<usize>();
        octets = octets.saturating_add(taille);
        if octets > max {
            break;
        }
        sortie.extend_from_slice(bout);
        i = fin;
    }
    while sortie.last() == Some(&' ') {
        sortie.pop();
    }
    sortie
}

/// Vrai si `s` n'a que ce que l'étape 5 laisse : caractères permis, et chevrons dans les marqueurs connus seulement.
pub(crate) fn sortie_permise(s: &str) -> bool {
    let c: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut accents = 0u8;
    while let Some(x) = car(&c, i) {
        if let Some(fin) = marqueur(&c, i) {
            i = fin;
            accents = 0;
            continue;
        }
        if accent_combinant(x) {
            accents = accents.saturating_add(1);
            if accents > 2 || i == 0 {
                return false;
            }
        } else if permis(x) {
            accents = 0;
        } else {
            return false;
        }
        i = suivant(i);
    }
    true
}

/// Le nombre de fois que le détecteur sonnerait sur ce texte, sans le nettoyer : nul sur toute sortie de `nettoyer`.
pub(crate) fn alertes(s: &str) -> u32 {
    let mut a = 0;
    let c = normaliser(s);
    let c = couche_precise(&c, &mut a);
    let _ = couche_entropie(&c, &mut a);
    a
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::as_conversions)]
mod tests;

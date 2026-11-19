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
//! - Les signes combinants hors du bloc U+0300 à U+036F sont remplacés par une espace, pas comptés à part, sauf ceux
//!   qu'Unicode compte parmi les lettres (voyelles de l'arabe, de l'hébreu ou du devanagari, U+1DE7…) : gardés comme
//!   des lettres, même seuls ou empilés.

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

/// Le nettoyage complet, sans compter le refus : passes jusqu'au point fixe, les deux jugements de l'étape 6, puis la
/// relecture de la sortie. Le filtre et la relecture suivent la même règle (`trier`) : ce dernier refus ne devrait
/// jamais servir. S'il sert, une étape a laissé ce que l'étape 5 interdit, et le texte, venu d'ailleurs, est jeté
/// plutôt que gardé.
fn passer(brut: &str, forme: Forme) -> Result<String, Rejet> {
    let t = passer_sans_relecture(brut, forme)?;
    if !sortie_permise(&t) {
        return Err(Rejet::Forme);
    }
    Ok(t)
}

/// Vrai si la relecture finale de `passer` n'a rien à refuser pour ce texte, sous chaque forme : le banc de fuzzing et
/// les essais l'exigent, pour qu'un écart entre le filtre et la relecture se voie au lieu d'être tu par ce refus.
#[cfg(any(test, fuzzing))]
pub(crate) fn relecture_inutile(brut: &str) -> bool {
    [TEXTE, NOM, VERSION].into_iter().all(|forme| {
        passer_sans_relecture(brut, forme)
            .ok()
            .is_none_or(|t| sortie_permise(&t))
    })
}

fn passer_sans_relecture(brut: &str, forme: Forme) -> Result<String, Rejet> {
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
    let c = masques(c, forme.ip, &mut alertes);
    let c = filtrer(&c);
    (couper(&c, forme.max), alertes)
}

/// Les masques d'une passe, sans le filtre de l'étape 5 ni la coupe : la part commune à `nettoyer` et à `masquer`.
fn masques(c: &[char], ip: bool, alertes: &mut u32) -> Vec<char> {
    let c = couche_precise(c, alertes);
    let c = masquer_arobases(&c);
    let c = masquer_formes(&c, ip);
    let c = couche_precise(&c, alertes);
    couche_entropie(&c, alertes)
}

/// Ce que rend `masquer` quand ses passes ne trouvent pas leur point fixe : le texte entier est retiré, plutôt que
/// gardé à moitié masqué.
pub(crate) const RETIRE: &str = "[texte retiré : masquage instable]";

/// Le masquage seul, pour un texte long gardé pour l'auteur (le journal des erreurs) ou montré à la personne avant de
/// partir (le brouillon de `vanguard signaler`) : les mêmes masques que `nettoyer` (séries, secrets, MAC, IP, chemins,
/// jetons), jusqu'au point fixe, mais ni la borne de 300 octets, ni le filtre des caractères, ni les refus (une
/// sortie de PowerShell a peu de lettres et doit rester lisible). Le texte rendu est normalisé (invisibles retirés,
/// pleine chasse ramenée à l'ASCII, tabulations en espaces, fins de ligne en « \n ») : les masques ont jugé ce
/// texte-là, pas le brut. Au-delà de `ENTREE_MAX` octets, le reste est coupé à une espace et « […] » le dit : le coût
/// reste borné. Comme pour `nettoyer`, le retrait des noms (`journal::anonymiser`) et des faux marqueurs se fait
/// avant, dans `amelioration::masquer`.
pub(crate) fn masquer(brut: &str) -> String {
    let borne = borne_entree(brut);
    let mut t = normaliser(&borne.replace("\r\n", "\n"));
    let mut stable = false;
    for _ in 0..PASSES_MAX {
        let mut alertes = 0;
        let s = masques(&t, true, &mut alertes);
        if s == t {
            stable = true;
            break;
        }
        t = s;
    }
    if !stable {
        return RETIRE.to_string();
    }
    let mut sortie: String = t.into_iter().collect();
    if borne.len() < brut.len() {
        sortie.push_str(" […]");
    }
    sortie
}

/// Toute adresse web devient « `<url>` », où qu'elle soit, même collée à ce qui la précède (« --url=https://… »,
/// « voir:wss://… », « lien=www.… ») : le masquage, qui veut une frontière de mot devant, laissait sinon
/// « https:`<chemin>`?session=… », la requête lisible (relecture 0.97, haut f). Tout schéma « lettres:// » compte
/// (wss, ftp, rtsp, l'écriture désarmée hxxps), et aussi ses barres échappées à la JSON (« https:\/\/… »).
/// L'adresse va jusqu'à une espace ; un guillemet, un chevron ou un accent grave ne la ferme que s'il ouvrait juste
/// devant elle (« "https://…" », « `<https://…>` ») : permis dans une adresse (« /wiki/L'Avare », « q=`<script>` »),
/// ils laissaient sinon la suite de la requête en clair. La ponctuation qui la ferme (« . », « , », « ) ») reste
/// derrière.
pub(crate) fn sans_urls(texte: &str) -> String {
    sans_urls_avec(texte, str::to_string)
}

/// Le texte désarmé pour le masquage : normalisé, adresses web retirées entières (`sans_urls`), puis faux marqueurs
/// désarmés entre elles seulement (`sans_faux_marqueurs`). Dans l'autre ordre, le chevron d'un faux marqueur écrit
/// dans une adresse (« https://x/`<ip>`/y?session=… ») devenait une espace qui la coupait (relecture 0.97, moyen).
pub(crate) fn desarme(brut: &str) -> String {
    let t = normalise(&brut.replace("\r\n", "\n"));
    sans_urls_avec(&t, sans_faux_marqueurs)
}

/// `sans_urls`, en passant `autour` sur chaque morceau de texte entre deux adresses.
fn sans_urls_avec(texte: &str, autour: impl Fn(&str) -> String) -> String {
    let bas = texte.to_ascii_lowercase();
    let mut sortie = String::with_capacity(texte.len());
    let mut pos = 0;
    while let Some((i, corps)) = prochaine_url(&bas, pos) {
        sortie.push_str(&autour(&texte[pos..i]));
        let url = &texte[i..];
        let fermant = match texte[..i].chars().next_back() {
            Some('"') => Some('"'),
            Some('\'') => Some('\''),
            Some('<') => Some('>'),
            Some('`') => Some('`'),
            _ => None,
        };
        // Jusqu'à une espace ; un fermant ne ferme qu'au dernier de ce morceau : « 'https://…/L'Avare?lecteur=…' »
        // ou « <https://…?q=a>b&lecteur=…> » laissaient sinon la requête (relecture 0.97, ronde 4, bas).
        let blanc = url
            .get(corps..)
            .and_then(|reste| reste.find(char::is_whitespace))
            .map_or(url.len(), |k| k.saturating_add(corps));
        let fin = fermant
            .and_then(|f| url.get(corps..blanc)?.rfind(f))
            .map_or(blanc, |k| k.saturating_add(corps));
        let garde = url[..fin].trim_end_matches(['.', ',', ';', ':', ')', ']', '}', '!']);
        sortie.push_str("<url>");
        sortie.push_str(&url[garde.len()..fin]);
        pos = i.saturating_add(fin);
    }
    sortie.push_str(&autour(&texte[pos..]));
    sortie
}

/// La prochaine adresse web à partir de `pos` dans le texte en minuscules : son début et la longueur de son schéma
/// (« wss:// », « www. »), qui n'est jamais coupée. Un schéma a au moins deux caractères, dont une lettre en tête :
/// « C://x » n'en est pas un.
fn prochaine_url(bas: &str, pos: usize) -> Option<(usize, usize)> {
    [
        url_a_schema(bas, pos),
        url_a_une_barre(bas, pos),
        url_sans_schema(bas, pos),
    ]
    .into_iter()
    .flatten()
    .min()
}

/// Les schémas du web qui restent une adresse avec une seule barre (« https:/exemple.com/… », une barre perdue en
/// route) ; un autre mot devant « :/ » (« erreur:/home/… ») est un chemin, pris par le masquage.
const SCHEMAS_A_UNE_BARRE: [&str; 8] = ["http", "https", "hxxp", "hxxps", "ftp", "ftps", "ws", "wss"];

/// La prochaine adresse « schéma:/hôte… » à une seule barre, schéma de `SCHEMAS_A_UNE_BARRE` (relecture 0.97,
/// ronde 4, bas).
fn url_a_une_barre(bas: &str, pos: usize) -> Option<(usize, usize)> {
    bas.get(pos..)?.match_indices(":/").find_map(|(k, _)| {
        let k = pos.saturating_add(k);
        if !bas
            .as_bytes()
            .get(k.saturating_add(2))
            .is_some_and(u8::is_ascii_alphanumeric)
        {
            return None;
        }
        let debut = k.saturating_sub(bas[..k].bytes().rev().take_while(u8::is_ascii_alphabetic).count());
        let avant_ok = !bas[..debut]
            .bytes()
            .next_back()
            .is_some_and(|b| b.is_ascii_alphanumeric());
        (avant_ok && SCHEMAS_A_UNE_BARRE.contains(&&bas[debut..k]))
            .then(|| (debut, k.saturating_add(2).saturating_sub(debut)))
    })
}

/// La prochaine adresse sans schéma à « // » en tête (« //cdn.exemple.com/… ») : rien de collé devant, et un hôte à
/// point juste après (relecture 0.97, ronde 4, bas).
fn url_sans_schema(bas: &str, pos: usize) -> Option<(usize, usize)> {
    bas.get(pos..)?.match_indices("//").find_map(|(k, _)| {
        let k = pos.saturating_add(k);
        let avant_ok = bas[..k]
            .bytes()
            .next_back()
            .is_none_or(|b| b.is_ascii_whitespace() || b"\"'(<=[,;`".contains(&b));
        let hote: &str = bas
            .get(k.saturating_add(2)..)?
            .split(|x: char| !(x.is_ascii_alphanumeric() || x == '.' || x == '-'))
            .next()?;
        let a_point = hote.split('.').filter(|e| !e.is_empty()).count() >= 2
            && hote
                .rsplit('.')
                .next()
                .is_some_and(|tld| tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic()));
        (avant_ok && a_point).then_some((k, 2))
    })
}

/// La prochaine adresse « schéma:// » ou « www. ».
fn url_a_schema(bas: &str, mut pos: usize) -> Option<(usize, usize)> {
    let de_schema = |b: u8| b.is_ascii_alphanumeric() || b"+.-".contains(&b);
    loop {
        let reste = bas.get(pos..)?;
        let separateur = ["://", ":\\/\\/"]
            .iter()
            .filter_map(|s| reste.find(s).map(|k| (pos.saturating_add(k), s.len())))
            .min();
        let www = reste
            .match_indices("www.")
            .map(|(k, _)| pos.saturating_add(k))
            .find(|&k| {
                !bas[..k]
                    .bytes()
                    .next_back()
                    .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'.')
                    && bas
                        .as_bytes()
                        .get(k.saturating_add(4))
                        .is_some_and(u8::is_ascii_alphanumeric)
            });
        let schema = separateur.map(|(k, n)| {
            let debut = bas[..k].bytes().rev().take_while(|b| de_schema(*b)).count();
            let mut d = k.saturating_sub(debut);
            // Le schéma commence à sa première lettre (« --url=… » s'arrête au « = », « -wss:// » au « w »).
            while d < k && !bas.as_bytes().get(d).is_some_and(u8::is_ascii_alphabetic) {
                d = d.saturating_add(1);
            }
            (d, k, k.saturating_add(n))
        });
        match (schema, www) {
            (Some((d, _, _)), Some(w)) if w < d => return Some((w, 4)),
            (None, Some(w)) => return Some((w, 4)),
            (Some((d, k, apres)), _) if k.saturating_sub(d) >= 2 => return Some((d, apres.saturating_sub(d))),
            (Some((_, _, apres)), _) => pos = apres,
            (None, None) => return None,
        }
    }
}

/// Le brut sans faux marqueurs : un « `<ip>` » ou un « `<chemin .pdf>` » écrit dans le texte (pleine chasse et
/// invisibles compris) perd son chevron ouvrant. Sans cela, les masques le sauteraient comme un marqueur déjà posé,
/// et il pourrait couper un jeton en deux (« ghp_`<ip>`… »). Les autres chevrons restent (« a < b », une preuve de
/// concept en HTML), à la différence de `sans_chevrons`. Rend le texte normalisé, comme `masquer`.
pub(crate) fn sans_faux_marqueurs(brut: &str) -> String {
    let mut c = normaliser(&brut.replace("\r\n", "\n"));
    let mut i = 0;
    while i < c.len() {
        if marqueur(&c, i).is_some()
            && let Some(x) = c.get_mut(i)
        {
            *x = ' ';
        }
        i = suivant(i);
    }
    c.into_iter().collect()
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

/// Le texte brut sans chevrons, pleine chasse comprise : à appliquer avant `journal::anonymiser`, qui pose ses
/// propres marqueurs. Sans cela, « `<secret>` » écrit dans un message d'erreur passerait pour un marqueur posé par
/// le nettoyage, et ce qui le suit ou l'entoure échapperait à la recherche.
pub(crate) fn sans_chevrons(brut: &str) -> String {
    brut.chars()
        .map(|x| if matches!(pleine_chasse(x), '<' | '>') { ' ' } else { x })
        .collect()
}

/// La normalisation du nettoyage (`normaliser`), rendue en texte. La porte MCP la fait passer avant ses propres
/// réductions : faites sur le brut, elles ne verraient pas « （…） » ni « P\u{200B}ID », que le nettoyage ramène
/// ensuite à « (…) » et à « PID ».
pub(crate) fn normalise(texte: &str) -> String {
    normaliser(texte).into_iter().collect()
}

/// Le texte en caractères : invisibles retirés, formes pleine chasse (« ｇｈｐ＿ ») ramenées à l'ASCII, fins de ligne
/// unifiées (une valeur de `Cookie:` court jusqu'à la fin de sa ligne), autres contrôles et espaces en espace simple,
/// guillemets et apostrophes typographiques en guillemet et apostrophe droits (« password : « … » » est une valeur
/// entre guillemets, comme `password: "…"`).
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
        // Les points idéographiques (« 198。51。100。23 ») : un point pour le détecteur d'adresses.
        '\u{3002}' | '\u{FF61}' => '.',
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
const CLES: [&str; 23] = [
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
    // L'allemand colle ses mots : « Netzwerksicherheitsschlüssel », « Schlüsselinhalt » (netsh wlan … key=clear).
    "passwort",
    "kennwort",
    "schlüssel",
    // Sans tréma, comme on l'écrit sur un clavier sans « ü ».
    "schluessel",
    "schlussel",
];

/// Mots courts qui annoncent un secret seulement comme mot entier ou comme dernier morceau d'un nom (`DB_PASS`,
/// `wifi-psk`, « Clé : ») : cherchés dans un mot, ils sonneraient partout (« compass », « keyboard »).
const CLES_COURTES: [&str; 10] = ["pass", "pw", "psk", "mdp", "cle", "clé", "clef", "key", "passe", "pin"];

/// Mots qui annoncent un secret même quelques mots avant le séparateur : « Mot de passe Wi-Fi : … », « Clé de
/// sécurité réseau : … », « Invalid API key: … ».
const CLES_FORTES: [&str; 11] = [
    "passe",
    "clé",
    "cle",
    "clef",
    "password",
    "passwd",
    "passphrase",
    "mdp",
    "psk",
    "passwort",
    "kennwort",
];

/// Clés dont la valeur court jusqu'à la fin de la ligne : « Authorization: Basic … », « Cookie: a=1; b=2 ».
const CLES_LIGNE: [&str; 2] = ["authorization", "cookie"];

/// Mots qui annoncent un mot de passe, souvent une phrase de passe de plusieurs mots (« phrase de passe : lune verte
/// soupe orange ») : la valeur court jusqu'à la fin de la phrase, pas seulement jusqu'à la première espace.
/// Aussi « secret », « clé », « pw » : un secret de plusieurs mots (« client_secret=lune verte ») ne sort pas plus que
/// la phrase de passe.
const CLES_PHRASE: [&str; 13] = [
    "passe",
    "password",
    "passwd",
    "passphrase",
    "mdp",
    "psk",
    "pwd",
    "pass",
    "secret",
    "clé",
    "cle",
    "clef",
    "pw",
];

/// Ce qui, n'importe où dans un nom écrit sans « _ » ni « - » (« PGPASSWORD », « userPassword », « pass-phrase »),
/// annonce aussi une phrase de passe ; de même en allemand (« Kennwort », « Netzwerksicherheitsschlüssel » : une clé
/// de Wi-Fi peut porter des espaces).
const CLES_PHRASE_DANS: [&str; 9] = [
    "password",
    "passwd",
    "passphrase",
    "motdepasse",
    "passwort",
    "kennwort",
    "schlüssel",
    "schluessel",
    "schlussel",
];

/// Les formes de « mot de passe » (et « pass phrase ») qui, dans les 48 caractères avant le séparateur, annoncent un
/// secret à quelques mots de distance. Aussi « phrase secrète » (GnuPG en français), « code d'accès » et « Key
/// Content » (la clé du Wi-Fi que montre « netsh wlan show profile key=clear » : « content » seul n'annonce rien).
const MOTS_DE_PASSE: [&str; 11] = [
    "mot de passe",
    "mot-de-passe",
    "mot_de_passe",
    "motdepasse",
    "pass phrase",
    "phrase secrète",
    "phrase secrete",
    "code d'accès",
    "code d'acces",
    "code d’accès",
    "key content",
];

/// Les mots qui annoncent un jeton à la suite (« Bearer abc… »).
const SCHEMAS: [&str; 5] = ["bearer", "basic", "token", "digest", "negotiate"];

/// Les options de ligne de commande et les mots suivis du secret après une simple espace : `--password x`,
/// `-Password x`, `/pass x`, `-p x`, « mot de passe x », `sshpass -p x`. Sans `-`, « p » et « u » ne comptent pas.
const CLES_SANS_SEPARATEUR: [&str; 15] = [
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
    "passwort",
    "kennwort",
    "p",
];

fn mot_de_cle(x: char) -> bool {
    x.is_alphanumeric() || x == '_' || x == '-'
}

fn entre_cle_et_valeur(x: char) -> bool {
    x == ' ' || x == '\t' || x == '"' || x == '\''
}

/// Si le caractère juste avant `k` sépare une clé de sa valeur : `entre_cle_et_valeur`, ou la barre d'un guillemet
/// échappé (« \\"password\\": \\"lune verte\\" », du JSON dans du JSON). Pas une barre seule : « dossier\\pass\\x »
/// est un chemin.
fn separe_cle_et_valeur(c: &[char], k: usize) -> bool {
    avant(c, k)
        .is_some_and(|y| entre_cle_et_valeur(y) || (y == '\\' && car(c, k).is_some_and(|q| q == '"' || q == '\'')))
}

/// Un nom sans « _ » ni « - » : « pass-phrase » et « pass_phrase » se lisent « passphrase ».
fn compact(mot: &str) -> String {
    mot.chars().filter(|y| *y != '_' && *y != '-').collect()
}

/// Si ce mot (en minuscules) annonce un secret : un mot-clé dedans, ou un mot court entier ou en dernier morceau.
fn mot_annonce_un_secret(mot: &str) -> bool {
    let tasse = compact(mot);
    // Sans accents : « secrète » contient alors « secret ».
    let plat: String = tasse.chars().map(sans_accent).collect();
    CLES.iter()
        .any(|cle| mot.contains(cle) || tasse.contains(cle) || plat.contains(cle))
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
    let echappe = premier == '\\' && car(c, suivant(i)).is_some_and(|q| q == '"' || q == '\'');
    if premier.is_whitespace() || "\"'=:".contains(premier) || echappe {
        return None;
    }
    let mut j = i;
    while separe_cle_et_valeur(c, j) {
        j = j.checked_sub(1)?;
    }
    let separateur = j.checked_sub(1)?;
    let sep = car(c, separateur)?;
    if !(sep == ':' || sep == '=') || (sep == ':' && (avant(c, separateur) == Some(':') || premier == ':')) {
        return apres_option(c, i, j);
    }
    let mut k = separateur;
    while separe_cle_et_valeur(c, k) || avant(c, k).is_some_and(|y| y == '=' || y == ':') {
        k = k.checked_sub(1)?;
    }
    let mots = mots_avant(c, k);
    let dernier = mots.first().map_or("", String::as_str);
    // « -p=Lune2Verte » : la même règle que la valeur collée à « -p ».
    if sep == '=' && dernier.starts_with('-') && dernier.trim_start_matches('-') == "p" {
        let fin = fin_tant_que(c, i, |y| !y.is_whitespace() && y != '"' && y != '\'');
        return (fin > i && mot_de_passe_colle(morceau(c, i, fin))).then_some(fin);
    }
    let devant = chaine(c, k.saturating_sub(48), k).to_lowercase();
    let annonce = mot_annonce_un_secret(dernier)
        || mots.iter().any(|m| CLES_FORTES.contains(&m.as_str()))
        || MOTS_DE_PASSE.iter().any(|m| devant.contains(m));
    if !annonce {
        return None;
    }
    let phrase = mots.iter().any(|m| {
        CLES_PHRASE.iter().any(|cle| {
            m == cle
                || m.strip_suffix(cle)
                    .is_some_and(|tete| tete.ends_with('_') || tete.ends_with('-'))
        }) || CLES_PHRASE_DANS.iter().any(|cle| compact(m).contains(cle))
    }) || MOTS_DE_PASSE.iter().any(|m| devant.contains(m));
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
    } else if phrase {
        fin_de_phrase(c, i)
    } else {
        // Jusqu'à une espace seulement : un mot de passe peut contenir `(`, `,`, `;`, `&` ou commencer par eux.
        let fin = fin_tant_que(c, i, |y| !y.is_whitespace());
        apres_schema(c, i, fin)
    };
    (fin > i).then_some(fin)
}

/// La fin de la phrase qui commence en `i` : un saut de ligne, ou un « . ; ! ? » suivi d'une espace ou de la fin
/// du texte (ce signe n'en fait pas partie). « Wi-Fi.Maison » ou « a.b » ne la coupent pas.
fn fin_de_phrase(c: &[char], i: usize) -> usize {
    let mut j = i;
    while let Some(y) = car(c, j) {
        if y == '\n' || (".;!?".contains(y) && car(c, suivant(j)).is_none_or(char::is_whitespace)) {
            break;
        }
        j = suivant(j);
    }
    j
}

/// La valeur qui suit une option ou un mot connu après une simple espace (`j` : début des espaces) : `-p x`,
/// `--password x`, « mot de passe x », `-u alice:x`. Un mot de la langue n'est pas pris.
fn apres_option(c: &[char], i: usize, j: usize) -> Option<usize> {
    if j == i {
        return option_collee(c, i);
    }
    if let Some(fin) = apres_net_use(c, i) {
        return Some(fin);
    }
    // Entre guillemets (« -p 'Lune2 Verte9' », « Kennwort "Lune2Verte" ») : jusqu'au même guillemet.
    let guillemet = guillemet_ouvrant(c, i);
    // Dans une liste de Python (« ['mysql', '-p', 'Lune2Verte'] ») : l'option est le mot entre guillemets avant la
    // virgule ; sans ce saut, son guillemet fermant passerait pour l'ouvrant de la valeur.
    let mut fin_option = j;
    if guillemet.is_some() && avant(c, fin_option) == Some(',') {
        let fermant = fin_option.checked_sub(1)?;
        if avant(c, fermant).is_some_and(|y| y == '"' || y == '\'') {
            fin_option = fermant.checked_sub(1)?;
        }
    }
    let mut debut = fin_option;
    while avant(c, debut).is_some_and(|y| mot_de_cle(y) || y == '/') {
        debut = debut.checked_sub(1)?;
    }
    // « '-p', » : ce guillemet ferme l'option entre guillemets, la valeur n'est pas la virgule (elle la suit). Collée
    // (« "-p"Lune2Verte », lu « -pLune2Verte » par le shell), elle reste prise.
    if fin_option == j && guillemet.is_some() && avant(c, debut) == guillemet && car(c, i) == Some(',') {
        return None;
    }
    let brut = chaine(c, debut, fin_option).to_lowercase();
    let option = brut.starts_with(['-', '/']);
    let mot = brut.trim_start_matches(['-', '/']);
    let fin = fin_de_valeur(c, i, guillemet);
    let valeur = morceau(c, i, fin);
    let utilisateur = option && matches!(mot, "u" | "user") && valeur.iter().any(|y| *y == ':' || *y == '%');
    let cle = CLES_SANS_SEPARATEUR.contains(&mot) && (option || mot.len() > 1);
    // Entre guillemets, la valeur peut avoir plusieurs mots : « -p 'mon dossier' » reste, « -p 'Lune2 Verte9' » non.
    let langue = valeur.split(|y| y.is_whitespace()).all(mot_de_la_langue);
    ((cle && !langue) || utilisateur).then_some(fin)
}

/// La valeur collée à une option courte, au début d'un mot : « mysql -pLune2Verte », « -ualice:Lune2Verte ». Pour
/// « -p », ni un mot de la langue ou des minuscules et tirets (« -pthread », « -pedantic-errors »), ni un port
/// (« docker -p8080:80 ») ; pour « -u », seulement avec « : » ou « % » (utilisateur et mot de passe). L'option peut
/// être entre guillemets ou dans une liste (« '-pLune2Verte', », l'erreur de subprocess de Python) : la valeur s'arrête
/// alors au même guillemet.
fn option_collee(c: &[char], i: usize) -> Option<usize> {
    let lettre = avant(c, i)?;
    let tiret = i.checked_sub(2).and_then(|k| car(c, k))?;
    let devant = i.checked_sub(3).and_then(|k| car(c, k));
    // Aussi après « = » : « OPTS=-pLune2Verte ».
    let debut_de_mot = devant.is_none_or(|y| y.is_whitespace() || "\"'[(,=".contains(y));
    if tiret != '-' || !debut_de_mot || !matches!(lettre, 'p' | 'u') {
        return None;
    }
    let guillemet = devant.filter(|y| *y == '"' || *y == '\'');
    let fin = fin_tant_que(c, i, |y| !y.is_whitespace() && Some(y) != guillemet);
    let valeur = morceau(c, i, fin);
    let pris = if lettre == 'u' {
        valeur.iter().any(|y| *y == ':' || *y == '%')
    } else {
        mot_de_passe_colle(valeur)
    };
    (pris && fin > i).then_some(fin)
}

/// Si la valeur collée à « -p » (« -pLune2Verte », « -p=Lune2Verte ») est un mot de passe : ni un mot de la langue ou
/// des minuscules et tirets (« -pthread », « -pedantic-errors »), ni un port (« -p8080:80 »), ni un signe seul (« -p$ »
/// devant une espace : le vrai mot de passe suit, pris à la passe suivante quand le filtre a ôté le signe). Quatre
/// signes ou plus (« -p!!!! ») sont pris.
fn mot_de_passe_colle(valeur: &[char]) -> bool {
    !mot_de_la_langue(valeur)
        && (valeur.iter().any(|y| y.is_alphanumeric()) || valeur.len() >= 4)
        && !valeur.iter().all(|y| y.is_lowercase() || *y == '-' || *y == '_')
        && !valeur.iter().all(|y| y.is_ascii_digit() || ":.-/".contains(*y))
}

/// Le guillemet collé devant la valeur en `i`, s'il y en a un : c'est lui qui l'ouvre. Pas un guillemet plus loin
/// (« "-p" Lune2Verte » : celui-là ferme l'option).
fn guillemet_ouvrant(c: &[char], i: usize) -> Option<char> {
    avant(c, i).filter(|y| *y == '"' || *y == '\'')
}

/// La fin d'une valeur : ouverte par un guillemet, jusqu'au même guillemet ou à la fin de la ligne, espaces comprises
/// (« -p 'Lune2 Verte9' ») ; sinon jusqu'à une espace.
fn fin_de_valeur(c: &[char], i: usize, guillemet: Option<char>) -> usize {
    match guillemet {
        Some(q) => fin_tant_que(c, i, |y| y != q && y != '\n'),
        None => fin_tant_que(c, i, |y| !y.is_whitespace()),
    }
}

/// « net use Z: \\\\serveur\\partage Lune2Verte /user:alice » : le mot de passe de Windows suit le chemin UNC (« \\\\ »
/// ou « // », entre guillemets ou non ; après une lettre de lecteur ou « * », et au plus quatre options « /… » entre
/// le chemin et lui). « net.exe » aussi. Entre guillemets, la valeur va jusqu'au même guillemet.
fn apres_net_use(c: &[char], i: usize) -> Option<usize> {
    if car(c, i) == Some('/') {
        return None;
    }
    // Les mots avant la valeur, du plus proche au plus loin. On part de la valeur (sans son guillemet ouvrant), pas de
    // `j` : le guillemet fermant d'un chemin (« "\\srv\mon partage" Lune2Verte ») appartient au mot d'avant.
    let mut mots = Vec::new();
    let mut curseur = if guillemet_ouvrant(c, i).is_some() {
        i.saturating_sub(1)
    } else {
        i
    };
    while mots.len() < 8 {
        while avant(c, curseur).is_some_and(|y| y == ' ' || y == '\t') {
            curseur = curseur.saturating_sub(1);
        }
        let mut debut = curseur;
        // Un mot entre guillemets (« "\\srv\mon partage" ») se prend en entier, espaces comprises.
        if let Some(q) = avant(c, debut).filter(|y| *y == '"' || *y == '\'') {
            let mut k = debut.saturating_sub(1);
            while avant(c, k).is_some_and(|y| y != q && y != '\n') {
                k = k.saturating_sub(1);
            }
            if avant(c, k) == Some(q) {
                debut = k.saturating_sub(1);
            }
        }
        while avant(c, debut).is_some_and(|y| !y.is_whitespace()) {
            debut = debut.saturating_sub(1);
        }
        if debut == curseur {
            break;
        }
        let brut = chaine(c, debut, curseur).to_lowercase();
        // Un guillemet ouvert et pas refermé : la valeur est dans ce mot (« "\\srv\mon partage" » vu depuis
        // « partage" »), pas après lui.
        let ouvert = brut
            .chars()
            .next()
            .filter(|q| *q == '"' || *q == '\'')
            .is_some_and(|q| brut.chars().count() == 1 || !brut.ends_with(q));
        mots.push((brut.trim_matches(['"', '\'']).to_string(), ouvert));
        curseur = debut;
    }
    let unc = mots
        .iter()
        .take(5)
        .position(|(mot, _)| mot.starts_with("\\\\") || mot.starts_with("//"))?;
    if !mots.iter().take(unc).all(|(mot, _)| mot.starts_with('/')) || mots.iter().take(suivant(unc)).any(|m| m.1) {
        return None;
    }
    let mots: Vec<String> = mots.into_iter().map(|(mot, _)| mot).collect();
    let reste = mots.get(suivant(unc)..).unwrap_or(&[]);
    let lecteur = reste
        .first()
        .is_some_and(|mot| mot == "*" || (mot.chars().count() == 2 && mot.ends_with(':')));
    let reste = if lecteur { reste.get(1..).unwrap_or(&[]) } else { reste };
    // « C:\Windows\System32\net.exe » aussi : le dernier élément du chemin (les mots sont déjà en minuscules).
    let commande = matches!(reste, [verbe, net, ..]
        if verbe == "use" && matches!(net.rsplit(['\\', '/']).next(), Some("net" | "net.exe")));
    let fin = fin_de_valeur(c, i, guillemet_ouvrant(c, i));
    (commande && fin > i).then_some(fin)
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
/// n'est pas le chemin « //h/x »), numéro de série annoncé, IPv6 en nom inverse ou à tirets, chemin absolu, GUID,
/// adresse MAC (à deux-points, à tirets, à points, dans un nom d'interface), adresse IP (à points, puis à tirets dans
/// un nom d'hôte), chemin relatif, groupes de chiffres, longue suite hexadécimale.
fn masquer_formes(c: &[char], ip: bool) -> Vec<char> {
    // Les positions où aucune IPv6 ne peut commencer (`Ip6::RienJusqua`) : chaque suite n'est lue qu'une fois.
    let mut sans_ipv6_avant = 0;
    // Une requête collée à un marqueur (« `<chemin .pdf>`?session=… ») part avec lui (relecture 0.97, ronde 4, bas).
    let avec_requete = |c: &[char], (fin, par): (usize, String)| {
        if car(c, fin) == Some('?') {
            (fin_tant_que(c, fin, |x| !fin_d_adresse(x)), par)
        } else {
            (fin, par)
        }
    };
    remplacer(c, |c, i| {
        forme(c, i, ip, &mut sans_ipv6_avant).map(|f| avec_requete(c, f))
    })
}

/// La forme à masquer qui commence en `i`, sa fin et son remplacement.
fn forme(c: &[char], i: usize, ip: bool, sans_ipv6_avant: &mut usize) -> Option<(usize, String)> {
    {
        if let Some(fin) = coupe_a_gauche(c, i) {
            return Some((fin, "<chemin>".to_string()));
        }
        if let Some(fin) = adresse_web(c, i) {
            return Some((fin, "<url>".to_string()));
        }
        if let Some((debut, fin)) = serie(c, i) {
            return Some((fin, format!("{}<numéro>", chaine(c, i, debut))));
        }
        if ip && let Some(fin) = nom_inverse_ipv6(c, i) {
            return Some((fin, "<ip>".to_string()));
        }
        if ip && let Some(fin) = ipv6_a_tirets(c, i) {
            return Some((fin, "<ip>".to_string()));
        }
        if let Some((fin, nom)) = chemin(c, i) {
            return Some((fin, marqueur_de_chemin(&chaine(c, i, nom))));
        }
        if let Some(fin) = guid(c, i) {
            return Some((fin, "<guid>".to_string()));
        }
        if let Some(fin) = mac(c, i) {
            return Some((fin, "<mac>".to_string()));
        }
        if let Some(fin) = interface_a_mac(c, i) {
            return Some((fin, format!("{}<mac>", chaine(c, i, plus(i, 3)))));
        }
        if let Some(fin) = mac_a_points(c, i) {
            return Some((fin, "<mac>".to_string()));
        }
        if ip && i >= *sans_ipv6_avant {
            match ipv6(c, i) {
                Ip6::Adresse(fin) => return Some((fin, "<ip>".to_string())),
                Ip6::RienJusqua(fin) => *sans_ipv6_avant = fin,
                Ip6::Heure(fin) => return Some((fin, morceau(c, i, fin).iter().collect())),
                Ip6::Rien => {}
            }
        }
        if ip && let Some(fin) = ipv4(c, i) {
            return Some((fin, "<ip>".to_string()));
        }
        if ip && let Some(fin) = ipv4_a_tirets(c, i) {
            return Some((fin, "<ip>".to_string()));
        }
        if let Some(fin) = chemin_relatif(c, i) {
            return Some((fin, marqueur_de_chemin(&chaine(c, i, fin))));
        }
        if let Some(fin) = groupes_de_chiffres(c, i) {
            return Some((fin, "<numéro>".to_string()));
        }
        hexa(c, i).map(|fin| (fin, "<hex>".to_string()))
    }
}

/// Un chemin coupé à gauche par « … » (un extrait, `chasse::extrait`) : « …oé Martin\Downloads\Facture.exe ». Son
/// début est perdu, rien ne dit où finit le nom ni s'il est sous un dossier personnel : tout part, jusqu'à la fin
/// de la ligne ou de l'extrait (« … » suivant). Reconnu à un « … » collé à ce qui suit, sans lettre ni chiffre
/// devant, et à une barre entre deux caractères non blancs dans les `SEGMENT_MAX` caractères qui suivent ;
/// « …et 3 autres » ou « Chargement… /usr/bin » restent (relecture 0.97, ronde 4, moyen).
fn coupe_a_gauche(c: &[char], i: usize) -> Option<usize> {
    if car(c, i) != Some('…')
        || avant(c, i).is_some_and(char::is_alphanumeric)
        || car(c, suivant(i)).is_none_or(char::is_whitespace)
    {
        return None;
    }
    let fin = fin_tant_que(c, suivant(i), |x| x != '\n' && x != '…');
    let barre = (suivant(i)..fin.min(plus(i, SEGMENT_MAX))).any(|k| {
        car(c, k).is_some_and(|x| x == '/' || x == '\\')
            && avant(c, k).is_some_and(|x| !x.is_whitespace())
            && car(c, suivant(k)).is_some_and(|x| !x.is_whitespace())
    });
    barre.then_some(fin)
}

/// Le texte sans les chemins coupés à gauche (`coupe_a_gauche`), pour une réduction qui ne passe pas par
/// `masquer`. Sans `normaliser` : le reste du texte est rendu tel quel (« «…» » ne devient pas « "…" »).
pub(crate) fn sans_coupes(texte: &str) -> String {
    let c: Vec<char> = texte.chars().collect();
    remplacer(&c, |c, i| coupe_a_gauche(c, i).map(|f| (f, "<chemin>".to_string())))
        .into_iter()
        .collect()
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

/// Un chemin absolu qui commence en `i` : sa fin, et la fin de son nom, d'où vient l'extension montrée. Windows (« C:\ », « \\nas\ »,
/// « \\?\C:\ », « %APPDATA%\ », « \Device\… »), Unix (« /… », « ~/… », « $HOME/… »).
fn chemin(c: &[char], i: usize) -> Option<(usize, usize)> {
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
        let (nom, a_extension) = fin_du_dernier(c, pos, bout, espace);
        if separateurs < exiges || (nom == pos && separateurs == 0 && pos == debut && pos == suivant(i)) {
            return None;
        }
        if nom == pos && entre(i, pos) <= 1 {
            return None;
        }
        let fin = if espace.is_some() {
            jusqu_a_l_arret(c, i, pos, bout, nom, a_extension)
        } else {
            nom
        };
        return Some((fin, nom));
    }
}

/// La fin d'un chemin dont le dernier élément porte des espaces, nom lu jusqu'à `nom` : entre guillemets ou
/// parenthèses, jusqu'au fermant ; sinon, sans mot à extension (« Rapport annuel.docx » finit le nom), jusqu'à
/// l'arrêt (`bout`) quand c'est « : » ou la fin de la ligne, ou sous un dossier personnel (« /home/ », « Users\ »,
/// « /run/media/ », « ~/ », `DOSSIERS_PERSONNELS`) ; jamais plus de `2 × SEGMENT_MAX` caractères après la dernière
/// barre. La fin d'un nom à espaces (« Impôts Zoé Martin ») sortait sinon après le marqueur (relecture 0.97, ronde 4,
/// moyen). Des mots de la phrase peuvent partir avec lui : un masque de trop, jamais un nom qui reste.
fn jusqu_a_l_arret(c: &[char], i: usize, pos: usize, bout: usize, nom: usize, a_extension: bool) -> usize {
    let borne = SEGMENT_MAX.saturating_mul(2);
    let fermant = match avant(c, i) {
        Some('"') => Some('"'),
        Some('\'') => Some('\''),
        Some('(') => Some(')'),
        _ => None,
    };
    if let Some(f) = fermant {
        let mut k = nom;
        while let Some(y) = car(c, k) {
            if y == f {
                return k;
            }
            if y == '\n' || entre(pos, k) > borne {
                break;
            }
            k = suivant(k);
        }
    }
    if a_extension {
        return nom;
    }
    let tete = chaine(c, i, pos).to_lowercase();
    let personnel = tete.starts_with('~')
        || tete.starts_with("$home")
        || tete.starts_with("%userprofile%")
        || tete.contains("/run/media/")
        || tete.split(['/', '\\']).any(|e| DOSSIERS_PERSONNELS.contains(&e));
    // Hors d'un dossier personnel, seul « chemin: message » arrête : la fin de ligne y laisserait avaler un mot de
    // passe (« net use \\\\srv\\partage Lune2Verte ») dans le marqueur, alors que le masquage le voit à part.
    let arret = if personnel {
        car(c, bout).is_none_or(|y| y == ':' || y == '\n')
    } else {
        car(c, bout) == Some(':') && car(c, suivant(bout)).is_none_or(char::is_whitespace)
    };
    if !arret || entre(pos, bout) > borne {
        return nom;
    }
    let mut fin = bout;
    while fin > nom && avant(c, fin).is_some_and(|y| y.is_whitespace() || y == '.') {
        fin = fin.saturating_sub(1);
    }
    fin
}

/// Un chemin relatif plus long que cela n'est pas lu : le coût d'une lecture reste borné.
const RELATIF_MAX: usize = 256;

/// Les dossiers de premier niveau du dépôt de Vanguard (et « library », la bibliothèque standard de Rust) : un
/// chemin qui commence par l'un d'eux (« src/journal.rs », « outils/verifier.sh », « ./relais/worker.js ») est le lieu
/// d'une panique ou un fichier du projet, pas un fichier de la personne.
const DOSSIERS_DU_DEPOT: [&str; 13] = [
    "src",
    "outils",
    "relais",
    "fuzz",
    "fenetre",
    "docs",
    "tests",
    "assets",
    "extensions",
    "supply-chain",
    "target",
    "library",
    "proptest-regressions",
];

/// Les dossiers personnels (sans casse) : un chemin qui en passe par un est masqué même sans extension
/// (« Users\\marie\\Documents », « Bureau/projets »).
const DOSSIERS_PERSONNELS: [&str; 17] = [
    "users",
    "home",
    "documents",
    "desktop",
    "bureau",
    "downloads",
    "téléchargements",
    "pictures",
    "images",
    "photos",
    "music",
    "musique",
    "videos",
    "vidéos",
    "onedrive",
    "dropbox",
    "appdata",
];

/// Les extensions qui font d'un mot seul un nom de fichier à masquer (`chemin_relatif`) : documents, courriels,
/// images, sons, vidéos, archives, et les suffixes de copie, de chiffrement ou de téléchargement (« .pdf.gpg »,
/// « .pdf.part », « .pdf.crdownload »), qu'un nom ait l'un ou l'autre en bout de chaîne (relecture 0.97, moyen).
/// Les programmes (« net.exe », « setup.msi ») n'y sont pas : leur nom est celui d'un outil, rarement d'une personne.
const EXTENSIONS_NUES: [&str; 82] = [
    "pdf",
    "doc",
    "docx",
    "docm",
    "dotx",
    "dotm",
    "odt",
    "rtf",
    "txt",
    "pages",
    "xls",
    "xlsx",
    "xlsm",
    "xlsb",
    "xltx",
    "ods",
    "numbers",
    "csv",
    "ppt",
    "pptx",
    "pptm",
    "potx",
    "odp",
    "key",
    "eml",
    "msg",
    "pst",
    "ost",
    "mbox",
    "vcf",
    "ics",
    "htm",
    "html",
    "jpg",
    "jpeg",
    "jfif",
    "png",
    "gif",
    "heic",
    "webp",
    "avif",
    "bmp",
    "tif",
    "tiff",
    "mp3",
    "m4a",
    "wav",
    "flac",
    "ogg",
    "mp4",
    "m4v",
    "mov",
    "mkv",
    "avi",
    "webm",
    "wmv",
    "zip",
    "7z",
    "rar",
    "gz",
    "tgz",
    "tar",
    "iso",
    "kdbx",
    "epub",
    "gpg",
    "asc",
    "bak",
    "tmp",
    "part",
    "crdownload",
    // Notes, données, journaux, certificats, profils VPN, bases (relecture 0.97, ronde 4, bas).
    "md",
    "json",
    "xml",
    "svg",
    "log",
    "pem",
    "p12",
    "pfx",
    "ovpn",
    "sqlite",
    "db",
];

/// Les extensions de programmes et de scripts : la sorte d'un fichier lancé, gardée dans « `<chemin .exe>` ».
const EXTENSIONS_DE_PROGRAMME: [&str; 17] = [
    "exe", "msi", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "sh", "py", "jar", "scr", "lnk", "deb", "rpm", "app",
];

/// Les noms de fichiers banals d'un projet (« README.txt », « requirements.txt ») : ils ne nomment personne et
/// aident à comprendre une erreur ; gardés (relecture 0.97, bas).
const NOMS_BANALS: [&str; 10] = [
    "readme",
    "license",
    "licence",
    "changelog",
    "requirements",
    "robots",
    "cmakelists",
    "contributing",
    "authors",
    "copying",
];

/// Une extension montrable : dans la liste fermée et d'au plus `EXTENSION_MAX` caractères, la règle du marqueur
/// « `<chemin .ext>` » (et du relais, `outils/relais-schema.py`). Une « extension » quelconque peut être un nom
/// (« zoe.martin », « Rapport.alice »). Les extensions plus longues de la liste (« numbers », « crdownload »,
/// « sqlite ») servent seulement à reconnaître un nom nu : jamais montrées (relecture 0.97, ronde 4, bas).
pub(crate) fn extension_connue(ext: &str) -> bool {
    let e = ext.to_ascii_lowercase();
    e.len() <= EXTENSION_MAX && (EXTENSIONS_NUES.contains(&e.as_str()) || EXTENSIONS_DE_PROGRAMME.contains(&e.as_str()))
}

/// Les dossiers dont chaque enfant direct est un compte (« /home/alice.pdf », « C:\Users\alice.pdf ») : son
/// « extension » est la fin d'un nom.
const PARENTS_DE_COMPTE: [&str; 3] = ["home", "users", "homes"];

/// L'extension montrée d'un chemin ou d'un nom de fichier : la dernière extension connue de son dernier élément
/// (« CV.pdf.crdownload » → pdf, « CV.pdf.zoe » → pdf), jamais une inconnue, ni pour un dossier de compte. Le seul
/// juge de ce qui sort dans un marqueur (`marqueur_de_chemin`) : chemins absolus et relatifs, noms nus, brouillon de
/// `vanguard signaler`, commande du journal (relecture 0.97, ronde 4, haut).
pub(crate) fn extension_montree(chemin: &str) -> Option<String> {
    let elements: Vec<&str> = chemin.split(['/', '\\']).filter(|e| !e.is_empty()).collect();
    let (dernier, parents) = elements.split_last()?;
    if parents
        .last()
        .is_some_and(|p| PARENTS_DE_COMPTE.contains(&p.to_lowercase().as_str()))
    {
        return None;
    }
    // Un point en tête (fichier caché) n'ouvre pas d'extension : « .bashrc » n'en a pas, « .Zoe-Martin.pdf » si.
    let morceaux: Vec<&str> = dernier.strip_prefix('.').unwrap_or(dernier).split('.').collect();
    if morceaux.first().is_none_or(|n| n.is_empty()) {
        return None;
    }
    morceaux.get(1..)?.iter().rev().find_map(|m| {
        let ext: String = m.chars().take_while(char::is_ascii_alphanumeric).collect();
        extension_connue(&ext).then(|| ext.to_ascii_lowercase())
    })
}

/// Le marqueur d'un chemin ou d'un nom de fichier : « `<chemin .pdf>` » ou « `<chemin>` » (`extension_montree`).
pub(crate) fn marqueur_de_chemin(chemin: &str) -> String {
    extension_montree(chemin).map_or_else(|| "<chemin>".to_string(), |e| format!("<chemin .{e}>"))
}

/// Un nom de fichier nu (« CV-Zoe-Martin.pdf ») : pris si une des extensions de sa chaîne est dans la liste fermée
/// (« .pdf.gpg », « .tar.gz », « .pdf.crdownload ») et si ce qui la précède porte une lettre, n'importe où
/// (« 2026.Zoe-Martin.pdf », « .Zoe-Martin.pdf ») ; « v1.2 », « 192.168.1.5 » ou « main.rs » restent (relecture 0.97,
/// moyens). Un nom nu ne commence pas avant un « = » (« --image=CV.pdf » : seul « CV.pdf » en est un), et un marqueur
/// déjà posé n'en fait pas partie (« --image=`<chemin .pdf>` » restait sinon un nom à extension, avalé avec le nom
/// de l'option : relecture 0.97, ronde 4, bas). L'extension montrée est celle de `extension_montree`.
fn nom_nu(nom: &[char]) -> bool {
    if nom.iter().any(|y| *y == '=' || *y == '<') {
        return false;
    }
    let texte: String = nom.iter().collect();
    let elements: Vec<&str> = texte.split('.').collect();
    let ext = |e: &str| -> String {
        e.chars()
            .take_while(char::is_ascii_alphanumeric)
            .collect::<String>()
            .to_ascii_lowercase()
    };
    let Some(connue) = (1..elements.len()).rev().find(|&k| {
        elements
            .get(k)
            .is_some_and(|e| EXTENSIONS_NUES.contains(&ext(e).as_str()))
    }) else {
        return false;
    };
    let lettre = elements
        .get(..connue)
        .is_some_and(|avant| avant.iter().any(|e| e.chars().any(char::is_alphabetic)));
    let banal = elements.len() == 2
        && elements
            .first()
            .is_some_and(|e| NOMS_BANALS.contains(&e.to_ascii_lowercase().as_str()));
    lettre && !banal
}

/// Un chemin relatif : des éléments séparés par « / » ou « \ » (« Documents/impots-2026.pdf », « Bureau\paie.xlsx »,
/// « .ssh/id_ed25519 », « ../Marie Tremblay/notes.txt »). Rend sa fin et l'extension de son dernier élément. Les
/// éléments du milieu peuvent porter des espaces (« Bureau/Marie Tremblay/paie.xlsx »), pas le premier ni le
/// dernier. N'est pris que ce qui ne peut pas être un mot à barre de la langue ou du métier (« read/write »,
/// « TCP/IP », « HTTP/1.1 », « o/N », « 8080/tcp », une clé de registre) : un dernier élément à extension qui porte
/// une lettre (« notes.db-journal », « paie.xlsx#Feuille1 » : l'extension est le début de ce qui suit le dernier
/// point), un élément caché n'importe où (« projet/.ssh/… »), un dossier personnel (`DOSSIERS_PERSONNELS`), ou
/// « . »/« .. » devant au moins deux éléments (« ../Marie/notes »). Un chemin du dépôt (`DOSSIERS_DU_DEPOT`) reste
/// lisible, sauf s'il passe par un dossier personnel ; « ./vanguard » aussi.
fn chemin_relatif(c: &[char], i: usize) -> Option<usize> {
    if !avant_chemin(avant(c, i)) || !car(c, i).is_some_and(caractere_de_chemin) {
        return None;
    }
    let separateur = |y: char| y == '/' || y == '\\';
    let arret = |y: char| separateur(y) || arret_de_chemin(y);
    let mut elements: Vec<(usize, usize)> = Vec::new();
    let mut pos = i;
    loop {
        // L'élément qui commence en `pos`, sans espace ; un marqueur de l'anonymisation en fait partie. La borne
        // compte depuis le début du chemin : chaque position de départ coûte au plus RELATIF_MAX caractères lus.
        let mut bout = pos;
        while let Some(y) = car(c, bout) {
            if entre(i, bout) > RELATIF_MAX {
                return None;
            }
            if let Some(fin) = marqueur(c, bout) {
                bout = fin;
            } else if arret(y) || y.is_whitespace() {
                break;
            } else {
                bout = suivant(bout);
            }
        }
        // Au milieu, un élément peut continuer après une espace s'il finit par un séparateur, sous SEGMENT_MAX et sans
        // point : un nom de fichier suivi de la phrase (« impots.pdf et Bureau/… ») n'est pas un dossier à espaces.
        if !elements.is_empty()
            && car(c, bout).is_some_and(char::is_whitespace)
            && !morceau(c, pos, bout).contains(&'.')
        {
            let mut k = bout;
            while car(c, k).is_some_and(|y| !arret(y) && y != '.') && entre(pos, k) <= SEGMENT_MAX {
                k = marqueur(c, k).unwrap_or(suivant(k));
            }
            if car(c, k).is_some_and(separateur) && !avant(c, k).is_some_and(char::is_whitespace) {
                bout = k;
            }
        }
        if bout == pos {
            return None;
        }
        elements.push((pos, bout));
        if car(c, bout).is_some_and(separateur) && car(c, suivant(bout)).is_some_and(|y| !y.is_whitespace()) {
            pos = suivant(bout);
            continue;
        }
        break;
    }
    let dernier = *elements.last()?;
    let seul = elements.len() < 2;
    // La ponctuation de fin de phrase (« . », « ) », « ! »…) ne fait pas partie du dernier élément ; « .. » oui.
    let mut fin = dernier.1;
    while fin > dernier.0
        && avant(c, fin).is_some_and(|y| ".)]}!".contains(y))
        && !morceau(c, dernier.0, fin).iter().all(|y| *y == '.')
    {
        fin = fin.saturating_sub(1);
    }
    let nom = morceau(c, dernier.0, fin);
    // L'extension : les lettres et chiffres qui suivent le dernier point, jusqu'au premier autre caractère.
    let extension: Option<String> = nom.iter().rposition(|y| *y == '.').and_then(|p| {
        let reste = nom.get(suivant(p)..)?;
        let n = reste.iter().take_while(|y| y.is_ascii_alphanumeric()).count();
        let ext: String = reste.get(..n)?.iter().collect();
        (1..=EXTENSION_MAX).contains(&n).then(|| ext.to_ascii_lowercase())
    });
    let a_lettre = extension
        .as_ref()
        .is_some_and(|e| e.chars().any(|y| y.is_ascii_alphabetic()));
    // Un nom de fichier nu (« CV-Zoe-Martin.pdf ») nomme souvent quelqu'un : pris seulement si son extension est d'un
    // document, d'une image, d'une archive ou d'un programme (liste fermée), et son nom porte une lettre ; « main.rs »,
    // « exemple.com » ou « v1.2 » restent (relecture 0.97, haut b).
    if seul {
        return nom_nu(nom).then_some(fin);
    }
    let textes: Vec<String> = elements.iter().map(|(a, b)| chaine(c, *a, *b).to_lowercase()).collect();
    let point = |e: &str| e == "." || e == "..";
    let cache = textes.iter().any(|e| e.starts_with('.') && !point(e));
    let relatif = textes.iter().any(|e| point(e)) && textes.iter().filter(|e| !point(e)).count() >= 2;
    let personnel = textes.iter().any(|e| DOSSIERS_PERSONNELS.contains(&e.as_str()));
    let depot = textes
        .iter()
        .find(|e| !point(e))
        .is_some_and(|e| DOSSIERS_DU_DEPOT.contains(&e.as_str()));
    ((a_lettre || cache || relatif || personnel) && (!depot || personnel)).then_some(fin)
}

/// La fin du nom du dernier élément d'un chemin, qui va de `pos` à `k` (arrêt ou fin) : jusqu'à la première espace,
/// sauf si un mot proche finit par une extension (« Rapport annuel.docx introuvable »), et si un tel mot a été trouvé.
/// Les points de fin de phrase n'en font pas partie.
fn fin_du_dernier(c: &[char], pos: usize, k: usize, espace: Option<usize>) -> (usize, bool) {
    let premiere = espace.map_or(k, |e| plus(pos, e));
    let mut fin = premiere;
    let mut trouve = false;
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
                trouve = true;
                break;
            }
            debut_mot = fin_tant_que(c, fin_mot, char::is_whitespace);
        }
    }
    while fin > pos && avant(c, fin) == Some('.') {
        fin = fin.saturating_sub(1);
    }
    (fin, trouve)
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

/// Une adresse MAC, à deux-points ou à tirets. À deux-points, ses bornes l'isolent d'une IPv6 (« fe80::1:2:3:4:5:6 »
/// n'en contient pas une). À tirets (la forme de Windows), aucune IPv6 n'est en jeu : ce qui la touche, avant comme
/// après (« MAC:00-1A-… », « id-00-1a-… », « 00-1A-…: link up »), ne la garde pas lisible, et la suite de jeton
/// collée derrière (« 00-1A-…_x », « 00-1A-…=… ») part avec elle plutôt que d'en laisser deviner la fin. À soulignés
/// (« bluez_card.00_1A_… », « dev_00_1A_… » de BlueZ et PipeWire), la même règle qu'à tirets.
fn mac(c: &[char], i: usize) -> Option<usize> {
    let s = car(c, plus(i, 2)).filter(|s| matches!(s, ':' | '-' | '_'))?;
    if s == ':' && avant(c, i).is_some_and(|p| jeton(p) || p == ':') {
        return None;
    }
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
    if s != ':' {
        return Some(fin_tant_que(c, j, jeton));
    }
    (!car(c, j).is_some_and(|y| jeton(y) || y == ':')).then_some(j)
}

/// Les préfixes des noms d'interface Linux qui portent l'adresse MAC de la carte (noms prévisibles de systemd : cartes
/// USB, partage de connexion, InfiniBand, liaison série).
const INTERFACES_A_MAC: [&str; 5] = ["enx", "wlx", "wwx", "ibx", "slx"];

/// « enx001a2b3c4d5e » : un préfixe d'interface puis exactement 12 chiffres hexadécimaux. Rend la fin ; le préfixe
/// reste lisible. Seul un chiffre hexadécimal de plus l'empêche après (« enx…p1 » garde son port) ; avant, seule une
/// lettre ou un chiffre ASCII : une lettre accentuée collée (« éenx… ») ne la désarme pas.
fn interface_a_mac(c: &[char], i: usize) -> Option<usize> {
    if avant(c, i).is_some_and(|p| p.is_ascii_alphanumeric())
        || !INTERFACES_A_MAC.iter().any(|p| commence_par_sans_casse(c, i, p))
    {
        return None;
    }
    let fin = hexadecimaux(c, plus(i, 3), 12)?;
    (!car(c, fin).is_some_and(|y| y.is_ascii_hexdigit())).then_some(fin)
}

/// La forme de Cisco, « 001a.2b3c.4d5e » : trois groupes de 4 chiffres hexadécimaux séparés par des points. Une suite
/// qui continue par un point et un caractère de jeton part avec elle. Seuls une lettre, un chiffre ou un point collés
/// l'empêchent : « mac=001a.… », « vlan-001a.… », « 001a.…/24 » sont des adresses. Trois groupes de chiffres
/// décimaux seuls (« 2026.1118.1504 », une version) n'en sont pas une.
fn mac_a_points(c: &[char], i: usize) -> Option<usize> {
    if avant(c, i).is_some_and(|p| p.is_alphanumeric() || p == '.') {
        return None;
    }
    let mut j = i;
    for rang in 0..3 {
        if rang > 0 {
            if car(c, j) != Some('.') {
                return None;
            }
            j = suivant(j);
        }
        j = hexadecimaux(c, j, 4)?;
    }
    if morceau(c, i, j).iter().all(|y| y.is_ascii_digit() || *y == '.') {
        return None;
    }
    if car(c, j) == Some('.') && car(c, suivant(j)).is_some_and(jeton) {
        return Some(fin_tant_que(c, j, jeton_etendu));
    }
    (!car(c, j).is_some_and(char::is_alphanumeric)).then_some(j)
}

/// Le nombre d'étiquettes d'un nom inverse IPv6 : 32 pour une adresse entière, moins pour un préfixe de zone.
const NOM_INVERSE_MAX: usize = 32;

/// « 7.0.0.0.….d.f.ip6.arpa » (requêtes PTR des journaux de dnsmasq, resolved, avahi) : de 1 à 32 chiffres
/// hexadécimaux, chacun suivi d'un point, puis « ip6.arpa ». Rend la fin des chiffres ; « .ip6.arpa » reste lisible.
/// L'adresse se relirait en retournant les chiffres.
fn nom_inverse_ipv6(c: &[char], i: usize) -> Option<usize> {
    if avant(c, i).is_some_and(char::is_alphanumeric) {
        return None;
    }
    let mut j = i;
    for _ in 0..NOM_INVERSE_MAX {
        if !car(c, j).is_some_and(|x| x.is_ascii_hexdigit()) || car(c, suivant(j)) != Some('.') {
            break;
        }
        j = plus(j, 2);
    }
    let apres = plus(j, "ip6.arpa".len());
    (j > i && commence_par_sans_casse(c, j, "ip6.arpa") && !car(c, apres).is_some_and(char::is_alphanumeric))
        .then(|| j.saturating_sub(1))
}

/// La longueur d'une IPv6 à tirets, zone comprise (« fe80--1ff-fe23-4567-890as3 ») : 39 caractères pour l'adresse
/// la plus longue, plus la zone.
const IPV6_A_TIRETS_MAX: usize = 64;

/// Le nom UNC de Windows qui porte une IPv6, « 2001-db8-…-7348.ipv6-literal.net » (les « : » y deviennent des
/// tirets, une IPv4 finale garde ses points : « --ffff-198.51.100.23.ipv6-literal.net ») : ce qui précède
/// « .ipv6-literal.net » est masqué, le suffixe reste. Sans ce suffixe, la forme stricte d'une IPv6 écrite avec des
/// tirets (`ipv6_a_tirets_seule`).
fn ipv6_a_tirets(c: &[char], i: usize) -> Option<usize> {
    if avant(c, i).is_some_and(|p| p.is_ascii_alphanumeric() || p == '-') {
        return None;
    }
    let mut fin = fin_tant_que(c, i, |x| x.is_ascii_alphanumeric() || x == '-');
    let adresse = morceau(c, i, fin);
    if !adresse.contains(&'-') || !adresse.iter().any(char::is_ascii_hexdigit) {
        return None;
    }
    // Les trois points d'une IPv4 finale, au plus.
    for _ in 0..4 {
        if commence_par_sans_casse(c, fin, ".ipv6-literal.net") {
            return (entre(i, fin) <= IPV6_A_TIRETS_MAX).then_some(fin);
        }
        if car(c, fin) != Some('.') || !car(c, suivant(fin)).is_some_and(|y| y.is_ascii_digit()) {
            break;
        }
        fin = fin_tant_que(c, suivant(fin), |y| y.is_ascii_digit());
    }
    ipv6_a_tirets_seule(c, i)
}

/// Une IPv6 écrite avec des tirets hors d'un nom UNC (« 2001-db8-85a3-0-0-8a2e-370-7334 », « fe80--1ff:… »
/// recopiée d'un nom d'hôte). Pour ne pas prendre une date ou un numéro de téléphone : huit groupes de 1 à 4
/// chiffres hexadécimaux dont un de 3 ou 4 et un chiffre ; ou un seul « -- » (les zéros sautés), au moins deux
/// groupes, un groupe de 4, un chiffre et une lettre hexadécimale (« 2026--11 » reste). Ni lettre, ni chiffre, ni
/// tiret collé autour ; un « .domaine » peut suivre.
fn ipv6_a_tirets_seule(c: &[char], i: usize) -> Option<usize> {
    let fin = fin_tant_que(c, i, |y| y.is_ascii_hexdigit() || y == '-');
    if entre(i, fin) > IPV6_A_TIRETS_MAX || car(c, fin).is_some_and(char::is_alphanumeric) {
        return None;
    }
    let texte = chaine(c, i, fin);
    // Des groupes de 1 à 4 chiffres hexadécimaux, séparés par un seul tiret.
    let groupes = |partie: &str| -> Option<Vec<usize>> {
        if partie.is_empty() {
            return Some(Vec::new());
        }
        let tailles: Vec<usize> = partie.split('-').map(str::len).collect();
        tailles.iter().all(|n| (1..=4).contains(n)).then_some(tailles)
    };
    let (tailles, double) = match texte.split_once("--") {
        Some((gauche, droite)) => {
            let (g, d) = (groupes(gauche)?, groupes(droite)?);
            ([g, d].concat(), true)
        }
        None => (groupes(&texte)?, false),
    };
    let chiffre = texte.chars().any(|y| y.is_ascii_digit());
    let lettre = texte.chars().any(|y| y.is_ascii_alphabetic());
    let pris = if double {
        (2..=7).contains(&tailles.len()) && tailles.contains(&4) && chiffre && lettre
    } else {
        tailles.len() == 8 && tailles.iter().any(|n| *n >= 3) && chiffre
    };
    pris.then_some(fin)
}

/// Une IPv4 écrite avec des tirets dans un nom d'hôte, la forme que les fournisseurs d'accès et les nuages donnent à
/// l'adresse publique d'un abonné : « ip-198-51-100-23 », « ec2-198-51-100-23 », « 198-51-100-23.example.net », et la
/// forme inverse « modemcable023.100-51-198 » (un point, puis deux tirets). Quatre nombres de 0 à 255.
///
/// Il faut un contexte de nom d'hôte, sinon « ports 10-20-30-40 » ou « 1.2-3-4 » seraient pris : une étiquette avec
/// une lettre juste avant (« ec2- », « dsl2- », « modemcable ») ou après (« .example.net », « -static »), au
/// plus une étiquette de chiffres seuls entre les deux (« node-7- »). Pas un chiffre collé devant, ni une étiquette
/// de quatre chiffres ou plus : une date (« 2026-11-18-… ») n'en est pas une, ni une version de noyau
/// (« 6.1.0-28-amd64 » : deux points). Limite : quatre nombres seuls, sans nom d'hôte autour, restent lisibles.
fn ipv4_a_tirets(c: &[char], i: usize) -> Option<usize> {
    if avant(c, i).is_some_and(|p| p.is_ascii_digit()) {
        return None;
    }
    let mut j = i;
    let mut separateurs = Vec::with_capacity(3);
    for rang in 0..4 {
        if rang > 0 {
            separateurs.push(car(c, j).filter(|x| *x == '-' || *x == '.')?);
            j = suivant(j);
        }
        let fin = fin_tant_que(c, j, |y| y.is_ascii_digit());
        if !(1..=3).contains(&entre(j, fin)) || chaine(c, j, fin).parse::<u16>().ok()? > 255 {
            return None;
        }
        j = fin;
    }
    if separateurs != ['-'; 3] && separateurs != ['.', '-', '-'] {
        return None;
    }
    let suite = |k: usize| car(c, k).is_some_and(|y| y.is_ascii_digit());
    let apres = car(c, j);
    if suite(j) || (matches!(apres, Some('-' | '.')) && suite(suivant(j))) {
        return None;
    }
    (etiquette_avant(c, i) || etiquette_apres(c, j)).then_some(j)
}

/// L'étiquette de nom d'hôte qui finit juste avant `i` : (début, fin), lettres et chiffres ASCII.
fn etiquette_finissant(c: &[char], i: usize) -> (usize, usize) {
    let mut k = i;
    while k > 0 && avant(c, k).is_some_and(|y| y.is_ascii_alphanumeric()) {
        k = k.saturating_sub(1);
    }
    (k, i)
}

/// Si un nom d'hôte précède l'adresse à tirets qui commence en `i` : des lettres collées (« modemcable », « ip »),
/// ou, avant un « - » ou un « . », une étiquette qui porte une lettre (« ec2- », « dsl2- »), au plus une étiquette
/// de un à trois chiffres entre les deux (« node-7- »).
fn etiquette_avant(c: &[char], i: usize) -> bool {
    let a_lettre = |m: &[char]| m.iter().any(char::is_ascii_alphabetic);
    match avant(c, i) {
        Some(p) if p.is_ascii_alphabetic() => true,
        Some('-' | '.') => {
            let (debut, fin) = etiquette_finissant(c, i.saturating_sub(1));
            let m = morceau(c, debut, fin);
            if a_lettre(m) {
                return true;
            }
            if !(1..=3).contains(&m.len()) || !matches!(avant(c, debut), Some('-' | '.')) {
                return false;
            }
            let (d2, f2) = etiquette_finissant(c, debut.saturating_sub(1));
            a_lettre(morceau(c, d2, f2))
        }
        _ => false,
    }
}

/// Si un nom d'hôte suit l'adresse à tirets qui finit en `j` : après un « . » ou un « - », une étiquette qui
/// commence par une lettre (« .example.net », « -static »).
fn etiquette_apres(c: &[char], j: usize) -> bool {
    matches!(car(c, j), Some('-' | '.')) && car(c, suivant(j)).is_some_and(|y| y.is_ascii_alphabetic())
}

/// Les racines d'un mot qui annonce un numéro de série, sans casse ni accents : « serial », « série »,
/// « Seriennummer ». Une famille plutôt qu'une liste : chaque ronde de relecture trouvait une écriture de plus
/// (« serial-number », « serialno », « serial_short », « iSerial », « ID_SERIAL »).
const RACINES_DE_SERIE: [&str; 3] = ["serien", "serial", "serie"];
/// Ce qui peut suivre la racine dans le même mot, « _ » et « - » retirés : « serial_number », « serialno »,
/// « ID_SERIAL_SHORT », « Seriennummer ». Pas « s » : « series » (une suite, un feuilleton) n'annonce rien.
const SUFFIXES_DE_SERIE: [&str; 7] = ["", "number", "nummer", "num", "no", "nr", "short"];
/// Ce qui peut précéder la racine, collé sans « _ » ni « - » : « iSerial » (lsusb), « IDSERIAL ». Avec « _ » ou
/// « - » (« disk_serial », « ID_SERIAL »), tout préfixe est permis.
const PREFIXES_DE_SERIE: [&str; 3] = ["", "i", "id"];
/// Les annonces courtes : « SN » (anglais) et « NS » (numéro de série). Seulement suivies de « : », « = » ou « # »,
/// ou d'une valeur longue qui a la forme d'un numéro (lettres capitales et chiffres).
const SERIES_COURTES: [&str; 2] = ["sn", "ns"];
/// Les mots de liaison entre l'annonce et la valeur (« Serial number: », « numéro de série n° », « serial number is »,
/// « le numéro de série est »).
const LIAISONS_DE_SERIE: [&str; 14] = [
    "number", "nummer", "no", "nr", "n°", "nº", "num", "numéro", "numero", "de", "is", "est", "ist", "was",
];
/// Le nombre de mots qui peuvent séparer l'annonce de son « : » (« numéro de série du disque : », « Serial Number
/// (system): »).
const MOTS_AVANT_SEPARATEUR: usize = 3;
/// Le nombre de morceaux d'une valeur écrite avec des espaces (« WX 12A 34B »).
const MORCEAUX_DE_SERIE: usize = 4;
/// Une valeur plus longue que cela n'est lue que si un chiffre paraît avant : le coût d'un refus reste borné.
const SERIE_LECTURE: usize = 128;

/// Si `motif` (en minuscules) est écrit en `i`, quelle que soit la casse (« SÉRIE » compris) : sa fin.
fn mot_sans_casse(c: &[char], i: usize, motif: &str) -> Option<usize> {
    let mut j = i;
    for m in motif.chars() {
        if car(c, j).is_none_or(|x| x.to_lowercase().ne(std::iter::once(m))) {
            return None;
        }
        j = suivant(j);
    }
    Some(j)
}

/// Une lettre en minuscule et sans accent, pour reconnaître « SÉRIE » comme « serie ».
fn sans_accent(x: char) -> char {
    match x.to_lowercase().next().unwrap_or(x) {
        'é' | 'è' | 'ê' | 'ë' => 'e',
        autre => autre,
    }
}

/// La force d'une annonce de numéro de série.
#[derive(Clone, Copy, PartialEq)]
enum Annonce {
    /// « serial », « série », « S/N » et leur famille.
    Forte,
    /// « SN », « NS » : trop courts pour annoncer seuls.
    Courte,
}

/// Si le mot `mot` (en minuscules, sans accents, « _ » et « - » gardés) annonce un numéro de série.
fn mot_de_serie(mot: &[char]) -> Option<Annonce> {
    let compact: String = mot.iter().filter(|y| **y != '_' && **y != '-').collect();
    if SERIES_COURTES.contains(&compact.as_str()) && !mot.contains(&'_') {
        return Some(Annonce::Courte);
    }
    for racine in RACINES_DE_SERIE {
        let r: Vec<char> = racine.chars().collect();
        for k in 0..=mot.len().saturating_sub(r.len()) {
            if mot.get(k..plus(k, r.len())) != Some(r.as_slice()) {
                continue;
            }
            let tete: String = mot.get(..k).unwrap_or(&[]).iter().collect();
            let queue: String = mot
                .get(plus(k, r.len())..)
                .unwrap_or(&[])
                .iter()
                .filter(|y| **y != '_' && **y != '-')
                .collect();
            // Devant « number » ou « nummer », le mot composé est sans ambiguïté : toute tête de lettres est permise
            // (« DiskSerialNumber », « SystemSerialNumber », « Volumeseriennummer »).
            let compose = matches!(queue.as_str(), "number" | "nummer") && tete.chars().all(char::is_alphabetic);
            let tete_permise = compose || PREFIXES_DE_SERIE.contains(&tete.as_str()) || tete.ends_with(['_', '-']);
            if tete_permise && SUFFIXES_DE_SERIE.contains(&queue.as_str()) {
                return Some(Annonce::Forte);
            }
        }
    }
    None
}

/// Un séparateur explicite entre l'annonce et la valeur, qui commence en `j` : « : », « = », « # », « -> », un
/// tiret seul, des points de conduite (« Serial Number.......: »). Rend sa fin.
fn separateur_de_serie(c: &[char], j: usize) -> Option<usize> {
    let x = car(c, j)?;
    if matches!(x, ':' | '=' | '#') {
        return Some(suivant(j));
    }
    if commence_par(c, j, "->") {
        return Some(plus(j, 2));
    }
    if x == '-' && car(c, suivant(j)).is_none_or(char::is_whitespace) {
        return Some(suivant(j));
    }
    let points = fin_tant_que(c, j, |y| y == '.' || y == '…');
    (entre(j, points) >= 2 || x == '…').then_some(points)
}

/// Un morceau de valeur qui suit un premier morceau après une espace (« WX 12A 34B ») : lettres capitales, chiffres
/// et tirets seulement, de 2 à 16 caractères ; un mot en minuscules (« fin ») arrête la valeur.
fn morceau_de_serie(m: &[char]) -> bool {
    (2..=16).contains(&m.len())
        && m.iter()
            .all(|y| y.is_ascii_uppercase() || y.is_ascii_digit() || *y == '-')
}

/// Un numéro de série annoncé : « sn=PF2ABCDE9 », « S/N:WD1234XYZ », « Serial number: ABC123 », « numéro de série
/// du disque : WX 12A 34B », « iSerial 3 PF2ABCDE9 » (lsusb). Rend le début et la fin de la valeur ; l'annonce reste
/// lisible. La valeur porte un chiffre. Sans séparateur (« : », « = », « # », « n° »…), elle porte aussi une lettre
/// et a au moins 6 caractères : « une série de 123456 essais » reste. Faite de chiffres seuls, elle n'est prise
/// qu'après un séparateur et à partir de 6 chiffres : « sn: 4 segments », « série n° 2 » restent.
fn serie(c: &[char], i: usize) -> Option<(usize, usize)> {
    if avant(c, i).is_some_and(|p| p.is_alphanumeric() || p == '_' || p == '-' || p == '/') {
        return None;
    }
    // Le mot de l'annonce : lettres, chiffres, « _ », « - » ; ou « S/N ».
    let (annonce, mut pos, point) = if let Some(fin) = mot_sans_casse(c, i, "s/n") {
        (Annonce::Forte, fin, false)
    } else {
        let fin = fin_tant_que(c, i, |y| y.is_alphanumeric() || y == '_' || y == '-');
        if entre(i, fin) > 32 {
            return None;
        }
        let mot: Vec<char> = morceau(c, i, fin).iter().map(|y| sans_accent(*y)).collect();
        let annonce = mot_de_serie(&mot)?;
        // Une abréviation finie par un point (« Serien-Nr.: », « Seriennr. ») : le point fait partie de l'annonce.
        let abrege = ["nr", "no", "num"]
            .iter()
            .any(|a| mot.ends_with(&a.chars().collect::<Vec<_>>()));
        let point = abrege && car(c, fin) == Some('.');
        (annonce, if point { suivant(fin) } else { fin }, point)
    };
    // Après le point d'une abréviation, la valeur peut être collée (« Serien-Nr.PF2QZ8X71K ») : le point sépare.
    if !point && car(c, pos).is_some_and(char::is_alphanumeric) {
        return None;
    }
    let mut explicite = false;
    let mut liaisons = 0;
    loop {
        let mot = fin_tant_que(c, pos, |y| y == ' ' || y == '\t');
        if let Some(fin) = separateur_de_serie(c, mot) {
            explicite = true;
            pos = fin;
            continue;
        }
        let liaison = LIAISONS_DE_SERIE
            .iter()
            .filter(|_| liaisons < 3)
            // Le filtre est dans la recherche : « is » ne doit pas cacher « ist », ni « num » cacher « numéro ».
            .find_map(|l| {
                mot_sans_casse(c, mot, l)
                    .filter(|fin| l.ends_with(['°', 'º']) || !car(c, *fin).is_some_and(char::is_alphanumeric))
                    .map(|fin| (*l, fin))
            });
        if let Some((lien, fin)) = liaison {
            explicite |= lien.ends_with(['°', 'º']);
            liaisons = suivant(liaisons);
            pos = if car(c, fin) == Some('.') { suivant(fin) } else { fin };
            continue;
        }
        // Quelques mots puis un séparateur : « numéro de série du disque : », « Serial Number (system): ».
        if !explicite && let Some(fin) = mots_puis_separateur(c, mot) {
            explicite = true;
            pos = fin;
            continue;
        }
        pos = mot;
        break;
    }
    // Le numéro d'ordre de lsusb (« iSerial 3 PF2ABCDE9 ») : un petit nombre suivi d'une valeur à lettres et chiffres.
    let index = fin_tant_que(c, pos, |y| y.is_ascii_digit());
    if (1..=3).contains(&entre(pos, index)) && car(c, index).is_some_and(|y| y == ' ' || y == '\t') {
        let suite = fin_tant_que(c, index, |y| y == ' ' || y == '\t');
        let bout = fin_tant_que(c, suite, |y| !y.is_whitespace());
        let valeur = morceau(c, suite, bout);
        if valeur.iter().any(char::is_ascii_digit) && valeur.iter().any(char::is_ascii_alphabetic) {
            pos = suite;
        }
    }
    if car(c, pos).is_none_or(char::is_whitespace) {
        return None;
    }
    // Le premier morceau, puis, après un séparateur, les morceaux qui ont la forme d'un numéro (« WX 12A 34B »). Un
    // marqueur déjà posé (« <numéro> ») en fait partie.
    let (mut fin, mut morceaux, mut debut) = (pos, 0usize, pos);
    let (mut chiffre, mut lettre, mut longueur) = (false, false, 0usize);
    loop {
        let (net, bout) = if let Some(f) = marqueur(c, debut) {
            (f, f)
        } else {
            let mut bout_lu = debut;
            let mut vu = chiffre;
            while let Some(y) = car(c, bout_lu).filter(|y| !y.is_whitespace()) {
                if !vu && entre(pos, bout_lu) >= SERIE_LECTURE {
                    return None;
                }
                vu |= y.is_ascii_digit();
                bout_lu = suivant(bout_lu);
            }
            // La ponctuation qui suit la valeur (« ABC123, » « (WX12) ») n'en fait pas partie.
            let mut net = bout_lu;
            while net > debut && avant(c, net).is_some_and(|y| ",;.)".contains(y)) {
                net = net.saturating_sub(1);
            }
            let m = morceau(c, debut, net);
            if morceaux > 0 && !morceau_de_serie(m) {
                break;
            }
            chiffre |= m.iter().any(char::is_ascii_digit);
            lettre |= m.iter().any(|y| y.is_alphabetic());
            longueur = longueur.saturating_add(m.iter().filter(|y| y.is_alphanumeric()).count());
            (net, bout_lu)
        };
        fin = net;
        morceaux = suivant(morceaux);
        let suite = fin_tant_que(c, bout, |y| y == ' ' || y == '\t');
        if net < bout || !explicite || morceaux >= MORCEAUX_DE_SERIE || suite == bout || car(c, suite).is_none() {
            break;
        }
        debut = suite;
    }
    if !chiffre {
        return None;
    }
    let pris = match (explicite, lettre) {
        (true, true) => true,
        (true, false) => longueur >= 6,
        (false, _) => lettre && longueur >= if annonce == Annonce::Courte { 8 } else { 6 },
    };
    let courte_permise = annonce == Annonce::Forte
        || explicite
        || morceau(c, pos, fin)
            .iter()
            .all(|y| y.is_ascii_uppercase() || y.is_ascii_digit());
    (pris && courte_permise && fin > pos).then_some((pos, fin))
}

/// Jusqu'à `MOTS_AVANT_SEPARATEUR` mots sans chiffre (« du disque », « (system) ») puis un séparateur explicite :
/// sa fin.
fn mots_puis_separateur(c: &[char], j: usize) -> Option<usize> {
    let mut k = j;
    for _ in 0..MOTS_AVANT_SEPARATEUR {
        let bout = fin_tant_que(c, k, |y| y.is_alphabetic() || "()[]'".contains(y));
        if bout == k || entre(k, bout) > 24 {
            return None;
        }
        let blanc = fin_tant_que(c, bout, |y| y == ' ' || y == '\t');
        if let Some(fin) = separateur_de_serie(c, blanc).filter(|_| car(c, blanc) != Some('-')) {
            return Some(fin);
        }
        if blanc == bout {
            return None;
        }
        k = blanc;
    }
    None
}

fn ipv4(c: &[char], i: usize) -> Option<usize> {
    // Une lettre collée devant n'empêche rien (« host198.51.100.23 », « v1.198.51.100.23 ») : seul un chiffre ou un
    // point d'un nombre plus long le fait. Le prix : « python3.11.2.1 » devient « python<ip> ».
    if avant(c, i).is_some_and(|p| p.is_ascii_digit() || (p == '.' && !point_de_phrase(c, i))) {
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
    // Un port écrit après un point (« 198.51.100.23.443 », la forme de tcpdump et de netstat sous BSD) est pris avec
    // l'adresse, quelle que soit sa longueur et avec les lettres qui y sont collées ; de même des lettres collées
    // (« 198.51.100.23x ») : sinon l'adresse entière sortirait. Dans le doute, masquer : le mot d'avant ne décide pas
    // seul (« paquet », « règle » précèdent aussi des adresses). Ne restent lisibles que des formes qui ne peuvent pas
    // être une adresse avec son port : un cinquième nombre suivi d'un autre (« 1.2.3.4.5.6 ») ; un suffixe de version
    // connu (« 1.2.3.4rc1 », « 4.19.0.0beta ») ; après un mot de numéro, un cinquième nombre de deux chiffres au plus
    // derrière un premier nombre sous 100 (« version 1.2.3.4.5 », « section 5.2.3.4.1 »). Limite dite au CHANGELOG :
    // « version 10.0.0.5.22 » reste aussi lisible.
    if car(c, j) == Some('.') && car(c, suivant(j)).is_some_and(|y| y.is_ascii_digit()) {
        let fin = fin_tant_que(c, suivant(j), |y| y.is_ascii_digit());
        let encore = car(c, fin) == Some('.') && car(c, suivant(fin)).is_some_and(|y| y.is_ascii_digit());
        if encore {
            return None;
        }
        let premier = chaine(c, i, fin_tant_que(c, i, |y| y.is_ascii_digit()))
            .parse::<u16>()
            .unwrap_or(u16::MAX);
        let court = entre(suivant(j), fin) <= 2 && !car(c, fin).is_some_and(|y| y.is_ascii_alphanumeric());
        if court && premier < 100 && mot_de_numero_avant(c, i) {
            return None;
        }
        return Some(fin_tant_que(c, fin, |y| y.is_ascii_alphanumeric()));
    }
    if car(c, j).is_some_and(|y| y.is_ascii_alphabetic()) {
        let fin = fin_tant_que(c, j, |y| y.is_ascii_alphanumeric());
        return (!suffixe_de_version(&chaine(c, j, fin))).then_some(fin);
    }
    // Port et préfixe : « 10.0.0.1:8080 », « 10.0.0.0/8 ».
    // Pas si un point suit le nombre : c'est une seconde adresse (« 198.51.100.23/198.51.100.24 »), lue à son tour.
    for marque in [':', '/'] {
        if car(c, j) == Some(marque) {
            let fin = fin_tant_que(c, suivant(j), |y| y.is_ascii_digit());
            if (1..=5).contains(&entre(suivant(j), fin)) && car(c, fin) != Some('.') {
                j = fin;
            }
        }
    }
    Some(j)
}

/// Les mots qui précèdent un numéro (de version, de section d'un guide, d'un pilote) plutôt qu'une adresse. Ni
/// « paquet », « package », « règle », « rule » ni « v » (« nc -v ») : ils précèdent aussi des adresses dans les
/// journaux réseau.
const MOTS_DE_NUMERO: [&str; 9] = [
    "version",
    "versions",
    "build",
    "section",
    "contrôle",
    "control",
    "pilote",
    "driver",
    "release",
];

/// Si le mot juste avant `i` (une seule espace entre eux) est un mot de numéro (`MOTS_DE_NUMERO`), écrit seul : pas
/// collé à un tiret, un trait bas ou un chiffre (« --version »).
fn mot_de_numero_avant(c: &[char], i: usize) -> bool {
    if avant(c, i) != Some(' ') {
        return false;
    }
    let fin = i.saturating_sub(1);
    let mut debut = fin;
    while avant(c, debut).is_some_and(char::is_alphabetic) {
        debut = debut.saturating_sub(1);
    }
    if avant(c, debut).is_some_and(|p| p == '-' || p == '_' || p.is_ascii_digit()) {
        return false;
    }
    let mot = chaine(c, debut, fin).to_lowercase();
    MOTS_DE_NUMERO.contains(&mot.as_str())
}

/// Un suffixe de version connu, collé à quatre nombres (« rc1 », « beta », « alpha2 », « esr ») : pas un port.
fn suffixe_de_version(lettres: &str) -> bool {
    let bas = lettres.to_ascii_lowercase();
    ["alpha", "beta", "rc", "esr"]
        .iter()
        .filter_map(|s| bas.strip_prefix(s))
        .any(|reste| reste.chars().all(|y| y.is_ascii_digit()))
}

/// Le point juste avant `i` finit-il une phrase ou des points de suspension (« …fin.198.51.100.23 », « ...10.0.0.5 »)
/// plutôt qu'un nombre (« 1.2.3.4.5 ») ? Alors une adresse peut commencer en `i`.
fn point_de_phrase(c: &[char], i: usize) -> bool {
    avant(c, i) == Some('.') && !avant(c, i.saturating_sub(1)).is_some_and(|p| p.is_ascii_digit())
}

/// Ce que la lecture d'une IPv6 rend en `i`.
enum Ip6 {
    /// Une adresse, qui finit là.
    Adresse(usize),
    /// Pas d'adresse qui commence en `i`.
    Rien,
    /// Pas d'adresse qui commence entre `i` et cette fin : la suite de `i` n'a pas deux « : » et un chiffre, et les
    /// suites qui partent plus loin en sont des morceaux. Sauter ces positions garde la lecture linéaire.
    RienJusqua(usize),
    /// Une heure de forme exacte (`heure`), gardée telle quelle jusqu'à cette fin : aucune autre forme n'y est
    /// cherchée (sa fraction de 8 ou 9 chiffres n'est pas une longue suite hexadécimale).
    Heure(usize),
}

/// Un caractère du cœur d'une IPv6 : chiffre hexadécimal, « : », ou « . » (IPv4 portée, port écrit après un point).
fn de_l_ipv6(x: char) -> bool {
    x.is_ascii_hexdigit() || x == ':' || x == '.'
}

/// Deux « : » ou plus et un chiffre décimal : la forme qui suffit pour masquer.
fn assez_pour_une_ipv6(suite: &[char]) -> bool {
    suite.iter().filter(|y| **y == ':').count() >= 2 && suite.iter().any(char::is_ascii_digit)
}

/// Une heure de forme exacte, de `debut` à `fin`, par une grammaire stricte et sans contexte : HH:MM ou HH:MM:SS,
/// deux chiffres décimaux par groupe (heures 00 à 23, minutes 00 à 59, secondes 00 à 60), puis peut-être « . » et 1
/// à 9 chiffres décimaux ; bornée des deux côtés par un caractère qui n'est ni hexadécimal, ni « : », ni « . ». Jamais
/// « :: » (un groupe vide n'a pas deux chiffres), jamais de lettre a-f, jamais plus de trois groupes : tout le reste
/// garde la forme d'une adresse et reste masqué.
fn heure(c: &[char], debut: usize, fin: usize) -> bool {
    if avant(c, debut).is_some_and(de_l_ipv6) || car(c, fin).is_some_and(de_l_ipv6) {
        return false;
    }
    let suite = morceau(c, debut, fin);
    let (groupes, fraction) = match suite.iter().position(|y| *y == '.') {
        Some(p) => (
            suite.get(..p).unwrap_or(&[]),
            Some(suite.get(suivant(p)..).unwrap_or(&[])),
        ),
        None => (suite, None),
    };
    if fraction.is_some_and(|f| f.is_empty() || f.len() > 9 || !f.iter().all(char::is_ascii_digit)) {
        return false;
    }
    let groupes: Vec<&[char]> = groupes.split(|y| *y == ':').collect();
    if !(2..=3).contains(&groupes.len()) {
        return false;
    }
    let maximums = [['2', '3'], ['5', '9'], ['6', '0']];
    groupes.iter().zip(maximums).all(|(groupe, max)| match groupe {
        [a, b] if a.is_ascii_digit() && b.is_ascii_digit() => [*a, *b] <= max,
        _ => false,
    })
}

/// La fin d'une suite sans les points et le deux-points seul qui finissent la phrase (« …::7. », « …::7: erreur ») ;
/// un « :: » final reste à l'adresse (« fd12:: »).
fn sans_ponctuation_finale(c: &[char], debut: usize, mut fin: usize) -> usize {
    while fin > debut {
        match avant(c, fin) {
            Some('.') => fin = fin.saturating_sub(1),
            Some(':') if avant(c, fin.saturating_sub(1)) != Some(':') => fin = fin.saturating_sub(1),
            _ => break,
        }
    }
    fin
}

/// La fin du mot qui commence avant `j` (jusqu'à l'espace), sans la ponctuation qui finit la phrase.
fn fin_du_mot(c: &[char], debut: usize, j: usize) -> usize {
    let mut fin = fin_tant_que(c, j, |y| !y.is_whitespace());
    while fin > debut
        && avant(c, fin).is_some_and(|p| matches!(p, '.' | ',' | ';' | ':' | '!' | '?' | ')' | ']' | '»' | '"' | '\''))
    {
        fin = fin.saturating_sub(1);
    }
    fin
}

/// IPv6, par une grammaire stricte et sans regarder le contexte (3e re-contrôle : chaque ronde trouvait une
/// étiquette ou un mot collé de plus que la lecture par le contexte laissait sortir). Dans le doute, masquer : toute
/// suite de chiffres hexadécimaux, de « : » et de « . » qui compte au moins deux « : » et un chiffre est une adresse,
/// quoi qu'il y ait autour ; un crochet ouvrant devant, une zone (« %eth0 », « %br-lan », « %eth0.100 »), un préfixe
/// (« /64 ») et un port (« ]:443 », « %eth0:546 ») sont pris avec elle. Elle ne commence ni par un point ni par un
/// deux-points seul (celui d'une étiquette, « addr:fd12::7 », qui garde son nom) ; elle commence au milieu d'un mot
/// (« hôte:fd12:… » donne « `hôt<ip>` » : le « e » est hexadécimal). Les points et le deux-points seul qui la finissent
/// sont de la phrase. Un mot collé après (« …::7:Connection refused », « …:eth0 ») est masqué avec elle, jusqu'à
/// l'espace (4e re-contrôle) : un dernier groupe fait de lettres a-f (« …::beefx ») ne se distingue pas du début d'un
/// mot, et le rendre ferait sortir 16 bits de l'adresse. Seule exception : une heure de forme exacte (`heure`), sans quoi le journal servi perd sa chronologie.
/// Prix accepté : une heure mal bornée (« 12:30:45. », « hôte12:30:45 ») ou un rapport (« 1:2:3 ») sont masqués.
fn ipv6(c: &[char], i: usize) -> Ip6 {
    let crochet = car(c, i) == Some('[');
    let debut = if crochet { suivant(i) } else { i };
    match car(c, debut) {
        Some(x) if x.is_ascii_hexdigit() => {}
        Some(':') if car(c, suivant(debut)) == Some(':') => {}
        _ => return Ip6::Rien,
    }
    let coeur = fin_tant_que(c, debut, de_l_ipv6);
    if heure(c, debut, coeur) {
        return Ip6::Heure(coeur);
    }
    if !assez_pour_une_ipv6(morceau(c, debut, coeur)) {
        return Ip6::RienJusqua(coeur);
    }
    let mut fin = sans_ponctuation_finale(c, debut, coeur);
    if !assez_pour_une_ipv6(morceau(c, debut, fin)) {
        return Ip6::RienJusqua(coeur);
    }
    // Un mot collé après : le cœur s'arrête au milieu d'un mot, masqué en entier sans reculer (MASQUEUR-4).
    if fin == coeur && car(c, coeur).is_some_and(|y| y.is_alphanumeric() || y == '_') {
        return Ip6::Adresse(fin_du_mot(c, debut, coeur));
    }
    let mut j = fin;
    if car(c, j) == Some('%') && car(c, suivant(j)).is_some_and(|y| y.is_ascii_alphanumeric()) {
        // La zone : un nom d'interface ; un point n'y entre que suivi d'un chiffre (« %eth0.Le texte » garde son mot).
        j = suivant(j);
        loop {
            j = fin_tant_que(c, j, |y| y.is_ascii_alphanumeric() || matches!(y, '-' | '_'));
            if car(c, j) == Some('.') && car(c, suivant(j)).is_some_and(|y| y.is_ascii_digit()) {
                j = suivant(j);
            } else {
                break;
            }
        }
    }
    if car(c, j) == Some('/') && car(c, suivant(j)).is_some_and(|y| y.is_ascii_digit()) {
        j = fin_tant_que(c, suivant(j), |y| y.is_ascii_digit());
    }
    if crochet && car(c, j) == Some(']') {
        j = suivant(j);
    }
    // Un port après la zone ou le crochet ; sinon le deux-points est de la phrase (« fe80::1%eth0: Name … »).
    if car(c, j) == Some(':') && car(c, suivant(j)).is_some_and(|y| y.is_ascii_digit()) {
        j = fin_tant_que(c, suivant(j), |y| y.is_ascii_digit());
    }
    if j > fin && car(c, j).is_some_and(|y| y.is_alphanumeric() || y == '_') {
        j = fin_du_mot(c, debut, j);
    }
    fin = j;
    Ip6::Adresse(fin)
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
/// Un accent du bloc U+0300 à U+036F n'en est jamais un, même compté comme lettre par Unicode (U+0345, iota
/// souscrit ; U+0363 à U+036F, petites lettres latines suscrites comme U+0364) : il suit la règle des accents
/// (`trier`), jamais gardé seul ni en tête.
pub(crate) fn permis(x: char) -> bool {
    (x.is_alphabetic() && !invisible(x) && !accent_combinant(x))
        || x.is_ascii_digit()
        || " .,:;'()[]#%/_-+=".contains(x)
}

/// Accents écrits à part (« e » puis U+0301, comme les noms de fichier de macOS) : gardés après une lettre, deux au
/// plus, pour qu'un mot accentué ne soit pas coupé en deux, sans laisser empiler des signes sur une lettre.
fn accent_combinant(x: char) -> bool {
    ('\u{0300}'..='\u{036F}').contains(&x)
}

/// Le nombre d'accents écrits à part gardés de suite sur une lettre.
const ACCENTS_MAX: u8 = 2;

/// Ce que l'étape 5 fait d'un caractère hors marqueur.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tri {
    /// Un caractère permis : la suite d'accents repart de zéro.
    Garde,
    /// Un accent gardé : il suit une lettre ou un accent gardé, et la suite reste sous `ACCENTS_MAX`.
    Accent,
    /// Tout le reste : remplacé par une espace au nettoyage, refusé à la relecture.
    Retire,
}

/// La règle de l'étape 5, la seule : `filtrer` la suit pour écrire et `sortie_permise` pour relire, avec le même
/// caractère d'avant (le dernier écrit) et la même suite d'accents. Deux règles écrites à part avaient divergé : le
/// filtre gardait comme une lettre un accent qu'Unicode compte parmi les lettres (U+0345, U+0364), seul ou en tête,
/// que la relecture refusait comme accent. U+034F (liant de graphèmes), dans le bloc mais invisible, n'est jamais
/// gardé : `normaliser` le retire déjà, la relecture le refuse aussi. Recopiée dans le relais (relais/worker.js,
/// `trier`) : `corpus_du_relais_identique` et les essais du relais exigent les mêmes réponses sur les textes du
/// corpus commun (relais/essais/corpus-detecteur.json), pas sur toute entrée. Ce corpus porte un cas par branche
/// (lettre-accent en tête, après un chiffre, une ponctuation ou un marqueur, trois accents, U+034F) : un écart de
/// la copie sur l'une d'elles y est vu.
fn trier(x: char, precedent: Option<char>, accents: u8) -> Tri {
    if accent_combinant(x) {
        if !invisible(x) && accents < ACCENTS_MAX && precedent.is_some_and(|p| p.is_alphabetic() || accent_combinant(p))
        {
            Tri::Accent
        } else {
            Tri::Retire
        }
    } else if permis(x) {
        Tri::Garde
    } else {
        Tri::Retire
    }
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
        let tri = if renvoi(c, i, &sortie) {
            Tri::Retire
        } else {
            trier(x, sortie.last().copied(), accents)
        };
        let y = match tri {
            Tri::Garde => {
                accents = 0;
                x
            }
            Tri::Accent => {
                accents = accents.saturating_add(1);
                x
            }
            Tri::Retire => {
                accents = 0;
                ' '
            }
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

/// Vrai si `s` n'a que ce que l'étape 5 laisse : caractères permis, accents selon `trier` (la règle même du filtre),
/// et chevrons dans les marqueurs connus seulement. `passer` n'accepte aucune sortie qu'elle refuse.
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
        match trier(x, avant(&c, i), accents) {
            Tri::Garde => accents = 0,
            Tri::Accent => accents = accents.saturating_add(1),
            Tri::Retire => return false,
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

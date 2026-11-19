//! Le garde-fou de confidentialité du brouillon, en trois couches. 1. Ne pas prendre ce qui n'est pas utile à un
//! éditeur : `reduire_chemin` (un nom de fichier personnel comme « CV-Prénom-Nom.pdf » porte un nom complet que
//! `anonymiser` ne connaît pas) et `compte` (le compte d'un proche sur le même ordinateur passait en clair).
//! 2. Masquer chaque valeur avec `journal::anonymiser`, puis avec le masquage commun de ce qui sort
//! (`amelioration::texte::masquer` : séries, secrets, jetons, MAC, IP, chemins), avant et après `anonymiser` ; les
//! adresses web entières sont retirées avant tout (`texte::sans_urls` : leur requête porte souvent un jeton de
//! session). 3. Contrôle final : chercher
//! dans le texte entier chaque nom connu ; s'il en reste un, rien n'est écrit.
//!
//! Le contrôle final n'est pas une couche indépendante : il relit la même liste que celle qui a servi au masquage. Il
//! attrape un défaut du code, pas un nom que Vanguard ignore (nom complet, nom d'un proche, ville) : la vraie dernière
//! couche est la relecture par la personne, et les textes ne promettent pas plus.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::collections::BTreeMap;

/// Ce qui a été masqué, par sorte : montré à la personne avant d'écrire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Sorte {
    Dossier,
    Personne,
    Machine,
    Reseau,
    Appareil,
    Compte,
    Courriel,
    Sid,
    Numero,
    Wifi,
    Ip,
    Mac,
    Site,
    Fichier,
    Secret,
    Chemin,
    Identifiant,
}

impl Sorte {
    /// Le libellé, au pluriel quand il y en a plusieurs.
    fn libelle(self, n: u32, anglais: bool) -> String {
        let (fr, en) = match self {
            Sorte::Dossier => ("chemin(s) du dossier personnel", "home folder path(s)"),
            Sorte::Personne => ("nom(s) de compte", "account name(s)"),
            Sorte::Machine => ("nom(s) d'ordinateur", "computer name(s)"),
            Sorte::Reseau => ("nom(s) de réseau", "network name(s)"),
            Sorte::Appareil => ("nom(s) d'appareil", "device name(s)"),
            Sorte::Compte => ("autre(s) compte(s)", "other account(s)"),
            Sorte::Courriel => ("adresse(s) courriel", "email address(es)"),
            Sorte::Sid => ("identifiant(s) Windows (SID)", "Windows identifier(s) (SID)"),
            Sorte::Numero => ("numéro(s) de série", "serial number(s)"),
            Sorte::Wifi => ("nom(s) de Wi-Fi", "Wi-Fi name(s)"),
            Sorte::Ip => ("adresse(s) IP", "IP address(es)"),
            Sorte::Mac => ("adresse(s) MAC", "MAC address(es)"),
            Sorte::Site => ("site(s) web et requête(s)", "website(s) and query string(s)"),
            Sorte::Fichier => ("nom(s) de fichier personnel", "personal file name(s)"),
            Sorte::Secret => ("secret(s) ou jeton(s)", "secret(s) or token(s)"),
            Sorte::Chemin => ("chemin(s) de fichier", "file path(s)"),
            Sorte::Identifiant => (
                "identifiant(s) (GUID, hexadécimal)",
                "identifier(s) (GUID, hexadecimal)",
            ),
        };
        format!("{n} {}", if anglais { en } else { fr })
    }

    /// Le nom de la sorte seule, sans la valeur : ce que dit un refus du contrôle final.
    pub(crate) fn nom(self) -> String {
        let l = self.libelle(1, crate::langue::anglais());
        l.split_once(' ').map_or(l.clone(), |(_, s)| s.to_string())
    }
}

/// Le décompte de ce qui a été masqué.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Decompte(pub BTreeMap<Sorte, u32>);

impl Decompte {
    pub(crate) fn ajouter(&mut self, sorte: Sorte, n: u32) {
        if n > 0 {
            let fois = self.0.entry(sorte).or_default();
            *fois = fois.saturating_add(n);
        }
    }

    pub(crate) fn fusionner(&mut self, autre: &Decompte) {
        for (s, n) in &autre.0 {
            self.ajouter(*s, *n);
        }
    }

    /// « 3 chemin(s) du dossier personnel, 1 nom(s) d'ordinateur », dans la langue de l'interface.
    pub(crate) fn texte(&self) -> String {
        self.texte_dans(crate::langue::anglais())
    }

    /// Le même texte dans une langue donnée : celle du brouillon.
    pub(crate) fn texte_dans(&self, anglais: bool) -> String {
        if self.0.is_empty() {
            return if anglais { "nothing" } else { "rien" }.to_string();
        }
        self.0
            .iter()
            .map(|(s, n)| s.libelle(*n, anglais))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Les remplaçants posés par `anonymiser`, `reduire_chemin` et le masquage commun (`amelioration::texte::masquer`), et
/// la sorte qu'ils comptent. Toute adresse MAC ou IP finit en « `<mac>` » ou « `<ip>` » : comptées par leur marqueur.
const REMPLACANTS: &[(&str, Sorte)] = &[
    ("<utilisateur>", Sorte::Personne),
    ("<machine>", Sorte::Machine),
    ("<réseau>", Sorte::Reseau),
    ("<appareil>", Sorte::Appareil),
    ("<compte>", Sorte::Compte),
    ("<courriel>", Sorte::Courriel),
    ("S-1-5-21-0-0-0", Sorte::Sid),
    ("<numéro>", Sorte::Numero),
    ("<wifi>", Sorte::Wifi),
    ("<ip>", Sorte::Ip),
    ("<mac>", Sorte::Mac),
    ("<site>", Sorte::Site),
    ("<url>", Sorte::Site),
    ("<fichier>", Sorte::Fichier),
    ("<adresse>", Sorte::Courriel),
    ("<secret>", Sorte::Secret),
    ("<jeton>", Sorte::Secret),
    ("<clé>", Sorte::Secret),
    ("<chemin", Sorte::Chemin),
    ("<guid>", Sorte::Identifiant),
    ("<hex>", Sorte::Identifiant),
];

/// Le décompte entre un texte et son masquage : les remplaçants apparus (dont « `<mac>` » et « `<ip>` »).
fn compter(avant: &str, apres: &str, d: &mut Decompte) {
    let n = |t: &str, m: &str| u32::try_from(t.matches(m).count()).unwrap_or(u32::MAX);
    for (remplacant, sorte) in REMPLACANTS {
        d.ajouter(*sorte, n(apres, remplacant).saturating_sub(n(avant, remplacant)));
    }
    let tildes = |t: &str| {
        u32::try_from(
            t.char_indices()
                .filter(|(i, c)| *c == '~' && t[i.saturating_add(1)..].starts_with(['/', '\\']))
                .count(),
        )
        .unwrap_or(u32::MAX)
    };
    d.ajouter(Sorte::Dossier, tildes(apres).saturating_sub(tildes(avant)));
}

/// Le dossier personnel au début d'un chemin (« /home/alice/ », « C:\Users\Zoé\ », « ~/ »), et sa longueur.
fn dossier_personnel(chemin: &str, maisons: &[String]) -> Option<usize> {
    for m in maisons.iter().filter(|m| m.len() > 3) {
        if chemin.len() > m.len()
            && chemin.is_char_boundary(m.len())
            && chemin[..m.len()].eq_ignore_ascii_case(m)
            && chemin[m.len()..].starts_with(['/', '\\'])
        {
            return Some(m.len().saturating_add(1));
        }
    }
    if chemin.starts_with("~/") || chemin.starts_with("~\\") {
        return Some(2);
    }
    let bas = chemin.to_lowercase();
    for debut in ["/var/home/", "/home/", "/users/", "/run/media/", "/media/", "/root/"] {
        if let Some(reste) = bas.strip_prefix(debut) {
            // Le compte après le préfixe (« /home/alice/ »), sauf /root/, qui est déjà le dossier.
            let compte = if debut == "/root/" {
                0
            } else {
                reste.find('/')?.checked_add(1)?
            };
            return Some(debut.len().saturating_add(compte));
        }
    }
    let b = chemin.as_bytes();
    if let [lecteur, b':', b'\\' | b'/', _, ..] = *b
        && lecteur.is_ascii_alphabetic()
    {
        let reste = &bas[3..];
        if let Some(r) = reste.strip_prefix("users\\").or_else(|| reste.strip_prefix("users/")) {
            return "users\\"
                .len()
                .checked_add(3)?
                .checked_add(r.find(['\\', '/'])?)?
                .checked_add(1);
        }
    }
    None
}

/// Un chemin de fichier tel qu'il entre dans le brouillon : les dossiers du système restent (`/usr/bin/curl`,
/// `C:\Windows\System32\…`, qui aident à reproduire) ; sous un dossier personnel, ni les dossiers ni le nom ne
/// restent (« `<chemin .pdf>` »), seulement l'extension, qui dit la sorte de fichier.
pub(crate) fn reduire_chemin(chemin: &str, maisons: &[String]) -> String {
    if dossier_personnel(chemin, maisons).is_none() {
        return chemin.to_string();
    }
    marqueur_de_chemin(chemin)
}

/// Le marqueur d'un chemin entier : « `<chemin .pdf>` » si son extension est connue
/// (`amelioration::texte::extension_connue`, liste fermée), sinon « `<chemin>` ». Une extension quelconque peut être
/// un nom (« Rapport.alice », « firefox.desktop » sur l'ordinateur « desktop », « Lettre.Tremblay ») : gardée, elle
/// sortait, ou le contrôle final refusait tout le brouillon (relecture 0.97, moyen).
pub(crate) fn marqueur_de_chemin(chemin: &str) -> String {
    let nom = chemin.rsplit(['/', '\\']).next().unwrap_or_default();
    nom.rsplit_once('.')
        .filter(|(debut, e)| !debut.is_empty() && crate::amelioration::texte::extension_connue(e))
        .map_or_else(
            || "<chemin>".to_string(),
            |(_, e)| format!("<chemin .{}>", e.to_ascii_lowercase()),
        )
}

/// La ponctuation qui ferme un chemin cité (« (~/a/x.exe) », « ~/a/x.exe. »).
const FIN_DE_CHEMIN: [char; 7] = ['.', ',', ';', ')', '»', '"', '\''];

/// Les chemins sous un dossier personnel cités dans un texte (une alerte, un message d'examen), réduits comme
/// `reduire_chemin`. Un chemin s'arrête au premier espace : un nom de fichier qui en contient laisse passer sa fin, ce
/// que la relecture par la personne doit voir (c'est dit dans le brouillon). Un chemin coupé à gauche par « … »
/// (`chasse::extrait`) est réduit en entier : son début est perdu, rien ne prouve qu'il est hors d'un dossier
/// personnel.
pub(crate) fn reduire_chemins_dans(texte: &str, maisons: &[String]) -> String {
    reduire_lignes(texte, maisons, true)
}

/// Seulement les chemins coupés à gauche par « … », avant le masquage commun : lui prend un chemin absolu entier,
/// espaces comprises (« /home/alice/Documents/CV de Zoé Martin.pdf »), alors que la réduction s'arrête à la première
/// espace et lui laissait la fin du nom (relecture 0.97, régression de la ronde 2) ; un chemin coupé à gauche, lui,
/// n'est plus reconnu par le masquage et doit passer avant.
fn reduire_coupes_dans(texte: &str, maisons: &[String]) -> String {
    reduire_lignes(texte, maisons, false)
}

fn reduire_lignes(texte: &str, maisons: &[String], tout: bool) -> String {
    texte
        .split('\n')
        .map(|ligne| reduire_ligne(ligne, maisons, tout))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Un chemin coupé à gauche en cours de lecture, sur plusieurs morceaux quand le compte a une espace
/// (« (…oé Martin\Downloads\x.exe) ») : ce qui précède le « … », le chemin lu jusqu'ici, et le texte d'origine, rendu
/// tel quel s'il ne s'avère pas être un chemin (« …et 3 autres »).
struct Coupe {
    prefixe: String,
    chemin: String,
    origine: String,
}

impl Coupe {
    /// Un morceau qui commence un chemin coupé : un « … » avant sa première barre, suivi d'au moins un caractère.
    fn lire(morceau: &str) -> Option<Coupe> {
        let barre = morceau.find(['/', '\\']).unwrap_or(morceau.len());
        let k = morceau[..barre].rfind('…')?;
        let corps = morceau.trim_end_matches(FIN_DE_CHEMIN);
        let apres = corps
            .get(k.saturating_add('…'.len_utf8())..)
            .filter(|a| !a.is_empty())?;
        Some(Coupe {
            prefixe: morceau[..k].to_string(),
            chemin: apres.to_string(),
            origine: morceau.to_string(),
        })
    }

    fn a_une_barre(&self) -> bool {
        self.chemin.contains(['/', '\\'])
    }

    /// Réduit en entier s'il porte une barre ; sinon le texte d'origine, qui n'était pas un chemin.
    fn rendre(self, suite: &str, maisons: &[String]) -> String {
        if self.a_une_barre() {
            format!(
                "{}{}{suite}",
                self.prefixe,
                reduire_chemin(&format!("~/{}", self.chemin), maisons)
            )
        } else {
            self.origine
        }
    }
}

/// La fin d'un nom de fichier à espaces après un chemin coupé : jusqu'à `MOTS_APRES_COUPE` mots sans barre, dont le
/// dernier finit par une extension (« …\\Downloads\\Facture Bob Exemple.exe ») ; l'indice de ce dernier mot.
fn fin_du_nom(morceaux: &[&str], j: usize) -> Option<usize> {
    const MOTS_APRES_COUPE: usize = 4;
    (j..morceaux.len().min(j.saturating_add(MOTS_APRES_COUPE)))
        .take_while(|&k| morceaux.get(k).is_some_and(|m| !m.contains(['/', '\\'])))
        .find(|&k| {
            let corps = morceaux.get(k).map_or("", |m| m.trim_end_matches(FIN_DE_CHEMIN));
            corps.rsplit_once('.').is_some_and(|(nom, e)| {
                !nom.is_empty()
                    && (1..=crate::amelioration::texte::EXTENSION_MAX).contains(&e.len())
                    && e.chars().all(|c| c.is_ascii_alphanumeric())
                    && e.chars().any(|c| c.is_ascii_alphabetic())
            })
        })
}

fn reduire_ligne(ligne: &str, maisons: &[String], tout: bool) -> String {
    let morceaux: Vec<&str> = ligne.split(' ').collect();
    let mut l = String::with_capacity(ligne.len());
    let mut coupe: Option<Coupe> = None;
    let mut j = 0;
    while let Some(&morceau) = morceaux.get(j) {
        let corps = morceau.trim_end_matches(FIN_DE_CHEMIN);
        let suite = &morceau[corps.len()..];
        if let Some(mut c) = coupe.take() {
            if c.a_une_barre() && !morceau.contains(['/', '\\']) {
                // Le chemin est fini, sauf si un nom à espaces le termine : ses mots en font partie.
                if let Some(k) = fin_du_nom(&morceaux, j) {
                    let mut suite_finale = "";
                    for m in morceaux.get(j..=k).unwrap_or_default() {
                        let corps = m.trim_end_matches(FIN_DE_CHEMIN);
                        c.chemin.push(' ');
                        c.chemin.push_str(corps);
                        suite_finale = &m[corps.len()..];
                    }
                    l.push_str(&c.rendre(suite_finale, maisons));
                    j = k.saturating_add(1);
                    continue;
                }
                l.push_str(&c.rendre("", maisons));
            } else {
                // Encore le chemin (le reste d'un compte avec une espace, ou un dossier).
                c.origine.push(' ');
                c.origine.push_str(morceau);
                c.chemin.push(' ');
                c.chemin.push_str(corps);
                if suite.is_empty() {
                    coupe = Some(c);
                } else {
                    l.push_str(&c.rendre(suite, maisons));
                }
                j = j.saturating_add(1);
                continue;
            }
        }
        if j > 0 {
            l.push(' ');
        }
        j = j.saturating_add(1);
        if let Some(c) = Coupe::lire(morceau) {
            if suite.is_empty() {
                coupe = Some(c);
            } else {
                l.push_str(&c.rendre(suite, maisons));
            }
            continue;
        }
        if tout {
            l.push_str(&reduire_morceau(morceau, maisons));
        } else {
            l.push_str(morceau);
        }
    }
    if let Some(c) = coupe {
        l.push_str(&c.rendre("", maisons));
    }
    l
}

/// Un morceau sans espace : le chemin sous un dossier personnel qu'il contient, réduit.
fn reduire_morceau(morceau: &str, maisons: &[String]) -> String {
    let debut = morceau.find(['/', '\\', '~']).unwrap_or(morceau.len());
    // « C:\Users\… » : la lettre du lecteur fait partie du chemin. Une seule lettre, pas la fin d'un mot
    // (« fichier:~/… », « file:///… ») : sinon le chemin lu commence à « r:~/ » et n'est plus reconnu.
    let lecteur = debut >= 2
        && morceau[..debut].ends_with(':')
        && morceau[..debut.saturating_sub(1)].ends_with(|c: char| c.is_ascii_alphabetic())
        && !morceau[..debut.saturating_sub(2)].ends_with(|c: char| c.is_alphanumeric());
    // « file:///home/… » : les barres en trop du schéma ne font pas partie du chemin.
    let debut = if lecteur {
        debut.saturating_sub(2)
    } else if morceau[..debut].ends_with(':') && morceau[debut..].starts_with("///") {
        debut.saturating_add(2)
    } else {
        debut
    };
    let (avant, reste) = morceau.split_at(debut);
    let chemin_seul = reste.trim_end_matches(FIN_DE_CHEMIN);
    let suite = &reste[chemin_seul.len()..];
    if chemin_seul.len() > 2 && dossier_personnel(chemin_seul, maisons).is_some() {
        format!("{avant}{}{suite}", reduire_chemin(chemin_seul, maisons))
    } else {
        morceau.to_string()
    }
}

/// Les comptes du système, qui ne nomment personne : gardés tels quels dans la preuve. Tout autre compte devient
/// « `<compte>` » : `anonymiser` ne masque que celui de la personne, et le compte d'un proche sur le même ordinateur
/// (« bob ») passait en clair.
pub(crate) fn compte(nom: &str) -> String {
    const SYSTEME: &[&str] = &[
        "root",
        "system",
        "local service",
        "network service",
        "nt authority\\system",
        "nt authority\\local service",
        "nt authority\\network service",
        "localsystem",
        "daemon",
        "nobody",
        "bin",
        "sys",
        "_www",
        "www-data",
        "messagebus",
        "polkitd",
        "dbus",
        "avahi",
        "systemd-network",
        "systemd-resolve",
        "systemd-timesync",
        "systemd-oom",
        "trustedinstaller",
    ];
    let bas = nom.trim().to_lowercase();
    // Un compte de service (« NT SERVICE\\WinDefend », « _apt ») : seulement un nom d'un mot, sans espace ni
    // accent ; « NT SERVICE\\Zoé Martin » ou « _Zoé Martin » nomment quelqu'un (relecture 0.97, bas).
    let service =
        |reste: &str| !reste.is_empty() && reste.chars().all(|c| c.is_ascii_alphanumeric() || "_.-$".contains(c));
    let de_service =
        bas.strip_prefix("nt service\\").is_some_and(service) || bas.strip_prefix('_').is_some_and(service);
    if SYSTEME.contains(&bas.as_str()) || de_service {
        nom.trim().to_string()
    } else {
        "<compte>".to_string()
    }
}

/// Une valeur masquée avec une fonction d'anonymisation donnée, et son décompte : les faux marqueurs d'abord, puis
/// `anonymiser`, puis le masquage commun de ce qui sort (`amelioration::texte::masquer` : séries, secrets, jetons,
/// MAC, IP, chemins, adresses web ; le même que le journal des erreurs), puis les adresses web qu'il n'aurait pas
/// prises (leur requête) et les chemins personnels qui resteraient (« ~/Documents/CV-Zoé-Martin.pdf »).
/// Le texte rendu est celui qui est montré puis écrit : rien de brut ne part à côté.
pub(crate) fn masquer_avec(texte: &str, maisons: &[String], anonymiser: &dyn Fn(&str) -> String) -> (String, Decompte) {
    // Compté contre le texte reçu : `desarme` retire déjà les adresses web, que le décompte doit voir.
    let (fin, _) = masquer_prepare(&crate::amelioration::texte::desarme(texte), maisons, anonymiser);
    let mut d = Decompte::default();
    compter(texte, &fin, &mut d);
    (fin, d)
}

/// `masquer_avec` sans désarmer les faux repères : pour un texte déjà désarmé où Vanguard a posé les siens.
pub(crate) fn masquer_prepare(
    texte: &str,
    maisons: &[String],
    anonymiser: &dyn Fn(&str) -> String,
) -> (String, Decompte) {
    let mut d = Decompte::default();
    // L'ordre compte (relecture 0.97, hauts d, e et f) : les adresses web entières d'abord, même collées ; puis les
    // chemins coupés à gauche, avant le masquage, qui prenait sinon leur fin (« …ob Exemple\Downloads\x.exe ») et
    // laissait leur début (les autres chemins restent au masquage, qui les prend entiers, espaces comprises) ; puis le masquage avant `anonymiser`, qui pose ses
    // marqueurs au début d'un secret, et encore après ; enfin les chemins, pour ce qu'`anonymiser` aurait découvert.
    let reduit = reduire_coupes_dans(&crate::amelioration::texte::sans_urls(texte), maisons);
    let premier = crate::amelioration::texte::masquer(&reduit);
    let masque = crate::amelioration::texte::masquer(&anonymiser(&premier));
    let fin = reduire_chemins_dans(&masque, maisons);
    compter(texte, &fin, &mut d);
    (fin, d)
}

/// Les dossiers personnels de cet ordinateur (HOME, USERPROFILE).
pub(crate) fn maisons() -> Vec<String> {
    ["HOME", "USERPROFILE"]
        .iter()
        .filter_map(|v| std::env::var(v).ok())
        .filter(|m| m.len() > 3)
        .collect()
}

/// Les valeurs personnelles connues que le contrôle final cherche : celles de `noms_a_retirer` (la personne, la
/// machine, les réseaux et appareils de la base), les dossiers personnels, et la sorte de chacune.
pub(crate) fn connues() -> Vec<(String, Sorte)> {
    let mut v: Vec<(String, Sorte)> = crate::journal::noms_a_retirer()
        .into_iter()
        .map(|(n, remplacant)| {
            let sorte = match remplacant {
                "<utilisateur>" => Sorte::Personne,
                "<machine>" => Sorte::Machine,
                "<réseau>" => Sorte::Reseau,
                _ => Sorte::Appareil,
            };
            (n, sorte)
        })
        .collect();
    v.extend(maisons().into_iter().map(|m| (m, Sorte::Dossier)));
    v
}

/// Un mot entier : ni lettre ni chiffre collé avant ou après (comme `anonymiser`, qui ne coupe pas « Maxime »).
fn trouve_en_mot(texte: &str, nom: &str) -> bool {
    let bas = texte.to_lowercase();
    let nom = nom.to_lowercase();
    if nom.is_empty() {
        return false;
    }
    bas.match_indices(&nom).any(|(i, _)| {
        let avant = bas[..i].chars().next_back();
        let apres = bas[i.saturating_add(nom.len())..].chars().next();
        avant.is_none_or(|c| !c.is_alphanumeric()) && apres.is_none_or(|c| !c.is_alphanumeric())
    })
}

/// Contrôle final, fermé en cas de doute : une valeur connue qui survit dans le texte, et rien n'est écrit. Rend les
/// sortes trouvées, jamais les valeurs (elles iraient sinon à l'écran et au journal des erreurs). Les noms de moins
/// de 3 caractères ne sont jamais masqués, ni cherchés ici.
pub(crate) fn controle_final(texte: &str, connues: &[(String, Sorte)]) -> Result<(), Vec<Sorte>> {
    let mut trouvees: Vec<Sorte> = connues
        .iter()
        .filter(|(v, _)| v.trim().chars().count() >= 3)
        .filter(|(v, s)| {
            let v = v.trim();
            if *s == Sorte::Dossier {
                // Un dossier personnel, sous toutes ses écritures (barres obliques, doublées).
                [v.to_string(), v.replace('\\', "/"), v.replace('\\', "\\\\")]
                    .iter()
                    .any(|w| texte.to_lowercase().contains(&w.to_lowercase()))
            } else {
                trouve_en_mot(texte, v)
            }
        })
        .map(|(_, s)| *s)
        .collect();
    trouvees.sort();
    trouvees.dedup();
    if trouvees.is_empty() { Ok(()) } else { Err(trouvees) }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    /// Une adresse web part entière, même collée à une option ou à un mot (valeurs inventées).
    #[test]
    fn adresses_web_sans_requete_ni_jeton() {
        use crate::amelioration::texte::sans_urls;
        assert_eq!(sans_urls("vu https://203.0.113.9/x?session=abc#k ici"), "vu <url> ici");
        assert_eq!(
            sans_urls("--url=HTTPS://alice:secret@exemple.example:8443/a?t=1, et xhttp://localhost:631/."),
            "--url=<url>, et <url>."
        );
        assert_eq!(sans_urls("rien ici"), "rien ici");
        assert_eq!(
            sans_urls("« http://192.0.2.4/?q » (https://exemple.test/a)"),
            "« <url> » (<url>)"
        );
    }

    #[test]
    fn chemins_personnels_reduits() {
        let m: Vec<String> = vec!["/home/alice".into()];
        assert_eq!(
            reduire_chemin("/home/alice/Documents/CV-Zoé-Martin.pdf", &m),
            "<chemin .pdf>"
        );
        assert_eq!(reduire_chemin("/home/bob/x", &m), "<chemin>");
        assert_eq!(reduire_chemin("/Users/alice/Desktop/a.TXT", &m), "<chemin .txt>");
        assert_eq!(
            reduire_chemin(r"C:\Users\Zoé\Downloads\setup.exe", &m),
            r"<chemin .exe>"
        );
        assert_eq!(reduire_chemin("/usr/bin/curl", &m), "/usr/bin/curl");
        assert_eq!(
            reduire_chemin(r"C:\Windows\System32\cmd.exe", &m),
            r"C:\Windows\System32\cmd.exe"
        );
        assert_eq!(
            reduire_chemins_dans("isolé : ~/Documents/CV-Zoé.pdf, puis C:\\Users\\Zoé\\a.exe.", &m),
            "isolé : <chemin .pdf>, puis <chemin .exe>."
        );
        assert_eq!(reduire_chemins_dans("ligne 1\n/usr/lib/x", &m), "ligne 1\n/usr/lib/x");
    }

    /// Un chemin coupé à gauche par `chasse::extrait` : son début est perdu, il est réduit en entier, même quand le
    /// compte coupé a une espace.
    #[test]
    fn chemin_coupe_a_gauche_reduit_en_entier() {
        let m: Vec<String> = vec!["/home/alice".into()];
        assert_eq!(
            reduire_chemins_dans("lancé (…échargements/Facture-Bob-Exemple/x.exe) hier", &m),
            "lancé (<chemin .exe>) hier"
        );
        let w = reduire_chemins_dans(r"lancé (…ob Exemple\Downloads\x.exe) hier", &m);
        assert_eq!(w, r"lancé (<chemin .exe>) hier");
        assert!(!w.contains("ob") && !w.contains("Exemple"), "{w}");
        // Sans parenthèse : le chemin s'arrête au premier morceau sans barre.
        assert_eq!(
            reduire_chemins_dans("vu …ce/Bob-Exemple/x.sh puis rien", &m),
            "vu <chemin .sh> puis rien"
        );
        // Un « … » qui ne coupe pas de chemin ne change rien.
        for t in [
            "dossiers protégés… et /usr/bin/curl",
            "…et 3 autres.",
            "(…)",
            "<chemin .pdf>",
        ] {
            assert_eq!(reduire_chemins_dans(t, &m), t);
        }
    }

    /// « fichier:~/… », « path:/home/… », « file:///home/… » : le mot avant « : » n'est pas une lettre de lecteur.
    #[test]
    fn schema_ou_mot_avant_le_chemin() {
        let m: Vec<String> = vec!["/home/alice".into()];
        for (avant, apres) in [
            ("fichier:~/Documents/CV-Bob-Exemple.pdf", "fichier:<chemin .pdf>"),
            ("path:/home/alice/CV-Bob-Exemple.pdf", "path:<chemin .pdf>"),
            ("file:///home/alice/CV-Bob-Exemple.pdf", "file://<chemin .pdf>"),
            (r"C:\Users\alice\a.exe", r"<chemin .exe>"),
            (r"(C:\Users\alice\a.exe)", r"(<chemin .exe>)"),
            ("«C:/Users/alice/a.exe»", "«<chemin .exe>»"),
            (r"fichier:C:\Users\alice\a.exe", r"fichier:<chemin .exe>"),
            ("https://192.0.2.4/home/x", "https://192.0.2.4/home/x"),
        ] {
            assert_eq!(reduire_chemins_dans(avant, &m), apres, "{avant}");
        }
    }

    #[test]
    fn comptes_du_systeme_seulement() {
        assert_eq!(compte("root"), "root");
        assert_eq!(compte("NT AUTHORITY\\SYSTEM"), "NT AUTHORITY\\SYSTEM");
        assert_eq!(compte("bob"), "<compte>");
        assert_eq!(compte("Zoé"), "<compte>");
        assert_eq!(compte("NT SERVICE\\WinDefend"), "NT SERVICE\\WinDefend");
        assert_eq!(compte("_apt"), "_apt");
        assert_eq!(compte("NT SERVICE\\Zoé Martin"), "<compte>");
        assert_eq!(compte("_Zoé Martin"), "<compte>");
        assert_eq!(compte("_"), "<compte>");
    }

    #[test]
    fn decompte_de_ce_qui_est_masque() {
        let (t, d) = masquer_avec(
            "alice@example.com 3c:22:fb:12:34:56 https://exemple.example/?s=1 /home/bob/a.pdf",
            &[],
            &|t: &str| {
                t.replace("alice@example.com", "<courriel>")
                    .replace("3c:22:fb:12:34:56", "3c:22:fb:aa:bb:cc")
                    .replace("/home/bob", "/home/<compte>")
            },
        );
        assert!(
            !t.contains("alice@") && !t.contains("12:34:56") && !t.contains("s=1"),
            "{t}"
        );
        assert_eq!(d.0.get(&Sorte::Courriel), Some(&1));
        assert_eq!(d.0.get(&Sorte::Mac), Some(&1));
        assert_eq!(d.0.get(&Sorte::Site), Some(&1), "{t}");
        // Le chemin entier devient « <chemin .pdf> » par le masquage commun : compté comme chemin, une seule fois.
        assert_eq!(t, "<adresse> <mac> <url> <chemin .pdf>");
        assert_eq!(d.0.get(&Sorte::Chemin), Some(&1), "{:?}", d.0);
        assert_ne!(d.texte(), "rien");
    }

    /// Relecture 0.97, hauts d, e et f (valeurs inventées) : un secret dont `anonymiser` marque le début, une adresse
    /// web collée à une option, un chemin coupé à gauche ne laissent rien de lisible.
    #[test]
    fn ordre_du_masquage() {
        let m: Vec<String> = vec!["/home/alice".into()];
        let anonymiser = |t: &str| t.replace("alice", "<utilisateur>");
        let masque = |t: &str| masquer_avec(t, &m, &anonymiser).0;
        let w = masque("curl -u alice:Lune2Verte9 --url=https://exemple.test/a?session=abc");
        assert_eq!(w, "curl -u <secret> --url=<url>");
        let w = masque(r"lancé (…ob Exemple\Downloads\x.exe) hier");
        assert_eq!(w, "lancé (<chemin .exe>) hier");
    }

    /// Relecture 0.97, ronde 3 : un chemin à espaces sous un dossier personnel part entier, dans un texte libre ; un
    /// chemin coupé à gauche aussi, jusqu'à son extension (valeurs inventées).
    #[test]
    fn chemins_a_espaces_dans_un_texte() {
        let m: Vec<String> = vec!["/home/alice".into()];
        let masque = |t: &str| masquer_avec(t, &m, &|t: &str| t.replace("alice", "<utilisateur>")).0;
        assert_eq!(
            masque("isolé : /home/bob/Documents/Facture Marie Tremblay 2026.pdf"),
            "isolé : <chemin .pdf>"
        );
        assert_eq!(
            masque("isolé : /home/alice/Documents/CV de Zoé Martin.pdf hier"),
            "isolé : <chemin .pdf> hier"
        );
        assert_eq!(
            masque(r"isolé : C:\Users\alice\Documents\CV de Zoé Martin.pdf hier"),
            "isolé : <chemin .pdf> hier"
        );
        assert_eq!(
            masque("ouvert \"/home/alice/Mes documents/Impôts Zoé Martin 2025.pdf\" par x"),
            "ouvert \"<chemin .pdf>\" par x"
        );
        assert_eq!(
            masque(r"lancé …oé Martin\Downloads\Facture Bob Exemple.exe hier"),
            "lancé <chemin .exe> hier"
        );
    }

    /// Relecture 0.97, ronde 3 : une extension inconnue d'un chemin entier ne reste pas (un nom de compte, de
    /// machine ou de famille) ; une connue, oui.
    #[test]
    fn marqueur_de_chemin_a_extension_connue() {
        assert_eq!(marqueur_de_chemin("/home/alice/Rapport.alice"), "<chemin>");
        assert_eq!(
            marqueur_de_chemin("/home/alice/.local/share/applications/firefox.desktop"),
            "<chemin>"
        );
        assert_eq!(marqueur_de_chemin("/home/alice/Documents/Lettre.Tremblay"), "<chemin>");
        assert_eq!(marqueur_de_chemin("/tmp/update.ALICE"), "<chemin>");
        assert_eq!(marqueur_de_chemin(r"C:\Users\alice\x.EXE"), "<chemin .exe>");
        assert_eq!(marqueur_de_chemin("/home/alice/.bashrc"), "<chemin>");
    }

    #[test]
    fn controle_final_dit_la_sorte_pas_la_valeur() {
        let connues = vec![
            ("DESKTOP-AB12".to_string(), Sorte::Machine),
            ("/home/alice".to_string(), Sorte::Dossier),
            ("al".to_string(), Sorte::Personne),
        ];
        assert_eq!(controle_final("rien de personnel, malice", &connues), Ok(()));
        let e = controle_final("vu sur desktop-ab12 dans /HOME/alice/x", &connues).unwrap_err();
        assert_eq!(e, vec![Sorte::Dossier, Sorte::Machine]);
        assert!(!e.iter().any(|s| s.nom().contains("AB12")));
        // Un mot plus long qui le contient n'est pas le nom (« DESKTOP-AB123 »).
        assert_eq!(controle_final("DESKTOP-AB123", &connues), Ok(()));
    }
}

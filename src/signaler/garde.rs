//! Le garde-fou de confidentialité du brouillon, en trois couches. 1. Ne pas prendre ce qui n'est pas utile à un
//! éditeur : `reduire_chemin` (un nom de fichier personnel comme « CV-Prénom-Nom.pdf » porte un nom complet que
//! `anonymiser` ne connaît pas) et `compte` (le compte d'un proche sur le même ordinateur passait en clair).
//! 2. Masquer chaque valeur avec `journal::anonymiser`, et les adresses web avec `masquer_url` (code nouveau :
//! `anonymiser` ne touche pas aux URL, dont la requête porte souvent un jeton de session). 3. Contrôle final : chercher
//! dans le texte entier chaque nom connu ; s'il en reste un, rien n'est écrit.
//!
//! Le contrôle final n'est pas une couche indépendante : il relit la même liste que celle qui a servi au masquage. Il
//! attrape un défaut du code, pas un nom que Vanguard ignore (nom complet, nom d'un proche, ville) : la vraie dernière
//! couche est la relecture par la personne, et les textes ne promettent pas plus.

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
            Sorte::Ip => ("adresse(s) IP publique(s)", "public IP address(es)"),
            Sorte::Mac => ("adresse(s) MAC", "MAC address(es)"),
            Sorte::Site => ("site(s) web et requête(s)", "website(s) and query string(s)"),
            Sorte::Fichier => ("nom(s) de fichier personnel", "personal file name(s)"),
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
            *self.0.entry(sorte).or_default() += n;
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

/// Les remplaçants posés par `anonymiser`, et la sorte qu'ils comptent.
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
    ("203.0.113.", Sorte::Ip),
    ("<site>", Sorte::Site),
    ("<fichier>", Sorte::Fichier),
];

/// Les mots d'un texte, coupés aux espaces et à la ponctuation qui n'entre ni dans une adresse ni dans un chemin.
fn mots(texte: &str) -> impl Iterator<Item = &str> {
    texte
        .split(|c: char| c.is_whitespace() || "\"'«»()[]<>,;`".contains(c))
        .filter(|m| !m.is_empty())
}

/// Une adresse MAC (six paires d'hexadécimaux séparées par « : » ou « - »).
fn forme_mac(m: &str) -> bool {
    let groupes: Vec<&str> = m.split([':', '-']).collect();
    groupes.len() == 6
        && groupes
            .iter()
            .all(|g| g.len() == 2 && g.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Une adresse IPv6 (au moins deux « : », des hexadécimaux), sans être une MAC.
fn forme_ipv6(m: &str) -> bool {
    let m = m.split('%').next().unwrap_or_default().trim_end_matches('.');
    m.matches(':').count() >= 2
        && m.chars().any(|c| c.is_ascii_hexdigit())
        && m.chars().all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
        && !forme_mac(m)
}

/// Le décompte entre un texte et son masquage : les remplaçants apparus, les adresses MAC et IPv6 disparues.
fn compter(avant: &str, apres: &str, d: &mut Decompte) {
    let n = |t: &str, m: &str| u32::try_from(t.matches(m).count()).unwrap_or(u32::MAX);
    for (remplacant, sorte) in REMPLACANTS {
        d.ajouter(*sorte, n(apres, remplacant).saturating_sub(n(avant, remplacant)));
    }
    let tildes = |t: &str| {
        u32::try_from(
            t.char_indices()
                .filter(|(i, c)| *c == '~' && t[i + 1..].starts_with(['/', '\\']))
                .count(),
        )
        .unwrap_or(u32::MAX)
    };
    d.ajouter(Sorte::Dossier, tildes(apres).saturating_sub(tildes(avant)));
    let restes: std::collections::BTreeSet<&str> = mots(apres).collect();
    for m in mots(avant) {
        let m = m.trim_end_matches(['.', ':']);
        if !restes.contains(m) {
            if forme_mac(m) {
                d.ajouter(Sorte::Mac, 1);
            } else if forme_ipv6(m) {
                d.ajouter(Sorte::Ip, 1);
            }
        }
    }
}

/// Une adresse web sans ce qui peut la rattacher à quelqu'un : la requête (« ?session=… ») et le fragment toujours
/// retirés (jetons de session), le nom et le mot de passe (« alice:secret@ ») aussi, et l'hôte remplacé par
/// « `<site>` » quand c'est un nom : un site visité dit qui on est. Une adresse IP reste pour `anonymiser`, qui masque
/// les publiques et garde les locales (les mêmes chez tout le monde). La personne remet ce qu'il faut pour
/// reproduire dans le fichier, après l'avoir vu.
pub(crate) fn masquer_url(texte: &str) -> String {
    let mut sortie = String::with_capacity(texte.len());
    let mut reste = texte;
    while let Some(i) = debut_url(reste) {
        sortie.push_str(&reste[..i]);
        let url = &reste[i..];
        let fin = url
            .find(|c: char| c.is_whitespace() || "\"'<>`«»".contains(c))
            .unwrap_or(url.len());
        sortie.push_str(&url_reduite(&url[..fin]));
        reste = &url[fin..];
    }
    sortie.push_str(reste);
    sortie
}

/// La position de la prochaine adresse « http(s):// », à la casse près.
fn debut_url(texte: &str) -> Option<usize> {
    let bas = texte.to_ascii_lowercase();
    [bas.find("https://"), bas.find("http://")].into_iter().flatten().min()
}

fn url_reduite(url: &str) -> String {
    let Some((schema, apres)) = url.split_once("://") else {
        return url.to_string();
    };
    let sans_suite = apres.split(['?', '#']).next().unwrap_or_default();
    let (autorite, chemin) = match sans_suite.find('/') {
        Some(k) => sans_suite.split_at(k),
        None => (sans_suite, ""),
    };
    let hote_port = autorite.rsplit('@').next().unwrap_or_default();
    let (hote, port) = match hote_port.rsplit_once(':') {
        Some((h, p)) if !h.contains(']') && p.chars().all(|c| c.is_ascii_digit()) => (h, Some(p)),
        _ => (hote_port, None),
    };
    let est_ip = hote.starts_with('[') || hote.chars().all(|c| c.is_ascii_digit() || c == '.');
    let local = hote.eq_ignore_ascii_case("localhost");
    let hote = if est_ip || local || hote.is_empty() {
        hote.to_string()
    } else {
        "<site>".to_string()
    };
    let port = port.map(|p| format!(":{p}")).unwrap_or_default();
    format!("{schema}://{hote}{port}{chemin}")
}

/// Le dossier personnel au début d'un chemin (« /home/alice/ », « C:\Users\Zoé\ », « ~/ »), et sa longueur.
fn dossier_personnel(chemin: &str, maisons: &[String]) -> Option<usize> {
    for m in maisons.iter().filter(|m| m.len() > 3) {
        if chemin.len() > m.len()
            && chemin.is_char_boundary(m.len())
            && chemin[..m.len()].eq_ignore_ascii_case(m)
            && chemin[m.len()..].starts_with(['/', '\\'])
        {
            return Some(m.len() + 1);
        }
    }
    if chemin.starts_with("~/") || chemin.starts_with("~\\") {
        return Some(2);
    }
    let bas = chemin.to_lowercase();
    for debut in ["/var/home/", "/home/", "/users/", "/run/media/", "/media/", "/root/"] {
        if let Some(reste) = bas.strip_prefix(debut) {
            // Le compte après le préfixe (« /home/alice/ »), sauf /root/, qui est déjà le dossier.
            let compte = if debut == "/root/" { 0 } else { reste.find('/')? + 1 };
            return Some(debut.len() + compte);
        }
    }
    let b = chemin.as_bytes();
    if b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/') {
        let reste = &bas[3..];
        if let Some(r) = reste.strip_prefix("users\\").or_else(|| reste.strip_prefix("users/")) {
            return Some(3 + "users\\".len() + r.find(['\\', '/'])? + 1);
        }
    }
    None
}

/// Un chemin de fichier tel qu'il entre dans le brouillon : les dossiers du système restent (`/usr/bin/curl`,
/// `C:\Windows\System32\…`, qui aident à reproduire) ; sous un dossier personnel, ni les dossiers ni le nom ne
/// restent (« `~/…/<fichier>.pdf` »), seulement l'extension, qui dit la sorte de fichier.
pub(crate) fn reduire_chemin(chemin: &str, maisons: &[String]) -> String {
    if dossier_personnel(chemin, maisons).is_none() {
        return chemin.to_string();
    }
    let nom = chemin.rsplit(['/', '\\']).next().unwrap_or_default();
    let extension = nom
        .rsplit_once('.')
        .map(|(_, e)| e)
        .filter(|e| !e.is_empty() && e.len() <= 8 && e.chars().all(|c| c.is_ascii_alphanumeric()))
        .map(|e| format!(".{}", e.to_ascii_lowercase()))
        .unwrap_or_default();
    let separateur = if chemin.contains('\\') { '\\' } else { '/' };
    format!("~{separateur}…{separateur}<fichier>{extension}")
}

/// La ponctuation qui ferme un chemin cité (« (~/a/x.exe) », « ~/a/x.exe. »).
const FIN_DE_CHEMIN: [char; 7] = ['.', ',', ';', ')', '»', '"', '\''];

/// Les chemins sous un dossier personnel cités dans un texte (une alerte, un message d'examen), réduits comme
/// `reduire_chemin`. Un chemin s'arrête au premier espace : un nom de fichier qui en contient laisse passer sa fin, ce
/// que la relecture par la personne doit voir (c'est dit dans le brouillon). Un chemin coupé à gauche par « … »
/// (`chasse::extrait`) est réduit en entier : son début est perdu, rien ne prouve qu'il est hors d'un dossier
/// personnel.
pub(crate) fn reduire_chemins_dans(texte: &str, maisons: &[String]) -> String {
    texte
        .split('\n')
        .map(|ligne| reduire_ligne(ligne, maisons))
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
        let apres = corps.get(k + '…'.len_utf8()..).filter(|a| !a.is_empty())?;
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

fn reduire_ligne(ligne: &str, maisons: &[String]) -> String {
    let mut l = String::with_capacity(ligne.len());
    let mut coupe: Option<Coupe> = None;
    for (j, morceau) in ligne.split(' ').enumerate() {
        let corps = morceau.trim_end_matches(FIN_DE_CHEMIN);
        let suite = &morceau[corps.len()..];
        if let Some(mut c) = coupe.take() {
            if c.a_une_barre() && !morceau.contains(['/', '\\']) {
                // Le chemin est fini : ce morceau est la suite du texte.
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
                continue;
            }
        }
        if j > 0 {
            l.push(' ');
        }
        if let Some(c) = Coupe::lire(morceau) {
            if suite.is_empty() {
                coupe = Some(c);
            } else {
                l.push_str(&c.rendre(suite, maisons));
            }
            continue;
        }
        l.push_str(&reduire_morceau(morceau, maisons));
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
        && morceau[..debut - 1].ends_with(|c: char| c.is_ascii_alphabetic())
        && !morceau[..debut - 2].ends_with(|c: char| c.is_alphanumeric());
    // « file:///home/… » : les barres en trop du schéma ne font pas partie du chemin.
    let debut = if lecteur {
        debut - 2
    } else if morceau[..debut].ends_with(':') && morceau[debut..].starts_with("///") {
        debut + 2
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
    if SYSTEME.contains(&bas.as_str()) || bas.starts_with("nt service\\") || bas.starts_with('_') {
        nom.trim().to_string()
    } else {
        "<compte>".to_string()
    }
}

/// Une valeur masquée avec une fonction d'anonymisation donnée, et son décompte : les adresses web d'abord (leur
/// requête), puis `anonymiser`, puis les chemins personnels qui restent (« ~/Documents/CV-Zoé-Martin.pdf »).
pub(crate) fn masquer_avec(texte: &str, maisons: &[String], anonymiser: &dyn Fn(&str) -> String) -> (String, Decompte) {
    let mut d = Decompte::default();
    let sans_url = masquer_url(texte);
    let anonyme = anonymiser(&sans_url);
    let reduit = reduire_chemins_dans(&anonyme, maisons);
    compter(texte, &reduit, &mut d);
    (reduit, d)
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
        let apres = bas[i + nom.len()..].chars().next();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adresses_web_sans_requete_ni_jeton() {
        assert_eq!(
            masquer_url("vu https://203.0.113.9/x?session=abc#k ici"),
            "vu https://203.0.113.9/x ici"
        );
        assert_eq!(
            masquer_url("HTTPS://alice:secret@exemple.example:8443/a/b?t=1 et http://localhost:631/"),
            "HTTPS://<site>:8443/a/b et http://localhost:631/"
        );
        assert_eq!(masquer_url("rien ici"), "rien ici");
        assert_eq!(masquer_url("« http://192.0.2.4/?q » fin"), "« http://192.0.2.4/ » fin");
    }

    #[test]
    fn chemins_personnels_reduits() {
        let m: Vec<String> = vec!["/home/alice".into()];
        assert_eq!(
            reduire_chemin("/home/alice/Documents/CV-Zoé-Martin.pdf", &m),
            "~/…/<fichier>.pdf"
        );
        assert_eq!(reduire_chemin("/home/bob/x", &m), "~/…/<fichier>");
        assert_eq!(reduire_chemin("/Users/alice/Desktop/a.TXT", &m), "~/…/<fichier>.txt");
        assert_eq!(
            reduire_chemin(r"C:\Users\Zoé\Downloads\setup.exe", &m),
            r"~\…\<fichier>.exe"
        );
        assert_eq!(reduire_chemin("/usr/bin/curl", &m), "/usr/bin/curl");
        assert_eq!(
            reduire_chemin(r"C:\Windows\System32\cmd.exe", &m),
            r"C:\Windows\System32\cmd.exe"
        );
        assert_eq!(
            reduire_chemins_dans("isolé : ~/Documents/CV-Zoé.pdf, puis C:\\Users\\Zoé\\a.exe.", &m),
            "isolé : ~/…/<fichier>.pdf, puis ~\\…\\<fichier>.exe."
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
            "lancé (~/…/<fichier>.exe) hier"
        );
        let w = reduire_chemins_dans(r"lancé (…ob Exemple\Downloads\x.exe) hier", &m);
        assert_eq!(w, r"lancé (~\…\<fichier>.exe) hier");
        assert!(!w.contains("ob") && !w.contains("Exemple"), "{w}");
        // Sans parenthèse : le chemin s'arrête au premier morceau sans barre.
        assert_eq!(
            reduire_chemins_dans("vu …ce/Bob-Exemple/x.sh puis rien", &m),
            "vu ~/…/<fichier>.sh puis rien"
        );
        // Un « … » qui ne coupe pas de chemin ne change rien.
        for t in [
            "dossiers protégés… et /usr/bin/curl",
            "…et 3 autres.",
            "(…)",
            "~/…/<fichier>.pdf",
        ] {
            assert_eq!(reduire_chemins_dans(t, &m), t);
        }
    }

    /// « fichier:~/… », « path:/home/… », « file:///home/… » : le mot avant « : » n'est pas une lettre de lecteur.
    #[test]
    fn schema_ou_mot_avant_le_chemin() {
        let m: Vec<String> = vec!["/home/alice".into()];
        for (avant, apres) in [
            ("fichier:~/Documents/CV-Bob-Exemple.pdf", "fichier:~/…/<fichier>.pdf"),
            ("path:/home/alice/CV-Bob-Exemple.pdf", "path:~/…/<fichier>.pdf"),
            ("file:///home/alice/CV-Bob-Exemple.pdf", "file://~/…/<fichier>.pdf"),
            (r"C:\Users\alice\a.exe", r"~\…\<fichier>.exe"),
            (r"(C:\Users\alice\a.exe)", r"(~\…\<fichier>.exe)"),
            ("«C:/Users/alice/a.exe»", "«~/…/<fichier>.exe»"),
            (r"fichier:C:\Users\alice\a.exe", r"fichier:~\…\<fichier>.exe"),
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
        assert_eq!(d.0.get(&Sorte::Site), Some(&1));
        assert_eq!(d.0.get(&Sorte::Fichier), Some(&1));
        assert_ne!(d.texte(), "rien");
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

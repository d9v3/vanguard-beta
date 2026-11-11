//! Une ligne de la configuration du client SSH (~/.ssh/config, ses fichiers inclus, la configuration du système),
//! découpée une seule fois pour les trois lecteurs de Vanguard : le dépliage des « Include » (`machine::Depliage`), les
//! réglages risqués de `cles_ssh` et le client post-quantique. Chacun avait son propre découpage, aucun celui de SSH :
//! un mot-clé entre guillemets, un « = » devant lui, une valeur synonyme ou un hôte large autre que « * » passaient
//! pour des lignes sans effet, alors que SSH les appliquait.
//!
//! Une liste PERMISE de formes : SSH découpe le mot-clé avec `strdelim` et les arguments avec `argv_split`
//! (readconf.c, misc.c) ; ce qui n'entre pas exactement dans une forme que les deux découpent pareil est
//! `NonInterpretee`, dit « non lu » par l'appelant, jamais pris pour « rien ». Une forme oubliée est dite, pas tue.

// Ni `unsafe` : du code pur, sur un texte venu de n'importe qui.
#![forbid(unsafe_code)]

/// Ce qu'une ligne de configuration du client SSH est pour Vanguard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ligne<'a> {
    /// Vide ou commentaire : SSH n'en fait rien.
    Rien,
    /// Une forme que Vanguard ne découpe pas exactement comme SSH : dite « non lu ».
    NonInterpretee,
    /// « Include » et ses arguments tels qu'écrits (le dépliage les résout, `machine::motif_interprete`).
    Include(&'a str),
    /// « Host » ou « Match » : `true` si la suite vaut pour tous les serveurs (dans le doute aussi).
    Portee(bool),
    /// Un réglage que Vanguard juge, à une seule valeur, sans ses guillemets.
    Valeur(Cle, &'a str),
    /// Un autre mot-clé : Vanguard ne le juge pas et ne lit pas ses arguments.
    Autre,
}

/// Les réglages à une valeur que Vanguard juge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cle {
    ForwardAgent,
    StrictHostKeyChecking,
    KexAlgorithms,
    WarnWeakCrypto,
}

/// Les blancs de `strdelim` (WHITESPACE de misc.h).
const BLANCS: [char; 4] = [' ', '\t', '\r', '\n'];

/// Découpe une ligne comme SSH (`process_config_line_depth`), ou dit qu'elle n'est pas interprétée.
pub(crate) fn lire_ligne(ligne: &str) -> Ligne<'_> {
    // SSH lit une chaîne C : un octet nul finit la ligne.
    let ligne = ligne.split('\0').next().unwrap_or_default();
    // Blancs et sauts de page de fin retirés, jamais le premier caractère : « \f » seul reste un mot-clé (refusé).
    let Some(premier) = ligne.chars().next() else {
        return Ligne::Rien;
    };
    let fin = ligne.trim_end_matches([' ', '\t', '\r', '\n', '\u{c}']);
    let ligne = if fin.is_empty() {
        ligne.get(..premier.len_utf8()).unwrap_or_default()
    } else {
        fin
    };
    // Blancs de tête puis un seul « = » (le premier `strdelim` rend un mot vide et saute un « = »).
    let reste = ligne.trim_start_matches(BLANCS);
    let reste = reste.strip_prefix('=').map_or(reste, |r| r.trim_start_matches(BLANCS));
    if reste.is_empty() || reste.starts_with('#') {
        return Ligne::Rien;
    }
    let fin_cle = reste.find([' ', '\t', '\r', '\n', '"', '=']).unwrap_or(reste.len());
    let (cle, apres) = reste.split_at_checked(fin_cle).unwrap_or((reste, ""));
    // Un mot-clé de SSH est fait de lettres et de chiffres ASCII ; entre guillemets (que SSH retire, même au milieu
    // du mot), ou fait d'autre chose : non interprété.
    if cle.is_empty() || !cle.bytes().all(|o| o.is_ascii_alphanumeric()) {
        return Ligne::NonInterpretee;
    }
    let arguments = if let Some(r) = apres.strip_prefix('=') {
        r.trim_start_matches(BLANCS)
    } else if apres.starts_with('"') {
        return Ligne::NonInterpretee;
    } else {
        let r = apres.trim_start_matches(BLANCS);
        r.strip_prefix('=').map_or(r, |r| r.trim_start_matches(BLANCS))
    };
    // Sans argument, SSH refuse toute la configuration.
    if arguments.is_empty() {
        return Ligne::NonInterpretee;
    }
    let valeur = |c: Cle| match mots(arguments).as_deref() {
        Some([v]) => Ligne::Valeur(c, v),
        _ => Ligne::NonInterpretee,
    };
    match cle.to_ascii_lowercase().as_str() {
        "include" => Ligne::Include(arguments),
        "host" => match mots(arguments) {
            Some(m) if !m.is_empty() => Ligne::Portee(m.iter().any(|p| universel(p))),
            _ => Ligne::NonInterpretee,
        },
        "match" => mots(arguments)
            .and_then(|m| match_globale(&m))
            .map_or(Ligne::NonInterpretee, Ligne::Portee),
        "forwardagent" => valeur(Cle::ForwardAgent),
        "stricthostkeychecking" => valeur(Cle::StrictHostKeyChecking),
        "kexalgorithms" => valeur(Cle::KexAlgorithms),
        "warnweakcrypto" => valeur(Cle::WarnWeakCrypto),
        _ => Ligne::Autre,
    }
}

/// Les arguments d'un réglage jugé, découpés comme `argv_split` les découpe, pour les seules formes où tout lecteur
/// s'accorde : des mots séparés par espaces ou tabulations, sans guillemet, apostrophe, barre oblique inverse, « # »,
/// « = » ni caractère de contrôle ; ou un mot entier entre guillemets (espaces et apostrophes permises, ni barre
/// oblique inverse ni contrôle, non vide). Un mot qui commence par « # » ouvre un commentaire. Le reste : `None`.
fn mots(texte: &str) -> Option<Vec<&str>> {
    let mut mots = Vec::new();
    let mut reste = texte;
    loop {
        reste = reste.trim_start_matches([' ', '\t']);
        if reste.is_empty() || reste.starts_with('#') {
            return Some(mots);
        }
        let (mot, apres) = if let Some(entre) = reste.strip_prefix('"') {
            let (mot, apres) = entre.split_once('"')?;
            let permis = !mot.is_empty() && !mot.contains('\\') && !mot.chars().any(char::is_control);
            (permis && (apres.is_empty() || apres.starts_with([' ', '\t']))).then_some((mot, apres))?
        } else {
            let fin = reste.find([' ', '\t']).unwrap_or(reste.len());
            let (mot, apres) = reste.split_at_checked(fin)?;
            let interdit = |c: char| "\"'\\#=".contains(c) || c.is_control();
            (!mot.contains(interdit)).then_some((mot, apres))?
        };
        mots.push(mot);
        reste = apres;
    }
}

/// Un motif d'hôte qui couvre des serveurs qu'il ne nomme pas : sans « ! », avec un « * », sans lettre ni chiffre
/// (« * », « ** », « ?* », « *.* »). « *.exemple.org » nomme un domaine : précis.
fn universel(motif: &str) -> bool {
    !motif.starts_with('!') && motif.contains('*') && !motif.chars().any(char::is_alphanumeric)
}

/// La suite d'un « Match » vaut-elle pour tous les serveurs ? Les critères se cumulent (ET). Un critère qui restreint
/// l'hôte (« host » ou « originalhost » sans motif universel, ou « !host » avec) rend la suite précise, « !all »
/// jamais vraie ; les autres (« all », « canonical », « final », et ceux qui ne regardent pas l'hôte : user, exec…)
/// ne restreignent pas l'hôte, et dans le doute la suite est globale. Critère inconnu, argument manquant, « all »
/// suivi d'autre chose : `None` (non interprété).
fn match_globale(mots: &[&str]) -> Option<bool> {
    if mots.is_empty() {
        return None;
    }
    let mut globale = true;
    let mut i = mots.iter();
    while let Some(mot) = i.next() {
        let (nie, critere) = mot.strip_prefix('!').map_or((false, *mot), |c| (true, c));
        match critere.to_ascii_lowercase().as_str() {
            "all" => {
                if i.next().is_some() {
                    return None;
                }
                globale &= !nie;
            }
            "canonical" | "final" => {}
            "host" | "originalhost" => {
                let tout = i.next()?.split(',').any(universel);
                if nie == tout {
                    globale = false;
                }
            }
            "user" | "localuser" | "exec" | "localnetwork" | "tagged" | "command" | "version" | "sessiontype" => {
                i.next()?;
            }
            _ => return None,
        }
    }
    Some(globale)
}

/// « ForwardAgent » : tout autre chose que « no » ou « false » prête l'agent (« yes », « true », un chemin de prise,
/// une variable).
#[cfg_attr(windows, allow(dead_code))] // Sous Windows, les « Include » ne sont pas dépliés ni les risques lus.
pub(crate) fn pret_d_agent(valeur: &str) -> bool {
    !["no", "false"].iter().any(|v| valeur.eq_ignore_ascii_case(v))
}

/// « StrictHostKeyChecking » : relâché, sauf les valeurs qui vérifient (une valeur inconnue, SSH la refuse).
#[cfg_attr(windows, allow(dead_code))] // Sous Windows, les « Include » ne sont pas dépliés ni les risques lus.
pub(crate) fn sans_verification(valeur: &str) -> bool {
    !["yes", "true", "ask", "accept-new"]
        .iter()
        .any(|v| valeur.eq_ignore_ascii_case(v))
}

/// « WarnWeakCrypto » : l'avertissement est coupé sauf par « yes » ou « true » (« no-pq-kex » coupe celui du
/// post-quantique).
pub(crate) fn avertissement_coupe(valeur: &str) -> bool {
    !["yes", "true"].iter().any(|v| valeur.eq_ignore_ascii_case(v))
}

/// Une ligne d'une configuration dépliée, ou la limite d'un fichier inclus : SSH remet, à la fin de chaque fichier
/// inclus, la portée Host/Match d'avant l'« Include ».
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Lue {
    /// Fichier montré, numéro de ligne, ligne.
    Ligne(String, usize, String),
    #[cfg_attr(windows, allow(dead_code))] // Sous Windows, les « Include » ne sont pas dépliés.
    Entree,
    #[cfg_attr(windows, allow(dead_code))]
    Sortie,
}

/// La portée en cours d'une configuration lue dans l'ordre : les lignes valent-elles pour tous les serveurs ?
pub(crate) struct Portee {
    globale: bool,
    /// Faux dans un fichier inclus sous un « Host » ou un « Match » précis : rien n'y est global (SSH le lit en
    /// « jamais vrai »).
    plafond: bool,
    pile: Vec<(bool, bool)>,
}

impl Portee {
    /// Au début d'un fichier de tête : tout vaut pour tous les serveurs.
    pub(crate) fn nouvelle() -> Self {
        Portee {
            globale: true,
            plafond: true,
            pile: Vec::new(),
        }
    }

    pub(crate) fn globale(&self) -> bool {
        self.globale
    }

    /// Une ligne lue : rend ce qu'elle est, après avoir suivi la portée. Une ligne non interprétée qui pourrait être
    /// un « Host » ou un « Match » rend la suite globale : dans le doute, un réglage relâché est signalé.
    pub(crate) fn lire<'a>(&mut self, lue: &'a Lue) -> Option<(&'a str, usize, Ligne<'a>)> {
        match lue {
            Lue::Entree => {
                self.pile.push((self.globale, self.plafond));
                self.plafond = self.globale;
                None
            }
            Lue::Sortie => {
                if let Some((globale, plafond)) = self.pile.pop() {
                    self.globale = globale;
                    self.plafond = plafond;
                }
                None
            }
            Lue::Ligne(fichier, n, texte) => {
                let l = lire_ligne(texte);
                match l {
                    Ligne::Portee(g) => self.globale = self.plafond && g,
                    Ligne::NonInterpretee if peut_etre_portee(texte) => self.globale = self.plafond,
                    _ => {}
                }
                Some((fichier.as_str(), *n, l))
            }
        }
    }
}

/// Une ligne non interprétée que SSH pourrait lire comme « Host » ou « Match » : ses blancs, « = » et guillemets
/// retirés, elle commence par l'un d'eux (`strdelim` ne fait que retirer un guillemet et couper au suivant).
fn peut_etre_portee(ligne: &str) -> bool {
    let sans: String = ligne
        .trim_start_matches(|c: char| BLANCS.contains(&c) || c == '=' || c == '"')
        .chars()
        .filter(|&c| c != '"')
        .take(5)
        .collect::<String>()
        .to_ascii_lowercase();
    sans.starts_with("host") || sans.starts_with("match")
}

/// Un texte long montré par son début et sa fin, au plus `ABREGE` caractères (un chemin d'inclusion de 4 Kio était
/// montré en entier).
#[cfg_attr(windows, allow(dead_code))] // Sous Windows, les « Include » ne sont pas dépliés ni les risques lus.
pub(crate) fn abreger(texte: &str) -> String {
    const ABREGE: usize = 120;
    let n = texte.chars().count();
    if n <= ABREGE {
        return texte.to_string();
    }
    let debut: String = texte.chars().take(ABREGE / 2).collect();
    let fin: String = texte.chars().skip(n.saturating_sub(ABREGE / 2 - 1)).collect();
    format!("{debut}…{fin}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mot_cle_et_arguments_comme_ssh() {
        use Cle::*;
        use Ligne::*;
        for (ligne, attendu) in [
            ("", Rien),
            ("   ", Rien),
            ("# ForwardAgent yes", Rien),
            ("  =# x", Rien),
            ("ForwardAgent yes", Valeur(ForwardAgent, "yes")),
            ("forwardagent=yes", Valeur(ForwardAgent, "yes")),
            ("  ForwardAgent = yes # commentaire", Valeur(ForwardAgent, "yes")),
            ("ForwardAgent\tyes\r", Valeur(ForwardAgent, "yes")),
            ("ForwardAgent\ryes", Valeur(ForwardAgent, "yes")),
            ("ForwardAgent yes\u{c}", Valeur(ForwardAgent, "yes")),
            ("=ForwardAgent yes", Valeur(ForwardAgent, "yes")),
            (" = ForwardAgent yes", Valeur(ForwardAgent, "yes")),
            ("ForwardAgent \"yes\"", Valeur(ForwardAgent, "yes")),
            ("ForwardAgent yes\0 no", Valeur(ForwardAgent, "yes")),
            ("KexAlgorithms \"a b\"", Valeur(KexAlgorithms, "a b")),
            ("Include a b", Include("a b")),
            ("=Include x", Include("x")),
            (" = include=x", Include("x")),
            ("IdentityFile \"~/.ssh/a b\" 'c'", Autre),
            ("ProxyCommand ssh -W \"%h:%p\" passerelle", Autre),
            // Non interprétées : mot-clé entre guillemets (même au milieu), « = » en trop, sans argument, valeur entre
            // apostrophes, guillemets partiels, échappée, « # » ou contrôle dans un mot, plus d'une valeur.
            ("\"ForwardAgent\" yes", NonInterpretee),
            ("For\"ward\"Agent yes", NonInterpretee),
            ("\"Include\"inclus", NonInterpretee),
            ("Inc\"lude\"inclus", NonInterpretee),
            ("==ForwardAgent yes", NonInterpretee),
            ("ForwardAgent==yes", NonInterpretee),
            ("Host", NonInterpretee),
            ("Include", NonInterpretee),
            ("\u{c}", NonInterpretee),
            ("Forward-Agent yes", NonInterpretee),
            ("ForwardAgent 'yes'", NonInterpretee),
            ("ForwardAgent \"yes", NonInterpretee),
            ("ForwardAgent y\"es\"", NonInterpretee),
            ("ForwardAgent \"yes\"x", NonInterpretee),
            ("ForwardAgent \"\"", NonInterpretee),
            ("ForwardAgent ye\\s", NonInterpretee),
            ("ForwardAgent no#x", NonInterpretee),
            ("ForwardAgent no\u{c}x", NonInterpretee),
            ("ForwardAgent yes no", NonInterpretee),
            ("ForwardAgent # rien", NonInterpretee),
            ("Host '*'", NonInterpretee),
            ("Host # rien", NonInterpretee),
        ] {
            assert_eq!(lire_ligne(ligne), attendu, "{ligne:?}");
        }
    }

    #[test]
    fn portees_comme_ssh() {
        for (ligne, globale) in [
            ("Host *", Some(true)),
            ("Host \"*\"", Some(true)),
            ("Host **", Some(true)),
            ("Host ?*", Some(true)),
            ("Host *.*", Some(true)),
            ("Host * !labo", Some(true)),
            ("Host labo *", Some(true)),
            ("Host labo", Some(false)),
            ("Host *.exemple.org", Some(false)),
            ("Host !*", Some(false)),
            ("Host ???", Some(false)),
            ("Host *,labo", Some(false)),
            ("Match all", Some(true)),
            ("Match final all", Some(true)),
            ("Match canonical all # x", Some(true)),
            ("Match final", Some(true)),
            ("Match host *", Some(true)),
            ("MATCH Host labo,*", Some(true)),
            ("Match !host labo", Some(true)),
            ("Match exec \"test -f /x\"", Some(true)),
            ("Match user alice", Some(true)),
            ("Match host labo exec \"nc -z %h 22\"", Some(false)),
            ("Match originalhost labo", Some(false)),
            ("Match !host *", Some(false)),
            ("Match !all", Some(false)),
            ("Match host labo all", Some(false)),
            ("Match all host labo", None),
            ("Match host", None),
            ("Match host=*", None),
            ("Match inconnu x", None),
            ("Match exec \"test \\\"x\\\"\"", None),
        ] {
            let attendu = globale.map_or(Ligne::NonInterpretee, Ligne::Portee);
            assert_eq!(lire_ligne(ligne), attendu, "{ligne:?}");
        }
    }

    #[test]
    fn valeurs_jugees_comme_ssh() {
        for v in ["yes", "true", "Yes", "$SSH_AUTH_SOCK", "/run/agent.sock", "ask"] {
            assert!(pret_d_agent(v), "{v}");
        }
        for v in ["no", "NO", "false", "False"] {
            assert!(!pret_d_agent(v), "{v}");
        }
        for v in ["no", "off", "false", "NO", "Off"] {
            assert!(sans_verification(v), "{v}");
        }
        for v in ["yes", "true", "ask", "accept-new", "Accept-New"] {
            assert!(!sans_verification(v), "{v}");
        }
        for v in ["no", "no-pq-kex", "false", "NO"] {
            assert!(avertissement_coupe(v), "{v}");
        }
        assert!(!avertissement_coupe("yes") && !avertissement_coupe("TRUE"));
    }

    /// SSH remet la portée d'avant l'« Include » à la fin du fichier inclus ; sous un « Host » précis, rien du
    /// fichier inclus n'est global, pas même un « Host * ».
    #[test]
    fn portee_remise_apres_un_inclus() {
        let l = |t: &str| Lue::Ligne("f".into(), 1, t.into());
        let globales = |lignes: &[Lue]| -> Vec<bool> {
            let mut p = Portee::nouvelle();
            lignes.iter().filter_map(|x| p.lire(x).map(|_| p.globale())).collect()
        };
        let apres_inclus = [Lue::Entree, l("Host labo"), Lue::Sortie, l("ForwardAgent yes")];
        assert_eq!(globales(&apres_inclus), [false, true]);
        let sous_host = [
            l("Host labo"),
            Lue::Entree,
            l("ForwardAgent yes"),
            l("Host *"),
            l("ForwardAgent yes"),
            Lue::Sortie,
            l("ForwardAgent yes"),
        ];
        assert_eq!(globales(&sous_host), [false, false, false, false, false]);
        let doute = [l("Host labo"), l("\"Host\" labo"), l("ForwardAgent yes")];
        assert_eq!(globales(&doute), [false, true, true]);
        let autre_doute = [l("Host labo"), l("ForwardAgent 'no'"), l("ForwardAgent yes")];
        assert_eq!(globales(&autre_doute), [false, false, false]);
    }

    #[test]
    fn abreger_garde_debut_et_fin() {
        assert_eq!(abreger("court"), "court");
        let long = format!("debut{}fin", "é".repeat(4000));
        let a = abreger(&long);
        assert!(a.starts_with("debut") && a.ends_with("fin") && a.contains('…'), "{a}");
        assert_eq!(a.chars().count(), 120);
    }
}

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
    /// « Host » ou « Match » : pour qui vaut la suite.
    Portee(Etendue),
    /// Un réglage que Vanguard juge, à une seule valeur, sans ses guillemets.
    Valeur(Cle, &'a str),
    /// Un autre mot-clé : Vanguard ne le juge pas et ne lit pas ses arguments.
    Autre,
}

/// Pour qui vaut la suite d'un « Host » ou d'un « Match ». Trois états, pas deux : « dans le doute, global » est
/// prudent pour qui alerte sur toute ligne globale, mais faux pour qui garde la première valeur globale et s'arrête
/// (une bonne valeur sous un en-tête que SSH n'applique pas cachait la mauvaise, vraiment globale, qui suivait).
/// L'ordre compte : la portée d'en-têtes cumulés (Include, critères d'un Match) est la plus petite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Etendue {
    /// Pour aucun serveur, ou pour des serveurs nommés.
    Precise,
    /// Peut-être pour tous les serveurs, pas à coup sûr : SSH peut ne pas l'appliquer (« Match final », « user »,
    /// « exec »…, joker avec exclusion, « *.* », ligne non interprétée qui pourrait être un en-tête).
    PeutEtre,
    /// Pour tous les serveurs, à coup sûr : début d'un fichier de tête, « Host * » sans exclusion, « Match all ».
    Globale,
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
        "host" => en_tete(arguments)
            .map(|m| etendue_host(&m))
            .map_or(Ligne::NonInterpretee, Ligne::Portee),
        "match" => en_tete(arguments)
            .and_then(|m| etendue_match(&m))
            .map_or(Ligne::NonInterpretee, Ligne::Portee),
        "forwardagent" => valeur(Cle::ForwardAgent),
        "stricthostkeychecking" => valeur(Cle::StrictHostKeyChecking),
        "kexalgorithms" => match valeur(Cle::KexAlgorithms) {
            Ligne::Valeur(_, v) if !kex_lisible(v) => Ligne::NonInterpretee,
            l => l,
        },
        "warnweakcrypto" => valeur(Cle::WarnWeakCrypto),
        _ => Ligne::Autre,
    }
}

/// La plus longue liste KexAlgorithms jugée : celle de tous les échanges qu'OpenSSH 10.6 connaît fait 425 octets.
const KEX_MAX: usize = 4096;

/// Une liste KexAlgorithms que Vanguard juge, sinon dite « non lu » (vérification de Fable n° 3, N2) : au plus
/// `KEX_MAX` octets, et chaque entrée sous la borne de `match_pattern_list`, au-delà de laquelle SSH ne retire rien
/// d'une liste « - » (une entrée de 500 000 « * » faisait planter la comparaison, des « *? » la figeaient).
fn kex_lisible(valeur: &str) -> bool {
    let liste = valeur.strip_prefix(['+', '-', '^']).unwrap_or(valeur);
    valeur.len() <= KEX_MAX && liste.split(',').all(|e| e.len() <= MOTIF_LISTE_MAX)
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

/// Les arguments d'un « Host » ou d'un « Match », découpés comme `argv_split` (misc.c) les découpe : guillemets et
/// apostrophes retirés, échappements `\'`, `\"`, `\\` et (hors guillemets) `\ ` lus, « # » en tête de mot qui
/// ouvre un commentaire. Un guillemet resté ouvert, un mot vide (SSH refuse alors le fichier), aucun mot, ou un
/// caractère de contrôle autre que la tabulation (forme que Vanguard ne sait pas montrer telle quelle) : `None`.
fn en_tete(texte: &str) -> Option<Vec<String>> {
    if texte.chars().any(|c| c.is_control() && c != '\t') {
        return None;
    }
    let mut mots = Vec::new();
    let mut c = texte.chars().peekable();
    while let Some(&x) = c.peek() {
        if x == ' ' || x == '\t' {
            c.next();
            continue;
        }
        if x == '#' {
            break;
        }
        let mut guillemet = None;
        let mut mot = String::new();
        while let Some(x) = c.next() {
            match (x, guillemet) {
                ('\\', _) => match c.peek() {
                    Some(&n) if matches!(n, '\'' | '"' | '\\') || (n == ' ' && guillemet.is_none()) => {
                        mot.push(n);
                        c.next();
                    }
                    _ => mot.push('\\'),
                },
                (' ' | '\t', None) => break,
                ('"' | '\'', None) => guillemet = Some(x),
                (_, Some(g)) if x == g => guillemet = None,
                _ => mot.push(x),
            }
        }
        if guillemet.is_some() || mot.is_empty() {
            return None;
        }
        mots.push(mot);
    }
    (!mots.is_empty()).then_some(mots)
}

/// Un motif d'hôte qui PEUT couvrir des serveurs qu'il ne nomme pas : un « * » et ni lettre ni chiffre (« * », « ** »,
/// « ?* », « *.* », « *_* »). Borne haute, voulue large : « *.exemple.org » nomme un domaine, il est précis. Jamais
/// sous une négation, où exagérer « couvre tout » voudrait dire « ne s'applique jamais » (`couvre_tout`).
fn peut_couvrir_tout(motif: &str) -> bool {
    motif.contains('*') && !motif.chars().any(char::is_alphanumeric)
}

/// Un motif d'hôte qui couvre tout nom à coup sûr : des « * » et au plus un « ? » (« ?? » refuse un nom d'un
/// caractère). Borne basse, seule permise sous une négation.
fn couvre_tout(motif: &str) -> bool {
    motif.contains('*') && motif.chars().all(|c| c == '*' || c == '?') && motif.matches('?').count() <= 1
}

/// La portée d'un « Host » : SSH l'applique si un motif couvre l'hôte et qu'aucun motif nié (« !x ») ne le couvre.
fn etendue_host(motifs: &[String]) -> Etendue {
    let (nies, positifs): (Vec<&str>, Vec<&str>) = motifs.iter().map(String::as_str).partition(|m| m.starts_with('!'));
    let nies: Vec<&str> = nies.iter().map(|m| m.get(1..).unwrap_or_default()).collect();
    if nies.iter().any(|m| couvre_tout(m)) {
        // Nié pour tout hôte : jamais appliqué.
        Etendue::Precise
    } else if nies.is_empty() && positifs.iter().any(|m| couvre_tout(m)) {
        Etendue::Globale
    } else if positifs.iter().any(|m| peut_couvrir_tout(m)) {
        Etendue::PeutEtre
    } else {
        Etendue::Precise
    }
}

/// Le plus long motif que `match_pattern_list` (match.c d'OpenSSH) compare : il recopie chaque motif, son « ! » retiré,
/// dans un tampon de 1024 octets, et rend « aucune correspondance » pour TOUTE la liste dès qu'un motif atteint 1023
/// octets, même si un autre motif de la liste couvre tout (mesuré avec `ssh -G` 10.6 : 1022 passe, 1023 non). « Host »
/// n'a pas cette borne (`match_pattern`, sans tampon : 5 000 octets mesurés).
const MOTIF_LISTE_MAX: usize = 1022;

/// La portée du critère « host » ou « originalhost » d'un « Match », sa liste séparée par des virgules
/// (`match_pattern_list` : vrai si un motif couvre l'hôte et qu'aucun motif nié ne le couvre), « !host » s'il est nié.
fn etendue_liste(liste: &str, nie: bool) -> Etendue {
    // Au-delà de la borne de SSH, la liste ne correspond à rien : bloc jamais appliqué, ou toujours sous « !host ».
    // Cette borne tient à un tampon d'OpenSSH, pas à sa documentation : « peut-être » dans les deux sens, jamais une
    // portée tenue pour sûre (vérification de Fable n° 3, N1 : un joker voisin faisait croire « global à coup sûr »).
    if liste
        .split(',')
        .any(|m| m.strip_prefix('!').unwrap_or(m).len() > MOTIF_LISTE_MAX)
    {
        return Etendue::PeutEtre;
    }
    let (nies, positifs): (Vec<&str>, Vec<&str>) = liste.split(',').partition(|m| m.starts_with('!'));
    let nies: Vec<&str> = nies.iter().map(|m| m.get(1..).unwrap_or_default()).collect();
    let toujours = nies.is_empty() && positifs.iter().any(|m| couvre_tout(m));
    let jamais = nies.iter().any(|m| couvre_tout(m)) || !positifs.iter().any(|m| peut_couvrir_tout(m));
    match (nie, toujours, jamais) {
        (false, true, _) => Etendue::Globale,
        (false, false, true) | (true, true, _) => Etendue::Precise,
        // « !host » vaut pour tout hôte que la liste ne couvre pas : peut-être tous, même si la liste nomme un
        // hôte (seule une liste qui couvre tout à coup sûr rend la négation précise).
        _ => Etendue::PeutEtre,
    }
}

/// La portée d'un « Match » : les critères se cumulent (ET), la plus petite l'emporte. « all » seul : globale ; « !all »
/// jamais vrai ; « host » et « originalhost » selon leur liste (`etendue_liste`) ; « canonical », « final » et les
/// critères qui ne regardent pas l'hôte (user, exec…) : peut-être, puisque SSH peut ne pas l'appliquer. Critère
/// inconnu, argument manquant, vide ou commençant par « # », « all » suivi d'autre chose ou après plus d'un critère
/// (SSH refuse alors le fichier) : `None` (non interprété). `match_cfg_line` (readconf.c) d'OpenSSH 10.6.
fn etendue_match(mots: &[String]) -> Option<Etendue> {
    let mut etendue = Etendue::Globale;
    let mut criteres = 0_usize;
    let mut i = mots.iter();
    while let Some(mot) = i.next() {
        let (nie, critere) = mot.strip_prefix('!').map_or((false, mot.as_str()), |c| (true, c));
        // « host=* » : la valeur collée par un « = », pour les seuls critères qu'OpenSSH 10.0 et plus lit ainsi
        // (vérification de Fable n° 3, N5). Avant 10.0, SSH refuse tout le fichier (« Unsupported Match attribute ») :
        // lire comme 10.6 ne fait jamais croire appliqué un bloc d'un SSH qui, lui, ne se lance plus.
        let (nom, colle) = match critere.split_once('=') {
            Some((nom, valeur)) if CRITERES_A_EGAL.iter().any(|c| nom.eq_ignore_ascii_case(c)) => (nom, Some(valeur)),
            _ => (critere, None),
        };
        let nom = nom.to_ascii_lowercase();
        if nom == "all" {
            if criteres > 1 || i.next().is_some() {
                return None;
            }
            etendue = etendue.min(if nie { Etendue::Precise } else { Etendue::Globale });
            continue;
        }
        criteres = criteres.saturating_add(1);
        if matches!(nom.as_str(), "canonical" | "final") {
            etendue = etendue.min(Etendue::PeutEtre);
            continue;
        }
        let valeur = match colle {
            Some(v) => v,
            None => i.next()?,
        };
        // SSH refuse une valeur vide (sauf pour « tagged » et « command ») ou qui commence par « # ».
        if valeur.starts_with('#') || (valeur.is_empty() && !matches!(nom.as_str(), "tagged" | "command")) {
            return None;
        }
        let e = match nom.as_str() {
            "host" | "originalhost" => etendue_liste(valeur, nie),
            "user" | "localuser" | "exec" | "localnetwork" | "tagged" | "command" | "version" | "sessiontype" => {
                Etendue::PeutEtre
            }
            _ => return None,
        };
        etendue = etendue.min(e);
    }
    Some(etendue)
}

/// Les critères d'un « Match » qu'OpenSSH 10.0 et plus accepte aussi écrits « critère=valeur » (`strprefix` de
/// `match_cfg_line`) ; pas « sessiontype », ni ceux sans valeur (« all », « canonical », « final »).
const CRITERES_A_EGAL: [&str; 9] = [
    "host",
    "originalhost",
    "user",
    "localuser",
    "localnetwork",
    "version",
    "tagged",
    "command",
    "exec",
];

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

/// La portée en cours d'une configuration lue dans l'ordre : pour qui valent les lignes ?
pub(crate) struct Portee {
    etendue: Etendue,
    /// Dans un fichier inclus, la portée de l'« Include » : rien n'y vaut pour plus de serveurs (SSH lit un fichier
    /// inclus sous un « Host » précis en « jamais vrai »).
    plafond: Etendue,
    pile: Vec<(Etendue, Etendue)>,
}

impl Portee {
    /// Au début d'un fichier de tête : tout vaut pour tous les serveurs.
    pub(crate) fn nouvelle() -> Self {
        Portee {
            etendue: Etendue::Globale,
            plafond: Etendue::Globale,
            pile: Vec::new(),
        }
    }

    pub(crate) fn etendue(&self) -> Etendue {
        self.etendue
    }

    /// Une ligne lue : rend ce qu'elle est, après avoir suivi la portée. Une ligne non interprétée qui pourrait être
    /// un « Host » ou un « Match » rend la suite « peut-être globale » : un réglage relâché y est signalé, et une
    /// valeur qui s'y trouve ne passe jamais pour celle de tous les serveurs.
    pub(crate) fn lire<'a>(&mut self, lue: &'a Lue) -> Option<(&'a str, usize, Ligne<'a>)> {
        match lue {
            Lue::Entree => {
                self.pile.push((self.etendue, self.plafond));
                self.plafond = self.etendue;
                None
            }
            Lue::Sortie => {
                if let Some((etendue, plafond)) = self.pile.pop() {
                    self.etendue = etendue;
                    self.plafond = plafond;
                }
                None
            }
            Lue::Ligne(fichier, n, texte) => {
                let l = lire_ligne(texte);
                match l {
                    Ligne::Portee(e) => self.etendue = self.plafond.min(e),
                    Ligne::NonInterpretee if peut_etre_portee(texte) => {
                        self.etendue = self.plafond.min(Etendue::PeutEtre);
                    }
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
            ("Host # rien", NonInterpretee),
        ] {
            assert_eq!(lire_ligne(ligne), attendu, "{ligne:?}");
        }
    }

    /// Trois états : globale à coup sûr, peut-être (SSH peut ne pas l'appliquer), précise. Vérification de Fable
    /// n° 2 : P1 (en-têtes « dans le doute » qui ne sont plus « globale »), P2 (négation : seul un motif qui couvre tout
    /// à coup sûr la rend précise), P6 (apostrophes et échappements lus comme `argv_split`).
    #[test]
    fn portees_comme_ssh() {
        use Etendue::{Globale as G, PeutEtre as P, Precise as X};
        for (ligne, etendue) in [
            ("Host *", Some(G)),
            ("Host \"*\"", Some(G)),
            ("Host '*'", Some(G)),
            ("Host **", Some(G)),
            ("Host ?*", Some(G)),
            ("Host *?", Some(G)),
            ("Host labo *", Some(G)),
            ("Host 'labo 2' *", Some(G)),
            ("Host \\\"labo\\\" *", Some(G)),
            ("Host * # commentaire", Some(G)),
            ("Host *.*", Some(P)),
            ("Host ??*", Some(P)),
            ("Host *_*", Some(P)),
            ("Host * !labo", Some(P)),
            ("Host * !*_*", Some(P)),
            ("Host * !??*", Some(P)),
            ("Host labo", Some(X)),
            ("Host 'labo'", Some(X)),
            ("Host labo#2", Some(X)),
            ("Host *.exemple.org", Some(X)),
            ("Host !*", Some(X)),
            ("Host ???", Some(X)),
            ("Host *,labo", Some(X)),
            ("Host * !*", Some(X)),
            ("Host * !?*", Some(X)),
            ("Match all", Some(G)),
            ("Match all # x", Some(G)),
            ("Match host *", Some(G)),
            ("Match originalhost ?*", Some(G)),
            ("MATCH Host labo,*", Some(G)),
            ("Match final all", Some(P)),
            ("Match canonical all # x", Some(P)),
            ("Match final", Some(P)),
            ("Match canonical", Some(P)),
            ("Match host *,!labo", Some(P)),
            ("Match host *.*", Some(P)),
            ("Match !host labo", Some(P)),
            ("Match exec \"test -f /x\"", Some(P)),
            ("Match exec 'test -f /x'", Some(P)),
            ("Match exec \"test \\\"x\\\"\"", Some(P)),
            ("Match exec test\\ -f\\ /x", Some(P)),
            ("Match !exec true", Some(P)),
            ("Match user alice", Some(P)),
            ("Match localuser alice", Some(P)),
            ("Match tagged essai", Some(P)),
            ("Match localnetwork 192.0.2.0/24", Some(P)),
            ("Match command uptime", Some(P)),
            ("Match version OpenSSH_10*", Some(P)),
            ("Match sessiontype shell", Some(P)),
            ("Match host * user alice", Some(P)),
            // P2 : sous une négation, un motif « presque universel » ne couvre pas tout hôte.
            ("Match !host *_*", Some(P)),
            ("Match !host *-*", Some(P)),
            ("Match !host *.*", Some(P)),
            ("Match !host *é*", Some(P)),
            ("Match !host ??*", Some(P)),
            ("Match !originalhost *_*", Some(P)),
            ("Match !host labo,*_*", Some(P)),
            ("Match !host *,!labo", Some(P)),
            ("Match host labo exec \"nc -z %h 22\"", Some(X)),
            ("Match originalhost labo", Some(X)),
            ("Match host *é*", Some(X)),
            ("Match host *,!*", Some(X)),
            ("Match !host *", Some(X)),
            ("Match !host ?*", Some(X)),
            ("Match !originalhost labo,**", Some(X)),
            ("Match !all", Some(X)),
            ("Match host labo all", Some(X)),
            ("Match all host labo", None),
            ("Match host", None),
            ("Match host a user b all", None),
            ("Match host labo user bob", Some(X)),
            ("Match inconnu x", None),
            ("Match exec \"test", None),
            ("Match exec ''", None),
            ("Host ''", None),
            ("Host a ''", None),
            ("Host 'a", None),
            ("Host *\u{b}x", None),
        ] {
            let attendu = etendue.map_or(Ligne::NonInterpretee, Ligne::Portee);
            assert_eq!(lire_ligne(ligne), attendu, "{ligne:?}");
        }
    }

    /// Vérification de Fable n° 3, N5 : « critère=valeur », comme OpenSSH 10.0 et plus le lit (`ssh -G` 10.6) ;
    /// seulement pour les critères qu'il accepte ainsi, jamais vide (sauf « tagged » et « command ») ni « # ».
    #[test]
    fn criteres_a_egal_comme_openssh_10() {
        use Etendue::{Globale as G, PeutEtre as P, Precise as X};
        for (ligne, etendue) in [
            ("Match host=*", Some(G)),
            ("Match HOST=*", Some(G)),
            ("Match 'host=*'", Some(G)),
            ("Match host=\"*\"", Some(G)),
            ("Match originalhost=*", Some(G)),
            ("Match host=* all", Some(G)),
            ("Match host=*,labo", Some(G)),
            ("Match !host=*", Some(X)),
            ("Match host=serveur", Some(X)),
            ("Match !host=*,!x", Some(P)),
            ("Match host=*,!serveur", Some(P)),
            ("Match !host=autre", Some(P)),
            ("Match host==*", Some(P)),
            ("Match host=*  user=bob", Some(P)),
            ("Match user=bob", Some(P)),
            ("Match exec=true", Some(P)),
            ("Match tagged=", Some(P)),
            ("Match command=", Some(P)),
            ("Match version=OpenSSH_10*", Some(P)),
            ("Match host=", None),
            ("Match host= *", None),
            ("Match host=#x", None),
            ("Match host '#x'", None),
            ("Match user=", None),
            ("Match all=x", None),
            ("Match canonical=x", None),
            ("Match final=x", None),
            ("Match sessiontype=shell", None),
            ("Match inconnu=x", None),
        ] {
            let attendu = etendue.map_or(Ligne::NonInterpretee, Ligne::Portee);
            assert_eq!(lire_ligne(ligne), attendu, "{ligne:?}");
        }
    }

    /// Vérification de Fable n° 3, N1 : `match_pattern_list` ne compare plus rien au-delà de 1022 octets par motif
    /// (« ! » non compté) ; « Host » n'a pas cette borne. 1022 : la liste est lue ; 1023 : « peut-être », dans
    /// chaque sens, pour « host » et « originalhost ». Les mêmes formes sont jugées par `ssh -G` dans
    /// `tests/programme.rs` (`un_motif_trop_long_ne_rend_pas_la_portee_sure`).
    #[test]
    fn motif_au_dela_de_la_borne_de_ssh() {
        use Etendue::{Globale as G, PeutEtre as P, Precise as X};
        let a = |n: usize| "a".repeat(n);
        for critere in ["host", "originalhost"] {
            for (n, positif, nie) in [(1022, G, X), (1023, P, P), (5000, P, P)] {
                let long = a(n);
                for (ligne, attendu) in [
                    (format!("Match {critere} *,{long}"), positif),
                    (format!("Match {critere} {long},*"), positif),
                    (format!("Match !{critere} *,{long}"), nie),
                    (format!("Match {critere}=*,{long}"), positif),
                    (format!("Match !{critere}=*,{long}"), nie),
                ] {
                    assert_eq!(lire_ligne(&ligne), Ligne::Portee(attendu), "{critere} {n}");
                }
            }
            // Le « ! » ne compte pas : 1022 octets après lui restent lus.
            let nie_1022 = format!("Match {critere} *,!{}", a(1022));
            assert_eq!(lire_ligne(&nie_1022), Ligne::Portee(P));
            let tout_nie = format!("Match {critere} *,!*,{}", a(1022));
            assert_eq!(lire_ligne(&tout_nie), Ligne::Portee(X));
            let tout_nie_long = format!("Match {critere} *,!*,{}", a(1023));
            assert_eq!(lire_ligne(&tout_nie_long), Ligne::Portee(P));
        }
        // Octets, pas caractères : 511 « é » font 1022 octets, 512 en font 1024.
        assert_eq!(
            lire_ligne(&format!("Match host *,{}", "é".repeat(511))),
            Ligne::Portee(G)
        );
        assert_eq!(
            lire_ligne(&format!("Match host *,{}", "é".repeat(512))),
            Ligne::Portee(P)
        );
        // « Host » compare chaque motif sans tampon : un motif long n'y change rien.
        assert_eq!(lire_ligne(&format!("Host * {}", a(5000))), Ligne::Portee(G));
        assert_eq!(lire_ligne(&format!("Host * !{}", a(5000))), Ligne::Portee(P));
        assert_eq!(lire_ligne(&format!("Host {}", "*".repeat(5000))), Ligne::Portee(G));
    }

    /// Vérification de Fable n° 3, N2 : une liste KexAlgorithms trop longue pour être jugée est dite « non lu »,
    /// jamais comparée (une entrée de 500 000 « * » faisait planter Vanguard).
    #[test]
    fn liste_kex_trop_longue_non_lue() {
        let etoiles = |n: usize| "*".repeat(n);
        let juge = |v: &str| {
            let ligne = format!("KexAlgorithms {v}");
            let lue = lire_ligne(&ligne);
            assert!(
                matches!(lue, Ligne::Valeur(Cle::KexAlgorithms, _) | Ligne::NonInterpretee),
                "{lue:?}"
            );
            lue != Ligne::NonInterpretee
        };
        assert!(juge(&format!("-{}", etoiles(1022))));
        assert!(juge(&format!("-a,{}", etoiles(1022))));
        assert!(!juge(&format!("-{}", etoiles(1023))));
        assert!(!juge(&format!("-a,{}", etoiles(1023))));
        assert!(!juge(&format!("-{}", etoiles(500_000))));
        // Des entrées courtes : seule la longueur de la liste compte (4 096 octets au plus).
        assert!(juge(&"a,".repeat(2048)));
        assert!(!juge(&format!("{}a", "a,".repeat(2048))));
        assert!(!juge(&etoiles(1023)));
    }

    /// Le découpage de `argv_split` (misc.c), mot pour mot.
    #[test]
    fn en_tete_decoupe_comme_argv_split() {
        for (texte, attendu) in [
            ("a b\tc", Some(vec!["a", "b", "c"])),
            ("'a b' \"c d\"", Some(vec!["a b", "c d"])),
            ("a'b c'd", Some(vec!["ab cd"])),
            ("\"it's\"", Some(vec!["it's"])),
            ("a\\ b", Some(vec!["a b"])),
            ("\"a\\ b\"", Some(vec!["a\\ b"])),
            ("\\'x\\' \\\\ \\z", Some(vec!["'x'", "\\", "\\z"])),
            ("a#b # c", Some(vec!["a#b"])),
            ("'#a'", Some(vec!["#a"])),
            ("x\\", Some(vec!["x\\"])),
            ("# rien", None),
            ("\"a", None),
            ("a ''", None),
        ] {
            let attendu = attendu.map(|v| v.into_iter().map(String::from).collect::<Vec<_>>());
            assert_eq!(en_tete(texte), attendu, "{texte:?}");
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
        use Etendue::{Globale as G, PeutEtre as P, Precise as X};
        let l = |t: &str| Lue::Ligne("f".into(), 1, t.into());
        let etendues = |lignes: &[Lue]| -> Vec<Etendue> {
            let mut p = Portee::nouvelle();
            lignes.iter().filter_map(|x| p.lire(x).map(|_| p.etendue())).collect()
        };
        let apres_inclus = [Lue::Entree, l("Host labo"), Lue::Sortie, l("ForwardAgent yes")];
        assert_eq!(etendues(&apres_inclus), [X, G]);
        let sous_host = [
            l("Host labo"),
            Lue::Entree,
            l("ForwardAgent yes"),
            l("Host *"),
            l("ForwardAgent yes"),
            Lue::Sortie,
            l("ForwardAgent yes"),
        ];
        assert_eq!(etendues(&sous_host), [X, X, X, X, X]);
        // Sous un en-tête « peut-être », un « Host * » inclus ne devient pas globale à coup sûr ; après, si.
        let sous_doute = [
            l("Match user bob"),
            Lue::Entree,
            l("Host *"),
            Lue::Sortie,
            l("KexAlgorithms x"),
            l("Host *"),
        ];
        assert_eq!(etendues(&sous_doute), [P, P, P, G]);
        let doute = [l("Host labo"), l("\"Host\" labo"), l("ForwardAgent yes")];
        assert_eq!(etendues(&doute), [X, P, P]);
        let autre_doute = [l("Host labo"), l("ForwardAgent 'no'"), l("ForwardAgent yes")];
        assert_eq!(etendues(&autre_doute), [X, X, X]);
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

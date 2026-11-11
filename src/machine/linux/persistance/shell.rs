//! Une ligne de shell coupée comme la coupe `/bin/sh -c` (Hyprland passe ses « exec » au shell ; relecture adverse 2,
//! N1) : chaque commande simple, ses mots aux guillemets ôtés, ses entrées redirigées, et ce que Vanguard ne sait pas
//! ramener à un texte fixe (variable, joker, `~nom`, `$'…'`). Les commandes de « $( … ) », des accents graves et de
//! « <( … ) » se lisent aussi, comme des commandes de la ligne. Pas un shell : ce qui ne se coupe pas sûrement
//! (guillemet non fermé, « << », « ;; ») est refusé, jamais deviné.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

/// Ce qu'un mot garde d'inconnu une fois lu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Flou {
    /// Un texte fixe (« $HOME » gardé tel quel : le shell le connaît, Vanguard le lit comme « ~ »).
    Aucun,
    /// Sa valeur ne se connaît qu'au lancement : variable, « $( … ) », accents graves, arithmétique.
    Variable,
    /// Une écriture que Vanguard ne développe pas : joker (« * », « ? », « [ »), accolades, « ~nom », « $'…' ».
    Ecriture,
}

/// Un mot d'une commande simple, guillemets et échappements ôtés.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Mot {
    pub(super) texte: String,
    pub(super) flou: Flou,
}

/// Une commande simple : ses mots (affectations en tête comprises) et ses entrées redirigées (« < f », « <<< mot »).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct Simple {
    pub(super) mots: Vec<Mot>,
    pub(super) entrees: Vec<Mot>,
}

/// Au plus autant de « $( … ) » l'un dans l'autre.
const PROFONDEUR_MAX: u32 = 8;

/// Les commandes simples de `ligne`, dans l'ordre, celles des substitutions comprises ; `Err` si elle ne se coupe
/// pas sûrement.
pub(super) fn commandes(ligne: &str) -> Result<Vec<Simple>, ()> {
    let c: Vec<char> = ligne.chars().collect();
    let mut sortie = Vec::new();
    lire(&c, 0, &mut sortie)?;
    Ok(sortie)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Redirection {
    Entree,
    Sortie,
}

/// Le mot en cours de lecture.
struct EnCours {
    texte: String,
    flou: Flou,
    commence: bool,
}

impl EnCours {
    fn nouveau() -> Self {
        Self {
            texte: String::new(),
            flou: Flou::Aucun,
            commence: false,
        }
    }

    fn marquer(&mut self, f: Flou) {
        // Une écriture inconnue l'emporte sur une variable : elle change même le chemin.
        if self.flou != Flou::Ecriture {
            self.flou = f;
        }
        self.commence = true;
    }
}

/// Où se ferme le groupe ouvert juste avant `i` par `ouvre` (« ( » de « $( », « { » de « ${ »), guillemets et
/// groupes imbriqués compris : l'indice du caractère fermant.
fn fermeture(c: &[char], mut i: usize, ouvre: char, ferme: char) -> Result<usize, ()> {
    let mut niveau = 1_u32;
    while let Some(&x) = c.get(i) {
        match x {
            '\\' => i = i.saturating_add(1),
            '\'' => {
                i = i.saturating_add(1);
                while c.get(i).is_some_and(|y| *y != '\'') {
                    i = i.saturating_add(1);
                }
                c.get(i).ok_or(())?;
            }
            '"' => {
                i = i.saturating_add(1);
                while let Some(&y) = c.get(i) {
                    if y == '\\' {
                        i = i.saturating_add(1);
                    } else if y == '"' {
                        break;
                    }
                    i = i.saturating_add(1);
                }
                c.get(i).ok_or(())?;
            }
            _ if x == ouvre => niveau = niveau.saturating_add(1),
            _ if x == ferme => {
                niveau = niveau.saturating_sub(1);
                if niveau == 0 {
                    return Ok(i);
                }
            }
            _ => {}
        }
        i = i.saturating_add(1);
    }
    Err(())
}

/// Lit les commandes de `c` dans `sortie` ; `profondeur` : combien de substitutions l'entourent.
#[allow(clippy::too_many_lines)]
fn lire(c: &[char], profondeur: u32, sortie: &mut Vec<Simple>) -> Result<(), ()> {
    if profondeur > PROFONDEUR_MAX {
        return Err(());
    }
    let mut simple = Simple::default();
    let mut mot = EnCours::nouveau();
    let mut attente: Option<Redirection> = None;
    let mut internes: Vec<Simple> = Vec::new();
    let mut i = 0_usize;
    // Un mot fini va dans la commande, ou est la cible de la redirection en attente.
    let finir_mot = |mot: &mut EnCours, simple: &mut Simple, attente: &mut Option<Redirection>| {
        if !mot.commence {
            return;
        }
        let fini = Mot {
            texte: std::mem::take(&mut mot.texte),
            flou: mot.flou,
        };
        *mot = EnCours::nouveau();
        match attente.take() {
            Some(Redirection::Entree) => simple.entrees.push(fini),
            Some(Redirection::Sortie) => {}
            None => simple.mots.push(fini),
        }
    };
    let finir_commande = |simple: &mut Simple, sortie: &mut Vec<Simple>| {
        let s = std::mem::take(simple);
        if !s.mots.is_empty() || !s.entrees.is_empty() {
            sortie.push(s);
        }
    };
    while let Some(&x) = c.get(i) {
        let suivant = c.get(i.saturating_add(1)).copied();
        match x {
            '#' if !mot.commence => {
                while c.get(i).is_some_and(|y| *y != '\n') {
                    i = i.saturating_add(1);
                }
                continue;
            }
            ' ' | '\t' => finir_mot(&mut mot, &mut simple, &mut attente),
            '\n' | ';' | '&' | '|' | '(' | ')' => {
                if x == '&' && suivant == Some('>') {
                    // « &> » et « &>> » : la sortie et les erreurs vers un fichier.
                    finir_mot(&mut mot, &mut simple, &mut attente);
                    attente = Some(Redirection::Sortie);
                    i = i.saturating_add(if c.get(i.saturating_add(2)) == Some(&'>') { 3 } else { 2 });
                    continue;
                }
                if x == ';' && suivant == Some(';') {
                    return Err(());
                }
                finir_mot(&mut mot, &mut simple, &mut attente);
                if attente.is_some() {
                    return Err(());
                }
                finir_commande(&mut simple, sortie);
                if (x == '&' || x == '|') && suivant == Some(x) {
                    i = i.saturating_add(1);
                }
            }
            '<' | '>' => {
                // Un mot fait de chiffres juste avant est un numéro de descripteur (« 2>&1 »).
                if mot.commence && mot.flou == Flou::Aucun && mot.texte.chars().all(|d| d.is_ascii_digit()) {
                    mot = EnCours::nouveau();
                } else {
                    finir_mot(&mut mot, &mut simple, &mut attente);
                }
                if attente.is_some() {
                    return Err(());
                }
                if suivant == Some('(') {
                    // « <( … ) », « >( … ) » : une commande de plus, et un mot dont la valeur est inconnue.
                    let fin = fermeture(c, i.saturating_add(2), '(', ')')?;
                    lire(
                        c.get(i.saturating_add(2)..fin).ok_or(())?,
                        profondeur.saturating_add(1),
                        &mut internes,
                    )?;
                    mot.marquer(Flou::Variable);
                    i = fin.saturating_add(1);
                    continue;
                }
                let mut j = i.saturating_add(1);
                let genre = if x == '<' {
                    match c.get(j) {
                        Some('<') if c.get(j.saturating_add(1)) == Some(&'<') => {
                            j = j.saturating_add(2);
                            Redirection::Entree
                        }
                        // « << » : un document en ligne, sur les lignes suivantes : pas dans une valeur d'une ligne.
                        Some('<') => return Err(()),
                        Some('>' | '&') => {
                            j = j.saturating_add(1);
                            Redirection::Entree
                        }
                        _ => Redirection::Entree,
                    }
                } else {
                    if matches!(c.get(j), Some('>' | '|' | '&')) {
                        j = j.saturating_add(1);
                    }
                    Redirection::Sortie
                };
                attente = Some(genre);
                i = j;
                continue;
            }
            '\'' => {
                mot.commence = true;
                i = i.saturating_add(1);
                while let Some(&y) = c.get(i).filter(|y| **y != '\'') {
                    mot.texte.push(y);
                    i = i.saturating_add(1);
                }
                c.get(i).ok_or(())?;
            }
            '"' => {
                mot.commence = true;
                i = i.saturating_add(1);
                loop {
                    let y = *c.get(i).ok_or(())?;
                    match y {
                        '"' => break,
                        '\\' => {
                            let e = *c.get(i.saturating_add(1)).ok_or(())?;
                            if matches!(e, '$' | '`' | '"' | '\\') {
                                mot.texte.push(e);
                            } else if e != '\n' {
                                mot.texte.push('\\');
                                mot.texte.push(e);
                            }
                            i = i.saturating_add(2);
                        }
                        '$' | '`' => i = expansion(c, i, profondeur, &mut mot, &mut internes)?,
                        _ => {
                            mot.texte.push(y);
                            i = i.saturating_add(1);
                        }
                    }
                }
            }
            '\\' => {
                match suivant {
                    Some('\n') => {}
                    Some(e) => {
                        mot.commence = true;
                        mot.texte.push(e);
                    }
                    None => return Err(()),
                }
                i = i.saturating_add(2);
                continue;
            }
            '$' | '`' => {
                if x == '$' && suivant == Some('\'') {
                    // « $'…' » : des échappements ANSI-C, non décodés ici.
                    mot.marquer(Flou::Ecriture);
                    i = i.saturating_add(2);
                    while let Some(&y) = c.get(i).filter(|y| **y != '\'') {
                        i = i.saturating_add(if y == '\\' { 2 } else { 1 });
                    }
                    c.get(i).ok_or(())?;
                } else {
                    i = expansion(c, i, profondeur, &mut mot, &mut internes)?;
                    continue;
                }
            }
            '{' | '}' if !mot.commence && suivant.is_none_or(|s| matches!(s, ' ' | '\t' | '\n' | ';')) => {
                // « { » et « } » seuls : un groupe, comme un séparateur.
                finir_commande(&mut simple, sortie);
            }
            '~' if !mot.commence => {
                // « ~ » et « ~/… » : le dossier personnel ; « ~nom » : celui d'un autre compte, non développé.
                mot.commence = true;
                mot.texte.push('~');
                if suivant.is_some_and(|s| !matches!(s, '/' | ' ' | '\t' | '\n' | ';' | '&' | '|' | ')')) {
                    mot.marquer(Flou::Ecriture);
                }
            }
            '*' | '?' | '[' | '{' => {
                mot.texte.push(x);
                mot.commence = true;
                // Un joker ou des accolades ne changent un chemin que dans un mot qui en est un.
                let chemin = mot.texte.starts_with(['/', '~', '.']) || mot.texte.starts_with("$HOME");
                if chemin || (x == '{' && c.get(i..).is_some_and(|r| r.contains(&'}'))) {
                    mot.marquer(Flou::Ecriture);
                }
            }
            _ => {
                mot.commence = true;
                mot.texte.push(x);
            }
        }
        i = i.saturating_add(1);
    }
    finir_mot(&mut mot, &mut simple, &mut attente);
    if attente.is_some() {
        return Err(());
    }
    finir_commande(&mut simple, sortie);
    sortie.append(&mut internes);
    Ok(())
}

/// Lit l'expansion qui commence en `i` (« $nom », « ${…} », « $( … ) », « $(( … )) », accents graves) dans `mot`,
/// les commandes des substitutions dans `internes` ; rend où reprendre.
fn expansion(
    c: &[char],
    i: usize,
    profondeur: u32,
    mot: &mut EnCours,
    internes: &mut Vec<Simple>,
) -> Result<usize, ()> {
    let suivant = c.get(i.saturating_add(1)).copied();
    if c.get(i) == Some(&'`') {
        let mut j = i.saturating_add(1);
        let mut dedans = String::new();
        loop {
            let y = *c.get(j).ok_or(())?;
            if y == '`' {
                break;
            }
            if y == '\\' && matches!(c.get(j.saturating_add(1)), Some('`' | '\\' | '$')) {
                j = j.saturating_add(1);
            }
            dedans.push(*c.get(j).ok_or(())?);
            j = j.saturating_add(1);
        }
        let interieur: Vec<char> = dedans.chars().collect();
        lire(&interieur, profondeur.saturating_add(1), internes)?;
        mot.marquer(Flou::Variable);
        return Ok(j.saturating_add(1));
    }
    match suivant {
        Some('(') => {
            let fin = fermeture(c, i.saturating_add(2), '(', ')')?;
            let dedans = c.get(i.saturating_add(2)..fin).ok_or(())?;
            // « $(( … )) » : un calcul ; ses « $( ) » se lisent aussi.
            let calcul = dedans.first() == Some(&'(') && dedans.last() == Some(&')');
            let a_lire = if calcul {
                dedans.get(1..dedans.len().saturating_sub(1)).unwrap_or_default()
            } else {
                dedans
            };
            if !calcul || a_lire.contains(&'$') || a_lire.contains(&'`') {
                lire(a_lire, profondeur.saturating_add(1), internes)?;
            }
            mot.marquer(Flou::Variable);
            Ok(fin.saturating_add(1))
        }
        Some('{') => {
            let fin = fermeture(c, i.saturating_add(2), '{', '}')?;
            let nom: String = c.get(i.saturating_add(2)..fin).ok_or(())?.iter().collect();
            if nom == "HOME" {
                mot.texte.push_str("$HOME");
                mot.commence = true;
            } else {
                if nom.contains(['$', '`']) {
                    // « ${A:-$(…)} » : la commande se lit.
                    let dedans: Vec<char> = nom.chars().skip_while(|x| *x != '$' && *x != '`').collect();
                    lire(&dedans, profondeur.saturating_add(1), internes)?;
                }
                mot.marquer(Flou::Variable);
            }
            Ok(fin.saturating_add(1))
        }
        Some(s) if s.is_ascii_alphabetic() || s == '_' => {
            let nom: String = c
                .get(i.saturating_add(1)..)
                .unwrap_or_default()
                .iter()
                .take_while(|x| x.is_ascii_alphanumeric() || **x == '_')
                .collect();
            if nom == "HOME" {
                mot.texte.push_str("$HOME");
                mot.commence = true;
            } else {
                mot.marquer(Flou::Variable);
            }
            Ok(i.saturating_add(1).saturating_add(nom.len()))
        }
        Some(s) if s.is_ascii_digit() || matches!(s, '@' | '*' | '#' | '?' | '$' | '!' | '-') => {
            mot.marquer(Flou::Variable);
            Ok(i.saturating_add(2))
        }
        _ => {
            // Un « $ » seul se lit tel quel.
            mot.texte.push('$');
            mot.commence = true;
            Ok(i.saturating_add(1))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mots(ligne: &str) -> Vec<Vec<String>> {
        commandes(ligne)
            .expect(ligne)
            .into_iter()
            .map(|s| s.mots.into_iter().map(|m| m.texte).collect())
            .collect()
    }

    #[test]
    fn coupee_comme_le_shell() {
        assert_eq!(
            mots("sleep 2 && /tmp/.x/a"),
            vec![vec!["sleep", "2"], vec!["/tmp/.x/a"]]
        );
        assert_eq!(mots("kitty&X"), vec![vec!["kitty"], vec!["X"]]);
        assert_eq!(mots("( X )"), vec![vec!["X"]]);
        assert_eq!(mots("{ X; }"), vec![vec!["X"]]);
        assert_eq!(mots("/tm\"\"p/.x/a"), vec![vec!["/tmp/.x/a"]]);
        assert_eq!(mots("\"$HOME\"/.x/a"), vec![vec!["$HOME/.x/a"]]);
        assert_eq!(
            mots("xsetroot -c x >/dev/null 2>&1 || true"),
            vec![vec!["xsetroot", "-c", "x"], vec!["true"]]
        );
        assert_eq!(mots("a $(b /tmp/c)"), vec![vec!["a", ""], vec!["b", "/tmp/c"]]);
        assert_eq!(mots("a `b`"), vec![vec!["a", ""], vec!["b"]]);
        let s = commandes("</tmp/.x/s sh").expect("entrée");
        assert_eq!(s.first().map(|s| s.entrees.len()), Some(1));
        assert!(commandes("echo 'a").is_err());
        assert!(commandes("cat <<FIN").is_err());
        assert!(commandes("case x in a) b;; esac").is_err());
    }

    #[test]
    fn flou_dit() {
        let premier = |l: &str| {
            commandes(l)
                .expect(l)
                .first()
                .and_then(|s| s.mots.first().map(|m| m.flou))
        };
        assert_eq!(premier("/t?p/.x/a"), Some(Flou::Ecriture));
        assert_eq!(premier("~alice/.x/a"), Some(Flou::Ecriture));
        assert_eq!(premier("~/.x/a"), Some(Flou::Aucun));
        assert_eq!(premier("$X/a"), Some(Flou::Variable));
        assert_eq!(premier("$'\\x2ftmp'/a"), Some(Flou::Ecriture));
        assert_eq!(premier("https://x.example/?a=b"), Some(Flou::Aucun));
    }
}

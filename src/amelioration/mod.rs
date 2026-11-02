//! L'auto-amélioration (plan des lots A1 à A8) : ce que Vanguard apprend de ses propres erreurs, sur l'ordinateur où
//! il tourne, sans qu'aucun secret ni rien de personnel n'en sorte. Ce lot (A1) n'en pose que la voie ouverte : les
//! textes, noms et versions venus de l'ordinateur, nettoyés par `texte`.

pub(crate) mod texte;

pub(crate) use texte::{NomLogiciel, Rejet, TexteNettoye, VersionTierce};

/// Un texte d'erreur brut, tel que l'ordinateur le donne : noms de la personne, de la machine et du réseau retirés
/// d'abord (`journal::anonymiser`, qui connaît le dossier personnel et la base des appareils), puis nettoyé. Les
/// chevrons du brut sont retirés avant : seuls l'anonymisation et le nettoyage posent des marqueurs. C'est la porte
/// d'entrée à prendre ; `TexteNettoye::nettoyer` seul laisserait passer un faux marqueur écrit dans le brut.
pub(crate) fn texte(brut: &str) -> Result<TexteNettoye, Rejet> {
    TexteNettoye::nettoyer(&crate::journal::anonymiser(&texte::sans_chevrons(brut)))
}

/// Le nom d'un logiciel, d'un service ou d'un pilote, nettoyé de la même façon.
pub(crate) fn nom(brut: &str) -> Result<NomLogiciel, Rejet> {
    NomLogiciel::nettoyer(&crate::journal::anonymiser(&texte::sans_chevrons(brut)))
}

/// La version d'un logiciel tiers. Une version que l'anonymisation changerait porte autre chose qu'une version (un
/// nom, une adresse) : refusée plutôt que réparée.
pub(crate) fn version(brut: &str) -> Result<VersionTierce, Rejet> {
    if crate::journal::anonymiser(brut) != brut {
        return Err(texte::compter(Rejet::Forme));
    }
    VersionTierce::nettoyer(brut)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymiser_puis_nettoyer() {
        let maison = std::env::var("HOME").unwrap_or_default();
        if maison.len() < 2 {
            return crate::essais::saute("dossier personnel inconnu");
        }
        let t = texte(&format!("échec de {maison}/Documents/notes.txt")).map(String::from);
        assert_eq!(t, Ok("échec de <chemin .txt>".to_string()));
        assert!(nom("Vanguard").is_ok());
        assert_eq!(version("1.2.3").map(String::from), Ok("1.2.3".to_string()));
        assert!(version(&format!("1.0-{maison}")).is_err());
    }

    #[test]
    fn faux_marqueurs_desarmes() {
        // Un message hostile qui écrit lui-même des marqueurs, en ASCII, en pleine chasse ou coupés d'un invisible.
        // Rien ici n'a l'allure d'une adresse ni d'un chemin : aucun marqueur ne doit ressortir.
        for brut in [
            "échec <url>suite banale fin",
            "échec \u{FF1C}url\u{FF1E}suite banale fin",
            "échec <\u{200B}chemin>suite banale fin",
        ] {
            let t = texte(brut).map(String::from).unwrap_or_default();
            assert!(!t.contains('<') && !t.contains('>'), "{brut:?} donne {t:?}");
            let n = nom(brut).map(String::from).unwrap_or_default();
            assert!(!n.contains('<') && !n.contains('>'), "{brut:?} donne {n:?}");
        }
    }
}

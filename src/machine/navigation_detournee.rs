//! Navigation détournée, au bilan : un proxy imposé (ou une configuration automatique de proxy) et des sites
//! redirigés par le fichier hosts font passer la navigation par un serveur choisi par quelqu'un d'autre, qui la lit
//! et peut la modifier. La vérification est celle de Réparer › Navigation détournée, qui sait aussi la corriger ; le
//! bilan la montre et y renvoie (un proxy peut être voulu, dans une entreprise).

use super::{Constat, alerte, ok};

use crate::risk::Niveau;
use crate::tr;

const CAT: &str = "Navigateur";

pub fn constat() -> Constat {
    let r = crate::reparer::navigation_ici();
    if let Some(raison) = r.inutile.as_deref().and_then(non_lu) {
        return super::impossible(CAT, raison);
    }
    juger(r.inutile.is_some(), &r.pourquoi)
}

/// Ce que « rien à faire » n'a pas pu lire : le fichier hosts (droits, disque), ou les réglages du proxy (Windows sans
/// PowerShell). Rien n'est conclu pour eux.
fn non_lu(inutile: &str) -> Option<&'static str> {
    let dit = |fr, en| inutile.contains(fr) || inutile.contains(en);
    if dit("fichier hosts non lu", "hosts file not read") {
        Some(tr!("fichier hosts illisible", "hosts file unreadable"))
    } else if dit("non lus", "not read") {
        Some(tr!("réglages du proxy illisibles", "proxy settings unreadable"))
    } else {
        None
    }
}

fn juger(rien: bool, pourquoi: &str) -> Constat {
    if rien {
        ok(
            CAT,
            tr!(
                "Navigation directe : ni proxy imposé, ni site redirigé par le fichier hosts.",
                "Direct browsing: no forced proxy, no site redirected by the hosts file."
            ),
        )
    } else {
        // « Trouvé : … » : la fin de l'explication de la réparation dit ce qui a été vu.
        let trouve = pourquoi
            .rsplit_once(tr!("Trouvé : ", "Found: "))
            .map_or(pourquoi, |(_, t)| t)
            .trim_end_matches('.');
        alerte(
            CAT,
            Niveau::Moyen,
            crate::trf!(
                "La navigation peut être détournée ({trouve}) : un serveur choisi par quelqu'un d'autre peut lire et modifier les pages. Normal seulement si vous ou votre employeur l'avez réglé.",
                "Browsing may be hijacked ({trouve}): a server chosen by someone else can read and change the pages. Normal only if you or your employer set it up."
            ),
        )
        .manuel(
            tr!(
                "Menu Dépanner pas à pas › Réparer une panne connue › Navigation détournée : il montre et défait ce qui a été trouvé",
                "Menu Step-by-step troubleshooting › Repair a known problem › Hijacked browsing: it shows and undoes what was found"
            ),
            &[],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un fichier hosts ou un proxy pas lu n'est jamais dit sain ; tout lu, c'est jugé.
    #[test]
    fn detournement_non_lu_est_dit() {
        assert_eq!(
            non_lu("aucun proxy imposé (fichier hosts non lu)"),
            Some("fichier hosts illisible")
        );
        assert_eq!(
            non_lu("fichier hosts non lu, réglages du proxy non lus"),
            Some("fichier hosts illisible")
        );
        assert_eq!(
            non_lu("aucune redirection dans le fichier hosts (réglages du proxy non lus)"),
            Some("réglages du proxy illisibles")
        );
        assert_eq!(non_lu("ni redirection dans le fichier hosts, ni proxy imposé"), None);
    }

    #[test]
    fn detournement_dit_ce_qui_a_ete_trouve() {
        assert!(juger(true, "").probleme.is_none());
        let c = juger(
            false,
            "Met en commentaire… Trouvé : proxy du bureau en mode « manual ».",
        );
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(
            c.message.contains("(proxy du bureau en mode « manual »)"),
            "{}",
            c.message
        );
    }
}

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
    // Windows sans PowerShell : le fichier hosts a été lu, pas le proxy. Rien n'est conclu pour lui.
    if r.inutile
        .as_deref()
        .is_some_and(|i| i.contains("non lus") || i.contains("not read"))
    {
        return super::impossible(CAT, tr!("réglages du proxy illisibles", "proxy settings unreadable"));
    }
    juger(r.inutile.is_some(), &r.pourquoi)
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

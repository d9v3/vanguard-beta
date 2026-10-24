//! Le résultat du diagnostic de l'ordinateur (`modele::resultat`) : le jugement de ses lignes, sans l'écran. Versé au
//! rapport (`examens/PRO-DIA-001.json`), au journal des événements, et rendu par `--json`.
//!
//! Seules les lignes qui vérifient quelque chose (erreurs du journal, programmes plantés, services en échec, écrans
//! bleus, arrêts et redémarrages brutaux, écart du dernier autotest) deviennent des constats ; le système, le modèle
//! ou la mémoire ne jugent rien et restent à l'écran. Une vérification qui n'a pas pu se faire est non vérifiée,
//! jamais « aucun ».

use super::Section;
use crate::machine::{Constat, alerte, impossible_par, ok};
use crate::modele::resultat::{Couverture, Resultat};
use crate::modele::{Objet, Raison};
use crate::risk::Niveau;
use crate::trf;

/// L'identifiant de l'outil (`modele::registre::OUTILS`).
pub(crate) const ID: &str = "PRO-DIA-001";

type Debut = (chrono::DateTime<chrono::Utc>, std::time::Instant);

/// La catégorie d'un point du diagnostic (nom interne français, traduit à l'affichage par `langue::categorie`).
fn categorie(point: &str) -> &'static str {
    match point {
        "erreurs-journal" => "Erreurs du journal",
        "plantages" => "Programmes",
        "services-en-echec" => "Services",
        "autotest" => "Autodiagnostic",
        _ => "Santé",
    }
}

/// Le résultat des sections d'un diagnostic commencé à `debut` : un constat par ligne qui vérifie quelque chose, et
/// le nombre de ces vérifications faites. Une ligne seulement informative (quelques erreurs ordinaires du journal,
/// niveau Info) est un fait, pas un problème : sinon presque chaque ordinateur sortait « probleme ». L'écran, lui,
/// la garde en couleur.
pub(super) fn resultat(sections: &[Section], debut: Debut) -> Resultat {
    let grave = |l: &super::Ligne| l.niveau.filter(|n| *n > Niveau::Info);
    let mut constats: Vec<Constat> = Vec::new();
    let mut verifies = 0u32;
    let mut non_verifies = Vec::new();
    for l in sections.iter().flat_map(|(_, lignes)| lignes) {
        let message = trf!("{} : {}", "{}: {}", l.libelle, l.valeur);
        let Some(point) = l.point else {
            // Une information qui signalerait pourtant un problème reste un problème, sans objet.
            if let Some(n) = grave(l) {
                constats.push(alerte("Santé", n, message));
            }
            continue;
        };
        let cat = categorie(point);
        let c = if l.verifie {
            verifies += 1;
            match grave(l) {
                Some(n) => alerte(cat, n, message),
                None => ok(cat, message),
            }
        } else {
            non_verifies.push(message.clone());
            impossible_par(cat, Raison::Illisible(l.valeur.clone()), message)
        };
        constats.push(c.avec_objet(Objet::de("diagnostic", point)));
    }
    Resultat::nouveau(ID, debut, &constats, Couverture { verifies, non_verifies })
}

#[cfg(test)]
mod tests {
    use super::super::{alerte, ligne, non_verifie, programmes_plantes};
    use super::*;

    fn debut() -> Debut {
        (chrono::Utc::now(), std::time::Instant::now())
    }

    #[test]
    fn rien_de_verifie_jamais_sain() {
        assert_eq!(resultat(&[], debut()).verdict(), "non-verifie");
        // Des informations seules (système, mémoire) ne vérifient rien.
        let infos: Vec<Section> = vec![("SYSTÈME".into(), vec![ligne("Nom", "portable-alice")])];
        let r = resultat(&infos, debut());
        assert_eq!(r.verdict(), "non-verifie");
        assert_eq!(r.constats, Vec::new());
        // Un journal illisible n'est jamais « aucune erreur ».
        let illisible: Vec<Section> = vec![(
            "PROBLÈMES RÉCENTS".into(),
            vec![
                programmes_plantes(&[]),
                non_verifie("Erreurs du journal", "journal illisible sans droits", "erreurs-journal"),
            ],
        )];
        let r = resultat(&illisible, debut());
        assert_eq!(r.verdict(), "non-verifie");
        assert_eq!((r.couverture.verifies, r.couverture.non_verifies.len()), (1, 1));
    }

    #[test]
    fn plantages_en_probleme() {
        // Un libellé de l'écran, pas une catégorie (relue par `langue::chaque_categorie_a_son_nom_anglais`).
        let services = "Services en échec";
        let sections: Vec<Section> = vec![(
            "PROBLÈMES RÉCENTS".into(),
            vec![
                programmes_plantes(&["firefox".into(), "firefox".into()]),
                alerte(services, "cups.service", Niveau::Moyen).juge("services-en-echec"),
            ],
        )];
        let r = resultat(&sections, debut());
        assert_eq!(r.verdict(), "probleme");
        assert_eq!(r.constats[0].objet.as_deref(), Some("diagnostic:plantages"));
        assert_eq!(r.constats[1].categorie, "Services");
        assert_eq!(r.couverture.verifies, 2);
        let sain: Vec<Section> = vec![("PROBLÈMES RÉCENTS".into(), vec![programmes_plantes(&[])])];
        assert_eq!(resultat(&sain, debut()).verdict(), "sain");
    }

    /// Quelques erreurs ordinaires du journal (niveau Info) : un fait, son message gardé, pas un problème ; au-dessus
    /// d'Info, un problème.
    #[test]
    fn information_jamais_un_probleme() {
        let erreurs = |n| alerte("Erreurs du journal", "5 depuis le démarrage : kernel (5)", n).juge("erreurs-journal");
        let r = resultat(&[("PROBLÈMES RÉCENTS".into(), vec![erreurs(Niveau::Info)])], debut());
        assert_eq!(r.verdict(), "sain");
        assert_eq!(r.constats[0].etat, "sain");
        assert!(
            r.constats[0].message.contains("kernel (5)"),
            "{}",
            r.constats[0].message
        );
        let r = resultat(&[("PROBLÈMES RÉCENTS".into(), vec![erreurs(Niveau::Moyen)])], debut());
        assert_eq!(r.verdict(), "probleme");
        // Une information sans point ne fait pas un constat, ni un problème.
        let r = resultat(
            &[("SYSTÈME".into(), vec![alerte("Note", "rien de grave", Niveau::Info)])],
            debut(),
        );
        assert_eq!(r.constats, Vec::new());
    }
}

//! Le résultat d'une analyse du moteur de Vanguard sur les endroits à risque (`modele::resultat`), sans l'écran :
//! chaque correspondance (empreinte, règle, base ClamAV, heuristique) avec sa gravité, et ce qui n'a pas pu être lu.
//! Rendu par `vanguard yara --json` (PRO-YAR-001) et repris par `vanguard antivirus --json` (PRO-ANV-001), qui y
//! ajoute son second avis et les programmes lancés au démarrage. Une analyse incomplète (fichier illisible, source
//! absente ou pas rafraîchie) n'est jamais « sain » : rien n'est conclu pour ce qui n'a pas été lu.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use crate::machine::{Constat, alerte, impossible_par, ok, sans_objet};
use crate::modele::resultat::{Couverture, Resultat, sans_piege};
use crate::modele::{Absence, Raison};
use crate::risk::Niveau;
use crate::{tr, trf};

/// L'identifiant de l'outil (`modele::registre::OUTILS`).
pub(crate) const ID: &str = "PRO-YAR-001";

pub(crate) const CAT: &str = "Fichiers suspects";

/// Les correspondances détaillées une à une, puis les autres comptées : la sortie reste bornée (la fenêtre lit au plus
/// 16 Mio et 5000 éléments), et un dossier plein de fichiers reconnus ne la noie pas.
pub(crate) const TROUVES_MAX: usize = 200;

/// De même pour ce qui n'a pas pu être vérifié et pour les simples informations.
pub(crate) const MANQUES_MAX: usize = 50;
pub(crate) const INFOS_MAX: usize = 50;

pub(crate) type Debut = (chrono::DateTime<chrono::Utc>, std::time::Instant);

/// Ce qu'une analyse a relevé, sans l'écran. Les phrases sont déjà prêtes à montrer (noms rendus affichables par
/// l'appelant) ; elles sont encore nettoyées ici, le nom d'un fichier étant choisi par son auteur.
#[derive(Default, Debug)]
pub(crate) struct Releve {
    /// Chaque correspondance : sa gravité, et sa phrase (fichier, famille, ce qui reste à faire).
    pub trouves: Vec<(Niveau, String)>,
    /// Ce qui n'a pas pu être vérifié, une phrase par manque.
    pub manques: Vec<String>,
    /// Ce qui est seulement dit (programmes lancés au démarrage) : ni un problème, ni un manque.
    pub infos: Vec<String>,
    /// Les endroits analysés (téléchargements, bureau…) : ce que l'analyse a vérifié.
    pub endroits: u32,
    /// Les fichiers passés au moteur.
    pub fichiers: usize,
}

/// Les phrases au-delà de `max` remplacées par une seule qui les compte, toutes nettoyées.
pub(crate) fn bornees(textes: &[String], max: usize, reste: impl Fn(usize) -> String) -> Vec<String> {
    let mut t: Vec<String> = textes.iter().take(max).map(|m| sans_piege(m, false)).collect();
    let n = textes.len().saturating_sub(max);
    if n > 0 {
        t.push(reste(n));
    }
    t
}

/// Le résultat sous l'identifiant `id` : une alerte par correspondance (bornées), sinon « rien de connu » quand tout a
/// été lu, ou « non vérifié » quand quelque chose manquait ; les informations à part, sans changer le verdict.
pub(crate) fn resultat_de(id: &str, cat: &'static str, r: &Releve, debut: Debut) -> Resultat {
    let mut constats: Vec<Constat> = r
        .trouves
        .iter()
        .take(TROUVES_MAX)
        .map(|(n, t)| alerte(cat, *n, sans_piege(t, false)))
        .collect();
    if let Some(pire) = r.trouves.iter().skip(TROUVES_MAX).map(|(n, _)| *n).max() {
        constats.push(alerte(
            cat,
            pire,
            trf!(
                "{} autre(s) correspondance(s), non détaillée(s) ici : l'analyse à l'écran les liste toutes.",
                "{} other match(es), not detailed here: the on-screen scan lists them all.",
                r.trouves.len().saturating_sub(TROUVES_MAX)
            ),
        ));
    }
    if constats.is_empty() {
        constats.push(if r.endroits == 0 {
            sans_objet(
                cat,
                Absence::Inactif,
                tr!(
                    "Aucun endroit à risque sur cet ordinateur (téléchargements, bureau, démarrage) : rien n'a été analysé.",
                    "No risky place on this computer (downloads, desktop, startup): nothing was scanned."
                ),
            )
        } else if r.manques.is_empty() {
            ok(
                cat,
                trf!(
                    "Rien de connu ni de suspect dans {} fichier(s) des endroits à risque (ce n'est pas une garantie).",
                    "Nothing known or suspicious in {} file(s) of the risky places (that is not a guarantee).",
                    r.fichiers
                ),
            )
        } else {
            impossible_par(
                cat,
                Raison::Illisible(tr!("analyse incomplète", "incomplete scan").to_string()),
                trf!(
                    "Rien de connu dans ce qui a été lu ({} fichier(s)), mais l'analyse est incomplète : rien n'est conclu pour le reste, non vérifié.",
                    "Nothing known in what was read ({} file(s)), but the scan is incomplete: nothing is concluded for the rest, not verified.",
                    r.fichiers
                ),
            )
        });
    }
    constats.extend(
        bornees(&r.infos, INFOS_MAX, |n| {
            trf!(
                "Et {n} autre(s), non détaillé(s) ici.",
                "And {n} other(s), not detailed here."
            )
        })
        .into_iter()
        .map(|t| ok(cat, t)),
    );
    let non_verifies = bornees(&r.manques, MANQUES_MAX, |n| {
        trf!(
            "{n} autre(s) élément(s) non vérifié(s), non détaillé(s) ici.",
            "{n} other item(s) not checked, not detailed here."
        )
    });
    Resultat::nouveau(
        id,
        debut,
        &constats,
        Couverture {
            verifies: r.endroits,
            non_verifies,
        },
    )
}

/// Le résultat de l'analyse YARA.
pub(crate) fn resultat(r: &Releve, debut: Debut) -> Resultat {
    resultat_de(ID, CAT, r, debut)
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    fn debut() -> Debut {
        (chrono::Utc::now(), std::time::Instant::now())
    }

    fn lu(fichiers: usize) -> Releve {
        Releve {
            endroits: 2,
            fichiers,
            ..Releve::default()
        }
    }

    /// Tout lu, rien trouvé : « sain » ; une correspondance : « probleme » à sa gravité ; aucun endroit : jamais sain.
    #[test]
    fn trouve_et_rien_trouve() {
        let r = lu(12);
        let res = resultat(&r, debut());
        assert_eq!(res.verdict(), "sain");
        assert!(res.constats[0].message.contains("12 fichier(s)"));
        let mut r = lu(12);
        r.trouves.push((
            Niveau::Critique,
            "/maison/essai/eicar.com : fichier d'essai EICAR".into(),
        ));
        r.trouves.push((Niveau::Moyen, "/maison/essai/x.sh : suspect".into()));
        let res = resultat(&r, debut());
        assert_eq!(res.verdict(), "probleme");
        assert_eq!(res.pire(), Some(Niveau::Critique));
        assert_eq!(res.constats.len(), 2);
        let res = resultat(&Releve::default(), debut());
        assert_eq!(res.verdict(), "non-verifie");
        assert_eq!(res.constats[0].etat, "sans-objet");
    }

    /// Une analyse partielle (fichier illisible, empreintes pas rafraîchies) n'est jamais « sain », même sans rien
    /// trouvé, et ne se dit pas « rien de connu » sans réserve.
    #[test]
    fn partiel_jamais_sain() {
        for manque in [
            "/maison/essai : 1 élément(s) illisible(s)",
            "empreintes de MalwareBazaar : copie gardée plus vieille que son rafraîchissement",
        ] {
            let mut r = lu(5);
            r.manques.push(manque.into());
            let res = resultat(&r, debut());
            assert_eq!(res.verdict(), "non-verifie", "{manque}");
            assert_eq!(res.constats[0].etat, "non-verifie");
            assert_eq!(res.couverture.non_verifies.len(), 1);
            // Une information ajoutée ne le rend pas sain non plus.
            r.infos.push("Lancé au démarrage : essai".into());
            assert_eq!(resultat(&r, debut()).verdict(), "non-verifie");
        }
    }

    /// Les correspondances, les manques et les informations sont bornés ; ce qui dépasse est compté, à la pire gravité.
    #[test]
    fn sortie_bornee() {
        let mut r = lu(1000);
        r.trouves = (0..TROUVES_MAX + 7)
            .map(|i| (Niveau::Moyen, format!("/maison/essai/f{i} : suspect")))
            .collect();
        r.trouves.push((Niveau::Critique, "/maison/essai/eicar.com".into()));
        r.manques = (0..MANQUES_MAX + 3).map(|i| format!("manque {i}")).collect();
        r.infos = (0..INFOS_MAX + 2).map(|i| format!("info {i}")).collect();
        let res = resultat(&r, debut());
        assert_eq!(res.constats.len(), TROUVES_MAX + 1 + INFOS_MAX + 1);
        assert_eq!(res.pire(), Some(Niveau::Critique));
        assert!(res.constats[TROUVES_MAX].message.starts_with("8 autre(s)"));
        assert_eq!(res.couverture.non_verifies.len(), MANQUES_MAX + 1);
        assert!(res.couverture.non_verifies[MANQUES_MAX].starts_with("3 autre(s)"));
        // Les informations ne changent pas le verdict : sans correspondance ni manque, il resterait sain.
        let mut r = lu(3);
        r.infos.push("Lancé au démarrage : essai".into());
        assert_eq!(resultat(&r, debut()).verdict(), "sain");
    }

    /// Un nom de fichier piégé (U+202E, saut de ligne, séquence d'échappement) n'arrive jamais tel quel au résultat.
    #[test]
    fn textes_sans_piege() {
        let mut r = lu(1);
        r.trouves.push((Niveau::Eleve, "facture\u{202e}fdp.exe\nsuite".into()));
        r.manques.push("lue dans x\u{1b}]52;c;y\u{7}".into());
        r.infos.push("démarrage\u{1b}[2J".into());
        let json = crate::modele::resultat::json(&resultat(&r, debut()));
        assert!(
            !json.contains('\u{202e}') && !json.contains("\\u001b") && !json.contains("\\n"),
            "{json}"
        );
    }
}

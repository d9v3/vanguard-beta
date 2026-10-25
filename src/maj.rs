//! Mises à jour : système, programmes, pilotes et firmware vérifiés d'un coup, puis installés après accord
//! (mêmes étapes que « vanguard corriger » ; « `[t]out` » passe par une seule fenêtre administrateur sous Windows).

use crate::machine::{self, Constat};
use crate::ui::*;

/// `seulement` : après une installation, les catégories installées, pour ne pas refaire toutes les recherches.
fn verifier(seulement: Option<&[&str]>) -> Vec<Constat> {
    trp!(
        "  {GRIS}Recherche en cours (jusqu'à deux minutes : les serveurs de mises à jour sont interrogés)…{RESET}",
        "  {GRIS}Searching (up to two minutes: the update servers are queried)…{RESET}"
    );
    let constats = machine::mises_a_jour_completes(seulement);
    machine::afficher_constats(&constats);
    constats
}

pub fn executer() {
    titre(tr!("Mises à jour", "Updates"));
    let constats = verifier(None);
    if constats.iter().all(|c| c.correctif.is_none()) {
        let impossibles = constats.iter().filter(|c| !c.verifie).count();
        if impossibles == 0 {
            trp!(
                "\n  {VERT}✔ Tout est à jour.{RESET}",
                "\n  {VERT}✔ Everything is up to date.{RESET}"
            );
        } else {
            trp!(
                "\n  ⚠ {impossibles} vérification(s) impossible(s) : je ne peux pas dire que tout est à jour.",
                "\n  ⚠ {impossibles} check(s) could not be done: I cannot say everything is up to date."
            );
        }
        return;
    }
    titre("Installation");
    let installees = crate::corriger::proposer(&constats, tr!("mises à jour", "updates"));
    if installees.is_empty() {
        return;
    }
    titre(tr!(
        "Nouvelle vérification de ce qui a été installé",
        "Checking again what was installed"
    ));
    let apres = verifier(Some(&installees));
    println!("{}", bilan_apres(&apres, &installees));
}

/// Ce qui reste après l'installation, relu : « vérifié » seulement si la vérification a pu se faire.
fn bilan_apres(apres: &[Constat], installees: &[&str]) -> String {
    let concernes: Vec<&Constat> = apres.iter().filter(|c| installees.contains(&c.categorie)).collect();
    let restent = concernes.iter().filter(|c| c.correctif.is_some()).count();
    let impossibles = concernes.iter().filter(|c| !c.verifie).count();
    if restent > 0 {
        trf!(
            "\n  ⚠ {restent} mise(s) à jour encore à faire : voir ci-dessus.",
            "\n  ⚠ {restent} update(s) still to do: see above."
        )
    } else if impossibles > 0 {
        trf!(
            "\n  ⚠ Installé, mais {impossibles} vérification(s) impossible(s) : je ne peux pas dire que tout est à jour.",
            "\n  ⚠ Installed, but {impossibles} check(s) could not be done: I cannot say everything is up to date."
        )
    } else {
        trf!(
            "\n  {VERT}✔ Installé et vérifié.{RESET}",
            "\n  {VERT}✔ Installed and checked.{RESET}"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::Correctif;

    fn constat(categorie: &'static str, a_faire: bool, verifie: bool) -> Constat {
        Constat {
            categorie,
            probleme: None,
            message: String::new(),
            correctif: a_faire.then(|| Correctif {
                action: "Installer".into(),
                commandes: vec![],
                automatique: true,
                bloque: None,
                defaire: crate::machine::Defaire::Inconnu,
            }),
            verifie,
            regle: "",
            objet: crate::modele::Objet::NonMigre,
            precision: crate::modele::Precision::Aucune,
        }
    }

    #[test]
    fn verifie_seulement_si_la_verification_a_pu_se_faire() {
        let installees = ["Mises à jour"];
        assert!(bilan_apres(&[constat("Mises à jour", false, true)], &installees).contains("✔"));
        // La recherche n'a pas pu se refaire : rien ne dit que c'est installé.
        let impossible = bilan_apres(&[constat("Mises à jour", false, false)], &installees);
        assert!(impossible.contains('⚠') && !impossible.contains('✔'), "{impossible}");
        assert!(bilan_apres(&[constat("Mises à jour", true, true)], &installees).contains("1 "));
        // Une autre catégorie, non installée cette fois, ne compte pas.
        assert!(bilan_apres(&[constat("Pilotes", true, false)], &installees).contains("✔"));
    }
}

//! Le résultat de l'examen d'un lien (`modele::resultat`) : chaque signe vu dans le lien, ce que les listes publiques
//! et le registre du domaine en disent quand ils ont été demandés, et ce qui n'a pas pu l'être, sans l'écran. Versé au
//! rapport (`examens/PRO-LIE-001.json`), au journal des événements, et rendu par `--json`. Le verdict n'est jamais
//! « sûr » : sans signe et sans manque, il est « sain » au sens de « rien trouvé dans ce qui a été examiné ».

use super::{Inscription, Lien, Signe, Verification, site};
use crate::machine::{Constat, alerte, impossible_par, ok};
use crate::modele::resultat::{Couverture, Resultat};
use crate::modele::{Objet, Raison};
use crate::risk::Niveau;

/// L'identifiant de l'outil (`modele::registre::OUTILS`).
pub(crate) const ID: &str = "PRO-LIE-001";

const CAT: &str = "Lien suspect";

type Debut = (chrono::DateTime<chrono::Utc>, std::time::Instant);

/// Ce qu'il en est des vérifications en ligne (l'âge du domaine et les listes publiques).
pub(super) enum EnLigneVu<'a> {
    /// Demandées : chaque réponse.
    Faites(&'a [Verification]),
    /// Pas demandées, et pourquoi (refusées, sans `--internet`, mode hors ligne) : rien n'est parti.
    PasFaites(&'static str),
    /// Rien à demander : le lien n'a pas de site (« javascript: », « data: »…).
    SansObjet,
}

/// L'objet des constats : le site qu'on achète (ou l'adresse IP), sinon le genre de lien sans site.
fn objet(lien: &Lien) -> Objet {
    if lien.hote.is_empty() {
        Objet::de("lien", &lien.schema)
    } else {
        Objet::de("site", &site(lien))
    }
}

/// Un signe : au-dessus d'une information, une alerte ; sinon un fait (domaine officiel, adresse locale, vieux
/// domaine).
fn constat_de(s: &Signe) -> Constat {
    if s.niveau > Niveau::Info {
        alerte(CAT, s.niveau, s.texte.clone())
    } else {
        ok(CAT, s.texte.clone())
    }
}

/// Le résultat de l'examen d'un lien commencé à `debut` : les signes du lien lui-même (`signes`), puis ce qu'ont dit
/// les vérifications en ligne.
pub(super) fn resultat(lien: &Lien, signes: &[Signe], en_ligne: &EnLigneVu, debut: Debut) -> Resultat {
    let quoi = objet(lien);
    let mut constats: Vec<Constat> = signes.iter().map(constat_de).collect();
    if constats.is_empty() {
        constats.push(ok(
            CAT,
            crate::tr!(
                "Rien de suspect dans le lien lui-même (ce n'est pas une garantie).",
                "Nothing suspicious in the link itself (that is not a guarantee)."
            ),
        ));
    }
    let mut verifies = 1u32;
    let mut non_verifies = Vec::new();
    match en_ligne {
        EnLigneVu::Faites(verifications) => {
            for v in *verifications {
                let note = v.note.as_deref().map(|n| format!(" ({n})")).unwrap_or_default();
                match (&v.reponse, &v.signe) {
                    (Inscription::Impossible(raison), _) => {
                        constats.push(impossible_par(
                            CAT,
                            Raison::Echoue(raison.clone()),
                            crate::trf!(
                                "{} : impossible à vérifier : {raison}{note}",
                                "{}: could not check: {raison}{note}",
                                v.liste
                            ),
                        ));
                        non_verifies.push(crate::trf!("{} : {raison}", "{}: {raison}", v.liste));
                        continue;
                    }
                    (Inscription::Inscrit(raison, niveau), _) => constats.push(alerte(
                        CAT,
                        *niveau,
                        crate::trf!("{} : listé : {raison}{note}", "{}: listed: {raison}{note}", v.liste),
                    )),
                    (Inscription::Absent, Some(s)) => constats.push(constat_de(s)),
                    (Inscription::Absent, None) => constats.push(ok(
                        CAT,
                        crate::trf!("{} : pas listé{note}", "{}: not listed{note}", v.liste),
                    )),
                }
                verifies += 1;
            }
        }
        EnLigneVu::PasFaites(pourquoi) => non_verifies.push(crate::trf!(
            "l'âge du domaine et les listes publiques ({pourquoi})",
            "the domain's age and the public lists ({pourquoi})"
        )),
        EnLigneVu::SansObjet => {}
    }
    let constats: Vec<Constat> = constats.into_iter().map(|c| c.avec_objet(quoi.clone())).collect();
    Resultat::nouveau(ID, debut, &constats, Couverture { verifies, non_verifies })
}

/// Le résultat d'un texte qui n'est pas un lien : rien de vérifié.
pub(super) fn refuse(debut: Debut) -> Resultat {
    let raison = crate::tr!(
        "Ce n'est pas un lien reconnu (il faut au moins un nom comme « exemple.com »).",
        "This is not a recognized link (it needs at least a name like “example.com”)."
    );
    Resultat::nouveau(
        ID,
        debut,
        &[impossible_par(CAT, Raison::Refuse(raison.to_string()), raison)],
        Couverture::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::super::{decouper, examiner, nettoyer};
    use super::*;

    fn examen(adresse: &str, en_ligne: &EnLigneVu) -> Resultat {
        let debut = (chrono::Utc::now(), std::time::Instant::now());
        let lien = decouper(&nettoyer(adresse)).unwrap();
        resultat(&lien, &examiner(&lien), en_ligne, debut)
    }

    #[test]
    fn resultat_d_un_lien() {
        let debut = (chrono::Utc::now(), std::time::Instant::now());
        assert_eq!(refuse(debut).verdict(), "non-verifie");
        // Rien d'examiné en ligne : jamais sain, même pour un lien sans signe.
        let sans = EnLigneVu::PasFaites("pas demandées");
        let r = examen("https://exemple.com/a", &sans);
        assert_eq!((r.verdict(), r.couverture.verifies), ("non-verifie", 1));
        assert_eq!(r.couverture.non_verifies.len(), 1);
        // Sous-domaine trompeur : problème, sans rien demander en ligne, et l'objet nomme le vrai site.
        let r = examen("https://paypal.com.compte-secure.example/login", &sans);
        assert_eq!(r.verdict(), "probleme");
        let piege = r.constats.iter().find(|c| c.etat == "probleme").unwrap();
        assert_eq!(piege.objet.as_deref(), Some("site:compte-secure.example"));
        // Les listes : listée, absente, muette.
        let reponses = [
            Verification::simple("URLhaus", Inscription::Absent),
            Verification::simple(
                "Spamhaus DBL",
                Inscription::Impossible("votre DNS n'a pas répondu".into()),
            ),
        ];
        let r = examen("https://exemple.com/a", &EnLigneVu::Faites(&reponses));
        assert_eq!((r.verdict(), r.couverture.verifies), ("non-verifie", 2));
        let reponses = [Verification::simple("URLhaus", Inscription::Absent)];
        assert_eq!(
            examen("https://exemple.com/a", &EnLigneVu::Faites(&reponses)).verdict(),
            "sain"
        );
        let reponses = [Verification::simple(
            "SURBL",
            Inscription::Inscrit("hameçonnage".into(), Niveau::Eleve),
        )];
        let r = examen("https://exemple.com/a", &EnLigneVu::Faites(&reponses));
        assert_eq!(r.pire(), Some(Niveau::Eleve));
        // Un lien sans site : rien à demander en ligne, l'objet dit son genre.
        let r = examen("javascript:alert(1)", &EnLigneVu::SansObjet);
        assert_eq!(r.pire(), Some(Niveau::Critique));
        assert_eq!(r.constats[0].objet.as_deref(), Some("lien:javascript"));
    }
}

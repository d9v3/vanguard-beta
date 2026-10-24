//! Le tri, avant tout brouillon : c'est la question qui compte. Une faille déjà connue (une CVE publiée) ne se signale
//! pas, elle se corrige par une mise à jour ; un logiciel malveillant ou un site d'hameçonnage n'est pas une faille
//! du produit ; une détection ratée relève de l'envoi d'un échantillon. Seul un comportement anormal d'un produit
//! mène à un rapport. Pur et sans entrée-sortie : testé seul.

use std::fmt::Write as _;

use crate::modele::evenement::{Evenement, Genre};
use crate::modele::resultat::Resultat;

/// Ce qu'on signale.
#[derive(Debug)]
pub(crate) enum Sujet {
    /// Le fil d'un incident du journal (borné), l'événement choisi, et combien d'événements du fil sont omis.
    Incident {
        choisi: Box<Evenement>,
        fil: Vec<Evenement>,
        omis: usize,
    },
    /// Le dernier examen d'un outil, relu par son sceau.
    Examen(Box<Resultat>),
    /// Rien de ce que Vanguard a vu : la personne écrit tout, Vanguard ne donne que le contexte du système.
    Rien,
}

/// Le résultat du tri.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case", tag = "sorte", content = "cve")]
pub(crate) enum Tri {
    /// Une faille publiée, avec ses CVE (vide : un logiciel pas à jour, sans CVE citée).
    FailleConnue(Vec<String>),
    /// Un logiciel malveillant, un botnet, un fichier isolé : pas une faille de l'éditeur.
    Malveillant,
    /// Un lien ou un courriel d'hameçonnage.
    Hameconnage,
    /// Un antivirus n'a pas vu un fichier : un échantillon à envoyer, pas une faille.
    DetectionRatee,
    /// Une protection « en profondeur » contournée : pas corrigée par défaut chez Microsoft, dit avant le brouillon.
    Contournement,
    /// Une faille dans Vanguard lui-même.
    Vanguard,
    /// Un comportement anormal d'un produit : un rapport à écrire.
    AEcrire,
}

/// Les CVE citées (« CVE-2026-12345 »), en majuscules, sans doublon, dans l'ordre.
pub(crate) fn cves(texte: &str) -> Vec<String> {
    let haut = texte.to_ascii_uppercase();
    let mut vues: Vec<String> = Vec::new();
    for (i, _) in haut.match_indices("CVE-") {
        let reste = &haut[i + 4..];
        let annee: String = reste.chars().take_while(char::is_ascii_digit).collect();
        if annee.len() != 4 || !reste[4..].starts_with('-') {
            continue;
        }
        let numero: String = reste[5..].chars().take_while(char::is_ascii_digit).collect();
        if (4..=7).contains(&numero.len()) {
            let cve = format!("CVE-{annee}-{numero}");
            if !vues.contains(&cve) {
                vues.push(cve);
            }
        }
    }
    vues
}

/// Le texte d'un événement où chercher ce qui le classe : sa clé, son titre, ce qui a été fait.
fn texte_de(e: &Evenement) -> String {
    let mut t = e.cle.clone().unwrap_or_default();
    t.push(' ');
    match &e.quoi {
        Genre::Alerte { famille, titre, texte } => {
            let _ = write!(t, "{famille} {titre} {texte}");
        }
        Genre::Action { quoi, .. } => t.push_str(quoi),
        Genre::Examen { outil, .. } => t.push_str(outil),
        _ => {}
    }
    t
}

/// Un événement qui dit un logiciel malveillant : un serveur de botnet, une menace bloquée, un fichier isolé ou
/// supprimé par une analyse, un programme arrivé dans Téléchargements.
fn malveillant(e: &Evenement) -> bool {
    let cle = e.cle.as_deref().unwrap_or_default();
    let famille = matches!(&e.quoi, Genre::Alerte { famille, .. }
        if matches!(famille.as_str(), "botnet" | "blocage" | "telechargement"));
    let analyse = e.source == crate::modele::evenement::Source::Analyse
        && matches!(e.quoi, Genre::Action { .. } | Genre::Annulation { supprime: true, .. });
    famille
        || analyse
        || [
            "botnet|",
            "blocage|",
            "SUR-BOT-001",
            "SUR-BLO-001",
            "SUR-TEL-001",
            "PRO-ESP-001",
        ]
        .iter()
        .any(|c| cle.starts_with(c))
}

fn hameconnage(cle: &str) -> bool {
    cle.starts_with("PRO-LIE-001") || cle.starts_with("PRO-COU-001")
}

/// Le tri d'un sujet. `Rien` et ce qui ne se classe pas ici donnent `AEcrire` : la question posée à la personne
/// (`mod.rs`) affine ensuite (détection ratée, contournement, Vanguard).
pub(crate) fn trier(sujet: &Sujet) -> Tri {
    match sujet {
        Sujet::Rien => Tri::AEcrire,
        Sujet::Examen(r) => {
            // Un examen sain, non vérifié ou falsifié (`resultat::derniers` le rend sans constat) ne prouve rien :
            // la personne dit elle-même la nature (`question_nature`).
            if r.verdict() != "probleme" {
                return Tri::AEcrire;
            }
            let messages = r
                .constats
                .iter()
                .filter(|c| c.etat == "probleme")
                .map(|c| c.message.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            match r.outil.as_str() {
                "PRO-PER-001" => Tri::FailleConnue(cves(&messages)),
                "PRO-LIE-001" | "PRO-COU-001" => Tri::Hameconnage,
                "PRO-ESP-001" | "PRO-ANV-001" | "PRO-YAR-001" | "PRO-MEM-001" => Tri::Malveillant,
                _ if !cves(&messages).is_empty() => Tri::FailleConnue(cves(&messages)),
                _ => Tri::AEcrire,
            }
        }
        Sujet::Incident { choisi, fil, .. } => {
            let tous = || std::iter::once(&**choisi).chain(fil.iter());
            let texte: String = tous().map(|e| texte_de(e) + " ").collect();
            if tous().any(|e| hameconnage(e.cle.as_deref().unwrap_or_default())) {
                return Tri::Hameconnage;
            }
            if tous().any(malveillant) {
                return Tri::Malveillant;
            }
            let c = cves(&texte);
            if !c.is_empty() || tous().any(|e| e.cle.as_deref().is_some_and(|k| k.starts_with("PRO-PER-001"))) {
                return Tri::FailleConnue(c);
            }
            Tri::AEcrire
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modele::evenement::Source;
    use crate::modele::resultat::{ConstatEcrit, Couverture};

    fn examen(outil: &str, message: &str) -> Sujet {
        examen_etat(outil, message, "probleme")
    }

    fn examen_etat(outil: &str, message: &str, etat: &str) -> Sujet {
        let probleme = etat == "probleme";
        Sujet::Examen(Box::new(Resultat {
            outil: outil.into(),
            schema: 1,
            debut: "2026-10-23T10:00:00Z".into(),
            duree_ms: 1,
            couverture: Couverture {
                verifies: 1,
                non_verifies: Vec::new(),
            },
            constats: vec![ConstatEcrit {
                regle: String::new(),
                objet: None,
                categorie: "x".into(),
                etat: etat.into(),
                niveau: probleme.then_some(crate::risk::Niveau::Eleve),
                raison: None,
                message: message.into(),
                corrigeable: false,
                date: None,
            }],
        }))
    }

    fn incident(e: Evenement) -> Sujet {
        Sujet::Incident {
            choisi: Box::new(e),
            fil: Vec::new(),
            omis: 0,
        }
    }

    #[test]
    fn cves_lues() {
        assert_eq!(
            cves("cve-2026-12345, CVE-2025-1234 et CVE-2026-12345 ; CVE-26-1, CVE-2026-12"),
            ["CVE-2026-12345", "CVE-2025-1234"]
        );
    }

    #[test]
    fn tri_des_sujets() {
        assert_eq!(
            trier(&examen("PRO-PER-001", "Firefox 120 : CVE-2026-0001 exploitée (KEV)")),
            Tri::FailleConnue(vec!["CVE-2026-0001".into()])
        );
        assert_eq!(trier(&examen("PRO-COU-001", "lien trompeur")), Tri::Hameconnage);
        assert_eq!(trier(&examen("PRO-ESP-001", "x")), Tri::Malveillant);
        let bot = Evenement::alerte(Source::Surveillance, "botnet", "Serveur de botnet", "203.0.113.7:443")
            .cle(Some("botnet|203.0.113.7:443"));
        assert_eq!(trier(&incident(bot)), Tri::Malveillant);
        let quarantaine = Evenement::action(Source::Analyse, "mis en quarantaine", true, &[]);
        assert_eq!(trier(&incident(quarantaine)), Tri::Malveillant);
        let lien = Evenement::alerte(Source::Outil, "autre", "Lien", "x").cle(Some("PRO-LIE-001"));
        assert_eq!(trier(&incident(lien)), Tri::Hameconnage);
        let port = Evenement::alerte(Source::Surveillance, "port", "Port ouvert", "8080").cle(Some("port|8080"));
        assert_eq!(trier(&incident(port)), Tri::AEcrire);
        assert_eq!(trier(&Sujet::Rien), Tri::AEcrire);
    }

    /// Un examen sain, non vérifié ou falsifié ne classe rien : « déjà connue », « malveillant » ou « hameçonnage »
    /// y seraient affirmés sans preuve ; la personne choisit la nature au clavier.
    #[test]
    fn examen_sans_probleme_ne_classe_rien() {
        for outil in ["PRO-PER-001", "PRO-ESP-001", "PRO-COU-001", "PRO-LIE-001"] {
            for etat in ["sain", "non-verifie"] {
                assert_eq!(
                    trier(&examen_etat(outil, "tout est à jour", etat)),
                    Tri::AEcrire,
                    "{outil} {etat}"
                );
            }
            let Sujet::Examen(mut falsifie) = examen(outil, "x") else {
                panic!()
            };
            falsifie.constats.clear();
            falsifie.couverture.verifies = 0;
            assert_eq!(trier(&Sujet::Examen(falsifie)), Tri::AEcrire, "{outil} falsifié");
        }
    }
}

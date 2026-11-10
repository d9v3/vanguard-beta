//! Le résultat de l'analyse antivirus rapide (`modele::resultat`, PRO-ANV-001), sans l'écran : ce que le moteur de
//! Vanguard a relevé sur les endroits à risque (`yara::resultat`), son second avis (clamscan sous Linux ; Defender,
//! qui met lui-même en quarantaine, n'est pas lancé par `--json` sous Windows) et les programmes lancés au démarrage.
//! Rendu par `vanguard antivirus --json` et versé au rapport. Rien n'y est changé : une correspondance est à isoler
//! depuis le menu. Un second avis qui a échoué ou une source non lue rendent le tout non vérifié, jamais « sain ».

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use crate::modele::resultat::Resultat;
use crate::protection::yara::resultat::{Debut, Releve, resultat_de};
use crate::{tr, trf};

/// L'identifiant de l'outil (`modele::registre::OUTILS`), aussi celui de `vanguard antivirus --etat --json`.
pub(crate) const ID: &str = "PRO-ANV-001";

const CAT: &str = "Antivirus";

/// Le résultat de l'analyse rapide.
pub(crate) fn resultat(r: &Releve, debut: Debut) -> Resultat {
    resultat_de(ID, CAT, r, debut)
}

/// Les programmes lancés au démarrage : dits un à un (à reconnaître, pas un problème en soi) ; une source illisible
/// est non vérifiée, la liste pouvant alors être incomplète.
pub(crate) fn ajouter_demarrage(r: &mut Releve, entrees: &[String], non_lus: &[String]) {
    r.infos.extend(
        entrees
            .iter()
            .map(|e| trf!("Lancé au démarrage : {e}", "Started at boot: {e}")),
    );
    r.manques.extend(non_lus.iter().map(|s| {
        trf!(
            "Programmes lancés au démarrage : {s} illisible d'ici, la liste peut être incomplète.",
            "Programs started at boot: {s} unreadable from here, the list may be incomplete."
        )
    }));
}

/// Windows : Defender n'est pas lancé, son analyse retirant d'elle-même ce qu'elle reconnaît.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn defender_pas_lance() -> &'static str {
    tr!(
        "Second avis de Microsoft Defender non lancé : son analyse met d'elle-même en quarantaine ce qu'elle reconnaît, et --json ne change rien. Son avis : l'analyse antivirus du menu.",
        "Microsoft Defender second opinion not run: its scan quarantines what it recognizes by itself, and --json changes nothing. For its opinion: the antivirus scan in the menu."
    )
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::Niveau;

    fn debut() -> Debut {
        (chrono::Utc::now(), std::time::Instant::now())
    }

    /// Les programmes au démarrage sont dits sans changer le verdict ; une source illisible le rend non vérifié.
    #[test]
    fn demarrage_dit_ou_non_verifie() {
        let mut r = Releve {
            endroits: 2,
            fichiers: 9,
            ..Releve::default()
        };
        ajouter_demarrage(&mut r, &["/maison/essai/.config/autostart/essai.desktop".into()], &[]);
        let res = resultat(&r, debut());
        assert_eq!(res.verdict(), "sain");
        assert_eq!(res.outil, ID);
        assert!(res.constats.iter().any(|c| c.message.contains("essai.desktop")));
        ajouter_demarrage(&mut r, &[], &["tâches planifiées".into()]);
        assert_eq!(resultat(&r, debut()).verdict(), "non-verifie");
        r.trouves.push((
            Niveau::Critique,
            "/maison/essai/eicar.com : Eicar-Test-Signature (ClamAV)".into(),
        ));
        assert_eq!(resultat(&r, debut()).verdict(), "probleme");
        assert!(defender_pas_lance().contains("--json"));
    }
}

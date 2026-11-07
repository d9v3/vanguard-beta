//! Le score à règles, pur et commun aux systèmes : à partir des signaux comptés sur la fenêtre (rafale, contenu
//! chiffré, noms, note de rançon, dispersion, piège, copies effacées, origine, processus invisible, exfiltration,
//! rafale lente), un verdict en quatre degrés. Aucune décision n'est prise ici : `juger` ne fait que classer, et la
//! réponse (alerte, « Bloquer », gel/arrêt) est décidée ailleurs (reponse.rs), sous ses propres garde-fous.
//!
//! Le pire défaut d'un tel score n'est pas de rater un rançongiciel (la sauvegarde reste) mais de crier sur un
//! programme honnête : chaque seuil est donc prudent, et le quasi-certain (seul à permettre un arrêt automatique)
//! exige l'ensemble des indices les plus durs à provoquer par accident.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

/// Fichiers existants réécrits à partir desquels on parle de rafale (Suspect).
pub(crate) const R1_SUSPECT: u32 = 10;
/// Fichiers existants réécrits à partir desquels c'est Grave (avec le format perdu sur la moitié).
pub(crate) const R1_GRAVE: u32 = 20;
/// Dossiers distincts touchés exigés pour le quasi-certain : un rançongiciel parcourt l'arbre.
pub(crate) const DOSSIERS_QUASI_CERTAIN: u32 = 3;
/// Même extension ajoutée sur au moins tant de fichiers (R3).
pub(crate) const EXT_AJOUTEE_MIN: u32 = 5;
/// Note de rançon vue dans au moins tant de dossiers (R4).
pub(crate) const NOTE_DOSSIERS_MIN: u32 = 3;
/// Fenêtre lente (L1) : fichiers réécrits au format perdu cumulés sur 30 min.
pub(crate) const L1_FICHIERS_MIN: u32 = 100;

/// Ce que l'effacement des copies de secours vaut, selon le contexte (Critique C4 : le ménage planifié du système ne
/// doit pas crier chaque jour).
// L'ordre des variantes est celui de la gravité : `Ord` les compare ainsi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub(crate) enum Copies {
    #[default]
    Aucune,
    /// Vu hors rafale (session de la personne) : Suspect pris seul.
    SessionHorsRafale,
    /// Vu pendant une rafale : R7, Grave.
    PendantRafale,
}

/// Les signaux comptés sur la fenêtre pour un groupe de processus. Tous calculés par des fonctions pures des modules
/// voisins ; ici, seulement le classement.
#[allow(clippy::struct_excessive_bools)] // un signal par drapeau : les regrouper masquerait ce que chacun mesure
#[derive(Debug, Clone, Default)]
pub(crate) struct Signaux {
    /// R1 : fichiers EXISTANTS distincts réécrits, remplacés ou renommés dans la fenêtre.
    pub reecrits: u32,
    /// R2 : parmi les réécrits, ceux dont le format est perdu.
    pub format_perdu: u32,
    /// R3 : noms suspects (même extension inconnue ajoutée sur ≥ 5, ou nom tiré au hasard).
    pub noms_suspects: bool,
    /// R4 : une même note de rançon dans ≥ 3 dossiers.
    pub note_de_rancon: bool,
    /// R5 : dossiers distincts touchés.
    pub dossiers: u32,
    /// R6 : un fichier-piège modifié ou renommé, vu en direct pendant la rafale.
    pub piege_touche: bool,
    /// R7 : effacement des copies de secours, avec son contexte.
    pub copies: Copies,
    /// E1 : lecture massive de fichiers personnels avec de nouvelles connexions sortantes.
    pub exfiltration: bool,
    /// L1 : rafale lente (≥ 100 fichiers au format perdu cumulés sur 30 min).
    pub rafale_lente: bool,
    /// La file des événements a débordé pendant une rafale : des changements perdus, signe d'un rançongiciel.
    pub deborde_pendant_rafale: bool,
}

/// Le verdict, du plus calme au plus sûr. L'ordre compte : un signal de plus ne fait jamais baisser le verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Verdict {
    Calme,
    Suspect,
    Grave,
    QuasiCertain,
}

/// La moitié au moins des réécrits ont perdu leur format (et il y a eu au moins un réécrit).
fn format_perdu_majoritaire(s: &Signaux) -> bool {
    s.reecrits > 0 && s.format_perdu.saturating_mul(2) >= s.reecrits
}

/// Une rafale chiffrée au sens du quasi-certain : ≥ 20 réécrits, dans ≥ 3 dossiers, format perdu sur ≥ 50 %.
fn rafale_chiffree(s: &Signaux) -> bool {
    s.reecrits >= R1_GRAVE && s.dossiers >= DOSSIERS_QUASI_CERTAIN && format_perdu_majoritaire(s)
}

/// Le verdict des signaux. `attribution_sure` : un seul groupe candidat, descripteur en écriture sur un fichier de la
/// rafale, et AUCUN processus du compte illisible (règle durcie de §2.1) ; sans elle, jamais de quasi-certain, donc
/// jamais d'arrêt automatique.
pub(crate) fn juger(s: &Signaux, attribution_sure: bool) -> Verdict {
    // Quasi certain : attribution sûre ET piège touché pendant la rafale ET rafale chiffrée. Le piège sans
    // attribution reste une coïncidence dans le temps (sans pid par événement), pas une preuve par fichier.
    if attribution_sure && s.piege_touche && rafale_chiffree(s) {
        return Verdict::QuasiCertain;
    }
    // Grave.
    if (s.reecrits >= R1_GRAVE && format_perdu_majoritaire(s))
        || s.piege_touche
        || s.copies == Copies::PendantRafale
        || s.rafale_lente
    {
        return Verdict::Grave;
    }
    // Suspect.
    if s.reecrits >= R1_SUSPECT
        || s.noms_suspects
        || s.note_de_rancon
        || s.copies == Copies::SessionHorsRafale
        || s.exfiltration
        || s.deborde_pendant_rafale
    {
        return Verdict::Suspect;
    }
    Verdict::Calme
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calme_par_defaut() {
        assert_eq!(juger(&Signaux::default(), false), Verdict::Calme);
        // Aucun effacement de copies vu : rien (la veille des fichiers ne compte R7 que pendant une rafale).
        let s = Signaux {
            copies: Copies::Aucune,
            ..Signaux::default()
        };
        assert_eq!(juger(&s, false), Verdict::Calme);
    }

    #[test]
    fn suspect_sur_rafale_moderee() {
        let s = Signaux {
            reecrits: 12,
            ..Signaux::default()
        };
        assert_eq!(juger(&s, true), Verdict::Suspect);
    }

    #[test]
    fn grave_sur_rafale_chiffree_sans_attribution() {
        let s = Signaux {
            reecrits: 40,
            format_perdu: 40,
            dossiers: 5,
            ..Signaux::default()
        };
        // Sans attribution, jamais quasi-certain, même rafale chiffrée : Grave au plus.
        assert_eq!(juger(&s, false), Verdict::Grave);
    }

    #[test]
    fn piege_touche_est_grave_sans_le_reste() {
        let s = Signaux {
            piege_touche: true,
            ..Signaux::default()
        };
        assert_eq!(juger(&s, true), Verdict::Grave);
    }

    #[test]
    fn quasi_certain_exige_tout() {
        let s = Signaux {
            reecrits: 25,
            format_perdu: 20,
            dossiers: 4,
            piege_touche: true,
            ..Signaux::default()
        };
        assert_eq!(juger(&s, true), Verdict::QuasiCertain);
        // Attribution non sûre : retombe à Grave.
        assert_eq!(juger(&s, false), Verdict::Grave);
        // Piège sans rafale chiffrée : Grave (par le piège), pas quasi-certain.
        let s2 = Signaux {
            reecrits: 5,
            format_perdu: 5,
            dossiers: 1,
            piege_touche: true,
            ..Signaux::default()
        };
        assert_eq!(juger(&s2, true), Verdict::Grave);
    }

    #[test]
    fn bornes_exactes() {
        let avec = |reecrits, format_perdu, dossiers| Signaux {
            reecrits,
            format_perdu,
            dossiers,
            ..Signaux::default()
        };
        // R1 = 10 : Suspect ; 9 : Calme.
        assert_eq!(juger(&avec(R1_SUSPECT, 0, 1), false), Verdict::Suspect);
        assert_eq!(juger(&avec(R1_SUSPECT - 1, 0, 1), false), Verdict::Calme);
        // R1 = 20 avec 50 % format perdu : Grave ; 49 % : Suspect.
        assert_eq!(juger(&avec(20, 10, 1), false), Verdict::Grave);
        assert_eq!(juger(&avec(20, 9, 1), false), Verdict::Suspect);
    }

    #[test]
    fn copies_pendant_rafale_grave() {
        let s = Signaux {
            copies: Copies::PendantRafale,
            ..Signaux::default()
        };
        assert_eq!(juger(&s, false), Verdict::Grave);
        let s = Signaux {
            copies: Copies::SessionHorsRafale,
            ..Signaux::default()
        };
        assert_eq!(juger(&s, false), Verdict::Suspect);
    }

    proptest::proptest! {
        #[test]
        fn ne_panique_jamais(
            reecrits in 0u32..10_000,
            format_perdu in 0u32..10_000,
            dossiers in 0u32..1_000,
            drapeaux in 0u16..=0x3ff,
            attribution in proptest::bool::ANY,
        ) {
            let s = signaux_de(reecrits, format_perdu, dossiers, drapeaux);
            let _ = juger(&s, attribution);
        }

        /// Monotonie : ajouter n'importe quel drapeau ne fait jamais baisser le verdict (attribution fixée).
        #[test]
        fn monotone_quand_on_ajoute_un_signal(
            reecrits in 0u32..100,
            format_perdu in 0u32..100,
            dossiers in 0u32..10,
            drapeaux in 0u16..=0x3ff,
            bit in 0u16..10,
            attribution in proptest::bool::ANY,
        ) {
            let base = signaux_de(reecrits, format_perdu, dossiers, drapeaux);
            let avant = juger(&base, attribution);
            let plus = signaux_de(reecrits, format_perdu, dossiers, drapeaux | (1 << bit));
            let apres = juger(&plus, attribution);
            proptest::prop_assert!(apres >= avant, "{avant:?} -> {apres:?}");
        }
    }

    #[cfg(test)]
    fn signaux_de(reecrits: u32, format_perdu: u32, dossiers: u32, drapeaux: u16) -> Signaux {
        Signaux {
            reecrits,
            format_perdu,
            dossiers,
            noms_suspects: drapeaux & 1 != 0,
            note_de_rancon: drapeaux & 2 != 0,
            piege_touche: drapeaux & 4 != 0,
            copies: if drapeaux & 8 != 0 {
                Copies::PendantRafale
            } else {
                Copies::Aucune
            },
            exfiltration: drapeaux & 64 != 0,
            rafale_lente: drapeaux & 128 != 0,
            deborde_pendant_rafale: drapeaux & 256 != 0,
        }
    }
}

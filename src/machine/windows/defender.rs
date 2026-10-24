//! Les protections de Defender que le profil « durcir » d'Optimiser active (règles ASR de base et contre les documents
//! piégés, protection réseau, logiciels indésirables, accès contrôlé aux dossiers), relues à chaque bilan. Sans
//! cette relecture, ce que Vanguard a posé ne comptait pas dans la note, et une protection coupée ensuite (un
//! logiciel malveillant le fait avec Set-MpPreference avant d'agir) passait inaperçue.
//!
//! Proposées au bilan : les blocages de base (Microsoft les dit sans revers), la protection réseau et les logiciels
//! indésirables. Celles qui peuvent gêner un programme légitime (documents piégés, dossiers contrôlés) ne le sont
//! que si Vanguard les avait posées et qu'elles ont été coupées depuis. Chaque correction note la valeur d'avant
//! (`annulables`), comme dans Optimiser.

use super::{Constat, alerte, ok};
use crate::machine::sans_objet;
use crate::modele::{Absence, Objet, Raison};
use crate::optimiser::Geste;
use crate::optimiser::defender::{self, ASR_BASE, ASR_BUREAUTIQUE, Etat, Pref};
use crate::risk::Niveau;
use crate::ui::{tr, trf};

const CAT: &str = "Antivirus";

/// Une protection telle qu'Optimiser la propose : l'id de son réglage (celui de la note), son nom, ses préférences,
/// et si le bilan la propose d'office.
struct Protection {
    reglage: &'static str,
    nom: (&'static str, &'static str),
    prefs: Vec<Pref>,
    proposee: bool,
}

fn protections() -> Vec<Protection> {
    vec![
        Protection {
            reglage: "defender_asr_base",
            nom: ("blocages de base (ASR)", "basic blocking (ASR)"),
            prefs: ASR_BASE.iter().map(|id| Pref::Asr(id)).collect(),
            proposee: true,
        },
        Protection {
            reglage: "defender_reseau",
            nom: ("protection réseau", "network protection"),
            prefs: vec![Pref::ProtectionReseau],
            proposee: true,
        },
        Protection {
            reglage: "defender_pua",
            nom: ("logiciels indésirables (PUA)", "unwanted software (PUA)"),
            prefs: vec![Pref::Pua],
            proposee: true,
        },
        Protection {
            reglage: "defender_asr_bureautique",
            nom: ("documents et pièces jointes piégés", "booby-trapped documents"),
            prefs: ASR_BUREAUTIQUE.iter().map(|id| Pref::Asr(id)).collect(),
            proposee: false,
        },
        Protection {
            reglage: "defender_dossiers",
            nom: ("accès contrôlé aux dossiers", "controlled folder access"),
            prefs: vec![Pref::DossiersControles],
            proposee: false,
        },
    ]
}

fn nom(p: &Protection) -> &'static str {
    if crate::langue::anglais() { p.nom.1 } else { p.nom.0 }
}

/// Bloque (mode 1) pour chacune de ses préférences. L'audit (2) ou l'avertissement (6) signalent sans bloquer.
fn en_place(etat: &Etat, p: &Protection) -> bool {
    p.prefs.iter().all(|pref| etat.valeur(*pref).as_deref() == Some("mp:1"))
}

/// La correction qui la remet en blocage, avec ses gestes : la valeur d'avant de chaque préférence est relevée
/// juste avant (une règle ASR jamais réglée sera retirée à l'annulation, pas mise à « coupée »).
fn remettre(c: Constat, p: &Protection) -> Constat {
    let commandes: Vec<String> = p
        .prefs
        .iter()
        .filter_map(|pref| defender::commande(*pref, Some("mp:1")))
        .collect();
    let gestes = p
        .prefs
        .iter()
        .map(|pref| Geste::defender(defender::cle(*pref)))
        .collect();
    c.corriger(
        trf!(
            "Activer « {} » dans Defender (annulable dans « Ce que Vanguard a changé »)",
            "Turn on “{}” in Defender (can be undone in “What Vanguard changed”)",
            nom(p)
        ),
        &commandes,
    )
    .annulable(gestes)
}

/// Le jugement, d'après l'état lu (`None` : Defender n'a pas répondu) et les réglages dont Vanguard garde la note.
pub(super) fn juger(etat: Option<&Etat>, notes: &[String]) -> Vec<Constat> {
    let Some(etat) = etat.filter(|e| e.lu) else {
        return vec![crate::machine::impossible_par(
            CAT,
            Raison::Illisible("Get-MpPreference".into()),
            tr!(
                "Impossible de vérifier les protections de Defender (règles ASR, protection réseau, PUA) : Defender n'a pas répondu.",
                "Could not check Defender's protections (ASR rules, network protection, PUA): Defender did not answer."
            ),
        )];
    };
    if !etat.actif {
        return vec![sans_objet(
            CAT,
            Absence::Logiciel,
            tr!(
                "Defender n'est pas l'antivirus actif (un autre antivirus le met en pause, ou il est coupé : voir la règle de l'antivirus) : ses blocages ne s'appliquent pas ici.",
                "Defender is not the active antivirus (another antivirus pauses it, or it is off: see the antivirus rule): its blocking does not apply here."
            ),
        )];
    }
    // Microsoft n'applique ces blocages qu'avec la protection en temps réel : coupée, des réglages restés à 1 ne
    // bloquent rien, et les dire « qui bloquent » serait faux. La règle de l'antivirus signale déjà la coupure.
    if etat.temps_reel == Some(false) {
        return vec![sans_objet(
            CAT,
            Absence::Logiciel,
            tr!(
                "La protection en temps réel de Defender est coupée (voir la règle de l'antivirus) : ses blocages (ASR, protection réseau, PUA, dossiers) ne s'appliquent pas.",
                "Defender's real-time protection is off (see the antivirus rule): its blocking (ASR, network protection, PUA, folders) does not apply."
            ),
        )];
    }
    let mut constats = Vec::new();
    let (mut actives, mut autres) = (Vec::new(), Vec::new());
    for p in protections() {
        let objet = Objet::de("defender", p.reglage);
        if en_place(etat, &p) {
            actives.push(nom(&p));
        } else if notes.iter().any(|n| {
            // Posée par Optimiser (l'id du réglage) ou par une correction du bilan (« bilan:<id> », que seul son
            // geste « defender|np » relie à la protection).
            *n == p.reglage || p.prefs.iter().any(|pref| *n == Geste::defender(defender::cle(*pref)).0)
        }) {
            constats.push(remettre(
                alerte(
                    CAT,
                    Niveau::Eleve,
                    trf!(
                        "Defender : « {} » ne bloque plus, alors que Vanguard l'avait activée. Un programme l'a coupée (un logiciel malveillant le fait avant d'agir), ou quelqu'un l'a changée dans Sécurité Windows.",
                        "Defender: “{}” no longer blocks, although Vanguard had turned it on. A program turned it off (malware does so before acting), or someone changed it in Windows Security.",
                        nom(&p)
                    ),
                )
                .avec_objet(objet),
                &p,
            ));
        } else if p.proposee {
            constats.push(remettre(
                alerte(
                    CAT,
                    Niveau::Info,
                    trf!(
                        "Defender : « {} » n'est pas activée. C'est Windows qui bloquerait lui-même, et il se protège contre la désactivation ; rien n'est bloqué par Vanguard.",
                        "Defender: “{}” is not turned on. Windows itself would do the blocking, and it protects itself against being turned off; Vanguard blocks nothing.",
                        nom(&p)
                    ),
                )
                .avec_objet(objet),
                &p,
            ));
        } else {
            autres.push(nom(&p));
        }
    }
    // Ce qui bloque, et ce qui reste au choix, à côté des alertes. Un sain seulement si quelque chose bloque :
    // « à choisir » seul dirait sain un Defender où rien ne bloque (les alertes des proposées sont là, de toute façon).
    if !actives.is_empty() {
        let mut texte = trf!(
            "Protections de Defender qui bloquent : {}.",
            "Defender protections that block: {}.",
            actives.join(", ")
        );
        if !autres.is_empty() {
            texte.push_str(&trf!(
                " À choisir dans Optimiser si vous voulez : {}.",
                " To choose in Optimize if you want: {}.",
                autres.join(", ")
            ));
        }
        constats.push(ok(CAT, texte));
    }
    constats
}

/// Lu à chaque bilan, jamais pris dans ce qu'Optimiser a gardé : une protection coupée entre deux bilans doit se
/// voir au suivant.
pub(super) fn protections_de_defender() -> Vec<Constat> {
    defender::oublier();
    let etat = defender::etat();
    juger(Some(&etat), &crate::optimiser::reglages_poses())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modele::Etat as EtatConstat;

    fn lu(texte: &str) -> Etat {
        defender::lire_sortie(texte)
    }

    const BASE: &str = "asr|56a863a9-875e-4185-98a7-b882c64b5ce5|1\nasr|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2|1\n\
                        asr|e6db77e5-3df2-4cf1-b95a-636979351e5b|1\n";

    #[test]
    fn rien_lu_non_verifie_et_defender_passif_sans_objet() {
        let c = juger(None, &[]);
        assert_eq!(c.len(), 1);
        assert!(matches!(c[0].etat(), EtatConstat::NonVerifie(Raison::Illisible(_))));
        let c = juger(Some(&lu("")), &[]);
        assert!(matches!(c[0].etat(), EtatConstat::NonVerifie(_)));
        let c = juger(Some(&lu("mode|Passive Mode\nav|True\n")), &["defender_reseau".into()]);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].etat(), EtatConstat::SansObjet(Absence::Logiciel));
    }

    #[test]
    fn tout_en_place_un_seul_sain() {
        let e = lu(&format!("mode|Normal\nav|True\nrtp|True\ncfa|0\nnp|1\npua|1\n{BASE}"));
        let c = juger(Some(&e), &[]);
        assert_eq!(c.len(), 1, "{:?}", c.iter().map(|c| &c.message).collect::<Vec<_>>());
        assert_eq!(c[0].etat(), EtatConstat::Sain);
        assert!(c[0].coherent());
    }

    /// Temps réel coupé : les réglages restés à 1 ne bloquent rien, jamais dits sains.
    #[test]
    fn temps_reel_coupe_jamais_sain() {
        let e = lu(&format!("mode|Normal\nav|True\nrtp|False\ncfa|0\nnp|1\npua|1\n{BASE}"));
        let c = juger(Some(&e), &["defender_reseau".into()]);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].etat(), EtatConstat::SansObjet(Absence::Logiciel));
        assert!(c[0].coherent());
    }

    /// Posée par une correction du bilan (note « bilan:<id> », geste « defender|np ») puis coupée : élevée aussi.
    #[test]
    fn coupee_apres_correction_du_bilan_elevee() {
        let e = lu(&format!("mode|Normal\nav|True\nnp|0\npua|1\n{BASE}"));
        let c = juger(Some(&e), &["bilan:x".into(), "defender|np".into()]);
        let a = c
            .iter()
            .find(|c| c.objet == Objet::de("defender", "defender_reseau"))
            .unwrap();
        assert_eq!(a.probleme, Some(Niveau::Eleve));
        // Le geste d'une règle ASR de base suffit pour la sienne.
        let e = lu("mode|Normal\nav|True\nnp|1\npua|1\n");
        let geste = Geste::defender(defender::cle(Pref::Asr(ASR_BASE[0]))).0;
        let c = juger(Some(&e), &["bilan:y".into(), geste]);
        let a = c
            .iter()
            .find(|c| c.objet == Objet::de("defender", "defender_asr_base"))
            .unwrap();
        assert_eq!(a.probleme, Some(Niveau::Eleve));
    }

    /// Jamais posées : les trois sans revers proposées (information, sans pénalité), avec leur correction annulable ;
    /// les deux autres seulement citées.
    #[test]
    fn jamais_posees_proposees_sans_penalite() {
        let e = lu("mode|Normal\nav|True\ncfa|0\nnp|0\npua|0\n");
        let c = juger(Some(&e), &[]);
        let alertes: Vec<&Constat> = c.iter().filter(|c| c.probleme.is_some()).collect();
        assert_eq!(alertes.len(), 3);
        for a in &alertes {
            assert_eq!(a.probleme, Some(Niveau::Info));
            let k = a.correctif.as_ref().unwrap();
            assert!(k.automatique && !k.commandes.is_empty());
            assert!(k.pourquoi_pas().is_none(), "{}", k.action);
            assert!(matches!(a.objet, Objet::De(_)) && a.coherent());
        }
        let base = alertes.iter().find(|a| a.message.contains("ASR")).unwrap();
        let k = base.correctif.as_ref().unwrap();
        assert_eq!(k.commandes.len(), 3);
        assert!(k.commandes[0].starts_with("Add-MpPreference -AttackSurfaceReductionRules_Ids"));
        // Rien ne bloque : aucun sain, seulement les alertes.
        assert!(c.iter().all(|c| c.etat() != EtatConstat::Sain));
        assert_eq!(c.len(), 3);
    }

    /// Posée par Vanguard puis coupée : alerte élevée, même pour une protection que le bilan ne propose pas d'office.
    #[test]
    fn coupee_apres_vanguard_elevee() {
        let e = lu(&format!("mode|Normal\nav|True\ncfa|0\nnp|1\npua|1\n{BASE}"));
        let c = juger(Some(&e), &["defender_dossiers".into(), "bilan:x".into()]);
        let a: Vec<&Constat> = c.iter().filter(|c| c.probleme.is_some()).collect();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].probleme, Some(Niveau::Eleve));
        assert_eq!(
            a[0].correctif.as_ref().unwrap().commandes,
            ["Set-MpPreference -EnableControlledFolderAccess 1"]
        );
        assert_eq!(a[0].objet, Objet::de("defender", "defender_dossiers"));
        // En audit seulement (2), une règle ASR ne bloque pas.
        let e = lu("mode|Normal\nav|True\nnp|1\npua|1\nasr|56a863a9-875e-4185-98a7-b882c64b5ce5|2\n");
        let c = juger(Some(&e), &["defender_asr_base".into()]);
        assert!(c.iter().any(|c| c.probleme == Some(Niveau::Eleve)));
    }

    /// Les gestes des corrections sont ceux de la liste fermée (`relever` refuse tout autre geste avant même de le
    /// lire) ; un nom hors de la liste, ou mal formé, est refusé.
    #[test]
    fn gestes_admis_par_la_liste_fermee() {
        use crate::optimiser::annulables::{PourquoiPas, relever};
        let hors_liste = |g: &str| {
            matches!(
                relever("bilan:essai".into(), "essai", &[Geste(g.into())]),
                Err(PourquoiPas::HorsListe(_))
            )
        };
        for p in protections() {
            for pref in &p.prefs {
                let g = Geste::defender(defender::cle(*pref));
                assert!(!hors_liste(&g.0), "{}", g.0);
            }
        }
        assert!(hors_liste("defender|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"));
        assert!(hors_liste("defender|np|x"));
    }
}

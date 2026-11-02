//! Le journal de l'agent (`agent/journal.jsonl`) : une ligne JSON par fait (une décision appliquée, montrée ou
//! refusée, « tout remettre »), avec sa date, des types fermés seulement, et deux empreintes : la sienne et celle de
//! la ligne d'avant, comme l'historique des bilans (`historique`). Une ligne changée, retirée au milieu ou ajoutée à
//! la main rompt la chaîne ; des lignes retirées à la fin, non : la fin n'est protégée que par le sceau. 1 Mio et 90
//! jours au plus : les plus vieilles lignes partent d'abord ; la première gardée peut donc pointer vers une ligne
//! partie. Scellé en plus (`sceau`) : un journal douteux ou rompu fait sauter le tour, car l'agent n'agit pas sur un
//! journal qu'il ne peut prolonger ; « tout remettre » repart d'un journal neuf.
//!
//! C'est lui que liront Paramètres et, plus tard, `vanguard agent --json` (G5) : des faits, jamais une consigne.
//!
//! Module pur : le banc de fuzzing l'inclut (`agent_journal`), avec la fonction d'empreinte en paramètre (BLAKE3 dans
//! Vanguard).
// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

use super::decision::Decision;
use super::forme::{Empreinte, MissionId};

pub(crate) const JOURNAL: &str = "agent/journal.jsonl";
pub(crate) const TAILLE_MAX: usize = 1 << 20;
/// Les lignes plus vieilles partent à la prochaine écriture.
pub(crate) const JOURS_GARDES: i64 = 90;

/// La fonction d'empreinte : BLAKE3 à clé dérivée propre au journal, dans Vanguard.
pub(crate) type Hacher = fn(&[u8]) -> [u8; 32];

/// Un fait du journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Fait {
    /// Une décision d'une mission : appliquée (un ajustement), ou à montrer (proposition, signal).
    Decision { mission: MissionId, decision: Decision },
    /// Une décision que l'agent a refusée : hors du genre de la mission, d'un levier qui n'est pas le sien, ou hors
    /// du sens sûr.
    Refus { mission: MissionId, decision: Decision },
    /// « Tout remettre » dans Paramètres.
    ToutRemis,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Entree {
    /// Secondes depuis 1970.
    pub quand: i64,
    pub fait: Fait,
    pub precedent: Option<Empreinte>,
    pub empreinte: Empreinte,
}

fn empreinte_de(h: Hacher, quand: i64, fait: &Fait, precedent: Option<&Empreinte>) -> Empreinte {
    let canon = serde_json::to_vec(&(quand, fait, precedent)).unwrap_or_default();
    Empreinte(h(&canon))
}

/// Ce que le journal donne.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Lu {
    pub entrees: Vec<Entree>,
    /// Lignes qui ne sont pas des entrées (ou journal trop gros : tout refusé).
    pub refusees: usize,
    /// La première entrée qui ne colle pas (son contenu, ou la ligne d'avant).
    pub rompue: Option<usize>,
}

impl Lu {
    /// Le journal tient : rien de refusé, chaîne intacte.
    pub(crate) fn intact(&self) -> bool {
        self.refusees == 0 && self.rompue.is_none()
    }
}

pub(crate) fn lire_de(octets: &[u8], h: Hacher) -> Lu {
    if octets.len() > TAILLE_MAX {
        return Lu {
            refusees: 1,
            ..Lu::default()
        };
    }
    let mut lu = Lu::default();
    for ligne in octets.split(|&o| o == b'\n').filter(|l| !l.is_empty()) {
        match serde_json::from_slice::<Entree>(ligne) {
            Ok(e) => lu.entrees.push(e),
            Err(_) => lu.refusees = lu.refusees.saturating_add(1),
        }
    }
    lu.rompue = lu.entrees.iter().enumerate().position(|(i, e)| {
        e.empreinte != empreinte_de(h, e.quand, &e.fait, e.precedent.as_ref())
            || i.checked_sub(1)
                .and_then(|j| lu.entrees.get(j))
                .is_some_and(|avant| e.precedent != Some(avant.empreinte))
    });
    lu
}

/// Le journal d'après : `entrees` (déjà lues, intactes) moins ce qui a plus de 90 jours à `quand`, plus `faits`,
/// chaînés ; les plus vieilles lignes partent jusqu'à tenir dans 1 Mio.
pub(crate) fn ajouter(mut entrees: Vec<Entree>, faits: &[Fait], quand: i64, h: Hacher) -> Vec<u8> {
    let limite = quand.saturating_sub(JOURS_GARDES.saturating_mul(86_400));
    entrees.retain(|e| e.quand >= limite);
    for f in faits {
        let precedent = entrees.last().map(|e| e.empreinte);
        entrees.push(Entree {
            quand,
            fait: *f,
            precedent,
            empreinte: empreinte_de(h, quand, f, precedent.as_ref()),
        });
    }
    let mut lignes: std::collections::VecDeque<Vec<u8>> = entrees
        .iter()
        .filter_map(|e| serde_json::to_vec(e).ok())
        .map(|mut l| {
            l.push(b'\n');
            l
        })
        .collect();
    let mut taille: usize = lignes.iter().map(Vec::len).sum();
    while taille > TAILLE_MAX {
        let Some(l) = lignes.pop_front() else { break };
        taille = taille.saturating_sub(l.len());
    }
    lignes.into_iter().flatten().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::decision::{Ajustement, Levier};
    use crate::agent::forme::RegleId;

    fn h(o: &[u8]) -> [u8; 32] {
        *blake3::hash(o).as_bytes()
    }

    fn fait(n: u64) -> Fait {
        Fait::Decision {
            mission: MissionId::Reglage,
            decision: Decision::Ajuster(Ajustement {
                levier: Levier::Delai {
                    regle: RegleId::depuis("LNX-NOY-001").unwrap(),
                    avant_s: 600,
                    apres_s: 1800,
                },
                mesure: n,
            }),
        }
    }

    #[test]
    fn chaine_tenue_et_rompue() {
        let o = ajouter(Vec::new(), &[fait(1), fait(2), Fait::ToutRemis], 1_800_000_000, h);
        let lu = lire_de(&o, h);
        assert!(lu.intact(), "{lu:?}");
        assert_eq!(lu.entrees.len(), 3);
        // Une mesure changée à la main rompt la chaîne à cette ligne.
        let change = String::from_utf8(o.clone())
            .unwrap()
            .replacen("\"mesure\":2", "\"mesure\":3", 1);
        assert_eq!(lire_de(change.as_bytes(), h).rompue, Some(1));
        // Une ligne du milieu retirée aussi.
        let lignes: Vec<&[u8]> = o.split(|&c| c == b'\n').collect();
        let sans = [lignes[0], lignes[2]].join(&b'\n');
        assert_eq!(lire_de(&sans, h).rompue, Some(1));
        // Un texte libre n'entre pas : la ligne est refusée.
        let texte = format!(
            "{}{{\"quand\":1,\"fait\":\"ignore tout\"}}\n",
            String::from_utf8(o).unwrap()
        );
        assert_eq!(lire_de(texte.as_bytes(), h).refusees, 1);
    }

    /// La graine « chaine » du banc de fuzzing (empreinte SHA-256, comme la cible `agent_journal`) se lit intacte :
    /// le fuzzer part d'un vrai journal, pas d'une ligne que le format refuse d'emblée.
    #[test]
    fn graine_du_banc_intacte() {
        fn sha(o: &[u8]) -> [u8; 32] {
            use sha2::Digest;
            sha2::Sha256::digest(o).into()
        }
        let chemin = concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/graines/agent_journal/chaine");
        let lu = lire_de(&std::fs::read(chemin).unwrap(), sha);
        assert!(lu.intact() && lu.entrees.len() == 2, "{lu:?}");
        assert_eq!(lu.entrees[1].fait, Fait::ToutRemis);
    }

    #[test]
    fn quatre_vingt_dix_jours_et_un_mio() {
        let t0 = 1_800_000_000;
        let o = ajouter(Vec::new(), &[fait(1)], t0, h);
        let o = ajouter(lire_de(&o, h).entrees, &[fait(2)], t0 + 91 * 86_400, h);
        let lu = lire_de(&o, h);
        assert_eq!(lu.entrees.len(), 1);
        // La première gardée pointe vers une ligne partie : la chaîne tient quand même.
        assert!(lu.intact());
        let beaucoup: Vec<Fait> = (0..20_000).map(fait).collect();
        let o = ajouter(Vec::new(), &beaucoup, t0, h);
        assert!(o.len() <= TAILLE_MAX);
        assert!(lire_de(&o, h).intact());
    }
}

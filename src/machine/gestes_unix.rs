//! La grammaire des gestes de Linux que l'assistant élevé (`machine::assistant`) fait en root, à côté des ordres du
//! blocage (`protection::blocage::ordres`) : une ligne « `vanguard:geste <famille> <champs>` » ne fait que DÉSIGNER
//! un geste d'une liste fermée, et l'enfant root la relit, la rejuge avec ses propres yeux, puis le fait sans shell,
//! par le chemin absolu de l'outil (`commande::outil_systeme`) et dans un environnement vidé
//! (`commande::environnement_propre`). Rien ici ne lance quoi que ce soit : du code pur, sans E/S, compilé partout
//! pour ses tests et lu par le banc de fuzzing (fuzz/fuzz_targets/gestes_unix.rs).
//!
//! Une seule famille pour l'instant, `programme <id>` : un programme de la table `PROGRAMMES`, avec ses arguments
//! figés. La ligne ne porte ni chemin, ni argument, ni texte libre : seulement l'identifiant. Les familles des
//! paquets, des unités systemd, des fichiers de configuration et du réseau suivront (plan du lot Unix, U2 à U7), sur
//! le même canal et avec les mêmes bornes.
//!
//! Un geste qui affaiblit la protection ou supprime quelque chose porte `affaiblit` ou `supprime` : l'enfant demande
//! alors l'accord de la personne sur son terminal (/dev/tty), et le refuse sans terminal (`assistant`).

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

/// Devant chaque geste : le préfixe des ordres (`ordres::PREFIXE`) suivi de « geste », un verbe qu'aucun ordre ni
/// aucun geste de Windows (`gestes.rs` : `vanguard:programme`, `vanguard:service`…) ne prend.
pub(crate) const PREFIXE: &str = "vanguard:geste ";
/// La plus longue ligne admise sur le canal : celle d'un ordre du blocage, `ordres::LIGNE_MAX` (repris ici pour que le
/// banc de fuzzing lise ce module seul ; l'essai `bornes_du_canal_communes_avec_les_ordres` les garde égales). Le
/// nombre de lignes d'une liste est borné par le canal lui-même (`ordres::LIGNES_MAX`, lu par l'assistant).
pub(crate) const LIGNE_MAX: usize = 8448;
/// La plus longue ligne d'un geste : un identifiant de la table, court ; tout ce qui dépasse est refusé avant d'être
/// découpé.
pub(crate) const GESTE_MAX: usize = 128;
const _: () = assert!(GESTE_MAX <= LIGNE_MAX, "un geste tient dans une ligne du canal");

/// Un programme figé : l'outil, cherché par l'enfant dans les dossiers du système, et ses arguments, tous écrits ici.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Programme {
    /// `[a-z0-9-]`, 40 caractères au plus.
    pub id: &'static str,
    /// Le nom de l'outil, sans dossier : l'enfant le cherche par `commande::outil_systeme`, jamais par un PATH.
    pub outil: &'static str,
    pub arguments: &'static [&'static str],
    /// Les codes de sortie qui veulent dire « fait ».
    pub reussites: &'static [i32],
    /// Le délai, en secondes, au-delà duquel l'outil est arrêté et le geste compté en échec.
    pub delai: u64,
    /// Le geste baisse une protection (le remettre comme avant, après un durcissement) : accord sur le terminal.
    pub affaiblit: bool,
    /// Le geste supprime quelque chose : accord sur le terminal.
    pub supprime: bool,
    pub fr: &'static str,
    pub en: &'static str,
}

/// Les signatures de ClamAV : freshclam les télécharge. Seul 0 veut dire « fait » ; tout autre code est une erreur
/// (réseau, miroir, base verrouillée par le service clamav-freshclam), rendue avec sa raison.
pub(crate) static FRESHCLAM: Programme = Programme {
    id: "freshclam",
    outil: "freshclam",
    arguments: &[],
    reussites: &[0],
    delai: 900,
    affaiblit: false,
    supprime: false,
    fr: "Mettre à jour les signatures de virus de ClamAV (freshclam)",
    en: "Update the ClamAV virus signatures (freshclam)",
};

/// La table : un identifiant n'y est qu'une fois (essai `la_table_est_bien_formee`).
pub(crate) static PROGRAMMES: &[&Programme] = &[&FRESHCLAM];

/// Un geste désigné par une ligne, relu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GesteUnix {
    Programme(&'static Programme),
}

impl GesteUnix {
    /// La ligne qui le porte ; `analyser(g.ligne()) == Some(g)`.
    pub(crate) fn ligne(self) -> String {
        match self {
            GesteUnix::Programme(p) => format!("{PREFIXE}programme {}", p.id),
        }
    }

    /// Ce que fait le geste, en une phrase (française et anglaise) : montrée avant l'accord, par le parent, puis par
    /// l'enfant avant de le faire.
    pub(crate) fn phrase(self) -> (&'static str, &'static str) {
        match self {
            GesteUnix::Programme(p) => (p.fr, p.en),
        }
    }

    /// L'enfant demande-t-il l'accord de la personne, sur son terminal, avant de le faire ?
    pub(crate) fn demande_accord(self) -> bool {
        match self {
            GesteUnix::Programme(p) => p.affaiblit || p.supprime,
        }
    }

    /// Le geste a-t-il un sens sur ce système ? Linux seulement : sous macOS, rien n'est converti avant un essai sur un
    /// vrai Mac (plan du lot Unix, D8).
    #[allow(
        clippy::unused_self,
        reason = "les familles à venir (paquets, unités) diront chacune où elles valent"
    )]
    pub(crate) fn permis_ici(self) -> bool {
        cfg!(target_os = "linux")
    }
}

/// Un identifiant de la table : minuscules ASCII, chiffres et tirets, 40 caractères au plus.
fn identifiant(t: &str) -> bool {
    !t.is_empty() && t.len() <= 40 && t.bytes().all(|o| matches!(o, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

/// Le geste que porte une ligne, si et seulement si la ligne est exactement sa forme admise : le préfixe, une famille
/// de la liste, des champs séparés par une seule espace, réécrits à l'identique (une majuscule, une espace de trop, un
/// champ en plus, un octet nul : refusés).
pub(crate) fn analyser(ligne: &str) -> Option<GesteUnix> {
    if ligne.len() > GESTE_MAX {
        return None;
    }
    let reste = ligne.strip_prefix(PREFIXE)?;
    let mots: Vec<&str> = reste.split(' ').collect();
    let geste = match mots.as_slice() {
        ["programme", id] if identifiant(id) => GesteUnix::Programme(PROGRAMMES.iter().copied().find(|p| p.id == *id)?),
        _ => return None,
    };
    (geste.ligne() == ligne).then_some(geste)
}

/// La ligne commence-t-elle comme un geste (bien formé ou non) ? Une telle ligne n'est jamais confiée à un shell :
/// refusée si elle ne se relit pas.
pub(crate) fn a_le_prefixe(ligne: &str) -> bool {
    ligne.starts_with(PREFIXE)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Les bornes reprises d'`ordres` restent les siennes : le canal n'a qu'une limite.
    #[test]
    fn bornes_du_canal_communes_avec_les_ordres() {
        use crate::protection::blocage::ordres;
        assert_eq!(LIGNE_MAX, ordres::LIGNE_MAX);
        assert!(PREFIXE.starts_with(ordres::PREFIXE));
    }

    #[test]
    fn la_table_est_bien_formee() {
        let mut vus = std::collections::HashSet::new();
        for p in PROGRAMMES {
            assert!(identifiant(p.id), "{}", p.id);
            assert!(vus.insert(p.id), "{} en double", p.id);
            // L'outil est un nom, jamais un chemin ni une option.
            assert!(identifiant(p.outil), "{}", p.outil);
            assert!(!p.reussites.is_empty() && p.delai > 0);
            assert!(!p.fr.is_empty() && !p.en.is_empty());
            // Aucun argument ne fait passer un shell, une expansion ou un saut de ligne.
            for a in p.arguments {
                assert!(
                    !a.is_empty() && !a.contains(['\0', '\n', '\r', '$', '`', ';', '|', '&']),
                    "{a}"
                );
            }
            let g = GesteUnix::Programme(p);
            assert!(g.ligne().len() <= GESTE_MAX);
        }
    }

    /// Propriété : chaque geste de la table se relit tel quel (`analyser(ligne(g)) == g`).
    #[test]
    fn aller_retour_de_chaque_geste() {
        for p in PROGRAMMES {
            let g = GesteUnix::Programme(p);
            assert_eq!(analyser(&g.ligne()), Some(g));
            assert!(a_le_prefixe(&g.ligne()));
        }
    }

    /// Une ligne qui n'a pas exactement la forme d'un geste n'en désigne aucun.
    #[test]
    fn refus_de_l_etranger() {
        for l in [
            "",
            "vanguard:geste",
            "vanguard:geste ",
            "vanguard:geste programme",
            "vanguard:geste programme ",
            "vanguard:geste programme inconnu",
            "vanguard:geste programme FRESHCLAM",
            "vanguard:geste programme freshclam ",
            "vanguard:geste programme  freshclam",
            "vanguard:geste programme freshclam --datadir=/tmp",
            "vanguard:geste programme freshclam\0",
            "vanguard:geste programme freshclam\n",
            "vanguard:geste programme ../freshclam",
            "vanguard:geste programme /usr/bin/freshclam",
            "vanguard:geste famille-inconnue freshclam",
            "vanguard:geste Programme freshclam",
            " vanguard:geste programme freshclam",
            "vanguard:programme freshclam",
            "sudo freshclam",
        ] {
            assert_eq!(analyser(l), None, "{l:?}");
        }
        let longue = format!("{PREFIXE}programme {}", "a".repeat(GESTE_MAX));
        assert_eq!(analyser(&longue), None);
        let tres_longue = format!("{PREFIXE}programme freshclam{}", " ".repeat(LIGNE_MAX));
        assert_eq!(analyser(&tres_longue), None);
    }

    /// Un geste de Linux n'est permis que sous Linux (aucun sous macOS, plan D8).
    #[test]
    fn permis_sous_linux_seulement() {
        assert_eq!(GesteUnix::Programme(&FRESHCLAM).permis_ici(), cfg!(target_os = "linux"));
        assert!(!GesteUnix::Programme(&FRESHCLAM).demande_accord());
    }
}

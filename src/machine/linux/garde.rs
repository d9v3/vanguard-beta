//! Le garde des lancements (Défense L3) : le service système `vanguard-garde`, root, qui reçoit de fanotify (L2) la
//! demande de permission de chaque exécution et refuse ce qui est CERTAINEMENT malveillant (P10), en mode « refus »
//! seulement ; en « observation » (le mode d'une première pose), tout passe et ce qu'il aurait refusé est noté.
//!
//! Les parties :
//! - `decision`, `cache`, `unite` : du code pur (le verdict, le cache par inode, le texte de l'unité) ;
//! - `listes` : l'ensemble CERTAIN, deux fichiers triés de 32 octets préparés par le compte (`compte`) et relus en root
//!   sans aucun lecteur de format (P22) : une liste forgée ne peut que rendre plus strict, les exceptions P11 gardent
//!   le système ;
//! - `servir` : le service (`vanguard garde-servir`, sous-commande cachée) ; `notifier` : sd_notify ; `sortie` :
//!   /run/vanguard/garde/etat.json et evenements.jsonl, lus par le compte ;
//! - `poser` : les ordres de l'assistant root (`GardePoser`… `GardeRetirer`) ;
//! - `compte` : ce que fait le Vanguard du compte (`vanguard garde on|off|etat|maj`, les listes, l'état lu).
//!
//! Le garde ne lance jamais une copie que le compte peut écrire : son programme est la copie, root:root 0755 dans
//! /opt/vanguard/garde, de l'assistant root qui l'a posé. Ses réglages (mode, pause, empreintes permises) ne
//! se lisent que dans /etc/vanguard, écrits par les ordres, avec le mot de passe.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

mod attente;
pub(crate) mod cache;
pub(crate) mod compte;
pub(crate) mod decision;
pub(crate) mod listes;
mod notifier;
mod poser;
pub(crate) mod servir;
pub(crate) mod sortie;
pub(crate) mod unite;

use serde::{Deserialize, Serialize};

pub(crate) use poser::{faire_ordre, juger_pose};

/// Le nom de l'unité.
pub(crate) const UNITE: &str = "vanguard-garde.service";
/// Le fichier de l'unité, écrit par la pose.
pub(crate) const FICHIER_UNITE: &str = "/etc/systemd/system/vanguard-garde.service";
/// Le dossier du programme du garde (à root seul). Dans /opt, pas dans /usr/local/lib : sous SELinux (Fedora), un
/// programme de /usr/local/lib porte lib_t, que systemd lance sans changer de domaine (init_t, qui ne peut pas marquer
/// un système de fichiers : le garde ne démarrerait jamais) ; ce qui est créé dans /opt porte usr_t, comme le veut
/// la politique pour ce chemin, et tourne en unconfined_service_t, même après un réétiquetage complet.
pub(crate) const DOSSIER_PROGRAMME: &str = "/opt/vanguard/garde";
/// Le programme du garde : la copie de l'assistant root qui l'a posé.
pub(crate) const PROGRAMME: &str = "/opt/vanguard/garde/vanguard";
/// Le dossier des réglages root de Vanguard.
pub(crate) const DOSSIER_REGLAGES: &str = "/etc/vanguard";
/// Les réglages du garde (root:root 0644) : le compte les lit, seuls les ordres les écrivent.
pub(crate) const REGLAGES: &str = "/etc/vanguard/garde.json";
/// Le dossier d'état du garde (StateDirectory de l'unité, 0700) : retiré avec lui.
pub(crate) const DOSSIER_ETAT: &str = "/var/lib/vanguard/garde";
/// Le battement, la version, le mode et les compteurs, réécrits chaque seconde.
pub(crate) const ETAT: &str = "/run/vanguard/garde/etat.json";
/// Les événements, une ligne JSON chacun ; à `sortie::EVENEMENTS_TAILLE_MAX`, l'ancien devient `EVENEMENTS_ANCIENS`.
pub(crate) const EVENEMENTS: &str = "/run/vanguard/garde/evenements.jsonl";
pub(crate) const EVENEMENTS_ANCIENS: &str = "/run/vanguard/garde/evenements.1.jsonl";
/// Les deux listes de l'ensemble CERTAIN, dans le dossier du compte nommé par les réglages.
pub(crate) const LISTE_SHA256: &str = "certain-sha256.bin";
pub(crate) const LISTE_MD5: &str = "certain-md5.bin";
/// La version des réglages.
pub(crate) const VERSION_REGLAGES: u32 = 1;
/// Les empreintes permises par la personne, au plus.
pub(crate) const PERMISES_MAX: usize = 4096;
/// Les empreintes de Vanguard gardées (les dernières poses et mises à jour) : jamais refusées (P11).
pub(crate) const VANGUARD_MAX: usize = 4;
/// La taille des réglages relus, au plus.
pub(crate) const REGLAGES_TAILLE_MAX: u64 = 1 << 20;

/// Les réglages du garde, dans /etc/vanguard/garde.json.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reglages {
    pub version: u32,
    /// Le compte qui prépare les listes (jamais root).
    pub compte: u32,
    /// Son dossier des listes.
    pub listes: String,
    /// `true` : le certain est refusé ; `false` : observation.
    pub refus: bool,
    /// La fin de la pause, en secondes depuis 1970, s'il y en a une.
    pub pause_jusqu_a: Option<u64>,
    /// Les SHA-256 (hexadécimal) que la personne a permis.
    pub permises: Vec<String>,
    /// Les SHA-256 (hexadécimal) des programmes de Vanguard posés : jamais refusés.
    pub vanguard: Vec<String>,
}

impl Reglages {
    /// Relus d'un texte JSON : une autre version, un compte root, un dossier relatif, une empreinte mal écrite ou
    /// des listes démesurées, refusés en entier.
    pub(crate) fn lire(texte: &str) -> Option<Reglages> {
        let r: Reglages = serde_json::from_str(texte).ok()?;
        let empreinte = |e: &String| e.len() == 64 && e.bytes().all(|o| matches!(o, b'0'..=b'9' | b'a'..=b'f'));
        let valides = r.version == VERSION_REGLAGES
            && r.compte != 0
            && r.listes.starts_with('/')
            && !r.listes.contains(['\0', '\n'])
            && r.permises.len() <= PERMISES_MAX
            && r.vanguard.len() <= VANGUARD_MAX
            && r.permises.iter().chain(&r.vanguard).all(empreinte);
        valides.then_some(r)
    }

    /// En pause à cet instant (secondes depuis 1970) ?
    pub(crate) fn en_pause(&self, maintenant: u64) -> bool {
        self.pause_jusqu_a.is_some_and(|f| maintenant < f)
    }
}

/// Les secondes depuis 1970.
pub(crate) fn maintenant() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Une empreinte en hexadécimal minuscule relue en 32 octets.
pub(crate) fn empreinte_de(hex: &str) -> Option<[u8; 32]> {
    let o = hex.as_bytes();
    if o.len() != 64 {
        return None;
    }
    let chiffre = |c: u8| match c {
        b'0'..=b'9' => c.checked_sub(b'0'),
        b'a'..=b'f' => c.checked_sub(b'a').and_then(|v| v.checked_add(10)),
        _ => None,
    };
    let mut e = [0u8; 32];
    for (sortie, paire) in e.iter_mut().zip(o.as_chunks::<2>().0) {
        *sortie = chiffre(paire[0])?.checked_mul(16)?.checked_add(chiffre(paire[1])?)?;
    }
    Some(e)
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    fn reglages() -> Reglages {
        Reglages {
            version: VERSION_REGLAGES,
            compte: 1000,
            listes: "/home/alice/.local/share/vanguard/garde".into(),
            refus: false,
            pause_jusqu_a: None,
            permises: vec!["ab".repeat(32)],
            vanguard: vec!["cd".repeat(32)],
        }
    }

    #[test]
    fn reglages_relus_ou_refuses() {
        let r = reglages();
        let texte = serde_json::to_string(&r).unwrap();
        assert_eq!(Reglages::lire(&texte), Some(r.clone()));
        for mauvais in [
            Reglages { compte: 0, ..r.clone() },
            Reglages {
                version: 2,
                ..r.clone()
            },
            Reglages {
                listes: "relatif".into(),
                ..r.clone()
            },
            Reglages {
                permises: vec!["AB".repeat(32)],
                ..r.clone()
            },
            Reglages {
                vanguard: vec!["cd".repeat(32); VANGUARD_MAX + 1],
                ..r.clone()
            },
        ] {
            assert_eq!(
                Reglages::lire(&serde_json::to_string(&mauvais).unwrap()),
                None,
                "{mauvais:?}"
            );
        }
        assert_eq!(
            Reglages::lire(&texte.replace("\"refus\"", "\"inconnu\":1,\"refus\"")),
            None
        );
        assert_eq!(Reglages::lire("{"), None);
    }

    #[test]
    fn pause_bornee_dans_le_temps() {
        let r = Reglages {
            pause_jusqu_a: Some(100),
            ..reglages()
        };
        assert!(r.en_pause(99));
        assert!(!r.en_pause(100));
        assert!(!reglages().en_pause(0));
    }

    #[test]
    fn empreintes_relues() {
        assert_eq!(empreinte_de(&"0a".repeat(32)), Some([10u8; 32]));
        assert_eq!(empreinte_de(&"0A".repeat(32)), None);
        assert_eq!(empreinte_de("0a"), None);
        assert_eq!(empreinte_de(&"0g".repeat(32)), None);
    }
}

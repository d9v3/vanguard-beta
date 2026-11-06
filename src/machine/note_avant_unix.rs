//! La note d'« avant » d'un geste de défense de Linux (`gestes_unix::Defense`), telle que l'enfant root l'écrit dans
//! `/var/lib/vanguard/avant/<id>` (`assistant::defense`) : ses octets et leur lecture stricte. À part pour le banc de
//! fuzzing (`fuzz/fuzz_targets/note_avant_unix.rs`). La note n'est lue que si le fichier est à root, en 0600, dans un
//! dossier à root fermé aux autres : un compte sans droits ne peut ni l'écrire ni la remplacer ; l'empreinte ne fait
//! que refuser une note abîmée (disque plein, coupure pendant l'écriture), jamais l'authentifier.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

/// L'en-tête d'une note, version comprise : une autre version n'est jamais lue.
pub(crate) const ENTETE: &[u8] = b"VGAVX\x01";
/// La plus longue valeur d'un champ : un fichier de démarrage entier (`RetirerLigne`) tient dans 512 Kio.
pub(crate) const VALEUR_MAX: usize = 512 * 1024;
/// Le plus grand nombre de champs.
pub(crate) const CHAMPS_MAX: usize = 16;
/// La plus longue clé : `[a-z-]`, 24 octets.
pub(crate) const CLE_MAX: usize = 24;
/// La plus longue note admise : deux valeurs de la plus longue taille, et le reste.
pub(crate) const NOTE_MAX: usize = 2 * VALEUR_MAX + 16 * 1024;
/// L'empreinte qui clôt une note.
pub(crate) const EMPREINTE: usize = 32;

/// Une note d'« avant » : le geste qui l'a écrite (sa ligne exacte), quand, et ce qu'il a trouvé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Note {
    /// La ligne du geste (`GesteUnix::ligne`), ASCII ; son identifiant est celui de la note.
    pub(crate) geste: String,
    /// Secondes depuis 1970 (UTC).
    pub(crate) date: u64,
    /// Les valeurs d'avant, chacune sous une clé distincte.
    pub(crate) champs: Vec<(String, Vec<u8>)>,
}

fn cle_admise(c: &str) -> bool {
    !c.is_empty() && c.len() <= CLE_MAX && c.bytes().all(|o| o.is_ascii_lowercase() || o == b'-')
}

impl Note {
    /// La valeur de cette clé.
    pub(crate) fn champ(&self, cle: &str) -> Option<&[u8]> {
        self.champs.iter().find(|(c, _)| c == cle).map(|(_, v)| v.as_slice())
    }

    /// La valeur de cette clé, en texte UTF-8.
    pub(crate) fn texte(&self, cle: &str) -> Option<&str> {
        std::str::from_utf8(self.champ(cle)?).ok()
    }

    /// Les octets de la note sous l'identifiant `id` : en-tête, l'identifiant et la ligne du geste (longueur sur
    /// 2 octets petit-boutiste, puis le texte ASCII), la date sur 8 octets, le nombre de champs sur 1 octet, chaque
    /// champ (la clé, longueur sur 1 octet ; la valeur, longueur sur 4 octets), puis le SHA-256 de tout ce qui
    /// précède. `None` : une note qui ne se relirait pas (clé, borne, texte non ASCII).
    pub(crate) fn octets(&self, id: &str) -> Option<Vec<u8>> {
        if !id.is_ascii() || !self.geste.is_ascii() || self.champs.len() > CHAMPS_MAX {
            return None;
        }
        let mut o = ENTETE.to_vec();
        for t in [id, self.geste.as_str()] {
            o.extend_from_slice(&u16::try_from(t.len()).ok()?.to_le_bytes());
            o.extend_from_slice(t.as_bytes());
        }
        o.extend_from_slice(&self.date.to_le_bytes());
        o.push(u8::try_from(self.champs.len()).ok()?);
        for (i, (c, v)) in self.champs.iter().enumerate() {
            if !cle_admise(c) || v.len() > VALEUR_MAX || self.champs.iter().take(i).any(|(d, _)| d == c) {
                return None;
            }
            o.push(u8::try_from(c.len()).ok()?);
            o.extend_from_slice(c.as_bytes());
            o.extend_from_slice(&u32::try_from(v.len()).ok()?.to_le_bytes());
            o.extend_from_slice(v);
        }
        if o.len().checked_add(EMPREINTE)? > NOTE_MAX {
            return None;
        }
        let empreinte = Sha256::digest(&o);
        o.extend_from_slice(&empreinte);
        Some(o)
    }

    /// La note `id`, si et seulement si ses octets en ont la forme exacte : bornée, empreinte juste, bonne version,
    /// identifiant égal à celui demandé (une note copiée sous un autre nom est refusée), textes ASCII, clés admises et
    /// distinctes, rien après. `None` sinon : rien n'est remis d'après elle.
    pub(crate) fn lire(id: &str, octets: &[u8]) -> Option<Note> {
        if octets.len() > NOTE_MAX {
            return None;
        }
        let (corps, empreinte) = octets.split_at(octets.len().checked_sub(EMPREINTE)?);
        if Sha256::digest(corps).as_slice() != empreinte {
            return None;
        }
        let mut reste = corps.strip_prefix(ENTETE)?;
        let mut textes = Vec::with_capacity(2);
        for _ in 0..2 {
            let (n, suite) = reste.split_first_chunk::<2>()?;
            let n = usize::from(u16::from_le_bytes(*n));
            let t = suite.get(..n)?;
            if !t.is_ascii() {
                return None;
            }
            textes.push(std::str::from_utf8(t).ok()?.to_string());
            reste = suite.get(n..)?;
        }
        let (date, suite) = reste.split_first_chunk::<8>()?;
        let (nombre, mut reste) = suite.split_first()?;
        if usize::from(*nombre) > CHAMPS_MAX {
            return None;
        }
        let mut champs: Vec<(String, Vec<u8>)> = Vec::with_capacity(usize::from(*nombre));
        for _ in 0..*nombre {
            let (n, suite) = reste.split_first()?;
            let c = std::str::from_utf8(suite.get(..usize::from(*n))?).ok()?;
            if !cle_admise(c) || champs.iter().any(|(d, _)| d == c) {
                return None;
            }
            let (l, suite) = suite.get(usize::from(*n)..)?.split_first_chunk::<4>()?;
            let l = usize::try_from(u32::from_le_bytes(*l)).ok()?;
            if l > VALEUR_MAX {
                return None;
            }
            champs.push((c.to_string(), suite.get(..l)?.to_vec()));
            reste = suite.get(l..)?;
        }
        let [id_lu, geste] = <[String; 2]>::try_from(textes).ok()?;
        if !reste.is_empty() || id_lu != id {
            return None;
        }
        Some(Note {
            geste,
            date: u64::from_le_bytes(*date),
            champs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note() -> Note {
        Note {
            geste: "vanguard:geste defense verrouiller-compte alice 0123456789abcdef".into(),
            date: 1_762_300_000,
            champs: vec![
                ("shell".into(), b"/bin/bash".to_vec()),
                ("verrouille".into(), b"non".to_vec()),
            ],
        }
    }

    #[test]
    fn aller_retour() {
        let o = note().octets("0123456789abcdef").unwrap();
        assert_eq!(Note::lire("0123456789abcdef", &o), Some(note()));
        assert_eq!(note().texte("shell"), Some("/bin/bash"));
        assert_eq!(note().champ("absent"), None);
    }

    /// Une note abîmée, tronquée, rallongée, copiée sous un autre nom ou d'une autre version n'est jamais lue.
    #[test]
    fn note_abimee_refusee() {
        let o = note().octets("0123456789abcdef").unwrap();
        assert_eq!(Note::lire("fedcba9876543210", &o), None);
        for i in 0..o.len() {
            let mut a = o.clone();
            a[i] ^= 1;
            assert_eq!(Note::lire("0123456789abcdef", &a), None, "octet {i}");
        }
        assert_eq!(Note::lire("0123456789abcdef", &o[..o.len() - 1]), None);
        let mut plus = o.clone();
        plus.push(0);
        assert_eq!(Note::lire("0123456789abcdef", &plus), None);
        assert_eq!(Note::lire("0123456789abcdef", &[]), None);
        // Clé en double, clé hors de la forme, trop de champs : pas écrite.
        let mut n = note();
        n.champs.push(("shell".into(), Vec::new()));
        assert_eq!(n.octets("0123456789abcdef"), None);
        let mut n = note();
        n.champs[0].0 = "Shell".into();
        assert_eq!(n.octets("0123456789abcdef"), None);
        let mut n = note();
        n.champs = (0..17).map(|i| ("a".repeat(i + 1), Vec::new())).collect();
        assert_eq!(n.octets("0123456789abcdef"), None);
        let mut n = note();
        n.champs = vec![("contenu".into(), vec![0; VALEUR_MAX + 1])];
        assert_eq!(n.octets("0123456789abcdef"), None);
    }
}

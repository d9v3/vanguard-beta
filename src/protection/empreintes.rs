//! Les empreintes SHA-256 de logiciels malveillants connus (MalwareBazaar, abuse.ch), pour l'analyse YARA : un fichier
//! dont l'empreinte y est, c'est ce logiciel malveillant précis, sans doute possible (une règle YARA, elle, reconnaît
//! une famille et peut se tromper). Gardées dans le dossier de Vanguard, triées pour une recherche en quelques
//! microsecondes : la liste complète (une archive zip d'environ 43 Mo, une fois par semaine) et les récentes
//! (48 heures, une fois par jour). Depuis le 21 oct. 2026, elles ne se téléchargent qu'avec la clé abuse.ch de la
//! personne (`abuse_ch`). Sans Internet ou sans clé, la copie d'avant sert (une empreinte connue le reste), et le
//! rafraîchissement manqué est dit ; sans copie du tout, c'est dit, jamais sain.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::protection::abuse_ch::{self, Echec, Export, Service};
use crate::ui::*;

/// Leurs noms chez MalwareBazaar (exports avec clé). Celui des récentes est confirmé par d'autres programmes qui le
/// téléchargent ; celui de la liste complète l'est moins : un nom changé se dit (« abuse.ch a répondu 404 »).
const COMPLETE: &str = "sha256_full.txt.zip";
const RECENTES: &str = "sha256_recent.txt";
/// La liste complète se retélécharge après une semaine, les récentes après un jour.
const SEMAINE: Duration = Duration::from_hours(7 * 24);
const JOUR: Duration = Duration::from_hours(24);
/// Au-delà, ce n'est pas la liste : la vraie fait 76 Mo de texte (oct. 2026) ; 1 Gio laissait une archive de 3,6 Mo
/// faire monter la mémoire à 2,5 Go à chaque bilan.
pub(crate) const TEXTE_MAX: usize = 256 << 20;
/// Moins d'empreintes que cela, ce n'est pas la liste (une page d'erreur, une archive vide) : la copie gardée reste.
/// La complète en a plus d'un million ; les récentes (48 heures), des centaines.
const COMPLETE_MIN: usize = 10_000;
const RECENTES_MIN: usize = 10;

/// Une liste de MalwareBazaar à télécharger : (son nom chez abuse.ch, son nom ici, après combien de temps la
/// redemander, délai en secondes, ce qui la reconnaît).
type Source = (&'static str, &'static str, Duration, u64, fn(&[u8]) -> bool);

/// Les empreintes connues, triées : (combien, de quand) se dit avec.
pub(crate) struct Empreintes {
    triees: Vec<[u8; 32]>,
    /// Pourquoi les listes n'ont pas pu être rafraîchies (clé abuse.ch manquante ou refusée, 404 d'un nom changé,
    /// 429, panne, pas d'Internet) : la copie gardée sert, et c'est dit à côté du résultat.
    pub(crate) avertissement: Option<String>,
}

impl Empreintes {
    #[cfg(test)]
    pub(crate) fn depuis(mut triees: Vec<[u8; 32]>) -> Empreintes {
        triees.sort_unstable();
        Empreintes {
            triees,
            avertissement: None,
        }
    }

    pub(crate) fn contient(&self, empreinte: &[u8; 32]) -> bool {
        self.triees.binary_search(empreinte).is_ok()
    }

    pub(crate) fn nombre(&self) -> usize {
        self.triees.len()
    }
}

/// Les empreintes d'un texte d'abuse.ch : une par ligne, lignes « # » de commentaire. Dans chaque ligne, le premier
/// champ de 64 chiffres hexadécimaux, guillemets et fins de ligne Windows ôtés : la liste nue comme l'export CSV (où
/// l'empreinte SHA-256 est la seule de cette longueur) se lisent pareil.
fn lire_texte(texte: &str) -> Vec<[u8; 32]> {
    lire_octets(texte.as_bytes())
}

/// `lire_texte`, sur les octets mêmes : sans copie en texte de la liste entière (un seul octet qui n'est pas de
/// l'UTF-8 forçait une seconde copie de tout le fichier).
fn lire_octets(octets: &[u8]) -> Vec<[u8; 32]> {
    let blanc = |b: &u8| b.is_ascii_whitespace();
    octets
        .split(|&b| b == b'\n')
        .map(|l| match l.iter().position(|b| !blanc(b)) {
            Some(debut) => l.split_at(debut).1,
            None => &[],
        })
        .filter(|l| !l.starts_with(b"#"))
        .filter_map(|l| {
            l.split(|&b| b == b',')
                .map(|c| {
                    let c = c.trim_ascii();
                    let c = c.strip_prefix(b"\"").unwrap_or(c);
                    c.strip_suffix(b"\"").unwrap_or(c).trim_ascii()
                })
                .find(|c| c.len() == 64 && c.iter().all(u8::is_ascii_hexdigit))
        })
        .map(|l| {
            let mut e = [0u8; 32];
            // 64 chiffres (filtrés plus haut) : 32 paires, une par octet.
            for (o, &[fort, faible]) in e.iter_mut().zip(l.as_chunks::<2>().0) {
                let chiffre = |b: u8| {
                    char::from(b)
                        .to_digit(16)
                        .and_then(|d| u8::try_from(d).ok())
                        .unwrap_or(0)
                };
                *o = (chiffre(fort) << 4) | chiffre(faible);
            }
            e
        })
        .collect()
}

fn mot16(o: &[u8], i: usize) -> Option<usize> {
    o.get(i..)?
        .first_chunk::<2>()
        .map(|m| usize::from(u16::from_le_bytes(*m)))
}

fn mot32(o: &[u8], i: usize) -> Option<usize> {
    o.get(i..)?
        .first_chunk::<4>()
        .and_then(|m| usize::try_from(u32::from_le_bytes(*m)).ok())
}

/// Le premier fichier d'une archive zip, décompressé : lu par son répertoire central (fin de l'archive), qui donne les
/// vraies tailles même quand l'en-tête local les laisse à zéro. Compression « deflate » (8) ou aucune (0) ; au-delà de
/// `max` octets décompressés, rien. `None` : ce n'est pas une archive lisible.
pub(crate) fn premier_fichier_zip(archive: &[u8], max: usize) -> Option<Vec<u8>> {
    premier_fichier_zip_avant(archive, max, std::time::Instant::now() + DELAI_ZIP)
}

/// Le temps de décompresser la liste complète : une vraie (≈ 100 Mio de texte) se lit en moins d'une seconde ; des
/// blocs deflate vides coûtent ≈ 1,2 s de processeur par Mio compressé sans rien produire.
const DELAI_ZIP: Duration = Duration::from_secs(60);

/// `premier_fichier_zip`, décompressé avant `echeance`.
fn premier_fichier_zip_avant(archive: &[u8], max: usize, echeance: std::time::Instant) -> Option<Vec<u8>> {
    // La fin du répertoire central : 22 octets, au plus 64 Kio de commentaire après.
    let debut = archive.len().saturating_sub(22 + 0xffff);
    let fin = (debut..archive.len().saturating_sub(21))
        .rev()
        .find(|&i| archive.get(i..i + 4) == Some(b"PK\x05\x06"))?;
    let central = mot32(archive, fin + 16)?;
    if archive.get(central..central + 4)? != b"PK\x01\x02" {
        return None;
    }
    let methode = mot16(archive, central + 10)?;
    let compresse = mot32(archive, central + 20)?;
    let decompresse = mot32(archive, central + 24)?;
    let local = mot32(archive, central + 42)?;
    if archive.get(local..local + 4)? != b"PK\x03\x04" || decompresse > max {
        return None;
    }
    let donnees = local + 30 + mot16(archive, local + 26)? + mot16(archive, local + 28)?;
    let brut = archive.get(donnees..donnees.checked_add(compresse)?)?;
    // Décompressé jusqu'à la taille annoncée, pas jusqu'à `max` : une archive qui annonce 1 octet et en contient
    // un milliard s'arrête au premier ; le résultat doit faire exactement la taille annoncée, d'octets compressés
    // plausibles pour elle, lus avant l'échéance (comme plugins/archive.rs).
    match methode {
        0 => (brut.len() == decompresse).then(|| brut.to_vec()),
        8 => crate::archives::deflate::entier_avant(brut, decompresse, echeance),
        _ => None,
    }
}

/// La liste complète reçue est-elle la liste ? Une archive lisible, de taille raisonnable une fois ouverte, avec
/// assez d'empreintes : sinon la copie gardée reste.
fn complete_valide(archive: &[u8]) -> bool {
    premier_fichier_zip(archive, TEXTE_MAX).is_some_and(|t| lire_octets(&t).len() >= COMPLETE_MIN)
}

/// La liste des récentes reçue est-elle la liste ?
fn recentes_valide(texte: &[u8]) -> bool {
    texte.len() <= TEXTE_MAX && lire_octets(texte).len() >= RECENTES_MIN
}

fn dossier() -> PathBuf {
    crate::socle::dossier_local().join("malwarebazaar")
}

/// Les empreintes chargées, ou pourquoi il n'y en a pas.
pub(crate) type Chargees = Result<&'static Empreintes, &'static String>;

/// Les empreintes connues, chargées une fois par lancement (et rafraîchies d'abord quand il le faut). `Err` : aucune
/// liste, ni téléchargée ni gardée, et pourquoi.
pub(crate) fn connues() -> Chargees {
    static CHARGEES: OnceLock<Result<Empreintes, String>> = OnceLock::new();
    CHARGEES.get_or_init(|| charger(true)).as_ref()
}

/// Les empreintes déjà gardées sur cet ordinateur, sans rien télécharger : pour le bilan, qui ne doit pas attendre
/// 43 Mo quand personne n'a demandé la protection active. `Err` : aucune liste gardée, et pourquoi.
pub(crate) fn gardees() -> Chargees {
    static GARDEES: OnceLock<Result<Empreintes, String>> = OnceLock::new();
    GARDEES.get_or_init(|| charger(false)).as_ref()
}

/// Les empreintes récentes seulement (48 heures, quelques milliers), relues sur le disque à chaque appel, sans rien
/// télécharger : pour le veilleur, un service borné à 128 Mo de mémoire, où la liste complète (plus d'un million
/// d'empreintes) ne tiendrait pas. `None` : aucune copie gardée.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn recentes_gardees() -> Option<Empreintes> {
    // Borné comme une liste : le veilleur tient en 128 Mo, un fichier creux de plusieurs Gio ne s'y charge pas.
    // La copie scellée seule (`socle::cache::gardee`) : changée hors de Vanguard, aucune liste, jamais une liste vide.
    let (octets, _) = crate::socle::cache::gardee(("malwarebazaar", "recentes.txt"), TEXTE_MAX as u64).ok()??;
    let mut triees = lire_texte(&String::from_utf8_lossy(&octets));
    triees.sort_unstable();
    triees.dedup();
    (!triees.is_empty()).then_some(Empreintes {
        triees,
        avertissement: None,
    })
}

fn charger(telecharger: bool) -> Result<Empreintes, String> {
    let d = dossier();
    // Sans clé, rien ne se rafraîchit, même quand on ne voulait rien télécharger : la copie vieillit, c'est dit.
    let mut echec = abuse_ch::cle().is_none().then_some(Echec::Manquante);
    if telecharger && echec.is_none() && !cfg!(test) && !crate::parametres::hors_ligne() {
        let _ = std::fs::create_dir_all(&d);
        // L'âge d'après le sceau de la copie, comme le téléchargement qui suit : la date du fichier faisait taire
        // l'annonce d'une copie sans sceau (ou datée dans le futur), retéléchargée quand même.
        if crate::socle::cache::age(("malwarebazaar", "complete.zip")).is_none_or(|a| a > SEMAINE) {
            trp!(
                "  {GRIS}Empreintes de MalwareBazaar : liste complète (environ 43 Mo, une fois par semaine)…{RESET}",
                "  {GRIS}MalwareBazaar fingerprints: full list (about 43 MB, once a week)…{RESET}"
            );
        }
        let listes: [Source; 2] = [
            (COMPLETE, "complete.zip", SEMAINE, 600, complete_valide),
            (RECENTES, "recentes.txt", JOUR, 60, recentes_valide),
        ];
        for (fichier, nom, apres, secondes, valide) in listes {
            let lieu = ("malwarebazaar", nom);
            let rendu = abuse_ch::export_et_manque(
                Service::MalwareBazaar,
                fichier,
                lieu,
                apres,
                Duration::from_secs(secondes),
                valide,
            );
            if let Some(e) = manque(&rendu) {
                echec.get_or_insert(e);
            }
        }
    }
    // Les copies scellées seules (`socle::cache::gardee`) : une copie vidée ou datée dans le futur par un autre
    // programme ne compte pas, et son refus est dit comme un rafraîchissement manqué.
    let mut refus = None;
    let mut gardee = |nom: &str, max: u64| match crate::socle::cache::gardee(("malwarebazaar", nom), max) {
        Ok(copie) => copie.map(|(o, _)| o),
        Err(r) => {
            refus.get_or_insert(r);
            None
        }
    };
    let mut triees = gardee("complete.zip", crate::socle::cache::LISTE_MAX)
        .and_then(|a| premier_fichier_zip(&a, TEXTE_MAX))
        .map(|t| lire_octets(&t))
        .unwrap_or_default();
    triees.extend(lire_octets(
        &gardee("recentes.txt", TEXTE_MAX as u64).unwrap_or_default(),
    ));
    triees.sort_unstable();
    triees.dedup();
    let raison = raison_des_copies(echec, refus);
    if triees.is_empty() {
        return Err(match raison {
            Some(r) => trf!("non vérifiées : {r}", "not checked: {r}"),
            None if telecharger => tr!("hors ligne, et aucune copie gardée", "offline, and no saved copy").into(),
            None => tr!(
                "absentes : une analyse YARA (vanguard yara) les télécharge",
                "missing: a YARA scan (vanguard yara) downloads them"
            )
            .into(),
        });
    }
    let avertissement = raison.map(|r| avertissement(&r));
    Ok(Empreintes { triees, avertissement })
}

/// Ce qui a manqué aux copies : la clé manquante d'abord (sans elle, rien ne se retélécharge jamais), puis le refus
/// d'une copie et ce qui la retélécharge, sinon l'échec du téléchargement.
fn raison_des_copies(echec: Option<Echec>, refus: Option<crate::socle::cache::Refus>) -> Option<String> {
    match (echec, refus) {
        (Some(Echec::Manquante), Some(r)) => Some(trf!("{} ; {}", "{}; {}", Echec::Manquante.raison(), r.texte())),
        (_, Some(r)) => Some(trf!(
            "{} (une analyse YARA, vanguard yara, la retélécharge)",
            "{} (a YARA scan, vanguard yara, downloads it again)",
            r.texte()
        )),
        (e, None) => e.map(Echec::raison),
    }
}

/// Ce qui a manqué à un export : son échec, ou, quand la copie d'avant a servi, pourquoi elle n'a pas été
/// rafraîchie. La liste des empreintes n'a pas de limite d'âge : sans cette raison, elle vieillirait sans le dire.
fn manque(rendu: &Result<Export, Echec>) -> Option<Echec> {
    match rendu {
        Ok((_, manque)) => *manque,
        Err(e) => Some(*e),
    }
}

/// L'avertissement montré à côté du résultat quand une copie gardée a servi, ou qu'une des deux manque.
fn avertissement(raison: &str) -> String {
    trf!(
        "empreintes de MalwareBazaar pas à jour ou incomplètes, ce qui reste a servi : {}",
        "MalwareBazaar fingerprints not up to date or incomplete, what is left was used: {}",
        raison
    )
}

/// Une empreinte en hexadécimal minuscule, telle que MalwareBazaar l'écrit.
pub(crate) fn hex(e: &[u8; 32]) -> String {
    e.iter().fold(String::with_capacity(64), |mut s, o| {
        let _ = write!(s, "{o:02x}");
        s
    })
}

/// L'empreinte SHA-256 d'un fichier, lue par morceaux. `None` : illisible.
pub(crate) fn sha256(chemin: &Path) -> Option<[u8; 32]> {
    sha256_de(std::fs::File::open(chemin).ok()?)
}

/// L'empreinte SHA-256 de ce qui se lit dans `f` (un fichier déjà ouvert et vérifié), par morceaux. `None` :
/// illisible.
pub(crate) fn sha256_de(mut f: impl std::io::Read) -> Option<[u8; 32]> {
    let mut h = Sha256::new();
    let mut tampon = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut tampon).ok()?;
        if n == 0 {
            break;
        }
        // Un lecteur qui dit avoir lu plus que le tampon : illisible plutôt qu'une empreinte inventée.
        h.update(tampon.get(..n)?);
    }
    Some(h.finalize().into())
}

/// Les fichiers dont l'empreinte est connue, parmi `fichiers` : leur chemin et leur empreinte en hexadécimal.
pub(crate) fn connus(empreintes: &Empreintes, fichiers: &[PathBuf]) -> Vec<(PathBuf, String)> {
    fichiers
        .iter()
        .filter_map(|f| {
            let e = sha256(f)?;
            empreintes.contient(&e).then(|| (f.clone(), hex(&e)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La liste complète effacée sous son sceau intact (un programme du compte qui voulait réduire l'antivirus aux
    /// empreintes des 48 dernières heures) : les empreintes restantes servent, mais jamais sans le dire.
    #[test]
    fn complete_effacee_sous_son_sceau_jamais_en_silence() {
        let lieu = |nom| ("malwarebazaar", nom);
        let _ = std::fs::remove_dir_all(dossier());
        let e = "9edfda3b77b3973f37708add497130d44cd88374c85812926f7974687006e3e5";
        crate::socle::cache::garder(lieu("recentes.txt"), format!("# MalwareBazaar\n{e}\n").as_bytes()).unwrap();
        crate::socle::cache::garder(lieu("complete.zip"), b"PK archive d'essai").unwrap();
        std::fs::remove_file(dossier().join("complete.zip")).unwrap();
        let chargees = charger(false).unwrap();
        assert_eq!(chargees.triees.len(), 1);
        let avertissement = chargees.avertissement.expect("la liste amputée doit se dire");
        let refus = crate::socle::cache::Refus::Effacee.raison();
        assert!(avertissement.contains(refus), "{avertissement}");
        // Sans promesse d'un téléchargement qui ne viendra pas : sans clé, la clé manquante est dite d'abord ; avec,
        // la commande qui retélécharge.
        let manquante = Echec::Manquante.raison();
        assert!(
            avertissement.contains(&manquante) || avertissement.contains("vanguard yara"),
            "{avertissement}"
        );
        // Les deux effacées : non vérifiées, jamais une liste vide.
        std::fs::remove_file(dossier().join("recentes.txt")).unwrap();
        let echec = charger(false).err().unwrap();
        assert!(echec.contains(refus), "{echec}");
        let _ = std::fs::remove_dir_all(dossier());
    }

    /// Un rafraîchissement manqué avec la clé (404 d'un nom changé, 429, pas d'Internet) se dit même quand la copie
    /// d'avant sert ; une copie rafraîchie, rien.
    #[test]
    fn rafraichissement_manque_dit() {
        let copie = || (b"x".to_vec(), Duration::ZERO);
        assert_eq!(manque(&Ok((copie(), None))), None);
        assert_eq!(
            manque(&Ok((copie(), Some(Echec::Reponse(404))))),
            Some(Echec::Reponse(404))
        );
        assert_eq!(
            manque(&Ok((copie(), Some(Echec::SansReponse)))),
            Some(Echec::SansReponse)
        );
        assert_eq!(manque(&Err(Echec::Refusee)), Some(Echec::Refusee));
        let a = avertissement(&Echec::Reponse(404).raison());
        assert!(a.contains("404") && a.contains("MalwareBazaar"), "{a}");
    }

    #[test]
    fn empreintes_lues_triees_cherchees() {
        let texte = "# MalwareBazaar\n# sha256_hash\n\
            9edfda3b77b3973f37708add497130d44cd88374c85812926f7974687006e3e5\n\
            pas une empreinte\n\
            23B2BEE6D808E7D3CAF0E3E6F51E10D470F4CF298766C87F2062A4121DFB0D19\n\
            zz2bee6d808e7d3caf0e3e6f51e10d470f4cf298766c87f2062a4121dfb0d19\n";
        let mut triees = lire_texte(texte);
        assert_eq!(triees.len(), 2);
        triees.sort_unstable();
        let e = Empreintes::depuis(triees);
        assert_eq!(e.nombre(), 2);
        assert!(e.contient(&lire_texte("23b2bee6d808e7d3caf0e3e6f51e10d470f4cf298766c87f2062a4121dfb0d19")[0]));
        assert!(!e.contient(&[0; 32]));
    }

    /// L'export avec clé : fins de ligne Windows, valeurs parfois entre guillemets ; et l'export CSV, où l'empreinte
    /// SHA-256 est le seul champ de 64 chiffres (MD5 et SHA-1 sont plus courts).
    #[test]
    fn empreintes_de_l_export_avec_cle() {
        let e = "9edfda3b77b3973f37708add497130d44cd88374c85812926f7974687006e3e5";
        assert_eq!(lire_texte(&format!("# MalwareBazaar\r\n\"{e}\"\r\n{e}\r\n")).len(), 2);
        let csv = format!(
            "# \"first_seen_utc\",\"sha256_hash\",\"md5_hash\",\"sha1_hash\"\r\n\"2026-10-21 12:00:00\", \"{e}\", \"{}\", \"{}\"\r\n",
            "0".repeat(32),
            "1".repeat(40)
        );
        assert_eq!(lire_texte(&csv), lire_texte(e));
    }

    /// Une archive zip faite ici, comme celle d'abuse.ch (un fichier, « deflate », tailles dans le répertoire central
    /// seulement) ; puis la même sans compression, et des archives abîmées.
    #[test]
    fn archive_zip_lue() {
        fn archive(contenu: &[u8], methode: u16) -> Vec<u8> {
            let donnees = if methode == 8 {
                miniz_oxide::deflate::compress_to_vec(contenu, 6)
            } else {
                contenu.to_vec()
            };
            archive_de(&donnees, contenu.len(), methode)
        }
        /// L'archive d'octets déjà compressés (`donnees`), qui annonce `taille` octets une fois décompressée.
        fn archive_de(donnees: &[u8], taille: usize, methode: u16) -> Vec<u8> {
            let nom = b"full_sha256.txt";
            let mut z = b"PK\x03\x04".to_vec();
            z.extend_from_slice(&[20, 0, 8, 0]); // version, drapeaux (bit 3 : tailles plus loin)
            z.extend_from_slice(&methode.to_le_bytes());
            z.extend_from_slice(&[0; 16]); // heure, date, CRC et tailles laissés à zéro
            z.extend_from_slice(&u16::try_from(nom.len()).unwrap().to_le_bytes());
            z.extend_from_slice(&[0, 0]);
            z.extend_from_slice(nom);
            z.extend_from_slice(donnees);
            let central = z.len();
            z.extend_from_slice(b"PK\x01\x02");
            z.extend_from_slice(&[20, 0, 20, 0, 8, 0]);
            z.extend_from_slice(&methode.to_le_bytes());
            z.extend_from_slice(&[0; 8]);
            z.extend_from_slice(&u32::try_from(donnees.len()).unwrap().to_le_bytes());
            z.extend_from_slice(&u32::try_from(taille).unwrap().to_le_bytes());
            z.extend_from_slice(&u16::try_from(nom.len()).unwrap().to_le_bytes());
            z.extend_from_slice(&[0; 12]);
            z.extend_from_slice(&0u32.to_le_bytes()); // l'en-tête local, au début
            z.extend_from_slice(nom);
            let taille_central = z.len() - central;
            z.extend_from_slice(b"PK\x05\x06");
            z.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
            z.extend_from_slice(&u32::try_from(taille_central).unwrap().to_le_bytes());
            z.extend_from_slice(&u32::try_from(central).unwrap().to_le_bytes());
            z.extend_from_slice(&[0, 0]);
            z
        }
        let texte = "# sha256_hash\n9edfda3b77b3973f37708add497130d44cd88374c85812926f7974687006e3e5\n".repeat(50);
        assert_eq!(
            premier_fichier_zip(&archive(texte.as_bytes(), 8), 1 << 20).unwrap(),
            texte.as_bytes()
        );
        assert_eq!(
            premier_fichier_zip(&archive(texte.as_bytes(), 0), 1 << 20).unwrap(),
            texte.as_bytes()
        );
        // Trop gros une fois décompressé, abîmé, ou pas une archive : rien, sans paniquer.
        assert!(premier_fichier_zip(&archive(texte.as_bytes(), 8), 100).is_none());
        let mut abimee = archive(texte.as_bytes(), 8);
        abimee.truncate(abimee.len() - 30);
        assert!(premier_fichier_zip(&abimee, 1 << 20).is_none());
        assert!(premier_fichier_zip(b"pas une archive", 1 << 20).is_none());
        // Une bombe : la taille annoncée (1 octet) ment sur ce que l'archive contient (des Mio de la même ligne).
        // Rien n'est décompressé au-delà de l'annonce, et l'écart la fait refuser.
        let gros = texte.repeat(2000);
        let mut bombe = archive(gros.as_bytes(), 8);
        let central = bombe.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        bombe[central + 24..central + 28].copy_from_slice(&1u32.to_le_bytes());
        assert!(premier_fichier_zip(&bombe, TEXTE_MAX).is_none());
        // Annoncée plus grande que son contenu : refusée aussi.
        let mut menteuse = archive(texte.as_bytes(), 8);
        let central = menteuse.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        let plus = u32::try_from(texte.len() + 1).unwrap();
        menteuse[central + 24..central + 28].copy_from_slice(&plus.to_le_bytes());
        assert!(premier_fichier_zip(&menteuse, TEXTE_MAX).is_none());
        // Des blocs deflate vides devant le vrai contenu : lus à une échéance lointaine, refusés à une échéance
        // passée ; plus nombreux que la taille annoncée ne le permet, refusés sans être décodés.
        let long = texte.repeat(300);
        let flux = crate::archives::deflate::tests::vides_puis(256 << 10, long.as_bytes());
        let lente = archive_de(&flux, long.len(), 8);
        let loin = std::time::Instant::now() + Duration::from_secs(600);
        assert!(premier_fichier_zip_avant(&lente, TEXTE_MAX, loin).is_some_and(|c| c == long.as_bytes()));
        assert!(premier_fichier_zip_avant(&lente, TEXTE_MAX, std::time::Instant::now()).is_none());
        let gonflee = archive_de(
            &crate::archives::deflate::tests::vides_puis(2 * long.len(), long.as_bytes()),
            long.len(),
            8,
        );
        assert!(premier_fichier_zip_avant(&gonflee, TEXTE_MAX, loin).is_none());
        // Stockée : la taille annoncée doit être celle des octets.
        assert!(premier_fichier_zip(&archive_de(texte.as_bytes(), texte.len() - 1, 0), TEXTE_MAX).is_none());
        // La validation à la réception : une archive presque vide, ou une bombe, ne remplace pas la copie gardée.
        assert!(!complete_valide(&archive(texte.as_bytes(), 8)));
        assert!(!complete_valide(&bombe));
        let liste = (0..COMPLETE_MIN).fold(String::new(), |mut s, i| {
            let _ = writeln!(s, "{i:064x}");
            s
        });
        assert!(complete_valide(&archive(liste.as_bytes(), 8)));
        assert!(recentes_valide(texte.as_bytes()) && !recentes_valide(b"<html>erreur</html>"));
    }

    /// La lecture sur les octets mêmes rend ce que rendait la lecture en texte, octet non UTF-8 compris.
    #[test]
    fn lecture_des_octets_comme_du_texte() {
        let a = "9edfda3b77b3973f37708add497130d44cd88374c85812926f7974687006e3e5";
        let csv = format!(
            "# commentaire\r\n  {a}\r\n\"2026-10-23\", \"{}\", \"x\"\n# {a}\npas une empreinte\n",
            a.to_uppercase()
        );
        assert_eq!(lire_octets(csv.as_bytes()), lire_texte(&csv));
        assert_eq!(lire_octets(csv.as_bytes()).len(), 2);
        let mut abime = csv.into_bytes();
        abime.push(0xff);
        abime.extend_from_slice(format!("\n{a}\n").as_bytes());
        assert_eq!(lire_octets(&abime).len(), 3);
    }

    #[test]
    fn fichier_connu_retrouve() {
        let d = crate::socle::dossier_local().join("empreintes");
        std::fs::create_dir_all(&d).unwrap();
        let (mauvais, bon) = (d.join("facture.exe"), d.join("photo.jpg"));
        std::fs::write(&mauvais, b"contenu d'essai qui joue le logiciel malveillant").unwrap();
        std::fs::write(&bon, b"autre chose").unwrap();
        let empreintes = Empreintes::depuis(vec![sha256(&mauvais).unwrap()]);
        let trouves = connus(&empreintes, &[mauvais.clone(), bon, d.join("absent")]);
        assert_eq!(trouves.len(), 1);
        assert_eq!(trouves[0].0, mauvais);
        assert_eq!(trouves[0].1.len(), 64);
    }
}

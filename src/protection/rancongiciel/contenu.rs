//! Le contenu d'un fichier réécrit, jugé en mémoire : son entropie, et surtout si son FORMAT est perdu (son en-tête
//! ne correspond plus à son extension d'origine). Toutes les décisions sont des fonctions pures, essayées sous Linux
//! et sous Wine ; la lecture, elle, est bornée (au plus 3 × 4 Kio par fichier) et ne garde rien.
//!
//! Pourquoi le format d'abord, l'entropie ensuite : l'entropie seule se trompe (une photo JPEG ou un .zip ont une
//! entropie proche de 8 sans être chiffrés, et un rançongiciel peut encoder en base64 pour la faire baisser). Le
//! changement de type est l'un des trois indicateurs centraux de CryptoDrop ; et le chiffrement « un bloc sur deux »
//! (intermittent) fait BAISSER l'entropie d'un échantillon de 4 Kio, alors qu'il touche quand même l'en-tête : c'est
//! le format perdu qui le prend, pas l'entropie.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::modele::Echec;

/// Un échantillon lu dans un fichier : 4 Kio.
pub(crate) const TAILLE_ECHANTILLON: usize = 4 << 10;
/// Trois échantillons par fichier (début, milieu, fin) : les modes à grands blocs (un bloc chiffré tous les 192
/// octets) touchent au moins l'un des trois.
pub(crate) const NB_ECHANTILLONS: usize = 3;

/// L'entropie de Shannon d'une suite d'octets, en bits par octet (0 pour un octet répété, ≈ 8 pour du vrai hasard).
/// Une suite vide vaut 0.
#[allow(clippy::cast_precision_loss)] // une mesure statistique : la précision du f32 suffit largement
pub(crate) fn entropie(octets: &[u8]) -> f32 {
    if octets.is_empty() {
        return 0.0;
    }
    let mut compte = [0u32; 256];
    for &o in octets {
        #[expect(
            clippy::indexing_slicing,
            reason = "un u8 vaut au plus 255 : toujours une case de [_; 256]"
        )]
        let case = &mut compte[usize::from(o)];
        *case += 1;
    }
    let total = octets.len() as f32;
    let mut h = 0.0f32;
    for &c in &compte {
        if c > 0 {
            let p = c as f32 / total;
            h -= p * p.log2();
        }
    }
    h
}

/// Une signature de format reconnue par ses premiers octets (« nombre magique »).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Signature {
    Pdf,
    Png,
    Jpeg,
    /// L'en-tête « PK\x03\x04 » des conteneurs zip : docx, xlsx, pptx, odt, ods, jar, epub.
    Zip,
    /// Un « ftyp » à l'octet 4 : mp4, mov, m4a, heic.
    Mp4,
    Gif,
    /// RIFF (wav, avi, webp).
    Riff,
    /// OggS.
    Ogg,
    /// ELF (programmes Linux) et Mach-O : rarement des fichiers personnels, mais un en-tête net.
    Elf,
}

/// Les extensions dont on connaît la signature attendue. `None` : extension sans en-tête fiable (« .locked », « .txt »
/// pour le texte se juge à part). La casse n'importe pas.
pub(crate) fn format_attendu(extension: &str) -> Option<Signature> {
    let ext = extension.trim_start_matches('.').to_ascii_lowercase();
    let s = match ext.as_str() {
        "pdf" => Signature::Pdf,
        "png" => Signature::Png,
        "jpg" | "jpeg" | "jpe" => Signature::Jpeg,
        "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp" | "epub" | "jar" | "zip" | "apk" => Signature::Zip,
        "mp4" | "m4v" | "m4a" | "mov" | "heic" | "heif" => Signature::Mp4,
        "gif" => Signature::Gif,
        "wav" | "avi" | "webp" => Signature::Riff,
        "ogg" | "oga" | "opus" => Signature::Ogg,
        "elf" | "so" | "o" => Signature::Elf,
        _ => return None,
    };
    Some(s)
}

/// Les octets correspondent-ils à la signature ? Lit au plus les premiers octets ; un fichier trop court ne
/// correspond pas.
fn correspond(signature: Signature, octets: &[u8]) -> bool {
    let debute = |prefixe: &[u8]| octets.starts_with(prefixe);
    match signature {
        Signature::Pdf => debute(b"%PDF-"),
        Signature::Png => debute(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]),
        Signature::Jpeg => debute(&[0xff, 0xd8, 0xff]),
        Signature::Zip => debute(b"PK\x03\x04") || debute(b"PK\x05\x06") || debute(b"PK\x07\x08"),
        Signature::Mp4 => octets.get(4..8).is_some_and(|m| m == b"ftyp"),
        Signature::Gif => debute(b"GIF87a") || debute(b"GIF89a"),
        Signature::Riff => debute(b"RIFF"),
        Signature::Ogg => debute(b"OggS"),
        Signature::Elf => debute(&[0x7f, b'E', b'L', b'F']) || debute(&[0xcf, 0xfa, 0xed, 0xfe]),
    }
}

/// La fin du fichier (son dernier échantillon) porte-t-elle la marque de fin de son format ? Seulement pour les
/// formats dont la fin est fiable : le JPEG est mis à part, car les photos « animées » des téléphones ajoutent une
/// vidéo après la fin de l'image, et une simple retouche de 20 d'entre elles aurait paru chiffrée. Limite dite : une
/// queue gardée intacte, ou un ZIP dont le commentaire dépasse 4 Kio, échappe à ce contrôle ou le trompe.
fn fin_correspond(signature: Signature, derniere: &[u8]) -> bool {
    let contient = |motif: &[u8]| derniere.windows(motif.len()).any(|w| w == motif);
    match signature {
        // La fin du répertoire central.
        Signature::Zip => contient(b"PK\x05\x06"),
        Signature::Pdf => contient(b"%%EOF"),
        Signature::Png => contient(b"IEND"),
        // L'octet de fin « ; », suivi au plus de zéros de bourrage.
        Signature::Gif => derniere.iter().rev().find(|&&o| o != 0) == Some(&0x3b),
        Signature::Jpeg | Signature::Mp4 | Signature::Riff | Signature::Ogg | Signature::Elf => true,
    }
}

/// Les octets sont-ils du texte lisible (UTF-8 valide, sans octet de contrôle hors \t \n \r) ? Un fichier texte
/// chiffré cesse de l'être. Un échantillon coupé au milieu d'un caractère multi-octets n'est pas pris pour du binaire
/// à cause de la coupure seule : on tolère quelques octets non valides en toute fin.
fn tout_texte(octets: &[u8]) -> bool {
    if octets.is_empty() {
        return false;
    }
    // Coupe les quelques derniers octets d'un éventuel caractère tronqué par l'échantillonnage.
    let fin = (0..4).find_map(|n| {
        let debut = octets.get(..octets.len().checked_sub(n)?)?;
        std::str::from_utf8(debut).ok().map(|_| debut)
    });
    let Some(debut) = fin else { return false };
    debut.iter().all(|&o| o >= 0x20 || matches!(o, b'\t' | b'\n' | b'\r')) && std::str::from_utf8(debut).is_ok()
}

/// Seuil d'entropie au-delà duquel un échantillon ressemble à du chiffrement ou de la compression (bits par octet).
pub(crate) const ENTROPIE_CHIFFRE: f32 = 7.8;

/// Le format est-il perdu ? `extension` : l'extension d'ORIGINE du fichier (celle d'avant un renommage, ou celle du
/// fichier supprimé apparié), pas l'extension actuelle (« .locked » n'a pas de signature). `echantillons` : jusqu'à
/// trois morceaux du contenu actuel.
///
/// Règle exacte (Critique C3) : si l'extension d'origine a une signature connue, le format est perdu dès que le
/// PREMIER échantillon (l'en-tête) ne correspond plus — l'entropie ne compte pas, car le chiffrement intermittent la
/// ferait baisser alors que l'en-tête est touché. Pour une extension de texte (« .txt », « .md », « .csv », « .log »,
/// « .json », « .xml », « .html »), le format est perdu quand le début cesse d'être du texte. Sinon (extension
/// inconnue), on retombe sur l'entropie : ≥ 7,8 bits/octet sur au moins un échantillon.
pub(crate) fn format_perdu(extension: &str, echantillons: &[Vec<u8>]) -> bool {
    let Some(tete) = echantillons.first() else {
        return false;
    };
    if let Some(signature) = format_attendu(extension) {
        // Un en-tête gardé n'implique pas une fin gardée : un chiffreur qui laisse les premiers octets intacts
        // chiffre la queue ou y ajoute son bloc de clé. Un fichier d'un seul échantillon a sa fin dans l'en-tête.
        return !correspond(signature, tete) || !fin_correspond(signature, echantillons.last().unwrap_or(tete));
    }
    if extension_texte(extension) {
        return !tout_texte(tete);
    }
    echantillons.iter().any(|e| entropie(e) >= ENTROPIE_CHIFFRE)
}

/// Un fichier texte, dont l'en-tête doit rester lisible.
pub(crate) fn extension_texte(extension: &str) -> bool {
    let ext = extension.trim_start_matches('.').to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "txt" | "md" | "csv" | "log" | "json" | "xml" | "html" | "htm" | "ini" | "conf" | "yaml" | "yml" | "rtf"
    )
}

/// Un contenu qui était du texte est-il devenu du binaire ? (en-tête d'origine lisible, contenu actuel non) : utile
/// pour un fichier dont on connaît l'ancien contenu plutôt que l'extension.
#[cfg(test)]
pub(crate) fn texte_devenu_binaire(avant: &[u8], apres: &[u8]) -> bool {
    tout_texte(avant) && !tout_texte(apres)
}

/// Lit jusqu'à trois échantillons de 4 Kio (début, milieu, fin) d'un fichier, en lecture seule, sans suivre un lien
/// symbolique et sans changer l'heure d'accès quand c'est possible. Rien n'est gardé. Un fichier « en ligne seulement »
/// (sur un stockage distant monté) n'est jamais déclenché : seuls les octets déjà présents sont lus, et un fichier plus
/// court rend moins d'échantillons.
#[cfg(target_os = "linux")]
pub(crate) fn echantillons(chemin: &Path) -> Result<Vec<Vec<u8>>, Echec> {
    use std::os::unix::fs::OpenOptionsExt;
    const OU: &str = "rancongiciel/echantillons";
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    // O_NOFOLLOW : jamais à travers un lien ; O_NOATIME : ne pas réécrire l'heure d'accès (ignoré par le noyau si le
    // fichier n'est pas à ce compte, sans échec).
    // O_NONBLOCK : un tube nommé ou un périphérique ne bloque jamais le fil unique du veilleur (un `mkfifo` dans
    // Documents l'arrêtait pour toujours) ; sur un fichier ordinaire, ce drapeau ne change rien.
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NOATIME | libc::O_NONBLOCK);
    let mut f = options.open(chemin).map_err(|e| Echec::io(OU, &e))?;
    // Vérifié sur le descripteur déjà ouvert, sans course entre le contrôle et l'usage : un tube, une prise ou un
    // périphérique n'est pas un document, rien à échantillonner.
    let meta = f.metadata().map_err(|e| Echec::io(OU, &e))?;
    if !meta.is_file() {
        return Ok(Vec::new());
    }
    echantillons_de(&mut f, meta.len()).map_err(|e| Echec::io(OU, &e))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn echantillons(chemin: &Path) -> Result<Vec<Vec<u8>>, Echec> {
    const OU: &str = "rancongiciel/echantillons";
    let mut f = std::fs::File::open(chemin).map_err(|e| Echec::io(OU, &e))?;
    let taille = f.metadata().map_err(|e| Echec::io(OU, &e))?.len();
    echantillons_de(&mut f, taille).map_err(|e| Echec::io(OU, &e))
}

/// Les échantillons d'un lecteur déjà ouvert, de sa taille connue : testable sans fichier réel. Un fichier qui tient
/// en un échantillon n'en rend qu'un ; un fichier moyen rend début, milieu et fin, sans recouvrement.
fn echantillons_de<L: Read + Seek>(lecteur: &mut L, taille: u64) -> std::io::Result<Vec<Vec<u8>>> {
    let bloc = TAILLE_ECHANTILLON as u64;
    if taille <= bloc {
        let mut v = Vec::new();
        lecteur.take(bloc).read_to_end(&mut v)?;
        return Ok(if v.is_empty() { Vec::new() } else { vec![v] });
    }
    // Trois positions : 0, le milieu, et la fin (sans dépasser). Réduites et dédupliquées pour les fichiers juste au-
    // dessus d'un bloc.
    let fin = taille - bloc;
    let milieu = taille / 2 - bloc / 2;
    let mut positions = [0u64, milieu, fin];
    positions.sort_unstable();
    let mut sortie = Vec::with_capacity(NB_ECHANTILLONS);
    let mut derniere: Option<u64> = None;
    for &pos in &positions {
        if derniere.is_some_and(|d| pos < d + bloc) {
            continue;
        }
        lecteur.seek(SeekFrom::Start(pos))?;
        let mut v = vec![0u8; TAILLE_ECHANTILLON];
        let lu = lire_plein(lecteur, &mut v)?;
        v.truncate(lu);
        if !v.is_empty() {
            sortie.push(v);
            derniere = Some(pos);
        }
    }
    Ok(sortie)
}

/// Lit autant que possible pour remplir `tampon` (un seul `read` peut en rendre moins) ; rend le nombre d'octets lus.
fn lire_plein<L: Read>(lecteur: &mut L, tampon: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while let Some(reste) = tampon.get_mut(total..).filter(|r| !r.is_empty()) {
        let place = reste.len();
        match lecteur.read(reste) {
            Ok(0) => break,
            // Un lecteur qui dit avoir lu plus que la place donnée : une erreur, pas un compte qui déborde.
            Ok(n) if n > place => return Err(std::io::Error::other("lecture plus longue que le tampon")),
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn entropie_bornes() {
        assert_eq!(entropie(&[]), 0.0);
        assert_eq!(entropie(&[7u8; 4096]), 0.0);
        // 256 valeurs également réparties : exactement 8 bits.
        let uniforme: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        assert!((entropie(&uniforme) - 8.0).abs() < 0.01);
    }

    #[test]
    fn hasard_proche_de_huit() {
        let mut v = vec![0u8; 8192];
        getrandom::fill(&mut v).unwrap();
        assert!(entropie(&v) >= ENTROPIE_CHIFFRE, "{}", entropie(&v));
    }

    #[test]
    fn signatures_reconnues() {
        // De vrais petits fichiers : en-tête ET marque de fin.
        let mut pdf = b"%PDF-1.7\n".to_vec();
        pdf.resize(64, b' ');
        pdf.extend_from_slice(b"\n%%EOF\n");
        assert!(!format_perdu("pdf", &[pdf]));
        assert!(format_perdu("pdf", &[vec![0u8; 64]]));
        let mut png = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3];
        png.extend_from_slice(&[0, 0, 0, 0, b'I', b'E', b'N', b'D', 0xae, 0x42, 0x60, 0x82]);
        assert!(!format_perdu("PNG", &[png]));
        let mut zip = b"PK\x03\x04".to_vec();
        zip.resize(32, 0);
        zip.extend_from_slice(b"PK\x05\x06");
        zip.resize(58, 0);
        assert!(!format_perdu("docx", &[zip]));
        let mut gif = b"GIF89a".to_vec();
        gif.resize(40, 1);
        gif.extend_from_slice(&[0x3b, 0, 0]);
        assert!(!format_perdu("gif", &[gif]));
        let mut mp4 = vec![0, 0, 0, 0x18];
        mp4.extend_from_slice(b"ftypmp42");
        assert!(!format_perdu("mp4", &[mp4]));
    }

    #[test]
    fn en_tete_garde_queue_chiffree() {
        // Un chiffreur lent qui garde « %PDF-1.7 » : la fin ne porte plus %%EOF, le format est perdu.
        let mut tete = b"%PDF-1.7\n".to_vec();
        tete.resize(TAILLE_ECHANTILLON, b' ');
        let mut milieu = vec![0u8; TAILLE_ECHANTILLON];
        let mut fin = vec![0u8; TAILLE_ECHANTILLON];
        getrandom::fill(&mut milieu).unwrap();
        getrandom::fill(&mut fin).unwrap();
        // Pas de « %%EOF » tiré au hasard dans la fin.
        while fin.windows(5).any(|w| w == b"%%EOF") {
            getrandom::fill(&mut fin).unwrap();
        }
        assert!(format_perdu("pdf", &[tete.clone(), milieu.clone(), fin]));
        // Le vrai PDF, qui finit par %%EOF, reste intact.
        let mut vraie_fin = vec![b' '; TAILLE_ECHANTILLON - 7];
        vraie_fin.extend_from_slice(b"\n%%EOF\n");
        assert!(!format_perdu("pdf", &[tete, milieu, vraie_fin]));
        // Une photo JPEG suivie d'une vidéo (photo animée) : pas de marque de fin exigée.
        let mut jpeg = vec![0xff, 0xd8, 0xff, 0xe1];
        jpeg.resize(64, 7);
        assert!(!format_perdu("jpg", &[jpeg, vec![9u8; 64]]));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tube_nomme_ne_bloque_pas() {
        let d = std::env::temp_dir().join(format!("vanguard-tube-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let tube = d.join("p.docx");
        if crate::essais::tube_nomme(&tube).is_err() {
            let _ = std::fs::remove_dir_all(&d);
            return crate::essais::saute("mkfifo indisponible ici");
        }
        // Sans O_NONBLOCK, cet appel attendait un écrivain pour toujours.
        let e = echantillons(&tube).unwrap();
        let _ = std::fs::remove_dir_all(&d);
        assert_eq!(e.len(), 0);
    }

    #[test]
    fn format_perdu_sur_pdf_chiffre() {
        // En-tête chiffré, mais le reste encore à faible entropie (chiffrement intermittent) : le format perdu suffit.
        let mut octets = vec![0u8; TAILLE_ECHANTILLON];
        getrandom::fill(&mut octets[..512]).unwrap();
        assert!(format_perdu("pdf", &[octets]));
    }

    #[test]
    fn texte_chiffre_perd_son_format() {
        let texte = "Bonjour, ceci est une note bien lisible.\n".repeat(50).into_bytes();
        assert!(!format_perdu("txt", std::slice::from_ref(&texte)));
        let mut chiffre = vec![0u8; 2048];
        getrandom::fill(&mut chiffre).unwrap();
        assert!(format_perdu("txt", &[chiffre]));
        // Texte devenu binaire, repéré par le contenu.
        let mut apres = vec![0u8; 2048];
        getrandom::fill(&mut apres).unwrap();
        assert!(texte_devenu_binaire(&texte, &apres));
    }

    #[test]
    fn base64_de_chiffre_perd_le_format_par_le_type() {
        // Des octets chiffrés encodés en base64 ont une entropie ≈ 6 (en dessous du seuil) : seul le format perdu
        // d'un type connu (PDF) les prend. Une extension inconnue avec du base64 ne déclenche donc pas R2, et c'est
        // voulu (pas de faux positif sur un vrai .b64).
        let brut: Vec<u8> = (0..3072u32).map(|i| u8::try_from(i * 37 % 256).unwrap()).collect();
        let b64 = base64_simple(&brut);
        assert!(
            entropie(b64.as_bytes()) < ENTROPIE_CHIFFRE,
            "{}",
            entropie(b64.as_bytes())
        );
        assert!(format_perdu("pdf", &[b64.clone().into_bytes()]));
        assert!(!format_perdu("b64", &[b64.into_bytes()]));
    }

    fn base64_simple(octets: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for bloc in octets.chunks(3) {
            let b = [bloc[0], *bloc.get(1).unwrap_or(&0), *bloc.get(2).unwrap_or(&0)];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for k in 0..4 {
                s.push(T[((n >> (18 - 6 * k)) & 0x3f) as usize] as char);
            }
        }
        s
    }

    #[test]
    fn echantillons_petit_et_moyen() {
        let petit = vec![1u8; 100];
        let e = echantillons_de(&mut Cursor::new(&petit), petit.len() as u64).unwrap();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].len(), 100);

        let moyen = vec![2u8; 100_000];
        let e = echantillons_de(&mut Cursor::new(&moyen), moyen.len() as u64).unwrap();
        assert_eq!(e.len(), 3);
        assert!(e.iter().all(|x| x.len() == TAILLE_ECHANTILLON));

        let vide: Vec<u8> = Vec::new();
        let rien = echantillons_de(&mut Cursor::new(&vide), 0).unwrap();
        assert_eq!(rien, Vec::<Vec<u8>>::new());
    }
}

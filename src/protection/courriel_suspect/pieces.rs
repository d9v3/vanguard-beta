//! Les pièces jointes, jugées sans jamais être ouvertes : leur nom (programme, double extension, caractère qui retourne
//! l'écriture), ce que leur contenu montre de lui-même (archive à mot de passe, macros, PDF qui lance du code, objet
//! intégré dans un RTF), puis YARA et l'antivirus. Pour ces deux moteurs, chaque pièce est écrite dans un dossier
//! jetable, sous un nom choisi par Vanguard (jamais celui de l'expéditeur, qui pourrait sortir du dossier), lisible
//! par l'utilisateur seul, jamais exécutable, et le dossier est effacé à la fin, même sur erreur.

use std::path::{Path, PathBuf};

use super::Signe;
use crate::protection::antivirus::Examen;
use crate::protection::telechargement;
use crate::risk::Niveau;
use crate::{tr, trf};

/// Une pièce jointe jugée.
#[derive(Debug)]
pub(crate) struct Piece {
    /// Le nom donné par l'expéditeur, brut (à rendre `affichable` avant de le montrer).
    pub nom: String,
    pub type_declare: String,
    pub taille: usize,
    pub signes: Vec<Signe>,
    /// Ce que n'a pas pu vérifier l'examen du contenu (message Outlook joint, archive illisible…).
    pub manques: Vec<String>,
    /// Le verdict de chaque moteur.
    pub moteurs: Vec<(String, Examen)>,
}

/// Pièces passées aux moteurs au plus : un courriel de 300 pièces ne doit pas occuper l'antivirus une heure.
pub(crate) const MOTEURS_MAX: usize = 20;
/// Entrées lues dans une archive.
const ZIP_ENTREES: usize = 2_000;

/// Ce qu'est un fichier, d'après son extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Classe {
    Programme,
    ImageDisque,
    Raccourci,
    OneNote,
    PageWeb,
    Macros,
    Archive,
}

/// Programmes et scripts en plus de ceux de « Vérifier un fichier téléchargé » : ceux que Windows lance d'un double
/// clic et qu'on ne voit qu'en pièce jointe.
const SCRIPTS: &[&str] = &[
    "vbs",
    "vbe",
    "wsf",
    "wsh",
    "hta",
    "cpl",
    "msc",
    "scr",
    "reg",
    "chm",
    "xll",
    "inf",
    "ps1",
    "psm1",
    "jse",
    "js",
    "bat",
    "cmd",
    "com",
    "pif",
    "msi",
    "msix",
    "appx",
    "appxbundle",
    "jar",
    "py",
    "pyw",
    "application",
    "gadget",
    "sct",
    "mde",
    "accde",
];

fn classe(extension: &str) -> Option<Classe> {
    let e = extension;
    // « .lnk » est un raccourci (dit comme tel) ; « .bin » n'est pas forcément un programme.
    if (telechargement::PROGRAMMES.contains(&e) && !matches!(e, "lnk" | "bin")) || SCRIPTS.contains(&e) {
        return Some(Classe::Programme);
    }
    Some(match e {
        "iso" | "img" | "vhd" | "vhdx" | "udf" => Classe::ImageDisque,
        "lnk" | "url" | "website" | "library-ms" | "searchconnector-ms" | "settingcontent-ms" => Classe::Raccourci,
        "one" | "onepkg" => Classe::OneNote,
        "html" | "htm" | "shtml" | "xhtml" | "svg" | "mht" | "mhtml" => Classe::PageWeb,
        "docm" | "xlsm" | "pptm" | "dotm" | "xltm" | "xlam" | "ppam" | "potm" | "xlsb" => Classe::Macros,
        "zip" | "rar" | "7z" | "gz" | "tgz" | "tar" | "cab" | "ace" | "arj" | "lzh" | "xz" | "bz2" | "z" | "zst" => {
            Classe::Archive
        }
        _ => return None,
    })
}

/// L'extension d'un nom tel que Windows le lit : en minuscules, espaces et points de fin retirés.
pub(crate) fn extension(nom: &str) -> String {
    let nom = nom.trim_end_matches(['.', ' ']);
    match nom.rsplit_once('.') {
        Some((avant, e)) if !avant.is_empty() => e.trim().to_lowercase(),
        _ => String::new(),
    }
}

const OLE: &[u8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1";

/// Cherche `aiguille` dans `meule`, en temps linéaire (Knuth-Morris-Pratt) : une pièce jointe de 50 Mo fabriquée pour
/// ressembler sans fin au motif ne doit pas faire tourner la recherche des minutes.
fn trouve(meule: &[u8], aiguille: &[u8]) -> bool {
    if aiguille.is_empty() {
        return true;
    }
    // `repli[j]` : la longueur du plus long bord de `aiguille[..=j]` ; poussé dans l'ordre, si bien qu'au tour de
    // l'octet `i`, `repli` a `i` cases et `k` < `i`.
    let mut repli = Vec::with_capacity(aiguille.len());
    repli.push(0_usize);
    let mut k = 0;
    for &c in aiguille.iter().skip(1) {
        #[expect(
            clippy::indexing_slicing,
            reason = "k < i = repli.len() < aiguille.len() : voir plus haut"
        )]
        while k > 0 && c != aiguille[k] {
            k = repli[k - 1];
        }
        if aiguille.get(k) == Some(&c) {
            k += 1;
        }
        repli.push(k);
    }
    let mut k = 0;
    for &o in meule {
        // `k` < `aiguille.len()` = `repli.len()` : il revient avant d'atteindre la longueur (return plus bas).
        #[expect(
            clippy::indexing_slicing,
            reason = "0 < k < aiguille.len() = repli.len() : voir plus haut"
        )]
        while k > 0 && o != aiguille[k] {
            k = repli[k - 1];
        }
        if aiguille.get(k) == Some(&o) {
            k += 1;
            if k == aiguille.len() {
                return true;
            }
        }
    }
    false
}

/// Le motif en UTF-16 petit-boutiste, comme les noms dans un fichier OLE.
fn utf16(t: &str) -> Vec<u8> {
    t.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn mot16(o: &[u8], i: usize) -> Option<usize> {
    o.get(i..)?
        .first_chunk::<2>()
        .map(|b| usize::from(u16::from_le_bytes(*b)))
}

fn mot32(o: &[u8], i: usize) -> Option<usize> {
    o.get(i..)?
        .first_chunk::<4>()
        .and_then(|b| usize::try_from(u32::from_le_bytes(*b)).ok())
}

/// Les noms d'une archive zip (et s'ils sont chiffrés), lus dans son répertoire central seul : rien n'est décompressé.
/// `plugins::archive` refuse les archives chiffrées, qui sont justement ce qu'on cherche ici.
fn noms_zip(o: &[u8], max: usize) -> Result<(Vec<(String, bool)>, bool), ()> {
    // La fin du répertoire central : dans les 65 557 derniers octets (22 + un commentaire de 65 535 au plus).
    let debut_recherche = o.len().saturating_sub(65_557);
    let fin = (debut_recherche..o.len().saturating_sub(21))
        .rev()
        .find(|&i| o.get(i..).is_some_and(|r| r.starts_with(b"PK\x05\x06")))
        .ok_or(())?;
    let total = mot16(o, fin + 10).ok_or(())?;
    let mut i = mot32(o, fin + 16).ok_or(())?;
    // 0xFFFFFFFF : archive ZIP64, au répertoire ailleurs ; pas lue.
    if i == 0xffff_ffff {
        return Err(());
    }
    let mut noms = Vec::new();
    for _ in 0..total.min(max) {
        if o.get(i..i + 4) != Some(b"PK\x01\x02") {
            return if noms.is_empty() { Err(()) } else { Ok((noms, true)) };
        }
        let drapeaux = mot16(o, i + 8).ok_or(())?;
        let (n, extra, commentaire) = (
            mot16(o, i + 28).ok_or(())?,
            mot16(o, i + 30).ok_or(())?,
            mot16(o, i + 32).ok_or(())?,
        );
        let debut = o.get(i + 46..i + 46 + n.min(1_024)).ok_or(())?;
        // La fin du nom, où sont l'extension et le dernier dossier : garder le début laissait un long chemin de
        // dossiers cacher un programme (un signe élevé devenu moyen, sans rien dire). Un nom coupé par la fin du
        // fichier garde son début, et l'archive se dit incomplète : même la dernière entrée, sans suivante pour le dire.
        let Some(entier) = o.get(i + 46..i + 46 + n) else {
            noms.push((String::from_utf8_lossy(debut).into_owned(), drapeaux & 1 != 0));
            return Ok((noms, true));
        };
        let nom = entier.get(entier.len().saturating_sub(1_024)..).unwrap_or(entier);
        noms.push((String::from_utf8_lossy(nom).into_owned(), drapeaux & 1 != 0));
        i += 46 + n + extra + commentaire;
    }
    Ok((noms, total > max))
}

/// Ce que montrent le nom, le type annoncé et le contenu d'une pièce jointe ; et ce qui n'a pas pu être vérifié.
pub(crate) fn juger(nom: &str, type_declare: &str, contenu: &[u8]) -> (Vec<Signe>, Vec<String>) {
    let mut signes: Vec<Signe> = Vec::new();
    let mut manques = Vec::new();
    let montre = crate::ui::affichable(nom);
    let montre = crate::ui::couper(&montre, 60);
    let debut = contenu.get(..8).unwrap_or(contenu);
    let nature = telechargement::nature(nom, debut);
    // Le conseil de `nature` pour un programme téléchargé (« ne le lance que s'il vient du site officiel ») contredirait
    // ici un « ne l'ouvre pas » : retiré plus bas quand un signe plus grave le dit.
    let conseils: Vec<String> = nature
        .iter()
        .filter(|(n, _)| *n == Niveau::Info)
        .map(|(_, t)| t.clone())
        .collect();
    signes.extend(nature);
    let ext = extension(nom);
    signes.extend(signe_du_nom(classe(&ext), &montre));
    // Un SVG est une image qui peut porter du script : ouvert (« noname » chez Gmail, « Part 1.2 » chez Thunderbird),
    // il s'exécute dans le navigateur. Sans nom, rien d'autre ne le dit.
    if classe(&ext) != Some(Classe::PageWeb)
        && (type_declare == "image/svg+xml" || ext == "svg")
        && contenu.to_ascii_lowercase().windows(7).any(|w| w == b"<script")
    {
        let qui = if nom.is_empty() {
            tr!("Pièce sans nom", "Unnamed attachment").to_string()
        } else {
            montre.clone()
        };
        signes.push((
            Niveau::Eleve,
            trf!(
                "{qui} : image SVG qui contient du script ; ouverte, elle s'exécute dans le navigateur.",
                "{qui}: SVG image containing script; once opened, it runs in the browser."
            ),
        ));
    }
    // Un programme sous un type de document annoncé : le nom peut être anodin, le contenu non.
    let programme = matches!(debut, [b'M', b'Z', ..] | [0x7f, b'E', b'L', b'F', ..]);
    let type_document = [
        "application/pdf",
        "image/",
        "text/",
        "application/msword",
        "application/vnd.",
    ]
    .iter()
    .any(|t| type_declare.starts_with(t));
    if programme && type_document && !signes.iter().any(|(n, _)| *n >= Niveau::Eleve) {
        signes.push((
            Niveau::Eleve,
            trf!(
                "{montre} : annoncé comme {}, c'est un programme.",
                "{montre}: announced as {}, it is a program.",
                crate::ui::affichable(type_declare)
            ),
        ));
    }

    regarder_le_contenu(contenu, &montre, &mut signes, &mut manques);
    let bas = nom.to_ascii_lowercase();
    if bas == "winmail.dat" || type_declare == "application/ms-tnef" {
        signes.push((
            Niveau::Info,
            tr!(
                "winmail.dat : pièces jointes emballées par Outlook, pas lues par Vanguard.",
                "winmail.dat: attachments wrapped by Outlook, not read by Vanguard."
            )
            .to_string(),
        ));
        manques.push("winmail.dat".to_string());
    }
    if matches!(
        type_declare,
        "application/pkcs7-mime" | "application/x-pkcs7-mime" | "application/pgp-encrypted"
    ) {
        manques.push(tr!("une partie chiffrée", "an encrypted part").to_string());
    }
    if signes.iter().any(|(n, _)| *n >= Niveau::Eleve) {
        signes.retain(|(n, t)| *n != Niveau::Info || !conseils.contains(t));
    }
    (signes, manques)
}

/// Ce que dit le nom seul, d'après sa classe d'extension.
fn signe_du_nom(classe: Option<Classe>, montre: &str) -> Option<Signe> {
    match classe {
        Some(Classe::Programme) => Some((
            Niveau::Eleve,
            trf!(
                "{montre} : un programme en pièce jointe. Aucun service sérieux n'en envoie ; ne l'ouvrez pas.",
                "{montre}: a program as an attachment. No serious service sends one; do not open it."
            ),
        )),
        Some(Classe::ImageDisque) => Some((
            Niveau::Eleve,
            trf!(
                "{montre} : image disque. Ouverte, elle échappe à l'avertissement « fichier venu d'Internet » ; une ruse courante.",
                "{montre}: disk image. Once opened, it escapes the “file from the Internet” warning; a common trick."
            ),
        )),
        Some(Classe::Raccourci) => Some((
            Niveau::Eleve,
            trf!(
                "{montre} : un raccourci, qui peut lancer n'importe quel programme.",
                "{montre}: a shortcut, which can start any program."
            ),
        )),
        Some(Classe::OneNote) => Some((
            Niveau::Eleve,
            trf!(
                "{montre} : bloc-notes OneNote, souvent piégé d'un bouton qui lance un programme.",
                "{montre}: OneNote notebook, often trapped with a button that starts a program."
            ),
        )),
        Some(Classe::PageWeb) => Some((
            Niveau::Eleve,
            trf!(
                "{montre} : page web en pièce jointe, souvent une fausse page de connexion qui s'ouvre depuis votre ordinateur.",
                "{montre}: web page as an attachment, often a fake login page that opens from your computer."
            ),
        )),
        Some(Classe::Macros) => Some((
            Niveau::Eleve,
            trf!(
                "{montre} : document à macros ; n'activez jamais le contenu qu'il demande.",
                "{montre}: macro-enabled document; never enable the content it asks for."
            ),
        )),
        Some(Classe::Archive) => Some((
            Niveau::Moyen,
            trf!(
                "{montre} : archive ; ce qu'elle contient se juge avant de l'ouvrir.",
                "{montre}: archive; what it contains must be judged before opening it."
            ),
        )),
        None => None,
    }
}

/// Ce que montre le contenu selon sa nature : archive zip, document OLE, PDF ou RTF ; et ce qui n'a pas pu être lu.
fn regarder_le_contenu(contenu: &[u8], montre: &str, signes: &mut Vec<Signe>, manques: &mut Vec<String>) {
    if contenu.starts_with(b"PK\x03\x04") || contenu.starts_with(b"PK\x05\x06") {
        regarder_le_zip(contenu, montre, signes, manques);
    } else if contenu.starts_with(OLE) {
        if trouve(contenu, &utf16("__substg1.0_")) {
            signes.push((
                Niveau::Info,
                trf!(
                    "{montre} : message Outlook joint (.msg), pas lu par Vanguard.",
                    "{montre}: attached Outlook message (.msg), not read by Vanguard."
                ),
            ));
            manques.push(trf!("le message joint {montre}", "the attached message {montre}"));
        } else if trouve(contenu, &utf16("_VBA_PROJECT")) {
            signes.push((
                Niveau::Eleve,
                trf!(
                    "{montre} : contient des macros (du code qui tourne à l'ouverture).",
                    "{montre}: contains macros (code that runs when opened)."
                ),
            ));
        }
    } else if contenu.starts_with(b"%PDF") {
        signes.extend(signes_pdf(contenu, montre));
    } else if contenu.starts_with(b"{\\rtf") && (trouve(contenu, b"\\object") || trouve(contenu, b"\\objdata")) {
        signes.push((
            Niveau::Moyen,
            trf!(
                "{montre} : document RTF avec un objet intégré, une façon connue de lancer du code.",
                "{montre}: RTF document with an embedded object, a known way to run code."
            ),
        ));
    }
}

/// Les noms d'une archive zip : chiffrés, à macros, ou qui cachent un programme ; une archive illisible ou coupée est dite.
fn regarder_le_zip(contenu: &[u8], montre: &str, signes: &mut Vec<Signe>, manques: &mut Vec<String>) {
    if let Ok((noms, coupe)) = noms_zip(contenu, ZIP_ENTREES) {
        if noms.iter().any(|(_, chiffre)| *chiffre) {
            signes.push((
                Niveau::Eleve,
                trf!(
                    "{montre} : archive à mot de passe ; les antivirus ne voient pas dedans, le mot de passe est souvent dans le message.",
                    "{montre}: password-protected archive; antivirus cannot see inside, the password is often in the message."
                ),
            ));
        }
        if noms
            .iter()
            .any(|(n, _)| n.to_ascii_lowercase().ends_with("vbaproject.bin"))
        {
            signes.push((
                Niveau::Eleve,
                trf!(
                    "{montre} : contient des macros (du code qui tourne à l'ouverture).",
                    "{montre}: contains macros (code that runs when opened)."
                ),
            ));
        }
        let dangereux: Vec<String> = noms
            .iter()
            .map(|(n, _)| n.rsplit(['/', '\\']).next().unwrap_or(n).to_string())
            .filter(|n| {
                matches!(
                    classe(&extension(n)),
                    Some(Classe::Programme | Classe::Raccourci | Classe::ImageDisque | Classe::OneNote)
                ) || !telechargement::nature(n, b"").is_empty()
            })
            .map(|n| crate::ui::affichable(&n))
            .collect();
        if !dangereux.is_empty() {
            signes.push((
                Niveau::Eleve,
                trf!(
                    "{montre} contient un programme ou un raccourci : {}.",
                    "{montre} contains a program or a shortcut: {}.",
                    crate::ui::resume(&dangereux, 3, ", ")
                ),
            ));
        }
        if coupe {
            manques.push(trf!("le contenu complet de {montre}", "the full content of {montre}"));
        }
    } else {
        signes.push((
            Niveau::Info,
            trf!(
                "{montre} : archive illisible, son contenu n'a pas été examiné.",
                "{montre}: unreadable archive, its content was not examined."
            ),
        ));
        manques.push(trf!("le contenu de {montre}", "the content of {montre}"));
    }
}

/// Les mots d'un PDF qui lancent quelque chose. Leur absence ne prouve rien : un PDF peut les cacher dans des objets
/// compressés, que Vanguard ne décompresse pas.
fn signes_pdf(o: &[u8], montre: &str) -> Vec<Signe> {
    let js = trouve(o, b"/JavaScript")
        || [
            b"/JS ".as_slice(),
            b"/JS(",
            b"/JS<",
            b"/JS/",
            b"/JS[",
            b"/JS\n",
            b"/JS\r",
        ]
        .iter()
        .any(|m| trouve(o, m));
    let mut signes = Vec::new();
    if js || trouve(o, b"/Launch") {
        signes.push((
            Niveau::Eleve,
            trf!(
                "{montre} : PDF qui contient du code ou lance un programme à l'ouverture.",
                "{montre}: PDF that contains code or starts a program when opened."
            ),
        ));
    }
    if trouve(o, b"/EmbeddedFile") {
        signes.push((
            Niveau::Moyen,
            trf!(
                "{montre} : PDF qui transporte un autre fichier.",
                "{montre}: PDF carrying another file."
            ),
        ));
    }
    if signes.is_empty() {
        signes.push((
            Niveau::Info,
            trf!(
                "{montre} : rien de piégé vu dans ce PDF, ce qui ne prouve rien (ses parties compressées ne sont pas lues).",
                "{montre}: nothing trapped seen in this PDF, which proves nothing (its compressed parts are not read)."
            ),
        ));
    }
    signes
}

/// Le dossier jetable des pièces, effacé quand il sort de portée, même sur erreur ou panique.
struct Jetable(PathBuf);

impl Drop for Jetable {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Le nom sous lequel une pièce est écrite : « piece-01.pdf ». L'extension d'origine aide l'antivirus à choisir son
/// examen ; réduite à des lettres et chiffres, elle ne peut rien faire sortir du dossier.
fn nom_disque(rang: usize, nom: &str) -> String {
    let ext = extension(nom);
    let ext = if (1..=8).contains(&ext.len()) && ext.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) {
        ext
    } else {
        "bin".into()
    };
    format!("piece-{:02}.{ext}", rang + 1)
}

fn ecrire(chemin: &Path, contenu: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(chemin)?.write_all(contenu)
}

/// Passe les pièces (au plus `MOTEURS_MAX`) à `examiner`, chacune écrite dans le dossier jetable `dossier` (créé par
/// l'appelant, effacé ici). `examiner` rend le verdict de chaque moteur ; les tests le remplacent par un faux.
pub(crate) fn passer_aux_moteurs(
    dossier: PathBuf,
    pieces: &mut [Piece],
    contenus: &[&[u8]],
    examiner: &mut dyn FnMut(&Path) -> Vec<(String, Examen)>,
) {
    let jetable = Jetable(dossier);
    for (rang, (piece, contenu)) in pieces.iter_mut().zip(contenus).enumerate().take(MOTEURS_MAX) {
        let chemin = jetable.0.join(nom_disque(rang, &piece.nom));
        if let Err(e) = ecrire(&chemin, contenu) {
            piece.moteurs.push((
                tr!("Écriture", "Writing").into(),
                Examen::Impossible(trf!(
                    "pièce non écrite dans le dossier jetable : {e}",
                    "attachment not written to the disposable folder: {e}"
                )),
            ));
            continue;
        }
        // L'antivirus du système (Defender) retire à la volée ce qu'il reconnaît : la pièce a disparu, c'est un verdict.
        if !chemin.exists() {
            piece.moteurs.push((
                tr!("Antivirus", "Antivirus").into(),
                Examen::Trouve(vec![tr!("retiré dès l'écriture", "removed as soon as written").into()]),
            ));
            continue;
        }
        piece.moteurs = examiner(&chemin);
        let _ = std::fs::remove_file(&chemin);
    }
}

/// Les vrais moteurs : YARA, puis l'antivirus. Un antivirus absent n'est proposé qu'une fois (l'installer ? non) : sa
/// réponse vaut pour les pièces suivantes, au lieu de reposer la question à chacune. Un fichier sauté par Defender
/// (exclu), lui, ne dit rien des autres : chacune repasse.
pub(crate) fn moteurs(
    yara: impl Fn(&Path) -> Examen,
    antivirus: impl Fn(&Path) -> Examen,
) -> impl FnMut(&Path) -> Vec<(String, Examen)> {
    let nom_antivirus = if cfg!(windows) { "Defender" } else { "ClamAV" };
    let mut absent: Option<String> = None;
    move |chemin| {
        let av = if let Some(raison) = &absent {
            Examen::Impossible(raison.clone())
        } else {
            let e = antivirus(chemin);
            if let Examen::Impossible(raison) = &e
                && raison != crate::protection::antivirus::raison_sautee()
            {
                absent = Some(raison.clone());
            }
            e
        };
        vec![("YARA".into(), yara(chemin)), (nom_antivirus.into(), av)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pire(signes: &[Signe]) -> Option<Niveau> {
        signes.iter().map(|(n, _)| *n).max()
    }

    /// Une archive zip sans compression (méthode 0) : en-têtes locaux, répertoire central, fin.
    fn zip(entrees: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut o = Vec::new();
        let mut central = Vec::new();
        for (nom, donnees, chiffre) in entrees {
            let local = u32::try_from(o.len()).unwrap();
            let drapeaux: u16 = u16::from(*chiffre);
            let n = u16::try_from(nom.len()).unwrap();
            let t = u32::try_from(donnees.len()).unwrap();
            o.extend_from_slice(b"PK\x03\x04\x14\0");
            o.extend_from_slice(&drapeaux.to_le_bytes());
            o.extend_from_slice(&[0; 10]);
            o.extend_from_slice(&t.to_le_bytes());
            o.extend_from_slice(&t.to_le_bytes());
            o.extend_from_slice(&n.to_le_bytes());
            o.extend_from_slice(&0_u16.to_le_bytes());
            o.extend_from_slice(nom.as_bytes());
            o.extend_from_slice(donnees);
            central.extend_from_slice(b"PK\x01\x02\x14\0\x14\0");
            central.extend_from_slice(&drapeaux.to_le_bytes());
            central.extend_from_slice(&[0; 10]);
            central.extend_from_slice(&t.to_le_bytes());
            central.extend_from_slice(&t.to_le_bytes());
            central.extend_from_slice(&n.to_le_bytes());
            central.extend_from_slice(&[0; 12]);
            central.extend_from_slice(&local.to_le_bytes());
            central.extend_from_slice(nom.as_bytes());
        }
        let debut = u32::try_from(o.len()).unwrap();
        let taille = u32::try_from(central.len()).unwrap();
        let nombre = u16::try_from(entrees.len()).unwrap();
        o.extend_from_slice(&central);
        o.extend_from_slice(b"PK\x05\x06\0\0\0\0");
        o.extend_from_slice(&nombre.to_le_bytes());
        o.extend_from_slice(&nombre.to_le_bytes());
        o.extend_from_slice(&taille.to_le_bytes());
        o.extend_from_slice(&debut.to_le_bytes());
        o.extend_from_slice(&[0, 0]);
        o
    }

    #[test]
    fn noms_et_contenus() {
        let (s, _) = juger("facture.pdf.exe", "application/octet-stream", b"MZ\x90\0");
        assert_eq!(pire(&s), Some(Niveau::Eleve));
        assert!(s.iter().any(|(_, t)| t.contains("Double extension")));
        let (s, _) = juger("facture\u{202e}fdp.exe", "application/pdf", b"MZ");
        assert_eq!(pire(&s), Some(Niveau::Critique));
        // Le nom montré est désamorcé.
        assert!(s.iter().all(|(_, t)| !t.contains('\u{202e}')));
        for nom in [
            "image.iso",
            "raccourci.lnk",
            "page.html",
            "devis.docm",
            "notes.one",
            "a.vbs",
            "a.HTA. ",
        ] {
            assert_eq!(pire(&juger(nom, "", b"").0), Some(Niveau::Eleve), "{nom}");
        }
        assert_eq!(pire(&juger("photos.zip", "", b"").0), Some(Niveau::Moyen));
        assert_eq!(pire(&juger("photo.jpg", "image/jpeg", b"\xff\xd8\xff").0), None);
        // Programme annoncé comme une image, sous un nom anodin.
        assert_eq!(pire(&juger("photo", "image/jpeg", b"MZ\x90\0").0), Some(Niveau::Eleve));
    }

    /// B1 (campagne 5) : un programme rangé sous un chemin de plus de 1 024 octets reste vu, au lieu de perdre son
    /// extension avec la fin du nom.
    #[test]
    fn programme_sous_un_long_chemin() {
        let long = format!("{}/scan.js", "dossier/".repeat(140));
        assert!(long.len() > 1_024);
        let z = zip(&[("lisez-moi.txt", b"x", false), (long.as_str(), b"y", false)]);
        let (s, _) = juger("documents.zip", "application/zip", &z);
        assert!(
            s.iter().any(|(n, t)| *n == Niveau::Eleve && t.contains("scan.js")),
            "{s:?}"
        );
    }

    /// La dernière entrée du répertoire annonce un nom plus long que ce qui reste du fichier : l'archive se dit
    /// incomplète, sans entrée suivante pour le dire (relecture du lot campagne 5).
    #[test]
    fn dernier_nom_coupe_par_la_fin() {
        let mut o = b"PK\x01\x02".to_vec();
        o.resize(46, 0);
        o[28..30].copy_from_slice(&5_000u16.to_le_bytes());
        o.extend([b'd'; 1_100]);
        let fin = o.len();
        o.extend(b"PK\x05\x06");
        o.resize(fin + 22, 0);
        o[fin + 10..fin + 12].copy_from_slice(&1u16.to_le_bytes());
        let (noms, coupe) = noms_zip(&o, ZIP_ENTREES).unwrap();
        assert_eq!(noms.len(), 1);
        assert!(coupe);
    }

    #[test]
    fn archives() {
        let z = zip(&[("lisez-moi.txt", b"x", false), ("scan.js", b"y", false)]);
        let (s, _) = juger("documents.zip", "application/zip", &z);
        assert!(
            s.iter().any(|(n, t)| *n == Niveau::Eleve && t.contains("scan.js")),
            "{s:?}"
        );
        let z = zip(&[("facture.pdf", b"x", true)]);
        let (s, _) = juger("facture.zip", "application/zip", &z);
        assert!(
            s.iter().any(|(n, t)| *n == Niveau::Eleve && t.contains("mot de passe")),
            "{s:?}"
        );
        let z = zip(&[
            ("[Content_Types].xml", b"x", false),
            ("word/vbaProject.bin", b"y", false),
        ]);
        let (s, _) = juger("devis.docx", "application/vnd.openxmlformats", &z);
        assert!(
            s.iter().any(|(n, t)| *n == Niveau::Eleve && t.contains("macros")),
            "{s:?}"
        );
        let (s, manques) = juger("abime.zip", "application/zip", b"PK\x03\x04abime");
        assert!(s.iter().any(|(_, t)| t.contains("illisible")) && !manques.is_empty());
    }

    #[test]
    fn ole_pdf_rtf() {
        let mut ole = OLE.to_vec();
        ole.extend(vec![0; 100]);
        ole.extend(utf16("_VBA_PROJECT"));
        assert_eq!(
            pire(&juger("vieux.doc", "application/msword", &ole).0),
            Some(Niveau::Eleve)
        );
        let mut msg = OLE.to_vec();
        msg.extend(utf16("__substg1.0_0037001F"));
        let (s, manques) = juger("transfere.msg", "application/vnd.ms-outlook", &msg);
        assert_eq!(pire(&s), Some(Niveau::Info));
        assert_ne!(manques, Vec::<String>::new());
        let pdf = b"%PDF-1.7\n1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>";
        assert_eq!(pire(&juger("f.pdf", "application/pdf", pdf).0), Some(Niveau::Eleve));
        let (s, _) = juger("f.pdf", "application/pdf", b"%PDF-1.7\n/Type /Catalog");
        assert_eq!(pire(&s), Some(Niveau::Info));
        let rtf = b"{\\rtf1 {\\object\\objemb {\\*\\objdata 0105}}}";
        assert_eq!(pire(&juger("f.rtf", "application/rtf", rtf).0), Some(Niveau::Moyen));
    }

    #[test]
    fn recherche_lineaire() {
        assert!(trouve(b"aaab", b"aab"));
        assert!(!trouve(b"aaaa", b"aab"));
        // Une meule fabriquée pour frôler le motif sans fin : vite.
        let meule = b"_\0".repeat(5_000_000);
        let debut = std::time::Instant::now();
        assert!(!trouve(&meule, &utf16("_VBA_PROJECT")));
        assert!(debut.elapsed() < std::time::Duration::from_secs(5));
    }

    fn piece(nom: &str) -> Piece {
        Piece {
            nom: nom.into(),
            type_declare: String::new(),
            taille: 1,
            signes: Vec::new(),
            manques: Vec::new(),
            moteurs: Vec::new(),
        }
    }

    #[test]
    fn pieces_ecrites_a_l_abri() {
        let dossier = crate::protection::isoler::dossier_jetable().unwrap();
        let garde = dossier.clone();
        let mut pieces = vec![piece("../../.bashrc"), piece("../../evil"), piece("rapport.PDF")];
        let mut vus = Vec::new();
        let mut faux = |p: &Path| {
            vus.push(p.to_path_buf());
            assert!(p.starts_with(&garde));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(std::fs::metadata(p).unwrap().permissions().mode() & 0o777, 0o600);
            }
            vec![("YARA".to_string(), Examen::Sain)]
        };
        passer_aux_moteurs(dossier.clone(), &mut pieces, &[b"x", b"y", b"%PDF"], &mut faux);
        // Jamais le nom de l'expéditeur : seule son extension, réduite à des lettres et des chiffres, est gardée.
        assert_eq!(vus[0].file_name().unwrap(), "piece-01.bashrc");
        assert_eq!(vus[1].file_name().unwrap(), "piece-02.bin");
        assert_eq!(vus[2].file_name().unwrap(), "piece-03.pdf");
        assert!(!dossier.exists(), "dossier jetable effacé");
        assert!(matches!(pieces[0].moteurs[0].1, Examen::Sain));
    }

    #[test]
    fn moteurs_absents_ou_qui_trouvent() {
        let appels = std::cell::Cell::new(0);
        let mut m = moteurs(
            |_| Examen::Trouve(vec!["Eicar".into()]),
            |_| {
                appels.set(appels.get() + 1);
                Examen::Impossible("ClamAV absent".into())
            },
        );
        let p = Path::new("/nexiste/pas");
        let un = m(p);
        let deux = m(p);
        // L'antivirus absent n'est demandé qu'une fois ; sa réponse vaut pour la pièce suivante, jamais « sain ».
        assert_eq!(appels.get(), 1);
        assert!(matches!(&deux[1].1, Examen::Impossible(r) if r == "ClamAV absent"));
        assert!(matches!(&un[0].1, Examen::Trouve(_)));
        // Relecture Defender : une pièce sautée (exclue) ne fait pas sauter les suivantes.
        let appels = std::cell::Cell::new(0);
        let mut m = moteurs(
            |_| Examen::Sain,
            |_| {
                appels.set(appels.get() + 1);
                if appels.get() == 1 {
                    Examen::Impossible(crate::protection::antivirus::raison_sautee().into())
                } else {
                    Examen::Trouve(vec!["Eicar".into()])
                }
            },
        );
        assert!(matches!(&m(p)[1].1, Examen::Impossible(_)));
        assert!(matches!(&m(p)[1].1, Examen::Trouve(_)));
        assert_eq!(appels.get(), 2);
    }
}

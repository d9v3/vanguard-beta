//! Fichiers sensibles qui traînent : dans Téléchargements et sur le Bureau, une pièce d'identité scannée, un relevé
//! bancaire, un export de mots de passe, une base KeePass, une clé privée ; dans Documents, seulement ce qui est un
//! secret en clair (mots de passe, clés). Un fichier reconnu à son nom ; un .csv, à sa première ligne (un export de
//! navigateur ou de gestionnaire a une colonne « password »). Rien d'autre n'est lu, rien ne part nulle part : le bilan
//! donne les noms et le conseil (ranger dans un dossier chiffré, ou supprimer ce qui a déjà servi).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::{Constat, alerte, ok};
use crate::risk::Niveau;
use crate::ui::*;

const CAT: &str = "Fichiers secrets";
/// Au-delà de cette profondeur, on ne descend plus (Documents peut être un arbre entier).
const PROFONDEUR: usize = 3;
/// Au plus ça d'entrées regardées par dossier, et ce temps pour tout : le bilan ne doit pas attendre un disque lent.
const MAX_ENTREES: usize = 5000;
const BUDGET: Duration = Duration::from_secs(5);

/// Pourquoi un fichier est sensible.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Raison {
    /// Pièce d'identité : passeport, permis, carte, numéro d'assurance sociale, acte de naissance.
    Identite,
    /// Mots de passe en clair : export, liste, base de gestionnaire hors de sa place, codes de secours.
    MotsDePasse,
    /// Clé privée, certificat avec sa clé, configuration VPN, portefeuille.
    Cles,
    /// Argent : relevé, impôts, paie, RIB.
    Argent,
}

impl Raison {
    fn nom(self) -> &'static str {
        match self {
            Raison::Identite => tr!("pièce d'identité", "identity document"),
            Raison::MotsDePasse => tr!("mots de passe", "passwords"),
            Raison::Cles => tr!("clé privée", "private key"),
            Raison::Argent => tr!("relevé ou impôts", "statement or taxes"),
        }
    }
}

/// Un dossier regardé, et ce qu'on y cherche : dans Documents, seulement les secrets en clair (une pièce d'identité
/// y est à sa place, c'est le chiffrement du disque qui la protège).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Dossier {
    Telechargements,
    Bureau,
    Documents,
}

impl Dossier {
    fn nom(self) -> &'static str {
        match self {
            Dossier::Telechargements => tr!("Téléchargements", "Downloads"),
            Dossier::Bureau => tr!("Bureau", "Desktop"),
            Dossier::Documents => "Documents",
        }
    }

    fn retient(self, r: Raison) -> bool {
        self != Dossier::Documents || matches!(r, Raison::MotsDePasse | Raison::Cles)
    }
}

/// Minuscules et sans accents, les séparateurs gardés (le simplificateur des menus retire les tirets, ce qui collerait
/// « Passeport-Alice » en un seul mot).
fn simple(t: &str) -> String {
    let mut s = String::with_capacity(t.len());
    for c in t.chars().flat_map(char::to_lowercase) {
        match c {
            'à' | 'â' | 'ä' | 'á' => s.push('a'),
            'é' | 'è' | 'ê' | 'ë' => s.push('e'),
            'î' | 'ï' | 'í' => s.push('i'),
            'ô' | 'ö' | 'ó' => s.push('o'),
            'ù' | 'û' | 'ü' | 'ú' => s.push('u'),
            'ç' => s.push('c'),
            'œ' => s.push_str("oe"),
            autre => s.push(autre),
        }
    }
    s
}

/// Les mots d'un nom de fichier, simplifiés, coupés à tout ce qui n'est pas lettre ou chiffre ; « mot de passe »
/// devient « mot », « de », « passe ».
fn mots(nom: &str) -> Vec<String> {
    simple(nom)
        .split(|c: char| !c.is_alphanumeric())
        .filter(|m| !m.is_empty())
        .map(str::to_string)
        .collect()
}

/// `suite` se lit-elle, mot à mot, dans `mots` ?
fn contient(mots: &[String], suite: &[&str]) -> bool {
    mots.windows(suite.len())
        .any(|f| f.iter().zip(suite).all(|(a, b)| a == b))
}

/// Ce qu'un nom de fichier dit, à lui seul.
pub(super) fn raison_du_nom(nom: &str) -> Option<Raison> {
    let simple = simple(nom);
    let extension = Path::new(&simple)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();
    let m = mots(nom);
    let un_de = |liste: &[&str]| liste.iter().any(|v| m.iter().any(|x| x == v));
    let suite = |liste: &[&[&str]]| liste.iter().any(|s| contient(&m, s));
    if matches!(extension, "kdbx" | "kdb")
        || un_de(&[
            "password",
            "passwords",
            "passwd",
            "motdepasse",
            "motsdepasse",
            "mdp",
            "bitwarden",
            "lastpass",
            "1password",
            "dashlane",
            "keepass",
        ])
        || suite(&[
            &["mot", "de", "passe"],
            &["mots", "de", "passe"],
            &["codes", "de", "secours"],
            &["backup", "codes"],
            &["recovery", "codes"],
            &["recovery", "phrase"],
            &["seed", "phrase"],
            &["phrase", "de", "recuperation"],
            &["cle", "de", "recuperation"],
            &["recovery", "key"],
        ])
    {
        return Some(Raison::MotsDePasse);
    }
    if matches!(extension, "pem" | "key" | "ppk" | "p12" | "pfx" | "ovpn")
        || suite(&[&["id", "rsa"], &["id", "ed25519"], &["id", "ecdsa"]])
        || simple == "wallet.dat"
    {
        return Some(Raison::Cles);
    }
    if un_de(&["passeport", "passport", "permis", "nas", "sin", "ssn", "ramq"])
        || suite(&[
            &["carte", "d", "identite"],
            &["carte", "identite"],
            &["id", "card"],
            &["identity", "card"],
            &["assurance", "sociale"],
            &["social", "security"],
            &["social", "insurance"],
            &["acte", "de", "naissance"],
            &["birth", "certificate"],
            &["assurance", "maladie"],
            &["health", "card"],
            &["driver", "s", "license"],
            &["drivers", "license"],
            &["driving", "licence"],
        ])
    {
        return Some(Raison::Identite);
    }
    if un_de(&[
        "releve",
        "releves",
        "statement",
        "statements",
        "impot",
        "impots",
        "tax",
        "taxes",
        "t4",
        "t1",
        "rib",
        "iban",
        "payslip",
        "paystub",
        "salaire",
        "paie",
        "paye",
    ]) || suite(&[
        &["bulletin", "de", "paie"],
        &["bank", "statement"],
        &["declaration", "de", "revenus"],
        &["avis", "de", "cotisation"],
        &["notice", "of", "assessment"],
        &["specimen", "de", "cheque"],
        &["void", "cheque"],
        &["void", "check"],
    ]) {
        return Some(Raison::Argent);
    }
    None
}

/// Une première ligne de .csv qui nomme une colonne de mots de passe : un export de navigateur (« name,url,username,
/// password ») ou de gestionnaire (« …,login_username,login_password »).
pub(super) fn entete_de_mots_de_passe(premiere_ligne: &str) -> bool {
    let l = simple(premiere_ligne);
    l.split([',', ';', '\t'])
        .map(|c| c.trim().trim_matches('"'))
        .any(|c| matches!(c, "password" | "login_password" | "mot de passe" | "motdepasse" | "pwd"))
}

/// Les premiers 256 octets d'un fichier, seulement s'il finit par .csv : la première ligne, rien de plus.
fn premiere_ligne_csv(chemin: &Path) -> Option<String> {
    use std::io::Read;
    if !chemin.extension().is_some_and(|e| e.eq_ignore_ascii_case("csv")) {
        return None;
    }
    let mut debut = [0u8; 256];
    let n = std::fs::File::open(chemin).ok()?.read(&mut debut).ok()?;
    let texte = String::from_utf8_lossy(debut.get(..n)?);
    texte.lines().next().map(str::to_string)
}

/// Un fichier trouvé : (dossier, nom prêt à montrer, raison).
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Trouve {
    dossier: Dossier,
    nom: String,
    raison: Raison,
}

/// Parcourt `racine` (profondeur limitée, sans suivre les liens, sans les dossiers cachés) et retient les fichiers
/// sensibles que ce dossier doit signaler.
pub(super) fn parcourir(dossier: Dossier, racine: &Path, fin: Instant) -> Vec<Trouve> {
    let mut trouves = Vec::new();
    let mut a_voir: Vec<(PathBuf, usize)> = vec![(racine.to_path_buf(), 0)];
    let mut vus = 0;
    while let Some((d, profondeur)) = a_voir.pop() {
        let Ok(entrees) = std::fs::read_dir(&d) else { continue };
        for e in entrees.flatten() {
            vus += 1;
            if vus > MAX_ENTREES || Instant::now() > fin {
                return trouves;
            }
            let nom = e.file_name().to_string_lossy().into_owned();
            if nom.starts_with('.') {
                continue;
            }
            let Ok(meta) = std::fs::symlink_metadata(e.path()) else {
                continue;
            };
            if meta.is_dir() {
                if profondeur + 1 < PROFONDEUR {
                    a_voir.push((e.path(), profondeur + 1));
                }
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            let raison = raison_du_nom(&nom).or_else(|| {
                premiere_ligne_csv(&e.path())
                    .filter(|l| entete_de_mots_de_passe(l))
                    .map(|_| Raison::MotsDePasse)
            });
            if let Some(raison) = raison.filter(|r| dossier.retient(*r)) {
                trouves.push(Trouve {
                    dossier,
                    nom: affichable(&nom),
                    raison,
                });
            }
        }
    }
    trouves.sort_by(|a, b| a.nom.cmp(&b.nom));
    trouves
}

/// Les dossiers à regarder sur cette machine.
fn dossiers() -> Vec<(Dossier, PathBuf)> {
    let mut d = Vec::new();
    if let Some(t) = crate::protection::telechargement::dossier_telechargements().filter(|p| p.is_dir()) {
        d.push((Dossier::Telechargements, t));
    }
    for (sorte, chemin) in crate::copier::sources() {
        match sorte {
            crate::copier::Sorte::Bureau => d.push((Dossier::Bureau, chemin)),
            crate::copier::Sorte::Documents => d.push((Dossier::Documents, chemin)),
            _ => {}
        }
    }
    // Le Bureau non configuré est le dossier personnel lui-même : il contient Documents et Téléchargements, on ne
    // le parcourt pas deux fois.
    let maison = crate::socle::maison();
    d.retain(|(s, c)| *s != Dossier::Bureau || c != &maison);
    d
}

/// Le constat, d'après ce qui a été trouvé.
pub(super) fn juger(trouves: &[Trouve], regardes: &[Dossier]) -> Constat {
    if regardes.is_empty() {
        return ok(
            CAT,
            tr!(
                "Pas de dossier Téléchargements, Bureau ou Documents à regarder.",
                "No Downloads, Desktop or Documents folder to look at."
            ),
        );
    }
    let noms_regardes = regardes.iter().map(|d| d.nom()).collect::<Vec<_>>().join(", ");
    if trouves.is_empty() {
        return ok(
            CAT,
            trf!(
                "Rien de sensible qui traîne dans {noms_regardes} (noms seulement).",
                "Nothing sensitive lying around in {noms_regardes} (names only)."
            ),
        );
    }
    let mut ou: Vec<&str> = trouves.iter().map(|t| t.dossier.nom()).collect();
    ou.dedup();
    let exemples: Vec<String> = trouves
        .iter()
        .take(4)
        .map(|t| format!("{} ({})", t.nom, t.raison.nom()))
        .collect();
    let suite = match trouves.len().saturating_sub(4) {
        0 => String::new(),
        n => trf!(" et {n} autre(s)", " and {n} other(s)"),
    };
    let mots_de_passe = trouves.iter().any(|t| t.raison == Raison::MotsDePasse);
    let conseil = if mots_de_passe {
        tr!(
            "Supprimer les exports de mots de passe déjà importés (ils sont en clair) et ranger le reste dans un dossier chiffré ou hors de l'ordinateur",
            "Delete the password exports already imported (they are in clear) and move the rest to an encrypted folder or off the computer"
        )
    } else {
        tr!(
            "Ranger ces fichiers dans un dossier chiffré ou hors de l'ordinateur, ou les supprimer s'ils ont déjà servi",
            "Move these files to an encrypted folder or off the computer, or delete them if they have already served"
        )
    };
    alerte(
        CAT,
        Niveau::Info,
        trf!(
            "{} fichier(s) sensible(s) traînent dans {} : {}{suite}. Seul le nom a été lu (et la première ligne d'un .csv) ; un vol, un partage ou un programme malveillant les emporte avec le reste.",
            "{} sensitive file(s) lying around in {}: {}{suite}. Only the name was read (and the first line of a .csv); a theft, a share or a malicious program takes them with the rest.",
            trouves.len(),
            ou.join(", "),
            exemples.join(", ")
        ),
    )
    .manuel(conseil, &[])
}

/// Au bilan.
pub fn constats() -> Vec<Constat> {
    let fin = Instant::now() + BUDGET;
    let dossiers = dossiers();
    let regardes: Vec<Dossier> = dossiers.iter().map(|(d, _)| *d).collect();
    let trouves: Vec<Trouve> = dossiers
        .iter()
        .flat_map(|(d, chemin)| parcourir(*d, chemin, fin))
        .collect();
    vec![juger(&trouves, &regardes)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noms_reconnus_et_noms_ordinaires() {
        let sensibles = [
            ("Passeport-Alice.pdf", Raison::Identite),
            ("scan passport 2024.jpg", Raison::Identite),
            ("Carte d'identité.png", Raison::Identite),
            ("NAS.pdf", Raison::Identite),
            ("Permis de conduire.jpg", Raison::Identite),
            ("Mots de passe.txt", Raison::MotsDePasse),
            ("Chrome Passwords.csv", Raison::MotsDePasse),
            ("bitwarden_export_20261018.json", Raison::MotsDePasse),
            ("Perso.kdbx", Raison::MotsDePasse),
            ("codes-de-secours-google.txt", Raison::MotsDePasse),
            ("Recovery Key.txt", Raison::MotsDePasse),
            ("id_rsa", Raison::Cles),
            ("id_ed25519.pub", Raison::Cles),
            ("serveur.pem", Raison::Cles),
            ("bureau.ovpn", Raison::Cles),
            ("wallet.dat", Raison::Cles),
            ("Relevé mars 2026.pdf", Raison::Argent),
            ("T4-2025.pdf", Raison::Argent),
            ("Déclaration de revenus 2025.pdf", Raison::Argent),
            ("bank-statement-2026-03.pdf", Raison::Argent),
            ("Spécimen de chèque.pdf", Raison::Argent),
        ];
        for (nom, attendu) in sensibles {
            assert_eq!(raison_du_nom(nom), Some(attendu), "{nom}");
        }
        for nom in [
            "vacances.jpg",
            "Rapport final.docx",
            "installer.exe",
            "notes.txt",
            "sinus.pdf",
            "taxidermie.pdf",
            "nasa-photo.png",
            "permission.txt",
            "keyboard.pdf",
            "passage.pdf",
            "liste.csv",
        ] {
            assert_eq!(raison_du_nom(nom), None, "{nom}");
        }
    }

    #[test]
    fn entetes_de_csv() {
        assert!(entete_de_mots_de_passe("name,url,username,password,note"));
        assert!(entete_de_mots_de_passe(
            "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp"
        ));
        assert!(entete_de_mots_de_passe("\"Site\";\"Utilisateur\";\"Mot de passe\""));
        assert!(!entete_de_mots_de_passe("date,montant,description"));
        assert!(!entete_de_mots_de_passe("nom,password_hint"));
    }

    #[test]
    fn documents_ne_signale_que_les_secrets_en_clair() {
        assert!(Dossier::Telechargements.retient(Raison::Identite));
        assert!(Dossier::Bureau.retient(Raison::Argent));
        assert!(!Dossier::Documents.retient(Raison::Identite));
        assert!(!Dossier::Documents.retient(Raison::Argent));
        assert!(Dossier::Documents.retient(Raison::MotsDePasse));
        assert!(Dossier::Documents.retient(Raison::Cles));
    }

    #[test]
    fn parcours_d_un_dossier_d_essai() {
        let base = std::env::temp_dir().join(format!("vanguard-sensibles-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let profond = base.join("a/b/c/d");
        std::fs::create_dir_all(&profond).unwrap();
        std::fs::create_dir_all(base.join(".cache")).unwrap();
        std::fs::write(base.join("vacances.jpg"), "").unwrap();
        std::fs::write(base.join("Passeport.pdf"), "").unwrap();
        std::fs::write(base.join("export.csv"), "name,url,username,password\nx,y,z,w\n").unwrap();
        std::fs::write(base.join("budget.csv"), "date,montant\n1,2\n").unwrap();
        std::fs::write(base.join("a/b/Relevé.pdf"), "").unwrap();
        // Trop profond, et caché : pas vus.
        std::fs::write(profond.join("Passeport.pdf"), "").unwrap();
        std::fs::write(base.join(".cache/password.txt"), "").unwrap();
        let fin = Instant::now() + Duration::from_secs(30);
        let t = parcourir(Dossier::Telechargements, &base, fin);
        let noms: Vec<&str> = t.iter().map(|x| x.nom.as_str()).collect();
        assert_eq!(noms, ["Passeport.pdf", "Relevé.pdf", "export.csv"]);
        assert_eq!(t[2].raison, Raison::MotsDePasse);
        // Dans Documents, seul l'export compte.
        let d = parcourir(Dossier::Documents, &base, fin);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].nom, "export.csv");
        // Le constat : un Info avec les noms et le conseil ; rien trouvé : OK.
        let c = juger(&t, &[Dossier::Telechargements]);
        assert_eq!(c.probleme, Some(Niveau::Info));
        assert!(
            c.message.contains("3 fichier") && c.message.contains("Passeport.pdf"),
            "{}",
            c.message
        );
        assert!(
            c.correctif
                .as_ref()
                .is_some_and(|k| !k.automatique && k.action.contains("export"))
        );
        let rien = juger(&[], &[Dossier::Bureau, Dossier::Documents]);
        assert_eq!(rien.probleme, None);
        assert!(rien.message.contains("Bureau, Documents"));
        assert_eq!(juger(&[], &[]).probleme, None);
        let _ = std::fs::remove_dir_all(&base);
    }
}

//! Les fichiers .cvd et .cld de ClamAV, lus sans clamscan ni sigtool : un en-tête de 512 octets
//! (« ClamAV-VDB:date:version:signatures:niveau:md5:signature:auteur:heure », complété d'espaces), puis une archive
//! tar, compressée par gzip (.cvd tel que publié) ou non (.cld, refait par freshclam après ses mises à jour), sans
//! les deux blocs nuls de fin ; la sorte se reconnaît au contenu (les deux octets du gzip), jamais au nom. Le membre `.info` liste chaque fichier
//! (nom:taille:sha256) : il sert de contrôle d'intégrité, gratuit. Un membre absent de la liste n'est ni cru ni lu
//! (compté), un membre listé mais absent ou différent fait refuser toute la base. La signature RSA (DSIG, .sign) n'est
//! pas vérifiée : la confiance vient du propriétaire du fichier (base.rs).
//!
//! Le fichier est une donnée hostile tant que sa confiance n'est pas établie, et l'est encore un peu après : tailles
//! bornées (fichier, contenu décompressé, nombre de membres), aucune panique, aucune allocation sans borne.
//!
//! Module pur, sans `crate::` autre que les lecteurs d'archives : le banc de fuzzing l'inclut par son chemin.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use std::ops::{ControlFlow, Range};

use sha2::{Digest, Sha256};

use super::commun::hex_fixe;
use crate::archives::{gzip, tar};

/// Un fichier de base, au plus : main.cvd fait 89 Mo (déc. 2025), daily.cld 86 Mo.
pub(crate) const FICHIER_MAX: usize = 512 << 20;
/// Son contenu décompressé, au plus : celui de main.cvd fait 236 Mo.
pub(crate) const CONTENU_MAX: usize = 768 << 20;
/// Les en-têtes tar parcourus, au plus : daily.cld en a une soixantaine (avec ses .cdiff).
const MEMBRES_MAX: usize = 10_000;
/// La taille de l'en-tête.
const EN_TETE: usize = 512;
/// Un en-tête tar : le contenu d'un membre le suit (`tar::Entree::position` est celle de son en-tête).
const BLOC_TAR: usize = 512;

/// Ce que dit l'en-tête.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EnTete {
    /// La date de construction, telle qu'écrite (« 07 Nov 2026 06-24 +0000 »).
    pub date: String,
    pub version: u32,
    /// Le nombre de signatures annoncé.
    pub signatures: u64,
    /// Le niveau de moteur le plus bas que la base demande.
    pub niveau: u32,
}

/// Pourquoi une base n'est pas lue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Erreur {
    /// Pas d'en-tête « ClamAV-VDB: » lisible.
    EnTete,
    /// Plus grande que `FICHIER_MAX`.
    TropGrosse,
    /// Le gzip est coupé, abîmé (CRC, taille), suivi d'autre chose, ou dépasse `CONTENU_MAX` une fois décompressé.
    Compression,
    /// L'archive tar est coupée, illisible, a trop de membres ou deux membres du même nom.
    Archive,
    /// Pas de liste `.info`.
    SansListe,
    /// Un fichier listé est absent, ou sa taille ou son empreinte diffère.
    ListeFausse(String),
}

/// Un membre de l'archive : son nom et sa place dans le tar décompressé.
type Membre = (String, Range<usize>);

/// Une base lue : son en-tête et ses membres listés.
#[derive(Debug)]
pub(crate) struct Cvd {
    pub en_tete: EnTete,
    contenu: Vec<u8>,
    membres: Vec<Membre>,
    /// Membres absents de la liste (`.info`), hors la liste elle-même : sautés.
    pub hors_liste: usize,
}

impl Cvd {
    /// Les membres listés par `.info` (sans elle), dans l'ordre de l'archive.
    pub(crate) fn membres(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.membres
            .iter()
            .filter_map(|(nom, r)| Some((nom.as_str(), self.contenu.get(r.clone())?)))
    }
}

/// L'en-tête de `octets`, s'il en a un.
pub(crate) fn en_tete(octets: &[u8]) -> Option<EnTete> {
    let brut = octets.get(..EN_TETE)?;
    let texte = std::str::from_utf8(brut).ok()?.trim_end_matches([' ', '\0']);
    let mut champs = texte.strip_prefix("ClamAV-VDB:")?.split(':');
    let date = champs.next()?.to_owned();
    let version = champs.next()?.trim().parse().ok()?;
    let signatures = champs.next()?.trim().parse().ok()?;
    let niveau = champs.next()?.trim().parse().ok()?;
    Some(EnTete {
        date,
        version,
        signatures,
        niveau,
    })
}

/// La base entière de `octets` (le fichier, pris pour éviter une copie de son contenu quand il n'est pas compressé).
pub(crate) fn lire(mut octets: Vec<u8>) -> Result<Cvd, Erreur> {
    if octets.len() > FICHIER_MAX {
        return Err(Erreur::TropGrosse);
    }
    let en_tete = en_tete(&octets).ok_or(Erreur::EnTete)?;
    let corps = octets.get(EN_TETE..).ok_or(Erreur::EnTete)?;
    let contenu = if gzip::est_gzip(corps) {
        gzip::degzip_controle(corps, CONTENU_MAX).ok_or(Erreur::Compression)?
    } else {
        octets.drain(..EN_TETE);
        octets
    };
    let mut membres: Vec<Membre> = Vec::new();
    // La fin du dernier membre vu, bourrage compris.
    let mut bout = 0usize;
    let fin = tar::parcourir(&contenu, MEMBRES_MAX, |e| {
        let debut = e.position.checked_add(BLOC_TAR);
        let fin = debut.and_then(|d| d.checked_add(e.contenu.len()));
        let suite = e
            .contenu
            .len()
            .div_ceil(BLOC_TAR)
            .checked_mul(BLOC_TAR)
            .and_then(|t| debut?.checked_add(t));
        let (Some(d), Some(f), Some(s)) = (debut, fin, suite) else {
            return ControlFlow::Break(());
        };
        bout = s;
        // Seuls les fichiers ordinaires : dossiers et liens ne contiennent pas de signatures.
        if matches!(e.type_, b'0' | 0) {
            membres.push((e.nom, d..f));
        }
        ControlFlow::Continue(())
    });
    // L'archive de ClamAV n'a pas les deux blocs nuls de fin : elle s'arrête juste après son dernier membre. Coupée
    // ailleurs (en-tête ou contenu entamé), elle est refusée.
    let entiere = fin == tar::FinTar::Fin || (fin == tar::FinTar::Coupee && bout != 0 && bout == contenu.len());
    if !entiere {
        return Err(Erreur::Archive);
    }
    let mut noms: Vec<&str> = membres.iter().map(|(n, _)| n.as_str()).collect();
    noms.sort_unstable();
    if noms.windows(2).any(|p| matches!(p, [a, b] if a == b)) {
        return Err(Erreur::Archive);
    }
    let (membres, hors_liste) = controler(&contenu, &membres)?;
    Ok(Cvd {
        en_tete,
        contenu,
        membres,
        hors_liste,
    })
}

/// Les membres listés par le `.info` de l'archive, après contrôle de leur taille et de leur empreinte, et le nombre
/// de ceux qui n'y sont pas.
fn controler(contenu: &[u8], membres: &[Membre]) -> Result<(Vec<Membre>, usize), Erreur> {
    let octets = |r: &Range<usize>| contenu.get(r.clone()).ok_or(Erreur::Archive);
    let mut infos = membres
        .iter()
        .filter(|(n, _)| n.rsplit_once('.').is_some_and(|(_, e)| e == "info"));
    let (nom_info, r) = infos.next().ok_or(Erreur::SansListe)?;
    if infos.next().is_some() {
        return Err(Erreur::Archive);
    }
    let liste = octets(r)?;
    let mut listes: Vec<(&str, usize, [u8; 32])> = Vec::new();
    for ligne in liste.split(|&o| o == b'\n') {
        let ligne = std::str::from_utf8(ligne.strip_suffix(b"\r").unwrap_or(ligne))
            .map_err(|_| Erreur::ListeFausse(nom_info.clone()))?;
        if ligne.is_empty() || ligne.starts_with("ClamAV-VDB:") || ligne.starts_with("DSIG:") {
            continue;
        }
        let faux = || Erreur::ListeFausse(nom_info.clone());
        let mut champs = ligne.split(':');
        let (Some(nom), Some(taille), Some(empreinte), None) =
            (champs.next(), champs.next(), champs.next(), champs.next())
        else {
            return Err(faux());
        };
        let taille: usize = taille.parse().map_err(|_| faux())?;
        let empreinte = hex_fixe::<32>(empreinte).ok_or_else(faux)?;
        listes.push((nom, taille, empreinte));
    }
    let mut gardes = Vec::new();
    for (nom, taille, empreinte) in &listes {
        let (_, r) = membres
            .iter()
            .find(|(n, _)| n == nom)
            .ok_or_else(|| Erreur::ListeFausse((*nom).to_owned()))?;
        let o = octets(r)?;
        if o.len() != *taille || Sha256::digest(o).as_slice() != empreinte.as_slice() {
            return Err(Erreur::ListeFausse((*nom).to_owned()));
        }
        gardes.push(((*nom).to_owned(), r.clone()));
    }
    let hors_liste = membres
        .iter()
        .filter(|(n, _)| n != nom_info && !listes.iter().any(|(l, _, _)| l == n))
        .count();
    // Dans l'ordre de l'archive : celui où ClamAV les lit.
    gardes.sort_by_key(|(_, r)| r.start);
    Ok((gardes, hors_liste))
}

/// Pour les essais d'ici et des modules voisins : une base minuscule fabriquée (en-tête, tar, gzip ou non).
#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
pub(crate) mod essais {
    use std::fmt::Write;

    use sha2::{Digest, Sha256};

    /// Un tar des `fichiers` (nom, contenu), terminé par deux blocs nuls.
    pub(crate) fn tar(fichiers: &[(&str, &[u8])]) -> Vec<u8> {
        let mut t = Vec::new();
        for (nom, contenu) in fichiers {
            let mut entete = [0u8; 512];
            entete[..nom.len()].copy_from_slice(nom.as_bytes());
            entete[100..108].copy_from_slice(b"0000644\0");
            let taille = format!("{:011o}\0", contenu.len());
            entete[124..136].copy_from_slice(taille.as_bytes());
            entete[156] = b'0';
            entete[257..263].copy_from_slice(b"ustar\0");
            t.extend_from_slice(&entete);
            t.extend_from_slice(contenu);
            t.resize(t.len().div_ceil(512) * 512, 0);
        }
        t.extend_from_slice(&[0u8; 1024]);
        t
    }

    /// La liste `.info` des `fichiers`.
    pub(crate) fn info(fichiers: &[(&str, &[u8])]) -> Vec<u8> {
        let mut t = String::from("ClamAV-VDB:07 Nov 2026 06-24 +0000:7:3:90:X:X:essai:0\n");
        for (nom, contenu) in fichiers {
            let e = crate::protection::clamav::commun::hex(&Sha256::digest(contenu));
            writeln!(t, "{nom}:{}:{e}", contenu.len()).unwrap();
        }
        t.push_str("DSIG:inventee\n");
        t.into_bytes()
    }

    /// L'en-tête de 512 octets.
    pub(crate) fn en_tete(version: u32) -> Vec<u8> {
        let mut e = format!("ClamAV-VDB:07 Nov 2026 06-24 +0000:{version}:3:90:X:X:essai:1794032658").into_bytes();
        e.resize(512, b' ');
        e
    }

    /// Un gzip d'un seul membre : en-tête de 10 octets, flux deflate, CRC et taille.
    pub(crate) fn gzip(contenu: &[u8]) -> Vec<u8> {
        let mut gz = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
        gz.extend(miniz_oxide::deflate::compress_to_vec(contenu, 6));
        gz.extend(crate::archives::crc32::crc32(contenu).to_le_bytes());
        gz.extend(u32::try_from(contenu.len()).unwrap().to_le_bytes());
        gz
    }

    /// Une base entière : en-tête, puis le tar des `fichiers` et de leur liste `<nom>.info`, compressé si `gz`.
    pub(crate) fn base(nom: &str, version: u32, fichiers: &[(&str, &[u8])], gz: bool) -> Vec<u8> {
        let info = info(fichiers);
        let nom_info = format!("{nom}.info");
        let mut tous: Vec<(&str, &[u8])> = vec![(nom_info.as_str(), &info)];
        tous.extend_from_slice(fichiers);
        let t = tar(&tous);
        let mut b = en_tete(version);
        if gz {
            b.extend_from_slice(&gzip(&t));
        } else {
            b.extend_from_slice(&t);
        }
        b
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    const HDB: &[u8] = b"0123456789abcdef0123456789abcdef:12:Essai.Inventee-1\n";
    const NDB: &[u8] = b"Essai.Corps-1:0:*:76616e6775617264\n";

    #[test]
    fn base_compressee_et_non() {
        for gz in [true, false] {
            let b = essais::base("main", 63, &[("main.hdb", HDB), ("main.ndb", NDB)], gz);
            let cvd = lire(b).unwrap();
            assert_eq!(cvd.en_tete.version, 63);
            assert_eq!(cvd.en_tete.signatures, 3);
            assert_eq!(cvd.en_tete.niveau, 90);
            assert_eq!(cvd.en_tete.date, "07 Nov 2026 06-24 +0000");
            let m: Vec<_> = cvd.membres().collect();
            assert_eq!(m, vec![("main.hdb", HDB), ("main.ndb", NDB)]);
            assert_eq!(cvd.hors_liste, 0);
        }
    }

    #[test]
    fn membre_hors_liste_saute() {
        let info = essais::info(&[("daily.hdb", HDB)]);
        let t = essais::tar(&[
            ("daily.info", &info),
            ("daily.hdb", HDB),
            ("daily.ndb", NDB),
            ("COPYING", b"x"),
        ]);
        let mut b = essais::en_tete(1);
        b.extend_from_slice(&t);
        let cvd = lire(b).unwrap();
        assert_eq!(cvd.membres().map(|(n, _)| n).collect::<Vec<_>>(), vec!["daily.hdb"]);
        assert_eq!(cvd.hors_liste, 2);
    }

    #[test]
    fn liste_fausse_ou_absente_refusee() {
        // Un membre changé après la liste.
        let info = essais::info(&[("main.hdb", HDB)]);
        let mut change = HDB.to_vec();
        change[0] = b'f';
        let mut b = essais::en_tete(1);
        b.extend_from_slice(&essais::tar(&[("main.info", &info), ("main.hdb", &change)]));
        assert_eq!(lire(b).unwrap_err(), Erreur::ListeFausse("main.hdb".into()));
        // Un membre listé absent.
        let mut b = essais::en_tete(1);
        b.extend_from_slice(&essais::tar(&[("main.info", &info)]));
        assert_eq!(lire(b).unwrap_err(), Erreur::ListeFausse("main.hdb".into()));
        // Sans liste.
        let mut b = essais::en_tete(1);
        b.extend_from_slice(&essais::tar(&[("main.hdb", HDB)]));
        assert_eq!(lire(b).unwrap_err(), Erreur::SansListe);
        // Deux listes, deux membres du même nom.
        let mut b = essais::en_tete(1);
        b.extend_from_slice(&essais::tar(&[("a.info", &info), ("b.info", &info), ("main.hdb", HDB)]));
        assert_eq!(lire(b).unwrap_err(), Erreur::Archive);
        let mut b = essais::en_tete(1);
        b.extend_from_slice(&essais::tar(&[
            ("main.info", &info),
            ("main.hdb", HDB),
            ("main.hdb", HDB),
        ]));
        assert_eq!(lire(b).unwrap_err(), Erreur::Archive);
        // Une ligne de liste de trop de champs.
        let mut b = essais::en_tete(1);
        b.extend_from_slice(&essais::tar(&[("main.info", b"main.hdb:1:2:3\n")]));
        assert_eq!(lire(b).unwrap_err(), Erreur::ListeFausse("main.info".into()));
    }

    #[test]
    fn en_tetes_et_corps_abimes() {
        assert_eq!(lire(Vec::new()).unwrap_err(), Erreur::EnTete);
        assert_eq!(lire(vec![b' '; 600]).unwrap_err(), Erreur::EnTete);
        let mut faux = b"ClamAV-VDB:date:x:1:90".to_vec();
        faux.resize(512, b' ');
        assert_eq!(lire(faux).unwrap_err(), Erreur::EnTete);
        // Un tar coupé.
        let mut b = essais::base("main", 1, &[("main.hdb", HDB)], false);
        b.truncate(b.len() - 1100);
        assert_eq!(lire(b).unwrap_err(), Erreur::Archive);
        // Un gzip abîmé.
        let mut b = essais::base("main", 1, &[("main.hdb", HDB)], true);
        let n = b.len();
        b[n - 6] ^= 0xFF;
        assert_eq!(lire(b).unwrap_err(), Erreur::Compression);
        // Un en-tête seul : pas d'archive.
        assert_eq!(lire(essais::en_tete(1)).unwrap_err(), Erreur::Archive);
    }

    /// L'archive telle que ClamAV l'écrit : sans les deux blocs nuls de fin, des en-têtes de type nul sans « ustar ».
    /// Elle est lue ; coupée dans un en-tête ou dans un contenu, elle ne l'est pas.
    #[test]
    fn archive_a_la_clamav() {
        let fichiers: &[(&str, &[u8])] = &[("main.hdb", HDB), ("main.ndb", NDB)];
        let info = essais::info(fichiers);
        let mut t = essais::tar(&[
            ("COPYING", b"x"),
            ("main.info", &info),
            ("main.hdb", HDB),
            ("main.ndb", NDB),
        ]);
        t.truncate(t.len() - 1024);
        for entete in [0, 1024, 2048, 3072] {
            t[entete + 156] = 0;
            t[entete + 257..entete + 263].fill(0);
        }
        for gz in [false, true] {
            let mut b = essais::en_tete(5);
            b.extend_from_slice(&if gz { essais::gzip(&t) } else { t.clone() });
            let cvd = lire(b).unwrap();
            assert_eq!(cvd.membres().collect::<Vec<_>>(), fichiers.to_vec());
            assert_eq!(cvd.hors_liste, 1);
        }
        // Un en-tête entamé après le dernier membre, un dernier membre sans son bourrage, ou coupé dans son contenu.
        let mut entame = t.clone();
        entame.extend_from_slice(&[b'a'; 100]);
        for coupe in [entame, t[..t.len() - 1].to_vec(), t[..t.len() - 500].to_vec()] {
            let mut b = essais::en_tete(5);
            b.extend_from_slice(&coupe);
            assert_eq!(lire(b).unwrap_err(), Erreur::Archive);
        }
    }
}

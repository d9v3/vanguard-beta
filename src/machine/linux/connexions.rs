//! Les connexions des comptes, lues sans outil : utmp, wtmp et btmp (la `struct utmp` de la glibc pour x86_64, 384
//! octets par enregistrement), lastlog (292 octets par compte, indexé par uid), et les bases SQLite de lastlog2 et de
//! wtmpdb par le lecteur maison (`crate::sqlite`).
//!
//! Pourquoi pas getutxent : le programme Linux est construit pour musl, où getutxent et utmpxname ne rendent rien ;
//! « aucune session » serait un faux vert. Et `who`, `last`, `lastlog2` sont des binaires qu'un rootkit remplace.
//!
//! Données hostiles : un fichier se lit borné (la fin de wtmp, une taille au plus pour les bases), un enregistrement
//! coupé est laissé, les textes passent par `from_utf8_lossy` et restent à neutraliser avant d'être montrés.

use std::io::{Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::Path;

pub(crate) const UTMP: &str = "/run/utmp";
pub(crate) const WTMP: &str = "/var/log/wtmp";
pub(crate) const BTMP: &str = "/var/log/btmp";
pub(crate) const LASTLOG: &str = "/var/log/lastlog";
pub(crate) const LASTLOG2: &str = "/var/lib/lastlog/lastlog2.db";
pub(crate) const WTMPDB: &str = "/var/lib/wtmpdb/wtmp.db";

/// Taille d'un enregistrement utmp (glibc, x86_64 : `__WORDSIZE_TIME64_COMPAT32`, bits/utmp.h).
pub(crate) const TAILLE_UTMP: usize = 384;
/// Taille d'une entrée de lastlog (ll_time u32, `ll_line[32]`, `ll_host[256]`).
const TAILLE_LASTLOG: u64 = 292;
/// Une base SQLite de connexions plus grosse n'est pas lue (une vraie fait quelques Mo, même sur un serveur).
const BASE_MAX: u64 = 64 << 20;

// Genres d'enregistrement utmp (bits/utmp.h).
pub(crate) const BOOT_TIME: i16 = 2;
pub(crate) const USER_PROCESS: i16 = 7;

/// Un enregistrement utmp, wtmp ou btmp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Enregistrement {
    pub genre: i16,
    pub pid: i32,
    /// Le terminal (« pts/0 », « tty1 », « ~ » pour un démarrage).
    pub ligne: String,
    /// Le compte (« reboot » pour un démarrage).
    pub compte: String,
    /// L'ordinateur d'où vient la session, ou la version du noyau pour un démarrage.
    pub hote: String,
    /// Secondes depuis 1970 : tv_sec est un u32 dans la glibc d'aujourd'hui (valable jusqu'en 2106).
    pub secondes: u32,
    pub adresse: Option<IpAddr>,
}

/// Une chaîne C d'un champ de taille fixe : jusqu'au premier zéro (le champ peut aussi être plein, sans zéro).
fn texte_c(octets: &[u8]) -> String {
    let fin = octets.iter().position(|&o| o == 0).unwrap_or(octets.len());
    String::from_utf8_lossy(&octets[..fin]).into_owned()
}

fn i16_le(o: &[u8], i: usize) -> i16 {
    i16::from_le_bytes([o[i], o[i + 1]])
}

fn u32_le(o: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([o[i], o[i + 1], o[i + 2], o[i + 3]])
}

/// L'adresse d'ut_addr_v6 : une IPv4 dans le premier mot seul, sinon une IPv6 ; tout à zéro, aucune.
fn adresse(o: &[u8]) -> Option<IpAddr> {
    if o.iter().all(|&b| b == 0) {
        return None;
    }
    if o[4..].iter().all(|&b| b == 0) {
        return Some(IpAddr::from([o[0], o[1], o[2], o[3]]));
    }
    Some(IpAddr::from(<[u8; 16]>::try_from(o).ok()?))
}

/// Les enregistrements d'un fichier utmp, wtmp ou btmp, dans l'ordre du fichier. Un reste de moins de 384 octets (un
/// enregistrement en cours d'écriture, ou un fichier abîmé) est laissé ; les enregistrements vides (EMPTY) aussi.
pub(crate) fn lire_utmp(octets: &[u8]) -> Vec<Enregistrement> {
    let (blocs, _) = octets.as_chunks::<TAILLE_UTMP>();
    blocs
        .iter()
        .filter_map(|b| {
            let genre = i16_le(b, 0);
            (genre != 0).then(|| Enregistrement {
                genre,
                pid: i32::from_le_bytes([b[4], b[5], b[6], b[7]]),
                ligne: texte_c(&b[8..40]),
                compte: texte_c(&b[44..76]),
                hote: texte_c(&b[76..332]),
                secondes: u32_le(b, 340),
                adresse: adresse(&b[348..364]),
            })
        })
        .collect()
}

/// La fin d'un fichier d'enregistrements utmp, `max` octets au plus, coupée sur une frontière d'enregistrement
/// comptée depuis le début (un reste incomplet à la fin est laissé par `lire_utmp`). Rend aussi s'il a fallu couper.
pub(crate) fn lire_fin(chemin: &Path, max: u64) -> std::io::Result<(Vec<u8>, bool)> {
    let mut f = std::fs::File::open(chemin)?;
    let taille = f.metadata()?.len();
    let n = TAILLE_UTMP as u64;
    let debut = if taille > max {
        (taille - max).div_ceil(n) * n
    } else {
        0
    };
    f.seek(SeekFrom::Start(debut))?;
    let mut octets = Vec::new();
    f.take(max).read_to_end(&mut octets)?;
    Ok((octets, debut > 0))
}

/// Le nom d'un genre d'enregistrement utmp.
pub(crate) fn nom_du_genre(genre: i16) -> &'static str {
    match genre {
        1 => "RUN_LVL",
        2 => "BOOT_TIME",
        3 => "NEW_TIME",
        4 => "OLD_TIME",
        5 => "INIT_PROCESS",
        6 => "LOGIN_PROCESS",
        7 => "USER_PROCESS",
        8 => "DEAD_PROCESS",
        9 => "ACCOUNTING",
        _ => "?",
    }
}

/// Une date ISO locale, d'après des secondes depuis 1970.
pub(crate) fn date(secondes: i64) -> String {
    chrono::DateTime::from_timestamp(secondes, 0).map_or_else(
        || "?".into(),
        |d| {
            d.with_timezone(&chrono::Local)
                .format("%Y-%m-%dT%H:%M:%S%:z")
                .to_string()
        },
    )
}

/// Une ligne lisible d'un enregistrement : date, genre, compte, terminal, hôte, adresse, processus. Les champs sont
/// séparés par des tabulations ; l'appelant neutralise les caractères de contrôle.
pub(crate) fn ligne(e: &Enregistrement) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\tpid {}",
        date(i64::from(e.secondes)),
        nom_du_genre(e.genre),
        e.compte,
        e.ligne,
        e.hote,
        e.adresse.map(|a| a.to_string()).unwrap_or_default(),
        e.pid
    )
}

/// Une entrée de lastlog : (secondes, terminal, hôte). `None` : jamais connecté (entrée à zéro ou absente du fichier
/// creux).
pub(crate) fn lastlog_de(chemin: &Path, uid: u32) -> std::io::Result<Option<(u32, String, String)>> {
    let mut f = std::fs::File::open(chemin)?;
    let position = u64::from(uid) * TAILLE_LASTLOG;
    if position + TAILLE_LASTLOG > f.metadata()?.len() {
        return Ok(None);
    }
    f.seek(SeekFrom::Start(position))?;
    let mut b = [0u8; 292];
    f.read_exact(&mut b)?;
    Ok(lire_lastlog(&b))
}

fn lire_lastlog(b: &[u8; 292]) -> Option<(u32, String, String)> {
    let t = u32_le(b, 0);
    (t != 0).then(|| (t, texte_c(&b[4..36]), texte_c(&b[36..292])))
}

/// Pourquoi une base SQLite de connexions n'a pas été lue ici : l'appelant repasse alors à l'outil.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PasLue {
    /// Pas de base à cet endroit.
    Absente,
    /// Une écriture récente n'est peut-être que dans le journal à côté (`-wal` ou `-journal` non vide) : la base
    /// seule donnerait des dates périmées.
    Journal,
    /// Plus grosse que `BASE_MAX`.
    TropGrosse,
    /// Illisible (droits, erreur du système) ou pas une base que le lecteur comprend.
    Illisible(String),
}

/// Les octets d'une base SQLite, seulement si elle se lit seule : pas de journal WAL ni de journal de retour en
/// arrière non vide à côté (le mode WAL se lit aux octets 18 et 19 de l'en-tête, à 2).
pub(crate) fn base(chemin: &Path) -> Result<Vec<u8>, PasLue> {
    let m = match std::fs::metadata(chemin) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(PasLue::Absente),
        Err(e) => return Err(PasLue::Illisible(e.to_string())),
    };
    if m.len() > BASE_MAX {
        return Err(PasLue::TropGrosse);
    }
    let a_cote = |suffixe: &str| {
        let mut nom = chemin.as_os_str().to_owned();
        nom.push(suffixe);
        std::fs::metadata(&nom).is_ok_and(|m| m.len() > 0)
    };
    if a_cote("-wal") || a_cote("-journal") {
        return Err(PasLue::Journal);
    }
    let mut octets = Vec::new();
    std::fs::File::open(chemin)
        .and_then(|f| f.take(BASE_MAX).read_to_end(&mut octets))
        .map_err(|e| PasLue::Illisible(e.to_string()))?;
    // En mode WAL sans fichier -wal (vidé au dernier point de contrôle), la base est complète.
    Ok(octets)
}

/// Une ligne de lastlog2 : le compte, sa dernière connexion (secondes), le terminal, l'hôte, le service PAM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Derniere {
    pub compte: String,
    pub secondes: i64,
    pub terminal: String,
    pub hote: String,
    pub service: String,
}

/// La table Lastlog2 (Name, Time en secondes, TTY, RemoteHost, Service). `None` : pas une base lastlog2.
pub(crate) fn lastlog2(octets: &[u8]) -> Option<Vec<Derniere>> {
    let lignes = crate::sqlite::lignes(octets, "Lastlog2", &["Name", "Time", "TTY", "RemoteHost", "Service"])?;
    Some(
        lignes
            .into_iter()
            .filter_map(|l| {
                let t = |i: usize| l.get(i).and_then(|v| v.texte()).unwrap_or_default().to_string();
                Some(Derniere {
                    compte: l.first()?.texte()?.to_string(),
                    secondes: l.get(1).and_then(crate::sqlite::Valeur::entier).unwrap_or(0),
                    terminal: t(2),
                    hote: t(3),
                    service: t(4),
                })
            })
            .collect(),
    )
}

// Genres d'une ligne de wtmpdb : ce ne sont pas ceux d'utmp (wtmpdb.h).
pub(crate) const WTMPDB_BOOT_TIME: i64 = 1;
pub(crate) const WTMPDB_USER_PROCESS: i64 = 3;

/// Une ligne de wtmpdb : genre (1 démarrage, 3 session), compte, entrée et sortie en microsecondes (sortie `None` :
/// toujours ouverte), terminal, hôte, service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Session {
    pub genre: i64,
    pub compte: String,
    pub entree: i64,
    pub sortie: Option<i64>,
    pub terminal: String,
    pub hote: String,
    pub service: String,
}

/// La table wtmp de wtmpdb (ID, Type, User, Login, Logout, TTY, RemoteHost, Service), dans l'ordre des ID.
pub(crate) fn wtmpdb(octets: &[u8]) -> Option<Vec<Session>> {
    let lignes = crate::sqlite::lignes(
        octets,
        "wtmp",
        &["Type", "User", "Login", "Logout", "TTY", "RemoteHost", "Service"],
    )?;
    Some(
        lignes
            .into_iter()
            .map(|l| {
                let t = |i: usize| l.get(i).and_then(|v| v.texte()).unwrap_or_default().to_string();
                let n = |i: usize| l.get(i).and_then(crate::sqlite::Valeur::entier);
                Session {
                    genre: n(0).unwrap_or(0),
                    compte: t(1),
                    entree: n(2).unwrap_or(0),
                    sortie: n(3),
                    terminal: t(4),
                    hote: t(5),
                    service: t(6),
                }
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un enregistrement utmp fabriqué (compte « alice », réseau de documentation 192.0.2.0/24).
    fn enregistrement(genre: i16, compte: &str, ligne: &str, hote: &str, secondes: u32) -> Vec<u8> {
        let mut b = vec![0u8; TAILLE_UTMP];
        b[0..2].copy_from_slice(&genre.to_le_bytes());
        b[4..8].copy_from_slice(&4242i32.to_le_bytes());
        b[8..8 + ligne.len()].copy_from_slice(ligne.as_bytes());
        b[44..44 + compte.len()].copy_from_slice(compte.as_bytes());
        b[76..76 + hote.len()].copy_from_slice(hote.as_bytes());
        b[340..344].copy_from_slice(&secondes.to_le_bytes());
        if let Ok(IpAddr::V4(a)) = hote.parse::<IpAddr>() {
            b[348..352].copy_from_slice(&a.octets());
        }
        b
    }

    #[test]
    fn enregistrements_utmp_fabriques() {
        let mut f = enregistrement(BOOT_TIME, "reboot", "~", "6.17.1-arch1-1", 1_792_000_000);
        f.extend(enregistrement(
            USER_PROCESS,
            "alice",
            "pts/0",
            "192.0.2.10",
            1_792_000_100,
        ));
        f.extend(vec![0u8; TAILLE_UTMP]);
        // Champs pleins, sans zéro final, et texte qui n'est pas de l'UTF-8 : lus sans déborder.
        let mut plein = enregistrement(USER_PROCESS, "", "", "", u32::MAX);
        plein[44..76].fill(b'a');
        plein[76..332].fill(0xff);
        f.extend(plein);
        // Un reste coupé : laissé.
        f.extend(&[7u8; 100]);
        let e = lire_utmp(&f);
        assert_eq!(e.len(), 3);
        assert_eq!(
            (e[0].genre, e[0].compte.as_str(), e[0].hote.as_str()),
            (BOOT_TIME, "reboot", "6.17.1-arch1-1")
        );
        assert_eq!(e[1].adresse, Some(IpAddr::from([192, 0, 2, 10])));
        assert_eq!(e[1].pid, 4242);
        assert_eq!(e[2].compte.len(), 32);
        assert_eq!(e[2].secondes, u32::MAX, "après 2038 aussi");
        assert!(ligne(&e[1]).contains("USER_PROCESS\talice\tpts/0\t192.0.2.10"));
        let vide = lire_utmp(&[]);
        assert!(vide.is_empty(), "{vide:?}");
    }

    #[test]
    fn fin_de_wtmp_sur_une_frontiere() {
        let dossier = crate::socle::dossier_local().join("connexions-fin");
        std::fs::create_dir_all(&dossier).unwrap();
        let chemin = dossier.join("wtmp");
        let mut f = Vec::new();
        for i in 0..10 {
            f.extend(enregistrement(USER_PROCESS, "alice", "pts/1", "", 1000 + i));
        }
        std::fs::write(&chemin, &f).unwrap();
        let (o, coupe) = lire_fin(&chemin, 3 * TAILLE_UTMP as u64 + 10).unwrap();
        assert!(coupe);
        let e = lire_utmp(&o);
        assert_eq!(e.iter().map(|e| e.secondes).collect::<Vec<_>>(), [1007, 1008, 1009]);
        let (o, coupe) = lire_fin(&chemin, 1 << 20).unwrap();
        assert!(!coupe);
        assert_eq!(lire_utmp(&o).len(), 10);
    }

    #[test]
    fn lastlog_creux() {
        let dossier = crate::socle::dossier_local().join("connexions-lastlog");
        std::fs::create_dir_all(&dossier).unwrap();
        let chemin = dossier.join("lastlog");
        let mut f = vec![0u8; 292 * 1001];
        let i = 1000 * 292;
        f[i..i + 4].copy_from_slice(&1_792_000_000u32.to_le_bytes());
        f[i + 4..i + 9].copy_from_slice(b"pts/2");
        f[i + 36..i + 46].copy_from_slice(b"192.0.2.11");
        std::fs::write(&chemin, &f).unwrap();
        assert_eq!(
            lastlog_de(&chemin, 1000).unwrap(),
            Some((1_792_000_000, "pts/2".into(), "192.0.2.11".into()))
        );
        assert_eq!(lastlog_de(&chemin, 999).unwrap(), None, "entrée à zéro");
        assert_eq!(lastlog_de(&chemin, u32::MAX).unwrap(), None, "au-delà du fichier");
    }

    /// Une base fabriquée en mémoire, au format SQLite : une page de schéma et une feuille par table, assez pour
    /// les deux tables lues ici. Les valeurs sont celles d'un compte inventé.
    fn base_sqlite(sql: &str, nom: &str, lignes: &[Vec<Option<ValeurEssai>>]) -> Vec<u8> {
        const PAGE: usize = 4096;
        fn varint(mut v: u64, sortie: &mut Vec<u8>) {
            let mut o = Vec::new();
            loop {
                o.push((v & 0x7f) as u8);
                v >>= 7;
                if v == 0 {
                    break;
                }
            }
            o.reverse();
            let n = o.len();
            for (i, b) in o.iter().enumerate() {
                sortie.push(if i + 1 < n { b | 0x80 } else { *b });
            }
        }
        fn enregistrement(valeurs: &[Option<ValeurEssai>]) -> Vec<u8> {
            let (mut types, mut corps) = (Vec::new(), Vec::new());
            for v in valeurs {
                match v {
                    None => types.push(0u64),
                    Some(ValeurEssai::E(n)) => {
                        types.push(6);
                        corps.extend(n.to_be_bytes());
                    }
                    Some(ValeurEssai::T(t)) => {
                        types.push(13 + 2 * t.len() as u64);
                        corps.extend(t.as_bytes());
                    }
                }
            }
            let mut entete = Vec::new();
            for t in &types {
                varint(*t, &mut entete);
            }
            let mut r = Vec::new();
            varint((entete.len() + 1) as u64, &mut r);
            r.extend(entete);
            r.extend(corps);
            r
        }
        fn feuille(page: &mut [u8], debut: usize, cellules: &[Vec<u8>]) {
            page[debut] = 0x0d;
            page[debut + 3..debut + 5].copy_from_slice(&u16::try_from(cellules.len()).unwrap().to_be_bytes());
            let mut fin = page.len();
            for (i, c) in cellules.iter().enumerate() {
                fin -= c.len();
                page[fin..fin + c.len()].copy_from_slice(c);
                let p = debut + 8 + 2 * i;
                page[p..p + 2].copy_from_slice(&u16::try_from(fin).unwrap().to_be_bytes());
            }
            page[debut + 5..debut + 7].copy_from_slice(&u16::try_from(fin).unwrap().to_be_bytes());
        }
        let cellule = |rowid: u64, rec: Vec<u8>| {
            let mut c = Vec::new();
            varint(rec.len() as u64, &mut c);
            varint(rowid, &mut c);
            c.extend(rec);
            c
        };
        let mut base = vec![0u8; 2 * PAGE];
        base[..16].copy_from_slice(b"SQLite format 3\0");
        base[16..18].copy_from_slice(&u16::try_from(PAGE).unwrap().to_be_bytes());
        base[18] = 1;
        base[19] = 1;
        let schema = enregistrement(&[
            Some(ValeurEssai::T("table".into())),
            Some(ValeurEssai::T(nom.into())),
            Some(ValeurEssai::T(nom.into())),
            Some(ValeurEssai::E(2)),
            Some(ValeurEssai::T(sql.into())),
        ]);
        let (p1, p2) = base.split_at_mut(PAGE);
        feuille(p1, 100, &[cellule(1, schema)]);
        let cellules: Vec<Vec<u8>> = lignes
            .iter()
            .enumerate()
            .map(|(i, l)| cellule(i as u64 + 1, enregistrement(l)))
            .collect();
        feuille(p2, 0, &cellules);
        base
    }

    #[derive(Clone)]
    enum ValeurEssai {
        E(i64),
        T(String),
    }

    #[allow(clippy::unnecessary_wraps)]
    fn t(s: &str) -> Option<ValeurEssai> {
        Some(ValeurEssai::T(s.into()))
    }

    #[allow(clippy::unnecessary_wraps)]
    fn e(n: i64) -> Option<ValeurEssai> {
        Some(ValeurEssai::E(n))
    }

    fn base_lastlog2() -> Vec<u8> {
        base_sqlite(
            "CREATE TABLE Lastlog2(Name TEXT PRIMARY KEY, Time INTEGER, TTY TEXT, RemoteHost TEXT, Service TEXT)",
            "Lastlog2",
            &[
                vec![t("alice"), e(1_792_000_000), t("pts/0"), t("192.0.2.10"), t("sshd")],
                vec![t("bob"), e(1_700_000_000), t("tty1"), None, t("login")],
            ],
        )
    }

    #[test]
    fn lastlog2_fabrique() {
        let l = lastlog2(&base_lastlog2()).unwrap();
        assert_eq!(l.len(), 2);
        assert_eq!(
            l[0],
            Derniere {
                compte: "alice".into(),
                secondes: 1_792_000_000,
                terminal: "pts/0".into(),
                hote: "192.0.2.10".into(),
                service: "sshd".into()
            }
        );
        assert_eq!(l[1].hote, "");
        // Pas la bonne table, ou pas une base : rien, jamais une liste vide à la place.
        assert_eq!(wtmpdb(&base_lastlog2()), None);
        assert_eq!(lastlog2(b"pas une base"), None);
        let mut abimee = base_lastlog2();
        abimee.truncate(5000);
        assert_eq!(lastlog2(&abimee), None);
    }

    #[test]
    fn wtmpdb_fabrique() {
        let b = base_sqlite(
            "CREATE TABLE wtmp(ID INTEGER PRIMARY KEY, Type INTEGER, User TEXT NOT NULL, Login INTEGER, Logout INTEGER, TTY TEXT, RemoteHost TEXT, Service TEXT) STRICT",
            "wtmp",
            &[
                vec![
                    None,
                    e(1),
                    t("reboot"),
                    e(1_792_000_000_000_000),
                    None,
                    t("~"),
                    t("6.17.1-arch1-1"),
                    None,
                ],
                vec![
                    None,
                    e(3),
                    t("alice"),
                    e(1_792_000_100_000_000),
                    e(1_792_000_200_000_000),
                    t("pts/0"),
                    t("192.0.2.10"),
                    t("sshd"),
                ],
            ],
        );
        let s = wtmpdb(&b).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!((s[0].genre, s[0].sortie), (WTMPDB_BOOT_TIME, None));
        assert_eq!(s[1].genre, WTMPDB_USER_PROCESS);
        assert_eq!(s[1].sortie, Some(1_792_000_200_000_000));
        assert_eq!(s[1].hote, "192.0.2.10");
    }

    #[test]
    fn base_avec_journal_refusee() {
        let dossier = crate::socle::dossier_local().join("connexions-base");
        std::fs::create_dir_all(&dossier).unwrap();
        let chemin = dossier.join("lastlog2.db");
        std::fs::write(&chemin, base_lastlog2()).unwrap();
        assert!(base(&chemin).is_ok());
        for suffixe in ["-wal", "-journal"] {
            let a_cote = dossier.join(format!("lastlog2.db{suffixe}"));
            std::fs::write(&a_cote, b"x").unwrap();
            assert_eq!(base(&chemin), Err(PasLue::Journal));
            // Vide : rien d'écrit en attente, la base se lit.
            std::fs::write(&a_cote, b"").unwrap();
            assert!(base(&chemin).is_ok());
        }
        assert_eq!(base(&dossier.join("absente.db")), Err(PasLue::Absente));
    }

    /// L'oracle : /run/utmp lu par Vanguard contre `who`, et lastlog2.db contre `lastlog2`, sur cet ordinateur (des
    /// nombres seulement dans les messages).
    #[test]
    fn connexions_comme_les_outils() {
        let Ok(o) = std::fs::read(UTMP) else {
            return crate::essais::saute("pas de /run/utmp");
        };
        let natifs = lire_utmp(&o).into_iter().filter(|e| e.genre == USER_PROCESS).count();
        let Some(who) =
            crate::commande::lancer(&mut std::process::Command::new("who"), 10).filter(|r| r.code == Some(0))
        else {
            return crate::essais::saute("who absent");
        };
        let outil = who.sortie.lines().filter(|l| !l.trim().is_empty()).count();
        assert_eq!(natifs, outil, "sessions ouvertes : utmp contre who");
        let Ok(octets) = base(Path::new(LASTLOG2)) else {
            return crate::essais::saute("lastlog2.db absente ou en cours d'écriture");
        };
        let natifs = lastlog2(&octets).expect("lastlog2.db illisible par le lecteur maison");
        let Some(r) = crate::commande::lancer_en_anglais(&mut std::process::Command::new("lastlog2"), 10)
            .filter(|r| r.code == Some(0))
        else {
            return crate::essais::saute("lastlog2 absent");
        };
        // Une ligne par compte connu de lastlog2.db, après l'en-tête (« Username Port From Latest »).
        let mut outil: Vec<String> = r
            .sortie
            .lines()
            .skip(1)
            .filter(|l| !l.contains("**Never logged in**"))
            .filter_map(|l| l.split_whitespace().next().map(String::from))
            .collect();
        let mut lus: Vec<String> = natifs
            .iter()
            .filter(|d| d.secondes > 0)
            .map(|d| d.compte.clone())
            .collect();
        outil.sort();
        lus.sort();
        assert!(
            outil == lus,
            "lastlog2 : {} comptes lus, {} par l'outil",
            lus.len(),
            outil.len()
        );
    }
}

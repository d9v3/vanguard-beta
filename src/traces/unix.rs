//! Ce que Linux et macOS partagent pour les traces : tâches cron, fichiers du shell et clés SSH autorisées, la fin
//! d'un fichier journal, un journal écrit par sa commande dans une borne, les événements de la chronologie repris
//! dans les journaux écrits.

use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use super::chronologie::{self, Apport, Evenement, lire_ligne_journal};
use super::{Bi, Feuille, Manque, Partie, Raison, bi, creer_fichier, entete};
use crate::commande::{Garder, lancer_vers};

/// Le dossier personnel.
pub(super) fn maison() -> PathBuf {
    crate::socle::maison()
}

/// Ce qui se lance à l'ouverture d'un shell, et les clés SSH qui ouvrent ce compte sans mot de passe : deux façons
/// courantes de garder la main sur un compte.
pub(super) fn shell_et_ssh(f: &mut Feuille) {
    let m = maison();
    for nom in [
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".profile",
        ".zshrc",
        ".zprofile",
        ".zshenv",
        ".zlogin",
        ".xprofile",
        ".xinitrc",
        ".config/fish/config.fish",
    ] {
        f.fichier_shell(&m.join(nom));
    }
    for chemin in ["/etc/profile", "/etc/bash.bashrc", "/etc/zshrc", "/etc/zprofile"] {
        f.fichier_shell(Path::new(chemin));
    }
    f.dossier(Path::new("/etc/profile.d"), 0, false);
    f.fichier(&m.join(".ssh/authorized_keys"), true);
    f.fichier(&m.join(".ssh/authorized_keys2"), false);
    f.fichier(Path::new("/root/.ssh/authorized_keys"), false);
}

/// Les tâches cron : celles du compte (crontab -l), celles du système, et le dossier des tâches de chaque compte,
/// lisible par root seulement.
pub(super) fn cron(f: &mut Feuille) {
    f.commande(Command::new("crontab").arg("-l"), 10, false);
    f.fichier(Path::new("/etc/crontab"), true);
    f.fichier(Path::new("/etc/anacrontab"), false);
    for d in [
        "/etc/cron.d",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/etc/periodic/daily",
    ] {
        f.dossier(Path::new(d), 50, false);
    }
    for d in [
        "/var/spool/cron",
        "/var/spool/cron/crontabs",
        "/var/at/tabs",
        "/usr/lib/cron/tabs",
    ] {
        if Path::new(d).is_dir() {
            if super::privilegie() {
                f.dossier(Path::new(d), 100, false);
            } else {
                f.section(d);
                f.ajouter(&Raison::Droits.note());
                f.manques.push(super::Manque {
                    quoi: bi!("Tâches cron de chaque compte ({d})", "Each account's cron jobs ({d})"),
                    raison: Raison::Droits,
                });
            }
        }
    }
}

/// La fin d'un fichier journal recopiée, au plus (`journaux_classiques`).
const FIN_JOURNAL: u64 = 10 << 20;

/// L'en-tête d'un journal écrit dont Vanguard n'a lu qu'une partie, par choix (la fin d'un fichier, le dernier
/// jour) : qui lit le fichier le sait, et la chronologie le relit pour ne pas dire que le système n'a pas gardé le
/// reste.
const LU_SUR: &str = "# Lu par Vanguard sur / Read by Vanguard over: ";

/// La ligne d'en-tête « lu sur » d'une étendue (« 10 Mo », « 1 jour »).
fn ligne_lu_sur(etendue: &Bi) -> String {
    format!("{LU_SUR}{} / {}\n", etendue.fr, etendue.en)
}

/// L'étendue lue d'après la ligne d'en-tête « lu sur ».
fn lu_sur(ligne: &str) -> Option<Bi> {
    let (fr, en) = ligne.strip_prefix(LU_SUR)?.trim_end().split_once(" / ")?;
    Some(Bi::new(fr, en))
}

/// La fin d'un fichier journal (`borne` octets au plus, à partir d'une ligne entière), et s'il a été coupé.
fn fin_de(source: &Path, borne: u64) -> std::io::Result<(Vec<u8>, bool)> {
    let mut f = std::fs::File::open(source)?;
    let taille = f.metadata()?.len();
    let depart = taille.saturating_sub(borne);
    f.seek(SeekFrom::Start(depart))?;
    let mut octets = Vec::new();
    f.take(borne).read_to_end(&mut octets)?;
    if depart > 0
        && let Some(i) = octets.iter().position(|&o| o == b'\n')
    {
        octets.drain(..=i);
    }
    Ok((octets, depart > 0))
}

/// Les fichiers tournés d'un journal (« auth.log.1 », « auth.log.2.gz », « secure-20261019 ») : le plus récent, s'il
/// se lit tel quel ; le plus récent compressé, quand c'est lui le dernier (Vanguard ne lit pas les journaux
/// compressés) ; s'il y en a d'autres, plus anciens, qui ne sont pas lus.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Tournes {
    pub lisible: Option<PathBuf>,
    pub compresse: Option<PathBuf>,
    pub autres: bool,
}

/// Les fichiers tournés de `source`, dans son dossier : nommés comme lui, suivis d'un point ou d'un tiret et d'un
/// chiffre. Un lien n'est pas suivi : il pourrait mener hors des journaux. Le plus récent est celui modifié le
/// dernier.
pub(super) fn tournes(source: &Path) -> Tournes {
    let (Some(dossier), Some(nom)) = (source.parent(), source.file_name()) else {
        return Tournes::default();
    };
    let nom = nom.to_string_lossy().into_owned();
    let mut trouves: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(dossier)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.strip_prefix(&nom)
                .and_then(|reste| reste.strip_prefix(['.', '-']))
                .is_some_and(|reste| reste.starts_with(|c: char| c.is_ascii_digit()))
        })
        .filter_map(|e| {
            let m = std::fs::symlink_metadata(e.path()).ok()?;
            m.is_file()
                .then(|| (m.modified().unwrap_or(std::time::UNIX_EPOCH), e.path()))
        })
        .collect();
    trouves.sort();
    let Some((_, recent)) = trouves.pop() else {
        return Tournes::default();
    };
    let compresse = recent
        .extension()
        .is_some_and(|x| ["gz", "xz", "bz2", "zst", "lz4", "z", "Z"].contains(&x.to_string_lossy().as_ref()));
    Tournes {
        autres: !trouves.is_empty(),
        lisible: (!compresse).then(|| recent.clone()),
        compresse: compresse.then_some(recent),
    }
}

/// Recopie dans `nom` la fin du fichier tourné le plus récent puis celle de `source` (`borne` octets au plus chacune),
/// dans l'ordre du temps ; rend la taille écrite et, s'il y en a un, ce qui a empêché de lire le fichier tourné. Ce que Vanguard n'a pas lu (une fin
/// coupée, un fichier tourné plus ancien ou compressé) est dit dans l'en-tête : la chronologie ne dira pas que le
/// système ne l'a pas gardé.
pub(super) fn copier_avec_le_tourne(
    source: &Path,
    tournes: &Tournes,
    dossier: &Path,
    nom: &str,
    borne: u64,
) -> std::io::Result<(u64, Option<std::io::Error>)> {
    let (actuel, coupe) = fin_de(source, borne)?;
    // Un fichier tourné illisible n'empêche pas de recopier le fichier lui-même : il compte comme non lu.
    let mut erreur = None;
    let ancien = tournes.lisible.as_deref().and_then(|t| match fin_de(t, borne) {
        Ok(lu) => Some((t, lu)),
        Err(e) => {
            erreur = Some(e);
            None
        }
    });
    let taille = mo(borne);
    let lu_sur = match &ancien {
        Some((_, (_, coupe_ancien))) if coupe || *coupe_ancien || tournes.autres => Some(Bi::new(
            format!("la fin du fichier et du dernier tourné ({} chacun au plus)", taille.fr),
            format!(
                "the end of the file and of the latest rotated one ({} each at most)",
                taille.en
            ),
        )),
        Some(_) => None,
        None if tournes.lisible.is_some() || tournes.compresse.is_some() => Some(Bi::new(
            "le fichier seul, sans ses fichiers tournés",
            "the file alone, without its rotated files",
        )),
        None => coupe.then_some(taille),
    };
    let mut sortie = creer_fichier(&dossier.join(nom))?;
    sortie.write_all(entete(&Bi::meme(source.to_string_lossy())).as_bytes())?;
    if let Some(etendue) = &lu_sur {
        sortie.write_all(ligne_lu_sur(etendue).as_bytes())?;
    }
    let mut ecrit = 0;
    if let Some((tourne, (octets, _))) = &ancien {
        writeln!(
            sortie,
            "# Avec, avant, la fin de / Preceded by the end of: {}",
            super::texte_sur(&tourne.to_string_lossy()).replace('\n', " ")
        )?;
        let mut texte = super::texte_sur(&String::from_utf8_lossy(octets));
        if !texte.is_empty() && !texte.ends_with('\n') {
            texte.push('\n');
        }
        sortie.write_all(texte.as_bytes())?;
        ecrit += octets.len() as u64;
    }
    sortie.write_all(super::texte_sur(&String::from_utf8_lossy(&actuel)).as_bytes())?;
    Ok((ecrit + actuel.len() as u64, erreur))
}

/// Lance une commande qui écrit un journal dans `nom` (après l'en-tête), `borne` octets au plus ; `etendue` : celle à
/// laquelle Vanguard limite la commande (« 1 jour »), dite dans l'en-tête. `Err` : le fichier ne s'écrit pas ;
/// `Ok(None)` : la commande ne démarre pas.
pub(super) fn journal_vers(
    dossier: &Path,
    nom: &str,
    titre: &Bi,
    commande: &mut Command,
    secondes: u64,
    garder: Garder,
    etendue: Option<&Bi>,
) -> std::io::Result<Option<crate::commande::Ecrit>> {
    journal_vers_borne(
        dossier,
        nom,
        titre,
        commande,
        secondes,
        garder,
        etendue,
        super::BORNE_JOURNAL,
    )
}

/// `journal_vers`, `borne` octets au plus (le témoin d'un relevé, plus court que le journal lui-même).
#[allow(clippy::too_many_arguments)]
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub(super) fn journal_vers_borne(
    dossier: &Path,
    nom: &str,
    titre: &Bi,
    commande: &mut Command,
    secondes: u64,
    garder: Garder,
    etendue: Option<&Bi>,
    borne: u64,
) -> std::io::Result<Option<crate::commande::Ecrit>> {
    let mut f = creer_fichier(&dossier.join(nom))?;
    f.write_all(entete(titre).as_bytes())?;
    if let Some(etendue) = etendue {
        f.write_all(ligne_lu_sur(etendue).as_bytes())?;
    }
    let _ = writeln!(f, "# $ {}", super::affichage_commande(commande));
    Ok(lancer_vers(commande, secondes, &f, borne, garder))
}

/// La taille lisible d'un journal écrit.
pub(super) fn mo(octets: u64) -> Bi {
    #[allow(clippy::cast_precision_loss)]
    let mo = octets as f64 / f64::from(1u32 << 20);
    if mo < 1.0 {
        Bi::new("moins de 1 Mo", "less than 1 MB")
    } else {
        bi!("{mo:.0} Mo", "{mo:.0} MB")
    }
}

/// Pourquoi un fichier journal ne se lit pas.
fn raison_de(e: &std::io::Error) -> Raison {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        Raison::Droits
    } else {
        Raison::Erreur(e.to_string())
    }
}

/// Les fichiers journaux classiques, quand le journal du système ne répond pas (pas de systemd, journal vide) : la
/// fin de chacun, précédée de celle de son fichier tourné le plus récent (« auth.log.1 ») : tourné la nuit, le
/// fichier lui-même ne couvre que la journée.
pub(super) fn journaux_classiques(p: &mut Partie, dossier: &Path, fichiers: &[&str]) -> u64 {
    let mut total = 0;
    for source in fichiers {
        let source = Path::new(source);
        if !source.is_file() {
            continue;
        }
        let nom = format!(
            "05-{}.txt",
            source.to_string_lossy().trim_start_matches('/').replace('/', "-")
        );
        let tournes = tournes(source);
        match copier_avec_le_tourne(source, &tournes, dossier, &nom, FIN_JOURNAL) {
            Ok((n, erreur_du_tourne)) => {
                total += n;
                let contenu = match tournes.lisible.as_deref().filter(|_| erreur_du_tourne.is_none()) {
                    Some(tourne) => bi!(
                        "la fin de {} et de {}, le fichier tourné le plus récent (10 Mo chacun au plus)",
                        "the end of {} and of {}, the latest rotated file (10 MB each at most)",
                        source.display(),
                        tourne.display()
                    ),
                    None => bi!(
                        "la fin de {} (10 Mo au plus)",
                        "the end of {} (10 MB at most)",
                        source.display()
                    ),
                };
                p.fichiers.push(super::Produit { nom, contenu });
                // Le dernier fichier tourné qui n'a pas pu être lu : ce qui précède le fichier manque, et c'est dit.
                if let (Some(t), Some(e)) = (tournes.lisible.as_deref(), erreur_du_tourne) {
                    p.manque(Bi::meme(t.to_string_lossy()), raison_de(&e));
                }
                if let Some(t) = &tournes.compresse {
                    p.manque(
                        Bi::meme(t.to_string_lossy()),
                        Raison::LuSur(Bi::new("les journaux non compressés", "the uncompressed logs")),
                    );
                }
            }
            Err(e) => p.manque(Bi::meme(source.to_string_lossy()), raison_de(&e)),
        }
    }
    total
}

/// Les événements de la chronologie dans les journaux texte que la collecte vient d'écrire (05-*.txt : journal de
/// systemd, fin des fichiers de /var/log, journal unifié de macOS), sauf `sauf` : ces fichiers sont relus, pas
/// l'ordinateur. Aucun journal écrit (place, droits, commande absente) : dit si `signaler_absence`. `sans_droits` :
/// le journal écrit lu sans droits (celui de systemd, par un compte ordinaire), qui ne montre que le compte.
pub(super) fn journaux_ecrits(
    dossier: &Path,
    sauf: Option<&str>,
    signaler_absence: bool,
    sans_droits: Option<&str>,
) -> Apport {
    let mut apport = Apport::default();
    let mut journaux: Vec<PathBuf> = std::fs::read_dir(dossier)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            let chemin = e.path();
            let nom = e.file_name().to_string_lossy().into_owned();
            nom.starts_with("05-") && chemin.extension().is_some_and(|x| x == "txt") && sauf != Some(nom.as_str())
        })
        .map(|e| e.path())
        .collect();
    journaux.sort();
    if journaux.is_empty() && signaler_absence {
        apport.manques.push(Manque {
            quoi: Bi::new(
                "Chronologie : journal du système (pas écrit, voir Journaux)",
                "Timeline: system log (not written, see Logs)",
            ),
            raison: Raison::Introuvable,
        });
    }
    let maintenant = chrono::Local::now().naive_local();
    let debut = chronologie::secondes(std::time::SystemTime::now()).unwrap_or(0) - chronologie::JOURS * 86_400;
    for chemin in journaux {
        let nom = chemin.file_name().unwrap_or_default().to_string_lossy().into_owned();
        match lire_fichier(&chemin, maintenant) {
            Ok(mut lecture) => {
                apport.evenements.append(&mut lecture.evenements);
                // Un journal qui ne couvre pas la semaine : ce qui précède manque à la chronologie, et c'est dit avec
                // sa vraie raison. Seul un journal lu en entier, avec les droits, dit ce que le système a gardé ; les
                // bornes de Vanguard (50 Mo, la fin d'un fichier, le dernier jour de macOS) ne l'accusent pas.
                if let Some(q) = lecture.plus_ancienne.filter(|q| *q > debut + 3600) {
                    let depuis = chronologie::date_locale(q, &chrono::Local);
                    let borne = std::fs::metadata(&chemin).is_ok_and(|m| m.len() >= super::BORNE_JOURNAL);
                    apport.manques.push(Manque {
                        quoi: bi!(
                            "Chronologie : {nom} ne remonte qu'au {depuis}",
                            "Timeline: {nom} only goes back to {depuis}"
                        ),
                        raison: if borne {
                            Raison::Borne(super::BORNE_JOURNAL)
                        } else if let Some(etendue) = lecture.lu_sur {
                            Raison::LuSur(etendue)
                        } else if sans_droits == Some(nom.as_str()) {
                            Raison::Droits
                        } else {
                            Raison::NonGarde
                        },
                    });
                }
            }
            Err(e) => apport.manques.push(Manque {
                quoi: bi!("Chronologie : {nom}", "Timeline: {nom}"),
                raison: Raison::Erreur(e.to_string()),
            }),
        }
    }
    apport
}

/// Ce qu'un journal texte donne à la chronologie : ses événements, la date de sa ligne la plus ancienne (jusqu'où il
/// remonte), le nombre de ses lignes datées (ses entrées) et, s'il le dit dans son en-tête, l'étendue à laquelle
/// Vanguard l'a limité.
#[derive(Debug, Default)]
pub(super) struct Lecture {
    pub evenements: Vec<Evenement>,
    pub plus_ancienne: Option<i64>,
    pub entrees: usize,
    pub lu_sur: Option<Bi>,
}

impl Lecture {
    fn ligne(&mut self, ligne: &str, maintenant: chrono::NaiveDateTime) {
        // Seul l'en-tête compte, avant la première entrée datée.
        if self.entrees == 0
            && self.lu_sur.is_none()
            && let Some(etendue) = lu_sur(ligne)
        {
            self.lu_sur = Some(etendue);
            return;
        }
        if let Some(q) = chronologie::quand_de_ligne(ligne, maintenant, &chrono::Local) {
            self.entrees += 1;
            self.plus_ancienne = Some(self.plus_ancienne.map_or(q, |p| p.min(q)));
        }
        if let Some(e) = lire_ligne_journal(ligne, maintenant, &chrono::Local) {
            self.evenements.push(e);
        }
    }
}

/// Un journal en texte, déjà en mémoire (la sortie bornée de journalctl).
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub(super) fn lire_texte(texte: &str, maintenant: chrono::NaiveDateTime) -> Lecture {
    let mut lecture = Lecture::default();
    for l in texte.lines() {
        lecture.ligne(l, maintenant);
    }
    lecture
}

/// Un journal écrit, ligne à ligne (50 Mo au plus, jamais tout en mémoire).
fn lire_fichier(chemin: &Path, maintenant: chrono::NaiveDateTime) -> std::io::Result<Lecture> {
    let mut lecteur = std::io::BufReader::new(std::fs::File::open(chemin)?);
    let mut lecture = Lecture::default();
    let mut octets = Vec::new();
    loop {
        octets.clear();
        if lecteur.read_until(b'\n', &mut octets)? == 0 {
            break;
        }
        lecture.ligne(&String::from_utf8_lossy(&octets), maintenant);
    }
    Ok(lecture)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La fin d'un fichier seul, sans fichier tourné ; la taille écrite.
    fn copier_la_fin(source: &Path, dossier: &Path, nom: &str, borne: u64) -> std::io::Result<u64> {
        copier_avec_le_tourne(source, &Tournes::default(), dossier, nom, borne).map(|(n, _)| n)
    }

    /// Un journal inventé, écrit comme la collecte l'écrit : ses événements repris ; sans journal, c'est dit.
    #[test]
    fn journal_repris_dans_la_chronologie() {
        let dossier = crate::socle::dossier_local().join("chronologie-journal");
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).unwrap();
        let vide = journaux_ecrits(&dossier, None, true, None);
        assert_eq!(vide.evenements, Vec::new());
        assert_eq!(vide.manques.len(), 1);
        assert_eq!(vide.manques[0].raison, Raison::Introuvable);
        std::fs::write(
            dossier.join("05-journal.txt"),
            "# Vanguard 0.82.0 — Journal du système, 7 jours / System log, 7 days\n\
             # $ journalctl --since=-7d --reverse --no-pager -o short-iso\n\
             2026-10-20T14:05:00-04:00 portable sudo[77]:     alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id\n\
             2026-10-20T14:04:00-04:00 portable systemd[1]: Started x.service.\n\
             2026-10-20T14:03:22-04:00 portable sshd[4242]: Accepted password for alice from 192.0.2.10 port 1 ssh2\n\
             \u{fffd}\u{1b}[2J pas une ligne\n",
        )
        .unwrap();
        std::fs::write(
            dossier.join("02-reseau.txt"),
            "2026-10-20T14:03:22-04:00 h sshd[1]: Failed x for y from z\n",
        )
        .unwrap();
        // Le journal complet écarté (Linux l'a lu filtré) : rien d'autre, et rien à dire.
        let sans = journaux_ecrits(&dossier, Some("05-journal.txt"), false, None);
        assert_eq!((sans.evenements.len(), sans.manques.len()), (0, 0));
        let a = journaux_ecrits(&dossier, None, true, None);
        // Le journal inventé est daté : selon le jour où le test tourne, il couvre la semaine ou ne remonte qu'au
        // 20 octobre 2026 (à l'heure de l'ordinateur), et c'est dit.
        assert!(
            a.manques
                .iter()
                .all(|m| m.quoi.fr.contains("05-journal.txt ne remonte qu'au 2026-10-")),
            "{:?}",
            a.manques
        );
        let genres: Vec<_> = a.evenements.iter().map(|e| e.genre).collect();
        assert_eq!(
            genres,
            [
                super::super::chronologie::Genre::Sudo,
                super::super::chronologie::Genre::SshAccepte
            ]
        );
    }

    /// Un journal qui ne couvre pas la semaine, avec sa vraie raison : coupé ou limité par Vanguard (la fin d'un
    /// fichier, le dernier jour de macOS), lu sans droits, ou seulement alors pas gardé par le système. Les journaux
    /// sont inventés, datés d'hier, et écrits par les vraies fonctions de la collecte.
    #[test]
    fn raison_d_un_journal_court() {
        let dossier = crate::socle::dossier_local().join("chronologie-raisons");
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).unwrap();
        let hier = (chrono::Local::now() - chrono::Duration::hours(30)).format("%Y-%m-%dT%H:%M:%S%:z");
        let ligne = format!("{hier} portable sshd[4242]: Accepted password for alice from 192.0.2.10 port 1 ssh2\n");
        // La fin d'un fichier de /var/log, coupée par Vanguard.
        let source = dossier.join("auth.log");
        std::fs::write(&source, format!("{}{ligne}", "x\n".repeat(64))).unwrap();
        let borne = u64::try_from(ligne.len()).unwrap() + 4;
        copier_la_fin(&source, &dossier, "05-var-log-auth.log.txt", borne).unwrap();
        // Le journal unifié, que Vanguard ne lit que sur le dernier jour.
        let jour = Bi::new("1 jour", "1 day");
        let mut echo = Command::new("echo");
        echo.arg(ligne.trim_end());
        let titre = Bi::new("Journal unifié, 1 jour", "Unified log, 1 day");
        let ecrit = journal_vers(
            &dossier,
            "05-log-show.txt",
            &titre,
            &mut echo,
            10,
            Garder::Fin,
            Some(&jour),
        );
        assert!(ecrit.unwrap().is_some());
        // Le journal de systemd lu sans droits, et un journal lu en entier.
        for nom in ["05-journal.txt", "05-var-log-messages.txt"] {
            std::fs::write(dossier.join(nom), format!("{}{ligne}", entete(&Bi::meme(nom)))).unwrap();
        }
        let a = journaux_ecrits(&dossier, None, true, Some("05-journal.txt"));
        let raison = |nom: &str| {
            a.manques
                .iter()
                .find(|m| m.quoi.fr.starts_with(&format!("Chronologie : {nom} ne remonte qu'au ")))
                .map(|m| m.raison.clone())
        };
        assert_eq!(raison("05-var-log-auth.log.txt"), Some(Raison::LuSur(mo(borne))));
        assert_eq!(raison("05-log-show.txt"), Some(Raison::LuSur(jour.clone())));
        assert_eq!(raison("05-journal.txt"), Some(Raison::Droits));
        assert_eq!(raison("05-var-log-messages.txt"), Some(Raison::NonGarde));
        assert_eq!(a.manques.len(), 4, "{:?}", a.manques);
        assert_eq!(
            Raison::LuSur(jour).texte(),
            Bi::new("lu sur 1 jour par Vanguard", "only 1 day read by Vanguard")
        );
        // L'en-tête ne compte qu'avant la première entrée : la même ligne plus bas n'est qu'une ligne du journal.
        let texte = format!("{ligne}{}", ligne_lu_sur(&Bi::new("10 Mo", "10 MB")));
        let l = lire_texte(&texte, chrono::Local::now().naive_local());
        assert_eq!((l.entrees, l.lu_sur), (1, None));
    }

    /// Un journal tourné la nuit (logrotate, busybox) : la fin du dernier fichier tourné est reprise avant celle du
    /// fichier, et ce que Vanguard n'a pas lu (plus ancien, compressé) est dit, jamais « pas gardé par le système ».
    /// Les journaux sont inventés.
    #[test]
    fn journal_tourne_repris() {
        let dossier = crate::socle::dossier_local().join("journal-tourne");
        let _ = std::fs::remove_dir_all(&dossier);
        let sources = dossier.join("log");
        std::fs::create_dir_all(&sources).unwrap();
        let ligne = |heures: i64, compte: &str| {
            let quand = (chrono::Local::now() - chrono::Duration::hours(heures)).format("%Y-%m-%dT%H:%M:%S%:z");
            format!("{quand} portable sshd[4242]: Accepted password for {compte} from 192.0.2.10 port 1 ssh2\n")
        };
        let ecrire = |nom: &str, texte: &str, il_y_a: u64| {
            let chemin = sources.join(nom);
            std::fs::write(&chemin, texte).unwrap();
            let quand = std::time::SystemTime::now() - std::time::Duration::from_secs(il_y_a);
            std::fs::File::options()
                .write(true)
                .open(&chemin)
                .unwrap()
                .set_modified(quand)
                .unwrap();
        };
        let auth = sources.join("auth.log");
        ecrire("auth.log", &ligne(2, "alice"), 0);
        ecrire("auth.log.1", &ligne(50, "bob"), 3600);
        // Pas des fichiers tournés de auth.log.
        ecrire("auth.log.old", &ligne(60, "x"), 10);
        ecrire("auth.logx.1", &ligne(60, "x"), 10);
        let t = tournes(&auth);
        assert_eq!(
            (t.lisible.as_deref(), t.compresse.as_deref(), t.autres),
            (Some(sources.join("auth.log.1").as_path()), None, false)
        );
        // Le seul fichier tourné, lu en entier : ce qui précède, le système ne l'a pas gardé.
        let mut p = Partie::new(Bi::new("Journaux", "Logs"));
        let chemin = auth.to_string_lossy().into_owned();
        assert!(journaux_classiques(&mut p, &dossier, &[&chemin]) > 0);
        assert!(p.manques.is_empty(), "{:?}", p.manques);
        assert!(
            p.fichiers[0]
                .contenu
                .fr
                .contains("auth.log.1, le fichier tourné le plus récent")
        );
        let a = journaux_ecrits(&dossier, None, true, None);
        let comptes: Vec<String> = a.evenements.iter().map(|e| e.detail.clone()).collect();
        assert_eq!(a.evenements.len(), 2, "{comptes:?}");
        assert!(
            comptes[0].contains("bob") && comptes[1].contains("alice"),
            "{comptes:?}"
        );
        assert!(
            a.manques.iter().all(|m| m.raison == Raison::NonGarde),
            "{:?}",
            a.manques
        );
        // Plus ancien, compressé, pas lu : dit comme une limite de Vanguard.
        ecrire("auth.log.2.gz", "\x1f\u{8b}", 7200);
        let _ = std::fs::remove_file(dossier.join(&p.fichiers[0].nom));
        let mut p = Partie::new(Bi::new("Journaux", "Logs"));
        journaux_classiques(&mut p, &dossier, &[&chemin]);
        assert!(p.manques.is_empty(), "{:?}", p.manques);
        let a = journaux_ecrits(&dossier, None, true, None);
        assert!(
            a.manques.iter().all(|m| matches!(m.raison, Raison::LuSur(_))) && !a.manques.is_empty(),
            "{:?}",
            a.manques
        );
        // Le plus récent compressé (logrotate sans delaycompress) : le fichier seul, et le compressé dit non lu.
        ecrire("auth.log.1.gz", "\x1f\u{8b}", 60);
        let t = tournes(&auth);
        assert_eq!(
            (t.lisible, t.compresse.as_deref()),
            (None, Some(sources.join("auth.log.1.gz").as_path()))
        );
        let _ = std::fs::remove_file(dossier.join(&p.fichiers[0].nom));
        let mut p = Partie::new(Bi::new("Journaux", "Logs"));
        journaux_classiques(&mut p, &dossier, &[&chemin]);
        assert_eq!(p.manques.len(), 1, "{:?}", p.manques);
        assert!(matches!(p.manques[0].raison, Raison::LuSur(_)));
        let texte = std::fs::read_to_string(dossier.join(&p.fichiers[0].nom)).unwrap();
        assert!(texte.contains(LU_SUR) && !texte.contains("bob"), "{texte}");
        // Un lien n'est jamais suivi.
        #[cfg(unix)]
        {
            let lien = dossier.join("lien");
            std::fs::create_dir_all(&lien).unwrap();
            std::os::unix::fs::symlink(&auth, lien.join("auth.log.1")).unwrap();
            std::fs::write(lien.join("auth.log"), "").unwrap();
            assert_eq!(tournes(&lien.join("auth.log")), Tournes::default());
        }
    }

    #[test]
    fn fin_d_un_journal_a_partir_d_une_ligne() {
        let dossier = crate::socle::dossier_local().join("fin-journal");
        std::fs::create_dir_all(&dossier).unwrap();
        let source = dossier.join("auth.log");
        std::fs::write(&source, "un\ndeux\ntrois\n").unwrap();
        assert_eq!(copier_la_fin(&source, &dossier, "fin.txt", 8).unwrap(), 6);
        let texte = std::fs::read_to_string(dossier.join("fin.txt")).unwrap();
        assert!(
            texte.starts_with("# Vanguard ") && texte.ends_with("\ntrois\n"),
            "{texte}"
        );
        assert!(!texte.contains("deux"));
        // Coupé : l'en-tête le dit.
        assert!(
            texte.contains("\n# Lu par Vanguard sur / Read by Vanguard over: moins de 1 Mo / less than 1 MB\n"),
            "{texte}"
        );
        // Tout tient : rien n'est coupé, et l'en-tête n'en dit rien.
        assert_eq!(copier_la_fin(&source, &dossier, "tout.txt", 100).unwrap(), 14);
        assert!(
            !std::fs::read_to_string(dossier.join("tout.txt"))
                .unwrap()
                .contains(LU_SUR)
        );
        // Jamais un fichier existant écrasé.
        assert!(copier_la_fin(&source, &dossier, "tout.txt", 100).is_err());
        assert_eq!(mo(3 << 20).fr, "3 Mo");
        assert_eq!(mo(10).en, "less than 1 MB");
    }
}

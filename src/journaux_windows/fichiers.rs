//! La source « fichiers » des événements de Windows : un dossier de journaux .evtx (celui qu'exporte `vanguard
//! traces`, ou `Windows\System32\winevt\Logs` d'un disque monté depuis la clé de secours), lu sous Linux, macOS ou
//! Windows par le lecteur maison, en flux : morceau par morceau, chaque événement voulu donné un à un.
//!
//! Les fichiers viennent d'ailleurs, parfois d'un Windows piraté : nombre de fichiers et octets lus bornés, liens
//! et fichiers spéciaux (tubes, périphériques) jamais ouverts, rien du contenu des journaux utilisé comme chemin.
//! Ce qui n'a pas pu être lu est dit fichier par fichier, avec le bilan du lecteur tel quel : jamais « rien vu ».

use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::evenement::{Ecart, EvenementWindows, Filtre, Origine};
use super::evtx::{self, Bilan, Bornes};
use super::trous::{self, Contexte, Nature, Numerotation, Present, Suite};

/// Les bornes d'une lecture de dossier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BornesFichiers {
    /// Fichiers .evtx lus au plus : un `winevt\Logs` en compte quelques centaines.
    pub fichiers: usize,
    /// Octets lus au plus, tous fichiers ensemble (d'après leur taille) : les fichiers au-delà sont comptés, pas lus.
    pub octets: u64,
    /// Les bornes de chaque fichier.
    pub evtx: Bornes,
    /// Trous gardés au plus par suite de numéros.
    pub trous: usize,
    /// Suites d'EventRecordID d'origine gardées au plus par fichier exporté (une par ordinateur et par journal).
    pub suites_origine: usize,
}

impl Default for BornesFichiers {
    fn default() -> Self {
        Self {
            fichiers: 4096,
            // Seize fois la borne d'un fichier : un disque où l'on a grossi les journaux passe, un dossier gonflé
            // exprès s'arrête.
            octets: 16 << 30,
            evtx: Bornes::default(),
            trous: 1000,
            suites_origine: 64,
        }
    }
}

/// Ce qui empêche de lire un fichier du tout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErreurFichier {
    /// Ouverture refusée ou impossible (droits, fichier disparu).
    Ouverture(std::io::ErrorKind),
    /// Pas un fichier ordinaire : lien, dossier, tube, périphérique. Jamais ouvert (un tube bloquerait la lecture,
    /// un lien mènerait ailleurs que le dossier lu).
    PasUnFichier,
    /// Pas d'en-tête « ElfFile » : pas un journal .evtx, ou coupé avant la fin de son en-tête.
    PasUnEvtx,
    /// Erreur de lecture en cours de route.
    Lecture(std::io::ErrorKind),
}

/// Ce que la lecture d'un fichier a donné.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BilanFichier {
    pub chemin: Arc<Path>,
    /// Le bilan du lecteur, tel quel (morceaux et enregistrements illisibles, bornes atteintes), ou pourquoi le
    /// fichier n'a pas pu être lu du tout.
    pub lecture: Result<Bilan, ErreurFichier>,
    /// Les journaux (System/Channel) vus dans le fichier, dans l'ordre où ils viennent, au plus `MAX_JOURNAUX`.
    pub journaux: Vec<String>,
    /// Événements donnés à l'appelant.
    pub donnes: u64,
    /// Événements écartés par le filtre (journal, numéro, dates).
    pub filtres: u64,
    /// Événements sans date lisible, quand le filtre a une fenêtre de dates : ni donnés ni jugés.
    pub sans_date: u64,
    /// Événements sans numéro d'événement lisible : ni donnés ni jugés (ils comptent dans la suite des numéros).
    pub sans_identifiant: u64,
    /// Les EventRecordID diffèrent des numéros des enregistrements : un export renuméroté, ou une archive
    /// d'événements transférés.
    pub exporte: bool,
    /// La suite des numéros du fichier, puis, pour un fichier exporté, celle des EventRecordID d'origine par
    /// ordinateur et par journal. Vide quand le fichier n'a pas pu être lu, ou que le filtre ne veut aucun de ses
    /// journaux.
    pub suites: Vec<Suite>,
    /// Événements dont la suite d'origine n'a pas été gardée (au-delà de `BornesFichiers::suites_origine`).
    pub hors_suites: u64,
}

impl BilanFichier {
    /// Le fichier a été lu en entier, et chaque événement donné ou écarté exprès : rien n'est resté sans jugement.
    /// Comme pour `Bilan::complet`, les enregistrements rangés après la place libre n'y comptent pas.
    pub(crate) fn complet(&self) -> bool {
        self.lecture.as_ref().is_ok_and(Bilan::complet) && self.sans_date == 0 && self.sans_identifiant == 0
    }
}

/// Ce que la lecture d'un dossier a donné.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BilanDossier {
    pub dossier: PathBuf,
    /// Un bilan par fichier .evtx essayé, dans l'ordre de leur nom.
    pub fichiers: Vec<BilanFichier>,
    /// Fichiers .evtx au-delà de `BornesFichiers::fichiers` ou `BornesFichiers::octets` : pas lus.
    pub hors_borne: u64,
    /// Entrées du dossier qui n'ont pas pu être lues (nom ou type) : peut-être des .evtx.
    pub entrees_illisibles: u64,
}

impl BilanDossier {
    /// Tout le dossier a été lu, et chaque fichier en entier.
    pub(crate) fn complet(&self) -> bool {
        self.hors_borne == 0 && self.entrees_illisibles == 0 && self.fichiers.iter().all(BilanFichier::complet)
    }
}

/// Journaux gardés au plus dans `BilanFichier::journaux` : un fichier ordinaire n'en a qu'un, une archive
/// d'événements transférés quelques-uns.
pub(crate) const MAX_JOURNAUX: usize = 16;

/// Lit les fichiers .evtx du dossier (pas ses sous-dossiers), dans l'ordre de leur nom, et donne à `recevoir` chaque
/// événement que `filtre` veut. `Err` : le dossier lui-même ne se lit pas.
pub(crate) fn lire_dossier(
    dossier: &Path,
    filtre: &Filtre,
    bornes: &BornesFichiers,
    mut recevoir: impl FnMut(EvenementWindows),
) -> std::io::Result<BilanDossier> {
    let mut bilan = BilanDossier {
        dossier: dossier.to_path_buf(),
        fichiers: Vec::new(),
        hors_borne: 0,
        entrees_illisibles: 0,
    };
    let mut chemins = Vec::new();
    for entree in std::fs::read_dir(dossier)? {
        let Ok(entree) = entree else {
            bilan.entrees_illisibles += 1;
            continue;
        };
        let chemin = entree.path();
        let evtx = chemin
            .extension()
            .and_then(|x| x.to_str())
            .is_some_and(|x| x.eq_ignore_ascii_case("evtx"));
        if evtx {
            chemins.push(chemin);
        }
        // Un dossier hostile peut contenir des millions d'entrées : la liste s'arrête un peu après la borne, le
        // reste n'est compté qu'en nombre.
        if chemins.len() > bornes.fichiers.saturating_mul(2) {
            bilan.hors_borne += 1;
            chemins.pop();
        }
    }
    chemins.sort();
    let mut octets = 0u64;
    for chemin in chemins {
        if bilan.fichiers.len() >= bornes.fichiers {
            bilan.hors_borne += 1;
            continue;
        }
        // La taille d'après le dossier, sans suivre de lien : elle décide seulement si le fichier entre dans la
        // borne ; le lecteur borne lui-même ce qu'il lit.
        let taille = std::fs::symlink_metadata(&chemin).map_or(0, |m| m.len());
        if octets.saturating_add(taille) > bornes.octets {
            bilan.hors_borne += 1;
            continue;
        }
        octets = octets.saturating_add(taille);
        bilan
            .fichiers
            .push(lire_fichier(&chemin, filtre, bornes, &mut recevoir));
    }
    Ok(bilan)
}

/// Ouvre un fichier ordinaire sans suivre de lien ni attendre (un tube s'ouvrirait sinon en bloquant), et vérifie
/// sur ce qui a été ouvert que c'est bien un fichier ordinaire.
fn ouvrir(chemin: &Path) -> Result<std::fs::File, ErreurFichier> {
    match std::fs::symlink_metadata(chemin) {
        Ok(m) if !m.file_type().is_file() => return Err(ErreurFichier::PasUnFichier),
        Ok(_) => {}
        Err(e) => return Err(ErreurFichier::Ouverture(e.kind())),
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let fichier = options.open(chemin).map_err(|e| ErreurFichier::Ouverture(e.kind()))?;
    match fichier.metadata() {
        Ok(m) if m.is_file() => Ok(fichier),
        Ok(_) => Err(ErreurFichier::PasUnFichier),
        Err(e) => Err(ErreurFichier::Ouverture(e.kind())),
    }
}

/// Lit un fichier .evtx et donne à `recevoir` chaque événement que `filtre` veut ; la suite de ses numéros est jugée
/// sur tous ses enregistrements, voulus ou non.
pub(crate) fn lire_fichier(
    chemin: &Path,
    filtre: &Filtre,
    bornes: &BornesFichiers,
    mut recevoir: impl FnMut(EvenementWindows),
) -> BilanFichier {
    let chemin: Arc<Path> = Arc::from(chemin);
    let mut bilan = BilanFichier {
        chemin: chemin.clone(),
        lecture: Err(ErreurFichier::PasUnEvtx),
        journaux: Vec::new(),
        donnes: 0,
        filtres: 0,
        sans_date: 0,
        sans_identifiant: 0,
        exporte: false,
        suites: Vec::new(),
        hors_suites: 0,
    };
    let fichier = match ouvrir(&chemin) {
        Ok(f) => f,
        Err(e) => {
            bilan.lecture = Err(e);
            return bilan;
        }
    };
    let mut presents: Vec<Present> = Vec::new();
    // Les EventRecordID d'origine, par (ordinateur, journal).
    let mut origines: Vec<((String, String), Vec<Present>)> = Vec::new();
    let mut voulu = filtre.journaux.is_empty();
    let lecture = evtx::parcourir(std::io::BufReader::new(fichier), &bornes.evtx, |e| {
        let date = e.cree.or(e.date);
        presents.push(Present { numero: e.numero, date });
        if e.numero_systeme.is_some_and(|n| n != e.numero) {
            bilan.exporte = true;
        }
        if let Some(n) = e.numero_systeme {
            let cle = (e.ordinateur.as_str(), e.canal.as_str());
            let place = origines.iter().position(|(c, _)| (c.0.as_str(), c.1.as_str()) == cle);
            match place {
                Some(i) => origines[i].1.push(Present { numero: n, date }),
                None if origines.len() < bornes.suites_origine => {
                    origines.push((
                        (e.ordinateur.clone(), e.canal.clone()),
                        vec![Present { numero: n, date }],
                    ));
                }
                None => bilan.hors_suites += 1,
            }
        }
        if !bilan.journaux.contains(&e.canal) && bilan.journaux.len() < MAX_JOURNAUX {
            bilan.journaux.push(e.canal.clone());
        }
        voulu |= filtre.veut_journal(&e.canal);
        let numero_fichier = e.numero;
        let Some(evenement) = EvenementWindows::depuis(
            e,
            Origine::Fichier {
                chemin: chemin.clone(),
                numero_fichier,
            },
        ) else {
            bilan.sans_identifiant += 1;
            return;
        };
        match filtre.juger(&evenement) {
            Ok(()) => {
                bilan.donnes += 1;
                recevoir(evenement);
            }
            Err(Ecart::Filtre) => bilan.filtres += 1,
            Err(Ecart::SansDate) => bilan.sans_date += 1,
        }
    });
    match lecture {
        Ok(lu) => {
            if voulu {
                bilan.suites = suites(&lu, presents, bilan.exporte, origines, bornes.trous);
            }
            bilan.lecture = Ok(lu);
        }
        Err(evtx::Erreur::PasUnEvtx) => bilan.lecture = Err(ErreurFichier::PasUnEvtx),
        Err(evtx::Erreur::Lecture(e)) => bilan.lecture = Err(ErreurFichier::Lecture(e.kind())),
    }
    bilan
}

/// La nature d'un trou entre deux morceaux, d'après ce que la lecture du fichier a pu faire.
pub(crate) fn entre_morceaux(lu: &Bilan) -> Nature {
    let pertes_sans_place = lu.morceaux_hors_borne > 0
        || lu.morceaux_sans_recap > 0
        || lu.morceaux.iter().any(|m| !m.lu && m.annonce.is_none());
    if pertes_sans_place {
        Nature::Illisible
    } else if lu.sale || lu.en_tete_abime {
        Nature::CopieAChaud
    } else {
        Nature::Absents
    }
}

/// Les suites d'un fichier lu : la sienne, puis, s'il est exporté, celles des EventRecordID d'origine.
fn suites(
    lu: &Bilan,
    presents: Vec<Present>,
    exporte: bool,
    origines: Vec<((String, String), Vec<Present>)>,
    max_trous: usize,
) -> Vec<Suite> {
    let contexte = Contexte {
        morceaux: &lu.morceaux,
        entre_morceaux: entre_morceaux(lu),
    };
    let mut sortie = vec![trous::juger(Numerotation::Journal, presents, &contexte, max_trous)];
    if exporte {
        let sans_morceaux = Contexte {
            morceaux: &[],
            entre_morceaux: Nature::AvantExport,
        };
        for ((ordinateur, journal), v) in origines {
            sortie.push(trous::juger(
                Numerotation::Origine { ordinateur, journal },
                v,
                &sans_morceaux,
                max_trous,
            ));
        }
    }
    sortie
}

#[cfg(test)]
mod tests;

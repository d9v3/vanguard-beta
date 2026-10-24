//! La source « fichiers » des événements de Windows : un dossier de journaux .evtx (celui qu'exporte `vanguard
//! traces`, ou `Windows\System32\winevt\Logs` d'un disque monté depuis la clé de secours), lu sous Linux, macOS ou
//! Windows par le lecteur maison, en flux : morceau par morceau, chaque événement voulu donné un à un.
//!
//! Les fichiers viennent d'ailleurs, parfois d'un Windows piraté : nombre de fichiers et octets lus bornés (les
//! journaux qui comptent lus d'abord, pour qu'un dossier gonflé de leurres ne les fasse pas passer au-delà), liens
//! et fichiers spéciaux (tubes, périphériques) jamais ouverts, rien du contenu des journaux utilisé comme chemin.
//! Ce qui n'a pas pu être lu est dit fichier par fichier, avec le bilan du lecteur tel quel : jamais « rien vu ».

use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::evenement::{Ecart, EvenementWindows, Filtre, Origine};
use super::evtx::{self, Bilan, Bornes, CAPACITE_MORCEAU, EtatMorceau};
use super::trous::{self, CLE_MAX, Contexte, Nature, Numerotation, Present, Suite};

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
    /// Trous gardés au plus pour tout le dossier : les suivants sont comptés (`Suite::trous_au_dela`).
    pub trous_dossier: usize,
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
            trous_dossier: 20_000,
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
    /// Parmi eux, ceux d'un morceau non vérifié (`EvenementWindows::verifie` faux).
    pub non_verifies: u64,
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
    /// Un bilan par fichier .evtx essayé, dans l'ordre de lecture : les journaux qui comptent (`PRIORITAIRES`), puis
    /// les autres du plus petit au plus grand.
    pub fichiers: Vec<BilanFichier>,
    /// Fichiers .evtx au-delà de `BornesFichiers::fichiers` ou `BornesFichiers::octets` : pas lus.
    pub hors_borne: u64,
    /// Entrées du dossier qui n'ont pas pu être lues (nom ou type) : peut-être des .evtx.
    pub entrees_illisibles: u64,
    /// Autres entrées du dossier, pas en .evtx : pas lues (un journal renommé n'est pas vu).
    pub autres: u64,
}

impl BilanDossier {
    /// Tout le dossier a été lu, et chaque fichier en entier.
    pub(crate) fn complet(&self) -> bool {
        self.hors_borne == 0 && self.entrees_illisibles == 0 && self.fichiers.iter().all(BilanFichier::complet)
    }
}

/// Journaux gardés au plus dans `BilanFichier::journaux` (chacun coupé à `CLE_MAX` caractères) : un fichier
/// ordinaire n'en a qu'un, une archive d'événements transférés quelques-uns.
pub(crate) const MAX_JOURNAUX: usize = 16;

/// Les journaux lus d'abord, dans cet ordre (noms de fichiers de `winevt\Logs`, puis ceux qu'exporte `vanguard
/// traces`) : ceux où une attaque se voit. Le reste suit, du plus petit au plus grand.
const PRIORITAIRES: [&str; 16] = [
    "Security.evtx",
    "System.evtx",
    "Microsoft-Windows-PowerShell%4Operational.evtx",
    "Microsoft-Windows-Windows Defender%4Operational.evtx",
    "Windows PowerShell.evtx",
    "Microsoft-Windows-TaskScheduler%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
    "Microsoft-Windows-Bits-Client%4Operational.evtx",
    "Microsoft-Windows-WMI-Activity%4Operational.evtx",
    "Microsoft-Windows-Sysmon%4Operational.evtx",
    "Application.evtx",
    "05-Security.evtx",
    "05-System.evtx",
    "05-PowerShell.evtx",
    "05-Defender.evtx",
];

/// Le rang d'un fichier dans la liste des prioritaires, et si son nom y est écrit exactement (même casse) : sur un
/// système de fichiers sensible à la casse, « SECURity.evtx » peut voisiner avec le vrai.
fn priorite(chemin: &Path) -> Option<(usize, bool)> {
    let nom = chemin.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    let rang = PRIORITAIRES.iter().position(|p| p.eq_ignore_ascii_case(nom))?;
    Some((rang, PRIORITAIRES[rang] == nom))
}

/// Coupe un nom venu du journal à `CLE_MAX` caractères.
fn couper(t: &str) -> String {
    t.chars().take(CLE_MAX).collect()
}

/// Lit les fichiers .evtx du dossier (pas ses sous-dossiers), les journaux qui comptent d'abord (un seul fichier par
/// nom prioritaire, celui écrit exactement de préférence), puis les autres du plus petit au plus grand, et donne à
/// `recevoir` chaque événement que `filtre` veut. `Err` : le dossier lui-même ne se lit pas.
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
        autres: 0,
    };
    // La taille d'après le dossier, sans suivre de lien : elle décide seulement de l'ordre et de la borne ; le
    // lecteur borne lui-même ce qu'il lit.
    let taille = |c: &Path| std::fs::symlink_metadata(c).map_or(0, |m| m.len());
    // Un fichier par nom prioritaire (écrit exactement, s'il y en a un), et les autres : au-delà de deux fois la
    // borne, ceux-ci ne sont comptés qu'en nombre (un dossier hostile peut contenir des millions d'entrées).
    let mut prioritaires: Vec<Option<(bool, PathBuf)>> = vec![None; PRIORITAIRES.len()];
    let mut autres: Vec<(u64, PathBuf)> = Vec::new();
    let ranger_autre = |c: PathBuf, autres: &mut Vec<(u64, PathBuf)>, bilan: &mut BilanDossier| {
        if autres.len() >= bornes.fichiers.saturating_mul(2) {
            bilan.hors_borne += 1;
        } else {
            autres.push((taille(&c), c));
        }
    };
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
        if !evtx {
            bilan.autres += 1;
            continue;
        }
        match priorite(&chemin) {
            Some((rang, exact)) => match prioritaires[rang].take() {
                None => prioritaires[rang] = Some((exact, chemin)),
                Some((false, deja)) if exact => {
                    ranger_autre(deja, &mut autres, &mut bilan);
                    prioritaires[rang] = Some((true, chemin));
                }
                Some(deja) => {
                    prioritaires[rang] = Some(deja);
                    ranger_autre(chemin, &mut autres, &mut bilan);
                }
            },
            None => ranger_autre(chemin, &mut autres, &mut bilan),
        }
    }
    autres.sort();
    let chemins = prioritaires
        .into_iter()
        .flatten()
        .map(|(_, c)| (taille(&c), c))
        .chain(autres);
    let mut octets = 0u64;
    let mut trous_restants = bornes.trous_dossier;
    for (taille, chemin) in chemins {
        if bilan.fichiers.len() >= bornes.fichiers || octets.saturating_add(taille) > bornes.octets {
            bilan.hors_borne += 1;
            continue;
        }
        octets = octets.saturating_add(taille);
        let f = lire_fichier_borne(&chemin, filtre, bornes, trous_restants, &mut recevoir);
        let gardes: usize = f.suites.iter().map(|s| s.trous.len()).sum();
        trous_restants = trous_restants.saturating_sub(gardes);
        bilan.fichiers.push(f);
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
    // Sous Windows, un point d'analyse (lien, jonction) est ouvert lui-même, pas suivi : posé entre la vérification
    // et l'ouverture, il n'est pas un fichier ordinaire et se voit ci-dessous.
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let fichier = options.open(chemin).map_err(|e| ErreurFichier::Ouverture(e.kind()))?;
    // Un point d'analyse qui n'est pas un lien (fichier OneDrive « à la demande », déduplication) s'ouvre lui-même
    // sans ses données : rouvert normalement, il se lit (un lien, lui, n'est pas un fichier et reste refusé).
    #[cfg(windows)]
    let fichier = {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        match fichier.metadata() {
            Ok(m) if m.file_type().is_file() && m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 => {
                std::fs::File::open(chemin).map_err(|e| ErreurFichier::Ouverture(e.kind()))?
            }
            _ => fichier,
        }
    };
    match fichier.metadata() {
        Ok(m) if m.file_type().is_file() => Ok(fichier),
        Ok(_) => Err(ErreurFichier::PasUnFichier),
        Err(e) => Err(ErreurFichier::Ouverture(e.kind())),
    }
}

/// Lit un fichier .evtx et donne à `recevoir` chaque événement que `filtre` veut ; la suite de ses numéros est jugée
/// sur tous ses enregistrements, voulus ou non, quel que soit leur journal (un journal renommé dans les
/// enregistrements ne fait pas taire la suite).
pub(crate) fn lire_fichier(
    chemin: &Path,
    filtre: &Filtre,
    bornes: &BornesFichiers,
    recevoir: impl FnMut(EvenementWindows),
) -> BilanFichier {
    lire_fichier_borne(chemin, filtre, bornes, bornes.trous_dossier, recevoir)
}

/// `lire_fichier`, au plus `trous_restants` trous gardés en tout (ce qu'il reste de la borne du dossier).
fn lire_fichier_borne(
    chemin: &Path,
    filtre: &Filtre,
    bornes: &BornesFichiers,
    trous_restants: usize,
    mut recevoir: impl FnMut(EvenementWindows),
) -> BilanFichier {
    let chemin: Arc<Path> = Arc::from(chemin);
    let mut bilan = BilanFichier {
        chemin: chemin.clone(),
        lecture: Err(ErreurFichier::PasUnEvtx),
        journaux: Vec::new(),
        donnes: 0,
        non_verifies: 0,
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
    let lecture = evtx::parcourir(std::io::BufReader::new(fichier), &bornes.evtx, |e| {
        let date = e.cree.or(e.date);
        presents.push(Present {
            numero: e.numero,
            date,
            morceau: Some(e.morceau),
            verifie: e.verifie,
        });
        // Un enregistrement non vérifié (page à moitié recopiée) ne fait pas d'un fichier un export.
        if e.verifie && e.numero_systeme.is_some_and(|n| n != e.numero) {
            bilan.exporte = true;
        }
        if let Some(n) = e.numero_systeme {
            let cle = (couper(&e.ordinateur), couper(&e.canal));
            let origine = Present {
                numero: n,
                date,
                morceau: None,
                verifie: e.verifie,
            };
            match origines.iter().position(|(c, _)| *c == cle) {
                Some(i) => origines[i].1.push(origine),
                None if origines.len() < bornes.suites_origine => origines.push((cle, vec![origine])),
                None => bilan.hors_suites += 1,
            }
        }
        let journal = couper(&e.canal);
        if !bilan.journaux.contains(&journal) && bilan.journaux.len() < MAX_JOURNAUX {
            bilan.journaux.push(journal);
        }
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
                bilan.non_verifies += u64::from(!evenement.verifie);
                recevoir(evenement);
            }
            Err(Ecart::Filtre) => bilan.filtres += 1,
            Err(Ecart::SansDate) => bilan.sans_date += 1,
        }
    });
    match lecture {
        Ok(lu) => {
            // Les enregistrements entiers non rendus existent : leur numéro n'est pas un trou.
            // Un enregistrement non rendu d'un morceau non vérifié ne prouve pas plus que ceux qui s'y rendent.
            let non_verifie = |rang: u64| {
                lu.morceaux
                    .iter()
                    .any(|m| m.rang == rang && m.etat == EtatMorceau::NonVerifie)
            };
            presents.extend(lu.numeros_non_rendus.iter().map(|&(numero, rang)| Present {
                numero,
                date: None,
                morceau: Some(rang),
                verifie: !non_verifie(rang),
            }));
            let max_trous = bornes.trous.min(trous_restants);
            bilan.suites = suites(&lu, presents, bilan.exporte, origines, max_trous);
            bilan.lecture = Ok(lu);
        }
        Err(evtx::Erreur::PasUnEvtx) => bilan.lecture = Err(ErreurFichier::PasUnEvtx),
        Err(evtx::Erreur::Lecture(e)) => bilan.lecture = Err(ErreurFichier::Lecture(e.kind())),
    }
    bilan
}

/// Les signes d'une copie à chaud, que le drapeau « sale » seul ne prouve pas (il n'est pas couvert par le CRC de
/// l'en-tête) : un morceau à zéro avant un morceau écrit (jamais arrivé sur le disque ; Windows remplit ses
/// morceaux dans l'ordre, et un journal fermé proprement n'a de morceaux à zéro qu'à la fin), ou des morceaux
/// d'époques mêlées : plus d'un retour en arrière des numéros dans l'ordre du fichier (un journal tournant n'en a
/// qu'un, là où il reprend au début), ou un retour en arrière vers un morceau que le suivant ne prolonge pas (un
/// morceau resté d'un tour plus ancien). Vus dans les échantillons publics copiés d'un cliché de volume. Un
/// attaquant qui remet un morceau à zéro et pose le drapeau fabrique les mêmes signes : la copie à chaud reste une
/// réserve, jamais une absence de constat.
fn signes_de_copie(lu: &Bilan) -> bool {
    let mut vide_avant = false;
    let mut zero_au_milieu = false;
    for m in &lu.morceaux {
        match m.etat {
            EtatMorceau::Vide | EtatMorceau::Prepare => vide_avant = true,
            _ if vide_avant => zero_au_milieu = true,
            _ => {}
        }
    }
    let plages: Vec<(u64, u64)> = lu
        .morceaux
        .iter()
        .filter(|m| m.etat == EtatMorceau::Lu)
        .filter_map(|m| m.annonce)
        .collect();
    let reculs: Vec<usize> = (1..plages.len()).filter(|&i| plages[i].0 < plages[i - 1].0).collect();
    let recul_isole = reculs.iter().any(|&i| {
        plages
            .get(i + 1)
            .is_some_and(|suivant| plages[i].1.checked_add(1) != Some(suivant.0))
    });
    zero_au_milieu || reculs.len() > 1 || recul_isole
}

/// La nature d'un trou entre deux morceaux que les pertes de lecture ne couvrent pas, d'après l'état du fichier.
pub(crate) fn entre_morceaux(lu: &Bilan) -> Nature {
    if (lu.sale || lu.en_tete_abime) && signes_de_copie(lu) {
        Nature::CopieAChaud
    } else {
        Nature::Absents
    }
}

/// Ce que la lecture a perdu sans savoir quels numéros : les morceaux écartés sans plage connue (à leur capacité ;
/// pour un morceau non vérifié, ses passages abîmés ;
/// rien pour un bloc au-delà du nombre de morceaux qu'annonce l'en-tête d'un fichier propre, qui n'a rien pu
/// porter : du rebut ajouté au bout), les morceaux au-delà des bornes et ceux sans récapitulatif (pleins).
fn pertes(lu: &Bilan) -> Vec<u64> {
    let ecrits = lu
        .nombre_morceaux
        .filter(|_| !lu.sale && !lu.en_tete_abime)
        .map(u64::from);
    let mut sortie: Vec<u64> = lu
        .morceaux
        .iter()
        .filter_map(|m| {
            let capacite = match m.etat {
                EtatMorceau::Ecarte if m.annonce.is_none() => m.capacite,
                // Relu enregistrement par enregistrement : ses seules pertes sans numéro sont ses passages abîmés,
                // à un enregistrement par 28 octets.
                EtatMorceau::NonVerifie => m.non_rendus,
                _ => return None,
            };
            Some(if ecrits.is_some_and(|n| m.rang >= n) {
                0
            } else {
                capacite
            })
        })
        .collect();
    // Chacun pour soi : dans un journal tournant, deux morceaux voisins dans le fichier peuvent porter des numéros
    // éloignés. Au-delà de `MAX_RECAPS` pertes, la dernière prend le reste (le bilan ne grossit pas sans fin).
    let pleins = lu.morceaux_hors_borne.saturating_add(lu.morceaux_sans_recap);
    let un_par_un = pleins.min(evtx::MAX_RECAPS as u64);
    sortie.extend((0..un_par_un).map(|_| CAPACITE_MORCEAU));
    if let Some(dernier) = sortie.last_mut()
        && pleins > un_par_un
    {
        *dernier = dernier.saturating_add((pleins - un_par_un).saturating_mul(CAPACITE_MORCEAU));
    }
    sortie
}

/// Les suites d'un fichier lu : la sienne, puis, s'il est exporté, celles des EventRecordID d'origine.
fn suites(
    lu: &Bilan,
    presents: Vec<Present>,
    exporte: bool,
    origines: Vec<((String, String), Vec<Present>)>,
    max_trous: usize,
) -> Vec<Suite> {
    let pertes = pertes(lu);
    let morceaux = lu.morceaux.len() as u64 + lu.morceaux_hors_borne + lu.morceaux_sans_recap;
    let vide_par_windows = presents.is_empty()
        && lu.morceaux.iter().any(|m| m.etat == EtatMorceau::Prepare)
        && lu
            .morceaux
            .iter()
            .all(|m| matches!(m.etat, EtatMorceau::Prepare | EtatMorceau::Vide));
    let contexte = Contexte {
        morceaux: &lu.morceaux,
        entre_morceaux: entre_morceaux(lu),
        pertes: &pertes,
        // Le prochain numéro de l'en-tête (juste, couvert par son CRC) : dans un fichier sale, il retarde (vu dans
        // chaque échantillon sale), mais un prochain en avance y reste un signe ; le drapeau sale, hors du CRC, ne
        // le fait pas taire. Rien pour un journal vidé par Windows (un morceau préparé, aucun enregistrement) : la
        // numérotation continue après un effacement, sans trou.
        prochain: lu.prochain_numero.filter(|_| !vide_par_windows),
        prochain_peut_retarder: lu.sale,
        capacite: morceaux.saturating_mul(CAPACITE_MORCEAU),
    };
    let mut sortie = vec![trous::juger(Numerotation::Journal, presents, &contexte, max_trous)];
    if exporte {
        let mut restant = max_trous.saturating_sub(sortie[0].trous.len());
        for ((ordinateur, journal), v) in origines {
            let s = trous::juger(
                Numerotation::Origine { ordinateur, journal },
                v,
                &Contexte::nu(Nature::AvantExport),
                restant,
            );
            restant = restant.saturating_sub(s.trous.len());
            sortie.push(s);
        }
    }
    sortie
}

#[cfg(test)]
mod tests;

//! Les trous dans la suite des numéros d'enregistrement (EventRecordID) d'un journal : des enregistrements retirés
//! un à un (effacement partiel, T1070.001), que l'effacement entier (1102, 104) ne dit pas.
//!
//! Ce que dit Microsoft du numéro : le premier enregistrement d'un journal porte le numéro 1, les suivants se
//! suivent ; un journal qui écrase ses plus anciens n'a plus le numéro 1, le plus ancien est ailleurs (« Event Log
//! Records », <https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-records>). Après un effacement,
//! la suite continue : le 1102 qui ouvre le journal vidé porte un grand numéro (exemple de la page de l'événement
//! 1102, EventRecordID 1087729 ;
//! <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102>),
//! vu aussi dans un échantillon public (security_big_sample.evtx de la crate evtx : un 1102 au numéro 227126, en
//! tête d'un fichier dont les morceaux recomptent depuis 1). Ni l'effacement ni la rotation ne font donc de trou :
//! ils font commencer la suite plus loin. Ce qui précède le plus petit numéro n'est jamais un trou.
//!
//! Où tombe chaque numéro manquant, et ce qu'il veut dire :
//! - entre deux enregistrements d'un même morceau lu, ou dans la plage qu'annonce l'en-tête d'un morceau lu : ce
//!   morceau le réclame. Windows numérote les enregistrements d'un morceau à la suite : il y manque des
//!   enregistrements retirés (`Retires`), le morceau réécrit et ses CRC recalculés ; sauf si le morceau a des
//!   enregistrements que la lecture n'a pas rendus, et assez pour couvrir tout ce qui lui manque (`Illisible`).
//!   Un morceau écarté qui annoncerait les mêmes numéros n'y change rien : un numéro n'a qu'un morceau ;
//! - dans la plage qu'annonce un morceau écarté (CRC faux) : la lecture l'a perdu (`Illisible`) ;
//! - ailleurs, entre deux morceaux : la lecture a pu le perdre dans un morceau écarté dont la plage n'est pas
//!   connue, mais un tel morceau ne porte qu'une plage contiguë d'au plus `CAPACITE_MORCEAU` numéros : ce que les
//!   pertes peuvent couvrir est `Illisible`, le reste prend la nature donnée par l'appelant (`Absents` pour un
//!   fichier propre ou l'ordinateur vivant ; `CopieAChaud` pour un fichier « sale » qui en montre les signes ;
//!   `AvantExport` pour les EventRecordID d'origine d'un fichier exporté).
//!
//! Un morceau au CRC faux est relu (`EtatMorceau::NonVerifie`) : ses enregistrements entiers comptent comme
//! présents, mais ne comblent jamais un numéro qu'un morceau vérifié réclame (un faux morceau ajouté ne fait pas
//! disparaître un retrait), et la suite dit combien de ses numéros ne tiennent qu'à eux (`Suite::non_verifies`) :
//! une suite sans trou dont `non_verifies` n'est pas nul n'est pas une preuve que rien n'a été retiré. Un numéro
//! manquant dans ce qu'il couvre est `Illisible`, peut-être un de ses enregistrements abîmés.
//!
//! Le prochain numéro qu'annonce l'en-tête du fichier (couvert par son CRC) fait voir les derniers enregistrements
//! ôtés, et un journal remis à zéro à la main ; pas un journal vidé par Windows (un morceau préparé, aucun
//! enregistrement), dont la numérotation continue sans trou.
//!
//! Le drapeau « sale » de l'en-tête du fichier n'est pas couvert par son CRC : un attaquant le pose sans rien
//! recalculer. `CopieAChaud` n'est donc jamais une raison de se taire, seulement une réserve (fichiers::entre_morceaux
//! exige en plus les signes d'une copie à chaud : morceaux remis à zéro avant d'autres, morceaux d'époques mêlées,
//! vus dans les échantillons publics copiés d'un cliché de volume). Ce que la suite ne peut pas voir : des
//! enregistrements modifiés ou remplacés sans changer leur numéro, et un fichier renuméroté entier.
//!
//! Module autonome (aucun `crate::`) : pur, sans entrée ni sortie, essayé par proptest contre un modèle naïf.

use std::collections::{BTreeSet, HashMap};

use chrono::{DateTime, Utc};

use super::evtx::{EtatMorceau, RecapMorceau};

/// Ce qu'un trou veut dire, d'après l'endroit où il tombe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Nature {
    /// Réclamé par un morceau lu (entre deux de ses enregistrements, ou dans sa plage annoncée) que ses
    /// enregistrements non rendus ne suffisent pas à expliquer : des enregistrements retirés du morceau.
    Retires,
    /// Entre deux morceaux d'un fichier fermé proprement, ou dans ce que rend le service des journaux de
    /// l'ordinateur, au-delà de ce que la lecture a pu perdre : des enregistrements manquent. Retirés (morceaux
    /// remis à zéro ou ôtés, derniers enregistrements ôtés, fichier remplacé), ou fichier copié incomplet.
    Absents,
    /// Comme `Absents`, dans un fichier « sale » ou à l'en-tête abîmé qui montre les signes d'une copie à chaud :
    /// les morceaux que Windows gardait en mémoire n'étaient pas sur le disque. Pas une preuve d'effacement, mais
    /// pas une absence de preuve non plus (le drapeau n'est pas protégé).
    CopieAChaud,
    /// Là où la lecture a perdu quelque chose qui peut le contenir : non vérifié.
    Illisible,
    /// Entre deux EventRecordID d'origine d'un fichier exporté, d'une archive d'événements transférés ou d'un
    /// journal de collecte : effacés du journal d'origine avant l'export, ou laissés de côté par le filtre de
    /// l'export ou de l'abonnement.
    AvantExport,
}

/// Quels numéros forment la suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Numerotation {
    /// Ceux du journal lu : les en-têtes des enregistrements d'un fichier, ou les EventRecordID que rend le service
    /// des journaux.
    Journal,
    /// Les EventRecordID d'origine d'un fichier exporté ou d'un journal de collecte, pour un ordinateur et un
    /// journal (System/Computer, System/Channel, coupés à `CLE_MAX` caractères) : une archive d'événements
    /// transférés en mêle plusieurs, chacun avec sa propre suite.
    Origine { ordinateur: String, journal: String },
}

/// Les caractères gardés d'un nom d'ordinateur ou de journal dans `Numerotation::Origine` : un vrai nom en a moins
/// de 256 (un nom DNS complet 253), un nom démesuré ne fait pas grossir le bilan.
pub(crate) const CLE_MAX: usize = 256;

/// Des numéros qui manquent, de `de` à `a` compris.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Trou {
    pub de: u64,
    pub a: u64,
    pub nature: Nature,
    /// La date de l'enregistrement présent juste avant (le plus grand numéro sous `de`), s'il y en a un et qu'elle
    /// est lisible.
    pub avant: Option<DateTime<Utc>>,
    /// La date de l'enregistrement présent juste après (le plus petit numéro au-dessus de `a`).
    pub apres: Option<DateTime<Utc>>,
}

impl Trou {
    /// Le nombre de numéros qui manquent.
    pub(crate) fn nombre(&self) -> u64 {
        (self.a - self.de).saturating_add(1)
    }
}

/// La suite des numéros d'un journal et ses trous.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Suite {
    pub numerotation: Numerotation,
    /// Le plus petit et le plus grand numéro présents, réclamés par un morceau lu, ou attendus d'après l'en-tête
    /// du fichier ; rien pour une suite vide.
    pub premier: Option<u64>,
    pub dernier: Option<u64>,
    /// Numéros distincts présents.
    pub presents: u64,
    /// Numéros vus plus d'une fois (au-delà de la première) : jamais écrits ainsi par Windows dans un même journal.
    pub doublons: u64,
    /// Morceaux lus à l'en-tête incohérent (`RecapMorceau::incoherent`), et un prochain numéro annoncé par
    /// l'en-tête du fichier qui ne dépasse pas le plus grand présent : un fichier réécrit.
    pub incoherences: u64,
    /// Les trous, dans l'ordre des numéros, au plus `max_trous`.
    pub trous: Vec<Trou>,
    /// Trous au-delà de `max_trous`, comptés sans être gardés.
    pub trous_au_dela: u64,
    /// Numéros présents seulement par un enregistrement d'un morceau non vérifié : la suite n'est alors pas
    /// prouvée sur eux (voir `juger`). Zéro pour une suite entièrement vérifiée.
    pub non_verifies: u64,
}

/// Un numéro présent, sa date, le rang du morceau qui le porte (rien hors d'un fichier), et s'il vient d'un
/// morceau vérifié (`Enregistrement::verifie`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Present {
    pub numero: u64,
    pub date: Option<DateTime<Utc>>,
    pub morceau: Option<u64>,
    pub verifie: bool,
}

/// Ce que l'on sait du journal autour de ses numéros.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Contexte<'a> {
    /// Les morceaux du fichier (vide pour la source vivante et pour les EventRecordID d'origine).
    pub morceaux: &'a [RecapMorceau],
    /// La nature d'un trou qu'aucun morceau ne réclame et que les pertes ne couvrent pas.
    pub entre_morceaux: Nature,
    /// Ce que la lecture a perdu sans savoir où : pour chaque perte, le plus de numéros contigus qu'elle peut
    /// cacher (un morceau écarté sans plage connue, un morceau au-delà des bornes, un événement rendu sans son
    /// numéro : 1).
    pub pertes: &'a [u64],
    /// Le prochain numéro qu'annonce l'en-tête d'un fichier fermé proprement : ce qui manque entre le plus grand
    /// présent et lui est un trou (les derniers enregistrements ôtés).
    pub prochain: Option<u64>,
    /// Le prochain numéro peut retarder sur les présents (fichier sale) sans que l'en-tête soit incohérent.
    pub prochain_peut_retarder: bool,
    /// Le plus d'enregistrements que le fichier peut porter (ses morceaux, pleins) : quand aucun numéro n'est
    /// connu mais que l'en-tête en attend, le plus ancien possible est `prochain - capacite`.
    pub capacite: u64,
}

impl Contexte<'_> {
    /// Sans morceaux, sans pertes, sans en-tête : la source vivante ou les EventRecordID d'origine.
    pub(crate) fn nu(entre_morceaux: Nature) -> Contexte<'static> {
        Contexte {
            morceaux: &[],
            entre_morceaux,
            pertes: &[],
            prochain: None,
            prochain_peut_retarder: false,
            capacite: 0,
        }
    }
}

/// D'où relève un numéro manquant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Classe {
    /// Réclamé par le morceau lu de cet indice (dans `Contexte::morceaux`).
    Morceau(usize),
    /// Dans la plage qu'annonce un morceau écarté.
    Ecarte,
    /// Entre deux morceaux.
    Libre,
}

/// La plage qu'un morceau lu réclame : son annonce et l'étendue de ses propres enregistrements, ensemble.
fn etendues(presents: &[Present], morceaux: &[RecapMorceau]) -> Vec<Option<(u64, u64)>> {
    let mut rang_vers_indice: HashMap<u64, usize> = HashMap::new();
    for (i, m) in morceaux.iter().enumerate() {
        if m.etat == EtatMorceau::Lu {
            rang_vers_indice.entry(m.rang).or_insert(i);
        }
    }
    let mut sortie: Vec<Option<(u64, u64)>> = morceaux
        .iter()
        .map(|m| if m.etat == EtatMorceau::Lu { m.annonce } else { None })
        .collect();
    for p in presents.iter().filter(|p| p.verifie) {
        let Some(&i) = p.morceau.and_then(|r| rang_vers_indice.get(&r)) else {
            continue;
        };
        sortie[i] = Some(match sortie[i] {
            Some((a, b)) => (a.min(p.numero), b.max(p.numero)),
            None => (p.numero, p.numero),
        });
    }
    sortie
}

/// Ce qu'un morceau non vérifié couvre : sa plage annoncée quand son en-tête est juste (bornée à ce qu'un morceau
/// peut porter) ; sinon, les séries de ses numéros relus dont les écarts tiennent dans ce qu'il a perdu (ses
/// passages abîmés, `RecapMorceau::non_rendus`), jamais de son plus petit à son plus grand numéro : deux numéros
/// lointains d'un faux morceau ne couvrent pas tout ce qui les sépare. Un numéro manquant qui y tombe est peut-être
/// un de ses enregistrements illisibles : `Illisible`, comme dans un morceau écarté.
fn zones_non_verifiees(presents: &[Present], morceaux: &[RecapMorceau]) -> Vec<(u64, u64)> {
    let mut sortie: Vec<(u64, u64)> = Vec::new();
    let mut sans_annonce: HashMap<u64, (u64, Vec<u64>)> = HashMap::new();
    for m in morceaux.iter().filter(|m| m.etat == EtatMorceau::NonVerifie) {
        match m.annonce {
            Some(a) => sortie.push(a),
            None => {
                sans_annonce.entry(m.rang).or_insert((m.non_rendus, Vec::new()));
            }
        }
    }
    for p in presents.iter().filter(|p| !p.verifie) {
        if let Some((_, v)) = p.morceau.and_then(|r| sans_annonce.get_mut(&r)) {
            v.push(p.numero);
        }
    }
    for (perdus, mut numeros) in sans_annonce.into_values() {
        numeros.sort_unstable();
        let mut serie: Option<(u64, u64)> = None;
        for n in numeros {
            serie = match serie {
                Some((a, b)) if n == b || n - b - 1 <= perdus => Some((a, n)),
                Some(z) => {
                    sortie.push(z);
                    Some((n, n))
                }
                None => Some((n, n)),
            };
        }
        sortie.extend(serie);
    }
    sortie.sort_unstable();
    sortie
}

/// Le début de la suite reculé d'une zone non vérifiée à l'autre tant que chacune rejoint le début courant. Les
/// zones prises de la fin la plus haute à la plus basse : une zone qui ne rejoint pas le début n'est rejointe par
/// aucune des suivantes, qui finissent plus bas.
fn debut_rejoint(mut lo: u64, zones: &[(u64, u64)]) -> u64 {
    let mut par_fin: Vec<(u64, u64)> = zones.to_vec();
    par_fin.sort_unstable_by_key(|z| std::cmp::Reverse(z.1));
    for (a, b) in par_fin {
        if b.saturating_add(1) < lo {
            break;
        }
        lo = lo.min(a);
    }
    lo
}

/// Des paliers : chaque palier vaut de son début jusqu'au début du suivant ; avant le premier, rien ne réclame.
/// Pour chacun, le morceau lu qui réclame ses numéros (celui dont l'étendue commence le plus bas, puis le premier
/// rang) et s'il tombe dans l'annonce d'un morceau écarté.
fn paliers(
    etendues: &[Option<(u64, u64)>],
    morceaux: &[RecapMorceau],
    zones_nv: &[(u64, u64)],
) -> Vec<(u64, Option<usize>, bool)> {
    // (numéro, +1 entrée / -1 sortie, Some(indice) d'un lu ou None d'un écarté, début de l'étendue)
    let mut bords: Vec<(u64, i8, Option<usize>, u64)> = Vec::new();
    for (i, e) in etendues.iter().enumerate() {
        if let Some((p, d)) = *e {
            bords.push((p, 1, Some(i), p));
            if let Some(fin) = d.checked_add(1) {
                bords.push((fin, -1, Some(i), p));
            }
        }
    }
    let annonces_ecartees = morceaux
        .iter()
        .filter(|m| m.etat == EtatMorceau::Ecarte)
        .filter_map(|m| m.annonce);
    for (p, d) in annonces_ecartees.chain(zones_nv.iter().copied()) {
        bords.push((p, 1, None, p));
        if let Some(fin) = d.checked_add(1) {
            bords.push((fin, -1, None, p));
        }
    }
    bords.sort_unstable_by_key(|b| b.0);
    let mut actifs: BTreeSet<(u64, u64, usize)> = BTreeSet::new();
    let mut ecartes = 0i64;
    let mut sortie = Vec::new();
    let mut i = 0;
    while i < bords.len() {
        let pos = bords[i].0;
        while i < bords.len() && bords[i].0 == pos {
            let (_, sens, lu, debut) = bords[i];
            match (lu, sens) {
                (Some(k), 1) => {
                    actifs.insert((debut, morceaux[k].rang, k));
                }
                (Some(k), _) => {
                    actifs.remove(&(debut, morceaux[k].rang, k));
                }
                (None, s) => ecartes += i64::from(s),
            }
            i += 1;
        }
        sortie.push((pos, actifs.first().map(|a| a.2), ecartes > 0));
    }
    sortie
}

/// Des pertes de capacités données couvrent-elles chaque plage de `tailles` ? Une perte ne couvre qu'une partie
/// contiguë d'une seule plage ; les plus grandes plages servies d'abord par les plus grandes pertes, une plage que
/// le reste ne couvre pas entière n'est pas couverte (et ne consomme rien). Rend, pour chaque plage, si elle l'est.
fn couvertes(tailles: &[u64], pertes: &[u64]) -> Vec<bool> {
    let mut ordre: Vec<usize> = (0..tailles.len()).collect();
    ordre.sort_unstable_by(|&a, &b| tailles[b].cmp(&tailles[a]));
    let mut triees: Vec<u64> = pertes.iter().copied().filter(|&c| c > 0).collect();
    triees.sort_unstable_by(|a, b| b.cmp(a));
    // Les sommes cumulées : les pertes prises dans l'ordre, la recherche de celles qui couvrent une plage se fait
    // par dichotomie (des milliers d'événements sans numéro font autant de pertes d'un numéro).
    let mut cumul = Vec::with_capacity(triees.len() + 1);
    cumul.push(0u64);
    for c in &triees {
        let dernier = *cumul.last().unwrap_or(&0);
        cumul.push(dernier.saturating_add(*c));
    }
    let mut debut = 0usize;
    let mut sortie = vec![false; tailles.len()];
    for i in ordre {
        let base = cumul[debut];
        // La plus petite fin `j` telle que les pertes de `debut` à `j` couvrent la plage.
        let j = debut + cumul[debut..].partition_point(|&s| s - base < tailles[i]);
        if j < cumul.len() {
            debut = j;
            sortie[i] = true;
        }
    }
    sortie
}

/// La suite des numéros `presents` (dans n'importe quel ordre, doublons compris) et ses trous, d'après le
/// `contexte`. Les numéros manquants sont ceux qui tombent entre le plus petit et le plus grand numéro présents,
/// réclamés par un morceau lu, ou attendus d'après l'en-tête du fichier : ce qui précède le plus petit (journal
/// tournant, effacé) n'en est pas un.
pub(crate) fn juger(
    numerotation: Numerotation,
    mut presents: Vec<Present>,
    contexte: &Contexte,
    max_trous: usize,
) -> Suite {
    let doublons = dedoublonner(&mut presents);
    let etendues = etendues(&presents, contexte.morceaux);
    let zones_nv = zones_non_verifiees(&presents, contexte.morceaux);
    ecarter_non_verifies(&mut presents, &etendues, &zones_nv);
    let non_verifies = presents.iter().filter(|p| !p.verifie).count() as u64;
    let (premier, dernier, incoherences) = bornes(&presents, &etendues, contexte);
    let mut suite = Suite {
        numerotation,
        premier,
        dernier,
        presents: presents.len() as u64,
        doublons,
        incoherences,
        trous: Vec::new(),
        trous_au_dela: 0,
        non_verifies,
    };
    let (Some(lo), Some(hi)) = (premier, dernier) else {
        return suite;
    };
    // Les numéros manquants, découpés aux paliers : (de, a, classe).
    let paliers = paliers(&etendues, contexte.morceaux, &zones_nv);
    let segments = segments_manquants(&presents, lo, hi, &paliers);
    ranger_les_trous(&mut suite, segments, contexte, max_trous);
    dater_les_trous(&mut suite, &presents);
    suite
}

/// Trie les présents par numéro et n'en garde qu'un par numéro (un numéro vu vérifié et non vérifié : le vérifié
/// l'emporte) ; rend le nombre de doublons retirés.
fn dedoublonner(presents: &mut Vec<Present>) -> u64 {
    presents.sort_unstable_by_key(|p| (p.numero, !p.verifie));
    let avant_dedoublonnage = presents.len();
    presents.dedup_by_key(|p| p.numero);
    (avant_dedoublonnage - presents.len()) as u64
}

/// Retire des présents les enregistrements non vérifiés qui ne prouvent rien : ceux qu'un morceau vérifié réclame, et
/// les vieux restes isolés d'avant la suite.
fn ecarter_non_verifies(presents: &mut Vec<Present>, etendues: &[Option<(u64, u64)>], zones_nv: &[(u64, u64)]) {
    // Un numéro qu'un morceau vérifié réclame ne se comble pas par un enregistrement non vérifié (un faux morceau au
    // CRC faux ajouté au fichier, qui porterait les numéros retirés) : il reste manquant. Ailleurs, l'enregistrement
    // non vérifié existe dans le fichier, son numéro est présent ; la suite le compte (`Suite::non_verifies`).
    let mut reclamees: Vec<(u64, u64)> = etendues.iter().flatten().copied().collect();
    reclamees.sort_unstable();
    let mut fusionnees: Vec<(u64, u64)> = Vec::new();
    for (a, b) in reclamees {
        match fusionnees.last_mut() {
            Some(d) if a <= d.1.saturating_add(1) => d.1 = d.1.max(b),
            _ => fusionnees.push((a, b)),
        }
    }
    let reclame = |n: u64| {
        let i = fusionnees.partition_point(|z| z.0 <= n);
        i > 0 && fusionnees[i - 1].1 >= n
    };
    presents.retain(|p| p.verifie || !reclame(p.numero));
    // Un enregistrement non vérifié plus ancien que tout ce qui est vérifié ne fait reculer le début de la suite que
    // si ce qu'il couvre rejoint ce début (le plus ancien morceau, déchiré) : un vieux reste isolé d'un tour précédent
    // ne fait pas de ce qui a été écrasé un trou.
    let plus_ancien_verifie = presents
        .iter()
        .filter(|p| p.verifie)
        .map(|p| p.numero)
        .chain(etendues.iter().flatten().map(|e| e.0))
        .min();
    if let Some(mut lo) = plus_ancien_verifie {
        lo = debut_rejoint(lo, zones_nv);
        presents.retain(|p| p.verifie || p.numero >= lo);
    }
}

/// Le premier et le dernier numéro de la suite (présents, réclamés par un morceau lu, ou attendus d'après l'en-tête
/// du fichier) et le nombre d'incohérences : morceaux à l'en-tête incohérent, prochain numéro annoncé en retard.
fn bornes(
    presents: &[Present],
    etendues: &[Option<(u64, u64)>],
    contexte: &Contexte,
) -> (Option<u64>, Option<u64>, u64) {
    let mut premier = presents
        .first()
        .map(|p| p.numero)
        .into_iter()
        .chain(etendues.iter().flatten().map(|e| e.0))
        .min();
    let mut dernier = presents
        .last()
        .map(|p| p.numero)
        .into_iter()
        .chain(etendues.iter().flatten().map(|e| e.1))
        .max();
    let mut incoherences = contexte.morceaux.iter().filter(|m| m.incoherent).count() as u64;
    if let Some(attendu) = contexte.prochain.and_then(|p| p.checked_sub(1)) {
        match dernier {
            Some(d) if attendu < d => incoherences += u64::from(!contexte.prochain_peut_retarder),
            Some(_) => dernier = Some(attendu),
            // Rien de présent ni de réclamé, et l'en-tête attend des enregistrements : tout ce que le fichier
            // pouvait porter manque.
            None if attendu >= 1 => {
                premier = Some(attendu.saturating_sub(contexte.capacite.saturating_sub(1)).max(1));
                dernier = Some(attendu);
            }
            None => {}
        }
    }
    (premier, dernier, incoherences)
}

/// Les numéros qui manquent entre `lo` et `hi`, découpés aux `paliers` : (de, a, classe), dans l'ordre.
fn segments_manquants(
    presents: &[Present],
    lo: u64,
    hi: u64,
    paliers: &[(u64, Option<usize>, bool)],
) -> Vec<(u64, u64, Classe)> {
    let mut segments: Vec<(u64, u64, Classe)> = Vec::new();
    let mut k = 0usize;
    let mut decouper = |de: u64, a: u64, segments: &mut Vec<(u64, u64, Classe)>| {
        let mut x = de;
        loop {
            while k < paliers.len() && paliers[k].0 <= x {
                k += 1;
            }
            let classe = match k.checked_sub(1).map(|j| paliers[j]) {
                Some((_, Some(m), _)) => Classe::Morceau(m),
                Some((_, None, true)) => Classe::Ecarte,
                _ => Classe::Libre,
            };
            let fin = match paliers.get(k) {
                Some(&(debut, _, _)) if debut <= a => debut - 1,
                _ => a,
            };
            match segments.last_mut() {
                Some(dernier) if dernier.2 == classe && dernier.1.checked_add(1) == Some(x) => dernier.1 = fin,
                _ => segments.push((x, fin, classe)),
            }
            if fin >= a {
                break;
            }
            x = fin + 1;
        }
    };
    // Le prochain numéro attendu ; rien quand le dernier possible est passé.
    let mut attendu = Some(lo);
    for p in presents {
        if let Some(x) = attendu
            && p.numero > x
        {
            decouper(x, p.numero - 1, &mut segments);
        }
        attendu = p.numero.checked_add(1);
    }
    if let Some(x) = attendu
        && x <= hi
    {
        decouper(x, hi, &mut segments);
    }
    segments
}

/// Chaque segment devient un trou de sa nature (ce qui manque à un morceau contre ce qu'il n'a pas rendu, les plages
/// libres contre les pertes) ; les segments voisins de même nature se rejoignent ; au-delà de `max_trous`, comptés.
fn ranger_les_trous(suite: &mut Suite, segments: Vec<(u64, u64, Classe)>, contexte: &Contexte, max_trous: usize) {
    let mut manque_au_morceau = vec![0u64; contexte.morceaux.len()];
    let mut libres = Vec::new();
    for &(de, a, classe) in &segments {
        let n = (a - de).saturating_add(1);
        match classe {
            Classe::Morceau(m) => manque_au_morceau[m] = manque_au_morceau[m].saturating_add(n),
            Classe::Libre => libres.push(n),
            Classe::Ecarte => {}
        }
    }
    let mut couverte = couvertes(&libres, contexte.pertes).into_iter();
    // Le dernier trou compté au-delà de la borne (nature, fin) : un segment qui le prolonge n'en fait pas un de plus.
    let mut dernier_au_dela: Option<(Nature, u64)> = None;
    for (de, a, classe) in segments {
        let nature = match classe {
            Classe::Morceau(m) if manque_au_morceau[m] <= contexte.morceaux[m].non_rendus => Nature::Illisible,
            Classe::Morceau(_) => Nature::Retires,
            Classe::Ecarte => Nature::Illisible,
            Classe::Libre if couverte.next().unwrap_or(false) => Nature::Illisible,
            Classe::Libre => contexte.entre_morceaux,
        };
        let gardes = suite.trous.len();
        match suite.trous.last_mut() {
            Some(t) if t.nature == nature && t.a.checked_add(1) == Some(de) => t.a = a,
            _ if gardes >= max_trous => {
                let prolonge = dernier_au_dela.is_some_and(|(n, fin)| n == nature && fin.checked_add(1) == Some(de));
                if !prolonge {
                    suite.trous_au_dela += 1;
                }
                dernier_au_dela = Some((nature, a));
            }
            _ => suite.trous.push(Trou {
                de,
                a,
                nature,
                avant: None,
                apres: None,
            }),
        }
    }
}

/// Les dates autour de chaque trou : celles des présents voisins.
fn dater_les_trous(suite: &mut Suite, presents: &[Present]) {
    for t in &mut suite.trous {
        let i = presents.partition_point(|p| p.numero < t.de);
        t.avant = i.checked_sub(1).and_then(|j| presents.get(j)).and_then(|p| p.date);
        t.apres = presents.get(i).and_then(|p| p.date);
    }
}

#[cfg(test)]
mod tests;

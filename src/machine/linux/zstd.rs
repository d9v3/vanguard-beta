//! Décodeur zstd (RFC 8878), écrit pour Vanguard : en lecture seule, tout en mémoire, sans dictionnaire. Ce que le
//! système range en zstd ne se lisait que par une commande (`pacman`, `journalctl`) : les bases des dépôts de pacman
//! (omarchy.db), les champs longs du journal de systemd, les modules du noyau (.ko.zst).
//!
//! Pourquoi pas une crate : le format est fermé et décrit en entier par la RFC (trames, blocs, Huffman, FSE), le
//! décodage seul tient en quelques centaines de lignes, et rien de ce qu'on lit n'a besoin de vitesse (une base de
//! quelques Mo, des champs de journal de quelques ko). Une donnée abîmée ou hostile rend `None`, jamais une panique :
//! chaque taille lue est bornée avant usage, et la somme de contrôle de la trame, quand elle est là, est vérifiée.

/// La signature d'une trame zstd, en tête de fichier.
pub(crate) const SIGNATURE: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

/// Un bloc ne dépasse jamais 128 Kio, décompressé (RFC 8878, 3.1.1.2.4).
const BLOC_MAX: usize = 128 << 10;

/// Une trame à sauter commence par l'une des 16 signatures 0x184D2A50 à 0x184D2A5F (RFC 8878, 3.1.2).
fn a_sauter(magique: u64) -> bool {
    magique & 0xffff_fff0 == 0x184d_2a50
}

/// Les octets commencent-ils comme un flux zstd : une trame, ou une trame à sauter (la RFC les permet partout, en
/// tête comprise ; pzstd en écrit une en tête).
pub(crate) fn est_zstd(octets: &[u8]) -> bool {
    octets.starts_with(&SIGNATURE) || octets.get(..4).is_some_and(|m| a_sauter(le(m)))
}

/// Le contenu décompressé de toutes les trames qui se suivent dans `entree` (le programme zstd les met bout à bout),
/// les trames à sauter ignorées, où qu'elles soient. `None` si ce n'est pas du zstd (rien, comme pour `zstd -d`, est
/// une fin inattendue), si c'est abîmé, si une trame demande un dictionnaire ou si le résultat dépasserait `max`
/// octets (une bombe de décompression s'arrête là).
pub(crate) fn decompresser(entree: &[u8], max: usize) -> Option<Vec<u8>> {
    if !est_zstd(entree) {
        return None;
    }
    let mut sortie = Vec::new();
    let mut reste = entree;
    while !reste.is_empty() {
        let magique = le(reste.get(..4)?);
        let lus = if a_sauter(magique) {
            // Trame à sauter : 4 octets de taille, puis ce que le programme qui l'a écrite y a mis.
            8usize.checked_add(usize::try_from(le(reste.get(4..8)?)).ok()?)?
        } else if reste.starts_with(&SIGNATURE) {
            trame(reste, &mut sortie, max)?
        } else {
            return None;
        };
        reste = reste.get(lus..)?;
    }
    Some(sortie)
}

/// Une trame (RFC 8878, 3.1.1) ajoutée à `sortie` ; rend le nombre d'octets lus dans `entree`.
fn trame(entree: &[u8], sortie: &mut Vec<u8>, max: usize) -> Option<usize> {
    let descripteur = *entree.get(4)?;
    let segment_unique = descripteur & 0x20 != 0;
    let controle = descripteur & 0x04 != 0;
    // Le bit réservé doit valoir zéro : sinon, c'est une version du format qu'on ne connaît pas.
    if descripteur & 0x08 != 0 {
        return None;
    }
    // La taille de la fenêtre ne sert qu'à qui décode en flux : ici, tout reste en mémoire.
    let mut i = if segment_unique { 5 } else { 6 };
    let octets_dico = match descripteur & 3 {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 4,
    };
    if le(entree.get(i..i + octets_dico)?) != 0 {
        return None;
    }
    i += octets_dico;
    let octets_taille = match descripteur >> 6 {
        0 => usize::from(segment_unique),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let taille_annoncee = match octets_taille {
        0 => None,
        2 => Some(le(entree.get(i..i + 2)?) + 256),
        n => Some(le(entree.get(i..i + n)?)),
    };
    i += octets_taille;

    let debut = sortie.len();
    let mut etat = Etat::default();
    loop {
        let entete = le(entree.get(i..i + 3)?);
        i += 3;
        let taille = usize::try_from(entete >> 3).ok()?;
        match (entete >> 1) & 3 {
            0 => {
                ajouter(sortie, entree.get(i..i + taille)?, max)?;
                i += taille;
            }
            1 => {
                if sortie.len().checked_add(taille)? > max {
                    return None;
                }
                sortie.resize(sortie.len() + taille, *entree.get(i)?);
                // Un bloc répété ne tient qu'un octet dans l'entrée, quelle que soit sa taille.
                i += 1;
            }
            2 => {
                if taille > BLOC_MAX {
                    return None;
                }
                bloc_compresse(entree.get(i..i + taille)?, &mut etat, sortie, debut, max)?;
                i += taille;
            }
            _ => return None,
        }
        if entete & 1 != 0 {
            break;
        }
    }
    if taille_annoncee.is_some_and(|t| u64::try_from(sortie.len() - debut).ok() != Some(t)) {
        return None;
    }
    if controle {
        if xxh64(sortie.get(debut..)?, 0) & 0xffff_ffff != le(entree.get(i..i + 4)?) {
            return None;
        }
        i += 4;
    }
    Some(i)
}

/// Un entier non signé en petit-boutiste, de 0 à 8 octets.
fn le(octets: &[u8]) -> u64 {
    octets.iter().take(8).rev().fold(0, |v, &o| (v << 8) | u64::from(o))
}

fn ajouter(sortie: &mut Vec<u8>, octets: &[u8], max: usize) -> Option<()> {
    if sortie.len().checked_add(octets.len())? > max {
        return None;
    }
    sortie.extend_from_slice(octets);
    Some(())
}

/// Ce qu'un bloc laisse au suivant dans la même trame : la table de Huffman (littéraux « sans arbre »), les trois
/// tables des séquences (mode « répéter ») et les trois derniers décalages.
struct Etat {
    huffman: Option<TableHuffman>,
    tables: [Option<TableFse>; 3],
    recents: [u64; 3],
}

impl Default for Etat {
    fn default() -> Self {
        // Les décalages de départ de la RFC (3.1.2.5).
        Etat {
            huffman: None,
            tables: [None, None, None],
            recents: [1, 4, 8],
        }
    }
}

/// Une séquence : copier `litteraux` octets des littéraux, puis `copie` octets pris plus tôt dans la sortie.
struct Sequence {
    litteraux: u64,
    copie: u64,
    decalage: u64,
}

/// Un bloc compressé : les littéraux, puis les séquences qui les assemblent.
fn bloc_compresse(bloc: &[u8], etat: &mut Etat, sortie: &mut Vec<u8>, debut: usize, max: usize) -> Option<()> {
    let (litteraux, lus) = litteraux(bloc, &mut etat.huffman)?;
    let sequences = sequences(bloc.get(lus..)?, &mut etat.tables)?;
    let mut pos = 0usize;
    for s in sequences {
        let fin = pos.checked_add(usize::try_from(s.litteraux).ok()?)?;
        ajouter(sortie, litteraux.get(pos..fin)?, max)?;
        pos = fin;
        let recul = usize::try_from(decalage(&s, &mut etat.recents)?).ok()?;
        // Pas de dictionnaire : une copie ne remonte pas avant le début de la trame.
        if recul == 0 || recul > sortie.len() - debut {
            return None;
        }
        let longueur = usize::try_from(s.copie).ok()?;
        if sortie.len().checked_add(longueur)? > max {
            return None;
        }
        let depart = sortie.len() - recul;
        if recul >= longueur {
            sortie.extend_from_within(depart..depart + longueur);
        } else {
            // La copie recouvre ce qu'elle écrit (un motif qui se répète) : octet par octet.
            for k in 0..longueur {
                let o = *sortie.get(depart + k)?;
                sortie.push(o);
            }
        }
    }
    ajouter(sortie, litteraux.get(pos..)?, max)
}

/// Le décalage réel d'une séquence, et la mise à jour des trois derniers (RFC 8878, 3.1.2.5).
fn decalage(s: &Sequence, recents: &mut [u64; 3]) -> Option<u64> {
    let [r0, r1, r2] = *recents;
    if s.decalage > 3 {
        let d = s.decalage - 3;
        *recents = [d, r0, r1];
        return Some(d);
    }
    // Sans littéral avant la copie, « le dernier décalage » ne servirait à rien (la séquence d'avant aurait été
    // prolongée) : les codes se décalent d'un cran.
    let rang = if s.litteraux == 0 { s.decalage } else { s.decalage - 1 };
    match rang {
        0 => Some(r0),
        1 => {
            *recents = [r1, r0, r2];
            Some(r1)
        }
        2 => {
            *recents = [r2, r0, r1];
            Some(r2)
        }
        _ => {
            let d = r0.checked_sub(1).filter(|&d| d > 0)?;
            *recents = [d, r0, r1];
            Some(d)
        }
    }
}

// --- Lecture des bits ---

/// Jusqu'à 57 bits pris à la position `debut` (en bits, petit-boutiste) ; zéro au-delà de la fin.
fn bits(octets: &[u8], debut: usize, n: u32) -> u64 {
    if n == 0 {
        return 0;
    }
    let premier = debut / 8;
    let mut v = 0u64;
    for k in 0..8 {
        v |= u64::from(octets.get(premier + k).copied().unwrap_or(0)) << (8 * k);
    }
    (v >> (debut % 8)) & ((1u64 << n) - 1)
}

/// Un flux lu vers l'avant, bit par bit (les descriptions de tables FSE).
struct Avant<'a> {
    octets: &'a [u8],
    bit: usize,
}

impl Avant<'_> {
    fn lire(&mut self, n: u32) -> Option<u64> {
        let fin = self.bit.checked_add(n as usize)?;
        if fin > self.octets.len() * 8 {
            return None;
        }
        let v = bits(self.octets, self.bit, n);
        self.bit = fin;
        Some(v)
    }
}

/// Un flux lu à l'envers (Huffman, séquences) : le dernier octet porte un bit de fin, au-dessus duquel il n'y a que
/// des zéros ; on lit ensuite vers le début. Au-delà du début, la lecture rend des zéros et note le débordement,
/// qui marque la fin des poids de Huffman.
struct Arriere<'a> {
    octets: &'a [u8],
    restant: usize,
    deborde: bool,
}

impl<'a> Arriere<'a> {
    fn new(octets: &'a [u8]) -> Option<Self> {
        let dernier = *octets.last()?;
        if dernier == 0 {
            return None;
        }
        let restant = octets.len() * 8 - dernier.leading_zeros() as usize - 1;
        Some(Arriere {
            octets,
            restant,
            deborde: false,
        })
    }

    fn regarder(&self, n: u32) -> u64 {
        match u32::try_from(self.restant) {
            Ok(r) if r < n => bits(self.octets, 0, r) << (n - r),
            _ => bits(self.octets, self.restant - n as usize, n),
        }
    }

    fn avancer(&mut self, n: u32) {
        let n = n as usize;
        if n > self.restant {
            self.deborde = true;
            self.restant = 0;
        } else {
            self.restant -= n;
        }
    }

    fn lire(&mut self, n: u32) -> u64 {
        let v = self.regarder(n);
        self.avancer(n);
        v
    }

    /// Tout lu, au bit près : un flux valide n'a ni bit en trop ni bit manquant.
    fn fini(&self) -> bool {
        self.restant == 0 && !self.deborde
    }
}

/// L'indice du bit de poids fort (log2 arrondi en dessous). Zéro pour zéro, qui n'arrive que d'une table abîmée :
/// la vérification qui suit la refuse, sans panique.
fn bit_fort(x: u32) -> u32 {
    x.checked_ilog2().unwrap_or(0)
}

// --- FSE (RFC 8878, 4.1) ---

/// Une table de décodage FSE : pour chaque état, le symbole, les bits à lire et la base de l'état suivant.
#[derive(Clone)]
struct TableFse {
    log: u32,
    cases: Vec<(u8, u8, u16)>,
}

impl TableFse {
    /// Un seul symbole, sans aucun bit à lire (mode RLE des séquences).
    fn unique(symbole: u8) -> Self {
        TableFse {
            log: 0,
            cases: vec![(symbole, 0, 0)],
        }
    }

    /// Les probabilités normalisées (-1 : « moins de 1 ») vers la table, réparties comme le veut la RFC.
    fn new(probas: &[i16], log: u32) -> Option<Self> {
        let taille = 1usize << log;
        let mut symboles = vec![0u8; taille];
        let mut suivant = vec![0u32; probas.len()];
        // Les symboles « moins de 1 » prennent une case chacun, depuis la fin de la table.
        let mut haut = taille;
        for (s, &p) in probas.iter().enumerate() {
            if p == -1 {
                haut = haut.checked_sub(1)?;
                *symboles.get_mut(haut)? = u8::try_from(s).ok()?;
                *suivant.get_mut(s)? = 1;
            }
        }
        let pas = (taille >> 1) + (taille >> 3) + 3;
        let masque = taille - 1;
        let mut pos = 0usize;
        for (s, &p) in probas.iter().enumerate() {
            if p <= 0 {
                continue;
            }
            *suivant.get_mut(s)? = u32::try_from(p).ok()?;
            for _ in 0..p {
                *symboles.get_mut(pos)? = u8::try_from(s).ok()?;
                loop {
                    pos = (pos + pas) & masque;
                    if pos < haut {
                        break;
                    }
                }
            }
        }
        if pos != 0 {
            return None;
        }
        let mut cases = Vec::with_capacity(taille);
        for &s in &symboles {
            let compte = suivant.get_mut(usize::from(s))?;
            let etat = *compte;
            *compte += 1;
            let nb = log.checked_sub(bit_fort(etat))?;
            let base = (u64::from(etat) << nb).checked_sub(taille as u64)?;
            cases.push((s, u8::try_from(nb).ok()?, u16::try_from(base).ok()?));
        }
        Some(TableFse { log, cases })
    }
}

/// Un état de décodage FSE sur une table.
struct EtatFse<'t> {
    table: &'t TableFse,
    etat: usize,
}

impl<'t> EtatFse<'t> {
    fn new(table: &'t TableFse, flux: &mut Arriere) -> Self {
        // Lu sur `log` bits : toujours dans la table.
        let etat = usize::try_from(flux.lire(table.log)).unwrap_or(0);
        EtatFse { table, etat }
    }

    // L'état reste dans la table par construction (lu sur `log` bits, puis masqué) ; `None` s'il en sortait.
    fn symbole(&self) -> Option<u8> {
        self.table.cases.get(self.etat).map(|c| c.0)
    }

    fn suivant(&mut self, flux: &mut Arriere) -> Option<()> {
        let &(_, nb, base) = self.table.cases.get(self.etat)?;
        // base + bits lus reste sous la taille de la table, par construction.
        self.etat =
            (usize::from(base) + usize::try_from(flux.lire(u32::from(nb))).unwrap_or(0)) & (self.table.cases.len() - 1);
        Some(())
    }
}

/// La description d'une table FSE en tête d'un flux (RFC 8878, 4.1.1) : les probabilités, la précision et le
/// nombre d'octets lus.
fn lire_probas(octets: &[u8], max_symbole: usize, max_log: u32) -> Option<(Vec<i16>, u32, usize)> {
    let mut flux = Avant { octets, bit: 0 };
    let log = u32::try_from(flux.lire(4)?).ok()? + 5;
    if log > max_log {
        return None;
    }
    let mut restant: i32 = 1 << log;
    let mut probas: Vec<i16> = Vec::new();
    while restant > 0 {
        if probas.len() > max_symbole {
            return None;
        }
        // Les valeurs possibles vont de 0 à restant + 1 ; les plus petites s'écrivent avec un bit de moins.
        let possibles = u32::try_from(restant + 1).ok()?;
        let n = bit_fort(possibles) + 1;
        let mut v = u32::try_from(flux.lire(n)?).ok()?;
        let bas = (1u32 << (n - 1)) - 1;
        let seuil = ((1u32 << n) - 1).checked_sub(possibles)?;
        if v & bas < seuil {
            v &= bas;
            flux.bit -= 1;
        } else if v > bas {
            v -= seuil;
        }
        let p = i16::try_from(v).ok()? - 1;
        restant -= i32::from(p.abs());
        probas.push(p);
        if p == 0 {
            // Les zéros qui suivent un zéro se comptent par paires de bits, 3 voulant dire « et encore ».
            loop {
                let repete = flux.lire(2)?;
                probas.extend(std::iter::repeat_n(0, usize::try_from(repete).ok()?));
                if repete != 3 {
                    break;
                }
            }
        }
    }
    if restant != 0 || probas.len() > max_symbole + 1 {
        return None;
    }
    Some((probas, log, flux.bit.div_ceil(8)))
}

// --- Huffman (RFC 8878, 4.2) ---

/// La table de décodage des littéraux : on regarde `max_bits` bits, la case donne le symbole et les bits à prendre.
#[derive(Clone)]
struct TableHuffman {
    max_bits: u32,
    cases: Vec<(u8, u8)>,
}

/// La description de l'arbre en tête des littéraux : la table et le nombre d'octets lus.
fn lire_huffman(octets: &[u8]) -> Option<(TableHuffman, usize)> {
    let entete = usize::from(*octets.first()?);
    let (poids, lus) = if entete < 128 {
        // Les poids compressés en FSE, sur `entete` octets.
        (poids_fse(octets.get(1..1 + entete)?)?, 1 + entete)
    } else {
        // Les poids en clair, quatre bits chacun, le premier dans la moitié haute.
        let n = entete - 127;
        let flux = octets.get(1..1 + n.div_ceil(2))?;
        let poids = flux.iter().flat_map(|&o| [o >> 4, o & 0xf]).take(n).collect();
        (poids, 1 + n.div_ceil(2))
    };
    Some((table_huffman(poids)?, lus))
}

/// Les poids codés en FSE : deux états entrelacés sur la même table, jusqu'au débordement du flux, après quoi
/// l'autre état donne encore son symbole.
fn poids_fse(octets: &[u8]) -> Option<Vec<u8>> {
    let (probas, log, lus) = lire_probas(octets, 255, 6)?;
    let table = TableFse::new(&probas, log)?;
    let mut flux = Arriere::new(octets.get(lus..)?)?;
    let mut un = EtatFse::new(&table, &mut flux);
    let mut deux = EtatFse::new(&table, &mut flux);
    let mut poids = Vec::new();
    // 255 poids au plus : le 256e symbole se déduit des autres.
    while poids.len() < 254 {
        poids.push(un.symbole()?);
        un.suivant(&mut flux)?;
        if flux.deborde {
            poids.push(deux.symbole()?);
            return Some(poids);
        }
        if poids.len() >= 254 {
            break;
        }
        poids.push(deux.symbole()?);
        deux.suivant(&mut flux)?;
        if flux.deborde {
            poids.push(un.symbole()?);
            return Some(poids);
        }
    }
    None
}

/// Les poids vers la table : le dernier symbole prend le poids qui complète la somme à une puissance de deux ; un
/// symbole de poids w occupe 2^(w-1) cases, les poids faibles (codes longs) d'abord, dans l'ordre des symboles.
fn table_huffman(mut poids: Vec<u8>) -> Option<TableHuffman> {
    if poids.iter().any(|&w| w > 11) {
        return None;
    }
    let somme: u32 = poids.iter().filter(|&&w| w > 0).map(|&w| 1u32 << (w - 1)).sum();
    if somme == 0 {
        return None;
    }
    let max_bits = bit_fort(somme) + 1;
    if max_bits > 11 {
        return None;
    }
    let reste = (1u32 << max_bits) - somme;
    if !reste.is_power_of_two() {
        return None;
    }
    poids.push(u8::try_from(bit_fort(reste) + 1).ok()?);
    let mut cases = Vec::with_capacity(1 << max_bits);
    for w in 1..=max_bits {
        for (s, _) in poids.iter().enumerate().filter(|&(_, &p)| u32::from(p) == w) {
            let nb = u8::try_from(max_bits + 1 - w).ok()?;
            let s = u8::try_from(s).ok()?;
            cases.extend(std::iter::repeat_n((s, nb), 1 << (w - 1)));
        }
    }
    (cases.len() == 1 << max_bits).then_some(TableHuffman { max_bits, cases })
}

/// Un flux de Huffman : exactement `n` symboles, et tout le flux lu.
fn huffman_flux(table: &TableHuffman, octets: &[u8], n: usize, sortie: &mut Vec<u8>) -> Option<()> {
    let mut flux = Arriere::new(octets)?;
    for _ in 0..n {
        let (s, nb) = *table.cases.get(usize::try_from(flux.regarder(table.max_bits)).ok()?)?;
        flux.avancer(u32::from(nb));
        sortie.push(s);
    }
    flux.fini().then_some(())
}

// --- Littéraux (RFC 8878, 3.1.1.3.1) ---

/// La section des littéraux d'un bloc : les octets, et ce qu'elle occupe dans le bloc.
fn litteraux(bloc: &[u8], huffman: &mut Option<TableHuffman>) -> Option<(Vec<u8>, usize)> {
    let b0 = *bloc.first()?;
    let genre = b0 & 3;
    let format = (b0 >> 2) & 3;
    if genre < 2 {
        // En clair ou répété : une taille sur 5, 12 ou 20 bits.
        let (taille, entete) = match format {
            0 | 2 => (usize::from(b0 >> 3), 1),
            1 => (usize::try_from(le(bloc.get(..2)?) >> 4).ok()?, 2),
            _ => (usize::try_from(le(bloc.get(..3)?) >> 4).ok()?, 3),
        };
        if genre == 0 {
            return Some((bloc.get(entete..entete + taille)?.to_vec(), entete + taille));
        }
        return Some((vec![*bloc.get(entete)?; taille], entete + 1));
    }
    // Compressés en Huffman : un flux ou quatre, les deux tailles sur 10, 14 ou 18 bits.
    let (quatre, entete, largeur) = match format {
        0 => (false, 3, 10),
        1 => (true, 3, 10),
        2 => (true, 4, 14),
        _ => (true, 5, 18),
    };
    let v = le(bloc.get(..entete)?) >> 4;
    let masque = (1u64 << largeur) - 1;
    let taille = usize::try_from(v & masque).ok()?;
    let compresse = usize::try_from((v >> largeur) & masque).ok()?;
    if taille > BLOC_MAX {
        return None;
    }
    let donnees = bloc.get(entete..entete + compresse)?;
    let arbre = if genre == 2 {
        let (table, lus) = lire_huffman(donnees)?;
        *huffman = Some(table);
        lus
    } else {
        // « Sans arbre » : la table du bloc d'avant.
        0
    };
    let table = huffman.as_ref()?;
    let flux = donnees.get(arbre..)?;
    let mut sortie = Vec::with_capacity(taille);
    if quatre {
        let t1 = usize::try_from(le(flux.get(..2)?)).ok()?;
        let t2 = usize::try_from(le(flux.get(2..4)?)).ok()?;
        let t3 = usize::try_from(le(flux.get(4..6)?)).ok()?;
        let corps = flux.get(6..)?;
        let fin3 = t1.checked_add(t2)?.checked_add(t3)?;
        let part = taille.div_ceil(4);
        let derniere = taille.checked_sub(3 * part)?;
        huffman_flux(table, corps.get(..t1)?, part, &mut sortie)?;
        huffman_flux(table, corps.get(t1..t1 + t2)?, part, &mut sortie)?;
        huffman_flux(table, corps.get(t1 + t2..fin3)?, part, &mut sortie)?;
        huffman_flux(table, corps.get(fin3..)?, derniere, &mut sortie)?;
    } else {
        huffman_flux(table, flux, taille, &mut sortie)?;
    }
    Some((sortie, entete + compresse))
}

// --- Séquences (RFC 8878, 3.1.1.3.2) ---

/// Bases et bits supplémentaires des codes de longueur de littéraux (0 à 35).
const LITTERAUX: [(u32, u32); 36] = [
    (0, 0),
    (1, 0),
    (2, 0),
    (3, 0),
    (4, 0),
    (5, 0),
    (6, 0),
    (7, 0),
    (8, 0),
    (9, 0),
    (10, 0),
    (11, 0),
    (12, 0),
    (13, 0),
    (14, 0),
    (15, 0),
    (16, 1),
    (18, 1),
    (20, 1),
    (22, 1),
    (24, 2),
    (28, 2),
    (32, 3),
    (40, 3),
    (48, 4),
    (64, 6),
    (128, 7),
    (256, 8),
    (512, 9),
    (1024, 10),
    (2048, 11),
    (4096, 12),
    (8192, 13),
    (16384, 14),
    (32768, 15),
    (65536, 16),
];

/// Bases et bits supplémentaires des codes de longueur de copie (0 à 52) ; une copie fait au moins 3 octets.
const COPIES: [(u32, u32); 53] = [
    (3, 0),
    (4, 0),
    (5, 0),
    (6, 0),
    (7, 0),
    (8, 0),
    (9, 0),
    (10, 0),
    (11, 0),
    (12, 0),
    (13, 0),
    (14, 0),
    (15, 0),
    (16, 0),
    (17, 0),
    (18, 0),
    (19, 0),
    (20, 0),
    (21, 0),
    (22, 0),
    (23, 0),
    (24, 0),
    (25, 0),
    (26, 0),
    (27, 0),
    (28, 0),
    (29, 0),
    (30, 0),
    (31, 0),
    (32, 0),
    (33, 0),
    (34, 0),
    (35, 1),
    (37, 1),
    (39, 1),
    (41, 1),
    (43, 2),
    (47, 2),
    (51, 3),
    (59, 3),
    (67, 4),
    (83, 4),
    (99, 5),
    (131, 7),
    (259, 8),
    (515, 9),
    (1027, 10),
    (2051, 11),
    (4099, 12),
    (8195, 13),
    (16387, 14),
    (32771, 15),
    (65539, 16),
];

/// Les distributions prédéfinies (RFC 8878, 3.1.1.3.2.2) : longueurs de littéraux, décalages, longueurs de copie.
const PREDEFINI_LITTERAUX: [i16; 36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1,
];
const PREDEFINI_DECALAGES: [i16; 29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];
const PREDEFINI_COPIES: [i16; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];

/// Les séquences d'un bloc. `tables` : longueurs de littéraux, décalages, longueurs de copie, gardées pour les blocs
/// suivants de la trame.
fn sequences(octets: &[u8], tables: &mut [Option<TableFse>; 3]) -> Option<Vec<Sequence>> {
    let b0 = usize::from(*octets.first()?);
    let (nombre, mut i) = match b0 {
        0 => return Some(Vec::new()),
        1..128 => (b0, 1),
        128..255 => (((b0 - 128) << 8) + usize::from(*octets.get(1)?), 2),
        _ => (usize::try_from(le(octets.get(1..3)?)).ok()? + 0x7f00, 3),
    };
    let modes = *octets.get(i)?;
    i += 1;
    if modes & 3 != 0 {
        return None;
    }
    // L'ordre des descriptions dans le bloc : littéraux, décalages, copies.
    let sortes: [(u8, &[i16], u32, usize, u32); 3] = [
        (modes >> 6, &PREDEFINI_LITTERAUX, 6, 35, 9),
        ((modes >> 4) & 3, &PREDEFINI_DECALAGES, 5, 31, 8),
        ((modes >> 2) & 3, &PREDEFINI_COPIES, 6, 52, 9),
    ];
    for ((mode, predefini, log_predefini, max_symbole, max_log), table) in sortes.into_iter().zip(tables.iter_mut()) {
        *table = match mode {
            0 => Some(TableFse::new(predefini, log_predefini)?),
            1 => {
                let s = *octets.get(i)?;
                i += 1;
                if usize::from(s) > max_symbole {
                    return None;
                }
                Some(TableFse::unique(s))
            }
            2 => {
                let (probas, log, lus) = lire_probas(octets.get(i..)?, max_symbole, max_log)?;
                i += lus;
                Some(TableFse::new(&probas, log)?)
            }
            // « Répéter » : la table du bloc d'avant, qui doit exister.
            _ => Some(table.clone()?),
        };
    }
    let [Some(t_litteraux), Some(t_decalages), Some(t_copies)] = &*tables else {
        return None;
    };
    let mut flux = Arriere::new(octets.get(i..)?)?;
    let mut e_litteraux = EtatFse::new(t_litteraux, &mut flux);
    let mut e_decalages = EtatFse::new(t_decalages, &mut flux);
    let mut e_copies = EtatFse::new(t_copies, &mut flux);
    // Une séquence produit au moins 3 octets et un bloc en fait 128 Kio au plus : la borne évite une réservation
    // géante sur un nombre inventé.
    let mut sortie = Vec::with_capacity(nombre.min(BLOC_MAX / 3));
    for k in 0..nombre {
        let code_decalage = u32::from(e_decalages.symbole()?);
        let (base_copie, bits_copie) = *COPIES.get(usize::from(e_copies.symbole()?))?;
        let (base_litteraux, bits_litteraux) = *LITTERAUX.get(usize::from(e_litteraux.symbole()?))?;
        if code_decalage > 31 {
            return None;
        }
        // Les bits supplémentaires dans cet ordre : décalage, copie, littéraux.
        let decalage = (1u64 << code_decalage) + flux.lire(code_decalage);
        let copie = u64::from(base_copie) + flux.lire(bits_copie);
        let litteraux = u64::from(base_litteraux) + flux.lire(bits_litteraux);
        sortie.push(Sequence {
            litteraux,
            copie,
            decalage,
        });
        if k + 1 < nombre {
            // Et les états dans celui-ci : littéraux, copie, décalage.
            e_litteraux.suivant(&mut flux)?;
            e_copies.suivant(&mut flux)?;
            e_decalages.suivant(&mut flux)?;
        }
        if flux.deborde {
            return None;
        }
    }
    flux.fini().then_some(sortie)
}

// --- XXH64, la somme de contrôle des trames ---

const P1: u64 = 0x9e37_79b1_85eb_ca87;
const P2: u64 = 0xc2b2_ae3d_27d4_eb4f;
const P3: u64 = 0x1656_67b1_9e37_79f9;
const P4: u64 = 0x85eb_ca77_c2b2_ae63;
const P5: u64 = 0x27d4_eb2f_1656_67c5;

fn tour(acc: u64, entree: u64) -> u64 {
    acc.wrapping_add(entree.wrapping_mul(P2))
        .rotate_left(31)
        .wrapping_mul(P1)
}

fn fusion(acc: u64, v: u64) -> u64 {
    (acc ^ tour(0, v)).wrapping_mul(P1).wrapping_add(P4)
}

/// XXH64 (la somme de contrôle d'une trame en garde les 32 bits du bas).
fn xxh64(octets: &[u8], graine: u64) -> u64 {
    let mut reste = octets;
    let mut h = if octets.len() >= 32 {
        let mut v = [
            graine.wrapping_add(P1).wrapping_add(P2),
            graine.wrapping_add(P2),
            graine,
            graine.wrapping_sub(P1),
        ];
        while let Some((bloc, suite)) = reste.split_first_chunk::<32>() {
            for (acc, mot) in v.iter_mut().zip(bloc.as_chunks::<8>().0) {
                *acc = tour(*acc, le(mot));
            }
            reste = suite;
        }
        let mut h = v[0]
            .rotate_left(1)
            .wrapping_add(v[1].rotate_left(7))
            .wrapping_add(v[2].rotate_left(12))
            .wrapping_add(v[3].rotate_left(18));
        for acc in v {
            h = fusion(h, acc);
        }
        h
    } else {
        graine.wrapping_add(P5)
    };
    h = h.wrapping_add(octets.len() as u64);
    while let Some((mot, suite)) = reste.split_first_chunk::<8>() {
        h = (h ^ tour(0, le(mot))).rotate_left(27).wrapping_mul(P1).wrapping_add(P4);
        reste = suite;
    }
    if let Some((mot, suite)) = reste.split_first_chunk::<4>() {
        h = (h ^ le(mot).wrapping_mul(P1))
            .rotate_left(23)
            .wrapping_mul(P2)
            .wrapping_add(P3);
        reste = suite;
    }
    for &o in reste {
        h = (h ^ u64::from(o).wrapping_mul(P5)).rotate_left(11).wrapping_mul(P1);
    }
    h ^= h >> 33;
    h = h.wrapping_mul(P2);
    h ^= h >> 29;
    h = h.wrapping_mul(P3);
    h ^ (h >> 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOTS: [&str; 13] = [
        "pare-feu",
        "alice",
        "salon",
        "noyau",
        "journal",
        "paquet",
        "Vanguard",
        "réseau",
        "clé",
        "bilan",
        "sshd",
        "erreur",
        "démarrage",
    ];

    /// Le texte des vecteurs « court » et « long » : des mots dans un ordre qui revient vite.
    fn texte(n: usize) -> Vec<u8> {
        (0..n)
            .map(|i| MOTS[(i * 7 + i / 13) % MOTS.len()])
            .collect::<Vec<_>>()
            .join(" ")
            .into_bytes()
    }

    /// Le texte du vecteur « hasard » : des mots et des nombres tirés par un générateur congruentiel.
    fn hasard() -> Vec<u8> {
        let mut x: u64 = 1;
        let mut mots: Vec<String> = Vec::new();
        for _ in 0..700 {
            x = (x * 1_103_515_245 + 12_345) % (1 << 31);
            mots.push(MOTS[usize::try_from((x >> 16) % 13).unwrap()].to_string());
            if (x >> 8).is_multiple_of(5) {
                mots.push((x % 1000).to_string());
            }
        }
        mots.join(" ").into_bytes()
    }

    fn hexa(h: &str) -> Vec<u8> {
        (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
            .collect()
    }

    // Écrits par le programme zstd 1.5 (`zstd -19`, `zstd -1 --no-check`) à partir des textes ci-dessus. « long »
    // fait trois blocs (tables répétées d'un bloc à l'autre) ; « hasard », des littéraux en Huffman sur quatre flux
    // et des tables FSE décrites dans le bloc.
    const COURT_19: &str = concat!(
        "28b52ffd64b400150300c2051214c0ebfffafff36e4ab9dd714b5648b8febbda554fa4571ab6e16cb67b17ade491e55bf796",
        "dccd57cb5ab6747220bcdcd9d8d92a24ce9a5a785ad5380fa4f67219d2da975c00f7ba0700ae4282a775005448e0b7105e85",
        "042c4380d3070d665f33eb21",
    );
    const COURT_1: &str = concat!(
        "28b52ffd60b400750300c205131ab0271dcc6992a8a0b26db2642509468cd8b4db450ca967cc2302e5bdc21aa08bfe35a054",
        "88f01d7af0e7dfacdacf145808e7f09a30466b19029aa91ea25484264695571f94cef300e0f7080a00552890682188190754",
        "3020b91d90590c55cce09049c0b219387dd06006",
    );
    const LONG_19: &str = concat!(
        "28b52ffda4ca5d0400540400c2051214c0ebfffafff36e4ab9dd714b5648b8febbda554fa4571ab6e16cb67b17ade491e55b",
        "f796dccd57cb5ab6747220bcdcd9d8d92a24ce9a5a785ad5380fa4f67219d2da975c00f7ba19a8e0f7ff3b20c245f41810fe",
        "11e1a749fcd3ed6f44fbbc94fe5fc2db9fe2e8a4f2f22ad1770976ef98ef8ea27aa455bcda534e557faf64ac6070fa489302",
        "540000000100fdff0ffeb906023d0000000100c7dd0e8024184ee8",
    );
    const HASARD_19: &str = concat!(
        "28b52ffd646c149d2400469d481e90296dffbbffff3a5afbc53f6a3df0bff819eacf5db9b9b2bbc5bcbb6802520039003900",
        "dcbba7a6865606511ac769d082b19c879a4926cbe04753261c1e0f02731ac3e204ce4cca00b11c5a9c0521a046290014e634",
        "8869148651a839ca433261c87869390ba6612414c36198a3904c08d49c086311753b4eceea3e6a6726d7666da9e5e20b35af",
        "38ab3a71ed30cf8978ab4aeabbdee56eaafe1bb5979195fbae7dedcd3ba36eeadeef69898c76fab6c8787967ba76a8cfb577",
        "eaa2dece9ebfbd5cee271f59f26dfd754bad5f55e523decb35b6eb3a4bccbc6e43b63bfd9ebdfed665543d654abe7cfb21a6",
        "fd55d9fa3362759f2dd7972fb9aedb7cf5a53b357ffb0cfb5031319b2f957e2aeefb9e74170dc9d62aaf376b7bf3b2fa0cf3",
        "b84d1a81b0a8818a794aa569cf21080104812486547a1124208c38432891159424490a8d012da131bb66e40f25ca9134e083",
        "534b85d7015f10e9799ab17446daece722a86088b77e10929151192a456d269e4713a8a24665a47cdc79ade84115cb79c2e7",
        "4217d55a4ed5dfe1a5f2368d05f9850f77ef9550a8955798a129aabebe7de250c40d11c9bb18aebf618d361e282a8b9f30a1",
        "ea9112842bef6b52619714f001ee853130aad8013a5afbd268e9ca2ddc2573d112ea1692255c62d585032667276b1e548256",
        "bea9c87630c2fdf63c583e583b1370e6a592f66329b0df30eb0e916f4f85aa830def6bf2b4c0d3c8f674940802bae424587f",
        "341242917064d7acc943274a3211d60e5408cfbd0b958e4daf9bcaf7c677377aa17155197f037257517c431623409bfb1cc9",
        "e2e5c6746126cd04524e8d5314105b84bdd1f5f6223c3df50e05ae9767d791428a5910ab7e16adcfd6c460e0829cf689cd5e",
        "56a25085e2c1134cea806bd882b50362ce455e518fd510f5cfe3217647b6cf403a850984d6958d99a38dbe494980e9875eb5",
        "cdd80134fbf71b8ccc24ac9304eec1cbd70b58d06d774cfe3da9160678486fff34d6c9512370ae6ea7c81680d88cc884c882",
        "4d88a599294d5228b03c461103a089d2856cf8a5a8296b84849f0a564e83a0723a34c19049b3048783543f97002bd0b4aea2",
        "5d6d1cec291dce8b36440c42171f9f72734fb1c77810305d40767687625ec4ae11fcf7744f4f658cfd71ccb3ac3e570ded16",
        "e5f99b5c095ae5747840d82fae7da04f3f5d0d909822d53992e22f049296c8660a35a6ab1f2aa50d399b96f3364825db61d6",
        "8600666bbe6d4269adf95865057d6c64e010c4e5a6df6347b49c195c1218597c529c2893c818184a20b508b75f6ade700c3e",
        "4479969018095e45fd700c80fc04e23de4b22f4449827f205e0c91afca2cd2c5644f26d909479f649b82cde2672706728aba",
        "965dfc9643d5d4dc0868d1424abe82d9650741b2b12de5d2197379cc9ef4d8a78ed02868761480f1eea81b936c165f28fdf4",
        "8b48926fb761671cecfd3114855349d5ce18600cacaafe18c42800dd2d9c22225bda0d9231018cc265e026637a3760fb2348",
        "610ac753ea0a2adaf02517a3160f27015882851d212196323b0d79c0b2edab45bb84a9b32a44393ef7b5f0e3bbea15e92430",
        "02be9b1eabc3f49a5103db7a056bad1c2f21b6a44f8f92fa47cd4d56ccb06a38a8be05",
    );

    #[test]
    fn vecteurs_du_programme_zstd() {
        assert_eq!(decompresser(&hexa(COURT_19), 1 << 20), Some(texte(60)));
        assert_eq!(decompresser(&hexa(COURT_1), 1 << 20), Some(texte(60)));
        assert_eq!(decompresser(&hexa(LONG_19), 1 << 20), Some(texte(40_000)));
        assert_eq!(decompresser(&hexa(HASARD_19), 1 << 20), Some(hasard()));
    }

    #[test]
    fn xxh64_des_vecteurs_connus() {
        assert_eq!(xxh64(b"", 0), 0xef46_db37_51d8_e999);
        assert_eq!(xxh64(b"abc", 0), 0x44bc_2cf5_ad77_0999);
    }

    /// Une trame à la main : en-tête (segment unique, taille sur un octet, somme de contrôle), puis les blocs.
    fn trame_a_la_main(blocs: &[(u8, &[u8], usize)], taille: u8, contenu: &[u8]) -> Vec<u8> {
        let mut t = SIGNATURE.to_vec();
        t.extend([0x24, taille]);
        for (k, (sorte, octets, n)) in blocs.iter().enumerate() {
            let dernier = u32::from(k + 1 == blocs.len());
            let entete = dernier | (u32::from(*sorte) << 1) | (u32::try_from(*n).unwrap() << 3);
            t.extend(&entete.to_le_bytes()[..3]);
            t.extend(*octets);
        }
        t.extend(&u32::try_from(xxh64(contenu, 0) & 0xffff_ffff).unwrap().to_le_bytes());
        t
    }

    #[test]
    fn blocs_en_clair_et_repetes() {
        let t = trame_a_la_main(&[(0, b"salon ", 6), (1, b"z", 4)], 10, b"salon zzzz");
        assert_eq!(decompresser(&t, 100).as_deref(), Some(&b"salon zzzz"[..]));
        // Deux trames de suite, une trame à sauter entre elles.
        let mut deux = t.clone();
        deux.extend([0x5a, 0x2a, 0x4d, 0x18, 2, 0, 0, 0, 0xaa, 0xbb]);
        deux.extend(&t);
        assert_eq!(decompresser(&deux, 100).as_deref(), Some(&b"salon zzzzsalon zzzz"[..]));
        // Une trame à sauter en tête (pzstd en écrit une), vide ou non : `zstd -dc` la saute, ici aussi. Seule, elle
        // ne contient rien ; rien du tout n'est pas du zstd.
        let mut en_tete = vec![0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0];
        en_tete.extend(&t);
        assert!(est_zstd(&en_tete));
        assert_eq!(decompresser(&en_tete, 100).as_deref(), Some(&b"salon zzzz"[..]));
        let mut pleine = vec![0x5f, 0x2a, 0x4d, 0x18, 3, 0, 0, 0, 1, 2, 3];
        pleine.extend(&t);
        assert_eq!(decompresser(&pleine, 100).as_deref(), Some(&b"salon zzzz"[..]));
        assert_eq!(decompresser(&en_tete[..8], 100), Some(Vec::new()));
        assert_eq!(decompresser(&en_tete[..7], 100), None);
        assert_eq!(decompresser(&pleine[..10], 100), None);
        assert_eq!(decompresser(b"", 100), None);
        assert!(!est_zstd(b"\x50\x2a\x4d\x19\0\0\0\0"));
        // Au-delà de la borne, rien : une bombe de décompression s'arrête avant d'occuper la mémoire.
        assert_eq!(decompresser(&t, 9), None);
        // Somme de contrôle fausse, taille annoncée fausse, bit réservé, dictionnaire, signature.
        let mut faux = t.clone();
        *faux.last_mut().unwrap() ^= 1;
        assert_eq!(decompresser(&faux, 100), None);
        assert_eq!(
            decompresser(&trame_a_la_main(&[(0, b"salon ", 6)], 7, b"salon "), 100),
            None
        );
        let mut reserve = t.clone();
        reserve[4] |= 0x08;
        assert_eq!(decompresser(&reserve, 100), None);
        let mut dico = SIGNATURE.to_vec();
        dico.extend([0x21, 7, 6, 1, 0, 0]);
        assert_eq!(decompresser(&dico, 100), None);
        assert_eq!(decompresser(b"pas du zstd", 100), None);
        // Un reste qui n'est ni une trame ni une trame à sauter.
        let mut reste = t;
        reste.extend(b"??");
        assert_eq!(decompresser(&reste, 100), None);
    }

    /// Chaque octet changé, chaque coupure : jamais de panique (les dépassements de capacité paniquent aussi dans la
    /// version publiée), et jamais un contenu faux quand la trame a sa somme de contrôle.
    #[test]
    fn donnees_abimees_sans_panique() {
        for (h, attendu, controle) in [
            (COURT_19, texte(60), true),
            (COURT_1, texte(60), false),
            (LONG_19, texte(40_000), true),
            (HASARD_19, hasard(), true),
        ] {
            let bon = hexa(h);
            for i in 0..bon.len() {
                for masque in [0x01, 0x10, 0x80, 0xff] {
                    let mut abime = bon.clone();
                    abime[i] ^= masque;
                    let lu = decompresser(&abime, 1 << 20);
                    if controle {
                        assert!(lu.is_none() || lu.as_ref() == Some(&attendu), "octet {i}");
                    }
                }
                assert_eq!(decompresser(&bon[..i], 1 << 20), None, "coupé à {i}");
            }
        }
    }

    /// Sur cet ordinateur, quand le programme zstd est là : des textes et des octets au hasard compressés à tous les
    /// niveaux, en blocs petits et grands, se lisent comme il les lit.
    #[test]
    fn comme_le_programme_zstd() {
        if !crate::machine::linux::natif::present("zstd") {
            return crate::essais::saute("zstd absent");
        }
        let d = std::env::temp_dir().join(format!("vanguard-zstd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let mut x: u64 = 7;
        let mut octets_au_hasard = || {
            (0..300_000)
                .map(|_| {
                    x = x
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    // Peu de valeurs différentes : compressible, mais pas en motifs.
                    (x >> 59) as u8
                })
                .collect::<Vec<u8>>()
        };
        let entrees = [
            texte(40_000),
            hasard().repeat(50),
            octets_au_hasard(),
            Vec::new(),
            b"a".to_vec(),
        ];
        for (k, entree) in entrees.iter().enumerate() {
            let source = d.join(format!("e{k}"));
            std::fs::write(&source, entree).unwrap();
            for options in [
                &["-1"][..],
                &["-3", "--no-check"],
                &["-9"],
                &["-19"],
                &["--ultra", "-22"],
                &["-5", "-B4096"],
            ] {
                let cible = d.join(format!("e{k}.zst"));
                let ok = std::process::Command::new("zstd")
                    .args(options)
                    .args(["-q", "-f", "-o"])
                    .arg(&cible)
                    .arg(&source)
                    .status()
                    .is_ok_and(|s| s.success());
                assert!(ok, "zstd {options:?}");
                let compresse = std::fs::read(&cible).unwrap();
                assert_eq!(
                    decompresser(&compresse, 1 << 24).as_ref(),
                    Some(entree),
                    "entrée {k}, zstd {options:?}"
                );
            }
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Sur cet ordinateur : les modules du noyau en .ko.zst et les bases de pacman en zstd se lisent comme le
    /// programme zstd les lit, quand ils sont là.
    #[test]
    fn fichiers_du_systeme_comme_zstd() {
        if !crate::machine::linux::natif::present("zstd") {
            return crate::essais::saute("zstd absent");
        }
        let mut fichiers: Vec<std::path::PathBuf> = Vec::new();
        if let Ok(version) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
            let mut pile = vec![std::path::PathBuf::from(format!(
                "/usr/lib/modules/{}/kernel",
                version.trim()
            ))];
            while let Some(dossier) = pile.pop() {
                for e in std::fs::read_dir(&dossier).into_iter().flatten().flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        pile.push(p);
                    } else if p.extension().is_some_and(|x| x == "zst") && fichiers.len() < 400 {
                        fichiers.push(p);
                    }
                }
            }
        }
        for e in std::fs::read_dir("/var/lib/pacman/sync")
            .into_iter()
            .flatten()
            .flatten()
        {
            fichiers.push(e.path());
        }
        for f in fichiers {
            let Ok(octets) = std::fs::read(&f) else { continue };
            if !octets.starts_with(&SIGNATURE) {
                continue;
            }
            let Ok(sortie) = std::process::Command::new("zstd").args(["-dcq"]).arg(&f).output() else {
                continue;
            };
            assert!(sortie.status.success(), "{}", f.display());
            assert_eq!(decompresser(&octets, 1 << 30), Some(sortie.stdout), "{}", f.display());
        }
    }
}

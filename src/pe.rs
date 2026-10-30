//! La version d'un exécutable Windows (PE), lue dans sa ressource de version (RT_VERSION, VS_FIXEDFILEINFO), avec
//! son architecture (champ Machine de l'en-tête COFF). Écrit pour Vanguard, en Rust, sans fonction de Windows : la
//! même lecture sous Linux, où elle se teste, que sous Windows. Un .exe peut être fabriqué pour gêner l'analyse :
//! seuls les morceaux utiles sont lus, par `Seek`, jamais le fichier entier ; chaque position est contrôlée contre la
//! taille du fichier, l'arbre des ressources a sa profondeur exacte (3) et au plus 1 024 entrées par répertoire, et
//! tout ce qui sort de la forme attendue donne `None`, jamais une panique.
//!
//! Les mêmes en-têtes donnent aussi les gardes que le programme Windows de Vanguard doit porter (`gardes`) : le champ
//! DependentLoadFlags de son répertoire « Load Config » (ses DLL importées ne viennent que de System32, voir
//! `machine/windows/chargement.rs`) et son manifeste (ressource RT_MANIFEST n° 1). Le déploiement, qui tourne sous
//! Linux, les relit dans le vanguard.exe compilé avant de le livrer (`vanguard deploiement verifier-pe`), comme la
//! compilation reproductible de la CI : d'où ce module compilé partout, et pas seulement sous Windows.
//!
//! Lecteur pur, sans `crate::` : le banc de fuzzing l'inclut par son chemin.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Au-delà, l'en-tête PE ne commence pas là où un éditeur de liens le met.
const E_LFANEW_MAX: u32 = 4096;
/// Le maximum de sections que Windows accepte.
const SECTIONS_MAX: u16 = 96;
/// Entrées d'un répertoire de ressources : un exécutable réel en a quelques dizaines.
const ENTREES_MAX: usize = 1024;
/// La ressource de version : quelques Kio.
const VERSION_MAX: u32 = 64 << 10;
/// Octets lus en tout dans un fichier.
const LUS_MAX: usize = 256 << 10;
/// Le type RT_VERSION.
const RT_VERSION: u32 = 16;
/// Le type RT_MANIFEST, et le numéro du manifeste qu'un .exe porte pour son propre processus
/// (CREATEPROCESS_MANIFEST_RESOURCE_ID) : le seul que Windows lit en le lançant.
const RT_MANIFEST: u32 = 24;
const MANIFESTE_DU_PROCESSUS: u32 = 1;
/// Le répertoire de données n° 2 (ressources) et n° 10 (Load Config).
const REPERTOIRE_RESSOURCES: u32 = 2;
const REPERTOIRE_LOAD_CONFIG: u32 = 10;
/// DependentLoadFlags est au décalage 78 (2 octets) d'IMAGE_LOAD_CONFIG_DIRECTORY64 : Windows ne le lit que si la
/// taille annoncée du répertoire le couvre.
const DRAPEAUX_DE_CHARGEMENT: u32 = 78;
pub(crate) const TAILLE_MIN_DRAPEAUX: u32 = DRAPEAUX_DE_CHARGEMENT + 2;
/// LOAD_LIBRARY_SEARCH_SYSTEM32.
pub(crate) const SYSTEM32_SEULEMENT: u16 = 0x800;
/// La signature de VS_FIXEDFILEINFO.
const SIGNATURE: u32 = 0xFEEF_04BD;

/// L'architecture d'un exécutable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Machine {
    X86,
    X64,
    Arm64,
    Autre(u16),
}

impl Machine {
    fn depuis(champ: u16) -> Machine {
        match champ {
            0x014c => Machine::X86,
            0x8664 => Machine::X64,
            0xAA64 => Machine::Arm64,
            autre => Machine::Autre(autre),
        }
    }
}

/// Ce que dit un exécutable : version du fichier et du produit (quatre nombres de 16 bits chacune), architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InfoPe {
    pub fichier: [u16; 4],
    pub produit: [u16; 4],
    pub machine: Machine,
}

/// Pourquoi la version d'un exécutable n'a pas été lue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Echec {
    /// Le fichier ne s'ouvre pas (absent, interdit…).
    Ouverture(std::io::ErrorKind),
    /// Pas un fichier ordinaire (dossier, tube nommé).
    PasUnFichier,
    /// Pas un exécutable PE, pas de ressource de version, ou une forme refusée.
    Format,
}

/// La version de l'exécutable `chemin`. Un fichier ordinaire seulement (un tube nommé bloquerait la lecture).
#[cfg_attr(not(any(windows, test)), allow(dead_code))] // logiciels pas à jour, sous Windows
pub(crate) fn version(chemin: &Path) -> Result<InfoPe, Echec> {
    let (mut fichier, taille) = ouvrir(chemin)?;
    lire(&mut fichier, taille).ok_or(Echec::Format)
}

/// Un fichier ordinaire ouvert sans attendre (un tube nommé bloquerait la lecture), et sa taille.
fn ouvrir(chemin: &Path) -> Result<(std::fs::File, u64), Echec> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
    let fichier = options.open(chemin).map_err(|e| Echec::Ouverture(e.kind()))?;
    let meta = fichier.metadata().map_err(|e| Echec::Ouverture(e.kind()))?;
    if !meta.is_file() {
        return Err(Echec::PasUnFichier);
    }
    Ok((fichier, meta.len()))
}

/// Une section : où ses données sont en mémoire (RVA) et dans le fichier.
#[derive(Clone, Copy)]
struct Section {
    adresse: u32,
    taille_virtuelle: u32,
    taille_brute: u32,
    position: u32,
}

/// Le lecteur borné : position contrôlée contre la taille du fichier, total des octets lus compté.
struct Lecteur<'a, R> {
    source: &'a mut R,
    taille: u64,
    lus: usize,
}

impl<R: Read + Seek> Lecteur<'_, R> {
    fn octets(&mut self, position: u64, n: usize) -> Option<Vec<u8>> {
        let fin = position.checked_add(n as u64)?;
        self.lus = self.lus.checked_add(n)?;
        if fin > self.taille || self.lus > LUS_MAX {
            return None;
        }
        self.source.seek(SeekFrom::Start(position)).ok()?;
        let mut tampon = vec![0u8; n];
        self.source.read_exact(&mut tampon).ok()?;
        Some(tampon)
    }

    fn u16(&mut self, position: u64) -> Option<u16> {
        self.octets(position, 2)?.try_into().ok().map(u16::from_le_bytes)
    }

    fn u32(&mut self, position: u64) -> Option<u32> {
        self.octets(position, 4)?.try_into().ok().map(u32::from_le_bytes)
    }
}

/// La position dans le fichier d'une adresse virtuelle (RVA) et des `n` octets qui la suivent, s'ils sont tous dans
/// les données brutes d'une même section.
fn position(sections: &[Section], rva: u32, n: u32) -> Option<u64> {
    let s = sections.iter().find(|s| {
        let etendue = s.taille_virtuelle.max(s.taille_brute);
        rva >= s.adresse && u64::from(rva) < u64::from(s.adresse) + u64::from(etendue)
    })?;
    let decalage = rva - s.adresse;
    if u64::from(decalage) + u64::from(n) > u64::from(s.taille_brute) {
        return None;
    }
    Some(u64::from(s.position) + u64::from(decalage))
}

/// `position`, en plus stricte : les `n` octets doivent aussi tenir dans la taille virtuelle de la section (quand elle
/// est donnée), c'est-à-dire dans ce que le chargeur de Windows met en mémoire, pas seulement dans le fichier.
fn position_chargee(sections: &[Section], rva: u32, n: u32) -> Option<u64> {
    let s = sections.iter().find(|s| {
        rva >= s.adresse && u64::from(rva) < u64::from(s.adresse) + u64::from(s.taille_virtuelle.max(s.taille_brute))
    })?;
    let fin = u64::from(rva - s.adresse) + u64::from(n);
    if s.taille_virtuelle != 0 && fin > u64::from(s.taille_virtuelle) {
        return None;
    }
    position(sections, rva, n)
}

/// Les en-têtes d'un PE, lus et contrôlés : architecture, forme (PE32+ ou PE32), table des répertoires de données,
/// sections dont les données brutes sont toutes dans le fichier.
struct Entetes {
    machine: Machine,
    pe32_plus: bool,
    /// Position de la table des répertoires dans le fichier, et ce qu'en annonce l'en-tête facultatif : nombre
    /// d'entrées, place qu'elles ont avant la fin de l'en-tête.
    repertoires: u64,
    nombre_repertoires: u32,
    place_repertoires: u32,
    sections: Vec<Section>,
}

impl Entetes {
    /// L'adresse (RVA) et la taille du répertoire n° `n` ; `None` s'il n'est pas annoncé, ne tient pas dans l'en-tête
    /// facultatif ou est vide.
    fn repertoire<R: Read + Seek>(&self, l: &mut Lecteur<'_, R>, n: u32) -> Option<(u32, u32)> {
        if n >= self.nombre_repertoires || (n + 1) * 8 > self.place_repertoires {
            return None;
        }
        let entree = self.repertoires + u64::from(n) * 8;
        let rva = l.u32(entree)?;
        (rva != 0).then_some((rva, l.u32(entree + 4)?))
    }
}

fn entetes<R: Read + Seek>(l: &mut Lecteur<'_, R>) -> Option<Entetes> {
    // En-tête DOS, puis l'en-tête PE qu'il désigne.
    if l.octets(0, 2)? != b"MZ" {
        return None;
    }
    let e_lfanew = l.u32(0x3C)?;
    if e_lfanew >= E_LFANEW_MAX {
        return None;
    }
    let pe = u64::from(e_lfanew);
    if l.octets(pe, 4)? != b"PE\0\0" {
        return None;
    }
    // En-tête COFF.
    let machine = Machine::depuis(l.u16(pe + 4)?);
    let nombre_sections = l.u16(pe + 6)?;
    let taille_facultatif = l.u16(pe + 20)?;
    if nombre_sections == 0 || nombre_sections > SECTIONS_MAX {
        return None;
    }
    // En-tête facultatif : PE32 ou PE32+, et la table des répertoires de données qui le termine.
    let facultatif = pe + 24;
    let (pe32_plus, nombre_repertoires, debut_repertoires) = match l.u16(facultatif)? {
        0x10B => (false, l.u32(facultatif + 92)?, 96u16),
        0x20B => (true, l.u32(facultatif + 108)?, 112u16),
        _ => return None,
    };
    let place_repertoires = u32::from(taille_facultatif.checked_sub(debut_repertoires)?);
    // Table des sections.
    let table = facultatif + u64::from(taille_facultatif);
    let mut sections = Vec::with_capacity(usize::from(nombre_sections));
    for i in 0..u64::from(nombre_sections) {
        let s = l.octets(table + i * 40, 40)?;
        sections.push(Section {
            taille_virtuelle: mot32_a(&s, 8)?,
            adresse: mot32_a(&s, 12)?,
            taille_brute: mot32_a(&s, 16)?,
            position: mot32_a(&s, 20)?,
        });
    }
    // Les données brutes de chaque section doivent être dans le fichier.
    if sections
        .iter()
        .any(|s| u64::from(s.position) + u64::from(s.taille_brute) > l.taille)
    {
        return None;
    }
    Some(Entetes {
        machine,
        pe32_plus,
        repertoires: facultatif + u64::from(debut_repertoires),
        nombre_repertoires,
        place_repertoires,
        sections,
    })
}

/// La version et l'architecture d'un exécutable de `taille` octets. `None` : pas un PE, pas de ressource de version,
/// ou une forme refusée.
#[cfg_attr(not(any(windows, test)), allow(dead_code))] // logiciels pas à jour, sous Windows
pub(crate) fn lire<R: Read + Seek>(source: &mut R, taille: u64) -> Option<InfoPe> {
    let mut l = Lecteur { source, taille, lus: 0 };
    let e = entetes(&mut l)?;
    let (rva_ressources, _) = e.repertoire(&mut l, REPERTOIRE_RESSOURCES)?;
    let donnees = ressource(&mut l, &e.sections, rva_ressources, RT_VERSION, None, VERSION_MAX)?;
    let (fichier, produit) = info_fixe(&donnees)?;
    Some(InfoPe {
        fichier,
        produit,
        machine: e.machine,
    })
}

/// Le répertoire « Load Config » d'un PE 64 bits, tel que Windows le lit : la taille annoncée par la table des
/// répertoires, celle écrite au début de la structure, et DependentLoadFlags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LoadConfig {
    pub taille_repertoire: u32,
    pub taille: u32,
    pub drapeaux: u16,
}

impl LoadConfig {
    /// Les DLL importées ne viennent-elles que de System32 ? Seulement si le champ y est, et couvert par les deux
    /// tailles : une taille plus courte laisserait le champ ignoré, quelle que soit sa valeur. Les deux tailles
    /// doivent aussi être égales, comme les écrivent GNU ld, lld et MSVC : deux valeurs différentes, c'est une image
    /// retouchée dont on ne sait pas laquelle Windows croira.
    pub(crate) fn system32_seulement(&self) -> bool {
        self.taille >= TAILLE_MIN_DRAPEAUX
            && self.taille_repertoire == self.taille
            && self.drapeaux == SYSTEM32_SEULEMENT
    }
}

/// Les gardes d'un exécutable : son Load Config (PE32+ seulement) et son manifeste. Chacune `None` quand elle manque
/// ou ne se lit pas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Gardes {
    pub load_config: Option<LoadConfig>,
    pub manifeste: Option<Vec<u8>>,
}

/// Les gardes d'un exécutable de `taille` octets. `None` : pas un PE, ou des en-têtes refusés.
pub(crate) fn lire_gardes<R: Read + Seek>(source: &mut R, taille: u64) -> Option<Gardes> {
    let mut l = Lecteur { source, taille, lus: 0 };
    let e = entetes(&mut l)?;
    let load_config = e
        .pe32_plus
        .then(|| {
            let (rva, taille_repertoire) = e.repertoire(&mut l, REPERTOIRE_LOAD_CONFIG)?;
            // Les octets jusqu'au champ compris doivent être dans les données brutes d'une même section.
            let debut = position_chargee(&e.sections, rva, TAILLE_MIN_DRAPEAUX)?;
            Some(LoadConfig {
                taille_repertoire,
                taille: l.u32(debut)?,
                drapeaux: l.u16(debut + u64::from(DRAPEAUX_DE_CHARGEMENT))?,
            })
        })
        .flatten();
    let manifeste = e.repertoire(&mut l, REPERTOIRE_RESSOURCES).and_then(|(rva, _)| {
        ressource(
            &mut l,
            &e.sections,
            rva,
            RT_MANIFEST,
            Some(MANIFESTE_DU_PROCESSUS),
            VERSION_MAX,
        )
    });
    Some(Gardes { load_config, manifeste })
}

/// Les gardes de l'exécutable `chemin`, lu sans être lancé. Un fichier ordinaire seulement.
#[cfg_attr(not(any(target_os = "linux", windows, test)), allow(dead_code))] // le déploiement, sous Linux
pub(crate) fn gardes(chemin: &Path) -> Result<Gardes, Echec> {
    let (mut fichier, taille) = ouvrir(chemin)?;
    lire_gardes(&mut fichier, taille).ok_or(Echec::Format)
}

/// Une entrée d'un répertoire de ressources : son nom ou numéro, et le décalage de ce qu'elle désigne (bit de poids
/// fort : un sous-répertoire), depuis le début des ressources.
struct Entree {
    nom: u32,
    decalage: u32,
}

/// Les entrées du répertoire au `decalage` des ressources : d'abord celles à nom, puis celles à numéro.
fn entrees<R: Read + Seek>(
    l: &mut Lecteur<'_, R>,
    sections: &[Section],
    rva_ressources: u32,
    decalage: u32,
) -> Option<Vec<Entree>> {
    let rva = rva_ressources.checked_add(decalage)?;
    let debut = position(sections, rva, 16)?;
    let nommees = usize::from(l.u16(debut + 12)?);
    let numerotees = usize::from(l.u16(debut + 14)?);
    let n = nommees + numerotees;
    if n == 0 || n > ENTREES_MAX {
        return None;
    }
    let taille = u32::try_from(n * 8).ok()?;
    let position_entrees = position(sections, rva.checked_add(16)?, taille)?;
    let brut = l.octets(position_entrees, n * 8)?;
    let (morceaux, _) = brut.as_chunks::<8>();
    Some(
        morceaux
            .iter()
            .map(|e| Entree {
                nom: u32::from_le_bytes([e[0], e[1], e[2], e[3]]),
                decalage: u32::from_le_bytes([e[4], e[5], e[6], e[7]]),
            })
            .collect(),
    )
}

const SOUS_REPERTOIRE: u32 = 0x8000_0000;

/// Les octets d'une ressource : niveau 1, le type `type_` ; niveau 2, le nom `nom` (le premier si `None`) ; niveau 3,
/// sa première langue, qui désigne les données, de `max` octets au plus. Chaque sous-répertoire est plus loin que son parent : un arbre qui reviendrait en
/// arrière (une boucle) est refusé.
fn ressource<R: Read + Seek>(
    l: &mut Lecteur<'_, R>,
    sections: &[Section],
    rva_ressources: u32,
    type_: u32,
    nom: Option<u32>,
    max: u32,
) -> Option<Vec<u8>> {
    let niveau1 = entrees(l, sections, rva_ressources, 0)?;
    let de_type = niveau1.iter().find(|e| e.nom == type_)?;
    if de_type.decalage & SOUS_REPERTOIRE == 0 {
        return None;
    }
    let decalage2 = de_type.decalage & !SOUS_REPERTOIRE;
    if decalage2 == 0 {
        return None;
    }
    let niveau2 = entrees(l, sections, rva_ressources, decalage2)?;
    let nom = match nom {
        Some(n) => niveau2.iter().find(|e| e.nom == n)?,
        None => niveau2.first()?,
    };
    if nom.decalage & SOUS_REPERTOIRE == 0 {
        return None;
    }
    let decalage3 = nom.decalage & !SOUS_REPERTOIRE;
    if decalage3 <= decalage2 {
        return None;
    }
    let niveau3 = entrees(l, sections, rva_ressources, decalage3)?;
    let langue = niveau3.first()?;
    // Au troisième niveau, des données, jamais un répertoire : la profondeur est exactement 3.
    if langue.decalage & SOUS_REPERTOIRE != 0 || langue.decalage <= decalage3 {
        return None;
    }
    // IMAGE_RESOURCE_DATA_ENTRY : adresse (RVA) et taille des données.
    let entree = position(sections, rva_ressources.checked_add(langue.decalage)?, 16)?;
    let rva_donnees = l.u32(entree)?;
    let taille = l.u32(entree + 4)?;
    if taille == 0 || taille > max {
        return None;
    }
    let debut = position(sections, rva_donnees, taille)?;
    l.octets(debut, usize::try_from(taille).ok()?)
}

/// VS_VERSIONINFO : longueur, longueur de la valeur, type, la clé « VS_VERSION_INFO » en UTF-16, un alignement sur
/// 4 octets, puis VS_FIXEDFILEINFO (52 octets, signature 0xFEEF04BD). Rend les versions du fichier et du produit.
fn info_fixe(donnees: &[u8]) -> Option<([u16; 4], [u16; 4])> {
    let mot16 = |a: usize| Some(u16::from_le_bytes([*donnees.get(a)?, *donnees.get(a + 1)?]));
    let mot32 = |a: usize| {
        Some(u32::from_le_bytes([
            *donnees.get(a)?,
            *donnees.get(a + 1)?,
            *donnees.get(a + 2)?,
            *donnees.get(a + 3)?,
        ]))
    };
    let longueur = usize::from(mot16(0)?);
    let longueur_valeur = usize::from(mot16(2)?);
    if longueur > donnees.len() || longueur_valeur < 52 {
        return None;
    }
    let cle: Vec<u16> = "VS_VERSION_INFO\0".encode_utf16().collect();
    for (i, c) in cle.iter().enumerate() {
        if mot16(6 + 2 * i)? != *c {
            return None;
        }
    }
    let fixe = (6 + 2 * cle.len()).next_multiple_of(4);
    if fixe + 52 > longueur || mot32(fixe)? != SIGNATURE {
        return None;
    }
    let quatre = |ms: u32, ls: u32| {
        #[allow(clippy::cast_possible_truncation)]
        [(ms >> 16) as u16, ms as u16, (ls >> 16) as u16, ls as u16]
    };
    Some((
        quatre(mot32(fixe + 8)?, mot32(fixe + 12)?),
        quatre(mot32(fixe + 16)?, mot32(fixe + 20)?),
    ))
}

// --- Les champs du module « pe » des règles YARA (protection/moteur_yara.rs) ---
//
// Ils ne suivent pas la lecture stricte d'au-dessus : une règle doit trouver ce que trouve YARA-X, l'oracle du moteur,
// même sur un exécutable abîmé (un logiciel malveillant l'est souvent exprès). Ce qui suit a été établi en boîte
// noire, en comparant à YARA-X des milliers de PE fabriqués exprès et les PE réels de ce PC, puis il est gardé par les
// tests de l'oracle (moteur_yara, en développement seulement). Rien n'y vient de son code.

/// Ce que le module « pe » donne d'un fichier, pour les règles qui s'en servent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ChampsYara {
    /// pe.entry_point : la position du point d'entrée dans le fichier, `None` quand il ne s'y ramène pas (indéfini).
    pub point_d_entree: Option<u64>,
    /// Le répertoire de sécurité (n° 4) : sa position dans le fichier et sa taille annoncée.
    pub securite: Option<(u64, u64)>,
}

/// Le répertoire de données n° 4 : les signatures Authenticode, désignées par une position dans le fichier (pas une
/// RVA).
const REPERTOIRE_SECURITE: u64 = 4;
/// Les sections lues, au plus : au-delà, YARA-X les ignore.
const SECTIONS_YARA: u16 = 96;

/// Lit `n` octets à `position`, s'ils sont tous avant `taille`.
fn morceau<R: Read + Seek>(source: &mut R, taille: u64, position: u64, n: usize) -> Option<Vec<u8>> {
    if position.checked_add(n as u64)? > taille {
        return None;
    }
    source.seek(SeekFrom::Start(position)).ok()?;
    let mut tampon = vec![0u8; n];
    source.read_exact(&mut tampon).ok()?;
    Some(tampon)
}

/// Les champs YARA d'un fichier de `taille` octets ; `None` si ce n'est pas un PE pour YARA (pe.is_pe faux : tout le
/// module est alors indéfini). Un PE : « MZ », un en-tête DOS entier (64 octets), et « PE\0\0 » suivi de l'en-tête
/// COFF (24 octets en tout) là où pointe e_lfanew. Un en-tête facultatif plus court que sa forme fixe (96 octets en
/// PE32, 112 en PE32+, quelle que soit la taille qu'il annonce) compte comme rempli de zéros.
pub(crate) fn champs_yara<R: Read + Seek>(source: &mut R, taille: u64) -> Option<ChampsYara> {
    champs(source, taille, false)
}

/// `champs_yara` d'une image chargée en mémoire (sections à leur RVA, en-têtes à leur place) : pe.entry_point y est
/// l'adresse d'entrée relative à la base, comme libyara la donne pour la mémoire d'un processus (base +
/// AddressOfEntryPoint, la base étant ici le début des données). Le répertoire de sécurité désigne une position dans
/// le FICHIER, qui n'est pas chargée : aucune signature n'y est lue.
pub(crate) fn champs_yara_chargee<R: Read + Seek>(source: &mut R, taille: u64) -> Option<ChampsYara> {
    champs(source, taille, true)
}

fn champs<R: Read + Seek>(source: &mut R, taille: u64, chargee: bool) -> Option<ChampsYara> {
    // `morceau` rend exactement les octets demandés : les lectures de mots qui suivent sont dedans (un `None` n'y
    // viendrait que d'un défaut d'ici, et ferait dire « pas un PE » plutôt que planter).
    let dos = morceau(source, taille, 0, 0x40)?;
    if !dos.starts_with(b"MZ") {
        return None;
    }
    let pe = u64::from(mot32_a(&dos, 0x3C)?);
    let coff = morceau(source, taille, pe, 24)?;
    if !coff.starts_with(b"PE\0\0") {
        return None;
    }
    let nombre_sections = mot16_a(&coff, 6)?;
    let taille_facultatif = u64::from(mot16_a(&coff, 20)?);
    let facultatif = pe + 24;
    let pe32_plus = morceau(source, taille, facultatif, 2).is_some_and(|m| mot16_a(&m, 0) == Some(0x20B));
    let forme = if pe32_plus { 112 } else { 96 };
    let (rva, alignement_sections, alignement_fichier) = match morceau(source, taille, facultatif, forme) {
        Some(f) => (mot32_a(&f, 16)?, mot32_a(&f, 32)?, mot32_a(&f, 36)?),
        None => (0, 0, 0),
    };
    let securite = morceau(source, taille, facultatif + forme as u64 + 8 * REPERTOIRE_SECURITE, 8)
        .and_then(|r| Some((u64::from(mot32_a(&r, 0)?), u64::from(mot32_a(&r, 4)?))));
    // La table des sections suit l'en-tête facultatif de la taille qu'il annonce ; elle s'arrête à la première entrée
    // qui sort du fichier.
    let table = facultatif + taille_facultatif;
    let mut sections = Vec::new();
    for i in 0..u64::from(nombre_sections.min(SECTIONS_YARA)) {
        let Some(section) = morceau(source, taille, table + i * 40, 40).and_then(|s| {
            Some(Section {
                taille_virtuelle: mot32_a(&s, 8)?,
                adresse: mot32_a(&s, 12)?,
                taille_brute: mot32_a(&s, 16)?,
                position: mot32_a(&s, 20)?,
            })
        }) else {
            break;
        };
        sections.push(section);
    }
    if chargee {
        return Some(ChampsYara {
            point_d_entree: Some(u64::from(rva)),
            securite: None,
        });
    }
    Some(ChampsYara {
        point_d_entree: position_yara(&sections, rva, alignement_sections, alignement_fichier),
        securite,
    })
}

/// La position dans le fichier de l'adresse `rva`, comme YARA-X la calcule : la section qui la contient (de son
/// adresse jusqu'à la plus grande de ses deux tailles) et dont l'adresse est la plus haute, la dernière à égalité ;
/// la position de ses données arrondie à l'alignement des fichiers (512 au plus), puis à 512 si les sections sont
/// alignées sur une page ou plus. Hors des données brutes de cette section, ou dans aucune section : indéfini, sauf
/// sous la plus basse des sections, dans les en-têtes, où la RVA est sa propre position. Sans section : indéfini. Une
/// position au-delà de 32 bits est ramenée à 0xFFFFFFFF.
fn position_yara(sections: &[Section], rva: u32, alignement_sections: u32, alignement_fichier: u32) -> Option<u64> {
    let mut choisie: Option<&Section> = None;
    for s in sections {
        let contient = rva >= s.adresse && rva - s.adresse < s.taille_virtuelle.max(s.taille_brute);
        if contient && choisie.is_none_or(|c| s.adresse >= c.adresse) {
            choisie = Some(s);
        }
    }
    let Some(s) = choisie else {
        let plus_basse = sections.iter().map(|s| s.adresse).min()?;
        return (rva < plus_basse).then_some(u64::from(rva));
    };
    let decalage = rva - s.adresse;
    if decalage >= s.taille_brute {
        return None;
    }
    let mut position = u64::from(s.position);
    if alignement_fichier != 0 {
        let a = u64::from(alignement_fichier.min(0x200));
        position = position / a * a;
    }
    if alignement_sections >= 0x1000 {
        position = position / 0x200 * 0x200;
    }
    // Une somme qui dépasse 32 bits s'arrête à 0xFFFFFFFF, comme dans YARA-X.
    Some((position + u64::from(decalage)).min(u64::from(u32::MAX)))
}

/// L'identifiant d'objet signedData (1.2.840.113549.1.7.2), tel qu'il s'écrit en DER (et en BER : un OID est toujours
/// primitif) au début de toute signature Authenticode.
const OID_SIGNED_DATA: [u8; 11] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];

/// pe.number_of_signatures > 0, en plus large : le répertoire de sécurité (borné au fichier) contient-il une
/// structure signedData ? YARA-X ne compte une signature que s'il la lit entière (structure PKCS#7 complète, un seul
/// signataire, contenu Authenticode…), ce que Vanguard ne refait pas : toute signature que YARA-X compte contient cet
/// identifiant dans ce répertoire, si bien qu'une règle qui exige une signature trouve au moins tout ce que trouve
/// YARA-X (et, en plus, un fichier dont la signature est abîmée). Sur les PE de ce PC, les deux disent la même chose
/// (test de l'oracle).
pub(crate) fn signature_presente<R: Read + Seek>(source: &mut R, taille: u64, champs: &ChampsYara) -> bool {
    let Some((debut, longueur)) = champs.securite else {
        return false;
    };
    let fin = debut.saturating_add(longueur).min(taille);
    if debut >= fin || source.seek(SeekFrom::Start(debut)).is_err() {
        return false;
    }
    // Par blocs, chacun gardant la fin du précédent : un identifiant à cheval est vu.
    let mut tampon = vec![0u8; (64 << 10) + OID_SIGNED_DATA.len()];
    let mut garde = 0usize;
    let mut position = debut;
    while position < fin {
        let voulu = usize::try_from(fin - position).unwrap_or(usize::MAX).min(64 << 10);
        // `garde` (moins que l'identifiant) plus un bloc tiennent dans le tampon : une zone hors de lui, défaut
        // d'ici, se lit comme une lecture ratée.
        let Some(zone) = tampon.get_mut(garde..garde + voulu) else {
            return false;
        };
        if source.read_exact(zone).is_err() {
            return false;
        }
        let plein = garde + voulu;
        if tampon
            .get(..plein)
            .is_some_and(|t| t.windows(OID_SIGNED_DATA.len()).any(|w| w == OID_SIGNED_DATA))
        {
            return true;
        }
        garde = (OID_SIGNED_DATA.len() - 1).min(plein);
        tampon.copy_within(plein - garde..plein, 0);
        position += voulu as u64;
    }
    false
}

// --- Structure entière d'un PE, pour l'analyse des fichiers (`analyse/`) ---
//
// Ajoutée en bloc au lecteur commun : les mêmes en-têtes (`entetes`, contrôlés), puis ce qu'une analyse antivirus
// regarde : sections (nom, droits, entropie), point d'entrée, imports, présence d'une signature Authenticode (sa
// VÉRIFICATION n'est pas faite ici), octets après la dernière section (overlay). D'après « PE Format »
// (learn.microsoft.com) : en-tête facultatif (AddressOfEntryPoint en 16, SizeOfHeaders en 60, Subsystem en 68),
// table des sections (Characteristics en 36), répertoire n° 1 (imports, IMAGE_IMPORT_DESCRIPTOR de 20 octets),
// n° 4 (certificats : une POSITION dans le fichier, pas une RVA ; WIN_CERTIFICATE alignés sur 8 octets) et n° 14
// (en-tête CLR : .NET). Le fichier est déjà en mémoire (borné par l'appelant) : lu par tranches contrôlées.

/// IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE.
const SCN_EXECUTE: u32 = 0x2000_0000;
const SCN_WRITE: u32 = 0x8000_0000;
/// Le répertoire n° 1 (imports), n° 4 (certificats), n° 14 (en-tête CLR).
const REPERTOIRE_IMPORTS: u32 = 1;
const REPERTOIRE_CERTIFICATS: u32 = 4;
const REPERTOIRE_CLR: u32 = 14;
/// Bornes des imports : bien au-delà d'un programme réel (quelques dizaines de DLL, quelques milliers de fonctions).
const DLL_MAX: usize = 512;
const FONCTIONS_MAX: usize = 16_384;
const NOM_MAX: usize = 256;
/// Les certificats parcourus (un programme réel en a un, parfois deux).
const CERTIFICATS_MAX: usize = 16;

/// Une section, telle que la décrit sa table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SectionPe {
    /// Huit octets au plus, jusqu'au premier nul (sans le décodage « /n » des fichiers objets : un exécutable n'en a
    /// pas).
    pub nom: String,
    pub adresse: u32,
    pub taille_virtuelle: u32,
    pub position: u32,
    pub taille_brute: u32,
    pub caracteristiques: u32,
    /// Entropie de Shannon des données brutes, en millièmes de bit par octet (0 à 8 000).
    pub entropie: u16,
}

impl SectionPe {
    pub(crate) fn executable(&self) -> bool {
        self.caracteristiques & SCN_EXECUTE != 0
    }

    pub(crate) fn ecrivable(&self) -> bool {
        self.caracteristiques & SCN_WRITE != 0
    }

    fn contient_rva(&self, rva: u32) -> bool {
        let etendue = self.taille_virtuelle.max(self.taille_brute);
        rva >= self.adresse && u64::from(rva) < u64::from(self.adresse) + u64::from(etendue)
    }
}

/// Une DLL importée et ses fonctions (« #n » pour un import par numéro).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImportPe {
    pub dll: String,
    pub fonctions: Vec<String>,
}

/// La signature Authenticode : présente ou non (jamais vérifiée ici).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Authenticode {
    Absente,
    /// Une table de certificats dont la première entrée est un PKCS#7 (WIN_CERT_TYPE_PKCS_SIGNED_DATA, révision 2).
    Presente,
    /// Annoncée, mais hors du fichier ou d'une autre forme.
    Illisible,
}

/// La structure d'un PE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StructurePe {
    pub machine: Machine,
    pub pe32_plus: bool,
    /// Characteristics de l'en-tête COFF (0x2000 : une DLL).
    pub caracteristiques: u16,
    pub sous_systeme: u16,
    pub point_entree: u32,
    pub sections: Vec<SectionPe>,
    pub imports: Vec<ImportPe>,
    /// La table des imports ne se lit pas jusqu'au bout (hors section, sans fin, au-delà des bornes).
    pub imports_incomplets: bool,
    pub authenticode: Authenticode,
    /// La place de la table des certificats dans le fichier, si elle y est.
    pub certificats: Option<std::ops::Range<u64>>,
    /// Octets de la table des certificats au-delà des entrées qu'elle déclare (des données cachées « dans » la
    /// signature, que la vérification d'Authenticode ne couvre pas).
    pub apres_certificats: Option<std::ops::Range<u64>>,
    pub dotnet: bool,
    /// La fin des en-têtes et des données des sections : au-delà, c'est l'overlay (hors certificats).
    pub fin_des_donnees: u64,
    /// Les morceaux de l'overlay, hors table des certificats.
    pub overlay: Vec<std::ops::Range<u64>>,
}

impl StructurePe {
    /// Le point d'entrée est-il dans une section ? (Un point d'entrée nul, celui d'une DLL sans DllMain, l'est
    /// toujours.)
    pub(crate) fn point_entree_dans_une_section(&self) -> bool {
        self.point_entree == 0 || self.sections.iter().any(|s| s.contient_rva(self.point_entree))
    }

    /// La section qui contient le point d'entrée.
    pub(crate) fn section_du_point_entree(&self) -> Option<&SectionPe> {
        self.sections.iter().find(|s| s.contient_rva(self.point_entree))
    }
}

/// L'entropie de Shannon d'octets, en millièmes de bit par octet.
pub(crate) fn entropie(octets: &[u8]) -> u16 {
    if octets.is_empty() {
        return 0;
    }
    let mut compte = [0u64; 256];
    for &o in octets {
        #[expect(clippy::indexing_slicing, reason = "un octet indexe une table de 256 entrées")]
        {
            compte[usize::from(o)] += 1;
        }
    }
    #[allow(clippy::cast_precision_loss)]
    let n = octets.len() as f64;
    let h: f64 = compte
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            #[allow(clippy::cast_precision_loss)]
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum();
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let milli = (h * 1000.0).round().clamp(0.0, 8000.0) as u16;
    milli
}

fn mot16_a(octets: &[u8], i: usize) -> Option<u16> {
    octets.get(i..)?.first_chunk::<2>().map(|b| u16::from_le_bytes(*b))
}

fn mot32_a(octets: &[u8], i: usize) -> Option<u32> {
    octets.get(i..)?.first_chunk::<4>().map(|b| u32::from_le_bytes(*b))
}

fn mot64_a(octets: &[u8], i: usize) -> Option<u64> {
    octets.get(i..)?.first_chunk::<8>().map(|b| u64::from_le_bytes(*b))
}

/// La position dans le fichier d'une RVA : dans les données brutes d'une section, ou dans les en-têtes (avant la
/// première section, où le chargeur les met tels quels).
fn position_rva(sections: &[Section], taille_entetes: u32, rva: u32, n: u32) -> Option<usize> {
    if let Some(p) = position(sections, rva, n) {
        return usize::try_from(p).ok();
    }
    (u64::from(rva) + u64::from(n) <= u64::from(taille_entetes)).then_some(rva as usize)
}

/// Une chaîne ASCII terminée par un nul, d'au plus `NOM_MAX` octets, à la RVA `rva`.
fn chaine_rva(octets: &[u8], sections: &[Section], taille_entetes: u32, rva: u32) -> Option<String> {
    let debut = position_rva(sections, taille_entetes, rva, 1)?;
    let reste = octets.get(debut..)?;
    let reste = reste.get(..NOM_MAX).unwrap_or(reste);
    let fin = reste.iter().position(|&o| o == 0)?;
    Some(String::from_utf8_lossy(reste.get(..fin)?).into_owned())
}

/// La structure du PE `octets` (le fichier entier). `None` : pas un PE, ou des en-têtes refusés par `entetes`.
pub(crate) fn structure(octets: &[u8]) -> Option<StructurePe> {
    let mut curseur = std::io::Cursor::new(octets);
    let taille = octets.len() as u64;
    let mut l = Lecteur {
        source: &mut curseur,
        taille,
        lus: 0,
    };
    let e = entetes(&mut l)?;
    let pe = usize::try_from(mot32_a(octets, 0x3C)?).ok()?;
    let facultatif = pe + 24;
    let taille_facultatif = usize::from(mot16_a(octets, pe + 20)?);
    let caracteristiques = mot16_a(octets, pe + 22)?;
    let point_entree = mot32_a(octets, facultatif + 16)?;
    let taille_entetes = mot32_a(octets, facultatif + 60)?;
    let sous_systeme = mot16_a(octets, facultatif + 68)?;
    let table = facultatif + taille_facultatif;
    let mut sections = Vec::with_capacity(e.sections.len());
    // L'entropie se calcule une fois par plage, et sur deux fois le fichier au plus : 96 sections qui couvrent
    // chacune tout le fichier ne coûtent pas 96 lectures (au-delà, l'entropie reste à 0, non calculée).
    let mut deja: Vec<((u32, u32), u16)> = Vec::new();
    let mut budget = octets.len().saturating_mul(2).saturating_add(1 << 20);
    for (i, s) in e.sections.iter().enumerate() {
        let entree = octets.get(table + i * 40..)?.first_chunk::<40>()?;
        let nom = &entree[..8];
        // Jusqu'au premier nul (les huit octets s'il n'y en a pas).
        let nom = String::from_utf8_lossy(nom.split(|&o| o == 0).next().unwrap_or(nom)).into_owned();
        let debut = s.position as usize;
        let brut = octets.get(debut..debut + s.taille_brute as usize).unwrap_or(&[]);
        sections.push(SectionPe {
            nom,
            adresse: s.adresse,
            taille_virtuelle: s.taille_virtuelle,
            position: s.position,
            taille_brute: s.taille_brute,
            caracteristiques: mot32_a(entree, 36)?,
            entropie: match deja.iter().find(|(r, _)| *r == (s.position, s.taille_brute)) {
                Some(&(_, h)) => h,
                None if brut.len() <= budget => {
                    budget -= brut.len();
                    let h = entropie(brut);
                    deja.push(((s.position, s.taille_brute), h));
                    h
                }
                None => 0,
            },
        });
    }
    let repertoire = |n: u32| -> Option<(u32, u32)> {
        if n >= e.nombre_repertoires || (n + 1) * 8 > e.place_repertoires {
            return None;
        }
        let entree = usize::try_from(e.repertoires).ok()? + n as usize * 8;
        let rva = mot32_a(octets, entree)?;
        (rva != 0).then_some((rva, mot32_a(octets, entree + 4)?))
    };
    let (imports, imports_incomplets) = match repertoire(REPERTOIRE_IMPORTS) {
        Some((rva, _)) => imports(octets, &e.sections, taille_entetes, rva, e.pe32_plus),
        None => (Vec::new(), false),
    };
    // Certificats : position et taille dans le fichier.
    let (mut authenticode, mut certificats, mut apres_certificats) = (Authenticode::Absente, None, None);
    if let Some((position_cert, taille_cert)) = repertoire(REPERTOIRE_CERTIFICATS).filter(|&(_, t)| t > 0) {
        let fin = u64::from(position_cert) + u64::from(taille_cert);
        if fin > taille || taille_cert < 8 {
            authenticode = Authenticode::Illisible;
        } else {
            certificats = Some(u64::from(position_cert)..fin);
            let debut = position_cert as usize;
            let revision = mot16_a(octets, debut + 4);
            let sorte = mot16_a(octets, debut + 6);
            authenticode = if revision == Some(0x0200) && sorte == Some(0x0002) {
                Authenticode::Presente
            } else {
                Authenticode::Illisible
            };
            // Les entrées WIN_CERTIFICATE à la suite, chacune arrondie à 8 octets ; ce qui reste au-delà de la
            // dernière n'est pas un certificat.
            let mut i = 0u64;
            for _ in 0..CERTIFICATS_MAX {
                // `i` reste sous `taille_cert` (32 bits) : la conversion ne coupe rien.
                let Some(longueur) = usize::try_from(i)
                    .ok()
                    .and_then(|d| mot32_a(octets, debut + d))
                    .map(u64::from)
                else {
                    break;
                };
                if longueur < 8 || i + longueur > u64::from(taille_cert) {
                    break;
                }
                i += longueur.next_multiple_of(8);
                if i >= u64::from(taille_cert) {
                    break;
                }
            }
            let couvert = u64::from(position_cert) + i.min(u64::from(taille_cert));
            if fin > couvert && fin - couvert >= 8 {
                apres_certificats = Some(couvert..fin);
            }
        }
    }
    let dotnet = repertoire(REPERTOIRE_CLR).is_some();
    // La fin des données : les en-têtes, puis la plus lointaine des sections (données brutes).
    let fin_des_donnees = sections
        .iter()
        .filter(|s| s.taille_brute > 0)
        .map(|s| u64::from(s.position) + u64::from(s.taille_brute))
        .chain([u64::from(taille_entetes).min(taille)])
        .max()
        .unwrap_or(0);
    let mut overlay = Vec::new();
    if fin_des_donnees < taille {
        match certificats.clone() {
            Some(c) if c.start >= fin_des_donnees => {
                if c.start > fin_des_donnees {
                    overlay.push(fin_des_donnees..c.start);
                }
                if c.end < taille {
                    overlay.push(c.end..taille);
                }
            }
            Some(c) if c.end > fin_des_donnees => overlay.push(c.end..taille),
            _ => overlay.push(fin_des_donnees..taille),
        }
        overlay.retain(|r| r.end > r.start);
    }
    Some(StructurePe {
        machine: e.machine,
        pe32_plus: e.pe32_plus,
        caracteristiques,
        sous_systeme,
        point_entree,
        sections,
        imports,
        imports_incomplets,
        authenticode,
        certificats,
        apres_certificats,
        dotnet,
        fin_des_donnees,
        overlay,
    })
}

/// La table des imports à la RVA `rva` : (DLL et fonctions, lue jusqu'au bout ou non).
fn imports(
    octets: &[u8],
    sections: &[Section],
    taille_entetes: u32,
    rva: u32,
    pe32_plus: bool,
) -> (Vec<ImportPe>, bool) {
    let mut dlls = Vec::new();
    let mut fonctions_lues = 0usize;
    let largeur: u32 = if pe32_plus { 8 } else { 4 };
    for n in 0..=DLL_MAX {
        let Some(descripteur) = rva
            .checked_add(u32::try_from(n * 20).unwrap_or(u32::MAX))
            .and_then(|r| position_rva(sections, taille_entetes, r, 20))
        else {
            return (dlls, true);
        };
        let Some(d) = octets.get(descripteur..descripteur + 20) else {
            return (dlls, true);
        };
        if d.iter().all(|&o| o == 0) {
            return (dlls, false);
        }
        if n == DLL_MAX {
            return (dlls, true);
        }
        let (Some(recherche), Some(nom), Some(adresses)) = (mot32_a(d, 0), mot32_a(d, 12), mot32_a(d, 16)) else {
            return (dlls, true);
        };
        let Some(dll) = chaine_rva(octets, sections, taille_entetes, nom) else {
            return (dlls, true);
        };
        let table = if recherche != 0 { recherche } else { adresses };
        let mut fonctions = Vec::new();
        let mut complete = false;
        for k in 0u32.. {
            if fonctions_lues >= FONCTIONS_MAX {
                break;
            }
            let Some(p) = k
                .checked_mul(largeur)
                .and_then(|d| table.checked_add(d))
                .and_then(|r| position_rva(sections, taille_entetes, r, largeur))
            else {
                break;
            };
            let (valeur, par_numero) = if pe32_plus {
                let Some(v) = mot64_a(octets, p) else { break };
                (v & 0x7FFF_FFFF, v & (1 << 63) != 0)
            } else {
                let Some(v) = mot32_a(octets, p) else { break };
                (u64::from(v & 0x7FFF_FFFF), v & (1 << 31) != 0)
            };
            if valeur == 0 && !par_numero {
                complete = true;
                break;
            }
            fonctions_lues += 1;
            if par_numero {
                fonctions.push(format!("#{}", valeur & 0xFFFF));
            } else {
                // Hint/Name : un indice de 2 octets, puis le nom.
                let nom = u32::try_from(valeur)
                    .ok()
                    .and_then(|r| r.checked_add(2))
                    .and_then(|r| chaine_rva(octets, sections, taille_entetes, r));
                fonctions.push(nom.unwrap_or_default());
            }
        }
        dlls.push(ImportPe { dll, fonctions });
        if !complete {
            return (dlls, true);
        }
    }
    (dlls, true)
}

#[cfg(test)]
pub(crate) mod essais {
    //! Un PE minimal fabriqué en Rust, pour les tests d'ici et de l'inventaire : aucun .exe tiers dans le dépôt.

    /// Les réglages d'un PE fabriqué : de quoi le rendre valide, ou abîmé d'une façon précise.
    #[derive(Clone)]
    pub(crate) struct Fabrique {
        pub machine: u16,
        pub pe32_plus: bool,
        pub fichier: [u16; 4],
        pub produit: [u16; 4],
        pub signature: u32,
        /// Décalage du répertoire de niveau 2 (depuis le début des ressources).
        pub niveau2: u32,
        pub niveau3: u32,
        /// Le troisième niveau pointe un sous-répertoire au lieu des données.
        pub trop_profond: bool,
        pub entrees_niveau1: u16,
        pub taille_version: Option<u32>,
        /// Ajouté à l'adresse des données de version (hors section).
        pub decalage_donnees: u32,
        pub e_lfanew: u32,
        pub taille_brute: Option<u32>,
    }

    impl Default for Fabrique {
        fn default() -> Self {
            Fabrique {
                machine: 0x8664,
                pe32_plus: true,
                fichier: [1, 2, 3, 4],
                produit: [5, 6, 7, 8],
                signature: super::SIGNATURE,
                niveau2: 0x18,
                niveau3: 0x30,
                trop_profond: false,
                entrees_niveau1: 1,
                taille_version: None,
                decalage_donnees: 0,
                e_lfanew: 0x40,
                taille_brute: None,
            }
        }
    }

    fn mot16(v: &mut [u8], a: usize, x: u16) {
        v[a..a + 2].copy_from_slice(&x.to_le_bytes());
    }

    fn mot32(v: &mut [u8], a: usize, x: u32) {
        v[a..a + 4].copy_from_slice(&x.to_le_bytes());
    }

    /// La ressource VS_VERSIONINFO, seule (sans StringFileInfo).
    fn version_info(f: &Fabrique) -> Vec<u8> {
        let mut v = vec![0u8; 92];
        mot16(&mut v, 0, 92);
        mot16(&mut v, 2, 52);
        for (i, c) in "VS_VERSION_INFO\0".encode_utf16().enumerate() {
            mot16(&mut v, 6 + 2 * i, c);
        }
        mot32(&mut v, 40, f.signature);
        mot32(&mut v, 44, 0x0001_0000);
        let ms = |q: [u16; 4]| (u32::from(q[0]) << 16) | u32::from(q[1]);
        let ls = |q: [u16; 4]| (u32::from(q[2]) << 16) | u32::from(q[3]);
        mot32(&mut v, 48, ms(f.fichier));
        mot32(&mut v, 52, ls(f.fichier));
        mot32(&mut v, 56, ms(f.produit));
        mot32(&mut v, 60, ls(f.produit));
        v
    }

    /// Un PE : en-tête DOS, en-têtes PE, une section « .rsrc » (RVA 0x1000, à 0x200 du fichier) qui contient l'arbre
    /// des ressources (types, noms, langues), l'entrée de données, puis VS_VERSIONINFO.
    pub(crate) fn pe(f: &Fabrique) -> Vec<u8> {
        const RVA: u32 = 0x1000;
        const BRUT: usize = 0x200;
        let mut v = vec![0u8; 0x400];
        v[..2].copy_from_slice(b"MZ");
        mot32(&mut v, 0x3C, f.e_lfanew);
        let pe = 0x40usize;
        v[pe..pe + 4].copy_from_slice(b"PE\0\0");
        mot16(&mut v, pe + 4, f.machine);
        mot16(&mut v, pe + 6, 1);
        let (magic, taille_facultatif, nombre, repertoires) = if f.pe32_plus {
            (0x20Bu16, 240u16, 108usize, 112usize)
        } else {
            (0x10B, 224, 92, 96)
        };
        mot16(&mut v, pe + 20, taille_facultatif);
        let facultatif = pe + 24;
        mot16(&mut v, facultatif, magic);
        mot32(&mut v, facultatif + nombre, 16);
        mot32(&mut v, facultatif + repertoires + 16, RVA);
        mot32(&mut v, facultatif + repertoires + 20, 0x200);
        let section = facultatif + usize::from(taille_facultatif);
        v[section..section + 5].copy_from_slice(b".rsrc");
        mot32(&mut v, section + 8, 0x200);
        mot32(&mut v, section + 12, RVA);
        mot32(&mut v, section + 16, f.taille_brute.unwrap_or(0x200));
        mot32(&mut v, section + 20, u32::try_from(BRUT).unwrap());
        // Niveau 1 (0x00) : n entrées à numéro, la dernière RT_VERSION.
        let r = BRUT;
        mot16(&mut v, r + 14, f.entrees_niveau1);
        for i in 0..usize::from(f.entrees_niveau1.min(1)) {
            mot32(&mut v, r + 16 + 8 * i, 16);
            mot32(&mut v, r + 20 + 8 * i, 0x8000_0000 | f.niveau2);
        }
        // Niveau 2 : un nom (1).
        let n2 = r + f.niveau2 as usize;
        mot16(&mut v, n2 + 14, 1);
        mot32(&mut v, n2 + 16, 1);
        mot32(&mut v, n2 + 20, 0x8000_0000 | f.niveau3);
        // Niveau 3 : une langue (0x409), qui désigne l'entrée de données à 0x48.
        let n3 = r + f.niveau3 as usize;
        mot16(&mut v, n3 + 14, 1);
        mot32(&mut v, n3 + 16, 0x409);
        mot32(&mut v, n3 + 20, if f.trop_profond { 0x8000_0048 } else { 0x48 });
        let donnees = version_info(f);
        let entree = r + 0x48;
        mot32(&mut v, entree, RVA + 0x60 + f.decalage_donnees);
        mot32(
            &mut v,
            entree + 4,
            f.taille_version.unwrap_or(u32::try_from(donnees.len()).unwrap()),
        );
        v[r + 0x60..r + 0x60 + donnees.len()].copy_from_slice(&donnees);
        v
    }

    /// Un PE32+ qui porte des gardes (`lire_gardes`) : une section « .rdata » (RVA 0x1000, à 0x200 du fichier) où
    /// commence le Load Config — (taille écrite dans la structure, taille annoncée par le répertoire n° 10,
    /// DependentLoadFlags), absent si `None` — et une section « .rsrc » (RVA 0x2000, à 0x400) dont l'arbre a un seul
    /// manifeste (RT_MANIFEST, au `numero` donné, langue 0x409), sans ressources si `None`.
    pub(crate) fn gardes_d_essai(
        load_config: Option<(u32, u32, u16)>,
        manifeste: Option<&[u8]>,
        numero: u32,
    ) -> Vec<u8> {
        let mut v = vec![0u8; 0x800];
        v[..2].copy_from_slice(b"MZ");
        mot32(&mut v, 0x3C, 0x40);
        v[0x40..0x44].copy_from_slice(b"PE\0\0");
        mot16(&mut v, 0x44, 0x8664);
        mot16(&mut v, 0x46, 2);
        mot16(&mut v, 0x54, 240);
        let facultatif = 0x58;
        mot16(&mut v, facultatif, 0x20B);
        mot32(&mut v, facultatif + 108, 16);
        let repertoires = facultatif + 112;
        if let Some((taille, taille_repertoire, drapeaux)) = load_config {
            mot32(&mut v, repertoires + 80, 0x1000);
            mot32(&mut v, repertoires + 84, taille_repertoire);
            mot32(&mut v, 0x200, taille);
            mot16(&mut v, 0x200 + 78, drapeaux);
        }
        let table = facultatif + 240;
        for (i, (nom, rva, brut)) in [(&b".rdata"[..], 0x1000u32, 0x200u32), (&b".rsrc"[..], 0x2000, 0x400)]
            .into_iter()
            .enumerate()
        {
            let s = table + 40 * i;
            v[s..s + nom.len()].copy_from_slice(nom);
            mot32(&mut v, s + 8, 0x200);
            mot32(&mut v, s + 12, rva);
            mot32(&mut v, s + 16, 0x200);
            mot32(&mut v, s + 20, brut);
        }
        if let Some(manifeste) = manifeste {
            mot32(&mut v, repertoires + 16, 0x2000);
            mot32(&mut v, repertoires + 20, 0x200);
            let r = 0x400;
            // Niveau 1 : RT_MANIFEST ; niveau 2 : le numéro ; niveau 3 : une langue, qui désigne l'entrée à 0x48.
            for (niveau, nom, suite) in [
                (0, 24, 0x8000_0018u32),
                (0x18, numero, 0x8000_0030),
                (0x30, 0x409, 0x48),
            ] {
                mot16(&mut v, r + niveau + 14, 1);
                mot32(&mut v, r + niveau + 16, nom);
                mot32(&mut v, r + niveau + 20, suite);
            }
            mot32(&mut v, r + 0x48, 0x2060);
            mot32(&mut v, r + 0x4C, u32::try_from(manifeste.len()).unwrap());
            v[r + 0x60..r + 0x60 + manifeste.len()].copy_from_slice(manifeste);
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::essais::{Fabrique, gardes_d_essai, pe};
    use super::*;
    use std::io::Cursor;

    fn lu(octets: &[u8]) -> Option<InfoPe> {
        lire(&mut Cursor::new(octets), octets.len() as u64)
    }

    #[test]
    fn version_et_architecture() {
        for (machine, attendue) in [
            (0x8664, Machine::X64),
            (0x014c, Machine::X86),
            (0xAA64, Machine::Arm64),
            (0x01c4, Machine::Autre(0x01c4)),
        ] {
            for pe32_plus in [true, false] {
                let f = Fabrique {
                    machine,
                    pe32_plus,
                    fichier: [156, 0, 8078, 48],
                    produit: [156, 0, 8078, 47],
                    ..Fabrique::default()
                };
                assert_eq!(
                    lu(&pe(&f)),
                    Some(InfoPe {
                        fichier: [156, 0, 8078, 48],
                        produit: [156, 0, 8078, 47],
                        machine: attendue
                    }),
                    "{machine:x} {pe32_plus}"
                );
            }
        }
    }

    #[test]
    fn formes_hostiles_refusees() {
        let refuse = |f: Fabrique, quoi: &str| assert_eq!(lu(&pe(&f)), None, "{quoi}");
        refuse(
            Fabrique {
                e_lfanew: 0x2000,
                ..Fabrique::default()
            },
            "e_lfanew hors fichier",
        );
        refuse(
            Fabrique {
                e_lfanew: 0x41,
                ..Fabrique::default()
            },
            "e_lfanew qui ne désigne pas « PE »",
        );
        refuse(
            Fabrique {
                signature: 0xFEEF_04BC,
                ..Fabrique::default()
            },
            "signature fausse",
        );
        refuse(
            Fabrique {
                entrees_niveau1: 0,
                ..Fabrique::default()
            },
            "répertoire sans entrée",
        );
        refuse(
            Fabrique {
                entrees_niveau1: 2000,
                ..Fabrique::default()
            },
            "trop d'entrées",
        );
        refuse(
            Fabrique {
                niveau3: 0x18,
                niveau2: 0x30,
                ..Fabrique::default()
            },
            "arbre qui revient en arrière",
        );
        refuse(
            Fabrique {
                trop_profond: true,
                ..Fabrique::default()
            },
            "quatrième niveau",
        );
        refuse(
            Fabrique {
                taille_version: Some(0),
                ..Fabrique::default()
            },
            "taille 0",
        );
        refuse(
            Fabrique {
                taille_version: Some(1 << 20),
                ..Fabrique::default()
            },
            "taille démesurée",
        );
        refuse(
            Fabrique {
                decalage_donnees: 0x1000,
                ..Fabrique::default()
            },
            "données hors section",
        );
        refuse(
            Fabrique {
                taille_brute: Some(0x10_0000),
                ..Fabrique::default()
            },
            "section qui déborde du fichier",
        );
        // Coupé : à chaque endroit, jamais lu.
        let bon = pe(&Fabrique::default());
        for n in [0, 2, 0x3C, 0x44, 0x100, 0x200, 0x260, 0x2b0, bon.len() - 1] {
            assert_eq!(lu(&bon[..n]), None, "coupé à {n}");
        }
        assert_eq!(lu(b"#!/bin/sh\n"), None);
    }

    fn gardes_lues(octets: &[u8]) -> Option<Gardes> {
        lire_gardes(&mut Cursor::new(octets), octets.len() as u64)
    }

    #[test]
    fn gardes_d_un_pe_fabrique() {
        let manifeste = b"<assembly>asInvoker UTF-8</assembly>";
        let g = gardes_lues(&gardes_d_essai(Some((148, 148, 0x800)), Some(manifeste), 1)).unwrap();
        let lc = g.load_config.unwrap();
        assert_eq!(
            lc,
            LoadConfig {
                taille_repertoire: 148,
                taille: 148,
                drapeaux: 0x800
            }
        );
        assert!(lc.system32_seulement());
        assert_eq!(g.manifeste.as_deref(), Some(&manifeste[..]));
        // Rien : un PE sans Load Config ni ressources reste un PE.
        assert_eq!(
            gardes_lues(&gardes_d_essai(None, None, 1)),
            Some(Gardes {
                load_config: None,
                manifeste: None
            })
        );
        // Un manifeste sous un autre numéro n'est pas celui du processus.
        assert_eq!(
            gardes_lues(&gardes_d_essai(None, Some(manifeste), 2))
                .unwrap()
                .manifeste,
            None
        );
        // Une taille qui ne couvre pas le champ, de l'un ou l'autre côté : Windows ne le lit pas.
        for (taille, repertoire) in [(79, 148), (148, 79), (0, 0), (79, 79), (148, 80), (80, 148)] {
            let g = gardes_lues(&gardes_d_essai(Some((taille, repertoire, 0x800)), None, 1)).unwrap();
            assert!(!g.load_config.unwrap().system32_seulement(), "{taille} {repertoire}");
        }
        assert!(
            LoadConfig {
                taille_repertoire: 80,
                taille: 80,
                drapeaux: SYSTEM32_SEULEMENT
            }
            .system32_seulement()
        );
        assert_eq!(gardes_lues(b"MZ"), None);
        assert_eq!(gardes_lues(&[]), None);
    }

    #[test]
    fn gardes_formes_refusees() {
        let bon = gardes_d_essai(Some((148, 148, 0x800)), Some(b"asInvoker"), 1);
        let repertoire = 0x58 + 112 + 80;
        // PE32 (32 bits) : le Load Config n'a pas cette forme, il n'est pas lu.
        let mut pe32 = bon.clone();
        pe32[0x58..0x5A].copy_from_slice(&0x10Bu16.to_le_bytes());
        assert_eq!(gardes_lues(&pe32).unwrap().load_config, None);
        // Un RVA hors de toute section, ou au bord de la section : les 80 octets n'y sont pas.
        for rva in [0x9000u32, 0x1000 + 0x200 - 40] {
            let mut hors = bon.clone();
            hors[repertoire..repertoire + 4].copy_from_slice(&rva.to_le_bytes());
            assert_eq!(gardes_lues(&hors).unwrap().load_config, None, "{rva:x}");
        }
        // Le Load Config au-delà de la taille virtuelle de la section (hors de l'image chargée), même dans le fichier.
        let mut virtuelle = bon.clone();
        let section = 0x58 + 240;
        virtuelle[section + 8..section + 12].copy_from_slice(&40u32.to_le_bytes());
        assert_eq!(gardes_lues(&virtuelle).unwrap().load_config, None);
        // Moins de 11 répertoires annoncés : le n° 10 n'existe pas.
        let mut peu = bon.clone();
        peu[0x58 + 108..0x58 + 112].copy_from_slice(&10u32.to_le_bytes());
        assert_eq!(gardes_lues(&peu).unwrap().load_config, None);
        // Tronqué au milieu du Load Config, ou avant les en-têtes.
        assert_eq!(gardes_lues(&bon[..0x200 + 40]), None);
        assert_eq!(gardes_lues(&bon[..0x60]), None);
        // e_lfanew démesuré.
        let mut loin = bon.clone();
        loin[0x3C..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(gardes_lues(&loin), None);
    }

    #[test]
    fn fichier_ordinaire_seulement() {
        let dossier = std::env::temp_dir().join(format!("vanguard-pe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).unwrap();
        let exe = dossier.join("chrome.exe");
        std::fs::write(&exe, pe(&Fabrique::default())).unwrap();
        assert_eq!(version(&exe).map(|i| i.fichier), Ok([1, 2, 3, 4]));
        // Un dossier : refusé à l'ouverture sous Windows, refusé comme pas un fichier ailleurs.
        if cfg!(windows) {
            assert!(version(&dossier).is_err());
        } else {
            assert_eq!(version(&dossier), Err(Echec::PasUnFichier));
        }
        assert!(matches!(version(&dossier.join("absent.exe")), Err(Echec::Ouverture(_))));
        std::fs::write(&exe, b"MZ").unwrap();
        assert_eq!(version(&exe), Err(Echec::Format));
        std::fs::remove_dir_all(&dossier).unwrap();
    }

    /// Sous Windows (Wine) : notre propre programme, compilé à côté des tests, porte la version de Cargo.toml
    /// (winresource la grave à la compilation). Absent : le test le dit et sort.
    #[cfg(windows)]
    #[test]
    fn version_de_vanguard_exe() {
        let Some(exe) = std::env::current_exe()
            .ok()
            .and_then(|t| Some(t.parent()?.parent()?.join("vanguard.exe")))
            .filter(|e| e.is_file())
        else {
            return crate::essais::saute("vanguard.exe pas encore compilé à côté des tests : version non vérifiée");
        };
        let info = version(&exe).unwrap_or_else(|e| panic!("{}: {e:?}", exe.display()));
        let attendue: Vec<u16> = env!("CARGO_PKG_VERSION")
            .split('.')
            .map(|n| n.parse().unwrap())
            .collect();
        assert_eq!(&info.fichier[..3], &attendue[..], "{}", exe.display());
        assert_eq!(info.machine, Machine::X64);
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 2000, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn jamais_de_plantage(octets in proptest::collection::vec(proptest::num::u8::ANY, 0..1200)) {
            let _ = lu(&octets);
            let _ = gardes_lues(&octets);
            let mut mz = octets.clone();
            if mz.len() >= 0x40 {
                mz[..2].copy_from_slice(b"MZ");
                mz[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
            }
            let _ = lu(&mz);
            let _ = gardes_lues(&mz);
        }

        /// Un PE valide abîmé à quelques endroits : lu ou refusé, sans planter.
        #[test]
        fn pe_abime(changements in proptest::collection::vec((0usize..0x400, proptest::num::u8::ANY), 1..6), pe32 in proptest::bool::ANY) {
            let mut octets = pe(&Fabrique { pe32_plus: pe32, ..Fabrique::default() });
            for (i, x) in changements {
                octets[i] = x;
            }
            let _ = lu(&octets);
        }

        /// Un PE à gardes abîmé à quelques endroits : lu ou refusé, sans planter.
        #[test]
        fn gardes_abimees(changements in proptest::collection::vec((0usize..0x800, proptest::num::u8::ANY), 1..8)) {
            let mut octets = gardes_d_essai(Some((148, 148, 0x800)), Some(b"asInvoker UTF-8"), 1);
            for (i, x) in changements {
                octets[i] = x;
            }
            let _ = gardes_lues(&octets);
        }
    }
}

//! Les fichiers d'une archive zip : seulement des fichiers stockés tels quels ou compressés (deflate), sans zip64 ni
//! chiffrement, comme tldr-pages en publie. Le répertoire central est cherché depuis la fin, puis chaque entrée lue à
//! la position que donne son en-tête local.

use super::Bornes;

/// Les fichiers (nom, contenu). Une entrée illisible, hors des bornes ou dont le contenu n'a pas la taille annoncée
/// est sautée ; une archive illisible donne une liste vide. Au plus `entrees` entrées parcourues, `fichier` octets
/// par fichier, `total` en tout.
pub(crate) fn lire(octets: &[u8], bornes: &Bornes) -> Vec<(String, Vec<u8>)> {
    // La fin du répertoire central, cherchée depuis la fin (un commentaire peut la suivre).
    let Some(fin) = (0..octets.len().saturating_sub(21))
        .rev()
        .take(65_557)
        .find(|&i| u32_a(octets, i) == Some(0x0605_4b50))
    else {
        return Vec::new();
    };
    let (Some(nombre), Some(debut)) = (u16_a(octets, fin + 10), u32_a(octets, fin + 16)) else {
        return Vec::new();
    };
    let mut fichiers = Vec::new();
    let mut total = 0;
    let mut i = debut as usize;
    for _ in 0..usize::from(nombre).min(bornes.entrees) {
        if u32_a(octets, i) != Some(0x0201_4b50) {
            break;
        }
        let Some((methode, compresse, taille, longueur_nom, autres, local)) = entree_centrale(octets, i) else {
            break;
        };
        let nom = octets
            .get(i + 46..i + 46 + longueur_nom)
            .map(|n| String::from_utf8_lossy(n).into_owned());
        i += 46 + longueur_nom + autres;
        let Some(nom) = nom else { break };
        if taille > bornes.fichier || total + taille > bornes.total {
            continue;
        }
        let donnees = donnees_locales(octets, local, compresse);
        // La taille rendue doit être celle annoncée, qui a passé les bornes : une entrée qui ment (annoncée minuscule,
        // décompressée bien plus grande) ferait sinon dépasser la borne du total.
        let contenu = match (methode, donnees) {
            (0, Some(d)) if d.len() == taille => Some(d.to_vec()),
            (8, Some(d)) => miniz_oxide::inflate::decompress_to_vec_with_limit(d, taille)
                .ok()
                .filter(|c| c.len() == taille),
            _ => None,
        };
        if let Some(contenu) = contenu {
            total += contenu.len();
            fichiers.push((nom, contenu));
        }
    }
    fichiers
}

/// Pourquoi une archive n'est pas intacte (`controler`) ; le numéro est celui de l'entrée dans le répertoire central.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Defaut {
    /// Pas de fin de répertoire central : pas un zip, ou coupé.
    PasUnZip,
    /// Zip64, ou une archive sur plusieurs disques : ces champs ne disent alors plus rien, tldr-pages n'en fait pas.
    NonPrise,
    /// Trop d'entrées, ou une entrée (ou leur somme) annoncée plus grande que les bornes : refusée sans décompresser.
    Demesuree,
    /// Une entrée illisible : en-tête coupé, nom différent dans l'en-tête local, contenu de la mauvaise taille.
    Illisible(usize),
    /// Chiffrée, ou ni stockée ni compressée par deflate.
    Methode(usize),
    /// Lue, mais son CRC-32 n'est pas celui annoncé.
    Crc(usize),
}

/// Une entrée relue par `controler`, avant d'être décompressée.
struct Entree<'a> {
    nom: &'a [u8],
    methode: u16,
    crc: u32,
    taille: usize,
    local: usize,
    donnees: std::ops::Range<usize>,
}

/// Le contrôle entier d'une archive, comme `zipfile.testzip()` de Python : chaque entrée du répertoire central relue
/// à son en-tête local (même nom), décompressée, à sa taille et à son CRC-32 annoncés. Une seule qui ne va pas, et
/// l'archive entière est refusée (`lire`, lui, la saute). Au plus `entrees` entrées, `fichier` octets annoncés par
/// entrée et `total` en tout, jugés avant de décompresser. Rend les noms des entrées, dans l'ordre.
///
/// Deux passes : la forme d'abord, puis le contenu. Le répertoire central doit finir juste où commence sa fin (pas
/// d'entrée cachée au-delà du nombre annoncé), et les entrées ne se chevauchent pas, comme le veut zipfile : chaque
/// octet compressé n'est donc décompressé qu'une fois, et une archive où mille entrées désignent les mêmes 36 Mo ne
/// coûte pas mille décompressions.
pub(crate) fn controler(octets: &[u8], bornes: &Bornes) -> Result<Vec<String>, Defaut> {
    let fin = (0..octets.len().saturating_sub(21))
        .rev()
        .take(65_557)
        .find(|&i| u32_a(octets, i) == Some(0x0605_4b50))
        .ok_or(Defaut::PasUnZip)?;
    let champ16 = |d: usize| u16_a(octets, fin + d).ok_or(Defaut::PasUnZip);
    let (disque, disque_central, ici, nombre) = (champ16(4)?, champ16(6)?, champ16(8)?, champ16(10)?);
    let (taille_centrale, debut) = (
        u32_a(octets, fin + 12).ok_or(Defaut::PasUnZip)?,
        u32_a(octets, fin + 16).ok_or(Defaut::PasUnZip)?,
    );
    if disque != 0 || disque_central != 0 || ici != nombre || nombre == 0xFFFF {
        return Err(Defaut::NonPrise);
    }
    if taille_centrale == 0xFFFF_FFFF || debut == 0xFFFF_FFFF {
        return Err(Defaut::NonPrise);
    }
    if usize::from(nombre) > bornes.entrees {
        return Err(Defaut::Demesuree);
    }
    let (debut, taille_centrale) = (debut as usize, taille_centrale as usize);
    // Un répertoire qui ne finit pas là où commence sa fin : des octets devant l'archive, ou des entrées cachées.
    if debut.checked_add(taille_centrale) != Some(fin) {
        return Err(Defaut::Illisible(0));
    }
    // Première passe : la forme de chaque entrée, sans rien décompresser.
    let mut entrees = Vec::with_capacity(usize::from(nombre));
    let mut total: usize = 0;
    let mut i = debut;
    for n in 0..usize::from(nombre) {
        if u32_a(octets, i) != Some(0x0201_4b50) {
            return Err(Defaut::Illisible(n));
        }
        let (Some(drapeaux), Some(crc), Some((methode, compresse, taille, longueur_nom, autres, local))) =
            (u16_a(octets, i + 8), u32_a(octets, i + 16), entree_centrale(octets, i))
        else {
            return Err(Defaut::Illisible(n));
        };
        let nom = octets.get(i + 46..i + 46 + longueur_nom).ok_or(Defaut::Illisible(n))?;
        i += 46 + longueur_nom + autres;
        // Bit 0 : chiffrée ; bit 6 : chiffrement « fort ». Ni l'un ni l'autre ne se relit sans mot de passe.
        if drapeaux & 0x41 != 0 || !matches!(methode, 0 | 8) {
            return Err(Defaut::Methode(n));
        }
        total = total.saturating_add(taille);
        if taille > bornes.fichier || total > bornes.total {
            return Err(Defaut::Demesuree);
        }
        // Le nom de l'en-tête local doit être celui du répertoire central, comme le veut zipfile.
        let longueur_locale = u16_a(octets, local + 26).map(usize::from);
        if longueur_locale != Some(longueur_nom) || octets.get(local + 30..local + 30 + longueur_nom) != Some(nom) {
            return Err(Defaut::Illisible(n));
        }
        let donnees = donnees_locales(octets, local, compresse).ok_or(Defaut::Illisible(n))?;
        let depart = donnees.as_ptr() as usize - octets.as_ptr() as usize;
        entrees.push(Entree {
            nom,
            methode,
            crc,
            taille,
            local,
            donnees: depart..depart + compresse,
        });
    }
    if i != fin {
        return Err(Defaut::Illisible(usize::from(nombre)));
    }
    // Pas de chevauchement : rangées par position, chaque entrée (en-tête local et données) finit avant la suivante,
    // et la dernière avant le répertoire central.
    let mut ordre: Vec<usize> = (0..entrees.len()).collect();
    ordre.sort_by_key(|&k| entrees[k].local);
    for (j, &k) in ordre.iter().enumerate() {
        let suivante = ordre.get(j + 1).map_or(debut, |&s| entrees[s].local);
        if entrees[k].donnees.end > suivante {
            return Err(Defaut::Illisible(k));
        }
    }
    // Seconde passe : le contenu, à sa taille et à son CRC.
    let mut noms = Vec::with_capacity(entrees.len());
    for (n, e) in entrees.iter().enumerate() {
        let donnees = &octets[e.donnees.clone()];
        let contenu = match e.methode {
            0 => (donnees.len() == e.taille).then(|| donnees.to_vec()),
            // Un octet de marge : un contenu plus long que la taille annoncée se voit à sa longueur.
            _ => miniz_oxide::inflate::decompress_to_vec_with_limit(donnees, e.taille.saturating_add(1))
                .ok()
                .filter(|c| c.len() == e.taille),
        }
        .ok_or(Defaut::Illisible(n))?;
        if super::crc32::crc32(&contenu) != e.crc {
            return Err(Defaut::Crc(n));
        }
        noms.push(String::from_utf8_lossy(e.nom).into_owned());
    }
    Ok(noms)
}

fn u16_a(octets: &[u8], i: usize) -> Option<u16> {
    octets
        .get(i..i.checked_add(2)?)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32_a(octets: &[u8], i: usize) -> Option<u32> {
    octets
        .get(i..i.checked_add(4)?)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Une entrée du répertoire central : (méthode, taille compressée, taille, longueur du nom, longueur des champs qui
/// suivent le nom, position de l'en-tête local).
fn entree_centrale(octets: &[u8], i: usize) -> Option<(u16, usize, usize, usize, usize, usize)> {
    Some((
        u16_a(octets, i + 10)?,
        u32_a(octets, i + 20)? as usize,
        u32_a(octets, i + 24)? as usize,
        usize::from(u16_a(octets, i + 28)?),
        usize::from(u16_a(octets, i + 30)?) + usize::from(u16_a(octets, i + 32)?),
        u32_a(octets, i + 42)? as usize,
    ))
}

/// Les données d'un fichier, après son en-tête local.
fn donnees_locales(octets: &[u8], local: usize, compresse: usize) -> Option<&[u8]> {
    (u32_a(octets, local)? == 0x0403_4b50).then_some(())?;
    let depart = local + 30 + usize::from(u16_a(octets, local + 26)?) + usize::from(u16_a(octets, local + 28)?);
    octets.get(depart..depart.checked_add(compresse)?)
}

// --- Parcours entrée par entrée, pour l'analyse des fichiers (`analyse/`) ---
//
// `lire` saute ce qu'il ne lit pas et `controler` refuse tout pour une seule entrée : deux lectures faites pour une
// archive qu'on attend intacte (tldr-pages). Un fichier à analyser peut être fabriqué pour tromper un lecteur : il
// faut voir chaque entrée, même celles qu'un extracteur lirait et que le répertoire central tait, et dire pour
// chacune pourquoi elle n'est pas lue. D'où `parcourir` (la forme, sans rien décompresser) puis `extraire` (une
// entrée, bornée). Format : APPNOTE.TXT de PKWARE (4.3.7 en-tête local, 4.3.12 répertoire central, 4.3.14 à 4.3.16
// fins de répertoire, zip64 compris, 4.5.3 champ zip64, 4.6.9 nom Unicode d'Info-ZIP).

/// D'où vient une entrée vue par `parcourir`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Provenance {
    /// Du répertoire central, dans le nombre annoncé par sa fin.
    Centrale,
    /// Du répertoire central, au-delà du nombre annoncé : un lecteur qui se fie au nombre ne la voit pas.
    AuDelaDuNombre,
    /// Un en-tête local que le répertoire central ne désigne pas (ou pas de répertoire central du tout) : un
    /// extracteur qui lit les en-têtes à la suite (lecture en flux) la voit, un autre non.
    LocaleSeule,
}

/// Une entrée vue, avant décompression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Vue {
    /// Le nom tel qu'écrit (UTF-8 si `utf8`, sinon une page de code que le format ne dit pas).
    pub nom: Vec<u8>,
    /// Le nom de l'en-tête local, s'il se lit (pour une entrée centrale).
    pub nom_local: Option<Vec<u8>>,
    /// Le nom du champ Unicode d'Info-ZIP (0x7075), que certains extracteurs préfèrent au nom écrit.
    pub nom_unicode: Option<Vec<u8>>,
    pub utf8: bool,
    pub drapeaux: u16,
    pub methode: u16,
    pub crc: u32,
    pub compresse: u64,
    pub taille: u64,
    /// Position de l'en-tête local dans `octets` (décalage des octets placés devant l'archive compris).
    pub local: usize,
    /// Les octets compressés, s'ils sont dans le fichier. Pour une entrée locale seule dont la taille n'est écrite
    /// qu'après les données (bit 3), jusqu'à la fin du fichier : `taille_inconnue`.
    pub donnees: Option<std::ops::Range<usize>>,
    pub taille_inconnue: bool,
    pub provenance: Provenance,
}

/// Ce que `parcourir` a vu de l'archive.
#[allow(clippy::struct_excessive_bools)] // des constats, chacun pour lui-même
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Parcours {
    pub entrees: Vec<Vue>,
    /// La fin du répertoire central a été trouvée (sinon : coupée, ou pas une archive complète).
    pub fin_trouvee: bool,
    /// Le nombre d'entrées annoncé par la fin du répertoire central.
    pub annoncees: u64,
    /// Octets placés devant l'archive (programme auto-extractible, autre fichier collé devant).
    pub decalage: usize,
    pub zip64: bool,
    /// Archive sur plusieurs disques : les positions ne désignent pas ce fichier seul.
    pub multidisque: bool,
    /// Plus d'entrées que la borne : le reste n'est pas vu.
    pub limitees: bool,
    /// Le répertoire central annoncé ne se lit pas où il devrait (position hors du fichier, signature absente).
    pub central_illisible: bool,
    /// Où commence l'archive dans `octets` (le premier en-tête local vu).
    pub debut: usize,
}

fn u64_a(octets: &[u8], i: usize) -> Option<u64> {
    octets.get(i..i.checked_add(8)?).map(|b| {
        let mut m = [0u8; 8];
        m.copy_from_slice(b);
        u64::from_le_bytes(m)
    })
}

/// Le champ libre `id` d'une suite de champs (identifiant, longueur, données), s'il y est en entier.
fn champ_libre(champs: &[u8], id: u16) -> Option<&[u8]> {
    let mut i = 0usize;
    while i + 4 <= champs.len() {
        let (code, n) = (u16_a(champs, i)?, usize::from(u16_a(champs, i + 2)?));
        let donnees = champs.get(i + 4..i + 4 + n)?;
        if code == id {
            return Some(donnees);
        }
        i += 4 + n;
    }
    None
}

/// Les entrées de l'archive `octets`, sans rien décompresser : le répertoire central entier (même au-delà du nombre
/// annoncé), puis chaque en-tête local qu'il ne désigne pas. Au plus `entrees_max` entrées.
pub(crate) fn parcourir(octets: &[u8], entrees_max: usize) -> Parcours {
    let mut p = Parcours::default();
    let fin = (0..octets.len().saturating_sub(21))
        .rev()
        .take(65_557)
        .find(|&i| u32_a(octets, i) == Some(0x0605_4b50));
    if let Some(fin) = fin {
        p.fin_trouvee = true;
        central(octets, fin, entrees_max, &mut p);
    }
    locales_seules(octets, entrees_max, &mut p);
    p.debut = p.entrees.iter().map(|e| e.local).min().unwrap_or(0);
    p
}

/// Le répertoire central que désigne la fin trouvée en `fin` (APPNOTE 4.3.16, et 4.3.14-4.3.15 pour zip64).
fn central(octets: &[u8], fin: usize, entrees_max: usize, p: &mut Parcours) {
    let champ16 = |d: usize| u16_a(octets, fin + d).unwrap_or(0);
    let (disque, disque_central) = (champ16(4), champ16(6));
    let mut annoncees = u64::from(champ16(10));
    let mut taille_centrale = u64::from(u32_a(octets, fin + 12).unwrap_or(0));
    let mut debut = u64::from(u32_a(octets, fin + 16).unwrap_or(0));
    // La fin du répertoire central est là où celui-ci finit : sans zip64, juste devant elle.
    let mut fin_du_central = fin;
    // Zip64 : le localisateur (20 octets) juste devant la fin, qui désigne la fin zip64 (4.3.14, 4.3.15).
    if let Some(localisateur) = fin.checked_sub(20)
        && u32_a(octets, localisateur) == Some(0x0706_4b50)
    {
        p.zip64 = true;
        if let Some(position) = u64_a(octets, localisateur + 8).and_then(|v| usize::try_from(v).ok())
            && u32_a(octets, position) == Some(0x0606_4b50)
        {
            annoncees = u64_a(octets, position + 32).unwrap_or(annoncees);
            taille_centrale = u64_a(octets, position + 40).unwrap_or(taille_centrale);
            debut = u64_a(octets, position + 48).unwrap_or(debut);
            fin_du_central = position;
        }
    }
    p.annoncees = annoncees;
    p.multidisque = disque != 0 || disque_central != 0;
    // Des octets devant l'archive décalent toutes les positions écrites (un programme auto-extractible dont les
    // positions n'ont pas été corrigées) : le décalage est ce qui sépare le répertoire de sa position écrite.
    let attendu = (fin_du_central as u64).checked_sub(taille_centrale);
    let decalage = attendu.and_then(|a| a.checked_sub(debut)).unwrap_or(0);
    let decalage = usize::try_from(decalage).unwrap_or(0);
    p.decalage = decalage;
    let Some(mut i) = usize::try_from(debut).ok().and_then(|d| d.checked_add(decalage)) else {
        p.central_illisible = true;
        return;
    };
    if u32_a(octets, i) != Some(0x0201_4b50) && annoncees > 0 {
        p.central_illisible = true;
    }
    let mut n = 0u64;
    while i < fin_du_central && u32_a(octets, i) == Some(0x0201_4b50) {
        if p.entrees.len() >= entrees_max {
            p.limitees = true;
            return;
        }
        let Some((vue, suivante)) = entree_vue(octets, i, decalage, n < annoncees) else {
            p.central_illisible = true;
            return;
        };
        p.entrees.push(vue);
        i = suivante;
        n += 1;
    }
    if n < annoncees {
        p.central_illisible = true;
    }
}

/// L'entrée centrale en `i` et la position de la suivante.
fn entree_vue(octets: &[u8], i: usize, decalage: usize, annoncee: bool) -> Option<(Vue, usize)> {
    let drapeaux = u16_a(octets, i + 8)?;
    let methode = u16_a(octets, i + 10)?;
    let crc = u32_a(octets, i + 16)?;
    let mut compresse = u64::from(u32_a(octets, i + 20)?);
    let mut taille = u64::from(u32_a(octets, i + 24)?);
    let longueur_nom = usize::from(u16_a(octets, i + 28)?);
    let longueur_champs = usize::from(u16_a(octets, i + 30)?);
    let longueur_commentaire = usize::from(u16_a(octets, i + 32)?);
    let mut local = u64::from(u32_a(octets, i + 42)?);
    let nom = octets.get(i + 46..i + 46 + longueur_nom)?.to_vec();
    let champs = octets.get(i + 46 + longueur_nom..i + 46 + longueur_nom + longueur_champs)?;
    let suivante = i + 46 + longueur_nom + longueur_champs + longueur_commentaire;
    // Champ zip64 (4.5.3) : seulement les valeurs qui valent 0xFFFFFFFF, dans cet ordre.
    if let Some(z) = champ_libre(champs, 0x0001) {
        let mut j = 0;
        for valeur in [&mut taille, &mut compresse, &mut local] {
            if *valeur == 0xFFFF_FFFF
                && let Some(v) = u64_a(z, j)
            {
                *valeur = v;
                j += 8;
            }
        }
    }
    let nom_unicode = champ_libre(champs, 0x7075)
        .filter(|u| u.first() == Some(&1))
        .and_then(|u| u.get(5..))
        .map(<[u8]>::to_vec);
    let local = usize::try_from(local).ok()?.checked_add(decalage)?;
    let (nom_local, donnees) = match donnees_entree(octets, local, compresse) {
        Some((n, d)) => (Some(n), Some(d)),
        None => (None, None),
    };
    Some((
        Vue {
            nom,
            nom_local,
            nom_unicode,
            utf8: drapeaux & 0x0800 != 0,
            drapeaux,
            methode,
            crc,
            compresse,
            taille,
            local,
            donnees,
            taille_inconnue: false,
            provenance: if annoncee {
                Provenance::Centrale
            } else {
                Provenance::AuDelaDuNombre
            },
        },
        suivante,
    ))
}

/// Le nom de l'en-tête local en `local` et la place des `compresse` octets qui le suivent, s'ils sont dans le
/// fichier.
fn donnees_entree(octets: &[u8], local: usize, compresse: u64) -> Option<(Vec<u8>, std::ops::Range<usize>)> {
    (u32_a(octets, local)? == 0x0403_4b50).then_some(())?;
    let longueur_nom = usize::from(u16_a(octets, local + 26)?);
    let depart = local
        .checked_add(30 + longueur_nom)?
        .checked_add(usize::from(u16_a(octets, local + 28)?))?;
    let nom = octets.get(local + 30..local + 30 + longueur_nom)?.to_vec();
    let fin = depart.checked_add(usize::try_from(compresse).ok()?)?;
    (fin <= octets.len()).then_some((nom, depart..fin))
}

/// Les en-têtes locaux que le répertoire central ne désigne pas, ni ne contient dans les données d'une entrée qu'il
/// désigne (une archive stockée dans une autre a les siens : ils sont à elle).
fn locales_seules(octets: &[u8], entrees_max: usize, p: &mut Parcours) {
    // Les places connues, rangées et fusionnées : chaque signature trouvée s'y cherche par dichotomie, et un fichier
    // fait de signatures collées ne coûte pas une comparaison par entrée connue.
    let mut places: Vec<(usize, usize)> = p
        .entrees
        .iter()
        .map(|e| {
            let d = e.donnees.clone().unwrap_or(e.local..e.local);
            (e.local.min(d.start), d.end.max(e.local + 1))
        })
        .collect();
    places.sort_unstable();
    let mut fusion: Vec<(usize, usize)> = Vec::with_capacity(places.len());
    for (debut, fin) in places {
        match fusion.last_mut() {
            Some(der) if debut <= der.1 => der.1 = der.1.max(fin),
            _ => fusion.push((debut, fin)),
        }
    }
    let connue = |position: usize| {
        let k = fusion.partition_point(|&(debut, _)| debut <= position);
        k > 0 && position < fusion[k - 1].1
    };
    let mut i = 0usize;
    while let Some(trouve) = octets
        .get(i..)
        .and_then(|reste| reste.windows(4).position(|f| f == b"PK\x03\x04"))
    {
        let position = i + trouve;
        i = position + 4;
        if connue(position) {
            continue;
        }
        let Some(vue) = entree_locale(octets, position) else {
            continue;
        };
        if p.entrees.len() >= entrees_max {
            p.limitees = true;
            return;
        }
        // Les données d'une entrée locale de taille connue sont à elle : on reprend la recherche après.
        if let Some(d) = vue.donnees.as_ref().filter(|_| !vue.taille_inconnue) {
            i = i.max(d.end);
        }
        p.entrees.push(vue);
    }
}

/// L'entrée d'un en-tête local seul (4.3.7) : sa taille compressée y est écrite, sauf avec le bit 3, où elle ne
/// l'est qu'après les données ; les données courent alors jusqu'à la fin du fichier, et seul un flux deflate dit où
/// il finit.
fn entree_locale(octets: &[u8], local: usize) -> Option<Vue> {
    let drapeaux = u16_a(octets, local + 6)?;
    let methode = u16_a(octets, local + 8)?;
    let crc = u32_a(octets, local + 14)?;
    let compresse = u64::from(u32_a(octets, local + 18)?);
    let taille = u64::from(u32_a(octets, local + 22)?);
    let longueur_nom = usize::from(u16_a(octets, local + 26)?);
    let longueur_champs = usize::from(u16_a(octets, local + 28)?);
    let nom = octets.get(local + 30..local + 30 + longueur_nom)?.to_vec();
    let depart = local + 30 + longueur_nom + longueur_champs;
    if depart > octets.len() {
        return None;
    }
    let taille_inconnue = drapeaux & 0x0008 != 0 && compresse == 0;
    let donnees = if taille_inconnue {
        Some(depart..octets.len())
    } else {
        let fin = depart.checked_add(usize::try_from(compresse).ok()?)?;
        (fin <= octets.len()).then_some(depart..fin)
    };
    Some(Vue {
        nom_local: Some(nom.clone()),
        nom,
        nom_unicode: None,
        utf8: drapeaux & 0x0800 != 0,
        drapeaux,
        methode,
        crc,
        compresse,
        taille,
        local,
        donnees,
        taille_inconnue,
        provenance: Provenance::LocaleSeule,
    })
}

/// Pourquoi une entrée n'est pas extraite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refus {
    /// Chiffrée (bit 0 ou 6, ou méthode 99 d'AES) : rien ne se lit sans le mot de passe.
    Chiffree,
    /// Une méthode que Vanguard ne décompresse pas (bzip2, LZMA, zstd, deflate64…).
    Methode(u16),
    /// Les données ne sont pas dans le fichier, ou leur fin ne se connaît pas.
    Illisible,
}

/// Une entrée extraite : son contenu (entier ou non : `fin`), et si son CRC-32 est celui annoncé (`None` : contenu
/// pas entier, ou CRC écrit seulement après les données).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Extrait {
    pub contenu: Vec<u8>,
    pub fin: super::deflate::Fin,
    pub crc_juste: Option<bool>,
}

/// Le contenu de l'entrée `vue` de `octets`, au plus `limite` octets : stockée ou deflate seulement.
pub(crate) fn extraire(octets: &[u8], vue: &Vue, limite: usize) -> Result<Extrait, Refus> {
    use super::deflate::Fin;
    if vue.drapeaux & 0x41 != 0 || vue.methode == 99 {
        return Err(Refus::Chiffree);
    }
    let donnees = vue
        .donnees
        .clone()
        .and_then(|d| octets.get(d))
        .ok_or(Refus::Illisible)?;
    let (contenu, fin) = match vue.methode {
        0 if vue.taille_inconnue => return Err(Refus::Illisible),
        0 if donnees.len() > limite => (donnees[..limite].to_vec(), Fin::Limite),
        0 => (donnees.to_vec(), Fin::Complet),
        8 => {
            let lu = super::deflate::inflater(donnees, limite);
            (lu.contenu, lu.fin)
        }
        autre => return Err(Refus::Methode(autre)),
    };
    let crc_connu = !(vue.provenance == Provenance::LocaleSeule && vue.drapeaux & 0x0008 != 0);
    let crc_juste = (fin == Fin::Complet && crc_connu).then(|| super::crc32::crc32(&contenu) == vue.crc);
    Ok(Extrait {
        contenu,
        fin,
        crc_juste,
    })
}

#[cfg(test)]
pub(crate) mod essais {
    //! Des archives zip fabriquées pour les tests d'ici et de la clé (`guide::tldr::cle`) : aucun zip tiers.

    /// Un zip fabriqué ici : (nom, méthode, contenu), le CRC calculé par `crc32`, les tailles justes.
    pub(crate) fn archive_controlee(entrees: &[(&str, u16, &[u8])]) -> Vec<u8> {
        let mut zip = Vec::new();
        let mut central = Vec::new();
        for (nom, methode, contenu) in entrees {
            let donnees = if *methode == 8 {
                miniz_oxide::deflate::compress_to_vec(contenu, 6)
            } else {
                contenu.to_vec()
            };
            let local = u32::try_from(zip.len()).unwrap();
            let (crc, compresse, taille) = (
                super::super::crc32::crc32(contenu),
                u32::try_from(donnees.len()).unwrap(),
                u32::try_from(contenu.len()).unwrap(),
            );
            let longueur = u16::try_from(nom.len()).unwrap();
            zip.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            zip.extend_from_slice(&[20, 0, 0, 0]);
            zip.extend_from_slice(&methode.to_le_bytes());
            zip.extend_from_slice(&[0; 4]);
            for v in [crc, compresse, taille] {
                zip.extend_from_slice(&v.to_le_bytes());
            }
            zip.extend_from_slice(&longueur.to_le_bytes());
            zip.extend_from_slice(&[0, 0]);
            zip.extend_from_slice(nom.as_bytes());
            zip.extend_from_slice(&donnees);
            central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            central.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
            central.extend_from_slice(&methode.to_le_bytes());
            central.extend_from_slice(&[0; 4]);
            for v in [crc, compresse, taille] {
                central.extend_from_slice(&v.to_le_bytes());
            }
            central.extend_from_slice(&longueur.to_le_bytes());
            central.extend_from_slice(&[0; 12]);
            central.extend_from_slice(&local.to_le_bytes());
            central.extend_from_slice(nom.as_bytes());
        }
        let debut = u32::try_from(zip.len()).unwrap();
        let nombre = u16::try_from(entrees.len()).unwrap();
        let taille = u32::try_from(central.len()).unwrap();
        zip.extend_from_slice(&central);
        zip.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        zip.extend_from_slice(&[0; 4]);
        zip.extend_from_slice(&nombre.to_le_bytes());
        zip.extend_from_slice(&nombre.to_le_bytes());
        zip.extend_from_slice(&taille.to_le_bytes());
        zip.extend_from_slice(&debut.to_le_bytes());
        zip.extend_from_slice(&[0, 0]);
        zip
    }
}

#[cfg(test)]
mod tests {
    use super::essais::archive_controlee;
    use super::*;

    /// Une archive zip faite à la main : (nom, données telles qu'écrites, méthode, taille annoncée) par entrée.
    fn archive(entrees: &[(&str, Vec<u8>, u16, u32)]) -> Vec<u8> {
        let (mut zip, mut central) = (Vec::new(), Vec::new());
        for (nom, donnees, methode, taille) in entrees {
            let local = u32::try_from(zip.len()).unwrap();
            let compresse = u32::try_from(donnees.len()).unwrap();
            let longueur = u16::try_from(nom.len()).unwrap();
            zip.extend(0x0403_4b50u32.to_le_bytes());
            zip.extend([20, 0, 0, 0]);
            zip.extend(methode.to_le_bytes());
            zip.extend([0u8; 8]);
            zip.extend(compresse.to_le_bytes());
            zip.extend(taille.to_le_bytes());
            zip.extend(longueur.to_le_bytes());
            zip.extend([0, 0]);
            zip.extend(nom.as_bytes());
            zip.extend(donnees);
            central.extend(0x0201_4b50u32.to_le_bytes());
            central.extend([20, 0, 20, 0, 0, 0]);
            central.extend(methode.to_le_bytes());
            central.extend([0u8; 8]);
            central.extend(compresse.to_le_bytes());
            central.extend(taille.to_le_bytes());
            central.extend(longueur.to_le_bytes());
            central.extend([0u8; 12]);
            central.extend(local.to_le_bytes());
            central.extend(nom.as_bytes());
        }
        let debut = u32::try_from(zip.len()).unwrap();
        let n = u16::try_from(entrees.len()).unwrap();
        let taille_centrale = u32::try_from(central.len()).unwrap();
        zip.extend(central);
        zip.extend(0x0605_4b50u32.to_le_bytes());
        zip.extend([0, 0, 0, 0]);
        zip.extend(n.to_le_bytes());
        zip.extend(n.to_le_bytes());
        zip.extend(taille_centrale.to_le_bytes());
        zip.extend(debut.to_le_bytes());
        zip.extend([0, 0]);
        zip
    }

    #[test]
    fn stockees_et_compressees() {
        let texte = b"# exemple\n\n> Une page inventee.\n".repeat(20);
        let deflate = miniz_oxide::deflate::compress_to_vec(&texte, 6);
        let taille = u32::try_from(texte.len()).unwrap();
        let zip = archive(&[
            ("pages/common/a.md", b"stockee".to_vec(), 0, 7),
            ("pages/common/b.md", deflate, 8, taille),
            ("pages/common/c.md", b"xx".to_vec(), 0, 3),
        ]);
        let bornes = Bornes {
            entrees: 10,
            fichier: 1 << 16,
            total: 1 << 16,
        };
        let lus = lire(&zip, &bornes);
        assert_eq!(lus.len(), 2, "la taille fausse de c.md l'écarte");
        assert_eq!(lus[0], ("pages/common/a.md".to_string(), b"stockee".to_vec()));
        assert_eq!(lus[1].1, texte);
    }

    /// Une entrée compressée qui ment sur sa taille (annoncée minuscule, décompressée bien plus grande) : écartée, et
    /// les bornes tiennent sur ce qui est rendu, pas sur ce qui est annoncé.
    #[test]
    fn taille_annoncee_fausse() {
        let gros = vec![b'a'; 60_000];
        let deflate = miniz_oxide::deflate::compress_to_vec(&gros, 6);
        let entrees: Vec<(String, Vec<u8>, u16, u32)> = (0..20)
            .map(|i| (format!("pages/common/{i}.md"), deflate.clone(), 8, 1))
            .collect();
        let entrees: Vec<(&str, Vec<u8>, u16, u32)> = entrees
            .iter()
            .map(|(n, d, m, t)| (n.as_str(), d.clone(), *m, *t))
            .collect();
        let bornes = Bornes {
            entrees: 100,
            fichier: 1 << 16,
            total: 1 << 17,
        };
        let lus = lire(&archive(&entrees), &bornes);
        assert!(lus.iter().map(|(_, c)| c.len()).sum::<usize>() <= bornes.total);
        assert!(lus.is_empty(), "{} entrées rendues", lus.len());
    }

    const BORNES_CONTROLE: Bornes = Bornes {
        entrees: 100,
        fichier: 1 << 16,
        total: 1 << 17,
    };

    /// Ce que `zipfile.testzip()` refusait, et un peu plus : l'archive entière est refusée pour une seule entrée.
    #[test]
    fn controle_entier() {
        let texte: &[u8] = b"# tar\n\n> Archiver.\n\n- Creer :\n\n`tar cf a.tar b`\n";
        let bonne = archive_controlee(&[
            ("pages/", 0, b""),
            ("pages/common/tar.md", 8, texte),
            ("pages/linux/ls.md", 0, b"# ls\n"),
        ]);
        assert_eq!(
            controler(&bonne, &BORNES_CONTROLE),
            Ok(vec![
                "pages/".to_string(),
                "pages/common/tar.md".to_string(),
                "pages/linux/ls.md".to_string()
            ])
        );
        // Un octet de données inversé dans la page stockée : elle se lit encore (`lire` la rend), seul le CRC le voit.
        let position = bonne.windows(5).position(|f| f == b"# ls\n").unwrap();
        let mut inversee = bonne.clone();
        inversee[position + 2] ^= 0x20;
        assert_eq!(lire(&inversee, &BORNES_CONTROLE).len(), 3);
        assert_eq!(controler(&inversee, &BORNES_CONTROLE), Err(Defaut::Crc(2)));
        // Le CRC changé dans le répertoire central.
        let central = bonne
            .windows(4)
            .position(|f| f == 0x0201_4b50u32.to_le_bytes())
            .unwrap();
        let mut crc = bonne.clone();
        crc[central + 16] ^= 1;
        assert_eq!(controler(&crc, &BORNES_CONTROLE), Err(Defaut::Crc(0)));
        // Chiffrée (bit 0), ou chiffrement fort (bit 6), dans le répertoire central.
        for bit in [1u8, 0x40] {
            let mut chiffree = bonne.clone();
            chiffree[central + 8] |= bit;
            assert_eq!(controler(&chiffree, &BORNES_CONTROLE), Err(Defaut::Methode(0)));
        }
        // Méthode 12 (bzip2) : inconnue, refusée.
        let bzip = archive_controlee(&[("pages/linux/ls.md", 12, b"# ls\n")]);
        assert_eq!(controler(&bzip, &BORNES_CONTROLE), Err(Defaut::Methode(0)));
        // Un autre nom dans l'en-tête local que dans le répertoire central.
        let mut nom = bonne.clone();
        let local = nom.windows(19).position(|f| f == b"pages/common/tar.md").unwrap();
        nom[local] = b'P';
        assert_eq!(controler(&nom, &BORNES_CONTROLE), Err(Defaut::Illisible(1)));
        // Tronquée, ou sans fin de répertoire central.
        assert!(controler(&bonne[..bonne.len() / 2], &BORNES_CONTROLE).is_err());
        assert_eq!(controler(b"pas un zip", &BORNES_CONTROLE), Err(Defaut::PasUnZip));
        assert_eq!(controler(&[], &BORNES_CONTROLE), Err(Defaut::PasUnZip));
    }

    /// Ce que zipfile refuse aussi : des entrées qui se chevauchent (deux noms sur les mêmes données, ou l'une dans
    /// les données de l'autre), un répertoire central qui cache des entrées au-delà du nombre annoncé.
    #[test]
    fn controle_chevauchements_et_entrees_cachees() {
        let bonne = archive_controlee(&[("pages/a.md", 0, b"# a\n"), ("pages/b.md", 0, b"# b\n")]);
        assert!(controler(&bonne, &BORNES_CONTROLE).is_ok());
        let central = bonne
            .windows(4)
            .position(|f| f == 0x0201_4b50u32.to_le_bytes())
            .unwrap();
        let second = central + 46 + "pages/a.md".len();
        // La seconde entrée désigne l'en-tête local de la première (même nom pour passer le contrôle du nom).
        let mut meme = bonne.clone();
        meme[second + 42..second + 46].copy_from_slice(&0u32.to_le_bytes());
        meme[second + 46 + 6] = b'a';
        assert!(controler(&meme, &BORNES_CONTROLE).is_err());
        // La fin annonce une entrée, le répertoire en a deux.
        let fin = bonne.len() - 22;
        let mut cachee = bonne.clone();
        cachee[fin + 8..fin + 12].copy_from_slice(&[1, 0, 1, 0]);
        assert!(controler(&cachee, &BORNES_CONTROLE).is_err());
        // Des octets devant l'archive : les positions ne disent plus rien.
        let mut devant = b"MZ".to_vec();
        devant.extend_from_slice(&bonne);
        assert!(controler(&devant, &BORNES_CONTROLE).is_err());
        // Mille entrées vides du même nom sur les mêmes données compressées : refusées avant toute décompression.
        let vides: Vec<(&str, u16, &[u8])> = (0..1000).map(|_| ("pages/a.md", 8, &b""[..])).collect();
        let mut multiple = archive_controlee(&vides);
        let premier = multiple
            .windows(4)
            .position(|f| f == 0x0201_4b50u32.to_le_bytes())
            .unwrap();
        let mut j = premier;
        while multiple.get(j..j + 4) == Some(&0x0201_4b50u32.to_le_bytes()[..]) {
            let longueur = usize::from(u16::from_le_bytes([multiple[j + 28], multiple[j + 29]]));
            let local = u32::from_le_bytes(multiple[premier + 42..premier + 46].try_into().unwrap());
            multiple[j + 42..j + 46].copy_from_slice(&local.to_le_bytes());
            j += 46 + longueur;
        }
        assert!(controler(&multiple, &BORNES_CONTROLE).is_err());
    }

    /// Les formes que le lecteur ne sait pas lire, et les bornes, jugées avant de décompresser.
    #[test]
    fn controle_formes_et_bornes() {
        let bonne = archive_controlee(&[("pages/linux/ls.md", 0, b"# ls\n")]);
        let fin = bonne.len() - 22;
        // Une archive sur plusieurs disques, ou des entrées sur un autre disque.
        let mut disques = bonne.clone();
        disques[fin + 4] = 1;
        assert_eq!(controler(&disques, &BORNES_CONTROLE), Err(Defaut::NonPrise));
        let mut ailleurs = bonne.clone();
        ailleurs[fin + 8] = 0;
        assert_eq!(controler(&ailleurs, &BORNES_CONTROLE), Err(Defaut::NonPrise));
        // Les marques de zip64.
        let mut zip64 = bonne.clone();
        zip64[fin + 16..fin + 20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(controler(&zip64, &BORNES_CONTROLE), Err(Defaut::NonPrise));
        // Plus d'entrées que la borne.
        let noms: Vec<String> = (0..3).map(|n| format!("pages/common/{n}.md")).collect();
        let trois: Vec<(&str, u16, &[u8])> = noms.iter().map(|n| (n.as_str(), 0, &b"x"[..])).collect();
        let bornes = Bornes {
            entrees: 2,
            ..BORNES_CONTROLE
        };
        assert_eq!(controler(&archive_controlee(&trois), &bornes), Err(Defaut::Demesuree));
        // Une entrée annoncée trop grosse, ou leur somme : refusées sans être décompressées.
        let gros = vec![b'a'; 200_000];
        let bombe = archive_controlee(&[("pages/common/a.md", 8, &gros)]);
        assert_eq!(controler(&bombe, &BORNES_CONTROLE), Err(Defaut::Demesuree));
        let moyen = vec![b'a'; 50_000];
        let somme = archive_controlee(&[
            ("pages/common/a.md", 8, &moyen),
            ("pages/common/b.md", 8, &moyen),
            ("pages/common/c.md", 8, &moyen),
        ]);
        assert_eq!(controler(&somme, &BORNES_CONTROLE), Err(Defaut::Demesuree));
        // Une entrée qui ment sur sa taille (annoncée 1, décompressée en 50 000) : illisible.
        let mut ment = archive_controlee(&[("pages/common/a.md", 8, &moyen)]);
        let central = ment.windows(4).position(|f| f == 0x0201_4b50u32.to_le_bytes()).unwrap();
        ment[central + 24..central + 28].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(controler(&ment, &BORNES_CONTROLE), Err(Defaut::Illisible(0)));
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 2000, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn jamais_de_plantage(octets in proptest::collection::vec(proptest::num::u8::ANY, 0..600)) {
            let bornes = Bornes { entrees: 100, fichier: 1 << 12, total: 1 << 14 };
            let _ = lire(&octets, &bornes);
            let _ = controler(&octets, &bornes);
            // Une fin de répertoire central en queue : le parcours des entrées est essayé, pas seulement la recherche.
            let mut avec_fin = octets.clone();
            avec_fin.extend(0x0605_4b50u32.to_le_bytes());
            avec_fin.extend([0, 0, 0, 0, 3, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            let _ = lire(&avec_fin, &bornes);
            let _ = controler(&avec_fin, &bornes);
        }
    }
}

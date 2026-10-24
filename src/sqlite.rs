//! Un lecteur SQLite écrit pour Vanguard, sans bibliothèque ni programme sqlite3 : un fichier lu en mémoire, page par
//! page. Il compte les lignes d'une table (identifiants des navigateurs, sans en décoder une seule) et lit quelques
//! colonnes d'une table (la base des autorisations de macOS, TCC.db ; sous Linux, les dernières connexions de
//! lastlog2 et les sessions de wtmpdb). Lecture seule, bornée : une base abîmée ou
//! fabriquée (page qui renvoie à elle-même, débordement sans fin, arbre trop profond) est refusée, jamais suivie.
//! Le journal WAL n'est pas lu : l'appelant dit que les changements récents peuvent manquer.

/// Un fichier SQLite, lu en mémoire, juste assez pour compter les lignes d'une table : l'en-tête donne la taille des
/// pages, la page 1 porte la table des tables (sqlite_master) où se lit la page racine de « logins », puis l'arbre de
/// cette table se parcourt, feuille par feuille, en additionnant les nombres de cellules. Aucune cellule n'est décodée.
struct Sqlite<'a> {
    octets: &'a [u8],
    page: usize,
    /// Octets réservés à la fin de chaque page (presque toujours 0).
    reserve: usize,
}

/// Un entier variable de SQLite (1 à 9 octets) : (valeur, longueur).
fn varint(b: &[u8]) -> Option<(u64, usize)> {
    let mut v: u64 = 0;
    for (i, o) in b.iter().take(9).enumerate() {
        if i == 8 {
            return Some(((v << 8) | u64::from(*o), 9));
        }
        v = (v << 7) | u64::from(o & 0x7f);
        if o & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

fn u16be(b: &[u8], i: usize) -> Option<usize> {
    Some(usize::from(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?])))
}

fn u32be(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *b.get(i)?,
        *b.get(i + 1)?,
        *b.get(i + 2)?,
        *b.get(i + 3)?,
    ]))
}

/// Taille d'une colonne d'après son type de série (texte, blob, entier, nul) ; `None` pour un type inconnu.
fn taille_colonne(type_serie: u64) -> Option<usize> {
    Some(match type_serie {
        0 | 8 | 9 | 12 | 13 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 4,
        5 => 6,
        6 | 7 => 8,
        n if n >= 12 => usize::try_from((n - 12) / 2).ok()?,
        _ => return None,
    })
}

/// Un entier d'une colonne, d'après son type de série.
fn entier(type_serie: u64, b: &[u8]) -> Option<u64> {
    match type_serie {
        8 => Some(0),
        9 => Some(1),
        1..=6 => {
            let n = taille_colonne(type_serie)?;
            let mut v: u64 = 0;
            for o in b.get(..n)? {
                v = (v << 8) | u64::from(*o);
            }
            Some(v)
        }
        _ => None,
    }
}

impl<'a> Sqlite<'a> {
    fn ouvrir(octets: &'a [u8]) -> Option<Self> {
        if octets.get(..16)? != b"SQLite format 3\0" {
            return None;
        }
        let page = match u16be(octets, 16)? {
            1 => 65536,
            n if n.is_power_of_two() && n >= 512 => n,
            _ => return None,
        };
        Some(Sqlite {
            octets,
            page,
            reserve: usize::from(*octets.get(20)?),
        })
    }

    /// La page n (à partir de 1).
    fn page(&self, n: u32) -> Option<&'a [u8]> {
        let debut = usize::try_from(n).ok()?.checked_sub(1)?.checked_mul(self.page)?;
        self.octets.get(debut..debut.checked_add(self.page)?)
    }

    /// Les cellules d'une page d'arbre : (type de page, positions des cellules, enfant de droite).
    fn cellules(&self, numero: u32) -> Option<(u8, Vec<usize>, Option<u32>)> {
        let p = self.page(numero)?;
        let base = if numero == 1 { 100 } else { 0 };
        let genre = *p.get(base)?;
        let n = u16be(p, base + 3)?;
        let (droite, entete) = if genre == 0x05 || genre == 0x02 {
            (Some(u32be(p, base + 8)?), 12)
        } else {
            (None, 8)
        };
        let positions = (0..n)
            .map(|i| u16be(p, base + entete + 2 * i))
            .collect::<Option<Vec<usize>>>()?;
        Some((genre, positions, droite))
    }

    /// Nombre de lignes de l'arbre d'une table, à partir de sa page racine. Une page déjà vue est refusée : dans un
    /// vrai arbre, chaque page n'a qu'un parent ; un fichier abîmé dont une page renvoie à elle-même (ou plusieurs
    /// fois à la même) ferait sinon des milliards de chemins et figerait le bilan, malgré la limite de profondeur.
    fn compter(&self, racine: u32, profondeur: usize, vues: &mut std::collections::HashSet<u32>) -> Option<usize> {
        if profondeur > 20 || !vues.insert(racine) {
            return None;
        }
        let (genre, positions, droite) = self.cellules(racine)?;
        match genre {
            0x0d => Some(positions.len()),
            0x05 => {
                let p = self.page(racine)?;
                let mut total = 0;
                for pos in positions {
                    total += self.compter(u32be(p, pos)?, profondeur + 1, vues)?;
                }
                Some(total + self.compter(droite?, profondeur + 1, vues)?)
            }
            _ => None,
        }
    }

    /// La page racine de la table `nom`, lue dans sqlite_master (page 1 : type, name, tbl_name, rootpage, sql).
    fn racine_de(
        &self,
        nom: &str,
        page: u32,
        profondeur: usize,
        vues: &mut std::collections::HashSet<u32>,
    ) -> Option<u32> {
        if profondeur > 20 || !vues.insert(page) {
            return None;
        }
        let (genre, positions, droite) = self.cellules(page)?;
        let p = self.page(page)?;
        match genre {
            0x0d => {
                for pos in positions {
                    if let Some(r) = Self::ligne_de_master(p, pos, nom) {
                        return Some(r);
                    }
                }
                None
            }
            0x05 => positions
                .into_iter()
                .filter_map(|pos| u32be(p, pos))
                .chain(droite)
                .find_map(|enfant| self.racine_de(nom, enfant, profondeur + 1, vues)),
            _ => None,
        }
    }

    /// Une cellule de sqlite_master : la page racine si c'est la table `nom`. Les quatre premières colonnes tiennent
    /// toujours dans la partie locale de la cellule (seul le texte SQL, après elles, peut déborder).
    fn ligne_de_master(p: &[u8], pos: usize, nom: &str) -> Option<u32> {
        let (_, l1) = varint(p.get(pos..)?)?;
        let (_, l2) = varint(p.get(pos + l1..)?)?;
        let enregistrement = p.get(pos + l1 + l2..)?;
        let (taille_entete, l3) = varint(enregistrement)?;
        let taille_entete = usize::try_from(taille_entete).ok()?;
        let mut types = Vec::new();
        let mut i = l3;
        while i < taille_entete {
            let (t, l) = varint(enregistrement.get(i..taille_entete)?)?;
            types.push(t);
            i += l;
        }
        let [t_type, t_nom, t_table, t_racine, ..] = types[..] else {
            return None;
        };
        let mut i = taille_entete;
        let champ = |i: &mut usize, t: u64| -> Option<&[u8]> {
            let n = taille_colonne(t)?;
            let c = enregistrement.get(*i..i.checked_add(n)?)?;
            *i += n;
            Some(c)
        };
        let genre = champ(&mut i, t_type)?;
        let nom_lu = champ(&mut i, t_nom)?;
        champ(&mut i, t_table)?;
        let racine = champ(&mut i, t_racine)?;
        (genre == b"table" && nom_lu == nom.as_bytes())
            .then(|| entier(t_racine, racine))
            .flatten()
            .and_then(|r| u32::try_from(r).ok())
    }
}

/// Le nombre de lignes de la table `table` d'un fichier SQLite ; `None` si le fichier ne se lit pas ainsi.
pub(crate) fn compter_lignes(octets: &[u8], table: &str) -> Option<usize> {
    let db = Sqlite::ouvrir(octets)?;
    // L'octet de réserve ne change pas la lecture des en-têtes ; il est lu pour refuser un fichier incohérent.
    if db.reserve >= db.page {
        return None;
    }
    let racine = db.racine_de(table, 1, 0, &mut std::collections::HashSet::new())?;
    db.compter(racine, 0, &mut std::collections::HashSet::new())
}

// ───────────────────────────── Lire des colonnes ─────────────────────────────

#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub(crate) use colonnes::Valeur;
/// La lecture des colonnes ne sert qu'à macOS (TCC.db) ; ailleurs, seulement aux essais et au banc de fuzzing
/// (fuzz/, où cargo-fuzz pose `--cfg fuzzing`).
#[cfg(any(target_os = "macos", test, fuzzing))]
pub(crate) use colonnes::compteur;
#[cfg(any(target_os = "macos", target_os = "linux", test, fuzzing))]
pub(crate) use colonnes::lignes;

#[cfg(any(target_os = "macos", target_os = "linux", test, fuzzing))]
mod colonnes {
    use super::{Sqlite, taille_colonne, u32be, varint};
    use std::collections::HashSet;

    /// Une valeur lue dans une colonne. Les nombres à virgule et les blobs ne servent à aucun appelant : `Autre`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum Valeur {
        Nul,
        Entier(i64),
        Texte(String),
        Autre,
    }

    impl Valeur {
        pub(crate) fn entier(&self) -> Option<i64> {
            match self {
                Valeur::Entier(n) => Some(*n),
                _ => None,
            }
        }

        pub(crate) fn texte(&self) -> Option<&str> {
            match self {
                Valeur::Texte(t) => Some(t),
                _ => None,
            }
        }

        /// L'entier que lirait un programme qui demande un entier à SQLite (sqlite3_column_int) : un entier tel quel,
        /// et un texte par son début numérique (blancs, signe, chiffres ; aucun chiffre : 0). Une colonne INTEGER
        /// accepte un texte qui ne se convertit pas : lu comme entier seulement, « 2 » ou « 2x » rangé en texte
        /// échappait au contrôle, alors que le programme qui le lit y voit 2. `None` : nul, ou d'un autre type.
        #[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))] // bases TCC du Mac
        pub(crate) fn entier_lu(&self) -> Option<i64> {
            match self {
                Valeur::Entier(n) => Some(*n),
                Valeur::Texte(t) => {
                    let t = t.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
                    let (negatif, chiffres) = match t.as_bytes().first() {
                        Some(b'-') => (true, &t[1..]),
                        Some(b'+') => (false, &t[1..]),
                        _ => (false, t),
                    };
                    let mut n: i64 = 0;
                    for c in chiffres.bytes().take_while(u8::is_ascii_digit) {
                        n = n.saturating_mul(10).saturating_add(i64::from(c - b'0'));
                    }
                    Some(if negatif { -n } else { n })
                }
                _ => None,
            }
        }
    }

    /// Pages de débordement suivies pour une seule cellule : une ligne de TCC.db tient dans une page ; au-delà de 64
    /// pages (256 Ko avec des pages de 4 Ko), c'est une chaîne fabriquée ou qui boucle.
    const PAGES_DEBORDEMENT: usize = 64;
    /// Lignes lues au plus dans une table : TCC.db en a quelques centaines.
    const LIGNES_MAX: usize = 100_000;
    /// Valeurs créées au plus par un parcours (32 octets chacune, soit environ 32 Mo) : le budget d'octets ne suffit
    /// pas, car un en-tête fait de types 0 (Nul, aucun octet de corps) crée une valeur par octet de charge. Borne
    /// fixe, sans lien avec la taille du fichier, pour qu'une vraie TCC.db de petite taille ne soit jamais refusée.
    pub(super) const VALEURS_MAX: usize = 1_000_000;

    /// Un entier signé de 1 à 8 octets, poids fort d'abord (complément à deux).
    pub(super) fn signe(octets: &[u8]) -> i64 {
        let mut v: i64 = if octets.first().is_some_and(|o| o & 0x80 != 0) {
            -1
        } else {
            0
        };
        for o in octets {
            v = (v << 8) | i64::from(*o);
        }
        v
    }

    /// Les valeurs d'un enregistrement : un en-tête (sa taille, puis le type de série de chaque colonne), puis les
    /// colonnes à la suite. `None` : type inconnu (10, 11) ou enregistrement plus court que son en-tête.
    fn valeurs(charge: &[u8]) -> Option<Vec<Valeur>> {
        let (taille_entete, l) = varint(charge)?;
        let taille_entete = usize::try_from(taille_entete).ok()?;
        let entete = charge.get(..taille_entete)?;
        let mut types = Vec::new();
        let mut i = l;
        while i < taille_entete {
            let (t, n) = varint(entete.get(i..)?)?;
            types.push(t);
            i += n;
        }
        let mut pos = taille_entete;
        types
            .into_iter()
            .map(|t| {
                let n = taille_colonne(t)?;
                let champ = charge.get(pos..pos.checked_add(n)?)?;
                pos += n;
                Some(match t {
                    0 => Valeur::Nul,
                    1..=6 => Valeur::Entier(signe(champ)),
                    8 => Valeur::Entier(0),
                    9 => Valeur::Entier(1),
                    n if n >= 13 && n % 2 == 1 => Valeur::Texte(String::from_utf8_lossy(champ).into_owned()),
                    _ => Valeur::Autre,
                })
            })
            .collect()
    }

    /// Les colonnes d'un « CREATE TABLE » : (nom, alias du rowid). Le corps entre la première et la dernière parenthèse est
    /// coupé aux virgules de premier niveau (hors parenthèses et guillemets) ; chaque morceau commence par le nom de sa
    /// colonne, sauf les contraintes de table (PRIMARY KEY (…), FOREIGN KEY…), qui viennent après les colonnes. Une
    /// colonne « INTEGER PRIMARY KEY » n'est pas écrite dans la ligne : c'est le rowid.
    pub(super) fn colonnes_de(sql: &str) -> Option<Vec<(String, bool)>> {
        let corps = sql.get(sql.find('(')? + 1..sql.rfind(')')?)?;
        let mut morceaux = Vec::new();
        let (mut profondeur, mut guillemet, mut debut) = (0usize, None, 0);
        for (i, c) in corps.char_indices() {
            match (guillemet, c) {
                (Some(g), _) if c == g => guillemet = None,
                (None, '"' | '\'' | '`') => guillemet = Some(c),
                (None, '[') => guillemet = Some(']'),
                (None, '(') => profondeur += 1,
                (None, ')') => profondeur = profondeur.saturating_sub(1),
                (None, ',') if profondeur == 0 => {
                    morceaux.push(&corps[debut..i]);
                    debut = i + 1;
                }
                // Dans des guillemets, ou un caractère ordinaire.
                _ => {}
            }
        }
        morceaux.push(&corps[debut..]);
        let mut colonnes = Vec::new();
        for m in morceaux {
            let m = m.trim();
            let (nom, reste) = match m.chars().next()? {
                o @ ('"' | '`' | '[') => {
                    let f = if o == '[' { ']' } else { o };
                    let fin = m[1..].find(f)? + 1;
                    (&m[1..fin], &m[fin + 1..])
                }
                _ => m.split_once(char::is_whitespace).unwrap_or((m, "")),
            };
            let mot = nom.to_uppercase();
            if !m.starts_with(['"', '`', '['])
                && ["CONSTRAINT", "PRIMARY", "UNIQUE", "CHECK", "FOREIGN"].contains(&mot.as_str())
            {
                continue;
            }
            let reste = reste.split_whitespace().collect::<Vec<_>>().join(" ").to_uppercase();
            colonnes.push((nom.to_string(), reste.starts_with("INTEGER PRIMARY KEY")));
        }
        (!colonnes.is_empty()).then_some(colonnes)
    }

    impl Sqlite<'_> {
        /// Octets utiles d'une page (sans la réserve).
        fn utile(&self) -> usize {
            self.page - self.reserve
        }

        /// Une cellule d'une feuille de table (page `p`, position `pos`) : (rowid, enregistrement complet). Ce qui ne tient
        /// pas dans la page continue dans une chaîne de pages de débordement (4 octets : la suivante, puis la suite).
        pub(super) fn charge(&self, p: &[u8], pos: usize) -> Option<(i64, Vec<u8>)> {
            let (taille, l1) = varint(p.get(pos..)?)?;
            let (rowid, l2) = varint(p.get(pos + l1..)?)?;
            let taille = usize::try_from(taille).ok()?;
            let utile = self.utile();
            let max_local = utile.checked_sub(35)?;
            // La part gardée dans la page, calculée comme SQLite la calcule (format de fichier, § 1.6 : U, X, M, K).
            let local = if taille <= max_local {
                taille
            } else {
                let min_local = ((utile - 12) * 32 / 255).checked_sub(23)?;
                let essai = min_local + (taille - min_local) % (utile - 4);
                if essai <= max_local { essai } else { min_local }
            };
            let debut = pos + l1 + l2;
            let mut charge = p.get(debut..debut.checked_add(local)?)?.to_vec();
            let mut suivante = if local < taille {
                Some(u32be(p, debut + local)?)
            } else {
                None
            };
            let mut pages = 0;
            while charge.len() < taille {
                pages += 1;
                if pages > PAGES_DEBORDEMENT {
                    return None;
                }
                let page = self.page(suivante?)?;
                let morceau = (utile - 4).min(taille - charge.len());
                charge.extend_from_slice(page.get(4..4 + morceau)?);
                suivante = Some(u32be(page, 0)?);
            }
            Some((rowid.cast_signed(), charge))
        }

        /// Toutes les lignes de l'arbre d'une table, à partir de sa page racine : (rowid, valeurs). Une page déjà vue, un
        /// arbre de plus de 20 niveaux, plus de `LIGNES_MAX` lignes, plus d'octets de charge que `budget` ou plus de
        /// valeurs que `valeurs_max` : refusé (`None`), comme dans `compter`.
        fn parcourir(
            &self,
            racine: u32,
            profondeur: usize,
            vues: &mut HashSet<u32>,
            budget: &mut usize,
            valeurs_max: &mut usize,
            lignes: &mut Vec<(i64, Vec<Valeur>)>,
        ) -> Option<()> {
            if profondeur > 20 || !vues.insert(racine) {
                return None;
            }
            let (genre, positions, droite) = self.cellules(racine)?;
            let p = self.page(racine)?;
            match genre {
                0x0d => {
                    for pos in positions {
                        if lignes.len() >= LIGNES_MAX {
                            return None;
                        }
                        let (rowid, charge) = self.charge(p, pos)?;
                        // Chaque octet d'une charge n'est écrit qu'une fois dans le fichier : un total plus grand que
                        // le fichier vient de cellules ou de pages de débordement partagées, donc d'un fichier
                        // fabriqué (des Go recopiés, puis un arrêt net faute de mémoire).
                        *budget = budget.checked_sub(charge.len())?;
                        let v = valeurs(&charge)?;
                        *valeurs_max = valeurs_max.checked_sub(v.len())?;
                        lignes.push((rowid, v));
                    }
                }
                0x05 => {
                    for pos in positions {
                        self.parcourir(u32be(p, pos)?, profondeur + 1, vues, budget, valeurs_max, lignes)?;
                    }
                    self.parcourir(droite?, profondeur + 1, vues, budget, valeurs_max, lignes)?;
                }
                _ => return None,
            }
            Some(())
        }
    }

    /// Les colonnes `colonnes` (par leur nom, sans égard à la casse) de chaque ligne de la table `table`, dans cet ordre ;
    /// une colonne que la table n'a pas, ou qu'une ligne ancienne n'a pas encore (ALTER TABLE), vaut `Nul`. `None` : pas
    /// une base SQLite, table absente, ou fichier abîmé (jamais une table vide à sa place).
    pub(crate) fn lignes(octets: &[u8], table: &str, colonnes: &[&str]) -> Option<Vec<Vec<Valeur>>> {
        let db = Sqlite::ouvrir(octets)?;
        // Le format exige au moins 480 octets utiles par page : en dessous, le calcul du débordement n'a plus de sens.
        if db.reserve >= db.page || db.utile() < 480 {
            return None;
        }
        // sqlite_master (page 1) : type, name, tbl_name, rootpage, sql.
        let mut master = Vec::new();
        db.parcourir(
            1,
            0,
            &mut HashSet::new(),
            &mut octets.len(),
            &mut { VALEURS_MAX },
            &mut master,
        )?;
        let (racine, sql) = master.iter().find_map(|(_, v)| match v.as_slice() {
            [
                Valeur::Texte(genre),
                Valeur::Texte(nom),
                _,
                Valeur::Entier(r),
                Valeur::Texte(sql),
                ..,
            ] if genre == "table" && nom.eq_ignore_ascii_case(table) => Some((u32::try_from(*r).ok()?, sql.clone())),
            _ => None,
        })?;
        // La page 1 est celle de sqlite_master : une table qui y renvoie ferait relire le même arbre.
        if racine < 2 {
            return None;
        }
        drop(master);
        let schema = colonnes_de(&sql)?;
        let places: Vec<Option<(usize, bool)>> = colonnes
            .iter()
            .map(|c| {
                schema
                    .iter()
                    .position(|(n, _)| n.eq_ignore_ascii_case(c))
                    .map(|i| (i, schema[i].1))
            })
            .collect();
        let mut brutes = Vec::new();
        db.parcourir(
            racine,
            0,
            &mut HashSet::new(),
            &mut octets.len(),
            &mut { VALEURS_MAX },
            &mut brutes,
        )?;
        Some(
            brutes
                .into_iter()
                .map(|(rowid, v)| {
                    places
                        .iter()
                        .map(|place| match *place {
                            Some((i, true)) if matches!(v.get(i), None | Some(Valeur::Nul)) => Valeur::Entier(rowid),
                            Some((i, _)) => v.get(i).cloned().unwrap_or(Valeur::Nul),
                            None => Valeur::Nul,
                        })
                        .collect()
                })
                .collect(),
        )
    }

    /// Le compteur de changements du fichier (octets 24 à 27 de l'en-tête), qui avance à chaque écriture validée : deux
    /// lectures qui le voient différent n'ont pas lu la même base.
    #[cfg_attr(not(any(target_os = "macos", test, fuzzing)), allow(dead_code))]
    pub(crate) fn compteur(octets: &[u8]) -> Option<u32> {
        if octets.get(..16)? != b"SQLite format 3\0" {
            return None;
        }
        u32be(octets, 24)
    }
}

#[cfg(test)]
mod tests {
    use super::colonnes::{VALEURS_MAX, Valeur, colonnes_de, signe};
    use super::*;

    #[test]
    fn lignes_de_login_data_comptees_page_par_page() {
        let vide = include_bytes!("../assets/essais/login-data-vide.sqlite");
        let trois = include_bytes!("../assets/essais/login-data-3.sqlite");
        // 300 lignes sur des pages de 512 octets : l'arbre a des pages intérieures.
        let trois_cents = include_bytes!("../assets/essais/login-data-300.sqlite");
        assert_eq!(compter_lignes(vide, "logins"), Some(0));
        assert_eq!(compter_lignes(trois, "logins"), Some(3));
        assert_eq!(compter_lignes(trois_cents, "logins"), Some(300));
        assert_eq!(compter_lignes(trois, "meta"), Some(2));
        assert_eq!(compter_lignes(trois, "inexistante"), None);
        assert_eq!(compter_lignes(b"pas une base", "logins"), None);
        assert_eq!(compter_lignes(&trois[..3000], "logins"), None);
        // Un fichier abîmé : chaque cellule de la page racine (intérieure) renvoie à cette même page. Avant, des
        // milliards de chemins ; maintenant, refusé tout de suite.
        let db = Sqlite::ouvrir(trois_cents).unwrap();
        let racine = db
            .racine_de("logins", 1, 0, &mut std::collections::HashSet::new())
            .unwrap();
        let (genre, positions, _) = db.cellules(racine).unwrap();
        assert_eq!(genre, 0x05, "la racine doit être une page intérieure pour cet essai");
        let mut piege = trois_cents.to_vec();
        let debut = (racine as usize - 1) * db.page;
        for pos in positions {
            piege[debut + pos..debut + pos + 4].copy_from_slice(&racine.to_be_bytes());
        }
        let avant = std::time::Instant::now();
        assert_eq!(compter_lignes(&piege, "logins"), None);
        assert!(avant.elapsed() < std::time::Duration::from_secs(1));
        // Les entiers variables de SQLite.
        assert_eq!(varint(&[0x05]), Some((5, 1)));
        assert_eq!(varint(&[0x81, 0x00]), Some((128, 2)));
        assert_eq!(varint(&[0xff; 9]), Some((u64::MAX, 9)));
        assert_eq!(varint(&[0x80]), None);
        assert_eq!(taille_colonne(13), Some(0));
        assert_eq!(taille_colonne(27), Some(7));
        assert_eq!(taille_colonne(10), None);
        assert_eq!(entier(1, &[7]), Some(7));
        assert_eq!(entier(2, &[1, 0]), Some(256));
    }

    #[test]
    fn colonnes_de_tcc_lues_debordement_compris() {
        // Base inventée (python3, page de 512 octets) : le schéma de Big Sur, 205 lignes (pages intérieures), un client
        // de plus de 700 caractères (pages de débordement) ; le texte du schéma lui-même déborde de la page 1.
        let base = include_bytes!("../assets/essais/tcc-bigsur.sqlite");
        let l = lignes(
            base,
            "access",
            &["service", "client", "client_type", "auth_value", "allowed"],
        )
        .unwrap();
        assert_eq!(l.len(), 205);
        assert_eq!(
            l[0],
            vec![
                Valeur::Texte("kTCCServiceListenEvent".into()),
                Valeur::Texte("com.example.Clavier".into()),
                Valeur::Entier(0),
                Valeur::Entier(2),
                Valeur::Nul,
            ]
        );
        assert_eq!(l[1][1].texte(), Some("/Users/alice/Downloads/outil"));
        assert_eq!(l[1][2].entier(), Some(1));
        let long = l[4][1].texte().unwrap();
        assert!(long.starts_with("/Users/alice/Applications/xxx") && long.ends_with("/outil-long"));
        assert_eq!(
            long.len(),
            "/Users/alice/Applications/".len() + 700 + "/outil-long".len()
        );
        // Une autre table, et le rowid d'une clé texte (pas un alias) : la colonne se lit telle quelle.
        let admin = lignes(base, "ADMIN", &["key", "value"]).unwrap();
        assert_eq!(admin, vec![vec![Valeur::Texte("version".into()), Valeur::Entier(15)]]);
        assert_eq!(lignes(base, "inexistante", &["x"]), None);
        // Avant Big Sur : « allowed » à la place d'« auth_value ».
        let ancien = include_bytes!("../assets/essais/tcc-ancien.sqlite");
        let l = lignes(ancien, "access", &["service", "client", "auth_value", "allowed"]).unwrap();
        assert_eq!(l.len(), 3);
        assert_eq!((l[0][2].clone(), l[0][3].entier()), (Valeur::Nul, Some(1)));
        // Base tronquée, ou qui n'en est pas une : refusée, jamais une table vide.
        assert_eq!(lignes(&base[..base.len() / 2], "access", &["client"]), None);
        assert_eq!(lignes(b"pas une base", "access", &["client"]), None);
        assert_eq!(compteur(base).map(|c| c > 0), Some(true));
        assert_eq!(compteur(b"pas une base"), None);
    }

    #[test]
    fn debordement_qui_boucle_refuse() {
        // Une cellule qui annonce 10 Mo, dont la page de débordement renvoie à elle-même : sans la borne, 20 000 tours
        // et 10 Mo copiés ; avec, refusée après 64 pages.
        let mut octets = vec![0u8; 1024];
        octets[512..516].copy_from_slice(&2u32.to_be_bytes());
        let db = Sqlite {
            octets: &octets,
            page: 512,
            reserve: 0,
        };
        let mut cellule = vec![0x84, 0xe2, 0xad, 0x00, 0x01];
        assert_eq!(varint(&cellule), Some((10_000_000, 4)));
        let local = (500 * 32 / 255) - 23;
        cellule.extend(std::iter::repeat_n(b'x', local));
        cellule.extend(2u32.to_be_bytes());
        assert_eq!(db.charge(&cellule, 0), None);
        // La même chaîne, pour une cellule qui tient en trois pages : lue (la boucle ne se voit pas, la taille borne).
        let mut courte = vec![0x8b, 0x08, 0x01];
        assert_eq!(varint(&courte), Some((1416, 2)));
        let k = local + (1416 - local) % 508;
        courte.extend(std::iter::repeat_n(b'x', k));
        courte.extend(2u32.to_be_bytes());
        assert_eq!(db.charge(&courte, 0).map(|(r, c)| (r, c.len())), Some((1, 1416)));
    }

    /// Une base fabriquée de trois pages de 512 octets : sqlite_master (page 1) annonce la table « access » en page 2 ;
    /// la page 2 a `pointeurs` pointeurs vers une même cellule de 16 000 octets, dont la page de débordement (page 3)
    /// renvoie à elle-même.
    /// Un entier au format varint de SQLite (groupes de 7 bits, le bit haut annonce la suite).
    fn v(n: usize) -> Vec<u8> {
        let mut n = u64::try_from(n).unwrap();
        let mut groupes = vec![u8::try_from(n & 0x7f).unwrap()];
        n >>= 7;
        while n > 0 {
            groupes.push(u8::try_from(n & 0x7f).unwrap() | 0x80);
            n >>= 7;
        }
        groupes.reverse();
        groupes
    }

    /// La cellule de sqlite_master qui annonce la table « access » à la page `racine`.
    fn cellule_access(racine: u8) -> Vec<u8> {
        let sql = b"CREATE TABLE access (service TEXT, client TEXT)";
        let textes: [&[u8]; 3] = [b"table", b"access", b"access"];
        let mut entete: Vec<u8> = textes.iter().flat_map(|t| v(t.len() * 2 + 13)).collect();
        entete.push(1);
        entete.extend(v(sql.len() * 2 + 13));
        let mut charge = v(entete.len() + 1);
        charge.extend(entete);
        for t in textes {
            charge.extend_from_slice(t);
        }
        charge.push(racine);
        charge.extend_from_slice(sql);
        let mut cellule = v(charge.len());
        cellule.extend(v(1));
        cellule.extend(charge);
        cellule
    }

    fn base_a_cellule_partagee(pointeurs: usize) -> Vec<u8> {
        let mut b = vec![0u8; 3 * 512];
        b[..16].copy_from_slice(b"SQLite format 3\0");
        b[16..18].copy_from_slice(&512u16.to_be_bytes());
        // sqlite_master : type, name, tbl_name, rootpage, sql.
        let cellule = cellule_access(2);
        b[100] = 0x0d;
        b[103..105].copy_from_slice(&1u16.to_be_bytes());
        b[108..110].copy_from_slice(&300u16.to_be_bytes());
        b[300..300 + cellule.len()].copy_from_slice(&cellule);
        // La grande cellule : un texte de 15 996 octets ; 252 octets dans la page, le reste en débordement.
        let taille = 16_000;
        let mut charge = vec![4];
        charge.extend(v(15_996 * 2 + 13));
        charge.resize(252, b'x');
        let mut cellule = v(taille);
        cellule.extend(v(1));
        cellule.extend(charge);
        cellule.extend(3u32.to_be_bytes());
        let page2 = 512;
        b[page2] = 0x0d;
        b[page2 + 3..page2 + 5].copy_from_slice(&u16::try_from(pointeurs).unwrap().to_be_bytes());
        for i in 0..pointeurs {
            b[page2 + 8 + 2 * i..page2 + 10 + 2 * i].copy_from_slice(&200u16.to_be_bytes());
        }
        b[page2 + 200..page2 + 200 + cellule.len()].copy_from_slice(&cellule);
        b[1024..1028].copy_from_slice(&3u32.to_be_bytes());
        b[1028..].fill(b'x');
        b
    }

    #[test]
    fn cellule_partagee_refusee() {
        // Avant : chaque pointeur recopiait 16 000 octets (des Go avec des pages de 64 Ko et 100 000 lignes). Un
        // fichier de 1 536 octets ne peut pas porter plus de charge que sa taille : refusé.
        let base = base_a_cellule_partagee(90);
        assert!(lignes(&base, "access", &["service"]).is_none());
        assert!(lignes(&base_a_cellule_partagee(1), "access", &["service"]).is_none());
        // La table des tables, elle, se lit : seule la charge impossible est refusée.
        let db = Sqlite::ouvrir(&base).unwrap();
        assert_eq!(
            db.racine_de("access", 1, 0, &mut std::collections::HashSet::new()),
            Some(2)
        );
    }

    /// Une base fabriquée aux pages de 64 Ko : sqlite_master (page 1) annonce « access » en page `racine` ; la page 2
    /// est intérieure et mène à `feuilles` feuilles, chacune portant une cellule de 65 000 octets dont l'en-tête n'est
    /// fait que de types 0 (Nul, aucun octet de corps).
    fn base_a_nuls(racine: u8, feuilles: usize) -> Vec<u8> {
        const PAGE: usize = 65_536;
        let mut b = vec![0u8; (feuilles + 2) * PAGE];
        b[..16].copy_from_slice(b"SQLite format 3\0");
        // 1 dans l'en-tête : des pages de 65 536 octets.
        b[16..18].copy_from_slice(&1u16.to_be_bytes());
        let cellule = cellule_access(racine);
        b[100] = 0x0d;
        b[103..105].copy_from_slice(&1u16.to_be_bytes());
        b[108..110].copy_from_slice(&300u16.to_be_bytes());
        b[300..300 + cellule.len()].copy_from_slice(&cellule);
        // Page 2, intérieure : un enfant par cellule, la dernière feuille en pointeur de droite.
        let p2 = PAGE;
        b[p2] = 0x05;
        b[p2 + 3..p2 + 5].copy_from_slice(&u16::try_from(feuilles - 1).unwrap().to_be_bytes());
        b[p2 + 8..p2 + 12].copy_from_slice(&u32::try_from(feuilles + 2).unwrap().to_be_bytes());
        for i in 0..feuilles - 1 {
            let place = 20_000 + 5 * i;
            b[p2 + 12 + 2 * i..p2 + 14 + 2 * i].copy_from_slice(&u16::try_from(place).unwrap().to_be_bytes());
            b[p2 + place..p2 + place + 4].copy_from_slice(&u32::try_from(i + 3).unwrap().to_be_bytes());
            b[p2 + place + 4] = 1;
        }
        let taille = 65_000;
        for k in 3..feuilles + 3 {
            let d = (k - 1) * PAGE;
            // L'en-tête couvre toute la charge : sa taille, puis des zéros.
            let mut cellule = v(taille);
            cellule.extend(v(k));
            cellule.extend(v(taille));
            cellule.resize(cellule.len() + taille - v(taille).len(), 0);
            b[d] = 0x0d;
            b[d + 3..d + 5].copy_from_slice(&1u16.to_be_bytes());
            b[d + 8..d + 10].copy_from_slice(&100u16.to_be_bytes());
            b[d + 100..d + 100 + cellule.len()].copy_from_slice(&cellule);
        }
        b
    }

    #[test]
    fn valeurs_bornees_meme_sous_le_budget_d_octets() {
        // Avant : chaque octet d'en-tête devenait une valeur de 32 octets ; une base de 32 Mo (la taille admise) en
        // créait près d'un Go. Au-delà de VALEURS_MAX valeurs : refusé.
        let trop = VALEURS_MAX / 64_997 + 1;
        assert!(lignes(&base_a_nuls(2, trop), "access", &["service"]).is_none());
        // Sous la borne, la même forme se lit : une ligne par feuille.
        assert_eq!(
            lignes(&base_a_nuls(2, 2), "access", &["service"]).map(|l| l.len()),
            Some(2)
        );
        // Une table qui renvoie à la page 1 ferait relire sqlite_master comme si c'était elle : refusé.
        assert!(lignes(&base_a_nuls(1, 2), "access", &["service"]).is_none());
    }

    #[test]
    fn schema_coupe_aux_bonnes_virgules() {
        let c = colonnes_de(
            "CREATE TABLE t (\"a b\" TEXT, [c] INTEGER DEFAULT (f(1, 2)), d TEXT DEFAULT 'x,y', id INTEGER  primary key, \
             PRIMARY KEY (a), CONSTRAINT k UNIQUE (d))",
        )
        .unwrap();
        let noms: Vec<&str> = c.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(noms, ["a b", "c", "d", "id"]);
        assert_eq!(c.iter().filter(|(_, alias)| *alias).count(), 1);
        assert_eq!(colonnes_de("pas de parenthèses"), None);
        assert_eq!(signe(&[0xff]), -1);
        assert_eq!(signe(&[0x01, 0x00]), 256);
        assert_eq!(signe(&[0x80, 0, 0, 0, 0, 0, 0, 0]), i64::MIN);
    }
}

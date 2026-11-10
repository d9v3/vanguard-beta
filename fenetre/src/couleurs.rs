//! Les couleurs de la fenêtre, sans rien dessiner : les six préréglages acceptés (sombre et clair), les cinq couleurs
//! vives qu'on peut choisir (l'accent et les quatre couleurs de gravité), et les mesures de lisibilité (contraste
//! WCAG, écart OKLab). Les neutres (fonds, textes) restent ceux du préréglage choisi.
//!
//! Le même fichier sert à `vanguard` (src/parametres/couleurs.rs l'inclut par son chemin) : une seule table, un seul
//! calcul, et les mêmes refus des deux côtés. La fenêtre n'écrit jamais rien : elle propose un `Choix`, `vanguard`
//! le revérifie (`verifier`) et l'enregistre dans parametres.json, scellé.
//!
//! Prévenir sans interdire : un contraste sous 3:1 ou deux couleurs de gravité trop proches font une remarque
//! (`remarques`), jamais un refus. Seule une couleur presque invisible sur le fond du thème (sous 1,5:1) est refusée
//! (`verifier`) : une fenêtre prise ne pourrait pas enregistrer, pour les lancements suivants, des alertes noires sur
//! du noir.

/// Une couleur : rouge, vert, bleu.
pub type Rgb = [u8; 3];

/// Le thème réglé : chacun garde ses couleurs.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Theme {
    Sombre,
    Clair,
}

impl Theme {
    pub const TOUS: [Theme; 2] = [Theme::Sombre, Theme::Clair];

    pub fn mot(self) -> &'static str {
        match self {
            Theme::Sombre => "sombre",
            Theme::Clair => "clair",
        }
    }

    pub fn lire(mot: &str) -> Option<Theme> {
        Theme::TOUS.into_iter().find(|t| t.mot() == mot)
    }

    /// L'octet du protocole du relais : 1 ou 2.
    #[cfg(any(target_os = "linux", test))] // le relais n'existe que sous Linux
    pub fn octet(self) -> u8 {
        match self {
            Theme::Sombre => 1,
            Theme::Clair => 2,
        }
    }

    #[cfg(any(target_os = "linux", test))] // le relais n'existe que sous Linux
    pub fn depuis_octet(o: u8) -> Option<Theme> {
        Theme::TOUS.into_iter().find(|t| t.octet() == o)
    }

    pub fn depuis_sombre(sombre: bool) -> Theme {
        if sombre { Theme::Sombre } else { Theme::Clair }
    }
}

/// D'où viennent les neutres et les couleurs de départ : un des six préréglages, ou les couleurs du système (le
/// thème d'Omarchy, l'accent de Windows), lues par `vanguard`, posées sur les neutres de Vanguard.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Base {
    Vanguard,
    Braise,
    Emeraude,
    Ambre,
    Violet,
    Glacier,
    Systeme,
}

impl Base {
    pub const TOUTES: [Base; 7] = [
        Base::Vanguard,
        Base::Braise,
        Base::Emeraude,
        Base::Ambre,
        Base::Violet,
        Base::Glacier,
        Base::Systeme,
    ];

    /// Le mot de parametres.json et de la ligne de commande.
    pub fn mot(self) -> &'static str {
        match self {
            Base::Vanguard => "vanguard",
            Base::Braise => "braise",
            Base::Emeraude => "emeraude",
            Base::Ambre => "ambre",
            Base::Violet => "violet",
            Base::Glacier => "glacier",
            Base::Systeme => "systeme",
        }
    }

    pub fn lire(mot: &str) -> Option<Base> {
        Base::TOUTES.into_iter().find(|b| b.mot() == mot)
    }

    /// L'octet du protocole du relais : 0 à 6.
    #[cfg(any(target_os = "linux", test))] // le relais n'existe que sous Linux
    pub fn octet(self) -> u8 {
        match self {
            Base::Vanguard => 0,
            Base::Braise => 1,
            Base::Emeraude => 2,
            Base::Ambre => 3,
            Base::Violet => 4,
            Base::Glacier => 5,
            Base::Systeme => 6,
        }
    }

    #[cfg(any(target_os = "linux", test))] // le relais n'existe que sous Linux
    pub fn depuis_octet(o: u8) -> Option<Base> {
        Base::TOUTES.into_iter().find(|b| b.octet() == o)
    }

    /// Le préréglage de ce thème : pour le système, celui de Vanguard (ses neutres ; les couleurs vives viennent du
    /// système).
    pub fn prereglage(self, theme: Theme) -> &'static Prereglage {
        let i = match self {
            Base::Vanguard | Base::Systeme => 0,
            Base::Braise => 1,
            Base::Emeraude => 2,
            Base::Ambre => 3,
            Base::Violet => 4,
            Base::Glacier => 5,
        };
        let paire = PREREGLAGES.get(i).unwrap_or(&PREREGLAGES[0]);
        match theme {
            Theme::Sombre => &paire.0,
            Theme::Clair => &paire.1,
        }
    }
}

/// Le nombre de couleurs vives.
pub const VIFS: usize = 5;

/// Une couleur vive, à choisir : l'accent (boutons, liens) et les quatre couleurs de gravité.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Vif {
    Accent,
    /// Critique, élevée.
    Grave,
    /// À corriger.
    Moyen,
    /// À surveiller.
    Jaune,
    /// Sain.
    Bon,
}

impl Vif {
    /// Dans l'ordre des couleurs d'un `Choix`.
    pub const TOUS: [Vif; VIFS] = [Vif::Accent, Vif::Grave, Vif::Moyen, Vif::Jaune, Vif::Bon];

    pub fn rang(self) -> usize {
        match self {
            Vif::Accent => 0,
            Vif::Grave => 1,
            Vif::Moyen => 2,
            Vif::Jaune => 3,
            Vif::Bon => 4,
        }
    }

    pub fn mot(self) -> &'static str {
        match self {
            Vif::Accent => "accent",
            Vif::Grave => "grave",
            Vif::Moyen => "moyen",
            Vif::Jaune => "jaune",
            Vif::Bon => "bon",
        }
    }
}

/// Les couleurs fixes d'un préréglage : fonds, surfaces, textes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Neutres {
    pub fond: Rgb,
    pub surface: Rgb,
    pub s2: Rgb,
    pub s3: Rgb,
    pub encre: Rgb,
    pub doux: Rgb,
    pub discret: Rgb,
}

/// Un préréglage d'un thème : ses neutres et ses cinq couleurs vives (dans l'ordre de `Vif::TOUS`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Prereglage {
    pub neutres: Neutres,
    pub vifs: [Rgb; VIFS],
}

const fn h(x: u32) -> Rgb {
    let [_, r, g, b] = x.to_be_bytes();
    [r, g, b]
}

const fn p(n: [u32; 7], v: [u32; VIFS]) -> Prereglage {
    Prereglage {
        neutres: Neutres {
            fond: h(n[0]),
            surface: h(n[1]),
            s2: h(n[2]),
            s3: h(n[3]),
            encre: h(n[4]),
            doux: h(n[5]),
            discret: h(n[6]),
        },
        vifs: [h(v[0]), h(v[1]), h(v[2]), h(v[3]), h(v[4])],
    }
}

/// Les six préréglages acceptés par l'auteur (palettes.json du lot, tels quels), sombre puis clair, dans l'ordre de
/// `Base::TOUTES`. Le contraste des couleurs vives vise environ 10, 6, 8,5, 12 et 8 sur le fond sombre ; 4,8, 5,0,
/// 5,4, 4,5 et 4,8 sur la surface claire (un essai le recalcule).
#[allow(clippy::unreadable_literal)] // des couleurs « rrggbb », comme on les écrit partout ailleurs
const PREREGLAGES: [(Prereglage, Prereglage); 6] = [
    (
        p(
            [0x000000, 0x0a0d0e, 0x101417, 0x171d20, 0xe8eef1, 0x9aa7ae, 0x626e75],
            [0x3fbef7, 0xf24f4d, 0xfb852f, 0xe7c03a, 0x45b45e],
        ),
        p(
            [0xf2f5f7, 0xffffff, 0xecf1f3, 0xe1e7eb, 0x0a151b, 0x495860, 0x69777e],
            [0x067ba5, 0xd22e33, 0xa85208, 0x8f7304, 0x018433],
        ),
    ),
    (
        p(
            [0x000000, 0x0f0b0a, 0x171311, 0x201a19, 0xf2ebe9, 0xafa19d, 0x766865],
            [0xf85c30, 0xe94f97, 0xea900f, 0xddc33c, 0x45b45e],
        ),
        p(
            [0xf7f3f2, 0xffffff, 0xf4eeed, 0xebe4e2, 0x1c110e, 0x61514d, 0x80716c],
            [0xd33b04, 0xca2f7d, 0x985d0a, 0x897609, 0x018433],
        ),
    ),
    (
        p(
            [0x000000, 0x0a0d0c, 0x101513, 0x171d1b, 0xe8efec, 0x9aa8a3, 0x626f6a],
            [0x1fc9a3, 0xf24f4d, 0xfb852f, 0xe7c03a, 0x61b240],
        ),
        p(
            [0xf2f5f4, 0xffffff, 0xecf1ef, 0xe1e8e5, 0x0a1713, 0x495954, 0x697873],
            [0x148268, 0xd22e33, 0xa85208, 0x8f7304, 0x348203],
        ),
    ),
    (
        p(
            [0x000000, 0x0e0c09, 0x161310, 0x1f1b17, 0xf0ece7, 0xaca399, 0x726a61],
            [0xf4a21c, 0xf34e56, 0xfe814f, 0xc5cb4a, 0x3eb663],
        ),
        p(
            [0xf6f4f2, 0xffffff, 0xf2efeb, 0xeae5e1, 0x19120a, 0x5d5448, 0x7c7368],
            [0x9d670e, 0xd22d3d, 0xb74507, 0x787b0f, 0x08833c],
        ),
    ),
    (
        p(
            [0x000000, 0x0d0c0e, 0x141317, 0x1c1b20, 0xedecf1, 0xa6a2ae, 0x6d6a75],
            [0xb689ff, 0xf24f4d, 0xfb852f, 0xe7c03a, 0x45b45e],
        ),
        p(
            [0xf5f4f7, 0xffffff, 0xf0eff3, 0xe7e5eb, 0x15121c, 0x575360, 0x76727f],
            [0x895acb, 0xd22e33, 0xa85208, 0x8f7304, 0x018433],
        ),
    ),
    (
        p(
            [0x000000, 0x0a0c0f, 0x111417, 0x181c20, 0xe9edf2, 0x9ca6b0, 0x646d76],
            [0x87b8ea, 0xf24f4d, 0xfb852f, 0xe7c03a, 0x45b45e],
        ),
        p(
            [0xf2f5f7, 0xffffff, 0xedf0f4, 0xe2e7eb, 0x0d151c, 0x4c5661, 0x6c7680],
            [0x4775a5, 0xd22e33, 0xa85208, 0x8f7304, 0x018433],
        ),
    ),
];

/// Ce qui est réglé pour un thème : la base (ses neutres) et les cinq couleurs vives.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Choix {
    pub base: Base,
    pub vifs: [Rgb; VIFS],
}

impl Choix {
    /// Le préréglage tel quel (pour le système : les couleurs de Vanguard, en attendant celles lues).
    pub fn du_prereglage(base: Base, theme: Theme) -> Choix {
        Choix {
            base,
            vifs: base.prereglage(theme).vifs,
        }
    }

    pub fn vif(&self, v: Vif) -> Rgb {
        self.vifs.get(v.rang()).copied().unwrap_or_default()
    }

    pub fn poser(&mut self, v: Vif, c: Rgb) {
        if let Some(x) = self.vifs.get_mut(v.rang()) {
            *x = c;
        }
    }
}

/// Toutes les couleurs montrées pour un thème : les neutres de la base, les vives choisies, et l'encre posée sur
/// l'accent (noire ou blanche, la plus contrastée).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Jeu {
    pub neutres: Neutres,
    pub vifs: [Rgb; VIFS],
    pub sur_vif: Rgb,
}

impl Jeu {
    /// Rien de réglé : le préréglage Vanguard.
    pub fn de(theme: Theme, choix: Option<&Choix>) -> Jeu {
        let choix = choix.copied().unwrap_or(Choix::du_prereglage(Base::Vanguard, theme));
        let accent = choix.vif(Vif::Accent);
        Jeu {
            neutres: choix.base.prereglage(theme).neutres,
            vifs: choix.vifs,
            sur_vif: sur_vif(accent),
        }
    }

    pub fn vif(&self, v: Vif) -> Rgb {
        self.vifs.get(v.rang()).copied().unwrap_or_default()
    }
}

/// « 3fbef7 » : six chiffres hexadécimaux minuscules, sans dièse.
pub fn hex(c: Rgb) -> String {
    format!("{:02x}{:02x}{:02x}", c[0], c[1], c[2])
}

/// Exactement six chiffres hexadécimaux minuscules ; tout autre texte (dièse, majuscule, espace, longueur voisine) :
/// rien.
pub fn lire_hex(texte: &str) -> Option<Rgb> {
    let o = texte.as_bytes();
    if o.len() != 6 {
        return None;
    }
    let chiffre = |c: u8| {
        if c.is_ascii_digit() || (b'a'..=b'f').contains(&c) {
            char::from(c).to_digit(16).and_then(|d| u8::try_from(d).ok())
        } else {
            None
        }
    };
    let mut rgb = [0u8; 3];
    for (case, [haut, bas]) in rgb.iter_mut().zip(o.as_chunks::<2>().0) {
        *case = (chiffre(*haut)? << 4) | chiffre(*bas)?;
    }
    Some(rgb)
}

/// Les cinq couleurs vives, séparées par des virgules : « 3fbef7,f24f4d,fb852f,e7c03a,45b45e ».
pub fn vifs_hex(vifs: &[Rgb; VIFS]) -> String {
    vifs.iter().map(|c| hex(*c)).collect::<Vec<_>>().join(",")
}

/// Exactement cinq couleurs de `lire_hex`, séparées par des virgules ; tout autre texte : rien.
pub fn lire_vifs(texte: &str) -> Option<[Rgb; VIFS]> {
    let mut vifs = [[0u8; 3]; VIFS];
    let mut morceaux = texte.split(',');
    for case in &mut vifs {
        *case = lire_hex(morceaux.next()?)?;
    }
    morceaux.next().is_none().then_some(vifs)
}

/// Une composante sRVB (0 à 255) en lumière linéaire (WCAG 2).
fn lineaire(c: u8) -> f64 {
    let c = f64::from(c) / 255.0;
    if c <= 0.040_45 {
        c / 12.92
    } else {
        ((c + 0.055) / 1.055).powf(2.4)
    }
}

/// La luminance relative (WCAG 2), de 0 (noir) à 1 (blanc).
pub fn luminance(c: Rgb) -> f64 {
    0.2126 * lineaire(c[0]) + 0.7152 * lineaire(c[1]) + 0.0722 * lineaire(c[2])
}

/// Le contraste WCAG de deux couleurs, de 1:1 à 21:1.
pub fn contraste(a: Rgb, b: Rgb) -> f64 {
    let (x, y) = (luminance(a), luminance(b));
    (x.max(y) + 0.05) / (x.min(y) + 0.05)
}

/// La couleur dans l'espace OKLab (L, a, b) : les distances y suivent ce que l'œil voit.
#[allow(clippy::many_single_char_names)] // les lettres de la formule publiée d'OKLab
pub fn oklab(c: Rgb) -> [f64; 3] {
    let (r, g, b) = (lineaire(c[0]), lineaire(c[1]), lineaire(c[2]));
    let l = (0.412_221_470_8 * r + 0.536_332_536_3 * g + 0.051_445_992_9 * b).cbrt();
    let m = (0.211_903_498_2 * r + 0.680_699_545_1 * g + 0.107_396_956_6 * b).cbrt();
    let s = (0.088_302_461_9 * r + 0.281_718_837_6 * g + 0.629_978_700_5 * b).cbrt();
    [
        0.210_454_255_3 * l + 0.793_617_785 * m - 0.004_072_046_8 * s,
        1.977_998_495_1 * l - 2.428_592_205 * m + 0.450_593_709_9 * s,
        0.025_904_037_1 * l + 0.782_771_766_2 * m - 0.808_675_766 * s,
    ]
}

/// L'écart de deux couleurs : leur distance dans OKLab (0 : la même ; 0,02 : à peine visible côte à côte ; les
/// préréglages gardent au moins 0,07 entre deux couleurs vives).
pub fn ecart(a: Rgb, b: Rgb) -> f64 {
    let (x, y) = (oklab(a), oklab(b));
    x.iter().zip(y).map(|(u, v)| (u - v) * (u - v)).sum::<f64>().sqrt()
}

/// L'encre posée sur l'accent (le texte d'un bouton plein) : noire ou blanche, celle qui contraste le plus.
pub fn sur_vif(accent: Rgb) -> Rgb {
    const NOIR: Rgb = [0, 0, 0];
    const BLANC: Rgb = [0xff, 0xff, 0xff];
    if contraste(accent, NOIR) >= contraste(accent, BLANC) {
        NOIR
    } else {
        BLANC
    }
}

/// Sous ce contraste avec le fond, une remarque (WCAG : 3:1 pour ce qui n'est pas du texte courant).
pub const CONTRASTE_CONSEILLE: f64 = 3.0;
/// Sous cet écart entre deux couleurs de gravité, une remarque (les préréglages gardent au moins 0,07).
pub const ECART_CONSEILLE: f64 = 0.06;
/// Sous ce contraste avec le fond, la couleur est presque invisible : refusée.
pub const CONTRASTE_MIN: f64 = 1.5;

/// Le pire contraste d'une couleur sur les deux fonds où elle se dessine (le fond de la fenêtre et ses cartes).
pub fn contraste_sur_fonds(n: &Neutres, c: Rgb) -> f64 {
    contraste(c, n.fond).min(contraste(c, n.surface))
}

/// Ce qui se lit mal, sans être refusé.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Remarque {
    /// Peu de contraste avec le fond.
    Contraste { vif: Vif, ratio: f64 },
    /// Deux couleurs trop proches : deux gravités, ou l'accent (boutons, « à corriger ») et une gravité.
    Proches { a: Vif, b: Vif, ecart: f64 },
}

/// Les remarques de lisibilité d'un choix : « grave » et « sain » trop proches d'abord (une alerte prise pour ce qui
/// va bien), puis les contrastes et les autres paires dans l'ordre des couleurs. L'accent compte : il dit aussi
/// « à corriger » dans le bilan.
pub fn remarques(theme: Theme, choix: &Choix) -> Vec<Remarque> {
    let n = choix.base.prereglage(theme).neutres;
    let mut r: Vec<Remarque> = Vif::TOUS
        .into_iter()
        .map(|vif| (vif, contraste_sur_fonds(&n, choix.vif(vif))))
        .filter(|(_, ratio)| *ratio < CONTRASTE_CONSEILLE)
        .map(|(vif, ratio)| Remarque::Contraste { vif, ratio })
        .collect();
    for (i, a) in Vif::TOUS.into_iter().enumerate() {
        for b in Vif::TOUS.into_iter().skip(i.saturating_add(1)) {
            let e = ecart(choix.vif(a), choix.vif(b));
            if e < ECART_CONSEILLE {
                r.push(Remarque::Proches { a, b, ecart: e });
            }
        }
    }
    // Stable : le reste garde son ordre.
    r.sort_by_key(|m| !m.grave_comme_sain());
    r
}

impl Remarque {
    /// « Grave » et « sain » se confondent : la remarque la plus lourde, montrée en premier et en gras.
    pub fn grave_comme_sain(&self) -> bool {
        matches!(
            self,
            Remarque::Proches {
                a: Vif::Grave,
                b: Vif::Bon,
                ..
            }
        )
    }
}

/// Pourquoi un choix est refusé : une couleur presque invisible sur le fond du thème.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Refus {
    pub vif: Vif,
    pub ratio: f64,
}

/// Le choix peut-il s'enregistrer ? Refusé seulement si une couleur se voit à peine sur un des fonds (sous
/// `CONTRASTE_MIN`) ; tout le reste, même peu lisible, se règle (avec ses remarques).
pub fn verifier(theme: Theme, choix: &Choix) -> Result<(), Refus> {
    let n = choix.base.prereglage(theme).neutres;
    match Vif::TOUS
        .into_iter()
        .map(|vif| (vif, contraste_sur_fonds(&n, choix.vif(vif))))
        .find(|(_, ratio)| *ratio < CONTRASTE_MIN)
    {
        Some((vif, ratio)) => Err(Refus { vif, ratio }),
        None => Ok(()),
    }
}

/// Les couleurs du système posées sur un thème : chacune qui se verrait à peine sur ses fonds (le thème d'Omarchy
/// est sombre, la fenêtre claire) garde celle de Vanguard. Rend le choix et les couleurs gardées.
pub fn depuis_le_systeme(theme: Theme, systeme: &[Option<Rgb>; VIFS]) -> (Choix, Vec<Vif>) {
    let mut choix = Choix::du_prereglage(Base::Systeme, theme);
    let n = choix.base.prereglage(theme).neutres;
    let mut gardees = Vec::new();
    for (vif, lue) in Vif::TOUS.into_iter().zip(systeme) {
        match lue {
            Some(c) if contraste_sur_fonds(&n, *c) >= CONTRASTE_MIN => choix.poser(vif, *c),
            Some(_) => gardees.push(vif),
            None => {}
        }
    }
    (choix, gardees)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Les contrastes et l'écart le plus petit de chaque préréglage, recalculés ici avec les formules de palettes.py
    /// (WCAG 2, OKLab) : ceux que palettes.py donnait (sur le fond en sombre, sur la surface en clair). Une table
    /// recopiée de travers, ou une formule fausse, s'y voit.
    #[test]
    fn les_prereglages_tiennent_leurs_cibles() {
        #[rustfmt::skip]
        let attendus: [(Base, Theme, [f64; VIFS], f64); 12] = [
            (Base::Vanguard, Theme::Sombre, [9.92, 6.0, 8.5, 12.0, 7.94], 0.1215),
            (Base::Vanguard, Theme::Clair, [4.79, 5.03, 5.42, 4.54, 4.83], 0.0918),
            (Base::Braise, Theme::Sombre, [6.56, 6.03, 8.49, 11.95, 7.94], 0.115),
            (Base::Braise, Theme::Clair, [4.78, 4.98, 5.38, 4.51, 4.83], 0.0701),
            (Base::Emeraude, Theme::Sombre, [9.94, 6.0, 8.5, 12.0, 7.95], 0.1123),
            (Base::Emeraude, Theme::Clair, [4.75, 5.03, 5.42, 4.54, 4.84], 0.0918),
            (Base::Ambre, Theme::Sombre, [10.03, 6.04, 8.47, 12.02, 8.08], 0.093),
            (Base::Ambre, Theme::Clair, [4.79, 5.02, 5.43, 4.53, 4.86], 0.0783),
            (Base::Violet, Theme::Sombre, [8.01, 6.0, 8.5, 12.0, 7.94], 0.1215),
            (Base::Violet, Theme::Clair, [4.79, 5.03, 5.42, 4.54, 4.83], 0.0918),
            (Base::Glacier, Theme::Sombre, [10.07, 6.0, 8.5, 12.0, 7.94], 0.1215),
            (Base::Glacier, Theme::Clair, [4.82, 5.03, 5.42, 4.54, 4.83], 0.0918),
        ];
        for (base, theme, contrastes, ecart_min) in attendus {
            let pr = base.prereglage(theme);
            let fond = match theme {
                Theme::Sombre => pr.neutres.fond,
                Theme::Clair => pr.neutres.surface,
            };
            for (vif, attendu) in Vif::TOUS.into_iter().zip(contrastes) {
                let k = contraste(pr.vifs[vif.rang()], fond);
                assert!((k - attendu).abs() < 0.006, "{base:?} {theme:?} {vif:?} : {k}");
            }
            let mut e = f64::MAX;
            for (i, a) in pr.vifs.iter().enumerate() {
                for b in &pr.vifs[i + 1..] {
                    e = e.min(ecart(*a, *b));
                }
            }
            assert!((e - ecart_min).abs() < 0.0006, "{base:?} {theme:?} : {e}");
            // Rien à redire d'un préréglage, et rien de refusé.
            let choix = Choix::du_prereglage(base, theme);
            assert_eq!(remarques(theme, &choix), [], "{base:?} {theme:?}");
            assert_eq!(verifier(theme, &choix), Ok(()));
        }
    }

    /// L'encre sur l'accent : noire en sombre, blanche en clair, comme palettes.json la donne pour chacun.
    #[test]
    fn l_encre_sur_l_accent_est_la_plus_contrastee() {
        for base in Base::TOUTES {
            assert_eq!(
                Jeu::de(Theme::Sombre, Some(&Choix::du_prereglage(base, Theme::Sombre))).sur_vif,
                [0; 3]
            );
            assert_eq!(
                Jeu::de(Theme::Clair, Some(&Choix::du_prereglage(base, Theme::Clair))).sur_vif,
                [0xff; 3]
            );
        }
        assert_eq!(sur_vif([0xff, 0xff, 0x00]), [0; 3]);
        assert_eq!(sur_vif([0x00, 0x00, 0x80]), [0xff; 3]);
    }

    #[test]
    fn les_mots_et_les_octets_aller_retour() {
        for t in Theme::TOUS {
            assert_eq!(Theme::lire(t.mot()), Some(t));
            assert_eq!(Theme::depuis_octet(t.octet()), Some(t));
        }
        for b in Base::TOUTES {
            assert_eq!(Base::lire(b.mot()), Some(b));
            assert_eq!(Base::depuis_octet(b.octet()), Some(b));
        }
        for faux in ["", "Sombre", "sombre ", "noir", "systeme\0"] {
            assert_eq!(Theme::lire(faux), None);
            assert_eq!(Base::lire(faux), None);
        }
        assert_eq!(Theme::depuis_octet(0), None);
        assert_eq!(Theme::depuis_octet(3), None);
        assert_eq!(Base::depuis_octet(7), None);
        assert_eq!(Base::depuis_octet(0xff), None);
        let rangs: Vec<usize> = Vif::TOUS.iter().map(|v| v.rang()).collect();
        assert_eq!(rangs, [0, 1, 2, 3, 4]);
    }

    #[test]
    fn les_couleurs_se_lisent_strictement() {
        assert_eq!(lire_hex("3fbef7"), Some([0x3f, 0xbe, 0xf7]));
        assert_eq!(hex([0x3f, 0xbe, 0xf7]), "3fbef7");
        for faux in [
            "", "#3fbef7", "3FBEF7", "3fbef", "3fbef77", " 3fbef7", "3fbeg7", "3fbe-7", "+3fbe7",
        ] {
            assert_eq!(lire_hex(faux), None, "{faux:?}");
        }
        let vifs = Base::Braise.prereglage(Theme::Clair).vifs;
        assert_eq!(lire_vifs(&vifs_hex(&vifs)), Some(vifs));
        for faux in [
            "",
            "000000,000000,000000,000000",
            "000000,000000,000000,000000,000000,",
            "000000,000000,000000,000000,000000,000000",
            "000000,000000,000000,000000, 000000",
            "000000;000000;000000;000000;000000",
            "000000,000000,000000,000000,/home/alice",
        ] {
            assert_eq!(lire_vifs(faux), None, "{faux:?}");
        }
    }

    /// Prévenir sans interdire : peu de contraste ou deux gravités proches font une remarque ; seule une couleur
    /// presque invisible est refusée. Le noir sur le fond noir, le blanc sur la surface blanche : refusés.
    #[test]
    fn peu_lisible_previent_invisible_refuse() {
        let mut c = Choix::du_prereglage(Base::Vanguard, Theme::Sombre);
        c.poser(Vif::Jaune, [0x50, 0x50, 0x50]);
        c.poser(Vif::Bon, c.vif(Vif::Grave));
        let r = remarques(Theme::Sombre, &c);
        // « Grave » pris pour « sain » d'abord, puis le reste dans l'ordre des couleurs.
        assert!(
            matches!(r[0], Remarque::Proches { a: Vif::Grave, b: Vif::Bon, ecart } if ecart < 1e-9),
            "{r:?}"
        );
        assert!(r[0].grave_comme_sain());
        assert!(
            matches!(r[1], Remarque::Contraste { vif: Vif::Jaune, ratio } if ratio < 3.0),
            "{r:?}"
        );
        assert_eq!(verifier(Theme::Sombre, &c), Ok(()));
        // L'accent dit aussi « à corriger » : trop près d'une gravité, une remarque (l'accent d'un système rouge
        // contre le rouge de « grave »).
        let mut c = Choix::du_prereglage(Base::Vanguard, Theme::Sombre);
        c.poser(Vif::Accent, [0xff, 0x0a, 0x1e]);
        c.poser(Vif::Grave, [0xff, 0x4d, 0x4d]);
        let r = remarques(Theme::Sombre, &c);
        assert!(
            r.iter().any(|x| matches!(
                x,
                Remarque::Proches {
                    a: Vif::Accent,
                    b: Vif::Grave,
                    ..
                }
            )),
            "{r:?}"
        );
        assert!(!r.iter().any(Remarque::grave_comme_sain));
        c.poser(Vif::Grave, [0, 0, 0]);
        assert!(matches!(
            verifier(Theme::Sombre, &c),
            Err(Refus { vif: Vif::Grave, .. })
        ));
        let mut c = Choix::du_prereglage(Base::Glacier, Theme::Clair);
        c.poser(Vif::Accent, [0xff; 3]);
        assert!(matches!(
            verifier(Theme::Clair, &c),
            Err(Refus { vif: Vif::Accent, .. })
        ));
        // Le pire des deux fonds compte : en clair, la surface blanche.
        c.poser(Vif::Accent, [0xf0, 0xf0, 0xf0]);
        assert!(verifier(Theme::Clair, &c).is_err());
    }

    /// Les couleurs du système : posées sur les neutres de Vanguard ; une absente garde celle de Vanguard ; une
    /// presque invisible sur ce thème aussi, et c'est dit.
    #[test]
    fn le_systeme_garde_ce_qui_se_verrait_mal() {
        let lues = [
            Some([0xff, 0x0a, 0x1e]),
            None,
            Some([0xff, 0xcf, 0x5c]),
            Some([0xff, 0xff, 0xf0]),
            None,
        ];
        let (c, gardees) = depuis_le_systeme(Theme::Sombre, &lues);
        assert_eq!(c.base, Base::Systeme);
        assert_eq!(c.vif(Vif::Accent), [0xff, 0x0a, 0x1e]);
        assert_eq!(c.vif(Vif::Grave), Base::Vanguard.prereglage(Theme::Sombre).vifs[1]);
        assert_eq!(gardees, []);
        let (c, gardees) = depuis_le_systeme(Theme::Clair, &lues);
        // Le jaune pâle (ffcf5c) et le presque blanc se perdent sur la surface blanche.
        assert_eq!(gardees, [Vif::Moyen, Vif::Jaune]);
        assert_eq!(c.vif(Vif::Jaune), Base::Vanguard.prereglage(Theme::Clair).vifs[3]);
        assert_eq!(c.vif(Vif::Accent), [0xff, 0x0a, 0x1e]);
        assert_eq!(verifier(Theme::Clair, &c), Ok(()));
    }
}

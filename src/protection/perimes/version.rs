//! Les numéros de version des logiciels, comparés sans rien deviner : seulement des nombres séparés par des points,
//! de 1 à 6 champs, un champ absent valant zéro (1.2 = 1.2.0). Ce qui n'a pas cette forme n'est pas une version
//! (`None`), et le logiciel est dit « non vérifié » plutôt que comparé de travers. Chaque éditeur écrit les siennes à
//! sa façon (« 153.5.1esr », « 1.8.0_511 », « 21.0.13+9 ») : une normalisation par éditeur, là seulement où sa forme
//! est connue, jamais une règle générale qui retirerait un suffixe partout.
//!
//! Lecteur pur, sans `crate::`.

use std::cmp::Ordering;
use std::fmt;

const CHAMPS_MAX: usize = 6;
/// Neuf chiffres au plus par champ : tient dans un u32, et aucun éditeur n'en écrit plus.
const CHIFFRES_MAX: usize = 9;

/// Une version : jusqu'à six nombres. L'égalité et l'ordre comptent les champs absents comme des zéros ; pas de
/// `Hash`, qui devrait suivre cette égalité.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Version {
    champs: [u32; CHAMPS_MAX],
    n: u8,
}

impl Version {
    /// « 26.001.21662 » ; espaces autour retirés. Zéros en tête acceptés (26.001 = 26.1). `None` : champ vide,
    /// signe, lettre, plus de six champs ou de neuf chiffres.
    pub(crate) fn lire(texte: &str) -> Option<Version> {
        let texte = texte.trim();
        let mut champs = [0u32; CHAMPS_MAX];
        let mut n = 0usize;
        for morceau in texte.split('.') {
            if n == CHAMPS_MAX
                || morceau.is_empty()
                || morceau.len() > CHIFFRES_MAX
                || !morceau.bytes().all(|o| o.is_ascii_digit())
            {
                return None;
            }
            // `n` < CHAMPS_MAX, vérifié juste au-dessus.
            *champs.get_mut(n)? = morceau.parse().ok()?;
            n += 1;
        }
        Some(Version {
            champs,
            n: u8::try_from(n).ok()?,
        })
    }

    /// Les champs écrits.
    pub(crate) fn champs(&self) -> &[u32] {
        #[expect(
            clippy::indexing_slicing,
            reason = "n ≤ CHAMPS_MAX : lire, tronquee et depuis, seules à faire une Version, le garantissent"
        )]
        &self.champs[..usize::from(self.n)]
    }

    /// Le nombre de champs écrits.
    pub(crate) fn longueur(&self) -> usize {
        usize::from(self.n)
    }

    pub(crate) fn majeur(&self) -> u32 {
        self.champs[0]
    }

    /// Les `n` premiers champs (au moins un) ; les autres sont oubliés.
    pub(crate) fn tronquee(&self, n: usize) -> Version {
        let n = n.clamp(1, usize::from(self.n));
        let mut champs = [0u32; CHAMPS_MAX];
        for (d, &s) in champs.iter_mut().zip(&self.champs).take(n) {
            *d = s;
        }
        Version {
            champs,
            n: u8::try_from(n).unwrap_or(1),
        }
    }

    /// Une version faite de nombres déjà lus (1 à 6) : celles qu'un fichier donne en binaire (ressource d'un .exe).
    pub(crate) fn depuis(nombres: &[u32]) -> Option<Version> {
        if nombres.is_empty() || nombres.len() > CHAMPS_MAX {
            return None;
        }
        let mut champs = [0u32; CHAMPS_MAX];
        for (d, &s) in champs.iter_mut().zip(nombres) {
            *d = s;
        }
        Some(Version {
            champs,
            n: u8::try_from(nombres.len()).ok()?,
        })
    }
}

impl PartialEq for Version {
    fn eq(&self, autre: &Self) -> bool {
        self.cmp(autre) == Ordering::Equal
    }
}

impl Eq for Version {}

impl PartialOrd for Version {
    fn partial_cmp(&self, autre: &Self) -> Option<Ordering> {
        Some(self.cmp(autre))
    }
}

impl Ord for Version {
    /// Champ à champ ; les champs absents valent zéro (les tableaux en sont déjà remplis).
    fn cmp(&self, autre: &Self) -> Ordering {
        self.champs.cmp(&autre.champs)
    }
}

impl fmt::Display for Version {
    /// Les champs lus, sans zéros en tête ni champs ajoutés.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, c) in self.champs().iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            write!(f, "{c}")?;
        }
        Ok(())
    }
}

// ───────────────────────────── Normalisations par éditeur ─────────────────────────────

/// Firefox : « 158.0.1 », ou l'ESR « 153.5.1esr » (le suffixe que product-details et Firefox écrivent). Une bêta
/// (« 159.0b5 ») ou une Nightly (« 161.0a1 ») n'est pas une version publiée : `None`.
pub(crate) fn firefox(texte: &str) -> Option<Version> {
    let texte = texte.trim();
    Version::lire(texte.strip_suffix("esr").unwrap_or(texte))
}

/// Java, tel que le fichier `release` d'une installation l'écrit (`JAVA_VERSION`) : « 1.8.0_511 » (Java 8 et avant),
/// « 21.0.13 », « 17 », « 11.0.32.1 ». Rend trois champs : version, mise à jour intermédiaire, mise à jour de sécurité
/// (8.0.511, 21.0.13, 17.0.0, 11.0.32).
pub(crate) fn java_release(texte: &str) -> Option<Version> {
    let texte = texte.trim();
    if let Some(reste) = texte.strip_prefix("1.") {
        // « 1.8.0_511 » : Java 8 ; « 1.8.0 » sans mise à jour.
        let (base, maj) = reste.split_once('_').unwrap_or((reste, "0"));
        let base = Version::lire(base)?;
        if base.longueur() > 2 || maj.len() > CHIFFRES_MAX || !maj.bytes().all(|o| o.is_ascii_digit()) || maj.is_empty()
        {
            return None;
        }
        return Version::depuis(&[base.majeur(), 0, maj.parse().ok()?]);
    }
    trois_champs(Version::lire(texte)?)
}

/// La distribution de Java dont endoflife.date donne la version : chacune l'écrit à sa façon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FormeJava {
    /// Oracle JDK : « 21.0.13.0.2 », « 8u511 », « 26.0.2.1 ».
    Oracle,
    /// Eclipse Temurin : « 21.0.13+9 », « 27+35 », « 8u504-b01 ».
    Temurin,
    /// Amazon Corretto : « 25.0.4.11.1 », et pour Java 8 « 8.504.05.1 ».
    Corretto,
    /// Microsoft Build of OpenJDK : « 21.0.13.0.2 », « 11.0.32.1 ».
    Microsoft,
}

/// Java, tel qu'endoflife.date l'écrit pour `forme` : trois champs, comparables à `java_release`.
pub(crate) fn java_eol(texte: &str, forme: FormeJava) -> Option<Version> {
    let texte = texte.trim();
    // « 8u511 », « 8u504-b01 » (Oracle, Temurin) : Java 8 et sa mise à jour.
    if let Some((majeur, reste)) = texte.split_once('u')
        && matches!(forme, FormeJava::Oracle | FormeJava::Temurin)
    {
        let maj = match forme {
            FormeJava::Temurin => reste.split_once("-b").map_or(reste, |(m, _)| m),
            _ => reste,
        };
        let majeur = Version::lire(majeur)?;
        let maj = Version::lire(maj)?;
        if majeur.longueur() != 1 || maj.longueur() != 1 {
            return None;
        }
        return Version::depuis(&[majeur.majeur(), 0, maj.majeur()]);
    }
    let base = match forme {
        // « 21.0.13+9 » : le numéro de construction après « + ».
        FormeJava::Temurin => texte.split_once('+').map_or(texte, |(v, _)| v),
        _ => texte,
    };
    let v = Version::lire(base)?;
    // Corretto 8 : « 8.504.05.1 » = Java 8, mise à jour 504.
    if forme == FormeJava::Corretto
        && let [8, mise, _, _] = *v.champs()
    {
        return Version::depuis(&[8, 0, mise]);
    }
    trois_champs(v)
}

/// Les trois premiers champs, complétés de zéros.
fn trois_champs(v: Version) -> Option<Version> {
    let c = v.tronquee(3);
    Version::depuis(&[
        c.champs().first().copied()?,
        c.champs().get(1).copied().unwrap_or(0),
        c.champs().get(2).copied().unwrap_or(0),
    ])
}

/// Chrome et Edge : toujours quatre champs (« 156.0.8078.48 ») ; une autre forme n'est pas la leur.
pub(crate) fn chrome_edge(texte: &str) -> Option<Version> {
    Version::lire(texte).filter(|v| v.longueur() == 4)
}

/// Adobe Acrobat et Reader : trois champs, le deuxième et le troisième à zéros en tête (« 26.002.22031 »).
pub(crate) fn adobe(texte: &str) -> Option<Version> {
    Version::lire(texte).filter(|v| v.longueur() == 3)
}

/// Brave, comparé aux trois champs que Brave publie (« 1.98.60 »). Son exécutable et son Info.plist peuvent les
/// précéder du majeur de Chromium (« 156.1.98.60 », forme vue chez des tiers, à confirmer sur une vraie
/// installation) : seulement quand ce premier champ dépasse le suivant, sinon ce serait une autre forme, devinée.
/// La forme « 198.60 » (CFBundleVersion selon des tiers) est ambiguë : `None`.
pub(crate) fn brave(texte: &str) -> Option<Version> {
    let v = Version::lire(texte)?;
    match *v.champs() {
        [_, _, _] => Some(v),
        [chromium, b, m, p] if chromium > b => Version::depuis(&[b, m, p]),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(texte: &str) -> Version {
        Version::lire(texte).unwrap_or_else(|| panic!("{texte}"))
    }

    #[test]
    fn lecture_stricte() {
        assert_eq!(v("26.001.21662"), v("26.1.21662"));
        assert_eq!(v(" 1.2 ").to_string(), "1.2");
        assert_eq!(v("007").to_string(), "7");
        assert_eq!(v("1.2.3.4.5.6").longueur(), 6);
        for mauvaise in [
            "",
            " ",
            ".",
            "1.",
            ".1",
            "1..2",
            "-1",
            "+1",
            "1.2a",
            "1.2-3",
            "v1.2",
            "1,2",
            "1.2.3.4.5.6.7",
            "1234567890",
            "1.2 3",
            "١.٢",
        ] {
            assert!(Version::lire(mauvaise).is_none(), "{mauvaise:?}");
        }
        assert_eq!(v("999999999").majeur(), 999_999_999);
    }

    #[test]
    fn ordre_et_egalite() {
        assert_eq!(v("1.2"), v("1.2.0"));
        assert_eq!(v("1.2"), v("1.2.0.0.0.0"));
        assert!(v("1.10") > v("1.9"));
        assert!(v("156.0.8078.48") > v("156.0.8078.47"));
        assert!(v("152.0.7977.169") < v("156.0.8078.48"));
        assert!(v("26.2.22031") > v("26.1.21662"));
        assert!(v("2") > v("1.99.99"));
        assert_eq!(v("16.0.20430.20178").tronquee(2), v("16.0"));
        assert_eq!(v("1.2").tronquee(5).longueur(), 2);
        assert_eq!(v("1.2").tronquee(0).to_string(), "1");
        assert_eq!(Version::depuis(&[156, 0, 8078, 48]), Some(v("156.0.8078.48")));
        assert_eq!(Version::depuis(&[]), None);
        assert_eq!(Version::depuis(&[1; 7]), None);
    }

    /// Les exemples de l'étude (§6) : Acrobat à zéros en tête, ESR, Java des quatre distributions.
    #[test]
    fn normalisations_par_editeur() {
        use FormeJava::*;
        assert_eq!(firefox("153.5.1esr"), Some(v("153.5.1")));
        assert_eq!(firefox("115.43.1esr"), Some(v("115.43.1")));
        assert_eq!(firefox("158.0.1"), Some(v("158.0.1")));
        assert_eq!(firefox("159.0b5"), None);
        assert_eq!(firefox("161.0a1"), None);
        assert_eq!(firefox("esr"), None);
        // Le fichier `release` d'une installation.
        assert_eq!(java_release("1.8.0_511"), Some(v("8.0.511")));
        assert_eq!(java_release("1.8.0"), Some(v("8.0.0")));
        assert_eq!(java_release("21.0.13"), Some(v("21.0.13")));
        assert_eq!(java_release("17"), Some(v("17.0.0")));
        assert_eq!(java_release("11.0.32.1"), Some(v("11.0.32")));
        assert_eq!(java_release("1.8.0_"), None);
        assert_eq!(java_release("1.8.0_51x"), None);
        assert_eq!(java_release("21-ea"), None);
        // endoflife.date, par distribution (valeurs du 23 oct. 2026).
        assert_eq!(java_eol("8u511", Oracle), Some(v("8.0.511")));
        assert_eq!(java_eol("21.0.13.0.2", Oracle), Some(v("21.0.13")));
        assert_eq!(java_eol("26.0.2.1", Oracle), Some(v("26.0.2")));
        assert_eq!(java_eol("8u504-b01", Temurin), Some(v("8.0.504")));
        assert_eq!(java_eol("21.0.13+9", Temurin), Some(v("21.0.13")));
        assert_eq!(java_eol("27+35", Temurin), Some(v("27.0.0")));
        assert_eq!(java_eol("26.0.2.1+1", Temurin), Some(v("26.0.2")));
        assert_eq!(java_eol("25.0.4.11.1", Corretto), Some(v("25.0.4")));
        assert_eq!(java_eol("8.504.05.1", Corretto), Some(v("8.0.504")));
        assert_eq!(java_eol("27.0.0.36.1", Corretto), Some(v("27.0.0")));
        assert_eq!(java_eol("21.0.13.0.2", Microsoft), Some(v("21.0.13")));
        assert_eq!(java_eol("11.0.32.1", Microsoft), Some(v("11.0.32")));
        // Une forme d'une autre distribution n'est pas devinée.
        assert_eq!(java_eol("8u511", Corretto), None);
        assert_eq!(java_eol("21.0.13+9", Oracle), None);
        assert_eq!(java_eol("27.28.101-zulu", Oracle), None);
        // La version installée et celle d'endoflife.date se comparent.
        assert!(java_release("1.8.0_481") < java_eol("8u504-b01", Temurin));
        assert_eq!(java_release("21.0.13"), java_eol("21.0.13.0.2", Microsoft));
        // Chrome, Edge, Adobe : leur nombre de champs.
        assert_eq!(chrome_edge("156.0.8078.48"), Some(v("156.0.8078.48")));
        assert_eq!(chrome_edge("156.0.8078"), None);
        assert_eq!(adobe("26.002.22031"), Some(v("26.2.22031")));
        assert_eq!(adobe("26.002.22031\n"), Some(v("26.2.22031")));
        assert_eq!(adobe("26.002"), None);
        assert_eq!(adobe("<html>"), None);
        // Brave : trois champs, ou précédés du majeur de Chromium.
        assert_eq!(brave("1.98.60"), Some(v("1.98.60")));
        assert_eq!(brave("156.1.98.60"), Some(v("1.98.60")));
        assert_eq!(brave("198.60"), None);
        assert_eq!(brave("1.2.98.60"), None);
        assert_eq!(brave("1.98.60.1.2"), None);
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 2000, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn jamais_de_plantage(texte in ".{0,40}") {
            let _ = Version::lire(&texte);
            let _ = firefox(&texte);
            let _ = java_release(&texte);
            let _ = brave(&texte);
            for forme in [FormeJava::Oracle, FormeJava::Temurin, FormeJava::Corretto, FormeJava::Microsoft] {
                let _ = java_eol(&texte, forme);
            }
        }

        #[test]
        fn chiffres_et_points(texte in "[0-9.]{0,30}") {
            let _ = Version::lire(&texte);
        }

        /// Relue depuis son affichage, une version est la même ; des « .0 » ajoutés ou des zéros en tête n'y changent
        /// rien.
        #[test]
        fn aller_retour(champs in proptest::collection::vec(0u32..1_000_000, 1..=6), zeros in 0usize..3) {
            let a = Version::depuis(&champs).unwrap();
            proptest::prop_assert_eq!(Version::lire(&a.to_string()), Some(a));
            if champs.len() < 6 {
                let plus = format!("{a}{}", ".0".repeat((6 - champs.len()).min(zeros + 1)));
                proptest::prop_assert_eq!(Version::lire(&plus), Some(a));
            }
            let en_tete: Vec<String> = champs.iter().map(|c| format!("{}{c}", "0".repeat(zeros))).collect();
            proptest::prop_assert_eq!(Version::lire(&en_tete.join(".")), Some(a));
        }

        /// L'ordre est celui des vecteurs complétés de zéros (l'oracle).
        #[test]
        fn ordre_de_reference(a in proptest::collection::vec(0u32..20, 1..=6), b in proptest::collection::vec(0u32..20, 1..=6)) {
            let complete = |v: &[u32]| { let mut c = v.to_vec(); c.resize(6, 0); c };
            let (va, vb) = (Version::depuis(&a).unwrap(), Version::depuis(&b).unwrap());
            proptest::prop_assert_eq!(va.cmp(&vb), complete(&a).cmp(&complete(&b)));
            proptest::prop_assert_eq!(va == vb, complete(&a) == complete(&b));
        }

        /// Plus de six champs, ou un champ de dix chiffres : jamais une version.
        #[test]
        fn trop_long(champs in proptest::collection::vec(0u32..100, 7..12), grand in 1_000_000_000u64..10_000_000_000) {
            let texte = champs.iter().map(u32::to_string).collect::<Vec<_>>().join(".");
            proptest::prop_assert!(Version::lire(&texte).is_none());
            let long = format!("1.{grand}");
            proptest::prop_assert!(Version::lire(&long).is_none());
        }
    }
}

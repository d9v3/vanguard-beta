//! Masquer dans le binaire les mots d'attaque que Vanguard **cherche**.
//!
//! But : qu'un antivirus ne prenne pas Vanguard pour l'outil qu'il traque. Vanguard reconnaît des outils offensifs
//! et des contournements d'AMSI par les mots de leurs commandes (« sekurlsa:: », « amsiscanbuffer »…). Écrits en
//! clair dans le programme, ces mots suffisent à une signature d'antivirus pour classer *Vanguard* comme l'outil
//! d'attaque — Defender a ainsi supprimé une version à cause de la seule présence de ces chaînes, sans que Vanguard
//! fasse rien de malveillant. Les éditeurs d'antivirus chiffrent leurs propres bases de signatures pour la même
//! raison. Ici, une simple transformation réversible suffit.
//!
//! Ce n'est **pas** un secret : rien n'est caché à l'utilisateur ni à un analyste. Le code source garde les mots en
//! clair, commentés, et ce module dit ouvertement comment les retrouver. Seule la forme compilée est brouillée.
//! `encoder` applique un XOR à la compilation (`const`), le littéral d'origine ne reste donc pas dans le binaire ;
//! `decoder` le refait à l'inverse en mémoire, une seule fois, au premier usage (`LazyLock`).
//!
//! Emploi : `liste_masquee!["sekurlsa::", "lsadump::"]` donne un `LazyLock<Vec<String>>` ; `mot_masque!("...")`
//! donne un `&'static str`, pour un mot cherché seul. On ne masque que les mots que le programme *cherche* ; les
//! messages montrés à l'utilisateur restent lisibles (`tr!`), un nom d'outil affiché (« Mimikatz ») n'est pas une
//! signature.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

/// La clé du XOR. Ce n'en est pas une au sens d'un secret : elle est publique, elle sert seulement à ce que les mots
/// d'attaque ne soient pas des chaînes ASCII repérables telles quelles dans le binaire.
const CLE: [u8; 8] = [0x4b, 0x1d, 0xa7, 0x6e, 0xf2, 0x39, 0xc5, 0x80];

/// Encode `clair` à la compilation : chaque octet XOR la clé. Évaluée en `const`, l'entrée (le littéral d'origine)
/// n'est pas émise dans le binaire ; seul le tableau brouillé y figure. `N` est la longueur du littéral.
#[must_use]
pub const fn encoder<const N: usize>(clair: &[u8]) -> [u8; N] {
    let mut code = [0u8; N];
    let mut i = 0;
    while i < N {
        // Pas d'itérateur dans une `const fn`. Évaluée en `const`, une sortie de bornes serait une erreur de
        // compilation, jamais un arrêt chez l'utilisateur.
        #[expect(
            clippy::indexing_slicing,
            clippy::arithmetic_side_effects,
            reason = "i < N (boucle) ; CLE.len() = 8, jamais nul ; clair.len() == N (code_masque! passe $mot.len())"
        )]
        {
            code[i] = clair[i] ^ CLE[i % CLE.len()];
        }
        #[expect(
            clippy::arithmetic_side_effects,
            reason = "i < N, longueur d'un tableau : i + 1 ne déborde pas"
        )]
        {
            i += 1;
        }
    }
    code
}

/// Refait l'opération à l'inverse, en mémoire, à l'exécution. L'entrée vient toujours d'un littéral `&str` encodé
/// par `encoder`, donc le résultat est de l'UTF-8 valide : la lecture « avec pertes » ne change rien à ce mot, elle
/// évite seulement un arrêt si un appel direct passait autre chose.
#[must_use]
pub fn decoder(code: &[u8]) -> String {
    let octets: Vec<u8> = code.iter().zip(CLE.iter().cycle()).map(|(b, k)| b ^ k).collect();
    String::from_utf8_lossy(&octets).into_owned()
}

/// Le littéral brouillé à la compilation, en tableau d'octets. Le reste des macros s'en sert ; à n'appeler que par
/// elles.
#[macro_export]
#[doc(hidden)]
macro_rules! code_masque {
    ($mot:literal) => {{
        const N: usize = $mot.len();
        const CODE: [u8; N] = $crate::masque::encoder::<N>($mot.as_bytes());
        CODE
    }};
}

/// Un mot d'attaque cherché seul, décodé une fois au premier usage, rendu en `&'static str`.
#[macro_export]
macro_rules! mot_masque {
    ($mot:literal) => {{
        static MOT: ::std::sync::LazyLock<String> =
            ::std::sync::LazyLock::new(|| $crate::masque::decoder(&$crate::code_masque!($mot)));
        MOT.as_str()
    }};
}

/// Une liste de mots d'attaque cherchés, décodée une fois au premier usage, rendue en `LazyLock<Vec<String>>`.
#[macro_export]
macro_rules! liste_masquee {
    ($($mot:literal),+ $(,)?) => {
        ::std::sync::LazyLock::new(|| ::std::vec![$($crate::masque::decoder(&$crate::code_masque!($mot))),+])
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn aller_retour() {
        // Encodé à la compilation puis décodé : on retrouve le mot exactement, « :: » et « $ » compris.
        assert_eq!(mot_masque!("sekurlsa::"), "sekurlsa::");
        assert_eq!(mot_masque!("setvalue($null,$true)"), "setvalue($null,$true)");
        // Un espace et un tiret dans le mot (« -e powershell ») passent aussi.
        assert_eq!(mot_masque!("-e powershell"), "-e powershell");
    }

    #[test]
    fn encode_vraiment() {
        // Le code n'est pas le mot : au moins un octet diffère (sinon le masquage ne servirait à rien).
        const CODE: [u8; 10] = super::encoder::<10>(b"sekurlsa::");
        assert_ne!(&CODE, b"sekurlsa::");
    }

    #[test]
    fn non_ascii_et_vide() {
        // Décodage d'UTF-8 multioctet et du mot vide : pas de panique, résultat exact.
        assert_eq!(super::decoder(&super::encoder::<0>(b"")), "");
        let accents = "élève";
        let code = super::encoder::<{ "élève".len() }>(accents.as_bytes());
        assert_eq!(super::decoder(&code), accents);
    }

    #[test]
    fn liste() {
        let liste: ::std::sync::LazyLock<Vec<String>> = liste_masquee!["amsiscanbuffer", "lsadump::"];
        assert_eq!(liste.as_slice(), &["amsiscanbuffer".to_owned(), "lsadump::".to_owned()]);
    }
}

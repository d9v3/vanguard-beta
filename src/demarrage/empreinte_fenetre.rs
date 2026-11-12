//! L'empreinte SHA-256 de la fenêtre (`vanguard-fenetre`) compilée avec ce programme : la seule fenêtre que
//! `vanguard` lance (LIV-1, MODELE-DE-MENACE.md, « La fenêtre »). `outils/compiler-version.sh` compile la fenêtre
//! d'abord, puis ce programme avec `VANGUARD_FENETRE_SHA256_LINUX` / `VANGUARD_FENETRE_SHA256_WINDOWS` ; build.rs
//! garde celle du système visé, la refuse si elle n'a pas la forme exacte, et la grave ici. Comme ce programme est
//! signé par l'auteur (manifeste et historique des versions), l'empreinte de sa fenêtre l'est aussi : aucune clé ni
//! signature de plus. Une compilation sans empreinte (`cargo build`, les essais) grave « AUCUNE » et ne lance jamais
//! de fenêtre.
//!
//! Gravée en clair dans le fichier (« VANGUARD-FENETRE:<64 chiffres>; »), elle se lit aussi sans lancer le programme :
//! la mise à jour y vérifie la fenêtre téléchargée avec un `vanguard` neuf, `compiler-version.sh` la relit.

/// L'empreinte gravée : « VANGUARD-FENETRE:<64 chiffres hexadécimaux minuscules>; » ou « VANGUARD-FENETRE:AUCUNE; ».
static GRAVEE: &str = concat!("VANGUARD-FENETRE:", env!("VANGUARD_FENETRE_GRAVEE"), ";");

/// Ce qu'un programme dit de sa fenêtre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gravee {
    /// Compilé sans fenêtre : il n'en lance aucune.
    Aucune,
    /// L'empreinte SHA-256 de la seule fenêtre qu'il lance.
    Empreinte([u8; 32]),
}

/// Garde la marque dans le fichier, appelé au début de `main` : sans une lecture qui reste après l'optimisation, un
/// programme dont le lancement de la fenêtre n'est jamais atteint (le cas avant qu'elle soit livrée) la perdait à
/// l'édition des liens. `outils/compiler-version.sh` l'a vu (compilation de la 0.96) ; il refuse un programme sans
/// sa marque, et la mise à jour lit celle du programme téléchargé.
pub(crate) fn garder() {
    std::hint::black_box(GRAVEE.as_ptr());
}

/// La fenêtre de ce programme-ci, lue dans sa marque gravée (`black_box` : sans lecture, l'éditeur de liens la
/// retirerait du fichier). `None` ne devrait jamais arriver (un essai le garde) : la fenêtre n'est alors pas lancée.
pub(crate) fn de_ce_programme() -> Option<Gravee> {
    gravee(std::hint::black_box(GRAVEE).as_bytes())
}

/// La fenêtre que dit le contenu d'un programme. `None` : aucune marque (un programme d'avant la 0.96), ou des marques
/// qui se contredisent.
pub(crate) fn gravee(octets: &[u8]) -> Option<Gravee> {
    let entete = entete();
    let mut vue = None;
    let mut reste = octets;
    while let Some(i) = reste.windows(entete.len()).position(|f| f == entete) {
        reste = reste.get(i..).and_then(|r| r.get(entete.len()..)).unwrap_or_default();
        // Ce qui suit l'en-tête sans avoir la forme exacte n'est pas une marque : ignoré.
        let Some(lue) = lire(reste) else { continue };
        match vue {
            None => vue = Some(lue),
            Some(v) if v == lue => {}
            Some(_) => return None,
        }
    }
    vue
}

/// Une marque juste après l'en-tête : « AUCUNE; » ou 64 chiffres hexadécimaux minuscules puis « ; ».
fn lire(suite: &[u8]) -> Option<Gravee> {
    if suite.starts_with(b"AUCUNE;") {
        return Some(Gravee::Aucune);
    }
    let (chiffres, apres) = (suite.get(..64)?, suite.get(64)?);
    // Minuscules seulement : `from_str_radix` accepterait aussi les majuscules et un « + ».
    if *apres != b';' || !chiffres.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let (paires, []) = chiffres.as_chunks::<2>() else {
        return None;
    };
    let mut empreinte = [0u8; 32];
    for (o, paire) in empreinte.iter_mut().zip(paires) {
        *o = u8::from_str_radix(std::str::from_utf8(paire).ok()?, 16).ok()?;
    }
    Some(Gravee::Empreinte(empreinte))
}

/// Ce qui précède la marque, décalé d'un cran (« W » pour « V ») : en clair, ce texte paraîtrait une seconde fois dans
/// le programme, suivi de ce que l'éditeur de liens met après lui (comme `mise_a_jour::ENTETE_DECALE`).
const ENTETE_DECALE: [u8; 17] = *b"WBOHVBSE.GFOFUSF;";

/// L'en-tête en clair, refait au lancement.
fn entete() -> [u8; 17] {
    std::hint::black_box(ENTETE_DECALE).map(|o| o.saturating_sub(1))
}

/// La marque d'un programme inventé qui lance la fenêtre d'empreinte `e`, pour les essais d'autres modules (la mise à
/// jour) : l'en-tête refait au lancement, comme le lecteur le refait.
#[cfg(test)]
pub(crate) fn marque_d_essai(e: &[u8; 32]) -> Vec<u8> {
    let mut m = entete().to_vec();
    m.extend(e.iter().flat_map(|o| format!("{o:02x}").into_bytes()));
    m.push(b';');
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Une marque, son en-tête refait comme le lecteur le refait : en clair dans les essais, il paraîtrait dans ce
    /// programme suivi d'autre chose, que `ce_programme_grave_sa_fenetre` lit.
    fn marque(suite: &str) -> Vec<u8> {
        let mut m = entete().to_vec();
        m.extend(suite.as_bytes());
        m.push(b';');
        m
    }

    /// Les essais compilent sans empreinte : ce programme dit « aucune », et le dit dans son propre fichier.
    #[test]
    fn ce_programme_grave_sa_fenetre() {
        assert_eq!(de_ce_programme(), Some(Gravee::Aucune));
        let exe = std::env::current_exe().unwrap();
        let octets = std::fs::read(exe).unwrap();
        assert_eq!(gravee(&octets), Some(Gravee::Aucune));
    }

    #[test]
    fn la_marque_se_lit_strictement() {
        let h = "0123456789abcdef".repeat(4);
        let mut attendu = [0u8; 32];
        for (i, o) in attendu.iter_mut().enumerate() {
            *o = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef][i % 8];
        }
        let mut entoure = b"\0\0du bruit".to_vec();
        entoure.extend(marque(&h));
        entoure.extend(entete());
        entoure.extend(b"pas une marque");
        assert_eq!(gravee(&entoure), Some(Gravee::Empreinte(attendu)));
        assert_eq!(gravee(&marque("AUCUNE")), Some(Gravee::Aucune));
        // Une marque, ou rien : longueur voisine, majuscules, sans « ; », vide.
        assert_eq!(gravee(&marque(&h[1..])), None);
        assert_eq!(gravee(&marque(&format!("{h}0"))), None);
        assert_eq!(gravee(&marque(&h.to_uppercase())), None);
        assert_eq!(gravee(&[&entete()[..], h.as_bytes()].concat()), None);
        assert_eq!(gravee(b""), None);
        // Deux marques qui se contredisent : aucune n'est crue.
        let mut deux = marque(&h);
        deux.extend(marque("AUCUNE"));
        assert_eq!(gravee(&deux), None);
        let mut deux = marque(&h);
        deux.extend(marque(&"f".repeat(64)));
        assert_eq!(gravee(&deux), None);
        // La même, deux fois : la même réponse.
        let mut deux = marque(&h);
        deux.extend(marque(&h));
        assert_eq!(gravee(&deux), Some(Gravee::Empreinte(attendu)));
    }
}

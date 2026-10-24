//! Le parcours d'une archive tar : blocs de 512 octets, un en-tête (nom, taille en octal, type) puis le contenu
//! arrondi au bloc. Les noms longs se lisent comme les écrivent bsdtar, GNU tar et git archive (codeload de GitHub) :
//! préfixe ustar, en-tête pax « x » (`path=`, `size=`) et GNU « L » pour l'entrée qui suit ; l'en-tête global « g »
//! de git archive (un commentaire) est sauté. Seuls les fichiers ordinaires sont rendus ; liens, dossiers et le reste
//! sont sautés, jamais suivis.
//!
//! Lecteur pur, sans `crate::` : le banc de fuzzing l'inclut par son chemin.

use super::Bornes;

/// Ce qu'une archive a donné : les fichiers gardés (nom, contenu) et le nombre de ceux qui étaient voulus mais trop
/// gros pour être lus (à dire, jamais à taire).
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Lus {
    pub fichiers: Vec<(String, Vec<u8>)>,
    pub trop_gros: usize,
}

/// Une entrée vue par `parcourir` : son nom complet (pax, GNU ou ustar), son type (octet 156 de l'en-tête : `0` ou
/// nul pour un fichier ordinaire, `5` un dossier, `1` et `2` des liens…), son contenu et la position de son en-tête.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entree<'a> {
    pub nom: String,
    pub type_: u8,
    pub contenu: &'a [u8],
    pub position: usize,
}

/// Comment s'est arrêté `parcourir`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FinTar {
    /// Le bloc nul de fin : tout a été vu.
    Fin,
    /// Coupée avant ses blocs de fin, ou un contenu qui déborde du fichier.
    Coupee,
    /// Une taille illisible, un en-tête pax ou un nom GNU qui n'en est pas un.
    Illisible,
    /// Plus d'en-têtes que la borne : le reste n'est pas vu.
    Limite,
    /// Le visiteur a demandé l'arrêt.
    Arretee,
}

/// Chaque entrée de `tar` (sauf les en-têtes pax « x » et « g » et les noms longs GNU « L » et « K », appliqués à
/// l'entrée qui suit), dans l'ordre, au plus `entrees` en-têtes parcourus.
pub(crate) fn parcourir<'a>(
    tar: &'a [u8],
    entrees: usize,
    mut visiteur: impl FnMut(Entree<'a>) -> std::ops::ControlFlow<()>,
) -> FinTar {
    let mut pos = 0usize;
    // Le nom et la taille donnés par un en-tête pax ou GNU, pour l'entrée qui suit seulement.
    let mut nom_suivant: Option<String> = None;
    let mut taille_suivante: Option<usize> = None;
    for _ in 0..entrees {
        let Some(entete) = pos.checked_add(512).and_then(|fin| tar.get(pos..fin)) else {
            return FinTar::Coupee;
        };
        // Deux blocs nuls marquent la fin ; le premier suffit à dire qu'il n'y a plus rien à lire.
        if entete.iter().all(|&o| o == 0) {
            return FinTar::Fin;
        }
        let taille = match taille_suivante.take() {
            Some(t) => t,
            None => match octal(&entete[124..136]) {
                Some(t) => t,
                None => return FinTar::Illisible,
            },
        };
        let debut = pos + 512;
        let Some(contenu) = debut.checked_add(taille).and_then(|fin| tar.get(debut..fin)) else {
            return FinTar::Coupee;
        };
        let position = pos;
        let Some(suivant) = taille
            .div_ceil(512)
            .checked_mul(512)
            .and_then(|arrondi| debut.checked_add(arrondi))
        else {
            return FinTar::Coupee;
        };
        pos = suivant;
        match entete[156] {
            b'x' => {
                let Some((nom, taille)) = pax(contenu) else {
                    return FinTar::Illisible;
                };
                nom_suivant = nom;
                taille_suivante = taille;
            }
            b'L' => {
                // Un nom, terminé par un nul ; au-delà de 4 Kio, ce n'en est pas un.
                if contenu.len() > 4096 {
                    return FinTar::Illisible;
                }
                let fin = contenu.iter().position(|&o| o == 0).unwrap_or(contenu.len());
                nom_suivant = Some(String::from_utf8_lossy(&contenu[..fin]).into_owned());
            }
            // L'en-tête global de git archive (le commit), le lien long de GNU : rien pour l'entrée qui suit.
            b'g' | b'K' => {}
            type_ => {
                let nom = nom_suivant.take().unwrap_or_else(|| nom_ustar(entete));
                let entree = Entree {
                    nom,
                    type_,
                    contenu,
                    position,
                };
                if visiteur(entree).is_break() {
                    return FinTar::Arretee;
                }
            }
        }
    }
    FinTar::Limite
}

/// Les fichiers ordinaires de `tar` dont `garder` accepte le nom complet. `None` : archive coupée avant ses blocs de
/// fin (ce qui manque ne doit pas passer pour absent), taille illisible, ou une borne dépassée (`entrees` en-têtes
/// parcourus, `total` octets gardés). Un fichier voulu de plus de `fichier` octets est sauté sans être lu, et
/// compté dans `trop_gros`. Dossiers, liens et le reste sont sautés, jamais suivis.
pub(crate) fn fichiers(tar: &[u8], bornes: &Bornes, mut garder: impl FnMut(&str) -> bool) -> Option<Lus> {
    use std::ops::ControlFlow;
    let mut lus = Lus::default();
    let mut total = 0usize;
    let fin = parcourir(tar, bornes.entrees, |e| {
        if !matches!(e.type_, b'0' | 0) || !garder(&e.nom) {
            return ControlFlow::Continue(());
        }
        if e.contenu.len() > bornes.fichier {
            lus.trop_gros += 1;
            return ControlFlow::Continue(());
        }
        match total.checked_add(e.contenu.len()) {
            Some(t) if t <= bornes.total => total = t,
            _ => return ControlFlow::Break(()),
        }
        lus.fichiers.push((e.nom, e.contenu.to_vec()));
        ControlFlow::Continue(())
    });
    (fin == FinTar::Fin).then_some(lus)
}

/// Le nom d'un en-tête : préfixe ustar (345..500) et nom (0..100), chacun jusqu'à son premier nul.
fn nom_ustar(entete: &[u8]) -> String {
    let champ = |de: usize, a: usize| {
        let c = &entete[de..a];
        String::from_utf8_lossy(&c[..c.iter().position(|&o| o == 0).unwrap_or(c.len())]).into_owned()
    };
    let nom = champ(0, 100);
    if &entete[257..262] == b"ustar" {
        let prefixe = champ(345, 500);
        if !prefixe.is_empty() {
            return format!("{prefixe}/{nom}");
        }
    }
    nom
}

/// Une taille en octal, stricte : des chiffres de 0 à 7 seulement, entourés d'espaces ou de nuls. La forme binaire
/// de GNU (premier octet à 0x80, pour les fichiers de plus de 8 Go) est refusée : aucun fichier lu ici n'en a besoin.
fn octal(champ: &[u8]) -> Option<usize> {
    let texte = std::str::from_utf8(champ).ok()?;
    let texte = texte.trim_matches(|c| c == ' ' || c == '\0');
    if texte.is_empty() || !texte.bytes().all(|o| (b'0'..=b'7').contains(&o)) {
        return None;
    }
    usize::from_str_radix(texte, 8).ok()
}

/// Un en-tête pax (« longueur clé=valeur\n », un par ligne) : le nom (`path`) et la taille (`size`) de l'entrée
/// suivante. Lu ligne à ligne, sans se fier à la longueur écrite devant : une valeur qui contiendrait un retour à la
/// ligne donnerait au pire un nom étrange, jamais une lecture hors de l'en-tête. `None` : une taille illisible.
fn pax(contenu: &[u8]) -> Option<(Option<String>, Option<usize>)> {
    let (mut nom, mut taille) = (None, None);
    for ligne in contenu.split(|&o| o == b'\n') {
        let Some(espace) = ligne.iter().position(|&o| o == b' ') else {
            continue;
        };
        let enregistrement = &ligne[espace + 1..];
        if let Some(valeur) = enregistrement.strip_prefix(b"path=") {
            nom = Some(String::from_utf8_lossy(valeur).into_owned());
        } else if let Some(valeur) = enregistrement.strip_prefix(b"size=") {
            let texte = std::str::from_utf8(valeur).ok()?;
            if texte.is_empty() || !texte.bytes().all(|o| o.is_ascii_digit()) {
                return None;
            }
            taille = Some(texte.parse().ok()?);
        }
    }
    Some((nom, taille))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BORNES: Bornes = Bornes {
        entrees: 100,
        fichier: 1 << 10,
        total: 1 << 12,
    };

    /// Une entrée tar faite à la main : en-tête ustar (nom, préfixe, taille en octal, type) et contenu arrondi.
    fn entree(tar: &mut Vec<u8>, nom: &str, prefixe: &str, contenu: &[u8], type_: u8) {
        let mut entete = [0u8; 512];
        entete[..nom.len()].copy_from_slice(nom.as_bytes());
        entete[124..135].copy_from_slice(format!("{:011o}", contenu.len()).as_bytes());
        entete[156] = type_;
        entete[257..263].copy_from_slice(b"ustar\0");
        entete[345..345 + prefixe.len()].copy_from_slice(prefixe.as_bytes());
        tar.extend(entete);
        tar.extend(contenu);
        tar.extend(vec![0u8; contenu.len().div_ceil(512) * 512 - contenu.len()]);
    }

    /// Une archive comme codeload la donne pour un dépôt : en-tête global « g », dossiers, noms longs par pax « x »
    /// et GNU « L », préfixe ustar, un lien, puis les blocs de fin.
    fn archive() -> Vec<u8> {
        let mut tar = Vec::new();
        entree(
            &mut tar,
            "pax_global_header",
            "",
            b"52 comment=0123456789abcdef0123456789abcdef01234567\n",
            b'g',
        );
        entree(&mut tar, "depot-main/", "", b"", b'5');
        entree(
            &mut tar,
            "depot-main/announce/2026/mfsa2026-01.yml",
            "",
            b"fixed_in:\n- Firefox 150\n",
            b'0',
        );
        let long = format!("depot-main/announce/2026/{}.yml", "x".repeat(120));
        entree(
            &mut tar,
            "PaxHeader/long",
            "",
            format!("130 path={long}\n").as_bytes(),
            b'x',
        );
        entree(&mut tar, "tronque", "", b"pax\n", b'0');
        entree(&mut tar, "././@LongLink", "", format!("{long}-gnu\0").as_bytes(), b'L');
        entree(&mut tar, "tronque2", "", b"gnu\n", b'0');
        entree(&mut tar, "mfsa2025-99.md", "depot-main/announce/2025", b"---\n", 0);
        entree(&mut tar, "depot-main/lien.yml", "", b"", b'2');
        entree(&mut tar, "depot-main/README.md", "", b"# x\n", b'0');
        tar.extend([0u8; 1024]);
        tar
    }

    #[test]
    fn noms_longs_prefixe_et_types() {
        let lus = fichiers(&archive(), &BORNES, |n| n.contains("/announce/")).unwrap();
        let noms: Vec<&str> = lus.fichiers.iter().map(|(n, _)| n.as_str()).collect();
        let long = format!("depot-main/announce/2026/{}.yml", "x".repeat(120));
        assert_eq!(
            noms,
            [
                "depot-main/announce/2026/mfsa2026-01.yml",
                long.as_str(),
                format!("{long}-gnu").as_str(),
                "depot-main/announce/2025/mfsa2025-99.md",
            ]
        );
        assert_eq!(lus.fichiers[1].1, b"pax\n");
        assert_eq!(lus.fichiers[2].1, b"gnu\n");
        assert_eq!(lus.trop_gros, 0);
        // Tout garder : le README aussi, jamais le lien, le dossier ni l'en-tête global.
        let tous = fichiers(&archive(), &BORNES, |_| true).unwrap();
        assert_eq!(tous.fichiers.len(), 5);
        assert!(
            tous.fichiers
                .iter()
                .all(|(n, _)| !n.contains("lien") && !n.contains("pax_global"))
        );
    }

    #[test]
    fn coupee_ou_illisible() {
        let tar = archive();
        // Coupée au milieu d'un contenu, entre deux entrées, ou sans blocs de fin : ce qui manque ne passe pas pour
        // absent.
        assert_eq!(fichiers(&tar[..512 * 3 + 10], &BORNES, |_| true), None);
        assert_eq!(fichiers(&tar[..512 * 4], &BORNES, |_| true), None);
        assert_eq!(fichiers(&tar[..tar.len() - 1024], &BORNES, |_| true), None);
        assert_eq!(fichiers(&[], &BORNES, |_| true), None);
        // Taille non octale, ou binaire de GNU.
        for taille in [
            &b"00000000009\0"[..],
            b"           \0",
            b"0000000001x\0",
            b"\x80\0\0\0\0\0\0\0\0\0\0\x10",
        ] {
            let mut abimee = tar.clone();
            abimee[512 * 2 + 124..512 * 2 + 136].copy_from_slice(taille);
            assert_eq!(fichiers(&abimee, &BORNES, |_| true), None, "{taille:?}");
        }
        // Taille annoncée plus grande que l'archive.
        let mut grosse = Vec::new();
        entree(&mut grosse, "a", "", b"x", b'0');
        grosse[124..135].copy_from_slice(b"77777777777");
        assert_eq!(fichiers(&grosse, &BORNES, |_| true), None);
        // Une page d'erreur à la place.
        assert_eq!(fichiers(&b"<html>Not Found</html>".repeat(50), &BORNES, |_| true), None);
    }

    #[test]
    fn bornes() {
        let mut tar = Vec::new();
        entree(&mut tar, "a/gros.yml", "", &vec![b'x'; 2000], b'0');
        entree(&mut tar, "a/petit.yml", "", b"ok", b'0');
        tar.extend([0u8; 1024]);
        // Trop gros : sauté sans être lu, et compté.
        let lus = fichiers(&tar, &BORNES, |_| true).unwrap();
        assert_eq!(lus.fichiers, vec![("a/petit.yml".to_string(), b"ok".to_vec())]);
        assert_eq!(lus.trop_gros, 1);
        // Pas voulu : ni lu ni compté.
        assert_eq!(
            fichiers(&tar, &BORNES, |n| n.ends_with("petit.yml")).unwrap().trop_gros,
            0
        );
        // Total dépassé : rien de rendu, plutôt qu'une partie.
        let mut plein = Vec::new();
        for i in 0..5 {
            entree(&mut plein, &format!("a/{i}.yml"), "", &[b'y'; 1000], b'0');
        }
        plein.extend([0u8; 1024]);
        assert_eq!(fichiers(&plein, &BORNES, |_| true), None);
        // Plus d'en-têtes que la borne.
        let peu = Bornes { entrees: 4, ..BORNES };
        assert_eq!(fichiers(&plein, &peu, |_| false), None);
        assert!(fichiers(&plein, &Bornes { entrees: 6, ..peu }, |_| false).is_some());
    }

    /// La taille d'un en-tête pax l'emporte sur celle de l'en-tête ustar (celle des fichiers de plus de 8 Go).
    #[test]
    fn taille_donnee_par_pax() {
        let mut tar = Vec::new();
        entree(&mut tar, "PaxHeader/a", "", b"12 size=600\n", b'x');
        let mut a = Vec::new();
        entree(&mut a, "a.yml", "", &[b'z'; 600], b'0');
        a[124..135].copy_from_slice(b"00000000000");
        tar.extend(a);
        tar.extend([0u8; 1024]);
        let lus = fichiers(&tar, &BORNES, |_| true).unwrap();
        assert_eq!(lus.fichiers[0].1.len(), 600);
        let mut faux = Vec::new();
        entree(&mut faux, "PaxHeader/a", "", b"12 size=6x0\n", b'x');
        assert_eq!(fichiers(&faux, &BORNES, |_| true), None);
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 2000, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn jamais_de_plantage(octets in proptest::collection::vec(proptest::num::u8::ANY, 0..3000)) {
            let _ = fichiers(&octets, &BORNES, |_| true);
        }

        /// Une archive valide abîmée d'un octet : lue ou refusée, sans planter.
        #[test]
        fn archive_abimee(i in 0usize..10_000, x in 1u8..=255) {
            let mut tar = archive();
            let i = i % tar.len();
            tar[i] ^= x;
            let _ = fichiers(&tar, &BORNES, |_| true);
        }
    }
}

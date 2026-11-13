//! Ce que /etc/ld.so.preload fait charger dans TOUS les programmes, root compris : une seule lecture, sur les octets,
//! partagée par le bilan (`linux/persistance.rs`), le geste de défense du fils root (`defense_eleve.rs`) et l'avis du
//! démarrage (`protection/environnement.rs`). Chacun avait sa lecture, et elles avaient dérivé (relecture adverse du
//! lot 096, C1 à C4).
//!
//! Le chargeur de glibc (`elf/rtld.c`, `dl_main`) n'efface pas les commentaires ligne par ligne : sa boucle cherche
//! chaque « # » depuis le DÉBUT du fichier, avec un compte d'octets qui a déjà perdu tout ce qui précédait la fin du
//! commentaire d'avant. Dès le deuxième « # », la recherche ou l'effacement s'arrête trop tôt, et une ligne
//! « # /chemin.so » peut être chargée. Sa boucle est donc portée telle quelle, bogue compris (comparée au vrai
//! chargeur, glibc 2.44 : voir les essais), puis réunie avec la lecture « idéale » (« # » jusqu'au bout de sa ligne),
//! pour le cas où une autre glibc lirait autrement : une bibliothèque vue par l'une des deux compte.

/// Les séparateurs du chargeur : espace, tabulation, « \n » et « : ». Pas « \r » : « a.so\r » est un autre fichier
/// que « a.so », et c'est lui que le chargeur cherche.
const SEPARATEURS: [u8; 4] = *b" \t\n:";

/// Une bibliothèque que /etc/ld.so.preload fait charger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Prechargee {
    /// Son nom, octet pour octet, tel que le chargeur le cherche (un « \r » ou un octet hors UTF-8 compris).
    pub(crate) nom: Vec<u8>,
    /// Sa ligne, comptée depuis 0 et coupée au seul « \n », comme la relit le fils root.
    pub(crate) ligne: usize,
    /// Après un « # » de sa ligne : la ligne semble en commentaire, mais le chargeur la lit quand même.
    pub(crate) apres_un_diese: bool,
}

/// Les bibliothèques que /etc/ld.so.preload, de contenu `octets`, fait charger, dans l'ordre du fichier : celles du
/// chargeur de glibc (`comme_le_chargeur`) réunies avec celles de la lecture idéale (`par_ligne`).
pub(crate) fn bibliotheques(octets: &[u8]) -> Vec<Prechargee> {
    let mut mots = comme_le_chargeur(octets);
    mots.extend(par_ligne(octets));
    mots.sort_unstable();
    mots.dedup();
    let mut sortie = Vec::with_capacity(mots.len());
    // Les mots sont triés par leur début : la ligne se suit d'un mot au suivant, en un seul passage sur le fichier.
    let (mut vu, mut ligne, mut debut_de_ligne) = (0usize, 0usize, 0usize);
    for (debut, fin) in mots {
        if let Some(entre) = octets.get(vu..debut) {
            for (i, o) in entre.iter().enumerate() {
                if *o == b'\n' {
                    ligne = ligne.saturating_add(1);
                    debut_de_ligne = vu.saturating_add(i).saturating_add(1);
                }
            }
        }
        vu = vu.max(debut);
        sortie.push(Prechargee {
            nom: octets.get(debut..fin).unwrap_or_default().to_vec(),
            ligne,
            apres_un_diese: octets.get(debut_de_ligne..fin).is_some_and(|d| d.contains(&b'#')),
        });
    }
    sortie
}

/// Les seuls noms que le chargeur de glibc 2.44 essaie de charger (`comme_le_chargeur`), sans la lecture idéale : pour
/// voir ce qu'un retrait lui fait VRAIMENT charger en plus (ronde 4 du lot 096, G34-2 : une ligne qui porte un NUL
/// l'arrête, et les lignes suivantes, montrées au bilan par la lecture idéale, ne sont chargées qu'après son retrait).
pub(crate) fn noms_du_chargeur(octets: &[u8]) -> Vec<Vec<u8>> {
    comme_le_chargeur(octets)
        .into_iter()
        .map(|(debut, fin)| octets.get(debut..fin).unwrap_or_default().to_vec())
        .collect()
}

/// Les mots de `f[debut..fin]` qui ne contiennent aucun octet `coupe`, en (début, fin) dans `f`.
fn mots(f: &[u8], debut: usize, fin: usize, coupe: impl Fn(u8) -> bool, sortie: &mut Vec<(usize, usize)>) {
    let mut mot: Option<usize> = None;
    let fin = fin.min(f.len());
    for (i, o) in f.iter().enumerate().take(fin).skip(debut) {
        if coupe(*o) {
            if let Some(d) = mot.take() {
                sortie.push((d, i));
            }
        } else if mot.is_none() {
            mot = Some(i);
        }
    }
    if let Some(d) = mot {
        sortie.push((d, fin));
    }
}

/// La lecture du chargeur de glibc 2.44 (`elf/rtld.c`, `dl_main`), portée telle quelle : les mots qu'il essaie de
/// charger, en (début, fin) dans `octets`, dans son ordre.
fn comme_le_chargeur(octets: &[u8]) -> Vec<(usize, usize)> {
    // Un fichier vide n'est pas projeté en mémoire (`_dl_sysdep_read_whole_file`) : rien n'est chargé.
    if octets.is_empty() {
        return Vec::new();
    }
    let mut f = octets.to_vec();
    // 1. Les commentaires, effacés en place par des espaces. Le début de la recherche (`runp`) n'avance jamais, seul
    //    le compte (`rest`) diminue : c'est le bogue, gardé tel quel.
    //      comment = memchr (runp, '#', rest); rest -= comment - runp;
    //      do *comment = ' '; while (--rest > 0 && *++comment != '\n');
    let mut reste = f.len();
    while reste > 0 {
        let Some(diese) = f.get(..reste).and_then(|d| d.iter().position(|o| *o == b'#')) else {
            break;
        };
        reste = reste.saturating_sub(diese);
        let mut i = diese;
        loop {
            if let Some(o) = f.get_mut(i) {
                *o = b' ';
            }
            reste = reste.saturating_sub(1);
            i = i.saturating_add(1);
            if reste == 0 || f.get(i) == Some(&b'\n') {
                break;
            }
        }
    }
    // 2. Un dernier nom qu'aucun séparateur ne suit (`problem`) : l'octet qui le précède devient NUL, et il est lu à
    //    part, même s'il vient après un NUL. Sinon, le dernier octet (un séparateur) devient NUL.
    let probleme = if f.last().is_some_and(|o| !SEPARATEURS.contains(o)) {
        let debut = f
            .iter()
            .rposition(|o| SEPARATEURS.contains(o))
            .map_or(0, |p| p.saturating_add(1));
        if let Some(avant) = debut.checked_sub(1).and_then(|p| f.get_mut(p)) {
            *avant = 0;
        }
        Some(debut)
    } else {
        if let Some(o) = f.last_mut() {
            *o = 0;
        }
        None
    };
    let mut sortie = Vec::new();
    // 3. `strsep` sur la chaîne C du début du fichier : jusqu'au premier NUL, coupée sur les séparateurs. Sautée
    //    quand le dernier nom commence le fichier (`file != problem`).
    if probleme != Some(0) {
        let fin = f.iter().position(|o| *o == 0).unwrap_or(f.len());
        mots(&f, 0, fin, |o| SEPARATEURS.contains(&o), &mut sortie);
    }
    // 4. Le dernier nom (`strndupa`) : jusqu'à son premier NUL ; vide, il ne nomme rien.
    if let Some(debut) = probleme {
        let fin = f
            .get(debut..)
            .and_then(|d| d.iter().position(|o| *o == 0))
            .map_or(f.len(), |p| debut.saturating_add(p));
        if fin > debut {
            sortie.push((debut, fin));
        }
    }
    sortie
}

/// La lecture « idéale » : un « # » ferme sa ligne jusqu'au « \n » ; mots coupés sur les séparateurs et sur NUL. Un
/// nom caché derrière un NUL se montre donc : le chargeur d'aujourd'hui s'arrête au NUL, rien ne dit qu'un autre le
/// fera, et un NUL dans ce fichier texte est déjà une façon de cacher.
fn par_ligne(octets: &[u8]) -> Vec<(usize, usize)> {
    let mut sortie = Vec::new();
    let mut debut = 0usize;
    for ligne in octets.split(|o| *o == b'\n') {
        let utile = ligne.iter().position(|o| *o == b'#').unwrap_or(ligne.len());
        mots(
            octets,
            debut,
            debut.saturating_add(utile),
            |o| SEPARATEURS.contains(&o) || o == 0,
            &mut sortie,
        );
        debut = debut.saturating_add(ligne.len()).saturating_add(1);
    }
    sortie
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noms(v: &[(usize, usize)], f: &[u8]) -> Vec<Vec<u8>> {
        v.iter().map(|(d, e)| f[*d..*e].to_vec()).collect()
    }

    fn tous(f: &[u8]) -> Vec<Vec<u8>> {
        bibliotheques(f).into_iter().map(|b| b.nom).collect()
    }

    /// Ce que le VRAI chargeur essaie de charger pour chacun de ces fichiers : relevé sur glibc 2.44, dans un bac à
    /// sable bwrap (un faux /etc/ld.so.preload monté, `/usr/bin/true` lancé, les noms lus dans ses messages
    /// « object '…' cannot be preloaded »). La boucle portée doit rendre exactement la même liste, dans le même
    /// ordre. Le même relevé a été refait sur 3000 fichiers tirés au hasard (« # », blancs, « : », « \r », NUL…),
    /// tous identiques (rapport du lot 096).
    #[test]
    fn colle_au_vrai_chargeur() {
        let cas: [(&[u8], &[&[u8]]); 20] = [
            // Relecture adverse, C1 : le deuxième « # » n'est jamais effacé, la bibliothèque est chargée.
            (
                b"# une note anodine assez longue pour couvrir la suite du fichier\n# /opt/x/evil.so\n",
                &[b"#", b"/opt/x/evil.so"],
            ),
            // C1, autre forme : l'effacement s'arrête trop tôt, « so » reste.
            (b"# c\n# /tmp/evil2.so\n", &[b"so"]),
            // C2 : le « \r » fait partie du nom.
            (b"/opt/x/libz.so.1\r\n", &[b"/opt/x/libz.so.1\r"]),
            // C3 : le premier « # » ferme bien sa ligne.
            (b"/usr/lib/a.so # note /tmp/c.so\n", &[b"/usr/lib/a.so"]),
            // C5 : des mots vides puis un commentaire.
            (b": # x\n", &[]),
            (
                b"/tmp/a.so\n# long comment ......\n# /opt/b.so\n",
                &[b"/tmp/a.so", b"#", b"/opt/b.so"],
            ),
            // NUL : la chaîne C s'arrête, sauf pour un dernier nom sans séparateur après lui.
            (b"/a.so\0/b.so", &[b"/a.so"]),
            (b"/a.so\0x /b.so", &[b"/a.so", b"/b.so"]),
            (b"/a.so\0x /b.so\n", &[b"/a.so"]),
            // Un NUL dans un commentaire effacé ne coupe rien.
            (b"# x\0y\n/a.so\n", &[b"/a.so"]),
            (b"\n\0", &[]),
            (b"#", &[]),
            (b"a#b", &[b"a"]),
            (b"# rien\n# note\n", &[b"note"]),
            (b"/tmp/.x/libhook.so\n# note\n", &[b"/tmp/.x/libhook.so"]),
            (b"//tmp/.x/libhook.so\n", &[b"//tmp/.x/libhook.so"]),
            (
                b"-- /tmp/l.so\n; /tmp/l.so\n",
                &[b"--", b"/tmp/l.so", b";", b"/tmp/l.so"],
            ),
            (b"/a.so:/b.so\t/c.so /d.so", &[b"/a.so", b"/b.so", b"/c.so", b"/d.so"]),
            // Saut de page et tabulation verticale ne coupent pas.
            (b"\x0c/a.so\x0b\n", &[b"\x0c/a.so\x0b"]),
            (b"\xff/a.so\n", &[b"\xff/a.so"]),
        ];
        for (contenu, attendu) in cas {
            let vu = comme_le_chargeur(contenu);
            let attendu: Vec<Vec<u8>> = attendu.iter().map(|m| m.to_vec()).collect();
            assert_eq!(noms(&vu, contenu), attendu, "{:?}", String::from_utf8_lossy(contenu));
            // La réunion n'en perd aucun.
            let t = tous(contenu);
            assert!(
                attendu.iter().all(|m| t.contains(m)),
                "{:?}",
                String::from_utf8_lossy(contenu)
            );
        }
        assert_eq!(comme_le_chargeur(b""), Vec::new());
    }

    /// La ligne de chaque bibliothèque (coupée au seul « \n », comme le fils root) et la marque « après un # » : une
    /// ligne qui semble en commentaire mais que le chargeur lit quand même.
    #[test]
    fn ligne_et_diese() {
        let f = b"/usr/lib/a.so\n# une note anodine assez longue pour couvrir la suite\n# /opt/x/evil.so\n";
        let b = bibliotheques(f);
        let vu: Vec<(&[u8], usize, bool)> = b
            .iter()
            .map(|p| (p.nom.as_slice(), p.ligne, p.apres_un_diese))
            .collect();
        assert_eq!(
            vu,
            vec![
                (b"/usr/lib/a.so".as_slice(), 0, false),
                (b"#".as_slice(), 2, true),
                (b"/opt/x/evil.so".as_slice(), 2, true),
            ]
        );
        // Une ligne en « \r\n » garde son « \r » et son numéro.
        let b = bibliotheques(b"# x\r\n/tmp/a.so\r\n");
        assert_eq!(b.len(), 1);
        assert_eq!(
            (b[0].nom.as_slice(), b[0].ligne, b[0].apres_un_diese),
            (b"/tmp/a.so\r".as_slice(), 1, false)
        );
    }

    /// Rien à charger : fichier vide, blancs, séparateurs seuls, commentaires seuls (C5 : « : # x »).
    #[test]
    fn rien_a_charger() {
        for vide in [
            &b""[..],
            b"   ",
            b"\t\n",
            b":",
            b": # x\n",
            b"# tout en commentaire\n",
            b"   # decale\n",
        ] {
            assert!(bibliotheques(vide).is_empty(), "{:?}", String::from_utf8_lossy(vide));
        }
    }

    /// La lecture idéale complète celle du chargeur : un nom caché derrière un NUL se montre aussi.
    #[test]
    fn reunion_avec_la_lecture_ideale() {
        assert_eq!(
            noms(&comme_le_chargeur(b"/a.so\0/b.so\n"), b"/a.so\0/b.so\n"),
            vec![b"/a.so".to_vec()]
        );
        assert_eq!(tous(b"/a.so\0/b.so\n"), vec![b"/a.so".to_vec(), b"/b.so".to_vec()]);
    }

    /// `noms_du_chargeur` rend les seuls noms du chargeur, sans la lecture idéale : une ligne qui porte un NUL cache
    /// au chargeur les lignes suivantes, qu'il charge une fois cette ligne retirée (ronde 4 du lot 096, G34-2). Cet
    /// essai la tient aussi dans la compilation des essais pour Windows, où le seul code qui s'en sert (Linux) manque.
    #[test]
    fn noms_du_chargeur_sans_la_lecture_ideale() {
        assert_eq!(noms_du_chargeur(b"/a.so\0\n/b.so\n"), vec![b"/a.so".to_vec()]);
        assert_eq!(noms_du_chargeur(b"/b.so\n"), vec![b"/b.so".to_vec()]);
        assert_eq!(noms_du_chargeur(b""), Vec::<Vec<u8>>::new());
    }

    /// Sur des fichiers tirés au hasard (graine fixe) : jamais de panique, chaque nom est non vide, sans séparateur,
    /// à sa ligne, et la réunion garde tout ce que le chargeur charge.
    #[test]
    fn jamais_de_panique_ni_de_perte() {
        let alphabet: &[&[u8]] = &[b"#", b" ", b"\t", b":", b"\n", b"\r", b"\0", b"a", b"/", b"so", b"\xff"];
        let mut graine: u64 = 0x5eed_0960;
        let mut tirer = |n: u64| {
            graine = graine
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (graine >> 33) % n
        };
        for _ in 0..5000 {
            let longueur = tirer(48);
            let mut f = Vec::new();
            for _ in 0..longueur {
                f.extend_from_slice(alphabet[usize::try_from(tirer(alphabet.len() as u64)).unwrap()]);
            }
            let b = bibliotheques(&f);
            for p in &b {
                assert!(
                    !p.nom.is_empty() && !p.nom.iter().any(|o| SEPARATEURS.contains(o)),
                    "{f:?}"
                );
                let lignes: Vec<&[u8]> = f.split(|o| *o == b'\n').collect();
                assert!(
                    lignes[p.ligne].windows(p.nom.len()).any(|w| w == p.nom.as_slice()),
                    "{f:?}"
                );
            }
            let t: Vec<Vec<u8>> = b.into_iter().map(|p| p.nom).collect();
            for m in noms(&comme_le_chargeur(&f), &f) {
                assert!(t.contains(&m), "{f:?}");
            }
        }
    }
}

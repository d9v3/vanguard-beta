//! Les raccourcis Windows (.lnk, [MS-SHLLINK]) : en-tête de 76 octets (HeaderSize 0x4C, LinkCLSID
//! 00021401-0000-0000-C000-000000000046, LinkFlags), liste d'identifiants (LinkTargetIDList, IDListSize puis les
//! éléments, terminés par deux octets nuls), LinkInfo (chemin local LocalBasePath et CommonPathSuffix, ou réseau
//! CommonNetworkRelativeLink, et leurs formes Unicode), chaînes (NAME_STRING, RELATIVE_PATH, WORKING_DIR,
//! COMMAND_LINE_ARGUMENTS, ICON_LOCATION : un compte de caractères de 16 bits, UTF-16 si IsUnicode), blocs de
//! données (taille, signature ; EnvironmentVariableDataBlock 0xA0000001 de 0x314 octets ; fin : un bloc de moins de 4
//! octets). Ce qui suit le bloc de fin n'appartient pas au raccourci : des octets ajoutés, à analyser à part.
//!
//! La liste d'identifiants n'est pas décodée (son contenu dépend de chaque extension de l'Explorateur, la
//! spécification ne le décrit pas) : quand elle seule désigne la cible, celle-ci n'est connue qu'à peu près (les
//! noms lisibles qu'elle contient), et c'est dit.
//!
//! Lecteur pur, sans `crate::` : le banc de fuzzing l'inclut par son chemin.

use super::lecture::{chaine_c, chaine_utf16, latin1_ou_utf8, tranche, u16le, u32le, utf16le};

pub(crate) const CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
const HAS_ID_LIST: u32 = 1;
const HAS_LINK_INFO: u32 = 1 << 1;
const HAS_NAME: u32 = 1 << 2;
const HAS_RELATIVE_PATH: u32 = 1 << 3;
const HAS_WORKING_DIR: u32 = 1 << 4;
const HAS_ARGUMENTS: u32 = 1 << 5;
const HAS_ICON_LOCATION: u32 = 1 << 6;
const IS_UNICODE: u32 = 1 << 7;
const BLOC_ENVIRONNEMENT: u32 = 0xA000_0001;
const BLOCS_MAX: usize = 64;
const CHEMIN_MAX: usize = 4096;

/// Ce que dit un raccourci.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Lnk {
    pub drapeaux: u32,
    pub attributs: u32,
    pub affichage: u32,
    /// La liste d'identifiants, brute.
    pub liste_ids: Option<Vec<u8>>,
    pub chemin_local: Option<String>,
    pub chemin_reseau: Option<String>,
    pub suffixe: Option<String>,
    pub nom: Option<String>,
    pub chemin_relatif: Option<String>,
    pub dossier: Option<String>,
    pub arguments: Option<String>,
    pub icone: Option<String>,
    pub cible_environnement: Option<String>,
    pub signatures_blocs: Vec<u32>,
    /// La structure s'arrête avant sa fin (chaîne, bloc ou liste coupés).
    pub tronque: bool,
    /// Où finit le raccourci (après le bloc de fin) : au-delà, des octets ajoutés.
    pub fin: usize,
}

/// Les programmes qui exécutent ce qu'on leur donne (interpréteurs, hôtes de scripts, et ceux que Windows fournit
/// et que des attaques détournent) : un raccourci qui en lance un est un fait à relever.
pub(crate) const INTERPRETEURS: &[&str] = &[
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "msiexec.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "forfiles.exe",
    "conhost.exe",
    "wmic.exe",
    "msbuild.exe",
    "installutil.exe",
    "regasm.exe",
    "regsvcs.exe",
    "cmstp.exe",
    "schtasks.exe",
    "curl.exe",
    "hh.exe",
    "msxsl.exe",
    "odbcconf.exe",
    "pcalua.exe",
];

impl Lnk {
    /// La cible, telle que Windows la compose : chemin local ou réseau et son suffixe, sinon le bloc d'environnement,
    /// sinon le chemin relatif. `None` : seule la liste d'identifiants la désigne.
    pub(crate) fn cible(&self) -> Option<String> {
        let suffixe = self.suffixe.clone().unwrap_or_default();
        if let Some(local) = self.chemin_local.as_ref().filter(|c| !c.is_empty()) {
            return Some(format!("{local}{suffixe}"));
        }
        if let Some(reseau) = self.chemin_reseau.as_ref().filter(|c| !c.is_empty()) {
            return Some(if suffixe.is_empty() {
                reseau.clone()
            } else {
                format!("{reseau}\\{suffixe}")
            });
        }
        self.cible_environnement
            .clone()
            .filter(|c| !c.is_empty())
            .or_else(|| self.chemin_relatif.clone().filter(|c| !c.is_empty()))
    }

    /// Les noms lisibles de la liste d'identifiants (ASCII et UTF-16 d'au moins 3 caractères), joints par « \ » :
    /// une cible approchée, quand rien d'autre ne la donne.
    pub(crate) fn cible_approchee(&self) -> Option<String> {
        let ids = self.liste_ids.as_ref()?;
        let mut morceaux: Vec<String> = Vec::new();
        for m in chaines_lisibles(ids) {
            if !morceaux.contains(&m) {
                morceaux.push(m);
            }
        }
        (!morceaux.is_empty()).then(|| morceaux.join("\\"))
    }

    /// Les interpréteurs nommés dans la cible, les arguments ou la liste d'identifiants (sans tenir compte de la
    /// casse, en ASCII comme en UTF-16).
    pub(crate) fn interpreteurs(&self) -> Vec<&'static str> {
        let mut textes: Vec<String> = [self.cible(), self.arguments.clone(), self.cible_approchee()]
            .into_iter()
            .flatten()
            .map(|t| t.to_ascii_lowercase())
            .collect();
        if let Some(ids) = &self.liste_ids {
            textes.push(latin1_ou_utf8(ids).to_ascii_lowercase());
        }
        INTERPRETEURS
            .iter()
            .copied()
            .filter(|i| {
                let sans_exe = i.trim_end_matches(".exe");
                textes.iter().any(|t| {
                    t.contains(i)
                        || (sans_exe.len() >= 4
                            && t.split(|c: char| !(c.is_alphanumeric() || c == '.' || c == '_' || c == '-'))
                                .any(|mot| mot == sans_exe))
                })
            })
            .collect()
    }

    /// Des arguments rembourrés : une longue suite de blancs, qui repousse le vrai contenu au-delà de ce que montre la
    /// fenêtre des propriétés.
    pub(crate) fn arguments_rembourres(&self) -> bool {
        self.arguments.as_ref().is_some_and(|a| {
            let mut suite = 0usize;
            a.chars().any(|c| {
                suite = if c.is_whitespace() { suite + 1 } else { 0 };
                suite >= 64
            })
        })
    }
}

/// Les suites lisibles d'au moins 3 caractères (lettres, chiffres, ponctuation de chemin), en ASCII et en UTF-16.
fn chaines_lisibles(octets: &[u8]) -> Vec<String> {
    let lisible = |c: u8| c.is_ascii_alphanumeric() || b" .-_:\\$~()[]".contains(&c);
    let mut v = Vec::new();
    let mut courant = String::new();
    for &o in octets {
        if lisible(o) {
            courant.push(char::from(o));
        } else {
            if courant.len() >= 3 {
                v.push(std::mem::take(&mut courant));
            }
            courant.clear();
        }
    }
    if courant.len() >= 3 {
        v.push(std::mem::take(&mut courant));
    }
    for decalage in 0..2 {
        courant.clear();
        let mut k = decalage;
        while k + 1 < octets.len() {
            let (bas, haut) = (octets[k], octets[k + 1]);
            if haut == 0 && lisible(bas) {
                courant.push(char::from(bas));
            } else {
                if courant.len() >= 3 && !v.contains(&courant) {
                    v.push(courant.clone());
                }
                courant.clear();
            }
            k += 2;
        }
        if courant.len() >= 3 && !v.contains(&courant) {
            v.push(courant.clone());
        }
    }
    v
}

/// Le raccourci `octets`. `None` : pas un raccourci (en-tête ou CLSID).
pub(crate) fn lire(octets: &[u8]) -> Option<Lnk> {
    if u32le(octets, 0)? != 0x4C || tranche(octets, 4, 16)? != CLSID {
        return None;
    }
    let drapeaux = u32le(octets, 20)?;
    let mut l = Lnk {
        drapeaux,
        attributs: u32le(octets, 24)?,
        affichage: u32le(octets, 60)?,
        ..Lnk::default()
    };
    let mut i = 76usize;
    if drapeaux & HAS_ID_LIST != 0 {
        let Some(taille) = u16le(octets, i).map(usize::from) else {
            l.tronque = true;
            l.fin = octets.len();
            return Some(l);
        };
        let Some(ids) = tranche(octets, i + 2, taille) else {
            l.tronque = true;
            l.fin = octets.len();
            return Some(l);
        };
        l.liste_ids = Some(ids.to_vec());
        i += 2 + taille;
    }
    if drapeaux & HAS_LINK_INFO != 0 {
        let Some(taille) = u32le(octets, i).map(|t| t as usize) else {
            l.tronque = true;
            l.fin = octets.len();
            return Some(l);
        };
        match tranche(octets, i, taille) {
            // ForceNoLinkInfo : Windows l'ignore, nous la lisons quand même (la cible qu'elle désigne est un fait).
            Some(info) if taille >= 0x1C => lien(info, &mut l),
            _ => {
                l.tronque = true;
                l.fin = octets.len();
                return Some(l);
            }
        }
        i += taille;
    }
    let unicode = drapeaux & IS_UNICODE != 0;
    for (drapeau, champ) in [
        (HAS_NAME, 0usize),
        (HAS_RELATIVE_PATH, 1),
        (HAS_WORKING_DIR, 2),
        (HAS_ARGUMENTS, 3),
        (HAS_ICON_LOCATION, 4),
    ] {
        if drapeaux & drapeau == 0 {
            continue;
        }
        let Some(compte) = u16le(octets, i).map(usize::from) else {
            l.tronque = true;
            l.fin = octets.len();
            return Some(l);
        };
        let n = if unicode { compte * 2 } else { compte };
        let Some(brut) = tranche(octets, i + 2, n) else {
            l.tronque = true;
            l.fin = octets.len();
            return Some(l);
        };
        let texte = if unicode { utf16le(brut) } else { latin1_ou_utf8(brut) };
        i += 2 + n;
        let place = match champ {
            0 => &mut l.nom,
            1 => &mut l.chemin_relatif,
            2 => &mut l.dossier,
            3 => &mut l.arguments,
            _ => &mut l.icone,
        };
        *place = Some(texte);
    }
    // Les blocs de données, jusqu'au bloc de fin.
    for _ in 0..BLOCS_MAX {
        let Some(taille) = u32le(octets, i).map(|t| t as usize) else {
            l.tronque = true;
            l.fin = octets.len();
            return Some(l);
        };
        if taille < 4 {
            l.fin = i + 4;
            return Some(l);
        }
        let Some(bloc) = tranche(octets, i, taille).filter(|_| taille >= 8) else {
            l.tronque = true;
            l.fin = octets.len();
            return Some(l);
        };
        let signature = u32le(bloc, 4).unwrap_or(0);
        l.signatures_blocs.push(signature);
        if signature == BLOC_ENVIRONNEMENT && taille >= 0x314 {
            let unicode = chaine_utf16(bloc, 8 + 260, 520).filter(|c| !c.is_empty());
            l.cible_environnement = unicode.or_else(|| chaine_c(bloc, 8, 260));
        }
        i += taille;
    }
    // Plus de blocs que la borne : le reste n'est pas lu.
    l.tronque = true;
    l.fin = octets.len();
    Some(l)
}

/// LinkInfo : chemin local (LocalBasePath, CommonPathSuffix et leurs formes Unicode quand l'en-tête les annonce) ou
/// réseau (NetName de CommonNetworkRelativeLink). Chaque décalage est contrôlé contre la taille de la structure.
fn lien(info: &[u8], l: &mut Lnk) {
    let taille_entete = u32le(info, 4).unwrap_or(0) as usize;
    let drapeaux = u32le(info, 8).unwrap_or(0);
    let champ = |a: usize| u32le(info, a).map(|v| v as usize).filter(|&v| v > 0 && v < info.len());
    if drapeaux & 1 != 0 {
        let unicode = (taille_entete >= 0x24)
            .then(|| champ(0x1C).and_then(|d| chaine_utf16(info, d, CHEMIN_MAX)))
            .flatten();
        l.chemin_local = unicode.or_else(|| champ(0x10).and_then(|d| chaine_c(info, d, CHEMIN_MAX)));
    }
    if drapeaux & 2 != 0
        && let Some(reseau) = champ(0x14)
        && let Some(lien_reseau) = info.get(reseau..)
    {
        let taille = u32le(lien_reseau, 0).unwrap_or(0) as usize;
        if taille >= 0x14
            && let Some(structure) = lien_reseau.get(..taille)
            && let Some(nom) = u32le(structure, 8).map(|v| v as usize).filter(|&v| v > 0 && v < taille)
        {
            l.chemin_reseau = chaine_c(structure, nom, CHEMIN_MAX);
        }
    }
    let unicode = (taille_entete >= 0x24)
        .then(|| champ(0x20).and_then(|d| chaine_utf16(info, d, CHEMIN_MAX)))
        .flatten();
    l.suffixe = unicode
        .or_else(|| champ(0x18).and_then(|d| chaine_c(info, d, CHEMIN_MAX)))
        .filter(|s| !s.is_empty());
}

#[cfg(test)]
pub(crate) mod essais {
    //! Des raccourcis fabriqués ici.

    /// Un raccourci : en-tête, liste d'identifiants `ids` (si donnée), LinkInfo avec `chemin` local (si donné),
    /// arguments (Unicode), bloc de fin, puis `ajout`.
    pub(crate) fn raccourci(
        ids: Option<&[u8]>,
        chemin: Option<&str>,
        arguments: Option<&str>,
        ajout: &[u8],
    ) -> Vec<u8> {
        let mut drapeaux = super::IS_UNICODE;
        let mut v = vec![0u8; 76];
        v[..4].copy_from_slice(&0x4Cu32.to_le_bytes());
        v[4..20].copy_from_slice(&super::CLSID);
        if let Some(ids) = ids {
            drapeaux |= super::HAS_ID_LIST;
            let mut liste = ids.to_vec();
            liste.extend([0, 0]);
            v.extend(u16::try_from(liste.len()).unwrap().to_le_bytes());
            v.extend(liste);
        }
        if let Some(chemin) = chemin {
            drapeaux |= super::HAS_LINK_INFO;
            let mut info = vec![0u8; 0x1C];
            info[4..8].copy_from_slice(&0x1Cu32.to_le_bytes());
            info[8..12].copy_from_slice(&1u32.to_le_bytes());
            // VolumeID minimal, puis le chemin, puis un suffixe vide.
            info[12..16].copy_from_slice(&0x1Cu32.to_le_bytes());
            info.extend(0x10u32.to_le_bytes());
            info.extend([0u8; 12]);
            let position_chemin = info.len();
            info.extend(chemin.as_bytes());
            info.push(0);
            let position_suffixe = info.len();
            info.push(0);
            info[16..20].copy_from_slice(&u32::try_from(position_chemin).unwrap().to_le_bytes());
            info[24..28].copy_from_slice(&u32::try_from(position_suffixe).unwrap().to_le_bytes());
            let taille = u32::try_from(info.len()).unwrap();
            info[..4].copy_from_slice(&taille.to_le_bytes());
            v.extend(info);
        }
        if let Some(a) = arguments {
            drapeaux |= super::HAS_ARGUMENTS;
            let unites: Vec<u16> = a.encode_utf16().collect();
            v.extend(u16::try_from(unites.len()).unwrap().to_le_bytes());
            v.extend(unites.iter().flat_map(|u| u.to_le_bytes()));
        }
        v.extend(0u32.to_le_bytes());
        v[20..24].copy_from_slice(&drapeaux.to_le_bytes());
        v.extend(ajout);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::essais::raccourci;
    use super::*;

    #[test]
    fn cible_arguments_interpreteur() {
        let v = raccourci(
            None,
            Some("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            Some("-NoP -W Hidden -c iex"),
            b"",
        );
        let l = lire(&v).unwrap();
        assert!(!l.tronque);
        assert_eq!(l.fin, v.len());
        assert_eq!(
            l.cible().as_deref(),
            Some("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
        );
        assert_eq!(l.arguments.as_deref(), Some("-NoP -W Hidden -c iex"));
        assert_eq!(l.interpreteurs(), ["powershell.exe"]);
        assert!(!l.arguments_rembourres());
        // Arguments rembourrés, octets ajoutés après le bloc de fin.
        let rembourre = format!("{}/c start calc", " ".repeat(300));
        let v = raccourci(
            None,
            Some("C:\\Windows\\System32\\cmd.exe"),
            Some(&rembourre),
            b"PK\x03\x04",
        );
        let l = lire(&v).unwrap();
        assert!(l.arguments_rembourres());
        assert_eq!(l.interpreteurs(), ["cmd.exe"]);
        assert_eq!(&v[l.fin..], b"PK\x03\x04");
    }

    /// La cible seulement dans la liste d'identifiants (UTF-16 dans un élément) : approchée, et l'interpréteur vu.
    #[test]
    fn cible_dans_la_liste_d_identifiants() {
        let mut element = vec![0u8; 4];
        element.extend("mshta.exe".encode_utf16().flat_map(u16::to_le_bytes));
        let mut ids = u16::try_from(element.len() + 2).unwrap().to_le_bytes().to_vec();
        ids.extend(&element);
        let l = lire(&raccourci(Some(&ids), None, Some("https://exemple.invalid/a.hta"), b"")).unwrap();
        assert_eq!(l.cible(), None);
        assert!(l.cible_approchee().unwrap().contains("mshta.exe"));
        assert_eq!(l.interpreteurs(), ["mshta.exe"]);
    }

    #[test]
    fn coupes_ou_refuses() {
        let v = raccourci(None, Some("C:\\x.exe"), Some("abc"), b"");
        for coupe in [80, 100, v.len() - 2] {
            let l = lire(&v[..coupe]).unwrap();
            assert!(l.tronque, "coupé à {coupe}");
        }
        let mut autre = v.clone();
        autre[4] ^= 1;
        assert!(lire(&autre).is_none());
        assert!(lire(b"L\0\0\0").is_none());
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 2000, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn jamais_de_plantage(i in 0usize..400, x in proptest::num::u8::ANY, j in 0usize..400, y in proptest::num::u8::ANY) {
            let mut v = raccourci(Some(&[6, 0, b'a', b'b', b'c', b'd']), Some("C:\\Windows\\notepad.exe"), Some("x"), b"");
            let n = v.len();
            v[i % n] = x;
            v[j % n] = y;
            if let Some(l) = lire(&v) {
                proptest::prop_assert!(l.fin <= v.len());
                let _ = (l.cible(), l.interpreteurs(), l.cible_approchee());
            }
        }
    }
}

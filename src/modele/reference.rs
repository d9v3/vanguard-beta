//! Les référentiels reconnus pour les règles de la machine : chaque règle du bilan cite au moins une référence du
//! CIS (Controls v8, ou un benchmark), de Microsoft ou de l'ANSSI (champ `references` de `machine::regles::Regle`).
//! Les autres sources (MITRE ATT&CK, RFC, documentation d'un éditeur) peuvent s'y ajouter, jamais la remplacer : la
//! personne relie ainsi chaque alerte à un référentiel reconnu, et Vanguard pourra dire combien de mesures d'un
//! référentiel la machine suit.

/// Un référentiel reconnu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Referentiel {
    Cis,
    Microsoft,
    Anssi,
}

/// Le référentiel d'une référence, d'après son début (« CIS Controls v8 4.5 », « Microsoft : … », « ANSSI … »).
pub(crate) fn referentiel(reference: &str) -> Option<Referentiel> {
    if reference.starts_with("CIS ") {
        Some(Referentiel::Cis)
    } else if reference.starts_with("Microsoft") {
        Some(Referentiel::Microsoft)
    } else if reference.starts_with("ANSSI") {
        Some(Referentiel::Anssi)
    } else {
        None
    }
}

/// La première référence d'un référentiel reconnu, celle qu'on cite d'abord.
pub(crate) fn principale<'a>(references: &[&'a str]) -> Option<&'a str> {
    references.iter().copied().find(|r| referentiel(r).is_some())
}

/// Une mesure des CIS Controls v8 bien écrite (lue par les tests des règles) : « CIS Controls v8 4.5 », 18 contrôles, numéro de mesure ensuite.
#[cfg(test)]
pub(crate) fn mesure_cis_bien_ecrite(reference: &str) -> bool {
    let Some(numero) = reference.strip_prefix("CIS Controls v8 ") else {
        return true;
    };
    let Some((controle, mesure)) = numero.split_once('.') else {
        return false;
    };
    controle.parse::<u8>().is_ok_and(|c| (1..=18).contains(&c)) && mesure.parse::<u8>().is_ok_and(|m| m >= 1)
}

/// Ce qui ne va pas avec une référence à ATT&CK (lue par les tests des règles), ou `None` : « MITRE ATT&CK » suivi
/// d'une technique (T1547, T1547.005) ou d'une mesure d'atténuation (M1042) qui existe dans la version 20 ; une
/// référence qui commence par « MITRE » ou parle d'ATT&CK sous une autre forme est refusée, pour ne pas passer
/// inaperçue
/// (assets/attack-v20.tsv, tirée des données de MITRE). Un ancien numéro est refusé avec son remplaçant. Les autres
/// références ne sont pas jugées ici.
#[cfg(test)]
pub(crate) fn faute_attack(reference: &str) -> Option<String> {
    let majuscules = reference.to_uppercase();
    if !majuscules.starts_with("MITRE") && !majuscules.contains("ATT&CK") {
        return None;
    }
    let identifiant = reference
        .strip_prefix("MITRE ATT&CK ")
        .filter(|i| identifiant_attack_bien_ecrit(i));
    let Some(identifiant) = identifiant else {
        return Some(format!(
            "« {reference} » : attendu « MITRE ATT&CK T1547.005 » ou « MITRE ATT&CK M1042 »"
        ));
    };
    attack_inconnu(identifiant)
}

/// Un identifiant d'ATT&CK hors de la version 20 (champ `techniques` des règles EVT-), avec son remplaçant quand il
/// a été révoqué ; `None` s'il existe.
#[cfg(test)]
pub(crate) fn attack_inconnu(identifiant: &str) -> Option<String> {
    let mut renvoi = None;
    for ligne in include_str!("../../assets/attack-v20.tsv")
        .lines()
        .filter(|l| !l.starts_with('#'))
    {
        let champs: Vec<&str> = ligne.split('\t').collect();
        match champs.as_slice() {
            ["technique" | "mesure", id, ..] if *id == identifiant => return None,
            ["renvoi", id, nouveau, ..] if *id == identifiant => renvoi = Some(*nouveau),
            _ => {}
        }
    }
    Some(match renvoi {
        Some(nouveau) => format!("{identifiant} n'existe plus dans ATT&CK 20 : citer {nouveau}"),
        None => format!("{identifiant} inconnu d'ATT&CK 20"),
    })
}

/// T1234, T1234.001 ou M1234.
#[cfg(test)]
fn identifiant_attack_bien_ecrit(i: &str) -> bool {
    let chiffres = |s: &str, n: usize| s.len() == n && s.bytes().all(|c| c.is_ascii_digit());
    match i.split_once('.') {
        Some((t, sous)) => t.starts_with('T') && chiffres(&t[1..], 4) && chiffres(sous, 3),
        None => (i.starts_with('T') || i.starts_with('M')) && chiffres(&i[1..], 4),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn referentiels_reconnus() {
        assert_eq!(referentiel("CIS Controls v8 4.5"), Some(Referentiel::Cis));
        assert_eq!(
            referentiel("Microsoft : BitLocker overview"),
            Some(Referentiel::Microsoft)
        );
        assert_eq!(
            referentiel("ANSSI BP-028 (configuration d'un système GNU/Linux)"),
            Some(Referentiel::Anssi)
        );
        assert_eq!(referentiel("MITRE ATT&CK T1547"), None);
        assert_eq!(
            principale(&["MITRE ATT&CK T1547", "CIS Controls v8 13.2"]),
            Some("CIS Controls v8 13.2")
        );
        assert_eq!(principale(&["RFC 6092"]), None);
        assert!(mesure_cis_bien_ecrite("CIS Controls v8 12.6") && mesure_cis_bien_ecrite("CIS Docker Benchmark"));
        assert!(!mesure_cis_bien_ecrite("CIS Controls v8 19.1") && !mesure_cis_bien_ecrite("CIS Controls v8 4"));
    }

    /// La liste de référence d'ATT&CK : techniques, sous-techniques et mesures connues ; les fautes de frappe, les
    /// identifiants mal écrits et les anciens numéros refusés.
    #[test]
    fn references_attack() {
        for bonne in [
            "MITRE ATT&CK T1547",
            "MITRE ATT&CK T1547.005",
            "MITRE ATT&CK M1042",
            "CIS Controls v8 4.5",
            "Microsoft : Attack surface reduction rules",
        ] {
            assert_eq!(faute_attack(bonne), None, "{bonne}");
        }
        for mauvaise in [
            "MITRE ATT&CK",
            "MITRE ATTACK T1547",
            "ATT&CK T1547",
            "MITRE ATT&CK T154",
            "MITRE ATT&CK t1547",
            "MITRE ATT&CK  T1547",
            "MITRE ATT&CK T1547.5",
        ] {
            assert!(faute_attack(mauvaise).unwrap().contains("attendu"), "{mauvaise}");
        }
        assert!(faute_attack("MITRE ATT&CK T1999").unwrap().contains("inconnu"));
        assert!(faute_attack("MITRE ATT&CK M1999").unwrap().contains("inconnu"));
        // T1070.001 (effacer les journaux de Windows) est devenue T1685.005 dans la version 20.
        assert!(
            faute_attack("MITRE ATT&CK T1070.001")
                .unwrap()
                .contains("citer T1685.005")
        );
        assert_eq!(attack_inconnu("T1685.005"), None);
    }
}

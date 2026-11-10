//! Le catalogue des failles exploitées de la CISA (Known Exploited Vulnerabilities) : les CVE dont une attaque réelle
//! est connue. Une faille connue d'un logiciel installé qui y figure passe avant les autres. Téléchargé en entier (la
//! liste des logiciels de l'ordinateur ne sort jamais), gardé un jour ; hors ligne, la copie d'avant sert jusqu'à un
//! mois. Le catalogue suit les faits : une faille exploitée d'hier peut ne pas y être encore (PHP2Shell, 21 oct. 2026).

// Sous Linux seulement : les parties Windows ne sont pas encore relues ; le lint y viendra avec elles.
#![cfg_attr(target_os = "linux", warn(clippy::arithmetic_side_effects, clippy::as_conversions))]

use std::time::Duration;

use chrono::NaiveDate;

use crate::modele::raison::Echec;
use crate::{tr, trf};

mod resultat;
#[cfg(test)]
pub(crate) use resultat::corpus;

const ADRESSE: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const FRAICHE: Duration = Duration::from_hours(24);
const TROP_VIEILLE: Duration = Duration::from_hours(30 * 24);
/// La copie gardée : sous-dossier et nom, dans le dossier de Vanguard.
const LIEU: (&str, &str) = ("kev", "kev.json");

/// Une faille du catalogue.
pub(crate) struct Exploitee {
    /// En majuscules.
    pub cve: String,
    /// Le jour où la CISA l'a ajoutée, pas celui de la première attaque.
    pub ajoutee: Option<NaiveDate>,
    pub editeur: String,
    pub produit: String,
    pub nom: String,
    /// Des rançongiciels s'en servent.
    pub rancongiciel: bool,
}

/// Les CVE exploitées et le jour de leur ajout au catalogue. `Err` : pourquoi le catalogue ne sert pas ; rien n'est
/// alors dit « pas exploité ».
#[cfg(target_os = "linux")]
pub(crate) fn exploitees() -> Result<std::collections::HashMap<String, Option<NaiveDate>>, String> {
    Ok(catalogue()?.into_iter().map(|e| (e.cve, e.ajoutee)).collect())
}

/// Le catalogue entier ; `Err` : pourquoi il ne sert pas.
pub(crate) fn catalogue() -> Result<Vec<Exploitee>, String> {
    catalogue_selon(None)
}

/// `catalogue`, ou, quand `coupure` dit pourquoi rien ne doit partir (réglage, travail sans Internet, tests), la
/// copie gardée seule, sans rien demander.
pub(crate) fn catalogue_selon(coupure: Option<&str>) -> Result<Vec<Exploitee>, String> {
    catalogue_et_age(coupure).map(|(c, _)| c).map_err(String::from)
}

/// Le contexte des échecs de lecture du catalogue (`modele::raison::Echec`).
const LECTURE: &str = "dernieres-failles/catalogue";

/// `catalogue_selon`, avec l'âge de la copie lue : `--json` dit qu'une copie de plus d'un jour (hors ligne, la CISA
/// injoignable) peut manquer les derniers ajouts, au lieu de la croire complète. L'échec se montre par sa phrase
/// seule (`Raison::Echoue`), comme avant le canal d'erreur commun.
fn catalogue_et_age(coupure: Option<&str>) -> Result<(Vec<Exploitee>, Duration), Echec> {
    use crate::protection::abuse_ch::Echec as Liste;
    let (octets, age) = match coupure {
        None => crate::socle::cache::liste(demande(), LIEU, FRAICHE, |o| analyser(o).is_some())
            .resultat(false)
            .map_err(|e| {
                Echec::echoue(
                    LECTURE,
                    match e {
                        Liste::Reponse(code) => trf!("la CISA a répondu {code}", "CISA answered {code}"),
                        Liste::SansReponse => tr!("pas d'Internet ?", "no Internet?").to_string(),
                        autre => autre.raison(),
                    },
                )
            })?,
        // L'âge vient du sceau de la copie, pas de la date du fichier (`socle::cache::gardee`).
        Some(pourquoi) => match crate::socle::cache::gardee(LIEU, crate::socle::cache::LISTE_MAX) {
            Ok(Some(copie)) => copie,
            Ok(None) => return Err(Echec::echoue(LECTURE, pourquoi)),
            Err(refus) => {
                return Err(Echec::echoue(
                    LECTURE,
                    trf!("{pourquoi} ; {}", "{pourquoi}; {}", refus.texte()),
                ));
            }
        },
    };
    if age > TROP_VIEILLE {
        return Err(Echec::echoue(
            LECTURE,
            tr!(
                "copie de plus d'un mois, rafraîchissement impossible",
                "copy more than a month old, could not refresh it"
            ),
        ));
    }
    analyser(&octets).map(|c| (c, age)).ok_or_else(|| {
        Echec::echoue(
            LECTURE,
            tr!(
                "catalogue illisible (page d'un portail Wi-Fi ?)",
                "catalog unreadable (a Wi-Fi portal page?)"
            ),
        )
    })
}

/// Le contexte des échecs de lecture des CVE d'ici (`modele::raison::Echec`).
const PAQUETS: &str = "dernieres-failles/paquets";

/// Les CVE des paquets de cet ordinateur : sous Arch, le suivi de sécurité les donne (arch-audit). `Err` : pourquoi
/// on ne les connaît pas, et rien n'est alors dit « ne touche pas cet ordinateur ». Sans Internet demandé, arch-audit
/// n'est pas lancé : il télécharge le suivi de sécurité d'Arch.
fn cves_ici() -> Result<std::collections::HashSet<String>, Echec> {
    if crate::parametres::hors_ligne() {
        return Err(Echec::echoue(PAQUETS, crate::parametres::raison_hors_ligne()));
    }
    cves_du_systeme()
}

#[cfg(target_os = "linux")]
fn cves_du_systeme() -> Result<std::collections::HashSet<String>, Echec> {
    crate::machine::linux::cves_installees().ok_or_else(|| {
        Echec::echoue(
            PAQUETS,
            tr!(
                "suivi de sécurité des paquets pas lu (seulement sous Arch, avec arch-audit)",
                "package security tracker not read (only on Arch, with arch-audit)"
            ),
        )
    })
}

#[cfg(not(target_os = "linux"))]
fn cves_du_systeme() -> Result<std::collections::HashSet<String>, Echec> {
    Err(Echec::echoue(
        PAQUETS,
        tr!(
            "pas de suivi de sécurité des paquets sous Windows : le bilan (Failles connues) juge les logiciels",
            "no package security tracker on Windows: the check-up (Known flaws) judges the software"
        ),
    ))
}

/// Le premier jour de la période : `jours` avant `aujourd_hui`.
fn depuis(aujourd_hui: NaiveDate, jours: u32) -> NaiveDate {
    aujourd_hui
        .checked_sub_signed(chrono::Duration::days(i64::from(jours)))
        .unwrap_or(NaiveDate::MIN)
}

/// `vanguard dernieres-failles --json` : les mêmes failles que l'écran, jugées en résultat et versées au rapport. Rien
/// n'est demandé ni changé ; sans Internet ni copie gardée, le résultat dit pourquoi il ne conclut pas.
pub fn json(jours: u32) {
    let debut = (chrono::Utc::now(), std::time::Instant::now());
    let aujourd_hui = chrono::Local::now().date_naive();
    let r = resultat::resultat(catalogue_et_age(None), jours, aujourd_hui, cves_ici, debut);
    crate::modele::resultat::verser(&r);
    println!("{}", crate::modele::resultat::json(&r));
}

/// La demande du catalogue : la même pour le programme et pour les canaris de la veille de nuit (`canaris`).
pub(crate) fn demande() -> crate::http::Demande<'static> {
    crate::http::Demande {
        taille_max: 64 << 20,
        ..crate::http::Demande::get(ADRESSE, Duration::from_secs(60))
    }
}

/// `{"vulnerabilities": [{"cveID": "CVE-…", "dateAdded": "2026-10-20", …}, …]}`. `None` pour tout autre texte :
/// jamais un catalogue vide, donc « rien d'exploité », à sa place.
pub(crate) fn analyser(octets: &[u8]) -> Option<Vec<Exploitee>> {
    let v: serde_json::Value = serde_json::from_slice(octets).ok()?;
    let texte =
        |e: &serde_json::Value, champ: &str| crate::ui::affichable(e[champ].as_str().unwrap_or_default().trim());
    let liste: Vec<Exploitee> = v
        .get("vulnerabilities")?
        .as_array()?
        .iter()
        .filter_map(|e| {
            Some(Exploitee {
                cve: e["cveID"].as_str()?.trim().to_uppercase(),
                ajoutee: e["dateAdded"]
                    .as_str()
                    .and_then(|d| NaiveDate::parse_from_str(d.get(..10)?, "%Y-%m-%d").ok()),
                editeur: texte(e, "vendorProject"),
                produit: texte(e, "product"),
                nom: texte(e, "vulnerabilityName"),
                rancongiciel: e["knownRansomwareCampaignUse"] == "Known",
            })
        })
        .collect();
    (!liste.is_empty()).then_some(liste)
}

/// Les failles ajoutées au catalogue depuis `depuis`, les plus récentes d'abord ; celles de `ici` (les CVE des
/// logiciels de cet ordinateur, quand on les connaît) en tête.
fn recentes<'a>(
    catalogue: &'a [Exploitee],
    depuis: NaiveDate,
    ici: &std::collections::HashSet<String>,
) -> Vec<&'a Exploitee> {
    let mut v: Vec<&Exploitee> = catalogue
        .iter()
        .filter(|e| e.ajoutee.is_some_and(|d| d >= depuis))
        .collect();
    v.sort_by(|a, b| {
        ici.contains(&b.cve)
            .cmp(&ici.contains(&a.cve))
            .then(b.ajoutee.cmp(&a.ajoutee))
            .then(a.cve.cmp(&b.cve))
    });
    v
}

/// `vanguard dernieres-failles [--jours N]` : les failles exploitées ajoutées au catalogue ces derniers jours.
pub fn ecran(jours: u32) {
    use crate::ui::*;
    let catalogue = match catalogue() {
        Ok(c) => c,
        Err(raison) => {
            trp!(
                "  ✖ Catalogue des failles exploitées (CISA) pas lu : {raison}.",
                "  ✖ Exploited flaws catalog (CISA) not read: {raison}."
            );
            return;
        }
    };
    let depuis = depuis(chrono::Local::now().date_naive(), jours);
    let ici = cves_ici().ok();
    let vide = std::collections::HashSet::new();
    let liste = recentes(&catalogue, depuis, ici.as_ref().unwrap_or(&vide));
    println!();
    trp!(
        "  {GRAS}Failles exploitées ajoutées au catalogue de la CISA ces {jours} derniers jours : {}{RESET}",
        "  {GRAS}Exploited flaws added to CISA's catalog in the last {jours} days: {}{RESET}",
        liste.len()
    );
    println!();
    for e in &liste {
        let date = e.ajoutee.map_or_else(String::new, |d| d.to_string());
        let touche = ici.as_ref().is_some_and(|i| i.contains(&e.cve));
        let marque = if touche {
            format!("{}✖{RESET} ", couleur(crate::risk::Niveau::Critique))
        } else {
            "  ".to_string()
        };
        println!("  {marque}{date}  {}  {} {}", e.cve, e.editeur, e.produit);
        let mut detail = e.nom.clone();
        if e.rancongiciel {
            detail.push_str(tr!(" — utilisée par des rançongiciels", " — used by ransomware"));
        }
        if touche {
            detail.push_str(tr!(
                " — touche un paquet de cet ordinateur",
                " — affects a package on this computer"
            ));
        }
        afficher_aligne("      ", &detail, 6, GRIS);
    }
    println!();
    let touche_ici = liste.iter().any(|e| ici.as_ref().is_some_and(|i| i.contains(&e.cve)));
    let fin = if touche_ici {
        tr!(
            "✖ : touche un paquet de cet ordinateur (suivi de sécurité de la distribution). Le bilan (Failles connues) dit quoi mettre à jour.",
            "✖: affects a package on this computer (the distribution's security tracker). The check-up (Known flaws) says what to update."
        )
    } else {
        tr!(
            "Ce qui touche vos logiciels : le bilan (Failles connues). Le catalogue ne liste que des failles dont une attaque réelle est connue.",
            "What affects your software: the check-up (Known flaws). The catalog only lists flaws with a known real attack."
        )
    };
    afficher_aligne("  ", fin, 2, GRIS);
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_lu() {
        let json = br#"{"title":"CISA Catalog","vulnerabilities":[{"cveID":"CVE-2021-44228","product":"Log4j","dateAdded":"2021-12-10","knownRansomwareCampaignUse":"Known"},{"cveID":"cve-2024-3400"}]}"#;
        let c = analyser(json).unwrap();
        assert_eq!(c.len(), 2);
        assert!(c[0].cve == "CVE-2021-44228" && c[0].rancongiciel && c[0].ajoutee.is_some());
        assert!(c[1].cve == "CVE-2024-3400" && !c[1].rancongiciel && c[1].ajoutee.is_none());
        // Portail Wi-Fi, catalogue vide ou d'une autre forme : pas lu, jamais « rien d'exploité ».
        for t in [
            &b"<html>Salon</html>"[..],
            br#"{"vulnerabilities":[]}"#,
            br#"{"title":"x"}"#,
        ] {
            assert!(analyser(t).is_none());
        }
    }

    /// Une copie réduite du vrai catalogue (CC0, voir assets/essais/LICENCES-ESSAIS.txt) se lit entière, éditeur et
    /// produit compris : le rapprochement des logiciels pas à jour s'en servira.
    #[test]
    fn copie_reduite_du_vrai_catalogue() {
        let c = analyser(include_bytes!("../../assets/essais/kev-extrait.json")).unwrap();
        assert_eq!(c.len(), 16);
        assert!(
            c.iter()
                .all(|e| e.cve.starts_with("CVE-") && e.ajoutee.is_some() && !e.produit.is_empty())
        );
        for (editeur, produit) in [
            ("Google", "Chromium V8"),
            ("Google", "Chrome for Android UI"),
            ("Mozilla", "Firefox"),
            ("Microsoft", "WordPad"),
            ("Adobe", "Reader and Acrobat"),
            ("Oracle", "Java SE and JRockit"),
            ("7-Zip", "7-Zip"),
        ] {
            assert!(
                c.iter().any(|e| e.editeur == editeur && e.produit == produit),
                "{editeur} {produit}"
            );
        }
    }

    #[test]
    fn recentes_d_abord_et_celles_d_ici_en_tete() {
        let e = |cve: &str, d: &str| Exploitee {
            cve: cve.into(),
            ajoutee: NaiveDate::parse_from_str(d, "%Y-%m-%d").ok(),
            editeur: String::new(),
            produit: String::new(),
            nom: String::new(),
            rancongiciel: false,
        };
        let cat = [
            e("CVE-1", "2026-10-01"),
            e("CVE-2", "2026-10-20"),
            e("CVE-3", "2026-10-16"),
            e("CVE-4", "sans date"),
        ];
        let depuis = NaiveDate::parse_from_str("2026-10-15", "%Y-%m-%d").unwrap();
        let ordre = |ici: &[&str]| -> Vec<String> {
            let ici: std::collections::HashSet<String> = ici.iter().map(|s| (*s).to_string()).collect();
            recentes(&cat, depuis, &ici).iter().map(|e| e.cve.clone()).collect()
        };
        // Trop vieille ou sans date : hors de la liste ; la plus récente d'abord.
        assert_eq!(ordre(&[]), ["CVE-2", "CVE-3"]);
        // Celle qui touche cet ordinateur passe en tête.
        assert_eq!(ordre(&["CVE-3"]), ["CVE-3", "CVE-2"]);
    }
}

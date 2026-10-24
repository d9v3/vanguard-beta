//! Les unités de systemd lues par le client D-Bus maison, au lieu de `systemctl list-units`, `list-unit-files`,
//! `list-timers` et `show -p Result` : le gestionnaire du système (bus système) ou celui de l'utilisateur (bus de la
//! session). Lecture seule : ListUnits, ListUnitFiles, GetUnit et Properties.Get, toutes dans LECTURES.

use super::dbus::{Bus, CHEMIN_SYSTEMD, GESTIONNAIRE, SYSTEMD, Valeur};
use crate::modele::Echec;

/// Une erreur du client D-Bus dans le canal d'erreur commun (son texte reste celui du bus).
fn echec(e: String) -> Echec {
    Echec::echoue("systemd", e)
}

/// Le bus d'un gestionnaire : celui du système, ou celui de l'utilisateur (bus de la session ; refusé sous root).
pub(crate) fn bus(utilisateur: bool) -> Result<Bus, Echec> {
    if utilisateur {
        super::dbus::actions::session()
    } else {
        Bus::systeme().map_err(echec)
    }
}

/// Une unité chargée, comme ListUnits la décrit (`a(ssssssouso)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Unite {
    pub nom: String,
    pub description: String,
    pub chargement: String,
    pub activite: String,
    pub sous_etat: String,
    pub chemin: String,
}

/// Les unités chargées (toutes, actives ou non : `list-units --all`).
pub(crate) fn unites(bus: &mut Bus) -> Result<Vec<Unite>, Echec> {
    let corps = bus
        .appeler(SYSTEMD, CHEMIN_SYSTEMD, GESTIONNAIRE, "ListUnits", "", Vec::new())
        .map_err(echec)?;
    Ok(lire_unites(corps.first()))
}

fn lire_unites(liste: Option<&Valeur>) -> Vec<Unite> {
    let mut v: Vec<Unite> = liste
        .map(Valeur::elements)
        .unwrap_or_default()
        .iter()
        .filter_map(|u| {
            let m = u.elements();
            let t = |i: usize| m.get(i).and_then(Valeur::texte).map(String::from);
            Some(Unite {
                nom: t(0)?,
                description: t(1).unwrap_or_default(),
                chargement: t(2).unwrap_or_default(),
                activite: t(3).unwrap_or_default(),
                sous_etat: t(4).unwrap_or_default(),
                chemin: t(6)?,
            })
        })
        .collect();
    v.sort_by(|a, b| a.nom.cmp(&b.nom));
    v
}

/// Les fichiers d'unités et leur état d'activation (`list-unit-files`) : (chemin du fichier, état), triés par nom.
pub(crate) fn fichiers(bus: &mut Bus) -> Result<Vec<(String, String)>, Echec> {
    let corps = bus
        .appeler(SYSTEMD, CHEMIN_SYSTEMD, GESTIONNAIRE, "ListUnitFiles", "", Vec::new())
        .map_err(echec)?;
    Ok(lire_fichiers(corps.first()))
}

fn lire_fichiers(liste: Option<&Valeur>) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = liste
        .map(Valeur::elements)
        .unwrap_or_default()
        .iter()
        .filter_map(|f| {
            let m = f.elements();
            Some((m.first()?.texte()?.to_string(), m.get(1)?.texte()?.to_string()))
        })
        .collect();
    v.sort_by(|a, b| nom_de(&a.0).cmp(nom_de(&b.0)).then_with(|| a.0.cmp(&b.0)));
    v
}

/// Le nom d'une unité d'après le chemin de son fichier.
pub(crate) fn nom_de(chemin: &str) -> &str {
    chemin.rsplit('/').next().unwrap_or(chemin)
}

/// Une minuterie : son nom, le service qu'elle lance, ses passages (µs depuis 1970 ; 0 : jamais, ou aucun calendrier
/// pour le prochain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Minuterie {
    pub nom: String,
    pub service: String,
    pub dernier: u64,
    pub prochain: u64,
    pub activite: String,
}

/// Les minuteries chargées (`list-timers --all`) : les unités « *.timer » de ListUnits, puis les propriétés
/// LastTriggerUSec, NextElapseUSecRealtime et Unit de chacune.
pub(crate) fn minuteries(bus: &mut Bus) -> Result<Vec<Minuterie>, Echec> {
    let mut v = Vec::new();
    // Les noms d'unités de systemd sont sensibles à la casse : « .timer » seul est une minuterie.
    for u in unites(bus)?
        .into_iter()
        .filter(|u| u.nom.rsplit_once('.').is_some_and(|(_, s)| s == "timer"))
    {
        let p = bus
            .proprietes(SYSTEMD, &u.chemin, "org.freedesktop.systemd1.Timer")
            .map_err(echec)?;
        v.push(Minuterie {
            service: p.champ("Unit").and_then(Valeur::texte).unwrap_or_default().to_string(),
            dernier: p.champ("LastTriggerUSec").and_then(Valeur::entier).unwrap_or(0),
            prochain: p.champ("NextElapseUSecRealtime").and_then(Valeur::entier).unwrap_or(0),
            activite: u.activite,
            nom: u.nom,
        });
    }
    Ok(v)
}

/// Le résultat du dernier passage d'un service (`show -p Result`) : « success », « exit-code »… `None` : service
/// pas chargé, ou illisible.
pub(crate) fn resultat(bus: &mut Bus, service: &str) -> Option<String> {
    let chemin = bus
        .appeler(
            SYSTEMD,
            CHEMIN_SYSTEMD,
            GESTIONNAIRE,
            "GetUnit",
            "s",
            vec![Valeur::texte_de(service)],
        )
        .ok()?
        .first()?
        .texte()?
        .to_string();
    bus.propriete(SYSTEMD, &chemin, "org.freedesktop.systemd1.Service", "Result")
        .ok()?
        .texte()
        .map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> Valeur {
        Valeur::texte_de(s)
    }

    #[test]
    fn listes_fabriquees() {
        let unite = |nom: &str, chemin: &str| {
            Valeur::Structure(vec![
                t(nom),
                t("Description"),
                t("loaded"),
                t("active"),
                t("waiting"),
                t(""),
                t(chemin),
                Valeur::U32(0),
                t(""),
                t("/"),
            ])
        };
        let l = Valeur::Tableau(vec![
            unite("vanguard-z.timer", "/org/freedesktop/systemd1/unit/z"),
            unite("a.service", "/org/freedesktop/systemd1/unit/a"),
            // Une unité mal formée (pas de chemin) : laissée.
            Valeur::Structure(vec![t("b.service")]),
        ]);
        let u = lire_unites(Some(&l));
        assert_eq!(
            u.iter().map(|u| u.nom.as_str()).collect::<Vec<_>>(),
            ["a.service", "vanguard-z.timer"]
        );
        assert_eq!(u[1].sous_etat, "waiting");
        assert!(lire_unites(None).is_empty(), "rien");
        let f = Valeur::Tableau(vec![
            Valeur::Structure(vec![t("/usr/lib/systemd/system/sshd.service"), t("disabled")]),
            Valeur::Structure(vec![t("/etc/systemd/system/a.service"), t("enabled")]),
            Valeur::Structure(vec![t("/etc/x.service")]),
        ]);
        assert_eq!(
            lire_fichiers(Some(&f)),
            [
                ("/etc/systemd/system/a.service".to_string(), "enabled".to_string()),
                (
                    "/usr/lib/systemd/system/sshd.service".to_string(),
                    "disabled".to_string()
                )
            ]
        );
        assert_eq!(nom_de("/etc/systemd/system/a.service"), "a.service");
    }

    /// L'oracle : les fichiers d'unités et les minuteries du système lus par D-Bus contre systemctl, sur cet
    /// ordinateur (des nombres seulement dans les messages).
    #[test]
    fn unites_comme_systemctl() {
        let mut systeme = match bus(false) {
            Ok(b) => b,
            Err(e) => return crate::essais::saute(&format!("bus système injoignable ({e})")),
        };
        let natifs = fichiers(&mut systeme).unwrap();
        let Some(r) = crate::commande::lancer(
            std::process::Command::new("systemctl").args(["list-unit-files", "--no-pager", "--full", "--no-legend"]),
            30,
        )
        .filter(|r| r.code == Some(0)) else {
            return crate::essais::saute("systemctl absent");
        };
        let outil: std::collections::BTreeSet<&str> =
            r.sortie.lines().filter_map(|l| l.split_whitespace().next()).collect();
        let lus: std::collections::BTreeSet<&str> = natifs.iter().map(|(c, _)| nom_de(c)).collect();
        let absents = lus.difference(&outil).count();
        assert_eq!(
            absents,
            0,
            "{absents} fichiers d'unités lus par D-Bus, absents de systemctl ({} contre {})",
            lus.len(),
            outil.len()
        );
        let m = minuteries(&mut systeme).unwrap();
        let Some(j) = crate::machine::sortie("systemctl", &["list-timers", "--all", "--output=json"]) else {
            return crate::essais::saute("systemctl list-timers muet");
        };
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        let mut outil: Vec<(String, u64, String)> = v
            .as_array()
            .unwrap()
            .iter()
            .map(|t| {
                (
                    t["unit"].as_str().unwrap_or_default().to_string(),
                    t["last"].as_u64().unwrap_or(0),
                    t["activates"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        let mut minuteries_lues: Vec<(String, u64, String)> =
            m.into_iter().map(|m| (m.nom, m.dernier, m.service)).collect();
        outil.sort();
        minuteries_lues.sort();
        assert!(
            outil == minuteries_lues,
            "minuteries : {} par D-Bus, {} par systemctl",
            minuteries_lues.len(),
            outil.len()
        );
    }
}

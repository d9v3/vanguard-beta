//! Le résultat de « Qui parle à Internet ? » (`modele::resultat`) : le jugement du relevé, sans l'écran. Versé au
//! rapport (`examens/PRO-SOR-001.json`), au journal des événements, et rendu par `--json`. Ce que l'écran signale
//! (programme à regarder de près, serveur de commande de botnet, site dangereux demandé) devient une alerte de même
//! gravité ; ce qu'il marque « ? » (chemin ou programme invisible sans droits, liste ou mémoire DNS manquante) est dit
//! non vérifié.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use super::{Analyse, Releve, sites_trouves};
use crate::machine::{Constat, alerte, impossible, impossible_par, ok};
use crate::modele::resultat::{Couverture, Resultat};
use crate::modele::{Objet, Raison};
use crate::risk::Niveau;

/// L'identifiant de l'outil (`modele::registre::OUTILS`).
pub(crate) const ID: &str = "PRO-SOR-001";

const CAT: &str = "Connexions sortantes";

type Debut = (chrono::DateTime<chrono::Utc>, std::time::Instant);

/// Le résultat d'un relevé commencé à `debut`, jugé par `analyser` : les connexions programme par programme, puis la
/// mémoire DNS. Points vérifiés : les connexions, la mémoire DNS contre les serveurs de commande, contre URLhaus.
pub(super) fn resultat(r: &Releve, a: &Analyse, debut: Debut) -> Resultat {
    let mut constats: Vec<Constat> = Vec::new();
    let mut verifies = 0;
    let mut non_verifies: Vec<String> = r.listes_absentes.clone();
    match &r.connexions {
        None => constats.push(impossible(
            CAT,
            crate::tr!(
                "les connexions de cet ordinateur ne se lisent pas",
                "this computer's connections cannot be read"
            ),
        )),
        Some(connexions) if connexions.is_empty() => {
            verifies += 1;
            constats.push(ok(
                CAT,
                crate::tr!(
                    "Aucune connexion vers Internet en ce moment.",
                    "No connection to the Internet right now."
                ),
            ));
        }
        Some(_) => {
            verifies += 1;
            constats.extend(programmes(a, &mut non_verifies));
            constats.extend(cachees(r, a, &mut non_verifies));
        }
    }
    match &r.memoire_dns {
        Err(raison) => non_verifies.push(crate::trf!(
            "Mémoire DNS pas vérifiée : {raison}.",
            "DNS cache not checked: {raison}."
        )),
        // Vide : rien n'a été comparé, ce n'est pas « aucun nom dangereux » (un autre résolveur répond peut-être).
        Ok(noms) if noms.is_empty() => {
            let raison = super::memoire_dns_vide();
            constats.push(impossible_par(CAT, Raison::Introuvable, raison));
            non_verifies.push(raison.to_string());
        }
        Ok(noms) => {
            // Liste des domaines absente : déjà dite dans `listes_absentes`, rien n'est déclaré sain.
            if r.botnets.domaines.is_some() {
                verifies += 1;
                constats.extend(domaines_de_commande(r, noms));
            }
            match &r.urlhaus {
                Some(Ok((hotes, _))) => {
                    verifies += 1;
                    constats.extend(sites(noms, hotes));
                }
                Some(Err(raison)) => non_verifies.push(raison.clone()),
                None => {}
            }
        }
    }
    Resultat::nouveau(ID, debut, &constats, Couverture { verifies, non_verifies })
}

/// Un constat par programme : une alerte quand l'écran le marque à regarder de près (sa gravité, ses signes), sinon
/// un « rien de suspect » ; sans son chemin, il n'est pas jugé et compte parmi les non vérifiés.
fn programmes(a: &Analyse, non_verifies: &mut Vec<String>) -> Vec<Constat> {
    let mut constats = Vec::new();
    let mut sans_chemin = 0;
    for p in &a.programmes {
        let nom = &p.nom;
        let serveurs = &p.serveurs;
        let objet = Objet::de("programme", nom);
        if let Some(niveau) = p.pire {
            let signes: Vec<&str> = p
                .signes
                .iter()
                .filter(|(n, _)| *n > Niveau::Info)
                .map(|(_, t)| t.as_str())
                .collect();
            let signes = signes.join(" ");
            constats.push(
                alerte(
                    CAT,
                    niveau,
                    crate::trf!("{nom} → {serveurs} : {signes}", "{nom} → {serveurs}: {signes}"),
                )
                .avec_objet(objet),
            );
        } else if p.chemin.is_none() {
            sans_chemin += 1;
        } else {
            let n = p.connexions;
            constats.push(
                ok(
                    CAT,
                    crate::trf!(
                        "{nom} → {serveurs} : {n} connexion(s), rien de suspect.",
                        "{nom} → {serveurs}: {n} connection(s), nothing suspicious."
                    ),
                )
                .avec_objet(objet),
            );
        }
    }
    if sans_chemin > 0 {
        non_verifies.push(crate::trf!(
            "{sans_chemin} programme(s) dont le chemin est invisible sans droits d'administrateur : pas jugés",
            "{sans_chemin} program(s) whose path is invisible without administrator rights: not judged"
        ));
    }
    constats
}

/// Les connexions des programmes d'autres comptes : invisibles sans droits, donc non vérifiées, sauf vers un serveur
/// de commande connu, qui se juge à l'adresse seule.
fn cachees(r: &Releve, a: &Analyse, non_verifies: &mut Vec<String>) -> Vec<Constat> {
    if a.cachees.is_empty() {
        return Vec::new();
    }
    let n = a.cachees.len();
    non_verifies.push(crate::trf!(
        "{n} connexion(s) de programmes d'autres comptes (système, services) : invisibles sans droits d'administrateur",
        "{n} connection(s) from other accounts' programs (system, services): invisible without administrator rights"
    ));
    let mut vus = BTreeSet::new();
    a.cachees
        .iter()
        .filter_map(|(c, _)| {
            let serveur = r.botnets.serveur(c)?;
            let adresse = SocketAddr::new(c.distante.to_canonical(), c.port).to_string();
            vus.insert(adresse.clone()).then(|| {
                alerte(
                    CAT,
                    Niveau::Eleve,
                    crate::trf!(
                        "Un programme d'un autre compte parle à un serveur de commande de botnet connu : {serveur}.",
                        "Another account's program talks to a known botnet command server: {serveur}."
                    ),
                )
                .avec_objet(Objet::de("serveur", &adresse))
            })
        })
        .collect()
}

/// La mémoire DNS contre les domaines des serveurs de commande (ThreatFox).
fn domaines_de_commande(r: &Releve, noms: &[String]) -> Vec<Constat> {
    let mut vus = BTreeSet::new();
    let trouves: Vec<Constat> = noms
        .iter()
        .filter_map(|n| {
            let montre = r.botnets.domaine(n)?;
            let nom = n.trim_end_matches('.').to_lowercase();
            vus.insert(nom.clone()).then(|| {
                alerte(
                    CAT,
                    Niveau::Eleve,
                    crate::trf!(
                        "Nom demandé : {montre} : un serveur de commande de botnet connu.",
                        "Name asked: {montre}: a known botnet command server."
                    ),
                )
                .avec_objet(Objet::de("domaine", &nom))
            })
        })
        .collect();
    if !trouves.is_empty() {
        return trouves;
    }
    let n = noms.len();
    vec![ok(
        CAT,
        crate::trf!(
            "Mémoire DNS : aucun des {n} noms demandés récemment n'est un serveur de commande connu.",
            "DNS cache: none of the {n} recently asked names is a known command server."
        ),
    )]
}

/// La mémoire DNS contre les hôtes d'URLhaus.
fn sites(noms: &[String], hotes: &std::collections::HashSet<String>) -> Vec<Constat> {
    let trouves = sites_trouves(noms, hotes);
    if trouves.is_empty() {
        let n = noms.len();
        return vec![ok(
            CAT,
            crate::trf!(
                "Mémoire DNS : aucun des {n} noms demandés récemment ne distribue de logiciels malveillants (URLhaus).",
                "DNS cache: none of the {n} recently asked names distributes malware (URLhaus)."
            ),
        )];
    }
    trouves
        .into_iter()
        .map(|site| {
            alerte(
                CAT,
                Niveau::Eleve,
                crate::trf!(
                    "Site qui distribue des logiciels malveillants demandé récemment : {site} (URLhaus). Un téléchargement a pu suivre.",
                    "Site that distributes malware asked recently: {site} (URLhaus). A download may have followed."
                ),
            )
            .avec_objet(Objet::de("site", &site))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::{Botnets, Connexion, analyser};
    use super::*;
    use std::collections::HashMap;
    use std::net::IpAddr;

    fn debut() -> Debut {
        (chrono::Utc::now(), std::time::Instant::now())
    }

    fn releve(connexions: Option<Vec<Connexion>>) -> Releve {
        Releve {
            botnets: Botnets::default(),
            listes_absentes: Vec::new(),
            connexions,
            noms: HashMap::new(),
            montages: String::new(),
            memoire_dns: Err("réservé à root".into()),
            urlhaus: None,
        }
    }

    #[test]
    fn rien_de_lu_jamais_sain() {
        let r = releve(None);
        let res = resultat(&r, &analyser(&r), debut());
        assert_eq!(res.verdict(), "non-verifie");
        assert_eq!(res.couverture.verifies, 0);
        // Aucune connexion, mais la mémoire DNS ne se lit pas : pas « sain » non plus.
        let r = releve(Some(Vec::new()));
        let res = resultat(&r, &analyser(&r), debut());
        assert_eq!((res.verdict(), res.couverture.verifies), ("non-verifie", 1));
    }

    /// Une mémoire DNS vide n'a rien comparé : ni les serveurs de commande ni URLhaus ne comptent vérifiés.
    #[test]
    fn memoire_dns_vide_non_verifiee() {
        let mut r = releve(Some(Vec::new()));
        r.botnets.domaines = Some(HashMap::new());
        r.urlhaus = Some(Ok((std::collections::HashSet::new(), None)));
        r.memoire_dns = Ok(Vec::new());
        let res = resultat(&r, &analyser(&r), debut());
        assert_eq!((res.verdict(), res.couverture.verifies), ("non-verifie", 1));
        assert!(
            res.constats
                .iter()
                .any(|c| c.etat == "non-verifie" && c.message.contains("vide")),
            "{:?}",
            res.constats
        );
        // Un seul nom lu suffit : les deux comparaisons sont faites.
        r.memoire_dns = Ok(vec!["exemple.org".into()]);
        let res = resultat(&r, &analyser(&r), debut());
        assert_eq!((res.verdict(), res.couverture.verifies), ("sain", 3));
    }

    #[test]
    fn programme_vers_un_serveur_de_commande() {
        let serveur: IpAddr = "203.0.113.7".parse().unwrap();
        let mut r = releve(Some(vec![
            Connexion {
                pid: Some(42),
                programme: Some("facture".into()),
                chemin: Some("/usr/bin/facture".into()),
                ..Connexion::vers(serveur, 443)
            },
            // Celle d'un autre compte, vers le même serveur.
            Connexion::vers(serveur, 8080),
        ]));
        r.botnets.feodo.insert(serveur);
        r.botnets.domaines = Some(HashMap::from([("mal.example".to_string(), "Emotet".to_string())]));
        r.memoire_dns = Ok(vec!["a.mal.example.".into(), "exemple.org".into()]);
        r.urlhaus = Some(Ok((["telechargement.example".to_string()].into(), None)));
        let a = analyser(&r);
        let res = resultat(&r, &a, debut());
        assert_eq!(res.verdict(), "probleme");
        assert_eq!(res.pire(), Some(Niveau::Eleve));
        assert_eq!(res.couverture.verifies, 3);
        let objets: Vec<&str> = res
            .constats
            .iter()
            .filter(|c| c.etat == "probleme")
            .filter_map(|c| c.objet.as_deref())
            .collect();
        assert_eq!(
            objets,
            ["programme:facture", "serveur:203.0.113.7:8080", "domaine:a.mal.example"]
        );
        assert!(
            res.couverture.non_verifies.iter().any(|n| n.contains("autres comptes")),
            "{:?}",
            res.couverture.non_verifies
        );
    }
}

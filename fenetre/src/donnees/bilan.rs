//! Les constats d'un bilan (`audit --json`) ou d'un outil (le résultat commun, `modele::resultat` de Vanguard),
//! rangés comme l'écran les montre : à corriger, bon à savoir, ce qui va bien, pas pu vérifier.
//!
//! La règle de Vanguard tient ici aussi : ce qui n'a pas pu être vérifié n'est jamais compté comme sain. Un état
//! inconnu (écrit par une version plus récente), un constat illisible ou un constat sans état ni preuve de
//! vérification vont dans « pas pu vérifier ». La note n'est montrée que si Vanguard la dit fiable (`fiable`, posé
//! par `audit --json`) : sinon une machine peu vérifiée aurait une note rassurante.
//!
//! L'audit du réseau (`audit-reseau --json`) a sa propre forme, six domaines qui portent chacun des constats de
//! l'audit : `lire_audit_reseau` les met à la suite, et la même vue les montre.

use serde::Deserialize;

use super::{Liste, Texte};

/// Où un constat se range.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Rang {
    Corriger,
    Savoir,
    Sain,
    SansObjet,
    NonVerifie,
}

impl Rang {
    pub const TOUS: [Rang; 5] = [
        Rang::Corriger,
        Rang::Savoir,
        Rang::Sain,
        Rang::SansObjet,
        Rang::NonVerifie,
    ];

    pub fn nom(self) -> &'static str {
        match self {
            Rang::Corriger => crate::tr!("à corriger", "to fix"),
            Rang::Savoir => crate::tr!("bon à savoir", "good to know"),
            Rang::Sain => crate::tr!("sains", "healthy"),
            Rang::SansObjet => crate::tr!("sans objet ici", "not applicable"),
            Rang::NonVerifie => crate::tr!("pas pu vérifier", "could not check"),
        }
    }
}

/// La gravité d'un point à corriger.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Gravite {
    Info,
    Moyenne,
    Elevee,
    Critique,
}

impl Gravite {
    /// « Info », « Moyen », « Eleve », « Critique » (`risk::Niveau` de Vanguard) ; un autre mot : moyenne, pour ne
    /// pas taire un problème dont on ne connaît pas le niveau.
    pub(super) fn lire(mot: &str) -> Option<Gravite> {
        match mot {
            "" => None,
            "Info" => Some(Gravite::Info),
            "Eleve" => Some(Gravite::Elevee),
            "Critique" => Some(Gravite::Critique),
            _ => Some(Gravite::Moyenne),
        }
    }

    pub fn nom(self) -> &'static str {
        match self {
            Gravite::Info => "info",
            Gravite::Moyenne => crate::tr!("moyen", "medium"),
            Gravite::Elevee => crate::tr!("élevé", "high"),
            Gravite::Critique => crate::tr!("critique", "critical"),
        }
    }
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct CorrectifBrut {
    action: Texte,
}

/// Un constat tel que Vanguard l'écrit : les champs de l'audit (`probleme`, `correctif`, `verifie`) et ceux du
/// résultat commun (`niveau`, `corrigeable`), tous facultatifs.
#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct ConstatBrut {
    categorie: Texte,
    probleme: Texte,
    niveau: Texte,
    message: Texte,
    correctif: Option<CorrectifBrut>,
    verifie: Option<bool>,
    regle: Texte,
    etat: Texte,
    objet: Texte,
}

/// Un constat prêt à montrer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Constat {
    pub categorie: String,
    pub regle: String,
    pub objet: String,
    pub message: String,
    /// Ce que la correction ferait, quand Vanguard en propose une (montrée, jamais appliquée d'ici dans ce lot).
    pub action: String,
    pub gravite: Option<Gravite>,
    pub rang: Rang,
}

impl From<ConstatBrut> for Constat {
    fn from(b: ConstatBrut) -> Constat {
        let gravite = Gravite::lire(if b.probleme.is_empty() {
            b.niveau.as_str()
        } else {
            b.probleme.as_str()
        });
        let rang = match b.etat.as_str() {
            "sain" => Rang::Sain,
            "sans-objet" => Rang::SansObjet,
            "probleme" => match gravite {
                Some(Gravite::Info) => Rang::Savoir,
                _ => Rang::Corriger,
            },
            // Sans état (une version d'avant) : seulement ce que les autres champs prouvent.
            "" => match (b.verifie, gravite) {
                (Some(false), _) | (None, None) => Rang::NonVerifie,
                (_, Some(Gravite::Info)) => Rang::Savoir,
                (_, Some(_)) => Rang::Corriger,
                (Some(true), None) => Rang::Sain,
            },
            // « non-verifie », ou un état qu'on ne connaît pas : jamais sain.
            _ => Rang::NonVerifie,
        };
        let categorie = if b.categorie.is_empty() {
            crate::tr!("Autre", "Other").to_string()
        } else {
            crate::nettoyage::nom(b.categorie.as_str(), 60)
        };
        Constat {
            categorie,
            regle: crate::nettoyage::nom(b.regle.as_str(), 40),
            objet: crate::nettoyage::nom(b.objet.as_str(), 120),
            message: b.message.0,
            action: b.correctif.map(|c| c.action.0).unwrap_or_default(),
            gravite,
            rang,
        }
    }
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct CouvertureBrute {
    verifies: Option<u64>,
    non_verifies: Vec<Texte>,
}

/// Les deux formes relues : l'audit (`score`, `fiable`, `systeme`) et le résultat commun (`outil`, `couverture`).
#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct Brut {
    systeme: Texte,
    score: Option<u64>,
    fiable: Option<bool>,
    outil: Texte,
    couverture: Option<CouvertureBrute>,
    constats: Liste<ConstatBrut>,
}

/// Un bilan ou un résultat d'outil, rangé.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Vue {
    pub systeme: String,
    pub outil: String,
    /// La note sur 100, seulement quand Vanguard la dit fiable.
    pub note: Option<u32>,
    /// Une note existait, mais Vanguard la dit non fiable (trop peu vérifié) : elle n'est pas montrée.
    pub note_retenue: bool,
    pub constats: Vec<Constat>,
    /// Les constats qui ne se lisaient pas : comptés avec « pas pu vérifier ».
    pub illisibles: usize,
    /// Ce que l'outil dit n'avoir pas pu vérifier (sa couverture), en plus de ses constats.
    pub manques: Vec<String>,
}

/// Lit un bilan ou un résultat d'outil.
pub fn lire(sortie: &[u8]) -> Result<Vue, String> {
    let b: Brut = super::lire(sortie)?;
    let note = b.score.and_then(|s| u32::try_from(s).ok()).filter(|s| *s <= 100);
    let fiable = b.fiable == Some(true) && !b.constats.elements.is_empty();
    let manques = b
        .couverture
        .map(|c| {
            c.non_verifies
                .into_iter()
                .take(super::ELEMENTS_MAX)
                .map(|t| t.0)
                .filter(|t| !t.is_empty())
                .collect()
        })
        .unwrap_or_default();
    Ok(Vue {
        systeme: crate::nettoyage::nom(b.systeme.as_str(), 80),
        outil: crate::nettoyage::nom(b.outil.as_str(), 40),
        note: note.filter(|_| fiable),
        note_retenue: note.is_some() && !fiable,
        illisibles: b.constats.illisibles,
        constats: b.constats.elements.into_iter().map(Constat::from).collect(),
        manques,
    })
}

/// Un domaine de `audit-reseau --json` : son nom et ses constats (de la forme de l'audit).
#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct DomaineBrut {
    domaine: Texte,
    constats: Liste<ConstatBrut>,
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct BrutReseau {
    reseau: Texte,
    nom_reseau: Texte,
    score: Option<u64>,
    domaines: Liste<DomaineBrut>,
}

/// Lit `audit-reseau --json` : les constats des domaines à la suite, rangés sous leur domaine quand ils n'ont pas
/// de catégorie. Vanguard n'écrit aucune note dès qu'un domaine est trop peu vérifié (il n'y a pas de `fiable` ici) :
/// la note est prise telle quelle, et `note_incomplete` dit à côté ce qui reste non vérifié.
pub fn lire_audit_reseau(sortie: &[u8]) -> Result<Vue, String> {
    let b: BrutReseau = super::lire(sortie)?;
    let mut illisibles = b.domaines.illisibles;
    let mut constats = Vec::new();
    for d in b.domaines.elements {
        illisibles = illisibles.saturating_add(d.constats.illisibles);
        for mut c in d.constats.elements {
            // Chaque liste est bornée, leur somme ne l'est pas : la même borne pour le tout.
            if constats.len() >= super::ELEMENTS_MAX {
                illisibles = illisibles.saturating_add(1);
                continue;
            }
            if c.categorie.is_empty() {
                c.categorie = d.domaine.clone();
            }
            constats.push(Constat::from(c));
        }
    }
    let mut manques = Vec::new();
    if b.reseau.is_empty() {
        manques.push(
            crate::tr!(
                "Aucun réseau local : rien n'a pu être audité",
                "No local network: nothing could be audited"
            )
            .to_string(),
        );
    } else if constats.is_empty() && illisibles == 0 {
        manques.push(crate::tr!("Aucun domaine lu", "No area read").to_string());
    }
    let nom = if b.nom_reseau.is_empty() {
        &b.reseau
    } else {
        &b.nom_reseau
    };
    // Une note sans aucun constat n'a rien jugé : pas montrée.
    let note = b
        .score
        .and_then(|s| u32::try_from(s).ok())
        .filter(|s| *s <= 100 && !constats.is_empty());
    Ok(Vue {
        systeme: crate::nettoyage::nom(nom.as_str(), 80),
        outil: "audit-reseau".into(),
        note,
        note_retenue: false,
        illisibles,
        constats,
        manques,
    })
}

impl Vue {
    pub fn compte(&self, rang: Rang) -> usize {
        let n = self.constats.iter().filter(|c| c.rang == rang).count();
        if rang == Rang::NonVerifie {
            n.saturating_add(self.illisibles).saturating_add(self.manques.len())
        } else {
            n
        }
    }

    /// Une note montrée alors que des vérifications n'ont pas pu se faire : leur nombre. La note de Vanguard ne les
    /// compte pas ; la fenêtre le dit à côté du chiffre, en couleur d'alerte, pour qu'un 100/100 ne passe pas pour
    /// « tout est sain ».
    pub fn note_incomplete(&self) -> Option<usize> {
        let n = self.compte(Rang::NonVerifie);
        (self.note.is_some() && n > 0).then_some(n)
    }

    /// Les constats d'un rang ; à corriger, les plus graves d'abord (l'ordre de Vanguard gardé à gravité égale).
    pub fn de_rang(&self, rang: Rang) -> Vec<&Constat> {
        let mut v: Vec<&Constat> = self.constats.iter().filter(|c| c.rang == rang).collect();
        if rang == Rang::Corriger {
            v.sort_by_key(|c| std::cmp::Reverse(c.gravite));
        }
        v
    }

    /// Les catégories saines, avec leur nombre de vérifications, dans l'ordre du bilan.
    pub fn sains_par_categorie(&self) -> Vec<(String, usize)> {
        let mut v: Vec<(String, usize)> = Vec::new();
        for c in self.constats.iter().filter(|c| c.rang == Rang::Sain) {
            match v.iter_mut().find(|(n, _)| *n == c.categorie) {
                Some((_, k)) => *k = k.saturating_add(1),
                None => v.push((c.categorie.clone(), 1)),
            }
        }
        v
    }

    /// Les constats sains un par un quand ils sont tous d'une même catégorie : c'est un inventaire (programmes au
    /// démarrage, conteneurs), et une pastille « Programmes au démarrage 11 » en cacherait la liste. `None` avec
    /// plusieurs catégories (le bilan), qui restent une pastille chacune, ou avec un seul constat sain.
    pub fn sains_en_liste(&self) -> Option<Vec<&Constat>> {
        let sains = self.de_rang(Rang::Sain);
        let premier: &Constat = sains.first().copied()?;
        (sains.len() > 1 && sains.iter().all(|c| c.categorie == premier.categorie)).then_some(sains)
    }

    /// La bande : par catégorie, dans l'ordre du bilan, le rang de chaque vérification.
    pub fn groupes(&self) -> Vec<(String, Vec<Rang>)> {
        let mut v: Vec<(String, Vec<Rang>)> = Vec::new();
        for c in &self.constats {
            match v.iter_mut().find(|(n, _)| *n == c.categorie) {
                Some((_, r)) => r.push(c.rang),
                None => v.push((c.categorie.clone(), vec![c.rang])),
            }
        }
        v
    }

    /// Le résumé d'une ligne, pour la console et l'accueil.
    pub fn resume(&self) -> String {
        let corriger = self.compte(Rang::Corriger);
        let nv = self.compte(Rang::NonVerifie);
        crate::trf!(
            "{} vérification(s), {} à corriger, {} pas pu vérifier",
            "{} check(s), {} to fix, {} could not check",
            self.constats.len(),
            corriger,
            nv
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn une_note_avec_des_points_non_verifies_le_dit() {
        let mut v = lire(AUDIT.as_bytes()).unwrap();
        assert_eq!(v.note, Some(82));
        // Le constat « non-verifie » et ceux qui ne se lisent pas.
        assert_eq!(v.note_incomplete(), Some(v.compte(Rang::NonVerifie)));
        assert!(v.note_incomplete().is_some_and(|n| n > 0));
        v.constats.retain(|c| c.rang != Rang::NonVerifie);
        v.illisibles = 0;
        v.manques.clear();
        assert_eq!(v.note_incomplete(), None);
        v.manques.push("pare-feu".into());
        assert_eq!(v.note_incomplete(), Some(1));
        v.note = None;
        assert_eq!(v.note_incomplete(), None);
    }

    const AUDIT: &str = r#"{
        "systeme": "Linux · essai",
        "score": 82,
        "fiable": true,
        "constats": [
            {"categorie": "Pare-feu", "probleme": null, "message": "ufw actif.", "correctif": null,
             "verifie": true, "regle": "LNX-PFE-001", "etat": "sain"},
            {"categorie": "SSH", "probleme": "Eleve", "message": "Connexion root permise.",
             "correctif": {"action": "Refuser root.", "commandes": ["x"], "automatique": false},
             "verifie": true, "regle": "LNX-SSH-002", "etat": "probleme"},
            {"categorie": "SSH", "probleme": "Moyen", "message": "Mot de passe permis.", "correctif": null,
             "verifie": true, "regle": "LNX-SSH-003", "etat": "probleme"},
            {"categorie": "Mises à jour", "probleme": "Critique", "message": "12 paquets en retard.",
             "correctif": null, "verifie": true, "etat": "probleme"},
            {"categorie": "Comptes", "probleme": "Info", "message": "Compte alice sans mot de passe expiré.",
             "correctif": null, "verifie": true, "etat": "probleme"},
            {"categorie": "Chiffrement", "probleme": "Info", "message": "Illisible sans droits.",
             "correctif": null, "verifie": false, "etat": "non-verifie", "raison": "droits"},
            {"categorie": "Partage", "probleme": null, "message": "Aucun partage.", "correctif": null,
             "verifie": true, "etat": "sans-objet", "absence": "logiciel"},
            {"categorie": "Pare-feu", "probleme": null, "message": "Entrées refusées.", "correctif": null,
             "verifie": true, "etat": "sain", "champ_futur": {"a": 1}},
            {"categorie": "Nouveau", "message": "Écrit par une version plus récente.", "etat": "a-revoir"},
            "pas un constat"
        ]
    }"#;

    /// Un inventaire (une seule catégorie) se montre ligne par ligne ; plusieurs catégories ou un seul sain restent
    /// des pastilles.
    #[test]
    fn inventaire_en_liste() {
        let un = |cat: &str, m: &str| format!(r#"{{"categorie": "{cat}", "etat": "sain", "message": "{m}"}}"#);
        let vue = |c: &[String]| lire(format!(r#"{{"constats": [{}]}}"#, c.join(",")).as_bytes()).unwrap();
        let liste = vue(&[
            un("Démarrage", "Alpha"),
            un("Démarrage", "Bravo"),
            un("Démarrage", "Charlie"),
        ]);
        let messages: Option<Vec<&str>> = liste
            .sains_en_liste()
            .map(|l| l.iter().map(|c| c.message.as_str()).collect());
        assert_eq!(messages, Some(vec!["Alpha", "Bravo", "Charlie"]));
        assert!(vue(&[un("Pare-feu", "A"), un("SSH", "B")]).sains_en_liste().is_none());
        assert!(vue(&[un("Démarrage", "Alpha")]).sains_en_liste().is_none());
        assert!(vue(&[]).sains_en_liste().is_none());
    }

    #[test]
    fn range_un_audit() {
        let v = lire(AUDIT.as_bytes()).unwrap();
        assert_eq!(v.note, Some(82));
        assert_eq!(v.compte(Rang::Corriger), 3);
        assert_eq!(v.compte(Rang::Savoir), 1);
        assert_eq!(v.compte(Rang::Sain), 2);
        assert_eq!(v.compte(Rang::SansObjet), 1);
        // Le non vérifié, l'état inconnu et la ligne illisible.
        assert_eq!(v.compte(Rang::NonVerifie), 3);
        assert_eq!(v.illisibles, 1);
        let corriger: Vec<&str> = v.de_rang(Rang::Corriger).iter().map(|c| c.message.as_str()).collect();
        assert_eq!(
            corriger,
            [
                "12 paquets en retard.",
                "Connexion root permise.",
                "Mot de passe permis."
            ]
        );
        assert_eq!(
            v.de_rang(Rang::Corriger).get(1).map(|c| c.action.as_str()),
            Some("Refuser root.")
        );
        assert_eq!(v.sains_par_categorie(), [("Pare-feu".to_string(), 2)]);
        // Deux sains de la même catégorie : la liste, ligne par ligne.
        assert_eq!(v.sains_en_liste().map(|l| l.len()), Some(2));
        let tous = v.groupes();
        let groupes: Vec<&str> = tous.iter().map(|g| g.0.as_str()).collect();
        assert_eq!(
            groupes,
            [
                "Pare-feu",
                "SSH",
                "Mises à jour",
                "Comptes",
                "Chiffrement",
                "Partage",
                "Nouveau"
            ]
        );
    }

    #[test]
    fn la_note_n_est_montree_que_fiable() {
        let sans = AUDIT.replace(r#""fiable": true,"#, r#""fiable": false,"#);
        let v = lire(sans.as_bytes()).unwrap();
        assert_eq!(v.note, None);
        assert!(v.note_retenue);
        // Une version d'avant, qui n'écrit pas `fiable` : pas de note non plus.
        let ancienne = AUDIT.replace(r#""fiable": true,"#, "");
        assert_eq!(lire(ancienne.as_bytes()).unwrap().note, None);
        // Une note hors de 0..=100 n'est pas montrée.
        let folle = AUDIT.replace("82", "4000000000000");
        assert_eq!(lire(folle.as_bytes()).unwrap().note, None);
        // Aucun constat : rien n'a été jugé, pas de note.
        let vide = lire(br#"{"score": 100, "fiable": true, "constats": []}"#).unwrap();
        assert_eq!(vide.note, None);
    }

    #[test]
    fn sans_etat_seule_la_preuve_compte() {
        let v = lire(
            br#"{"constats": [
                {"categorie": "A", "probleme": null, "verifie": true},
                {"categorie": "B", "probleme": null, "verifie": false},
                {"categorie": "C", "probleme": null},
                {"categorie": "D", "probleme": "Moyen"},
                {"categorie": "E", "probleme": "Info", "verifie": true}
            ]}"#,
        )
        .unwrap();
        let rangs: Vec<Rang> = v.constats.iter().map(|c| c.rang).collect();
        assert_eq!(
            rangs,
            [
                Rang::Sain,
                Rang::NonVerifie,
                Rang::NonVerifie,
                Rang::Corriger,
                Rang::Savoir
            ]
        );
    }

    #[test]
    fn range_un_resultat_d_outil() {
        let v = lire(
            r#"{"outil": "PRO-LEN-001", "schema": 1, "debut": "2026-11-09T14:00:00Z", "duree_ms": 2143,
                "couverture": {"verifies": 6, "non_verifies": ["Disque : illisible", ""]},
                "constats": [
                    {"categorie": "Santé", "etat": "sain", "message": "Rien ne force."},
                    {"categorie": "Mémoire", "etat": "probleme", "niveau": "Moyen", "message": "Presque pleine.",
                     "corrigeable": true}
                ]}"#
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(v.outil, "PRO-LEN-001");
        assert_eq!(v.note, None);
        assert_eq!(v.compte(Rang::Corriger), 1);
        assert_eq!(
            v.de_rang(Rang::Corriger).first().and_then(|c| c.gravite),
            Some(Gravite::Moyenne)
        );
        // Un manque de la couverture compte comme non vérifié ; un manque vide est ignoré.
        assert_eq!(v.manques, ["Disque : illisible"]);
        assert_eq!(v.compte(Rang::NonVerifie), 1);
    }

    #[test]
    fn un_texte_piege_arrive_propre() {
        let v = lire(
            "{\"constats\": [{\"categorie\": \"R\u{e9}seau\\u202e\", \"etat\": \"probleme\", \"probleme\": \"Moyen\", \
             \"message\": \"Salon\\u001b[2K\\rtout va bien\"}]}"
                .as_bytes(),
        )
        .unwrap();
        let c = v.constats.first().unwrap();
        assert_eq!(c.categorie, "Réseau\u{fffd}");
        assert_eq!(c.message, "Salon\u{fffd}tout va bien");
    }

    #[test]
    fn range_un_audit_du_reseau() {
        let v = lire_audit_reseau(
            br#"{"reseau": "192.168.1.0/24", "nom_reseau": "Salon", "score": 70, "domaines": [
                {"domaine": "Wi-Fi", "constats": [
                    {"categorie": "Wi-Fi", "etat": "probleme", "probleme": "Eleve", "message": "WPA2 seul."},
                    {"etat": "sain", "message": "Rien d'ouvert."}]},
                {"domaine": "Postes", "constats": [{"etat": "non-verifie", "message": "Pas lu."}, 3]},
                "pas un domaine"
            ]}"#,
        )
        .unwrap();
        assert_eq!(v.systeme, "Salon");
        assert_eq!(v.note, Some(70));
        assert_eq!(v.constats.len(), 3);
        // Sans catégorie : rangé sous son domaine.
        assert_eq!(v.constats[1].categorie, "Wi-Fi");
        assert_eq!(v.constats[2].categorie, "Postes");
        assert_eq!(v.compte(Rang::Corriger), 1);
        // Le constat non vérifié, le constat illisible et le domaine illisible : jamais sains.
        assert_eq!(v.illisibles, 2);
        assert_eq!(v.compte(Rang::NonVerifie), 3);
        assert_eq!(v.note_incomplete(), Some(3));

        // Aucun réseau local : pas de note, et c'est dit.
        let v = lire_audit_reseau(br#"{"reseau": null, "score": null, "domaines": []}"#).unwrap();
        assert_eq!(v.note, None);
        assert_eq!(v.manques.len(), 1);
        assert!(v.compte(Rang::NonVerifie) > 0);
        // Une note sans aucun constat ne se montre pas, et le vide est dit.
        let v = lire_audit_reseau(br#"{"reseau": "10.0.0.0/24", "score": 100, "domaines": []}"#).unwrap();
        assert_eq!(v.note, None);
        assert_eq!(v.manques.len(), 1);
    }

    #[test]
    fn l_audit_du_reseau_est_borne_dans_son_ensemble() {
        let domaine = format!(
            r#"{{"domaine": "Postes", "constats": [{}]}}"#,
            vec!["{}"; 3000].join(",")
        );
        let json = format!(r#"{{"reseau": "10.0.0.0/24", "domaines": [{domaine}, {domaine}]}}"#);
        let v = lire_audit_reseau(json.as_bytes()).unwrap();
        assert_eq!(v.constats.len(), crate::donnees::ELEMENTS_MAX);
        assert_eq!(v.illisibles, 6000 - crate::donnees::ELEMENTS_MAX);
    }

    #[test]
    fn un_json_abime_rend_une_erreur() {
        assert!(lire(b"").is_err());
        assert!(lire(b"{\"constats\": [").is_err());
        assert!(lire(b"[]").is_err());
        let v = lire(b"{}").unwrap();
        assert_eq!(v.constats, []);
        assert_eq!(v.note, None);
    }
}

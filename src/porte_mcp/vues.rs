//! Ce que la porte montre d'un événement, d'un constat ou d'un bilan : des noms fermés, des nombres, des dates UTC,
//! des liens hachés ; le texte venu de l'ordinateur seulement nettoyé, borné et rangé à part (`texte_externe`).
//! Jamais un chemin, une ligne de commande, un compte, un pid, une adresse, l'objet d'un constat, un geste.

use serde_json::{Map, Value, json};

use crate::modele::evenement::{Evenement, Genre};
use crate::risk::Niveau;

/// Un nom fermé : 1 à `max` caractères parmi `[a-z0-9-]`, sinon rien.
pub(crate) fn ferme(texte: &str, max: usize) -> Option<&str> {
    let bon = !texte.is_empty()
        && texte.len() <= max
        && texte
            .bytes()
            .all(|o| o.is_ascii_lowercase() || o.is_ascii_digit() || o == b'-');
    bon.then_some(texte)
}

/// Une version (« 0.96.0 », « 0.96.0+1789000000 ») : chiffres, lettres minuscules, `.`, `+`, `-`, 32 au plus.
fn version(texte: &str) -> Option<&str> {
    let bon = !texte.is_empty()
        && texte.len() <= 32
        && texte
            .bytes()
            .all(|o| o.is_ascii_lowercase() || o.is_ascii_digit() || matches!(o, b'.' | b'+' | b'-'));
    bon.then_some(texte)
}

/// Une date UTC de la forme « AAAA-MM-JJTHH:MM:SSZ », sinon rien.
pub(crate) fn date_utc(texte: &str) -> Option<&str> {
    let forme = b"0000-00-00T00:00:00Z";
    let bon = texte.len() == forme.len()
        && texte
            .bytes()
            .zip(forme.iter())
            .all(|(o, &f)| if f == b'0' { o.is_ascii_digit() } else { o == f });
    bon.then_some(texte)
}

/// Une empreinte SHA-256 : 64 chiffres hexadécimaux minuscules, sinon rien.
pub(crate) fn sha256(texte: &str) -> Option<&str> {
    let bon = texte.len() == 64 && texte.bytes().all(|o| o.is_ascii_digit() || (b'a'..=b'f').contains(&o));
    bon.then_some(texte)
}

/// Le nom stable d'une gravité.
pub(crate) fn niveau(n: Niveau) -> &'static str {
    match n {
        Niveau::Info => "info",
        Niveau::Moyen => "moyen",
        Niveau::Eleve => "eleve",
        Niveau::Critique => "critique",
    }
}

/// La gravité d'un nom stable.
pub(crate) fn niveau_de(nom: &str) -> Option<Niveau> {
    match nom {
        "info" => Some(Niveau::Info),
        "moyen" => Some(Niveau::Moyen),
        "eleve" => Some(Niveau::Eleve),
        "critique" => Some(Niveau::Critique),
        _ => None,
    }
}

/// Les sortes d'événements que la porte connaît (`Genre::sorte`).
pub(crate) const SORTES: &[&str] = &[
    "alerte",
    "preuve",
    "action",
    "annulation",
    "normale",
    "normale-oubliee",
    "version",
    "rupture",
    "examen",
    "session-porte",
    "inconnu",
];

/// Un texte venu de l'ordinateur, qui peut citer un attaquant : passé par l'anonymisation et le nettoyage de la voie
/// ouverte (`amelioration::texte` : 300 octets, secrets remplacés, ponctuation sans effet), puis sans piège. Rangé à
/// part, marqué ; jeté en entier (vide, `retire`) quand le nettoyage le refuse.
pub(crate) fn texte_externe(brut: &str) -> Value {
    let net = crate::amelioration::texte(brut)
        .map(|t| crate::modele::resultat::sans_piege(t.as_str(), false))
        .unwrap_or_default();
    if net.trim().is_empty() {
        return json!({ "texte_externe": "", "nettoye": true, "retire": true });
    }
    json!({ "texte_externe": net, "nettoye": true })
}

/// Le nom court d'un programme (son nom de fichier seul), nettoyé comme un nom de logiciel ; rien s'il est refusé.
fn nom_de_programme(chemin: &str) -> Option<String> {
    let court = chemin.rsplit(['/', '\\']).next().unwrap_or_default();
    let nom = crate::amelioration::nom(court).ok()?;
    let sur = crate::modele::resultat::nom_sans_piege(nom.as_str(), 64);
    (!sur.trim().is_empty()).then_some(sur)
}

/// Le préfixe fermé d'une clé de déduplication (« alerte-botnet » de « alerte-botnet|10.0.0.5 ») : ce qui la range,
/// jamais ce qu'elle désigne.
fn prefixe_de_cle(cle: &str) -> Option<&str> {
    let tete = cle.split(['|', ':']).next().unwrap_or_default();
    ferme(tete, 40)
}

/// Ce qui lie sans rien dire : un identifiant (qui porte le pid), une cause, une clé, un blocage, haché sous une clé
/// tirée pour la session (BLAKE3, 16 octets). Deux réponses de la même session se relient ; rien ne se relit hors
/// d'elle.
pub(crate) struct Liens([u8; 32]);

impl Liens {
    pub(crate) fn tirer() -> Option<Liens> {
        let mut cle = [0u8; 32];
        getrandom::fill(&mut cle).ok()?;
        Some(Liens(cle))
    }

    #[cfg(test)]
    pub(crate) fn fixes() -> Liens {
        Liens([7; 32])
    }

    pub(crate) fn lien(&self, texte: &str) -> String {
        let h = blake3::keyed_hash(&self.0, texte.as_bytes());
        h.as_bytes()
            .iter()
            .take(16)
            .fold(String::with_capacity(32), |mut s, o| {
                use std::fmt::Write as _;
                let _ = write!(s, "{o:02x}");
                s
            })
    }
}

/// Un événement tel que la porte le montre. `verifie` : écrit sous une tête crue, après la dernière rupture.
pub(crate) fn evenement(e: &Evenement, verifie: bool, liens: &Liens) -> Value {
    let mut v = Map::new();
    v.insert("id".into(), json!(liens.lien(&e.id)));
    v.insert("quand".into(), json!(date_utc(&e.quand)));
    v.insert("source".into(), serde_json::to_value(e.source).unwrap_or(Value::Null));
    v.insert("gravite".into(), json!(e.gravite.map(niveau)));
    v.insert("cle".into(), json!(e.cle.as_deref().and_then(prefixe_de_cle)));
    v.insert("cle_lien".into(), json!(e.cle.as_deref().map(|c| liens.lien(c))));
    v.insert("cause".into(), json!(e.cause.as_deref().map(|c| liens.lien(c))));
    v.insert("essai".into(), json!(e.essai));
    v.insert("genre".into(), json!(e.quoi.sorte()));
    v.insert("verifie".into(), json!(verifie));
    match &e.quoi {
        Genre::Alerte { famille, titre, texte } => {
            v.insert("famille".into(), json!(ferme(famille, 40)));
            v.insert("titre".into(), texte_externe(titre));
            v.insert("texte".into(), texte_externe(texte));
        }
        Genre::Preuve { releve } => {
            let fichier = releve.fichier.as_ref();
            v.insert(
                "sha256".into(),
                json!(fichier.and_then(|f| f.sha256.as_deref()).and_then(sha256)),
            );
            v.insert("taille".into(), json!(fichier.and_then(|f| f.taille)));
            let programme = releve.processus.as_ref().and_then(|p| p.programme.as_deref());
            v.insert("programme".into(), json!(programme.and_then(nom_de_programme)));
            v.insert("connexions".into(), json!(releve.connexions.len()));
            v.insert("impossible".into(), json!(releve.impossible.len()));
        }
        Genre::Action {
            reussi,
            automatique,
            blocage,
            annulable,
            ..
        } => {
            v.insert("reussi".into(), json!(reussi));
            v.insert("automatique".into(), json!(automatique));
            v.insert("annulable".into(), json!(annulable.is_some()));
            v.insert("blocage".into(), json!(blocage.as_deref().map(|b| liens.lien(b))));
        }
        Genre::Annulation { objet, supprime } => {
            v.insert("objet".into(), json!(liens.lien(objet)));
            v.insert("supprime".into(), json!(supprime));
        }
        Genre::Version { de, vers } => {
            v.insert("de".into(), json!(de.as_deref().and_then(version)));
            v.insert("vers".into(), json!(version(vers)));
        }
        Genre::Examen {
            outil,
            verdict,
            problemes,
            non_verifies,
        } => {
            let outil = crate::modele::resultat::AVEC_RESULTAT
                .iter()
                .find(|o| **o == outil.as_str());
            v.insert("outil".into(), json!(outil));
            v.insert("verdict".into(), json!(verdict_ferme(verdict)));
            v.insert("problemes".into(), json!(problemes));
            v.insert("non_verifies".into(), json!(non_verifies));
        }
        Genre::SessionPorte { duree_s, fin, .. } => {
            v.insert("duree_s".into(), json!(duree_s));
            v.insert("fin".into(), json!(ferme(fin, 40)));
        }
        Genre::Normale { .. } | Genre::NormaleOubliee | Genre::Rupture { .. } | Genre::Inconnu => {}
    }
    Value::Object(v)
}

/// Un verdict d'examen, fermé.
pub(crate) fn verdict_ferme(verdict: &str) -> Option<&'static str> {
    ["sain", "non-verifie", "probleme", "sans-objet"]
        .into_iter()
        .find(|v| *v == verdict)
}

/// Un constat tel que la porte le montre : jamais `objet`, `geste` ni `dossier`.
pub(crate) fn constat(c: &crate::modele::resultat::ConstatEcrit) -> Value {
    let regle = (!c.regle.is_empty()
        && c.regle.len() <= 64
        && c.regle
            .bytes()
            .all(|o| o.is_ascii_alphanumeric() || matches!(o, b'-' | b'_' | b'.')))
    .then_some(c.regle.as_str());
    let categorie = crate::amelioration::nom(&c.categorie)
        .ok()
        .map(|n| crate::modele::resultat::nom_sans_piege(n.as_str(), 64));
    json!({
        "regle": regle,
        "categorie": categorie,
        "etat": verdict_ferme(&c.etat),
        "niveau": c.niveau.map(niveau),
        "raison": c.raison.as_deref().and_then(|r| ferme(r, 40)),
        "corrigeable": c.corrigeable,
        "date": c.date.as_deref().and_then(date_utc),
        "message": texte_externe(&c.message),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn les_formes_fermees_refusent_le_reste() {
        assert_eq!(ferme("botnet-c2", 40), Some("botnet-c2"));
        assert_eq!(ferme("Botnet", 40), None);
        assert_eq!(ferme("a/b", 40), None);
        assert_eq!(ferme("", 40), None);
        assert_eq!(date_utc("2026-11-16T12:00:00Z"), Some("2026-11-16T12:00:00Z"));
        assert_eq!(date_utc("2026-11-16T12:00:00+01:00"), None);
        assert_eq!(sha256(&"a".repeat(64)), Some("a".repeat(64).as_str()));
        assert_eq!(sha256(&"A".repeat(64)), None);
        assert_eq!(prefixe_de_cle("alerte-botnet|10.0.0.5"), Some("alerte-botnet"));
        assert_eq!(prefixe_de_cle("/home/alice/x"), None);
        assert_eq!(
            nom_de_programme("/home/alice/.cache/minerai-xmr"),
            Some("minerai-xmr".into())
        );
        assert_eq!(version("0.96.0+1789000000"), Some("0.96.0+1789000000"));
        assert_eq!(version("0.96 /home"), None);
    }

    #[test]
    fn les_liens_sont_stables_dans_la_session_et_ne_disent_rien() {
        let l = Liens::fixes();
        assert_eq!(l.lien("e-1-1234"), l.lien("e-1-1234"));
        assert_ne!(l.lien("e-1-1234"), l.lien("e-1-1235"));
        assert_eq!(l.lien("x").len(), 32);
        let autre = Liens([8; 32]);
        assert_ne!(l.lien("x"), autre.lien("x"));
    }
}

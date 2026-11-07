//! Les suites préréglées : pour chaque type d'alerte, les gestes enchaînés, dans l'ordre (suspendre, couper ses
//! connexions, relever la preuve, bloquer, surveiller, prévenir). Les défauts sont fournis ; la personne choisit,
//! ordonne et retire des gestes dans le menu Blocage (`blocage.json`, champ `suites`, scellé avec le reste). Pas de
//! langage de règles : une suite n'est qu'une liste de gestes de la liste fermée (`Etape`), chacun fait par le geste
//! de R1 qui le rejuge (`gestes`, `suspension`, `surveiller`, `ordres::juger`).
//!
//! Anti-forge et auto-résilience : une suite illisible (champ abîmé, geste inconnu, doublon, liste vide), ou lue d'un
//! fichier changé hors de Vanguard (`parametres::charger_de` la retire alors), ou qui retire en automatique un geste
//! que le blocage tout seul garde toujours (`plancher_tenu`), laisse la place à la suite par défaut, et c'est dit.
//!
//! Ce module est pur : ce qu'il faut savoir de la menace est lu ailleurs (`mod.rs`, `enchainer`) et donné ici.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use serde_json::Value;

use crate::{tr, trf};

/// Un type d'alerte, qui a sa suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Type {
    /// Le veilleur anti-rançongiciel (fichiers chiffrés en rafale, piège touché).
    Rancongiciel,
    /// Une connexion vers un serveur de commande connu.
    ServeurDeCommande,
    /// Un outil d'attaque connu en marche.
    OutilDAttaque,
    /// Un fichier dont l'empreinte est connue de MalwareBazaar.
    MalwareConnu,
    /// Une famille de logiciels malveillants reconnue par ses règles (AV4, à venir) : le type et sa suite existent
    /// déjà, rien ne le produit encore.
    Famille,
    /// Un agent d'IA hors de contrôle : serveur d'IA ouvert au réseau, agent réglé pour tout faire sans demander.
    AgentIa,
    /// Un programme dont le lancement a été refusé par le garde (à venir) : le type et sa suite existent déjà.
    LancementRefuse,
}

impl Type {
    pub(crate) const TOUS: [Type; 7] = [
        Type::Rancongiciel,
        Type::ServeurDeCommande,
        Type::OutilDAttaque,
        Type::MalwareConnu,
        Type::Famille,
        Type::AgentIa,
        Type::LancementRefuse,
    ];

    /// Le nom gardé dans blocage.json (jamais traduit).
    pub(crate) fn nom(self) -> &'static str {
        match self {
            Type::Rancongiciel => "rancongiciel",
            Type::ServeurDeCommande => "serveur-de-commande",
            Type::OutilDAttaque => "outil-d-attaque",
            Type::MalwareConnu => "malware-connu",
            Type::Famille => "famille",
            Type::AgentIa => "agent-ia",
            Type::LancementRefuse => "lancement-refuse",
        }
    }

    /// Le titre montré, aussi en précision de menu (au plus 31 colonnes : l'éditeur y ajoute « * »).
    pub(crate) fn titre(self) -> &'static str {
        match self {
            Type::Rancongiciel => tr!("Rançongiciel", "Ransomware"),
            Type::ServeurDeCommande => tr!("Serveur de commande", "Command server"),
            Type::OutilDAttaque => tr!("Outil d'attaque", "Attack tool"),
            Type::MalwareConnu => tr!("Malware connu (empreinte)", "Known malware (fingerprint)"),
            Type::Famille => tr!("Famille de malwares", "Malware family"),
            Type::AgentIa => tr!("Agent d'IA hors de contrôle", "AI agent out of control"),
            Type::LancementRefuse => tr!("Lancement refusé par le garde", "Launch refused by the guard"),
        }
    }

    /// Ce qui produit ce type aujourd'hui, en une précision de menu (au plus 33 colonnes).
    pub(crate) fn origine(self) -> &'static str {
        match self {
            Type::Rancongiciel => tr!("veilleur anti-rançongiciel", "ransomware watcher"),
            Type::ServeurDeCommande => tr!("connexions dangereuses", "dangerous connections"),
            Type::OutilDAttaque | Type::MalwareConnu => tr!("programmes malveillants", "malicious programs"),
            Type::Famille => tr!("à venir (familles)", "coming (families)"),
            Type::AgentIa => tr!("agents et serveurs d'IA", "AI agents and servers"),
            Type::LancementRefuse => tr!("à venir (garde des lancements)", "coming (launch guard)"),
        }
    }
}

/// Un geste d'une suite : la liste fermée. Rien d'autre ne s'écrit dans une suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Etape {
    /// Geler le programme (réversible : `vanguard blocage reprendre`).
    Suspendre,
    /// Couper ses connexions déjà ouvertes.
    CouperConnexions,
    /// Couper le réseau d'un programme (R3) : pas encore disponible ; nommé, il est dit et sauté.
    CouperReseau,
    /// Relever la preuve (processus, fichier, connexions) avant qu'un geste ne l'efface.
    Preuve,
    /// Le geste prévu : arrêt et quarantaine, règle de pare-feu, port fermé, réglage remis.
    Bloquer,
    /// Surveiller de plus près, 7 jours.
    Surveiller,
    /// Prévenir : notification et tableau de bord.
    Prevenir,
}

impl Etape {
    pub(crate) const TOUTES: [Etape; 7] = [
        Etape::Suspendre,
        Etape::CouperConnexions,
        Etape::CouperReseau,
        Etape::Preuve,
        Etape::Bloquer,
        Etape::Surveiller,
        Etape::Prevenir,
    ];

    /// Le nom gardé dans blocage.json (jamais traduit).
    pub(crate) fn nom(self) -> &'static str {
        match self {
            Etape::Suspendre => "suspendre",
            Etape::CouperConnexions => "couper-connexions",
            Etape::CouperReseau => "couper-reseau",
            Etape::Preuve => "preuve",
            Etape::Bloquer => "bloquer",
            Etape::Surveiller => "surveiller",
            Etape::Prevenir => "prevenir",
        }
    }

    fn de_nom(nom: &str) -> Option<Etape> {
        Etape::TOUTES.into_iter().find(|e| e.nom() == nom)
    }

    /// Le geste montré (au plus 40 colonnes).
    pub(crate) fn texte(self) -> &'static str {
        match self {
            Etape::Suspendre => tr!("Suspendre (geler)", "Suspend (freeze)"),
            Etape::CouperConnexions => tr!("Couper ses connexions", "Cut its connections"),
            Etape::CouperReseau => tr!("Couper le réseau du programme", "Cut the program's network"),
            Etape::Preuve => tr!("Relever la preuve", "Record the evidence"),
            Etape::Bloquer => tr!("Bloquer (arrêt et quarantaine…)", "Block (stop and quarantine…)"),
            Etape::Surveiller => tr!("Surveiller de plus près (7 jours)", "Watch more closely (7 days)"),
            Etape::Prevenir => tr!("Prévenir (notification)", "Notify (notification)"),
        }
    }

    /// Ce qui le défait, un par un (au plus 33 colonnes) : seuls Suspendre et Bloquer changent quelque chose, et
    /// chacun a sa propre annulation, à part de celles des autres gestes de la même suite.
    pub(crate) fn annulation(self) -> &'static str {
        match self {
            Etape::Suspendre => tr!("« reprendre » le lève", "“resume” lifts it"),
            Etape::Bloquer => tr!("« annuler » le défait, seul", "“undo” reverts it, alone"),
            Etape::Surveiller => tr!("prend fin après 7 jours", "ends after 7 days"),
            Etape::CouperReseau => tr!("pas encore disponible", "not available yet"),
            Etape::CouperConnexions | Etape::Preuve | Etape::Prevenir => {
                tr!("rien à défaire", "nothing to undo")
            }
        }
    }

    /// Le geste existe-t-il déjà ? « Couper le réseau d'un programme » attend R3.
    pub(crate) fn disponible(self) -> bool {
        self != Etape::CouperReseau
    }
}

/// La suite par défaut d'un type. Le rançongiciel : ce que fait déjà `rancongiciel::reponse` (geler la lignée, ce qui
/// coupe ses envois ; la preuve ; l'arrêt et la quarantaine, qui ferment ses connexions ; prévenir). Les autres : ce
/// que le blocage de R1 fait déjà (la preuve avant le geste, le geste, l'alerte), la coupure des connexions déjà
/// ouvertes en plus pour un serveur de commande.
pub(crate) fn defaut(t: Type) -> Vec<Etape> {
    use Etape::{Bloquer, CouperConnexions, Preuve, Prevenir, Suspendre};
    match t {
        Type::Rancongiciel => vec![Suspendre, CouperConnexions, Preuve, Bloquer, Prevenir],
        Type::ServeurDeCommande => vec![Preuve, Bloquer, CouperConnexions, Prevenir],
        Type::OutilDAttaque | Type::MalwareConnu | Type::Famille | Type::AgentIa | Type::LancementRefuse => {
            vec![Preuve, Bloquer, Prevenir]
        }
    }
}

/// Une suite tient-elle le plancher du blocage tout seul (une menace certaine, en automatique) ? Bloquer, puis
/// prévenir (un geste fait tout seul est toujours dit après coup) ; le rançongiciel est gelé avant l'arrêt (le gel
/// arrête le chiffrement pendant la preuve). Le reste se choisit : la coupure des connexions déjà ouvertes vers une
/// adresse ou un port fait partie du geste Bloquer lui-même (R1), elle ne se retire pas avec l'étape.
pub(crate) fn plancher_tenu(t: Type, s: &[Etape]) -> bool {
    let ou = |e: Etape| s.iter().position(|x| *x == e);
    let (Some(bloquer), Some(prevenir)) = (ou(Etape::Bloquer), ou(Etape::Prevenir)) else {
        return false;
    };
    if prevenir < bloquer {
        return false;
    }
    t != Type::Rancongiciel || ou(Etape::Suspendre).is_some_and(|g| g < bloquer)
}

/// Ce que le plancher garde, à dire dans l'éditeur.
pub(crate) fn plancher_dit(t: Type) -> &'static str {
    match t {
        Type::Rancongiciel => tr!(
            "En automatique, une suite garde toujours : suspendre, puis bloquer, puis prévenir. Sinon, celle par défaut s'applique, et c'est dit.",
            "In automatic mode, a suite always keeps: suspend, then block, then notify. Otherwise, the default one applies, and this is said."
        ),
        _ => tr!(
            "En automatique, une suite garde toujours : bloquer, puis prévenir. Sinon, celle par défaut s'applique, et c'est dit.",
            "In automatic mode, a suite always keeps: block, then notify. Otherwise, the default one applies, and this is said."
        ),
    }
}

/// La suite écrite pour ce type dans le champ `suites` de blocage.json : `Ok(None)` si rien n'y est écrit (la suite
/// par défaut), `Err` si elle ne se lit pas (pourquoi). Seuls des gestes de la liste fermée, chacun une fois, au
/// moins un.
pub(crate) fn lire(suites: &Value, t: Type) -> Result<Option<Vec<Etape>>, String> {
    let carte = match suites {
        Value::Null => return Ok(None),
        Value::Object(c) => c,
        _ => {
            return Err(tr!(
                "le champ « suites » n'est pas une liste par type",
                "the “suites” field is not a list per type"
            )
            .to_string());
        }
    };
    let Some(v) = carte.get(t.nom()) else {
        return Ok(None);
    };
    let Value::Array(liste) = v else {
        return Err(tr!("ce n'est pas une liste de gestes", "it is not a list of actions").to_string());
    };
    if liste.is_empty() || liste.len() > Etape::TOUTES.len() {
        return Err(tr!(
            "une suite a de un à sept gestes",
            "a suite has from one to seven actions"
        )
        .to_string());
    }
    let mut etapes = Vec::with_capacity(liste.len());
    for g in liste {
        let Some(e) = g.as_str().and_then(Etape::de_nom) else {
            return Err(trf!(
                "geste inconnu : {}",
                "unknown action: {}",
                crate::ui::affichable(&crate::ui::couper(&g.to_string(), 40))
            ));
        };
        if etapes.contains(&e) {
            return Err(trf!("geste en double : {}", "duplicate action: {}", e.nom()));
        }
        etapes.push(e);
    }
    Ok(Some(etapes))
}

/// Écrit la suite d'un type (`None` : la remet par défaut, en la retirant du fichier). Un champ qui n'était pas une
/// liste par type est remplacé.
pub(crate) fn ecrire(suites: &mut Value, t: Type, etapes: Option<&[Etape]>) {
    if !suites.is_object() {
        *suites = Value::Object(serde_json::Map::new());
    }
    if let Value::Object(carte) = suites {
        match etapes {
            Some(e) => {
                carte.insert(
                    t.nom().to_string(),
                    Value::Array(e.iter().map(|x| Value::String(x.nom().to_string())).collect()),
                );
            }
            None => {
                carte.remove(t.nom());
            }
        }
        if carte.is_empty() {
            *suites = Value::Null;
        }
    }
}

/// La suite qui s'applique, et pourquoi ce n'est pas celle écrite quand elle ne sert pas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Retenue {
    pub(crate) etapes: Vec<Etape>,
    /// La suite écrite ne sert pas (illisible, ou plancher retiré en automatique) : pourquoi, à dire.
    pub(crate) dit: Option<String>,
}

/// La suite d'un type, d'après ce qui a été lu (`lire`) : écrite et lisible, elle sert, sauf en automatique si elle
/// ne tient pas le plancher ; illisible ou absente, celle par défaut.
pub(crate) fn retenir(t: Type, lue: Result<Option<Vec<Etape>>, String>, automatique: bool) -> Retenue {
    match lue {
        Ok(None) => Retenue {
            etapes: defaut(t),
            dit: None,
        },
        Err(raison) => Retenue {
            etapes: defaut(t),
            dit: Some(trf!(
                "suite « {} » illisible dans blocage.json ({raison}) : celle par défaut s'applique",
                "“{}” suite unreadable in blocage.json ({raison}): the default one applies",
                t.titre()
            )),
        },
        Ok(Some(s)) if automatique && !plancher_tenu(t, &s) => Retenue {
            etapes: defaut(t),
            dit: Some(trf!(
                "la suite « {} » retire un geste que le blocage tout seul garde toujours : celle par défaut s'applique",
                "the “{}” suite removes an action that blocking by itself always keeps: the default one applies",
                t.titre()
            )),
        },
        Ok(Some(s)) => Retenue { etapes: s, dit: None },
    }
}

/// Ce sur quoi la suite agit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cible {
    /// Un programme : en marche (un processus à suspendre), et dont l'empreinte se lit (à surveiller).
    Programme { en_marche: bool, empreinte: bool },
    /// Une adresse (serveur de commande).
    Adresse,
    /// Le port d'un serveur d'IA ouvert au réseau.
    Port,
    /// Un réglage ou un port (agent d'IA, démarrage).
    Reglage,
}

/// Ce que devient un geste de la suite pour cette menace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Plan {
    /// Fait à son tour.
    Faire,
    /// Fait par le geste Bloquer de la même suite (la preuve relevée juste avant lui, les connexions coupées avec lui).
    AvecBloquer(&'static str),
    /// Sans objet ici : sauté, et c'est dit.
    SansObjet(&'static str),
    /// Pas encore disponible (R3) : dit et sauté, la suite continue.
    PasDisponible,
}

/// Le plan de la suite pour cette cible : chaque geste, dans l'ordre, fait ou sauté (avec pourquoi). Un geste
/// sauté ne casse jamais la suite. `bloquer_possible` : le geste Bloquer est prêt ; refusé par ses garde-fous, il est
/// dit refusé à son tour, et ce qu'il aurait fait avec lui (la preuve, la coupure) se fait à part quand c'est possible.
#[allow(
    clippy::match_same_arms,
    reason = "un cas par geste et par cible, lu dans l'ordre : les fusionner mêlerait les gardes"
)]
pub(crate) fn planifier(s: &[Etape], c: Cible, surveillance_ici: bool, bloquer_possible: bool) -> Vec<(Etape, Plan)> {
    let bloquer = s.iter().position(|e| *e == Etape::Bloquer).filter(|_| bloquer_possible);
    s.iter()
        .enumerate()
        .map(|(i, &e)| {
            let plan = match (e, c) {
                (Etape::CouperReseau, _) => Plan::PasDisponible,
                (Etape::Bloquer | Etape::Prevenir, _) => Plan::Faire,
                (Etape::Preuve, _) if bloquer.is_some() => Plan::AvecBloquer(tr!(
                    "relevée par Bloquer, juste avant son geste",
                    "recorded by Block, right before its action"
                )),
                (Etape::Preuve, _) => Plan::Faire,
                (Etape::Suspendre, Cible::Programme { en_marche: true, .. }) if bloquer.is_some_and(|b| b < i) => {
                    Plan::SansObjet(tr!(
                        "arrêté juste avant : plus rien à suspendre",
                        "stopped just before: nothing left to suspend"
                    ))
                }
                (Etape::Suspendre, Cible::Programme { en_marche: true, .. }) => Plan::Faire,
                (Etape::Suspendre, _) => Plan::SansObjet(tr!(
                    "aucun processus en marche à suspendre",
                    "no running process to suspend"
                )),
                (Etape::CouperConnexions, Cible::Adresse | Cible::Port) if bloquer.is_some() => {
                    Plan::AvecBloquer(tr!(
                        "coupées juste après la règle, avec elle",
                        "cut right after the rule, with it"
                    ))
                }
                (Etape::CouperConnexions, Cible::Adresse) => Plan::Faire,
                (Etape::CouperConnexions, Cible::Programme { .. }) if bloquer.is_some() => Plan::AvecBloquer(tr!(
                    "un programme gelé n'envoie plus rien ; arrêté, ses connexions se ferment",
                    "a frozen program sends nothing more; stopped, its connections close"
                )),
                (Etape::CouperConnexions, Cible::Programme { .. }) => Plan::SansObjet(tr!(
                    "seules, les connexions d'un programme se coupent avec « couper le réseau d'un programme », pas encore disponible",
                    "on their own, a program's connections are cut by “cut a program's network”, not available yet"
                )),
                (Etape::CouperConnexions, Cible::Port) => Plan::SansObjet(tr!(
                    "seules, celles d'un port se coupent avec la règle qui le ferme (Bloquer)",
                    "on their own, a port's connections are cut with the rule that closes it (Block)"
                )),
                (Etape::CouperConnexions, Cible::Reglage) => Plan::SansObjet(tr!(
                    "aucune connexion désignée",
                    "no connection designated"
                )),
                (Etape::Surveiller, Cible::Programme { empreinte: true, .. }) if surveillance_ici => Plan::Faire,
                (Etape::Surveiller, Cible::Programme { empreinte: true, .. }) => Plan::SansObjet(tr!(
                    "Linux seulement pour l'instant",
                    "Linux only for now"
                )),
                (Etape::Surveiller, _) => Plan::SansObjet(tr!(
                    "aucun fichier de programme dont l'empreinte se lit",
                    "no program file whose fingerprint can be read"
                )),
            };
            (e, plan)
        })
        .collect()
}

/// Les gestes qu'on peut encore ajouter à une suite (ceux qu'elle n'a pas), dans l'ordre de la liste fermée.
pub(crate) fn a_ajouter(s: &[Etape]) -> Vec<Etape> {
    Etape::TOUTES.into_iter().filter(|e| !s.contains(e)).collect()
}

/// Monte le geste `i` d'un cran (le premier ne bouge pas).
pub(crate) fn monter(s: &mut [Etape], i: usize) {
    if let Some(avant) = i.checked_sub(1)
        && i < s.len()
    {
        s.swap(avant, i);
    }
}

/// Retire le geste `i` ; une suite garde au moins un geste (`false` : rien retiré).
pub(crate) fn retirer(s: &mut Vec<Etape>, i: usize) -> bool {
    if s.len() <= 1 || i >= s.len() {
        return false;
    }
    s.remove(i);
    true
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use Etape::*;
    use serde_json::json;

    /// Les défauts : le rançongiciel, dans l'ordre de `rancongiciel::reponse` ; chacun tient le plancher (la suite
    /// par défaut est toujours permise en automatique) ; chaque type en a un, la famille et le lancement refusé aussi.
    #[test]
    fn defauts_fournis_et_tenant_le_plancher() {
        assert_eq!(
            defaut(Type::Rancongiciel),
            [Suspendre, CouperConnexions, Preuve, Bloquer, Prevenir]
        );
        assert_eq!(
            defaut(Type::ServeurDeCommande),
            [Preuve, Bloquer, CouperConnexions, Prevenir]
        );
        for t in Type::TOUS {
            let d = defaut(t);
            assert!(plancher_tenu(t, &d), "{t:?}");
            assert!(d.iter().all(|e| e.disponible()), "{t:?}");
            assert_eq!(
                lire(&json!({ t.nom(): d.iter().map(|e| e.nom()).collect::<Vec<_>>() }), t),
                Ok(Some(d))
            );
        }
    }

    /// La lecture : rien d'écrit, la suite par défaut ; écrite, telle quelle et dans son ordre ; abîmée (pas une
    /// liste, geste inconnu, doublon, vide, trop longue), refusée avec sa raison.
    #[test]
    fn lecture_d_une_suite() {
        assert_eq!(lire(&Value::Null, Type::OutilDAttaque), Ok(None));
        assert_eq!(lire(&json!({}), Type::OutilDAttaque), Ok(None));
        assert_eq!(
            lire(
                &json!({"outil-d-attaque": ["prevenir", "bloquer"]}),
                Type::OutilDAttaque
            ),
            Ok(Some(vec![Prevenir, Bloquer]))
        );
        // Un autre type ne compte pas pour celui-ci.
        assert_eq!(
            lire(&json!({"malware-connu": ["bloquer"]}), Type::OutilDAttaque),
            Ok(None)
        );
        for abime in [
            json!([]),
            json!("bloquer"),
            json!({"outil-d-attaque": "bloquer"}),
            json!({"outil-d-attaque": []}),
            json!({"outil-d-attaque": ["bloquer", "effacer-tout"]}),
            json!({"outil-d-attaque": ["bloquer", 3]}),
            json!({"outil-d-attaque": ["bloquer", "bloquer"]}),
            json!({"outil-d-attaque": ["Bloquer"]}),
            json!({"outil-d-attaque": ["bloquer", "preuve", "prevenir", "suspendre", "surveiller", "couper-reseau", "couper-connexions", "bloquer"]}),
        ] {
            assert!(lire(&abime, Type::OutilDAttaque).is_err(), "{abime}");
        }
    }

    /// Le plancher du certain : en automatique, une suite qui retire l'arrêt (ou prévient avant, ou ne gèle plus le
    /// rançongiciel avant) laisse la place à celle par défaut, et c'est dit ; proposée (un clic), elle sert telle
    /// quelle.
    #[test]
    fn plancher_du_certain_en_automatique() {
        let sans_arret = vec![Preuve, Prevenir];
        for t in Type::TOUS {
            let r = retenir(t, Ok(Some(sans_arret.clone())), true);
            assert_eq!(r.etapes, defaut(t), "{t:?}");
            assert!(r.dit.is_some());
            let r = retenir(t, Ok(Some(sans_arret.clone())), false);
            assert_eq!(r.etapes, sans_arret);
            assert!(r.dit.is_none());
        }
        assert!(!plancher_tenu(Type::MalwareConnu, &[Prevenir, Bloquer]));
        assert!(plancher_tenu(Type::MalwareConnu, &[Bloquer, Surveiller, Prevenir]));
        assert!(!plancher_tenu(Type::Rancongiciel, &[Bloquer, Suspendre, Prevenir]));
        assert!(!plancher_tenu(Type::Rancongiciel, &[Preuve, Bloquer, Prevenir]));
        assert!(plancher_tenu(Type::Rancongiciel, &[Suspendre, Bloquer, Prevenir]));
        assert!(!plancher_tenu(Type::ServeurDeCommande, &[CouperConnexions, Prevenir]));
        assert!(plancher_tenu(Type::ServeurDeCommande, &[Bloquer, Prevenir]));
        // Plus que le plancher (surveiller, couper le réseau à venir) : gardé tel quel en automatique.
        let plus = vec![Suspendre, CouperReseau, Preuve, Bloquer, Surveiller, Prevenir];
        assert_eq!(retenir(Type::Rancongiciel, Ok(Some(plus.clone())), true).etapes, plus);
    }

    /// Un champ abîmé (ou forgé en n'importe quoi) : la suite par défaut, et c'est dit ; jamais une suite vide.
    #[test]
    fn suite_abimee_vaut_celle_par_defaut() {
        for auto in [false, true] {
            let r = retenir(
                Type::ServeurDeCommande,
                lire(&json!({"serveur-de-commande": ["ignorer"]}), Type::ServeurDeCommande),
                auto,
            );
            assert_eq!(r.etapes, defaut(Type::ServeurDeCommande));
            assert!(r.dit.is_some());
        }
        assert_eq!(
            retenir(Type::Famille, Ok(None), true),
            Retenue {
                etapes: defaut(Type::Famille),
                dit: None
            }
        );
    }

    /// L'ordre est gardé, et le plan suit l'ordre : la preuve et la coupure se font avec Bloquer s'il est dans la
    /// suite ; Suspendre après Bloquer n'a plus d'objet ; « couper le réseau » (R3) est dit et sauté sans casser la
    /// suite.
    #[test]
    fn plan_dans_l_ordre_et_geste_a_venir_saute() {
        let prog = Cible::Programme {
            en_marche: true,
            empreinte: true,
        };
        let p = planifier(&defaut(Type::Rancongiciel), prog, true, true);
        let ordre: Vec<Etape> = p.iter().map(|(e, _)| *e).collect();
        assert_eq!(ordre, defaut(Type::Rancongiciel));
        assert_eq!(p[0].1, Plan::Faire);
        assert!(matches!(p[1].1, Plan::AvecBloquer(_)));
        assert!(matches!(p[2].1, Plan::AvecBloquer(_)));
        assert_eq!(p[3].1, Plan::Faire);
        assert_eq!(p[4].1, Plan::Faire);

        let s = [CouperReseau, Bloquer, Suspendre, Surveiller, Prevenir];
        let p = planifier(&s, prog, true, true);
        assert_eq!(p[0].1, Plan::PasDisponible);
        assert_eq!(p[1].1, Plan::Faire);
        assert!(matches!(p[2].1, Plan::SansObjet(_)));
        assert_eq!(p[3].1, Plan::Faire);
        assert_eq!(p[4].1, Plan::Faire);
        assert!(matches!(planifier(&s, prog, false, true)[3].1, Plan::SansObjet(_)));

        // Une adresse : la coupure seule se fait ; avec Bloquer, elle suit la règle.
        assert_eq!(
            planifier(&[CouperConnexions], Cible::Adresse, true, true)[0].1,
            Plan::Faire
        );
        assert!(matches!(
            planifier(&[CouperConnexions, Bloquer], Cible::Adresse, true, true)[0].1,
            Plan::AvecBloquer(_)
        ));
        // Sans Bloquer, la preuve se relève à son tour ; un réglage n'a ni processus ni connexion.
        let p = planifier(
            &[Suspendre, CouperConnexions, Preuve, Prevenir],
            Cible::Reglage,
            true,
            true,
        );
        assert!(matches!(p[0].1, Plan::SansObjet(_)));
        assert!(matches!(p[1].1, Plan::SansObjet(_)));
        assert_eq!(p[2].1, Plan::Faire);
        // Le port d'un serveur d'IA : ses connexions se coupent avec la règle qui le ferme, pas seules.
        assert!(matches!(
            planifier(&[Bloquer, CouperConnexions], Cible::Port, true, true)[1].1,
            Plan::AvecBloquer(_)
        ));
        assert!(matches!(
            planifier(&[CouperConnexions], Cible::Port, true, true)[0].1,
            Plan::SansObjet(_)
        ));
        // Bloquer refusé par ses garde-fous : dit à son tour ; la preuve se relève seule, la coupure vers l'adresse se
        // fait à part.
        let p = planifier(&defaut(Type::ServeurDeCommande), Cible::Adresse, true, false);
        assert_eq!(p[0], (Preuve, Plan::Faire));
        assert_eq!(p[1], (Bloquer, Plan::Faire));
        assert_eq!(p[2], (CouperConnexions, Plan::Faire));
    }

    /// Annulation un par un : chaque geste qui change quelque chose (Suspendre, Bloquer) a sa propre annulation,
    /// distincte ; les autres ne changent rien à défaire, et le disent.
    #[test]
    fn annulation_un_par_un() {
        assert_ne!(Suspendre.annulation(), Bloquer.annulation());
        for e in Etape::TOUTES {
            assert_ne!(e.annulation(), "");
            assert!(e.annulation().chars().count() <= 33, "{e:?}");
        }
        assert!(!CouperReseau.disponible());
        assert_eq!(Etape::TOUTES.iter().filter(|e| !e.disponible()).count(), 1);
    }

    /// L'éditeur : écrire puis relire donne la même suite, dans son ordre ; remettre par défaut la retire du
    /// fichier ; un champ abîmé est remplacé à l'écriture ; monter et retirer gardent au moins un geste.
    #[test]
    fn editeur_ecrire_monter_retirer() {
        let mut v = json!("abîmé");
        ecrire(&mut v, Type::AgentIa, Some(&[Bloquer, Preuve]));
        assert_eq!(lire(&v, Type::AgentIa), Ok(Some(vec![Bloquer, Preuve])));
        ecrire(&mut v, Type::Famille, Some(&[Bloquer]));
        ecrire(&mut v, Type::AgentIa, None);
        assert_eq!(lire(&v, Type::AgentIa), Ok(None));
        ecrire(&mut v, Type::Famille, None);
        assert_eq!(v, Value::Null);

        let mut s = vec![Preuve, Bloquer, Prevenir];
        monter(&mut s, 2);
        assert_eq!(s, [Preuve, Prevenir, Bloquer]);
        monter(&mut s, 0);
        monter(&mut s, 9);
        assert_eq!(s, [Preuve, Prevenir, Bloquer]);
        assert!(retirer(&mut s, 0));
        assert!(retirer(&mut s, 0));
        assert!(!retirer(&mut s, 0));
        assert_eq!(s, [Bloquer]);
        assert_eq!(a_ajouter(&s).len(), 6);
        assert!(!a_ajouter(&s).contains(&Bloquer));
    }

    /// Les textes tiennent : un geste au plus 40 colonnes, un type au plus 31, une précision au plus 33 ; les noms gardés
    /// dans le fichier sont tous différents.
    #[test]
    fn les_textes_tiennent() {
        for e in Etape::TOUTES {
            assert!(e.texte().chars().count() <= 40, "{e:?}");
            assert!(e.annulation().chars().count() <= 33, "{e:?}");
        }
        for t in Type::TOUS {
            // Le titre sert aussi de précision (« Toute la suite »), et l'éditeur y ajoute « * ».
            assert!(t.titre().chars().count() <= 31, "{t:?}");
            assert!(t.origine().chars().count() <= 33, "{t:?}");
        }
        let mut noms: Vec<&str> = Etape::TOUTES.iter().map(|e| e.nom()).collect();
        noms.extend(Type::TOUS.iter().map(|t| t.nom()));
        let n = noms.len();
        noms.sort_unstable();
        noms.dedup();
        assert_eq!(noms.len(), n);
    }
}

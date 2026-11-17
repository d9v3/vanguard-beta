//! Le protocole face à un client hostile : enveloppes piégées, lots, méthodes inconnues, rythme, tailles. De faux
//! outils : seul le protocole est jugé ici.

use super::*;
use proptest::prelude::*;

struct Faux {
    appels: u32,
}

impl Outils for Faux {
    fn liste(&self) -> Value {
        json!([{ "name": "faux" }])
    }

    fn nom_ferme(&self, nom: &str) -> Option<&'static str> {
        ["faux", "gros", "refuse", "sans-teinte"]
            .into_iter()
            .find(|n| *n == nom)
    }

    fn appeler(&mut self, nom: &'static str, arguments: Option<&RawValue>) -> Result<Map<String, Value>, Code> {
        self.appels = self.appels.saturating_add(1);
        let mut m = Map::new();
        match nom {
            "faux" => {
                m.insert("teinte".into(), json!(TEINTE));
                m.insert("origine".into(), json!("vanguard"));
                m.insert("schema".into(), json!(1));
                m.insert("arguments".into(), json!(arguments.map(RawValue::get)));
            }
            "gros" => {
                m.insert("teinte".into(), json!(TEINTE));
                m.insert("texte".into(), json!("a".repeat(REPONSE_MAX)));
            }
            "sans-teinte" => {
                // Une autre clé avant elle, dans l'ordre d'insertion (`preserve_order`, que les dépendances des
                // essais activent) comme dans l'ordre alphabétique (le programme publié).
                m.insert("a".into(), json!(1));
                m.insert("teinte".into(), json!("fiable"));
                m.insert("zeta".into(), json!(2));
            }
            _ => return Err(Code::Arguments),
        }
        Ok(m)
    }
}

fn faux() -> Faux {
    Faux { appels: 0 }
}

const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"essai","version":"1"}}}"#;

/// Une session ouverte, et l'horloge qui avance d'une seconde par ligne (sous le rythme).
struct Essai {
    s: Session,
    o: Faux,
    ms: u64,
}

impl Essai {
    fn nouveau() -> Essai {
        let mut e = Essai {
            s: Session::new("0.0.0-essai", 1000),
            o: faux(),
            ms: 0,
        };
        let (r, f) = e.envoyer(INIT);
        assert!(r.get("result").is_some(), "{r}");
        assert_eq!(f, None);
        e
    }

    fn brut(&mut self, ligne: &[u8]) -> Suite {
        self.ms = self.ms.saturating_add(1000);
        self.s.traiter(ligne, self.ms, &mut self.o)
    }

    fn envoyer(&mut self, ligne: &str) -> (Value, Option<Fin>) {
        match self.brut(ligne.as_bytes()) {
            Suite::Repondre { texte, fermer } => {
                assert!(!texte.contains('\n'), "une réponse tient sur une ligne");
                (serde_json::from_str(&texte).expect("réponse en JSON"), fermer)
            }
            Suite::Rien => (Value::Null, None),
        }
    }
}

fn code_de(r: &Value) -> &str {
    r.pointer("/error/data/code").and_then(Value::as_str).unwrap_or("")
}

/// Chaque réponse porte la teinte : `_meta` d'un résultat, `data` d'une erreur.
fn teinte_de(r: &Value) -> Option<&str> {
    r.pointer("/result/_meta/vanguard~1teinte")
        .or_else(|| r.pointer("/error/data/teinte"))
        .and_then(Value::as_str)
}

#[test]
fn initialisation_puis_liste_et_appel() {
    let mut e = Essai::nouveau();
    let (r, _) = e.envoyer(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    assert_eq!(r, Value::Null, "une notification n'a pas de réponse");
    let (r, _) = e.envoyer(r#"{"jsonrpc":"2.0","id":"a","method":"tools/list"}"#);
    assert_eq!(r["id"], "a");
    assert_eq!(r["result"]["tools"][0]["name"], "faux");
    let (r, f) =
        e.envoyer(r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"faux","arguments":{"x":1}}}"#);
    assert_eq!(f, None);
    assert_eq!(r["result"]["isError"], false);
    assert_eq!(r["result"]["structuredContent"]["arguments"], r#"{"x":1}"#);
    let texte = r["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        texte.starts_with(r#"{"teinte":"non-fiable","origine":"vanguard","schema":1,"#),
        "la teinte d'abord : {texte}"
    );
    assert_eq!(e.s.appels.get("faux"), Some(&1));
    let (r, _) = e.envoyer(r#"{"jsonrpc":"2.0","id":4,"method":"ping"}"#);
    assert!(r["result"].is_object());
}

#[test]
fn la_teinte_est_posee_quoi_que_rende_l_outil() {
    let mut e = Essai::nouveau();
    let appel = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sans-teinte"}}"#;
    let Suite::Repondre { texte: ligne, .. } = e.brut(appel.as_bytes()) else {
        panic!("une réponse attendue");
    };
    let r: Value = serde_json::from_str(&ligne).unwrap();
    assert_eq!(r["result"]["structuredContent"]["teinte"], TEINTE);
    let texte = r["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(texte.starts_with(r#"{"teinte":"non-fiable""#), "{texte}");
    // Dans la ligne écrite, `structuredContent` aussi commence par la teinte, quel que soit l'ordre de la `Map`.
    assert!(
        ligne.contains(r#""structuredContent":{"teinte":"non-fiable","a":1,"zeta":2}"#),
        "{ligne}"
    );
}

#[test]
fn avant_l_initialisation_rien_n_est_servi() {
    let mut s = Session::new("0", 100);
    let mut o = faux();
    for m in ["tools/list", "tools/call"] {
        let l = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{m}","params":{{"name":"faux"}}}}"#);
        let Suite::Repondre { texte, fermer } = s.traiter(l.as_bytes(), 0, &mut o) else {
            panic!("une réponse attendue");
        };
        assert!(texte.contains("non-initialise"), "{texte}");
        assert_eq!(fermer, None);
    }
    assert_eq!(o.appels, 0);
}

#[test]
fn une_seconde_initialisation_est_refusee() {
    let mut e = Essai::nouveau();
    let (r, f) = e.envoyer(INIT);
    assert_eq!(code_de(&r), "deja-initialise");
    assert_eq!(f, None);
}

#[test]
fn initialize_sans_ses_champs_est_refuse() {
    let mut s = Session::new("0", 100);
    let Suite::Repondre { texte, .. } = s.traiter(
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        0,
        &mut faux(),
    ) else {
        panic!("une réponse attendue");
    };
    assert!(texte.contains("parametres"), "{texte}");
}

#[test]
fn seule_la_liste_fermee_des_outils_est_appelee() {
    let mut e = Essai::nouveau();
    for nom in ["ecrire", "FAUX", "faux ", "../faux", ""] {
        let l = json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":nom}}).to_string();
        let (r, f) = e.envoyer(&l);
        assert_eq!(code_de(&r), "outil-inconnu", "{nom}");
        assert_eq!(f, None);
    }
    assert_eq!(e.o.appels, 0);
    assert!(e.s.appels.is_empty());
}

#[test]
fn arguments_refuses_par_l_outil() {
    let mut e = Essai::nouveau();
    let (r, f) = e.envoyer(r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"refuse"}}"#);
    assert_eq!(code_de(&r), "arguments");
    assert_eq!(r["error"]["code"], -32602);
    assert_eq!(f, None);
    assert!(e.s.appels.is_empty(), "un appel refusé n'est pas compté réussi");
}

#[test]
fn une_reponse_trop_grande_est_refusee() {
    let mut e = Essai::nouveau();
    let (r, f) = e.envoyer(r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"gros"}}"#);
    assert_eq!(code_de(&r), "reponse-trop-grande");
    assert_eq!(f, None);
}

#[test]
fn enveloppes_piegees_refusees_et_session_fermee() {
    let piegees: &[(&str, &str)] = &[
        ("{", "json"),
        ("nul", "json"),
        (r#"{"jsonrpc":"2.0","id":1,"method":"ping"} {}"#, "json"),
        (r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#, "lot"),
        ("[]", "lot"),
        ("42", "enveloppe"),
        (r#""ping""#, "enveloppe"),
        (r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#, "enveloppe"),
        (r#"{"id":1,"method":"ping"}"#, "enveloppe"),
        (r#"{"jsonrpc":"2.0","id":1}"#, "enveloppe"),
        (r#"{"jsonrpc":"2.0","id":1,"method":"ping","x":1}"#, "enveloppe"),
        (
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/list"}"#,
            "enveloppe",
        ),
        (r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#, "enveloppe"),
        (r#"{"jsonrpc":"2.0","id":1.5,"method":"ping"}"#, "enveloppe"),
        (r#"{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}"#, "enveloppe"),
        (r#"{"jsonrpc":"2.0","id":"","method":"ping"}"#, "enveloppe"),
        (r#"{"jsonrpc":"2.0","id":"a\nb","method":"ping"}"#, "enveloppe"),
        // Un id texte est en ASCII visible : ni sens d'écriture inversé, ni séparateur de ligne, ni blanc.
        (
            "{\"jsonrpc\":\"2.0\",\"id\":\"\u{202e} x\",\"method\":\"ping\"}",
            "enveloppe",
        ),
        (r#"{"jsonrpc":"2.0","id":"\u202Ex","method":"ping"}"#, "enveloppe"),
        (
            "{\"jsonrpc\":\"2.0\",\"id\":\"a\u{2028}b\",\"method\":\"ping\"}",
            "enveloppe",
        ),
        (r#"{"jsonrpc":"2.0","id":"a b","method":"ping"}"#, "enveloppe"),
        (r#"{"jsonrpc":"2.0","id":"é","method":"ping"}"#, "enveloppe"),
        (r#"{"jsonrpc":"2.0","id":1,"method":7}"#, "enveloppe"),
    ];
    for (ligne, attendu) in piegees {
        let mut e = Essai::nouveau();
        let (r, f) = e.envoyer(ligne);
        assert_eq!(code_de(&r), *attendu, "{ligne} : {r}");
        assert_eq!(teinte_de(&r), Some(TEINTE), "{ligne}");
        assert_eq!(f, Some(Fin::Hostile), "{ligne}");
        assert!(e.s.hostile);
    }
    let long = format!(r#"{{"jsonrpc":"2.0","id":"{}","method":"ping"}}"#, "a".repeat(65));
    let (r, f) = Essai::nouveau().envoyer(&long);
    assert_eq!((code_de(&r), f), ("enveloppe", Some(Fin::Hostile)));
    // 64 caractères visibles, la borne exacte : accepté et renvoyé tel quel.
    let id = format!("{}~", "A-z.:_9".repeat(9));
    let borne = format!(r#"{{"jsonrpc":"2.0","id":"{id}","method":"ping"}}"#);
    let (r, f) = Essai::nouveau().envoyer(&borne);
    assert_eq!((r["id"].as_str(), f), (Some(id.as_str()), None), "{r}");
}

#[test]
fn une_reponse_recue_n_est_pas_repondue_par_son_id() {
    // JSON-RPC interdit de répondre à une réponse : l'erreur porte l'id null.
    for ligne in [
        r#"{"jsonrpc":"2.0","id":7,"result":{}}"#,
        r#"{"jsonrpc":"2.0","id":7,"error":{"code":1,"message":"x"}}"#,
        r#"{"jsonrpc":"2.0","id":7}"#,
    ] {
        let (r, f) = Essai::nouveau().envoyer(ligne);
        assert_eq!(code_de(&r), "enveloppe", "{ligne}");
        assert_eq!(r["id"], Value::Null, "{ligne}");
        assert_eq!(f, Some(Fin::Hostile));
    }
}

#[test]
fn json_profond_refuse_sans_deborder_la_pile() {
    let profond = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    let (r, f) = Essai::nouveau().envoyer(&profond);
    assert_eq!(code_de(&r), "json");
    assert_eq!(f, Some(Fin::Hostile));
    let objet = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}}"#,
        "{\"a\":".repeat(5000)
    );
    let (r, _) = Essai::nouveau().envoyer(&objet);
    assert_eq!(code_de(&r), "json");
}

#[test]
fn encodage_faux_refuse() {
    for brut in [
        &b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\0"[..],
        b"\xff\xfe{}",
        b"{\"a\":\"\xc3\x28\"}",
    ] {
        let mut e = Essai::nouveau();
        let Suite::Repondre { texte, fermer } = e.brut(brut) else {
            panic!("une réponse attendue");
        };
        assert!(texte.contains("\"encodage\""), "{texte}");
        assert_eq!(fermer, Some(Fin::Hostile));
    }
}

#[test]
fn champs_inconnus_des_parametres_refuses() {
    let mut e = Essai::nouveau();
    for l in [
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"cursor":"x"}}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"faux","ecrire":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"faux","name":"gros"}}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":[]}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#,
        // Des paramètres en tableau, que serde lirait par position : refusés, comme dans le schéma publié.
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":["faux"]}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":["faux",{"x":1}]}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":[]}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":[]}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":[{"x":1}]}"#,
    ] {
        let (r, f) = e.envoyer(l);
        assert_eq!(code_de(&r), "parametres", "{l}");
        assert_eq!(f, None);
    }
    let (r, _) = e.envoyer(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"progressToken":1}}}"#);
    assert!(r["result"]["tools"].is_array(), "_meta est permis : {r}");
    assert_eq!(e.o.appels, 0);
    // `initialize` aussi : ses paramètres en tableau ne l'ouvrent pas.
    let mut s = Session::new("0", 100);
    let mut o = faux();
    let tableau = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":["2025-06-18",{},{"name":"x"}]}"#;
    let Suite::Repondre { texte, .. } = s.traiter(tableau, 0, &mut o) else {
        panic!("une réponse attendue");
    };
    assert!(texte.contains("\"parametres\""), "{texte}");
    assert!(!s.ouverte);
}

#[test]
fn demandes_inconnues_refusees_sans_fermer() {
    // Une demande bien formée reçoit son -32601 propre, sans compter : un client plus récent que la porte n'est
    // pas accusé pour avoir essayé des méthodes nouvelles.
    let mut e = Essai::nouveau();
    for i in 1..=10 {
        let (r, f) = e.envoyer(&format!(r#"{{"jsonrpc":"2.0","id":{i},"method":"shell/exec{i}"}}"#));
        assert_eq!(code_de(&r), "methode-inconnue");
        assert_eq!(r["error"]["code"], -32601);
        assert_eq!(r["id"], i);
        assert_eq!(f, None);
    }
    assert!(!e.s.hostile);
    assert_eq!(e.s.refus.get(&Code::MethodeInconnue), Some(&10));
}

#[test]
fn methodes_mcp_non_servies_ne_ferment_pas() {
    let mut e = Essai::nouveau();
    for m in MCP_NON_SERVIES {
        let (r, f) = e.envoyer(&format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{m}"}}"#));
        assert_eq!(code_de(&r), "methode-non-servie", "{m}");
        assert_eq!(f, None);
    }
    assert!(!e.s.hostile);
}

#[test]
fn notifications_inconnues_comptees_sans_reponse() {
    let mut e = Essai::nouveau();
    let (r, _) = e.envoyer(r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}"#);
    assert_eq!(r, Value::Null);
    for _ in 0..2 {
        assert_eq!(e.brut(br#"{"jsonrpc":"2.0","method":"x/y"}"#), Suite::Rien);
    }
    match e.brut(br#"{"jsonrpc":"2.0","method":"x/z"}"#) {
        Suite::Repondre { fermer, .. } => assert_eq!(fermer, Some(Fin::Hostile)),
        Suite::Rien => panic!("la troisième méthode inconnue ferme, même en notification"),
    }
}

#[test]
fn trop_vite_ferme_la_session() {
    let mut s = Session::new("0", 1000);
    let mut o = faux();
    let ping = br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
    for i in 0..u64::try_from(RYTHME).unwrap_or(0) {
        let Suite::Repondre { fermer, .. } = s.traiter(ping, i * 10, &mut o) else {
            panic!("une réponse attendue");
        };
        assert_eq!(fermer, None, "ligne {i}");
    }
    let Suite::Repondre { texte, fermer } = s.traiter(ping, 300, &mut o) else {
        panic!("une réponse attendue");
    };
    assert!(texte.contains("\"rythme\""), "{texte}");
    assert!(
        texte.contains("\"id\":1,"),
        "le refus porte l'id de la demande : {texte}"
    );
    assert_eq!(fermer, Some(Fin::Hostile));
    // Les lignes vides ne comptent pas : cent d'un trait, puis une demande, rien ne ferme.
    let mut s = Session::new("0", 1000);
    for i in 0..100u64 {
        assert_eq!(s.traiter(b"  ", i, &mut o), Suite::Rien);
    }
    let Suite::Repondre { fermer, .. } = s.traiter(ping, 100, &mut o) else {
        panic!("une réponse attendue");
    };
    assert_eq!(fermer, None);
    // Au rythme permis, rien ne ferme.
    let mut s = Session::new("0", 1000);
    for i in 0..200u64 {
        let Suite::Repondre { fermer, .. } = s.traiter(ping, i * 60, &mut o) else {
            panic!("une réponse attendue");
        };
        assert_eq!(fermer, None, "ligne {i}");
    }
}

#[test]
fn trop_de_demandes_ferme_la_session() {
    let mut s = Session::new("0", 3);
    let mut o = faux();
    let ping = br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
    let mut fins = Vec::new();
    for i in 0..4u64 {
        if let Suite::Repondre { fermer, .. } = s.traiter(ping, i * 1000, &mut o) {
            fins.push(fermer);
        }
    }
    assert_eq!(fins, [None, None, None, Some(Fin::Demandes)]);
}

#[test]
fn une_ligne_vide_ne_repond_rien() {
    let mut e = Essai::nouveau();
    assert_eq!(e.brut(b""), Suite::Rien);
}

#[test]
fn le_texte_ordonne_garde_la_teinte_en_tete() {
    let mut m = Map::new();
    m.insert("a".into(), json!(1));
    m.insert("teinte".into(), json!(TEINTE));
    m.insert("schema".into(), json!(1));
    m.insert("zz\"".into(), json!("x\ny"));
    m.insert("origine".into(), json!("vanguard"));
    let t = texte_ordonne(&m);
    assert!(
        t.starts_with(r#"{"teinte":"non-fiable","origine":"vanguard","schema":1,"#),
        "{t}"
    );
    assert_eq!(serde_json::from_str::<Value>(&t).ok(), Some(Value::Object(m)));
}

proptest! {
    /// N'importe quelles lignes : jamais de panique, chaque réponse est une ligne JSON teintée, et les faux outils ne
    /// sont appelés que par leur nom fermé.
    #[test]
    fn toute_ligne_donne_une_reponse_teintee(lignes in proptest::collection::vec(
        prop_oneof![
            proptest::collection::vec(proptest::num::u8::ANY, 0..200),
            "[ -~]{0,120}".prop_map(String::into_bytes),
            proptest::sample::select(vec![
                INIT.as_bytes().to_vec(),
                br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"faux"}}"#.to_vec(),
                br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#.to_vec(),
                br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_vec(),
            ]),
        ],
        1..30,
    )) {
        let mut s = Session::new("0", 1000);
        let mut o = faux();
        for (i, l) in lignes.iter().enumerate() {
            let ms = u64::try_from(i).unwrap_or(0).saturating_mul(1000);
            if let Suite::Repondre { texte, fermer } = s.traiter(l, ms, &mut o) {
                let r: Value = serde_json::from_str(&texte).expect("réponse en JSON");
                prop_assert_eq!(teinte_de(&r), Some(TEINTE));
                prop_assert!(texte.len() <= REPONSE_MAX);
                if fermer.is_some() {
                    break;
                }
            }
        }
    }
}

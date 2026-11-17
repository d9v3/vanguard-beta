//! La porte de lecture des assistants d'IA (src/porte_mcp/trame.rs et rpc.rs) face à n'importe quels octets : des
//! lignes découpées sous la borne, puis jugées par le protocole avec de faux outils. Jamais de panique ; chaque ligne
//! lue tient dans la borne, sans `\n` ; chaque réponse est un objet JSON-RPC 2.0 sous `REPONSE_MAX`, marqué « non
//! fiable » (`_meta` ou `error.data`) ; une session fermée ne répond plus ; un outil n'est appelé que par son nom fermé.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../src/porte_mcp/trame.rs"]
mod trame;
#[allow(dead_code)]
#[path = "../../src/porte_mcp/rpc.rs"]
mod rpc;

use rpc::{Code, Outils, REPONSE_MAX, Session, Suite, TEINTE};
use serde_json::value::RawValue;
use serde_json::{Map, Value, json};
use trame::Lu;

const MAX: usize = 4096;

struct Faux {
    appels: u32,
}

impl Outils for Faux {
    fn liste(&self) -> Value {
        json!([{ "name": "faux" }])
    }

    fn nom_ferme(&self, nom: &str) -> Option<&'static str> {
        (nom == "faux").then_some("faux")
    }

    fn appeler(&mut self, nom: &'static str, arguments: Option<&RawValue>) -> Result<Map<String, Value>, Code> {
        assert_eq!(nom, "faux");
        self.appels = self.appels.saturating_add(1);
        let mut m = Map::new();
        m.insert("teinte".into(), json!(TEINTE));
        m.insert("taille".into(), json!(arguments.map_or(0, |a| a.get().len())));
        Ok(m)
    }
}

fn verifier(texte: &str) {
    assert!(texte.len() <= REPONSE_MAX + 4096, "{}", texte.len());
    assert!(!texte.contains('\n'), "une réponse sur plusieurs lignes");
    let v: Value = serde_json::from_str(texte).expect("une réponse qui n'est pas du JSON");
    assert_eq!(v.get("jsonrpc"), Some(&json!("2.0")));
    let teinte = v
        .pointer("/error/data/teinte")
        .or_else(|| v.pointer("/result/_meta/vanguard~1teinte"));
    assert_eq!(teinte, Some(&json!(TEINTE)), "{texte}");
}

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    // Le premier octet ouvre la session (ou non) et règle l'horloge : de 0 à 255 ms entre deux lignes.
    let (reglage, reste) = octets.split_first().map_or((0, octets), |(r, x)| (*r, x));
    let pas = u64::from(reglage);
    let mut session = Session::new("0.0.0-fuzz", 50);
    let mut outils = Faux { appels: 0 };
    let mut ms = 0u64;
    if reglage & 1 == 1 {
        let init = br#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"fuzz","version":"1"}}}"#;
        let Suite::Repondre { texte, fermer } = session.traiter(init, ms, &mut outils) else {
            panic!("initialize sans réponse");
        };
        verifier(&texte);
        assert_eq!(fermer, None);
    }
    let mut lecteur = std::io::Cursor::new(reste);
    loop {
        ms = ms.saturating_add(pas);
        let suite = match trame::lire_ligne(&mut lecteur, MAX, &mut || {}) {
            Lu::Ligne(ligne) => {
                assert!(ligne.len() <= MAX && !ligne.contains(&b'\n'), "{}", ligne.len());
                session.traiter(&ligne, ms, &mut outils)
            }
            Lu::TropGrande => session.refuser(&Value::Null, Code::TropGrande),
            Lu::Fin | Lu::Coupee | Lu::Erreur => break,
        };
        if let Suite::Repondre { texte, fermer } = suite {
            verifier(&texte);
            if fermer.is_some() {
                break;
            }
        }
    }
});

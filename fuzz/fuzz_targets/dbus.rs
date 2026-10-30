//! Les messages du client D-Bus fait maison (src/machine/linux/dbus.rs) : sur le bus de la session, n'importe quel
//! programme du compte peut répondre ou envoyer un signal. Signatures imbriquées sans fin, tableaux démesurés,
//! alignements faux, variantes dans des variantes, champs d'en-tête qui mentent sur leur type.
#![no_main]

// Sans #[macro_use] : dbus.rs importe lui-même tr! et trf! (`use crate::{tr, trf}`), exportés par la cale.
#[path = "../cale/langue.rs"]
mod langue;

#[path = "../cale/ui.rs"]
mod ui;

#[path = "../cale/modele.rs"]
mod modele;

#[allow(dead_code)]
#[path = "../../src/machine/linux/dbus.rs"]
mod dbus;

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let Ok(message) = dbus::Message::decoder_si(octets, |_| true) else {
        // L'en-tête seul, le corps jamais lu (un signal qui ne répond pas à l'appel en cours).
        let _ = dbus::Message::decoder_si(octets, |_| false);
        return;
    };
    // La longueur que la connexion lit d'après les 16 premiers octets est celle du message décodé : sinon, le
    // message suivant serait lu à partir du milieu de celui-ci.
    let debut: &[u8; 16] = octets[..16].try_into().unwrap();
    assert_eq!(dbus::longueur_totale(debut), Ok(octets.len()));
    let _ = message.corps.iter().map(dbus::Valeur::textes).count();
});

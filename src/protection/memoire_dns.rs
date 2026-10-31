//! La mémoire DNS de l'ordinateur : les noms qu'il a demandés récemment, même quand la connexion est déjà fermée.
//! Windows la donne à chaque compte ; sous Linux, systemd-resolved ne la donne qu'en root ; macOS ne la montre pas.
//! Lecture seule : rien n'est vidé.

/// Les noms en mémoire, en minuscules, sans le point final. `Err` : pourquoi ils n'ont pas pu être lus, à montrer.
pub(crate) fn noms() -> Result<Vec<String>, String> {
    // Un nom que le hosts envoie nulle part (le blocage de Vanguard, ou celui de la personne) n'a mené à rien : sous
    // Windows, la mémoire DNS le garde pourtant comme demandé.
    let bloques = crate::protection::sites_bloques::noms_bloques_ici();
    let mut noms: Vec<String> = lire()?
        .into_iter()
        .map(|n| n.trim_end_matches('.').to_lowercase())
        .filter(|n| !n.is_empty() && !bloques.contains(n))
        .collect();
    noms.sort();
    noms.dedup();
    Ok(noms)
}

/// La réponse de DumpCache (systemd-resolved, protocole varlink) : les noms des entrées de chaque interface. `None` :
/// une erreur, ou une réponse qui n'en est pas une ; `Some(Err(…))` : l'erreur nommée par systemd-resolved.
#[cfg(any(target_os = "linux", test))]
fn lire_dump(reponse: &str) -> Option<Result<Vec<String>, String>> {
    let v: serde_json::Value = serde_json::from_str(reponse).ok()?;
    if let Some(erreur) = v.get("error").and_then(serde_json::Value::as_str) {
        return Some(Err(erreur.to_string()));
    }
    let noms = v
        .get("parameters")?
        .get("dump")?
        .as_array()?
        .iter()
        .filter_map(|interface| interface.get("cache")?.as_array())
        .flatten()
        .filter_map(|entree| entree.get("key")?.get("name")?.as_str().map(String::from))
        .collect();
    Some(Ok(noms))
}

#[cfg(target_os = "linux")]
fn lire() -> Result<Vec<String>, String> {
    use std::io::{Read, Write};
    const SOCKET: &str = "/run/systemd/resolve/io.systemd.Resolve.Monitor";
    let pas_de_resolved = || {
        crate::tr!(
            "pas de mémoire DNS lisible (systemd-resolved absent)",
            "no readable DNS cache (systemd-resolved missing)"
        )
        .to_string()
    };
    let en_root = || {
        crate::tr!(
            "lisible seulement en root : sudo vanguard connexions-sortantes",
            "readable only as root: sudo vanguard outbound-connections"
        )
        .to_string()
    };
    // Le socket est en 0600 sur les systemd d'avant polkit : refusé n'est pas absent.
    let mut prise = std::os::unix::net::UnixStream::connect(SOCKET).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            en_root()
        } else {
            pas_de_resolved()
        }
    })?;
    let delai = Some(std::time::Duration::from_secs(5));
    let _ = prise.set_read_timeout(delai);
    let _ = prise.set_write_timeout(delai);
    prise
        .write_all(b"{\"method\":\"io.systemd.Resolve.Monitor.DumpCache\"}\0")
        .map_err(|_| pas_de_resolved())?;
    // Une réponse varlink finit par un octet nul ; bornée à 32 Mo, une mémoire DNS en fait bien moins.
    let mut reponse = Vec::new();
    let mut morceau = vec![0u8; 65_536];
    while !reponse.ends_with(&[0]) && reponse.len() < 32 << 20 {
        match prise.read(&mut morceau) {
            Ok(0) | Err(_) => break,
            // Plus que le morceau donné : une lecture fausse, la réponse s'arrête là (et se relit incomplète).
            Ok(n) => match morceau.get(..n) {
                Some(lu) => reponse.extend_from_slice(lu),
                None => break,
            },
        }
    }
    let texte = String::from_utf8_lossy(reponse.strip_suffix(&[0]).unwrap_or(&reponse)).into_owned();
    match lire_dump(&texte) {
        Some(Ok(noms)) => Ok(noms),
        Some(Err(e)) if e.contains("Authentication") || e.contains("PermissionDenied") => Err(en_root()),
        Some(Err(e)) if e.contains("MethodNotFound") => Err(crate::tr!(
            "systemd-resolved trop ancien pour montrer sa mémoire DNS",
            "systemd-resolved too old to show its DNS cache"
        )
        .to_string()),
        Some(Err(e)) => Err(crate::ui::affichable(&e)),
        None => Err(crate::tr!(
            "réponse illisible de systemd-resolved",
            "unreadable answer from systemd-resolved"
        )
        .to_string()),
    }
}

#[cfg(windows)]
// FFI de dnsapi : DnsGetCacheDataTable et DnsFree.
#[allow(unsafe_code)]
fn lire() -> Result<Vec<String>, String> {
    use std::ffi::c_void;

    /// DNS_CACHE_ENTRY (dnsapi) : une entrée de la mémoire, chaînée à la suivante.
    #[repr(C)]
    struct Entree {
        suivante: *mut Entree,
        nom: *mut u16,
        genre: u16,
        taille: u16,
        drapeaux: u32,
    }

    #[link(name = "dnsapi")]
    unsafe extern "system" {
        fn DnsGetCacheDataTable(table: *mut *mut Entree) -> i32;
        fn DnsFree(donnees: *mut c_void, genre: u32);
    }

    const A_PLAT: u32 = 0;
    // Bien au-delà de ce que garde d'ordinaire la mémoire DNS de Windows : une borne de durée, pas un tri.
    const MAILLONS: usize = 65_536;
    let mut entree: *mut Entree = std::ptr::null_mut();
    let mut noms = Vec::new();
    // SAFETY: DnsGetCacheDataTable (fonction de dnsapi sans documentation publique, la même depuis Windows XP, que
    // ipconfig /displaydns emploie) rend une liste chaînée allouée par Windows, ou rien. Chaque entrée est lue une fois,
    // son nom (chaîne terminée par un zéro) copié, puis le nom et l'entrée rendus par DnsFree, comme le font les outils
    // qui l'emploient ; la suivante est lue avant de rendre l'entrée. Un nom n'est lu qu'à 1 024 caractères au plus,
    // la borne testée avant chaque caractère. Une boucle dans la liste ramènerait à une entrée déjà rendue : chaque
    // adresse est notée, et la lecture s'arrête avant d'en relire une, sans la toucher (toute la liste est allouée
    // avant la lecture : une entrée rendue ne peut pas reparaître sous une adresse neuve). Au-delà de MAILLONS, ou
    // après une boucle, le reste de la liste reste à Windows, non rendu.
    unsafe {
        if DnsGetCacheDataTable(&raw mut entree) == 0 {
            return Err(crate::tr!(
                "mémoire DNS illisible (Windows refuse)",
                "DNS cache unreadable (Windows refuses)"
            )
            .to_string());
        }
        let mut vues = std::collections::HashSet::new();
        while !entree.is_null() && vues.len() < MAILLONS && vues.insert(entree.addr()) {
            let suivante = (*entree).suivante;
            let nom = (*entree).nom;
            if !nom.is_null() {
                let mut fin = 0;
                while fin < 1024 && *nom.add(fin) != 0 {
                    fin += 1;
                }
                noms.push(String::from_utf16_lossy(std::slice::from_raw_parts(nom, fin)));
                DnsFree(nom.cast(), A_PLAT);
            }
            DnsFree(entree.cast(), A_PLAT);
            entree = suivante;
        }
    }
    Ok(noms)
}

#[cfg(target_os = "macos")]
fn lire() -> Result<Vec<String>, String> {
    Err(crate::tr!(
        "macOS ne montre pas sa mémoire DNS",
        "macOS does not show its DNS cache"
    )
    .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reponse_de_systemd_resolved() {
        // Réponse inventée, à la forme de DumpCache : une interface, deux entrées.
        let texte = r#"{"parameters":{"dump":[{"ifindex":2,"ifname":"wlan0","protocol":"dns","family":2,
            "cache":[{"key":{"class":1,"type":1,"name":"exemple.invalid"},"rrs":[]},
                     {"key":{"class":1,"type":28,"name":"Serveur.Exemple.invalid."}}]},
            {"protocol":"llmnr","cache":[]}]}}"#;
        assert_eq!(
            lire_dump(texte),
            Some(Ok(vec![
                "exemple.invalid".to_string(),
                "Serveur.Exemple.invalid.".to_string()
            ]))
        );
        assert_eq!(
            lire_dump(r#"{"error":"io.systemd.InteractiveAuthenticationRequired"}"#),
            Some(Err("io.systemd.InteractiveAuthenticationRequired".to_string()))
        );
        assert_eq!(lire_dump("pas du json"), None);
        assert_eq!(lire_dump(r#"{"parameters":{}}"#), None);
    }

    /// La vraie mémoire (Windows sous Wine, Linux sans root ici) : une réponse ou une raison, jamais un plantage.
    #[test]
    fn memoire_lue_ou_raison_dite() {
        match noms() {
            Ok(noms) => assert!(noms.iter().all(|n| !n.ends_with('.') && *n == n.to_lowercase())),
            Err(raison) => assert_ne!(raison, ""),
        }
    }
}

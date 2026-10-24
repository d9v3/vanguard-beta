//! Une demande HTTP/1.1 GET sur une prise Unix, pour les API locales qui n'en ont pas d'autre : le démon de Docker
//! (/var/run/docker.sock) et snapd (/run/snapd.socket). Lecture seule (GET), une demande par connexion
//! (« Connection: close »), un délai, une réponse bornée ; corps en longueur annoncée, jusqu'à la fermeture, ou par
//! morceaux (« chunked », ce que Go envoie sans longueur).
//!
//! La réponse vient d'un démon local, mais elle peut être fausse (un programme qui a pris la place de la prise) :
//! tout est borné et vérifié, une forme inattendue rend une erreur.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use crate::modele::Echec;

/// Une réponse plus grosse est refusée : la liste des conteneurs ou des images d'une grosse machine tient en
/// quelques Mo.
const REPONSE_MAX: usize = 16 << 20;
const DELAI: Duration = Duration::from_secs(10);

fn echec(e: impl Into<String>) -> Echec {
    Echec::echoue("http_unix", e)
}

/// GET `chemin` sur la prise `prise` : (code HTTP, corps). `Err` : prise injoignable (droits compris : le texte du
/// système le dit), réponse mal formée ou trop grosse.
pub(crate) fn get(prise: &Path, chemin: &str) -> Result<(u16, Vec<u8>), Echec> {
    // Le chemin vient du code de Vanguard ; rien qui coupe la ligne de demande ne doit y entrer.
    if !chemin.starts_with('/') || chemin.bytes().any(|o| o <= b' ' || o == 0x7f) {
        return Err(echec("chemin refusé"));
    }
    // La prise d'un démon du système appartient à root (ou au compte, pour un démon à lui) : une autre, posée par un
    // autre compte, n'est pas celle du démon.
    {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(prise).map_err(|e| Echec::io("http_unix/connexion", &e))?;
        // SAFETY : geteuid ne prend rien et ne peut pas échouer.
        let moi = unsafe { libc::geteuid() };
        if m.uid() != 0 && m.uid() != moi {
            return Err(echec("prise d'un autre compte"));
        }
    }
    let mut s = UnixStream::connect(prise).map_err(|e| Echec::io("http_unix/connexion", &e))?;
    s.set_read_timeout(Some(DELAI)).map_err(|e| echec(e.to_string()))?;
    s.set_write_timeout(Some(DELAI)).map_err(|e| echec(e.to_string()))?;
    // Un Host est exigé en HTTP/1.1 (Go le refuse sans) ; celui du client officiel de Docker.
    let demande = format!(
        "GET {chemin} HTTP/1.1\r\nHost: api.moby.localhost\r\nUser-Agent: Vanguard\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    s.write_all(demande.as_bytes()).map_err(|e| echec(e.to_string()))?;
    // Une échéance pour toute la réponse, pas seulement pour chaque lecture : un démon qui envoie un octet toutes les
    // neuf secondes ne retient pas Vanguard.
    let echeance = std::time::Instant::now() + DELAI;
    let mut octets = Vec::new();
    let mut tampon = vec![0u8; 64 << 10];
    loop {
        let reste = echeance.saturating_duration_since(std::time::Instant::now());
        if reste.is_zero() {
            return Err(echec("pas de réponse à temps"));
        }
        s.set_read_timeout(Some(reste)).map_err(|e| echec(e.to_string()))?;
        let n = s.read(&mut tampon).map_err(|e| echec(e.to_string()))?;
        if n == 0 {
            break;
        }
        octets.extend_from_slice(&tampon[..n]);
        if octets.len() > REPONSE_MAX {
            return Err(echec("réponse trop grosse"));
        }
    }
    lire_reponse(&octets)
}

/// Le code et le corps d'une réponse HTTP/1.x entière.
fn lire_reponse(octets: &[u8]) -> Result<(u16, Vec<u8>), Echec> {
    let fin_entete = octets
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| echec("en-tête incomplet"))?;
    let entete = std::str::from_utf8(&octets[..fin_entete]).map_err(|_| echec("en-tête illisible"))?;
    let corps = &octets[fin_entete + 4..];
    let mut lignes = entete.split("\r\n");
    let statut = lignes.next().unwrap_or_default();
    let mut mots = statut.split(' ');
    if !mots.next().is_some_and(|v| v.starts_with("HTTP/1.")) {
        return Err(echec("pas une réponse HTTP"));
    }
    let code: u16 = mots
        .next()
        .and_then(|c| c.parse().ok())
        .filter(|c| (100..600).contains(c))
        .ok_or_else(|| echec("code HTTP"))?;
    let mut longueur = None;
    let mut morceaux = false;
    for l in lignes {
        let Some((cle, valeur)) = l.split_once(':') else {
            continue;
        };
        let valeur = valeur.trim();
        if cle.eq_ignore_ascii_case("content-length") {
            longueur = Some(valeur.parse::<usize>().map_err(|_| echec("Content-Length"))?);
        } else if cle.eq_ignore_ascii_case("transfer-encoding") {
            morceaux = valeur.to_ascii_lowercase().split(',').any(|v| v.trim() == "chunked");
        }
    }
    let corps = if morceaux {
        sans_morceaux(corps)?
    } else if let Some(n) = longueur {
        corps.get(..n).ok_or_else(|| echec("corps coupé"))?.to_vec()
    } else {
        corps.to_vec()
    };
    Ok((code, corps))
}

/// Le corps d'une réponse « chunked » : des morceaux « taille en hexadécimal \r\n données \r\n », jusqu'au morceau
/// vide.
fn sans_morceaux(mut o: &[u8]) -> Result<Vec<u8>, Echec> {
    let mut corps = Vec::new();
    loop {
        let fin = o
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| echec("morceau"))?;
        let taille = std::str::from_utf8(&o[..fin]).map_err(|_| echec("morceau"))?;
        // Des extensions (« ;nom=valeur ») peuvent suivre la taille.
        let taille = taille.split(';').next().unwrap_or_default().trim();
        let n = usize::from_str_radix(taille, 16).map_err(|_| echec("taille de morceau"))?;
        o = &o[fin + 2..];
        if n == 0 {
            return Ok(corps);
        }
        let donnees = o.get(..n).ok_or_else(|| echec("morceau coupé"))?;
        if corps.len() + n > REPONSE_MAX {
            return Err(echec("réponse trop grosse"));
        }
        corps.extend_from_slice(donnees);
        o = o
            .get(n..)
            .and_then(|r| r.strip_prefix(b"\r\n"))
            .ok_or_else(|| echec("fin de morceau"))?;
    }
}

/// GET qui rend du JSON (code 200 seulement).
pub(crate) fn get_json(prise: &Path, chemin: &str) -> Result<serde_json::Value, Echec> {
    let (code, corps) = get(prise, chemin)?;
    let v: serde_json::Value = serde_json::from_slice(&corps).map_err(|_| echec("JSON illisible"))?;
    if code != 200 {
        let message = v
            .pointer("/message")
            .or_else(|| v.pointer("/result/message"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        return Err(echec(format!("HTTP {code} {}", crate::ui::affichable(message))));
    }
    Ok(v)
}

/// La prise de snapd.
pub(crate) const SNAPD: &str = "/run/snapd.socket";

/// Le résultat d'une réponse de snapd (`{"type":"sync","status-code":200,"result":…}`) ; une réponse d'erreur
/// (`"type":"error"`) ou d'une autre forme est une erreur, jamais un résultat vide.
pub(crate) fn snapd(prise: &Path, chemin: &str) -> Result<serde_json::Value, Echec> {
    let mut v = get_json(prise, chemin)?;
    if v.get("type").and_then(serde_json::Value::as_str) != Some("sync") {
        return Err(echec("réponse de snapd inattendue"));
    }
    v.get_mut("result")
        .map(serde_json::Value::take)
        .ok_or_else(|| echec("réponse de snapd sans résultat"))
}

/// Les mises à jour de snap proposées (GET /v2/find?select=refresh) : leurs noms. snapd interroge le magasin.
pub(crate) fn snaps_a_mettre_a_jour(prise: &Path) -> Result<Vec<String>, Echec> {
    let r = snapd(prise, "/v2/find?select=refresh")?;
    Ok(r.as_array()
        .ok_or_else(|| echec("liste attendue"))?
        .iter()
        .map(|s| crate::ui::affichable(s.get("name").and_then(serde_json::Value::as_str).unwrap_or("?")))
        .collect())
}

/// Les connexions établies des snaps (GET /v2/connections) : (interface, snap qui la reçoit par sa prise « plug »).
pub(crate) fn connexions_snap(prise: &Path) -> Result<Vec<(String, String)>, Echec> {
    let r = snapd(prise, "/v2/connections")?;
    Ok(r.get("established")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|c| {
            let interface = c.get("interface")?.as_str()?.to_string();
            let snap = c.get("plug")?.get("snap")?.as_str()?.to_string();
            Some((interface, snap))
        })
        .collect())
}

#[cfg(test)]
pub(super) mod essais {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;

    /// Un faux démon sur une prise Unix d'un dossier jetable : il lit la demande, la garde, et répond `reponse`
    /// (une réponse par connexion, autant que `reponses`).
    pub(crate) fn faux_demon(
        nom: &str,
        reponses: Vec<Vec<u8>>,
    ) -> (std::path::PathBuf, std::thread::JoinHandle<Vec<String>>) {
        let dossier = std::env::temp_dir().join(format!("vanguard-http-unix-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).unwrap();
        let chemin = dossier.join("demon.sock");
        let l = UnixListener::bind(&chemin).unwrap();
        let fil = std::thread::spawn(move || {
            let mut demandes = Vec::new();
            for r in reponses {
                let (mut s, _) = l.accept().unwrap();
                let mut d = Vec::new();
                let mut o = [0u8; 1];
                while !d.ends_with(b"\r\n\r\n") {
                    if s.read(&mut o).unwrap() == 0 {
                        break;
                    }
                    d.push(o[0]);
                }
                demandes.push(String::from_utf8_lossy(&d).into_owned());
                let _ = s.write_all(&r);
            }
            demandes
        });
        (chemin, fil)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reponses_lues() {
        let r = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]en trop";
        assert_eq!(lire_reponse(r).unwrap(), (200, b"[]".to_vec()));
        let m = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n[1,\r\n2;x=y\r\n2]\r\n0\r\n\r\n";
        assert_eq!(lire_reponse(m).unwrap(), (200, b"[1,2]".to_vec()));
        for faux in [
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffff\r\nab"[..],
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n[]",
            b"SSH-2.0-x\r\n\r\n",
            b"HTTP/1.1 999 Non\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n",
        ] {
            assert!(lire_reponse(faux).is_err(), "{}", String::from_utf8_lossy(faux));
        }
    }

    #[test]
    fn snapd_par_un_faux_demon() {
        let reponse =
            |json: &str| format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{json}", json.len()).into_bytes();
        let (prise, _) = essais::faux_demon(
            "snapd",
            vec![
                reponse(r#"{"type":"sync","status-code":200,"result":[{"name":"firefox"},{"name":"vlc"}]}"#),
                reponse(
                    r#"{"type":"sync","status-code":200,"result":{"established":[
                    {"interface":"camera","plug":{"snap":"zoom","plug":"camera"},"slot":{"snap":"snapd","slot":"camera"}},
                    {"interface":"home","plug":{"snap":"vlc","plug":"home"}}],"plugs":[]}}"#,
                ),
                reponse(r#"{"type":"error","status-code":500,"result":{"message":"cannot list updates"}}"#),
                reponse(r#"{"type":"sync","status-code":200,"result":[]}"#),
            ],
        );
        assert_eq!(snaps_a_mettre_a_jour(&prise).unwrap(), ["firefox", "vlc"]);
        assert_eq!(
            connexions_snap(&prise).unwrap(),
            [
                ("camera".to_string(), "zoom".to_string()),
                ("home".to_string(), "vlc".to_string())
            ]
        );
        // Une erreur de snapd (même en HTTP 200) n'est jamais « à jour ».
        assert!(snaps_a_mettre_a_jour(&prise).is_err());
        assert_eq!(snaps_a_mettre_a_jour(&prise).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn par_un_faux_demon() {
        let (prise, fil) = essais::faux_demon(
            "get",
            vec![
                b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{\"a\": true}".to_vec(),
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 23\r\n\r\n{\"message\":\"bad\\u001b\"}".to_vec(),
            ],
        );
        assert_eq!(get_json(&prise, "/version").unwrap()["a"], true);
        let e = get_json(&prise, "/x").unwrap_err().to_string();
        assert!(e.contains("HTTP 400") && !e.contains('\x1b'), "{e}");
        let demandes = fil.join().unwrap();
        assert!(
            demandes[0].starts_with("GET /version HTTP/1.1\r\nHost: "),
            "{}",
            demandes[0]
        );
        assert!(get(&prise, "/a b").is_err(), "espace dans le chemin");
        assert!(get(&prise, "x").is_err());
    }
}

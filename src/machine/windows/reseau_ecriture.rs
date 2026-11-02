//! Les actes du réseau du processus élevé (`vanguard:hosts-ecrire`, `vanguard:dns-auto`, `vanguard:dns-serveurs`,
//! grammaire de `gestes.rs`), faits sans PowerShell.
//!
//! Le hosts : le fichier préparé par Vanguard non élevé est lu ici en mémoire (ni lien, ni tube, 1 Mio au plus), avec
//! le hosts ; les deux empreintes de la ligne sont revérifiées, la différence rejugée (`gestes::verifier_hosts` : hors
//! du bloc de Vanguard, seules des lignes mises en commentaire ; dans le bloc, que des « 0.0.0.0 nom » et « :: nom »,
//! jamais un nom protégé), montrée avant l'accord, puis rejugée encore au moment d'écrire. L'écriture passe par un
//! fichier temporaire du dossier etc (que seul un administrateur écrit), puis ReplaceFileW, qui remplace le hosts d'un
//! coup en gardant ses droits et sa copie d'avant (hosts.vanguard-AAAAMMJJ-HHMMSS, rendue comme valeur d'avant).
//!
//! Le DNS d'une carte : la carte doit être dans la liste de Windows (GetAdaptersAddresses), les serveurs dans la liste
//! fermée (`gestes::RESOLVEURS`) ou être la valeur d'avant que ce processus a lui-même notée en la remplaçant
//! (`gestes::DNS_AVANT_CLE`). Écrit par SetInterfaceDnsSettings, relu dans le registre, puis le cache DNS vidé.

use std::ffi::c_void;
use std::io::Write as _;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY};

use super::corrections::{Resultat, avant_notable};
use crate::machine::gestes::{self, Acte, CoteDns, DnsServeurs, GuidReseau, HostsEcrire};
use crate::modele::Echec;
use crate::ui::{tr, trf};

/// Fait un acte du réseau ; `None` : l'acte n'en est pas un.
pub(super) fn faire_acte(acte: &Acte) -> Option<Resultat> {
    Some(match acte {
        Acte::HostsEcrire(h) => ecrire_hosts(h),
        Acte::DnsAuto(g) => dns(&DnsServeurs {
            guid: *g,
            v4: CoteDns::Vider,
            v6: CoteDns::Vider,
        }),
        Acte::DnsServeurs(d) => dns(d),
        _ => return None,
    })
}

// --------------------------------------------------------------- le hosts

/// Le hosts de ce Windows, sous le System32 que Windows donne (jamais la variable SystemRoot).
fn chemin_hosts() -> PathBuf {
    crate::commande::dossier_systeme().join(r"drivers\etc\hosts")
}

/// Lit un fichier du hosts : absent, il est vide (un hosts peut manquer) ; un lien, un tube ou plus de 1 Mio, refusé.
fn lire(chemin: &Path) -> Result<Vec<u8>, Echec> {
    // Un octet de plus que la borne : `verifier_hosts` dit « trop gros » au lieu d'une erreur de lecture.
    let max = u64::try_from(gestes::HOSTS_MAX).unwrap_or(u64::MAX).saturating_add(1);
    match crate::socle::lire_ordinaire(chemin, max) {
        Ok(o) => Ok(o),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(Echec::io("reseau/hosts-lire", &e).detail(crate::ui::affichable(&chemin.to_string_lossy()))),
    }
}

/// Le fichier préparé et le hosts lus, la différence jugée : ce que la fenêtre montre, ou la raison du refus.
fn juger(h: &HostsEcrire) -> Result<(Vec<u8>, Vec<u8>, gestes::DiffHosts), Echec> {
    let hosts = lire(&chemin_hosts())?;
    let max = u64::try_from(gestes::HOSTS_MAX).unwrap_or(u64::MAX).saturating_add(1);
    // Absent ou remplacé par autre chose qu'un fichier : changé depuis que Vanguard l'a écrit.
    let Ok(prepare) = crate::socle::lire_ordinaire(Path::new(&h.chemin), max) else {
        return Err(refus(&gestes::RefusHosts::PrepareChange));
    };
    let diff = gestes::verifier_hosts(h, &prepare, &hosts).map_err(|r| refus(&r))?;
    Ok((prepare, hosts, diff))
}

/// Un refus du hosts, dit dans la langue de l'interface.
fn refus(r: &gestes::RefusHosts) -> Echec {
    Echec::refuse("reseau/hosts", crate::protection::sites_bloques::refus_hosts(r))
}

/// Ce que la fenêtre élevée montre avant l'accord : la différence, lue et jugée ici. `Err` : la raison du refus ; la
/// liste entière est alors refusée sans rien demander.
pub(super) fn montrer_hosts(h: &HostsEcrire) -> Result<Vec<String>, Echec> {
    juger(h).map(|(_, _, d)| crate::protection::sites_bloques::lignes_du_diff(&d))
}

/// Écrit le fichier préparé à la place du hosts, s'il est encore celui qui a été montré et que le hosts n'a pas bougé.
fn ecrire_hosts(h: &HostsEcrire) -> Resultat {
    // Relu et rejugé au moment d'écrire : l'égalité des empreintes garantit les octets montrés avant l'accord.
    let (prepare, hosts, diff) = match juger(h) {
        Ok(j) => j,
        Err(raison) => return Resultat::echec(None, raison.to_string()),
    };
    if prepare == hosts {
        return Resultat::rien(
            tr!("le fichier hosts est déjà ainsi", "the hosts file is already like this").to_string(),
        );
    }
    let cible = chemin_hosts();
    let Some(dossier) = cible.parent().map(Path::to_path_buf) else {
        return Resultat::echec(
            None,
            tr!("dossier du hosts introuvable", "hosts folder not found").to_string(),
        );
    };
    let date = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let copie = libre(&dossier, &format!("hosts.vanguard-{date}"));
    let temporaire = libre(&dossier, &format!("hosts.vanguard-nouveau-{}", std::process::id()));
    if let Err(e) = ecrire_temporaire(&temporaire, &prepare) {
        let _ = std::fs::remove_file(&temporaire);
        return Resultat::echec(
            None,
            trf!("fichier temporaire pas écrit : {e}", "temporary file not written: {e}"),
        );
    }
    let fait = if hosts.is_empty() && !cible.exists() {
        // Pas de hosts à remplacer : le nouveau prend sa place (le dossier etc n'est écrit que par un administrateur).
        std::fs::rename(&temporaire, &cible).map_err(|e| Echec::ecriture("reseau/hosts-remplacer", &e))
    } else {
        remplacer(&cible, &temporaire, &copie)
    };
    let _ = std::fs::remove_file(&temporaire);
    if let Err(e) = fait {
        return Resultat::echec(
            None,
            trf!(
                "le fichier hosts n'a pas été remplacé ({e}) : il est resté tel quel",
                "the hosts file was not replaced ({e}): it was left as it was"
            ),
        );
    }
    // Relu : seul ce qui est sur le disque compte.
    match lire(&cible) {
        Ok(relu) if relu == prepare => {}
        _ => {
            return Resultat::echec(
                Some(avant_notable(&copie.to_string_lossy())),
                tr!(
                    "le fichier hosts relu n'est pas celui qui a été préparé : un autre programme l'a changé juste après",
                    "the hosts file read back is not the one prepared: another program changed it right after"
                )
                .to_string(),
            );
        }
    }
    vider_cache_dns();
    let mut r = Resultat::fait(avant_notable(&if hosts.is_empty() && !copie.exists() {
        tr!("aucun fichier hosts", "no hosts file").to_string()
    } else {
        trf!("copie gardée : {}", "copy kept: {}", copie.to_string_lossy())
    }));
    r.raison = trf!(
        "{} ligne(s) mise(s) en commentaire, {} site(s) bloqué(s) en plus, {} débloqué(s)",
        "{} line(s) commented out, {} site(s) newly blocked, {} unblocked",
        diff.commentees.len(),
        diff.ajoutes.len(),
        diff.retires.len()
    );
    r
}

/// Un nom libre dans `dossier` : `nom`, ou `nom-2`, `nom-3`… (deux écritures dans la même seconde).
fn libre(dossier: &Path, nom: &str) -> PathBuf {
    let mut chemin = dossier.join(nom);
    let mut n = 2u32;
    while chemin.exists() && n < 100 {
        chemin = dossier.join(format!("{nom}-{n}"));
        n = n.saturating_add(1);
    }
    chemin
}

/// Le nouveau hosts, écrit dans un fichier qui n'existait pas (jamais un fichier posé d'avance), puis mis sur le disque.
fn ecrire_temporaire(chemin: &Path, octets: &[u8]) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(chemin)?;
    f.write_all(octets)?;
    f.sync_all()
}

fn large(chemin: &Path) -> Vec<u16> {
    chemin.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// ReplaceFileW : le hosts devient le fichier temporaire, l'ancien est renommé en `copie`. Windows rouvre le hosts dès
/// que son dossier change, et un antivirus le lit : partagé ailleurs, l'échange est refait (dix fois, 300 ms).
// FFI de kernel32 : ReplaceFileW.
#[allow(unsafe_code)]
fn remplacer(cible: &Path, temporaire: &Path, copie: &Path) -> Result<(), Echec> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn ReplaceFileW(
            remplace: *const u16,
            remplacant: *const u16,
            copie: *const u16,
            drapeaux: u32,
            exclure: *mut c_void,
            reserve: *mut c_void,
        ) -> i32;
    }
    const REPLACEFILE_WRITE_THROUGH: u32 = 0x1;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    const ERROR_UNABLE_TO_REMOVE_REPLACED: i32 = 1175;
    const ERROR_UNABLE_TO_MOVE_REPLACEMENT_2: i32 = 1177;
    let (c, t, s) = (large(cible), large(temporaire), large(copie));
    let mut derniere = String::new();
    for _ in 0..10 {
        // SAFETY: les trois chemins sont des chaînes UTF-16 terminées par un zéro, vivantes pendant l'appel ; les deux
        // pointeurs réservés sont nuls, comme la documentation l'exige.
        let ok = unsafe {
            ReplaceFileW(
                c.as_ptr(),
                t.as_ptr(),
                s.as_ptr(),
                REPLACEFILE_WRITE_THROUGH,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok != 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        derniere = e.to_string();
        match e.raw_os_error() {
            Some(ERROR_SHARING_VIOLATION | ERROR_UNABLE_TO_REMOVE_REPLACED) => {
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
            Some(ERROR_UNABLE_TO_MOVE_REPLACEMENT_2) => {
                // L'ancien hosts porte déjà le nom de la copie et le nouveau n'a pas pris sa place : l'ancien revient.
                let remis = std::fs::rename(copie, cible).is_ok() || std::fs::copy(copie, cible).is_ok();
                return Err(Echec::echoue(
                    "reseau/hosts-remplacer",
                    if remis {
                        derniere
                    } else {
                        trf!(
                            "{derniere} ; le hosts manque, sa copie est {}",
                            "{derniere}; the hosts file is missing, its copy is {}",
                            copie.to_string_lossy()
                        )
                    },
                ));
            }
            _ => return Err(Echec::echoue("reseau/hosts-remplacer", derniere)),
        }
    }
    Err(Echec::echoue("reseau/hosts-remplacer", derniere))
}

/// DnsFlushResolverCache de dnsapi.dll, chargée à la demande depuis System32 seulement (une fausse DLL posée à côté de
/// Vanguard ne passe pas). Sous Wine, non appelée. Un cache qui ne se vide pas n'annule rien : les noms changés
/// expirent d'eux-mêmes en quelques minutes.
// FFI de kernel32 : LoadLibraryExW et GetProcAddress, le pointeur rendu changé en fonction typée (transmute).
#[allow(unsafe_code)]
fn vider_cache_dns() {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryExW(nom: *const u16, fichier: *mut c_void, drapeaux: u32) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, nom: *const u8) -> *mut c_void;
        fn FreeLibrary(module: *mut c_void) -> i32;
    }
    type Vider = unsafe extern "system" fn() -> i32;
    const CHERCHER_DANS_SYSTEM32: u32 = 0x800;
    if crate::journal::sous_wine() {
        return;
    }
    let nom: Vec<u16> = "dnsapi.dll\0".encode_utf16().collect();
    // SAFETY: le nom de la DLL et celui de la fonction sont terminés par un zéro ; le pointeur rendu est vérifié non
    // nul avant d'être converti à la signature de DnsFlushResolverCache (aucun paramètre, BOOL rendu) ; le module
    // n'est libéré qu'une fois, après l'appel.
    unsafe {
        let module = LoadLibraryExW(nom.as_ptr(), std::ptr::null_mut(), CHERCHER_DANS_SYSTEM32);
        if module.is_null() {
            return;
        }
        let fonction = GetProcAddress(module, c"DnsFlushResolverCache".as_ptr().cast());
        if !fonction.is_null() {
            let vider = std::mem::transmute::<*mut c_void, Vider>(fonction);
            vider();
        }
        FreeLibrary(module);
    }
}

// --------------------------------------------------------------- le DNS d'une carte

const TCPIP4: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
const TCPIP6: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces";

/// La valeur NameServer d'une carte pour une famille ; vide si elle manque (automatique). `None` : illisible.
fn name_server(guid: GuidReseau, v6: bool) -> Option<String> {
    let cle = format!("{}\\{}", if v6 { TCPIP6 } else { TCPIP4 }, guid.texte());
    let k = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(&cle, KEY_QUERY_VALUE | KEY_WOW64_64KEY)
        .ok();
    match k {
        Some(k) => match k.get_value::<String, _>("NameServer") {
            Ok(v) => Some(v),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(String::new()),
            Err(_) => None,
        },
        // Pas de clé IPv6 pour une carte sans IPv6 : rien de réglé.
        None if v6 => Some(String::new()),
        None => None,
    }
}

/// Une valeur NameServer réécrite comme une ligne l'écrit (« ip,ip », adresses canoniques) ; `None` si une adresse ne
/// se lit pas.
fn canonique(v: &str) -> Option<String> {
    v.split([',', ' ', ';'])
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<std::net::IpAddr>().ok().map(|ip| ip.to_string()))
        .collect::<Option<Vec<_>>>()
        .map(|l| l.join(","))
}

/// Le nom de la valeur notée d'une carte et d'une famille, dans `gestes::DNS_AVANT_CLE`.
fn nom_note(guid: GuidReseau, v6: bool) -> String {
    format!("{} {}", guid.texte(), if v6 { "v6" } else { "v4" })
}

fn lire_note(guid: GuidReseau, v6: bool) -> Option<String> {
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(gestes::DNS_AVANT_CLE, KEY_QUERY_VALUE | KEY_WOW64_64KEY)
        .ok()?
        .get_value::<String, _>(nom_note(guid, v6))
        .ok()
}

fn noter(guid: GuidReseau, v6: bool, valeur: &str) -> std::io::Result<()> {
    let (k, _) = RegKey::predef(HKEY_LOCAL_MACHINE)
        .create_subkey_with_flags(gestes::DNS_AVANT_CLE, KEY_SET_VALUE | KEY_WOW64_64KEY)?;
    k.set_value(nom_note(guid, v6), &valeur.to_string())
}

/// Les serveurs DNS d'une carte : rejugés ici (carte connue, serveurs de la liste ou valeur d'avant notée), écrits,
/// relus, puis le cache vidé. La valeur d'avant (« v4|v6 ») est rendue.
fn dns(d: &DnsServeurs) -> Resultat {
    let guid = d.guid.texte();
    let Some(cartes) = super::cartes::cartes() else {
        return Resultat::echec(
            None,
            tr!(
                "la liste des cartes réseau ne se lit pas : rien n'est changé",
                "the network adapter list cannot be read: nothing is changed"
            )
            .to_string(),
        );
    };
    if !cartes.iter().any(|c| c.guid.eq_ignore_ascii_case(&guid)) {
        return Resultat::echec(
            None,
            trf!(
                "carte réseau inconnue ({guid}) : rien n'est changé",
                "unknown network adapter ({guid}): nothing is changed"
            ),
        );
    }
    let (Some(avant4), Some(avant6)) = (name_server(d.guid, false), name_server(d.guid, true)) else {
        return Resultat::echec(
            None,
            tr!(
                "les serveurs DNS de la carte ne se lisent pas : rien n'est changé",
                "the adapter's DNS servers cannot be read: nothing is changed"
            )
            .to_string(),
        );
    };
    let avant = avant_notable(&format!("{avant4}|{avant6}"));
    let mut ecrits = 0u32;
    for (cote, v6, actuel) in [(&d.v4, false, &avant4), (&d.v6, true, &avant6)] {
        let Some(voulu) = cote.valeur() else { continue };
        // Hors de la liste fermée : seulement la valeur d'avant que ce processus a notée en la remplaçant.
        if cote.hors_liste() && lire_note(d.guid, v6).as_deref() != Some(voulu.as_str()) {
            return Resultat::echec(
                Some(avant),
                trf!(
                    "{voulu} n'est pas un serveur DNS de la liste de Vanguard ni la valeur d'avant notée pour cette carte : refusé",
                    "{voulu} is neither a DNS server from Vanguard's list nor the previous value noted for this adapter: refused"
                ),
            );
        }
        let actuel_canonique = canonique(actuel);
        if actuel_canonique.as_deref() == Some(voulu.as_str()) {
            continue;
        }
        // Remplacer une valeur hors liste (la box, le DNS de l'entreprise) par un serveur de la liste : elle est notée
        // d'abord, pour pouvoir la remettre. Pas en remettant en automatique (réparer un détournement), ni quand elle
        // ne se lit pas comme des adresses.
        if matches!(cote, CoteDns::Serveurs(_))
            && let Some(a) = actuel_canonique.filter(|a| !a.is_empty())
            && a.split(',').any(|ip| !gestes::RESOLVEURS.contains(&ip))
            && let Err(e) = noter(d.guid, v6, &a)
        {
            return Resultat::echec(
                Some(avant),
                trf!(
                    "la valeur d'avant ({a}) n'a pas pu être notée ({e}) : rien n'est changé, pour pouvoir la remettre",
                    "the previous value ({a}) could not be noted ({e}): nothing is changed, so it can be restored"
                ),
            );
        }
        if let Err(e) = poser(d.guid, v6, &voulu) {
            return Resultat::echec(Some(avant), e.to_string());
        }
        // Relu : seul le registre de Windows compte.
        let relu = name_server(d.guid, v6).and_then(|v| canonique(&v));
        if relu.as_deref() != Some(voulu.as_str()) {
            return Resultat::echec(
                Some(avant),
                trf!(
                    "relu après l'écriture : {} au lieu de {voulu}",
                    "read back after writing: {} instead of {voulu}",
                    relu.unwrap_or_else(|| tr!("illisible", "unreadable").to_string())
                ),
            );
        }
        ecrits = ecrits.saturating_add(1);
    }
    if ecrits == 0 {
        return Resultat::rien(
            tr!(
                "les serveurs DNS de la carte sont déjà ainsi",
                "the adapter's DNS servers are already like this"
            )
            .to_string(),
        );
    }
    vider_cache_dns();
    Resultat::fait(avant)
}

/// DNS_INTERFACE_SETTINGS (netioapi.h), version 1.
#[repr(C)]
struct ReglagesDns {
    version: u32,
    drapeaux: u64,
    domaine: *mut u16,
    serveurs: *mut u16,
    recherche: *mut u16,
    enregistrement: u32,
    nom_de_carte: u32,
    llmnr: u32,
    requete_nom_de_carte: u32,
    serveurs_profil: *mut u16,
}

/// GUID (guiddef.h).
#[repr(C)]
#[derive(Clone, Copy)]
struct Guid {
    d1: u32,
    d2: u16,
    d3: u16,
    d4: [u8; 8],
}

fn guid_windows(g: GuidReseau) -> Guid {
    let n = g.0;
    let bas = u64::try_from(n & u128::from(u64::MAX)).unwrap_or_default();
    Guid {
        d1: u32::try_from(n >> 96).unwrap_or_default(),
        d2: u16::try_from((n >> 80) & 0xFFFF).unwrap_or_default(),
        d3: u16::try_from((n >> 64) & 0xFFFF).unwrap_or_default(),
        d4: bas.to_be_bytes(),
    }
}

/// Pose NameServer d'une famille par SetInterfaceDnsSettings (iphlpapi.dll, Windows 10 2004 et après), qui prévient le
/// client DNS ; vide : les serveurs du DHCP. Sans elle (Windows plus ancien, Wine), le registre est écrit directement,
/// ce que le client DNS prend au prochain renouvellement de la carte.
// FFI de kernel32 (LoadLibraryExW, GetProcAddress, le pointeur changé en fonction typée) et d'iphlpapi.
#[allow(unsafe_code)]
fn poser(guid: GuidReseau, v6: bool, valeur: &str) -> Result<(), Echec> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryExW(nom: *const u16, fichier: *mut c_void, drapeaux: u32) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, nom: *const u8) -> *mut c_void;
        fn FreeLibrary(module: *mut c_void) -> i32;
    }
    type Poser = unsafe extern "system" fn(Guid, *const ReglagesDns) -> u32;
    const CHERCHER_DANS_SYSTEM32: u32 = 0x800;
    const VERSION1: u32 = 1;
    const DNS_SETTING_IPV6: u64 = 0x1;
    const DNS_SETTING_NAMESERVER: u64 = 0x2;

    let mut texte: Vec<u16> = valeur.encode_utf16().chain(Some(0)).collect();
    let reglages = ReglagesDns {
        version: VERSION1,
        drapeaux: DNS_SETTING_NAMESERVER | if v6 { DNS_SETTING_IPV6 } else { 0 },
        domaine: std::ptr::null_mut(),
        serveurs: texte.as_mut_ptr(),
        recherche: std::ptr::null_mut(),
        enregistrement: 0,
        nom_de_carte: 0,
        llmnr: 0,
        requete_nom_de_carte: 0,
        serveurs_profil: std::ptr::null_mut(),
    };
    let code = if crate::journal::sous_wine() {
        None
    } else {
        let nom: Vec<u16> = "iphlpapi.dll\0".encode_utf16().collect();
        // SAFETY: le nom de la DLL et celui de la fonction sont terminés par un zéro ; le pointeur rendu est vérifié
        // non nul avant d'être converti à la signature de netioapi.h (GUID par valeur, structure constante → DWORD) ;
        // la structure, de la disposition de DNS_INTERFACE_SETTINGS (test de taille), et la chaîne qu'elle désigne
        // vivent pendant l'appel, qui ne garde aucun pointeur ; le module n'est libéré qu'une fois, après l'appel.
        unsafe {
            let module = LoadLibraryExW(nom.as_ptr(), std::ptr::null_mut(), CHERCHER_DANS_SYSTEM32);
            if module.is_null() {
                None
            } else {
                let fonction = GetProcAddress(module, c"SetInterfaceDnsSettings".as_ptr().cast());
                let code = if fonction.is_null() {
                    None
                } else {
                    let poser = std::mem::transmute::<*mut c_void, Poser>(fonction);
                    Some(poser(guid_windows(guid), &raw const reglages))
                };
                FreeLibrary(module);
                code
            }
        }
    };
    match code {
        Some(0) => Ok(()),
        Some(c) => Err(Echec::echoue(
            "reseau/dns-poser",
            trf!(
                "Windows a refusé les serveurs DNS (SetInterfaceDnsSettings, code {c})",
                "Windows refused the DNS servers (SetInterfaceDnsSettings, code {c})"
            ),
        )),
        None => {
            let cle = format!("{}\\{}", if v6 { TCPIP6 } else { TCPIP4 }, guid.texte());
            RegKey::predef(HKEY_LOCAL_MACHINE)
                .open_subkey_with_flags(&cle, KEY_SET_VALUE | KEY_WOW64_64KEY)
                .and_then(|k| k.set_value("NameServer", &valeur.to_string()))
                .map_err(|e| Echec::ecriture("reseau/dns-registre", &e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La disposition de DNS_INTERFACE_SETTINGS en 64 bits : 64 octets, NameServer à 24.
    #[test]
    fn la_structure_du_dns_a_la_taille_de_windows() {
        if cfg!(target_pointer_width = "64") {
            assert_eq!(std::mem::size_of::<ReglagesDns>(), 64);
            assert_eq!(std::mem::offset_of!(ReglagesDns, serveurs), 24);
            assert_eq!(std::mem::offset_of!(ReglagesDns, serveurs_profil), 56);
        }
        assert_eq!(std::mem::size_of::<Guid>(), 16);
        let g = guid_windows(GuidReseau::lire("{4D36E972-E325-11CE-BFC1-08002BE10318}").unwrap());
        assert_eq!((g.d1, g.d2, g.d3), (0x4D36_E972, 0xE325, 0x11CE));
        assert_eq!(g.d4, [0xBF, 0xC1, 0x08, 0x00, 0x2B, 0xE1, 0x03, 0x18]);
    }

    #[test]
    fn name_server_canonique() {
        assert_eq!(canonique("").as_deref(), Some(""));
        assert_eq!(canonique("1.1.1.1 1.0.0.1").as_deref(), Some("1.1.1.1,1.0.0.1"));
        assert_eq!(
            canonique("2620:00FE::FE,2620:fe::9").as_deref(),
            Some("2620:fe::fe,2620:fe::9")
        );
        assert_eq!(canonique("box.lan"), None);
    }
}

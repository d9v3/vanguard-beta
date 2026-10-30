//! Parcours « L'imprimante ne marche pas » : le service d'impression tourne-t-il, l'imprimante est-elle installée,
//! en pause, joignable sur le réseau, des impressions sont-elles bloquées dans la file. Linux et macOS : CUPS
//! (lpstat) ; Windows : le spouleur et Get-Printer. Vider la file, réactiver l'imprimante ou relancer le service :
//! montré, puis fait après accord.

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use super::{Etat, a_savoir, fait, question, verifications};
use crate::ui::*;

/// Une imprimante installée.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct Imprimante {
    pub nom: String,
    pub en_pause: bool,
    /// Adresse réseau de l'imprimante (« 192.168.1.20 », « imprimante.local ») ; vide : USB ou inconnue.
    pub hote: String,
    pub en_attente: usize,
    pub par_defaut: bool,
}

/// L'hôte d'une adresse d'imprimante : « ipp://192.168.1.20/ipp/print », « socket://imprimante.local:9100 » ; rien
/// pour l'USB ou une adresse découverte (dnssd://).
#[cfg_attr(windows, allow(dead_code))]
fn hote(uri: &str) -> String {
    let Some((schema, reste)) = uri.split_once("://") else {
        return String::new();
    };
    if !["ipp", "ipps", "http", "https", "socket", "lpd"].contains(&schema) {
        return String::new();
    }
    let hote = reste.split(['/', '?']).next().unwrap_or_default();
    let hote = hote.rsplit('@').next().unwrap_or(hote);
    // « [fe80::1]:631 » : IPv6 entre crochets ; sinon « hôte:port ».
    match hote.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or_default().to_string(),
        None => hote.split(':').next().unwrap_or_default().to_string(),
    }
}

/// `lpstat -p -d -v -o`, en anglais (LC_ALL=C) : imprimantes, état, adresse, impressions en attente.
#[cfg_attr(windows, allow(dead_code))]
fn imprimantes_lpstat(texte: &str) -> Vec<Imprimante> {
    let mut liste: Vec<Imprimante> = Vec::new();
    let defaut = texte
        .lines()
        .find_map(|l| l.strip_prefix("system default destination:"))
        .map(|d| d.trim().to_string());
    for l in texte.lines() {
        if let Some(reste) = l.strip_prefix("printer ") {
            let nom = reste.split_whitespace().next().unwrap_or_default().to_string();
            liste.push(Imprimante {
                en_pause: reste.contains("disabled"),
                par_defaut: defaut.as_deref() == Some(nom.as_str()),
                nom,
                ..Imprimante::default()
            });
        } else if let Some(reste) = l.strip_prefix("device for ")
            && let Some((nom, uri)) = reste.split_once(':')
            && let Some(i) = liste.iter_mut().find(|i| i.nom == nom.trim())
        {
            i.hote = hote(uri.trim());
        }
    }
    // « HP_LaserJet-12 alice 1024 Sat 18 Oct 2026 » : une impression en attente, nommée « imprimante-numéro ».
    for l in texte.lines() {
        if let Some(travail) = l.split_whitespace().next()
            && let Some((nom, numero)) = travail.rsplit_once('-')
            && numero.chars().all(|c| c.is_ascii_digit())
            && let Some(i) = liste.iter_mut().find(|i| i.nom == nom)
        {
            i.en_attente += 1;
        }
    }
    liste
}

/// L'imprimante répond-elle sur le réseau (IPP 631, impression directe 9100, page web 80) ?
fn repond(hote: &str) -> bool {
    let adresses: Vec<SocketAddr> = [631u16, 9100, 80]
        .iter()
        .filter_map(|&p| (hote, p).to_socket_addrs().ok()?.next())
        .collect();
    adresses
        .into_iter()
        .any(|a| super::reseau::joignable(a, Duration::from_millis(1500)))
}

/// La liste des imprimantes dit-elle ce qui est installé ? Sous Windows, elle passe par le spouleur : arrêté, elle
/// revient vide (EnumPrinters comme Get-Printer échouent), et « aucune imprimante installée » serait faux.
#[cfg_attr(not(windows), allow(dead_code))]
fn liste_lisible(spouleur: &str, imprimantes: &[Imprimante]) -> bool {
    spouleur == "Running" || !imprimantes.is_empty()
}

fn montrer(imprimantes: &[Imprimante]) {
    if imprimantes.is_empty() {
        Etat::Mauvais.dire(tr!(
            "Aucune imprimante n'est installée sur cet ordinateur.",
            "No printer is installed on this computer."
        ));
        return;
    }
    for i in imprimantes {
        for (etat, texte) in etat_de(i, repond) {
            etat.dire(&texte);
        }
    }
}

/// Ce qui est dit d'une imprimante. Son nom et son adresse viennent de qui l'a installée, ou de l'imprimante elle-même
/// quand elle s'annonce sur le réseau : montrés rendus inoffensifs ; ils restent tels quels pour l'essai `repond` et
/// pour les commandes.
fn etat_de(i: &Imprimante, repond: impl Fn(&str) -> bool) -> Vec<(Etat, String)> {
    let mut lignes = Vec::new();
    let defaut = if i.par_defaut {
        tr!(" (par défaut)", " (default)")
    } else {
        ""
    };
    let (nom, hote) = (affichable(&i.nom), affichable(&i.hote));
    if i.en_pause {
        lignes.push((
            Etat::Mauvais,
            trf!("{}{defaut} : en pause.", "{}{defaut}: paused.", nom),
        ));
    } else {
        lignes.push((Etat::Bon, trf!("{}{defaut} : prête.", "{}{defaut}: ready.", nom)));
    }
    if !i.hote.is_empty() {
        if repond(&i.hote) {
            lignes.push((
                Etat::Bon,
                trf!(
                    "Elle répond sur le réseau ({}).",
                    "It answers on the network ({}).",
                    hote
                ),
            ));
        } else {
            lignes.push((
                Etat::Mauvais,
                trf!(
                    "Elle ne répond pas sur le réseau ({}) : éteinte, sur un autre Wi-Fi, ou son adresse a changé.",
                    "It does not answer on the network ({}): turned off, on another Wi-Fi, or its address changed.",
                    hote
                ),
            ));
        }
    }
    if i.en_attente > 0 {
        lignes.push((
            Etat::Mauvais,
            trf!(
                "{} impression(s) en attente dans sa file.",
                "{} print job(s) waiting in its queue.",
                i.en_attente
            ),
        ));
    }
    lignes
}

pub(super) fn imprimante() {
    let Some(quoi) = question(
        tr!("Que se passe-t-il ?", "What is happening?"),
        &[
            tr!("J'imprime, mais rien ne sort", "I print, but nothing comes out"),
            tr!("L'imprimante n'apparaît pas", "The printer does not show up"),
            tr!(
                "Elle affiche une erreur (papier, encre, bourrage)",
                "It shows an error (paper, ink, jam)"
            ),
        ],
    ) else {
        return;
    };
    let Some(liaison) = question(
        tr!("Elle est reliée comment ?", "How is it connected?"),
        &[
            tr!("Câble USB", "USB cable"),
            tr!("Wi-Fi ou câble réseau", "Wi-Fi or network cable"),
            tr!("Je ne sais pas", "I don't know"),
        ],
    ) else {
        return;
    };
    verifications();
    let installees = systeme::verifier();
    let mut conseils = Vec::new();
    if quoi == 2 {
        conseils.push(tr!(
            "Erreur sur l'imprimante : son écran ou ses voyants disent laquelle. Bourrage : retirez doucement la feuille dans le sens du papier, imprimante éteinte. Puis annulez l'impression bloquée et relancez-la.",
            "Error on the printer: its screen or lights say which one. Jam: gently pull the sheet out in the paper's direction, printer off. Then cancel the stuck job and print again."
        ));
    }
    if liaison == 1 {
        conseils.push(tr!(
            "En Wi-Fi, l'imprimante doit être sur le même réseau que l'ordinateur. Si le routeur lui donne une autre adresse à chaque fois, la réserver dans le routeur (« bail fixe ») évite de la perdre.",
            "On Wi-Fi, the printer must be on the same network as the computer. If the router gives it a different address every time, reserving one in the router (“static lease”) keeps it from getting lost."
        ));
    }
    // Aucune imprimante installée : rien ne peut sortir, quelle que soit la panne décrite.
    if quoi == 1 || installees.as_ref().is_some_and(Vec::is_empty) {
        conseils.push(if cfg!(windows) {
            tr!(
                "Ajouter une imprimante : Paramètres › Bluetooth et appareils › Imprimantes et scanners › Ajouter un appareil.",
                "Add a printer: Settings › Bluetooth & devices › Printers & scanners › Add device."
            )
        } else if cfg!(target_os = "macos") {
            tr!(
                "Ajouter une imprimante : Réglages Système › Imprimantes et scanners › Ajouter une imprimante.",
                "Add a printer: System Settings › Printers & Scanners › Add Printer."
            )
        } else {
            tr!(
                "Ajouter une imprimante : les réglages du bureau (Imprimantes), ou l'interface de CUPS dans le navigateur, http://localhost:631. La plupart des imprimantes récentes marchent sans pilote (IPP Everywhere).",
                "Add a printer: the desktop settings (Printers), or the CUPS interface in the browser, http://localhost:631. Most recent printers work without a driver (IPP Everywhere)."
            )
        });
    }
    if liaison == 0 {
        conseils.push(tr!(
            "En USB : essayez un autre port et un autre câble, imprimante allumée avant de le brancher.",
            "On USB: try another port and another cable, with the printer on before plugging it in."
        ));
    }
    a_savoir(&conseils);
}

#[cfg(unix)]
mod systeme {
    use std::process::Command;

    use super::super::proposer;
    use super::{Etat, Imprimante, fait, imprimantes_lpstat, montrer};
    use crate::ui::*;

    fn lpstat(args: &[&str]) -> Option<String> {
        let r = crate::commande::lancer(Command::new("lpstat").args(args).env("LC_ALL", "C"), 15)?;
        Some(format!("{}{}", r.sortie, r.erreurs))
    }

    /// Vérifie et propose ; rend les imprimantes installées, si CUPS a pu les dire.
    pub fn verifier() -> Option<Vec<Imprimante>> {
        let Some(etat) = lpstat(&["-r"]) else {
            Etat::Mauvais.dire(tr!(
                "CUPS, le service d'impression, n'est pas installé.",
                "CUPS, the printing service, is not installed."
            ));
            return None;
        };
        if etat.contains("not running") {
            Etat::Mauvais.dire(tr!(
                "Le service d'impression (CUPS) est arrêté.",
                "The printing service (CUPS) is stopped."
            ));
            let demarrer = if cfg!(target_os = "macos") {
                "sudo launchctl kickstart -k system/org.cups.cupsd"
            } else {
                "sudo systemctl enable --now cups"
            };
            if proposer(
                tr!(
                    "\n  Démarrer le service d'impression ? [o/N] : ",
                    "\n  Start the printing service? [y/N]: "
                ),
                &[demarrer.to_string()],
            ) {
                fait(tr!("Service démarré.", "Service started."));
            } else {
                return None;
            }
        } else {
            Etat::Bon.dire(tr!(
                "Le service d'impression (CUPS) tourne.",
                "The printing service (CUPS) is running."
            ));
        }
        let imprimantes = imprimantes_lpstat(&lpstat(&["-p", "-d", "-v", "-o"]).unwrap_or_default());
        montrer(&imprimantes);
        for i in imprimantes.iter().filter(|i| i.en_pause) {
            // Le nom vient de CUPS ; entre apostrophes, il reste un seul mot pour le shell. Montré, il est rendu
            // inoffensif.
            let nom = crate::commande::sh_chaine(&i.nom);
            let montre = affichable(&i.nom);
            if proposer(
                &trf!("\n  Réactiver {} ? [o/N] : ", "\n  Re-enable {}? [y/N]: ", montre),
                &[format!("cupsenable {nom} || sudo cupsenable {nom}")],
            ) {
                fait(&trf!("{} réactivée.", "{} re-enabled.", montre));
            }
        }
        if imprimantes.iter().any(|i| i.en_attente > 0)
            && proposer(
                tr!(
                    "\n  Annuler les impressions en attente (à relancer ensuite) ? [o/N] : ",
                    "\n  Cancel the waiting print jobs (to send again afterwards)? [y/N]: "
                ),
                &["cancel -a".to_string()],
            )
        {
            fait(tr!("File vidée.", "Queue cleared."));
        }
        Some(imprimantes)
    }
}

#[cfg(windows)]
mod systeme {
    use super::{Etat, Imprimante, fait, liste_lisible, montrer};
    use crate::ui::*;

    /// Vérifie et propose ; rend les imprimantes installées, si Windows a pu les dire.
    /// La file du spouleur, écrite en toutes lettres : « $env:SystemRoot » vide en ferait la racine du disque.
    /// SystemRoot absent ou relatif : le dossier de Windows par défaut.
    pub(super) fn vider_la_file(racine: Option<std::path::PathBuf>) -> String {
        let windows = racine
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"));
        let file = crate::commande::ps_chaine(&windows.join(r"System32\spool\PRINTERS").to_string_lossy());
        format!("Get-ChildItem -LiteralPath {file} -File | Remove-Item -Force")
    }

    /// L'état lu par le gestionnaire de services et le spouleur, sans PowerShell ; `None` si le gestionnaire de
    /// services ne répond pas.
    fn lire_natif() -> Option<(String, Vec<Imprimante>)> {
        let spouleur = crate::machine::windows::gestionnaire::statut("Spooler")?.to_string();
        let imprimantes = crate::machine::windows::impression::imprimantes()
            .into_iter()
            .map(|i| Imprimante {
                nom: i.nom,
                en_pause: i.en_pause,
                hote: i.hote,
                en_attente: i.en_attente,
                par_defaut: i.par_defaut,
            })
            .collect();
        Some((spouleur, imprimantes))
    }

    /// L'état lu par PowerShell, en secours.
    fn lire_par_powershell() -> Option<(String, Vec<Imprimante>)> {
        let json = crate::machine::windows::ps(
            "$s = (Get-Service Spooler -ErrorAction SilentlyContinue).Status
             $defaut = (Get-CimInstance Win32_Printer | Where-Object Default).Name
             $l = @(try { Get-Printer | ForEach-Object { $p = $_
               $hote = try { (Get-PrinterPort -Name $p.PortName -ErrorAction Stop).PrinterHostAddress } catch { '' }
               @{ nom = $p.Name; pause = ($p.PrinterStatus -match 'Paused|Offline'); hote = \"$hote\"
                  attente = @(try { Get-PrintJob -PrinterName $p.Name -ErrorAction Stop } catch { }).Count; defaut = ($p.Name -eq $defaut) } } } catch { })
             [pscustomobject]@{ spouleur = \"$s\"; imprimantes = $l } | ConvertTo-Json -Compress -Depth 3",
        )?;
        let v: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
        let spouleur = v
            .get("spouleur")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        let imprimantes: Vec<Imprimante> = v
            .get("imprimantes")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .map(|i| Imprimante {
                nom: i["nom"].as_str().unwrap_or_default().to_string(),
                en_pause: i["pause"].as_bool().unwrap_or(false),
                hote: i["hote"].as_str().unwrap_or_default().to_string(),
                en_attente: usize::try_from(i["attente"].as_u64().unwrap_or(0)).unwrap_or(0),
                par_defaut: i["defaut"].as_bool().unwrap_or(false),
            })
            .collect();
        Some((spouleur, imprimantes))
    }

    pub fn verifier() -> Option<Vec<Imprimante>> {
        let Some((spouleur, imprimantes)) = lire_natif().or_else(lire_par_powershell) else {
            Etat::Info.dire(tr!(
                "État de l'impression illisible (PowerShell).",
                "Printing state not readable (PowerShell)."
            ));
            return None;
        };
        let marche = spouleur == "Running";
        Etat::selon(marche).dire(if marche {
            tr!("Le spouleur d'impression tourne.", "The print spooler is running.")
        } else {
            tr!("Le spouleur d'impression est arrêté.", "The print spooler is stopped.")
        });
        let lisible = liste_lisible(&spouleur, &imprimantes);
        if lisible {
            montrer(&imprimantes);
        } else {
            illisible_sans_spouleur();
        }
        let bloque = imprimantes.iter().any(|i| i.en_attente > 0);
        if (!marche || bloque)
            && demander(tr!(
                "\n  Relancer le spouleur et vider sa file (les impressions en attente sont annulées) ? [o/N] : ",
                "\n  Restart the spooler and clear its queue (waiting print jobs are cancelled)? [y/N]: "
            ))
            .oui()
            && crate::machine::appliquer(&[
                "Stop-Service Spooler -Force".to_string(),
                vider_la_file(std::env::var_os("SystemRoot").map(std::path::PathBuf::from)),
                "Start-Service Spooler".to_string(),
            ])
        {
            fait(tr!(
                "Spouleur relancé, file vidée.",
                "Spooler restarted, queue cleared."
            ));
            if !lisible {
                // La liste lue spouleur arrêté était vide par force : relue maintenant qu'il tourne.
                return match lire_natif().or_else(lire_par_powershell) {
                    Some((spouleur, imprimantes)) if liste_lisible(&spouleur, &imprimantes) => {
                        montrer(&imprimantes);
                        Some(imprimantes)
                    }
                    _ => {
                        illisible_sans_spouleur();
                        None
                    }
                };
            }
        }
        // Spouleur arrêté et liste vide : rien ne dit qu'aucune imprimante n'est installée, aucun conseil d'en ajouter.
        lisible.then_some(imprimantes)
    }

    fn illisible_sans_spouleur() {
        Etat::Info.dire(tr!(
            "Liste des imprimantes illisible : Windows ne la donne que par le spouleur, arrêté.",
            "Printer list not readable: Windows only gives it through the spooler, which is stopped."
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La file du spouleur vidée par son chemin écrit, même sans SystemRoot (jamais la racine du disque).
    #[cfg(windows)]
    #[test]
    fn file_du_spouleur_ecrite_en_toutes_lettres() {
        assert_eq!(
            systeme::vider_la_file(Some(r"D:\Windows".into())),
            r"Get-ChildItem -LiteralPath 'D:\Windows\System32\spool\PRINTERS' -File | Remove-Item -Force"
        );
        for absent in [None, Some(std::path::PathBuf::new()), Some(r"\Windows".into())] {
            assert!(systeme::vider_la_file(absent).contains(r"-LiteralPath 'C:\Windows\System32\spool\PRINTERS'"));
        }
    }

    /// Spouleur arrêté : la liste vide ne veut pas dire « aucune imprimante », elle ne se lit pas.
    #[test]
    fn spouleur_arrete_liste_illisible() {
        let une = [Imprimante {
            nom: "Salon_Laser".into(),
            ..Imprimante::default()
        }];
        assert!(liste_lisible("Running", &[]));
        assert!(liste_lisible("Running", &une));
        assert!(!liste_lisible("Stopped", &[]));
        assert!(!liste_lisible("", &[]));
        assert!(liste_lisible("Stopped", &une));
    }

    #[test]
    fn imprimantes_de_cups() {
        let texte = "printer Salon_Laser is idle.  enabled since Sat 18 Oct 2026 10:00:00\n\
                     printer Bureau-Jet disabled since Sat 18 Oct 2026 09:00:00 -\n\treason unknown\n\
                     system default destination: Salon_Laser\n\
                     device for Salon_Laser: ipp://192.168.1.20/ipp/print\n\
                     device for Bureau-Jet: usb://HP/DeskJet%202700?serial=ESSAI\n\
                     Salon_Laser-12           alice          1024   Sat 18 Oct 2026 10:01:00\n\
                     Salon_Laser-13           alice          2048   Sat 18 Oct 2026 10:02:00\n";
        let l = imprimantes_lpstat(texte);
        assert_eq!(l.len(), 2);
        assert_eq!(
            l[0],
            Imprimante {
                nom: "Salon_Laser".into(),
                en_pause: false,
                hote: "192.168.1.20".into(),
                en_attente: 2,
                par_defaut: true,
            }
        );
        assert!(l[1].en_pause && l[1].hote.is_empty() && !l[1].par_defaut);
        assert_eq!(hote("socket://imprimante.local:9100"), "imprimante.local");
        assert_eq!(hote("ipps://[fe80::1]:631/ipp/print"), "fe80::1");
        assert_eq!(hote("dnssd://HP%20LaserJet._ipp._tcp.local/"), "");
    }

    /// Une imprimante du réseau s'annonce avec le nom de son choix : piégé, il arrive inoffensif dans ce qui est dit
    /// d'elle ; le nom tel quel reste pour la commande qui la réactive.
    #[test]
    fn nom_d_imprimante_piege() {
        let i = Imprimante {
            nom: "Salon\x1b]52;c;eA==\x07\x1b[2K\r\u{202e}".into(),
            en_pause: true,
            hote: "imprimante\x1b[8m.local".into(),
            par_defaut: true,
            ..Imprimante::default()
        };
        for repond in [true, false] {
            let lignes = etat_de(&i, |_| repond);
            assert_eq!(lignes.len(), 2);
            for (_, texte) in &lignes {
                assert!(!crate::ui::contient_un_piege(texte), "{texte}");
            }
            assert!(lignes[0].1.starts_with("Salon�]52;c;eA==��[2K��"), "{}", lignes[0].1);
            assert_eq!(lignes[0].0, Etat::Mauvais);
        }
    }
}

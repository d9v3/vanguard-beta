//! Parcours « Pas de son » : le service du son tourne-t-il, quelle sortie est choisie, est-elle muette, à quel volume.
//! Linux : PulseAudio ou PipeWire (pactl) ; macOS : volume de sortie (osascript) ; Windows : les services du son.
//! Remettre le son, choisir la sortie ou relancer le service : montré, puis fait après accord.

use super::{Etat, a_savoir, fait, question, verifications};
use crate::ui::*;

/// Une sortie du son (Linux : un « sink » de pactl).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Sortie {
    pub nom: String,
    /// Ce qu'on montre : la description de pactl, sinon le nom.
    pub description: String,
}

/// Le genre d'une sortie, d'après son nom : ce que la personne a répondu (haut-parleurs, casque, HDMI, Bluetooth).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn genre(nom: &str) -> usize {
    let n = nom.to_lowercase();
    let contient = |mots: &[&str]| mots.iter().any(|m| n.contains(m));
    if contient(&["hdmi", "displayport"]) {
        2
    } else if contient(&["bluez", "bluetooth"]) {
        3
    } else {
        usize::from(contient(&["headphone", "headset", "usb"]))
    }
}

/// `pactl list sinks` : les sorties (nom et description), lues en anglais (LC_ALL=C). La description vient souvent de
/// l'appareil (le nom d'un casque Bluetooth) : prête à montrer. Le nom, qui sert à choisir la sortie, reste tel quel.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn sorties_pactl(texte: &str) -> Vec<Sortie> {
    texte
        .split("Sink #")
        .skip(1)
        .filter_map(|bloc| {
            let champ = |cle: &str| {
                bloc.lines()
                    .find_map(|l| l.trim().strip_prefix(cle).map(|v| v.trim().to_string()))
            };
            let nom = champ("Name:")?;
            Some(Sortie {
                description: affichable(
                    &champ("Description:")
                        .filter(|d| !d.is_empty())
                        .unwrap_or_else(|| nom.clone()),
                ),
                nom,
            })
        })
        .collect()
}

/// « Volume: front-left: 32768 /  50% / -18.06 dB, … » → 50.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn volume_pactl(texte: &str) -> Option<u32> {
    texte
        .split('/')
        .find_map(|p| p.trim().strip_suffix('%').and_then(|v| v.trim().parse().ok()))
}

pub(super) fn son() {
    let Some(ou) = question(
        tr!("Où manque le son ?", "Where is the sound missing?"),
        &[
            tr!("Partout, aucun son", "Everywhere, no sound at all"),
            tr!("Dans un seul programme", "In one program only"),
            tr!("Le son grésille ou coupe", "The sound crackles or cuts out"),
        ],
    ) else {
        return;
    };
    let Some(sortie_voulue) = question(
        tr!("Par où le son doit-il sortir ?", "Where should the sound come out?"),
        &[
            tr!("Haut-parleurs de l'ordinateur", "The computer's speakers"),
            tr!("Casque ou écouteurs", "Headphones or earphones"),
            tr!("Écran ou télé (HDMI)", "Monitor or TV (HDMI)"),
            tr!("Bluetooth", "Bluetooth"),
        ],
    ) else {
        return;
    };
    verifications();
    systeme::verifier(ou, sortie_voulue);
    let mut conseils = Vec::new();
    if ou == 1 {
        conseils.push(tr!(
            "Un seul programme muet : son propre volume (souvent dans le programme lui-même), ou le mélangeur de volume du système, qui règle chaque programme à part.",
            "One silent program: its own volume (often inside the program itself), or the system volume mixer, which sets each program separately."
        ));
    }
    if ou == 2 {
        conseils.push(tr!(
            "Son qui grésille : essayez une autre prise ou un autre câble ; en Bluetooth, rapprochez le casque et éloignez-le du Wi-Fi 2,4 GHz. Relancer le service du son règle souvent les coupures.",
            "Crackling sound: try another port or cable; on Bluetooth, bring the headset closer and away from 2.4 GHz Wi-Fi. Restarting the sound service often fixes the cuts."
        ));
    }
    if sortie_voulue == 2 {
        conseils.push(tr!(
            "HDMI : l'écran ou la télé doit avoir son propre volume monté, et la bonne entrée choisie.",
            "HDMI: the monitor or TV must have its own volume turned up, and the right input selected."
        ));
    }
    if sortie_voulue == 3 {
        conseils.push(tr!(
            "Bluetooth : un casque connecté en « mains libres » sonne mal ; déconnectez-le puis reconnectez-le, ou choisissez le profil « haute qualité » (A2DP).",
            "Bluetooth: a headset connected as “hands-free” sounds bad; disconnect and reconnect it, or choose the “high quality” profile (A2DP)."
        ));
    }
    a_savoir(&conseils);
}

#[cfg(target_os = "linux")]
mod systeme {
    use std::process::Command;

    use super::super::proposer;
    use super::{Etat, Sortie, fait, genre, sorties_pactl, volume_pactl};
    use crate::ui::*;

    fn pactl(args: &[&str]) -> Option<String> {
        let r = crate::commande::lancer(Command::new("pactl").args(args).env("LC_ALL", "C"), 10)?;
        (r.code == Some(0)).then_some(r.sortie)
    }

    /// Relance PipeWire (ou PulseAudio) dans la session : le son revient en quelques secondes. PipeWire se
    /// reconnaît à son programme : la session, elle, peut justement ne plus répondre.
    fn relancer() -> Vec<String> {
        let pipewire = ["/usr/bin", "/bin", "/usr/local/bin"]
            .iter()
            .any(|d| std::path::Path::new(d).join("pipewire").exists());
        if pipewire {
            vec!["systemctl --user restart wireplumber pipewire pipewire-pulse".into()]
        } else {
            vec!["pulseaudio -k; sleep 2; pulseaudio --check || pulseaudio --start".into()]
        }
    }

    pub fn verifier(_ou: usize, voulue: usize) {
        let Some(info) = pactl(&["info"]) else {
            Etat::Mauvais.dire(tr!(
                "Le service du son ne répond pas (ni PipeWire, ni PulseAudio).",
                "The sound service does not answer (neither PipeWire nor PulseAudio)."
            ));
            if proposer(
                tr!(
                    "\n  Relancer le service du son ? [o/N] : ",
                    "\n  Restart the sound service? [y/N]: "
                ),
                &relancer(),
            ) {
                fait(tr!("Service relancé.", "Service restarted."));
            }
            return;
        };
        let serveur = affichable(
            info.lines()
                .find_map(|l| l.strip_prefix("Server Name:"))
                .map_or("PulseAudio", str::trim),
        );
        Etat::Bon.dire(&trf!("Service du son : {serveur}.", "Sound service: {serveur}."));
        let sorties = sorties_pactl(&pactl(&["list", "sinks"]).unwrap_or_default());
        let defaut = pactl(&["get-default-sink"]).unwrap_or_default().trim().to_string();
        let Some(actuelle) = sorties.iter().find(|s| s.nom == defaut) else {
            Etat::Mauvais.dire(tr!(
                "Aucune sortie du son n'est choisie (carte son non reconnue, ou casque Bluetooth déconnecté).",
                "No sound output is selected (sound card not recognized, or Bluetooth headset disconnected)."
            ));
            return;
        };
        let nom = &actuelle.description;
        Etat::Info.dire(&trf!("Sortie choisie : {nom}.", "Selected output: {nom}."));
        let muette = pactl(&["get-sink-mute", "@DEFAULT_SINK@"]).is_some_and(|m| m.contains("yes"));
        let volume = pactl(&["get-sink-volume", "@DEFAULT_SINK@"])
            .as_deref()
            .and_then(volume_pactl);
        if muette {
            Etat::Mauvais.dire(tr!("Le son est coupé (muet).", "The sound is muted."));
            if proposer(
                tr!("\n  Remettre le son ? [o/N] : ", "\n  Unmute? [y/N]: "),
                &["pactl set-sink-mute @DEFAULT_SINK@ 0".into()],
            ) {
                fait(tr!("Son remis.", "Sound unmuted."));
            }
        } else if let Some(v) = volume {
            if v < 10 {
                Etat::Mauvais.dire(&trf!("Volume très bas ({v} %).", "Volume very low ({v}%)."));
                if proposer(
                    tr!(
                        "\n  Mettre le volume à 50 % ? [o/N] : ",
                        "\n  Set the volume to 50%? [y/N]: "
                    ),
                    &["pactl set-sink-volume @DEFAULT_SINK@ 50%".into()],
                ) {
                    fait(tr!("Volume à 50 %.", "Volume at 50%."));
                }
            } else {
                Etat::Bon.dire(&trf!("Volume à {v} %, son non coupé.", "Volume at {v}%, not muted."));
            }
        }
        // La sortie choisie n'est pas celle qu'on attend : proposer celles qui y ressemblent.
        if genre(&actuelle.nom) != voulue {
            let candidates: Vec<&Sortie> = sorties.iter().filter(|s| s.nom != actuelle.nom).collect();
            if candidates.is_empty() {
                Etat::Mauvais.dire(tr!(
                    "Aucune autre sortie n'est disponible : la prise, le câble ou l'appairage Bluetooth sont à vérifier.",
                    "No other output is available: the port, the cable or the Bluetooth pairing need checking."
                ));
                return;
            }
            Etat::Info.dire(tr!(
                "Le son sort peut-être ailleurs que là où vous l'attendez. Sorties disponibles :",
                "The sound may be going somewhere else than where you expect. Available outputs:"
            ));
            for (i, s) in candidates.iter().enumerate() {
                println!("    {TOUCHE}{}{RESET}  {}", i + 1, s.description);
            }
            let choix = demander(tr!(
                "\n  Numéro de la sortie à utiliser (Entrée pour garder celle-ci) : ",
                "\n  Number of the output to use (Enter to keep this one): "
            ));
            if let Some(s) = choix
                .trim()
                .parse::<usize>()
                .ok()
                .and_then(|n| n.checked_sub(1))
                .and_then(|i| candidates.get(i))
            {
                // Le nom vient de pactl ; entre apostrophes, il reste un seul mot pour le shell.
                let commande = format!("pactl set-default-sink {}", crate::commande::sh_chaine(&s.nom));
                if crate::machine::appliquer(&[commande]) {
                    fait(tr!("Sortie changée.", "Output changed."));
                }
            }
        }
        if proposer(
            tr!(
                "\n  Toujours rien ? Relancer le service du son ? [o/N] : ",
                "\n  Still nothing? Restart the sound service? [y/N]: "
            ),
            &relancer(),
        ) {
            fait(tr!("Service relancé.", "Service restarted."));
        }
    }
}

#[cfg(target_os = "macos")]
mod systeme {
    use std::process::Command;

    use super::{Etat, fait};
    use crate::ui::*;

    fn osascript(script: &str) -> Option<String> {
        let r = crate::commande::lancer(Command::new("osascript").args(["-e", script]), 10)?;
        (r.code == Some(0)).then(|| r.sortie.trim().to_string())
    }

    pub fn verifier(_ou: usize, _voulue: usize) {
        let muet = osascript("output muted of (get volume settings)");
        let volume: Option<u32> = osascript("output volume of (get volume settings)").and_then(|v| v.parse().ok());
        match (muet.as_deref(), volume) {
            (Some("true"), _) => {
                Etat::Mauvais.dire(tr!("Le son est coupé (muet).", "The sound is muted."));
                if demander(tr!("\n  Remettre le son ? [o/N] : ", "\n  Unmute? [y/N]: ")).oui()
                    && crate::machine::appliquer(&["osascript -e 'set volume without output muted'".to_string()])
                {
                    fait(tr!("Son remis.", "Sound unmuted."));
                }
            }
            (_, Some(v)) if v < 10 => {
                Etat::Mauvais.dire(&trf!("Volume très bas ({v} %).", "Volume very low ({v}%)."));
                if demander(tr!(
                    "\n  Mettre le volume à 50 % ? [o/N] : ",
                    "\n  Set the volume to 50%? [y/N]: "
                ))
                .oui()
                    && crate::machine::appliquer(&["osascript -e 'set volume output volume 50'".to_string()])
                {
                    fait(tr!("Volume à 50 %.", "Volume at 50%."));
                }
            }
            (_, Some(v)) => Etat::Bon.dire(&trf!("Volume à {v} %, son non coupé.", "Volume at {v}%, not muted.")),
            _ => Etat::Info.dire(tr!("Volume illisible.", "Volume not readable.")),
        }
        Etat::Info.dire(tr!(
            "La sortie se choisit dans Réglages Système › Son › Sortie (ou en cliquant sur le haut-parleur de la barre des menus).",
            "The output is chosen in System Settings › Sound › Output (or by clicking the speaker in the menu bar)."
        ));
        if demander(tr!(
            "\n  Ouvrir les réglages du son ? [o/N] : ",
            "\n  Open the sound settings? [y/N]: "
        ))
        .oui()
        {
            crate::machine::ouvrir("x-apple.systempreferences:com.apple.Sound-Settings.extension");
        }
        if demander(tr!(
            "\n  Toujours rien ? Relancer le service du son (mot de passe administrateur) ? [o/N] : ",
            "\n  Still nothing? Restart the sound service (administrator password)? [y/N]: "
        ))
        .oui()
            && crate::machine::appliquer(&["sudo killall coreaudiod".to_string()])
        {
            fait(tr!("Service relancé.", "Service restarted."));
        }
    }
}

#[cfg(windows)]
mod systeme {
    use super::{Etat, fait};
    use crate::ui::*;

    /// Les mêmes lignes que le script de secours (« service|état », « carte|nom|OK ou Error »), lues auprès du
    /// gestionnaire de services et de SetupAPI ; `None` si l'un des deux ne répond pas.
    pub(super) fn lire_natif() -> Option<String> {
        use crate::machine::windows::{gestionnaire, peripheriques};
        let mut lignes = Vec::new();
        for service in ["Audiosrv", "AudioEndpointBuilder"] {
            lignes.push(format!("{service}|{}", gestionnaire::statut(service)?));
        }
        for carte in peripheriques::presents(&peripheriques::SON)? {
            lignes.push(ligne_de_carte(&carte.nom, carte.marche));
        }
        Some(lignes.join("\n"))
    }

    /// « carte|nom|OK » sur une seule ligne. Le nom vient du pilote ou de l'appareil branché (un casque USB annonce
    /// le sien) : un saut de ligne y ferait une ligne de plus, lue comme un service arrêté, et une séquence
    /// d'échappement passée par là arriverait au terminal sans le filtre d'`affichable`. Séparateur et caractères de
    /// contrôle deviennent des espaces.
    pub(super) fn ligne_de_carte(nom: &str, marche: bool) -> String {
        let nom: String = nom
            .chars()
            .map(|c| if c == '|' || c.is_control() { ' ' } else { c })
            .collect();
        format!("carte|{nom}|{}", if marche { "OK" } else { "Error" })
    }

    pub fn verifier(_ou: usize, _voulue: usize) {
        // Les deux services du son ; le volume et la sortie, eux, ne se lisent qu'à travers les API de Windows.
        let etat = lire_natif()
            .or_else(|| {
                crate::machine::windows::ps(
                    "@('Audiosrv','AudioEndpointBuilder') | ForEach-Object { $s = Get-Service $_ -ErrorAction SilentlyContinue; \"$_|$($s.Status)\" }; \
                     @(Get-CimInstance Win32_SoundDevice) | ForEach-Object { \"carte|$($_.Name -replace '[\\x00-\\x1f\\x7f|]', ' ')|$($_.Status)\" }",
                )
            })
            .unwrap_or_default();
        let mut arrete = false;
        for l in etat.lines() {
            let c: Vec<&str> = l.trim().split('|').collect();
            match c[..] {
                // Le nom d'une carte son vient de son pilote ou de l'appareil branché : montré rendu inoffensif.
                ["carte", nom, statut] => {
                    let (marche, nom, statut) = (statut == "OK", affichable(nom), affichable(statut));
                    Etat::selon(marche).dire(&if marche {
                        trf!("Carte son : {nom}.", "Sound card: {nom}.")
                    } else {
                        trf!(
                            "Carte son en erreur : {nom} ({statut}).",
                            "Sound card in error: {nom} ({statut})."
                        )
                    });
                }
                // Seuls les deux services demandés : une autre ligne à deux champs ne dit rien d'eux.
                [service @ ("Audiosrv" | "AudioEndpointBuilder"), statut] => {
                    let marche = statut == "Running";
                    arrete |= !marche;
                    Etat::selon(marche).dire(&if marche {
                        trf!("Service {service} : démarré.", "Service {service}: running.")
                    } else {
                        trf!("Service {service} : arrêté.", "Service {service}: stopped.")
                    });
                }
                _ => {}
            }
        }
        if etat.is_empty() {
            Etat::Info.dire(tr!(
                "État du son illisible (PowerShell).",
                "Sound state not readable (PowerShell)."
            ));
        }
        Etat::Info.dire(tr!(
            "Le volume et la sortie se règlent en cliquant sur le haut-parleur, près de l'horloge (flèche à droite du curseur : choisir la sortie).",
            "Volume and output are set by clicking the speaker, near the clock (arrow to the right of the slider: choose the output)."
        ));
        if demander(tr!(
            "\n  Ouvrir les réglages du son ? [o/N] : ",
            "\n  Open the sound settings? [y/N]: "
        ))
        .oui()
        {
            crate::machine::ouvrir("ms-settings:sound");
        }
        let question = if arrete {
            tr!(
                "\n  Démarrer les services du son (fenêtre administrateur) ? [o/N] : ",
                "\n  Start the sound services (administrator window)? [y/N]: "
            )
        } else {
            tr!(
                "\n  Toujours rien ? Relancer les services du son (fenêtre administrateur) ? [o/N] : ",
                "\n  Still nothing? Restart the sound services (administrator window)? [y/N]: "
            )
        };
        if demander(question).oui()
            && crate::machine::appliquer(&[
                "Restart-Service -Force AudioEndpointBuilder".to_string(),
                "Start-Service Audiosrv".to_string(),
            ])
        {
            fait(tr!("Services relancés.", "Services restarted."));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le vrai gestionnaire de services et SetupAPI (Wine ici, la VM ensuite), sans PowerShell : les deux services
    /// sont toujours dans les lignes, chacune de la forme lue par `verifier`.
    #[cfg(windows)]
    #[test]
    fn son_lu_sans_powershell() {
        if let Some(t) = systeme::lire_natif() {
            assert!(t.lines().take(2).all(|l| l.split('|').count() == 2), "{t}");
            assert!(
                t.lines()
                    .skip(2)
                    .all(|l| l.starts_with("carte|") && l.split('|').count() == 3),
                "{t}"
            );
        }
    }

    /// Un nom de carte piégé (saut de ligne, séquence d'échappement, séparateur) reste une seule ligne à trois champs.
    #[cfg(windows)]
    #[test]
    fn nom_de_carte_piege() {
        let l = systeme::ligne_de_carte("Casque\n\x1b]52;c;eA==\x07|OK\r\nAudiosrv|Stopped", true);
        assert_eq!(l.lines().count(), 1, "{l}");
        assert_eq!(l.split('|').count(), 3, "{l}");
        assert!(
            l.starts_with("carte|Casque  ]52;c;eA==  OK  Audiosrv Stopped|OK"),
            "{l}"
        );
        assert_eq!(
            systeme::ligne_de_carte("Realtek Audio", false),
            "carte|Realtek Audio|Error"
        );
    }

    #[test]
    fn sorties_de_pactl() {
        let texte = "Sink #52\n\tState: SUSPENDED\n\tName: alsa_output.pci-0000_00_1f.3.analog-stereo\n\tDescription: Audio interne Stéréo analogique\n\n\
                     Sink #61\n\tState: RUNNING\n\tName: alsa_output.pci-0000_01_00.1.hdmi-stereo\n\tDescription: GB205 HDMI / DisplayPort\n";
        let s = sorties_pactl(texte);
        assert_eq!(s.len(), 2);
        assert_eq!(s[1].description, "GB205 HDMI / DisplayPort");
        assert_eq!(genre(&s[0].nom), 0);
        assert_eq!(genre(&s[1].nom), 2);
        assert_eq!(genre("bluez_output.00_1B_66_00_00_01.1"), 3);
        assert_eq!(
            volume_pactl("Volume: front-left: 32768 /  50% / -18.06 dB,   front-right: 32768 /  50% / -18.06 dB"),
            Some(50)
        );
        assert_eq!(volume_pactl("rien"), None);
        // La description d'un casque Bluetooth vient de son nom, choisi par l'appareil : piégée, elle arrive
        // inoffensive ; le nom de la sortie, qui sert à la choisir, reste tel quel.
        let piege = "Sink #7\n\tName: bluez_output.00_1B_66_00_00_01.1\n\tDescription: Casque\x1b]52;c;eA==\x07\x1b[2K\r\u{202e}\n";
        let s = sorties_pactl(piege);
        assert_eq!(s[0].description, "Casque�]52;c;eA==��[2K��");
        assert_eq!(s[0].nom, "bluez_output.00_1B_66_00_00_01.1");
    }
}

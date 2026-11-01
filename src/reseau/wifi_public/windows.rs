//! Le mode Wi-Fi public sous Windows : le réseau passe en catégorie Public, le profil Public du pare-feu bloque toutes
//! les entrées (même celles des programmes autorisés : partage de fichiers, découverte du réseau), NetBIOS est coupé
//! sur la carte, et le DNS protecteur est posé (non chiffré ici : le réglage DoH par carte n'est pas vérifiable sans
//! un vrai Windows 11, c'est dit). Tout passe par Vanguard administrateur, en une seule demande : la catégorie et le
//! profil Public sont des actes natifs (`vanguard:reseau-categorie`, `vanguard:pare-feu-public`, `gestes.rs`), faits
//! par COM et relus dans le processus élevé ; NetBIOS reste une commande PowerShell. Lignes pures, essayées partout
//! (la commande PowerShell analysée par pwsh dans verifier.sh) ; lectures sous Windows seulement.

#![cfg_attr(not(windows), allow(dead_code))]

use super::etat::{Element, PARAMETRES_PROFIL, guid_valide};

/// La lecture, sans droits d'administrateur : la carte Wi-Fi active, son profil réseau, le profil Public du
/// pare-feu tel qu'il est réglé sur cet ordinateur (`PersistentStore` : hors stratégie de groupe). Le nom du réseau
/// en dernier, il peut contenir « | ».
pub(crate) const LECTURE: &str = "$a = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and $_.NdisPhysicalMedium -eq 9 } | Select-Object -First 1; \
     if ($a) { \"CARTE|$($a.ifIndex)|$($a.InterfaceGuid)\"; \
     $p = Get-NetConnectionProfile -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue | Select-Object -First 1; \
     if ($p) { \"PROFIL|$($p.InstanceID)|$($p.NetworkCategory)|$($p.Name)\" } }; \
     $f = Get-NetFirewallProfile -Profile Public -PolicyStore PersistentStore; \
     \"PAREFEU|$($f.Enabled)|$($f.DefaultInboundAction)|$($f.AllowInboundRules)\"";

/// Ce que dit la lecture.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Lu {
    /// Index et GUID de la carte Wi-Fi active.
    pub carte: Option<(u32, String)>,
    /// GUID du profil réseau, sa catégorie (Public, Private, DomainAuthenticated) et son nom.
    pub profil: Option<(String, String, String)>,
    /// Le profil Public du pare-feu : Enabled, DefaultInboundAction, AllowInboundRules.
    pub pare_feu: Option<[String; 3]>,
}

pub(crate) fn lire_sortie(sortie: &str) -> Lu {
    let mut lu = Lu::default();
    for l in sortie.lines().map(str::trim) {
        if let Some(r) = l.strip_prefix("CARTE|") {
            lu.carte = r
                .split_once('|')
                .and_then(|(i, g)| Some((i.parse().ok()?, g.to_string())))
                .filter(|(_, g)| guid_valide(g));
        } else if let Some(r) = l.strip_prefix("PROFIL|") {
            let c: Vec<&str> = r.splitn(3, '|').collect();
            if let [guid, categorie, nom] = c[..]
                && guid_valide(guid)
                && ["Public", "Private", "DomainAuthenticated"].contains(&categorie)
            {
                lu.profil = Some((guid.to_string(), categorie.to_string(), nom.to_string()));
            }
        } else if let Some(r) = l.strip_prefix("PAREFEU|") {
            let c: Vec<&str> = r.split('|').collect();
            if let [a, b, d] = c.as_slice()
                && PARAMETRES_PROFIL
                    .iter()
                    .zip(&c)
                    .all(|((_, valeurs), v)| valeurs.contains(v))
            {
                lu.pare_feu = Some([a.to_string(), b.to_string(), d.to_string()]);
            }
        }
    }
    lu
}

/// Ce que le mode veut pour chaque paramètre du profil Public, et s'il faut le changer d'après sa valeur. « Non
/// configuré » vaut déjà allumé et bloquer : rien n'est changé pour si peu.
pub(crate) fn a_changer_profil(lu: &[String; 3]) -> Vec<(&'static str, &'static str, String)> {
    let mut l = Vec::new();
    if lu[0] == "False" {
        l.push(("Enabled", "True", lu[0].clone()));
    }
    if lu[1] == "Allow" {
        l.push(("DefaultInboundAction", "Block", lu[1].clone()));
    }
    if lu[2] != "False" {
        l.push(("AllowInboundRules", "False", lu[2].clone()));
    }
    l
}

/// La ligne qui pose des paramètres du profil Public, sous les noms et valeurs de NetSecurity que lit `LECTURE` et que
/// note l'état : l'acte `pare-feu-public`. `None` : aucun paramètre, un nom ou une valeur hors liste, ou ce que
/// l'acte refuse (couper le pare-feu ; « non configuré » ailleurs que pour les règles entrantes, jamais changé par
/// le mode).
pub(crate) fn regler_profil(parametres: &[(&str, &str)]) -> Option<String> {
    use crate::machine::gestes::{ReglagePublic, ValeurPublic, ligne_pare_feu_public};
    let reglages = parametres
        .iter()
        .map(|p| {
            Some(match *p {
                ("Enabled", "True") => (ReglagePublic::Actif, ValeurPublic::Oui),
                ("DefaultInboundAction", "Block") => (ReglagePublic::EntrantBloque, ValeurPublic::Oui),
                ("DefaultInboundAction", "Allow") => (ReglagePublic::EntrantBloque, ValeurPublic::Non),
                // AllowInboundRules dit l'inverse : « False », les règles des programmes autorisés ignorées.
                ("AllowInboundRules", "False") => (ReglagePublic::ReglesEntrantes, ValeurPublic::Non),
                ("AllowInboundRules", "True") => (ReglagePublic::ReglesEntrantes, ValeurPublic::Oui),
                ("AllowInboundRules", "NotConfigured") => (ReglagePublic::ReglesEntrantes, ValeurPublic::Absent),
                _ => return None,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    ligne_pare_feu_public(&reglages)
}

/// Le réseau en catégorie Public, tout de suite (INetworkListManager), désigné par le GUID de son profil.
pub(crate) fn rendre_public(guid: &str) -> Option<String> {
    crate::machine::gestes::ligne_reseau_categorie(guid, crate::machine::gestes::Categorie::Public)
}

/// La catégorie Private remise : tout de suite si Windows connaît encore le réseau, sinon dans le registre, pour la
/// prochaine connexion à ce réseau (le processus élevé choisit, après avoir relu que le profil existe).
pub(crate) fn rendre_prive(guid: &str) -> Option<String> {
    crate::machine::gestes::ligne_reseau_categorie(guid, crate::machine::gestes::Categorie::Prive)
}

/// NetBIOS de la carte (0 selon DHCP, 1 allumé, 2 coupé), par la méthode de WMI qui l'applique tout de suite et
/// l'écrit dans le registre. Elle répond par un code au lieu d'une erreur : 0 fait, 1 fait au redémarrage.
pub(crate) fn netbios(carte: &str, valeur: u32) -> Option<String> {
    (guid_valide(carte) && valeur <= 2).then(|| {
        format!(
            "$r = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter \"SettingID='{carte}'\" | \
             Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{{ TcpipNetbiosOptions = [uint32]{valeur} }}; \
             if (-not $r -or $r.ReturnValue -gt 1) {{ throw \"SetTcpipNetbios : $($r.ReturnValue)\" }}"
        )
    })
}

/// La commande qui remet un élément propre à Windows (le DNS passe par `optimiser`). Un pare-feu trouvé coupé
/// n'est jamais recoupé.
pub(crate) fn remettre(e: &Element) -> Option<String> {
    if !e.valide() || e.jamais_remis() {
        return None;
    }
    match e {
        Element::Categorie { guid, .. } => rendre_prive(guid),
        Element::ProfilPublic { parametre, avant } => regler_profil(&[(parametre.as_str(), avant.as_str())]),
        Element::NetBios { carte, avant } => netbios(carte, *avant),
        _ => None,
    }
}

#[cfg(windows)]
pub(crate) mod lecture {
    use super::super::etat::Element;

    fn dword(cle: &str, valeur: &str) -> Option<u32> {
        winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
            .open_subkey(cle)
            .ok()?
            .get_value(valeur)
            .ok()
    }

    pub(crate) fn lire() -> super::Lu {
        crate::machine::windows::ps(super::LECTURE)
            .map(|s| super::lire_sortie(&s))
            .unwrap_or_default()
    }

    /// La catégorie d'un profil réseau dans le registre (0 Public, 1 Private, 2 DomainAuthenticated).
    pub(crate) fn categorie(guid: &str) -> Option<&'static str> {
        let n = dword(
            &format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{guid}"),
            "Category",
        )?;
        Some(match n {
            0 => "Public",
            1 => "Private",
            _ => "DomainAuthenticated",
        })
    }

    /// NetbiosOptions de la carte ; absent vaut 0 (selon DHCP).
    pub(crate) fn netbios(carte: &str) -> Option<u32> {
        let cle = format!(r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{carte}");
        winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
            .open_subkey(&cle)
            .ok()?;
        Some(dword(&cle, "NetbiosOptions").unwrap_or(0))
    }

    /// L'élément est-il à sa valeur d'avant ? `None` : illisible. `pare_feu` : la lecture du profil Public, faite une
    /// fois pour tous.
    /// La catégorie en usage, par INetworkListManager ; `None` si Windows ne connaît pas ce réseau en ce moment.
    fn categorie_en_usage(guid: &str) -> Option<&'static str> {
        let g = crate::machine::gestes::GuidReseau::lire(guid)?;
        Some(match crate::machine::windows::pare_feu::categorie_en_direct(g)? {
            0 => "Public",
            1 => "Private",
            _ => "DomainAuthenticated",
        })
    }

    /// `en_direct` : la catégorie se relit en usage seulement (juste après l'allumage, le réseau est connecté : le
    /// registre seul dirait pris ce que Windows n'applique pas). Sinon, en usage si Windows connaît le réseau, et
    /// dans le registre pour un réseau qui n'est plus là (remis pour sa prochaine connexion).
    pub(crate) fn a_l_avant(e: &Element, pare_feu: Option<&[String; 3]>, en_direct: bool) -> Option<bool> {
        match e {
            Element::Categorie { guid, avant } => match categorie_en_usage(guid) {
                Some(c) => Some(c == avant),
                None if en_direct => None,
                None => categorie(guid).map(|c| c == avant),
            },
            Element::ProfilPublic { parametre, avant } => {
                let i = super::PARAMETRES_PROFIL.iter().position(|(p, _)| p == parametre)?;
                pare_feu.and_then(|f| f.get(i)).map(|v| *v == *avant)
            }
            Element::NetBios { carte, avant } => netbios(carte).map(|v| v == *avant),
            Element::Dns { avant } => crate::optimiser::dns_relu(avant).map(|v| v == *avant),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::gestes;

    const G: &str = "{0B8C2F4E-1A2B-4C3D-9E8F-001122334455}";

    #[test]
    fn lecture_de_powershell() {
        let s = format!("CARTE|12|{G}\nPROFIL|{G}|Private|Café | le coin\nPAREFEU|True|NotConfigured|NotConfigured\n");
        let lu = lire_sortie(&s);
        assert_eq!(lu.carte, Some((12, G.to_string())));
        assert_eq!(
            lu.profil,
            Some((G.to_string(), "Private".into(), "Café | le coin".into()))
        );
        assert_eq!(
            lu.pare_feu,
            Some(["True".into(), "NotConfigured".into(), "NotConfigured".into()])
        );
        // Ce qui n'a pas la forme attendue n'est pas lu : jamais une valeur inventée.
        let lu = lire_sortie(&format!("CARTE|x|{G}\nPROFIL|{G}|Autre|x\nPAREFEU|Oui|Block|False\n"));
        assert_eq!(lu, Lu::default());
    }

    #[test]
    fn profil_public_le_strict_necessaire() {
        let lu = |a: &str, b: &str, c: &str| [a.to_string(), b.to_string(), c.to_string()];
        assert_eq!(
            a_changer_profil(&lu("True", "NotConfigured", "NotConfigured")),
            vec![("AllowInboundRules", "False", "NotConfigured".to_string())]
        );
        assert_eq!(a_changer_profil(&lu("NotConfigured", "Block", "False")), vec![]);
        let tout = a_changer_profil(&lu("False", "Allow", "True"));
        assert_eq!(tout.len(), 3);
        let parametres: Vec<(&str, &str)> = tout.iter().map(|(p, v, _)| (*p, *v)).collect();
        let ligne = regler_profil(&parametres).unwrap();
        assert_eq!(
            ligne,
            "vanguard:pare-feu-public actif=oui,entrant-bloque=oui,regles-entrantes=non"
        );
        // Ce que le mode pose durcit, et fait ce que faisait l'ancienne commande (le chemin de Wine).
        let acte = gestes::analyser_acte(&ligne).unwrap();
        assert!(acte.durcit() && !acte.affaiblit());
        assert_eq!(
            acte.powershell(),
            "Set-NetFirewallProfile -Profile Public -PolicyStore PersistentStore -Enabled True -DefaultInboundAction Block -AllowInboundRules False"
        );
        assert!(regler_profil(&[("Enabled", "$false")]).is_none());
        assert!(regler_profil(&[("DefaultOutboundAction", "Allow")]).is_none());
        assert!(regler_profil(&[]).is_none());
        // Couper le pare-feu ne s'écrit pas, ni « non configuré » là où le mode ne le change jamais.
        assert!(regler_profil(&[("Enabled", "False")]).is_none());
        assert!(regler_profil(&[("Enabled", "NotConfigured")]).is_none());
        assert!(regler_profil(&[("DefaultInboundAction", "NotConfigured")]).is_none());
        assert!(regler_profil(&[("AllowInboundRules", "False"), ("AllowInboundRules", "True")]).is_none());
        assert!(regler_profil(&[("allowinboundrules", "false")]).is_none());
    }

    #[test]
    fn remises_de_windows() {
        let coupe = Element::ProfilPublic {
            parametre: "Enabled".into(),
            avant: "False".into(),
        };
        assert!(
            remettre(&coupe).is_none(),
            "un pare-feu trouvé coupé n'est jamais recoupé"
        );
        let regle = Element::ProfilPublic {
            parametre: "AllowInboundRules".into(),
            avant: "NotConfigured".into(),
        };
        let ligne = remettre(&regle).unwrap();
        assert_eq!(ligne, "vanguard:pare-feu-public regles-entrantes=absent");
        // Une remise rend le PC moins protégé : la console élevée le dit avant l'accord.
        let acte = gestes::analyser_acte(&ligne).unwrap();
        assert!(acte.affaiblit() && !acte.durcit());
        assert_eq!(
            acte.powershell(),
            "Set-NetFirewallProfile -Profile Public -PolicyStore PersistentStore -AllowInboundRules NotConfigured"
        );
        let entrees = Element::ProfilPublic {
            parametre: "DefaultInboundAction".into(),
            avant: "Allow".into(),
        };
        assert_eq!(
            remettre(&entrees).as_deref(),
            Some("vanguard:pare-feu-public entrant-bloque=non")
        );
        let c = remettre(&Element::Categorie {
            guid: G.into(),
            avant: "Private".into(),
        })
        .unwrap();
        assert_eq!(c, format!("vanguard:reseau-categorie {G} prive"));
        let acte = gestes::analyser_acte(&c).unwrap();
        assert!(acte.affaiblit());
        let ps = acte.powershell();
        assert!(
            ps.contains(&format!("InstanceID -eq '{G}'")) && ps.contains("-Value 1 -Type DWord"),
            "{ps}"
        );
        let n = remettre(&Element::NetBios {
            carte: G.into(),
            avant: 0,
        })
        .unwrap();
        assert!(
            n.contains(&format!("SettingID='{G}'")) && n.contains("[uint32]0"),
            "{n}"
        );
        assert!(netbios("{pas un guid}", 2).is_none() && netbios(G, 3).is_none());
        assert!(rendre_prive("{0B8C2F4E-1A2B-4C3D-9E8F-001122334455}'; Remove-Item C:\\ #").is_none());
        assert!(rendre_public("{0B8C2F4E-1A2B-4C3D-9E8F-001122334455}'; Remove-Item C:\\ #").is_none());
        let p = rendre_public(G).unwrap();
        assert_eq!(p, format!("vanguard:reseau-categorie {G} public"));
        assert!(gestes::analyser_acte(&p).unwrap().durcit());
        // Un GUID en minuscules est réécrit dans la forme unique que relit le processus élevé.
        assert_eq!(rendre_public(&G.to_lowercase()), Some(p));
    }
}

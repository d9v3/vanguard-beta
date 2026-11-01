//! Les corrections natives de Windows : une liste fermée, appliquée par les fonctions de Windows (registre…) dans
//! le processus élevé (`eleve`), au lieu d'un script PowerShell. Une correction se désigne par `vanguard:<id>` :
//! jamais du code ni une commande libre. C'est le processus élevé qui relit chaque ligne contre cette table : ce
//! que le clic d'administrateur autorise, ce sont ces gestes-là, et rien d'autre. Chaque entrée garde son
//! équivalent PowerShell, pour le chemin par script (Wine, une DLL posée à côté de Vanguard).
//!
//! La règle d'origine, « un identifiant, jamais un paramètre », vaut pour cette table. Depuis le 22 octobre 2026, le
//! processus élevé accepte aussi les ordres du blocage (`protection::blocage::ordres`), qui portent des paramètres
//! TYPÉS (une adresse, un port, un numéro de processus et son programme, une valeur d'avant) : il les reparse, refuse
//! toute autre forme, puis rejuge lui-même chaque geste (garde-fous du blocage). Toujours pas de texte libre.

use crate::langue::anglais;

/// Devant chaque identifiant, pour qu'aucune commande PowerShell ne soit prise pour une correction native.
pub(crate) const PREFIXE: &str = "vanguard:";
/// Au-delà, une liste n'est pas celle d'une session de Vanguard.
#[cfg(test)]
pub(crate) const LIGNES_MAX: usize = 64;
/// Une ligne plus longue qu'un identifiant ne vient pas de Vanguard (le canal la refuse avant de l'analyser).
pub(crate) const LIGNE_MAX: usize = 256;

/// L'identifiant du point de restauration, passé en premier par `reparer::point_restauration`.
pub(crate) const POINT: &str = "vanguard:point-de-restauration";

/// Ce qu'une correction change.
pub(crate) enum Geste {
    /// Une valeur DWORD sous HKEY_LOCAL_MACHINE, mise à la donnée voulue (la clé est créée si elle manque).
    Dword {
        cle: &'static str,
        valeur: &'static str,
        donnee: u32,
    },
    /// Le point de restauration, avant de toucher au système.
    PointDeRestauration,
}

pub(crate) struct Correction {
    /// Sans le préfixe : `[a-z0-9-]`, 40 caractères au plus.
    pub id: &'static str,
    pub geste: Geste,
    fr: &'static str,
    en: &'static str,
}

impl Correction {
    /// Ce que la correction fait, en une phrase, montré par le processus élevé avant de la faire.
    pub(crate) fn texte(&self) -> &'static str {
        if anglais() { self.en } else { self.fr }
    }

    /// L'équivalent PowerShell, pour le chemin par script. La clé n'est créée que si elle manque : « New-Item -Force »
    /// sur une clé existante l'écraserait avec ses autres valeurs.
    pub(crate) fn powershell(&self) -> String {
        match self.geste {
            Geste::Dword { cle, valeur, donnee } => format!(
                "if (-not (Test-Path -LiteralPath 'HKLM:\\{cle}')) {{ New-Item -Path 'HKLM:\\{cle}' -Force | Out-Null }}; \
                 Set-ItemProperty -LiteralPath 'HKLM:\\{cle}' -Name {valeur} -Value {donnee} -Type DWord"
            ),
            Geste::PointDeRestauration => crate::reparer::point_restauration_powershell(),
        }
    }
}

const WDIGEST: &str = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest";
const RDP_TCP: &str = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
const LSA: &str = r"SYSTEM\CurrentControlSet\Control\Lsa";
const UAC: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
const APPINIT: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
const APPINIT_32: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows";
/// La clé que le basculeur « Liste de blocage des pilotes vulnérables » de Sécurité Windows écrit (Isolation du noyau).
pub(crate) const PILOTES_VULNERABLES: &str = r"SYSTEM\CurrentControlSet\Control\CI\Config";

/// La liste fermée. Chaque entrée renforce la sécurité ; aucune ne coupe un pare-feu, Defender, BitLocker ou l'UAC,
/// ni une connexion à distance en cours (`rdp-nla` exige une authentification, il ne ferme pas le Bureau à distance).
static TABLE: &[Correction] = &[
    Correction {
        id: "point-de-restauration",
        geste: Geste::PointDeRestauration,
        fr: "Point de restauration, pour pouvoir revenir en arrière",
        en: "Restore point, so you can go back",
    },
    Correction {
        id: "wdigest-coupe",
        geste: Geste::Dword {
            cle: WDIGEST,
            valeur: "UseLogonCredential",
            donnee: 0,
        },
        fr: "Couper WDigest : plus de mot de passe en clair dans la mémoire (HKLM\\…\\WDigest, UseLogonCredential = 0)",
        en: "Turn WDigest off: no more clear-text password in memory (HKLM\\...\\WDigest, UseLogonCredential = 0)",
    },
    Correction {
        id: "rdp-nla",
        geste: Geste::Dword {
            cle: RDP_TCP,
            valeur: "UserAuthentication",
            donnee: 1,
        },
        fr: "Exiger l'authentification au niveau réseau (NLA) pour le Bureau à distance (HKLM\\…\\RDP-Tcp, UserAuthentication = 1)",
        en: "Require Network Level Authentication (NLA) for Remote Desktop (HKLM\\...\\RDP-Tcp, UserAuthentication = 1)",
    },
    dword(
        "comptes-sans-mdp-limites",
        LSA,
        "LimitBlankPasswordUse",
        1,
        "Réserver les comptes sans mot de passe à l'écran de connexion (HKLM\\…\\Lsa, LimitBlankPasswordUse = 1)",
        "Restrict password-less accounts to the sign-in screen (HKLM\\...\\Lsa, LimitBlankPasswordUse = 1)",
    ),
    dword(
        "ntlmv2-seul",
        LSA,
        "LmCompatibilityLevel",
        3,
        "NTLMv2 seulement, le réglage par défaut de Windows (HKLM\\…\\Lsa, LmCompatibilityLevel = 3)",
        "NTLMv2 only, the Windows default (HKLM\\...\\Lsa, LmCompatibilityLevel = 3)",
    ),
    dword(
        "sam-anonyme-ferme",
        LSA,
        "RestrictAnonymousSAM",
        1,
        "Refuser la liste des comptes aux connexions anonymes (HKLM\\…\\Lsa, RestrictAnonymousSAM = 1)",
        "Refuse the account list to anonymous connections (HKLM\\...\\Lsa, RestrictAnonymousSAM = 1)",
    ),
    dword(
        "anonyme-hors-tous",
        LSA,
        "EveryoneIncludesAnonymous",
        0,
        "Sortir l'anonyme du groupe « Tout le monde » (HKLM\\…\\Lsa, EveryoneIncludesAnonymous = 0)",
        "Take anonymous out of the Everyone group (HKLM\\...\\Lsa, EveryoneIncludesAnonymous = 0)",
    ),
    dword(
        "lmhash-coupe",
        LSA,
        "NoLMHash",
        1,
        "Ne plus garder l'ancienne forme LM des mots de passe (HKLM\\…\\Lsa, NoLMHash = 1)",
        "Stop keeping the old LM form of passwords (HKLM\\...\\Lsa, NoLMHash = 1)",
    ),
    dword(
        "appinit-coupe",
        APPINIT,
        "LoadAppInit_DLLs",
        0,
        "Ne plus charger les DLL AppInit, le réglage d'origine (HKLM\\…\\Windows, LoadAppInit_DLLs = 0)",
        "Stop loading AppInit DLLs, the original setting (HKLM\\...\\Windows, LoadAppInit_DLLs = 0)",
    ),
    dword(
        "appinit-coupe-32",
        APPINIT_32,
        "LoadAppInit_DLLs",
        0,
        "Ne plus charger les DLL AppInit des programmes 32 bits (HKLM\\…\\WOW6432Node\\…\\Windows, LoadAppInit_DLLs = 0)",
        "Stop loading AppInit DLLs in 32-bit programs (HKLM\\...\\WOW6432Node\\...\\Windows, LoadAppInit_DLLs = 0)",
    ),
    dword(
        "wpad-coupe",
        r"SYSTEM\CurrentControlSet\Services\WinHttp\Parameters",
        "DisableWpad",
        1,
        "Couper la découverte automatique du proxy (WPAD) (HKLM\\…\\WinHttp\\Parameters, DisableWpad = 1)",
        "Turn proxy auto-discovery (WPAD) off (HKLM\\...\\WinHttp\\Parameters, DisableWpad = 1)",
    ),
    dword(
        "smb-invite-coupe",
        r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
        "AllowInsecureGuestAuth",
        0,
        "Couper les connexions invité aux partages (HKLM\\…\\LanmanWorkstation\\Parameters, AllowInsecureGuestAuth = 0)",
        "Turn guest connections to shares off (HKLM\\...\\LanmanWorkstation\\Parameters, AllowInsecureGuestAuth = 0)",
    ),
    dword(
        "journal-powershell",
        r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        "EnableScriptBlockLogging",
        1,
        "Journaliser les scripts PowerShell (HKLM\\…\\ScriptBlockLogging, EnableScriptBlockLogging = 1)",
        "Log PowerShell scripts (HKLM\\...\\ScriptBlockLogging, EnableScriptBlockLogging = 1)",
    ),
    dword(
        "uac-active",
        UAC,
        "EnableLUA",
        1,
        "Réactiver l'UAC, effectif après redémarrage (HKLM\\…\\Policies\\System, EnableLUA = 1)",
        "Turn UAC back on, effective after a restart (HKLM\\...\\Policies\\System, EnableLUA = 1)",
    ),
    dword(
        "uac-demande",
        UAC,
        "ConsentPromptBehaviorAdmin",
        5,
        "Remettre la demande de l'UAC, le réglage de Windows (HKLM\\…\\Policies\\System, ConsentPromptBehaviorAdmin = 5)",
        "Bring back the UAC prompt, the Windows setting (HKLM\\...\\Policies\\System, ConsentPromptBehaviorAdmin = 5)",
    ),
    dword(
        "pilotes-vulnerables-bloques",
        PILOTES_VULNERABLES,
        "VulnerableDriverBlocklistEnable",
        1,
        "Activer la liste de Microsoft qui bloque les pilotes vulnérables, effectif après redémarrage (HKLM\\…\\CI\\Config, VulnerableDriverBlocklistEnable = 1)",
        "Turn on Microsoft's vulnerable driver blocklist, effective after a restart (HKLM\\...\\CI\\Config, VulnerableDriverBlocklistEnable = 1)",
    ),
    dword(
        "llmnr-coupe",
        r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
        "EnableMulticast",
        0,
        "Couper LLMNR, la résolution de noms par diffusion (HKLM\\…\\DNSClient, EnableMulticast = 0)",
        "Turn LLMNR (broadcast name resolution) off (HKLM\\...\\DNSClient, EnableMulticast = 0)",
    ),
];

/// Une entrée de la table qui met une valeur DWORD sous HKLM.
const fn dword(
    id: &'static str,
    cle: &'static str,
    valeur: &'static str,
    donnee: u32,
    fr: &'static str,
    en: &'static str,
) -> Correction {
    Correction {
        id,
        geste: Geste::Dword { cle, valeur, donnee },
        fr,
        en,
    }
}

/// L'identifiant complet d'une correction de la table (« vanguard:wdigest-coupe »), à mettre dans un `Correctif`.
pub(crate) fn id(court: &str) -> String {
    debug_assert!(
        TABLE.iter().any(|c| c.id == court),
        "correction native inconnue : {court}"
    );
    format!("{PREFIXE}{court}")
}

/// La correction désignée par une ligne, si et seulement si la ligne est exactement un identifiant de la table :
/// le préfixe, puis des minuscules, chiffres et tirets, rien d'autre (ni espace, ni paramètre, ni fin de ligne).
pub(crate) fn analyser(ligne: &str) -> Option<&'static Correction> {
    if ligne.len() > LIGNE_MAX {
        return None;
    }
    let court = ligne.strip_prefix(PREFIXE)?;
    let forme = !court.is_empty()
        && court.len() <= 40
        && court
            .bytes()
            .all(|o| o.is_ascii_lowercase() || o.is_ascii_digit() || o == b'-');
    if !forme {
        return None;
    }
    TABLE.iter().find(|c| c.id == court)
}

/// Comment se défait une correction faite de ces commandes : une correction native (un DWORD sous HKLM) durcit
/// Windows (WDigest, NLA, Lsa, UAC…) ; c'est une protection, que Vanguard ne défait jamais. Défaite d'après une note de
/// reglages.json, que tout programme du compte peut réécrire, elle remettait en administrateur la valeur qu'une
/// note forgée choisissait (UseLogonCredential = 1). La personne peut toujours la changer elle-même dans Windows. Un
/// acte de service qui durcit (`gestes::SERVICES`, RemoteRegistry désactivé…) compte de même, comme le pare-feu remis
/// en marche, le profil Public durci ou un réseau passé en Public ; un acte qui ne durcit pas (arrêter puis relancer
/// wuauserv), comme le reste (PowerShell, le point de restauration seul, un dossier vidé), n'est pas relevé.
pub(crate) fn comment_defaire(commandes: &[String]) -> crate::machine::Defaire {
    use crate::machine::Defaire;
    use crate::machine::gestes::{self, Acte};
    // Chaque ligne : `Some(durcit)`, ou `None` si elle n'est ni une correction de la table ni un acte de service.
    let durcies: Option<Vec<bool>> = commandes
        .iter()
        .map(|l| match (analyser(l), gestes::analyser_acte(l)) {
            (Some(c), _) => Some(matches!(c.geste, Geste::Dword { .. })),
            (
                None,
                Some(a @ (Acte::Service(_) | Acte::PareFeuActif | Acte::PareFeuPublic(_) | Acte::ReseauCategorie(_))),
            ) => Some(a.durcit()),
            _ => None,
        })
        .collect();
    match durcies {
        Some(d) if d.contains(&true) => Defaire::Protection,
        _ => Defaire::Inconnu,
    }
}

/// La phrase d'un acte de la table, montrée avant l'UAC et dans la fenêtre administrateur. Un acte qui affaiblit
/// (remettre en route ce que Vanguard avait coupé, à l'annulation d'un réglage) le dit en toutes lettres.
pub(crate) fn texte_acte(acte: &crate::machine::gestes::Acte) -> String {
    use crate::ui::trf;
    let phrase = phrase_acte(acte);
    if acte.affaiblit() {
        trf!(
            "{phrase} — rend le PC moins protégé (remet ce que Vanguard avait coupé)",
            "{phrase} — makes the PC less protected (restores what Vanguard had turned off)"
        )
    } else {
        phrase
    }
}

/// Un réglage du profil Public, en clair : « entrées bloquées par défaut : oui ».
fn texte_reglage_public(r: crate::machine::gestes::ReglagePublic, v: crate::machine::gestes::ValeurPublic) -> String {
    use crate::machine::gestes::{ReglagePublic, ValeurPublic};
    use crate::ui::tr;
    let nom = match r {
        ReglagePublic::Actif => tr!("allumé", "on"),
        ReglagePublic::EntrantBloque => tr!("entrées bloquées par défaut", "inbound blocked by default"),
        ReglagePublic::ReglesEntrantes => tr!("entrées des programmes autorisés", "inbound for allowed programs"),
    };
    let valeur = match v {
        ValeurPublic::Oui => tr!("oui", "yes"),
        ValeurPublic::Non => tr!("non", "no"),
        ValeurPublic::Absent => tr!("non configuré (valeur de Windows)", "not configured (Windows default)"),
    };
    crate::ui::trf!("{nom} : {valeur}", "{nom}: {valeur}")
}

fn phrase_acte(acte: &crate::machine::gestes::Acte) -> String {
    use crate::machine::gestes::{ACoter, Acte, Action, Categorie, Vidable};
    use crate::ui::{tr, trf};
    match acte {
        Acte::Service(s) => {
            let n = s.nom;
            match s.action {
                Action::Arreter => trf!(
                    "Arrêter le service {n} (et les services qui en dépendent)",
                    "Stop the {n} service (and the services that depend on it)"
                ),
                Action::Demarrer => trf!("Démarrer le service {n}", "Start the {n} service"),
                Action::Redemarrer => trf!(
                    "Redémarrer le service {n} (et les services qui en dépendent)",
                    "Restart the {n} service (and the services that depend on it)"
                ),
                Action::Desactive => trf!("Désactiver le service {n}", "Disable the {n} service"),
                Action::Manuel => trf!(
                    "Mettre le service {n} en démarrage manuel",
                    "Set the {n} service to manual start"
                ),
                Action::Auto => trf!(
                    "Mettre le service {n} en démarrage automatique",
                    "Set the {n} service to automatic start"
                ),
                Action::Reactiver => trf!(
                    "Remettre le service {n} en manuel s'il est désactivé",
                    "Set the {n} service back to manual if it is disabled"
                ),
            }
        }
        Acte::Vider(Vidable::TempWindows) => tr!(
            r"Vider le dossier temporaire de Windows (Windows\Temp ; ce qui est en usage reste)",
            r"Empty the Windows temporary folder (Windows\Temp; what is in use stays)"
        )
        .to_string(),
        Acte::Vider(Vidable::WuTelechargements) => tr!(
            r"Vider les téléchargements de Windows Update (Windows\SoftwareDistribution\Download)",
            r"Empty the Windows Update downloads (Windows\SoftwareDistribution\Download)"
        )
        .to_string(),
        Acte::ViderFileImpression => tr!(
            "Vider la file d'impression (les fichiers du dossier du spouleur)",
            "Empty the print queue (the files in the spooler folder)"
        )
        .to_string(),
        Acte::MettreDeCote(ACoter::SoftwareDistribution) => tr!(
            r"Mettre de côté le cache de Windows Update (Windows\SoftwareDistribution, renommé avec la date)",
            r"Set aside the Windows Update cache (Windows\SoftwareDistribution, renamed with the date)"
        )
        .to_string(),
        Acte::MettreDeCote(ACoter::Catroot2) => tr!(
            r"Mettre de côté le catalogue des signatures (Windows\System32\catroot2, renommé avec la date)",
            r"Set aside the signature catalog (Windows\System32\catroot2, renamed with the date)"
        )
        .to_string(),
        Acte::PareFeuActif => tr!(
            "Remettre le Pare-feu Windows en marche sur les trois profils (domaine, privé, public)",
            "Turn the Windows Firewall back on for the three profiles (domain, private, public)"
        )
        .to_string(),
        Acte::PareFeuPublic(p) => {
            let reglages: Vec<String> = p.reglages().map(|(r, v)| texte_reglage_public(r, v)).collect();
            trf!(
                "Profil Public du Pare-feu Windows : {}",
                "Windows Firewall Public profile: {}",
                reglages.join(tr!(" ; ", "; "))
            )
        }
        Acte::ReseauCategorie(r) => {
            let g = r.guid.texte();
            match r.categorie {
                Categorie::Public => trf!(
                    "Passer le réseau {g} en catégorie Public",
                    "Set the network {g} to the Public category"
                ),
                Categorie::Prive => trf!(
                    "Remettre le réseau {g} en catégorie Privé",
                    "Set the network {g} back to the Private category"
                ),
            }
        }
    }
}

/// La ligne est-elle faite par le processus élevé lui-même, sans PowerShell : une correction de la table, un ordre du
/// blocage permis sous Windows, un programme fixe (`gestes::PROGRAMMES`) ou un acte (`gestes::SERVICES`…) ?
pub(crate) fn native(ligne: &str) -> bool {
    analyser(ligne).is_some()
        || crate::protection::blocage::ordres::analyser(ligne).is_some_and(|o| o.permis_ici())
        || crate::machine::gestes::analyser_programme(ligne).is_some()
        || crate::machine::gestes::analyser_acte(ligne).is_some()
}

/// La phrase d'un programme fixe, avec la commande lancée : « Réparer les fichiers de Windows (SFC) : sfc.exe /scannow ».
pub(crate) fn texte_programme(a: &crate::machine::gestes::Appel) -> String {
    crate::trf!(
        "{} : {}",
        "{}: {}",
        if anglais() { a.programme.en } else { a.programme.fr },
        a.commande()
    )
}

/// La liste telle que le processus élevé la recevra, validée ligne à ligne, dans l'ordre ; `None` dès qu'une ligne
/// n'est pas une correction de la table, qu'il y en a trop, ou qu'une revient deux fois (une liste de Vanguard
/// n'applique jamais deux fois le même geste : une répétition est un signe de bricolage).
#[cfg(test)]
pub(crate) fn valider(lignes: &[String]) -> Option<Vec<&'static Correction>> {
    if lignes.is_empty() || lignes.len() > LIGNES_MAX {
        return None;
    }
    let mut vues = std::collections::HashSet::new();
    lignes
        .iter()
        .map(|l| analyser(l).filter(|c| vues.insert(c.id)))
        .collect()
}

/// Pour le chemin par script : chaque correction native, chaque ordre du blocage, chaque programme fixe et chaque acte,
/// remplacé par son équivalent PowerShell, le reste inchangé.
pub(crate) fn en_powershell(correctifs: &[Vec<String>]) -> Vec<Vec<String>> {
    use crate::protection::blocage::ordres;
    correctifs
        .iter()
        .map(|c| {
            c.iter()
                .map(|l| match (analyser(l), ordres::analyser(l)) {
                    (Some(c), _) => c.powershell(),
                    // Un ordre sans équivalent (couper une connexion, qu'aucun Vanguard ne demande sous Windows) : une
                    // erreur dite par la fenêtre, jamais un geste deviné.
                    (None, Some(o)) => ordres::powershell(&o)
                        .unwrap_or_else(|| "throw 'Vanguard : geste sans équivalent PowerShell'".to_string()),
                    (None, None) => {
                        use crate::machine::gestes;
                        match (gestes::analyser_programme(l), gestes::analyser_acte(l)) {
                            (Some(a), _) => a.powershell(),
                            (None, Some(a)) => a.powershell(),
                            (None, None) => l.clone(),
                        }
                    }
                })
                .collect()
        })
        .collect()
}

/// Le texte à montrer pour une commande : la phrase d'une correction native ou d'un ordre, la commande elle-même sinon.
pub(crate) fn affichable(commande: &str) -> String {
    if let Some(a) = crate::machine::gestes::analyser_programme(commande) {
        return texte_programme(&a);
    }
    if let Some(a) = crate::machine::gestes::analyser_acte(commande) {
        return texte_acte(&a);
    }
    analyser(commande).map_or_else(
        || crate::protection::blocage::ordres::affichable(commande),
        |c| c.texte().to_string(),
    )
}

/// La valeur actuelle de VulnerableDriverBlocklistEnable ; `None` : absente ou illisible.
pub(crate) fn valeur_pilotes() -> Option<u32> {
    let racine = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
    racine
        .open_subkey_with_flags(PILOTES_VULNERABLES, winreg::enums::KEY_READ)
        .ok()?
        .get_value::<u32, _>("VulnerableDriverBlocklistEnable")
        .ok()
}

/// La liste de blocage des pilotes vulnérables remise à sa valeur d'avant (`None` : la valeur est retirée), puis
/// relue : l'annulation exacte du geste « Pilotes » du blocage.
pub(crate) fn remettre_pilotes(avant: Option<u32>) -> crate::protection::blocage::ordres::Resultat {
    use crate::protection::blocage::ordres::Resultat;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE};
    const VALEUR: &str = "VulnerableDriverBlocklistEnable";
    let racine = winreg::RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Some(v) = avant {
        let ecrit = racine
            .create_subkey_with_flags(PILOTES_VULNERABLES, KEY_READ | KEY_WRITE)
            .and_then(|(k, _)| k.set_value(VALEUR, &v).map(|()| k))
            .and_then(|k| k.get_value::<u32, _>(VALEUR));
        return match ecrit {
            Ok(relu) if relu == v => Resultat::ok(),
            Ok(relu) => Resultat::echec(format!("relu {relu} au lieu de {v}")),
            Err(e) => Resultat::echec(e.to_string()),
        };
    }
    let cle = match racine.open_subkey_with_flags(PILOTES_VULNERABLES, KEY_READ | KEY_WRITE) {
        Ok(k) => k,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Resultat::ok(),
        Err(e) => return Resultat::echec(e.to_string()),
    };
    match cle.delete_value(VALEUR) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Resultat::echec(e.to_string()),
    }
    match cle.get_raw_value(VALEUR) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Resultat::ok(),
        _ => Resultat::echec(crate::tr!(
            "la valeur est toujours là après son retrait",
            "the value is still there after its removal"
        )),
    }
}

/// Résultat d'une correction appliquée par le processus élevé : réussie ou non, et la valeur d'avant quand il y en
/// a une (« 1 », « absent »), pour l'annuler exactement.
pub(crate) struct Resultat {
    pub reussi: bool,
    pub avant: Option<String>,
    pub raison: String,
}

/// Applique une correction de la table avec les droits du processus (élevé) : la valeur d'avant est lue, la nouvelle
/// écrite puis relue, et seul ce qui se relit tel qu'écrit compte comme réussi.
pub(crate) fn appliquer(c: &Correction) -> Resultat {
    match c.geste {
        Geste::Dword { cle, valeur, donnee } => ecrire_dword(cle, valeur, donnee),
        Geste::PointDeRestauration => {
            let (reussi, raison) = super::eleve::point_de_restauration();
            Resultat {
                reussi,
                avant: None,
                raison,
            }
        }
    }
}

/// La valeur d'avant, telle qu'on saura la remettre : un DWORD (« 1 »), « absent » (valeur absente) ou « clé absente ».
/// Autre type, ou lecture en échec : rien n'est changé, puisque le retour arrière effacerait une valeur qui existait.
fn valeur_d_avant(racine: &winreg::RegKey, cle: &str, valeur: &str) -> Result<String, String> {
    use std::io::ErrorKind::NotFound;
    use winreg::enums::{KEY_READ, RegType};
    let k = match racine.open_subkey_with_flags(cle, KEY_READ) {
        Ok(k) => k,
        Err(e) if e.kind() == NotFound => return Ok("clé absente".into()),
        Err(e) => return Err(format!("valeur d'avant illisible, rien changé : {e}")),
    };
    match k.get_raw_value(valeur) {
        Err(e) if e.kind() == NotFound => Ok("absent".into()),
        Err(e) => Err(format!("valeur d'avant illisible, rien changé : {e}")),
        // Un DWORD fait 4 octets : sinon, le même refus qu'un type inattendu, jamais une valeur inventée.
        Ok(brute) => match <[u8; 4]>::try_from(&*brute.bytes) {
            Ok(octets) if brute.vtype == RegType::REG_DWORD => Ok(u32::from_le_bytes(octets).to_string()),
            _ => Err(format!(
                "valeur d'avant de type inattendu ({:?}), rien changé",
                brute.vtype
            )),
        },
    }
}

fn ecrire_dword(cle: &str, valeur: &str, donnee: u32) -> Resultat {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE};
    let racine = winreg::RegKey::predef(HKEY_LOCAL_MACHINE);
    let avant = match valeur_d_avant(&racine, cle, valeur) {
        Ok(avant) => avant,
        Err(raison) => {
            return Resultat {
                reussi: false,
                avant: None,
                raison,
            };
        }
    };
    // RegCreateKeyEx ouvre une clé qui existe sans toucher à ses valeurs (au contraire de New-Item -Force).
    let ecrit = racine
        .create_subkey_with_flags(cle, KEY_READ | KEY_WRITE)
        .and_then(|(k, _)| k.set_value(valeur, &donnee).map(|()| k))
        .and_then(|k| k.get_value::<u32, _>(valeur));
    match ecrit {
        Ok(relu) if relu == donnee => Resultat {
            reussi: true,
            avant: Some(avant),
            raison: String::new(),
        },
        Ok(relu) => Resultat {
            reussi: false,
            avant: Some(avant),
            raison: format!("relu {relu} au lieu de {donnee}"),
        },
        Err(e) => Resultat {
            reussi: false,
            avant: Some(avant),
            raison: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Les actes du pare-feu et des réseaux : une remise est dite moins protégée avant l'accord, ce qui durcit ne
    /// l'est pas ; le pare-feu rallumé, le profil Public durci et un réseau passé en Public sont des protections, que
    /// « Défaire » ne propose pas ; une remise seule ne l'est pas. Le chemin de Wine reprend les commandes d'avant.
    #[test]
    fn les_actes_du_pare_feu_se_montrent_et_se_defont() {
        use crate::machine::Defaire;
        use crate::machine::gestes;
        let g = "{0B8C2F4E-1A2B-4C3D-9E8F-001122334455}";
        let moins = |l: &str| {
            let t = affichable(l);
            assert!(!t.starts_with("vanguard:"), "{t}");
            t.contains("moins protégé") || t.contains("less protected")
        };
        let durcies = [
            gestes::ligne_pare_feu_actif(),
            "vanguard:pare-feu-public actif=oui,entrant-bloque=oui,regles-entrantes=non".to_string(),
            format!("vanguard:reseau-categorie {g} public"),
        ];
        for l in &durcies {
            assert!(native(l) && !moins(l), "{l}");
            assert_eq!(comment_defaire(std::slice::from_ref(l)), Defaire::Protection, "{l}");
        }
        let remises = [
            "vanguard:pare-feu-public regles-entrantes=absent".to_string(),
            "vanguard:pare-feu-public entrant-bloque=non".to_string(),
            format!("vanguard:reseau-categorie {g} prive"),
        ];
        for l in &remises {
            assert!(native(l) && moins(l), "{l}");
            assert_eq!(comment_defaire(std::slice::from_ref(l)), Defaire::Inconnu, "{l}");
        }
        let ps = en_powershell(&[vec![gestes::ligne_pare_feu_actif()]]);
        assert_eq!(
            ps,
            vec![vec![
                "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True".to_string()
            ]]
        );
    }

    /// Lecture seule : rien n'est écrit dans le registre de la machine de test.
    #[test]
    fn valeur_d_avant_exacte_ou_refus() {
        let hklm = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
        let nt = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
        assert_eq!(
            valeur_d_avant(&hklm, r"SOFTWARE\VanguardInexistante", "X").unwrap(),
            "clé absente"
        );
        assert_eq!(valeur_d_avant(&hklm, nt, "VanguardInexistante").unwrap(), "absent");
        // Une chaîne (REG_SZ) ne se remet pas comme un DWORD : refusée, rien n'est changé.
        assert!(
            valeur_d_avant(&hklm, nt, "ProductName")
                .unwrap_err()
                .contains("type inattendu")
        );
    }

    #[test]
    fn la_table_est_bien_formee() {
        for c in TABLE {
            assert!(analyser(&id(c.id)).is_some_and(|t| std::ptr::eq(t, c)), "{}", c.id);
            assert!(!c.powershell().is_empty() && !c.texte().is_empty());
            // Aucun geste de la table n'affaiblit la sécurité : les valeurs écrites sont celles du durcissement.
            if let Geste::Dword { valeur, donnee, .. } = c.geste {
                const DURCIES: &[(&str, u32)] = &[
                    ("UseLogonCredential", 0),
                    ("UserAuthentication", 1),
                    ("LimitBlankPasswordUse", 1),
                    ("LmCompatibilityLevel", 3),
                    ("RestrictAnonymousSAM", 1),
                    ("EveryoneIncludesAnonymous", 0),
                    ("NoLMHash", 1),
                    ("LoadAppInit_DLLs", 0),
                    ("DisableWpad", 1),
                    ("AllowInsecureGuestAuth", 0),
                    ("EnableScriptBlockLogging", 1),
                    ("EnableLUA", 1),
                    ("ConsentPromptBehaviorAdmin", 5),
                    ("EnableMulticast", 0),
                    ("VulnerableDriverBlocklistEnable", 1),
                ];
                assert!(DURCIES.contains(&(valeur, donnee)), "{valeur} = {donnee}");
            }
        }
        assert_eq!(analyser(POINT).map(|c| c.id), Some("point-de-restauration"));
        // Le chemin par script crée la clé seulement si elle manque, puis écrit un vrai DWORD.
        let llmnr = analyser(&id("llmnr-coupe")).unwrap().powershell();
        assert!(llmnr.starts_with(
            "if (-not (Test-Path -LiteralPath 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient'))"
        ));
        assert!(llmnr.ends_with("-Name EnableMulticast -Value 0 -Type DWord"));
    }

    /// Tout ce qui n'est pas exactement un identifiant de la table est refusé : du PowerShell, un identifiant
    /// décoré, un paramètre, une casse différente, un caractère de contrôle, une ligne trop longue.
    #[test]
    fn les_lignes_hostiles_sont_refusees() {
        for hostile in [
            "",
            "vanguard:",
            "Set-ItemProperty HKLM:\\x -Name y -Value 1",
            "vanguard:wdigest-coupe; Remove-Item C:\\",
            "vanguard:wdigest-coupe ",
            " vanguard:wdigest-coupe",
            "vanguard:wdigest-coupe\n",
            "vanguard:wdigest-coupe\r",
            "vanguard:wdigest-coupe\0",
            "vanguard:WDIGEST-COUPE",
            "vanguard:wdigest-coupe 1",
            "vanguard:wdigest-coupe=1",
            "vanguard:../wdigest-coupe",
            "vanguard:inconnue",
            "vanguard:uac-coupe",
            "Vanguard:wdigest-coupe",
            "vanguard:vanguard:wdigest-coupe",
            "vanguard:wdigést-coupe",
        ] {
            assert!(analyser(hostile).is_none(), "{hostile:?}");
        }
        let longue = format!("vanguard:{}", "a".repeat(41));
        assert!(analyser(&longue).is_none());
        let tres_longue = format!("vanguard:wdigest-coupe{}", " ".repeat(LIGNE_MAX));
        assert!(analyser(&tres_longue).is_none());
    }

    #[test]
    fn la_liste_est_validee_entiere_ou_pas_du_tout() {
        let bonne = vec![POINT.to_string(), id("wdigest-coupe"), id("rdp-nla")];
        let v = valider(&bonne).unwrap();
        assert_eq!(
            v.iter().map(|c| c.id).collect::<Vec<_>>(),
            ["point-de-restauration", "wdigest-coupe", "rdp-nla"]
        );
        // Une seule ligne étrangère, et rien ne passe.
        let mut melee = bonne.clone();
        melee.push("Disable-LocalUser alice".into());
        assert!(valider(&melee).is_none());
        // Une répétition non plus, ni une liste vide ou trop longue.
        assert!(valider(&[id("rdp-nla"), id("rdp-nla")]).is_none());
        assert!(valider(&[]).is_none());
        assert!(valider(&vec![id("rdp-nla"); LIGNES_MAX + 1]).is_none());
    }

    #[test]
    fn liste_mixte_vers_powershell() {
        let correctifs = vec![
            vec![POINT.to_string()],
            vec![id("rdp-nla")],
            vec!["Update-MpSignature".to_string()],
            vec![crate::machine::gestes::ligne_programme("sfc-scannow", None)],
        ];
        assert!(correctifs[..2].iter().flatten().all(|l| native(l)));
        assert!(!native(&correctifs[2][0]) && native(&correctifs[3][0]));
        let ps = en_powershell(&correctifs);
        assert!(ps[0][0].contains("Checkpoint-Computer"), "{}", ps[0][0]);
        assert!(ps[1][0].contains("UserAuthentication -Value 1"), "{}", ps[1][0]);
        assert_eq!(ps[2][0], "Update-MpSignature");
        assert!(affichable(&id("rdp-nla")).contains("NLA"));
        assert_eq!(affichable("Update-MpSignature"), "Update-MpSignature");
        // Un programme fixe : par son chemin dans System32, jamais par le PATH ; montré avec sa commande.
        assert_eq!(ps[3][0], r#"& "$env:SystemRoot\System32\sfc.exe" /scannow"#);
        assert!(
            affichable(&correctifs[3][0]).ends_with("sfc.exe /scannow"),
            "{}",
            affichable(&correctifs[3][0])
        );
    }
}

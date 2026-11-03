//! Options de défense : ce que Microsoft Defender, ses règles ASR et le Pare-feu Windows appliquent vraiment, ce
//! qu'une stratégie (GPO, Intune) impose, la protection contre les falsifications, un antivirus tiers, et si le PC est
//! géré par une organisation ; puis les choix de la personne. Les lectures sont dans `machine::windows::defense_etat`
//! (WMI natif, INetFwPolicy2, registre) ; ici, le modèle, son interprétation, l'écran et le JSON, testés sur tous les
//! systèmes.
//!
//! L'écran (`ecran`) ne fait que choisir. Changer une option passe par les choix de la personne
//! (`vanguard:defender-choix`, `vanguard:defender-asr-choix`, `vanguard:defender-exclusion-ajouter`,
//! `vanguard:defender-dossiers-autoriser`, `vanguard:choix-noter`) et « Rallumer » (`vanguard:rallumer`), faits dans
//! la fenêtre administrateur : une baisse y est montrée, puis confirmée, et sa valeur d'avant notée
//! (`machine::choix_avant`). Une mesure qui manque
//! se dit « non vérifié », jamais saine. Le JSON ne porte que des identifiants et des nombres :
//! aucun chemin, nom de compte, de machine, de domaine ni d'antivirus.

use crate::machine::gestes::{ChoixAsr, ChoixDefender, GenreExclusion, IdChoix, ReglageDefender};
use crate::ui::{ACCENT, DISCRET, GRIS, RESET, VERT, largeur_affichee};
use crate::{tr, trf};

/// Les options de Defender lues dans `MSFT_MpPreference`, dans l'ordre de l'écran.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Opt {
    TempsReel,
    Cloud,
    Echantillons,
    Pua,
    Reseau,
    Dossiers,
    Comportement,
    Telechargements,
    Scripts,
    PremiereVue,
}

impl Opt {
    pub(crate) const TOUTES: [Opt; 10] = [
        Opt::TempsReel,
        Opt::Cloud,
        Opt::Echantillons,
        Opt::Pua,
        Opt::Reseau,
        Opt::Dossiers,
        Opt::Comportement,
        Opt::Telechargements,
        Opt::Scripts,
        Opt::PremiereVue,
    ];

    /// L'identifiant stable, celui du JSON et des notes du lot suivant (`defender-<id>`).
    pub(crate) fn id(self) -> &'static str {
        match self {
            Opt::TempsReel => "temps-reel",
            Opt::Cloud => "cloud",
            Opt::Echantillons => "echantillons",
            Opt::Pua => "pua",
            Opt::Reseau => "reseau",
            Opt::Dossiers => "dossiers",
            Opt::Comportement => "comportement",
            Opt::Telechargements => "telechargements",
            Opt::Scripts => "scripts",
            Opt::PremiereVue => "premiere-vue",
        }
    }

    /// Le champ de `MSFT_MpPreference`. Les `Disable…` sont des booléens, rangés en 1 (vrai : coupée) ou 0.
    pub(crate) fn champ(self) -> &'static str {
        match self {
            Opt::TempsReel => "DisableRealtimeMonitoring",
            Opt::Cloud => "MAPSReporting",
            Opt::Echantillons => "SubmitSamplesConsent",
            Opt::Pua => "PUAProtection",
            Opt::Reseau => "EnableNetworkProtection",
            Opt::Dossiers => "EnableControlledFolderAccess",
            Opt::Comportement => "DisableBehaviorMonitoring",
            Opt::Telechargements => "DisableIOAVProtection",
            Opt::Scripts => "DisableScriptScanning",
            Opt::PremiereVue => "DisableBlockAtFirstSeen",
        }
    }

    fn inverse(self) -> bool {
        matches!(
            self,
            Opt::TempsReel | Opt::Comportement | Opt::Telechargements | Opt::Scripts | Opt::PremiereVue
        )
    }

    /// Masculin en français (« coupé ») : le blocage, l'accès contrôlé.
    fn masculin(self) -> bool {
        matches!(self, Opt::Pua | Opt::Dossiers | Opt::PremiereVue)
    }

    pub(crate) fn libelle(self) -> &'static str {
        match self {
            Opt::TempsReel => tr!("Protection en temps réel", "Real-time protection"),
            Opt::Cloud => tr!("Protection fournie par le cloud", "Cloud-delivered protection"),
            Opt::Echantillons => tr!("Envoi d'échantillons", "Sample submission"),
            Opt::Pua => tr!("Blocage des logiciels indésirables", "Potentially unwanted apps"),
            Opt::Reseau => tr!("Protection réseau", "Network protection"),
            Opt::Dossiers => tr!("Accès contrôlé aux dossiers", "Controlled folder access"),
            Opt::Comportement => tr!("Surveillance du comportement", "Behavior monitoring"),
            Opt::Telechargements => tr!("Analyse des téléchargements", "Download scanning"),
            Opt::Scripts => tr!("Analyse des scripts", "Script scanning"),
            Opt::PremiereVue => tr!("Blocage à la première détection", "Block at first sight"),
        }
    }

    /// Ce que veut dire la valeur lue (`None` : illisible, non vérifiée).
    pub(crate) fn etat(self, v: Option<i64>) -> EtatOpt {
        let Some(v) = v else { return EtatOpt::Illisible };
        if self.inverse() {
            return match v {
                0 => EtatOpt::Allumee,
                1 => EtatOpt::Coupee,
                n => EtatOpt::Autre(n),
            };
        }
        match (self, v) {
            (_, 0) if self != Opt::Echantillons => EtatOpt::Coupee,
            (Opt::Cloud, 1) => EtatOpt::Base,
            (Opt::Cloud, 2) => EtatOpt::Avancee,
            (Opt::Echantillons, 0) => EtatOpt::ToujoursDemander,
            (Opt::Echantillons, 1) => EtatOpt::SursSansDemander,
            (Opt::Echantillons, 2) => EtatOpt::Jamais,
            (Opt::Echantillons, 3) => EtatOpt::TousSansDemander,
            (Opt::Pua | Opt::Reseau | Opt::Dossiers, 1) => EtatOpt::Bloque,
            (Opt::Pua | Opt::Reseau | Opt::Dossiers, 2) => EtatOpt::Audit,
            (Opt::Dossiers, 3) => EtatOpt::BloqueDisques,
            (Opt::Dossiers, 4) => EtatOpt::AuditDisques,
            (_, n) => EtatOpt::Autre(n),
        }
    }
}

/// L'état d'une option, une liste fermée.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum EtatOpt {
    Allumee,
    Coupee,
    Base,
    Avancee,
    ToujoursDemander,
    SursSansDemander,
    Jamais,
    TousSansDemander,
    Bloque,
    Audit,
    BloqueDisques,
    AuditDisques,
    /// Une valeur que Microsoft n'a pas documentée : montrée telle quelle, jamais jugée.
    Autre(i64),
    Illisible,
}

impl EtatOpt {
    pub(crate) fn id(self) -> &'static str {
        match self {
            EtatOpt::Allumee => "allumee",
            EtatOpt::Coupee => "coupee",
            EtatOpt::Base => "base",
            EtatOpt::Avancee => "avancee",
            EtatOpt::ToujoursDemander => "toujours-demander",
            EtatOpt::SursSansDemander => "surs-sans-demander",
            EtatOpt::Jamais => "jamais",
            EtatOpt::TousSansDemander => "tous-sans-demander",
            EtatOpt::Bloque => "bloque",
            EtatOpt::Audit => "audit",
            EtatOpt::BloqueDisques => "bloque-disques",
            EtatOpt::AuditDisques => "audit-disques",
            EtatOpt::Autre(_) => "autre",
            EtatOpt::Illisible => "illisible",
        }
    }

    fn texte(self, masculin: bool) -> String {
        match self {
            EtatOpt::Allumee if masculin => tr!("allumé", "on").to_string(),
            EtatOpt::Allumee => tr!("allumée", "on").to_string(),
            EtatOpt::Coupee if masculin => tr!("coupé", "off").to_string(),
            EtatOpt::Coupee => tr!("coupée", "off").to_string(),
            EtatOpt::Base => tr!("de base", "basic").to_string(),
            EtatOpt::Avancee => tr!("avancée", "advanced").to_string(),
            EtatOpt::ToujoursDemander => tr!("toujours demander", "always ask").to_string(),
            EtatOpt::SursSansDemander => tr!("fichiers sûrs, sans demander", "safe files, without asking").to_string(),
            EtatOpt::Jamais => tr!("jamais", "never").to_string(),
            EtatOpt::TousSansDemander => tr!("tous, sans demander", "all files, without asking").to_string(),
            EtatOpt::Bloque => tr!("bloque", "blocks").to_string(),
            EtatOpt::Audit => tr!("audit (signale sans bloquer)", "audit (reports, no block)").to_string(),
            EtatOpt::BloqueDisques => tr!("bloque (disques seulement)", "blocks (disks only)").to_string(),
            EtatOpt::AuditDisques => tr!("audit (disques seulement)", "audit (disks only)").to_string(),
            EtatOpt::Autre(n) => trf!("valeur {n} (inconnue)", "value {n} (unknown)"),
            EtatOpt::Illisible => tr!("non vérifié (illisible)", "not checked (unreadable)").to_string(),
        }
    }

    /// Vert quand l'option protège ; gris discret quand elle est coupée ou faible, sans alarme : c'est un état, pas
    /// un constat du bilan.
    fn couleur(self) -> &'static str {
        match self {
            EtatOpt::Allumee
            | EtatOpt::Avancee
            | EtatOpt::Bloque
            | EtatOpt::BloqueDisques
            | EtatOpt::TousSansDemander => VERT,
            EtatOpt::Coupee | EtatOpt::Jamais => ACCENT,
            _ => "",
        }
    }
}

/// Le mode de Defender, d'après `AMRunningMode` (et `AntivirusEnabled` quand ce champ manque).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ModeDefender {
    Actif,
    /// Un autre antivirus protège ; Defender ne fait que des analyses à la demande.
    Passif,
    /// Defender passif, mais le blocage EDR de Microsoft Defender for Endpoint agit encore.
    BlocageEdr,
    Coupe,
    Illisible,
}

impl ModeDefender {
    pub(crate) fn depuis(mode: Option<&str>, antivirus: Option<bool>) -> ModeDefender {
        let mode = mode.map(|m| m.trim().to_ascii_lowercase()).unwrap_or_default();
        match mode.as_str() {
            "" => match antivirus {
                Some(true) => ModeDefender::Actif,
                Some(false) => ModeDefender::Coupe,
                None => ModeDefender::Illisible,
            },
            "normal" if antivirus == Some(false) => ModeDefender::Coupe,
            "normal" => ModeDefender::Actif,
            "edr block mode" => ModeDefender::BlocageEdr,
            "not running" => ModeDefender::Coupe,
            m if m.contains("passive") => ModeDefender::Passif,
            _ => ModeDefender::Illisible,
        }
    }

    pub(crate) fn id(self) -> &'static str {
        match self {
            ModeDefender::Actif => "actif",
            ModeDefender::Passif => "passif",
            ModeDefender::BlocageEdr => "blocage-edr",
            ModeDefender::Coupe => "coupe",
            ModeDefender::Illisible => "illisible",
        }
    }
}

/// Qui a allumé la protection contre les falsifications (`TamperProtectionSource`), sans garder le texte lu.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum SourceFalsif {
    /// Intune, Defender for Endpoint, Configuration Manager : la personne ne peut pas la couper elle-même.
    Organisation,
    /// Sécurité Windows, à la main.
    Personne,
    Autre,
}

impl SourceFalsif {
    pub(crate) fn depuis(source: &str) -> Option<SourceFalsif> {
        let s = source.trim().to_ascii_lowercase();
        if s.is_empty() || s == "n/a" || s.starts_with("not ") {
            None
        } else if ["intune", "atp", "configmgr", "mde", "mem", "sense", "e5"]
            .iter()
            .any(|o| s.contains(o))
        {
            Some(SourceFalsif::Organisation)
        } else if s == "ui" {
            Some(SourceFalsif::Personne)
        } else {
            Some(SourceFalsif::Autre)
        }
    }

    fn id(self) -> &'static str {
        match self {
            SourceFalsif::Organisation => "organisation",
            SourceFalsif::Personne => "personne",
            SourceFalsif::Autre => "autre",
        }
    }
}

/// `MSFT_MpComputerStatus`.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Statut {
    pub(crate) mode: ModeDefender,
    /// `RealTimeProtectionEnabled` : l'effet, qui passe avant la préférence (une stratégie peut l'emporter).
    pub(crate) temps_reel: Option<bool>,
    pub(crate) falsifications: Option<bool>,
    pub(crate) source: Option<SourceFalsif>,
}

/// Un nombre d'éléments d'une liste de `MSFT_MpPreference`, ou la liste masquée aux comptes sans droits (« N/A: Must
/// be an administrator… »). Jamais les éléments eux-mêmes : des chemins.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Compte {
    Nombre(usize),
    Masque,
}

impl Compte {
    pub(crate) fn depuis(elements: &[String]) -> Compte {
        if elements.iter().any(|x| x.trim_start().starts_with("N/A")) {
            Compte::Masque
        } else {
            Compte::Nombre(elements.iter().filter(|x| !x.trim().is_empty()).count())
        }
    }

    fn json(self) -> serde_json::Value {
        match self {
            Compte::Nombre(n) => n.into(),
            Compte::Masque => serde_json::Value::Null,
        }
    }
}

/// L'action d'une règle ASR (`AttackSurfaceReductionRules_Actions`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ActionAsr {
    Coupee,
    Bloque,
    Audit,
    Avertit,
    /// 5 : « NotConfigured », la règle est listée sans être réglée.
    NonReglee,
    Autre(i64),
    /// La liste des actions est plus courte que celle des règles : rien n'est supposé.
    Illisible,
}

impl ActionAsr {
    pub(crate) fn depuis(v: Option<i64>) -> ActionAsr {
        match v {
            Some(0) => ActionAsr::Coupee,
            Some(1) => ActionAsr::Bloque,
            Some(2) => ActionAsr::Audit,
            Some(5) => ActionAsr::NonReglee,
            Some(6) => ActionAsr::Avertit,
            Some(n) => ActionAsr::Autre(n),
            None => ActionAsr::Illisible,
        }
    }

    fn texte(self) -> String {
        match self {
            // « Désactivée », le mot du plan (§2.2) et de Sécurité Windows : la règle reste listée, à 0.
            ActionAsr::Coupee => tr!("désactivée", "disabled").to_string(),
            ActionAsr::Bloque => tr!("bloque", "blocks").to_string(),
            ActionAsr::Audit => tr!("audit", "audit").to_string(),
            ActionAsr::Avertit => tr!("avertit", "warns").to_string(),
            ActionAsr::NonReglee => tr!("non réglée", "not set").to_string(),
            ActionAsr::Autre(n) => trf!("valeur {n}", "value {n}"),
            ActionAsr::Illisible => tr!("illisible", "unreadable").to_string(),
        }
    }

    fn valeur(self) -> Option<i64> {
        match self {
            ActionAsr::Coupee => Some(0),
            ActionAsr::Bloque => Some(1),
            ActionAsr::Audit => Some(2),
            ActionAsr::Avertit => Some(6),
            ActionAsr::NonReglee => Some(5),
            ActionAsr::Autre(n) => Some(n),
            ActionAsr::Illisible => None,
        }
    }
}

/// Les règles ASR lues : celles que Vanguard connaît, par leur identifiant de la table (jamais le texte lu), et le
/// nombre des autres, seulement comptées.
#[derive(Clone, Debug, PartialEq, Default)]
pub(crate) struct Asr {
    pub(crate) regles: Vec<(&'static str, ActionAsr)>,
    pub(crate) inconnues: usize,
}

impl Asr {
    /// Les deux listes parallèles de `MSFT_MpPreference` ; un identifiant écrit en majuscules ou entre accolades est
    /// le même.
    pub(crate) fn depuis(ids: &[String], actions: &[Option<i64>]) -> Asr {
        let mut asr = Asr::default();
        for (i, id) in ids.iter().enumerate() {
            let Some(connu) = asr_connue(id) else {
                asr.inconnues += 1;
                continue;
            };
            let action = ActionAsr::depuis(actions.get(i).copied().flatten());
            if !asr.regles.iter().any(|(r, _)| *r == connu) {
                asr.regles.push((connu, action));
            }
        }
        asr.regles
            .sort_by_key(|(id, _)| ASR_TOUTES.iter().position(|r| r == id).unwrap_or(usize::MAX));
        asr
    }

    fn action(&self, id: &str) -> Option<ActionAsr> {
        self.regles.iter().find(|(r, _)| *r == id).map(|(_, a)| *a)
    }
}

/// Un identifiant de règle ASR de la table, quelle que soit la casse ou les accolades ; `None` pour un autre texte.
pub(crate) fn asr_connue(id: &str) -> Option<&'static str> {
    let propre = id
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .to_ascii_lowercase();
    ASR_TOUTES.iter().copied().find(|r| *r == propre)
}

/// Les 19 règles ASR que Microsoft documente (« Attack surface reduction rules reference »), tenues par les gestes
/// (`vanguard:defender-asr-choix` ne vise qu'elles).
pub(crate) use crate::machine::gestes::ASR_TOUTES;

/// Ce que bloque une règle ASR, pour l'écran ; `None` hors de la table.
pub(crate) fn nom_asr(id: &str) -> Option<&'static str> {
    Some(match id {
        "56a863a9-875e-4185-98a7-b882c64b5ce5" => {
            tr!("pilotes signés mais vulnérables", "vulnerable signed drivers")
        }
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" => {
            tr!("vol de mots de passe dans LSASS", "credential theft from LSASS")
        }
        "e6db77e5-3df2-4cf1-b95a-636979351e5b" => tr!("persistance par WMI", "persistence through WMI"),
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a" => {
            tr!("Office qui lance des programmes", "Office launching programs")
        }
        "3b576869-a4ec-4529-8536-b80a7769e899" => {
            tr!("Office qui crée des exécutables", "Office creating executables")
        }
        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" => tr!("Office qui injecte du code", "Office injecting code"),
        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" => {
            tr!("macros Office qui appellent Win32", "Office macros calling Win32")
        }
        "26190899-1602-49e8-8b27-eb1d0a1ce869" => {
            tr!("Outlook qui lance des programmes", "Outlook launching programs")
        }
        "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" => {
            tr!(
                "Adobe Reader qui lance des programmes",
                "Adobe Reader launching programs"
            )
        }
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" => {
            tr!("exécutables reçus par courriel", "executables from email")
        }
        "d3e037e1-3eb8-44c8-a917-57927947596d" => {
            tr!(
                "scripts JS/VBS qui lancent un téléchargement",
                "JS/VBS launching downloads"
            )
        }
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc" => {
            tr!("scripts peut-être masqués", "possibly obfuscated scripts")
        }
        "01443614-cd74-433a-b99e-2ecdc07bfc25" => {
            tr!(
                "exécutables rares, récents ou inconnus",
                "rare, new or unknown executables"
            )
        }
        "c1db55ab-c21a-4637-bb3f-a12568109d35" => {
            tr!(
                "protection avancée contre les rançongiciels",
                "advanced ransomware protection"
            )
        }
        "d1e49aac-8f56-4280-b9ba-993a6d77406c" => {
            tr!("programmes lancés par PsExec et WMI", "processes from PsExec and WMI")
        }
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" => {
            tr!("programmes non signés sur clé USB", "unsigned programs from USB")
        }
        "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" => {
            tr!("outils système copiés ou imités", "copied or impersonated system tools")
        }
        "33ddedf1-c6e0-47cb-833e-de6133960387" => {
            tr!("redémarrage en mode sans échec", "rebooting into Safe Mode")
        }
        "a8f5898e-1dc8-49a9-9878-85004b8a61e6" => {
            tr!("webshells sur un serveur", "webshells on servers")
        }
        _ => return None,
    })
}

/// `MSFT_MpPreference`.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Preferences {
    /// Dans l'ordre de `Opt::TOUTES`.
    pub(crate) valeurs: [Option<i64>; 10],
    pub(crate) asr: Asr,
    /// Dossiers, programmes, extensions exclus de l'analyse.
    pub(crate) exclusions: [Compte; 3],
    /// Programmes permis malgré l'accès contrôlé aux dossiers.
    pub(crate) applis_permises: Compte,
}

impl Preferences {
    fn valeur(&self, o: Opt) -> Option<i64> {
        Opt::TOUTES
            .iter()
            .position(|x| *x == o)
            .and_then(|i| self.valeurs.get(i).copied().flatten())
    }
}

/// Une valeur de stratégie : la clé sous HKLM et le nom de la valeur. Sa seule présence dit qu'une stratégie impose le
/// réglage, quelle que soit la valeur (« Désactivé » dans gpedit pose souvent 0, c'est encore imposer).
pub(crate) type Emplacement = (&'static str, &'static str);

const GPO: &str = r"SOFTWARE\Policies\Microsoft\Windows Defender";
const MDM: &str = r"SOFTWARE\Microsoft\PolicyManager\current\device\Defender";

/// Où une stratégie de groupe (GPO) ou une gestion (Intune, CSP Defender) impose chaque option.
pub(crate) fn strategies_de(o: Opt) -> &'static [Emplacement] {
    match o {
        Opt::TempsReel => &[
            (
                r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
                "DisableRealtimeMonitoring",
            ),
            (MDM, "AllowRealtimeMonitoring"),
        ],
        Opt::Cloud => &[
            (
                r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet",
                "SpynetReporting",
            ),
            (MDM, "AllowCloudProtection"),
        ],
        Opt::Echantillons => &[
            (
                r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet",
                "SubmitSamplesConsent",
            ),
            (MDM, "SubmitSamplesConsent"),
        ],
        Opt::Pua => &[
            (GPO, "PUAProtection"),
            (r"SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine", "MpEnablePus"),
            (MDM, "PUAProtection"),
        ],
        Opt::Reseau => &[
            (
                r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection",
                "EnableNetworkProtection",
            ),
            (MDM, "EnableNetworkProtection"),
        ],
        Opt::Dossiers => &[
            (
                r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access",
                "EnableControlledFolderAccess",
            ),
            (MDM, "EnableControlledFolderAccess"),
        ],
        Opt::Comportement => &[
            (
                r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
                "DisableBehaviorMonitoring",
            ),
            (MDM, "AllowBehaviorMonitoring"),
        ],
        Opt::Telechargements => &[
            (
                r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
                "DisableIOAVProtection",
            ),
            (MDM, "AllowIOAVProtection"),
        ],
        Opt::Scripts => &[
            (
                r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
                "DisableScriptScanning",
            ),
            (MDM, "AllowScriptScanning"),
        ],
        Opt::PremiereVue => &[(
            r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet",
            "DisableBlockAtFirstSeen",
        )],
    }
}

/// Les règles ASR imposées par GPO : un nom de valeur par règle (son identifiant) sous cette clé.
pub(crate) const GPO_ASR: &str =
    r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules";
/// Par Intune : une seule chaîne « id=action|id=action ».
pub(crate) const MDM_ASR: Emplacement = (MDM, "AttackSurfaceReductionRules");
/// Les exclusions imposées : des valeurs sous ces clés de GPO, ou ces valeurs de MDM.
pub(crate) const GPO_EXCLUSIONS: [&str; 3] = [
    r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths",
    r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes",
    r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Extensions",
];
pub(crate) const MDM_EXCLUSIONS: [Emplacement; 3] = [
    (MDM, "ExcludedPaths"),
    (MDM, "ExcludedProcesses"),
    (MDM, "ExcludedExtensions"),
];
/// Le Pare-feu Windows imposé par GPO, par profil (le profil privé s'appelait « Standard » avant Windows Vista, et les
/// anciens modèles d'administration l'écrivent encore là).
pub(crate) const GPO_PARE_FEU: [&[&str]; 3] = [
    &[r"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"],
    &[
        r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile",
        r"SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile",
    ],
    &[r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"],
];
pub(crate) const VALEURS_PARE_FEU: [&str; 4] = [
    "EnableFirewall",
    "DefaultInboundAction",
    "DefaultOutboundAction",
    "DoNotAllowExceptions",
];

/// Les identifiants d'une chaîne de règles ASR d'Intune (« id=1|id=2 »), ceux de la table seulement.
pub(crate) fn asr_de_mdm(chaine: &str) -> Vec<&'static str> {
    chaine
        .split('|')
        .filter_map(|r| asr_connue(r.split('=').next().unwrap_or_default()))
        .collect()
}

/// Plusieurs présences lues : imposée si l'une l'est, libre si toutes se lisent absentes, sinon non vérifié.
pub(crate) fn une_presente(presences: impl IntoIterator<Item = Option<bool>>) -> Option<bool> {
    let mut toutes_lues = true;
    for p in presences {
        match p {
            Some(true) => return Some(true),
            Some(false) => {}
            None => toutes_lues = false,
        }
    }
    toutes_lues.then_some(false)
}

/// Ce que les stratégies imposent.
#[derive(Clone, Debug, PartialEq, Default)]
pub(crate) struct Strategies {
    /// Dans l'ordre de `Opt::TOUTES`.
    pub(crate) options: [Option<bool>; 10],
    /// Règles ASR imposées (identifiants de la table) ; `None` : illisible.
    pub(crate) asr: Option<Vec<&'static str>>,
    pub(crate) exclusions: Option<bool>,
    /// Domaine, privé, public.
    pub(crate) pare_feu: [Option<bool>; 3],
}

impl Strategies {
    fn option(&self, o: Opt) -> Option<bool> {
        Opt::TOUTES
            .iter()
            .position(|x| *x == o)
            .and_then(|i| self.options.get(i).copied().flatten())
    }
}

/// Un profil du Pare-feu Windows, lu par INetFwPolicy2 (l'effet : une stratégie passe avant le réglage local).
#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub(crate) struct Profil {
    pub(crate) actif: Option<bool>,
    pub(crate) entrees_bloquees: Option<bool>,
    pub(crate) sorties_bloquees: Option<bool>,
    pub(crate) tout_bloquer: Option<bool>,
}

/// INetFwPolicy2.
#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub(crate) struct PareFeu {
    /// `CurrentProfileTypes` : bits 1 domaine, 2 privé, 4 public.
    pub(crate) courants: Option<i32>,
    /// Domaine, privé, public.
    pub(crate) profils: [Profil; 3],
    /// `LocalPolicyModifyState` (`NET_FW_MODIFY_STATE`), pour le profil actuel seulement : 0 le réglage local compte,
    /// 1 une stratégie l'emporte, 2 tout l'entrant est bloqué (`BlockAllInboundTraffic`), une règle locale n'aurait
    /// pas d'effet.
    pub(crate) modification: Option<i32>,
    pub(crate) regles: Option<i32>,
}

const PROFILS: [(&str, i32); 3] = [("domaine", 1), ("prive", 2), ("public", 4)];

fn nom_profil(i: usize) -> &'static str {
    match i {
        0 => tr!("Domaine", "Domain"),
        1 => tr!("Privé", "Private"),
        _ => tr!("Public", "Public"),
    }
}

/// Un produit inscrit au Centre de sécurité Windows (`root\SecurityCenter2`).
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Produit {
    /// Prêt à montrer (`ui::affichable`), 64 caractères au plus ; jamais dans le JSON.
    pub(crate) nom: String,
    pub(crate) actif: Option<bool>,
    pub(crate) microsoft: bool,
}

impl Produit {
    /// `productState` : l'état d'activité est dans les bits 12 à 15 (1 : en marche), d'après ce qu'en écrivent les
    /// éditeurs ; un état illisible n'est pas « en marche ». Defender se reconnaît à son chemin `windowsdefender://`.
    pub(crate) fn depuis(nom: Option<&str>, etat: Option<i64>, chemin: Option<&str>) -> Produit {
        let brut = nom.unwrap_or_default();
        let microsoft = chemin.is_some_and(|c| c.trim().to_ascii_lowercase().starts_with("windowsdefender://"))
            || brut.to_ascii_lowercase().contains("windows defender")
            || brut.to_ascii_lowercase().contains("microsoft defender")
            || brut.eq_ignore_ascii_case("windows firewall");
        let mut nom = crate::ui::couper(&crate::ui::affichable(brut.trim()), 64);
        if nom.is_empty() {
            nom = tr!("(sans nom)", "(no name)").to_string();
        }
        Produit {
            nom,
            actif: etat.map(|e| (e >> 12) & 0xF == 1),
            microsoft,
        }
    }
}

/// Le Centre de sécurité ; `None` dans un champ : l'espace de noms n'existe pas (Windows Server) ou ne répond pas.
#[derive(Clone, Debug, PartialEq, Default)]
pub(crate) struct Centre {
    pub(crate) antivirus: Option<Vec<Produit>>,
    pub(crate) pare_feu: Option<Vec<Produit>>,
}

impl Centre {
    /// Le premier antivirus d'un autre éditeur, en marche.
    fn antivirus_tiers(&self) -> Option<&Produit> {
        self.antivirus
            .as_ref()?
            .iter()
            .find(|p| !p.microsoft && p.actif == Some(true))
    }

    fn pare_feu_tiers(&self) -> Option<&Produit> {
        self.pare_feu
            .as_ref()?
            .iter()
            .find(|p| !p.microsoft && p.actif == Some(true))
    }
}

/// Le PC est-il géré par une organisation ?
#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub(crate) struct Gestion {
    /// Joint à un domaine Active Directory (`Win32_ComputerSystem.PartOfDomain`).
    pub(crate) domaine: Option<bool>,
    /// Joint à Entra ID (Azure AD) : une entrée sous `CloudDomainJoin\JoinInfo`.
    pub(crate) entra: Option<bool>,
    /// Inscrit à une gestion (MDM, Intune) : une inscription active sous `Enrollments`.
    pub(crate) mdm: Option<bool>,
}

impl Gestion {
    pub(crate) fn geree(self) -> Option<bool> {
        une_presente([self.domaine, self.entra, self.mdm])
    }
}

/// Une inscription de `HKLM\SOFTWARE\Microsoft\Enrollments\<id>` est-elle une gestion active ? Windows y laisse des
/// entrées sans fournisseur ou abandonnées : seule compte celle qui nomme son fournisseur et dit « inscrite » (1).
pub(crate) fn inscription_active(fournisseur: Option<&str>, etat: Option<u32>) -> bool {
    fournisseur.is_some_and(|f| !f.trim().is_empty()) && etat == Some(1)
}

/// L'édition de Windows, d'après `EditionID`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Edition {
    /// Famille (« Core ») : Microsoft disait autrefois les règles ASR réservées à Pro et plus ; sa page de 2026 les dit
    /// disponibles partout où Defender l'est (`texte_effet_asr`).
    Famille,
    Serveur,
    Autre,
}

impl Edition {
    pub(crate) fn depuis(id: &str) -> Edition {
        let id = id.trim();
        if id.starts_with("Core") {
            Edition::Famille
        } else if id.starts_with("Server") {
            Edition::Serveur
        } else {
            Edition::Autre
        }
    }
}

/// Tout ce qui a été lu. `None` : la lecture n'a pas répondu (WMI absent, Wine, service arrêté).
#[derive(Clone, Debug, PartialEq, Default)]
pub(crate) struct Etat {
    pub(crate) statut: Option<Statut>,
    pub(crate) preferences: Option<Preferences>,
    pub(crate) strategies: Strategies,
    pub(crate) pare_feu: Option<PareFeu>,
    pub(crate) centre: Centre,
    pub(crate) gestion: Gestion,
    pub(crate) edition: Option<Edition>,
}

impl Etat {
    /// Les stratégies du pare-feu, par profil. Seule la GPO se lit : le Firewall CSP d'Intune range la sienne
    /// ailleurs. Sur un PC inscrit à une gestion, ou dont l'inscription ne se lit pas, « aucune GPO » ne prouve pas
    /// que rien n'est imposé : non vérifié.
    fn pare_feu_impose(&self) -> [Option<bool>; 3] {
        let mdm_possible = self.gestion.mdm != Some(false);
        self.strategies.pare_feu.map(|v| match v {
            Some(false) if mdm_possible => None,
            v => v,
        })
    }

    fn mode(&self) -> ModeDefender {
        self.statut.as_ref().map_or(ModeDefender::Illisible, |s| s.mode)
    }

    /// L'état d'une option ; pour le temps réel, l'effet relu dans `MSFT_MpComputerStatus` passe avant la
    /// préférence.
    fn etat_opt(&self, o: Opt) -> EtatOpt {
        if o == Opt::TempsReel
            && let Some(effet) = self.statut.as_ref().and_then(|s| s.temps_reel)
        {
            return if effet { EtatOpt::Allumee } else { EtatOpt::Coupee };
        }
        o.etat(self.preferences.as_ref().and_then(|p| p.valeur(o)))
    }
}

/// L'antivirus qui protège à la place de Defender, pour les textes ; « un autre antivirus » s'il n'est pas nommé.
fn nom_du_tiers(e: &Etat) -> String {
    e.centre.antivirus_tiers().map_or_else(
        || tr!("un autre antivirus", "another antivirus").to_string(),
        |p| p.nom.clone(),
    )
}

/// Une ligne « libellé ···· valeur », la valeur à la colonne 42.
fn pointilles(libelle: &str, valeur: &str, style: &str) -> String {
    const COLONNE: usize = 40;
    let points = COLONNE.saturating_sub(largeur_affichee(libelle) + 3).max(2);
    format!(
        "  {style}{libelle} {DISCRET}{}{RESET} {style}{valeur}{RESET}",
        "·".repeat(points)
    )
}

/// Un texte en retrait, coupé à la largeur de l'écran.
fn note(lignes: &mut Vec<String>, texte: &str, style: &str) {
    for l in crate::ui::envelopper(texte, crate::ui::LARGEUR - 6) {
        lignes.push(format!("      {style}{l}{RESET}"));
    }
}

/// Les réglages se lisent, mais pas l'état de Defender : rien ne dit qu'ils agissent.
fn effet_non_verifie() -> &'static str {
    tr!(
        "Effet non vérifié : l'état de Defender ne se lit pas.",
        "Effect not checked: Defender's state cannot be read."
    )
}

/// La note d'une valeur imposée ; une stratégie qui ne se lit pas le dit aussi, pour ne pas passer pour « libre ».
fn imposee(lignes: &mut Vec<String>, oui: Option<bool>) {
    let texte = match oui {
        Some(true) => tr!(
            "↳ imposé par une stratégie (GPO ou Intune) : Windows garde la valeur de la stratégie, quoi que Vanguard écrive.",
            "↳ enforced by a policy (GPO or Intune): Windows keeps the policy's value, whatever Vanguard writes."
        ),
        None => tr!(
            "↳ stratégie (GPO ou Intune) : non vérifiée.",
            "↳ policy (GPO or Intune): not checked."
        ),
        Some(false) => return,
    };
    note(lignes, texte, GRIS);
}

fn oui_non(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => tr!("oui", "yes"),
        Some(false) => tr!("non", "no"),
        None => tr!("non vérifié", "not checked"),
    }
}

/// Les lignes de l'écran, couleurs comprises, chacune dans `ui::LARGEUR` colonnes (le titre est à part).
pub(crate) fn lignes(e: &Etat) -> Vec<String> {
    let mut l = Vec::new();
    section_defender(&mut l, e);
    section_asr(&mut l, e);
    section_pare_feu(&mut l, e);
    section_centre(&mut l, e);
    section_gestion(&mut l, e);
    l
}

/// Ce que dit un Defender qui ne protège pas (plan §3.3, antivirus tiers) ; `None` s'il est actif ou illisible.
fn texte_mode(e: &Etat) -> Option<String> {
    match e.mode() {
        ModeDefender::Passif | ModeDefender::BlocageEdr => {
            let nom = nom_du_tiers(e);
            Some(trf!(
                "Defender est en mode passif : {nom} est votre antivirus. Les réglages de Defender et les règles ASR n'ont pas d'effet tant que {nom} protège ; réglez-le dans son propre programme. Le pare-feu reste réglable ici.",
                "Defender is in passive mode: {nom} is your antivirus. Defender settings and ASR rules have no effect while {nom} protects you; adjust it in its own program. The firewall can still be adjusted here."
            ))
        }
        ModeDefender::Coupe => Some(
            tr!(
                "Defender est coupé : ses réglages et ses règles ASR n'ont pas d'effet.",
                "Defender is off: its settings and ASR rules have no effect."
            )
            .to_string(),
        ),
        ModeDefender::Actif | ModeDefender::Illisible => None,
    }
}

fn section_defender(l: &mut Vec<String>, e: &Etat) {
    l.push(String::new());
    l.push(crate::ui::ligne_section("Microsoft Defender"));
    let mode = e.mode();
    let (texte, style) = match mode {
        ModeDefender::Actif => (tr!("actif", "active"), VERT),
        ModeDefender::Passif => (tr!("en mode passif", "in passive mode"), ACCENT),
        ModeDefender::BlocageEdr => (tr!("passif, blocage EDR", "passive, EDR block mode"), ACCENT),
        ModeDefender::Coupe => (tr!("coupé", "off"), ACCENT),
        ModeDefender::Illisible => (tr!("non vérifié (illisible)", "not checked (unreadable)"), ""),
    };
    l.push(pointilles(
        tr!("Antivirus Defender", "Defender antivirus"),
        texte,
        style,
    ));
    if let Some(t) = texte_mode(e) {
        note(l, &t, GRIS);
    }
    let statut = e.statut.as_ref();
    let falsif = statut.and_then(|s| s.falsifications);
    let (texte, style) = match falsif {
        Some(true) => (tr!("active", "on"), VERT),
        Some(false) => (tr!("coupée", "off"), ACCENT),
        None => (tr!("non vérifiée", "not checked"), ""),
    };
    l.push(pointilles(
        tr!("Contre les falsifications", "Tamper protection"),
        texte,
        style,
    ));
    if falsif == Some(true) {
        let texte = if statut.and_then(|s| s.source) == Some(SourceFalsif::Organisation) {
            tr!(
                "Imposée par votre organisation : vous ne pouvez pas la couper vous-même. Elle empêche tout programme, Vanguard compris, de changer la plupart de ces réglages.",
                "Enforced by your organization: you cannot turn it off yourself. It stops any program, Vanguard included, from changing most of these settings."
            )
        } else {
            tr!(
                "Elle empêche tout programme, Vanguard compris, de changer la plupart de ces réglages.",
                "It stops any program, Vanguard included, from changing most of these settings."
            )
        };
        note(l, texte, GRIS);
    }
    // Defender qui ne protège pas : ses options sont montrées, en gris, puisqu'elles n'agissent pas.
    // Mode illisible : la préférence est lue, pas son effet ; rien en vert.
    let gris = mode != ModeDefender::Actif;
    // Aucune stratégie lisible (registre refusé) : une seule note, pas dix.
    let aucune_lue = Opt::TOUTES.iter().all(|o| e.strategies.option(*o).is_none());
    for o in Opt::TOUTES {
        let etat = e.etat_opt(o);
        let style = if gris { GRIS } else { etat.couleur() };
        l.push(pointilles(o.libelle(), &etat.texte(o.masculin()), style));
        if !aucune_lue {
            imposee(l, e.strategies.option(o));
        }
    }
    if aucune_lue {
        imposee(l, None);
    }
    if mode == ModeDefender::Illisible && e.preferences.is_some() {
        note(l, effet_non_verifie(), GRIS);
    }
    let exclusions = e.preferences.as_ref().map(|p| p.exclusions);
    let (texte, style) = match exclusions {
        None => (
            tr!("non vérifiées (illisibles)", "not checked (unreadable)").to_string(),
            "",
        ),
        Some(c) if c.contains(&Compte::Masque) => (
            tr!("visibles avec l'accord admin.", "visible with admin approval").to_string(),
            GRIS,
        ),
        Some(c) => match c
            .iter()
            .map(|x| if let Compte::Nombre(n) = x { *n } else { 0 })
            .sum::<usize>()
        {
            0 => (tr!("aucune", "none").to_string(), VERT),
            total => (total.to_string(), ACCENT),
        },
    };
    l.push(pointilles(
        tr!("Exclusions de l'analyse", "Scan exclusions"),
        &texte,
        style,
    ));
    // Le détail tient sur sa propre ligne : des nombres seulement, jamais les chemins exclus.
    if let Some([Compte::Nombre(d), Compte::Nombre(p), Compte::Nombre(t)]) = exclusions
        && d + p + t > 0
    {
        note(
            l,
            &trf!(
                "{d} dossier(s), {p} programme(s), {t} type(s) de fichier",
                "{d} folder(s), {p} program(s), {t} file type(s)"
            ),
            GRIS,
        );
    }
    imposee(l, e.strategies.exclusions);
    if let Some(Compte::Nombre(n)) = e.preferences.as_ref().map(|p| p.applis_permises)
        && n > 0
    {
        l.push(pointilles(
            tr!("Programmes permis (dossiers)", "Allowed apps (folders)"),
            &n.to_string(),
            "",
        ));
    }
}

fn section_asr(l: &mut Vec<String>, e: &Etat) {
    l.push(String::new());
    l.push(crate::ui::ligne_section(tr!("Règles ASR", "ASR rules")));
    let Some(p) = e.preferences.as_ref() else {
        l.push(format!(
            "  {}",
            tr!(
                "Non vérifiées : la liste des règles ne se lit pas.",
                "Not checked: the rule list cannot be read."
            )
        ));
        return;
    };
    // Grises quand elles ne s'appliquent pas, ou que rien ne le vérifie.
    let gris = effet_asr(e) != EffetAsr::SAppliquent;
    let imposees = e.strategies.asr.as_deref().unwrap_or_default();
    let compte = |a: ActionAsr| p.asr.regles.iter().filter(|(_, x)| *x == a).count();
    let reglees = p.asr.regles.len();
    l.push(format!(
        "  {}",
        trf!(
            "{} bloquent · {} en audit · {} avertissent · {} désactivées ou non réglées",
            "{} block · {} audit · {} warn · {} disabled or not set",
            compte(ActionAsr::Bloque),
            compte(ActionAsr::Audit),
            compte(ActionAsr::Avertit),
            ASR_TOUTES.len() - reglees + compte(ActionAsr::Coupee) + compte(ActionAsr::NonReglee)
        )
    ));
    let mut une_imposee = false;
    for id in ASR_TOUTES {
        let Some(action) = p.asr.action(id) else { continue };
        let style = match action {
            _ if gris => GRIS,
            ActionAsr::Bloque => VERT,
            _ => "",
        };
        let etoile = if imposees.contains(&id) {
            une_imposee = true;
            " *"
        } else {
            ""
        };
        let statut = crate::ui::ajuster(&action.texte(), 11);
        let nom = nom_asr(id).unwrap_or("?");
        l.push(format!("    {style}{statut} {nom}{etoile}{RESET}"));
    }
    if une_imposee {
        note(
            l,
            tr!(
                "* imposée par une stratégie (GPO ou Intune).",
                "* enforced by a policy (GPO or Intune)."
            ),
            GRIS,
        );
    }
    if p.asr.inconnues > 0 {
        note(
            l,
            &trf!(
                "{} autre(s) règle(s) que Vanguard ne connaît pas encore.",
                "{} other rule(s) Vanguard does not know yet.",
                p.asr.inconnues
            ),
            GRIS,
        );
    }
    // Sans effet (Defender passif ou coupé) : dit même sans règle réglée, comme avant ; l'effet des autres cas ne
    // concerne que des règles réglées.
    if reglees > 0 || effet_asr(e) == EffetAsr::DefenderInactif {
        note(l, &texte_effet_asr(e), GRIS);
    }
}

/// Ce qui laisse les règles ASR agir (plan §2.2) : Defender antivirus actif **et** la protection en temps réel
/// allumée. La relecture de `AttackSurfaceReductionRules_Ids/Actions` est le stockage de la préférence, pas son
/// application : c'est ceci qui dit si elle s'applique.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EffetAsr {
    SAppliquent,
    /// Passif derrière un autre antivirus, en blocage EDR, ou coupé.
    DefenderInactif,
    TempsReelCoupe,
    /// Windows Famille : Microsoft le dit pris en charge aujourd'hui, pas toujours avant ; rien ne le relit.
    Famille,
    /// L'état de Defender ne se lit pas.
    NonVerifie,
}

impl EffetAsr {
    /// Pour `--json`.
    pub(crate) fn id(self) -> &'static str {
        match self {
            EffetAsr::SAppliquent => "s-appliquent",
            EffetAsr::DefenderInactif => "defender-inactif",
            EffetAsr::TempsReelCoupe => "temps-reel-coupe",
            EffetAsr::Famille => "famille",
            EffetAsr::NonVerifie => "non-verifie",
        }
    }
}

pub(crate) fn effet_asr(e: &Etat) -> EffetAsr {
    let mode = e.mode();
    if mode != ModeDefender::Actif && mode != ModeDefender::Illisible {
        EffetAsr::DefenderInactif
    } else if e.etat_opt(Opt::TempsReel) == EtatOpt::Coupee {
        // L'effet relu passe avant la préférence (`etat_opt`) : c'est ce que Defender applique.
        EffetAsr::TempsReelCoupe
    } else if mode == ModeDefender::Illisible {
        // Avant l'édition : sans Defender relu, même sur Famille, rien n'est vérifié.
        EffetAsr::NonVerifie
    } else if e.edition == Some(Edition::Famille) {
        EffetAsr::Famille
    } else {
        EffetAsr::SAppliquent
    }
}

/// La phrase de `effet_asr`, dite à l'écran des règles et sous leur liste.
pub(crate) fn texte_effet_asr(e: &Etat) -> String {
    match effet_asr(e) {
        EffetAsr::SAppliquent => tr!(
            "Les règles s'appliquent : Defender est l'antivirus actif et la protection en temps réel est allumée.",
            "The rules apply: Defender is the active antivirus and real-time protection is on."
        )
        .to_string(),
        EffetAsr::DefenderInactif if e.mode() == ModeDefender::Coupe => tr!(
            "Sans effet : Defender n'est pas l'antivirus actif. Son antivirus est coupé : les règles restent réglables, et agiront quand il sera rallumé.",
            "No effect: Defender is not the active antivirus. Its antivirus is off: the rules can still be set, and will act once it is back on."
        )
        .to_string(),
        EffetAsr::DefenderInactif => {
            let nom = nom_du_tiers(e);
            trf!(
                "Sans effet : Defender n'est pas l'antivirus actif. Il est en mode passif, {nom} est votre antivirus : les règles ASR n'agissent pas tant que {nom} protège.",
                "No effect: Defender is not the active antivirus. It is in passive mode, {nom} is your antivirus: ASR rules do not act while {nom} protects you."
            )
        }
        EffetAsr::TempsReelCoupe => tr!(
            "Sans effet tant que la protection en temps réel est coupée. Tant qu'elle l'est, les règles ne s'appliquent pas ; elles restent réglables, et agiront quand elle sera rallumée (ligne 1).",
            "No effect while real-time protection is off. While it is, the rules do not apply; they can still be set, and will act once it is back on (line 1)."
        )
        .to_string(),
        // La page de Microsoft (« ASR rules reference », 2026) dit les règles disponibles sur toute édition qui a
        // Defender, Famille comprise ; elle disait autrefois Pro et plus. Rien ne relit leur application : le dire.
        EffetAsr::Famille => tr!(
            "Windows Famille : Microsoft dit aujourd'hui les règles ASR disponibles sur toute édition qui a Defender ; un Windows Famille ancien peut les garder notées sans les appliquer. La relecture montre le réglage, pas son effet.",
            "Windows Home: Microsoft now says ASR rules are available on any edition that has Defender; an older Windows Home may keep them noted without applying them. The reread shows the setting, not its effect."
        )
        .to_string(),
        EffetAsr::NonVerifie => effet_non_verifie().to_string(),
    }
}

/// L'avertissement des 8 règles que les Réglages recommandés écartent exprès (P4) : elles peuvent gêner un programme
/// légitime, Vanguard compris. Proposées dans les Options, jamais dans « Réglages recommandés » ni dans Optimiser ;
/// « Essayez d'abord Audit » pour chacune. `None` pour les 11 autres.
pub(crate) fn avertissement_asr(id: &str) -> Option<&'static str> {
    Some(match id {
        "01443614-cd74-433a-b99e-2ecdc07bfc25" => tr!(
            "Peut bloquer Vanguard lui-même après une mise à jour (un nouvel exécutable, encore peu répandu) et des programmes rares. Elle a besoin de la protection par le cloud. Essayez d'abord Audit.",
            "May block Vanguard itself after an update (a new executable, not yet widespread) and rare programs. It needs cloud-delivered protection. Try Audit first."
        ),
        "c1db55ab-c21a-4637-bb3f-a12568109d35" => tr!(
            "Faux positifs fréquents sur les programmes peu connus, Vanguard compris. Elle a besoin de la protection par le cloud. Essayez d'abord Audit.",
            "Frequent false positives on little-known programs, Vanguard included. It needs cloud-delivered protection. Try Audit first."
        ),
        // Vanguard n'appelle par WMI que des méthodes de réglage (MSFT_MpPreference, MSFT_SmbServerConfiguration,
        // SystemRestore.CreateRestorePoint), jamais Win32_Process.Create : la règle ne vise pas ce qu'il fait.
        "d1e49aac-8f56-4280-b9ba-993a6d77406c" => tr!(
            "Bloque les programmes lancés par PsExec et par WMI (Win32_Process.Create) : peut casser des outils d'administration à distance et des scripts d'entreprise. Vanguard n'en dépend pas : il lit et règle par WMI, sans jamais y lancer de programme. Essayez d'abord Audit.",
            "Blocks programs started by PsExec and by WMI (Win32_Process.Create): may break remote administration tools and company scripts. Vanguard does not depend on it: it reads and sets through WMI, never starting a program there. Try Audit first."
        ),
        "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" => tr!(
            "Peut bloquer des outils portables légitimes, rangés hors de leur dossier habituel. Essayez d'abord Audit.",
            "May block legitimate portable tools, kept outside their usual folder. Try Audit first."
        ),
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc" => tr!(
            "Peut bloquer des scripts d'installation légitimes. Elle a besoin de la protection par le cloud. Essayez d'abord Audit.",
            "May block legitimate setup scripts. It needs cloud-delivered protection. Try Audit first."
        ),
        "33ddedf1-c6e0-47cb-833e-de6133960387" => tr!(
            "Empêche aussi de redémarrer en mode sans échec pour dépanner (l'environnement de récupération de Windows y mène encore). Essayez d'abord Audit.",
            "Also prevents restarting into Safe Mode to troubleshoot (the Windows recovery environment still leads there). Try Audit first."
        ),
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" => tr!(
            "Vanguard portable sur une clé USB : ses extensions non signées seraient bloquées, comme tout programme non signé lancé depuis une clé. Essayez d'abord Audit.",
            "Vanguard portable on a USB drive: its unsigned extensions would be blocked, like any unsigned program run from a drive. Try Audit first."
        ),
        "a8f5898e-1dc8-49a9-9878-85004b8a61e6" => tr!(
            "Faite pour les serveurs Exchange ; sans effet utile sur un PC. Essayez d'abord Audit.",
            "Made for Exchange servers; no useful effect on a PC. Try Audit first."
        ),
        _ => return None,
    })
}

/// Les règles qui ont besoin de la protection par le cloud (« ASR rules reference », dépendances) : coupée, elles
/// ne bloquent rien.
pub(crate) fn asr_avec_cloud(id: &str) -> bool {
    matches!(
        id,
        "01443614-cd74-433a-b99e-2ecdc07bfc25"
            | "5beb7efe-fd9a-4556-801d-275e5ffc04cc"
            | "c1db55ab-c21a-4637-bb3f-a12568109d35"
    )
}

fn section_pare_feu(l: &mut Vec<String>, e: &Etat) {
    l.push(String::new());
    l.push(crate::ui::ligne_section(tr!("Pare-feu Windows", "Windows Firewall")));
    let Some(f) = e.pare_feu else {
        l.push(format!(
            "  {}",
            tr!(
                "Non vérifié : le Pare-feu Windows ne répond pas (service arrêté ?).",
                "Not checked: Windows Firewall does not answer (service stopped?)."
            )
        ));
        return;
    };
    for (i, ((p, (_, bit)), imposee_ici)) in f.profils.iter().zip(PROFILS).zip(e.pare_feu_impose()).enumerate() {
        let courant = f.courants.is_some_and(|c| c & bit != 0);
        let nom = if courant {
            trf!("{} (réseau actuel)", "{} (current network)", nom_profil(i))
        } else {
            nom_profil(i).to_string()
        };
        let (texte, style) = match p.actif {
            Some(true) => (tr!("allumé", "on"), VERT),
            Some(false) => (tr!("coupé", "off"), ACCENT),
            None => (tr!("non vérifié", "not checked"), ""),
        };
        l.push(pointilles(&nom, texte, style));
        if p.actif == Some(true) {
            let entrees = match p.entrees_bloquees {
                Some(true) => tr!("entrées bloquées par défaut", "inbound blocked by default"),
                Some(false) => tr!("entrées PERMISES par défaut", "inbound ALLOWED by default"),
                None => tr!("entrées : non vérifié", "inbound: not checked"),
            };
            let sorties = match p.sorties_bloquees {
                Some(true) => tr!("sorties bloquées", "outbound blocked"),
                Some(false) => tr!("sorties permises", "outbound allowed"),
                None => tr!("sorties : non vérifié", "outbound: not checked"),
            };
            note(l, &format!("{entrees}, {sorties}"), GRIS);
            if p.tout_bloquer == Some(true) {
                note(
                    l,
                    tr!(
                        "toutes les entrées bloquées, exceptions comprises",
                        "all inbound blocked, exceptions included"
                    ),
                    GRIS,
                );
            }
        }
        imposee(l, imposee_ici);
    }
    match f.modification {
        Some(1) => note(
            l,
            tr!(
                "Profil actuel : une stratégie l'emporte sur les réglages locaux du pare-feu.",
                "Current profile: a policy overrides the firewall's local settings."
            ),
            GRIS,
        ),
        Some(2) => note(
            l,
            tr!(
                "Profil actuel : tout l'entrant est bloqué, une règle d'entrée locale n'aurait pas d'effet.",
                "Current profile: all inbound is blocked, a local inbound rule would have no effect."
            ),
            GRIS,
        ),
        _ => {}
    }
    if let Some(n) = f.regles {
        l.push(pointilles(
            tr!("Règles du pare-feu", "Firewall rules"),
            &n.to_string(),
            "",
        ));
    }
}

fn section_centre(l: &mut Vec<String>, e: &Etat) {
    l.push(String::new());
    l.push(crate::ui::ligne_section(tr!(
        "Centre de sécurité Windows",
        "Windows Security Center"
    )));
    let Some(av) = e.centre.antivirus.as_ref() else {
        l.push(format!(
            "  {}",
            tr!(
                "Inconnu : le Centre de sécurité ne répond pas (absent de Windows Server).",
                "Unknown: Security Center does not answer (absent from Windows Server)."
            )
        ));
        return;
    };
    if av.is_empty() {
        l.push(pointilles(
            tr!("Antivirus inscrits", "Registered antivirus"),
            tr!("aucun", "none"),
            ACCENT,
        ));
    }
    for p in av {
        let etat = match p.actif {
            Some(true) => tr!("en marche", "running"),
            Some(false) => tr!("arrêté", "stopped"),
            None => tr!("état illisible", "state unreadable"),
        };
        // « Antivirus : <nom> (état) », le nom coupé pour que l'état reste sur la ligne.
        let debut = tr!("Antivirus :", "Antivirus:");
        let place = crate::ui::LARGEUR.saturating_sub(largeur_affichee(debut) + largeur_affichee(etat) + 6);
        let nom = crate::ui::couper(&p.nom, place);
        l.push(format!("  {GRIS}{debut}{RESET} {nom} {GRIS}({etat}){RESET}"));
    }
    if let Some(p) = e.centre.pare_feu_tiers() {
        note(
            l,
            &trf!(
                "{} gère le pare-feu ; le pare-feu de Windows peut être coupé par lui, c'est voulu.",
                "{} manages the firewall; it may turn Windows Firewall off, which is intended.",
                p.nom
            ),
            GRIS,
        );
    }
}

fn section_gestion(l: &mut Vec<String>, e: &Etat) {
    l.push(String::new());
    l.push(crate::ui::ligne_section(tr!("Gestion du PC", "PC management")));
    let g = e.gestion;
    for (libelle, valeur) in [
        (tr!("Joint à un domaine", "Joined to a domain"), g.domaine),
        (tr!("Joint à Entra ID", "Joined to Entra ID"), g.entra),
        (
            tr!("Inscrit à une gestion (MDM)", "Enrolled in management (MDM)"),
            g.mdm,
        ),
    ] {
        l.push(pointilles(libelle, oui_non(valeur), ""));
    }
    let texte = match g.geree() {
        Some(true) => tr!(
            "Ce PC est géré par une organisation : ses réglages de défense viennent d'elle. Pour les changer, voyez votre service informatique.",
            "This PC is managed by an organization: its defense settings come from it. To change them, see your IT department."
        ),
        Some(false) => tr!(
            "Ce PC n'est géré par aucune organisation.",
            "This PC is not managed by any organization."
        ),
        None => tr!(
            "Non vérifié : on ne sait pas si une organisation gère ce PC.",
            "Not checked: it is unknown whether an organization manages this PC."
        ),
    };
    note(l, texte, GRIS);
}

/// Le JSON de `vanguard options-defense --json` : des identifiants et des nombres, rien de personnel.
pub(crate) fn json(e: &Etat) -> serde_json::Value {
    use serde_json::json;
    let p = e.preferences.as_ref();
    let options: Vec<_> = Opt::TOUTES
        .iter()
        .map(|&o| {
            json!({
                "id": o.id(),
                "valeur": p.and_then(|p| p.valeur(o)),
                "etat": e.etat_opt(o).id(),
                "imposee": e.strategies.option(o),
            })
        })
        .collect();
    let imposees = e.strategies.asr.as_deref();
    let regles: Vec<_> = p.map_or_else(Vec::new, |p| {
        p.asr
            .regles
            .iter()
            .map(|(id, a)| {
                json!({
                    "id": id,
                    "action": a.valeur(),
                    "imposee": imposees.map(|i| i.contains(id)),
                })
            })
            .collect()
    });
    let statut = e.statut.as_ref();
    let profils: Vec<_> = e.pare_feu.map_or_else(Vec::new, |f| {
        f.profils
            .iter()
            .zip(PROFILS)
            .zip(e.pare_feu_impose())
            .map(|((p, (id, bit)), imposee)| {
                json!({
                    "id": id,
                    "actif": p.actif,
                    "reseau_actuel": f.courants.map(|c| c & bit != 0),
                    "entrees_bloquees": p.entrees_bloquees,
                    "sorties_bloquees": p.sorties_bloquees,
                    "tout_bloquer": p.tout_bloquer,
                    "imposee": imposee,
                })
            })
            .collect()
    });
    let modification = e.pare_feu.and_then(|f| f.modification).map(|m| match m {
        0 => "locale",
        1 => "strategie",
        2 => "entrant-bloque",
        _ => "autre",
    });
    let actifs = |l: &Option<Vec<Produit>>| l.as_ref().map(|l| l.iter().filter(|p| p.actif == Some(true)).count());
    json!({
        "version": 1,
        "lecture_seule": true,
        "disponible": true,
        "defender": {
            "mode": e.mode().id(),
            "temps_reel_effectif": statut.and_then(|s| s.temps_reel),
            "falsifications": statut.and_then(|s| s.falsifications),
            "falsifications_source": statut.and_then(|s| s.source).map(SourceFalsif::id),
            "options": options,
            "exclusions": p.map(|p| json!({
                "visibles": !p.exclusions.contains(&Compte::Masque),
                "dossiers": p.exclusions[0].json(),
                "programmes": p.exclusions[1].json(),
                "extensions": p.exclusions[2].json(),
            })),
            "exclusions_imposees": e.strategies.exclusions,
            "applis_permises": p.map(|p| p.applis_permises.json()),
        },
        "asr": {
            "lues": p.is_some(),
            "regles": regles,
            "inconnues": p.map(|p| p.asr.inconnues),
            "imposees_lues": imposees.is_some(),
            "effet": p.map(|_| effet_asr(e).id()),
        },
        "pare_feu": {
            "lu": e.pare_feu.is_some(),
            "profils": profils,
            "modification": modification,
            "regles": e.pare_feu.and_then(|f| f.regles),
        },
        "centre_securite": {
            "lu": e.centre.antivirus.is_some(),
            "antivirus_inscrits": e.centre.antivirus.as_ref().map(Vec::len),
            "antivirus_en_marche": actifs(&e.centre.antivirus),
            "antivirus_tiers_en_marche": e.centre.antivirus.as_ref().map(|_| e.centre.antivirus_tiers().is_some()),
            "pare_feu_tiers_en_marche": e.centre.pare_feu.as_ref().map(|_| e.centre.pare_feu_tiers().is_some()),
        },
        "gestion": {
            "domaine": e.gestion.domaine,
            "entra": e.gestion.entra,
            "mdm": e.gestion.mdm,
            "geree": e.gestion.geree(),
        },
        "edition": e.edition.map(|x| match x {
            Edition::Famille => "famille",
            Edition::Serveur => "serveur",
            Edition::Autre => "autre",
        }),
    })
}

/// Le JSON hors de Windows : fermé, sans rien lire.
#[cfg(any(not(windows), test))]
fn json_hors_windows() -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "lecture_seule": true,
        "disponible": false,
        "raison": "windows-seulement",
    })
}

fn titre() -> &'static str {
    tr!("Options de défense", "Defense options")
}

// ------------------------------------------------------------------ choix de la personne et « Rallumer »

/// L'option de l'écran que règle un réglage des choix.
fn opt_de(r: ReglageDefender) -> Opt {
    match r {
        ReglageDefender::TempsReel => Opt::TempsReel,
        ReglageDefender::Maps => Opt::Cloud,
        ReglageDefender::Cfa => Opt::Dossiers,
        ReglageDefender::Np => Opt::Reseau,
        ReglageDefender::Pua => Opt::Pua,
        ReglageDefender::Echantillons => Opt::Echantillons,
        ReglageDefender::Comportement => Opt::Comportement,
        ReglageDefender::Telechargements => Opt::Telechargements,
        ReglageDefender::Scripts => Opt::Scripts,
        ReglageDefender::PremiereVue => Opt::PremiereVue,
    }
}

/// Le réglage des choix d'une option de l'écran (les dix ont le leur).
pub(crate) fn reglage_de(o: Opt) -> ReglageDefender {
    match o {
        Opt::TempsReel => ReglageDefender::TempsReel,
        Opt::Cloud => ReglageDefender::Maps,
        Opt::Dossiers => ReglageDefender::Cfa,
        Opt::Reseau => ReglageDefender::Np,
        Opt::Pua => ReglageDefender::Pua,
        Opt::Echantillons => ReglageDefender::Echantillons,
        Opt::Comportement => ReglageDefender::Comportement,
        Opt::Telechargements => ReglageDefender::Telechargements,
        Opt::Scripts => ReglageDefender::Scripts,
        Opt::PremiereVue => ReglageDefender::PremiereVue,
    }
}

/// Le plus de colonnes qu'un texte venu d'ailleurs (chemin exclu, programme permis) prend à l'écran (R13).
const TEXTE_EXTERNE_MAX: usize = 60;

/// Un texte venu d'ailleurs, prêt à montrer : caractères piégés remplacés, coupé à `TEXTE_EXTERNE_MAX` colonnes.
pub(crate) fn externe(texte: &str) -> String {
    crate::ui::couper(&crate::ui::affichable(texte), TEXTE_EXTERNE_MAX)
}

/// Le genre d'une exclusion, en mots.
pub(crate) fn nom_genre(g: GenreExclusion) -> &'static str {
    match g {
        GenreExclusion::Chemin => tr!("dossier ou fichier", "folder or file"),
        GenreExclusion::Processus => tr!("programme", "program"),
        GenreExclusion::Extension => tr!("type de fichier", "file type"),
    }
}

/// L'avertissement d'une exclusion large (R8), dit avant la question.
pub(crate) fn avertissement_large() -> &'static str {
    tr!(
        "⚠ EXCLUSION LARGE : Defender n'examinera plus une grande partie du PC (un disque entier, Windows, les téléchargements, le dossier temporaire, un interpréteur ou tout un type de programme). Les virus s'y cachent souvent. N'acceptez que si vous savez exactement pourquoi.",
        "⚠ BROAD EXCLUSION: Defender will stop scanning a large part of the PC (a whole drive, Windows, downloads, the temporary folder, an interpreter or a whole type of program). Viruses often hide there. Only accept if you know exactly why."
    )
}

/// Ce que la fenêtre administrateur montre pour une exclusion ajoutée : son genre et son texte rendu affichable et
/// borné (R13). L'avertissement d'une exclusion large vient avant la question (`avertissement_large`).
pub(crate) fn texte_ajout_exclusion(g: GenreExclusion, texte: &str) -> String {
    let t = externe(texte);
    trf!(
        "Exclusion de l'analyse ({}) : AJOUTER « {t} »",
        "Scan exclusion ({}): ADD “{t}”",
        nom_genre(g)
    )
}

/// Ce que la fenêtre administrateur montre pour un programme permis malgré l'accès contrôlé aux dossiers.
pub(crate) fn texte_autoriser_dossiers(texte: &str) -> String {
    let t = externe(texte);
    trf!(
        "Accès contrôlé aux dossiers : PERMETTRE à « {t} » d'écrire dans vos dossiers protégés",
        "Controlled folder access: ALLOW “{t}” to write to your protected folders"
    )
}

/// Le nom d'un réglage des choix, pour la fenêtre administrateur et les phrases d'une liste.
pub(crate) fn nom_choix(id: IdChoix) -> String {
    match id {
        IdChoix::Defender(r) => opt_de(r).libelle().to_string(),
        IdChoix::Asr(g) => {
            let n = nom_asr(g).unwrap_or("?");
            trf!("Règle ASR « {n} »", "ASR rule “{n}”")
        }
        IdChoix::Exclusion(g, _) => trf!("Exclusion de l'analyse ({})", "Scan exclusion ({})", nom_genre(g)),
        IdChoix::DossiersAutorise(_) => tr!(
            "Programme permis (accès contrôlé aux dossiers)",
            "Allowed app (controlled folder access)"
        )
        .to_string(),
    }
}

/// Une valeur d'un réglage des choix, en mots (`None` : illisible ; `Some(None)` : règle ASR absente de la liste).
#[allow(clippy::option_option)] // None : illisible ou sans note ; Some(None) : valeur absente
pub(crate) fn texte_choix(id: IdChoix, v: Option<Option<i64>>) -> String {
    match (id, v) {
        (_, None) => EtatOpt::Illisible.texte(false),
        (IdChoix::Defender(r), Some(v)) => {
            let o = opt_de(r);
            o.etat(v).texte(o.masculin())
        }
        (IdChoix::Asr(_), Some(None)) => tr!("absente de la liste (sans effet)", "not listed (no effect)").to_string(),
        (IdChoix::Asr(_), Some(v)) => ActionAsr::depuis(v).texte(),
        (IdChoix::Exclusion(..) | IdChoix::DossiersAutorise(_), Some(Some(0))) => tr!("absente", "absent").to_string(),
        (IdChoix::Exclusion(..) | IdChoix::DossiersAutorise(_), Some(Some(1))) => {
            tr!("présente", "present").to_string()
        }
        (IdChoix::Exclusion(..) | IdChoix::DossiersAutorise(_), Some(v)) => {
            EtatOpt::Autre(v.unwrap_or(-1)).texte(false)
        }
    }
}

/// Ce qui protège encore quand `id` est baissé (plan §2.1), dit avant la question et dans le bilan : jamais
/// « rien », toujours la suite.
pub(crate) fn protege_encore(id: IdChoix) -> &'static str {
    match id {
        IdChoix::Defender(ReglageDefender::TempsReel) => tr!(
            "Ce qui protège encore : SmartScreen, le pare-feu, l'analyse à la demande, la protection de Vanguard. Ne protègent plus : les règles ASR, l'accès contrôlé aux dossiers, la protection réseau, le blocage à la première détection. Windows peut le rallumer de lui-même.",
            "What still protects you: SmartScreen, the firewall, on-demand scans, Vanguard's protection. No longer protecting: ASR rules, controlled folder access, network protection, block at first sight. Windows may turn it back on by itself."
        ),
        IdChoix::Defender(ReglageDefender::Maps) => tr!(
            "Ce qui protège encore : les signatures locales, le temps réel, les règles ASR. Le blocage à la première détection ne marche plus.",
            "What still protects you: local signatures, real-time protection, ASR rules. Block at first sight no longer works."
        ),
        IdChoix::Defender(ReglageDefender::Echantillons) => tr!(
            "Ce qui protège encore : tout le reste. C'est surtout un choix de vie privée : seule l'analyse des fichiers inconnus par le cloud est plus lente ou absente.",
            "What still protects you: everything else. It is mostly a privacy choice: only the cloud analysis of unknown files is slower or missing."
        ),
        IdChoix::Defender(ReglageDefender::Pua) => tr!(
            "Ce qui protège encore : le temps réel contre les vrais virus, le filtre de SmartScreen dans Edge (s'il est allumé).",
            "What still protects you: real-time protection against real viruses, SmartScreen's filter in Edge (if on)."
        ),
        IdChoix::Defender(ReglageDefender::Np) => tr!(
            "Ce qui protège encore : SmartScreen dans Edge, le DNS protecteur de Vanguard s'il est posé, les listes noires de Vanguard.",
            "What still protects you: SmartScreen in Edge, Vanguard's protective DNS if set, Vanguard's blocklists."
        ),
        IdChoix::Defender(ReglageDefender::Cfa) => tr!(
            "Ce qui protège encore : le temps réel, les pièges contre les rançongiciels de Vanguard (canaris), vos sauvegardes.",
            "What still protects you: real-time protection, Vanguard's ransomware traps (canaries), your backups."
        ),
        IdChoix::DossiersAutorise(_) => tr!(
            "Ce qui protège encore : le reste de l'accès contrôlé aux dossiers ; seul ce programme y écrit librement.",
            "What still protects you: the rest of controlled folder access; only this program writes there freely."
        ),
        IdChoix::Defender(ReglageDefender::Comportement) => tr!(
            "Ce qui protège encore : les signatures, le cloud, les règles ASR (en partie).",
            "What still protects you: signatures, the cloud, ASR rules (in part)."
        ),
        IdChoix::Defender(ReglageDefender::Telechargements) => tr!(
            "Ce qui protège encore : SmartScreen, le temps réel à l'ouverture du fichier.",
            "What still protects you: SmartScreen, real-time protection when the file is opened."
        ),
        IdChoix::Defender(ReglageDefender::Scripts) => tr!(
            "Ce qui protège encore : AMSI reste actif pour les autres moteurs ; le temps réel.",
            "What still protects you: AMSI stays on for the other engines; real-time protection."
        ),
        IdChoix::Defender(ReglageDefender::PremiereVue) => tr!(
            "Ce qui protège encore : le cloud (sans attente), les signatures.",
            "What still protects you: the cloud (without waiting), signatures."
        ),
        IdChoix::Exclusion(..) => tr!(
            "Ce qui protège encore : tout, sauf pour ce qui est exclu.",
            "What still protects you: everything, except for what is excluded."
        ),
        IdChoix::Asr(_) => tr!(
            "Ce qui protège encore : la protection en temps réel, le pare-feu et les autres règles.",
            "What still protects you: real-time protection, the firewall and the other rules."
        ),
    }
}

/// Ce qu'une baisse change, dit sous la liste des valeurs (plan §3.2) : avec ce qui protège encore.
pub(crate) fn effet_baisse(id: IdChoix) -> String {
    let effet = match id {
        IdChoix::Defender(ReglageDefender::TempsReel) => tr!(
            "Couper : Defender n'examine plus les fichiers à l'ouverture. Les règles ASR, l'accès contrôlé aux dossiers et la protection réseau ne bloquent plus tant qu'elle est coupée.",
            "Turn off: Defender no longer scans files when they open. ASR rules, controlled folder access and network protection stop blocking while it is off."
        ),
        IdChoix::Defender(ReglageDefender::Maps) => tr!(
            "Couper ou baisser : Defender ne demande plus l'avis du cloud de Microsoft sur un fichier inconnu.",
            "Turn off or lower: Defender no longer asks Microsoft's cloud about an unknown file."
        ),
        IdChoix::Defender(ReglageDefender::Echantillons) => tr!(
            "« Jamais » : aucun fichier n'est envoyé à Microsoft pour analyse ; « toujours demander » : Windows vous demande avant chaque envoi.",
            "“Never”: no file is sent to Microsoft for analysis; “always ask”: Windows asks you before each submission."
        ),
        IdChoix::Defender(ReglageDefender::Pua) => tr!(
            "Couper : les logiciels publicitaires, barres d'outils et autres programmes indésirables ne sont plus bloqués.",
            "Turn off: adware, toolbars and other unwanted programs are no longer blocked."
        ),
        IdChoix::Defender(ReglageDefender::Np) => tr!(
            "Couper : les sites dangereux connus ne sont plus bloqués pour les programmes autres qu'Edge.",
            "Turn off: known dangerous sites are no longer blocked for programs other than Edge."
        ),
        IdChoix::Defender(ReglageDefender::Cfa) => tr!(
            "Couper : n'importe quel programme peut de nouveau modifier vos Documents, Images et autres dossiers protégés.",
            "Turn off: any program can again change your Documents, Pictures and other protected folders."
        ),
        IdChoix::Defender(ReglageDefender::Comportement) => tr!(
            "Couper : Defender ne surveille plus ce que font les programmes en marche.",
            "Turn off: Defender no longer watches what running programs do."
        ),
        IdChoix::Defender(ReglageDefender::Telechargements) => tr!(
            "Couper : les fichiers téléchargés et les pièces jointes ne sont plus examinés à leur arrivée.",
            "Turn off: downloaded files and attachments are no longer scanned when they arrive."
        ),
        IdChoix::Defender(ReglageDefender::Scripts) => tr!(
            "Couper : Defender n'examine plus les scripts (PowerShell, JavaScript, VBScript) avant qu'ils tournent.",
            "Turn off: Defender no longer scans scripts (PowerShell, JavaScript, VBScript) before they run."
        ),
        IdChoix::Defender(ReglageDefender::PremiereVue) => tr!(
            "Couper : un fichier inconnu n'est plus retenu le temps que le cloud l'examine.",
            "Turn off: an unknown file is no longer held while the cloud examines it."
        ),
        IdChoix::Exclusion(..) => tr!(
            "Ajouter : Defender n'examine plus ce dossier, ce programme ou ce type de fichier.",
            "Add: Defender no longer scans this folder, program or file type."
        ),
        IdChoix::DossiersAutorise(_) => tr!(
            "Permettre : ce programme peut modifier vos dossiers protégés.",
            "Allow: this program can change your protected folders."
        ),
        IdChoix::Asr(_) => tr!(
            "Désactiver ou passer en audit : la règle ne bloque plus. En audit, Defender note seulement ce qu'elle aurait bloqué (journal de Defender, événement 1122).",
            "Disable or set to audit: the rule no longer blocks. In audit, Defender only logs what it would have blocked (Defender log, event 1122)."
        ),
    };
    format!("{effet} {}", protege_encore(id))
}

/// L'identifiant d'un réglage des choix tel que la personne l'écrit (`temps-reel`, `pua`, `asr-<GUID>`, ou le
/// texte complet `defender-pua`).
fn id_de(texte: &str) -> Option<IdChoix> {
    let t = texte.trim().to_ascii_lowercase();
    IdChoix::lire(&t)
        .or_else(|| IdChoix::lire(&format!("defender-{t}")))
        .or_else(|| asr_connue(t.strip_prefix("asr-").unwrap_or(&t)).map(IdChoix::Asr))
}

/// La ligne d'un choix (`vanguard options-defense --choisir <id> <valeur>`) ; `None` si l'identifiant ou la valeur
/// n'en est pas un.
pub(crate) fn ligne_choix(id: &str, valeur: &str) -> Option<String> {
    let v = valeur.trim().to_ascii_lowercase();
    match id_de(id)? {
        IdChoix::Defender(r) => {
            let c = ChoixDefender::TOUS.into_iter().find(|c| c.mot() == v)?;
            crate::machine::gestes::ligne_baisse_defender(r, c)
        }
        IdChoix::Asr(g) => {
            let c = ChoixAsr::TOUS.into_iter().find(|c| c.mot() == v)?;
            crate::machine::gestes::ligne_baisse_asr(g, c)
        }
        // Un élément de liste s'ajoute par son texte (`ligne_exclure`, `ligne_permettre`), jamais par son empreinte.
        IdChoix::Exclusion(..) | IdChoix::DossiersAutorise(_) => None,
    }
}

/// Le genre d'exclusion tel que la personne l'écrit : `chemin` ou `dossier`, `processus` ou `programme`,
/// `extension` ou `type`.
fn genre_de(mot: &str) -> Option<GenreExclusion> {
    match mot.trim().to_lowercase().as_str() {
        "chemin" | "dossier" | "fichier" | "path" | "folder" | "file" => Some(GenreExclusion::Chemin),
        "processus" | "programme" | "process" | "program" => Some(GenreExclusion::Processus),
        "extension" | "type" => Some(GenreExclusion::Extension),
        _ => None,
    }
}

/// La ligne d'une exclusion ajoutée (`--exclure <genre> <texte>`, ou l'écran) ; `None` pour un genre inconnu ou un
/// texte refusé (vide, trop long, caractère de contrôle). Une extension s'écrit sans son point.
pub(crate) fn ligne_exclure(genre: &str, texte: &str) -> Option<String> {
    ligne_exclusion(genre_de(genre)?, texte)
}

/// Le texte d'une exclusion tel qu'il est envoyé et noté : sans espaces autour, une extension sans son point.
fn texte_exclusion(g: GenreExclusion, texte: &str) -> &str {
    let t = texte.trim();
    if g == GenreExclusion::Extension {
        t.trim_start_matches('.')
    } else {
        t
    }
}

/// La ligne d'une exclusion d'un genre connu (`ligne_exclure`, l'écran).
fn ligne_exclusion(g: GenreExclusion, texte: &str) -> Option<String> {
    crate::machine::gestes::ligne_ajout_exclusion(g, texte_exclusion(g, texte))
}

/// La ligne d'un programme permis malgré l'accès contrôlé aux dossiers (`--permettre <programme>`, ou l'écran).
pub(crate) fn ligne_permettre(programme: &str) -> Option<String> {
    crate::machine::gestes::ligne_autoriser_dossiers(programme.trim())
}

/// La ligne « C'est moi » (`--noter <id>`, ou l'écran) : la valeur actuelle, déjà baissée hors de Vanguard, notée
/// « par votre choix » dans la fenêtre administrateur, avec la même question qu'une baisse (P11).
pub(crate) fn ligne_noter(id: &str) -> Option<String> {
    id_de(id).map(crate::machine::gestes::ligne_noter)
}

/// Les identifiants et valeurs admis, pour l'aide d'une commande refusée.
fn aide_choix() -> String {
    let mut l = Vec::new();
    for r in ReglageDefender::TOUS {
        let mots: Vec<&str> = r.choix().iter().map(|c| c.mot()).collect();
        l.push(format!("  {} : {}", r.id_choix(), mots.join(", ")));
    }
    let mots: Vec<&str> = ChoixAsr::TOUS.iter().map(|c| c.mot()).collect();
    l.push(format!("  asr-<GUID> : {}", mots.join(", ")));
    l.push("  --exclure <dossier|programme|type> <texte> ; --permettre <programme> ; --noter <id>".to_string());
    l.join("\n")
}

/// `vanguard options-defense --choisir <id> <valeur>` : un choix de la personne, montré puis fait dans la fenêtre
/// administrateur (une baisse y est confirmée). Faux si la commande est refusée ou si le geste n'a pas réussi.
pub fn choisir(id: &str, valeur: &str) -> bool {
    let Some(ligne) = ligne_choix(id, valeur) else {
        eprintln!(
            "{}\n{}",
            tr!("Choix inconnu. Admis :", "Unknown choice. Allowed:"),
            aide_choix()
        );
        return false;
    };
    appliquer_choix(ligne)
}

/// `vanguard options-defense --exclure <genre> <texte>` : une exclusion de l'analyse, montrée puis confirmée dans
/// la fenêtre administrateur comme toute baisse.
pub fn exclure(genre: &str, texte: &str) -> bool {
    let Some(ligne) = ligne_exclure(genre, texte) else {
        eprintln!(
            "{}\n{}",
            tr!("Exclusion refusée. Admis :", "Exclusion refused. Allowed:"),
            aide_choix()
        );
        return false;
    };
    appliquer_choix(ligne)
}

/// `vanguard options-defense --permettre <programme>` : un programme permis malgré l'accès contrôlé aux dossiers,
/// montré puis confirmé comme toute baisse.
pub fn permettre(programme: &str) -> bool {
    let Some(ligne) = ligne_permettre(programme) else {
        eprintln!("{}", tr!("Programme refusé.", "Program refused."));
        return false;
    };
    appliquer_choix(ligne)
}

/// `vanguard options-defense --noter <id>` : « C'est moi » (P11).
pub fn noter(id: &str) -> bool {
    let Some(ligne) = ligne_noter(id) else {
        eprintln!(
            "{}\n{}",
            tr!("Réglage inconnu. Admis :", "Unknown setting. Allowed:"),
            aide_choix()
        );
        return false;
    };
    appliquer_choix(ligne)
}

/// `vanguard options-defense --rallumer <id>` : remet la valeur d'avant notée si elle protège, sinon la valeur sûre.
pub fn rallumer(id: &str) -> bool {
    let Some(i) = id_de(id) else {
        eprintln!(
            "{}\n{}",
            tr!("Réglage inconnu. Admis :", "Unknown setting. Allowed:"),
            aide_choix()
        );
        return false;
    };
    appliquer_choix(crate::machine::gestes::ligne_rallumer(i))
}

#[cfg_attr(not(windows), allow(clippy::needless_pass_by_value))] // la ligne n'est consommée que sous Windows
fn appliquer_choix(ligne: String) -> bool {
    #[cfg(windows)]
    {
        crate::ui::titre(titre());
        let reussis = crate::machine::appliquer_chacune(&[vec![ligne]]);
        reussis.first().copied().unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        let _ = ligne;
        eprintln!(
            "{}",
            tr!(
                "Windows seulement : ces réglages sont ceux de Microsoft Defender.",
                "Windows only: these settings are Microsoft Defender's."
            )
        );
        false
    }
}

/// L'écran (menu 4.10, `vanguard options-defense`).
pub fn afficher() {
    #[cfg(windows)]
    ecran::ecran();
    #[cfg(not(windows))]
    crate::ui::titre(titre());
    #[cfg(not(windows))]
    crate::ui::afficher_aligne(
        "  ",
        tr!(
            "Windows seulement : cet écran lit Microsoft Defender, ses règles ASR et le Pare-feu Windows.",
            "Windows only: this screen reads Microsoft Defender, its ASR rules and Windows Firewall."
        ),
        2,
        "",
    );
}

/// `vanguard options-defense --json`.
pub fn afficher_json() {
    #[cfg(windows)]
    let v = json(&crate::machine::windows::defense_etat::lire());
    #[cfg(not(windows))]
    let v = json_hors_windows();
    println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
}

#[cfg_attr(not(windows), allow(dead_code))]
mod ecran;

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn textes(l: &[&str]) -> Vec<String> {
        l.iter().map(|s| (*s).to_string()).collect()
    }

    /// Un PC courant : Defender actif, Tamper active par la personne, deux règles qui bloquent, une en audit, une
    /// inconnue ; le profil public courant, le domaine coupé et imposé par une GPO.
    pub(super) fn courant() -> Etat {
        let mut valeurs = [Some(0); 10];
        valeurs[1] = Some(2); // cloud avancé
        valeurs[2] = Some(1); // échantillons sûrs
        valeurs[3] = Some(1); // PUA bloque
        valeurs[4] = Some(2); // réseau en audit
        let mut options = [Some(false); 10];
        options[4] = Some(true);
        Etat {
            statut: Some(Statut {
                mode: ModeDefender::Actif,
                temps_reel: Some(true),
                falsifications: Some(true),
                source: Some(SourceFalsif::Personne),
            }),
            preferences: Some(Preferences {
                valeurs,
                asr: Asr::depuis(
                    &textes(&[
                        "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2",
                        "{56a863a9-875e-4185-98a7-b882c64b5ce5}",
                        "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
                        "00000000-0000-0000-0000-000000000000",
                    ]),
                    &[Some(1), Some(1), Some(2), Some(1)],
                ),
                exclusions: [Compte::Nombre(1), Compte::Nombre(0), Compte::Nombre(0)],
                applis_permises: Compte::Nombre(2),
            }),
            strategies: Strategies {
                options,
                asr: Some(vec!["56a863a9-875e-4185-98a7-b882c64b5ce5"]),
                exclusions: Some(false),
                pare_feu: [Some(true), Some(false), Some(false)],
            },
            pare_feu: Some(PareFeu {
                courants: Some(4),
                profils: [
                    Profil {
                        actif: Some(false),
                        ..Profil::default()
                    },
                    Profil {
                        actif: Some(true),
                        entrees_bloquees: Some(true),
                        sorties_bloquees: Some(false),
                        tout_bloquer: Some(false),
                    },
                    Profil {
                        actif: Some(true),
                        entrees_bloquees: Some(true),
                        sorties_bloquees: Some(false),
                        tout_bloquer: Some(true),
                    },
                ],
                modification: Some(1),
                regles: Some(412),
            }),
            centre: Centre {
                antivirus: Some(vec![Produit::depuis(
                    Some("Windows Defender"),
                    Some(397_568),
                    Some("windowsdefender://"),
                )]),
                pare_feu: Some(vec![]),
            },
            gestion: Gestion {
                domaine: Some(false),
                entra: Some(false),
                mdm: Some(false),
            },
            edition: Some(Edition::Autre),
        }
    }

    #[test]
    fn modes_de_defender() {
        use ModeDefender::*;
        assert_eq!(ModeDefender::depuis(Some("Normal"), Some(true)), Actif);
        assert_eq!(ModeDefender::depuis(Some("Normal"), None), Actif);
        assert_eq!(ModeDefender::depuis(Some("Normal"), Some(false)), Coupe);
        assert_eq!(ModeDefender::depuis(Some("Passive Mode"), Some(true)), Passif);
        assert_eq!(ModeDefender::depuis(Some("SxS Passive Mode"), None), Passif);
        assert_eq!(ModeDefender::depuis(Some("EDR Block Mode"), None), BlocageEdr);
        assert_eq!(ModeDefender::depuis(Some("Not running"), Some(true)), Coupe);
        assert_eq!(ModeDefender::depuis(Some(""), Some(true)), Actif);
        assert_eq!(ModeDefender::depuis(None, Some(false)), Coupe);
        // Ni mode ni antivirus lus : jamais « actif ».
        assert_eq!(ModeDefender::depuis(None, None), Illisible);
        assert_eq!(ModeDefender::depuis(Some("Mode inventé"), Some(true)), Illisible);
    }

    #[test]
    fn valeurs_des_options() {
        assert_eq!(Opt::TempsReel.etat(Some(0)), EtatOpt::Allumee);
        assert_eq!(Opt::TempsReel.etat(Some(1)), EtatOpt::Coupee);
        assert_eq!(Opt::PremiereVue.etat(Some(1)), EtatOpt::Coupee);
        assert_eq!(Opt::Cloud.etat(Some(0)), EtatOpt::Coupee);
        assert_eq!(Opt::Cloud.etat(Some(1)), EtatOpt::Base);
        assert_eq!(Opt::Cloud.etat(Some(2)), EtatOpt::Avancee);
        assert_eq!(Opt::Echantillons.etat(Some(0)), EtatOpt::ToujoursDemander);
        assert_eq!(Opt::Echantillons.etat(Some(1)), EtatOpt::SursSansDemander);
        assert_eq!(Opt::Echantillons.etat(Some(2)), EtatOpt::Jamais);
        assert_eq!(Opt::Echantillons.etat(Some(3)), EtatOpt::TousSansDemander);
        assert_eq!(Opt::Pua.etat(Some(1)), EtatOpt::Bloque);
        assert_eq!(Opt::Reseau.etat(Some(2)), EtatOpt::Audit);
        assert_eq!(Opt::Dossiers.etat(Some(3)), EtatOpt::BloqueDisques);
        assert_eq!(Opt::Dossiers.etat(Some(4)), EtatOpt::AuditDisques);
        // Ce que Microsoft ne documente pas n'est ni allumé ni coupé.
        assert_eq!(Opt::Reseau.etat(Some(3)), EtatOpt::Autre(3));
        assert_eq!(Opt::Reseau.etat(Some(6)), EtatOpt::Autre(6));
        assert_eq!(Opt::Scripts.etat(Some(2)), EtatOpt::Autre(2));
        for o in Opt::TOUTES {
            assert_eq!(o.etat(None), EtatOpt::Illisible, "{}", o.id());
        }
        let ids: std::collections::HashSet<_> = Opt::TOUTES.iter().map(|o| o.id()).collect();
        assert_eq!(ids.len(), Opt::TOUTES.len());
    }

    #[test]
    fn regles_asr_lues() {
        let a = Asr::depuis(
            &textes(&[
                "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",
                "{be9ba2d9-53ea-4cdc-84e5-9b1eeee46550}",
                "56a863a9-875e-4185-98a7-b882c64b5ce5",
                "33ddedf1-c6e0-47cb-833e-de6133960387",
                "26190899-1602-49e8-8b27-eb1d0a1ce869",
                "\u{1b}]52;c;piege\u{7}",
                "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",
            ]),
            &[Some(0), Some(1), Some(2), Some(6), Some(9)],
        );
        assert_eq!(
            a.regles,
            vec![
                ("56a863a9-875e-4185-98a7-b882c64b5ce5", ActionAsr::Audit),
                ("d4f940ab-401b-4efc-aadc-ad5f3c50688a", ActionAsr::Coupee),
                ("26190899-1602-49e8-8b27-eb1d0a1ce869", ActionAsr::Autre(9)),
                // Plus de règles que d'actions : l'action de la dernière n'est pas supposée.
                ("7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", ActionAsr::Illisible),
                ("be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", ActionAsr::Bloque),
                ("33ddedf1-c6e0-47cb-833e-de6133960387", ActionAsr::Avertit),
            ]
        );
        assert_eq!(a.inconnues, 1);
        assert_eq!(
            asr_de_mdm("D4F940AB-401B-4EFC-AADC-AD5F3C50688A=1|inconnue=2||56a863a9-875e-4185-98a7-b882c64b5ce5=2"),
            vec![
                "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
                "56a863a9-875e-4185-98a7-b882c64b5ce5"
            ]
        );
    }

    /// 5 (« NotConfigured ») est une règle listée sans être réglée : comptée avec les coupées, jamais « valeur 5 ».
    #[test]
    fn asr_non_reglee_comptee() {
        assert_eq!(ActionAsr::depuis(Some(5)), ActionAsr::NonReglee);
        let mut e = courant();
        if let Some(p) = e.preferences.as_mut() {
            p.asr = Asr::depuis(
                &textes(&[
                    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2",
                    "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
                ]),
                &[Some(1), Some(5)],
            );
        }
        let l = lignes(&e).join("\n");
        assert!(
            l.contains("1 bloquent · 0 en audit · 0 avertissent · 18 désactivées ou non réglées"),
            "{l}"
        );
        assert!(l.contains("non réglée "));
        assert!(!l.contains("valeur 5"));
        let j = json(&e);
        let regles = j["asr"]["regles"].as_array().cloned().unwrap_or_default();
        assert!(
            regles
                .iter()
                .any(|r| r["id"] == "d4f940ab-401b-4efc-aadc-ad5f3c50688a" && r["action"] == 5)
        );
    }

    #[test]
    fn table_asr_complete() {
        let uniques: std::collections::HashSet<_> = ASR_TOUTES.iter().collect();
        assert_eq!(uniques.len(), 19);
        for id in ASR_TOUTES {
            assert_eq!(id, id.to_ascii_lowercase());
            assert_eq!(id.len(), 36);
            assert!(nom_asr(id).is_some(), "{id}");
            crate::langue::en_anglais(|| assert!(nom_asr(id).is_some(), "{id}"));
        }
        for id in crate::machine::gestes::ASR_BASE
            .iter()
            .chain(&crate::machine::gestes::ASR_BUREAUTIQUE)
        {
            assert!(ASR_TOUTES.contains(id), "{id}");
        }
        assert_eq!(nom_asr("inconnue"), None);
    }

    #[test]
    fn listes_comptees_jamais_montrees() {
        assert_eq!(
            Compte::depuis(&textes(&["C:\\Jeux", "D:\\Outils", ""])),
            Compte::Nombre(2)
        );
        assert_eq!(
            Compte::depuis(&textes(&["N/A: Must be an administrator to view exclusions"])),
            Compte::Masque
        );
        assert_eq!(Compte::depuis(&[]), Compte::Nombre(0));
    }

    #[test]
    fn falsifications_et_produits() {
        assert_eq!(SourceFalsif::depuis("Intune"), Some(SourceFalsif::Organisation));
        assert_eq!(SourceFalsif::depuis("ATP"), Some(SourceFalsif::Organisation));
        assert_eq!(SourceFalsif::depuis("ConfigMgr"), Some(SourceFalsif::Organisation));
        assert_eq!(SourceFalsif::depuis("UI"), Some(SourceFalsif::Personne));
        assert_eq!(SourceFalsif::depuis("Signatures"), Some(SourceFalsif::Autre));
        assert_eq!(SourceFalsif::depuis(""), None);
        assert_eq!(SourceFalsif::depuis("N/A"), None);
        let av = Produit::depuis(Some("Antivirus \u{1b}[2KX"), Some(0x61100), Some("C:\\x\\av.exe"));
        assert_eq!(av.actif, Some(true));
        assert!(!av.microsoft);
        assert!(!av.nom.contains('\u{1b}'));
        assert_eq!(Produit::depuis(Some("Y"), Some(0x60100), None).actif, Some(false));
        assert_eq!(Produit::depuis(Some("Y"), None, None).actif, None);
        let long = "A".repeat(300);
        assert!(largeur_affichee(&Produit::depuis(Some(&long), None, None).nom) <= 64);
        assert!(Produit::depuis(Some("Windows Defender"), Some(0x61100), Some("windowsdefender://")).microsoft);
    }

    #[test]
    fn gestion_et_inscriptions() {
        assert!(inscription_active(Some("MS DM Server"), Some(1)));
        assert!(!inscription_active(Some(""), Some(1)));
        assert!(!inscription_active(None, Some(1)));
        assert!(!inscription_active(Some("MS DM Server"), Some(0)));
        assert!(!inscription_active(Some("MS DM Server"), None));
        let g = Gestion {
            domaine: Some(false),
            entra: Some(false),
            mdm: Some(false),
        };
        assert_eq!(g.geree(), Some(false));
        assert_eq!(Gestion { mdm: None, ..g }.geree(), None);
        assert_eq!(
            Gestion {
                entra: Some(true),
                mdm: None,
                ..g
            }
            .geree(),
            Some(true)
        );
        assert_eq!(une_presente([Some(false), None, Some(true)]), Some(true));
        assert_eq!(une_presente([Some(false), Some(false)]), Some(false));
        assert_eq!(une_presente([]), Some(false));
        assert_eq!(Edition::depuis("Core"), Edition::Famille);
        assert_eq!(Edition::depuis("CoreSingleLanguage"), Edition::Famille);
        assert_eq!(Edition::depuis("Professional"), Edition::Autre);
        assert_eq!(Edition::depuis("ServerStandard"), Edition::Serveur);
    }

    #[test]
    fn strategies_toutes_sous_hklm_et_sans_doublon() {
        for o in Opt::TOUTES {
            let s = strategies_de(o);
            assert_ne!(s.len(), 0);
            for (cle, valeur) in s {
                assert!(cle.starts_with(r"SOFTWARE\"), "{cle}");
                assert!(!valeur.is_empty() && !valeur.contains('\\'));
            }
        }
        assert!(GPO_ASR.starts_with(GPO));
    }

    /// Chaque ligne tient dans la largeur, en français comme en anglais, pour un PC courant, un PC où rien ne se lit
    /// et un PC à antivirus tiers au nom très long.
    #[test]
    fn lignes_dans_la_largeur() {
        let mut tiers = courant();
        tiers.statut = Some(Statut {
            mode: ModeDefender::Passif,
            temps_reel: Some(false),
            falsifications: Some(true),
            source: Some(SourceFalsif::Organisation),
        });
        tiers.centre.antivirus = Some(vec![Produit::depuis(
            Some(&"Antivirus Très Long ".repeat(10)),
            Some(0x61100),
            None,
        )]);
        tiers.centre.pare_feu = Some(vec![Produit::depuis(
            Some(&"Pare-feu ".repeat(20)),
            Some(0x61100),
            None,
        )]);
        tiers.edition = Some(Edition::Famille);
        tiers.gestion.mdm = Some(true);
        let mut cache = courant();
        if let Some(p) = cache.preferences.as_mut() {
            p.exclusions = [Compte::Masque; 3];
            p.asr = Asr::depuis(
                &ASR_TOUTES.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
                &[Some(1), Some(2), Some(6), Some(0), Some(99)],
            );
        }
        for e in [courant(), Etat::default(), tiers, cache] {
            for anglais in [false, true] {
                let l = if anglais {
                    crate::langue::en_anglais(|| lignes(&e))
                } else {
                    lignes(&e)
                };
                for ligne in &l {
                    assert!(largeur_affichee(ligne) <= crate::ui::LARGEUR, "{ligne}");
                }
            }
        }
    }

    #[test]
    fn ecran_d_un_pc_courant() {
        let l = lignes(&courant()).join("\n");
        // L'écran change les réglages : plus de « lecture seule », plus de renvoi à l'ancien outil.
        assert!(!l.contains("Lecture seule") && !l.contains("vanguard defender"));
        assert!(l.contains("actif"));
        assert!(l.contains("avancée"));
        assert!(l.contains("Public (réseau actuel)"));
        assert!(l.contains("412"));
        assert!(l.contains("* imposée par une stratégie"));
        assert!(l.contains("1 autre(s) règle(s)"));
        assert!(l.contains("1 dossier(s)"));
        assert!(l.contains("n'est géré par aucune organisation"));
        let en = crate::langue::en_anglais(|| lignes(&courant()).join("\n"));
        assert!(!en.contains("Read-only"));
        assert!(en.contains("Public (current network)"));
        assert!(!en.contains("Lecture seule"));
    }

    /// Rien ne se lit (Wine, WMI en panne) : tout est dit non vérifié, rien n'est dit actif ni allumé.
    #[test]
    fn rien_de_lu_rien_de_sain() {
        let l = lignes(&Etat::default()).join("\n");
        assert!(l.contains("non vérifié"));
        for mot in ["actif", "allumé", "bloque", "aucune", "active", "n'est géré par aucune"] {
            let sans_couleur: String = l.replace(RESET, "");
            assert!(
                !sans_couleur
                    .lines()
                    .any(|x| x.trim_end().ends_with(&format!(" {mot}")) && !x.contains("Lecture")),
                "« {mot} » sans mesure :\n{l}"
            );
        }
        let j = json(&Etat::default());
        assert_eq!(j["defender"]["mode"], "illisible");
        assert_eq!(j["defender"]["options"][0]["etat"], "illisible");
        assert_eq!(j["gestion"]["geree"], serde_json::Value::Null);
        assert_eq!(j["pare_feu"]["lu"], false);
    }

    #[test]
    fn passif_dit_et_grise() {
        let mut e = courant();
        e.statut = Some(Statut {
            mode: ModeDefender::Passif,
            ..e.statut.clone().unwrap()
        });
        e.centre.antivirus = Some(vec![Produit::depuis(Some("Antivirus Exemple"), Some(0x61100), None)]);
        let l = lignes(&e).join("\n");
        assert!(l.contains("Antivirus Exemple est votre antivirus"));
        assert!(l.contains("Sans effet : Defender n'est pas l'antivirus actif."));
        assert!(!l.contains(&format!("{VERT}bloque")));
    }

    /// `LocalPolicyModifyState = 2` : l'entrant bloqué du profil actuel, pas une stratégie.
    #[test]
    fn entrant_bloque_n_est_pas_une_strategie() {
        let mut e = courant();
        if let Some(f) = e.pare_feu.as_mut() {
            f.modification = Some(2);
        }
        let l = lignes(&e).join("\n");
        assert!(l.contains("tout l'entrant est bloqué"), "{l}");
        assert_eq!(json(&e)["pare_feu"]["modification"], "entrant-bloque");
    }

    /// Le pare-feu d'Intune ne se lit pas : sur un PC inscrit (ou d'inscription illisible), « aucune GPO » devient
    /// non vérifié, à l'écran comme dans le JSON ; une GPO lue reste imposée.
    #[test]
    fn pare_feu_libre_seulement_hors_mdm() {
        let mut e = courant();
        assert_eq!(json(&e)["pare_feu"]["profils"][1]["imposee"], false);
        for mdm in [Some(true), None] {
            e.gestion.mdm = mdm;
            assert_eq!(e.pare_feu_impose(), [Some(true), None, None]);
            let j = json(&e);
            assert_eq!(j["pare_feu"]["profils"][0]["imposee"], true);
            assert_eq!(j["pare_feu"]["profils"][1]["imposee"], serde_json::Value::Null);
            assert!(
                lignes(&e)
                    .join("\n")
                    .contains("↳ stratégie (GPO ou Intune) : non vérifiée.")
            );
        }
    }

    /// L'état de Defender ne se lit pas, ses réglages oui : rien en vert, et l'effet dit non vérifié.
    #[test]
    fn mode_illisible_rien_en_vert() {
        let mut e = courant();
        e.statut = None;
        let l = lignes(&e).join("\n");
        assert!(
            l.contains("Effet non vérifié : l'état de Defender ne se lit pas."),
            "{l}"
        );
        // Le pare-feu se lit à part : seules les sections de Defender sont grises.
        let defender = l.split("Pare-feu").next().unwrap_or_default();
        assert!(defender.contains("Règles ASR"), "{l}");
        assert!(!defender.contains(VERT), "{l}");
    }

    #[test]
    fn falsifications_e5_par_l_organisation() {
        assert_eq!(SourceFalsif::depuis("E5 transition"), Some(SourceFalsif::Organisation));
    }

    fn textes_de(v: &serde_json::Value, sortie: &mut Vec<String>) {
        match v {
            serde_json::Value::String(s) => sortie.push(s.clone()),
            serde_json::Value::Array(a) => a.iter().for_each(|x| textes_de(x, sortie)),
            serde_json::Value::Object(o) => o.values().for_each(|x| textes_de(x, sortie)),
            _ => {}
        }
    }

    /// Le JSON ne porte ni nom d'antivirus ni chemin, seulement des identifiants fermés et des nombres.
    #[test]
    fn json_sans_donnee_personnelle() {
        let mut e = courant();
        e.centre.antivirus = Some(vec![Produit::depuis(
            Some("Antivirus d'alice"),
            Some(0x61100),
            Some("C:\\Users\\alice\\av.exe"),
        )]);
        let texte = json(&e).to_string();
        assert!(!texte.contains("alice"));
        assert!(!texte.contains("Defender\""));
        assert!(!texte.contains("00000000-0000"));
        let j = json(&e);
        assert_eq!(j["version"], 1);
        assert_eq!(j["lecture_seule"], true);
        assert_eq!(j["defender"]["mode"], "actif");
        assert_eq!(j["defender"]["options"][1]["etat"], "avancee");
        assert_eq!(j["defender"]["options"][4]["imposee"], true);
        assert_eq!(j["asr"]["inconnues"], 1);
        assert_eq!(j["asr"]["regles"][0]["id"], "56a863a9-875e-4185-98a7-b882c64b5ce5");
        assert_eq!(j["asr"]["regles"][0]["imposee"], true);
        assert_eq!(j["pare_feu"]["profils"][2]["reseau_actuel"], true);
        assert_eq!(j["pare_feu"]["modification"], "strategie");
        assert_eq!(j["centre_securite"]["antivirus_tiers_en_marche"], true);
        assert_eq!(json_hors_windows()["disponible"], false);
        // Chaque texte du JSON est un identifiant de Vanguard (minuscules, chiffres, tirets) : rien du système.
        let mut t = Vec::new();
        textes_de(&j, &mut t);
        assert!(
            t.iter().all(|s| s
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')),
            "{t:?}"
        );
    }

    /// Ce qui laisse les règles ASR agir, dans l'ordre : Defender actif, puis le temps réel, puis l'édition ; le JSON
    /// le dit par un identifiant.
    #[test]
    fn effet_des_regles_asr() {
        let mut e = courant();
        assert_eq!(effet_asr(&e), EffetAsr::SAppliquent);
        assert_eq!(json(&e)["asr"]["effet"], "s-appliquent");
        e.edition = Some(Edition::Famille);
        assert_eq!(effet_asr(&e), EffetAsr::Famille);
        e.statut.as_mut().unwrap().temps_reel = Some(false);
        assert_eq!(effet_asr(&e), EffetAsr::TempsReelCoupe);
        assert_eq!(json(&e)["asr"]["effet"], "temps-reel-coupe");
        assert!(texte_effet_asr(&e).contains("les règles ne s'appliquent pas"));
        crate::langue::en_anglais(|| assert!(texte_effet_asr(&e).contains("the rules do not apply")));
        for m in [ModeDefender::Passif, ModeDefender::BlocageEdr, ModeDefender::Coupe] {
            e.statut.as_mut().unwrap().mode = m;
            assert_eq!(effet_asr(&e), EffetAsr::DefenderInactif, "{m:?}");
            assert!(texte_effet_asr(&e).starts_with("Sans effet"));
        }
        e.statut.as_mut().unwrap().mode = ModeDefender::Illisible;
        e.statut.as_mut().unwrap().temps_reel = Some(true);
        e.edition = Some(Edition::Autre);
        assert_eq!(effet_asr(&e), EffetAsr::NonVerifie);
        e.preferences = None;
        assert_eq!(json(&e)["asr"]["effet"], serde_json::Value::Null);
    }

    /// Relecture D4 : Defender illisible sur un Windows Famille dit « non vérifié », pas le texte de Famille.
    #[test]
    fn effet_asr_illisible_avant_famille() {
        let mut e = courant();
        e.edition = Some(Edition::Famille);
        e.statut.as_mut().unwrap().mode = ModeDefender::Illisible;
        assert_eq!(effet_asr(&e), EffetAsr::NonVerifie);
        assert_eq!(texte_effet_asr(&e), effet_non_verifie());
    }

    /// Les 8 règles écartées des Réglages recommandés ont chacune leur avertissement, « Essayez d'abord Audit » à la
    /// fin ; celles qui ont besoin du cloud le disent ; les 11 autres n'en ont pas.
    #[test]
    fn avertissement_des_8_regles_ecartees() {
        let avec: Vec<&str> = ASR_TOUTES
            .iter()
            .copied()
            .filter(|id| avertissement_asr(id).is_some())
            .collect();
        assert_eq!(avec.len(), 8);
        for id in &avec {
            assert!(
                !crate::machine::gestes::ASR_BASE.contains(id) && !crate::machine::gestes::ASR_BUREAUTIQUE.contains(id),
                "{id}"
            );
            let fr = avertissement_asr(id).unwrap();
            assert!(fr.ends_with("Essayez d'abord Audit."), "{fr}");
            assert_eq!(fr.contains("cloud"), asr_avec_cloud(id), "{fr}");
            crate::langue::en_anglais(|| {
                let en = avertissement_asr(id).unwrap();
                assert!(en.ends_with("Try Audit first."), "{en}");
                assert_eq!(en.contains("cloud"), asr_avec_cloud(id), "{en}");
            });
        }
        assert!(avec.iter().all(|id| ASR_TOUTES.contains(id)));
        assert_eq!(ASR_TOUTES.iter().filter(|id| asr_avec_cloud(id)).count(), 3);
    }

    #[test]
    fn temps_reel_effectif_avant_la_preference() {
        let mut e = courant();
        // La préférence dit allumée, l'effet relu dit coupée (une stratégie l'emporte) : l'effet.
        e.statut.as_mut().unwrap().temps_reel = Some(false);
        assert_eq!(e.etat_opt(Opt::TempsReel), EtatOpt::Coupee);
        assert!(
            lignes(&e)
                .join("\n")
                .contains("Sans effet tant que la protection en temps réel est coupée.")
        );
    }
}

//! Les réglages du registre que le processus élevé met à leur valeur sûre (`vanguard:reglage <mot>`), et leur remise
//! (`vanguard:reglage-remettre <mot>`), défense D6b.
//!
//! La ligne ne porte qu'un identifiant (`gestes::IdReglage`) : la clé, les valeurs et leurs cibles sont celles de la
//! table ci-dessous, jamais un chemin venu de la ligne. Avant d'écrire, la valeur d'avant de chaque valeur (son type et
//! ses octets exacts, ou son absence) est notée sous HKLM `SOFTWARE\Vanguard\ChoixAvant` (que seuls les
//! administrateurs écrivent), scellée par son empreinte SHA-256 ; sans note qui se relit, rien n'est écrit. La seule
//! exception est le mot de passe en clair de l'ouverture automatique (`DefaultPassword`) : il n'est jamais noté ni
//! montré, exprès, et son retrait est « non annulable » (question à part dans le processus élevé).
//!
//! La remise n'écrit que ce que la note garde, et seulement si chaque valeur est encore celle que Vanguard a écrite :
//! jamais par-dessus un changement fait depuis. Le geste passe par un `Registre` : winreg sous Windows
//! (`reglages_ecriture`), un faux registre dans les essais, si bien que chaque cas se vérifie sur tous les systèmes.
//!
//! La même note sert au chemin d'un service (ImagePath) que Vanguard change en l'écrivant au registre : valeurs
//! « avant » et « ecrit ».

use sha2::{Digest, Sha256};

use crate::machine::gestes::IdReglage;
use crate::modele::Echec;
use crate::ui::{tr, trf, trp};

/// La ruche d'une valeur : celle de la machine (HKLM, vue 64 bits) ou celle du compte de la personne (HKU\<SID>).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ruche {
    Machine,
    Compte,
}

/// Ce qu'une valeur doit devenir.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cible {
    /// REG_DWORD de cette valeur.
    Dword(u32),
    /// REG_DWORD qui a au moins ces bits : les autres bits lus restent (une valeur plus forte ne baisse jamais).
    Bits(u32),
    /// REG_SZ de ce texte (comparé sans la casse).
    Sz(&'static str),
    /// Retirée.
    Absente,
}

/// Une valeur de la table : où, laquelle, sa cible ; `secret` : jamais montrée ni notée (`DefaultPassword`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ecrit {
    pub(crate) ruche: Ruche,
    pub(crate) cle: String,
    pub(crate) valeur: &'static str,
    pub(crate) cible: Cible,
    pub(crate) secret: bool,
}

/// Une valeur lue : le code de son type (1 REG_SZ, 2 REG_EXPAND_SZ, 3 REG_BINARY, 4 REG_DWORD, 7 REG_MULTI_SZ,
/// 11 REG_QWORD) et ses octets exacts. Ses octets sont mis à zéro quand elle disparaît (un mot de passe en clair
/// peut y passer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Brute {
    pub(crate) code: u32,
    pub(crate) octets: Vec<u8>,
}

impl Drop for Brute {
    fn drop(&mut self) {
        self.octets.fill(0);
        std::hint::black_box(&self.octets);
    }
}

/// Les types qu'une note sait garder.
pub(crate) const CODES: [u32; 6] = [1, 2, 3, 4, 7, 11];
/// La plus longue valeur notée, en octets : au-delà, ce n'est pas un réglage de cette table (rien n'est écrit).
pub(crate) const VALEUR_MAX: usize = 1024;
/// Le début de chaque note de réglage : jamais celui d'une note de choix (`choix_note`).
const ENTETE: &[u8] = b"VGREG\x01";
/// Le préfixe du nom d'une note de réglage, puis celui d'un chemin de service : jamais le nom d'un choix.
pub(crate) const PREFIXE_REGLAGE: &str = "reg-";
pub(crate) const PREFIXE_SERVICE: &str = "svc-";

const LSA: &str = r"SYSTEM\CurrentControlSet\Control\Lsa";
const WINLOGON: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
const HVCI: &str = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity";
const STATION: &str = r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters";
const PAUSE: &str = r"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings";
const PS_STRATEGIE: &str = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell";

fn machine(cle: &str, valeur: &'static str, cible: Cible) -> Ecrit {
    Ecrit {
        ruche: Ruche::Machine,
        cle: cle.to_string(),
        valeur,
        cible,
        secret: false,
    }
}

fn compte(cle: &str, valeur: &'static str, cible: Cible) -> Ecrit {
    Ecrit {
        ruche: Ruche::Compte,
        ..machine(cle, valeur, cible)
    }
}

/// Les valeurs d'un réglage, dans l'ordre où elles sont écrites (pour l'ouverture automatique, `AutoAdminLogon=0`
/// d'abord : si le retrait du mot de passe échouait ensuite, Windows ne s'ouvrirait plus tout seul quand même).
pub(crate) fn table(id: IdReglage) -> Vec<Ecrit> {
    use Cible::{Absente, Bits, Dword, Sz};
    match id {
        IdReglage::LsaPpl => vec![machine(LSA, "RunAsPPL", Dword(2))],
        IdReglage::AssistanceCoupe => vec![machine(
            r"SYSTEM\CurrentControlSet\Control\Remote Assistance",
            "fAllowToGetHelp",
            Dword(0),
        )],
        IdReglage::OuvertureAutoMdp => vec![
            machine(WINLOGON, "AutoAdminLogon", Sz("0")),
            Ecrit {
                secret: true,
                ..machine(WINLOGON, "DefaultPassword", Absente)
            },
        ],
        IdReglage::OuvertureAutoCoupe => vec![machine(WINLOGON, "AutoAdminLogon", Sz("0"))],
        IdReglage::SmartScreen => vec![machine(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
            "SmartScreenEnabled",
            Sz("Warn"),
        )],
        IdReglage::SmartScreenStrategie => vec![machine(
            r"SOFTWARE\Policies\Microsoft\Windows\System",
            "EnableSmartScreen",
            Absente,
        )],
        IdReglage::Hvci => vec![machine(HVCI, "Enabled", Dword(1)), machine(HVCI, "Locked", Dword(0))],
        IdReglage::MajPause => [
            "PauseUpdatesExpiryTime",
            "PauseUpdatesStartTime",
            "PauseFeatureUpdatesStartTime",
            "PauseFeatureUpdatesEndTime",
            "PauseQualityUpdatesStartTime",
            "PauseQualityUpdatesEndTime",
        ]
        .into_iter()
        .map(|v| machine(PAUSE, v, Absente))
        .collect(),
        IdReglage::MajStrategie => vec![machine(
            r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
            "NoAutoUpdate",
            Absente,
        )],
        IdReglage::SmbSignature => vec![machine(STATION, "RequireSecuritySignature", Dword(1))],
        IdReglage::SmbInviteStrategie => vec![machine(
            r"SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation",
            "AllowInsecureGuestAuth",
            Absente,
        )],
        IdReglage::PsStrategieMachine => vec![
            machine(PS_STRATEGIE, "ExecutionPolicy", Absente),
            machine(PS_STRATEGIE, "EnableScripts", Absente),
        ],
        IdReglage::PsStrategieCompte => vec![
            compte(PS_STRATEGIE, "ExecutionPolicy", Absente),
            compte(PS_STRATEGIE, "EnableScripts", Absente),
        ],
        IdReglage::Macros(..) => id.office().map_or_else(Vec::new, |(version, cle)| {
            vec![compte(
                &format!(r"Software\Policies\Microsoft\Office\{version}\{cle}\Security"),
                "VBAWarnings",
                Absente,
            )]
        }),
        IdReglage::CredentialGuard => vec![
            machine(
                r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
                "EnableVirtualizationBasedSecurity",
                Dword(1),
            ),
            // Au moins le démarrage sécurisé (bit 1) ; 3 (avec la protection DMA) reste 3.
            machine(
                r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
                "RequirePlatformSecurityFeatures",
                Bits(1),
            ),
            machine(LSA, "LsaCfgFlags", Dword(2)),
        ],
    }
}

/// La valeur que la cible écrit ; `None` pour une valeur à retirer.
pub(crate) fn brute(cible: Cible) -> Option<Brute> {
    match cible {
        Cible::Dword(n) | Cible::Bits(n) => Some(Brute {
            code: 4,
            octets: n.to_le_bytes().to_vec(),
        }),
        Cible::Sz(t) => Some(Brute {
            code: 1,
            octets: t.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect(),
        }),
        Cible::Absente => None,
    }
}

/// La valeur que `poser` écrit pour atteindre `cible` depuis `lue` : celle de la cible, ou pour des bits, le DWORD lu
/// avec ces bits en plus (un autre type, ou rien : les bits seuls).
pub(crate) fn a_ecrire(cible: Cible, lue: Option<&Brute>) -> Option<Brute> {
    match cible {
        Cible::Bits(n) => brute(Cible::Dword(lue.and_then(dword).unwrap_or(0) | n)),
        c => brute(c),
    }
}

/// Le texte d'un REG_SZ ou REG_EXPAND_SZ, sans ses NUL de fin ; `None` pour un autre type ou un UTF-16 invalide.
pub(crate) fn texte(b: &Brute) -> Option<String> {
    if !matches!(b.code, 1 | 2) || !b.octets.len().is_multiple_of(2) {
        return None;
    }
    let unites: Vec<u16> = b
        .octets
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u16::from_le_bytes(*p))
        .collect();
    let fin = unites.iter().rposition(|&u| u != 0).map_or(0, |i| i + 1);
    String::from_utf16(unites.get(..fin)?).ok()
}

/// Un DWORD lu ; `None` pour un autre type.
pub(crate) fn dword(b: &Brute) -> Option<u32> {
    (b.code == 4).then(|| b.octets.as_slice().try_into().ok().map(u32::from_le_bytes))?
}

/// La valeur lue est-elle déjà à sa cible ?
pub(crate) fn atteinte(cible: Cible, lue: Option<&Brute>) -> bool {
    match (cible, lue) {
        (Cible::Absente, None) => true,
        (Cible::Dword(n), Some(b)) => dword(b) == Some(n),
        (Cible::Bits(n), Some(b)) => dword(b).is_some_and(|v| v & n == n),
        (Cible::Sz(t), Some(b)) => texte(b).is_some_and(|x| x.trim().eq_ignore_ascii_case(t)),
        _ => false,
    }
}

/// Une valeur montrée : « RunAsPPL=absente », « RunAsPPL=0 », « AutoAdminLogon=1 » ; le mot de passe jamais.
pub(crate) fn decrire(e: &Ecrit, lue: Option<&Brute>) -> String {
    let v = match lue {
        None => tr!("absente", "absent").to_string(),
        Some(_) if e.secret => tr!("présente (jamais montrée)", "present (never shown)").to_string(),
        Some(b) => match (dword(b), texte(b)) {
            (Some(n), _) => n.to_string(),
            (None, Some(t)) => {
                let court: String = t.chars().filter(|c| !c.is_control()).take(48).collect();
                format!("« {court} »")
            }
            (None, None) => trf!("type {}", "type {}", b.code),
        },
    };
    format!("{}={v}", e.valeur)
}

fn decrire_tout(ecrits: &[Ecrit], lues: &[Option<Brute>]) -> String {
    ecrits
        .iter()
        .zip(lues)
        .map(|(e, l)| decrire(e, l.as_ref()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Un SID de compte tel que `HKEY_USERS` le nomme : « S-1-… », chiffres et tirets seulement, borné.
pub(crate) fn sid_valide(sid: &str) -> bool {
    sid.len() <= 184
        && sid
            .strip_prefix("S-1-")
            .is_some_and(|r| !r.is_empty() && r.bytes().all(|b| b.is_ascii_digit() || b == b'-'))
}

/// Le nom de la note d'un réglage : `reg-<mot>`, et `reg-<mot>~<SID>` pour un réglage du compte (chaque compte la
/// sienne). `None` pour un réglage du compte sans SID valide.
pub(crate) fn nom_note(id: IdReglage, sid: Option<&str>) -> Option<String> {
    if id.du_compte() {
        let sid = sid.filter(|s| sid_valide(s))?;
        Some(format!("{PREFIXE_REGLAGE}{}~{sid}", id.mot()))
    } else {
        Some(format!("{PREFIXE_REGLAGE}{}", id.mot()))
    }
}

/// Le nom de la note du chemin d'un service : « svc- » puis les 16 premiers chiffres de l'empreinte de son nom en
/// minuscules (un nom de service peut avoir 256 caractères, un nom de valeur du registre en garde 16 383).
pub(crate) fn nom_note_service(nom: &str) -> String {
    let e = Sha256::digest(nom.to_lowercase().as_bytes());
    let hex = e.iter().take(8).fold(String::new(), |mut h, o| {
        let _ = std::fmt::Write::write_fmt(&mut h, format_args!("{o:02x}"));
        h
    });
    format!("{PREFIXE_SERVICE}{hex}")
}

fn pousser_texte(n: &mut Vec<u8>, t: &str) -> Option<()> {
    n.extend_from_slice(&u16::try_from(t.len()).ok()?.to_le_bytes());
    n.extend_from_slice(t.as_bytes());
    Some(())
}

/// La note : l'en-tête, son nom, puis pour chaque valeur son nom, sa présence, son type et ses octets ; enfin
/// l'empreinte SHA-256 de tout ce qui précède. `None` : un type qu'elle ne sait pas garder, une valeur trop longue,
/// ou plus que `choix_avant::NOTE_MAX`.
pub(crate) fn coder(nom: &str, valeurs: &[(&str, Option<&Brute>)]) -> Option<Vec<u8>> {
    let mut n = ENTETE.to_vec();
    pousser_texte(&mut n, nom)?;
    n.push(u8::try_from(valeurs.len()).ok()?);
    for (v, lue) in valeurs {
        pousser_texte(&mut n, v)?;
        match lue {
            None => n.push(0),
            Some(b) => {
                if !CODES.contains(&b.code) || b.octets.len() > VALEUR_MAX {
                    return None;
                }
                n.push(1);
                n.extend_from_slice(&b.code.to_le_bytes());
                n.extend_from_slice(&u32::try_from(b.octets.len()).ok()?.to_le_bytes());
                n.extend_from_slice(&b.octets);
            }
        }
    }
    let e = Sha256::digest(&n);
    n.extend_from_slice(&e);
    (n.len() <= super::choix_avant::NOTE_MAX).then_some(n)
}

struct Lecteur<'a>(&'a [u8]);

impl Lecteur<'_> {
    fn prendre(&mut self, n: usize) -> Option<&[u8]> {
        let (a, b) = self.0.split_at_checked(n)?;
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        self.prendre(1)?.first().copied()
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.prendre(2)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.prendre(4)?.try_into().ok()?))
    }
    fn texte(&mut self) -> Option<&str> {
        let n = usize::from(self.u16()?);
        std::str::from_utf8(self.prendre(n)?).ok()
    }
}

/// Les valeurs d'une note, si et seulement si elle est entière (empreinte), porte ce nom et exactement ces noms de
/// valeurs, dans cet ordre, avec des types et des longueurs qu'une note écrit ; `None` sinon (abîmée, forgée, d'une
/// autre version de la table).
pub(crate) fn decoder(octets: &[u8], nom: &str, attendues: &[&str]) -> Option<Vec<Option<Brute>>> {
    if octets.len() > super::choix_avant::NOTE_MAX {
        return None;
    }
    let (corps, empreinte) = octets.split_at_checked(octets.len().checked_sub(32)?)?;
    if Sha256::digest(corps).as_slice() != empreinte {
        return None;
    }
    let mut l = Lecteur(corps.strip_prefix(ENTETE)?);
    if l.texte()? != nom || usize::from(l.u8()?) != attendues.len() {
        return None;
    }
    let mut valeurs = Vec::with_capacity(attendues.len());
    for a in attendues {
        if l.texte()? != *a {
            return None;
        }
        valeurs.push(match l.u8()? {
            0 => None,
            1 => {
                let code = l.u32()?;
                let n = usize::try_from(l.u32()?).ok()?;
                if !CODES.contains(&code) || n > VALEUR_MAX {
                    return None;
                }
                Some(Brute {
                    code,
                    octets: l.prendre(n)?.to_vec(),
                })
            }
            _ => return None,
        });
    }
    l.0.is_empty().then_some(valeurs)
}

/// Ce que le processus élevé lit et écrit : winreg sous Windows, un faux dans les essais. Chaque erreur dit sa raison
/// en type (`Echec`), montrée telle quelle.
pub(crate) trait Registre {
    /// La valeur (`Ok(None)` : absente, clé comprise).
    fn lire(&mut self, ruche: Ruche, cle: &str, valeur: &str) -> Result<Option<Brute>, Echec>;
    /// Écrit exactement ces type et octets (la clé est créée au besoin).
    fn ecrire(&mut self, ruche: Ruche, cle: &str, valeur: &str, b: &Brute) -> Result<(), Echec>;
    /// Retire la valeur ; déjà absente : `Ok`.
    fn effacer(&mut self, ruche: Ruche, cle: &str, valeur: &str) -> Result<(), Echec>;
    fn lire_note(&mut self, nom: &str) -> Option<Vec<u8>>;
    fn ecrire_note(&mut self, nom: &str, octets: &[u8]) -> Result<(), Echec>;
    fn effacer_note(&mut self, nom: &str);
}

/// Ce qu'un réglage ou sa remise a donné.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Issue {
    /// Écrit et relu ; `avant` : les valeurs d'avant, montrables.
    Fait { avant: String },
    /// Déjà ainsi : rien d'écrit.
    Rien(String),
    /// Rien de compté comme fait (ce qui avait été écrit est remis) ; `avant` : les valeurs lues, si elles l'ont été.
    Echec { avant: Option<String>, raison: String },
}

fn echec(avant: Option<String>, raison: impl Into<String>) -> Issue {
    Issue::Echec {
        avant,
        raison: raison.into(),
    }
}

fn lire_tout(r: &mut impl Registre, ecrits: &[Ecrit]) -> Result<Vec<Option<Brute>>, Echec> {
    ecrits.iter().map(|e| r.lire(e.ruche, &e.cle, e.valeur)).collect()
}

fn ecrire_une(r: &mut impl Registre, e: &Ecrit, v: Option<&Brute>) -> Result<(), Echec> {
    match v {
        Some(b) => r.ecrire(e.ruche, &e.cle, e.valeur, b),
        None => r.effacer(e.ruche, &e.cle, e.valeur),
    }
}

/// Remet chaque valeur de `lues` (ce qui était là avant l'écriture) ; vrai si toutes se relisent ainsi.
fn revenir(r: &mut impl Registre, ecrits: &[Ecrit], lues: &[Option<Brute>]) -> bool {
    let mut bon = true;
    for (e, l) in ecrits.iter().zip(lues) {
        // Seule une valeur changée est récrite : celle qui n'a pas pu l'être est encore la bonne.
        if r.lire(e.ruche, &e.cle, e.valeur).ok().as_ref() == Some(l) {
            continue;
        }
        bon &= ecrire_une(r, e, l.as_ref()).is_ok() && r.lire(e.ruche, &e.cle, e.valeur).ok().as_ref() == Some(l);
    }
    bon
}

fn texte_revenu(revenu: bool) -> &'static str {
    if revenu {
        tr!("les valeurs d'avant sont remises", "the previous values are put back")
    } else {
        tr!(
            "ATTENTION : les valeurs d'avant ne se remettent pas toutes, vérifiez ce réglage",
            "WARNING: not all previous values could be put back, check this setting"
        )
    }
}

/// Met le réglage `id` à sa valeur sûre : lu, noté (s'il se remet) puis écrit et relu ; à la moindre erreur après la
/// note, les valeurs d'avant sont remises et la note effacée. `nom` : celui de `nom_note`.
pub(crate) fn poser<R: Registre>(r: &mut R, id: IdReglage, nom: &str) -> Issue {
    let ecrits = table(id);
    if ecrits.is_empty() {
        return echec(
            None,
            tr!(
                "réglage inconnu de la table : rien d'écrit",
                "setting unknown to the table: nothing written"
            ),
        );
    }
    let lues = match lire_tout(r, &ecrits) {
        Ok(l) => l,
        Err(e) => {
            return echec(
                None,
                trf!(
                    "lecture impossible ({e}) : rien d'écrit",
                    "cannot read ({e}): nothing written"
                ),
            );
        }
    };
    let avant = decrire_tout(&ecrits, &lues);
    if ecrits.iter().zip(&lues).all(|(e, l)| atteinte(e.cible, l.as_ref())) {
        return Issue::Rien(avant);
    }
    let annulable = id.annulable();
    if annulable {
        let valeurs: Vec<(&str, Option<&Brute>)> =
            ecrits.iter().zip(&lues).map(|(e, l)| (e.valeur, l.as_ref())).collect();
        let Some(note) = coder(nom, &valeurs) else {
            return echec(
                Some(avant),
                tr!(
                    "une valeur d'avant ne se note pas (type ou longueur inattendus) : rien d'écrit",
                    "a previous value cannot be noted (unexpected type or length): nothing written"
                ),
            );
        };
        if let Err(e) = r.ecrire_note(nom, &note) {
            return echec(
                Some(avant),
                trf!(
                    "la valeur d'avant ne se note pas ({e}) : rien d'écrit",
                    "the previous value cannot be noted ({e}): nothing written"
                ),
            );
        }
        if r.lire_note(nom).as_deref() != Some(note.as_slice()) {
            r.effacer_note(nom);
            return echec(
                Some(avant),
                tr!(
                    "la note ne se relit pas : rien d'écrit",
                    "the note cannot be read back: nothing written"
                ),
            );
        }
    }
    let annuler = |r: &mut R, raison: String| {
        let revenu = revenir(r, &ecrits, &lues);
        if annulable && revenu {
            r.effacer_note(nom);
        }
        echec(Some(avant.clone()), format!("{raison} ; {}", texte_revenu(revenu)))
    };
    for (e, l) in ecrits.iter().zip(&lues) {
        if atteinte(e.cible, l.as_ref()) {
            continue;
        }
        if let Err(raison) = ecrire_une(r, e, a_ecrire(e.cible, l.as_ref()).as_ref()) {
            return annuler(
                r,
                trf!(
                    "{} ne s'écrit pas ({raison})",
                    "{} cannot be written ({raison})",
                    e.valeur
                ),
            );
        }
    }
    match lire_tout(r, &ecrits) {
        Ok(relues) if ecrits.iter().zip(&relues).all(|(e, l)| atteinte(e.cible, l.as_ref())) => Issue::Fait { avant },
        _ => annuler(
            r,
            tr!(
                "les valeurs relues ne sont pas celles écrites",
                "the values read back are not the ones written"
            )
            .to_string(),
        ),
    }
}

/// Remet ce que `poser` a noté pour `id`, si et seulement si chaque valeur est encore celle que Vanguard a écrite ;
/// la note est effacée une fois les valeurs relues identiques à la note.
pub(crate) fn remettre(r: &mut impl Registre, id: IdReglage, nom: &str) -> Issue {
    if !id.annulable() {
        return echec(
            None,
            tr!(
                "ce réglage ne se remet pas (le mot de passe en clair n'a pas été gardé, exprès) : rien d'écrit",
                "this setting cannot be put back (the clear-text password was not kept, on purpose): nothing written"
            ),
        );
    }
    let ecrits = table(id);
    let noms: Vec<&str> = ecrits.iter().map(|e| e.valeur).collect();
    let Some(notees) = r.lire_note(nom).and_then(|o| decoder(&o, nom, &noms)) else {
        return echec(
            None,
            tr!(
                "aucune valeur d'avant notée par Vanguard pour ce réglage (ou note abîmée) : rien d'écrit",
                "no previous value noted by Vanguard for this setting (or damaged note): nothing written"
            ),
        );
    };
    let lues = match lire_tout(r, &ecrits) {
        Ok(l) => l,
        Err(e) => {
            return echec(
                None,
                trf!(
                    "lecture impossible ({e}) : rien d'écrit",
                    "cannot read ({e}): nothing written"
                ),
            );
        }
    };
    let avant = decrire_tout(&ecrits, &lues);
    if lues == notees {
        r.effacer_note(nom);
        return Issue::Rien(avant);
    }
    if !ecrits.iter().zip(&lues).all(|(e, l)| atteinte(e.cible, l.as_ref())) {
        return echec(
            Some(avant),
            tr!(
                "le réglage a changé depuis que Vanguard l'a écrit : Vanguard n'écrit jamais par-dessus ; rien d'écrit",
                "the setting has changed since Vanguard wrote it: Vanguard never writes over it; nothing written"
            ),
        );
    }
    for (e, n) in ecrits.iter().zip(&notees) {
        if let Err(raison) = ecrire_une(r, e, n.as_ref()) {
            let revenu = revenir(r, &ecrits, &lues);
            return echec(
                Some(avant),
                trf!(
                    "{} ne s'écrit pas ({raison}) ; {} ; la note est gardée",
                    "{} cannot be written ({raison}); {}; the note is kept",
                    e.valeur,
                    texte_revenu(revenu)
                ),
            );
        }
    }
    match lire_tout(r, &ecrits) {
        Ok(relues) if relues == notees => {
            r.effacer_note(nom);
            Issue::Fait { avant }
        }
        _ => echec(
            Some(avant),
            tr!(
                "les valeurs relues ne sont pas celles notées ; la note est gardée",
                "the values read back are not the noted ones; the note is kept"
            ),
        ),
    }
}

/// Le réglage est-il déjà à sa valeur sûre ? Les valeurs lues, montrables, si oui ; `None` sinon, ou illisible.
pub(crate) fn deja(r: &mut impl Registre, id: IdReglage) -> Option<String> {
    let ecrits = table(id);
    let lues = lire_tout(r, &ecrits).ok()?;
    (!ecrits.is_empty() && ecrits.iter().zip(&lues).all(|(e, l)| atteinte(e.cible, l.as_ref())))
        .then(|| decrire_tout(&ecrits, &lues))
}

/// Le texte montré de ce qu'une remise écrira : « RunAsPPL=absente » (`None` : pas de note valide).
pub(crate) fn texte_note(r: &mut impl Registre, id: IdReglage, nom: &str) -> Option<String> {
    let ecrits = table(id);
    let noms: Vec<&str> = ecrits.iter().map(|e| e.valeur).collect();
    let notees = decoder(&r.lire_note(nom)?, nom, &noms)?;
    Some(decrire_tout(&ecrits, &notees))
}

/// La question posée dans la console élevée avant d'écrire ce réglage, défaut non ; `None` : la liste acceptée suffit.
/// Le retrait du mot de passe en clair le dit « non annulable » ; chaque question dit le risque du plan (§4.2).
pub(crate) fn question(id: IdReglage) -> Option<&'static str> {
    Some(match id {
        IdReglage::OuvertureAutoMdp => tr!(
            "  Windows ne s'ouvrira plus tout seul : assurez-vous de connaître votre mot de passe, il sera demandé au démarrage.\n  Le mot de passe écrit en clair dans le registre est retiré sans copie.\n  Le retirer, non annulable ? [o/N] : ",
            "  Windows will no longer sign in by itself: make sure you know your password, it will be asked at startup.\n  The password written in clear text in the registry is removed without a copy.\n  Remove it, not undoable? [y/N]: "
        ),
        IdReglage::OuvertureAutoCoupe => tr!(
            "  Windows ne s'ouvrira plus tout seul : assurez-vous de connaître votre mot de passe, il sera demandé au démarrage (annulable).\n  Couper l'ouverture automatique ? [o/N] : ",
            "  Windows will no longer sign in by itself: make sure you know your password, it will be asked at startup (undoable).\n  Turn automatic sign-in off? [y/N]: "
        ),
        IdReglage::Hvci => tr!(
            "  L'intégrité de la mémoire refuse les pilotes incompatibles (anciens pilotes, certains VPN, anti-triche ou matériels) : au prochain redémarrage, un périphérique ou un accès à distance par VPN peut ne plus marcher. Annulable, sans verrou.\n  L'activer ? [o/N] : ",
            "  Memory integrity refuses incompatible drivers (old drivers, some VPNs, anti-cheat or hardware): after the next restart, a device or remote access through a VPN may stop working. Undoable, no lock.\n  Turn it on? [y/N]: "
        ),
        IdReglage::CredentialGuard => tr!(
            "  Credential Guard peut empêcher des machines virtuelles d'autres éditeurs ou d'anciens VPN de marcher, au prochain redémarrage. Annulable, sans verrou UEFI.\n  L'activer ? [o/N] : ",
            "  Credential Guard may stop third-party virtual machines or old VPNs from working, after the next restart. Undoable, no UEFI lock.\n  Turn it on? [y/N]: "
        ),
        IdReglage::LsaPpl => tr!(
            "  La protection LSA refuse les modules d'authentification non signés (lecteur d'empreintes, double authentification du Bureau à distance d'un autre éditeur) : au prochain redémarrage, une ouverture de session par l'un d'eux peut ne plus marcher. Annulable, sans verrou UEFI.\n  L'activer ? [o/N] : ",
            "  LSA protection refuses unsigned authentication modules (fingerprint reader, third-party two-factor sign-in for Remote Desktop): after the next restart, a sign-in through one of them may stop working. Undoable, no UEFI lock.\n  Turn it on? [y/N]: "
        ),
        _ => return None,
    })
}

/// Un oui tapé dans une vraie console, et rien d'autre : hors console (tube, fichier), la réponse vaut non, sans rien
/// demander. Entrée seule, la fin de l'entrée ou une autre réponse : non.
pub(crate) fn confirmer(console: bool, question: &str, demander: impl FnOnce(&str) -> String) -> bool {
    if !console {
        trp!(
            "  L'entrée n'est pas une console : la réponse vaut non, rien n'est écrit.",
            "  The input is not a console: the answer is no, nothing is written."
        );
        return false;
    }
    crate::langue::oui(&demander(question))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct Faux {
        valeurs: HashMap<(bool, String, String), Brute>,
        notes: HashMap<String, Vec<u8>>,
        /// Les écritures refusées (nom de valeur), pour essayer le retour arrière.
        refusees: Vec<&'static str>,
        /// Une écriture « réussit » sans rien changer (relue autre).
        muettes: Vec<&'static str>,
        note_refusee: bool,
        ecritures: usize,
    }

    fn cle(ruche: Ruche, cle: &str, valeur: &str) -> (bool, String, String) {
        (ruche == Ruche::Compte, cle.to_string(), valeur.to_string())
    }

    impl Registre for Faux {
        fn lire(&mut self, ruche: Ruche, c: &str, v: &str) -> Result<Option<Brute>, Echec> {
            Ok(self.valeurs.get(&cle(ruche, c, v)).cloned())
        }
        fn ecrire(&mut self, ruche: Ruche, c: &str, v: &str, b: &Brute) -> Result<(), Echec> {
            self.ecritures += 1;
            if self.refusees.contains(&v) {
                return Err(Echec::refuse("essai", "refusé"));
            }
            if !self.muettes.contains(&v) {
                self.valeurs.insert(cle(ruche, c, v), b.clone());
            }
            Ok(())
        }
        fn effacer(&mut self, ruche: Ruche, c: &str, v: &str) -> Result<(), Echec> {
            self.ecritures += 1;
            if self.refusees.contains(&v) {
                return Err(Echec::refuse("essai", "refusé"));
            }
            if !self.muettes.contains(&v) {
                self.valeurs.remove(&cle(ruche, c, v));
            }
            Ok(())
        }
        fn lire_note(&mut self, nom: &str) -> Option<Vec<u8>> {
            self.notes.get(nom).cloned()
        }
        fn ecrire_note(&mut self, nom: &str, o: &[u8]) -> Result<(), Echec> {
            if self.note_refusee {
                return Err(Echec::refuse("essai", "note refusée"));
            }
            self.notes.insert(nom.to_string(), o.to_vec());
            Ok(())
        }
        fn effacer_note(&mut self, nom: &str) {
            self.notes.remove(nom);
        }
    }

    fn dw(n: u32) -> Brute {
        brute(Cible::Dword(n)).unwrap()
    }

    fn sz(t: &str) -> Brute {
        Brute {
            code: 1,
            octets: t.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect(),
        }
    }

    fn mettre(f: &mut Faux, e: &Ecrit, b: Brute) {
        f.valeurs.insert(cle(e.ruche, &e.cle, e.valeur), b);
    }

    fn valeur(f: &Faux, e: &Ecrit) -> Option<Brute> {
        f.valeurs.get(&cle(e.ruche, &e.cle, e.valeur)).cloned()
    }

    #[test]
    fn chaque_reglage_a_sa_table_et_son_mot() {
        let tous = IdReglage::tous();
        assert_eq!(tous.len(), 14 + 3 * 6);
        for id in &tous {
            let t = table(*id);
            assert!(!t.is_empty(), "{id:?}");
            assert_eq!(IdReglage::lire(&id.mot()), Some(*id));
            for e in &t {
                assert_eq!(e.ruche == Ruche::Compte, id.du_compte(), "{id:?}");
                // Jamais une valeur de la session à distance ni de l'accès à distance dans la table.
                for interdit in [
                    "Terminal Server",
                    "TermService",
                    "RDP-Tcp",
                    "PortNumber",
                    "fDenyTSConnections",
                ] {
                    assert!(!e.cle.contains(interdit), "{id:?} {}", e.cle);
                }
                // Jamais un verrou : « Locked » n'est écrit qu'à 0.
                if e.valeur == "Locked" {
                    assert_eq!(e.cible, Cible::Dword(0), "{id:?}");
                }
            }
            let nom = nom_note(*id, Some("S-1-5-21-1-2-3-1001")).unwrap();
            assert!(nom.starts_with(PREFIXE_REGLAGE));
            assert!(crate::machine::gestes::IdChoix::lire(&nom).is_none(), "{nom}");
        }
    }

    #[test]
    fn sans_verrou_uefi() {
        // RunAsPPL=2 (1 poserait le verrou UEFI), HVCI Locked=0, LsaCfgFlags=2 (1 : avec verrou).
        assert!(
            table(IdReglage::LsaPpl)
                .iter()
                .any(|e| e.valeur == "RunAsPPL" && e.cible == Cible::Dword(2))
        );
        assert!(
            table(IdReglage::Hvci)
                .iter()
                .any(|e| e.cible == Cible::Dword(0) && e.cle.ends_with("HypervisorEnforcedCodeIntegrity"))
        );
        assert!(
            table(IdReglage::CredentialGuard)
                .iter()
                .any(|e| e.valeur == "LsaCfgFlags" && e.cible == Cible::Dword(2))
        );
    }

    #[test]
    fn smartscreen_par_la_valeur_de_la_personne() {
        let t = table(IdReglage::SmartScreen);
        assert!(t.iter().all(|e| !e.cle.contains("Policies")));
    }

    #[test]
    fn la_note_se_relit_et_refuse_ce_qui_n_est_pas_elle() {
        let a = dw(0);
        let n = coder("reg-x", &[("A", Some(&a)), ("B", None)]).unwrap();
        assert_eq!(decoder(&n, "reg-x", &["A", "B"]), Some(vec![Some(dw(0)), None]));
        // Un autre nom, d'autres valeurs, un autre ordre : refusée.
        assert_eq!(decoder(&n, "reg-y", &["A", "B"]), None);
        assert_eq!(decoder(&n, "reg-x", &["B", "A"]), None);
        assert_eq!(decoder(&n, "reg-x", &["A"]), None);
        // Un octet changé : l'empreinte ne tient plus.
        for i in 0..n.len() {
            let mut m = n.clone();
            m[i] ^= 1;
            assert_eq!(decoder(&m, "reg-x", &["A", "B"]), None, "octet {i}");
        }
        // Tronquée, ou rallongée.
        assert_eq!(decoder(&n[..n.len() - 1], "reg-x", &["A", "B"]), None);
        let mut plus = n.clone();
        plus.push(0);
        assert_eq!(decoder(&plus, "reg-x", &["A", "B"]), None);
        // Un type inconnu ou une valeur trop longue ne se notent pas.
        assert_eq!(
            coder(
                "n",
                &[(
                    "A",
                    Some(&Brute {
                        code: 9,
                        octets: vec![]
                    })
                )]
            ),
            None
        );
        assert_eq!(
            coder(
                "n",
                &[(
                    "A",
                    Some(&Brute {
                        code: 3,
                        octets: vec![0; VALEUR_MAX + 1]
                    })
                )]
            ),
            None
        );
    }

    #[test]
    fn poser_note_puis_ecrit_et_remettre_rend_exactement() {
        let mut f = Faux::default();
        let t = table(IdReglage::Hvci);
        mettre(&mut f, &t[0], dw(0));
        let nom = nom_note(IdReglage::Hvci, None).unwrap();
        assert!(matches!(poser(&mut f, IdReglage::Hvci, &nom), Issue::Fait { .. }));
        assert_eq!(valeur(&f, &t[0]), Some(dw(1)));
        assert_eq!(valeur(&f, &t[1]), Some(dw(0)));
        assert!(f.notes.contains_key(&nom));
        assert_eq!(
            texte_note(&mut f, IdReglage::Hvci, &nom).unwrap(),
            "Enabled=0, Locked=absente"
        );
        // Encore : déjà ainsi, rien d'écrit.
        let avant = f.ecritures;
        assert!(matches!(poser(&mut f, IdReglage::Hvci, &nom), Issue::Rien(_)));
        assert_eq!(f.ecritures, avant);
        assert!(matches!(remettre(&mut f, IdReglage::Hvci, &nom), Issue::Fait { .. }));
        assert_eq!(valeur(&f, &t[0]), Some(dw(0)));
        assert_eq!(valeur(&f, &t[1]), None);
        assert!(!f.notes.contains_key(&nom));
    }

    #[test]
    fn sans_note_rien_n_est_ecrit() {
        let mut f = Faux {
            note_refusee: true,
            ..Faux::default()
        };
        let nom = nom_note(IdReglage::LsaPpl, None).unwrap();
        assert!(matches!(poser(&mut f, IdReglage::LsaPpl, &nom), Issue::Echec { .. }));
        assert_eq!(f.ecritures, 0);
        assert!(f.valeurs.is_empty());
    }

    #[test]
    fn une_ecriture_refusee_remet_tout_et_efface_la_note() {
        let mut f = Faux {
            refusees: vec!["LsaCfgFlags"],
            ..Faux::default()
        };
        let nom = nom_note(IdReglage::CredentialGuard, None).unwrap();
        let t = table(IdReglage::CredentialGuard);
        mettre(&mut f, &t[0], dw(0));
        let Issue::Echec { raison, .. } = poser(&mut f, IdReglage::CredentialGuard, &nom) else {
            panic!("refusé attendu");
        };
        assert!(raison.contains("LsaCfgFlags"), "{raison}");
        assert_eq!(valeur(&f, &t[0]), Some(dw(0)));
        assert_eq!(valeur(&f, &t[1]), None);
        assert!(!f.notes.contains_key(&nom));
    }

    /// Credential Guard ne baisse jamais RequirePlatformSecurityFeatures : 3 (démarrage sécurisé et protection DMA)
    /// reste 3 ; 2 (la protection DMA seule) devient 3 ; la remise rend la valeur d'avant.
    #[test]
    fn credential_guard_garde_la_protection_dma() {
        let t = table(IdReglage::CredentialGuard);
        let exiges = t
            .iter()
            .find(|e| e.valeur == "RequirePlatformSecurityFeatures")
            .unwrap();
        let nom = nom_note(IdReglage::CredentialGuard, None).unwrap();
        for (avant, apres) in [(3, 3), (2, 3), (1, 1)] {
            let mut f = Faux::default();
            mettre(&mut f, exiges, dw(avant));
            assert!(matches!(
                poser(&mut f, IdReglage::CredentialGuard, &nom),
                Issue::Fait { .. }
            ));
            assert_eq!(valeur(&f, exiges), Some(dw(apres)), "{avant}");
            assert!(matches!(
                remettre(&mut f, IdReglage::CredentialGuard, &nom),
                Issue::Fait { .. }
            ));
            assert_eq!(valeur(&f, exiges), Some(dw(avant)), "{avant}");
        }
    }

    #[test]
    fn une_ecriture_muette_compte_comme_un_echec() {
        let mut f = Faux {
            muettes: vec!["RunAsPPL"],
            ..Faux::default()
        };
        let nom = nom_note(IdReglage::LsaPpl, None).unwrap();
        assert!(matches!(poser(&mut f, IdReglage::LsaPpl, &nom), Issue::Echec { .. }));
        assert!(!f.notes.contains_key(&nom));
    }

    #[test]
    fn la_remise_n_ecrit_jamais_par_dessus_un_changement() {
        let mut f = Faux::default();
        let t = table(IdReglage::SmbSignature);
        mettre(&mut f, &t[0], dw(0));
        let nom = nom_note(IdReglage::SmbSignature, None).unwrap();
        assert!(matches!(
            poser(&mut f, IdReglage::SmbSignature, &nom),
            Issue::Fait { .. }
        ));
        // Changé depuis (par la personne ou un programme) : la remise refuse, la note reste.
        mettre(&mut f, &t[0], dw(7));
        assert!(matches!(
            remettre(&mut f, IdReglage::SmbSignature, &nom),
            Issue::Echec { .. }
        ));
        assert_eq!(valeur(&f, &t[0]), Some(dw(7)));
        assert!(f.notes.contains_key(&nom));
    }

    #[test]
    fn la_remise_refuse_sans_note_ou_note_abimee() {
        let mut f = Faux::default();
        let nom = nom_note(IdReglage::SmbSignature, None).unwrap();
        assert!(matches!(
            remettre(&mut f, IdReglage::SmbSignature, &nom),
            Issue::Echec { .. }
        ));
        // Une note d'un autre réglage sous ce nom : refusée.
        let autre = coder("reg-lsa-ppl", &[("RunAsPPL", None)]).unwrap();
        f.notes.insert(nom.clone(), autre);
        assert!(matches!(
            remettre(&mut f, IdReglage::SmbSignature, &nom),
            Issue::Echec { .. }
        ));
        assert_eq!(f.ecritures, 0);
    }

    #[test]
    fn le_mot_de_passe_en_clair_n_est_ni_note_ni_montre_ni_remis() {
        let mut f = Faux::default();
        let t = table(IdReglage::OuvertureAutoMdp);
        mettre(&mut f, &t[0], sz("1"));
        mettre(&mut f, &t[1], sz("secret-tres-long"));
        let nom = nom_note(IdReglage::OuvertureAutoMdp, None).unwrap();
        let Issue::Fait { avant } = poser(&mut f, IdReglage::OuvertureAutoMdp, &nom) else {
            panic!("fait attendu");
        };
        assert!(!avant.contains("secret"), "{avant}");
        assert!(f.notes.is_empty());
        assert_eq!(valeur(&f, &t[0]), Some(sz("0")));
        assert_eq!(valeur(&f, &t[1]), None);
        assert!(matches!(
            remettre(&mut f, IdReglage::OuvertureAutoMdp, &nom),
            Issue::Echec { .. }
        ));
        assert_eq!(ligne_remettre(IdReglage::OuvertureAutoMdp), None);
    }

    fn ligne_remettre(id: IdReglage) -> Option<String> {
        crate::machine::gestes::ligne_reglage_remettre(id)
    }

    #[test]
    fn note_du_compte_par_sid_et_service_par_empreinte() {
        let id = IdReglage::PsStrategieCompte;
        assert_eq!(nom_note(id, None), None);
        assert_eq!(nom_note(id, Some(r"S-1-5-21-1\..\x")), None);
        assert_eq!(
            nom_note(id, Some("S-1-5-21-1-2-3-1001")).unwrap(),
            "reg-ps-strategie-compte~S-1-5-21-1-2-3-1001"
        );
        assert_eq!(nom_note_service("Spooler"), nom_note_service("spooler"));
        assert_ne!(nom_note_service("Spooler"), nom_note_service("Spooler2"));
        assert_eq!(nom_note_service("x").len(), 4 + 16);
    }

    #[test]
    fn atteinte_compare_le_type() {
        // Des bits : au moins ceux-là, les autres gardés ; jamais une valeur plus forte baissée.
        assert!(atteinte(Cible::Bits(1), Some(&dw(1))));
        assert!(atteinte(Cible::Bits(1), Some(&dw(3))));
        assert!(!atteinte(Cible::Bits(1), Some(&dw(2))));
        assert!(!atteinte(Cible::Bits(1), Some(&sz("1"))));
        assert!(!atteinte(Cible::Bits(1), None));
        assert_eq!(a_ecrire(Cible::Bits(1), Some(&dw(2))), Some(dw(3)));
        assert_eq!(a_ecrire(Cible::Bits(1), None), Some(dw(1)));
        assert_eq!(a_ecrire(Cible::Bits(1), Some(&sz("x"))), Some(dw(1)));
        assert_eq!(a_ecrire(Cible::Dword(2), Some(&dw(7))), Some(dw(2)));
        assert!(atteinte(Cible::Dword(1), Some(&dw(1))));
        assert!(!atteinte(Cible::Dword(1), Some(&sz("1"))));
        assert!(atteinte(Cible::Sz("Warn"), Some(&sz("warn"))));
        assert!(!atteinte(Cible::Sz("0"), None));
        assert!(atteinte(Cible::Absente, None));
        assert!(!atteinte(Cible::Absente, Some(&dw(0))));
    }

    /// Les questions du risque : défaut non, « non annulable » pour le mot de passe en clair seul ; hors console, non
    /// sans rien demander ; seul un oui tapé confirme.
    #[test]
    fn question_puis_confirmation_defaut_non() {
        for id in IdReglage::tous() {
            match question(id) {
                Some(q) => {
                    assert!(q.contains("[o/N]") || q.contains("[y/N]"), "{id:?}");
                    let non_annulable = q.contains("non annulable") || q.contains("not undoable");
                    assert_eq!(non_annulable, !id.annulable(), "{id:?}");
                }
                None => assert!(id.annulable(), "{id:?}"),
            }
        }
        for id in [
            IdReglage::OuvertureAutoMdp,
            IdReglage::OuvertureAutoCoupe,
            IdReglage::Hvci,
            IdReglage::CredentialGuard,
            IdReglage::LsaPpl,
        ] {
            assert!(question(id).is_some(), "{id:?}");
        }
        assert!(question(IdReglage::MajPause).is_none());
        // Hors console : jamais demandé, non.
        assert!(!confirmer(false, "q", |_| unreachable!("demandé hors console")));
        for r in ["o", "oui", "y", "yes", " O \n"] {
            assert!(confirmer(true, "q", |_| r.to_string()), "{r:?}");
        }
        for r in ["", "\n", "n", "non", "ok", "o o", "oui!"] {
            assert!(!confirmer(true, "q", |_| r.to_string()), "{r:?}");
        }
    }

    /// « Déjà ainsi » seulement si chaque valeur de la table est à sa cible ; une valeur illisible ou une seule à
    /// côté : à écrire.
    #[test]
    fn deja_seulement_si_tout_est_atteint() {
        let mut f = Faux::default();
        assert!(deja(&mut f, IdReglage::LsaPpl).is_none());
        let t = table(IdReglage::LsaPpl);
        for e in &t {
            let b = brute(e.cible);
            match b {
                Some(b) => mettre(&mut f, e, b),
                None => {
                    f.valeurs.remove(&cle(e.ruche, &e.cle, e.valeur));
                }
            }
        }
        assert!(deja(&mut f, IdReglage::LsaPpl).is_some());
        // RunAsPPL=1 (le verrou UEFI) n'est pas « déjà ainsi » : à 2.
        let ppl = t.iter().find(|e| e.valeur == "RunAsPPL").unwrap();
        mettre(&mut f, ppl, dw(1));
        assert!(deja(&mut f, IdReglage::LsaPpl).is_none());
        // Même nombre, autre type : pas atteint.
        mettre(&mut f, ppl, sz("2"));
        assert!(deja(&mut f, IdReglage::LsaPpl).is_none());
    }
}

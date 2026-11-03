//! Services au chemin sans guillemets : « C:\Program Files\Mon Outil\svc.exe », sans guillemets, Windows essaie
//! d'abord « C:\Program.exe », puis « C:\Program Files\Mon.exe ». Un programme posé là démarre avec les droits du
//! service, souvent ceux du système. Signalé seulement si un de ces dossiers est modifiable par tous les comptes :
//! sans cela, le défaut n'est pas exploitable (C:\ et Program Files ne le sont pas).

use super::super::{Constat, alerte};
use super::corrections::{Resultat, avant_notable};
use super::ps;
use crate::machine::gestes::{self, NomFichier};
use crate::risk::Niveau;
use crate::ui::{affichable, resume, tr, trf, trp};

/// Pour chaque service au chemin sans guillemets : « SVC|nom|programme|dossier modifiable|arguments ». Les
/// arguments viennent en dernier : ils peuvent contenir « | », qu'un chemin Windows n'admet pas, et le dernier champ
/// garde tout le reste de la ligne. Les comptes sont reconnus par leur SID (Utilisateurs, Utilisateurs authentifiés,
/// Tout le monde, Interactif), pas par leur nom, qui change avec la langue de Windows.
const SCRIPT: &str = r#"
$tous = 'S-1-5-32-545','S-1-5-11','S-1-1-0','S-1-5-4'
function Modifiable($d) {
  try {
    foreach ($r in (Get-Acl -LiteralPath $d).Access) {
      # Une règle « héritée seulement » vaut pour le contenu, pas pour le dossier : celle de C:\ pour ses sous-dossiers.
      if ($r.AccessControlType -ne 'Allow' -or ($r.PropagationFlags -band 2)) { continue }
      $sid = try { $r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { '' }
      # Créer un fichier (0x2), ou écriture et tous droits génériques.
      if ($tous -contains $sid -and ([int64]$r.FileSystemRights -band 0x50000002)) { return $true }
    }
  } catch {}
  return $false
}
foreach ($s in Get-CimInstance Win32_Service) {
  $c = [string]$s.PathName
  if (-not $c -or $c.StartsWith('"') -or $c -notmatch '^(.+?\.exe)(\s.*)?$') { continue }
  $exe = $Matches[1]; $suite = [string]$Matches[2]
  if ($exe -notmatch ' ') { continue }
  $parties = $exe -split ' '
  for ($i = 1; $i -lt $parties.Count; $i++) {
    $d = Split-Path -Parent (($parties[0..($i - 1)] -join ' '))
    if ($d -and (Test-Path -LiteralPath $d) -and (Modifiable $d)) { "SVC|$($s.Name)|$exe|$d|$suite"; break }
  }
}
'SVC_FIN'
"#;

pub(super) fn services_sans_guillemets() -> Option<Constat> {
    // Lus dans le registre et par les droits de Windows ; PowerShell si la clé des services ne s'ouvre pas.
    let sortie = lire_natif().or_else(|| ps(SCRIPT))?;
    juger(&sortie)
}

/// Les comptes de tous (Utilisateurs, Utilisateurs authentifiés, Tout le monde, Interactif), par leur SID.
const TOUS: [&str; 4] = ["S-1-5-32-545", "S-1-5-11", "S-1-1-0", "S-1-5-4"];

/// Les mêmes lignes que le script, sans PowerShell : les services Win32 du registre (ImagePath, variables développées
/// comme Win32_Service le fait) et les droits des dossiers lus par Windows. `None` si la clé des services ne s'ouvre
/// pas.
fn lire_natif() -> Option<String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let services = winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(crate::machine::windows::CLE_SERVICES)
        .ok()?;
    let mut lignes = Vec::new();
    for nom in services.enum_keys().flatten() {
        let Ok(cle) = services.open_subkey(&nom) else { continue };
        let Some(brut) = cle
            .get_raw_value("ImagePath")
            .ok()
            .and_then(|b| super::corrections::texte_reg(&b))
        else {
            continue;
        };
        let type_service = cle.get_value::<u32, _>("Type").unwrap_or(0);
        if let Some(j) = juger_service(type_service, &brut, variable_systeme, existe, dossier_modifiable) {
            // « SVCM » : signalé, mais à corriger à la main (variable inconnue, programme introuvable).
            let sorte = if j.a_la_main.is_some() { "SVCM" } else { "SVC" };
            // Sans dossier piège (chemin inconnu), le champ reste vide.
            let dossier = j
                .dossier
                .as_deref()
                .map(|d| d.display().to_string())
                .unwrap_or_default();
            lignes.push(format!("{sorte}|{nom}|{}|{dossier}|{}", j.exe, j.suite));
        }
    }
    lignes.push("SVC_FIN".into());
    Some(lignes.join("\n"))
}

/// Service dans son propre processus (0x10) ou partagé (0x20) : les pilotes (1, 2) n'en sont pas.
const SERVICE_WIN32: u32 = 0x30;

/// Une variable de l'environnement du système, celui avec lequel le gestionnaire des services développe ImagePath :
/// SystemRoot, windir et SystemDrive demandés à Windows (GetSystemWindowsDirectoryW, sans repli), Program Files,
/// ProgramData, ALLUSERSPROFILE et PUBLIC par les dossiers connus (SHGetKnownFolderPath), les autres lues dans
/// Session Manager\Environment, que seul un administrateur écrit. Jamais l'environnement de ce processus : le
/// processus élevé hérite de celui du compte qui l'élève (HKCU\Environment, `set` avant de lancer Vanguard).
pub(super) fn variable_systeme(nom: &str) -> Option<String> {
    // Le dossier de Windows tel que Windows le donne, ou rien : le repli de `dossiers()` (parent de System32) est une
    // supposition, et une valeur supposée ne doit pas mener à une écriture.
    static WINDOWS: std::sync::OnceLock<Option<std::path::PathBuf>> = std::sync::OnceLock::new();
    let windows = WINDOWS.get_or_init(super::environnement::dossier_windows).as_deref();
    let d = super::environnement::dossiers();
    variable_selon(
        nom,
        |n| dossier_calcule(d, windows, n),
        |n| {
            winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
                .open_subkey(ENVIRONNEMENT_SYSTEME)
                .ok()?
                .get_value(n)
                .ok()
        },
    )
}

/// Les variables que Windows calcule lui-même, absentes de Session Manager\Environment : demandées à Windows, jamais
/// lues ailleurs (une valeur du même nom posée dans Session Manager est ignorée). ProgramFiles(Arm), de Windows
/// ARM64, n'en est pas : aucun dossier connu documenté ne la donne ; elle reste inconnue, donc à la main.
const CALCULEES: [&str; 12] = [
    "SystemRoot",
    "windir",
    "SystemDrive",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramW6432",
    "CommonProgramFiles",
    "CommonProgramFiles(x86)",
    "CommonProgramW6432",
    "ProgramData",
    "ALLUSERSPROFILE",
    "PUBLIC",
];

/// Le dossier que Windows donne pour une variable calculée (`CALCULEES`), sans barre finale ; `None` pour une autre
/// variable ou un dossier que Windows n'a pas donné. `windows` : le dossier de Windows (GetSystemWindowsDirectoryW),
/// `None` s'il ne l'a pas donné ; SystemDrive en est la lettre (« C: »).
fn dossier_calcule(d: &super::environnement::Dossiers, windows: Option<&std::path::Path>, nom: &str) -> Option<String> {
    let nom = nom.to_ascii_lowercase();
    if nom == "systemdrive" {
        let w = windows?.to_str()?;
        let mut c = w.chars();
        return (c.next().is_some_and(|l| l.is_ascii_alphabetic()) && c.next() == Some(':'))
            .then(|| w[..2].to_string());
    }
    let p = match nom.as_str() {
        "systemroot" | "windir" => windows,
        "programfiles" => d.program_files.as_deref(),
        "programfiles(x86)" => d.program_files_x86.as_deref(),
        "programw6432" => d.program_files_x64.as_deref(),
        "commonprogramfiles" => d.fichiers_communs.as_deref(),
        "commonprogramfiles(x86)" => d.fichiers_communs_x86.as_deref(),
        "commonprogramw6432" => d.fichiers_communs_x64.as_deref(),
        "programdata" | "allusersprofile" => d.program_data.as_deref(),
        "public" => d.public.as_deref(),
        _ => None,
    }?;
    p.to_str()
        .map(|t| t.trim_end_matches('\\').to_string())
        .filter(|t| !t.is_empty())
}

/// La valeur d'une variable du système : une variable calculée vient de `dossier` seul ; une autre, de `session`
/// (Session Manager\Environment), développée avec les seules variables calculées. Une valeur qui cite une autre
/// variable est inconnue.
fn variable_selon(
    nom: &str,
    dossier: impl Fn(&str) -> Option<String>,
    session: impl Fn(&str) -> Option<String>,
) -> Option<String> {
    if CALCULEES.iter().any(|c| c.eq_ignore_ascii_case(nom)) {
        return dossier(nom);
    }
    developper_tout(&session(nom)?, &dossier)
}

/// L'environnement du système (HKLM).
const ENVIRONNEMENT_SYSTEME: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

/// Le programme cité existe-t-il, en fichier ?
fn existe(exe: &std::path::Path) -> bool {
    exe.is_file()
}

/// Un dossier qui existe et qu'un compte de tous peut modifier, d'après les droits lus par Windows.
fn dossier_modifiable(d: &std::path::Path) -> bool {
    d.is_dir() && super::securite::du_fichier(d).is_some_and(|o| modifiable_par_tous(&o))
}

/// Un service signalé : le programme et les arguments développés, le dossier piège (aucun quand le programme cite une
/// variable inconnue : Vanguard ne sait pas où il mène), et la raison de le laisser à la main quand Vanguard ne doit
/// pas l'écrire.
#[derive(Debug)]
struct Signale {
    exe: String,
    suite: String,
    dossier: Option<std::path::PathBuf>,
    a_la_main: Option<String>,
}

/// Le jugement d'un service, LE MÊME pour le bilan (`lire_natif`) et pour le processus élevé qui pose les guillemets
/// (`entre_guillemets`) : un service Win32 dont le chemin (ImagePath brut, variables développées) n'a pas de
/// guillemets et dont un dossier piège est modifiable. Une variable que l'environnement du système ne connaît pas, ou
/// un programme qui n'existe pas, le laisse à la main : Vanguard ne sait pas ce que Windows lancerait. Un programme
/// qui cite lui-même une variable inconnue est signalé sans dossier piège : son vrai chemin, donc ses dossiers, est
/// inconnu, et le taire le ferait passer pour sain.
fn juger_service(
    type_service: u32,
    brut: &str,
    variable: impl Fn(&str) -> Option<String>,
    existe: impl Fn(&std::path::Path) -> bool,
    modifiable: impl Fn(&std::path::Path) -> bool,
) -> Option<Signale> {
    if type_service & SERVICE_WIN32 == 0 {
        return None;
    }
    let chemin = developper(brut, &variable);
    // Un programme sans espace, même avec une variable inconnue (« %X%\svc.exe »), n'est pas signalé : Windows ne le
    // couperait que si la valeur de %X% avait une espace ; les variables de Windows qui en ont une sont calculées
    // ici, sauf ProgramFiles(Arm), dont le dossier piège (C:\) n'est pas modifiable par défaut.
    let (exe, suite) = programme_sans_guillemets(&chemin)?;
    if let Some(v) = variable_inconnue(exe, &variable) {
        return Some(Signale {
            exe: exe.to_string(),
            suite: suite.to_string(),
            dossier: None,
            a_la_main: Some(trf!(
                "variable %{v}% inconnue de l'environnement du système : Vanguard ne sait pas où ce chemin mène",
                "variable %{v}% unknown to the system environment: Vanguard does not know where this path leads"
            )),
        });
    }
    let dossier = dossier_piege(exe, modifiable)?;
    let a_la_main = if let Some(v) = variable_inconnue(brut, &variable) {
        Some(trf!(
            "variable %{v}% inconnue de l'environnement du système",
            "variable %{v}% unknown to the system environment"
        ))
    } else if !existe(std::path::Path::new(exe)) {
        Some(trf!(
            "programme introuvable : {}",
            "program not found: {}",
            affichable(exe)
        ))
    } else {
        None
    };
    Some(Signale {
        exe: exe.to_string(),
        suite: suite.to_string(),
        dossier: Some(dossier),
        a_la_main,
    })
}

/// Le nouvel ImagePath brut, entre guillemets, si et seulement si `juger_service` signale ce service et que la
/// nouvelle valeur, développée, ne diffère de l'ancienne que par les guillemets autour du programme : les variables
/// (« %SystemRoot% ») restent telles quelles, le type de la valeur aussi. Un service laissé à la main n'en a pas.
fn entre_guillemets(
    type_service: u32,
    brut: &str,
    variable: impl Fn(&str) -> Option<String>,
    existe: impl Fn(&std::path::Path) -> bool,
    modifiable: impl Fn(&std::path::Path) -> bool,
) -> Option<String> {
    let j = juger_service(type_service, brut, &variable, existe, modifiable)?;
    guillemets_du_jugement(&j, brut, variable)
}

/// La suite d'`entre_guillemets`, une fois le service jugé : rien pour un service à la main ou sans dossier piège.
fn guillemets_du_jugement(j: &Signale, brut: &str, variable: impl Fn(&str) -> Option<String>) -> Option<String> {
    // Deux gardes, pas une : un service sans dossier piège a toujours une raison d'être à la main, mais une branche
    // future qui oublierait l'une n'écrirait pas pour autant.
    if j.a_la_main.is_some() || j.dossier.is_none() {
        return None;
    }
    let (brut_exe, brut_suite) = programme_et_suite(brut)?;
    let nouveau = format!("\"{brut_exe}\"{brut_suite}");
    (developper(&nouveau, &variable) == format!("\"{}\"{}", j.exe, j.suite)).then_some(nouveau)
}

/// Met entre guillemets le chemin du service `nom` (processus élevé) : ImagePath relu, rejugé par `juger_service`,
/// confié au gestionnaire des services (ChangeServiceConfigW, pas d'écriture directe dans sa base), puis relu.
/// Déjà entre guillemets : rien d'écrit. La valeur d'avant est notée.
pub(super) fn poser_guillemets(nom: &NomFichier) -> Resultat {
    use std::io::ErrorKind::NotFound;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE};
    let absent = || {
        Resultat::rien(
            tr!(
                "service absent : rien à corriger ici, rien d'écrit",
                "no such service: nothing to fix here, nothing written"
            )
            .to_string(),
        )
    };
    let chemin = format!(r"{}\{}", crate::machine::windows::CLE_SERVICES, nom.texte());
    // Lecture seule : l'écriture passe par le gestionnaire des services.
    let cle = match winreg::RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(&chemin, KEY_QUERY_VALUE) {
        Ok(c) => c,
        Err(e) if e.kind() == NotFound => return absent(),
        Err(e) => {
            return Resultat::echec(
                None,
                trf!("clé du service illisible : {e}", "service key unreadable: {e}"),
            );
        }
    };
    let brute = match cle.get_raw_value("ImagePath") {
        Ok(b) => b,
        Err(e) if e.kind() == NotFound => {
            return Resultat::rien(
                tr!(
                    "pas de chemin (ImagePath) : rien à corriger ici, rien d'écrit",
                    "no path (ImagePath): nothing to fix here, nothing written"
                )
                .to_string(),
            );
        }
        Err(e) => return Resultat::echec(None, trf!("ImagePath illisible : {e}", "ImagePath unreadable: {e}")),
    };
    let Some(brut) = super::corrections::texte_reg(&brute) else {
        return Resultat::echec(
            None,
            trf!(
                "refusé : ImagePath de type {:?}, pas un texte ; rien d'écrit",
                "refused: ImagePath of type {:?}, not text; nothing written",
                brute.vtype
            ),
        );
    };
    let avant = avant_notable(&brut);
    if brut.starts_with('"') {
        return Resultat::rien(
            tr!(
                "déjà entre guillemets, rien d'écrit",
                "already in quotes, nothing written"
            )
            .to_string(),
        );
    }
    let type_service = cle.get_value::<u32, _>("Type").unwrap_or(0);
    if let Some(raison) =
        juger_service(type_service, &brut, variable_systeme, existe, dossier_modifiable).and_then(|j| j.a_la_main)
    {
        return Resultat::echec(
            Some(avant),
            trf!(
                "refusé, à corriger à la main dans regedit : {raison} ; rien d'écrit",
                "refused, to fix by hand in regedit: {raison}; nothing written"
            ),
        );
    }
    let Some(nouveau) = entre_guillemets(type_service, &brut, variable_systeme, existe, dossier_modifiable) else {
        return Resultat::echec(
            Some(avant),
            tr!(
                "refusé : le bilan refait ici ne signale pas ce service (ou le chemin changerait autrement que par les guillemets) ; rien d'écrit",
                "refused: the check redone here does not flag this service (or the path would change beyond the quotes); nothing written"
            )
            .to_string(),
        );
    };
    // Un chemin REG_SZ qui contient « % » : le gestionnaire des services l'écrirait en REG_EXPAND_SZ et son sens
    // changerait. Écrit au registre en gardant REG_SZ, le chemin d'avant noté (défense D6b).
    if sens_change_par_le_gestionnaire(&brute.vtype, &brut) {
        return noter_et_ecrire(nom, &brute, &nouveau);
    }
    if let Some(r) = refus_session(nom, &[&brut, &nouveau]) {
        return r;
    }
    match super::services_ecriture::changer_le_chemin(nom.texte(), &nouveau) {
        Ok(true) => {}
        Ok(false) => return absent(),
        Err(e) => return Resultat::echec(Some(avant), e.to_string()),
    }
    match cle.get_raw_value("ImagePath") {
        Ok(relue) if relue_conforme(&brute.vtype, &relue, &nouveau) => Resultat::fait(avant),
        Ok(relue) => Resultat::echec(
            Some(avant),
            trf!(
                "relu {} ({:?}) au lieu de {}",
                "read back {} ({:?}) instead of {}",
                super::corrections::decrire(&relue),
                relue.vtype,
                avant_notable(&nouveau)
            ),
        ),
        Err(e) => Resultat::echec(Some(avant), e.to_string()),
    }
}

/// Le nouvel ImagePath brut d'un service signalé que Vanguard ne sait pas vérifier (variable inconnue, programme
/// introuvable : `a_la_main`) : les guillemets autour du programme, rien d'autre ; la valeur développée ne change que
/// par eux (une variable connue qui déplacerait le « .exe » : rien). Un service sans raison d'être à la main passe
/// par `guillemets_du_jugement`, jamais par ici.
fn guillemets_risques_du_jugement(
    j: &Signale,
    brut: &str,
    variable: impl Fn(&str) -> Option<String>,
) -> Option<String> {
    j.a_la_main.as_ref()?;
    let (brut_exe, brut_suite) = programme_et_suite(brut)?;
    let nouveau = format!("\"{brut_exe}\"{brut_suite}");
    (developper(&nouveau, &variable) == format!("\"{}\"{}", j.exe, j.suite)).then_some(nouveau)
}

/// Le chemin brut d'un service, lu en lecture seule : la clé, la valeur et son texte ; ou ce qu'il faut répondre.
fn lire_chemin(nom: &NomFichier) -> Result<(winreg::RegKey, winreg::RegValue<'static>, String), Resultat> {
    use std::io::ErrorKind::NotFound;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE};
    let chemin = format!(r"{}\{}", crate::machine::windows::CLE_SERVICES, nom.texte());
    let cle = match winreg::RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(&chemin, KEY_QUERY_VALUE) {
        Ok(c) => c,
        Err(e) if e.kind() == NotFound => {
            return Err(Resultat::rien(
                tr!(
                    "service absent : rien à corriger ici, rien d'écrit",
                    "no such service: nothing to fix here, nothing written"
                )
                .to_string(),
            ));
        }
        Err(e) => {
            return Err(Resultat::echec(
                None,
                trf!("clé du service illisible : {e}", "service key unreadable: {e}"),
            ));
        }
    };
    let brute = match cle.get_raw_value("ImagePath") {
        Ok(b) => b,
        Err(e) => {
            return Err(Resultat::echec(
                None,
                trf!("ImagePath illisible : {e}", "ImagePath unreadable: {e}"),
            ));
        }
    };
    let Some(brut) = super::corrections::texte_reg(&brute) else {
        return Err(Resultat::echec(
            None,
            trf!(
                "refusé : ImagePath de type {:?}, pas un texte ; rien d'écrit",
                "refused: ImagePath of type {:?}, not text; nothing written",
                brute.vtype
            ),
        ));
    };
    Ok((cle, brute, brut))
}

/// Les octets d'un texte REG_SZ ou REG_EXPAND_SZ : UTF-16 petit-boutiste, zéro final.
fn octets_texte(t: &str) -> Vec<u8> {
    t.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
}

/// Une valeur de registre telle que la note la garde.
fn brute_de(v: &winreg::RegValue) -> crate::machine::reglages::Brute {
    crate::machine::reglages::Brute {
        code: v.vtype.clone() as u32,
        octets: v.bytes.to_vec(),
    }
}

/// Écrit `valeur` (type et octets exacts) dans ImagePath du service, au registre.
fn ecrire_au_registre(nom: &NomFichier, valeur: &winreg::RegValue) -> std::io::Result<()> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE};
    let chemin = format!(r"{}\{}", crate::machine::windows::CLE_SERVICES, nom.texte());
    winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(&chemin, KEY_QUERY_VALUE | KEY_SET_VALUE)?
        .set_raw_value("ImagePath", valeur)
}

/// Changer le chemin d'un service d'accès à distance (TermService, sshd…) ou d'un outil d'accès à distance, de prise
/// en main ou de VPN (AnyDesk, TeamViewer, OpenVPN… : nom du service ou programme des `chemins`, actuel ou visé)
/// pendant une session, ou quand elle ne se lit pas : refusé (garde B, `gestes::refus_chemin_outil`).
fn refus_session(nom: &NomFichier, chemins: &[&str]) -> Option<Resultat> {
    gestes::refus_chemin_outil(
        nom.texte(),
        chemins,
        super::reglages_ecriture::session_ouverte(),
        crate::protection::blocage::gardes::programme_de_session,
    )
    .then(|| {
        Resultat::echec(
            None,
            tr!(
                "service d'accès à distance (ou outil d'accès à distance, de prise en main ou VPN) et session à distance en cours (ou illisible) : Vanguard ne touche pas à son chemin ; rien d'écrit",
                "remote access service (or remote access, remote control or VPN tool) and remote session in progress (or unreadable): Vanguard leaves its path alone; nothing written"
            )
            .to_string(),
        )
    })
}

/// Deux valeurs du registre identiques : même type, mêmes octets.
fn meme_valeur(a: &winreg::RegValue, b: &winreg::RegValue) -> bool {
    a.vtype == b.vtype && a.bytes.as_ref() == b.bytes.as_ref()
}

/// Note le chemin d'avant et celui écrit (ChoixAvant, « svc-… »), puis écrit `nouveau` : au registre en gardant le
/// type quand le gestionnaire des services en changerait le sens (REG_SZ avec « % »), par lui sinon ; relu. À la
/// moindre erreur, le chemin d'avant est remis et la note effacée.
fn noter_et_ecrire(nom: &NomFichier, brute: &winreg::RegValue, nouveau: &str) -> Resultat {
    use crate::machine::reglages;
    let brut = super::corrections::texte_reg(brute).unwrap_or_default();
    if let Some(r) = refus_session(nom, &[&brut, nouveau]) {
        return r;
    }
    let avant = avant_notable(&brut);
    let note_nom = reglages::nom_note_service(nom.texte());
    let ecrit = reglages::Brute {
        code: brute.vtype.clone() as u32,
        octets: octets_texte(nouveau),
    };
    let ancien = brute_de(brute);
    let Some(note) = reglages::coder(&note_nom, &[("avant", Some(&ancien)), ("ecrit", Some(&ecrit))]) else {
        return Resultat::echec(
            Some(avant),
            tr!(
                "le chemin d'avant ne se note pas (trop long) : rien d'écrit",
                "the previous path cannot be noted (too long): nothing written"
            )
            .to_string(),
        );
    };
    if let Err(e) = crate::machine::choix_avant::ecrire_brut(&note_nom, &note) {
        return Resultat::echec(
            Some(avant),
            trf!(
                "le chemin d'avant ne se note pas ({e}) : rien d'écrit",
                "the previous path cannot be noted ({e}): nothing written"
            ),
        );
    }
    if crate::machine::choix_avant::lire_brut(&note_nom).as_deref() != Some(note.as_slice()) {
        crate::machine::choix_avant::effacer_brut(&note_nom);
        return Resultat::echec(
            Some(avant),
            tr!(
                "la note ne se relit pas : rien d'écrit",
                "the note cannot be read back: nothing written"
            )
            .to_string(),
        );
    }
    // Relu juste avant d'écrire : un chemin changé pendant la question n'est jamais écrasé.
    if !lire_chemin(nom).is_ok_and(|(_, v, _)| meme_valeur(&v, brute)) {
        crate::machine::choix_avant::effacer_brut(&note_nom);
        return Resultat::echec(
            Some(avant),
            tr!(
                "le chemin a changé pendant la question : rien d'écrit",
                "the path changed during the question: nothing written"
            )
            .to_string(),
        );
    }
    let direct = sens_change_par_le_gestionnaire(&brute.vtype, &brut);
    let ecriture = if direct {
        ecrire_au_registre(
            nom,
            &winreg::RegValue {
                bytes: octets_texte(nouveau).into(),
                vtype: brute.vtype.clone(),
            },
        )
        .map_err(|e| e.to_string())
    } else {
        match super::services_ecriture::changer_le_chemin(nom.texte(), nouveau) {
            Ok(true) => Ok(()),
            Ok(false) => Err(tr!("service absent", "no such service").to_string()),
            Err(e) => Err(e.to_string()),
        }
    };
    let relue = lire_chemin(nom).ok().map(|(_, v, _)| v);
    if ecriture.is_ok() && relue.as_ref().is_some_and(|v| relue_conforme(&brute.vtype, v, nouveau)) {
        if direct {
            trp!(
                "  Écrit au registre : le gestionnaire des services le lira au prochain démarrage de Windows.",
                "  Written to the registry: the service manager will read it at the next Windows restart."
            );
        }
        return Resultat::fait(avant);
    }
    // Retour arrière : le chemin d'avant, exactement.
    let _ = ecrire_au_registre(nom, brute);
    let revenu = lire_chemin(nom).is_ok_and(|(_, v, _)| v.vtype == brute.vtype && v.bytes == brute.bytes);
    if revenu {
        crate::machine::choix_avant::effacer_brut(&note_nom);
    }
    let raison = match ecriture {
        Err(e) => e,
        Ok(()) => tr!(
            "le chemin relu n'est pas celui écrit",
            "the path read back is not the one written"
        )
        .to_string(),
    };
    Resultat::echec(
        Some(avant),
        if revenu {
            trf!(
                "{raison} ; le chemin d'avant est remis",
                "{raison}; the previous path is put back"
            )
        } else {
            trf!(
                "{raison} ; ATTENTION : le chemin d'avant ne se remet pas, vérifiez ce service (note gardée)",
                "{raison}; WARNING: the previous path could not be put back, check this service (note kept)"
            )
        },
    )
}

/// Met entre guillemets, après la question du risque, le chemin d'un service que Vanguard ne sait pas vérifier
/// (processus élevé) : relu, rejugé par `juger_service` (il doit être signalé, et « à la main »), puis noté et écrit.
pub(super) fn guillemets_risques(nom: &NomFichier) -> Resultat {
    let (cle, brute, brut) = match lire_chemin(nom) {
        Ok(l) => l,
        Err(r) => return r,
    };
    let avant = avant_notable(&brut);
    if brut.starts_with('"') {
        return Resultat::rien(
            tr!(
                "déjà entre guillemets, rien d'écrit",
                "already in quotes, nothing written"
            )
            .to_string(),
        );
    }
    let type_service = cle.get_value::<u32, _>("Type").unwrap_or(0);
    let Some(j) = juger_service(type_service, &brut, variable_systeme, existe, dossier_modifiable) else {
        return Resultat::echec(
            Some(avant),
            tr!(
                "refusé : le bilan refait ici ne signale pas ce service ; rien d'écrit",
                "refused: the check redone here does not flag this service; nothing written"
            )
            .to_string(),
        );
    };
    let Some(raison) = j.a_la_main.clone() else {
        return Resultat::echec(
            Some(avant),
            tr!(
                "refusé : ce chemin se vérifie, il passe par la correction sans question ; rien d'écrit",
                "refused: this path can be checked, it goes through the fix without a question; nothing written"
            )
            .to_string(),
        );
    };
    let Some(nouveau) = guillemets_risques_du_jugement(&j, &brut, variable_systeme) else {
        return Resultat::echec(
            Some(avant),
            tr!(
                "refusé : le chemin changerait autrement que par les guillemets ; rien d'écrit",
                "refused: the path would change beyond the quotes; nothing written"
            )
            .to_string(),
        );
    };
    if let Some(r) = refus_session(nom, &[&brut, &nouveau]) {
        return r;
    }
    let question = trf!(
        "  Service « {} » : {raison}.\n  Avec les guillemets, le service peut ne plus démarrer (chemin d'avant noté : « vanguard options-defense --remettre service:{} » le remet).\n  Mettre les guillemets ? [o/N] : ",
        "  Service “{}”: {raison}.\n  With the quotes, the service may no longer start (previous path noted: “vanguard options-defense --remettre service:{}” puts it back).\n  Add the quotes? [y/N]: ",
        affichable(nom.texte()),
        affichable(nom.texte())
    );
    if !crate::machine::reglages::confirmer(super::eleve::console_reelle(), &question, crate::ui::demander_ou_defaut) {
        return Resultat::echec(
            Some(avant),
            tr!("non confirmé : rien d'écrit", "not confirmed: nothing written").to_string(),
        );
    }
    noter_et_ecrire(nom, &brute, &nouveau)
}

/// La note du chemin d'un service : le chemin d'avant et celui que Vanguard a écrit.
fn note_chemin(nom: &NomFichier) -> Option<(crate::machine::reglages::Brute, crate::machine::reglages::Brute)> {
    use crate::machine::reglages;
    let note_nom = reglages::nom_note_service(nom.texte());
    let octets = crate::machine::choix_avant::lire_brut(&note_nom)?;
    let mut v = reglages::decoder(&octets, &note_nom, &["avant", "ecrit"])?.into_iter();
    Some((v.next()??, v.next()??))
}

/// Le texte d'une brute de chemin (REG_SZ ou REG_EXPAND_SZ).
fn texte_brute(b: &crate::machine::reglages::Brute) -> Option<String> {
    let t = type_texte(b.code)?;
    super::corrections::texte_reg(&winreg::RegValue {
        bytes: b.octets.clone().into(),
        vtype: t,
    })
}

fn type_texte(code: u32) -> Option<winreg::enums::RegType> {
    match code {
        1 => Some(winreg::enums::RegType::REG_SZ),
        2 => Some(winreg::enums::RegType::REG_EXPAND_SZ),
        _ => None,
    }
}

/// Ce que la remise du chemin d'un service va écrire, montré avant la question des baisses.
pub(super) fn texte_remise(nom: &NomFichier) -> String {
    let n = affichable(nom.texte());
    match note_chemin(nom).and_then(|(a, e)| Some((texte_brute(&a)?, texte_brute(&e)?))) {
        Some((avant, ecrit)) => trf!(
            "Chemin du service « {n} » : {} → REMIS À {}",
            "Path of the “{n}” service: {} → PUT BACK TO {}",
            avant_notable(&ecrit),
            avant_notable(&avant)
        ),
        None => trf!(
            "Chemin du service « {n} » : aucun chemin d'avant noté, rien ne sera écrit",
            "Path of the “{n}” service: no previous path noted, nothing will be written"
        ),
    }
}

/// Remet le chemin d'avant qu'une écriture de Vanguard a noté, si et seulement si le chemin est encore celui que
/// Vanguard a écrit (jamais par-dessus un changement fait depuis) ; la note est effacée une fois le chemin relu.
pub(super) fn remettre_chemin(nom: &NomFichier) -> Resultat {
    let Some((ancien, ecrit)) = note_chemin(nom) else {
        return Resultat::echec(
            None,
            tr!(
                "aucun chemin d'avant noté par Vanguard pour ce service (ou note abîmée) : rien d'écrit",
                "no previous path noted by Vanguard for this service (or damaged note): nothing written"
            )
            .to_string(),
        );
    };
    let (Some(t_ancien), Some(t_ecrit), Some(type_ancien)) =
        (texte_brute(&ancien), texte_brute(&ecrit), type_texte(ancien.code))
    else {
        return Resultat::echec(
            None,
            tr!("note abîmée : rien d'écrit", "damaged note: nothing written").to_string(),
        );
    };
    let (_, brute, brut) = match lire_chemin(nom) {
        Ok(l) => l,
        Err(r) => return r,
    };
    let avant = avant_notable(&brut);
    let note_nom = crate::machine::reglages::nom_note_service(nom.texte());
    if brute.vtype == type_ancien && brute.bytes.as_ref() == ancien.octets.as_slice() {
        crate::machine::choix_avant::effacer_brut(&note_nom);
        return Resultat::rien(trf!(
            "déjà ainsi ({avant}), rien d'écrit",
            "already so ({avant}), nothing written"
        ));
    }
    if !relue_conforme(&type_ancien, &brute, &t_ecrit) {
        return Resultat::echec(
            Some(avant),
            tr!(
                "le chemin a changé depuis que Vanguard l'a écrit : Vanguard n'écrit jamais par-dessus ; rien d'écrit",
                "the path has changed since Vanguard wrote it: Vanguard never writes over it; nothing written"
            )
            .to_string(),
        );
    }
    if let Some(r) = refus_session(nom, &[&brut, &t_ancien]) {
        return r;
    }
    let ecriture = if sens_change_par_le_gestionnaire(&type_ancien, &t_ancien) {
        ecrire_au_registre(
            nom,
            &winreg::RegValue {
                bytes: ancien.octets.clone().into(),
                vtype: type_ancien.clone(),
            },
        )
        .map_err(|e| e.to_string())
    } else {
        match super::services_ecriture::changer_le_chemin(nom.texte(), &t_ancien) {
            Ok(true) => Ok(()),
            Ok(false) => Err(tr!("service absent", "no such service").to_string()),
            Err(e) => Err(e.to_string()),
        }
    };
    if let Err(e) = ecriture {
        return Resultat::echec(Some(avant), trf!("{e} ; la note est gardée", "{e}; the note is kept"));
    }
    match lire_chemin(nom) {
        Ok((_, v, _)) if relue_conforme(&type_ancien, &v, &t_ancien) => {
            crate::machine::choix_avant::effacer_brut(&note_nom);
            Resultat::fait(avant)
        }
        _ => Resultat::echec(
            Some(avant),
            tr!(
                "le chemin relu n'est pas celui noté ; la note est gardée",
                "the path read back is not the noted one; the note is kept"
            )
            .to_string(),
        ),
    }
}

/// Un ImagePath REG_SZ qui contient « % » : le gestionnaire des services ne le développe pas, mais l'écrirait en
/// REG_EXPAND_SZ (comme tout chemin qu'il reçoit) ; « %X% » deviendrait une variable. Sans « % », même sens.
fn sens_change_par_le_gestionnaire(vtype: &winreg::enums::RegType, brut: &str) -> bool {
    *vtype == winreg::enums::RegType::REG_SZ && brut.contains('%')
}

/// La valeur relue est-elle celle voulue ? Le texte exact, et le type d'avant ; un REG_SZ d'avant peut revenir en
/// REG_EXPAND_SZ (écrit ainsi par le gestionnaire des services) : sans « % », même sens.
fn relue_conforme(avant: &winreg::enums::RegType, relue: &winreg::RegValue, nouveau: &str) -> bool {
    use winreg::enums::RegType::{REG_EXPAND_SZ, REG_SZ};
    let type_admis =
        relue.vtype == *avant || (*avant == REG_SZ && relue.vtype == REG_EXPAND_SZ && !nouveau.contains('%'));
    type_admis && super::corrections::texte_reg(relue).as_deref() == Some(nouveau)
}

/// La première variable (« %Nom% ») de `texte` que `variable` ne connaît pas.
fn variable_inconnue(texte: &str, variable: impl Fn(&str) -> Option<String>) -> Option<String> {
    let mut inconnue = None;
    developper(texte, |n| {
        let v = variable(n);
        if v.is_none() && inconnue.is_none() {
            inconnue = Some(n.to_string());
        }
        v
    });
    inconnue
}

/// `texte` développé, ou `None` s'il cite une variable inconnue.
fn developper_tout(texte: &str, variable: impl Fn(&str) -> Option<String>) -> Option<String> {
    variable_inconnue(texte, &variable)
        .is_none()
        .then(|| developper(texte, variable))
}

/// « %SystemRoot%\x » développé ; une variable inconnue reste telle quelle.
fn developper(texte: &str, mut variable: impl FnMut(&str) -> Option<String>) -> String {
    let mut sortie = String::new();
    let mut reste = texte;
    while let Some(debut) = reste.find('%') {
        let apres = &reste[debut + 1..];
        let Some(fin) = apres.find('%') else { break };
        sortie.push_str(&reste[..debut]);
        match (fin > 0).then(|| variable(&apres[..fin])).flatten() {
            Some(v) => sortie.push_str(&v),
            None => sortie.push_str(&reste[debut..debut + fin + 2]),
        }
        reste = &apres[fin + 1..];
    }
    sortie.push_str(reste);
    sortie
}

/// Le programme d'une ligne de service sans guillemets et la suite (arguments, espace de tête compris), comme
/// `'^(.+?\.exe)(\s.*)?$'` ; `None` si la ligne commence par un guillemet, n'a pas de « .exe » suivi d'un blanc ou
/// de la fin, ou si le programme n'a pas d'espace (rien à piéger).
fn programme_sans_guillemets(ligne: &str) -> Option<(&str, &str)> {
    programme_et_suite(ligne).filter(|(exe, _)| exe.contains(' '))
}

/// Le programme et la suite d'une ligne sans guillemets, comme `'^(.+?\.exe)(\s.*)?$'`, espace ou non dans le
/// programme (un ImagePath brut « %ProgramFiles%\Outil\svc.exe » n'en a pas avant d'être développé).
fn programme_et_suite(ligne: &str) -> Option<(&str, &str)> {
    if ligne.is_empty() || ligne.starts_with('"') {
        return None;
    }
    let bas = ligne.to_ascii_lowercase();
    let fin = bas.match_indices(".exe").map(|(i, _)| i + 4).find(|&f| {
        f > 4
            && ligne
                .get(f..)
                .is_some_and(|r| r.chars().next().is_none_or(char::is_whitespace))
    })?;
    Some(ligne.split_at(fin))
}

/// Le premier dossier où un programme piégé démarrerait à la place du service (« C:\ » pour « C:\Program.exe », puis
/// « C:\Program Files » pour « C:\Program Files\Mon.exe »…), s'il est `modifiable`.
fn dossier_piege(exe: &str, modifiable: impl Fn(&std::path::Path) -> bool) -> Option<std::path::PathBuf> {
    let parties: Vec<&str> = exe.split(' ').collect();
    (1..parties.len()).find_map(|i| {
        let debut = parties.get(..i)?.join(" ");

        let d = std::path::Path::new(&debut).parent()?;
        (!d.as_os_str().is_empty() && modifiable(d)).then(|| d.to_path_buf())
    })
}

/// Une règle « autoriser » qui n'est pas « héritée seulement » donne à un compte de tous le droit de créer un fichier
/// (0x2), d'écrire (générique, 0x40000000) ou tout (générique, 0x10000000) : ce que le script lisait dans Get-Acl.
fn modifiable_par_tous(descripteur: &[u8]) -> bool {
    const HERITEE_SEULEMENT: u8 = 0x8;
    const ECRIRE: u32 = 0x5000_0002;
    let Some(regles) = super::securite::aces(descripteur) else {
        // Sans liste de droits, tout le monde a tout.
        return true;
    };
    regles.iter().any(|r| {
        r.sorte == 0
            && r.drapeaux & HERITEE_SEULEMENT == 0
            && r.masque & ECRIRE != 0
            && super::securite::sid_en_texte(&r.sid).is_some_and(|s| TOUS.contains(&s.as_str()))
    })
}

/// Les services exploitables lus dans la sortie du script, avec la ligne qui met leur chemin entre guillemets (le nom
/// seul : le processus élevé relit ImagePath et rejuge). `None` sans service à signaler, ou si la liste n'a pas été
/// lue jusqu'au bout.
pub(super) fn juger(sortie: &str) -> Option<Constat> {
    if !sortie.lines().any(|l| l.trim() == "SVC_FIN") {
        return None;
    }
    let mut noms = Vec::new();
    let mut inconnus = Vec::new();
    let mut commandes = Vec::new();
    let mut automatiques = Vec::new();
    let mut risques = Vec::new();
    let mut a_la_main = Vec::new();
    for (manuel, ligne) in sortie.lines().filter_map(|l| {
        let l = l.trim_end_matches('\r');
        l.strip_prefix("SVC|")
            .map(|r| (false, r))
            .or_else(|| l.strip_prefix("SVCM|").map(|r| (true, r)))
    }) {
        // Arguments en dernier : « -f a|b » reste entier (le dossier, avant, reste juste).
        let mut champs = ligne.splitn(4, '|');
        let (Some(nom), Some(_programme), Some(dossier), Some(_arguments)) =
            (champs.next(), champs.next(), champs.next(), champs.next())
        else {
            continue;
        };
        if nom.is_empty() {
            continue;
        }
        // Sans dossier : le programme cite une variable inconnue, son chemin réel est inconnu. Toujours à la main, que
        // la ligne soit « SVCM » ou non.
        if dossier.is_empty() {
            inconnus.push(affichable(nom));
            // « SVCM » : les guillemets après la question du risque (défense D6b), le processus élevé rejugeant.
            match gestes::ligne_service_guillemets_risque(nom).filter(|_| manuel) {
                Some(l) => {
                    commandes.push(l);
                    risques.push(affichable(nom));
                }
                None => a_la_main.push(affichable(nom)),
            }
            continue;
        }
        // Un nom de service peut avoir des espaces et des parenthèses (« Bonjour Service », « Intel(R) … ») : écarté,
        // le service exploitable passait pour sain. Il est toujours signalé ; un nom que la grammaire des lignes
        // refuse (séparateur, caractère de contrôle, « .. ») n'a pas de ligne : à corriger à la main.
        noms.push(format!("{} ({})", affichable(nom), affichable(dossier)));
        let ligne = if manuel {
            gestes::ligne_service_guillemets_risque(nom).map(|l| (l, &mut risques))
        } else {
            gestes::ligne_service_guillemets(nom).map(|l| (l, &mut automatiques))
        };
        match ligne {
            Some((l, liste)) => {
                commandes.push(l);
                liste.push(affichable(nom));
            }
            None => a_la_main.push(affichable(nom)),
        }
    }
    if noms.is_empty() && inconnus.is_empty() {
        return None;
    }
    // Ce que Vanguard n'a pas pu situer est dit tel quel, à vérifier, jamais compté comme sain.
    let inconnu = trf!(
        "Service au chemin sans guillemets qui cite une variable inconnue de l'environnement du système : {}. Vanguard ne sait pas où ce chemin mène : à vérifier à la main.",
        "Service with an unquoted path that cites a variable unknown to the system environment: {}. Vanguard does not know where this path leads: to check by hand.",
        resume(&inconnus, 3, ", ")
    );
    let constat = if noms.is_empty() {
        alerte("Persistance", Niveau::Moyen, inconnu)
    } else {
        let piege = trf!(
            "Service au chemin sans guillemets, dans un dossier modifiable par tous : {}. Un programme posé là démarrerait avec les droits du système.",
            "Service with an unquoted path, in a folder anyone can change: {}. A program dropped there would start with system rights.",
            resume(&noms, 3, ", ")
        );
        let message = if inconnus.is_empty() {
            piege
        } else {
            format!("{piege} {inconnu}")
        };
        alerte("Persistance", Niveau::Eleve, message)
    };
    // Une correction automatique : dite telle quelle, service par service ; celle qui demande d'abord, à part.
    let mut parties = Vec::new();
    if !automatiques.is_empty() {
        parties.push(trf!(
            "Vanguard ajoute les guillemets au chemin du service {} ; signaler ensuite le défaut à l'éditeur du programme",
            "Vanguard adds the quotes to the path of the service {}; then report the flaw to the program's publisher",
            resume(&automatiques, 3, ", ")
        ));
    }
    if !risques.is_empty() {
        parties.push(trf!(
            "Vanguard ajoute les guillemets, après une question (il ne sait pas vérifier ce chemin : le service peut ne plus démarrer ; chemin d'avant noté, annulable), au chemin du service {}",
            "Vanguard adds the quotes, after a question (it cannot check this path: the service may no longer start; previous path noted, undoable), to the path of the service {}",
            resume(&risques, 3, ", ")
        ));
    }
    let action = parties.join(" ; ");
    if commandes.is_empty() {
        return Some(constat.manuel(
            trf!(
                "Vérifier à la main, dans regedit, le chemin (ImagePath) du service, puis le mettre entre guillemets : {}",
                "In regedit, check the service's path (ImagePath) by hand, then put it in quotes: {}",
                resume(&a_la_main, 3, ", ")
            ),
            &[],
        ));
    }
    if a_la_main.is_empty() {
        return Some(constat.corriger(action, &commandes));
    }
    Some(constat.corriger(
        trf!(
            "{action} ; à la main dans regedit pour : {}",
            "{action}; by hand in regedit for: {}",
            resume(&a_la_main, 3, ", ")
        ),
        &commandes,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le chemin relu juste avant d'écrire doit être exactement celui qui a été jugé et montré : type et octets.
    #[test]
    fn chemin_relu_avant_d_ecrire_identique() {
        use winreg::enums::{REG_EXPAND_SZ, REG_SZ};
        let v = |vtype, t: &str| winreg::RegValue {
            bytes: octets_texte(t).into(),
            vtype,
        };
        assert!(meme_valeur(&v(REG_SZ, r"C:\a b\s.exe"), &v(REG_SZ, r"C:\a b\s.exe")));
        assert!(!meme_valeur(
            &v(REG_SZ, r"C:\a b\s.exe"),
            &v(REG_EXPAND_SZ, r"C:\a b\s.exe")
        ));
        assert!(!meme_valeur(&v(REG_SZ, r"C:\a b\s.exe"), &v(REG_SZ, r"C:\a b\t.exe")));
        assert!(!meme_valeur(&v(REG_SZ, r"C:\a b\s.exe"), &v(REG_SZ, r"C:\a b\s.exe ")));
    }

    #[test]
    fn programmes_sans_guillemets() {
        assert_eq!(
            programme_sans_guillemets(r"C:\Program Files\Mon Outil\svc.exe -k x"),
            Some((r"C:\Program Files\Mon Outil\svc.exe", " -k x"))
        );
        assert_eq!(
            programme_sans_guillemets(r"C:\Mon Outil\a.exe.bak\svc.EXE"),
            Some((r"C:\Mon Outil\a.exe.bak\svc.EXE", ""))
        );
        assert_eq!(programme_sans_guillemets(r#""C:\Program Files\a.exe""#), None);
        assert_eq!(programme_sans_guillemets(r"C:\Windows\svchost.exe -k netsvcs"), None);
        assert_eq!(programme_sans_guillemets(r"C:\Program Files\pilote.sys"), None);
        assert_eq!(programme_sans_guillemets(".exe x"), None);
    }

    #[test]
    fn variables_developpees() {
        let v = |n: &str| (n == "SystemRoot").then(|| r"C:\Windows".to_string());
        assert_eq!(
            developper(r"%SystemRoot%\system32\a.exe", v),
            r"C:\Windows\system32\a.exe"
        );
        assert_eq!(developper("%Inconnue%\\a %SystemRoot%", v), r"%Inconnue%\a C:\Windows");
        assert_eq!(developper("100% sûr", v), "100% sûr");
        assert_eq!(developper("%%", v), "%%");
    }

    #[test]
    fn dossiers_pieges() {
        let exe = r"C:\Program Files\Mon Outil\svc.exe";
        let ouvert = |d: &std::path::Path| d.to_string_lossy() == r"C:\Program Files";
        assert_eq!(dossier_piege(exe, ouvert), Some(r"C:\Program Files".into()));
        assert_eq!(dossier_piege(exe, |_| false), None);
    }

    /// Un descripteur avec une règle : (sorte, drapeaux, masque) pour Utilisateurs (S-1-5-32-545).
    fn descripteur(sorte: u8, drapeaux: u8, masque: u32) -> Vec<u8> {
        let mut sid = vec![1, 2, 0, 0, 0, 0, 0, 5];
        sid.extend_from_slice(&32u32.to_le_bytes());
        sid.extend_from_slice(&545u32.to_le_bytes());
        let mut regle = vec![sorte, drapeaux];
        regle.extend_from_slice(&u16::try_from(8 + sid.len()).unwrap().to_le_bytes());
        regle.extend_from_slice(&masque.to_le_bytes());
        regle.extend_from_slice(&sid);
        let mut d = vec![1, 0, 0x04, 0x80];
        d.extend_from_slice(&[0; 12]);
        d.extend_from_slice(&20u32.to_le_bytes());
        d.extend_from_slice(&[2, 0]);
        d.extend_from_slice(&u16::try_from(8 + regle.len()).unwrap().to_le_bytes());
        d.extend_from_slice(&[1, 0, 0, 0]);
        d.extend_from_slice(&regle);
        d
    }

    #[test]
    fn droits_de_tous() {
        assert!(modifiable_par_tous(&descripteur(0, 0, 0x2)));
        assert!(modifiable_par_tous(&descripteur(0, 0x3, 0x4000_0000)));
        // Héritée seulement, refus, ou lecture seule : pas exploitable.
        assert!(!modifiable_par_tous(&descripteur(0, 0x8, 0x2)));
        assert!(!modifiable_par_tous(&descripteur(1, 0, 0x2)));
        assert!(!modifiable_par_tous(&descripteur(0, 0, 0x0012_00A9)));
    }

    /// Le vrai registre et les vrais droits (Wine ici, la VM ensuite) : la liste se lit jusqu'au bout.
    #[test]
    fn services_lus_sans_powershell() {
        let t = lire_natif().expect("clé des services");
        assert!(t.ends_with("SVC_FIN"), "{t}");
        let _ = juger(&t);
    }

    #[test]
    fn chemins_sans_guillemets() {
        // Liste pas lue jusqu'au bout : rien.
        assert!(juger("SVC|Outil|C:\\Mes Outils\\svc.exe|C:\\Mes Outils| -k\n").is_none());
        assert!(juger("SVC_FIN\n").is_none());
        let c = juger(
            "SVC|OutilMaj|C:\\Mes Outils\\Outil Maj\\maj.exe|C:\\Mes Outils| -service\r\nSVC|pi;ege|C:\\A B\\x.exe|C:\\A B|\nSVC_FIN\n",
        )
        .unwrap();
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(c.message.contains("OutilMaj (C:\\Mes Outils)") && c.message.contains("pi;ege"));
        let k = c.correctif.unwrap();
        assert!(k.automatique);
        // Le nom seul, en hexadécimal : le processus élevé relit ImagePath.
        assert_eq!(
            k.commandes,
            [
                gestes::ligne_service_guillemets("OutilMaj").unwrap(),
                gestes::ligne_service_guillemets("pi;ege").unwrap()
            ]
        );
        assert_eq!(k.commandes[1], "vanguard:service-guillemets 700069003b00650067006500");
        // Espaces, parenthèses et apostrophe dans le nom : signalé, avec sa ligne (l'apostrophe doublée dans la
        // commande d'avant). Un nom que la grammaire refuse est signalé, à corriger à la main.
        let c = juger(
            "SVC|Bonjour Service|C:\\Program Files\\Bonjour\\mDNSResponder.exe|C:\\Program Files|\nSVC|Intel(R) l'outil|C:\\A B\\x.exe|C:\\A B|\nSVC|a/b|C:\\A B\\y.exe|C:\\A B|\nSVC_FIN\n",
        )
        .unwrap();
        assert!(c.message.contains("Bonjour Service (C:\\Program Files)"));
        assert!(c.message.contains("Intel(R) l'outil") && c.message.contains("a/b"));
        let k = c.correctif.unwrap();
        assert_eq!(k.commandes.len(), 2);
        assert!(k.automatique && k.action.contains("a/b"), "{}", k.action);
        // La correction automatique est dite telle quelle, avec le nom du service.
        assert!(
            (k.action.contains("Vanguard ajoute les guillemets") || k.action.contains("Vanguard adds the quotes"))
                && k.action.contains("Bonjour Service"),
            "{}",
            k.action
        );
        let ps = super::super::corrections::en_powershell(std::slice::from_ref(&k.commandes));
        assert!(ps[0][0].starts_with("$k = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Bonjour Service'; "));
        assert!(ps[0][1].contains("Services\\Intel(R) l''outil'; "));
        // Seuls des noms refusés : à la main, sans ligne.
        let c = juger("SVC|a\\b|C:\\A B\\y.exe|C:\\A B|\nSVC|..|C:\\A B\\z.exe|C:\\A B|\nSVC_FIN\n").unwrap();
        let k = c.correctif.unwrap();
        assert!(k.commandes.is_empty() && !k.automatique && k.action.contains("regedit"));
    }

    /// Des arguments qui contiennent « | » : le dossier reste juste ; le processus élevé relit toute la ligne du
    /// service, arguments compris.
    #[test]
    fn arguments_avec_barre() {
        let c = juger("SVC|Outil|C:\\Mon Outil\\svc.exe|C:\\Mon Outil| -f a|b\nSVC_FIN\n").unwrap();
        assert!(c.message.contains("Outil (C:\\Mon Outil)"), "{}", c.message);
        assert_eq!(
            c.correctif.unwrap().commandes,
            [gestes::ligne_service_guillemets("Outil").unwrap()]
        );
        let v = |n: &str| (n == "X").then(|| "C:\\Mon Outil".to_string());
        assert_eq!(
            entre_guillemets(0x10, r"C:\Mon Outil\svc.exe -f a|b", v, |_| true, |_| true).as_deref(),
            Some(r#""C:\Mon Outil\svc.exe" -f a|b"#)
        );
    }

    /// Le processus élevé rejuge par LA fonction du bilan (`juger_service`), sur les mêmes données : il ne pose des
    /// guillemets que sur un service que le bilan signale, sans toucher aux variables, et la valeur développée ne
    /// change que par les guillemets.
    #[test]
    fn le_processus_eleve_rejuge_comme_le_bilan() {
        let variable = |n: &str| match n {
            "ProgramFiles" => Some(r"C:\Program Files".to_string()),
            "Bizarre" => Some(r"C:\A B\x.exe C:\Autre".to_string()),
            _ => None,
        };
        let ouvert = |d: &std::path::Path| d == std::path::Path::new(r"C:\");
        let cas: [(u32, &str, Option<&str>); 9] = [
            (
                0x10,
                r"C:\Program Files\Mon Outil\svc.exe -k x",
                Some(r#""C:\Program Files\Mon Outil\svc.exe" -k x"#),
            ),
            // Variable gardée telle quelle : sans espace avant d'être développée, piégée après.
            (
                0x20,
                r"%ProgramFiles%\Outil\svc.exe",
                Some(r#""%ProgramFiles%\Outil\svc.exe""#),
            ),
            // Un pilote, un chemin déjà entre guillemets, un programme sans espace, un dossier sûr : pas signalés.
            (0x1, r"C:\Program Files\Pilote\p.exe", None),
            (0x10, r#""C:\Program Files\a.exe""#, None),
            (0x10, r"C:\Windows\svchost.exe -k netsvcs", None),
            (0x10, r"C:\Sur\Mon Outil\svc.exe", None),
            (0x10, r"C:\Program Files\pilote.sys", None),
            // Une variable qui déplacerait le « .exe » : la valeur changerait autrement que par les guillemets.
            (0x10, r"%Bizarre%\y.exe", None),
            (0x10, "", None),
        ];
        for (type_service, brut, attendu) in cas {
            let bilan = juger_service(type_service, brut, variable, |_| true, ouvert);
            let eleve = entre_guillemets(type_service, brut, variable, |_| true, ouvert);
            assert_eq!(eleve.as_deref(), attendu, "{brut}");
            // Le processus élevé n'écrit jamais là où le bilan ne signale rien.
            assert!(eleve.is_none() || bilan.is_some(), "{brut}");
            if let (Some(nouveau), Some(j)) = (&eleve, &bilan) {
                assert_eq!(
                    developper(nouveau, variable),
                    format!("\"{}\"{}", j.exe, j.suite),
                    "{brut}"
                );
            }
        }
        // Le cas %Bizarre% est bien signalé par le bilan : c'est la garde des guillemets seuls qui refuse.
        assert!(juger_service(0x10, r"%Bizarre%\y.exe", variable, |_| true, ouvert).is_some());
    }

    /// Une variable que l'environnement du système ne connaît pas, ou un programme introuvable : signalé, mais à la
    /// main ; le processus élevé n'écrit rien. Le bilan le dit par une ligne « SVCM », sans commande.
    #[test]
    fn variable_inconnue_ou_programme_absent_a_la_main() {
        let variable = |n: &str| n.eq_ignore_ascii_case("SystemRoot").then(|| r"C:\Windows".to_string());
        let ouvert = |d: &std::path::Path| d == std::path::Path::new(r"C:\");
        let present = |p: &std::path::Path| p == std::path::Path::new(r"C:\Program Files\Mon Outil\svc.exe");
        let brut = r"C:\Program Files\Mon Outil\svc.exe -k %Inconnue%";
        let j = juger_service(0x10, brut, variable, present, ouvert).unwrap();
        assert!(
            j.a_la_main.as_deref().is_some_and(|r| r.contains("%Inconnue%")),
            "{j:?}"
        );
        assert_eq!(entre_guillemets(0x10, brut, variable, present, ouvert), None);
        let brut = r"C:\Program Files\Autre Outil\svc.exe";
        let j = juger_service(0x10, brut, variable, present, ouvert).unwrap();
        assert!(
            j.a_la_main.as_deref().is_some_and(|r| r.contains("Autre Outil")),
            "{j:?}"
        );
        assert_eq!(entre_guillemets(0x10, brut, variable, present, ouvert), None);
        // Présent et sans variable inconnue : écrit.
        let brut = r"C:\Program Files\Mon Outil\svc.exe -k %SystemRoot%";
        assert!(
            juger_service(0x10, brut, variable, present, ouvert)
                .unwrap()
                .a_la_main
                .is_none()
        );
        assert_eq!(
            entre_guillemets(0x10, brut, variable, present, ouvert).as_deref(),
            Some(r#""C:\Program Files\Mon Outil\svc.exe" -k %SystemRoot%"#)
        );
        // La ligne du bilan « SVCM » : les guillemets après la question du risque (défense D6b), jamais la ligne
        // ordinaire ; l'action dit que le service peut ne plus démarrer.
        let c = juger("SVCM|Outil|C:\\Mon Outil\\svc.exe|C:\\Mon Outil|\nSVC_FIN\n").unwrap();
        let k = c.correctif.unwrap();
        assert_eq!(k.commandes, [gestes::ligne_service_guillemets_risque("Outil").unwrap()]);
        assert!(
            k.action.contains("Outil")
                && (k.action.contains("peut ne plus démarrer") || k.action.contains("may no longer start")),
            "{}",
            k.action
        );
        // Un service à la main parmi d'autres : chacun sa ligne, la risquée pour celui à la main seulement.
        let c = juger("SVCM|Outil|C:\\A B\\x.exe|C:\\A B|\nSVC|Autre|C:\\A B\\y.exe|C:\\A B|\nSVC_FIN\n").unwrap();
        let k = c.correctif.unwrap();
        assert_eq!(
            k.commandes,
            [
                gestes::ligne_service_guillemets_risque("Outil").unwrap(),
                gestes::ligne_service_guillemets("Autre").unwrap()
            ]
        );
        // Un nom que la grammaire refuse n'a aucune ligne, même risquée : à la main.
        let c = juger("SVCM|a..b|C:\\A B\\x.exe|C:\\A B|\nSVC_FIN\n").unwrap();
        let k = c.correctif.unwrap();
        assert!(k.commandes.is_empty() && !k.automatique, "{}", k.action);
    }

    /// Le développement par l'environnement du système : une valeur qui cite une variable inconnue n'est pas
    /// développée à moitié ; « %% » n'est pas une variable.
    #[test]
    fn developpement_entier_ou_rien() {
        let v = |n: &str| (n == "SystemRoot").then(|| r"C:\Windows".to_string());
        assert_eq!(
            developper_tout(r"%SystemRoot%\system32\cmd.exe", v).as_deref(),
            Some(r"C:\Windows\system32\cmd.exe")
        );
        assert_eq!(developper_tout(r"%SystemRoot%\%Autre%", v), None);
        assert_eq!(variable_inconnue("%% 100%", v), None);
        assert_eq!(variable_inconnue(r"%Autre%\%Encore%", v).as_deref(), Some("Autre"));
    }

    /// Le vrai environnement du système (Wine ici, la VM ensuite) : chaque variable calculée a la valeur des mêmes
    /// sources que `dossiers()`. Que Session Manager ne les remplace pas, c'est `program_files_par_les_dossiers_connus`
    /// qui le prouve (ici, les deux coïncident) ; que ce processus n'y est pour rien, `environnement_du_compte_sans_effet`
    /// et la garde `aucune_variable_lue_dans_le_processus`.
    #[test]
    fn environnement_du_systeme() {
        let Some(racine) = variable_systeme("SystemRoot") else {
            return crate::essais::saute("dossier de Windows illisible");
        };
        assert_eq!(variable_systeme("windir").as_deref(), Some(racine.as_str()));
        assert!(!racine.ends_with('\\') && racine.len() > 2, "{racine}");
        assert_eq!(variable_systeme("VanguardInexistante"), None);
        let d = super::super::environnement::dossiers();
        assert_eq!(
            variable_systeme("programfiles").map(std::path::PathBuf::from),
            d.program_files.clone()
        );
        assert_eq!(
            variable_systeme("ProgramData").map(std::path::PathBuf::from),
            d.program_data.clone()
        );
        assert_eq!(
            variable_systeme("ALLUSERSPROFILE").map(std::path::PathBuf::from),
            d.program_data.clone()
        );
        assert_eq!(
            variable_systeme("PUBLIC").map(std::path::PathBuf::from),
            d.public.clone()
        );
        assert_eq!(variable_systeme("SystemDrive").as_deref(), racine.get(..2));
    }

    /// Des dossiers de Windows inventés, pour les variables calculées.
    fn dossiers_exemple() -> super::super::environnement::Dossiers {
        super::super::environnement::Dossiers {
            windows: r"C:\Windows".into(),
            program_files: Some(r"C:\Program Files\".into()),
            program_files_x86: Some(r"C:\Program Files (x86)".into()),
            program_files_x64: Some(r"C:\Program Files".into()),
            fichiers_communs: Some(r"C:\Program Files\Common Files".into()),
            fichiers_communs_x86: Some(r"C:\Program Files (x86)\Common Files".into()),
            fichiers_communs_x64: Some(r"C:\Program Files\Common Files".into()),
            program_data: Some(r"C:\ProgramData".into()),
            public: Some(r"C:\Users\Public".into()),
            ..Default::default()
        }
    }

    /// ProgramFiles et les autres variables calculées viennent des dossiers connus (fonction injectée), jamais de
    /// Session Manager, même si une valeur du même nom y est posée ; une autre variable de Session Manager est
    /// développée avec eux seulement.
    #[test]
    fn program_files_par_les_dossiers_connus() {
        let d = dossiers_exemple();
        let w = Some(std::path::Path::new(r"C:\Windows"));
        let session = |n: &str| match n {
            "ProgramFiles" | "SystemRoot" | "SystemDrive" | "PUBLIC" => Some(r"C:\Piege".to_string()),
            "Outils" => Some(r"%ProgramFiles(x86)%\Outils".to_string()),
            "Mixte" => Some(r"%ProgramFiles%\%Autre%".to_string()),
            "VendorHome" => Some(r"%SystemDrive%\Vendor".to_string()),
            "ProgramFiles(Arm)" => Some(r"C:\Program Files (Arm)".to_string()),
            _ => None,
        };
        let v = |n: &str| variable_selon(n, |m| dossier_calcule(&d, w, m), session);
        assert_eq!(v("ProgramFiles").as_deref(), Some(r"C:\Program Files"));
        assert_eq!(v("PROGRAMFILES").as_deref(), Some(r"C:\Program Files"));
        assert_eq!(v("SystemRoot").as_deref(), Some(r"C:\Windows"));
        assert_eq!(v("windir").as_deref(), Some(r"C:\Windows"));
        assert_eq!(v("ProgramW6432").as_deref(), Some(r"C:\Program Files"));
        assert_eq!(
            v("CommonProgramFiles(x86)").as_deref(),
            Some(r"C:\Program Files (x86)\Common Files")
        );
        assert_eq!(
            v("CommonProgramW6432").as_deref(),
            Some(r"C:\Program Files\Common Files")
        );
        assert_eq!(v("ProgramData").as_deref(), Some(r"C:\ProgramData"));
        assert_eq!(v("Outils").as_deref(), Some(r"C:\Program Files (x86)\Outils"));
        assert_eq!(v("Mixte"), None);
        assert_eq!(v("Absente"), None);
        // SystemDrive : la lettre du dossier de Windows, jamais celle de Session Manager ; une valeur qui la cite se
        // développe.
        assert_eq!(v("SystemDrive").as_deref(), Some("C:"));
        assert_eq!(v("systemdrive").as_deref(), Some("C:"));
        assert_eq!(v("VendorHome").as_deref(), Some(r"C:\Vendor"));
        assert_eq!(v("ALLUSERSPROFILE").as_deref(), Some(r"C:\ProgramData"));
        assert_eq!(v("PUBLIC").as_deref(), Some(r"C:\Users\Public"));
        // ProgramFiles(Arm) n'est pas calculée (aucun dossier connu documenté) : Session Manager la donne telle quelle.
        assert_eq!(v("ProgramFiles(Arm)").as_deref(), Some(r"C:\Program Files (Arm)"));
        // Le dossier de Windows non donné : SystemRoot, windir et SystemDrive inconnues, sans repli ni Session Manager,
        // même si `Dossiers::windows` (le repli de `dossiers()`) a une valeur.
        let v0 = |n: &str| variable_selon(n, |m| dossier_calcule(&d, None, m), session);
        for n in ["SystemRoot", "windir", "SystemDrive", "VendorHome"] {
            assert_eq!(v0(n), None, "{n}");
        }
        assert_eq!(v0("ProgramFiles").as_deref(), Some(r"C:\Program Files"));
        // Un dossier de Windows sans lettre (chemin réseau) : pas de SystemDrive.
        let unc = Some(std::path::Path::new(r"\\serveur\Windows"));
        assert_eq!(dossier_calcule(&d, unc, "SystemDrive"), None);
        // Un dossier que Windows ne donne pas : la variable est inconnue, Session Manager ne la remplace pas.
        let sans = super::super::environnement::Dossiers {
            program_files: None,
            ..dossiers_exemple()
        };
        let v2 = |n: &str| variable_selon(n, |m| dossier_calcule(&sans, w, m), session);
        assert_eq!(v2("ProgramFiles"), None);
        // Le service %ProgramFiles% du banc : dossier piège sous Program Files, guillemets posés, variable gardée.
        let brut = r"%ProgramFiles%\vg-essai\Mon Outil\svc.exe";
        let ouvert = |p: &std::path::Path| p == std::path::Path::new(r"C:\Program Files\vg-essai");
        let j = juger_service(0x10, brut, v, |_| true, ouvert).unwrap();
        assert_eq!(j.exe, r"C:\Program Files\vg-essai\Mon Outil\svc.exe");
        assert_eq!(
            j.dossier.as_deref(),
            Some(std::path::Path::new(r"C:\Program Files\vg-essai"))
        );
        assert!(j.a_la_main.is_none(), "{j:?}");
        assert_eq!(
            entre_guillemets(0x10, brut, v, |_| true, ouvert).as_deref(),
            Some(r#""%ProgramFiles%\vg-essai\Mon Outil\svc.exe""#)
        );
        // Sans le dossier connu : à la main, rien d'écrit.
        let j = juger_service(0x10, brut, v2, |_| true, ouvert).unwrap();
        assert!(j.a_la_main.is_some() && j.dossier.is_none(), "{j:?}");
        assert_eq!(entre_guillemets(0x10, brut, v2, |_| true, ouvert), None);
        // Le cas type : un service sous %SystemDrive%, dans un dossier que tous peuvent modifier. Signalé avec son
        // dossier piège et son correctif, la variable gardée.
        let brut = r"%SystemDrive%\Vendor Tools\Agent Service\svc.exe -k";
        let ouvert = |p: &std::path::Path| p == std::path::Path::new(r"C:\Vendor Tools");
        let j = juger_service(0x10, brut, v, |_| true, ouvert).unwrap();
        assert_eq!(j.exe, r"C:\Vendor Tools\Agent Service\svc.exe");
        assert_eq!(j.dossier.as_deref(), Some(std::path::Path::new(r"C:\Vendor Tools")));
        assert!(j.a_la_main.is_none(), "{j:?}");
        assert_eq!(
            entre_guillemets(0x10, brut, v, |_| true, ouvert).as_deref(),
            Some(r#""%SystemDrive%\Vendor Tools\Agent Service\svc.exe" -k"#)
        );
        // Sans le dossier de Windows : à la main, rien d'écrit.
        let j = juger_service(0x10, brut, v0, |_| true, ouvert).unwrap();
        assert!(j.a_la_main.is_some() && j.dossier.is_none(), "{j:?}");
        assert_eq!(entre_guillemets(0x10, brut, v0, |_| true, ouvert), None);
    }

    /// Le type de l'ImagePath face au gestionnaire des services : un REG_SZ avec « % » est refusé avant d'écrire ;
    /// à la relecture, le REG_EXPAND_SZ n'est admis à la place d'un REG_SZ que sans « % ».
    #[test]
    fn type_du_chemin_garde_son_sens() {
        use winreg::enums::RegType::{REG_BINARY, REG_EXPAND_SZ, REG_SZ};
        assert!(sens_change_par_le_gestionnaire(&REG_SZ, r"C:\%X%\svc.exe"));
        assert!(!sens_change_par_le_gestionnaire(&REG_SZ, r"C:\A B\svc.exe"));
        assert!(!sens_change_par_le_gestionnaire(
            &REG_EXPAND_SZ,
            r"%SystemRoot%\A B\svc.exe"
        ));
        let valeur = |t: &str, vtype| winreg::RegValue {
            bytes: t
                .encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<u8>>()
                .into(),
            vtype,
        };
        let n = r#""C:\A B\svc.exe""#;
        assert!(relue_conforme(&REG_SZ, &valeur(n, REG_SZ), n));
        assert!(relue_conforme(&REG_SZ, &valeur(n, REG_EXPAND_SZ), n));
        assert!(relue_conforme(&REG_EXPAND_SZ, &valeur(n, REG_EXPAND_SZ), n));
        assert!(!relue_conforme(&REG_EXPAND_SZ, &valeur(n, REG_SZ), n));
        assert!(!relue_conforme(&REG_SZ, &valeur(r#""C:\A B\autre.exe""#, REG_SZ), n));
        assert!(!relue_conforme(&REG_SZ, &valeur(n, REG_BINARY), n));
        let p = r#""%X%\A B\svc.exe""#;
        assert!(!relue_conforme(&REG_SZ, &valeur(p, REG_EXPAND_SZ), p));
    }

    /// La seconde garde d'`entre_guillemets` : un jugement sans dossier piège n'écrit rien, même sans raison d'être à
    /// la main ; le bilan ne donne pas de commande à une ligne sans dossier, même « SVC ».
    #[test]
    fn sans_dossier_piege_rien_d_ecrit() {
        let v = |n: &str| (n == "X").then(|| r"C:\A B".to_string());
        let j = |dossier: Option<&str>| Signale {
            exe: r"C:\A B\svc.exe".into(),
            suite: String::new(),
            dossier: dossier.map(std::path::PathBuf::from),
            a_la_main: None,
        };
        assert_eq!(
            guillemets_du_jugement(&j(Some(r"C:\")), r"C:\A B\svc.exe", v).as_deref(),
            Some(r#""C:\A B\svc.exe""#)
        );
        assert_eq!(guillemets_du_jugement(&j(None), r"C:\A B\svc.exe", v), None);
        let c = juger("SVC|Outil|C:\\A B\\svc.exe||\nSVC_FIN\n").unwrap();
        let k = c.correctif.unwrap();
        assert!(k.commandes.is_empty() && !k.automatique, "{}", k.action);
    }

    /// Un programme qui cite une variable inconnue, sans guillemets, avec un espace : signalé « à vérifier à la main »
    /// sans dossier piège (son vrai chemin est inconnu), jamais écrit ; le bilan le dit honnêtement.
    #[test]
    fn variable_inconnue_signalee_sans_dossier_piege() {
        let variable = |n: &str| n.eq_ignore_ascii_case("SystemRoot").then(|| r"C:\Windows".to_string());
        let ferme = |_: &std::path::Path| false;
        let brut = r"%NEXISTEPASVG%\Mon Outil\svc.exe -k";
        let j = juger_service(0x10, brut, variable, |_| true, ferme).unwrap();
        assert!(j.dossier.is_none(), "{j:?}");
        assert!(
            j.a_la_main
                .as_deref()
                .is_some_and(|r| r.contains("%NEXISTEPASVG%")
                    && (r.contains("ne sait pas où") || r.contains("does not know where"))),
            "{j:?}"
        );
        assert_eq!(entre_guillemets(0x10, brut, variable, |_| true, ferme), None);
        // Entre guillemets ou un pilote : rien à piéger, pas signalé. Sans espace : rien de visible, pas signalé non
        // plus (pourquoi : voir `juger_service`).
        assert!(juger_service(0x10, r"%NEXISTEPASVG%\svc.exe -k", variable, |_| true, ferme).is_none());
        assert!(juger_service(0x10, r#""%NEXISTEPASVG%\Mon Outil\svc.exe""#, variable, |_| true, ferme).is_none());
        assert!(juger_service(0x1, brut, variable, |_| true, ferme).is_none());
        // La ligne du bilan : SVCM au dossier vide ; signalé, sans commande, à la main.
        let c = juger("SVCM|vg-essai-var|%NEXISTEPASVG%\\Mon Outil\\svc.exe||\nSVC_FIN\n").unwrap();
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(
            c.message.contains("vg-essai-var")
                && (c.message.contains("ne sait pas où") || c.message.contains("does not know where")),
            "{}",
            c.message
        );
        let k = c.correctif.unwrap();
        assert_eq!(
            k.commandes,
            [gestes::ligne_service_guillemets_risque("vg-essai-var").unwrap()]
        );
        assert!(k.action.contains("vg-essai-var"), "{}", k.action);
        // Même cas en « SVC » (pas à la main) : sans dossier, toujours à la main, aucune ligne.
        let c = juger("SVC|vg-essai-var|%NEXISTEPASVG%\\Mon Outil\\svc.exe||\nSVC_FIN\n").unwrap();
        let k = c.correctif.unwrap();
        assert!(
            k.commandes.is_empty() && !k.automatique && k.action.contains("vg-essai-var"),
            "{}",
            k.action
        );
        // Avec un service piégé : élevé, les deux dits, chacun sa ligne (la risquée pour celui à la main).
        let c = juger("SVCM|vg-essai-var|%X%\\A B\\svc.exe||\nSVC|Autre|C:\\A B\\y.exe|C:\\A B|\nSVC_FIN\n").unwrap();
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(
            c.message.contains("Autre (C:\\A B)") && c.message.contains("vg-essai-var"),
            "{}",
            c.message
        );
        let k = c.correctif.unwrap();
        assert_eq!(
            k.commandes,
            [
                gestes::ligne_service_guillemets_risque("vg-essai-var").unwrap(),
                gestes::ligne_service_guillemets("Autre").unwrap()
            ]
        );
        assert!(k.action.contains("vg-essai-var"), "{}", k.action);
    }

    /// Ce que le compte pose dans HKCU\Environment arrive dans l'environnement de ses processus, dont le processus
    /// élevé : relancé avec les variables calculées et une variable inventée forgées, Vanguard ne s'en sert pas.
    /// Sous Wine, SystemRoot et ProgramFiles sont remis d'aplomb par Wine : seule la variable inventée y prouve
    /// quelque chose (la preuve de fond reste `aucune_variable_lue_dans_le_processus`).
    #[test]
    fn environnement_du_compte_sans_effet() {
        const PIEGE: &str = r"C:\vg-piege";
        // Sans danger pour le démarrage de l'enfant.
        const SURES: [&str; 6] = [
            "ProgramFiles",
            "CommonProgramFiles",
            "ProgramData",
            "ALLUSERSPROFILE",
            "PUBLIC",
            "NEXISTEPASVG",
        ];
        // Un SystemRoot forgé peut empêcher un programme de démarrer sur un vrai Windows (DLL qui ne s'initialise
        // pas, 0xc0000142) : essayé d'abord, puis sans lui si l'enfant n'a pas démarré.
        const SYSTEME: [&str; 2] = ["SystemRoot", "windir"];
        if std::env::var_os("VANGUARD_ESSAI_ENV_FORGE").is_some() {
            if std::env::var("NEXISTEPASVG").as_deref() == Ok(PIEGE) {
                println!("environnement forgé reçu");
            }
            for n in SURES.iter().chain(&SYSTEME).filter(|n| **n != "NEXISTEPASVG") {
                assert_ne!(variable_systeme(n).as_deref(), Some(PIEGE), "{n}");
            }
            assert_eq!(variable_systeme("NEXISTEPASVG"), None);
            return;
        }
        let relancer = |forgees: &[&str]| {
            let mut c = std::process::Command::new(std::env::current_exe().unwrap());
            c.args([
                "--exact",
                "machine::windows::services::tests::environnement_du_compte_sans_effet",
                "--nocapture",
            ])
            .env("VANGUARD_ESSAI_ENV_FORGE", "1");
            for n in forgees {
                c.env(n, PIEGE);
            }
            let sortie = c.output().unwrap();
            (
                sortie.status.success(),
                String::from_utf8_lossy(&sortie.stdout).into_owned(),
            )
        };
        let toutes: Vec<&str> = SURES.iter().chain(&SYSTEME).copied().collect();
        let (mut reussi, mut texte) = relancer(&toutes);
        // L'enfant n'a pas atteint le premier test : il n'a pas démarré avec ce SystemRoot. Le reste est vérifié.
        let sans_systeme = !texte.contains("running 1 test");
        if sans_systeme {
            (reussi, texte) = relancer(&SURES);
        }
        // Le test relancé a bien tourné (un filtre qui ne trouverait rien réussirait aussi).
        assert!(reussi && texte.contains("1 passed"), "{texte}");
        if !texte.contains("environnement forgé reçu") {
            return crate::essais::saute("environnement forgé perdu dans le processus relancé");
        }
        if sans_systeme {
            crate::essais::saute("l'enfant ne démarre pas avec un SystemRoot forgé : vérifié sans lui");
        }
    }

    /// Aucune lecture de l'environnement de ce processus hors des tests : l'enfant élevé hérite de celui du compte.
    /// Les dossiers viennent d'`environnement.rs` (`dossiers`, `dossier_windows`), lu aussi.
    #[test]
    fn aucune_variable_lue_dans_le_processus() {
        for (nom, source) in [
            ("services.rs", include_str!("services.rs")),
            ("environnement.rs", include_str!("environnement.rs")),
        ] {
            // Le module des tests seulement : environnement.rs a d'autres éléments sous `cfg(test)` avant lui.
            let code = source.split("\n#[cfg(test)]\nmod tests {").next().unwrap();
            assert!(code.len() < source.len(), "{nom} : module des tests introuvable");
            for interdit in [
                "env::var",
                "env::vars",
                "ExpandEnvironmentStrings",
                "GetEnvironmentVariable",
            ] {
                assert!(!code.contains(interdit), "{nom} : {interdit}");
            }
        }
    }

    /// Les guillemets risqués (défense D6b) : seulement pour un service à la main, autour du programme brut, et si la
    /// valeur développée ne change que par eux ; un jugement sans raison d'être à la main passe par l'autre chemin.
    #[test]
    fn guillemets_risques_seulement_a_la_main_et_exacts() {
        let variable = |n: &str| n.eq_ignore_ascii_case("SystemRoot").then(|| r"C:\Windows".to_string());
        let ouvert = |d: &std::path::Path| d == std::path::Path::new(r"C:\");
        let absent = |_: &std::path::Path| false;
        // Programme introuvable : entre guillemets, rien d'autre.
        let brut = r"C:\Program Files\Autre Outil\svc.exe -k x";
        let j = juger_service(0x10, brut, variable, absent, ouvert).unwrap();
        assert!(j.a_la_main.is_some(), "{j:?}");
        assert_eq!(
            guillemets_risques_du_jugement(&j, brut, variable).as_deref(),
            Some(r#""C:\Program Files\Autre Outil\svc.exe" -k x"#)
        );
        // La variable connue reste telle quelle dans le brut.
        let brut = r"%SystemRoot%\Mon Outil\svc.exe";
        if let Some(j) = juger_service(0x10, brut, variable, absent, ouvert) {
            assert_eq!(
                guillemets_risques_du_jugement(&j, brut, variable).as_deref(),
                Some(r#""%SystemRoot%\Mon Outil\svc.exe""#)
            );
        }
        // Sans raison d'être à la main : jamais par ici.
        let j = Signale {
            exe: r"C:\A B\svc.exe".into(),
            suite: String::new(),
            dossier: Some(std::path::PathBuf::from(r"C:\")),
            a_la_main: None,
        };
        assert_eq!(guillemets_risques_du_jugement(&j, r"C:\A B\svc.exe", variable), None);
        // Un jugement qui ne correspond pas au brut (le programme développé serait un autre) : rien.
        let j = Signale {
            exe: r"C:\Autre\svc.exe".into(),
            suite: String::new(),
            dossier: None,
            a_la_main: Some("x".into()),
        };
        assert_eq!(guillemets_risques_du_jugement(&j, r"C:\A B\svc.exe", variable), None);
        // Déjà entre guillemets : rien.
        let j = Signale {
            exe: r"C:\A B\svc.exe".into(),
            suite: String::new(),
            dossier: None,
            a_la_main: Some("x".into()),
        };
        assert_eq!(
            guillemets_risques_du_jugement(&j, r#""C:\A B\svc.exe""#, variable),
            None
        );
        assert_eq!(
            guillemets_risques_du_jugement(&j, r"C:\A B\svc.exe", variable).as_deref(),
            Some(r#""C:\A B\svc.exe""#)
        );
    }
}

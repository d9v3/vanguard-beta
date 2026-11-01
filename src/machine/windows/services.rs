//! Services au chemin sans guillemets : « C:\Program Files\Mon Outil\svc.exe », sans guillemets, Windows essaie
//! d'abord « C:\Program.exe », puis « C:\Program Files\Mon.exe ». Un programme posé là démarre avec les droits du
//! service, souvent ceux du système. Signalé seulement si un de ces dossiers est modifiable par tous les comptes :
//! sans cela, le défaut n'est pas exploitable (C:\ et Program Files ne le sont pas).

use super::super::{Constat, alerte};
use super::corrections::{Resultat, avant_notable};
use super::ps;
use crate::machine::gestes::{self, NomFichier};
use crate::risk::Niveau;
use crate::ui::{affichable, resume, tr, trf};

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
            lignes.push(format!("{sorte}|{nom}|{}|{}|{}", j.exe, j.dossier.display(), j.suite));
        }
    }
    lignes.push("SVC_FIN".into());
    Some(lignes.join("\n"))
}

/// Service dans son propre processus (0x10) ou partagé (0x20) : les pilotes (1, 2) n'en sont pas.
const SERVICE_WIN32: u32 = 0x30;

/// Une variable de l'environnement du système, celui avec lequel le gestionnaire des services développe ImagePath :
/// SystemRoot et windir demandés à Windows (GetSystemWindowsDirectoryW), les autres lues dans Session
/// Manager\Environment, que seul un administrateur écrit. Jamais l'environnement de ce processus : le processus élevé
/// hérite de celui du compte qui l'élève (HKCU\Environment, `set` avant de lancer Vanguard). Une valeur qui cite une
/// autre variable que SystemRoot ou windir est inconnue.
fn variable_systeme(nom: &str) -> Option<String> {
    let windows = || {
        super::environnement::dossier_windows()
            .and_then(|p| p.to_str().map(|t| t.trim_end_matches('\\').to_string()))
            .filter(|t| !t.is_empty())
    };
    let racine = |n: &str| n.eq_ignore_ascii_case("SystemRoot") || n.eq_ignore_ascii_case("windir");
    if racine(nom) {
        return windows();
    }
    let brute: String = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(ENVIRONNEMENT_SYSTEME)
        .ok()?
        .get_value(nom)
        .ok()?;
    developper_tout(&brute, |n| if racine(n) { windows() } else { None })
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

/// Un service signalé : le programme et les arguments développés, le dossier piège, et la raison de le laisser à la
/// main quand Vanguard ne doit pas l'écrire.
#[derive(Debug)]
struct Signale {
    exe: String,
    suite: String,
    dossier: std::path::PathBuf,
    a_la_main: Option<String>,
}

/// Le jugement d'un service, LE MÊME pour le bilan (`lire_natif`) et pour le processus élevé qui pose les guillemets
/// (`entre_guillemets`) : un service Win32 dont le chemin (ImagePath brut, variables développées) n'a pas de
/// guillemets et dont un dossier piège est modifiable. Une variable que l'environnement du système ne connaît pas, ou
/// un programme qui n'existe pas, le laisse à la main : Vanguard ne sait pas ce que Windows lancerait.
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
    let (exe, suite) = programme_sans_guillemets(&chemin)?;
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
        dossier,
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
    if j.a_la_main.is_some() {
        return None;
    }
    let (brut_exe, brut_suite) = programme_et_suite(brut)?;
    let nouveau = format!("\"{brut_exe}\"{brut_suite}");
    (developper(&nouveau, &variable) == format!("\"{}\"{}", j.exe, j.suite)).then_some(nouveau)
}

/// Met entre guillemets le chemin du service `nom` (processus élevé) : ImagePath relu, rejugé par `juger_service`,
/// écrit avec le même type (REG_SZ ou REG_EXPAND_SZ) puis relu. Déjà entre guillemets : rien d'écrit. La valeur
/// d'avant est notée.
pub(super) fn poser_guillemets(nom: &NomFichier) -> Resultat {
    use std::io::ErrorKind::NotFound;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE};
    let chemin = format!(r"{}\{}", crate::machine::windows::CLE_SERVICES, nom.texte());
    let cle = match winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(&chemin, KEY_QUERY_VALUE | KEY_SET_VALUE)
    {
        Ok(c) => c,
        Err(e) if e.kind() == NotFound => {
            return Resultat::rien(
                tr!(
                    "service absent : rien à corriger ici, rien d'écrit",
                    "no such service: nothing to fix here, nothing written"
                )
                .to_string(),
            );
        }
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
    let octets: Vec<u8> = nouveau.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect();
    let valeur = winreg::RegValue {
        bytes: octets.into(),
        vtype: brute.vtype.clone(),
    };
    if let Err(e) = cle.set_raw_value("ImagePath", &valeur) {
        return Resultat::echec(Some(avant), e.to_string());
    }
    match cle.get_raw_value("ImagePath") {
        Ok(relue)
            if relue.vtype == brute.vtype
                && super::corrections::texte_reg(&relue).as_deref() == Some(nouveau.as_str()) =>
        {
            Resultat::fait(avant)
        }
        Ok(relue) => Resultat::echec(
            Some(avant),
            trf!(
                "relu {} au lieu de {}",
                "read back {} instead of {}",
                super::corrections::decrire(&relue),
                avant_notable(&nouveau)
            ),
        ),
        Err(e) => Resultat::echec(Some(avant), e.to_string()),
    }
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
    let mut commandes = Vec::new();
    let mut automatiques = Vec::new();
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
        // Un nom de service peut avoir des espaces et des parenthèses (« Bonjour Service », « Intel(R) … ») : écarté,
        // le service exploitable passait pour sain. Il est toujours signalé ; un nom que la grammaire des lignes
        // refuse (séparateur, caractère de contrôle, « .. ») n'a pas de ligne : à corriger à la main.
        noms.push(format!("{} ({})", affichable(nom), affichable(dossier)));
        match gestes::ligne_service_guillemets(nom).filter(|_| !manuel) {
            Some(l) => {
                commandes.push(l);
                automatiques.push(affichable(nom));
            }
            None => a_la_main.push(affichable(nom)),
        }
    }
    if noms.is_empty() {
        return None;
    }
    let constat = alerte(
        "Persistance",
        Niveau::Eleve,
        trf!(
            "Service au chemin sans guillemets, dans un dossier modifiable par tous : {}. Un programme posé là démarrerait avec les droits du système.",
            "Service with an unquoted path, in a folder anyone can change: {}. A program dropped there would start with system rights.",
            resume(&noms, 3, ", ")
        ),
    );
    // Une correction automatique : dite telle quelle, service par service.
    let action = trf!(
        "Vanguard ajoute les guillemets au chemin du service {} ; signaler ensuite le défaut à l'éditeur du programme",
        "Vanguard adds the quotes to the path of the service {}; then report the flaw to the program's publisher",
        resume(&automatiques, 3, ", ")
    );
    if commandes.is_empty() {
        return Some(constat.manuel(
            trf!(
                "Mettre à la main, dans regedit, le chemin (ImagePath) du service entre guillemets : {}",
                "In regedit, put the service's path (ImagePath) in quotes by hand: {}",
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
        let c = juger("SVCM|Outil|C:\\Mon Outil\\svc.exe|C:\\Mon Outil|\nSVC_FIN\n").unwrap();
        let k = c.correctif.unwrap();
        assert!(
            k.commandes.is_empty() && !k.automatique && k.action.contains("Outil"),
            "{}",
            k.action
        );
        // Un service à la main parmi d'autres : seul l'autre a sa ligne.
        let c = juger("SVCM|Outil|C:\\A B\\x.exe|C:\\A B|\nSVC|Autre|C:\\A B\\y.exe|C:\\A B|\nSVC_FIN\n").unwrap();
        let k = c.correctif.unwrap();
        assert_eq!(k.commandes, [gestes::ligne_service_guillemets("Autre").unwrap()]);
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

    /// Le vrai environnement du système (Wine ici, la VM ensuite) : SystemRoot vient de Windows, pas de ce processus.
    #[test]
    fn environnement_du_systeme() {
        let Some(racine) = variable_systeme("SystemRoot") else {
            return crate::essais::saute("dossier de Windows illisible");
        };
        assert_eq!(variable_systeme("windir").as_deref(), Some(racine.as_str()));
        assert!(!racine.ends_with('\\') && racine.len() > 2, "{racine}");
        assert_eq!(variable_systeme("VanguardInexistante"), None);
    }
}

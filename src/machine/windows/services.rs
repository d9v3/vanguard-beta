//! Services au chemin sans guillemets : « C:\Program Files\Mon Outil\svc.exe », sans guillemets, Windows essaie
//! d'abord « C:\Program.exe », puis « C:\Program Files\Mon.exe ». Un programme posé là démarre avec les droits du
//! service, souvent ceux du système. Signalé seulement si un de ces dossiers est modifiable par tous les comptes :
//! sans cela, le défaut n'est pas exploitable (C:\ et Program Files ne le sont pas).

use super::super::{Constat, alerte};
use super::ps;
use crate::commande::ps_chaine;
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
    // Service dans son propre processus (0x10) ou partagé (0x20) : les pilotes (1, 2) n'en sont pas.
    const SERVICE_WIN32: u32 = 0x30;
    let services = winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(crate::machine::windows::CLE_SERVICES)
        .ok()?;
    let mut lignes = Vec::new();
    for nom in services.enum_keys().flatten() {
        let Ok(cle) = services.open_subkey(&nom) else { continue };
        if cle.get_value::<u32, _>("Type").unwrap_or(0) & SERVICE_WIN32 == 0 {
            continue;
        }
        let Ok(chemin) = cle.get_value::<String, _>("ImagePath") else {
            continue;
        };
        let chemin = developper(&chemin, |v| std::env::var(v).ok());
        let Some((exe, suite)) = programme_sans_guillemets(&chemin) else {
            continue;
        };
        if let Some(d) = dossier_piege(exe, |d| {
            d.is_dir() && super::securite::du_fichier(d).is_some_and(|o| modifiable_par_tous(&o))
        }) {
            lignes.push(format!("SVC|{nom}|{exe}|{}|{suite}", d.display()));
        }
    }
    lignes.push("SVC_FIN".into());
    Some(lignes.join("\n"))
}

/// « %SystemRoot%\x » développé ; une variable inconnue reste telle quelle.
fn developper(texte: &str, variable: impl Fn(&str) -> Option<String>) -> String {
    let mut sortie = String::new();
    let mut reste = texte;
    while let Some(debut) = reste.find('%') {
        let apres = &reste[debut + 1..];
        let Some(fin) = apres.find('%') else { break };
        sortie.push_str(&reste[..debut]);
        match variable(&apres[..fin]).filter(|_| fin > 0) {
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
    if ligne.is_empty() || ligne.starts_with('"') {
        return None;
    }
    let bas = ligne.to_ascii_lowercase();
    let fin = bas
        .match_indices(".exe")
        .map(|(i, _)| i + 4)
        .find(|&f| f > 4 && ligne[f..].chars().next().is_none_or(char::is_whitespace))?;
    let (exe, suite) = ligne.split_at(fin);
    exe.contains(' ').then_some((exe, suite))
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

/// Les services exploitables lus dans la sortie du script, avec la commande qui met leur chemin entre guillemets.
/// `None` sans service à signaler, ou si la liste n'a pas été lue jusqu'au bout.
pub(super) fn juger(sortie: &str) -> Option<Constat> {
    if !sortie.lines().any(|l| l.trim() == "SVC_FIN") {
        return None;
    }
    let mut noms = Vec::new();
    let mut commandes = Vec::new();
    for ligne in sortie
        .lines()
        .filter_map(|l| l.trim_end_matches('\r').strip_prefix("SVC|"))
    {
        let mut champs = ligne.splitn(4, '|');
        // Arguments en dernier : « -f a|b » reste entier, et la commande de correction ne
        // perd rien de la ligne du service.
        let (Some(nom), Some(programme), Some(dossier), Some(arguments)) =
            (champs.next(), champs.next(), champs.next(), champs.next())
        else {
            continue;
        };
        if nom.is_empty() {
            continue;
        }
        // Un nom de service peut avoir des espaces et des parenthèses (« Bonjour Service », « Intel(R) … ») : écarté,
        // le service exploitable passait pour sain. Il est toujours signalé ; seule la commande est retenue quand le
        // nom changerait le chemin du registre (séparateur ou caractère de contrôle). Entre apostrophes doublées,
        // le reste ne peut rien injecter.
        noms.push(format!("{} ({})", affichable(nom), affichable(dossier)));
        if nom.chars().any(|c| c == '\\' || c == '/' || c.is_control()) {
            continue;
        }
        let chemin = format!(r"HKLM:\SYSTEM\CurrentControlSet\Services\{nom}");
        let valeur = format!("\"{programme}\"{arguments}");
        commandes.push(format!(
            "Set-ItemProperty -LiteralPath {} -Name ImagePath -Value {}",
            ps_chaine(&chemin),
            ps_chaine(&valeur)
        ));
    }
    if noms.is_empty() {
        return None;
    }
    let commandes: Vec<&str> = commandes.iter().map(String::as_str).collect();
    Some(
        alerte(
            "Persistance",
            Niveau::Eleve,
            trf!(
                "Service au chemin sans guillemets, dans un dossier modifiable par tous : {}. Un programme posé là démarrerait avec les droits du système.",
                "Service with an unquoted path, in a folder anyone can change: {}. A program dropped there would start with system rights.",
                resume(&noms, 3, ", ")
            ),
        )
        .manuel(
            tr!(
                "Mettre le chemin du service entre guillemets (commande ci-dessous, en administrateur), puis signaler le défaut à l'éditeur du programme",
                "Put the service's path in quotes (command below, as administrator), then report the flaw to the program's publisher"
            ),
            &commandes,
        ),
    )
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
        assert!(!k.automatique);
        assert_eq!(
            k.commandes,
            [
                "Set-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\OutilMaj' -Name ImagePath -Value '\"C:\\Mes Outils\\Outil Maj\\maj.exe\" -service'",
                "Set-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\pi;ege' -Name ImagePath -Value '\"C:\\A B\\x.exe\"'"
            ]
        );
        // Espaces, parenthèses et apostrophe dans le nom : signalé, la commande garde le nom entre apostrophes
        // doublées. Un nom qui changerait le chemin du registre est signalé sans commande.
        let c = juger(
            "SVC|Bonjour Service|C:\\Program Files\\Bonjour\\mDNSResponder.exe|C:\\Program Files|\nSVC|Intel(R) l'outil|C:\\A B\\x.exe|C:\\A B|\nSVC|a/b|C:\\A B\\y.exe|C:\\A B|\nSVC_FIN\n",
        )
        .unwrap();
        assert!(c.message.contains("Bonjour Service (C:\\Program Files)"));
        assert!(c.message.contains("Intel(R) l'outil") && c.message.contains("a/b"));
        let k = c.correctif.unwrap();
        assert_eq!(k.commandes.len(), 2);
        assert!(k.commandes[0].starts_with(
            "Set-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Bonjour Service' -Name ImagePath"
        ));
        assert!(k.commandes[1].contains("Services\\Intel(R) l''outil' -Name"));
    }

    /// Des arguments qui contiennent « | » : le dossier reste juste et la commande garde
    /// toute la ligne du service.
    #[test]
    fn arguments_avec_barre() {
        let c = juger("SVC|Outil|C:\\Mon Outil\\svc.exe|C:\\Mon Outil| -f a|b\nSVC_FIN\n").unwrap();
        assert!(c.message.contains("Outil (C:\\Mon Outil)"), "{}", c.message);
        assert_eq!(
            c.correctif.unwrap().commandes,
            [
                "Set-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Outil' -Name ImagePath -Value '\"C:\\Mon Outil\\svc.exe\" -f a|b'"
            ]
        );
    }
}

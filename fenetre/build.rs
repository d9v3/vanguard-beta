//! Pour Windows seulement : le manifeste de vanguard-fenetre.exe et les options de l'éditeur de liens, comme pour
//! vanguard.exe (build.rs de la racine), sans nouvelle dépendance (ni winresource ni ce qu'il amène) : un fichier .rc
//! d'une ligne, compilé par windres de MinGW (tests, clippy, outils/verifier.sh) ou par zig rc quand cargo-zigbuild
//! compile (programmes publiés, outils/compiler-version.sh). `vanguard deploiement verifier-binaire --attendu windows`
//! relit le résultat dans le .exe.

use std::path::{Path, PathBuf};
use std::process::Command;

/// asInvoker : la fenêtre ne demande jamais les droits d'administrateur. Page de code UTF-8 : les accents des
/// chemins et des messages restent justes. Le même texte que pour vanguard.exe.
const MANIFESTE: &str = r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security>
  </trustInfo>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings><activeCodePage xmlns="http://schemas.microsoft.com/SMI/2019/WindowsSettings">UTF-8</activeCodePage></windowsSettings>
  </application>
</assembly>
"#;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let zig = par_zig();
    if let Err(e) = manifeste(zig) {
        // Le programme livré doit porter son manifeste : en version publiée (et toujours sous zig), son absence
        // arrête la compilation au lieu d'un avertissement que personne ne lit. Les tests et clippy s'en passent.
        if zig || std::env::var("PROFILE").as_deref() == Ok("release") {
            println!("cargo:warning=manifeste de vanguard-fenetre.exe non intégré : {e}");
            std::process::exit(1);
        }
        println!("cargo:warning=manifeste de vanguard-fenetre.exe non intégré : {e}");
    }
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu") {
        // Sans l'heure de la compilation dans l'en-tête PE : un même code donne le même .exe. lld (zig) : -Brepro.
        println!(
            "cargo:rustc-link-arg={}",
            if zig {
                "-Wl,-Brepro"
            } else {
                "-Wl,--no-insert-timestamp"
            }
        );
        // La garde contre une DLL posée à côté du programme (src/chargement.rs) n'est référencée par aucun code :
        // exigée ici, elle reste, et son absence fait échouer l'édition des liens au lieu de passer en silence.
        println!(
            "cargo:rustc-link-arg-bins={}",
            if zig {
                "-Wl,-u,_load_config_used"
            } else {
                "-Wl,--require-defined=_load_config_used"
            }
        );
        // 8 Mio de pile pour le fil principal, réservés et non engagés, comme vanguard.exe et comme sous Linux.
        println!("cargo:rustc-link-arg-bins=-Wl,--stack,8388608");
    }
}

/// Vrai quand cargo-zigbuild compile cette cible (il pose CARGO_ZIGBUILD_TARGET_<cible>).
fn par_zig() -> bool {
    std::env::var("TARGET")
        .map(|cible| format!("CARGO_ZIGBUILD_TARGET_{}", cible.replace('-', "_")))
        .inspect(|nom| println!("cargo:rerun-if-env-changed={nom}"))
        .is_ok_and(|nom| std::env::var_os(nom).is_some())
}

/// Le manifeste en ressource RT_MANIFEST (24) n° 1, celui du processus, dans un objet COFF lié au programme.
fn manifeste(zig: bool) -> Result<(), String> {
    let sortie = PathBuf::from(std::env::var("OUT_DIR").map_err(|e| format!("OUT_DIR : {e}"))?);
    let fichier = sortie.join("vanguard-fenetre.manifest");
    let rc = sortie.join("ressources.rc");
    let objet = sortie.join("ressources.o");
    std::fs::write(&fichier, MANIFESTE).map_err(|e| format!("{} : {e}", fichier.display()))?;
    // Le nom du fichier seul, cherché dans le dossier du .rc : aucun chemin de la machine dans le programme.
    std::fs::write(&rc, "1 24 \"vanguard-fenetre.manifest\"\n").map_err(|e| format!("{} : {e}", rc.display()))?;
    let etat = if zig {
        zig_rc(&sortie, &rc, &objet)?
    } else {
        Command::new("x86_64-w64-mingw32-windres")
            .current_dir(&sortie)
            .args(["--input-format=rc", "--output-format=coff", "-I"])
            .arg(&sortie)
            .arg("-i")
            .arg(&rc)
            .arg("-o")
            .arg(&objet)
            .status()
            .map_err(|e| format!("x86_64-w64-mingw32-windres : {e}"))?
    };
    if !etat.success() {
        return Err(format!("compilateur de ressources : {etat}"));
    }
    println!("cargo:rustc-link-arg-bins={}", objet.display());
    Ok(())
}

/// zig rc, celui posé et vérifié par outils/chaine-zig.sh, donné par son chemin (jamais un zig pris dans le PATH) ;
/// sans dossier d'inclusion du système, comme pour vanguard.exe.
fn zig_rc(sortie: &Path, rc: &Path, objet: &Path) -> Result<std::process::ExitStatus, String> {
    println!("cargo:rerun-if-env-changed=CARGO_ZIGBUILD_ZIG_PATH");
    let zig = std::env::var_os("CARGO_ZIGBUILD_ZIG_PATH")
        .map(PathBuf::from)
        .filter(|chemin| chemin.is_absolute() && chemin.is_file())
        .ok_or("CARGO_ZIGBUILD_ZIG_PATH absente ou pas un chemin complet vers zig")?;
    Command::new(zig)
        .current_dir(sortie)
        .args([
            "rc",
            "/x",
            "/:auto-includes",
            "none",
            "/:target",
            "x64",
            "/:output-format",
            "coff",
            "/c",
            "65001",
        ])
        .arg("/i")
        .arg(sortie)
        .arg("/fo")
        .arg(objet)
        .arg("--")
        .arg(rc)
        .status()
        .map_err(|e| format!("zig rc : {e}"))
}

//! `vanguard deploiement verifier-binaire` : les protections qu'un programme livré doit porter, relues dans ses
//! en-têtes avant qu'il parte, jamais en le lançant. Le format se reconnaît aux premiers octets :
//! - Linux (ELF, `analyse::elf`) : PIE (ET_DYN et DF_1_PIE), statique (sans PT_INTERP), la marque du RELRO complet
//!   (PT_GNU_RELRO et BIND_NOW, sous l'une de ses trois formes : le démarrage de musl ne l'applique pas, Vanguard le
//!   fait lui-même au lancement, `socle::relro`), pile non exécutable (PT_GNU_STACK sans PF_X), aucun PT_LOAD à la
//!   fois écrivable et exécutable ; CET (IBT, SHSTK) affiché seulement ;
//! - Windows (PE, `crate::pe`) : ce que vérifiait `verifier-pe` (DLL importées depuis System32 seulement, manifeste
//!   UTF-8 et asInvoker), plus ASLR (DYNAMIC_BASE, et HIGH_ENTROPY_VA en 64 bits), DEP (NX_COMPAT) et des
//!   relocalisations présentes et pas retirées (sans elles, Windows ne déplace pas l'image, bit ou non) ; CFG et CET
//!   affichés seulement ;
//! - Mac (Mach-O universel, `analyse::macho`) : les deux tranches (arm64, x86_64), chacune lue et vérifiée : MH_EXECUTE,
//!   MH_PIE, sans MH_ALLOW_STACK_EXECUTION, __PAGEZERO sans droits, aucun segment écrivable et exécutable, et la
//!   signature (LC_CODE_SIGNATURE) que macOS exige sur arm64.
//!
//! Un seul refus par fichier, qui nomme chaque protection manquante et le champ lu. Ce qui ne se lit pas est refusé :
//! ce qui n'est pas vérifié ne part pas.

use std::io::Read;
use std::path::Path;

use crate::analyse::{elf, macho};
use crate::pe;
use crate::ui::*;

/// Au-delà, ce n'est pas un programme de Vanguard : lu en entier en mémoire, le fichier est borné.
const TAILLE_MAX: u64 = 512 << 20;

/// Une protection exigée, nommée sans dépendre de la langue (les essais la reconnaissent ainsi).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Protection {
    // ELF
    Pie,
    Statique,
    Relro,
    LiaisonImmediate,
    PileNonExecutable,
    SansEcrivableExecutable,
    SectionDynamique,
    Segments,
    // PE
    System32,
    Manifeste,
    Aslr,
    AslrHauteEntropie,
    Dep,
    Relocalisations,
    // Mach-O
    Universel,
    Tranche,
    Executable,
    PageZero,
    Signature,
    Commandes,
}

/// Une protection manquante, et ce qu'en dit le fichier, dans la langue de l'interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Manque {
    pub protection: Protection,
    pub texte: String,
}

/// Ce que la lecture d'un programme a trouvé : un résumé de ce qu'il porte, ses manques, et ce qui est affiché sans
/// être exigé (CFG, CET).
#[derive(Debug, Default)]
pub(super) struct Jugement {
    pub resume: String,
    pub manques: Vec<Manque>,
    pub infos: Vec<String>,
}

impl Jugement {
    fn manque(&mut self, protection: Protection, texte: String) {
        self.manques.push(Manque { protection, texte });
    }
}

/// Vérifie chaque fichier et le dit, une ligne par fichier. `true` si tous portent leurs protections.
pub(super) fn verifier(fichiers: &[std::path::PathBuf]) -> bool {
    let mut tous = true;
    for fichier in fichiers {
        tous &= verifier_un(fichier);
    }
    tous
}

fn verifier_un(fichier: &Path) -> bool {
    let f = fichier.display();
    match juger(fichier) {
        Err(pourquoi) => {
            eprintln!(
                "{}",
                trf!(
                    "✖ {f} illisible ({pourquoi}) : ne pas le livrer",
                    "✖ {f} unreadable ({pourquoi}): do not ship it"
                )
            );
            false
        }
        Ok(j) if !j.manques.is_empty() => {
            let manques: Vec<&str> = j.manques.iter().map(|m| m.texte.as_str()).collect();
            let manques = manques.join(" ; ");
            eprintln!(
                "{}",
                trf!(
                    "✖ {f} : {manques} ; ne pas le livrer",
                    "✖ {f}: {manques}; do not ship it"
                )
            );
            false
        }
        Ok(j) => {
            let infos = j.infos.join(", ");
            println!("{}", trf!("✔ {f} : {} ; {infos}", "✔ {f}: {}; {infos}", j.resume));
            true
        }
    }
}

/// Pourquoi un fichier n'a pas été jugé : il est refusé, jamais compté comme vérifié.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Illisible {
    /// Le fichier ne s'ouvre ou ne se lit pas (absent, interdit…).
    Ouverture(std::io::ErrorKind),
    /// Pas un fichier ordinaire (dossier, tube nommé).
    PasUnFichier,
    /// Plus grand que TAILLE_MAX.
    TropGrand,
    /// Commence comme un ELF, mais ses en-têtes ne se lisent pas.
    Elf,
    /// Commence comme un PE, mais ses en-têtes ne se lisent pas.
    Pe,
    /// Ni ELF, ni PE, ni Mach-O.
    Inconnu,
}

impl std::fmt::Display for Illisible {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ouverture(k) => write!(f, "{}", std::io::Error::from(*k)),
            Self::PasUnFichier => f.write_str(tr!("pas un fichier ordinaire", "not a regular file")),
            Self::TropGrand => f.write_str(&trf!("plus de {TAILLE_MAX} octets", "more than {TAILLE_MAX} bytes")),
            Self::Elf => f.write_str(tr!("pas un ELF lisible", "not a readable ELF")),
            Self::Pe => f.write_str(tr!(
                "pas un programme Windows lisible",
                "not a readable Windows program"
            )),
            Self::Inconnu => f.write_str(tr!(
                "format inconnu : ni ELF, ni PE, ni Mach-O",
                "unknown format: neither ELF, PE nor Mach-O"
            )),
        }
    }
}

/// Le jugement du fichier `fichier`, lu une seule fois (le format et les protections viennent des mêmes octets).
pub(super) fn juger(fichier: &Path) -> Result<Jugement, Illisible> {
    let octets = lire(fichier)?;
    if octets.starts_with(b"\x7fELF") {
        let e = elf::lire(&octets).ok_or(Illisible::Elf)?;
        Ok(juger_elf(&e))
    } else if octets.starts_with(b"MZ") {
        let g = pe::lire_gardes(
            &mut std::io::Cursor::new(&octets),
            crate::analyse::lecture::en_u64(octets.len()),
        )
        .ok_or(Illisible::Pe)?;
        Ok(juger_pe(&g))
    } else if let Some(u) = macho::universel(&octets) {
        Ok(juger_universel(&octets, &u))
    } else if macho::lire(&octets).is_some() {
        let mut j = Jugement::default();
        j.manque(
            Protection::Universel,
            tr!(
                "Mach-O d'une seule architecture, universel attendu (arm64 et x86_64)",
                "single-architecture Mach-O, universal expected (arm64 and x86_64)"
            )
            .to_string(),
        );
        Ok(j)
    } else {
        Err(Illisible::Inconnu)
    }
}

/// Les octets du fichier ordinaire `fichier`, au plus TAILLE_MAX.
fn lire(fichier: &Path) -> Result<Vec<u8>, Illisible> {
    let (f, taille) = pe::ouvrir(fichier).map_err(|e| match e {
        pe::Echec::Ouverture(k) => Illisible::Ouverture(k),
        pe::Echec::PasUnFichier | pe::Echec::Format => Illisible::PasUnFichier,
    })?;
    if taille > TAILLE_MAX {
        return Err(Illisible::TropGrand);
    }
    let mut octets = Vec::new();
    f.take(TAILLE_MAX.saturating_add(1))
        .read_to_end(&mut octets)
        .map_err(|e| Illisible::Ouverture(e.kind()))?;
    // Le fichier a pu grandir entre sa taille et sa lecture.
    if crate::analyse::lecture::en_u64(octets.len()) > TAILLE_MAX {
        return Err(Illisible::TropGrand);
    }
    Ok(octets)
}

/// Une valeur lue, ou « absent » sans son entrée.
fn hexa(valeur: Option<u64>) -> String {
    valeur.map_or_else(|| tr!("absent", "missing").to_string(), |v| format!("0x{v:X}"))
}

fn oui_non(b: bool) -> &'static str {
    if b { tr!("oui", "yes") } else { tr!("non", "no") }
}

/// Un programme Linux : celui de Vanguard est un static-pie de musl.
fn juger_elf(e: &elf::Elf) -> Jugement {
    let mut j = Jugement {
        resume: tr!(
            "ELF static-pie, marque RELRO (BIND_NOW, appliqué par Vanguard au démarrage), pile non exécutable, aucun segment \
             écrivable et exécutable",
            "ELF static-pie, RELRO marking (BIND_NOW, applied by Vanguard at startup), non-executable stack, no writable \
             and executable segment"
        )
        .to_string(),
        ..Jugement::default()
    };
    if e.segments_illisibles {
        j.manque(
            Protection::Segments,
            tr!("table des segments illisible", "unreadable segment table").to_string(),
        );
    }
    if e.dynamique_illisible {
        j.manque(
            Protection::SectionDynamique,
            tr!(
                "section dynamique illisible (PT_DYNAMIC double, hors du fichier ou sans DT_NULL)",
                "unreadable dynamic section (PT_DYNAMIC twice, outside the file or without DT_NULL)"
            )
            .to_string(),
        );
    }
    let d = e.dynamique.unwrap_or_default();
    if e.type_ != elf::ET_DYN || !d.pie() {
        let (t, f1) = (e.type_, hexa(d.drapeaux_1));
        j.manque(
            Protection::Pie,
            trf!(
                "PIE absent (e_type {t}, DT_FLAGS_1 {f1})",
                "PIE missing (e_type {t}, DT_FLAGS_1 {f1})"
            ),
        );
    }
    if let Some(i) = &e.interpreteur {
        j.manque(
            Protection::Statique,
            trf!(
                "pas statique : interpréteur demandé (PT_INTERP {i})",
                "not static: interpreter requested (PT_INTERP {i})"
            ),
        );
    }
    if !e.relro {
        j.manque(
            Protection::Relro,
            tr!("RELRO absent (pas de PT_GNU_RELRO)", "RELRO missing (no PT_GNU_RELRO)").to_string(),
        );
    }
    if !d.liaison_immediate() {
        let (f, f1) = (hexa(d.drapeaux), hexa(d.drapeaux_1));
        j.manque(
            Protection::LiaisonImmediate,
            trf!(
                "BIND_NOW absent, RELRO partiel (DT_FLAGS {f}, DT_FLAGS_1 {f1}, sans DT_BIND_NOW)",
                "BIND_NOW missing, partial RELRO (DT_FLAGS {f}, DT_FLAGS_1 {f1}, no DT_BIND_NOW)"
            ),
        );
    }
    match e.pile_executable {
        Some(false) => {}
        Some(true) => j.manque(
            Protection::PileNonExecutable,
            tr!(
                "pile exécutable (PT_GNU_STACK avec PF_X)",
                "executable stack (PT_GNU_STACK with PF_X)"
            )
            .to_string(),
        ),
        None => j.manque(
            Protection::PileNonExecutable,
            tr!(
                "pile peut-être exécutable (PT_GNU_STACK absent)",
                "stack possibly executable (PT_GNU_STACK missing)"
            )
            .to_string(),
        ),
    }
    for s in e
        .segments
        .iter()
        .filter(|s| s.type_ == elf::PT_LOAD && s.ecrivable() && s.executable())
    {
        let a = s.adresse;
        j.manque(
            Protection::SansEcrivableExecutable,
            trf!(
                "segment écrivable et exécutable (PT_LOAD à 0x{a:X})",
                "writable and executable segment (PT_LOAD at 0x{a:X})"
            ),
        );
    }
    j.infos.push(match e.cet {
        Some(c) => trf!(
            "CET : IBT {}, SHSTK {} (affiché seulement)",
            "CET: IBT {}, SHSTK {} (shown only)",
            oui_non(c & elf::CET_IBT != 0),
            oui_non(c & elf::CET_SHSTK != 0)
        ),
        None => tr!("CET absent (affiché seulement)", "CET missing (shown only)").to_string(),
    });
    j
}

/// Un programme Windows : ses gardes d'avant (System32, manifeste) et son durcissement.
fn juger_pe(g: &pe::Gardes) -> Jugement {
    let mut j = Jugement {
        resume: tr!(
            "DLL importées depuis System32 seulement, manifeste UTF-8 et asInvoker, ASLR à haute entropie, DEP, relocalisations",
            "imported DLLs from System32 only, UTF-8 and asInvoker manifest, high-entropy ASLR, DEP, relocations"
        )
        .to_string(),
        ..Jugement::default()
    };
    gardes_pe(g, &mut j);
    let d = g.durcissement;
    let dll = d.dll_caracteristiques;
    if !d.a(pe::DYNAMIC_BASE) {
        j.manque(
            Protection::Aslr,
            trf!(
                "ASLR absent (DllCharacteristics 0x{dll:04X}, sans DYNAMIC_BASE)",
                "ASLR missing (DllCharacteristics 0x{dll:04X}, no DYNAMIC_BASE)"
            ),
        );
    }
    if d.pe32_plus && !d.a(pe::HIGH_ENTROPY_VA) {
        j.manque(
            Protection::AslrHauteEntropie,
            trf!(
                "ASLR à haute entropie absent (DllCharacteristics 0x{dll:04X}, sans HIGH_ENTROPY_VA)",
                "high-entropy ASLR missing (DllCharacteristics 0x{dll:04X}, no HIGH_ENTROPY_VA)"
            ),
        );
    }
    if !d.a(pe::NX_COMPAT) {
        j.manque(
            Protection::Dep,
            trf!(
                "DEP absent (DllCharacteristics 0x{dll:04X}, sans NX_COMPAT)",
                "DEP missing (DllCharacteristics 0x{dll:04X}, no NX_COMPAT)"
            ),
        );
    }
    if !d.relocalisable() {
        let (c, lu) = (d.caracteristiques, oui_non(d.relocalisations));
        j.manque(
            Protection::Relocalisations,
            trf!(
                "relocalisations absentes ou retirées, Windows ne peut pas déplacer l'image (répertoire n° 5 lisible : {lu}, Characteristics 0x{c:04X})",
                "relocations missing or stripped, Windows cannot move the image (directory 5 readable: {lu}, Characteristics 0x{c:04X})"
            ),
        );
    }
    j.infos.push(trf!(
        "CFG {}, CET {} (affichés seulement)",
        "CFG {}, CET {} (shown only)",
        if d.a(pe::GUARD_CF) {
            tr!("présent", "present")
        } else {
            tr!("absent", "missing")
        },
        if d.cet {
            tr!("présent", "present")
        } else {
            tr!("absent", "missing")
        }
    ));
    j
}

/// Les gardes que vérifiait `verifier-pe` : DependentLoadFlags (`machine::windows::chargement`), qui ferme le
/// chargement d'une DLL posée à côté du programme, et son manifeste.
fn gardes_pe(g: &pe::Gardes, j: &mut Jugement) {
    if !g.load_config.is_some_and(|c| c.system32_seulement()) {
        let config = match g.load_config {
            None => tr!("absent", "missing").to_string(),
            Some(c) => trf!(
                "tailles {} et {}, drapeaux 0x{:X}",
                "sizes {} and {}, flags 0x{:X}",
                c.taille_repertoire,
                c.taille,
                c.drapeaux
            ),
        };
        j.manque(
            Protection::System32,
            trf!(
                "DLL importées pas limitées à System32 (Load Config : {config})",
                "imported DLLs not limited to System32 (Load Config: {config})"
            ),
        );
    }
    // Un seul niveau demandé, asInvoker (Vanguard démarre sans droits d'administrateur), et la page de code UTF-8
    // (sans elle, accents et chemins sont cassés dans la console et les fichiers), rien d'autre.
    let lu = g.manifeste.as_deref().and_then(super::lire_manifeste);
    let mut manquants = Vec::new();
    match &lu {
        None => manquants.push(tr!("absent ou malformé", "missing or malformed").to_string()),
        Some((niveaux, pages)) => {
            if !matches!(niveaux.as_slice(), [seul] if seul == "asInvoker") {
                manquants.push(trf!(
                    "requestedExecutionLevel : {niveaux:?} au lieu d'un seul asInvoker",
                    "requestedExecutionLevel: {niveaux:?} instead of a single asInvoker"
                ));
            }
            if pages.is_empty() || pages.iter().any(|p| p != "UTF-8") {
                manquants.push(trf!(
                    "activeCodePage : {pages:?} au lieu de UTF-8",
                    "activeCodePage: {pages:?} instead of UTF-8"
                ));
            }
        }
    }
    if !manquants.is_empty() {
        let manquants = manquants.join(", ");
        j.manque(
            Protection::Manifeste,
            trf!(
                "manifeste absent ou incomplet ({manquants})",
                "manifest missing or incomplete ({manquants})"
            ),
        );
    }
}

/// Le nom d'une architecture Mac.
fn architecture(cpu: u32) -> String {
    match cpu {
        macho::CPU_ARM64 => "arm64".to_string(),
        macho::CPU_X86_64 => "x86_64".to_string(),
        autre => format!("cpu 0x{autre:X}"),
    }
}

/// Un programme Mac universel : les deux architectures attendues, chaque tranche lue et vérifiée. Ne vérifier que la
/// première laisserait passer l'autre.
fn juger_universel(octets: &[u8], u: &macho::Universel) -> Jugement {
    let mut j = Jugement {
        resume: tr!(
            "Mach-O universel (arm64, x86_64) : MH_EXECUTE, PIE, pile non exécutable, __PAGEZERO, aucun segment écrivable et exécutable, arm64 signé",
            "universal Mach-O (arm64, x86_64): MH_EXECUTE, PIE, non-executable stack, __PAGEZERO, no writable and executable segment, arm64 signed"
        )
        .to_string(),
        ..Jugement::default()
    };
    for attendue in [macho::CPU_ARM64, macho::CPU_X86_64] {
        if !u.tranches.iter().any(|t| t.cpu == attendue) {
            let a = architecture(attendue);
            j.manque(
                Protection::Universel,
                trf!("tranche {a} manquante", "{a} slice missing"),
            );
        }
    }
    if u.tranches_hors_fichier > 0 {
        let n = u.tranches_hors_fichier;
        j.manque(
            Protection::Tranche,
            trf!(
                "{n} tranche(s) hors du fichier, non vérifiée(s)",
                "{n} slice(s) outside the file, not checked"
            ),
        );
    }
    for t in &u.tranches {
        let a = architecture(t.cpu);
        let tranche = usize::try_from(t.position)
            .ok()
            .zip(usize::try_from(t.taille).ok())
            .and_then(|(p, n)| octets.get(p..p.checked_add(n)?))
            .and_then(macho::lire);
        match tranche {
            None => j.manque(
                Protection::Tranche,
                trf!("tranche {a} illisible", "{a} slice unreadable"),
            ),
            Some(m) if m.cpu != t.cpu => {
                let lue = architecture(m.cpu);
                j.manque(
                    Protection::Tranche,
                    trf!(
                        "tranche annoncée {a}, lue {lue}",
                        "slice announced as {a}, read as {lue}"
                    ),
                );
            }
            Some(m) => juger_tranche(&a, &m, &mut j),
        }
    }
    j.infos.push(
        tr!(
            "chaque tranche lue par le programme Linux, pas par le Mac lui-même",
            "each slice read by the Linux program, not by the Mac one itself"
        )
        .to_string(),
    );
    j
}

/// Une tranche d'un programme Mac.
fn juger_tranche(a: &str, m: &macho::MachO, j: &mut Jugement) {
    if m.commandes_illisibles {
        j.manque(
            Protection::Commandes,
            trf!(
                "{a} : commandes de chargement illisibles",
                "{a}: unreadable load commands"
            ),
        );
    }
    if m.type_fichier != macho::MH_EXECUTE {
        let t = m.type_fichier;
        j.manque(
            Protection::Executable,
            trf!(
                "{a} : pas un exécutable (filetype {t})",
                "{a}: not an executable (filetype {t})"
            ),
        );
    }
    let flags = m.drapeaux;
    if flags & macho::MH_PIE == 0 {
        j.manque(
            Protection::Pie,
            trf!(
                "{a} : PIE absent (flags 0x{flags:08X})",
                "{a}: PIE missing (flags 0x{flags:08X})"
            ),
        );
    }
    if flags & macho::MH_ALLOW_STACK_EXECUTION != 0 {
        j.manque(
            Protection::PileNonExecutable,
            trf!(
                "{a} : pile exécutable (MH_ALLOW_STACK_EXECUTION, flags 0x{flags:08X})",
                "{a}: executable stack (MH_ALLOW_STACK_EXECUTION, flags 0x{flags:08X})"
            ),
        );
    }
    if !m
        .segments
        .iter()
        .any(|s| s.nom == "__PAGEZERO" && s.adresse == 0 && s.maxprot == 0 && s.initprot == 0)
    {
        j.manque(
            Protection::PageZero,
            trf!(
                "{a} : __PAGEZERO absent ou accessible",
                "{a}: __PAGEZERO missing or accessible"
            ),
        );
    }
    for s in m.segments.iter().filter(|s| s.ecrivable_executable()) {
        let nom = &s.nom;
        j.manque(
            Protection::SansEcrivableExecutable,
            trf!(
                "{a} : segment écrivable et exécutable ({nom})",
                "{a}: writable and executable segment ({nom})"
            ),
        );
    }
    if m.cpu == macho::CPU_ARM64 && !m.signature {
        j.manque(
            Protection::Signature,
            trf!(
                "{a} : signature absente (LC_CODE_SIGNATURE, exigée par macOS sur arm64)",
                "{a}: signature missing (LC_CODE_SIGNATURE, required by macOS on arm64)"
            ),
        );
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyse::elf::essais::{Durci, elf64, elf64_durci};
    use crate::analyse::macho::essais::{MacDurci, macho64, macho64_durci, universel_de};
    use crate::pe::essais::{Retrait, gardes_d_essai, sans_protection};

    /// Une protection retirée des réglages d'un binaire fabriqué, et celle que le refus doit nommer.
    type Retire<T> = (fn(&mut T), Protection);

    const MANIFESTE: &[u8] =
        br#"<assembly><requestedExecutionLevel level="asInvoker"/><activeCodePage>UTF-8</activeCodePage></assembly>"#;

    fn dossier() -> std::path::PathBuf {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Le jugement des `octets`, écrits dans un fichier.
    fn jugement(d: &Path, octets: &[u8]) -> Jugement {
        let f = d.join("programme");
        std::fs::write(&f, octets).unwrap();
        juger(&f).unwrap()
    }

    /// Les protections manquantes des `octets`.
    fn manques(d: &Path, octets: &[u8]) -> Vec<Protection> {
        jugement(d, octets).manques.iter().map(|m| m.protection).collect()
    }

    fn pe_durci() -> Vec<u8> {
        gardes_d_essai(Some((148, 148, 0x800)), Some(MANIFESTE), 1)
    }

    fn mac(arm: MacDurci, x86: MacDurci) -> Vec<u8> {
        universel_de(&[
            (macho::CPU_ARM64, macho64_durci(macho::CPU_ARM64, arm)),
            (macho::CPU_X86_64, macho64_durci(macho::CPU_X86_64, x86)),
        ])
    }

    #[test]
    fn elf_chaque_protection_retiree_est_refusee() {
        let d = dossier();
        assert_eq!(manques(&d, &elf64_durci(Durci::COMPLET)), []);
        let retraits: [Retire<Durci>; 5] = [
            (|x| x.pie = false, Protection::Pie),
            (|x| x.relro = false, Protection::Relro),
            (|x| x.liaison_immediate = false, Protection::LiaisonImmediate),
            (|x| x.pile_non_executable = false, Protection::PileNonExecutable),
            (|x| x.statique = false, Protection::Statique),
        ];
        for (retirer, protection) in retraits {
            let mut durci = Durci::COMPLET;
            retirer(&mut durci);
            assert_eq!(manques(&d, &elf64_durci(durci)), [protection]);
        }
        // CET n'est qu'affiché.
        let mut avec_cet = Durci::COMPLET;
        avec_cet.cet = true;
        let j = jugement(&d, &elf64_durci(avec_cet));
        assert!(
            j.manques.is_empty() && j.infos[0].contains("IBT oui, SHSTK oui"),
            "{:?}",
            j.infos
        );
        assert!(jugement(&d, &elf64_durci(Durci::COMPLET)).infos[0].contains("CET absent"));
        // ET_DYN sans DF_1_PIE : une bibliothèque, pas un exécutable PIE.
        let mut v = elf64_durci(Durci::COMPLET);
        v[0x198..0x1A0].copy_from_slice(&elf::DF_1_NOW.to_le_bytes());
        assert_eq!(manques(&d, &v), [Protection::Pie]);
        // PT_GNU_STACK absent (devenu PT_NULL) : la pile n'est pas dite non exécutable.
        let mut v = elf64_durci(Durci::COMPLET);
        v[0x40 + 112..0x40 + 116].fill(0);
        assert_eq!(manques(&d, &v), [Protection::PileNonExecutable]);
        // Un PT_LOAD écrivable et exécutable.
        let mut v = elf64_durci(Durci::COMPLET);
        v[0x40 + 4] = 7;
        assert_eq!(manques(&d, &v), [Protection::SansEcrivableExecutable]);
        // Section dynamique sans DT_NULL : illisible, et donc ni PIE ni BIND_NOW lus.
        let mut v = elf64_durci(Durci::COMPLET);
        v[0x1A0..0x1B0].fill(0xAA);
        v[0x40 + 56 + 32..0x40 + 56 + 40].copy_from_slice(&0x28u64.to_le_bytes());
        let m = manques(&d, &v);
        assert!(
            m.contains(&Protection::SectionDynamique) && m.contains(&Protection::Pie),
            "{m:?}"
        );
        // Un vieil ELF d'essai (ET_EXEC, interpréteur, sans section dynamique ni RELRO) : tout manque.
        let m = manques(&d, &elf64(5, false, 0x40_0180, b""));
        for p in [
            Protection::Pie,
            Protection::Statique,
            Protection::Relro,
            Protection::LiaisonImmediate,
        ] {
            assert!(m.contains(&p), "{p:?} {m:?}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn pe_chaque_protection_retiree_est_refusee() {
        let d = dossier();
        let j = jugement(&d, &pe_durci());
        assert!(j.manques.is_empty(), "{:?}", j.manques);
        assert_eq!(j.infos, ["CFG absent, CET absent (affichés seulement)"]);
        for (retrait, protection) in [
            (Retrait::DynamicBase, Protection::Aslr),
            (Retrait::HighEntropyVa, Protection::AslrHauteEntropie),
            (Retrait::NxCompat, Protection::Dep),
            (Retrait::Relocalisations, Protection::Relocalisations),
            (Retrait::RelocsStripped, Protection::Relocalisations),
        ] {
            let mut v = pe_durci();
            sans_protection(&mut v, retrait);
            assert_eq!(manques(&d, &v), [protection], "{retrait:?}");
        }
        // Les gardes d'avant restent exigées.
        assert_eq!(
            manques(&d, &gardes_d_essai(None, Some(MANIFESTE), 1)),
            [Protection::System32]
        );
        assert_eq!(
            manques(&d, &gardes_d_essai(Some((148, 148, 0x800)), None, 1)),
            [Protection::Manifeste]
        );
        // CFG présent : affiché, jamais exigé.
        let mut v = pe_durci();
        v[0x58 + 71] |= 0x40;
        let j = jugement(&d, &v);
        assert!(j.manques.is_empty() && j.infos[0].starts_with("CFG présent"));
        // Un PE32 n'a pas HIGH_ENTROPY_VA à porter : seul DYNAMIC_BASE et NX_COMPAT comptent.
        let mut j = Jugement::default();
        let gardes = pe::Gardes {
            load_config: None,
            manifeste: None,
            durcissement: pe::Durcissement {
                pe32_plus: false,
                caracteristiques: 0x102,
                dll_caracteristiques: 0x0140,
                relocalisations: true,
                cet: false,
            },
        };
        j.manques = juger_pe(&gardes).manques;
        assert!(!j.manques.iter().any(|m| m.protection == Protection::AslrHauteEntropie));
        // En-tête facultatif trop court pour DllCharacteristics et les répertoires : illisible, refusé.
        let mut v = pe_durci();
        v[0x54..0x56].copy_from_slice(&60u16.to_le_bytes());
        let court = d.join("court.exe");
        std::fs::write(&court, &v).unwrap();
        assert!(juger(&court).is_err() && !verifier(&[court]));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn mac_chaque_protection_retiree_est_refusee() {
        let d = dossier();
        let complet = MacDurci::COMPLET;
        assert_eq!(manques(&d, &mac(complet, complet)), []);
        let retraits: [Retire<MacDurci>; 6] = [
            (|x| x.pie = false, Protection::Pie),
            (|x| x.pile_non_executable = false, Protection::PileNonExecutable),
            (
                |x| x.sans_ecrivable_executable = false,
                Protection::SansEcrivableExecutable,
            ),
            (|x| x.page_zero = false, Protection::PageZero),
            (|x| x.signature = false, Protection::Signature),
            (|x| x.executable = false, Protection::Executable),
        ];
        for (retirer, protection) in retraits {
            let mut tranche = complet;
            retirer(&mut tranche);
            // Sur l'une ou l'autre tranche : vérifier la seule première laisserait passer la seconde.
            assert_eq!(
                manques(&d, &mac(tranche, complet)),
                [protection],
                "arm64 {protection:?}"
            );
            let attendu: &[Protection] = if protection == Protection::Signature {
                // La signature n'est exigée que sur arm64.
                &[]
            } else {
                &[protection]
            };
            assert_eq!(manques(&d, &mac(complet, tranche)), attendu, "x86_64 {protection:?}");
        }
        // Une seule architecture, dans un universel ou seule.
        let arm = macho64_durci(macho::CPU_ARM64, complet);
        assert_eq!(
            manques(&d, &universel_de(&[(macho::CPU_ARM64, arm.clone())])),
            [Protection::Universel]
        );
        assert_eq!(manques(&d, &arm), [Protection::Universel]);
        // Une tranche annoncée x86_64 qui est arm64, ou qui n'est pas un Mach-O.
        let faux = universel_de(&[(macho::CPU_ARM64, arm.clone()), (macho::CPU_X86_64, arm.clone())]);
        assert_eq!(manques(&d, &faux), [Protection::Tranche]);
        let illisible = universel_de(&[(macho::CPU_ARM64, arm), (macho::CPU_X86_64, vec![0u8; 0x400])]);
        assert_eq!(manques(&d, &illisible), [Protection::Tranche]);
        // L'ancien Mach-O d'essai (sans PIE ? si : MH_PIE posé ; sans __PAGEZERO ni signature) seul : pas universel.
        assert_eq!(manques(&d, &macho64(5, false)), [Protection::Universel]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn refus_dits_dans_les_deux_langues() {
        let d = dossier();
        let mut v = pe_durci();
        sans_protection(&mut v, Retrait::DynamicBase);
        let j = jugement(&d, &v);
        assert_eq!(
            j.manques[0].texte,
            "ASLR absent (DllCharacteristics 0x0120, sans DYNAMIC_BASE)"
        );
        let j = crate::langue::en_anglais(|| jugement(&d, &v));
        assert_eq!(
            j.manques[0].texte,
            "ASLR missing (DllCharacteristics 0x0120, no DYNAMIC_BASE)"
        );
        let mut durci = Durci::COMPLET;
        durci.liaison_immediate = false;
        let v = elf64_durci(durci);
        assert_eq!(
            jugement(&d, &v).manques[0].texte,
            "BIND_NOW absent, RELRO partiel (DT_FLAGS 0x0, DT_FLAGS_1 0x8000000, sans DT_BIND_NOW)"
        );
        assert_eq!(
            crate::langue::en_anglais(|| jugement(&d, &v)).manques[0].texte,
            "BIND_NOW missing, partial RELRO (DT_FLAGS 0x0, DT_FLAGS_1 0x8000000, no DT_BIND_NOW)"
        );
        let mut tranche = MacDurci::COMPLET;
        tranche.pie = false;
        let v = mac(MacDurci::COMPLET, tranche);
        assert_eq!(
            jugement(&d, &v).manques[0].texte,
            "x86_64 : PIE absent (flags 0x00000085)"
        );
        assert_eq!(
            crate::langue::en_anglais(|| jugement(&d, &v)).manques[0].texte,
            "x86_64: PIE missing (flags 0x00000085)"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Le programme des essais, compilé comme celui qu'on livre (static-pie de musl, mêmes options d'édition des
    /// liens) : il porte ses protections. Un réglage perdu dans .cargo/config.toml ou build.rs se voit ici.
    #[cfg(target_os = "linux")]
    #[test]
    fn le_programme_des_essais_est_durci() {
        let exe = std::env::current_exe().unwrap();
        let j = juger(&exe).unwrap();
        assert!(j.manques.is_empty(), "{}: {:?}", exe.display(), j.manques);
    }

    #[test]
    fn illisible_ou_inconnu_refuse() {
        let d = dossier();
        let f = d.join("texte");
        std::fs::write(&f, b"#!/bin/sh\necho bonjour\n").unwrap();
        assert_eq!(juger(&f).unwrap_err(), Illisible::Inconnu);
        assert_eq!(
            Illisible::Inconnu.to_string(),
            "format inconnu : ni ELF, ni PE, ni Mach-O"
        );
        std::fs::write(&f, b"MZ pas un programme").unwrap();
        assert_eq!(juger(&f).unwrap_err(), Illisible::Pe);
        std::fs::write(&f, b"\x7fELF").unwrap();
        assert_eq!(juger(&f).unwrap_err(), Illisible::Elf);
        assert_eq!(
            juger(&d.join("absent")).unwrap_err(),
            Illisible::Ouverture(std::io::ErrorKind::NotFound)
        );
        // Un dossier : refusé partout. Windows refuse déjà de l'ouvrir comme un fichier (accès refusé, sans
        // FILE_FLAG_BACKUP_SEMANTICS) ; ailleurs il s'ouvre et n'est pas un fichier ordinaire.
        let attendu = if cfg!(windows) {
            Illisible::Ouverture(std::io::ErrorKind::PermissionDenied)
        } else {
            Illisible::PasUnFichier
        };
        assert_eq!(juger(&d).unwrap_err(), attendu);
        // Plusieurs fichiers : un seul refusé suffit à refuser le tout, et chacun est jugé.
        let bon = d.join("vanguard.exe");
        std::fs::write(&bon, pe_durci()).unwrap();
        assert!(verifier(std::slice::from_ref(&bon)));
        assert!(!verifier(&[bon.clone(), d.join("absent")]));
        assert!(!verifier(&[d.join("absent"), bon]));
        let _ = std::fs::remove_dir_all(&d);
    }
}

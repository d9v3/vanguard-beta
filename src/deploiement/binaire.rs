//! `vanguard deploiement verifier-binaire` : les protections qu'un programme livré doit porter, relues dans ses
//! en-têtes avant qu'il parte, jamais en le lançant. Le format se reconnaît aux premiers octets :
//! - Linux (ELF, `analyse::elf`) : PIE (ET_DYN et DF_1_PIE), statique (sans PT_INTERP), la marque du RELRO complet
//!   (un seul PT_GNU_RELRO, dans un PT_LOAD écrivable et sur toute la section dynamique, et BIND_NOW, sous l'une de
//!   ses trois formes : le démarrage de musl ne l'applique pas, Vanguard le fait lui-même au lancement,
//!   `socle::relro`), pile non exécutable (PT_GNU_STACK sans PF_X), aucun PT_LOAD à la
//!   fois écrivable et exécutable ; CET (IBT, SHSTK) affiché seulement. Avec `--glibc` (la fenêtre de Vanguard,
//!   liée à la libc du système) : au lieu de « statique », un seul PT_INTERP, celui de la glibc x86-64, et ni
//!   DT_RPATH ni DT_RUNPATH ; le reste de même ;
//! - Windows (PE, `crate::pe`) : ce que vérifiait `verifier-pe` (DLL importées depuis System32 seulement, manifeste
//!   UTF-8 et asInvoker), plus ASLR (DYNAMIC_BASE, et en 64 bits HIGH_ENTROPY_VA avec LARGE_ADDRESS_AWARE, qu'il
//!   exige), DEP (NX_COMPAT) et des
//!   relocalisations présentes et pas retirées (sans elles, Windows ne déplace pas l'image, bit ou non) ; CFG et CET
//!   affichés seulement.
//!
//! Chaque programme doit aussi être d'une architecture qu'on livre (ELF 64 bits petit-boutiste x86-64, PE32+ AMD64)
//! et, avec `--attendu`, du système que le script annonce : un ELF posé à la place du .exe
//! porterait toutes ses protections, et ne démarrerait pas.
//!
//! Un seul refus par fichier, qui nomme chaque protection manquante et le champ lu. Ce qui ne se lit pas est refusé :
//! ce qui n'est pas vérifié ne part pas.

use std::io::Read;
use std::path::Path;

use super::Systeme;
use crate::analyse::elf;
use crate::pe;
use crate::ui::*;

/// Au-delà, ce n'est pas un programme de Vanguard : lu en entier en mémoire, le fichier est borné.
const TAILLE_MAX: u64 = 512 << 20;

/// Une protection exigée, nommée sans dépendre de la langue (les essais la reconnaissent ainsi).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Protection {
    /// Un format autre que celui attendu, ou une architecture qu'on ne livre pas : un programme qui ne démarrerait
    /// pas là où il part, quelles que soient ses protections.
    Architecture,
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

/// Vérifie chaque fichier et le dit, une ligne par fichier. `true` si tous portent leurs protections, et, avec
/// `attendu`, sont tous des programmes de ce système. `glibc` : voir `juger`.
pub(super) fn verifier(fichiers: &[std::path::PathBuf], attendu: Option<Systeme>, glibc: bool) -> bool {
    let mut tous = true;
    for fichier in fichiers {
        tous &= verifier_un(fichier, attendu, glibc);
    }
    tous
}

fn verifier_un(fichier: &Path, attendu: Option<Systeme>, glibc: bool) -> bool {
    let f = fichier.display();
    match juger(fichier, attendu, glibc) {
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
            let manques = manques.join(tr!(" ; ", "; "));
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
    /// Ni ELF, ni PE.
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
                "format inconnu : ni ELF, ni PE",
                "unknown format: neither ELF nor PE"
            )),
        }
    }
}

impl std::error::Error for Illisible {}

/// Le nom d'un système et de son format, dans la langue de l'interface.
fn nom_systeme(s: Systeme) -> &'static str {
    match s {
        Systeme::Linux => tr!("programme Linux (ELF)", "Linux program (ELF)"),
        Systeme::Windows => tr!("programme Windows (PE)", "Windows program (PE)"),
    }
}

/// Le jugement du fichier `fichier`, lu une seule fois (le format et les protections viennent des mêmes octets).
/// Avec `attendu`, un autre format est un manque, nommé en premier ; ses protections sont jugées quand même. Avec
/// `glibc` (la fenêtre de Vanguard, qui demande la libc du système pour ses bibliothèques d'affichage), un programme
/// Linux peut demander un interpréteur, mais seulement celui de la glibc x86-64 (`INTERPRETEUR_GLIBC`), et sans
/// dossier de bibliothèques écrit dans le programme (DT_RPATH, DT_RUNPATH) ; le reste est exigé de même.
pub(super) fn juger(fichier: &Path, attendu: Option<Systeme>, glibc: bool) -> Result<Jugement, Illisible> {
    let octets = lire(fichier)?;
    let (systeme, mut j) = if octets.starts_with(b"\x7fELF") {
        let e = elf::lire(&octets).ok_or(Illisible::Elf)?;
        (Systeme::Linux, juger_elf(&e, glibc))
    } else if octets.starts_with(b"MZ") {
        let g = pe::lire_gardes(
            &mut std::io::Cursor::new(&octets),
            crate::analyse::lecture::en_u64(octets.len()),
        )
        .ok_or(Illisible::Pe)?;
        (Systeme::Windows, juger_pe(&g))
    } else {
        return Err(Illisible::Inconnu);
    };
    if let Some(attendu) = attendu
        && attendu != systeme
    {
        let (lu, attendu) = (nom_systeme(systeme), nom_systeme(attendu));
        j.manques.insert(
            0,
            Manque {
                protection: Protection::Architecture,
                texte: trf!("{lu} au lieu d'un {attendu}", "{lu} instead of a {attendu}"),
            },
        );
    }
    Ok(j)
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

/// L'interpréteur de la glibc x86-64, le seul permis avec `glibc` : un chemin fixe de l'ABI, posé par le système.
const INTERPRETEUR_GLIBC: &str = "/lib64/ld-linux-x86-64.so.2";

/// Un programme Linux : celui de Vanguard est un static-pie de musl ; avec `glibc`, la fenêtre (voir `juger`).
fn juger_elf(e: &elf::Elf, glibc: bool) -> Jugement {
    let mut j = Jugement {
        resume: if glibc {
            trf!(
                "ELF PIE lié à la glibc (interpréteur {INTERPRETEUR_GLIBC}, sans RPATH ni RUNPATH), RELRO complet \
                 (BIND_NOW), pile non exécutable, aucun segment écrivable et exécutable",
                "ELF PIE linked to glibc (interpreter {INTERPRETEUR_GLIBC}, no RPATH or RUNPATH), full RELRO \
                 (BIND_NOW), non-executable stack, no writable and executable segment"
            )
        } else {
            tr!(
                "ELF static-pie, marque RELRO (BIND_NOW, appliqué par Vanguard au démarrage), pile non exécutable, aucun segment \
                 écrivable et exécutable",
                "ELF static-pie, RELRO marking (BIND_NOW, applied by Vanguard at startup), non-executable stack, no writable \
                 and executable segment"
            )
            .to_string()
        },
        ..Jugement::default()
    };
    if !e.bits64 || e.gros_boutiste || e.machine != elf::EM_X86_64 {
        let (bits, m) = (if e.bits64 { 64 } else { 32 }, e.machine);
        let ordre = if e.gros_boutiste {
            tr!("gros-boutiste", "big-endian")
        } else {
            tr!("petit-boutiste", "little-endian")
        };
        j.manque(
            Protection::Architecture,
            trf!(
                "architecture non livrée : ELF {bits} bits {ordre}, e_machine {m} ; x86-64 attendu (64 bits, petit-boutiste, e_machine 62)",
                "architecture not shipped: ELF {bits}-bit {ordre}, e_machine {m}; x86-64 expected (64-bit, little-endian, e_machine 62)"
            ),
        );
    }
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
    // Statique : sans segment PT_INTERP. La chaîne ne sert qu'au message : un PT_INTERP dont elle ne se lit pas
    // (hors du fichier) n'en demande pas moins un interpréteur au noyau. Avec `glibc` : un seul PT_INTERP, celui de
    // la glibc, lu tel quel (le noyau prend le premier ; un second, ou une chaîne illisible, est refusé).
    let interpretes = e.segments.iter().filter(|s| s.type_ == elf::PT_INTERP).count();
    if glibc {
        if interpretes != 1 || e.interpreteur.as_deref() != Some(INTERPRETEUR_GLIBC) {
            let i = e
                .interpreteur
                .clone()
                .unwrap_or_else(|| tr!("absent ou illisible", "missing or unreadable").to_string());
            j.manque(
                Protection::Statique,
                trf!(
                    "interpréteur autre que celui de la glibc ({interpretes} PT_INTERP, {i} ; {INTERPRETEUR_GLIBC} attendu)",
                    "interpreter other than glibc's ({interpretes} PT_INTERP, {i}; {INTERPRETEUR_GLIBC} expected)"
                ),
            );
        }
        if e.dynamique.is_some_and(|d| d.chemin_de_recherche) {
            j.manque(
                Protection::Statique,
                tr!(
                    "dossiers de bibliothèques écrits dans le programme (DT_RPATH ou DT_RUNPATH) : une bibliothèque posée là \
                     serait chargée avant celles du système",
                    "library folders written into the program (DT_RPATH or DT_RUNPATH): a library placed there would be \
                     loaded before the system's"
                )
                .to_string(),
            );
        }
    } else if interpretes > 0 {
        let i = e
            .interpreteur
            .clone()
            .unwrap_or_else(|| tr!("illisible", "unreadable").to_string());
        j.manque(
            Protection::Statique,
            trf!(
                "pas statique : interpréteur demandé (PT_INTERP {i})",
                "not static: interpreter requested (PT_INTERP {i})"
            ),
        );
    }
    // La marque doit aussi couvrir ce qu'il faut : vide, hors de tout PT_LOAD écrivable ou à côté de la section
    // dynamique, elle ne protège pas ce qu'elle annonce (relro.rs la prend telle quelle) ; à deux, on ne sait pas laquelle le démarrage prend (relro.rs : la première, glibc : la
    // dernière).
    let relros: Vec<&elf::Segment> = e.segments.iter().filter(|s| s.type_ == elf::PT_GNU_RELRO).collect();
    match relros.as_slice() {
        [] => j.manque(
            Protection::Relro,
            tr!("RELRO absent (pas de PT_GNU_RELRO)", "RELRO missing (no PT_GNU_RELRO)").to_string(),
        ),
        [seul] if !elf::dans_un_load_ecrivable(&e.segments, seul) => {
            let (adresse, taille) = (seul.adresse, seul.taille_memoire);
            j.manque(
                Protection::Relro,
                trf!(
                    "RELRO vide ou hors de tout PT_LOAD écrivable, rien n'y est protégé (PT_GNU_RELRO à 0x{adresse:X}, 0x{taille:X} octets)",
                    "RELRO empty or outside every writable PT_LOAD, nothing protected (PT_GNU_RELRO at 0x{adresse:X}, 0x{taille:X} bytes)"
                ),
            );
        }
        // `-z relro` y met toujours la section dynamique, et la .got juste après : une marque qui ne la couvre pas
        // protège autre chose que ce qu'elle annonce.
        [seul] => {
            for dynamique in e
                .segments
                .iter()
                .filter(|s| s.type_ == elf::PT_DYNAMIC && !elf::contient(seul, s))
            {
                let (adresse, taille) = (dynamique.adresse, dynamique.taille_memoire);
                let (debut, longueur) = (seul.adresse, seul.taille_memoire);
                j.manque(
                    Protection::Relro,
                    trf!(
                        "RELRO ne couvre pas la section dynamique, ni la .got qui la suit (PT_DYNAMIC à 0x{adresse:X}, 0x{taille:X} octets ; PT_GNU_RELRO à 0x{debut:X}, 0x{longueur:X} octets)",
                        "RELRO does not cover the dynamic section, nor the .got after it (PT_DYNAMIC at 0x{adresse:X}, 0x{taille:X} bytes; PT_GNU_RELRO at 0x{debut:X}, 0x{longueur:X} bytes)"
                    ),
                );
            }
        }
        plusieurs => {
            let n = plusieurs.len();
            j.manque(
                Protection::Relro,
                trf!(
                    "{n} PT_GNU_RELRO : on ne sait pas lequel est appliqué",
                    "{n} PT_GNU_RELRO: unknown which one is applied"
                ),
            );
        }
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
    let d = g.durcissement;
    if !d.pe32_plus || d.machine != pe::Machine::X64 {
        let forme = if d.pe32_plus { "PE32+" } else { "PE32" };
        let m = d.machine.champ();
        j.manque(
            Protection::Architecture,
            trf!(
                "architecture non livrée : {forme}, Machine 0x{m:04X} ; PE32+ AMD64 attendu (0x8664)",
                "architecture not shipped: {forme}, Machine 0x{m:04X}; PE32+ AMD64 expected (0x8664)"
            ),
        );
    }
    gardes_pe(g, &mut j);
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
    } else if d.pe32_plus && d.caracteristiques & pe::LARGE_ADDRESS_AWARE == 0 {
        // /HIGHENTROPYVA exige /LARGEADDRESSAWARE (documentation de l'éditeur de liens de Microsoft) : le drapeau
        // seul ne promet pas que l'image tienne à une adresse au-delà de 2 Gio, et l'entropie annoncée n'est pas due.
        let c = d.caracteristiques;
        j.manque(
            Protection::AslrHauteEntropie,
            trf!(
                "ASLR à haute entropie sans LARGE_ADDRESS_AWARE, qu'il exige (Characteristics 0x{c:04X})",
                "high-entropy ASLR without LARGE_ADDRESS_AWARE, which it requires (Characteristics 0x{c:04X})"
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

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    /// LANG-ERRWRAP : une erreur standard, avec un texte pour chaque variante.
    #[test]
    fn illisible_est_une_erreur_standard() {
        for e in [
            Illisible::PasUnFichier,
            Illisible::TropGrand,
            Illisible::Elf,
            Illisible::Pe,
            Illisible::Inconnu,
        ] {
            let e: &dyn std::error::Error = &e;
            assert_ne!(e.to_string(), "");
        }
    }
    use crate::analyse::elf::essais::{Durci, elf64, elf64_durci, entete};
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
        juger(&f, None, false).unwrap()
    }

    /// Les protections manquantes des `octets`.
    fn manques(d: &Path, octets: &[u8]) -> Vec<Protection> {
        jugement(d, octets).manques.iter().map(|m| m.protection).collect()
    }

    fn pe_durci() -> Vec<u8> {
        gardes_d_essai(Some((148, 148, 0x800)), Some(MANIFESTE), 1)
    }

    /// Un ELF durci qui demande l'interpréteur de la glibc, comme la fenêtre de Vanguard.
    fn elf_glibc() -> Vec<u8> {
        let mut durci = Durci::COMPLET;
        durci.statique = false;
        let mut v = elf64_durci(durci);
        let i = b"/lib64/ld-linux-x86-64.so.2\0";
        v[0x160..0x160 + i.len()].copy_from_slice(i);
        let longueur = (i.len() as u64).to_le_bytes();
        let n = usize::from(u16::from_le_bytes([v[56], v[57]]));
        for k in 0..n {
            let p = crate::analyse::elf::essais::ENTETES + 56 * k;
            if v[p..p + 4] == elf::PT_INTERP.to_le_bytes() {
                v[p + 32..p + 40].copy_from_slice(&longueur);
                v[p + 40..p + 48].copy_from_slice(&longueur);
            }
        }
        v
    }

    /// `--glibc` (la fenêtre) : l'interpréteur de la glibc exigé, lui seul, sans RPATH ni RUNPATH ; un static-pie
    /// n'est pas la fenêtre et se voit refusé ; sans l'option, le programme de la glibc reste refusé.
    #[test]
    fn glibc_seulement_avec_l_option_et_son_seul_interpreteur() {
        let d = dossier();
        let juge = |octets: &[u8], glibc| {
            let f = d.join("fenetre");
            std::fs::write(&f, octets).unwrap();
            juger(&f, Some(Systeme::Linux), glibc)
                .unwrap()
                .manques
                .iter()
                .map(|m| m.protection)
                .collect::<Vec<_>>()
        };
        assert_eq!(juge(&elf_glibc(), true), []);
        assert_eq!(juge(&elf_glibc(), false), [Protection::Statique]);
        // Un autre interpréteur (celui de musl), ou aucun : refusés avec --glibc.
        let mut musl = Durci::COMPLET;
        musl.statique = false;
        assert_eq!(juge(&elf64_durci(musl), true), [Protection::Statique]);
        assert_eq!(juge(&elf64_durci(Durci::COMPLET), true), [Protection::Statique]);
        // Un DT_RUNPATH (à la place de DT_FLAGS) : refusé avec --glibc, et BIND_NOW tient par DF_1_NOW.
        let mut v = elf_glibc();
        v[0x180..0x188].copy_from_slice(&29u64.to_le_bytes());
        assert_eq!(juge(&v, true), [Protection::Statique]);
        let f = d.join("fenetre");
        std::fs::write(&f, elf_glibc()).unwrap();
        assert!(verifier(std::slice::from_ref(&f), Some(Systeme::Linux), true));
        assert!(!verifier(std::slice::from_ref(&f), Some(Systeme::Linux), false));
        // Chaque autre protection retirée reste refusée avec --glibc.
        let mut sans_pie = Durci::COMPLET;
        sans_pie.statique = false;
        sans_pie.pie = false;
        assert!(juge(&elf64_durci(sans_pie), true).contains(&Protection::Pie));
        let _ = std::fs::remove_dir_all(&d);
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
        v[entete(2)..entete(2) + 4].fill(0);
        assert_eq!(manques(&d, &v), [Protection::PileNonExecutable]);
        // Un PT_LOAD écrivable et exécutable.
        let mut v = elf64_durci(Durci::COMPLET);
        v[entete(0) + 4] = 7;
        assert_eq!(manques(&d, &v), [Protection::SansEcrivableExecutable]);
        // Section dynamique sans DT_NULL : illisible, et donc ni PIE ni BIND_NOW lus.
        let mut v = elf64_durci(Durci::COMPLET);
        v[0x1A0..0x1B0].fill(0xAA);
        v[entete(1) + 32..entete(1) + 40].copy_from_slice(&0x28u64.to_le_bytes());
        let m = manques(&d, &v);
        assert!(
            m.contains(&Protection::SectionDynamique) && m.contains(&Protection::Pie),
            "{m:?}"
        );
        // Les en-têtes de programme d'elf64_durci (`entete`) : PT_LOAD du code, PT_DYNAMIC, PT_GNU_STACK,
        // PT_GNU_RELRO, puis PT_INTERP (s'il y est) et le PT_LOAD des données.
        // PT_GNU_RELRO vide, ou hors de tout PT_LOAD : la marque est là, mais rien n'y serait protégé.
        let mut v = elf64_durci(Durci::COMPLET);
        v[entete(3) + 40..entete(3) + 48].fill(0);
        let j = jugement(&d, &v);
        assert_eq!(
            j.manques.iter().map(|m| m.protection).collect::<Vec<_>>(),
            [Protection::Relro]
        );
        assert!(j.manques[0].texte.contains("0x0 octets"), "{:?}", j.manques);
        let mut v = elf64_durci(Durci::COMPLET);
        v[entete(3) + 16..entete(3) + 24].copy_from_slice(&0x10_0000u64.to_le_bytes());
        assert_eq!(manques(&d, &v), [Protection::Relro]);
        // Rétréci à 16 octets : dans le PT_LOAD des données, mais la section dynamique (et la .got qui la suit chez
        // un vrai éditeur de liens) reste écrivable.
        let mut v = elf64_durci(Durci::COMPLET);
        v[entete(3) + 32..entete(3) + 48].copy_from_slice(&[0x10, 0, 0, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 0, 0, 0, 0]);
        let j = jugement(&d, &v);
        assert_eq!(
            j.manques.iter().map(|m| m.protection).collect::<Vec<_>>(),
            [Protection::Relro]
        );
        assert!(j.manques[0].texte.contains("section dynamique"), "{:?}", j.manques);
        // Déplacé dans le PT_LOAD du code, déjà en lecture seule : le protéger ne change rien, les données restent
        // écrivables.
        let mut v = elf64_durci(Durci::COMPLET);
        v[entete(3) + 8..entete(3) + 16].copy_from_slice(&0x100u64.to_le_bytes());
        v[entete(3) + 16..entete(3) + 24].copy_from_slice(&0x100u64.to_le_bytes());
        let j = jugement(&d, &v);
        assert_eq!(
            j.manques.iter().map(|m| m.protection).collect::<Vec<_>>(),
            [Protection::Relro]
        );
        assert!(j.manques[0].texte.contains("écrivable"), "{:?}", j.manques);
        // Débordant de son PT_LOAD : pas dedans non plus.
        let mut v = elf64_durci(Durci::COMPLET);
        v[entete(3) + 40..entete(3) + 48].copy_from_slice(&0x81u64.to_le_bytes());
        assert_eq!(manques(&d, &v), [Protection::Relro]);
        // Deux PT_GNU_RELRO (la pile en devient un) : on ne sait pas lequel le démarrage protège.
        let mut v = elf64_durci(Durci::COMPLET);
        v[entete(2)..entete(2) + 4].copy_from_slice(&elf::PT_GNU_RELRO.to_le_bytes());
        let j = jugement(&d, &v);
        assert!(
            j.manques
                .iter()
                .any(|m| m.protection == Protection::Relro && m.texte.contains("2 PT_GNU_RELRO")),
            "{:?}",
            j.manques
        );
        // Un PT_INTERP dont la chaîne ne se lit pas (hors du fichier) : le chargeur, lui, en demanderait un. Statique
        // veut dire sans PT_INTERP, pas sans chaîne lisible.
        let mut v = elf64_durci(Durci {
            statique: false,
            ..Durci::COMPLET
        });
        v[entete(4) + 8..entete(4) + 16].copy_from_slice(&0xFFFF_0000u64.to_le_bytes());
        let j = jugement(&d, &v);
        assert_eq!(
            j.manques.iter().map(|m| m.protection).collect::<Vec<_>>(),
            [Protection::Statique]
        );
        assert!(j.manques[0].texte.contains("illisible"), "{:?}", j.manques);
        // PT_DYNAMIC lu à p_offset mais chargé ailleurs (p_vaddr à un autre décalage dans le PT_LOAD) : les octets lus ne
        // sont pas ceux que le démarrage trouve. Illisible, jamais cru.
        let mut v = elf64_durci(Durci::COMPLET);
        v[entete(1) + 16..entete(1) + 24].copy_from_slice(&0x100u64.to_le_bytes());
        assert!(manques(&d, &v).contains(&Protection::SectionDynamique));
        // Hors de tout PT_LOAD.
        let mut v = elf64_durci(Durci::COMPLET);
        v[entete(1) + 8..entete(1) + 16].copy_from_slice(&0x1_0180u64.to_le_bytes());
        v[entete(1) + 16..entete(1) + 24].copy_from_slice(&0x1_0180u64.to_le_bytes());
        assert!(manques(&d, &v).contains(&Protection::SectionDynamique));
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
            (Retrait::LargeAddressAware, Protection::AslrHauteEntropie),
        ] {
            let mut v = pe_durci();
            sans_protection(&mut v, retrait);
            assert_eq!(manques(&d, &v), [protection], "{retrait:?}");
        }
        let mut v = pe_durci();
        sans_protection(&mut v, Retrait::LargeAddressAware);
        let j = jugement(&d, &v);
        assert!(
            j.manques[0].texte.contains("sans LARGE_ADDRESS_AWARE") && j.manques[0].texte.contains("0x0002"),
            "{:?}",
            j.manques
        );
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
                machine: pe::Machine::X86,
                pe32_plus: false,
                caracteristiques: 0x102,
                dll_caracteristiques: 0x0140,
                relocalisations: true,
                cet: false,
            },
        };
        j.manques = juger_pe(&gardes).manques;
        assert!(!j.manques.iter().any(|m| m.protection == Protection::AslrHauteEntropie));
        // Mais un PE32 x86 n'est pas ce qu'on livre.
        assert_eq!(j.manques[0].protection, Protection::Architecture);
        assert_eq!(
            j.manques[0].texte,
            "architecture non livrée : PE32, Machine 0x014C ; PE32+ AMD64 attendu (0x8664)"
        );
        // En-tête facultatif trop court pour DllCharacteristics et les répertoires : illisible, refusé.
        let mut v = pe_durci();
        v[0x54..0x56].copy_from_slice(&60u16.to_le_bytes());
        let court = d.join("court.exe");
        std::fs::write(&court, &v).unwrap();
        assert!(juger(&court, None, false).is_err() && !verifier(&[court], None, false));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un programme d'une architecture qu'on ne livre pas, ou d'un autre système que celui attendu : refusé, même
    /// avec toutes ses protections.
    #[test]
    fn architecture_et_format_attendus() {
        use crate::analyse::elf::essais::{Forme, elf_durci};
        let d = dossier();
        let ecrire = |nom: &str, octets: &[u8]| {
            let f = d.join(nom);
            std::fs::write(&f, octets).unwrap();
            f
        };
        let protections = |f: &Path, attendu| -> Vec<Protection> {
            juger(f, attendu, false)
                .unwrap()
                .manques
                .iter()
                .map(|m| m.protection)
                .collect()
        };
        let linux = ecrire("vanguard", &elf64_durci(Durci::COMPLET));
        let windows = ecrire("vanguard.exe", &pe_durci());
        let systemes = [Systeme::Linux, Systeme::Windows];
        for (f, s) in [(&linux, Systeme::Linux), (&windows, Systeme::Windows)] {
            assert_eq!(protections(f, None), [], "{s:?}");
            assert_eq!(protections(f, Some(s)), [], "{s:?}");
            assert!(verifier(std::slice::from_ref(f), Some(s), false));
            // Tout autre système attendu : refusé, et seulement pour cela.
            for autre in systemes.into_iter().filter(|a| *a != s) {
                assert_eq!(
                    protections(f, Some(autre)),
                    [Protection::Architecture],
                    "{s:?} au lieu de {autre:?}"
                );
                assert!(!verifier(std::slice::from_ref(f), Some(autre), false));
            }
        }
        // Un ELF à la place du .exe, dit dans les deux langues.
        assert_eq!(
            juger(&linux, Some(Systeme::Windows), false).unwrap().manques[0].texte,
            "programme Linux (ELF) au lieu d'un programme Windows (PE)"
        );
        assert_eq!(
            crate::langue::en_anglais(|| juger(&linux, Some(Systeme::Windows), false))
                .unwrap()
                .manques[0]
                .texte,
            "Linux program (ELF) instead of a Windows program (PE)"
        );
        // ELF 32 bits (x86 ou x86-64 annoncé), aarch64, gros-boutiste : refusés même sans système attendu.
        let x = Forme::X86_64;
        for forme in [
            Forme { bits64: false, ..x },
            Forme {
                bits64: false,
                machine: 3,
                ..x
            },
            Forme { machine: 183, ..x },
            Forme {
                gros_boutiste: true,
                ..x
            },
        ] {
            let f = ecrire("autre", &elf_durci(Durci::COMPLET, forme));
            assert_eq!(protections(&f, None), [Protection::Architecture], "{forme:?}");
            assert_eq!(
                protections(&f, Some(Systeme::Linux)),
                [Protection::Architecture],
                "{forme:?}"
            );
        }
        let f = ecrire(
            "elf32",
            &elf_durci(
                Durci::COMPLET,
                Forme {
                    bits64: false,
                    machine: 3,
                    ..x
                },
            ),
        );
        assert_eq!(
            juger(&f, None, false).unwrap().manques[0].texte,
            "architecture non livrée : ELF 32 bits petit-boutiste, e_machine 3 ; x86-64 attendu (64 bits, petit-boutiste, e_machine 62)"
        );
        assert_eq!(
            crate::langue::en_anglais(|| juger(&f, None, false)).unwrap().manques[0].texte,
            "architecture not shipped: ELF 32-bit little-endian, e_machine 3; x86-64 expected (64-bit, little-endian, e_machine 62)"
        );
        // Un PE32+ d'une autre machine (x86, ARM64) : refusé.
        for machine in [0x014Cu16, 0xAA64, 0x01C4] {
            let mut v = pe_durci();
            v[0x44..0x46].copy_from_slice(&machine.to_le_bytes());
            let f = ecrire("autre.exe", &v);
            assert_eq!(protections(&f, None), [Protection::Architecture], "0x{machine:04X}");
            assert_eq!(protections(&f, Some(Systeme::Windows)), [Protection::Architecture]);
        }
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
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Le programme des essais, compilé comme celui qu'on livre (static-pie de musl, mêmes options d'édition des
    /// liens) : il porte ses protections. Un réglage perdu dans .cargo/config.toml ou build.rs se voit ici.
    /// Suppose la cible par défaut des essais, x86_64-unknown-linux-musl (.cargo/config.toml) : lancé avec
    /// `--target x86_64-unknown-linux-gnu`, il jugerait un autre programme (dynamique, chargé par glibc) que celui
    /// qu'on livre, et son verdict ne dirait rien du programme publié.
    #[cfg(target_os = "linux")]
    #[test]
    fn le_programme_des_essais_est_durci() {
        let exe = std::env::current_exe().unwrap();
        let j = juger(&exe, None, false).unwrap();
        assert!(j.manques.is_empty(), "{}: {:?}", exe.display(), j.manques);
    }

    #[test]
    fn illisible_ou_inconnu_refuse() {
        let d = dossier();
        let f = d.join("texte");
        std::fs::write(&f, b"#!/bin/sh\necho bonjour\n").unwrap();
        assert_eq!(juger(&f, None, false).unwrap_err(), Illisible::Inconnu);
        assert_eq!(Illisible::Inconnu.to_string(), "format inconnu : ni ELF, ni PE");
        // Un programme Mac (Mach-O universel) : Vanguard n'en livre plus, refusé comme inconnu.
        std::fs::write(&f, [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2]).unwrap();
        assert_eq!(juger(&f, None, false).unwrap_err(), Illisible::Inconnu);
        std::fs::write(&f, b"MZ pas un programme").unwrap();
        assert_eq!(juger(&f, None, false).unwrap_err(), Illisible::Pe);
        std::fs::write(&f, b"\x7fELF").unwrap();
        assert_eq!(juger(&f, None, false).unwrap_err(), Illisible::Elf);
        assert_eq!(
            juger(&d.join("absent"), None, false).unwrap_err(),
            Illisible::Ouverture(std::io::ErrorKind::NotFound)
        );
        // Un dossier : refusé partout. Windows refuse déjà de l'ouvrir comme un fichier (accès refusé, sans
        // FILE_FLAG_BACKUP_SEMANTICS) ; ailleurs il s'ouvre et n'est pas un fichier ordinaire.
        let attendu = if cfg!(windows) {
            Illisible::Ouverture(std::io::ErrorKind::PermissionDenied)
        } else {
            Illisible::PasUnFichier
        };
        assert_eq!(juger(&d, None, false).unwrap_err(), attendu);
        // Plusieurs fichiers : un seul refusé suffit à refuser le tout, et chacun est jugé.
        let bon = d.join("vanguard.exe");
        std::fs::write(&bon, pe_durci()).unwrap();
        assert!(verifier(std::slice::from_ref(&bon), None, false));
        assert!(!verifier(&[bon.clone(), d.join("absent")], None, false));
        assert!(!verifier(&[d.join("absent"), bon], None, false));
        let _ = std::fs::remove_dir_all(&d);
    }
}

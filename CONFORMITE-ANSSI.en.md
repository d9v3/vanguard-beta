# Vanguard and the ANSSI Rust guide

> Français : [CONFORMITE-ANSSI.md](CONFORMITE-ANSSI.md).

ANSSI publishes [programming rules for developing secure applications in
Rust](https://anssi-fr.github.io/rust-guide/), the Secure Rust Guidelines, with a [checklist](https://anssi-fr.github.io/rust-guide/checklist.html).
This table checks Vanguard against its 60 points (46 rules, 14 recommendations), as the guide stood on May 18, 2026. The
review was done on the code of version 0.89, still in preparation, on October 30, 2026.

Verdicts:

- **met**: the code follows the point, and the evidence is cited;
- **partial**: it follows it in part, and what is missing is stated;
- **gap**: it does not follow it yet;
- **waiver**: it departs from it on purpose, and the reason is written down;
- **not applicable**: the point cannot apply to Vanguard.

What is missing is not counted as met. Every partial and every gap has a next step: fixed in this batch, or
added to the work that comes next (proofs with Miri and Kani, arithmetic checked module by module, then the roadmap).

## In brief

| Verdict | Points |
|---|---:|
| met | 40 |
| partial | 12 |
| gap | 2 |
| waiver | 1 |
| not applicable | 5 |

Gaps found during the review and fixed in this batch: two pointer reads on Windows (DNS memory: bound
checked before the character, linked list stopped on a loop), a read of the wrong member of a VARIANT passed by reference
(WMI), a race between two walks of the accounts database on macOS, a safe function that read any
type from a Windows buffer, a handle with two owners, a hand-written `Send` that was not needed, leaks
on three error paths, the data key and its plaintext buffers never wiped, the missing `mem_forget` lint, and the environment variables
that could silently change a released program.

## Development environment

| Point | Verdict | Evidence | Next step |
|---|---|---|---|
| DENV-STABLE | met | `rust-toolchain.toml` pins a stable toolchain; the nightly toolchain is used only for the fuzzing bench (`outils/fuzz.sh`). | — |
| DENV-TIERS | waiver | Two of the four targets are tier 2: `x86_64-unknown-linux-musl`, the Linux target and the one for the USB key, and `x86_64-apple-darwin`. The rule is aimed at safety-critical systems (avionics, vehicles), which Vanguard is not. What makes up for it: the test suite runs on musl at every check, and on a GitHub Intel Mac (`.github/workflows/macos.yml`). | — |
| DENV-CARGO-LOCK | met | The four `Cargo.lock` files are versioned; every cargo command runs with `--locked` (`outils/verifier.sh`). | — |
| DENV-CARGO-OPTS | met | `[profile.dev]` and `[profile.test]` change only `debug` and `opt-level` (`Cargo.toml`). | — |
| DENV-CARGO-ENVVARS | partial | `outils/compiler-version.sh` sets `RUSTFLAGS` (`--remap-path-prefix`), so that a released program keeps no path from the machine that built it: this is the condition for a reproducible build. Fixed in this batch: it removes from the environment what would silently change the program (`RUSTUP_TOOLCHAIN`, `RUSTC`, `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`, `CARGO_ENCODED_RUSTFLAGS`, `CARGO_BUILD_…`, `CARGO_PROFILE_…`, `CARGO_TARGET_…_LINKER`, and for ring's C code `CC`, `AR`, `CFLAGS`…) and refuses any `rustc` other than the one in `rust-toolchain.toml`. Still open: a personal `~/.cargo/config.toml` (`[profile.release]`, `[build] rustc`), which nothing checks, and no automatic comparison of the Linux and Windows programs built on the author's computer with those of the CI (musl-gcc and MinGW versions differ from one machine to another). | Move to `trim-paths` once cargo has stabilized it. |
| DENV-FORMAT | met | `rustfmt.toml`; `cargo fmt --check` is the first step of `outils/verifier.sh`, and so of the CI. | — |
| DENV-LINTER | met | clippy pedantic and the restriction lints in `Cargo.toml`, zero warnings on the four targets (`-D warnings`). | — |
| DENV-AUTOFIX | met | No `cargo fix` or `clippy --fix` in `outils/` or `.github/`; the fix proposed by the night watch is never merged without review (`outils/veille/LISEZMOI.md`). | — |

## Libraries

| Point | Verdict | Evidence | Next step |
|---|---|---|---|
| LIBS-VETTING-DIRECT | partial | `cargo vet --locked --frozen` at every check and in the CI (`supply-chain/`): each version is either covered by an imported review (Google, Mozilla, Bytecode Alliance, Zcash, ISRG) or exempted at its exact number, and a new version fails. With Internet, the imported reviews are downloaded again from their registries (`outils/verifier.sh`): an entry written by hand in `imports.lock` does not count. Most direct dependencies still have only an exemption, which tracks the version without saying that its code was read. | Own reviews (`cargo vet certify`), first for the format readers, the network and cryptography: roadmap. |
| LIBS-VETTING-TRANSITIVE | partial | 111 crates out of 489 covered by the imported reviews, 2 in part, 376 exempted (`cargo vet`). | Same next step. |
| LIBS-OUTDATED | gap | Versions are tracked by hand, with no tool that reports a late dependency. A few are kept back on purpose, with the reason in `Cargo.toml`. | `cargo outdated` in the weekly watch, with the list of versions kept back on purpose: roadmap. |
| LIBS-AUDIT | met | `cargo audit` (the "known vulnerabilities" step of `outils/verifier.sh`), every night in the CI, and `cargo deny` for RustSec vulnerabilities (`deny.toml`). | — |

## Language

| Point | Verdict | Evidence | Next step |
|---|---|---|---|
| LANG-NAMING | met | rustc's `nonstandard_style` and clippy's `style` group, denied at compile time. Names are in French, as the project requires, in Rust's casing. | — |
| LANG-ARITH | partial | In the 50 modules of src/ read by the fuzzing bench, `arithmetic_side_effects` and `as_conversions` are refused (`#![warn(…)]` at the top of each, `-D warnings` at verification; a test in main.rs requires the attribute in every module fuzz/ includes): `checked_*` and a returned error, `try_from` or `From`, saturation only where it is the intended meaning (counters, budgets), wrapping only for checksums and hashes; 35 proven invariants keep their operation under `#[expect]`, with the proof in the reason. Elsewhere, overflow-checks turns an overflow into a caught panic, but no lint enforces the explicit operation. No reachable overflow was found. | The rest of the crate (about 1,300 raw calculations, far from hostile data): roadmap. |
| LANG-ERRWRAP | partial | Errors are per-module enums or texts to display; only one implements `std::error::Error`. None exposes dangerous internal state. | `Display` and `Error` on the reader errors: roadmap. |
| LANG-LIMIT-PANIC | met | Outside tests: no `panic!`, `unwrap()`, `expect(`, `todo!` or `unimplemented!`, all denied by clippy (`Cargo.toml`). | — |
| LANG-LIMIT-PANIC-SRC | met | The `assert!` calls outside tests are evaluated at compile time; the `unreachable!` calls follow the test that makes them unreachable. | — |
| LANG-ARRINDEXING | met | `indexing_slicing` denied; each exception carries `#[expect(clippy::indexing_slicing, reason = …)]`. | — |
| LANG-SYNC-TRAITS | met | Fixed in this batch: the hand-written `Send` for the elevated process, already `Send` through its handle, is removed (`src/machine/windows/eleve.rs`). | — |
| LANG-CMP-INV | met | The version comparisons all derive from `cmp`, on the compared fields only (`src/protection/perimes/version.rs`). | — |
| LANG-CMP-DEFAULTS | met | Only `eq`, `partial_cmp` and `cmp` are written. | — |
| LANG-CMP-DERIVE | met | Deriving would also compare the original text of a version: the reason is written next to it. | — |
| LANG-DROP | met | Each `Drop` releases a resource (handle, library, socket, lock, terminal mode, temporary folder, wipe). | — |
| LANG-DROP-NO-PANIC | met | No `Drop` body can panic: errors are ignored there, with no `unwrap` or index. | — |
| LANG-DROP-NO-CYCLE | met | No `Weak` or `Rc` with interior mutability in production; the readers' `Rc` are immutable. | — |
| LANG-DROP-SEC | partial | Buffers that hold a secret (WireGuard keys, memory read from other processes, and, since this batch, the data key in `src/chiffrement.rs`) are wiped by volatile writes (`socle::effacer`) in their `Drop`, and the buffers holding the plaintext key as soon as it is copied. Still in memory: the copy of the key kept for the session (a `static`, so the passphrase is asked only once, never dropped) and the passphrase. | Explicit wipe at the end of use, `Drop` kept as a safety net, and the passphrase in a wiped buffer: roadmap. |

## Unsafe and memory

| Point | Verdict | Evidence | Next step |
|---|---|---|---|
| LANG-UNSAFE | met | The `unsafe` blocks in `src/` are system calls (Windows, libc, macOS) or reads of its structures; none is in a format reader. Each says why it is safe (`// SAFETY:`, enforced by clippy). Their count is shown at every check (`outils/verifier.sh`). | — |
| UNSAFE-NOUB | met | Two possible undefined behaviors found and fixed in this batch: the race between two walks of `getpwent` and `getutxent` on macOS (one lock per database, in `src/machine/macos/noyau.rs`) and the read of a VARIANT passed by reference (`src/machine/windows/wmi.rs`). | Miri on the readers that make no system call, Kani on a few: next batch. |
| LANG-UNSAFE-ENCP | met | Fixed in this batch: the read of the account settings now accepts only the structures tied to their level by an `unsafe` trait, each implementation saying why (`src/machine/windows/comptes.rs`), and the precondition of copying a Wi-Fi list is written down (`src/machine/wifi/wlanapi.rs`). | — |
| MEM-FORGET | met | No `mem::forget`. | — |
| MEM-FORGET-LINT | met | Added in this batch: `mem_forget` in the lints of `Cargo.toml`. | — |
| MEM-NO-LEAK | partial | The tldr-pages pages are kept for the session with `leak` (`src/guide/tldr.rs`) and reloaded after each download of the archives: the lost memory grows with the number of downloads in one session. | Make the guide programs own their texts: roadmap. |
| MEM-LEAK | partial | The three other intended leaks are done once per process and justified (`src/main.rs`, `src/machine/windows/eleve.rs`); the tldr one is not (previous point). | Same next step. |
| MEM-MANUALLYDROP | met | Fixed in this batch: the elevated process channel is no longer wrapped in a `File` that is never released, but in a copy of its handle that has its own owner (`src/machine/windows/eleve.rs`). The remaining `ManuallyDrop` targets a union with trivial content (`src/machine/windows/wmi.rs`). | — |
| MEM-NORAWPOINTER | met | Fixed in this batch: the position of the data in a ZIP is computed without subtracting pointers (`src/archives/zip.rs`), and addresses turned into numbers go through `.addr()`, each one justified: bounding the links of a Windows answer (`src/machine/windows/cartes.rs`, `src/machine/windows/gestionnaire.rs`), aligning a buffer (`src/verifier_cle.rs`). The other raw pointers outside `unsafe` are used for identity (`ptr::eq`) or to prepare a system call. | — |
| MEM-INTOFROMRAWALWAYS | not applicable | No `into_raw`. | — |
| MEM-INTOFROMRAWONLY | not applicable | No `from_raw` of `Box`, `Rc`, `Arc` or `CString`. | — |
| MEM-UNINIT | met | No `mem::uninitialized`; the two `MaybeUninit` are read only after the call that fills them succeeds. | — |
| MEM-MUT-REC-RC | met | No recursive `Rc<RefCell<…>>`; the `RefCell` are used only in tests. | — |

## Interfacing with C (FFI)

| Point | Verdict | Evidence | Next step |
|---|---|---|---|
| FFI-SAFEWRAPPING | partial | Each `extern` block is private to its module and wrapped in safe functions; but some Windows functions are declared in several modules. | A shared module of declarations for Windows: roadmap. |
| FFI-CTYPE | met | The `extern` signatures use only integers, raw pointers, function pointers and `#[repr(C)]` structures. | — |
| FFI-TCONS | met | The copied structures have the size and alignment of the headers, checked by tests (`size_of`) for the most sensitive ones. | — |
| FFI-AUTOMATE | partial | The generated bindings of the `windows` crate are used for COM and WMI; some of the Win32 and macOS declarations are still written by hand. | Gradual move to the generated bindings: roadmap. |
| FFI-PFTYPE | partial | Fixed in this batch on the macOS side (`c_int`, `c_uint` for IOKit and `atexit`). On the Windows side, `u32`, `i32` and `u16` for DWORD, BOOL, LONG and WORD: exact on Windows, which fixes them that way, but not under the header's name. | With the shared module of declarations. |
| FFI-CKNONROBUST | met | `BOOL` values are read in full and compared to zero; C enumerations are read as integers. | — |
| FFI-CKINRUST | met | SAFEARRAY element size, buffer caps, range of each followed link: checked on the Rust side. | — |
| FFI-CK-PTR-VALID | met | Nullness tested before each read; range checked for linked lists. Fixed in this batch: the read of DNS memory tests its bound before each character and stops before reading an entry already freed, if the list loops (`src/protection/memoire_dns.rs`). | — |
| FFI-INPUT-PTR | met | No Rust function called by C receives a pointer. | — |
| FFI-CK-INPUT-REF-VALID | not applicable | No Rust function called by C receives a reference. | — |
| FFI-MARKEDFUNPTR | met | Function pointers are typed `unsafe extern "system"` or `"C"`. | — |
| FFI-CKFUNPTR | met | Each address returned by `GetProcAddress` or `dlsym` is tested as non-null before use; libraries are loaded only from System32. | — |
| FFI-NOENUM | met | No Rust `enum` receives a value from C. | — |
| FFI-R-OPAQUE | gap | The opaque handles (HANDLE, SC_HANDLE, EVT_HANDLE, HDEVINFO, BCrypt, WLAN, io_object_t) are `*mut c_void` or `u32`: two kinds of handles could be mixed up without the compiler noticing. | One type per kind of handle, with the shared module: roadmap. |
| FFI-C-OPAQUE | not applicable | No Rust type is handed to C. | — |
| FFI-CK-REF-MODEL | met | Pointers created by `&raw mut` and `&raw const`, `packed` fields copied before use. | — |
| FFI-MEM-NODROP | met | No type that implements `Drop` is passed by value to C. | — |
| FFI-MEM-OWNER | met | All memory allocated by the system is returned by its own function: `LocalFree`, `NetApiBufferFree`, `WlanFreeMemory`, `DnsFree`, `FreeMibTable`, `VariantClear`, `CFRelease`. One deliberate exception: the tail of a DNS memory list that loops or exceeds 65,536 entries is left to Windows rather than freed twice. | — |
| FFI-MEM-WRAPPING | partial | `Drop` wrappers exist (Wi-Fi sessions, memory reader, handles, CoreFoundation objects, COM); most releases are still written by hand. Fixed in this batch: the error paths that skipped the release (BCrypt fingerprints, shares, elevated channel). | `Drop` guards for each kind of system memory: roadmap. |
| FFI-NOPANIC | met | The two functions called by C cannot panic: an atomic write (signal), and a test cleanup that ignores its errors. | — |
| FFI-CAPI | not applicable | Vanguard is a program, not a library: the only exported symbol is a piece of data read by the Windows loader (`src/chargement.rs`). | — |

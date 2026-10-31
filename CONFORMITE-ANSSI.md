# Vanguard et le guide Rust de l'ANSSI

> English: [CONFORMITE-ANSSI.en.md](CONFORMITE-ANSSI.en.md).

L'ANSSI publie des [règles de programmation pour développer des applications sécurisées en
Rust](https://anssi-fr.github.io/rust-guide/fr/), avec leur [liste récapitulative](https://anssi-fr.github.io/rust-guide/fr/checklist.html).
Ce tableau confronte Vanguard à ses 60 points (46 règles, 14 recommandations), dans l'état du guide au 18 mai 2026. La
relecture a été faite sur le code de la version 0.89 en préparation, le 30 octobre 2026.

Verdicts :

- **tenu** : le code suit le point, la preuve est citée ;
- **partiel** : il le suit en partie, ce qui manque est dit ;
- **écart** : il ne le suit pas encore ;
- **dérogation** : il s'en écarte exprès, la raison est écrite ;
- **sans objet** : le point ne peut pas s'appliquer à Vanguard.

Ce qui manque n'est pas compté comme tenu. Chaque partiel et chaque écart a sa suite : corrigé dans ce lot, ou
inscrit à la feuille de route.

## En bref

| Verdict | Points |
|---|---:|
| tenu | 40 |
| partiel | 12 |
| écart | 2 |
| dérogation | 1 |
| sans objet | 5 |

Écarts trouvés à la relecture et corrigés dans ce lot : deux lectures de pointeur sous Windows (mémoire DNS : borne
testée avant le caractère, liste chaînée arrêtée sur une boucle), une lecture du mauvais membre d'un VARIANT passé par référence
(WMI), une course entre deux parcours de la base des comptes sous macOS, une fonction sûre qui lisait n'importe quel
type dans un tampon de Windows, une poignée à deux propriétaires, un `Send` écrit à la main sans besoin, des fuites
sur trois chemins d'erreur, la clé de données et ses tampons en clair jamais effacés, le lint `mem_forget` absent, et les variables de
l'environnement qui pouvaient changer en silence un programme publié.

## Environnement de développement

| Point | Verdict | Preuve | Suite |
|---|---|---|---|
| DENV-STABLE | tenu | `rust-toolchain.toml` épingle une chaîne stable ; la chaîne nightly sert seulement au banc de fuzzing (`outils/fuzz.sh`). | — |
| DENV-TIERS | dérogation | Deux des quatre cibles sont de tier 2 : `x86_64-unknown-linux-musl`, la cible Linux et celle de la clé, et `x86_64-apple-darwin`. La règle vise les systèmes de sûreté critiques (avionique, véhicule), ce que Vanguard n'est pas. Ce qui compense : la suite de tests tourne sur musl à chaque vérification, et sur un Mac Intel de GitHub (`.github/workflows/macos.yml`). | — |
| DENV-CARGO-LOCK | tenu | Les cinq `Cargo.lock` sont versionnés ; tout cargo tourne en `--locked` (`outils/verifier.sh`), sauf `cargo kani`, qui n'a pas cette option : `outils/preuves.sh` vérifie d'abord le verrou de `outils/preuves/` (`cargo metadata --locked`), qui n'a aucune dépendance. | — |
| DENV-CARGO-OPTS | tenu | `[profile.dev]` et `[profile.test]` ne changent que `debug` et `opt-level` (`Cargo.toml`). | — |
| DENV-CARGO-ENVVARS | partiel | `outils/compiler-version.sh` pose `RUSTFLAGS` (`--remap-path-prefix`), pour qu'un programme publié ne garde aucun chemin de la machine qui l'a compilé : c'est la condition de la compilation reproductible. Corrigé dans ce lot : il retire de l'environnement ce qui changerait le programme en silence (`RUSTUP_TOOLCHAIN`, `RUSTC`, `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`, `CARGO_ENCODED_RUSTFLAGS`, `CARGO_BUILD_…`, `CARGO_PROFILE_…`, `CARGO_TARGET_…_LINKER`, et pour le C de ring `CC`, `AR`, `CFLAGS`…) et refuse un `rustc` autre que celui de `rust-toolchain.toml`. Reste : un `~/.cargo/config.toml` personnel (`[profile.release]`, `[build] rustc`), que rien ne relit, et aucune comparaison automatique des programmes Linux et Windows de l'ordinateur de l'auteur à ceux de la CI (les versions de musl-gcc et de MinGW diffèrent d'une machine à l'autre). | Passer à `trim-paths` quand cargo l'aura stabilisé. |
| DENV-FORMAT | tenu | `rustfmt.toml` ; `cargo fmt --check` est la première étape de `outils/verifier.sh`, donc de la CI. | — |
| DENV-LINTER | tenu | clippy pedantic et les lints de restriction de `Cargo.toml`, zéro remarque sur les quatre cibles (`-D warnings`). | — |
| DENV-AUTOFIX | tenu | Aucun `cargo fix` ni `clippy --fix` dans `outils/` ou `.github/` ; la correction proposée par la veille de nuit n'est jamais fusionnée sans relecture (`outils/veille/LISEZMOI.md`). | — |

## Bibliothèques

| Point | Verdict | Preuve | Suite |
|---|---|---|---|
| LIBS-VETTING-DIRECT | partiel | `cargo vet --locked --frozen` à chaque vérification et en CI (`supply-chain/`) : chaque version est soit couverte par une relecture importée (Google, Mozilla, Bytecode Alliance, Zcash, ISRG), soit exemptée à son numéro exact, et une version nouvelle échoue. Avec Internet, les relectures importées sont retéléchargées de leurs registres (`outils/verifier.sh`) : une entrée écrite à la main dans `imports.lock` ne compte pas. La plupart des dépendances directes n'ont encore qu'une exemption, qui trace la version sans dire que son code a été lu. | Relectures propres (`cargo vet certify`), d'abord pour les lecteurs de formats, le réseau et la cryptographie : feuille de route. |
| LIBS-VETTING-TRANSITIVE | partiel | 111 crates sur 489 couvertes par les relectures importées, 2 en partie, 376 exemptées (`cargo vet`). | Même suite. |
| LIBS-OUTDATED | écart | Les versions sont suivies à la main, sans outil qui signale une dépendance en retard. Quelques-unes sont gardées exprès, avec leur raison dans `Cargo.toml`. | `cargo outdated` dans la veille hebdomadaire, avec la liste des versions gardées exprès : feuille de route. |
| LIBS-AUDIT | tenu | `cargo audit` (étape « failles connues » de `outils/verifier.sh`), chaque nuit en CI, et `cargo deny` pour les failles RustSec (`deny.toml`). | — |

## Langage

| Point | Verdict | Preuve | Suite |
|---|---|---|---|
| LANG-NAMING | tenu | `nonstandard_style` de rustc et le groupe `style` de clippy, refusés à la compilation. Les noms sont en français, comme le veut le projet, dans la casse de Rust. | — |
| LANG-ARITH | partiel | Dans les modules de src/ que compile le banc de fuzzing (une cinquantaine, sous-modules compris), `arithmetic_side_effects` et `as_conversions` sont refusés (`#![warn(…)]` en tête de chacun, `-D warnings` à la vérification ; un test de main.rs exige l'attribut de chaque module inclus par fuzz/ et de ses sous-modules, et n'y permet de taire ces lints que par `#[expect]` ou sur un module d'essais) : `checked_*` et une erreur rendue, `try_from` ou `From`, saturation seulement là où c'est le sens voulu (compteurs, budgets), débordement circulaire seulement pour les sommes de contrôle et les hachages ; les invariants prouvés gardent leur opération sous `#[expect]`, la preuve dans la raison. Le lint ne voit pas tout : décalages (`<<`, `>>`), `pow`, `abs`, `next_multiple_of`, `div_ceil`, `step_by`, sommes d'itérateurs, `Duration` et `Instant` hors `+` et `*` ; dans ces modules, ces formes ont été relues à la main (bornées par une constante ou une vérification faite avant). Ailleurs, overflow-checks change un dépassement en panique rattrapée, mais aucun lint n'impose l'opération explicite. Aucun dépassement atteignable n'a été trouvé. | Le reste du crate (environ 1 300 calculs bruts, loin des données hostiles) : feuille de route. |
| LANG-ERRWRAP | partiel | Les erreurs sont des enums par module ou des textes à montrer ; une seule implémente `std::error::Error`. Aucune n'expose d'état interne dangereux. | `Display` et `Error` sur les erreurs des lecteurs : feuille de route. |
| LANG-LIMIT-PANIC | tenu | Hors tests : aucun `panic!`, `unwrap()`, `expect(`, `todo!` ni `unimplemented!`, tous refusés par clippy (`Cargo.toml`). | — |
| LANG-LIMIT-PANIC-SRC | tenu | Les `assert!` hors tests sont évalués à la compilation ; les `unreachable!` suivent le test qui les rend inatteignables. | — |
| LANG-ARRINDEXING | tenu | `indexing_slicing` refusé ; chaque exception porte `#[expect(clippy::indexing_slicing, reason = …)]`. | — |
| LANG-SYNC-TRAITS | tenu | Corrigé dans ce lot : le `Send` écrit à la main pour le processus élevé, déjà `Send` par sa poignée, est retiré (`src/machine/windows/eleve.rs`). | — |
| LANG-CMP-INV | tenu | Les comparaisons de versions dérivent toutes de `cmp`, sur les seuls champs comparés (`src/protection/perimes/version.rs`). | — |
| LANG-CMP-DEFAULTS | tenu | Seules `eq`, `partial_cmp` et `cmp` sont écrites. | — |
| LANG-CMP-DERIVE | tenu | La dérivation comparerait aussi le texte d'origine d'une version : la raison est écrite à côté. | — |
| LANG-DROP | tenu | Chaque `Drop` libère une ressource (poignée, bibliothèque, prise, verrou, mode du terminal, dossier temporaire, effacement). | — |
| LANG-DROP-NO-PANIC | tenu | Aucun corps de `Drop` ne peut paniquer : les erreurs y sont ignorées, sans `unwrap` ni indice. | — |
| LANG-DROP-NO-CYCLE | tenu | Aucun `Weak` ni `Rc` à mutabilité intérieure en production ; les `Rc` des lecteurs sont immuables. | — |
| LANG-DROP-SEC | partiel | Les tampons qui portent un secret (clés WireGuard, mémoire lue d'autres processus, et, depuis ce lot, la clé de données de `src/chiffrement.rs`) sont effacés par des écritures volatiles (`socle::effacer`) dans leur `Drop`, et les tampons qui portent la clé en clair dès sa copie. Restent en mémoire : l'exemplaire de la clé gardé pour la session (une `static`, pour ne demander la phrase qu'une fois, jamais détruite) et la phrase de passe. | Effacement explicite en fin d'usage, `Drop` gardé en filet, et la phrase de passe dans un tampon effacé : feuille de route. |

## Unsafe et mémoire

| Point | Verdict | Preuve | Suite |
|---|---|---|---|
| LANG-UNSAFE | tenu | Les blocs `unsafe` de `src/` sont des appels au système (Windows, libc, macOS) ou des lectures de ses structures ; aucun n'est dans un lecteur de format. Chacun dit pourquoi il est sûr (`// SAFETY:`, imposé par clippy). Leur compte paraît à chaque vérification (`outils/verifier.sh`). | — |
| UNSAFE-NOUB | tenu | Deux comportements indéfinis possibles trouvés et corrigés dans ce lot : la course entre deux parcours de `getpwent` et `getutxent` sous macOS (un verrou par base, dans `src/machine/macos/noyau.rs`) et la lecture d'un VARIANT passé par référence (`src/machine/windows/wmi.rs`). | Miri et Kani chaque semaine : section « Preuves : Miri et Kani ». |
| LANG-UNSAFE-ENCP | tenu | Corrigé dans ce lot : la lecture des réglages des comptes n'accepte plus que les structures liées à leur niveau par un trait `unsafe`, dont chaque implémentation dit pourquoi (`src/machine/windows/comptes.rs`), et la précondition de la copie d'une liste du Wi-Fi est écrite (`src/machine/wifi/wlanapi.rs`). | — |
| MEM-FORGET | tenu | Aucun `mem::forget`. | — |
| MEM-FORGET-LINT | tenu | Ajouté dans ce lot : `mem_forget` dans les lints de `Cargo.toml`. | — |
| MEM-NO-LEAK | partiel | Les pages de tldr-pages sont gardées pour la session par `leak` (`src/guide/tldr.rs`) et rechargées après chaque téléchargement des archives : la mémoire perdue croît avec le nombre de téléchargements dans une même session. | Faire posséder leurs textes aux programmes du guide : feuille de route. |
| MEM-LEAK | partiel | Les trois autres fuites voulues sont faites une fois par processus et justifiées (`src/main.rs`, `src/machine/windows/eleve.rs`) ; celle de tldr ne l'est pas (point précédent). | Même suite. |
| MEM-MANUALLYDROP | tenu | Corrigé dans ce lot : le canal du processus élevé n'est plus enveloppé dans un `File` jamais relâché, mais dans une copie de sa poignée qui a son propre propriétaire (`src/machine/windows/eleve.rs`). Le `ManuallyDrop` qui reste vise une union au contenu trivial (`src/machine/windows/wmi.rs`). | — |
| MEM-NORAWPOINTER | tenu | Corrigé dans ce lot : la position des données d'un ZIP est calculée sans soustraire de pointeurs (`src/archives/zip.rs`), et les adresses devenues des nombres le sont par `.addr()`, chacune justifiée : borner les liens d'une réponse de Windows (`src/machine/windows/cartes.rs`, `src/machine/windows/gestionnaire.rs`), aligner un tampon (`src/verifier_cle.rs`). Les autres pointeurs bruts hors `unsafe` servent à l'identité (`ptr::eq`) ou à préparer un appel au système. | — |
| MEM-INTOFROMRAWALWAYS | sans objet | Aucun `into_raw`. | — |
| MEM-INTOFROMRAWONLY | sans objet | Aucun `from_raw` de `Box`, `Rc`, `Arc` ou `CString`. | — |
| MEM-UNINIT | tenu | Aucun `mem::uninitialized` ; les deux `MaybeUninit` ne sont lus qu'après le succès de l'appel qui les remplit. | — |
| MEM-MUT-REC-RC | tenu | Aucun `Rc<RefCell<…>>` récursif ; les `RefCell` ne servent qu'aux tests. | — |

## Interfaçage avec le C (FFI)

| Point | Verdict | Preuve | Suite |
|---|---|---|---|
| FFI-SAFEWRAPPING | partiel | Chaque bloc `extern` est privé à son module et enveloppé de fonctions sûres ; mais certaines fonctions de Windows sont déclarées dans plusieurs modules. | Un module commun de déclarations pour Windows : feuille de route. |
| FFI-CTYPE | tenu | Les signatures `extern` n'emploient que des entiers, des pointeurs bruts, des pointeurs de fonction et des structures `#[repr(C)]`. | — |
| FFI-TCONS | tenu | Les structures recopiées ont la taille et l'alignement des en-têtes, vérifiés par des tests (`size_of`) pour les plus sensibles. | — |
| FFI-AUTOMATE | partiel | Les liaisons générées de la crate `windows` servent à COM et WMI ; une partie des déclarations Win32 et macOS restent écrites à la main. | Passage progressif aux liaisons générées : feuille de route. |
| FFI-PFTYPE | partiel | Corrigé dans ce lot côté macOS (`c_int`, `c_uint` pour IOKit et `atexit`). Côté Windows, `u32`, `i32` et `u16` pour DWORD, BOOL, LONG et WORD : exacts sur Windows, qui les fixe ainsi, mais pas sous le nom de l'en-tête. | Avec le module commun de déclarations. |
| FFI-CKNONROBUST | tenu | Les `BOOL` sont lus en entier et comparés à zéro ; les énumérations du C sont lues en entiers. | — |
| FFI-CKINRUST | tenu | Taille d'élément des SAFEARRAY, plafonds des tampons, plage de chaque lien suivi : contrôlés côté Rust. | — |
| FFI-CK-PTR-VALID | tenu | Nullité testée avant chaque lecture ; plage contrôlée pour les listes chaînées. Corrigé dans ce lot : la lecture de la mémoire DNS teste sa borne avant chaque caractère et s'arrête avant de relire une entrée déjà rendue, si la liste boucle (`src/protection/memoire_dns.rs`). | — |
| FFI-INPUT-PTR | tenu | Aucune fonction Rust appelée par le C ne reçoit de pointeur. | — |
| FFI-CK-INPUT-REF-VALID | sans objet | Aucune fonction Rust appelée par le C ne reçoit de référence. | — |
| FFI-MARKEDFUNPTR | tenu | Les pointeurs de fonction sont typés `unsafe extern "system"` ou `"C"`. | — |
| FFI-CKFUNPTR | tenu | Chaque adresse rendue par `GetProcAddress` ou `dlsym` est testée non nulle avant usage ; les bibliothèques ne sont chargées que depuis System32. | — |
| FFI-NOENUM | tenu | Aucun `enum` Rust ne reçoit une valeur du C. | — |
| FFI-R-OPAQUE | écart | Les poignées opaques (HANDLE, SC_HANDLE, EVT_HANDLE, HDEVINFO, BCrypt, WLAN, io_object_t) sont des `*mut c_void` ou des `u32` : deux sortes de poignées pourraient se confondre sans que le compilateur le voie. | Un type par sorte de poignée, avec le module commun : feuille de route. |
| FFI-C-OPAQUE | sans objet | Aucun type Rust n'est confié au C. | — |
| FFI-CK-REF-MODEL | tenu | Pointeurs créés par `&raw mut` et `&raw const`, champs `packed` copiés avant usage. | — |
| FFI-MEM-NODROP | tenu | Aucun type qui implémente `Drop` n'est passé par valeur au C. | — |
| FFI-MEM-OWNER | tenu | Toute mémoire allouée par le système est rendue par sa fonction : `LocalFree`, `NetApiBufferFree`, `WlanFreeMemory`, `DnsFree`, `FreeMibTable`, `VariantClear`, `CFRelease`. Une exception voulue : la fin d'une liste de la mémoire DNS qui boucle ou dépasse 65 536 entrées reste à Windows, plutôt que d'être rendue deux fois. | — |
| FFI-MEM-WRAPPING | partiel | Des enveloppes `Drop` existent (sessions Wi-Fi, lecteur de mémoire, poignées, objets CoreFoundation, COM) ; la plupart des libérations restent écrites à la main. Corrigé dans ce lot : les chemins d'erreur qui sautaient la libération (empreintes BCrypt, partages, canal élevé). | Des gardes `Drop` pour chaque sorte de mémoire du système : feuille de route. |
| FFI-NOPANIC | tenu | Les deux fonctions appelées par le C ne peuvent pas paniquer : une écriture atomique (signal), et un nettoyage des tests qui ignore ses erreurs. | — |
| FFI-CAPI | sans objet | Vanguard est un programme, pas une bibliothèque : le seul symbole exporté est une donnée lue par le chargeur de Windows (`src/chargement.rs`). | — |

## Preuves : Miri et Kani

Lancées par `outils/preuves.sh`, chaque jeudi par la veille continue (`outils/veille/LISEZMOI.md`) et à la main
après avoir touché à un `unsafe` ou à un lecteur prouvé ; trop lentes pour chaque vérification.

| Outil | Ce qui est couvert | Ce qui ne l'est pas |
|---|---|---|
| Miri (nightly, provenance stricte) | Les `unsafe` qui portent sur la mémoire de Vanguard, par des essais interprétés pour Linux et pour Windows : effacement des secrets (`src/socle/mod.rs`), allocateur compteur des essais (`src/protection/perimes/sources/mod.rs`, pour Linux : pour Windows, Miri refuse l'allocateur du système de std lui-même), textes UTF-16 lus jusqu'au zéro final (`src/machine/windows/impression.rs`, `partages.rs`, `comptes.rs`), structures C mises à zéro (`src/socle/mod.rs`, `processus.rs`, `memoire.rs`). Aucun comportement indéfini trouvé. | Les `unsafe` qui appellent le système ou lisent la mémoire qu'il rend : Miri ne simule pas Windows, libc ni macOS ; leurs essais sont hors de la liste que `outils/preuves.sh` lance à leur nom exact (un seul porte en plus `cfg_attr(miri, ignore)`). Les structures propres à macOS : Miri ne compile pas ring sans les outils d'Apple. |
| Kani (vérification bornée) | Pour toutes les entrées dans la borne, ni panique, ni débordement, ni boucle sans fin, plus une propriété simple : entiers de SQLite (`src/sqlite.rs` : aller-retour avec l'encodage de référence, longueur lue), bits de zstd (`src/machine/linux/zstd.rs` : égaux à une lecture bit à bit, compte des bits restants exact), noms DNS compressés (`src/audit/dns_client.rs`, le parcours d'un nom dans un message de 4 octets : boucles de pointeurs arrêtées au 17e saut, étiquettes et position de suite dans le message, que la garde de longueur arrête la lecture ou non ; l'assemblage du texte, `String` et décodage UTF-8 de la bibliothèque standard, reste hors de la preuve). La borne de 253 caractères d'un nom n'est pas prouvée (inatteignable en 4 octets) : c'est un garde-fou du code, couvert par le fuzzing. Preuves dans `outils/preuves/`. Aucun défaut trouvé. | Au-delà de la borne (quelques octets par lecteur), le fuzzing (`outils/fuzz.sh`) prend le relais. |

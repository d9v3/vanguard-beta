---
name: verifier
description: Tout vérifier avant un commit de Vanguard — mise en forme, tests Linux, clippy sur les quatre cibles, tests Windows sous Wine, scripts générés. À lancer après toute modification du code Rust ou des scripts, avant de committer.
---

Lance `outils/verifier.sh` : il fait tout ce qui suit, les cibles en parallèle, et finit par une ligne par étape
(`--rapide` : Linux seulement, pour un essai en cours de route ; `--sans-wine`). Une étape en échec : corrige, puis
relance. Le détail, si une étape demande d'y regarder de près :

1. `cargo fmt --check` (sinon `cargo fmt`).
2. `cargo test`.
3. `cargo clippy -q --all-targets --target <cible>` pour x86_64-unknown-linux-musl, x86_64-pc-windows-gnu,
   aarch64-apple-darwin et x86_64-apple-darwin : zéro remarque.
4. Tests Windows sous Wine (commande dans CLAUDE.md), avec un WINEPREFIX jetable dans le dossier temporaire de la
   session. La première fois, Wine prépare ce dossier (une minute).
5. Si un script généré a changé : commandes shell par `bash -n -c`, PowerShell par pwsh (voir .claude/rules/windows.md).
6. Dépendances : `cargo deny check` (deny.toml) et `cargo audit` ; « sautée » sans l'outil (cargo audit aussi sans
   Internet). Dans le passage complet (sans option, celui de la livraison), une étape sautée ou jamais lancée est un
   échec ; `--rapide`, `--sans-wine` et `--ci` finissent « passage partiel » et nomment ce qui n'a pas été vérifié.
7. Workflows : `zizmor --offline .github/workflows` (sans jeton dans l'environnement) ; nomenclatures :
   `outils/sbom.sh <dossier>` deux fois, identiques (cargo-cyclonedx 0.5.9). Sautées sans l'outil.

Pièges :
- Un test qui passe sous Linux peut ne pas compiler pour macOS ou Windows (`#[cfg]`) : les quatre clippy comptent.
- Ne pas lancer de test qui modifie la machine (sudo, services, registre de HKLM) : seulement des clés jetables
  de HKCU sous Wine.

Rends compte en une ligne par étape : tests passés par système, remarques clippy, ce qui n'a pas pu être lancé.

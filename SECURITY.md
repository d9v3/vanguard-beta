# Sécurité

**Français** · [English](#security)

Vanguard protège des ordinateurs : une faille dans Vanguard lui-même toucherait ceux qui l'utilisent. Si tu en trouves
une, **ne l'écris pas dans un ticket public**, ni ailleurs en public, avant la publication de l'avis.

## Signaler une faille

En privé, depuis l'onglet **Security** du dépôt, bouton **Report a vulnerability**
([lien direct](https://github.com/d9v3/vanguard-beta/security/advisories/new), avec un compte GitHub). Seuls le
mainteneur et toi voyez le signalement et la discussion qui suit. C'est la seule voie : aucune adresse courriel,
aucune personne à joindre ailleurs.

## Ce qu'il faut joindre

- la version de Vanguard : `vanguard --version` ;
- le système : Linux et sa distribution, Windows (10 ou 11, et sa version), macOS (version, Intel ou Apple) ;
- les étapes pour reproduire : commandes lancées, choix dans les menus, fichiers utilisés ;
- une preuve minimale : le plus petit fichier, la plus courte commande qui montre la faille, et ce qu'un attaquant
  pourrait en faire ;
- **rien de personnel** : ni nom d'ordinateur, ni compte, ni adresse IP ou MAC, ni réseau Wi-Fi, ni rapport ou journal
  complet tel quel. Une preuve n'en a pas besoin : remplace-les par des valeurs inventées (`alice`, `Salon`,
  `192.168.1.10`).

## Versions suivies

Seule la dernière version publiée (page Releases) reçoit les corrections. Vanguard publie au plus une version par
jour : la correction part dans la suivante, et aucune version plus ancienne n'est corrigée à part. Mets Vanguard à jour
(`vanguard se-mettre-a-jour`) et vérifie que la faille y est encore avant de la signaler.

## Délai de réponse

Une première réponse est visée dans les **7 jours** : signalement reçu, puis faille confirmée ou non. Vanguard n'a
qu'un mainteneur : la correction prend le temps qu'il faut, et le signalement dit où elle en est.

## Publication

1. La faille est corrigée dans une nouvelle version, avec un test qui la reproduit.
2. Ensuite seulement, un avis de sécurité GitHub (GHSA) la décrit dans l'onglet **Security** : ce qui est touché, la
   version corrigée, ce qu'il faut faire.
3. Si la faille le mérite, une CVE est demandée à GitHub depuis l'avis.
4. Tu es remercié dans l'avis et dans les notes de la version, sous le nom ou le pseudonyme que tu choisis, ou pas du
   tout si tu préfères.

Merci de garder le secret jusqu'à la publication de l'avis.

## Dans le champ

- le programme `vanguard` pour Linux, Windows et macOS, tel que publié (page Releases et dépôt
  [vanguard-update](https://github.com/d9v3/vanguard-update)), et les scripts qu'il écrit puis lance (PowerShell,
  shell) ;
- les scripts de la clé USB : `Lancer Vanguard.bat`, `Lancer Vanguard.command`, `autorun.sh` et ce qu'ils exécutent ;
- l'installation : la copie sur l'ordinateur depuis la clé, le raccourci, la mise à jour depuis la clé ou depuis
  GitHub.

Par exemple :

- Vanguard qui affaiblit la sécurité : une correction qui coupe une protection, un réglage qui ne s'annule pas
  exactement, une commande lancée sans ton accord ;
- une injection de commande (shell, PowerShell) par un nom de fichier, un nom d'appareil, une réponse du réseau ou le
  contenu d'un fichier lu par Vanguard ;
- la clé USB : protection en écriture contournée, programme de la clé remplacé ou lancé à la place d'un autre ;
- une mise à jour acceptée alors qu'elle est mal signée, plus ancienne ou modifiée ;
- une fuite de données personnelles : journal des erreurs, rapport, captures, tickets.

## Hors du champ

- Les failles de Windows, de macOS ou d'une distribution Linux, même trouvées avec Vanguard : à signaler à leur
  éditeur. Windows : [Microsoft Security Response Center](https://msrc.microsoft.com/report/vulnerability). macOS :
  [Apple Security Research](https://security.apple.com/submit). Linux : l'équipe de sécurité de ta distribution, par
  exemple [Debian](https://www.debian.org/security/), [Ubuntu](https://ubuntu.com/security/disclosure-policy),
  [Fedora](https://fedoraproject.org/wiki/Security_Bugs) ou [Arch Linux](https://security.archlinux.org/).
- Les failles d'un outil que Vanguard lance sans l'avoir écrit (trivy, ClamAV…) : à signaler à son projet.
- Les problèmes que Vanguard trouve sur ton ordinateur : c'est son travail, le bilan les explique.
- Ce que le [modèle de menace](MODELE-DE-MENACE.md) dit hors de portée de Vanguard (par exemple un attaquant déjà
  administrateur, ou le noyau compromis) : une limite écrite, pas une faille, sauf si Vanguard prétend le contraire.
- L'avertissement de SmartScreen ou d'un antivirus sur le programme : il n'a pas de certificat de signature de code.
  Son intégrité se vérifie autrement, voir plus bas.

## Vérifications déjà en place

- **cargo deny**, à chaque vérification complète (`outils/verifier.sh`) et chaque nuit sur GitHub : failles connues
  des dépendances (base RustSec), licences permises, crates.io comme seule source. Un avis admis l'est avec sa preuve,
  dans [deny.toml](deny.toml).
- **cargo audit**, chaque nuit sur GitHub, sur la même base RustSec.
- **cargo vet**, à chaque vérification : chaque version de chaque dépendance a une relecture publiée par Google,
  Mozilla, Bytecode Alliance, Zcash ou ISRG, ou une exemption écrite à son numéro exact
  ([supply-chain/](supply-chain/config.toml)). Une version nouvelle sans l'une ou l'autre fait échouer la vérification.
- **Guide Rust de l'ANSSI** : le code est confronté point par point à ses 60 règles et recommandations, dans
  [CONFORMITE-ANSSI.md](CONFORMITE-ANSSI.md) ; ce qui manque y est dit, avec sa suite.
- **cargo auditable** : chaque programme publié porte la liste de ses dépendances, versions comprises. N'importe qui
  peut la comparer aux failles connues sur le programme téléchargé, avec `cargo audit bin` (voir la section
  [Développer](README.md#développer) du README) ; `outils/failles-programmes.sh` le fait avant chaque publication.
- **Ed25519** : chaque version publiée est décrite par un manifeste (taille et empreinte SHA-256 de chaque programme)
  signé en Ed25519 sur l'ordinateur de l'auteur. Vanguard porte la clé publique et refuse une mise à jour mal signée,
  plus ancienne, ou dont la taille ou l'empreinte diffère.
- **Compilation reproductible** des programmes Linux et Windows, vérifiée la nuit sur GitHub quand le code a changé :
  le même code, compilé deux fois, donne exactement le même programme.
- **Nomenclatures (SBOM) et attestation** : chaque page de version joint la nomenclature CycloneDX de chaque
  programme (toutes les dépendances compilées, versions et licences). Le programme macOS, compilé par GitHub, et ces
  nomenclatures y sont attestés (Sigstore), à vérifier avec la GitHub CLI connectée :
  `gh attestation verify vanguard-macos -R d9v3/vanguard-beta --signer-workflow d9v3/vanguard-beta/.github/workflows/macos.yml --source-ref refs/heads/master`.
  Les nomenclatures Linux et Windows décrivent leur code, pas le fichier publié ; ces deux programmes, compilés par
  l'auteur, ne sont pas attestés : la mise à jour intégrée les vérifie par la signature Ed25519 ci-dessus.
- **Workflows de GitHub** relus par [zizmor](https://github.com/zizmorcore/zizmor) à chaque vérification (injections
  de gabarit, déclencheurs dangereux, jetons laissés dans les extractions), et leurs actions épinglées par commit.

---

# Security

[Français](#sécurité) · **English**

Vanguard protects computers: a flaw in Vanguard itself would hit the people who use it. If you find one, **do not
write it in a public issue**, or anywhere public, before the advisory is published.

## Reporting a vulnerability

Privately, from the repository's **Security** tab, **Report a vulnerability** button
([direct link](https://github.com/d9v3/vanguard-beta/security/advisories/new), with a GitHub account). Only the
maintainer and you see the report and the discussion that follows. It is the only channel: no email address, no one to
reach elsewhere.

## What to include

- Vanguard's version: `vanguard --version`;
- the system: Linux and its distribution, Windows (10 or 11, and its version), macOS (version, Intel or Apple);
- the steps to reproduce: commands run, menu choices, files used;
- a minimal proof: the smallest file, the shortest command that shows the flaw, and what an attacker could do with it;
- **nothing personal**: no computer name, account, IP or MAC address, Wi-Fi network, or full report or journal as is.
  A proof does not need them: replace them with made-up values (`alice`, `Salon`, `192.168.1.10`).

## Supported versions

Only the latest published version (Releases page) receives fixes. Vanguard publishes at most one version a day: the
fix ships in the next one, and no older version is fixed separately. Update Vanguard (`vanguard self-update`) and
check that the flaw is still there before reporting it.

## Response time

A first answer is aimed for within **7 days**: report received, then flaw confirmed or not. Vanguard has a single
maintainer: the fix takes the time it needs, and the report says where it stands.

## Disclosure

1. The flaw is fixed in a new version, with a test that reproduces it.
2. Only then, a GitHub security advisory (GHSA) describes it in the **Security** tab: what is affected, the fixed
   version, what to do.
3. If the flaw warrants it, a CVE is requested from GitHub through the advisory.
4. You are credited in the advisory and in the release notes, under the name or nickname you choose, or not at all if
   you prefer.

Please keep the flaw secret until the advisory is published.

## In scope

- the `vanguard` program for Linux, Windows and macOS, as published (Releases page and the
  [vanguard-update](https://github.com/d9v3/vanguard-update) repository), and the scripts it writes then runs
  (PowerShell, shell);
- the USB key's scripts: `Lancer Vanguard.bat`, `Lancer Vanguard.command`, `autorun.sh` and what they run;
- the installation: the copy onto the computer from the key, the shortcut, the update from the key or from GitHub.

For example:

- Vanguard weakening security: a fix that turns a protection off, a setting that cannot be undone exactly, a command
  run without your consent;
- command injection (shell, PowerShell) through a file name, a device name, a network answer or the content of a file
  Vanguard reads;
- the USB key: write protection bypassed, the key's program replaced or run instead of another one;
- an update accepted although it is badly signed, older or modified;
- a personal data leak: error journal, report, screenshots, issues.

## Out of scope

- Flaws in Windows, macOS or a Linux distribution, even found with Vanguard: report them to their vendor. Windows:
  [Microsoft Security Response Center](https://msrc.microsoft.com/report/vulnerability). macOS:
  [Apple Security Research](https://security.apple.com/submit). Linux: your distribution's security team, for example
  [Debian](https://www.debian.org/security/), [Ubuntu](https://ubuntu.com/security/disclosure-policy),
  [Fedora](https://fedoraproject.org/wiki/Security_Bugs) or [Arch Linux](https://security.archlinux.org/).
- Flaws in a tool Vanguard runs without having written it (trivy, ClamAV…): report them to its project.
- The problems Vanguard finds on your computer: that is its job, the check explains them.
- What the [threat model](MODELE-DE-MENACE.en.md) puts out of Vanguard's reach (for example an attacker who is already
  an administrator, or a compromised kernel): a written limit, not a flaw, unless Vanguard claims otherwise.
- The SmartScreen or antivirus warning about the program: it has no code signing certificate. Its integrity is checked
  another way, see below.

## Checks already in place

- **cargo deny**, in each full check (`outils/verifier.sh`) and every night on GitHub: known vulnerabilities in the
  dependencies (RustSec database), allowed licenses, crates.io as the only source. An accepted advisory comes with its
  proof, in [deny.toml](deny.toml).
- **cargo audit**, every night on GitHub, on the same RustSec database.
- **cargo vet**, at every verification: each version of each dependency has a review published by Google, Mozilla,
  Bytecode Alliance, Zcash or ISRG, or a written exemption at its exact number
  ([supply-chain/](supply-chain/config.toml)). A new version with neither fails the verification.
- **ANSSI's Secure Rust Guidelines**: the code is checked point by point against its 60 rules and recommendations,
  in [CONFORMITE-ANSSI.en.md](CONFORMITE-ANSSI.en.md); what is missing is said there, with what comes next.
- **cargo auditable**: every published program carries the list of its dependencies, versions included. Anyone can
  check it against known vulnerabilities on the downloaded program, with `cargo audit bin` (see the README's
  [Development](README.en.md#development) section); `outils/failles-programmes.sh` does it before each release.
- **Ed25519**: each published version is described by a manifest (size and SHA-256 checksum of each program) signed
  with Ed25519 on the author's computer. Vanguard carries the public key and refuses an update that is badly signed,
  older, or whose size or checksum differs.
- **Reproducible build** of the Linux and Windows programs, checked nightly on GitHub when the code changed: the same
  code, built twice, gives exactly the same program.
- **SBOMs and attestation**: each release page includes the CycloneDX bill of materials of each program (every
  compiled dependency, versions and licenses). The macOS program, built by GitHub, and these SBOMs are attested there
  (Sigstore); check with the GitHub CLI logged in:
  `gh attestation verify vanguard-macos -R d9v3/vanguard-beta --signer-workflow d9v3/vanguard-beta/.github/workflows/macos.yml --source-ref refs/heads/master`.
  The Linux and Windows SBOMs describe their code, not the published file; these two programs, built by the author,
  are not attested: the built-in update checks them with the Ed25519 signature above.
- **GitHub workflows** checked by [zizmor](https://github.com/zizmorcore/zizmor) at every verification (template
  injections, dangerous triggers, tokens left in checkouts), and their actions pinned by commit.

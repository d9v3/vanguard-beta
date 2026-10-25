# Extensions de Vanguard : plugins et laboratoire

Une extension ajoute un programme à Vanguard sans toucher à son code : un essai, un outil expérimental, celui
d'un autre. Elle n'est jamais du code de Vanguard : elle ne tourne qu'à ta demande, ses constats sont montrés à
part et ne comptent jamais dans la note.

Deux formes :

- **Plugin** : un outil durable, dans son dossier, avec un manifeste `plugin.toml`. Ajouté une fois
  (`vanguard plugins ajouter <dossier ou archive.zip>`), il est ensuite dans le menu.
- **Script du labo** : un fichier posé tel quel, sans manifeste, pour essayer vite (`vanguard labo ouvrir`
  donne le dossier).

Le menu principal a l'entrée **12. Extensions** (`vanguard extensions`) : 1 les plugins, 2 les scripts du labo,
3 l'interrupteur des restrictions.

## Où sont les extensions

Dans le dossier local de Vanguard, jamais sur la clé USB ni à côté du programme :

| Système | Dossier |
|---|---|
| Linux | `~/.local/share/vanguard/plugins/` (ou `$XDG_DATA_HOME/vanguard/plugins/`) |
| macOS | `~/Library/Application Support/vanguard/plugins/` |
| Windows | `%LOCALAPPDATA%\vanguard\plugins\` |

Le labo est le sous-dossier `labo/`. Vanguard refuse le dossier s'il n'est pas à toi ou si d'autres comptes peuvent
y écrire (Unix : `chmod go-w`), et sous Windows s'il est hors de ton profil.

## Un plugin

```
mon-plugin/
  plugin.toml
  mon-script.sh        (ou un .ps1, un .py, un programme compilé)
```

`plugin.toml` :

```toml
nom = "mon-plugin"                 # a-z, 0-9, tirets ; c'est aussi le nom du dossier
titre_fr = "Mon plugin"
titre_en = "My plugin"
description_fr = "Ce qu'il vérifie, en une phrase."
description_en = "What it checks, in one sentence."
auteur = "alice"                   # facultatif, montré tel quel (non vérifié, sauf signé : voir plus bas)
cle_auteur = "1f0c…"               # facultatif : clé publique Ed25519 de l'auteur, 64 chiffres hexadécimaux
source = "https://exemple.org/x"   # facultatif, montré tel quel (non vérifié)
systemes = ["linux", "macos", "windows"]
delai = 30                         # secondes, de 1 à 600 (60 par défaut)
commande = "mon-script.sh"         # chemin relatif au dossier, jamais « .. » ni absolu
arguments = ["--court"]            # arguments fixes, avant ceux tapés à la ligne de commande

[windows]                          # facultatif : une autre commande pour un système
commande = "mon-script.ps1"
```

Clés facultatives de plus, qui ne sont que des **demandes** : `confiance = "totale"` (tourner sans
restrictions), `dans_le_bilan = true` et `dans_la_surveillance = true` (tourner tout seul avec le bilan complet ou
la surveillance). Le récapitulatif les montre, et rien n'est accordé sans ta réponse à une question à part, après
l'approbation. L'accord vaut pour le dossier tel qu'il est : un fichier qui change, et il tombe.

L'interpréteur vient de l'extension : `.sh` par `/bin/sh`, `.bash` par `/bin/bash`, `.ps1` par le PowerShell de
System32 (`pwsh` ailleurs), `.py` par le `python3` du système ; le reste est lancé tel quel. Le dossier courant
est celui du plugin : lis tes fichiers par là (le programme lancé est une copie vérifiée, ailleurs).

Commandes :

```
vanguard plugins ajouter extensions/exemples/exemple   copie, analyse, montre, demande l'accord
vanguard plugins exemple                                le lance
vanguard plugins exemple --rapport                      ses constats dans le rapport HTML (section Plugins)
vanguard plugins exemple --isole                        sans réseau, dossier personnel masqué (Linux :
                                                       bubblewrap ; macOS : sandbox-exec ; pas sous Windows)
vanguard plugins liste                                  chaque plugin et son état
vanguard plugins approuver exemple                      après un changement, le remontre et le réapprouve
vanguard plugins retirer exemple
```

Après `--`, tout va au plugin tel quel (`vanguard plugins exemple -- --rapport`).

### Signer un plugin (auteur vérifié)

Sans signature, l'auteur et la source sont montrés tels que le manifeste les dit, « non vérifiés ». Avec
`cle_auteur` dans `plugin.toml` et `plugin.sig` à côté, Vanguard vérifie que **tout le dossier** vient de qui tient la
clé privée : l'approbation dit « signé par la clé …, signature vérifiée », et une signature absente ou fausse (un
fichier changé après la signature) fait refuser le plugin. La clé est notée à l'approbation : une mise à jour signée
par une autre clé, ou plus signée du tout, est signalée en rouge à l'approbation suivante (quelqu'un a pu remplacer
le plugin). La signature ne dit pas qui est l'auteur, seulement que c'est le même.

La signature : Ed25519, sur « vanguard-plugin 1 », un saut de ligne, l'empreinte du dossier sans `plugin.sig` (le
SHA-256 des lignes « empreinte  chemin » de `sha256sum`, triées par chemin, sans `target/` ni `.git/` à la racine)
et un saut de ligne ; en hexadécimal dans `plugin.sig`. Une clé : `openssl genpkey -algorithm ed25519 -out
auteur.pem` (à garder pour soi) ; la clé publique pour `cle_auteur` : `openssl pkey -in auteur.pem -pubout -outform
DER | tail -c 32 | od -An -tx1 | tr -d ' \n'`. Puis, dans le dossier du plugin, après le dernier changement (Linux ;
sous macOS, `shasum -a 256` à la place de `sha256sum`) :

```sh
# signer-plugin
rm -f plugin.sig
empreinte=$(find . -type f ! -path './target/*' ! -path './.git/*' | sed 's|^\./||' | LC_ALL=C sort |
  while IFS= read -r f; do sha256sum "$f"; done | sha256sum | cut -d' ' -f1)
message=$(mktemp)
printf 'vanguard-plugin 1\n%s\n' "$empreinte" >"$message"
openssl pkeyutl -sign -inkey auteur.pem -rawin -in "$message" | od -An -tx1 | tr -d ' \n' >plugin.sig
rm -f "$message"
```

## Le protocole

Chaque ligne écrite par l'extension est montrée (les caractères qui piloteraient le terminal sont remplacés par
`�`). Une ligne qui est un objet JSON comme celui-ci devient un constat, affiché comme ceux du bilan :

```json
{"vanguard":1,"niveau":"moyen","categorie":"Salon","message":"Une prise inventée a son port 23 ouvert."}
```

`niveau` : `ok`, `info`, `moyen`, `eleve` ou `critique`. Au plus 100 constats, catégorie de 40 caractères et message
de 300. Un constat est marqué « plugin <nom> » ou « labo <fichier> » et ne change jamais la note.

## Le laboratoire

```
vanguard labo ouvrir              crée le dossier s'il manque et en donne le chemin
vanguard labo                     la liste à choisir
vanguard labo essai.sh alice      le lance, avec ses arguments
```

Au premier lancement, Vanguard montre le chemin, l'empreinte, l'analyse et les 20 premières lignes du script, puis
demande l'accord ; s'il change ensuite, il redemande. Chaque lancement porte le bandeau « EXPÉRIMENTAL — hors du
programme de Vanguard ». Un exemple : [exemples/labo-exemple.sh](exemples/labo-exemple.sh).

## Un plugin en Rust

La bibliothèque [sdk](sdk) (`vanguard-extension`, sans dépendance) écrit les constats exactement comme Vanguard
les lit et lance un autre programme proprement (sans shell, délai et sortie bornés) :

```rust
use vanguard_extension::{Constat, lancer, message, tr};
message(tr("Bonjour", "Hello"));
Constat::moyen("Salon", "Une prise inventée a son port 23 ouvert.").envoyer();
let s = lancer("uname", &["-a"], std::time::Duration::from_secs(10));
```

L'exemple complet est [exemples/rust-exemple](exemples/rust-exemple) :

```
cd extensions/exemples/rust-exemple
cargo install --path . --root . --no-track      le programme dans bin/
vanguard plugins ajouter .
vanguard plugins rust-exemple
```

`target/` et `.git/` ne sont pas copiés avec le plugin.

## Les garde-fous, et l'interrupteur

Restrictions **actives** (par défaut) :

- approbation par l'empreinte SHA-256 de **tout** le dossier du plugin (chaque fichier, pas seulement le programme)
  ou du script ; un fichier changé, ajouté ou retiré : refusé jusqu'à une nouvelle approbation ;
- avant l'accord : l'analyse YARA et les empreintes MalwareBazaar de Vanguard (une correspondance : refus) ;
- le dossier copié en étant haché, et c'est la copie vérifiée qui tourne ;
- aucun lien suivi ; une archive ne peut rien écrire hors de son dossier (50 Mo au plus, ni « .. », ni nom de
  périphérique Windows comme CON ou COM1) ;
- jamais tout seul en administrateur (chaque lancement y est demandé, voir plus bas) ; jamais dans le bilan, la
  surveillance, l'entretien ni `bilan` ;
- le terminal retiré à l'extension (elle ne peut ni y écrire à côté du filtre ni y lire les frappes) ; délai et
  sortie bornés (1 Mio) : au-delà, elle est arrêtée avec tout ce qu'elle a lancé (sous Linux, ce qui reste de son
  groupe l'est aussi quand elle finit d'elle-même) ; environnement minimal (PATH du système, LANG, HOME),
  aucune variable de Vanguard.

Restrictions **coupées** :

- pour tout (menu Extensions › 3, `vanguard extensions --sans-restrictions on`) : ni accord, ni empreinte, ni
  analyse, bornes très larges, tout l'environnement, à la main seulement ;
- pour un élément (« Restrictions d'un plugin », « Marquer un script comme à moi », ou la question à part quand un
  manifeste demande la confiance) : le même, pour lui seul et tel qu'il est (son empreinte) ; c'est le seul moyen de
  le faire tourner tout seul avec le bilan ou la surveillance, s'il le demande.

La première coupure demande une confirmation, une seule fois ; remettre les restrictions est immédiat.

Ces choix (restrictions coupées, « à moi », lancement avec le bilan ou la surveillance) et les approbations sont
**scellés** par Vanguard : changés hors de Vanguard, ou repris d'une version d'avant sans sceau, ils n'accordent plus
rien et rien ne tourne tout seul ; le menu et le bilan le disent (COM-ETA-001). Il suffit de les redonner dans le menu.

**En administrateur**, rien de ce qui est dans le dossier des extensions ne lève une garde (sous Windows, tout
programme du compte peut l'écrire, même sans élévation) : aucune extension ne tourne avec le bilan, la
surveillance ou l'entretien, et chaque lancement à la main est montré avec son empreinte et demandé, à chaque fois.

Une seule chose reste, même sans restrictions : le dossier des extensions doit être à toi et fermé aux autres
comptes. Sinon un programme d'un autre compte pourrait y poser du code qui tournerait comme toi, sans rien demander.

# Modèle de menace

*[English](MODELE-DE-MENACE.en.md)*

Ce que Vanguard protège, contre qui, et ce qu'il ne protège pas. Cette page fixe le cadre des fonctions : chacune
devrait pouvoir dire quelle menace d'ici elle couvre. Les failles de Vanguard lui-même (un défaut du programme, de la
clé USB ou de la mise à jour) relèvent d'une autre page : [SECURITY.md](SECURITY.md).

## Ce que Vanguard protège

- **L'ordinateur sur lequel il tourne** : ses réglages de sécurité, ses mises à jour, ce qui s'y lance au démarrage,
  ce qui y tourne et ce qui parle à Internet. Linux, Windows et macOS.
- **Le réseau local vu depuis cet ordinateur** : le routeur, les appareils connectés, ce qui est ouvert vers
  Internet, le Wi-Fi.
- **Les données de la personne** : ses fichiers (pièges contre les rançongiciels, vérification de la sauvegarde), ses
  secrets (fuites de mots de passe et d'adresses courriel, clés SSH sans phrase de passe, clés privées et jetons
  laissés dans des fichiers), sa vie privée (logiciels espions).
- **Sa clé USB** : protégée en écriture ailleurs que sur l'ordinateur de son propriétaire, contre les vers de clé ;
  son carnet peut être chiffré par une phrase, contre une clé perdue ou prêtée.

## Contre qui : les menaces couvertes

| Menace | Ce que fait Vanguard |
|---|---|
| Un logiciel malveillant connu sur l'ordinateur | Antivirus du système en second avis, règles YARA, empreintes de MalwareBazaar, mémoire des programmes, lancements au démarrage, signes d'un rootkit ; blocage après accord, ou de lui-même pour ce qui ne fait aucun doute (protection active). |
| Un rançongiciel | Fichiers-pièges vérifiés chaque heure ; sous Linux, une fois allumé, un veilleur en direct qui arrête un cas quasi certain avec la protection active. |
| Une faiblesse de réglage ou une faille non corrigée | Bilan noté de A à F, mises à jour manquantes, failles activement exploitées du catalogue de la CISA, fin de support ; chaque correction après accord, annulable sauf celle qui rallume une protection. |
| Une exposition vers Internet | Ports que le routeur ouvre (demandés au routeur lui-même, ouvertures UPnP comprises), IPv6 publique sans pare-feu ; dans les journaux, les mots de passe devinés et les connexions au Bureau à distance depuis l'extérieur. |
| Un intrus sur le réseau local ou le Wi-Fi | Inventaire des appareils et des nouveaux venus, faux point d'accès, DNS et certificats détournés ; mode Wi-Fi public en déplacement. |
| Un proche qui surveille la personne | Logiciels espions, prise de contrôle à distance (faux technicien). |
| Une arnaque | Liens examinés sans les ouvrir, fichiers téléchargés vérifiés, fuites de comptes. |
| Un agent d'IA qui agit trop | Serveurs d'IA ouverts au réseau, agents qui agissent sans demander, serveurs MCP mal protégés. |

Le détail de chaque menace, menu par menu : [Ce que fait Vanguard](README.md#ce-que-fait-vanguard).

## Ce que Vanguard ne protège pas

- **Un attaquant qui a déjà les droits d'administrateur.** Il peut arrêter Vanguard, effacer ses traces ou fausser ce
  que le système lui répond. Vanguard ne se protège pas contre la désactivation : il signale seulement que sa
  surveillance a été coupée. Lancé lui-même en administrateur, Vanguard ne bloque rien de lui-même, parce que ses
  réglages de blocage peuvent être écrits par n'importe quel programme du compte.
- **Le noyau et le micrologiciel.** Vanguard ne charge rien dans le noyau. Il relève les signes d'un rootkit
  (processus cachés, modules du noyau qui se cachent ou non signés), mais un rootkit bien fait peut mentir au
  système qui l'interroge. Secure Boot est vérifié et le micrologiciel (BIOS, UEFI) mis à jour après accord, mais rien
  ne le surveille en direct.
- **Une menace nouvelle, encore sans signature.** Les détections reposent surtout sur des listes connues ; ce qui n'y
  est pas encore peut passer. Vanguard complète l'antivirus du système (Microsoft Defender, XProtect, ClamAV) : il ne
  le remplace pas.
- **Tout, en temps réel.** Hors des deux veilleurs de Linux (programmes et connexions, anti-rançongiciel ; coupés par
  défaut), de la surveillance en direct de l'intégrité des fichiers critiques et du blocage de Defender, la
  surveillance passe chaque heure, entre deux bilans.
- **La page visitée.** Vanguard n'a pas d'extension de navigateur : la page ouverte n'est pas examinée. Il examine un
  lien qu'on lui donne, bloque après accord des sites dangereux connus par le fichier hosts
  (`vanguard sites-dangereux`), et le mode Wi-Fi public passe à un DNS qui filtre.
- **Les autres appareils du réseau.** Il les observe, il ne les corrige pas et ne les attaque jamais : le routeur est
  lu, jamais modifié ; le seul mot de passe essayé est la communauté SNMP « public », et l'essai est annoncé.
- **Les comptes en ligne.** Les fuites connues sont signalées ; le compte lui-même relève du service qui l'héberge.
- **La perte des données.** Un programme malveillant du compte peut éteindre le veilleur anti-rançongiciel : la
  sauvegarde reste la vraie protection.
- **Un ordinateur volé allumé et déverrouillé.** Le chiffrement du disque (BitLocker, FileVault, LUKS) protège un
  ordinateur éteint ; Vanguard le vérifie et le recommande.
- **Ce que lit un ordinateur emprunté.** La protection en écriture empêche qu'on modifie la clé, pas qu'on la lise :
  le carnet n'est à l'abri que chiffré.

## Ce que Vanguard suppose

- **Le programme est le vrai.** Vérifiez son empreinte SHA-256 au téléchargement (`SHA256SUMS.txt`) ; chaque mise à
  jour est signée en Ed25519 et refusée si elle est mal signée, plus ancienne, ou si sa taille ou son empreinte ne
  correspond pas. Le programme n'a pas encore de certificat de signature de code.
- **Personne d'autre ne pilote Claude sur le dépôt du code.** Claude sur GitHub (.github/workflows/claude.yml) peut
  écrire dans le dépôt et lance cargo build et cargo test, pour vérifier ce qu'il corrige. Il ne se lance que pour le
  propriétaire, sur un fil (ticket ou demande de fusion du dépôt lui-même, jamais d'un fork) dont chaque commentaire,
  revue et commentaire de revue est du propriétaire ou des robots de Claude et de GitHub Actions. Juste avant Claude,
  le fil est verrouillé, puis relu de la même façon, et il le reste jusqu'à la fin du travail ; un second `@claude`
  sur le même fil attend la fin du premier. Restent : ceux qui ont un accès en écriture au dépôt, qui peuvent écrire
  même sur un fil verrouillé ; ce qu'il lit ailleurs que dans le fil (un ticket lié, une page, un texte d'un autre
  recopié par le propriétaire) ; et le code du dépôt lui-même, que cargo build et cargo test exécutent.
- **Le système répond juste au moment du bilan.** Un poste déjà compromis en administrateur peut tromper toutes ses
  lectures (voir plus haut).
- **Les listes et les outils tiers sont justes.** Les listes de menaces, de versions et de failles (abuse.ch, CISA,
  éditeurs) et les outils que Vanguard lance sans les avoir écrits (ClamAV, trivy, gitleaks) sont crus tels quels ;
  une liste trop vieille est dite non vérifiée.
- **Les programmes de votre compte ne visent pas Vanguard lui-même.** Vanguard garde son état (ce qu'il a déjà vu, ce
  que vous avez réglé, les défenses que vous avez allumées) dans un dossier de votre compte. Un programme malveillant
  qui tourne sous votre compte peut donc fausser cet état. Vanguard voit et dit la falsification simple (un fichier
  changé, effacé ou daté dans le futur) et ne s'y fie plus : aucune défense ne se coupe, aucune alerte ne se tait.
  Deux limites : le dossier de Vanguard effacé en entier le ramène à son premier usage, où il réapprend sans rien
  dire ; et un programme qui vise exprès ce mécanisme (il réécrit aussi les sceaux de Vanguard, ou les efface avec
  leurs témoins) n'est pas vu. Un programme qui garde le verrou des sceaux (sceaux.verrou) empêche Vanguard d'écrire
  son état et son journal des événements tant qu'il le garde : Vanguard ne l'attend qu'une fois, puis une seconde en
  tout, le dit au bilan, et compte les événements qu'il n'a pas pu noter pour les dire une fois le verrou rendu. Ceux
  d'un Vanguard tué pendant ce temps se perdent sans être comptés, et ce compte, écrit sans sceau, peut être effacé.
  La vraie parade, un service qui tourne sous un autre compte que le vôtre (administrateur), est prévue pour une
  version à venir.
- **La personne décide.** Rien n'est modifié sans son accord. Ce qu'elle accepte s'annule une correction à la fois,
  sauf ce qui rallume une protection et l'arrêt d'un programme ; une correction dont l'état d'avant ne se relève pas
  est dite « non annulable » avant d'être appliquée.
- **Les essais ont leurs limites.** Vanguard est essayé sur l'ordinateur de l'auteur, une VM Windows, un second PC
  Windows et les machines de GitHub (Windows, Mac, vraies distributions Linux). Il n'a jamais tourné sur un vrai Mac ;
  d'autres cas restent à essayer sur du vrai matériel (autres distributions, vrai routeur UPnP, démarrage de la clé).

## Ce qui sort de l'ordinateur

Les listes de menaces, de versions et de failles sont téléchargées en entier, les mêmes pour tous. Ce que Vanguard
envoie lui-même :

- **Sous Windows et macOS**, la liste des logiciels installés ne sort pas : leurs versions sont jugées sur ces listes.
- **Sous Arch Linux, après accord** (Paramètres › Paquets de l'AUR, coupé par défaut) : le nom des paquets
  installés hors des dépôts officiels, à aur.archlinux.org, pour connaître leur dernière version (règle LNX-MAJ-006
  et mises à jour de l'AUR) ; sans cet accord, ces paquets ne sont pas vérifiés, ce qui est dit.
- **Après accord** : l'adresse courriel aux services qui cherchent ses fuites, l'adresse Internet publique aux quatre
  listes noires (Spamhaus, SpamCop, DroneBL, PSBL), le nom du domaine d'un lien examiné.
- **Un mot de passe vérifié** : seuls 5 caractères de son empreinte, à Have I Been Pwned ; jamais le mot de passe.
- **Avec une clé abuse.ch** : la clé, à abuse.ch.
- **En mode Wi-Fi public** : les requêtes DNS, au Bouclier canadien de l'ACEI.
- **La recherche de mise à jour** : une demande à GitHub.
- Un rapport de faille préparé par Vanguard n'est jamais envoyé par lui : la personne le relit et l'envoie elle-même.

Cette liste est fermée : Vanguard refuse de joindre en HTTPS un hôte qui n'est pas dans le premier tableau (même au
bout d'une redirection), et un test du dépôt échoue si le code nomme une destination absente de ces tableaux, ou si
un tableau en nomme une que le code ne joint plus. Un proxy réglé dans le système reçoit les connexions HTTPS de
Vanguard (le chiffrement reste de bout en bout jusqu'au site) ; l'adresse publique jugée par les listes noires est
alors celle de sa sortie.

### Sites joints en HTTPS

| Site | Pour quoi | Ce qui part |
|---|---|---|
| `api.pwnedpasswords.com` | Mot de passe vérifié | 5 caractères de son empreinte |
| `haveibeenpwned.com`, `api.xposedornot.com` | Fuites d'une adresse courriel, après accord (le premier avec une clé) | L'adresse courriel ; la clé de Have I Been Pwned |
| `mb-api.abuse.ch`, `threatfox-api.abuse.ch`, `urlhaus-api.abuse.ch` | Listes de MalwareBazaar, ThreatFox et URLhaus | La clé abuse.ch |
| `feodotracker.abuse.ch` | Serveurs de botnets | Rien |
| `raw.githubusercontent.com` | Indicateurs de logiciels espions (Échap) | Rien |
| `www.cisa.gov` | Failles exploitées (KEV) | Rien |
| `www.loldrivers.io` | Pilotes vulnérables | Rien |
| `armmf.adobe.com`, `clients.config.office.net`, `edgeupdates.microsoft.com`, `res.public.onecdn.static.microsoft`, `product-details.mozilla.org`, `versionhistory.googleapis.com`, `versions.brave.com`, `slack.com`, `formulae.brew.sh`, `endoflife.date`, `codeload.github.com` | Dernières versions des logiciels et avis de sécurité, listes entières | Rien |
| `aur.archlinux.org` | Paquets de l'AUR, après accord | Le nom des paquets installés hors des dépôts officiels |
| `github.com`, `release-assets.githubusercontent.com`, `objects.githubusercontent.com` | Mise à jour de Vanguard, pages d'aide tldr | Rien |
| `rdap.org` | Âge du domaine d'un lien examiné, après accord | Le nom de domaine ; rdap.org renvoie la demande au registre du domaine (un seul saut, en HTTPS), seule redirection permise hors de ce tableau |
| `1.1.1.1` | Adresse Internet publique (listes noires), certificat présenté (HTTPS intercepté) | Rien |
| `speed.cloudflare.com` | Débit de la connexion, sur demande | Des octets sans contenu, reçus puis envoyés : environ 500 Mo au plus dans chaque sens |

### Connexions directes

| Destination | Pour quoi | Ce qui part |
|---|---|---|
| `1.1.1.1`, `1.0.0.1`, `2606:4700:4700::1111`, `2606:4700:4700::1001` (Cloudflare), `9.9.9.9`, `149.112.112.112`, `2620:fe::fe`, `2620:fe::9` (Quad9), `8.8.8.8`, `8.8.4.4`, `2001:4860:4860::8888`, `2001:4860:4860::8844` (Google), `94.140.14.14`, `94.140.15.15`, `2a10:50c0::ad1:ff`, `2a10:50c0::ad2:ff` (AdGuard), `149.112.121.20`, `149.112.122.20`, `2620:10a:80bb::20`, `2620:10a:80bc::20` (Bouclier canadien) | DNS le plus rapide (questions DNS) ; audit DNS et « Pas d'Internet » (Cloudflare, Quad9, Google) : la connexion s'établit-elle, en TCP 443 ? qualité de la connexion et sonde post-quantique vers `1.1.1.1` | Des noms courants, les mêmes pour tous ; l'adresse Internet publique, comme à tout site |
| `www.amazon.com`, `www.apple.com`, `www.google.com`, `www.microsoft.com`, `www.wikipedia.org`, `www.youtube.com`, `www.example.com` | Noms demandés pour mesurer ou vérifier le DNS | Le nom, au DNS |
| `one.one.one.one`, `dns.google`, `dns.quad9.net`, `internetsociety.org`, `dnssec-failed.org` | Audit DNS : réponses connues, DNSSEC | Le nom, au DNS utilisé |
| `stun.cloudflare.com`, `stun.l.google.com`, `stun1.l.google.com` | Type de NAT, et adresse vue d'Internet à chaque audit complet du réseau (jamais hors ligne) | L'adresse Internet publique et le port, comme à tout site |
| `zen.spamhaus.org`, `bl.spamcop.net`, `dnsbl.dronebl.org`, `psbl.surriel.com` | Listes noires d'adresses, après accord | L'adresse Internet publique, dans une question DNS |
| `dbl.spamhaus.org`, `multi.surbl.org`, `dbltest.com`, `test.surbl.org` | Listes noires de domaines, pour un lien examiné, après accord (et leur nom de test) | Le nom de domaine, dans une question DNS |

Le bilan demande aussi au DNS du système un nom tiré au hasard sous .com, qui ne nomme pas Vanguard (le DNS
invente-t-il des réponses ?), sauf hors ligne. Les noms des sites de ces tableaux passent par le DNS du système,
comme pour tout programme ; en mode Wi-Fi public (et après accord dans « DNS le plus rapide »), ce DNS devient le
Bouclier canadien ou le DNS choisi, pour tout l'ordinateur. La liste des connexions sortantes demande à ce DNS le
nom inverse de chaque adresse distante. Le reste des connexions directes reste sur le réseau local : la box (UPnP, sondes SSH et HTTPS), les imprimantes,
les caméras, le balayage des appareils, LLMNR et mDNS.

### Programmes lancés par Vanguard

Pendant le bilan, sans accord à part, Vanguard demande les mises à jour en attente aux outils du système, qui
interrogent leurs dépôts : checkupdates, dnf, apt, zypper, flatpak, snap, fwupdmgr (micrologiciels, LVFS),
softwareupdate et mas (Apple) ; yay ou paru seulement avec l'accord pour l'AUR. Sur demande ou après accord, il lance
des programmes qui joignent leurs propres serveurs : le gestionnaire de paquets (pacman, apt, dnf, winget), flatpak
(`dl.flathub.org`), Homebrew et son installation (`brew.sh`, script tiré de raw.githubusercontent.com), freshclam
pour ClamAV, la mise à jour des signatures de Defender, trivy pour les conteneurs (sa base de failles), l'installation
de Rosetta ; nmap, lui, n'interroge que les appareils du réseau local. Une page ouverte dans le navigateur après
accord (pages de « Signaler », portail du Wi-Fi public : l'adresse de la sonde du système, celle de NetworkManager
sous Linux, montrée avant) est jointe par le navigateur. Une extension ajoutée par la personne a le réseau de
l'ordinateur, sauf lancée isolée (Linux, macOS). Ces destinations dépendent de ces programmes, pas de Vanguard.

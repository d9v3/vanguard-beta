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
- **Le système répond juste au moment du bilan.** Un poste déjà compromis en administrateur peut tromper toutes ses
  lectures (voir plus haut).
- **Les listes et les outils tiers sont justes.** Les listes de menaces, de versions et de failles (abuse.ch, CISA,
  éditeurs) et les outils que Vanguard lance sans les avoir écrits (ClamAV, trivy, gitleaks) sont crus tels quels ;
  une liste trop vieille est dite non vérifiée.
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

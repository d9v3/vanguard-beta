//! La régression de détection : un corpus de cas fabriqués et inoffensifs (tests/corpus-detection/<ID>/) prouve que
//! chaque règle de détection tire encore. Pourquoi : `toute_regle_muette_ou_plantee_dit_non_verifie` garde qu'une
//! règle parle, pas qu'elle voit ; une règle débranchée (qui ne rend plus que « sain ») ou un motif retiré passaient
//! la vérification complète. Ici, chaque cas appelle la fonction de jugement de sa règle avec des données fabriquées
//! (`fabrique.txt`) et exige un constat d'au moins la gravité attendue, qui nomme ce que le cas a fabriqué ; le même
//! cas propre (`propre.txt`) exige qu'elle se taise.
//!
//! Le cas juge, il ne lit pas le système : la lecture reste aux règles, et les tests ne touchent jamais les vraies
//! données. Une règle dont le jugement n'est pas encore à part attend son extraction (lot S3b), un outil son cas
//! (lot S3c) ; une règle qu'on ne peut pas exercer hors ligne, sans moteur externe ni contenu d'attaque, est
//! exemptée avec sa raison. La liste est fermée : chaque règle qui cite une technique d'ATT&CK (T…), et chaque outil
//! qui détecte, a son cas ou sa raison, et une raison qui ne sert plus fait échouer.
//!
//! Les règles de durcissement (une mesure M… : pare-feu allumé, chiffrement du disque, réglage du noyau) restent hors
//! du corpus : elles lisent un réglage, pas une attaque, et `toute_regle_muette_ou_plantee_dit_non_verifie` les garde.
//!
//! Le cas juge, il ne suit pas la règle jusqu'à son jugement : une règle dont le `regle!` n'appellerait plus ce
//! jugement passerait. `chaque_regle_du_corpus_mene_a_son_jugement` tient ce fil dans le texte des sources (`FILS`),
//! grossièrement mais sûrement ; le suivre en vrai, sur une racine fabriquée, est l'affaire de S3b.
//!
//! Où tournent les cas : Linux ici et dans la CI, Windows sous Wine (verifier.sh complet) et sur le vrai Windows de
//! la CI (cargo test de ci.yml), macOS sur le Mac de GitHub (macos.yml). En `--ci`, verifier.sh ne lance pas Wine.
//!
//! Un dossier de cas : `attendu.toml` (la gravité exacte du cas fabriqué, mots attendus, ce que le cas propre peut
//! dire au plus, systèmes où il tourne), `fabrique.txt` et `propre.txt` (les données, au format que lit l'adaptateur de la règle).
//! Les adaptateurs sont près des règles (une table `CAS` par système, dans `machine::…::corpus`), là où le jugement
//! est visible. Rien qui ressemble à une signature (EICAR, motif YARA) n'y est écrit d'un bloc : assemblé à
//! l'exécution, comme dans analyse/tests.rs.

use std::collections::BTreeSet;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};

use crate::machine::Constat;
use crate::risk::Niveau;

/// Les données d'un cas, telles que l'adaptateur de la règle les lit.
pub(crate) struct Entree {
    /// Le dossier du cas (des fichiers fabriqués peuvent s'y trouver à côté des données).
    pub dossier: PathBuf,
    pub texte: String,
}

impl Entree {
    /// Les lignes utiles : sans blancs autour, ni vides, ni commentaires (« # »).
    pub(crate) fn lignes(&self) -> Vec<&str> {
        self.texte
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    }

    /// Les lignes coupées à « | ».
    pub(crate) fn champs(&self) -> Vec<Vec<&str>> {
        self.lignes().into_iter().map(|l| l.split('|').collect()).collect()
    }

    /// Les champs des lignes qui commencent par `genre|`, sans lui.
    pub(crate) fn de(&self, genre: &str) -> Vec<Vec<&str>> {
        self.champs()
            .into_iter()
            .filter(|c| c.first() == Some(&genre))
            .map(|c| c[1..].to_vec())
            .collect()
    }

    /// Un dossier jetable à ce cas, vide, hors du dépôt : pour les jugements qui lisent des fichiers posés exprès.
    /// Effacé quand il n'est plus tenu, même si le jugement panique.
    #[cfg(unix)]
    pub(crate) fn jetable(&self, nom: &str) -> Jetable {
        let cas = self
            .dossier
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let d = std::env::temp_dir().join(format!("vanguard-corpus-{}-{cas}-{nom}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Jetable(d)
    }
}

/// Un dossier jetable, effacé à la fin de sa portée (`Entree::jetable`).
#[cfg(unix)]
pub(crate) struct Jetable(PathBuf);

#[cfg(unix)]
impl std::ops::Deref for Jetable {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

#[cfg(unix)]
impl Drop for Jetable {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Le niveau donné à une notification de la surveillance (ou d'un outil qui signale sans niveau, comme une fuite de
/// secret) quand un cas en fait un constat : elle n'en a pas à l'écran, et une notification est une alerte que la
/// personne voit sur-le-champ. Fixé ici une fois, pour tous les cas. Pour ces cas (SUR-…, PRO-GIT-001), la « gravité
/// exacte » ne garde donc rien : le corpus prouve que l'alerte part, pas son niveau, et c'est le cas propre (posé
/// juste sous le seuil) qui tient les seuils internes.
pub(crate) const NIVEAU_D_UNE_NOTIFICATION: Niveau = Niveau::Eleve;

/// Une notification (titre, texte) en constat, au niveau fixé ci-dessus.
pub(crate) fn notification(titre: &str, texte: &str) -> Constat {
    crate::machine::alerte("Surveillance", NIVEAU_D_UNE_NOTIFICATION, format!("{titre} : {texte}"))
}

/// L'adaptateur d'une règle : ses données fabriquées données à sa fonction de jugement.
pub(crate) type Juge = fn(&Entree) -> Vec<Constat>;

/// Ce système, comme `attendu.toml` le nomme.
fn ce_systeme() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

/// Les cas qui tournent ici, de toutes les tables.
fn tous_les_cas() -> Vec<(&'static str, Juge)> {
    let mut cas: Vec<(&'static str, Juge)> = Vec::new();
    cas.extend_from_slice(crate::machine::corpus::CAS);
    #[cfg(target_os = "linux")]
    cas.extend_from_slice(crate::machine::linux::corpus::CAS);
    #[cfg(windows)]
    cas.extend_from_slice(crate::machine::windows::corpus::CAS);
    #[cfg(target_os = "macos")]
    cas.extend_from_slice(crate::machine::macos::corpus::CAS);
    cas.extend_from_slice(crate::journaux_windows::regles::corpus::CAS);
    cas.extend_from_slice(crate::audit::corpus::CAS);
    cas.extend_from_slice(CAS_DES_OUTILS);
    cas
}

/// Les cas des outils et des surveillances du registre (modele/registre.rs), dont les adaptateurs sont dans leur
/// module.
const CAS_DES_OUTILS: &[(&str, Juge)] = &[
    ("PRO-TEL-001", crate::protection::telechargement::corpus_nature),
    ("SUR-TEL-001", crate::protection::telechargement::corpus_signalements),
    ("PRO-LIE-001", crate::protection::lien::corpus),
    ("PRO-COU-001", crate::protection::courriel_suspect::corpus),
    ("PRO-ESP-001", crate::protection::espions::corpus),
    #[cfg(unix)]
    ("PRO-DIS-001", crate::protection::distance::corpus),
    ("PRO-GIT-001", crate::protection::secrets_git::corpus),
    ("SUR-BOT-001", crate::protection::sortantes::corpus_botnets),
    ("SUR-FIC-001", crate::protection::integrite::corpus_signaler),
    ("SUR-PAS-001", crate::reseau::surveillance::corpus_passerelle),
    ("SUR-WIF-001", crate::reseau::surveillance::corpus_audit),
    ("SUR-APP-001", crate::reseau::surveillance::corpus),
    ("SUR-PRT-001", crate::reseau::surveillance::corpus),
    ("SUR-EMP-001", crate::reseau::surveillance::corpus),
];

// ───────────────────────────── La liste fermée ─────────────────────────────

/// Les outils du registre (modele/registre.rs) qui ne détectent rien, avec leur raison : tous les autres doivent avoir
/// leur cas, leur exemption ou leur attente. Un nouvel outil doit choisir.
const NE_DETECTENT_PAS: &[(&str, &str)] = &[
    (
        "PRO-CAM-001",
        "inventaire : montre qui se sert de la caméra et du micro, sans juger",
    ),
    ("PRO-ACC-001", "inventaire des accès des applications à la vie privée"),
    ("PRO-DIA-001", "diagnostic du matériel et du système"),
    ("PRO-LEN-001", "ce qui rend l'ordinateur lent"),
    ("PRO-CNX-001", "test de connexion pour le jeu"),
    ("PRO-OBJ-001", "inventaire du dernier scan du réseau"),
    (
        "PRO-EVT-001",
        "le moteur des règles EVT-, dont chaque règle a sa ligne ici",
    ),
    (
        "SUR-MAC-001",
        "reprend les constats du bilan, que les cas de leurs règles gardent",
    ),
    ("AUT-VAN-001", "autodiagnostic de Vanguard lui-même"),
];

/// Les règles de détection qu'aucun cas n'exerce, pour de bon, avec leur raison.
const EXEMPTEES: &[(&str, &str)] = &[
    (
        "PRO-ANV-001",
        "le moteur est ClamAV ou Defender, externes par décision : EICAR y est essayé dans la VM et par outils/test-linux/essai.sh",
    ),
    ("PRO-CTN-001", "le jugement est celui de trivy, un programme externe"),
    (
        "PRO-LNO-001",
        "la liste noire DNS s'interroge en direct : rien à juger hors ligne",
    ),
    (
        "PRO-PER-001",
        "les failles exploitées viennent du catalogue KEV, lu en ligne",
    ),
    (
        "VEI-RAN-001",
        "surveillance comportementale en direct, hors du corpus de données fabriquées ; ses propres tests la gardent",
    ),
    (
        "VEI-RAN-002",
        "surveillance comportementale en direct, hors du corpus de données fabriquées ; ses propres tests la gardent",
    ),
    (
        "VEI-RAN-003",
        "surveillance comportementale en direct, hors du corpus de données fabriquées ; ses propres tests la gardent",
    ),
    (
        "VEI-EXF-001",
        "surveillance comportementale en direct, hors du corpus de données fabriquées ; ses propres tests la gardent",
    ),
    (
        "VEI-PRG-001",
        "le veilleur du noyau (Linux) juge en direct ce qu'il voit passer, hors du corpus ; ses propres tests le gardent",
    ),
    (
        "SUR-BLO-001",
        "la protection active agit (arrêt, blocage) : son jugement n'est pas séparé de ses gestes ; ses propres tests la gardent",
    ),
    (
        "PRO-YAR-001",
        "laissé hors du corpus après deux arrêts du filtre de sécurité ; le moteur YARA est comparé à YARA-X par ses tests",
    ),
    (
        "PRO-MEM-001",
        "laissé hors du corpus après deux arrêts du filtre de sécurité ; le moteur YARA est comparé à YARA-X par ses tests",
    ),
    (
        "VEI-CNX-001",
        "laissé hors du corpus après deux arrêts du filtre de sécurité ; ses propres tests le gardent",
    ),
    (
        "PRO-SOR-001",
        "ses jugements hors botnets (dossier à risque, port suspect) n'ont pas d'identifiant de règle à eux ; les serveurs de commande sont exercés par SUR-BOT-001",
    ),
];

/// Les cas dont le propre ne peut rendre aucun constat vérifié, avec leur raison : la règle dit toujours ce qu'elle ne
/// lit pas, et rien d'autre quand tout est sain. Leur propre doit quand même rendre quelque chose (jamais rien), sous
/// réserve ; leur cas fabriqué, lui, prouve que la règle tire. Une entrée sans `reserve` dans son attendu.toml, ou
/// sans cas, fait échouer.
const PROPRES_SANS_VERIFIE: &[(&str, &str)] = &[(
    "COM-TLS-003",
    "sans politique de Firefox qui ajoute un certificat, la règle ne rend que « magasin des navigateurs non lisible sans NSS », non vérifié ; un constat sain demanderait de changer la production",
)];

/// Les règles qui attendent l'extraction de leur jugement : vidée par le lot S3b, gardée pour qu'une règle de détection
/// nouvelle, dont le jugement n'est pas encore à part, s'y inscrive avec sa raison. Une entrée qui a son cas fait échouer.
const EN_ATTENTE_S3B: &[(&str, &str)] = &[];

/// Les outils et surveillances qui attendent leur cas : vidée par le lot S3c, gardée pour un outil nouveau qui s'y
/// inscrit le temps d'avoir le sien. Une entrée qui a son cas fait échouer.
const EN_ATTENTE_S3C: &[&str] = &[];

/// Le fil de chaque règle du bilan qui a un cas, de son `regle!` au jugement que son adaptateur appelle : la première
/// fonction est nommée dans le bloc `regle!`, chacune appelle la suivante (fichier sous src/, nom). Plusieurs
/// fonctions du même nom dans le fichier (une par système) : chacune, hors des essais, doit appeler la suivante ; la
/// version d'un système débranchée resterait sinon verte grâce à celle d'un autre.
const FILS: &[(&str, &[(&str, &str)])] = &[
    (
        "COM-CPT-001",
        &[
            ("machine/administrateurs.rs", "constat"),
            ("machine/administrateurs.rs", "juger"),
        ],
    ),
    (
        "COM-CPT-003",
        &[
            ("machine/chasse.rs", "connexion_forcee"),
            ("machine/chasse.rs", "juger_lues"),
            ("machine/chasse.rs", "juger_intrusions"),
        ],
    ),
    // Le lecteur du même fil, une version par système : chacune doit mener à sa lecture du journal.
    (
        "COM-CPT-003",
        &[
            ("machine/chasse.rs", "connexion_forcee"),
            ("machine/chasse.rs", "tentatives_lues@linux"),
            ("machine/linux/mod.rs", "tentatives_ssh_lues"),
            ("machine/linux/mod.rs", "tentatives_ssh"),
        ],
    ),
    (
        "COM-CPT-003",
        &[
            ("machine/chasse.rs", "connexion_forcee"),
            ("machine/chasse.rs", "tentatives_lues@windows"),
            ("machine/windows/evenements.rs", "tentatives_lues"),
        ],
    ),
    (
        "COM-CPT-003",
        &[
            ("machine/chasse.rs", "connexion_forcee"),
            ("machine/chasse.rs", "tentatives_lues@macos"),
            ("machine/chasse.rs", "tentatives_sans_journal"),
        ],
    ),
    // Linux passe par la lecture des fichiers d'ancres (un fichier sans nom y a son constat) ; Windows et macOS
    // jugent directement ce que leur magasin nomme.
    (
        "COM-CRT-001",
        &[
            ("machine/certificats.rs", "certificats@linux"),
            ("machine/certificats.rs", "certificats_dans"),
            ("machine/certificats.rs", "ancres"),
            ("machine/certificats.rs", "juger"),
        ],
    ),
    (
        "COM-CRT-001",
        &[
            ("machine/certificats.rs", "certificats@windows"),
            ("machine/certificats.rs", "juger"),
        ],
    ),
    (
        "COM-CRT-001",
        &[
            ("machine/certificats.rs", "certificats@macos"),
            ("machine/certificats.rs", "juger"),
        ],
    ),
    (
        "COM-DIS-001",
        &[
            ("protection/distance.rs", "constats"),
            ("protection/distance.rs", "juger"),
        ],
    ),
    (
        "COM-INT-002",
        &[("protection/pieges.rs", "constat"), ("protection/pieges.rs", "juger")],
    ),
    (
        "COM-JRN-001",
        &[
            ("machine/journaux.rs", "journaux@windows"),
            ("machine/journaux.rs", "juger_effacements"),
        ],
    ),
    (
        "COM-NAV-001",
        &[
            ("machine/extensions.rs", "extensions"),
            ("machine/extensions.rs", "juger"),
        ],
    ),
    (
        "COM-PRG-001",
        &[
            ("machine/chasse.rs", "programmes_suspects"),
            ("machine/chasse.rs", "juger_programmes"),
        ],
    ),
    (
        "LNX-PRV-004",
        &[
            ("machine/linux/privileges.rs", "dossiers_de_commandes"),
            ("machine/unix.rs", "dossiers_de_commandes"),
            ("machine/unix.rs", "juger_dossiers_de_commandes"),
        ],
    ),
    (
        "MAC-PRV-004",
        &[
            ("machine/macos/privileges.rs", "dossiers_de_commandes"),
            ("machine/unix.rs", "dossiers_de_commandes"),
            ("machine/unix.rs", "juger_dossiers_de_commandes"),
        ],
    ),
    (
        "LNX-PRS-003",
        &[
            ("machine/linux/dissimulation.rs", "processus_caches"),
            ("machine/linux/dissimulation.rs", "juger_processus_caches"),
        ],
    ),
    (
        "LNX-PRS-004",
        &[
            ("machine/linux/dissimulation.rs", "programmes_sans_fichier"),
            ("machine/linux/dissimulation.rs", "juger_sans_fichier"),
        ],
    ),
    (
        "LNX-NOY-006",
        &[
            ("machine/linux/dissimulation.rs", "modules_du_noyau"),
            ("machine/linux/dissimulation.rs", "juger_modules"),
        ],
    ),
    (
        "LNX-RES-002",
        &[
            ("machine/linux/dissimulation.rs", "ecoute_du_reseau"),
            ("machine/linux/dissimulation.rs", "juger_ecoute"),
        ],
    ),
    (
        "MAC-PRS-002",
        &[
            ("machine/macos/parite.rs", "elements_d_ouverture"),
            ("machine/macos/parite.rs", "juger_btm"),
        ],
    ),
    (
        "MAC-PRS-003",
        &[
            ("machine/macos/parite.rs", "crochets_et_extensions"),
            ("machine/macos/parite.rs", "juger_crochets"),
        ],
    ),
    (
        "WIN-ANV-002",
        &[
            ("machine/windows/exclusions.rs", "exclusions"),
            ("machine/windows/exclusions.rs", "juger"),
        ],
    ),
    (
        "WIN-PRS-002",
        &[
            ("machine/windows/portes.rs", "ifeo"),
            ("machine/windows/portes.rs", "juger_ifeo"),
        ],
    ),
    (
        "WIN-PRS-003",
        &[
            ("machine/windows/portes.rs", "programmes_remplaces"),
            ("machine/windows/portes.rs", "juger_remplaces"),
        ],
    ),
    (
        "WIN-PRS-004",
        &[
            ("machine/windows/portes.rs", "winlogon"),
            ("machine/windows/portes.rs", "juger_winlogon"),
        ],
    ),
    (
        "WIN-PRS-005",
        &[
            ("machine/windows/portes.rs", "appinit"),
            ("machine/windows/portes.rs", "juger_appinit"),
        ],
    ),
    ("WIN-PRS-006", &[("machine/windows/portes.rs", "juger_wmi")]),
    (
        "WIN-PRS-007",
        &[
            ("machine/windows/ancrages.rs", "lsa"),
            ("machine/windows/ancrages.rs", "juger_lsa"),
        ],
    ),
    (
        "WIN-PRS-008",
        &[
            ("machine/windows/ancrages.rs", "appcert"),
            ("machine/windows/ancrages.rs", "juger_appcert"),
        ],
    ),
    (
        "WIN-PRS-009",
        &[
            ("machine/windows/ancrages.rs", "moniteurs_impression"),
            ("machine/windows/ancrages.rs", "juger_dlls"),
        ],
    ),
    (
        "WIN-PRS-010",
        &[
            ("machine/windows/ancrages.rs", "fournisseurs_de_temps"),
            ("machine/windows/ancrages.rs", "juger_dlls"),
        ],
    ),
    (
        "WIN-PRS-011",
        &[
            ("machine/windows/ancrages.rs", "catalogue_winsock"),
            ("machine/windows/ancrages.rs", "juger_winsock"),
            ("machine/windows/ancrages.rs", "juger_dlls"),
        ],
    ),
    (
        "WIN-PRS-012",
        &[
            ("machine/windows/pilotes.rs", "pilotes"),
            ("machine/windows/pilotes.rs", "juger_pilotes"),
        ],
    ),
    (
        "WIN-SRV-001",
        &[
            ("machine/windows/services.rs", "services_sans_guillemets"),
            ("machine/windows/services.rs", "juger"),
        ],
    ),
    (
        "WIN-PRS-001",
        &[
            ("machine/windows/persistance.rs", "persistance"),
            ("machine/windows/persistance.rs", "juger_persistance"),
        ],
    ),
    (
        "WIN-JRN-003",
        &[
            ("machine/windows/evenements.rs", "juger_par_les_regles"),
            ("journaux_windows/regles/resultat.rs", "constats_du_bilan"),
        ],
    ),
    (
        "LNX-PRS-001",
        &[
            ("machine/linux/persistance.rs", "fichiers_suspects"),
            ("machine/linux/persistance.rs", "juger_fichiers_suspects"),
        ],
    ),
    (
        "LNX-PRS-002",
        &[
            ("machine/linux/persistance.rs", "persistance"),
            ("machine/linux/persistance.rs", "persistance_dans"),
        ],
    ),
    (
        "LNX-CPT-001",
        &[
            ("machine/linux/mod.rs", "comptes"),
            ("machine/linux/mod.rs", "juger_comptes"),
        ],
    ),
    (
        "LNX-SSH-002",
        &[
            ("machine/linux/mod.rs", "ssh_echecs"),
            ("machine/linux/mod.rs", "juger_echecs_ssh"),
        ],
    ),
    (
        "LNX-PRV-003",
        &[
            ("machine/linux/privileges.rs", "sudo_sans_mot_de_passe"),
            ("machine/unix.rs", "sudo_sans_mot_de_passe"),
            ("machine/unix.rs", "juger_sudo"),
        ],
    ),
    (
        "MAC-PRV-002",
        &[
            ("machine/macos/privileges.rs", "sudo_sans_mot_de_passe"),
            ("machine/unix.rs", "sudo_sans_mot_de_passe"),
            ("machine/unix.rs", "juger_sudo"),
        ],
    ),
    (
        "MAC-PRS-001",
        &[
            ("machine/macos/persistance.rs", "persistance"),
            ("machine/macos/persistance.rs", "persistance_dans"),
        ],
    ),
    (
        "MAC-SYS-003",
        &[
            ("machine/macos/durcissement.rs", "extensions_tierces"),
            ("machine/macos/durcissement.rs", "juger_extensions"),
        ],
    ),
    (
        "COM-INT-001",
        &[
            ("protection/integrite.rs", "constat"),
            ("protection/integrite.rs", "constat_de"),
        ],
    ),
    // Les fiches de l'audit du réseau n'ont pas de regle! : leur fil part du `constats` de leur domaine, et la fiche
    // doit être déclarée dans audit/fiches.rs.
    (
        "COM-ARP-002",
        &[("audit/arp.rs", "constats"), ("audit/arp.rs", "mac_de_la_box_changee")],
    ),
    (
        "COM-ARP-004",
        &[
            ("audit/arp.rs", "constats"),
            ("audit/arp.rs", "mac_pour_plusieurs_adresses"),
        ],
    ),
    (
        "COM-SEG-004",
        &[
            ("audit/segmentation.rs", "constats"),
            ("audit/segmentation.rs", "serveur_dhcp"),
        ],
    ),
    (
        "COM-SEG-005",
        &[
            ("audit/segmentation.rs", "constats"),
            ("audit/segmentation.rs", "deux_routeurs_ipv6"),
        ],
    ),
    (
        "COM-PST-003",
        &[("audit/postes.rs", "constats"), ("audit/postes.rs", "empoisonneur")],
    ),
    (
        "COM-WIF-003",
        &[("audit/wifi.rs", "constats"), ("audit/wifi.rs", "emetteurs")],
    ),
    (
        "COM-DNS-004",
        &[
            ("audit/dns_tls.rs", "constats"),
            ("audit/dns_tls.rs", "constats_divergence"),
        ],
    ),
    (
        "COM-TLS-001",
        &[("audit/dns_tls.rs", "constats"), ("audit/dns_tls.rs", "constat_tls")],
    ),
    (
        "COM-TLS-003",
        &[
            ("audit/dns_tls.rs", "constats"),
            ("audit/dns_tls.rs", "constats_racines_navigateurs"),
        ],
    ),
    // L'usurpation de la box se dit au scan et à la surveillance, pas par une fiche jugée de l'audit.
    (
        "COM-ARP-001",
        &[
            ("reseau/surveillance.rs", "veiller_passerelle"),
            ("reseau/mod.rs", "usurpation_arp"),
        ],
    ),
    // Les outils du registre n'ont pas de regle! : leur fil part d'une fonction de leur module (modele/registre.rs).
    (
        "PRO-TEL-001",
        &[
            ("protection/telechargement.rs", "verifier"),
            ("protection/telechargement.rs", "verifier_le_nom"),
            ("protection/telechargement.rs", "nature"),
        ],
    ),
    (
        "SUR-TEL-001",
        &[
            ("protection/telechargement.rs", "nouveaux_a_signaler"),
            ("protection/telechargement.rs", "a_signaler"),
        ],
    ),
    (
        "PRO-LIE-001",
        &[("protection/lien.rs", "verifier"), ("protection/lien.rs", "examiner")],
    ),
    (
        "PRO-COU-001",
        &[
            ("protection/courriel_suspect/mod.rs", "verifier"),
            ("protection/courriel_suspect/mod.rs", "examiner"),
        ],
    ),
    (
        "PRO-ESP-001",
        &[
            ("protection/espions/mod.rs", "constats_avec"),
            ("protection/espions/mod.rs", "constats_de"),
        ],
    ),
    (
        "PRO-DIS-001",
        &[
            ("protection/distance.rs", "constats"),
            ("protection/distance.rs", "juger"),
        ],
    ),
    (
        "PRO-GIT-001",
        &[
            ("protection/secrets_git.rs", "lire_historique"),
            ("protection/secrets_git.rs", "secret"),
        ],
    ),
    (
        "SUR-BOT-001",
        &[
            ("protection/sortantes.rs", "botnets_en_cours"),
            ("protection/sortantes.rs", "serveur"),
        ],
    ),
    (
        "SUR-FIC-001",
        &[
            ("protection/integrite.rs", "changements_a_signaler"),
            ("protection/integrite.rs", "a_notifier"),
        ],
    ),
    (
        "SUR-PAS-001",
        &[
            ("reseau/surveillance.rs", "veiller_passerelle"),
            ("reseau/surveillance.rs", "mac_changee"),
        ],
    ),
    (
        "SUR-WIF-001",
        &[
            ("reseau/surveillance.rs", "veiller_audit"),
            ("reseau/surveillance.rs", "nouveautes_audit"),
        ],
    ),
    (
        "SUR-APP-001",
        &[
            ("reseau/surveillance.rs", "passe"),
            ("reseau/surveillance.rs", "alertes_du_scan"),
        ],
    ),
    (
        "SUR-PRT-001",
        &[
            ("reseau/surveillance.rs", "passe"),
            ("reseau/surveillance.rs", "alertes_du_scan"),
        ],
    ),
    (
        "SUR-EMP-001",
        &[
            ("reseau/surveillance.rs", "passe"),
            ("reseau/surveillance.rs", "alertes_du_scan"),
        ],
    ),
];

/// Ce que l'adaptateur recopie de la règle, parce que la règle le donne en appelant un jugement commun : le texte
/// doit en rester dans le corps de sa vérification (fichier, fonction, texte), sinon l'adaptateur jugerait autre chose.
const RECOPIES: &[(&str, &str, &str, &str)] = &[
    (
        "WIN-PRS-009",
        "machine/windows/ancrages.rs",
        "moniteurs_impression",
        "Niveau::Moyen",
    ),
    (
        "WIN-PRS-010",
        "machine/windows/ancrages.rs",
        "fournisseurs_de_temps",
        "Niveau::Moyen",
    ),
    (
        "WIN-PRS-011",
        "machine/windows/ancrages.rs",
        "juger_winsock",
        "Niveau::Info",
    ),
    ("COM-ARP-001", "reseau/mod.rs", "afficher_entete", "Niveau::Critique"),
];

/// Les règles qui citent une technique d'ATT&CK (T…), lues dans la carte que outils/couverture-attack.py tire des
/// sources (verifier.sh la garde à jour) : la liste vaut pour les trois systèmes, quel que soit celui qui compile.
fn regles_qui_detectent() -> BTreeSet<String> {
    include_str!("../../COUVERTURE-ATTACK.md")
        .lines()
        .filter(|l| l.starts_with("| T") || l.starts_with("| ↳ T"))
        .flat_map(|l| l.split('`').skip(1).step_by(2))
        .filter(|id| super::id::bien_forme(id))
        .map(str::to_string)
        .collect()
}

fn racine_du_corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus-detection")
}

/// Les dossiers de cas du corpus.
fn dossiers_de_cas() -> BTreeSet<String> {
    std::fs::read_dir(racine_du_corpus())
        .expect("tests/corpus-detection illisible")
        .flatten()
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect()
}

// ───────────────────────────── Ce qu'un cas attend ─────────────────────────────

/// Pourquoi un `attendu.toml` ne se lit pas.
#[derive(Debug)]
struct Refus(String);

impl From<&str> for Refus {
    fn from(t: &str) -> Refus {
        Refus(t.to_string())
    }
}

/// Ce que le cas propre doit rendre.
#[derive(Debug, PartialEq, Eq)]
enum Propre {
    /// Au moins un constat, tous vérifiés, au plus ce niveau (`None` : aucun problème).
    AuPlus(Option<Niveau>),
    /// Rien du tout : la règle se tait sans constat quand tout va bien, au bilan aussi (son jugement rend `None`).
    Rien,
}

#[derive(Debug)]
struct Attendu {
    /// La gravité exacte du constat que le cas fabriqué doit faire tirer : la plus haute qu'il rend.
    gravite: Niveau,
    /// Des mots des données fabriquées, que ce constat doit nommer (sans la casse) : il tire pour ce cas, pas par
    /// hasard. Jamais un mot du message traduit, qui changerait avec la langue.
    mots: Vec<String>,
    propre: Propre,
    /// Pourquoi le cas propre n'a pas de données, quand l'état sain est l'absence même (une clé que Windows laisse
    /// vide) ; sans elle, `propre.txt` doit en avoir.
    propre_vide: Option<String>,
    /// Ce que la règle dit toujours ne pas pouvoir lire (un magasin illisible sans outil) : le cas propre peut alors
    /// rendre aussi des constats non vérifiés, à côté des autres ; sans elle, tout doit y être vérifié.
    reserve: Option<String>,
    systemes: Vec<String>,
}

fn niveau(texte: &str) -> Option<Niveau> {
    Some(match texte {
        "info" => Niveau::Info,
        "moyen" => Niveau::Moyen,
        "eleve" => Niveau::Eleve,
        "critique" => Niveau::Critique,
        _ => return None,
    })
}

/// Une valeur `"texte"` ou `["a", "b"]` : le peu de TOML dont un cas a besoin, sans dépendance de plus. Les textes
/// se lisent jusqu'au guillemet suivant (une virgule y reste) ; rien d'autre n'est admis, pas même un commentaire.
fn valeurs(v: &str) -> Result<Vec<String>, Refus> {
    let (liste, mut reste) = match v.strip_prefix('[') {
        Some(r) => (
            true,
            r.strip_suffix(']').ok_or_else(|| {
                Refus(format!(
                    "« {v} » : une liste se ferme par « ] » (pas de commentaire en fin de ligne)"
                ))
            })?,
        ),
        None => (false, v),
    };
    let mut sortie = Vec::new();
    loop {
        reste = reste.trim_start();
        if reste.is_empty() {
            break;
        }
        let r = reste
            .strip_prefix('"')
            .ok_or_else(|| Refus(format!("« {v} » : un texte entre guillemets attendu")))?;
        let fin = r
            .find('"')
            .ok_or_else(|| Refus(format!("« {v} » : guillemet fermant manquant")))?;
        sortie.push(r[..fin].to_string());
        reste = r[fin + 1..].trim_start();
        if !reste.is_empty() {
            if !liste {
                return Err(Refus(format!(
                    "« {v} » : rien après le texte (pas de commentaire en fin de ligne)"
                )));
            }
            reste = reste
                .strip_prefix(',')
                .ok_or_else(|| Refus(format!("« {v} » : une virgule entre les textes")))?;
        }
    }
    if sortie.is_empty() && !liste {
        return Err(Refus(format!("« {v} » : un texte entre guillemets attendu")));
    }
    Ok(sortie)
}

fn lire_attendu(texte: &str) -> Result<Attendu, Refus> {
    let (mut gravite, mut mots, mut propre, mut propre_vide, mut systemes) = (None, Vec::new(), None, None, Vec::new());
    let mut reserve = None;
    let mut vues = BTreeSet::new();
    for ligne in texte
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let (cle, v) = ligne
            .split_once('=')
            .ok_or_else(|| Refus(format!("« {ligne} » : « clé = valeur » attendu")))?;
        let cle = cle.trim();
        if !vues.insert(cle.to_string()) {
            return Err(Refus(format!("clé en double : {cle}")));
        }
        let v = valeurs(v.trim())?;
        let seul = || v.first().cloned().unwrap_or_default();
        match cle {
            "gravite" => gravite = Some(niveau(&seul()).ok_or("gravite : info, moyen, eleve ou critique")?),
            "mots" => mots = v,
            "propre" => {
                propre = Some(match seul().as_str() {
                    "aucun" => Propre::AuPlus(None),
                    "info" => Propre::AuPlus(Some(Niveau::Info)),
                    "rien" => Propre::Rien,
                    _ => return Err("propre : aucun, info ou rien".into()),
                });
            }
            "propre_vide" => propre_vide = Some(seul()).filter(|r| !r.trim().is_empty()),
            "reserve" => reserve = Some(seul()).filter(|r| !r.trim().is_empty()),
            "systemes" => systemes = v,
            autre => return Err(Refus(format!("clé inconnue : {autre}"))),
        }
    }
    let gravite = gravite.ok_or("gravite manque")?;
    if mots.is_empty() || mots.iter().any(|m| m.trim().is_empty()) {
        return Err("mots manque : le constat doit nommer ce que le cas a fabriqué".into());
    }
    let propre = propre.ok_or("propre manque")?;
    // Le cas propre doit dire moins que le cas fabriqué, sinon rien ne distingue les deux : une règle qui ne rend
    // qu'une information (à reconnaître) se prouve par un propre muet.
    if let Propre::AuPlus(Some(plafond)) = propre
        && plafond >= gravite
    {
        return Err("propre : il doit rester sous la gravité du cas fabriqué".into());
    }
    if systemes.is_empty()
        || systemes
            .iter()
            .any(|s| !["linux", "windows", "macos"].contains(&s.as_str()))
    {
        return Err("systemes : linux, windows ou macos".into());
    }
    Ok(Attendu {
        gravite,
        mots,
        propre,
        propre_vide,
        reserve,
        systemes,
    })
}

fn montrer(constats: &[Constat]) -> String {
    constats
        .iter()
        .map(|c| format!("  {:?} vérifié={} : {}", c.probleme, c.verifie, c.message))
        .collect::<Vec<_>>()
        .join("\n")
}

/// L'adaptateur sur un fichier du cas ; une panique (une ligne mal formée : un champ qui manque, un nombre qui ne se
/// lit pas) devient une faute qui nomme le cas, sans arrêter les autres.
fn juger_le_fichier(id: &str, fichier: &str, juge: Juge, entree: &Entree) -> Result<Vec<Constat>, Refus> {
    std::panic::catch_unwind(AssertUnwindSafe(|| juge(entree))).map_err(|p| {
        let pourquoi = p
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| p.downcast_ref::<&str>().map(|s| (*s).to_string()))
            .unwrap_or_default();
        Refus(format!(
            "{id}/{fichier} : ligne mal formée ({pourquoi}) ; le format des lignes est dit dans la documentation de l'adaptateur de {id}"
        ))
    })
}

/// Le cas `id` jugé : ce qui ne va pas, ou `None`.
/// Le cas `id` jugé, chacune de ses variantes : le cas même (`attendu.toml`, `fabrique.txt`, `propre.txt`), puis
/// `attendu-2.toml`, `fabrique-2.txt`, `propre-2.txt`, et ainsi de suite. Une règle a souvent plusieurs branches : un
/// cas par branche les tient toutes. Une variante à moitié posée est une faute.
fn faute_du_cas(id: &str, juge: Juge) -> Option<String> {
    let dossier = racine_du_corpus().join(id);
    let mut fautes = Vec::new();
    for n in variantes(&dossier) {
        if let Some(f) = faute_de_la_variante(id, juge, &n) {
            fautes.push(f);
        }
    }
    (!fautes.is_empty()).then(|| fautes.join("\n"))
}

/// Les suffixes des variantes d'un dossier de cas : « » pour le cas même, puis « -2 », « -3 »… d'après les fichiers
/// présents (attendu, fabrique ou propre : un seul suffit à la déclarer, les deux autres manquants feront la faute).
fn variantes(dossier: &Path) -> Vec<String> {
    let mut n: BTreeSet<u32> = BTreeSet::new();
    for e in std::fs::read_dir(dossier).into_iter().flatten().flatten() {
        let nom = e.file_name().to_string_lossy().into_owned();
        let base = nom
            .strip_suffix(".toml")
            .or_else(|| nom.strip_suffix(".txt"))
            .unwrap_or("");
        if let Some((genre, chiffre)) = base.rsplit_once('-')
            && ["attendu", "fabrique", "propre"].contains(&genre)
            && let Ok(k) = chiffre.parse::<u32>()
        {
            n.insert(k);
        }
    }
    std::iter::once(String::new())
        .chain(n.into_iter().map(|k| format!("-{k}")))
        .collect()
}

fn faute_de_la_variante(id: &str, juge: Juge, n: &str) -> Option<String> {
    let dossier = racine_du_corpus().join(id);
    let lire = |f: &str| std::fs::read_to_string(dossier.join(f)).map_err(|e| format!("{id}/{f} : {e}"));
    let attendu = match lire(&format!("attendu{n}.toml"))
        .and_then(|t| lire_attendu(&t).map_err(|e| format!("{id}/attendu{n}.toml : {}", e.0)))
    {
        Ok(a) => a,
        Err(e) => return Some(e),
    };
    let entree = |f: &str| {
        lire(f).map(|texte| Entree {
            dossier: dossier.clone(),
            texte,
        })
    };
    let (fabrique, propre) = match (entree(&format!("fabrique{n}.txt")), entree(&format!("propre{n}.txt"))) {
        (Ok(f), Ok(p)) => (f, p),
        (Err(e), _) | (_, Err(e)) => return Some(e),
    };
    let tires = match juger_le_fichier(id, &format!("fabrique{n}.txt"), juge, &fabrique) {
        Ok(t) => t,
        Err(e) => return Some(e.0),
    };
    let nomme = |c: &Constat| {
        let m = c.message.to_lowercase();
        attendu.mots.iter().all(|mot| m.contains(&mot.to_lowercase()))
    };
    if !tires
        .iter()
        .any(|c| c.verifie && c.probleme >= Some(attendu.gravite) && nomme(c))
    {
        return Some(format!(
            "{id} ne tire plus : aucun constat d'au moins {:?} qui nomme {:?}\n{}",
            attendu.gravite,
            attendu.mots,
            montrer(&tires)
        ));
    }
    // La gravité attendue est la plus haute rendue : une baisse (élevé devenu moyen) se voit aussi.
    let pire = tires.iter().filter_map(|c| c.probleme).max();
    if pire > Some(attendu.gravite) {
        return Some(format!(
            "{id}/attendu.toml : gravite trop basse, le cas rend {pire:?} : la relever, pour qu'une baisse se voie"
        ));
    }
    match (&attendu.propre_vide, propre.lignes().is_empty()) {
        (None, true) => {
            return Some(format!(
                "{id}/propre.txt sans données : un cas propre doit montrer des données saines (ou propre_vide = \"raison\" quand l'état sain est l'absence même)"
            ));
        }
        (Some(_), false) => return Some(format!("{id} : propre.txt a des données, propre_vide est de trop")),
        _ => {}
    }
    let muets = match juger_le_fichier(id, &format!("propre{n}.txt"), juge, &propre) {
        Ok(m) => m,
        Err(e) => return Some(e.0),
    };
    let juste = match attendu.propre {
        Propre::Rien => muets.is_empty(),
        Propre::AuPlus(plafond) => {
            let sans_verifie = PROPRES_SANS_VERIFIE.iter().any(|(i, _)| *i == id);
            !muets.is_empty()
                && (sans_verifie || muets.iter().any(|c| c.verifie))
                && muets.iter().all(|c| {
                    if c.verifie {
                        c.probleme <= plafond
                    } else {
                        attendu.reserve.is_some()
                    }
                })
        }
    };
    if !juste {
        return Some(format!(
            "{id} : son cas propre devait rendre {:?} (au moins un constat, tous vérifiés, sauf « rien »)\n{}",
            attendu.propre,
            montrer(&muets)
        ));
    }
    None
}

#[test]
fn chaque_cas_du_corpus_tire() {
    let ici = ce_systeme();
    let cas = tous_les_cas();
    let mut fautes = Vec::new();
    let mut vus = BTreeSet::new();
    for (id, juge) in &cas {
        if !vus.insert(*id) {
            fautes.push(format!("{id} : deux adaptateurs"));
            continue;
        }
        if let Some(f) = faute_du_cas(id, *juge) {
            fautes.push(f);
        }
    }
    // Chaque cas qui dit tourner ici a son adaptateur ici, et aucun adaptateur ne tourne là où son cas ne le dit pas.
    // Un attendu.toml qui ne se lit pas est une faute, jamais un cas couvert.
    for d in dossiers_de_cas() {
        let attendu = std::fs::read_to_string(racine_du_corpus().join(&d).join("attendu.toml"))
            .map_err(|e| e.to_string())
            .and_then(|t| lire_attendu(&t).map_err(|e| e.0));
        let systemes = match attendu {
            Ok(a) => a.systemes,
            Err(e) => {
                if !vus.contains(d.as_str()) {
                    fautes.push(format!("{d}/attendu.toml : {e}"));
                }
                continue;
            }
        };
        let ici_attendu = systemes.iter().any(|s| s == ici);
        match (ici_attendu, vus.contains(d.as_str())) {
            (true, false) => fautes.push(format!("{d} : son cas dit {ici}, aucun adaptateur ici")),
            (false, true) => fautes.push(format!("{d} : un adaptateur ici, son cas ne dit pas {ici}")),
            _ => {}
        }
    }
    for id in &vus {
        if !racine_du_corpus().join(id).is_dir() {
            fautes.push(format!("{id} : un adaptateur sans dossier de cas"));
        }
    }
    assert!(fautes.is_empty(), "corpus de détection :\n{}", fautes.join("\n"));
    // La ligne que verifier.sh exige et montre au résumé (étape « régression de détection »).
    println!(
        "corpus de détection ({ici}) : {} règles tirent, {} exemptées, {} en attente de S3b, {} de S3c",
        vus.len(),
        EXEMPTEES.len(),
        EN_ATTENTE_S3B.len(),
        EN_ATTENTE_S3C.len()
    );
}

#[test]
fn chaque_regle_de_detection_a_son_cas() {
    let outils: Vec<&str> = super::registre::OUTILS.iter().map(|o| o.id).collect();
    let mut fautes = Vec::new();
    for (id, _) in NE_DETECTENT_PAS {
        if !outils.contains(id) {
            fautes.push(format!("{id} (NE_DETECTENT_PAS) n'est plus un outil du registre"));
        }
    }
    let detectent: BTreeSet<String> = regles_qui_detectent()
        .into_iter()
        .chain(
            outils
                .iter()
                .filter(|id| !NE_DETECTENT_PAS.iter().any(|(n, _)| n == *id))
                .map(|s| (*s).to_string()),
        )
        .collect();
    // La carte doit compter : un format changé qui ne rendrait plus rien viderait la liste sans bruit.
    assert!(regles_qui_detectent().len() >= 60, "carte ATT&CK mal lue");
    let cas = dossiers_de_cas();
    let mises_a_part: Vec<(&str, &str)> = EXEMPTEES
        .iter()
        .map(|(id, _)| (*id, "EXEMPTEES"))
        .chain(EN_ATTENTE_S3B.iter().map(|(id, _)| (*id, "EN_ATTENTE_S3B")))
        .chain(EN_ATTENTE_S3C.iter().map(|id| (*id, "EN_ATTENTE_S3C")))
        .collect();
    let connues: BTreeSet<&str> = include_str!("../../tests/regles-connues.txt")
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let mut mots = l.split_whitespace();
            let id = mots.next()?;
            (!mots.any(|m| m == "retire")).then_some(id)
        })
        .collect();
    for id in &detectent {
        let ou: Vec<&str> = mises_a_part.iter().filter(|(i, _)| i == id).map(|(_, l)| *l).collect();
        match (cas.contains(id), ou.as_slice()) {
            (true, []) | (false, [_]) => {}
            (false, []) => fautes.push(format!(
                "{id} détecte sans cas : poser tests/corpus-detection/{id}/, ou le mettre dans EXEMPTEES avec sa raison (un outil qui ne détecte pas : NE_DETECTENT_PAS)"
            )),
            (true, l) => fautes.push(format!("{id} a son cas : le retirer de {}", l.join(", "))),
            (false, l) => fautes.push(format!("{id} deux fois : {}", l.join(", "))),
        }
    }
    for (id, liste) in &mises_a_part {
        if !detectent.contains(*id) {
            fautes.push(format!(
                "{id} ({liste}) ne détecte plus, ou n'existe plus : à retirer de la liste"
            ));
        }
    }
    for id in &cas {
        if !detectent.contains(id) {
            fautes.push(format!(
                "tests/corpus-detection/{id} : pas une règle de détection (sans technique T…, ni outil qui détecte)"
            ));
        }
    }
    for id in &detectent {
        if !connues.contains(id.as_str()) {
            fautes.push(format!("{id} absent de tests/regles-connues.txt, ou retiré"));
        }
    }
    for (id, _) in PROPRES_SANS_VERIFIE {
        let reserve = std::fs::read_to_string(racine_du_corpus().join(id).join("attendu.toml"))
            .ok()
            .and_then(|t| lire_attendu(&t).ok())
            .and_then(|a| a.reserve);
        if reserve.is_none() {
            fautes.push(format!(
                "{id} (PROPRES_SANS_VERIFIE) : sans cas, ou sans reserve dans son attendu.toml"
            ));
        }
    }
    for (id, raison) in EXEMPTEES
        .iter()
        .chain(EN_ATTENTE_S3B)
        .chain(NE_DETECTENT_PAS)
        .chain(PROPRES_SANS_VERIFIE)
    {
        if raison.trim().is_empty() {
            fautes.push(format!("{id} sans raison"));
        }
    }
    assert!(fautes.is_empty(), "liste fermée du corpus :\n{}", fautes.join("\n"));
}

/// Le texte de src/<fichier>.
fn source(fichier: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(fichier))
        .unwrap_or_else(|e| panic!("src/{fichier} : {e}"))
}

/// Les corps des fonctions `nom` d'un texte source (après leur accolade ouvrante, jusqu'à l'accolade fermante en
/// début de ligne ou au même retrait) : grossier, mais le code passe par rustfmt.
fn corps(texte: &str, nom: &str) -> Vec<String> {
    let texte = &code(texte);
    let mut sortie = Vec::new();
    for i in signatures(texte, nom) {
        let avant = &texte[..i];
        let debut_ligne = avant.rfind('\n').map_or(0, |n| n + 1);
        let retrait = texte[debut_ligne..].len() - texte[debut_ligne..].trim_start().len();
        let fin_attendue = format!("\n{}}}", " ".repeat(retrait));
        let Some(ouvre) = texte[i..].find('{') else { continue };
        let corps = &texte[i + ouvre + 1..];
        let fin = corps.find(&fin_attendue).unwrap_or(corps.len());
        sortie.push(corps[..fin].to_string());
    }
    sortie
}

/// Les fonctions `nom` d'un texte source hors des essais (ni dans un module d'essais, ni réservées aux essais par
/// leur `#[cfg]`), chacune avec ses attributs `#[cfg(…)]`, lus dans le texte (pour la nommer), et son corps (`corps`).
/// `nom@système` (« journaux@windows ») ne garde que celles que leur `#[cfg]` compile pour ce système : la version
/// qu'un fil suit quand les autres versions jugent une autre règle.
fn homonymes(texte: &str, nom: &str) -> Vec<(String, String)> {
    let (nom, systeme) = nom.split_once('@').map_or((nom, None), |(n, s)| (n, Some(s)));
    let lignes: Vec<&str> = texte.lines().collect();
    let texte = &code(texte);
    let essais = modules_d_essais(texte, &lignes);
    let mut sortie = Vec::new();
    for i in signatures(texte, nom) {
        if essais.iter().any(|r| r.contains(&i)) {
            continue;
        }
        let debut_ligne = texte[..i].rfind('\n').map_or(0, |n| n + 1);
        let attributs = cfg_au_dessus(&lignes, texte[..i].matches('\n').count());
        if !SYSTEMES.iter().any(|s| compile_pour(&attributs, s)) {
            continue;
        }
        if systeme.is_some_and(|s| attributs.is_empty() || !compile_pour(&attributs, s)) {
            continue;
        }
        let Some(c) = corps(&texte[debut_ligne..], nom).into_iter().next() else {
            continue;
        };
        let mut cfg = attributs.join(" ");
        if !cfg.is_empty() {
            cfg.push(' ');
        }
        sortie.push((cfg, c));
    }
    sortie
}

/// Les systèmes pour lesquels Vanguard se compile.
const SYSTEMES: [&str; 3] = ["linux", "windows", "macos"];

/// Les débuts des signatures `fn nom(` ou `fn nom<…>(` (générique) dans le code.
fn signatures(texte: &str, nom: &str) -> Vec<usize> {
    let signature = format!("fn {nom}");
    texte
        .match_indices(&signature)
        .filter(|(i, _)| matches!(texte.as_bytes().get(i + signature.len()), Some(b'(' | b'<')))
        .filter(|(i, _)| !texte[..*i].ends_with(|c: char| c.is_alphanumeric() || c == '_'))
        .map(|(i, _)| i)
        .collect()
}

/// Les attributs `#[cfg(…)]` posés sur l'élément de la ligne `ligne` (indice dans `lignes`), commentaires passés ;
/// un attribut que rustfmt étale sur plusieurs lignes est rejoint en une seule.
fn cfg_au_dessus(lignes: &[&str], ligne: usize) -> Vec<String> {
    let mut attributs = Vec::new();
    let mut k = ligne.min(lignes.len());
    while k > 0 {
        k -= 1;
        // Un commentaire en bout de ligne (« #[allow(…)] // pourquoi ») retiré.
        let l = lignes[k].trim();
        let l = l.split_once(" //").map_or(l, |(avant, _)| avant).trim_end();
        if l.starts_with("//") || (l.starts_with("#[") && l.ends_with(']')) {
            if l.starts_with("#[") {
                attributs.push(l.to_string());
            }
            continue;
        }
        // La dernière ligne d'un attribut étalé (« ))] ») : remonter jusqu'à son « #[ », dix lignes au plus.
        let Some(debut) = l
            .ends_with(']')
            .then(|| {
                (k.saturating_sub(10)..k)
                    .rev()
                    .find(|&j| lignes[j].trim().starts_with("#["))
            })
            .flatten()
        else {
            break;
        };
        let morceaux: Vec<&str> = lignes[debut..=k].iter().map(|m| m.trim()).collect();
        attributs.push(morceaux.join(" ").replace("( ", "(").replace(" )", ")"));
        k = debut;
    }
    attributs.retain(|a| a.starts_with("#[cfg("));
    attributs
}

/// Les attributs `#[cfg(…)]` tous vrais pour `systeme`, hors essais (`test` faux).
fn compile_pour(attributs: &[String], systeme: &str) -> bool {
    attributs.iter().all(|a| {
        let dedans = a.trim_start_matches("#[cfg(").trim_end_matches(']');
        let dedans = dedans.strip_suffix(')').unwrap_or(dedans);
        let jetons = jetons_cfg(dedans);
        let mut pos = 0;
        cfg_vrai(&jetons, &mut pos, systeme)
    })
}

/// Les jetons d'un prédicat de `cfg` : noms, chaînes (sans leurs guillemets), « ( », « ) », « , », « = ».
fn jetons_cfg(t: &str) -> Vec<String> {
    let mut jetons = Vec::new();
    let mut c = t.chars().peekable();
    while let Some(x) = c.next() {
        match x {
            '(' | ')' | ',' | '=' => jetons.push(x.to_string()),
            '"' => jetons.push(c.by_ref().take_while(|&y| y != '"').collect()),
            y if y.is_alphanumeric() || y == '_' => {
                let mut mot = y.to_string();
                while let Some(&z) = c.peek().filter(|z| z.is_alphanumeric() || **z == '_') {
                    mot.push(z);
                    c.next();
                }
                jetons.push(mot);
            }
            _ => {}
        }
    }
    jetons
}

/// Un prédicat de `cfg` à partir de `jetons[*pos]`, pour `systeme`, tel que le programme publié se compile : `all`,
/// `any`, `not`, `windows`, `unix`, `target_os = "…"` ; faux pour `test` et `fuzzing` (les essais, le banc de
/// fuzzing), `debug_assertions` (le programme publié se compile en version optimisée) et `feature = "…"` (Cargo.toml
/// n'en déclare aucune). Un autre nom, inconnu, est tenu pour vrai : la fonction compte, et doit appeler la suivante.
fn cfg_vrai(jetons: &[String], pos: &mut usize, systeme: &str) -> bool {
    let Some(mot) = jetons.get(*pos).cloned() else {
        return true;
    };
    *pos += 1;
    match mot.as_str() {
        "all" | "any" | "not" => {
            *pos += 1; // « ( »
            let mut valeurs = Vec::new();
            while jetons.get(*pos).is_some_and(|j| j != ")") {
                valeurs.push(cfg_vrai(jetons, pos, systeme));
                if jetons.get(*pos).is_some_and(|j| j == ",") {
                    *pos += 1;
                }
            }
            *pos += 1; // « ) »
            match mot.as_str() {
                "all" => valeurs.iter().all(|&v| v),
                "any" => valeurs.iter().any(|&v| v),
                _ => !valeurs.first().copied().unwrap_or(true),
            }
        }
        _ if jetons.get(*pos).is_some_and(|j| j == "=") => {
            let valeur = jetons.get(*pos + 1).cloned().unwrap_or_default();
            *pos += 2;
            match mot.as_str() {
                "target_os" => valeur == systeme,
                "target_family" => valeur == if systeme == "windows" { "windows" } else { "unix" },
                "feature" => false,
                _ => true,
            }
        }
        "windows" => systeme == "windows",
        "unix" => systeme != "windows",
        "test" | "fuzzing" | "debug_assertions" => false,
        _ => true,
    }
}

/// Les étendues (dans le code) des modules d'essais écrits en ligne : `mod nom {` dont le `#[cfg]` ne se compile
/// qu'avec les essais, jusqu'à son accolade fermante. Un essai placé n'importe où dans le fichier (pas seulement en
/// fin) n'est pas pris pour une version de la fonction.
fn modules_d_essais(texte: &str, lignes: &[&str]) -> Vec<std::ops::Range<usize>> {
    let mut sortie = Vec::new();
    let mut debut_ligne = 0;
    for (n, ligne) in texte.split('\n').enumerate() {
        let l = ligne.trim_start();
        let l = l
            .strip_prefix("pub(crate) ")
            .or_else(|| l.strip_prefix("pub "))
            .unwrap_or(l);
        if l.starts_with("mod ") && l.trim_end().ends_with('{') {
            let attributs = cfg_au_dessus(lignes, n);
            if !attributs.is_empty() && !SYSTEMES.iter().any(|s| compile_pour(&attributs, s)) {
                let ouvre = debut_ligne + ligne.rfind('{').unwrap_or(0);
                let mut profondeur = 0usize;
                let mut fin = texte.len();
                for (k, c) in texte[ouvre..].char_indices() {
                    match c {
                        '{' => profondeur += 1,
                        '}' => {
                            profondeur -= 1;
                            if profondeur == 0 {
                                fin = ouvre + k;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                sortie.push(ouvre..fin);
            }
        }
        debut_ligne += ligne.len() + 1;
    }
    sortie
}

/// Le code d'un texte source, sans ses commentaires « // » ni ses chaînes (leur contenu effacé, les guillemets
/// gardés) : un nom dans un commentaire ou un message ne prouve pas un appel. Les caractères « 'x' » et « '\\x' » sont
/// sautés en entier, pour qu'un « '\"' » n'ouvre pas une chaîne.
fn code(texte: &str) -> String {
    let c: Vec<char> = texte.chars().collect();
    let mut sortie = String::with_capacity(texte.len());
    let mut i = 0;
    while i < c.len() {
        match c[i] {
            '/' if c.get(i + 1) == Some(&'/') => {
                while i < c.len() && c[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            '"' => {
                // Une chaîne brute (r"…", r#"…"#) n'a pas d'échappement : elle finit au guillemet suivi de ses dièses.
                let dieses = sortie.chars().rev().take_while(|&d| d == '#').count();
                let brute = sortie.chars().rev().nth(dieses) == Some('r');
                sortie.push('"');
                i += 1;
                // Les sauts de ligne de la chaîne sont gardés : les lignes du code restent celles du texte.
                while i < c.len() {
                    if c[i] == '"' && (!brute || (1..=dieses).all(|k| c.get(i + k) == Some(&'#'))) {
                        i += if brute { dieses } else { 0 };
                        break;
                    }
                    let pas = if !brute && c[i] == '\\' { 2 } else { 1 };
                    sortie.extend(c[i..(i + pas).min(c.len())].iter().filter(|&&x| x == '\n'));
                    i += pas;
                }
                sortie.push('"');
            }
            '\'' if c.get(i + 2) == Some(&'\'') => {
                sortie.push_str("' '");
                i += 2;
            }
            '\'' if c.get(i + 1) == Some(&'\\') && c.get(i + 3) == Some(&'\'') => {
                sortie.push_str("' '");
                i += 3;
            }
            autre => sortie.push(autre),
        }
        i += 1;
    }
    sortie
}

/// `nom` appelé ou nommé comme mot entier dans `texte` (pas une partie d'un nom plus long).
fn nomme(texte: &str, nom: &str) -> bool {
    let mot = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
    texte
        .match_indices(nom)
        .any(|(i, _)| !mot(texte[..i].chars().next_back()) && !mot(texte[i + nom.len()..].chars().next()))
}

/// Les blocs `regle!` de tout src/machine et de protection, par identifiant.
fn blocs_regle() -> Vec<(String, String)> {
    let mut fichiers = Vec::new();
    let mut a_voir = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(d) = a_voir.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                a_voir.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                fichiers.push(p);
            }
        }
    }
    let mut blocs = Vec::new();
    for f in fichiers {
        let texte = std::fs::read_to_string(&f).unwrap();
        for (i, _) in texte.match_indices("\nregle!(") {
            let bloc = &texte[i..];
            let bloc = &bloc[..bloc[1..].find("\n);").map_or(bloc.len(), |f| f + 1)];
            if let Some(id) = bloc.split('"').nth(1) {
                blocs.push((id.to_string(), bloc.to_string()));
            }
        }
    }
    blocs
}

#[test]
fn chaque_regle_du_corpus_mene_a_son_jugement() {
    let blocs = blocs_regle();
    let fiches = source("audit/fiches.rs");
    let mut fautes = Vec::new();
    for (id, fil) in FILS {
        match blocs.iter().find(|(i, _)| i == id) {
            Some((_, bloc)) => {
                let (_, premiere) = fil[0];
                if !nomme(&code(bloc), premiere.split('@').next().unwrap_or(premiere)) {
                    fautes.push(format!("{id} : son regle! ne nomme plus {premiere}"));
                }
            }
            // Une fiche de l'audit, ou l'usurpation de la box (scan et surveillance) : pas de regle!.
            None if fiches.contains(&format!("Fiche {{ id: \"{id}\"")) || *id == "COM-ARP-001" => {}
            // Un outil du registre : son fil doit partir de son module.
            None if super::registre::OUTILS.iter().any(|o| o.id == *id) => {
                let module = super::registre::OUTILS
                    .iter()
                    .find(|o| o.id == *id)
                    .map_or("", |o| o.module);
                let dossier = module.replace("::", "/");
                // Une surveillance (SUR-) dont la notification se forme dans la passe de la surveillance du réseau
                // (empoisonneur, appareils, ports) peut partir de là.
                let passe = id.starts_with("SUR-")
                    && fil[0] == ("reseau/surveillance.rs", "passe")
                    && fil.last() == Some(&("reseau/surveillance.rs", "alertes_du_scan"));
                if !fil[0].0.starts_with(&dossier) && !passe {
                    fautes.push(format!(
                        "{id} : son fil part de {}, hors de son module {module}",
                        fil[0].0
                    ));
                }
            }
            None => fautes.push(format!(
                "{id} : ni bloc regle! dans src/, ni fiche dans audit/fiches.rs"
            )),
        }
        for paire in fil.windows(2) {
            let ((fichier, appelant), (fichier_appele, appele)) = (paire[0], paire[1]);
            let texte = source(fichier);
            let appelants = homonymes(&texte, appelant);
            if appelants.is_empty() {
                fautes.push(format!("{id} : pas de fonction {appelant} dans src/{fichier}"));
            }
            for (cfg, c) in &appelants {
                if !nomme(c, appele.split('@').next().unwrap_or(appele)) {
                    fautes.push(format!(
                        "{id} : {appelant} {cfg}(src/{fichier}) n'appelle plus {appele}"
                    ));
                }
            }
            if homonymes(&source(fichier_appele), appele).is_empty() {
                fautes.push(format!("{id} : pas de fonction {appele} dans src/{fichier_appele}"));
            }
        }
    }
    for (id, fichier, fonction, texte) in RECOPIES {
        if !corps(&source(fichier), fonction).iter().any(|c| c.contains(texte)) {
            // `corps` ne garde que le code : un « Niveau::Critique » dans un commentaire ne compte pas.
            fautes.push(format!(
                "{id} : {fonction} (src/{fichier}) ne donne plus {texte} au jugement : l'adaptateur le recopie, à suivre"
            ));
        }
    }
    // Chaque règle du bilan qui a un cas a son fil ; les règles EVT- passent par le vrai jeu (REGLES), sans fil.
    for d in dossiers_de_cas().iter().filter(|d| !d.starts_with("EVT-")) {
        if !FILS.iter().any(|(i, _)| i == d) {
            fautes.push(format!(
                "{d} : un cas sans fil dans FILS (de son regle! à son jugement)"
            ));
        }
    }
    assert!(fautes.is_empty(), "fil des règles du corpus :\n{}", fautes.join("\n"));
}

#[test]
fn le_fil_voit_une_regle_debranchee() {
    let bloc = "\nregle!(\n    \"COM-XXX-001\",\n    Os::Tous,\n    1,\n    (\"a\", \"b\"),\n    &[],\n    || vec![ok(\"x\", \"rien\")]\n);";
    assert!(!nomme(bloc, "connexion_forcee"));
    assert!(nomme("    connexion_forcee\n", "connexion_forcee"));
    assert!(!nomme("juger_programmes(x)", "juger"));
    // Débranchée, avec le nom du jugement dans un commentaire ou un message : ce n'est pas un appel.
    let debranchee =
        "fn persistance() -> Vec<Constat> {\n    // persistance_dans\n    vec![ok(\"x\", \"persistance_dans\")]\n}\n";
    assert!(!nomme(&corps(debranchee, "persistance")[0], "persistance_dans"));
    let bloc_doc =
        "\nregle!(\n    \"COM-XXX-001\",\n    // connexion_forcee\n    || vec![ok(\"x\", \"connexion_forcee\")]\n);";
    assert!(!nomme(&code(bloc_doc), "connexion_forcee"));
    assert!(
        !corps("fn v() {\n    // Niveau::Critique\n    f(Niveau::Info, '\"')\n}\n", "v")[0]
            .contains("Niveau::Critique")
    );
    assert!(corps("fn v() {\n    f(Niveau::Critique, '\\'')\n}\n", "v")[0].contains("Niveau::Critique"));
    // Une chaîne brute qui finit par une barre inverse ne cache pas la suite.
    assert!(nomme(&code("let a = r\"C:\\\";\njuger(a);\n"), "juger"));
    assert!(nomme(&code("let a = r#\"x\"y\"#;\njuger(a);\n"), "juger"));
    let texte = "fn a() {\n    b();\n}\n\nfn c() {\n    d();\n}\n";
    assert_eq!(corps(texte, "a").len(), 1);
    assert!(nomme(&corps(texte, "a")[0], "b") && !nomme(&corps(texte, "a")[0], "d"));
    // Campagne n° 4 (M5) : deux homonymes, un par système, dont un seul appelle le jugement : l'autre est vu
    // débranché, et nommé par son cfg. Une version d'essai (`#[cfg(test)]`, ou dans le module des essais) ne compte pas.
    let deux = "#[cfg(target_os = \"linux\")]\npub fn certificats() -> Vec<Constat> {\n    juger(lire())\n}\n\n\
                /// Windows.\n#[cfg(windows)]\npub fn certificats() -> Vec<Constat> {\n    let _ = lire();\n    Vec::new()\n}\n\n\
                #[cfg(test)]\nfn certificats() -> Vec<Constat> {\n    Vec::new()\n}\n\n\
                #[cfg(test)]\nmod tests {\n    fn certificats() {\n        rien();\n    }\n}\n";
    let vus = homonymes(deux, "certificats");
    assert_eq!(vus.len(), 2, "{vus:?}");
    let coupes: Vec<&str> = vus
        .iter()
        .filter(|(_, c)| !nomme(c, "juger"))
        .map(|(a, _)| a.as_str())
        .collect();
    assert_eq!(coupes, ["#[cfg(windows)] "]);
    assert_eq!(
        homonymes(deux, "certificats@linux")[0].0,
        "#[cfg(target_os = \"linux\")] "
    );
    assert_eq!(homonymes(deux, "certificats@macos"), []);
    // Deuxième passe : `not(windows)` n'est pas Windows ; un cfg étalé sur plusieurs lignes est lu ; une fonction
    // générique est une version ; un module d'essais au milieu du fichier, même sous `all(test, …)`, ne compte pas.
    let etales = "#[cfg(not(windows))]\nfn lire() {\n    a();\n}\n\n\
                  #[cfg(all(\n    windows,\n    not(target_os = \"linux\")\n))]\nfn lire() {\n    b();\n}\n\n\
                  #[cfg(all(test, windows))]\nmod essais {\n    fn lire() {\n        c();\n    }\n}\n\n\
                  #[cfg(target_os = \"macos\")]\npub(crate) fn lire<T: Copy>(x: T) {\n    d(x);\n}\n";
    let corps_de = |s: &str| -> Vec<String> { homonymes(etales, s).into_iter().map(|(_, c)| c).collect() };
    assert_eq!(homonymes(etales, "lire").len(), 3, "{:?}", homonymes(etales, "lire"));
    assert!(
        corps_de("lire@windows").iter().all(|c| nomme(c, "b")),
        "{:?}",
        corps_de("lire@windows")
    );
    assert_eq!(corps_de("lire@windows").len(), 1);
    assert_eq!(corps_de("lire@linux").len(), 1);
    assert!(nomme(&corps_de("lire@linux")[0], "a"));
    assert_eq!(corps_de("lire@macos").len(), 2);
    assert!(corps_de("lire").iter().all(|c| !nomme(c, "c")));
    // Ce qui ne se compile pas dans le programme publié (banc de fuzzing, mode débogage, fonctionnalité de Cargo)
    // n'est pas une version ; son contraire en est une, et un nom inconnu compte.
    let publie = "#[cfg(fuzzing)]\nfn lire() {\n    f();\n}\n\n#[cfg(debug_assertions)]\nfn lire() {\n    g();\n}\n\n\
                  #[cfg(feature = \"x\")]\nfn lire() {\n    h();\n}\n\n#[cfg(not(debug_assertions))]\nfn lire() {\n    i();\n}\n\n\
                  #[cfg(inconnu)]\nfn lire() {\n    j();\n}\n";
    let corps: Vec<String> = homonymes(publie, "lire").into_iter().map(|(_, c)| c).collect();
    assert_eq!(corps.len(), 2, "{corps:?}");
    assert!(nomme(&corps[0], "i") && nomme(&corps[1], "j"), "{corps:?}");
}

#[test]
fn lecture_de_ce_qu_un_cas_attend() {
    let a = lire_attendu(
        "# un cas\ngravite = \"eleve\"\nmots = [\"outil-corpus\", \"a,b\"]\npropre = \"info\"\nsystemes = [\"linux\"]\n",
    )
    .unwrap();
    assert_eq!(a.gravite, Niveau::Eleve);
    assert_eq!(a.mots, ["outil-corpus", "a,b"]);
    assert_eq!(a.propre, Propre::AuPlus(Some(Niveau::Info)));
    assert_eq!(a.systemes, ["linux"]);
    assert_eq!(a.propre_vide, None);
    let a = lire_attendu(
        "gravite = \"moyen\"\nmots = \"x\"\npropre = \"rien\"\npropre_vide = \"vide d'origine\"\nsystemes = \"windows\"",
    )
    .unwrap();
    assert_eq!(
        (a.propre, a.propre_vide.as_deref()),
        (Propre::Rien, Some("vide d'origine"))
    );
    // Ce qui ne prouverait rien, ou se lirait de travers, est refusé.
    for faux in [
        "gravite = \"info\"\nmots = \"x\"\npropre = \"info\"\nsystemes = \"linux\"",
        "gravite = \"eleve\"\npropre = \"aucun\"\nsystemes = \"linux\"",
        "gravite = \"eleve\"\nmots = \"x\"\nsystemes = \"linux\"",
        "gravite = \"eleve\"\nmots = \"x\"\npropre = \"aucun\"\nsystemes = \"bsd\"",
        "gravite = \"eleve\"\nmots = \"x\"\npropre = \"aucun\"\nsystemes = \"linux\"\nautre = \"y\"",
        "gravite = eleve\nmots = \"x\"\npropre = \"aucun\"\nsystemes = \"linux\"",
        "gravite = \"eleve\"\ngravite = \"moyen\"\nmots = \"x\"\npropre = \"aucun\"\nsystemes = \"linux\"",
        "gravite = \"eleve\" # commentaire\nmots = \"x\"\npropre = \"aucun\"\nsystemes = \"linux\"",
        "gravite = \"eleve\"\nmots = [\"x\" \"y\"]\npropre = \"aucun\"\nsystemes = \"linux\"",
        "gravite = \"eleve\"\nmots = [\"\"]\npropre = \"aucun\"\nsystemes = \"linux\"",
    ] {
        assert!(lire_attendu(faux).is_err(), "{faux}");
    }
}

#[test]
fn variantes_d_un_cas() {
    let d = std::env::temp_dir().join(format!("vanguard-corpus-variantes-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    for f in [
        "attendu.toml",
        "fabrique.txt",
        "propre.txt",
        "fabrique-2.txt",
        "attendu-3.toml",
        "notes.txt",
    ] {
        std::fs::write(d.join(f), "").unwrap();
    }
    assert_eq!(variantes(&d), ["", "-2", "-3"]);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn une_ligne_mal_formee_nomme_son_cas() {
    let entree = Entree {
        dossier: PathBuf::from("corpus"),
        texte: "champ-seul".into(),
    };
    let juge: Juge = |e| {
        let _ = e.champs()[0][3];
        Vec::new()
    };
    let faute = juger_le_fichier("COM-XXX-001", "fabrique.txt", juge, &entree)
        .err()
        .unwrap()
        .0;
    assert!(
        faute.starts_with("COM-XXX-001/fabrique.txt : ligne mal formée"),
        "{faute}"
    );
}

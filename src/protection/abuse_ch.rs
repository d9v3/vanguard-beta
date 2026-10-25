//! Les listes d'abuse.ch et la clé de la personne. MalwareBazaar (empreintes de logiciels malveillants), URLhaus (liens
//! piégés) et ThreatFox (serveurs de botnets) ont fermé leurs exports publics le 21 oct. 2026 (410 Gone) : leurs listes
//! ne se téléchargent plus qu'avec la clé gratuite d'un compte (https://auth.abuse.ch/). Une seule clé sert aux trois,
//! et à l'API de ThreatFox ; Feodo Tracker reste ouvert sans clé.
//!
//! La clé reste sur cet ordinateur : dans le dossier de Vanguard du compte (jamais sur la clé USB), lisible par ce
//! compte seul. Les exports la veulent dans le chemin de l'adresse : cette adresse n'est faite qu'ici, au moment de la
//! demande, et n'en sort jamais (ni message, ni journal, ni rapport, ni JSON) ; l'erreur rendue ne dit que ce qui
//! s'est passé. Montrée, la clé l'est masquée (« ••••3f2a »). Sans clé, ou clé refusée, une liste n'est pas vérifiée,
//! et c'est dit avec la raison : jamais comptée comme saine.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::selection::{Ligne, choisir};
use crate::socle::cache::liste;
use crate::ui::*;

// Le cache des listes vit dans le socle (`socle::cache`) : seuls les mots de ses échecs, qui nomment abuse.ch, sont
// ici.
pub(crate) use crate::socle::cache::Echec;

/// La réponse de l'API de ThreatFox, gardée à côté de la clé : effacée quand la clé change, pour que la nouvelle serve
/// aussitôt.
pub(crate) const FICHIER_API: &str = "api.json";

/// Les services d'abuse.ch qui demandent la clé pour leurs exports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Service {
    MalwareBazaar,
    Urlhaus,
    ThreatFox,
}

impl Service {
    /// Le début de l'adresse des exports ; la clé puis le nom du fichier s'y ajoutent (seul ce chemin est reconnu :
    /// l'en-tête Auth-Key ou « ?auth-key= » y valent 404, vérifié le 21 oct. 2026).
    fn exports(self) -> &'static str {
        match self {
            Service::MalwareBazaar => "https://mb-api.abuse.ch/v2/files/exports/",
            Service::Urlhaus => "https://urlhaus-api.abuse.ch/v2/files/exports/",
            Service::ThreatFox => "https://threatfox-api.abuse.ch/v2/files/exports/",
        }
    }
}

impl Echec {
    /// La raison, prête à montrer après « liste … non vérifiée : ».
    pub(crate) fn raison(self) -> String {
        match self {
            Echec::Manquante => tr!(
                "clé abuse.ch manquante (gratuite sur https://auth.abuse.ch/, à donner dans Paramètres)",
                "abuse.ch key missing (free at https://auth.abuse.ch/, to give in Settings)"
            )
            .into(),
            Echec::Refusee => tr!(
                "clé abuse.ch refusée (vérifiez-la sur https://auth.abuse.ch/, puis redonnez-la dans Paramètres)",
                "abuse.ch key refused (check it at https://auth.abuse.ch/, then give it again in Settings)"
            )
            .into(),
            Echec::Reponse(429) => tr!(
                "abuse.ch limite les demandes de ce compte pour l'instant",
                "abuse.ch is limiting this account's requests for now"
            )
            .into(),
            Echec::Reponse(code) => trf!("abuse.ch a répondu {code}", "abuse.ch answered {code}"),
            Echec::SansReponse => tr!("pas d'Internet ?", "no Internet?").into(),
            Echec::Ecriture => tr!(
                "copie impossible à écrire dans le dossier de Vanguard (disque plein ?)",
                "copy could not be written to Vanguard's folder (disk full?)"
            )
            .into(),
            Echec::Illisible => tr!(
                "réponse illisible (format changé, ou page d'un portail Wi-Fi ?)",
                "unreadable answer (format changed, or a Wi-Fi portal page?)"
            )
            .into(),
            // Les mots restent neutres : ce variant sert à toutes les sources du cache (CISA, GitHub, abuse.ch…).
            Echec::CopieRefusee(refus, Some(code)) => trf!(
                "copie gardée refusée ({}), et la redemande a reçu la réponse {code}",
                "kept copy refused ({}), and asking again got answer {code}",
                refus.raison()
            ),
            Echec::CopieRefusee(refus, None) => trf!(
                "copie gardée refusée ({}), et la redemande est restée sans réponse (pas d'Internet ?)",
                "kept copy refused ({}), and asking again got no answer (no Internet?)",
                refus.raison()
            ),
        }
    }
}

// ───────────────────────────── Les listes ─────────────────────────────

/// Un export utilisable : la copie et son âge, et pourquoi elle n'a pas été rafraîchie quand c'est celle d'avant qui
/// sert (404 sur un nom changé, 429, panne, pas d'Internet) : à dire, jamais à taire.
pub(crate) type Export = ((Vec<u8>, Duration), Option<Echec>);

/// Un export d'abuse.ch, avec la clé de la personne : `fichier` (son nom chez abuse.ch) gardé dans `lieu`
/// (sous-dossier, nom), comme `liste`. Sans clé, rien n'est demandé. Le rafraîchissement manqué ne se lit ici que
/// par l'âge de la copie : `export_et_manque` le dit aussi.
pub(crate) fn export(
    service: Service,
    fichier: &str,
    lieu: (&str, &str),
    fraiche: Duration,
    delai: Duration,
) -> Result<(Vec<u8>, Duration), Echec> {
    export_et_manque(service, fichier, lieu, fraiche, delai, |_| true).map(|(copie, _)| copie)
}

/// `export`, avec la raison d'un rafraîchissement manqué quand la copie d'avant sert : pour une liste sans limite
/// d'âge (les empreintes de MalwareBazaar), où l'âge seul ne le dirait pas. Seule une réponse que `valide` accepte
/// remplace la copie gardée : une archive anormale (démesurée une fois ouverte, ou presque vide) ne prend jamais la
/// place de la bonne.
pub(crate) fn export_et_manque(
    service: Service,
    fichier: &str,
    lieu: (&str, &str),
    fraiche: Duration,
    delai: Duration,
    valide: fn(&[u8]) -> bool,
) -> Result<Export, Echec> {
    let cle = cle().ok_or(Echec::Manquante)?;
    export_depuis(service.exports(), &cle, fichier, lieu, (fraiche, delai), valide)
}

/// L'export, depuis `base` (un serveur local dans les tests). L'adresse qui porte la clé naît et meurt ici.
fn export_depuis(
    base: &str,
    cle: &str,
    fichier: &str,
    lieu: (&str, &str),
    (fraiche, delai): (Duration, Duration),
    valide: fn(&[u8]) -> bool,
) -> Result<Export, Echec> {
    // Lettres et chiffres seulement : un segment de chemin sûr, sans « / ? # % » ni « .. » qui changerait l'adresse.
    if !cle_valide(cle) {
        return Err(Echec::Manquante);
    }
    let adresse = format!("{base}{cle}/{fichier}");
    let demande = crate::http::Demande {
        taille_max: 256 << 20,
        // Une redirection vers un autre hôte n'emporte pas la clé.
        meme_hote: true,
        ..crate::http::Demande::get(&adresse, delai)
    };
    let liste = liste(demande, lieu, fraiche, valide);
    let manque = liste.manque;
    liste.resultat(true).map(|copie| (copie, manque))
}

// ───────────────────────────── La clé ─────────────────────────────

/// La clé, sur cet ordinateur seulement (le dossier de Vanguard du compte, jamais la clé USB), sous la forme d'un
/// en-tête (« Auth-Key: … »). C'est là que la clé de l'API de ThreatFox était gardée avant que les exports la
/// demandent aussi : celle qu'on avait déjà donnée sert aux trois services sans rien refaire.
fn fichier_cle() -> PathBuf {
    crate::socle::dossier_local().join("threatfox").join("cle-entete")
}

/// La clé gardée dans `chemin`, vérifiée de nouveau : `Ok(None)` absente ; `Err` : là mais illisible (un fichier
/// modifié à la main n'ajoute rien à une demande).
fn lire_de(chemin: &Path) -> Result<Option<String>, ()> {
    let texte = match crate::socle::lire_texte_ordinaire(chemin, 4 << 10) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    };
    let cle = texte.trim().strip_prefix("Auth-Key:").ok_or(())?.trim();
    if cle_valide(cle) {
        Ok(Some(cle.to_string()))
    } else {
        Err(())
    }
}

/// La clé de la personne ; `None` : pas donnée, ou illisible.
pub(crate) fn cle() -> Option<String> {
    lire_de(&fichier_cle()).ok().flatten()
}

/// Une clé d'abuse.ch telle qu'elle se copie : lettres et chiffres seulement. Un retour à la ligne glissé dedans
/// ajouterait un en-tête à la demande de l'API ; un « / » ou un « ? », un autre chemin à celle des exports.
pub(crate) fn cle_valide(cle: &str) -> bool {
    (20..=128).contains(&cle.len()) && cle.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// La clé telle qu'elle se montre : ses quatre derniers caractères, assez pour la reconnaître.
pub(crate) fn masquee(cle: &str) -> String {
    let fin = cle.char_indices().rev().nth(3).map_or(0, |(i, _)| i);
    format!("••••{}", &cle[fin..])
}

/// `texte` avec la clé masquée partout où elle paraît : pour tout texte qui pourrait l'avoir prise au passage.
pub(crate) fn masquer(texte: &str, cle: &str) -> String {
    if cle.is_empty() {
        return texte.to_string();
    }
    texte.replace(cle, &masquee(cle))
}

/// Garde la clé dans `chemin`, lisible par ce compte seul (600 sous Unix ; sous Windows, le dossier local du compte
/// n'est ouvert qu'à lui). Le fichier est recréé : un ancien, plus ouvert, ne garde pas ses droits.
fn enregistrer_dans(chemin: &Path, cle: &str) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(dossier) = chemin.parent() {
        std::fs::create_dir_all(dossier)?;
    }
    oublier_de(chemin);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(chemin)?.write_all(format!("Auth-Key: {cle}\n").as_bytes())
}

/// Retire la clé de `chemin` et la réponse de l'API qu'elle a obtenue. Les listes téléchargées restent (des données
/// publiques), mais ne servent plus sans clé.
fn oublier_de(chemin: &Path) {
    let _ = std::fs::remove_file(chemin);
    if let Some(dossier) = chemin.parent() {
        let _ = std::fs::remove_file(dossier.join(FICHIER_API));
    }
}

/// Retire la clé de cet ordinateur.
pub(crate) fn oublier() {
    oublier_de(&fichier_cle());
}

/// La clé, telle que Paramètres la montre : masquée, absente ou illisible.
pub(crate) fn etat_court() -> String {
    match lire_de(&fichier_cle()) {
        Ok(Some(cle)) => masquee(&cle),
        Ok(None) => tr!("aucune : listes non vérifiées", "none: lists not checked").into(),
        Err(()) => tr!("illisible : à redonner", "unreadable: give it again").into(),
    }
}

/// Ce que la clé ouvre, et où la trouver.
fn explication() -> &'static str {
    tr!(
        "Depuis le 21 octobre 2026, abuse.ch ne donne ses listes qu'avec la clé gratuite d'un compte : empreintes de logiciels malveillants (MalwareBazaar), liens piégés (URLhaus), serveurs de botnets (ThreatFox). Sans elle, ces listes ne sont pas vérifiées, et c'est dit. Créez un compte sur https://auth.abuse.ch/, puis copiez votre clé (« Auth-Key »). Elle reste sur cet ordinateur, lisible par votre compte seul : jamais sur la clé USB, jamais montrée en entier.",
        "Since October 21, 2026, abuse.ch only gives its lists with a free account key: malware fingerprints (MalwareBazaar), malicious links (URLhaus), botnet servers (ThreatFox). Without it, these lists are not checked, and that is said. Create an account at https://auth.abuse.ch/, then copy your key (“Auth-Key”). It stays on this computer, readable by your account only: never on the USB key, never shown in full."
    )
}

/// Donner la clé : où la trouver, puis la clé collée. `true` : gardée.
pub(crate) fn donner() -> bool {
    println!();
    for ligne in envelopper(explication(), LARGEUR - 2) {
        println!("  {ligne}");
    }
    let question = tr!(
        "  Clé (elle ne s'affiche pas ; Entrée pour annuler) : ",
        "  Key (it is not shown; Enter to cancel): "
    );
    // Sans écho : la clé collée ne paraît pas à l'écran (ni dans l'historique du terminal). Entrée redirigée (pas de
    // terminal) : lue telle quelle, il n'y a rien à cacher.
    let cle = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        rpassword::prompt_password(question)
            .map(|c| c.trim().to_string())
            .unwrap_or_default()
    } else {
        demander(question)
    };
    if cle.is_empty() {
        return false;
    }
    if !cle_valide(&cle) {
        trp!(
            "  ✖ Clé illisible : seulement des lettres et des chiffres, sans espace.",
            "  ✖ Unreadable key: letters and digits only, no space."
        );
        return false;
    }
    let avant = self::cle().map_or_else(|| tr!("aucune", "none").to_string(), |c| masquee(&c));
    match enregistrer_dans(&fichier_cle(), &cle) {
        Ok(()) => {
            trp!(
                "  {VERT}✔{RESET} Clé abuse.ch : {avant} → {} (elle sert dès la prochaine vérification).",
                "  {VERT}✔{RESET} abuse.ch key: {avant} → {} (used from the next check on).",
                masquee(&cle)
            );
            true
        }
        // L'erreur d'écriture ne parle que du fichier ; masquée quand même, au cas où.
        Err(e) => {
            let e = masquer(&e.to_string(), &cle);
            trp!("  ✖ Clé pas gardée : {e}.", "  ✖ Key not saved: {e}.");
            false
        }
    }
}

/// Retire la clé, en montrant ce qui change.
pub(crate) fn retirer() {
    let avant = etat_court();
    oublier();
    trp!(
        "  {VERT}✔{RESET} Clé abuse.ch : {avant} → {}. Pour la remettre : la redonner (https://auth.abuse.ch/ la montre).",
        "  {VERT}✔{RESET} abuse.ch key: {avant} → {}. To put it back: give it again (https://auth.abuse.ch/ shows it).",
        tr!("aucune", "none")
    );
}

/// L'écran de la clé dans Paramètres : son état masqué, la donner (ou la remplacer), la retirer.
pub(crate) fn menu() {
    loop {
        let presente = fichier_cle().is_file();
        let mut lignes = vec![
            Ligne::Texte(String::new()),
            Ligne::Texte(ligne_titre(tr!("Clé abuse.ch", "abuse.ch key"))),
        ];
        lignes.extend(
            envelopper(explication(), LARGEUR - 4)
                .into_iter()
                .map(|l| Ligne::Texte(format!("  {GRIS}{l}{RESET}"))),
        );
        lignes.push(Ligne::Texte(String::new()));
        lignes.push(Ligne::Texte(trf!(
            "  {GRAS}En ce moment{RESET} : {}",
            "  {GRAS}Now{RESET}: {}",
            etat_court()
        )));
        lignes.push(Ligne::Texte(String::new()));
        if presente {
            lignes.push(Ligne::choix("1", tr!("Remplacer la clé", "Replace the key"), ""));
            lignes.push(Ligne::choix("2", tr!("Retirer la clé", "Remove the key"), ""));
        } else {
            lignes.push(Ligne::choix("1", tr!("Donner ma clé", "Give my key"), ""));
        }
        lignes.push(Ligne::Texte(String::new()));
        lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
        let Some(choix) = choisir(
            &lignes,
            tr!("\n  Choix (Entrée pour revenir) : ", "\n  Choice (Enter to go back): "),
            "1",
            tr!("revenir", "back"),
        ) else {
            return;
        };
        match choix.trim() {
            "1" => {
                donner();
            }
            "2" if presente => retirer(),
            _ => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socle::cache::{Liste, liste_validee};
    use std::io::{Read, Write};

    /// Une clé inventée, à la forme de celles d'abuse.ch (48 lettres et chiffres).
    const CLE: &str = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2w3X4";

    fn jetable(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vanguard-abuse-ch-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Un serveur HTTP local qui répond `reponse` à une demande et rend la ligne de demande reçue.
    fn serveur(reponse: &'static [u8]) -> (String, std::thread::JoinHandle<String>) {
        let ecoute = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}/v2/files/exports/", ecoute.local_addr().unwrap());
        let fil = std::thread::spawn(move || {
            let (mut prise, _) = ecoute.accept().unwrap();
            prise.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut recu = vec![0u8; 65_536];
            let n = prise.read(&mut recu).unwrap_or(0);
            let _ = prise.write_all(reponse);
            String::from_utf8_lossy(&recu[..n])
                .lines()
                .next()
                .unwrap_or_default()
                .to_string()
        });
        (base, fil)
    }

    /// Tout ce qu'un sous-dossier de listes contient, en texte.
    fn contenu(sous_dossier: &str) -> String {
        std::fs::read_dir(crate::socle::dossier_local().join(sous_dossier))
            .into_iter()
            .flatten()
            .flatten()
            .map(|f| String::from_utf8_lossy(&std::fs::read(f.path()).unwrap_or_default()).into_owned())
            .collect()
    }

    #[test]
    fn cle_gardee_lue_puis_retiree() {
        // Une clé collée avec un retour à la ligne, un espace ou de quoi changer le chemin d'une adresse : refusée.
        assert!(cle_valide(CLE));
        for mauvaise in [
            "a1B2c3D4e5F6g7H8i9J0\r\nX-Autre: 1",
            "a1B2c3D4 e5F6g7H8i9J0k1L2",
            "a1B2c3D4e5F6g7H8i9J0/../../autre",
            "a1B2c3D4e5F6g7H8i9J0k1L2?x=1",
            "a1B2c3D4e5F6g7H8i9J0k1L2#a",
            "a1B2c3D4e5F6g7H8i9J0%2Fk1L2",
            "court",
        ] {
            assert!(!cle_valide(mauvaise), "{mauvaise}");
        }
        let fichier = jetable("cle").join("threatfox").join("cle-entete");
        assert_eq!(lire_de(&fichier), Ok(None));
        enregistrer_dans(&fichier, CLE).unwrap();
        assert_eq!(std::fs::read_to_string(&fichier).unwrap(), format!("Auth-Key: {CLE}\n"));
        assert_eq!(lire_de(&fichier), Ok(Some(CLE.to_string())));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&fichier).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // Modifié à la main avec un en-tête de plus : illisible, pas une clé.
        std::fs::write(&fichier, format!("Auth-Key: {CLE}\r\nX-Autre: 1\n")).unwrap();
        assert_eq!(lire_de(&fichier), Err(()));
        // Retirée, avec la réponse de l'API qu'elle avait obtenue.
        let reponse = fichier.with_file_name(FICHIER_API);
        std::fs::write(&reponse, "{}").unwrap();
        oublier_de(&fichier);
        assert!(!fichier.exists() && !reponse.exists());
        let _ = std::fs::remove_dir_all(fichier.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn cle_montree_masquee() {
        assert_eq!(masquee(CLE), "••••w3X4");
        let texte = format!("échec de https://urlhaus-api.abuse.ch/v2/files/exports/{CLE}/hostfile.txt ({CLE})");
        let masque = masquer(&texte, CLE);
        assert!(!masque.contains(CLE), "{masque}");
        assert!(masque.contains("/exports/••••w3X4/hostfile.txt"), "{masque}");
        assert_eq!(masquer("rien", ""), "rien");
    }

    /// La clé va dans le chemin de la demande, au serveur seul : ni l'erreur rendue, ni sa raison, ni ce qui est
    /// écrit à côté de la liste ne la contiennent, quoi que réponde le serveur (refus, panne, rien du tout).
    #[test]
    fn la_cle_ne_fuit_jamais() {
        let lieu = ("essai-cle-abuse-ch", "liste.txt");
        let _ = std::fs::remove_dir_all(crate::socle::dossier_local().join(lieu.0));
        let delais = (Duration::ZERO, Duration::from_secs(5));
        let mut raisons = Vec::new();
        // Clé refusée : la réponse d'abuse.ch, vue le 21 oct. 2026.
        let (base, fil) = serveur(
            b"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: 45\r\nConnection: close\r\n\r\n{\"status\":401,\"message\":\"Invalid auth token\"}",
        );
        let refus = export_depuis(&base, CLE, "hostfile.txt", lieu, delais, |_| true).unwrap_err();
        assert_eq!(refus, Echec::Refusee);
        let demande = fil.join().unwrap();
        assert_eq!(demande, format!("GET /v2/files/exports/{CLE}/hostfile.txt HTTP/1.1"));
        raisons.push(format!("{refus:?} {}", refus.raison()));
        // Panne, sans copie d'avant.
        let (base, fil) = serveur(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let panne = export_depuis(&base, CLE, "hostfile.txt", lieu, delais, |_| true).unwrap_err();
        assert_eq!(panne, Echec::Reponse(502));
        fil.join().unwrap();
        raisons.push(format!("{panne:?} {}", panne.raison()));
        // Personne n'écoute.
        let libre = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let rien = export_depuis(
            &format!("http://{libre}/v2/files/exports/"),
            CLE,
            "x.txt",
            lieu,
            delais,
            |_| true,
        )
        .unwrap_err();
        assert_eq!(rien, Echec::SansReponse);
        raisons.push(format!("{rien:?} {}", rien.raison()));
        // Une clé qui changerait l'adresse n'est même pas envoyée.
        assert_eq!(
            export_depuis(&base, "a1B2c3D4e5F6g7H8i9J0/../x", "x.txt", lieu, delais, |_| true),
            Err(Echec::Manquante)
        );
        for raison in &raisons {
            assert!(!raison.contains(CLE) && !raison.contains("w3X4"), "{raison}");
        }
        // Rien de ce qui a été écrit à côté de la liste ne la contient (aucune liste, d'ailleurs : seul un 200 en
        // écrit une).
        assert!(!contenu(lieu.0).contains(CLE));
        // Réussie : la liste est gardée, toujours sans la clé.
        let (base, fil) =
            serveur(b"HTTP/1.1 200 OK\r\nContent-Length: 22\r\nConnection: close\r\n\r\n# URLhaus\n127.0.0.1 x\n");
        let ((octets, _), manque) = export_depuis(&base, CLE, "hostfile.txt", lieu, delais, |_| true).unwrap();
        fil.join().unwrap();
        assert_eq!(octets, b"# URLhaus\n127.0.0.1 x\n");
        assert_eq!(manque, None);
        assert!(!contenu(lieu.0).contains(CLE));
        let _ = std::fs::remove_dir_all(crate::socle::dossier_local().join(lieu.0));
    }

    /// Un rafraîchissement manqué alors qu'une copie d'avant existe : la copie sert, et la raison est rendue avec
    /// (404 d'un nom changé, 429, pas d'Internet), jamais tue. Une copie encore fraîche n'est pas redemandée : rien à
    /// dire.
    #[test]
    fn rafraichissement_manque_dit_avec_la_copie() {
        let lieu = ("essai-manque-abuse-ch", "liste.txt");
        let dossier = crate::socle::dossier_local().join(lieu.0);
        let _ = std::fs::remove_dir_all(&dossier);
        crate::socle::cache::garder(lieu, b"# d'avant\n").unwrap();
        let due = (Duration::ZERO, Duration::from_secs(5));
        for (reponse, attendu) in [
            (
                &b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..],
                Echec::Reponse(404),
            ),
            (
                &b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..],
                Echec::Reponse(429),
            ),
        ] {
            let reponse: &'static [u8] = reponse;
            let (base, fil) = serveur(reponse);
            let ((octets, _), manque) = export_depuis(&base, CLE, "nom_change.zip", lieu, due, |_| true).unwrap();
            fil.join().unwrap();
            assert_eq!(octets, b"# d'avant\n");
            assert_eq!(manque, Some(attendu));
            assert!(!attendu.raison().contains(CLE));
        }
        // Personne n'écoute : la copie sert, « pas d'Internet ? ».
        let libre = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let base = format!("http://{libre}/v2/files/exports/");
        let (_, manque) = export_depuis(&base, CLE, "x.zip", lieu, due, |_| true).unwrap();
        assert_eq!(manque, Some(Echec::SansReponse));
        // Encore fraîche : rien n'est demandé (personne n'écoute), rien à dire.
        let fraiche = (Duration::from_hours(1), Duration::from_secs(5));
        let (_, manque) = export_depuis(&base, CLE, "x.zip", lieu, fraiche, |_| true).unwrap();
        assert_eq!(manque, None);
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Une réponse 200 qui n'a pas la forme attendue (une page de portail Wi-Fi) ne remplace pas la bonne copie, et
    /// c'est dit ; sans copie d'avant, la raison est la forme, pas le code.
    #[test]
    fn reponse_invalide_garde_la_copie() {
        fn demande(base: &str) -> crate::http::Demande<'_> {
            crate::http::Demande::get(base, Duration::from_secs(5))
        }
        let lieu = ("essai-valide-abuse-ch", "liste.json");
        let dossier = crate::socle::dossier_local().join(lieu.0);
        let _ = std::fs::remove_dir_all(&dossier);
        let portail: &'static [u8] =
            b"HTTP/1.1 200 OK\r\nContent-Length: 22\r\nConnection: close\r\n\r\n<html>Connexion</html>";
        let json = |o: &[u8]| o.starts_with(b"{");
        // Aucune copie : la forme est la raison.
        let (base, fil) = serveur(portail);
        let liste = liste_validee(demande(&base), lieu, Duration::ZERO, &json);
        fil.join().unwrap();
        assert_eq!(liste.manque, Some(Echec::Illisible));
        assert!(liste.copie.is_none());
        assert_eq!(liste.resultat(false), Err(Echec::Illisible));
        assert!(!dossier.join(lieu.1).exists());
        // Une bonne réponse est gardée.
        let (base, fil) = serveur(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\n{\"a\": 1}");
        let liste = liste_validee(demande(&base), lieu, Duration::ZERO, &json);
        fil.join().unwrap();
        assert_eq!(liste.manque, None);
        assert_eq!(liste.copie.map(|c| c.0), Some(b"{\"a\": 1}".to_vec()));
        // Le portail ensuite : la bonne copie reste, et le manque est dit.
        let (base, fil) = serveur(portail);
        let liste = liste_validee(demande(&base), lieu, Duration::ZERO, &json);
        fil.join().unwrap();
        assert_eq!(liste.manque, Some(Echec::Illisible));
        assert_eq!(liste.copie.map(|c| c.0), Some(b"{\"a\": 1}".to_vec()));
        assert!(Echec::Illisible.raison().contains("portail") || Echec::Illisible.raison().contains("portal"));
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Une réponse 200 qui n'est pas la liste (page de blocage d'un proxy qui inspecte le HTTPS) : la copie d'avant
    /// reste, avec son âge, et la raison est dite. Avant, elle était remplacée par la page, qui paraissait fraîche.
    #[test]
    fn page_qui_n_est_pas_la_liste_garde_la_copie() {
        let lieu = ("essai-illisible-abuse-ch", "liste.txt");
        let dossier = crate::socle::dossier_local().join(lieu.0);
        let _ = std::fs::remove_dir_all(&dossier);
        crate::socle::cache::garder(lieu, b"# d'avant\n").unwrap();
        let (base, fil) =
            serveur(b"HTTP/1.1 200 OK\r\nContent-Length: 21\r\nConnection: close\r\n\r\n<html>Bloque</html>\r\n");
        let adresse = format!("{base}liste.txt");
        let demande = crate::http::Demande::get(&adresse, Duration::from_secs(5));
        let l = liste(demande, lieu, Duration::ZERO, |o| o.starts_with(b"# "));
        fil.join().unwrap();
        assert_eq!(l.manque, Some(Echec::Illisible));
        assert_eq!(l.copie.map(|(o, _)| o), Some(b"# d'avant\n".to_vec()));
        assert_eq!(std::fs::read(dossier.join(lieu.1)).unwrap(), b"# d'avant\n");
        // Sans copie d'avant : la raison, pas « a répondu 200 ».
        std::fs::remove_file(dossier.join(lieu.1)).unwrap();
        let (base, fil) =
            serveur(b"HTTP/1.1 200 OK\r\nContent-Length: 21\r\nConnection: close\r\n\r\n<html>Bloque</html>\r\n");
        let adresse = format!("{base}liste.txt");
        let demande = crate::http::Demande::get(&adresse, Duration::from_secs(5));
        let l = liste(demande, lieu, Duration::ZERO, |o| o.starts_with(b"# "));
        fil.join().unwrap();
        assert!(!dossier.join(lieu.1).exists());
        assert_eq!(l.resultat(false), Err(Echec::Illisible));
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Ce que dit une demande : la copie gardée sert tant que la clé n'est pas refusée ; sans copie, le code dit
    /// pourquoi. Sans clé (Feodo Tracker), un 403 n'est pas une clé refusée.
    #[test]
    fn resultat_d_une_liste() {
        let copie = || Some((b"# x\n".to_vec(), Duration::ZERO));
        assert!(
            Liste {
                copie: copie(),
                code: Some(502),
                manque: None
            }
            .resultat(true)
            .is_ok()
        );
        assert!(
            Liste {
                copie: copie(),
                code: None,
                manque: None
            }
            .resultat(true)
            .is_ok()
        );
        assert_eq!(
            Liste {
                copie: copie(),
                code: Some(401),
                manque: None
            }
            .resultat(true),
            Err(Echec::Refusee)
        );
        assert_eq!(
            Liste {
                copie: None,
                code: Some(403),
                manque: None
            }
            .resultat(true),
            Err(Echec::Refusee)
        );
        assert!(
            Liste {
                copie: copie(),
                code: Some(403),
                manque: None
            }
            .resultat(false)
            .is_ok()
        );
        assert_eq!(
            Liste {
                copie: None,
                code: Some(404),
                manque: None
            }
            .resultat(true),
            Err(Echec::Reponse(404))
        );
        assert_eq!(
            Liste {
                copie: None,
                code: None,
                manque: None
            }
            .resultat(false),
            Err(Echec::SansReponse)
        );
        // Chaque raison montrée dit où trouver la clé quand c'est elle qui manque.
        assert!(Echec::Manquante.raison().contains("https://auth.abuse.ch/"));
        assert!(Echec::Refusee.raison().contains("https://auth.abuse.ch/"));
    }
}

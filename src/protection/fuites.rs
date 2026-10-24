//! Mots de passe fuités : vérifie si un mot de passe figure dans les fuites de données connues (Have I Been Pwned).
//! Le mot de passe ne quitte jamais l'ordinateur : seuls les 5 premiers caractères de son empreinte SHA-1 partent,
//! le service renvoie toutes les empreintes qui commencent pareil (des centaines), et la comparaison se fait ici.

use crate::ui::*;

const SERVICE: &str = "https://api.pwnedpasswords.com/range/";

/// Empreinte SHA-1 en hexadécimal majuscule, coupée en (5 premiers caractères envoyés, reste gardé ici).
fn empreinte(mot_de_passe: &str) -> (String, String) {
    let hex = crate::socle::hachage::sha1_hexa(mot_de_passe.as_bytes()).to_uppercase();
    let (debut, fin) = hex.split_at(5);
    (debut.to_string(), fin.to_string())
}

/// Nombre de fuites où l'empreinte apparaît, d'après la réponse du service (« SUFFIXE:NOMBRE » par ligne ;
/// les lignes de remplissage, ajoutées pour masquer la taille de la réponse, valent 0).
fn occurrences(reponse: &str, fin: &str) -> u64 {
    reponse
        .lines()
        .filter_map(|l| l.trim().split_once(':'))
        .find(|(suffixe, _)| suffixe.eq_ignore_ascii_case(fin))
        .and_then(|(_, n)| n.trim().parse().ok())
        .unwrap_or(0)
}

/// Interroge le service (le début de l'empreinte seulement). `None` : pas de réponse.
fn interroger(debut: &str) -> Option<String> {
    let adresse = format!("{SERVICE}{debut}");
    let mut demande = crate::http::Demande::get(&adresse, std::time::Duration::from_secs(15));
    // Des réponses de taille égale : sur le réseau, la longueur ne trahit pas quelle empreinte a été demandée.
    demande.entetes.push(("Add-Padding", "true".into()));
    let r = crate::http::envoyer(demande).filter(|r| r.code == 200)?;
    let texte = r.texte();
    texte.contains(':').then_some(texte)
}

/// « 52 372 427 » en français, « 52,372,427 » en anglais.
fn milliers(n: u64) -> String {
    let separateur = if crate::langue::anglais() { ',' } else { ' ' };
    let chiffres = n.to_string();
    let mut sortie = String::new();
    for (i, c) in chiffres.chars().enumerate() {
        if i > 0 && (chiffres.len() - i).is_multiple_of(3) {
            sortie.push(separateur);
        }
        sortie.push(c);
    }
    sortie
}

/// Conseil sur la forme du mot de passe, sans le juger « solide » : ce test ne le sait pas.
fn conseil_forme(mot_de_passe: &str) -> Option<&'static str> {
    (mot_de_passe.chars().count() < 12).then(|| {
        tr!(
            "Il fait moins de 12 caractères : une phrase de passe de 4 ou 5 mots est plus solide et plus facile à retenir.",
            "It is shorter than 12 characters: a passphrase of 4 or 5 words is stronger and easier to remember."
        )
    })
}

pub fn verifier() {
    titre(tr!("Mots de passe fuités", "Leaked passwords"));
    trp!(
        "  Tapez un mot de passe : il ne s'affiche pas et ne quitte jamais cet ordinateur. Seuls 5 caractères de\n  son empreinte sont envoyés à Have I Been Pwned, la comparaison se fait ici. Entrée seule pour terminer.\n",
        "  Type a password: it is not shown and never leaves this computer. Only 5 characters of its hash\n  are sent to Have I Been Pwned, and the comparison happens here. Enter alone to finish.\n"
    );
    while let Ok(mot_de_passe) = rpassword::prompt_password(tr!("  Mot de passe : ", "  Password: ")) {
        if mot_de_passe.is_empty() {
            break;
        }
        let (debut, fin) = empreinte(&mot_de_passe);
        let Some(reponse) = interroger(&debut) else {
            trp!(
                "  ✖ Service injoignable (pas d'Internet ?).",
                "  ✖ Service unreachable (no Internet?)."
            );
            break;
        };
        match occurrences(&reponse, &fin) {
            0 => {
                trp!(
                    "  {VERT}✔{RESET} Absent des fuites connues. Ça ne veut pas dire qu'il est solide : seulement qu'il n'a pas circulé.",
                    "  {VERT}✔{RESET} Not in known leaks. That does not mean it is strong: only that it has not circulated."
                );
                if let Some(c) = conseil_forme(&mot_de_passe) {
                    println!("    {GRIS}{}{RESET}", crate::ui::commande_affichable(c));
                }
            }
            n => trp!(
                "  {}✖ Trouvé {} fois dans des fuites{RESET} : les pirates l'essaient en premier. Changez-le partout\n    où vous l'utilisez, et prenez un mot de passe différent pour chaque site (un gestionnaire\n    comme Bitwarden s'en charge).",
                "  {}✖ Found {} times in leaks{RESET}: attackers try it first. Change it everywhere you use it,\n    and use a different password for each site (a manager like Bitwarden does it for you).",
                couleur(crate::risk::Niveau::Critique),
                milliers(n)
            ),
        }
        println!();
    }
}

/// Adresse courriel encodée pour une URL (lettres, chiffres, @ . - _ gardés tels quels).
fn encoder(adresse: &str) -> String {
    adresse
        .bytes()
        .map(|o| match o {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'@' | b'.' | b'-' | b'_' => (o as char).to_string(),
            _ => format!("%{o:02X}"),
        })
        .collect()
}

/// Noms des fuites d'une réponse XposedOrNot : `{"breaches":[["Adobe","LinkedIn"]]}`, ou `{"Error":"Not found"}`
/// (aucune fuite). `None` : réponse illisible. Les noms, écrits par le service, sont lus prêts à montrer.
fn lire_xposedornot(texte: &str) -> Option<Vec<String>> {
    let v: serde_json::Value = serde_json::from_str(texte).ok()?;
    if v["Error"] == "Not found" {
        return Some(Vec::new());
    }
    Some(
        v["breaches"][0]
            .as_array()?
            .iter()
            .filter_map(|n| n.as_str().map(affichable))
            .collect(),
    )
}

/// Noms des fuites d'une réponse Have I Been Pwned (`[{"Name":"Adobe"},…]`), prêts à montrer.
fn lire_hibp(texte: &str) -> Option<Vec<String>> {
    let v: serde_json::Value = serde_json::from_str(texte).ok()?;
    Some(
        v.as_array()?
            .iter()
            .filter_map(|f| f["Name"].as_str().map(affichable))
            .collect(),
    )
}

/// Clé de l'API de Have I Been Pwned, si elle est fournie (VANGUARD_HIBP_CLE).
fn cle_hibp() -> Option<String> {
    crate::passage::variable("VANGUARD_HIBP_CLE").filter(|c| !c.is_empty())
}

/// Fuites où apparaît l'adresse : par Have I Been Pwned si une clé est fournie (`cle_hibp`), sinon par
/// XposedOrNot (gratuit, sans clé). `None` : service injoignable.
fn fuites_courriel(adresse: &str) -> Option<(Vec<String>, &'static str)> {
    // La clé part dans un en-tête de la demande, jamais sur la ligne de commande d'un programme.
    let (adresse_du_service, service) = match cle_hibp() {
        Some(_) => (
            format!(
                "https://haveibeenpwned.com/api/v3/breachedaccount/{}?truncateResponse=true",
                encoder(adresse)
            ),
            "Have I Been Pwned",
        ),
        None => (
            format!("https://api.xposedornot.com/v1/check-email/{}", encoder(adresse)),
            "XposedOrNot",
        ),
    };
    let mut demande = crate::http::Demande::get(&adresse_du_service, std::time::Duration::from_secs(20));
    if let Some(cle) = cle_hibp() {
        demande.entetes.push(("hibp-api-key", cle));
    }
    let r = crate::http::envoyer(demande)?;
    let corps = r.texte();
    match (cle_hibp().is_some(), r.code) {
        // Have I Been Pwned répond 404 quand l'adresse n'apparaît dans aucune fuite.
        (true, 404) => Some((Vec::new(), service)),
        (true, 200) => lire_hibp(&corps).map(|l| (l, service)),
        (false, _) => lire_xposedornot(&corps).map(|l| (l, service)),
        _ => None,
    }
}

/// « vanguard courriel » : dans quelles fuites de données une adresse apparaît-elle ?
pub fn verifier_courriel() {
    titre(tr!("Fuites d'adresse courriel", "Email address leaks"));
    let service = if cle_hibp().is_some() {
        "Have I Been Pwned"
    } else {
        "XposedOrNot"
    };
    trp!(
        "  {GRIS}Contrairement aux mots de passe, l'adresse elle-même est envoyée au service ({service}) pour la recherche.{RESET}\n",
        "  {GRIS}Unlike passwords, the address itself is sent to the service ({service}) for the search.{RESET}\n"
    );
    let adresse = demander(tr!(
        "  Adresse courriel (Entrée pour annuler) : ",
        "  Email address (Enter to cancel): "
    ));
    if adresse.is_empty() {
        return;
    }
    if !adresse.contains('@') || adresse.contains(char::is_whitespace) {
        trp!(
            "  ✖ Ce n'est pas une adresse courriel.",
            "  ✖ That is not an email address."
        );
        return;
    }
    if !demander(&trf!(
        "  Envoyer « {adresse} » à {service} pour la recherche ? [o/N] : ",
        "  Send “{adresse}” to {service} for the search? [y/N]: "
    ))
    .oui()
    {
        trp!("  Annulé : rien n'a été envoyé.", "  Cancelled: nothing was sent.");
        return;
    }
    match fuites_courriel(&adresse) {
        None => trp!(
            "  ✖ Service injoignable (pas d'Internet, ou clé refusée).",
            "  ✖ Service unreachable (no Internet, or key refused)."
        ),
        Some((liste, _)) if liste.is_empty() => trp!(
            "\n  {VERT}✔{RESET} Cette adresse n'apparaît dans aucune fuite connue de {service}.",
            "\n  {VERT}✔{RESET} This address does not appear in any leak known to {service}."
        ),
        Some((liste, _)) => {
            trp!(
                "\n  {}✖ Trouvée dans {} fuite(s){RESET} : {}",
                "\n  {}✖ Found in {} leak(s){RESET}: {}",
                couleur(crate::risk::Niveau::Eleve),
                liste.len(),
                resume(&liste, 12, ", ")
            );
            trp!(
                "\n  {} Changez le mot de passe de ces sites (et partout où vous utilisiez le même), activez la\n     double authentification, et méfiez-vous des courriels qui citent ces sites : ils servent\n     à l'hameçonnage.",
                "\n  {} Change the password of these sites (and anywhere you used the same one), turn on two-factor\n     authentication, and beware of emails mentioning these sites: they are used for phishing.",
                ampoule()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empreinte_et_reponse() {
        // SHA-1 de « password » : 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8.
        let (debut, fin) = empreinte("password");
        assert_eq!(debut, "5BAA6");
        assert_eq!(fin, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
        let reponse = "0018A45C4D1DEF81644B54AB7F969B88D65:10\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:52256179\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0\r\n";
        assert_eq!(occurrences(reponse, &fin), 52_256_179);
        assert_eq!(occurrences(reponse, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), 0);
        assert_eq!(milliers(52_256_179), "52 256 179");
        assert_eq!(milliers(999), "999");
        assert!(conseil_forme("court").is_some());
        assert_eq!(encoder("jean+test@exemple.ca"), "jean%2Btest@exemple.ca");
        assert_eq!(lire_xposedornot(r#"{"Error":"Not found","email":null}"#), Some(vec![]));
        assert_eq!(
            lire_xposedornot(r#"{"breaches":[["Adobe","LinkedIn"]]}"#),
            Some(vec!["Adobe".to_string(), "LinkedIn".to_string()])
        );
        assert_eq!(lire_hibp(r#"[{"Name":"Adobe"}]"#), Some(vec!["Adobe".to_string()]));
        // Les noms viennent du service : piégés, ils arrivent inoffensifs.
        assert_eq!(
            lire_hibp(r#"[{"Name":"Ad\u001b]52;c;eA==\u0007obe\u202e"}]"#),
            Some(vec!["Ad�]52;c;eA==�obe�".to_string()])
        );
        assert_eq!(
            lire_xposedornot(r#"{"breaches":[["Linked\u001b[2K\rIn"]]}"#),
            Some(vec!["Linked�[2K�In".to_string()])
        );
        assert_eq!(lire_xposedornot("pas du json"), None);
        assert!(conseil_forme("cheval agrafe batterie correct").is_none());
    }
}

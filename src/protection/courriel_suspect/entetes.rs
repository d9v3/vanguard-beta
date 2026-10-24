//! L'expéditeur et son authentification. Ce que le courriel dit de lui-même (From, Reply-To, nom affiché) vient de
//! l'expéditeur, donc peut mentir ; seul le résultat SPF, DKIM et DMARC écrit par le fournisseur qui a remis le courriel
//! à la personne compte. Les en-têtes s'empilent par le haut : chaque serveur ajoute les siens au-dessus de ceux qu'il
//! a reçus. Le résultat du fournisseur est donc le plus haut ; un faux résultat « tout réussi » glissé par l'expéditeur
//! est forcément plus bas, sous les « Received » des serveurs qui l'ont transporté.

use super::Signe;
use super::mime::{self, Entete};
use crate::protection::lien;
use crate::risk::Niveau;
use crate::{tr, trf};

/// Une adresse lue dans un en-tête.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Adresse {
    /// Mots encodés décodés ; peut contenir n'importe quoi (à rendre `affichable` avant de le montrer).
    pub nom_affiche: String,
    /// « alice@example.com ».
    pub courriel: String,
    /// En minuscules, sans point final.
    pub domaine: String,
}

/// Les adresses d'un en-tête (RFC 5322, allégée) : « "Nom" <a@b> », « a@b (Nom) », groupes « Liste: a@b, c@d; »,
/// commentaires. Au plus `max` ; le nombre d'adresses laissées est rendu aussi.
pub(crate) fn adresses(brut: &[u8], max: usize) -> (Vec<Adresse>, usize) {
    let valeur = String::from_utf8_lossy(brut);
    let mut liste = Vec::new();
    let mut laissees = 0;
    for morceau in decouper_hors_guillemets(&valeur, ',') {
        // Un groupe : « Nom du groupe: » avant les adresses, « ; » après.
        let morceau = match position_hors_guillemets(&morceau, ':') {
            Some(i) if !morceau[..i].contains('<') => morceau[i + 1..].to_string(),
            _ => morceau,
        };
        let morceau = morceau.trim().trim_end_matches(';').trim();
        if morceau.is_empty() {
            continue;
        }
        let Some(a) = une_adresse(morceau) else {
            continue;
        };
        if liste.len() >= max {
            laissees += 1;
        } else {
            liste.push(a);
        }
    }
    (liste, laissees)
}

fn une_adresse(morceau: &str) -> Option<Adresse> {
    let (sans_commentaires, commentaires) = retirer_commentaires(morceau);
    let (nom, adresse) = match sans_commentaires.rfind('<') {
        Some(i) => {
            let fin = sans_commentaires[i..]
                .find('>')
                .map_or(sans_commentaires.len(), |f| i + f);
            (
                sans_commentaires[..i].trim().to_string(),
                sans_commentaires[i + 1..fin].trim().to_string(),
            )
        }
        None => (commentaires.trim().to_string(), sans_commentaires.trim().to_string()),
    };
    let adresse = adresse.trim_matches(['"', ' ']).to_string();
    // Le domaine finit dans des messages et dans la question « ces noms sortiront » : un ESC ou un caractère bidi
    // glissé par l'expéditeur piloterait le terminal ou cacherait le nom qui part. Il devient « � », qui se voit, et
    // un tel nom n'est jamais envoyé en ligne (`domaines_en_ligne` n'accepte que lettres, chiffres, points, tirets).
    let domaine = adresse
        .rsplit_once('@')
        .map(|(_, d)| crate::ui::affichable(&d.trim().trim_end_matches(['.', '>']).to_lowercase()))
        .unwrap_or_default();
    if adresse.is_empty() && nom.is_empty() {
        return None;
    }
    let nom = enlever_guillemets(&nom);
    Some(Adresse {
        nom_affiche: mime::mots_encodes(nom.as_bytes(), &mime::BORNES).trim().to_string(),
        courriel: adresse,
        domaine,
    })
}

fn enlever_guillemets(t: &str) -> String {
    let mut s = String::with_capacity(t.len());
    let mut echappe = false;
    for c in t.chars() {
        match c {
            _ if echappe => {
                s.push(c);
                echappe = false;
            }
            '\\' => echappe = true,
            '"' => {}
            _ => s.push(c),
        }
    }
    s
}

/// Le texte sans ses commentaires « (…) » (hors guillemets, emboîtables), et les commentaires mis bout à bout.
fn retirer_commentaires(t: &str) -> (String, String) {
    let mut sans = String::with_capacity(t.len());
    let mut commentaires = String::new();
    let mut profondeur = 0_usize;
    let mut guillemets = false;
    let mut echappe = false;
    for c in t.chars() {
        if echappe {
            if profondeur > 0 {
                commentaires.push(c);
            } else {
                sans.push(c);
            }
            echappe = false;
            continue;
        }
        match c {
            '\\' => {
                echappe = true;
                if profondeur == 0 {
                    sans.push(c);
                }
            }
            '"' if profondeur == 0 => {
                guillemets = !guillemets;
                sans.push(c);
            }
            '(' if !guillemets => {
                if profondeur > 0 {
                    commentaires.push(c);
                }
                profondeur += 1;
            }
            ')' if !guillemets && profondeur > 0 => {
                profondeur -= 1;
                if profondeur > 0 {
                    commentaires.push(c);
                } else {
                    commentaires.push(' ');
                }
            }
            _ if profondeur > 0 => commentaires.push(c),
            _ => sans.push(c),
        }
    }
    (sans, commentaires)
}

fn position_hors_guillemets(t: &str, cherche: char) -> Option<usize> {
    let mut guillemets = false;
    let mut angle = false;
    let mut echappe = false;
    for (i, c) in t.char_indices() {
        match c {
            _ if echappe => echappe = false,
            '\\' => echappe = true,
            '"' => guillemets = !guillemets,
            '<' if !guillemets => angle = true,
            '>' if !guillemets => angle = false,
            _ if c == cherche && !guillemets && !angle => return Some(i),
            _ => {}
        }
    }
    None
}

fn decouper_hors_guillemets(t: &str, sep: char) -> Vec<String> {
    let mut morceaux = Vec::new();
    let mut reste = t;
    while let Some(i) = position_hors_guillemets(reste, sep) {
        morceaux.push(reste[..i].to_string());
        reste = &reste[i + sep.len_utf8()..];
    }
    morceaux.push(reste.to_string());
    morceaux
}

// ───────────────────────────── Authentification ─────────────────────────────

/// Un résultat SPF, DKIM ou DMARC (RFC 8601).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Resultat {
    Reussi,
    Echec,
    /// « softfail » : SPF dit « probablement pas autorisé ».
    EchecLeger,
    Neutre,
    Aucun,
    ErreurTemp,
    ErreurPerm,
    Autre(String),
}

fn resultat(t: &str) -> Resultat {
    match t.to_ascii_lowercase().as_str() {
        "pass" => Resultat::Reussi,
        "fail" | "hardfail" => Resultat::Echec,
        "softfail" => Resultat::EchecLeger,
        "neutral" => Resultat::Neutre,
        "none" => Resultat::Aucun,
        "temperror" => Resultat::ErreurTemp,
        "permerror" => Resultat::ErreurPerm,
        autre => Resultat::Autre(autre.chars().take(20).collect()),
    }
}

/// Un en-tête Authentication-Results lu.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Authentification {
    pub rang: usize,
    /// Le serveur qui l'a écrit (« authserv-id ») ; absent dans le format de Microsoft.
    pub serveur: Option<String>,
    /// SPF et le domaine de l'enveloppe (smtp.mailfrom).
    pub spf: Option<(Resultat, Option<String>)>,
    /// Chaque signature DKIM et son domaine (header.d, sinon header.i).
    pub dkim: Vec<(Resultat, Option<String>)>,
    /// DMARC et le domaine du From (header.from).
    pub dmarc: Option<(Resultat, Option<String>)>,
    /// Le fournisseur a gardé le courriel malgré un échec DMARC, parce qu'il l'a reconnu comme renvoyé (liste de
    /// diffusion, transfert) : « compauth=pass » chez Microsoft, « arc=pass » avec « dis=NONE » chez Gmail.
    pub accepte_par_fournisseur: bool,
}

/// À quel point on peut croire que le résultat vient du fournisseur de la personne.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Confiance {
    /// Rien ne prouve qu'un serveur l'a écrit.
    Aucune,
    /// Écrit après le passage d'un serveur, sans que son nom le confirme.
    Moyenne,
    /// Écrit par le serveur qui a remis le courriel, ou l'un de ses voisins.
    Forte,
}

/// Microsoft n'écrit pas le nom de son serveur dans ses Authentication-Results : on reconnaît alors les siens aux noms
/// de ses serveurs dans les « Received » au-dessus.
const MICROSOFT_SANS_AUTHSERV: &[&str] = &["outlook.com", "office365.com", "microsoft.com"];

/// Fournisseurs qui écrivent TOUJOURS un Authentication-Results à leur nom en haut de chaque courriel reçu. Quand le
/// résultat est sous le « Received » du fournisseur, rien dans les en-têtes ne distingue le sien d'un faux glissé par
/// l'expéditeur au même nom (le nom d'un serveur de réception se lit dans le DNS) : seul un fournisseur qui en écrit
/// toujours un garantit que le plus haut est le sien.
const FOURNISSEURS_AVEC_AR: &[&str] = &[
    "google.com",
    "yahoo.com",
    "aol.com",
    "icloud.com",
    "me.com",
    "messagingengine.com",
    "fastmail.com",
    "protonmail.ch",
    "proton.me",
    "zoho.com",
    "gmx.net",
    "web.de",
    "yandex.net",
    "mail.ru",
    "outlook.com",
    "office365.com",
    "microsoft.com",
];

/// Lit un Authentication-Results : « serveur ; spf=pass smtp.mailfrom=… ; dkim=… header.d=… ; dmarc=… header.from=… ».
pub(crate) fn lire_resultats(e: &Entete) -> Authentification {
    let (texte, commentaires) = retirer_commentaires(&e.texte());
    let mut a = Authentification {
        rang: e.rang,
        ..Authentification::default()
    };
    // Gmail écrit la décision appliquée en commentaire du DMARC : « dmarc=fail (p=REJECT … dis=NONE) ».
    let dis_none = commentaires.to_ascii_lowercase().contains("dis=none");
    let mut arc = false;
    let mut morceaux = texte.split(';').map(str::trim).peekable();
    // Le premier morceau est le nom du serveur, sauf au format de Microsoft, qui commence par « spf=… ».
    if let Some(premier) = morceaux.peek()
        && !premier.split_whitespace().next().unwrap_or("").contains('=')
    {
        a.serveur = premier
            .split_whitespace()
            .next()
            .map(|s| s.trim_end_matches('.').to_lowercase())
            .filter(|s| !s.is_empty());
        morceaux.next();
    }
    for m in morceaux {
        let mut jetons = m.split_whitespace();
        let Some((methode, res)) = jetons.next().and_then(|j| j.split_once('=')) else {
            continue;
        };
        let proprietes: Vec<(String, String)> = jetons
            .filter_map(|j| j.split_once('='))
            .map(|(k, v)| {
                (
                    k.to_ascii_lowercase(),
                    v.trim_matches('"').trim_start_matches('@').to_lowercase(),
                )
            })
            .collect();
        let prop = |nom: &str| proprietes.iter().find(|(k, _)| k == nom).map(|(_, v)| v.clone());
        let r = resultat(res);
        match methode.to_ascii_lowercase().as_str() {
            "spf" if a.spf.is_none() => {
                a.spf = Some((r, prop("smtp.mailfrom").map(|v| domaine_de(&v))));
            }
            "dkim" if a.dkim.len() < 20 => {
                a.dkim
                    .push((r, prop("header.d").or_else(|| prop("header.i").map(|v| domaine_de(&v)))));
            }
            "dmarc" if a.dmarc.is_none() => a.dmarc = Some((r, prop("header.from"))),
            // L'avis final de Microsoft, qui tient compte des renvois qu'il connaît.
            "compauth" if r == Resultat::Reussi => a.accepte_par_fournisseur = true,
            // ARC seul ne suffit pas : n'importe qui scelle sa propre chaîne. Il faut que Gmail ait aussi renoncé à
            // appliquer la politique du domaine (dis=NONE).
            "arc" if r == Resultat::Reussi => arc = true,
            _ => {}
        }
    }
    a.accepte_par_fournisseur |= arc && dis_none;
    a
}

/// Ajoute à `a` ce qu'un autre résultat du même passage dit et que `a` ne dit pas (un filtre par méthode, comme
/// OpenDKIM puis OpenDMARC). `tout` : aussi les réussites ; sinon seulement les échecs, qu'un escroc n'a aucun
/// intérêt à glisser, alors qu'un faux résultat dit toujours « réussi ».
fn fusionner(a: &mut Authentification, b: Authentification, tout: bool) {
    let garde = |r: &Resultat| tout || *r != Resultat::Reussi;
    if a.spf.is_none() {
        a.spf = b.spf.filter(|(r, _)| garde(r));
    }
    if a.dmarc.is_none() {
        a.dmarc = b.dmarc.filter(|(r, _)| garde(r));
    }
    for d in b.dkim.into_iter().filter(|(r, _)| garde(r)) {
        if a.dkim.len() < 20 {
            a.dkim.push(d);
        }
    }
    a.accepte_par_fournisseur |= tout && b.accepte_par_fournisseur;
}

/// « alice@example.com » ou « example.com » → « example.com ».
fn domaine_de(v: &str) -> String {
    v.rsplit_once('@')
        .map_or(v, |(_, d)| d)
        .trim_end_matches('.')
        .to_lowercase()
}

/// L'hôte qui suit « by » dans un Received : le serveur qui a reçu le courriel à cette étape.
fn hote_by(e: &Entete) -> Option<String> {
    let (texte, _) = retirer_commentaires(&e.texte());
    let mut jetons = texte.split_whitespace();
    while let Some(j) = jetons.next() {
        if j.eq_ignore_ascii_case("by") {
            return jetons
                .next()
                .map(|h| h.trim_matches(['[', ']', ';']).trim_end_matches('.').to_lowercase())
                .filter(|h| !h.is_empty());
        }
    }
    None
}

fn ip(h: &str) -> bool {
    h.parse::<std::net::IpAddr>().is_ok()
}

/// Le résultat d'authentification à croire, et à quel point ; avec ce qui a été repéré en route (faux résultat glissé
/// plus bas). Seul le plus haut compte : c'est celui du fournisseur, si le fournisseur en écrit un.
pub(crate) fn lire_authentification(entetes: &[Entete]) -> (Option<(Authentification, Confiance)>, Vec<Signe>) {
    let mut signes = Vec::new();
    let tous: Vec<&Entete> = mime::toutes(entetes, "authentication-results").collect();
    let Some(haut) = tous.first() else {
        return (None, signes);
    };
    let mut a = lire_resultats(haut);
    let received: Vec<&Entete> = mime::toutes(entetes, "received").collect();
    // Aucun « Received » entre deux résultats : écrits au même passage, par le même serveur.
    let separe = |e: &Entete| received.iter().any(|r| r.rang > haut.rang && r.rang < e.rang);
    let meme_domaine = |x: &Option<String>| match (&a.serveur, x) {
        (Some(s), Some(x)) => lien::domaine_enregistrable(s) == lien::domaine_enregistrable(x),
        _ => false,
    };
    // Tout en haut, au-dessus de tout « Received », personne d'autre que le fournisseur n'a pu écrire : ses réussites
    // comptent aussi. Plus bas, un faux peut suivre le vrai sans « Received » entre eux : seuls ses échecs comptent.
    let au_sommet = !received.iter().any(|r| r.rang < haut.rang);
    let bloc: Vec<Authentification> = tous
        .iter()
        .skip(1)
        .filter(|e| !separe(e))
        .map(|e| lire_resultats(e))
        .filter(|b| meme_domaine(&b.serveur))
        .collect();
    for b in bloc {
        fusionner(&mut a, b, au_sommet);
    }
    let dessus: Vec<Option<String>> = received
        .iter()
        .filter(|r| r.rang < a.rang)
        .map(|r| hote_by(r))
        .collect();
    let juste_dessous: Option<Option<String>> = received.iter().find(|r| r.rang > a.rang).map(|r| hote_by(r));
    let du_serveur = |h: &Option<String>, serveur: &str| {
        h.as_deref()
            .is_some_and(|h| ip(h) || lien::domaine_enregistrable(h) == lien::domaine_enregistrable(serveur))
    };
    // Une adresse IP passe pour n'importe quel nom : il faut au moins un serveur NOMMÉ qui confirme.
    let nomme = |h: &Option<String>, serveur: &str| {
        h.as_deref()
            .is_some_and(|h| !ip(h) && lien::domaine_enregistrable(h) == lien::domaine_enregistrable(serveur))
    };
    let de_microsoft = |h: &Option<String>| {
        h.as_deref()
            .is_some_and(|h| ip(h) || MICROSOFT_SANS_AUTHSERV.contains(&lien::domaine_enregistrable(h).as_str()))
    };
    let microsoft_nomme = |h: &Option<String>| {
        h.as_deref()
            .is_some_and(|h| !ip(h) && MICROSOFT_SANS_AUTHSERV.contains(&lien::domaine_enregistrable(h).as_str()))
    };
    let confiance = if received.is_empty() {
        // Aucun serveur n'a laissé de trace : un fichier écrit à la main dirait n'importe quoi.
        Confiance::Aucune
    } else {
        // Au-dessus : chaque serveur doit être celui qui a écrit le résultat. Sans rien au-dessus, le résultat a été
        // ajouté par le serveur du Received juste en dessous (un filtre posé sur le serveur de réception) : son nom
        // doit alors le confirmer.
        // Sous un « Received », le résultat peut être un faux au nom du fournisseur, quand celui-ci n'en écrit pas :
        // il faut alors un fournisseur qui en écrit toujours un.
        let sous_un_received = !dessus.is_empty();
        let temoins: Vec<Option<String>> = if sous_un_received {
            dessus
        } else {
            juste_dessous.into_iter().collect()
        };
        let confirme = !temoins.is_empty()
            && match &a.serveur {
                Some(s) => {
                    temoins.iter().all(|h| du_serveur(h, s))
                        && temoins.iter().any(|h| nomme(h, s))
                        && (!sous_un_received
                            || FOURNISSEURS_AVEC_AR.contains(&lien::domaine_enregistrable(s).as_str()))
                }
                None => temoins.iter().all(de_microsoft) && temoins.iter().any(microsoft_nomme),
            };
        if confirme { Confiance::Forte } else { Confiance::Moyenne }
    };
    // Le fournisseur retire normalement tout résultat qui porte son nom (RFC 8601 §5) : un autre plus bas, au même nom,
    // a été écrit par l'expéditeur pour tromper.
    // Seulement plus bas qu'un « Received » : au-dessus, c'est le même passage (un filtre par méthode).
    if let Some(serveur) = &a.serveur {
        for e in tous.iter().skip(1).filter(|e| separe(e)) {
            if lire_resultats(e).serveur.as_deref() == Some(serveur) {
                signes.push((
                    Niveau::Moyen,
                    trf!(
                        "Faux résultat d'authentification glissé dans le courriel ({}) : ignoré.",
                        "Fake authentication result slipped into the email ({}): ignored.",
                        crate::ui::affichable(serveur)
                    ),
                ));
                break;
            }
        }
    }
    (Some((a, confiance)), signes)
}

/// Ce que dit l'authentification de l'expéditeur, avec la règle ASYMÉTRIQUE : un faux résultat dit toujours
/// « réussi ». Un échec compte dès que le résultat a pu être écrit par un serveur (confiance moyenne) ; un « réussi »
/// seulement quand il vient sûrement du fournisseur. Rend les signes, et ce qui n'a pas pu être vérifié.
pub(crate) fn juger_authentification(
    auth: Option<&(Authentification, Confiance)>,
    domaine_from: &str,
) -> (Vec<Signe>, Vec<String>) {
    let mut signes = Vec::new();
    let mut manques = Vec::new();
    let non_verifiable = || {
        tr!(
            "Authentification de l'expéditeur impossible à vérifier : aucun résultat écrit par votre fournisseur (ceux plus bas dans le courriel peuvent venir de l'expéditeur).",
            "Sender authentication could not be checked: no result written by your provider (those further down the email may come from the sender)."
        )
        .to_string()
    };
    let a_verifier = || tr!("l'authentification de l'expéditeur", "the sender's authentication").to_string();
    let Some((a, confiance)) = auth.filter(|(_, c)| *c > Confiance::Aucune) else {
        signes.push((Niveau::Info, non_verifiable()));
        manques.push(a_verifier());
        return (signes, manques);
    };
    if let Some((_, Some(de))) = &a.dmarc
        && !domaine_from.is_empty()
        && de != domaine_from
    {
        signes.push((
            Niveau::Moyen,
            trf!(
                "Le résultat d'authentification parle d'un autre expéditeur ({}) que celui affiché ({}) : pas utilisé.",
                "The authentication result is about another sender ({}) than the one shown ({}): not used.",
                crate::ui::affichable(de),
                crate::ui::affichable(domaine_from)
            ),
        ));
        manques.push(a_verifier());
        return (signes, manques);
    }
    let aligne = |d: &Option<String>| {
        d.as_deref().is_some_and(|d| {
            !domaine_from.is_empty() && lien::domaine_enregistrable(d) == lien::domaine_enregistrable(domaine_from)
        })
    };
    let usurpation = |texte_dmarc: bool| -> Signe {
        let marque = lien::marque_officielle(domaine_from);
        let niveau = if marque.is_some() {
            Niveau::Critique
        } else {
            Niveau::Eleve
        };
        let domaine = crate::ui::affichable(domaine_from);
        (
            niveau,
            if texte_dmarc {
                trf!(
                    "DMARC : échec. {domaine} n'a pas autorisé cet envoi : quelqu'un se fait passer pour lui.",
                    "DMARC: fail. {domaine} did not authorize this sending: someone is impersonating it."
                )
            } else {
                trf!(
                    "SPF en échec et aucune signature DKIM valide : {domaine} n'a pas envoyé ce courriel.",
                    "SPF failed and no valid DKIM signature: {domaine} did not send this email."
                )
            },
        )
    };
    let dkim_aligne = a.dkim.iter().any(|(r, d)| *r == Resultat::Reussi && aligne(d));
    let dkim_reussi = a.dkim.iter().any(|(r, _)| *r == Resultat::Reussi);
    let spf = a.spf.as_ref().map(|(r, _)| r);
    let spf_aligne = a.spf.as_ref().is_some_and(|(r, d)| *r == Resultat::Reussi && aligne(d));
    let authentique = (
        Niveau::Info,
        tr!(
            "Domaine de l'expéditeur authentifié par votre fournisseur. Authentique ne veut pas dire honnête : un escroc authentifie très bien son propre domaine.",
            "Sender domain authenticated by your provider. Authentic does not mean honest: a scammer authenticates their own domain just fine."
        )
        .to_string(),
    );
    let incertain = || {
        tr!(
            "le résultat d'authentification (pas sûr qu'il vienne de votre fournisseur)",
            "the authentication result (not sure it comes from your provider)"
        )
        .to_string()
    };
    // Dit aussi dans la section, pas seulement au verdict : sinon elle resterait vide.
    let pas_cru = || {
        (
            Niveau::Info,
            tr!(
                "Le résultat dit « réussi », mais rien ne prouve que votre fournisseur l'a écrit : il n'est pas cru.",
                "The result says “pass”, but nothing proves your provider wrote it: it is not trusted."
            )
            .to_string(),
        )
    };
    match a.dmarc.as_ref().map(|(r, _)| r) {
        // Courriel renvoyé (liste de diffusion, transfert) que le fournisseur a reconnu : l'échec ne prouve rien, la
        // réussite non plus.
        Some(Resultat::Echec) if a.accepte_par_fournisseur => {
            signes.push((
                Niveau::Moyen,
                tr!(
                    "DMARC : échec, mais votre fournisseur l'a quand même accepté (courriel renvoyé ou liste de diffusion). Rien n'a pu être conclu.",
                    "DMARC: fail, but your provider still accepted it (forwarded email or mailing list). Nothing could be concluded."
                )
                .to_string(),
            ));
            manques.push(a_verifier());
        }
        Some(Resultat::Echec) => signes.push(usurpation(true)),
        Some(Resultat::Reussi) if *confiance == Confiance::Forte => signes.push(authentique),
        Some(Resultat::Reussi) => {
            signes.push(pas_cru());
            manques.push(incertain());
        }
        Some(Resultat::ErreurTemp | Resultat::ErreurPerm) => {
            signes.push((
                Niveau::Info,
                tr!(
                    "DMARC : erreur du côté du fournisseur, rien n'a pu être conclu.",
                    "DMARC: error on the provider's side, nothing could be concluded."
                )
                .to_string(),
            ));
            manques.push(a_verifier());
        }
        // Pas de DMARC (le domaine n'en publie pas, ou le fournisseur ne le vérifie pas) : SPF et DKIM.
        _ => {
            if spf == Some(&Resultat::Echec) && !dkim_reussi {
                signes.push(usurpation(false));
            } else if spf == Some(&Resultat::EchecLeger) && !dkim_reussi {
                signes.push((
                    Niveau::Moyen,
                    trf!(
                        "SPF : « probablement pas autorisé » et aucune signature DKIM valide : {} n'a peut-être pas envoyé ce courriel.",
                        "SPF: “probably not authorized” and no valid DKIM signature: {} may not have sent this email.",
                        crate::ui::affichable(domaine_from)
                    ),
                ));
            } else if dkim_aligne || spf_aligne {
                if *confiance == Confiance::Forte {
                    signes.push(authentique);
                } else {
                    signes.push(pas_cru());
                    manques.push(incertain());
                }
            } else if a.dkim.iter().any(|(r, _)| *r == Resultat::Echec) && !dkim_reussi {
                signes.push((
                    Niveau::Moyen,
                    tr!(
                        "Signature DKIM invalide : le courriel a pu être modifié en route.",
                        "Invalid DKIM signature: the email may have been altered on the way."
                    )
                    .to_string(),
                ));
            } else {
                signes.push((
                    Niveau::Info,
                    tr!(
                        "Aucune authentification réussie au nom de l'expéditeur affiché : rien ne prouve qu'il l'a envoyé.",
                        "No successful authentication for the sender shown: nothing proves they sent it."
                    )
                    .to_string(),
                ));
                manques.push(a_verifier());
            }
        }
    }
    // Un échec SPF seul, quand DKIM signe bien pour l'expéditeur : souvent un transfert, pas une usurpation.
    if matches!(spf, Some(Resultat::Echec | Resultat::EchecLeger)) && dkim_aligne {
        signes.push((
            Niveau::Info,
            tr!(
                "SPF en échec mais signature DKIM valide : souvent un courriel transféré.",
                "SPF failed but valid DKIM signature: often a forwarded email."
            )
            .to_string(),
        ));
    }
    (signes, manques)
}

// ───────────────────────────── Expéditeur ─────────────────────────────

/// Les messageries gratuites : n'importe qui y ouvre une adresse en une minute.
const FOURNISSEURS_GRATUITS: &str = "gmail.com googlemail.com outlook.com hotmail.com live.com msn.com yahoo.com \
yahoo.fr yahoo.ca ymail.com aol.com icloud.com me.com proton.me protonmail.com gmx.com gmx.fr gmx.de mail.com \
zoho.com yandex.com yandex.ru mail.ru orange.fr free.fr laposte.net sfr.fr videotron.ca sympatico.ca hotmail.fr \
outlook.fr live.fr live.ca hotmail.ca";

pub(crate) fn gratuit(domaine: &str) -> bool {
    let d = lien::domaine_enregistrable(domaine);
    FOURNISSEURS_GRATUITS.split_whitespace().any(|g| g == d)
}

/// Les mots qui accompagnent une marque dans un faux nom d'expéditeur (« PayPal Service Client ») : un nom fait
/// seulement d'une marque et de ces mots se fait passer pour elle ; un nom de personne (« Alice Rogers ») non.
const MOTS_GENERIQUES: &str = "service services support team equipe équipe securite sécurité security account accounts \
compte comptes client clients customer customers notification notifications alert alerts alerte alertes noreply no \
reply ne pas repondre répondre info infos information billing facturation facture invoice help aide assistance \
the le la les de du des d l from via inc canada france quebec québec online en ligne care center centre official \
officiel officielle mail messagerie verification vérification update mise à jour your votre ton ta tes";

/// Marques dont le nom est aussi un nom de personne ou un mot courant : comptées seulement quand le nom affiché ne dit
/// rien d'autre.
const MARQUES_AMBIGUES: &[&str] = &[
    "Rogers",
    "Ameli",
    "Apple",
    "Meta",
    "Steam",
    "Tangerine",
    "Telegram",
    "Discord",
    "Twitch",
    "Amazon",
    "Adobe",
];

/// L'expéditeur : nom affiché, adresse, domaine, adresse de réponse.
pub(crate) fn examiner_expediteur(entetes: &[Entete]) -> Vec<Signe> {
    let mut signes = Vec::new();
    let froms: Vec<&Entete> = mime::toutes(entetes, "from").collect();
    let Some(premier) = froms.first() else {
        signes.push((
            Niveau::Moyen,
            tr!(
                "Pas d'expéditeur (aucun en-tête From) : on ne sait pas qui l'envoie.",
                "No sender (no From header): we do not know who sends it."
            )
            .to_string(),
        ));
        return signes;
    };
    let (liste, laissees) = adresses(&premier.brut, 20);
    if froms.len() > 1 || liste.len() + laissees > 1 {
        signes.push((
            Niveau::Eleve,
            tr!(
                "Plusieurs expéditeurs : les logiciels de courriel n'affichent pas tous le même, une ruse pour tromper les filtres.",
                "Several senders: mail programs do not all show the same one, a trick to fool filters."
            )
            .to_string(),
        ));
    }
    let Some(de) = liste.first().filter(|a| !a.domaine.is_empty()) else {
        signes.push((
            Niveau::Moyen,
            tr!("Adresse de l'expéditeur illisible.", "Sender address unreadable.").to_string(),
        ));
        return signes;
    };
    let domaine = de.domaine.clone();
    let montre = |t: &str| crate::ui::affichable(t);
    if de.courriel.chars().any(crate::ui::piege) {
        signes.push((
            Niveau::Eleve,
            trf!(
                "Adresse de l'expéditeur piégée : elle contient des caractères qui pilotent le terminal ou retournent l'écriture (« {} »).",
                "Trapped sender address: it contains characters that drive the terminal or reverse the text (“{}”).",
                montre(&de.courriel)
            ),
        ));
    }
    if de.nom_affiche.chars().any(crate::ui::piege) {
        signes.push((
            Niveau::Moyen,
            trf!(
                "Caractères invisibles ou qui retournent l'écriture dans le nom affiché : « {} ».",
                "Invisible or text-reversing characters in the display name: “{}”.",
                montre(&de.nom_affiche)
            ),
        ));
    }
    // Une adresse dans le nom affiché : beaucoup de logiciels ne montrent que le nom.
    if let Some(autre) = de
        .nom_affiche
        .split(|c: char| c.is_whitespace() || "<>()\"',;".contains(c))
        .find(|m| m.contains('@') && m.rsplit_once('@').is_some_and(|(_, d)| d.contains('.')))
        .filter(|m| domaine_de(m) != domaine)
    {
        signes.push((
            Niveau::Eleve,
            trf!(
                "Le nom affiché contient une autre adresse (« {} ») : le vrai expéditeur est {}.",
                "The display name contains another address (“{}”): the real sender is {}.",
                montre(autre),
                montre(&de.courriel)
            ),
        ));
    }
    // Une marque dans le nom affiché, envoyée d'ailleurs que de ses domaines. Une boîte gratuite (gmail.com,
    // outlook.com) n'est jamais le domaine officiel d'une marque, même quand elle lui appartient : n'importe qui en
    // ouvre une, et Google ou Microsoft écrivent leurs vraies alertes depuis leurs propres domaines.
    if let Some((marque, vrai)) = lien::marque_nommee(&de.nom_affiche)
        && (gratuit(&domaine) || lien::marque_officielle(&domaine) != Some(marque))
    {
        // « PаyPаl » en а cyrillique, « PayPaI » avec un I majuscule : la marque ne se lit qu'une fois les lettres
        // ramenées à ce qu'on voit. Personne n'écrit ainsi le nom d'une marque sans vouloir tromper.
        if lien::marque_nommee_telle_quelle(&de.nom_affiche).is_none() {
            signes.push((
                Niveau::Eleve,
                trf!(
                    "Le nom affiché imite {marque} avec des lettres déguisées (« {} ») ; l'adresse vient de {} (le vrai : {vrai}).",
                    "The display name imitates {marque} with disguised letters (“{}”); the address comes from {} (the real one: {vrai}).",
                    montre(&de.nom_affiche),
                    montre(&domaine)
                ),
            ));
        }
        let generiques: Vec<&str> = MOTS_GENERIQUES.split_whitespace().collect();
        let marque_mots: Vec<String> = marque
            .split(|c: char| !c.is_alphanumeric())
            .map(str::to_lowercase)
            .collect();
        let seule = de
            .nom_affiche
            .split(|c: char| !c.is_alphanumeric())
            .filter(|m| !m.is_empty())
            .map(str::to_lowercase)
            .all(|m| {
                generiques.contains(&m.as_str())
                    || marque_mots.contains(&m)
                    || lien::marque_nommee(&m).is_some_and(|(n, _)| n == marque)
                    || m.chars().all(|c| c.is_ascii_digit())
            });
        let deguise = lien::marque_nommee_telle_quelle(&de.nom_affiche).is_none();
        let niveau = if deguise {
            None
        } else if gratuit(&domaine) || seule {
            Some(Niveau::Eleve)
        } else if MARQUES_AMBIGUES.contains(&marque) {
            None
        } else {
            Some(Niveau::Moyen)
        };
        if let Some(niveau) = niveau {
            signes.push((
                niveau,
                if gratuit(&domaine) {
                    trf!(
                        "Le nom affiché parle de {marque}, mais l'adresse est une messagerie gratuite ({}) : {marque} écrit depuis {vrai}.",
                        "The display name mentions {marque}, but the address is a free mailbox ({}): {marque} writes from {vrai}.",
                        montre(&domaine)
                    )
                } else {
                    trf!(
                        "Le nom affiché parle de {marque}, mais l'adresse vient de {} (le vrai : {vrai}).",
                        "The display name mentions {marque}, but the address comes from {} (the real one: {vrai}).",
                        montre(&domaine)
                    )
                },
            ));
        }
    }
    signes.extend(lien::examiner_domaine(&domaine));

    // Les réponses : envoyées ailleurs que chez l'expéditeur, elles vont à l'escroc.
    if let Some(r) = mime::valeur(entetes, "reply-to") {
        let (reponses, _) = adresses(&r.brut, 20);
        let mut vus = Vec::new();
        for rep in reponses.iter().filter(|a| !a.domaine.is_empty()) {
            if lien::domaine_enregistrable(&rep.domaine) == lien::domaine_enregistrable(&domaine)
                || vus.contains(&rep.domaine)
            {
                continue;
            }
            vus.push(rep.domaine.clone());
            let grave = gratuit(&rep.domaine) && !gratuit(&domaine);
            signes.push((
                if grave { Niveau::Eleve } else { Niveau::Moyen },
                if grave {
                    trf!(
                        "Les réponses partent vers une messagerie gratuite ({}), pas vers {} : le classique « on répond à l'escroc ».",
                        "Replies go to a free mailbox ({}), not to {}: the classic “you reply to the scammer”.",
                        montre(&rep.courriel),
                        montre(&domaine)
                    )
                } else {
                    trf!(
                        "Les réponses partent ailleurs : {}, pas {}.",
                        "Replies go elsewhere: {}, not {}.",
                        montre(&rep.domaine),
                        montre(&domaine)
                    )
                },
            ));
            signes.extend(
                lien::examiner_domaine(&rep.domaine)
                    .into_iter()
                    .filter(|(n, _)| *n > Niveau::Info),
            );
        }
    }
    // L'adresse de retour (enveloppe) : les services d'envoi (infolettres, factures) en ont une à eux, honnêtement.
    if let Some(rp) = mime::valeur(entetes, "return-path") {
        let (retour, _) = adresses(&rp.brut, 1);
        if let Some(r) = retour.first().filter(|r| {
            !r.domaine.is_empty() && lien::domaine_enregistrable(&r.domaine) != lien::domaine_enregistrable(&domaine)
        }) {
            signes.push((
                Niveau::Info,
                trf!(
                    "Adresse de retour d'un autre domaine ({}) : courant pour les services d'envoi, pas une preuve.",
                    "Return address from another domain ({}): common for sending services, not proof.",
                    montre(&r.domaine)
                ),
            ));
        }
    }
    signes
}

/// L'adresse du premier From, s'il y en a une.
pub(crate) fn expediteur(entetes: &[Entete]) -> Option<Adresse> {
    mime::valeur(entetes, "from").and_then(|e| adresses(&e.brut, 1).0.into_iter().next())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entetes(texte: &str) -> Vec<Entete> {
        mime::lire(format!("{texte}\n\ncorps").as_bytes()).entetes
    }

    fn pire(signes: &[Signe]) -> Option<Niveau> {
        signes.iter().map(|(n, _)| *n).max()
    }

    #[test]
    fn adresses_rfc5322() {
        let (l, _) = adresses(b"\"Alice, la vraie\" <alice@example.com>", 5);
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].nom_affiche, "Alice, la vraie");
        assert_eq!(l[0].domaine, "example.com");
        let (l, _) = adresses(b"bob@Example.ORG (Bob B.)", 5);
        assert_eq!(
            (l[0].nom_affiche.as_str(), l[0].domaine.as_str()),
            ("Bob B.", "example.org")
        );
        let (l, _) = adresses(b"Amis: a@example.com, b@example.org;", 5);
        assert_eq!(
            l.iter().map(|a| a.courriel.as_str()).collect::<Vec<_>>(),
            ["a@example.com", "b@example.org"]
        );
        let (l, laissees) = adresses(b"a@example.com, b@example.com, c@example.com", 2);
        assert_eq!((l.len(), laissees), (2, 1));
        let (l, _) = adresses(b"=?utf-8?Q?Caf=C3=A9?= <x@example.net>", 5);
        assert_eq!(l[0].nom_affiche, "Café");
    }

    #[test]
    fn authentification_du_fournisseur() {
        let e = entetes(
            "Received: from mail.example.org by mx.example.net with ESMTPS\n\
Authentication-Results: mx.example.net; spf=fail smtp.mailfrom=example.org; dkim=none; dmarc=fail header.from=example.org\n\
Received: from x by mail.example.org\nFrom: a@example.org",
        );
        let (a, signes) = lire_authentification(&e);
        let (a, c) = a.unwrap();
        // Sous le Received d'un fournisseur qui n'écrit pas toujours de résultat : un échec compte quand même.
        assert_eq!(c, Confiance::Moyenne);
        assert_eq!(signes, Vec::<Signe>::new());
        assert_eq!(a.serveur.as_deref(), Some("mx.example.net"));
        assert_eq!(a.dmarc, Some((Resultat::Echec, Some("example.org".into()))));
        let (s, _) = juger_authentification(Some(&(a.clone(), c)), "example.org");
        assert_eq!(pire(&s), Some(Niveau::Eleve));
        // Le même échec pour un domaine officiel d'une marque : usurpation.
        let mut a2 = a;
        a2.dmarc = Some((Resultat::Echec, Some("paypal.com".into())));
        let (s, _) = juger_authentification(Some(&(a2, Confiance::Moyenne)), "paypal.com");
        assert_eq!(pire(&s), Some(Niveau::Critique));
    }

    #[test]
    fn faux_resultats_jamais_crus() {
        // Seul résultat, placé sous tous les Received, disant « réussi » : écrit par l'expéditeur, pas cru.
        let e = entetes(
            "Received: from x by mx.example.net\nReceived: from y by relais.example.org\n\
Authentication-Results: mx.google.com; dmarc=pass header.from=paypal.com\nFrom: support@paypal.com",
        );
        let (a, _) = lire_authentification(&e);
        let a = a.unwrap();
        assert_eq!(a.1, Confiance::Moyenne);
        let (s, manques) = juger_authentification(Some(&a), "paypal.com");
        assert!(s.iter().all(|(_, t)| !t.contains("authentifié")), "{s:?}");
        assert_ne!(manques, Vec::<String>::new());
        // Sans aucun Received : rien ne prouve qu'un serveur l'a écrit.
        let e = entetes("Authentication-Results: mx.example.net; dmarc=pass\nFrom: a@example.org");
        let (a, _) = lire_authentification(&e);
        assert_eq!(a.as_ref().unwrap().1, Confiance::Aucune);
        let (s, manques) = juger_authentification(a.as_ref(), "example.org");
        assert_eq!(pire(&s), Some(Niveau::Info));
        assert!(s[0].1.contains("impossible à vérifier"));
        assert_eq!(manques.len(), 1);
        // Le fournisseur dit échec, un faux plus bas dit réussi : l'échec est retenu, le faux signalé.
        let e = entetes(
            "Received: by mx.example.net\nAuthentication-Results: mx.example.net; dmarc=fail header.from=example.org\n\
Received: from a by b.example.org\nAuthentication-Results: mx.example.net; dmarc=pass header.from=example.org\n\
From: a@example.org",
        );
        let (a, signes) = lire_authentification(&e);
        assert_eq!(pire(&signes), Some(Niveau::Moyen));
        assert!(signes[0].1.contains("glissé"));
        let (s, _) = juger_authentification(a.as_ref(), "example.org");
        assert_eq!(pire(&s), Some(Niveau::Eleve));
    }

    #[test]
    fn autre_expediteur_et_microsoft() {
        let a = Authentification {
            dmarc: Some((Resultat::Reussi, Some("example.com".into()))),
            ..Authentification::default()
        };
        let (s, manques) = juger_authentification(Some(&(a, Confiance::Forte)), "example.org");
        assert_eq!(pire(&s), Some(Niveau::Moyen));
        assert_ne!(manques, Vec::<String>::new());
        // Format de Microsoft, sans nom de serveur, sous des Received de ses serveurs : cru.
        let e = entetes(
            "Received: from a.prod.outlook.com (2603:10b6::1) by b.prod.outlook.com\n\
Authentication-Results: spf=pass (sender IP is 192.0.2.1) smtp.mailfrom=example.com; dkim=pass (signature was verified) header.d=example.com;dmarc=pass action=none header.from=example.com;compauth=pass reason=100\n\
From: a@example.com",
        );
        let (a, _) = lire_authentification(&e);
        let (a, c) = a.unwrap();
        assert_eq!(c, Confiance::Forte);
        assert!(a.serveur.is_none());
        assert_eq!(a.spf, Some((Resultat::Reussi, Some("example.com".into()))));
        let (s, manques) = juger_authentification(Some(&(a, c)), "example.com");
        assert!(
            s[0].1.contains("Authentique ne veut pas dire honnête") && manques.is_empty(),
            "{s:?}"
        );
        // Faux « mx.google.com » sous le Received d'un fournisseur qui n'en écrit pas : pas Forte.
        let e = entetes(
            "Received: from a by mail.example.net\nAuthentication-Results: mx.google.com; dmarc=pass\nFrom: a@example.com",
        );
        assert_eq!(lire_authentification(&e).0.unwrap().1, Confiance::Moyenne);
        // Écrit tout en haut par le filtre du serveur de réception, dont le Received suit juste dessous : cru.
        let e = entetes(
            "Authentication-Results: mx.example.net; dkim=pass header.d=example.com\nReceived: from a by mx2.example.net\n\
From: a@example.com",
        );
        let (a, _) = lire_authentification(&e);
        assert_eq!(a.as_ref().unwrap().1, Confiance::Forte);
        let (s, _) = juger_authentification(a.as_ref(), "example.com");
        assert_eq!(pire(&s), Some(Niveau::Info));
        // Erreur temporaire : rien de conclu.
        let a = Authentification {
            dmarc: Some((Resultat::ErreurTemp, None)),
            ..Authentification::default()
        };
        let (_, manques) = juger_authentification(Some(&(a, Confiance::Forte)), "example.com");
        assert_ne!(manques, Vec::<String>::new());
    }

    #[test]
    fn expediteurs() {
        let pire_de = |t: &str| pire(&examiner_expediteur(&entetes(t)));
        assert_eq!(pire_de("From: \"PayPal\" <alice@example.org>"), Some(Niveau::Eleve));
        assert_eq!(
            pire_de("From: PayPal Service Client <alice@example.org>"),
            Some(Niveau::Eleve)
        );
        assert_eq!(pire_de("From: PayPal <noreply@gmail.com>"), Some(Niveau::Eleve));
        assert_eq!(
            pire_de("From: \"support@paypal.com\" <x@exemple.example>"),
            Some(Niveau::Eleve)
        );
        assert_eq!(pire_de("From: Alice <alice@example.com>"), None);
        assert_eq!(pire_de("From: Alice Rogers <alice@example.com>"), None);
        assert_eq!(pire_de("From: PayPal <support@paypal.com>"), None);
        assert_eq!(pire_de("From: a@example.com\nFrom: b@example.org"), Some(Niveau::Eleve));
        assert_eq!(pire_de("From: a@example.com, b@example.org"), Some(Niveau::Eleve));
        assert_eq!(pire_de("To: a@example.com"), Some(Niveau::Moyen));
        // Nom RFC 2047 contenant U+202E : signalé, montré avec « � ».
        let s = examiner_expediteur(&entetes("From: =?utf-8?B?4oCuQWxpY2U=?= <alice@example.com>"));
        assert_eq!(pire(&s), Some(Niveau::Moyen));
        assert!(s[0].1.contains('\u{fffd}') && !s[0].1.contains('\u{202e}'));
        // Domaine punycode qui imite PayPal en lettres cyrilliques.
        assert_eq!(pire_de("From: support@xn--pypal-4ve.com"), Some(Niveau::Critique));
        // « UPS » en majuscules : la marque ; « Oups » : rien.
        assert_eq!(pire_de("From: UPS <suivi@example.org>"), Some(Niveau::Eleve));
        assert_eq!(pire_de("From: Oups Alice <alice@example.org>"), None);
    }

    #[test]
    fn faux_resultat_au_nom_du_fournisseur() {
        // A : un faux au nom du MX (lu dans le DNS), sous le Received de ce fournisseur, qui n'en écrit pas.
        let e = entetes(
            "Received: from smtp.paypa1.example ([192.0.2.9]) by mx1.example.net with ESMTP\n\
Authentication-Results: mx2.example.net; spf=pass smtp.mailfrom=paypal.com; dkim=pass header.d=paypal.com; dmarc=pass header.from=paypal.com\n\
From: PayPal <support@paypal.com>",
        );
        let (a, _) = lire_authentification(&e);
        assert_eq!(a.as_ref().unwrap().1, Confiance::Moyenne);
        let (s, manques) = juger_authentification(a.as_ref(), "paypal.com");
        assert!(s.iter().all(|(_, t)| !t.contains("Authentique")), "{s:?}");
        assert!(s.iter().any(|(_, t)| t.contains("pas cru")), "{s:?}");
        assert_ne!(manques, Vec::<String>::new());
        // B : une adresse IP au-dessus ne témoigne pour aucun nom, pas même mx.google.com.
        let e = entetes(
            "Received: from smtp.paypa1.example ([192.0.2.9]) by 192.0.2.25 with ESMTP\n\
Authentication-Results: mx.google.com; dmarc=pass header.from=paypal.com\n\
From: PayPal <support@paypal.com>",
        );
        assert_eq!(lire_authentification(&e).0.unwrap().1, Confiance::Moyenne);
        // Le vrai Gmail : une adresse IP puis mx.google.com au-dessus de son résultat.
        let e = entetes(
            "Received: by 2001:db8::1 with SMTP id x\n\
Received: from mail.example.com by mx.google.com with ESMTPS\n\
Authentication-Results: mx.google.com; dmarc=pass header.from=example.com\n\
From: alice@example.com",
        );
        assert_eq!(lire_authentification(&e).0.unwrap().1, Confiance::Forte);
    }

    #[test]
    fn resultats_du_meme_passage() {
        // OpenDMARC, OpenDKIM, policyd-spf : un résultat chacun, au même nom, au-dessus du seul Received.
        let bloc = |dmarc: &str| {
            entetes(&format!(
                "Authentication-Results: mail.example.net; spf=pass smtp.mailfrom=example.com\n\
Authentication-Results: mail.example.net; dmarc={dmarc} header.from=example.com\n\
Authentication-Results: mail.example.net; dkim=pass header.d=example.com\n\
Received: from a.example.com by mail.example.net\n\
From: alice@example.com"
            ))
        };
        let (a, signes) = lire_authentification(&bloc("pass"));
        assert_eq!(signes, Vec::<Signe>::new());
        let (a, c) = a.unwrap();
        assert_eq!(c, Confiance::Forte);
        assert_eq!(a.dkim.len(), 1);
        let (s, manques) = juger_authentification(Some(&(a, c)), "example.com");
        assert!(
            s[0].1.contains("Authentique ne veut pas dire honnête") && manques.is_empty(),
            "{s:?}"
        );
        // Le vrai échec du fournisseur, dans le deuxième : compté.
        let (a, _) = lire_authentification(&bloc("fail"));
        let (s, _) = juger_authentification(a.as_ref(), "example.com");
        assert_eq!(pire(&s), Some(Niveau::Eleve), "{s:?}");
        // Sous un Received, un « réussi » qui suit le vrai résultat peut être un faux : seuls les échecs comptent.
        let e = entetes(
            "Received: from a.example.org by mx.google.com\n\
Authentication-Results: mx.google.com; spf=none\n\
Authentication-Results: mx.google.com; dmarc=pass header.from=example.org; dkim=pass header.d=example.org\n\
From: a@example.org",
        );
        let (a, _) = lire_authentification(&e);
        let a = a.unwrap().0;
        assert_eq!((a.dmarc, a.dkim.len()), (None, 0));
    }

    #[test]
    fn dmarc_accepte_par_le_fournisseur() {
        let f = |compauth: &str| {
            entetes(&format!(
                "Received: from a.prod.outlook.com (2603:10b6::1) by b.prod.outlook.com\n\
Authentication-Results: spf=fail (sender IP is 192.0.2.7) smtp.mailfrom=desjardins.com; dkim=fail (body hash did not verify) header.d=desjardins.com;dmarc=fail action=none header.from=desjardins.com;compauth={compauth} reason=130\n\
Received: from liste.example.org by c.outlook.com\n\
From: Desjardins <info@desjardins.com>"
            ))
        };
        let (a, _) = lire_authentification(&f("pass"));
        let (s, manques) = juger_authentification(a.as_ref(), "desjardins.com");
        assert_eq!(pire(&s), Some(Niveau::Moyen), "{s:?}");
        assert_ne!(manques, Vec::<String>::new());
        let (a, _) = lire_authentification(&f("fail"));
        let (s, _) = juger_authentification(a.as_ref(), "desjardins.com");
        assert_eq!(pire(&s), Some(Niveau::Critique));
        // Gmail : arc=pass et la politique non appliquée (dis=NONE) ; arc=pass seul ne suffit pas.
        let g = |dis: &str| {
            entetes(&format!(
                "Received: from liste.example.org by mx.google.com\n\
Authentication-Results: mx.google.com; arc=pass (i=1); dmarc=fail (p=REJECT sp=REJECT dis={dis}) header.from=desjardins.com\n\
From: info@desjardins.com"
            ))
        };
        let (a, _) = lire_authentification(&g("NONE"));
        assert_eq!(
            pire(&juger_authentification(a.as_ref(), "desjardins.com").0),
            Some(Niveau::Moyen)
        );
        let (a, _) = lire_authentification(&g("QUARANTINE"));
        assert_eq!(
            pire(&juger_authentification(a.as_ref(), "desjardins.com").0),
            Some(Niveau::Critique)
        );
    }

    #[test]
    fn domaine_piege_jamais_brut() {
        let e = entetes("From: Bob <support@paypal.com.x\x1b[2J\x1b[8mcache.example>\nReply-To: r@a\x07b.example.org");
        let de = expediteur(&e).unwrap();
        assert!(!de.domaine.chars().any(char::is_control), "{:?}", de.domaine);
        let s = examiner_expediteur(&e);
        assert!(s.iter().all(|(_, t)| !t.chars().any(char::is_control)), "{s:?}");
        assert!(
            s.iter().any(|(n, t)| *n == Niveau::Eleve && t.contains("piégée")),
            "{s:?}"
        );
        // Le sous-domaine trompeur reste vu.
        assert_eq!(pire(&s), Some(Niveau::Critique));
    }

    #[test]
    fn marques_depuis_une_boite_gratuite_ou_deguisees() {
        let pire_de = |t: &str| pire(&examiner_expediteur(&entetes(t)));
        assert_eq!(
            pire_de("From: Microsoft account team <noreply@outlook.com>"),
            Some(Niveau::Eleve)
        );
        assert_eq!(
            pire_de("From: Google Security <noreply@gmail.com>"),
            Some(Niveau::Eleve)
        );
        // Les vrais avis de Facebook.
        assert!(pire_de("From: Facebook <security@facebookmail.com>") <= Some(Niveau::Info));
        for nom in ["P\u{430}yP\u{430}l", "PayPaI"] {
            let s = examiner_expediteur(&entetes(&format!("From: {nom} <avis@notifications-compte.example>")));
            assert_eq!(pire(&s), Some(Niveau::Eleve), "{nom} : {s:?}");
            assert!(s.iter().any(|(_, t)| t.contains("déguisées")), "{nom} : {s:?}");
        }
        let s = examiner_expediteur(&entetes("From: Paypal <avis@notifications-compte.example>"));
        assert_eq!(pire(&s), Some(Niveau::Eleve));
        assert!(s.iter().all(|(_, t)| !t.contains("déguisées")), "{s:?}");
        // « LinkedIn » écrit normalement : ni déguisé ni perdu.
        let s = examiner_expediteur(&entetes("From: LinkedIn <avis@notifications-compte.example>"));
        assert!(
            s.iter()
                .any(|(_, t)| t.contains("LinkedIn") && !t.contains("déguisées")),
            "{s:?}"
        );
        assert_eq!(pire_de("From: LinkedIn <noreply@linkedin.com>"), None);
    }

    #[test]
    fn reponses_et_retour() {
        let pire_de = |t: &str| pire(&examiner_expediteur(&entetes(t)));
        assert_eq!(
            pire_de("From: alice@example.com\nReply-To: alice@example.org"),
            Some(Niveau::Moyen)
        );
        assert_eq!(
            pire_de("From: support@paypal.com\nReply-To: support@gmail.com"),
            Some(Niveau::Eleve)
        );
        assert_eq!(
            pire_de("From: alice@example.com\nReply-To: Alice <alice@mail.example.com>"),
            None
        );
        assert_eq!(
            pire_de("From: alice@example.com\nReturn-Path: <rebond@envoi.example.net>"),
            Some(Niveau::Info)
        );
    }
}

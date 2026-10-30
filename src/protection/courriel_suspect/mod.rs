//! Ce courriel est-il une arnaque ? La personne donne un courriel enregistré (.eml : glissé depuis Thunderbird,
//! téléchargé depuis Gmail ou Outlook sur le web) ; Vanguard le lit comme une donnée hostile, SANS RIEN OUVRIR NI
//! EXÉCUTER : aucun lien suivi, aucune image chargée, aucun HTML rendu, aucune pièce jointe lancée. Il regarde le vrai
//! expéditeur (nom affiché qui imite une marque ou cache une autre adresse, réponses envoyées ailleurs, domaine qui
//! imite), le résultat SPF, DKIM et DMARC écrit par le fournisseur de la personne (jamais celui qu'un expéditeur
//! glisse plus bas), chaque lien (texte montré contre vraie adresse, avec les règles de « Ce lien est-il dangereux ? »)
//! et les pièces jointes (nom, contenu, YARA, antivirus, dans un dossier jetable). Après accord seulement, les noms de
//! domaine sortent de l'ordinateur pour leur âge et les listes publiques. Le verdict n'est jamais « sûr ».
//!
//! Différent de « Mon courriel a-t-il fuité ? » (`fuites`), qui cherche une adresse dans les fuites de données.

pub(crate) mod corps;
pub(crate) mod entetes;
pub(crate) mod mime;
pub(crate) mod pieces;
pub(crate) mod resultat;

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::protection::antivirus::Examen;
use crate::protection::lien;
use crate::risk::Niveau;
use crate::ui::*;
use corps::{ExamenLiens, LienTrouve, Source};
use mime::{Anomalie, Message, Partie};
use pieces::Piece;

/// Ce qu'on a vu, et sa gravité (comme `telechargement::nature`).
pub(crate) type Signe = (Niveau, String);

/// Liens lus au plus dans tout le courriel, et sites examinés.
const LIENS_MAX: usize = 1_000;
const SITES_MAX: usize = 50;
/// Domaines vérifiés en ligne au plus : chacun interroge quatre services.
const EN_LIGNE_MAX: usize = 10;

/// Ce que l'examen sur l'ordinateur a trouvé, section par section.
#[derive(Default)]
struct Constats {
    expediteur: Vec<Signe>,
    authentification: Vec<Signe>,
    structure: Vec<Signe>,
    liens: ExamenLiens,
    html: Vec<Signe>,
    pieces: Vec<Piece>,
    /// Ce qui n'a pas pu être vérifié : jamais compté sain, dit au verdict.
    manques: Vec<String>,
}

impl Constats {
    /// Le plus grave de ce qui a été vu (les informations ne comptent pas).
    fn pire(&self) -> Option<Niveau> {
        self.expediteur
            .iter()
            .chain(&self.authentification)
            .chain(&self.structure)
            .chain(&self.liens.trompeurs)
            .chain(self.liens.par_site.iter().flat_map(|(_, _, _, s)| s))
            .chain(&self.html)
            .chain(self.pieces.iter().flat_map(|p| &p.signes))
            .map(|(n, _)| *n)
            .chain(
                self.pieces
                    .iter()
                    .flat_map(|p| &p.moteurs)
                    .filter_map(|(_, e)| matches!(e, Examen::Trouve(_)).then_some(Niveau::Critique)),
            )
            .filter(|n| *n > Niveau::Info)
            .max()
    }
}

/// Une partie qu'on montre comme pièce jointe : annoncée comme telle, nommée, ou qui n'est ni texte ni image du corps.
/// Un SVG n'est pas une image du corps : c'est un document qui porte script et liens, que Gmail ou Thunderbird
/// proposent d'ouvrir (« noname », « Part 1.2 ») et qui s'ouvre alors dans le navigateur.
fn est_piece(p: &Partie) -> bool {
    if p.disposition.as_deref() == Some("attachment") || p.nom.is_some() {
        return true;
    }
    !(p.type_mime == "text/plain"
        || p.type_mime == "text/html"
        || (p.type_mime.starts_with("image/") && p.type_mime != "image/svg+xml"))
}

/// Les anomalies de forme, en clair. Souvent des logiciels maladroits ; un en-tête important en double sert à tromper
/// les filtres (les logiciels n'en lisent pas tous le même).
fn anomalies(m: &Message) -> (Vec<Signe>, Vec<String>) {
    let mut signes = Vec::new();
    let mut manques = Vec::new();
    for a in &m.anomalies {
        let (niveau, texte) = match a {
            Anomalie::TropGros | Anomalie::TropProfond | Anomalie::TropDeParties | Anomalie::TropDEntetes => (
                Niveau::Moyen,
                tr!(
                    "Courriel trop gros ou trop imbriqué : tout n'a pas été lu.",
                    "Email too big or too nested: not everything was read."
                )
                .to_string(),
            ),
            Anomalie::EnteteTropLong => (
                Niveau::Info,
                tr!("En-tête démesuré, coupé.", "Oversized header, cut.").to_string(),
            ),
            Anomalie::FrontiereAbsente | Anomalie::FrontiereTropLongue | Anomalie::FrontiereNonFermee => (
                Niveau::Info,
                tr!(
                    "Découpage en parties mal formé (lu au mieux).",
                    "Malformed split into parts (read as well as possible)."
                )
                .to_string(),
            ),
            Anomalie::FrontiereRepetee => (
                Niveau::Moyen,
                tr!(
                    "Parties emboîtées sous la même frontière : les logiciels ne le découpent pas tous pareil, une ruse contre les filtres.",
                    "Nested parts under the same boundary: programs do not all split it the same way, a trick against filters."
                )
                .to_string(),
            ),
            Anomalie::EncodageInconnu(e) => {
                // Le contenu n'est pas décodé : ce que voient les moteurs et la recherche de liens n'est pas ce que
                // le logiciel de courriel ouvrira (Thunderbird décode x-uuencode, par exemple).
                let manque = trf!(
                    "le contenu d'une partie à l'encodage inconnu ({})",
                    "the content of a part with an unknown encoding ({})",
                    affichable(e)
                );
                if !manques.contains(&manque) {
                    manques.push(manque);
                }
                (
                    Niveau::Info,
                    trf!(
                        "Encodage inconnu ({}) : partie lue telle quelle.",
                        "Unknown encoding ({}): part read as is.",
                        affichable(e)
                    ),
                )
            }
            Anomalie::Base64Abime => (
                Niveau::Info,
                tr!(
                    "Contenu encodé abîmé (lu au mieux).",
                    "Damaged encoded content (read as well as possible)."
                )
                .to_string(),
            ),
            Anomalie::EnteteEnDouble(nom) => (
                if matches!(nom.as_str(), "from" | "subject" | "content-type") { Niveau::Moyen } else { Niveau::Info },
                trf!(
                    "En-tête « {} » en double : les logiciels de courriel n'en montrent pas tous le même.",
                    "“{}” header twice: mail programs do not all show the same one.",
                    nom
                ),
            ),
            Anomalie::SansCorps => continue,
        };
        if !signes.iter().any(|(_, t)| *t == texte) {
            signes.push((niveau, texte));
        }
    }
    if m.incomplet {
        manques.push(
            tr!(
                "une partie du courriel (trop gros ou trop imbriqué)",
                "part of the email (too big or too nested)"
            )
            .to_string(),
        );
    }
    (signes, manques)
}

/// Tout l'examen qui se fait sur l'ordinateur, sans rien envoyer ni lancer : expéditeur, authentification, forme,
/// liens, pièces jointes (sans les moteurs). Rend aussi le contenu de chaque pièce, pour les moteurs.
fn examiner(m: &Message) -> (Constats, Vec<&[u8]>) {
    let mut c = Constats::default();
    let de = entetes::expediteur(&m.entetes);
    let domaine = de.as_ref().map(|a| a.domaine.clone()).unwrap_or_default();
    c.expediteur = entetes::examiner_expediteur(&m.entetes);
    let (auth, signes) = entetes::lire_authentification(&m.entetes);
    let (jugement, manques) = entetes::juger_authentification(auth.as_ref(), &domaine);
    c.authentification = signes.into_iter().chain(jugement).collect();
    c.manques.extend(manques);
    let (structure, manques) = anomalies(m);
    c.structure = structure;
    c.manques.extend(manques);

    let mut liens: Vec<LienTrouve> = Vec::new();
    let mut images_distantes = 0;
    let mut images = 0;
    let mut texte_visible = 0;
    let mut contenus = Vec::new();
    for p in &m.parties {
        let reste = LIENS_MAX.saturating_sub(liens.len());
        if est_piece(p) {
            let nom = p.nom.clone().unwrap_or_default();
            let (signes, manques) = pieces::juger(&nom, &p.type_mime, &p.contenu);
            c.manques.extend(manques);
            let ext = pieces::extension(&nom);
            if p.type_mime == "text/html"
                || p.type_mime == "image/svg+xml"
                || matches!(ext.as_str(), "html" | "htm" | "shtml" | "xhtml" | "svg")
            {
                // Une page jointe s'ouvre depuis l'ordinateur : ses liens et ses formulaires comptent autant.
                let nom_montre = if nom.is_empty() {
                    tr!("(sans nom)", "(no name)").to_string()
                } else {
                    nom.clone()
                };
                let source = Source::PieceHtml(nom_montre.clone());
                let h = corps::lire_html(&mime::texte(&p.contenu, p.jeu.as_deref()).0, reste, &source);
                let ou = trf!(
                    "dans la pièce jointe {}",
                    "in the attachment {}",
                    couper(&affichable(&nom_montre), 40)
                );
                c.html.extend(corps::signes_html(&h, &ou));
                liens.extend(h.base.iter().map(|b| LienTrouve {
                    cible: b.clone(),
                    affiche: None,
                    source: source.clone(),
                }));
                liens.extend(h.liens);
            }
            c.pieces.push(Piece {
                nom,
                type_declare: p.type_mime.clone(),
                taille: p.contenu.len(),
                signes,
                manques: Vec::new(),
                moteurs: Vec::new(),
            });
            contenus.push(p.contenu.as_slice());
            continue;
        }
        if p.type_mime.starts_with("image/") {
            images += 1;
            continue;
        }
        let (texte, jeu_connu) = mime::texte(&p.contenu, p.jeu.as_deref());
        if !jeu_connu {
            c.structure.push((
                Niveau::Info,
                trf!(
                    "Jeu de caractères {} lu au mieux : le texte peut être mal lu (les liens, eux, sont trouvés).",
                    "Character set {} read as well as possible: the text may be misread (links are still found).",
                    affichable(p.jeu.as_deref().unwrap_or(""))
                ),
            ));
        }
        let source = if p.dans_piece_jointe {
            Source::Transfere
        } else {
            Source::Texte
        };
        if p.type_mime == "text/html" {
            let source = if p.dans_piece_jointe {
                Source::Transfere
            } else {
                Source::Html
            };
            let h = corps::lire_html(&texte, reste, &source);
            let ou = if p.dans_piece_jointe {
                tr!("dans le courriel joint", "in the attached email")
            } else {
                tr!("dans le courriel", "inside the email")
            };
            c.html.extend(corps::signes_html(&h, ou));
            liens.extend(h.base.iter().map(|b| LienTrouve {
                cible: b.clone(),
                affiche: None,
                source: source.clone(),
            }));
            images += h.images;
            texte_visible += h.texte_visible;
            images_distantes += h.images_distantes;
            liens.extend(h.liens);
        } else {
            texte_visible += texte.chars().filter(|c| !c.is_whitespace()).count();
            liens.extend(corps::liens_texte(&texte, reste, &source));
        }
    }
    if liens.len() >= LIENS_MAX {
        c.manques.push(trf!(
            "les liens au-delà des {LIENS_MAX} premiers",
            "links beyond the first {LIENS_MAX}"
        ));
    }
    c.liens = corps::examiner_liens(&liens, SITES_MAX);
    c.manques.append(&mut c.liens.manques);
    if c.liens.non_examines > 0 {
        c.manques.push(trf!(
            "{} sites au-delà des {SITES_MAX} premiers",
            "{} sites beyond the first {SITES_MAX}",
            c.liens.non_examines
        ));
    }
    if images_distantes > 0 {
        c.html.push((
            Niveau::Info,
            trf!(
                "{} image(s) à charger depuis Internet : l'expéditeur saura que vous l'avez ouvert si votre logiciel les charge.",
                "{} image(s) loaded from the Internet: the sender will know you opened it if your program loads them.",
                images_distantes
            ),
        ));
    }
    // Un courriel fait d'images, sans lien ni texte : souvent un code QR à photographier (« quishing »).
    if c.liens.examines == 0 && images > 0 && texte_visible < 40 {
        c.html.push((
            Niveau::Info,
            tr!(
                "Courriel fait surtout d'images : un code QR dans une image n'est pas lu par Vanguard. Ne le photographiez pas pour l'ouvrir.",
                "Email made mostly of images: a QR code in an image is not read by Vanguard. Do not scan it to open it."
            )
            .to_string(),
        ));
        c.manques
            .push(tr!("les images (code QR possible)", "the images (possible QR code)").to_string());
    }
    if c.pieces.len() > pieces::MOTEURS_MAX {
        c.manques.push(trf!(
            "{} pièces jointes au-delà des {} premières (pas passées à l'antivirus)",
            "{} attachments beyond the first {} (not scanned by the antivirus)",
            c.pieces.len() - pieces::MOTEURS_MAX,
            pieces::MOTEURS_MAX
        ));
    }
    for p in &mut c.pieces {
        c.manques.append(&mut p.manques);
    }
    (c, contenus)
}

/// Pourquoi un fichier n'est pas lu.
#[derive(Debug, PartialEq, Eq)]
enum Refus {
    Introuvable,
    /// Présent, mais pas lisible (droits, erreur de lecture).
    Illisible,
    PasUnFichier,
    TropGros,
    /// Un message Outlook (.msg), que Vanguard ne lit pas.
    Msg,
    PasUnCourriel,
}

const OLE: &[u8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1";

/// Le fichier, lu au plus jusqu'à la borne (un « fichier » qui serait un lien vers un flux sans fin s'arrête là).
fn lire_fichier(chemin: &Path) -> Result<Vec<u8>, Refus> {
    let meta = std::fs::metadata(chemin).map_err(|_| Refus::Introuvable)?;
    if !meta.is_file() {
        return Err(Refus::PasUnFichier);
    }
    let max = u64::try_from(mime::BORNES.octets).unwrap_or(u64::MAX);
    if meta.len() > max {
        return Err(Refus::TropGros);
    }
    let mut octets = Vec::new();
    std::fs::File::open(chemin)
        .and_then(|f| f.take(max + 1).read_to_end(&mut octets))
        .map_err(|_| Refus::Illisible)?;
    if octets.len() > mime::BORNES.octets {
        return Err(Refus::TropGros);
    }
    if octets.starts_with(OLE) {
        return Err(Refus::Msg);
    }
    Ok(octets)
}

/// Un courriel reconnu : des en-têtes qu'on trouve dans tout courriel, et pas d'octet nul au début (un fichier binaire).
fn est_un_courriel(m: &Message, octets: &[u8]) -> bool {
    const CONNUS: &[&str] = &[
        "from",
        "received",
        "content-type",
        "subject",
        "date",
        "message-id",
        "return-path",
        "to",
        "mime-version",
        "delivered-to",
        "reply-to",
    ];
    !octets.get(..1024).unwrap_or(octets).contains(&0) && m.entetes.iter().any(|e| CONNUS.contains(&e.nom.as_str()))
}

/// Le verdict, prudent : jamais « sûr ». Ce qui n'a pas pu être vérifié est dit à la suite.
fn verdict(pire: Option<Niveau>, manques: &[String]) -> String {
    let mut t = match pire {
        Some(Niveau::Critique | Niveau::Eleve) => tr!(
            "Arnaque probable : ne cliquez sur aucun lien, n'ouvrez aucune pièce jointe et ne répondez pas. Supprimez-le. S'il parle d'un service que vous utilisez, allez sur son site en tapant vous-même son adresse.",
            "Probably a scam: do not click any link, do not open any attachment and do not reply. Delete it. If it mentions a service you use, go to its site by typing the address yourself."
        ),
        Some(Niveau::Moyen) => tr!(
            "Douteux : ne cliquez et n'ouvrez rien tant que vous n'avez pas vérifié auprès de l'expéditeur par un autre moyen (téléphone, site officiel).",
            "Doubtful: do not click or open anything until you have checked with the sender another way (phone, official site)."
        ),
        _ => tr!(
            "Rien de suspect trouvé dans ce que Vanguard a examiné. Ce n'est pas une garantie : une arnaque soignée, ou le vrai compte piraté d'un proche, ne laisse pas toujours de trace. Au moindre doute, contactez l'expéditeur par un autre moyen.",
            "Nothing suspicious found in what Vanguard examined. That is not a guarantee: a careful scam, or a friend's real hacked account, does not always leave a trace. If in doubt, contact the sender another way."
        ),
    }
    .to_string();
    if !manques.is_empty() {
        t += &trf!(
            " Tout n'a pas pu être vérifié ({}) : rien n'est conclu pour ce qui manque.",
            " Not everything could be checked ({}): nothing is concluded for what is missing.",
            resume(manques, 4, ", ")
        );
    }
    t
}

fn paragraphe(texte: &str) {
    for l in envelopper(texte, LARGEUR - 2) {
        println!("  {l}");
    }
}

/// Une ligne de constat (✔ ℹ ⚠ ✖), coupée pour tenir dans l'écran.
fn ligne(niveau: Option<Niveau>, texte: &str) {
    let marque = match niveau {
        None => format!("{VERT}✔{RESET}"),
        Some(Niveau::Info) => format!("{GRIS}ℹ{RESET}"),
        Some(Niveau::Moyen) => format!("{}⚠{RESET}", couleur(Niveau::Moyen)),
        Some(n) => format!("{}✖{RESET}", couleur(n)),
    };
    afficher_aligne(&format!("  {marque} "), texte, 4, "");
}

fn lignes(signes: &[Signe]) {
    let mut tries: Vec<&Signe> = signes.iter().collect();
    tries.sort_by_key(|(n, _)| std::cmp::Reverse(*n));
    for (n, t) in tries {
        ligne(Some(*n), t);
    }
}

/// Une valeur d'en-tête à montrer : mots encodés décodés, caractères pièges neutralisés, coupée.
fn montrer_entete(etiquette: &str, valeur: &str) {
    let v = couper(&affichable(valeur.trim()), LARGEUR - 12);
    println!("  {GRIS}{}{RESET} {v}", ajuster(etiquette, 9));
}

fn afficher_refus(refus: &Refus, chemin: &Path) {
    match refus {
        Refus::Introuvable => {
            ligne(
                Some(Niveau::Moyen),
                &trf!("Introuvable : {}", "Not found: {}", chemin_affichable(chemin)),
            );
        }
        Refus::Illisible => ligne(
            Some(Niveau::Moyen),
            &trf!(
                "Illisible (droits ou erreur de lecture) : {}",
                "Unreadable (permissions or read error): {}",
                chemin_affichable(chemin)
            ),
        ),
        Refus::PasUnFichier => ligne(
            Some(Niveau::Moyen),
            tr!(
                "Ce n'est pas un fichier : donnez un courriel enregistré (.eml).",
                "This is not a file: give a saved email (.eml)."
            ),
        ),
        Refus::TropGros => ligne(
            Some(Niveau::Moyen),
            &trf!(
                "Fichier de plus de {} Mo : plus gros qu'un courriel accepté par les fournisseurs, il n'est pas lu.",
                "File over {} MB: bigger than an email providers accept; it is not read.",
                mime::BORNES.octets / 1_000_000
            ),
        ),
        Refus::Msg => {
            ligne(
                Some(Niveau::Info),
                tr!(
                    "C'est un message Outlook (.msg), que Vanguard ne lit pas. Enregistrez le même message en .eml :",
                    "This is an Outlook message (.msg), which Vanguard does not read. Save the same message as .eml:"
                ),
            );
            for etape in [
                tr!(
                    "Outlook sur le web ou nouvel Outlook : ouvrez le message, menu « … » › Enregistrer sous (ou Télécharger) ;",
                    "Outlook on the web or new Outlook: open the message, “…” menu › Save as (or Download);"
                ),
                tr!(
                    "Thunderbird : Fichier › Enregistrer sous › Fichier ;",
                    "Thunderbird: File › Save As › File;"
                ),
                tr!(
                    "Gmail : menu ⋮ du message › Télécharger le message ;",
                    "Gmail: the message's ⋮ menu › Download message;"
                ),
                tr!(
                    "Apple Mail : Fichier › Enregistrer sous, format « Source brute ».",
                    "Apple Mail: File › Save As, “Raw Message Source” format."
                ),
            ] {
                afficher_aligne("      • ", etape, 8, "");
            }
            paragraphe(tr!(
                "Outlook classique (Windows) n'enregistre pas en .eml : passez par Outlook sur le web.",
                "Classic Outlook (Windows) does not save as .eml: use Outlook on the web."
            ));
        }
        Refus::PasUnCourriel => ligne(
            Some(Niveau::Moyen),
            tr!(
                "Ce fichier n'est pas un courriel reconnu (.eml).",
                "This file is not a recognized email (.eml)."
            ),
        ),
    }
}

/// Les domaines à vérifier en ligne : l'expéditeur, les adresses de réponse, puis les sites des liens les plus suspects.
/// Ni messagerie gratuite ni domaine officiel d'une marque : leur âge et ces listes ne diraient rien.
fn domaines_en_ligne(m: &Message, c: &Constats) -> Vec<String> {
    let mut domaines: Vec<String> = Vec::new();
    let mut ajouter = |d: &str| {
        let d = lien::domaine_enregistrable(d);
        // Seulement un vrai nom DNS : la question dit quels noms sortiront, un autre caractère (« : », espace)
        // ferait annoncer un nom que la vérification ne saurait pas lire.
        if !d.is_empty()
            && d.contains('.')
            && d.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            && !entetes::gratuit(&d)
            && lien::marque_officielle(&d).is_none()
            && !domaines.contains(&d)
            && domaines.len() < EN_LIGNE_MAX
        {
            domaines.push(d);
        }
    };
    if let Some(de) = entetes::expediteur(&m.entetes) {
        ajouter(&de.domaine);
    }
    if let Some(r) = mime::valeur(&m.entetes, "reply-to") {
        for a in entetes::adresses(&r.brut, 5).0 {
            ajouter(&a.domaine);
        }
    }
    let mut sites: Vec<(&String, Option<Niveau>)> = c
        .liens
        .par_site
        .iter()
        .map(|(s, _, _, signes)| (s, signes.iter().map(|(n, _)| *n).max()))
        .collect();
    sites.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    for (s, _) in sites {
        if s.parse::<std::net::IpAddr>().is_err() {
            ajouter(s);
        }
    }
    domaines
}

/// D'où vient un lien, pour l'écran.
fn origine(s: &Source) -> Option<String> {
    match s {
        Source::Texte | Source::Html => None,
        Source::PieceHtml(nom) => Some(trf!(
            "dans la pièce jointe {}",
            "in the attachment {}",
            couper(&affichable(nom), 30)
        )),
        Source::Transfere => Some(tr!("dans le courriel joint", "in the attached email").to_string()),
    }
}

fn afficher_liens(c: &Constats) {
    section(tr!("Liens", "Links"));
    let e = &c.liens;
    if e.examines == 0 {
        paragraphe(tr!("Aucun lien vers un site.", "No link to a site."));
    } else {
        println!(
            "  {GRIS}{}{RESET}",
            trf!(
                "{} lien(s) vers {} site(s), examinés sans être ouverts.",
                "{} link(s) to {} site(s), checked without being opened.",
                e.examines,
                e.par_site.len() + e.non_examines
            )
        );
    }
    // Ce qui concerne tout le courriel d'abord (textes trompeurs, formulaires), puis site par site.
    lignes(&e.trompeurs);
    lignes(&c.html);
    let mut sans_signe = Vec::new();
    for (site, exemple, source, signes) in &e.par_site {
        let graves: Vec<Signe> = signes.iter().filter(|(n, _)| *n > Niveau::Info).cloned().collect();
        if graves.is_empty() {
            sans_signe.push(if site.is_empty() {
                couper(&affichable(exemple), 30)
            } else {
                affichable(site)
            });
            continue;
        }
        let ou = origine(source)
            .map(|o| format!(" {GRIS}({o}){RESET}"))
            .unwrap_or_default();
        let nom = if site.is_empty() {
            couper(&affichable(exemple), 50)
        } else {
            couper(&affichable(site), 50)
        };
        println!("  {ACCENT}{nom}{RESET}{ou}");
        lignes(&graves);
    }
    if !sans_signe.is_empty() {
        afficher_aligne(
            &format!("  {GRIS}ℹ{RESET} "),
            &trf!(
                "Sans signe particulier : {}",
                "No particular sign: {}",
                resume(&sans_signe, 6, ", ")
            ),
            4,
            "",
        );
    }
}

fn afficher_pieces(c: &Constats) {
    if c.pieces.is_empty() {
        return;
    }
    section(tr!("Pièces jointes", "Attachments"));
    for p in &c.pieces {
        let nom = if p.nom.is_empty() {
            tr!("(sans nom)", "(no name)").to_string()
        } else {
            couper(&affichable(&p.nom), 44)
        };
        let taille = crate::protection::telechargement::taille(u64::try_from(p.taille).unwrap_or(u64::MAX));
        // Le type prend ce qui reste de la ligne : « application/vnd.openxmlformats-… » d'un simple .docx est long.
        // Deux espaces, le nom, « (», la taille, « , » et « ) ».
        let place = LARGEUR.saturating_sub(2 + largeur_affichee(&nom) + 2 + largeur_affichee(&taille) + 2 + 1);
        let precision = format!("{taille}, {}", couper(&affichable(&p.type_declare), place.clamp(8, 24)));
        println!("  {ACCENT}{nom}{RESET} {GRIS}({precision}){RESET}");
        lignes(&p.signes);
        for (moteur, examen) in &p.moteurs {
            match examen {
                Examen::Sain => ligne(None, &trf!("{moteur} : rien trouvé.", "{moteur}: nothing found.")),
                Examen::Trouve(noms) => ligne(
                    Some(Niveau::Critique),
                    &trf!("{moteur} : {}", "{moteur}: {}", resume(noms, 3, ", ")),
                ),
                Examen::Impossible(raison) => ligne(
                    Some(Niveau::Moyen),
                    &trf!(
                        "{moteur} : impossible à vérifier ({raison}).",
                        "{moteur}: could not check ({raison})."
                    ),
                ),
            }
        }
    }
}

/// Les vérifications en ligne, après accord ; rend le pire de ce qu'elles disent.
fn en_ligne(domaines: &[String], manques: &mut Vec<String>) -> Option<Niveau> {
    if domaines.is_empty() {
        return None;
    }
    section(tr!("En ligne", "Online"));
    let liste = resume(domaines, EN_LIGNE_MAX, ", ");
    if crate::parametres::hors_ligne() {
        paragraphe(&trf!(
            "Mode hors ligne : âge et listes publiques non vérifiés pour {liste}.",
            "Offline mode: age and public lists not checked for {liste}."
        ));
        manques.push(
            tr!(
                "l'âge des domaines et les listes publiques",
                "the domains' age and the public lists"
            )
            .to_string(),
        );
        return None;
    }
    paragraphe(&trf!(
        "Vérifier aussi en ligne ? L'âge de ces domaines et trois listes publiques de sites dangereux (URLhaus, Spamhaus, SURBL). Seuls ces noms sortiront de l'ordinateur : {liste} ; jamais le courriel, ni les adresses, ni les liens entiers.",
        "Also check online? The age of these domains and three public lists of dangerous sites (URLhaus, Spamhaus, SURBL). Only these names will leave the computer: {liste}; never the email, the addresses or the whole links."
    ));
    if !demander(tr!("  Continuer ? [o/N] : ", "  Continue? [y/N]: ")).oui() {
        trp!("  Rien n'a été envoyé.", "  Nothing was sent.");
        manques.push(
            tr!(
                "l'âge des domaines et les listes publiques",
                "the domains' age and the public lists"
            )
            .to_string(),
        );
        return None;
    }
    let mut pire = None;
    let mut absentes: Vec<String> = Vec::new();
    for d in domaines {
        println!("\n  {ACCENT}{d}{RESET}");
        let (p, manquent, faites) = lien::verifier_en_ligne(d);
        pire = pire.max(p);
        retenir_absentes(d, manquent, faites, &mut absentes);
    }
    if !absentes.is_empty() {
        manques.push(trf!("en ligne : {}", "online: {}", resume(&absentes, 4, ", ")));
    }
    pire
}

/// Les listes qui n'ont pas répondu ; et le domaine lui-même quand aucune vérification n'a pu partir pour lui : la
/// personne a accepté, le nom a été annoncé, son absence de résultat ne doit pas passer pour « rien trouvé ».
fn retenir_absentes(domaine: &str, manquent: Vec<String>, faites: usize, absentes: &mut Vec<String>) {
    if faites == 0 && !absentes.iter().any(|a| a == domaine) {
        absentes.push(domaine.to_string());
    }
    for m in manquent {
        if !absentes.contains(&m) {
            absentes.push(m);
        }
    }
}

/// Les « %XX » d'une URI décodés (« + » reste « + » : c'est un chemin, pas un formulaire).
fn pourcents(v: &str) -> Vec<u8> {
    let o = v.as_bytes();
    let mut s = Vec::with_capacity(o.len());
    let mut i = 0;
    while let Some(&c) = o.get(i) {
        if c == b'%'
            && let Some(h) = v.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            s.push(h);
            i += 3;
        } else {
            s.push(c);
            i += 1;
        }
    }
    s
}

/// Le chemin tapé ou glissé : sans guillemets ; « file:// » d'un terminal qui dépose une URI, avec ses « %20 » et
/// accents codés décodés ; « ~/ » développé.
pub(crate) fn chemin_saisi(r: &str) -> Option<PathBuf> {
    let r = r.trim().trim_matches(['"', '\'']);
    let r = match r.strip_prefix("file://") {
        Some(uri) => String::from_utf8_lossy(&pourcents(uri)).into_owned(),
        None => r.to_string(),
    };
    if r.is_empty() {
        return None;
    }
    Some(match r.strip_prefix("~/") {
        Some(reste) => crate::socle::maison().join(reste),
        None => PathBuf::from(r),
    })
}

/// Menu Antivirus et protection › Ce courriel est-il une arnaque ?, ou `vanguard courriel-suspect <fichier>`.
pub fn verifier(fichier: Option<&Path>) {
    let debut = (chrono::Utc::now(), std::time::Instant::now());
    titre(tr!("Ce courriel est-il une arnaque ?", "Is this email a scam?"));
    paragraphe(tr!(
        "Vanguard lit le fichier sans rien ouvrir : aucun lien n'est suivi, aucune image n'est chargée, aucune pièce jointe n'est lancée.",
        "Vanguard reads the file without opening anything: no link is followed, no image is loaded, no attachment is run."
    ));
    let chemin = if let Some(f) = fichier {
        f.to_path_buf()
    } else {
        let r = demander(tr!(
            "\n  Courriel à examiner (.eml ; glissez-le ici, ou tapez son chemin) : ",
            "\n  Email to check (.eml; drag it here, or type its path): "
        ));
        // Un fichier glissé arrive entre guillemets, ou en « file:// » selon le terminal.
        let Some(chemin) = chemin_saisi(&r) else {
            return;
        };
        chemin
    };
    println!();
    let octets = match lire_fichier(&chemin) {
        Ok(o) => o,
        Err(refus) => {
            afficher_refus(&refus, &chemin);
            return;
        }
    };
    let m = mime::lire(&octets);
    if !est_un_courriel(&m, &octets) {
        afficher_refus(&Refus::PasUnCourriel, &chemin);
        return;
    }

    let decode = |nom: &str| mime::valeur(&m.entetes, nom).map(|e| mime::mots_encodes(&e.brut, &mime::BORNES));
    montrer_entete(tr!("De", "From"), &decode("from").unwrap_or_default());
    if let Some(r) = decode("reply-to") {
        montrer_entete(tr!("Répondre", "Reply-to"), &r);
    }
    montrer_entete(tr!("Objet", "Subject"), &decode("subject").unwrap_or_default());
    if let Some(d) = decode("date") {
        montrer_entete(tr!("Date", "Date"), &d);
    }
    let nom_fichier = chemin
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    montrer_entete(
        tr!("Fichier", "File"),
        &format!(
            "{nom_fichier} ({})",
            crate::protection::telechargement::taille(u64::try_from(octets.len()).unwrap_or(u64::MAX))
        ),
    );

    let (mut c, contenus) = examiner(&m);
    section(tr!("Expéditeur", "Sender"));
    if c.expediteur.is_empty() {
        ligne(
            None,
            tr!(
                "Rien de trompeur dans l'expéditeur affiché.",
                "Nothing misleading in the sender shown."
            ),
        );
    }
    lignes(&c.expediteur);
    section(tr!(
        "Authentification (écrite par votre fournisseur)",
        "Authentication (written by your provider)"
    ));
    lignes(&c.authentification);
    if !c.structure.is_empty() {
        section(tr!("Forme du courriel", "Email structure"));
        lignes(&c.structure);
    }
    afficher_liens(&c);

    if !c.pieces.is_empty() {
        match crate::protection::isoler::dossier_jetable() {
            Ok(dossier) => {
                section(tr!("Analyse des pièces jointes", "Scanning the attachments"));
                let mut moteurs = pieces::moteurs(
                    crate::protection::yara::examiner,
                    crate::protection::antivirus::examiner,
                );
                pieces::passer_aux_moteurs(dossier, &mut c.pieces, &contenus, &mut moteurs);
            }
            Err(e) => c.manques.push(trf!(
                "l'analyse des pièces jointes (dossier jetable impossible : {e})",
                "the attachments scan (disposable folder impossible: {e})"
            )),
        }
        for p in &c.pieces {
            for (moteur, e) in &p.moteurs {
                if matches!(e, Examen::Impossible(_)) && !c.manques.contains(moteur) {
                    c.manques.push(moteur.clone());
                }
            }
        }
    }
    afficher_pieces(&c);

    let domaines = domaines_en_ligne(&m, &c);
    let pire_en_ligne = en_ligne(&domaines, &mut c.manques);
    let pire = c.pire().max(pire_en_ligne);

    println!();
    // Pas en vert quand des vérifications manquent : rien n'est conclu pour elles.
    let couleur_verdict = match pire {
        Some(n) => couleur(n),
        None if !c.manques.is_empty() => couleur(Niveau::Moyen),
        None => VERT,
    };
    for l in envelopper(&verdict(pire, &c.manques), LARGEUR - 2) {
        println!("  {couleur_verdict}{l}{RESET}");
    }
    crate::modele::resultat::verser(&resultat::resultat(&c, pire_en_ligne, debut));
}

/// `vanguard courriel-suspect --json` : l'examen sur l'ordinateur seulement, sans rien demander. La vérification en
/// ligne (qui demande un accord) et l'analyse des pièces jointes (qui lance les moteurs) n'y sont pas faites : elles
/// sont dites non vérifiées, jamais comptées saines.
pub fn json(chemin: &Path) {
    let debut = (chrono::Utc::now(), std::time::Instant::now());
    let r = match lire_fichier(chemin) {
        Err(refus) => resultat::refuse(&texte_refus(&refus), debut),
        Ok(octets) => {
            let m = mime::lire(&octets);
            if est_un_courriel(&m, &octets) {
                let (mut c, _) = examiner(&m);
                if !c.pieces.is_empty() {
                    c.manques.push(
                        tr!(
                            "l'analyse des pièces jointes (pas lancée avec --json)",
                            "the attachments scan (not run with --json)"
                        )
                        .to_string(),
                    );
                }
                if !domaines_en_ligne(&m, &c).is_empty() {
                    c.manques.push(
                        tr!(
                            "l'âge des domaines et les listes publiques (pas demandés avec --json)",
                            "the domains' age and the public lists (not asked with --json)"
                        )
                        .to_string(),
                    );
                }
                resultat::resultat(&c, None, debut)
            } else {
                resultat::refuse(&texte_refus(&Refus::PasUnCourriel), debut)
            }
        }
    };
    crate::modele::resultat::verser(&r);
    println!("{}", crate::modele::resultat::json(&r));
}

/// Pourquoi un fichier n'est pas examiné, en une phrase (le JSON ; l'écran en dit plus, `afficher_refus`).
fn texte_refus(r: &Refus) -> String {
    match r {
        Refus::Introuvable => tr!("fichier introuvable", "file not found"),
        Refus::Illisible => tr!("fichier illisible", "file unreadable"),
        Refus::PasUnFichier => tr!("pas un fichier", "not a file"),
        Refus::TropGros => tr!("fichier trop gros", "file too large"),
        Refus::Msg => tr!(
            "message Outlook (.msg), que Vanguard ne lit pas",
            "Outlook message (.msg), which Vanguard does not read"
        ),
        Refus::PasUnCourriel => tr!("pas un courriel", "not an email"),
    }
    .to_string()
}

/// PRO-COU-001 au corpus de détection : un courriel (.eml) fabriqué, examiné sur l'ordinateur seulement (ni moteurs
/// ni recherche en ligne). Le constat porte le pire signe et les textes des signes vus.
#[cfg(test)]
pub(crate) fn corpus(e: &crate::modele::corpus::Entree) -> Vec<crate::machine::Constat> {
    let m = mime::lire(e.texte.as_bytes());
    let (c, _) = examiner(&m);
    let signes: Vec<&str> = c
        .expediteur
        .iter()
        .chain(&c.authentification)
        .chain(&c.structure)
        .chain(&c.liens.trompeurs)
        .chain(&c.html)
        .chain(c.pieces.iter().flat_map(|p| &p.signes))
        .filter(|(n, _)| *n > Niveau::Info)
        .map(|(_, t)| t.as_str())
        .collect();
    let message = format!("{} {}", verdict(c.pire(), &c.manques), signes.join(" ; "));
    vec![match c.pire() {
        Some(n) => crate::machine::alerte("Surveillance", n, message),
        None => crate::machine::ok("Surveillance", message),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    const HAMECON: &str = "Received: from envoi.paypa1-secure.example by mx.example.net\r\n\
Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=paypa1-secure.example; dkim=none; dmarc=none\r\n\
From: \"PayPal Service\" <service@paypa1-secure.example>\r\n\
Reply-To: noreply@gmail.com\r\n\
To: alice@example.com\r\nSubject: =?utf-8?Q?Votre_compte_est_suspendu?=\r\n\
MIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=\"b\"\r\n\r\n\
--b\r\nContent-Type: text/plain\r\n\r\nConfirmez sur https://paypa1-secure.example/login\r\n\
--b\r\nContent-Type: text/html\r\n\r\n<a href=\"https://paypa1-secure.example/login\">https://www.paypal.com</a>\r\n--b--\r\n";

    // Le résultat tout en haut, écrit par le filtre du serveur de réception dont le Received suit : cru.
    const HONNETE: &str = "Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com\r\n\
Received: from mail.example.com by mx.example.net\r\n\
From: Alice <alice@example.com>\r\nTo: bob@example.org\r\nSubject: Photos\r\n\r\n\
Les photos sont sur https://www.example.com/album\r\n";

    #[test]
    fn hamecon_reconnu() {
        let m = mime::lire(HAMECON.as_bytes());
        assert!(est_un_courriel(&m, HAMECON.as_bytes()));
        let (c, contenus) = examiner(&m);
        assert_eq!(contenus.len(), 0);
        assert!(c.pire() >= Some(Niveau::Eleve));
        assert!(c.liens.trompeurs.iter().any(|(n, _)| *n == Niveau::Eleve));
        assert!(
            c.expediteur.iter().any(|(_, t)| t.contains("messagerie gratuite")),
            "{:?}",
            c.expediteur
        );
        assert!(verdict(c.pire(), &c.manques).starts_with("Arnaque probable"));
        let domaines = domaines_en_ligne(&m, &c);
        assert_eq!(domaines, ["paypa1-secure.example"]);
    }

    #[test]
    fn courriel_honnete() {
        let m = mime::lire(HONNETE.as_bytes());
        let (c, _) = examiner(&m);
        assert_eq!(c.pire(), None, "{:?}", c.expediteur);
        assert!(c.manques.is_empty(), "{:?}", c.manques);
        assert!(c.authentification[0].1.contains("Authentique ne veut pas dire honnête"));
        assert!(verdict(None, &c.manques).contains("Ce n'est pas une garantie"));
    }

    #[test]
    fn jamais_sur() {
        for pire in [None, Some(Niveau::Info), Some(Niveau::Moyen), Some(Niveau::Eleve)] {
            for manques in [vec![], vec!["YARA".to_string()]] {
                let v = verdict(pire, &manques).to_lowercase();
                assert!(
                    !v.contains("sûr") && !v.contains("sans danger") && !v.contains("safe"),
                    "{v}"
                );
                assert_eq!(v.contains("rien n'est conclu"), !manques.is_empty());
            }
        }
    }

    #[test]
    fn pieces_jointes_et_page_web() {
        let c = "From: alice@example.com\r\nContent-Type: multipart/mixed; boundary=m\r\n\r\n--m\r\n\
Content-Type: text/plain\r\n\r\nVoir la facture.\r\n--m\r\nContent-Type: application/octet-stream; name=\"facture.pdf.exe\"\r\n\
Content-Disposition: attachment; filename=\"facture.pdf.exe\"\r\nContent-Transfer-Encoding: base64\r\n\r\nTVqQAA==\r\n\
--m\r\nContent-Type: text/html; name=connexion.html\r\nContent-Disposition: attachment\r\n\r\n\
<form action=\"https://vol.example/post\"><input type=password></form>\r\n--m--\r\n";
        let m = mime::lire(c.as_bytes());
        let (c, contenus) = examiner(&m);
        assert_eq!(c.pieces.len(), 2);
        assert_eq!(contenus[0], b"MZ\x90\0");
        assert!(c.pieces[0].signes.iter().any(|(_, t)| t.contains("Double extension")));
        assert!(
            c.html
                .iter()
                .any(|(n, t)| *n == Niveau::Eleve && t.contains("connexion.html")),
            "{:?}",
            c.html
        );
        assert_eq!(c.pire(), Some(Niveau::Eleve));
    }

    #[test]
    fn fichiers_refuses() {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let msg = d.join("message.msg");
        let mut o = OLE.to_vec();
        o.extend("__substg1.0_".encode_utf16().flat_map(u16::to_le_bytes));
        std::fs::write(&msg, o).unwrap();
        assert_eq!(lire_fichier(&msg), Err(Refus::Msg));
        assert_eq!(lire_fichier(&d), Err(Refus::PasUnFichier));
        assert_eq!(lire_fichier(&d.join("absent.eml")), Err(Refus::Introuvable));
        let png = d.join("image.eml");
        std::fs::write(&png, b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR").unwrap();
        let octets = lire_fichier(&png).unwrap();
        assert!(!est_un_courriel(&mime::lire(&octets), &octets));
        // Boîte mbox : la ligne d'enveloppe ne cache pas les en-têtes.
        let mbox = b"From alice@example.com Mon Oct 20 10:00:00 2026\nFrom: alice@example.com\n\nx";
        assert!(est_un_courriel(&mime::lire(mbox), mbox));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn encodage_inconnu_jamais_compte_sain() {
        // Un programme annoncé en PDF, encodé en x-uuencode (que Thunderbird décode) : pas décodé ici, donc pas vu.
        let c = "Received: from a by mx.example.net\r\nFrom: Bob <bob@example.com>\r\n\
Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nVoici la facture.\r\n\
--b\r\nContent-Type: application/pdf; name=facture.pdf\r\nContent-Disposition: attachment; filename=facture.pdf\r\n\
Content-Transfer-Encoding: x-uuencode\r\n\r\nbegin 644 facture.pdf\r\nM35J0\r\n`\r\nend\r\n--b--\r\n";
        let (c, _) = examiner(&mime::lire(c.as_bytes()));
        assert!(c.manques.iter().any(|m| m.contains("x-uuencode")), "{:?}", c.manques);
    }

    #[test]
    fn svg_sans_nom_examine() {
        let c = "Received: from a by mx.example.net\r\nFrom: Bob <bob@example.com>\r\n\
Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nVoici la facture.\r\n\
--b\r\nContent-Type: image/svg+xml\r\n\r\n<svg xmlns=\"http://www.w3.org/2000/svg\"><script>location=\"https://vol.example/\"\
</script><a href=\"https://paypal.com.vol.example/login\"><text>Payer</text></a></svg>\r\n--b--\r\n";
        let m = mime::lire(c.as_bytes());
        let (c, contenus) = examiner(&m);
        assert_eq!((c.pieces.len(), contenus.len()), (1, 1));
        assert!(
            c.liens.par_site.iter().any(|(s, _, _, _)| s == "vol.example"),
            "{:?}",
            c.liens.par_site
        );
        assert_eq!(c.pire(), Some(Niveau::Critique));
        assert!(
            c.pieces[0]
                .signes
                .iter()
                .any(|(n, t)| *n == Niveau::Eleve && t.contains("SVG")),
            "{:?}",
            c.pieces[0].signes
        );
    }

    #[test]
    fn en_ligne_seulement_des_noms_dns() {
        let c = "Received: from a by mx.example.net\r\nFrom: Bob <bob@phish.example:x>\r\n\
Reply-To: r@autre example.org\r\n\r\nbonjour";
        let m = mime::lire(c.as_bytes());
        let (constats, _) = examiner(&m);
        assert_eq!(domaines_en_ligne(&m, &constats), Vec::<String>::new());
        // Une vérification acceptée qui n'a pas pu partir : le nom compte parmi ce qui manque.
        let mut absentes = Vec::new();
        retenir_absentes("example.org", Vec::new(), 0, &mut absentes);
        retenir_absentes("example.net", vec!["SURBL".into()], 4, &mut absentes);
        assert_eq!(absentes, ["example.org", "SURBL"]);
    }

    #[test]
    fn chemins_glisses() {
        assert_eq!(
            chemin_saisi("'file:///tmp/Facture%20mars%C3%A9.eml'"),
            Some(PathBuf::from("/tmp/Facture marsé.eml"))
        );
        assert_eq!(chemin_saisi("  \"/tmp/a+b.eml\" "), Some(PathBuf::from("/tmp/a+b.eml")));
        assert_eq!(chemin_saisi("  "), None);
        let maison = crate::socle::maison();
        assert_eq!(chemin_saisi("~/x.eml"), Some(maison.join("x.eml")));
    }

    #[cfg(unix)]
    #[test]
    fn fichier_illisible() {
        use std::os::unix::fs::PermissionsExt;
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let f = d.join("ferme.eml");
        std::fs::write(&f, b"From: alice@example.com\n\nx").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o000)).unwrap();
        // Root lit tout : rien à prouver alors.
        if std::fs::read(&f).is_err() {
            assert_eq!(lire_fichier(&f), Err(Refus::Illisible));
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn courriel_d_images_seulement() {
        let c = "From: alice@example.com\r\nContent-Type: text/html\r\n\r\n<img src=\"cid:qr\">";
        let (c, _) = examiner(&mime::lire(c.as_bytes()));
        assert!(c.html.iter().any(|(_, t)| t.contains("code QR")));
        assert_ne!(c.manques, Vec::<String>::new());
    }
}

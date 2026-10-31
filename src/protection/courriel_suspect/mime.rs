//! Lecture d'un courriel enregistré (RFC 5322 et MIME : RFC 2045, 2046, 2047, 2231), écrite pour Vanguard. Le
//! courriel est une donnée hostile : tout est borné (taille, profondeur, nombre de parties et d'en-têtes, longueur
//! d'une frontière), lu en une passe avec une pile explicite (jamais de récursion qu'un courriel imbriqué mille fois
//! ferait déborder), et une borne atteinte marque le courriel « incomplet » au lieu de le dire lu. Rien n'est
//! interprété ici : les anomalies sont rendues comme des valeurs, que l'écran traduit et juge.
//!
//! Module autonome (aucun `crate::`) : le banc de fuzzing l'inclut par son chemin (`fuzz/fuzz_targets/courriel_mime.rs`).

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use std::borrow::Cow;

/// Les bornes de lecture. Celles du programme sont dans `BORNES` ; les tests en passent de plus petites.
#[derive(Debug, Clone)]
pub(crate) struct Bornes {
    /// Taille lue au plus : au-delà, le reste n'est pas lu.
    pub octets: usize,
    /// Parties multiples et courriels joints emboîtés.
    pub profondeur: usize,
    /// Parties finales (texte, page, pièce jointe).
    pub parties: usize,
    /// En-têtes gardés par bloc.
    pub entetes: usize,
    /// Longueur d'un en-tête déplié.
    pub entete_octets: usize,
    /// Taille d'un bloc d'en-têtes.
    pub bloc_entetes: usize,
    /// Mots encodés (RFC 2047) décodés par en-tête.
    pub mots_encodes: usize,
    /// Paramètres lus par en-tête (et morceaux d'un paramètre découpé, RFC 2231).
    pub parametres: usize,
    /// Longueur d'une frontière (la RFC en permet 70).
    pub frontiere: usize,
}

/// Les fournisseurs refusent les courriels de plus de 25 à 35 Mo ; 50 Mo laisse de la marge sans laisser lire n'importe
/// quoi.
pub(crate) const BORNES: Bornes = Bornes {
    octets: 50_000_000,
    profondeur: 10,
    parties: 300,
    entetes: 1_000,
    entete_octets: 64 * 1024,
    bloc_entetes: 1_000_000,
    mots_encodes: 200,
    parametres: 50,
    frontiere: 200,
};

/// Un en-tête : son nom en minuscules, sa valeur dépliée (lignes de suite recollées), son rang (0 : le plus haut, le
/// dernier ajouté en route).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entete {
    pub nom: String,
    pub brut: Vec<u8>,
    pub rang: usize,
}

impl Entete {
    /// La valeur en texte (UTF-8 abîmé remplacé), sans décoder les mots encodés.
    pub(crate) fn texte(&self) -> String {
        String::from_utf8_lossy(&self.brut).into_owned()
    }
}

/// Une partie finale, décodée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Partie {
    /// « 1.2.1 », pour l'affichage et les tests.
    pub chemin: String,
    pub profondeur: usize,
    /// En minuscules ; « text/plain » quand rien n'est dit (RFC 2045).
    pub type_mime: String,
    pub jeu: Option<String>,
    /// « attachment », « inline »…, en minuscules.
    pub disposition: Option<String>,
    /// Nom de fichier donné par l'expéditeur, décodé mais BRUT : c'est lui qu'on juge (un caractère qui retourne
    /// l'écriture est justement le piège). Jamais utilisé pour écrire sur le disque.
    pub nom: Option<String>,
    pub contenu: Vec<u8>,
    /// Dans un courriel joint (transféré).
    pub dans_piece_jointe: bool,
}

/// Ce qui est anormal dans la forme du courriel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Anomalie {
    TropGros,
    TropProfond,
    TropDeParties,
    TropDEntetes,
    EnteteTropLong,
    FrontiereAbsente,
    FrontiereTropLongue,
    FrontiereNonFermee,
    /// La frontière d'une partie reprend celle d'une partie qui la contient.
    FrontiereRepetee,
    EncodageInconnu(String),
    Base64Abime,
    /// Un en-tête qui ne devrait être là qu'une fois (son nom).
    EnteteEnDouble(String),
    SansCorps,
}

/// Le courriel lu.
#[derive(Debug, Default)]
pub(crate) struct Message {
    pub entetes: Vec<Entete>,
    pub parties: Vec<Partie>,
    pub anomalies: Vec<Anomalie>,
    /// Une borne atteinte : tout n'a pas été lu.
    pub incomplet: bool,
}

impl Message {
    fn noter(&mut self, a: Anomalie) {
        if !self.anomalies.contains(&a) {
            self.anomalies.push(a);
        }
    }
}

/// Le premier en-tête de ce nom (en minuscules).
pub(crate) fn valeur<'a>(entetes: &'a [Entete], nom: &str) -> Option<&'a Entete> {
    entetes.iter().find(|e| e.nom == nom)
}

/// Tous les en-têtes de ce nom, du plus haut au plus bas.
pub(crate) fn toutes<'a>(entetes: &'a [Entete], nom: &'a str) -> impl Iterator<Item = &'a Entete> {
    entetes.iter().filter(move |e| e.nom == nom)
}

pub(crate) fn lire(octets: &[u8]) -> Message {
    lire_borne(octets, &BORNES)
}

/// Un morceau à lire : une partie (ses en-têtes et son corps), ou un courriel joint.
struct Travail<'a> {
    octets: Cow<'a, [u8]>,
    profondeur: usize,
    chemin: String,
    /// Frontières des parties qui la contiennent.
    frontieres: Vec<Vec<u8>>,
    dans_piece_jointe: bool,
    /// Type par défaut : « message/rfc822 » dans un multipart/digest.
    digest: bool,
    racine: bool,
}

pub(crate) fn lire_borne(octets: &[u8], b: &Bornes) -> Message {
    let mut m = Message::default();
    let octets = match octets.split_at_checked(b.octets) {
        Some((lu, reste)) if !reste.is_empty() => {
            m.noter(Anomalie::TropGros);
            m.incomplet = true;
            lu
        }
        _ => octets,
    };
    // Une boîte mbox commence par « From adresse date » : une ligne d'enveloppe, pas un en-tête.
    let octets = if octets.starts_with(b"From ") {
        // Rien après la ligne d'enveloppe : le message est vide.
        octets.splitn(2, |&o| o == b'\n').nth(1).unwrap_or_default()
    } else {
        octets
    };
    let mut pile = vec![Travail {
        octets: Cow::Borrowed(octets),
        profondeur: 0,
        chemin: "1".into(),
        frontieres: Vec::new(),
        dans_piece_jointe: false,
        digest: false,
        racine: true,
    }];
    // Les morceaux empilés en tout : une partie multiple vide de mille enfants ne doit pas tourner sans fin.
    let mut empiles = 1_usize;
    while let Some(t) = pile.pop() {
        let (entetes, debut_corps, anomalies, coupe) = separer_entetes(&t.octets, b);
        for a in anomalies {
            m.noter(a);
        }
        m.incomplet |= coupe;
        if t.racine {
            m.entetes.clone_from(&entetes);
        }
        // Le corps commence dans le bloc (separer_entetes) ; sinon, la partie est sautée et le message dit incomplet.
        let Some(corps) = t.octets.get(debut_corps..) else {
            m.incomplet = true;
            continue;
        };
        let defaut = if t.digest { "message/rfc822" } else { "text/plain" };
        let (type_mime, params) = valeur(&entetes, "content-type")
            .map_or_else(|| (defaut.to_string(), Vec::new()), |e| parametres(&e.texte(), b));
        let type_mime = if type_mime.contains('/') {
            type_mime
        } else {
            defaut.to_string()
        };
        if t.racine {
            for nom in ["from", "subject", "content-type", "reply-to", "sender"] {
                if toutes(&entetes, nom).nth(1).is_some() {
                    m.noter(Anomalie::EnteteEnDouble(nom.into()));
                }
            }
            if corps.iter().all(u8::is_ascii_whitespace) {
                m.noter(Anomalie::SansCorps);
            }
        }
        let encodage = valeur(&entetes, "content-transfer-encoding")
            .map(|e| e.texte().trim().to_ascii_lowercase())
            .unwrap_or_default();

        if let Some(sorte) = type_mime.strip_prefix("multipart/") {
            match preparer_multipart(&params, &t, b) {
                Ok(frontiere) => {
                    if t.profondeur >= b.profondeur {
                        m.noter(Anomalie::TropProfond);
                        m.incomplet = true;
                    } else {
                        let reste = b.parties.saturating_mul(2).saturating_sub(empiles);
                        let (morceaux, anomalies, trop) = decouper_multipart(corps, &frontiere, reste);
                        for a in anomalies {
                            m.noter(a);
                        }
                        if trop {
                            m.noter(Anomalie::TropDeParties);
                            m.incomplet = true;
                        }
                        if morceaux.is_empty() {
                            // Aucune frontière trouvée : le corps est lu comme un texte, pour que ses liens se voient.
                            m.noter(Anomalie::FrontiereNonFermee);
                            pousser_feuille(&mut m, &t, "text/plain", &params, &entetes, corps, &encodage, b);
                            continue;
                        }
                        // Compteur borné par `reste` ci-dessus.
                        empiles = empiles.saturating_add(morceaux.len());
                        let mut frontieres = t.frontieres.clone();
                        frontieres.push(frontiere);
                        let mut enfants: Vec<Travail> = Vec::with_capacity(morceaux.len());
                        #[expect(
                            clippy::arithmetic_side_effects,
                            reason = "t.profondeur < b.profondeur, vérifié au-dessus"
                        )]
                        let profondeur = t.profondeur + 1;
                        for (rang, (debut, fin)) in (1_usize..).zip(morceaux) {
                            let plage = debut_corps.checked_add(debut).zip(debut_corps.checked_add(fin));
                            let octets = plage.and_then(|(debut, fin)| match &t.octets {
                                Cow::Borrowed(o) => o.get(debut..fin).map(Cow::Borrowed),
                                Cow::Owned(o) => o.get(debut..fin).map(|p| Cow::Owned(p.to_vec())),
                            });
                            // Les morceaux sont découpés dans le corps : un morceau hors de lui est sauté, dit.
                            let Some(octets) = octets else {
                                m.incomplet = true;
                                continue;
                            };
                            enfants.push(Travail {
                                octets,
                                profondeur,
                                chemin: format!("{}.{rang}", t.chemin),
                                frontieres: frontieres.clone(),
                                dans_piece_jointe: t.dans_piece_jointe,
                                digest: sorte == "digest",
                                racine: false,
                            });
                        }
                        // À l'envers : la première partie est lue la première.
                        pile.extend(enfants.into_iter().rev());
                    }
                }
                Err(a) => {
                    m.noter(a);
                    pousser_feuille(&mut m, &t, "text/plain", &params, &entetes, corps, &encodage, b);
                }
            }
        } else if matches!(type_mime.as_str(), "message/rfc822" | "message/global") {
            if t.profondeur >= b.profondeur {
                m.noter(Anomalie::TropProfond);
                m.incomplet = true;
            } else if empiles >= b.parties.saturating_mul(2) {
                m.noter(Anomalie::TropDeParties);
                m.incomplet = true;
            } else {
                // Un courriel joint n'est pas censé être encodé ; s'il l'est, on le décode quand même.
                let (decode, anomalie) = decoder(corps, &encodage);
                if let Some(a) = anomalie {
                    m.noter(a);
                }
                // Compteur borné juste au-dessus (b.parties * 2).
                empiles = empiles.saturating_add(1);
                let octets = match (decode, &t.octets) {
                    // `corps` a déjà été lu à cette place : elle est dans le bloc.
                    (None, Cow::Borrowed(o)) => o.get(debut_corps..).map(Cow::Borrowed),
                    (None, Cow::Owned(_)) => Some(Cow::Owned(corps.to_vec())),
                    (Some(d), _) => Some(Cow::Owned(d)),
                };
                let Some(octets) = octets else {
                    m.incomplet = true;
                    continue;
                };
                #[expect(
                    clippy::arithmetic_side_effects,
                    reason = "t.profondeur < b.profondeur, vérifié au-dessus"
                )]
                let profondeur = t.profondeur + 1;
                pile.push(Travail {
                    octets,
                    profondeur,
                    chemin: format!("{}.1", t.chemin),
                    frontieres: t.frontieres.clone(),
                    dans_piece_jointe: true,
                    digest: false,
                    racine: false,
                });
            }
        } else {
            pousser_feuille(&mut m, &t, &type_mime, &params, &entetes, corps, &encodage, b);
        }
    }
    m
}

/// La frontière d'une partie multiple, ou pourquoi elle ne sert pas.
fn preparer_multipart(params: &[(String, String)], t: &Travail, b: &Bornes) -> Result<Vec<u8>, Anomalie> {
    let frontiere = params
        .iter()
        .find(|(n, _)| n == "boundary")
        .map(|(_, v)| v.as_bytes().to_vec())
        .filter(|f| !f.is_empty())
        .ok_or(Anomalie::FrontiereAbsente)?;
    if frontiere.len() > b.frontiere {
        return Err(Anomalie::FrontiereTropLongue);
    }
    // Une frontière qui en prolonge une autre (ou l'inverse) se confond avec elle : la RFC 2046 l'interdit, et deux
    // logiciels ne découperaient plus le courriel de la même façon.
    if t.frontieres
        .iter()
        .any(|p| p.starts_with(&frontiere) || frontiere.starts_with(p))
    {
        return Err(Anomalie::FrontiereRepetee);
    }
    Ok(frontiere)
}

#[allow(clippy::too_many_arguments)]
fn pousser_feuille(
    m: &mut Message,
    t: &Travail,
    type_mime: &str,
    params: &[(String, String)],
    entetes: &[Entete],
    corps: &[u8],
    encodage: &str,
    b: &Bornes,
) {
    if m.parties.len() >= b.parties {
        m.noter(Anomalie::TropDeParties);
        m.incomplet = true;
        return;
    }
    let (disposition, params_disposition) = valeur(entetes, "content-disposition").map_or((None, Vec::new()), |e| {
        let (valeur_lue, params_lus) = parametres(&e.texte(), b);
        (Some(valeur_lue).filter(|v| !v.is_empty()), params_lus)
    });
    let chercher = |liste: &[(String, String)], nom: &str| liste.iter().find(|(n, _)| n == nom).map(|(_, v)| v.clone());
    // Des logiciels écrivent le nom en mots encodés (RFC 2047) même entre guillemets : décodé aussi.
    let nom = chercher(&params_disposition, "filename")
        .or_else(|| chercher(params, "name"))
        .map(|n| mots_encodes(n.as_bytes(), b));
    let (contenu, anomalie) = decoder(corps, encodage);
    if let Some(a) = anomalie {
        m.noter(a);
    }
    m.parties.push(Partie {
        chemin: t.chemin.clone(),
        profondeur: t.profondeur,
        type_mime: type_mime.to_string(),
        jeu: chercher(params, "charset").map(|j| j.to_ascii_lowercase()),
        disposition,
        nom,
        contenu: contenu.unwrap_or_else(|| corps.to_vec()),
        dans_piece_jointe: t.dans_piece_jointe,
    });
}

/// Le corps décodé selon son Content-Transfer-Encoding ; `None` quand il est tel quel.
fn decoder(corps: &[u8], encodage: &str) -> (Option<Vec<u8>>, Option<Anomalie>) {
    match encodage {
        "" | "7bit" | "8bit" | "binary" => (None, None),
        "base64" => {
            let (d, abime) = base64_tolerant(corps);
            (Some(d), abime.then_some(Anomalie::Base64Abime))
        }
        "quoted-printable" => (Some(quoted_printable(corps)), None),
        autre => (None, Some(Anomalie::EncodageInconnu(autre.chars().take(40).collect()))),
    }
}

/// Les lignes d'un bloc : (début, fin du contenu, début de la ligne suivante). Fins de ligne CRLF, LF ou CR seul.
fn lignes(octets: &[u8]) -> impl Iterator<Item = (usize, &[u8], usize)> + '_ {
    let mut i = 0;
    std::iter::from_fn(move || {
        let reste = octets.get(i..).filter(|r| !r.is_empty())?;
        let debut = i;
        let n = reste
            .iter()
            .position(|&o| o == b'\n' || o == b'\r')
            .unwrap_or(reste.len());
        // `n` est pris dans `reste` : la coupe ne manque jamais.
        let (ligne, apres) = reste.split_at_checked(n)?;
        let saut = match apres {
            [b'\r', b'\n', ..] => 2,
            [] => 0,
            _ => 1,
        };
        i = debut.checked_add(n)?.checked_add(saut)?;
        Some((debut, ligne, i))
    })
}

/// Un nom d'en-tête : des caractères imprimables, sans espace ni « : ».
fn nom_d_entete(ligne: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut morceaux = ligne.splitn(2, |&o| o == b':');
    let nom = trim_fin(morceaux.next()?);
    let reste = morceaux.next()?;
    (!nom.is_empty() && nom.iter().all(|&o| (33..=126).contains(&o))).then_some((nom, reste))
}

fn trim_fin(mut o: &[u8]) -> &[u8] {
    while let [avant @ .., b' ' | b'\t'] = o {
        o = avant;
    }
    o
}

fn trim_debut(mut o: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', apres @ ..] = o {
        o = apres;
    }
    o
}

/// Les en-têtes d'un bloc, l'indice où commence le corps, les anomalies, et si une borne a coupé la lecture. Une ligne
/// qui n'est ni un en-tête ni une suite commence le corps (des logiciels oublient la ligne vide).
fn separer_entetes(octets: &[u8], b: &Bornes) -> (Vec<Entete>, usize, Vec<Anomalie>, bool) {
    let mut entetes: Vec<Entete> = Vec::new();
    let mut anomalies = Vec::new();
    let mut coupe = false;
    let mut lus = 0_usize;
    let mut garder = true;
    for (debut, ligne, suivante) in lignes(octets) {
        if ligne.is_empty() {
            return (entetes, suivante, anomalies, coupe);
        }
        // Compteur comparé à sa borne juste après ; `suivante` >= `debut` (lignes).
        lus = lus.saturating_add(suivante.saturating_sub(debut));
        if lus > b.bloc_entetes && garder {
            garder = false;
            coupe = true;
            anomalies.push(Anomalie::TropDEntetes);
        }
        if let [b' ' | b'\t', ..] = ligne {
            // Ligne de suite : recollée à l'en-tête d'avant, sans dépasser sa borne.
            if let Some(e) = entetes.last_mut().filter(|_| garder) {
                let place = b.entete_octets.saturating_sub(e.brut.len());
                if ligne.len() > place {
                    e.brut.extend(ligne.iter().take(place));
                    if !anomalies.contains(&Anomalie::EnteteTropLong) {
                        anomalies.push(Anomalie::EnteteTropLong);
                    }
                    coupe = true;
                } else {
                    e.brut.extend_from_slice(ligne);
                }
            }
            continue;
        }
        let Some((nom, reste)) = nom_d_entete(ligne) else {
            return (entetes, debut, anomalies, coupe);
        };
        if !garder {
            continue;
        }
        if entetes.len() >= b.entetes {
            garder = false;
            coupe = true;
            anomalies.push(Anomalie::TropDEntetes);
            continue;
        }
        let mut brut = trim_debut(reste).to_vec();
        if brut.len() > b.entete_octets {
            brut.truncate(b.entete_octets);
            anomalies.push(Anomalie::EnteteTropLong);
            coupe = true;
        }
        entetes.push(Entete {
            nom: String::from_utf8_lossy(nom).to_ascii_lowercase(),
            brut,
            rang: entetes.len(),
        });
    }
    for e in &mut entetes {
        let fin = trim_fin(&e.brut).len();
        e.brut.truncate(fin);
    }
    // Pas de ligne vide : tout était en-têtes, le corps est vide.
    (entetes, octets.len(), anomalies, coupe)
}

/// Une ligne de frontière : « --frontière », « --frontière-- » (la dernière), suivies seulement d'espaces.
fn ligne_frontiere(ligne: &[u8], frontiere: &[u8]) -> Option<bool> {
    let reste = ligne.strip_prefix(b"--")?.strip_prefix(frontiere)?;
    let (fermante, reste) = match reste.strip_prefix(b"--") {
        Some(r) => (true, r),
        None => (false, reste),
    };
    reste.iter().all(|c| matches!(c, b' ' | b'\t')).then_some(fermante)
}

/// Découpe le corps d'une partie multiple : les morceaux entre ses lignes de frontière (indices dans `corps`), sans le
/// préambule ni l'épilogue. Au plus `max` morceaux : `true` si d'autres ont été laissés.
fn decouper_multipart(corps: &[u8], frontiere: &[u8], max: usize) -> (Vec<(usize, usize)>, Vec<Anomalie>, bool) {
    let mut morceaux = Vec::new();
    let mut anomalies = Vec::new();
    let mut ouvert: Option<usize> = None;
    let mut ferme = false;
    for (debut, ligne, suivante) in lignes(corps) {
        let Some(fermante) = ligne_frontiere(ligne, frontiere) else {
            continue;
        };
        if let Some(d) = ouvert {
            // Le saut de ligne qui précède la frontière lui appartient (RFC 2046).
            let mut f = debut;
            for fin_de_ligne in b"\n\r" {
                if f > d
                    && let Some(avant) = f.checked_sub(1)
                    && corps.get(avant) == Some(fin_de_ligne)
                {
                    f = avant;
                }
            }
            if morceaux.len() >= max {
                return (morceaux, anomalies, true);
            }
            morceaux.push((d, f.max(d)));
        }
        if fermante {
            ferme = true;
            ouvert = None;
            break;
        }
        ouvert = Some(suivante);
    }
    if let Some(d) = ouvert {
        if morceaux.len() >= max {
            return (morceaux, anomalies, true);
        }
        morceaux.push((d, corps.len()));
    }
    if !ferme && !morceaux.is_empty() {
        anomalies.push(Anomalie::FrontiereNonFermee);
    }
    (morceaux, anomalies, false)
}

#[expect(
    clippy::arithmetic_side_effects,
    reason = "chaque bras retire le bas de sa propre plage : ni négatif ni débordement"
)]
fn valeur_base64(o: u8) -> Option<u8> {
    match o {
        b'A'..=b'Z' => Some(o - b'A'),
        b'a'..=b'z' => Some(o - b'a' + 26),
        b'0'..=b'9' => Some(o - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Base64 lu avec la tolérance de la RFC 2045 (§6.8) : ce qui n'est pas de l'alphabet est sauté, un « = » termine un
/// groupe (des logiciels collent plusieurs blocs). Les décodeurs déjà présents dans Vanguard refusent le moindre
/// caractère étranger : un courriel se lit comme les logiciels de courriel le lisent, sinon ce qu'ils montrent
/// échapperait à l'examen. `true` : quelque chose clochait (caractère étranger, groupe incomplet).
fn base64_tolerant(octets: &[u8]) -> (Vec<u8>, bool) {
    let mut sortie = Vec::with_capacity((octets.len() / 4).saturating_mul(3));
    let mut groupe = 0_u32;
    let mut n = 0_u8;
    let mut abime = false;
    let mut apres_egal = false;
    for &o in octets {
        if let Some(v) = valeur_base64(o) {
            if apres_egal {
                // Des données après un « = » : un second bloc collé au premier.
                abime = true;
                apres_egal = false;
            }
            groupe = (groupe << 6) | u32::from(v);
            #[expect(clippy::arithmetic_side_effects, reason = "n < 4 : remis à 0 dès qu'il vaut 4")]
            {
                n += 1;
            }
            if n == 4 {
                sortie.extend_from_slice(&groupe.to_be_bytes()[1..]);
                groupe = 0;
                n = 0;
            }
        } else if o == b'=' {
            vider_groupe(&mut sortie, groupe, n, &mut abime);
            groupe = 0;
            n = 0;
            apres_egal = true;
        } else if !o.is_ascii_whitespace() {
            abime = true;
        }
    }
    if n > 0 {
        // Sans remplissage : décodé quand même, mais signalé.
        abime = true;
        vider_groupe(&mut sortie, groupe, n, &mut abime);
    }
    (sortie, abime)
}

fn vider_groupe(sortie: &mut Vec<u8>, groupe: u32, n: u8, abime: &mut bool) {
    match n {
        // 12 bits lus : un octet, et 4 bits de remplissage.
        2 => sortie.push((groupe >> 4).to_be_bytes()[3]),
        // 18 bits lus : deux octets, et 2 bits de remplissage.
        3 => sortie.extend_from_slice(&(groupe >> 2).to_be_bytes()[2..]),
        1 => *abime = true,
        _ => {}
    }
}

#[expect(
    clippy::arithmetic_side_effects,
    reason = "chaque bras retire le bas de sa propre plage : ni négatif ni débordement"
)]
fn hex(o: u8) -> Option<u8> {
    match o {
        b'0'..=b'9' => Some(o - b'0'),
        b'a'..=b'f' => Some(o - b'a' + 10),
        b'A'..=b'F' => Some(o - b'A' + 10),
        _ => None,
    }
}

/// Quoted-printable (RFC 2045 §6.7) : « =XY » est un octet, « = » en fin de ligne recolle la ligne suivante ; un « = »
/// mal formé reste tel quel.
fn quoted_printable(octets: &[u8]) -> Vec<u8> {
    let mut sortie = Vec::with_capacity(octets.len());
    let mut reste = octets;
    while let Some((&o, apres)) = reste.split_first() {
        if o != b'=' {
            sortie.push(o);
            reste = apres;
            continue;
        }
        // Saut de ligne doux, avec des espaces oubliés avant lui.
        reste = match trim_debut(apres) {
            [b'\r', b'\n', suite @ ..] | [b'\n' | b'\r', suite @ ..] => suite,
            [] => &[],
            [_, ..] => {
                if let [h, l, suite @ ..] = apres
                    && let (Some(h), Some(l)) = (hex(*h), hex(*l))
                {
                    sortie.push(h << 4 | l);
                    suite
                } else {
                    sortie.push(b'=');
                    apres
                }
            }
        };
    }
    sortie
}

/// Windows-1252, de 0x80 à 0x9F (le reste est Latin-1) ; les cinq cases vides deviennent « � ».
const WINDOWS_1252: [char; 32] = [
    '€', '\u{fffd}', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\u{fffd}', 'Ž', '\u{fffd}', '\u{fffd}',
    '‘', '’', '“', '”', '•', '–', '—', '˜', '™', 'š', '›', 'œ', '\u{fffd}', 'ž', 'Ÿ',
];

/// Un texte dans son jeu de caractères : UTF-8, ASCII, Latin-1, Latin-9 et Windows-1252 sont lus exactement ; les autres
/// au mieux (`false` : le texte peut être mal lu ; les liens, en ASCII, se trouvent quand même).
pub(crate) fn texte(octets: &[u8], jeu: Option<&str>) -> (String, bool) {
    let jeu = jeu.map(|j| j.trim().trim_matches('"').to_ascii_lowercase());
    match jeu.as_deref() {
        None | Some("utf-8" | "utf8" | "us-ascii" | "ascii") => (String::from_utf8_lossy(octets).into_owned(), true),
        Some("iso-8859-1" | "iso8859-1" | "latin1" | "latin-1" | "l1") => {
            (octets.iter().map(|&o| char::from(o)).collect(), true)
        }
        Some("iso-8859-15" | "iso8859-15" | "latin9" | "latin-9") => (
            octets
                .iter()
                .map(|&o| match o {
                    0xa4 => '€',
                    0xa6 => 'Š',
                    0xa8 => 'š',
                    0xb4 => 'Ž',
                    0xb8 => 'ž',
                    0xbc => 'Œ',
                    0xbd => 'œ',
                    0xbe => 'Ÿ',
                    _ => char::from(o),
                })
                .collect(),
            true,
        ),
        Some("windows-1252" | "cp1252" | "x-cp1252") => (
            octets
                .iter()
                .map(|&o| match o {
                    0x80..=0x9f => usize::from(o)
                        .checked_sub(0x80)
                        .and_then(|k| WINDOWS_1252.get(k))
                        .copied()
                        .unwrap_or(char::REPLACEMENT_CHARACTER),
                    _ => char::from(o),
                })
                .collect(),
            true,
        ),
        Some(_) => (String::from_utf8_lossy(octets).into_owned(), false),
    }
}

/// Les mots encodés d'un en-tête (RFC 2047, « =?jeu?B?…?= » et « =?jeu?Q?…?= ») décodés ; les espaces entre deux mots
/// encodés voisins retirés (la RFC le veut). Un mot mal formé reste tel quel ; au-delà de la borne, le reste aussi.
pub(crate) fn mots_encodes(brut: &[u8], b: &Bornes) -> String {
    let mut sortie = String::new();
    let mut reste = brut;
    let mut decodes = 0_usize;
    // Espaces vus depuis le dernier mot encodé, gardés seulement si un texte ordinaire suit.
    let mut attente = String::new();
    let mut apres_mot = false;
    while let ici @ [_, ..] = reste {
        if decodes < b.mots_encodes
            && ici.starts_with(b"=?")
            && let Some((texte, longueur)) = mot_encode(ici)
        {
            if !apres_mot {
                sortie.push_str(&attente);
            }
            attente.clear();
            sortie.push_str(&texte);
            // Compteur borné par b.mots_encodes juste au-dessus.
            decodes = decodes.saturating_add(1);
            reste = ici.get(longueur..).unwrap_or_default();
            apres_mot = true;
            continue;
        }
        // Jusqu'au prochain « =? » après le premier octet, ou la fin.
        let n = ici
            .windows(2)
            .enumerate()
            .skip(1)
            .find(|(_, w)| *w == b"=?")
            .map_or(ici.len(), |(k, _)| k);
        let (morceau, suite) = ici.split_at_checked(n).unwrap_or((ici, &[]));
        let morceau = String::from_utf8_lossy(morceau);
        if apres_mot && morceau.chars().all(char::is_whitespace) {
            attente.push_str(&morceau);
        } else {
            sortie.push_str(&attente);
            attente.clear();
            sortie.push_str(&morceau);
            apres_mot = false;
        }
        reste = suite;
    }
    sortie.push_str(&attente);
    sortie
}

/// Un mot encodé au début de `o` : son texte et sa longueur. La RFC les limite à 75 caractères ; chercher la fin plus
/// loin que 1 024 octets ferait relire tout l'en-tête à chaque « =? » mal fermé.
fn mot_encode(o: &[u8]) -> Option<(String, usize)> {
    let o = o.get(..1024).unwrap_or(o);
    let reste = o.strip_prefix(b"=?")?;
    let q1 = reste.iter().position(|&c| c == b'?')?;
    let (jeu, reste) = reste.split_at_checked(q1)?;
    let jeu = std::str::from_utf8(jeu).ok()?;
    // « jeu*langue » (RFC 2231 §5).
    let jeu = jeu.split('*').next().unwrap_or(jeu);
    let reste = reste.strip_prefix(b"?")?;
    let (&sorte, reste) = reste.split_first()?;
    let reste = reste.strip_prefix(b"?")?;
    let fin = reste.windows(2).position(|w| w == b"?=")?;
    let code = reste.get(..fin)?;
    if code.iter().any(u8::is_ascii_whitespace) {
        return None;
    }
    let octets = match sorte.to_ascii_uppercase() {
        b'B' => base64_tolerant(code).0,
        b'Q' => {
            let mut s = Vec::with_capacity(code.len());
            let mut reste = code;
            while let Some((&c, apres)) = reste.split_first() {
                reste = apres;
                match c {
                    b'_' => s.push(b' '),
                    b'=' => {
                        if let [h, l, suite @ ..] = apres
                            && let (Some(h), Some(l)) = (hex(*h), hex(*l))
                        {
                            s.push(h << 4 | l);
                            reste = suite;
                        } else {
                            s.push(b'=');
                        }
                    }
                    c => s.push(c),
                }
            }
            s
        }
        _ => return None,
    };
    // « =? », le jeu, « ? », la sorte et « ? », le code, « ?= ».
    Some((
        texte(&octets, Some(jeu)).0,
        q1.checked_add(fin)?.checked_add(2 + 1 + 2 + 2)?,
    ))
}

/// Un morceau d'un paramètre découpé (RFC 2231) : son rang, s'il est encodé, sa valeur.
type Morceau = (usize, bool, String);

/// Découpe aux « ; » hors des guillemets.
fn morceaux_params(brut: &str) -> Vec<String> {
    let mut morceaux = Vec::new();
    let mut courant = String::new();
    let mut guillemets = false;
    let mut echappe = false;
    for c in brut.chars() {
        if echappe {
            courant.push(c);
            echappe = false;
            continue;
        }
        match c {
            '\\' if guillemets => {
                courant.push(c);
                echappe = true;
            }
            '"' => {
                guillemets = !guillemets;
                courant.push(c);
            }
            ';' if !guillemets => morceaux.push(std::mem::take(&mut courant)),
            _ => courant.push(c),
        }
    }
    morceaux.push(courant);
    morceaux
}

fn sans_guillemets(v: &str) -> String {
    let v = v.trim();
    match v.strip_prefix('"') {
        Some(r) => {
            let r = r.strip_suffix('"').unwrap_or(r);
            let mut s = String::with_capacity(r.len());
            let mut echappe = false;
            for c in r.chars() {
                if echappe || c != '\\' {
                    s.push(c);
                    echappe = false;
                } else {
                    echappe = true;
                }
            }
            s
        }
        None => v.to_string(),
    }
}

/// « %XX » décodés (RFC 2231).
fn pourcents(v: &str) -> Vec<u8> {
    let o = v.as_bytes();
    let mut s = Vec::with_capacity(o.len());
    let mut reste = o;
    while let Some((&c, apres)) = reste.split_first() {
        if c == b'%'
            && let [h, l, suite @ ..] = apres
            && let (Some(h), Some(l)) = (hex(*h), hex(*l))
        {
            s.push(h << 4 | l);
            reste = suite;
            continue;
        }
        s.push(c);
        reste = apres;
    }
    s
}

/// La valeur principale d'un en-tête structuré (« text/html », « attachment ») en minuscules, et ses paramètres (noms
/// en minuscules), guillemets retirés, morceaux de la RFC 2231 (« filename*0*=… ») recollés et décodés.
pub(crate) fn parametres(brut: &str, b: &Bornes) -> (String, Vec<(String, String)>) {
    let mut morceaux = morceaux_params(brut).into_iter();
    let principal = morceaux
        .next()
        .unwrap_or_default()
        .split(['(', ' ', '\t'])
        .find(|s| !s.is_empty())
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let mut simples: Vec<(String, String)> = Vec::new();
    // Paramètres découpés : nom de base → (rang, encodé ?, valeur).
    let mut decoupes: Vec<(String, Vec<Morceau>)> = Vec::new();
    for m in morceaux.take(b.parametres) {
        let Some((nom, v)) = m.split_once('=') else {
            continue;
        };
        let nom = nom.trim().to_ascii_lowercase();
        let v = sans_guillemets(v);
        let (base, etendu) = match nom.strip_suffix('*') {
            Some(n) => (n.to_string(), true),
            None => (nom.clone(), false),
        };
        let (base, rang) = match base.rsplit_once('*') {
            Some((n, r)) if !r.is_empty() && r.bytes().all(|c| c.is_ascii_digit()) => {
                (n.to_string(), r.parse::<usize>().ok())
            }
            _ => (base, None),
        };
        if !etendu && rang.is_none() {
            simples.push((nom, v));
            continue;
        }
        let rang = rang.unwrap_or(0);
        if rang >= b.parametres {
            continue;
        }
        match decoupes.iter_mut().find(|(n, _)| *n == base) {
            Some((_, l)) => l.push((rang, etendu, v)),
            None => decoupes.push((base, vec![(rang, etendu, v)])),
        }
    }
    for (base, mut l) in decoupes {
        l.sort_by_key(|(r, _, _)| *r);
        let mut jeu: Option<String> = None;
        let mut octets = Vec::new();
        for (i, (_, etendu, v)) in l.iter().enumerate() {
            if *etendu {
                let v = if i == 0 {
                    // « jeu'langue'valeur ».
                    let mut p = v.splitn(3, '\'');
                    match (p.next(), p.next(), p.next()) {
                        (Some(j), Some(_), Some(reste)) => {
                            jeu = Some(j.to_string()).filter(|j| !j.is_empty());
                            reste
                        }
                        _ => v.as_str(),
                    }
                } else {
                    v.as_str()
                };
                octets.extend(pourcents(v));
            } else {
                octets.extend_from_slice(v.as_bytes());
            }
        }
        // La forme RFC 2231 l'emporte sur une forme simple du même nom.
        simples.retain(|(n, _)| *n != base);
        simples.push((base, texte(&octets, jeu.as_deref()).0));
    }
    (principal, simples)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn petit() -> Bornes {
        Bornes {
            octets: 10_000,
            profondeur: 4,
            parties: 10,
            entetes: 20,
            entete_octets: 200,
            bloc_entetes: 2_000,
            mots_encodes: 5,
            parametres: 10,
            frontiere: 70,
        }
    }

    #[test]
    fn texte_simple() {
        let m = lire(b"From: Alice <alice@example.com>\r\nSubject: Bonjour\r\n\r\nSalut, voici le lien.\r\n");
        assert_eq!(m.entetes.len(), 2);
        assert_eq!(valeur(&m.entetes, "subject").unwrap().texte(), "Bonjour");
        assert_eq!(m.parties.len(), 1);
        assert_eq!(m.parties[0].type_mime, "text/plain");
        assert_eq!(m.parties[0].contenu, b"Salut, voici le lien.\r\n");
        assert!(m.anomalies.is_empty() && !m.incomplet);
    }

    #[test]
    fn en_tetes_plies_et_fins_de_ligne() {
        // Ligne de suite, LF seul, CR seul.
        let m = lire(b"Subject: un\n  deux\rFrom: a@example.com\n\ncorps");
        assert_eq!(valeur(&m.entetes, "subject").unwrap().texte(), "un  deux");
        assert_eq!(valeur(&m.entetes, "from").unwrap().rang, 1);
        assert_eq!(m.parties[0].contenu, b"corps");
        // Ligne d'enveloppe mbox retirée.
        let m = lire(b"From alice@example.com Mon Oct 20 10:00:00 2026\nFrom: a@example.com\n\nx");
        assert_eq!(m.entetes.len(), 1);
        // Pas de ligne vide : le corps commence à la première ligne qui n'est pas un en-tête.
        let m = lire(b"From: a@example.com\nceci est le corps\n");
        assert_eq!(m.entetes.len(), 1);
        assert_eq!(m.parties[0].contenu, b"ceci est le corps\n");
    }

    #[test]
    fn alternative_base64_et_qp() {
        let c = b"Content-Type: multipart/alternative; boundary=\"b1\"\r\n\r\npreambule\r\n--b1\r\n\
Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n\
Caf=C3=A9 =\r\nsuite\r\n--b1\r\nContent-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n\r\n\
PGEgaHJlZj0iaHR0cHM6Ly9leGFtcGxlLmNvbSI+eDwvYT4=\r\n--b1--\r\nepilogue";
        let m = lire(c);
        assert_eq!(m.parties.len(), 2);
        assert_eq!(m.parties[0].chemin, "1.1");
        assert_eq!(texte(&m.parties[0].contenu, Some("utf-8")).0, "Café suite");
        assert_eq!(m.parties[1].contenu, b"<a href=\"https://example.com\">x</a>");
        assert!(m.anomalies.is_empty(), "{:?}", m.anomalies);
    }

    #[test]
    fn mots_encodes_rfc2047() {
        let b = &BORNES;
        assert_eq!(mots_encodes(b"=?UTF-8?B?Q2Fmw6k=?=", b), "Café");
        assert_eq!(mots_encodes(b"=?iso-8859-1?Q?Caf=E9_cr=E8me?=", b), "Café crème");
        // Deux mots voisins recollés ; le texte ordinaire garde ses espaces.
        assert_eq!(mots_encodes(b"=?utf-8?Q?a?= =?utf-8?Q?b?= et c", b), "ab et c");
        // Jeu inconnu : lu au mieux ; mot mal fermé : tel quel.
        assert_eq!(mots_encodes(b"=?x-inconnu?Q?abc?=", b), "abc");
        assert_eq!(mots_encodes(b"=?utf-8?Q?abc", b), "=?utf-8?Q?abc");
        // Au-delà de la borne, le reste n'est pas décodé.
        let mut p = petit();
        p.mots_encodes = 1;
        assert_eq!(mots_encodes(b"=?utf-8?Q?a?= =?utf-8?Q?b?=", &p), "a =?utf-8?Q?b?=");
        // U+202E dans un nom : décodé tel quel, c'est l'écran qui le neutralise.
        assert!(mots_encodes(b"=?utf-8?B?4oCu?=", b).contains('\u{202e}'));
    }

    #[test]
    fn parametres_rfc2231() {
        let b = &BORNES;
        let (t, p) = parametres("attachment; filename*=UTF-8''facture%E2%80%AEfdp.exe", b);
        assert_eq!(t, "attachment");
        assert_eq!(p, [("filename".to_string(), "facture\u{202e}fdp.exe".to_string())]);
        let (_, p) = parametres("attachment; filename*0*=utf-8''r%C3%A9; filename*1=\"sum;é.pdf\"", b);
        assert_eq!(p[0].1, "résum;é.pdf");
        let (t, p) = parametres("Text/HTML; charset=\"ISO-8859-1\"; name=\"a \\\"b\\\".html\"", b);
        assert_eq!(t, "text/html");
        assert_eq!(p[0], ("charset".into(), "ISO-8859-1".into()));
        assert_eq!(p[1].1, "a \"b\".html");
    }

    #[test]
    fn imbrications_et_courriel_joint() {
        let c = b"Content-Type: multipart/mixed; boundary=m\n\n--m\nContent-Type: multipart/related; boundary=r\n\n\
--r\nContent-Type: multipart/alternative; boundary=a\n\n--a\nContent-Type: text/plain\n\ntexte\n--a--\n--r--\n\
--m\nContent-Type: message/rfc822\n\nFrom: b@example.org\nContent-Type: text/html\n\n<p>transfere</p>\n\
--m\nContent-Type: application/pdf; name=f.pdf\nContent-Disposition: attachment\nContent-Transfer-Encoding: base64\n\n\
JVBERi0=\n--m--\n";
        let m = lire(c);
        assert_eq!(m.parties.len(), 3, "{:?}", m.parties);
        assert_eq!(m.parties[0].chemin, "1.1.1.1");
        assert_eq!(m.parties[0].profondeur, 3);
        assert!(m.parties[1].dans_piece_jointe && m.parties[1].type_mime == "text/html");
        assert_eq!(m.parties[2].nom.as_deref(), Some("f.pdf"));
        assert_eq!(m.parties[2].disposition.as_deref(), Some("attachment"));
        assert_eq!(m.parties[2].contenu, b"%PDF-");
        assert!(m.anomalies.is_empty(), "{:?}", m.anomalies);
    }

    #[test]
    fn jeux_de_caracteres() {
        assert_eq!(texte(&[0x80, b'5'], Some("windows-1252")).0, "€5");
        assert_eq!(texte(&[0xa4, 0xe9], Some("ISO-8859-15")).0, "€é");
        assert_eq!(texte(&[0xe9], Some("latin1")).0, "é");
        assert!(!texte(b"abc", Some("koi8-r")).1);
    }

    #[test]
    fn frontiere_en_boucle() {
        // La frontière intérieure reprend l'extérieure : la partie reste opaque, rien ne tourne en rond.
        let c = b"Content-Type: multipart/mixed; boundary=b\n\n--b\n\
Content-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain\n\nx\n--b--\n--b--\n";
        let m = lire(c);
        assert!(m.anomalies.contains(&Anomalie::FrontiereRepetee), "{:?}", m.anomalies);
        // Préfixe de la frontière d'un parent : pareil.
        let c = b"Content-Type: multipart/mixed; boundary=bb\n\n--bb\n\
Content-Type: multipart/mixed; boundary=b\n\nx\n--bb--\n";
        assert!(lire(c).anomalies.contains(&Anomalie::FrontiereRepetee));
    }

    /// `n` parties multiples emboîtées, chacune avec sa frontière.
    fn emboite(n: usize) -> Vec<u8> {
        let mut c = Vec::new();
        for i in 0..n {
            c.extend_from_slice(format!("Content-Type: multipart/mixed; boundary=f{i}x\n\n--f{i}x\n").as_bytes());
        }
        c.extend_from_slice(b"Content-Type: text/plain\n\nfond\n");
        for i in (0..n).rev() {
            c.extend_from_slice(format!("--f{i}x--\n").as_bytes());
        }
        c
    }

    #[test]
    fn mille_niveaux() {
        let debut = std::time::Instant::now();
        let m = lire(&emboite(1_000));
        assert!(m.anomalies.contains(&Anomalie::TropProfond) && m.incomplet);
        assert_eq!(m.parties, Vec::<Partie>::new());
        assert!(
            debut.elapsed() < std::time::Duration::from_secs(1),
            "{:?}",
            debut.elapsed()
        );
        // Dans la borne : lu jusqu'au fond.
        let m = lire(&emboite(5));
        assert_eq!(m.parties.len(), 1);
        assert_eq!(m.parties[0].contenu, b"fond");
    }

    #[test]
    fn cent_mille_parties() {
        let mut c = b"Content-Type: multipart/mixed; boundary=p\n\n".to_vec();
        for _ in 0..100_000 {
            c.extend_from_slice(b"--p\n\nx\n");
        }
        c.extend_from_slice(b"--p--\n");
        let debut = std::time::Instant::now();
        let m = lire(&c);
        assert!(m.anomalies.contains(&Anomalie::TropDeParties) && m.incomplet);
        assert!(m.parties.len() <= BORNES.parties);
        assert!(
            debut.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            debut.elapsed()
        );
    }

    #[test]
    fn bornes_de_taille_et_d_en_tetes() {
        let b = petit();
        let m = lire_borne(&vec![b'a'; 20_000], &b);
        assert!(m.anomalies.contains(&Anomalie::TropGros) && m.incomplet);
        // En-tête d'un mégaoctet en lignes de suite.
        let mut c = b"Subject: x\n".to_vec();
        for _ in 0..20_000 {
            c.extend_from_slice(b" 0123456789012345678901234567890123456789012345\n");
        }
        c.extend_from_slice(b"\ncorps");
        let m = lire(&c);
        assert!(m.anomalies.contains(&Anomalie::EnteteTropLong) && m.incomplet);
        assert!(valeur(&m.entetes, "subject").unwrap().brut.len() <= BORNES.entete_octets);
        assert_eq!(m.parties[0].contenu, b"corps");
        // 10 000 en-têtes.
        let mut c = Vec::new();
        for i in 0..10_000 {
            c.extend_from_slice(format!("X-N{i}: v\n").as_bytes());
        }
        c.extend_from_slice(b"\ncorps");
        let m = lire(&c);
        assert_eq!(m.entetes.len(), BORNES.entetes);
        assert!(m.anomalies.contains(&Anomalie::TropDEntetes) && m.incomplet);
        assert_eq!(m.parties[0].contenu, b"corps");
    }

    #[test]
    fn base64_abime() {
        assert_eq!(base64_tolerant(b"Q2Fm\r\nw6k="), ("Café".as_bytes().to_vec(), false));
        // Ordures, « = » au milieu, sans remplissage : décodé, signalé.
        let (d, abime) = base64_tolerant(b"Q2F!!m w6k");
        assert_eq!(d, "Café".as_bytes());
        assert!(abime);
        let (d, abime) = base64_tolerant(b"YQ==Yg==");
        assert_eq!(d, b"ab");
        assert!(abime);
        let m = lire(b"Content-Transfer-Encoding: base64\n\nYWJj*ZA\n");
        assert!(m.anomalies.contains(&Anomalie::Base64Abime));
        assert_eq!(m.parties[0].contenu, b"abcd");
    }

    #[test]
    fn quoted_printable_tolerant() {
        assert_eq!(quoted_printable(b"a=3Db=\r\nc =ZZ d=\n"), b"a=bc =ZZ d");
        assert_eq!(quoted_printable(b"fin="), b"fin");
    }

    #[test]
    fn courriels_abimes() {
        // Frontière jamais fermée : la dernière partie va jusqu'au bout, signalée.
        let m = lire(b"Content-Type: multipart/mixed; boundary=z\n\n--z\n\nun\n--z\n\ndeux");
        assert_eq!(m.parties.len(), 2);
        assert_eq!(m.parties[1].contenu, b"deux");
        assert!(m.anomalies.contains(&Anomalie::FrontiereNonFermee));
        // Préambule contenant une fausse ligne de frontière (« --z-pas-elle ») : ignorée.
        let m = lire(b"Content-Type: multipart/mixed; boundary=z\n\n--z-pas-elle\n--z\n\nun\n--z--\n");
        assert_eq!(m.parties.len(), 1);
        assert_eq!(m.parties[0].contenu, b"un");
        // Frontière trop longue : la partie est lue comme du texte, pour ses liens.
        let longue = "f".repeat(1_000);
        let c = format!("Content-Type: multipart/mixed; boundary={longue}\n\n--{longue}\n\nx\n");
        let m = lire(c.as_bytes());
        assert!(m.anomalies.contains(&Anomalie::FrontiereTropLongue));
        assert_eq!(m.parties.len(), 1);
        // Sans frontière.
        assert!(
            lire(b"Content-Type: multipart/mixed\n\nx")
                .anomalies
                .contains(&Anomalie::FrontiereAbsente)
        );
        // Deux Content-Type : le premier compte, le doublon est signalé.
        let m = lire(b"Content-Type: text/html\nContent-Type: text/plain\n\n<a>");
        assert_eq!(m.parties[0].type_mime, "text/html");
        assert!(m.anomalies.contains(&Anomalie::EnteteEnDouble("content-type".into())));
        // Encodage inconnu : corps gardé tel quel.
        let m = lire(b"Content-Transfer-Encoding: x-uuencode\n\nbegin");
        assert_eq!(m.anomalies, [Anomalie::EncodageInconnu("x-uuencode".into())]);
        assert_eq!(m.parties[0].contenu, b"begin");
        // NUL, UTF-8 invalide, CR seul : lus sans planter.
        let m = lire(b"Subject: \xff\x00\rFrom: a@example.com\r\r\x00\xfe");
        assert_eq!(m.entetes.len(), 2);
        // Fichier vide, image PNG.
        let m = lire(b"");
        assert!(m.entetes.is_empty() && m.anomalies.contains(&Anomalie::SansCorps));
        let m = lire(b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR");
        assert_eq!(m.entetes, Vec::<Entete>::new());
    }

    #[test]
    fn digest() {
        let m = lire(b"Content-Type: multipart/digest; boundary=d\n\n--d\n\nFrom: a@example.org\n\nun\n--d--\n");
        assert_eq!(m.parties.len(), 1);
        assert!(m.parties[0].dans_piece_jointe);
        assert_eq!(m.parties[0].contenu, b"un");
    }

    #[test]
    fn pire_courriel_de_50_mo_lu_vite() {
        // Le pire trouvé : neuf parties emboîtées (chaque niveau relit tout ce qu'il contient), un en-tête de suite
        // démesuré, puis 50 Mo de lignes qui ressemblent à une frontière sans en être une. Tout reste linéaire.
        let mut c = Vec::new();
        for i in 0..9 {
            c.extend_from_slice(format!("Content-Type: multipart/mixed; boundary=f{i}x\n\n--f{i}x\n").as_bytes());
        }
        c.extend_from_slice(b"Subject: =?utf-8?Q?a");
        while c.len() < 1_000_000 {
            c.extend_from_slice(b" =?a?Q?\n");
        }
        c.extend_from_slice(b"\n");
        while c.len() < 50_000_000 {
            c.extend_from_slice(b"--f8x-presque\n--f0\n=?x?B?\n");
        }
        let debut = std::time::Instant::now();
        let m = lire(&c);
        assert_eq!(m.parties.len(), 1);
        // Moins de 2 s en version publiée ; la version de test, sans optimisation, a plus de marge.
        let limite = if cfg!(debug_assertions) { 30 } else { 2 };
        assert!(
            debut.elapsed() < std::time::Duration::from_secs(limite),
            "{:?}",
            debut.elapsed()
        );
    }
}

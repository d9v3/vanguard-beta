//! Le cache des listes téléchargées (menaces d'abuse.ch, catalogue de la CISA, Échap, pilotes vulnérables,
//! versions des logiciels) : une copie gardée dans le dossier de Vanguard, redemandée quand elle a vieilli, jamais
//! remplacée par une réponse qui n'est pas la liste. Les mots qui disent un échec restent chez abuse.ch
//! (`protection::abuse_ch`), qui les a écrits pour ses listes ; chaque autre source dit les siens.
//!
//! Chaque copie est scellée avec sa date de téléchargement (`<nom>.sceau.json` à côté, lui-même scellé par `sceau`) :
//! un programme du compte qui vidait une liste et la datait dans le futur faisait taire l'antivirus, les botnets, le
//! KEV ou Échap pour toujours, la date du fichier disant « encore fraîche » à jamais. L'âge vient donc de la date
//! scellée, jamais de celle du fichier ; une copie sans sceau, changée, acceptée telle quelle ou datée dans le futur
//! est périmée : redemandée, et si elle ne peut pas l'être, la liste n'est pas vérifiée (et c'est dit), jamais
//! comptée comme saine. Comme le sceau : barrière, pas coffre (qui refait les sceaux n'est pas vu).

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::{tr, trf};

/// Pourquoi une liste n'a pas pu être vérifiée. Elle ne porte ni l'adresse ni la clé : rien à masquer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Echec {
    /// Aucune clé donnée (ou un fichier de clé abîmé) : rien n'est demandé.
    Manquante,
    /// abuse.ch a refusé la clé (401, 403).
    Refusee,
    /// Une autre réponse, et aucune copie d'avant : 404 (fichier renommé ?), 429 (trop de demandes), panne…
    Reponse(u16),
    /// Pas de réponse (pas d'Internet ?), et aucune copie d'avant.
    SansReponse,
    /// La réponse n'a pas pu être gardée sur le disque (plein ? droits ?).
    Ecriture,
    /// Une réponse 200 qui n'est pas la liste (page de blocage d'un proxy, portail Wi-Fi) : la copie d'avant reste.
    Illisible,
    /// Le travail sans Internet est demandé (`parametres::hors_ligne`) : rien n'est parti.
    HorsLigne,
    /// La copie gardée ne peut pas être crue (`Refus`), et la redemande n'a rien donné (`Redemande`).
    CopieRefusee(Refus, Redemande),
}

/// Ce qu'a donné la redemande d'une copie refusée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Redemande {
    /// Une réponse qui n'est pas la liste : son code.
    Reponse(u16),
    SansReponse,
    /// Rien n'est parti : travail sans Internet.
    HorsLigne,
    /// Déjà redemandée il y a peu (`PLANCHER`) : pas encore de nouvelle demande.
    Attente,
    /// La réponse n'a pas pu être gardée, ou le dossier pas créé.
    Ecriture,
}

/// Pourquoi une copie gardée ne peut pas être crue : elle est alors périmée, quel que soit son âge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refus {
    /// Pas de date de téléchargement sûre : la copie d'une version d'avant, ou sa date effacée.
    SansSceau,
    /// Elle, ou sa date, changées hors de Vanguard (ou illisibles).
    HorsVanguard,
    /// Effacée, ou remplacée par autre chose qu'un fichier (lien, dossier, tube), alors que sa date est restée.
    Effacee,
    /// Sa date a été acceptée telle quelle après l'effacement des sceaux de Vanguard : rien ne prouve qui l'a écrite.
    Adoptee,
    /// Datée dans le futur : elle ne vieillirait jamais.
    DateFuture,
}

impl Refus {
    /// La raison, prête à suivre « copie gardée refusée, ».
    pub(crate) fn raison(self) -> &'static str {
        match self {
            Refus::SansSceau => tr!(
                "copie d'une version d'avant de Vanguard, sans date sûre",
                "a copy from an earlier version of Vanguard, without a reliable date"
            ),
            Refus::HorsVanguard => tr!("changée hors de Vanguard", "changed outside Vanguard"),
            Refus::Effacee => tr!(
                "effacée ou remplacée hors de Vanguard",
                "deleted or replaced outside Vanguard"
            ),
            Refus::Adoptee => tr!(
                "acceptée telle quelle après l'effacement des sceaux de Vanguard",
                "accepted as it was after Vanguard's seals were deleted"
            ),
            Refus::DateFuture => tr!(
                "datée dans le futur : l'horloge de cet ordinateur retarde, ou la date a été changée",
                "dated in the future: this computer's clock is behind, or the date was changed"
            ),
        }
    }

    /// Ce que dit une liste qui ne sert pas parce que sa copie gardée est refusée. Sans promesse : qui la retélécharge
    /// (et si elle peut l'être) dépend du lecteur, qui le dit après.
    pub(crate) fn texte(self) -> String {
        trf!(
            "copie gardée refusée, {} ; elle ne sert plus tant qu'elle n'est pas retéléchargée",
            "kept copy refused, {}; it is no longer used until it is downloaded again",
            self.raison()
        )
    }
}

/// Le texte d'une copie refusée que la redemande n'a pas remplacée, neutre (toutes les sources du cache s'en servent).
pub(crate) fn texte_copie_refusee(refus: Refus, redemande: Redemande) -> String {
    let apres = match redemande {
        Redemande::Reponse(code) => trf!(
            "la redemande a reçu la réponse {code}",
            "asking again got answer {code}"
        ),
        Redemande::SansReponse => tr!(
            "la redemande est restée sans réponse, pas d'Internet ?",
            "asking again got no answer, no Internet?"
        )
        .to_string(),
        Redemande::HorsLigne => trf!(
            "rien n'est redemandé : {}",
            "nothing is asked again: {}",
            crate::parametres::raison_hors_ligne()
        ),
        Redemande::Attente => tr!(
            "déjà redemandée il y a moins d'un quart d'heure",
            "already asked again less than a quarter of an hour ago"
        )
        .to_string(),
        Redemande::Ecriture => tr!(
            "la réponse n'a pas pu être gardée, disque plein ?",
            "the answer could not be kept, disk full?"
        )
        .to_string(),
    };
    trf!(
        "copie gardée refusée, {} ; {apres}",
        "kept copy refused, {}; {apres}",
        refus.raison()
    )
}

/// Une liste demandée : la copie gardée et son âge (la nouvelle quand le téléchargement a réussi, sinon celle
/// d'avant ; `None` : aucune), le code de la réponse quand une demande a été faite, et pourquoi la copie n'a pas été
/// rafraîchie quand elle devait l'être (`None` : encore fraîche, ou remplacée).
pub(crate) struct Liste {
    pub copie: Option<(Vec<u8>, Duration)>,
    pub code: Option<u16>,
    pub manque: Option<Echec>,
}

impl Liste {
    /// La copie à utiliser, ou pourquoi il n'y en a pas. `avec_cle` : une réponse 401 ou 403 veut dire clé refusée,
    /// et la copie d'avant ne sert pas (elle était celle d'une clé qui ne vaut plus).
    pub(crate) fn resultat(self, avec_cle: bool) -> Result<(Vec<u8>, Duration), Echec> {
        if avec_cle && matches!(self.code, Some(401 | 403)) {
            return Err(Echec::Refusee);
        }
        match (self.copie, self.code) {
            (Some(copie), _) => Ok(copie),
            (None, _) if self.manque == Some(Echec::Illisible) => Err(Echec::Illisible),
            (None, _) if let Some(refus @ (Echec::CopieRefusee(..) | Echec::HorsLigne)) = self.manque => Err(refus),
            (None, Some(code)) => Err(Echec::Reponse(code)),
            (None, None) => Err(Echec::SansReponse),
        }
    }
}

/// Une liste téléchargée, gardée dans `sous_dossier/nom` du dossier de Vanguard : `fraiche` sans être redemandée,
/// retéléchargée ensuite. La télécharger ne dit à personne ce qu'on cherche (on prend la liste entière). Seule une
/// réponse 200 que `valide` accepte remplace la copie d'avant (un 429, une panne ou une page qui n'est pas la liste
/// la gardent, avec son âge : le lancement suivant redemande), par l'écriture atomique : jamais à moitié écrite.
/// Partagé entre MalwareBazaar, URLhaus, Feodo Tracker, ThreatFox, le catalogue de la CISA, Échap, la liste des
/// pilotes vulnérables (LOLDrivers) et les versions des logiciels. Le seul endroit qui télécharge une liste : le
/// travail sans Internet s'y vérifie, et rien ne part alors.
pub(crate) fn liste(
    demande: crate::http::Demande,
    lieu: (&str, &str),
    fraiche: Duration,
    valide: fn(&[u8]) -> bool,
) -> Liste {
    liste_validee(demande, lieu, fraiche, &valide)
}

/// Au-delà, ce n'est pas une liste téléchargée (la plus grosse, l'archive complète de MalwareBazaar, fait quelques
/// centaines de Mio au plus).
pub(crate) const LISTE_MAX: u64 = 1 << 30;

/// Une horloge qui recule de quelques minutes (synchronisée au démarrage, juste après un téléchargement) ne fait pas
/// refuser une copie : jusque-là, elle a l'âge zéro. Au-delà, elle est dite datée dans le futur.
const MARGE_HORLOGE: u64 = 10 * 60;

/// Une copie refusée n'est pas redemandée plus souvent : un programme qui la touche avant chaque passe ferait sinon
/// partir une demande (avec la clé abuse.ch de la personne) à chaque bilan, jusqu'à se faire limiter.
const PLANCHER: Duration = Duration::from_mins(15);

/// Le sceau d'une copie : quand elle a été téléchargée (secondes depuis 1970), sa taille et son empreinte BLAKE3.
/// Scellé lui-même (`sceau`) : changer la copie, ou la date, se voit.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct Sceau {
    telecharge: u64,
    taille: u64,
    empreinte: String,
}

/// Le nom du sceau d'une copie sous le dossier de Vanguard (`sceau` y garde son empreinte).
fn nom_du_sceau((sous_dossier, nom): (&str, &str)) -> String {
    format!("{sous_dossier}/{nom}.sceau.json")
}

/// Le nom de la date de la dernière redemande d'une copie refusée, scellée elle aussi (`PLANCHER`).
fn nom_de_la_demande((sous_dossier, nom): (&str, &str)) -> String {
    format!("{sous_dossier}/{nom}.demande.json")
}

fn empreinte(octets: &[u8]) -> String {
    blake3::hash(octets).to_hex().to_string()
}

fn maintenant() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Le sceau d'une copie, relu sans rien écrire (le veilleur le lit aussi, dans une unité sans droit d'écrire ici) :
/// `Ok(None)` s'il n'y en a pas et pas de copie non plus, `Err` s'il ne peut pas être cru. Aucun sceau à côté d'une
/// copie : sans date sûre, elle ne vaut rien.
fn sceau_de(lieu: (&str, &str)) -> Result<Option<Sceau>, Refus> {
    use crate::sceau::Lecture;
    let dossier = super::dossier_local();
    let copie_la = || std::fs::symlink_metadata(dossier.join(lieu.0).join(lieu.1)).is_ok();
    let octets = match crate::sceau::lire_sans_ecrire(&dossier, &nom_du_sceau(lieu)) {
        Lecture::Intact(o) => o,
        Lecture::Absent | Lecture::Inconnu if copie_la() => return Err(Refus::SansSceau),
        Lecture::Absent | Lecture::Inconnu => return Ok(None),
        Lecture::Falsifie(None) if !copie_la() => return Ok(None),
        Lecture::Adopte(_) => return Err(Refus::Adoptee),
        // Les sceaux des copies ne sont jamais adoptés (ils ne sont pas dans l'inventaire) : après l'effacement des
        // sceaux de Vanguard, le leur se lit changé ; c'est cet effacement qu'il faut dire.
        Lecture::Falsifie(Some(_)) if crate::sceau::refaits_dans(&dossier) => return Err(Refus::Adoptee),
        Lecture::Falsifie(_) | Lecture::Illisible(_) => return Err(Refus::HorsVanguard),
    };
    let sceau: Sceau = serde_json::from_slice(&octets).map_err(|_| Refus::HorsVanguard)?;
    if sceau.telecharge > maintenant().saturating_add(MARGE_HORLOGE) {
        return Err(Refus::DateFuture);
    }
    Ok(Some(sceau))
}

/// L'âge d'une copie d'après son sceau (jamais la date du fichier, que tout programme du compte change).
fn age_de(sceau: &Sceau) -> Duration {
    Duration::from_secs(maintenant().saturating_sub(sceau.telecharge))
}

/// L'âge de la copie gardée de `lieu` d'après son sceau, sans la lire : `None` sans copie qui puisse être crue (à
/// télécharger). Pour annoncer un long téléchargement au bon moment.
pub(crate) fn age(lieu: (&str, &str)) -> Option<Duration> {
    sceau_de(lieu).ok().flatten().map(|s| age_de(&s))
}

/// La copie gardée de `lieu` (sous-dossier, nom), `max` octets au plus, et son âge d'après son sceau : `Ok(None)` s'il
/// n'y en a jamais eu (ni copie, ni sceau), `Err` si elle ne peut pas être crue (sans sceau, changée, effacée sous son
/// sceau, acceptée telle quelle après l'effacement des sceaux, datée dans le futur). Pour qui relit une liste sans la
/// demander (le veilleur, le bilan, hors ligne) : une copie refusée n'est jamais une liste vide, donc vérifiée.
pub(crate) fn gardee(lieu: (&str, &str), max: u64) -> Result<Option<(Vec<u8>, Duration)>, Refus> {
    let Some(sceau) = sceau_de(lieu)? else {
        return Ok(None);
    };
    let fichier = super::dossier_local().join(lieu.0).join(lieu.1);
    // Un simple fichier, borné : un tube ou un lien vers /dev/zero posé à sa place ne fige ni ne remplit rien. Et
    // ne se lit pas : sous un sceau intact, c'est une copie effacée ou remplacée, jamais « pas encore de copie »
    // (effacer la liste complète de MalwareBazaar réduisait sinon l'antivirus aux 48 dernières heures, sans un mot).
    let Ok(octets) = super::lire_ordinaire(&fichier, max) else {
        return Err(Refus::Effacee);
    };
    if octets.len() as u64 != sceau.taille || empreinte(&octets) != sceau.empreinte {
        return Err(Refus::HorsVanguard);
    }
    Ok(Some((octets, age_de(&sceau))))
}

/// Le verrou d'une copie : la copie et son sceau s'écrivent ensemble. Sans lui, la surveillance et un bilan qui
/// téléchargent la même liste en même temps laissaient le sceau de l'un sur la copie de l'autre : lue changée, donc
/// redemandée pour rien.
fn verrou(lieu: (&str, &str)) -> std::io::Result<super::Verrou> {
    let dossier = super::dossier_local().join(lieu.0);
    let nom = format!("{}.verrou", lieu.1);
    super::Verrou::prendre(&dossier, &nom, false, super::ATTENTE_ECRITURE).map_err(|e| e.erreur(&nom))
}

/// Garde `octets` comme copie de `lieu`, scellée avec la date d'aujourd'hui : la copie d'abord, puis son sceau, sous
/// le verrou de la copie. Si le sceau ne s'écrit pas, la copie se lit refusée : périmée, jamais crue.
pub(crate) fn garder(lieu: (&str, &str), octets: &[u8]) -> std::io::Result<()> {
    let _verrou = verrou(lieu)?;
    let dossier = super::dossier_local();
    super::ecrire_atomique(&dossier.join(lieu.0).join(lieu.1), octets)?;
    let sceau = Sceau {
        telecharge: maintenant(),
        taille: octets.len() as u64,
        empreinte: empreinte(octets),
    };
    crate::sceau::ecrire_dans(
        &dossier,
        &nom_du_sceau(lieu),
        &serde_json::to_vec(&sceau).map_err(std::io::Error::other)?,
    )
}

/// Oublie une copie : la copie ET son sceau (et la date de sa dernière redemande). Effacer la copie seule laissait un
/// sceau sans copie, que `gardee` lit comme une copie effacée hors de Vanguard.
pub(crate) fn oublier(lieu: (&str, &str)) -> std::io::Result<()> {
    let _verrou = verrou(lieu)?;
    let dossier = super::dossier_local();
    match std::fs::remove_file(dossier.join(lieu.0).join(lieu.1)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    crate::sceau::effacer_dans(&dossier, &nom_du_sceau(lieu))?;
    crate::sceau::effacer_dans(&dossier, &nom_de_la_demande(lieu))
}

/// Une copie refusée a-t-elle déjà été redemandée il y a moins de `PLANCHER` ? D'après une date scellée : effacée ou
/// changée, elle ne retient rien (la demande part, comme avant ce plancher).
fn redemandee_recemment(lieu: (&str, &str)) -> bool {
    let dossier = super::dossier_local();
    let crate::sceau::Lecture::Intact(o) = crate::sceau::lire_sans_ecrire(&dossier, &nom_de_la_demande(lieu)) else {
        return false;
    };
    let Some(quand) = std::str::from_utf8(&o).ok().and_then(|t| t.trim().parse::<u64>().ok()) else {
        return false;
    };
    let ici = maintenant();
    quand <= ici.saturating_add(MARGE_HORLOGE) && ici.saturating_sub(quand) < PLANCHER.as_secs()
}

/// Note, scellée, la redemande d'une copie refusée. Une note qui ne s'écrit pas ne coûte qu'une demande de plus.
fn noter_redemande(lieu: (&str, &str)) {
    let _ = crate::sceau::ecrire_dans(
        &super::dossier_local(),
        &nom_de_la_demande(lieu),
        maintenant().to_string().as_bytes(),
    );
}

/// Les tests : une copie scellée vieillie de `age` (son sceau réécrit par Vanguard, comme s'il l'avait téléchargée
/// alors).
#[cfg(test)]
pub(crate) fn vieillir_pour_essai(lieu: (&str, &str), age: Duration) {
    let dossier = super::dossier_local();
    let octets = std::fs::read(dossier.join(lieu.0).join(lieu.1)).unwrap();
    let sceau = Sceau {
        telecharge: maintenant() - age.as_secs(),
        taille: octets.len() as u64,
        empreinte: empreinte(&octets),
    };
    crate::sceau::ecrire_dans(&dossier, &nom_du_sceau(lieu), &serde_json::to_vec(&sceau).unwrap()).unwrap();
}

/// Une adresse vers cette machine, dans les tests seulement (le petit serveur local, `http::permise`) : rien ne sort
/// de l'ordinateur, la suite refaite sans Internet (`VANGUARD_HORS_LIGNE=1`) peut donc encore s'en servir.
fn vers_cette_machine(adresse: &str) -> bool {
    cfg!(test) && adresse.starts_with("http://127.0.0.1:")
}

/// `liste`, pour un `valide` qui a besoin de son contexte (une fermeture : les versions des logiciels jugent chaque
/// source par son propre lecteur).
pub(crate) fn liste_validee(
    demande: crate::http::Demande,
    lieu: (&str, &str),
    fraiche: Duration,
    valide: &dyn Fn(&[u8]) -> bool,
) -> Liste {
    let hors_ligne = crate::parametres::hors_ligne() && !vers_cette_machine(demande.adresse);
    liste_selon(hors_ligne, demande, lieu, fraiche, valide)
}

/// `liste_validee`, le travail sans Internet donné (`hors_ligne` : rien ne part).
fn liste_selon(
    hors_ligne: bool,
    demande: crate::http::Demande,
    lieu: (&str, &str),
    fraiche: Duration,
    valide: &dyn Fn(&[u8]) -> bool,
) -> Liste {
    // Le sceau seul d'abord : une copie à redemander n'est lue (parfois des centaines de Mio) que si la demande échoue.
    let sceau = sceau_de(lieu);
    let mut refusee = gardee_sans_lire(&sceau, lieu);
    if let Ok(Some(s)) = &sceau
        && age_de(s) < fraiche
    {
        // Changée depuis son sceau, elle n'est pas rendue ici : redemandée, comme une copie trop vieille.
        match gardee(lieu, LISTE_MAX) {
            Ok(Some(copie)) => {
                return Liste {
                    copie: Some(copie),
                    code: None,
                    manque: None,
                };
            }
            Ok(None) => {}
            Err(refus) => refusee = Some(refus),
        }
    }
    let (mut code, mut copie) = (None, None);
    let mut manque;
    let mut redemande = Redemande::Ecriture;
    if hors_ligne {
        manque = Some(Echec::HorsLigne);
        redemande = Redemande::HorsLigne;
    } else if refusee.is_some() && redemandee_recemment(lieu) {
        manque = Some(Echec::SansReponse);
        redemande = Redemande::Attente;
    } else if std::fs::create_dir_all(super::dossier_local().join(lieu.0)).is_ok() {
        if refusee.is_some() {
            noter_redemande(lieu);
        }
        let reponse = crate::http::envoyer(demande);
        code = reponse.as_ref().map(|r| r.code);
        (manque, redemande) = match reponse {
            Some(r) if r.code == 200 && !valide(&r.corps) => (Some(Echec::Illisible), Redemande::Reponse(200)),
            // L'écriture atomique du socle, et non un renommage fait ici : sous Windows, Defender qui analyse
            // l'ancienne copie faisait échouer le renommage, et la liste gardait sa vieille copie. Non gardée, la
            // réponse sert quand même cette fois-ci : c'est la liste, reçue à l'instant.
            Some(r) if r.code == 200 => {
                let garde = garder(lieu, &r.corps);
                if garde.is_ok() {
                    // Remplacée : un refus à venir repart sans attente.
                    let _ = crate::sceau::effacer_dans(&super::dossier_local(), &nom_de_la_demande(lieu));
                }
                copie = Some((r.corps, Duration::ZERO));
                (garde.err().map(|_| Echec::Ecriture), Redemande::Ecriture)
            }
            Some(r) => (Some(Echec::Reponse(r.code)), Redemande::Reponse(r.code)),
            None => (Some(Echec::SansReponse), Redemande::SansReponse),
        };
    } else {
        manque = Some(Echec::Ecriture);
    }
    if copie.is_none() {
        match gardee(lieu, LISTE_MAX) {
            Ok(gardee) => copie = gardee,
            // Refusée et pas remplacée : la liste n'est pas vérifiée, et la raison dit pourquoi la copie ne sert pas
            // (une réponse qui n'est pas la liste reste dite illisible).
            Err(refus) if manque != Some(Echec::Illisible) => {
                manque = Some(Echec::CopieRefusee(refus, redemande));
            }
            Err(_) => {}
        }
    }
    Liste { copie, code, manque }
}

/// Le refus de la copie gardée d'après son sceau, sans lire la copie (`Some` : refusée). Une copie absente sous un
/// sceau intact compte aussi (`Effacee`).
fn gardee_sans_lire(sceau: &Result<Option<Sceau>, Refus>, lieu: (&str, &str)) -> Option<Refus> {
    match sceau {
        Err(r) => Some(*r),
        Ok(None) => None,
        Ok(Some(_)) => {
            let fichier = super::dossier_local().join(lieu.0).join(lieu.1);
            let ordinaire = std::fs::symlink_metadata(fichier).is_ok_and(|m| m.file_type().is_file());
            (!ordinaire).then_some(Refus::Effacee)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// Un serveur local qui répond `reponse` à une seule demande.
    fn serveur(reponse: &'static [u8]) -> (String, std::thread::JoinHandle<()>) {
        let ecoute = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let adresse = format!("http://{}/liste.txt", ecoute.local_addr().unwrap());
        let fil = std::thread::spawn(move || {
            let (mut prise, _) = ecoute.accept().unwrap();
            prise.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut recu = vec![0u8; 4096];
            let _ = prise.read(&mut recu);
            let _ = prise.write_all(reponse);
        });
        (adresse, fil)
    }

    /// Une adresse où personne n'écoute : pas de réponse, comme sans Internet.
    fn personne() -> String {
        let libre = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        format!("http://{libre}/liste.txt")
    }

    fn demande(adresse: &str) -> crate::http::Demande<'_> {
        crate::http::Demande::get(adresse, Duration::from_secs(5))
    }

    fn propre(lieu: (&str, &str)) {
        let _ = std::fs::remove_dir_all(super::super::dossier_local().join(lieu.0));
    }

    /// Personne ne doit s'être connecté à `ecoute` (rien n'est parti).
    fn rien_recu(ecoute: &std::net::TcpListener) {
        ecoute.set_nonblocking(true).unwrap();
        assert!(
            matches!(ecoute.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "une demande est partie"
        );
    }

    /// La date de la dernière redemande oubliée : la suite d'un test redemande tout de suite.
    fn sans_plancher(lieu: (&str, &str)) {
        crate::sceau::effacer_dans(&super::super::dossier_local(), &nom_de_la_demande(lieu)).unwrap();
    }

    /// La copie gardée vaut ce que dit son sceau, jamais la date du fichier : vidée, posée sans sceau, effacée sous son
    /// sceau, son sceau effacé ou réécrit à côté, datée dans le futur, elle est refusée (jamais une liste vide, donc
    /// vérifiée).
    #[test]
    fn copie_forgee_refusee() {
        let lieu = ("essai-cache-forge", "liste.txt");
        propre(lieu);
        let dossier = super::super::dossier_local();
        let fichier = dossier.join(lieu.0).join(lieu.1);
        assert_eq!(gardee(lieu, LISTE_MAX), Ok(None));
        garder(lieu, b"# liste\n1.2.3.4\n").unwrap();
        let (octets, age) = gardee(lieu, LISTE_MAX).unwrap().unwrap();
        assert_eq!(octets, b"# liste\n1.2.3.4\n");
        assert!(age < Duration::from_mins(1));
        assert!(super::age(lieu).is_some_and(|a| a < Duration::from_mins(1)));
        // Vidée par un autre programme, et le fichier daté dans le futur : refusée, la date du fichier ne compte pas.
        std::fs::write(&fichier, b"# liste\n").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&fichier)
            .unwrap()
            .set_modified(SystemTime::now() + Duration::from_hours(24 * 3650))
            .unwrap();
        assert_eq!(gardee(lieu, LISTE_MAX), Err(Refus::HorsVanguard));
        // Effacée sous son sceau intact (la liste complète de MalwareBazaar réduisait sinon l'antivirus aux 48 h) :
        // refusée, jamais « pas encore de copie ».
        garder(lieu, b"# liste\n1.2.3.4\n").unwrap();
        std::fs::remove_file(&fichier).unwrap();
        assert_eq!(gardee(lieu, LISTE_MAX), Err(Refus::Effacee));
        // Remplacée par un lien (ou un dossier) : de même.
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/dev/zero", &fichier).unwrap();
            assert_eq!(gardee(lieu, LISTE_MAX), Err(Refus::Effacee));
            std::fs::remove_file(&fichier).unwrap();
        }
        std::fs::create_dir(&fichier).unwrap();
        assert_eq!(gardee(lieu, LISTE_MAX), Err(Refus::Effacee));
        std::fs::remove_dir(&fichier).unwrap();
        std::fs::write(&fichier, b"# liste\n").unwrap();
        // Le sceau réécrit à côté, avec l'empreinte de la liste vidée et une date lointaine : refusé aussi.
        let forge = Sceau {
            telecharge: maintenant() + 1_000_000,
            taille: 8,
            empreinte: empreinte(b"# liste\n"),
        };
        std::fs::write(dossier.join(nom_du_sceau(lieu)), serde_json::to_vec(&forge).unwrap()).unwrap();
        assert_eq!(gardee(lieu, LISTE_MAX), Err(Refus::HorsVanguard));
        // Daté dans le futur par Vanguard lui-même (une horloge reculée depuis) : périmée, jamais fraîche à jamais,
        // et la raison parle de l'horloge, pas seulement d'une falsification.
        crate::sceau::ecrire_dans(&dossier, &nom_du_sceau(lieu), &serde_json::to_vec(&forge).unwrap()).unwrap();
        assert_eq!(gardee(lieu, LISTE_MAX), Err(Refus::DateFuture));
        assert!(Refus::DateFuture.raison().contains(tr!("horloge", "clock")));
        // Quelques minutes d'avance seulement (une horloge resynchronisée) : la copie sert, âge zéro.
        let proche = Sceau {
            telecharge: maintenant() + 120,
            ..forge
        };
        crate::sceau::ecrire_dans(&dossier, &nom_du_sceau(lieu), &serde_json::to_vec(&proche).unwrap()).unwrap();
        assert_eq!(
            gardee(lieu, LISTE_MAX),
            Ok(Some((b"# liste\n".to_vec(), Duration::ZERO)))
        );
        // Son sceau effacé (le fichier, puis son empreinte dans les sceaux) : sans date sûre, refusée.
        std::fs::remove_file(dossier.join(nom_du_sceau(lieu))).unwrap();
        assert_eq!(gardee(lieu, LISTE_MAX), Err(Refus::HorsVanguard));
        crate::sceau::effacer_dans(&dossier, &nom_du_sceau(lieu)).unwrap();
        assert_eq!(gardee(lieu, LISTE_MAX), Err(Refus::SansSceau));
        // Chaque refus se dit, sans promettre de téléchargement.
        for r in [
            Refus::SansSceau,
            Refus::HorsVanguard,
            Refus::Effacee,
            Refus::Adoptee,
            Refus::DateFuture,
        ] {
            assert!(!r.raison().is_empty() && r.texte().contains(r.raison()));
        }
        propre(lieu);
    }

    /// Oublier une copie retire la copie et son sceau : ensuite, aucune copie (un premier téléchargement), jamais une
    /// copie « effacée hors de Vanguard ».
    #[test]
    fn oublier_retire_la_copie_et_son_sceau() {
        let lieu = ("essai-cache-oubli", "api.json");
        propre(lieu);
        garder(lieu, b"{}").unwrap();
        oublier(lieu).unwrap();
        assert_eq!(gardee(lieu, LISTE_MAX), Ok(None));
        // Déjà oubliée : rien à dire.
        oublier(lieu).unwrap();
        propre(lieu);
    }

    /// Une copie refusée est périmée, quel que soit son âge : redemandée ; sans réponse, la liste n'est pas
    /// vérifiée et la raison le dit. Remplacée par une vraie réponse, elle sert de nouveau, scellée.
    #[test]
    fn copie_refusee_redemandee_sinon_non_verifiee() {
        let lieu = ("essai-cache-refusee", "liste.txt");
        propre(lieu);
        let fichier = super::super::dossier_local().join(lieu.0).join(lieu.1);
        let jour = Duration::from_hours(24);
        // Fraîche et scellée : rien n'est demandé (personne n'écoute), la copie sert.
        garder(lieu, b"# liste\n1.2.3.4\n").unwrap();
        let l = liste(demande(&personne()), lieu, jour, |_| true);
        assert_eq!((l.code, l.manque), (None, None));
        assert_eq!(l.copie.map(|c| c.0), Some(b"# liste\n1.2.3.4\n".to_vec()));
        // Vidée par un autre programme (sous son sceau encore frais) : redemandée ; sans réponse, aucune copie, et la
        // raison le dit.
        std::fs::write(&fichier, b"# liste\n").unwrap();
        let l = liste(demande(&personne()), lieu, jour, |_| true);
        assert!(l.copie.is_none());
        assert_eq!(
            l.manque,
            Some(Echec::CopieRefusee(Refus::HorsVanguard, Redemande::SansReponse))
        );
        let raison = l.resultat(false).unwrap_err().raison();
        assert!(raison.contains(Refus::HorsVanguard.raison()), "{raison}");
        // Une réponse refusée par le serveur : le code est dit avec le refus.
        sans_plancher(lieu);
        let (adresse, fil) =
            serveur(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let l = liste(demande(&adresse), lieu, jour, |_| true);
        fil.join().unwrap();
        assert_eq!(
            l.resultat(false),
            Err(Echec::CopieRefusee(Refus::HorsVanguard, Redemande::Reponse(503)))
        );
        // La vraie liste reçue : elle remplace la copie refusée, scellée, et sert.
        sans_plancher(lieu);
        let (adresse, fil) =
            serveur(b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\n# liste\n5.6.7.8\n");
        let l = liste(demande(&adresse), lieu, jour, |_| true);
        fil.join().unwrap();
        assert_eq!(l.manque, None);
        assert_eq!(l.copie.map(|c| c.0), Some(b"# liste\n5.6.7.8\n".to_vec()));
        assert_eq!(gardee(lieu, LISTE_MAX).unwrap().unwrap().0, b"# liste\n5.6.7.8\n");
        // Vieillie (d'après son sceau) puis sans réponse : la copie d'avant sert, avec son âge, et le manque est dit.
        vieillir_pour_essai(lieu, jour * 2);
        let l = liste(demande(&personne()), lieu, jour, |_| true);
        assert_eq!(l.manque, Some(Echec::SansReponse));
        assert!(l.copie.is_some_and(|(_, age)| age >= jour * 2));
        propre(lieu);
    }

    /// Sans Internet (`VANGUARD_HORS_LIGNE`, le réglage) : rien ne part, même pour une copie sans sceau d'une version
    /// d'avant ; la copie scellée sert avec son âge, la copie refusée n'est pas vérifiée, et la raison le dit.
    #[test]
    fn hors_ligne_rien_ne_part() {
        let lieu = ("essai-cache-hors-ligne", "liste.txt");
        propre(lieu);
        let ecoute = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let adresse = format!("http://{}/liste.txt", ecoute.local_addr().unwrap());
        let jour = Duration::from_hours(24);
        // Aucune copie : la raison est le travail sans Internet, pas « pas de réponse ».
        let l = liste_selon(true, demande(&adresse), lieu, jour, &|_| true);
        assert_eq!(l.resultat(false), Err(Echec::HorsLigne));
        // Une copie scellée, vieille : elle sert, son âge et le manque dits.
        garder(lieu, b"# liste\n").unwrap();
        vieillir_pour_essai(lieu, jour * 2);
        let l = liste_selon(true, demande(&adresse), lieu, jour, &|_| true);
        assert_eq!(l.manque, Some(Echec::HorsLigne));
        assert!(l.copie.is_some_and(|(_, age)| age >= jour * 2));
        // Une copie d'une version d'avant, sans sceau : refusée, rien ne part, non vérifiée.
        crate::sceau::effacer_dans(&super::super::dossier_local(), &nom_du_sceau(lieu)).unwrap();
        let l = liste_selon(true, demande(&adresse), lieu, jour, &|_| true);
        let echec = l.resultat(false).unwrap_err();
        assert_eq!(echec, Echec::CopieRefusee(Refus::SansSceau, Redemande::HorsLigne));
        assert_ne!(echec.raison(), "");
        rien_recu(&ecoute);
        propre(lieu);
    }

    /// Une copie refusée n'est pas redemandée plus d'une fois par quart d'heure : un programme qui la touche avant
    /// chaque passe ne fait pas partir une demande (avec la clé de la personne) à chaque fois. Toujours non vérifiée.
    #[test]
    fn copie_refusee_pas_redemandee_sans_cesse() {
        let lieu = ("essai-cache-plancher", "liste.txt");
        propre(lieu);
        let jour = Duration::from_hours(24);
        garder(lieu, b"# liste\n1.2.3.4\n").unwrap();
        std::fs::write(super::super::dossier_local().join(lieu.0).join(lieu.1), b"# liste\n").unwrap();
        let l = liste(demande(&personne()), lieu, jour, |_| true);
        assert_eq!(
            l.manque,
            Some(Echec::CopieRefusee(Refus::HorsVanguard, Redemande::SansReponse))
        );
        let ecoute = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let adresse = format!("http://{}/liste.txt", ecoute.local_addr().unwrap());
        let l = liste(demande(&adresse), lieu, jour, |_| true);
        assert_eq!(
            l.resultat(false),
            Err(Echec::CopieRefusee(Refus::HorsVanguard, Redemande::Attente))
        );
        rien_recu(&ecoute);
        // La date de la redemande effacée hors de Vanguard : elle ne retient plus rien, la demande repart.
        sans_plancher(lieu);
        let l = liste(demande(&personne()), lieu, jour, |_| true);
        assert!(matches!(l.manque, Some(Echec::CopieRefusee(_, Redemande::SansReponse))));
        propre(lieu);
    }
}

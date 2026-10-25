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
    /// La copie gardée ne peut pas être crue (`Refus`), et la redemande n'a rien donné : le code de la réponse, ou
    /// `None` sans réponse.
    CopieRefusee(Refus, Option<u16>),
}

/// Pourquoi une copie gardée ne peut pas être crue : elle est alors périmée, quel que soit son âge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refus {
    /// Pas de date de téléchargement scellée : la copie d'une version d'avant, ou son sceau effacé.
    SansSceau,
    /// Elle, ou son sceau, changés hors de Vanguard (ou illisibles).
    HorsVanguard,
    /// Son sceau a été accepté tel quel après des sceaux refaits : rien ne prouve qui l'a écrit.
    Adoptee,
    /// Datée dans le futur : elle ne vieillirait jamais.
    DateFuture,
}

impl Refus {
    /// La raison, prête à suivre « copie gardée refusée : ».
    pub(crate) fn raison(self) -> &'static str {
        match self {
            Refus::SansSceau => tr!(
                "sans date de téléchargement scellée (copie d'une version d'avant, ou sceau effacé)",
                "no sealed download date (a copy from an earlier version, or its seal deleted)"
            ),
            Refus::HorsVanguard => tr!("changée hors de Vanguard", "changed outside Vanguard"),
            Refus::Adoptee => tr!(
                "acceptée telle quelle après des sceaux refaits",
                "accepted as it was after seals were remade"
            ),
            Refus::DateFuture => tr!("datée dans le futur", "dated in the future"),
        }
    }

    /// Ce que dit une liste qui ne sert pas parce que sa copie gardée est refusée.
    pub(crate) fn texte(self) -> String {
        trf!(
            "copie gardée refusée ({}) : redemandée au prochain téléchargement",
            "kept copy refused ({}): asked again at the next download",
            self.raison()
        )
    }
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
            (None, _) if let Some(refus @ Echec::CopieRefusee(..)) = self.manque => Err(refus),
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
/// pilotes vulnérables (LOLDrivers) et les versions des logiciels.
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
/// copie : sans date scellée, elle ne vaut rien.
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
        Lecture::Falsifie(_) | Lecture::Illisible(_) => return Err(Refus::HorsVanguard),
    };
    let sceau: Sceau = serde_json::from_slice(&octets).map_err(|_| Refus::HorsVanguard)?;
    if sceau.telecharge > maintenant() {
        return Err(Refus::DateFuture);
    }
    Ok(Some(sceau))
}

/// L'âge d'une copie d'après son sceau (jamais la date du fichier, que tout programme du compte change).
fn age_de(sceau: &Sceau) -> Duration {
    Duration::from_secs(maintenant().saturating_sub(sceau.telecharge))
}

/// La copie gardée de `lieu` (sous-dossier, nom), `max` octets au plus, et son âge d'après son sceau : `Ok(None)` s'il
/// n'y en a pas, `Err` si elle ne peut pas être crue (sans sceau, changée, acceptée telle quelle après des sceaux
/// refaits, datée dans le futur). Pour qui relit une liste sans la demander (le veilleur, le bilan, hors ligne) :
/// une copie refusée n'est jamais une liste vide, donc vérifiée.
pub(crate) fn gardee(lieu: (&str, &str), max: u64) -> Result<Option<(Vec<u8>, Duration)>, Refus> {
    let Some(sceau) = sceau_de(lieu)? else {
        return Ok(None);
    };
    let fichier = super::dossier_local().join(lieu.0).join(lieu.1);
    // Un simple fichier, borné : un tube ou un lien vers /dev/zero posé à sa place ne fige ni ne remplit rien.
    let Ok(octets) = super::lire_ordinaire(&fichier, max) else {
        return Ok(None);
    };
    if octets.len() as u64 != sceau.taille || empreinte(&octets) != sceau.empreinte {
        return Err(Refus::HorsVanguard);
    }
    Ok(Some((octets, age_de(&sceau))))
}

/// Garde `octets` comme copie de `lieu`, scellée avec la date d'aujourd'hui : la copie d'abord, puis son sceau. Entre
/// les deux, ou si le sceau ne s'écrit pas, la copie se lit refusée : périmée, jamais crue.
pub(crate) fn garder(lieu: (&str, &str), octets: &[u8]) -> std::io::Result<()> {
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

/// `liste`, pour un `valide` qui a besoin de son contexte (une fermeture : les versions des logiciels jugent chaque
/// source par son propre lecteur).
pub(crate) fn liste_validee(
    demande: crate::http::Demande,
    lieu: (&str, &str),
    fraiche: Duration,
    valide: &dyn Fn(&[u8]) -> bool,
) -> Liste {
    // Le sceau seul d'abord : une copie à redemander n'est lue (parfois des centaines de Mio) que si la demande échoue.
    let sceau = sceau_de(lieu);
    if let Ok(Some(s)) = &sceau
        && age_de(s) < fraiche
    {
        // Changée depuis son sceau, elle n'est pas rendue ici : redemandée, comme une copie trop vieille.
        if let Ok(Some(copie)) = gardee(lieu, LISTE_MAX) {
            return Liste {
                copie: Some(copie),
                code: None,
                manque: None,
            };
        }
    }
    let dossier = super::dossier_local().join(lieu.0);
    let (mut code, mut manque, mut copie) = (None, Some(Echec::Ecriture), None);
    if std::fs::create_dir_all(&dossier).is_ok() {
        let reponse = crate::http::envoyer(demande);
        code = reponse.as_ref().map(|r| r.code);
        manque = match reponse {
            Some(r) if r.code == 200 && !valide(&r.corps) => Some(Echec::Illisible),
            // L'écriture atomique du socle, et non un renommage fait ici : sous Windows, Defender qui analyse
            // l'ancienne copie faisait échouer le renommage, et la liste gardait sa vieille copie. Non gardée, la
            // réponse sert quand même cette fois-ci : c'est la liste, reçue à l'instant.
            Some(r) if r.code == 200 => {
                let garde = garder(lieu, &r.corps);
                copie = Some((r.corps, Duration::ZERO));
                garde.err().map(|_| Echec::Ecriture)
            }
            Some(r) => Some(Echec::Reponse(r.code)),
            None => Some(Echec::SansReponse),
        };
    }
    if copie.is_none() {
        match gardee(lieu, LISTE_MAX) {
            Ok(gardee) => copie = gardee,
            // Refusée et pas remplacée : la liste n'est pas vérifiée, et la raison dit pourquoi la copie ne sert pas.
            Err(refus) if matches!(manque, Some(Echec::Reponse(_) | Echec::SansReponse | Echec::Ecriture)) => {
                manque = Some(Echec::CopieRefusee(refus, code));
            }
            Err(_) => {}
        }
    }
    Liste { copie, code, manque }
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

    /// La copie gardée vaut ce que dit son sceau, jamais la date du fichier : vidée, posée sans sceau, son sceau
    /// effacé ou réécrit à côté, datée dans le futur, elle est refusée (jamais une liste vide, donc vérifiée).
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
        // Vidée par un autre programme, et le fichier daté dans le futur : refusée, la date du fichier ne compte pas.
        std::fs::write(&fichier, b"# liste\n").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&fichier)
            .unwrap()
            .set_modified(SystemTime::now() + Duration::from_hours(24 * 3650))
            .unwrap();
        assert_eq!(gardee(lieu, LISTE_MAX), Err(Refus::HorsVanguard));
        // Le sceau réécrit à côté, avec l'empreinte de la liste vidée et une date lointaine : refusé aussi.
        let forge = Sceau {
            telecharge: maintenant() + 1_000_000,
            taille: 8,
            empreinte: empreinte(b"# liste\n"),
        };
        std::fs::write(dossier.join(nom_du_sceau(lieu)), serde_json::to_vec(&forge).unwrap()).unwrap();
        assert_eq!(gardee(lieu, LISTE_MAX), Err(Refus::HorsVanguard));
        // Daté dans le futur par Vanguard lui-même (une horloge reculée depuis) : périmée, jamais fraîche à jamais.
        crate::sceau::ecrire_dans(&dossier, &nom_du_sceau(lieu), &serde_json::to_vec(&forge).unwrap()).unwrap();
        assert_eq!(gardee(lieu, LISTE_MAX), Err(Refus::DateFuture));
        // Son sceau effacé (le fichier, puis son empreinte dans les sceaux) : sans date scellée, refusée.
        std::fs::remove_file(dossier.join(nom_du_sceau(lieu))).unwrap();
        assert_eq!(gardee(lieu, LISTE_MAX), Err(Refus::HorsVanguard));
        crate::sceau::effacer_dans(&dossier, &nom_du_sceau(lieu)).unwrap();
        assert_eq!(gardee(lieu, LISTE_MAX), Err(Refus::SansSceau));
        // Chaque refus se dit.
        for r in [Refus::SansSceau, Refus::HorsVanguard, Refus::Adoptee, Refus::DateFuture] {
            assert!(!r.raison().is_empty() && r.texte().contains(r.raison()));
        }
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
        // Vidée et datée dans le futur : redemandée ; sans réponse, aucune copie, et la raison le dit.
        std::fs::write(&fichier, b"# liste\n").unwrap();
        let l = liste(demande(&personne()), lieu, jour, |_| true);
        assert!(l.copie.is_none());
        assert_eq!(l.manque, Some(Echec::CopieRefusee(Refus::HorsVanguard, None)));
        let raison = l.resultat(false).unwrap_err().raison();
        assert!(raison.contains(Refus::HorsVanguard.raison()), "{raison}");
        // Une réponse refusée par le serveur : le code est dit avec le refus.
        let (adresse, fil) =
            serveur(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let l = liste(demande(&adresse), lieu, jour, |_| true);
        fil.join().unwrap();
        assert_eq!(
            l.resultat(false),
            Err(Echec::CopieRefusee(Refus::HorsVanguard, Some(503)))
        );
        // La vraie liste reçue : elle remplace la copie refusée, scellée, et sert.
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
}

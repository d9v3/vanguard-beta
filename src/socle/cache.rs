//! Le cache des listes téléchargées (menaces d'abuse.ch, catalogue de la CISA, Échap, pilotes vulnérables,
//! versions des logiciels) : une copie gardée dans le dossier de Vanguard, redemandée quand elle a vieilli, jamais
//! remplacée par une réponse qui n'est pas la liste. Les mots qui disent un échec restent chez abuse.ch
//! (`protection::abuse_ch`), qui les a écrits pour ses listes ; chaque autre source dit les siens.

use std::time::Duration;

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

/// `liste`, pour un `valide` qui a besoin de son contexte (une fermeture : les versions des logiciels jugent chaque
/// source par son propre lecteur).
pub(crate) fn liste_validee(
    demande: crate::http::Demande,
    (sous_dossier, nom): (&str, &str),
    fraiche: Duration,
    valide: &dyn Fn(&[u8]) -> bool,
) -> Liste {
    let dossier = super::dossier_local().join(sous_dossier);
    let fichier = dossier.join(nom);
    // L'âge du fichier lui-même, jamais d'une cible de lien (qui ne serait de toute façon pas lue).
    let age = || {
        std::fs::symlink_metadata(&fichier)
            .and_then(|m| m.modified())
            .ok()
            .map(|t| t.elapsed().unwrap_or_default())
    };
    let (mut code, mut manque) = (None, None);
    if age().is_none_or(|d| d >= fraiche) {
        manque = Some(Echec::Ecriture);
        if std::fs::create_dir_all(&dossier).is_ok() {
            let reponse = crate::http::envoyer(demande);
            code = reponse.as_ref().map(|r| r.code);
            manque = match reponse {
                Some(r) if r.code == 200 && !valide(&r.corps) => Some(Echec::Illisible),
                // L'écriture atomique du socle, et non un renommage fait ici : sous Windows, Defender qui analyse
                // l'ancienne copie faisait échouer le renommage, et la liste gardait sa vieille copie.
                Some(r) if r.code == 200 => super::ecrire_atomique(&fichier, &r.corps)
                    .err()
                    .map(|_| Echec::Ecriture),
                Some(r) => Some(Echec::Reponse(r.code)),
                None => Some(Echec::SansReponse),
            };
        }
    }
    Liste {
        // Un simple fichier, borné : un tube ou un lien vers /dev/zero posé à sa place ne fige ni ne remplit rien.
        copie: super::lire_ordinaire(&fichier, LISTE_MAX).ok().zip(age()),
        code,
        manque,
    }
}

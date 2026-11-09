//! Le temps réel des fichiers (Linux) : la suite d'un fichier que le veilleur vient d'examiner, par les gestes et
//! les réglages du blocage, comme la passe horaire sur Téléchargements (`menaces::telecharges`). Certain : mis en
//! quarantaine tout seul si la protection active le permet (annulable, `vanguard blocage annuler`) ; Famille, ou
//! Certain sans l'automatique : une notification qui mène au geste en un clic (`vanguard alerte <id>`) ; Suspect : une
//! alerte, sans geste. Le veilleur décide du débit des notifications ; rien n'est relu ici du disque, sauf
//! l'empreinte du fichier juste avant sa quarantaine.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::gestes::{self, Contexte};
use super::menaces::{self, Menace};
use super::parametres::{Categorie, Decision, decider};
use crate::protection::moteur::{self, Resultat, Verdict};
use crate::protection::quarantaine::Identite;
use crate::reseau::tableau::Genre;
use crate::{tr, trf};

/// La taille au-delà de laquelle l'empreinte relue avant la quarantaine n'est pas calculée : celle des fichiers que le
/// veilleur examine.
pub(crate) const TAILLE_MAX: u64 = 64 << 20;
/// Le temps du moteur pour rejuger un fichier depuis son alerte.
const DELAI: Duration = Duration::from_secs(15);

/// Ce que devient un fichier examiné en direct.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Suite {
    /// Sain, ou un contenu auquel la personne a fait confiance (P5) : rien.
    Rien,
    /// Rien trouvé, mais une partie ou une source manquait : compté et dit, jamais sain.
    NonVerifie,
    /// Suspect (heuristiques seules) : une alerte, aucun geste.
    Alerte,
    /// Famille, ou certain sans l'automatique (ou que la personne vient de sortir de la quarantaine) : la notification
    /// mène au geste en un clic.
    UnClic,
    /// Certain, protection active en automatique : quarantaine toute seule, annulable.
    Quarantaine,
}

/// Pur. `auto` : la catégorie Programmes en automatique avec l'accord, Vanguard ni administrateur ni en coupure du
/// temps réel (`pour_agir`) ; `remise` : la personne a sorti ce même contenu de la quarantaine (il n'y retourne pas
/// tout seul, sans quoi l'annulation serait défaite dans la seconde) ; `confiance` : elle lui a fait confiance (P5).
pub(crate) fn suite_de(verdict: &Verdict, auto: bool, remise: bool, confiance: bool) -> Suite {
    match verdict {
        Verdict::Certain(..) if confiance => Suite::Rien,
        Verdict::Certain(..) if auto && !remise => Suite::Quarantaine,
        Verdict::Certain(..) | Verdict::Famille(..) => Suite::UnClic,
        Verdict::Suspect(_) => Suite::Alerte,
        Verdict::NonVerifie(_) => Suite::NonVerifie,
        Verdict::Sain => Suite::Rien,
    }
}

/// Ce que la suite a fait, pour les compteurs du veilleur.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Fait {
    pub suite: Suite,
    /// Le fichier est en quarantaine.
    pub isole: bool,
}

/// Ce que le débit du veilleur permet de dire d'une menace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Annonce {
    /// Notée au journal et notifiée.
    Notifier,
    /// Notée au journal seulement.
    Noter,
    /// Déjà dite (même contenu, même chemin) ou au-delà du débit : seule une quarantaine a lieu encore (un geste qui
    /// protège, noté par le blocage) ; une alerte ou un clic ne se redisent pas.
    Taire,
}

/// La suite du fichier `chemin`, arrivé dans `ou` (le dossier, prêt à montrer), d'après `r`, selon `annonce`.
/// `identite` : celle du fichier lu à l'examen ; sa quarantaine n'isole que lui.
pub(crate) fn fichier_en_direct(
    chemin: &Path,
    ou: &str,
    r: &Resultat,
    annonce: Annonce,
    identite: Option<Identite>,
) -> Fait {
    let notifier = annonce == Annonce::Notifier;
    let verdict = r.verdict();
    let Some(m) = menaces::menace_du_fichier(chemin.to_path_buf(), r, ou) else {
        return Fait {
            suite: suite_de(&verdict, false, false, false),
            isole: false,
        };
    };
    let p = super::pour_agir(
        super::parametres_tus(),
        gestes::administrateur_ou_inconnu() || crate::protection::temps_reel::coupure().is_some(),
    );
    let auto = decider(&p, Categorie::Programmes, true) == Decision::Auto;
    let hex = r.sha256.as_ref().map(crate::protection::empreintes::hex);
    let remise = hex
        .as_deref()
        .is_some_and(|h| crate::changements::quarantaine_remise(&m.cle, h));
    let confiance = r.sha256.as_ref().is_some_and(super::confiance_accordee);
    // La personne a sorti ce contenu exact de la quarantaine (clé posée à la remise) : rien n'est redit ni refait,
    // comme à la passe horaire ; un autre contenu sous ce nom a une autre clé et se juge de nouveau.
    let sorti = r
        .sha256
        .as_ref()
        .and_then(|e| m.cle_remise_avec(e))
        .is_some_and(|c| crate::protection::normales::est_normale(&c));
    let suite = if sorti {
        Suite::Rien
    } else {
        suite_de(&verdict, auto, remise, confiance)
    };
    let mut isole = false;
    if annonce == Annonce::Taire && suite != Suite::Quarantaine {
        return Fait { suite, isole };
    }
    match suite {
        Suite::Quarantaine => {
            // Le contenu a changé depuis l'examen, ou ne se relit plus : rien n'est isolé sur la foi d'un autre
            // contenu (un fichier de la personne glissé au même nom) ; sa nouvelle écriture le ramène dans la file.
            // Un autre inode sous ce nom (un lien dur vers un fichier de la personne) : pareil.
            if !meme_contenu(chemin, hex.as_deref()) || !toujours_le_meme(chemin, identite.as_ref()) {
                return Fait {
                    suite: Suite::NonVerifie,
                    isole: false,
                };
            }
            let mut ctx = Contexte::lire(HashSet::new(), false);
            ctx.examine = identite.map(|i| (chemin.to_path_buf(), i));
            isole = super::bloquer_tout_seul(&m, &ctx, &p, None, notifier);
            // La quarantaine a refusé un autre fichier glissé sous ce nom : ce qui est là n'a pas été examiné.
            if !isole && !toujours_le_meme(chemin, identite.as_ref()) {
                return Fait {
                    suite: Suite::NonVerifie,
                    isole: false,
                };
            }
        }
        Suite::UnClic => {
            let texte = if remise {
                trf!(
                    "{} Vous l'avez sorti de la quarantaine : Vanguard ne l'y remet pas tout seul.",
                    "{} You took it out of quarantine: Vanguard does not put it back by itself.",
                    m.quoi
                )
            } else {
                m.quoi.clone()
            };
            super::alerter_blocage_avec(
                &m,
                tr!(
                    "Vanguard : fichier dangereux reconnu",
                    "Vanguard: dangerous file recognized"
                ),
                &texte,
                notifier,
            );
        }
        Suite::Alerte => alerter_suspect(&m, notifier),
        Suite::Rien | Suite::NonVerifie => {}
    }
    Fait { suite, isole }
}

/// Le fichier a-t-il encore le contenu examiné ? Relu sans attendre (un tube glissé à sa place), fichier ordinaire
/// seulement.
fn meme_contenu(chemin: &Path, attendu: Option<&str>) -> bool {
    let Some(attendu) = attendu else {
        return false;
    };
    matches!(
        crate::traces::empreinte(chemin, TAILLE_MAX),
        crate::traces::Empreinte::Sha256(h) if h.eq_ignore_ascii_case(attendu)
    )
}

/// Le nom porte-t-il encore le fichier examiné (même inode) ? Sans identité (hors du temps réel), rien à comparer.
fn toujours_le_meme(chemin: &Path, identite: Option<&Identite>) -> bool {
    #[cfg(unix)]
    {
        identite.is_none_or(|i| std::fs::symlink_metadata(chemin).is_ok_and(|m| Identite::de(&m).meme_fichier(i)))
    }
    #[cfg(not(unix))]
    {
        let _ = (chemin, identite);
        true
    }
}

/// Un suspect : noté au journal (relié à sa clé, pour « c'est normal ici ») et notifié, sans geste ni lien vers un
/// geste. Une alerte déclarée normale se tait.
fn alerter_suspect(m: &Menace, notifier: bool) {
    let cle = m.cle_normale_ici();
    if crate::protection::normales::est_normale(&cle) {
        return;
    }
    let titre = tr!("Vanguard : fichier suspect", "Vanguard: suspicious file");
    let texte = trf!(
        "{} Rien n'est fait : vérifiez d'où il vient avant de l'ouvrir.",
        "{} Nothing is done: check where it comes from before opening it.",
        m.quoi
    );
    crate::reseau::tableau::noter_alerte_liee(Genre::Blocage, Some(&cle), None, titre, &texte);
    if notifier {
        crate::reseau::surveillance::notifier(titre, &texte);
    }
}

/// Pur : le chemin que nomme la clé « normale ici » d'un fichier (« `blocage|sha256:<hex>|fichier:<chemin>` »), s'il
/// est absolu.
pub(crate) fn chemin_de_cle(cle: &str) -> Option<PathBuf> {
    let (hex, reste) = cle.strip_prefix("blocage|sha256:")?.split_once('|')?;
    if hex.len() != 64 || !hex.bytes().all(|o| o.is_ascii_hexdigit()) {
        return None;
    }
    let chemin = PathBuf::from(reste.strip_prefix("fichier:")?);
    chemin.is_absolute().then_some(chemin)
}

/// `vanguard alerte <id>` sur l'alerte d'un fichier du temps réel hors de Téléchargements (que `menaces::chercher` ne
/// rejuge pas) : le fichier que nomme sa clé, rejugé maintenant par le moteur, seulement s'il est l'enfant direct
/// d'un des dossiers surveillés (`dossiers` : chemin et nom à montrer).
pub(super) fn menace_d_alerte(cle: &str, dossiers: &[(PathBuf, String)]) -> Option<Menace> {
    let chemin = chemin_de_cle(cle)?;
    let (_, ou) = dossiers.iter().find(|(d, _)| chemin.parent() == Some(d.as_path()))?;
    let sources = moteur::sources(moteur::Usage::EnContinu);
    let r = moteur::examiner(&chemin, &sources, DELAI).ok()?;
    menaces::menace_du_fichier(chemin, &r, ou)
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::protection::heuristiques::Heuristique;
    use crate::protection::moteur::Source;

    /// Verdict → geste : seul le certain, l'automatique permis, part en quarantaine ; jamais un suspect ni une
    /// famille ; un contenu remis par la personne revient à un clic ; la confiance tait le certain.
    #[test]
    fn verdict_vers_geste() {
        let certain = Verdict::Certain(Source::EmpreinteMalwareBazaar, "x".into());
        let famille = Verdict::Famille(Source::Yara, "Regle".into());
        let suspect = Verdict::Suspect(vec![Heuristique::NomTrompeur]);
        let non_verifie = Verdict::NonVerifie(vec!["contenu 7z non ouvert".into()]);
        assert_eq!(suite_de(&certain, true, false, false), Suite::Quarantaine);
        assert_eq!(suite_de(&certain, false, false, false), Suite::UnClic);
        assert_eq!(suite_de(&certain, true, true, false), Suite::UnClic);
        assert_eq!(suite_de(&certain, true, false, true), Suite::Rien);
        for (auto, remise) in [(true, false), (false, false), (true, true)] {
            assert_eq!(suite_de(&famille, auto, remise, false), Suite::UnClic);
            assert_eq!(suite_de(&suspect, auto, remise, false), Suite::Alerte);
            assert_eq!(suite_de(&non_verifie, auto, remise, false), Suite::NonVerifie);
            assert_eq!(suite_de(&Verdict::Sain, auto, remise, false), Suite::Rien);
        }
        // La confiance ne vaut que pour le contenu exact reconnu : une famille ou un suspect restent dits.
        assert_eq!(suite_de(&famille, true, false, true), Suite::UnClic);
        assert_eq!(suite_de(&suspect, true, false, true), Suite::Alerte);
    }

    /// La clé d'une alerte relue : seulement « blocage|sha256:<64 hex>|fichier:<absolu> ».
    #[test]
    fn chemin_de_cle_piege() {
        let h = "ab".repeat(32);
        assert_eq!(
            chemin_de_cle(&format!("blocage|sha256:{h}|fichier:/home/alice/Bureau/a|b.exe")),
            Some(PathBuf::from("/home/alice/Bureau/a|b.exe"))
        );
        for cle in [
            format!("blocage|sha256:{h}|fichier:relatif/a.exe"),
            format!("blocage|sha256:{}|fichier:/a", "zz".repeat(32)),
            format!("blocage|sha256:{}|fichier:/a", "ab".repeat(31)),
            format!("blocage|sha256:{h}|connexion:203.0.113.7"),
            format!("veilleur|rapprochee|{h}"),
            "blocage|fichier:/home/alice/a".to_string(),
            String::new(),
        ] {
            assert_eq!(chemin_de_cle(&cle), None, "{cle}");
        }
    }

    /// Le contenu relu avant la quarantaine : un autre contenu, un tube ou un lien glissé à sa place ne vaut pas.
    #[test]
    fn meme_contenu_relu() {
        use sha2::Digest;
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let f = d.join("colis.bin");
        std::fs::write(&f, b"contenu d'essai").unwrap();
        let h = crate::protection::empreintes::hex(&sha2::Sha256::digest(b"contenu d'essai").into());
        assert!(meme_contenu(&f, Some(&h)));
        assert!(meme_contenu(&f, Some(&h.to_uppercase())));
        assert!(!meme_contenu(&f, None));
        std::fs::write(&f, b"autre contenu").unwrap();
        assert!(!meme_contenu(&f, Some(&h)));
        std::fs::remove_file(&f).unwrap();
        // Un tube nommé : relu sans attendre, ce n'est pas un fichier ordinaire.
        crate::essais::tube_nomme(&f).unwrap();
        assert!(!meme_contenu(&f, Some(&h)));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Sorti de la quarantaine par la personne (décidé : clé liée au contenu exact) : le temps réel ne le remet pas
    /// en quarantaine et ne le redit pas ; la clé d'un autre contenu au même nom est autre.
    #[test]
    fn contenu_sorti_laisse_en_place() {
        use crate::protection::moteur::Trouvaille;
        let dossier = crate::essais::Jetable::nouveau("sorti-en-direct");
        let f = dossier.join("colis.exe");
        std::fs::write(&f, b"MZ sorti").unwrap();
        let e = crate::protection::empreintes::sha256(&f).unwrap();
        let r = Resultat {
            trouvailles: vec![Trouvaille {
                source: Source::EmpreinteMalwareBazaar,
                nom: "essai".into(),
                partie: String::new(),
            }],
            sha256: Some(e),
            ..Resultat::default()
        };
        let autre = crate::protection::empreintes::sha256_de(&b"MZ autre"[..]).unwrap();
        assert_ne!(
            crate::protection::normales::cle_remise(&e, &f),
            crate::protection::normales::cle_remise(&autre, &f)
        );
        crate::protection::normales::declarer(&crate::protection::normales::cle_remise(&e, &f), "blocage", "t", "x")
            .unwrap();
        let fait = fichier_en_direct(&f, "Téléchargements", &r, Annonce::Taire, None);
        assert_eq!(
            fait,
            Fait {
                suite: Suite::Rien,
                isole: false
            }
        );
        assert_eq!(std::fs::read(&f).unwrap(), b"MZ sorti");
    }

    /// Le nom porte-t-il encore l'inode examiné ? Un lien dur glissé à sa place, même au même contenu, ne vaut pas.
    #[cfg(unix)]
    #[test]
    fn inode_examine_relu() {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let f = d.join("colis.exe");
        let autre = d.join("copie.exe");
        std::fs::write(&f, b"contenu d'essai").unwrap();
        std::fs::write(&autre, b"contenu d'essai").unwrap();
        let examine = Identite::de(&std::fs::symlink_metadata(&f).unwrap());
        assert!(toujours_le_meme(&f, Some(&examine)));
        assert!(toujours_le_meme(&f, None));
        std::fs::remove_file(&f).unwrap();
        std::fs::hard_link(&autre, &f).unwrap();
        assert!(!toujours_le_meme(&f, Some(&examine)));
        std::fs::remove_file(&f).unwrap();
        assert!(!toujours_le_meme(&f, Some(&examine)));
        let _ = std::fs::remove_dir_all(&d);
    }
}

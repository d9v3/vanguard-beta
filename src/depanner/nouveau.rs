//! Parcours « Nouvel ordinateur » : neuf, d'occasion ou réinstallé, les premières choses à faire dans le bon ordre :
//! mises à jour, chiffrement du disque, sauvegardes, pack de départ, confidentialité, protection (Windows). Vanguard
//! vérifie d'abord où il en est (le bilan, catégories utiles), puis propose chaque outil ; chacun redemande son accord.

use super::{a_savoir, bilan, conseil, proposer_outil, question, verifications};
use crate::machine::Constat;
use crate::ui::*;

/// D'où vient l'ordinateur.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Origine {
    Neuf,
    Occasion,
    Reinstalle,
}

impl Origine {
    fn depuis(reponse: usize) -> Origine {
        match reponse {
            0 => Origine::Neuf,
            1 => Origine::Occasion,
            _ => Origine::Reinstalle,
        }
    }
}

/// Les catégories du bilan qui comptent pour un ordinateur qui commence : à jour, chiffré, sauvegardé, verrouillé,
/// protégé ; d'occasion, aussi ce qui tourne déjà dessus.
pub(super) fn categories(origine: Origine) -> Vec<&'static str> {
    let mut c = vec![
        "Mises à jour",
        "Chiffrement",
        "Sauvegardes",
        "Verrouillage",
        "Pare-feu",
        "Comptes",
        "Protection système",
    ];
    if origine == Origine::Occasion {
        c.extend(["Persistance", "Accès à distance", "Fichiers suspects", "Secure Boot"]);
    }
    c
}

/// Une étape du départ, dans l'ordre, avec l'outil de Vanguard qui la fait quand il y en a un.
pub(super) struct Etape {
    pub titre: &'static str,
    pub pourquoi: &'static str,
    /// La question qui ouvre l'outil, et l'outil.
    pub outil: Option<(&'static str, fn())>,
}

fn confidentialite() {
    crate::optimiser::menu(crate::optimiser::Categorie::Confidentialite);
}

/// Les étapes, dans l'ordre : d'abord ce qui ferme les portes (mises à jour, chiffrement), puis ce qui protège les
/// fichiers (sauvegardes), puis le confort (programmes, confidentialité). Pour un ordinateur d'occasion, la
/// réinstallation passe devant tout : c'est la seule façon d'être sûr de ce qui tourne.
pub(super) fn etapes(origine: Origine, fichiers_a_ramener: bool, chiffre: Option<bool>) -> Vec<Etape> {
    let mut e = Vec::new();
    if origine == Origine::Occasion {
        e.push(Etape {
            titre: tr!("Réinstaller le système", "Reinstall the system"),
            pourquoi: tr!(
                "Un ordinateur d'occasion a eu une autre vie : programmes, comptes, réglages, parfois un mouchard. La seule certitude est le système remis à neuf : Windows « Réinitialiser ce PC » (Supprimer tout), macOS « Effacer contenu et réglages », ou Linux installé depuis la clé VANGUARD. Les vérifications ci-dessus disent ce que Vanguard a trouvé en attendant.",
                "A used computer had another life: programs, accounts, settings, sometimes a spy. The only certainty is a fresh system: Windows “Reset this PC” (Remove everything), macOS “Erase All Content and Settings”, or Linux installed from the VANGUARD key. The checks above say what Vanguard found meanwhile."
            ),
            outil: None,
        });
    }
    e.push(Etape {
        titre: tr!("Mises à jour", "Updates"),
        pourquoi: tr!(
            "Un ordinateur neuf a passé des mois en boîte : système, programmes, pilotes et firmware ont pris du retard, et les failles connues sont les premières essayées.",
            "A new computer spent months in its box: system, programs, drivers and firmware fell behind, and known flaws are the first ones tried."
        ),
        outil: Some((
            tr!("\n  Vérifier les mises à jour ? [o/N] : ", "\n  Check for updates? [y/N]: "),
            crate::maj::executer,
        )),
    });
    e.push(Etape {
        titre: tr!("Chiffrement du disque", "Disk encryption"),
        pourquoi: match chiffre {
            Some(true) => tr!(
                "Déjà chiffré : gardez la clé de récupération (compte Microsoft, iCloud, ou imprimée) hors de l'ordinateur ; sans elle, un disque chiffré qui ne démarre plus est perdu.",
                "Already encrypted: keep the recovery key (Microsoft account, iCloud, or printed) away from the computer; without it, an encrypted disk that no longer boots is lost."
            ),
            Some(false) => tr!(
                "Pas chiffré : un ordinateur perdu ou volé livre tous ses fichiers à qui le branche ailleurs. À activer maintenant, tant qu'il n'y a presque rien dessus (c'est rapide) : la marche à suivre est dans le bilan ci-dessus.",
                "Not encrypted: a lost or stolen computer hands over all its files to whoever plugs it elsewhere. Turn it on now, while there is almost nothing on it (it is quick): the steps are in the check above."
            ),
            None => tr!(
                "Vanguard n'a pas pu lire l'état du chiffrement : vérifiez-le vous-même (BitLocker, FileVault ou LUKS). Un ordinateur perdu ou volé non chiffré livre tous ses fichiers.",
                "Vanguard could not read the encryption state: check it yourself (BitLocker, FileVault or LUKS). A lost or stolen unencrypted computer hands over all its files."
            ),
        },
        outil: None,
    });
    e.push(Etape {
        titre: tr!("Sauvegardes", "Backups"),
        pourquoi: if fichiers_a_ramener {
            tr!(
                "Ramenez vos fichiers depuis le disque de l'ancien ordinateur ou la copie faite avec Copier mes fichiers, dans Documents, Images, Vidéos… Puis une sauvegarde automatique vers un autre disque ou en ligne : un disque qui lâche, un vol ou un rançongiciel emportent tout ce qui n'existe qu'ici.",
                "Bring your files back from the old computer's disk or the copy made with Copy my files, into Documents, Pictures, Videos… Then an automatic backup to another disk or online: a failing disk, a theft or ransomware takes everything that exists only here."
            )
        } else {
            tr!(
                "Dès le début, une sauvegarde automatique vers un autre disque ou en ligne : un disque qui lâche, un vol ou un rançongiciel emportent tout ce qui n'existe qu'ici. L'état actuel est dans le bilan ci-dessus.",
                "From the start, an automatic backup to another disk or online: a failing disk, a theft or ransomware takes everything that exists only here. The current state is in the check above."
            )
        },
        outil: fichiers_a_ramener.then_some((
            tr!(
                "\n  Analyser le disque de l'ancien ordinateur (antivirus) avant de copier ? [o/N] : ",
                "\n  Scan the old computer's disk (antivirus) before copying? [y/N]: "
            ),
            crate::protection::antivirus::choisir as fn(),
        )),
    });
    e.push(Etape {
        titre: tr!("Pack de départ", "Starter pack"),
        pourquoi: tr!(
            "Un navigateur, un gestionnaire de mots de passe, la vidéo, la bureautique et les archives, installés depuis les sources officielles : pas de « télécharger ici » trouvé par un moteur de recherche, où se cachent les faux installateurs.",
            "A browser, a password manager, video, office and archives, installed from the official sources: no “download here” found through a search engine, where fake installers hide."
        ),
        outil: Some((
            tr!("\n  Ouvrir le pack de départ ? [o/N] : ", "\n  Open the starter pack? [y/N]: "),
            crate::logiciels::recommandes,
        )),
    });
    if crate::optimiser::a_des_reglages(crate::optimiser::Categorie::Confidentialite) {
        e.push(Etape {
            titre: tr!("Confidentialité", "Privacy"),
            pourquoi: tr!(
                "Les réglages d'usine envoient télémétrie, publicité ciblée et suggestions : chaque réglage est montré, s'applique si vous le cochez et s'annule exactement.",
                "Factory settings send telemetry, targeted ads and suggestions: each setting is shown, applies if you check it and is undone exactly."
            ),
            outil: Some((
                tr!(
                    "\n  Ouvrir les réglages de confidentialité ? [o/N] : ",
                    "\n  Open the privacy settings? [y/N]: "
                ),
                confidentialite,
            )),
        });
    }
    if cfg!(windows) {
        e.push(Etape {
            titre: tr!("Protection contre les attaques", "Protection against attacks"),
            pourquoi: tr!(
                "Les protections de Defender qui bloquent les attaques (macros, accès contrôlé aux dossiers, protection réseau) ne sont pas toutes actives d'usine.",
                "Defender's protections that block attacks (macros, controlled folder access, network protection) are not all on from the factory."
            ),
            outil: Some((
                tr!("\n  Ouvrir ces protections ? [o/N] : ", "\n  Open these protections? [y/N]: "),
                crate::optimiser::protection,
            )),
        });
    }
    e
}

/// L'état du chiffrement du disque d'après le bilan : chiffré, pas chiffré, ou illisible.
pub(super) fn chiffre(constats: &[Constat]) -> Option<bool> {
    constats
        .iter()
        .find(|c| c.categorie == "Chiffrement" && c.verifie)
        .map(|c| c.probleme.is_none())
}

pub(super) fn nouveau() {
    let Some(origine) = question(
        tr!("D'où vient cet ordinateur ?", "Where does this computer come from?"),
        &[
            tr!("Neuf", "New"),
            tr!("D'occasion ou reconditionné", "Used or refurbished"),
            tr!("Je viens de le réinstaller", "I just reinstalled it"),
        ],
    ) else {
        return;
    };
    let origine = Origine::depuis(origine);
    let Some(fichiers) = question(
        tr!(
            "Avez-vous des fichiers à ramener d'un ancien ordinateur ?",
            "Do you have files to bring back from an old computer?"
        ),
        &[tr!("Oui", "Yes"), tr!("Non", "No")],
    ) else {
        return;
    };
    verifications();
    let constats = bilan(&categories(origine));
    section(tr!("DANS L'ORDRE", "IN ORDER"));
    for (i, e) in etapes(origine, fichiers == 0, chiffre(&constats)).iter().enumerate() {
        println!("  {TOUCHE}{}{RESET} {GRAS}{}{RESET}", i + 1, e.titre);
        afficher_aligne("    ", e.pourquoi, 4, "");
        if let Some((question, outil)) = e.outil {
            proposer_outil(question, outil);
        }
        println!();
    }
    a_savoir(&[
        tr!(
            "Pour finir, le bilan complet (menu principal) note l'ordinateur, et la surveillance du réseau (menu Réseau) prévient quand un appareil inconnu arrive.",
            "To finish, the full check (main menu) grades the machine, and the network monitoring (Network menu) warns when an unknown device shows up."
        ),
        tr!(
            "Gardez la clé VANGUARD dans un tiroir : elle redémarre l'ordinateur quand le système ne veut plus, et porte une copie de Vanguard pour les trois systèmes.",
            "Keep the VANGUARD key in a drawer: it boots the computer when the system no longer will, and carries a copy of Vanguard for the three systems."
        ),
    ]);
    if origine == Origine::Occasion {
        conseil(tr!(
            "Occasion : demandez au vendeur la facture et vérifiez que l'ordinateur n'est plus lié à son compte (Localiser, compte Microsoft, Google) ; sinon il peut le verrouiller à distance.",
            "Used: ask the seller for the invoice and check that the computer is no longer tied to their account (Find My, Microsoft account, Google); otherwise they can lock it remotely."
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn constat(categorie: &'static str, probleme: Option<crate::risk::Niveau>, verifie: bool) -> Constat {
        Constat {
            categorie,
            probleme,
            message: String::new(),
            correctif: None,
            verifie,
            regle: "",
            objet: crate::modele::Objet::NonMigre,
            precision: crate::modele::Precision::Aucune,
        }
    }

    #[test]
    fn la_reinstallation_passe_devant_pour_l_occasion() {
        let e = etapes(Origine::Occasion, false, Some(true));
        assert!(e[0].titre.contains("instal"), "{}", e[0].titre);
        assert!(e[0].outil.is_none());
        let n = etapes(Origine::Neuf, false, Some(true));
        assert_eq!(n.len() + 1, e.len());
        assert!(n[0].titre.contains(tr!("Mises", "Updates")));
        // Mises à jour, chiffrement, sauvegardes, pack : toujours là, dans cet ordre.
        let titres: Vec<&str> = n.iter().map(|x| x.titre).collect();
        assert_eq!(
            &titres[..4],
            &["Mises à jour", "Chiffrement du disque", "Sauvegardes", "Pack de départ"]
        );
    }

    #[test]
    fn les_fichiers_a_ramener_proposent_l_antivirus() {
        let avec = etapes(Origine::Reinstalle, true, None);
        let sans = etapes(Origine::Reinstalle, false, None);
        let sauvegardes = |e: &[Etape]| e.iter().find(|x| x.titre == "Sauvegardes").unwrap().outil.is_some();
        assert!(sauvegardes(&avec) && !sauvegardes(&sans));
        assert!(avec[1].pourquoi.contains("n'a pas pu lire"));
        assert!(
            etapes(Origine::Neuf, false, Some(false))[1]
                .pourquoi
                .contains("Pas chiffré")
        );
    }

    #[test]
    fn categories_et_chiffrement_lus_du_bilan() {
        assert!(categories(Origine::Occasion).len() > categories(Origine::Neuf).len());
        assert!(categories(Origine::Neuf).contains(&"Chiffrement"));
        let c = [
            constat("Comptes", None, true),
            constat("Chiffrement", Some(crate::risk::Niveau::Moyen), true),
        ];
        assert_eq!(chiffre(&c), Some(false));
        assert_eq!(chiffre(&[constat("Chiffrement", None, true)]), Some(true));
        assert_eq!(
            chiffre(&[constat("Chiffrement", Some(crate::risk::Niveau::Info), false)]),
            None
        );
        assert_eq!(chiffre(&[]), None);
    }
}

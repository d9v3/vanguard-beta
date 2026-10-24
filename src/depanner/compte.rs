//! Parcours « Mon compte a été piraté » : courriel, réseau social, banque ou jeu. D'abord reprendre la main par la
//! page officielle du service (jamais par un lien reçu), puis, dans l'ordre : mot de passe neuf, validation en deux
//! étapes, sessions et applications déconnectées, ce que l'intrus laisse derrière lui (transfert du courriel,
//! bénéficiaires, messages aux contacts). Vanguard vérifie ensuite que cet ordinateur n'est pas la cause (voleur de mots
//! de passe, extension, prise de contrôle) et propose les recherches de fuites. Rien n'est changé sans accord.

use super::{a_savoir, bilan, conseil, ecran, proposer_outil, question};
use crate::ui::*;

/// Le compte piraté.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Sorte {
    Courriel,
    Social,
    Banque,
    Autre,
}

impl Sorte {
    fn depuis(reponse: usize) -> Sorte {
        match reponse {
            0 => Sorte::Courriel,
            1 => Sorte::Social,
            2 => Sorte::Banque,
            _ => Sorte::Autre,
        }
    }
}

/// Ce qui, sur cet ordinateur, aurait pu livrer le mot de passe : un voleur lancé au démarrage, une extension qui lit
/// les pages, une prise de contrôle, un DNS ou un certificat qui détourne les pages de connexion.
pub(super) const CATEGORIES: &[&str] = &[
    "Persistance",
    "Accès à distance",
    "Extensions",
    "Navigateur",
    "Certificats",
    "DNS",
    "Fichiers suspects",
];

/// Les étapes, dans l'ordre : reprendre la main, puis fermer chaque porte que l'intrus a pu laisser.
pub(super) fn etapes(sorte: Sorte, acces: bool) -> Vec<&'static str> {
    let mut e = Vec::new();
    if !acces {
        e.push(if sorte == Sorte::Banque {
            tr!(
                "Appelez votre banque au numéro au dos de votre carte (jamais celui d'un message reçu) : elle bloque l'accès et la carte, et rouvre votre compte.",
                "Call your bank at the number on the back of your card (never one from a message you received): it blocks access and the card, and reopens your account."
            )
        } else {
            tr!(
                "Reprenez la main par la page de récupération officielle du service, tapée vous-même, jamais par un lien reçu : Google accounts.google.com/signin/recovery, Microsoft account.live.com/acsr, Apple iforgot.apple.com, Facebook et Instagram facebook.com/hacked.",
                "Take back control through the service's official recovery page, typed yourself, never through a link you received: Google accounts.google.com/signin/recovery, Microsoft account.live.com/acsr, Apple iforgot.apple.com, Facebook and Instagram facebook.com/hacked."
            )
        });
    }
    e.push(tr!(
        "Changez le mot de passe : long, unique, jamais utilisé ailleurs ; un gestionnaire de mots de passe (Bitwarden, KeePassXC) les retient pour vous.",
        "Change the password: long, unique, never used elsewhere; a password manager (Bitwarden, KeePassXC) remembers them for you."
    ));
    e.push(tr!(
        "Activez la validation en deux étapes, par une application (Aegis, Google Authenticator) ou une clé de sécurité plutôt que par texto.",
        "Turn on two-step verification, with an app (Aegis, Google Authenticator) or a security key rather than by text message."
    ));
    e.push(tr!(
        "Déconnectez toutes les autres sessions, et retirez les appareils et les applications reliées que vous ne reconnaissez pas : l'intrus garde sinon sa session ouverte.",
        "Sign out every other session, and remove the devices and linked apps you do not recognize: otherwise the intruder keeps their session open."
    ));
    match sorte {
        Sorte::Courriel => e.push(tr!(
            "Dans le courriel : règles de transfert automatique et filtres (un intrus se fait envoyer une copie de tout), adresse et téléphone de secours. Le courriel ouvre tous les autres comptes : changez ensuite les mots de passe de ceux qui y sont reliés.",
            "In the mailbox: automatic forwarding rules and filters (an intruder has a copy of everything sent to them), recovery address and phone. Email opens every other account: then change the passwords of those tied to it."
        )),
        Sorte::Social => e.push(tr!(
            "Prévenez vos contacts : des messages ont pu partir en votre nom (demandes d'argent, liens piégés). Retirez ce que l'intrus a publié, et vérifiez l'adresse de courriel et le téléphone du compte.",
            "Warn your contacts: messages may have gone out in your name (money requests, trapped links). Remove what the intruder posted, and check the account's email address and phone."
        )),
        Sorte::Banque => e.push(tr!(
            "Avec la banque : contestez les opérations que vous n'avez pas faites, vérifiez les bénéficiaires ajoutés et les plafonds ; une plainte à la police aide souvent au remboursement.",
            "With the bank: dispute the transactions you did not make, check added payees and limits; a police report often helps get reimbursed."
        )),
        Sorte::Autre => e.push(tr!(
            "Vérifiez l'adresse de courriel et le téléphone du compte, et ce qui a pu être échangé, vendu ou acheté (jeux, objets, abonnements) : le service peut souvent l'annuler.",
            "Check the account's email address and phone, and what may have been traded, sold or bought (games, items, subscriptions): the service can often reverse it."
        )),
    }
    e.push(tr!(
        "Partout où vous utilisiez le même mot de passe : changez-le aussi, en commençant par le courriel et la banque.",
        "Everywhere you used the same password: change it too, starting with email and the bank."
    ));
    e
}

pub(super) fn compte() {
    let Some(sorte) = question(
        tr!("Quel compte a été piraté ?", "Which account was hacked?"),
        &[
            tr!("Mon courriel", "My email"),
            tr!(
                "Un réseau social (Facebook, Instagram, TikTok…)",
                "A social network (Facebook, Instagram, TikTok…)"
            ),
            tr!("Ma banque, un paiement en ligne", "My bank, an online payment"),
            tr!("Un jeu ou un autre compte", "A game or another account"),
        ],
    ) else {
        return;
    };
    let sorte = Sorte::depuis(sorte);
    let Some(acces) = question(
        tr!("Pouvez-vous encore vous y connecter ?", "Can you still sign in?"),
        &[
            tr!("Oui", "Yes"),
            tr!("Non, le mot de passe a changé", "No, the password was changed"),
        ],
    ) else {
        return;
    };
    ecran();
    section(tr!("DANS L'ORDRE", "IN ORDER"));
    afficher_aligne(
        "  ",
        tr!(
            "Depuis un appareil sûr : votre téléphone, ou cet ordinateur si la vérification plus bas ne trouve rien.",
            "From a safe device: your phone, or this computer if the check below finds nothing."
        ),
        2,
        GRIS,
    );
    for (i, etape) in etapes(sorte, acces == 0).iter().enumerate() {
        afficher_aligne(&format!("  {TOUCHE}{}{RESET} ", i + 1), etape, 4, "");
    }
    section(tr!(
        "CET ORDINATEUR A-T-IL LIVRÉ LE MOT DE PASSE ?",
        "DID THIS COMPUTER GIVE AWAY THE PASSWORD?"
    ));
    bilan(CATEGORIES);
    conseil(tr!(
        "Un voleur de mots de passe lancé au démarrage, une extension qui lit les pages ou une prise de contrôle suffit : si une ligne ci-dessus est rouge, réglez-la avant de changer les mots de passe d'ici (Après une infection, dans ce menu).",
        "A password stealer started at boot, an extension that reads pages or a remote control is enough: if a line above is red, fix it before changing passwords from here (After an infection, in this menu)."
    ));
    proposer_outil(
        tr!(
            "\n  Chercher votre adresse de courriel dans les fuites connues ? [o/N] : ",
            "\n  Look up your email address in the known leaks? [y/N]: "
        ),
        crate::protection::fuites::verifier_courriel,
    );
    proposer_outil(
        tr!(
            "\n  Vérifier si un mot de passe est dans les fuites connues ? [o/N] : ",
            "\n  Check whether a password is in the known leaks? [y/N]: "
        ),
        crate::protection::fuites::verifier,
    );
    a_savoir(&[tr!(
        "Le piratage commence souvent par un faux message (« votre compte va être fermé ») : avant de cliquer, collez le lien dans « Ce lien est-il dangereux ? » (menu Arnaques et vie privée).",
        "Hacking often starts with a fake message (“your account will be closed”): before clicking, paste the link into “Is this link dangerous?” (Scams and privacy menu)."
    )]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reprendre_la_main_d_abord() {
        let sans = etapes(Sorte::Courriel, false);
        assert!(sans[0].contains("récupération officielle"));
        assert!(etapes(Sorte::Courriel, true)[0].starts_with("Changez le mot de passe"));
        // La banque : le numéro au dos de la carte, jamais celui d'un message.
        assert!(etapes(Sorte::Banque, false)[0].contains("au dos de votre carte"));
        // Chaque sorte a son étape propre, et le même mot de passe ailleurs ferme la liste.
        for s in [Sorte::Courriel, Sorte::Social, Sorte::Banque, Sorte::Autre] {
            let e = etapes(s, true);
            assert_eq!(e.len(), 5, "{s:?}");
            assert!(e.last().unwrap().contains("même mot de passe"));
        }
        assert!(etapes(Sorte::Courriel, true)[3].contains("transfert automatique"));
        assert_eq!(Sorte::depuis(2), Sorte::Banque);
        assert_eq!(Sorte::depuis(9), Sorte::Autre);
    }
}

//! Parcours « Ordinateur d'un proche » : pour qui dépanne l'ordinateur d'un parent ou d'un ami. Trois questions (qui
//! s'en sert, pourquoi on te l'a confié, et si son réseau peut être regardé), le bilan de la machine, puis un résumé
//! en mots de tous les jours : trois à cinq points, ce qui va bien et ce qui reste à faire, mis en ordre selon les
//! réponses. Ensuite les corrections du circuit habituel (chacune montrée puis acceptée, point de restauration
//! d'abord), et la page à laisser, avec des conseils choisis pour la personne. Le réseau est celui du proche : il
//! n'est regardé qu'avec son accord.

use super::{Etat, a_savoir, conseil, ecran, proposer_outil, question};
use crate::machine::{Audit, Constat};
use crate::reseau::{Options, Rapport};
use crate::risk::Niveau;
use crate::ui::*;

/// Qui se sert de l'ordinateur, dans l'ordre des réponses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Qui {
    Age,
    Enfant,
    Adulte,
}

impl Qui {
    fn depuis(reponse: usize) -> Qui {
        match reponse {
            0 => Qui::Age,
            1 => Qui::Enfant,
            _ => Qui::Adulte,
        }
    }
}

/// Pourquoi on te l'a confié, dans l'ordre des réponses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Raison {
    Lent,
    Virus,
    Bilan,
}

impl Raison {
    fn depuis(reponse: usize) -> Raison {
        match reponse {
            0 => Raison::Lent,
            1 => Raison::Virus,
            _ => Raison::Bilan,
        }
    }
}

/// Un sujet du résumé : plusieurs catégories du bilan dites en une phrase que tout le monde comprend.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Sujet {
    FinDeSupport,
    MisesAJour,
    Antivirus,
    Louche,
    Distance,
    Navigateur,
    PareFeu,
    Sauvegardes,
    Disque,
    Comptes,
    Chiffrement,
    SansFil,
    /// Les autres appareils de la maison, quand le réseau a été regardé.
    Maison,
}

/// Tous les sujets, dans l'ordre par défaut : ce qui expose le plus d'abord.
const SUJETS: [Sujet; 13] = [
    Sujet::FinDeSupport,
    Sujet::MisesAJour,
    Sujet::Antivirus,
    Sujet::Louche,
    Sujet::Distance,
    Sujet::PareFeu,
    Sujet::Sauvegardes,
    Sujet::Disque,
    Sujet::Comptes,
    Sujet::Navigateur,
    Sujet::Chiffrement,
    Sujet::SansFil,
    Sujet::Maison,
];

impl Sujet {
    /// Les catégories du bilan qu'il regroupe (noms internes, en français).
    fn categories(self) -> &'static [&'static str] {
        match self {
            Sujet::FinDeSupport => &["Fin de support"],
            Sujet::MisesAJour => &["Mises à jour", "Redémarrage", "Pilotes", "Firmware", "Programmes"],
            Sujet::Antivirus => &["Antivirus"],
            Sujet::Louche => &["Fichiers suspects", "Persistance", "Rançongiciels"],
            Sujet::Distance => &["Accès à distance", "Bureau à distance", "Gestion à distance"],
            Sujet::Navigateur => &["Navigateur", "Extensions", "DNS"],
            Sujet::PareFeu => &["Pare-feu", "Ports en écoute", "Partages de fichiers", "SMBv1"],
            Sujet::Sauvegardes => &["Sauvegardes"],
            Sujet::Disque => &["Santé"],
            Sujet::Comptes => &["Comptes", "Verrouillage", "Groupes", "Privilèges", "Sudo"],
            Sujet::Chiffrement => &["Chiffrement"],
            Sujet::SansFil => &["Wi-Fi", "Bluetooth"],
            Sujet::Maison => &[],
        }
    }

    fn bien(self) -> &'static str {
        match self {
            Sujet::FinDeSupport => tr!(
                "Le système reçoit encore ses correctifs de sécurité.",
                "The system still gets its security fixes."
            ),
            Sujet::MisesAJour => tr!(
                "Le système et les programmes sont à jour.",
                "The system and the programs are up to date."
            ),
            Sujet::Antivirus => tr!("L'antivirus veille.", "The antivirus is on guard."),
            Sujet::Louche => tr!(
                "Rien de louche ne se lance tout seul.",
                "Nothing suspicious starts by itself."
            ),
            Sujet::Distance => tr!(
                "Personne ne peut prendre la main sur l'ordinateur à distance.",
                "Nobody can take control of the computer remotely."
            ),
            Sujet::Navigateur => tr!(
                "Le navigateur est propre : pas d'ajout douteux ni de détournement.",
                "The browser is clean: no dubious add-on or hijacking."
            ),
            Sujet::PareFeu => tr!(
                "La porte d'entrée (le pare-feu) est fermée aux inconnus.",
                "The front door (the firewall) is closed to strangers."
            ),
            Sujet::Sauvegardes => tr!(
                "Les photos et documents ont une copie à part.",
                "Photos and documents have a separate copy."
            ),
            Sujet::Disque => tr!(
                "Le disque a de la place et il est en bon état.",
                "The disk has room and is in good shape."
            ),
            Sujet::Comptes => tr!(
                "Les comptes et l'écran sont protégés par un mot de passe.",
                "The accounts and the screen are protected by a password."
            ),
            Sujet::Chiffrement => tr!(
                "Le disque est chiffré : un voleur ne pourrait pas lire les fichiers.",
                "The disk is encrypted: a thief could not read the files."
            ),
            Sujet::SansFil => tr!("Le Wi-Fi et le Bluetooth sont sûrs.", "Wi-Fi and Bluetooth are safe."),
            Sujet::Maison => tr!(
                "Les autres appareils du réseau local n'exposent rien d'inquiétant.",
                "The other devices in the home expose nothing worrying."
            ),
        }
    }

    fn a_faire(self) -> &'static str {
        match self {
            Sujet::FinDeSupport => tr!(
                "Le système ne reçoit plus de correctifs de sécurité : il faudra le remplacer.",
                "The system no longer gets security fixes: it will have to be replaced."
            ),
            Sujet::MisesAJour => tr!(
                "Des mises à jour attendent : elles bouchent les failles.",
                "Updates are waiting: they plug the holes."
            ),
            Sujet::Antivirus => tr!(
                "L'antivirus ne veille pas comme il le devrait.",
                "The antivirus is not on guard as it should be."
            ),
            Sujet::Louche => tr!(
                "Quelque chose de louche est installé ou se lance tout seul : à examiner.",
                "Something suspicious is installed or starts by itself: to look into."
            ),
            Sujet::Distance => tr!(
                "Un programme permet de prendre la main à distance : à retirer s'il n'a pas été voulu.",
                "A program allows remote control: to remove if nobody wanted it."
            ),
            Sujet::Navigateur => tr!(
                "Le navigateur a un ajout ou un réglage douteux.",
                "The browser has a dubious add-on or setting."
            ),
            Sujet::PareFeu => tr!(
                "La porte d'entrée (le pare-feu) laisse passer trop de choses.",
                "The front door (the firewall) lets too much through."
            ),
            Sujet::Sauvegardes => tr!(
                "Aucune copie des photos et documents : une panne, et tout est perdu.",
                "No copy of the photos and documents: one failure, and everything is lost."
            ),
            Sujet::Disque => tr!(
                "Le disque est presque plein ou s'use : faire de la place et une copie des fichiers.",
                "The disk is almost full or wearing out: free some room and copy the files."
            ),
            Sujet::Comptes => tr!(
                "Un compte ou l'écran est mal protégé (mot de passe, verrouillage).",
                "An account or the screen is poorly protected (password, lock)."
            ),
            Sujet::Chiffrement => tr!(
                "Le disque n'est pas chiffré : en cas de vol, tout se lit.",
                "The disk is not encrypted: if stolen, everything can be read."
            ),
            Sujet::SansFil => tr!(
                "Le Wi-Fi ou le Bluetooth n'est pas sûr.",
                "Wi-Fi or Bluetooth is not safe."
            ),
            Sujet::Maison => tr!(
                "Un appareil du réseau local est à régler sur l'appareil lui-même (routeur, imprimante…).",
                "A device in the home needs fixing on the device itself (router, printer…)."
            ),
        }
    }
}

/// Un point du résumé : un sujet connu, ou une catégorie du bilan qu'aucun sujet ne regroupe (dite par son nom).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Point {
    Connu(Sujet),
    Autre(&'static str),
}

impl Point {
    fn a_faire(self) -> String {
        match self {
            Point::Connu(s) => s.a_faire().to_string(),
            Point::Autre(cat) => trf!(
                "{} : un point à régler, montré dans les corrections.",
                "{}: something to fix, shown in the fixes.",
                crate::langue::categorie(cat)
            ),
        }
    }
}

/// Les sujets dans l'ordre où les mettre en avant : d'abord ce qui répond à la raison, puis ce qui compte pour cette
/// personne, puis le reste dans l'ordre par défaut. Chaque sujet une fois.
pub(super) fn priorite(qui: Qui, raison: Raison) -> Vec<Sujet> {
    let pour_la_raison: &[Sujet] = match raison {
        Raison::Lent => &[Sujet::Disque, Sujet::MisesAJour, Sujet::Louche, Sujet::Antivirus],
        Raison::Virus => &[Sujet::Louche, Sujet::Antivirus, Sujet::Distance, Sujet::Navigateur],
        Raison::Bilan => &[Sujet::MisesAJour, Sujet::Sauvegardes, Sujet::Antivirus],
    };
    // Une personne âgée est la cible des faux techniciens et des pages piégées ; un enfant installe des jeux et
    // n'a pas besoin d'être administrateur ; un adulte a surtout à perdre ses fichiers et ses comptes.
    let pour_la_personne: &[Sujet] = match qui {
        Qui::Age => &[
            Sujet::Distance,
            Sujet::Navigateur,
            Sujet::Sauvegardes,
            Sujet::MisesAJour,
        ],
        Qui::Enfant => &[Sujet::Comptes, Sujet::Navigateur, Sujet::Louche],
        Qui::Adulte => &[Sujet::Sauvegardes, Sujet::Chiffrement, Sujet::Comptes],
    };
    let mut ordre: Vec<Sujet> = Vec::new();
    // La maison juste après les sujets mis en avant : la personne a accepté qu'on la regarde, elle s'attend à en
    // entendre parler.
    for s in pour_la_raison
        .iter()
        .chain(pour_la_personne)
        .chain(&[Sujet::Maison])
        .chain(&SUJETS)
    {
        if !ordre.contains(s) {
            ordre.push(*s);
        }
    }
    ordre
}

/// Le résumé à montrer : ce qui va bien, ce qui reste à faire, et combien de points à faire ne tiennent pas dedans.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Resume {
    pub bien: Vec<Point>,
    pub a_faire: Vec<Point>,
    pub autres: usize,
}

/// Cinq points au plus : ce qui reste à faire d'abord (le critique en tête, puis selon la priorité), en gardant deux
/// places à ce qui va bien quand il y en a, pour que la personne entende aussi ce qui est en ordre. Un sujet n'est
/// « bien » que si l'une de ses vérifications a réussi et qu'aucune n'a rien signalé, pas même une information (un
/// service inconnu au démarrage n'est pas « rien de louche ») : une vérification impossible n'est jamais comptée
/// comme saine. `appareils` : les autres appareils de la maison à régler, si le
/// réseau a été regardé.
pub(super) fn resume(constats: &[Constat], appareils: Option<usize>, priorite: &[Sujet]) -> Resume {
    let rang = |s: Sujet| priorite.iter().position(|p| *p == s).unwrap_or(priorite.len());
    let a_regler = |c: &Constat| c.probleme.is_some_and(|n| n >= Niveau::Moyen);
    // (critique, rang, point)
    let mut a_faire: Vec<(bool, usize, Point)> = Vec::new();
    let mut bien: Vec<(usize, Point)> = Vec::new();
    for s in SUJETS {
        let siens: Vec<&Constat> = constats
            .iter()
            .filter(|c| s.categories().contains(&c.categorie))
            .collect();
        let pire = siens.iter().filter(|c| a_regler(c)).filter_map(|c| c.probleme).max();
        match (s, pire) {
            (Sujet::Maison, _) => match appareils {
                Some(0) => bien.push((rang(s), Point::Connu(s))),
                Some(_) => a_faire.push((false, rang(s), Point::Connu(s))),
                None => {}
            },
            (_, Some(n)) => a_faire.push((n == Niveau::Critique, rang(s), Point::Connu(s))),
            (_, None)
                if siens.iter().any(|c| c.verifie && c.probleme.is_none())
                    && siens.iter().all(|c| c.probleme.is_none()) =>
            {
                bien.push((rang(s), Point::Connu(s)));
            }
            _ => {}
        }
    }
    // Les catégories qu'aucun sujet ne regroupe : après les sujets connus, sauf si c'est critique.
    for c in constats.iter().filter(|c| a_regler(c)) {
        if SUJETS.iter().any(|s| s.categories().contains(&c.categorie)) {
            continue;
        }
        let critique = c.probleme == Some(Niveau::Critique);
        match a_faire.iter_mut().find(|(_, _, p)| *p == Point::Autre(c.categorie)) {
            Some(deja) => deja.0 |= critique,
            None => a_faire.push((critique, usize::MAX, Point::Autre(c.categorie))),
        }
    }
    a_faire.sort_by_key(|(critique, rang, _)| (!critique, *rang));
    bien.sort_by_key(|(rang, _)| *rang);
    let n_faire = a_faire.len().min(5 - bien.len().min(2));
    let n_bien = bien.len().min(5 - n_faire).min(3);
    Resume {
        autres: a_faire.len() - n_faire,
        a_faire: a_faire.into_iter().take(n_faire).map(|(_, _, p)| p).collect(),
        bien: bien.into_iter().take(n_bien).map(|(_, p)| p).collect(),
    }
}

/// Les conseils de la page à laisser, choisis pour cette personne et pour la raison de la visite.
fn conseils(qui: Qui, raison: Raison) -> Vec<&'static str> {
    let mut c = Vec::new();
    match qui {
        Qui::Age => c.push(tr!(
            "Si quelqu'un vous appelle pour « réparer votre ordinateur », ou si une fenêtre dit qu'il est bloqué et donne un numéro à appeler : raccrochez, fermez la fenêtre, et appelez la personne qui vous aide. Les vraies entreprises n'appellent jamais d'elles-mêmes.",
            "If someone calls you to “fix your computer”, or a window says it is locked and gives a number to call: hang up, close the window, and call the person who helps you. Real companies never call on their own."
        )),
        Qui::Enfant => {
            c.push(tr!(
                "Les jeux et les programmes se prennent seulement au magasin officiel (Steam, Microsoft Store, App Store…) : les « versions gratuites » trouvées ailleurs cachent souvent des virus.",
                "Games and programs only come from the official store (Steam, Microsoft Store, App Store…): “free versions” found elsewhere often hide viruses."
            ));
            c.push(tr!(
                "Un message qui fait peur ou qui demande de l'argent, des photos ou un mot de passe : le montrer à un adulte avant de répondre.",
                "A message that scares you or asks for money, photos or a password: show it to an adult before answering."
            ));
        }
        Qui::Adulte => c.push(tr!(
            "Activez la validation en deux étapes sur votre courriel et votre banque : un mot de passe volé ne suffit alors plus.",
            "Turn on two-step verification for your email and your bank: a stolen password is then no longer enough."
        )),
    }
    match raison {
        Raison::Lent => c.push(tr!(
            "Redémarrez l'ordinateur au moins une fois par semaine, et désinstallez les programmes dont vous ne vous servez plus : il reste plus rapide.",
            "Restart the computer at least once a week, and uninstall the programs you no longer use: it stays faster."
        )),
        Raison::Virus => c.push(tr!(
            "Un message qui presse (« votre compte sera fermé », « virus détecté », « colis en attente ») est presque toujours une arnaque : ne cliquez pas, ne rappelez pas, demandez d'abord.",
            "A message that rushes you (“your account will be closed”, “virus detected”, “parcel waiting”) is almost always a scam: do not click, do not call back, ask first."
        )),
        Raison::Bilan => {}
    }
    c
}

/// Les autres appareils de la maison qui ont un vrai problème (même tri que Corriger, sans les simples informations).
fn appareils_a_regler(r: &Rapport) -> usize {
    r.hotes
        .iter()
        .filter(|h| h.role != Some("cette machine") && h.alertes.iter().any(|(n, _)| *n >= Niveau::Moyen))
        .count()
}

/// Le scan du réseau local, sur un fil à part avec son propre moteur : le parcours est appelé depuis un menu
/// synchrone, déjà dans le moteur du programme, où l'on ne peut pas en attendre un autre.
fn scanner_le_reseau() -> Option<Rapport> {
    std::thread::spawn(|| {
        let moteur = tokio::runtime::Builder::new_multi_thread().enable_all().build().ok()?;
        let resultat = moteur.block_on(crate::reseau::executer(Options::defaut(None, "courants")));
        moteur.shutdown_background();
        resultat
            .map_err(|e| {
                crate::journal::erreur("scan réseau", &e);
                trp!("  ✖ Scan du réseau impossible : {e}", "  ✖ Network scan failed: {e}");
            })
            .ok()
    })
    .join()
    .ok()
    .flatten()
}

/// Le bilan dans l'ordre de la priorité, pour que les corrections viennent dans le même ordre que le résumé.
fn dans_l_ordre(audit: &Audit, priorite: &[Sujet]) -> Audit {
    let rang = |c: &Constat| {
        priorite
            .iter()
            .position(|s| s.categories().contains(&c.categorie))
            .unwrap_or(priorite.len())
    };
    let mut constats = audit.constats.clone();
    constats.sort_by_key(rang);
    Audit {
        systeme: audit.systeme,
        score: audit.score,
        constats,
    }
}

/// Montre le résumé, en mots de tous les jours.
fn afficher_resume(audit: &Audit, r: &Resume) {
    section(tr!("EN RÉSUMÉ", "IN SHORT"));
    if audit.fiable() {
        afficher_note(tr!("Note de l'ordinateur", "Computer grade"), audit.score);
    }
    if !r.bien.is_empty() {
        trp!("\n  {GRAS}Ce qui va bien{RESET}", "\n  {GRAS}What is fine{RESET}");
        for p in &r.bien {
            if let Point::Connu(s) = p {
                Etat::Bon.dire(s.bien());
            }
        }
    }
    trp!(
        "\n  {GRAS}Ce qui reste à faire{RESET}",
        "\n  {GRAS}What is left to do{RESET}"
    );
    if r.a_faire.is_empty() {
        Etat::Bon.dire(tr!(
            "Rien d'important : l'ordinateur est en ordre.",
            "Nothing important: the computer is in order."
        ));
    }
    for p in &r.a_faire {
        Etat::Mauvais.dire(&p.a_faire());
    }
    if r.autres > 0 {
        Etat::Info.dire(&trf!(
            "Et {} autre(s) point(s), montré(s) dans les corrections.",
            "And {} other point(s), shown in the fixes.",
            r.autres
        ));
    }
    if audit.impossibles() > 0 {
        Etat::Info.dire(&trf!(
            "{} vérification(s) impossible(s) ici : pas comptée(s) comme bonne(s).",
            "{} check(s) could not be done here: not counted as fine.",
            audit.impossibles()
        ));
    }
}

/// Le parcours.
pub(super) fn proche() {
    let Some(qui) = question(
        tr!(
            "Trois questions, puis un bilan simple et une page claire à laisser. Qui se sert surtout de cet ordinateur ?",
            "Three questions, then a simple check-up and a clear page to leave behind. Who mostly uses this computer?"
        ),
        &[
            tr!("Une personne âgée", "An older person"),
            tr!("Un enfant ou un ado", "A child or a teenager"),
            tr!("Un adulte", "An adult"),
        ],
    ) else {
        return;
    };
    let Some(raison) = question(
        tr!("Pourquoi vous l'a-t-on confié ?", "Why were you asked to look at it?"),
        &[
            tr!("Il est lent", "It is slow"),
            tr!("Peur d'un virus ou d'une arnaque", "Fear of a virus or a scam"),
            tr!("Un bilan général", "A general check-up"),
        ],
    ) else {
        return;
    };
    // « Non » d'abord : c'est la réponse par défaut, le réseau du proche ne se regarde qu'avec son accord.
    let Some(reseau) = question(
        tr!(
            "Regarder aussi le réseau local (routeur, autres appareils) ? C'est le réseau de votre proche : seulement avec son accord.",
            "Also look at the home network (router, other devices)? It is your relative's network: only with their consent."
        ),
        &[
            tr!("Non, seulement cet ordinateur", "No, only this computer"),
            tr!("Oui, il ou elle est d'accord", "Yes, they agreed"),
        ],
    ) else {
        return;
    };
    let (qui, raison) = (Qui::depuis(qui), Raison::depuis(raison));
    let priorite = priorite(qui, raison);

    ecran();
    section(tr!("BILAN DE L'ORDINATEUR", "COMPUTER CHECK-UP"));
    trp!(
        "  {GRIS}Bilan en cours (quelques secondes ; jusqu'à une minute sous Windows)…{RESET}",
        "  {GRIS}Checking (a few seconds; up to a minute on Windows)…{RESET}"
    );
    let audit = crate::machine::auditer(false);
    let rapport = if reseau == 1 { scanner_le_reseau() } else { None };
    // Le bilan d'arrivée au carnet : la page à laisser dira « à l'arrivée » si les corrections changent la note.
    crate::historique::enregistrer(Some(&audit), rapport.as_ref());
    crate::ordinateurs::noter(Some(&audit), rapport.as_ref());
    let r = resume(&audit.constats, rapport.as_ref().map(appareils_a_regler), &priorite);
    afficher_resume(&audit, &r);

    let mut a_savoir_ici = Vec::new();
    if raison == Raison::Virus {
        a_savoir_ici.push(tr!(
            "Si un message a demandé de l'argent ou si quelqu'un a pris la main sur l'ordinateur : parcours « Après une infection », dans Dépanner pas à pas.",
            "If a message asked for money or someone took control of the computer: “After an infection”, in Troubleshoot step by step."
        ));
    }
    a_savoir(&a_savoir_ici);
    match raison {
        Raison::Lent => proposer_outil(
            tr!(
                "\n  Mesurer ce qui le ralentit (« Pourquoi c'est lent ? ») ? [o/N] : ",
                "\n  Measure what slows it down (“Why is it slow?”)? [y/N]: "
            ),
            crate::lenteur::menu,
        ),
        Raison::Virus => proposer_outil(
            tr!(
                "\n  Lancer une analyse antivirus rapide ? [o/N] : ",
                "\n  Run a quick antivirus scan? [y/N]: "
            ),
            || crate::protection::antivirus::analyser(crate::protection::antivirus::Portee::Rapide),
        ),
        Raison::Bilan => {}
    }
    // Le faux technicien vise surtout les aînés : la recherche des programmes de prise de contrôle, en plus du bilan.
    if raison == Raison::Virus || qui == Qui::Age {
        proposer_outil(
            tr!(
                "\n  Chercher un programme de prise de contrôle (faux technicien) ? [o/N] : ",
                "\n  Look for a remote control program (fake technician)? [y/N]: "
            ),
            crate::protection::distance::menu,
        );
    }

    // Les corrections du circuit habituel, dans l'ordre du résumé : chacune montrée puis acceptée, point de
    // restauration avant la première.
    let audit = match crate::corriger::corriger(&dans_l_ordre(&audit, &priorite), rapport.as_ref()) {
        Some(nouveau) => {
            crate::historique::enregistrer(Some(&nouveau), rapport.as_ref());
            nouveau
        }
        None => audit,
    };

    if demander(tr!(
        "\n  Préparer la page à laisser à votre proche (note, ce qui reste à faire, conseils) ? [O/n] : ",
        "\n  Prepare the page to leave to your relative (grade, what is left to do, tips)? [Y/n]: "
    ))
    .trim()
    .chars()
    .next()
    .is_none_or(|c| !matches!(c, 'n' | 'N'))
    {
        crate::a_laisser::laisser_avec(&audit, &conseils(qui, raison));
    } else {
        conseil(tr!(
            "La page reste possible plus tard : menu Cet ordinateur › Rapport à laisser.",
            "The page is still possible later: This computer menu › Report to leave behind."
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::{alerte, impossible, ok};

    #[test]
    fn reponses_dans_l_ordre_des_questions() {
        assert_eq!([0, 1, 2].map(Qui::depuis), [Qui::Age, Qui::Enfant, Qui::Adulte]);
        assert_eq!(
            [0, 1, 2].map(Raison::depuis),
            [Raison::Lent, Raison::Virus, Raison::Bilan]
        );
    }

    #[test]
    fn priorite_selon_les_reponses() {
        for qui in [Qui::Age, Qui::Enfant, Qui::Adulte] {
            for raison in [Raison::Lent, Raison::Virus, Raison::Bilan] {
                let p = priorite(qui, raison);
                // Chaque sujet une fois, aucun oublié.
                assert_eq!(p.len(), SUJETS.len());
                assert!(SUJETS.iter().all(|s| p.contains(s)));
            }
        }
        assert_eq!(priorite(Qui::Adulte, Raison::Lent)[0], Sujet::Disque);
        assert_eq!(
            priorite(Qui::Age, Raison::Virus)[..3],
            [Sujet::Louche, Sujet::Antivirus, Sujet::Distance]
        );
        // Bilan général d'une personne âgée : la prise de main à distance avant le pare-feu.
        let p = priorite(Qui::Age, Raison::Bilan);
        let rang = |s| p.iter().position(|x| *x == s).unwrap();
        assert!(rang(Sujet::Distance) < rang(Sujet::PareFeu));
    }

    #[test]
    fn resume_court_et_oriente() {
        let constats = vec![
            ok("Pare-feu", "Pare-feu actif."),
            ok("Antivirus", "ClamAV à jour."),
            ok("Chiffrement", "Disque chiffré."),
            alerte("Mises à jour", Niveau::Moyen, "12 mises à jour attendent."),
            alerte("Sauvegardes", Niveau::Moyen, "Aucune sauvegarde."),
            alerte("Santé", Niveau::Eleve, "Disque plein à 97 %."),
            alerte("Comptes", Niveau::Critique, "Compte « alice » sans mot de passe."),
            alerte("SSH", Niveau::Moyen, "Connexion par mot de passe."),
            alerte("DNS", Niveau::Info, "Information seulement."),
        ];
        // Lent : le critique d'abord, puis le disque et les mises à jour ; deux places gardées à ce qui va bien.
        let r = resume(&constats, None, &priorite(Qui::Adulte, Raison::Lent));
        assert_eq!(
            r.a_faire,
            [
                Point::Connu(Sujet::Comptes),
                Point::Connu(Sujet::Disque),
                Point::Connu(Sujet::MisesAJour)
            ]
        );
        assert_eq!(r.bien.len(), 2);
        assert_eq!(r.autres, 2, "sauvegardes et SSH ne tiennent pas dans les cinq points");
        assert!(r.bien.len() + r.a_faire.len() <= 5);
        // Adulte, bilan général : les sauvegardes passent avant le disque.
        let r = resume(&constats, None, &priorite(Qui::Adulte, Raison::Bilan));
        assert_eq!(
            r.a_faire[1..],
            [Point::Connu(Sujet::MisesAJour), Point::Connu(Sujet::Sauvegardes)]
        );
        // Le chiffrement, qui compte pour un adulte, est dit parmi ce qui va bien.
        assert!(r.bien.contains(&Point::Connu(Sujet::Chiffrement)));
        // Une catégorie qu'aucun sujet ne regroupe est dite par son nom, après les sujets connus.
        let seul_ssh = [alerte("SSH", Niveau::Moyen, "Connexion par mot de passe.")];
        let r = resume(&seul_ssh, None, &priorite(Qui::Adulte, Raison::Bilan));
        assert_eq!(r.a_faire, [Point::Autre("SSH")]);
        assert!(r.bien.is_empty() && r.autres == 0);
    }

    #[test]
    fn rien_d_invente_dans_le_resume() {
        // Une vérification impossible n'est jamais « bien » ; une simple information n'est pas « à faire ».
        let constats = vec![
            impossible("Antivirus", "service absent"),
            alerte("Sauvegardes", Niveau::Info, "Instantanés seulement."),
        ];
        let r = resume(&constats, None, &priorite(Qui::Age, Raison::Virus));
        assert!(r.bien.is_empty() && r.a_faire.is_empty() && r.autres == 0);
        // Le réseau, s'il a été regardé : la maison à régler, ou en ordre.
        let r = resume(&constats, Some(2), &priorite(Qui::Age, Raison::Virus));
        assert_eq!(r.a_faire, [Point::Connu(Sujet::Maison)]);
        let r = resume(&constats, Some(0), &priorite(Qui::Age, Raison::Virus));
        assert_eq!(r.bien, [Point::Connu(Sujet::Maison)]);
        // Une information dans un sujet (service inconnu au démarrage) : ni « bien » ni « à faire ».
        let constats = [
            ok("Fichiers suspects", "Rien de suspect."),
            alerte("Persistance", Niveau::Info, "Service inconnu au démarrage."),
        ];
        let r = resume(&constats, None, &priorite(Qui::Age, Raison::Virus));
        assert!(r.bien.is_empty() && r.a_faire.is_empty());
    }

    #[test]
    fn conseils_choisis_pour_la_personne() {
        assert_eq!(conseils(Qui::Age, Raison::Bilan).len(), 1);
        assert_eq!(conseils(Qui::Adulte, Raison::Lent).len(), 2);
        let c = conseils(Qui::Enfant, Raison::Virus);
        assert_eq!(c.len(), 3);
        let mut sans_doublon = c.clone();
        sans_doublon.dedup();
        assert_eq!(sans_doublon, c);
    }

    #[test]
    fn corrections_dans_l_ordre_du_resume() {
        let audit = Audit {
            systeme: "test",
            score: 60,
            constats: vec![
                alerte("Pare-feu", Niveau::Eleve, "Pare-feu coupé."),
                alerte("SSH", Niveau::Moyen, "Connexion par mot de passe."),
                alerte("Accès à distance", Niveau::Eleve, "AnyDesk au démarrage."),
            ],
        };
        let ordre = dans_l_ordre(&audit, &priorite(Qui::Age, Raison::Virus));
        let categories: Vec<&str> = ordre.constats.iter().map(|c| c.categorie).collect();
        assert_eq!(categories, ["Accès à distance", "Pare-feu", "SSH"]);
        assert_eq!(ordre.score, 60);
    }
}

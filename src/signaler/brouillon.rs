//! Le brouillon : assemblé à partir de ce que Vanguard a vu (le fil d'un incident, un examen) et de ce que seule la
//! personne sait (ce qu'elle a fait, ce qui s'est passé), chaque valeur masquée avant d'entrer, puis rendu en Markdown
//! neutralisé. Pur et sans entrée-sortie : le masquage est donné par l'appelant (`Masque`), si bien qu'un test peut
//! le court-circuiter et voir le contrôle final refuser.
//!
//! Honnêteté : l'état de la chaîne du journal est écrit dans le brouillon (un journal changé hors de Vanguard rend les
//! observations « non vérifiées », un journal adopté ou incomplet « non prouvé », jamais « intact »), aucun score
//! CVSS ni CWE n'est inventé, et le brouillon dit qu'il a été préparé par un outil automatique.

use std::fmt::Write as _;

use super::garde::{self, Decompte};
use super::markdown::{bloc_de_code, neutraliser_markdown};
use super::programmes::{Champ, Fiche, Langue};
use super::tri::Sujet;
use crate::modele::evenement::{Evenement, Genre};
use crate::modele::journal::Lecture;
use crate::modele::resultat::{Resultat, sans_piege};

/// Événements du fil gardés au plus : le fil choisi, pas le journal ; ce qui manque est dit.
pub(crate) const FIL_MAX: usize = 50;
/// Une valeur (réponse, message) gardée jusqu'à cette longueur, en caractères : un texte de 1 Mo ne gonfle pas le
/// brouillon.
pub(crate) const VALEUR_MAX: usize = 4000;
/// Constats d'un examen gardés au plus.
const CONSTATS_MAX: usize = 50;

/// Les critères de Microsoft : un contournement « en profondeur » n'est pas corrigé par défaut.
const CRITERES_MICROSOFT: &str = "https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria";

/// Comment masquer une valeur : les dossiers personnels connus et la fonction d'anonymisation.
pub(crate) struct Masque<'a> {
    pub maisons: &'a [String],
    pub anonymiser: &'a dyn Fn(&str) -> String,
}

impl Masque<'_> {
    fn masquer(&self, texte: &str, d: &mut Decompte) -> String {
        let borne = crate::modele::evenement::borne(&sans_piege(texte, true), VALEUR_MAX);
        let (t, n) = garde::masquer_avec(&borne, self.maisons, self.anonymiser);
        d.fusionner(&n);
        t
    }

    fn chemin(&self, chemin: &str, d: &mut Decompte) -> String {
        let reduit = garde::reduire_chemin(chemin, self.maisons);
        if reduit != chemin {
            d.ajouter(garde::Sorte::Fichier, 1);
        }
        self.masquer(&reduit, d)
    }
}

/// Ce que seule la personne sait, tel qu'elle l'a écrit (vide : pas répondu).
#[derive(Clone, Debug, Default)]
pub(crate) struct Reponses {
    pub produit: String,
    pub fait: String,
    pub vu: String,
    pub attendu: String,
    pub impact: String,
    pub preuve: String,
    /// Les CVE d'une faille connue que la personne signale quand même (la mise à jour ne la corrigerait pas).
    pub outre_connue: Vec<String>,
    /// Une protection « en profondeur » contournée.
    pub contournement: bool,
}

/// Le contexte lu par Vanguard.
pub(crate) struct Contexte {
    /// « Arch Linux 6.17.2 », « Windows 10.0.26200.9711 », « macOS 15.1 (Apple Silicon) ».
    pub systeme: String,
    /// L'état de la chaîne du journal, pour un incident.
    pub journal: Option<Lecture>,
    /// Ce que dit le catalogue KEV de la CISA des CVE de `outre_connue`.
    pub kev: Option<Kev>,
}

/// Le catalogue KEV de la CISA, lu dans sa copie gardée seulement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Kev {
    /// Les CVE qui y sont (exploitées) ; vide : aucune.
    Exploitees(Vec<String>),
    /// Pourquoi il n'a pas servi (copie absente, trop vieille, illisible).
    NonVerifie(String),
}

/// La valeur d'une rubrique, déjà masquée.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Texte {
    /// Écrit par la personne : neutralisé à l'écriture du Markdown.
    Personne(String),
    /// Lu par Vanguard ou venu de l'extérieur : dans un bloc de code.
    Vanguard(String),
    /// Écrit par Vanguard lui-même (ni nom ni valeur venus d'ailleurs).
    Note(String),
    ACompleter,
}

/// Une observation du fil : sa date, sa sorte, son contenu masqué.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Observation {
    pub quand: String,
    pub sorte: String,
    pub contenu: String,
}

/// Le brouillon assemblé.
#[derive(Clone)]
pub(crate) struct Brouillon {
    pub fiche: &'static Fiche,
    pub langue: Langue,
    pub champs: Vec<(Champ, Texte)>,
    pub observations: Vec<Observation>,
    /// Ce qui a été vu, en tête des observations (examen, état du journal), déjà masqué.
    pub en_tete: Vec<Texte>,
    pub omis: usize,
    /// Les rubriques qui manquent pour soumettre.
    pub manque: Vec<Champ>,
    pub masques: Decompte,
    pub notes: Vec<Texte>,
}

impl Brouillon {
    pub(crate) fn incomplet(&self) -> bool {
        !self.manque.is_empty()
    }
}

/// Une réponse vide ou faite d'espaces.
fn vide(t: &str) -> bool {
    t.trim().is_empty()
}

/// La phrase honnête sur l'état du journal, dans la langue du brouillon. Jamais « intact » pour un journal adopté,
/// incomplet ou falsifié.
pub(crate) fn phrase_journal(l: &Lecture, langue: Langue) -> String {
    match l {
        Lecture::Vide => langue.t("Journal des événements : vide.", "Event log: empty.").into(),
        Lecture::Intact => langue
            .t(
                "Journal des événements : intact (chaîne et tête scellée d'accord).",
                "Event log: intact (chain and sealed head agree).",
            )
            .into(),
        Lecture::Adopte => langue
            .t(
                "Journal des événements : non prouvé (accepté tel quel au premier usage des sceaux).",
                "Event log: not proven (accepted as it was when the seals were first used).",
            )
            .into(),
        Lecture::Incomplet(_) => langue
            .t(
                "Journal des événements : incomplet, non prouvé.",
                "Event log: incomplete, not proven.",
            )
            .into(),
        Lecture::Falsifie(_) => langue
            .t(
                "Journal des événements : changé hors de Vanguard. Les observations ci-dessous ne sont pas vérifiées.",
                "Event log: changed outside Vanguard. The observations below are not verified.",
            )
            .into(),
    }
}

/// Le contenu d'un événement, réduit à ce qui sert à un éditeur, avant masquage. Pas la ligne de commande de la
/// preuve (un jeton, un mot de passe), ni `Preuve::lignes()`, qui l'écrit avec le chemin complet du fichier.
fn contenu(e: &Evenement, m: &Masque, d: &mut Decompte, l: Langue) -> String {
    let mut lignes: Vec<String> = Vec::new();
    match &e.quoi {
        Genre::Alerte { famille, titre, texte } => {
            lignes.push(format!("{famille}{} {titre}", l.t(" :", ":")));
            lignes.push(texte.clone());
        }
        Genre::Preuve { releve } => {
            if let Some(p) = &releve.processus {
                if let Some(prog) = &p.programme {
                    lignes.push(format!("{} {}", l.t("programme :", "program:"), m.chemin(prog, d)));
                }
                if let Some(c) = &p.compte {
                    let compte_garde = garde::compte(c);
                    if compte_garde != c.trim() {
                        d.ajouter(garde::Sorte::Compte, 1);
                    }
                    lignes.push(format!("{} {compte_garde}", l.t("compte :", "account:")));
                }
            }
            if let Some(f) = &releve.fichier {
                lignes.push(format!("{} {}", l.t("fichier :", "file:"), m.chemin(&f.chemin, d)));
                if let Some(h) = &f.sha256 {
                    lignes.push(format!("SHA-256 {h}"));
                }
                if let Some(t) = f.taille {
                    lignes.push(format!("{t} {}", l.t("octets", "bytes")));
                }
            }
            if !releve.connexions.is_empty() {
                // « 203.0.113.7:443 (PID 4242, nom) » : seulement le nombre et les ports.
                let mut ports: Vec<String> = releve
                    .connexions
                    .iter()
                    .filter_map(|c| {
                        c.split_whitespace()
                            .next()?
                            .rsplit_once(':')
                            .map(|(_, p)| p.to_string())
                    })
                    .filter(|p| p.chars().all(|c| c.is_ascii_digit()))
                    .collect();
                ports.sort();
                ports.dedup();
                lignes.push(format!(
                    "{} {} ; ports {}",
                    releve.connexions.len(),
                    l.t("connexion(s)", "connection(s)"),
                    ports.join(", ")
                ));
            }
            if !releve.impossible.is_empty() {
                lignes.push(format!(
                    "{} {}",
                    releve.impossible.len(),
                    l.t("élément(s) non relevé(s)", "item(s) not recorded")
                ));
            }
            // Déjà masqué champ par champ : le masquage général suit quand même (un nom de programme).
            return m.masquer(&lignes.join("\n"), d);
        }
        Genre::Action {
            quoi,
            reussi,
            commandes,
            ..
        } => {
            lignes.push(format!(
                "{quoi} ({})",
                if *reussi {
                    l.t("réussi", "succeeded")
                } else {
                    l.t("échec", "failed")
                }
            ));
            if !commandes.is_empty() {
                lignes.push(format!(
                    "{} {}",
                    commandes.len(),
                    l.t("commande(s), non reprise(s)", "command(s), not included")
                ));
            }
        }
        _ => lignes.push(e.resume()),
    }
    if let Some(c) = &e.cle {
        lignes.push(format!("{} {c}", l.t("clé :", "key:")));
    }
    m.masquer(&lignes.join("\n"), d)
}

/// Les examens qui nomment l'inventaire de la machine, et le niveau des constats qui partent quand même. Les logiciels
/// périmés nomment chaque logiciel installé (VPN, Tor Browser…) : seuls les produits touchés par une faille exploitée
/// (critique). Le diagnostic nomme les programmes plantés, les sources des erreurs du journal et les services en
/// échec ; les connexions sortantes, chaque programme et ses serveurs : seuls les constats élevés ou plus (écrans
/// bleus, serveur de commande de botnet). Un rapport sur un seul programme n'a pas à emporter le reste.
fn seuil_d_inventaire(outil: &str) -> Option<crate::risk::Niveau> {
    match outil {
        "PRO-PER-001" => Some(crate::risk::Niveau::Critique),
        "PRO-DIA-001" | "PRO-SOR-001" => Some(crate::risk::Niveau::Eleve),
        _ => None,
    }
}

/// L'en-tête d'un examen : l'outil, la date, le verdict, ce qui n'a pas pu être vérifié (dont un sceau qui ne tient
/// pas : `resultat::derniers` ne reprend alors aucun constat), puis ses constats non sains.
fn examen(r: &Resultat, m: &Masque, d: &mut Decompte, l: Langue) -> (Vec<Texte>, Vec<Observation>) {
    let sujet = crate::modele::registre::OUTILS
        .iter()
        .find(|o| o.id == r.outil)
        .map_or("", |o| l.t(o.sujet.0, o.sujet.1));
    let mut lignes = vec![
        format!("{} ({sujet})", r.outil),
        format!("{} {}", l.t("examen du", "examined on"), r.debut),
        format!("{} {}", l.t("verdict :", "verdict:"), r.verdict()),
        format!(
            "{} {}",
            l.t("points vérifiés :", "items checked:"),
            r.couverture.verifies
        ),
    ];
    // Un examen qui nomme l'inventaire de la machine (`seuil_d_inventaire`) : seul le compte des points non vérifiés
    // reste, et seuls les problèmes au seuil ou au-dessus.
    let seuil = seuil_d_inventaire(&r.outil);
    if seuil.is_some() {
        if !r.couverture.non_verifies.is_empty() {
            lignes.push(format!(
                "{} {} {}",
                l.t("non vérifié :", "not checked:"),
                r.couverture.non_verifies.len(),
                l.t("point(s)", "item(s)")
            ));
        }
    } else {
        lignes.extend(
            r.couverture
                .non_verifies
                .iter()
                .map(|n| format!("{} {n}", l.t("non vérifié :", "not checked:"))),
        );
    }
    let en_tete = vec![Texte::Vanguard(m.masquer(&lignes.join("\n"), d))];
    let observations = r
        .constats
        .iter()
        .filter(|c| c.etat != "sain" && c.etat != "sans-objet")
        .filter(|c| seuil.is_none_or(|s| c.etat == "probleme" && c.niveau >= Some(s)))
        .take(CONSTATS_MAX)
        .map(|c| Observation {
            quand: String::new(),
            sorte: c.etat.clone(),
            contenu: m.masquer(format!("{} {}", c.regle, c.message).trim(), d),
        })
        .collect();
    (en_tete, observations)
}

/// Assemble le brouillon pour `fiche`, dans `langue` : chaque valeur passe par `sans_piege`, est bornée, puis masquée.
pub(crate) fn assembler(
    fiche: &'static Fiche,
    langue: Langue,
    sujet: &Sujet,
    rep: &Reponses,
    ctx: &Contexte,
    masque: &Masque,
) -> Brouillon {
    let mut d = Decompte::default();
    let personne = |t: &str, d: &mut Decompte| {
        if vide(t) {
            Texte::ACompleter
        } else {
            Texte::Personne(masque.masquer(t.trim(), d))
        }
    };
    let produit = if vide(&rep.produit) && fiche.programme == super::programmes::Programme::Vanguard {
        Texte::Vanguard(format!("Vanguard {}", env!("CARGO_PKG_VERSION")))
    } else {
        personne(&rep.produit, &mut d)
    };
    let systeme = Texte::Vanguard(masque.masquer(&ctx.systeme, &mut d));
    let mut champs = Vec::new();
    for &c in fiche.champs {
        let t = match c {
            Champ::Produit => produit.clone(),
            Champ::Systeme => systeme.clone(),
            Champ::Etapes => personne(&rep.fait, &mut d),
            Champ::Observe => personne(&rep.vu, &mut d),
            Champ::Attendu => personne(&rep.attendu, &mut d),
            Champ::Impact => personne(&rep.impact, &mut d),
            Champ::PreuveDeConcept => personne(&rep.preuve, &mut d),
            Champ::MisesAJour => Texte::Note(
                langue
                    .t(
                        "non vérifié par Vanguard : à compléter (Paramètres › Windows Update › Historique).",
                        "not checked by Vanguard: to be completed (Settings › Windows Update › Update history).",
                    )
                    .into(),
            ),
            Champ::Resume
            | Champ::TypeDeFaille
            | Champ::Composant
            | Champ::Configuration
            | Champ::AutresTouches
            | Champ::EditeurContacte => Texte::ACompleter,
        };
        champs.push((c, t));
    }
    let mut manquants = Vec::new();
    if vide(&rep.fait) {
        manquants.push(Champ::Etapes);
    }
    if vide(&rep.vu) {
        manquants.push(Champ::Observe);
    }
    if fiche.preuve_exigee && vide(&rep.preuve) {
        manquants.push(Champ::PreuveDeConcept);
    }

    let mut en_tete = Vec::new();
    let mut observations = Vec::new();
    let mut omis = 0;
    match sujet {
        Sujet::Rien => en_tete.push(Texte::Note(
            langue
                .t(
                    "Rien de ce que Vanguard a vu : rapport écrit par la personne.",
                    "Nothing Vanguard saw: report written by the person.",
                )
                .into(),
        )),
        Sujet::Examen(res) => {
            let (t, o) = examen(res, masque, &mut d, langue);
            en_tete = t;
            observations = o;
        }
        Sujet::Incident { choisi, fil, omis: o } => {
            if let Some(j) = &ctx.journal {
                en_tete.push(Texte::Note(phrase_journal(j, langue)));
                if let Lecture::Incomplet(raison) | Lecture::Falsifie(raison) = j {
                    en_tete.push(Texte::Vanguard(masque.masquer(raison, &mut d)));
                }
            }
            let mut gardes: Vec<&Evenement> = fil.iter().filter(|e| !e.essai).collect();
            omis = *o + gardes.len().saturating_sub(FIL_MAX);
            // Le choix de la personne reste dans le fil gardé : couper avant lui ôterait le sujet même du rapport.
            if let Some(i) = gardes.iter().position(|e| e.id == choisi.id).filter(|&i| i >= FIL_MAX) {
                let c = gardes.remove(i);
                gardes.truncate(FIL_MAX - 1);
                gardes.push(c);
            }
            for e in gardes.into_iter().take(FIL_MAX) {
                observations.push(Observation {
                    quand: masque.masquer(&e.quand, &mut d),
                    sorte: e.quoi.sorte().to_string(),
                    contenu: contenu(e, masque, &mut d, langue),
                });
            }
        }
    }

    let mut notes = Vec::new();
    if !rep.outre_connue.is_empty() {
        let mut t = format!(
            "{} {}.",
            langue.t(
                "Faille déjà connue, signalée quand même : la personne pense que la mise à jour ne la corrige pas.",
                "Already known flaw, reported anyway: the person believes the update does not fix it.",
            ),
            rep.outre_connue.join(", ")
        );
        match &ctx.kev {
            Some(Kev::Exploitees(dans)) if !dans.is_empty() => {
                let _ = write!(
                    t,
                    " {} {}.",
                    langue.t(
                        "Au catalogue KEV de la CISA (exploitée) :",
                        "In CISA's KEV catalog (exploited):"
                    ),
                    dans.join(", ")
                );
            }
            Some(Kev::Exploitees(_)) => t.push_str(langue.t(
                " Absente du catalogue KEV de la CISA (copie gardée).",
                " Not in CISA's KEV catalog (kept copy).",
            )),
            Some(Kev::NonVerifie(_)) | None => t.push_str(langue.t(
                " Catalogue KEV de la CISA : non vérifié.",
                " CISA's KEV catalog: not checked.",
            )),
        }
        notes.push(Texte::Note(t));
    }
    if rep.contournement {
        notes.push(Texte::Note(format!(
            "{} {CRITERES_MICROSOFT}",
            langue.t(
                "Contournement d'une protection « en profondeur » (AppLocker, accès contrôlé aux dossiers, Exploit Guard) : Microsoft ne le corrige pas par défaut.",
                "Bypass of a “defense-in-depth” protection (AppLocker, controlled folder access, Exploit Guard): Microsoft does not fix it by default.",
            )
        )));
    }

    Brouillon {
        fiche,
        langue,
        champs,
        observations,
        en_tete,
        omis,
        manque: manquants,
        masques: d,
        notes,
    }
}

/// Un texte rendu en Markdown selon sa sorte.
fn rendu(t: &Texte, l: Langue) -> String {
    match t {
        Texte::Personne(s) => neutraliser_markdown(s),
        Texte::Vanguard(s) => bloc_de_code(s),
        Texte::Note(s) => s.clone(),
        Texte::ACompleter => format!("_{}_", l.t("À compléter.", "To be completed.")),
    }
}

/// Le brouillon en Markdown, les en-têtes dans sa langue.
pub(crate) fn en_markdown(b: &Brouillon) -> String {
    let l = b.langue;
    let f = b.fiche;
    let mut s = String::new();
    let titre = format!(
        "{} {}",
        l.t("Brouillon de signalement :", "Vulnerability report draft:"),
        f.nom
    );
    if b.incomplet() {
        let manque: Vec<&str> = b.manque.iter().map(|c| c.titre(l)).collect();
        let _ = write!(
            s,
            "# {} — {titre}\n\n**{} {}.**\n\n",
            l.t("INCOMPLET", "INCOMPLETE"),
            l.t(
                "INCOMPLET : ne le soumets pas tel quel. Il manque :",
                "INCOMPLETE: do not submit it as is. Missing:"
            ),
            manque.join(", ")
        );
    } else {
        let _ = write!(s, "# {titre}\n\n");
    }
    let _ = write!(
        s,
        "_{}_\n\n_{}_\n\n",
        l.t(
            "Préparé avec Vanguard (outil automatique), relu par la personne qui le soumet.",
            "Prepared with Vanguard (an automated tool), reviewed by the person submitting it."
        ),
        l.t(
            "Ne publie rien avant que l'éditeur ait publié son avis.",
            "Do not publish anything before the vendor has published its advisory."
        )
    );
    let _ = write!(
        s,
        "- {} {}\n- {} {}\n- {} {}\n",
        l.t("Où soumettre :", "Where to submit:"),
        f.adresse,
        l.t("Compte :", "Account:"),
        l.t(f.compte.0, f.compte.1),
        l.t("Champs d'après :", "Fields according to:"),
        f.source
    );
    for n in &b.notes {
        let _ = writeln!(s, "- {}", rendu(n, l));
    }
    s.push('\n');
    for (c, t) in &b.champs {
        let _ = write!(s, "## {}\n\n{}\n\n", c.titre(l), rendu(t, l));
    }
    let _ = write!(s, "## {}\n\n", l.t("Ce que Vanguard a vu", "What Vanguard saw"));
    for t in &b.en_tete {
        let _ = write!(s, "{}\n\n", rendu(t, l));
    }
    for o in &b.observations {
        let quand = if o.quand.is_empty() {
            String::new()
        } else {
            format!("{} · ", neutraliser_markdown(&o.quand))
        };
        let _ = write!(
            s,
            "- {quand}{}\n\n{}\n\n",
            neutraliser_markdown(&o.sorte),
            bloc_de_code(&o.contenu)
        );
    }
    if b.omis > 0 {
        let _ = write!(
            s,
            "_{} {}._\n\n",
            b.omis,
            l.t(
                "événement(s) du fil omis (50 au plus)",
                "event(s) of the thread left out (50 at most)"
            )
        );
    }
    let _ = write!(s, "## {}\n\n", l.t("Masqué avant d'écrire", "Removed before writing"));
    let _ = writeln!(
        s,
        "{}\n\n{}",
        neutraliser_markdown(&b.masques.texte_dans(l == Langue::En)),
        l.t(
            "Limites : deux serveurs différents peuvent porter le même numéro 203.0.113.x ; un nom de moins de 3 caractères (4 pour un réseau ou un appareil) n'est jamais masqué ; un nom de fichier avec des espaces peut garder sa fin ; les adresses web ont perdu leur requête et leur nom de site. Remettez ce qu'il faut pour reproduire, et relisez : vous seul savez ce qui est personnel.",
            "Limits: two different servers may carry the same 203.0.113.x number; a name shorter than 3 characters (4 for a network or a device) is never masked; a file name with spaces may keep its end; web addresses lost their query string and site name. Put back what is needed to reproduce, and read it again: only you know what is personal."
        )
    );
    s
}

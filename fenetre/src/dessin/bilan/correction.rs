//! La feuille « Voir la correction » : ce que Vanguard ferait pour un constat, lu par `vanguard correction --voir`,
//! puis « Appliquer cette correction » ; et la feuille « Remettre comme avant » d'une ligne de « Ce que Vanguard a
//! changé » (`vanguard changements --voir`). Un seul geste par feuille, et seulement :
//!
//! - pour un aperçu lu, que rien n'empêche d'appliquer d'ici (`appli::peut_accepter` : droits du compte, annulable,
//!   automatique, ni retouché, ni coupé, ni plus large que la feuille, assez court pour se lire) ; sinon, la raison
//!   est dite à la place du bouton, et le terminal reste le chemin ;
//! - 2 s après que l'aperçu s'est montré (conception, Q7) : le bouton se montre grisé avant ;
//! - une fois : accepté, la feuille passe à « en cours », puis montre l'issue (« Fait. », ce que Vanguard a relu).
//!
//! Le bouton ne rend que le jeton et l'accord reçus de l'aperçu (`appli::accepter`), jamais un texte relu ici.
//!
//! Chaque texte de Vanguard (ceux que l'accord engage, et sa raison de refus) est dessiné signe par signe
//! (`dessin::signe_par_signe`) : les ligatures des polices ne lient jamais deux de ses signes, « -> » ne se dessine
//! pas comme « → » ; et chaque nom ou valeur est dans son propre cadre, dessiné par la fenêtre, pour qu'aucun signe
//! d'un nom (guillemet, chevron, signe égal) n'imite la frontière entre deux champs.
//!
//! Leurs mises en page sont gardées d'une image à l'autre (`Memoire`), tant que la feuille est ouverte.

use std::collections::HashMap;
use std::sync::Arc;

use eframe::egui::{
    self, Color32, Frame, Galley, Margin, RichText, ScrollArea, Stroke, TextFormat, Ui, text::LayoutJob,
};

use crate::appli::{Appli, EtatFeuille, FeuilleCorrection, peut_accepter, phrase_issue};
use crate::commandes::{APERCU_LU, Empreinte, Famille};
use crate::dessin::{
    RAYON_CARTE, ajouter_signe_par_signe, bouton, mono, moyenne, ombre, pal, police, signale, signale_avec,
    signe_par_signe, texte,
};
use crate::donnees::changements::{Annulation, IssueChange};
use crate::donnees::correction::{Apercu, Droits, Lecture};
use crate::donnees::mise_a_jour::{MiseAJour, Origine, Vue};

/// Largeur de la feuille, et la marge gardée autour sur un petit écran.
const LARGEUR: f32 = 760.0;
const MARGE: f32 = 32.0;
/// Ce que prennent le titre et le pied (boutons) : le corps défile dans le reste, le pied reste toujours visible.
const TITRE_ET_PIED: f32 = 190.0;

/// Ce que la personne copie pour faire la correction elle-même, dans un terminal.
const COMMANDE_TERMINAL: &str = "vanguard corriger";

/// Les textes de Vanguard de la feuille, déjà mis en page (vérification de Fable n° 4, N6). Dessiné signe par signe,
/// un texte a un tronçon par signe : egui referait à chaque image le travail de le décrire et de le hacher en entier
/// pour retrouver sa mise en page dans sa mémoire, environ 32 ms par image pour le plus grand aperçu permis
/// (780 000 signes). Gardée ici, une mise en page se reprend telle quelle tant que rien n'a changé (`garde`). Elle vit
/// dans la mémoire d'egui, avec la feuille, et part avec elle (`oublier`, à chaque image où aucune n'est ouverte).
#[derive(Clone, Default)]
struct Memoire {
    /// Un petit texte qu'egui met en page à chaque image. Quand egui vide sa propre mémoire des mises en page (atlas
    /// des signes presque plein, autre échelle, autres polices), il revient neuf : les mises en page gardées ici, qui
    /// pointent dans l'ancien atlas des signes, sont alors oubliées.
    temoin: Option<Arc<Galley>>,
    textes: HashMap<Cle, Mise>,
    /// Le contenu de l'aperçu a été vu plus large que la feuille (`depasse`) : un texte n'y est pas montré en entier.
    /// Gardé tant que la feuille est ouverte, et dit comme une coupe (vérification de Fable n° 4, N1).
    depasse: bool,
}

/// La place d'un texte de Vanguard dans la feuille.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Cle {
    Message,
    Action,
    PourquoiPas,
    Raison,
    Commande(usize),
    Geste(usize),
    Valeur(usize),
    Titre,
    Chemin(usize),
    /// La mise à jour : la version visée, l'empreinte, la version d'aujourd'hui de chaque programme.
    Visee,
    Sha256,
    Version(usize),
}

/// Ce que la personne a fait sur la feuille, à cette image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reponse {
    Rien,
    /// « Annuler », « Fermer », Échap ou un clic à côté (`Appli::annuler`).
    Fermer,
    /// « Appliquer cette correction » ou « Remettre comme avant » (`Appli::accepter`).
    Accepter,
    /// « Annuler cette correction », après une correction faite : la feuille de son annulation
    /// (`Appli::voir_annulation`).
    AnnulerLaCorrection(Empreinte),
}

/// La feuille ouverte, s'il y en a une, et ce que la personne y fait. Dessinée au-dessus de tout l'écran, quel qu'il
/// soit (le bilan, « Ce que Vanguard a changé »).
pub fn montrer(appli: &mut Appli, ctx: &egui::Context) {
    let Some(f) = appli.feuille_correction() else {
        return;
    };
    let offerte = match &f.etat {
        EtatFeuille::Recu(IssueChange::Fait {
            annulation: Some(j), ..
        }) => appli.dans_les_changements(*j),
        _ => false,
    };
    match feuille(ctx, f, offerte) {
        Reponse::Rien => {}
        Reponse::Fermer => appli.annuler(),
        Reponse::Accepter => appli.accepter(),
        Reponse::AnnulerLaCorrection(j) => appli.voir_annulation(j),
    }
}

/// Une mise en page gardée et ce qui a été demandé pour elle. La largeur demandée est gardée telle quelle : egui
/// l'arrondit au point avant de mettre en page (`galley.job` n'a pas la largeur demandée).
#[derive(Clone)]
struct Mise {
    format: TextFormat,
    largeur: f32,
    halign: egui::Align,
    justify: bool,
    echelle: f32,
    galley: Arc<Galley>,
}

fn id_memoire() -> egui::Id {
    egui::Id::unique("feuille-correction-mises")
}

/// Pour les essais : le nombre de textes de Vanguard dont la feuille garde la mise en page.
#[cfg(test)]
pub fn mises_gardees(ctx: &egui::Context) -> usize {
    ctx.data(|d| d.get_temp::<Memoire>(id_memoire()))
        .map_or(0, |m| m.textes.len())
}

/// À chaque image où aucune feuille n'est ouverte (`dessin::cadre::tout`) : ses mises en page partent avec elle,
/// quelle que soit la façon dont elle s'est fermée (« Annuler », un autre écran, « Retour »).
pub fn oublier(ctx: &egui::Context) {
    ctx.data_mut(|d| d.remove::<Memoire>(id_memoire()));
}

/// Un texte de Vanguard, à la suite de `debut` (une phrase de la fenêtre), signe par signe, mis en page comme
/// `ui.label` le ferait (largeur disponible, alignement) ; repris de `memoire` si le texte, la police, la couleur,
/// la largeur, l'alignement et l'échelle sont exactement ceux de la mise en page gardée.
fn garde(ui: &mut Ui, memoire: &mut Memoire, cle: Cle, debut: &str, t: &str, format: &TextFormat) {
    let largeur = ui.available_width();
    let (halign, justify) = (ui.layout().horizontal_placement(), ui.layout().horizontal_justify());
    let echelle = ui.ctx().pixels_per_point();
    let reprise = memoire.textes.get(&cle).filter(|m| {
        m.format == *format
            && m.galley.job.text.strip_prefix(debut) == Some(t)
            && m.largeur.to_bits() == largeur.to_bits()
            && m.halign == halign
            && m.justify == justify
            && m.echelle.to_bits() == echelle.to_bits()
    });
    let galley = if let Some(m) = reprise {
        Arc::clone(&m.galley)
    } else {
        let mut job = LayoutJob::default();
        if !debut.is_empty() {
            job.append(debut, 0.0, format.clone());
        }
        ajouter_signe_par_signe(&mut job, t, format);
        job.wrap.max_width = largeur;
        job.halign = halign;
        job.justify = justify;
        let galley = ui.fonts_mut(|f| f.layout_job(job));
        memoire.textes.insert(
            cle,
            Mise {
                format: format.clone(),
                largeur,
                halign,
                justify,
                echelle,
                galley: Arc::clone(&galley),
            },
        );
        galley
    };
    ui.add(egui::Label::new(galley));
}

/// Dessine la feuille au-dessus de l'écran. `offerte` : l'annulation d'une correction faite est offerte par la
/// dernière liste de « Ce que Vanguard a changé » (« Annuler cette correction » s'active).
pub fn feuille(ctx: &egui::Context, f: &FeuilleCorrection, offerte: bool) -> Reponse {
    let p = pal();
    let temoin =
        ctx.fonts_mut(|fonts| fonts.layout_job(LayoutJob::simple_singleline("x".into(), police(12.0), Color32::WHITE)));
    let mut memoire = ctx
        .data_mut(|d| d.remove_temp::<Memoire>(id_memoire()))
        .unwrap_or_default();
    if !memoire.temoin.as_ref().is_some_and(|t| Arc::ptr_eq(t, &temoin)) {
        memoire = Memoire {
            temoin: Some(temoin),
            textes: HashMap::new(),
            depasse: memoire.depasse,
        };
    }
    let ecran = ctx.content_rect();
    let largeur = (ecran.width() - 2.0 * MARGE).clamp(280.0, LARGEUR);
    let corps_max = (ecran.height() - 2.0 * MARGE - TITRE_ET_PIED).max(120.0);
    let cadre = Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(2.0, p.accent))
        .shadow(ombre())
        .corner_radius(RAYON_CARTE)
        .inner_margin(Margin::same(22));
    let reponse = egui::Modal::new(egui::Id::unique("feuille-correction"))
        .frame(cadre)
        .backdrop_color(p.fond.gamma_multiply(0.7))
        .show(ctx, |ui| {
            ui.set_width(largeur);
            let titre = match f.famille {
                Famille::Correction => crate::tr!("Voir la correction", "See the fix"),
                Famille::Annulation => crate::tr!("Remettre comme avant", "Restore as before"),
                Famille::MiseAJour => crate::tr!("Mettre à jour Vanguard", "Update Vanguard"),
            };
            ui.label(RichText::new(titre).font(moyenne(20.0)).color(p.encre));
            let sous_titre = match &f.etat {
                EtatFeuille::Envoi => crate::tr!(
                    "En cours : Vanguard rejuge tout, puis agit. Ça ne s'interrompt pas.",
                    "Running: Vanguard checks everything again, then acts. It is not interrupted."
                ),
                EtatFeuille::Recu(_) => crate::tr!("Vanguard a répondu.", "Vanguard answered."),
                _ => crate::tr!(
                    "Aperçu : rien n'a changé sur l'ordinateur.",
                    "Preview: nothing changed on the computer."
                ),
            };
            ui.label(texte(sous_titre, 13.0, p.doux));
            ui.add_space(12.0);
            if let Some(avis) = &f.avis {
                signale(ui, p.jaune, avis, 14.0);
                ui.add_space(8.0);
            }
            // La feuille est une `Area` : sa place est celle de l'image d'avant. Sans hauteur minimale, le corps ne
            // grandirait que de quelques points par image ; avec elle, il prend tout de suite sa hauteur.
            ScrollArea::vertical()
                .max_height(corps_max)
                .min_scrolled_height(corps_max)
                .auto_shrink([false, true])
                .show(ui, |ui| corps(ui, f, &mut memoire));
            ui.add_space(14.0);
            pied(ui, f, memoire.depasse, offerte)
        });
    let r = if reponse.should_close() {
        Reponse::Fermer
    } else {
        reponse.inner
    };
    if r != Reponse::Fermer {
        ctx.data_mut(|d| d.insert_temp(id_memoire(), memoire));
    }
    r
}

/// Ce qu'un aperçu permet d'ici : rien à dire s'il n'y a pas d'aperçu lu ; sinon, il s'applique d'ici, ou une raison
/// l'en empêche.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ici {
    PasDApercu,
    Possible,
    Empeche(&'static str),
}

fn empechement(etat: &EtatFeuille, depasse: bool) -> Ici {
    let pas_d_ici = match etat {
        EtatFeuille::Lue(Lecture::Lue(a)) => a.pas_d_ici(),
        EtatFeuille::Annulation(Lecture::Lue(a)) => a.pas_d_ici(),
        EtatFeuille::MiseAJour(Vue::Proposee(a)) => a.pas_d_ici(),
        _ => return Ici::PasDApercu,
    };
    let raison = pas_d_ici.or_else(|| {
        depasse.then_some(crate::tr!(
            "Un texte est plus large que la feuille : il n'est pas montré en entier, elle ne s'applique pas d'ici.",
            "A text is wider than the sheet: it is not shown in full, it is not applied from here."
        ))
    });
    raison.map_or(Ici::Possible, Ici::Empeche)
}

/// Le pied. Avant le geste : « Annuler », et le bouton qui change s'il s'applique d'ici (grisé les 2 premières
/// secondes), ou la raison qui l'empêche et « Copier la commande » pour le terminal. Pendant : « Fermer » (le geste
/// finit seul). Après : « Fermer », et « Annuler cette correction » après une correction faite.
fn pied(ui: &mut Ui, f: &FeuilleCorrection, depasse: bool, offerte: bool) -> Reponse {
    let p = pal();
    let mut r = Reponse::Rien;
    match &f.etat {
        EtatFeuille::Envoi => {
            if bouton(ui, crate::tr!("Fermer", "Close"), false, true).clicked() {
                r = Reponse::Fermer;
            }
        }
        EtatFeuille::Recu(issue) => {
            ui.horizontal(|ui| {
                if bouton(ui, crate::tr!("Fermer", "Close"), true, true).clicked() {
                    r = Reponse::Fermer;
                }
                if f.famille == Famille::Correction
                    && let IssueChange::Fait {
                        annulation: Some(j), ..
                    } = issue
                {
                    let t = crate::tr!("Annuler cette correction", "Undo this fix");
                    if bouton(ui, t, false, offerte).clicked() {
                        r = Reponse::AnnulerLaCorrection(*j);
                    }
                    if !offerte {
                        ui.label(texte(
                            crate::tr!(
                                "en attente de « Ce que Vanguard a changé »…",
                                "waiting for “What Vanguard changed”…"
                            ),
                            12.0,
                            p.discret,
                        ));
                    }
                }
            });
        }
        etat => {
            let empeche = empechement(etat, depasse);
            if let Ici::Empeche(raison) = empeche {
                ui.label(texte(raison, 13.0, p.doux));
                ui.add_space(8.0);
            }
            ui.horizontal(|ui| {
                if bouton(ui, crate::tr!("Annuler", "Cancel"), empeche != Ici::Possible, true).clicked() {
                    r = Reponse::Fermer;
                }
                if empeche == Ici::Possible {
                    let maintenant = std::time::Instant::now();
                    let actif = peut_accepter(etat, f.montre, maintenant).is_some();
                    if !actif && let Some(m) = f.montre {
                        // Redessiné quand les 2 s sont passées : le bouton s'active seul.
                        let reste = APERCU_LU.saturating_sub(maintenant.saturating_duration_since(m));
                        ui.ctx()
                            .request_repaint_after(reste + std::time::Duration::from_millis(20));
                    }
                    let t = match f.famille {
                        Famille::Correction => crate::tr!("Appliquer cette correction", "Apply this fix"),
                        Famille::Annulation => crate::tr!("Remettre comme avant", "Restore as before"),
                        Famille::MiseAJour => crate::tr!("Installer cette mise à jour", "Install this update"),
                    };
                    if bouton(ui, t, true, actif).clicked() && actif {
                        r = Reponse::Accepter;
                    }
                }
                let terminal = matches!(etat, EtatFeuille::Lue(Lecture::Lue(a)) if a.droits != Droits::Compte);
                if terminal && bouton(ui, crate::tr!("Copier la commande", "Copy the command"), false, true).clicked() {
                    ui.ctx().copy_text(COMMANDE_TERMINAL.to_owned());
                }
            });
        }
    }
    r
}

fn corps(ui: &mut Ui, f: &FeuilleCorrection, memoire: &mut Memoire) {
    let p = pal();
    match &f.etat {
        EtatFeuille::Attente { .. } => {
            ui.label(texte(
                crate::tr!("Lecture de la correction…", "Reading the fix…"),
                14.0,
                p.doux,
            ));
        }
        EtatFeuille::Lue(Lecture::Lue(a)) => {
            if depasse(ui, |ui| apercu(ui, a, memoire)) && !memoire.depasse {
                // Dit dès l'image suivante, en tête de l'aperçu (et le bouton qui change ne s'active pas).
                memoire.depasse = true;
                ui.ctx().request_repaint();
            }
        }
        EtatFeuille::Annulation(Lecture::Lue(a)) => {
            if depasse(ui, |ui| apercu_annulation(ui, a, memoire)) && !memoire.depasse {
                memoire.depasse = true;
                ui.ctx().request_repaint();
            }
        }
        EtatFeuille::MiseAJour(Vue::Proposee(a)) => {
            if depasse(ui, |ui| apercu_mise_a_jour(ui, a, memoire)) && !memoire.depasse {
                memoire.depasse = true;
                ui.ctx().request_repaint();
            }
        }
        // Rien n'est proposé : l'état vient du code de Vanguard, dit par la fenêtre (« à jour » en vert seulement
        // quand Vanguard l'a vérifié), puis sa raison, signe par signe.
        EtatFeuille::MiseAJour(v @ (Vue::AJour(r) | Vue::Rien(r) | Vue::NonVerifiee(r))) => {
            let (tete, couleur) = match v {
                Vue::AJour(_) => (crate::tr!("À jour, vérifié. ", "Up to date, verified. "), p.bon),
                Vue::Rien(_) => (
                    crate::tr!("Rien à mettre à jour ici. ", "Nothing to update here. "),
                    p.doux,
                ),
                _ => (
                    crate::tr!(
                        "Pas vérifié : rien n'est dit à jour. ",
                        "Not verified: nothing is said up to date. "
                    ),
                    p.jaune,
                ),
            };
            signale_avec(ui, couleur, 14.0, |ui| {
                let format = TextFormat::simple(police(14.0), p.encre);
                garde(ui, memoire, Cle::Raison, tete, r, &format);
            });
        }
        EtatFeuille::Envoi => {
            ui.label(texte(
                match f.famille {
                    Famille::Correction => {
                        crate::tr!("Vanguard applique la correction…", "Vanguard is applying the fix…")
                    }
                    Famille::Annulation => crate::tr!("Vanguard remet comme avant…", "Vanguard is restoring…"),
                    // Sous Windows, la nouvelle copie n'est pas lancée pour essai (`mise_a_jour::essayer`).
                    Famille::MiseAJour if cfg!(windows) => crate::tr!(
                        "Vanguard revérifie, télécharge s'il le faut, puis pose et relit chaque programme…",
                        "Vanguard checks again, downloads if needed, then places and reads back each program…"
                    ),
                    Famille::MiseAJour => crate::tr!(
                        "Vanguard revérifie, télécharge s'il le faut, puis pose et essaie chaque programme…",
                        "Vanguard checks again, downloads if needed, then places and tries each program…"
                    ),
                },
                14.0,
                p.doux,
            ));
        }
        EtatFeuille::Recu(issue) => recu(ui, f.famille, issue),
        // La raison d'un refus est un texte de Vanguard : signe par signe. Les autres raisons sont celles de la fenêtre.
        EtatFeuille::Lue(Lecture::Refusee(r))
        | EtatFeuille::Annulation(Lecture::Refusee(r))
        | EtatFeuille::MiseAJour(Vue::Refusee(r)) => {
            signale_avec(ui, p.jaune, 14.0, |ui| {
                let format = TextFormat::simple(police(14.0), p.encre);
                garde(
                    ui,
                    memoire,
                    Cle::Raison,
                    crate::tr!("Pas d'aperçu : ", "No preview: "),
                    r,
                    &format,
                );
            });
        }
        EtatFeuille::Lue(Lecture::Illisible(r))
        | EtatFeuille::Annulation(Lecture::Illisible(r))
        | EtatFeuille::MiseAJour(Vue::Illisible(r))
        | EtatFeuille::Echec(r) => {
            signale(
                ui,
                p.jaune,
                &crate::trf!("Pas d'aperçu : {}", "No preview: {}", r),
                14.0,
            );
        }
    }
}

/// L'issue d'un geste : « Fait. » et ce que Vanguard a relu, ou l'échec, ou l'issue inconnue (jamais « rien n'a été
/// fait », que seul un refus dit, et un refus montre un nouvel aperçu).
fn recu(ui: &mut Ui, famille: Famille, issue: &IssueChange) {
    let p = pal();
    match issue {
        IssueChange::Fait { relu, .. } => {
            ui.label(
                RichText::new(crate::tr!("Fait.", "Done."))
                    .font(moyenne(22.0))
                    .color(p.bon),
            );
            ui.add_space(6.0);
            let (t, couleur) = match relu {
                crate::donnees::changements::Relu::Corrige => (
                    crate::tr!("Vanguard a relu : corrigé.", "Vanguard read it again: fixed."),
                    p.bon,
                ),
                crate::donnees::changements::Relu::EncoreSignale => (
                    crate::tr!(
                        "Vanguard a relu : encore signalé.",
                        "Vanguard read it again: still reported."
                    ),
                    p.jaune,
                ),
                crate::donnees::changements::Relu::Revenu => (
                    crate::tr!(
                        "Vanguard a relu : revenu comme avant.",
                        "Vanguard read it again: back as before."
                    ),
                    p.bon,
                ),
                crate::donnees::changements::Relu::MisAJour => (
                    // Sous Windows, la nouvelle copie n'est pas lancée pour essai (`mise_a_jour::essayer`).
                    if cfg!(windows) {
                        crate::tr!(
                            "Vanguard a relu et comparé chaque programme posé : à jour.",
                            "Vanguard read back and compared each program placed: up to date."
                        )
                    } else {
                        crate::tr!(
                            "Vanguard a relu, comparé et essayé chaque programme posé : à jour.",
                            "Vanguard read back, compared and tried each program placed: up to date."
                        )
                    },
                    p.bon,
                ),
                crate::donnees::changements::Relu::PasRevenu => (
                    crate::tr!(
                        "Vanguard a relu : pas revenu comme avant partout. Voyez « Ce que Vanguard a changé ».",
                        "Vanguard read it again: not back as before everywhere. See “What Vanguard changed”."
                    ),
                    p.jaune,
                ),
            };
            signale(ui, couleur, t, 14.0);
            if famille == Famille::Correction {
                ui.add_space(6.0);
                ui.label(texte(
                    crate::tr!(
                        "Elle s'annule ici, ou depuis « Ce que Vanguard a changé ».",
                        "It can be undone here, or from “What Vanguard changed”."
                    ),
                    13.0,
                    p.doux,
                ));
            }
        }
        _ => signale(ui, p.jaune, &phrase_issue(famille, issue), 14.0),
    }
}

/// L'aperçu d'une annulation : ce qui sera remis, valeur par valeur (le chemin dans son cadre, aujourd'hui → avant),
/// et « changé depuis » en jaune quand aujourd'hui n'est pas ce que Vanguard avait posé.
fn apercu_annulation(ui: &mut Ui, a: &Annulation, memoire: &mut Memoire) {
    let p = pal();
    garde(
        ui,
        memoire,
        Cle::Titre,
        "",
        &a.titre,
        &TextFormat::simple(police(15.0), p.encre),
    );
    ui.add(egui::Label::new(signe_par_signe(&a.date, police(12.0), p.discret)).wrap());
    if a.retouche {
        ui.add_space(6.0);
        signale(
            ui,
            p.jaune,
            crate::tr!(
                "Ce texte a été retouché avant de l'afficher : il n'est pas exactement celui de Vanguard.",
                "This text was altered before showing it: it is not exactly Vanguard's."
            ),
            13.0,
        );
    }
    if a.coupe || memoire.depasse {
        ui.add_space(6.0);
        signale(
            ui,
            p.jaune,
            crate::tr!(
                "Un texte trop long a été coupé : la suite n'est pas montrée.",
                "A text that was too long was cut: the rest is not shown."
            ),
            13.0,
        );
    }
    ui.add_space(12.0);
    ui.label(
        RichText::new(crate::tr!("Ce qui sera remis", "What will be restored"))
            .font(moyenne(15.0))
            .color(p.encre),
    );
    ui.add_space(2.0);
    for (i, v) in a.valeurs.iter().enumerate() {
        cadre(ui, memoire, Cle::Chemin(i), &v.chemin, p.encre);
        ui.horizontal_wrapped(|ui| {
            ui.add_space(12.0);
            ui.label(texte(crate::tr!("droits aujourd'hui", "rights today"), 12.0, p.discret));
            ui.label(RichText::new(&v.actuel).font(mono(13.0)).color(p.encre));
            ui.label(texte("→", 12.0, p.discret));
            ui.label(texte(crate::tr!("remis à", "restored to"), 12.0, p.discret));
            ui.label(RichText::new(&v.avant).font(mono(13.0)).color(p.encre));
        });
        if v.change_depuis {
            let t = if v.pose.is_empty() {
                crate::tr!(
                    "Changé depuis, par vous ou un programme : ce que Vanguard avait posé n'est plus connu.",
                    "Changed since, by you or a program: what Vanguard had set is no longer known."
                )
                .to_string()
            } else {
                crate::trf!(
                    "Changé depuis, par vous ou un programme (Vanguard avait posé {}).",
                    "Changed since, by you or a program (Vanguard had set {}).",
                    v.pose
                )
            };
            signale(ui, p.jaune, &t, 13.0);
        }
        ui.add_space(6.0);
    }
    ui.add_space(6.0);
    signale(
        ui,
        p.bon,
        crate::tr!(
            "Avec les droits de votre compte, sans mot de passe d'administrateur.",
            "With your account's rights, without an administrator password."
        ),
        13.0,
    );
}

/// La taille d'un programme : en Mio, un chiffre après la virgule, puis en octets.
fn taille(octets: u64) -> String {
    const MIO: u64 = 1 << 20;
    let (entiers, dixiemes) = (octets / MIO, (octets % MIO) * 10 / MIO);
    crate::trf!(
        "{},{} Mio ({} octets)",
        "{}.{} MiB ({} bytes)",
        entiers,
        dixiemes,
        octets
    )
}

/// L'aperçu de la mise à jour : d'où vient le programme, sa version, son empreinte et sa taille, puis chaque
/// programme d'ici qu'il remplacerait, avec sa version d'aujourd'hui. Chaque texte de Vanguard dans son cadre.
fn apercu_mise_a_jour(ui: &mut Ui, a: &MiseAJour, memoire: &mut Memoire) {
    let p = pal();
    let fort = |ui: &mut Ui, t: &str| {
        ui.add_space(12.0);
        ui.label(RichText::new(t).font(moyenne(15.0)).color(p.encre));
        ui.add_space(2.0);
    };
    let origine = match a.origine {
        Origine::Github => crate::tr!(
            "GitHub : la dernière version publiée, signée par l'auteur ; Vanguard a vérifié la signature.",
            "GitHub: the latest published version, signed by the author; Vanguard verified the signature."
        ),
        Origine::Cle => crate::tr!(
            "La clé VANGUARD d'où tourne Vanguard.",
            "The VANGUARD key Vanguard runs from."
        ),
    };
    ui.label(texte(
        crate::tr!("D'où elle vient", "Where it comes from"),
        12.0,
        p.discret,
    ));
    ui.label(texte(origine, 14.0, p.encre));
    if a.retouche {
        ui.add_space(6.0);
        signale(
            ui,
            p.jaune,
            crate::tr!(
                "Ce texte a été retouché avant de l'afficher : il n'est pas exactement celui de Vanguard.",
                "This text was altered before showing it: it is not exactly Vanguard's."
            ),
            13.0,
        );
    }
    if a.coupe || memoire.depasse {
        ui.add_space(6.0);
        signale(
            ui,
            p.jaune,
            crate::tr!(
                "Un texte trop long a été coupé : la suite n'est pas montrée.",
                "A text that was too long was cut: the rest is not shown."
            ),
            13.0,
        );
    }
    fort(ui, crate::tr!("Ce qui s'installerait", "What would be installed"));
    ui.label(texte(crate::tr!("version", "version"), 12.0, p.discret));
    cadre(ui, memoire, Cle::Visee, &a.visee, p.encre);
    ui.label(texte(
        crate::tr!("empreinte SHA-256", "SHA-256 fingerprint"),
        12.0,
        p.discret,
    ));
    cadre(ui, memoire, Cle::Sha256, &a.sha256, p.encre);
    ui.label(texte(&taille(a.taille), 12.0, p.doux));
    fort(ui, crate::tr!("Ce qui serait remplacé", "What would be replaced"));
    for (i, c) in a.cibles.iter().enumerate() {
        cadre(ui, memoire, Cle::Chemin(i), &c.chemin, p.encre);
        ui.label(texte(
            crate::tr!("version aujourd'hui", "version today"),
            12.0,
            p.discret,
        ));
        cadre(ui, memoire, Cle::Version(i), &c.version, p.doux);
        ui.add_space(6.0);
    }
    ui.add_space(6.0);
    signale(
        ui,
        p.bon,
        crate::tr!(
            "Avec les droits de votre compte. Vanguard revérifie tout au moment d'installer, écrit à côté, relit, compare et essaie, puis remplace d'un coup ; sinon, l'ancien reste en place. Jamais une version plus ancienne.",
            "With your account's rights. Vanguard checks everything again when installing, writes alongside, reads back, compares and tries, then replaces at once; otherwise, the old one stays in place. Never an older version."
        ),
        13.0,
    );
}

/// Un texte de Vanguard dans son propre cadre, à chasse fixe, signe par signe : une commande, un geste, une valeur.
fn cadre(ui: &mut Ui, memoire: &mut Memoire, cle: Cle, t: &str, couleur: Color32) {
    let p = pal();
    Frame::new()
        .fill(p.fond)
        .stroke(Stroke::new(1.0, p.discret.gamma_multiply(0.5)))
        .corner_radius(4)
        .inner_margin(Margin::symmetric(8, 4))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            garde(ui, memoire, cle, "", t, &TextFormat::simple(mono(12.0), couleur));
        });
}

/// Dessine `contenu` ; vrai s'il a pris plus de place que la largeur qu'il avait. Un texte qui ne se replie pas
/// élargit tout ce qui le contient (egui agrandit la place à son contenu) : ce texte et ceux qui suivent sortent alors
/// de la feuille ou de l'écran, sans être ni retouchés ni coupés. Aucun texte de l'aperçu ne le fait aujourd'hui
/// (essai `aucun_texte_de_la_feuille_ne_depasse_sa_largeur`) ; si un changement d'egui, des polices ou de la feuille
/// le permettait, l'aperçu le dirait comme une coupe au lieu de le montrer pour entier.
fn depasse(ui: &mut Ui, contenu: impl FnOnce(&mut Ui)) -> bool {
    let largeur = ui.available_width();
    let debut = ui.min_rect().left();
    contenu(ui);
    ui.min_rect().right() - debut > largeur + 0.5
}

fn apercu(ui: &mut Ui, a: &Apercu, memoire: &mut Memoire) {
    let p = pal();
    let fort = |ui: &mut Ui, t: &str| {
        ui.add_space(12.0);
        ui.label(RichText::new(t).font(moyenne(15.0)).color(p.encre));
        ui.add_space(2.0);
    };
    // Une rangée qui se replie : dans une rangée simple, un texte ne va pas à la ligne et la rangée s'élargit à ses
    // textes ; une catégorie et une règle de 80 signes larges élargiraient alors toute la feuille, et le texte qui
    // suit sortirait de l'écran sans être ni retouché ni coupé (vérification de Fable n° 4, N1).
    ui.horizontal_wrapped(|ui| {
        ui.add(egui::Label::new(signe_par_signe(&a.categorie, police(12.0), p.discret)).wrap());
        ui.add(egui::Label::new(texte(a.gravite.nom(), 12.0, p.encre)).wrap());
        ui.add(egui::Label::new(signe_par_signe(&a.regle, mono(12.0), p.discret)).wrap());
    });
    ui.add_space(4.0);
    let format = TextFormat::simple(police(15.0), p.encre);
    garde(ui, memoire, Cle::Message, "", &a.message, &format);
    if a.retouche {
        ui.add_space(6.0);
        signale(
            ui,
            p.jaune,
            crate::tr!(
                "Ce texte a été retouché avant de l'afficher (caractères invisibles, de contrôle, que la fenêtre ne sait pas dessiner ou qui en imitent un autre, remplacés par « \u{fffd} » ou retirés ; sauts de ligne, espaces en tête ou longues suites d'espaces resserrés) : il n'est pas exactement celui de Vanguard.",
                "This text was altered before showing it (invisible or control characters, or ones this window cannot draw or that mimic another, replaced by “\u{fffd}” or removed; line breaks, leading spaces or long runs of spaces tightened): it is not exactly Vanguard's."
            ),
            13.0,
        );
    }
    // Un texte trop large pour la feuille (`depasse`) n'est pas montré en entier : c'est une coupe.
    if a.coupe || memoire.depasse {
        ui.add_space(6.0);
        signale(
            ui,
            p.jaune,
            crate::tr!(
                "Un texte trop long a été coupé : la suite n'est pas montrée.",
                "A text that was too long was cut: the rest is not shown."
            ),
            13.0,
        );
    }

    fort(ui, crate::tr!("Ce que Vanguard va faire", "What Vanguard will do"));
    garde(
        ui,
        memoire,
        Cle::Action,
        "",
        &a.action,
        &TextFormat::simple(police(14.0), p.doux),
    );
    if !a.automatique {
        ui.label(texte(
            crate::tr!(
                "Pas de geste automatique : la marche à suivre est expliquée, à faire vous-même.",
                "No automatic step: the way to do it is explained, for you to do."
            ),
            13.0,
            p.discret,
        ));
    }
    // Ce qui compte pour décider (droits, annulation) avant la liste des commandes, qui peut être longue.
    fort(ui, crate::tr!("À savoir", "Good to know"));
    if a.annulable {
        signale(
            ui,
            p.bon,
            crate::tr!(
                "S'annule : la valeur d'avant est notée, elle se remet exactement.",
                "Can be undone: the value before is noted and is put back exactly."
            ),
            13.0,
        );
    } else {
        // Un aperçu non annulable a toujours son « pourquoi pas » (`donnees::correction::coherent`) ; vide, la phrase
        // est celle de la fenêtre.
        let debut = if a.pourquoi_pas.is_empty() {
            crate::tr!(
                "Ne s'annule pas : Vanguard ne note pas de valeur d'avant pour ce geste.",
                "Cannot be undone: Vanguard notes no value before for this step."
            )
        } else {
            crate::tr!("Ne s'annule pas : ", "Cannot be undone: ")
        };
        signale_avec(ui, p.moyen, 13.0, |ui| {
            let format = TextFormat::simple(police(13.0), p.encre);
            garde(ui, memoire, Cle::PourquoiPas, debut, &a.pourquoi_pas, &format);
        });
    }
    match a.droits {
        Droits::Compte => signale(
            ui,
            p.bon,
            crate::tr!(
                "Avec les droits de votre compte, sans mot de passe d'administrateur.",
                "With your account's rights, without an administrator password."
            ),
            13.0,
        ),
        Droits::Admin => signale(
            ui,
            p.jaune,
            crate::tr!(
                "Cette correction demande les droits d'administrateur. Elle arrivera ici avec le prochain lot. D'ici là : vanguard corriger dans un terminal.",
                "This fix needs administrator rights. It will come here with the next batch. Until then: vanguard corriger in a terminal."
            ),
            13.0,
        ),
        Droits::Terminal => signale(
            ui,
            p.jaune,
            crate::tr!(
                "Cette correction pose une question : elle se fait dans le terminal (vanguard corriger).",
                "This fix asks a question: it is done in the terminal (vanguard corriger)."
            ),
            13.0,
        ),
    }
    if !a.point_de_restauration {
        signale(
            ui,
            p.discret,
            crate::tr!(
                "Pas de point de restauration : il demanderait les droits d'administrateur.",
                "No restore point: it would need administrator rights."
            ),
            13.0,
        );
    }
    if !a.commandes.is_empty() {
        fort(ui, crate::tr!("Commandes", "Commands"));
        // Chaque commande dans son propre cadre : une longue commande repliée sur deux lignes ne peut pas passer pour
        // deux commandes.
        for (i, c) in a.commandes.iter().enumerate() {
            cadre(ui, memoire, Cle::Commande(i), c, p.doux);
            ui.add_space(4.0);
        }
    }
    if !a.avant.is_empty() {
        fort(ui, crate::tr!("Valeurs d'avant, notées", "Values before, noted"));
        // Le geste dans son cadre, puis sa valeur dans le sien, sous « valeur notée » écrit par la fenêtre : un nom
        // qui contient « = », des guillemets ou des chevrons reste dans son cadre et n'imite pas une seconde valeur.
        // Une valeur absente est dite en italique, sans cadre : le texte « absente » écrit dans un fichier, lui, est
        // dans un cadre et ne passe pas pour une absence.
        for (i, v) in a.avant.iter().enumerate() {
            cadre(ui, memoire, Cle::Geste(i), &v.geste, p.discret);
            ui.horizontal_top(|ui| {
                ui.add_space(12.0);
                ui.label(texte(crate::tr!("valeur notée :", "value noted:"), 12.0, p.discret));
                match v.valeur.as_deref() {
                    Some(valeur) => {
                        ui.vertical(|ui| cadre(ui, memoire, Cle::Valeur(i), valeur, p.encre));
                    }
                    None => {
                        ui.label(
                            texte(
                                crate::tr!("absente, rien de noté", "absent, nothing noted"),
                                12.0,
                                p.discret,
                            )
                            .italics(),
                        );
                    }
                }
            });
            ui.add_space(6.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use eframe::egui::{FontFamily, Shape, epaint::Galley};

    use super::*;
    use crate::commandes::Accord;
    use crate::donnees::bilan::Gravite;
    use crate::donnees::correction::Avant;

    /// Un aperçu inventé (maison « alice ») dont chaque texte de Vanguard contient des suites que les polices lient.
    fn exemple(annulable: bool) -> Apercu {
        Apercu {
            version: "0.93.0".into(),
            regle: "LNX=>SSH..003".into(),
            categorie: "Clés -> SSH".into(),
            gravite: Gravite::Critique,
            message: "Clé privée ~/.ssh/id_<a> lisible par d'autres -> x".into(),
            action: "Protéger la clé id_<a> => x..y".into(),
            commandes: vec!["chmod 600 ~/.ssh/'id_<a>' -> x".into(), "a != b >= c <= www".into()],
            automatique: true,
            droits: Droits::Compte,
            annulable,
            pourquoi_pas: if annulable {
                String::new()
            } else {
                "Vanguard ne sait pas relever <- l'état => d'avant".into()
            },
            avant: if annulable {
                vec![Avant {
                    geste: "droits|/home/alice/.ssh/id_x = «y» -> z".into(),
                    valeur: Some("0644 => «700»".into()),
                }]
            } else {
                Vec::new()
            },
            point_de_restauration: false,
            accord: Accord::lire(&"ab".repeat(32)).unwrap(),
            retouche: false,
            coupe: false,
        }
    }

    fn galeries(forme: &Shape, sortie: &mut Vec<Arc<Galley>>) {
        match forme {
            Shape::Text(t) => sortie.push(t.galley.clone()),
            Shape::Vec(v) => v.iter().for_each(|f| galeries(f, sortie)),
            _ => {}
        }
    }

    /// Une image sans écran (`run_ui`) de ce que `dessin` peint : les textes qu'elle a mis en page.
    fn textes_peints(ctx: &egui::Context, dessin: impl FnMut(&mut Ui)) -> Vec<Arc<Galley>> {
        let entree = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(800.0, 3000.0))),
            ..Default::default()
        };
        let mut sortie = ctx.run_ui(entree, dessin);
        sortie.textures_delta.clear();
        let mut g = Vec::new();
        for c in &sortie.shapes {
            galeries(&c.shape, &mut g);
        }
        g
    }

    /// Vrai si `t` est peint dans un texte de l'image, chaque signe dans sa propre section (façonné seul : aucune
    /// ligature avec son voisin), dans une police que les essais de `dessin::encre` couvrent (Inter ou JetBrains
    /// Mono, de 12 à 15 points).
    fn peint_signe_par_signe(peints: &[Arc<Galley>], t: &str) -> bool {
        peints.iter().any(|g| {
            g.job.text.match_indices(t).any(|(o, _)| {
                t.char_indices().all(|(i, c)| {
                    g.job.sections.iter().any(|s| {
                        s.byte_range.start.0 == o + i
                            && s.byte_range.end.0 == o + i + c.len_utf8()
                            && matches!(
                                s.format.font_id.family,
                                FontFamily::Proportional | FontFamily::Monospace
                            )
                            && (12.0..=15.0).contains(&s.format.font_id.size)
                    })
                })
            })
        })
    }

    /// Vérification de Fable n° 3, A1 et A2 : chaque texte de Vanguard de la feuille (catégorie, règle, message,
    /// action, commandes, geste et valeur d'avant, « pourquoi pas », raison d'un refus) est peint signe par signe, dans
    /// une police et une taille dont la liste des signes permis est vérifiée. Un seul texte peint d'un bloc (ligatures
    /// permises) fait échouer cet essai.
    #[test]
    fn chaque_texte_de_vanguard_est_peint_signe_par_signe() {
        let ctx = egui::Context::default();
        crate::dessin::polices(&ctx);
        for annulable in [true, false] {
            let a = exemple(annulable);
            let mut memoire = Memoire::default();
            let peints = textes_peints(&ctx, |ui| apercu(ui, &a, &mut memoire));
            let mut textes = vec![&a.categorie, &a.regle, &a.message, &a.action];
            textes.extend(&a.commandes);
            for v in &a.avant {
                textes.push(&v.geste);
                textes.extend(&v.valeur);
            }
            if !annulable {
                textes.push(&a.pourquoi_pas);
            }
            for t in textes {
                assert!(
                    peint_signe_par_signe(&peints, t),
                    "{t:?} n'est pas peint signe par signe"
                );
            }
        }
        let raison = "ce problème a disparu -> refaites le bilan".to_string();
        let mut memoire = Memoire::default();
        let peints = textes_peints(&ctx, |ui| {
            let jeton = crate::commandes::Empreinte::lire(&"cd".repeat(16)).unwrap();
            let f = FeuilleCorrection::essai(
                Famille::Correction,
                jeton,
                EtatFeuille::Lue(Lecture::Refusee(raison.clone())),
            );
            corps(ui, &f, &mut memoire);
        });
        assert!(peint_signe_par_signe(&peints, &raison));
    }

    fn textes_et_coupes(forme: &Shape, coupe: egui::Rect, sortie: &mut Vec<(egui::Rect, egui::Rect)>) {
        match forme {
            Shape::Text(t) => {
                let place = egui::Rect::from_min_size(t.pos, t.galley.size());
                sortie.push((place.union(t.visual_bounding_rect()), coupe));
            }
            Shape::Vec(v) => v.iter().for_each(|f| textes_et_coupes(f, coupe, sortie)),
            _ => {}
        }
    }

    /// Quelques images sans écran de la feuille entière (`feuille`, dans sa `Modal`) sur un écran de cette taille :
    /// la place de chaque texte peint à la dernière image (dessin et encre), et le rectangle qui le coupe.
    fn feuille_peinte(ctx: &egui::Context, ecran: egui::Vec2, f: &FeuilleCorrection) -> Vec<(egui::Rect, egui::Rect)> {
        let mut textes = Vec::new();
        // Une `Area` se mesure à sa première image et se place aux suivantes : seule la dernière compte.
        for _ in 0..4 {
            let entree = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, ecran)),
                ..Default::default()
            };
            let mut sortie = ctx.run_ui(entree, |ui| {
                feuille(ui.ctx(), f, false);
            });
            sortie.textures_delta.clear();
            textes.clear();
            for c in &sortie.shapes {
                textes_et_coupes(&c.shape, c.clip_rect, &mut textes);
            }
        }
        textes
    }

    /// Un aperçu fait pour élargir la feuille : chaque texte de Vanguard long (80 signes, `NOM_MAX`, pour la catégorie
    /// et la règle), fait d'un seul signe large, sans espace où se replier.
    fn large(annulable: bool, droits: Droits, signe: char) -> Apercu {
        let w = |n: usize| signe.to_string().repeat(n);
        let mut a = exemple(annulable);
        a.categorie = w(80);
        a.regle = w(80);
        a.message = w(900);
        a.action = w(700);
        a.commandes = vec![w(500), format!("chmod 600 {}", w(300))];
        a.droits = droits;
        a.automatique = false;
        if annulable {
            a.avant = vec![
                Avant {
                    geste: w(400),
                    valeur: Some(w(400)),
                },
                Avant {
                    geste: w(200),
                    valeur: None,
                },
            ];
        } else {
            a.pourquoi_pas = w(600);
        }
        a
    }

    /// Vérification de Fable n° 4, N1 : aucun texte de la feuille ne sort de sa largeur, ni de l'écran, ni du
    /// rectangle qui le coupe, quelle que soit la largeur des textes de Vanguard ; à 1280×800 et à la plus petite
    /// fenêtre (960×640). Une rangée qui ne se replie pas (catégorie, gravité, règle) élargissait toute la feuille.
    /// Deux signes larges : « W » (Inter) et U+1F852, le signe permis le plus large (32 points à 12, dessiné par Inter
    /// même dans la règle, à chasse fixe, car JetBrains Mono ne l'a pas) : 80 « W » à chasse fixe tiennent dans la
    /// feuille, 80 flèches non. Les longs textes remplissent la feuille : elle garde aussi sa largeur.
    #[test]
    fn aucun_texte_de_la_feuille_ne_depasse_sa_largeur() {
        let ctx = egui::Context::default();
        crate::dessin::polices(&ctx);
        let jeton = crate::commandes::Empreinte::lire(&"cd".repeat(16)).unwrap();
        let mut etats: Vec<EtatFeuille> = Vec::new();
        for signe in ['W', '\u{1f852}'] {
            for (annulable, droits) in [(true, Droits::Compte), (false, Droits::Terminal), (true, Droits::Admin)] {
                etats.push(EtatFeuille::Lue(Lecture::Lue(Box::new(large(
                    annulable, droits, signe,
                )))));
            }
            let w = |n: usize| signe.to_string().repeat(n);
            etats.extend([
                EtatFeuille::Lue(Lecture::Refusee(w(200))),
                EtatFeuille::Lue(Lecture::Illisible(w(300))),
                EtatFeuille::Echec(w(300)),
            ]);
        }
        etats.push(EtatFeuille::Attente { lance: true });
        for ecran in [egui::vec2(1280.0, 800.0), egui::vec2(960.0, 640.0)] {
            let largeur = (ecran.x - 2.0 * MARGE).clamp(280.0, LARGEUR);
            for etat in &etats {
                let f = FeuilleCorrection::essai(Famille::Correction, jeton, etat.clone());
                oublier(&ctx);
                let textes = feuille_peinte(&ctx, ecran, &f);
                assert!(textes.len() > 3, "{ecran:?} {etat:?} : rien de peint");
                assert!(
                    !depassee(&ctx),
                    "{ecran:?} : la feuille a vu un texte plus large qu'elle"
                );
                let (mut gauche, mut droite) = (f32::INFINITY, f32::NEG_INFINITY);
                for (r, coupe) in &textes {
                    assert!(
                        r.left() >= -0.5 && r.right() <= ecran.x + 0.5,
                        "{ecran:?} : un texte sort de l'écran ({r:?})"
                    );
                    assert!(
                        r.left() >= coupe.left() - 0.5 && r.right() <= coupe.right() + 0.5,
                        "{ecran:?} : un texte est coupé sur le côté ({r:?} dans {coupe:?})"
                    );
                    gauche = gauche.min(r.left());
                    droite = droite.max(r.right());
                }
                assert!(
                    droite - gauche <= largeur + 0.5,
                    "{ecran:?} : les textes occupent {} points pour une feuille de {largeur}",
                    droite - gauche
                );
                if !matches!(etat, EtatFeuille::Attente { .. }) {
                    assert!(
                        droite - gauche >= largeur - 40.0,
                        "{ecran:?} : la feuille s'est rétrécie à {} points",
                        droite - gauche
                    );
                }
            }
        }
    }

    /// La feuille ouverte a vu un texte plus large qu'elle (`Memoire::depasse`).
    fn depassee(ctx: &egui::Context) -> bool {
        ctx.data(|d| d.get_temp::<Memoire>(id_memoire()))
            .is_some_and(|m| m.depasse)
    }

    /// N1, la garde : un contenu plus large que sa place se voit (`depasse`), un contenu qui se replie non ; et la
    /// feuille qui l'a vu le dit comme une coupe, en tête de l'aperçu. Sans elle, un texte qui ne se replie pas
    /// sortirait de la feuille sans que rien ne le dise.
    #[test]
    fn un_texte_plus_large_que_la_feuille_compte_comme_coupe() {
        let ctx = egui::Context::default();
        crate::dessin::polices(&ctx);
        let long = "W".repeat(80);
        let mut vus = Vec::new();
        textes_peints(&ctx, |ui| {
            for repli in [false, true] {
                ui.allocate_ui(egui::vec2(300.0, 2000.0), |ui| {
                    vus.push(depasse(ui, |ui| {
                        if repli {
                            ui.horizontal_wrapped(|ui| {
                                ui.add(egui::Label::new(signe_par_signe(&long, police(12.0), Color32::WHITE)).wrap());
                                ui.add(egui::Label::new(signe_par_signe(&long, mono(12.0), Color32::WHITE)).wrap());
                            });
                        } else {
                            ui.horizontal(|ui| {
                                ui.label(signe_par_signe(&long, police(12.0), Color32::WHITE));
                            });
                        }
                        ui.label(texte("suite", 12.0, Color32::WHITE));
                    }));
                });
            }
        });
        assert_eq!(vus, [true, false]);
        let coupe = crate::tr!(
            "Un texte trop long a été coupé : la suite n'est pas montrée.",
            "A text that was too long was cut: the rest is not shown."
        );
        let a = exemple(true);
        assert!(!a.coupe);
        for vu in [false, true] {
            let mut memoire = Memoire {
                depasse: vu,
                ..Memoire::default()
            };
            let peints = textes_peints(&ctx, |ui| apercu(ui, &a, &mut memoire));
            assert_eq!(peints.iter().any(|g| g.job.text == coupe), vu);
        }
    }

    /// N1, la garde jusqu'au bouton : un aperçu dont un texte a été vu plus large que la feuille (donc pas montré en
    /// entier) ne s'applique pas d'ici ; le pied le dit et n'offre pas « Appliquer cette correction », même après
    /// les 2 secondes. Le même aperçu, montré en entier, l'offre.
    #[test]
    fn un_texte_plus_large_que_la_feuille_empeche_d_appliquer_d_ici() {
        let ctx = egui::Context::default();
        crate::dessin::polices(&ctx);
        let jeton = crate::commandes::Empreinte::lire(&"cd".repeat(16)).unwrap();
        let etat = EtatFeuille::Lue(Lecture::Lue(Box::new(exemple(true))));
        assert_eq!(empechement(&etat, false), Ici::Possible);
        assert!(matches!(empechement(&etat, true), Ici::Empeche(_)));
        let mut f = FeuilleCorrection::essai(Famille::Correction, jeton, etat);
        f.montre = std::time::Instant::now().checked_sub(APERCU_LU + std::time::Duration::from_secs(1));
        let bouton = crate::tr!("Appliquer cette correction", "Apply this fix");
        for depasse in [false, true] {
            let peints = textes_peints(&ctx, |ui| {
                pied(ui, &f, depasse, false);
            });
            assert_eq!(
                peints.iter().any(|g| g.job.text == bouton),
                !depasse,
                "depasse {depasse}"
            );
        }
    }

    /// Une image sans écran de la feuille seule, avec ces événements : vrai si elle se ferme, et les textes peints.
    fn image_de_feuille(
        ctx: &egui::Context,
        ecran: egui::Vec2,
        f: &FeuilleCorrection,
        events: Vec<egui::Event>,
    ) -> (bool, Vec<Arc<Galley>>) {
        let entree = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, ecran)),
            events,
            ..Default::default()
        };
        let mut fermer = false;
        let mut sortie = ctx.run_ui(entree, |ui| fermer = feuille(ui.ctx(), f, false) == Reponse::Fermer);
        sortie.textures_delta.clear();
        let mut g = Vec::new();
        for c in &sortie.shapes {
            galeries(&c.shape, &mut g);
        }
        (fermer, g)
    }

    /// Le nombre de mises en page dans la mémoire d'egui. Une fonction plutôt que la méthode nommée :
    /// `FontsView::num_galleys_in_cache` lie la durée de vie de la vue à son type, et `fonts` en demande une valable
    /// pour toutes.
    fn en_memoire(f: &egui::epaint::FontsView<'_>) -> usize {
        f.num_galleys_in_cache()
    }

    fn gardees(ctx: &egui::Context) -> HashMap<Cle, Arc<Galley>> {
        ctx.data(|d| d.get_temp::<Memoire>(id_memoire()))
            .map(|m| m.textes.into_iter().map(|(cle, mise)| (cle, mise.galley)).collect())
            .unwrap_or_default()
    }

    /// Vérification de Fable n° 4, N6 : la feuille met en page ses textes de Vanguard une fois, puis les reprend ; elle
    /// les refait quand le texte, la largeur, l'échelle ou les polices changent, et les oublie en se fermant. Sans
    /// mémoire, chaque texte signe par signe est remis en page (et haché en entier par egui) à chaque image.
    #[test]
    fn la_feuille_garde_ses_mises_en_page() {
        use crate::donnees::correction::{AVANT_MAX, COMMANDES_MAX};
        let ctx = egui::Context::default();
        crate::dessin::polices(&ctx);
        let jeton = crate::commandes::Empreinte::lire(&"cd".repeat(16)).unwrap();
        let mut a = exemple(true);
        a.commandes = (0..COMMANDES_MAX).map(|i| format!("chmod 600 ~/.ssh/id_{i}")).collect();
        a.avant = (0..AVANT_MAX)
            .map(|i| Avant {
                geste: format!("droits|/home/alice/.ssh/id_{i}"),
                valeur: Some(format!("06{i}")),
            })
            .collect();
        let vanguard = 2 + COMMANDES_MAX + 2 * AVANT_MAX;
        let mut f = FeuilleCorrection::essai(
            Famille::Correction,
            jeton,
            EtatFeuille::Lue(Lecture::Lue(Box::new(a.clone()))),
        );
        let grand = egui::vec2(1280.0, 800.0);
        // Pendant le fondu d'ouverture de la feuille, egui peint des copies éclaircies des mises en page : on attend
        // qu'il soit fini (une image sans écran avance l'horloge d'un soixantième de seconde).
        let fondu = ctx.global_style().animation_time * 60.0;
        let mut images = 0.0_f32;
        while images < fondu + 4.0 {
            image_de_feuille(&ctx, grand, &f, Vec::new());
            images += 1.0;
        }
        let avant = gardees(&ctx);
        let (_, peints) = image_de_feuille(&ctx, grand, &f, Vec::new());
        let apres = gardees(&ctx);
        assert_eq!(
            apres.len(),
            vanguard,
            "chaque texte de Vanguard a sa mise en page gardée"
        );
        // Reprises telles quelles, et ce sont elles qui sont peintes.
        assert!(
            apres
                .iter()
                .all(|(cle, g)| avant.get(cle).is_some_and(|v| Arc::ptr_eq(v, g)))
        );
        assert!(peints.iter().any(|g| Arc::ptr_eq(g, &apres[&Cle::Message])));
        assert!(peints.iter().any(|g| Arc::ptr_eq(g, &apres[&Cle::Commande(0)])));
        // Ce qu'egui a mis en page à cette image (sa mémoire ne garde que ce qui a servi) : les seuls textes de la
        // fenêtre, aucun de Vanguard. Une largeur qui ne tombe pas sur un point entier (valeurs d'avant, « pourquoi
        // pas ») ne doit pas faire refaire la mise en page : egui l'arrondit avant de mettre en page.
        let faites = ctx.fonts(en_memoire);
        // (16 depuis l'étape 5 : le bouton « Appliquer cette correction » s'y ajoute ; tous des textes de la fenêtre.)
        assert!(faites <= 16, "{faites} mises en page par image");

        // Un autre texte : refait.
        let mut b = a.clone();
        b.message = "Clé id_<b> lisible par d'autres".into();
        f.etat = EtatFeuille::Lue(Lecture::Lue(Box::new(b)));
        let (_, peints) = image_de_feuille(&ctx, grand, &f, Vec::new());
        let apres = gardees(&ctx);
        assert_eq!(apres[&Cle::Message].job.text, "Clé id_<b> lisible par d'autres");
        assert!(peints.iter().any(|g| Arc::ptr_eq(g, &apres[&Cle::Message])));
        assert!(Arc::ptr_eq(&apres[&Cle::Commande(0)], &avant[&Cle::Commande(0)]));

        // Une fenêtre plus étroite : tout est refait à la nouvelle largeur.
        let etroit = egui::vec2(700.0, 800.0);
        let largeur = etroit.x - 2.0 * MARGE;
        assert!(largeur < LARGEUR);
        for _ in 0..3 {
            image_de_feuille(&ctx, etroit, &f, Vec::new());
        }
        let apres = gardees(&ctx);
        assert_eq!(apres.len(), vanguard);
        for (cle, g) in &apres {
            assert!(!Arc::ptr_eq(g, &avant[cle]), "mise en page gardée d'une autre largeur");
            assert!(
                g.job.wrap.max_width <= largeur,
                "mise en page à {} pour une feuille de {largeur}",
                g.job.wrap.max_width
            );
        }

        // Une autre échelle : refaite à cette échelle.
        ctx.set_pixels_per_point(2.0);
        for _ in 0..3 {
            image_de_feuille(&ctx, etroit, &f, Vec::new());
        }
        let deux = gardees(&ctx);
        assert_eq!(deux.len(), vanguard);
        assert!(deux.values().all(|g| g.pixels_per_point.to_bits() == 2.0f32.to_bits()));

        // D'autres polices : egui vide sa mémoire des mises en page (et son atlas des signes) ; rien de gardé ne sert.
        let mut polices = ctx.fonts(|f| f.definitions().clone());
        polices.families.insert(
            FontFamily::Proportional,
            vec!["inter".into(), "mono".into(), "inter-m".into()],
        );
        ctx.set_fonts(polices);
        for _ in 0..3 {
            image_de_feuille(&ctx, etroit, &f, Vec::new());
        }
        let neuves = gardees(&ctx);
        assert_eq!(neuves.len(), vanguard);
        assert!(
            neuves.iter().all(|(cle, g)| !Arc::ptr_eq(g, &deux[cle])),
            "mise en page d'avant les polices"
        );

        // L'autre thème : chaque texte est refait à ses couleurs.
        let sombre = pal().encre;
        crate::dessin::appliquer_theme(&ctx, false);
        assert_ne!(pal().encre, sombre);
        image_de_feuille(&ctx, etroit, &f, Vec::new());
        let claires = gardees(&ctx);
        assert_eq!(claires.len(), vanguard);
        assert!(
            claires[&Cle::Message]
                .job
                .sections
                .iter()
                .all(|s| s.format.color == pal().encre)
        );

        // Une autre encre dans le même thème : egui garde son atlas des signes (le témoin ne change pas), seule la
        // couleur demandée dit que la mise en page gardée n'est plus la bonne.
        let mut autre = pal();
        autre.encre = Color32::from_rgb(1, 2, 3);
        crate::dessin::appliquer_palette(&ctx, autre, false);
        image_de_feuille(&ctx, etroit, &f, Vec::new());
        let recolorees = gardees(&ctx);
        assert_eq!(recolorees.len(), vanguard);
        assert!(
            recolorees[&Cle::Message]
                .job
                .sections
                .iter()
                .all(|s| s.format.color == autre.encre)
        );

        // Échap ferme la feuille : sa mémoire part avec elle.
        let echap = egui::Event::Key {
            key: egui::Key::Escape,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        };
        let (fermee, _) = image_de_feuille(&ctx, etroit, &f, vec![echap]);
        assert!(fermee);
        assert!(gardees(&ctx).is_empty());
        image_de_feuille(&ctx, etroit, &f, Vec::new());
        assert_eq!(gardees(&ctx).len(), vanguard);
        oublier(&ctx);
        assert!(ctx.data(|d| d.get_temp::<Memoire>(id_memoire())).is_none());
    }

    /// N6 : le coût par image du plus grand aperçu permis (64 commandes et 64 valeurs d'avant de `TEXTE_MAX` signes,
    /// environ 780 000 signes), et d'un aperçu ordinaire ; à lancer en `--release`, sortie montrée (`--nocapture`).
    #[test]
    #[ignore = "outil : mesure du coût par image de la feuille (N6), à lancer en --release --nocapture"]
    fn mesurer_le_cout_par_image() {
        use std::time::{Duration, Instant};
        let ctx = egui::Context::default();
        crate::dessin::polices(&ctx);
        let jeton = crate::commandes::Empreinte::lire(&"cd".repeat(16)).unwrap();
        let long = |graine: &str| -> String {
            format!("{graine} chmod 600 ~/.ssh/id_x && ")
                .repeat(200)
                .chars()
                .take(crate::nettoyage::TEXTE_MAX)
                .collect()
        };
        let mut grand = exemple(false);
        grand.message = long("message");
        grand.action = long("action");
        grand.pourquoi_pas = long("pourquoi");
        grand.commandes = (0..crate::donnees::correction::COMMANDES_MAX)
            .map(|i| long(&format!("c{i}")))
            .collect();
        grand.avant = (0..crate::donnees::correction::AVANT_MAX)
            .map(|i| Avant {
                geste: long(&format!("g{i}")),
                valeur: Some(long(&format!("v{i}"))),
            })
            .collect();
        let signes: usize = [&grand.message, &grand.action, &grand.pourquoi_pas]
            .into_iter()
            .chain(&grand.commandes)
            .chain(
                grand
                    .avant
                    .iter()
                    .flat_map(|v| std::iter::once(&v.geste).chain(&v.valeur)),
            )
            .map(|t| t.chars().count())
            .sum();
        for (nom, a) in [("ordinaire", exemple(true)), ("le plus grand", grand)] {
            let f = FeuilleCorrection::essai(Famille::Correction, jeton, EtatFeuille::Lue(Lecture::Lue(Box::new(a))));
            let image = || {
                let entree = egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1280.0, 800.0))),
                    ..Default::default()
                };
                let debut = Instant::now();
                let sortie = ctx.run_ui(entree, |ui| {
                    feuille(ui.ctx(), &f, false);
                });
                let dessin = debut.elapsed();
                let debut = Instant::now();
                let _ = ctx.tessellate(sortie.shapes, sortie.pixels_per_point);
                (dessin, debut.elapsed())
            };
            let premieres = [image(), image(), image()];
            let n: u32 = 30;
            let (mut dessin, mut maillage) = (Duration::ZERO, Duration::ZERO);
            for _ in 0..n {
                let (d, m) = image();
                dessin += d;
                maillage += m;
            }
            eprintln!(
                "{nom} : 3 premières images {:?} ; ensuite {:?} par image (+ maillage {:?})",
                premieres.map(|(d, m)| d + m),
                dessin / n,
                maillage / n
            );
        }
        eprintln!("signes de Vanguard dans le plus grand : {signes}");
    }

    /// A1, par l'image : dans la feuille, une suite de deux signes (« -> », « => », « <- ») ne se peint pas comme la
    /// flèche qu'une ligature d'Inter en ferait, ni dans le message (15 points) ni dans l'action (14 points).
    #[test]
    fn une_suite_ne_se_peint_pas_comme_un_signe() {
        let ctx = egui::Context::default();
        crate::dessin::polices(&ctx);
        let image = |t: &str| {
            let mut a = exemple(true);
            a.message = format!("message {t}");
            a.action = format!("action {t}");
            let mut memoire = Memoire::default();
            let peints = textes_peints(&ctx, |ui| apercu(ui, &a, &mut memoire));
            let atlas = ctx.fonts_mut(|f| f.image());
            [&a.message, &a.action].map(|t| {
                let g = peints.iter().find(|g| g.job.text == *t).unwrap();
                crate::dessin::encre::image(&atlas, g, egui::Vec2::ZERO)
            })
        };
        for (suite, signe) in [("x->y", "x\u{2192}y"), ("x=>y", "x\u{21d2}y"), ("x<-y", "x\u{2190}y")] {
            let (deux, un) = (image(suite), image(signe));
            assert_ne!(deux[0], un[0], "message : {suite} se peint comme {signe}");
            assert_ne!(deux[1], un[1], "action : {suite} se peint comme {signe}");
        }
    }
}

//! Mettre Vanguard à jour depuis la fenêtre : `vanguard se-mettre-a-jour --voir --json`, puis
//! `vanguard se-mettre-a-jour --appliquer --accord <accord> --json`, sur le modèle d'une correction (conception, 2.3).
//!
//! `--voir` dit exactement ce qui s'installerait, sans rien changer à l'ordinateur ni aux programmes : d'où vient
//! le programme (la clé VANGUARD d'où tourne Vanguard, ou la dernière version publiée sur GitHub, signée par l'auteur
//! et vérifiée), sa version, son empreinte SHA-256 et sa taille, et chaque programme d'ici qu'il remplacerait avec sa
//! version d'aujourd'hui. L'accord résume tout cela. Rien de plus récent : « à jour », seulement quand c'est vérifié ;
//! une réponse qui manque, un manifeste plus vieux que celui déjà vu ou une copie illisible disent « non vérifié »,
//! jamais « à jour ». Ce qui demande une question (repartir des versions vues) reste au terminal. Ce que `--voir`
//! écrit, liste fermée : son entrée au carnet des aperçus (proposé seulement), et, comme le terminal pour tout
//! manifeste signé vu, la plus haute version vue et la révocation de la clé principale ; avec eux, le registre des
//! sceaux, son témoin et ses verrous (`lecture_seule::EXEMPTES_CARNET`, `EXEMPTES_VUES`).
//!
//! `--appliquer` refait tout l'aperçu, exige le même accord (une nouvelle version publiée entre-temps, une clé
//! changée, une copie remplacée le changent : refusé), consomme l'aperçu au carnet (2 s à 10 min, une seule fois),
//! puis seulement retient le manifeste, télécharge et vérifie le programme (taille et empreinte signées), et le pose
//! par le chemin de toujours (`installer` : version gravée revérifiée, écrit à côté, relu et comparé, essayé sauf
//! sous Windows où `essayer` ne lance rien, mis en place d'un coup). Le reste `.ancien` d'une mise à jour faite
//! pendant que la copie tournait (Windows) s'efface après l'accord, comme au terminal. Jamais vers une version plus
//! ancienne. La fenêtre ne télécharge, ne vérifie et n'écrit rien.
//!
//! La fenêtre de Vanguard (`vanguard-fenetre`) posée à côté d'un programme remplacé le suit, montrée dans l'aperçu
//! comme une ligne de plus (donc dans l'accord) : celle de la clé si c'est bien celle que grave son programme, ou
//! celle de la nouvelle version, téléchargée après l'accord seulement et vérifiée contre l'empreinte gravée dans le
//! programme vérifié (`sa_fenetre`). Sa ligne du résultat relit la fenêtre posée : « à jour » seulement si c'est la
//! bonne.
//!
//! Il n'y a qu'une mise à jour à la fois : le jeton est fixe (`JETON`). Les chemins montrés sont « ~/… » sous le
//! dossier personnel ; le chemin de la clé n'est pas montré (il dit le nom du compte), seulement « clé VANGUARD ».

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::github::{self, Publiee};
use super::{
    Essai, Etat, Lu, TAILLE_MAX, Verdict, Version, ecrire, installer, lire_octets, lire_programme, sa_fenetre,
};
use crate::machine::carnet;
use crate::modele::Echec;
use crate::ui::{GRAS, RESET, VERT};
use crate::{tr, trf, trp};

/// La sorte de l'aperçu, dans la dernière ligne de `--voir`.
pub(crate) const SORTE_VOIR: &str = "voir-mise-a-jour";
/// La sorte du geste qui installe, dans le carnet, la dernière ligne et le journal.
pub(crate) const SORTE: &str = "mettre-a-jour";
/// Le jeton de la mise à jour : une seule à la fois, aucune liste ne le donne. « mise-a-jour-vang » en hexadécimal.
pub(crate) const JETON: &str = "6d6973652d612d6a6f75722d76616e67";
/// Le contexte de l'accord : celui d'une correction ou d'une annulation ne vaut jamais ici, ni l'inverse.
const CONTEXTE_ACCORD: &str = "vanguard accord v1 mise-a-jour";

/// Un programme d'ici que la mise à jour remplacerait.
#[derive(serde::Serialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Cible {
    /// Son chemin, « ~/… » sous le dossier personnel.
    pub chemin: String,
    /// Sa version d'aujourd'hui (« d'avant la 0.78 » sans version gravée).
    pub version: String,
}

/// Tout ce que l'aperçu donne à montrer ; chaque champ est dans l'accord (`champs`).
#[derive(serde::Serialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Apercu {
    pub version: String,
    pub langue: String,
    pub jeton: String,
    /// « cle » (la clé VANGUARD d'où tourne Vanguard) ou « github » (signée par l'auteur, vérifiée).
    pub origine: String,
    /// La version qui s'installerait.
    pub visee: String,
    /// L'empreinte SHA-256 du programme qui s'installerait, 64 chiffres hexadécimaux.
    pub sha256: String,
    /// Sa taille, en octets.
    pub taille: u64,
    pub cibles: Vec<Cible>,
}

impl Apercu {
    fn champs(&self) -> Vec<(&'static str, Vec<u8>)> {
        use crate::machine::apercu::{bloc, liste};
        let cibles: Vec<Vec<u8>> = self
            .cibles
            .iter()
            .map(|c| {
                let mut o = Vec::new();
                bloc(&mut o, c.chemin.as_bytes());
                bloc(&mut o, c.version.as_bytes());
                o
            })
            .collect();
        vec![
            ("version", self.version.clone().into_bytes()),
            ("langue", self.langue.clone().into_bytes()),
            ("jeton", self.jeton.clone().into_bytes()),
            ("origine", self.origine.clone().into_bytes()),
            ("visee", self.visee.clone().into_bytes()),
            ("sha256", self.sha256.clone().into_bytes()),
            ("taille", self.taille.to_le_bytes().to_vec()),
            ("cibles", liste(cibles.iter().map(Vec::as_slice))),
        ]
    }

    pub(crate) fn accord(&self) -> String {
        crate::machine::apercu::accord_de(CONTEXTE_ACCORD, self.champs())
    }
}

/// Pourquoi rien n'est proposé, ou refusé.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refus {
    /// Vérifié : rien de plus récent que ce qui est ici (la version publiée ou celle de la clé).
    AJour(String),
    /// Rien ici que la mise à jour remplacerait (ni copie, ni programme lancé hors de la clé).
    Rien,
    /// Pas vérifié : pourquoi. Jamais « à jour ».
    NonVerifie(String),
    /// L'aperçu sans la lecture seule posée par main avant tout : code 2.
    SansLectureSeule,
    /// Accord mal formé : code 2.
    MalForme,
    /// En lecture seule : code 2.
    LectureSeule,
    /// L'état relu ne donne plus le même accord.
    Change,
    Carnet(carnet::Refus),
}

impl Refus {
    pub(crate) fn raison(&self) -> String {
        match self {
            Refus::AJour(v) => trf!(
                "Vanguard est à jour ici (dernière version : {})",
                "Vanguard is up to date here (latest version: {})",
                v
            ),
            Refus::Rien => tr!(
                "rien ici que la mise à jour remplacerait",
                "nothing here that the update would replace"
            )
            .to_string(),
            Refus::NonVerifie(r) => trf!("non vérifié : {}", "not verified: {}", r),
            Refus::SansLectureSeule => tr!(
                "l'aperçu se demande par « vanguard se-mettre-a-jour --voir », « se-mettre-a-jour » en premier : rien d'autre ne le donne",
                "the preview is asked for with “vanguard se-mettre-a-jour --voir”, “se-mettre-a-jour” first: nothing else gives it"
            )
            .to_string(),
            Refus::MalForme => tr!(
                "accord (64 chiffres hexadécimaux minuscules) mal formé",
                "malformed agreement (64 lowercase hexadecimal digits)"
            )
            .to_string(),
            Refus::LectureSeule => crate::machine::appliquer::lecture_seule(),
            Refus::Change => tr!(
                "ça a changé depuis l'aperçu (nouvelle version, clé ou copie changée), ou il a été fait dans une autre langue (VANGUARD_LANG, langue du système) : rien n'a été fait, refaites l'aperçu dans la langue du geste",
                "it changed since the preview (new version, key or copy changed), or the preview was made in another language (VANGUARD_LANG, system language): nothing was done, show the preview again in the language of the action"
            )
            .to_string(),
            Refus::Carnet(r) => r.raison(),
        }
    }

    /// L'état dit à la fenêtre : « a-jour », « rien », « non-verifie » ou « refuse ».
    fn etat(&self) -> &'static str {
        match self {
            Refus::AJour(_) => "a-jour",
            Refus::Rien => "rien",
            Refus::NonVerifie(_) => "non-verifie",
            _ => "refuse",
        }
    }

    /// Le mot du refus au journal : fixe.
    fn code(&self) -> &'static str {
        match self {
            Refus::AJour(_) => "a-jour",
            Refus::Rien => "rien",
            Refus::NonVerifie(_) => "non-verifie",
            Refus::SansLectureSeule => "sans-lecture-seule",
            Refus::MalForme => "mal-forme",
            Refus::LectureSeule => "lecture-seule",
            Refus::Change => "change-depuis",
            Refus::Carnet(r) => r.code(),
        }
    }

    fn code_de_sortie(&self) -> i32 {
        match self {
            Refus::SansLectureSeule | Refus::MalForme | Refus::LectureSeule => 2,
            _ => 1,
        }
    }
}

/// Ce que l'ordinateur répond : le vrai (`Ici`), ou celui d'un essai.
pub(super) trait Monde {
    /// L'état de la copie face à la clé d'où tourne Vanguard, sans rien effacer.
    fn etat_cle(&self) -> Etat;
    /// Ce que la mise à jour depuis GitHub remplacerait (`cibles_github`).
    fn cibles_github(&self) -> Vec<PathBuf>;
    /// La copie de cet ordinateur.
    fn copie(&self) -> PathBuf;
    fn dossier_sur(&self) -> bool;
    fn vues_douteuses(&self) -> bool;
    /// La dernière version publiée, manifeste reçu et signature vérifiée, sans rien retenir.
    fn derniere(&self) -> Result<Publiee, Echec>;
    /// `github::juger_la_vue` : sans rien écrire.
    fn juger_la_vue(&self, p: &Publiee) -> Result<(), Echec>;
    fn courante(&self) -> Option<Version>;
    fn maintenant(&self) -> u64;
    /// Après l'accord seulement : retenir le manifeste (`github::retenir`).
    fn retenir(&self, p: &Publiee) -> Result<(), Echec>;
    /// Pendant l'aperçu, ce que le terminal retient d'un manifeste vu, signature vérifiée et pas plus vieux que le
    /// déjà vu : la plus haute version vue et la révocation (`github::retenir_pendant_un_apercu`). Rien d'autre.
    fn retenir_la_vue(&self, p: &Publiee) -> Result<(), Echec>;
    /// Après l'accord seulement : le programme téléchargé, taille et empreinte signées vérifiées.
    fn telecharger(&self, p: &Publiee) -> Result<Vec<u8>, Echec>;
    /// Après l'accord, et seulement si une fenêtre est posée à côté d'un programme remplacé : la fenêtre de la
    /// dernière version, pas encore jugée (`sa_fenetre` la compare à l'empreinte gravée dans le programme vérifié).
    fn telecharger_fenetre(&self) -> Result<Vec<u8>, String>;
    fn essai(&self) -> Essai;
    /// L'empreinte du programme qui tourne (`protection::cle::image_qui_tourne`) : seuls ses octets se posent depuis
    /// la clé lue à `source` (`gardes_de_la_cle`).
    fn soi(&self, source: &Path) -> Option<String>;
    /// Le dossier du registre scellé où Vanguard note les copies qu'il pose (`programmes_poses`).
    fn registre(&self) -> PathBuf;
    /// `juger_cibles` du terminal : (planchers, à remplacer, doutes à dire), la version publiée étant `publiee`.
    fn juger(&self, cibles: Vec<PathBuf>, publiee: Version) -> (Vec<Version>, Vec<PathBuf>, Vec<String>);
    /// `reconnue_ici` du terminal : la copie à `c` vient-elle de Vanguard (liste des copies, historique signé) ?
    fn reconnue(&self, c: &Path) -> Result<(), String>;
}

/// L'ordinateur pour de vrai.
struct Ici;

impl Monde for Ici {
    fn etat_cle(&self) -> Etat {
        // Jamais pendant les tests : la vraie copie peut être là.
        if cfg!(test) {
            return Etat::Rien;
        }
        super::programme().map_or(Etat::Rien, |exe| {
            super::etat_de(
                &exe,
                crate::reseau::cle_du_programme().as_deref(),
                &self.copie(),
                super::courante(),
                TAILLE_MAX,
            )
        })
    }
    fn cibles_github(&self) -> Vec<PathBuf> {
        super::cibles_github()
    }
    fn copie(&self) -> PathBuf {
        super::copie_de_cet_ordinateur()
    }
    fn dossier_sur(&self) -> bool {
        github::dossier_sur()
    }
    fn vues_douteuses(&self) -> bool {
        github::versions_vues_douteuses()
    }
    fn derniere(&self) -> Result<Publiee, Echec> {
        github::derniere_recue()
    }
    fn juger_la_vue(&self, p: &Publiee) -> Result<(), Echec> {
        github::juger_la_vue(p)
    }
    fn courante(&self) -> Option<Version> {
        super::courante()
    }
    fn maintenant(&self) -> u64 {
        super::maintenant()
    }
    fn retenir(&self, p: &Publiee) -> Result<(), Echec> {
        github::retenir(p)
    }
    fn retenir_la_vue(&self, p: &Publiee) -> Result<(), Echec> {
        github::retenir_pendant_un_apercu(p)
    }
    fn telecharger(&self, p: &Publiee) -> Result<Vec<u8>, Echec> {
        github::programme_verifie(p).map_err(|e| Echec::echoue("mise_a_jour/remise", e))
    }
    fn telecharger_fenetre(&self) -> Result<Vec<u8>, String> {
        github::fenetre_recue()
    }
    fn essai(&self) -> Essai {
        super::essayer
    }
    fn soi(&self, _: &Path) -> Option<String> {
        crate::protection::cle::image_qui_tourne()
    }
    fn registre(&self) -> PathBuf {
        crate::socle::dossier_local()
    }
    fn juger(&self, cibles: Vec<PathBuf>, publiee: Version) -> (Vec<Version>, Vec<PathBuf>, Vec<String>) {
        super::juger_cibles(cibles, publiee, &self.copie(), &self.registre(), super::reconnue_ici)
    }
    fn reconnue(&self, c: &Path) -> Result<(), String> {
        super::reconnue_ici(c).map_err(String::from)
    }
}

/// D'où vient ce qui s'installerait.
#[derive(Debug)]
enum Source {
    /// Les octets du programme lancé depuis la clé, lus pour l'aperçu : ce sont eux qui s'installent ; avec la
    /// fenêtre posée à côté de lui, si c'est bien la sienne (`sa_fenetre::de_la_source`).
    Cle { octets: Vec<u8>, fenetre: Option<Vec<u8>> },
    /// La version publiée : le programme se télécharge après l'accord, vérifié contre sa taille et son empreinte.
    Github(Publiee),
}

/// Ce qui serait fait : l'aperçu, la source, les vrais chemins remplacés, et pour chacun la fenêtre qui suit (même
/// ordre ; `apercu.cibles` montre chaque programme, puis sa fenêtre s'il en a une).
#[derive(Debug)]
struct Plan {
    apercu: Apercu,
    source: Source,
    cibles: Vec<(PathBuf, Version)>,
    fenetres: Vec<Option<PathBuf>>,
    /// Chaque fenêtre telle que relue pour ce plan : la pose la compare à ce qui est là (C-7, relecture 0.96).
    vues: Vec<sa_fenetre::Vue>,
}

fn sha256_hex(octets: &[u8]) -> String {
    github::hex(&Sha256::digest(octets))
}

/// Le chemin d'une copie tel qu'il se montre et part vers la fenêtre : sans le préfixe étendu de Windows quand il
/// peut s'ôter sans rien changer (`sans_prefixe_etendu`), puis « ~/… » sous le dossier personnel.
fn montre(chemin: &Path) -> String {
    crate::optimiser::annulables::chemin_montre(sans_prefixe_etendu(&chemin.to_string_lossy()))
}

/// Sous Windows, `canonicalize` rend `\\?\C:\…`, que la fenêtre refuse (elle ne lit que `C:\…`). Ce préfixe ne
/// s'ôte que pour la forme exacte `\\?\X:\…` dont le reste désigne le même fichier sans lui : moins de 260 octets,
/// chaque nom non vide, sans « . » ni « .. », sans point ni espace à la fin, sans caractère interdit, sans nom réservé
/// (CON, NUL, COM1…). Sinon (`\\?\UNC\…`, un autre préfixe, un nom douteux), le chemin reste tel quel : la fenêtre
/// le refuse, rien ne s'installe. Seul l'affichage change : les fichiers se lisent et s'écrivent par le vrai chemin.
fn sans_prefixe_etendu(chemin: &str) -> &str {
    let Some(reste) = chemin.strip_prefix(r"\\?\") else {
        return chemin;
    };
    let (Some(noms), [lettre, b':', b'\\', _, ..]) = (reste.get(3..), reste.as_bytes()) else {
        return chemin;
    };
    if lettre.is_ascii_alphabetic() && reste.len() < 260 && noms.split('\\').all(nom_sans_prefixe) {
        reste
    } else {
        chemin
    }
}

/// Un nom de chemin qui se lit pareil avec ou sans le préfixe étendu.
fn nom_sans_prefixe(nom: &str) -> bool {
    const RESERVES: [&str; 6] = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"];
    if nom.is_empty() || nom.ends_with(['.', ' ']) {
        return false;
    }
    if nom
        .chars()
        .any(|c| c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '/' | '|' | '?' | '*'))
    {
        return false;
    }
    let base = nom
        .split('.')
        .next()
        .unwrap_or(nom)
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    let numerote = ["COM", "LPT"].iter().any(|p| {
        base.strip_prefix(p).is_some_and(|n| {
            let mut c = n.chars();
            matches!((c.next(), c.next()), (Some('0'..='9' | '¹' | '²' | '³'), None))
        })
    });
    !RESERVES.contains(&base.as_str()) && !numerote
}

fn apercu(
    origine: &str,
    visee: Version,
    sha256: String,
    taille: u64,
    cibles: &[(PathBuf, Version)],
    fenetres: &[Option<PathBuf>],
) -> Apercu {
    // Deux compilations du même numéro se distinguent par leur date (`cote_a_cote`) : jamais « 0.95.0 remplace
    // 0.95.0 » sans dire laquelle est la plus récente.
    let mut visee_dite = ecrire(visee);
    let mut montrees = Vec::with_capacity(cibles.len());
    for ((c, _), f) in cibles.iter().zip(fenetres.iter().chain(std::iter::repeat(&None))) {
        montrees.push(Cible {
            chemin: montre(c),
            version: match lire_programme(c, TAILLE_MAX) {
                Lu::Version(v) => {
                    let (ici, la) = super::cote_a_cote(v, visee);
                    if la != ecrire(visee) {
                        visee_dite = la;
                    }
                    ici
                }
                _ => super::version_affichee(None),
            },
        });
        // Sa fenêtre, remplacée par celle de la nouvelle version : dans l'accord comme le programme.
        if let Some(f) = f {
            montrees.push(Cible {
                chemin: montre(f),
                version: if std::fs::symlink_metadata(f).is_ok() {
                    tr!("sa fenêtre", "its window")
                } else {
                    tr!("sa fenêtre, nouvelle ici", "its window, new here")
                }
                .to_string(),
            });
        }
    }
    let cibles = montrees;
    Apercu {
        version: env!("CARGO_PKG_VERSION").to_string(),
        langue: if crate::langue::anglais() { "en" } else { "fr" }.to_string(),
        jeton: JETON.to_string(),
        origine: origine.to_string(),
        visee: visee_dite,
        sha256,
        taille,
        cibles,
    }
}

/// Pour quoi le plan est fait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pour {
    /// L'aperçu (`--voir`) : un manifeste signé reçu de GitHub y est retenu comme au terminal (`Monde::retenir_la_vue`).
    Voir,
    /// Le geste (`--appliquer`) : rien n'est retenu avant l'accord comparé et consommé.
    Appliquer,
}

/// Ce qui serait installé, relu maintenant, ou pourquoi rien n'est proposé. Rien n'est écrit, sauf, pour l'aperçu,
/// ce que GitHub a montré de signé (`Pour::Voir`).
fn plan(m: &dyn Monde, pour: Pour) -> Result<Plan, Refus> {
    match m.etat_cle() {
        // La clé d'abord : ses octets lus maintenant sont ceux qui s'installeront, version revérifiée.
        Etat::AMettreAJour { source, cle, .. } => {
            let octets = lire_octets(&source, TAILLE_MAX).map_err(Refus::NonVerifie)?;
            if super::version_gravee(&octets) != Some(cle) {
                return Err(Refus::NonVerifie(
                    tr!(
                        "le programme de la clé ne porte plus la version lue",
                        "the key's program no longer carries the version read"
                    )
                    .to_string(),
                ));
            }
            let copie = m.copie();
            // Les gardes du terminal (`remplacer`) : les octets du programme qui tourne, jamais un retour en arrière
            // que la liste des copies interdit. Rejouées après l'accord (`agir` refait le plan).
            // Devant une liste en doute, la sortie (la dernière version signée, reçue de GitHub, qui retient le
            // plancher) se décide dans le terminal : l'aperçu n'écrit rien avant l'accord.
            let au_terminal = || {
                Err(Echec::refuse(
                    "mise_a_jour/apercu",
                    tr!(
                        "dans la fenêtre, la sortie d'une liste en doute se décide dans le terminal (vanguard se-mettre-a-jour)",
                        "in the window, the way out of a list in doubt is decided in the terminal (vanguard se-mettre-a-jour)"
                    ),
                ))
            };
            super::gardes_de_la_cle(
                &octets,
                &copie,
                cle,
                m.soi(&source).as_deref(),
                &m.registre(),
                au_terminal,
            )
            .map_err(|e| Refus::NonVerifie(sans_entete(&e)))?;
            // Sa fenêtre suit si c'est bien la sienne, jugée ici et revérifiée à la pose (`installer_avec`).
            let (fenetre, chemin) = sa_fenetre::de_la_source(&source, &octets)
                .zip(sa_fenetre::pour(&copie))
                .unzip();
            let cibles = vec![(copie, cle)];
            let vues = vec![sa_fenetre::Vue::de(chemin.clone())];
            let fenetres = vec![chemin];
            let taille = u64::try_from(octets.len()).unwrap_or(u64::MAX);
            Ok(Plan {
                apercu: apercu("cle", cle, sha256_hex(&octets), taille, &cibles, &fenetres),
                source: Source::Cle { octets, fenetre },
                cibles,
                fenetres,
                vues,
            })
        }
        Etat::Illisible(e) => Err(Refus::NonVerifie(trf!(
            "la copie de cet ordinateur ne se lit pas, sa version reste inconnue ({})",
            "the copy on this computer cannot be read, its version is unknown ({})",
            e
        ))),
        // Comme au terminal (R3-C3) : une copie plus récente que la clé n'est crue que reconnue (liste des copies
        // posées, ou historique signé) ; sinon jamais « à jour » ni « rien », même si elle grave la version publiée.
        // La dernière version signée, plus récente qu'elle, la remplace pourtant, comme au terminal (`juger_cibles`
        // ne demande la reconnaissance que d'une copie plus récente que la publiée).
        Etat::ClePlusAncienne { .. } => match m.reconnue(&m.copie()) {
            Ok(()) => plan_github(m, pour),
            Err(e) => match plan_github(m, pour) {
                Err(Refus::AJour(_) | Refus::Rien) => Err(Refus::NonVerifie(trf!(
                    "la copie d'ici se dit plus récente que la clé, mais Vanguard ne la reconnaît ni comme celle qu'il a posée ni comme une version publiée ({}) ; elle n'est pas remplacée, la suite se décide dans le terminal (vanguard se-mettre-a-jour)",
                    "the copy on this computer claims to be newer than the key, but Vanguard recognizes it neither as the one it set up nor as a published version ({}); it is not replaced, what to do next is decided in the terminal (vanguard se-mettre-a-jour)",
                    sans_entete(&e)
                ))),
                autre => autre,
            },
        },
        Etat::Rien | Etat::PasDepuisLaCle | Etat::AJour(_) => plan_github(m, pour),
    }
}

fn plan_github(m: &dyn Monde, pour: Pour) -> Result<Plan, Refus> {
    let cibles = m.cibles_github();
    if cibles.is_empty() {
        // R5-REGISTRE-3 : sans copie ici, une liste des copies en doute est dite (le terminal la dit), pas « rien ».
        if let Err(d) = crate::programmes_poses::copie_notee_dans(&m.registre(), &m.copie()) {
            return Err(Refus::NonVerifie(trf!(
                "{} ; la suite se décide dans le terminal (vanguard se-mettre-a-jour)",
                "{}; what to do next is decided in the terminal (vanguard se-mettre-a-jour)",
                sans_entete(&super::doute_sans_copie(d))
            )));
        }
        return Err(Refus::Rien);
    }
    if !m.dossier_sur() {
        return Err(Refus::NonVerifie(
            tr!(
                "lancé en root avec le dossier d'un autre compte : pas de mise à jour depuis GitHub",
                "started as root with another account's folder: no update from GitHub"
            )
            .to_string(),
        ));
    }
    if m.vues_douteuses() {
        return Err(Refus::NonVerifie(
            tr!(
                "les versions déjà vues ici ont été changées hors de Vanguard ; repartir de zéro se décide dans le terminal (vanguard se-mettre-a-jour)",
                "the versions already seen here were changed outside Vanguard; starting over is decided in the terminal (vanguard se-mettre-a-jour)"
            )
            .to_string(),
        ));
    }
    // Chaque copie d'ici lue une fois : sa version, ou « d'avant la 0.78 ». Une seule qui ne se lit pas (un lien vers
    // rien, un dossier, une lecture ratée, disparue depuis la liste) : rien n'est dit à jour ni proposé, son chemin
    // est dit ; elle n'est jamais passée sous silence à côté d'une copie lisible.
    let mut lues: Vec<(PathBuf, Option<Version>)> = Vec::with_capacity(cibles.len());
    for c in cibles {
        let v = match lire_programme(&c, TAILLE_MAX) {
            Lu::Version(v) => Some(v),
            Lu::Ancien => None,
            Lu::Illisible(e) => return Err(copie_illisible(&c, &e)),
            Lu::Absent => return Err(copie_illisible(&c, tr!("disparue", "gone"))),
        };
        lues.push((c, v));
    }
    let p = m
        .derniere()
        .map_err(|e| Refus::NonVerifie(trf!("GitHub : {}", "GitHub: {}", e)))?;
    m.juger_la_vue(&p).map_err(|e| Refus::NonVerifie(e.to_string()))?;
    // L'aperçu retient ce qu'il a vu de signé, comme le terminal : sans quoi un « à jour » ou un aperçu pas accepté ne
    // relèverait rien, et un manifeste plus vieux resservi plus tard serait jugé sans ce plancher. Le geste, lui,
    // retient après l'accord (`agir`).
    if pour == Pour::Voir {
        m.retenir_la_vue(&p).map_err(|e| Refus::NonVerifie(e.to_string()))?;
    }
    // Les doutes du terminal (`juger_cibles`) : une copie plus récente que Vanguard ne reconnaît pas, une liste des
    // copies qui ne peut pas être crue, un retour en arrière. Un seul, et rien n'est dit à jour ni proposé : la sortie
    // (remplacer par la dernière version signée, refaire la liste) se décide au terminal, où chaque doute est dit.
    let (_, jugees, doutes) = m.juger(lues.iter().map(|(c, _)| c.clone()).collect(), p.version);
    if !doutes.is_empty() {
        let dits: Vec<String> = doutes.iter().map(|d| sans_entete(d)).collect();
        return Err(Refus::NonVerifie(trf!(
            "{} ; la suite se décide dans le terminal (vanguard se-mettre-a-jour)",
            "{}; what to do next is decided in the terminal (vanguard se-mettre-a-jour)",
            dits.join(" ; ")
        )));
    }
    // Le plancher : le programme lancé et les copies d'ici (`depuis_github`).
    let ici: Vec<Version> = lues.iter().filter_map(|(_, v)| *v).chain(m.courante()).collect();
    // Seulement ce qui est plus ancien que la version publiée (sans version gravée : d'avant la 0.78, donc plus
    // ancien) ; jamais un plus récent.
    let a_remplacer: Vec<(PathBuf, Version)> = lues
        .into_iter()
        .filter(|(c, v)| v.is_none_or(|v| v < p.version) && jugees.contains(c))
        .map(|(c, _)| (c, p.version))
        .collect();
    if a_remplacer.is_empty() {
        return Err(match super::verdict(p.version, &ici, m.maintenant(), false) {
            Verdict::AJour => Refus::AJour(ecrire(p.version)),
            Verdict::Perimee(age) => Refus::NonVerifie(trf!(
                "la dernière version signée {} ({}) : rien ne prouve que ce soit encore la dernière",
                "the latest signed version {} ({}): nothing proves it is still the latest",
                age,
                ecrire(p.version)
            )),
            Verdict::PlusRecenteIci(v) => Refus::NonVerifie(trf!(
                "Vanguard {} tourne ici, plus récent que la dernière version signée ({}) : un ancien manifeste a pu être remis en place",
                "Vanguard {} runs here, newer than the latest signed version ({}): an old manifest may have been put back",
                ecrire(v),
                ecrire(p.version)
            )),
            // Les doutes sont refusés plus haut, chacun dit.
            Verdict::Doutes => Refus::NonVerifie(
                tr!(
                    "un programme d'ici n'a pas pu être vérifié",
                    "a program here could not be checked"
                )
                .to_string(),
            ),
        });
    }
    // La fenêtre posée à côté d'un programme remplacé le suit (`sa_fenetre::installer_avec_sa_fenetre`).
    let fenetres: Vec<Option<PathBuf>> = a_remplacer.iter().map(|(c, _)| sa_fenetre::a_cote(c)).collect();
    let vues = fenetres.iter().cloned().map(sa_fenetre::Vue::de).collect();
    Ok(Plan {
        apercu: apercu("github", p.version, p.sha256_hex(), p.taille(), &a_remplacer, &fenetres),
        source: Source::Github(p),
        cibles: a_remplacer,
        fenetres,
        vues,
    })
}

/// Une copie d'ici qui ne se lit pas : sa version reste inconnue, rien n'est dit à jour.
/// Un refus ou un doute du terminal, sur une ligne et sans son « non vérifié : » de tête (`Refus::raison` le dit).
fn sans_entete(texte: &str) -> String {
    let une_ligne = texte.split_whitespace().collect::<Vec<_>>().join(" ");
    for tete in [
        "Non vérifié : ",
        "non vérifié : ",
        "Not checked: ",
        "not checked: ",
        "Not verified: ",
        "not verified: ",
    ] {
        if let Some(reste) = une_ligne.strip_prefix(tete) {
            return reste.to_string();
        }
    }
    une_ligne
}

fn copie_illisible(chemin: &Path, pourquoi: &str) -> Refus {
    Refus::NonVerifie(trf!(
        "{} ne se lit pas, sa version reste inconnue ({})",
        "{} cannot be read, its version is unknown ({})",
        montre(chemin),
        pourquoi
    ))
}

/// `vanguard se-mettre-a-jour --voir [--json]` : ce qui s'installerait, rien de changé (s'écrivent seulement le carnet
/// des aperçus quand quelque chose est proposé, et ce que GitHub a montré de signé : voir l'en-tête). Avec `json`, la dernière ligne :
/// `{"geste":"voir-mise-a-jour","issue":"fait"|"refuse","raison","etat":"propose"|"a-jour"|"rien"|"non-verifie"|
/// "refuse","apercu","accord"}`. Code : 0 proposé, 1 rien de proposé, 2 sans la lecture seule.
pub(crate) fn voir(json: bool) -> i32 {
    // Fermé par construction, comme l'aperçu d'une correction : sans la lecture seule posée par main avant tout le
    // reste, rien n'est relu.
    let issue = if crate::autotest::lecture_seule::sans_attente() {
        plan(&Ici, Pour::Voir).map(|p| p.apercu)
    } else {
        Err(Refus::SansLectureSeule)
    };
    if let Ok(a) = &issue {
        carnet::dire_si_remplace(carnet::noter(SORTE, &a.jeton, &a.accord()), json);
    }
    let code = match &issue {
        Ok(_) => 0,
        Err(r) => r.code_de_sortie(),
    };
    if json {
        let ligne = match &issue {
            Ok(a) => serde_json::json!({
                "geste": SORTE_VOIR, "issue": "fait", "raison": "", "etat": "propose", "apercu": a,
                "accord": a.accord()
            }),
            Err(r) => serde_json::json!({
                "geste": SORTE_VOIR, "issue": "refuse", "raison": r.raison(), "etat": r.etat()
            }),
        };
        println!("{ligne}");
    } else {
        match &issue {
            Ok(a) => dire_apercu(a),
            Err(r @ Refus::AJour(_)) => trp!("  {VERT}✔{RESET} {}", "  {VERT}✔{RESET} {}", r.raison()),
            Err(r) => trp!("  ✖ Pas d'aperçu : {}", "  ✖ No preview: {}", r.raison()),
        }
    }
    code
}

fn dire_apercu(a: &Apercu) {
    use crate::machine::apercu::montre_strict;
    let origine = if a.origine == "cle" {
        tr!("la clé VANGUARD", "the VANGUARD key")
    } else {
        tr!(
            "GitHub, signée par l'auteur (signature vérifiée)",
            "GitHub, signed by the author (signature checked)"
        )
    };
    trp!(
        "{GRAS}Mettre Vanguard à jour{RESET} (rien n'a changé) : Vanguard {}, depuis {}",
        "{GRAS}Update Vanguard{RESET} (nothing changed): Vanguard {}, from {}",
        a.visee,
        origine
    );
    trp!(
        "  SHA-256 : {} ({} octets)",
        "  SHA-256: {} ({} bytes)",
        a.sha256,
        a.taille
    );
    for c in &a.cibles {
        trp!(
            "  remplace {} ({})",
            "  replaces {} ({})",
            montre_strict(&c.chemin),
            montre_strict(&c.version)
        );
    }
    trp!("  Accord : {}", "  Consent: {}", a.accord());
}

/// Ce qu'est devenue la demande.
#[derive(Debug, PartialEq, Eq)]
enum Issue {
    /// Fait jusqu'au bout : chaque cible (chemin montré, `Err` : pourquoi elle n'est pas mise à jour, et ce qui est en
    /// place, dit par `installer`).
    Fait(Vec<(String, Result<(), String>)>),
    Refuse(Refus),
    /// Arrêté avant de rien remplacer (téléchargement, manifeste) : pourquoi.
    Echec(String),
}

/// Le geste, l'accord reçu bien formé : relire, comparer, consommer, puis seulement retenir, télécharger, installer.
fn agir(m: &dyn Monde, accord: &str, consommer: impl FnOnce() -> Result<(), carnet::Refus>) -> Issue {
    let plan = match plan(m, Pour::Appliquer) {
        Ok(p) => p,
        Err(r) => return Issue::Refuse(r),
    };
    if plan.apercu.accord() != accord {
        return Issue::Refuse(Refus::Change);
    }
    if let Err(r) = consommer() {
        return Issue::Refuse(Refus::Carnet(r));
    }
    // Le reste d'une mise à jour faite pendant que la copie tournait (Windows, `mettre_en_place`) s'efface comme au
    // terminal (`commande`), après l'accord seulement. Encore lancé, il reste : il partira la fois suivante.
    let _ = std::fs::remove_file(m.copie().with_file_name(format!("{}.ancien", super::NOM)));
    sa_fenetre::effacer_l_ancienne(&m.copie());
    let essai = m.essai();
    let mut faites = Vec::with_capacity(plan.apercu.cibles.len());
    match plan.source {
        Source::Cle { octets, fenetre } => {
            for (((chemin, visee), f), vue) in plan.cibles.iter().zip(&plan.fenetres).zip(&plan.vues) {
                let r = match (&fenetre, f) {
                    (Some(o), Some(f)) => {
                        sa_fenetre::installer_avec(&octets, chemin, *visee, &m.registre(), &m.copie(), essai, o, f, vue)
                    }
                    _ => installer(&octets, chemin, *visee, &m.registre(), &m.copie(), essai),
                };
                noter_la_pose(&mut faites, &octets, chemin, f.as_deref(), r);
            }
        }
        Source::Github(p) => {
            if let Err(e) = m.retenir(&p) {
                return Issue::Echec(e.to_string());
            }
            let octets = match m.telecharger(&p) {
                Ok(o) => o,
                Err(e) => return Issue::Echec(e.to_string()),
            };
            // La fenêtre de la nouvelle version : téléchargée une fois, et seulement s'il en faut une.
            let mut recue: Option<Vec<u8>> = None;
            let mut recevoir = || -> Result<Vec<u8>, String> {
                if let Some(f) = &recue {
                    return Ok(f.clone());
                }
                let f = m.telecharger_fenetre()?;
                recue = Some(f.clone());
                Ok(f)
            };
            for (((chemin, visee), f), vue) in plan.cibles.iter().zip(&plan.fenetres).zip(&plan.vues) {
                let r = sa_fenetre::installer_avec_sa_fenetre(
                    &octets,
                    chemin,
                    *visee,
                    &m.registre(),
                    &m.copie(),
                    essai,
                    vue,
                    &mut recevoir,
                );
                noter_la_pose(&mut faites, &octets, chemin, f.as_deref(), r);
            }
        }
    }
    Issue::Fait(faites)
}

/// La ligne d'un programme posé (ou pas), puis celle de sa fenêtre : relue, elle n'est « à jour » que si c'est bien
/// celle que grave le programme posé ; le programme pas posé, elle dit la même raison (l'ancienne reste ou revient).
fn noter_la_pose(
    faites: &mut Vec<(String, Result<(), String>)>,
    octets: &[u8],
    chemin: &Path,
    fenetre: Option<&Path>,
    r: Result<(), String>,
) {
    let ligne_fenetre = fenetre.map(|f| {
        let rf = match &r {
            Ok(()) => sa_fenetre::posee_juste(octets, f),
            Err(e) => Err(e.clone()),
        };
        (montre(f), rf)
    });
    faites.push((montre(chemin), r));
    faites.extend(ligne_fenetre);
}

/// `vanguard se-mettre-a-jour --appliquer --accord <accord> [--json]`. Code : 0 tout remplacé, 1 refusé, en échec ou
/// une cible pas remplacée, 2 forme refusée. Avec `json`, la dernière ligne : `{"geste":"mettre-a-jour","issue":
/// "fait|refuse|echec","raison","cibles":[{"chemin","issue":"fait|echec","raison"}]}`.
pub(crate) fn appliquer(accord: &str, json: bool) -> i32 {
    let issue = if crate::autotest::lecture_seule::active() {
        Issue::Refuse(Refus::LectureSeule)
    } else if !crate::machine::appliquer::accord_bien_forme(accord) {
        Issue::Refuse(Refus::MalForme)
    } else {
        agir(&Ici, accord, || carnet::consommer(SORTE, JETON, accord))
    };
    noter_au_journal(&issue);
    carnet::noter_altere_au_journal();
    let (code, mot, raison) = match &issue {
        Issue::Fait(c) if c.iter().all(|(_, r)| r.is_ok()) => (0, "fait", String::new()),
        Issue::Fait(_) => (
            1,
            "fait",
            tr!(
                "pas tout mis à jour : la raison de chaque cible dit ce qui est en place",
                "not everything updated: each target's reason says what is in place"
            )
            .to_string(),
        ),
        Issue::Refuse(r) => (r.code_de_sortie(), "refuse", r.raison()),
        Issue::Echec(e) => (1, "echec", e.clone()),
    };
    let cibles: Vec<serde_json::Value> = match &issue {
        Issue::Fait(c) => c
            .iter()
            .map(|(chemin, r)| match r {
                Ok(()) => serde_json::json!({ "chemin": chemin, "issue": "fait", "raison": "" }),
                Err(e) => serde_json::json!({ "chemin": chemin, "issue": "echec", "raison": e }),
            })
            .collect(),
        _ => Vec::new(),
    };
    if json {
        println!(
            "{}",
            serde_json::json!({ "geste": SORTE, "issue": mot, "raison": raison, "cibles": cibles })
        );
    } else {
        match &issue {
            Issue::Fait(c) => {
                for (chemin, r) in c {
                    match r {
                        Ok(()) => trp!(
                            "  {VERT}✔{RESET} {} : à jour.",
                            "  {VERT}✔{RESET} {}: up to date.",
                            chemin
                        ),
                        Err(e) => trp!(
                            "  ✖ {} n'est pas mis à jour : {}",
                            "  ✖ {} is not updated: {}",
                            chemin,
                            e
                        ),
                    }
                }
            }
            Issue::Refuse(_) => trp!("  ✖ Rien n'a changé : {raison}", "  ✖ Nothing changed: {raison}"),
            Issue::Echec(_) => trp!(
                "  ✖ Rien n'est remplacé : {raison}",
                "  ✖ Nothing is replaced: {raison}"
            ),
        }
    }
    code
}

/// La demande au journal des événements, faite ou pas : l'issue typée, jamais un chemin. Un même refus redit dans les
/// 10 minutes n'est noté qu'une fois.
fn noter_au_journal(issue: &Issue) {
    use crate::modele::evenement::{Evenement, Source};
    let texte = match issue {
        Issue::Fait(c) if c.iter().all(|(_, r)| r.is_ok()) => tr!(
            "Mise à jour de Vanguard demandée par un geste : faite",
            "Vanguard update requested by a gesture: done"
        )
        .to_string(),
        Issue::Fait(_) => tr!(
            "Mise à jour de Vanguard demandée par un geste : pas tout remplacé (echec)",
            "Vanguard update requested by a gesture: not everything replaced (echec)"
        )
        .to_string(),
        Issue::Refuse(r) => trf!(
            "Mise à jour de Vanguard demandée par un geste : refusée ({})",
            "Vanguard update requested by a gesture: refused ({})",
            r.code()
        ),
        Issue::Echec(_) => tr!(
            "Mise à jour de Vanguard demandée par un geste : en échec (echec)",
            "Vanguard update requested by a gesture: failed (echec)"
        )
        .to_string(),
    };
    let reussi = matches!(issue, Issue::Fait(c) if c.iter().all(|(_, r)| r.is_ok()));
    let ev = Evenement::action(Source::Vanguard, &texte, reussi, &[]).cle(Some(SORTE));
    if matches!(issue, Issue::Refuse(_))
        && crate::modele::journal::dernier_evenement(|e| e.cle.as_deref() == Some(SORTE), chrono::Duration::minutes(10))
            .is_some_and(|d| d.source == ev.source && d.quoi == ev.quoi)
    {
        return;
    }
    crate::modele::journal::noter(ev);
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::path::Path;

    use super::super::NOM;
    use super::*;
    use crate::demarrage::empreinte_fenetre::marque_d_essai;

    /// R-6 (recontrôle 0.95) : l'accord couvre la langue de l'aperçu ; un geste lancé dans une autre langue est
    /// refusé, et le refus le dit, avec la variable qui la choisit.
    #[test]
    fn refus_change_nomme_la_langue() {
        let fr = Refus::Change.raison();
        assert!(fr.contains("autre langue") && fr.contains("VANGUARD_LANG"), "{fr}");
        let en = crate::langue::en_anglais(|| Refus::Change.raison());
        assert!(en.contains("another language") && en.contains("VANGUARD_LANG"), "{en}");
    }

    /// Un faux programme qui porte la version `v` (« 0.95.0+1790000000 ») ; `reste` le distingue d'un autre.
    fn programme(v: &str, reste: &str) -> Vec<u8> {
        [
            b"prog ".as_slice(),
            &super::super::entete(),
            format!("{v}; {reste}").as_bytes(),
        ]
        .concat()
    }

    fn version(v: &str) -> Version {
        super::super::lire_version(v).unwrap()
    }

    const ESSAI_OK: Essai = |_, _| Ok(());

    /// Un ordinateur inventé : chaque réponse est posée par l'essai ; ce qui se fait après l'accord est compté.
    struct Faux {
        etat: Etat,
        copie: PathBuf,
        cibles: Vec<PathBuf>,
        douteuses: bool,
        derniere: Result<Publiee, String>,
        vue: Result<(), String>,
        courante: Option<Version>,
        maintenant: u64,
        recus: Vec<u8>,
        /// La fenêtre que GitHub donnerait (`telecharger_fenetre`), et combien de fois elle a été demandée.
        fenetre: Result<Vec<u8>, String>,
        fenetres_telechargees: Cell<u32>,
        retenus: Cell<u32>,
        /// Les manifestes retenus pendant un aperçu (`retenir_la_vue`).
        vus: Cell<u32>,
        telecharges: Cell<u32>,
        /// Une fenêtre posée là pendant le téléchargement du programme (un autre programme du compte).
        apparait: Option<PathBuf>,
        /// L'empreinte du programme qui tourne ; `None` : celle de la clé lue (le cas ordinaire).
        #[allow(clippy::option_option)] // None : l'empreinte de la source ; Some(None) : pas d'empreinte
        soi: Option<Option<String>>,
        /// Le registre des copies posées (un dossier à l'essai, vide au départ).
        registre: PathBuf,
        /// Ce que répond la reconnaissance d'une copie plus récente (`reconnue_ici`).
        reconnue: Result<(), String>,
    }

    impl Faux {
        fn nouveau(dossier: &Path) -> Self {
            Self {
                etat: Etat::Rien,
                copie: dossier.join("bin").join(NOM),
                cibles: Vec::new(),
                douteuses: false,
                derniere: Err("pas de réponse".into()),
                vue: Ok(()),
                courante: Some(version("0.94.0+1790000000")),
                maintenant: 1_790_000_000,
                recus: Vec::new(),
                fenetre: Err("pas de fenêtre publiée".into()),
                fenetres_telechargees: Cell::new(0),
                retenus: Cell::new(0),
                vus: Cell::new(0),
                telecharges: Cell::new(0),
                apparait: None,
                soi: None,
                registre: dossier.join("registre"),
                reconnue: Ok(()),
            }
        }
    }

    impl Monde for Faux {
        fn etat_cle(&self) -> Etat {
            self.etat.clone()
        }
        fn cibles_github(&self) -> Vec<PathBuf> {
            self.cibles.clone()
        }
        fn copie(&self) -> PathBuf {
            self.copie.clone()
        }
        fn dossier_sur(&self) -> bool {
            true
        }
        fn vues_douteuses(&self) -> bool {
            self.douteuses
        }
        fn derniere(&self) -> Result<Publiee, Echec> {
            self.derniere.clone().map_err(|e| Echec::echoue("essai", e))
        }
        fn juger_la_vue(&self, _: &Publiee) -> Result<(), Echec> {
            self.vue.clone().map_err(|e| Echec::refuse("essai", e))
        }
        fn courante(&self) -> Option<Version> {
            self.courante
        }
        fn maintenant(&self) -> u64 {
            self.maintenant
        }
        fn retenir(&self, _: &Publiee) -> Result<(), Echec> {
            self.retenus.set(self.retenus.get().saturating_add(1));
            Ok(())
        }
        fn retenir_la_vue(&self, _: &Publiee) -> Result<(), Echec> {
            self.vus.set(self.vus.get().saturating_add(1));
            Ok(())
        }
        fn telecharger(&self, _: &Publiee) -> Result<Vec<u8>, Echec> {
            self.telecharges.set(self.telecharges.get().saturating_add(1));
            if let Some(f) = &self.apparait {
                std::fs::write(f, b"fenetre apparue").map_err(|e| Echec::echoue("essai", e.to_string()))?;
            }
            Ok(self.recus.clone())
        }
        fn telecharger_fenetre(&self) -> Result<Vec<u8>, String> {
            self.fenetres_telechargees
                .set(self.fenetres_telechargees.get().saturating_add(1));
            self.fenetre.clone()
        }
        fn essai(&self) -> Essai {
            ESSAI_OK
        }
        fn soi(&self, source: &Path) -> Option<String> {
            self.soi.clone().unwrap_or_else(|| {
                std::fs::read(source)
                    .ok()
                    .map(|o| blake3::hash(&o).to_hex().to_string())
            })
        }
        fn registre(&self) -> PathBuf {
            self.registre.clone()
        }
        fn juger(&self, cibles: Vec<PathBuf>, publiee: Version) -> (Vec<Version>, Vec<PathBuf>, Vec<String>) {
            let reconnue = |_: &Path| self.reconnue.clone().map_err(|e| Echec::refuse("essai", e));
            super::super::juger_cibles(cibles, publiee, &self.copie, &self.registre, reconnue)
        }
        fn reconnue(&self, _: &Path) -> Result<(), String> {
            self.reconnue.clone()
        }
    }

    fn dossier(nom: &str) -> PathBuf {
        let d = crate::essais::temporaire().join(format!("vanguard-maj-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    const CONSOMME: fn() -> Result<(), carnet::Refus> = || Ok(());

    /// Depuis la clé : l'aperçu dit la version, l'empreinte des octets lus et la copie remplacée ; un autre accord ne
    /// fait rien ; l'accord montré pose exactement ces octets.
    #[test]
    fn la_cle_ne_pose_que_ce_que_l_apercu_a_montre() {
        let d = dossier("cle");
        let mut f = Faux::nouveau(&d);
        let source = d.join("cle").join(NOM);
        let neuf = programme("0.95.0+1790000000", "cle");
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::write(&source, &neuf).unwrap();
        std::fs::create_dir_all(f.copie.parent().unwrap()).unwrap();
        let ancien = programme("0.94.0+1780000000", "copie");
        std::fs::write(&f.copie, &ancien).unwrap();
        f.etat = Etat::AMettreAJour {
            source: source.clone(),
            copie: Some(version("0.94.0+1780000000")),
            cle: version("0.95.0+1790000000"),
        };
        let a = plan(&f, Pour::Voir).unwrap().apercu;
        assert_eq!(a.origine, "cle");
        assert_eq!(a.visee, "0.95.0");
        assert_eq!(a.sha256, sha256_hex(&neuf));
        assert_eq!(a.cibles.len(), 1);
        assert_eq!(a.cibles[0].version, "0.94.0");
        assert_eq!(a.jeton, JETON);
        // Un accord qui n'est pas celui-là : rien.
        let autre = "ab".repeat(32);
        assert_eq!(agir(&f, &autre, CONSOMME), Issue::Refuse(Refus::Change));
        assert_eq!(std::fs::read(&f.copie).unwrap(), ancien);
        // Le carnet refuse : rien.
        let refuse = || Err(carnet::Refus::TropJeune);
        assert_eq!(
            agir(&f, &a.accord(), refuse),
            Issue::Refuse(Refus::Carnet(carnet::Refus::TropJeune))
        );
        assert_eq!(std::fs::read(&f.copie).unwrap(), ancien);
        // L'accord montré : posé.
        let Issue::Fait(c) = agir(&f, &a.accord(), CONSOMME) else {
            panic!("pas fait")
        };
        assert!(c.iter().all(|(_, r)| r.is_ok()), "{c:?}");
        assert_eq!(std::fs::read(&f.copie).unwrap(), neuf);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// La clé changée entre l'aperçu et l'accord (même version, autres octets) : refusé, rien posé.
    #[test]
    fn une_cle_changee_apres_l_apercu_est_refusee() {
        let d = dossier("cle-changee");
        let mut f = Faux::nouveau(&d);
        let source = d.join("cle").join(NOM);
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::write(&source, programme("0.95.0+1790000000", "montre")).unwrap();
        std::fs::create_dir_all(f.copie.parent().unwrap()).unwrap();
        let ancien = programme("0.94.0+1780000000", "copie");
        std::fs::write(&f.copie, &ancien).unwrap();
        f.etat = Etat::AMettreAJour {
            source: source.clone(),
            copie: Some(version("0.94.0+1780000000")),
            cle: version("0.95.0+1790000000"),
        };
        let accord = plan(&f, Pour::Voir).unwrap().apercu.accord();
        std::fs::write(&source, programme("0.95.0+1790000000", "autre")).unwrap();
        assert_eq!(agir(&f, &accord, CONSOMME), Issue::Refuse(Refus::Change));
        assert_eq!(std::fs::read(&f.copie).unwrap(), ancien);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une clé prête à remplacer la copie (0.94) par la 0.95 : l'ordinateur inventé et l'ancienne copie.
    fn cle_prete(nom: &str) -> (PathBuf, Faux, Vec<u8>) {
        let d = dossier(nom);
        let mut f = Faux::nouveau(&d);
        let source = d.join("cle").join(NOM);
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::write(&source, programme("0.95.0+1790000000", "cle")).unwrap();
        std::fs::create_dir_all(f.copie.parent().unwrap()).unwrap();
        let ancien = programme("0.94.0+1780000000", "copie");
        std::fs::write(&f.copie, &ancien).unwrap();
        f.etat = Etat::AMettreAJour {
            source,
            copie: Some(version("0.94.0+1780000000")),
            cle: version("0.95.0+1790000000"),
        };
        (d, f, ancien)
    }

    /// Les gardes du terminal tiennent aussi pour l'aperçu de la clé (`gardes_de_la_cle`) : seuls les octets du
    /// programme qui tourne se posent ; sans son empreinte, rien. Le changement après l'aperçu est revu à l'accord.
    #[test]
    fn la_cle_d_un_autre_programme_ne_se_pose_pas_par_l_apercu() {
        let (d, mut f, ancien) = cle_prete("cle-pas-soi");
        let accord = plan(&f, Pour::Voir).unwrap().apercu.accord();
        for (soi, dit) in [
            (Some("0".repeat(64)), tr!("a changé", "has changed")),
            (None, tr!("ne se lit pas", "cannot be read")),
        ] {
            f.soi = Some(soi);
            match plan(&f, Pour::Voir) {
                Err(Refus::NonVerifie(e)) => assert!(e.contains(dit), "{e}"),
                autre => panic!("{:?}", autre.map(|p| p.apercu)),
            }
            match agir(&f, &accord, CONSOMME) {
                Issue::Refuse(Refus::NonVerifie(e)) => assert!(e.contains(dit), "{e}"),
                autre => panic!("{autre:?}"),
            }
            assert_eq!(std::fs::read(&f.copie).unwrap(), ancien);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// R3-C1 par l'aperçu : une copie plus récente notée par Vanguard (0.96), remplacée depuis par une plus ancienne,
    /// n'est pas écrasée par la clé (0.95) : refusé avant l'aperçu, rien posé.
    #[test]
    fn l_apercu_de_la_cle_ne_revient_pas_en_arriere() {
        let (d, f, ancien) = cle_prete("cle-retour");
        crate::programmes_poses::copie_posee_dans(&f.registre, &f.copie, &programme("0.96.0+1795000000", "notee"));
        match plan(&f, Pour::Voir) {
            Err(Refus::NonVerifie(e)) => assert!(e.contains("0.96.0"), "{e}"),
            autre => panic!("{:?}", autre.map(|p| p.apercu)),
        }
        assert_eq!(std::fs::read(&f.copie).unwrap(), ancien);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Relecture adverse : devant une liste des copies en doute, la sortie (dernière version signée, reçue de GitHub,
    /// qui retient le plancher) n'est pas demandée par l'aperçu : rien n'est écrit avant l'accord, le terminal décide.
    #[test]
    fn l_apercu_de_la_cle_devant_une_liste_en_doute_renvoie_au_terminal() {
        let (d, f, ancien) = cle_prete("cle-doute");
        crate::programmes_poses::copie_posee_dans(&f.registre, &f.copie, &ancien);
        std::fs::remove_file(f.registre.join(crate::programmes_poses::FICHIER)).unwrap();
        let accord = format!("sha256:{}", "0".repeat(64));
        for essai in [plan(&f, Pour::Voir).err(), plan(&f, Pour::Appliquer).err()] {
            match essai {
                Some(Refus::NonVerifie(e)) => assert!(e.contains("se-mettre-a-jour"), "{e}"),
                autre => panic!("{autre:?}"),
            }
        }
        assert!(matches!(
            agir(&f, &accord, CONSOMME),
            Issue::Refuse(Refus::NonVerifie(_))
        ));
        assert_eq!((f.retenus.get(), f.vus.get(), f.telecharges.get()), (0, 0, 0));
        assert_eq!(std::fs::read(&f.copie).unwrap(), ancien);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// R3-C3 par l'aperçu : une copie plus récente que la clé, qui grave la version publiée mais que Vanguard ne
    /// reconnaît pas, n'est jamais dite « à jour » (le terminal la dit non vérifiée).
    #[test]
    fn une_copie_plus_recente_que_la_cle_non_reconnue_n_est_pas_a_jour() {
        let d = dossier("cle-ancienne");
        let mut f = Faux::nouveau(&d);
        std::fs::create_dir_all(f.copie.parent().unwrap()).unwrap();
        let ici = programme("0.96.0+1793000000", "etrangere");
        std::fs::write(&f.copie, &ici).unwrap();
        f.cibles = vec![f.copie.clone()];
        f.derniere = Ok(Publiee::d_essai(version("0.96.0+1793000000"), &ici));
        f.maintenant = 1_793_000_000;
        f.etat = Etat::ClePlusAncienne {
            copie: version("0.96.0+1793000000"),
            cle: version("0.95.0+1790000000"),
        };
        let r = plan(&f, Pour::Voir).map(|p| p.apercu);
        assert!(matches!(r, Err(Refus::AJour(_))), "reconnue : à jour, {r:?}");
        f.reconnue = Err("pas dans la liste".into());
        match plan(&f, Pour::Voir) {
            Err(Refus::NonVerifie(e)) => assert!(e.contains("pas dans la liste"), "{e}"),
            autre => panic!("{:?}", autre.map(|p| p.apercu)),
        }
        // Une version signée plus récente qu'elle la remplace, comme au terminal (2e relecture adverse).
        let publie = programme("0.97.0+1793000000", "publie");
        f.derniere = Ok(Publiee::d_essai(version("0.97.0+1793000000"), &publie));
        f.recus = publie;
        match plan(&f, Pour::Voir) {
            Ok(p) => assert_eq!(
                p.cibles.iter().map(|(c, _)| c.clone()).collect::<Vec<_>>(),
                vec![f.copie.clone()]
            ),
            Err(r) => panic!("{r:?}"),
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// R5-REGISTRE-3 par l'aperçu : sans copie ici, la liste des copies en doute est dite, jamais « rien ».
    #[test]
    fn sans_copie_une_liste_en_doute_n_est_pas_rien() {
        let d = dossier("sans-copie-doute");
        let f = Faux::nouveau(&d);
        assert!(matches!(plan(&f, Pour::Voir), Err(Refus::Rien)));
        crate::programmes_poses::copie_posee_dans(&f.registre, &f.copie, b"posee");
        std::fs::remove_file(f.registre.join(crate::programmes_poses::FICHIER)).unwrap();
        match plan(&f, Pour::Voir) {
            Err(Refus::NonVerifie(e)) => {
                assert!(e.contains(tr!("la liste des copies", "the list of copies")), "{e}");
                assert!(e.contains("se-mettre-a-jour"), "{e}");
            }
            autre => panic!("{:?}", autre.map(|p| p.apercu)),
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// R4-REGISTRE-1 et 3 par l'aperçu : la liste des copies effacée alors qu'un sceau l'attendait ne dit pas « rien
    /// de noté ». Le terminal le dit et en sort ; l'aperçu ne propose rien et ne dit jamais « à jour ».
    #[test]
    fn github_un_registre_en_doute_n_est_jamais_propose_ni_a_jour() {
        let d = dossier("github-doute");
        let mut f = Faux::nouveau(&d);
        std::fs::create_dir_all(f.copie.parent().unwrap()).unwrap();
        let ancien = programme("0.94.0+1780000000", "copie");
        std::fs::write(&f.copie, &ancien).unwrap();
        crate::programmes_poses::copie_posee_dans(&f.registre, &f.copie, &ancien);
        std::fs::remove_file(f.registre.join(crate::programmes_poses::FICHIER)).unwrap();
        f.cibles = vec![f.copie.clone()];
        let publie = programme("0.95.0+1790000000", "publie");
        f.derniere = Ok(Publiee::d_essai(version("0.95.0+1790000000"), &publie));
        f.recus = publie;
        for p in [Pour::Voir, Pour::Appliquer] {
            match plan(&f, p) {
                Err(Refus::NonVerifie(e)) => {
                    assert!(e.contains(tr!("la liste des copies", "the list of copies")), "{e}");
                    assert!(e.contains("se-mettre-a-jour"), "{e}");
                }
                autre => panic!("{:?}", autre.map(|p| p.apercu)),
            }
        }
        // Une copie plus récente que Vanguard ne reconnaît pas : jamais « à jour » non plus.
        let _ = std::fs::remove_dir_all(&f.registre);
        std::fs::write(&f.copie, programme("0.96.0+1795000000", "inconnue")).unwrap();
        f.reconnue = Err("pas dans la liste".into());
        match plan(&f, Pour::Voir) {
            Err(Refus::NonVerifie(e)) => assert!(e.contains("pas dans la liste"), "{e}"),
            autre => panic!("{:?}", autre.map(|p| p.apercu)),
        }
        assert_eq!(f.telecharges.get(), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Depuis GitHub : rien n'est retenu ni téléchargé avant l'accord ; une nouvelle version publiée entre l'aperçu
    /// et l'accord le fait refuser ; l'accord montré pose les octets reçus, à la place de chaque programme plus ancien
    /// seulement (jamais d'un plus récent).
    #[test]
    fn github_ne_retient_ni_ne_telecharge_avant_l_accord() {
        let d = dossier("github");
        let mut f = Faux::nouveau(&d);
        let (vieux, recent) = (d.join("a").join(NOM), d.join("b").join(NOM));
        for (c, v) in [(&vieux, "0.94.0+1780000000"), (&recent, "0.96.0+1795000000")] {
            std::fs::create_dir_all(c.parent().unwrap()).unwrap();
            std::fs::write(c, programme(v, "ici")).unwrap();
        }
        f.cibles = vec![vieux.clone(), recent.clone()];
        let publie = programme("0.95.0+1790000000", "publie");
        f.derniere = Ok(Publiee::d_essai(version("0.95.0+1790000000"), &publie));
        f.recus = publie.clone();
        let a = plan(&f, Pour::Voir).unwrap().apercu;
        assert_eq!(a.origine, "github");
        assert_eq!(a.sha256, sha256_hex(&publie));
        assert_eq!(a.cibles.len(), 1, "le plus récent n'est jamais remplacé");
        assert_eq!((f.retenus.get(), f.telecharges.get()), (0, 0));
        // Un mauvais accord : ni retenu, ni téléchargé.
        assert_eq!(agir(&f, &"cd".repeat(32), CONSOMME), Issue::Refuse(Refus::Change));
        assert_eq!((f.retenus.get(), f.telecharges.get()), (0, 0));
        // Une version publiée entre-temps : l'accord ne vaut plus.
        let accord = a.accord();
        let plus_neuf = programme("0.95.1+1791000000", "publie");
        f.derniere = Ok(Publiee::d_essai(version("0.95.1+1791000000"), &plus_neuf));
        assert_eq!(agir(&f, &accord, CONSOMME), Issue::Refuse(Refus::Change));
        assert_eq!((f.retenus.get(), f.telecharges.get()), (0, 0));
        // L'accord de ce qui est montré : retenu, téléchargé, posé.
        f.derniere = Ok(Publiee::d_essai(version("0.95.0+1790000000"), &publie));
        let Issue::Fait(c) = agir(&f, &accord, CONSOMME) else {
            panic!("pas fait")
        };
        assert!(c.iter().all(|(_, r)| r.is_ok()), "{c:?}");
        assert_eq!((f.retenus.get(), f.telecharges.get()), (1, 1));
        assert_eq!(std::fs::read(&vieux).unwrap(), publie);
        assert_eq!(std::fs::read(&recent).unwrap(), programme("0.96.0+1795000000", "ici"));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un programme inventé de version `v` qui lance la fenêtre `fenetre` (son empreinte gravée).
    fn lancant(v: &str, fenetre: &[u8]) -> Vec<u8> {
        [programme(v, "lance "), marque_d_essai(&Sha256::digest(fenetre).into())].concat()
    }

    /// La clé : sa fenêtre, si c'est celle que grave son programme, est une ligne de l'aperçu (donc de l'accord) et
    /// suit la copie, relue au résultat ; une autre fenêtre n'est ni montrée ni posée ; une fenêtre apparue à la clé
    /// après l'aperçu change l'accord.
    #[test]
    fn la_fenetre_de_la_cle_suit_ce_que_l_apercu_a_montre() {
        let d = dossier("cle-fenetre");
        let mut f = Faux::nouveau(&d);
        let source = d.join("cle").join(NOM);
        let fenetre_cle = sa_fenetre::pour(&source).unwrap();
        let fenetre_ici = sa_fenetre::pour(&f.copie).unwrap();
        let neuve = b"fenetre 0.95".to_vec();
        let neuf = lancant("0.95.0+1790000000", &neuve);
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::write(&source, &neuf).unwrap();
        std::fs::create_dir_all(f.copie.parent().unwrap()).unwrap();
        let ancien = programme("0.94.0+1780000000", "copie");
        let remettre = || {
            std::fs::write(&f.copie, &ancien).unwrap();
            std::fs::write(&fenetre_ici, b"ancienne fenetre").unwrap();
        };
        remettre();
        f.etat = Etat::AMettreAJour {
            source: source.clone(),
            copie: Some(version("0.94.0+1780000000")),
            cle: version("0.95.0+1790000000"),
        };
        // Sans fenêtre à la clé : le programme seul, comme avant.
        let sans = plan(&f, Pour::Voir).unwrap().apercu;
        assert_eq!(sans.cibles.len(), 1);
        // Une fenêtre qui n'est pas celle du programme : ni montrée, ni posée.
        std::fs::write(&fenetre_cle, b"fenetre plantee").unwrap();
        let a = plan(&f, Pour::Voir).unwrap().apercu;
        assert_eq!(a.cibles.len(), 1);
        assert!(matches!(agir(&f, &a.accord(), CONSOMME), Issue::Fait(c) if c.len() == 1 && c[0].1.is_ok()));
        assert_eq!(std::fs::read(&fenetre_ici).unwrap(), b"ancienne fenetre");
        remettre();
        // La sienne, apparue après l'aperçu : l'accord ne vaut plus.
        std::fs::write(&fenetre_cle, &neuve).unwrap();
        assert_eq!(agir(&f, &sans.accord(), CONSOMME), Issue::Refuse(Refus::Change));
        assert_eq!(std::fs::read(&f.copie).unwrap(), ancien);
        // Montrée, puis posée avec le programme.
        let a = plan(&f, Pour::Voir).unwrap().apercu;
        assert_eq!(a.cibles.len(), 2);
        assert_eq!(a.cibles[1].chemin, montre(&fenetre_ici));
        assert_eq!(a.cibles[1].version, "sa fenêtre");
        let Issue::Fait(c) = agir(&f, &a.accord(), CONSOMME) else {
            panic!("pas fait")
        };
        assert_eq!(c.len(), 2);
        assert!(c.iter().all(|(_, r)| r.is_ok()), "{c:?}");
        assert_eq!(c[1].0, montre(&fenetre_ici));
        assert_eq!(std::fs::read(&f.copie).unwrap(), neuf);
        assert_eq!(std::fs::read(&fenetre_ici).unwrap(), neuve);
        // Pas encore de fenêtre ici : dite nouvelle.
        remettre();
        std::fs::remove_file(&fenetre_ici).unwrap();
        let a = plan(&f, Pour::Voir).unwrap().apercu;
        assert_eq!(a.cibles[1].version, "sa fenêtre, nouvelle ici");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// C-7 (relecture 0.96) : une fenêtre apparue à côté d'un programme pendant son téléchargement, après l'accord,
    /// était remplacée sans avoir été montrée. Rien n'est remplacé pour lui, la ligne le dit, rien n'est téléchargé.
    #[test]
    fn github_ne_remplace_pas_une_fenetre_apparue_apres_l_accord() {
        let d = dossier("github-fenetre-apparue");
        let mut f = Faux::nouveau(&d);
        let ici = d.join("a").join(NOM);
        let fenetre = sa_fenetre::pour(&ici).unwrap();
        std::fs::create_dir_all(ici.parent().unwrap()).unwrap();
        let ancien = programme("0.94.0+1780000000", "ici");
        std::fs::write(&ici, &ancien).unwrap();
        f.cibles = vec![ici.clone()];
        let neuve = b"fenetre 0.95".to_vec();
        let publie = lancant("0.95.0+1790000000", &neuve);
        f.derniere = Ok(Publiee::d_essai(version("0.95.0+1790000000"), &publie));
        f.recus = publie;
        f.fenetre = Ok(neuve);
        let vu = plan(&f, Pour::Voir).unwrap().apercu;
        assert_eq!(vu.cibles.len(), 1, "aucune fenêtre montrée");
        f.apparait = Some(fenetre.clone());
        let Issue::Fait(c) = agir(&f, &vu.accord(), CONSOMME) else {
            panic!("pas fait")
        };
        assert_eq!(c.len(), 1, "{c:?}");
        let raison = c[0].1.clone().expect_err("remplacé sans avoir été montré");
        assert!(
            raison.contains("depuis ce qui a été montré") || raison.contains("since what was shown"),
            "{raison}"
        );
        assert_eq!(std::fs::read(&ici).unwrap(), ancien);
        assert_eq!(std::fs::read(&fenetre).unwrap(), b"fenetre apparue");
        assert_eq!(f.fenetres_telechargees.get(), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// GitHub : la fenêtre posée à côté d'un programme remplacé est une ligne de l'aperçu ; la fenêtre de la nouvelle
    /// version n'est téléchargée qu'après l'accord, une fois ; une autre que celle gravée, ou aucune reçue, et rien
    /// n'est remplacé, chaque ligne le dit ; une fenêtre posée après l'aperçu change l'accord.
    #[test]
    fn github_ne_pose_que_la_fenetre_gravee_apres_l_accord() {
        let d = dossier("github-fenetre");
        let mut f = Faux::nouveau(&d);
        let ici = d.join("a").join(NOM);
        let fenetre = sa_fenetre::pour(&ici).unwrap();
        std::fs::create_dir_all(ici.parent().unwrap()).unwrap();
        let ancien = programme("0.94.0+1780000000", "ici");
        let remettre = || {
            std::fs::write(&ici, &ancien).unwrap();
            std::fs::write(&fenetre, b"ancienne fenetre").unwrap();
        };
        let inchange =
            || std::fs::read(&ici).unwrap() == ancien && std::fs::read(&fenetre).unwrap() == b"ancienne fenetre";
        std::fs::write(&ici, &ancien).unwrap();
        f.cibles = vec![ici.clone()];
        let neuve = b"fenetre 0.95".to_vec();
        let publie = lancant("0.95.0+1790000000", &neuve);
        f.derniere = Ok(Publiee::d_essai(version("0.95.0+1790000000"), &publie));
        f.recus = publie.clone();
        // Sans fenêtre ici à l'aperçu, posée avant l'accord : il ne vaut plus.
        let sans = plan(&f, Pour::Voir).unwrap().apercu;
        assert_eq!(sans.cibles.len(), 1);
        remettre();
        assert_eq!(agir(&f, &sans.accord(), CONSOMME), Issue::Refuse(Refus::Change));
        let a = plan(&f, Pour::Voir).unwrap().apercu;
        assert_eq!(a.cibles.len(), 2);
        assert_eq!(a.cibles[1].chemin, montre(&fenetre));
        assert_eq!(f.fenetres_telechargees.get(), 0);
        assert_eq!(agir(&f, &"cd".repeat(32), CONSOMME), Issue::Refuse(Refus::Change));
        assert_eq!(f.fenetres_telechargees.get(), 0);
        // Une autre fenêtre que celle gravée, puis aucune reçue : rien de remplacé, les deux lignes le disent.
        for recue in [
            Ok(b"fenetre plantee".to_vec()),
            Err("téléchargement interrompu".to_string()),
        ] {
            f.fenetre = recue;
            let Issue::Fait(c) = agir(&f, &a.accord(), CONSOMME) else {
                panic!("pas fait")
            };
            assert_eq!(c.len(), 2);
            assert!(c.iter().all(|(_, r)| r.is_err()), "{c:?}");
            assert!(inchange());
        }
        // Un nouveau programme qui ne lance aucune fenêtre : posé seul, rien téléchargé ; la ligne de la fenêtre, relue,
        // ne dit pas « à jour ».
        let sans_fenetre = [
            &programme("0.95.0+1790000000", "aucune ")[..],
            &marque_d_essai(&[0; 32])[..17],
            b"AUCUNE;",
        ]
        .concat();
        f.derniere = Ok(Publiee::d_essai(version("0.95.0+1790000000"), &sans_fenetre));
        f.recus = sans_fenetre.clone();
        let avant = f.fenetres_telechargees.get();
        let accord = plan(&f, Pour::Voir).unwrap().apercu.accord();
        let Issue::Fait(c) = agir(&f, &accord, CONSOMME) else {
            panic!("pas fait")
        };
        assert!(c[0].1.is_ok() && c[1].1.is_err(), "{c:?}");
        assert_eq!(std::fs::read(&ici).unwrap(), sans_fenetre);
        assert_eq!(std::fs::read(&fenetre).unwrap(), b"ancienne fenetre");
        assert_eq!(f.fenetres_telechargees.get(), avant);
        remettre();
        f.derniere = Ok(Publiee::d_essai(version("0.95.0+1790000000"), &publie));
        f.recus = publie.clone();
        // La bonne : les deux posés, la fenêtre téléchargée une fois.
        f.fenetre = Ok(neuve.clone());
        let avant = f.fenetres_telechargees.get();
        let Issue::Fait(c) = agir(&f, &a.accord(), CONSOMME) else {
            panic!("pas fait")
        };
        assert!(c.iter().all(|(_, r)| r.is_ok()), "{c:?}");
        assert_eq!(f.fenetres_telechargees.get(), avant + 1);
        assert_eq!(std::fs::read(&ici).unwrap(), publie);
        assert_eq!(std::fs::read(&fenetre).unwrap(), neuve);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Rien n'est « à jour » sans être vérifié : pas de réponse, versions vues changées, manifeste plus vieux que le
    /// déjà vu, version signée trop vieille, plus récent ici, copie illisible vue depuis la clé (`Etat::Illisible`).
    /// À jour seulement quand c'est prouvé. Une copie illisible vue depuis GitHub (une vraie, sur le disque) :
    /// `une_copie_illisible_n_est_jamais_a_jour`.
    #[test]
    fn rien_de_verifie_n_est_jamais_a_jour() {
        let d = dossier("non-verifie");
        let mut f = Faux::nouveau(&d);
        let ici = d.join("a").join(NOM);
        std::fs::create_dir_all(ici.parent().unwrap()).unwrap();
        std::fs::write(&ici, programme("0.95.0+1790000000", "ici")).unwrap();
        f.cibles = vec![ici.clone()];
        let non = |r: Result<Plan, Refus>| matches!(r, Err(Refus::NonVerifie(_)));
        // Pas de réponse.
        assert!(non(plan(&f, Pour::Voir)));
        // La même version, publiée récemment : à jour.
        f.derniere = Ok(Publiee::d_essai(version("0.95.0+1790000000"), b"x"));
        assert!(matches!(plan(&f, Pour::Voir), Err(Refus::AJour(_))));
        // Plus vieille que la plus haute vue.
        f.vue = Err("manifeste plus vieux".into());
        assert!(non(plan(&f, Pour::Voir)));
        f.vue = Ok(());
        // Versions vues changées hors de Vanguard.
        f.douteuses = true;
        assert!(non(plan(&f, Pour::Voir)));
        f.douteuses = false;
        // Signée il y a trop longtemps.
        f.maintenant = 1_790_000_000 + 90 * 86_400;
        assert!(non(plan(&f, Pour::Voir)));
        f.maintenant = 1_790_000_000;
        // Plus récent ici que la dernière signée.
        f.courante = Some(version("0.96.0+1795000000"));
        assert!(non(plan(&f, Pour::Voir)));
        f.courante = Some(version("0.95.0+1790000000"));
        // La copie illisible.
        f.etat = Etat::Illisible("illisible".into());
        assert!(non(plan(&f, Pour::Voir)));
        f.etat = Etat::Rien;
        assert!(matches!(plan(&f, Pour::Voir), Err(Refus::AJour(_))));
        // Rien ici à remplacer.
        f.cibles.clear();
        assert_eq!(plan(&f, Pour::Voir).err(), Some(Refus::Rien));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Le préfixe étendu de Windows ne s'ôte que de la forme exacte `\\?\X:\…` dont le reste nomme le même
    /// fichier ; tout le reste est rendu tel quel (la fenêtre le refuse).
    #[test]
    fn le_prefixe_etendu_ne_s_ote_que_sans_rien_changer() {
        let ote = [
            (r"\\?\C:\Outils\vanguard.exe", r"C:\Outils\vanguard.exe"),
            (r"\\?\d:\a b\vanguard.exe", r"d:\a b\vanguard.exe"),
            (
                r"\\?\C:\Users\alice\AppData\Local\Vanguard\bin\vanguard.exe",
                r"C:\Users\alice\AppData\Local\Vanguard\bin\vanguard.exe",
            ),
            (r"\\?\C:\console\vanguard.exe", r"C:\console\vanguard.exe"),
        ];
        for (avec, sans) in ote {
            assert_eq!(sans_prefixe_etendu(avec), sans, "{avec}");
        }
        let long = format!(r"\\?\C:\{}\vanguard.exe", "a".repeat(260));
        let gardes = [
            r"C:\Outils\vanguard.exe",
            r"\\?\UNC\serveur\partage\vanguard.exe",
            r"\\.\C:\vanguard.exe",
            r"\\?\Volume{0e1f}\vanguard.exe",
            r"\\?\C:",
            r"\\?\C:\",
            r"\\?\C:vanguard.exe",
            r"\\?\1:\vanguard.exe",
            r"\\?\C:\dossier.\vanguard.exe",
            r"\\?\C:\dossier \vanguard.exe",
            r"\\?\C:\a\..\vanguard.exe",
            r"\\?\C:\a\.\vanguard.exe",
            r"\\?\C:\a\\vanguard.exe",
            r"\\?\C:\a\vanguard.exe\",
            r"\\?\C:\a/b\vanguard.exe",
            r"\\?\C:\a:flux\vanguard.exe",
            r"\\?\C:\a*\vanguard.exe",
            r"\\?\C:\CON\vanguard.exe",
            r"\\?\C:\a\nul.txt",
            r"\\?\C:\a\Com1 .exe",
            r"\\?\C:\a\lpt9",
            r"\\?\C:\a\COM¹",
            r"\\?\C:\a\conin$",
            long.as_str(),
        ];
        for g in gardes {
            assert_eq!(sans_prefixe_etendu(g), g, "{g}");
        }
    }

    /// Sous Windows, à partir d'un vrai `canonicalize` (forme `\\?\C:\…`) : le chemin montré perd le préfixe et
    /// nomme le même fichier.
    #[cfg(windows)]
    #[test]
    fn un_vrai_chemin_canonique_se_montre_sans_prefixe() {
        let d = dossier("canonique");
        let f = d.join("Outils").join(NOM);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, b"x").unwrap();
        let canonique = f.canonicalize().unwrap();
        let texte = canonique.to_string_lossy().into_owned();
        assert!(texte.starts_with(r"\\?\"), "{texte}");
        let sans = sans_prefixe_etendu(&texte);
        assert!(!sans.starts_with(r"\\"), "{sans}");
        let o = sans.as_bytes();
        assert!(o[0].is_ascii_alphabetic() && o[1] == b':' && o[2] == b'\\', "{sans}");
        assert_eq!(Path::new(sans).canonicalize().unwrap(), canonique);
        assert!(!montre(&canonique).starts_with(r"\\"));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Depuis GitHub, une copie d'ici qui ne se lit pas (un lien vers rien, un dossier à la place du programme) n'est
    /// jamais « à jour » ni passée sous silence à côté d'une copie lisible : « non vérifié », avec son chemin.
    #[cfg(unix)]
    #[test]
    fn une_copie_illisible_n_est_jamais_a_jour() {
        let d = dossier("copie-illisible");
        let mut f = Faux::nouveau(&d);
        f.courante = Some(version("0.95.0+1790000000"));
        f.derniere = Ok(Publiee::d_essai(version("0.95.0+1790000000"), b"x"));
        let casse = d.join("casse").join(NOM);
        std::fs::create_dir_all(casse.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(d.join("nulle-part"), &casse).unwrap();
        let dossier_ici = d.join("dossier").join(NOM);
        std::fs::create_dir_all(&dossier_ici).unwrap();
        let vieux = d.join("vieux").join(NOM);
        std::fs::create_dir_all(vieux.parent().unwrap()).unwrap();
        std::fs::write(&vieux, programme("0.94.0+1780000000", "ici")).unwrap();
        let nomme = |r: Result<Plan, Refus>, c: &Path| {
            let montre = montre(c);
            matches!(r, Err(Refus::NonVerifie(ref t)) if t.contains(&montre))
        };
        // Un lien vers rien, puis un dossier : non vérifié, le chemin dit.
        f.cibles = vec![casse.clone()];
        assert!(nomme(plan(&f, Pour::Voir), &casse));
        f.cibles = vec![dossier_ici.clone()];
        assert!(nomme(plan(&f, Pour::Voir), &dossier_ici));
        // Une copie vieille lisible et une illisible : rien n'est proposé en taisant l'illisible.
        f.derniere = Ok(Publiee::d_essai(version("0.95.0+1790000000"), b"x"));
        f.cibles = vec![vieux.clone(), casse.clone()];
        assert!(nomme(plan(&f, Pour::Voir), &casse));
        // L'accord recalculé suit le même chemin : rien n'est posé.
        f.recus = b"x".to_vec();
        assert!(matches!(
            agir(&f, &"cd".repeat(32), CONSOMME),
            Issue::Refuse(Refus::NonVerifie(_))
        ));
        assert_eq!(std::fs::read(&vieux).unwrap(), programme("0.94.0+1780000000", "ici"));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// L'aperçu retient ce que GitHub a montré de signé, comme le terminal (plancher des versions vues, révocation),
    /// qu'il propose quelque chose ou dise « à jour » ; jamais un manifeste refusé, jamais avant d'avoir vu un
    /// manifeste ; le geste, lui, ne retient qu'après l'accord. Le vrai plancher : `github::tests`.
    #[test]
    fn l_apercu_retient_ce_que_github_a_signe() {
        let d = dossier("vue");
        let mut f = Faux::nouveau(&d);
        f.maintenant = 1_795_100_000;
        let ici = d.join("a").join(NOM);
        std::fs::create_dir_all(ici.parent().unwrap()).unwrap();
        std::fs::write(&ici, programme("0.94.0+1780000000", "ici")).unwrap();
        f.cibles = vec![ici.clone()];
        // Pas de réponse : rien à retenir.
        assert!(plan(&f, Pour::Voir).is_err());
        assert_eq!(f.vus.get(), 0);
        let publie = programme("0.96.0+1795000000", "publie");
        f.derniere = Ok(Publiee::d_essai(version("0.96.0+1795000000"), &publie));
        assert!(plan(&f, Pour::Voir).is_ok());
        assert_eq!((f.vus.get(), f.retenus.get()), (1, 0));
        // « À jour » aussi : vu, donc retenu.
        f.courante = Some(version("0.96.0+1795000000"));
        std::fs::write(&ici, programme("0.96.0+1795000000", "ici")).unwrap();
        assert!(matches!(plan(&f, Pour::Voir), Err(Refus::AJour(_))));
        assert_eq!(f.vus.get(), 2);
        // Plus vieux que le déjà vu : refusé, rien de retenu.
        f.vue = Err("manifeste plus vieux que celui déjà vu".into());
        assert!(matches!(plan(&f, Pour::Voir), Err(Refus::NonVerifie(_))));
        assert_eq!(f.vus.get(), 2);
        // Le geste : rien avant l'accord.
        f.vue = Ok(());
        let _ = plan(&f, Pour::Appliquer);
        assert_eq!((f.vus.get(), f.retenus.get()), (2, 0));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Le reste d'une mise à jour faite pendant que la copie tournait (`NOM.ancien`, Windows) s'efface comme au
    /// terminal, après l'accord seulement : un mauvais accord le laisse.
    #[test]
    fn le_reste_d_une_mise_a_jour_s_efface_apres_l_accord() {
        let d = dossier("ancien");
        let mut f = Faux::nouveau(&d);
        f.maintenant = 1_790_100_000;
        std::fs::create_dir_all(f.copie.parent().unwrap()).unwrap();
        std::fs::write(&f.copie, programme("0.94.0+1780000000", "ici")).unwrap();
        let ancien = f.copie.with_file_name(format!("{NOM}.ancien"));
        std::fs::write(&ancien, b"vieux").unwrap();
        // Celui de sa fenêtre aussi.
        let mut nom = sa_fenetre::pour(&f.copie).unwrap().file_name().unwrap().to_os_string();
        nom.push(".ancien");
        let ancienne_fenetre = f.copie.with_file_name(nom);
        std::fs::write(&ancienne_fenetre, b"vieille").unwrap();
        f.cibles = vec![f.copie.clone()];
        let publie = programme("0.95.0+1790000000", "publie");
        f.derniere = Ok(Publiee::d_essai(version("0.95.0+1790000000"), &publie));
        f.recus = publie.clone();
        let accord = plan(&f, Pour::Voir).unwrap().apercu.accord();
        assert_eq!(agir(&f, &"cd".repeat(32), CONSOMME), Issue::Refuse(Refus::Change));
        assert!(ancien.exists(), "un mauvais accord ne touche à rien");
        assert!(ancienne_fenetre.exists());
        assert!(matches!(agir(&f, &accord, CONSOMME), Issue::Fait(_)));
        assert!(!ancien.exists());
        assert!(!ancienne_fenetre.exists());
        assert_eq!(std::fs::read(&f.copie).unwrap(), publie);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// L'accord ne vaut que pour ce geste : il change avec chaque champ montré, et n'est pas celui d'un autre contexte.
    #[test]
    fn l_accord_lie_chaque_champ() {
        let a = Apercu {
            version: "0.95.0".into(),
            langue: "fr".into(),
            jeton: JETON.into(),
            origine: "github".into(),
            visee: "0.95.1+1".into(),
            sha256: "00".repeat(32),
            taille: 10,
            cibles: vec![Cible {
                chemin: "~/.local/share/vanguard/bin/vanguard".into(),
                version: "0.95.0+1".into(),
            }],
        };
        let base = a.accord();
        let mut changes = Vec::new();
        let mut b = a.clone();
        b.origine = "cle".into();
        changes.push(b);
        let mut b = a.clone();
        b.visee = "0.95.2+1".into();
        changes.push(b);
        let mut b = a.clone();
        b.sha256 = "01".repeat(32);
        changes.push(b);
        let mut b = a.clone();
        b.taille = 11;
        changes.push(b);
        let mut b = a.clone();
        b.cibles[0].chemin = "~/bin/vanguard".into();
        changes.push(b);
        let mut b = a.clone();
        b.cibles[0].version = "0.94.0+1".into();
        changes.push(b);
        let mut b = a.clone();
        b.cibles.push(b.cibles[0].clone());
        changes.push(b);
        for c in changes {
            assert_ne!(c.accord(), base, "{c:?}");
        }
        assert_ne!(
            crate::machine::apercu::accord_de("vanguard accord v1 annulation", a.champs()),
            base
        );
    }
}

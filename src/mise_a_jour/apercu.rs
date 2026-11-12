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
//! Il n'y a qu'une mise à jour à la fois : le jeton est fixe (`JETON`). Les chemins montrés sont « ~/… » sous le
//! dossier personnel ; le chemin de la clé n'est pas montré (il dit le nom du compte), seulement « clé VANGUARD ».

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::github::{self, Publiee};
use super::{Essai, Etat, Lu, TAILLE_MAX, Verdict, Version, ecrire, installer, lire_octets, lire_programme};
use crate::machine::carnet;
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
                "ça a changé depuis l'aperçu (nouvelle version, clé ou copie changée) : rien n'a été fait, refaites l'aperçu",
                "it changed since the preview (new version, key or copy changed): nothing was done, show the preview again"
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
    fn derniere(&self) -> Result<Publiee, String>;
    /// `github::juger_la_vue` : sans rien écrire.
    fn juger_la_vue(&self, p: &Publiee) -> Result<(), String>;
    fn courante(&self) -> Option<Version>;
    fn maintenant(&self) -> u64;
    /// Après l'accord seulement : retenir le manifeste (`github::retenir`).
    fn retenir(&self, p: &Publiee) -> Result<(), String>;
    /// Pendant l'aperçu, ce que le terminal retient d'un manifeste vu, signature vérifiée et pas plus vieux que le
    /// déjà vu : la plus haute version vue et la révocation (`github::retenir_pendant_un_apercu`). Rien d'autre.
    fn retenir_la_vue(&self, p: &Publiee) -> Result<(), String>;
    /// Après l'accord seulement : le programme téléchargé, taille et empreinte signées vérifiées.
    fn telecharger(&self, p: &Publiee) -> Result<Vec<u8>, String>;
    fn essai(&self) -> Essai;
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
    fn derniere(&self) -> Result<Publiee, String> {
        github::derniere_recue().map_err(String::from)
    }
    fn juger_la_vue(&self, p: &Publiee) -> Result<(), String> {
        github::juger_la_vue(p)
    }
    fn courante(&self) -> Option<Version> {
        super::courante()
    }
    fn maintenant(&self) -> u64 {
        super::maintenant()
    }
    fn retenir(&self, p: &Publiee) -> Result<(), String> {
        github::retenir(p)
    }
    fn retenir_la_vue(&self, p: &Publiee) -> Result<(), String> {
        github::retenir_pendant_un_apercu(p)
    }
    fn telecharger(&self, p: &Publiee) -> Result<Vec<u8>, String> {
        github::programme_verifie(p)
    }
    fn essai(&self) -> Essai {
        super::essayer
    }
}

/// D'où vient ce qui s'installerait.
#[derive(Debug)]
enum Source {
    /// Les octets du programme lancé depuis la clé, lus pour l'aperçu : ce sont eux qui s'installent.
    Cle(Vec<u8>),
    /// La version publiée : le programme se télécharge après l'accord, vérifié contre sa taille et son empreinte.
    Github(Publiee),
}

/// Ce qui serait fait : l'aperçu, la source, et les vrais chemins remplacés (dans l'ordre de `apercu.cibles`).
#[derive(Debug)]
struct Plan {
    apercu: Apercu,
    source: Source,
    cibles: Vec<(PathBuf, Version)>,
}

fn sha256_hex(octets: &[u8]) -> String {
    github::hex(&Sha256::digest(octets))
}

fn apercu(origine: &str, visee: Version, sha256: String, taille: u64, cibles: &[(PathBuf, Version)]) -> Apercu {
    // Deux compilations du même numéro se distinguent par leur date (`cote_a_cote`) : jamais « 0.95.0 remplace
    // 0.95.0 » sans dire laquelle est la plus récente.
    let mut visee_dite = ecrire(visee);
    let cibles = cibles
        .iter()
        .map(|(c, _)| Cible {
            chemin: crate::optimiser::annulables::chemin_montre(&c.to_string_lossy()),
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
        })
        .collect();
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
            let cibles = vec![(m.copie(), cle)];
            let taille = u64::try_from(octets.len()).unwrap_or(u64::MAX);
            Ok(Plan {
                apercu: apercu("cle", cle, sha256_hex(&octets), taille, &cibles),
                source: Source::Cle(octets),
                cibles,
            })
        }
        Etat::Illisible(e) => Err(Refus::NonVerifie(trf!(
            "la copie de cet ordinateur ne se lit pas, sa version reste inconnue ({})",
            "the copy on this computer cannot be read, its version is unknown ({})",
            e
        ))),
        Etat::Rien | Etat::PasDepuisLaCle | Etat::AJour(_) | Etat::ClePlusAncienne { .. } => plan_github(m, pour),
    }
}

fn plan_github(m: &dyn Monde, pour: Pour) -> Result<Plan, Refus> {
    let cibles = m.cibles_github();
    if cibles.is_empty() {
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
    m.juger_la_vue(&p).map_err(Refus::NonVerifie)?;
    // L'aperçu retient ce qu'il a vu de signé, comme le terminal : sans quoi un « à jour » ou un aperçu pas accepté ne
    // relèverait rien, et un manifeste plus vieux resservi plus tard serait jugé sans ce plancher. Le geste, lui,
    // retient après l'accord (`agir`).
    if pour == Pour::Voir {
        m.retenir_la_vue(&p).map_err(Refus::NonVerifie)?;
    }
    // Le plancher : le programme lancé et les copies d'ici (`depuis_github`).
    let ici: Vec<Version> = lues.iter().filter_map(|(_, v)| *v).chain(m.courante()).collect();
    // Seulement ce qui est plus ancien que la version publiée (sans version gravée : d'avant la 0.78, donc plus
    // ancien) ; jamais un plus récent.
    let a_remplacer: Vec<(PathBuf, Version)> = lues
        .into_iter()
        .filter(|(_, v)| v.is_none_or(|v| v < p.version))
        .map(|(c, _)| (c, p.version))
        .collect();
    if a_remplacer.is_empty() {
        return Err(match super::verdict(p.version, &ici, m.maintenant()) {
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
        });
    }
    Ok(Plan {
        apercu: apercu("github", p.version, p.sha256_hex(), p.taille(), &a_remplacer),
        source: Source::Github(p),
        cibles: a_remplacer,
    })
}

/// Une copie d'ici qui ne se lit pas : sa version reste inconnue, rien n'est dit à jour.
fn copie_illisible(chemin: &Path, pourquoi: &str) -> Refus {
    Refus::NonVerifie(trf!(
        "{} ne se lit pas, sa version reste inconnue ({})",
        "{} cannot be read, its version is unknown ({})",
        crate::optimiser::annulables::chemin_montre(&chemin.to_string_lossy()),
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
    /// Fait jusqu'au bout : chaque cible (chemin montré, `Err` : pourquoi elle n'est pas remplacée, l'ancienne reste).
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
    let octets = match plan.source {
        Source::Cle(octets) => octets,
        Source::Github(p) => {
            if let Err(e) = m.retenir(&p) {
                return Issue::Echec(e);
            }
            match m.telecharger(&p) {
                Ok(o) => o,
                Err(e) => return Issue::Echec(e),
            }
        }
    };
    let essai = m.essai();
    Issue::Fait(
        plan.cibles
            .iter()
            .zip(&plan.apercu.cibles)
            .map(|((chemin, visee), montre)| (montre.chemin.clone(), installer(&octets, chemin, *visee, essai)))
            .collect(),
    )
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
                "pas tout remplacé : l'ancien reste en place là où c'est dit",
                "not everything replaced: the old one stays where it says so"
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
                            "  ✖ {} n'est pas remplacé, l'ancien reste en place : {}",
                            "  ✖ {} is not replaced, the old one stays in place: {}",
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
        retenus: Cell<u32>,
        /// Les manifestes retenus pendant un aperçu (`retenir_la_vue`).
        vus: Cell<u32>,
        telecharges: Cell<u32>,
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
                retenus: Cell::new(0),
                vus: Cell::new(0),
                telecharges: Cell::new(0),
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
        fn derniere(&self) -> Result<Publiee, String> {
            self.derniere.clone()
        }
        fn juger_la_vue(&self, _: &Publiee) -> Result<(), String> {
            self.vue.clone()
        }
        fn courante(&self) -> Option<Version> {
            self.courante
        }
        fn maintenant(&self) -> u64 {
            self.maintenant
        }
        fn retenir(&self, _: &Publiee) -> Result<(), String> {
            self.retenus.set(self.retenus.get().saturating_add(1));
            Ok(())
        }
        fn retenir_la_vue(&self, _: &Publiee) -> Result<(), String> {
            self.vus.set(self.vus.get().saturating_add(1));
            Ok(())
        }
        fn telecharger(&self, _: &Publiee) -> Result<Vec<u8>, String> {
            self.telecharges.set(self.telecharges.get().saturating_add(1));
            Ok(self.recus.clone())
        }
        fn essai(&self) -> Essai {
            ESSAI_OK
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
            let montre = crate::optimiser::annulables::chemin_montre(&c.to_string_lossy());
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
        f.cibles = vec![f.copie.clone()];
        let publie = programme("0.95.0+1790000000", "publie");
        f.derniere = Ok(Publiee::d_essai(version("0.95.0+1790000000"), &publie));
        f.recus = publie.clone();
        let accord = plan(&f, Pour::Voir).unwrap().apercu.accord();
        assert_eq!(agir(&f, &"cd".repeat(32), CONSOMME), Issue::Refuse(Refus::Change));
        assert!(ancien.exists(), "un mauvais accord ne touche à rien");
        assert!(matches!(agir(&f, &accord, CONSOMME), Issue::Fait(_)));
        assert!(!ancien.exists());
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

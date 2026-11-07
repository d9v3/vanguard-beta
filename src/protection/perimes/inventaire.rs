//! Ce que l'inventaire de Windows a trouvé : chaque logiciel suivi installé, sa version telle que
//! lue et telle que comparable, où il est et pour qui, et ce qui n'a pas pu être lu (comptes, dossiers refusés),
//! qui sera dit, jamais compté comme sain.

// Sous Linux seulement : les parties Windows ne sont pas encore relues ; le lint y viendra avec elles.
#![cfg_attr(target_os = "linux", warn(clippy::arithmetic_side_effects, clippy::as_conversions))]

use std::path::{Path, PathBuf};

use super::produits::{Distribution, Produit};
use super::version::{self, Version};
use crate::trf;

/// Logiciels gardés au plus : au-delà, un ordinateur fabriqué pour gêner l'analyse.
const INSTALLES_MAX: usize = 64;
/// Caractères gardés de la version telle que lue.
const BRUTE_MAX: usize = 64;

/// La piste de mise à jour d'un logiciel, quand elle compte pour le juger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Branche {
    /// La piste principale de l'éditeur (Firefox, Acrobat Continuous, Java).
    Release,
    /// Firefox ESR.
    Esr,
    /// Un canal nommé : Edge « extended », Office (nom ou GUID de son adresse, en minuscules).
    Canal(String),
    /// Acrobat et Reader des pistes 2020 et 2024 : aucune source fixe.
    Classic,
    /// Pas lue : l'étape des verdicts en décide (Firefox par sa version) ou dit le logiciel non vérifié.
    Inconnue,
}

/// L'architecture d'un logiciel : elle choisit la source (Chrome et Brave publient par plateforme).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Plateforme {
    X86,
    X64,
    Arm64,
    Inconnue,
}

impl Plateforme {
    /// D'après le champ Machine d'un exécutable Windows.
    #[cfg(any(windows, test))]
    pub(crate) fn de_pe(machine: crate::pe::Machine) -> Plateforme {
        match machine {
            crate::pe::Machine::X86 => Plateforme::X86,
            crate::pe::Machine::X64 => Plateforme::X64,
            crate::pe::Machine::Arm64 => Plateforme::Arm64,
            crate::pe::Machine::Autre(_) => Plateforme::Inconnue,
        }
    }

    /// D'après `OS_ARCH` d'un fichier `release` de Java, ou `Platform` d'Office.
    pub(crate) fn de_nom(nom: &str) -> Plateforme {
        match nom.trim().to_ascii_lowercase().as_str() {
            "amd64" | "x86_64" | "x64" => Plateforme::X64,
            "x86" | "i386" | "i586" | "i686" => Plateforme::X86,
            "aarch64" | "arm64" => Plateforme::Arm64,
            _ => Plateforme::Inconnue,
        }
    }
}

/// Un logiciel suivi, installé.
#[derive(Debug, Clone)]
pub(crate) struct Installe {
    pub produit: Produit,
    /// La version telle que lue, bornée à 64 caractères et prête à montrer ; vide si rien n'a été lu.
    pub brute: String,
    /// `None` : illisible ou d'une forme inconnue, le logiciel sera dit « non vérifié ».
    pub version: Option<Version>,
    /// Le dossier ; montré par `ui::chemin_affichable`.
    pub lieu: PathBuf,
    /// Le compte pour qui il est installé ; `None` : pour toute la machine.
    pub compte: Option<String>,
    pub branche: Branche,
    pub plateforme: Plateforme,
    /// Une mise à jour attend un redémarrage du navigateur (`new_chrome.exe`, `new_msedge.exe`) : la version gardée
    /// est celle qui tourne.
    pub attente: bool,
    /// Une autre version vue au même endroit (dossier de version d'un navigateur qui ne dit pas la même chose que
    /// son exécutable).
    pub ecart: Option<Version>,
}

impl Installe {
    /// Un logiciel trouvé à `lieu`, de version `brute` telle que lue et `version` une fois normalisée ; le reste à
    /// ses valeurs neutres.
    pub(crate) fn nouveau(produit: Produit, brute: &str, version: Option<Version>, lieu: &Path) -> Installe {
        Installe {
            produit,
            brute: crate::ui::affichable(&brute.trim().chars().take(BRUTE_MAX).collect::<String>()),
            version,
            lieu: lieu.to_path_buf(),
            compte: None,
            branche: Branche::Inconnue,
            plateforme: Plateforme::Inconnue,
            attente: false,
            ecart: None,
        }
    }
}

/// Ce qui n'a pas pu être lu : dit avec le verdict, jamais compté comme sain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NonLu {
    /// Sans droits d'administrateur, les autres comptes ne se lisent pas.
    Comptes(usize),
    /// Un dossier qui ne s'ouvre pas.
    Dossier(PathBuf),
    /// Le registre d'un compte dont la session est fermée (sa ruche n'est pas chargée, et Vanguard ne la charge
    /// pas) : seuls ses dossiers sont lus.
    Registre(String),
    /// Logiciels au-delà de 64, ou applications au-delà de la borne du parcours.
    Trop(usize),
}

impl NonLu {
    pub(crate) fn texte(&self) -> String {
        match self {
            NonLu::Comptes(n) => trf!(
                "{n} autre(s) compte(s) non vérifié(s) : lancer Vanguard en administrateur",
                "{n} other account(s) not checked: run Vanguard as administrator"
            ),
            NonLu::Dossier(d) => trf!(
                "dossier non lu : {}",
                "folder not read: {}",
                crate::ui::chemin_affichable(d)
            ),
            NonLu::Registre(c) => trf!(
                "registre du compte {} non lu (session fermée) : ses dossiers seulement",
                "registry of account {} not read (logged off): its folders only",
                crate::ui::affichable(c)
            ),
            NonLu::Trop(n) => trf!(
                "{n} logiciel(s) au-delà de la borne, non vérifié(s)",
                "{n} program(s) beyond the limit, not checked"
            ),
        }
    }
}

/// Tout ce que l'inventaire a trouvé.
#[derive(Debug, Default)]
pub(crate) struct Inventaire {
    pub installes: Vec<Installe>,
    pub non_lus: Vec<NonLu>,
}

impl Inventaire {
    /// Ajoute un logiciel, sauf s'il est déjà là (même produit au même endroit, sans tenir compte de la casse :
    /// Windows ne la distingue pas, et le même dossier se trouve par plusieurs chemins). Au-delà de 64, il est
    /// compté dans `NonLu::Trop`.
    pub(crate) fn ajouter(&mut self, installe: Installe) {
        let cle = installe.lieu.to_string_lossy().to_lowercase();
        if self
            .installes
            .iter()
            .any(|i| i.produit == installe.produit && i.lieu.to_string_lossy().to_lowercase() == cle)
        {
            return;
        }
        if self.installes.len() < INSTALLES_MAX {
            self.installes.push(installe);
            return;
        }
        self.trop(1);
    }

    /// Note `n` éléments laissés de côté par une borne.
    pub(crate) fn trop(&mut self, n: usize) {
        if let Some(NonLu::Trop(m)) = self.non_lus.iter_mut().find(|x| matches!(x, NonLu::Trop(_))) {
            *m = (*m).saturating_add(n);
        } else {
            self.non_lus.push(NonLu::Trop(n));
        }
    }

    /// Note ce qui n'a pas été lu, une seule fois.
    pub(crate) fn non_lu(&mut self, non_lu: NonLu) {
        if !self.non_lus.contains(&non_lu) {
            self.non_lus.push(non_lu);
        }
    }
}

/// Java installé dans `dossier`, d'après son fichier `release` : la distribution (`IMPLEMENTOR`), la version
/// (`JAVA_VERSION`), l'architecture (`OS_ARCH`). Sans `IMPLEMENTOR` (Java 8 d'Oracle, entre autres), la
/// distribution reste « autre » : non vérifiée plutôt que devinée.
pub(crate) fn java_dans(dossier: &Path) -> Option<Installe> {
    let release = super::lecteurs::release(&super::lecteurs::texte_borne(&dossier.join("release"))?)?;
    let distribution = release
        .implementor
        .as_deref()
        .map_or(Distribution::Autre, Distribution::depuis_implementor);
    let mut i = Installe::nouveau(
        Produit::Java(distribution),
        &release.version,
        version::java_release(&release.version),
        dossier,
    );
    i.branche = Branche::Release;
    i.plateforme = release.arch.as_deref().map_or(Plateforme::Inconnue, Plateforme::de_nom);
    Some(i)
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doublons_et_borne() {
        let mut inv = Inventaire::default();
        let lieu = Path::new(r"C:\Program Files\Google\Chrome");
        inv.ajouter(Installe::nouveau(Produit::Chrome, "156.0.8078.48", None, lieu));
        inv.ajouter(Installe::nouveau(
            Produit::Chrome,
            "1",
            None,
            Path::new(r"c:\program files\google\chrome"),
        ));
        inv.ajouter(Installe::nouveau(Produit::Brave, "1", None, lieu));
        assert_eq!(inv.installes.len(), 2);
        for i in 0..100 {
            inv.ajouter(Installe::nouveau(
                Produit::Firefox,
                "1",
                None,
                &PathBuf::from(format!("/x/{i}")),
            ));
        }
        assert_eq!(inv.installes.len(), INSTALLES_MAX);
        assert_eq!(inv.non_lus, vec![NonLu::Trop(100 + 2 - INSTALLES_MAX)]);
        inv.non_lu(NonLu::Comptes(2));
        inv.non_lu(NonLu::Comptes(2));
        assert_eq!(inv.non_lus.len(), 2);
        inv.non_lu(NonLu::Registre("bob".into()));
        inv.non_lu(NonLu::Dossier(PathBuf::from("/x")));
        assert!(inv.non_lus.iter().all(|n| !n.texte().is_empty()));
    }

    #[test]
    fn version_brute_bornee_et_affichable() {
        let i = Installe::nouveau(
            Produit::Edge,
            &format!(" 1.2\x1b[2K{}", "9".repeat(100)),
            None,
            Path::new("x"),
        );
        assert_eq!(i.brute.chars().count(), BRUTE_MAX);
        assert!(!i.brute.contains('\x1b'));
        assert_eq!(Plateforme::de_nom("AMD64"), Plateforme::X64);
        assert_eq!(Plateforme::de_nom("aarch64"), Plateforme::Arm64);
        assert_eq!(Plateforme::de_nom("i586"), Plateforme::X86);
        assert_eq!(Plateforme::de_nom("sparcv9"), Plateforme::Inconnue);
        assert_eq!(Plateforme::de_pe(crate::pe::Machine::Arm64), Plateforme::Arm64);
    }
}

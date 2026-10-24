//! Le socle d'analyse des fichiers de l'antivirus de Vanguard : pour un fichier, l'arbre de ses « parties » (lui-même,
//! puis ce qu'il contient : entrées d'archives, flux d'un document OLE, source de ses macros, octets ajoutés après un
//! exécutable, architectures d'un Mach-O universel, texte décodé d'un script UTF-16…), chacune avec son type reconnu
//! par le CONTENU, son chemin interne, sa taille, son empreinte SHA-256, les faits relevés et ce qui n'a pas pu être
//! lu, et pourquoi. Aucun verdict ici : les motifs (AV2, YARA), les signatures (AV3, ClamAV) et les heuristiques (AV4)
//! s'en servent.
//!
//! Les fichiers analysés peuvent être piégés : tout est borné (taille du fichier, profondeur, nombre de parties,
//! octets décompressés en tout et par partie, taux de compression, temps), chaque lecteur rend une forme refusée au
//! lieu de paniquer, et ce qui n'est pas lu (format inconnu ou non ouvert ici, chiffré, coupé, borne atteinte) est
//! dit dans `manques`, jamais compté comme lu. Une partie qui contient l'un de ses ancêtres (une « quine », zip qui se
//! contient lui-même) n'est pas rouverte.
//!
//! Module autonome (sans interface ni `crate::` hors des lecteurs communs `archives` et `pe`) : le banc de fuzzing
//! l'inclut par son chemin. Les lecteurs propres à l'analyse (`cfb`, `ovba`, `vba`, `lnk`, `elf`, `macho`, `texte`)
//! n'utilisent que `lecture` : ils s'incluent aussi seuls.

mod arbre;
pub(crate) mod cfb;
pub(crate) mod elf;
pub(crate) mod lecture;
pub(crate) mod lnk;
pub(crate) mod macho;
pub(crate) mod nature;
pub(crate) mod nom;
pub(crate) mod office;
pub(crate) mod ovba;
pub(crate) mod texte;
pub(crate) mod vba;

#[cfg(test)]
mod tests;

use std::time::Duration;

#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use arbre::{analyser, analyser_fichier};

/// Les bornes d'une analyse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Bornes {
    /// Au-delà, le fichier n'est pas lu (dit « trop gros »).
    pub taille_fichier: u64,
    /// L'imbrication la plus profonde ouverte (le fichier est au niveau 0).
    pub profondeur: usize,
    /// Le nombre de parties d'un fichier.
    pub parties: usize,
    /// La taille d'une partie extraite (décompressée, décodée, lue dans un flux).
    pub taille_partie: usize,
    /// Les octets produits en tout (décompressés, décodés, copiés hors du fichier) : le coût d'une bombe.
    pub produits: u64,
    /// Au-delà de `seuil_taux` octets produits, le rapport entre ce qui est produit et la taille du fichier ne doit
    /// pas dépasser `taux` : une bombe imbriquée (42.zip) s'arrête là, bien avant `produits`.
    pub taux: u64,
    pub seuil_taux: u64,
    /// Le temps d'une analyse.
    pub delai: Duration,
    /// Les octets examinés en tout (empreinte, type, lecture de chaque partie, copiée ou non).
    pub examines: u64,
    /// Les entrées parcourues dans une archive (zip, tar) ou un fichier composé.
    pub entrees: usize,
    /// Le texte décodé d'un script.
    pub texte: usize,
}

impl Default for Bornes {
    fn default() -> Self {
        Bornes {
            taille_fichier: 256 << 20,
            profondeur: 8,
            parties: 20_000,
            taille_partie: 64 << 20,
            produits: 256 << 20,
            taux: 200,
            seuil_taux: 32 << 20,
            delai: Duration::from_secs(60),
            examines: 1 << 30,
            entrees: 20_000,
            texte: 8 << 20,
        }
    }
}

/// Le type d'une partie, reconnu par son contenu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Type {
    Vide,
    Pe,
    /// « MZ » sans en-tête PE : un programme DOS ou 16 bits (NE, comme les polices .fon), ou un PE abîmé ; non lu.
    ExecutableDos,
    Elf,
    MachO,
    MachOUniversel,
    ClasseJava,
    Zip,
    /// Un zip avec [Content_Types].xml : document Office (docx, xlsx, pptx et leurs formes à macros).
    Ooxml,
    /// Un zip OpenDocument (odt, ods, odp).
    OpenDocument,
    Jar,
    Apk,
    Gzip,
    Tar,
    /// Un fichier composé OLE qu'on n'a pas su ranger plus précisément.
    Cfb,
    DocWord,
    ClasseurExcel,
    PresentationPowerPoint,
    Msi,
    /// Un document OOXML chiffré (EncryptionInfo et EncryptedPackage, [MS-OFFCRYPTO]).
    OoxmlChiffre,
    /// Un flux interne d'un fichier composé, de forme connue, lu tel quel (WordDocument, \x05SummaryInformation…).
    FluxOle,
    /// La source d'un module VBA, décompressée.
    SourceVba,
    Lnk,
    Script(texte::Langage),
    Texte,
    // Reconnus, non ouverts : dits « non vérifiés ».
    SeptZip,
    Rar,
    Cab,
    Iso,
    Bzip2,
    Xz,
    Zstd,
    Lzip,
    Pdf,
    Rtf,
    OneNote,
    Chm,
    Wim,
    DisqueVirtuel,
    Dmg,
    Xar,
    Ar,
    Rpm,
    Cpio,
    SquashFs,
    // Reconnus, sans contenu caché à ouvrir : leurs octets, lus tels quels, suffisent.
    Image,
    Media,
    Police,
    Sqlite,
    Wasm,
    Inconnu,
}

impl Type {
    /// Un format reconnu dont Vanguard ne lit pas le contenu (archive, disque, document à objets embarqués).
    pub(crate) fn non_lu(self) -> bool {
        matches!(
            self,
            Type::ExecutableDos
                | Type::ClasseJava
                | Type::PresentationPowerPoint
                | Type::SeptZip
                | Type::Rar
                | Type::Cab
                | Type::Iso
                | Type::Bzip2
                | Type::Xz
                | Type::Zstd
                | Type::Lzip
                | Type::Pdf
                | Type::Rtf
                | Type::OneNote
                | Type::Chm
                | Type::Wim
                | Type::DisqueVirtuel
                | Type::Dmg
                | Type::Xar
                | Type::Ar
                | Type::Rpm
                | Type::Cpio
                | Type::SquashFs
        )
    }

    /// Un exécutable ou ce qui en lance un (raccourci, script) : ce qu'une extension de document ne doit pas cacher.
    pub(crate) fn executable(self) -> bool {
        // Les scripts n'en sont pas : leur langage n'est que deviné, et un texte s'ouvre dans un éditeur.
        matches!(
            self,
            Type::Pe | Type::ExecutableDos | Type::Elf | Type::MachO | Type::MachOUniversel | Type::Lnk | Type::Msi
        )
    }
}

/// D'où vient une partie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origine {
    /// Le fichier analysé.
    Fichier,
    /// Une entrée d'un zip, désignée par son répertoire central.
    EntreeZip,
    /// Une entrée d'un zip au-delà du nombre annoncé par la fin du répertoire central.
    EntreeZipCachee,
    /// Un en-tête local que le répertoire central ne désigne pas.
    EntreeZipLocale,
    /// Un zip collé à la fin d'un autre fichier (image, document…).
    ZipAjoute,
    /// Le contenu d'un gzip.
    Gzip,
    EntreeTar,
    FluxOle,
    /// Une entrée du fichier composé que son arbre n'atteint pas.
    FluxOleOrphelin,
    SourceVba,
    /// Des octets après la fin des données d'un exécutable (PE, ELF, Mach-O) ou d'un raccourci.
    Overlay,
    /// Des octets dans la table des certificats d'un PE, au-delà des certificats qu'elle déclare.
    ApresCertificats,
    /// Une architecture d'un Mach-O universel.
    Tranche,
    /// Le texte d'un script UTF-16, en UTF-8.
    TexteDecode,
}

/// Pourquoi tout ou partie d'une partie n'a pas été lu : dit « non vérifié », jamais compté sain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Raison {
    /// Aucun format reconnu : les octets sont lus tels quels, leur structure ne l'est pas.
    FormatInconnu,
    /// Un format reconnu dont le contenu n'est pas ouvert ici (7z, RAR, CAB, ISO, PDF…).
    FormatNonLu(Type),
    Chiffre,
    /// Coupé, ou une structure qui s'arrête avant sa fin.
    Tronque,
    /// Une structure abîmée ou refusée (en-têtes, flux deflate, répertoire).
    Illisible(&'static str),
    /// Une méthode de compression zip que Vanguard ne décompresse pas.
    Methode(u16),
    /// Plus grand que la borne d'un fichier ou d'une partie : le reste n'est pas lu.
    TropGros,
    Profondeur,
    TropDeParties,
    /// Les octets produits en tout ont atteint leur borne.
    Production,
    /// Le taux de compression dépasse sa borne : une bombe, arrêtée.
    TauxDeCompression,
    /// La partie contient l'un de ses ancêtres (une « quine ») : pas rouverte.
    Quine,
    Delai,
    /// Plus d'entrées que la borne : les autres ne sont pas vues.
    EntreesLimitees,
    /// Un raccourci dont seule la liste d'identifiants (non décodée) désigne la cible.
    CibleNonDecodee,
    /// Un module VBA dont la source ne se lit pas (flux absent, compression abîmée) ou est vide alors que le
    /// module a du code compilé (« p-code », qui s'exécute quand même).
    SourceVbaIllisible,
    /// Les octets examinés en tout ont atteint leur borne (tranches qui se chevauchent, overlays) : le reste n'est
    /// pas lu.
    Travail,
    /// Des macros Excel 4.0 (XLM) d'un classeur 97-2003 : leurs formules, compilées, ne sont pas décodées.
    MacrosXlmNonDecodees,
    /// Un exécutable compressé par un paqueteur connu (UPX) : son vrai code n'est pas lu.
    Paquete(&'static str),
    /// Un format dont la fin ne se trouve pas (TIFF, image coupée ou abîmée) : des données ajoutées après, qu'un
    /// extracteur ouvrirait, ne se distinguent pas de l'image.
    FinIntrouvable,
    /// Un module VBA qui a du code compilé (p-code) : c'est lui qu'Office exécute quand sa version correspond, et il
    /// n'est pas décodé ici. Une source leurre (« Sub Bonjour() ») peut le cacher : la source lue ne prouve rien.
    PcodeNonLu,
}

/// Un fait relevé (pour les heuristiques d'AV4) : rien de tout cela n'est un verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Fait {
    Nom(nom::FaitNom),
    /// Une extension de document sur un contenu qui s'exécute (« photo.jpg » qui est un programme).
    ExtensionTrompeuse(String),
    // Archives.
    /// L'en-tête local porte un autre nom que le répertoire central (deux extracteurs ne verraient pas le même).
    NomLocalDifferent(String),
    /// Le champ Unicode d'Info-ZIP porte un autre nom.
    NomUnicodeDifferent(String),
    /// Un autre nom de la même archive est égal à celui-ci, sans tenir compte de la casse.
    NomEnDouble,
    /// Les mêmes données qu'une autre entrée (non relues).
    DonneesPartagees(String),
    CrcFaux,
    TailleAnnonceeFausse {
        annoncee: u64,
        lue: u64,
    },
    /// Des octets devant l'archive (programme auto-extractible, autre fichier).
    DonneesAvantArchive(u64),
    /// Un lien symbolique ou physique dans une archive tar (non suivi) : son nom et sa cible.
    Lien(String),
    // PE.
    SectionEcrivableExecutable(String),
    PointEntreeHorsSection,
    PointEntreeDansSectionEcrivable,
    /// La dernière section porte le point d'entrée (ce que font souvent les paqueteurs et les infecteurs).
    PointEntreeDansDerniereSection,
    Authenticode(crate::pe::Authenticode),
    /// Des octets cachés dans la table des certificats, après les certificats déclarés.
    DonneesApresSignature(u64),
    Overlay(u64),
    Dotnet,
    ImportsIncomplets,
    /// Une section à l'entropie d'un contenu compressé ou chiffré (au-delà de 7,2 bits par octet).
    SectionEntropieElevee {
        nom: String,
        entropie: u16,
    },
    // ELF.
    SegmentEcrivableExecutable,
    PileExecutable,
    PointEntreeHorsSegmentExecutable,
    Interpreteur(String),
    SectionsIllisibles,
    // Mach-O.
    SegmentMachOEcrivableExecutable(String),
    SignatureDeCode,
    EditeurDeLiens(String),
    TranchesHorsFichier(usize),
    // Office.
    /// Un projet VBA : nombre de modules.
    MacrosVba(usize),
    ModuleVba(String),
    /// Plus de faits que la borne : les suivants ne sont pas gardés.
    FaitsLimites,
    /// Des octets après la fin du flux compressé d'une entrée zip, dans sa place.
    DonneesApresFlux(u64),
    /// L'en-tête local d'une entrée zip ne dit pas la même chose que le répertoire central (méthode, chiffrement,
    /// tailles) : les deux lectures sont faites.
    EnTeteLocalDifferent,
    /// Une procédure qui se lance d'elle-même (AutoOpen, Document_Open, Workbook_Open…).
    ProcedureAutomatique(String),
    /// Une feuille de macros Excel 4.0 (XLM).
    MacrosXlm(String),
    /// Une feuille masquée (`true` : « très masquée », invisible dans l'interface).
    FeuilleMasquee {
        nom: String,
        tres: bool,
    },
    /// Une relation vers l'extérieur dans un document OOXML (modèle ou objet chargé à l'ouverture).
    RelationExterne(String),
    /// Des contrôles ActiveX déclarés.
    ActiveX,
    /// Des macros Basic dans un document OpenDocument.
    MacrosBasic,
    /// L'arbre du fichier composé revient sur lui-même.
    ArbreOleBoucle,
    FluxOrphelin(String),
    // Raccourcis.
    CibleLnk(String),
    CibleApprochee(String),
    ArgumentsLnk(String),
    DossierDeTravail(String),
    IconeLnk(String),
    /// Un interpréteur nommé dans la cible, les arguments ou la liste d'identifiants.
    InterpreteurLance(&'static str),
    ArgumentsRembourres,
    // Texte.
    Encodage(texte::Encodage),
    /// La ligne « #! ».
    LigneInterpreteur(String),
    /// La plus longue ligne, si elle dépasse 1 000 caractères (obscurcissement fréquent).
    LigneLongue(usize),
}

/// Le détail d'une structure lue, pour qui en veut plus que les faits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Details {
    Aucun,
    Pe(Box<crate::pe::StructurePe>),
    Elf(Box<elf::Elf>),
    MachO(Box<macho::MachO>),
    Lnk(Box<lnk::Lnk>),
    Vba(Box<vba::Projet>),
    Texte {
        encodage: texte::Encodage,
        langage: texte::Langage,
        lignes: usize,
    },
}

/// Une partie de l'arbre.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Partie {
    /// Le numéro de la partie qui la contient (`None` : le fichier).
    pub parent: Option<usize>,
    pub profondeur: usize,
    /// Le chemin dans la partie parente (nom d'entrée, chemin de flux, « #overlay »…), ou le nom du fichier.
    pub chemin: String,
    pub origine: Origine,
    pub type_: Type,
    pub taille: u64,
    /// `None` : les octets n'ont pas été lus (entrée chiffrée, trop grosse, méthode inconnue…).
    pub sha256: Option<[u8; 32]>,
    pub faits: Vec<Fait>,
    pub manques: Vec<Raison>,
    pub details: Details,
}

/// L'analyse d'un fichier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Analyse {
    /// Les parties, la première est le fichier ; chacune après son parent.
    pub parties: Vec<Partie>,
    /// Les octets produits (décompressés, décodés, extraits).
    pub produits: u64,
    pub duree: Duration,
}

impl Analyse {
    /// Tout a-t-il été lu ? Faux dès qu'une partie a un manque : le fichier est alors « non vérifié ».
    pub(crate) fn entierement_lue(&self) -> bool {
        self.parties.iter().all(|p| p.manques.is_empty())
    }

    /// Chaque manque, avec le numéro de sa partie.
    pub(crate) fn manques(&self) -> impl Iterator<Item = (usize, &Raison)> {
        self.parties
            .iter()
            .enumerate()
            .flat_map(|(i, p)| p.manques.iter().map(move |r| (i, r)))
    }

    /// Les parties directement contenues dans la partie `i`.
    pub(crate) fn enfants(&self, i: usize) -> impl Iterator<Item = usize> + '_ {
        self.parties
            .iter()
            .enumerate()
            .filter(move |(_, p)| p.parent == Some(i))
            .map(|(k, _)| k)
    }

    /// Le chemin complet d'une partie (« facture.docx › word/vbaProject.bin › VBA/Module1 »).
    pub(crate) fn chemin_complet(&self, i: usize) -> String {
        let mut morceaux = Vec::new();
        let mut k = Some(i);
        while let Some(j) = k {
            morceaux.push(self.parties[j].chemin.as_str());
            k = self.parties[j].parent;
        }
        morceaux.reverse();
        morceaux.join(" › ")
    }
}

//! Le parcours d'un fichier en arbre de parties, borné : chaque partie est reconnue par son contenu, lue par son
//! lecteur, et ses enfants analysés à leur tour, en profondeur, un à la fois (seuls les octets de la branche en cours
//! sont gardés en mémoire). Le visiteur reçoit chaque partie lue avec ses octets, une fois : les motifs (AV2) et les
//! signatures (AV3) les lisent là, sans que l'arbre garde le contenu.

use std::time::Instant;

use super::{Analyse, Bornes, Details, Fait, Origine, Partie, Raison, Type};
use super::{cfb, elf, lnk, macho, nature, nom, office, ovba, texte, vba};
use crate::archives::{deflate, tar, zip};

/// L'entropie au-delà de laquelle une section a l'air compressée ou chiffrée (en millièmes de bit par octet).
const ENTROPIE_ELEVEE: u16 = 7200;
/// La plus longue ligne d'un texte qui mérite d'être dite.
const LIGNE_LONGUE: usize = 1000;
/// Les noms de flux internes connus des fichiers composés : leur contenu, de forme propre à l'application, est lu
/// tel quel sans être « inconnu ».
const FLUX_CONNUS: &[&str] = &[
    "WordDocument",
    "1Table",
    "0Table",
    "Workbook",
    "Book",
    "PowerPoint Document",
    "Current User",
    "\u{5}SummaryInformation",
    "\u{5}DocumentSummaryInformation",
    "\u{1}CompObj",
    "\u{1}Ole",
    "\u{3}ObjInfo",
    "EncryptionInfo",
    "EncryptedPackage",
];

/// Les faits gardés pour une partie.
const FAITS_MAX: usize = 1024;
/// Les projets VBA lus dans un fichier composé (un document en a un).
const PROJETS_VBA_MAX: usize = 16;
/// Les membres d'un gzip lus à la suite.
const MEMBRES_GZIP_MAX: usize = 4096;

/// L'état d'une analyse.
struct Etat<'v> {
    bornes: Bornes,
    debut: Instant,
    produits: u64,
    /// Les octets examinés (empreinte, type, lecture) de toutes les parties, copiées ou non : le coût en temps.
    examines: u64,
    taille_racine: u64,
    parties: Vec<Partie>,
    /// Les empreintes de la branche en cours (une partie qui en contient une est une quine).
    ancetres: Vec<[u8; 32]>,
    visiteur: &'v mut dyn FnMut(&Partie, &[u8]),
}

/// L'analyse de `octets`, nommé `nom` (le nom du fichier, pour les faits de nom ; jamais pour le type). `visiteur`
/// est appelé une fois pour chaque partie dont les octets sont lus.
pub(crate) fn analyser(octets: &[u8], nom: &str, bornes: &Bornes, visiteur: &mut dyn FnMut(&Partie, &[u8])) -> Analyse {
    let mut e = Etat {
        bornes: *bornes,
        debut: Instant::now(),
        produits: 0,
        examines: 0,
        taille_racine: octets.len() as u64,
        parties: Vec::new(),
        ancetres: Vec::new(),
        visiteur,
    };
    if octets.len() as u64 > bornes.taille_fichier {
        e.non_lue(
            None,
            nom.to_string(),
            Origine::Fichier,
            octets.len() as u64,
            Vec::new(),
            vec![Raison::TropGros],
        );
    } else {
        e.partie(octets, None, nom.to_string(), Origine::Fichier, Vec::new(), Vec::new());
    }
    Analyse {
        parties: e.parties,
        produits: e.produits,
        duree: e.debut.elapsed(),
    }
}

/// L'analyse du fichier `chemin` : un fichier ordinaire seulement (un tube nommé bloquerait la lecture), lu en entier
/// s'il tient dans la borne, sinon dit « trop gros » sans être lu.
pub(crate) fn analyser_fichier(
    chemin: &std::path::Path,
    bornes: &Bornes,
    visiteur: &mut dyn FnMut(&Partie, &[u8]),
) -> std::io::Result<Analyse> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
    let fichier = options.open(chemin)?;
    let meta = fichier.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "pas un fichier ordinaire",
        ));
    }
    let nom = chemin
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if meta.len() > bornes.taille_fichier {
        let mut e = Etat {
            bornes: *bornes,
            debut: Instant::now(),
            produits: 0,
            examines: 0,
            taille_racine: meta.len(),
            parties: Vec::new(),
            ancetres: Vec::new(),
            visiteur,
        };
        e.non_lue(
            None,
            nom,
            Origine::Fichier,
            meta.len(),
            Vec::new(),
            vec![Raison::TropGros],
        );
        return Ok(Analyse {
            parties: e.parties,
            produits: 0,
            duree: e.debut.elapsed(),
        });
    }
    // Lu jusqu'à la borne plus un octet : un fichier qui grandit pendant la lecture se voit trop gros, jamais coupé
    // en silence.
    let mut octets = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    fichier
        .take(bornes.taille_fichier.saturating_add(1))
        .read_to_end(&mut octets)?;
    Ok(analyser(&octets, &nom, bornes, visiteur))
}

#[cfg(test)]
pub(super) fn essai_sha256(octets: &[u8]) -> [u8; 32] {
    sha256(octets)
}

fn sha256(octets: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(octets);
    h.finalize().into()
}

impl Etat<'_> {
    fn manque(&mut self, i: usize, raison: Raison) {
        if let Some(p) = self.parties.get_mut(i)
            && !p.manques.contains(&raison)
        {
            p.manques.push(raison);
        }
    }

    fn fait(&mut self, i: usize, fait: Fait) {
        // Une partie qui accumulerait des centaines de milliers de faits (flux orphelins, modules) coûterait leur
        // carré à comparer : au-delà de la borne, un seul fait le dit.
        if let Some(p) = self.parties.get_mut(i)
            && !p.faits.contains(&fait)
        {
            if p.faits.len() < FAITS_MAX {
                p.faits.push(fait);
            } else if !p.faits.contains(&Fait::FaitsLimites) {
                p.faits.push(Fait::FaitsLimites);
            }
        }
    }

    /// Une partie dont les octets ne sont pas lus (chiffrée, méthode inconnue, trop grosse…) : elle figure dans
    /// l'arbre, avec ses manques, sans empreinte ni visite.
    fn non_lue(
        &mut self,
        parent: Option<usize>,
        chemin: String,
        origine: Origine,
        taille: u64,
        mut faits: Vec<Fait>,
        manques: Vec<Raison>,
    ) -> Option<usize> {
        if let Some(p) = parent
            && self.parties.len() >= self.bornes.parties
        {
            self.manque(p, Raison::TropDeParties);
            return None;
        }
        faits.extend(nom::examiner(&chemin).into_iter().map(Fait::Nom));
        let profondeur = parent.map_or(0, |p| self.parties[p].profondeur + 1);
        self.parties.push(Partie {
            parent,
            profondeur,
            chemin,
            origine,
            type_: Type::Inconnu,
            taille,
            sha256: None,
            faits,
            manques,
            details: Details::Aucun,
        });
        Some(self.parties.len() - 1)
    }

    /// Les octets qu'une extraction peut encore produire : la borne d'une partie, celle du total, et le taux de
    /// compression. `Err` : la raison qui l'interdit.
    fn budget(&self) -> Result<usize, Raison> {
        if self.produits > self.bornes.seuil_taux
            && self.produits > self.bornes.taux.saturating_mul(self.taille_racine.max(1))
        {
            return Err(Raison::TauxDeCompression);
        }
        let reste = self.bornes.produits.saturating_sub(self.produits);
        if reste == 0 {
            return Err(Raison::Production);
        }
        Ok(usize::try_from(reste)
            .unwrap_or(usize::MAX)
            .min(self.bornes.taille_partie))
    }

    /// La raison d'une extraction arrêtée à `limite` octets : la borne d'une partie, ou celle du total.
    fn raison_de_limite(&self, limite: usize) -> Raison {
        if limite >= self.bornes.taille_partie {
            Raison::TropGros
        } else {
            Raison::Production
        }
    }

    fn produit(&mut self, n: usize) {
        self.produits = self.produits.saturating_add(n as u64);
    }

    /// La partie `octets`, puis ses enfants. Rend son numéro (`None` : pas analysée, une borne l'a dit au parent).
    fn partie(
        &mut self,
        octets: &[u8],
        parent: Option<usize>,
        chemin: String,
        origine: Origine,
        mut faits: Vec<Fait>,
        manques: Vec<Raison>,
    ) -> Option<usize> {
        if let Some(p) = parent {
            if self.parties.len() >= self.bornes.parties {
                self.manque(p, Raison::TropDeParties);
                return None;
            }
            if self.debut.elapsed() > self.bornes.delai {
                self.manque(p, Raison::Delai);
                return None;
            }
            // Des tranches qui se chevauchent (architectures d'un Mach-O, overlays) ne sont pas copiées, donc pas
            // comptées dans `produits` : leur lecture l'est ici.
            if self.examines.saturating_add(octets.len() as u64) > self.bornes.examines {
                self.manque(p, Raison::Travail);
                return None;
            }
        }
        self.examines = self.examines.saturating_add(octets.len() as u64);
        let empreinte = sha256(octets);
        let type_ = nature::deviner(octets);
        faits.extend(nom::examiner(&chemin).into_iter().map(Fait::Nom));
        if type_.executable()
            && let Some(extension) = nom::extension(&chemin).filter(|e| nom::DOCUMENTS.contains(&e.as_str()))
        {
            faits.push(Fait::ExtensionTrompeuse(extension));
        }
        let profondeur = parent.map_or(0, |p| self.parties[p].profondeur + 1);
        self.parties.push(Partie {
            parent,
            profondeur,
            chemin,
            origine,
            type_,
            taille: octets.len() as u64,
            sha256: Some(empreinte),
            faits,
            manques,
            details: Details::Aucun,
        });
        let i = self.parties.len() - 1;
        if self.ancetres.contains(&empreinte) {
            self.manque(i, Raison::Quine);
        } else {
            self.ancetres.push(empreinte);
            self.lire(i, octets, type_);
            self.ancetres.pop();
        }
        (self.visiteur)(&self.parties[i], octets);
        Some(i)
    }

    /// Un enfant de `i` : refusé à la profondeur maximale (dit sur `i`).
    fn enfant(
        &mut self,
        i: usize,
        octets: &[u8],
        chemin: String,
        origine: Origine,
        faits: Vec<Fait>,
        manques: Vec<Raison>,
    ) -> Option<usize> {
        if self.parties[i].profondeur + 1 > self.bornes.profondeur {
            self.manque(i, Raison::Profondeur);
            return None;
        }
        self.partie(octets, Some(i), chemin, origine, faits, manques)
    }

    fn lire(&mut self, i: usize, octets: &[u8], type_: Type) {
        // Le début de l'overlay déjà analysé à part (un zip qui y commence est déjà vu).
        let mut overlay: Option<u64> = None;
        match type_ {
            Type::Pe => overlay = self.pe(i, octets),
            Type::Elf => overlay = self.elf(i, octets),
            Type::MachO => overlay = self.macho(i, octets),
            Type::MachOUniversel => overlay = self.universel(i, octets),
            Type::Zip => self.zip(i, octets),
            Type::Gzip => self.gzip(i, octets),
            Type::Tar => self.tar(i, octets),
            Type::Cfb => self.cfb(i, octets),
            Type::Lnk => overlay = self.lnk(i, octets),
            Type::Image => overlay = self.image(i, octets),
            Type::Script(_) | Type::Texte => self.texte(i, octets),
            Type::Inconnu => self.manque(i, Raison::FormatInconnu),
            t if t.non_lu() => self.manque(i, Raison::FormatNonLu(t)),
            _ => {}
        }
        // Les formats que leurs lecteurs cherchent ailleurs qu'au début (un fichier peut être les deux à la fois) :
        // PDF dans le premier Kio, ISO 9660 au secteur 16.
        if type_ != Type::Pdf && nature::pdf_au_debut(octets) {
            self.manque(i, Raison::FormatNonLu(Type::Pdf));
        }
        if type_ != Type::Iso && nature::iso(octets) {
            self.manque(i, Raison::FormatNonLu(Type::Iso));
        }
        // Un zip collé à la fin, que lirait un extracteur qui cherche la fin de l'archive depuis la fin du fichier :
        // derrière n'importe quel fichier, sauf ceux dont il est déjà la lecture (zip, OOXML…).
        if !matches!(
            self.parties[i].type_,
            Type::Zip | Type::Ooxml | Type::OpenDocument | Type::Jar | Type::Apk | Type::Vide
        ) {
            self.zip_ajoute(i, octets, overlay);
        }
    }

    /// Une image PNG : ses morceaux jusqu'à IEND ; ce qui suit est analysé à part.
    fn image(&mut self, i: usize, octets: &[u8]) -> Option<u64> {
        let fin = nature::fin_png(octets)?;
        if fin >= octets.len() {
            return None;
        }
        let r = fin as u64..octets.len() as u64;
        self.fait(i, Fait::Overlay(r.end - r.start));
        self.morceau(i, octets, r.clone(), "#apres-image", Origine::Overlay);
        Some(r.start)
    }

    // --- Exécutables ---

    fn pe(&mut self, i: usize, octets: &[u8]) -> Option<u64> {
        let Some(s) = crate::pe::structure(octets) else {
            self.manque(i, Raison::Illisible("en-têtes PE"));
            return None;
        };
        for section in &s.sections {
            if section.executable() && section.ecrivable() {
                self.fait(i, Fait::SectionEcrivableExecutable(section.nom.clone()));
            }
            if section.entropie > ENTROPIE_ELEVEE {
                self.fait(
                    i,
                    Fait::SectionEntropieElevee {
                        nom: section.nom.clone(),
                        entropie: section.entropie,
                    },
                );
            }
        }
        // UPX : ses sections (« UPX0 », « UPX1 ») ou sa marque « UPX! » dans les en-têtes, que renommer les sections
        // ne retire pas.
        if s.sections.iter().any(|x| x.nom.starts_with("UPX"))
            || octets[..octets.len().min(4096)].windows(4).any(|f| f == b"UPX!")
        {
            self.manque(i, Raison::Paquete("UPX"));
        }
        if !s.point_entree_dans_une_section() {
            self.fait(i, Fait::PointEntreeHorsSection);
        }
        if let Some(section) = s.section_du_point_entree() {
            if section.ecrivable() {
                self.fait(i, Fait::PointEntreeDansSectionEcrivable);
            }
            if s.sections.len() > 1 && s.sections.last() == Some(section) {
                self.fait(i, Fait::PointEntreeDansDerniereSection);
            }
        }
        self.fait(i, Fait::Authenticode(s.authenticode));
        if s.dotnet {
            self.fait(i, Fait::Dotnet);
        }
        if s.imports_incomplets {
            self.fait(i, Fait::ImportsIncomplets);
        }
        if let Some(r) = s.apres_certificats.clone() {
            self.fait(i, Fait::DonneesApresSignature(r.end - r.start));
            self.morceau(i, octets, r, "#apres-certificats", Origine::ApresCertificats);
        }
        for r in s.overlay.clone() {
            self.fait(i, Fait::Overlay(r.end - r.start));
            self.morceau(i, octets, r.clone(), &format!("#overlay@{}", r.start), Origine::Overlay);
        }
        let debut_overlay = s.overlay.first().map(|r| r.start);
        self.parties[i].details = Details::Pe(Box::new(s));
        debut_overlay
    }

    /// Les octets `r` de `octets`, analysés comme un enfant (sans copie).
    fn morceau(&mut self, i: usize, octets: &[u8], r: std::ops::Range<u64>, chemin: &str, origine: Origine) {
        let (Ok(debut), Ok(fin)) = (usize::try_from(r.start), usize::try_from(r.end)) else {
            return;
        };
        if let Some(m) = octets.get(debut..fin) {
            self.enfant(i, m, chemin.to_string(), origine, Vec::new(), Vec::new());
        }
    }

    fn elf(&mut self, i: usize, octets: &[u8]) -> Option<u64> {
        let Some(e) = elf::lire(octets) else {
            self.manque(i, Raison::Illisible("en-tête ELF"));
            return None;
        };
        if e.segments
            .iter()
            .any(|s| s.type_ == elf::PT_LOAD && s.ecrivable() && s.executable())
        {
            self.fait(i, Fait::SegmentEcrivableExecutable);
        }
        if e.pile_executable == Some(true) {
            self.fait(i, Fait::PileExecutable);
        }
        if matches!(e.type_, 2 | 3) && !e.point_entree_executable() {
            self.fait(i, Fait::PointEntreeHorsSegmentExecutable);
        }
        if let Some(interp) = &e.interpreteur {
            self.fait(i, Fait::Interpreteur(interp.clone()));
        }
        if e.sections_illisibles {
            self.fait(i, Fait::SectionsIllisibles);
        }
        if e.segments_illisibles {
            self.manque(i, Raison::Illisible("table des segments ELF"));
        }
        let mut debut_overlay = None;
        if e.fin_des_donnees < octets.len() as u64 {
            let r = e.fin_des_donnees..octets.len() as u64;
            debut_overlay = Some(r.start);
            self.fait(i, Fait::Overlay(r.end - r.start));
            self.morceau(i, octets, r, "#overlay", Origine::Overlay);
        }
        self.parties[i].details = Details::Elf(Box::new(e));
        debut_overlay
    }

    fn macho(&mut self, i: usize, octets: &[u8]) -> Option<u64> {
        let Some(m) = macho::lire(octets) else {
            self.manque(i, Raison::Illisible("en-tête Mach-O"));
            return None;
        };
        for s in &m.segments {
            if s.ecrivable_executable() {
                self.fait(i, Fait::SegmentMachOEcrivableExecutable(s.nom.clone()));
            }
        }
        if m.signature {
            self.fait(i, Fait::SignatureDeCode);
        }
        if let Some(d) = &m.editeur_de_liens {
            self.fait(i, Fait::EditeurDeLiens(d.clone()));
        }
        if m.chiffre.is_some() {
            self.manque(i, Raison::Chiffre);
        }
        if m.commandes_illisibles {
            self.manque(i, Raison::Illisible("commandes de chargement Mach-O"));
        }
        let mut debut_overlay = None;
        if m.fin_des_donnees < octets.len() as u64 && !m.commandes_illisibles {
            let r = m.fin_des_donnees..octets.len() as u64;
            debut_overlay = Some(r.start);
            self.fait(i, Fait::Overlay(r.end - r.start));
            self.morceau(i, octets, r, "#overlay", Origine::Overlay);
        }
        self.parties[i].details = Details::MachO(Box::new(m));
        debut_overlay
    }

    fn universel(&mut self, i: usize, octets: &[u8]) -> Option<u64> {
        let Some(u) = macho::universel(octets) else {
            self.manque(i, Raison::Illisible("en-tête universel"));
            return None;
        };
        if u.tranches_hors_fichier > 0 {
            self.fait(i, Fait::TranchesHorsFichier(u.tranches_hors_fichier));
            self.manque(i, Raison::Tronque);
        }
        for (k, t) in u.tranches.iter().enumerate() {
            self.morceau(
                i,
                octets,
                t.position..t.position + t.taille,
                &format!("#tranche{k}"),
                Origine::Tranche,
            );
        }
        if u.fin_des_donnees < octets.len() as u64 {
            let r = u.fin_des_donnees..octets.len() as u64;
            self.fait(i, Fait::Overlay(r.end - r.start));
            self.morceau(i, octets, r.clone(), "#overlay", Origine::Overlay);
            return Some(r.start);
        }
        None
    }

    // --- Archives ---

    fn zip(&mut self, i: usize, octets: &[u8]) {
        let p = zip::parcourir(octets, self.bornes.entrees);
        if !p.fin_trouvee || p.central_illisible {
            // Sans répertoire central lisible, seuls les en-têtes locaux sont vus : on ne sait pas s'il en manque.
            self.manque(i, Raison::Tronque);
        }
        if p.multidisque {
            self.manque(i, Raison::Illisible("archive sur plusieurs disques"));
        }
        if p.limitees {
            self.manque(i, Raison::EntreesLimitees);
        }
        if p.decalage > 0 {
            self.fait(i, Fait::DonneesAvantArchive(p.decalage as u64));
        }
        // Le type précis, par les noms d'entrées.
        let noms: Vec<String> = p.entrees.iter().map(|v| nom_zip(&v.nom, v.utf8)).collect();
        let a = |n: &str| noms.iter().any(|x| x == n);
        self.parties[i].type_ = if a("[Content_Types].xml") {
            Type::Ooxml
        } else if a("mimetype") && noms.iter().any(|n| n.starts_with("META-INF/")) {
            Type::OpenDocument
        } else if a("AndroidManifest.xml") {
            Type::Apk
        } else if a("META-INF/MANIFEST.MF") {
            Type::Jar
        } else {
            Type::Zip
        };
        if self.parties[i].type_ == Type::OpenDocument && noms.iter().any(|n| n.starts_with("Basic/")) {
            self.fait(i, Fait::MacrosBasic);
        }
        let mut vus_casse: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for n in &noms {
            *vus_casse.entry(n.to_lowercase()).or_default() += 1;
        }
        // Les données déjà lues : même en-tête local, même méthode, mêmes tailles et drapeaux de chiffrement (une
        // entrée qui désigne le même en-tête avec une autre méthode ou une autre taille se lit autrement : relue).
        let mut locaux: std::collections::HashMap<(usize, u16, u64, u64, u16), String> =
            std::collections::HashMap::new();
        for (vue, nom) in p.entrees.iter().zip(noms) {
            if self.debut.elapsed() > self.bornes.delai {
                self.manque(i, Raison::Delai);
                return;
            }
            let mut faits = Vec::new();
            let origine = match vue.provenance {
                zip::Provenance::Centrale => Origine::EntreeZip,
                zip::Provenance::AuDelaDuNombre => Origine::EntreeZipCachee,
                zip::Provenance::LocaleSeule => Origine::EntreeZipLocale,
            };
            if vue.local_different {
                faits.push(Fait::EnTeteLocalDifferent);
            }
            if let Some(local) = vue.nom_local.as_ref().filter(|l| **l != vue.nom) {
                faits.push(Fait::NomLocalDifferent(nom_zip(local, vue.utf8)));
            }
            if let Some(u) = &vue.nom_unicode {
                let u = String::from_utf8_lossy(u).into_owned();
                if u != nom {
                    faits.push(Fait::NomUnicodeDifferent(u));
                }
            }
            if vus_casse.get(&nom.to_lowercase()).copied().unwrap_or(0) > 1 {
                faits.push(Fait::NomEnDouble);
            }
            // Un dossier vide n'est pas une partie.
            if nom.ends_with('/') && vue.taille == 0 && vue.compresse == 0 {
                continue;
            }
            let cle = (vue.local, vue.methode, vue.compresse, vue.taille, vue.drapeaux & 0x41);
            if let Some(autre) = locaux.get(&cle) {
                faits.push(Fait::DonneesPartagees(autre.clone()));
                self.non_lue(Some(i), nom, origine, vue.taille, faits, Vec::new());
                continue;
            }
            locaux.insert(cle, nom.clone());
            if self.parties[i].profondeur + 1 > self.bornes.profondeur {
                self.manque(i, Raison::Profondeur);
                return;
            }
            let limite = match self.budget() {
                Ok(l) => l,
                Err(r) => {
                    self.non_lue(Some(i), nom, origine, vue.taille, faits, vec![r]);
                    continue;
                }
            };
            match zip::extraire(octets, vue, limite) {
                Err(refus) => {
                    let raison = match refus {
                        zip::Refus::Chiffree => Raison::Chiffre,
                        zip::Refus::Methode(m) => Raison::Methode(m),
                        zip::Refus::Illisible => Raison::Illisible("entrée zip"),
                    };
                    self.non_lue(Some(i), nom, origine, vue.taille, faits, vec![raison]);
                }
                Ok(x) => {
                    self.produit(x.contenu.len());
                    let mut manques = Vec::new();
                    match x.fin {
                        deflate::Fin::Complet => {}
                        deflate::Fin::Limite => manques.push(self.raison_de_limite(limite)),
                        deflate::Fin::Coupe => manques.push(Raison::Tronque),
                        deflate::Fin::Abime => manques.push(Raison::Illisible("flux deflate")),
                        deflate::Fin::Delai => manques.push(Raison::Delai),
                    }
                    if x.crc_juste == Some(false) {
                        faits.push(Fait::CrcFaux);
                    }
                    if x.fin == deflate::Fin::Complet && !vue.taille_inconnue && x.contenu.len() as u64 != vue.taille {
                        faits.push(Fait::TailleAnnonceeFausse {
                            annoncee: vue.taille,
                            lue: x.contenu.len() as u64,
                        });
                    }
                    self.office_dans_zip(i, &nom, &x.contenu);
                    if !x.reste.is_empty() {
                        self.fait(i, Fait::DonneesApresFlux((x.reste.end - x.reste.start) as u64));
                        let reste = x.reste.start as u64..x.reste.end as u64;
                        self.morceau(i, octets, reste, &format!("{nom}#apres-flux"), Origine::Overlay);
                    }
                    self.enfant(i, &x.contenu, nom, origine, faits, manques);
                }
            }
        }
    }

    /// Ce que les parties d'un document OOXML disent sur lui ([Content_Types].xml, relations).
    fn office_dans_zip(&mut self, i: usize, nom: &str, contenu: &[u8]) {
        if !matches!(self.parties[i].type_, Type::Ooxml) {
            return;
        }
        if nom == "[Content_Types].xml" {
            let t = office::types_de_contenu(&String::from_utf8_lossy(contenu));
            if t.macros_xlm {
                self.fait(i, Fait::MacrosXlm(String::new()));
            }
            if t.activex {
                self.fait(i, Fait::ActiveX);
            }
        } else if nom.to_ascii_lowercase().ends_with(".rels") {
            for cible in office::relations_externes(&String::from_utf8_lossy(contenu)) {
                self.fait(i, Fait::RelationExterne(cible));
            }
        }
    }

    fn zip_ajoute(&mut self, i: usize, octets: &[u8], overlay: Option<u64>) {
        // Une fin de répertoire central dans les 64 Kio de la fin, puis au moins une entrée dont l'en-tête local se
        // lit : là commence l'archive (une entrée centrale qui désigne n'importe où ne compte pas).
        let queue = octets.len().saturating_sub(65_557 + 22);
        if !octets[queue..].windows(4).any(|f| f == b"PK\x05\x06") {
            return;
        }
        let p = zip::parcourir(octets, self.bornes.entrees);
        if !p.fin_trouvee {
            return;
        }
        let debut = p.entrees.iter().filter(|e| e.donnees.is_some()).map(|e| e.local).min();
        let Some(debut) = debut.filter(|&d| d > 0) else {
            if p.entrees.iter().any(|e| e.provenance != zip::Provenance::LocaleSeule) {
                // Un répertoire central dont aucune entrée ne se lit : ce qu'un extracteur ferait ne se sait pas.
                self.manque(i, Raison::Illisible("zip collé à la fin"));
            }
            return;
        };
        // Déjà dans l'overlay, analysé à part.
        if overlay.is_some_and(|o| debut as u64 >= o) {
            return;
        }
        if let Some(archive) = octets.get(debut..) {
            self.enfant(
                i,
                archive,
                "#zip-ajoute".to_string(),
                Origine::ZipAjoute,
                Vec::new(),
                Vec::new(),
            );
        }
    }

    fn gzip(&mut self, i: usize, octets: &[u8]) {
        let nom = nom_gzip(octets).unwrap_or_else(|| "#contenu".to_string());
        let limite = match self.budget() {
            Ok(l) => l,
            Err(r) => {
                self.non_lue(Some(i), nom, Origine::Gzip, 0, Vec::new(), vec![r]);
                return;
            }
        };
        let mut contenu = Vec::new();
        let mut manques = Vec::new();
        let mut faits = Vec::new();
        let mut debut = 0usize;
        let mut apres = None;
        // Chaque membre, à la suite (comme gzip -d) ; leur somme bornée, leur nombre aussi.
        for membre in 0.. {
            if membre >= MEMBRES_GZIP_MAX {
                manques.push(Raison::EntreesLimitees);
                break;
            }
            if self.debut.elapsed() > self.bornes.delai {
                manques.push(Raison::Delai);
                break;
            }
            let Some(flux) = crate::archives::gzip::debut_du_flux(octets, debut) else {
                manques.push(Raison::Illisible("en-tête gzip"));
                break;
            };
            let lu = deflate::inflater(&octets[flux..], limite - contenu.len());
            let fin = flux + lu.lus;
            if lu.fin == deflate::Fin::Complet {
                let crc = octets
                    .get(fin..fin + 4)
                    .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
                if crc != Some(crate::archives::crc32::crc32(&lu.contenu)) {
                    faits.push(Fait::CrcFaux);
                }
            }
            contenu.extend_from_slice(&lu.contenu);
            match lu.fin {
                deflate::Fin::Complet => {}
                deflate::Fin::Limite => {
                    manques.push(self.raison_de_limite(limite));
                    break;
                }
                deflate::Fin::Coupe => {
                    manques.push(Raison::Tronque);
                    break;
                }
                deflate::Fin::Abime => {
                    manques.push(Raison::Illisible("flux deflate"));
                    break;
                }
                deflate::Fin::Delai => {
                    manques.push(Raison::Delai);
                    break;
                }
            }
            debut = fin + 8;
            if debut >= octets.len() {
                if debut > octets.len() {
                    manques.push(Raison::Tronque);
                }
                break;
            }
            if !crate::archives::gzip::est_gzip(&octets[debut..]) {
                // Autre chose après le dernier membre : analysé à part, comme un overlay.
                apres = Some(debut);
                break;
            }
        }
        self.produit(contenu.len());
        self.enfant(i, &contenu, nom, Origine::Gzip, faits, manques);
        if let Some(debut) = apres {
            self.fait(i, Fait::Overlay((octets.len() - debut) as u64));
            self.morceau(
                i,
                octets,
                debut as u64..octets.len() as u64,
                "#apres-gzip",
                Origine::Overlay,
            );
        }
    }

    fn tar(&mut self, i: usize, octets: &[u8]) {
        use std::ops::ControlFlow;
        let mut entrees = Vec::new();
        let fin = tar::parcourir(octets, self.bornes.entrees, |e| {
            entrees.push((e.nom, e.type_, e.position, e.contenu.len()));
            ControlFlow::Continue(())
        });
        match fin {
            tar::FinTar::Fin | tar::FinTar::Arretee => {}
            tar::FinTar::Coupee => self.manque(i, Raison::Tronque),
            tar::FinTar::Illisible => self.manque(i, Raison::Illisible("en-tête tar")),
            tar::FinTar::Limite => self.manque(i, Raison::EntreesLimitees),
        }
        let mut fin_des_entrees = 0usize;
        for (nom, type_, position, taille) in entrees {
            if self.debut.elapsed() > self.bornes.delai {
                self.manque(i, Raison::Delai);
                return;
            }
            let debut = position + 512;
            fin_des_entrees = fin_des_entrees.max(debut + taille.div_ceil(512) * 512);
            match type_ {
                // Liens : sans contenu, jamais suivis.
                b'1' | b'2' => {
                    let cible = octets
                        .get(position + 157..position + 257)
                        .map(|c| {
                            String::from_utf8_lossy(&c[..c.iter().position(|&o| o == 0).unwrap_or(c.len())])
                                .into_owned()
                        })
                        .unwrap_or_default();
                    self.fait(i, Fait::Lien(format!("{nom} -> {cible}")));
                }
                // Tout le reste qui a un contenu : GNU tar et libarchive extraient un type inconnu comme un fichier
                // ordinaire (0, nul, 7 contigu, mais aussi les lettres des éditeurs, un dossier qui aurait des
                // données). Le fichier clairsemé de GNU (« S ») n'a que ses morceaux de données : dit non reconstitué.
                _ if taille > 0 => {
                    let manques = if type_ == b'S' {
                        vec![Raison::Illisible("fichier clairsemé")]
                    } else {
                        Vec::new()
                    };
                    if let Some(contenu) = octets.get(debut..debut + taille) {
                        self.enfant(i, contenu, nom, Origine::EntreeTar, Vec::new(), manques);
                    }
                }
                _ => {}
            }
        }
        // Après le bloc de fin : une autre archive mise bout à bout (`tar -i` la lit), ou autre chose.
        if fin == tar::FinTar::Fin {
            let mut reste = fin_des_entrees.min(octets.len());
            while octets
                .get(reste..reste + 512)
                .is_some_and(|b| b.iter().all(|&o| o == 0))
            {
                reste += 512;
            }
            let queue = octets.get(reste..).unwrap_or(&[]);
            if queue.iter().any(|&o| o != 0) {
                self.fait(i, Fait::Overlay(queue.len() as u64));
                self.morceau(
                    i,
                    octets,
                    reste as u64..octets.len() as u64,
                    "#apres-tar",
                    Origine::Overlay,
                );
            }
        }
    }

    // --- Documents OLE ---

    fn cfb(&mut self, i: usize, octets: &[u8]) {
        let limite = self.bornes.taille_partie;
        let Ok(ole) = cfb::Cfb::lire(octets, limite) else {
            self.manque(i, Raison::Illisible("fichier composé"));
            return;
        };
        if ole.arbre_boucle {
            self.fait(i, Fait::ArbreOleBoucle);
        }
        if ole.fat_incomplete || ole.mini_illisible {
            self.manque(i, Raison::Tronque);
        }
        if ole.limite_atteinte {
            self.manque(i, Raison::EntreesLimitees);
        }
        let a_la_racine = |n: &str| {
            ole.places
                .iter()
                .any(|p| cfb::egaux_sans_casse(&ole.entrees[p.entree].nom, n) && p.parent == 0)
        };
        self.parties[i].type_ = if a_la_racine("EncryptedPackage") && a_la_racine("EncryptionInfo") {
            Type::OoxmlChiffre
        } else if a_la_racine("WordDocument") {
            Type::DocWord
        } else if a_la_racine("Workbook") || a_la_racine("Book") {
            Type::ClasseurExcel
        } else if a_la_racine("PowerPoint Document") {
            Type::PresentationPowerPoint
        } else if ole.entrees[0].clsid == office::CLSID_MSI {
            Type::Msi
        } else {
            Type::Cfb
        };
        match self.parties[i].type_ {
            Type::OoxmlChiffre => self.manque(i, Raison::Chiffre),
            // Le flux « PowerPoint Document » ([MS-PPT]) porte, compressés, le projet VBA et les objets embarqués :
            // il n'est pas lu.
            Type::PresentationPowerPoint => self.manque(i, Raison::FormatNonLu(Type::PresentationPowerPoint)),
            _ => {}
        }
        // Les projets VBA : chaque stockage « VBA » qui a un flux « dir ». Pour chaque flux de module, le ou les
        // modules qui le désignent (nom, début de la source).
        let mut modules: std::collections::HashMap<usize, Vec<(String, u32)>> = std::collections::HashMap::new();
        // Les flux que le projet désigne (dir, modules) : connus, sans être « inconnus ».
        let mut flux_du_projet: std::collections::HashSet<usize> = std::collections::HashSet::new();
        let stockages_vba: Vec<(usize, String)> = ole
            .places
            .iter()
            .filter(|p| ole.entrees[p.entree].type_ == 1 && cfb::egaux_sans_casse(&ole.entrees[p.entree].nom, "VBA"))
            .map(|p| (p.entree, p.chemin.clone()))
            .collect();
        let mut projets = 0usize;
        for (stockage, _) in &stockages_vba {
            if self.debut.elapsed() > self.bornes.delai {
                self.manque(i, Raison::Delai);
                return;
            }
            let Some(dir) = ole.flux_nomme(*stockage, "dir") else {
                continue;
            };
            projets += 1;
            if projets > PROJETS_VBA_MAX {
                self.manque(i, Raison::EntreesLimitees);
                break;
            }
            flux_du_projet.insert(dir);
            let limite = match self.budget() {
                Ok(l) => l,
                Err(r) => {
                    self.manque(i, r);
                    continue;
                }
            };
            let Ok(brut) = ole.flux(dir, limite) else {
                self.manque(i, Raison::SourceVbaIllisible);
                continue;
            };
            // Le flux brut est une copie : compté, comme tout ce qui est produit.
            self.produit(brut.len());
            let budget = match self.budget() {
                Ok(b) => b,
                Err(r) => {
                    self.manque(i, r);
                    continue;
                }
            };
            let d = ovba::decompresser(&brut, budget);
            self.produit(d.contenu.len());
            let projet = vba::lire_dir(&d.contenu);
            if d.defaut.is_some() || projet.incomplet {
                self.manque(i, Raison::SourceVbaIllisible);
            }
            self.fait(i, Fait::MacrosVba(projet.modules.len()));
            for m in &projet.modules {
                self.fait(i, Fait::ModuleVba(m.nom.clone()));
                // Le nom Unicode et celui sur un octet, s'ils diffèrent : les deux flux sont lus comme sources.
                let mut trouve = false;
                for nom in std::iter::once(&m.flux).chain(m.flux_mbcs.iter()) {
                    if let Some(f) = ole.flux_nomme(*stockage, nom) {
                        trouve = true;
                        flux_du_projet.insert(f);
                        modules.entry(f).or_default().push((m.nom.clone(), m.decalage));
                    }
                }
                if !trouve {
                    self.manque(i, Raison::SourceVbaIllisible);
                }
            }
            self.parties[i].details = Details::Vba(Box::new(projet));
        }
        // Chaque flux atteint par l'arbre, puis les orphelins. Dans un stockage VBA, sont connus les flux que
        // le projet désigne et ceux que [MS-OVBA] 2.3.4 nomme (_VBA_PROJECT, PROJECT, PROJECTwm, PROJECTlk, __SRP_n).
        let parents_vba: std::collections::HashSet<usize> = ole
            .places
            .iter()
            .filter(|p| stockages_vba.iter().any(|(s, _)| *s == p.entree))
            .map(|p| p.parent)
            .collect();
        let vba_nomme = |p: &cfb::Place| {
            let nom = &ole.entrees[p.entree].nom;
            (stockages_vba.iter().any(|(s, _)| p.parent == *s)
                && (["_VBA_PROJECT", "dir"].iter().any(|n| cfb::egaux_sans_casse(n, nom))
                    || nom.to_ascii_uppercase().starts_with("__SRP_")))
                || (parents_vba.contains(&p.parent)
                    && ["PROJECT", "PROJECTwm", "PROJECTlk"]
                        .iter()
                        .any(|n| cfb::egaux_sans_casse(n, nom)))
        };
        let flux: Vec<(usize, String, bool, bool)> = ole
            .places
            .iter()
            .filter(|p| ole.entrees[p.entree].type_ == 2)
            .map(|p| {
                (
                    p.entree,
                    p.chemin.clone(),
                    false,
                    vba_nomme(p) || flux_du_projet.contains(&p.entree),
                )
            })
            .chain(
                ole.orphelines
                    .iter()
                    .filter(|&&k| ole.entrees[k].type_ == 2)
                    .map(|&k| (k, ole.entrees[k].nom.clone(), true, false)),
            )
            .collect();
        for (k, chemin, orphelin, vba) in flux {
            if self.debut.elapsed() > self.bornes.delai {
                self.manque(i, Raison::Delai);
                return;
            }
            let chemin_affiche: String = chemin
                .chars()
                .flat_map(|ch| {
                    if ch.is_control() {
                        ch.escape_default().collect::<Vec<_>>()
                    } else {
                        vec![ch]
                    }
                })
                .collect();
            if orphelin {
                self.fait(i, Fait::FluxOrphelin(chemin_affiche.clone()));
            }
            let origine = if orphelin {
                Origine::FluxOleOrphelin
            } else {
                Origine::FluxOle
            };
            let taille = ole.entrees[k].taille;
            let limite = match self.budget() {
                Ok(l) => l,
                Err(r) => {
                    self.non_lue(Some(i), chemin_affiche, origine, taille, Vec::new(), vec![r]);
                    continue;
                }
            };
            let donnees = match ole.flux(k, limite) {
                Ok(d) => d,
                Err(defaut) => {
                    let raison = match defaut {
                        cfb::Defaut::Limite => self.raison_de_limite(limite),
                        cfb::Defaut::Tronque => Raison::Tronque,
                        _ => Raison::Illisible("chaîne de secteurs"),
                    };
                    self.non_lue(Some(i), chemin_affiche, origine, taille, Vec::new(), vec![raison]);
                    continue;
                }
            };
            self.produit(donnees.len());
            let nom_flux = ole.entrees[k].nom.clone();
            self.faits_du_flux(i, &nom_flux, &donnees);
            let connu = vba || FLUX_CONNUS.iter().any(|n| cfb::egaux_sans_casse(n, &nom_flux));
            let Some(j) = self.enfant(i, &donnees, chemin_affiche.clone(), origine, Vec::new(), Vec::new()) else {
                continue;
            };
            if connu && self.parties[j].type_ == Type::Inconnu {
                self.parties[j].type_ = Type::FluxOle;
                self.parties[j].manques.retain(|r| *r != Raison::FormatInconnu);
            }
            for (nom_module, decalage) in modules.get(&k).cloned().unwrap_or_default() {
                self.source_vba(j, &donnees, &nom_module, decalage, &chemin_affiche);
            }
        }
    }

    /// Ce que disent les flux de Word et d'Excel.
    fn faits_du_flux(&mut self, i: usize, nom: &str, donnees: &[u8]) {
        if cfb::egaux_sans_casse(nom, "WordDocument") && office::word_chiffre(donnees) == Some(true) {
            self.manque(i, Raison::Chiffre);
        }
        if cfb::egaux_sans_casse(nom, "Workbook") || cfb::egaux_sans_casse(nom, "Book") {
            let c = office::classeur(donnees);
            if c.chiffre {
                self.manque(i, Raison::Chiffre);
            }
            if c.incomplet {
                self.manque(i, Raison::Illisible("classeur"));
            }
            for f in c.feuilles {
                if f.sorte == 1 {
                    self.fait(i, Fait::MacrosXlm(f.nom.clone()));
                    self.manque(i, Raison::MacrosXlmNonDecodees);
                }
                if f.masquage > 0 {
                    self.fait(
                        i,
                        Fait::FeuilleMasquee {
                            nom: f.nom,
                            tres: f.masquage == 2,
                        },
                    );
                }
            }
        }
    }

    /// La source du module VBA dont le flux est la partie `j` : décompressée depuis `decalage`, puis ses procédures
    /// qui se lancent d'elles-mêmes.
    fn source_vba(&mut self, j: usize, flux: &[u8], nom_module: &str, decalage: u32, chemin: &str) {
        let Some(compresse) = flux.get(decalage as usize..) else {
            self.manque(j, Raison::SourceVbaIllisible);
            return;
        };
        let budget = match self.budget() {
            Ok(b) => b,
            Err(r) => {
                self.manque(j, r);
                return;
            }
        };
        let d = ovba::decompresser(compresse, budget);
        self.produit(d.contenu.len());
        let mut manques = Vec::new();
        match d.defaut {
            None => {}
            Some(ovba::Defaut::Limite) => manques.push(self.raison_de_limite(budget)),
            Some(_) => manques.push(Raison::SourceVbaIllisible),
        }
        let source = super::lecture::latin1_ou_utf8(&d.contenu);
        // Une source sans code (rien que ses lignes « Attribute ») derrière du code compilé (le flux en a avant
        // `decalage`) : ce code s'exécute quand même, et n'est pas décodé ici.
        if decalage > 0 && vba::source_sans_code(&source) {
            manques.push(Raison::SourceVbaIllisible);
        }
        let faits: Vec<Fait> = vba::procedures_automatiques(&source, nom_module)
            .into_iter()
            .map(Fait::ProcedureAutomatique)
            .collect();
        for f in &faits {
            // Remontée sur le fichier composé : le premier fait qu'une heuristique y cherchera.
            if let Some(parent) = self.parties[j].parent {
                self.fait(parent, f.clone());
            }
        }
        if let Some(k) = self.enfant(
            j,
            source.as_bytes(),
            format!("{chemin}#source"),
            Origine::SourceVba,
            faits,
            manques,
        ) {
            self.parties[k].type_ = Type::SourceVba;
            self.parties[k].manques.retain(|r| *r != Raison::FormatInconnu);
        }
    }

    // --- Raccourcis et texte ---

    fn lnk(&mut self, i: usize, octets: &[u8]) -> Option<u64> {
        let Some(l) = lnk::lire(octets) else {
            self.manque(i, Raison::Illisible("raccourci"));
            return None;
        };
        if l.tronque {
            self.manque(i, Raison::Tronque);
        }
        if let Some(cible) = l.cible() {
            self.fait(i, Fait::CibleLnk(cible));
        }
        if !l.cible_coherente() {
            if let Some(approchee) = l.cible_approchee() {
                self.fait(i, Fait::CibleApprochee(approchee));
            }
            self.manque(i, Raison::CibleNonDecodee);
        }
        if let Some(a) = &l.arguments {
            self.fait(i, Fait::ArgumentsLnk(a.clone()));
        }
        if let Some(d) = &l.dossier {
            self.fait(i, Fait::DossierDeTravail(d.clone()));
        }
        if let Some(c) = &l.icone {
            self.fait(i, Fait::IconeLnk(c.clone()));
        }
        for interp in l.interpreteurs() {
            self.fait(i, Fait::InterpreteurLance(interp));
        }
        if l.arguments_rembourres() {
            self.fait(i, Fait::ArgumentsRembourres);
        }
        let mut debut_overlay = None;
        if !l.tronque && l.fin < octets.len() {
            let r = l.fin as u64..octets.len() as u64;
            debut_overlay = Some(r.start);
            self.fait(i, Fait::Overlay(r.end - r.start));
            self.morceau(i, octets, r, "#overlay", Origine::Overlay);
        }
        self.parties[i].details = Details::Lnk(Box::new(l));
        debut_overlay
    }

    fn texte(&mut self, i: usize, octets: &[u8]) {
        let limite = self.bornes.texte.min(self.bornes.taille_partie);
        let Some(t) = texte::lire(octets, limite) else {
            self.manque(i, Raison::FormatInconnu);
            return;
        };
        self.fait(i, Fait::Encodage(t.encodage));
        if let Some(l) = &t.interpreteur {
            self.fait(i, Fait::LigneInterpreteur(l.clone()));
        }
        if t.plus_longue_ligne > LIGNE_LONGUE {
            self.fait(i, Fait::LigneLongue(t.plus_longue_ligne));
        }
        self.parties[i].details = Details::Texte {
            encodage: t.encodage,
            langage: t.langage,
            lignes: t.lignes,
        };
        // Au-delà de la limite, rien ne dit que c'est encore du texte.
        if t.tronque {
            self.manque(i, Raison::TropGros);
        }
        // L'UTF-16 décodé : ce que liront les motifs écrits en ASCII.
        if t.encodage.utf16() {
            let manques = if t.tronque { vec![Raison::TropGros] } else { Vec::new() };
            if self.budget().is_err() {
                self.manque(i, Raison::Production);
                return;
            }
            self.produit(t.contenu.len());
            self.enfant(
                i,
                t.contenu.as_bytes(),
                "#texte".to_string(),
                Origine::TexteDecode,
                Vec::new(),
                manques,
            );
        }
    }
}

/// Le nom d'une entrée zip : UTF-8 si le drapeau le dit (ou si c'en est), sinon octet par octet.
fn nom_zip(nom: &[u8], utf8: bool) -> String {
    if utf8 {
        String::from_utf8_lossy(nom).into_owned()
    } else {
        super::lecture::latin1_ou_utf8(nom)
    }
}

/// Le nom d'origine écrit dans l'en-tête gzip (FNAME), s'il y est.
fn nom_gzip(octets: &[u8]) -> Option<String> {
    let drapeaux = *octets.get(3)?;
    if drapeaux & 8 == 0 {
        return None;
    }
    let mut pos = 10usize;
    if drapeaux & 4 != 0 {
        pos += 2 + usize::from(super::lecture::u16le(octets, pos)?);
    }
    super::lecture::chaine_c(octets, pos, 4096).filter(|n| !n.is_empty())
}

//! Le registre des règles du bilan. Chaque règle se déclare là où elle est écrite (`inventory::submit!`), avec un
//! identifiant stable et ce qu'il faut savoir d'elle ; le bilan prend toutes celles de son système et les lance en
//! parallèle avec les autres vérifications. Ajouter une règle, c'est l'écrire et la déclarer : aucune liste centrale à
//! tenir. Son identifiant suit chacun de ses constats (champ `regle`) jusqu'au rapport JSON : reformuler un message ne
//! change pas la règle.

use super::{Constat, Verification};

/// Le système d'une règle.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Os {
    Linux,
    Windows,
    /// Les deux : les vérifications communes, montrées après celles du système.
    Tous,
}

impl Os {
    /// Celui où tourne Vanguard.
    pub const fn actuel() -> Os {
        if cfg!(windows) { Os::Windows } else { Os::Linux }
    }

    /// Le début des identifiants de ses règles.
    #[cfg(test)]
    pub const fn prefixe(self) -> &'static str {
        match self {
            Os::Linux => "LNX",
            Os::Windows => "WIN",
            Os::Tous => "COM",
        }
    }
}

/// Une règle du bilan.
pub struct Regle {
    /// Stable et jamais réutilisé : système, domaine, numéro (« LNX-PLT-001 »).
    pub id: &'static str,
    pub systeme: Os,
    /// Sa place dans le bilan : les règles s'y montrent par rang croissant (100 et plus pour celles du système, 500
    /// et plus pour les communes), comme les listes d'avant.
    pub rang: u16,
    /// Ce qu'elle vérifie, en français et en anglais.
    pub sujet: (&'static str, &'static str),
    /// Références de durcissement (CIS, ANSSI, documentation de l'éditeur), quand il y en a.
    pub references: &'static [&'static str],
    pub verifier: fn() -> Vec<Constat>,
    /// Ce que le relevé local (`amelioration`) garde de l'objet d'un constat : son nom, ou sa sorte seule.
    pub partage: Partage,
}

/// Le nom de l'objet d'un constat est-il gardé par le relevé local (plan d'auto-amélioration, §1) ? `Nom` seulement
/// pour les règles dont ce nom est le sujet (logiciel périmé, pilote vulnérable, service ou unité en échec, programme
/// espion connu) ; toutes les autres (logiciels nouveaux, extensions, fichiers, réseau, sites) n'en gardent que la
/// sorte, et c'est la valeur que donne `regle!` sans rien dire. Garde : `partage_du_nom_seulement_pour_ses_sujets`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Partage {
    Nom,
    Sorte,
}

inventory::collect!(Regle);

/// Déclare une règle au registre : identifiant, système, rang, sujet (français, anglais), références, vérification.
/// Un identifiant mal formé ne compile pas.
/// Un septième argument, `partage = Nom`, garde le nom de l'objet au relevé local (`Partage`).
macro_rules! regle {
    ($id:literal, $os:expr, $rang:literal, $sujet:expr, $refs:expr, $verifier:expr, partage = $p:ident $(,)?) => {
        const _: () = assert!(
            $crate::modele::id::bien_forme($id),
            "identifiant de règle mal formé"
        );
        inventory::submit! {
            $crate::machine::regles::Regle {
                id: $id,
                systeme: $os,
                rang: $rang,
                sujet: $sujet,
                references: $refs,
                verifier: $verifier,
                partage: $crate::machine::regles::Partage::$p,
            }
        }
    };
    ($id:literal, $os:expr, $rang:literal, $sujet:expr, $refs:expr, $verifier:expr $(,)?) => {
        $crate::machine::regles::regle!($id, $os, $rang, $sujet, $refs, $verifier, partage = Sorte);
    };
}
pub(crate) use regle;

/// Les règles d'un système, communes comprises, dans l'ordre du bilan (rang, puis identifiant).
pub fn regles(os: Os) -> Vec<&'static Regle> {
    let mut regles: Vec<&'static Regle> = inventory::iter::<Regle>
        .into_iter()
        .filter(|r| r.systeme == os || r.systeme == Os::Tous)
        .collect();
    regles.sort_by_key(|r| (r.rang, r.id));
    regles
}

/// La référence d'abord citée d'une règle de ce système (CIS, Microsoft ou ANSSI : `modele::reference`) ; `None`
/// pour un identifiant inconnu ici (vide, constat hors du registre).
pub(crate) fn reference_de(id: &str) -> Option<&'static str> {
    if id.is_empty() {
        return None;
    }
    inventory::iter::<Regle>
        .into_iter()
        .find(|r| r.id == id)
        .and_then(|r| crate::modele::reference::principale(r.references))
}

/// Le texte d'un sujet dans la langue de l'interface.
fn sujet(s: (&'static str, &'static str)) -> &'static str {
    if crate::langue::anglais() { s.1 } else { s.0 }
}

/// « vanguard regles » : les règles du bilan pour ce système (toutes ses vérifications), puis celles de l'audit du
/// réseau et les outils, avec leur sujet et leurs références : un seul registre d'identifiants.
pub fn afficher() {
    use crate::ui::*;
    let ligne = |id: &str, s: (&'static str, &'static str), references: &[&str]| {
        println!("  {TOUCHE}{id}{RESET}  {}", sujet(s));
        if !references.is_empty() {
            println!("        {GRIS}{}{RESET}", references.join(" · "));
        }
    };
    let regles = regles(Os::actuel());
    titre(&crate::trf!(
        "Règles du bilan déclarées pour ce système : {}",
        "Check rules declared for this system: {}",
        regles.len()
    ));
    for r in regles {
        ligne(r.id, r.sujet, r.references);
    }
    let fiches = crate::audit::fiches::FICHES;
    titre(&crate::trf!(
        "Règles de l'audit du réseau : {}",
        "Network audit rules: {}",
        fiches.len()
    ));
    for f in fiches {
        ligne(f.id, f.sujet, f.references);
    }
    let outils = crate::modele::registre::OUTILS;
    titre(&crate::trf!(
        "Outils et surveillances : {}",
        "Tools and monitoring: {}",
        outils.len()
    ));
    for o in outils {
        ligne(o.id, o.sujet, &[]);
    }
    let croisees = crate::autotest::croisees::croisees();
    titre(&crate::trf!(
        "Lectures croisées de l'autotest : {}",
        "Self-test cross-checks: {}",
        croisees.len()
    ));
    for c in croisees {
        ligne(c.id, c.sujet, &[c.outil]);
    }
}

/// Tous les identifiants de ce programme : règles du bilan de ce système, fiches de l'audit du réseau, outils et
/// surveillances (identifiant, sujet).
#[cfg(test)]
pub(crate) fn tous_les_identifiants() -> Vec<(&'static str, (&'static str, &'static str))> {
    regles(Os::actuel())
        .into_iter()
        .map(|r| (r.id, r.sujet))
        .chain(crate::audit::fiches::FICHES.iter().map(|f| (f.id, f.sujet)))
        .chain(crate::modele::registre::OUTILS.iter().map(|o| (o.id, o.sujet)))
        .chain(
            crate::journaux_windows::regles::jeu::REGLES
                .iter()
                .map(|r| (r.id, r.sujet)),
        )
        .chain(
            crate::autotest::croisees::croisees()
                .into_iter()
                .map(|c| (c.id, c.sujet)),
        )
        .collect()
}

/// Les règles qui peuvent encore ne rien rendre sans panne : chez elles, une liste vide veut dire « rien à signaler »
/// ou « rien à juger » (pas de clé branchée, aucun piège posé, rien d'anormal). Ailleurs, une règle qui ne rend
/// rien devient « non vérifié » (`modele::Raison::Muette`), jamais un silence qu'on lirait comme sain. Cliquet :
/// la liste ne fait que rétrécir, à mesure que ces règles disent elles-mêmes sain, sans objet ou non vérifié.
pub(crate) const MUETTES_TOLEREES: &[&str] = &[
    "COM-AGT-001",
    "COM-AGT-002",
    "COM-BLU-001",
    "COM-CLE-001",
    "COM-CLE-002",
    "COM-CLE-003",
    "COM-CPT-001",
    "COM-CPT-002",
    "COM-CPT-003",
    "COM-CRT-001",
    "COM-DIS-001",
    "COM-DNS-001",
    "COM-ESP-001",
    "COM-ETA-001",
    "COM-FIC-001",
    "COM-HEU-001",
    "COM-HIS-001",
    "COM-INT-002",
    "COM-JRN-001",
    "COM-MAJ-001",
    "COM-MAT-001",
    "COM-MDP-001",
    "COM-NAV-001",
    "COM-NAV-002",
    "COM-PAR-001",
    "COM-PRG-001",
    "COM-PUB-001",
    "COM-SAV-001",
    "COM-SUR-001",
    "COM-SUR-003",
    "LNX-CPT-002",
    "LNX-CTN-001",
    "LNX-JRN-001",
    "LNX-MAJ-002",
    "LNX-MAJ-004",
    "LNX-MAJ-006",
    "LNX-NOY-001",
    "LNX-NOY-002",
    "LNX-NOY-005",
    "LNX-NOY-006",
    "LNX-PRS-001",
    "LNX-PRS-002",
    "LNX-PRS-004",
    "LNX-PRV-001",
    "LNX-PRV-002",
    "LNX-PRV-003",
    "LNX-PRV-004",
    "LNX-RES-002",
    "LNX-SES-001",
    "LNX-SES-002",
    "LNX-SES-003",
    "LNX-SSH-002",
    "LNX-SSH-003",
    "LNX-SSH-004",
    "LNX-SSH-005",
    "LNX-SSH-006",
    "WIN-ANV-001",
    "WIN-ANV-002",
    "WIN-CPT-001",
    "WIN-CPT-002",
    "WIN-DEM-001",
    "WIN-JRN-002",
    "WIN-MAJ-002",
    "WIN-PRS-001",
    "WIN-PRS-002",
    "WIN-PRS-003",
    "WIN-PRS-004",
    "WIN-PRS-005",
    "WIN-PRS-006",
    "WIN-PRS-007",
    "WIN-PRS-008",
    "WIN-PRS-009",
    "WIN-PRS-010",
    "WIN-PRS-011",
    "WIN-PRS-012",
    "WIN-RES-002",
    "WIN-SRV-001",
];

/// Le plafond du cliquet : baisser ce nombre quand une règle sort de la liste, jamais le monter.
#[cfg(test)]
const MUETTES_TOLEREES_AU_PLUS: usize = 77;

/// Les vérifications du bilan pour ce système, une par règle, dans l'ordre des rangs (le bilan les lance par
/// `machine::bilan_des_regles`).
#[cfg(test)]
pub(super) fn verifications<'a>() -> Vec<Verification<'a>> {
    regles(Os::actuel()).into_iter().map(verification).collect()
}

/// Le délai d'une règle ordinaire : bien au-delà de ce que prend la plus lente (lire un dossier personnel chargé,
/// relire des journaux), assez court pour qu'un bilan figé (fichier sur un montage réseau mort, appel du système qui
/// ne revient pas) finisse et nomme la règle fautive.
pub(crate) const DELAI: std::time::Duration = std::time::Duration::from_mins(10);
/// Celui des règles qui attendent Internet ou le gestionnaire de mises à jour (domaine « MAJ ») :
/// winget, la recherche de Windows Update et les sources des logiciels pas à jour prennent parfois plusieurs minutes.
pub(crate) const DELAI_LONG: std::time::Duration = std::time::Duration::from_mins(30);

/// Les règles qui ne prennent jamais de second essai (R4) : celles des journaux effacés, dont l'une cède à l'autre ce
/// qu'elle a lu dans le même bilan (`apres_les_regles`) ; une seconde lecture le ferait dire deux fois. L'auto-réglage
/// n'en note donc jamais pour elles.
pub(crate) const SANS_SECOND_ESSAI: [&str; 2] = ["COM-JRN-001", "WIN-JRN-003"];

impl Regle {
    /// Au-delà, la règle est dite non vérifiée et le bilan continue sans elle.
    pub(crate) fn delai(&self) -> std::time::Duration {
        if self.id.get(4..7) == Some("MAJ") {
            DELAI_LONG
        } else {
            DELAI
        }
    }

    /// Le délai appliqué : celui du code, monté à `DELAI_LONG` si l'auto-réglage l'a monté (`longs`,
    /// `autotest::reglage`). Jamais sous celui du code, jamais au-delà de `DELAI_LONG`.
    pub(crate) fn delai_avec(&self, longs: &std::collections::BTreeSet<String>) -> std::time::Duration {
        if longs.contains(self.id) {
            self.delai().max(DELAI_LONG)
        } else {
            self.delai()
        }
    }
}

/// La vérification d'une règle : chaque constat porte son identifiant, même celui d'une règle qui plante (« erreur
/// interne » non vérifiée, qui dit laquelle et que `Audit::fiable` voit), qui ne rend rien (« non vérifié », hors des
/// muettes tolérées) ou qui dépasse son délai (« non vérifié », délai dépassé).
#[cfg(test)]
pub(super) fn verification<'a>(r: &'static Regle) -> Verification<'a> {
    sous_delai(r, r.delai())
}

/// `verification`, avec le délai appliqué (`Regle::delai_avec`).
pub(super) fn verification_avec<'a>(r: &'static Regle, longs: &std::collections::BTreeSet<String>) -> Verification<'a> {
    sous_delai(r, r.delai_avec(longs))
}

/// Le second essai d'une règle (R4, `super::second_essai`), sous le délai que lui laisse le bilan.
pub(super) fn second_essai<'a>(r: &'static Regle, delai: std::time::Duration) -> Verification<'a> {
    sous_delai(r, delai)
}

/// Le délai d'un second essai (R4), compris dans le délai total du bilan : ce qui reste de `DELAI_LONG` depuis son
/// départ (`ecoule`), jamais plus que le délai de la règle (`delai`). Rien quand il n'en reste plus : un bilan qui
/// dépasse déjà `DELAI_LONG` ne relance rien.
pub(crate) fn delai_du_second_essai(
    ecoule: std::time::Duration,
    delai: std::time::Duration,
) -> Option<std::time::Duration> {
    DELAI_LONG
        .checked_sub(ecoule)
        .filter(|reste| !reste.is_zero())
        .map(|reste| reste.min(delai))
}

/// La règle tourne dans un fil à part, attendu au plus `delai`. Un fil bloqué ne peut pas être arrêté de
/// l'extérieur : il est laissé à lui-même (ce qu'il rendrait ensuite est jeté), et c'est le seul moyen de ne pas
/// figer le bilan ni la surveillance horaire derrière lui. `thread::scope` ne le permettrait pas : il attend chacun.
fn sous_delai<'a>(r: &'static Regle, delai: std::time::Duration) -> Verification<'a> {
    use crate::modele::Raison;
    use std::sync::mpsc::RecvTimeoutError;
    // L'interrupteur de lecture seule de l'autotest suit la règle dans son fil (il vaut par fil sous `cargo test`).
    let lecture_seule = crate::autotest::lecture_seule::heritage();
    // Le bilan dont cette vérification fait partie : celui en cours quand elle est créée, posé dans son fil.
    let bilan = super::bilan_en_cours();
    Box::new(move || {
        let (envoi, reception) = std::sync::mpsc::channel();
        let lance = std::thread::Builder::new()
            .name(format!("regle {}", r.id))
            .spawn(move || {
                lecture_seule.poser_ici();
                super::poser_bilan_du_fil(Some(bilan));
                // Le bilan peut être déjà reparti : un envoi qui ne trouve personne ne dit rien.
                let _ = envoi.send(crate::journal::rattraper(r.verifier));
            });
        let rendu = if lance.is_ok() {
            reception.recv_timeout(delai)
        } else {
            // Plus de fil possible (limite du système) : la règle tourne ici, sans délai, plutôt que pas du tout.
            let avant = super::poser_bilan_du_fil(Some(bilan));
            let rendu = crate::journal::rattraper(r.verifier);
            super::poser_bilan_du_fil(avant);
            Ok(rendu)
        };
        let mut constats = match rendu {
            Ok(Ok(constats)) => constats,
            Ok(Err(_)) | Err(RecvTimeoutError::Disconnected) => vec![super::impossible_par(
                "Audit",
                Raison::Panique,
                crate::trf!(
                    "Impossible de vérifier (erreur interne, règle {}).",
                    "Could not check (internal error, rule {}).",
                    r.id
                ),
            )],
            Err(RecvTimeoutError::Timeout) => vec![super::impossible_par(
                "Audit",
                Raison::Delai,
                crate::trf!(
                    "Impossible de vérifier ({}) : la vérification dépasse son délai de {} s, règle {}. Le bilan a continué sans elle.",
                    "Could not check ({}): the check exceeds its {} s time limit, rule {}. The check went on without it.",
                    sujet(r.sujet),
                    delai.as_secs(),
                    r.id
                ),
            )],
        };
        if constats.is_empty() && !MUETTES_TOLEREES.contains(&r.id) {
            constats.push(super::impossible_par(
                "Audit",
                Raison::Muette,
                crate::trf!(
                    "Impossible de vérifier ({}) : la vérification n'a rien rendu, règle {}.",
                    "Could not check ({}): the check returned nothing, rule {}.",
                    sujet(r.sujet),
                    r.id
                ),
            ));
        }
        constats
            .into_iter()
            .map(|mut c| {
                c.regle = r.id;
                c
            })
            .collect::<Vec<Constat>>()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Chaque identifiant : unique, de la forme « LNX-PLT-001 », au préfixe de son système ; chaque règle a son sujet
    /// dans les deux langues.
    #[test]
    fn identifiants_uniques_et_bien_formes() {
        let mut vus = std::collections::HashSet::new();
        for r in inventory::iter::<Regle> {
            assert!(vus.insert(r.id), "{} déclaré deux fois", r.id);
            let morceaux: Vec<&str> = r.id.split('-').collect();
            assert!(
                morceaux.len() == 3
                    && morceaux[0] == r.systeme.prefixe()
                    && morceaux[1].len() == 3
                    && morceaux[1].chars().all(|c| c.is_ascii_uppercase())
                    && morceaux[2].len() == 3
                    && morceaux[2].chars().all(|c| c.is_ascii_digit()),
                "identifiant mal formé : {}",
                r.id
            );
            assert!(!r.sujet.0.is_empty() && !r.sujet.1.is_empty(), "{} sans sujet", r.id);
        }
    }

    /// Le bilan de ce système lance une vérification par règle, dans l'ordre des rangs ; toutes sont bien
    /// enregistrées (une déclaration perdue à l'édition des liens ferait tomber le compte).
    #[test]
    fn une_verification_par_regle() {
        let regles = regles(Os::actuel());
        assert_eq!(verifications().len(), regles.len());
        assert!(regles.windows(2).all(|r| (r[0].rang, r[0].id) < (r[1].rang, r[1].id)));
        assert!(regles.len() >= 35, "{} règles seulement", regles.len());
        assert!(regles.iter().filter(|r| r.systeme == Os::Tous).count() >= 20);
    }

    /// Les lignes de tests/regles-connues.txt : (identifiant, marques).
    fn connus() -> Vec<(&'static str, Vec<&'static str>)> {
        include_str!("../../tests/regles-connues.txt")
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .map(|l| {
                let mut mots = l.split_whitespace();
                (mots.next().unwrap_or_default(), mots.collect())
            })
            .collect()
    }

    /// Un identifiant de ce système (ou commun) : ceux que ce programme compile tous.
    fn d_ici(id: &str) -> bool {
        // Les lectures croisées de l'autotest portent le système après « AUT- » : celles des autres ne sont pas
        // compilées ici.
        id.starts_with(Os::actuel().prefixe())
            || ["COM", "PRO", "SUR", "VEI", "EVT", "AUT-VAN"]
                .iter()
                .any(|p| id.starts_with(p))
            || id
                .strip_prefix("AUT-")
                .is_some_and(|r| r.starts_with(Os::actuel().prefixe()))
    }

    /// T1 : règles du bilan, fiches de l'audit du réseau et outils forment un seul registre : chaque identifiant une
    /// fois, bien formé, avec son sujet dans les deux langues.
    #[test]
    fn registre_unique() {
        let tous = tous_les_identifiants();
        let mut vus = std::collections::HashSet::new();
        for (id, (fr, en)) in &tous {
            assert!(vus.insert(*id), "{id} donné deux fois (règle, fiche ou outil)");
            assert!(crate::modele::id::bien_forme(id), "{id} mal formé");
            assert!(!fr.is_empty() && !en.is_empty(), "{id} sans sujet");
        }
        assert!(tous.len() >= 90, "{} identifiants seulement", tous.len());
        for o in crate::modele::registre::OUTILS {
            assert!(!o.module.is_empty(), "{} sans module", o.id);
            let prefixe = &o.id[..3];
            assert!(
                ["PRO", "SUR", "VEI", "AUT"].contains(&prefixe),
                "{} : préfixe d'outil attendu",
                o.id
            );
        }
    }

    /// T2 : chaque identifiant est noté dans tests/regles-connues.txt, un identifiant retiré n'y revient jamais, et un
    /// identifiant de ce système qui disparaît du programme doit y être marqué « retire » (sinon une autre règle
    /// pourrait le reprendre sans que l'historique ni les alertes acceptées ne le voient).
    #[test]
    fn identifiants_connus_jamais_repris() {
        let connus = connus();
        let mut vus = std::collections::HashSet::new();
        for (id, marques) in &connus {
            assert!(vus.insert(*id), "{id} noté deux fois dans regles-connues.txt");
            assert!(
                crate::modele::id::bien_forme(id),
                "{id} mal formé dans regles-connues.txt"
            );
            assert!(
                marques.iter().all(|m| *m == "retire"),
                "{id} : marque inconnue {marques:?}"
            );
        }
        let ici: std::collections::HashSet<&str> = tous_les_identifiants().into_iter().map(|(id, _)| id).collect();
        for id in &ici {
            match connus.iter().find(|(c, _)| c == id) {
                None => panic!("{id} absent de tests/regles-connues.txt : l'y ajouter"),
                Some((_, m)) => assert!(!m.contains(&"retire"), "{id} est retiré : jamais le reprendre"),
            }
        }
        for (id, marques) in &connus {
            if d_ici(id) && !marques.contains(&"retire") {
                assert!(
                    ici.contains(id),
                    "{id} n'existe plus : le marquer « retire » dans regles-connues.txt"
                );
            }
        }
    }

    /// T3 (C5) : chaque règle de ce système cite au moins une référence du CIS, de Microsoft ou de l'ANSSI, les
    /// mesures des CIS Controls v8 bien écrites ; chaque fiche de l'audit du réseau a ses références.
    #[test]
    fn chaque_regle_a_sa_reference() {
        use crate::modele::reference::{mesure_cis_bien_ecrite, principale};
        for r in regles(Os::actuel()) {
            assert!(
                principale(r.references).is_some(),
                "{} : citer une référence du CIS, de Microsoft ou de l'ANSSI",
                r.id
            );
            assert!(
                r.references.iter().all(|x| mesure_cis_bien_ecrite(x)),
                "{} : {:?}",
                r.id,
                r.references
            );
            assert_eq!(reference_de(r.id), principale(r.references));
        }
        for f in crate::audit::fiches::FICHES {
            assert!(!f.references.is_empty(), "{} sans référence", f.id);
        }
        assert_eq!(reference_de(""), None);
    }

    /// Les références des règles des deux systèmes, lues dans les sources : chaque système ne compile que les siennes,
    /// et les règles de Windows ne passeraient sinon ce test que sous Wine. (identifiant, références) de chaque
    /// `regle!` et de chaque `Regle { id: … }` de src/machine.
    fn regles_des_sources() -> Vec<(String, Vec<String>)> {
        fn parcourir(d: &std::path::Path, sortie: &mut Vec<(String, Vec<String>)>) {
            for e in std::fs::read_dir(d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    parcourir(&p, sortie);
                    continue;
                }
                if p.extension().is_none_or(|x| x != "rs") {
                    continue;
                }
                let texte = std::fs::read_to_string(&p).unwrap();
                let code = texte.find("#[cfg(test)]\nmod ").map_or(texte.as_str(), |t| &texte[..t]);
                for debut in ["regle!(", "id: \""] {
                    for (i, _) in code.match_indices(debut) {
                        let reste = &code[i + debut.len()..];
                        let reste = reste.trim_start().trim_start_matches('"');
                        let id: String = reste.chars().take(11).collect();
                        if !crate::modele::id::bien_forme(&id) || id.contains("TST") {
                            continue;
                        }
                        let Some(a) = reste.find("&[") else { continue };
                        let Some(b) = reste[a..].find(']') else { continue };
                        let refs = reste[a + 2..a + b]
                            .split('"')
                            .skip(1)
                            .step_by(2)
                            .map(String::from)
                            .collect();
                        sortie.push((id, refs));
                    }
                }
            }
        }
        let mut sortie = Vec::new();
        parcourir(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/machine"),
            &mut sortie,
        );
        sortie
    }

    /// Les seules règles dont le relevé local garde le nom de l'objet (plan d'auto-amélioration, §1 et P1) : ce nom
    /// y est le sujet même (logiciel périmé, paquet à faille, service en échec, pilote vulnérable, espion connu).
    const PARTAGE_DU_NOM: [&str; 5] = [
        "COM-ESP-001",
        "LNX-MAJ-003",
        "LNX-SRV-001",
        "WIN-MAJ-002",
        "WIN-PRS-012",
    ];

    /// Garde de `partage`, pour les deux systèmes (lu dans les sources) et pour celui-ci (règles enregistrées) :
    /// exactement les cinq règles de `PARTAGE_DU_NOM` disent `partage = Nom` ; les logiciels nouveaux, les
    /// extensions, les fichiers, le réseau, le Wi-Fi, le DNS, les partages et les sites n'en gardent que la sorte.
    /// Une règle de plus demande de changer la liste ici, donc une relecture.
    #[test]
    fn partage_du_nom_seulement_pour_ses_sujets() {
        fn parcourir(d: &std::path::Path, lues: &mut std::collections::BTreeSet<String>) {
            for e in std::fs::read_dir(d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    parcourir(&p, lues);
                    continue;
                }
                if p.extension().is_none_or(|x| x != "rs") {
                    continue;
                }
                let texte = std::fs::read_to_string(&p).unwrap();
                let code = texte.find("#[cfg(test)]\nmod ").map_or(texte.as_str(), |t| &texte[..t]);
                // Une règle écrite à la main (`partage: …::Nom`) ; nommer la variante ailleurs (un filtre) reste permis.
                assert!(
                    !code
                        .match_indices("partage:")
                        .any(|(i, _)| code[i..].split(',').next().is_some_and(|v| v.contains("Partage::Nom"))),
                    "{} : `partage = Nom` passe par regle!",
                    p.display()
                );
                // Seulement l'argument de `regle!`, seul sur sa ligne (la doc de la macro en parle aussi).
                for (i, _) in code.match_indices("\n    partage = Nom\n") {
                    let avant = &code[..i];
                    let debut = avant.rfind("regle!(").expect("partage hors de regle!");
                    let id: String = avant[debut + 7..]
                        .trim_start()
                        .trim_start_matches('"')
                        .chars()
                        .take(11)
                        .collect();
                    assert!(lues.insert(id), "{} : deux fois", p.display());
                }
            }
        }
        let mut lues = std::collections::BTreeSet::new();
        parcourir(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/machine"),
            &mut lues,
        );
        let attendues: std::collections::BTreeSet<String> = PARTAGE_DU_NOM.iter().map(|s| (*s).to_string()).collect();
        assert_eq!(lues, attendues);
        for r in inventory::iter::<Regle> {
            let nom = PARTAGE_DU_NOM.contains(&r.id);
            assert_eq!(r.partage == Partage::Nom, nom, "{}", r.id);
            for sorte in [
                "COM-NAV", "COM-FIC", "-RES-", "-WIF-", "COM-DNS", "COM-PAR", "COM-PRG", "COM-EXT",
            ] {
                assert!(!(r.id.contains(sorte) && r.partage == Partage::Nom), "{}", r.id);
            }
        }
    }

    /// C5, pour les deux systèmes : toute règle déclarée dans les sources cite une référence reconnue ; la lecture
    /// des sources trouve bien les règles de chaque système, nouvelles comprises.
    #[test]
    fn chaque_regle_des_deux_systemes_a_sa_reference() {
        use crate::modele::reference::{mesure_cis_bien_ecrite, principale};
        let lues = regles_des_sources();
        for (id, refs) in &lues {
            let refs: Vec<&str> = refs.iter().map(String::as_str).collect();
            assert!(
                principale(&refs).is_some(),
                "{id} : citer une référence du CIS, de Microsoft ou de l'ANSSI"
            );
            assert!(refs.iter().all(|r| mesure_cis_bien_ecrite(r)), "{id} : {refs:?}");
        }
        for attendu in [
            "WIN-SSH-001",
            "WIN-ANV-003",
            "WIN-DUR-005",
            "LNX-RES-003",
            "COM-LOG-001",
            "LNX-PLT-001",
        ] {
            assert!(
                lues.iter().any(|(id, _)| id == attendu),
                "{attendu} non lu dans les sources"
            );
        }
        // Celles de ce système, toutes lues : la lecture ne peut pas en manquer une sans que ce test le voie.
        for r in regles(Os::actuel()) {
            assert!(
                lues.iter().any(|(id, _)| id == r.id),
                "{} non lu dans les sources",
                r.id
            );
        }
        assert!(lues.len() >= 120, "{} règles lues seulement", lues.len());
    }

    /// Lot 7b : chaque identifiant d'ATT&CK cité par une règle (bilan des deux systèmes, audit du réseau, journaux
    /// de Windows) existe dans la version 20 : ni faute de frappe ni ancien numéro. La carte COUVERTURE-ATTACK.md
    /// en est tirée (outils/couverture-attack.py) ; citer ATT&CK n'est pas obligatoire.
    #[test]
    fn identifiants_attack_connus() {
        use crate::modele::reference::{attack_inconnu, faute_attack};
        let mut fautes = Vec::new();
        let mut cites = 0;
        let lues = regles_des_sources();
        let sources = lues
            .iter()
            .map(|(id, refs)| (id.as_str(), refs.iter().map(String::as_str).collect()));
        let fiches = crate::audit::fiches::FICHES
            .iter()
            .map(|f| (f.id, f.references.to_vec()));
        for (id, refs) in sources.chain(fiches) {
            let refs: Vec<&str> = refs;
            for r in &refs {
                cites += usize::from(r.starts_with("MITRE ATT&CK "));
                fautes.extend(faute_attack(r).map(|f| format!("{id} : {f}")));
            }
        }
        for r in crate::journaux_windows::regles::jeu::REGLES {
            assert!(!r.techniques.is_empty(), "{} sans technique", r.id);
            for t in r.techniques {
                cites += 1;
                fautes.extend(attack_inconnu(t).map(|f| format!("{} : {f}", r.id)));
            }
        }
        assert!(fautes.is_empty(), "{}", fautes.join("\n"));
        assert!(cites >= 176, "{cites} citations d'ATT&CK seulement");
    }

    /// T5 : le cliquet des muettes tolérées : rangées, une seule fois, au plus ce qu'elles étaient, toutes connues,
    /// et celles de ce système existent encore.
    #[test]
    fn cliquet_des_muettes() {
        assert!(
            MUETTES_TOLEREES.len() <= MUETTES_TOLEREES_AU_PLUS,
            "la liste des muettes tolérées ne doit jamais grandir"
        );
        assert!(
            MUETTES_TOLEREES.windows(2).all(|p| p[0] < p[1]),
            "liste à ranger, sans doublon"
        );
        let connus = connus();
        let ici: Vec<&str> = regles(Os::actuel()).iter().map(|r| r.id).collect();
        for id in MUETTES_TOLEREES {
            assert!(connus.iter().any(|(c, _)| c == id), "{id} inconnue");
            assert!(
                !d_ici(id) || ici.contains(id),
                "{id} n'existe plus : la retirer de MUETTES_TOLEREES"
            );
        }
    }

    /// Une règle lit dans son fil le numéro du bilan dont sa vérification fait partie : celui d'à sa création, même
    /// si un autre bilan avance le compteur avant qu'elle tourne (WIN-JRN-003 y note sa lecture de System, que
    /// COM-JRN-001 ne reprend que pour ce bilan-là). Hors d'une vérification, aucun.
    #[test]
    fn numero_du_bilan_recu_par_la_regle() {
        // u64::MAX : la règle n'a lu aucun numéro dans son fil.
        static VU: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let regle: &'static Regle = Box::leak(Box::new(Regle {
            id: "LNX-TST-002",
            systeme: Os::actuel(),
            rang: 1,
            sujet: ("essai", "test"),
            references: &[],
            partage: Partage::Sorte,
            verifier: || {
                VU.store(
                    super::super::bilan_du_fil().unwrap_or(u64::MAX),
                    std::sync::atomic::Ordering::Relaxed,
                );
                vec![super::super::ok("Audit", "essai")]
            },
        }));
        let avant = super::super::bilan_en_cours();
        let v = verification(regle);
        let cree = super::super::bilan_en_cours();
        super::super::BILAN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        v();
        let vu = VU.load(std::sync::atomic::Ordering::Relaxed);
        assert!(avant <= vu && vu <= cree, "{avant} ≤ {vu} ≤ {cree}");
        assert!(vu < super::super::bilan_en_cours());
        assert_eq!(super::super::bilan_du_fil(), None);
    }

    /// Chaque règle de ce système, mise à l'épreuve : si elle ne rendait rien, son constat dirait « non vérifié
    /// (muette) » avec son identifiant (sauf les muettes tolérées) ; si elle plantait, « non vérifié (erreur
    /// interne) ». Jamais un silence, jamais un sain.
    #[test]
    fn toute_regle_muette_ou_plantee_dit_non_verifie() {
        use crate::modele::{Etat, Raison};
        for r in regles(Os::actuel()) {
            let doublure = |verifier: fn() -> Vec<Constat>| -> &'static Regle {
                Box::leak(Box::new(Regle {
                    id: r.id,
                    systeme: r.systeme,
                    rang: r.rang,
                    sujet: r.sujet,
                    references: r.references,
                    verifier,
                    partage: r.partage,
                }))
            };
            let muette = verification(doublure(Vec::new))();
            if MUETTES_TOLEREES.contains(&r.id) {
                assert!(muette.is_empty(), "{}", r.id);
            } else {
                assert_eq!(muette.len(), 1, "{}", r.id);
                assert_eq!(muette[0].regle, r.id);
                assert_eq!(muette[0].etat(), Etat::NonVerifie(Raison::Muette), "{}", r.id);
                assert!(muette[0].message.contains(r.id) && muette[0].message.contains(r.sujet.0));
                assert!(muette[0].coherent());
            }
            let plantee = verification(doublure(|| panic!("règle d'essai")))();
            assert_eq!(plantee.len(), 1, "{}", r.id);
            assert_eq!(plantee[0].etat(), Etat::NonVerifie(Raison::Panique), "{}", r.id);
            assert_eq!(plantee[0].regle, r.id);
        }
    }
    /// E7 : une règle qui dépasse son délai dit « non vérifié (délai dépassé) » avec son identifiant, sans retenir le
    /// bilan ; celle d'à côté rend ses constats. Les règles qui attendent Internet ont le délai long.
    #[test]
    fn regle_hors_delai_non_verifiee_les_autres_continuent() {
        use crate::modele::{Etat, Raison};
        use std::time::{Duration, Instant};
        let essai = |id: &'static str, verifier: fn() -> Vec<Constat>| -> &'static Regle {
            Box::leak(Box::new(Regle {
                id,
                systeme: Os::actuel(),
                rang: 1,
                sujet: ("essai", "test"),
                references: &[],
                partage: Partage::Sorte,
                verifier,
            }))
        };
        let lente = essai("LNX-TST-002", || {
            std::thread::sleep(Duration::from_secs(3));
            vec![super::super::ok("Audit", "fini")]
        });
        let rapide = essai("LNX-TST-003", || vec![super::super::ok("Audit", "fini")]);
        let debut = Instant::now();
        let constats = super::super::en_parallele(vec![
            sous_delai(lente, Duration::from_millis(50)),
            sous_delai(rapide, Duration::from_secs(60)),
        ]);
        assert!(
            debut.elapsed() < Duration::from_secs(2),
            "le bilan a attendu la règle lente"
        );
        assert_eq!(constats.len(), 2);
        assert_eq!(constats[0].etat(), Etat::NonVerifie(Raison::Delai));
        assert_eq!(constats[0].regle, "LNX-TST-002");
        assert!(constats[0].message.contains("LNX-TST-002") && constats[0].coherent());
        assert_eq!(constats[1].etat(), Etat::Sain);
        assert_eq!(constats[1].regle, "LNX-TST-003");
        let maj = essai("WIN-MAJ-001", Vec::new);
        assert_eq!(maj.delai(), DELAI_LONG);
        assert_eq!(rapide.delai(), DELAI);
    }
}

//! Les comptes rendus pour Claude : un seul format, commun à l'autotest, au journal des erreurs et aux lenteurs, que
//! la veille de nuit (`outils/veille/`) lit pour choisir une correction à proposer.
//!
//! Une cause par ligne de travail : son genre, la règle, le contexte et l'emplacement dans le code, un code, combien
//! de fois, dans quelles versions et sur quelles familles de systèmes, d'où elle vient, quand, et la commande qui la
//! rejoue. Rien d'autre : jamais le détail d'une erreur, une commande tapée, un chemin ou un nom lu sur l'ordinateur.
//! Chaque champ texte est un type de `champs`, validé par son motif ou sa liste fermée à la construction comme à la
//! lecture ; le JSON refuse tout champ inconnu, et le Markdown se dérive du JSON seulement.
//!
//! Le schéma gardé par la veille (`outils/veille/schema-compte-rendu.json`, que l'IA ne peut pas changer) a les mêmes
//! clés et les mêmes listes : un essai les compare.

pub(crate) mod champs;
// Le lot de schéma 2 (lot A3) : construit et relu seulement, rien ne l'envoie avant A4.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod envoi;
// La réception chez l'auteur (lot A8) : relève du relais relue et agrégée pour la veille de nuit.
pub(crate) mod flotte;
pub(crate) mod journal;
pub(crate) mod triage;

use serde::{Deserialize, Serialize};

use crate::modele::Echec;
use crate::ui::{tr, trf};

pub(crate) use champs::{
    Cle, Code, Contexte, Famille, Genre, Jour, Lieu, Provenance, Regle, Reproduction, Sha, Source, Version,
};

/// La version du format.
pub(crate) const SCHEMA: u16 = 1;
/// Au plus autant de causes dans un compte rendu (la veille n'en garde que 20 en file).
pub(crate) const CAUSES_MAX: usize = 1000;
/// Au plus autant de versions distinctes par cause.
pub(crate) const VERSIONS_MAX: usize = 50;

/// Un compte rendu.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompteRendu {
    pub schema: u16,
    pub source: Source,
    /// La version de Vanguard qui l'a écrit.
    pub version: Version,
    /// Le commit d'où vient le programme, quand il est connu (la veille le pose).
    pub base_git: Option<Sha>,
    pub causes: Vec<Cause>,
}

/// Une cause : tout ce qui la décrit, en champs validés.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Cause {
    /// L'empreinte de (genre, règle, contexte, emplacement sans la colonne, code) : la même cause garde la même clé
    /// d'une version, d'un ordinateur et d'une nuit à l'autre.
    pub cle: Cle,
    pub genre: Genre,
    pub regle: Option<Regle>,
    pub contexte: Option<Contexte>,
    pub lieu: Option<Lieu>,
    pub code: Option<Code>,
    /// Combien de fois elle a été vue.
    pub compte: u32,
    /// Les versions distinctes où elle a été vue, triées.
    pub versions: Vec<Version>,
    /// Les familles de systèmes distinctes, triées. Un « ordinateur distinct » ne se voit pas : le journal ne porte
    /// aucun identifiant de machine, voulu ainsi (Loi 25) ; familles et versions en tiennent lieu.
    pub systemes: Vec<Famille>,
    pub provenance: Provenance,
    pub premiere: Jour,
    pub derniere: Jour,
    pub reproduction: Option<Reproduction>,
}

/// La clé d'une cause, d'après ses champs normalisés (jamais un texte de l'erreur).
pub(crate) fn cle_de(
    genre: Genre,
    regle: Option<&Regle>,
    contexte: Option<Contexte>,
    lieu: Option<&Lieu>,
    code: Option<&Code>,
) -> Cle {
    let parties = [
        genre.id(),
        regle.map_or("-", Regle::as_str),
        contexte.map_or("-", Contexte::id),
        lieu.map_or("-", Lieu::sans_colonne),
        code.map_or("-", Code::as_str),
    ];
    let h = blake3::hash(parties.join("\u{1f}").as_bytes());
    Cle::de_hachage(h.as_bytes())
}

impl Cause {
    /// Une cause vue une fois, sa clé calculée.
    #[allow(clippy::too_many_arguments)] // un argument par champ, chacun déjà validé
    pub(crate) fn nouvelle(
        genre: Genre,
        regle: Option<Regle>,
        contexte: Option<Contexte>,
        lieu: Option<Lieu>,
        code: Option<Code>,
        version: Version,
        famille: Famille,
        provenance: Provenance,
        jour: Jour,
    ) -> Cause {
        Cause {
            cle: cle_de(genre, regle.as_ref(), contexte, lieu.as_ref(), code.as_ref()),
            genre,
            regle,
            contexte,
            lieu,
            code,
            compte: 1,
            versions: vec![version],
            systemes: vec![famille],
            provenance,
            premiere: jour.clone(),
            derniere: jour,
            reproduction: None,
        }
    }

    /// Ajoute une autre vue de la même cause : compte, versions, familles et dates.
    pub(crate) fn fusionner(&mut self, autre: Cause) {
        self.compte = self.compte.saturating_add(autre.compte);
        for v in autre.versions {
            if !self.versions.contains(&v) {
                self.versions.push(v);
            }
        }
        self.versions.sort_by_key(version_cle);
        if self.versions.len() > VERSIONS_MAX {
            // Les plus récentes comptent : une cause qui revient dans une version récente.
            self.versions.drain(..self.versions.len() - VERSIONS_MAX);
        }
        for s in autre.systemes {
            if !self.systemes.contains(&s) {
                self.systemes.push(s);
            }
        }
        self.systemes.sort();
        if autre.premiere < self.premiere {
            self.premiere = autre.premiere;
        }
        if autre.derniere > self.derniere {
            self.derniere = autre.derniere;
        }
        // Une entrée de cet ordinateur, une seule fois, suffit à dire « vue ici ».
        if autre.provenance == Provenance::CetOrdinateur {
            self.provenance = Provenance::CetOrdinateur;
        }
        self.reproduction = self.reproduction.or(autre.reproduction);
    }
}

/// Une version en nombres, pour la trier (« 0.9.0 » avant « 0.10.0 »).
pub(crate) fn version_cle(v: &Version) -> (u16, u16, u16) {
    let mut p = v.as_str().split('.').map(|x| x.parse().unwrap_or(0));
    (p.next().unwrap_or(0), p.next().unwrap_or(0), p.next().unwrap_or(0))
}

impl CompteRendu {
    pub(crate) fn nouveau(source: Source) -> CompteRendu {
        CompteRendu {
            schema: SCHEMA,
            source,
            version: Version::du_programme(),
            base_git: None,
            causes: Vec::new(),
        }
    }

    /// Ajoute une cause, ou la fusionne avec celle qui a la même clé ; au-delà de `CAUSES_MAX`, ignorée.
    pub(crate) fn ajouter(&mut self, c: Cause) {
        if let Some(d) = self.causes.iter_mut().find(|d| d.cle == c.cle) {
            d.fusionner(c);
        } else if self.causes.len() < CAUSES_MAX {
            self.causes.push(c);
        }
    }

    /// Lit un compte rendu JSON : champs inconnus refusés, chaque champ par son motif, et les bornes du format.
    pub(crate) fn lire(json: &[u8]) -> Result<CompteRendu, Echec> {
        // Le message de serde n'est pas repris : il citerait un nom de champ venu du fichier.
        let c: CompteRendu = serde_json::from_slice(json).map_err(|e| {
            refus(trf!(
                "compte rendu refusé : champ inconnu, hors motif ou JSON invalide (ligne {}, colonne {})",
                "report refused: unknown field, field out of pattern or invalid JSON (line {}, column {})",
                e.line(),
                e.column()
            ))
        })?;
        c.verifier()?;
        Ok(c)
    }

    /// Les bornes du format, au-delà de ce que serde vérifie : schéma, nombre de causes, et pour chacune ses listes,
    /// ses dates et sa clé recalculée.
    pub(crate) fn verifier(&self) -> Result<(), Echec> {
        let c = self;
        if c.schema != SCHEMA {
            return Err(refus(trf!(
                "compte rendu refusé : schéma {} inconnu (attendu {})",
                "report refused: unknown schema {} (expected {})",
                c.schema,
                SCHEMA
            )));
        }
        if c.causes.len() > CAUSES_MAX {
            return Err(refus(trf!(
                "compte rendu refusé : plus de {} causes",
                "report refused: more than {} causes",
                CAUSES_MAX
            )));
        }
        for cause in &c.causes {
            let bornes = cause.compte >= 1
                && !cause.versions.is_empty()
                && cause.versions.len() <= VERSIONS_MAX
                && !cause.systemes.is_empty()
                && cause.systemes.len() <= Famille::TOUS.len()
                && cause.premiere <= cause.derniere;
            let cle = cle_de(
                cause.genre,
                cause.regle.as_ref(),
                cause.contexte,
                cause.lieu.as_ref(),
                cause.code.as_ref(),
            );
            if !bornes || cle != cause.cle {
                return Err(refus(trf!(
                    "compte rendu refusé : cause {} hors des bornes du format",
                    "report refused: cause {} outside the format's bounds",
                    cause.cle
                )));
            }
        }
        Ok(())
    }

    /// Le JSON, tel que la veille le lit.
    pub(crate) fn json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Le Markdown, dérivé du JSON seulement : un tableau par cause. Chaque valeur est un champ validé, sans
    /// caractère que le Markdown interprète (ni `|`, ni `<`, ni accent grave).
    pub(crate) fn markdown(&self) -> String {
        use std::fmt::Write as _;
        let mut m = trf!(
            "# Compte rendu pour Claude : {} (Vanguard {})\n\n{} cause(s).\n",
            "# Report for Claude: {} (Vanguard {})\n\n{} cause(s).\n",
            self.source.id(),
            self.version,
            self.causes.len()
        );
        if let Some(b) = &self.base_git {
            let _ = writeln!(m, "{}{b}", tr!("Commit : ", "Commit: "));
        }
        let vide = String::from("-");
        let liste = |v: Vec<&str>| if v.is_empty() { vide.clone() } else { v.join(", ") };
        for c in &self.causes {
            let lignes = [
                (tr!("genre", "kind"), c.genre.id().to_string()),
                (
                    tr!("règle", "rule"),
                    c.regle.as_ref().map_or_else(|| vide.clone(), ToString::to_string),
                ),
                (
                    tr!("contexte", "context"),
                    c.contexte.map_or_else(|| vide.clone(), |x| x.id().to_string()),
                ),
                (
                    tr!("emplacement", "location"),
                    c.lieu.as_ref().map_or_else(|| vide.clone(), ToString::to_string),
                ),
                (
                    tr!("code", "code"),
                    c.code.as_ref().map_or_else(|| vide.clone(), ToString::to_string),
                ),
                (tr!("vue", "seen"), trf!("{} fois", "{} time(s)", c.compte)),
                (
                    tr!("versions", "versions"),
                    liste(c.versions.iter().map(Version::as_str).collect()),
                ),
                (
                    tr!("systèmes", "systems"),
                    liste(c.systemes.iter().map(|s| s.id()).collect()),
                ),
                (tr!("provenance", "origin"), c.provenance.id().to_string()),
                (tr!("première", "first"), c.premiere.to_string()),
                (tr!("dernière", "last"), c.derniere.to_string()),
                (
                    tr!("rejouer", "replay"),
                    c.reproduction.map_or_else(|| vide.clone(), |r| r.id().to_string()),
                ),
            ];
            let _ = write!(m, "\n## {} {}\n\n| | |\n|---|---|\n", tr!("Cause", "Cause"), c.cle);
            for (nom, valeur) in lignes {
                let _ = writeln!(m, "| {nom} | {valeur} |");
            }
        }
        m
    }
}

/// `vanguard compte-rendu …` (caché, pour la veille de nuit).
#[derive(clap::Subcommand)]
pub(crate) enum Quoi {
    /// Le Markdown d'un compte rendu JSON (lu par ses motifs ; un champ inconnu ou hors motif est refusé).
    Markdown {
        /// Le compte rendu JSON.
        fichier: std::path::PathBuf,
    },
    /// Le triage du journal rapatrié (`outils/deployer.sh`) : la file des causes, en compte rendu JSON, et une ligne
    /// de comptes sur la sortie.
    Journal {
        /// Le journal de cet ordinateur (`retours/journal-cet-ordinateur.txt`).
        #[arg(long = "cet-ordinateur")]
        cet_ordinateur: Option<std::path::PathBuf>,
        /// Le journal rapporté par la clé (`retours/journal-cle.txt`).
        #[arg(long)]
        cle: Option<std::path::PathBuf>,
        /// Le suivi d'une nuit à l'autre (`veille/etat/causes.json`) ; sans lui, tout est lu et rien n'est gardé.
        #[arg(long)]
        etat: Option<std::path::PathBuf>,
        /// Les alertes déjà traitées par la veille (`veille/etat/alertes-traitees.txt`).
        #[arg(long)]
        traitees: Option<std::path::PathBuf>,
        /// Où écrire le compte rendu de la file.
        #[arg(long)]
        sortie: std::path::PathBuf,
    },
    /// La relève brute du relais relue lot par lot (`retours/envois`) : une ligne de comptes, rien d'écrit.
    Envois {
        /// Le dossier de la relève (`retours/envois`).
        #[arg(long)]
        dossier: std::path::PathBuf,
        /// Les références tirées de l'arbre (`outils/veille/references-flotte.sh`).
        #[arg(long)]
        references: std::path::PathBuf,
        /// Le jour de la nuit (AAAA-MM-JJ, UTC) ; aujourd'hui par défaut.
        #[arg(long)]
        aujourdhui: Option<String>,
    },
    /// La même lecture, agrégée par version dans `veille/etat/flotte` (une voix par source et par jour).
    Flotte {
        /// Le dossier de la relève (`retours/envois`).
        #[arg(long)]
        dossier: std::path::PathBuf,
        /// Les références tirées de l'arbre (`outils/veille/references-flotte.sh`).
        #[arg(long)]
        references: std::path::PathBuf,
        /// Le dossier de l'état (`veille/etat/flotte`).
        #[arg(long)]
        etat: std::path::PathBuf,
        /// Le jour de la nuit (AAAA-MM-JJ, UTC) ; aujourd'hui par défaut.
        #[arg(long)]
        aujourdhui: Option<String>,
    },
}

/// Le contexte des échecs de lecture (`champs::CONTEXTES_ECHEC`).
const LIRE: &str = "compte-rendu/lire";

/// Un compte rendu refusé, dit par une phrase déjà traduite.
fn refus(phrase: String) -> Echec {
    Echec::refuse(LIRE, phrase)
}

/// Le plus gros compte rendu lu.
const LECTURE_MAX: u64 = 4 * 1024 * 1024;

/// Lance `vanguard compte-rendu …` : rend le code de sortie (0 lu, 1 refusé ou illisible).
pub(crate) fn executer(quoi: &Quoi) -> i32 {
    match quoi {
        Quoi::Markdown { fichier } => match lire_fichier(fichier).and_then(|o| CompteRendu::lire(&o)) {
            Ok(c) => {
                print!("{}", c.markdown());
                0
            }
            Err(e) => {
                eprintln!("{e}");
                1
            }
        },
        Quoi::Journal {
            cet_ordinateur,
            cle,
            etat,
            traitees,
            sortie,
        } => {
            let demande = triage::Demande {
                cet_ordinateur: cet_ordinateur.as_deref(),
                cle: cle.as_deref(),
                etat: etat.as_deref(),
                traitees: traitees.as_deref(),
                sortie,
            };
            match triage::executer(&demande) {
                Ok(t) => {
                    println!("{}", t.ligne());
                    eprintln!("{}", triage::phrase(&t));
                    0
                }
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        }
        Quoi::Envois {
            dossier,
            references,
            aujourdhui,
        } => flotte_lancee(dossier, references, None, aujourdhui.as_deref()),
        Quoi::Flotte {
            dossier,
            references,
            etat,
            aujourdhui,
        } => flotte_lancee(dossier, references, Some(etat), aujourdhui.as_deref()),
    }
}

/// `envois` (sans état, rien d'écrit) ou `flotte` : la ligne de comptes sur la sortie, la phrase sur l'erreur.
fn flotte_lancee(
    dossier: &std::path::Path,
    references: &std::path::Path,
    etat: Option<&std::path::Path>,
    aujourdhui: Option<&str>,
) -> i32 {
    let fait = flotte::References::lire(references).and_then(|refs| {
        let demande = flotte::Demande {
            dossier,
            references: &refs,
            etat,
            aujourdhui: flotte::aujourdhui(aujourdhui)?,
            etat_max: flotte::ETAT_MAX,
        };
        flotte::executer(&demande)
    });
    match fait {
        Ok(c) => {
            println!("{}", c.ligne());
            eprintln!("{}", flotte::phrase(&c));
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

/// Un fichier lu en entier, borné.
fn lire_fichier(chemin: &std::path::Path) -> Result<Vec<u8>, Echec> {
    use std::io::Read as _;
    let f = std::fs::File::open(chemin).map_err(|e| Echec::io(LIRE, &e))?;
    let mut o = Vec::new();
    f.take(LECTURE_MAX + 1)
        .read_to_end(&mut o)
        .map_err(|e| Echec::io(LIRE, &e))?;
    if o.len() as u64 > LECTURE_MAX {
        return Err(refus(trf!(
            "compte rendu refusé : plus de {} octets",
            "report refused: more than {} bytes",
            LECTURE_MAX
        )));
    }
    Ok(o)
}

#[cfg(test)]
mod tests;

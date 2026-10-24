//! Pourquoi un constat n'a pas pu être vérifié, en type et non en texte : un code stable (« muette ») que les
//! scripts et l'historique comparent, et un texte dans les deux langues pour l'écran.
//!
//! Le canal d'erreur commun (`Echec`) porte une `Raison` : une fonction qui échoue dit pourquoi en type (absent,
//! refusé, illisible, falsifié…), avec un code stable que le journal des erreurs note entre crochets. Les tickets
//! du journal se regroupent ainsi par code, et non plus par la phrase traduite. `From<Echec> for String` laisse `?`
//! marcher dans les fonctions qui rendent encore leur erreur en texte, migrées une à une.
//!
//! `traces::Raison` (droits, délai, place, bornes de la collecte) reste à part : elle porte des cas propres aux
//! traces et leur texte bilingue (`Bi`), écrits tels quels dans le LISEZMOI des traces.

/// La raison d'un « non vérifié ».
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Raison {
    /// Réservé à root ou à l'administrateur.
    #[cfg_attr(not(test), allow(dead_code))] // posée au fil de la migration des règles (E5)
    Droits,
    /// L'outil qui lit n'est pas sur cet ordinateur (son nom).
    Absente(String),
    /// La lecture a échoué : le pourquoi, tel que le système le dit.
    #[cfg_attr(not(any(test, target_os = "linux")), allow(dead_code))]
    // posée au fil de la migration des règles (E5)
    Illisible(String),
    /// La règle n'a rien rendu : ni sain, ni problème, ni raison. Jamais compté sain.
    Muette,
    /// La règle a planté (rattrapée) : son identifiant suit le constat.
    Panique,
    /// La règle a dépassé son délai (`machine::regles`) : le bilan a continué sans elle.
    Delai,
    /// Écrit par une version plus ancienne de Vanguard (ou à la main) : ce qu'elle ne savait pas écrire manque.
    VersionAncienne,
    /// Un « impossible » d'avant ce modèle, dont la raison n'est que dans le message.
    NonPrecisee,
    /// Ce qu'on cherchait n'est pas là (fichier, entrée de la quarantaine, note).
    Introuvable,
    /// Changé hors de Vanguard (son sceau ne correspond plus) : jamais cru.
    Falsifie,
    /// Refusé par Vanguard lui-même, pour ne rien abîmer : la phrase dit pourquoi (un autre fichier à sa place, une
    /// valeur hors des bornes, un réglage interdit).
    Refuse(String),
    /// La commande ou le système a dit non (code de sortie, erreur rendue).
    Echoue(String),
}

impl Raison {
    /// Le code stable, sans langue : il ne change jamais pour un même cas.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Raison::Droits => "droits",
            Raison::Absente(_) => "absente",
            Raison::Illisible(_) => "illisible",
            Raison::Muette => "muette",
            Raison::Panique => "panique",
            Raison::Delai => "delai",
            Raison::VersionAncienne => "version-ancienne",
            Raison::NonPrecisee => "non-precisee",
            Raison::Introuvable => "introuvable",
            Raison::Falsifie => "falsifie",
            Raison::Refuse(_) => "refuse",
            Raison::Echoue(_) => "echoue",
        }
    }

    /// Le texte en français et en anglais : montré par le canal d'erreur commun ; vérifié par T11.
    pub(crate) fn textes(&self) -> (String, String) {
        match self {
            Raison::Droits if cfg!(windows) => ("réservé à l'administrateur".into(), "administrator only".into()),
            Raison::Droits => ("réservé à root".into(), "root only".into()),
            Raison::Absente(c) => (format!("« {c} » absent"), format!("“{c}” missing")),
            Raison::Illisible(e) => (format!("illisible : {e}"), format!("unreadable: {e}")),
            Raison::Muette => (
                "la vérification n'a rien rendu".into(),
                "the check returned nothing".into(),
            ),
            Raison::Panique => ("erreur interne".into(), "internal error".into()),
            Raison::Delai => ("délai dépassé".into(), "time limit exceeded".into()),
            Raison::VersionAncienne => (
                "écrit par une version plus ancienne".into(),
                "written by an older version".into(),
            ),
            Raison::NonPrecisee => ("raison dans le message".into(), "reason in the message".into()),
            Raison::Introuvable => ("introuvable".into(), "not found".into()),
            Raison::Falsifie => ("changé hors de Vanguard".into(), "changed outside Vanguard".into()),
            Raison::Refuse(p) | Raison::Echoue(p) => (p.clone(), p.clone()),
        }
    }

    /// Le texte dans la langue de l'interface.
    pub(crate) fn texte(&self) -> String {
        let (fr, en) = self.textes();
        if crate::langue::anglais() { en } else { fr }
    }
}

/// Un échec typé : pourquoi (`raison`), où (`contexte`, stable : « quarantaine/remettre »), et ce que le système
/// en a dit (`detail`, peut-être vide). Rendu en texte par `From<Echec> for String`, il passe par `?` dans les
/// fonctions qui rendent encore une erreur en texte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Echec {
    pub raison: Raison,
    pub contexte: &'static str,
    pub detail: String,
}

impl Echec {
    pub(crate) fn new(contexte: &'static str, raison: Raison) -> Echec {
        Echec {
            raison,
            contexte,
            detail: String::new(),
        }
    }

    /// Ce que le système en a dit, ou la phrase qui précise.
    pub(crate) fn detail(mut self, detail: impl Into<String>) -> Echec {
        self.detail = detail.into();
        self
    }

    /// Un refus de Vanguard, sa phrase déjà dans la langue de l'interface.
    pub(crate) fn refuse(contexte: &'static str, phrase: impl Into<String>) -> Echec {
        Echec::new(contexte, Raison::Refuse(phrase.into()))
    }

    /// Un échec du système ou d'une commande, sa phrase déjà dans la langue de l'interface.
    pub(crate) fn echoue(contexte: &'static str, phrase: impl Into<String>) -> Echec {
        Echec::new(contexte, Raison::Echoue(phrase.into()))
    }

    /// Une erreur d'entrée-sortie, rangée par sa sorte : absent, droits, ou illisible avec ce qu'en dit le système.
    pub(crate) fn io(contexte: &'static str, e: &std::io::Error) -> Echec {
        let raison = match e.kind() {
            std::io::ErrorKind::NotFound => Raison::Introuvable,
            std::io::ErrorKind::PermissionDenied => Raison::Droits,
            _ => Raison::Illisible(e.to_string()),
        };
        // La raison dit déjà tout : le texte du système (« entity not found ») ne s'ajoute pas.
        Echec {
            raison,
            contexte,
            detail: String::new(),
        }
    }

    /// Une écriture (ou un déplacement, une suppression) qui a échoué : jamais « illisible », et jamais « réservé à
    /// root » pour un fichier du compte en lecture seule ou tenu par un autre programme ; le texte du système
    /// (disque plein, fichier occupé) est gardé, c'est lui qui dit quoi faire.
    pub(crate) fn ecriture(contexte: &'static str, e: &std::io::Error) -> Echec {
        match e.kind() {
            std::io::ErrorKind::NotFound => Echec::new(contexte, Raison::Introuvable),
            _ => Echec::new(contexte, Raison::Echoue(e.to_string())),
        }
    }

    /// Le code stable de sa raison.
    pub(crate) fn code(&self) -> &'static str {
        self.raison.code()
    }

    /// Note l'échec au journal des erreurs, avec son code entre crochets : le script des tickets regroupe par code.
    pub(crate) fn journaliser(&self) {
        crate::journal::erreur(self.contexte, &format!("[{}] {self}", self.code()));
    }
}

impl std::fmt::Display for Echec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let texte = self.raison.texte();
        // Une falsification ou une absence dite par une phrase complète : la phrase seule, sans le redire.
        let phrase = matches!(self.raison, Raison::Falsifie | Raison::Introuvable);
        if self.detail.is_empty() || texte.contains(&self.detail) {
            f.write_str(&texte)
        } else if phrase {
            f.write_str(&self.detail)
        } else {
            write!(f, "{texte} ({})", self.detail)
        }
    }
}

impl From<Echec> for String {
    fn from(e: Echec) -> String {
        e.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T11 : un code par cas, jamais deux fois le même, et un texte dans les deux langues.
    #[test]
    fn codes_uniques_et_textes_bilingues() {
        let toutes = [
            Raison::Droits,
            Raison::Absente("nmcli".into()),
            Raison::Illisible("accès refusé".into()),
            Raison::Muette,
            Raison::Panique,
            Raison::Delai,
            Raison::VersionAncienne,
            Raison::NonPrecisee,
            Raison::Introuvable,
            Raison::Falsifie,
            Raison::Refuse("valeur hors des bornes".into()),
            Raison::Echoue("code de sortie 1".into()),
        ];
        let mut codes = std::collections::HashSet::new();
        for r in &toutes {
            assert!(codes.insert(r.code()), "code en double : {}", r.code());
            assert!(r.code().chars().all(|c| c.is_ascii_lowercase() || c == '-'));
            let (fr, en) = r.textes();
            assert!(!fr.is_empty() && !en.is_empty(), "{r:?}");
        }
    }

    /// Une écriture qui échoue (disque plein, fichier en lecture seule ou tenu par un autre programme) : jamais dite
    /// « illisible » ni « réservé à root », et le texte du système reste.
    #[test]
    fn ecriture_garde_la_cause_du_systeme() {
        let plein = Echec::ecriture("essai", &std::io::Error::from(std::io::ErrorKind::StorageFull));
        assert_eq!(plein.code(), "echoue");
        assert!(!plein.to_string().contains("illisible"), "{plein}");
        let refuse = Echec::ecriture("essai", &std::io::Error::other("fichier occupé"));
        assert_eq!(refuse.to_string(), "fichier occupé");
        let droits = Echec::ecriture("essai", &std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert_eq!(droits.code(), "echoue");
        assert!(!droits.to_string().contains("root"), "{droits}");
        let absent = Echec::ecriture("essai", &std::io::Error::from(std::io::ErrorKind::NotFound));
        assert_eq!(absent.code(), "introuvable");
    }

    /// Un échec se lit en texte (dans la langue de l'interface), passe par `?` vers une fonction qui rend du texte,
    /// et garde son code stable pour le journal des erreurs.
    #[test]
    fn echec_en_texte_et_par_point_d_interrogation() {
        fn appelant() -> Result<(), String> {
            Err(Echec::io(
                "essai/lecture",
                &std::io::Error::from(std::io::ErrorKind::NotFound),
            ))?;
            Ok(())
        }
        let texte = crate::langue::en_anglais(appelant).unwrap_err();
        assert_eq!(texte, "not found");
        let droits = Echec::io("essai", &std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert_eq!(droits.code(), "droits");
        let autre = Echec::io("essai", &std::io::Error::other("disque plein"));
        assert_eq!(autre.code(), "illisible");
        assert_eq!(
            crate::langue::en_anglais(|| autre.to_string()),
            "unreadable: disque plein"
        );
        let refus = Echec::refuse("essai", "un autre fichier est à sa place");
        assert_eq!(String::from(refus.clone()), "un autre fichier est à sa place");
        assert_eq!(refus.code(), "refuse");
    }

    /// Le plafond des fonctions qui rendent leur erreur en texte (`-> Result<_, String>`) : le canal d'erreur
    /// commun (`Echec`) les fait baisser ; une nouvelle ne doit pas s'y ajouter. Baisser ce nombre, jamais le monter.
    /// 202 → 186 avec l'étape E5 : les fonctions du lot « preuve et réponse » (déclarer normale, quarantaine, gestes
    /// du blocage) d'abord, puis les réglages du blocage, son pare-feu et les versions vues. 185 : la lecture des
    /// Paramètres.
    const ERREURS_EN_TEXTE_AU_PLUS: usize = 185;

    /// T13 : le cliquet des erreurs en texte, compté hors des modules de tests.
    #[test]
    fn cliquet_des_erreurs_en_texte() {
        fn compter(d: &std::path::Path) -> usize {
            let mut n = 0;
            for e in std::fs::read_dir(d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    n += compter(&p);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    let texte = std::fs::read_to_string(&p).unwrap();
                    let code = texte.find("#[cfg(test)]\nmod ").map_or(texte.as_str(), |t| &texte[..t]);
                    n += code
                        .lines()
                        .filter(|l| l.find("-> Result<").is_some_and(|i| l[i..].contains(", String>")))
                        .count();
                }
            }
            n
        }
        let n = compter(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"));
        assert!(n > 50, "{n} seulement : le compte ne lit plus les sources");
        assert!(
            n <= ERREURS_EN_TEXTE_AU_PLUS,
            "{n} fonctions rendent leur erreur en texte, plafond {ERREURS_EN_TEXTE_AU_PLUS} : ne pas en ajouter"
        );
    }
}

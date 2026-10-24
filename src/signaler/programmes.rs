//! Les programmes de signalement : une liste fermée, écrite ici, avec les adresses vérifiées le 23 oct. 2026. Aucune
//! n'est construite à partir de ce que la personne a écrit : le brouillon ne part jamais par une adresse, et ouvrir la
//! page d'un programme (sur demande) ne transmet rien.

use crate::tr;

/// Un programme de signalement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Programme {
    Msrc,
    Google,
    Chrome,
    Mozilla,
    Apple,
    Ghsa,
    CertCc,
    CertFr,
    Vanguard,
}

/// Une rubrique du brouillon.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Champ {
    Resume,
    TypeDeFaille,
    Produit,
    Composant,
    Systeme,
    MisesAJour,
    Configuration,
    Etapes,
    Observe,
    Attendu,
    PreuveDeConcept,
    Impact,
    AutresTouches,
    EditeurContacte,
}

/// La langue d'un brouillon : pas forcément celle de l'interface (les éditeurs lisent l'anglais).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Langue {
    Fr,
    En,
}

impl Langue {
    /// Le texte dans cette langue.
    pub(crate) fn t(self, fr: &'static str, en: &'static str) -> &'static str {
        match self {
            Langue::Fr => fr,
            Langue::En => en,
        }
    }

    pub(crate) fn de_l_interface() -> Langue {
        if crate::langue::anglais() {
            Langue::En
        } else {
            Langue::Fr
        }
    }

    pub(crate) fn lire(code: &str) -> Option<Langue> {
        match code.trim().to_ascii_lowercase().as_str() {
            "fr" | "francais" | "français" | "french" => Some(Langue::Fr),
            "en" | "anglais" | "english" => Some(Langue::En),
            _ => None,
        }
    }
}

impl Champ {
    /// Le titre de la rubrique, dans la langue du brouillon.
    pub(crate) fn titre(self, l: Langue) -> &'static str {
        match self {
            Champ::Resume => l.t("Résumé", "Summary"),
            Champ::TypeDeFaille => l.t("Type de faille", "Vulnerability type"),
            Champ::Produit => l.t("Produit et version", "Product and version"),
            Champ::Composant => l.t("Composant", "Component"),
            Champ::Systeme => l.t("Système", "Operating system"),
            Champ::MisesAJour => l.t("Mises à jour installées", "Installed updates"),
            Champ::Configuration => l.t("Configuration particulière", "Special configuration"),
            Champ::Etapes => l.t("Étapes pour reproduire", "Steps to reproduce"),
            Champ::Observe => l.t("Ce qui s'est passé", "What happened"),
            Champ::Attendu => l.t("Ce qui aurait dû se passer", "Expected behavior"),
            Champ::PreuveDeConcept => l.t("Preuve de concept", "Proof of concept"),
            Champ::Impact => l.t("Impact", "Impact"),
            Champ::AutresTouches => l.t("Qui d'autre est touché", "Who else is affected"),
            Champ::EditeurContacte => l.t("Éditeur déjà contacté ?", "Vendor already contacted?"),
        }
    }
}

/// La fiche d'un programme : où la personne soumet elle-même, avec quel compte, ce qu'il demande, et d'où vient
/// cette liste de champs.
pub(crate) struct Fiche {
    pub programme: Programme,
    /// Stable, pour `--programme` et le nom du fichier.
    pub id: &'static str,
    pub nom: &'static str,
    pub adresse: &'static str,
    /// Le compte demandé, en français puis en anglais.
    pub compte: (&'static str, &'static str),
    pub champs: &'static [Champ],
    /// `None` : la langue de l'interface.
    pub langue: Option<Langue>,
    /// Une preuve de concept est exigée : sans elle, le brouillon reste INCOMPLET.
    pub preuve_exigee: bool,
    pub source: &'static str,
}

/// Le compte d'un programme dont on n'a pas vérifié l'exigence (CERT/CC, CERT-FR) : dit comme tel, jamais
/// « demandé ».
pub(crate) const COMPTE_A_VERIFIER: (&str, &str) = ("à vérifier", "to be checked");

impl Fiche {
    pub(crate) fn compte_verifie(&self) -> bool {
        self.compte != COMPTE_A_VERIFIER
    }
}

use Champ::{
    Attendu, AutresTouches, Composant, Configuration, EditeurContacte, Etapes, Impact, MisesAJour, Observe,
    PreuveDeConcept, Produit, Resume, Systeme, TypeDeFaille,
};

/// La liste fermée des programmes, dans l'ordre où le menu les montre quand rien n'en propose un en premier.
pub(crate) const PROGRAMMES: &[Fiche] = &[
    Fiche {
        programme: Programme::Msrc,
        id: "msrc",
        nom: "Microsoft (MSRC)",
        adresse: "https://msrc.microsoft.com/create-report",
        compte: ("Microsoft ou Gmail", "Microsoft or Gmail"),
        champs: &[
            TypeDeFaille,
            Produit,
            Systeme,
            MisesAJour,
            Configuration,
            Etapes,
            Observe,
            Attendu,
            PreuveDeConcept,
            Impact,
        ],
        langue: Some(Langue::En),
        preuve_exigee: true,
        source: "https://www.microsoft.com/en-us/msrc/faqs-report-an-issue",
    },
    Fiche {
        programme: Programme::Google,
        id: "google",
        nom: "Google (Android, Cloud…)",
        adresse: "https://bughunters.google.com/report",
        compte: ("Google", "Google"),
        champs: &[
            Produit,
            Resume,
            Systeme,
            Etapes,
            Observe,
            Attendu,
            AutresTouches,
            Impact,
        ],
        langue: Some(Langue::En),
        preuve_exigee: false,
        source: "https://bughunters.google.com/report",
    },
    Fiche {
        programme: Programme::Chrome,
        id: "chrome",
        nom: "Chrome",
        adresse: "https://issues.chromium.org/issues/new?component=1363614&template=1922342",
        compte: ("Google", "Google"),
        champs: &[Resume, Produit, Systeme, Etapes, Observe, Attendu, PreuveDeConcept],
        langue: Some(Langue::En),
        preuve_exigee: true,
        source: "https://chromium.googlesource.com/chromium/src/+/da170c2267b2201954efe1c8fa5d2d89ab09f7bf/docs/security/vrp-faq.md",
    },
    Fiche {
        programme: Programme::Mozilla,
        id: "mozilla",
        nom: "Mozilla (Firefox, Thunderbird)",
        adresse: "https://bugzilla.mozilla.org/enter_bug.cgi",
        compte: ("Bugzilla", "Bugzilla"),
        champs: &[
            Produit,
            Composant,
            Resume,
            Systeme,
            Etapes,
            Observe,
            Attendu,
            PreuveDeConcept,
        ],
        langue: Some(Langue::En),
        preuve_exigee: false,
        source: "https://wiki.mozilla.org/Security/Fileabug",
    },
    Fiche {
        programme: Programme::Apple,
        id: "apple",
        nom: "Apple",
        adresse: "https://security.apple.com/submit",
        compte: ("Apple", "Apple"),
        champs: &[Produit, Systeme, Observe, Attendu, Etapes, PreuveDeConcept],
        langue: Some(Langue::En),
        preuve_exigee: true,
        source: "https://support.apple.com/102549",
    },
    Fiche {
        programme: Programme::Ghsa,
        id: "ghsa",
        nom: "GitHub (GHSA)",
        adresse: "https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability",
        compte: ("GitHub", "GitHub"),
        champs: &[Resume, Produit, Etapes, Observe, Attendu, PreuveDeConcept, Impact],
        langue: None,
        preuve_exigee: false,
        source: "https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability",
    },
    Fiche {
        programme: Programme::CertCc,
        id: "cert-cc",
        nom: "CERT/CC",
        adresse: "https://www.kb.cert.org/vuls/report/",
        compte: COMPTE_A_VERIFIER,
        champs: &[Produit, Resume, EditeurContacte, Etapes, Observe, Attendu, Impact],
        langue: Some(Langue::En),
        preuve_exigee: false,
        source: "https://www.kb.cert.org/vuls/report/",
    },
    Fiche {
        programme: Programme::CertFr,
        id: "cert-fr",
        nom: "CERT-FR",
        adresse: "https://club.ssi.gouv.fr/#/declarations",
        compte: COMPTE_A_VERIFIER,
        champs: &[Produit, Resume, Systeme, Etapes, Observe, Attendu, Impact],
        langue: Some(Langue::Fr),
        preuve_exigee: false,
        source: "https://cert.cyber.gouv.fr/contact/",
    },
    Fiche {
        programme: Programme::Vanguard,
        id: "vanguard",
        nom: "Vanguard",
        adresse: "https://github.com/d9v3/vanguard-beta/security/advisories/new",
        compte: ("GitHub", "GitHub"),
        champs: &[Produit, Systeme, Etapes, Observe, Attendu, PreuveDeConcept],
        langue: None,
        preuve_exigee: false,
        source: "https://github.com/d9v3/vanguard-beta/blob/master/SECURITY.md",
    },
];

impl Programme {
    pub(crate) fn fiche(self) -> &'static Fiche {
        PROGRAMMES
            .iter()
            .find(|f| f.programme == self)
            .unwrap_or(&PROGRAMMES[0])
    }

    /// `--programme msrc`, ou son nom (« Microsoft »), à la casse près.
    pub(crate) fn lire(texte: &str) -> Option<Programme> {
        let t = texte.trim().to_ascii_lowercase();
        PROGRAMMES
            .iter()
            .find(|f| f.id == t || f.nom.to_ascii_lowercase().starts_with(&t) && t.len() >= 4)
            .map(|f| f.programme)
    }

    /// Ce qu'il faut savoir avant de soumettre, dans la langue de l'interface.
    pub(crate) fn avertissement(self) -> Option<&'static str> {
        match self {
            Programme::Mozilla => Some(tr!(
                "Sur Bugzilla, une description ne se modifie plus une fois envoyée : relisez avant. Cochez « security » (bogue de sécurité).",
                "On Bugzilla, a description cannot be edited once submitted: read it first. Tick “security” (security bug)."
            )),
            Programme::Ghsa => Some(tr!(
                "Le bouton « Report a vulnerability » (onglet Security du dépôt) n'existe que si le dépôt l'a activé. Sinon, suis son SECURITY.md.",
                "The “Report a vulnerability” button (the repository's Security tab) only exists if the repository enabled it. Otherwise, follow its SECURITY.md."
            )),
            Programme::Apple => Some(tr!(
                "Apple limite les envois et peut suspendre une personne qui envoie des rapports automatiques non validés : n'envoyez qu'un rapport que vous avez reproduit, avec ses étapes et sa preuve de concept.",
                "Apple caps submissions and may suspend someone who sends unvalidated automated reports: only send a report you reproduced, with its steps and proof of concept."
            )),
            Programme::CertCc => Some(tr!(
                "Le CERT/CC conseille d'écrire d'abord à l'éditeur, et ne répond pas à tous les rapports.",
                "CERT/CC advises writing to the vendor first, and does not answer every report."
            )),
            Programme::CertFr => Some(tr!(
                "Le CERT-FR traite surtout l'administration et les entités essentielles ou importantes ; un particulier ou une PME : 17Cyber.",
                "CERT-FR mainly handles public bodies and essential or important entities; individuals and small businesses: 17Cyber."
            )),
            _ => None,
        }
    }
}

/// Le système sur lequel l'assistant tourne : il choisit le programme proposé en premier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Plateforme {
    Linux,
    Windows,
    Macos,
}

impl Plateforme {
    pub(crate) fn d_ici() -> Plateforme {
        if cfg!(windows) {
            Plateforme::Windows
        } else if cfg!(target_os = "macos") {
            Plateforme::Macos
        } else {
            Plateforme::Linux
        }
    }
}

/// Les programmes dans l'ordre où les proposer, selon le produit nommé par la personne et le système : celui de
/// l'éditeur reconnu d'abord, puis ceux du système, puis le reste de la liste. Toujours tous : la personne choisit.
pub(crate) fn propose(produit: &str, systeme: Plateforme) -> Vec<Programme> {
    // Des mots entiers : « ios » est dans « studios », « office » dans « LibreOffice », « edge » dans
    // « knowledge » ; une sous-chaîne proposerait en premier un programme qui n'a rien à voir.
    let bas = produit.to_lowercase();
    let mots_du_produit: Vec<&str> = bas
        .split(|c: char| !c.is_alphanumeric())
        .filter(|m| !m.is_empty())
        .collect();
    let a = |mots: &[&str]| mots.iter().any(|m| mots_du_produit.contains(m));
    let mut ordre = Vec::new();
    if a(&["vanguard"]) {
        ordre.push(Programme::Vanguard);
    }
    if a(&["chrome", "chromium"]) {
        ordre.push(Programme::Chrome);
    }
    if a(&["firefox", "thunderbird", "mozilla"]) {
        ordre.push(Programme::Mozilla);
    }
    if a(&[
        "windows",
        "defender",
        "edge",
        "office",
        "outlook",
        "teams",
        "microsoft",
        "azure",
        "xbox",
    ]) {
        ordre.push(Programme::Msrc);
    }
    if a(&["macos", "safari", "icloud", "iphone", "ipad", "ios", "apple"]) {
        ordre.push(Programme::Apple);
    }
    if a(&["android", "google", "pixel"]) {
        ordre.push(Programme::Google);
    }
    if a(&["github", "crate", "crates", "npm", "pypi"]) {
        ordre.push(Programme::Ghsa);
    }
    ordre.extend(match systeme {
        Plateforme::Windows => [Programme::Msrc, Programme::Chrome, Programme::Mozilla],
        Plateforme::Macos => [Programme::Apple, Programme::Chrome, Programme::Mozilla],
        Plateforme::Linux => [Programme::Chrome, Programme::Mozilla, Programme::Ghsa],
    });
    ordre.extend(PROGRAMMES.iter().map(|f| f.programme));
    let mut vus = Vec::new();
    ordre.retain(|p| {
        let nouveau = !vus.contains(p);
        vus.push(*p);
        nouveau
    });
    // Le CERT/CC et le CERT-FR en dernier recours, après les programmes des éditeurs.
    ordre.sort_by_key(|p| matches!(p, Programme::CertCc | Programme::CertFr));
    ordre
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chaque_fiche_est_complete() {
        let mut ids = Vec::new();
        for f in PROGRAMMES {
            assert!(
                f.adresse.starts_with("https://") && f.source.starts_with("https://"),
                "{}",
                f.id
            );
            assert!(!f.adresse.contains("mailto:"), "{}", f.id);
            assert!(
                f.champs.contains(&Champ::Etapes) && f.champs.contains(&Champ::Observe),
                "{}",
                f.id
            );
            assert_eq!(
                f.preuve_exigee,
                f.champs.contains(&Champ::PreuveDeConcept) && f.preuve_exigee
            );
            assert_eq!(Programme::lire(f.id), Some(f.programme));
            assert_eq!(f.programme.fiche().id, f.id);
            assert!(!ids.contains(&f.id));
            ids.push(f.id);
        }
        // Les champs des sources relues le 23 oct. 2026.
        let msrc = Programme::Msrc.fiche();
        for c in [
            TypeDeFaille,
            Produit,
            MisesAJour,
            Configuration,
            Etapes,
            PreuveDeConcept,
            Impact,
        ] {
            assert!(msrc.champs.contains(&c));
        }
        for p in [Programme::Msrc, Programme::Apple, Programme::Chrome] {
            assert!(p.fiche().preuve_exigee, "{p:?}");
        }
        assert_eq!(Programme::CertFr.fiche().langue, Some(Langue::Fr));
        assert_eq!(Programme::Ghsa.fiche().langue, None);
        assert_eq!(Programme::lire("inconnu"), None);
    }

    #[test]
    fn le_programme_propose_suit_le_produit_et_le_systeme() {
        assert_eq!(propose("Firefox 132", Plateforme::Windows)[0], Programme::Mozilla);
        assert_eq!(propose("Windows Defender", Plateforme::Linux)[0], Programme::Msrc);
        assert_eq!(propose("", Plateforme::Macos)[0], Programme::Apple);
        assert_eq!(propose("", Plateforme::Linux)[0], Programme::Chrome);
        assert_eq!(propose("Vanguard 0.85", Plateforme::Linux)[0], Programme::Vanguard);
        assert_eq!(propose("Microsoft Edge 120", Plateforme::Linux)[0], Programme::Msrc);
        assert_eq!(propose("iOS 18.1", Plateforme::Windows)[0], Programme::Apple);
        // Un mot qui en contient un autre ne compte pas.
        for produit in ["LibreOffice 24.8", "Obsidian Knowledge", "Studios 3", "Pixelmator 2"] {
            assert_eq!(propose(produit, Plateforme::Linux)[0], Programme::Chrome, "{produit}");
        }
        let tous = propose("x", Plateforme::Windows);
        assert_eq!(tous.len(), PROGRAMMES.len());
        assert!(matches!(tous[tous.len() - 2..], [Programme::CertCc, Programme::CertFr]));
    }
}

//! Le verdict du garde sur un lancement, pur : ce qui n'est pas CERTAIN passe toujours ; le certain passe aussi
//! quand la personne l'a permis, quand c'est une exception P11 (le système, Vanguard, un processus critique, un outil
//! d'accès à distance en pleine session : une alerte Critique, jamais un refus), en pause et en observation. Seul le
//! dernier cas refuse : tout le reste répond ALLOW.

#![forbid(unsafe_code)]
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

/// Pourquoi un fichier est certain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Certitude {
    /// Son empreinte (SHA-256, ou MD5 et taille) est dans l'ensemble CERTAIN.
    Liste,
    /// Il porte la marque d'essai EICAR (un programme ELF ou PE).
    Essai,
}

/// Les exceptions P11 : jamais refusées.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Exception {
    /// Un fichier du système, à root, que personne d'autre ne peut écrire.
    Systeme,
    /// Vanguard lui-même, ou le garde.
    Vanguard,
    /// Lancé par un processus critique (init, le gestionnaire de session…).
    Critique,
    /// Un outil d'accès à distance pendant une session ouverte.
    Session,
}

/// Ce que le garde sait d'un lancement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Faits {
    pub certain: Option<Certitude>,
    /// La personne a permis cette empreinte.
    pub permise: bool,
    pub exception: Option<Exception>,
}

/// Le mode du garde à cet instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Mode {
    /// Choisi exprès, avec le mot de passe.
    pub refus: bool,
    pub en_pause: bool,
}

/// Le verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Rien de certain.
    Propre,
    /// Certain, mais permis par la personne.
    Permise(Certitude),
    /// Certain, mais une exception P11 : alerte Critique.
    Epargne(Certitude, Exception),
    /// Certain, en observation ou en pause : noté, permis.
    Observe(Certitude),
    /// Certain, en mode refus : EPERM.
    Refuse(Certitude),
}

impl Verdict {
    /// La réponse à fanotify.
    pub(crate) fn permet(self) -> bool {
        !matches!(self, Verdict::Refuse(_))
    }

    /// Le nom interne, dans evenements.jsonl.
    pub(crate) fn nom(self) -> &'static str {
        match self {
            Verdict::Propre => "propre",
            Verdict::Permise(_) => "permise",
            Verdict::Epargne(..) => "epargne",
            Verdict::Observe(_) => "observe",
            Verdict::Refuse(_) => "refuse",
        }
    }
}

/// Ce qu'on sait d'un lancement certain, pour ses exceptions.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Lancement<'a> {
    /// Le chemin du fichier, tel que le noyau le donne.
    pub chemin: &'a str,
    /// Son propriétaire et ses droits (fstat du descripteur).
    pub uid: u32,
    pub mode: u32,
    /// Son empreinte est celle d'un programme de Vanguard posé.
    pub de_vanguard: bool,
    /// Le processus qui lance, et son nom.
    pub pid: u32,
    pub nom: &'a str,
}

/// L'exception P11 d'un lancement certain, s'il en a une. `session_ouverte` n'est demandée que pour un outil d'accès à
/// distance.
pub(crate) fn exception(l: &Lancement<'_>, session_ouverte: impl FnOnce() -> bool) -> Option<Exception> {
    use crate::protection::blocage::gardes;
    if l.de_vanguard || l.chemin == super::PROGRAMME {
        return Some(Exception::Vanguard);
    }
    // À root, que ni le groupe ni les autres ne peuvent écrire, dans un dossier du système.
    if l.uid == 0 && l.mode & 0o022 == 0 && gardes::dossier_systeme(l.chemin, crate::machine::regles::Os::Linux) {
        return Some(Exception::Systeme);
    }
    if gardes::processus_critique(l.pid, l.nom) {
        return Some(Exception::Critique);
    }
    if gardes::programme_de_session(l.chemin) && session_ouverte() {
        return Some(Exception::Session);
    }
    None
}

/// Le verdict.
pub(crate) fn juger(f: Faits, m: Mode) -> Verdict {
    let Some(c) = f.certain else {
        return Verdict::Propre;
    };
    if f.permise {
        return Verdict::Permise(c);
    }
    if let Some(e) = f.exception {
        return Verdict::Epargne(c, e);
    }
    if m.refus && !m.en_pause {
        Verdict::Refuse(c)
    } else {
        Verdict::Observe(c)
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    const EXCEPTIONS: [Option<Exception>; 5] = [
        None,
        Some(Exception::Systeme),
        Some(Exception::Vanguard),
        Some(Exception::Critique),
        Some(Exception::Session),
    ];

    /// Tous les faits et tous les modes : seul le certain, ni permis ni épargné, en refus hors pause, est refusé.
    #[test]
    fn seul_le_certain_en_refus_est_refuse() {
        for certain in [None, Some(Certitude::Liste), Some(Certitude::Essai)] {
            for permise in [false, true] {
                for exception in EXCEPTIONS {
                    for refus in [false, true] {
                        for en_pause in [false, true] {
                            let f = Faits {
                                certain,
                                permise,
                                exception,
                            };
                            let v = juger(f, Mode { refus, en_pause });
                            let attendu = certain.is_some() && !permise && exception.is_none() && refus && !en_pause;
                            assert_eq!(!v.permet(), attendu, "{f:?} refus={refus} pause={en_pause} → {v:?}");
                            assert_eq!(v == Verdict::Propre, certain.is_none());
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn exceptions_p11() {
        let l = Lancement {
            chemin: "/home/alice/Téléchargements/outil",
            uid: 1000,
            mode: 0o100_755,
            de_vanguard: false,
            pid: 4242,
            nom: "bash",
        };
        let jamais = || -> bool { panic!("la session n'est demandée que pour un outil d'accès à distance") };
        assert_eq!(exception(&l, jamais), None);
        assert_eq!(
            exception(&Lancement { de_vanguard: true, ..l }, jamais),
            Some(Exception::Vanguard)
        );
        let programme = Lancement {
            chemin: crate::machine::linux::garde::PROGRAMME,
            ..l
        };
        assert_eq!(exception(&programme, jamais), Some(Exception::Vanguard));
        let systeme = Lancement {
            chemin: "/usr/bin/true",
            uid: 0,
            ..l
        };
        assert_eq!(exception(&systeme, jamais), Some(Exception::Systeme));
        // Dans /usr/bin, mais au compte, ou écrivable par le groupe : pas du système.
        assert_eq!(exception(&Lancement { uid: 1000, ..systeme }, jamais), None);
        assert_eq!(
            exception(
                &Lancement {
                    mode: 0o100_775,
                    ..systeme
                },
                jamais
            ),
            None
        );
        // À root hors des dossiers du système (/usr/local, /opt, /tmp) : pas une exception.
        for chemin in ["/usr/local/bin/outil", "/opt/outil", "/tmp/outil"] {
            assert_eq!(exception(&Lancement { chemin, ..systeme }, jamais), None, "{chemin}");
        }
        assert_eq!(exception(&Lancement { pid: 1, ..l }, jamais), Some(Exception::Critique));
        let sshd = Lancement {
            chemin: "/home/alice/sshd",
            ..l
        };
        assert_eq!(exception(&sshd, || true), Some(Exception::Session));
        assert_eq!(exception(&sshd, || false), None);
    }

    #[test]
    fn les_exceptions_passent_avant_le_mode() {
        let f = Faits {
            certain: Some(Certitude::Liste),
            permise: false,
            exception: Some(Exception::Systeme),
        };
        let refus = Mode {
            refus: true,
            en_pause: false,
        };
        assert_eq!(juger(f, refus), Verdict::Epargne(Certitude::Liste, Exception::Systeme));
        let observation = Mode {
            refus: false,
            en_pause: false,
        };
        let sans = Faits { exception: None, ..f };
        assert_eq!(juger(sans, observation), Verdict::Observe(Certitude::Liste));
        assert_eq!(juger(sans, refus), Verdict::Refuse(Certitude::Liste));
        assert_eq!(Verdict::Refuse(Certitude::Essai).nom(), "refuse");
    }
}

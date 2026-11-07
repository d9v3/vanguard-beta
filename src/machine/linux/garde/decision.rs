//! Le verdict du garde sur un lancement, pur : ce qui n'est pas CERTAIN passe toujours ; le certain passe aussi
//! quand la personne l'a permis, quand c'est une exception P11 (le système, Vanguard, ce que lance init : une alerte
//! Critique, jamais un refus), en pause et en observation. Seul le dernier cas refuse : tout le reste répond ALLOW.
//!
//! Une exception ne se décide jamais sur un nom que le compte choisit : ni le nom du processus qui lance
//! (`/proc/<pid>/comm`, réglable par `prctl`), ni le nom du fichier lancé (un fichier certain renommé « sshd »). Ces
//! noms ne servent qu'à l'affichage ; les noms critiques et les outils de session restent pour la défense D6
//! (`blocage::gardes`), où le nom de ce qui tourne déjà est subi, pas fourni.

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
    /// Lancé par init (PID 1), que seul root règle.
    Critique,
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
    /// Le processus qui lance (dans l'espace de processus du garde : celui de l'hôte).
    pub pid: u32,
}

/// Le numéro d'init : dans l'espace de processus de l'hôte, le seul processus que le compte ne peut ni être ni
/// imiter (un conteneur a son init, mais pas ce numéro-là vu d'ici).
const PID_INIT: u32 = 1;

/// L'exception P11 d'un lancement certain, s'il en a une : par le fichier lui-même (à root, non écrivable par d'autres)
/// ou par le numéro du lanceur, jamais par un nom.
pub(crate) fn exception(l: &Lancement<'_>) -> Option<Exception> {
    use crate::protection::blocage::gardes;
    // À root, que ni le groupe ni les autres ne peuvent écrire : le compte ne peut pas en créer un pareil.
    let a_root = l.uid == 0 && l.mode & 0o022 == 0;
    // Le programme posé n'est épargné par son chemin qu'à root : un fichier au compte vu sous ce chemin (un autre
    // espace de montage) ne l'est pas.
    if l.de_vanguard || (a_root && l.chemin == super::PROGRAMME) {
        return Some(Exception::Vanguard);
    }
    if a_root && gardes::dossier_systeme(l.chemin, crate::machine::regles::Os::Linux) {
        return Some(Exception::Systeme);
    }
    if l.pid == PID_INIT {
        return Some(Exception::Critique);
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

    const EXCEPTIONS: [Option<Exception>; 4] = [
        None,
        Some(Exception::Systeme),
        Some(Exception::Vanguard),
        Some(Exception::Critique),
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
        };
        assert_eq!(exception(&l), None);
        assert_eq!(
            exception(&Lancement { de_vanguard: true, ..l }),
            Some(Exception::Vanguard)
        );
        let programme = Lancement {
            chemin: crate::machine::linux::garde::PROGRAMME,
            uid: 0,
            ..l
        };
        assert_eq!(exception(&programme), Some(Exception::Vanguard));
        // Le chemin du programme posé, mais un fichier au compte (vu d'un autre espace de montage) : rien.
        assert_eq!(exception(&Lancement { uid: 1000, ..programme }), None);
        let systeme = Lancement {
            chemin: "/usr/bin/true",
            uid: 0,
            ..l
        };
        assert_eq!(exception(&systeme), Some(Exception::Systeme));
        // Dans /usr/bin, mais au compte, ou écrivable par le groupe : pas du système.
        assert_eq!(exception(&Lancement { uid: 1000, ..systeme }), None);
        assert_eq!(
            exception(&Lancement {
                mode: 0o100_775,
                ..systeme
            }),
            None
        );
        // À root hors des dossiers du système (/usr/local, /opt, /tmp) : pas une exception.
        for chemin in ["/usr/local/bin/outil", "/opt/outil", "/tmp/outil"] {
            assert_eq!(exception(&Lancement { chemin, ..systeme }), None, "{chemin}");
        }
        assert_eq!(exception(&Lancement { pid: 1, ..l }), Some(Exception::Critique));
    }

    /// B1 : un fichier certain au compte, renommé comme un outil de session ou un processus vital, ou lancé par un
    /// processus qui en a pris le nom (comm), est refusé en mode refus. Le nom du lanceur n'entre même pas dans les
    /// faits jugés : seul son numéro compte, et ce n'est pas celui d'init.
    #[test]
    fn un_nom_choisi_par_le_compte_n_epargne_jamais() {
        let refus = Mode {
            refus: true,
            en_pause: false,
        };
        for nom in [
            "sshd",
            "sshd-session",
            "xrdp",
            "anydesk",
            "x11vnc",
            "systemd",
            "init",
            "gnome-shell",
            "Xorg",
        ] {
            let chemin = format!("/home/alice/{nom}");
            // Le fichier porte le nom ; le lanceur, quel que soit son comm, n'est connu que par son numéro.
            for pid in [2, 4, 4242, u32::MAX] {
                let l = Lancement {
                    chemin: &chemin,
                    uid: 1000,
                    mode: 0o100_755,
                    de_vanguard: false,
                    pid,
                };
                assert_eq!(exception(&l), None, "{chemin} lancé par {pid}");
                let f = Faits {
                    certain: Some(Certitude::Liste),
                    permise: false,
                    exception: exception(&l),
                };
                assert_eq!(juger(f, refus), Verdict::Refuse(Certitude::Liste), "{chemin}");
            }
        }
        // Le source de la décision ne lit aucun nom de processus.
        let source = include_str!("decision.rs");
        let code: String = source
            .split("#[cfg(test)]")
            .next()
            .unwrap()
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect();
        for interdit in ["comm", "processus_critique", "programme_de_session", "session_ouverte"] {
            assert!(
                !code.contains(&format!("{interdit}(")) && !code.contains(&format!("/{interdit}")),
                "decision.rs juge par {interdit}"
            );
        }
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

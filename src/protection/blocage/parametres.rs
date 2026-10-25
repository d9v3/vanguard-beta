//! Les réglages du blocage, gardés sur cet ordinateur seulement (blocage.json, comme appris.json) : un mode par
//! catégorie de menaces, et l'accord donné une fois pour la protection active.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::modele::{Echec, Raison};

use crate::{tr, trf};

/// Ce que Vanguard fait d'une menace d'une catégorie.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Mode {
    /// Rien n'est proposé : l'alerte du bilan reste, sans bouton.
    Desactive,
    /// Chaque menace propose « Bloquer » : le geste est montré, puis fait après accord.
    #[default]
    UnClic,
    /// Le certain est bloqué tout seul, puis notifié ; le douteux garde son bouton.
    Automatique,
}

impl Mode {
    pub(crate) const TOUS: [Mode; 3] = [Mode::Desactive, Mode::UnClic, Mode::Automatique];

    pub(crate) fn libelle(self) -> &'static str {
        match self {
            Mode::Desactive => tr!("désactivé", "off"),
            Mode::UnClic => tr!("un clic", "one click"),
            Mode::Automatique => tr!("automatique", "automatic"),
        }
    }

    /// Le mode d'un mot de la ligne de commande, en français ou en anglais.
    pub(crate) fn depuis_mot(mot: &str) -> Option<Mode> {
        match mot.trim().to_lowercase().as_str() {
            "off" | "non" | "no" | "desactive" | "désactivé" | "desactiver" | "désactiver" | "aucun" | "none" => {
                Some(Mode::Desactive)
            }
            "clic" | "click" | "un-clic" | "one-click" | "1clic" | "1click" | "manuel" | "manual" => Some(Mode::UnClic),
            "auto" | "automatique" | "automatic" | "actif" | "active" => Some(Mode::Automatique),
            _ => None,
        }
    }
}

/// Les quatre catégories de menaces, chacune avec son mode.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub(crate) enum Categorie {
    /// Logiciels malveillants et outils d'attaque : arrêt du processus, puis quarantaine du fichier.
    Programmes,
    /// Connexions vers un serveur de commande : règle de pare-feu sortante.
    Connexions,
    /// Lancements automatiques malveillants, et la liste de blocage des pilotes vulnérables (Windows).
    Demarrage,
    /// Serveurs d'IA ouverts au réseau, agents réglés pour tout faire sans demander.
    AgentsIa,
}

impl Categorie {
    pub(crate) const TOUTES: [Categorie; 4] = [
        Categorie::Programmes,
        Categorie::Connexions,
        Categorie::Demarrage,
        Categorie::AgentsIa,
    ];

    pub(crate) fn titre(self) -> &'static str {
        match self {
            Categorie::Programmes => tr!("Programmes malveillants", "Malicious programs"),
            Categorie::Connexions => tr!("Connexions dangereuses", "Dangerous connections"),
            Categorie::Demarrage => tr!("Démarrage et pilotes", "Startup and drivers"),
            Categorie::AgentsIa => tr!("Agents et serveurs d'IA", "AI agents and servers"),
        }
    }

    /// Ce que le blocage y fait, en une phrase.
    pub(crate) fn geste(self) -> &'static str {
        match self {
            Categorie::Programmes => tr!(
                "arrêter le processus, puis mettre son fichier en quarantaine",
                "stop the process, then quarantine its file"
            ),
            Categorie::Connexions => tr!(
                "règle de pare-feu sortante vers l'adresse du serveur",
                "outbound firewall rule to the server's address"
            ),
            Categorie::Demarrage => tr!(
                "retirer le lancement automatique ; pilotes vulnérables bloqués (Windows)",
                "remove the automatic start; vulnerable drivers blocked (Windows)"
            ),
            Categorie::AgentsIa => tr!(
                "fermer au réseau un serveur d'IA ; remettre les demandes de permission",
                "close an AI server to the network; bring permission prompts back"
            ),
        }
    }

    /// Y a-t-il là quelque chose de certain ? Seules ces catégories peuvent bloquer toutes seules : une empreinte de
    /// MalwareBazaar, un outil d'attaque connu, un serveur de commande. Un lancement automatique douteux ou un
    /// réglage d'agent ne le sont jamais assez.
    pub(crate) fn a_du_certain(self) -> bool {
        matches!(self, Categorie::Programmes | Categorie::Connexions)
    }

    /// Le mot de la ligne de commande.
    pub(crate) fn mot(self) -> &'static str {
        match self {
            Categorie::Programmes => tr!("programmes", "programs"),
            Categorie::Connexions => tr!("connexions", "connections"),
            Categorie::Demarrage => tr!("demarrage", "startup"),
            Categorie::AgentsIa => tr!("agents", "agents"),
        }
    }

    /// La catégorie d'un mot de la ligne de commande, en français ou en anglais.
    pub(crate) fn depuis_mot(mot: &str) -> Option<Categorie> {
        match mot.trim().to_lowercase().as_str() {
            "programmes" | "programme" | "programs" | "program" | "malware" | "a" => Some(Categorie::Programmes),
            "connexions" | "connexion" | "connections" | "connection" | "reseau" | "réseau" | "network" | "b" => {
                Some(Categorie::Connexions)
            }
            "demarrage" | "démarrage" | "startup" | "pilotes" | "drivers" | "c" => Some(Categorie::Demarrage),
            "agents" | "agent" | "ia" | "ai" | "agents-ia" | "ai-agents" | "d" => Some(Categorie::AgentsIa),
            _ => None,
        }
    }
}

/// Les réglages, tels que gardés dans blocage.json.
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq, Clone)]
pub(crate) struct Parametres {
    /// L'accord pour la protection active (« AAAA-MM-JJ HH:MM »), donné une fois ; `None` : jamais donné, et
    /// « automatique » vaut alors un clic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accord: Option<String>,
    #[serde(default)]
    pub programmes: Mode,
    #[serde(default)]
    pub connexions: Mode,
    #[serde(default)]
    pub demarrage: Mode,
    #[serde(default)]
    pub agents_ia: Mode,
}

impl Parametres {
    /// Le mode réglé pour cette catégorie, tel qu'écrit.
    pub(crate) fn mode(&self, c: Categorie) -> Mode {
        match c {
            Categorie::Programmes => self.programmes,
            Categorie::Connexions => self.connexions,
            Categorie::Demarrage => self.demarrage,
            Categorie::AgentsIa => self.agents_ia,
        }
    }

    /// Règle le mode d'une catégorie ; « automatique » là où rien n'est certain est refusé (`Err` : pourquoi).
    pub(crate) fn regler(&mut self, c: Categorie, m: Mode) -> Result<(), Echec> {
        if m == Mode::Automatique && !c.a_du_certain() {
            return Err(Echec::refuse(
                "blocage/regler",
                trf!(
                    "« {} » n'a rien de certain : jamais automatique, désactivé ou un clic seulement.",
                    "“{}” has nothing certain: never automatic, only off or one click.",
                    c.titre()
                ),
            ));
        }
        *match c {
            Categorie::Programmes => &mut self.programmes,
            Categorie::Connexions => &mut self.connexions,
            Categorie::Demarrage => &mut self.demarrage,
            Categorie::AgentsIa => &mut self.agents_ia,
        } = m;
        Ok(())
    }

    /// Le mode qui s'applique vraiment : automatique seulement avec l'accord, et là où quelque chose est certain ;
    /// sinon un clic.
    pub(crate) fn effectif(&self, c: Categorie) -> Mode {
        match self.mode(c) {
            Mode::Automatique if self.accord.is_none() || !c.a_du_certain() => Mode::UnClic,
            m => m,
        }
    }

    /// La protection active tourne-t-elle (au moins une catégorie réellement automatique) ?
    pub(crate) fn actif(&self) -> bool {
        Categorie::TOUTES.iter().any(|&c| self.effectif(c) == Mode::Automatique)
    }

    /// Tout est-il désactivé ? Alors le bilan ne cherche même pas.
    pub(crate) fn rien(&self) -> bool {
        Categorie::TOUTES.iter().all(|&c| self.effectif(c) == Mode::Desactive)
    }
}

/// Ce que la protection fait d'une menace trouvée.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Decision {
    /// Bloquée toute seule, puis notifiée.
    Auto,
    /// « Bloquer » proposé : le geste est montré, puis fait après accord.
    UnClic,
    /// Rien : la catégorie est désactivée (l'alerte du bilan reste).
    Rien,
}

/// Bloquer tout seul demande les trois : la catégorie réglée sur automatique, l'accord donné, une menace certaine.
pub(crate) fn decider(p: &Parametres, c: Categorie, certaine: bool) -> Decision {
    match p.effectif(c) {
        Mode::Desactive => Decision::Rien,
        Mode::Automatique if certaine => Decision::Auto,
        Mode::Automatique | Mode::UnClic => Decision::UnClic,
    }
}

/// Le nom du fichier, scellé (`sceau`) : une catégorie désactivée ne bloque plus rien.
pub(crate) const BLOCAGE: &str = "blocage.json";

fn fichier() -> PathBuf {
    crate::socle::dossier_local().join(BLOCAGE)
}

/// Les réglages ; `Err` (la raison) si le fichier existe mais ne se lit pas : les défauts servent, sans automatique,
/// et rien ne l'écrase en silence.
pub(crate) fn charger() -> Result<Parametres, Echec> {
    charger_de(&fichier()).map(|(p, _)| p)
}

/// Pourquoi des catégories désactivées dans blocage.json ne comptent pas (`charger_de`), ou `None`.
pub(crate) fn ignores() -> Option<&'static str> {
    charger_de(&fichier()).ok().and_then(|(_, r)| r)
}

/// Les réglages relus sous leur sceau. Changés hors de Vanguard, ou acceptés tels quels après des sceaux refaits :
/// une catégorie « désactivée » vaut « un clic » (la défense reste là, l'alerte du bilan garde son bouton), l'accord
/// de la protection active ne vaut rien (rien ne se bloque sans clic sur la foi d'un fichier non cru), et la raison
/// est rendue pour être dite. Un programme du compte qui y désactivait ses propres catégories ne coupait sinon le
/// blocage choisi par la personne qu'en silence.
fn charger_de(chemin: &Path) -> Result<(Parametres, Option<&'static str>), Echec> {
    use crate::sceau::Lecture;
    const OU: &str = "blocage/reglages";
    let dossier = chemin.parent().unwrap_or_else(|| Path::new("."));
    let nom = chemin.file_name().and_then(|n| n.to_str()).unwrap_or(BLOCAGE);
    let (octets, douteux) = match crate::sceau::lire_dans(dossier, nom) {
        Lecture::Absent | Lecture::Inconnu | Lecture::Falsifie(None) => return Ok((Parametres::default(), None)),
        Lecture::Illisible(e) => return Err(Echec::new(OU, Raison::Illisible(e))),
        Lecture::Intact(o) => (o, None),
        // Repris d'une version d'avant à la mise à jour : le choix de la personne, gardé. Après des sceaux refaits :
        // rien ne prouve qui l'a écrit.
        Lecture::Adopte(o) if crate::sceau::repris_dans(dossier, nom) => (o, None),
        Lecture::Adopte(o) => (
            o,
            Some(tr!(
                "accepté tel quel après des sceaux refaits",
                "accepted as it was after seals were remade"
            )),
        ),
        Lecture::Falsifie(Some(o)) => (o, Some(tr!("changé hors de Vanguard", "changed outside Vanguard"))),
    };
    let texte = String::from_utf8(octets).map_err(|e| Echec::new(OU, Raison::Illisible(e.to_string())))?;
    let mut p: Parametres = serde_json::from_str(texte.trim_start_matches('\u{feff}'))
        .map_err(|e| Echec::new(OU, Raison::Illisible(e.to_string())))?;
    let Some(raison) = douteux else {
        return Ok((p, None));
    };
    let mut coupait = false;
    for m in [&mut p.programmes, &mut p.connexions, &mut p.demarrage, &mut p.agents_ia] {
        if *m == Mode::Desactive {
            *m = Mode::UnClic;
            coupait = true;
        }
    }
    // L'accord de la protection active est le seul témoin du consentement à bloquer sans clic : venu d'un fichier
    // non cru, il ne vaut rien (l'automatique redevient un clic).
    coupait |= p.accord.take().is_some();
    Ok((p, coupait.then_some(raison)))
}

/// blocage.json d'une version d'avant, accepté tel quel à la mise à jour : rescellé (`sceau::resceller_si`).
pub(crate) fn resceller_d_avant() {
    crate::sceau::resceller_si(BLOCAGE, |o| serde_json::from_slice::<Parametres>(o).is_ok());
}

pub(crate) fn enregistrer(p: &Parametres) -> std::io::Result<()> {
    enregistrer_dans(p, &fichier())
}

fn enregistrer_dans(p: &Parametres, chemin: &Path) -> std::io::Result<()> {
    let texte = serde_json::to_string_pretty(p).map_err(std::io::Error::other)?;
    let dossier = chemin.parent().unwrap_or_else(|| Path::new("."));
    let nom = chemin.file_name().and_then(|n| n.to_str()).unwrap_or(BLOCAGE);
    crate::sceau::ecrire_dans(dossier, nom, texte.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn par_defaut_un_clic_partout() {
        let p = Parametres::default();
        for c in Categorie::TOUTES {
            assert_eq!(p.effectif(c), Mode::UnClic);
        }
        assert!(!p.actif() && !p.rien());
    }

    /// Garde-fou : automatique ne vaut que pour une catégorie réglée ainsi, avec l'accord, et pour le certain.
    #[test]
    fn automatique_seulement_avec_accord_et_pour_le_certain() {
        let mut p = Parametres::default();
        p.regler(Categorie::Connexions, Mode::Automatique).unwrap();
        // Sans accord : un clic, même pour le certain.
        assert_eq!(decider(&p, Categorie::Connexions, true), Decision::UnClic);
        assert!(!p.actif());
        p.accord = Some("2026-10-21 20:00".into());
        assert!(p.actif());
        assert_eq!(decider(&p, Categorie::Connexions, true), Decision::Auto);
        // Le douteux garde son bouton.
        assert_eq!(decider(&p, Categorie::Connexions, false), Decision::UnClic);
        // Une autre catégorie, restée sur un clic, ne bloque rien toute seule.
        assert_eq!(decider(&p, Categorie::Programmes, true), Decision::UnClic);
        // Désactivé : rien.
        p.regler(Categorie::Programmes, Mode::Desactive).unwrap();
        assert_eq!(decider(&p, Categorie::Programmes, true), Decision::Rien);
        // Rien de certain au démarrage ni chez les agents : automatique refusé, et un fichier écrit à la main qui le
        // dirait vaut un clic.
        assert!(p.regler(Categorie::Demarrage, Mode::Automatique).is_err());
        assert!(p.regler(Categorie::AgentsIa, Mode::Automatique).is_err());
        p.agents_ia = Mode::Automatique;
        assert_eq!(decider(&p, Categorie::AgentsIa, true), Decision::UnClic);
    }

    /// Un texte écrit par Vanguard tel quel, scellé.
    fn enregistrer_brut(f: &Path, texte: &str) {
        crate::sceau::ecrire_dans(f.parent().unwrap(), BLOCAGE, texte.as_bytes()).unwrap();
    }

    /// Un programme du compte désactive des catégories dans blocage.json : le fichier n'est plus scellé, ces
    /// catégories valent « un clic » (rien ne se coupe), son accord ne fait rien bloquer sans clic, et la raison est
    /// rendue pour être dite.
    #[test]
    fn categories_desactivees_hors_de_vanguard_ne_coupent_rien() {
        let d = crate::socle::dossier_local().join("essai-blocage-forge");
        let _ = std::fs::remove_dir_all(&d);
        let f = d.join(BLOCAGE);
        let p = Parametres {
            accord: Some("2026-10-21 20:00".into()),
            connexions: Mode::Automatique,
            ..Parametres::default()
        };
        enregistrer_dans(&p, &f).unwrap();
        assert_eq!(charger_de(&f).unwrap(), (p.clone(), None));
        std::fs::write(
            &f,
            r#"{"accord":"2026-10-21 20:00","programmes":"desactive","connexions":"automatique","demarrage":"desactive","agents_ia":"desactive"}"#,
        )
        .unwrap();
        let (lu, raison) = charger_de(&f).unwrap();
        assert!(raison.is_some_and(|r| r.contains("hors de Vanguard") || r.contains("outside Vanguard")));
        for c in Categorie::TOUTES {
            assert_ne!(lu.effectif(c), Mode::Desactive, "{c:?}");
        }
        // L'accord forgé ne vaut rien : l'automatique redevient un clic.
        assert_eq!(lu.accord, None);
        assert_eq!(decider(&lu, Categorie::Connexions, true), Decision::UnClic);
        assert!(!lu.rien());
        // Réglé de nouveau par Vanguard : scellé, une catégorie désactivée l'est pour de bon.
        let mut voulu = lu;
        voulu.regler(Categorie::Programmes, Mode::Desactive).unwrap();
        enregistrer_dans(&voulu, &f).unwrap();
        assert_eq!(
            charger_de(&f).unwrap().0.effectif(Categorie::Programmes),
            Mode::Desactive
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn reglages_ecrits_relus_ou_refuses() {
        let d = crate::socle::dossier_local().join("essai-blocage-reglages");
        let _ = std::fs::remove_dir_all(&d);
        let f = d.join("blocage.json");
        // Absent : les défauts.
        assert_eq!(charger_de(&f).unwrap().0, Parametres::default());
        let p = Parametres {
            accord: Some("2026-10-21 20:00".into()),
            programmes: Mode::Automatique,
            connexions: Mode::Automatique,
            demarrage: Mode::UnClic,
            agents_ia: Mode::Desactive,
        };
        enregistrer_dans(&p, &f).unwrap();
        let texte = std::fs::read_to_string(&f).unwrap();
        assert!(texte.contains("\"programmes\": \"automatique\"") && texte.contains("\"agents_ia\": \"desactive\""));
        assert_eq!(charger_de(&f).unwrap().0, p);
        // Un champ manquant (version d'avant) prend sa valeur par défaut.
        enregistrer_brut(&f, "{\"connexions\": \"un-clic\"}");
        assert_eq!(charger_de(&f).unwrap().0, Parametres::default());
        // Abîmé : refusé, jamais lu comme des défauts qu'on réécrirait par-dessus.
        enregistrer_brut(&f, "{pas du json");
        assert!(charger_de(&f).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn mots_de_la_ligne_de_commande() {
        assert_eq!(Categorie::depuis_mot("Connexions"), Some(Categorie::Connexions));
        assert_eq!(Categorie::depuis_mot("startup"), Some(Categorie::Demarrage));
        assert_eq!(Categorie::depuis_mot("ai"), Some(Categorie::AgentsIa));
        assert_eq!(Categorie::depuis_mot("programs"), Some(Categorie::Programmes));
        assert_eq!(Categorie::depuis_mot("tout"), None);
        assert_eq!(Mode::depuis_mot("auto"), Some(Mode::Automatique));
        assert_eq!(Mode::depuis_mot("one-click"), Some(Mode::UnClic));
        assert_eq!(Mode::depuis_mot("Désactivé"), Some(Mode::Desactive));
        assert_eq!(Mode::depuis_mot("peut-être"), None);
        for c in Categorie::TOUTES {
            assert_eq!(Categorie::depuis_mot(c.mot()), Some(c));
        }
    }
}

//! Le menu des gestes d'une menace : le geste prévu (Bloquer) en tête, puis Suspendre, Surveiller de plus près,
//! Faire confiance (ou « c'est normal ici ») et Ignorer. Chaque geste est permis, à confirmer (un cas que les
//! garde-fous laissent à la personne : signature illisible, confiance à un programme certain), ou grisé avec sa
//! raison : un geste refusé reste visible, pour qu'on sache pourquoi il n'est pas offert.
//!
//! Ce module est pur : ce qu'il faut savoir de la menace est lu ailleurs (`mod.rs`, `Faits`) et donné ici.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use crate::tr;

/// Un geste du menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Choix {
    /// Le geste prévu : arrêter et mettre en quarantaine, une règle de pare-feu, retirer un lancement…
    Bloquer,
    /// Geler le processus, réversible (`suspension`).
    Suspendre,
    /// Alerter quand il se lance (au plus une fois par heure) pendant 7 jours (`surveiller`), Linux seulement pour
    /// l'instant.
    Surveiller,
    /// Certain : faire confiance à ce fichier précis (son empreinte), 90 jours, confirmation tapée. Douteux : c'est
    /// normal ici, 90 jours.
    Confiance,
    /// Ne rien faire cette fois.
    Ignorer,
}

/// Ce que le menu montre d'un geste.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Etat {
    Permis,
    /// Permis, mais une question attend la personne avant d'agir : pourquoi.
    Confirmer(String),
    /// Refusé d'avance par un garde-fou : pourquoi.
    Grise(String),
}

/// Ce que les gestes demandent de savoir de la menace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Faits {
    pub(crate) certaine: bool,
    /// Le blocage : `Ok(true)` si une signature illisible sera confirmée, `Err` : le refus de `gestes::preparer`.
    pub(crate) bloquer: Result<bool, String>,
    /// La suspension rejugée (`ordres::juger`) : `None` si permise, sinon pourquoi pas ; `Some` aussi quand la menace
    /// n'a pas de processus en marche.
    pub(crate) suspendre: Option<String>,
    /// L'empreinte du fichier du programme se lit (surveillance et confiance s'y attachent).
    pub(crate) empreinte: bool,
    /// Ce système sait surveiller de plus près (Linux, par le veilleur).
    pub(crate) surveillance_ici: bool,
}

/// Les gestes, dans l'ordre du menu (le prévu en tête), chacun avec son état.
pub(crate) fn gestes(f: &Faits) -> Vec<(Choix, Etat)> {
    let bloquer = match &f.bloquer {
        Ok(false) => Etat::Permis,
        Ok(true) => Etat::Confirmer(
            tr!(
                "signature illisible : montrée, puis confirmée",
                "unreadable signature: shown, then confirmed"
            )
            .to_string(),
        ),
        Err(r) => Etat::Grise(r.clone()),
    };
    let suspendre = match &f.suspendre {
        None => Etat::Permis,
        Some(r) => Etat::Grise(r.clone()),
    };
    let sans_fichier = || {
        tr!(
            "aucun fichier de programme dont l'empreinte se lit",
            "no program file whose fingerprint can be read"
        )
        .to_string()
    };
    let surveiller = if !f.surveillance_ici {
        Etat::Grise(
            tr!(
                "Linux seulement pour l'instant (Windows : après le veilleur de Windows)",
                "Linux only for now (Windows: after the Windows watcher)"
            )
            .to_string(),
        )
    } else if f.empreinte {
        Etat::Permis
    } else {
        Etat::Grise(sans_fichier())
    };
    let confiance = match (f.certaine, f.empreinte) {
        (false, _) => Etat::Permis,
        (true, true) => Etat::Confirmer(
            tr!(
                "programme certain : confirmation tapée, liée à ce fichier précis",
                "certain program: typed confirmation, tied to this exact file"
            )
            .to_string(),
        ),
        (true, false) => Etat::Grise(sans_fichier()),
    };
    vec![
        (Choix::Bloquer, bloquer),
        (Choix::Suspendre, suspendre),
        (Choix::Surveiller, surveiller),
        (Choix::Confiance, confiance),
        (Choix::Ignorer, Etat::Permis),
    ]
}

/// Le texte du geste dans le menu (au plus 40 colonnes).
pub(crate) fn texte(c: Choix, certaine: bool) -> &'static str {
    match c {
        Choix::Bloquer => tr!("Bloquer (le geste prévu)", "Block (the planned action)"),
        Choix::Suspendre => tr!("Suspendre (réversible)", "Suspend (reversible)"),
        Choix::Surveiller => tr!("Surveiller de plus près (7 jours)", "Watch more closely (7 days)"),
        Choix::Confiance if certaine => tr!("Faire confiance à ce fichier", "Trust this file"),
        Choix::Confiance => tr!("C'est normal ici (90 jours)", "This is normal here (90 days)"),
        Choix::Ignorer => tr!("Ignorer pour cette fois", "Ignore this time"),
    }
}

/// La précision grise à droite d'un geste permis (au plus 33 colonnes).
pub(crate) fn precision(c: Choix, e: &Etat) -> &'static str {
    match (c, e) {
        (_, Etat::Confirmer(_)) => tr!("à confirmer", "to confirm"),
        (Choix::Bloquer, _) => tr!("prévu", "planned"),
        (Choix::Suspendre, _) => tr!("« reprendre » le lève", "“resume” lifts it"),
        (Choix::Surveiller, _) => tr!("une alerte par heure au plus", "at most one alert per hour"),
        (Choix::Confiance, _) => tr!("90 jours", "90 days"),
        (Choix::Ignorer, _) => "",
    }
}

/// La clé « normale » d'une confiance accordée à un fichier certain : liée à son empreinte, jamais à son chemin (le
/// même chemin réécrit par un autre malware n'en profite pas).
pub(crate) fn cle_confiance(empreinte: &[u8; 32]) -> String {
    crate::protection::normales::cle_blocage(&format!("confiance|{}", super::surveiller::hex(empreinte)))
}

/// Le préfixe des clés de confiance : jamais proposées dans « Ce que Vanguard a appris » (le journal n'est pas scellé,
/// et la confiance à un certain se tape).
pub(crate) const PREFIXE_CONFIANCE: &str = "blocage|confiance|";

/// La personne a-t-elle fait confiance à ce fichier certain (90 jours) ?
pub(crate) fn confiance_accordee(empreinte: &[u8; 32]) -> bool {
    crate::protection::normales::est_normale(&cle_confiance(empreinte))
}

/// Le mot à taper pour faire confiance à un fichier certain.
pub(crate) fn mot_de_confiance() -> &'static str {
    tr!("CONFIANCE", "TRUST")
}

/// La réponse tapée vaut-elle confiance ? Le mot exact (casse ignorée), rien d'autre : « o » ou Entrée ne suffisent
/// pas.
pub(crate) fn confiance_tapee(reponse: &str) -> bool {
    let r = reponse.trim();
    r.eq_ignore_ascii_case(mot_de_confiance()) || r.eq_ignore_ascii_case("CONFIANCE") || r.eq_ignore_ascii_case("TRUST")
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
mod tests {
    use super::*;

    fn faits() -> Faits {
        Faits {
            certaine: false,
            bloquer: Ok(false),
            suspendre: None,
            empreinte: true,
            surveillance_ici: true,
        }
    }

    fn etat(g: &[(Choix, Etat)], c: Choix) -> Etat {
        g.iter().find(|(x, _)| *x == c).map(|(_, e)| e.clone()).unwrap()
    }

    /// Le prévu en tête, Ignorer en dernier, toujours les cinq.
    #[test]
    fn l_ordre_du_menu() {
        let g = gestes(&faits());
        let ordre: Vec<Choix> = g.iter().map(|(c, _)| *c).collect();
        assert_eq!(
            ordre,
            [
                Choix::Bloquer,
                Choix::Suspendre,
                Choix::Surveiller,
                Choix::Confiance,
                Choix::Ignorer
            ]
        );
        assert!(g.iter().all(|(_, e)| *e == Etat::Permis));
    }

    /// Un refus des garde-fous grise, avec sa raison telle quelle ; une signature illisible se confirme.
    #[test]
    fn un_refus_reste_visible_et_grise() {
        let mut f = faits();
        f.bloquer = Err("processus critique".into());
        f.suspendre = Some("Vanguard lui-même".into());
        let g = gestes(&f);
        assert_eq!(etat(&g, Choix::Bloquer), Etat::Grise("processus critique".into()));
        assert_eq!(etat(&g, Choix::Suspendre), Etat::Grise("Vanguard lui-même".into()));
        assert_eq!(g.len(), 5);
        f.bloquer = Ok(true);
        assert!(matches!(etat(&gestes(&f), Choix::Bloquer), Etat::Confirmer(_)));
    }

    /// Surveiller : grisé hors de Linux, ou sans empreinte lisible.
    #[test]
    fn surveiller_selon_le_systeme_et_l_empreinte() {
        let mut f = faits();
        f.surveillance_ici = false;
        assert!(matches!(etat(&gestes(&f), Choix::Surveiller), Etat::Grise(_)));
        f.surveillance_ici = true;
        f.empreinte = false;
        assert!(matches!(etat(&gestes(&f), Choix::Surveiller), Etat::Grise(_)));
    }

    /// Confiance : un douteux se déclare normal ; un certain se confirme (empreinte lisible) ou est grisé.
    #[test]
    fn confiance_a_un_certain() {
        let mut f = faits();
        assert_eq!(etat(&gestes(&f), Choix::Confiance), Etat::Permis);
        f.certaine = true;
        assert!(matches!(etat(&gestes(&f), Choix::Confiance), Etat::Confirmer(_)));
        f.empreinte = false;
        assert!(matches!(etat(&gestes(&f), Choix::Confiance), Etat::Grise(_)));
    }

    /// Le mot exact, rien d'autre.
    #[test]
    fn la_confiance_se_tape() {
        assert!(confiance_tapee(" confiance "));
        assert!(confiance_tapee("TRUST"));
        for non in ["", "o", "oui", "y", "confianc", "confiance!"] {
            assert!(!confiance_tapee(non), "{non}");
        }
    }

    /// La clé tient à l'empreinte, et commence par le préfixe que « Ce que Vanguard a appris » ne propose jamais.
    #[test]
    fn cle_de_confiance() {
        let a = cle_confiance(&[1u8; 32]);
        assert!(a.starts_with(PREFIXE_CONFIANCE));
        assert_ne!(a, cle_confiance(&[2u8; 32]));
    }

    /// Les textes tiennent : au plus 40 colonnes, et une précision au plus 33.
    #[test]
    fn les_textes_tiennent() {
        for c in [
            Choix::Bloquer,
            Choix::Suspendre,
            Choix::Surveiller,
            Choix::Confiance,
            Choix::Ignorer,
        ] {
            for certaine in [false, true] {
                assert!(texte(c, certaine).chars().count() <= 40);
            }
            for e in [Etat::Permis, Etat::Confirmer(String::new())] {
                assert!(precision(c, &e).chars().count() <= 33);
            }
        }
    }
}

//! Les couleurs de la fenêtre telles que `vanguard couleurs --json` les dit, et l'issue d'un changement. La fenêtre
//! ne lit aucun fichier : ni parametres.json, ni le thème d'Omarchy, ni le registre de Windows ; `vanguard` lit,
//! juge et écrit, la fenêtre relit sa réponse ici. Elle la relit strictement : une couleur qui ne se lit pas, ou
//! qui se verrait à peine (`couleurs::verifier`), ne vaut pas ; celles de Vanguard servent, et la raison est dite.

use serde::Deserialize;

use super::Texte;
use crate::commandes::ChangementCouleurs;
use crate::couleurs::{Base, Choix, Rgb, Theme, VIFS, lire_hex, lire_vifs, verifier};
use crate::lanceur::{Fin, Issue};

/// Pourquoi les couleurs réglées ne valent pas : celles de Vanguard servent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Doute {
    /// parametres.json changé hors de Vanguard.
    HorsVanguard,
    /// parametres.json accepté tel quel après des sceaux refaits.
    Adopte,
    /// parametres.json effacé hors de Vanguard.
    Efface,
    /// parametres.json illisible.
    Illisible,
    /// Des couleurs gardées qui ne se lisent pas, ou qui se verraient à peine (dit par `vanguard` ou vu ici).
    Invalides,
}

impl Doute {
    fn lire(mot: &str) -> Doute {
        match mot {
            "hors_vanguard" => Doute::HorsVanguard,
            "adopte" => Doute::Adopte,
            "efface" => Doute::Efface,
            "illisible" => Doute::Illisible,
            // Un mot inconnu (un `vanguard` plus récent) : un doute quand même, jamais rien.
            _ => Doute::Invalides,
        }
    }

    /// La phrase des coulisses et de la console.
    pub fn texte(self) -> &'static str {
        match self {
            Doute::HorsVanguard => crate::tr!(
                "parametres.json a été changé hors de Vanguard : les couleurs de Vanguard servent.",
                "parametres.json was changed outside Vanguard: Vanguard's colors are used."
            ),
            Doute::Adopte => crate::tr!(
                "parametres.json a été accepté tel quel après des sceaux refaits : les couleurs de Vanguard servent.",
                "parametres.json was accepted as it was after seals were remade: Vanguard's colors are used."
            ),
            Doute::Efface => crate::tr!(
                "parametres.json a été effacé hors de Vanguard : les couleurs de Vanguard servent.",
                "parametres.json was deleted outside Vanguard: Vanguard's colors are used."
            ),
            Doute::Illisible => crate::tr!(
                "parametres.json est illisible : les couleurs de Vanguard servent.",
                "parametres.json is unreadable: Vanguard's colors are used."
            ),
            Doute::Invalides => crate::tr!(
                "Des couleurs gardées sont invalides : celles de Vanguard servent.",
                "Some saved colors are invalid: Vanguard's are used."
            ),
        }
    }
}

/// D'où viennent les couleurs du système.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    Omarchy,
    Windows,
}

/// Les couleurs du système, lues par `vanguard` (dans l'ordre de `Vif::TOUS` ; une case vide : pas trouvée).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Systeme {
    pub source: Source,
    pub vifs: [Option<Rgb>; VIFS],
}

/// Les couleurs réglées, relues.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Lues {
    /// Par thème, dans l'ordre de `Theme::TOUS` ; rien : celles de Vanguard.
    pub choix: [Option<Choix>; 2],
    pub doute: Option<Doute>,
    pub systeme: Option<Systeme>,
}

impl Lues {
    pub fn de(&self, t: Theme) -> Option<Choix> {
        match t {
            Theme::Sombre => self.choix[0],
            Theme::Clair => self.choix[1],
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ChoixBrut {
    base: Texte,
    vifs: Texte,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct SystemeBrut {
    source: Texte,
    vifs: Vec<Texte>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Brut {
    sombre: Option<ChoixBrut>,
    clair: Option<ChoixBrut>,
    douteux: Texte,
    systeme: Option<SystemeBrut>,
}

/// Un choix écrit par `vanguard` : une base connue, cinq couleurs strictes, lisibles sur le thème.
fn choix_de(b: &ChoixBrut, t: Theme) -> Option<Choix> {
    let c = Choix {
        base: Base::lire(b.base.as_str())?,
        vifs: lire_vifs(b.vifs.as_str())?,
    };
    verifier(t, &c).is_ok().then_some(c)
}

fn systeme_de(s: &SystemeBrut) -> Option<Systeme> {
    let source = match s.source.as_str() {
        "omarchy" => Source::Omarchy,
        "windows" => Source::Windows,
        _ => return None,
    };
    let [a, b, c, d, e] = s.vifs.as_slice() else {
        return None;
    };
    let vifs = [a, b, c, d, e].map(|t| lire_hex(t.as_str()));
    vifs.iter().any(Option::is_some).then_some(Systeme { source, vifs })
}

/// Lit `vanguard couleurs --json`.
pub fn lire(sortie: &[u8]) -> Result<Lues, String> {
    let b: Brut = super::lire(sortie)?;
    let mut doute = (!b.douteux.is_empty()).then(|| Doute::lire(b.douteux.as_str()));
    let mut choix = [None; 2];
    for (case, (t, brut)) in choix.iter_mut().zip(Theme::TOUS.into_iter().zip([&b.sombre, &b.clair])) {
        if let Some(brut) = brut {
            *case = choix_de(brut, t);
            if case.is_none() {
                doute = doute.or(Some(Doute::Invalides));
            }
        }
    }
    Ok(Lues {
        choix,
        doute,
        systeme: b.systeme.as_ref().and_then(systeme_de),
    })
}

/// Ce qu'est devenu un changement des couleurs, d'après Vanguard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IssueCouleurs {
    /// Fait : les couleurs d'avant (pour revenir en arrière) et celles d'après.
    Fait {
        avant: Option<Choix>,
        apres: Option<Choix>,
    },
    Refuse(String),
    Echec(String),
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct IssueBrute {
    geste: Texte,
    issue: Texte,
    raison: Texte,
    theme: Texte,
    avant: Option<ChoixBrut>,
    apres: Option<ChoixBrut>,
}

/// Lit l'issue d'un changement des couleurs, strictement : « fait » seulement si Vanguard le dit, pour ce geste-là,
/// ce thème-là et exactement les couleurs demandées, avec le code 0 et une valeur d'avant lisible. Toute autre
/// réponse est un échec : les couleurs relues ensuite montrent l'état réel.
pub fn lire_issue(cc: ChangementCouleurs, f: &Fin) -> IssueCouleurs {
    let illisible = || {
        IssueCouleurs::Echec(
            crate::tr!(
                "réponse de Vanguard illisible ; les couleurs relues montrent l'état réel",
                "unreadable answer from Vanguard; the reloaded colors show the real state"
            )
            .to_string(),
        )
    };
    match &f.issue {
        Issue::Terminee => {}
        Issue::Arretee => return IssueCouleurs::Echec(crate::tr!("arrêté", "stopped").to_string()),
        Issue::DelaiDepasse => {
            return IssueCouleurs::Echec(
                crate::tr!("arrêté : trop long sans finir", "stopped: too long without finishing").to_string(),
            );
        }
        Issue::TropLongue => return illisible(),
        Issue::Impossible(e) => {
            return IssueCouleurs::Echec(crate::trf!("pas pu lancer : {}", "could not start: {}", e));
        }
    }
    let Some(ligne) = f
        .sortie
        .split(|o| *o == b'\n')
        .rev()
        .find(|l| !l.iter().all(u8::is_ascii_whitespace))
    else {
        return illisible();
    };
    let Ok(b) = super::lire::<IssueBrute>(ligne) else {
        return illisible();
    };
    if b.geste.as_str() != "couleurs" {
        return illisible();
    }
    let raison = crate::nettoyage::nom(b.raison.as_str(), 200);
    match (b.issue.as_str(), f.code) {
        ("fait", Some(0)) => {}
        ("refuse", Some(c)) if c != 0 => return IssueCouleurs::Refuse(raison),
        ("echec", Some(c)) if c != 0 => return IssueCouleurs::Echec(raison),
        _ => return illisible(),
    }
    let lu = |c: &Option<ChoixBrut>| match c {
        None => Some(None),
        Some(c) => choix_de(c, cc.theme).map(Some),
    };
    match (Theme::lire(b.theme.as_str()), lu(&b.avant), lu(&b.apres)) {
        (Some(t), Some(avant), Some(apres)) if t == cc.theme && apres == cc.choix => {
            IssueCouleurs::Fait { avant, apres }
        }
        _ => illisible(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::couleurs::Vif;
    use std::time::Duration;

    const BRAISE: &str = "f85c30,e94f97,ea900f,ddc33c,45b45e";

    #[test]
    fn les_couleurs_se_relisent_strictement() {
        let l = lire(
            format!(
                r##"{{"sombre":{{"base":"braise","vifs":"{BRAISE}"}},"clair":null,"douteux":null,
                "systeme":{{"source":"omarchy","vifs":["ff0000",null,"#00ff00","00ff00","0000ff"]}}}}"##
            )
            .as_bytes(),
        )
        .unwrap();
        let braise = Choix::du_prereglage(Base::Braise, Theme::Sombre);
        assert_eq!(l.de(Theme::Sombre), Some(braise));
        assert_eq!(l.de(Theme::Clair), None);
        assert_eq!(l.doute, None);
        let s = l.systeme.unwrap();
        assert_eq!(s.source, Source::Omarchy);
        // Un dièse n'est pas la forme stricte : la case reste vide, pas devinée.
        assert_eq!(
            s.vifs,
            [Some([0xff, 0, 0]), None, None, Some([0, 0xff, 0]), Some([0, 0, 0xff])]
        );

        // Une couleur noire sur le fond noir, une base inconnue, un mot de plus : ne vaut pas, et c'est dit.
        for mauvais in [
            r#"{"sombre":{"base":"vanguard","vifs":"000000,f24f4d,fb852f,e7c03a,45b45e"}}"#,
            r#"{"sombre":{"base":"rose","vifs":"3fbef7,f24f4d,fb852f,e7c03a,45b45e"}}"#,
            r#"{"clair":{"base":"vanguard","vifs":"067ba5,d22e33,a85208,8f7304"}}"#,
        ] {
            let l = lire(mauvais.as_bytes()).unwrap();
            assert_eq!(l.choix, [None, None], "{mauvais}");
            assert_eq!(l.doute, Some(Doute::Invalides), "{mauvais}");
        }
        let l = lire(br#"{"douteux":"hors_vanguard"}"#).unwrap();
        assert_eq!((l.choix, l.doute), ([None, None], Some(Doute::HorsVanguard)));
        assert_eq!(lire(br#"{"douteux":"autre"}"#).unwrap().doute, Some(Doute::Invalides));
        // Une source inconnue, ou pas exactement cinq cases : pas de couleurs du système.
        for s in [
            r#"{"systeme":{"source":"autre","vifs":["ff0000",null,null,null,null]}}"#,
            r#"{"systeme":{"source":"windows","vifs":["ff0000"]}}"#,
            r#"{"systeme":{"source":"windows","vifs":[null,null,null,null,null]}}"#,
        ] {
            assert_eq!(lire(s.as_bytes()).unwrap().systeme, None, "{s}");
        }
        assert!(lire(b"").is_err());
    }

    fn fin(sortie: &str, code: i32) -> Fin {
        Fin {
            lancement: crate::commandes::Lancement::Couleurs(ChangementCouleurs {
                theme: Theme::Sombre,
                choix: None,
            }),
            code: Some(code),
            sortie: sortie.as_bytes().to_vec(),
            issue: Issue::Terminee,
            duree: Duration::from_millis(10),
        }
    }

    /// « Fait » seulement pour ce geste, ce thème et exactement ce qui était demandé ; la valeur d'avant revient
    /// pour annuler.
    #[test]
    fn l_issue_d_un_changement_se_lit_strictement() {
        let braise = Choix::du_prereglage(Base::Braise, Theme::Sombre);
        let cc = ChangementCouleurs {
            theme: Theme::Sombre,
            choix: Some(braise),
        };
        let fait = format!(
            r#"{{"geste":"couleurs","issue":"fait","raison":"","theme":"sombre","avant":null,"apres":{{"base":"braise","vifs":"{BRAISE}"}}}}"#
        );
        assert_eq!(
            lire_issue(cc, &fin(&fait, 0)),
            IssueCouleurs::Fait {
                avant: None,
                apres: Some(braise)
            }
        );
        // Code non nul, autre thème, autres couleurs, autre geste : illisible.
        assert!(matches!(lire_issue(cc, &fin(&fait, 1)), IssueCouleurs::Echec(_)));
        let autre = ChangementCouleurs {
            theme: Theme::Clair,
            choix: Some(braise),
        };
        assert!(matches!(lire_issue(autre, &fin(&fait, 0)), IssueCouleurs::Echec(_)));
        let mut vanguard = braise;
        vanguard.poser(Vif::Accent, [0x3f, 0xbe, 0xf7]);
        let differente = ChangementCouleurs {
            theme: Theme::Sombre,
            choix: Some(vanguard),
        };
        assert!(matches!(
            lire_issue(differente, &fin(&fait, 0)),
            IssueCouleurs::Echec(_)
        ));
        assert!(matches!(
            lire_issue(cc, &fin(&fait.replace("\"couleurs\"", "\"retirer\""), 0)),
            IssueCouleurs::Echec(_)
        ));
        let refus = r#"{"geste":"couleurs","issue":"refuse","raison":"trop sombre","theme":null}"#;
        assert_eq!(
            lire_issue(cc, &fin(refus, 1)),
            IssueCouleurs::Refuse("trop sombre".into())
        );
    }
}

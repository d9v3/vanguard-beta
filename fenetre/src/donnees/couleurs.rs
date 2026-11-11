//! Les couleurs de la fenêtre telles que `vanguard couleurs --json` les dit, et l'issue d'un changement. La fenêtre
//! ne lit aucun fichier : ni parametres.json, ni le thème d'Omarchy, ni le registre de Windows ; `vanguard` lit,
//! juge et écrit, la fenêtre relit sa réponse ici. Elle la relit strictement : une couleur qui ne se lit pas, ou
//! qui se verrait à peine (`couleurs::verifier`), ne vaut pas ; celles de Vanguard servent, et la raison est dite.
//! Le réglage des animations, gardé par `vanguard` (`couleurs --animations`), vient dans la même réponse.

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
    /// parametres.json absent alors que les sceaux ont été refaits : peut-être effacé.
    Inconnu,
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
            "inconnu" => Doute::Inconnu,
            // Un mot inconnu (un `vanguard` plus récent) : un doute quand même, jamais rien.
            _ => Doute::Invalides,
        }
    }

    /// La phrase des coulisses et de la console.
    pub fn texte(self) -> &'static str {
        match self {
            Doute::HorsVanguard => crate::tr!(
                "parametres.json a été changé hors de Vanguard : les couleurs et les animations de Vanguard servent.",
                "parametres.json was changed outside Vanguard: Vanguard's colors and animations are used."
            ),
            Doute::Adopte => crate::tr!(
                "parametres.json a été accepté tel quel après des sceaux refaits : les couleurs et les animations de Vanguard servent.",
                "parametres.json was accepted as it was after seals were remade: Vanguard's colors and animations are used."
            ),
            Doute::Efface => crate::tr!(
                "parametres.json a été effacé hors de Vanguard : les couleurs et les animations de Vanguard servent.",
                "parametres.json was deleted outside Vanguard: Vanguard's colors and animations are used."
            ),
            Doute::Illisible => crate::tr!(
                "parametres.json est illisible : les couleurs et les animations de Vanguard servent.",
                "parametres.json is unreadable: Vanguard's colors and animations are used."
            ),
            Doute::Inconnu => crate::tr!(
                "parametres.json est absent alors que les sceaux ont été refaits (peut-être effacé) : les couleurs et les animations de Vanguard servent.",
                "parametres.json is missing while the seals were remade (maybe deleted): Vanguard's colors and animations are used."
            ),
            Doute::Invalides => crate::tr!(
                "Des couleurs gardées sont invalides : celles de Vanguard servent.",
                "Some saved colors are invalid: Vanguard's are used."
            ),
        }
    }

    /// `vanguard couleurs` refuse d'écrire par-dessus ce fichier-là : illisible, ses autres réglages seraient perdus ;
    /// effacé ou changé hors de Vanguard, le rescellement effacerait la trace. La fenêtre ne propose donc rien
    /// d'enregistrer, et dit pourquoi (`refus`).
    pub fn bloque(self) -> bool {
        matches!(
            self,
            Doute::HorsVanguard | Doute::Adopte | Doute::Efface | Doute::Illisible
        )
    }

    /// Ce qu'on fait d'un fichier qui bloque l'enregistrement.
    pub fn refus() -> &'static str {
        crate::tr!(
            "Aucune couleur ne s'enregistre par-dessus : « vanguard parametres » dit ce qu'il a ignoré, et un réglage changé là le réécrit.",
            "No color is saved over it: “vanguard settings” says what it ignored, and a setting changed there rewrites it."
        )
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
    /// Les animations gardées (`true` : réduites) ; rien : pas dit (un `vanguard` d'avant ce réglage), ou un mot
    /// inconnu, et la fenêtre garde les siennes.
    pub animations_reduites: Option<bool>,
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
    animations: Texte,
    douteux: Texte,
    systeme: Option<SystemeBrut>,
}

/// Le mot des animations, strictement : « reduites » ou « toutes », rien d'autre.
fn animations_de(mot: &str) -> Option<bool> {
    match mot {
        "reduites" => Some(true),
        "toutes" => Some(false),
        _ => None,
    }
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
        animations_reduites: animations_de(b.animations.as_str()),
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

/// La dernière ligne d'un changement qui a fini, lue en JSON ; sinon la raison de l'échec à montrer (`None` : une
/// réponse illisible).
fn reponse<T: serde::de::DeserializeOwned>(f: &Fin) -> Result<T, Option<String>> {
    match &f.issue {
        Issue::Terminee => {}
        Issue::Arretee => return Err(Some(crate::tr!("arrêté", "stopped").to_string())),
        Issue::DelaiDepasse => {
            return Err(Some(
                crate::tr!("arrêté : trop long sans finir", "stopped: too long without finishing").to_string(),
            ));
        }
        Issue::TropLongue => return Err(None),
        Issue::Impossible(e) => return Err(Some(crate::trf!("pas pu lancer : {}", "could not start: {}", e))),
    }
    let ligne = f
        .sortie
        .split(|o| *o == b'\n')
        .rev()
        .find(|l| !l.iter().all(u8::is_ascii_whitespace))
        .ok_or(None)?;
    super::lire::<T>(ligne).map_err(|_| None)
}

/// L'issue dite par Vanguard.
enum Dite {
    Fait,
    Refuse(String),
    Echec(String),
    Illisible,
}

/// L'issue dite par Vanguard pour ce geste-là, avec son code : « fait » seulement avec le code 0, un refus ou un
/// échec avec un code non nul (et sa raison, nettoyée) ; tout le reste est illisible.
fn issue_dite(geste: &Texte, attendu: &str, issue: &Texte, raison: &Texte, code: Option<i32>) -> Dite {
    if geste.as_str() != attendu {
        return Dite::Illisible;
    }
    let raison = crate::nettoyage::nom(raison.as_str(), 200);
    match (issue.as_str(), code) {
        ("fait", Some(0)) => Dite::Fait,
        ("refuse", Some(c)) if c != 0 => Dite::Refuse(raison),
        ("echec", Some(c)) if c != 0 => Dite::Echec(raison),
        _ => Dite::Illisible,
    }
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
    let b: IssueBrute = match reponse(f) {
        Ok(b) => b,
        Err(Some(r)) => return IssueCouleurs::Echec(r),
        Err(None) => return illisible(),
    };
    match issue_dite(&b.geste, "couleurs", &b.issue, &b.raison, f.code) {
        Dite::Fait => {}
        Dite::Refuse(r) => return IssueCouleurs::Refuse(r),
        Dite::Echec(r) => return IssueCouleurs::Echec(r),
        Dite::Illisible => return illisible(),
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

/// Ce qu'est devenu un changement des animations, d'après Vanguard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IssueAnimations {
    /// Gardées : la valeur d'avant (`true` : réduites).
    Fait {
        avant: bool,
    },
    Refuse(String),
    Echec(String),
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct IssueAnimationsBrute {
    geste: Texte,
    issue: Texte,
    raison: Texte,
    avant: Texte,
    apres: Texte,
}

/// Lit l'issue d'un changement des animations, aussi strictement que celle des couleurs : « fait » seulement pour
/// le geste « animations », le code 0, une valeur d'avant lisible et exactement celle demandée après.
pub fn lire_issue_animations(reduites: bool, f: &Fin) -> IssueAnimations {
    let illisible = || {
        IssueAnimations::Echec(
            crate::tr!("réponse de Vanguard illisible", "unreadable answer from Vanguard").to_string(),
        )
    };
    let b: IssueAnimationsBrute = match reponse(f) {
        Ok(b) => b,
        Err(Some(r)) => return IssueAnimations::Echec(r),
        Err(None) => return illisible(),
    };
    match issue_dite(&b.geste, "animations", &b.issue, &b.raison, f.code) {
        Dite::Fait => {}
        Dite::Refuse(r) => return IssueAnimations::Refuse(r),
        Dite::Echec(r) => return IssueAnimations::Echec(r),
        Dite::Illisible => return illisible(),
    }
    match (animations_de(b.avant.as_str()), animations_de(b.apres.as_str())) {
        (Some(avant), Some(apres)) if apres == reduites => IssueAnimations::Fait { avant },
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
        // Ce que `vanguard couleurs` refuse d'écraser bloque l'enregistrement ; des couleurs invalides ou un fichier
        // peut-être effacé, non (rien d'autre à perdre, rien à resceller).
        for (mot, bloque) in [
            ("hors_vanguard", true),
            ("adopte", true),
            ("efface", true),
            ("illisible", true),
            ("inconnu", false),
            ("invalides", false),
        ] {
            let d = lire(format!(r#"{{"douteux":"{mot}"}}"#).as_bytes())
                .unwrap()
                .doute
                .unwrap();
            assert_eq!(d.bloque(), bloque, "{mot}");
        }
        assert_eq!(lire(br#"{"douteux":"inconnu"}"#).unwrap().doute, Some(Doute::Inconnu));
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

    /// Les animations gardées se relisent strictement : deux mots, sinon rien (la fenêtre garde les siennes) ; leur
    /// issue n'est « faite » que pour ce geste, le code 0 et exactement la valeur demandée.
    #[test]
    fn les_animations_se_relisent_strictement() {
        for (json, attendu) in [
            (r#"{"animations":"reduites"}"#, Some(true)),
            (r#"{"animations":"toutes"}"#, Some(false)),
            ("{}", None),
            (r#"{"animations":"Reduites"}"#, None),
            (r#"{"animations":true}"#, None),
        ] {
            assert_eq!(lire(json.as_bytes()).unwrap().animations_reduites, attendu, "{json}");
        }
        let fin = |sortie: &str, code| Fin {
            lancement: crate::commandes::Lancement::Animations(true),
            ..fin(sortie, code)
        };
        let fait =
            r#"{"geste":"animations","issue":"fait","raison":"","avant":"toutes","apres":"reduites","douteux":null}"#;
        assert_eq!(
            lire_issue_animations(true, &fin(fait, 0)),
            IssueAnimations::Fait { avant: false }
        );
        for (sortie, code, voulu) in [
            (fait, 1, true),
            (fait, 0, false),
            (&fait.replace("\"animations\",\"issue", "\"couleurs\",\"issue"), 0, true),
            (&fait.replace("\"toutes\"", "\"rien\""), 0, true),
        ] {
            assert!(
                matches!(
                    lire_issue_animations(voulu, &fin(sortie, code)),
                    IssueAnimations::Echec(_)
                ),
                "{sortie} {code} {voulu}"
            );
        }
        let refus = r#"{"geste":"animations","issue":"refuse","raison":"parametres.json a été changé hors de Vanguard","avant":null,"apres":null,"douteux":"hors_vanguard"}"#;
        assert!(matches!(
            lire_issue_animations(true, &fin(refus, 1)),
            IssueAnimations::Refuse(r) if r.contains("hors de Vanguard")
        ));
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

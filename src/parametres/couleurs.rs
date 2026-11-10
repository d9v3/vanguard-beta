//! Les couleurs de la fenêtre (`vanguard couleurs`, alias `colors`) : pour chaque thème (sombre, clair), un des six
//! préréglages ou les couleurs du système, et les cinq couleurs vives (l'accent et les quatre gravités). Gardées
//! dans parametres.json, scellé : c'est ici qu'elles s'écrivent, jamais dans la fenêtre, qui n'écrit rien. Elle
//! lance `vanguard couleurs --json` pour les lire, et `vanguard couleurs --theme … --base … --vifs … --json` pour les
//! changer, avec des valeurs qu'elle a construites ; tout est revérifié ici (mots fermés, six chiffres
//! hexadécimaux, une couleur presque invisible sur le fond refusée), comme si la demande venait de n'importe qui.
//!
//! Le modèle (préréglages, mesures, refus) est le même fichier que celui de la fenêtre (fenetre/src/couleurs.rs),
//! inclus par son chemin : une seule table, et les mêmes refus des deux côtés.
//!
//! Les couleurs du système se lisent ici aussi, jamais dans la fenêtre (son bac à sable ne voit pas le dossier
//! personnel) : le thème d'Omarchy sous Linux (colors.toml : accent, red, orange, yellow, green), la couleur
//! d'accentuation sous Windows (l'accent seul). Un parametres.json changé hors de Vanguard, effacé ou illisible :
//! les couleurs de Vanguard, et la raison est dite (la fenêtre la montre dans ses coulisses).

#[path = "../../fenetre/src/couleurs.rs"]
// Le modèle est partagé : la fenêtre en dessine davantage (les neutres, l'encre sur l'accent, les remarques).
#[allow(dead_code)]
mod modele;

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::ui::*;
use modele::{Base, Choix, Rgb, Theme, VIFS, Vif};

/// Ce que parametres.json garde des couleurs : par thème, rien (celles de Vanguard) ou un choix.
#[derive(Serialize, Deserialize, Default, Clone, PartialEq, Eq, Debug)]
pub(crate) struct Reglees {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sombre: Option<Garde>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    clair: Option<Garde>,
}

/// Un choix tel qu'il est gardé : le mot de la base et les cinq couleurs (« 3fbef7,f24f4d,… »). Relu par
/// `choix_de`, qui refuse tout ce que `vanguard couleurs` n'aurait pas écrit.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
struct Garde {
    base: String,
    vifs: String,
}

impl Reglees {
    pub(crate) fn est_vide(&self) -> bool {
        self.sombre.is_none() && self.clair.is_none()
    }

    fn de(&self, t: Theme) -> Option<&Garde> {
        match t {
            Theme::Sombre => self.sombre.as_ref(),
            Theme::Clair => self.clair.as_ref(),
        }
    }

    fn poser(&mut self, t: Theme, g: Option<Garde>) {
        match t {
            Theme::Sombre => self.sombre = g,
            Theme::Clair => self.clair = g,
        }
    }
}

fn garde_de(c: &Choix) -> Garde {
    Garde {
        base: c.base.mot().to_string(),
        vifs: modele::vifs_hex(&c.vifs),
    }
}

/// Le choix gardé, s'il est tel que `vanguard couleurs` l'écrit : base connue, cinq couleurs strictes, aucune
/// presque invisible sur ce thème.
fn choix_de(g: &Garde, theme: Theme) -> Option<Choix> {
    let c = Choix {
        base: Base::lire(&g.base)?,
        vifs: modele::lire_vifs(&g.vifs)?,
    };
    modele::verifier(theme, &c).is_ok().then_some(c)
}

/// Pourquoi les couleurs réglées ne valent pas : celles de Vanguard servent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Doute {
    /// parametres.json changé hors de Vanguard.
    HorsVanguard,
    /// Accepté tel quel après des sceaux refaits : rien ne prouve qui l'a écrit.
    Adopte,
    /// Effacé hors de Vanguard.
    Efface,
    /// Là, mais il ne se lit pas.
    Illisible,
    /// Scellé, mais des couleurs que `vanguard couleurs` n'écrit pas.
    Invalides,
}

impl Doute {
    /// Le mot du JSON, que la fenêtre traduit.
    fn mot(self) -> &'static str {
        match self {
            Doute::HorsVanguard => "hors_vanguard",
            Doute::Adopte => "adopte",
            Doute::Efface => "efface",
            Doute::Illisible => "illisible",
            Doute::Invalides => "invalides",
        }
    }

    fn texte(self) -> &'static str {
        match self {
            Doute::HorsVanguard => tr!(
                "parametres.json changé hors de Vanguard : les couleurs de Vanguard servent",
                "parametres.json changed outside Vanguard: Vanguard's colors are used"
            ),
            Doute::Adopte => tr!(
                "parametres.json accepté tel quel après des sceaux refaits : les couleurs de Vanguard servent",
                "parametres.json accepted as it was after seals were remade: Vanguard's colors are used"
            ),
            Doute::Efface => tr!(
                "parametres.json effacé hors de Vanguard : les couleurs de Vanguard servent",
                "parametres.json deleted outside Vanguard: Vanguard's colors are used"
            ),
            Doute::Illisible => tr!(
                "parametres.json illisible : les couleurs de Vanguard servent",
                "parametres.json unreadable: Vanguard's colors are used"
            ),
            Doute::Invalides => tr!(
                "couleurs gardées invalides : celles de Vanguard servent",
                "invalid saved colors: Vanguard's are used"
            ),
        }
    }
}

/// Les couleurs réglées, relues : par thème (dans l'ordre de `Theme::TOUS`), et pourquoi certaines ne valent pas.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Lues {
    choix: [Option<Choix>; 2],
    doute: Option<Doute>,
}

impl Lues {
    fn de(&self, t: Theme) -> Option<Choix> {
        match t {
            Theme::Sombre => self.choix[0],
            Theme::Clair => self.choix[1],
        }
    }
}

fn lire_dans(chemin: &Path) -> Lues {
    let Ok((f, j)) = super::juger(chemin) else {
        return Lues {
            choix: [None; 2],
            doute: Some(Doute::Illisible),
        };
    };
    let mut doute = if j.efface {
        Some(Doute::Efface)
    } else if j.couleurs {
        j.douteux.map(|d| match d {
            super::Douteux::Adopte => Doute::Adopte,
            super::Douteux::HorsVanguard => Doute::HorsVanguard,
        })
    } else {
        None
    };
    let choix = Theme::TOUS.map(|t| {
        let g = f.couleurs.de(t)?;
        let c = choix_de(g, t);
        if c.is_none() {
            doute = doute.or(Some(Doute::Invalides));
        }
        c
    });
    Lues { choix, doute }
}

/// Ce que demande un changement : un choix pour un thème, ou ses couleurs remises à celles de Vanguard.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Voulu {
    Choix(Choix),
    Defaut,
}

/// Pourquoi un changement n'est pas fait.
#[derive(Clone, PartialEq, Debug)]
enum Refus {
    /// La demande ne se comprend pas (code 2).
    MalFormee(String),
    /// Une couleur se verrait à peine sur le fond du thème (code 1).
    Invisible(modele::Refus),
}

impl Refus {
    fn raison(&self) -> String {
        match self {
            Refus::MalFormee(r) => r.clone(),
            Refus::Invisible(r) => trf!(
                "{} se verrait à peine sur le fond (contraste {}:1, il faut au moins {}:1)",
                "{} would barely show on the background (contrast {}:1, at least {}:1 is needed)",
                nom_du_vif(r.vif),
                nombre(r.ratio, 2),
                nombre(modele::CONTRASTE_MIN, 1)
            ),
        }
    }
}

/// Un nombre à `decimales` chiffres après la virgule, écrit comme dans la langue de l'affichage.
fn nombre(x: f64, decimales: usize) -> String {
    let texte = format!("{x:.decimales$}");
    if crate::langue::anglais() {
        texte
    } else {
        texte.replace('.', ",")
    }
}

fn nom_du_vif(v: Vif) -> &'static str {
    match v {
        Vif::Accent => tr!("l'accent", "the accent"),
        Vif::Grave => tr!("la couleur « grave »", "the “severe” color"),
        Vif::Moyen => tr!("la couleur « moyen »", "the “medium” color"),
        Vif::Jaune => tr!("la couleur « à surveiller »", "the “watch” color"),
        Vif::Bon => tr!("la couleur « sain »", "the “healthy” color"),
    }
}

/// La demande, depuis les options de la ligne de commande : seulement des mots fermés et des couleurs strictes.
/// `systeme` : les couleurs du système, lues seulement si la base « systeme » est demandée sans ses couleurs.
fn comprendre(
    theme: Option<&str>,
    base: Option<&str>,
    vifs: Option<&str>,
    defaut: bool,
    reglee: impl FnOnce(Theme) -> Option<Choix>,
    systeme: impl FnOnce() -> Option<[Option<Rgb>; VIFS]>,
) -> Result<(Theme, Voulu), Refus> {
    let mal = |fr: &str, en: &str| Refus::MalFormee(if crate::langue::anglais() { en } else { fr }.to_string());
    let Some(theme) = theme else {
        return Err(mal(
            "--theme sombre ou --theme clair manque",
            "--theme sombre or --theme clair is missing",
        ));
    };
    let Some(theme) = Theme::lire(theme) else {
        return Err(mal(
            "thème inconnu (sombre ou clair)",
            "unknown theme (sombre or clair)",
        ));
    };
    if defaut {
        if base.is_some() || vifs.is_some() {
            return Err(mal(
                "--defaut ne se donne pas avec --base ni --vifs",
                "--defaut is not given with --base or --vifs",
            ));
        }
        return Ok((theme, Voulu::Defaut));
    }
    let base = match base {
        Some(mot) => Some(Base::lire(mot).ok_or_else(|| {
            mal(
                "base inconnue (vanguard, braise, emeraude, ambre, violet, glacier ou systeme)",
                "unknown base (vanguard, braise, emeraude, ambre, violet, glacier or systeme)",
            )
        })?),
        None => None,
    };
    let vifs = match vifs {
        Some(t) => Some(modele::lire_vifs(t).ok_or_else(|| {
            mal(
                "--vifs : cinq couleurs de six chiffres hexadécimaux minuscules, séparées par des virgules",
                "--vifs: five colors of six lowercase hexadecimal digits, separated by commas",
            )
        })?),
        None => None,
    };
    let choix = match (base, vifs) {
        (None, None) => {
            return Err(mal(
                "rien à changer : --base, --vifs ou --defaut",
                "nothing to change: --base, --vifs or --defaut",
            ));
        }
        (Some(base), Some(vifs)) => Choix { base, vifs },
        // Sans base : celle déjà réglée pour ce thème, sinon celle de Vanguard.
        (None, Some(vifs)) => Choix {
            base: reglee(theme).map_or(Base::Vanguard, |c| c.base),
            vifs,
        },
        (Some(Base::Systeme), None) => match systeme() {
            Some(lues) => modele::depuis_le_systeme(theme, &lues).0,
            None => {
                return Err(Refus::MalFormee(
                    tr!(
                        "aucune couleur du système trouvée (thème d'Omarchy ou accent de Windows)",
                        "no system colors found (Omarchy theme or Windows accent)"
                    )
                    .to_string(),
                ));
            }
        },
        (Some(base), None) => Choix::du_prereglage(base, theme),
    };
    modele::verifier(theme, &choix).map_err(Refus::Invisible)?;
    Ok((theme, Voulu::Choix(choix)))
}

/// Le changement fait dans le fichier (relu sous son sceau, réécrit scellé) : la valeur d'avant et celle d'après.
/// Un fichier changé hors de Vanguard n'est jamais rescellé tel quel : ses couleurs, comme ses réglages qui coupaient
/// une défense, valent leur défaut avant le changement (`super::juger`).
fn changer_dans(chemin: &Path, theme: Theme, voulu: Voulu) -> std::io::Result<(Option<Choix>, Option<Choix>)> {
    let avant = lire_dans(chemin).de(theme);
    let apres = match voulu {
        Voulu::Choix(c) => Some(c),
        Voulu::Defaut => None,
    };
    super::modifier_dans(chemin, |f| {
        let nouvelle = apres.as_ref().map(garde_de);
        if f.couleurs.de(theme) == nouvelle.as_ref() {
            return false;
        }
        f.couleurs.poser(theme, nouvelle);
        true
    })?;
    Ok((avant, apres))
}

/// `vanguard couleurs` : sans option, les couleurs réglées et celles du système ; avec `--theme`, un changement.
/// Rend le code de sortie : 0 fait (ou lu), 1 refusé ou non fait, 2 demande mal formée. Avec `json`, la dernière
/// ligne dit tout, pour la fenêtre.
pub fn commande(json: bool, theme: Option<&str>, base: Option<&str>, vifs: Option<&str>, defaut: bool) -> i32 {
    let chemin = super::fichier();
    if theme.is_none() && base.is_none() && vifs.is_none() && !defaut {
        let lues = lire_dans(&chemin);
        let systeme = du_systeme();
        if json {
            println!("{}", json_lu(&lues, systeme.as_ref()));
        } else {
            afficher(&lues, systeme.as_ref());
        }
        return 0;
    }
    let demande = comprendre(
        theme,
        base,
        vifs,
        defaut,
        |t| lire_dans(&chemin).de(t),
        || du_systeme().map(|s| s.vifs),
    );
    let (code, issue, raison, theme, avant, apres) = match demande {
        Err(r) => {
            let code = if matches!(r, Refus::MalFormee(_)) { 2 } else { 1 };
            (code, "refuse", r.raison(), None, None, None)
        }
        Ok((t, voulu)) => match changer_dans(&chemin, t, voulu) {
            Ok((avant, apres)) => (0, "fait", String::new(), Some(t), avant, apres),
            Err(e) => (
                1,
                "echec",
                trf!("non enregistré ({})", "not saved ({})", e),
                Some(t),
                None,
                None,
            ),
        },
    };
    if json {
        println!(
            "{}",
            serde_json::json!({
                "geste": "couleurs",
                "issue": issue,
                "raison": raison,
                "theme": theme.map(Theme::mot),
                "avant": avant.as_ref().map(json_choix),
                "apres": apres.as_ref().map(json_choix),
            })
        );
    } else if issue == "fait" {
        let t = theme.unwrap_or(Theme::Sombre);
        trp!(
            "  {VERT}✔{RESET} Couleurs du thème {} : avant {}, maintenant {}.",
            "  {VERT}✔{RESET} Colors of the {} theme: before {}, now {}.",
            t.mot(),
            dit(avant.as_ref()),
            dit(apres.as_ref())
        );
        afficher_aligne(
            "  ",
            &trf!(
                "Pour annuler : vanguard couleurs --theme {} {}",
                "To undo: vanguard colors --theme {} {}",
                t.mot(),
                options_de(avant.as_ref())
            ),
            2,
            GRIS,
        );
    } else {
        trp!("  ✖ Rien n'a changé : {raison}", "  ✖ Nothing changed: {raison}");
    }
    code
}

fn json_choix(c: &Choix) -> serde_json::Value {
    serde_json::json!({ "base": c.base.mot(), "vifs": modele::vifs_hex(&c.vifs) })
}

fn json_lu(lues: &Lues, systeme: Option<&Systeme>) -> serde_json::Value {
    serde_json::json!({
        "sombre": lues.de(Theme::Sombre).as_ref().map(json_choix),
        "clair": lues.de(Theme::Clair).as_ref().map(json_choix),
        "douteux": lues.doute.map(Doute::mot),
        "systeme": systeme.map(|s| serde_json::json!({
            "source": s.source,
            "vifs": s.vifs.iter().map(|c| c.map(modele::hex)).collect::<Vec<_>>(),
        })),
    })
}

/// Un choix en mots : « braise (ff4a3d, …) » ; rien : les couleurs de Vanguard.
fn dit(c: Option<&Choix>) -> String {
    match c {
        Some(c) => format!("{} ({})", c.base.mot(), modele::vifs_hex(&c.vifs)),
        None => tr!("celles de Vanguard", "Vanguard's").to_string(),
    }
}

/// Les options qui remettent ce choix.
fn options_de(c: Option<&Choix>) -> String {
    match c {
        Some(c) => format!("--base {} --vifs {}", c.base.mot(), modele::vifs_hex(&c.vifs)),
        None => "--defaut".to_string(),
    }
}

fn afficher(lues: &Lues, systeme: Option<&Systeme>) {
    titre(tr!("Couleurs de la fenêtre", "Window colors"));
    if let Some(d) = lues.doute {
        afficher_aligne(
            &format!("  {}⚠{RESET} ", couleur(crate::risk::Niveau::Moyen)),
            d.texte(),
            4,
            "",
        );
    }
    for t in Theme::TOUS {
        println!("  {GRAS}{:<8}{RESET} {}", t.mot(), dit(lues.de(t).as_ref()));
    }
    match systeme {
        Some(s) => println!(
            "  {GRIS}{}{RESET}",
            trf!(
                "Couleurs du système ({}) : {}",
                "System colors ({}): {}",
                s.source,
                s.vifs
                    .iter()
                    .map(|c| c.map_or_else(|| "-".to_string(), modele::hex))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        ),
        None => println!(
            "  {GRIS}{}{RESET}",
            tr!("Aucune couleur du système trouvée.", "No system colors found.")
        ),
    }
    println!();
    afficher_aligne(
        "  ",
        tr!(
            "Changer : vanguard couleurs --theme sombre|clair --base <préréglage> [--vifs accent,grave,moyen,faible,bon] ; --defaut remet celles de Vanguard. La fenêtre les règle dans Réglages.",
            "Change: vanguard colors --theme sombre|clair --base <preset> [--vifs accent,severe,medium,low,good]; --defaut puts Vanguard's back. The window sets them in Settings."
        ),
        2,
        GRIS,
    );
}

/// Les couleurs du système : d'où elles viennent, et les cinq (une absente : `None`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Systeme {
    source: &'static str,
    vifs: [Option<Rgb>; VIFS],
}

/// Au-delà, ce n'est pas un fichier de couleurs.
#[cfg(target_os = "linux")]
const TOML_MAX: u64 = 64 << 10;

#[cfg(target_os = "linux")]
fn du_systeme() -> Option<Systeme> {
    let maison = crate::socle::personnel::dossier_personnel()?;
    // Le thème courant d'Omarchy : sous ~/.local/state depuis la version 3, sous ~/.config avant.
    [
        ".local/state/omarchy/current/theme/colors.toml",
        ".config/omarchy/current/theme/colors.toml",
    ]
    .into_iter()
    .find_map(|c| crate::socle::lire_ordinaire(&maison.join(c), TOML_MAX).ok())
    .and_then(|o| String::from_utf8(o).ok())
    .and_then(|t| lire_omarchy(&t))
    .map(|vifs| Systeme {
        source: "omarchy",
        vifs,
    })
}

/// La couleur d'accentuation de Windows (HKCU\Software\Microsoft\Windows\DWM, AccentColor : 0xAABBGGRR) : l'accent
/// seul, les gravités restent celles de Vanguard.
#[cfg(windows)]
fn du_systeme() -> Option<Systeme> {
    let cle = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
        .open_subkey(r"Software\Microsoft\Windows\DWM")
        .ok()?;
    let [r, g, b, _] = cle.get_value::<u32, _>("AccentColor").ok()?.to_le_bytes();
    Some(Systeme {
        source: "windows",
        vifs: [Some([r, g, b]), None, None, None, None],
    })
}

#[cfg(not(any(target_os = "linux", windows)))]
fn du_systeme() -> Option<Systeme> {
    None
}

/// Les couleurs d'un colors.toml d'Omarchy (lignes `clé = "#rrggbb"`) : accent, red, orange, yellow, green, dans
/// l'ordre de `Vif::TOUS`. Une valeur qui n'est pas une couleur stricte est ignorée ; aucune des cinq : rien.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn lire_omarchy(texte: &str) -> Option<[Option<Rgb>; VIFS]> {
    const CLES: [&str; VIFS] = ["accent", "red", "orange", "yellow", "green"];
    let mut vifs = [None; VIFS];
    for ligne in texte.lines() {
        let Some((cle, valeur)) = ligne.split_once('=') else {
            continue;
        };
        let Some(rang) = CLES.iter().position(|c| *c == cle.trim()) else {
            continue;
        };
        let valeur = valeur.trim();
        let Some(hex) = valeur
            .strip_prefix("\"#")
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| valeur.strip_prefix("'#").and_then(|v| v.strip_suffix('\'')))
        else {
            continue;
        };
        if let (Some(case), Some(c)) = (vifs.get_mut(rang), modele::lire_hex(&hex.to_ascii_lowercase())) {
            *case = Some(c);
        }
    }
    vifs.iter().any(Option::is_some).then_some(vifs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dossier(nom: &str) -> std::path::PathBuf {
        let d = crate::essais::temporaire().join(format!("vanguard-couleurs-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn lu(chemin: &Path) -> Vec<u8> {
        std::fs::read(chemin).unwrap()
    }

    fn braise() -> Choix {
        Choix::du_prereglage(Base::Braise, Theme::Sombre)
    }

    /// Un changement s'annule exactement : remettre la valeur d'avant redonne le fichier octet pour octet, les autres
    /// réglages gardés ; la valeur d'avant est rendue.
    #[test]
    fn un_changement_s_annule_exactement() {
        let d = dossier("annuler");
        let f = d.join(super::super::PARAMETRES);
        super::super::modifier_dans(&f, |p| {
            p.langue = Some("fr".into());
            true
        })
        .unwrap();
        let depart = lu(&f);
        let (avant, apres) = changer_dans(&f, Theme::Sombre, Voulu::Choix(braise())).unwrap();
        assert_eq!((avant, apres), (None, Some(braise())));
        assert_ne!(lu(&f), depart);
        assert_eq!(lire_dans(&f).de(Theme::Sombre), Some(braise()));
        assert_eq!(lire_dans(&f).de(Theme::Clair), None);
        // Un second changement rend le premier comme valeur d'avant.
        let mut autre = braise();
        autre.poser(Vif::Accent, [0x12, 0x80, 0xff]);
        let (avant, _) = changer_dans(&f, Theme::Sombre, Voulu::Choix(autre)).unwrap();
        assert_eq!(avant, Some(braise()));
        changer_dans(&f, Theme::Sombre, Voulu::Choix(braise())).unwrap();
        let (avant, apres) = changer_dans(&f, Theme::Sombre, Voulu::Defaut).unwrap();
        assert_eq!((avant, apres), (Some(braise()), None));
        assert_eq!(lu(&f), depart, "le fichier redevient octet pour octet celui d'avant");
        assert_eq!(super::super::charger_de(&f).unwrap().langue.as_deref(), Some("fr"));
    }

    /// Ce que la fenêtre (ou n'importe qui) envoie est revérifié : mots fermés, couleurs strictes, rien d'invisible ;
    /// une demande refusée ne touche pas au fichier.
    #[test]
    fn une_demande_invalide_est_refusee() {
        let rien = |_| None;
        let sans_systeme = || None;
        let ok = "3fbef7,f24f4d,fb852f,e7c03a,45b45e";
        for (theme, base, vifs, defaut) in [
            (None, Some("braise"), None, false),
            (Some("noir"), Some("braise"), None, false),
            (Some("Sombre"), Some("braise"), None, false),
            (Some("sombre"), Some("rouge"), None, false),
            (
                Some("sombre"),
                Some("braise"),
                Some("3FBEF7,f24f4d,fb852f,e7c03a,45b45e"),
                false,
            ),
            (
                Some("sombre"),
                Some("braise"),
                Some("#3fbef7,f24f4d,fb852f,e7c03a,45b45e"),
                false,
            ),
            (
                Some("sombre"),
                Some("braise"),
                Some("3fbef7,f24f4d,fb852f,e7c03a"),
                false,
            ),
            (Some("sombre"), Some("braise"), Some(ok), true),
            (Some("sombre"), None, None, false),
            (Some("sombre"), Some("systeme"), None, false),
            (Some("sombre"), Some("braise;rm -rf"), None, false),
        ] {
            let r = comprendre(theme, base, vifs, defaut, rien, sans_systeme);
            assert!(
                matches!(r, Err(Refus::MalFormee(_))),
                "{theme:?} {base:?} {vifs:?} {defaut}: {r:?}"
            );
        }
        // Noir sur le fond noir : presque invisible, refusé (code 1).
        let r = comprendre(
            Some("sombre"),
            Some("vanguard"),
            Some("000000,f24f4d,fb852f,e7c03a,45b45e"),
            false,
            rien,
            sans_systeme,
        );
        assert!(
            matches!(r, Err(Refus::Invisible(modele::Refus { vif: Vif::Accent, .. }))),
            "{r:?}"
        );
        // Le blanc sur la surface blanche du thème clair aussi.
        let r = comprendre(
            Some("clair"),
            Some("glacier"),
            Some(&format!("ffffff{}", &ok[6..])),
            false,
            rien,
            sans_systeme,
        );
        assert!(matches!(r, Err(Refus::Invisible(_))), "{r:?}");
        // Bien formées : acceptées.
        assert_eq!(
            comprendre(Some("clair"), None, None, true, rien, sans_systeme),
            Ok((Theme::Clair, Voulu::Defaut))
        );
        assert_eq!(
            comprendre(Some("sombre"), Some("braise"), None, false, rien, sans_systeme),
            Ok((Theme::Sombre, Voulu::Choix(braise())))
        );
        // Sans base : celle déjà réglée.
        let r = comprendre(Some("sombre"), None, Some(ok), false, |_| Some(braise()), sans_systeme);
        assert!(
            matches!(r, Ok((_, Voulu::Choix(Choix { base: Base::Braise, .. })))),
            "{r:?}"
        );
    }

    /// Changé hors de Vanguard : les couleurs ne valent pas, la raison est dite, et le prochain changement n'en
    /// rescelle aucune.
    #[test]
    fn un_fichier_change_hors_de_vanguard_rend_les_couleurs_de_vanguard() {
        let d = dossier("forge");
        let f = d.join(super::super::PARAMETRES);
        changer_dans(&f, Theme::Sombre, Voulu::Choix(braise())).unwrap();
        // Un programme du compte réécrit le fichier (le sceau ne correspond plus).
        let mut glacier = Choix::du_prereglage(Base::Glacier, Theme::Clair);
        glacier.poser(Vif::Grave, [0xee, 0x00, 0x00]);
        std::fs::write(
            &f,
            format!(
                r#"{{"couleurs":{{"sombre":{{"base":"violet","vifs":"{}"}},"clair":{{"base":"glacier","vifs":"{}"}}}}}}"#,
                modele::vifs_hex(&Choix::du_prereglage(Base::Violet, Theme::Sombre).vifs),
                modele::vifs_hex(&glacier.vifs)
            ),
        )
        .unwrap();
        let l = lire_dans(&f);
        assert_eq!(l.choix, [None, None]);
        assert_eq!(l.doute, Some(Doute::HorsVanguard));
        assert_eq!(json_lu(&l, None)["douteux"], "hors_vanguard");
        // Rien à changer (le clair vaut déjà celles de Vanguard) : rien d'écrit, le doute reste dit.
        changer_dans(&f, Theme::Clair, Voulu::Defaut).unwrap();
        assert_eq!(lire_dans(&f).doute, Some(Doute::HorsVanguard));
        // Un changement du thème clair : le thème sombre forgé n'est pas rescellé avec lui.
        let g = Choix::du_prereglage(Base::Glacier, Theme::Clair);
        let (avant, _) = changer_dans(&f, Theme::Clair, Voulu::Choix(g)).unwrap();
        assert_eq!(avant, None, "la valeur d'avant est celle montrée, pas la forgée");
        let l = lire_dans(&f);
        assert_eq!((l.choix, l.doute), ([None, Some(g)], None));
        // Effacé hors de Vanguard : dit aussi.
        changer_dans(&f, Theme::Sombre, Voulu::Choix(braise())).unwrap();
        std::fs::remove_file(&f).unwrap();
        assert_eq!(lire_dans(&f).doute, Some(Doute::Efface));
    }

    /// Illisible (pas du JSON, ou un dossier à sa place) : les couleurs de Vanguard, dit.
    #[test]
    fn un_fichier_illisible_rend_les_couleurs_de_vanguard() {
        let d = dossier("illisible");
        let f = d.join(super::super::PARAMETRES);
        changer_dans(&f, Theme::Sombre, Voulu::Choix(braise())).unwrap();
        std::fs::remove_file(&f).unwrap();
        std::fs::create_dir(&f).unwrap();
        let l = lire_dans(&f);
        assert_eq!((l.choix, l.doute), ([None, None], Some(Doute::Illisible)));
    }

    /// Scellé mais pas tel que `vanguard couleurs` l'écrit (une version future, un bogue) : ignoré, dit.
    #[test]
    fn des_couleurs_gardees_invalides_ne_valent_pas() {
        let d = dossier("invalides");
        let f = d.join(super::super::PARAMETRES);
        for (base, vifs) in [
            ("rouge", "3fbef7,f24f4d,fb852f,e7c03a,45b45e"),
            ("vanguard", "3fbef7,f24f4d"),
            ("vanguard", "000000,f24f4d,fb852f,e7c03a,45b45e"),
        ] {
            super::super::modifier_dans(&f, |p| {
                p.couleurs.sombre = Some(Garde {
                    base: base.into(),
                    vifs: vifs.into(),
                });
                true
            })
            .unwrap();
            let l = lire_dans(&f);
            assert_eq!(
                (l.choix, l.doute),
                ([None, None], Some(Doute::Invalides)),
                "{base} {vifs}"
            );
        }
    }

    /// Le colors.toml d'Omarchy, inventé : les cinq clés lues, le reste ignoré, une valeur douteuse aussi.
    #[test]
    fn le_theme_d_omarchy_se_lit() {
        let texte = "# un thème\nmode = \"dark\"\naccent = \"#FF0A1E\"\nred=\"#ff4d4d\"\n  orange = '#ff9a4d'\n\
                     yellow = \"ffcf5c\"\ngreen = \"#9fd36a; rm\"\nbright_red = \"#ff7a7a\"\nbackground = \"#000000\"\n";
        assert_eq!(
            lire_omarchy(texte),
            Some([
                Some([0xff, 0x0a, 0x1e]),
                Some([0xff, 0x4d, 0x4d]),
                Some([0xff, 0x9a, 0x4d]),
                None,
                None
            ])
        );
        assert_eq!(lire_omarchy("background = \"#000000\"\n"), None);
        assert_eq!(lire_omarchy(""), None);
    }

    /// La base « systeme » sans ses couleurs : celles lues, une illisible sur le thème gardée de Vanguard.
    #[test]
    fn la_base_du_systeme_prend_les_couleurs_lues() {
        let lues = [Some([0xff, 0x0a, 0x1e]), None, None, Some([0xff, 0xff, 0xf8]), None];
        let r = comprendre(Some("clair"), Some("systeme"), None, false, |_| None, || Some(lues));
        let Ok((Theme::Clair, Voulu::Choix(c))) = r else {
            panic!("{r:?}")
        };
        assert_eq!(c.base, Base::Systeme);
        assert_eq!(c.vif(Vif::Accent), [0xff, 0x0a, 0x1e]);
        assert_eq!(c.vif(Vif::Jaune), Base::Vanguard.prereglage(Theme::Clair).vifs[3]);
    }
}

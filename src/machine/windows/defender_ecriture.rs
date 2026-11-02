//! Les actes de Defender du processus élevé (`vanguard:defender…`, grammaire de `gestes.rs`), faits par WMI dans
//! `root\Microsoft\Windows\Defender` (MSFT_MpPreference, MSFT_MpThreat), ce que font les commandes de Defender sans
//! passer par PowerShell : un script qui les nomme est bloqué par AMSI sur un Windows à jour.
//!
//! Chaque acte relit avant d'écrire, puis relit après. Windows peut ignorer la demande sans erreur : la protection
//! contre les falsifications rend la main « réussi » et garde la valeur, une stratégie de groupe ou un autre antivirus
//! aussi. Seule la valeur relue compte : un réglage qui n'a pas bougé est un échec dit avec sa cause probable, jamais
//! un « fait ».

use std::time::Duration;

use super::corrections::{Resultat, avant_notable};
use super::exclusions;
use super::wmi::{self, CLASSE_ABSENTE, Ligne, Parametre, Retour, Valeur};
use crate::machine::gestes::{self, Acte, GenreExclusion, ModeAsr, ReglageDefender, ValeurDefender};
use crate::modele::raison::Echec;
use crate::ui::{tr, trf};

const ESPACE: &str = r"root\Microsoft\Windows\Defender";
const PREFERENCES: &str = "MSFT_MpPreference";
const ETAT: &str = "MSFT_MpComputerStatus";
const MENACES: &str = "MSFT_MpThreat";
const IDS_ASR: &str = "AttackSurfaceReductionRules_Ids";
const ACTIONS_ASR: &str = "AttackSurfaceReductionRules_Actions";
/// Une méthode de Defender répond en quelques secondes ; retirer des menaces peut effacer des fichiers, plus long.
const DELAI: Duration = Duration::from_secs(120);
/// Le temps réel met un instant à repartir après l'écriture : relu jusqu'à 5 s (10 fois, toutes les 500 ms).
const RELECTURES: u32 = 10;
const PAUSE: Duration = Duration::from_millis(500);

/// Fait un acte de Defender ; `None` : l'acte n'en est pas un.
pub(super) fn faire_acte(acte: &Acte) -> Option<Resultat> {
    Some(match acte {
        Acte::Defender(ReglageDefender::TempsReel, _) => temps_reel(acte),
        Acte::Defender(r, v) => reglage(*r, *v, acte),
        Acte::DefenderAsr(id, m) => regle_asr(id, *m, acte),
        Acte::DefenderExclusionRetirer(g, e) => retirer_exclusion(*g, e.texte(), acte),
        Acte::DefenderMenacesRetirer => retirer_menaces(),
        _ => return None,
    })
}

/// La seule instance de MSFT_MpPreference, ces champs lus ; `None` si Defender ne répond pas.
fn preferences(champs: &[&str]) -> Option<Ligne> {
    wmi::requete(ESPACE, PREFERENCES, "", champs)?.into_iter().next()
}

/// Un entier relu, booléen compris (DisableRealtimeMonitoring) : faux 0, vrai 1.
fn entier(v: &Valeur) -> Option<i64> {
    match v {
        Valeur::Booleen(b) => Some(i64::from(*b)),
        x => x.entier(),
    }
}

/// L'état de la protection en temps réel (`RealTimeProtectionEnabled`) et de la protection contre les falsifications
/// (`IsTamperProtected`), tels que Defender les applique ; `None` pour ce qui ne se lit pas.
fn etat() -> (Option<bool>, Option<bool>) {
    let booleen = |l: &Ligne, champ: &str| match l.get(champ) {
        Some(Valeur::Booleen(b)) => Some(*b),
        _ => None,
    };
    wmi::requete(ESPACE, ETAT, "", &["RealTimeProtectionEnabled", "IsTamperProtected"])
        .and_then(|l| l.into_iter().next())
        .map_or((None, None), |l| {
            (
                booleen(&l, "RealTimeProtectionEnabled"),
                booleen(&l, "IsTamperProtected"),
            )
        })
}

/// Pourquoi Windows a gardé la valeur : la protection contre les falsifications si elle est active (elle ignore la
/// demande sans erreur), sinon une stratégie de groupe ou un autre antivirus.
fn pourquoi_garde() -> String {
    match etat().1 {
        Some(true) => tr!(
            "Windows a gardé la valeur : la protection contre les falsifications l'empêche (Sécurité Windows > Protection contre les virus et menaces > Gérer les paramètres)",
            "Windows kept the value: tamper protection prevents it (Windows Security > Virus & threat protection > Manage settings)"
        )
        .to_string(),
        _ => tr!(
            "Windows a gardé la valeur : une stratégie de groupe, une gestion d'entreprise ou un autre antivirus l'impose",
            "Windows kept the value: a group policy, enterprise management or another antivirus enforces it"
        )
        .to_string(),
    }
}

/// Le contexte des échecs d'écriture de Defender, stable pour le journal des erreurs.
const CONTEXTE: &str = "defender/ecriture";

/// Appelle la méthode statique de `classe` ; `Err` : le refus de Windows, sa phrase prête à montrer.
fn appeler(classe: &str, methode: &str, parametres: Vec<(&'static str, gestes::ValeurWmi)>) -> Result<(), Echec> {
    let parametres = parametres.into_iter().map(|(n, v)| (n, Parametre::from(v))).collect();
    match wmi::methode(ESPACE, classe, methode, parametres, DELAI) {
        Retour::Valeur(0) => Ok(()),
        Retour::Valeur(n) => Err(Echec::echoue(
            CONTEXTE,
            match u32::try_from(n) {
                Ok(code) => trf!(
                    "Windows a refusé la demande (code 0x{:08X})",
                    "Windows refused the request (code 0x{:08X})",
                    code
                ),
                Err(_) => trf!("Windows a répondu {n}", "Windows answered {n}"),
            },
        )),
        Retour::Refuse(code) if CLASSE_ABSENTE.contains(&code) => Err(Echec::echoue(
            CONTEXTE,
            trf!(
                "Defender ne répond pas par WMI (code 0x{:08X}) : coupé, ou remplacé par un autre antivirus ?",
                "Defender does not answer through WMI (code 0x{:08X}): off, or replaced by another antivirus?",
                code
            ),
        )),
        Retour::Refuse(code) => Err(Echec::echoue(
            CONTEXTE,
            trf!(
                "Windows a refusé la demande (code 0x{:08X})",
                "Windows refused the request (code 0x{:08X})",
                code
            ),
        )),
        Retour::SansReponse => Err(Echec::echoue(
            CONTEXTE,
            tr!("Defender n'a pas répondu à temps", "Defender did not answer in time"),
        )),
    }
}

/// L'appel de MSFT_MpPreference que décrit `gestes::methode_defender` pour cet acte.
fn appeler_preferences(acte: &Acte) -> Result<(), Echec> {
    let Some((methode, parametres)) = gestes::methode_defender(acte) else {
        return Err(Echec::refuse(
            CONTEXTE,
            tr!("acte de Defender non reconnu", "Defender act not recognized"),
        ));
    };
    appeler(PREFERENCES, methode, parametres)
}

fn illisible() -> Resultat {
    Resultat::echec(
        None,
        tr!(
            "réglages de Defender illisibles (WMI), rien d'écrit",
            "Defender settings unreadable (WMI), nothing written"
        )
        .to_string(),
    )
}

/// La protection en temps réel remise en marche (DisableRealtimeMonitoring à faux), jugée sur ce que Defender
/// applique (RealTimeProtectionEnabled), relu jusqu'à 5 s après l'écriture.
fn temps_reel(acte: &Acte) -> Resultat {
    const PROP: &str = "DisableRealtimeMonitoring";
    if etat().0 == Some(true) {
        return Resultat::rien(
            tr!(
                "la protection en temps réel est déjà en marche, rien d'écrit",
                "real-time protection is already on, nothing written"
            )
            .to_string(),
        );
    }
    let Some(lue) = preferences(&[PROP]).and_then(|l| l.get(PROP).and_then(entier)) else {
        return illisible();
    };
    let avant = avant_notable(&format!("{PROP}={lue}"));
    if !ReglageDefender::TempsReel.a_ecrire(ValeurDefender::Actif, lue) {
        // Le réglage dit « en marche » et Defender ne l'applique pas : l'écrire de nouveau ne changerait rien.
        return Resultat::echec(
            Some(avant),
            tr!(
                "le réglage est déjà en marche, mais Defender ne l'applique pas : une stratégie de groupe ou un autre antivirus la coupe",
                "the setting is already on, but Defender does not apply it: a group policy or another antivirus turns it off"
            )
            .to_string(),
        );
    }
    if let Err(r) = appeler_preferences(acte) {
        return Resultat::echec(Some(avant), r.to_string());
    }
    for _ in 0..RELECTURES {
        std::thread::sleep(PAUSE);
        if etat().0 == Some(true) {
            return Resultat::fait(avant);
        }
    }
    let relue = preferences(&[PROP]).and_then(|l| l.get(PROP).and_then(entier));
    Resultat::echec(
        Some(avant),
        match relue {
            Some(0) => tr!(
                "réglage écrit, mais la protection en temps réel n'est pas repartie (relue après 5 s)",
                "setting written, but real-time protection has not started again (read back after 5 s)"
            )
            .to_string(),
            Some(_) => pourquoi_garde(),
            None => tr!(
                "réglage relu illisible après l'écriture : rien n'est compté comme fait",
                "setting unreadable after writing: nothing is counted as done"
            )
            .to_string(),
        },
    )
}

/// Un réglage (cloud, accès contrôlé aux dossiers, protection réseau, PUA) mis à une valeur plus sûre, jamais
/// baissé : rien n'est écrit si la valeur lue protège déjà autant (`ReglageDefender::a_ecrire`).
fn reglage(r: ReglageDefender, v: ValeurDefender, acte: &Acte) -> Resultat {
    let prop = r.propriete();
    let lire = || preferences(&[prop]).and_then(|l| l.get(prop).and_then(entier));
    let Some(lue) = lire() else {
        return illisible();
    };
    let avant = avant_notable(&format!("{prop}={lue}"));
    if !r.a_ecrire(v, lue) {
        return Resultat::rien(trf!(
            "déjà réglé ({prop} = {lue}), rien d'écrit",
            "already set ({prop} = {lue}), nothing written"
        ));
    }
    if let Err(raison) = appeler_preferences(acte) {
        return Resultat::echec(Some(avant), raison.to_string());
    }
    match lire() {
        Some(relue) if !r.a_ecrire(v, relue) => Resultat::fait(avant),
        Some(_) => Resultat::echec(Some(avant), pourquoi_garde()),
        None => Resultat::echec(
            Some(avant),
            tr!(
                "réglage relu illisible après l'écriture : rien n'est compté comme fait",
                "setting unreadable after writing: nothing is counted as done"
            )
            .to_string(),
        ),
    }
}

/// Ce que dit la liste ASR de Defender pour une règle : illisible (Defender muet, liste cachée « N/A… »), ou lue,
/// avec l'action de la règle (`None` si elle n'y est pas).
enum LectureAsr {
    Illisible,
    Lue(Option<i64>),
}

/// L'action d'une règle ASR dans la liste de Defender. Les identifiants se comparent sans casse (Defender garde celle
/// de qui l'a ajoutée).
fn action_asr(id: &str) -> LectureAsr {
    let Some(l) = preferences(&[IDS_ASR, ACTIONS_ASR]) else {
        return LectureAsr::Illisible;
    };
    let ids = l.get(IDS_ASR).map(Valeur::textes).unwrap_or_default();
    // Un élément qui n'est pas un texte décalerait les règles par rapport à leurs actions (`textes` l'écarte) :
    // illisible, plutôt que l'action d'une autre règle.
    let decalee = matches!(l.get(IDS_ASR), Some(Valeur::Liste(v)) if v.len() != ids.len());
    if decalee || ids.iter().any(|x| x.starts_with("N/A")) {
        return LectureAsr::Illisible;
    }
    let actions = l.get(ACTIONS_ASR).map(Valeur::liste).unwrap_or_default();
    LectureAsr::Lue(
        ids.iter()
            .position(|x| x.eq_ignore_ascii_case(id))
            // Une action manquante n'est pas crue « bloque » : 0, la moins sûre.
            .map(|i| actions.get(i).and_then(entier).unwrap_or(0)),
    )
}

/// Une règle ASR des listes d'Optimiser mise en blocage ou en audit (jamais baissée).
fn regle_asr(id: &str, m: ModeAsr, acte: &Acte) -> Resultat {
    let LectureAsr::Lue(lue) = action_asr(id) else {
        return illisible();
    };
    let avant = avant_notable(&format!(
        "{id}={}",
        lue.map_or_else(|| "absente".to_string(), |a| a.to_string())
    ));
    if !m.a_ecrire(lue) {
        return Resultat::rien(
            tr!(
                "règle déjà réglée au moins ainsi, rien d'écrit",
                "rule already set at least this way, nothing written"
            )
            .to_string(),
        );
    }
    if let Err(r) = appeler_preferences(acte) {
        return Resultat::echec(Some(avant), r.to_string());
    }
    match action_asr(id) {
        LectureAsr::Lue(relue) if !m.a_ecrire(relue) => Resultat::fait(avant),
        LectureAsr::Lue(_) => Resultat::echec(Some(avant), pourquoi_garde()),
        LectureAsr::Illisible => Resultat::echec(
            Some(avant),
            tr!(
                "règles relues illisibles après l'écriture : rien n'est compté comme fait",
                "rules unreadable after writing: nothing is counted as done"
            )
            .to_string(),
        ),
    }
}

/// La liste relue d'un genre d'exclusion (chemins, processus, extensions, dans l'ordre de `lecture_wmi`).
fn du_genre(listes: &[Vec<String>; 3], g: GenreExclusion) -> &[String] {
    let [chemins, processus, extensions] = listes;
    match g {
        GenreExclusion::Chemin => chemins,
        GenreExclusion::Processus => processus,
        GenreExclusion::Extension => extensions,
    }
}

/// Le motif de refus d'une exclusion à retirer, d'après les listes relues : `None` si elle peut partir. Pure, pour
/// l'essayer : la liste se lit (ni cachée « N/A… », ni masquée par une politique, qui peut la rendre vide),
/// l'exclusion y est telle quelle, et le bilan la signale (`exclusions::signalee`, la règle du constat).
fn refus_exclusion(
    listes: &[Vec<String>; 3],
    cachees_par_politique: bool,
    g: GenreExclusion,
    valeur: &str,
) -> Option<String> {
    if exclusions::cachee(listes) || cachees_par_politique {
        return Some(
            tr!(
                "les exclusions de Defender sont cachées, rien retiré",
                "Defender exclusions are hidden, nothing removed"
            )
            .to_string(),
        );
    }
    if !du_genre(listes, g).iter().any(|x| x == valeur) {
        return Some(
            tr!(
                "cette exclusion n'est pas dans la liste relue de Defender, rien retiré",
                "this exclusion is not in Defender's list read back, nothing removed"
            )
            .to_string(),
        );
    }
    if !exclusions::signalee(g, valeur) {
        return Some(
            tr!(
                "le bilan ne signale pas cette exclusion : refusée, rien retiré",
                "the scan does not report this exclusion: refused, nothing removed"
            )
            .to_string(),
        );
    }
    None
}

/// Une exclusion signalée par le bilan, retirée par MSFT_MpPreference.Remove, puis cherchée de nouveau.
fn retirer_exclusion(g: GenreExclusion, valeur: &str, acte: &Acte) -> Resultat {
    let Some((listes, politiques)) = exclusions::lecture_wmi() else {
        return illisible();
    };
    if let Some(r) = refus_exclusion(&listes, politiques.aux_admins, g, valeur) {
        return Resultat::echec(None, r);
    }
    let avant = avant_notable(&format!("{}={valeur}", g.propriete()));
    if let Err(r) = appeler_preferences(acte) {
        return Resultat::echec(Some(avant), r.to_string());
    }
    match exclusions::lecture_wmi() {
        // Cachée par une politique à la relecture, la liste peut revenir vide : jamais prise pour un retrait.
        Some((apres, politiques)) if exclusions::cachee(&apres) || politiques.aux_admins => Resultat::echec(
            Some(avant),
            tr!(
                "exclusions cachées à la relecture : rien n'est compté comme fait",
                "exclusions hidden when read back: nothing is counted as done"
            )
            .to_string(),
        ),
        Some((apres, _)) if !du_genre(&apres, g).iter().any(|x| x == valeur) => Resultat::fait(avant),
        Some(_) => Resultat::echec(Some(avant), pourquoi_garde()),
        None => Resultat::echec(
            Some(avant),
            tr!(
                "exclusions relues illisibles après le retrait : rien n'est compté comme fait",
                "exclusions unreadable after removal: nothing is counted as done"
            )
            .to_string(),
        ),
    }
}

/// Le nombre de menaces actives que Defender connaît (MSFT_MpThreat, IsActive) ; une menace dont l'état ne se lit
/// pas compte comme active. `None` si la liste ne se lit pas.
fn menaces_actives() -> Option<usize> {
    let lignes = wmi::requete(ESPACE, MENACES, "", &["ThreatID", "IsActive"])?;
    Some(
        lignes
            .iter()
            .filter(|l| !matches!(l.get("IsActive"), Some(Valeur::Booleen(false))))
            .count(),
    )
}

/// Les menaces actives retirées (MSFT_MpThreat.Remove, ce que fait la commande de Defender qui les retire), puis
/// recomptées : il n'en reste aucune, ou c'est un échec.
fn retirer_menaces() -> Resultat {
    let Some(avant) = menaces_actives() else {
        return Resultat::echec(
            None,
            tr!(
                "menaces de Defender illisibles (WMI), rien retiré",
                "Defender threats unreadable (WMI), nothing removed"
            )
            .to_string(),
        );
    };
    if avant == 0 {
        return Resultat::rien(
            tr!(
                "aucune menace active dans Defender, rien retiré",
                "no active threat in Defender, nothing removed"
            )
            .to_string(),
        );
    }
    let note = avant_notable(&trf!("{avant} menace(s) active(s)", "{avant} active threat(s)"));
    if let Err(r) = appeler(MENACES, "Remove", Vec::new()) {
        return Resultat::echec(Some(note), r.to_string());
    }
    match menaces_actives() {
        Some(0) => Resultat::fait(note),
        Some(n) => Resultat::echec(
            Some(note),
            trf!(
                "il reste {n} menace(s) active(s) après le retrait",
                "{n} active threat(s) remain after the removal"
            ),
        ),
        None => Resultat::echec(
            Some(note),
            tr!(
                "menaces relues illisibles après le retrait : rien n'est compté comme fait",
                "threats unreadable after removal: nothing is counted as done"
            )
            .to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(l: &[&str]) -> Vec<String> {
        l.iter().map(|s| (*s).to_string()).collect()
    }

    /// La ligne forgée qui désigne une exclusion ordinaire, absente, ou dans une liste cachée : refusée avant tout
    /// appel à Defender.
    #[test]
    fn exclusion_rejugee() {
        let listes = [v(&["C:\\", "D:\\Jeux"]), v(&["jeu.exe"]), v(&[".exe"])];
        assert_eq!(refus_exclusion(&listes, false, GenreExclusion::Chemin, "C:\\"), None);
        assert_eq!(refus_exclusion(&listes, false, GenreExclusion::Extension, ".exe"), None);
        // Présente mais ordinaire : le bilan ne la signale pas.
        assert!(refus_exclusion(&listes, false, GenreExclusion::Chemin, "D:\\Jeux").is_some());
        assert!(refus_exclusion(&listes, false, GenreExclusion::Processus, "jeu.exe").is_some());
        // Signalable mais absente, ou dans une autre liste que celle de son genre.
        assert!(refus_exclusion(&listes, false, GenreExclusion::Chemin, "C:\\Users").is_some());
        assert!(refus_exclusion(&listes, false, GenreExclusion::Processus, ".exe").is_some());
        // Comparée telle quelle : une autre casse n'est pas celle que Defender garde.
        assert!(refus_exclusion(&listes, false, GenreExclusion::Extension, ".EXE").is_some());
        // Liste cachée, par « N/A » ou par une politique.
        let cachees = [
            v(&["N/A: Must be an administrator to view exclusions"]),
            v(&[]),
            v(&[".exe"]),
        ];
        assert!(refus_exclusion(&cachees, false, GenreExclusion::Extension, ".exe").is_some());
        assert!(refus_exclusion(&listes, true, GenreExclusion::Chemin, "C:\\").is_some());
    }

    /// Sous Wine, Defender n'existe pas : chaque acte est un échec dit (illisible), jamais un « fait ». Sur un vrai
    /// Windows, ces actes changeraient Defender : sauté hors de Wine.
    #[test]
    fn sans_defender_jamais_vert() {
        if !crate::commande::sous_wine() {
            return crate::essais::saute("change Defender sur un vrai Windows");
        }
        let actes = [
            gestes::ligne_defender(ReglageDefender::TempsReel, ValeurDefender::Actif),
            gestes::ligne_defender(ReglageDefender::Pua, ValeurDefender::Bloquer),
            gestes::ligne_defender_asr(gestes::ASR_BASE[0], ModeAsr::Bloquer),
            gestes::ligne_defender_exclusion_retirer(GenreExclusion::Chemin, "C:\\"),
            Some(gestes::ligne_defender_menaces_retirer()),
        ];
        for ligne in actes.into_iter().map(Option::unwrap) {
            let acte = gestes::analyser_acte(&ligne).unwrap();
            let r = faire_acte(&acte).unwrap();
            assert!(!r.reussi && !r.raison.is_empty(), "{ligne}");
        }
        assert!(faire_acte(&gestes::analyser_acte("vanguard:service SSDPSRV arreter").unwrap()).is_none());
    }
}

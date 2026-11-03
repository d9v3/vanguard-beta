//! Les gestes SSH du processus élevé (défense D6c), en code pur : réserver les droits d'un fichier SSH
//! (administrators_authorized_keys, une clé privée) et mettre un réglage de sshd_config à « no ».
//!
//! Les droits : la liste d'avant (DACL, en SDDL) est notée sous ChoixAvant avant d'écrire, relue, puis la liste voulue
//! posée et relue ; la remise ne pose la liste d'avant que si la liste est encore celle que Vanguard a posée. Le
//! contenu du fichier n'est jamais touché. Une liste d'avant trop longue pour une note : question « non annulable »,
//! non par défaut.
//!
//! sshd_config : la nouvelle version (le réglage à « no » en tête, avant tout `Match` et tout `Include`) est écrite à
//! côté, éprouvée par `sshd -t` AVANT de remplacer quoi que ce soit, puis l'ancienne est gardée en copie par le
//! remplacement lui-même ; la note garde le nom de la copie et les empreintes d'avant et d'après. sshd n'est redémarré
//! que sans session SSH en cours (`relance`) ; PasswordAuthentication n'est jamais coupé pendant une session SSH, sans
//! même poser la question (`accord_mots_de_passe`).
//!
//! Tout passe par deux traits, `Fichier` et `Config` : Windows dans `ssh_ecriture`, des faux dans les essais, si bien
//! que chaque garde s'essaie sous Linux.

use sha2::{Digest, Sha256};

use crate::machine::gestes::{CibleSsh, ReglageSshd};
use crate::machine::reglages::{self, Brute, Issue};
use crate::modele::raison::Echec;
use crate::ui::{tr, trf};

/// Le type d'une valeur de note qui garde du texte (REG_BINARY : les octets tels quels).
const TEXTE: u32 = 3;
/// Le début du nom de la copie d'avant de sshd_config, dans le même dossier.
pub(crate) const PREFIXE_COPIE: &str = "sshd_config.vanguard-";

// ------------------------------------------------------------------------------------------------ noms des notes

/// Le nom de la note des droits d'un fichier SSH : « ssh-cles-admin », ou « ssh-cle- » puis les 16 premiers chiffres
/// de l'empreinte du SID et du nom de la clé (chaque compte la sienne). `None` : une clé sans SID valide.
pub(crate) fn nom_note_droits(c: &CibleSsh, sid: Option<&str>) -> Option<String> {
    match c {
        CibleSsh::ClesAdmin => Some("ssh-cles-admin".to_string()),
        CibleSsh::Cle(n) => {
            let sid = sid.filter(|s| reglages::sid_valide(s))?;
            let e = Sha256::digest(format!("{sid}\\{}", n.texte()).to_lowercase().as_bytes());
            Some(format!("ssh-cle-{}", hex(e.get(..8)?)))
        }
    }
}

/// Le nom de la note d'un réglage de sshd_config : `sshd-<mot>`.
pub(crate) fn nom_note_sshd(r: ReglageSshd) -> String {
    format!("sshd-{}", r.mot())
}

fn hex(octets: &[u8]) -> String {
    octets.iter().fold(String::with_capacity(octets.len() * 2), |mut s, o| {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{o:02x}"));
        s
    })
}

/// L'empreinte SHA-256 en hexadécimal minuscule.
pub(crate) fn empreinte(octets: &[u8]) -> String {
    hex(&Sha256::digest(octets))
}

// ------------------------------------------------------------------------------------------------ listes des droits

/// Ce qui compte d'une liste des droits en SDDL (« D:PAI(A;;FA;;;SY)… ») : protégée ou non de l'héritage, nulle (tout
/// le monde a tout), et ses règles posées sur le fichier lui-même (sans « ID », les héritées viennent du dossier).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Explicites {
    pub(crate) protegee: bool,
    pub(crate) nulle: bool,
    /// Les règles telles qu'écrites, dans leur ordre.
    pub(crate) regles: Vec<String>,
    /// Porte-t-elle des règles héritées du dossier (hors de la comparaison : Windows les recalcule) ?
    pub(crate) heritees: bool,
}

impl Explicites {
    /// Les règles en majuscules, triées : la forme comparée.
    fn cle(&self) -> (bool, bool, Vec<String>) {
        let mut r: Vec<String> = self.regles.iter().map(|x| x.to_ascii_uppercase()).collect();
        r.sort();
        (self.protegee, self.nulle, r)
    }

    /// La liste à poser : les règles posées sur le fichier, protégée ou non (les héritées, Windows les recalcule).
    pub(crate) fn a_poser(&self) -> String {
        if self.nulle {
            return "D:NO_ACCESS_CONTROL".to_string();
        }
        format!("D:{}{}", if self.protegee { "P" } else { "" }, self.regles.concat())
    }
}

/// Lit la partie « D: » d'un SDDL ; `None` : pas une liste des droits (ou une parenthèse qui ne se ferme pas).
pub(crate) fn explicites(sddl: &str) -> Option<Explicites> {
    let reste = sddl.trim().strip_prefix("D:")?;
    let debut = reste.find('(').unwrap_or(reste.len());
    let (drapeaux, mut regles_texte) = reste.split_at(debut);
    if drapeaux.contains("NO_ACCESS_CONTROL") {
        return Some(Explicites {
            protegee: false,
            nulle: true,
            regles: Vec::new(),
            heritees: false,
        });
    }
    if !drapeaux.chars().all(|c| matches!(c, 'P' | 'A' | 'I' | 'R')) {
        return None;
    }
    let mut regles = Vec::new();
    let mut heritees = false;
    while !regles_texte.is_empty() {
        // Une règle : « ( … ) », les parenthèses d'une condition comprises.
        if !regles_texte.starts_with('(') {
            return None;
        }
        let mut profondeur = 0usize;
        let mut fin = None;
        for (i, c) in regles_texte.char_indices() {
            match c {
                '(' => profondeur += 1,
                ')' => {
                    profondeur = profondeur.checked_sub(1)?;
                    if profondeur == 0 {
                        fin = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let fin = fin?;
        let regle = regles_texte.get(..=fin)?;
        regles_texte = regles_texte.get(fin + 1..)?;
        // Le deuxième champ : les drapeaux d'héritage, par paires de lettres (« OICIID »).
        let heritee = regle
            .trim_start_matches('(')
            .split(';')
            .nth(1)
            .is_some_and(|d| d.as_bytes().chunks(2).any(|p| p.eq_ignore_ascii_case(b"ID")));
        if heritee {
            heritees = true;
        } else {
            regles.push(regle.to_string());
        }
    }
    Some(Explicites {
        protegee: drapeaux.contains('P'),
        nulle: false,
        regles,
        heritees,
    })
}

/// Deux listes ont-elles les mêmes règles posées sur le fichier et la même protection ? Illisible : non.
pub(crate) fn memes_droits(a: &str, b: &str) -> bool {
    match (explicites(a), explicites(b)) {
        (Some(x), Some(y)) => x.cle() == y.cle(),
        _ => false,
    }
}

/// La liste `lu` est-elle bien `avant` remise : mêmes règles posées et même protection, et les règles héritées du
/// dossier revenues si `avant` en avait (une liste qui ne reprend pas l'héritage n'est pas celle d'avant).
pub(crate) fn remise(lu: &str, avant: &str) -> bool {
    memes_droits(lu, avant)
        && match (explicites(lu), explicites(avant)) {
            (Some(l), Some(a)) => !a.heritees || l.heritees,
            _ => false,
        }
}

/// La liste voulue : SYSTEM et les administrateurs, plus le compte de la personne pour une clé privée, sans héritage.
/// `None` : un SID qui n'en a pas la forme.
pub(crate) fn voulu(sid: Option<&str>) -> Option<String> {
    const BASE: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";
    match sid {
        None => Some(BASE.to_string()),
        Some(s) if reglages::sid_valide(s) => Some(format!("{BASE}(A;;FA;;;{s})")),
        Some(_) => None,
    }
}

/// Le fichier dont les droits changent : sa poignée ouverte sous Windows, un faux dans les essais.
pub(crate) trait Fichier {
    /// La liste des droits en SDDL (« D:… ») ; `None` : illisible.
    fn lire(&mut self) -> Option<String>;
    /// Pose cette liste (protégée si elle porte « P »).
    fn poser(&mut self, sddl: &str) -> Result<(), Echec>;
    fn lire_note(&mut self, nom: &str) -> Option<Vec<u8>>;
    fn ecrire_note(&mut self, nom: &str, octets: &[u8]) -> Result<(), Echec>;
    fn effacer_note(&mut self, nom: &str);
}

fn echec(avant: Option<String>, raison: impl Into<String>) -> Issue {
    Issue::Echec {
        avant,
        raison: raison.into(),
    }
}

fn brute_texte(t: &str) -> Brute {
    Brute {
        code: TEXTE,
        octets: t.as_bytes().to_vec(),
    }
}

fn lire_texte(b: Option<&Brute>) -> Option<String> {
    let b = b?;
    (b.code == TEXTE).then(|| String::from_utf8(b.octets.clone()).ok())?
}

/// Remet la liste d'avant après une pose ratée ; vrai si elle se relit ainsi.
fn revenir(f: &mut impl Fichier, avant: &str) -> bool {
    if f.lire().is_some_and(|l| remise(&l, avant)) {
        return true;
    }
    let Some(e) = explicites(avant) else {
        return false;
    };
    f.poser(&e.a_poser()).is_ok() && f.lire().is_some_and(|l| remise(&l, avant))
}

fn texte_revenu(revenu: bool) -> &'static str {
    if revenu {
        tr!(
            "la liste des droits d'avant est remise",
            "the previous list of rights is put back"
        )
    } else {
        tr!(
            "ATTENTION : la liste des droits d'avant ne se remet pas, la note est gardée ; vérifiez les droits de ce fichier",
            "WARNING: the previous list of rights cannot be put back, the note is kept; check the rights of this file"
        )
    }
}

/// Réserve le fichier : la liste d'avant notée (relue), puis `voulu` posée et relue ; à la moindre erreur après la
/// note, la liste d'avant est remise (la note effacée seulement si elle se relit remise). Une liste d'avant trop
/// longue pour une note : `confirmer_sans_note` (question « non annulable », non par défaut) ou rien.
pub(crate) fn reserver(
    f: &mut impl Fichier,
    nom: &str,
    voulu: &str,
    confirmer_sans_note: impl FnOnce() -> bool,
) -> Issue {
    let Some(avant) = f.lire() else {
        return echec(
            None,
            tr!(
                "la liste des droits ne se lit pas : rien d'écrit",
                "the list of rights cannot be read: nothing written"
            ),
        );
    };
    if explicites(&avant).is_none() {
        return echec(
            Some(avant),
            tr!(
                "la liste des droits a une forme inattendue : rien d'écrit",
                "the list of rights has an unexpected form: nothing written"
            ),
        );
    }
    if memes_droits(&avant, voulu) {
        return Issue::Rien(avant);
    }
    let annulable = match noter(f, nom, &[("avant", &avant), ("ecrit", voulu)]) {
        Ok(n) => n,
        Err(raison) => return echec(Some(avant), raison),
    };
    if !annulable && !confirmer_sans_note() {
        return echec(
            Some(avant),
            tr!("non confirmé : rien d'écrit", "not confirmed: nothing written"),
        );
    }
    // Relue juste avant d'écrire : changée depuis la note, rien n'est écrit.
    if f.lire().is_none_or(|l| l != avant) {
        f.effacer_note(nom);
        return echec(
            Some(avant),
            tr!(
                "la liste des droits a changé pendant le geste : rien d'écrit",
                "the list of rights changed during the action: nothing written"
            ),
        );
    }
    let raison = match f.poser(voulu) {
        Ok(()) if f.lire().is_some_and(|l| memes_droits(&l, voulu)) => return Issue::Fait { avant },
        Ok(()) => tr!(
            "la liste relue n'est pas celle posée",
            "the list read back is not the one set"
        )
        .to_string(),
        Err(e) => trf!(
            "la liste des droits ne se pose pas ({e})",
            "the list of rights cannot be set ({e})"
        ),
    };
    let revenu = revenir(f, &avant);
    if revenu {
        f.effacer_note(nom);
    }
    echec(Some(avant), format!("{raison} ; {}", texte_revenu(revenu)))
}

/// Note `valeurs` sous `nom`, et la relit. `Ok(false)` : trop longue pour une note (rien n'est noté).
fn noter(f: &mut impl Fichier, nom: &str, valeurs: &[(&str, &str)]) -> Result<bool, Echec> {
    let brutes: Vec<(&str, Brute)> = valeurs.iter().map(|(n, v)| (*n, brute_texte(v))).collect();
    let refs: Vec<(&str, Option<&Brute>)> = brutes.iter().map(|(n, b)| (*n, Some(b))).collect();
    let Some(octets) = reglages::coder(nom, &refs) else {
        return Ok(false);
    };
    f.ecrire_note(nom, &octets).map_err(|e| {
        Echec::echoue(
            "ssh/noter",
            trf!(
                "la valeur d'avant ne se note pas ({e}) : rien d'écrit",
                "the previous value cannot be noted ({e}): nothing written"
            ),
        )
    })?;
    if f.lire_note(nom).as_deref() != Some(octets.as_slice()) {
        f.effacer_note(nom);
        return Err(Echec::echoue(
            "ssh/noter",
            tr!(
                "la note ne se relit pas : rien d'écrit",
                "the note cannot be read back: nothing written"
            ),
        ));
    }
    Ok(true)
}

/// La liste d'avant et la liste posée qu'une note garde ; `None` : pas de note, ou abîmée.
pub(crate) fn note_droits(octets: &[u8], nom: &str) -> Option<(String, String)> {
    let v = reglages::decoder(octets, nom, &["avant", "ecrit"])?;
    let avant = lire_texte(v.first()?.as_ref())?;
    let ecrit = lire_texte(v.get(1)?.as_ref())?;
    (explicites(&avant).is_some() && explicites(&ecrit).is_some()).then_some((avant, ecrit))
}

/// Remet la liste d'avant notée, si et seulement si la liste est encore celle que Vanguard a posée ; la note est
/// effacée une fois la liste d'avant relue (règles posées sur le fichier et protection : les héritées viennent du
/// dossier, tel qu'il est aujourd'hui).
pub(crate) fn remettre_droits(f: &mut impl Fichier, nom: &str) -> Issue {
    let Some((avant, ecrit)) = f.lire_note(nom).and_then(|o| note_droits(&o, nom)) else {
        return echec(
            None,
            tr!(
                "aucune liste des droits d'avant notée par Vanguard pour ce fichier (ou note abîmée) : rien d'écrit",
                "no previous list of rights noted by Vanguard for this file (or damaged note): nothing written"
            ),
        );
    };
    let Some(lu) = f.lire() else {
        return echec(
            None,
            tr!(
                "la liste des droits ne se lit pas : rien d'écrit",
                "the list of rights cannot be read: nothing written"
            ),
        );
    };
    if memes_droits(&lu, &avant) {
        f.effacer_note(nom);
        return Issue::Rien(lu);
    }
    if !memes_droits(&lu, &ecrit) {
        return echec(
            Some(lu),
            tr!(
                "la liste des droits a changé depuis que Vanguard l'a posée : Vanguard n'écrit jamais par-dessus ; rien d'écrit",
                "the list of rights has changed since Vanguard set it: Vanguard never writes over it; nothing written"
            ),
        );
    }
    let Some(a_poser) = explicites(&avant).map(|e| e.a_poser()) else {
        return echec(
            Some(lu),
            tr!("note abîmée : rien d'écrit", "damaged note: nothing written"),
        );
    };
    let raison = match f.poser(&a_poser) {
        Ok(()) if f.lire().is_some_and(|l| remise(&l, &avant)) => {
            f.effacer_note(nom);
            return Issue::Fait { avant: lu };
        }
        Ok(()) => tr!(
            "la liste relue n'est pas celle notée",
            "the list read back is not the noted one"
        )
        .to_string(),
        Err(e) => trf!(
            "la liste des droits ne se pose pas ({e})",
            "the list of rights cannot be set ({e})"
        ),
    };
    // La liste posée par Vanguard revient : la remise pourra être refaite, la note est gardée.
    let revenu = f.lire().is_some_and(|l| memes_droits(&l, &ecrit))
        || (f.poser(&ecrit).is_ok() && f.lire().is_some_and(|l| memes_droits(&l, &ecrit)));
    echec(
        Some(lu),
        if revenu {
            trf!(
                "{raison} ; la liste posée par Vanguard est remise, la note est gardée",
                "{raison}; the list set by Vanguard is put back, the note is kept"
            )
        } else {
            trf!(
                "{raison} ; ATTENTION : vérifiez les droits de ce fichier, la note est gardée",
                "{raison}; WARNING: check the rights of this file, the note is kept"
            )
        },
    )
}

// ------------------------------------------------------------------------------------------------ sshd_config

/// Le réglage `r` est-il encore à corriger dans cette configuration (partie globale, comme le bilan) ?
pub(crate) fn signale(r: ReglageSshd, texte: &str) -> bool {
    let conf = crate::machine::sshd::partie_globale_sshd(texte);
    match r {
        ReglageSshd::MotsDePasseVides => crate::machine::sshd::mots_de_passe_vides_sshd(&conf),
        ReglageSshd::MotsDePasse => crate::machine::sshd::mots_de_passe_sshd(&conf),
    }
}

/// La configuration avec « `<mot-clé> no` » en tête (après l'indicateur d'ordre des octets s'il y en a un), précédé
/// d'un commentaire ASCII : sshd garde la première valeur lue, avant tout `Match` et tout `Include`. Les fins de
/// ligne suivent celles du fichier (CRLF ou LF).
pub(crate) fn avec_reglage(octets: &[u8], r: ReglageSshd) -> Vec<u8> {
    const BOM: &[u8] = b"\xEF\xBB\xBF";
    let (bom, corps) = match octets.strip_prefix(BOM) {
        Some(c) => (BOM, c),
        None => (&[][..], octets),
    };
    let fin: &[u8] = if corps.windows(2).any(|w| w == b"\r\n") {
        b"\r\n"
    } else {
        b"\n"
    };
    let mut n = Vec::with_capacity(octets.len() + 160);
    n.extend_from_slice(bom);
    n.extend_from_slice(
        format!(
            "# Vanguard: {} no (undo: vanguard options-defense --remettre sshd:{})",
            r.mot_cle(),
            r.mot()
        )
        .as_bytes(),
    );
    n.extend_from_slice(fin);
    n.extend_from_slice(format!("{} no", r.mot_cle()).as_bytes());
    n.extend_from_slice(fin);
    n.extend_from_slice(corps);
    n
}

/// Les ports où sshd écoute, d'après la partie globale (`Port`, plusieurs permis ; 22 sans rien), pour reconnaître
/// une session SSH entrante.
pub(crate) fn ports_sshd(texte: &str) -> Vec<u16> {
    let conf = crate::machine::sshd::partie_globale_sshd(texte);
    let mut ports: Vec<u16> = conf
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let (k, v) = l.split_once(|c: char| c.is_whitespace() || c == '=')?;
            k.eq_ignore_ascii_case("port")
                .then(|| v.trim().trim_start_matches('=').trim().parse::<u16>().ok())?
        })
        .collect();
    // ListenAddress « adresse:port » ouvre aussi un port.
    ports.extend(conf.lines().map(str::trim).filter_map(|l| {
        let (k, v) = l.split_once(|c: char| c.is_whitespace() || c == '=')?;
        if !k.eq_ignore_ascii_case("listenaddress") {
            return None;
        }
        let v = v.trim().trim_start_matches('=').trim();
        let (_, port) = v.rsplit_once(':')?;
        // « ::1 » sans crochets : pas un port.
        (v.starts_with('[') || v.matches(':').count() == 1)
            .then(|| port.parse::<u16>().ok())
            .flatten()
    }));
    if ports.is_empty() {
        ports.push(22);
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Ce qui suit l'écriture de sshd_config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Relance {
    /// En marche, aucune session SSH : redémarré maintenant.
    Redemarrer,
    /// Une session SSH en cours, ou l'état qui ne se lit pas : au prochain redémarrage de sshd.
    AuProchain,
    /// Arrêté : la configuration vaudra à son prochain démarrage.
    Arrete,
}

/// sshd ne redémarre que s'il tourne et qu'aucune session SSH n'est en cours ; une session illisible compte comme une
/// session (Vanguard ne coupe jamais une session à distance).
pub(crate) fn relance(en_marche: Option<bool>, session: Option<bool>) -> Relance {
    match (en_marche, session) {
        (Some(false), _) => Relance::Arrete,
        (Some(true), Some(false)) => Relance::Redemarrer,
        _ => Relance::AuProchain,
    }
}

/// L'accord pour couper PasswordAuthentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AccordMdp {
    /// Une session SSH en cours (ou illisible) : refusé sans question.
    RefusSession,
    NonConfirme,
    Oui,
}

/// Jamais pendant une session SSH (elle peut avoir été ouverte par mot de passe) : refusé SANS poser la question ;
/// sinon la question « Une clé est-elle déjà posée pour votre compte ? », non par défaut.
pub(crate) fn accord_mots_de_passe(session: Option<bool>, demander: impl FnOnce() -> bool) -> AccordMdp {
    if session != Some(false) {
        return AccordMdp::RefusSession;
    }
    if demander() {
        AccordMdp::Oui
    } else {
        AccordMdp::NonConfirme
    }
}

/// sshd_config et son dossier : Windows dans `ssh_ecriture`, un faux dans les essais.
pub(crate) trait Config {
    /// sshd_config tel qu'il est sur le disque (borné, sans suivre de lien).
    fn lire(&mut self) -> Result<Vec<u8>, Echec>;
    /// Écrit ces octets dans un fichier neuf du dossier (jamais un fichier posé d'avance) ; son chemin.
    fn ecrire_temporaire(&mut self, octets: &[u8]) -> Result<String, Echec>;
    /// `sshd -t -f <temporaire>` : `Err` avec ce que sshd dit, s'il refuse.
    fn tester(&mut self, temporaire: &str) -> Result<(), Echec>;
    fn effacer_temporaire(&mut self, temporaire: &str);
    /// Un nom libre pour la copie d'avant (`PREFIXE_COPIE` puis la date), dans le même dossier.
    fn nom_copie(&mut self) -> String;
    /// sshd_config devient le temporaire ; l'ancien prend le nom `copie` (`None` : pas de copie gardée).
    fn remplacer(&mut self, temporaire: &str, copie: Option<&str>) -> Result<(), Echec>;
    /// La copie d'avant, par son nom dans le dossier.
    fn lire_copie(&mut self, nom: &str) -> Result<Vec<u8>, Echec>;
    fn lire_note(&mut self, nom: &str) -> Option<Vec<u8>>;
    fn ecrire_note(&mut self, nom: &str, octets: &[u8]) -> Result<(), Echec>;
    fn effacer_note(&mut self, nom: &str);
}

/// Un nom de copie admis : `PREFIXE_COPIE` puis chiffres, tirets ; jamais un chemin.
pub(crate) fn nom_copie_valide(nom: &str) -> bool {
    nom.len() <= 64
        && nom
            .strip_prefix(PREFIXE_COPIE)
            .is_some_and(|r| !r.is_empty() && r.bytes().all(|b| b.is_ascii_digit() || b == b'-'))
}

/// Le texte d'une configuration lue : UTF-8 sans zéro, ou rien.
pub(crate) fn texte_config(octets: &[u8]) -> Option<&str> {
    std::str::from_utf8(octets).ok().filter(|t| !t.contains('\0'))
}

/// Met le réglage `r` à « no » : rejugé sur la configuration lue ici, la nouvelle version éprouvée par `sshd -t`
/// avant de remplacer, la copie d'avant et les empreintes notées (relues), le fichier relu juste avant de remplacer
/// puis après. `Fait.avant` : le nom de la copie d'avant.
pub(crate) fn ecrire_sshd(c: &mut impl Config, r: ReglageSshd, nom: &str) -> Issue {
    let ancien = match c.lire() {
        Ok(o) => o,
        Err(e) => {
            return echec(
                None,
                trf!(
                    "sshd_config ne se lit pas ({e}) : rien d'écrit (un fichier absent n'est jamais créé)",
                    "sshd_config cannot be read ({e}): nothing written (a missing file is never created)"
                ),
            );
        }
    };
    let Some(texte) = texte_config(&ancien) else {
        return echec(
            None,
            tr!(
                "sshd_config n'est pas du texte : rien d'écrit",
                "sshd_config is not text: nothing written"
            ),
        );
    };
    if !signale(r, texte) {
        return Issue::Rien(format!("{} no", r.mot_cle()));
    }
    let nouveau = avec_reglage(&ancien, r);
    if texte_config(&nouveau).is_none_or(|t| signale(r, t)) {
        return echec(
            None,
            tr!(
                "le réglage resterait actif (UsePAM et clavier interactif, ou autre) : à corriger à la main ; rien d'écrit",
                "the setting would stay on (UsePAM and keyboard-interactive, or other): to fix by hand; nothing written"
            ),
        );
    }
    let temporaire = match c.ecrire_temporaire(&nouveau) {
        Ok(t) => t,
        Err(e) => {
            return echec(
                None,
                trf!(
                    "la nouvelle version ne s'écrit pas ({e}) : rien de remplacé",
                    "the new version cannot be written ({e}): nothing replaced"
                ),
            );
        }
    };
    if let Err(e) = c.tester(&temporaire) {
        c.effacer_temporaire(&temporaire);
        return echec(
            None,
            trf!(
                "sshd -t refuse la nouvelle version ({}) : rien de remplacé",
                "sshd -t refuses the new version ({}): nothing replaced",
                crate::ui::couper(&crate::ui::affichable(&e.to_string()), 300)
            ),
        );
    }
    let copie = c.nom_copie();
    if !nom_copie_valide(&copie) {
        c.effacer_temporaire(&temporaire);
        return echec(
            None,
            tr!(
                "nom de copie inattendu : rien de remplacé",
                "unexpected copy name: nothing replaced"
            ),
        );
    }
    let (sha_avant, sha_ecrit) = (empreinte(&ancien), empreinte(&nouveau));
    let note = {
        let brutes = [
            ("copie", brute_texte(&copie)),
            ("avant", brute_texte(&sha_avant)),
            ("ecrit", brute_texte(&sha_ecrit)),
        ];
        let refs: Vec<(&str, Option<&Brute>)> = brutes.iter().map(|(n, b)| (*n, Some(b))).collect();
        reglages::coder(nom, &refs)
    };
    let Some(note) = note else {
        c.effacer_temporaire(&temporaire);
        return echec(
            None,
            tr!(
                "la note ne se code pas : rien de remplacé",
                "the note cannot be encoded: nothing replaced"
            ),
        );
    };
    if let Err(e) = c.ecrire_note(nom, &note) {
        c.effacer_temporaire(&temporaire);
        return echec(
            None,
            trf!(
                "la copie d'avant ne se note pas ({e}) : rien de remplacé",
                "the previous copy cannot be noted ({e}): nothing replaced"
            ),
        );
    }
    if c.lire_note(nom).as_deref() != Some(note.as_slice()) {
        c.effacer_note(nom);
        c.effacer_temporaire(&temporaire);
        return echec(
            None,
            tr!(
                "la note ne se relit pas : rien de remplacé",
                "the note cannot be read back: nothing replaced"
            ),
        );
    }
    if c.lire().ok().as_deref() != Some(ancien.as_slice()) {
        c.effacer_note(nom);
        c.effacer_temporaire(&temporaire);
        return echec(
            None,
            tr!(
                "sshd_config a changé pendant le geste : rien de remplacé",
                "sshd_config changed during the action: nothing replaced"
            ),
        );
    }
    if let Err(e) = c.remplacer(&temporaire, Some(&copie)) {
        // Le remplacement raté laisse d'ordinaire l'ancien en place : alors la note s'efface.
        if c.lire().ok().as_deref() == Some(ancien.as_slice()) {
            c.effacer_note(nom);
            c.effacer_temporaire(&temporaire);
            return echec(
                None,
                trf!(
                    "sshd_config ne se remplace pas ({e}) : il est resté tel quel",
                    "sshd_config cannot be replaced ({e}): it stayed as it was"
                ),
            );
        }
        return echec(
            None,
            trf!(
                "sshd_config ne se remplace pas ({e}) ; ATTENTION : vérifiez sshd_config, la copie d'avant est {copie}, la note est gardée",
                "sshd_config cannot be replaced ({e}); WARNING: check sshd_config, the previous copy is {copie}, the note is kept"
            ),
        );
    }
    if c.lire().ok().as_deref() != Some(nouveau.as_slice()) {
        return echec(
            Some(copie.clone()),
            trf!(
                "sshd_config relu n'est pas celui écrit ; ATTENTION : vérifiez-le, la copie d'avant est {copie}, la note est gardée",
                "sshd_config read back is not the one written; WARNING: check it, the previous copy is {copie}, the note is kept"
            ),
        );
    }
    Issue::Fait { avant: copie }
}

/// Le nom de la copie d'avant et les empreintes d'avant et d'après qu'une note garde.
pub(crate) fn note_sshd(octets: &[u8], nom: &str) -> Option<(String, String, String)> {
    let v = reglages::decoder(octets, nom, &["copie", "avant", "ecrit"])?;
    let copie = lire_texte(v.first()?.as_ref())?;
    let avant = lire_texte(v.get(1)?.as_ref())?;
    let ecrit = lire_texte(v.get(2)?.as_ref())?;
    let empreinte_valide = |e: &str| e.len() == 64 && e.bytes().all(|b| b.is_ascii_hexdigit());
    (nom_copie_valide(&copie) && empreinte_valide(&avant) && empreinte_valide(&ecrit)).then_some((copie, avant, ecrit))
}

/// Remet la copie d'avant, si et seulement si sshd_config est encore celui que Vanguard a écrit et que la copie est
/// encore celle d'avant (empreintes de la note) ; éprouvée par `sshd -t` avant de remplacer, la note effacée une fois
/// la copie relue en place. `Fait.avant` : le nom de la copie remise.
pub(crate) fn remettre_sshd(c: &mut impl Config, nom: &str) -> Issue {
    let Some((copie, sha_avant, sha_ecrit)) = c.lire_note(nom).and_then(|o| note_sshd(&o, nom)) else {
        return echec(
            None,
            tr!(
                "aucune copie de sshd_config notée par Vanguard pour ce réglage (ou note abîmée) : rien d'écrit",
                "no copy of sshd_config noted by Vanguard for this setting (or damaged note): nothing written"
            ),
        );
    };
    let actuel = match c.lire() {
        Ok(o) => o,
        Err(e) => {
            return echec(
                None,
                trf!(
                    "sshd_config ne se lit pas ({e}) : rien d'écrit",
                    "sshd_config cannot be read ({e}): nothing written"
                ),
            );
        }
    };
    let sha = empreinte(&actuel);
    if sha == sha_avant {
        c.effacer_note(nom);
        return Issue::Rien(copie);
    }
    if sha != sha_ecrit {
        return echec(
            None,
            tr!(
                "sshd_config a changé depuis que Vanguard l'a écrit : Vanguard n'écrit jamais par-dessus ; rien d'écrit",
                "sshd_config has changed since Vanguard wrote it: Vanguard never writes over it; nothing written"
            ),
        );
    }
    let d_avant = match c.lire_copie(&copie) {
        Ok(o) if empreinte(&o) == sha_avant => o,
        Ok(_) => {
            return echec(
                None,
                trf!(
                    "la copie {copie} a changé depuis : rien d'écrit",
                    "the copy {copie} has changed since: nothing written"
                ),
            );
        }
        Err(e) => {
            return echec(
                None,
                trf!(
                    "la copie {copie} ne se lit pas ({e}) : rien d'écrit",
                    "the copy {copie} cannot be read ({e}): nothing written"
                ),
            );
        }
    };
    let temporaire = match c.ecrire_temporaire(&d_avant) {
        Ok(t) => t,
        Err(e) => {
            return echec(
                None,
                trf!(
                    "la copie ne s'écrit pas à côté ({e}) : rien de remplacé",
                    "the copy cannot be written alongside ({e}): nothing replaced"
                ),
            );
        }
    };
    if let Err(e) = c.tester(&temporaire) {
        c.effacer_temporaire(&temporaire);
        return echec(
            None,
            trf!(
                "sshd -t refuse la version d'avant ({}) : rien de remplacé, la note est gardée",
                "sshd -t refuses the previous version ({}): nothing replaced, the note is kept",
                crate::ui::couper(&crate::ui::affichable(&e.to_string()), 300)
            ),
        );
    }
    if c.lire().ok().as_deref() != Some(actuel.as_slice()) {
        c.effacer_temporaire(&temporaire);
        return echec(
            None,
            tr!(
                "sshd_config a changé pendant le geste : rien de remplacé",
                "sshd_config changed during the action: nothing replaced"
            ),
        );
    }
    if let Err(e) = c.remplacer(&temporaire, None) {
        c.effacer_temporaire(&temporaire);
        return echec(
            None,
            trf!(
                "sshd_config ne se remplace pas ({e}) ; la note est gardée",
                "sshd_config cannot be replaced ({e}); the note is kept"
            ),
        );
    }
    if c.lire().ok().as_deref() != Some(d_avant.as_slice()) {
        return echec(
            None,
            trf!(
                "sshd_config relu n'est pas la copie d'avant ; ATTENTION : vérifiez-le, la copie {copie} et la note sont gardées",
                "sshd_config read back is not the previous copy; WARNING: check it, the copy {copie} and the note are kept"
            ),
        );
    }
    c.effacer_note(nom);
    Issue::Fait { avant: copie }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::gestes::NomFichier;
    use std::collections::HashMap;

    const ALICE: &str = "S-1-5-21-111-222-333-1001";

    /// L'erreur d'un faux, comme Windows en rendrait une.
    fn faux(texte: &str) -> Echec {
        Echec::echoue("essai", texte)
    }

    #[test]
    fn noms_des_notes() {
        assert_eq!(
            nom_note_droits(&CibleSsh::ClesAdmin, None).as_deref(),
            Some("ssh-cles-admin")
        );
        let cle = CibleSsh::Cle(NomFichier::nouveau("id_rsa").unwrap());
        let n = nom_note_droits(&cle, Some(ALICE)).unwrap();
        assert!(n.starts_with("ssh-cle-") && n.len() == "ssh-cle-".len() + 16, "{n}");
        // Chaque compte la sienne ; la casse du nom ne compte pas (Windows non plus).
        assert_ne!(nom_note_droits(&cle, Some("S-1-5-21-111-222-333-1002")).unwrap(), n);
        let maj = CibleSsh::Cle(NomFichier::nouveau("ID_RSA").unwrap());
        assert_eq!(nom_note_droits(&maj, Some(ALICE)).unwrap(), n);
        assert_eq!(nom_note_droits(&cle, None), None);
        assert_eq!(nom_note_droits(&cle, Some("S-1-5-21-1;D:")), None);
        assert_eq!(nom_note_sshd(ReglageSshd::MotsDePasse), "sshd-mots-de-passe");
        // Jamais le nom d'une note de choix, de réglage ou de service.
        for n in [n.as_str(), "ssh-cles-admin", "sshd-mots-de-passe-vides"] {
            assert!(crate::machine::gestes::IdChoix::lire(n).is_none());
            assert!(!n.starts_with(reglages::PREFIXE_REGLAGE) && !n.starts_with(reglages::PREFIXE_SERVICE));
        }
    }

    #[test]
    fn listes_des_droits_lues() {
        let e = explicites("D:PAI(A;;FA;;;SY)(A;;FA;;;BA)").unwrap();
        assert!(e.protegee && !e.nulle);
        assert_eq!(e.regles, ["(A;;FA;;;SY)", "(A;;FA;;;BA)"]);
        // Les héritées (ID) ne comptent pas ; une condition garde ses parenthèses.
        let e = explicites("D:AI(A;ID;FA;;;SY)(A;OICIID;0x1200a9;;;BU)(XA;;FR;;;WD;(Member_of {SID(BA)}))").unwrap();
        assert!(!e.protegee);
        assert_eq!(e.regles, ["(XA;;FR;;;WD;(Member_of {SID(BA)}))"]);
        assert!(explicites("D:NO_ACCESS_CONTROL").unwrap().nulle);
        assert_eq!(explicites("O:SYD:(A;;FA;;;SY)"), None);
        assert_eq!(explicites("D:(A;;FA;;;SY"), None);
        assert_eq!(explicites("D:P(A;;FA;;;SY))"), None);
        assert_eq!(explicites("D:X(A;;FA;;;SY)"), None);
        // L'ordre et la casse ne comptent pas, la protection si.
        assert!(memes_droits(
            "D:PAI(A;;FA;;;BA)(a;;fa;;;sy)",
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
        ));
        assert!(!memes_droits(
            "D:AI(A;;FA;;;BA)(A;;FA;;;SY)",
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
        ));
        assert!(!memes_droits(
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)",
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
        ));
        assert!(!memes_droits("illisible", "illisible"));
        assert_eq!(voulu(None).as_deref(), Some("D:P(A;;FA;;;SY)(A;;FA;;;BA)"));
        assert_eq!(
            voulu(Some(ALICE)).as_deref(),
            Some("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-21-111-222-333-1001)")
        );
        // Un SID forgé ne glisse jamais une règle de plus.
        assert_eq!(voulu(Some("S-1-1-0)(A;;FA;;;WD")), None);
        assert_eq!(
            explicites("D:AI(A;;FA;;;BU)(A;ID;FA;;;SY)").unwrap().a_poser(),
            "D:(A;;FA;;;BU)"
        );
    }

    /// Un fichier inventé : sa liste (lue telle que Windows la rendrait, protégée « PAI »), les notes, des pannes.
    #[derive(Default)]
    struct FauxFichier {
        liste: String,
        notes: HashMap<String, Vec<u8>>,
        poses: Vec<String>,
        /// Les poses refusées (la n-ième, à partir de 0).
        refuser_pose: Option<usize>,
        refuser_note: bool,
        /// Une autre main change la liste juste après la note.
        changee_apres_note: Option<String>,
        /// Le dossier ne transmet rien : une liste non protégée revient sans héritées.
        sans_heritage: bool,
    }

    impl Fichier for FauxFichier {
        fn lire(&mut self) -> Option<String> {
            (!self.liste.is_empty()).then(|| self.liste.clone())
        }
        fn poser(&mut self, sddl: &str) -> Result<(), Echec> {
            let n = self.poses.len();
            self.poses.push(sddl.to_string());
            if self.refuser_pose == Some(n) {
                return Err(faux("accès refusé"));
            }
            let e = explicites(sddl).ok_or_else(|| faux("SDDL"))?;
            // Windows rend la liste avec ses héritées (ici une du dossier) quand elle n'est pas protégée.
            self.liste = if e.protegee {
                format!("D:PAI{}", e.regles.concat())
            } else if self.sans_heritage {
                format!("D:{}", e.regles.concat())
            } else {
                format!("D:AI{}(A;ID;FA;;;SY)", e.regles.concat())
            };
            Ok(())
        }
        fn lire_note(&mut self, nom: &str) -> Option<Vec<u8>> {
            self.notes.get(nom).cloned()
        }
        fn ecrire_note(&mut self, nom: &str, octets: &[u8]) -> Result<(), Echec> {
            if self.refuser_note {
                return Err(faux("registre"));
            }
            self.notes.insert(nom.into(), octets.to_vec());
            if let Some(l) = self.changee_apres_note.take() {
                self.liste = l;
            }
            Ok(())
        }
        fn effacer_note(&mut self, nom: &str) {
            self.notes.remove(nom);
        }
    }

    const OUVERTE: &str = "D:AI(A;;0x1301bf;;;BU)(A;ID;FA;;;SY)(A;ID;FA;;;BA)";
    const VOULUE: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";

    #[test]
    fn droits_reserves_puis_remis() {
        let mut f = FauxFichier {
            liste: OUVERTE.into(),
            ..FauxFichier::default()
        };
        let issue = reserver(&mut f, "ssh-cles-admin", VOULUE, || {
            panic!("pas de question avec une note")
        });
        assert_eq!(issue, Issue::Fait { avant: OUVERTE.into() });
        assert!(memes_droits(&f.liste, VOULUE));
        // La liste d'avant est notée telle quelle, héritées comprises.
        let (avant, ecrit) = note_droits(&f.notes["ssh-cles-admin"], "ssh-cles-admin").unwrap();
        assert_eq!((avant.as_str(), ecrit.as_str()), (OUVERTE, VOULUE));
        // Déjà réservé : rien.
        assert!(matches!(
            reserver(&mut f, "ssh-cles-admin", VOULUE, || false),
            Issue::Rien(_)
        ));
        // Défaire remet les règles posées sur le fichier et l'héritage ; la note s'efface.
        let issue = remettre_droits(&mut f, "ssh-cles-admin");
        assert!(matches!(issue, Issue::Fait { .. }), "{issue:?}");
        assert!(memes_droits(&f.liste, OUVERTE), "{}", f.liste);
        assert_eq!(f.poses.last().unwrap(), "D:(A;;0x1301bf;;;BU)");
        assert!(f.notes.is_empty());
        // Sans note : rien.
        assert!(matches!(remettre_droits(&mut f, "ssh-cles-admin"), Issue::Echec { .. }));
    }

    #[test]
    fn remise_sans_les_heritees_n_est_pas_celle_d_avant() {
        let mut f = FauxFichier {
            liste: OUVERTE.into(),
            ..FauxFichier::default()
        };
        assert!(matches!(reserver(&mut f, "n", VOULUE, || false), Issue::Fait { .. }));
        // L'héritage ne revient pas : la remise n'est pas dite faite, la liste de Vanguard est reposée, la note reste.
        f.sans_heritage = true;
        let issue = remettre_droits(&mut f, "n");
        assert!(matches!(issue, Issue::Echec { .. }), "{issue:?}");
        assert!(memes_droits(&f.liste, VOULUE), "{}", f.liste);
        assert!(f.notes.contains_key("n"));
        assert!(remise(OUVERTE, OUVERTE) && !remise("D:(A;;0x1301bf;;;BU)", OUVERTE));
        assert!(remise("D:(A;;FA;;;BU)", "D:(A;;FA;;;BU)"));
    }

    #[test]
    fn remise_jamais_par_dessus_un_changement() {
        let mut f = FauxFichier {
            liste: OUVERTE.into(),
            ..FauxFichier::default()
        };
        assert!(matches!(reserver(&mut f, "n", VOULUE, || false), Issue::Fait { .. }));
        // Quelqu'un a changé la liste depuis : la remise n'écrit rien, la note reste.
        f.liste = "D:PAI(A;;FA;;;SY)".into();
        let poses = f.poses.len();
        assert!(matches!(remettre_droits(&mut f, "n"), Issue::Echec { .. }));
        assert_eq!(f.poses.len(), poses);
        assert!(f.notes.contains_key("n"));
        // Déjà remise à la main comme avant : rien d'écrit, la note s'efface.
        f.liste = OUVERTE.into();
        assert!(matches!(remettre_droits(&mut f, "n"), Issue::Rien(_)));
        assert!(f.notes.is_empty());
        // Une note forgée (empreinte fausse) ne fait rien poser.
        f.liste = VOULUE.into();
        f.notes.insert("n".into(), b"VGREG\x01faux".to_vec());
        assert!(matches!(remettre_droits(&mut f, "n"), Issue::Echec { .. }));
        assert_eq!(f.poses.len(), poses);
    }

    #[test]
    fn rien_sans_note_ni_par_dessus() {
        // Le registre refuse la note : rien n'est posé.
        let mut f = FauxFichier {
            liste: OUVERTE.into(),
            refuser_note: true,
            ..FauxFichier::default()
        };
        assert!(matches!(reserver(&mut f, "n", VOULUE, || true), Issue::Echec { .. }));
        assert!(f.poses.is_empty(), "{:?}", f.poses);
        // La liste change entre la note et la pose : rien n'est posé, la note s'efface.
        let mut f = FauxFichier {
            liste: OUVERTE.into(),
            changee_apres_note: Some("D:PAI(A;;FA;;;WD)".into()),
            ..FauxFichier::default()
        };
        assert!(matches!(reserver(&mut f, "n", VOULUE, || true), Issue::Echec { .. }));
        assert!(f.poses.is_empty(), "{:?}", f.poses);
        assert!(f.notes.is_empty());
        // Illisible : rien.
        let mut f = FauxFichier::default();
        assert!(matches!(
            reserver(&mut f, "n", VOULUE, || true),
            Issue::Echec { avant: None, .. }
        ));
    }

    #[test]
    fn pose_ratee_remet_la_liste_d_avant() {
        let mut f = FauxFichier {
            liste: OUVERTE.into(),
            refuser_pose: Some(0),
            ..FauxFichier::default()
        };
        let Issue::Echec { raison, .. } = reserver(&mut f, "n", VOULUE, || true) else {
            panic!()
        };
        assert!(
            raison.contains("ne se pose pas") || raison.contains("cannot be set"),
            "{raison}"
        );
        assert_eq!(f.liste, OUVERTE);
        // Rien de changé : la note s'efface.
        assert!(f.notes.is_empty());
    }

    #[test]
    fn liste_trop_longue_question_non_annulable() {
        // Plus de 1024 octets : pas de note possible ; la question décide, non par défaut.
        let longue = format!("D:AI{}", "(A;;FR;;;S-1-5-21-111-222-333-1001)".repeat(40));
        let mut f = FauxFichier {
            liste: longue.clone(),
            ..FauxFichier::default()
        };
        assert!(matches!(reserver(&mut f, "n", VOULUE, || false), Issue::Echec { .. }));
        assert!(f.poses.is_empty(), "{:?}", f.poses);
        let mut posee = false;
        let issue = reserver(&mut f, "n", VOULUE, || {
            posee = true;
            true
        });
        assert!(posee && matches!(issue, Issue::Fait { .. }), "{issue:?}");
        assert!(f.notes.is_empty());
        assert!(matches!(remettre_droits(&mut f, "n"), Issue::Echec { .. }));
    }

    #[test]
    fn reglage_en_tete_de_sshd_config() {
        let livree = b"#PasswordAuthentication yes\r\nInclude conf.d/*\r\nMatch Group administrators\r\n PasswordAuthentication yes\r\n";
        let n = avec_reglage(livree, ReglageSshd::MotsDePasse);
        let t = std::str::from_utf8(&n).unwrap();
        assert!(t.is_ascii());
        assert!(t.starts_with("# Vanguard: PasswordAuthentication no (undo: vanguard options-defense --remettre sshd:mots-de-passe)\r\nPasswordAuthentication no\r\n#Password"), "{t}");
        assert!(t.ends_with(std::str::from_utf8(livree).unwrap()));
        assert!(signale(ReglageSshd::MotsDePasse, std::str::from_utf8(livree).unwrap()));
        assert!(!signale(ReglageSshd::MotsDePasse, t));
        // LF et indicateur d'ordre des octets gardés.
        let n = avec_reglage(b"\xEF\xBB\xBFPermitEmptyPasswords yes\n", ReglageSshd::MotsDePasseVides);
        assert!(n.starts_with(b"\xEF\xBB\xBF# Vanguard: PermitEmptyPasswords no"));
        assert!(n.ends_with(b"\nPermitEmptyPasswords no\nPermitEmptyPasswords yes\n"));
        assert!(!signale(ReglageSshd::MotsDePasseVides, texte_config(&n).unwrap()));
        assert!(signale(ReglageSshd::MotsDePasseVides, "PermitEmptyPasswords yes\n"));
        // Le clavier interactif avec PAM : PasswordAuthentication seul ne suffit pas.
        let pam = b"UsePAM yes\nKbdInteractiveAuthentication yes\n";
        assert!(signale(
            ReglageSshd::MotsDePasse,
            texte_config(&avec_reglage(pam, ReglageSshd::MotsDePasse)).unwrap()
        ));
        assert_eq!(texte_config(b"a\0b"), None);
    }

    #[test]
    fn ports_de_sshd_lus() {
        assert_eq!(ports_sshd("#Port 2222\n"), [22]);
        assert_eq!(
            ports_sshd("Port 2222\nPort=443\nListenAddress 0.0.0.0:8022\nListenAddress ::1\n"),
            [443, 2222, 8022]
        );
        assert_eq!(ports_sshd("ListenAddress [::]:2200\nMatch User x\nPort 9\n"), [2200]);
    }

    #[test]
    fn session_ssh_ni_redemarrage_ni_question() {
        assert_eq!(relance(Some(true), Some(false)), Relance::Redemarrer);
        assert_eq!(relance(Some(true), Some(true)), Relance::AuProchain);
        assert_eq!(relance(Some(true), None), Relance::AuProchain);
        assert_eq!(relance(None, Some(false)), Relance::AuProchain);
        assert_eq!(relance(Some(false), Some(true)), Relance::Arrete);
        // Une session SSH en cours, ou illisible : refus SANS question.
        for s in [Some(true), None] {
            assert_eq!(
                accord_mots_de_passe(s, || panic!("aucune question pendant une session")),
                AccordMdp::RefusSession
            );
        }
        assert_eq!(accord_mots_de_passe(Some(false), || false), AccordMdp::NonConfirme);
        assert_eq!(accord_mots_de_passe(Some(false), || true), AccordMdp::Oui);
    }

    /// Un dossier ssh inventé.
    #[derive(Default)]
    struct FauxDossier {
        fichiers: HashMap<String, Vec<u8>>,
        notes: HashMap<String, Vec<u8>>,
        sshd_refuse: bool,
        testes: Vec<Vec<u8>>,
        remplacements: usize,
        n: usize,
    }

    impl Config for FauxDossier {
        fn lire(&mut self) -> Result<Vec<u8>, Echec> {
            self.fichiers.get("sshd_config").cloned().ok_or_else(|| faux("absent"))
        }
        fn ecrire_temporaire(&mut self, octets: &[u8]) -> Result<String, Echec> {
            self.n += 1;
            let nom = format!("tmp{}", self.n);
            self.fichiers.insert(nom.clone(), octets.to_vec());
            Ok(nom)
        }
        fn tester(&mut self, temporaire: &str) -> Result<(), Echec> {
            self.testes.push(self.fichiers[temporaire].clone());
            if self.sshd_refuse {
                Err(faux("line 1: Bad configuration option: \x1b[31mPasswordAuthentication"))
            } else {
                Ok(())
            }
        }
        fn effacer_temporaire(&mut self, temporaire: &str) {
            self.fichiers.remove(temporaire);
        }
        fn nom_copie(&mut self) -> String {
            format!("{PREFIXE_COPIE}20261103-120000")
        }
        fn remplacer(&mut self, temporaire: &str, copie: Option<&str>) -> Result<(), Echec> {
            self.remplacements += 1;
            let neuf = self
                .fichiers
                .remove(temporaire)
                .ok_or_else(|| faux("temporaire absent"))?;
            let ancien = self
                .fichiers
                .insert("sshd_config".into(), neuf)
                .ok_or_else(|| faux("absent"))?;
            if let Some(c) = copie {
                self.fichiers.insert(c.into(), ancien);
            }
            Ok(())
        }
        fn lire_copie(&mut self, nom: &str) -> Result<Vec<u8>, Echec> {
            self.fichiers.get(nom).cloned().ok_or_else(|| faux("absente"))
        }
        fn lire_note(&mut self, nom: &str) -> Option<Vec<u8>> {
            self.notes.get(nom).cloned()
        }
        fn ecrire_note(&mut self, nom: &str, octets: &[u8]) -> Result<(), Echec> {
            self.notes.insert(nom.into(), octets.to_vec());
            Ok(())
        }
        fn effacer_note(&mut self, nom: &str) {
            self.notes.remove(nom);
        }
    }

    fn dossier(conf: &[u8]) -> FauxDossier {
        let mut d = FauxDossier::default();
        d.fichiers.insert("sshd_config".into(), conf.to_vec());
        d
    }

    #[test]
    fn sshd_t_refuse_rien_remplace() {
        let mut d = dossier(b"PermitEmptyPasswords yes\n");
        d.sshd_refuse = true;
        let Issue::Echec { raison, .. } = ecrire_sshd(&mut d, ReglageSshd::MotsDePasseVides, "sshd-x") else {
            panic!()
        };
        // Le texte de sshd est nettoyé avant d'être montré.
        assert!(!raison.contains('\x1b'), "{raison}");
        assert_eq!(d.testes.len(), 1);
        assert_eq!(d.remplacements, 0);
        assert_eq!(d.fichiers.len(), 1, "le temporaire est effacé");
        assert_eq!(d.fichiers["sshd_config"], b"PermitEmptyPasswords yes\n");
        assert!(d.notes.is_empty());
    }

    #[test]
    fn sshd_config_ecrit_puis_remis() {
        let avant = b"PermitEmptyPasswords yes\r\nPort 22\r\n".to_vec();
        let mut d = dossier(&avant);
        let issue = ecrire_sshd(&mut d, ReglageSshd::MotsDePasseVides, "sshd-v");
        let copie = format!("{PREFIXE_COPIE}20261103-120000");
        assert_eq!(issue, Issue::Fait { avant: copie.clone() });
        // Éprouvée avant de remplacer : la version testée est celle qui est en place.
        assert_eq!(d.testes, [d.fichiers["sshd_config"].clone()]);
        assert_eq!(d.fichiers[&copie], avant);
        assert!(!signale(
            ReglageSshd::MotsDePasseVides,
            texte_config(&d.fichiers["sshd_config"]).unwrap()
        ));
        // Déjà fait : rien.
        assert!(matches!(
            ecrire_sshd(&mut d, ReglageSshd::MotsDePasseVides, "sshd-v"),
            Issue::Rien(_)
        ));
        assert_eq!(d.remplacements, 1);
        // Défaire : la copie d'avant revient, éprouvée elle aussi ; la note s'efface.
        assert_eq!(remettre_sshd(&mut d, "sshd-v"), Issue::Fait { avant: copie });
        assert_eq!(d.fichiers["sshd_config"], avant);
        assert_eq!(d.testes.len(), 2);
        assert!(d.notes.is_empty());
    }

    #[test]
    fn remise_sshd_jamais_par_dessus() {
        let mut d = dossier(b"PasswordAuthentication yes\n");
        assert!(matches!(
            ecrire_sshd(&mut d, ReglageSshd::MotsDePasse, "sshd-m"),
            Issue::Fait { .. }
        ));
        // Changé à la main depuis : rien d'écrit, note gardée.
        d.fichiers
            .insert("sshd_config".into(), b"PasswordAuthentication no\nPort 2\n".to_vec());
        assert!(matches!(remettre_sshd(&mut d, "sshd-m"), Issue::Echec { .. }));
        assert_eq!(d.remplacements, 1);
        assert!(d.notes.contains_key("sshd-m"));
        // La copie d'avant changée : rien d'écrit non plus.
        let ecrit = avec_reglage(b"PasswordAuthentication yes\n", ReglageSshd::MotsDePasse);
        d.fichiers.insert("sshd_config".into(), ecrit);
        let copie = format!("{PREFIXE_COPIE}20261103-120000");
        d.fichiers
            .insert(copie, b"PasswordAuthentication yes\nAuthorizedKeysFile C:/x\n".to_vec());
        assert!(matches!(remettre_sshd(&mut d, "sshd-m"), Issue::Echec { .. }));
        assert_eq!(d.remplacements, 1);
        // Une note dont la copie est un chemin : refusée à la lecture.
        let brutes = [
            ("copie", brute_texte(r"..\..\Windows\win.ini")),
            ("avant", brute_texte(&"0".repeat(64))),
            ("ecrit", brute_texte(&"0".repeat(64))),
        ];
        let refs: Vec<(&str, Option<&Brute>)> = brutes.iter().map(|(n, b)| (*n, Some(b))).collect();
        let forgee = reglages::coder("sshd-m", &refs).unwrap();
        assert_eq!(note_sshd(&forgee, "sshd-m"), None);
    }

    #[test]
    fn sshd_config_absent_ou_changeant() {
        // Absent : jamais créé.
        let mut d = FauxDossier::default();
        assert!(matches!(
            ecrire_sshd(&mut d, ReglageSshd::MotsDePasse, "n"),
            Issue::Echec { .. }
        ));
        assert!(d.fichiers.is_empty() && d.testes.is_empty());
        // Clés seulement déjà : rien.
        let mut d = dossier(b"PasswordAuthentication no\n");
        assert!(matches!(
            ecrire_sshd(&mut d, ReglageSshd::MotsDePasse, "n"),
            Issue::Rien(_)
        ));
        assert!(d.testes.is_empty(), "{:?}", d.testes);
        // PAM laisserait le mot de passe passer : à la main, rien d'écrit.
        let mut d = dossier(b"UsePAM yes\nKbdInteractiveAuthentication yes\nPasswordAuthentication yes\n");
        assert!(matches!(
            ecrire_sshd(&mut d, ReglageSshd::MotsDePasse, "n"),
            Issue::Echec { .. }
        ));
        assert!(d.testes.is_empty(), "{:?}", d.testes);
        assert!(nom_copie_valide("sshd_config.vanguard-20261103-120000-2"));
        assert!(!nom_copie_valide(r"sshd_config.vanguard-1\..\x"));
        assert!(!nom_copie_valide("sshd_config.vanguard-"));
    }
}

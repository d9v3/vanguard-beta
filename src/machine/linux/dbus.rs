//! Un petit client D-Bus écrit pour Vanguard, sans bibliothèque : une prise Unix vers le bus système,
//! l'authentification EXTERNAL, des messages encodés et décodés à la main (en-tête, corps aligné, signatures).
//!
//! Pourquoi : `systemctl`, `systemd-analyze` et `busctl` ne font que parler D-Bus puis mettre la réponse en texte, qu'il
//! fallait ensuite relire (une langue, un format qui change d'une version à l'autre, un faux dans le PATH). La réponse
//! D-Bus, elle, est typée.
//!
//! Lecture seule : seules les méthodes de `LECTURES` partent, toutes sans effet sur le système ; une autre est refusée
//! avant d'être envoyée. Aucun appel ne demande d'autorisation interactive (pas de fenêtre polkit).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use crate::{tr, trf};

/// Les quelques actions de Vanguard (unités de l'utilisateur, notification, dconf), à part des lectures de ce fichier :
/// une seconde liste fermée, sur le bus de la session seulement.
pub(crate) mod actions;

/// La prise du bus système (chemin fixe de la spécification ; /var/run en est un lien).
const BUS_SYSTEME: &str = "/run/dbus/system_bus_socket";
/// Le temps laissé à une réponse, comme `busctl` (10 s) : un service bloqué ne doit pas figer Vanguard.
const DELAI: Duration = Duration::from_secs(10);
/// Un message plus gros est refusé (la spécification permet 128 Mio ; aucune lecture de Vanguard n'en approche).
const TAILLE_MAX: usize = 32 << 20;
/// Un tableau plus long est refusé (limite de la spécification).
const TABLEAU_MAX: usize = 64 << 20;
/// Tableaux, structures et variantes imbriqués : la spécification en permet 64 en tout.
const PROFONDEUR_MAX: usize = 64;
/// Valeurs décodées dans un message, au plus. La taille seule ne suffit pas : chaque valeur prend 32 octets en mémoire,
/// et un « ay » de 32 Mio en ferait 1 Gio. Un million (32 Mio) laisse de la marge aux plus grosses réponses lues
/// (GetManagedObjects d'udisks2 sur une machine à centaines de volumes : quelques centaines de milliers).
const VALEURS_MAX: usize = 1 << 20;

const DBUS: &str = "org.freedesktop.DBus";
const PROPRIETES: &str = "org.freedesktop.DBus.Properties";
const OBJETS: &str = "org.freedesktop.DBus.ObjectManager";

pub(crate) const SYSTEMD: &str = "org.freedesktop.systemd1";
pub(crate) const CHEMIN_SYSTEMD: &str = "/org/freedesktop/systemd1";
pub(crate) const GESTIONNAIRE: &str = "org.freedesktop.systemd1.Manager";
pub(crate) const UNITE: &str = "org.freedesktop.systemd1.Unit";

/// Les seules méthodes que ce client envoie, (interface, méthode) : toutes lisent, aucune ne change le système.
const LECTURES: &[(&str, &str)] = &[
    (DBUS, "Hello"),
    // Le processus qui tient un nom du bus : pour ne croire un service que s'il est le vrai programme.
    (DBUS, "GetConnectionUnixProcessID"),
    (PROPRIETES, "Get"),
    (PROPRIETES, "GetAll"),
    (OBJETS, "GetManagedObjects"),
    (GESTIONNAIRE, "ListUnits"),
    (GESTIONNAIRE, "ListUnitsFiltered"),
    (GESTIONNAIRE, "GetUnit"),
    // Lit le journal SMART déjà relevé par udisks2 ; SmartUpdate, qui le relève, n'est pas permis.
    ("org.freedesktop.UDisks2.NVMe.Controller", "SmartGetAttributes"),
    // Lot 4 (Linux) : lectures qui remplacent systemctl, loginctl, fwupdmgr et nmcli. GetSettings ne rend jamais
    // les secrets (GetSecrets, à part, n'est pas permis) ; GetUpgrades lit les métadonnées déjà téléchargées.
    (GESTIONNAIRE, "ListUnitFiles"),
    ("org.freedesktop.login1.Manager", "ListSessions"),
    ("org.freedesktop.fwupd", "GetHostSecurityAttrs"),
    ("org.freedesktop.fwupd", "GetDevices"),
    ("org.freedesktop.fwupd", "GetUpgrades"),
    ("org.freedesktop.NetworkManager.Settings", "ListConnections"),
    ("org.freedesktop.NetworkManager.Settings.Connection", "GetSettings"),
];

// Genres de message.
const APPEL: u8 = 1;
const RETOUR: u8 = 2;
const ERREUR: u8 = 3;
const SIGNAL: u8 = 4;

/// Une valeur D-Bus. `Texte` sert aux chaînes (`s`), chemins d'objet (`o`) et signatures (`g`) ; une variante garde
/// sa signature pour pouvoir être réécrite.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Valeur {
    Octet(u8),
    Booleen(bool),
    I16(i16),
    U16(u16),
    I32(i32),
    U32(u32),
    I64(i64),
    U64(u64),
    Reel(f64),
    Texte(String),
    Fd(u32),
    Tableau(Vec<Valeur>),
    Dictionnaire(Vec<(Valeur, Valeur)>),
    Structure(Vec<Valeur>),
    Variante(String, Box<Valeur>),
}

impl Valeur {
    pub(crate) fn texte_de(t: &str) -> Self {
        Valeur::Texte(t.to_string())
    }

    /// La valeur elle-même, sans les variantes qui l'enveloppent.
    pub(crate) fn nue(&self) -> &Valeur {
        let mut v = self;
        while let Valeur::Variante(_, dedans) = v {
            v = dedans;
        }
        v
    }

    pub(crate) fn texte(&self) -> Option<&str> {
        match self.nue() {
            Valeur::Texte(t) => Some(t),
            _ => None,
        }
    }

    pub(crate) fn booleen(&self) -> Option<bool> {
        match self.nue() {
            Valeur::Booleen(b) => Some(*b),
            _ => None,
        }
    }

    /// Un entier positif ou nul, quel que soit son type ; `None` pour un négatif ou autre chose qu'un entier.
    pub(crate) fn entier(&self) -> Option<u64> {
        match *self.nue() {
            Valeur::Octet(n) => Some(n.into()),
            Valeur::U16(n) => Some(n.into()),
            Valeur::U32(n) => Some(n.into()),
            Valeur::U64(n) => Some(n),
            Valeur::I16(n) => u64::try_from(n).ok(),
            Valeur::I32(n) => u64::try_from(n).ok(),
            Valeur::I64(n) => u64::try_from(n).ok(),
            _ => None,
        }
    }

    /// Les éléments d'un tableau ou les membres d'une structure (vide pour le reste).
    pub(crate) fn elements(&self) -> &[Valeur] {
        match self.nue() {
            Valeur::Tableau(v) | Valeur::Structure(v) => v,
            _ => &[],
        }
    }

    /// Les entrées d'un dictionnaire (vide pour le reste).
    pub(crate) fn entrees(&self) -> &[(Valeur, Valeur)] {
        match self.nue() {
            Valeur::Dictionnaire(v) => v,
            _ => &[],
        }
    }

    /// La valeur à la clé `cle` d'un dictionnaire à clés texte (`a{sv}`, `a{oa{sv}}`…), sans sa variante.
    pub(crate) fn champ(&self, cle: &str) -> Option<&Valeur> {
        self.entrees()
            .iter()
            .find(|(k, _)| k.texte() == Some(cle))
            .map(|(_, v)| v.nue())
    }

    /// Les chaînes d'un tableau (`as`) ; les éléments d'un autre type sont sautés.
    pub(crate) fn textes(&self) -> Vec<String> {
        self.elements()
            .iter()
            .filter_map(|v| v.texte().map(String::from))
            .collect()
    }
}

fn mal_forme(detail: &str) -> String {
    trf!(
        "message D-Bus mal formé ({detail})",
        "malformed D-Bus message ({detail})"
    )
}

// ---------------------------------------------------------------------------------------------------------------
// Signatures

fn type_de_base(c: u8) -> bool {
    b"ybnqiuxtdsogh".contains(&c)
}

/// La longueur du premier type complet de `sig` (« a{sv}i » → 5).
fn longueur_type(sig: &[u8], profondeur: usize) -> Result<usize, String> {
    if profondeur > PROFONDEUR_MAX {
        return Err(mal_forme("signature trop imbriquée"));
    }
    match sig.first() {
        Some(&c) if type_de_base(c) || c == b'v' => Ok(1),
        Some(b'a') if sig.get(1) == Some(&b'{') => {
            if !sig.get(2).is_some_and(|&c| type_de_base(c)) {
                return Err(mal_forme("clé de dictionnaire"));
            }
            let n = longueur_type(&sig[3..], profondeur + 1)?;
            if sig.get(3 + n) != Some(&b'}') {
                return Err(mal_forme("dictionnaire"));
            }
            Ok(4 + n)
        }
        Some(b'a') => Ok(1 + longueur_type(&sig[1..], profondeur + 1)?),
        Some(b'(') => {
            let mut i = 1;
            loop {
                match sig.get(i) {
                    Some(b')') if i > 1 => return Ok(i + 1),
                    None | Some(b')') => return Err(mal_forme("structure")),
                    _ => i += longueur_type(&sig[i..], profondeur + 1)?,
                }
            }
        }
        _ => Err(mal_forme("signature")),
    }
}

/// Les types complets d'une signature (« sa{sv} » → « s », « a{sv} »).
fn types(sig: &str) -> Result<Vec<&[u8]>, String> {
    let mut reste = sig.as_bytes();
    if reste.len() > 255 {
        return Err(mal_forme("signature trop longue"));
    }
    let mut liste = Vec::new();
    while !reste.is_empty() {
        let n = longueur_type(reste, 0)?;
        liste.push(&reste[..n]);
        reste = &reste[n..];
    }
    Ok(liste)
}

/// L'alignement d'un type, d'après son premier caractère.
fn alignement(c: u8) -> usize {
    match c {
        b'n' | b'q' => 2,
        b'b' | b'i' | b'u' | b's' | b'o' | b'a' | b'h' => 4,
        b'x' | b't' | b'd' | b'(' | b'{' => 8,
        _ => 1,
    }
}

/// Un chemin d'objet valide : « / », ou des éléments [A-Za-z0-9_] non vides séparés par « / ».
fn chemin_valide(c: &str) -> bool {
    c == "/"
        || c.strip_prefix('/').is_some_and(|reste| {
            reste
                .split('/')
                .all(|e| !e.is_empty() && e.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        })
}

// ---------------------------------------------------------------------------------------------------------------
// Encodage (petit-boutiste)

#[derive(Default)]
struct Ecrivain {
    octets: Vec<u8>,
}

impl Ecrivain {
    fn aligner(&mut self, n: usize) {
        while !self.octets.len().is_multiple_of(n) {
            self.octets.push(0);
        }
    }

    fn u32(&mut self, n: u32) {
        self.aligner(4);
        self.octets.extend(n.to_le_bytes());
    }

    fn chaine(&mut self, t: &str) -> Result<(), String> {
        if t.contains('\0') {
            return Err(mal_forme("caractère nul dans une chaîne"));
        }
        self.u32(u32::try_from(t.len()).map_err(|_| mal_forme("chaîne trop longue"))?);
        self.octets.extend(t.as_bytes());
        self.octets.push(0);
        Ok(())
    }

    fn signature(&mut self, t: &str) -> Result<(), String> {
        types(t)?;
        self.octets
            .push(u8::try_from(t.len()).map_err(|_| mal_forme("signature trop longue"))?);
        self.octets.extend(t.as_bytes());
        self.octets.push(0);
        Ok(())
    }

    /// Écrit `v`, du type complet `sig`.
    fn ecrire(&mut self, sig: &[u8], v: &Valeur, profondeur: usize) -> Result<(), String> {
        if profondeur > PROFONDEUR_MAX {
            return Err(mal_forme("valeur trop imbriquée"));
        }
        let c = sig[0];
        self.aligner(alignement(c));
        match (c, v) {
            (b'y', Valeur::Octet(n)) => self.octets.push(*n),
            (b'b', Valeur::Booleen(b)) => self.u32(u32::from(*b)),
            (b'n', Valeur::I16(n)) => self.octets.extend(n.to_le_bytes()),
            (b'q', Valeur::U16(n)) => self.octets.extend(n.to_le_bytes()),
            (b'i', Valeur::I32(n)) => self.octets.extend(n.to_le_bytes()),
            (b'u', Valeur::U32(n)) | (b'h', Valeur::Fd(n)) => self.u32(*n),
            (b'x', Valeur::I64(n)) => self.octets.extend(n.to_le_bytes()),
            (b't', Valeur::U64(n)) => self.octets.extend(n.to_le_bytes()),
            (b'd', Valeur::Reel(n)) => self.octets.extend(n.to_le_bytes()),
            (b's', Valeur::Texte(t)) => self.chaine(t)?,
            (b'o', Valeur::Texte(t)) if chemin_valide(t) => self.chaine(t)?,
            (b'g', Valeur::Texte(t)) => self.signature(t)?,
            (b'v', Valeur::Variante(s, dedans)) => {
                let t = types(s)?;
                let [seul] = t[..] else {
                    return Err(mal_forme("variante à plusieurs types"));
                };
                self.signature(s)?;
                self.ecrire(seul, dedans, profondeur + 1)?;
            }
            (b'(', Valeur::Structure(membres)) => {
                let t = types(std::str::from_utf8(&sig[1..sig.len() - 1]).unwrap_or_default())?;
                if t.len() != membres.len() {
                    return Err(mal_forme("structure incomplète"));
                }
                for (s, m) in t.into_iter().zip(membres) {
                    self.ecrire(s, m, profondeur + 1)?;
                }
            }
            (b'a', Valeur::Tableau(_) | Valeur::Dictionnaire(_)) => self.tableau(sig, v, profondeur)?,
            _ => return Err(mal_forme("valeur d'un autre type que sa signature")),
        }
        Ok(())
    }

    fn tableau(&mut self, sig: &[u8], v: &Valeur, profondeur: usize) -> Result<(), String> {
        let element = &sig[1..];
        let place = self.octets.len();
        self.u32(0);
        // Le remplissage avant le premier élément n'entre pas dans la longueur.
        self.aligner(alignement(element[0]));
        let debut = self.octets.len();
        match (element[0], v) {
            (b'{', Valeur::Dictionnaire(entrees)) => {
                let cle = &element[1..2];
                let valeur = &element[2..element.len() - 1];
                for (k, val) in entrees {
                    self.aligner(8);
                    self.ecrire(cle, k, profondeur + 1)?;
                    self.ecrire(valeur, val, profondeur + 1)?;
                }
            }
            (c, Valeur::Tableau(elements)) if c != b'{' => {
                for e in elements {
                    self.ecrire(element, e, profondeur + 1)?;
                }
            }
            _ => return Err(mal_forme("valeur d'un autre type que sa signature")),
        }
        let longueur = self.octets.len() - debut;
        if longueur > TABLEAU_MAX {
            return Err(mal_forme("tableau trop long"));
        }
        let n = u32::try_from(longueur).map_err(|_| mal_forme("tableau trop long"))?;
        self.octets[place..place + 4].copy_from_slice(&n.to_le_bytes());
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Décodage (les deux boutismes)

struct Lecteur<'a> {
    octets: &'a [u8],
    pos: usize,
    grand_boutiste: bool,
    /// Valeurs déjà décodées (voir `VALEURS_MAX`).
    valeurs: usize,
}

impl Lecteur<'_> {
    fn prendre(&mut self, n: usize) -> Result<&[u8], String> {
        let fin = self.pos.checked_add(n).filter(|&f| f <= self.octets.len());
        let fin = fin.ok_or_else(|| mal_forme("message tronqué"))?;
        let morceau = &self.octets[self.pos..fin];
        self.pos = fin;
        Ok(morceau)
    }

    /// Saute le remplissage, que la spécification veut nul.
    fn aligner(&mut self, n: usize) -> Result<(), String> {
        let reste = (n - self.pos % n) % n;
        if self.prendre(reste)?.iter().any(|&o| o != 0) {
            return Err(mal_forme("remplissage non nul"));
        }
        Ok(())
    }

    fn fixe<const N: usize>(&mut self) -> Result<[u8; N], String> {
        self.aligner(N)?;
        let mut t = [0; N];
        t.copy_from_slice(self.prendre(N)?);
        if self.grand_boutiste {
            t.reverse();
        }
        // Rendu petit-boutiste : les appelants décodent tous en from_le_bytes.
        Ok(t)
    }

    fn u32(&mut self) -> Result<u32, String> {
        self.fixe::<4>().map(u32::from_le_bytes)
    }

    fn texte(&mut self, n: usize) -> Result<String, String> {
        let t = self.prendre(n)?.to_vec();
        if self.prendre(1)? != [0] {
            return Err(mal_forme("chaîne sans nul final"));
        }
        // Le nul est interdit dans une chaîne D-Bus, comme à l'encodage.
        if t.contains(&0) {
            return Err(mal_forme("caractère nul dans une chaîne"));
        }
        String::from_utf8(t).map_err(|_| mal_forme("chaîne hors UTF-8"))
    }

    fn signature(&mut self) -> Result<String, String> {
        let n = self.prendre(1)?[0];
        let s = self.texte(n.into())?;
        types(&s)?;
        Ok(s)
    }

    /// Lit une valeur du type complet `sig`.
    fn lire(&mut self, sig: &[u8], profondeur: usize) -> Result<Valeur, String> {
        if profondeur > PROFONDEUR_MAX {
            return Err(mal_forme("valeur trop imbriquée"));
        }
        self.valeurs += 1;
        if self.valeurs > VALEURS_MAX {
            return Err(mal_forme("trop de valeurs"));
        }
        Ok(match sig[0] {
            b'y' => Valeur::Octet(self.prendre(1)?[0]),
            b'b' => match self.u32()? {
                0 => Valeur::Booleen(false),
                1 => Valeur::Booleen(true),
                _ => return Err(mal_forme("booléen")),
            },
            b'n' => Valeur::I16(i16::from_le_bytes(self.fixe()?)),
            b'q' => Valeur::U16(u16::from_le_bytes(self.fixe()?)),
            b'i' => Valeur::I32(i32::from_le_bytes(self.fixe()?)),
            b'u' => Valeur::U32(self.u32()?),
            b'h' => Valeur::Fd(self.u32()?),
            b'x' => Valeur::I64(i64::from_le_bytes(self.fixe()?)),
            b't' => Valeur::U64(u64::from_le_bytes(self.fixe()?)),
            b'd' => Valeur::Reel(f64::from_le_bytes(self.fixe()?)),
            b's' | b'o' => {
                let n = self.u32()? as usize;
                let t = self.texte(n)?;
                if sig[0] == b'o' && !chemin_valide(&t) {
                    return Err(mal_forme("chemin d'objet"));
                }
                Valeur::Texte(t)
            }
            b'g' => Valeur::Texte(self.signature()?),
            b'v' => {
                let s = self.signature()?;
                let t = types(&s)?;
                let [seul] = t[..] else {
                    return Err(mal_forme("variante à plusieurs types"));
                };
                let dedans = self.lire(seul, profondeur + 1)?;
                Valeur::Variante(s, Box::new(dedans))
            }
            b'(' => {
                self.aligner(8)?;
                let t = types(std::str::from_utf8(&sig[1..sig.len() - 1]).unwrap_or_default())?;
                let mut membres = Vec::with_capacity(t.len());
                for s in t {
                    membres.push(self.lire(s, profondeur + 1)?);
                }
                Valeur::Structure(membres)
            }
            b'a' => self.tableau(&sig[1..], profondeur)?,
            _ => return Err(mal_forme("signature")),
        })
    }

    fn tableau(&mut self, element: &[u8], profondeur: usize) -> Result<Valeur, String> {
        let longueur = self.u32()? as usize;
        if longueur > TABLEAU_MAX {
            return Err(mal_forme("tableau trop long"));
        }
        self.aligner(alignement(element[0]))?;
        let fin = self
            .pos
            .checked_add(longueur)
            .filter(|&f| f <= self.octets.len())
            .ok_or_else(|| mal_forme("tableau tronqué"))?;
        // Chaque élément prend au moins un octet : la boucle finit.
        let dictionnaire = element[0] == b'{';
        let mut elements = Vec::new();
        let mut entrees = Vec::new();
        while self.pos < fin {
            if dictionnaire {
                self.aligner(8)?;
                let cle = self.lire(&element[1..2], profondeur + 1)?;
                let valeur = self.lire(&element[2..element.len() - 1], profondeur + 1)?;
                entrees.push((cle, valeur));
            } else {
                elements.push(self.lire(element, profondeur + 1)?);
            }
        }
        if self.pos != fin {
            return Err(mal_forme("tableau débordé"));
        }
        Ok(if dictionnaire {
            Valeur::Dictionnaire(entrees)
        } else {
            Valeur::Tableau(elements)
        })
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Messages

/// Un message D-Bus : l'en-tête et ses champs, puis le corps décodé d'après `signature`.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct Message {
    pub genre: u8,
    pub drapeaux: u8,
    pub serie: u32,
    pub chemin: Option<String>,
    pub interface: Option<String>,
    pub membre: Option<String>,
    pub nom_erreur: Option<String>,
    pub reponse_a: Option<u32>,
    pub destination: Option<String>,
    pub expediteur: Option<String>,
    pub signature: String,
    pub corps: Vec<Valeur>,
}

impl Message {
    fn appel(
        destination: &str,
        chemin: &str,
        interface: &str,
        membre: &str,
        signature: &str,
        corps: Vec<Valeur>,
    ) -> Self {
        Message {
            genre: APPEL,
            chemin: Some(chemin.into()),
            interface: Some(interface.into()),
            membre: Some(membre.into()),
            destination: Some(destination.into()),
            signature: signature.into(),
            corps,
            ..Message::default()
        }
    }

    /// Les octets du message, petit-boutiste.
    fn encoder(&self) -> Result<Vec<u8>, String> {
        let t = types(&self.signature)?;
        if t.len() != self.corps.len() {
            return Err(mal_forme("corps différent de sa signature"));
        }
        let mut corps = Ecrivain::default();
        for (s, v) in t.into_iter().zip(&self.corps) {
            corps.ecrire(s, v, 0)?;
        }
        let champ = |code: u8, sig: &str, v: Valeur| {
            Valeur::Structure(vec![Valeur::Octet(code), Valeur::Variante(sig.into(), Box::new(v))])
        };
        let mut champs = Vec::new();
        let textes = [
            (1, "o", &self.chemin),
            (2, "s", &self.interface),
            (3, "s", &self.membre),
            (4, "s", &self.nom_erreur),
            (6, "s", &self.destination),
            (7, "s", &self.expediteur),
        ];
        for (code, sig, v) in textes {
            if let Some(v) = v {
                champs.push(champ(code, sig, Valeur::texte_de(v)));
            }
        }
        if let Some(n) = self.reponse_a {
            champs.push(champ(5, "u", Valeur::U32(n)));
        }
        if !self.signature.is_empty() {
            champs.push(champ(8, "g", Valeur::texte_de(&self.signature)));
        }
        champs.sort_by_key(|c| c.elements().first().and_then(Valeur::entier));
        let mut e = Ecrivain::default();
        e.octets.extend([b'l', self.genre, self.drapeaux, 1]);
        e.u32(u32::try_from(corps.octets.len()).map_err(|_| mal_forme("corps trop long"))?);
        e.u32(self.serie);
        e.ecrire(b"a(yv)", &Valeur::Tableau(champs), 0)?;
        e.aligner(8);
        e.octets.extend(corps.octets);
        if e.octets.len() > TAILLE_MAX {
            return Err(mal_forme("message trop long"));
        }
        Ok(e.octets)
    }

    /// Le message entier lu dans `octets` (ni plus ni moins), corps compris.
    #[cfg(test)]
    fn decoder(octets: &[u8]) -> Result<Self, String> {
        Self::decoder_si(octets, |_| true)
    }

    /// Comme `decoder`, mais le corps n'est décodé que si `voulu` le demande d'après l'en-tête ; sinon il reste vide.
    /// Un message qui ne répond pas à l'appel en cours (un signal que n'importe quel compte peut envoyer) est ainsi
    /// jeté sans que son corps soit lu.
    fn decoder_si(octets: &[u8], voulu: impl FnOnce(&Message) -> bool) -> Result<Self, String> {
        let grand_boutiste = match octets.first() {
            Some(b'l') => false,
            Some(b'B') => true,
            _ => return Err(mal_forme("boutisme")),
        };
        let mut l = Lecteur {
            octets,
            pos: 1,
            grand_boutiste,
            valeurs: 0,
        };
        let [genre, drapeaux, version] = l.prendre(3)?.try_into().map_err(|_| mal_forme("en-tête"))?;
        if version != 1 {
            return Err(mal_forme("version du protocole"));
        }
        let longueur_corps = l.u32()? as usize;
        let serie = l.u32()?;
        if serie == 0 {
            return Err(mal_forme("numéro de série nul"));
        }
        let mut m = Message {
            genre,
            drapeaux,
            serie,
            ..Message::default()
        };
        for c in l.lire(b"a(yv)", 0)?.elements() {
            let [Valeur::Octet(code), Valeur::Variante(sig, v)] = c.elements() else {
                continue;
            };
            let texte = || v.texte().map(String::from).ok_or_else(|| mal_forme("champ d'en-tête"));
            match (code, sig.as_str()) {
                (1, "o") => m.chemin = Some(texte()?),
                (2, "s") => m.interface = Some(texte()?),
                (3, "s") => m.membre = Some(texte()?),
                (4, "s") => m.nom_erreur = Some(texte()?),
                (5, "u") => m.reponse_a = v.entier().and_then(|n| u32::try_from(n).ok()),
                (6, "s") => m.destination = Some(texte()?),
                (7, "s") => m.expediteur = Some(texte()?),
                (8, "g") => m.signature = texte()?,
                // Aucun descripteur n'a été négocié : un message qui en annonce n'est pas pour ce client.
                (9, "u") if v.entier() != Some(0) => return Err(mal_forme("descripteurs de fichier")),
                (9, "u") => {}
                (1..=9, _) => return Err(mal_forme("type d'un champ d'en-tête")),
                // Un champ inconnu est ignoré, comme le veut la spécification.
                _ => {}
            }
        }
        l.aligner(8)?;
        if l.pos.checked_add(longueur_corps) != Some(octets.len()) {
            return Err(mal_forme("longueur du corps"));
        }
        let types_du_corps = types(&m.signature)?;
        let complet = match genre {
            APPEL => m.chemin.is_some() && m.membre.is_some(),
            RETOUR => m.reponse_a.is_some(),
            ERREUR => m.reponse_a.is_some() && m.nom_erreur.is_some(),
            SIGNAL => m.chemin.is_some() && m.interface.is_some() && m.membre.is_some(),
            _ => true,
        };
        if !complet {
            return Err(mal_forme("champ d'en-tête manquant"));
        }
        if voulu(&m) {
            for s in types_du_corps {
                m.corps.push(l.lire(s, 0)?);
            }
            if l.pos != octets.len() {
                return Err(mal_forme("corps plus long que sa signature"));
            }
        }
        Ok(m)
    }
}

/// La longueur totale d'un message, d'après ses 16 premiers octets.
fn longueur_totale(debut: &[u8; 16]) -> Result<usize, String> {
    let nombre = |i: usize| {
        let t = [debut[i], debut[i + 1], debut[i + 2], debut[i + 3]];
        u64::from(if debut[0] == b'B' {
            u32::from_be_bytes(t)
        } else {
            u32::from_le_bytes(t)
        })
    };
    let entete = (16 + nombre(12)).div_ceil(8) * 8;
    usize::try_from(entete + nombre(4))
        .ok()
        .filter(|&n| n <= TAILLE_MAX)
        .ok_or_else(|| mal_forme("message trop long"))
}

// ---------------------------------------------------------------------------------------------------------------
// Connexion

fn erreur_io(e: &std::io::Error) -> String {
    if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) {
        tr!("le bus n'a pas répondu à temps", "the bus did not answer in time").to_string()
    } else {
        trf!("bus D-Bus : {e}", "D-Bus: {e}")
    }
}

/// Une connexion au bus, prête aux appels.
pub(crate) struct Bus {
    prise: UnixStream,
    serie: u32,
    /// Une lecture ou une écriture a échoué en route (délai dépassé au milieu d'un message, prise coupée) : le flux
    /// est désynchronisé, l'appel suivant lirait du milieu d'un message. La connexion n'est plus utilisée.
    casse: bool,
}

/// L'uid tel que l'authentification EXTERNAL l'écrit : ses chiffres décimaux en ASCII, puis en hexadécimal
/// (1000 → « 31303030 »).
fn uid_hexa(uid: u32) -> String {
    uid.to_string().bytes().fold(String::new(), |mut h, b| {
        let _ = write!(h, "{b:02x}");
        h
    })
}

impl Bus {
    /// Le bus système (services de l'ordinateur : systemd, udisks2…).
    pub(crate) fn systeme() -> Result<Self, String> {
        let prise = UnixStream::connect(BUS_SYSTEME)
            .map_err(|e| trf!("bus système injoignable ({e})", "system bus unreachable ({e})"))?;
        Self::sur(prise)
    }

    /// Le bus de la session du compte (les programmes de la session : GameMode…), d'après
    /// DBUS_SESSION_BUS_ADDRESS (« unix:path=… » seulement), sinon $XDG_RUNTIME_DIR/bus.
    /// `None` : pas de bus de session joignable (surveillance hors session) ; rien n'est alors su de la session.
    pub(crate) fn session() -> Option<Self> {
        let chemin = std::env::var("DBUS_SESSION_BUS_ADDRESS")
            .ok()
            .and_then(|a| chemin_de_session(&a))
            .or_else(|| std::env::var_os("XDG_RUNTIME_DIR").map(|d| std::path::PathBuf::from(d).join("bus")))?;
        Self::sur(UnixStream::connect(&chemin).ok()?).ok()
    }

    /// Authentifie la prise puis se présente au bus (Hello, obligatoire avant tout autre appel).
    fn sur(prise: UnixStream) -> Result<Self, String> {
        prise.set_read_timeout(Some(DELAI)).map_err(|e| erreur_io(&e))?;
        prise.set_write_timeout(Some(DELAI)).map_err(|e| erreur_io(&e))?;
        let mut bus = Bus {
            prise,
            serie: 0,
            casse: false,
        };
        bus.authentifier()?;
        bus.echanger(Message::appel(
            DBUS,
            "/org/freedesktop/DBus",
            DBUS,
            "Hello",
            "",
            Vec::new(),
        ))?;
        Ok(bus)
    }

    fn ecrire(&mut self, octets: &[u8]) -> Result<(), String> {
        self.verifier_entiere()?;
        let r = self.prise.write_all(octets).map_err(|e| erreur_io(&e));
        if r.is_err() {
            self.condamner();
        }
        r
    }

    /// Ferme la prise : plus rien n'en est lu ni écrit (voir `casse`).
    fn condamner(&mut self) {
        self.casse = true;
        let _ = self.prise.shutdown(std::net::Shutdown::Both);
    }

    fn verifier_entiere(&self) -> Result<(), String> {
        if self.casse {
            return Err(tr!(
                "connexion au bus fermée après une erreur",
                "bus connection closed after an error"
            )
            .to_string());
        }
        Ok(())
    }

    /// Une ligne de l'authentification, sans « \r\n ». Lue octet par octet : rien du flux binaire qui suit n'est pris.
    fn ligne(&mut self) -> Result<String, String> {
        let mut ligne = Vec::new();
        let mut octet = [0];
        while !ligne.ends_with(b"\r\n") {
            if ligne.len() > 1024 {
                return Err(mal_forme("ligne d'authentification trop longue"));
            }
            self.prise.read_exact(&mut octet).map_err(|e| erreur_io(&e))?;
            ligne.push(octet[0]);
        }
        ligne.truncate(ligne.len() - 2);
        Ok(String::from_utf8_lossy(&ligne).into_owned())
    }

    /// EXTERNAL : le bus reconnaît le compte au noyau (les droits de la prise). Sans identité écrite d'abord, il prend
    /// celle que le noyau lui donne, juste aussi dans un espace de noms d'utilisateurs (`unshare -r`), où le
    /// programme se croit root ; un bus qui la veut écrite reçoit l'uid en hexadécimal.
    fn authentifier(&mut self) -> Result<(), String> {
        self.ecrire(b"\0AUTH EXTERNAL\r\n")?;
        let mut reponse = self.ligne()?;
        if reponse == "DATA" || reponse.starts_with("DATA ") {
            self.ecrire(b"DATA\r\n")?;
            reponse = self.ligne()?;
        }
        if reponse.starts_with("REJECTED") {
            // SAFETY : geteuid ne prend rien et ne peut pas échouer.
            let uid = unsafe { libc::geteuid() };
            self.ecrire(format!("AUTH EXTERNAL {}\r\n", uid_hexa(uid)).as_bytes())?;
            reponse = self.ligne()?;
        }
        if !reponse.starts_with("OK ") {
            let vu = crate::ui::affichable(&reponse);
            return Err(trf!(
                "le bus a refusé la connexion ({vu})",
                "the bus refused the connection ({vu})"
            ));
        }
        self.ecrire(b"BEGIN\r\n")
    }

    /// Le prochain message ; son corps n'est décodé que s'il répond à l'appel `attendu`.
    fn recevoir(&mut self, echeance: Instant, attendu: u32) -> Result<Message, String> {
        let reste = echeance.saturating_duration_since(Instant::now());
        if reste.is_zero() {
            return Err(tr!("le bus n'a pas répondu à temps", "the bus did not answer in time").to_string());
        }
        let octets = self.lire_message(reste);
        // Un message lu à moitié (ou une longueur refusée, dont la suite reste dans la prise) désynchronise le flux.
        let octets = octets.inspect_err(|_| self.condamner())?;
        // Lu en entier, un message mal formé ne désynchronise rien : la connexion reste bonne.
        Message::decoder_si(&octets, |m| {
            m.reponse_a == Some(attendu) && matches!(m.genre, RETOUR | ERREUR)
        })
    }

    /// Les octets d'un message entier, d'après la longueur annoncée dans ses 16 premiers.
    fn lire_message(&mut self, delai: Duration) -> Result<Vec<u8>, String> {
        self.verifier_entiere()?;
        self.prise.set_read_timeout(Some(delai)).map_err(|e| erreur_io(&e))?;
        let mut debut = [0; 16];
        self.prise.read_exact(&mut debut).map_err(|e| erreur_io(&e))?;
        let mut octets = debut.to_vec();
        octets.resize(longueur_totale(&debut)?.max(16), 0);
        self.prise.read_exact(&mut octets[16..]).map_err(|e| erreur_io(&e))?;
        Ok(octets)
    }

    /// Envoie un appel et attend sa réponse ; les signaux et ce qui répond à autre chose sont passés.
    fn echanger(&mut self, mut appel: Message) -> Result<Message, String> {
        self.serie = self.serie.wrapping_add(1).max(1);
        appel.serie = self.serie;
        let octets = appel.encoder()?;
        self.ecrire(&octets)?;
        let echeance = Instant::now() + DELAI;
        loop {
            let r = self.recevoir(echeance, appel.serie)?;
            if r.reponse_a != Some(appel.serie) || !matches!(r.genre, RETOUR | ERREUR) {
                continue;
            }
            if r.genre == ERREUR {
                let nom = r.nom_erreur.unwrap_or_default();
                let detail = r.corps.first().and_then(Valeur::texte).unwrap_or_default();
                return Err(crate::ui::affichable(&format!("{nom} : {detail}")));
            }
            return Ok(r);
        }
    }

    /// Appelle une méthode de lecture (`LECTURES`) et rend le corps de la réponse.
    pub(crate) fn appeler(
        &mut self,
        destination: &str,
        chemin: &str,
        interface: &str,
        methode: &str,
        signature: &str,
        arguments: Vec<Valeur>,
    ) -> Result<Vec<Valeur>, String> {
        if !LECTURES.contains(&(interface, methode)) {
            return Err(trf!(
                "{interface}.{methode} n'est pas une lecture permise",
                "{interface}.{methode} is not an allowed read"
            ));
        }
        let appel = Message::appel(destination, chemin, interface, methode, signature, arguments);
        Ok(self.echanger(appel)?.corps)
    }

    /// Une propriété d'un objet, sans sa variante.
    pub(crate) fn propriete(
        &mut self,
        destination: &str,
        chemin: &str,
        interface: &str,
        nom: &str,
    ) -> Result<Valeur, String> {
        let corps = self.appeler(
            destination,
            chemin,
            PROPRIETES,
            "Get",
            "ss",
            vec![Valeur::texte_de(interface), Valeur::texte_de(nom)],
        )?;
        corps
            .into_iter()
            .next()
            .map(|v| v.nue().clone())
            .ok_or_else(|| mal_forme("réponse vide"))
    }

    /// Toutes les propriétés d'une interface d'un objet : un dictionnaire `a{sv}`.
    pub(crate) fn proprietes(&mut self, destination: &str, chemin: &str, interface: &str) -> Result<Valeur, String> {
        let corps = self.appeler(
            destination,
            chemin,
            PROPRIETES,
            "GetAll",
            "s",
            vec![Valeur::texte_de(interface)],
        )?;
        corps.into_iter().next().ok_or_else(|| mal_forme("réponse vide"))
    }

    /// Les objets d'un service et leurs propriétés, par interface (`ObjectManager`), triés par chemin.
    pub(crate) fn objets(&mut self, destination: &str, racine: &str) -> Result<Vec<(String, Valeur)>, String> {
        let corps = self.appeler(destination, racine, OBJETS, "GetManagedObjects", "", Vec::new())?;
        let mut objets: Vec<(String, Valeur)> = corps
            .first()
            .map(Valeur::entrees)
            .unwrap_or_default()
            .iter()
            .filter_map(|(chemin, interfaces)| Some((chemin.texte()?.to_string(), interfaces.clone())))
            .collect();
        objets.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(objets)
    }
}

/// Le chemin de la prise d'une adresse de bus « unix:path=/run/user/1000/bus[,guid=…] » ; une autre forme (abstract,
/// tcp) n'est pas suivie.
fn chemin_de_session(adresse: &str) -> Option<std::path::PathBuf> {
    adresse.split(';').find_map(|a| {
        let reste = a.strip_prefix("unix:")?;
        reste
            .split(',')
            .find_map(|c| c.strip_prefix("path="))
            .map(std::path::PathBuf::from)
    })
}

/// Un jeu tourne-t-il sous GameMode (`ClientCount` > 0 sur le bus de la session) ? `None` : GameMode absent, le bus
/// injoignable, ou le nom tenu par un autre programme que gamemoded : rien de su (seul un jeu lancé par gamemoderun
/// est vu). Le nom com.feralinteractive.GameMode, lancé à la demande, est souvent libre : n'importe quel programme du
/// compte pouvait le prendre et faire croire à un jeu sans fin.
pub(crate) fn gamemode_actif() -> Option<bool> {
    const NOM: &str = "com.feralinteractive.GameMode";
    let mut bus = Bus::session()?;
    let pid = bus
        .appeler(
            DBUS,
            "/org/freedesktop/DBus",
            DBUS,
            "GetConnectionUnixProcessID",
            "s",
            vec![Valeur::texte_de(NOM)],
        )
        .ok()?
        .first()?
        .entier()?;
    if !programme_gamemoded(std::path::Path::new(&format!("/proc/{pid}/exe"))) {
        return None;
    }
    bus.propriete(NOM, "/com/feralinteractive/GameMode", NOM, "ClientCount")
        .ok()?
        .entier()
        .map(|n| n > 0)
}

/// Le programme désigné (le lien /proc/<pid>/exe d'un processus) est-il gamemoded installé par le système : nommé
/// ainsi, à root, que personne d'autre ne peut réécrire ? Un faux service est lancé par le compte, depuis un fichier
/// du compte (ou par un interpréteur, qui ne s'appelle pas gamemoded).
fn programme_gamemoded(exe: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(cible) = std::fs::read_link(exe) else {
        return false;
    };
    cible.file_name().is_some_and(|n| n == "gamemoded")
        && std::fs::metadata(&cible).is_ok_and(|m| m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0)
}

/// L'erreur d'un appel dit que le service n'est pas sur ce bus (pas installé, ou arrêté sans activation) : rien à
/// lire, ce qui n'est pas une lecture qui échoue.
pub(crate) fn service_absent(erreur: &str) -> bool {
    ["ServiceUnknown", "NameHasNoOwner"]
        .iter()
        .any(|nom| erreur.starts_with(&format!("org.freedesktop.DBus.Error.{nom} ")))
}

// ---------------------------------------------------------------------------------------------------------------
// systemd

/// Les unités en échec, triées, comme `systemctl --failed` : `ListUnitsFiltered(["failed"])` retient une unité dont
/// l'état de chargement, d'activité ou le sous-état vaut « failed » ; comme systemctl sans --all, une unité qui en
/// suit une autre (un périphérique vu sous plusieurs noms) n'est comptée qu'une fois.
pub(crate) fn unites_en_echec(bus: &mut Bus) -> Result<Vec<String>, String> {
    let corps = bus.appeler(
        SYSTEMD,
        CHEMIN_SYSTEMD,
        GESTIONNAIRE,
        "ListUnitsFiltered",
        "as",
        vec![Valeur::Tableau(vec![Valeur::texte_de("failed")])],
    )?;
    Ok(noms_d_unites(corps.first(), true))
}

/// Les unités chargées, nom → chemin d'objet (ListUnits).
pub(crate) fn unites_chargees(bus: &mut Bus) -> Result<HashMap<String, String>, String> {
    let corps = bus.appeler(SYSTEMD, CHEMIN_SYSTEMD, GESTIONNAIRE, "ListUnits", "", Vec::new())?;
    Ok(corps
        .first()
        .map(Valeur::elements)
        .unwrap_or_default()
        .iter()
        .filter_map(|u| {
            let m = u.elements();
            Some((m.first()?.texte()?.to_string(), m.get(6)?.texte()?.to_string()))
        })
        .collect())
}

/// Les suffixes d'unité que systemctl reconnaît : un autre nom (« sshd ») est un service.
const SUFFIXES_D_UNITE: [&str; 11] = [
    ".service",
    ".socket",
    ".target",
    ".timer",
    ".mount",
    ".automount",
    ".path",
    ".slice",
    ".scope",
    ".device",
    ".swap",
];

/// Le nom complet d'une unité, comme systemctl le complète : « sshd » → « sshd.service », « ssh.socket » tel quel.
pub(crate) fn nom_d_unite(nom: &str) -> String {
    if SUFFIXES_D_UNITE.iter().any(|s| nom.ends_with(s)) {
        nom.to_string()
    } else {
        format!("{nom}.service")
    }
}

/// L'état d'activité d'une unité (« active », « reloading », « inactive », « failed »…), comme `systemctl
/// is-active` l'écrit : GetUnit, qui trouve aussi une unité chargée sous un autre de ses noms (sshd.service, alias
/// de ssh.service), puis sa propriété ActiveState. `Ok(None)` : aucune unité chargée de ce nom, donc inactive, et
/// c'est vérifié.
pub(crate) fn etat_d_activite(bus: &mut Bus, nom: &str) -> Result<Option<String>, crate::modele::raison::Echec> {
    let echec = |e: String| crate::modele::raison::Echec::echoue("dbus/etat_d_activite", e);
    let unite = nom_d_unite(nom);
    let corps = match bus.appeler(
        SYSTEMD,
        CHEMIN_SYSTEMD,
        GESTIONNAIRE,
        "GetUnit",
        "s",
        vec![Valeur::texte_de(&unite)],
    ) {
        Ok(c) => c,
        Err(e) if e.starts_with("org.freedesktop.systemd1.NoSuchUnit ") => return Ok(None),
        Err(e) => return Err(echec(e)),
    };
    let chemin = corps
        .first()
        .and_then(Valeur::texte)
        .ok_or_else(|| echec(mal_forme("GetUnit sans chemin")))?
        .to_string();
    let etat = bus.propriete(SYSTEMD, &chemin, UNITE, "ActiveState").map_err(echec)?;
    etat.texte()
        .map(|t| Some(t.to_string()))
        .ok_or_else(|| echec(mal_forme("ActiveState")))
}

/// Les noms d'une liste d'unités `a(ssssssouso)` (nom, description, chargement, activité, sous-état, suivie…), triés ;
/// `sans_suivies` : sans celles qui en suivent une autre.
fn noms_d_unites(liste: Option<&Valeur>, sans_suivies: bool) -> Vec<String> {
    let mut noms: Vec<String> = liste
        .map(Valeur::elements)
        .unwrap_or_default()
        .iter()
        .filter(|u| !sans_suivies || u.elements().get(5).and_then(Valeur::texte).is_none_or(str::is_empty))
        .filter_map(|u| u.elements().first()?.texte().map(String::from))
        .collect();
    noms.sort();
    noms
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> Valeur {
        Valeur::texte_de(s)
    }

    /// Un message de la spécification, octet par octet : l'appel Hello que tout client envoie en premier.
    #[test]
    fn hello_octet_par_octet() {
        let mut m = Message::appel(DBUS, "/org/freedesktop/DBus", DBUS, "Hello", "", Vec::new());
        m.serie = 1;
        let octets = m.encoder().unwrap();
        let mut attendu: Vec<u8> = vec![b'l', 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0];
        // Longueur des champs (109, le « m » que tout bus voit en premier), puis chaque champ aligné sur 8 : code, signature de la variante, valeur.
        attendu.extend(109u32.to_le_bytes());
        let mut champ = |code: u8, sig: u8, texte: &str| {
            while !attendu.len().is_multiple_of(8) {
                attendu.push(0);
            }
            attendu.extend([code, 1, sig, 0]);
            attendu.extend(u32::try_from(texte.len()).unwrap().to_le_bytes());
            attendu.extend(texte.as_bytes());
            attendu.push(0);
        };
        champ(1, b'o', "/org/freedesktop/DBus");
        champ(2, b's', "org.freedesktop.DBus");
        champ(3, b's', "Hello");
        champ(6, b's', "org.freedesktop.DBus");
        assert_eq!(attendu.len(), 16 + 109);
        while !attendu.len().is_multiple_of(8) {
            attendu.push(0);
        }
        assert_eq!(octets, attendu);
        assert_eq!(Message::decoder(&octets).unwrap(), m);
        assert_eq!(
            longueur_totale(&octets[..16].try_into().unwrap()).unwrap(),
            octets.len()
        );
    }

    /// Un corps aux alignements piégeux, octet par octet : un octet, puis un u64 aligné sur 8, un tableau de u64 dont le
    /// remplissage ne compte pas dans la longueur, un dictionnaire a{sv}, une structure.
    #[test]
    fn corps_aligne_octet_par_octet() {
        let mut e = Ecrivain::default();
        let valeurs = [
            (&b"y"[..], Valeur::Octet(7)),
            (b"t", Valeur::U64(0x0102_0304_0506_0708)),
            (b"at", Valeur::Tableau(vec![Valeur::U64(1)])),
            (
                b"a{sv}",
                Valeur::Dictionnaire(vec![(t("a"), Valeur::Variante("q".into(), Box::new(Valeur::U16(5))))]),
            ),
            (b"(bn)", Valeur::Structure(vec![Valeur::Booleen(true), Valeur::I16(-2)])),
        ];
        for (s, v) in &valeurs {
            e.ecrire(s, v, 0).unwrap();
        }
        let attendu: Vec<u8> = [
            &[7, 0, 0, 0, 0, 0, 0, 0][..],
            &[8, 7, 6, 5, 4, 3, 2, 1],
            // at : longueur 8 (sans les 4 octets de remplissage qui suivent), puis le u64 aligné sur 8.
            &[8, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
            // a{sv} : longueur 12 ; l'entrée alignée sur 8 : « a », variante « q », remplissage, 5.
            &[12, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, b'a', 0, 1, b'q', 0, 0, 5, 0],
            // (bn) aligné sur 8 : vrai, -2.
            &[0, 0, 0, 0, 1, 0, 0, 0, 0xfe, 0xff],
        ]
        .concat();
        assert_eq!(e.octets, attendu);
        let mut l = Lecteur {
            octets: &e.octets,
            pos: 0,
            grand_boutiste: false,
            valeurs: 0,
        };
        for (s, v) in &valeurs {
            assert_eq!(&l.lire(s, 0).unwrap(), v);
        }
        assert_eq!(l.pos, e.octets.len());
    }

    /// Un message grand-boutiste (« B ») se lit aussi : un bus sur une machine grand-boutiste en envoie.
    #[test]
    fn grand_boutiste() {
        let mut octets = vec![b'B', RETOUR, 0, 1, 0, 0, 0, 4, 0, 0, 0, 9];
        // Réponse à 3, zéro descripteur de fichier (un champ permis), signature « u ».
        let champs: Vec<u8> = [
            &[5, 1, b'u', 0][..],
            &[0, 0, 0, 3],
            &[9, 1, b'u', 0],
            &[0, 0, 0, 0],
            &[8, 1, b'g', 0, 1, b'u', 0],
        ]
        .concat();
        octets.extend(u32::try_from(champs.len()).unwrap().to_be_bytes());
        octets.extend(champs);
        while !octets.len().is_multiple_of(8) {
            octets.push(0);
        }
        octets.extend(42u32.to_be_bytes());
        let m = Message::decoder(&octets).unwrap();
        assert_eq!((m.serie, m.reponse_a, m.corps), (9, Some(3), vec![Valeur::U32(42)]));
        assert_eq!(
            longueur_totale(&octets[..16].try_into().unwrap()).unwrap(),
            octets.len()
        );
    }

    /// Toutes les formes de valeurs repassent à l'identique (encodées puis décodées), dans un vrai message.
    #[test]
    fn aller_retour() {
        let corps = vec![
            Valeur::I32(-5),
            Valeur::I64(i64::MIN),
            Valeur::Reel(1.5),
            t("é"),
            t("/org/a_b"),
            t("a{sv}"),
            Valeur::Tableau(vec![]),
            Valeur::Tableau(vec![Valeur::Tableau(vec![Valeur::Octet(1), Valeur::Octet(2)])]),
            Valeur::Dictionnaire(vec![(
                t("/x"),
                Valeur::Dictionnaire(vec![(
                    t("i"),
                    Valeur::Variante("as".into(), Box::new(Valeur::Tableau(vec![t("z")]))),
                )]),
            )]),
            Valeur::Variante(
                "v".into(),
                Box::new(Valeur::Variante("u".into(), Box::new(Valeur::U32(3)))),
            ),
        ];
        let mut m = Message::appel("a.b", "/", "a.b", "C", "ixdsogayaaya{oa{sv}}v", corps);
        m.serie = 77;
        let octets = m.encoder().unwrap();
        assert_eq!(Message::decoder(&octets).unwrap(), m);
        assert_eq!(m.corps[9].nue(), &Valeur::U32(3));
    }

    /// Ce qu'un bus pourrait envoyer de travers est refusé, sans paniquer ni lire hors du message.
    #[test]
    fn messages_mal_formes() {
        let mut m = Message::appel(
            "a.b",
            "/a",
            "a.b",
            "C",
            "as",
            vec![Valeur::Tableau(vec![t("x"), t("y")])],
        );
        m.serie = 2;
        let bon = m.encoder().unwrap();
        for n in 0..bon.len() {
            assert!(Message::decoder(&bon[..n]).is_err(), "tronqué à {n}");
        }
        let mut ajoute = bon.clone();
        ajoute.push(0);
        assert!(Message::decoder(&ajoute).is_err());
        // Un tableau qui se dit plus long que le message.
        let mut long = bon.clone();
        let corps = bon.len() - u32::from_le_bytes(bon[4..8].try_into().unwrap()) as usize;
        long[corps..corps + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Message::decoder(&long).is_err());
        // Un booléen qui vaut 2, une version 2, un numéro de série nul, un boutisme inconnu.
        let lecteur = |octets: &'static [u8]| Lecteur {
            octets,
            pos: 0,
            grand_boutiste: false,
            valeurs: 0,
        };
        assert!(lecteur(&[2, 0, 0, 0]).lire(b"b", 0).is_err());
        // Un nul dans une chaîne, un chemin ou une signature (la spécification l'interdit, l'encodeur le refuse).
        assert!(lecteur(&[3, 0, 0, 0, b'a', 0, b'b', 0]).lire(b"s", 0).is_err());
        assert!(lecteur(&[3, 0, 0, 0, b'/', 0, b'b', 0]).lire(b"o", 0).is_err());
        assert!(lecteur(&[2, b'y', 0, 0]).lire(b"g", 0).is_err());
        assert_eq!(lecteur(&[3, 0, 0, 0, b'a', b'b', b'c', 0]).lire(b"s", 0), Ok(t("abc")));
        // Un remplissage d'alignement non nul : avant un u64, avant le premier élément d'un tableau.
        let mut l = lecteur(&[7, 1, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(l.lire(b"y", 0), Ok(Valeur::Octet(7)));
        assert!(l.lire(b"t", 0).is_err());
        let mut l = lecteur(&[7, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(l.lire(b"y", 0), Ok(Valeur::Octet(7)));
        assert_eq!(l.lire(b"t", 0), Ok(Valeur::U64(9)));
        assert!(
            lecteur(&[8, 0, 0, 0, 1, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0])
                .lire(b"at", 0)
                .is_err()
        );
        for (i, v) in [(3, 2), (8, 0), (0, b'x')] {
            let mut faux = bon.clone();
            faux[i] = v;
            assert!(Message::decoder(&faux).is_err());
        }
        // Une signature trop imbriquée, ou incomplète.
        assert!(types(&format!("{}y", "a".repeat(100))).is_err());
        for s in ["a", "(", "()", "a{vs}", "a{s}", "{sv}", "(i", "z"] {
            assert!(types(s).is_err(), "{s}");
        }
        // Un message plus grand que la limite n'est pas lu.
        let mut debut = [0u8; 16];
        debut[0] = b'l';
        debut[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(longueur_totale(&debut).is_err());
        // Une valeur qui ne va pas avec sa signature n'est pas écrite.
        assert!(Ecrivain::default().ecrire(b"s", &Valeur::U32(1), 0).is_err());
        assert!(Ecrivain::default().ecrire(b"o", &t("pas un chemin"), 0).is_err());
    }

    /// Un faux GameMode lancé par le compte n'est pas cru : seul un programme nommé gamemoded, à root et que personne
    /// d'autre ne réécrit, l'est.
    #[test]
    fn faux_gamemode() {
        use std::os::unix::fs::PermissionsExt;
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let faux = d.join("gamemoded");
        std::fs::write(&faux, b"#!/bin/sh\n").unwrap();
        let lien = d.join("exe");
        std::os::unix::fs::symlink(&faux, &lien).unwrap();
        // Réécrivable par le groupe : refusé, même là où il paraît à root (`unshare -r` des essais sans Internet).
        std::fs::set_permissions(&faux, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(!programme_gamemoded(&lien));
        // Un interpréteur du système (à root), sous un autre nom : refusé.
        let sh = d.join("sh");
        std::os::unix::fs::symlink("/bin/sh", &sh).unwrap();
        assert!(!programme_gamemoded(&sh));
        assert!(!programme_gamemoded(&d.join("absent")));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une méthode hors de la liste des lectures n'est pas envoyée, même à un faux bus.
    #[test]
    fn seules_les_lectures_partent() {
        let (client, mut serveur) = UnixStream::pair().unwrap();
        let mut bus = Bus {
            prise: client,
            serie: 0,
            casse: false,
        };
        let r = bus.appeler(
            SYSTEMD,
            CHEMIN_SYSTEMD,
            GESTIONNAIRE,
            "StartUnit",
            "ss",
            vec![t("x"), t("replace")],
        );
        assert!(r.is_err());
        serveur.set_nonblocking(true).unwrap();
        assert!(serveur.read(&mut [0; 1]).is_err(), "rien n'est parti");
        assert!(
            LECTURES
                .iter()
                .all(|(_, m)| !m.starts_with("Set") && !m.starts_with("Start"))
        );
    }

    fn lire_ligne(s: &mut UnixStream, auth: &mut Vec<u8>) {
        let debut = auth.len();
        let mut o = [0];
        while !auth[debut..].ends_with(b"\r\n") {
            s.read_exact(&mut o).unwrap();
            auth.push(o[0]);
        }
    }

    fn lire_message(s: &mut UnixStream) -> Message {
        let mut debut = [0; 16];
        s.read_exact(&mut debut).unwrap();
        let mut octets = debut.to_vec();
        octets.resize(longueur_totale(&debut).unwrap(), 0);
        s.read_exact(&mut octets[16..]).unwrap();
        Message::decoder(&octets).unwrap()
    }

    /// Un faux bus (paire de prises) : il lit l'authentification et chaque message octet par octet, répond à Hello
    /// après un signal, puis confie l'appel suivant à `repondre`. Rend la prise du client et ce qu'il a reçu pendant
    /// l'authentification.
    fn faux_bus(
        repondre: impl FnOnce(&mut UnixStream, Message) + Send + 'static,
    ) -> (UnixStream, std::thread::JoinHandle<Vec<u8>>) {
        faux_bus_qui(b"DATA\r\n", repondre)
    }

    /// `faux_bus`, dont la première réponse à l'authentification est `premiere` (« DATA », ou « REJECTED » pour un bus
    /// qui veut l'identité écrite).
    fn faux_bus_qui(
        premiere: &'static [u8],
        repondre: impl FnOnce(&mut UnixStream, Message) + Send + 'static,
    ) -> (UnixStream, std::thread::JoinHandle<Vec<u8>>) {
        let (client, mut serveur) = UnixStream::pair().unwrap();
        let fil = std::thread::spawn(move || {
            let mut auth = Vec::new();
            lire_ligne(&mut serveur, &mut auth);
            serveur.write_all(premiere).unwrap();
            lire_ligne(&mut serveur, &mut auth);
            serveur.write_all(b"OK 0123456789abcdef0123456789abcdef\r\n").unwrap();
            lire_ligne(&mut serveur, &mut auth);
            let hello = lire_message(&mut serveur);
            assert_eq!(hello.membre.as_deref(), Some("Hello"));
            // Un signal avant la réponse (le bus annonce le nom donné) : le client doit le passer.
            let signal = Message {
                genre: SIGNAL,
                serie: 1,
                chemin: Some("/org/freedesktop/DBus".into()),
                interface: Some(DBUS.into()),
                membre: Some("NameAcquired".into()),
                signature: "s".into(),
                corps: vec![t(":1.42")],
                ..Message::default()
            };
            serveur.write_all(&signal.encoder().unwrap()).unwrap();
            serveur.write_all(&retour(&hello, "s", vec![t(":1.42")])).unwrap();
            let appel = lire_message(&mut serveur);
            repondre(&mut serveur, appel);
            auth
        });
        (client, fil)
    }

    fn retour(a: &Message, signature: &str, corps: Vec<Valeur>) -> Vec<u8> {
        Message {
            genre: RETOUR,
            serie: 3,
            reponse_a: Some(a.serie),
            signature: signature.into(),
            corps,
            ..Message::default()
        }
        .encoder()
        .unwrap()
    }

    /// L'authentification EXTERNAL sans identité écrite, puis Hello, puis ListUnitsFiltered : ce que le client envoie
    /// et ce qu'il comprend de la réponse.
    #[test]
    fn unites_en_echec_par_un_faux_bus() {
        let (client, fil) = faux_bus(|s, appel| {
            assert_eq!(
                (
                    appel.destination.as_deref(),
                    appel.chemin.as_deref(),
                    appel.interface.as_deref()
                ),
                (Some(SYSTEMD), Some(CHEMIN_SYSTEMD), Some(GESTIONNAIRE))
            );
            assert_eq!(appel.membre.as_deref(), Some("ListUnitsFiltered"));
            assert_eq!(appel.corps, vec![Valeur::Tableau(vec![t("failed")])]);
            let unite = |nom: &str, suivie: &str| {
                Valeur::Structure(vec![
                    t(nom),
                    t("description"),
                    t("loaded"),
                    t("failed"),
                    t("failed"),
                    t(suivie),
                    t("/org/freedesktop/systemd1/unit/x"),
                    Valeur::U32(0),
                    t(""),
                    t("/"),
                ])
            };
            let liste = Valeur::Tableau(vec![
                unite("zz.service", ""),
                unite("dev-sda.device", "dev-disk.device"),
                unite("aa.mount", ""),
            ]);
            s.write_all(&retour(&appel, "a(ssssssouso)", vec![liste])).unwrap();
        });
        let mut bus = Bus::sur(client).unwrap();
        assert_eq!(unites_en_echec(&mut bus).unwrap(), ["aa.mount", "zz.service"]);
        assert_eq!(fil.join().unwrap(), b"\0AUTH EXTERNAL\r\nDATA\r\nBEGIN\r\n");
    }

    /// Un bus qui refuse EXTERNAL sans identité (REJECTED) : le client la redonne écrite, l'uid décimal en
    /// hexadécimal, puis continue.
    #[test]
    fn authentification_apres_un_refus() {
        assert_eq!(uid_hexa(1000), "31303030");
        assert_eq!(uid_hexa(0), "30");
        assert_eq!(uid_hexa(u32::MAX), "34323934393637323935");
        let (client, fil) = faux_bus_qui(b"REJECTED EXTERNAL DBUS_COOKIE_SHA1\r\n", |s, appel| {
            s.write_all(&retour(&appel, "a(ssssssouso)", vec![Valeur::Tableau(vec![])]))
                .unwrap();
        });
        let mut bus = Bus::sur(client).unwrap();
        assert_eq!(unites_en_echec(&mut bus).unwrap(), Vec::<String>::new());
        // SAFETY : geteuid ne prend rien et ne peut pas échouer.
        let uid = unsafe { libc::geteuid() };
        let attendu = format!("\0AUTH EXTERNAL\r\nAUTH EXTERNAL {}\r\nBEGIN\r\n", uid_hexa(uid));
        assert_eq!(String::from_utf8(fil.join().unwrap()).unwrap(), attendu);
        // Refusé deux fois : la connexion n'est pas ouverte.
        let (client, mut serveur) = UnixStream::pair().unwrap();
        let fil = std::thread::spawn(move || {
            let mut auth = Vec::new();
            for _ in 0..2 {
                lire_ligne(&mut serveur, &mut auth);
                serveur.write_all(b"REJECTED EXTERNAL\r\n").unwrap();
            }
        });
        assert!(Bus::sur(client).is_err());
        fil.join().unwrap();
    }

    /// Une erreur du service arrive comme une erreur, avec son nom et son message ; une propriété arrive sans sa
    /// variante.
    #[test]
    fn erreur_et_propriete() {
        let (client, fil) = faux_bus(|s, appel| {
            assert_eq!(appel.corps, vec![t("org.freedesktop.UDisks2.Drive"), t("Model")]);
            let erreur = Message {
                genre: ERREUR,
                serie: 3,
                reponse_a: Some(appel.serie),
                nom_erreur: Some("org.freedesktop.DBus.Error.UnknownInterface".into()),
                signature: "s".into(),
                corps: vec![t("pas là")],
                ..Message::default()
            };
            s.write_all(&erreur.encoder().unwrap()).unwrap();
        });
        let mut bus = Bus::sur(client).unwrap();
        let r = bus.propriete(
            "org.freedesktop.UDisks2",
            "/a",
            "org.freedesktop.UDisks2.Drive",
            "Model",
        );
        assert_eq!(r.unwrap_err(), "org.freedesktop.DBus.Error.UnknownInterface : pas là");
        fil.join().unwrap();
        // Un service absent du bus n'est pas une lecture qui échoue ; un refus ou un autre nom, si.
        assert!(service_absent(
            "org.freedesktop.DBus.Error.ServiceUnknown : The name is not activatable"
        ));
        assert!(service_absent("org.freedesktop.DBus.Error.NameHasNoOwner : x"));
        assert!(!service_absent("org.freedesktop.DBus.Error.AccessDenied : x"));
        assert!(!service_absent("org.freedesktop.DBus.Error.ServiceUnknownX : x"));

        let (client, fil) = faux_bus(|s, appel| {
            s.write_all(&retour(
                &appel,
                "v",
                vec![Valeur::Variante("s".into(), Box::new(t("Disque")))],
            ))
            .unwrap();
        });
        let mut bus = Bus::sur(client).unwrap();
        let r = bus.propriete(
            "org.freedesktop.UDisks2",
            "/a",
            "org.freedesktop.UDisks2.Drive",
            "Model",
        );
        assert_eq!(r.unwrap(), t("Disque"));
        fil.join().unwrap();
    }

    /// Un bus qui ne répond plus : le client abandonne au bout du délai au lieu d'attendre toujours.
    #[test]
    fn bus_muet() {
        let (client, _serveur) = UnixStream::pair().unwrap();
        let mut bus = Bus {
            prise: client,
            serie: 0,
            casse: false,
        };
        let echeance = Instant::now() + Duration::from_millis(50);
        assert!(bus.recevoir(echeance, 1).is_err());
    }

    /// Un délai dépassé au milieu d'un message condamne la connexion : la suite du message, arrivée après, n'est
    /// jamais prise pour le début d'un autre, et l'appel suivant échoue aussitôt, sans rien envoyer ni attendre.
    #[test]
    fn connexion_condamnee_apres_une_lecture_coupee() {
        let (client, mut serveur) = UnixStream::pair().unwrap();
        let mut bus = Bus {
            prise: client,
            serie: 0,
            casse: false,
        };
        let appel = Message {
            serie: 1,
            ..Message::default()
        };
        let reponse = retour(&appel, "s", vec![t("x")]);
        serveur.write_all(&reponse[..20]).unwrap();
        assert!(bus.recevoir(Instant::now() + Duration::from_millis(50), 1).is_err());
        // La suite du message et une réponse entière arrivent trop tard : la prise est déjà fermée de ce côté.
        assert!(serveur.write_all(&reponse[20..]).is_err());
        let debut = Instant::now();
        let r = bus.proprietes(SYSTEMD, "/a", UNITE);
        assert_eq!(
            r.unwrap_err(),
            tr!(
                "connexion au bus fermée après une erreur",
                "bus connection closed after an error"
            )
        );
        assert!(debut.elapsed() < Duration::from_secs(1));
        // Rien n'est parti après la coupure, et la prise est fermée de son côté.
        assert_eq!(serveur.read(&mut [0; 1]).unwrap(), 0);
        // Un message entier mais mal formé, lui, ne condamne rien : le flux reste aligné.
        let (client, mut serveur) = UnixStream::pair().unwrap();
        let mut bus = Bus {
            prise: client,
            serie: 0,
            casse: false,
        };
        let mut faux = reponse.clone();
        faux[3] = 2;
        serveur.write_all(&faux).unwrap();
        serveur.write_all(&reponse).unwrap();
        let echeance = Instant::now() + Duration::from_secs(5);
        assert!(bus.recevoir(echeance, 1).is_err());
        assert_eq!(bus.recevoir(echeance, 1).unwrap().corps, vec![t("x")]);
    }

    /// Trop de valeurs dans un message (un « ay » de plusieurs millions d'octets en ferait autant de 32 octets en
    /// mémoire) : refusé dès la limite. Juste en dessous, il passe.
    #[test]
    fn trop_de_valeurs() {
        let octets = |n: usize| {
            let mut o = u32::try_from(n).unwrap().to_le_bytes().to_vec();
            o.resize(4 + n, 7);
            o
        };
        let lire = |o: &[u8]| {
            Lecteur {
                octets: o,
                pos: 0,
                grand_boutiste: false,
                valeurs: 0,
            }
            .lire(b"ay", 0)
        };
        // Le tableau compte pour une valeur.
        assert_eq!(
            lire(&octets(VALEURS_MAX - 1)).unwrap().elements().len(),
            VALEURS_MAX - 1
        );
        assert_eq!(lire(&octets(VALEURS_MAX)), Err(mal_forme("trop de valeurs")));
    }

    /// Le corps d'un message qui ne répond pas à l'appel en cours n'est pas décodé : un signal envoyé par n'importe
    /// quel compte, même au corps énorme ou faux, ne coûte rien et ne fait pas échouer l'appel.
    #[test]
    fn corps_des_autres_messages_ignore() {
        let mut signal = Message {
            genre: SIGNAL,
            serie: 5,
            chemin: Some("/a".into()),
            interface: Some("a.b".into()),
            membre: Some("C".into()),
            signature: "u".into(),
            corps: vec![Valeur::U32(2)],
            ..Message::default()
        }
        .encoder()
        .unwrap();
        // Le même corps lu comme un booléen : 2 n'en est pas un.
        let i = signal.windows(4).position(|f| f == [b'g', 0, 1, b'u']).unwrap();
        signal[i + 3] = b'b';
        assert!(Message::decoder(&signal).is_err());
        let m = Message::decoder_si(&signal, |_| false).unwrap();
        assert_eq!((m.genre, m.corps.len()), (SIGNAL, 0));
        let (client, mut serveur) = UnixStream::pair().unwrap();
        let mut bus = Bus {
            prise: client,
            serie: 0,
            casse: false,
        };
        let appel = Message {
            serie: 1,
            ..Message::default()
        };
        serveur.write_all(&signal).unwrap();
        // Une réponse à un autre appel, au corps faux elle aussi.
        let mut autre = retour(
            &Message {
                serie: 9,
                ..appel.clone()
            },
            "u",
            vec![Valeur::U32(2)],
        );
        let i = autre.windows(4).position(|f| f == [b'g', 0, 1, b'u']).unwrap();
        autre[i + 3] = b'b';
        serveur.write_all(&autre).unwrap();
        serveur.write_all(&retour(&appel, "s", vec![t("x")])).unwrap();
        let echeance = Instant::now() + Duration::from_secs(5);
        for _ in 0..2 {
            assert_eq!(bus.recevoir(echeance, 1).unwrap().corps, Vec::new());
        }
        assert_eq!(bus.recevoir(echeance, 1).unwrap().corps, vec![t("x")]);
    }

    #[test]
    fn adresse_du_bus_de_la_session() {
        assert_eq!(
            chemin_de_session("unix:path=/run/user/1000/bus,guid=0123"),
            Some(std::path::PathBuf::from("/run/user/1000/bus"))
        );
        assert_eq!(
            chemin_de_session("unix:abstract=/tmp/x;unix:path=/run/bus"),
            Some(std::path::PathBuf::from("/run/bus"))
        );
        assert_eq!(chemin_de_session("tcp:host=192.0.2.1,port=1"), None);
    }

    /// Le vrai bus système, quand il est là : les unités en échec sont celles que dit `systemctl --failed`.
    #[test]
    fn en_echec_comme_systemctl() {
        // Un bus injoignable rend la lecture croisée « sautée », ce qui suffit à l'autotest ; mais si systemctl
        // répond, le bus système répond aussi, et le test doit échouer plutôt que se dire sauté.
        if crate::commande::lancer(
            std::process::Command::new("systemctl").args(["--failed", "--no-legend", "--plain"]),
            20,
        )
        .is_some_and(|r| r.code == Some(0))
        {
            Bus::systeme().expect("systemctl répond : le bus système aussi");
        }
        crate::autotest::croisees::essayer("AUT-LNX-007");
    }

    #[test]
    fn noms_d_unites_completes() {
        assert_eq!(nom_d_unite("sshd"), "sshd.service");
        assert_eq!(nom_d_unite("ssh.socket"), "ssh.socket");
        assert_eq!(nom_d_unite("auditd.service"), "auditd.service");
        assert_eq!(nom_d_unite("multi-user.target"), "multi-user.target");
        assert_eq!(
            nom_d_unite("systemd-tmpfiles-clean.timer"),
            "systemd-tmpfiles-clean.timer"
        );
        // Un point dans le nom n'est pas un suffixe.
        assert_eq!(nom_d_unite("org.cups.cupsd"), "org.cups.cupsd.service");
    }

    /// GetUnit puis la propriété ActiveState : le chemin rendu est celui qui est lu ; une unité absente est
    /// inactive (vérifié), une autre erreur reste une erreur.
    #[test]
    fn etat_d_activite_par_un_faux_bus() {
        let (client, fil) = faux_bus(|s, appel| {
            assert_eq!(appel.membre.as_deref(), Some("GetUnit"));
            assert_eq!(appel.corps, vec![t("sshd.service")]);
            s.write_all(&retour(
                &appel,
                "o",
                vec![t("/org/freedesktop/systemd1/unit/ssh_2eservice")],
            ))
            .unwrap();
            let get = lire_message(s);
            assert_eq!(
                get.chemin.as_deref(),
                Some("/org/freedesktop/systemd1/unit/ssh_2eservice")
            );
            assert_eq!(get.corps, vec![t(UNITE), t("ActiveState")]);
            s.write_all(&retour(
                &get,
                "v",
                vec![Valeur::Variante("s".into(), Box::new(t("active")))],
            ))
            .unwrap();
        });
        let mut bus = Bus::sur(client).unwrap();
        assert_eq!(etat_d_activite(&mut bus, "sshd").unwrap().as_deref(), Some("active"));
        fil.join().unwrap();

        let erreur = |nom: &'static str| {
            move |s: &mut UnixStream, appel: Message| {
                let m = Message {
                    genre: ERREUR,
                    serie: 3,
                    reponse_a: Some(appel.serie),
                    nom_erreur: Some(nom.into()),
                    signature: "s".into(),
                    corps: vec![t("Unit ufw.service not loaded.")],
                    ..Message::default()
                };
                s.write_all(&m.encoder().unwrap()).unwrap();
            }
        };
        let (client, fil) = faux_bus(erreur("org.freedesktop.systemd1.NoSuchUnit"));
        let mut bus = Bus::sur(client).unwrap();
        assert_eq!(etat_d_activite(&mut bus, "ufw"), Ok(None));
        fil.join().unwrap();
        let (client, fil) = faux_bus(erreur("org.freedesktop.DBus.Error.AccessDenied"));
        let mut bus = Bus::sur(client).unwrap();
        assert!(etat_d_activite(&mut bus, "ufw").is_err());
        fil.join().unwrap();
    }
}

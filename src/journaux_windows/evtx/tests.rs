//! Les essais du lecteur .evtx : des fichiers fabriqués ici, octet par octet (en-tête, morceau, enregistrements,
//! gabarits, CRC justes), puis abîmés de façon contrôlée ; des octets au hasard (proptest) ; et la lecture croisée
//! avec la crate `evtx` (dépendance de développement seulement) sur ces fichiers et sur des échantillons publics
//! (`VANGUARD_EVTX_ECHANTILLONS`, jamais dans le dépôt).

use std::collections::{BTreeMap, HashMap};

use super::*;

// ---- Fabrication ----

/// Un nœud de gabarit : élément (nom, attributs, contenu) ou morceau de texte.
#[derive(Clone)]
enum G {
    E(&'static str, Vec<(&'static str, P)>, Vec<G>),
    P(P),
}

/// Texte, substitution (indice, type attendu), substitution optionnelle.
#[derive(Clone, Copy)]
enum P {
    T(&'static str),
    S(u16, u8),
    O(u16, u8),
}

/// Une valeur de substitution.
enum V {
    Nul,
    Chaine(&'static str),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Ft(u64),
    Sid(Vec<u8>),
    Guid([u8; 16]),
    /// Type et octets tels quels (tableaux, types inconnus).
    Brut(u8, Vec<u8>),
    /// Un fragment BinXml écrit en place.
    BinXml(Box<dyn Fn(&mut Ecrivain)>),
}

fn e(nom: &'static str, attributs: Vec<(&'static str, P)>, contenu: Vec<G>) -> G {
    G::E(nom, attributs, contenu)
}

/// Un élément qui ne contient qu'une substitution.
fn s(nom: &'static str, id: u16, type_valeur: u8) -> G {
    G::E(nom, vec![], vec![G::P(P::S(id, type_valeur))])
}

fn data(nom: &'static str, piece: P) -> G {
    G::E("Data", vec![("Name", P::T(nom))], vec![G::P(piece)])
}

const XMLNS: &str = "http://schemas.microsoft.com/win/2004/08/events/event";

/// Un gabarit comme celui des événements de sécurité : System complet, EventData avec un champ optionnel, un
/// tableau et une valeur d'un type inconnu.
fn gabarit_securite() -> G {
    e(
        "Event",
        vec![("xmlns", P::T(XMLNS))],
        vec![
            e(
                "System",
                vec![],
                vec![
                    e("Provider", vec![("Name", P::S(0, 1)), ("Guid", P::O(1, 0x0F))], vec![]),
                    s("EventID", 2, 6),
                    s("Level", 3, 4),
                    e("TimeCreated", vec![("SystemTime", P::S(4, 0x11))], vec![]),
                    s("EventRecordID", 5, 0x0A),
                    e("Correlation", vec![("ActivityID", P::O(6, 0x0F))], vec![]),
                    s("Channel", 7, 1),
                    s("Computer", 8, 1),
                    e("Security", vec![("UserID", P::O(9, 0x13))], vec![]),
                ],
            ),
            e(
                "EventData",
                vec![],
                vec![
                    data("TargetUserName", P::S(10, 1)),
                    data("IpAddress", P::O(11, 1)),
                    data("LogonType", P::S(12, 8)),
                    data("Groupes", P::S(13, 0x81)),
                    data("Etrange", P::S(14, 0x20)),
                ],
            ),
        ],
    )
}

/// Un événement à UserData, dont le contenu est une valeur BinXml (comme 1102, journal effacé).
fn gabarit_userdata() -> G {
    e(
        "Event",
        vec![("xmlns", P::T(XMLNS))],
        vec![
            e(
                "System",
                vec![],
                vec![
                    e("Provider", vec![("Name", P::S(0, 1))], vec![]),
                    s("EventID", 1, 6),
                    e("TimeCreated", vec![("SystemTime", P::S(2, 0x11))], vec![]),
                    s("EventRecordID", 3, 0x0A),
                    s("Channel", 4, 1),
                    s("Computer", 5, 1),
                ],
            ),
            e("UserData", vec![], vec![G::P(P::S(6, 0x21))]),
        ],
    )
}

fn gabarit_effacement() -> G {
    e(
        "LogFileCleared",
        vec![(
            "xmlns",
            P::T("http://manifests.microsoft.com/win/2004/08/windows/eventlog"),
        )],
        vec![s("SubjectUserName", 0, 1), s("SubjectDomainName", 1, 1)],
    )
}

/// L'empreinte d'un nom ([MS-EVEN6] 2.2.12, NameHash : hash = hash × 65599 + caractère, 16 bits du bas).
fn empreinte(nom: &str) -> u16 {
    let h = nom
        .encode_utf16()
        .fold(0u32, |h, c| h.wrapping_mul(65_599).wrapping_add(u32::from(c)));
    u16::try_from(h & 0xFFFF).unwrap()
}

/// Un morceau en cours d'écriture : les positions sont celles du morceau, comme dans le fichier.
struct Ecrivain {
    o: Vec<u8>,
    noms: HashMap<&'static str, u32>,
    gabarits: HashMap<u32, u32>,
    enregistrements: Vec<(u64, usize)>,
    /// La place de l'ElementByteLength de chaque élément écrit.
    longueurs: Vec<usize>,
}

fn pos32(p: usize) -> u32 {
    u32::try_from(p).unwrap()
}

impl Ecrivain {
    fn new() -> Self {
        Self {
            o: vec![0; EN_TETE_MORCEAU],
            noms: HashMap::new(),
            gabarits: HashMap::new(),
            enregistrements: Vec::new(),
            longueurs: Vec::new(),
        }
    }
    fn pos(&self) -> usize {
        self.o.len()
    }
    fn u8(&mut self, v: u8) {
        self.o.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.o.extend(v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.o.extend(v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.o.extend(v.to_le_bytes());
    }
    fn octets(&mut self, o: &[u8]) {
        self.o.extend_from_slice(o);
    }
    fn reecrire_u32(&mut self, ou: usize, v: u32) {
        self.o[ou..ou + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn longueur_depuis(&mut self, champ: usize) {
        let n = pos32(self.pos() - champ - 4);
        self.reecrire_u32(champ, n);
    }
    fn utf16(&mut self, t: &str) {
        for c in t.encode_utf16() {
            self.u16(c);
        }
    }

    /// Un nom rangé en place la première fois, désigné par sa position ensuite.
    fn nom(&mut self, nom: &'static str) {
        if let Some(&p) = self.noms.get(nom) {
            self.u32(p);
            return;
        }
        let p = pos32(self.pos() + 4);
        self.noms.insert(nom, p);
        self.u32(p);
        self.u32(0);
        self.u16(empreinte(nom));
        self.u16(u16::try_from(nom.encode_utf16().count()).unwrap());
        self.utf16(nom);
        self.u16(0);
    }

    fn piece(&mut self, p: P) {
        match p {
            P::T(t) => {
                self.u8(0x05);
                self.u8(0x01);
                self.u16(u16::try_from(t.encode_utf16().count()).unwrap());
                self.utf16(t);
            }
            P::S(id, t) | P::O(id, t) => {
                self.u8(if matches!(p, P::S(..)) { 0x0D } else { 0x0E });
                self.u16(id);
                self.u8(t);
            }
        }
    }

    /// Un élément de gabarit : avec DependencyId (0xFFFF), longueurs justes.
    fn element(&mut self, g: &G) {
        match g {
            G::P(p) => self.piece(*p),
            G::E(nom, attributs, contenu) => {
                self.u8(if attributs.is_empty() { 0x01 } else { 0x41 });
                self.u16(0xFFFF);
                let taille = self.pos();
                self.longueurs.push(taille);
                self.u32(0);
                self.nom(nom);
                if !attributs.is_empty() {
                    let liste = self.pos();
                    self.u32(0);
                    for (i, (n, p)) in attributs.iter().enumerate() {
                        self.u8(if i + 1 < attributs.len() { 0x46 } else { 0x06 });
                        self.nom(n);
                        self.piece(*p);
                    }
                    self.longueur_depuis(liste);
                }
                if contenu.is_empty() {
                    self.u8(0x03);
                } else {
                    self.u8(0x02);
                    for c in contenu {
                        self.element(c);
                    }
                    self.u8(0x04);
                }
                self.longueur_depuis(taille);
            }
        }
    }

    /// Une instance : la définition en place la première fois (identifiée par `id`), désignée ensuite.
    fn instance(&mut self, id: u32, gabarit: &G, valeurs: &[V]) {
        self.u8(0x0C);
        self.u8(0x01);
        self.u32(id);
        if let Some(&d) = self.gabarits.get(&id) {
            self.u32(d);
        } else {
            let d = pos32(self.pos() + 4);
            self.gabarits.insert(id, d);
            self.u32(d);
            self.u32(0);
            let mut guid = [0x5A; 16];
            guid[..4].copy_from_slice(&id.to_le_bytes());
            self.octets(&guid);
            let taille = self.pos();
            self.u32(0);
            self.octets(&[0x0F, 1, 1, 0]);
            self.element(gabarit);
            self.u8(0x00);
            self.longueur_depuis(taille);
        }
        self.u32(u32::try_from(valeurs.len()).unwrap());
        let descripteurs = self.pos();
        for _ in valeurs {
            self.u32(0);
        }
        for (i, v) in valeurs.iter().enumerate() {
            let debut = self.pos();
            let t = self.valeur(v);
            let taille = u16::try_from(self.pos() - debut).unwrap();
            let d = descripteurs + 4 * i;
            self.o[d..d + 2].copy_from_slice(&taille.to_le_bytes());
            self.o[d + 2] = t;
        }
    }

    fn valeur(&mut self, v: &V) -> u8 {
        match v {
            V::Nul => 0x00,
            V::Chaine(t) => {
                self.utf16(t);
                0x01
            }
            V::U8(n) => {
                self.u8(*n);
                0x04
            }
            V::U16(n) => {
                self.u16(*n);
                0x06
            }
            V::U32(n) => {
                self.u32(*n);
                0x08
            }
            V::U64(n) => {
                self.u64(*n);
                0x0A
            }
            V::Ft(n) => {
                self.u64(*n);
                0x11
            }
            V::Sid(o) => {
                self.octets(o);
                0x13
            }
            V::Guid(g) => {
                self.octets(g);
                0x0F
            }
            V::Brut(t, o) => {
                self.octets(o);
                *t
            }
            V::BinXml(f) => {
                f(self);
                0x21
            }
        }
    }

    /// Un enregistrement : en-tête, fragment, `corps` (l'instance), fin, copie de la taille.
    fn enregistrement(&mut self, numero: u64, date: u64, corps: impl FnOnce(&mut Self)) {
        let debut = self.pos();
        self.octets(b"**\0\0");
        self.u32(0);
        self.u64(numero);
        self.u64(date);
        self.octets(&[0x0F, 1, 1, 0]);
        corps(self);
        self.u8(0x00);
        let taille = pos32(self.pos() - debut + 4);
        self.u32(taille);
        self.reecrire_u32(debut + 4, taille);
        self.enregistrements.push((numero, debut));
    }

    /// Le morceau de 64 Kio, en-tête rempli (les CRC viennent de `recalculer_crc`).
    fn finir(mut self) -> Vec<u8> {
        let libre = self.pos();
        assert!(libre <= MORCEAU, "morceau trop plein : {libre}");
        self.o.resize(MORCEAU, 0);
        self.o[..8].copy_from_slice(b"ElfChnk\0");
        let premier = self.enregistrements.first().map_or(0, |e| e.0);
        let (dernier, dernier_pos) = self.enregistrements.last().copied().unwrap_or((0, 0));
        for (ou, v) in [(8, premier), (16, dernier), (24, premier), (32, dernier)] {
            self.o[ou..ou + 8].copy_from_slice(&v.to_le_bytes());
        }
        self.reecrire_u32(40, 128);
        self.reecrire_u32(44, pos32(dernier_pos));
        self.reecrire_u32(48, pos32(libre));
        self.o
    }
}

/// 24 oct. 2026, 13:05:09,1234567 UTC en FILETIME.
const DATE: u64 = 134_373_207_091_234_567;

fn sid_systeme() -> Vec<u8> {
    vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]
}

fn guid_fournisseur() -> [u8; 16] {
    [
        0x25, 0x96, 0x84, 0x54, 0x78, 0x54, 0x94, 0x49, 0xA5, 0xBA, 0x3E, 0x3B, 0x03, 0x28, 0xC3, 0x0D,
    ]
}

fn valeurs_securite(
    id: u16,
    numero: u64,
    compte: &'static str,
    adresse: Option<&'static str>,
    etrange: bool,
) -> Vec<V> {
    let groupes: Vec<u8> = "Administrateurs\0Utilisateurs\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    vec![
        V::Chaine("Microsoft-Windows-Security-Auditing"),
        if adresse.is_some() {
            V::Guid(guid_fournisseur())
        } else {
            V::Nul
        },
        V::U16(id),
        V::U8(0),
        V::Ft(DATE + numero),
        V::U64(numero),
        V::Nul,
        V::Chaine("Security"),
        V::Chaine("poste-alice"),
        V::Sid(sid_systeme()),
        V::Chaine(compte),
        adresse.map_or(V::Nul, V::Chaine),
        V::U32(10),
        V::Brut(0x81, groupes),
        if etrange {
            V::Brut(0x20, vec![1, 2, 3])
        } else {
            V::U32(7)
        },
    ]
}

/// Trois enregistrements numérotés à partir de `premier` : un 4624 (gabarit rangé en place), un 4625 (le même
/// gabarit désigné, valeurs optionnelles nulles), un 1102 à UserData (valeur BinXml portant sa propre instance).
pub(crate) fn morceau_type(premier: u64) -> Vec<u8> {
    morceau_type_avec(premier, true)
}

/// Le morceau type ; `etrange` : avec la valeur EvtHandle (type 0x20), que nous rendons « inconnu ».
fn morceau_type_avec(premier: u64, etrange: bool) -> Vec<u8> {
    let mut m = Ecrivain::new();
    m.enregistrement(premier, DATE + premier, |m| {
        m.instance(
            1,
            &gabarit_securite(),
            &valeurs_securite(4624, premier, "alice", Some("192.0.2.10"), etrange),
        );
    });
    m.enregistrement(premier + 1, DATE + premier + 1, |m| {
        m.instance(
            1,
            &gabarit_securite(),
            &valeurs_securite(4625, premier + 1, "bob", None, etrange),
        );
    });
    m.enregistrement(premier + 2, DATE + premier + 2, |m| {
        let effacement = V::BinXml(Box::new(|m| {
            m.octets(&[0x0F, 1, 1, 0]);
            m.instance(3, &gabarit_effacement(), &[V::Chaine("alice"), V::Chaine("POSTE")]);
            m.u8(0x00);
        }));
        m.instance(
            2,
            &gabarit_userdata(),
            &[
                V::Chaine("Microsoft-Windows-Eventlog"),
                V::U16(1102),
                V::Ft(DATE + premier + 2),
                V::U64(premier + 2),
                V::Chaine("Security"),
                V::Chaine("poste-alice"),
                effacement,
            ],
        );
    });
    m.finir()
}

/// Un fichier : en-tête puis les morceaux donnés, CRC recalculés.
pub(crate) fn fichier(morceaux: &[Vec<u8>]) -> Vec<u8> {
    let mut f = vec![0u8; EN_TETE];
    f[..8].copy_from_slice(b"ElfFile\0");
    let n = u64::try_from(morceaux.len()).unwrap();
    f[16..24].copy_from_slice(&n.saturating_sub(1).to_le_bytes());
    f[24..32].copy_from_slice(&(3 * n + 1).to_le_bytes());
    f[32..36].copy_from_slice(&128u32.to_le_bytes());
    f[36..38].copy_from_slice(&1u16.to_le_bytes());
    f[38..40].copy_from_slice(&3u16.to_le_bytes());
    f[40..42].copy_from_slice(&4096u16.to_le_bytes());
    f[42..44].copy_from_slice(&u16::try_from(n).unwrap().to_le_bytes());
    for m in morceaux {
        f.extend_from_slice(m);
    }
    recalculer_crc(&mut f);
    f
}

/// Un morceau d'échecs de connexion (4625, journal Security) aux numéros d'enregistrement donnés, dans cet ordre,
/// l'EventRecordID de chacun valant `origine(numéro)` et sa date `DATE` plus son numéro : l'en-tête du morceau
/// annonce du premier au dernier, comme Windows l'écrit. Pour les essais de la suite des numéros
/// (journaux_windows::fichiers).
pub(crate) fn morceau_aux_numeros(numeros: &[u64], origine: impl Fn(u64) -> u64) -> Vec<u8> {
    let mut m = Ecrivain::new();
    for &n in numeros {
        m.enregistrement(n, DATE + n, |m| {
            m.instance(
                1,
                &gabarit_securite(),
                &valeurs_securite(4625, origine(n), "alice", Some("192.0.2.10"), false),
            );
        });
    }
    m.finir()
}

fn fichier_type() -> Vec<u8> {
    fichier(&[morceau_type(1)])
}

fn champ<'a>(e: &'a Enregistrement, nom: &str) -> Option<&'a str> {
    e.champs.iter().find(|(n, _)| n == nom).map(|(_, v)| v.as_str())
}

fn lire_type(octets: &[u8]) -> Lecture {
    lire_octets(octets, &Bornes::default()).unwrap()
}

// ---- Fichiers fabriqués ----

#[test]
fn un_fichier_fabrique_se_lit_entier() {
    let lu = lire_type(&fichier_type());
    let bilan = &lu.bilan;
    assert_eq!(
        (
            bilan.morceaux_lus,
            bilan.enregistrements_lus,
            bilan.enregistrements_illisibles
        ),
        (1, 3, 0),
        "{bilan:?}"
    );
    // La valeur de type 0x20 (EvtHandle) : rendue « inconnu », comptée, l'enregistrement gardé.
    assert_eq!(bilan.valeurs_inconnues, 2, "{bilan:?}");
    assert!(!bilan.complet());
    let [ouverture, echec, effacement] = &lu.enregistrements[..] else {
        panic!("{:?}", lu.enregistrements)
    };

    assert_eq!(
        (
            ouverture.numero,
            ouverture.numero_systeme,
            ouverture.id,
            ouverture.niveau
        ),
        (1, Some(1), Some(4624), Some(0))
    );
    assert_eq!(ouverture.fournisseur, "Microsoft-Windows-Security-Auditing");
    assert_eq!(
        (ouverture.canal.as_str(), ouverture.ordinateur.as_str()),
        ("Security", "poste-alice")
    );
    assert_eq!(ouverture.date, valeurs::filetime(DATE + 1));
    assert_eq!(ouverture.cree, valeurs::filetime(DATE + 1));
    assert_eq!(valeurs::date(ouverture.cree.unwrap()), "2026-10-24T13:05:09.1234568Z");
    assert_eq!(champ(ouverture, "TargetUserName"), Some("alice"));
    assert_eq!(champ(ouverture, "IpAddress"), Some("192.0.2.10"));
    assert_eq!(champ(ouverture, "LogonType"), Some("10"));
    assert_eq!(champ(ouverture, "Etrange"), Some(valeurs::INCONNU));
    // Un tableau : l'élément répété pour chaque case ([MS-EVEN6] 3.1.4.7.5).
    let groupes: Vec<&str> = ouverture
        .champs
        .iter()
        .filter(|(n, _)| n == "Groupes")
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(groupes, ["Administrateurs", "Utilisateurs"]);
    let systeme = ouverture.evenement.enfant("System").unwrap();
    let fournisseur = systeme.enfant("Provider").unwrap();
    assert_eq!(
        fournisseur.attribut("Guid"),
        Some("{54849625-5478-4994-A5BA-3E3B0328C30D}")
    );
    assert_eq!(systeme.enfant("Security").unwrap().attribut("UserID"), Some("S-1-5-18"));
    assert_eq!(ouverture.evenement.attribut("xmlns"), Some(XMLNS));

    // Le même gabarit désigné : les substitutions optionnelles nulles ôtent attribut et élément.
    assert_eq!((echec.numero, echec.id), (2, Some(4625)));
    assert_eq!(champ(echec, "TargetUserName"), Some("bob"));
    assert_eq!(champ(echec, "IpAddress"), None);
    let systeme = echec.evenement.enfant("System").unwrap();
    assert_eq!(systeme.enfant("Provider").unwrap().attribut("Guid"), None);
    assert_eq!(systeme.enfant("Correlation").unwrap().attributs.len(), 0);

    // Une valeur BinXml portant sa propre instance de gabarit : UserData.
    assert_eq!(
        (effacement.numero, effacement.id, effacement.fournisseur.as_str()),
        (3, Some(1102), "Microsoft-Windows-Eventlog")
    );
    assert_eq!(
        effacement.champs,
        [
            ("SubjectUserName".to_string(), "alice".to_string()),
            ("SubjectDomainName".to_string(), "POSTE".to_string())
        ]
    );
    let journal = effacement
        .evenement
        .enfant("UserData")
        .unwrap()
        .enfant("LogFileCleared")
        .unwrap();
    assert_eq!(
        journal.attribut("xmlns"),
        Some("http://manifests.microsoft.com/win/2004/08/windows/eventlog")
    );
}

#[test]
fn le_fichier_et_la_memoire_se_lisent_pareil() {
    let octets = fichier_type();
    let dossier = std::env::temp_dir().join(format!("vanguard-evtx-{}", std::process::id()));
    std::fs::create_dir_all(&dossier).unwrap();
    let chemin = dossier.join("essai.evtx");
    std::fs::write(&chemin, &octets).unwrap();
    let lu = lire_fichier(&chemin, &Bornes::default()).unwrap();
    let _ = std::fs::remove_dir_all(&dossier);
    assert_eq!(lu, lire_type(&octets));
    match lire_fichier(&dossier.join("absent.evtx"), &Bornes::default()) {
        Err(Erreur::Lecture(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
        autre => panic!("{autre:?}"),
    }
}

#[test]
fn ce_qui_n_est_pas_un_evtx_est_refuse() {
    for octets in [&b""[..], b"ElfFile\0", &[0u8; 5000], &fichier_type()[..4095]] {
        assert!(matches!(
            lire_octets(octets, &Bornes::default()),
            Err(Erreur::PasUnEvtx)
        ));
    }
    let mut f = fichier_type();
    f[0] = b'e';
    assert!(matches!(lire_octets(&f, &Bornes::default()), Err(Erreur::PasUnEvtx)));
}

#[test]
fn un_crc_faux_ecarte_le_morceau_sans_taire_les_suivants() {
    let mut f = fichier(&[morceau_type(1), morceau_type(4), morceau_type(7)]);
    // Un octet d'un enregistrement du deuxième morceau, après le calcul des CRC.
    f[EN_TETE + MORCEAU + 600] ^= 0xFF;
    let lu = lire_type(&f);
    assert_eq!(
        (lu.bilan.morceaux_lus, lu.bilan.morceaux_illisibles),
        (2, 1),
        "{:?}",
        lu.bilan
    );
    let numeros: Vec<u64> = lu.enregistrements.iter().map(|e| e.numero).collect();
    assert_eq!(numeros, [1, 2, 3, 7, 8, 9]);
    // L'en-tête du morceau abîmé, cette fois.
    let mut f = fichier(&[morceau_type(1), morceau_type(4)]);
    f[EN_TETE + 300] ^= 1;
    let lu = lire_type(&f);
    assert_eq!((lu.bilan.morceaux_lus, lu.bilan.morceaux_illisibles), (1, 1));
    assert_eq!(lu.enregistrements[0].numero, 4);
}

#[test]
fn un_en_tete_de_fichier_abime_n_empeche_pas_de_lire_les_morceaux() {
    let mut f = fichier_type();
    // Le nombre de morceaux annoncé change, le CRC de l'en-tête ne suit pas.
    f[42] = 9;
    let lu = lire_type(&f);
    assert!(lu.bilan.en_tete_abime);
    assert!(!lu.bilan.complet());
    assert_eq!(lu.enregistrements.len(), 3);
}

/// Chaque morceau lu ou écarté laisse son récapitulatif (sa plage annoncée quand son en-tête est juste, ce qu'il n'a
/// pas rendu) et chaque événement le rang de son morceau : de quoi juger la suite des numéros (journaux_windows::trous).
#[test]
fn chaque_morceau_laisse_son_recapitulatif() {
    let mut f = fichier(&[
        morceau_type(1),
        vec![0; MORCEAU],
        morceau_type(4),
        morceau_type(7),
        morceau_type(10),
    ]);
    // Le morceau de rang 3 : un octet de ses enregistrements changé, son en-tête (qui porte le CRC des
    // enregistrements) juste. Celui de rang 4 : en-tête faux.
    f[EN_TETE + 3 * MORCEAU + EN_TETE_MORCEAU + 40] ^= 0xFF;
    f[EN_TETE + 4 * MORCEAU + 124] ^= 0xFF;
    // Un morceau coupé en fin de fichier.
    f.extend_from_slice(&[b'E'; 100]);
    let lu = lire_type(&f);
    let recap = |rang, lu, annonce, non_rendus| RecapMorceau {
        rang,
        lu,
        annonce,
        non_rendus,
    };
    assert_eq!(
        lu.bilan.morceaux,
        [
            recap(0, true, Some((1, 3)), 0),
            recap(2, true, Some((4, 6)), 0),
            recap(3, false, Some((7, 9)), 0),
            recap(4, false, None, 0),
            recap(5, false, None, 0),
        ]
    );
    assert_eq!(lu.bilan.morceaux_sans_recap, 0);
    let rangs: Vec<(u64, u64)> = lu.enregistrements.iter().map(|e| (e.numero, e.morceau)).collect();
    assert_eq!(rangs, [(1, 0), (2, 0), (3, 0), (4, 2), (5, 2), (6, 2)]);
    // Un enregistrement illisible ou laissé au-delà de la borne compte dans son morceau.
    let bornes = Bornes {
        enregistrements: 2,
        ..Bornes::default()
    };
    let lu = lire_octets(&fichier(&[morceau_type(1), morceau_type(4)]), &bornes).unwrap();
    assert_eq!(lu.bilan.morceaux, [recap(0, true, Some((1, 3)), 1)]);
    assert_eq!(lu.bilan.morceaux_hors_borne, 1);
}

#[test]
fn les_morceaux_vides_ne_sont_pas_des_pertes() {
    let lu = lire_type(&fichier(&[morceau_type(1), vec![0; MORCEAU], Ecrivain::new().finir()]));
    assert_eq!(
        (
            lu.bilan.morceaux_lus,
            lu.bilan.morceaux_vides,
            lu.bilan.morceaux_illisibles
        ),
        (1, 2, 0)
    );
}

#[test]
fn un_morceau_coupe_en_fin_de_fichier_est_compte() {
    let f = fichier(&[morceau_type(1), morceau_type(4)]);
    let lu = lire_type(&f[..f.len() - 100]);
    assert_eq!((lu.bilan.morceaux_lus, lu.bilan.morceaux_illisibles), (1, 1));
    assert_eq!(lu.enregistrements.len(), 3);
}

/// L'enregistrement `rang` du morceau type, à sa place dans le fichier.
fn position_enregistrement(rang: usize) -> usize {
    let mut pos = EN_TETE + EN_TETE_MORCEAU;
    let f = fichier_type();
    for _ in 0..rang {
        pos += usize::try_from(u32_a(&f, pos + 4).unwrap()).unwrap();
    }
    pos
}

#[test]
fn un_enregistrement_abime_est_compte_et_la_lecture_continue() {
    // La copie de la taille du deuxième enregistrement : la suite est retrouvée à la signature suivante.
    let mut f = fichier_type();
    let deuxieme = position_enregistrement(1);
    let taille = usize::try_from(u32_a(&f, deuxieme + 4).unwrap()).unwrap();
    f[deuxieme + taille - 4] ^= 0x10;
    recalculer_crc(&mut f);
    let lu = lire_type(&f);
    assert_eq!(lu.bilan.enregistrements_illisibles, 1, "{:?}", lu.bilan);
    assert_eq!(lu.enregistrements.iter().map(|e| e.numero).collect::<Vec<_>>(), [1, 3]);

    // Un jeton impossible dans le BinXml du troisième : lui seul est perdu.
    let mut f = fichier_type();
    let troisieme = position_enregistrement(2);
    f[troisieme + 24 + 4] = 0x3F;
    recalculer_crc(&mut f);
    let lu = lire_type(&f);
    assert_eq!(lu.bilan.enregistrements_illisibles, 1);
    assert_eq!(lu.enregistrements.iter().map(|e| e.numero).collect::<Vec<_>>(), [1, 2]);
}

#[test]
fn les_bornes_de_nombre_et_de_taille_sont_tenues_et_dites() {
    let f = fichier(&[morceau_type(1), morceau_type(4), morceau_type(7)]);
    let bornes = Bornes {
        enregistrements: 4,
        ..Bornes::default()
    };
    let lu = lire_octets(&f, &bornes).unwrap();
    assert_eq!(lu.enregistrements.len(), 4);
    assert_eq!(
        (lu.bilan.enregistrements_hors_borne, lu.bilan.morceaux_hors_borne),
        (2, 1),
        "{:?}",
        lu.bilan
    );
    assert!(!lu.bilan.complet());

    let bornes = Bornes {
        taille_fichier: (EN_TETE + 2 * MORCEAU) as u64,
        ..Bornes::default()
    };
    let lu = lire_octets(&f, &bornes).unwrap();
    assert_eq!((lu.bilan.morceaux_lus, lu.bilan.morceaux_hors_borne), (2, 1));
    assert_eq!(lu.enregistrements.len(), 6);
}

#[test]
fn les_chaines_trop_longues_sont_coupees_et_comptees() {
    let bornes = Bornes {
        texte: 4,
        ..Bornes::default()
    };
    let lu = lire_octets(&fichier_type(), &bornes).unwrap();
    assert_eq!(lu.enregistrements.len(), 3);
    assert_eq!(lu.enregistrements[0].fournisseur, "Micr");
    assert!(lu.bilan.chaines_tronquees > 0);
}

/// Un enregistrement seul dans un morceau, au corps écrit par `corps`.
fn fichier_d_un_enregistrement(corps: impl FnOnce(&mut Ecrivain)) -> Vec<u8> {
    let mut m = Ecrivain::new();
    m.enregistrement(1, DATE, corps);
    fichier(&[m.finir()])
}

#[test]
fn trop_de_substitutions_annoncees_fait_perdre_l_enregistrement_seul() {
    let f = fichier_d_un_enregistrement(|m| {
        m.instance(1, &s("Event", 0, 1), &[]);
        // Le nombre de valeurs, réécrit : 5 000, que rien ne suit.
        let n = m.pos() - 4;
        m.reecrire_u32(n, 5000);
    });
    let lu = lire_type(&f);
    assert_eq!(
        (lu.bilan.enregistrements_lus, lu.bilan.enregistrements_illisibles),
        (0, 1)
    );
    let noeud = rendre_binxml(&f[EN_TETE..EN_TETE + MORCEAU], EN_TETE_MORCEAU + 24, &Bornes::default());
    assert_eq!(noeud, Err(ErreurBinxml::Substitutions));
}

#[test]
fn une_definition_de_gabarit_qui_contient_une_instance_s_arrete() {
    // Le corps d'une définition ne peut pas porter d'instance (la grammaire ne l'y met pas) : un gabarit qui se
    // désignerait lui-même s'arrête là, et l'enregistrement est seul perdu.
    let f = fichier_d_un_enregistrement(|m| {
        m.u8(0x0C);
        m.u8(0x01);
        m.u32(9);
        let d = pos32(m.pos() + 4);
        m.u32(d);
        m.u32(0);
        m.octets(&[0; 16]);
        let taille = m.pos();
        m.u32(0);
        m.octets(&[0x0F, 1, 1, 0]);
        // Le corps : une instance qui désigne cette même définition.
        m.u8(0x0C);
        m.u8(0x01);
        m.u32(9);
        m.u32(d);
        m.u32(0);
        m.u8(0x00);
        m.longueur_depuis(taille);
        m.u32(0);
    });
    let lu = lire_type(&f);
    assert_eq!(
        (lu.bilan.enregistrements_lus, lu.bilan.enregistrements_illisibles),
        (0, 1)
    );
}

/// Un gabarit `Boite` qui contient une seule valeur BinXml, imbriquée `n` fois.
fn boites(m: &mut Ecrivain, n: usize) {
    let boite = e("Boite", vec![], vec![G::P(P::S(0, 0x21))]);
    if n == 0 {
        m.instance(1, &boite, &[V::Nul]);
        return;
    }
    let reste = n - 1;
    m.instance(1, &boite, &[V::BinXml(Box::new(move |m| boites(m, reste)))]);
}

#[test]
fn une_imbrication_trop_profonde_s_arrete_sans_deborder_la_pile() {
    let lu = lire_type(&fichier_d_un_enregistrement(|m| boites(m, 10)));
    assert_eq!(lu.bilan.enregistrements_lus, 1, "{:?}", lu.bilan);
    let f = fichier_d_un_enregistrement(|m| boites(m, 200));
    let lu = lire_type(&f);
    assert_eq!(
        (lu.bilan.enregistrements_lus, lu.bilan.enregistrements_illisibles),
        (0, 1)
    );
    assert_eq!(rendu_seul(&f), Err(ErreurBinxml::Profondeur));
}

/// Le BinXml du premier enregistrement d'un fichier fabriqué, rendu seul : pour voir pourquoi il échoue.
fn rendu_seul(f: &[u8]) -> Result<Noeud, ErreurBinxml> {
    rendre_binxml(&f[EN_TETE..EN_TETE + MORCEAU], EN_TETE_MORCEAU + 24, &Bornes::default())
}

#[test]
fn une_valeur_demultipliee_s_arrete_au_budget_de_travail() {
    // Trois niveaux de 300 substitutions de la même valeur : 27 millions de textes si rien ne bornait le rendu.
    fn niveau(m: &mut Ecrivain, profondeur: u32) {
        let contenu: Vec<G> = (0..300).map(|_| G::P(P::S(0, 0x21))).collect();
        let gabarit = e("N", vec![], contenu);
        let valeur = if profondeur == 0 {
            V::Chaine("x")
        } else {
            V::BinXml(Box::new(move |m| niveau(m, profondeur - 1)))
        };
        m.instance(10 + profondeur, &gabarit, &[valeur]);
    }
    let debut = std::time::Instant::now();
    let f = fichier_d_un_enregistrement(|m| niveau(m, 2));
    let lu = lire_type(&f);
    assert_eq!(
        (lu.bilan.enregistrements_lus, lu.bilan.enregistrements_illisibles),
        (0, 1)
    );
    assert_eq!(rendu_seul(&f), Err(ErreurBinxml::Travail));
    // Un seul niveau (300 textes) passe.
    assert!(rendu_seul(&fichier_d_un_enregistrement(|m| niveau(m, 0))).is_ok());
    assert!(
        debut.elapsed() < std::time::Duration::from_secs(20),
        "{:?}",
        debut.elapsed()
    );
}

#[test]
fn une_place_libre_reculee_ne_cache_rien_sans_le_dire() {
    // La place libre reculée jusqu'au troisième enregistrement, le dernier numéro et les CRC ajustés : un en-tête
    // qui se tient, et le troisième n'est plus lu (Windows ne le lirait pas non plus), mais il est compté.
    let mut f = fichier_type();
    let troisieme = position_enregistrement(2) - EN_TETE;
    f[EN_TETE + 48..EN_TETE + 52].copy_from_slice(&pos32(troisieme).to_le_bytes());
    f[EN_TETE + 16..EN_TETE + 24].copy_from_slice(&2u64.to_le_bytes());
    recalculer_crc(&mut f);
    let lu = lire_type(&f);
    assert_eq!(lu.enregistrements.len(), 2);
    assert_eq!(
        (
            lu.bilan.enregistrements_apres_place_libre,
            lu.bilan.enregistrements_absents
        ),
        (1, 0),
        "{:?}",
        lu.bilan
    );
    // Jusqu'au début : le morceau passe pour préparé sans enregistrement, les trois sont comptés quand même.
    let mut f = fichier_type();
    f[EN_TETE + 48..EN_TETE + 52].copy_from_slice(&pos32(EN_TETE_MORCEAU).to_le_bytes());
    recalculer_crc(&mut f);
    let lu = lire_type(&f);
    assert_eq!((lu.enregistrements.len(), lu.bilan.morceaux_vides), (0, 1));
    assert_eq!(lu.bilan.enregistrements_apres_place_libre, 3);
}

#[test]
fn un_element_qui_ne_finit_pas_a_sa_longueur_est_illisible() {
    let mut m = Ecrivain::new();
    m.enregistrement(1, DATE, |m| m.instance(1, &s("Event", 0, 1), &[V::Chaine("x")]));
    let longueur = m.longueurs[0];
    let mut morceau = m.finir();
    assert!(rendre_binxml(&morceau, EN_TETE_MORCEAU + 24, &Bornes::default()).is_ok());
    morceau[longueur] += 1;
    let f = fichier(&[morceau]);
    let lu = lire_type(&f);
    assert_eq!(
        (lu.bilan.enregistrements_lus, lu.bilan.enregistrements_illisibles),
        (0, 1)
    );
    assert_eq!(rendu_seul(&f), Err(ErreurBinxml::Gabarit));
}

#[test]
fn la_lecture_d_un_morceau_a_son_budget() {
    let bornes = Bornes {
        lecture_morceau: 300,
        ..Bornes::default()
    };
    let lu = lire_octets(&fichier_type(), &bornes).unwrap();
    assert!(lu.bilan.enregistrements_illisibles > 0, "{:?}", lu.bilan);
    // Le budget épuisé pendant la lecture du gabarit, puis avant même.
    let morceau = &fichier_type()[EN_TETE..EN_TETE + MORCEAU];
    let bornes = Bornes {
        lecture_morceau: 100,
        ..Bornes::default()
    };
    assert_eq!(
        rendre_binxml(morceau, EN_TETE_MORCEAU + 24, &bornes),
        Err(ErreurBinxml::Gabarit)
    );
    let bornes = Bornes {
        lecture_morceau: 4,
        ..Bornes::default()
    };
    assert_eq!(
        rendre_binxml(morceau, EN_TETE_MORCEAU + 24, &bornes),
        Err(ErreurBinxml::Lecture)
    );
}

// ---- Octets au hasard ----

/// Les bornes que tout résultat doit tenir, quoi que contienne le fichier.
fn verifier_bornes(lu: &Lecture, bornes: &Bornes) {
    assert!(lu.enregistrements.len() <= bornes.enregistrements);
    assert_eq!(lu.bilan.enregistrements_lus, lu.enregistrements.len() as u64);
    for e in &lu.enregistrements {
        let (mut noeuds, mut texte) = (0, 0);
        let mut pile = vec![&e.evenement];
        while let Some(n) = pile.pop() {
            noeuds += 1;
            texte += n.texte.len() + n.attributs.iter().map(|(_, v)| v.len()).sum::<usize>();
            pile.extend(&n.enfants);
        }
        assert!(noeuds <= bornes.noeuds);
        assert!(texte <= bornes.texte_enregistrement);
    }
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

    /// Des octets quelconques derrière un en-tête juste : jamais de panique, les bornes tenues.
    #[test]
    fn des_octets_au_hasard_ne_font_jamais_paniquer(
        corps in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..3 * MORCEAU),
        signer in proptest::prelude::any::<bool>(),
    ) {
        let mut f = fichier(&[]);
        if signer && corps.len() >= 8 {
            let mut corps = corps.clone();
            corps[..8].copy_from_slice(b"ElfChnk\0");
            f.extend(corps);
            recalculer_crc(&mut f);
        } else {
            f.extend(corps);
        }
        let bornes = Bornes::default();
        if let Ok(lu) = lire_octets(&f, &bornes) {
            verifier_bornes(&lu, &bornes);
        }
    }

    /// Le fichier type abîmé à quelques endroits au hasard, CRC recalculés ou non : jamais de panique, les bornes
    /// tenues, et rien n'est perdu sans être compté.
    #[test]
    fn un_fichier_abime_au_hasard_ne_fait_jamais_paniquer(
        coups in proptest::collection::vec((0usize..EN_TETE + MORCEAU, proptest::prelude::any::<u8>()), 1..12),
        recalculer in proptest::prelude::any::<bool>(),
    ) {
        let mut f = fichier_type();
        for (ou, v) in coups {
            f[ou] = v;
        }
        if recalculer {
            recalculer_crc(&mut f);
        }
        let bornes = Bornes { noeuds: 64, travail: 2000, ..Bornes::default() };
        if let Ok(lu) = lire_octets(&f, &bornes) {
            verifier_bornes(&lu, &bornes);
            // Sans CRC recalculés, un coup dans le morceau l'écarte tout entier, et c'est compté.
            if !recalculer && lu.enregistrements.len() < 3 {
                proptest::prop_assert!(lu.bilan.morceaux_illisibles == 1, "{:?}", lu.bilan);
            }
        }
    }

    /// Le BinXml seul, à n'importe quelle position d'un morceau au hasard.
    #[test]
    fn du_binxml_au_hasard_ne_fait_jamais_paniquer(
        morceau in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4096),
        debut in 0usize..4096,
    ) {
        let _ = rendre_binxml(&morceau, debut, &Bornes::default());
    }
}

// ---- Lecture croisée avec la crate evtx ----

/// Ce que la lecture croisée compare d'un événement.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Vu {
    id: Option<u32>,
    fournisseur: String,
    canal: String,
    cree: Option<DateTime<Utc>>,
    champs: Vec<(String, String)>,
}

fn vu(e: &Enregistrement) -> Vu {
    // Seulement EventData : la lecture croisée compare les champs que les deux lecteurs nomment de la même façon.
    let champs = if e.evenement.enfant("EventData").is_some() {
        e.champs.clone()
    } else {
        Vec::new()
    };
    Vu {
        id: e.id,
        fournisseur: e.fournisseur.clone(),
        canal: e.canal.clone(),
        cree: e.cree,
        champs,
    }
}

/// Le XML rendu par la crate evtx, réduit à ce que compare la lecture croisée.
fn vu_xml(xml: &str) -> Vu {
    use quick_xml::events::Event;
    let mut lecteur = quick_xml::Reader::from_str(xml);
    let mut chemin: Vec<String> = Vec::new();
    let mut v = Vu::default();
    let mut texte: Option<String> = None;
    let mut nom_champ = String::new();
    let (mut id, mut canal) = (String::new(), String::new());
    let attribut = |e: &quick_xml::events::BytesStart, nom: &str| {
        e.try_get_attribute(nom).ok().flatten().and_then(|a| {
            a.normalized_value(quick_xml::XmlVersion::Implicit1_0)
                .ok()
                .map(std::borrow::Cow::into_owned)
        })
    };
    loop {
        let evenement = lecteur.read_event().unwrap();
        let (ouvert, vide) = match &evenement {
            Event::Start(e) => (Some(e), false),
            Event::Empty(e) => (Some(e), true),
            _ => (None, false),
        };
        if let Some(e) = ouvert {
            let nom = e.local_name().as_ref().to_string();
            let parent = chemin.last().map(String::as_str);
            match (parent, nom.as_str()) {
                (Some("System"), "Provider") => {
                    v.fournisseur = attribut(e, "Name")
                        .or_else(|| attribut(e, "EventSourceName"))
                        .unwrap_or_default();
                }
                (Some("System"), "TimeCreated") => {
                    v.cree = attribut(e, "SystemTime")
                        .and_then(|t| DateTime::parse_from_rfc3339(&t).ok())
                        .map(|d| d.with_timezone(&Utc));
                }
                (Some("EventData"), n) => {
                    nom_champ = if n == "Data" {
                        attribut(e, "Name").unwrap_or_default()
                    } else {
                        n.to_string()
                    };
                    if vide {
                        v.champs.push((nom_champ.clone(), String::new()));
                    } else {
                        texte = Some(String::new());
                    }
                }
                _ => {}
            }
            if !vide {
                chemin.push(nom);
            }
            continue;
        }
        let ajouter = |dans: &mut String, chemin: &[String], texte: &mut Option<String>, t: &str| {
            if let Some(x) = texte {
                x.push_str(t);
            } else if chemin.len() == 3 && chemin[1] == "System" {
                // Pas RenderingInfo/Channel, que portent les événements transférés.
                dans.push_str(t);
            }
        };
        let mut ailleurs = String::new();
        let cible = match chemin.last().map(String::as_str) {
            Some("EventID") => &mut id,
            Some("Channel") => &mut canal,
            _ => &mut ailleurs,
        };
        match evenement {
            Event::Text(t) => ajouter(cible, &chemin, &mut texte, &t.xml10_content()),
            Event::CData(t) => ajouter(cible, &chemin, &mut texte, &t.into_inner()),
            Event::GeneralRef(r) => {
                let c = match r.as_ref() {
                    "amp" => '&',
                    "lt" => '<',
                    "gt" => '>',
                    "quot" => '"',
                    "apos" => '\'',
                    _ => r.resolve_char_ref().ok().flatten().unwrap_or('\u{FFFD}'),
                };
                ajouter(cible, &chemin, &mut texte, &c.to_string());
            }
            Event::End(_) => {
                chemin.pop();
                if chemin.last().is_some_and(|p| p == "EventData")
                    && let Some(t) = texte.take()
                {
                    v.champs.push((std::mem::take(&mut nom_champ), t));
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    v.id = id.trim().parse().ok();
    v.canal = canal.trim().to_string();
    v
}

/// Les événements vus par la crate evtx (CRC vérifiés, comme nous), par numéro d'enregistrement, et le nombre de
/// ceux qu'elle n'a pas pu rendre.
fn lecture_oracle(octets: Vec<u8>) -> (BTreeMap<u64, Vu>, usize) {
    let reglages = evtx::ParserSettings::new()
        .validate_checksums(true)
        .num_threads(1)
        .indent(false);
    let mut lecteur = evtx::EvtxParser::from_buffer(octets)
        .unwrap()
        .with_configuration(reglages);
    let mut vus = BTreeMap::new();
    let mut erreurs = 0;
    for r in lecteur.records() {
        match r {
            Ok(r) => {
                vus.insert(r.event_record_id, vu_xml(&r.data));
            }
            Err(_) => erreurs += 1,
        }
    }
    (vus, erreurs)
}

/// Une valeur ramenée à ce que les deux lecteurs rendent de la même façon : les fins de ligne comme un analyseur XML
/// les livre (XML 1.0 § 2.11 : « \r\n » devient « \n »), un GUID sans accolades (que nous gardons, comme la forme
/// canonique de [MS-EVEN6] 3.1.4.7.3), une date à la microseconde (la crate s'y arrête, nous gardons les centaines
/// de nanosecondes du FILETIME et les millisecondes du SYSTEMTIME).
pub(crate) fn forme_commune(v: &str) -> String {
    let v = v.replace("\r\n", "\n").replace('\r', "\n");
    if let Ok(d) = DateTime::parse_from_rfc3339(&v) {
        return d.timestamp_micros().to_string();
    }
    let guid = v.len() == 38
        && v.starts_with('{')
        && v.ends_with('}')
        && v[1..37].chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    if guid { v[1..37].to_ascii_uppercase() } else { v }
}

/// Le résultat d'une lecture croisée : comparés, identiques, et les écarts par sorte (avec un exemple chacun).
#[derive(Debug, Default)]
struct Croisement {
    compares: usize,
    seulement_nous: usize,
    seulement_oracle: usize,
    erreurs_oracle: usize,
    /// Événements dont des champs vides ont été ôtés avant de comparer.
    champs_vides_otes: usize,
    /// Notre bilan : morceaux écartés, enregistrements illisibles, annoncés mais absents.
    morceaux_illisibles: u64,
    enregistrements_illisibles: u64,
    enregistrements_absents: u64,
    apres_place_libre: u64,
    ecarts: BTreeMap<&'static str, (usize, String)>,
}

fn croiser(octets: &[u8]) -> Croisement {
    let nous = lire_type(octets);
    let (oracle, erreurs_oracle) = lecture_oracle(octets.to_vec());
    let mut c = Croisement {
        erreurs_oracle,
        morceaux_illisibles: nous.bilan.morceaux_illisibles,
        enregistrements_illisibles: nous.bilan.enregistrements_illisibles,
        enregistrements_absents: nous.bilan.enregistrements_absents,
        apres_place_libre: nous.bilan.enregistrements_apres_place_libre,
        ..Croisement::default()
    };
    let mut vus = BTreeMap::new();
    for e in &nous.enregistrements {
        vus.insert(e.numero, vu(e));
    }
    for (numero, a) in &vus {
        let Some(b) = oracle.get(numero) else {
            c.seulement_nous += 1;
            continue;
        };
        c.compares += 1;
        let mut ecart = |sorte: &'static str, detail: String| {
            let entree = c.ecarts.entry(sorte).or_insert((0, detail));
            entree.0 += 1;
        };
        if a.id != b.id {
            ecart("EventID", format!("{numero} : {:?} / {:?}", a.id, b.id));
        }
        if a.fournisseur != b.fournisseur {
            ecart(
                "Provider",
                format!("{numero} : {:?} / {:?}", a.fournisseur, b.fournisseur),
            );
        }
        if a.canal != b.canal {
            ecart("Channel", format!("{numero} : {:?} / {:?}", a.canal, b.canal));
        }
        // La crate s'arrête à la microseconde ; nous gardons les centaines de nanosecondes du FILETIME.
        let micro = |d: Option<DateTime<Utc>>| d.map(|d| d.timestamp_micros());
        if micro(a.cree) != micro(b.cree) {
            ecart("TimeCreated", format!("{numero} : {:?} / {:?}", a.cree, b.cree));
        }
        // Un élément à substitution optionnelle nulle : ôté chez nous comme le veut [MS-EVEN6] 3.1.4.7.2, rendu vide
        // par la crate. Les champs vides sont donc ôtés des deux côtés avant de comparer (une valeur rendue vide
        // d'un côté et pleine de l'autre reste un écart : les listes n'ont plus la même longueur).
        let pleins = |champs: &[(String, String)]| -> Vec<(String, String)> {
            champs
                .iter()
                .filter(|(_, v)| !v.is_empty())
                .map(|(n, v)| (n.clone(), forme_commune(v)))
                .collect()
        };
        let (pa, pb) = (pleins(&a.champs), pleins(&b.champs));
        if pa.len() != a.champs.len() || pb.len() != b.champs.len() {
            c.champs_vides_otes += 1;
        }
        if pa != pb {
            let premier = pa.iter().zip(&pb).find(|(x, y)| x != y);
            ecart(
                "EventData",
                format!(
                    "{numero} : {} / {} champs, premier écart {premier:?}",
                    pa.len(),
                    pb.len()
                ),
            );
        }
    }
    c.seulement_oracle = oracle.keys().filter(|n| !vus.contains_key(n)).count();
    c
}

#[test]
fn la_crate_evtx_lit_nos_fichiers_fabriques_comme_nous() {
    // Sans la valeur EvtHandle : la crate refuse l'enregistrement entier qui en porte une, nous la rendons
    // « inconnu » et gardons le reste (essayé : 4 enregistrements sur 6 en erreur chez elle).
    let c = croiser(&fichier(&[morceau_type_avec(1, false), morceau_type_avec(4, false)]));
    assert_eq!(
        (c.compares, c.seulement_nous, c.seulement_oracle, c.erreurs_oracle),
        (6, 0, 0, 0),
        "{c:?}"
    );
    assert!(c.ecarts.is_empty(), "{c:?}");
}

#[test]
fn lecture_croisee_des_echantillons() {
    let Some(dossier) = std::env::var_os("VANGUARD_EVTX_ECHANTILLONS") else {
        return crate::essais::saute("VANGUARD_EVTX_ECHANTILLONS absente : pas d'échantillons .evtx à croiser");
    };
    let mut chemins: Vec<_> = std::fs::read_dir(&dossier)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "evtx"))
        .collect();
    chemins.sort();
    assert!(!chemins.is_empty(), "aucun .evtx dans {dossier:?}");
    let mut total = Croisement::default();
    for chemin in &chemins {
        let octets = std::fs::read(chemin).unwrap();
        let c = croiser(&octets);
        eprintln!(
            "{} : {} comparés, {} seulement nous, {} seulement evtx ({} erreurs), écarts {:?} ; nous : {} morceaux \
             écartés, {} enregistrements illisibles, {} absents",
            chemin.file_name().unwrap().to_string_lossy(),
            c.compares,
            c.seulement_nous,
            c.seulement_oracle,
            c.erreurs_oracle,
            c.ecarts,
            c.morceaux_illisibles,
            c.enregistrements_illisibles,
            c.enregistrements_absents
        );
        total.compares += c.compares;
        total.seulement_nous += c.seulement_nous;
        total.seulement_oracle += c.seulement_oracle;
        total.erreurs_oracle += c.erreurs_oracle;
        total.champs_vides_otes += c.champs_vides_otes;
        total.morceaux_illisibles += c.morceaux_illisibles;
        total.enregistrements_illisibles += c.enregistrements_illisibles;
        total.enregistrements_absents += c.enregistrements_absents;
        total.apres_place_libre += c.apres_place_libre;
        for (sorte, (n, d)) in c.ecarts {
            total.ecarts.entry(sorte).or_insert((0, d)).0 += n;
        }
    }
    eprintln!("TOTAL : {total:?}");
    assert!(total.compares > 0);
    // Aucun écart, et rien que nous lisions sans que la crate le lise aussi. L'inverse arrive : elle lit des morceaux
    // aux CRC faux que nous écartons (Application_no_crc32.evtx des échantillons de la crate), et c'est compté.
    assert!(total.ecarts.is_empty(), "{total:?}");
    assert_eq!(total.seulement_nous, 0, "{total:?}");
    assert!(
        total.seulement_oracle == 0 || total.morceaux_illisibles > 0,
        "{total:?}"
    );
}

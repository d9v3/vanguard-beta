//! Une prise netlink et ses messages, écrits à la main : ce que nf_tables (`nftables`) et la coupure des connexions
//! (`couper`) envoient au noyau, et la lecture de ses accusés. Les messages se construisent en fonctions pures
//! (testées octet par octet) ; seule `Prise` parle au noyau.
//!
//! Le format : en-tête nlmsghdr (16 octets : longueur, type, drapeaux, numéro, port), puis le corps ; chaque
//! attribut (nlattr) a 4 octets d'en-tête (longueur, type), sa donnée, et un bourrage jusqu'au multiple de 4
//! (linux/netlink.h).

// FFI de libc : prise netlink (socket, setsockopt, sendto, recv).
#![allow(unsafe_code)]

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub(crate) const NLM_F_REQUEST: u16 = 0x01;
pub(crate) const NLM_F_ACK: u16 = 0x04;
pub(crate) const NLM_F_DUMP: u16 = 0x300;
pub(crate) const NLM_F_CREATE: u16 = 0x400;
pub(crate) const NLM_F_APPEND: u16 = 0x800;
pub(crate) const NLMSG_ERROR: u16 = 2;
pub(crate) const NLMSG_DONE: u16 = 3;
/// Le bit d'un attribut qui en contient d'autres.
pub(crate) const NLA_F_NESTED: u16 = 1 << 15;

/// Un corps de message en construction : des attributs les uns après les autres.
#[derive(Default)]
pub(crate) struct Attributs(pub Vec<u8>);

impl Attributs {
    /// Un attribut, sa donnée telle quelle, bourré jusqu'au multiple de 4.
    pub(crate) fn brut(&mut self, genre: u16, donnee: &[u8]) {
        let longueur = u16::try_from(4 + donnee.len()).unwrap_or(u16::MAX);
        self.0.extend_from_slice(&longueur.to_ne_bytes());
        self.0.extend_from_slice(&genre.to_ne_bytes());
        self.0.extend_from_slice(donnee);
        self.bourrer();
    }

    /// Un texte terminé par un zéro (NLA_STRING / NLA_NUL_STRING).
    pub(crate) fn texte(&mut self, genre: u16, t: &str) {
        let mut d = t.as_bytes().to_vec();
        d.push(0);
        self.brut(genre, &d);
    }

    /// Un entier de 32 bits dans l'ordre du réseau : nf_tables les attend ainsi (NLA_BE32).
    pub(crate) fn be32(&mut self, genre: u16, v: u32) {
        self.brut(genre, &v.to_be_bytes());
    }

    /// Un attribut qui en contient d'autres, écrits par `f` ; sa longueur est fixée après coup.
    pub(crate) fn imbrique(&mut self, genre: u16, f: impl FnOnce(&mut Attributs)) {
        let debut = self.0.len();
        self.0.extend_from_slice(&[0, 0]);
        self.0.extend_from_slice(&(genre | NLA_F_NESTED).to_ne_bytes());
        let mut dedans = Attributs(std::mem::take(&mut self.0));
        f(&mut dedans);
        self.0 = dedans.0;
        let longueur = u16::try_from(self.0.len() - debut).unwrap_or(u16::MAX);
        #[expect(
            clippy::indexing_slicing,
            reason = "les deux octets en `debut` sont posés au début de cette fonction, et `f` n'a que des ajouts"
        )]
        self.0[debut..debut + 2].copy_from_slice(&longueur.to_ne_bytes());
        self.bourrer();
    }

    fn bourrer(&mut self) {
        while !self.0.len().is_multiple_of(4) {
            self.0.push(0);
        }
    }
}

/// Un message entier : l'en-tête, puis `corps` (déjà aligné sur 4).
pub(crate) fn message(genre: u16, drapeaux: u16, sequence: u32, corps: &[u8]) -> Vec<u8> {
    let longueur = u32::try_from(16 + corps.len()).unwrap_or(u32::MAX);
    let mut m = Vec::with_capacity(16 + corps.len());
    m.extend_from_slice(&longueur.to_ne_bytes());
    m.extend_from_slice(&genre.to_ne_bytes());
    m.extend_from_slice(&drapeaux.to_ne_bytes());
    m.extend_from_slice(&sequence.to_ne_bytes());
    // Le port : 0, le noyau donne celui de la prise.
    m.extend_from_slice(&0u32.to_ne_bytes());
    m.extend_from_slice(corps);
    m
}

/// Les attributs d'un corps (type sans ses bits de drapeaux, donnée) ; un attribut tronqué arrête la lecture.
pub(crate) fn attributs(octets: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    let mut pos = 0usize;
    std::iter::from_fn(move || {
        let &[l0, l1, g0, g1] = octets.get(pos..)?.first_chunk::<4>()?;
        let longueur = usize::from(u16::from_ne_bytes([l0, l1]));
        let genre = u16::from_ne_bytes([g0, g1]) & !(NLA_F_NESTED | 1 << 14);
        if longueur < 4 {
            return None;
        }
        let donnee = octets.get(pos + 4..pos + longueur)?;
        pos += longueur.next_multiple_of(4);
        Some((genre, donnee))
    })
}

/// Un message reçu : son type, ses drapeaux, son numéro et son corps.
pub(crate) struct Recu<'a> {
    pub genre: u16,
    #[cfg_attr(not(test), allow(dead_code))]
    // décodé pour les tests du décodage ; le programme ne suit pas les numéros
    pub sequence: u32,
    pub corps: &'a [u8],
}

/// Les messages d'un tampon reçu.
pub(crate) fn recus(octets: &[u8]) -> impl Iterator<Item = Recu<'_>> {
    let mut pos = 0usize;
    std::iter::from_fn(move || {
        // L'en-tête en tableau : des indices constants, que le compilateur sait dans les bornes.
        let entete = octets.get(pos..)?.first_chunk::<16>()?;
        let longueur = usize::try_from(u32::from_ne_bytes([entete[0], entete[1], entete[2], entete[3]])).ok()?;
        if longueur < 16 {
            return None;
        }
        let corps = octets.get(pos + 16..pos.checked_add(longueur)?)?;
        let recu = Recu {
            genre: u16::from_ne_bytes([entete[4], entete[5]]),
            sequence: u32::from_ne_bytes([entete[8], entete[9], entete[10], entete[11]]),
            corps,
        };
        pos += longueur.next_multiple_of(4);
        Some(recu)
    })
}

/// Le code d'un NLMSG_ERROR (0 : accusé de réception ; sinon -errno) et le numéro du message qu'il vise.
pub(crate) fn erreur(r: &Recu<'_>) -> Option<(i32, u32)> {
    if r.genre != NLMSG_ERROR {
        return None;
    }
    let code = i32::from_ne_bytes(r.corps.get(0..4)?.try_into().ok()?);
    // Puis l'en-tête du message d'origine : son numéro est à l'octet 8 de cet en-tête.
    let vise = r
        .corps
        .get(12..16)
        .and_then(|o| o.try_into().ok())
        .map_or(0, u32::from_ne_bytes);
    Some((code, vise))
}

/// Le texte d'une erreur du noyau (-errno), dans la langue du système.
pub(crate) fn texte_errno(code: i32) -> String {
    std::io::Error::from_raw_os_error(code.saturating_neg()).to_string()
}

/// Une prise netlink ouverte, fermée une seule fois (OwnedFd).
pub(crate) struct Prise(OwnedFd);

impl Prise {
    /// Ouvre une prise sur ce protocole netlink, avec un délai de réception de 2 s : un noyau muet ne bloque jamais.
    pub(crate) fn ouvrir(protocole: i32) -> std::io::Result<Prise> {
        // SAFETY: socket ne lit aucune mémoire ; un descripteur rendu (≥ 0) est à nous seuls, confié à OwnedFd qui le
        // fermera une seule fois.
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, protocole) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: voir ci-dessus.
        let prise = Prise(unsafe { OwnedFd::from_raw_fd(fd) });
        let delai = libc::timeval { tv_sec: 2, tv_usec: 0 };
        let taille = libc::socklen_t::try_from(std::mem::size_of::<libc::timeval>()).unwrap_or(0);
        // SAFETY: `delai` est un timeval à nous, vivant pendant l'appel, de la taille annoncée.
        let r = unsafe {
            libc::setsockopt(
                prise.0.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const delai).cast(),
                taille,
            )
        };
        if r != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(prise)
    }

    /// Envoie ces octets au noyau, d'un seul envoi (un lot de nf_tables doit arriver entier).
    pub(crate) fn envoyer(&self, octets: &[u8]) -> std::io::Result<()> {
        // SAFETY: une adresse netlink à zéro (le noyau), de la taille exacte ; les octets vivent pendant l'appel.
        let envoye = unsafe {
            let mut adresse: libc::sockaddr_nl = std::mem::zeroed();
            adresse.nl_family = libc::sa_family_t::try_from(libc::AF_NETLINK).unwrap_or(16);
            libc::sendto(
                self.0.as_raw_fd(),
                octets.as_ptr().cast(),
                octets.len(),
                0,
                (&raw const adresse).cast(),
                libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_nl>()).unwrap_or(0),
            )
        };
        match usize::try_from(envoye) {
            Ok(n) if n == octets.len() => Ok(()),
            Ok(_) => Err(std::io::Error::other("envoi netlink incomplet")),
            Err(_) => Err(std::io::Error::last_os_error()),
        }
    }

    /// Reçoit un morceau de réponse ; `attendre` faux : sans attendre (rien de prêt : Ok(vide)).
    pub(crate) fn recevoir(&self, attendre: bool) -> std::io::Result<Vec<u8>> {
        let mut tampon = vec![0u8; 64 << 10];
        let drapeaux = if attendre { 0 } else { libc::MSG_DONTWAIT };
        // SAFETY: le tampon est à nous, de la taille annoncée, vivant pendant l'appel.
        let n = unsafe { libc::recv(self.0.as_raw_fd(), tampon.as_mut_ptr().cast(), tampon.len(), drapeaux) };
        if let Ok(n) = usize::try_from(n) {
            tampon.truncate(n);
            return Ok(tampon);
        }
        let e = std::io::Error::last_os_error();
        if !attendre && e.kind() == std::io::ErrorKind::WouldBlock {
            Ok(Vec::new())
        } else {
            Err(e)
        }
    }

    /// Envoie des messages qui demandent chacun un accusé (NLM_F_ACK), puis lit jusqu'à les avoir tous, ou jusqu'à
    /// la première erreur (le reste est alors lu sans attendre). `attendus` : leurs numéros. Rend la première erreur :
    /// (-errno, numéro du message visé).
    pub(crate) fn envoyer_et_attendre(&self, octets: &[u8], attendus: &[u32]) -> Result<(), (i32, u32)> {
        self.envoyer(octets)
            .map_err(|e| (e.raw_os_error().map_or(-libc::EIO, |c| -c), 0))?;
        let mut restants: std::collections::HashSet<u32> = attendus.iter().copied().collect();
        let mut premiere = None;
        while !restants.is_empty() {
            let morceau = match self.recevoir(premiere.is_none()) {
                Ok(m) if m.is_empty() => break,
                Ok(m) => m,
                // Délai dépassé : un accusé manque, ce n'est pas une réussite.
                Err(e) => return Err(premiere.unwrap_or((e.raw_os_error().map_or(-libc::EIO, |c| -c), 0))),
            };
            for r in recus(&morceau) {
                if let Some((code, vise)) = erreur(&r) {
                    restants.remove(&vise);
                    if code != 0 && premiere.is_none() {
                        premiere = Some((code, vise));
                    }
                }
            }
        }
        match premiere {
            Some(e) => Err(e),
            None if restants.is_empty() => Ok(()),
            None => Err((-libc::EIO, 0)),
        }
    }

    /// Envoie une demande de liste (NLM_F_DUMP) et rend les messages reçus jusqu'à NLMSG_DONE, ou l'erreur.
    pub(crate) fn lister(&self, octets: &[u8]) -> Result<Vec<u8>, i32> {
        self.envoyer(octets)
            .map_err(|e| e.raw_os_error().map_or(-libc::EIO, |c| -c))?;
        let mut tout = Vec::new();
        loop {
            let morceau = self
                .recevoir(true)
                .map_err(|e| e.raw_os_error().map_or(-libc::EIO, |c| -c))?;
            if morceau.is_empty() {
                return Err(-libc::EIO);
            }
            let mut fini = false;
            for r in recus(&morceau) {
                if let Some((code, _)) = erreur(&r)
                    && code != 0
                {
                    return Err(code);
                }
                if r.genre == NLMSG_DONE {
                    fini = true;
                }
            }
            tout.extend_from_slice(&morceau);
            if fini {
                return Ok(tout);
            }
            // Une liste démesurée n'en est pas une.
            if tout.len() > 16 << 20 {
                return Err(-libc::E2BIG);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attributs_alignes_et_imbriques() {
        let mut a = Attributs::default();
        a.texte(1, "lo");
        a.be32(2, 7);
        a.imbrique(3, |b| b.brut(1, &[0xAB]));
        assert_eq!(
            a.0,
            [
                7, 0, 1, 0, b'l', b'o', 0, 0, // « lo\0 », bourré
                8, 0, 2, 0, 0, 0, 0, 7, // 7 dans l'ordre du réseau
                12, 0, 3, 0x80, 5, 0, 1, 0, 0xAB, 0, 0,
                0, // imbriqué : son en-tête compte le bourrage du dedans
            ]
        );
        let lus: Vec<(u16, Vec<u8>)> = attributs(&a.0).map(|(g, d)| (g, d.to_vec())).collect();
        assert_eq!(lus[0], (1, b"lo\0".to_vec()));
        assert_eq!(lus[2].0, 3, "le drapeau d'imbrication est ôté à la lecture");
        let m = message(0x0a00, NLM_F_REQUEST | NLM_F_ACK, 9, &a.0);
        assert_eq!(m.len(), 16 + a.0.len());
        assert_eq!(u32::from_ne_bytes(m[0..4].try_into().unwrap()), 44);
        let r = recus(&m).next().unwrap();
        assert_eq!((r.genre, r.sequence, r.corps.len()), (0x0a00, 9, 28));
    }

    #[test]
    fn accuse_et_erreur_se_lisent() {
        // NLMSG_ERROR : code, puis l'en-tête du message visé (numéro 5).
        let mut corps = (-2i32).to_ne_bytes().to_vec();
        corps.extend_from_slice(&message(0x0a0e, NLM_F_REQUEST, 5, &[])[..16]);
        let m = message(NLMSG_ERROR, 0, 5, &corps);
        let r = recus(&m).next().unwrap();
        assert_eq!(erreur(&r), Some((-2, 5)));
        assert_ne!(texte_errno(-2), "");
        // Un message tronqué ne se lit pas.
        assert!(recus(&m[..10]).next().is_none());
    }
}

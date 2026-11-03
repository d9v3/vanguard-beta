//! SSH sous Windows, à parité avec Linux et macOS : le serveur OpenSSH de Microsoft (service `sshd`, sa
//! configuration dans %ProgramData%\ssh, l'authentification par mot de passe, le fichier des clés des
//! administrateurs) et les clés privées du compte (%USERPROFILE%\.ssh). Tout est lu en Rust : le registre pour le
//! service, WMI pour son état, les fichiers eux-mêmes et leurs droits (`securite`).
//!
//! Les corrections (défense D6c) passent par les gestes du processus élevé (`ssh_ecriture`), montrées puis
//! acceptées : les droits d'administrators_authorized_keys ou d'une clé réservés (liste d'avant notée, annulable),
//! « PermitEmptyPasswords no » et « PasswordAuthentication no » dans sshd_config (copie d'avant gardée, `sshd -t`
//! avant de remplacer). Couper les mots de passe peut enfermer dehors quelqu'un qui n'a pas encore de clé : la
//! question est posée, et le geste est refusé pendant une session SSH ; sshd n'est jamais redémarré pendant l'une
//! d'elles. Sans configuration lisible (fichier absent), la marche à suivre reste à faire soi-même.

use std::path::{Path, PathBuf};

use super::{Constat, alerte, ok};
use crate::machine::gestes::ReglageSshd;
use crate::machine::{cle_protegee, impossible_par, sans_objet};
use crate::modele::{Absence, Objet, Raison};
use crate::risk::Niveau;
use crate::ui::{affichable, resume, tr, trf};

const CAT: &str = "SSH";
const CAT_CLES: &str = "Clés SSH";
/// SYSTEM et le groupe Administrateurs : les seuls qui doivent pouvoir écrire administrators_authorized_keys
/// (OpenSSH le refuse sinon, et Microsoft le documente ainsi).
const ADMINISTRATION: [&str; 2] = ["S-1-5-18", "S-1-5-32-544"];
/// Tout le monde, les utilisateurs authentifiés, le groupe Utilisateurs, la session interactive : « les autres ».
const TOUS: [&str; 4] = ["S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-4"];
/// Écrire, ajouter, changer les droits ou le propriétaire, écriture générique, tout.
const ECRIRE: u32 = 0x2 | 0x4 | 0x4_0000 | 0x8_0000 | 0x4000_0000 | 0x1000_0000;
/// Lire les données, lecture générique, tout.
const LIRE: u32 = 0x1 | 0x8000_0000 | 0x1000_0000;
/// Une règle « héritée seulement » vaut pour le contenu d'un dossier, pas pour l'objet lui-même.
const HERITEE_SEULEMENT: u8 = 0x8;

/// Un fichier lu, ou pourquoi pas.
#[derive(Debug, PartialEq)]
pub(super) enum Lu {
    Texte(String),
    Absent,
    /// Les droits refusent la lecture : rien ne peut en être dit.
    Refuse,
}

/// Les droits d'un fichier, d'après sa liste (DACL).
#[derive(Debug, PartialEq)]
pub(super) enum Droits {
    Absent,
    /// Rien d'anormal.
    Surs,
    /// Ces comptes (SID) ont le droit visé alors qu'ils ne le devraient pas.
    Ouverts(Vec<String>),
    /// La liste ne se lit pas (réservée à l'administrateur).
    Illisibles,
}

/// Ce que le bilan sait du serveur.
pub(super) struct Serveur {
    /// La clé du service existe.
    pub service: bool,
    /// Son type de démarrage (2 automatique, 3 manuel, 4 désactivé).
    pub demarrage: Option<u32>,
    /// En marche, d'après WMI ; `None` : WMI n'a pas répondu.
    pub en_marche: Option<bool>,
    pub configuration: Lu,
    pub cles_admin: Droits,
}

/// Les comptes qui ont `masque` sur ce fichier, hors de `admis` ; `None` sans liste de droits lisible.
fn ouverts_a(descripteur: &[u8], masque: u32, admis: &dyn Fn(&str) -> bool) -> Option<Vec<String>> {
    let regles = super::securite::aces(descripteur)?;
    let mut sids: Vec<String> = regles
        .iter()
        .filter(|r| r.sorte == 0 && r.drapeaux & HERITEE_SEULEMENT == 0 && r.masque & masque != 0)
        .filter_map(|r| super::securite::sid_en_texte(&r.sid))
        .filter(|s| !admis(s))
        .collect();
    sids.sort();
    sids.dedup();
    Some(sids)
}

/// Les droits d'écriture de administrators_authorized_keys : réservés à SYSTEM et aux administrateurs.
pub(super) fn droits_cles_admin(descripteur: Option<&[u8]>, existe: bool) -> Droits {
    if !existe {
        return Droits::Absent;
    }
    // Sans liste de droits du tout (descripteur lu, mais aucune DACL), tout le monde a tout.
    match descripteur.map(|d| ouverts_a(d, ECRIRE, &|s| ADMINISTRATION.contains(&s))) {
        None => Droits::Illisibles,
        Some(None) => Droits::Ouverts(vec!["S-1-1-0".into()]),
        Some(Some(s)) if s.is_empty() => Droits::Surs,
        Some(Some(s)) => Droits::Ouverts(s),
    }
}

/// Une clé privée lisible par les autres (Tout le monde, Utilisateurs…) ? `None` : droits illisibles.
pub(super) fn cle_lisible_par_tous(descripteur: &[u8]) -> Option<bool> {
    match ouverts_a(descripteur, LIRE, &|s| !TOUS.contains(&s)) {
        Some(s) => Some(!s.is_empty()),
        // Aucune liste : tout le monde lit.
        None => super::securite::aces(descripteur).is_none().then_some(true),
    }
}

/// Le nom d'un compte bien connu, pour le message ; sinon son SID.
fn nom_du_sid(sid: &str) -> String {
    match sid {
        "S-1-1-0" => tr!("Tout le monde", "Everyone").to_string(),
        "S-1-5-11" => tr!("Utilisateurs authentifiés", "Authenticated Users").to_string(),
        "S-1-5-32-545" => tr!("Utilisateurs", "Users").to_string(),
        "S-1-5-4" => tr!("Interactif", "Interactive").to_string(),
        autre => affichable(autre),
    }
}

pub(super) fn juger_serveur(s: &Serveur) -> Vec<Constat> {
    // Sans service sshd (désinstallé : sa configuration peut rester sur le disque), rien ne reçoit de connexion,
    // quoi que contiennent ses fichiers.
    if !s.service {
        return vec![sans_objet(
            CAT,
            Absence::Logiciel,
            tr!(
                "Le serveur OpenSSH de Windows n'est pas installé : cet ordinateur ne reçoit aucune connexion SSH.",
                "Windows' OpenSSH server is not installed: this computer receives no SSH connection."
            ),
        )];
    }
    // WMI muet : on ne sait pas s'il tourne, il est jugé comme s'il tournait (une configuration faible se dit).
    let actif = s.en_marche.unwrap_or(true) || s.demarrage == Some(2);
    let mut constats = Vec::new();
    let fichier = r"%ProgramData%\ssh\administrators_authorized_keys";
    // StrictModes (oui par défaut) : OpenSSH refuse un fichier de clés que d'autres peuvent écrire, et une clé
    // ajoutée ainsi n'ouvre rien. `None` : configuration illisible, on ne sait pas, jugé comme s'il était coupé.
    let strict = match &s.configuration {
        Lu::Texte(t) => Some(
            crate::machine::sshd::valeur_sshd(&crate::machine::sshd::partie_globale_sshd(t), "StrictModes").as_deref()
                != Some("no"),
        ),
        Lu::Absent => Some(true),
        Lu::Refuse => None,
    };
    match &s.cles_admin {
        Droits::Ouverts(sids) => {
            let noms = resume(&sids.iter().map(|s| nom_du_sid(s)).collect::<Vec<_>>(), 4, ", ");
            let (niveau, message) = if strict == Some(true) {
                (
                    Niveau::Moyen,
                    trf!(
                        "{fichier} peut être modifié par d'autres que SYSTEM et les administrateurs ({noms}) : OpenSSH le refuse donc (StrictModes), les connexions par clé des administrateurs échouent, et un compte qui peut aussi en changer les droits pourrait y faire accepter sa clé.",
                        "{fichier} can be modified by others than SYSTEM and administrators ({noms}): OpenSSH therefore refuses it (StrictModes), administrators' key sign-ins fail, and an account that can also change its rights could get its key accepted there."
                    ),
                )
            } else {
                (
                    if actif { Niveau::Critique } else { Niveau::Moyen },
                    if strict == Some(false) {
                        trf!(
                            "{fichier} peut être modifié par d'autres que SYSTEM et les administrateurs ({noms}), et StrictModes est coupé : il suffit d'y ajouter sa clé pour se connecter en administrateur.",
                            "{fichier} can be modified by others than SYSTEM and administrators ({noms}), and StrictModes is off: adding one's key there is enough to sign in as administrator."
                        )
                    } else {
                        trf!(
                            "{fichier} peut être modifié par d'autres que SYSTEM et les administrateurs ({noms}) : si StrictModes est coupé (configuration illisible ici), il suffit d'y ajouter sa clé pour se connecter en administrateur.",
                            "{fichier} can be modified by others than SYSTEM and administrators ({noms}): if StrictModes is off (configuration unreadable here), adding one's key there is enough to sign in as administrator."
                        )
                    },
                )
            };
            constats.push(
                alerte(CAT, niveau, message)
                .avec_objet(Objet::de("fichier", "administrators_authorized_keys"))
                .corriger(
                    tr!(
                        "Réserver le fichier à SYSTEM et aux administrateurs (il n'est ni vidé ni réécrit ; droits d'avant notés, annulable)",
                        "Restrict the file to SYSTEM and administrators (it is neither emptied nor rewritten; previous rights noted, undoable)"
                    ),
                    &[crate::machine::gestes::ligne_ssh_droits(None).unwrap_or_default()],
                ),
            );
        }
        Droits::Illisibles => constats.push(impossible_par(
            CAT,
            Raison::Droits,
            trf!(
                "Impossible de vérifier les droits de {fichier} (réservés à l'administrateur).",
                "Could not check the rights of {fichier} (administrator only)."
            ),
        )),
        Droits::Absent | Droits::Surs => {}
    }
    if !actif {
        constats.push(ok(
            CAT,
            tr!(
                "Serveur OpenSSH installé mais arrêté, sans démarrage automatique : il ne reçoit aucune connexion.",
                "OpenSSH server installed but stopped, without automatic start: it receives no connection."
            ),
        ));
        return constats;
    }
    // Le geste ne crée jamais sshd_config : sans fichier lu, la marche à suivre reste à faire soi-même.
    let lisible = matches!(s.configuration, Lu::Texte(_));
    let conf = match &s.configuration {
        Lu::Texte(t) => crate::machine::sshd::partie_globale_sshd(t),
        // Sans fichier, sshd prend ses valeurs par défaut : mots de passe permis.
        Lu::Absent => String::new(),
        Lu::Refuse => {
            constats.push(impossible_par(
                CAT,
                Raison::Droits,
                tr!(
                    r"Impossible de vérifier la configuration du serveur OpenSSH (%ProgramData%\ssh\sshd_config réservé à l'administrateur).",
                    r"Could not check the OpenSSH server configuration (%ProgramData%\ssh\sshd_config administrator only)."
                ),
            ));
            return constats;
        }
    };
    let ou = tr!(
        r"Dans %ProgramData%\ssh\sshd_config (Bloc-notes en administrateur), puis « Restart-Service sshd » quand personne n'est connecté",
        r"In %ProgramData%\ssh\sshd_config (Notepad as administrator), then “Restart-Service sshd” when nobody is connected"
    );
    if crate::machine::sshd::mots_de_passe_vides_sshd(&conf) {
        let c = alerte(
            CAT,
            Niveau::Critique,
            tr!(
                "Le serveur OpenSSH accepte les comptes sans mot de passe : un tel compte s'ouvre depuis le réseau sans rien taper.",
                "The OpenSSH server accepts accounts without a password: such an account opens from the network without typing anything."
            ),
        );
        constats.push(if lisible {
            c.corriger(
                tr!(
                    "Mettre « PermitEmptyPasswords no » dans sshd_config (copie d'avant gardée, « sshd -t » avant de remplacer ; sshd redémarré seulement sans session SSH ouverte)",
                    "Set “PermitEmptyPasswords no” in sshd_config (previous copy kept, “sshd -t” before replacing; sshd restarted only with no SSH session open)"
                ),
                &[crate::machine::gestes::ligne_sshd_reglage(ReglageSshd::MotsDePasseVides)],
            )
        } else {
            c.manuel(trf!("{ou} : « PermitEmptyPasswords no ».", "{ou}: “PermitEmptyPasswords no”."), &[])
        });
    } else if crate::machine::sshd::mots_de_passe_sshd(&conf) {
        let c = alerte(
            CAT,
            Niveau::Moyen,
            tr!(
                "Le serveur OpenSSH accepte les mots de passe : depuis le réseau, on peut en essayer autant qu'on veut (force brute).",
                "The OpenSSH server accepts passwords: from the network, one can try as many as one wants (brute force)."
            ),
        );
        constats.push(if lisible {
            c.corriger(
                tr!(
                    "Après avoir ajouté votre clé depuis l'autre ordinateur : « PasswordAuthentication no » dans sshd_config (question « Une clé est-elle déjà posée pour votre compte ? » ; refusé pendant une session SSH ; copie d'avant gardée). Ou arrêter le service s'il ne sert pas",
                    "After adding your key from the other computer: “PasswordAuthentication no” in sshd_config (question “Is a key already set up for your account?”; refused during an SSH session; previous copy kept). Or stop the service if unused"
                ),
                &[crate::machine::gestes::ligne_sshd_reglage(ReglageSshd::MotsDePasse)],
            )
        } else {
            c.manuel(
                trf!(
                    "Après avoir ajouté votre clé depuis l'autre ordinateur : {ou} : « PasswordAuthentication no ». Ou arrêter le service s'il ne sert pas",
                    "After adding your key from the other computer: {ou}: “PasswordAuthentication no”. Or stop the service if unused"
                ),
                &[],
            )
        });
    } else {
        constats.push(ok(
            CAT,
            tr!(
                "Serveur OpenSSH en marche, clés seulement.",
                "OpenSSH server running, keys only."
            ),
        ));
    }
    constats
}

/// Une clé du dossier .ssh : son nom, protégée par une phrase de passe (`None` : pas une clé privée), lisible par
/// les autres (`None` : droits illisibles).
pub(super) struct Cle {
    pub nom: String,
    pub protegee: Option<bool>,
    pub lisible_par_tous: Option<bool>,
}

pub(super) fn juger_cles(dossier_existe: bool, cles: &[Cle]) -> Vec<Constat> {
    if !dossier_existe {
        return vec![ok(
            CAT_CLES,
            tr!(r"Pas de dossier %USERPROFILE%\.ssh.", r"No %USERPROFILE%\.ssh folder."),
        )];
    }
    let mut constats = Vec::new();
    for c in cles.iter().filter(|c| c.protegee.is_some()) {
        let nom = affichable(&c.nom);
        let objet = Objet::de("cle", &c.nom);
        if c.protegee == Some(false) {
            constats.push(
                alerte(
                    CAT_CLES,
                    Niveau::Moyen,
                    trf!(
                        r"Clé privée %USERPROFILE%\.ssh\{nom} sans phrase de passe : volée, elle ouvre tous les serveurs où elle est autorisée.",
                        r"Private key %USERPROFILE%\.ssh\{nom} has no passphrase: if stolen, it opens every server where it is authorized."
                    ),
                )
                .avec_objet(objet.clone())
                .manuel(
                    trf!(
                        "Ajouter une phrase de passe à {nom} (la clé publique ne change pas, rien à refaire sur les serveurs)",
                        "Add a passphrase to {nom} (the public key does not change, nothing to redo on the servers)"
                    ),
                    &[&format!(
                        "ssh-keygen -p -f \"$env:USERPROFILE\\.ssh\\{}\"",
                        c.nom.replace(['"', '`', '$'], "")
                    )],
                ),
            );
        }
        if c.lisible_par_tous == Some(true) {
            let constat = alerte(
                CAT_CLES,
                Niveau::Critique,
                trf!(
                    r"Clé privée %USERPROFILE%\.ssh\{nom} lisible par les autres comptes de cet ordinateur.",
                    r"Private key %USERPROFILE%\.ssh\{nom} is readable by the other accounts of this computer."
                ),
            )
            .avec_objet(objet);
            constats.push(match crate::machine::gestes::ligne_ssh_droits(Some(&c.nom)) {
                Some(ligne) => constat.corriger(
                    trf!(
                        "Réserver {nom} à votre compte, SYSTEM et aux administrateurs (la clé n'est pas touchée ; droits d'avant notés, annulable)",
                        "Restrict {nom} to your account, SYSTEM and administrators (the key itself is not touched; previous rights noted, undoable)"
                    ),
                    &[ligne],
                ),
                // Un nom que la grammaire des gestes refuse : la marche à suivre, à faire soi-même.
                None => constat.manuel(
                    trf!(
                        "Réserver {nom} à votre compte : Propriétés › Sécurité › Avancé, désactiver l'héritage et ne garder que vous, SYSTEM et Administrateurs",
                        "Restrict {nom} to your account: Properties › Security › Advanced, disable inheritance and keep only you, SYSTEM and Administrators"
                    ),
                    &[],
                ),
            });
        }
    }
    if cles
        .iter()
        .any(|c| c.protegee.is_some() && c.lisible_par_tous.is_none())
    {
        constats.push(impossible_par(
            CAT_CLES,
            Raison::Droits,
            tr!(
                "Impossible de lire les droits d'une clé privée de .ssh.",
                "Could not read the rights of a private key in .ssh."
            ),
        ));
    }
    if constats.is_empty() {
        constats.push(ok(
            CAT_CLES,
            tr!(
                "Clés privées de .ssh protégées par une phrase de passe et réservées à votre compte.",
                "Private keys in .ssh protected by a passphrase and restricted to your account."
            ),
        ));
    }
    constats
}

fn dossier_ssh_machine() -> PathBuf {
    std::env::var_os("ProgramData")
        .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from)
        .join("ssh")
}

fn lire(chemin: &Path) -> Lu {
    // Borné avant de lire : un fichier creux de plusieurs Gio ne se charge plus en entier (le manque de mémoire
    // arrêterait le processus, sans panique à rattraper).
    match crate::socle::lire_ordinaire(chemin, 1 << 20) {
        Ok(o) => Lu::Texte(String::from_utf8_lossy(&o).into_owned()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Lu::Absent,
        // Plus d'un Mio (pas une configuration de sshd), refusé, ou pas un simple fichier (lien, jonction) : illisible
        // plutôt que jugé à moitié.
        Err(_) => Lu::Refuse,
    }
}

/// WIN-SSH-001.
pub(super) fn serveur() -> Vec<Constat> {
    let cle = r"SYSTEM\CurrentControlSet\Services\sshd";
    let service = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(cle)
        .is_ok();
    let en_marche = service
        .then(|| super::wmi::requete(r"root\cimv2", "Win32_Service", "Name='sshd'", &["State"]))
        .flatten()
        .map(|l| l.first().and_then(|l| l["State"].texte()) == Some("Running"));
    let dossier = dossier_ssh_machine();
    let admin = dossier.join("administrators_authorized_keys");
    let existe = std::fs::symlink_metadata(&admin).is_ok();
    let descripteur = existe.then(|| super::securite::du_fichier(&admin)).flatten();
    juger_serveur(&Serveur {
        service,
        demarrage: super::registre(winreg::enums::HKEY_LOCAL_MACHINE, cle, "Start"),
        en_marche,
        configuration: lire(&dossier.join("sshd_config")),
        cles_admin: droits_cles_admin(descripteur.as_deref(), existe),
    })
}

/// WIN-SSH-002 : toute clé privée, quel que soit son nom, reconnue à son contenu.
pub(super) fn cles_du_compte() -> Vec<Constat> {
    let dossier = crate::socle::maison().join(".ssh");
    let existe = dossier.is_dir();
    let cles: Vec<Cle> = std::fs::read_dir(&dossier)
        .into_iter()
        .flatten()
        .flatten()
        .take(500)
        .filter(|f| f.file_type().is_ok_and(|t| t.is_file()))
        .filter_map(|f| {
            // Borné avant de lire, comme sshd_config.
            let texte = crate::socle::lire_ordinaire(&f.path(), 64 << 10).ok()?;
            let protegee = cle_protegee(&String::from_utf8_lossy(&texte))?;
            Some(Cle {
                nom: f.file_name().to_string_lossy().into_owned(),
                protegee: Some(protegee),
                lisible_par_tous: super::securite::du_fichier(&f.path()).and_then(|d| cle_lisible_par_tous(&d)),
            })
        })
        .collect();
    juger_cles(existe, &cles)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::gestes::{ligne_ssh_droits, ligne_sshd_reglage};
    use crate::modele::Etat;

    /// Un descripteur autonome inventé : (sorte, drapeaux, masque, SID en texte) par règle.
    fn descripteur(regles: &[(u8, u8, u32, &[u32])]) -> Vec<u8> {
        let mut aces = Vec::new();
        for (sorte, drapeaux, masque, sid) in regles {
            // SID : révision 1, autorité 5 (NT) sauf « Tout le monde » (1, sous-autorité 0).
            let autorite: u8 = if **sid == [0] { 1 } else { 5 };
            let sous: &[u32] = sid;
            let mut s = vec![1, u8::try_from(sous.len()).unwrap(), 0, 0, 0, 0, 0, autorite];
            for x in sous {
                s.extend_from_slice(&x.to_le_bytes());
            }
            let taille = u16::try_from(8 + s.len()).unwrap();
            aces.push(*sorte);
            aces.push(*drapeaux);
            aces.extend_from_slice(&taille.to_le_bytes());
            aces.extend_from_slice(&masque.to_le_bytes());
            aces.extend_from_slice(&s);
        }
        let mut d = vec![1, 0];
        d.extend_from_slice(&(0x8000u16 | 0x4).to_le_bytes());
        d.extend_from_slice(&[0; 12]);
        d.extend_from_slice(&20u32.to_le_bytes());
        // Liste : révision, réservé, taille, nombre, réservé.
        d.extend_from_slice(&[2, 0]);
        d.extend_from_slice(&u16::try_from(8 + aces.len()).unwrap().to_le_bytes());
        d.extend_from_slice(&u16::try_from(regles.len()).unwrap().to_le_bytes());
        d.extend_from_slice(&[0, 0]);
        d.extend_from_slice(&aces);
        d
    }

    const SYSTEM: &[u32] = &[18];
    const ADMINS: &[u32] = &[32, 544];
    const UTILISATEURS: &[u32] = &[32, 545];
    const ALICE: &[u32] = &[21, 111, 222, 333, 1001];

    #[test]
    fn droits_des_cles_des_administrateurs() {
        let sur = descripteur(&[(0, 0, 0x1F_01FF, SYSTEM), (0, 0, 0x1F_01FF, ADMINS)]);
        assert_eq!(droits_cles_admin(Some(&sur), true), Droits::Surs);
        // Ce qu'un « Ajouter » de l'Explorateur laisse : les utilisateurs peuvent écrire.
        let ouvert = descripteur(&[(0, 0, 0x1F_01FF, ADMINS), (0, 0, 0x1_2116, UTILISATEURS)]);
        assert_eq!(
            droits_cles_admin(Some(&ouvert), true),
            Droits::Ouverts(vec!["S-1-5-32-545".into()])
        );
        // Lecture seule pour un compte : pas une écriture. Une règle « héritée seulement » ne vaut pas pour lui.
        let lecture = descripteur(&[
            (0, 0, 0x1_2089, ALICE),
            (0, 0x8, 0x1F_01FF, UTILISATEURS),
            (0, 0, 0x1F_01FF, ADMINS),
        ]);
        assert_eq!(droits_cles_admin(Some(&lecture), true), Droits::Surs);
        // Une règle « refuser » n'ouvre rien.
        let refus = descripteur(&[(1, 0, 0x1F_01FF, ALICE), (0, 0, 0x1F_01FF, SYSTEM)]);
        assert_eq!(droits_cles_admin(Some(&refus), true), Droits::Surs);
        assert_eq!(droits_cles_admin(None, true), Droits::Illisibles);
        assert_eq!(droits_cles_admin(None, false), Droits::Absent);
    }

    #[test]
    fn cle_privee_lisible_par_tous() {
        let a_soi = descripteur(&[
            (0, 0, 0x1F_01FF, ALICE),
            (0, 0, 0x1F_01FF, SYSTEM),
            (0, 0, 0x1F_01FF, ADMINS),
        ]);
        assert_eq!(cle_lisible_par_tous(&a_soi), Some(false));
        let tous = descripteur(&[(0, 0, 0x1F_01FF, ALICE), (0, 0, 0x1_20A9, UTILISATEURS)]);
        assert_eq!(cle_lisible_par_tous(&tous), Some(true));
        let monde = descripteur(&[(0, 0, 0x8000_0000, &[0])]);
        assert_eq!(cle_lisible_par_tous(&monde), Some(true));
    }

    fn serveur(demarrage: Option<u32>, en_marche: Option<bool>, conf: &str, cles_admin: Droits) -> Vec<Constat> {
        juger_serveur(&Serveur {
            service: true,
            demarrage,
            en_marche,
            configuration: Lu::Texte(conf.into()),
            cles_admin,
        })
    }

    /// La configuration livrée par Microsoft : mots de passe permis (commentés, valeur par défaut), le bloc des
    /// administrateurs à la fin.
    const LIVREE: &str = "#PasswordAuthentication yes\n#PermitEmptyPasswords no\nAuthorizedKeysFile .ssh/authorized_keys\n\
                          Match Group administrators\n       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys\n";

    #[test]
    fn serveur_absent_arrete_ou_en_marche() {
        let absent = juger_serveur(&Serveur {
            service: false,
            demarrage: None,
            en_marche: None,
            configuration: Lu::Absent,
            cles_admin: Droits::Absent,
        });
        assert_eq!(absent.len(), 1);
        assert_eq!(absent[0].etat(), Etat::SansObjet(Absence::Logiciel));
        // Désinstallé, sa configuration et son fichier de clés restés sur le disque : rien ne reçoit de connexion.
        let reste = juger_serveur(&Serveur {
            service: false,
            demarrage: None,
            en_marche: None,
            configuration: Lu::Texte(LIVREE.into()),
            cles_admin: Droits::Ouverts(vec!["S-1-5-32-545".into()]),
        });
        assert_eq!(reste.len(), 1);
        assert_eq!(reste[0].etat(), Etat::SansObjet(Absence::Logiciel));
        let arrete = serveur(Some(3), Some(false), LIVREE, Droits::Surs);
        assert_eq!(arrete.len(), 1);
        assert_eq!(arrete[0].etat(), Etat::Sain);
        let c = serveur(Some(2), Some(true), LIVREE, Droits::Surs);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].probleme, Some(Niveau::Moyen));
        // Défense D6c : corrigé par le geste fermé du processus élevé (question, refus pendant une session SSH).
        let k = c[0].correctif.as_ref().unwrap();
        assert!(k.automatique);
        assert_eq!(k.commandes, [ligne_sshd_reglage(ReglageSshd::MotsDePasse)]);
        assert!(k.action.contains("Une clé est-elle déjà posée") || k.action.contains("Is a key already set up"));
        // Sans sshd_config (valeurs par défaut de sshd), le geste ne le crée pas : la marche à suivre, à la main.
        let sans = juger_serveur(&Serveur {
            service: true,
            demarrage: Some(2),
            en_marche: Some(true),
            configuration: Lu::Absent,
            cles_admin: Droits::Surs,
        });
        assert_eq!(sans[0].probleme, Some(Niveau::Moyen));
        let k = sans[0].correctif.as_ref().unwrap();
        assert!(!k.automatique);
        assert!(k.commandes.is_empty(), "{:?}", k.commandes);
        let cles = serveur(
            Some(2),
            Some(true),
            "PasswordAuthentication no\nMatch Group administrators\n PasswordAuthentication yes\n",
            Droits::Surs,
        );
        assert_eq!(cles[0].etat(), Etat::Sain);
        let vide = serveur(Some(3), None, "PermitEmptyPasswords yes\n", Droits::Surs);
        assert_eq!(vide[0].probleme, Some(Niveau::Critique));
        let k = vide[0].correctif.as_ref().unwrap();
        assert!(k.automatique);
        assert_eq!(k.commandes, [ligne_sshd_reglage(ReglageSshd::MotsDePasseVides)]);
        assert!(vide.iter().all(Constat::coherent));
        assert!(c.iter().chain(&sans).all(Constat::coherent));
    }

    #[test]
    fn fichier_des_cles_des_administrateurs() {
        // StrictModes par défaut : OpenSSH refuse le fichier ouvert, une clé ajoutée n'ouvre rien.
        let c = serveur(
            Some(2),
            Some(true),
            "PasswordAuthentication no\n",
            Droits::Ouverts(vec!["S-1-5-11".into()]),
        );
        assert_eq!(c[0].probleme, Some(Niveau::Moyen));
        assert!(c[0].message.contains("StrictModes"));
        // Défense D6c : le geste fermé (aucun chemin dans la ligne), plus la commande icacls.
        let cles_admin = ligne_ssh_droits(None).unwrap();
        assert_eq!(
            c[0].correctif.as_ref().unwrap().commandes,
            std::slice::from_ref(&cles_admin)
        );
        assert!(c[0].correctif.as_ref().unwrap().automatique);
        // StrictModes coupé : une clé ajoutée ouvre une session d'administrateur.
        let c = serveur(
            Some(2),
            Some(true),
            "PasswordAuthentication no\nStrictModes no\n",
            Droits::Ouverts(vec!["S-1-5-11".into()]),
        );
        assert_eq!(c[0].probleme, Some(Niveau::Critique));
        assert!(c[0].message.contains("administrators_authorized_keys"));
        assert_eq!(c[0].correctif.as_ref().unwrap().commandes, [cles_admin]);
        // Arrêté : la porte reste, moins urgente.
        let c = serveur(Some(4), Some(false), "", Droits::Ouverts(vec!["S-1-5-11".into()]));
        assert_eq!(c[0].probleme, Some(Niveau::Moyen));
        let c = serveur(Some(2), Some(true), "PasswordAuthentication no\n", Droits::Illisibles);
        assert!(matches!(c[0].etat(), Etat::NonVerifie(Raison::Droits)));
        let refus = juger_serveur(&Serveur {
            service: true,
            demarrage: Some(2),
            en_marche: Some(true),
            configuration: Lu::Refuse,
            cles_admin: Droits::Absent,
        });
        assert!(matches!(refus[0].etat(), Etat::NonVerifie(Raison::Droits)));
    }

    #[test]
    fn cles_du_compte_jugees() {
        assert_eq!(juger_cles(false, &[])[0].etat(), Etat::Sain);
        let cle = |nom: &str, protegee, lisible| Cle {
            nom: nom.into(),
            protegee,
            lisible_par_tous: lisible,
        };
        let c = juger_cles(true, &[cle("id_ed25519", Some(true), Some(false))]);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].etat(), Etat::Sain);
        let c = juger_cles(true, &[cle("serveur", Some(false), Some(true))]);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].probleme, Some(Niveau::Moyen));
        assert_eq!(c[1].probleme, Some(Niveau::Critique));
        assert!(c[0].correctif.as_ref().unwrap().commandes[0].contains(r"\.ssh\serveur"));
        // Défense D6c : lisible par les autres, réservée par le geste fermé, le nom en hexadécimal dans la ligne.
        let k = c[1].correctif.as_ref().unwrap();
        assert!(k.automatique);
        assert_eq!(k.commandes, [ligne_ssh_droits(Some("serveur")).unwrap()]);
        assert!(c.iter().all(Constat::coherent));
        // Un nom hostile : nettoyé dans le message ; refusé par la grammaire (contrôle), la marche à suivre à la main.
        let hostile = "id\x1b[31m\rcache";
        let c = juger_cles(true, &[cle(hostile, Some(true), Some(true))]);
        assert_eq!(c.len(), 1);
        assert!(
            !c[0].message.contains('\x1b') && !c[0].message.contains('\r'),
            "{:?}",
            c[0].message
        );
        let k = c[0].correctif.as_ref().unwrap();
        assert!(!k.automatique && k.commandes.is_empty());
        let long = "k".repeat(300);
        let c = juger_cles(true, &[cle(&long, Some(true), Some(true))]);
        assert!(!c[0].correctif.as_ref().unwrap().automatique);
        let c = juger_cles(true, &[cle("id_rsa", Some(true), None)]);
        assert!(matches!(c[0].etat(), Etat::NonVerifie(Raison::Droits)));
    }
}

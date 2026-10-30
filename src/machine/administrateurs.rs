//! Nouveaux administrateurs : un compte ajouté au groupe des administrateurs (wheel, sudo ou admin sous Linux, admin
//! sous macOS, Administrateurs sous Windows) a tous les droits. Un intrus qui s'installe se les donne souvent ainsi.
//! Vanguard note la première fois qu'il voit chaque administrateur (administrateurs.json, sur cet ordinateur) et
//! signale ceux de la dernière semaine ; ceux du premier passage sont connus d'avant. La surveillance horaire suit la
//! catégorie « Comptes » : un nouvel administrateur y fait une notification.

use std::collections::BTreeMap;

use chrono::NaiveDate;

use super::{Constat, alerte, ok};
use crate::risk::Niveau;
use crate::ui::{affichable, resume};
use crate::{tr, trf};

const CAT: &str = "Comptes";
const RECENT_JOURS: i64 = 7;

#[derive(serde::Serialize, serde::Deserialize, Default, Debug, PartialEq, Eq)]
struct Vus {
    /// Nom → date de la première fois (« AAAA-MM-JJ »), vide pour ceux du premier passage.
    vus: BTreeMap<String, String>,
}

/// Les administrateurs déjà vus, scellés (`sceau::deja_vus`).
const VUS: &str = crate::sceau::ADMINISTRATEURS;

/// Les membres des groupes d'administration dans /etc/group (« wheel:x:998:alice,bob »).
#[cfg(any(target_os = "linux", test))]
fn lire_groupes(texte: &str) -> Vec<String> {
    let mut noms: Vec<String> = texte
        .lines()
        .filter_map(|l| {
            let c: Vec<&str> = l.split(':').collect();
            match c.as_slice() {
                [groupe, _, _, membres, ..] if matches!(*groupe, "wheel" | "sudo" | "admin") => Some(*membres),
                _ => None,
            }
        })
        .flat_map(|membres| {
            membres
                .split(',')
                .map(str::trim)
                .filter(|m| !m.is_empty())
                .map(String::from)
        })
        .collect();
    noms.sort();
    noms.dedup();
    noms
}

/// « GroupMembership: root alice » (dscl . -read /Groups/admin GroupMembership).
#[cfg(any(target_os = "macos", test))]
fn lire_dscl(texte: &str) -> Vec<String> {
    texte
        .split_once("GroupMembership:")
        .map(|(_, r)| sans_root(r.split_whitespace().map(String::from).collect()))
        .unwrap_or_default()
}

/// Les membres sans root (toujours là, il n'est pas une personne), triés, chacun une fois.
#[cfg(any(target_os = "macos", test))]
fn sans_root(mut membres: Vec<String>) -> Vec<String> {
    membres.retain(|n| n != "root");
    membres.sort();
    membres.dedup();
    membres
}

/// macOS : les membres du groupe admin rendus par la bibliothèque du système (getgrnam_r, la base que lit dscl),
/// sans lancer de programme. dscl (sa sortie, demandée par `secours`) ne sert que si cette lecture ne rend personne
/// d'autre que root : un Mac a toujours un administrateur, une liste vide est une lecture manquée (groupe dont Open
/// Directory ne remplit pas les noms), pas un groupe vidé. Il en va de même après dscl : une liste vide y rend `None`,
/// comme une lecture impossible, sinon le bilan dirait « aucun en dehors de root » sur une liste jamais lue.
#[cfg(any(target_os = "macos", test))]
fn admins_macos(natif: Option<Vec<String>>, secours: impl FnOnce() -> Option<String>) -> Option<Vec<String>> {
    natif
        .map(sans_root)
        .filter(|m| !m.is_empty())
        .or_else(|| secours().map(|t| lire_dscl(&t)).filter(|m| !m.is_empty()))
}

/// Les administrateurs de cet ordinateur ; `None` : la liste ne se lit pas.
fn lire() -> Option<Vec<String>> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/etc/group").ok().map(|t| lire_groupes(&t))
    }
    #[cfg(target_os = "macos")]
    {
        // `sortie` exige le code 0 : un dscl en erreur (groupe introuvable, Open Directory muet) ne vaut pas lecture.
        admins_macos(super::macos::membres_admin(), || {
            super::sortie("dscl", &[".", "-read", "/Groups/admin", "GroupMembership"])
        })
    }
    #[cfg(windows)]
    {
        // Le groupe par son identifiant (S-1-5-32-544, son nom change avec la langue de Windows), lu avec les autres
        // vérifications des comptes en un seul lancement de PowerShell.
        let sortie = super::windows::comptes_locaux();
        crate::commande::section(sortie.as_deref(), "ADM").map(|l| {
            l.iter()
                .map(|n| n.trim().to_string())
                .filter(|n| !n.is_empty())
                .collect()
        })
    }
}

/// Le nom sous lequel cet administrateur a déjà été vu. Sous Windows, un nom de compte ne dépend pas de la casse :
/// « PC\Alice » lu autrement qu'au bilan d'avant (« PC\alice ») n'est pas un nouvel administrateur.
fn cle_vue(vus: &BTreeMap<String, String>, nom: &str, sans_casse: bool) -> String {
    sans_casse
        .then(|| vus.keys().find(|k| k.to_lowercase() == nom.to_lowercase()).cloned())
        .flatten()
        .unwrap_or_else(|| nom.to_string())
}

fn juger(admins: &[String], avant: Option<&Vus>, aujourd_hui: NaiveDate) -> (Constat, Vus) {
    let mut vus = avant.map(|v| v.vus.clone()).unwrap_or_default();
    let cles: Vec<String> = admins.iter().map(|a| cle_vue(&vus, a, cfg!(windows))).collect();
    // Un administrateur sorti du groupe est oublié : remis plus tard (par un intrus, souvent un compte dormant), il
    // repart de la date du jour et se signale comme un nouveau. Gardé, sa vieille date le faisait passer pour connu.
    // Une liste lue vide n'efface rien : ce peut être une lecture incomplète plutôt qu'un groupe vidé, et tout oublier
    // ferait signaler chacun comme nouveau au bilan suivant.
    if !admins.is_empty() {
        vus.retain(|k, _| cles.contains(k));
    }
    for cle in &cles {
        let date = if avant.is_some() {
            aujourd_hui.format("%Y-%m-%d").to_string()
        } else {
            String::new()
        };
        vus.entry(cle.clone()).or_insert(date);
    }
    let recents: Vec<String> = admins
        .iter()
        .zip(&cles)
        .filter(|(_, cle)| {
            vus.get(*cle)
                .and_then(|d| NaiveDate::parse_from_str(d, "%Y-%m-%d").ok())
                .is_some_and(|d| (aujourd_hui - d).num_days() < RECENT_JOURS)
        })
        .map(|(a, _)| affichable(a))
        .collect();
    let constat = if recents.is_empty() {
        let noms: Vec<String> = admins.iter().map(|a| affichable(a)).collect();
        ok(
            CAT,
            trf!(
                "Administrateurs de cet ordinateur : {} ; aucun nouveau cette semaine.",
                "Administrators of this computer: {}; none new this week.",
                if noms.is_empty() {
                    tr!("aucun en dehors de root", "none besides root").to_string()
                } else {
                    resume(&noms, 5, ", ")
                }
            ),
        )
    } else {
        alerte(
            CAT,
            Niveau::Eleve,
            trf!(
                "Nouveau compte administrateur cette semaine : {}. Si ce n'est pas vous qui l'avez ajouté, quelqu'un s'est donné tous les droits sur cet ordinateur.",
                "New administrator account this week: {}. If you did not add it, someone gave themselves every right on this computer.",
                recents.join(", ")
            ),
        )
        // Les comptes nouveaux eux-mêmes : un autre administrateur ajouté plus tard est un autre objet.
        .avec_objet(crate::modele::Objet::de("administrateurs", &{
            let mut r = recents.clone();
            r.sort();
            r.join(",")
        }))
        .manuel(retrait(), &[])
    };
    (constat, Vus { vus })
}

fn retrait() -> &'static str {
    if cfg!(windows) {
        tr!(
            "S'il n'est pas à vous : le retirer des administrateurs (Gestion de l'ordinateur › Utilisateurs et groupes locaux › Groupes › Administrateurs), puis changer vos mots de passe et lancer l'antivirus",
            "If it is not yours: remove it from administrators (Computer Management › Local Users and Groups › Groups › Administrators), then change your passwords and run the antivirus"
        )
    } else if cfg!(target_os = "macos") {
        tr!(
            "S'il n'est pas à vous : Réglages Système › Utilisateurs et groupes, lui retirer « Administrateur », puis changer vos mots de passe",
            "If it is not yours: System Settings › Users & Groups, remove “Administrator”, then change your passwords"
        )
    } else {
        tr!(
            "S'il n'est pas à vous : le retirer du groupe (« sudo gpasswd -d <compte> wheel », ou sudo), puis changer vos mots de passe et lancer l'antivirus",
            "If it is not yours: remove it from the group (“sudo gpasswd -d <account> wheel”, or sudo), then change your passwords and run the antivirus"
        )
    }
}

pub fn constat() -> Option<Constat> {
    let admins = lire()?;
    let (avant, douteux) = avant_de(crate::sceau::deja_vus(VUS));
    let (mut c, apres) = juger(&admins, avant.as_ref(), chrono::Local::now().date_naive());
    if douteux && c.probleme.is_some() {
        c.message += crate::sceau::redit();
    }
    if avant.as_ref() != Some(&apres)
        && let Ok(texte) = serde_json::to_string_pretty(&apres)
    {
        let _ = crate::sceau::ecrire(VUS, texte);
    }
    Some(c)
}

/// Les déjà vus relus sous leur sceau, et s'ils ne pouvaient pas être crus : effacés, changés hors de Vanguard ou
/// illisibles, ils valent une liste vide (chacun est redit), jamais un premier passage muet.
fn avant_de(lu: Result<Option<Vec<u8>>, ()>) -> (Option<Vus>, bool) {
    match lu {
        Ok(None) => (None, false),
        Ok(Some(o)) => serde_json::from_slice(&o).map_or((Some(Vus::default()), true), |v| (Some(v), false)),
        Err(()) => (Some(Vus::default()), true),
    }
}

/// COM-CPT-001 au corpus de détection : `vu|compte|date` (déjà vus), `admin|compte` (lus aujourd'hui, le 20 oct. 2026).
#[cfg(test)]
pub(super) fn corpus(e: &crate::modele::corpus::Entree) -> Vec<Constat> {
    let vus = e
        .de("vu")
        .iter()
        .map(|c| (c[0].to_string(), c.get(1).copied().unwrap_or_default().to_string()))
        .collect();
    let admins: Vec<String> = e.de("admin").iter().map(|c| c[0].to_string()).collect();
    let jour = NaiveDate::from_ymd_opt(2026, 10, 20).unwrap();
    vec![juger(&admins, Some(&Vus { vus }), jour).0]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jour(j: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 10, j).unwrap()
    }

    /// Des déjà vus effacés, changés hors de Vanguard ou illisibles ne font jamais un premier passage muet : chaque
    /// administrateur est redit ; seul un fichier jamais écrit est un premier passage.
    #[test]
    fn deja_vus_effaces_ou_changes_tout_redit() {
        let admins = vec!["alice".to_string(), "intrus".to_string()];
        let (avant, douteux) = avant_de(Err(()));
        assert!(douteux);
        let (c, _) = juger(&admins, avant.as_ref(), jour(10));
        assert!(c.probleme.is_some() && c.message.contains("intrus"), "{}", c.message);
        let (avant, douteux) = avant_de(Ok(Some(b"pas du json".to_vec())));
        assert!(douteux && avant.is_some());
        let (avant, douteux) = avant_de(Ok(None));
        assert!(!douteux && avant.is_none());
        let (c, _) = juger(&admins, avant.as_ref(), jour(10));
        assert!(c.probleme.is_none(), "{}", c.message);
    }

    #[test]
    fn meme_compte_sans_casse_sous_windows() {
        let vus = BTreeMap::from([(r"PC\Alice".to_string(), String::new())]);
        assert_eq!(cle_vue(&vus, r"PC\alice", true), r"PC\Alice");
        assert_eq!(cle_vue(&vus, r"PC\ÉLODIE", true), r"PC\ÉLODIE");
        // Ailleurs, « alice » et « Alice » sont deux comptes.
        assert_eq!(cle_vue(&vus, r"PC\alice", false), r"PC\alice");
    }

    #[test]
    fn lectures() {
        let group = "root:x:0:root\nwheel:x:998:alice,bob\nsudo:x:27:alice\nvideo:x:985:alice,carol\n";
        assert_eq!(lire_groupes(group), ["alice", "bob"]);
        assert_eq!(lire_dscl("GroupMembership: root alice bob\n"), ["alice", "bob"]);
        assert_eq!(lire_dscl("No such key: GroupMembership"), Vec::<String>::new());
    }

    /// macOS, sur des listes inventées : la lecture par la bibliothèque du système suffit dès qu'elle rend une
    /// personne ; dscl ne sert que si elle échoue ou ne rend que root.
    #[test]
    fn administrateurs_macos_sans_dscl() {
        let noms = |v: &[&str]| v.iter().map(|n| (*n).to_string()).collect::<Vec<_>>();
        let jamais = || -> Option<String> { panic!("dscl lancé alors que la lecture native suffit") };
        assert_eq!(
            admins_macos(Some(noms(&["root", "bob", "alice", "bob"])), jamais),
            Some(noms(&["alice", "bob"]))
        );
        let dscl = || Some("GroupMembership: root carol\n".to_string());
        assert_eq!(admins_macos(Some(noms(&["root"])), dscl), Some(noms(&["carol"])));
        assert_eq!(admins_macos(Some(Vec::new()), dscl), Some(noms(&["carol"])));
        assert_eq!(admins_macos(None, dscl), Some(noms(&["carol"])));
        // Ni l'une ni l'autre : rien n'est affirmé.
        assert_eq!(admins_macos(None, || None), None);
        // dscl lisible mais sans personne : une lecture manquée aussi, jamais « aucun en dehors de root ».
        for texte in ["No such key: GroupMembership", "GroupMembership: root\n", ""] {
            assert_eq!(admins_macos(None, || Some(texte.into())), None, "{texte:?}");
            assert_eq!(
                admins_macos(Some(noms(&["root"])), || Some(texte.into())),
                None,
                "{texte:?}"
            );
        }
    }

    #[test]
    fn nouvel_administrateur_signale_une_semaine() {
        let alice = vec!["alice".to_string()];
        let (c, vus) = juger(&alice, None, jour(10));
        assert!(c.probleme.is_none() && c.message.contains("alice"));
        let deux = vec!["alice".to_string(), "intrus".to_string()];
        let (c, vus) = juger(&deux, Some(&vus), jour(12));
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(c.message.contains("intrus") && !c.message.contains("alice"));
        assert_eq!(juger(&deux, Some(&vus), jour(18)).0.probleme, Some(Niveau::Eleve));
        assert!(juger(&deux, Some(&vus), jour(19)).0.probleme.is_none());
    }

    #[test]
    fn administrateur_retire_puis_remis_signale() {
        let (alice, deux) = (vec!["alice".to_string()], vec!["alice".to_string(), "bob".to_string()]);
        // bob est connu dès le premier passage (date vide), puis retiré du groupe.
        let (_, vus) = juger(&deux, None, jour(1));
        let (c, vus) = juger(&alice, Some(&vus), jour(2));
        assert!(c.probleme.is_none());
        assert!(!vus.vus.contains_key("bob"));
        // Remis des semaines plus tard : signalé comme un nouveau.
        let (c, _) = juger(&deux, Some(&vus), jour(25));
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(c.message.contains("bob") && !c.message.contains("alice"));
        // Une liste lue vide n'oublie personne.
        let (_, vides) = juger(&[], Some(&vus), jour(26));
        assert_eq!(vides, vus);
    }
}

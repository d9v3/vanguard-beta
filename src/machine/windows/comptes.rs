//! Comptes locaux Windows : invité, Administrateur intégré, comptes sans mot de passe exigé, règle des mots de passe
//! (longueur minimale, blocage après des essais ratés).

use super::*;

/// Comptes locaux : invité, administrateur intégré, comptes sans mot de passe exigé, et la règle qui empêche
/// d'utiliser un compte sans mot de passe depuis le réseau. Lus avec les autres vérifications des comptes
/// (`comptes_locaux`), en sections.
pub(super) fn comptes() -> Vec<Constat> {
    let sortie = super::comptes_locaux();
    let Some(utilisateurs) = section(sortie.as_deref(), "USR") else {
        return vec![illisible("Comptes")];
    };
    let moi = section(sortie.as_deref(), "MOI").and_then(|l| l.first().map(|s| s.trim().to_string()));
    let lbp = section(sortie.as_deref(), "LBP").and_then(|l| l.first().and_then(|s| s.trim().parse().ok()));
    juger_comptes(&utilisateurs, moi.as_deref(), lbp)
}

fn juger_comptes(utilisateurs: &[&str], moi: Option<&str>, lbp: Option<u32>) -> Vec<Constat> {
    use crate::modele::Objet;
    let mut constats = Vec::new();
    for u in utilisateurs {
        let c: Vec<&str> = u.trim().splitn(4, '|').collect();
        let [actif, exige, sid, nom] = c[..] else { continue };
        if !actif.eq_ignore_ascii_case("true") {
            continue;
        }
        let nom_ps = crate::commande::ps_texte(nom);
        // L'objet : le compte par son SID, que Windows ne réattribue jamais (le nom, lui, se renomme).
        let compte = |genre: &str| Objet::de(genre, &sid.to_uppercase());
        if sid.ends_with("-501") {
            constats.push(
                alerte(
                    "Comptes",
                    Niveau::Eleve,
                    trf!("Compte invité « {nom} » activé.", "Guest account “{nom}” enabled."),
                )
                .avec_objet(compte("invite"))
                .corriger(
                    tr!("Désactiver le compte invité", "Disable the guest account"),
                    &[&format!("Disable-LocalUser -Name '{nom_ps}'")],
                ),
            );
            continue;
        }
        if sid.ends_with("-500") {
            let constat = alerte(
                "Comptes",
                Niveau::Moyen,
                trf!(
                    "Compte Administrateur intégré « {nom} » activé : son nom est connu de tous, c'est la cible préférée des attaques par mot de passe.",
                    "Built-in Administrator account “{nom}” enabled: its name is known to everyone, it is the favorite target of password attacks."
                ),
            )
            .avec_objet(compte("administrateur-integre"));
            // On ne coupe pas le compte avec lequel on travaille.
            constats.push(if moi == Some(sid) {
                constat.manuel(
                    tr!(
                        "Créer votre propre compte administrateur, puis désactiver celui-ci",
                        "Create your own administrator account, then disable this one"
                    ),
                    &["Start-Process ms-settings:otherusers"],
                )
            } else {
                constat.corriger(
                    tr!(
                        "Désactiver le compte Administrateur intégré",
                        "Disable the built-in Administrator account"
                    ),
                    &[&format!("Disable-LocalUser -Name '{nom_ps}'")],
                )
            });
        }
        if exige.eq_ignore_ascii_case("false") {
            constats.push(
                alerte(
                    "Comptes",
                    Niveau::Moyen,
                    // Windows dit seulement qu'un mot de passe vide serait accepté (« mot de passe non exigé »), pas
                    // s'il l'est : un compte créé par New-LocalUser a ce réglage même avec un mot de passe.
                    trf!(
                        "Le compte « {nom} » accepte un mot de passe vide (Windows ne l'exige pas pour lui) : s'il n'en a pas, il s'ouvre sans rien taper.",
                        "The “{nom}” account accepts an empty password (Windows does not require one for it): if it has none, it opens without typing anything."
                    ),
                )
                .avec_objet(compte("mot-de-passe-non-exige"))
                // À faire soi-même : -PasswordRequired lève seulement le drapeau, sans donner de mot de passe. Un compte
                // déjà vide s'ouvrirait toujours sans rien taper, et le bilan le dirait sain. Le mot de passe d'abord
                // (Paramètres), puis le drapeau.
                .manuel(
                    trf!(
                        "Donner un mot de passe à « {nom} » (Paramètres > Comptes), puis l'exiger toujours",
                        "Give “{nom}” a password (Settings > Accounts), then always require one"
                    ),
                    &[
                        "Start-Process ms-settings:otherusers",
                        &format!("Set-LocalUser -Name '{nom_ps}' -PasswordRequired $true"),
                    ],
                ),
            );
        }
    }
    if lbp == Some(0) {
        constats.push(
            alerte(
                "Comptes",
                Niveau::Eleve,
                tr!(
                    "Les comptes sans mot de passe sont utilisables depuis le réseau (LimitBlankPasswordUse = 0).",
                    "Accounts without a password can be used from the network (LimitBlankPasswordUse = 0)."
                ),
            )
            .corriger(
                tr!(
                    "Réserver les comptes sans mot de passe à l'écran de connexion",
                    "Restrict password-less accounts to the sign-in screen"
                ),
                &[&super::corrections::id("comptes-sans-mdp-limites")],
            ),
        );
    }
    if constats.is_empty() {
        constats.push(ok(
            "Comptes",
            tr!(
                "Compte invité et Administrateur intégré désactivés, chaque compte exige un mot de passe.",
                "Guest and built-in Administrator accounts disabled, every account requires a password."
            ),
        ));
    }
    constats
}

/// USER_MODALS_INFO_0 de lmaccess.h : la longueur minimale des mots de passe, puis des champs qui ne servent pas ici.
#[repr(C)]
#[derive(Clone, Copy)]
struct Modales0 {
    longueur_min: u32,
    _age_max: u32,
    _age_min: u32,
    _deconnexion: u32,
    _historique: u32,
}

/// USER_MODALS_INFO_3 de lmaccess.h : durée et fenêtre du blocage, puis le nombre d'essais ratés qui bloque.
#[repr(C)]
#[derive(Clone, Copy)]
struct Modales3 {
    _duree: u32,
    _fenetre: u32,
    seuil: u32,
}

#[link(name = "netapi32")]
unsafe extern "system" {
    fn NetUserModalsGet(serveur: *const u16, niveau: u32, tampon: *mut *mut u8) -> u32;
    fn NetApiBufferFree(tampon: *mut std::ffi::c_void) -> u32;
    fn NetUserEnum(
        serveur: *const u16,
        niveau: u32,
        filtre: u32,
        tampon: *mut *mut std::ffi::c_void,
        taille_max: u32,
        lus: *mut u32,
        total: *mut u32,
        reprise: *mut u32,
    ) -> u32;
    fn NetUserGetInfo(serveur: *const u16, nom: *const u16, niveau: u32, tampon: *mut *mut std::ffi::c_void) -> u32;
    fn NetLocalGroupGetMembers(
        serveur: *const u16,
        groupe: *const u16,
        niveau: u32,
        tampon: *mut *mut std::ffi::c_void,
        taille_max: u32,
        lus: *mut u32,
        total: *mut u32,
        reprise: *mut usize,
    ) -> u32;
}

// ConvertSidToStringSidW et LocalFree sont déclarés une seule fois, dans `processus` : deux déclarations du même
// import, un futur changement de signature n'en corrigerait qu'une.
use super::processus::{ConvertSidToStringSidW, LocalFree};

#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertStringSidToSidW(texte: *const u16, sid: *mut *mut std::ffi::c_void) -> i32;
    fn LookupAccountSidW(
        systeme: *const u16,
        sid: *mut std::ffi::c_void,
        nom: *mut u16,
        taille_nom: *mut u32,
        domaine: *mut u16,
        taille_domaine: *mut u32,
        genre: *mut u32,
    ) -> i32;
}

/// USER_INFO_4 de lmaccess.h, champ par champ (192 octets en 64 bits) : le nom, l'âge du mot de passe, la
/// description, les drapeaux, la dernière connexion et le SID servent.
#[repr(C)]
struct Utilisateur4 {
    nom: *const u16,
    _mot_de_passe: *const u16,
    age_mot_de_passe: u32,
    _privilege: u32,
    _dossier: *const u16,
    commentaire: *const u16,
    drapeaux: u32,
    _script: *const u16,
    _droits: u32,
    _nom_complet: *const u16,
    _commentaire_utilisateur: *const u16,
    _parametres: *const u16,
    _postes: *const u16,
    derniere_connexion: u32,
    _derniere_deconnexion: u32,
    _expiration: u32,
    _stockage: u32,
    _unites: u32,
    _heures: *const u8,
    _essais_rates: u32,
    _connexions: u32,
    _serveur: *const u16,
    _pays: u32,
    _page_de_code: u32,
    sid: *mut std::ffi::c_void,
    _groupe: u32,
    _profil: *const u16,
    _lecteur: *const u16,
    mot_de_passe_expire: u32,
}

/// Une chaîne UTF-16 terminée par un zéro, lue au plus sur `max` caractères (borne vérifiée avant chaque lecture).
///
/// # Safety
/// `p` est nul ou pointe vers une chaîne terminée par un zéro, ou longue d'au moins `max` caractères.
unsafe fn texte_large(p: *const u16, max: usize) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut fin = 0;
    // SAFETY: voir la fonction ; la borne est testée avant la lecture.
    while fin < max && unsafe { *p.add(fin) } != 0 {
        fin += 1;
    }
    // SAFETY: les `fin` premiers caractères viennent d'être lus.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, fin) })
}

fn large(texte: &str) -> Vec<u16> {
    texte.encode_utf16().chain([0]).collect()
}

/// Un SID en texte (« S-1-5-21-… »), alloué puis rendu par Windows.
///
/// # Safety
/// `sid` est nul ou pointe vers un SID valide.
unsafe fn sid_texte(sid: *mut std::ffi::c_void) -> Option<String> {
    let mut texte: *mut u16 = std::ptr::null_mut();
    // SAFETY: ConvertSidToStringSidW alloue une chaîne terminée par un zéro, lue puis rendue une seule fois.
    unsafe {
        if sid.is_null() || ConvertSidToStringSidW(sid, &raw mut texte) == 0 || texte.is_null() {
            return None;
        }
        let t = texte_large(texte, 256);
        LocalFree(texte.cast());
        Some(t)
    }
}

/// Un compte local, tel que la lecture des comptes le décrit.
#[cfg_attr(test, derive(Clone))]
struct Compte {
    nom: String,
    actif: bool,
    mot_de_passe_exige: bool,
    sid: String,
    /// Secondes depuis 1970 ; 0 : jamais connecté.
    derniere_connexion: u32,
    /// Secondes depuis le dernier changement du mot de passe ; `None` : à changer à la prochaine connexion.
    age_mot_de_passe: Option<u32>,
    /// La description du compte (usri4_comment), celle de Get-LocalUser.
    description: String,
}

/// Les comptes locaux ordinaires (NetUserEnum, puis NetUserGetInfo niveau 4 pour le SID) ; `None` si Windows refuse
/// l'un d'eux ou n'en rend aucun.
fn comptes_natifs() -> Option<Vec<Compte>> {
    const NORMAUX: u32 = 2;
    const TOUT: u32 = u32::MAX;
    const DESACTIVE: u32 = 0x2;
    const SANS_MOT_DE_PASSE: u32 = 0x20;
    /// NERR_UserNotFound : le compte a été supprimé entre la liste et sa lecture ; le seul refus qui ne cache rien.
    const COMPTE_DISPARU: u32 = 2221;
    let mut tampon: *mut std::ffi::c_void = std::ptr::null_mut();
    let (mut lus, mut total, mut reprise) = (0u32, 0u32, 0u32);
    // SAFETY: niveau 0 : un tableau de `lus` pointeurs vers des noms (USER_INFO_0), alloué par Windows, lu tant
    // qu'il vit puis rendu une seule fois. Code non nul (sauf « il en reste », 234, qu'on n'accepte pas ici) : rien.
    let noms: Vec<String> = unsafe {
        let code = NetUserEnum(
            std::ptr::null(),
            0,
            NORMAUX,
            &raw mut tampon,
            TOUT,
            &raw mut lus,
            &raw mut total,
            &raw mut reprise,
        );
        if code != 0 || tampon.is_null() {
            if !tampon.is_null() {
                NetApiBufferFree(tampon.cast());
            }
            return None;
        }
        let noms = (0..lus as usize)
            .map(|i| texte_large(tampon.cast::<*const u16>().add(i).read_unaligned(), 256))
            .collect();
        NetApiBufferFree(tampon.cast());
        noms
    };
    let mut comptes = Vec::new();
    for nom in noms {
        let mut info: *mut std::ffi::c_void = std::ptr::null_mut();
        let nom_large = large(&nom);
        // SAFETY: NetUserGetInfo niveau 4 écrit un USER_INFO_4 alloué par Windows (que `Utilisateur4` reproduit) ;
        // son SID est dans le même bloc, converti avant de le rendre une seule fois.
        let compte = unsafe {
            let code = NetUserGetInfo(std::ptr::null(), nom_large.as_ptr(), 4, &raw mut info);
            // Windows ne remplit normalement pas le tampon quand il refuse ; s'il l'a fait, il est rendu quand même,
            // comme pour les deux autres appels.
            if code != 0 || info.is_null() {
                if !info.is_null() {
                    NetApiBufferFree(info.cast());
                }
                if code == COMPTE_DISPARU {
                    continue;
                }
                return None;
            }
            let u = &*info.cast::<Utilisateur4>();
            let compte = sid_texte(u.sid).map(|sid| Compte {
                nom: texte_large(u.nom, 256),
                actif: u.drapeaux & DESACTIVE == 0,
                mot_de_passe_exige: u.drapeaux & SANS_MOT_DE_PASSE == 0,
                sid,
                derniere_connexion: u.derniere_connexion,
                // À changer à la prochaine connexion (ou jamais défini) : Get-LocalUser ne dit alors aucune date, et
                // l'âge rendu n'en est pas une.
                age_mot_de_passe: (u.mot_de_passe_expire == 0).then_some(u.age_mot_de_passe),
                description: texte_large(u.commentaire, 1024),
            });
            NetApiBufferFree(info.cast());
            compte
        };
        // Un compte sans SID lisible manquerait au bilan sans que rien ne le dise : toute la lecture passe alors à
        // PowerShell.
        comptes.push(compte?);
    }
    (!comptes.is_empty()).then_some(comptes)
}

/// Le nom du groupe des administrateurs dans la langue de Windows, trouvé par son SID (S-1-5-32-544).
fn nom_du_groupe_des_administrateurs() -> Option<String> {
    let mut sid: *mut std::ffi::c_void = std::ptr::null_mut();
    let (mut nom, mut domaine) = (vec![0u16; 256], vec![0u16; 256]);
    let (mut taille_nom, mut taille_domaine, mut genre) = (256u32, 256u32, 0u32);
    // SAFETY: ConvertStringSidToSidW alloue le SID (rendu par LocalFree) ; LookupAccountSidW écrit au plus les tailles
    // données dans les deux tampons, qui les ont.
    unsafe {
        if ConvertStringSidToSidW(large("S-1-5-32-544").as_ptr(), &raw mut sid) == 0 || sid.is_null() {
            return None;
        }
        let trouve = LookupAccountSidW(
            std::ptr::null(),
            sid,
            nom.as_mut_ptr(),
            &raw mut taille_nom,
            domaine.as_mut_ptr(),
            &raw mut taille_domaine,
            &raw mut genre,
        ) != 0;
        LocalFree(sid);
        trouve.then(|| texte_large(nom.as_ptr(), 256))
    }
}

/// Les membres du groupe des administrateurs, « ORDINATEUR\nom » comme Get-LocalGroupMember : le groupe est trouvé
/// par son SID (S-1-5-32-544), son nom changeant avec la langue de Windows.
fn administrateurs_natifs() -> Option<Vec<String>> {
    let groupe = nom_du_groupe_des_administrateurs()?;
    let mut tampon: *mut std::ffi::c_void = std::ptr::null_mut();
    let (mut lus, mut total, mut reprise) = (0u32, 0u32, 0usize);
    // SAFETY: niveau 3 : un tableau de `lus` pointeurs vers « domaine\nom » (LOCALGROUP_MEMBERS_INFO_3), alloué par
    // Windows, lu tant qu'il vit puis rendu une seule fois.
    unsafe {
        let code = NetLocalGroupGetMembers(
            std::ptr::null(),
            large(&groupe).as_ptr(),
            3,
            &raw mut tampon,
            u32::MAX,
            &raw mut lus,
            &raw mut total,
            &raw mut reprise,
        );
        if code != 0 || tampon.is_null() {
            if !tampon.is_null() {
                NetApiBufferFree(tampon.cast());
            }
            return None;
        }
        let membres = (0..lus as usize)
            .map(|i| texte_large(tampon.cast::<*const u16>().add(i).read_unaligned(), 512))
            .collect();
        NetApiBufferFree(tampon.cast());
        Some(membres)
    }
}

/// Un champ des traces sur une ligne : ni saut de ligne ni séparateur, comme `N` le fait dans les scripts.
fn champ_de_trace(texte: &str, separateur: char) -> String {
    texte
        .replace(['\r', '\n', separateur], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Une date en secondes depuis 1970, à l'heure locale « yyyy-MM-dd HH:mm », comme les scripts des traces l'écrivent ;
/// vide pour 0 (jamais).
fn date_et_heure_locales(secondes: i64) -> String {
    use chrono::TimeZone;
    if secondes <= 0 {
        return String::new();
    }
    chrono::Local
        .timestamp_opt(secondes, 0)
        .single()
        .map(|d| d.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_default()
}

/// Les lignes des comptes pour les traces, dans l'ordre de Get-LocalUser : nom, activé, dernière connexion, mot de
/// passe changé (maintenant moins son âge), SID, description, séparés par `separateur`. `maintenant` : secondes
/// depuis 1970.
fn lignes_des_comptes(comptes: &[Compte], separateur: char, maintenant: i64) -> Vec<String> {
    let vrai = |b: bool| if b { "True" } else { "False" };
    comptes
        .iter()
        .map(|c| {
            [
                champ_de_trace(&c.nom, separateur),
                vrai(c.actif).to_string(),
                date_et_heure_locales(i64::from(c.derniere_connexion)),
                c.age_mot_de_passe
                    .map(i64::from)
                    .filter(|&age| age < maintenant)
                    .map(|age| date_et_heure_locales(maintenant - age))
                    .unwrap_or_default(),
                c.sid.clone(),
                champ_de_trace(&c.description, separateur),
            ]
            .join(&separateur.to_string())
        })
        .collect()
}

/// Les comptes locaux pour les traces (NetUserEnum puis NetUserGetInfo niveau 4), sans PowerShell ; `None` comme
/// pour le bilan : l'appelant demande alors à Get-LocalUser.
pub(crate) fn comptes_des_traces(separateur: char) -> Option<Vec<String>> {
    let maintenant = chrono::Utc::now().timestamp();
    Some(lignes_des_comptes(&comptes_natifs()?, separateur, maintenant))
}

/// LOCALGROUP_MEMBERS_INFO_2 de lmaccess.h (24 octets en 64 bits) : le SID, son genre, « domaine\nom ».
#[repr(C)]
struct Membre2 {
    _sid: *mut std::ffi::c_void,
    genre: u32,
    nom: *const u16,
}

/// La classe d'un membre comme Get-LocalGroupMember la nomme, d'après SID_NAME_USE : un compte (SidTypeUser), sinon
/// un groupe (groupe, alias, groupe connu) ; un SID d'un compte supprimé ou inconnu le dit.
fn classe_du_membre(genre: u32) -> &'static str {
    match genre {
        1 => "User",
        2 | 4 | 5 => "Group",
        6 => "DeletedAccount",
        _ => "Unknown",
    }
}

/// D'où vient un membre, déduit de son domaine, faute de PrincipalSource dans l'API réseau : « AzureAD\… » et
/// « MicrosoftAccount\… » se nomment ainsi, le nom de cet ordinateur, « NT AUTHORITY » et « BUILTIN » sont locaux,
/// tout autre domaine est celui d'Active Directory. Dit « déduit » dans les traces.
fn source_du_membre(nom: &str, ordinateur: &str) -> &'static str {
    let domaine = nom.split_once('\\').map_or("", |(d, _)| d);
    if domaine.eq_ignore_ascii_case("AzureAD") {
        "AzureAD"
    } else if domaine.eq_ignore_ascii_case("MicrosoftAccount") {
        "MicrosoftAccount"
    } else if domaine.is_empty()
        || domaine.eq_ignore_ascii_case(ordinateur)
        || domaine.eq_ignore_ascii_case("NT AUTHORITY")
        || domaine.eq_ignore_ascii_case("BUILTIN")
    {
        "Local"
    } else {
        "ActiveDirectory"
    }
}

/// Les membres du groupe des administrateurs pour les traces : « domaine\nom », classe et source (déduite), comme
/// Get-LocalGroupMember -SID S-1-5-32-544 ; `None` : Windows refuse, l'appelant demande alors à PowerShell.
pub(crate) fn administrateurs_des_traces(separateur: char) -> Option<Vec<String>> {
    let groupe = nom_du_groupe_des_administrateurs()?;
    let ordinateur = std::env::var("COMPUTERNAME").unwrap_or_default();
    let mut tampon: *mut std::ffi::c_void = std::ptr::null_mut();
    let (mut lus, mut total, mut reprise) = (0u32, 0u32, 0usize);
    // SAFETY: niveau 2 : un tableau de `lus` LOCALGROUP_MEMBERS_INFO_2 (`Membre2`), alloué par Windows, lu tant qu'il
    // vit puis rendu une seule fois ; chaque nom pointe dans le même bloc.
    unsafe {
        let code = NetLocalGroupGetMembers(
            std::ptr::null(),
            large(&groupe).as_ptr(),
            2,
            &raw mut tampon,
            u32::MAX,
            &raw mut lus,
            &raw mut total,
            &raw mut reprise,
        );
        if code != 0 || tampon.is_null() {
            if !tampon.is_null() {
                NetApiBufferFree(tampon.cast());
            }
            return None;
        }
        let membres = (0..lus as usize)
            .map(|i| {
                let m = tampon.cast::<Membre2>().add(i).read_unaligned();
                let nom = texte_large(m.nom, 512);
                [
                    champ_de_trace(&nom, separateur),
                    classe_du_membre(m.genre).to_string(),
                    format!("{} (déduit/inferred)", source_du_membre(&nom, &ordinateur)),
                ]
                .join(&separateur.to_string())
            })
            .collect();
        NetApiBufferFree(tampon.cast());
        Some(membres)
    }
}

/// La date locale (« 2026-10-20 ») d'une dernière connexion en secondes depuis 1970 ; vide pour « jamais ».
fn date_locale(secondes: u32) -> String {
    use chrono::TimeZone;
    if secondes == 0 {
        return String::new();
    }
    chrono::Local
        .timestamp_opt(i64::from(secondes), 0)
        .single()
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

/// Les sections de la lecture des comptes (USR, MOI, LBP, CPT, ADM), écrites comme le script PowerShell d'avant les
/// écrivait, pour que chaque vérification les lise sans changer son verdict.
fn sections_comptes(
    comptes: &[Compte],
    moi: Option<&str>,
    lbp: Option<u32>,
    administrateurs: Option<&[String]>,
) -> String {
    let vrai = |b: bool| if b { "True" } else { "False" };
    let mut t = String::new();
    for c in comptes {
        let _ = writeln!(
            t,
            "USR|{}|{}|{}|{}",
            vrai(c.actif),
            vrai(c.mot_de_passe_exige),
            c.sid,
            c.nom
        );
    }
    t.push_str("USR_FIN\n");
    if let Some(moi) = moi {
        let _ = writeln!(t, "MOI|{moi}\nMOI_FIN");
    }
    if let Some(lbp) = lbp {
        let _ = writeln!(t, "LBP|{lbp}\nLBP_FIN");
    }
    // Les comptes oubliés : actifs, pas celui-ci, ni les comptes intégrés (500 Administrateur, 501 invité,
    // 503 DefaultAccount, 504 WDAGUtilityAccount).
    let integre = |sid: &str| ["-500", "-501", "-503", "-504"].iter().any(|f| sid.ends_with(f));
    for c in comptes
        .iter()
        .filter(|c| c.actif && Some(c.sid.as_str()) != moi && !integre(&c.sid))
    {
        let _ = writeln!(t, "CPT|{}|{}", date_locale(c.derniere_connexion), c.nom);
    }
    t.push_str("CPT_FIN\n");
    if let Some(admins) = administrateurs {
        for a in admins {
            let _ = writeln!(t, "ADM|{a}");
        }
        t.push_str("ADM_FIN\n");
    }
    t
}

/// La lecture des comptes par les fonctions de Windows, sans PowerShell ; `None` si la liste des comptes ou celle
/// des administrateurs est refusée (l'appelant reprend alors le script PowerShell, qui sait peut-être lire le groupe :
/// sans cela, la section ADM manquerait et « Nouveau compte administrateur » resterait non vérifié).
pub(super) fn lecture_native() -> Option<String> {
    let comptes = comptes_natifs()?;
    let admins = administrateurs_natifs()?;
    let lbp = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(r"SYSTEM\CurrentControlSet\Control\Lsa")
        .and_then(|k| k.get_value::<u32, _>("LimitBlankPasswordUse"))
        .ok();
    let moi = super::processus::sid();
    Some(sections_comptes(&comptes, moi.as_deref(), lbp, Some(&admins)))
}

/// Une structure de lmaccess.h et le niveau de NetUserModalsGet qui la rend. Le lien entre les deux est écrit une
/// fois, ici : `modales` ne peut pas lire un bloc dans un type qui ne le reproduit pas.
trait NiveauModales: Copy {
    const NIVEAU: u32;
}

impl NiveauModales for Modales0 {
    const NIVEAU: u32 = 0;
}

impl NiveauModales for Modales3 {
    const NIVEAU: u32 = 3;
}

/// Un niveau de NetUserModalsGet sur cet ordinateur ; `None` si Windows refuse.
fn modales<T: NiveauModales>() -> Option<T> {
    let mut tampon: *mut u8 = std::ptr::null_mut();
    // SAFETY: NetUserModalsGet (serveur nul : cet ordinateur) écrit dans `tampon` un bloc alloué par Windows au format
    // du niveau `T::NIVEAU`, que `T` reproduit (repr(C), champs de lmaccess.h, trait `NiveauModales`) ; il est copié tant qu'il vit, puis rendu
    // une seule fois par NetApiBufferFree. Code non nul : rien n'a été alloué.
    unsafe {
        if NetUserModalsGet(std::ptr::null(), T::NIVEAU, &raw mut tampon) != 0 || tampon.is_null() {
            return None;
        }
        let valeur = std::ptr::read_unaligned(tampon.cast::<T>());
        NetApiBufferFree(tampon.cast());
        Some(valeur)
    }
}

/// La règle des mots de passe des comptes locaux, lue comme « net accounts » la lit (NetUserModalsGet : sans droits
/// d'administrateur, sans dépendre de la langue de Windows) : (longueur minimale, essais ratés avant blocage ; 0 :
/// jamais bloqué). ADSI (« WinNT://<nom de l'ordinateur> ») ne convient pas : sur un vrai Windows, ce nom désigne
/// l'objet ordinateur, qui n'a pas ces réglages (vu dans la VM de test le 20 octobre).
fn lire_politique() -> Option<(u32, u32)> {
    let longueur = modales::<Modales0>()?.longueur_min;
    let seuil = modales::<Modales3>()?.seuil;
    Some((longueur, seuil))
}

pub(super) fn politique() -> Option<Constat> {
    match lire_politique() {
        Some((longueur, seuil)) => juger_politique(longueur, seuil),
        None => Some(impossible(
            "Comptes",
            tr!(
                "règle des mots de passe illisible (NetUserModalsGet)",
                "password policy unreadable (NetUserModalsGet)"
            ),
        )),
    }
}

/// Sans blocage, un programme essaie des milliers de mots de passe sur un compte local (par le réseau, le Bureau à
/// distance) : Windows 11 bloque 10 minutes après 10 essais depuis 2022, les installations plus anciennes jamais.
/// Une longueur minimale sous 8 ne vaut qu'une information : elle ne touche que les comptes locaux, pas ceux de
/// Microsoft, et seulement au prochain changement de mot de passe. Rien d'illisible n'est compté comme sain : sans
/// valeur lue, `politique` le dit.
fn juger_politique(longueur: u32, seuil: u32) -> Option<Constat> {
    if seuil == 0 {
        return Some(
            alerte(
                "Comptes",
                Niveau::Moyen,
                tr!(
                    "Aucun blocage après des mots de passe faux : un programme peut en essayer des milliers sur les comptes locaux.",
                    "No lockout after wrong passwords: a program can try thousands of them on the local accounts."
                ),
            )
            .corriger(
                tr!(
                    "Bloquer un compte 10 minutes après 10 essais ratés (réglage de Windows 11)",
                    "Lock an account for 10 minutes after 10 failed attempts (Windows 11's setting)"
                ),
                &["net accounts /lockoutthreshold:10 /lockoutduration:10 /lockoutwindow:10"],
            ),
        );
    }
    (longueur < 8).then(|| {
        alerte(
            "Comptes",
            Niveau::Info,
            trf!(
                "Les mots de passe des comptes locaux peuvent faire moins de 8 caractères (minimum : {longueur}).",
                "Local account passwords can be shorter than 8 characters (minimum: {longueur})."
            ),
        )
        .corriger(
            tr!(
                "Exiger 8 caractères au prochain changement de mot de passe",
                "Require 8 characters at the next password change"
            ),
            &["net accounts /minpwlen:8"],
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Les sections écrites comme le script PowerShell : un compte actif, l'invité désactivé, celui de la personne,
    /// et un compte jamais connecté ; puis relues par les vérifications des comptes.
    #[test]
    fn sections_des_comptes_comme_powershell() {
        let compte = |nom: &str, actif, exige, rid: u32, connexion| Compte {
            nom: nom.into(),
            actif,
            mot_de_passe_exige: exige,
            sid: format!("S-1-5-21-1-1-1-{rid}"),
            derniere_connexion: connexion,
            age_mot_de_passe: Some(0),
            description: String::new(),
        };
        let comptes = [
            compte("alice", true, true, 1001, 1_792_000_000),
            compte("Invité", false, false, 501, 0),
            compte("bob", true, false, 1002, 0),
        ];
        let admins = vec![r"SALON-PC\alice".to_string()];
        let t = sections_comptes(&comptes, Some("S-1-5-21-1-1-1-1001"), Some(1), Some(&admins));
        assert!(t.starts_with("USR|True|True|S-1-5-21-1-1-1-1001|alice\nUSR|False|False|S-1-5-21-1-1-1-501|Invité\n"));
        assert!(t.contains("MOI|S-1-5-21-1-1-1-1001\nMOI_FIN\nLBP|1\nLBP_FIN\n"));
        // Seul bob est un compte oublié possible : alice est la personne, l'invité est désactivé.
        assert!(t.contains("CPT||bob\nCPT_FIN\n"));
        assert!(t.ends_with("ADM|SALON-PC\\alice\nADM_FIN\n"));
        let usr = section(Some(t.as_str()), "USR").unwrap();
        assert_eq!(usr.len(), 3);
        // Le compte sans mot de passe exigé est vu par le jugement d'avant.
        assert!(!juger_comptes(&usr, Some("S-1-5-21-1-1-1-1001"), Some(1)).is_empty());
    }

    /// Les lignes des comptes pour les traces, comme celles de Get-LocalUser : la chronologie y lit la dernière
    /// connexion et le mot de passe changé ; un nom ou une description piégés ne coupent pas la ligne.
    #[test]
    fn lignes_des_comptes_comme_get_localuser() {
        let c = Compte {
            nom: "alice".into(),
            actif: true,
            mot_de_passe_exige: true,
            sid: "S-1-5-21-1-1-1-1001".into(),
            derniere_connexion: 1_792_000_000,
            age_mot_de_passe: Some(3600),
            description: "Compte\r\nde\u{1f}test".into(),
        };
        let jamais = Compte {
            nom: "bob".into(),
            derniere_connexion: 0,
            description: String::new(),
            ..c.clone()
        };
        // À changer à la prochaine connexion : aucune date de mot de passe, comme Get-LocalUser.
        let a_changer = Compte {
            nom: "carole".into(),
            age_mot_de_passe: None,
            ..c.clone()
        };
        let sep = '\u{1f}';
        let l = lignes_des_comptes(&[c, jamais, a_changer], sep, 1_792_003_600);
        assert_eq!(l[2].split(sep).nth(3), Some(""));
        let champs: Vec<&str> = l[0].split(sep).collect();
        assert_eq!(champs.len(), 6);
        assert_eq!(
            (champs[0], champs[1], champs[4], champs[5]),
            ("alice", "True", "S-1-5-21-1-1-1-1001", "Compte de test")
        );
        // Le mot de passe changé une heure avant « maintenant », soit à la dernière connexion.
        assert_eq!(champs[2], champs[3]);
        // Les dates à la forme que la chronologie des traces lit ; bob, jamais connecté, n'a pas de dernière
        // connexion.
        assert!(chrono::NaiveDateTime::parse_from_str(champs[2], "%Y-%m-%d %H:%M").is_ok());
        let bob: Vec<&str> = l[1].split(sep).collect();
        assert_eq!(bob[2], "");
        assert!(chrono::NaiveDateTime::parse_from_str(bob[3], "%Y-%m-%d %H:%M").is_ok());
    }

    #[test]
    fn membres_des_administrateurs() {
        assert_eq!(classe_du_membre(1), "User");
        assert_eq!(classe_du_membre(4), "Group");
        assert_eq!(classe_du_membre(8), "Unknown");
        assert_eq!(source_du_membre(r"SALON-PC\alice", "SALON-PC"), "Local");
        assert_eq!(source_du_membre(r"salon-pc\alice", "SALON-PC"), "Local");
        assert_eq!(source_du_membre(r"NT AUTHORITY\SYSTEM", "SALON-PC"), "Local");
        assert_eq!(source_du_membre(r"AzureAD\AliceMartin", "SALON-PC"), "AzureAD");
        assert_eq!(
            source_du_membre(r"MicrosoftAccount\alice@exemple.org", "SALON-PC"),
            "MicrosoftAccount"
        );
        assert_eq!(source_du_membre(r"BUREAU\alice", "SALON-PC"), "ActiveDirectory");
        assert_eq!(std::mem::size_of::<Membre2>(), 24);
        assert_eq!(std::mem::offset_of!(Membre2, nom), 16);
    }

    /// USER_INFO_4 comme lmaccess.h le range (vérifié contre les en-têtes de MinGW).
    #[test]
    fn utilisateur4_a_sa_forme() {
        use std::mem::offset_of;
        assert_eq!(std::mem::size_of::<Utilisateur4>(), 192);
        assert_eq!(offset_of!(Utilisateur4, age_mot_de_passe), 16);
        assert_eq!(offset_of!(Utilisateur4, commentaire), 32);
        assert_eq!(offset_of!(Utilisateur4, drapeaux), 40);
        assert_eq!(offset_of!(Utilisateur4, derniere_connexion), 96);
        assert_eq!(offset_of!(Utilisateur4, sid), 152);
    }

    /// Sous Wine, les vraies fonctions de Windows répondent ou refusent sans planter ; ce qu'elles rendent se relit.
    #[test]
    fn lecture_native_sous_wine() {
        if let Some(t) = lecture_native() {
            // Une lecture rendue est complète : la section ADM y est toujours (sinon le script la relit).
            assert!(t.contains("USR_FIN\n") && t.contains("CPT_FIN\n") && t.contains("ADM_FIN\n"));
            assert!(section(Some(t.as_str()), "USR").is_some());
        }
        let texte = [u16::from(b'a'), u16::from(b'b'), u16::from(b'c')];
        // SAFETY: trois caractères sans zéro final, lus au plus sur trois.
        assert_eq!(unsafe { texte_large(texte.as_ptr(), 3) }, "abc");
    }

    #[test]
    fn regle_des_mots_de_passe() {
        assert!(juger_politique(8, 10).is_none() && juger_politique(14, 5).is_none());
        let sans_blocage = juger_politique(0, 0).unwrap();
        assert_eq!(sans_blocage.probleme, Some(Niveau::Moyen));
        assert!(sans_blocage.correctif.unwrap().commandes[0].contains("/lockoutthreshold:10"));
        let courts = juger_politique(0, 10).unwrap();
        assert_eq!(courts.probleme, Some(Niveau::Info));
        assert_eq!(courts.correctif.unwrap().commandes, ["net accounts /minpwlen:8"]);
    }

    /// Les deux structures ont la taille de celles de lmaccess.h : un champ de trop ou de moins décalerait le seuil.
    #[test]
    fn modales_au_format_de_windows() {
        assert_eq!(std::mem::size_of::<Modales0>(), 20);
        assert_eq!(std::mem::size_of::<Modales3>(), 12);
        // Sous Wine, l'appel répond ou refuse, sans planter ; la valeur lue n'est jamais inventée.
        let _ = lire_politique();
    }

    #[test]
    fn comptes_juges() {
        let utilisateurs = [
            "True|True|S-1-5-21-1-1-1-1001|alice",
            "False|False|S-1-5-21-1-1-1-501|Invité",
            "False|True|S-1-5-21-1-1-1-500|Administrateur",
        ];
        let c = juger_comptes(&utilisateurs, Some("S-1-5-21-1-1-1-1001"), Some(1));
        assert!(c.len() == 1 && c[0].probleme.is_none());
        let utilisateurs = [
            "True|False|S-1-5-21-1-1-1-1002|enfant",
            "True|False|S-1-5-21-1-1-1-501|Invité",
            "True|True|S-1-5-21-1-1-1-500|Administrateur",
        ];
        let c = juger_comptes(&utilisateurs, Some("S-1-5-21-1-1-1-500"), Some(0));
        let niveaux: Vec<_> = c.iter().map(|c| c.probleme).collect();
        assert_eq!(
            niveaux,
            [
                Some(Niveau::Moyen),
                Some(Niveau::Eleve),
                Some(Niveau::Moyen),
                Some(Niveau::Eleve)
            ]
        );
        // Administrateur intégré utilisé en ce moment : conseil, pas de désactivation automatique.
        assert!(c[2].correctif.as_ref().is_some_and(|k| !k.automatique));
        // Compte sans mot de passe exigé : à faire soi-même (le drapeau seul ne donne pas de mot de passe), le nom
        // protégé dans la commande montrée.
        let k = c[0].correctif.as_ref().unwrap();
        assert!(!k.automatique);
        assert_eq!(
            k.commandes,
            [
                "Start-Process ms-settings:otherusers",
                "Set-LocalUser -Name 'enfant' -PasswordRequired $true"
            ]
        );
    }

    /// T4 : un compte se reconnaît à son SID, dans les deux langues.
    #[test]
    fn cles_sans_langue() {
        let usr = [
            "True|True|S-1-5-21-1-1-1-501|Invité",
            "True|False|S-1-5-21-1-1-1-1002|alice",
            "True|True|S-1-5-21-1-1-1-500|Administrateur",
        ];
        let cles = crate::machine::controler_regle("WIN-CPT-001", || {
            juger_comptes(&usr, Some("S-1-5-21-1-1-1-1001"), Some(1))
        });
        assert_eq!(
            cles,
            [
                "WIN-CPT-001|administrateur-integre:S-1-5-21-1-1-1-500",
                "WIN-CPT-001|invite:S-1-5-21-1-1-1-501",
                "WIN-CPT-001|mot-de-passe-non-exige:S-1-5-21-1-1-1-1002"
            ]
        );
    }
}

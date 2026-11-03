//! Les gestes du compte (`gestes::COMPTE`) : les valeurs du HKCU de la personne (réglages pour jouer, macros d'Office,
//! stratégie d'exécution de PowerShell, shell de remplacement, proxy, démarrage) et son mode d'alimentation. Le compte
//! peut déjà les changer : les faire derrière l'UAC n'ajoutait rien, sauf un défaut. Quand la fenêtre administrateur
//! s'ouvre sous un autre compte (« par-dessus l'épaule »), son HKCU est celui de cet autre compte. Ils sont donc faits
//! ici, dans le processus de Vanguard, qui tourne sous le compte de la personne : `RegKey::predef(HKEY_CURRENT_USER)`
//! est la ruche de son jeton, la même que `HKEY_USERS\<SID de la personne>` d'avant (`reparer::sid_de_la_personne`
//! lit ce même jeton). Aucune demande d'administrateur, aucun PowerShell. Limite, la même qu'avant : Vanguard lancé
//! tout entier sous un autre compte (« Exécuter en tant qu'autre utilisateur », ou administrateur d'emblée sous les
//! identifiants d'un autre) écrit dans le HKCU de ce compte-là, celui de son jeton.
//!
//! L'ordre d'une liste est gardé (`gestes::lancer_separe`) : le point de restauration et le travail élevé d'abord, en
//! un seul passage, puis ces gestes. Chacun est noté comme les autres (`changements`), avec sa valeur d'avant.

use super::corrections::{self, Resultat};
use crate::machine::gestes::{self, Donnee, FaitCompte, GesteCompte, PassageEleve};
use crate::ui::{GRIS, RESET, VERT, tr, trf, trp};

/// Le mode d'alimentation « Performances élevées » (SCHEME_MIN de powercfg).
pub(crate) const PERFORMANCES: &str = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c";

/// Fait des correctifs : leurs points de restauration et leur travail élevé par `eleve` (un seul passage, l'ordre
/// gardé), puis leurs gestes du compte ici. `eleve` rend `None` quand il n'a rien fait (dit par lui) : alors rien du
/// compte non plus, et chaque correctif est en échec, ses lignes notées telles quelles.
pub(crate) fn lancer(
    correctifs: &[Vec<String>],
    eleve: impl FnOnce(&[Vec<String>]) -> Option<(Vec<bool>, Vec<Vec<String>>)>,
) -> (Vec<bool>, Vec<Vec<String>>) {
    let mut un_echec = false;
    let mut premier = true;
    let fait = gestes::lancer_separe(
        correctifs,
        |l| l == corrections::POINT,
        |envoyes| {
            let (resultats, notes) = eleve(envoyes)?;
            Some(PassageEleve {
                resultats,
                notes,
                arrete: crate::machine::arretee_a_votre_demande(),
            })
        },
        |g| {
            if std::mem::take(&mut premier) {
                trp!(
                    "    {GRIS}Réglages de votre compte, sans droits d'administrateur :{RESET}",
                    "    {GRIS}Settings of your account, without administrator rights:{RESET}"
                );
            }
            let r = faire(g);
            dire(g, &r);
            un_echec |= !r.reussi;
            FaitCompte {
                reussi: r.reussi,
                rien: r.rien,
                avant: r.avant,
            }
        },
    );
    let Some((resultats, notes)) = fait else {
        return (vec![false; correctifs.len()], correctifs.to_vec());
    };
    // « À finir au redémarrage » ne vaut que sans vrai échec : un geste du compte manqué en est un.
    if un_echec && crate::machine::a_finir_au_redemarrage() {
        crate::machine::noter_inacheve(crate::machine::Inacheve::Non);
    }
    (resultats, notes)
}

/// Le geste et son issue, dans les mots de la personne, comme le processus élevé les montre.
fn dire(g: &GesteCompte, r: &Resultat) {
    println!("    {}", crate::ui::affichable(&g.texte(!crate::langue::anglais())));
    match (r.reussi, &r.avant) {
        (true, _) if r.rien => trp!("  {VERT}OK{RESET} ({})", "  {VERT}OK{RESET} ({})", r.raison),
        (true, Some(avant)) => trp!(
            "  {VERT}OK{RESET} (avant : {avant})",
            "  {VERT}OK{RESET} (before: {avant})"
        ),
        (true, None) => trp!("  {VERT}OK{RESET}", "  {VERT}OK{RESET}"),
        (false, _) => trp!("  Échec : {}", "  Failed: {}", r.raison),
    }
}

/// Fait un geste du compte, sous HKCU seulement (ou par powercfg, sans droits), et le relit. Un réglage d'Internet
/// changé est annoncé à WinINet, pour que les navigateurs le prennent sans fermer la session.
pub(crate) fn faire(g: &GesteCompte) -> Resultat {
    let r = match g.valeur() {
        Some(_) if matches!(g, GesteCompte::Macros { .. }) => {
            macros_sous(&winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER), g)
        }
        Some(_) => faire_sous(&winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER), g),
        None => alimentation(),
    };
    if r.reussi && !r.rien && g.rafraichir() && !prevenir_wininet() {
        // Écrit et relu : seul l'annonce a manqué. Le réglage vaut à la prochaine ouverture du navigateur.
        crate::journal::erreur(
            crate::compte_rendu::Contexte::echec("wininet/annonce"),
            "InternetSetOptionW (réglages changés) refusé",
        );
    }
    r
}

/// VBAWarnings mis à 2 (demander avant une macro) seulement s'il est plus permissif : 3 (macros signées seulement)
/// et 4 (toutes coupées) sont plus stricts, jamais baissés, même par une liste d'avant qui disait 1.
fn macros_sous(racine: &winreg::RegKey, g: &GesteCompte) -> Resultat {
    let actuelle = g.valeur().and_then(|(cle, nom)| {
        racine
            .open_subkey_with_flags(cle, winreg::enums::KEY_READ)
            .ok()?
            .get_value::<u32, _>(String::from_utf16(&nom).ok()?)
            .ok()
    });
    match actuelle {
        Some(v @ (3 | 4)) => Resultat::rien(trf!(
            "déjà {v}, plus strict, rien d'écrit",
            "already {v}, stricter, nothing written"
        )),
        _ => faire_sous(racine, g),
    }
}

/// Une valeur du geste écrite sous `racine` (HKCU ; une clé d'essai pour les tests).
fn faire_sous(racine: &winreg::RegKey, g: &GesteCompte) -> Resultat {
    match (g.valeur(), g.donnee()) {
        (Some((cle, nom)), Some(Donnee::Dword(d))) => match String::from_utf16(&nom) {
            Ok(nom) => corrections::ecrire_dword_sous(racine, &cle, &nom, d, true),
            Err(_) => Resultat::echec(
                None,
                tr!("nom de valeur illisible", "unreadable value name").to_string(),
            ),
        },
        (Some((cle, nom)), Some(Donnee::Sz(t))) => ecrire_texte(racine, &cle, &nom, |_| t.to_string()),
        (Some((cle, nom)), Some(Donnee::SwapEffect)) => ecrire_texte(racine, &cle, &nom, |avant| {
            gestes::avec_swap_effect(avant.unwrap_or_default())
        }),
        (Some((cle, nom)), Some(Donnee::Retirer)) => retirer(racine, &cle, &nom),
        // L'alimentation n'a pas de valeur ; aucun geste n'a une clé sans donnée (`GesteCompte::valeur`, `donnee`).
        _ => Resultat::echec(None, tr!("geste incomplet", "incomplete action").to_string()),
    }
}

fn nom_os(nom: &[u16]) -> std::ffi::OsString {
    use std::os::windows::ffi::OsStringExt;
    std::ffi::OsString::from_wide(nom)
}

/// Une valeur texte (REG_SZ) du compte mise à `nouveau(texte d'avant)`, la clé créée au besoin (RegCreateKeyEx ne
/// touche pas aux valeurs d'une clé qui existe). La valeur d'avant doit être un REG_SZ ou absente : un autre type
/// est refusé, son retour arrière ne serait pas exact. Déjà la bonne : rien d'écrit.
fn ecrire_texte(hkcu: &winreg::RegKey, cle: &str, nom: &[u16], nouveau: impl Fn(Option<&str>) -> String) -> Resultat {
    use std::io::ErrorKind::NotFound;
    use winreg::enums::{KEY_READ, KEY_WRITE, RegType};
    let nom = nom_os(nom);
    let (avant, texte) = match hkcu.open_subkey_with_flags(cle, KEY_READ) {
        Err(e) if e.kind() == NotFound => ("clé absente".to_string(), None),
        Err(e) => return illisible(&e),
        Ok(k) => match k.get_raw_value(&nom) {
            Err(e) if e.kind() == NotFound => ("absent".to_string(), None),
            Err(e) => return illisible(&e),
            Ok(brute) => match corrections::texte_reg(&brute).filter(|_| brute.vtype == RegType::REG_SZ) {
                Some(t) => (corrections::avant_notable(&t), Some(t)),
                None if brute.vtype == RegType::REG_SZ => {
                    return Resultat::echec(
                        None,
                        tr!(
                            "valeur d'avant illisible (texte mal formé), rien d'écrit",
                            "previous value unreadable (malformed text), nothing written"
                        )
                        .to_string(),
                    );
                }
                None => {
                    return Resultat::echec(
                        None,
                        trf!(
                            "valeur d'avant de type inattendu ({:?}), rien d'écrit",
                            "previous value of unexpected type ({:?}), nothing written",
                            brute.vtype
                        ),
                    );
                }
            },
        },
    };
    let donnee = nouveau(texte.as_deref());
    if texte.as_deref() == Some(donnee.as_str()) {
        return Resultat::rien(trf!(
            "déjà « {} », rien d'écrit",
            "already “{}”, nothing written",
            corrections::avant_notable(&donnee)
        ));
    }
    let ecrit = hkcu
        .create_subkey_with_flags(cle, KEY_READ | KEY_WRITE)
        .and_then(|(k, _)| k.set_value(&nom, &donnee).map(|()| k))
        .and_then(|k| k.get_value::<String, _>(&nom));
    match ecrit {
        Ok(relu) if relu == donnee => Resultat::fait(avant),
        Ok(_) => Resultat::echec(
            Some(avant),
            tr!(
                "relue, la valeur n'est pas celle écrite",
                "read back, the value is not the one written"
            )
            .to_string(),
        ),
        Err(e) => Resultat::echec(Some(avant), e.to_string()),
    }
}

/// Une valeur du compte retirée, puis son absence relue ; sa valeur d'avant notée (texte, DWORD ou type). Déjà
/// absente (ou sa clé) : rien à faire.
fn retirer(hkcu: &winreg::RegKey, cle: &str, nom: &[u16]) -> Resultat {
    use std::io::ErrorKind::NotFound;
    use winreg::enums::{KEY_QUERY_VALUE, KEY_SET_VALUE};
    let deja = || Resultat::rien(tr!("déjà absente, rien d'écrit", "already absent, nothing written").to_string());
    let nom = nom_os(nom);
    let k = match hkcu.open_subkey_with_flags(cle, KEY_QUERY_VALUE | KEY_SET_VALUE) {
        Ok(k) => k,
        Err(e) if e.kind() == NotFound => return deja(),
        Err(e) => return illisible(&e),
    };
    let avant = match k.get_raw_value(&nom) {
        Ok(brute) => corrections::decrire(&brute),
        Err(e) if e.kind() == NotFound => return deja(),
        Err(e) => return illisible(&e),
    };
    if let Err(e) = k.delete_value(&nom) {
        return Resultat::echec(Some(avant), e.to_string());
    }
    match k.get_raw_value(&nom) {
        Err(e) if e.kind() == NotFound => Resultat::fait(avant),
        _ => Resultat::echec(
            Some(avant),
            tr!(
                "la valeur est toujours là après son retrait",
                "the value is still there after its removal"
            )
            .to_string(),
        ),
    }
}

fn illisible(e: &std::io::Error) -> Resultat {
    Resultat::echec(
        None,
        trf!(
            "valeur d'avant illisible, rien d'écrit : {e}",
            "previous value unreadable, nothing written: {e}"
        ),
    )
}

/// Le mode actif, lu par powercfg (son chemin dans System32, sans droits).
fn mode_actif() -> Option<String> {
    let r = crate::commande::lancer(crate::commande::systeme("powercfg").arg("/getactivescheme"), 15)?;
    (r.code == Some(0))
        .then(|| crate::gaming::windows::guid_alimentation(&r.sortie))
        .flatten()
}

/// « Performances élevées » activé par powercfg /setactive, sans droits (un mode qui existe), puis relu ; la valeur
/// d'avant est le GUID du mode d'avant.
fn alimentation() -> Resultat {
    let Some(avant) = mode_actif() else {
        return Resultat::echec(
            None,
            tr!(
                "mode d'alimentation actif illisible, rien changé",
                "active power plan unreadable, nothing changed"
            )
            .to_string(),
        );
    };
    if avant == PERFORMANCES {
        return Resultat::rien(tr!("déjà actif, rien changé", "already active, nothing changed").to_string());
    }
    let lance = crate::commande::lancer(
        crate::commande::systeme("powercfg").args(["/setactive", "SCHEME_MIN"]),
        15,
    );
    if lance.is_none_or(|r| r.code != Some(0)) {
        return Resultat::echec(
            Some(avant),
            tr!("powercfg a refusé le changement", "powercfg refused the change").to_string(),
        );
    }
    match mode_actif() {
        Some(apres) if apres == PERFORMANCES => Resultat::fait(avant),
        _ => Resultat::echec(
            Some(avant),
            tr!(
                "relu, le mode actif n'est pas « Performances élevées »",
                "read back, the active plan is not “High performance”"
            )
            .to_string(),
        ),
    }
}

/// Annonce à WinINet que ses réglages ont changé (INTERNET_OPTION_SETTINGS_CHANGED, puis INTERNET_OPTION_REFRESH en
/// plus), pour toutes ses connexions : Edge et les programmes qui suivent les réglages de Windows prennent le proxy coupé
/// sans fermer la session. wininet.dll est chargée à la demande depuis System32 seulement (une liaison fixe la
/// chargerait à chaque lancement ; un nom seul la chercherait d'abord à côté du programme). Elle n'est jamais
/// déchargée : WinINet peut garder des fils ou des rappels (détection du proxy), qu'un FreeLibrary laisserait sans
/// code. `false` : non annoncé.
// FFI : LoadLibraryExW, GetProcAddress et InternetSetOptionW.
#[allow(unsafe_code)]
fn prevenir_wininet() -> bool {
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryExW(nom: *const u16, fichier: *mut c_void, drapeaux: u32) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, nom: *const u8) -> *mut c_void;
    }
    /// BOOL InternetSetOptionW(HINTERNET, DWORD, LPVOID, DWORD) (wininet.h).
    type Regler = unsafe extern "system" fn(*mut c_void, u32, *mut c_void, u32) -> i32;
    /// LOAD_LIBRARY_SEARCH_SYSTEM32.
    const CHERCHER_DANS_SYSTEM32: u32 = 0x800;
    const INTERNET_OPTION_REFRESH: u32 = 37;
    const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
    let nom: Vec<u16> = "wininet.dll\0".encode_utf16().collect();
    // SAFETY: le nom de la DLL et celui de la fonction sont terminés par un zéro ; le pointeur rendu est vérifié non
    // nul avant d'être converti à la signature de wininet.h ; les deux options s'emploient sans poignée (réglage
    // global) ni tampon (NULL, longueur 0), selon la documentation ; le module reste chargé (jamais libéré), le
    // pointeur de fonction reste donc valable.
    unsafe {
        let module = LoadLibraryExW(nom.as_ptr(), std::ptr::null_mut(), CHERCHER_DANS_SYSTEM32);
        if module.is_null() {
            return false;
        }
        let fonction = GetProcAddress(module, c"InternetSetOptionW".as_ptr().cast());
        if fonction.is_null() {
            false
        } else {
            let regler = std::mem::transmute::<*mut c_void, Regler>(fonction);
            let change = regler(
                std::ptr::null_mut(),
                INTERNET_OPTION_SETTINGS_CHANGED,
                std::ptr::null_mut(),
                0,
            ) != 0;
            // REFRESH en plus, comme l'exemple de Microsoft (relire le registre) ; sans poignée, Wine le refuse
            // (ERROR_INTERNET_INCORRECT_HANDLE_TYPE) : seul SETTINGS_CHANGED décide.
            let _ = regler(std::ptr::null_mut(), INTERNET_OPTION_REFRESH, std::ptr::null_mut(), 0);
            change
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use winreg::RegKey;
    use winreg::enums::HKEY_CURRENT_USER;

    /// Une clé d'essai sous HKCU, prise pour racine à la place de HKCU : les gestes y écrivent leurs vraies clés et
    /// leurs vrais noms, sans toucher aux réglages du compte (Wine ici, la VM ensuite).
    struct Racine {
        chemin: String,
        cle: RegKey,
    }

    impl Racine {
        fn nouvelle(nom: &str) -> Option<Self> {
            let chemin = format!(r"Software\VanguardTest-compte-{nom}-{}", std::process::id());
            let (cle, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(&chemin).ok()?;
            Some(Self { chemin, cle })
        }
    }

    impl Drop for Racine {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.chemin);
        }
    }

    fn geste(ligne: &str) -> GesteCompte {
        gestes::analyser_compte(ligne).unwrap()
    }

    /// Un DWORD du compte : clé créée au besoin, valeur d'avant notée (« absent »), relu ; refait, rien d'écrit.
    #[test]
    fn dword_du_compte_ecrit_puis_deja_bon() {
        let Some(r) = Racine::nouvelle("dword") else {
            return crate::essais::saute("registre inaccessible");
        };
        let g = geste(&gestes::ligne_compte("jeux-dvr").unwrap());
        let fait = faire_sous(&r.cle, &g);
        assert!(fait.reussi && !fait.rien, "{}", fait.raison);
        assert_eq!(fait.avant.as_deref(), Some("clé absente"));
        let lu: u32 = r
            .cle
            .open_subkey(r"System\GameConfigStore")
            .unwrap()
            .get_value("GameDVR_Enabled")
            .unwrap();
        assert_eq!(lu, 0);
        let refait = faire_sous(&r.cle, &g);
        assert!(refait.reussi && refait.rien);
        // Macros d'Office : VBAWarnings à 2, sous la clé de la version et du programme.
        let g = geste(&gestes::ligne_macros("15.0", "excel").unwrap());
        let (k, _) = r
            .cle
            .create_subkey(r"Software\Microsoft\Office\15.0\excel\Security")
            .unwrap();
        k.set_value("VBAWarnings", &1u32).unwrap();
        let fait = macros_sous(&r.cle, &g);
        assert!(
            fait.reussi && !fait.rien && fait.avant.as_deref() == Some("1"),
            "{:?}",
            fait.avant
        );
        assert_eq!(k.get_value::<u32, _>("VBAWarnings").unwrap(), 2);
        // Plus strict depuis (3 : signées seulement, 4 : toutes coupées) : jamais baissé.
        for strict in [3u32, 4] {
            k.set_value("VBAWarnings", &strict).unwrap();
            let fait = macros_sous(&r.cle, &g);
            assert!(fait.reussi && fait.rien, "{}", fait.raison);
            assert_eq!(k.get_value::<u32, _>("VBAWarnings").unwrap(), strict);
        }
    }

    /// Un texte du compte : seul un REG_SZ (ou rien) est remplacé, d'un autre type rien n'est écrit ; une valeur
    /// voisine de la clé reste. DirectXUserGlobalSettings : seul SwapEffectUpgradeEnable change.
    #[test]
    fn texte_du_compte_seulement_sur_un_texte() {
        let Some(r) = Racine::nouvelle("texte") else {
            return crate::essais::saute("registre inaccessible");
        };
        let (souris, _) = r.cle.create_subkey(r"Control Panel\Mouse").unwrap();
        souris.set_value("MouseSpeed", &"1").unwrap();
        souris.set_value("MouseSensitivity", &"10").unwrap();
        souris.set_value("MouseThreshold1", &6u32).unwrap();
        let fait = faire_sous(&r.cle, &geste(&gestes::ligne_compte("souris-vitesse").unwrap()));
        assert!(fait.reussi && fait.avant.as_deref() == Some("1"), "{}", fait.raison);
        assert_eq!(souris.get_value::<String, _>("MouseSpeed").unwrap(), "0");
        assert_eq!(souris.get_value::<String, _>("MouseSensitivity").unwrap(), "10");
        let refuse = faire_sous(&r.cle, &geste(&gestes::ligne_compte("souris-seuil1").unwrap()));
        assert!(!refuse.reussi);
        assert_eq!(souris.get_value::<u32, _>("MouseThreshold1").unwrap(), 6);
        let (dx, _) = r
            .cle
            .create_subkey(r"Software\Microsoft\DirectX\UserGpuPreferences")
            .unwrap();
        dx.set_value("DirectXUserGlobalSettings", &"VRROptimizeEnable=0;")
            .unwrap();
        let fait = faire_sous(&r.cle, &geste(&gestes::ligne_compte("jeux-fenetres").unwrap()));
        assert!(fait.reussi, "{}", fait.raison);
        let apres: String = dx.get_value("DirectXUserGlobalSettings").unwrap();
        assert_eq!(apres, gestes::avec_swap_effect("VRROptimizeEnable=0;"));
        assert!(apres.contains("VRROptimizeEnable=0;") && apres.contains("SwapEffectUpgradeEnable=1;"));
    }

    /// Un retrait du compte vise le nom exact, demi-caractère isolé compris, et seulement lui ; la valeur d'avant est
    /// notée ; déjà absente, rien à faire.
    #[test]
    fn retrait_du_compte_au_nom_exact() {
        let Some(r) = Racine::nouvelle("retrait") else {
            return crate::essais::saute("registre inaccessible");
        };
        let (run, _) = r.cle.create_subkey(gestes::CLE_RUN).unwrap();
        let piege = nom_os(&[0x61, 0xD800]);
        run.set_value(&piege, &r"C:\Users\Public\x.exe").unwrap();
        run.set_value("a", &"garde").unwrap();
        run.set_value("*", &"garde aussi").unwrap();
        let g = geste(&gestes::ligne_run_retirer(false, &[0x61, 0xD800]).unwrap());
        let fait = faire_sous(&r.cle, &g);
        assert!(fait.reussi && !fait.rien, "{}", fait.raison);
        assert_eq!(fait.avant.as_deref(), Some(r"C:\Users\Public\x.exe"));
        assert!(run.get_raw_value(&piege).is_err());
        assert_eq!(run.get_value::<String, _>("a").unwrap(), "garde");
        assert_eq!(run.get_value::<String, _>("*").unwrap(), "garde aussi");
        let refait = faire_sous(&r.cle, &g);
        assert!(refait.reussi && refait.rien);
        // Le proxy : ProxyEnable à 0, le script retiré ; ProxyServer reste.
        let (internet, _) = r
            .cle
            .create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
            .unwrap();
        internet.set_value("ProxyEnable", &1u32).unwrap();
        internet.set_value("ProxyServer", &"10.0.0.9:3128").unwrap();
        internet
            .set_value("AutoConfigURL", &"http://pac.exemple/p.pac")
            .unwrap();
        for id in ["proxy-coupe", "proxy-script-retire"] {
            let fait = faire_sous(&r.cle, &geste(&gestes::ligne_compte(id).unwrap()));
            assert!(fait.reussi && !fait.rien, "{id} : {}", fait.raison);
        }
        assert_eq!(internet.get_value::<u32, _>("ProxyEnable").unwrap(), 0);
        assert!(internet.get_raw_value("AutoConfigURL").is_err());
        assert_eq!(internet.get_value::<String, _>("ProxyServer").unwrap(), "10.0.0.9:3128");
    }

    /// WinINet se charge depuis System32 et accepte l'annonce (SETTINGS_CHANGED), sans poignée ni tampon.
    #[test]
    fn wininet_prevenu() {
        assert!(prevenir_wininet());
    }
}

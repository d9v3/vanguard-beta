//! `vanguard console <commande> -- <valeur>` : ce que la Console de la fenêtre lance quand on tape une valeur après
//! le nom d'une commande. La liste est fermée (`NOMS`), chaque commande n'accepte qu'une sorte de valeur
//! (`socle::valeur_console::Argument`) et seulement en lecture : jamais `--internet`, `--premier`, `--empreinte`,
//! `--dossier`, ni une option qui change ou envoie quelque chose. La valeur est rejugée ici en entier, même si la
//! fenêtre et son relais l'ont déjà fait : sous Windows il n'y a pas de relais, et rien de ce qui précède n'est cru.
//!
//! Confidentialité : ce processus ne relève rien et n'envoie rien (`amelioration::taire`, posé dans `main` avant
//! tout le reste), et le journal des erreurs n'en garde que « `console <commande> -- <valeur>` » (`journal`).

use std::path::{Path, PathBuf};

use crate::socle::valeur_console::{self, Argument, Racine, Refus};

/// Les commandes que la Console peut lancer avec une valeur, dans l'ordre de `sorte`.
pub(crate) const NOMS: [&str; 8] = [
    "chercher",
    "lien",
    "evenements",
    "dernieres-failles",
    "journaux-windows",
    "verifier-fichier",
    "courriel-suspect",
    "verifier-moi",
];

/// La sorte de valeur que chaque commande accepte : une seule.
pub(crate) fn sorte(commande: &str) -> Option<Argument> {
    Some(match commande {
        "chercher" => Argument::Mots,
        "lien" => Argument::Adresse,
        "evenements" => Argument::Incident,
        "dernieres-failles" | "journaux-windows" => Argument::Jours,
        "verifier-fichier" | "courriel-suspect" | "verifier-moi" => Argument::Chemin,
        _ => return None,
    })
}

/// La valeur rejugée, prête pour sa commande.
#[derive(Debug)]
pub(crate) enum Jugee {
    /// Un fichier ouvert une seule fois, sans suivre de lien, et jugé sur ce qui est ouvert : seul ce descripteur est
    /// passé à la commande, qui ne rouvre rien par son chemin.
    #[cfg(any(target_os = "linux", windows))]
    Fichier(crate::socle::ouvrir_console::FichierJuge),
    /// Un nombre de jours, de 1 à 3650.
    Jours(u32),
    /// Un texte dont la forme est bonne (mots, lien, incident).
    Texte(String),
}

/// Juge `valeur` pour `commande`, contre les endroits permis `racines` sous `maison`.
pub(crate) fn juger(commande: &str, valeur: &str, maison: &Path, racines: &[Racine]) -> Result<Jugee, Refus> {
    let sorte = sorte(commande).ok_or(Refus::Forme)?;
    match sorte {
        #[cfg(any(target_os = "linux", windows))]
        Argument::Chemin => crate::socle::ouvrir_console::ouvrir_juge(valeur, maison, racines).map(Jugee::Fichier),
        // Ailleurs, aucune descente sans lien n'est écrite : rien n'est ouvert.
        #[cfg(not(any(target_os = "linux", windows)))]
        Argument::Chemin => valeur_console::juger_lexical(valeur, maison, racines).and(Err(Refus::NonVerifie)),
        Argument::Jours => {
            valeur_console::valider(sorte, valeur)?;
            valeur_console::jours(valeur).map(|j| Jugee::Jours(u32::from(j)))
        }
        Argument::Adresse | Argument::Mots | Argument::Incident => {
            valeur_console::valider(sorte, valeur)?;
            Ok(Jugee::Texte(valeur.to_owned()))
        }
    }
}

/// Les endroits permis de ce compte.
#[cfg(unix)]
pub(crate) fn racines(maison: &Path) -> Vec<Racine> {
    // Le fichier de user-dirs.dirs est lu par le lecteur sûr (fichier ordinaire, borné) : un tube nommé posé à sa
    // place n'arrête pas la commande. XDG_CONFIG_HOME relatif : ignoré, comme le fait la spécification.
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|c| c.is_absolute())
        .unwrap_or_else(|| maison.join(".config"));
    let declares = crate::socle::lire_texte_ordinaire(&config.join("user-dirs.dirs"), 64 << 10).unwrap_or_default();
    let compte = crate::socle::personnel::compte_de(crate::socle::uid()).map(|(nom, _)| nom);
    valeur_console::racines_linux(maison, &declares, compte.as_ref().and_then(|n| n.to_str()))
}

/// Les endroits permis de ce compte : Téléchargements, Bureau et Documents (là où Windows les place, s'ils sont des
/// enfants directs du profil ou sous son OneDrive, puis ceux du profil) ; et la racine de chaque lecteur amovible que
/// Windows connaît comme tel. Tout est jugé sur le texte : rien n'est résolu ici (`canonicalize` suit une jonction ou
/// un partage, et ouvrir \\serveur\x envoie déjà l'empreinte NTLM de la session ; les dossiers connus sont demandés
/// sans vérification, `dossier_actuel`). La descente qui suit (`ouvrir_console`) ne suit aucun lien ni point de
/// montage.
#[cfg(windows)]
pub(crate) fn racines(maison: &Path) -> Vec<Racine> {
    use crate::machine::windows::environnement::{Connu, dossier_actuel};
    const DOSSIERS: [(Connu, &str); 3] = [
        (Connu::Telechargements, "Downloads"),
        (Connu::Bureau, "Desktop"),
        (Connu::Documents, "Documents"),
    ];
    // Un profil à la racine d'un lecteur (« C:\ ») ferait de tout le lecteur un « enfant du profil ».
    if !sur_un_disque(maison) || maison.parent().is_none() {
        return Vec::new();
    }
    // AppData tel que Windows le place, et tel que le dit l'environnement : jamais un endroit permis, ni rien sous
    // lui. OneDrive : jamais lui-même, mais le Bureau et les Documents que sa sauvegarde y place, oui.
    let nuages: Vec<PathBuf> = Connu::NUAGES.iter().filter_map(|c| dossier_actuel(*c)).collect();
    let jamais: Vec<PathBuf> = Connu::JAMAIS
        .iter()
        .filter_map(|c| dossier_actuel(*c))
        .chain(
            ["APPDATA", "LOCALAPPDATA"]
                .iter()
                .filter_map(std::env::var_os)
                .map(PathBuf::from),
        )
        .collect();
    let mut racines: Vec<PathBuf> = Vec::new();
    let mut garder = |r: PathBuf| {
        if !racines.iter().any(|d| meme_chemin(d, &r)) {
            racines.push(r);
        }
    };
    for (connu, profil) in DOSSIERS {
        if let Some(r) = dossier_actuel(connu).and_then(|c| racine_du_registre(&c, maison, &jamais, &nuages)) {
            garder(r);
        }
        garder(maison.join(profil));
    }
    for l in crate::machine::windows::lecteurs::lecteurs() {
        if l.amovible && sur_un_disque(&l.racine) {
            garder(l.racine);
        }
    }
    racines.into_iter().map(Racine::meme).collect()
}

/// Deux chemins qui désignent le même endroit sur le texte, comparés composant par composant comme
/// `valeur_console::reste_sous` et sans tenir compte de la casse (comme le système de fichiers de Windows) : une
/// barre finale, un « \.\ », des « / » ou une autre casse n'en font pas un autre chemin. Comparer le texte brut
/// laissait « C:\Users\alice\OneDrive\ » passer pour un enfant du profil autre que OneDrive.
#[cfg(windows)]
fn meme_chemin(a: &Path, b: &Path) -> bool {
    a.components().count() == b.components().count()
        && a.components()
            .zip(b.components())
            .all(|(x, y)| valeur_console::meme_composant(x, y))
}

/// Un chemin « C:\… » : une lettre de lecteur et sa racine, rien d'autre (ni \\serveur, ni \\?\UNC\, ni \\?\C:\,
/// ni « C:relatif »).
#[cfg(windows)]
fn sur_un_disque(chemin: &Path) -> bool {
    use std::path::{Component, Prefix};
    let mut composants = chemin.components();
    matches!(composants.next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_)))
        && composants.next() == Some(Component::RootDir)
}

/// Les noms des dossiers du profil qui ne sont jamais un endroit permis (en minuscules, tels qu'ils sont sur le
/// disque : Windows n'en traduit que l'affichage).
#[cfg(windows)]
const NOMS_JAMAIS: [&str; 9] = [
    "pictures",
    "videos",
    "music",
    "favorites",
    "contacts",
    "links",
    "saved games",
    "searches",
    "3d objects",
];

/// Un dossier connu tel que Windows le place (lu dans le registre, déjà développé), gardé seulement s'il est sur un
/// disque, sous le profil `maison`, hors des dossiers `jamais` et de tout ce qui est sous eux (AppData, les autres
/// dossiers connus, voir `Connu::JAMAIS`), autre que les dossiers `nuages` eux-mêmes (OneDrive, `Connu::NUAGES` :
/// seuls ses enfants peuvent l'être), et soit enfant direct du profil, soit enfant direct de son OneDrive (par son
/// nom, « OneDrive », « OneDrive - Entreprise », ou par sa place, un dossier de `nuages`). Chaque nom est simple :
/// ni « .. », ni « : », ni « ~ » (un nom court comme APPDAT~1 désigne AppData), ni point ou espace final (« AppData. »
/// aussi), ni nom de périphérique, ni celui d'un autre dossier connu (Pictures, Saved Games…, `NOMS_JAMAIS`) ;
/// OneDrive lui-même n'est pas un endroit permis. Les égalités se jugent composant par composant (`meme_chemin`).
/// HKCU s'écrit sans droits particuliers : un \\serveur\x y enverrait sinon l'empreinte NTLM de la session à qui
/// l'a écrit, un AppData\Roaming ferait lire des secrets comme des Documents, et un OneDrive entier tout ce qui y est
/// synchronisé.
#[cfg(windows)]
fn racine_du_registre(valeur: &Path, maison: &Path, jamais: &[PathBuf], nuages: &[PathBuf]) -> Option<PathBuf> {
    use std::path::Component;
    if !sur_un_disque(valeur)
        || jamais
            .iter()
            .any(|a| valeur_console::reste_sous(valeur, a).is_some() || meme_chemin(valeur, a))
        || nuages.iter().any(|n| meme_chemin(valeur, n))
    {
        return None;
    }
    let reste = valeur_console::reste_sous(valeur, maison)?;
    let noms: Vec<String> = reste
        .components()
        .map(|c| match c {
            Component::Normal(n) => n.to_str().map(str::to_lowercase),
            _ => None,
        })
        .collect::<Option<_>>()?;
    let simple = |n: &String| {
        !n.is_empty()
            && !n.starts_with('.')
            && !n.contains([':', '~'])
            && !n.ends_with(['.', ' '])
            && !n.starts_with("appdata")
            && !NOMS_JAMAIS.contains(&n.as_str())
            && !crate::socle::valeur_console::nom_de_peripherique(std::ffi::OsStr::new(n))
    };
    let nuage = |n: &String| n == "onedrive" || n.starts_with("onedrive - ");
    // Un OneDrive déplacé sous un autre nom (« Nuage ») est reconnu par sa place, celle que Windows donne.
    let sous_un_nuage = || {
        valeur
            .parent()
            .is_some_and(|p| nuages.iter().any(|n| meme_chemin(p, n)))
    };
    let permis = match noms.as_slice() {
        [nom] => simple(nom) && !nuage(nom),
        [dessus, nom] => (nuage(dessus) || sous_un_nuage()) && simple(dessus) && simple(nom) && !nuage(nom),
        _ => false,
    };
    permis.then(|| valeur.to_path_buf())
}

/// Lance la commande, la valeur rejugée ; un refus est dit (sans la valeur) et rend le code 2, celui d'un argument
/// refusé, sans rien lancer.
pub(crate) async fn executer(commande: &str, valeur: &str) {
    let maison = crate::socle::maison_du_compte();
    let racines = if sorte(commande) == Some(Argument::Chemin) {
        racines(&maison)
    } else {
        Vec::new()
    };
    let jugee = match juger(commande, valeur, &maison, &racines) {
        Ok(j) => j,
        Err(refus) => {
            crate::tre!(
                "  Valeur refusée pour « {} » : {}.",
                "  Value refused for “{}”: {}.",
                commande,
                refus.phrase()
            );
            if sorte(commande) == Some(Argument::Chemin) {
                crate::tre!(
                    "  Permis : un fichier sous Téléchargements, Bureau ou Documents, ou sur un support amovible.",
                    "  Allowed: a file under Downloads, Desktop or Documents, or on a removable drive."
                );
            }
            crate::machine::quitter(2);
        }
    };
    // Rien ne sort sur Internet, sauf le catalogue fixe des failles exploitées (la valeur n'y sert qu'à trier) :
    // l'examen d'un fichier peut sinon demander son empreinte à MalwareBazaar.
    if commande != "dernieres-failles" {
        crate::parametres::forcer_hors_ligne();
    }
    match (commande, jugee) {
        ("chercher", Jugee::Texte(mots)) => {
            if !crate::menu::recherche::chercher(&mots, false, true).await {
                crate::machine::quitter(1);
            }
        }
        ("lien", Jugee::Texte(adresse)) => crate::protection::lien::json(&adresse, false),
        ("evenements", Jugee::Texte(incident)) => crate::evenements::afficher(true, Some(&incident)),
        ("dernieres-failles", Jugee::Jours(jours)) => crate::protection::kev::json(jours),
        ("journaux-windows", Jugee::Jours(jours)) => crate::journaux_windows::commande::executer(None, jours, true),
        #[cfg(any(target_os = "linux", windows))]
        ("verifier-fichier", Jugee::Fichier(f)) => crate::protection::telechargement::json_juge(&f),
        #[cfg(any(target_os = "linux", windows))]
        ("courriel-suspect", Jugee::Fichier(f)) => crate::protection::courriel_suspect::json_juge(&f),
        #[cfg(any(target_os = "linux", windows))]
        ("verifier-moi", Jugee::Fichier(f)) => crate::protection::manifeste::verifier_copie_json(&f),
        _ => crate::machine::quitter(2),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Chaque nom de la liste fermée a sa sorte, et rien d'autre n'en a (ni une commande qui change, ni une option).
    #[test]
    fn chaque_commande_a_une_seule_sorte() {
        for n in NOMS {
            assert!(sorte(n).is_some(), "{n}");
        }
        for n in [
            "corriger",
            "bilan",
            "--internet",
            "lien --internet",
            "",
            "verifier-fichier ",
        ] {
            assert_eq!(sorte(n), None, "{n}");
        }
    }

    /// Chaque sorte rejugée : la valeur d'une autre sorte ne passe pas (des mots pour des jours, un chemin relatif
    /// pour un fichier), et une valeur hostile est refusée pour toutes les commandes.
    #[test]
    fn juger_refuse_ce_qui_n_est_pas_de_sa_sorte() {
        let maison = Path::new("/home/alice");
        let refus = |r: Result<Jugee, Refus>| r.err();
        assert!(matches!(
            juger("dernieres-failles", "30", maison, &[]),
            Ok(Jugee::Jours(30))
        ));
        assert_eq!(
            refus(juger("dernieres-failles", "abc", maison, &[])),
            Some(Refus::Forme)
        );
        assert_eq!(
            refus(juger("journaux-windows", "3651", maison, &[])),
            Some(Refus::Forme)
        );
        assert!(matches!(
            juger("evenements", "inc-20261116-1", maison, &[]),
            Ok(Jugee::Texte(t)) if t == "inc-20261116-1"
        ));
        assert_eq!(refus(juger("evenements", "a b", maison, &[])), Some(Refus::Forme));
        assert_eq!(
            refus(juger("lien", "https://exemple.test/a b", maison, &[])),
            Some(Refus::Forme)
        );
        assert_eq!(
            refus(juger("verifier-fichier", "x.pdf", maison, &[])),
            Some(Refus::Relatif)
        );
        assert_eq!(refus(juger("bilan", "x", maison, &[])), Some(Refus::Forme));
        for n in NOMS {
            for hostile in ["--internet", "-x", "a\u{202E}b", "x\ny", "\0", " ", ""] {
                assert!(juger(n, hostile, maison, &[]).is_err(), "{n} {hostile:?}");
            }
            assert_eq!(
                refus(juger(n, &"a".repeat(5000), maison, &[])),
                Some(Refus::TropLongue),
                "{n}"
            );
        }
    }

    /// Le programme refuse la valeur tapée sans « -- » devant, ou une seconde valeur : la ligne est
    /// `console <commande> -- <valeur>`, une seule case libre.
    #[test]
    fn la_ligne_de_la_console_est_fermee() {
        use clap::Parser;
        let lire = |l: &[&str]| crate::demarrage::arguments::Args::try_parse_from(l);
        let a = lire(&["vanguard", "console", "lien", "--", "--internet"]).unwrap();
        assert!(matches!(
            a.commande,
            Some(crate::demarrage::arguments::Commande::Console { ref commande, ref valeur })
                if commande == "lien" && valeur == "--internet"
        ));
        for refuse in [
            &["vanguard", "console", "lien", "https://exemple.test"][..],
            &["vanguard", "console", "lien", "--internet", "--", "x"],
            &["vanguard", "console", "corriger", "--", "x"],
            &["vanguard", "console", "lien", "--", "a", "b"],
            &["vanguard", "console", "lien", "--"],
        ] {
            assert!(lire(refuse).is_err(), "{refuse:?}");
        }
    }

    /// Les dossiers connus du registre (HKCU, que tout programme du compte réécrit) jugés sur le texte seul : un
    /// partage (\\serveur, \\?\UNC\), un chemin hors du profil, dans AppData, trop profond hors de OneDrive, OneDrive
    /// lui-même ou un autre dossier connu (Images, Parties enregistrées…) ne devient jamais un endroit permis ; rien
    /// n'est ouvert ni résolu pour le dire.
    /// Les dossiers connus viennent de SHGetKnownFolderPath, tels que Windows les place : Documents est un enfant
    /// direct du profil (dans le préfixe jetable sous Wine) et passe le jugement du registre ; AppData, Images et les
    /// autres de `Connu::JAMAIS` sont au contraire refusés comme racine.
    #[cfg(windows)]
    #[test]
    fn les_dossiers_connus_viennent_de_windows() {
        use crate::machine::windows::environnement::{Connu, dossier_actuel};
        let maison = PathBuf::from(std::env::var_os("USERPROFILE").unwrap());
        let jamais: Vec<PathBuf> = Connu::JAMAIS.iter().filter_map(|c| dossier_actuel(*c)).collect();
        let nuages: Vec<PathBuf> = Connu::NUAGES.iter().filter_map(|c| dossier_actuel(*c)).collect();
        let documents = dossier_actuel(Connu::Documents).unwrap();
        assert_eq!(documents.parent(), Some(maison.as_path()), "{documents:?}");
        assert_eq!(
            racine_du_registre(&documents, &maison, &jamais, &nuages),
            Some(documents.clone())
        );
        let appdata = dossier_actuel(Connu::AppData).unwrap();
        assert!(appdata.starts_with(&maison), "{appdata:?}");
        assert_eq!(racine_du_registre(&appdata, &maison, &jamais, &nuages), None);
        for c in [Connu::Images, Connu::Musique, Connu::Videos] {
            if let Some(d) = dossier_actuel(c) {
                assert_eq!(racine_du_registre(&d, &maison, &jamais, &nuages), None, "{d:?}");
            }
        }
        assert!(racines(&maison).iter().any(|r| r.reelle == documents));
    }

    #[cfg(windows)]
    #[test]
    fn le_registre_ne_donne_que_des_enfants_du_profil() {
        let maison = Path::new(r"C:\Users\alice");
        let jamais = [
            PathBuf::from(r"C:\Users\alice\AppData\Roaming"),
            PathBuf::from(r"C:\Users\alice\Donnees"),
            PathBuf::from(r"C:\Users\alice\Mes images"),
        ];
        // OneDrive tel que Windows le place (FOLDERID_SkyDrive) : la sauvegarde de ses dossiers y met le Bureau et
        // les Documents, qui restent permis ; OneDrive lui-même et ce qui est plus bas, non.
        let nuages = [PathBuf::from(r"C:\Users\alice\OneDrive")];
        let juge = |v: &str| racine_du_registre(Path::new(v), maison, &jamais, &nuages);
        for permis in [
            r"C:\Users\alice\Downloads",
            r"c:\users\ALICE\Mes documents",
            r"C:\Users\alice\OneDrive\Documents",
            r"C:\Users\alice\OneDrive\Desktop",
            r"c:\users\alice\onedrive\Bureau",
            r"C:\Users\alice\OneDrive - Contoso\Bureau",
        ] {
            assert_eq!(juge(permis), Some(PathBuf::from(permis)), "{permis}");
        }
        // Dans `jamais`, tout ce qui est sous un dossier est refusé : c'est pourquoi OneDrive n'y est pas.
        let tout_refuse = [jamais.as_slice(), nuages.as_slice()].concat();
        assert_eq!(
            racine_du_registre(
                Path::new(r"C:\Users\alice\OneDrive\Documents"),
                maison,
                &tout_refuse,
                &[]
            ),
            None
        );
        // Un OneDrive déplacé sous un autre nom (« Nuage ») : la règle des noms le laisserait passer comme enfant
        // direct du profil ; c'est sa place, dans `nuages`, qui le refuse lui-même, et qui laisse passer ses enfants
        // directs (Documents, Bureau) comme ceux d'un dossier nommé « OneDrive ». L'égalité se juge composant par
        // composant : ni une barre finale, ni « \.\ », ni des « / », ni la casse n'en font un autre dossier.
        let deplace = [PathBuf::from(r"C:\Users\alice\Nuage")];
        let juge_deplace = |v: &str| racine_du_registre(Path::new(v), maison, &jamais, &deplace);
        for refuse in [
            r"C:\Users\alice\Nuage",
            r"c:\users\alice\nuage",
            r"C:\Users\alice\Nuage\",
            r"C:\Users\alice\.\Nuage",
            r"C:\Users\alice\Nuage\.",
            r"C:/Users/alice/Nuage/",
            r"C:\USERS\ALICE\NUAGE\",
            r"C:\Users\alice\Nuage\Pictures",
            r"C:\Users\alice\Nuage\OneDrive",
            r"C:\Users\alice\Nuage\a\b",
        ] {
            assert_eq!(juge_deplace(refuse), None, "{refuse}");
        }
        for permis in [
            r"C:\Users\alice\Nuage\Documents",
            r"C:\Users\alice\Nuage\Desktop",
            r"c:\users\alice\NUAGE\Bureau",
            r"C:/Users/alice/Nuage/./Documents",
        ] {
            assert_eq!(juge_deplace(permis), Some(PathBuf::from(permis)), "{permis}");
        }
        // Sans `nuages`, « Nuage » n'est qu'un enfant du profil, et ce qui est sous lui, trop profond.
        assert!(racine_du_registre(Path::new(r"C:\Users\alice\Nuage"), maison, &jamais, &[]).is_some());
        assert_eq!(
            racine_du_registre(Path::new(r"C:\Users\alice\Nuage\Documents"), maison, &jamais, &[]),
            None
        );
        for refuse in [
            r"\\127.0.0.1\absent\Downloads",
            r"\\?\UNC\127.0.0.1\absent\Downloads",
            r"\\?\C:\Users\alice\Downloads",
            r"\\.\C:\Users\alice\Downloads",
            r"C:Users\alice\Downloads",
            r"C:\Users\bob\Downloads",
            r"C:\Users\alice",
            r"C:\Users\alice\..\bob\Downloads",
            r"C:\Users\alice\AppData",
            r"C:\Users\alice\AppData\Roaming\Downloads",
            r"C:\Users\alice\Donnees",
            // Un dossier de `jamais` lui-même, écrit autrement.
            r"C:\Users\alice\Donnees\",
            r"C:\Users\alice\.\Donnees",
            r"C:/Users/alice/donnees/",
            r"C:\USERS\ALICE\DONNEES\.",
            r"C:\Users\alice\APPDAT~1",
            r"C:\Users\alice\AppData.",
            r"C:\Users\alice\Downloads ",
            r"C:\Users\alice\.ssh",
            r"C:\Users\alice\CON",
            r"C:\Users\alice\a\b",
            r"C:\Users\alice\OneDriveX\Documents",
            r"C:\Users\alice\OneDrive\a\b",
            r"C:\Users\alice\OneDrive\AppData",
            // OneDrive lui-même, et les autres dossiers connus, par leur nom ou là où Windows les place.
            r"C:\Users\alice\OneDrive",
            r"c:\users\alice\onedrive",
            r"C:\Users\alice\OneDrive - Contoso",
            r"C:\Users\alice\OneDrive\OneDrive - Contoso",
            r"C:\Users\alice\Pictures",
            r"C:\Users\alice\OneDrive\Pictures",
            r"C:\Users\alice\Videos",
            r"C:\Users\alice\Music",
            r"C:\Users\alice\Favorites",
            r"C:\Users\alice\Contacts",
            r"C:\Users\alice\Links",
            r"C:\Users\alice\Saved Games",
            r"C:\Users\alice\OneDrive - Contoso\saved games",
            r"C:\Users\alice\Searches",
            r"C:\Users\alice\Mes images",
            r"C:\Users\alice\Mes images\Vacances",
        ] {
            assert_eq!(juge(refuse), None, "{refuse}");
        }
        // Un profil à la racine d'un lecteur : aucun endroit permis, sinon tout le lecteur serait « sous le profil ».
        assert_eq!(racines(Path::new(r"C:\")), Vec::<Racine>::new());
        assert!(sur_un_disque(Path::new(r"E:\")));
        assert!(!sur_un_disque(Path::new(r"\\?\Volume{0}\")));
        assert!(!sur_un_disque(Path::new(r"\\serveur\partage\")));
    }
}

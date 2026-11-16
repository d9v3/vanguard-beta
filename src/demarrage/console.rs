//! `vanguard console <commande> -- <valeur>` : ce que la Console de la fenêtre lance quand on tape une valeur après
//! le nom d'une commande. La liste est fermée (`NOMS`), chaque commande n'accepte qu'une sorte de valeur
//! (`socle::valeur_console::Argument`) et seulement en lecture : jamais `--internet`, `--premier`, `--empreinte`,
//! `--dossier`, ni une option qui change ou envoie quelque chose. La valeur est rejugée ici en entier, même si la
//! fenêtre et son relais l'ont déjà fait : sous Windows il n'y a pas de relais, et rien de ce qui précède n'est cru.
//!
//! Confidentialité : ce processus ne relève rien et n'envoie rien (`amelioration::taire`, posé dans `main` avant
//! tout le reste), et le journal des erreurs n'en garde que « console <commande> -- <valeur> » (`journal`).

use std::path::{Path, PathBuf};

use crate::socle::valeur_console::{self, Argument, Refus};

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
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Jugee {
    /// Un fichier : son chemin réel, liens résolus, seul passé à la commande.
    Fichier(PathBuf),
    /// Un nombre de jours, de 1 à 3650.
    Jours(u32),
    /// Un texte dont la forme est bonne (mots, lien, incident).
    Texte(String),
}

/// Juge `valeur` pour `commande`, contre les endroits permis `racines` (déjà réels) sous `maison`.
pub(crate) fn juger(commande: &str, valeur: &str, maison: &Path, racines: &[PathBuf]) -> Result<Jugee, Refus> {
    let sorte = sorte(commande).ok_or(Refus::Forme)?;
    match sorte {
        Argument::Chemin => valeur_console::juger_chemin(valeur, maison, racines).map(Jugee::Fichier),
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

/// Les endroits permis de ce compte, en chemins réels.
#[cfg(unix)]
pub(crate) fn racines(maison: &Path) -> Vec<PathBuf> {
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

/// Les endroits permis de ce compte, en chemins réels : Téléchargements, Bureau et Documents (ceux du registre, puis
/// ceux du profil), seulement sous le profil ; et la racine de chaque lecteur amovible que Windows connaît comme tel.
#[cfg(windows)]
pub(crate) fn racines(maison: &Path) -> Vec<PathBuf> {
    const DOSSIERS: [(&str, &str); 3] = [
        ("{374DE290-123F-4565-9164-39C4925E467B}", "Downloads"),
        ("Desktop", "Desktop"),
        ("Personal", "Documents"),
    ];
    let Ok(maison_reelle) = maison.canonicalize() else {
        return Vec::new();
    };
    let cle = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
        .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
        .ok();
    let mut candidats: Vec<PathBuf> = Vec::new();
    for (valeur, profil) in DOSSIERS {
        if let Some(c) = cle.as_ref().and_then(|k| k.get_value::<String, _>(valeur).ok()) {
            candidats.push(PathBuf::from(crate::protection::pieges::developper(&c)));
        }
        candidats.push(maison.join(profil));
    }
    let mut racines: Vec<PathBuf> = Vec::new();
    for c in candidats {
        if let Ok(r) = c.canonicalize()
            && r.is_dir()
            && valeur_console::racine_permise(&r, &maison_reelle)
            && !racines.contains(&r)
        {
            racines.push(r);
        }
    }
    for l in crate::machine::windows::lecteurs::lecteurs() {
        if l.amovible
            && let Ok(r) = l.racine.canonicalize()
            && !racines.contains(&r)
        {
            racines.push(r);
        }
    }
    racines
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
        ("verifier-fichier", Jugee::Fichier(f)) => crate::protection::telechargement::json(&f, None),
        ("courriel-suspect", Jugee::Fichier(f)) => crate::protection::courriel_suspect::json(&f),
        ("verifier-moi", Jugee::Fichier(f)) => crate::protection::manifeste::verifier_moi_json(Some(&f)),
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
        assert_eq!(juger("dernieres-failles", "30", maison, &[]), Ok(Jugee::Jours(30)));
        assert_eq!(juger("dernieres-failles", "abc", maison, &[]), Err(Refus::Forme));
        assert_eq!(juger("journaux-windows", "3651", maison, &[]), Err(Refus::Forme));
        assert_eq!(
            juger("evenements", "inc-20261116-1", maison, &[]),
            Ok(Jugee::Texte("inc-20261116-1".into()))
        );
        assert_eq!(juger("evenements", "a b", maison, &[]), Err(Refus::Forme));
        assert_eq!(
            juger("lien", "https://exemple.test/a b", maison, &[]),
            Err(Refus::Forme)
        );
        assert_eq!(juger("verifier-fichier", "x.pdf", maison, &[]), Err(Refus::Relatif));
        assert_eq!(juger("bilan", "x", maison, &[]), Err(Refus::Forme));
        for n in NOMS {
            for hostile in ["--internet", "-x", "a\u{202E}b", "x\ny", "\0", " ", ""] {
                assert!(juger(n, hostile, maison, &[]).is_err(), "{n} {hostile:?}");
            }
            assert_eq!(juger(n, &"a".repeat(5000), maison, &[]), Err(Refus::TropLongue), "{n}");
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
}

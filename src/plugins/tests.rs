//! Essais des plugins sur des dossiers jetables, avec des plugins inventés (compte « alice », réseau « Salon »).
#![allow(clippy::many_single_char_names)]
// Les essais des dossiers et des lancements sont pour Unix (scripts shell, droits) : sous Windows, leurs outils dorment.
#![cfg_attr(windows, allow(dead_code, unused_imports))] // j, p, a, s, e : le jetable, un plugin, une approbation…

use super::sortie::{analyser, garder, gardes_de};
use super::*;

/// Lancé en root (verifier.sh refait la suite dans `unshare -rn`, où le compte devient 0 et /tmp n'appartient plus à
/// personne de connu) : Vanguard y refuse à raison toute extension ; ces essais n'ont alors rien à montrer.
#[cfg(unix)]
fn en_root() -> bool {
    // SAFETY : geteuid ne prend aucun argument, ne touche aucune mémoire et ne peut pas échouer.
    unsafe { libc::geteuid() == 0 }
}

/// Le dossier des plugins d'un essai : réservé à son compte, retiré à la fin.
struct Jetable(PathBuf);

impl Jetable {
    fn nouveau() -> Jetable {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("vanguard-plugins-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        creer_prive(&d.join("plugins")).unwrap();
        creer_prive(&d.join("source")).unwrap();
        Jetable(d)
    }

    fn racine(&self) -> PathBuf {
        self.0.join("plugins")
    }

    fn source(&self) -> PathBuf {
        self.0.join("source")
    }
}

impl Drop for Jetable {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn manifeste(delai: u64) -> String {
    format!(
        r#"nom = "salon"
titre_fr = "Essai du salon"
titre_en = "Living room test"
description_fr = "Un plugin inventé."
description_en = "A made-up plugin."
systemes = ["linux", "macos", "windows"]
delai = {delai}
commande = "essai.sh"
arguments = ["alice"]

[windows]
commande = "essai.ps1"
"#
    )
}

const SCRIPT: &str = r#"echo "bonjour $1 $2"
echo "dossier $(pwd)"
echo "moi $0"
printf 'piege \033]52;c;eA==\007 fin\n'
echo '{"vanguard":1,"niveau":"moyen","categorie":"Salon","message":"Une prise inventée est ouverte."}'
echo '{"vanguard":1,"niveau":"ok","categorie":"Salon","message":"Tout va bien."}'
env | cut -d= -f1 | sort | tr '\n' ' '
echo
"#;

fn ecrire_source(j: &Jetable, delai: u64, script: &str) {
    std::fs::write(j.source().join(MANIFESTE), manifeste(delai)).unwrap();
    std::fs::write(j.source().join("essai.sh"), script).unwrap();
    std::fs::write(j.source().join("essai.ps1"), "Write-Output 'bonjour'\n").unwrap();
    creer_prive(&j.source().join("donnees")).unwrap();
    std::fs::write(j.source().join("donnees").join("liste.txt"), "Salon\n").unwrap();
}

#[test]
fn options_pour_vanguard_et_pour_le_plugin() {
    let a = |v: &[&str]| v.iter().map(ToString::to_string).collect::<Vec<_>>();
    let f = Facon::default();
    let isole = Facon {
        isole: true,
        auto: None,
    };
    assert_eq!(
        options_de_lancement(&a(&["x", "--rapport", "y"])),
        (true, f, a(&["x", "y"]))
    );
    assert_eq!(options_de_lancement(&a(&["--isole", "x"])), (false, isole, a(&["x"])));
    assert_eq!(
        options_de_lancement(&a(&["--", "--rapport", "--"])),
        (false, f, a(&["--rapport", "--"]))
    );
    assert_eq!(options_de_lancement(&a(&[])), (false, f, a(&[])));
}

#[test]
fn le_protocole_et_ses_bornes() {
    let mut sortie = String::from("ligne simple\n");
    sortie += "{\"vanguard\":1,\"niveau\":\"eleve\",\"categorie\":\"Réseau\",\"message\":\"Port \\u001b[2K ouvert\\nsur Salon\"}\n";
    // Pas du protocole : version, niveau inconnu, champ manquant, JSON cassé. Montrées comme des lignes.
    sortie += "{\"vanguard\":2,\"niveau\":\"info\",\"categorie\":\"a\",\"message\":\"b\"}\n";
    sortie += "{\"vanguard\":1,\"niveau\":\"grave\",\"categorie\":\"a\",\"message\":\"b\"}\n";
    sortie += "{\"vanguard\":1,\"niveau\":\"info\",\"message\":\"b\"}\n";
    sortie += "{\"vanguard\":1,\n";
    let lu = analyser(&sortie);
    assert_eq!(lu.constats.len(), 1);
    let c = &lu.constats[0];
    assert_eq!(c.probleme(), Some(crate::risk::Niveau::Eleve));
    assert_eq!(c.message, "Port \u{fffd}[2K ouvert sur Salon");
    assert_eq!(lu.lignes.len(), 5);
    let longue = format!(
        "{{\"vanguard\":1,\"niveau\":\"info\",\"categorie\":\"{}\",\"message\":\"{}\"}}\n",
        "c".repeat(100),
        "m".repeat(1000)
    );
    let lu = analyser(&longue.repeat(150));
    assert_eq!((lu.constats.len(), lu.constats_en_trop), (100, 50));
    assert!(lu.constats[0].categorie.chars().count() <= 40 && lu.constats[0].message.chars().count() <= 300);
    let lu = analyser(&"x\n".repeat(500));
    assert_eq!((lu.lignes.len(), lu.lignes_en_trop), (400, 100));
}

/// Un dossier signé par la clé d'essai : le manifeste dit sa clé publique, plugin.sig signe l'empreinte du reste.
fn signer_le_dossier(d: &Path, cle: &ed25519_dalek::SigningKey) {
    use ed25519_dalek::Signer;
    let publique = hex(&cle.verifying_key().to_bytes());
    let texte = std::fs::read_to_string(d.join(MANIFESTE)).unwrap();
    std::fs::write(d.join(MANIFESTE), format!("cle_auteur = \"{publique}\"\n{texte}")).unwrap();
    let _ = std::fs::remove_file(d.join(SIGNATURE));
    let fichiers = arbre(d, None, false).unwrap();
    let message = format!("{DOMAINE_PLUGIN}\n{}\n", empreinte_arbre(&fichiers));
    std::fs::write(d.join(SIGNATURE), hex(&cle.sign(message.as_bytes()).to_bytes())).unwrap();
}

/// L'auteur vérifié : signé par la clé que dit le manifeste, oui ; un fichier changé après la signature, une
/// signature d'une autre clé, une signature absente : refusés ; sans clé dite, l'auteur reste « non vérifié ».
#[test]
fn l_auteur_est_verifie_par_sa_signature() {
    let j = Jetable::nouveau();
    ecrire_source(&j, 5, SCRIPT);
    let d = j.source();
    let lire = || (lire_manifeste(&d).unwrap().0, arbre(&d, None, false).unwrap());
    let (m, f) = lire();
    assert_eq!(auteur_verifie(&m, &d, &f), Ok(None));
    let alice = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
    signer_le_dossier(&d, &alice);
    let (m, f) = lire();
    assert_eq!(auteur_verifie(&m, &d, &f), Ok(Some(alice.verifying_key().to_bytes())));
    // Un octet changé après la signature.
    std::fs::write(d.join("donnees").join("liste.txt"), "Salon et cuisine\n").unwrap();
    let (m, f) = lire();
    assert!(auteur_verifie(&m, &d, &f).is_err());
    // Re-signé par une autre clé, mais le manifeste dit toujours celle d'alice.
    let autre = ed25519_dalek::SigningKey::from_bytes(&[12; 32]);
    let fichiers = arbre(&d, None, false).unwrap();
    let sans: Fichiers = fichiers.into_iter().filter(|(c, _)| c != SIGNATURE).collect();
    let message = format!("{DOMAINE_PLUGIN}\n{}\n", empreinte_arbre(&sans));
    std::fs::write(
        d.join(SIGNATURE),
        hex(&ed25519_dalek::Signer::sign(&autre, message.as_bytes()).to_bytes()),
    )
    .unwrap();
    let (m, f) = lire();
    assert!(auteur_verifie(&m, &d, &f).is_err());
    // Plus de signature du tout.
    std::fs::remove_file(d.join(SIGNATURE)).unwrap();
    let (m, f) = lire();
    assert!(auteur_verifie(&m, &d, &f).is_err());
    // Une clé mal écrite dans le manifeste : le manifeste est refusé.
    let texte = std::fs::read_to_string(d.join(MANIFESTE)).unwrap();
    let premiere = texte.lines().next().unwrap().to_string();
    std::fs::write(d.join(MANIFESTE), texte.replacen(&premiere, "cle_auteur = \"abc\"", 1)).unwrap();
    assert!(lire_manifeste(&d).is_err());
}

/// La recette donnée aux auteurs dans extensions/LISEZMOI.md (sha256sum, sort, openssl) signe ce que Vanguard
/// vérifie : la même empreinte de l'arbre, le même message. Sans ces outils (Wine), rien à essayer.
#[cfg(unix)]
#[test]
fn la_recette_d_openssl_signe_ce_que_vanguard_verifie() {
    let present = std::process::Command::new("sh")
        .args(["-c", "command -v openssl && command -v sha256sum && command -v od"])
        .output()
        .is_ok_and(|r| r.status.success());
    if !present {
        return crate::essais::saute("openssl ou sha256sum absents");
    }
    let j = Jetable::nouveau();
    ecrire_source(&j, 5, SCRIPT);
    let d = j.source();
    let cle = j.0.join("auteur.pem");
    let lancer = |script: &str| {
        let r = std::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .current_dir(&d)
            .output()
            .unwrap();
        assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
        String::from_utf8(r.stdout).unwrap()
    };
    lancer(&format!("openssl genpkey -algorithm ed25519 -out '{}'", cle.display()));
    let publique = lancer(&format!(
        "openssl pkey -in '{}' -pubout -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \\n'",
        cle.display()
    ));
    let texte = std::fs::read_to_string(d.join(MANIFESTE)).unwrap();
    std::fs::write(d.join(MANIFESTE), format!("cle_auteur = \"{publique}\"\n{texte}")).unwrap();
    // La recette, telle qu'extensions/LISEZMOI.md la donne.
    let lisezmoi = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/extensions/LISEZMOI.md")).unwrap();
    let recette = lisezmoi
        .split("```sh\n# signer-plugin\n")
        .nth(1)
        .and_then(|r| r.split("```").next())
        .expect("recette de signature absente d'extensions/LISEZMOI.md");
    lancer(&recette.replace("auteur.pem", &cle.display().to_string()));
    let (m, _) = lire_manifeste(&d).unwrap();
    let f = arbre(&d, None, false).unwrap();
    assert!(auteur_verifie(&m, &d, &f).unwrap().is_some());
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn droits(chemin: &Path, mode: u32) {
        std::fs::set_permissions(chemin, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn ajoute_approuve_puis_lance_la_copie_verifiee() {
        if en_root() {
            return crate::essais::saute("en root : extensions refusées");
        }
        let j = Jetable::nouveau();
        ecrire_source(&j, 20, SCRIPT);
        let racine = j.racine();
        // Refusé : rien n'est ajouté, aucune copie ne traîne.
        let e = ajouter(&racine, &j.source(), |_| false).unwrap_err();
        assert!(e.contains("Rien"), "{e}");
        assert_eq!(std::fs::read_dir(&racine).unwrap().count(), 0);
        assert!(lancer(&racine, "salon", &[], Facon::default()).is_err());

        assert_eq!(ajouter(&racine, &j.source(), |_| true).unwrap(), "salon");
        assert!(racine.join("salon/donnees/liste.txt").is_file());
        let p = inventaire(&racine);
        assert_eq!((p.len(), &p[0].etat), (1, &Etat::Pret));
        let a = approbations(&racine);
        let ap = &a.plugins["salon"];
        // Tout le dossier a son empreinte : le .sh, le .ps1, le manifeste et les données.
        assert_eq!(ap.fichiers.len(), 4, "{:?}", ap.fichiers);

        let issue = lancer(&racine, "salon", &["--salut".to_string()], Facon::default()).unwrap();
        let s = &issue.borne.sortie;
        assert_eq!(issue.borne.code, Some(0), "{s} {}", issue.borne.erreurs);
        assert!(s.contains("bonjour alice --salut"), "{s}");
        // C'est la copie de tout le dossier qui tourne, dans ce dossier copié, retirée ensuite.
        let dossier = s.lines().find_map(|l| l.strip_prefix("dossier ")).unwrap();
        assert!(dossier.contains("/.lancement-") && dossier.ends_with("/salon"), "{s}");
        assert!(s.contains("/.lancement-"), "{s}");
        assert!(
            !std::fs::read_dir(&racine)
                .unwrap()
                .flatten()
                .any(|e| e.file_name().to_string_lossy().starts_with(".lancement-"))
        );
        // Environnement minimal : ni les variables de cargo ni celles de Vanguard.
        let variables = s.lines().last().unwrap();
        assert!(variables.contains("PATH") && variables.contains("LANG"), "{variables}");
        assert!(
            !variables.contains("CARGO") && !variables.contains("VANGUARD"),
            "{variables}"
        );
        let lu = analyser(s);
        assert_eq!(lu.constats.len(), 2);
        assert!(
            lu.lignes
                .iter()
                .any(|l| l.contains("piege \u{fffd}]52;c;eA==\u{fffd} fin"))
        );
        assert!(!lu.lignes.iter().any(|l| crate::ui::contient_un_piege(l)));

        // --rapport : gardés, relus pour le rapport, retirés avec le plugin.
        garder(&racine, &issue.manifeste, &lu.constats).unwrap();
        let g = gardes_de(&racine.join(CONSTATS));
        assert_eq!((g.len(), g[0].nom.as_str(), g[0].constats.len()), (1, "salon", 2));
        assert!(retirer(&racine, "salon", |_| true).unwrap());
        assert!(!racine.join("salon").exists() && approbations(&racine).plugins.is_empty());
        assert!(gardes_de(&racine.join(CONSTATS)).is_empty());
    }

    #[test]
    fn un_programme_ou_un_manifeste_change_est_refuse_jusqu_a_l_approbation() {
        if en_root() {
            return crate::essais::saute("en root : extensions refusées");
        }
        let j = Jetable::nouveau();
        ecrire_source(&j, 20, "echo un\n");
        let racine = j.racine();
        ajouter(&racine, &j.source(), |_| true).unwrap();
        assert!(lancer(&racine, "salon", &[], Facon::default()).is_ok());
        // Le programme échangé après l'approbation.
        std::fs::write(racine.join("salon/essai.sh"), "echo deux\n").unwrap();
        let e = lancer(&racine, "salon", &[], Facon::default()).err().unwrap();
        assert!(e.contains("a changé"), "{e}");
        assert_eq!(inventaire(&racine)[0].etat, Etat::Change);
        // Refuser la nouvelle approbation laisse le refus ; l'accepter le lève.
        assert!(approuver(&racine, "salon", |_| false).is_err());
        assert!(lancer(&racine, "salon", &[], Facon::default()).is_err());
        approuver(&racine, "salon", |_| true).unwrap();
        assert_eq!(
            lancer(&racine, "salon", &[], Facon::default()).unwrap().borne.sortie,
            "deux\n"
        );
        // Le manifeste changé (un argument de plus) : refusé aussi.
        let m = std::fs::read_to_string(racine.join("salon").join(MANIFESTE)).unwrap();
        std::fs::write(
            racine.join("salon").join(MANIFESTE),
            m.replace("[\"alice\"]", "[\"alice\", \"bob\"]"),
        )
        .unwrap();
        assert!(
            lancer(&racine, "salon", &[], Facon::default())
                .err()
                .unwrap()
                .contains("a changé")
        );
    }

    #[test]
    fn liens_et_dossiers_partages_refuses() {
        if en_root() {
            return crate::essais::saute("en root : extensions refusées");
        }
        let j = Jetable::nouveau();
        ecrire_source(&j, 20, "echo un\n");
        let racine = j.racine();
        // Une source qui contient un lien n'est pas copiée.
        std::os::unix::fs::symlink("/etc/hostname", j.source().join("lien")).unwrap();
        assert!(ajouter(&racine, &j.source(), |_| true).unwrap_err().contains("lien"));
        std::fs::remove_file(j.source().join("lien")).unwrap();
        ajouter(&racine, &j.source(), |_| true).unwrap();

        // Le programme remplacé par un lien vers un autre : refusé à l'ouverture (O_NOFOLLOW).
        let programme = racine.join("salon/essai.sh");
        std::fs::rename(&programme, racine.join("salon/vrai.sh")).unwrap();
        std::os::unix::fs::symlink(racine.join("salon/vrai.sh"), &programme).unwrap();
        assert!(lancer(&racine, "salon", &[], Facon::default()).is_err());
        std::fs::remove_file(&programme).unwrap();
        std::fs::rename(racine.join("salon/vrai.sh"), &programme).unwrap();
        assert!(lancer(&racine, "salon", &[], Facon::default()).is_ok());

        // Un programme que d'autres peuvent modifier, puis un dossier ouvert au groupe : refusés.
        droits(&programme, 0o620);
        assert!(
            lancer(&racine, "salon", &[], Facon::default())
                .err()
                .unwrap()
                .contains("modifiable")
        );
        droits(&programme, 0o600);
        droits(&racine.join("salon"), 0o770);
        assert!(
            lancer(&racine, "salon", &[], Facon::default())
                .err()
                .unwrap()
                .contains("d'autres comptes")
        );
        droits(&racine.join("salon"), 0o700);
        droits(&racine, 0o757);
        assert!(dossier_sur(&racine.join("salon")).is_err());
        droits(&racine, 0o700);
        assert!(lancer(&racine, "salon", &[], Facon::default()).is_ok());

        // Le dossier du plugin remplacé par un lien : refusé.
        std::fs::rename(racine.join("salon"), j.0.join("ailleurs")).unwrap();
        std::os::unix::fs::symlink(j.0.join("ailleurs"), racine.join("salon")).unwrap();
        assert!(
            lancer(&racine, "salon", &[], Facon::default())
                .err()
                .unwrap()
                .contains("lien")
        );
        // Retirer enlève le lien, pas ce qu'il désigne.
        assert!(retirer(&racine, "salon", |_| true).unwrap());
        assert!(j.0.join("ailleurs/essai.sh").is_file());
    }

    #[test]
    fn noms_et_chemins_hors_du_dossier_refuses() {
        if en_root() {
            return crate::essais::saute("en root : extensions refusées");
        }
        let j = Jetable::nouveau();
        let racine = j.racine();
        for nom in ["../source", "approuves.json", ".constats", "Salon", "liste"] {
            assert!(lancer(&racine, nom, &[], Facon::default()).is_err(), "{nom}");
            assert!(retirer(&racine, nom, |_| true).is_err(), "{nom}");
        }
        // Un plugin posé à la main, jamais approuvé : refusé, et dit comme tel.
        ecrire_source(&j, 20, "echo un\n");
        creer_prive(&racine.join("salon")).unwrap();
        arbre(&j.source(), Some(&racine.join("salon")), false).unwrap();
        assert_eq!(inventaire(&racine)[0].etat, Etat::NonApprouve);
        assert!(
            lancer(&racine, "salon", &[], Facon::default())
                .err()
                .unwrap()
                .contains("pas approuvé")
        );
        // Ajouter depuis le dossier des plugins lui-même : on renvoie vers approuver.
        assert!(
            ajouter(&racine, &racine.join("salon"), |_| true)
                .unwrap_err()
                .contains("approuver")
        );
    }

    /// Un manifeste ne peut que demander : `confiance = "totale"` et `dans_le_bilan` ne lèvent rien tout seuls, ni posés
    /// à la main ni ajoutés ; seule la réponse à la question à part les accorde, liée à l'empreinte du dossier.
    #[test]
    fn un_manifeste_demande_la_confiance_sans_jamais_l_obtenir_seul() {
        if en_root() {
            return crate::essais::saute("en root : extensions refusées");
        }
        let j = Jetable::nouveau();
        ecrire_source(&j, 20, "echo confiance\n");
        let m = manifeste(20).replace("delai = 20", "delai = 20\nconfiance = \"totale\"\ndans_le_bilan = true");
        std::fs::write(j.source().join(MANIFESTE), m).unwrap();
        let racine = j.racine();
        let bilan = Facon {
            isole: false,
            auto: Some(Auto::Bilan),
        };
        // Posé à la main : ni lancé à la main, ni avec le bilan.
        creer_prive(&racine.join("salon")).unwrap();
        arbre(&j.source(), Some(&racine.join("salon")), false).unwrap();
        assert!(lancer(&racine, "salon", &[], Facon::default()).is_err());
        assert!(lancer(&racine, "salon", &[], bilan).is_err());
        std::fs::remove_dir_all(racine.join("salon")).unwrap();
        // Ajouté, approuvé, mais la confiance refusée : restreint, jamais avec le bilan.
        let mut questions = Vec::new();
        ajouter(&racine, &j.source(), |q| {
            questions.push(q.to_string());
            !q.contains("demande de tourner")
        })
        .unwrap();
        assert_eq!(questions.len(), 2, "{questions:?}");
        assert!(questions[1].contains("sans restrictions") && questions[1].contains("bilan"));
        assert!(lancer(&racine, "salon", &[], Facon::default()).is_ok());
        assert!(lancer(&racine, "salon", &[], bilan).is_err());
        // Accordée : il tourne avec le bilan, tel quel.
        approuver(&racine, "salon", |_| true).unwrap();
        std::fs::write(racine.join("salon/donnees/liste.txt"), "Cuisine\n").unwrap();
        approuver(&racine, "salon", |_| true).unwrap();
        assert_eq!(
            lancer(&racine, "salon", &[], bilan).unwrap().borne.sortie,
            "confiance\n"
        );
        // Un seul fichier change (pas le programme) : la confiance tombe, et le lancement à la main est refusé.
        std::fs::write(racine.join("salon/donnees/liste.txt"), "Garage\n").unwrap();
        assert!(lancer(&racine, "salon", &[], bilan).is_err());
        assert!(
            lancer(&racine, "salon", &[], Facon::default())
                .err()
                .unwrap()
                .contains("a changé")
        );
        // Retiré puis remis : la confiance d'avant ne revient pas.
        assert!(retirer(&racine, "salon", |_| true).unwrap());
        assert_eq!(reglages::charger(&racine).plugins_a_moi.len(), 0);
    }

    /// « À moi » vaut pour le dossier tel qu'il était : un fichier ajouté ou changé le rend restreint (et refusé).
    #[test]
    fn a_moi_tombe_quand_le_dossier_change() {
        if en_root() {
            return crate::essais::saute("en root : extensions refusées");
        }
        let j = Jetable::nouveau();
        ecrire_source(&j, 20, ". ./lib.sh\necho \"$NOM\"\n");
        std::fs::write(j.source().join("lib.sh"), "NOM=salon\n").unwrap();
        let racine = j.racine();
        ajouter(&racine, &j.source(), |_| true).unwrap();
        let empreinte = inventaire(&racine)[0].empreinte.clone().unwrap();
        reglages::accorder(&racine, false, "salon", &empreinte, false, false).unwrap();
        // À moi : l'environnement complet (les variables de cargo comprises).
        assert_eq!(
            lancer(&racine, "salon", &[], Facon::default()).unwrap().borne.sortie,
            "salon\n"
        );
        // Le fichier lu par le script change : refusé, plus à moi.
        std::fs::write(racine.join("salon/lib.sh"), "NOM=piege\n").unwrap();
        assert!(
            lancer(&racine, "salon", &[], Facon::default())
                .err()
                .unwrap()
                .contains("a changé")
        );
        // Un fichier ajouté : de même.
        std::fs::write(racine.join("salon/lib.sh"), "NOM=salon\n").unwrap();
        assert!(lancer(&racine, "salon", &[], Facon::default()).is_ok());
        std::fs::write(racine.join("salon/aide.dll"), "MZ").unwrap();
        assert!(lancer(&racine, "salon", &[], Facon::default()).is_err());
    }

    /// Le plugin n'a plus de terminal : il ne peut ni y écrire à côté du filtre ni y lire les frappes.
    #[test]
    fn le_plugin_perd_le_terminal() {
        if en_root() {
            return crate::essais::saute("en root : extensions refusées");
        }
        let j = Jetable::nouveau();
        ecrire_source(
            &j,
            20,
            "if (exec 3>/dev/tty) 2>/dev/null; then echo tty; else echo sans; fi\n",
        );
        let racine = j.racine();
        ajouter(&racine, &j.source(), |_| true).unwrap();
        assert_eq!(
            lancer(&racine, "salon", &[], Facon::default()).unwrap().borne.sortie,
            "sans\n"
        );
    }

    #[test]
    fn un_plugin_trop_long_est_arrete_au_delai() {
        if en_root() {
            return crate::essais::saute("en root : extensions refusées");
        }
        let j = Jetable::nouveau();
        ecrire_source(&j, 1, "echo debut\nsleep 30\necho fin\n");
        let racine = j.racine();
        ajouter(&racine, &j.source(), |_| true).unwrap();
        let debut = std::time::Instant::now();
        let issue = lancer(&racine, "salon", &[], Facon::default()).unwrap();
        assert!(issue.borne.delai && issue.borne.sortie == "debut\n");
        assert!(debut.elapsed() < std::time::Duration::from_secs(10));
    }

    /// Les réglages et les approbations sont scellés : réécrits par un autre programme du compte (« sans
    /// restrictions », la confiance « à moi » avec le bilan, une approbation), ou acceptés tels quels après des sceaux
    /// effacés, ils n'accordent rien : rien ne tourne tout seul ni sans question, et c'est dit. Réécrits par Vanguard
    /// (la personne qui approuve de nouveau), ils valent de nouveau.
    #[test]
    fn reglages_et_approbations_forges_n_accordent_rien() {
        if en_root() {
            return crate::essais::saute("en root : extensions refusées");
        }
        let j = Jetable::nouveau();
        ecrire_source(&j, 20, "echo confiance\n");
        let m = manifeste(20).replace(
            "delai = 20",
            "delai = 20\ndans_le_bilan = true\ndans_la_surveillance = true",
        );
        std::fs::write(j.source().join(MANIFESTE), m).unwrap();
        let racine = j.racine();
        let auto = |quand| Facon {
            isole: false,
            auto: Some(quand),
        };
        ajouter(&racine, &j.source(), |_| true).unwrap();
        let empreinte = inventaire(&racine)[0].empreinte.clone().unwrap();
        reglages::accorder(&racine, false, "salon", &empreinte, true, true).unwrap();
        assert!(lancer(&racine, "salon", &[], auto(Auto::Bilan)).is_ok());
        assert_eq!(douteux(&racine), Vec::<String>::new());
        let reglages_json = racine.join("reglages.json");
        let approuves_json = racine.join(APPROUVES);
        // Les réglages réécrits à côté de Vanguard, avec la coupure générale en plus.
        let vrais = std::fs::read_to_string(&reglages_json).unwrap();
        let forges = vrais.replacen("\"sans_restrictions\": false", "\"sans_restrictions\": true", 1);
        assert_ne!(vrais, forges);
        std::fs::write(&reglages_json, &forges).unwrap();
        assert_eq!(reglages::charger(&racine), reglages::Reglages::default());
        assert!(lancer(&racine, "salon", &[], auto(Auto::Bilan)).is_err());
        assert!(lancer(&racine, "salon", &[], auto(Auto::Surveillance)).is_err());
        let dit = douteux(&racine);
        assert_eq!(dit.len(), 2, "{dit:?}");
        assert!(
            dit[0].contains("hors de Vanguard") || dit[0].contains("outside Vanguard"),
            "{dit:?}"
        );
        // Ce qu'il faut refaire est nommé.
        assert!(dit[1].contains("salon"), "{dit:?}");
        // Approuvé par Vanguard, il tourne encore à la main, restreint (la confiance forgée ne vaut rien).
        assert!(lancer(&racine, "salon", &[], Facon::default()).is_ok());
        // L'approbation réécrite à côté (le même contenu, un espace de plus) : plus rien n'est approuvé.
        let mut a = std::fs::read(&approuves_json).unwrap();
        a.push(b' ');
        std::fs::write(&approuves_json, &a).unwrap();
        assert_eq!(inventaire(&racine)[0].etat, Etat::NonApprouve);
        let refus = lancer(&racine, "salon", &[], Facon::default()).err().unwrap();
        assert!(refus.contains("pas approuvé") && refus.contains("ignorées"), "{refus}");
        assert_eq!(douteux(&racine).len(), 3);
        // Le bilan le dit comme les autres falsifications (COM-ETA-001), par l'inventaire des fichiers scellés.
        let sceaux = racine.parent().unwrap();
        for nom in [reglages::SCELLE, APPROUVES_SCELLE] {
            assert!(
                matches!(
                    crate::sceau::lire_dans(sceaux, nom),
                    crate::sceau::Lecture::Falsifie(Some(_))
                ),
                "{nom}"
            );
            assert!(crate::modele::inventaire::scelles().any(|n| n == nom), "{nom}");
        }
        // Les sceaux effacés : les deux fichiers sont acceptés tels quels, mais jamais crus.
        std::fs::remove_file(sceaux.join("sceaux.json")).unwrap();
        assert!(matches!(
            crate::sceau::lire_dans(sceaux, APPROUVES_SCELLE),
            crate::sceau::Lecture::Adopte(_)
        ));
        assert_eq!(reglages::charger(&racine), reglages::Reglages::default());
        assert!(lancer(&racine, "salon", &[], Facon::default()).is_err());
        assert!(lancer(&racine, "salon", &[], auto(Auto::Bilan)).is_err());
        let dit = douteux(&racine).join(" ");
        assert!(dit.contains("tel quel") || dit.contains("as it was"), "{dit}");
        assert!(dit.contains("vanguard extensions") && dit.contains("salon"), "{dit}");
        // Couper les restrictions redemande l'accord (la confirmation forgée ne compte pas), et l'ancien fichier
        // est gardé à côté, pas écrasé en silence.
        let mut demande = false;
        assert!(
            reglages::basculer(&racine, |_| {
                demande = true;
                true
            })
            .unwrap()
        );
        assert!(demande);
        assert!(
            std::fs::read_dir(&racine)
                .unwrap()
                .flatten()
                .any(|e| e.file_name().to_string_lossy().starts_with("reglages.illisible-"))
        );
        assert!(reglages::charger(&racine).sans_restrictions);
        // Approuvé de nouveau par la personne : il tourne.
        reglages::basculer(&racine, |_| true).unwrap();
        approuver(&racine, "salon", |_| true).unwrap();
        assert!(lancer(&racine, "salon", &[], Facon::default()).is_ok());
        assert_eq!(douteux(&racine), Vec::<String>::new());
    }

    /// Les fichiers des extensions d'une version d'avant le sceau, repris à la mise à jour : n'accordant rien (les
    /// restrictions coupées puis remises, une approbation d'un plugin retiré), ils sont réécrits scellés, sans alerte,
    /// la confirmation de la coupure redemandée ; accordant encore quelque chose, ils restent ignorés, et ce qu'il faut
    /// refaire est dit, avec la commande.
    #[test]
    fn fichiers_d_une_version_d_avant() {
        if en_root() {
            return crate::essais::saute("en root : extensions refusées");
        }
        let j = Jetable::nouveau();
        let racine = j.racine();
        let sceaux = racine.parent().unwrap();
        // La 0.87 : la coupure confirmée puis les restrictions remises, et l'approbation d'un plugin retiré depuis.
        std::fs::write(
            racine.join("reglages.json"),
            r#"{"sans_restrictions":false,"coupure_confirmee":true}"#,
        )
        .unwrap();
        std::fs::write(
            racine.join(APPROUVES),
            r#"{"plugins":{"ancien":{"arbre":"a1","fichiers":{},"le":"2026-10-01 10:00"}}}"#,
        )
        .unwrap();
        assert!(matches!(
            crate::sceau::lire_dans(sceaux, reglages::SCELLE),
            crate::sceau::Lecture::Adopte(_)
        ));
        // Rien d'accordé : aucune alerte, et rescellés.
        assert_eq!(douteux(&racine), Vec::<String>::new());
        reglages::resceller_dans(sceaux);
        for nom in [reglages::SCELLE, APPROUVES_SCELLE] {
            assert!(
                matches!(crate::sceau::lire_dans(sceaux, nom), crate::sceau::Lecture::Intact(_)),
                "{nom}"
            );
        }
        // Réécrits à leurs défauts : la confirmation reprise n'évite pas la question.
        assert!(!reglages::charger(&racine).coupure_confirmee);
        let mut demande = false;
        reglages::basculer(&racine, |_| {
            demande = true;
            false
        })
        .unwrap();
        assert!(demande);
        // Un élément « à moi » repris d'avant : ignoré, rien rescellé, et dit avec son nom et la commande.
        let j = Jetable::nouveau();
        let racine = j.racine();
        let sceaux = racine.parent().unwrap();
        std::fs::write(
            racine.join("reglages.json"),
            r#"{"plugins_a_moi":[{"nom":"salon","empreinte":"a1","bilan":true}]}"#,
        )
        .unwrap();
        reglages::resceller_dans(sceaux);
        assert!(matches!(
            crate::sceau::lire_dans(sceaux, reglages::SCELLE),
            crate::sceau::Lecture::Adopte(_)
        ));
        assert_eq!(reglages::charger(&racine), reglages::Reglages::default());
        let dit = douteux(&racine).join(" ");
        assert!(
            dit.contains("version d'avant") && dit.contains("vanguard extensions") && dit.contains("salon"),
            "{dit}"
        );
    }
}

#[cfg(unix)]
mod labo_unix {
    use super::super::labo;
    use super::*;

    fn poser(j: &Jetable, fichier: &str, texte: &str) -> PathBuf {
        let d = labo::dossier_labo(&j.racine()).unwrap();
        let chemin = d.join(fichier);
        std::fs::write(&chemin, texte).unwrap();
        chemin
    }

    #[test]
    fn un_script_est_montre_approuve_puis_redemande_s_il_change() {
        if en_root() {
            return crate::essais::saute("en root : extensions refusées");
        }
        let j = Jetable::nouveau();
        let racine = j.racine();
        let chemin = poser(&j, "essai.sh", "echo \"labo $1 $(pwd)\"\n");
        std::fs::write(labo::dossier_labo(&racine).unwrap().join("LISEZMOI.txt"), "notes").unwrap();
        let s = labo::scripts(&racine);
        assert_eq!(s.len(), 2);
        assert!(matches!(s[0].etat, labo::Etat::Refuse(_)), "un texte n'est pas lancé");
        assert_eq!(s[1].etat, labo::Etat::NonApprouve);
        // Refusé : rien ne tourne, rien n'est noté.
        assert!(labo::lancer(&racine, "essai.sh", &[], Facon::default(), |_| false).is_err());
        assert!(approbations(&racine).labo.is_empty());
        let mut demande = String::new();
        let b = labo::lancer(&racine, "essai.sh", &["alice".into()], Facon::default(), |q| {
            demande = q.to_string();
            true
        })
        .unwrap();
        assert!(demande.contains("Approuver ce script"), "{demande}");
        let reel = std::fs::canonicalize(racine.join("labo")).unwrap();
        assert_eq!(b.sortie, format!("labo alice {}\n", reel.display()));
        // Approuvé : plus de question.
        assert!(labo::lancer(&racine, "essai.sh", &[], Facon::default(), |_| panic!("déjà approuvé")).is_ok());
        // Changé : redemandé ; refusé, il ne tourne pas.
        std::fs::write(&chemin, "echo autre\n").unwrap();
        assert_eq!(labo::scripts(&racine)[1].etat, labo::Etat::Change);
        assert!(labo::lancer(&racine, "essai.sh", &[], Facon::default(), |_| false).is_err());
        let b = labo::lancer(&racine, "essai.sh", &[], Facon::default(), |_| true).unwrap();
        assert_eq!(b.sortie, "autre\n");
        // Un lien n'est jamais suivi ; un nom qui sort du dossier est refusé.
        std::os::unix::fs::symlink(&chemin, racine.join("labo/lien.sh")).unwrap();
        assert!(labo::lancer(&racine, "lien.sh", &[], Facon::default(), |_| true).is_err());
        assert!(labo::lancer(&racine, "../approuves.json", &[], Facon::default(), |_| true).is_err());
        assert!(labo::retirer(&racine, "essai.sh", |_| true).unwrap());
        assert!(!chemin.exists() && approbations(&racine).labo.is_empty());
    }

    #[test]
    fn sans_restrictions_rien_n_est_demande_sauf_le_dossier() {
        if en_root() {
            return crate::essais::saute("en root : extensions refusées");
        }
        let j = Jetable::nouveau();
        let racine = j.racine();
        poser(&j, "libre.sh", "echo libre\n");
        assert!(reglages::basculer(&racine, |_| true).unwrap());
        let b = labo::lancer(&racine, "libre.sh", &[], Facon::default(), |_| {
            panic!("aucune question")
        })
        .unwrap();
        assert_eq!(b.sortie, "libre\n");
        // Un plugin jamais approuvé tourne aussi, avec tout l'environnement (les variables de cargo comprises).
        ecrire_source(&j, 20, "env | grep -c CARGO\n");
        creer_prive(&racine.join("salon")).unwrap();
        arbre(&j.source(), Some(&racine.join("salon")), false).unwrap();
        let issue = lancer(&racine, "salon", &[], Facon::default()).unwrap();
        assert_ne!(issue.borne.sortie.trim(), "0");
        // Le seul contrôle qui reste : un dossier ouvert aux autres comptes refuse tout.
        std::fs::set_permissions(racine.join("labo"), std::os::unix::fs::PermissionsExt::from_mode(0o777)).unwrap();
        assert!(labo::lancer(&racine, "libre.sh", &[], Facon::default(), |_| true).is_err());
        std::fs::set_permissions(racine.join("labo"), std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        // Remis : la question revient.
        assert!(!reglages::basculer(&racine, |_| panic!("remettre ne demande rien")).unwrap());
        assert!(labo::lancer(&racine, "libre.sh", &[], Facon::default(), |_| false).is_err());
    }

    #[test]
    fn une_archive_zip_est_depliee_analysee_puis_ajoutee() {
        if en_root() {
            return crate::essais::saute("en root : extensions refusées");
        }
        let j = Jetable::nouveau();
        let racine = j.racine();
        let m = manifeste(20);
        let zip = super::super::archive::tests::zip(&[
            ("salon/", b"", 0o40_755),
            ("salon/plugin.toml", m.as_bytes(), 0o100_644),
            ("salon/essai.sh", b"echo zip\n", 0o100_644),
            ("salon/essai.ps1", b"Write-Output zip\n", 0o100_644),
        ]);
        let archive = j.0.join("salon.zip");
        std::fs::write(&archive, zip).unwrap();
        assert_eq!(ajouter(&racine, &archive, |_| true).unwrap(), "salon");
        assert_eq!(
            lancer(&racine, "salon", &[], Facon::default()).unwrap().borne.sortie,
            "zip\n"
        );
        // Une archive qui sort de son dossier : refusée, rien d'ajouté.
        let piegee = super::super::archive::tests::zip(&[("../evade.sh", b"x", 0o100_644)]);
        std::fs::write(&archive, piegee).unwrap();
        assert!(retirer(&racine, "salon", |_| true).unwrap());
        assert!(
            ajouter(&racine, &archive, |_| true)
                .unwrap_err()
                .contains("hors du dossier")
        );
        assert!(!j.0.join("evade.sh").exists() && !racine.join("evade.sh").exists());
    }

    /// Isolé : sans réseau (seule la boucle locale) et le dossier personnel en lecture seule. Seulement là où
    /// bubblewrap peut tourner (espaces de noms d'utilisateur permis).
    #[cfg(target_os = "linux")]
    #[test]
    fn isole_sans_reseau_ni_ecriture() {
        if en_root() {
            return crate::essais::saute("en root : extensions refusées");
        }
        let essai = std::process::Command::new("bwrap")
            .args(["--ro-bind", "/", "/", "--unshare-all", "true"])
            .status();
        if !essai.is_ok_and(|s| s.success()) {
            return crate::essais::saute("bubblewrap ne peut pas tourner ici");
        }
        let j = Jetable::nouveau();
        let racine = j.racine();
        poser(
            &j,
            "isole.sh",
            "grep -c : /proc/net/dev; ls -A \"$1\" | wc -l; touch \"$1/.vanguard-isole-essai\" 2>/dev/null && echo ecrit\n",
        );
        let maison = std::env::var("HOME").unwrap_or_default();
        let b = labo::lancer(
            &racine,
            "isole.sh",
            std::slice::from_ref(&maison),
            Facon {
                isole: true,
                auto: None,
            },
            |_| true,
        )
        .unwrap();
        // Une seule interface (lo) dans /proc/net/dev : pas de réseau ; le vrai dossier personnel est vide, vu d'ici
        // (masqué : ni ses fichiers, ni ses sockets, ni ses tubes), et rien n'y reste.
        assert_eq!(
            b.sortie.split_whitespace().collect::<Vec<_>>(),
            ["1", "0", "ecrit"],
            "{}",
            b.erreurs
        );
        assert!(!Path::new(&maison).join(".vanguard-isole-essai").exists());
    }

    /// Isolé sous macOS (sandbox-exec) : le dossier personnel ni lu ni écrit, pas de réseau, le dossier de
    /// l'extension relu mais pas écrit ; l'écriture permise reste celle du dossier jetable (HOME de l'extension).
    #[cfg(target_os = "macos")]
    #[test]
    fn isole_sous_macos_sans_reseau_ni_dossier_personnel() {
        if !Path::new("/usr/bin/sandbox-exec").is_file() {
            return crate::essais::saute("sandbox-exec absent");
        }
        let j = Jetable::nouveau();
        let racine = j.racine();
        poser(
            &j,
            "isole.sh",
            "ls \"$1\" >/dev/null 2>&1 && echo lit\n\
             touch \"$1/.vanguard-isole-essai\" 2>/dev/null && echo ecrit\n\
             /usr/bin/nc -z -G 2 1.1.1.1 53 >/dev/null 2>&1 && echo reseau\n\
             touch ./essai 2>/dev/null && echo dossier\n\
             touch \"$HOME/essai\" 2>/dev/null && echo jetable\n",
        );
        let maison = std::env::var("HOME").unwrap_or_default();
        let b = labo::lancer(
            &racine,
            "isole.sh",
            std::slice::from_ref(&maison),
            Facon {
                isole: true,
                auto: None,
            },
            |_| true,
        )
        .unwrap();
        assert_eq!(
            b.sortie.split_whitespace().collect::<Vec<_>>(),
            ["jetable"],
            "{}",
            b.erreurs
        );
        assert!(!Path::new(&maison).join(".vanguard-isole-essai").exists());
    }
}

/// En administrateur (ici, la suite refaite dans `unshare -rn`, où le compte est 0) : rien ne tourne tout seul, et
/// rien ne s'ajoute ni ne s'approuve, quoi que dise le dossier.
#[cfg(unix)]
#[test]
fn en_administrateur_rien_ne_tourne_tout_seul() {
    if !en_root() {
        return crate::essais::saute("pas en root");
    }
    let racine = std::env::temp_dir().join(format!("vanguard-admin-{}", std::process::id()));
    let auto = Facon {
        isole: false,
        auto: Some(Auto::Bilan),
    };
    assert!(
        lancer(&racine, "salon", &[], auto)
            .err()
            .unwrap()
            .contains("administrateur")
    );
    assert!(
        ajouter(&racine, &racine, |_| true)
            .err()
            .unwrap()
            .contains("administrateur")
    );
    assert!(
        approuver(&racine, "salon", |_| true)
            .err()
            .unwrap()
            .contains("administrateur")
    );
    assert!(opt_in(false).is_empty() && opt_in(true).is_empty());
}

/// Un interpréteur n'est pris que s'il est au système : à root, dans des dossiers fermés aux autres.
#[cfg(unix)]
#[test]
fn seul_un_interprete_du_systeme_est_pris() {
    assert!(du_systeme(Path::new("/bin/sh")) || en_root());
    let j = Jetable::nouveau();
    let faux = j.0.join("python3");
    std::fs::write(&faux, "#!/bin/sh\n").unwrap();
    assert!(!du_systeme(&faux));
}

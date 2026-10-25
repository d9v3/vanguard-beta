//! L'inventaire des fichiers d'état de Vanguard : ce qu'il garde dans son dossier de données (ou sur la clé), quel
//! module l'écrit, à quelle version de son format, et s'il est scellé (`sceau`). `sceau` en tire la liste de ce qu'il
//! protège : un fichier qui décide de ce que Vanguard dit ne peut plus être ajouté sans qu'on se demande s'il doit
//! l'être, et un test relit le code pour qu'aucun nom n'y échappe (ce qu'il voit : le doc de son test, T12).
//!
//! Ce n'est pas un registre de ce que Vanguard a posé sur le système : la désinstallation recalcule tout à partir de
//! ce qu'elle trouve, exprès (desinstaller.rs), et ne lit pas cette liste.

use crate::sceau;

/// Où vit un fichier d'état.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // lu par les tests ; l'export du journal (E3) s'en servira
pub(crate) enum Lieu {
    /// Le dossier de données de cet ordinateur (`reseau::dossier_local`).
    Local,
    /// La clé VANGUARD.
    Cle,
    /// La clé si elle est branchée, sinon le dossier de données.
    CleSinonLocal,
}

/// Un fichier (ou un sous-dossier) d'état.
#[cfg_attr(not(test), allow(dead_code))] // `module` et `lieu` : lus par les tests et l'export à venir
pub(crate) struct FichierEtat {
    /// Son nom sous le dossier, tel que le code le joint (« historique.json », « versions/plus-haute-vue.txt »).
    pub nom: &'static str,
    pub module: &'static str,
    /// La version de son format : notée dans les sceaux à chaque écriture d'un fichier scellé.
    pub schema: u16,
    /// Scellé par `sceau` : ce qu'il contient fait taire ou parler une alerte.
    pub scelle: bool,
    pub lieu: Lieu,
}

const fn local(nom: &'static str, module: &'static str) -> FichierEtat {
    FichierEtat {
        nom,
        module,
        schema: 1,
        scelle: false,
        lieu: Lieu::Local,
    }
}

const fn scelle(nom: &'static str, module: &'static str) -> FichierEtat {
    FichierEtat {
        scelle: true,
        ..local(nom, module)
    }
}

/// Tous les fichiers d'état connus, rangés par module.
pub(crate) const INVENTAIRE: &[FichierEtat] = &[
    // Scellés : ce qu'un programme du compte réécrirait pour faire taire sa propre alerte.
    scelle(sceau::APPRIS, "apprentissage"),
    scelle(sceau::INTEGRITE, "protection::integrite"),
    // Schéma 2 : chaque changement signalé avec son état (empreinte), pas seulement son chemin.
    FichierEtat {
        schema: 2,
        ..scelle(sceau::INTEGRITE_SIGNALE, "protection::integrite")
    },
    scelle(sceau::BOTNETS, "protection::sortantes"),
    scelle(sceau::VERSIONS, "mise_a_jour::github"),
    scelle(sceau::MACHINE, "reseau::surveillance"),
    scelle(sceau::WIFI_PUBLIC, "reseau::wifi_public"),
    scelle(sceau::REGLAGES, "optimiser"),
    scelle(sceau::NORMALES, "protection::normales"),
    scelle(sceau::TEMPS_REEL, "protection::temps_reel"),
    scelle(sceau::TEMPS_REEL_RAPPEL, "protection::temps_reel"),
    scelle(sceau::AUDIT, "reseau::surveillance"),
    scelle(sceau::SITES, "protection::sortantes"),
    scelle(sceau::PASSERELLE, "reseau::surveillance"),
    scelle(sceau::REVOCATION, "mise_a_jour::github"),
    scelle(sceau::TELECHARGEMENTS, "protection::telechargement"),
    scelle(sceau::BLOCAGE_SIGNALEES, "protection::blocage"),
    scelle(sceau::LOGICIELS, "machine::logiciels_vus"),
    // Le dernier résultat de chaque outil : un « rien trouvé » forgé ne s'affiche plus en vert dans le rapport.
    scelle(crate::modele::resultat::FICHIERS[0], "modele::resultat"),
    scelle(crate::modele::resultat::FICHIERS[1], "modele::resultat"),
    scelle(crate::modele::resultat::FICHIERS[2], "modele::resultat"),
    scelle(crate::modele::resultat::FICHIERS[3], "modele::resultat"),
    scelle(crate::modele::resultat::FICHIERS[4], "modele::resultat"),
    scelle(crate::modele::resultat::FICHIERS[5], "modele::resultat"),
    scelle(crate::modele::resultat::FICHIERS[6], "modele::resultat"),
    scelle(crate::modele::resultat::FICHIERS[7], "modele::resultat"),
    scelle(crate::modele::resultat::FICHIERS[8], "modele::resultat"),
    scelle(crate::modele::resultat::FICHIERS[9], "modele::resultat"),
    scelle(crate::modele::resultat::FICHIERS[10], "modele::resultat"),
    scelle(crate::modele::resultat::FICHIERS[11], "modele::resultat"),
    scelle(crate::modele::resultat::FICHIERS[12], "modele::resultat"),
    scelle(crate::modele::resultat::FICHIERS[13], "modele::resultat"),
    // L'autotest : la date du dernier (scellée, sinon un programme du compte repousserait l'hebdomadaire à jamais) et
    // ses lectures contredites ; le journal des mesures, non scellé (il ne décide d'aucune alerte).
    scelle(crate::autotest::DERNIER, "autotest"),
    local(crate::autotest::mesures::MESURES, "autotest::mesures"),
    // La tête du journal des événements : retirer la fin du journal sans elle se voit.
    scelle(crate::modele::journal::TETE, "modele::journal"),
    local("sceaux.json", "sceau"),
    local("sceaux.verrou", "sceau"),
    // Historique des bilans : schéma 2 depuis les clés des constats et leur seconde empreinte.
    FichierEtat {
        schema: 2,
        ..local("historique.json", "historique")
    },
    // Le relevé des corrections et des blocages : « Tout remettre comme avant » le rejoue en administrateur.
    scelle(crate::changements::RELEVE, "changements"),
    // L'empreinte de chacune de ses lignes : un relevé changé garde les lignes que Vanguard a écrites.
    scelle(crate::changements::LIGNES, "changements"),
    local(crate::modele::journal::DOSSIER, "modele::journal"),
    local("evenements.verrou", "modele::journal"),
    // Le verrou du système du journal (`socle::Verrou::prendre_compatible`), à côté de celui des versions d'avant.
    local("evenements.lock", "modele::journal"),
    local(crate::modele::resultat::EXAMENS, "modele::resultat"),
    // Le travail sans Internet, l'autodiagnostic et les versions des logiciels s'y coupent.
    scelle(crate::parametres::PARAMETRES, "parametres"),
    // Les défenses voulues (surveillance, veilleur, anti-rançongiciel) : effacées avec leur tâche, une défense coupée
    // se disait « coupée, comme par défaut ».
    scelle(crate::voulues::FICHIER, "voulues"),
    // Le programme que lance chaque tâche de Vanguard, et son empreinte : une unité pointée ailleurs restait verte.
    scelle(crate::programmes_poses::FICHIER, "programmes_poses"),
    // L'état du service du veilleur : forgé, un faux veilleur passait pour vivant.
    scelle(sceau::VEILLEUR_ETAT, "machine::linux::veilleur"),
    local("passage-restes", "passage"),
    local("reprise-version-d-avant", "passage"),
    local("bin", "mise_a_jour"),
    local("versions", "mise_a_jour::github, protection::perimes"),
    local("raccourci-retrait", "raccourci"),
    // L'état de l'entretien du mois d'avant et la note de la sauvegarde mise en place : une alerte inscrite d'avance ne
    // se disait pas nouvelle ; une note forgée faisait couper Time Machine à l'annulation.
    scelle(sceau::ENTRETIEN, "entretien"),
    scelle(sceau::SAUVEGARDE, "sauvegarde"),
    local("verifier-sauvegarde", "sauvegarde"),
    local("verifier-sauvegarde-liste", "sauvegarde"),
    local("verifier-sauvegarde-tube", "sauvegarde"),
    local("cle-donnees", "chiffrement"),
    local("cle-donnees-enveloppe-retiree", "reseau"),
    local("jeux.json", "gaming::annulation"),
    local("plugins", "plugins::sortie"),
    // Les restrictions des extensions et leurs approbations : « sans restrictions », « à moi » et une approbation font
    // tourner du code sans question.
    scelle(crate::plugins::reglages::SCELLE, "plugins::reglages"),
    scelle(crate::plugins::APPROUVES_SCELLE, "plugins"),
    local("tldr", "guide::tldr"),
    // Machine.
    scelle(sceau::ADMINISTRATEURS, "machine::administrateurs"),
    scelle(sceau::BLUETOOTH, "machine::bluetooth"),
    // Un port inscrit d'avance taisait un port exposé, ou un serveur d'IA ouvert.
    scelle(sceau::PORTS_BLOQUES, "machine"),
    local("corrections", "machine::windows"),
    local("accessibilite", "machine::windows::portes"),
    local("loldrivers", "machine::windows::pilotes"),
    local("veilleur-voulu", "machine::linux::veilleur"),
    local("veilleur-oublier-le-choix", "machine::linux::veilleur"),
    local("rancongiciel-voulu", "machine::linux::veilleur"),
    // Réglages du veilleur anti-rançongiciel (dossiers en plus, exclusions), scellés ; écrit par le palier 1 Linux.
    scelle("rancongiciel-reglages.json", "protection::rancongiciel"),
    // Protection.
    // Une catégorie désactivée ne bloque plus rien.
    scelle(crate::protection::blocage::parametres::BLOCAGE, "protection::blocage"),
    local("blocage", "protection::blocage::gestes"),
    local("quarantaine", "protection::quarantaine"),
    // Vidée ou effacée, les fichiers-pièges n'étaient plus vérifiés.
    scelle(sceau::PIEGES, "protection::pieges"),
    local("sites-bloques", "protection::sites_bloques"),
    scelle(sceau::CLES_CONNUES, "protection::cles_connues"),
    // Les références de la clé : chaque fichier de manifestes-cle/ est scellé sous son nom (`sceau::TARDIFS_DOSSIERS`).
    local(sceau::MANIFESTES_CLE, "protection::manifeste"),
    scelle(sceau::MANIFESTE_CLE, "protection::manifeste"),
    local("empreintes", "protection::empreintes, traces"),
    local("malwarebazaar", "protection::empreintes"),
    local("echap", "protection::espions::echap"),
    local("kev", "protection::kev"),
    local("feodo", "protection::sortantes"),
    local("threatfox", "protection::abuse_ch"),
    local("urlhaus", "protection::lien"),
    // Brouillons de signalement (0600), jamais sur la clé : la désinstallation les compte avant de les effacer.
    local(crate::signaler::DOSSIER, "signaler"),
    // Réseau et surveillance. Les copies « <nom>.illisible-<date>.json » (historique, appareils) sont des copies de
    // secours datées d'un fichier qui ne se lisait plus : rangées sous leur fichier d'origine, pas inventoriées à part.
    // Le carnet de cet ordinateur : un appareil inscrit d'avance n'était jamais « nouveau ».
    scelle(sceau::APPAREILS, "reseau"),
    local("appareils.json.vanguard", "chiffrement"),
    local("appareils.verrou", "reseau"),
    local("appareils.lock", "reseau"),
    local("alertes.verrou", "reseau::tableau"),
    local("connexion.json", "reseau::connexion"),
    local("surveillance-voulue", "reseau::surveillance"),
    local("horodatage", "reseau::surveillance"),
    local("retrait-constate", "reseau::surveillance"),
    local("unites-relues", "reseau::surveillance"),
    local("surveillance-alertes.jsonl", "reseau::tableau"),
    scelle(sceau::SURVEILLANCE_PASSE, "reseau::tableau"),
    local("surveillance-reseau-non-verifie.txt", "reseau::tableau"),
    local("tableau.html", "reseau::tableau"),
    local("tableau-journal", "reseau::tableau"),
    local("tableau-reseau", "reseau::tableau"),
    // Traces (collecte après incident).
    local("chronologie", "traces::chronologie"),
    local("chronologie-journal", "traces::unix"),
    local("chronologie-raisons", "traces::unix"),
    local("feuille", "traces"),
    local("feuille-dates", "traces"),
    local("fin-journal", "traces::unix"),
    local("journal-cible", "traces::linux"),
    local("journal-tourne", "traces::unix"),
    local("processus", "traces::linux"),
    // Hors du dossier de données.
    FichierEtat {
        lieu: Lieu::Cle,
        ..local("ordinateurs.json", "ordinateurs")
    },
    FichierEtat {
        lieu: Lieu::CleSinonLocal,
        ..local("journal-erreurs.txt", "journal")
    },
    FichierEtat {
        lieu: Lieu::CleSinonLocal,
        ..local("traces", "traces")
    },
];

/// Les fichiers scellés : ce que `sceau` protège.
pub(crate) fn scelles() -> impl Iterator<Item = &'static str> {
    INVENTAIRE.iter().filter(|f| f.scelle).map(|f| f.nom)
}

/// La version du format d'un fichier d'état (1 s'il n'est pas inventorié : jamais plus récent qu'il ne l'est).
pub(crate) fn schema(nom: &str) -> u16 {
    INVENTAIRE.iter().find(|f| f.nom == nom).map_or(1, |f| f.schema)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    /// Les fichiers Rust de src, sans leurs modules de tests (leurs noms « essai-… » sont des dossiers jetables).
    fn sources() -> Vec<(String, String)> {
        fn parcourir(d: &std::path::Path, tous: &mut Vec<(String, String)>) {
            for e in std::fs::read_dir(d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    parcourir(&p, tous);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    let texte = std::fs::read_to_string(&p).unwrap();
                    let code = texte.find("#[cfg(test)]\nmod ").map_or(texte.as_str(), |t| &texte[..t]);
                    tous.push((p.display().to_string(), code.to_string()));
                }
            }
        }
        let mut tous = Vec::new();
        parcourir(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut tous);
        tous
    }

    /// Le premier littéral d'un texte qui commence juste après une parenthèse ouvrante (« "nom" » ou « ("nom", »).
    fn litteral(apres: &str) -> Option<&str> {
        let reste = apres.trim_start().trim_start_matches('(').trim_start();
        let dedans = reste.strip_prefix('"')?;
        Some(&dedans[..dedans.find('"')?])
    }

    /// La valeur d'une constante `&str` du même fichier (« const NOM: &str = "valeur"; »), ou le premier élément d'une
    /// constante en couple.
    fn constante<'a>(code: &'a str, nom: &str) -> Option<&'a str> {
        let debut = code.find(&format!("const {nom}: "))?;
        let apres = &code[debut..];
        let egal = apres.find('=')?;
        litteral(&apres[egal + 1..])
    }

    /// Les variables qui portent un autre dossier que celui de Vanguard (LOCALAPPDATA de Windows, XDG_DATA_HOME,
    /// dossier d'un autre programme) : leurs `.join("…")` ne sont pas des fichiers d'état. Une nouvelle variable de ce
    /// nom ailleurs fait échouer le test : on décide alors, au lieu de laisser passer.
    const HORS_DU_DOSSIER: &[(&str, &str)] = &[
        ("sauvegarde.rs", "local"),
        ("machine/extensions.rs", "local"),
        ("nettoyer/windows.rs", "local"),
        ("raccourci.rs", "donnees"),
        ("machine/linux/natif.rs", "donnees"),
        ("optimiser/linux.rs", "donnees"),
        ("protection/acces.rs", "donnees"),
        ("protection/distance.rs", "donnees"),
    ];

    /// T12 : chaque nom que le code joint au dossier de données figure dans l'inventaire, par lui-même ou par son
    /// premier dossier. Ce que la lecture voit : `dossier_local().join(…)` (en clair ou par une constante du fichier),
    /// le lieu d'une liste téléchargée, le nom d'un verrou (`prendre_nomme(dossier, "…")`, `Verrou::prendre(…)`), et
    /// `.join("…")` sur une variable `local`, `nouveau` ou `donnees` (le nom que le code donne au dossier de données, en variable ou en
    /// paramètre), sauf celles de `HORS_DU_DOSSIER`. Pas ce qui passe par un autre nom de variable, ni les copies
    /// datées « <nom>.illisible-<date>.json » (rangées sous leur fichier d'origine).
    #[test]
    fn chaque_fichier_d_etat_est_inventorie() {
        let connus: BTreeSet<&str> = INVENTAIRE.iter().map(|f| f.nom).collect();
        let inventorie = |nom: &str| connus.contains(nom) || nom.split('/').next().is_some_and(|d| connus.contains(d));
        let mut manquants = BTreeSet::new();
        let mut vus = 0;
        for (fichier, code) in sources() {
            let mut noms = Vec::new();
            for (i, _) in code.match_indices("dossier_local()") {
                let suite = code[i + "dossier_local()".len()..].trim_start();
                let Some(arg) = suite.strip_prefix(".join(") else {
                    continue;
                };
                let arg = arg.trim_start();
                if let Some(n) = litteral(arg) {
                    noms.push(n.to_string());
                } else {
                    // Une constante : « NOM », « NOM.0 », « crate::sceau::NOM » (déjà dans l'inventaire par sceau).
                    let ident: String = arg
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == ':')
                        .collect();
                    let nom = ident.rsplit("::").next().unwrap_or_default();
                    if ident.contains("sceau::") || !nom.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
                        continue;
                    }
                    if let Some(v) = constante(&code, nom) {
                        noms.push(v.to_string());
                    }
                }
            }
            // Les variables qui nomment le dossier de données, et les verrous nommés.
            let relatif = fichier.replace('\\', "/");
            for var in ["local", "nouveau", "donnees"] {
                if HORS_DU_DOSSIER
                    .iter()
                    .any(|(f, v)| *v == var && relatif.ends_with(&format!("src/{f}")))
                {
                    continue;
                }
                let appel = format!("{var}.join(");
                for (i, _) in code.match_indices(&appel) {
                    let colle = code[..i]
                        .chars()
                        .next_back()
                        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.');
                    if !colle && let Some(n) = litteral(&code[i + appel.len()..]) {
                        noms.push(n.to_string());
                    }
                }
            }
            for (i, appel) in code
                .match_indices("prendre_nomme(")
                .chain(code.match_indices("Verrou::prendre("))
                .chain(code.match_indices("Verrou::prendre_compatible("))
            {
                let args = &code[i + appel.len()..];
                if let Some(virgule) = args.find(',')
                    && let Some(n) = litteral(&args[virgule + 1..])
                {
                    noms.push(n.to_string());
                }
            }
            // Les listes téléchargées : leur lieu est un couple (« ("feodo", "botnets.txt") »).
            for appel in ["abuse_ch::liste(", "abuse_ch::export(", "abuse_ch::export_et_manque("] {
                for (i, _) in code.match_indices(appel) {
                    // Les arguments de l'appel seulement, jusqu'à sa parenthèse fermante.
                    let reste = &code[i + appel.len()..];
                    let mut profondeur = 1;
                    let fin = reste
                        .char_indices()
                        .find(|&(_, c)| {
                            profondeur += match c {
                                '(' => 1,
                                ')' => -1,
                                _ => 0,
                            };
                            profondeur == 0
                        })
                        .map_or(reste.len(), |(k, _)| k);
                    let args = &reste[..fin];
                    if let Some(p) = args.find("(\"")
                        && let Some(n) = litteral(&args[p..])
                    {
                        noms.push(n.to_string());
                    }
                }
            }
            for n in noms {
                vus += 1;
                if !inventorie(&n) {
                    manquants.insert(format!("{n} ({fichier})"));
                }
            }
        }
        assert!(
            vus >= 40,
            "{vus} noms seulement : la lecture des sources ne trouve plus rien"
        );
        assert!(
            manquants.is_empty(),
            "fichiers d'état hors de l'inventaire (modele/inventaire.rs) : {manquants:?}"
        );
    }

    /// Un nom une seule fois ; les scellés sont dans le dossier de données (les sceaux y vivent).
    #[test]
    fn noms_uniques_et_scelles_locaux() {
        let mut vus = BTreeSet::new();
        for f in INVENTAIRE {
            assert!(vus.insert(f.nom), "{} inventorié deux fois", f.nom);
            assert!(!f.module.is_empty() && f.schema >= 1);
            assert!(!f.scelle || f.lieu == Lieu::Local, "{} scellé hors du dossier", f.nom);
        }
        assert_eq!(schema("historique.json"), 2);
        assert_eq!(schema("inconnu"), 1);
        assert!(scelles().any(|n| n == sceau::APPRIS));
        assert!(
            scelles().all(|n| n != "historique.json"),
            "l'historique a sa propre chaîne"
        );
    }

    /// Les fichiers (ou dossiers) d'état du dossier de données qui ne sont pas scellés, chacun avec sa raison : ce
    /// qu'ils contiennent ne coupe aucune défense, ne tait aucune alerte et ne donne aucun accord, ou une autre
    /// protection les couvre. Liste fermée (S2c, preuve du lot S2) : un nouveau fichier d'état non scellé, ou un
    /// fichier de cette liste devenu scellé ou retiré de l'inventaire, fait échouer `chaque_lecture_passe_par_le_sceau`.
    const NON_SCELLES: &[(&str, &str)] = &[
        (
            "autotest/mesures.json",
            "journal des mesures de l'autodiagnostic : ne décide d'aucune alerte",
        ),
        (
            "sceaux.json",
            "les sceaux eux-mêmes : effacés ou abîmés, ils se voient (refaits, COM-ETA-001)",
        ),
        ("sceaux.verrou", "verrou, sans contenu"),
        (
            "historique.json",
            "sa propre chaîne d'empreintes (rompue : alerte) ; jusqu'à 64 Mio, au-delà de ce que lit le sceau ; tendance \
             et « nouveau depuis » seulement, aucune défense",
        ),
        (
            "evenements",
            "journal des événements en ajout seul, chaîné, sa tête scellée (evenements.tete)",
        ),
        ("evenements.verrou", "verrou, sans contenu"),
        ("evenements.lock", "verrou, sans contenu"),
        (
            "examens",
            "copies datées des examens montrées au rapport ; le dernier résultat de chaque outil est scellé",
        ),
        (
            "passage-restes",
            "restes d'une version d'avant, montrés à la désinstallation qui demande avant d'effacer",
        ),
        (
            "reprise-version-d-avant",
            "marque de la reprise des données d'une version d'avant, sans contenu qui juge",
        ),
        (
            "bin",
            "la copie installée : son empreinte est scellée à la pose de chaque tâche (programmes-planifies.json)",
        ),
        (
            "versions",
            "copies des listes de versions, chacune scellée avec sa date par socle::cache ; plus-haute-vue et la \
             révocation, scellées sous leur nom",
        ),
        ("raccourci-retrait", "dossier jetable d'un essai seulement"),
        ("verifier-sauvegarde", "dossier jetable d'un essai seulement"),
        ("verifier-sauvegarde-liste", "dossier jetable d'un essai seulement"),
        ("verifier-sauvegarde-tube", "dossier jetable d'un essai seulement"),
        (
            "cle-donnees",
            "clé du carnet chiffré de la clé USB : elle ne sert qu'au carnet de la clé, que cles_connues juge ; dans le \
             dossier de cet ordinateur, aucune enveloppe n'est suivie",
        ),
        ("cle-donnees-enveloppe-retiree", "dossier jetable d'un essai seulement"),
        (
            "jeux.json",
            "note d'une version d'avant, plus réécrite ; ses notes tardives sont refusées",
        ),
        (
            "plugins",
            "sorties des extensions ; leurs réglages et leurs approbations sont scellés (plugins/reglages.json, \
             plugins/approuves.json)",
        ),
        ("tldr", "exemples du guide des commandes : du texte montré"),
        (
            "corrections",
            "scripts et résultats des corrections de Windows : le script est vérifié par son empreinte avant de tourner ; \
             ses « .resultats » sont écrits par le script en administrateur, pas par Vanguard (le même geste n'existe pas)",
        ),
        ("accessibilite", "dossier jetable d'un essai seulement"),
        (
            "loldrivers",
            "copie de la liste des pilotes vulnérables, scellée avec sa date par socle::cache",
        ),
        (
            "veilleur-voulu",
            "indice seulement : ce qui décide qu'une défense est coupée normalement est defenses-voulues.json (scellé) ; \
             posée, elle fait seulement croire le veilleur voulu (plus d'alertes)",
        ),
        ("veilleur-oublier-le-choix", "dossier jetable d'un essai seulement"),
        (
            "rancongiciel-voulu",
            "indice pour le bilan : la veille ne s'allume que par defenses-voulues.json (scellé) ; celle d'une version \
             d'avant n'est reprise qu'à la mise à jour",
        ),
        (
            "blocage",
            "copies des fichiers bloqués, pour défaire : le relevé qui les rejoue (changements.jsonl) est scellé",
        ),
        (
            "quarantaine",
            "fichiers isolés et leur registre : « Remettre » montre l'origine et demande, sans jamais écraser ; aucune \
             défense n'en dépend",
        ),
        (
            "sites-bloques",
            "fichier hosts préparé : son empreinte est vérifiée par le processus élevé avant l'écriture",
        ),
        (
            "manifestes-cle",
            "les références des clés : chaque fichier y est scellé sous son nom (sceau::TARDIFS_DOSSIERS)",
        ),
        (
            "empreintes",
            "copies des listes d'empreintes, chacune scellée avec sa date par socle::cache",
        ),
        (
            "malwarebazaar",
            "copies de MalwareBazaar, chacune scellée avec sa date par socle::cache",
        ),
        (
            "echap",
            "copie de la liste d'Échap, scellée avec sa date par socle::cache",
        ),
        ("kev", "copie du catalogue KEV, scellée avec sa date par socle::cache"),
        (
            "feodo",
            "copie de la liste des botnets, scellée avec sa date par socle::cache",
        ),
        (
            "threatfox",
            "copies de ThreatFox, scellées avec leur date par socle::cache ; la clé d'abuse.ch, vérifiée par sa forme",
        ),
        ("urlhaus", "copies d'URLhaus, scellées avec leur date par socle::cache"),
        (
            "signalements",
            "brouillons de signalement : rien ne part (aucun code réseau)",
        ),
        (
            "appareils.json.vanguard",
            "carnet chiffré : seul celui de la clé se lit ; trouvé dans le dossier de cet ordinateur, il est ignoré et \
             dit",
        ),
        ("appareils.verrou", "verrou, sans contenu"),
        ("appareils.lock", "verrou, sans contenu"),
        ("alertes.verrou", "verrou, sans contenu"),
        (
            "connexion.json",
            "habitudes du test de débit : un chiffre montré, aucune défense",
        ),
        (
            "surveillance-voulue",
            "indice seulement, comme veilleur-voulu (defenses-voulues.json décide)",
        ),
        ("horodatage", "dossier jetable d'un essai seulement"),
        ("retrait-constate", "dossier jetable d'un essai seulement"),
        ("unites-relues", "dossier jetable d'un essai seulement"),
        (
            "surveillance-alertes.jsonl",
            "ancien journal des alertes, plus écrit par Vanguard (une version d'avant lancée de la clé y écrit) : lu \
             pour le tableau seulement ; les alertes vont au journal des événements, à tête scellée",
        ),
        (
            "surveillance-reseau-non-verifie.txt",
            "note montrée au tableau : un scan du réseau qui n'a pas pu se faire ; rien ne s'y coupe",
        ),
        (
            "tableau.html",
            "la page du tableau, écrite pour être lue par la personne",
        ),
        ("tableau-journal", "dossier jetable d'un essai seulement"),
        ("tableau-reseau", "dossier jetable d'un essai seulement"),
        (
            "chronologie",
            "traces relevées après un incident : copiées, jamais jugées",
        ),
        (
            "chronologie-journal",
            "traces relevées après un incident : copiées, jamais jugées",
        ),
        (
            "chronologie-raisons",
            "traces relevées après un incident : copiées, jamais jugées",
        ),
        ("feuille", "traces relevées après un incident : copiées, jamais jugées"),
        (
            "feuille-dates",
            "traces relevées après un incident : copiées, jamais jugées",
        ),
        (
            "fin-journal",
            "traces relevées après un incident : copiées, jamais jugées",
        ),
        (
            "journal-cible",
            "traces relevées après un incident : copiées, jamais jugées",
        ),
        (
            "journal-tourne",
            "traces relevées après un incident : copiées, jamais jugées",
        ),
        (
            "processus",
            "traces relevées après un incident : copiées, jamais jugées",
        ),
        (
            "journal-erreurs.txt",
            "journal des erreurs anonymisé : écrit, jamais relu pour juger",
        ),
        ("traces", "traces relevées après un incident : copiées, jamais jugées"),
    ];

    /// Chaque endroit du code (hors `sceau.rs`, cet inventaire et les essais) où paraît le nom d'un fichier scellé
    /// ailleurs qu'en argument d'une fonction de `sceau` : (fichier source, nom, nombre d'endroits, raison). Liste
    /// fermée, au compte près : un endroit de plus (une nouvelle lecture sans le sceau, un chemin construit) ou de moins
    /// fait échouer `chaque_lecture_passe_par_le_sceau`.
    const HORS_DU_SCEAU: &[(&str, &str, usize, &str)] = &[
        (
            "apprentissage.rs",
            "appris.json",
            1,
            "chemin montré dans les messages ; la liste se lit par sceau::juge",
        ),
        (
            "autotest/mod.rs",
            "surveillance-passe.txt",
            1,
            "date du fichier seulement, qui rend au plus la preuve « non concluante » ; le contenu se lit par le sceau",
        ),
        (
            "changements.rs",
            "changements.jsonl",
            2,
            "chemin passé aux lecteurs du relevé, qui en tirent dossier et nom pour le sceau",
        ),
        (
            "chiffrement.rs",
            "appareils.json",
            8,
            "le carnet de la clé USB (racine/donnees) seulement, chiffré par la phrase et jugé par cles_connues : celui de cet ordinateur se lit toujours sous son sceau (reseau, lire_local)",
        ),
        (
            "desinstaller.rs",
            "changements.jsonl",
            2,
            "relevé copié tel quel pour la personne avant l'effacement du dossier, et nommé dans le message : rien n'y est jugé",
        ),
        (
            "desinstaller.rs",
            "defenses-voulues.json",
            1,
            "gardé pour une défense gardée : chemin comparé, jamais lu",
        ),
        (
            "desinstaller.rs",
            "pieges.json",
            1,
            "gardé pour des pièges gardés : chemin comparé, jamais lu",
        ),
        (
            "desinstaller.rs",
            "programmes-planifies.json",
            1,
            "gardé pour une défense gardée : chemin comparé, jamais lu",
        ),
        (
            "desinstaller.rs",
            "sauvegarde.json",
            2,
            "gardé pour une sauvegarde gardée : chemin comparé, jamais lu",
        ),
        (
            "desinstaller.rs",
            "veilleur-etat.json",
            1,
            "gardé pour un veilleur gardé : chemin comparé, jamais lu",
        ),
        (
            "machine/linux/veilleur.rs",
            "defenses-voulues.json",
            1,
            "nommé dans un message",
        ),
        (
            "machine/linux/veilleur.rs",
            "veilleur-etat.json",
            1,
            "le numéro du veilleur d'avant une mise à jour, qui l'écrit sans sceau : rien n'est cru de ses compteurs, le processus est revérifié par son image",
        ),
        (
            "modele/journal.rs",
            "evenements.tete",
            2,
            "plafond des lectures qui ne jugent pas la tête (traces en administrateur, elles ne disent rien d'intact), et la liste des fichiers du journal que les traces recopient",
        ),
        (
            "optimiser/mod.rs",
            "reglages.json",
            1,
            "mis de côté (renommé) quand il ne se lit pas ou a été changé : jamais lu pour juger",
        ),
        (
            "parametres.rs",
            "parametres.json",
            3,
            "chemin passé à charger_juge, qui en tire dossier et nom pour le sceau",
        ),
        (
            "passage.rs",
            "appareils.json",
            1,
            "présence seulement : les fichiers qui disent les données d'une version d'avant",
        ),
        (
            "passage.rs",
            "parametres.json",
            1,
            "présence seulement : les fichiers qui disent les données d'une version d'avant",
        ),
        (
            "passage.rs",
            "reglages.json",
            1,
            "présence seulement : les fichiers qui disent les données d'une version d'avant",
        ),
        (
            "plugins/mod.rs",
            "reglages.json",
            1,
            "celui des extensions, que lire_scelle relit par le sceau sous plugins/reglages.json",
        ),
        (
            "plugins/reglages.rs",
            "reglages.json",
            3,
            "celui des extensions : relu et écrit par le sceau sous plugins/reglages.json, ou mis de côté (renommé)",
        ),
        (
            "protection/blocage/mod.rs",
            "blocage.json",
            1,
            "mis de côté quand il ne se lit pas : jamais lu pour juger",
        ),
        (
            "protection/blocage/parametres.rs",
            "blocage.json",
            3,
            "chemin passé au lecteur, qui en tire dossier et nom pour le sceau",
        ),
        (
            "protection/cles_connues.rs",
            "appareils.json",
            1,
            "l'empreinte du carnet de la clé USB, sa référence (pas celui de cet ordinateur)",
        ),
        (
            "protection/cles_connues.rs",
            "cles-connues.json",
            1,
            "mis de côté quand il a été changé : le contenu se lit par le sceau",
        ),
        (
            "protection/manifeste.rs",
            "manifeste-cle.json",
            3,
            "l'ancienne référence : sa présence (sans la lire) et son chemin, que le lecteur relit par le sceau",
        ),
        (
            "protection/pieges.rs",
            "pieges.json",
            1,
            "chemin montré dans les messages ; la liste se lit par sceau::juge",
        ),
        (
            "protection/sortantes.rs",
            "surveillance-botnets.txt",
            1,
            "date du fichier seulement, pour le tableau ; le contenu se lit par le sceau",
        ),
        (
            "protection/temps_reel.rs",
            "temps-reel.json",
            2,
            "chemin passé au lecteur, qui en tire dossier et nom pour le sceau",
        ),
        (
            "reseau/mod.rs",
            "appareils.json",
            8,
            "le carnet de la clé USB (jugé par cles_connues) ; celui de cet ordinateur, par le sceau, ou mis de côté avant d'être réécrit ; la lecture qui retire ses noms du journal des erreurs, qui ne décide de rien ; et un message",
        ),
        (
            "reseau/surveillance.rs",
            "defenses-voulues.json",
            1,
            "nommé dans un message",
        ),
        (
            "reseau/tableau.rs",
            "surveillance-machine.json",
            1,
            "date du fichier seulement, quand la passe n'a jamais été notée (passes d'avant le tableau)",
        ),
        (
            "traces/vanguard.rs",
            "changements.jsonl",
            1,
            "traces après incident : relevé recopié et relu pour lister les gestes, rien n'y est jugé ni rejoué",
        ),
        (
            "voulues.rs",
            "defenses-voulues.json",
            1,
            "présence seulement : rien encore de noté, c'est une mise à jour d'une version d'avant",
        ),
    ];

    /// Le code sans ses commentaires (remplacés par des espaces, les positions gardées), et ses littéraux de texte
    /// (position, valeur), le contenu des littéraux blanchi dans le code rendu.
    #[allow(clippy::many_single_char_names)] // un lexeur : i, j, c, n, o se lisent mieux courts
    fn lexer(code: &str) -> (String, Vec<(usize, String)>) {
        let o: Vec<char> = code.chars().collect();
        let mut sortie: Vec<char> = Vec::with_capacity(o.len());
        let mut litteraux = Vec::new();
        let mut i = 0;
        while i < o.len() {
            let c = o[i];
            let suivant = o.get(i + 1).copied();
            if c == '/' && suivant == Some('/') {
                while i < o.len() && o[i] != '\n' {
                    sortie.push(' ');
                    i += 1;
                }
            } else if c == '/' && suivant == Some('*') {
                while i < o.len() && !(o[i] == '*' && o.get(i + 1) == Some(&'/')) {
                    sortie.push(if o[i] == '\n' { '\n' } else { ' ' });
                    i += 1;
                }
                sortie.extend([' ', ' ']);
                i += 2;
            } else if c == 'r'
                && (suivant == Some('"') || suivant == Some('#'))
                && !i.checked_sub(1).is_some_and(|k| o[k].is_alphanumeric() || o[k] == '_')
            {
                // Texte brut : r"…", r#"…"#.
                let mut j = i + 1;
                let mut dieses = 0;
                while o.get(j) == Some(&'#') {
                    dieses += 1;
                    j += 1;
                }
                if o.get(j) != Some(&'"') {
                    sortie.push(c);
                    i += 1;
                    continue;
                }
                let debut = sortie.len();
                let fin: String = std::iter::once('"').chain(std::iter::repeat_n('#', dieses)).collect();
                let reste: String = o[j + 1..].iter().collect();
                let n = reste
                    .find(&fin)
                    .map_or(reste.chars().count(), |k| reste[..k].chars().count());
                let valeur: String = o[j + 1..j + 1 + n].iter().collect();
                litteraux.push((debut, valeur));
                let total = (j + 1 + n + fin.chars().count()).min(o.len()) - i;
                sortie.extend(o[i..i + total].iter().map(|&c| if c == '\n' { '\n' } else { ' ' }));
                i += total;
            } else if c == '"' {
                let debut = sortie.len();
                let mut valeur = String::new();
                let mut j = i + 1;
                while j < o.len() && o[j] != '"' {
                    if o[j] == '\\' {
                        valeur.push(o[j]);
                        j += 1;
                    }
                    if j < o.len() {
                        valeur.push(o[j]);
                    }
                    j += 1;
                }
                litteraux.push((debut, valeur));
                let total = (j + 1).min(o.len()) - i;
                sortie.extend(o[i..i + total].iter().map(|&c| if c == '\n' { '\n' } else { ' ' }));
                i += total;
            } else if c == '\'' {
                // Un caractère ('"', '\'', '\n') ou une durée de vie ('a) : seul le premier se saute.
                let fin = if suivant == Some('\\') {
                    (i + 2..(i + 12).min(o.len())).find(|&k| o[k] == '\'')
                } else {
                    (o.get(i + 2) == Some(&'\'')).then_some(i + 2)
                };
                if let Some(f) = fin {
                    sortie.extend(std::iter::repeat_n(' ', f + 1 - i));
                    i = f + 1;
                } else {
                    sortie.push(c);
                    i += 1;
                }
            } else {
                sortie.push(c);
                i += 1;
            }
        }
        (sortie.into_iter().collect(), litteraux)
    }

    /// Les instructions `use` d'un code, sans espaces (« crate::sceau::{APPRIS,BOTNETS} »).
    fn imports(code: &str) -> Vec<String> {
        code.match_indices("use ")
            .filter(|(i, _)| *i == 0 || code[..*i].ends_with(['\n', ' ', '{', ';']))
            .filter_map(|(i, _)| {
                let reste = &code[i + 4..];
                Some(
                    reste[..reste.find(';')?]
                        .chars()
                        .filter(|c| !c.is_whitespace())
                        .collect(),
                )
            })
            .collect()
    }

    /// Le chemin complet d'un nom importé par `use` (« APPRIS » → « crate::sceau::APPRIS »).
    fn importe(code: &str, nom: &str) -> Option<String> {
        imports(code).into_iter().find_map(|u| {
            if let Some((prefixe, liste)) = u.split_once('{') {
                let liste = liste.trim_end_matches('}');
                let module = prefixe.trim_end_matches("::");
                // `use a::b::{self, …}` importe le module b lui-même.
                if module.rsplit("::").next() == Some(nom) && liste.split(',').any(|n| n == "self") {
                    return Some(module.to_string());
                }
                liste.split(',').any(|n| n == nom).then(|| format!("{prefixe}{nom}"))
            } else {
                (u.rsplit("::").next() == Some(nom)).then_some(u)
            }
        })
    }

    /// Le code d'un fichier sans ce qui ne compile que pour les essais : ses modules de tests, et chaque élément
    /// précédé de `#[cfg(test)]` (jusqu'à sa fin : `;` ou son bloc).
    fn sans_essais(code: &str) -> String {
        let mut sortie = String::new();
        let mut reste = code;
        while let Some(i) = reste.find("#[cfg(test)]") {
            sortie.push_str(&reste[..i]);
            let apres = &reste[i..];
            let (bloc, point) = (apres.find('{'), apres.find(';'));
            let fin = match (bloc, point) {
                (Some(b), Some(p)) if p < b => p + 1,
                (Some(b), _) => {
                    let mut profondeur = 0;
                    apres[b..]
                        .char_indices()
                        .find(|&(_, c)| {
                            profondeur += match c {
                                '{' => 1,
                                '}' => -1,
                                _ => 0,
                            };
                            profondeur == 0
                        })
                        .map_or(apres.len(), |(k, _)| b + k + 1)
                }
                (None, Some(p)) => p + 1,
                (None, None) => apres.len(),
            };
            reste = &apres[fin..];
        }
        sortie.push_str(reste);
        sortie
    }

    /// Les sources de src par chemin relatif (« protection/pieges.rs »), sans les commentaires ni les essais ; les
    /// fichiers de tests entiers (« plugins/tests.rs ») n'y sont pas.
    fn sources_sans_essais() -> BTreeMap<String, String> {
        let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        sources()
            .into_iter()
            .filter_map(|(f, code)| {
                let relatif = std::path::Path::new(&f)
                    .strip_prefix(&racine)
                    .ok()?
                    .to_string_lossy()
                    .replace('\\', "/");
                let nom = relatif.rsplit('/').next().unwrap_or_default();
                // Les commentaires retirés d'abord : un `#[cfg(test)]` cité dans un commentaire n'enlève rien.
                let sans_commentaires = lexer_commentaires(&code);
                (nom != "tests.rs" && nom != "essais.rs").then(|| (relatif, sans_essais(&sans_commentaires)))
            })
            .collect()
    }

    /// Le code sans ses commentaires, ses littéraux gardés.
    fn lexer_commentaires(code: &str) -> String {
        let (blanchi, litteraux) = lexer(code);
        let mut sortie: Vec<char> = blanchi.chars().collect();
        for (pos, valeur) in litteraux {
            let texte: Vec<char> = format!("\"{valeur}\"").chars().collect();
            for (k, c) in texte.into_iter().enumerate() {
                if let Some(place) = sortie.get_mut(pos + k) {
                    *place = c;
                }
            }
        }
        sortie.into_iter().collect()
    }

    /// Le fichier d'un module désigné depuis `fichier` (« crate::sauvegarde », « parametres », « super »).
    fn fichier_du_module(fichier: &str, chemin: &[&str], sources: &BTreeMap<String, String>) -> Option<String> {
        let mut dossier: Vec<&str> = fichier.split('/').collect();
        let feuille = dossier.pop().unwrap_or_default();
        // Le dossier des sous-modules du module de `fichier` : le sien pour mod.rs et main.rs, sinon son nom.
        if !matches!(feuille, "mod.rs" | "main.rs") {
            dossier.push(feuille.trim_end_matches(".rs"));
        }
        let mut segments = chemin.iter().copied().peekable();
        if segments.peek() == Some(&"crate") {
            dossier.clear();
            segments.next();
        }
        for seg in segments {
            if seg == "super" {
                dossier.pop();
            } else if seg != "self" {
                dossier.push(seg);
            }
        }
        let base = dossier.join("/");
        [format!("{base}.rs"), format!("{base}/mod.rs")]
            .into_iter()
            .chain((base.is_empty()).then(|| "main.rs".to_string()))
            .find(|f| sources.contains_key(f))
    }

    /// Ce que vaut une constante vue depuis `fichier` (« NOM », « sceau::NOM », « crate::x::NOM », ou un nom importé) :
    /// `Ok(Some(texte))` pour une constante `&str` (un littéral, ou une autre constante qu'elle reprend), `Ok(None)` pour
    /// une constante d'un autre type, `Err` si elle ne se trouve pas.
    fn valeur(
        fichier: &str,
        chemin: &str,
        sources: &BTreeMap<String, String>,
        profondeur: usize,
    ) -> Result<Option<String>, String> {
        if profondeur > 6 {
            return Err(format!("{fichier} : {chemin} (trop de détours)"));
        }
        let segments: Vec<&str> = chemin.split("::").filter(|s| !s.is_empty()).collect();
        let Some((nom, module)) = segments.split_last() else {
            return Err(format!("{fichier} : chemin vide"));
        };
        let ou = if module.is_empty() {
            fichier.to_string()
        } else if module.last() == Some(&"sceau") {
            "sceau.rs".to_string()
        } else {
            // Un module importé par `use` (« use crate::reseau::surveillance; ») : son chemin complet.
            let importe_ici = sources.get(fichier).and_then(|c| importe(c, module[0]));
            let complet: Vec<String> = importe_ici.map_or_else(
                || vec![module[0].to_string()],
                |p| p.split("::").map(str::to_string).collect::<Vec<_>>(),
            );
            let complet: Vec<&str> = complet
                .iter()
                .map(String::as_str)
                .chain(module[1..].iter().copied())
                .collect();
            fichier_du_module(fichier, module, sources)
                .or_else(|| fichier_du_module(fichier, &complet, sources))
                .ok_or_else(|| format!("{fichier} : module de {chemin}"))?
        };
        let code = sources.get(&ou).ok_or_else(|| format!("{ou} introuvable"))?;
        let definition = [format!("const {nom}: "), format!("static {nom}: ")]
            .iter()
            .find_map(|d| code.find(d.as_str()));
        let Some(debut) = definition else {
            // Importé dans ce fichier (`use …::NOM`), sinon pas une constante d'ici.
            if module.is_empty()
                && let Some(complet) = importe(code, nom)
                && complet != chemin
            {
                return valeur(&ou, &complet, sources, profondeur + 1);
            }
            return Err(format!("{fichier} : {chemin} introuvable"));
        };
        let (genre, apres) = code[debut..]
            .split_once(':')
            .unwrap_or_default()
            .1
            .split_once('=')
            .unwrap_or_default();
        if genre.trim() != "&str" && genre.trim() != "&'static str" {
            return Ok(None);
        }
        let apres = apres.trim_start();
        if let Some(dedans) = apres.strip_prefix('"') {
            return Ok(Some(dedans[..dedans.find('"').unwrap_or(0)].to_string()));
        }
        let autre: String = apres
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == ':')
            .collect();
        // Calculée (`if cfg!(…)`, un appel) : pas un nom de fichier d'état qui se suive ici.
        if !autre
            .rsplit("::")
            .next()
            .unwrap_or_default()
            .chars()
            .all(|c| c.is_ascii_uppercase() || c == '_')
        {
            return Ok(None);
        }
        valeur(&ou, &autre, sources, profondeur + 1)
    }

    /// Le nom de la fonction dont `code[..pos]` est dans les arguments (« crate::sceau::juge_dans »), s'il y en a une.
    fn appel_englobant(code: &str, pos: usize) -> Option<&str> {
        let mut profondeur = 0;
        for (i, c) in code[..pos].char_indices().rev() {
            match c {
                ')' | ']' | '}' => profondeur += 1,
                '(' if profondeur == 0 => {
                    let avant = &code[..i];
                    let debut = avant
                        .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':'))
                        .map_or(0, |k| k + 1);
                    return Some(&avant[debut..]);
                }
                '(' | '[' | '{' if profondeur > 0 => profondeur -= 1,
                '[' | '{' | ';' => return None,
                _ => {}
            }
        }
        None
    }

    /// Le texte de la ligne de `code` jusqu'à `pos`.
    fn debut_de_ligne(code: &str, pos: usize) -> &str {
        let debut = code[..pos].rfind('\n').map_or(0, |k| k + 1);
        &code[debut..pos]
    }

    /// T14 (S2c) : chaque fichier du dossier de données de Vanguard est scellé, sauf ceux de `NON_SCELLES` (avec leur
    /// raison) ; et le nom d'un fichier scellé (un littéral, ou une constante qui le vaut, même importée ou reprise
    /// d'un autre module) ne paraît dans le code qu'en argument d'une fonction de `sceau`, ou dans la définition d'une
    /// constante, sauf aux endroits de `HORS_DU_SCEAU`, comptés. Un nom qui paraît ailleurs, c'est un chemin construit
    /// ou un fichier lu sans le sceau. Ce qu'il ne voit pas : un nom écrit en morceaux (`format!`), ou passé par une
    /// variable d'un fichier à l'autre sans que son nom y paraisse. Une exception qui ne sert plus fait aussi échouer.
    #[test]
    fn chaque_lecture_passe_par_le_sceau() {
        // 1. Les fichiers non scellés : tous dans la liste fermée, et rien d'autre.
        let non_scelles: BTreeSet<&str> = INVENTAIRE
            .iter()
            .filter(|f| !f.scelle && f.lieu != Lieu::Cle)
            .map(|f| f.nom)
            .collect();
        let listes: BTreeSet<&str> = NON_SCELLES.iter().map(|(n, _)| *n).collect();
        let sans_raison: Vec<_> = non_scelles.difference(&listes).collect();
        assert!(
            sans_raison.is_empty(),
            "fichiers d'état ni scellés ni excusés : scellez-les (`scelle(…)` dans INVENTAIRE, src/modele/inventaire.rs) \
             ou ajoutez-les à NON_SCELLES, dans le même fichier, avec la raison : {sans_raison:?}"
        );
        let morts: Vec<_> = listes.difference(&non_scelles).collect();
        assert!(
            morts.is_empty(),
            "NON_SCELLES (src/modele/inventaire.rs) nomme des fichiers scellés ou hors de l'inventaire : {morts:?}"
        );
        assert!(NON_SCELLES.iter().all(|(_, r)| !r.is_empty()));
        // 2. Chaque endroit où paraît un nom scellé hors du sceau.
        let scelles: BTreeSet<&str> = scelles().collect();
        let sources = sources_sans_essais();
        let mut vus: BTreeMap<(String, String), usize> = BTreeMap::new();
        let mut introuvables = Vec::new();
        let permis = |code: &str, pos: usize| {
            let ligne = debut_de_ligne(code, pos).trim_start();
            // Dans la définition d'une constante (même sur plusieurs lignes) : un nom, pas un usage.
            let dans_definition = ["const ", "static "]
                .iter()
                .filter_map(|m| code[..pos].rfind(m))
                .max()
                .is_some_and(|d| {
                    let morceau = &code[d..pos];
                    !morceau.starts_with("const fn")
                        && morceau.find('=').is_none_or(|eq| !morceau[eq..].contains([';', '{']))
                });
            ligne.starts_with("use ")
                || dans_definition
                || appel_englobant(code, pos).is_some_and(|f| f.split("::").any(|s| s == "sceau"))
        };
        for (fichier, code) in &sources {
            if fichier == "sceau.rs" || fichier == "modele/inventaire.rs" {
                continue;
            }
            let (blanchi, litteraux) = lexer(code);
            for (pos, texte) in &litteraux {
                if scelles.contains(texte.as_str()) && !permis(&blanchi, *pos) {
                    *vus.entry((fichier.clone(), texte.clone())).or_default() += 1;
                }
            }
            // Les constantes en majuscules (« NOM », « crate::sceau::NOM »), chacune résolue.
            let octets = blanchi.as_bytes();
            let mut i = 0;
            while i < octets.len() {
                let c = octets[i] as char;
                let colle = i > 0 && {
                    let p = octets[i - 1] as char;
                    p.is_ascii_alphanumeric() || p == '_' || p == ':'
                };
                if !(c.is_ascii_alphabetic() || c == '_') || colle {
                    i += 1;
                    continue;
                }
                let fin = blanchi[i..]
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':'))
                    .map_or(blanchi.len(), |k| i + k);
                let chemin = blanchi[i..fin].trim_end_matches(':');
                let dernier = chemin.rsplit("::").next().unwrap_or_default();
                let majuscules = dernier.len() > 1
                    && dernier
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                    && dernier.chars().any(|c| c.is_ascii_uppercase());
                if majuscules && !permis(&blanchi, i) {
                    match valeur(fichier, chemin, &sources, 0) {
                        Ok(Some(v)) if scelles.contains(v.as_str()) => {
                            *vus.entry((fichier.clone(), v)).or_default() += 1;
                        }
                        // Une constante qui ne se trouve pas, en argument d'un `.join` : on ne sait pas ce qu'il joint.
                        Err(e) if blanchi[..i].trim_end().ends_with(".join(") => introuvables.push(e),
                        Ok(_) | Err(_) => {}
                    }
                }
                i = fin.max(i + 1);
            }
        }
        assert!(
            introuvables.is_empty(),
            "constantes jointes à un chemin que le test ne sait pas résoudre : {introuvables:?}"
        );
        assert!(
            vus.len() >= 10,
            "{} endroits seulement : la lecture des sources ne trouve plus rien",
            vus.len()
        );
        let attendus: BTreeMap<(String, String), usize> = HORS_DU_SCEAU
            .iter()
            .map(|(f, n, k, _)| (((*f).to_string(), (*n).to_string()), *k))
            .collect();
        let hors: Vec<_> = vus.iter().filter(|(k, n)| attendus.get(*k) != Some(n)).collect();
        assert!(
            hors.is_empty(),
            "noms de fichiers scellés hors du sceau, (fichier, nom) → nombre d'endroits : lisez-les par sceau::lire ou \
             sceau::juge, ou mettez à jour HORS_DU_SCEAU (src/modele/inventaire.rs) avec la raison : {hors:?}"
        );
        let morts: Vec<_> = attendus.keys().filter(|k| !vus.contains_key(*k)).collect();
        assert!(
            morts.is_empty(),
            "HORS_DU_SCEAU nomme des endroits que le code n'a plus : {morts:?}"
        );
        assert!(HORS_DU_SCEAU.iter().all(|(_, _, _, r)| !r.is_empty()));
    }
}

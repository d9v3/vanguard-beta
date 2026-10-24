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
    local("changements.jsonl", "changements"),
    local(crate::modele::journal::DOSSIER, "modele::journal"),
    local("evenements.verrou", "modele::journal"),
    local(crate::modele::resultat::EXAMENS, "modele::resultat"),
    local("parametres.json", "parametres"),
    local("passage-restes", "passage"),
    local("reprise-version-d-avant", "passage"),
    local("bin", "mise_a_jour"),
    local("versions", "mise_a_jour::github, protection::perimes"),
    local("raccourci-retrait", "raccourci"),
    local("entretien.json", "entretien"),
    local("sauvegarde.json", "sauvegarde"),
    local("verifier-sauvegarde", "sauvegarde"),
    local("verifier-sauvegarde-liste", "sauvegarde"),
    local("verifier-sauvegarde-tube", "sauvegarde"),
    local("cle-donnees", "chiffrement"),
    local("cle-donnees-enveloppe-retiree", "reseau"),
    local("jeux.json", "gaming::annulation"),
    local("plugins", "plugins::sortie"),
    local("tldr", "guide::tldr"),
    // Machine.
    local("administrateurs.json", "machine::administrateurs"),
    local("bluetooth.json", "machine::bluetooth"),
    local("ports-bloques.txt", "machine"),
    local("corrections", "machine::windows"),
    local("accessibilite", "machine::windows::portes"),
    local("loldrivers", "machine::windows::pilotes"),
    local("veilleur-etat.json", "machine::linux::veilleur"),
    local("veilleur-voulu", "machine::linux::veilleur"),
    local("veilleur-oublier-le-choix", "machine::linux::veilleur"),
    local("rancongiciel-voulu", "machine::linux::veilleur"),
    // Réglages du veilleur anti-rançongiciel (dossiers en plus, exclusions), scellés ; écrit par le palier 1 Linux.
    scelle("rancongiciel-reglages.json", "protection::rancongiciel"),
    // Protection.
    local("blocage.json", "protection::blocage"),
    local("blocage", "protection::blocage::gestes"),
    local("quarantaine", "protection::quarantaine"),
    local("pieges.json", "protection::pieges"),
    local("sites-bloques", "protection::sites_bloques"),
    local("cles-connues.json", "protection::cles_connues"),
    local("manifestes-cle", "protection::manifeste"),
    local("manifeste-cle.json", "protection::manifeste"),
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
    local("appareils.json", "reseau"),
    local("appareils.json.vanguard", "chiffrement"),
    local("appareils.verrou", "reseau"),
    local("alertes.verrou", "reseau::tableau"),
    local("connexion.json", "reseau::connexion"),
    local("surveillance-voulue", "reseau::surveillance"),
    local("horodatage", "reseau::surveillance"),
    local("retrait-constate", "reseau::surveillance"),
    local("unites-relues", "reseau::surveillance"),
    local("surveillance-alertes.jsonl", "reseau::tableau"),
    local("surveillance-passe.txt", "reseau::tableau"),
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
    use std::collections::BTreeSet;

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
    /// le lieu d'une liste téléchargée, le nom d'un verrou (`prendre_nomme(dossier, "…")`), et `.join("…")` sur une
    /// variable `local`, `nouveau` ou `donnees` (le nom que le code donne au dossier de données, en variable ou en
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
            for (i, _) in code.match_indices("prendre_nomme(") {
                let args = &code[i + "prendre_nomme(".len()..];
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
}

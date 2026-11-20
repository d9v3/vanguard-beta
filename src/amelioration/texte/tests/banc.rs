//! Banc de non-régression du masqueur : chaque entrée trouvée par les relecteurs (rondes 6 et 7, constats confirmés
//! et fermetures), rejouée avec sa sortie exacte. Deux familles : rien de personnel en clair, et rien de masqué en
//! trop sur un texte légitime. Un cas encore ouvert porte `#[ignore]` avec le numéro de son constat ; on retire la
//! marque dès que le cas est corrigé. Toutes les valeurs sont inventées.

use super::masquer_chez;

/// Un essai par cas : `nom: [maisons], entrée => sortie attendue;`.
macro_rules! banc {
    ($($(#[$m:meta])* $nom:ident : [$($maison:expr),*], $brut:expr => $attendu:expr;)*) => {
        $(
            $(#[$m])*
            #[test]
            fn $nom() {
                let brut: &str = $brut;
                assert_eq!(masquer_chez(brut, &[$($maison),*]), $attendu, "entrée : {brut:?}");
            }
        )*
    };
}

/// Cas sans rien de personnel : la sortie est l'entrée.
macro_rules! garde {
    ($($(#[$m:meta])* $nom:ident : $brut:expr;)*) => {
        $(
            $(#[$m])*
            #[test]
            fn $nom() {
                let brut: &str = $brut;
                assert_eq!(masquer_chez(brut, &[]), brut);
            }
        )*
    };
}

// Ronde 6 : chemins.
banc! {
    r6_chemins_0: [r"C:\Users\alice"],
        r"copie de \\?\C:\Users\alice\Documents\Impôts\Avis Luc Tremblay.pdf refusée" => "copie de <chemin .pdf>";
    r6_chemins_1: [], r"copie vers \\?\UNC\nas-martin\Sauvegardes\luc.tremblay\photos refusée"
        => "copie vers <chemin> refusée";
    r6_chemins_2: [], r#""\\\\nas\\partage\\Zoé Martin\\Lettre Roy.pdf""# => r#""<chemin .pdf>""#;
    r6_chemins_3: [], "Lecture de C://Users/bob/Lettre Roy.pdf refusée" => "Lecture de <chemin .pdf>";
    r6_chemins_4a: ["/home/alice"], "lecture de /mnt/sauvegarde/home/alice/Lettre Zoé Martin impossible"
        => "lecture de <chemin>";
    r6_chemins_4b: ["/home/alice"], "cc -I/home/alice/projets/client-tremblay/include x.c" => "cc -I<chemin>";
    #[ignore = "limite r6 chemins#5 (compte@hôte:)"]
    r6_chemins_5a: [], "scp bob@nas:/home/bob/Lettre Zoé Martin.pdf /tmp" => "scp <adresse>:<chemin .pdf>";
    r6_chemins_6: [], r#"mount -t cifs "//nas.local/Photos de Zoé Martin" /mnt/photos"#
        => r#"mount -t cifs "<chemin>" <chemin>"#;
    #[ignore = "limite r6 chemins#5 (compte@hôte:)"]
    r6_chemins_5b: [], "lecture de /home/bob/zoe.martin@exemple.test/Lettre Zoé Martin" => "lecture de <chemin>";
    #[ignore = "limite r6 chemins#7 (chemin derrière « < »)"]
    r6_chemins_7: [], "sort </home/bob/Documents/Impôts Zoé Martin.pdf>" => "sort <<chemin .pdf>";
    r6_chemins_9a: [], r"Get-Content $HOME\Lettre Zoé Martin.txt" => "Get-Content <chemin .txt>";
    r6_chemins_9b: [], "lecture de ~bob/Lettre Zoé Martin.pdf" => "lecture de <chemin .pdf>";
    r6_chemins_9c: [], "ouverture de file:/home/bob/Lettre Zoé Martin" => "ouverture de <url><chemin>";
    #[ignore = "limite r6 chemins#10 (maison suivie d'une espace)"]
    r6_chemins_10: [r"C:\Users\Zoé"], r"copie de C:\Users\Zoé d'alice\Lettre Roy refusée" => "copie de <chemin>";
}

// Ronde 6 : adresses, bornes et régressions.
banc! {
    r6_adresses_0: ["/home/alice"], "xdg-open file:/home/alice/Lettre de Zoé Martin Tremblay.pdf"
        => "xdg-open <url><chemin .pdf>";
    r6_adresses_1: [], "C://Users/bob/Lettre Roy.pdf" => "<chemin .pdf>";
    r6_adresses_2: [], r#"{"url":"https://a.test/x?id=5","status":403,"error":"forbidden"}"#
        => r#"{"url":"<url>","status":403,"error":"forbidden"}"#;
    r6_adresses_3: [], "Could not reach 192.0.2.7? Check the network: timeout after 30 s"
        => "Could not reach <ip>? Check the network: timeout after 30 s";
    r6_adresses_4: [], r#"{"msg":"Voulez-vous le recréer?\n/home/alice/Documents/Impôts Zoé Martin.pdf"}"#
        => r#"{"msg":"Voulez-vous le recréer?\n<chemin .pdf>"#;
    r6_bornes_0: ["/home/bob"], "Erreur : file:/home/bob/Lettre Zoé Martin.pdf introuvable"
        => "Erreur : <url><chemin .pdf>";
    r6_bornes_1a: ["/home/bob"], r#"{"error":"open failed\n/home/bob/Lettre Zoé Martin.pdf"}"#
        => r#"{"error":"open <chemin .pdf>"#;
    r6_bornes_1b: ["/home/bob"], r#"{"error":"open failed\n/home/bob/Lettre Zoé Martin"}"#
        => r#"{"error":"open failed\n<chemin>"#;
    r6_bornes_5a: [], "'/home/bob/Lettre Zoé Martin' n'existe pas" => "'<chemin>' n'existe pas";
    r6_bornes_5b: [], r#""/home/bob/Lettre Zoé.pdf" lu, puis \"fin\" x"# => r#""<chemin .pdf>" lu, puis \"fin\" x"#;
    r6_bornes_5c: [], "'/home/bob/Documents/Classe de 2019's photos Zoé Martin' fin" => "'<chemin>' fin";
    r6_bornes_5d: [], r#""C:\\Users\\bob\\Écran 27\" Zoé Martin.pdf" fin"# => r#""<chemin .pdf>" fin"#;
    r6_regressions_0: [], r#"mount "//nas.local/partage/Zoé Martin/Lettres" impossible"#
        => r#"mount "<chemin>" impossible"#;
    r5_json: [], r#"{"url":"https://a.test/x","detail":"introuvable","code":5}"#
        => r#"{"url":"<url>","detail":"introuvable","code":5}"#;
    // Le nom de fichier nu part (il peut nommer quelqu'un) ; l'expression de sed reste.
    r6_regressions_6a: [], r"sed 's/\//-/g' liste.txt" => r"sed 's/\//-/g' <chemin .txt>";
    r6_regressions_4: [], r##"{"url":"https://a.test/x","couleur":"#ff0000","detail":"introuvable","code":5}"##
        => r##"{"url":"<url>","couleur":"#ff0000","detail":"introuvable","code":5}"##;
    r6_regressions_5: [], "La passerelle est-elle 192.168.1.1? Oui, vérifié, mais le service ne répond pas"
        => "La passerelle est-elle <ip>? Oui, vérifié, mais le service ne répond pas";
}

// Ronde 7 : fermetures (variantes rejouées par le relecteur).
banc! {
    r7_ferme_nt_lecteur: [], r"copie de \??\C:\Users\alice\Documents\Avis.pdf refusée"
        => "copie de <chemin .pdf>";
    r7_ferme_barres_lecteur: [], r"copie de //?/C:/Users/alice/Documents/Avis.pdf refusée"
        => "copie de <chemin .pdf>";
    r7_ferme_point_lecteur: [], r"copie de \\.\C:\Users\alice\Documents\Avis.pdf refusée"
        => "copie de <chemin .pdf>";
    r7_ferme_unc_minuscule: [], r"copie vers \\?\unc\nas-martin\Sauvegardes\luc.tremblay\photos refusée"
        => "copie vers <chemin> refusée";
    r7_ferme_unc_point: [], r"copie vers \\.\UNC\nas-martin\Sauvegardes\luc.tremblay\photos refusée"
        => "copie vers <chemin> refusée";
    r7_ferme_tilde_option: ["/home/alice"], "cc -I~/projets/client-tremblay/include x.c" => "cc -I<chemin>";
    r7_ferme_option_l: ["/home/alice"], "ld -L/home/alice/projets/client-tremblay/lib x.o" => "ld -L<chemin>";
    r7_ferme_crlf: [], r#"{"msg":"Voulez-vous le recréer?\r\n/home/alice/Documents/Impôts Zoé Martin.pdf"}"#
        => r#"{"msg":"Voulez-vous le recréer?\r<chemin .pdf>"#;
    r7_ferme_tab: [], r#"{"msg":"Voulez-vous le recréer?\n\t/home/alice/Documents/Impôts Zoé Martin.pdf"}"#
        => r#"{"msg":"Voulez-vous le recréer?\n<chemin .pdf>"#;
}

// Ronde 7 : constats confirmés.
banc! {
    r7_fuites_0a: ["/home/bob"], r#"{"msg":"open failed: \/home\/bob\/Lettre Zoé Martin.pdf"}"#
        => r#"{"msg":"open failed: <chemin .pdf>"#;
    r7_fuites_0b: ["/home/bob"],
        r#"{"status":"error","date":"2026/11/20","path":"\/home\/bob\/Documents\/Lettre-Zoe-Martin.pdf"}"#
        => r#"{"status":"error","date":"2026/11/20","path":"<chemin .pdf>"}"#;
    r7_fuites_0c: [], r#"{"message":"Impossible de lire \/home\/alice\/x: refusé"}"#
        => r#"{"message":"Impossible de lire <chemin>"#;
    r7_fuites_0d: [], r"PHP Warning: fopen(\/home\/bob\/Lettre.pdf): failed to open stream"
        => "PHP Warning: fopen(<chemin .pdf>";
    r7_fuites_0e: [], r"ouverture de file:\/home\/bob\/Lettre Zoé Martin.pdf refusée"
        => "ouverture de <url><chemin .pdf>";
    r7_fuites_1a: [], r#"{"url":"https://a.test/x?filter={\"nom\":\"zoe.martin\"}&lecteur=luc.roy"}"#
        => r#"{"url":"<url>"}"#;
    r7_fuites_1b: [],
        r#"curl "https://api.test/items?where={"owner":"zoe.martin"}&key=abcdef0123456789abcdef0123456789" a échoué"#
        => r#"curl "<url>"}&key=<secret> a échoué"#;
    r7_fuites_1c: [], "lien 'https://a.test/x?nom=d'Alice':'Zoé'&lecteur=zoe.martin' refusé" => "lien '<url>' refusé";
    r7_fuites_1d: [], r#"lien "https://a.test/x#frag":suite-zoe.martin" refusé"# => r#"lien "<url>" refusé"#;
    r7_fuites_2a: [], r#"copie vers "\\\\?\\UNC\\nas-martin\\Sauvegardes\\luc.tremblay\\photos" refusée"#
        => r#"copie vers "<chemin>" refusée"#;
    r7_fuites_2b: [], r#"Os { code: 5, kind: PermissionDenied }: "\\\\?\\UNC\\nas\\Sauvegardes\\zoe.martin\\lettre.txt""#
        => r#"Os { code: 5, kind: PermissionDenied }: "<chemin .txt>""#;
    r7_fuites_2c: [], r#""\\\\?\\UNC\\nas-martin\\Sauvegardes\\Zoé Martin\\photos de Luc""# => r#""<chemin>""#;
    r7_fuites_3a: [], r"copie vers \??\UNC\nas-martin\Sauvegardes\luc.tremblay\photos refusée"
        => "copie vers <chemin> refusée";
    r7_fuites_3b: [], r"copie vers \\?\UNC/nas-martin/Sauvegardes/luc.tremblay/photos refusée"
        => "copie vers <chemin> refusée";
    r7_fuites_3c: [], "//?/UNC/nas-martin/Sauvegardes/Zoé Martin/photos" => "<chemin>";
    r7_fuites_4a: [], r#"{"file":"Documents\\Zoé Martin\\Lettre Roy.pdf"}"# => r#"{"file":"<chemin>"}"#;
    r7_fuites_4b: [], r#"erreur: "..\\zoe.martin\\lettre.txt": introuvable"# => r#"erreur: "<chemin .txt>": introuvable"#;
    r7_fuites_4c: [], r#"erreur: "sauvegardes\\zoe.martin\\lettre.txt": introuvable"#
        => r#"erreur: "<chemin .txt>": introuvable"#;
    r7_fuites_4d: [], r#"path: "\\\\\\\\nas\\\\partage\\\\Zoé Martin\\\\Lettre Roy.pdf""# => r#"path: "<chemin .pdf>""#;
    r7_fuites_5a: [], r#"{"error":"ligne 1\nDocuments/Zoé Martin/Lettre Roy.pdf introuvable"}"#
        => r#"{"error":"ligne 1\n<chemin>"#;
    r7_fuites_5b: [], r#"{"error":"ligne 1\n../Zoé Martin/Lettre Roy.pdf"}"# => r#"{"error":"ligne 1\n<chemin> <chemin .pdf>"}"#;
    r7_fuites_6a: [],
        r"copie de \\?\Volume{4c1b02c1-d990-11dc-99ae-806e6f6e6963}\Users\alice\AppData\Local\x.log refusée"
        => "copie de <chemin .log>";
    r7_fuites_6b: [],
        r"copie de \\?\Volume{4c1b02c1-d990-11dc-99ae-806e6f6e6963}\Users\Jean Dupont\Documents\Avis Luc.pdf"
        => "copie de <chemin .pdf>";
    r7_fuites_7a: [], "ouverture de file:C:/Users/Jean Dupont/Lettre Roy.pdf refusée" => "ouverture de <url><chemin .pdf>";
    r7_fuites_7b: [], "ouverture de file:$HOME/Lettre Zoé Martin.pdf refusée" => "ouverture de <url><chemin .pdf>";
    r7_fuites_7c: [], r"ouverture de file:%USERPROFILE%\Lettre Zoé Martin.pdf refusée"
        => "ouverture de <url><chemin .pdf>";
    r8_apostrophe_windows: [], r"lecture de C:\Users\bob\L'été de Zoé Martin.pdf refusée" => "lecture de <chemin .pdf>";
    r8_appel_unix: [], "open(/home/bob/Lettre Roy.pdf) a échoué" => "open(<chemin .pdf>";
    r7_fuites_8a: [], "mount '//nas.local/L'été de Zoé Martin' impossible" => "mount '<chemin>' impossible";
    r7_fuites_9a: [], "lecture de /srv/www/page.php?zoe.martin refusée" => "lecture de <chemin> refusée";
    r7_fuites_9b: [], "lecture de /srv/www/page.php?Zoé%20Martin refusée" => "lecture de <chemin> refusée";
    r7_fuites_10: [], r#"extrait : …"Zoé Martin\Downloads\Facture.exe" bloqué"# => "extrait : <chemin>";
    r7_fuites_12: [], "cc -I$HOME/projets/client-tremblay/include x.c" => "cc -I<chemin>";
    r7_abus_13a: [], r#"{"msg": "Le fichier \/home\/alice\/Documents\/notes.txt est introuvable"}"#
        => r#"{"msg": "Le fichier <chemin .txt>"#;
    r7_abus_13b: [], r#"{"msg": "open \/home\/bob\/Lettre Zoé Martin.pdf failed"}"# => r#"{"msg": "open <chemin .pdf>"#;
    r7_abus_17: [], r"… [Privé] Zoé Martin\outil.exe" => "<chemin>";
    r7_abus_18: [], "lecture de /srv/www/profil?zoe-martin refusée" => "lecture de <chemin> refusée";
    r7_abus_19: [], r#"{"url":"https://a.test/x?noms=[\"zoe\",\"martin\"]&jeton=abc"}"# => r#"{"url":"<url>"}"#;
}

// Sans abus : textes légitimes, gardés mot pour mot (rondes 5 à 7 et essais anti-abus existants).
garde! {
    garde_r6_regressions_3b: "Attente …: échec de usr/bin/outil (code 3)";
    garde_r6_regressions_1a: "voir (…) puis […] et {…} fin";
    garde_r6_regressions_1b: "Chargement… fini";
    garde_r6_regressions_1c: "liste […] dans src/journal.rs:12";
    garde_r6_regressions_1d: "bloc {…} dans src/journal.rs:12";
    garde_r6_regressions_1e: "voir (…) dans src/journal.rs:12";
    garde_r6_regressions_1f: "Chargement… fini dans src/journal.rs:12";
    garde_r6_regressions_3: "il affiche \"…\" puis panique dans src/journal.rs:12";
    garde_r6_regressions_6b: r"règle ^\/api\/v1 refusée";
    garde_r5_coupe_a: "(…) panique dans src/journal.rs:12 : index hors bornes";
    garde_r5_coupe_b: "liste […] vide";
    garde_r5_coupe_c: "…et 3 autres.";
    garde_r5_heure: "à 12:30:45?vraiment oui";
    garde_accent_grave: "lancer `ls -l` puis `cargo test`";
    garde_balise: "fin </div> ici";
    garde_r7_11a: "vitesse ~50Mo/s, 3 erreurs sur le disque de sauvegarde";
    garde_r7_11b: "Sauvegarde : ~3/4 du disque utilisé, nettoyage refusé (code 5)";
    garde_r7_16a: r#"printf "$msg\n""#;
    garde_r7_16b: r"sed 's/\r//g' fichier";
    garde_r7_16c: r#"replace(/\n/g, "")"#;
    garde_courant_1: "Le service wuauserv ne répond pas après 30 s";
    garde_courant_2: "ERROR_ACCESS_DENIED lors de la lecture du registre";
    garde_courant_3: "cible x86_64-unknown-linux-musl absente";
    garde_courant_4: "Échec : délai de 45 s dépassé (tentative 3/5)";
    garde_courant_5: "l'accès en read/write/execute est refusé";
    garde_courant_6: "Ressource temporairement indisponible";
    garde_courant_7: "version 10.0.19041.1 trop ancienne";
    garde_faux_positif_1: "erreur 0x80070005 accès refusé";
    garde_faux_positif_2: "mot de passe trop court";
    garde_faux_positif_3: "option -p ignorée";
    garde_faux_positif_4: "réseau Wi-Fi perdu";
    garde_faux_positif_5: "mise à jour du 2026-11-02 installée";
    garde_faux_positif_6: "port 8080 occupé";
    garde_faux_positif_7: "pid 4242 terminé";
    garde_json_date: r#"{"status":"error","date":"2026/11/20","code":5}"#;
    garde_sed_echappe: r"sed 's/a\/b/c\/d/' fichier";
    garde_r8_appel: "fopen(fichier) puis close(fichier) : délai dépassé";
    garde_r8_apostrophe: "l'été prochain, d'après l'équipe, rien n'a changé";
    garde_r8_sed_virgule: r"sed 's,\/usr\/bin,\/opt\/bin,g' fichier";
    garde_r8_sed_egal: r"sed -e s=\/usr\/lib=\/opt\/lib= fichier";
}

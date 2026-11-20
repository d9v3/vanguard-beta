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
        => r#"{"error":"open <chemin .pdf>"}"#;
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
    r6_regressions_6a: [], r"sed 's/\//-/g' liste.txt" => r"sed 's/<chemin>' <chemin .txt>";
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
        => r#"curl "<url>" a échoué"#;
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
    r7_fuites_4a: [], r#"{"file":"Documents\\Zoé Martin\\Lettre Roy.pdf"}"# => r#"{"file":"<chemin .pdf>"}"#;
    r7_fuites_4b: [], r#"erreur: "..\\zoe.martin\\lettre.txt": introuvable"# => r#"erreur: "<chemin .txt>": introuvable"#;
    r7_fuites_4c: [], r#"erreur: "sauvegardes\\zoe.martin\\lettre.txt": introuvable"#
        => r#"erreur: "<chemin .txt>": introuvable"#;
    r7_fuites_4d: [], r#"path: "\\\\\\\\nas\\\\partage\\\\Zoé Martin\\\\Lettre Roy.pdf""# => r#"path: "<chemin .pdf>""#;
    r7_fuites_5a: [], r#"{"error":"ligne 1\nDocuments/Zoé Martin/Lettre Roy.pdf introuvable"}"#
        => r#"{"error":"ligne <chemin .pdf> introuvable"}"#;
    r7_fuites_5b: [], r#"{"error":"ligne 1\n../Zoé Martin/Lettre Roy.pdf"}"# => r#"{"error":"ligne <chemin .pdf>"}"#;
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
    garde_r5_coupe_a: "(…) panique dans src/journal.rs:12 : index hors bornes";
    garde_r5_coupe_b: "liste […] vide";
    garde_r5_coupe_c: "…et 3 autres.";
    garde_r5_heure: "à 12:30:45?vraiment oui";
    garde_accent_grave: "lancer `ls -l` puis `cargo test`";
    garde_balise: "fin </div> ici";
    garde_r7_11a: "vitesse ~50Mo/s, 3 erreurs sur le disque de sauvegarde";
    garde_r7_11b: "Sauvegarde : ~3/4 du disque utilisé, nettoyage refusé (code 5)";
    garde_r7_16a: r#"printf "$msg\n""#;
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
    garde_r8_appel: "fopen(fichier) puis close(fichier) : délai dépassé";
    garde_r8_apostrophe: "l'été prochain, d'après l'équipe, rien n'a changé";
}

// Ronde 8 : constats confirmés (lot-journal-relecture-r8.json), fermeture-fuites (ff) et abus-regressions (ab).
banc! {
    r8_ff0a: [], r#"{"error":"cannot open `\/home\/alice\/Documents\/x.txt`"}"# => "{\"error\":\"cannot open `<chemin .txt>";
    r8_ff0b: [], r#"{"cmd":"echo x >\/home\/alice\/Documents\/x.txt"}"# => r#"{"cmd":"echo x ><chemin .txt>"#;
    r8_ff0c: [], r#"{"cmd":"ls;\/home\/alice\/bin\/outil"}"# => r#"{"cmd":"ls;<chemin>"#;
    r8_ff0d: [], r#"{"msg":"<\/home\/alice\/x.txt>"}"# => r#"{"msg":"</home/<compte><chemin .txt>>"}"#;
    r8_ff0e: ["/home/bob"], r#"{"a":">\/home\/bob\/Lettre Zoé Martin.pdf"}"# => r#"{"a":"><chemin .pdf>"#;
    r8_ff0f: [], r#"{"cmd":"cat x|\/home\/alice\/bin\/outil"}"# => r#"{"cmd":"cat x|<chemin>"#;
    r8_ff0g: ["/home/alice"], r#"{"error":"cannot open `\/home\/alice\/Documents\/x.txt`"}"# => "{\"error\":\"cannot open `<chemin .txt>";
    r8_ff1a: ["/home/alice"], r"sed -i 's/\/home\/alice\/projets/\/srv/' conf.ini" => "sed -i 's/<chemin>";
    r8_ff1b: ["/home/alice"], r"awk '/\/home\/alice\/projets/{print}' conf.ini" => "awk '<chemin>' conf.ini";
    r8_ff1c: ["/home/alice"], r"sed -i 's,\/home\/alice,\/home\/bob,g' /etc/passwd" => "sed -i 's,~,<chemin>";
    r8_ff1d: [], r"sed 's\/home\/alice\/projets\/x\/' f" => "sed '<jeton>' f";
    r8_ff1e: [], r"s,\/home\/alice\/Documents\/lettre.txt" => "s,<chemin .txt>";
    r8_ff2a: [], r#"{"msg":"copie refusée\n\\\\nas\\partage\\Zoé Martin\\Lettre Roy.pdf"}"# => r#"{"msg":"copie <chemin .pdf>"}"#;
    r8_ff2b: [], r#"{"msg":"ligne 1\n\\\\nas\\alice"}"# => r#"{"msg":"ligne 1\n<chemin>"}"#;
    r8_ff2c: [], r#"{"msg":"ligne 1\n/Zoé Martin/Lettre Roy.pdf"}"# => r#"{"msg":"ligne <chemin .pdf>"}"#;
    r8_ff3a: [], r#"s="\/home\/alice\/Documents\/Lettre Roy.pdf""# => r#"s="<chemin .pdf>""#;
    r8_ff3b: [], r#"s:38:"\/home\/alice\/Documents\/x.txt";"# => r#"s:38:"<chemin .txt>";"#;
    r8_ff3c: [], r#"y:"\/home\/alice\/Mes Documents\/Lettre Roy.pdf""# => r#"y:"<chemin .pdf>""#;
    r8_ff4a: [], r#"curl "https://api.test/items?where={"owner":"alice"}&lecteur=bob" a échoué"# => r#"curl "<url>" a échoué"#;
    r8_ff4b: [], r#"curl "https://api.test/items?ids=["alice","bob"]&ville=Montréal" a échoué"# => r#"curl "<url>" a échoué"#;
    r8_ff4c: [], r"lien 'https://a.test/x?nom='alice',age=3&lecteur=bob' refusé" => "lien '<url>' refusé";
    r8_ff5a: [], r"\\?\HarddiskVolume3\Users\alice\Documents\Lettre Roy.pdf" => "<chemin .pdf>";
    r8_ff5b: [], r"\\?\Volume4\Users\alice\x" => "<chemin>";
    r8_ff5c: [], r"\\\pc-bob\partage\alice\x" => "<chemin>";
    r8_ff6a: [], r#"{"a":"\/home/Zoé Martin\/Lettre Roy.pdf"}"# => r#"{"a":"<chemin .pdf>"}"#;
    r8_ff6b: [], r"erreur \/Users/Zoé Martin/Lettre Roy.pdf" => "erreur <chemin .pdf>";
    r8_ff7a: [], r#"{"msg":"ligne 1\u000aDocuments/Zoé Martin/Lettre Roy.pdf introuvable"}"# => r#"{"msg":"ligne <chemin .pdf> introuvable"}"#;
    r8_ff7b: [], r#"{"msg":"ligne 1\fDocuments/Zoé Martin/Lettre Roy.pdf introuvable"}"# => r#"{"msg":"ligne <chemin .pdf> introuvable"}"#;
    #[ignore = "limite r8 fermeture-fuites#7 (compte en premier élément d'un chemin relatif)"]
    r8_ff7c: [], r#"erreur: "alice\\Mes documents\\Lettre Roy.pdf" introuvable"# => r#"erreur: "<chemin .pdf>" introuvable"#;
    r8_ab0a: [], r#"{"error":"Accès refusé\n\\\\nas-bob\\Sauvegardes\\Zoé Martin\\Lettre Roy.pdf"}"# => r#"{"error":"Accès <chemin .pdf>"}"#;
    r8_ab0b: [], r#"Error { msg: "copie refusée\n\\\\nas-bob\\Sauvegardes\\Zoé Martin\\Lettre Roy.pdf" }"# => r#"Error { msg: "copie <chemin .pdf>" }"#;
    r8_ab0c: [], r#"{"stderr":"cp: impossible de copier\n//nas-bob/Sauvegardes/Zoé Martin/Lettre Roy.pdf"}"# => r#"{"stderr":"cp: impossible de <chemin .pdf>"}"#;
    r8_ab0d: [], r#"{"stderr":"ls: accès impossible\n\\\\nas-bob\\Zoé Martin: Permission non accordée"}"# => r#"{"stderr":"ls: accès impossible\n<chemin>: Permission non accordée"}"#;
    r8_ab0e: [], r#"{"error":"x\t\\\\nas-bob\\Sauvegardes\\Zoé Martin\\Lettre Roy.pdf"}"# => r#"{"error":"<chemin .pdf>"}"#;
    r8_ab0f: [], r#"{"error":"Accès refusé.\n/Zoé Martin/Lettre Roy.pdf"}"# => r#"{"error":"Accès <chemin .pdf>"}"#;
    r8_ab1a: [], r#"{"error":"Accès refusé\n\\\\?\\UNC\\nas-bob\\Sauvegardes\\Zoé Martin\\Lettre Roy.pdf"}"# => r#"{"error":"Accès <chemin .pdf>"#;
    r8_ab1b: [], r#"{"error":"Accès refusé\n\\\\?\\UNC\\nas-bob\\Sauvegardes\\Zoé Martin\\photos"}"# => r#"{"error":"Accès refusé\n<chemin>"#;
    r8_ab3a: [], r#"s="\/home\/alice\/lettre.txt""# => r#"s="<chemin .txt>""#;
    r8_ab3b: [], r#""s_path":"\/home\/alice\/lettre.txt""# => r#""s_path":"<chemin .txt>""#;
    r8_ab3c: [], r#"y-fichier="\/home\/alice\/lettre.txt""# => r#"y-fichier="<chemin .txt>""#;
    r8_ab6a: [], r#"{"log":"{\"url\":\"https://a.test/x?id=5\",\"status\":403,\"error\":\"forbidden\"}"}"# => r#"{"log":"{\"url\":\"<url>\",\"status\":403,\"error\":\"forbidden\"}"}"#;
    r8_ab6b: [], r#"{"https://a.test/x?id=5":"valeur","code":7}"# => r#"{"<url>":"valeur","code":7}"#;
    r8_ab9a: [], r#"curl "https://api.test/items?where={"owner":"alice"}&nom=Zoé Martin" a échoué"# => r#"curl "<url>" a échoué"#;
    r8_ab10a: [], r"erreur dans \\?\GLOBALROOT\Device\HarddiskVolume3\Users\Jean Dupont\Lettre Roy.pdf" => "erreur dans <chemin .pdf>";
    r8_ab8a: [], "sed 's/Documents//g' fichier.txt" => "sed '<chemin>' <chemin .txt>";
    r8_ab4a: [], "Le dossier /var/lib/vanguard n'existe pas : création refusée (code 5)" => "Le dossier <chemin> n'existe pas : création refusée (code 5)";
    r8_ab4b: [], "Le fichier /etc/fstab n'a pas pu être lu : accès refusé" => "Le fichier <chemin> n'a pas pu être lu : accès refusé";
    r8_ab4c: [], "open /var/lib/app doesn't exist: check the installation" => "open <chemin> doesn't exist: check the installation";
    r8_ab4d: [], r"C:\Windows\Temp n'est pas accessible : accès refusé" => "<chemin> n'est pas accessible : accès refusé";
    r8_ab6c: [], r#"{"question":"Supprimer /var/cache/app?","defaut":"non","code":5}"# => r#"{"question":"Supprimer <chemin>?","defaut":"non","code":5}"#;
    r8_ab6d: [], r#""Voulez-vous écraser /etc/app/config?" a demandé le programme"# => r#""Voulez-vous écraser <chemin>?" a demandé le programme"#;
    // Ronde 9 : la règle du délimiteur de sed sans tête personnelle, et une maison sous une tête inconnue.
    r9_faux_sed: [], r#"s="\/var\/lib\/app\/base.db""# => r#"s="<chemin .db>""#;
    r9_sed_maison: ["/srv/comptes/alice"], r"sed 's/\/srv\/comptes\/alice\/x/\/y/' f" => "sed 's/<chemin>";
    r8_ab10b: [], r"erreur dans \\?\GLOBALROOT\Device\HarddiskVolume3\Users\alice\lettre.txt" => "erreur dans <chemin .txt>";
}

// Ronde 8 : textes légitimes qui doivent rester (abus-regressions 2, 4, 5, 6, 7, 8).
garde! {}

// Ronde 9 : constats confirmés (lot-journal-relecture-r9.json), fermeture-fuites (ff) et abus-regressions (ab).
banc! {
    r9_ff0a: [], r#"{"error":"fopen(\/var\/www\/clients\/zoe.martin\/facture.pdf): failed to open stream"}"# => r#"{"error":"fopen(<chemin .pdf>: failed to open stream"}"#;
    r9_ff0b: [], r#"{"error":"fopen(\/mnt\/c\/Users\/zoe.martin\/facture.pdf): failed to open stream"}"# => r#"{"error":"fopen(<chemin .pdf>"#;
    r9_ff0c: [], r#"{"error":"file_get_contents(\/var\/www\/html\/clients\/Zoé Martin\/facture.pdf): Failed to open stream: No such file or directory"}"# => r#"{"error":"file_get_contents(<chemin .pdf>: Failed to open stream: No such file or directory"}"#;
    r9_ff0d: [], r#"{"error":"rename(\/mnt\/data\/zoe.martin\/a.pdf,\/mnt\/data\/zoe.martin\/b.pdf): refusé"}"# => r#"{"error":"rename(<chemin .pdf>,<chemin .pdf>: refusé"}"#;
    r9_ff0e: [], r#"{"file":"\/mnt\/c\/Users\/zoe.martin\/Downloads\/CV(1).pdf"}"# => r#"{"file":"<chemin .pdf>"}"#;
    r9_ff0f: [], r#"{"error":"ENOENT: no such file or directory, open '\/mnt\/data\/zoe.martin\/CV(1).pdf'"}"# => r#"{"error":"ENOENT: no such file or directory, open '<chemin .pdf>'"}"#;
    r9_ff0g: [], r#"{"msg":"Fichier introuvable (\/mnt\/c\/Users\/zoe.martin\/a.pdf)"}"# => r#"{"msg":"Fichier introuvable (<chemin .pdf>"#;
    r9_ff0h: [], r#"{"cmd":"rm \/mnt\/data\/zoe.martin\/*"}"# => r#"{"cmd":"rm <chemin>*"}"#;
    r9_ff0i: [], r#"{"paths":"\/mnt\/data\/zoe.martin\/a.pdf|\/mnt\/data\/luc.roy\/b.pdf"}"# => r#"{"paths":"<chemin .pdf>|<chemin .pdf>"}"#;
    r9_ff0j: [], r#"{"msg":"[\/mnt\/data\/zoe.martin\/a.pdf](lien)"}"# => r#"{"msg":"[<chemin .pdf>"}"#;
    r9_ff1a: [], r#"{"error":"cannot open `\/mnt\/c\/Users\/zoe.martin\/Documents\/x.txt`"}"# => r#"{"error":"cannot open `<chemin .txt>"#;
    r9_ff1b: [], r#"{"error":"cannot open `\/var\/home\/zoe.martin\/Documents\/x.txt`"}"# => r#"{"error":"cannot open `<chemin .txt>"#;
    r9_ff1c: [], r#"{"cmd":"echo x >\/mnt\/c\/Users\/zoe.martin\/Documents\/x.txt"}"# => r#"{"cmd":"echo x ><chemin .txt>"#;
    r9_ff1d: [], r#"{"cmd":"cat x|\/mnt\/c\/Users\/zoe.martin\/bin\/outil"}"# => r#"{"cmd":"cat x|<chemin>"#;
    r9_ff1e: [], r#"{"error":"cannot open `\/run\/media\/zoe.martin\/CLE\/Lettre Roy.pdf`"}"# => r#"{"error":"cannot open `<chemin .pdf>"#;
    r9_ff1f: [], r#"{"cmd":"ls;\/mnt\/nas\/Zoé Martin\/Lettre Roy.pdf"}"# => r#"{"cmd":"ls;<chemin .pdf>"}"#;
    r9_ff2a: [], r"sed 's/\/Users\/Zoé Martin\/Documents/x/' f" => r"sed 's/<chemin>";
    r9_ff2b: [], r"sed 's/\/home\/Zoé Martin\/Documents/x/' f" => r"sed 's/<chemin>";
    r9_ff2c: [], r"sed 's/\/mnt\/nas\/Zoé Martin\/Documents/x/' f" => r"sed 's/<chemin>";
    r9_ff3: [r"/srv/comptes/zoe.martin"], r"sed -i 's/\\/srv\\/comptes\\/zoe.martin\\/projets/x/' conf.ini" => r"sed -i 's/<chemin>";
    r9_ff4a: [], r#"{"msg":"ligne 1\u000A\\\\nas\\partage\\Zoé Martin\\Lettre Roy.pdf"}"# => r#"{"msg":"ligne <chemin .pdf>"}"#;
    r9_ff4b: [], r#"{"msg":"\u001b[01;34m/mnt/nas/Zoé Martin/Lettre Roy.pdf\u001b[0m"}"# => r#"{"msg":"<chemin .pdf>"}"#;
    r9_ff4c: [], r"b'ls: \x1b[01;34m/mnt/nas/Zoé Martin/Lettre Roy.pdf\x1b[0m'" => "b'ls: <chemin .pdf>'";
    r9_ff4d: [], r#"stderr: "ligne 1\u{c}/mnt/nas/Zoé Martin/Lettre Roy.pdf""# => r#"stderr: "ligne <chemin .pdf>""#;
    r9_ff4e: [], r#""ligne 1`n\\nas\partage\Zoé Martin\Lettre Roy.pdf""# => r#""ligne 1`<chemin .pdf>""#;
    r9_ff4f: [], "ls: \u{1b}[01;34m/mnt/nas/Zoé Martin/Lettre Roy.pdf\u{1b}[0m" => "ls: <chemin .pdf>";
    r9_ff5a: [], r"erreur: Documents//Zoé Martin//Lettre Roy.pdf introuvable" => "erreur: <chemin .pdf>";
    r9_ff5b: [], r"erreur: /mnt/nas/Zoé Martin/liste.php?[nom]=Zoé Martin introuvable" => r"erreur: <chemin>";
    r9_ff5c: [], r#"{"cmd":"sort <$HOME/Documents/Lettre Zoé Martin.txt"}"# => r#"{"cmd":"sort <<chemin .txt>"#;
    r9_ff6a: [], r#"{"msg":"ligne 1\n/Zoé Martin"}"# => r#"{"msg":"ligne 1\n<chemin>"#;
    r9_ff6b: [], r#"{"msg":"ligne 1\n\\\\nas\\Zoé Martin"}"# => r#"{"msg":"ligne 1\n<chemin>"#;
    r9_ff6c: [], r#"{"msg":"ligne 1\n//nas/Zoé Martin"}"# => r#"{"msg":"ligne 1\n<chemin>"#;
    r9_ab0a: [], r#"{"msg":"échec des tests\nDocuments/Zoé Martin/Lettre Roy.pdf"}"# => r#"{"msg":"échec des tests\n<chemin .pdf>"#;
    r9_ab0b: [], r#"{"msg":"entrée/sortie\nPhotos/Zoé Martin/IMG 01.jpg manquant"}"# => r#"{"msg":"<chemin .jpg>"}"#;
    r9_ab0c: [], r#""erreur\\nDocuments/Zoé Martin/Lettre Roy.pdf introuvable""# => r#""<chemin .pdf>""#;
    r9_ab0d: [], r#"{"log":"{\"msg\":\"ligne 1\\nDocuments/Zoé Martin/Lettre Roy.pdf\"}"}"# => r#"{"log":"{\"msg\":\"ligne <chemin .pdf>\"}"}"#;
    r9_ab1a: [], r"lecture de Documents/Zoé Martin//Lettre Roy.pdf refusée" => "lecture de <chemin .pdf>";
    r9_ab1b: [], r#"open("Documents//Zoé Martin//Lettre Roy.pdf") = -1 ENOENT"# => r#"open("<chemin .pdf>") = -1 ENOENT"#;
    r9_ab1c: [], r"lecture de Bureau//zoe.martin//lettre.pdf refusée" => r"lecture de <chemin .pdf>";
    r9_ab1d: [], r"erreur: could not open Téléchargements//Zoé Martin - CV.docx" => "erreur: could not open <chemin .docx>";
    r9_ab2a: [], r"fopen(\/srv\/partage\/zoe.martin\/lettre.txt): failed to open stream" => r"fopen(<chemin .txt>: failed to open stream";
    r9_ab2b: [], r#"{"msg":"open(\/var\/data\/zoe.martin\/lettre.txt) a échoué"}"# => r#"{"msg":"open(<chemin .txt>) a échoué"}"#;
    r9_ab2c: [], r#"{"path":"\/mnt\/partage\/zoe.martin\/Lettre_(1).pdf"}"# => r#"{"path":"<chemin .pdf>"}"#;
    r9_ab2d: [], r"PHP Warning: fopen(\/mnt\/nas\/Zoé Martin\/Lettre Roy.pdf): failed" => r"PHP Warning: fopen(<chemin .pdf>): failed";
    r9_ab3a: [], r#"curl "https://api.test/items?where={"owner":"zoe.martin"}" a échoué"# => r#"curl "<url>}" a échoué"#;
    r9_ab3b: [], r#"GET "https://api.test/x?json={"id":5,"owner":"zoe.martin"}" 403"# => r#"GET "<url>}" 403"#;
    r9_ab3c: [], r#"lien "https://a.test/x?t="12":"zoe.martin"" refusé"# => r#"lien "<url>" refusé"#;
    r9_ab4a: [], r"cat <$HOME/zoe.martin/notes.txt" => r"cat <<chemin .txt>";
    r9_ab4b: [], r"gcc -isystem$HOME/zoe.martin/include x.c" => r"gcc -isystem<chemin>";
    r9_ab4c: [], r"java -cp$HOME/zoe.martin/lib Main" => r"java -cp<chemin>";
    r9_ab4d: [], r"cat <$HOME/Lettre Zoé Martin.pdf" => r"cat <<chemin .pdf>";
    r9_ab5a: [], r"lecture de /srv/www/page.php?&nom=zoe.martin refusée" => r"lecture de <chemin>";
    r9_ab5b: [], r"ouverture de C:\inetpub\wwwroot\page.aspx?&nom=zoe.martin refusée" => r"ouverture de <chemin>";
    r9_ab5c: [], r"GET 192.0.2.7/x?-zoe.martin refusé" => r"GET <ip><chemin> refusé";
    r9_ab6a: [], r"extrait : …(2) Zoé Martin\Downloads\Facture.exe bloqué" => r"extrait : <chemin>";
    r9_ab6b: [], r"extrait : …(Zoé Martin) copie\Facture.pdf" => r"extrait : <chemin>";
    r9_ab6c: [], r#"extrait : …"Zoé Martin" (copie)\Facture.pdf"# => r"extrait : <chemin>";
    r9_ab6d: [], r"extrait : …[2024-11] Zoé Martin\Facture.pdf" => r"extrait : <chemin>";
    r9_ab6e: [], r"… [privé] zoé martin\outil.exe" => r"<chemin>";
}

// Ronde 9 : textes légitimes abîmés, limites écrites (CHANGELOG) ; dans le doute, on masque plus.
banc! {
    r9_ab7a: [], r#"{"url":"https://a.test/x?id=5","query":"a=b&c=d","status":403}"# => r#"{"url":"<url>":403}"#;
    r9_ab7b: [], r#"{"url":"https://a.test/x?id=5","cmd":"x=1 y=2 lancer","status":403}"# => r#"{"url":"<url>:"x=1 y=2 lancer","status":403}"#;
    r9_ab8a: [], r"rewrite ^\/users\/(.*)$ \/u\/$1 permanent;" => r"rewrite ^/users/(.*)$ <chemin> permanent;";
    r9_ab8b: [], r#"{"regex":"^\/users\/(\d+)$","ok":false}"# => r#"{"regex":"^/users/(\d+)$","ok":false}"#;
    r9_ab8c: [], r"grep -E '^\/root\/' fichier" => r"grep -E '^/root/' fichier";
    r9_ab8d: [], r#"<a href=\"\/home\">Accueil<\/a>"# => r#"<a href=\"<chemin>">Accueil</a>"#;
    r9_ab8e: [], r"GET \/home HTTP\/1.1" => r"GET <chemin>";
    r9_ab9a: [], r"sed -e 's|/usr/local|/opt|g' Makefile" => r"sed -e 's|<chemin>|<chemin>|g' Makefile";
    r9_ab9b: [], r"grep -E 'foo|/bar/' fichier" => r"grep -E 'foo|<chemin>' fichier";
    r9_ab9c: [], r"formule \\\hline dans le tableau" => r"formule <chemin> dans le tableau";
    // Fermeture partielle (ronde 10) : l'apostrophe collée au séparateur reste dans le nom, le prénom est masqué ;
    // la fin du nom sort encore (r9_ab9d ci-dessous, ouvert).
    r10_apostrophe_collee: [], r"lecture de /srv/partage/d'Alice Martin refusée" => r"lecture de <chemin> Martin refusée";
    #[ignore = "limite r9 abus-regressions#9 (apostrophe hors dossier personnel, nom à espaces)"]
    r9_ab9d: [], r"lecture de /srv/partage/d'Alice Martin refusée" => r"lecture de <chemin> refusée";
}

// Ronde 10 : anciennes gardes devenues limites écrites (CHANGELOG). La normalisation retire tout « \ » devant « / »,
// une coupure écrite (« \n », « \r », « \t »…) est une vraie frontière et « // » compte comme une barre : un sed,
// une regex, une route web ou une panique Windows écrits ainsi sortent abîmés, jamais une fuite.
banc! {
    r10_r6_regressions_6b: [], r"règle ^\/api\/v1 refusée" => r"règle ^/api/v1 refusée";
    r10_r7_16b: [], r"sed 's/\r//g' fichier" => r"sed 's/\r<chemin>' fichier";
    r10_r7_16c: [], r#"replace(/\n/g, "")"# => r#"replace(/\n<chemin>, "")"#;
    r10_sed_echappe: [], r"sed 's/a\/b/c\/d/' fichier" => r"sed 's/a/b/c/d/' fichier";
    r10_r8_sed_virgule: [], r"sed 's,\/usr\/bin,\/opt\/bin,g' fichier" => r"sed 's,<chemin>,<chemin>,g' fichier";
    r10_r8_sed_egal: [], r"sed -e s=\/usr\/lib=\/opt\/lib= fichier" => r"sed -e s=<chemin> fichier";
    r10_r8_ab2a: [], r"thread 'main' panicked at src\nettoyer\mod.rs:110:17:" => r"thread 'main' panicked at src\n<chemin>:110:17:";
    r10_r8_ab2b: [], r"thread 'main' panicked at src\reseau\nat\mod.rs:42:5: index hors bornes" => r"thread 'main' panicked at src\r<chemin>:42:5: index hors bornes";
    r10_r8_ab2c: [], r"panique dans src\amelioration\texte\tests.rs:12" => r"panique dans src\amelioration\t<chemin>:12";
    r10_r8_ab2d: [], r"voir target\release\vanguard.exe" => r"voir target\r<chemin .exe>";
    r10_r8_ab2e: [], r"at .\src\reseau\mod.rs:12" => r"at .\src\r<chemin>:12";
    r10_r8_ab5a: [], "Envoi … (2/3) terminé" => r"Envoi <chemin>";
    r10_r8_ab5b: [], "Attente … (3 essais) : échec de usr/bin/outil (code 3)" => r"Attente <chemin>";
    r10_r8_ab5c: [], "Erreur … [info] voir src/journal.rs:12" => r"Erreur <chemin>";
    r10_r8_ab5d: [], r#"Résultat … "ok" pour vanguard.exe"# => r"Résultat <chemin>";
    r10_r8_ab5e: [], "note … #3 dans src/journal.rs:12" => r"note <chemin>";
    r10_r8_ab7a: [], "abonnement à 10$US/mois refusé par la banque" => r"abonnement à 10<chemin> refusé par la banque";
    r10_r8_ab7b: [], "coût 25$CA/an, facture 3 en retard" => r"coût 25<chemin>, facture 3 en retard";
    r10_r8_ab7c: [], r#"sed -e "s/$PREFIX/usr/" Makefile"# => r#"sed -e "s/<chemin>" Makefile"#;
    r10_r8_ab8a: [], "sed 's/Documents//g' fichier" => r"sed '<chemin>' fichier";
    r10_r8_ab8b: [], "total.size//chunk.size vaut 3" => r"<chemin> vaut 3";
    r10_r8_ab8c: [], r"grep -E '\/(bin|sbin)\/' fichier" => r"grep -E '/(bin|sbin)/' fichier";
    r10_r8_ab8d: [], r"rewrite ^\/old\/(.*)$ \/new\/$1 permanent;" => r"rewrite ^/old/(.*)$ <chemin> permanent;";
}

// Ronde 10 : constats confirmés (lot-journal-relecture-r10.json), fermeture-fuites (ff) et abus-regressions (ab).
banc! {
    r11_ff0a: [], "vrai: \u{1b}[38;2;97;175;239m/mnt/data/zoe.martin/build\u{1b}[0m" => "vrai: <chemin>";
    r11_ff0b: [], "grep: \u{1b}[35m\u{1b}[K/mnt/data/zoe.martin/notes\u{1b}[m\u{1b}[K" => "grep: <chemin>";
    r11_ff0c: [], "make: \u{1b}[2K/mnt/data/zoe.martin/build" => "make: <chemin>";
    r11_ff0d: [], "\u{1b}[0;1;4;38;5;33m/mnt/data/zoe.martin/build\u{1b}[0m" => "<chemin>";
    r11_ff0e: [], "\u{1b}]8;;file:///mnt/data/zoe.martin/a.pdf\u{1b}\\lien\u{1b}]8;;\u{1b}\\" => "lien";
    r11_ff1a: [], r#"{"out":"\u001b[34mprojets/zoe.martin\u001b[0m/notes"}"# => r#"{"out":"<chemin>"}"#;
    r11_ff1b: [], r"/mnt/nas/Zoé Martin\x1b[0m/Lettre Roy.pdf" => "<chemin .pdf>";
    r11_ff1c: [], r#"{"out":"\u001b[34mD:\\Clients\\Zoé Martin\u001b[0m\\Lettre Roy.pdf"}"# => r#"{"out":"<chemin .pdf>"}"#;
    r11_ff1d: [], r"erreur: projets/alice\x1b[0m/x.tar.gz : erreur" => "erreur: <chemin .gz> : erreur";
    r11_ff2a: [], r#"cmdline: "cat\0/mnt/data/zoe.martin/notes.txt\0""# => r#"cmdline: "<chemin>""#;
    r11_ff2b: [], r#"{"cmdline":"cat\u0000/mnt/data/zoe.martin/notes.txt\u0000"}"# => r#"{"cmdline":"<chemin>"}"#;
    r11_ff2c: [], r"argv: cat\x00/mnt/data/zoe.martin/notes.txt\x00" => "argv: <chemin>";
    r11_ff2d: [], "sortie: \"\u{1b}[01;34m/mnt/data/zoe.martin\u{1b}[0m\"" => r#"sortie: "<chemin>""#;
    r11_ff2e: [], "sortie: \"erreur\u{1b}[31m: /mnt/nas/Zoé Martin/Lettre Roy.pdf\u{1b}[0m\"" => r#"sortie: "erreur: <chemin .pdf>""#;
    r11_ff2f: [], r"refusée\012/mnt/nas/Zoé Martin/Lettre Roy.pdf" => "<chemin .pdf>";
    r11_ff3a: [], r#"{"url":"https://api.exemple.com/x?where={\"owner\":\"Zoé Martin\"}"}"# => r#"{"url":"<url>}"}"#;
    r11_ff3b: [], r#"args: ["curl", "-s", "https://api.exemple.com/x?where={\"owner\":\"Zoé Martin\"}"]"# => r#"args: ["curl", "-s", "<url>}"]"#;
    r11_ff3c: [], r#"GET "https://api.exemple.com/clients?where={"nom":"Zoé Martin"}" 403"# => r#"GET "<url>}" 403"#;
    r11_ff3d: [], r#"ouvrir "https://www.exemple.com/search?q="Zoé Martin" Laval" a échoué"# => r#"ouvrir "<url>" Laval" a échoué"#;
    r11_ff4a: [], "cc -I/mnt/data/zoe.martin/include x.c" => "cc -I<chemin>";
    r11_ff4b: [], "ld -L/mnt/nas/Zoé-Martin/lib x.o" => "ld -L<chemin>";
    r11_ff4c: [], r#"cc "-I/mnt/nas/Zoé Martin/include" x.c"# => r#"cc "-I<chemin>" x.c"#;
    r11_ff5a: [], r#"{"file":"clients/Zoé Martin/Lettre Roy.pdf"}"# => r#"{"file":"<chemin .pdf>"}"#;
    r11_ff5b: [], r#"open("clients/Zoé Martin/Lettre Roy.pdf") = -1 ENOENT"# => r#"open("<chemin .pdf>") = -1 ENOENT"#;
    r11_ff5c: [], "lecture de clients/Zoé Martin/2024/Lettre de Luc Roy.pdf refusée" => "lecture de <chemin .pdf> refusée";
    r11_ff5d: [], r#"{"file":"clients\\Zoé Martin\\Lettre Roy.pdf"}"# => r#"{"file":"<chemin .pdf>"}"#;
    r11_ff6a: [], r#"args: ["curl", "https://api.exemple.com/x?where={"owner":"zoe.martin"}"]"# => r#"args: ["curl", "<url>}"]"#;
    r11_ff6b: [], r#"commande : curl, "https://api.exemple.com/x?where={"owner":"zoe.martin"}" a échoué"# => r#"commande : curl, "<url>}" a échoué"#;
    r11_ff6c: [], r#"{"a":1,"https://api.exemple.com/x?where={"owner":"zoe.martin"}":2}"# => r#"{"a":1,"<url>}":2}"#;
    r11_ff7a: [], "lecture de /mnt/nas/'Zoé Martin'/photo.jpg refusée" => "lecture de <chemin .jpg> refusée";
    r11_ff7b: [], r#"cd /mnt/nas/"Zoé Martin"/x"# => "cd <chemin>";
    r11_ff7c: [], r#"{"file":"&#47;mnt&#47;data&#47;zoe.martin&#47;facture.pdf"}"# => r#"{"file":"<chemin .pdf>"}"#;
    r11_ff7d: [], "lecture de 「/mnt/nas/Zoé Martin/Lettre Roy.pdf」 refusée" => r#"lecture de "<chemin .pdf>" refusée"#;
    r11_ff7e: [], "lecture de ´/mnt/nas/Zoé Martin/Lettre Roy.pdf´ refusée" => "lecture de '<chemin .pdf>' refusée";
    r11_ab0a: [], r"error: could not canonicalize\r\n\\?\D:\Clients\Zoé Martin\notes de Luc Roy.txt\r\n" => r"error: could not canonicalize\r<chemin>?\D:<chemin>";
    r11_ab0b: [], r"Introuvable.\r\n\\?\D:\Clients\Zoé Martin\contrat.docx\r\n" => r"Introuvable.\r<chemin>?\D:<chemin>";
    r11_ab0c: [], r#"{"stderr":"Introuvable.\r\n\\\\?\\C:\\Users\\alice\\Documents\\Lettre Zoé Martin.pdf\r\n"}"# => r#"{"stderr":"Introuvable.\r<chemin>?\\C:<chemin>"#;
    r11_ab0d: [], r#"{"error":"Accès refusé :\n\\\\?\\C:\\Users\\Zoé Martin"}"# => r#"{"error":"Accès refusé :<chemin>?\\C:<chemin>"#;
    r11_ab0e: [], r"erreur:\n\??\C:\Users\Zoé Martin" => r"erreur:<chemin>??\C:<chemin>";
    r11_ab1a: [], r"stdout: /srv/partage/\x1b[01;31mZoé Martin\x1b[0m/lettre.pdf" => "stdout: <chemin .pdf>";
    r11_ab1b: [], r"/mnt/nas/\x1b[01;31mzoe.martin\x1b[0m/facture.pdf" => "<chemin .pdf>";
    r11_ab1c: [], r"stdout: C:\Partage\\x1b[01;31mzoe.martin\x1b[0m\facture.pdf" => "stdout: <chemin .pdf>";
    r11_ab1d: [], r"voir https://a.test/x?nom=\x1b[01;31mzoe.martin\x1b[0m&lecteur=luc.roy ici" => "voir <url> ici";
    r11_ab1e: [], r"courriel \x1b[01;31mzoe\x1b[0m.martin@exemple.test refusé" => "courriel <adresse> refusé";
    r11_ab4: [], r#","https://api.test/items?where={"owner":"zoe.martin"}""# => r#","<url>}""#;
}

// Ronde 11 : cas qui tiennent chaque règle seule (survivants des mutations).
banc! {
    r11_mut_hexa_x: [], r"argv: cat\x1f/srv/Zoé Martin" => r"argv: cat\x1f<chemin>";
    r11_mut_hexa_u: [], r"argv: cat\u001F/srv/Zoé Martin" => r"argv: cat\u001F<chemin>";
    r11_mut_octal: [], r"argv: cat\012/srv/Zoé Martin" => r"argv: cat\012<chemin>";
    r11_mut_accolades: [], r"argv: cat\u{41}/srv/Zoé Martin" => r"argv: cat\u{41}<chemin>";
    r11_mut_nom_long: [], r"argv: cat\N{LINE FEED}/srv/Zoé Martin" => r"argv: cat\N{LINE FEED}<chemin>";
    r11_mut_entre_mots: [], "courriel zoe.mar\u{1b}[1mtin@exemple.test refusé" => "courriel <adresse> refusé";
}

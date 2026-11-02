//! La grammaire des lignes que le processus élevé de Windows lit du Vanguard non élevé (src/machine/windows/
//! gestes.rs) : script vérifié par empreinte, programme fixe de la table, acte sur un service ou un dossier de la
//! table, sur le pare-feu ou la catégorie d'un réseau (GUID), sur une clé du registre désignée par un nom en
//! hexadécimal UTF-16 (IFEO, SilentProcessExit, service), sur Defender (réglage vers le plus sûr seulement, règle
//! ASR des listes d'Optimiser, exclusion en hexadécimal UTF-16, menaces), liste validée, découpe d'une liste de correctifs en
//! morceaux natifs et PowerShell, états d'un script en échec ; gestes du compte (faits par Vanguard non élevé, jamais
//! par le processus élevé) et séparation d'une liste entre points, travail élevé et gestes du compte. Chemins piégés (« .. », NUL, lecteur manquant),
//! hexadécimal en majuscules ou en demi-paire, noms hors de la liste fermée, lignes et correctifs en nombre. Le réseau :
//! écriture du hosts (empreintes, chemin du fichier préparé en hexadécimal), DNS d'une carte (liste fermée), et le
//! jugement de la différence du hosts sur deux moitiés des octets (seules des lignes mises en commentaire hors du bloc
//! de Vanguard, jamais un nom protégé dans le bloc).
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/, cales) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../src/machine/windows/gestes.rs"]
mod gestes;

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let Ok(texte) = std::str::from_utf8(octets) else {
        return;
    };
    let lignes: Vec<String> = texte.split('\n').map(str::to_string).collect();
    for l in &lignes {
        // Une ligne relue se réécrit à l'identique : rien d'autre que sa forme exacte n'est accepté.
        if let Some(a) = gestes::analyser_programme(l) {
            assert_eq!(a.ligne(), *l);
            assert!(l.len() <= 256 && l.is_ascii());
            // Les arguments sont ceux de la table : le nom reçu n'en ajoute pas un, ni une espace.
            let args = a.arguments("C:");
            assert_eq!(args.len(), a.programme.arguments.len());
            assert!(args.iter().all(|x| !x.contains(['\n', '\r', '"'])));
        }
        // Un acte : de la table, écrit à l'identique, court, ASCII ; jamais accepté sans en avoir le verbe. Seuls les
        // actes nommés du registre dépassent 256 octets.
        if let Some(a) = gestes::analyser_acte(l) {
            assert_eq!(a.ligne(), *l);
            let nomme = matches!(
                a,
                gestes::Acte::IfeoDebugger(..)
                    | gestes::Acte::IfeoSilencieux(..)
                    | gestes::Acte::ServiceGuillemets(_)
                    | gestes::Acte::DefenderExclusionRetirer(..)
            );
            let borne = if matches!(a, gestes::Acte::HostsEcrire(_)) {
                gestes::HOSTS_LIGNE_MAX
            } else if nomme {
                gestes::ACTE_NOM_MAX
            } else {
                gestes::ACTE_MAX
            };
            assert!(l.len() <= borne && l.is_ascii());
            assert!(gestes::est_un_acte(l));
            assert!(!(a.durcit() && a.affaiblit()));
            match a {
                gestes::Acte::Service(s) => {
                    assert!(!(s.durcit && s.affaiblit));
                    assert!(gestes::SERVICES.iter().any(|t| t.nom == s.nom));
                }
                // Aucune ligne ne coupe le pare-feu ; « absent » ne vise que les règles d'entrée.
                gestes::Acte::PareFeuPublic(p) => {
                    for (r, v) in p.reglages() {
                        assert!(r != gestes::ReglagePublic::Actif || v == gestes::ValeurPublic::Oui);
                        assert!(v != gestes::ValeurPublic::Absent || r == gestes::ReglagePublic::ReglesEntrantes);
                    }
                }
                gestes::Acte::ReseauCategorie(r) => {
                    assert_eq!(gestes::GuidReseau::lire(&r.guid.texte()), Some(r.guid));
                }
                // Un nom ne sort jamais de sa racine : ni séparateur, ni « .. », ni contrôle, 260 unités au plus.
                gestes::Acte::IfeoDebugger(_, n)
                | gestes::Acte::IfeoSilencieux(_, n)
                | gestes::Acte::ServiceGuillemets(n) => {
                    let t = n.texte();
                    assert!(!t.is_empty() && t.encode_utf16().count() <= gestes::NOM_MAX);
                    assert!(!t.contains(['\\', '/', ':', '*', '?', '"', '<', '>', '|']) && !t.contains(".."));
                    assert!(!t.chars().any(char::is_control) && t != ".");
                    assert_eq!(gestes::NomFichier::lire(&n.hex()).as_ref(), Some(&n));
                    assert_eq!(gestes::NomFichier::nouveau(t).as_ref(), Some(&n));
                }
                // Aucune ligne ne baisse Defender : une valeur permise pour ce réglage, qui vise une valeur sûre (rang
                // non nul) ; la valeur écrite ne coupe ni le temps réel ni le cloud.
                gestes::Acte::Defender(r, v) => {
                    assert!(r.permises().contains(&v) && a.durcit() && !a.affaiblit());
                    assert!(r.rang(i64::from(r.attendue(v))) > 0);
                    match r.valeur_wmi(v) {
                        gestes::ValeurWmi::Booleen(desactive) => {
                            assert!(r == gestes::ReglageDefender::TempsReel && !desactive);
                        }
                        gestes::ValeurWmi::Octet(n) => assert!(n == 1 || n == 2),
                        autre => panic!("{autre:?}"),
                    }
                    assert_eq!(gestes::ligne_defender(r, v).as_deref(), Some(l.as_str()));
                }
                // Une règle des listes d'Optimiser seulement, mise en blocage ou en audit : jamais retirée.
                gestes::Acte::DefenderAsr(id, m) => {
                    assert_eq!(gestes::asr_connue(id), Some(id));
                    assert!(a.durcit() && !a.affaiblit() && gestes::ModeAsr::TOUS.contains(&m));
                    assert_eq!(gestes::ligne_defender_asr(id, m).as_deref(), Some(l.as_str()));
                }
                // Une exclusion relue à l'identique, sans contrôle, 260 unités au plus.
                gestes::Acte::DefenderExclusionRetirer(g, ref e) => {
                    let t = e.texte();
                    assert!(!t.is_empty() && t.encode_utf16().count() <= gestes::NOM_MAX);
                    assert!(!t.chars().any(char::is_control));
                    assert_eq!(gestes::Exclusion::lire(&e.hex()).as_ref(), Some(e));
                    assert_eq!(
                        gestes::ligne_defender_exclusion_retirer(g, t).as_deref(),
                        Some(l.as_str())
                    );
                    assert!(a.durcit() && !a.affaiblit());
                }
                gestes::Acte::DefenderMenacesRetirer => {
                    assert_eq!(*l, gestes::ligne_defender_menaces_retirer());
                }
                // Le fichier préparé : « hosts » d'un dossier « hosts-prepare », chemin complet sans détour ; deux
                // empreintes majuscules ; aucune commande PowerShell, et rien qui touche une carte.
                gestes::Acte::HostsEcrire(ref h) => {
                    assert!(!a.touche_le_reseau() && !a.durcit() && !a.affaiblit());
                    let c = h.chemin.to_ascii_lowercase();
                    assert!(
                        c.ends_with(r"\hosts-prepare\hosts") && !c.split(['\\', '/']).any(|x| x == ".." || x == ".")
                    );
                    assert!(!h.chemin.contains(['\0', '\n', '\r']));
                    for e in [&h.avant, &h.apres] {
                        assert!(e.len() == 64 && e.bytes().all(|o| o.is_ascii_digit() || (b'A'..=b'F').contains(&o)));
                    }
                    assert_eq!(
                        gestes::ligne_hosts_ecrire(&h.avant, &h.apres, &h.chemin).as_deref(),
                        Some(l.as_str())
                    );
                }
                gestes::Acte::DnsAuto(g) => {
                    assert!(a.touche_le_reseau());
                    assert_eq!(gestes::ligne_dns_auto(&g.texte()).as_deref(), Some(l.as_str()));
                }
                // Chaque serveur est de sa famille, une adresse d'hôte, quatre au plus ; la ligne se refait de ses
                // côtés ; jamais « les deux tels quels » ni « les deux vidés » (qui s'écrit dns-auto).
                gestes::Acte::DnsServeurs(ref d) => {
                    assert!(a.touche_le_reseau());
                    let cote = |c: &gestes::CoteDns, v6: bool| match c {
                        gestes::CoteDns::Garder => None,
                        gestes::CoteDns::Vider => Some(String::new()),
                        gestes::CoteDns::Serveurs(l) => {
                            assert!(!l.is_empty() && l.len() <= 4);
                            assert!(l.iter().all(|ip| ip.is_ipv6() == v6
                                && !ip.is_loopback()
                                && !ip.is_unspecified()
                                && !ip.is_multicast()));
                            Some(c.texte())
                        }
                    };
                    let (v4, v6) = (cote(&d.v4, false), cote(&d.v6, true));
                    assert!(
                        !matches!((&v4, &v6), (None, None))
                            && !(v4.as_deref() == Some("") && v6.as_deref() == Some(""))
                    );
                    assert_eq!(
                        gestes::ligne_dns(&d.guid.texte(), v4.as_deref(), v6.as_deref()).as_deref(),
                        Some(l.as_str())
                    );
                }
                _ => {}
            }
        }
        // Un geste du compte : écrit à l'identique, ASCII, borné ; jamais un programme, un acte ou un script, et
        // toujours refusé par la validation du processus élevé.
        if let Some(g) = gestes::analyser_compte(l) {
            assert_eq!(g.ligne(), *l);
            assert!(l.len() <= gestes::COMPTE_LIGNE_MAX && l.is_ascii() && l.starts_with(gestes::COMPTE));
            assert!(gestes::analyser_programme(l).is_none() && gestes::analyser_acte(l).is_none());
            assert!(gestes::analyser_script(l).is_none() && !gestes::est_un_acte(l));
            assert!(gestes::valider(std::slice::from_ref(l), |_| Some(())).is_none());
            assert_eq!(g.valeur().is_some(), g.donnee().is_some());
            if let gestes::GesteCompte::RetirerRun { nom, .. } = &g {
                assert!(nom.len() <= gestes::RUN_NOM_MAX && !nom.contains(&0));
                let runonce = matches!(g, gestes::GesteCompte::RetirerRun { runonce: true, .. });
                assert_eq!(gestes::ligne_run_retirer(runonce, nom).as_deref(), Some(l.as_str()));
            }
        }
        if let Some(s) = gestes::analyser_script(l) {
            assert_eq!(gestes::ligne_script(&s.empreinte, &s.chemin), *l);
            assert!(!s.chemin.split(['\\', '/']).any(|c| c == "." || c == ".."));
            assert!(!s.chemin.contains(['\0', '\n', '\r']));
        }
        if let Some(etats) = gestes::etats_du_script(l) {
            assert!(etats.len() <= gestes::ETATS_MAX);
            // Relus depuis la raison qu'en écrit le processus élevé : les mêmes.
            let code: i32 = l
                .strip_prefix("echec code=")
                .and_then(|r| r.split(' ').next())
                .and_then(|c| c.parse().ok())
                .unwrap();
            let raison = format!("echec {}", gestes::raison_du_script(code, &etats));
            assert_eq!(gestes::etats_du_script(&raison), Some(etats));
        }
    }
    // Le hosts : la première moitié des octets pour l'ancien, la seconde pour le nouveau. Admis, le nouveau ne diffère
    // de l'ancien que par des lignes mises en commentaire hors du bloc ; dans le bloc, aucun nom protégé ; les deux
    // tiennent dans la borne et ne sont pas de l'UTF-16. Les empreintes vérifient les octets, au sens strict.
    let (avant, apres) = octets.split_at(octets.len() / 2);
    if let Ok(d) = gestes::juger_hosts(avant, apres) {
        assert!(avant.len() <= gestes::HOSTS_MAX && apres.len() <= gestes::HOSTS_MAX);
        assert!(!apres.contains(&0) && !avant.contains(&0));
        assert!(d.ajoutes.iter().chain(&d.retires).all(|n| gestes::nom_hosts_valide(n)));
        assert!(d.ajoutes.iter().all(|n| !gestes::nom_protege(n)));
        assert!(d.commentees.iter().all(|c| !c.contains(['\n', '\r'])));
        // Sans bloc ni commentaire, rien d'autre ne change : les octets sont les mêmes.
        if d.vide() && !d.bloc_avant && !d.bloc_apres {
            assert_eq!(avant, apres);
        }
        let h = gestes::HostsEcrire {
            avant: gestes::empreinte_hosts(avant),
            apres: gestes::empreinte_hosts(apres),
            chemin: r"C:\Users\alice\AppData\Local\Vanguard\reparer\hosts-prepare\hosts".to_string(),
        };
        assert_eq!(gestes::verifier_hosts(&h, apres, avant), Ok(d));
        let mut change = apres.to_vec();
        change.push(b'#');
        assert_eq!(
            gestes::verifier_hosts(&h, &change, avant),
            Err(gestes::RefusHosts::PrepareChange)
        );
    }
    // Commenter ce qu'on veut d'un hosts admis donne une version admise, et qui ne commente que ces lignes-là.
    if gestes::juger_hosts(avant, avant).is_ok() {
        let commente = gestes::hosts_commente(avant, |ip| ip.is_ipv4());
        let d = gestes::juger_hosts(avant, &commente).expect("une version commentée est admise");
        assert!(d.ajoutes.is_empty() && d.retires.is_empty() && d.bloc_avant == d.bloc_apres);
        let tout = gestes::hosts_commente(avant, |_| true);
        assert!(gestes::juger_hosts(avant, &tout).is_ok());
        assert_eq!(gestes::hosts_commente(avant, |_| false), avant);
    }
    // La liste : acceptée, elle a une entrée par ligne ; les « autres » lignes ne passent que par le validateur donné,
    // qui admet ici toute longueur (comme un ordre du blocage et son chemin) : seule la borne de `valider` arrête une
    // ligne démesurée (graine « longue », -max_len d'outils/fuzz.sh).
    let autre = |l: &str| l.starts_with("autre").then_some(());
    // Deux lignes de script de même empreinte : la liste est refusée, quel que soit le chemin de chacune.
    let empreintes: Vec<String> = lignes
        .iter()
        .filter_map(|l| gestes::analyser_script(l))
        .map(|s| s.empreinte)
        .collect();
    let doublon = empreintes.iter().enumerate().any(|(i, e)| empreintes[..i].contains(e));
    match gestes::valider(&lignes, autre) {
        Some(v) => {
            assert_eq!(v.len(), lignes.len());
            assert!(!lignes.is_empty() && lignes.len() <= gestes::LIGNES_MAX);
            assert!(lignes.iter().all(|l| l.len() <= gestes::LIGNE_MAX));
            assert!(!doublon, "script en double accepté");
        }
        None => {
            // Refusée : il y a une raison, jamais une liste bonne refusée sans cause.
            let bonne = |l: &String| {
                l.len() <= gestes::LIGNE_MAX
                    && if l.starts_with(gestes::COMPTE) {
                        // Un geste du compte n'est jamais au processus élevé, même bien formé.
                        false
                    } else if l.starts_with(gestes::SCRIPT) {
                        gestes::analyser_script(l).is_some()
                    } else if l.starts_with(gestes::PROGRAMME) {
                        gestes::analyser_programme(l).is_some()
                    } else if gestes::est_un_acte(l) {
                        gestes::analyser_acte(l).is_some()
                    } else {
                        autre(l).is_some()
                    }
            };
            assert!(
                lignes.is_empty() || lignes.len() > gestes::LIGNES_MAX || doublon || !lignes.iter().all(bonne),
                "liste bonne refusée"
            );
        }
    }
    // La découpe : des correctifs séparés par une ligne vide ; chaque ligne est dans un seul morceau, dans l'ordre, et
    // un morceau natif n'a que des lignes natives (le point de restauration n'est jamais mêlé au script).
    let correctifs: Vec<Vec<String>> = texte
        .split("\n\n")
        .map(|c| c.split('\n').filter(|l| !l.is_empty()).map(str::to_string).collect())
        .collect();
    let natif = |l: &str| l.starts_with('#');
    let mut vues = Vec::new();
    for m in gestes::decouper(&correctifs, natif) {
        match m {
            gestes::Morceau::Natif(v) => {
                assert!(!v.is_empty());
                for (i, j) in v {
                    assert!(natif(&correctifs[i][j]));
                    vues.push((i, j));
                }
            }
            gestes::Morceau::Script(v) => {
                assert!(!v.is_empty());
                for (i, suite) in v {
                    assert!(!suite.is_empty());
                    for j in suite {
                        assert!(!natif(&correctifs[i][j]));
                        vues.push((i, j));
                    }
                }
            }
        }
    }
    let attendues: Vec<(usize, usize)> = correctifs
        .iter()
        .enumerate()
        .flat_map(|(i, c)| (0..c.len()).map(move |j| (i, j)))
        .collect();
    assert_eq!(vues, attendues);
    // La séparation : chaque ligne d'un correctif va à une seule part, dans l'ordre ; aux gestes du compte, seulement
    // une ligne que `analyser_compte` relit ; un point n'est jamais un geste du compte.
    let est_point = |l: &str| l.starts_with('!');
    let separes = gestes::separer(&correctifs, est_point);
    assert_eq!(separes.len(), correctifs.len());
    for (c, s) in correctifs.iter().zip(&separes) {
        let mut toutes: Vec<usize> = s.points.iter().chain(&s.eleves).chain(&s.compte).copied().collect();
        toutes.sort_unstable();
        assert_eq!(toutes, (0..c.len()).collect::<Vec<_>>());
        assert!(s.points.iter().all(|&j| est_point(&c[j])));
        assert!(
            s.compte
                .iter()
                .all(|&j| !est_point(&c[j]) && gestes::analyser_compte(&c[j]).is_some())
        );
        assert!(
            s.eleves
                .iter()
                .all(|&j| !est_point(&c[j]) && gestes::analyser_compte(&c[j]).is_none())
        );
    }
    // Le passage en deux temps : jamais un geste du compte envoyé au processus élevé ; aucun geste du compte fait
    // quand le passage élevé est arrêté ; un correctif réussi n'a que des parts réussies.
    let arrete = octets.first().is_some_and(|o| o & 1 == 1);
    let mut envoyes_au_processus_eleve: Vec<Vec<String>> = Vec::new();
    let mut faits = 0usize;
    let resultat = gestes::lancer_separe(
        &correctifs,
        est_point,
        |envoyes| {
            envoyes_au_processus_eleve = envoyes.to_vec();
            Some(gestes::PassageEleve {
                resultats: vec![true; envoyes.len()],
                notes: envoyes.to_vec(),
                arrete,
            })
        },
        |_| {
            faits = faits.saturating_add(1);
            gestes::FaitCompte {
                reussi: true,
                rien: false,
                avant: None,
            }
        },
    );
    let (resultats, notes) = resultat.unwrap();
    assert_eq!((resultats.len(), notes.len()), (correctifs.len(), correctifs.len()));
    assert!(
        envoyes_au_processus_eleve
            .iter()
            .flatten()
            .all(|l| gestes::analyser_compte(l).is_none())
    );
    let du_compte: usize = separes.iter().map(|s| s.compte.len()).sum();
    assert_eq!(
        faits,
        if arrete && !envoyes_au_processus_eleve.is_empty() {
            0
        } else {
            du_compte
        }
    );
});

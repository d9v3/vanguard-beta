//! Docker : ports publiés qui passent devant le pare-feu, lus même sans le groupe docker.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use super::*;

/// Ports de conteneurs joignables depuis le réseau, dans la colonne « Ports » de `docker ps` : tout sauf la
/// boucle locale (127.x, ::1). Une IP du réseau local (`-p 10.0.0.5:8080:80`) est aussi exposée.
/// Ex. « 0.0.0.0:8080->80/tcp, `[::]:8080->80/tcp`, 127.0.0.1:3389->3389/tcp » → [« 8080/tcp »], prêts à montrer
/// (un port mal formé reste du texte : rendu inoffensif, comme le nom d'un conteneur).
pub(super) fn ports_docker_exposes(colonne: &str) -> Vec<String> {
    let mut ports: Vec<String> = colonne
        .split(", ")
        .filter_map(|p| {
            let (hote, _) = p.split_once("->")?;
            let (adresse, port) = hote.rsplit_once(':')?;
            let proto = p.rsplit_once('/').map_or("tcp", |(_, pr)| pr);
            let ip = adresse.trim_matches(|c| c == '[' || c == ']');
            let locale = ip.parse::<std::net::IpAddr>().is_ok_and(|a| a.is_loopback());
            (!locale).then(|| crate::ui::affichable(&format!("{port}/{proto}")))
        })
        .collect();
    ports.dedup();
    ports
}

/// Docker écrit ses propres règles et passe devant ufw : un port publié sur 0.0.0.0 est joignable
/// depuis le réseau même avec le pare-feu actif.
pub(super) fn docker() -> Vec<Constat> {
    if !["/usr/bin/docker", "/bin/docker", "/usr/local/bin/docker"]
        .iter()
        .any(|d| Path::new(d).exists())
    {
        return vec![];
    }
    if let Some(origine) = docker_api::demon_designe() {
        return demon_designe_non_lu(origine);
    }
    // Rien ne désigne un autre démon : son API locale d'abord (lecture seule), la CLI s'il ne répond pas sur sa prise.
    if Path::new(docker_api::PRISE).exists() {
        match docker_api::conteneurs_sur(Path::new(docker_api::PRISE)) {
            Ok(liste) => return constats_docker(liste),
            // Hors du groupe docker (qui vaut root) : la CLI serait refusée de même.
            Err(e) if e.raison == crate::modele::Raison::Droits => {
                return vec![docker_sans_acces(&processus(), autres_visibles())];
            }
            Err(_) => {}
        }
    }
    let Some(liste) = ps_par_la_cli() else {
        return vec![docker_sans_acces(&processus(), autres_visibles())];
    };
    constats_docker(
        liste
            .lines()
            .map(|ligne| {
                let (nom, colonne) = ligne.split_once('\t').unwrap_or((ligne, ""));
                (crate::ui::affichable(nom), ports_docker_exposes(colonne))
            })
            .collect(),
    )
}

/// `docker ps` sur la prise par défaut, sans rien de la maison : `-H` fait prendre à la CLI le contexte « default »,
/// et `--config` (un dossier qui n'existe pas) lui fait ignorer ~/.docker. Sans eux, elle suivait le `currentContext`
/// du config.json trouvé par HOME (que `par_le_systeme` garde) : un fichier écrit par le compte après `demon_designe`,
/// ou à côté d'un DOCKER_CONFIG qu'elle ne voit pas, lui faisait lire un faux démon et dire « aucun port exposé » (N-2,
/// recontrôle 2 de la 0.95).
fn ps_par_la_cli() -> Option<String> {
    let hote = format!("unix://{}", docker_api::PRISE);
    let args = [
        "--config",
        "/nonexistent/vanguard-docker",
        "-H",
        &hote,
        "ps",
        "--format",
        "{{.Names}}\t{{.Ports}}",
    ];
    sortie_delai("docker", &args, 15, &[0])
}

/// Le démon de la personne est désigné par `origine` (DOCKER_HOST…, ou le config.json de la maison) : la CLI de
/// Vanguard, lancée sans les variables du compte et sur la prise par défaut, en lirait un autre, et son « aucun port
/// exposé » serait faux (E-4 et N-2, recontrôles 0.95). Il est dit non vérifié, avec son origine. Le démon du système
/// (la prise par défaut) est lu quand même s'il répond, sinon les processus ; seuls les ports exposés vus ainsi sont
/// gardés (`constats_demon_designe`) : leur « rien d'exposé » ne dit rien du démon désigné.
fn demon_designe_non_lu(origine: &str) -> Vec<Constat> {
    let prise = Path::new(docker_api::PRISE);
    constats_demon_designe(
        origine,
        prise.exists().then(|| docker_api::conteneurs_sur(prise)),
        || docker_sans_acces(&processus(), autres_visibles()),
    )
}

/// Les conteneurs actifs lus sur une prise : (nom prêt à montrer, ports exposés au réseau).
type Conteneurs = Vec<(String, Vec<String>)>;

/// `demon_designe_non_lu`, sans rien lire : `systeme`, la lecture de la prise par défaut (`None` : absente) ;
/// `par_processus`, la lecture par les processus, faite seulement si la prise ne répond pas.
///
/// Prise absente, refusée (hors du groupe docker : le cas courant) ou muette : les processus se lisent quand même, et
/// l'origine n'y change rien. Seule leur alerte vérifiée (un port publié hors de la boucle locale) est gardée : le
/// non vérifié ci-dessous l'aurait sinon remplacée, et une variable du compte aurait caché un signal déjà vu (N-3,
/// recontrôle 2 de la 0.95). Leur « sain », leur « aucun conteneur » ou leur propre non vérifié ne disent rien du
/// démon désigné : jamais gardés.
fn constats_demon_designe(
    origine: &str,
    systeme: Option<Result<Conteneurs, crate::modele::Echec>>,
    par_processus: impl FnOnce() -> Constat,
) -> Vec<Constat> {
    let vus = match systeme {
        Some(Ok(liste)) => constats_docker(liste),
        None | Some(Err(_)) => vec![par_processus()],
    };
    let mut constats: Vec<Constat> = vus.into_iter().filter(|c| c.verifie && c.probleme.is_some()).collect();
    constats.push(impossible(
        "Docker",
        &trf!(
            "le démon désigné par {origine} n'est pas lu : Vanguard ne suit pas un démon choisi par le compte (variable ou fichier de réglage), et ses ports publiés ne sont pas vérifiés",
            "the daemon set by {origine} is not read: Vanguard does not follow a daemon chosen by the account (variable or settings file), and its published ports are not checked"
        ),
    ));
    constats
}

/// Les constats des conteneurs actifs : (nom prêt à montrer, ports exposés au réseau).
fn constats_docker(liste: Vec<(String, Vec<String>)>) -> Vec<Constat> {
    let mut constats = Vec::new();
    let mut actifs = 0usize;
    for (nom, exposes) in liste {
        actifs = actifs.saturating_add(1);
        if exposes.is_empty() {
            continue;
        }
        constats.push(
            alerte(
                "Docker",
                Niveau::Eleve,
                trf!(
                    "Conteneur « {nom} » : port(s) {} publié(s) hors de la boucle locale. Docker passe devant le pare-feu : joignable(s) depuis le réseau.", "Container “{nom}”: port(s) {} published outside the loopback. Docker bypasses the firewall: reachable from the network.",
                    exposes.join(", ")
                ),
            )
            .manuel(
                tr!("Publier seulement en local, puis recréer le conteneur : -p 127.0.0.1:PORT:PORT, ou dans docker-compose « \"127.0.0.1:PORT:PORT\" »", "Publish locally only, then recreate the container: -p 127.0.0.1:PORT:PORT, or in docker-compose “\"127.0.0.1:PORT:PORT\"”"),
                &[],
            ),
        );
    }
    if constats.is_empty() {
        constats.push(ok(
            "Docker",
            trf!(
                "Aucun port de conteneur exposé au réseau ({actifs} conteneur(s) actif(s)).",
                "No container port exposed to the network ({actifs} running container(s))."
            ),
        ));
    }
    constats
}

/// Nom et ligne de commande de chaque processus, lus dans /proc (lisible par tous, sauf montage « hidepid »).
pub(super) fn processus() -> Vec<(String, Vec<String>)> {
    use crate::socle::processus::{arguments, nom_court, pids};
    pids()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|pid| Some((nom_court(pid)?.trim().to_string(), arguments(pid))))
        .collect()
}

/// Port publié par un processus docker-proxy : (adresse de l'hôte, « 8080/tcp »).
/// Ligne de commande : « -proto tcp -host-ip 0.0.0.0 -host-port 8080 -container-ip 172.17.0.2 -container-port 80 ».
/// N'importe quel programme peut porter ce nom et ces arguments : le port, montré, est rendu inoffensif.
pub(super) fn port_docker_proxy(args: &[String]) -> Option<(String, String)> {
    let valeur = |cle: &str| {
        args.iter()
            .position(|a| a == cle)
            .and_then(|i| args.get(i.checked_add(1)?))
            .cloned()
    };
    let proto = valeur("-proto").unwrap_or_else(|| "tcp".into());
    Some((
        valeur("-host-ip")?,
        crate::ui::affichable(&format!("{}/{proto}", valeur("-host-port")?)),
    ))
}

/// Les processus des autres comptes sont-ils visibles ? Le PID 1 (à root) se lit : /proc n'est pas monté avec
/// « hidepid » ; et Vanguard tourne dans l'espace de PID de l'ordinateur, pas dans un conteneur qui ne verrait pas
/// ceux de l'hôte (4026531836 : l'inode fixe de l'espace initial dans le noyau, PROC_PID_INIT_INO).
fn autres_visibles() -> bool {
    let initial = std::fs::read_link("/proc/self/ns/pid").is_ok_and(|l| l.as_os_str() == "pid:[4026531836]");
    initial && crate::socle::processus::nom_court(1).is_some()
}

/// Docker sans accès au démon (on n'est pas dans le groupe docker, et c'est mieux ainsi : ce groupe vaut root).
/// Les processus restent visibles : un « containerd-shim » par conteneur actif, un « docker-proxy » par port publié,
/// avec l'adresse et le port dans sa ligne de commande. De quoi conclure dans la plupart des cas. `autres_visibles` :
/// les processus des autres comptes se voient (`autres_visibles()`) ; sans cela, l'absence de « dockerd » ne prouve
/// rien.
pub(super) fn docker_sans_acces(procs: &[(String, Vec<String>)], autres_visibles: bool) -> Constat {
    let vu = |nom: &str| procs.iter().any(|(n, _)| n.starts_with(nom));
    if !procs.iter().any(|(n, _)| n == "dockerd") {
        // /proc masqué (hidepid) ou conteneur : on ne verrait aucun processus d'un autre compte, donc on ne conclut
        // rien.
        if !autres_visibles {
            return crate::machine::impossible_par(
                "Docker",
                crate::modele::Raison::Droits,
                tr!(
                    "Impossible de vérifier (processus des autres comptes masqués : hidepid ou conteneur).",
                    "Could not check (processes of other accounts hidden: hidepid or container)."
                ),
            );
        }
        // Démon arrêté, mais des conteneurs gardés en marche (live-restore) : leurs ports ne se lisent pas sans lui.
        if vu("containerd-shim") || vu("docker-proxy") {
            return impossible(
                "Docker",
                tr!(
                    "démon arrêté, conteneurs encore actifs (live-restore) : ports publiés non lus",
                    "daemon stopped, containers still running (live-restore): published ports not read"
                ),
            );
        }
        return ok(
            "Docker",
            tr!(
                "Docker installé, démon arrêté : aucun conteneur actif.",
                "Docker installed, daemon stopped: no running container."
            ),
        );
    }
    let conteneurs = procs.iter().filter(|(n, _)| n.starts_with("containerd-shim")).count();
    if conteneurs == 0 {
        return ok("Docker", tr!("Aucun conteneur actif.", "No running container."));
    }
    let mut exposes: Vec<String> = procs
        .iter()
        .filter(|(n, _)| n == "docker-proxy")
        .filter_map(|(_, args)| port_docker_proxy(args))
        .filter(|(ip, _)| {
            !ip.trim_matches(|c| c == '[' || c == ']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|a| a.is_loopback())
        })
        .map(|(_, port)| port)
        .collect();
    exposes.sort();
    exposes.dedup();
    if !exposes.is_empty() {
        return alerte(
            "Docker",
            Niveau::Eleve,
            trf!(
                "{conteneurs} conteneur(s) actif(s), port(s) {} publié(s) hors de la boucle locale. Docker passe devant le pare-feu : joignable(s) depuis le réseau.", "{conteneurs} running container(s), port(s) {} published outside the loopback. Docker bypasses the firewall: reachable from the network.",
                exposes.join(", ")
            ),
        )
        .manuel(
            tr!("Publier seulement en local, puis recréer le conteneur : -p 127.0.0.1:PORT:PORT, ou dans docker-compose « \"127.0.0.1:PORT:PORT\" »", "Publish locally only, then recreate the container: -p 127.0.0.1:PORT:PORT, or in docker-compose “\"127.0.0.1:PORT:PORT\"”"),
            &[],
        );
    }
    // Sans docker-proxy, un port publié passe seulement par le pare-feu de Docker, illisible sans root.
    let sans_proxy = std::fs::read_to_string("/etc/docker/daemon.json")
        .is_ok_and(|t| t.replace(' ', "").contains("\"userland-proxy\":false"));
    if sans_proxy {
        impossible(
            "Docker",
            tr!(
                "conteneurs actifs et userland-proxy coupé : ports publiés illisibles sans le groupe docker",
                "running containers and userland-proxy off: published ports unreadable without the docker group"
            ),
        )
    } else {
        ok(
            "Docker",
            trf!(
                "{conteneurs} conteneur(s) actif(s), aucun port publié hors de la boucle locale.",
                "{conteneurs} running container(s), no port published outside the loopback."
            ),
        )
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_docker() {
        let c = "0.0.0.0:8080->80/tcp, [::]:8080->80/tcp, 127.0.0.1:3389->3389/tcp, 0.0.0.0:53->53/udp, 9000/tcp";
        assert_eq!(ports_docker_exposes(c), vec!["8080/tcp", "53/udp"]);
        assert_eq!(
            ports_docker_exposes("127.0.0.1:8006->8006/tcp, [::1]:8006->8006/tcp"),
            [] as [std::string::String; 0]
        );
        // Publié sur l'IP du réseau local : exposé aussi.
        assert_eq!(ports_docker_exposes("10.0.0.179:8080->80/tcp"), vec!["8080/tcp"]);
        assert_eq!(ports_docker_exposes(":::9000->9000/tcp"), vec!["9000/tcp"]);
        assert_eq!(ports_docker_exposes(""), [] as [std::string::String; 0]);
        // Lu dans la ligne de commande d'un processus (que n'importe quel programme peut imiter) ou dans docker ps :
        // piégé, le port arrive inoffensif.
        assert_eq!(
            ports_docker_exposes("0.0.0.0:80\x1b[2K\r->80/tcp\u{202e}"),
            vec!["80�[2K�/tcp�"]
        );
        let args: Vec<String> = ["-host-ip", "0.0.0.0", "-host-port", "53\x1b]52;c;eA==\x07"]
            .map(str::to_string)
            .to_vec();
        assert_eq!(
            port_docker_proxy(&args),
            Some(("0.0.0.0".to_string(), "53�]52;c;eA==�/tcp".to_string()))
        );
    }

    #[test]
    fn docker_lu_sans_le_groupe_docker() {
        let p = |nom: &str, args: &str| (nom.to_string(), args.split(' ').map(str::to_string).collect::<Vec<_>>());
        let dockerd = p("dockerd", "/usr/bin/dockerd -H fd://");
        let shim = p("containerd-shim", "/usr/bin/containerd-shim-runc-v2 -namespace moby");
        let local = p(
            "docker-proxy",
            "/usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 8006 -container-ip 172.17.0.2 -container-port 8006",
        );
        let ouvert = p(
            "docker-proxy",
            "/usr/bin/docker-proxy -proto udp -host-ip 0.0.0.0 -host-port 53 -container-ip 172.17.0.3 -container-port 53",
        );
        // Démon actif, aucun conteneur : vérifié, rien à signaler.
        let c = docker_sans_acces(std::slice::from_ref(&dockerd), true);
        assert!(c.verifie && c.probleme.is_none());
        // Conteneur publié seulement en local : rien à signaler.
        let c = docker_sans_acces(&[dockerd.clone(), shim.clone(), local.clone()], true);
        assert!(c.verifie && c.probleme.is_none());
        // Port publié sur toutes les interfaces : alerte, avec le port.
        let c = docker_sans_acces(&[dockerd.clone(), shim.clone(), local, ouvert.clone()], true);
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(c.message.contains("53/udp") && !c.message.contains("8006"));
        // Démon arrêté, autres comptes visibles, aucun conteneur : vérifié, sain.
        let c = docker_sans_acces(&[], true);
        assert!(c.verifie && c.probleme.is_none(), "{}", c.message);
        // Démon arrêté mais un conteneur gardé en marche (live-restore) : on ne conclut pas, et ce n'est pas tu.
        for reste in [shim.clone(), ouvert] {
            let c = docker_sans_acces(&[reste], true);
            assert!(!c.verifie && c.message.contains("live-restore"), "{}", c.message);
            assert!(matches!(c.etat(), crate::modele::Etat::NonVerifie(r) if !r.attendue(false)));
        }
        // Processus des autres comptes invisibles (hidepid) : on ne conclut pas, faute de droits.
        for procs in [vec![], vec![shim]] {
            let c = docker_sans_acces(&procs, false);
            assert!(!c.verifie);
            assert_eq!(c.etat(), crate::modele::Etat::NonVerifie(crate::modele::Raison::Droits));
        }
        // Le dockerd vu suffit, même si le PID 1 ne se lit pas.
        assert!(docker_sans_acces(std::slice::from_ref(&dockerd), false).verifie);
    }

    /// N-3 (recontrôle 2 de la 0.95) : un démon désigné par une variable (DOCKER_HOST…) n'est pas lu, mais la lecture
    /// par les processus ne dépend pas de la variable. Hors du groupe docker (la prise refusée, le cas courant), son
    /// alerte « port publié hors de la boucle locale » disparaissait : une simple variable du compte cachait un signal
    /// vu, et le score montait. Son alerte reste, avec le non vérifié ; son « sain » ou son « aucun conteneur », qui ne
    /// disent rien du démon désigné, jamais.
    #[test]
    fn demon_designe_garde_l_alerte_des_processus() {
        let p = |nom: &str, args: &str| (nom.to_string(), args.split(' ').map(str::to_string).collect::<Vec<_>>());
        let dockerd = p("dockerd", "/usr/bin/dockerd -H fd://");
        let shim = p("containerd-shim", "/usr/bin/containerd-shim-runc-v2 -namespace moby");
        let ouvert = p(
            "docker-proxy",
            "/usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 8080 -container-ip 172.17.0.2 -container-port 80",
        );
        let resume = |c: &[Constat]| {
            c.iter()
                .map(|c| format!("{}|{:?}|{}", c.verifie, c.probleme, c.message))
                .collect::<Vec<_>>()
        };
        let non_verifie = |c: &Constat, variable: &str| !c.verifie && c.message.contains(variable);
        let refusee = || Some(Err(crate::modele::Echec::new("docker", crate::modele::Raison::Droits)));
        // Prise refusée ou absente, port publié vu par les processus : l'alerte ET le non vérifié.
        for systeme in [refusee(), None] {
            let procs = [dockerd.clone(), shim.clone(), ouvert.clone()];
            let c = constats_demon_designe("DOCKER_HOST", systeme, || docker_sans_acces(&procs, true));
            assert!(
                c.iter()
                    .any(|c| c.verifie && c.probleme == Some(Niveau::Eleve) && c.message.contains("8080/tcp")),
                "alerte des processus perdue : {:#?}",
                resume(&c)
            );
            assert!(c.iter().any(|c| non_verifie(c, "DOCKER_HOST")), "{:#?}", resume(&c));
            assert!(
                !c.iter().any(|c| c.verifie && c.probleme.is_none()),
                "{:#?}",
                resume(&c)
            );
        }
        // Rien de publié, démon arrêté ou processus masqués : ni « sain », ni « aucun conteneur », ni un second
        // non vérifié ; seulement celui du démon désigné.
        for (procs, visibles) in [
            (vec![dockerd.clone()], true),
            (vec![dockerd.clone(), shim.clone()], true),
            (vec![], true),
            (vec![shim.clone()], true),
            (vec![], false),
        ] {
            let c = constats_demon_designe("DOCKER_CONTEXT", refusee(), || docker_sans_acces(&procs, visibles));
            assert!(
                c.len() == 1 && non_verifie(&c[0], "DOCKER_CONTEXT"),
                "{:#?}",
                resume(&c)
            );
        }
        // La prise du système répond : ses ports exposés sont gardés, son « rien d'exposé » non ; les processus, qui
        // diraient la même chose de ce démon-là, ne sont pas relus.
        let sans_processus = || -> Constat { panic!("processus lus alors que la prise répond") };
        let c = constats_demon_designe(
            "DOCKER_CONFIG",
            Some(Ok(vec![("salon".into(), vec!["8080/tcp".into()])])),
            sans_processus,
        );
        assert!(
            c.len() == 2 && c[0].probleme == Some(Niveau::Eleve) && non_verifie(&c[1], "DOCKER_CONFIG"),
            "{:#?}",
            resume(&c)
        );
        let c = constats_demon_designe(
            "DOCKER_CONFIG",
            Some(Ok(vec![("salon".into(), vec![])])),
            sans_processus,
        );
        assert!(c.len() == 1 && non_verifie(&c[0], "DOCKER_CONFIG"), "{:#?}", resume(&c));
    }

    /// Posée dans le processus relancé par l'essai E-4.
    const RELANCE_E4: &str = "VANGUARD_ESSAI_E4_RELANCE";

    /// E-4 (recontrôle 0.95) : DOCKER_HOST désigne le démon de la personne (Docker sans root, autre hôte). La lecture
    /// native de la prise par défaut est alors sautée, mais la CLI, lancée sans les variables du compte, lisait un
    /// autre démon et pouvait dire « aucun port exposé » : un « sain » sur le mauvais démon. Le démon désigné est dit
    /// non vérifié, avec la variable, et rien n'est dit sain.
    #[test]
    fn demon_designe_par_docker_host_dit_non_verifie() {
        if std::env::var_os(RELANCE_E4).is_some() {
            for c in docker() {
                println!(
                    "constat-e4:{}|{}|{}",
                    c.verifie,
                    c.probleme.is_some(),
                    c.message.replace('\n', " ")
                );
            }
            return;
        }
        if !["/usr/bin/docker", "/bin/docker", "/usr/local/bin/docker"]
            .iter()
            .any(|d| Path::new(d).exists())
        {
            return crate::essais::saute("docker absent");
        }
        let d = crate::essais::Jetable::nouveau("e4-docker-host");
        let sortie = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "machine::linux::docker::tests::demon_designe_par_docker_host_dit_non_verifie",
                "--nocapture",
            ])
            .env(RELANCE_E4, "1")
            .env("DOCKER_HOST", format!("unix://{}", d.join("docker.sock").display()))
            .output()
            .unwrap();
        let texte = String::from_utf8_lossy(&sortie.stdout);
        assert!(sortie.status.success() && texte.contains("1 passed"), "{texte}");
        let constats: Vec<&str> = texte.lines().filter_map(|l| l.strip_prefix("constat-e4:")).collect();
        assert!(
            !constats.iter().any(|c| c.starts_with("true|false|")),
            "« sain » sur un autre démon que celui de DOCKER_HOST : {constats:#?}"
        );
        assert!(
            constats
                .iter()
                .any(|c| c.starts_with("false|") && c.contains("DOCKER_HOST")),
            "démon de DOCKER_HOST pas dit non vérifié : {constats:#?}"
        );
    }

    /// Un faux démon Docker sur une prise Unix du dossier temporaire (pas sous `essais::temporaire()` : le chemin
    /// d'une prise tient en 108 octets, comme pour `http_unix::essais::faux_demon`). Il compte les connexions et répond
    /// comme un démon sans conteneur : ce qu'un faux démon du compte dirait pour faire croire à « rien d'exposé ».
    /// Arrêté et retiré quand l'essai le lâche.
    struct FauxDemon {
        chemin: std::path::PathBuf,
        connexions: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        arret: std::sync::Arc<std::sync::atomic::AtomicBool>,
        fil: Option<std::thread::JoinHandle<()>>,
    }

    impl FauxDemon {
        fn nouveau(nom: &str) -> FauxDemon {
            use std::io::{Read, Write};
            use std::sync::atomic::Ordering::SeqCst;
            let chemin = std::env::temp_dir().join(format!("vanguard-{nom}-{}.sock", std::process::id()));
            let _ = std::fs::remove_file(&chemin);
            let ecoute = std::os::unix::net::UnixListener::bind(&chemin).unwrap();
            ecoute.set_nonblocking(true).unwrap();
            let connexions = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let arret = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let (compte, fin) = (connexions.clone(), arret.clone());
            let fil = std::thread::spawn(move || {
                while !fin.load(SeqCst) {
                    let Ok((mut s, _)) = ecoute.accept() else {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        continue;
                    };
                    compte.fetch_add(1, SeqCst);
                    let _ = s.set_nonblocking(false);
                    let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                    let mut demande = Vec::new();
                    let mut o = [0u8; 1];
                    while !demande.ends_with(b"\r\n\r\n") && matches!(s.read(&mut o), Ok(1)) {
                        demande.push(o[0]);
                    }
                    let demande = String::from_utf8_lossy(&demande);
                    let corps = if demande.starts_with("HEAD ") {
                        ""
                    } else if demande.contains("/_ping") {
                        "OK"
                    } else if demande.contains("/containers/json") {
                        "[]"
                    } else {
                        "{}"
                    };
                    let _ = write!(
                        s,
                        "HTTP/1.1 200 OK\r\nApi-Version: 1.47\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{corps}",
                        corps.len()
                    );
                }
            });
            FauxDemon {
                chemin,
                connexions,
                arret,
                fil: Some(fil),
            }
        }

        fn connexions(&self) -> usize {
            self.connexions.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl Drop for FauxDemon {
        fn drop(&mut self) {
            self.arret.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(fil) = self.fil.take() {
                let _ = fil.join();
            }
            let _ = std::fs::remove_file(&self.chemin);
        }
    }

    /// Posée dans le processus relancé par l'essai N-2 : « docker » (les constats) ou « cli » (`ps_par_la_cli`).
    const RELANCE_N2: &str = "VANGUARD_ESSAI_N2_RELANCE";

    /// N-2 (recontrôle 2 de la 0.95) : un contexte choisi dans ~/.docker/config.json, un fichier que le compte écrit,
    /// mène à un faux démon. La CLI de Vanguard, qui garde HOME, suivait ce contexte : le faux démon disait « aucun
    /// conteneur », et Vanguard « Aucun port de conteneur exposé », vérifié. Le démon désigné par le fichier est dit
    /// non vérifié, comme pour une variable ; ni les constats ni la CLI de Vanguard ne joignent le faux démon.
    #[test]
    fn contexte_de_la_maison_dit_non_verifie() {
        match std::env::var(RELANCE_N2).as_deref() {
            Ok("docker") => {
                for c in docker() {
                    println!(
                        "constat-n2:{}|{}|{}",
                        c.verifie,
                        c.probleme.is_some(),
                        c.message.replace('\n', " ")
                    );
                }
                return;
            }
            Ok(_) => {
                println!("cli-n2:{}", ps_par_la_cli().is_some());
                return;
            }
            Err(_) => {}
        }
        let Some(cli) = crate::commande::outil_systeme("docker") else {
            return crate::essais::saute("docker absent");
        };
        let maison = crate::essais::Jetable::nouveau("n2-docker-contexte");
        let demon = FauxDemon::nouveau("n2-docker");
        // Le contexte « temoin » du compte, rangé où la CLI le cherche : contexts/meta/<sha256 du nom>/meta.json.
        let reglages = maison.join(".docker");
        let meta = reglages
            .join("contexts")
            .join("meta")
            .join("9cf95f8768a2401fd50a768785ab7614dbe46a03d238d9a80f14e4d641563fa6");
        std::fs::create_dir_all(&meta).unwrap();
        std::fs::write(reglages.join("config.json"), r#"{"currentContext":"temoin"}"#).unwrap();
        let hote = format!("unix://{}", demon.chemin.display());
        let contexte = serde_json::json!({
            "Name": "temoin",
            "Metadata": {},
            "Endpoints": {"docker": {"Host": hote, "SkipTLSVerify": false}},
        });
        std::fs::write(meta.join("meta.json"), contexte.to_string()).unwrap();
        let lancer = |c: &mut std::process::Command| {
            c.env_remove("DOCKER_HOST")
                .env_remove("DOCKER_CONTEXT")
                .env_remove("DOCKER_CONFIG")
                .env("HOME", &*maison)
                .output()
                .unwrap()
        };
        // Témoin : la CLI de la personne, elle, suit ce contexte jusqu'au faux démon. Sans lui, « jamais joint » ne
        // prouverait rien.
        let s = lancer(std::process::Command::new(&cli).arg("ps"));
        assert!(
            demon.connexions() > 0,
            "contexte témoin pas suivi : {}",
            String::from_utf8_lossy(&s.stderr)
        );
        let avant = demon.connexions();
        let relancer = |mode: &str| {
            let s = lancer(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "machine::linux::docker::tests::contexte_de_la_maison_dit_non_verifie",
                        "--nocapture",
                    ])
                    .env(RELANCE_N2, mode),
            );
            let texte = String::from_utf8_lossy(&s.stdout).into_owned();
            assert!(s.status.success() && texte.contains("1 passed"), "{texte}");
            texte
        };
        let texte = relancer("docker");
        let constats: Vec<&str> = texte.lines().filter_map(|l| l.strip_prefix("constat-n2:")).collect();
        assert!(
            !constats.iter().any(|c| c.starts_with("true|false|")),
            "« sain » sur le démon d'un contexte de la maison : {constats:#?}"
        );
        assert!(
            constats
                .iter()
                .any(|c| c.starts_with("false|") && c.contains(docker_api::CONFIG_DE_LA_MAISON)),
            "démon du config.json de la maison pas dit non vérifié : {constats:#?}"
        );
        assert_eq!(
            demon.connexions(),
            avant,
            "constats lus sur le faux démon : {constats:#?}"
        );
        let texte = relancer("cli");
        assert!(texte.contains("cli-n2:"), "{texte}");
        assert_eq!(
            demon.connexions(),
            avant,
            "la CLI de Vanguard a suivi le contexte de la maison"
        );
    }
}

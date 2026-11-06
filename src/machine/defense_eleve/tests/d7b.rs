//! Essais du lot D7b : serveur SSH, BPF, journal, certificats, proxy, Bluetooth, arrêt d'un programme.

use super::*;
use crate::machine::gestes_unix::{AdresseBt, ReglageSsh};

const CLES: &str = "/home/alice/.ssh/authorized_keys";
const SSHD_D: &str = "/etc/ssh/sshd_config.d";

fn chemin(p: &str) -> CheminDesigne {
    CheminDesigne::nouveau(p.as_bytes()).unwrap()
}

/// Un ordinateur avec sshd : sshd_config.d de root, la clé d'alice posée.
fn faux_ssh() -> Faux {
    let mut a = Faux::nouveau();
    a.outils.push("sshd");
    a.dossier("/etc/ssh", 0o755, 0);
    a.dossier(SSHD_D, 0o755, 0);
    a.dossier("/home/alice", 0o755, 1000);
    a.dossier("/home/alice/.ssh", 0o700, 1000);
    a.poser(
        CLES,
        b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExemple alice@portable\n",
        0o600,
    );
    a.fichiers.get_mut(Path::new(CLES)).unwrap().fiche.uid = 1000;
    a
}

fn regler(a: &mut Faux, cle: &str, valeur: &str) {
    for (k, v) in &mut a.sshd_base {
        if k == cle {
            *v = valeur.to_string();
        }
    }
}

fn fichier_ssh(r: ReglageSsh) -> PathBuf {
    PathBuf::from(format!("{SSHD_D}/00-vanguard-{}.conf", r.mot()))
}

#[test]
fn ssh_mots_de_passe_vides_puis_defaire() {
    let mut a = faux_ssh().repondre("o");
    regler(&mut a, "permitemptypasswords", "yes");
    let mut s = FauxServices::nouveau();
    let r = faire_avec(Defense::DurcirSsh(ReglageSsh::MotsDePasseVides), &mut a, &mut s);
    assert!(r.reussi, "{}", r.raison);
    let p = fichier_ssh(ReglageSsh::MotsDePasseVides);
    assert_eq!(a.fichiers[&p].contenu, b"PermitEmptyPasswords no\n");
    assert_eq!(a.fichiers[&p].fiche.mode, 0o644);
    // Validé avant d'être rechargé ; les sessions ouvertes restent (un rechargement, jamais un redémarrage).
    assert!(a.journal.contains(&"sshd -t".to_string()), "{:?}", a.journal);
    assert_eq!(s.faits, ["recharger sshd.service"]);
    assert!(a.questions[0].contains("Les sessions SSH ouvertes restent ouvertes"));
    let mut a = a.repondre("o");
    let r = defaire(&mut a, &mut s);
    assert!(r.reussi, "{}", r.raison);
    assert!(!a.fichiers.contains_key(&p));
    assert!(a.notes.is_empty());
    assert_eq!(
        s.faits,
        ["recharger sshd.service", "recharger sshd.service"],
        "{} {:?}",
        r.raison,
        a.journal
    );
}

/// `sshd -t` en échec : le fichier est retiré, rien n'est rechargé, la note part.
#[test]
fn ssh_t_en_echec_rien_recharge() {
    let mut a = faux_ssh().repondre("o");
    regler(&mut a, "permitrootlogin", "yes");
    a.sshd_t = 255;
    // Le dossier de Vanguard déjà là (la note le crée sinon, et il reste) : le compte ci-dessous est exact.
    a.dossier(DOSSIER_VANGUARD, 0o755, 0);
    let avant = a.fichiers.clone();
    let mut s = FauxServices::nouveau();
    let r = faire_avec(Defense::DurcirSsh(ReglageSsh::Root), &mut a, &mut s);
    assert!(!r.reussi);
    assert!(r.raison.contains("sshd a échoué"), "{}", r.raison);
    assert!(s.faits.is_empty(), "{:?}", s.faits);
    assert_eq!(a.fichiers.len(), avant.len());
    assert!(!a.fichiers.contains_key(&fichier_ssh(ReglageSsh::Root)));
    assert!(a.notes.is_empty());
}

/// Un réglage lu avant celui de Vanguard l'emporte : retiré, rien n'est rechargé.
#[test]
fn ssh_sans_effet_retire() {
    let mut a = faux_ssh().repondre("o");
    regler(&mut a, "permitemptypasswords", "yes");
    a.sshd_sans_effet = true;
    let mut s = FauxServices::nouveau();
    let r = faire_avec(Defense::DurcirSsh(ReglageSsh::MotsDePasseVides), &mut a, &mut s);
    assert!(!r.reussi);
    assert!(r.raison.contains("sans effet"), "{}", r.raison);
    assert_eq!(s.faits, Vec::<String>::new());
    assert!(!a.fichiers.contains_key(&fichier_ssh(ReglageSsh::MotsDePasseVides)));
}

/// Depuis une session SSH (ou sans pouvoir dire le contraire) : refusé, sans question, rien d'écrit, quel que soit le
/// réglage.
#[test]
fn ssh_depuis_une_session_ssh_refuse() {
    type Preparer = Box<dyn Fn(&mut FauxServices)>;
    let par_ssh = |distante: bool, service: &str| SessionVue {
        distante,
        service: service.into(),
        groupes_du_meneur: vec!["/user.slice/user-1000.slice/session-2.scope".into()],
    };
    let cas: Vec<Preparer> = vec![
        Box::new(|s| s.lignee = vec!["/system.slice/sshd.service".into()]),
        Box::new(|s| s.lignee = vec!["/system.slice/system-sshd.slice/sshd@3-10.0.0.2:22.service".into()]),
        Box::new(|s| s.lignee = vec!["/system.slice/dropbear.service".into()]),
        Box::new(move |s| s.sessions = Some(vec![par_ssh(true, "")])),
        Box::new(move |s| s.sessions = Some(vec![par_ssh(false, "sshd")])),
        Box::new(|s| s.sessions = None),
        Box::new(|s| s.lignee = Vec::new()),
    ];
    for r in ReglageSsh::TOUS {
        for (i, preparer) in cas.iter().enumerate() {
            let mut a = faux_ssh().repondre("o");
            regler(&mut a, "permitemptypasswords", "yes");
            regler(&mut a, "permitrootlogin", "yes");
            let avant = a.fichiers.clone();
            let mut s = FauxServices::nouveau();
            preparer(&mut s);
            let res = faire_avec(Defense::DurcirSsh(r), &mut a, &mut s);
            assert!(!res.reussi, "{r:?} cas {i}");
            assert!(res.raison.contains("session SSH"), "{r:?} cas {i} : {}", res.raison);
            assert!(a.questions.is_empty(), "{r:?} cas {i}");
            assert_eq!(s.faits, Vec::<String>::new());
            rien_ecrit(&a, &avant);
        }
    }
}

/// Une session locale à côté d'une session SSH d'un autre scope : permis.
#[test]
fn ssh_autre_session_ssh_permise() {
    let mut a = faux_ssh().repondre("o");
    regler(&mut a, "permitemptypasswords", "yes");
    let mut s = FauxServices::nouveau();
    s.sessions = Some(vec![SessionVue {
        distante: true,
        service: "sshd".into(),
        groupes_du_meneur: vec!["/user.slice/user-1001.slice/session-9.scope".into()],
    }]);
    let r = faire_avec(Defense::DurcirSsh(ReglageSsh::MotsDePasseVides), &mut a, &mut s);
    assert!(r.reussi, "{}", r.raison);
}

/// sshd validé mais son rechargement en échec : le fichier est retiré, rien ne reste qui s'appliquerait au prochain
/// lancement de sshd sous un « pas fait ».
#[test]
fn ssh_rechargement_en_echec_retire_le_fichier() {
    let mut a = faux_ssh().repondre("o");
    regler(&mut a, "permitrootlogin", "yes");
    let mut s = FauxServices::nouveau();
    s.recharger_echoue = true;
    let r = faire_avec(Defense::DurcirSsh(ReglageSsh::Root), &mut a, &mut s);
    assert!(!r.reussi);
    assert!(r.raison.contains("délai dépassé"), "{}", r.raison);
    assert!(!a.fichiers.contains_key(&fichier_ssh(ReglageSsh::Root)));
    assert_eq!(s.faits, ["recharger sshd.service"]);
}

/// Couper les mots de passe : seulement si la personne a une clé que sshd accepterait.
#[test]
fn ssh_mots_de_passe_sans_cle_refuse() {
    type Preparer = Box<dyn Fn(&mut Faux)>;
    let cas: Vec<Preparer> = vec![
        Box::new(|a| {
            a.fichiers.remove(Path::new(CLES));
        }),
        // Un fichier vide, ou seulement commenté.
        Box::new(|a| a.fichiers.get_mut(Path::new(CLES)).unwrap().contenu = b"# ssh-ed25519 AAAA\n".to_vec()),
        // Modifiable par un autre compte.
        Box::new(|a| a.fichiers.get_mut(Path::new(CLES)).unwrap().fiche.mode = 0o666),
        // À un autre compte que la personne ou root.
        Box::new(|a| a.fichiers.get_mut(Path::new(CLES)).unwrap().fiche.uid = 1001),
        // Un lien.
        Box::new(|a| {
            a.liens.insert(PathBuf::from(CLES), PathBuf::from("/tmp/cles"));
        }),
        // StrictModes : ~/.ssh ou le dossier personnel ouvert au groupe, ou à un autre compte (sshd refuserait la clé).
        Box::new(|a| a.fichiers.get_mut(Path::new("/home/alice/.ssh")).unwrap().fiche.mode = 0o775),
        Box::new(|a| a.fichiers.get_mut(Path::new("/home/alice")).unwrap().fiche.mode = 0o777),
        Box::new(|a| a.fichiers.get_mut(Path::new("/home/alice/.ssh")).unwrap().fiche.uid = 1001),
        Box::new(|a| {
            a.fichiers.remove(Path::new("/home/alice"));
        }),
        // sshd ne lit pas ce fichier.
        Box::new(|a| regler(a, "authorizedkeysfile", "/etc/ssh/cles/%u")),
        Box::new(|a| regler(a, "authorizedkeysfile", "none")),
        Box::new(|a| regler(a, "pubkeyauthentication", "no")),
        Box::new(|a| regler(a, "authenticationmethods", "publickey,password")),
        // Personne de connu devant l'écran.
        Box::new(|a| a.personnes = Vec::new()),
        // Un compte qui n'est pas dans /etc/passwd.
        Box::new(|a| a.personnes = vec![1000, 4242]),
    ];
    for (i, preparer) in cas.iter().enumerate() {
        let mut a = faux_ssh().repondre("o");
        preparer(&mut a);
        let avant = a.fichiers.clone();
        let mut s = FauxServices::nouveau();
        let r = faire_avec(Defense::DurcirSsh(ReglageSsh::MotsDePasse), &mut a, &mut s);
        assert!(!r.reussi, "cas {i}");
        assert!(a.questions.is_empty(), "cas {i} : {}", r.raison);
        assert_eq!(s.faits, Vec::<String>::new());
        rien_ecrit(&a, &avant);
    }
    // Sans clé : la phrase dit quoi faire.
    let mut a = faux_ssh().repondre("o");
    a.fichiers.remove(Path::new(CLES));
    let r = faire_avec(
        Defense::DurcirSsh(ReglageSsh::MotsDePasse),
        &mut a,
        &mut FauxServices::nouveau(),
    );
    assert!(r.raison.contains("ssh-copy-id"), "{}", r.raison);
    // ~/.ssh ouvert : la phrase nomme le dossier et dit quoi faire.
    let mut a = faux_ssh().repondre("o");
    a.fichiers.get_mut(Path::new("/home/alice/.ssh")).unwrap().fiche.mode = 0o777;
    let r = faire_avec(
        Defense::DurcirSsh(ReglageSsh::MotsDePasse),
        &mut a,
        &mut FauxServices::nouveau(),
    );
    assert!(
        r.raison.contains("/home/alice/.ssh") && r.raison.contains("chmod go-w"),
        "{}",
        r.raison
    );
}

#[test]
fn ssh_mots_de_passe_avec_cle() {
    let mut a = faux_ssh().repondre("o");
    // %h et %u remplis : /home/alice/.ssh/authorized_keys.
    regler(&mut a, "authorizedkeysfile", "%h/.ssh/authorized_keys");
    let mut s = FauxServices::nouveau();
    let r = faire_avec(Defense::DurcirSsh(ReglageSsh::MotsDePasse), &mut a, &mut s);
    assert!(r.reussi, "{}", r.raison);
    assert!(a.questions[0].contains("AVERTISSEMENT"));
    assert_eq!(
        a.fichiers[&fichier_ssh(ReglageSsh::MotsDePasse)].contenu,
        b"PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
    );
    // Déjà fait : rien à changer, sans question.
    let n = a.questions.len();
    a.notes.clear();
    let r = faire_avec(Defense::DurcirSsh(ReglageSsh::MotsDePasse), &mut a, &mut s);
    assert!(r.reussi && r.raison.is_empty(), "{}", r.raison);
    assert_eq!(a.questions.len(), n);
}

#[test]
fn chemin_de_cles_rempli() {
    use super::super::systeme::chemin_de_cles as c;
    assert_eq!(
        c(".ssh/authorized_keys", "alice", 1000, "/home/alice"),
        Some(PathBuf::from("/home/alice/.ssh/authorized_keys"))
    );
    assert_eq!(
        c("/etc/ssh/cles/%u-%U%%", "alice", 1000, "/home/alice"),
        Some(PathBuf::from("/etc/ssh/cles/alice-1000%"))
    );
    assert_eq!(c("/etc/ssh/%i", "alice", 1000, "/home/alice"), None);
    assert_eq!(c("/etc/ssh/%", "alice", 1000, "/home/alice"), None);
}

/// Chaque avertissement du lot : Entrée seule dit non, rien n'est écrit ni lancé.
#[test]
fn avertissements_d7b_entree_dit_non() {
    type Preparer = Box<dyn Fn(&mut Faux)>;
    let cas: Vec<(Defense, Preparer)> = vec![
        (
            Defense::DurcirSsh(ReglageSsh::Root),
            Box::new(|a| regler(a, "permitrootlogin", "yes")),
        ),
        (Defense::DurcirSsh(ReglageSsh::MotsDePasse), Box::new(|_| {})),
        (
            Defense::OublierBluetooth(AdresseBt::lue("00:1A:7D:DA:71:13").unwrap()),
            Box::new(|a| a.bluetooth = Some(info_bt("Clavier", "input-keyboard"))),
        ),
    ];
    for (i, (d, preparer)) in cas.into_iter().enumerate() {
        let mut a = faux_ssh().repondre("");
        a.outils.push("bluetoothctl");
        preparer(&mut a);
        let avant = a.fichiers.clone();
        let mut s = FauxServices::nouveau();
        let r = faire_avec(d, &mut a, &mut s);
        assert!(!r.reussi, "cas {i}");
        assert_eq!(a.questions.len(), 1, "cas {i} : {}", r.raison);
        assert!(a.questions[0].contains("AVERTISSEMENT"), "cas {i} : {}", a.questions[0]);
        assert!(a.questions[0].contains("[o/N] (Entrée seule : non)"), "cas {i}");
        assert_eq!(s.faits, Vec::<String>::new());
        assert!(!a.journal.iter().any(|l| l.contains("remove")), "{:?}", a.journal);
        rien_ecrit(&a, &avant);
    }
}

// ————— BPF —————

fn faux_bpf(valeur: &str) -> Faux {
    let mut a = Faux::nouveau();
    a.outils.push("sysctl");
    a.dossier("/etc/sysctl.d", 0o755, 0);
    a.poser(BPF_FAUX, format!("{valeur}\n").as_bytes(), 0o644);
    a
}

const BPF_DURABLE: &str = "/etc/sysctl.d/90-vanguard-bpf.conf";

#[test]
fn bpf_jusqu_au_redemarrage_puis_defaire() {
    // Oui, puis non à la seconde question : jusqu'au redémarrage seulement.
    let mut a = faux_bpf("0").repondre("o").repondre("");
    let mut s = FauxServices::nouveau();
    let r = faire_avec(Defense::ReserverBpf, &mut a, &mut s);
    assert!(r.reussi, "{}", r.raison);
    assert_eq!(a.questions.len(), 2);
    assert!(a.questions[1].contains("90-vanguard-bpf.conf"));
    assert_eq!(a.texte(BPF_FAUX), "2\n");
    assert!(!a.fichiers.contains_key(Path::new(BPF_DURABLE)));
    let mut a = a.repondre("o");
    let r = defaire(&mut a, &mut s);
    assert!(r.reussi, "{}", r.raison);
    assert_eq!(a.texte(BPF_FAUX), "0\n");
    assert!(a.notes.is_empty());
}

#[test]
fn bpf_garde_apres_redemarrage_puis_defaire() {
    let mut a = faux_bpf("0").repondre("o").repondre("o");
    let mut s = FauxServices::nouveau();
    let r = faire_avec(Defense::ReserverBpf, &mut a, &mut s);
    assert!(r.reussi, "{}", r.raison);
    assert_eq!(a.texte(BPF_FAUX), "2\n");
    assert_eq!(a.texte(BPF_DURABLE), "kernel.unprivileged_bpf_disabled = 2\n");
    assert_eq!(a.mode(BPF_DURABLE), 0o644);
    let mut a = a.repondre("o");
    let r = defaire(&mut a, &mut s);
    assert!(r.reussi, "{}", r.raison);
    assert_eq!(a.texte(BPF_FAUX), "0\n");
    assert!(!a.fichiers.contains_key(Path::new(BPF_DURABLE)));
}

#[test]
fn bpf_deja_ferme_ou_illisible() {
    for v in ["1", "2"] {
        let mut a = faux_bpf(v);
        let r = faire_avec(Defense::ReserverBpf, &mut a, &mut FauxServices::nouveau());
        assert!(r.reussi && a.questions.is_empty(), "{v} : {}", r.raison);
    }
    let mut a = faux_bpf("x").repondre("o");
    let r = faire_avec(Defense::ReserverBpf, &mut a, &mut FauxServices::nouveau());
    assert!(!r.reussi && a.questions.is_empty());
    // Notre fichier changé par un autre : Défaire n'y touche pas.
    let mut a = faux_bpf("0").repondre("o").repondre("o");
    let mut s = FauxServices::nouveau();
    assert!(faire_avec(Defense::ReserverBpf, &mut a, &mut s).reussi);
    a.fichiers.get_mut(Path::new(BPF_DURABLE)).unwrap().contenu = b"kernel.x = 1\n".to_vec();
    let mut a = a.repondre("o");
    let r = defaire(&mut a, &mut s);
    assert!(!r.reussi);
    assert_eq!(a.texte(BPF_FAUX), "2\n");
}

/// /etc/sysctl.d qu'un autre compte peut changer : la seconde question n'est pas posée.
#[test]
fn bpf_sans_dossier_sur_pas_de_seconde_question() {
    let mut a = faux_bpf("0").repondre("o").repondre("o");
    a.fichiers.get_mut(Path::new("/etc/sysctl.d")).unwrap().fiche.mode = 0o777;
    let r = faire_avec(Defense::ReserverBpf, &mut a, &mut FauxServices::nouveau());
    assert!(r.reussi, "{}", r.raison);
    assert_eq!(a.questions.len(), 1);
    assert!(!a.fichiers.contains_key(Path::new(BPF_DURABLE)));
}

// ————— Journal —————

#[test]
fn journal_garde_sur_le_disque() {
    let mut a = Faux::nouveau().repondre("o");
    a.outils.push("journalctl");
    a.dossier("/etc/systemd", 0o755, 0);
    let mut s = FauxServices::nouveau();
    let r = faire_avec(Defense::GarderJournal, &mut a, &mut s);
    assert!(r.reussi, "{}", r.raison);
    assert!(a.questions[0].contains("non annulable"));
    assert_eq!(
        a.texte("/etc/systemd/journald.conf.d/zz-vanguard-persistant.conf"),
        "[Journal]\nStorage=persistent\n"
    );
    assert_eq!(s.faits, ["redemarrer systemd-journald.service"]);
    assert!(a.journal.contains(&"journalctl --flush".to_string()));
    assert!(a.fichiers.contains_key(Path::new("/var/log/journal")));
    // Non annulable : Défaire refuse, rien n'est retiré.
    let mut a = a.repondre("o");
    let r = defaire(&mut a, &mut s);
    assert!(!r.reussi);
    assert!(r.raison.contains("non annulable"), "{}", r.raison);
    assert!(
        a.fichiers
            .contains_key(Path::new("/etc/systemd/journald.conf.d/zz-vanguard-persistant.conf"))
    );
    // Déjà sur le disque : rien à faire.
    let mut b = Faux::nouveau();
    b.dossier("/var/log/journal", 0o2755, 0);
    let r = faire_avec(Defense::GarderJournal, &mut b, &mut FauxServices::nouveau());
    assert!(r.reussi && b.questions.is_empty());
}

// ————— Certificats —————

const ANCRE: &str = "/usr/local/share/ca-certificates/inconnu.crt";

fn faux_ancre(contenu: &[u8]) -> Faux {
    let mut a = Faux::nouveau();
    a.outils.push("update-ca-certificates");
    a.poser(ANCRE, contenu, 0o644);
    a
}

#[test]
fn ancre_illisible_retiree_et_copiee() {
    let contenu = b"-----BEGIN TRUSTED CERTIFICATE-----\nAAAA\n-----END TRUSTED CERTIFICATE-----\n";
    let mut a = faux_ancre(contenu).repondre("o");
    let mut s = FauxServices::nouveau();
    let r = faire_avec(Defense::RetirerAncre(chemin(ANCRE)), &mut a, &mut s);
    assert!(r.reussi, "{}", r.raison);
    assert!(!a.fichiers.contains_key(Path::new(ANCRE)));
    assert!(a.journal.contains(&"update-ca-certificates --fresh".to_string()));
    // La copie entière est dans la note.
    let note = Note::lire(ID, a.notes.values().next().unwrap()).unwrap();
    assert!(note.champs.iter().any(|(k, v)| k == "contenu" && v == contenu));
}

#[test]
fn ancre_refusee() {
    // Un certificat que Vanguard sait lire en entier : jamais retiré de lui-même.
    let mut a = faux_ancre(PEM_ESSAI.as_bytes()).repondre("o");
    let avant = a.fichiers.clone();
    assert!(
        !faire_avec(
            Defense::RetirerAncre(chemin(ANCRE)),
            &mut a,
            &mut FauxServices::nouveau()
        )
        .reussi
    );
    rien_ecrit(&a, &avant);
    // Paquet intact, ou illisible : refusé.
    for etat in [EtatPaquet::Intact("ca-certificates".into()), EtatPaquet::Illisible] {
        let mut a = faux_ancre(b"rien de lisible").repondre("o");
        a.paquets.insert(ANCRE.into(), etat.clone());
        let avant = a.fichiers.clone();
        let r = faire_avec(
            Defense::RetirerAncre(chemin(ANCRE)),
            &mut a,
            &mut FauxServices::nouveau(),
        );
        assert!(!r.reussi, "{etat:?}");
        assert_eq!(a.questions, Vec::<String>::new());
        rien_ecrit(&a, &avant);
    }
    // Sans outil pour refaire la liste : refusé.
    let mut a = faux_ancre(b"rien de lisible").repondre("o");
    a.outils.retain(|o| !o.starts_with("update-ca"));
    assert!(
        !faire_avec(
            Defense::RetirerAncre(chemin(ANCRE)),
            &mut a,
            &mut FauxServices::nouveau()
        )
        .reussi
    );
    // Hors des dossiers d'ancres : la ligne est refusée avant tout.
    let mut a = faux_ancre(b"x").repondre("o");
    a.poser("/etc/passwd.crt", b"x", 0o644);
    assert!(
        !faire_avec(
            Defense::RetirerAncre(chemin("/etc/passwd.crt")),
            &mut a,
            &mut FauxServices::nouveau()
        )
        .reussi
    );
    assert_eq!(a.questions, Vec::<String>::new());
}

/// Certificat autosigné « CN=Vanguard Test CA, O=Vanguard » (celui des essais de `certificats`).
const PEM_ESSAI: &str = "-----BEGIN CERTIFICATE-----
MIIBsTCCAVegAwIBAgIUNk+0eAFwLwngOVYPiSUQLdrH6QAwCgYIKoZIzj0EAwIw
LjEZMBcGA1UEAwwQVmFuZ3VhcmQgVGVzdCBDQTERMA8GA1UECgwIVmFuZ3VhcmQw
HhcNMjYxMDE5MTUzMjQ5WhcNMzYxMDE2MTUzMjQ5WjAuMRkwFwYDVQQDDBBWYW5n
dWFyZCBUZXN0IENBMREwDwYDVQQKDAhWYW5ndWFyZDBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABO6li7wNBvG58cVvUAO8x8MbwLw6+sJSlHQQEF3QihB7tNaTrLHI
1Kjunu34Azac9PL2Vl0qSCQxM6BKoZOLuvajUzBRMB0GA1UdDgQWBBQLNRnjyYUO
MUE4FCSskJprIu4RAzAfBgNVHSMEGDAWgBQLNRnjyYUOMUE4FCSskJprIu4RAzAP
BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIAw1C4ASo9mBvyoQbkIv
zFjhVZCJTZyJMc8UUk87nyaCAiEAwoEfebCe1+tJZhE4ypL4i0uaG6GD06Nd39my
xo1zjuQ=
-----END CERTIFICATE-----
";

// ————— Proxy —————

#[test]
fn proxy_commente() {
    let mut a = Faux::nouveau().repondre("o");
    a.poser(
        "/etc/environment",
        b"PATH=/usr/bin\nexport HTTPS_PROXY=http://10.0.0.1:3128\n",
        0o644,
    );
    let e = empreinte_de_ligne(b"export HTTPS_PROXY=http://10.0.0.1:3128");
    let r = faire_avec(
        Defense::CommenterProxy(e, chemin("/etc/environment")),
        &mut a,
        &mut FauxServices::nouveau(),
    );
    assert!(r.reussi, "{}", r.raison);
    assert_eq!(
        a.texte("/etc/environment"),
        "PATH=/usr/bin\n# Vanguard : export HTTPS_PROXY=http://10.0.0.1:3128\n"
    );
    assert!(a.questions[0].contains("non annulable"));
}

#[test]
fn proxy_autre_ligne_refusee() {
    for ligne in [
        &b"PATH=/usr/bin"[..],
        b"http_proxy_x=1",
        b"no_proxy=localhost",
        b"exporthttp_proxy=1",
    ] {
        let mut a = Faux::nouveau().repondre("o");
        let mut contenu = ligne.to_vec();
        contenu.push(b'\n');
        a.poser("/etc/environment", &contenu, 0o644);
        let avant = a.fichiers.clone();
        let r = faire_avec(
            Defense::CommenterProxy(empreinte_de_ligne(ligne), chemin("/etc/environment")),
            &mut a,
            &mut FauxServices::nouveau(),
        );
        assert!(!r.reussi, "{}", String::from_utf8_lossy(ligne));
        assert_eq!(a.questions, Vec::<String>::new());
        rien_ecrit(&a, &avant);
    }
    for ligne in [
        "http_proxy=x",
        "export ftp_proxy=x",
        "ALL_PROXY=x",
        "\texport\thttps_proxy=x",
    ] {
        assert!(super::super::systeme::ligne_de_proxy(ligne.as_bytes()), "{ligne}");
    }
}

// ————— Bluetooth —————

fn info_bt(nom: &str, icone: &str) -> String {
    format!(
        "Device 00:1A:7D:DA:71:13 (public)\n\tName: {nom}\n\tAlias: {nom}\n\tIcon: {icone}\n\tPaired: yes\n\tConnected: no\n"
    )
}

fn bt() -> Defense {
    Defense::OublierBluetooth(AdresseBt::lue("00:1A:7D:DA:71:13").unwrap())
}

fn faux_bt(info: String) -> Faux {
    let mut a = Faux::nouveau();
    a.outils.push("bluetoothctl");
    a.bluetooth = Some(info);
    a
}

#[test]
fn bluetooth_oublie() {
    let mut a = faux_bt(info_bt("Casque Salon", "audio-headset")).repondre("o");
    let mut s = FauxServices::nouveau();
    let r = faire_avec(bt(), &mut a, &mut s);
    assert!(r.reussi, "{}", r.raison);
    assert_eq!(a.questions.len(), 1);
    assert!(a.questions[0].contains("re-jumeler"));
    assert!(a.questions[0].contains("non annulable"));
    assert!(a.journal.contains(&"bluetoothctl remove 00:1A:7D:DA:71:13".to_string()));
    // Inconnu : rien à faire.
    let mut b = Faux::nouveau();
    b.outils.push("bluetoothctl");
    assert!(faire_avec(bt(), &mut b, &mut s).reussi);
    assert_eq!(b.questions, Vec::<String>::new());
}

/// Un clavier ou une souris : un second oui exigé ; non à la seconde question, rien n'est oublié.
#[test]
fn bluetooth_clavier_second_oui() {
    for (icone, classe) in [
        ("input-keyboard", ""),
        ("", "\tClass: 0x00002580\n"),
        ("input-mouse", ""),
    ] {
        let info = info_bt("Clavier", icone) + classe;
        let mut a = faux_bt(info.clone()).repondre("o").repondre("");
        let r = faire_avec(bt(), &mut a, &mut FauxServices::nouveau());
        assert!(!r.reussi, "{icone}{classe}");
        assert_eq!(a.questions.len(), 2);
        assert!(!a.journal.iter().any(|l| l.contains("remove")));
        assert!(a.notes.is_empty());
        let mut a = faux_bt(info).repondre("o").repondre("o");
        assert!(faire_avec(bt(), &mut a, &mut FauxServices::nouveau()).reussi);
        assert!(a.journal.iter().any(|l| l.contains("remove")));
    }
}

/// Un nom piégé (saut de ligne, échappement du terminal, retour chariot, très long) : montré échappé.
#[test]
fn bluetooth_nom_piege_echappe() {
    let nom = format!("Casque\x1b[2J\r\x07{}", "A".repeat(500));
    let mut a = faux_bt(info_bt(&nom, "audio-headset")).repondre("");
    let _ = faire_avec(bt(), &mut a, &mut FauxServices::nouveau());
    let q = &a.questions[0];
    assert!(!q.contains('\x1b') && !q.contains('\r') && !q.contains('\x07'), "{q:?}");
    assert!(q.contains("Casque\\x1b[2J\\x0d\\x07"), "{q}");
    assert!(!q.contains(&"A".repeat(100)));
}

/// bluetoothctl qui répond pour un autre appareil, ou sans le service : refusé.
#[test]
fn bluetooth_refuse() {
    let mut a = faux_bt(info_bt("x", "").replace("00:1A:7D:DA:71:13", "00:1A:7D:DA:71:14")).repondre("o");
    assert!(!faire_avec(bt(), &mut a, &mut FauxServices::nouveau()).reussi);
    assert_eq!(a.questions, Vec::<String>::new());
    let mut a = faux_bt(info_bt("x", "")).repondre("o");
    let mut s = FauxServices::nouveau();
    s.activite = "inactive".into();
    assert!(!faire_avec(bt(), &mut a, &mut s).reussi);
    assert_eq!(a.questions, Vec::<String>::new());
}

// ————— Arrêt d'un programme —————

fn vue(nom: &str) -> VueProcessus {
    VueProcessus {
        debut: 123_456,
        tgid: 4242,
        nom: nom.into(),
        exe: Some("/tmp/.x/mineur (deleted)".into()),
        uid: 1000,
        noyau: false,
        zombie: false,
    }
}

fn faux_programme(v: VueProcessus) -> Faux {
    let mut a = Faux::nouveau();
    a.processus.insert(4242, v);
    a.soupcons
        .insert(4242, "effacé d'un dossier temporaire après son lancement".into());
    a
}

const ARRET: Defense = Defense::ArreterProgramme(4242, 123_456);

#[test]
fn arret_traces_d_abord() {
    let mut a = faux_programme(vue("mineur")).repondre("o");
    let r = faire_avec(ARRET, &mut a, &mut FauxServices::nouveau());
    assert!(r.reussi, "{}", r.raison);
    let t = a.journal.iter().position(|l| l == "traces 4242").unwrap();
    let s = a.journal.iter().position(|l| l == "arreter 4242").unwrap();
    assert!(t < s, "{:?}", a.journal);
    assert!(a.questions[0].contains("/var/lib/vanguard/traces/4242-123456"));
    assert!(a.questions[0].contains("non annulable"));
}

#[test]
fn arret_refuse() {
    type Preparer = Box<dyn Fn(&mut Faux)>;
    let cas: Vec<Preparer> = vec![
        // Rien de suspect relu par root : une ligne forgée ne suffit pas.
        Box::new(|a| {
            a.soupcons.clear();
        }),
        // Une garde le retient (vital, Vanguard lui-même, programme du système).
        Box::new(|a| {
            a.gardes.insert(4242, "processus critique du système".into());
        }),
        // Un fil du noyau : le conseil de réinstaller, rien de fait.
        Box::new(|a| a.processus.get_mut(&4242).unwrap().noyau = true),
        // Un fil d'un autre programme.
        Box::new(|a| a.processus.get_mut(&4242).unwrap().tgid = 4000),
        // Programme illisible.
        Box::new(|a| a.processus.get_mut(&4242).unwrap().exe = None),
    ];
    for (i, preparer) in cas.iter().enumerate() {
        let mut a = faux_programme(vue("mineur")).repondre("o");
        preparer(&mut a);
        let r = faire_avec(ARRET, &mut a, &mut FauxServices::nouveau());
        assert!(!r.reussi, "cas {i}");
        assert!(a.questions.is_empty(), "cas {i}");
        assert!(a.journal.is_empty(), "cas {i} : {:?}", a.journal);
        assert!(a.notes.is_empty());
        if i == 2 {
            assert!(r.raison.contains("réinstallez"), "{}", r.raison);
        }
    }
    // Entrée seule : non, rien de copié ni d'arrêté.
    let mut a = faux_programme(vue("mineur")).repondre("");
    assert!(!faire_avec(ARRET, &mut a, &mut FauxServices::nouveau()).reussi);
    assert_eq!(a.journal, Vec::<String>::new());
}

/// Changé entre la copie de ses traces et l'arrêt (son numéro repris) : les traces restent, rien n'est arrêté.
#[test]
fn arret_change_pendant_les_traces() {
    let mut a = faux_programme(vue("mineur")).repondre("o");
    a.change_pendant_traces = true;
    let r = faire_avec(ARRET, &mut a, &mut FauxServices::nouveau());
    assert!(!r.reussi);
    assert!(r.raison.contains("pendant la copie"), "{}", r.raison);
    assert_eq!(a.journal, ["traces 4242"]);
    assert!(a.processus.contains_key(&4242));
}

/// Parti, ou son numéro repris par un autre programme (autre naissance), ou zombie : rien à faire, sans question.
#[test]
fn arret_deja_parti() {
    for preparer in [
        |a: &mut Faux| {
            a.processus.clear();
        },
        |a: &mut Faux| a.processus.get_mut(&4242).unwrap().debut = 999,
        |a: &mut Faux| a.processus.get_mut(&4242).unwrap().zombie = true,
    ] {
        let mut a = faux_programme(vue("mineur")).repondre("o");
        preparer(&mut a);
        let r = faire_avec(ARRET, &mut a, &mut FauxServices::nouveau());
        assert!(r.reussi, "{}", r.raison);
        assert_eq!(a.questions, Vec::<String>::new());
        assert_eq!(a.journal, Vec::<String>::new());
    }
}

#[test]
fn arret_nom_piege_echappe() {
    let mut v = vue(&format!("x\ny\x1b]0;t\x07\r{}", "B".repeat(300)));
    v.exe = Some("/tmp/\x1b[8mcache (deleted)".into());
    let mut a = faux_programme(v).repondre("");
    let _ = faire_avec(ARRET, &mut a, &mut FauxServices::nouveau());
    let q = &a.questions[0];
    assert!(!q.contains('\x1b') && !q.contains('\r') && !q.contains('\x07'), "{q:?}");
    assert!(q.contains("x\\x0ay"), "{q}");
    assert!(!q.contains(&"B".repeat(200)));
}

#[test]
fn naissance_lue_du_stat() {
    // Un nom qui contient « ) » et des espaces : lu après la dernière parenthèse.
    let stat =
        "4242 (a) b (c)) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 123456 1000 10 18446744073709551615";
    assert_eq!(naissance_du_stat(stat), Some(('S', 4_194_560, 123_456)));
    // Un fil du noyau (PF_KTHREAD).
    let noyau = "2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 3 0 0 18446744073709551615";
    let (_, drapeaux, _) = naissance_du_stat(noyau).unwrap();
    assert!(drapeaux & 0x0020_0000 != 0);
    assert_eq!(naissance_du_stat("4242 (court) S 1"), None);
    assert_eq!(naissance_du_stat("sans parenthèse"), None);
}

// ————— « Refaire » : un programme de tâche remis par un programme signé —————

const POSE: &str = "/usr/local/bin/vanguard";
const SIGNE: &[u8] = b"vanguard 0.89.1 publie et signe";
const IMPOSTEUR: &[u8] = b"vanguard change hors de Vanguard";

fn sha(o: &[u8]) -> [u8; 32] {
    Sha256::digest(o).into()
}

fn quarantaine() -> PathBuf {
    PathBuf::from(format!(
        "/var/lib/vanguard/quarantaine/{}-vanguard",
        gestes_unix::hex(&sha(IMPOSTEUR)[..8])
    ))
}

/// /usr/local/bin/vanguard remplacé par un imposteur ; l'historique signé connaît la 0.89.1, et elle se reçoit.
fn faux_pose() -> Faux {
    let mut a = Faux::nouveau();
    for d in ["/", "/usr", "/usr/local", "/usr/local/bin", "/var", "/var/lib"] {
        a.dossier(d, 0o755, 0);
    }
    a.poser(POSE, IMPOSTEUR, 0o755);
    a.fichiers.get_mut(Path::new(POSE)).unwrap().fiche.taille = IMPOSTEUR.len() as u64;
    a.historique = Some([(sha(SIGNE), "0.89.1".to_string())].into());
    a.signe = Some(("0.89.1".into(), SIGNE.to_vec()));
    a
}

fn remise() -> Defense {
    Defense::RemettreProgramme(chemin(POSE))
}

#[test]
fn programme_remis_imposteur_en_quarantaine() {
    let mut a = faux_pose().repondre("o");
    a.fichiers.get_mut(Path::new(POSE)).unwrap().caps = Some(vec![1, 2, 3, 4]);
    let r = faire_avec(remise(), &mut a, &mut FauxServices::nouveau());
    assert!(r.reussi, "{}", r.raison);
    let q = quarantaine();
    // L'imposteur copié d'abord, à root, lisible par root seul, jamais effacé ; puis le programme signé posé.
    assert_eq!(a.fichiers[&q].contenu, IMPOSTEUR);
    assert_eq!(a.fichiers[&q].fiche.mode, 0o400);
    assert_eq!(a.fichiers[Path::new(POSE)].contenu, SIGNE);
    assert_eq!(a.fichiers[Path::new(POSE)].fiche.mode, 0o755);
    assert_eq!(a.fichiers[Path::new(POSE)].fiche.uid, 0);
    let copie = a
        .journal
        .iter()
        .position(|l| l == &format!("ecrire {}", q.display()))
        .unwrap();
    let posee = a.journal.iter().position(|l| l == &format!("ecrire {POSE}")).unwrap();
    assert!(copie < posee, "{:?}", a.journal);
    assert_eq!(a.fichiers[Path::new("/var/lib/vanguard/quarantaine")].fiche.mode, 0o700);
    let question = &a.questions[0];
    assert!(question.contains("non annulable"), "{question}");
    assert!(question.contains(&gestes_unix::hex(&sha(IMPOSTEUR))), "{question}");
    assert!(question.contains("Ed25519"), "{question}");
    assert!(question.contains("compte d'uid 0, mode 755"), "{question}");
    assert_eq!(a.notes.len(), 1);
    // Relecture : ses capacités notées (la copie en quarantaine ne les garde pas), avec mode et propriétaire.
    let note = Note::lire(a.notes.keys().next().unwrap(), a.notes.values().next().unwrap()).unwrap();
    let champ = |k: &str| note.champs.iter().find(|(c, _)| c == k).map(|(_, v)| v.clone());
    assert_eq!(champ("capacites").as_deref(), Some(&b"01020304"[..]));
    assert_eq!(champ("mode").as_deref(), Some(&b"493"[..]));
    // Non annulable : Défaire refuse, rien ne revient.
    let mut a = a.repondre("o");
    assert!(!defaire(&mut a, &mut FauxServices::nouveau()).reussi);
    assert_eq!(a.fichiers[Path::new(POSE)].contenu, SIGNE);
}

#[test]
fn programme_remis_entree_dit_non() {
    let mut a = faux_pose().repondre("");
    let avant = a.fichiers.clone();
    let r = faire_avec(remise(), &mut a, &mut FauxServices::nouveau());
    assert!(!r.reussi);
    assert_eq!(a.questions.len(), 1);
    rien_ecrit(&a, &avant);
    assert!(!a.journal.iter().any(|l| l.starts_with("recevoir")), "{:?}", a.journal);
    assert_eq!(a.fichiers[Path::new(POSE)].contenu, IMPOSTEUR);
}

/// Déjà une version publiée et signée : rien à faire, sans question.
#[test]
fn programme_deja_signe() {
    let mut a = faux_pose().repondre("o");
    a.fichiers.get_mut(Path::new(POSE)).unwrap().contenu = SIGNE.to_vec();
    let r = faire_avec(remise(), &mut a, &mut FauxServices::nouveau());
    assert!(r.reussi, "{}", r.raison);
    assert_eq!(a.questions, Vec::<String>::new());
    assert!(a.journal.is_empty(), "{:?}", a.journal);
}

/// Chaque garde avant la question : refusé, rien demandé, rien écrit.
#[test]
fn programme_remis_refuse_avant_la_question() {
    type Preparer = Box<dyn Fn(&mut Faux)>;
    let cas: Vec<(&str, Preparer)> = vec![
        // Un dossier au-dessus modifiable par un autre compte, ou d'un autre compte.
        (
            "/usr/local/bin",
            Box::new(|a| a.fichiers.get_mut(Path::new("/usr/local/bin")).unwrap().fiche.mode = 0o777),
        ),
        (
            "/usr/local",
            Box::new(|a| a.fichiers.get_mut(Path::new("/usr/local")).unwrap().fiche.uid = 1000),
        ),
        // Un lien sur le chemin : jamais suivi.
        (
            "lien",
            Box::new(|a| {
                a.liens.insert(PathBuf::from(POSE), PathBuf::from("/etc/shadow"));
            }),
        ),
        // Un fichier d'un paquet : se réinstalle par son paquet.
        (
            "paquet",
            Box::new(|a| {
                a.paquets
                    .insert(PathBuf::from(POSE), EtatPaquet::Modifie("vanguard".into()));
            }),
        ),
        (
            "le gestionnaire",
            Box::new(|a| {
                a.paquets.insert(PathBuf::from(POSE), EtatPaquet::Illisible);
            }),
        ),
        // L'historique signé ne se lit pas (pas d'Internet) : rien n'est cru, l'erreur échappée.
        ("historique", Box::new(|a| a.historique = None)),
        // Trop grand pour être gardé en quarantaine.
        (
            "trop grand",
            Box::new(|a| a.fichiers.get_mut(Path::new(POSE)).unwrap().fiche.taille = u64::MAX),
        ),
        // Une copie en quarantaine au même nom, qui n'est pas la sienne.
        (
            "existe déjà",
            Box::new(|a| {
                a.dossier("/var/lib/vanguard", 0o755, 0);
                a.dossier("/var/lib/vanguard/quarantaine", 0o700, 0);
                a.poser(&quarantaine().to_string_lossy(), b"autre", 0o400);
            }),
        ),
        // Le dossier de quarantaine ouvert aux autres.
        (
            "quarantaine",
            Box::new(|a| {
                a.dossier("/var/lib/vanguard", 0o755, 0);
                a.dossier("/var/lib/vanguard/quarantaine", 0o755, 0);
            }),
        ),
    ];
    for (attendu, preparer) in &cas {
        let mut a = faux_pose().repondre("o");
        preparer(&mut a);
        let avant = a.fichiers.clone();
        let r = faire_avec(remise(), &mut a, &mut FauxServices::nouveau());
        assert!(!r.reussi, "{attendu}");
        assert!(r.raison.contains(attendu), "{attendu} : {}", r.raison);
        assert!(!r.raison.contains('\x1b'), "{:?}", r.raison);
        assert!(a.questions.is_empty(), "{attendu}");
        rien_ecrit(&a, &avant);
    }
}

/// Après le oui : le programme reçu n'est pas dans l'historique signé, ou ne se reçoit pas, ou l'imposteur a changé
/// pendant la question : rien n'est remplacé, l'imposteur reste où il est.
#[test]
fn programme_remis_refuse_apres_le_oui() {
    type Preparer = Box<dyn Fn(&mut Faux)>;
    let cas: Vec<(&str, Preparer)> = vec![
        (
            "historique signé",
            Box::new(|a| a.signe = Some(("0.89.1".into(), b"autre programme".to_vec()))),
        ),
        // Une version annoncée qui n'est pas celle que l'historique donne à ces octets.
        (
            "historique signé",
            Box::new(|a| a.signe = Some(("0.99.0".into(), SIGNE.to_vec()))),
        ),
        ("ne se reçoit pas", Box::new(|a| a.signe = None)),
        (
            "",
            Box::new(|a| a.pendant_la_question = Some((PathBuf::from(POSE), b"encore un autre".to_vec()))),
        ),
    ];
    for (attendu, preparer) in &cas {
        let mut a = faux_pose().repondre("o");
        preparer(&mut a);
        let r = faire_avec(remise(), &mut a, &mut FauxServices::nouveau());
        assert!(!r.reussi, "{attendu}");
        assert!(r.raison.contains(attendu), "{attendu} : {}", r.raison);
        assert!(
            !a.journal.iter().any(|l| l == &format!("ecrire {POSE}")),
            "{:?}",
            a.journal
        );
        assert!(!a.fichiers.contains_key(&quarantaine()), "{attendu}");
        assert_ne!(a.fichiers[Path::new(POSE)].contenu, SIGNE);
    }
}

/// Un chemin piégé (saut de ligne, échappement du terminal) dans un dossier admis : montré échappé par le fils.
#[test]
fn programme_remis_chemin_piege_echappe() {
    let piege = "/opt/x\n\x1b[31m\r/vanguard";
    let mut a = faux_pose().repondre("");
    a.dossier("/opt", 0o755, 0);
    a.dossier("/opt/x\n\x1b[31m\r", 0o755, 0);
    a.poser(piege, IMPOSTEUR, 0o755);
    let _ = faire_avec(
        Defense::RemettreProgramme(chemin(piege)),
        &mut a,
        &mut FauxServices::nouveau(),
    );
    let q = &a.questions[0];
    assert!(!q.contains('\x1b') && !q.contains('\r'), "{q:?}");
    assert!(q.contains("/opt/x\\x0a"), "{q}");
}

/// Une ligne qui désigne un autre programme, ou un programme dans le dossier d'un compte : refusée par le fils avant
/// tout jugement.
#[test]
fn programme_remis_ligne_hors_garde_refusee() {
    for p in [
        "/usr/bin/passwd",
        "/home/alice/.local/share/vanguard/bin/vanguard",
        "/tmp/vanguard",
    ] {
        let mut a = faux_pose().repondre("o");
        a.poser(p, IMPOSTEUR, 0o755);
        let avant = a.fichiers.clone();
        let r = faire_avec(
            Defense::RemettreProgramme(chemin(p)),
            &mut a,
            &mut FauxServices::nouveau(),
        );
        assert!(!r.reussi, "{p}");
        assert!(r.raison.contains("son propre programme"), "{}", r.raison);
        assert_eq!(a.questions, Vec::<String>::new());
        rien_ecrit(&a, &avant);
    }
}

/// Relecture : une empreinte trouvée dans l'historique signé le reste le temps du geste (Internet qui tombe après le
/// remplacement ne fait pas dire « pas fait ») ; un échec ne se garde pas, il se redemande.
#[test]
fn historique_garde_le_temps_du_geste() {
    let m = std::cell::RefCell::default();
    let e = [7u8; 32];
    let coupe = || Err(echoue("pas d'Internet"));
    assert!(de_memoire(&m, &e, coupe).is_err());
    assert_eq!(
        de_memoire(&m, &e, || Ok(Some("0.89.1".into()))),
        Ok(Some("0.89.1".into()))
    );
    assert_eq!(de_memoire(&m, &e, coupe), Ok(Some("0.89.1".into())));
    assert_eq!(de_memoire(&m, &[8; 32], || Ok(None)), Ok(None));
    assert_eq!(de_memoire(&m, &[8; 32], coupe), Ok(None));
}

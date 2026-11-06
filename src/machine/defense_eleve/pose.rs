//! Lot D7b, « Refaire » (`programmes_poses`) : le programme d'une tâche de Vanguard, remplacé hors de Vanguard par un
//! programme qui n'est pas une version publiée et signée, remis par un programme publié et signé par l'auteur. Root
//! relit tout : le chemin (aucun lien, chaque dossier à root et fermé aux autres comptes), le paquet (un fichier
//! d'un paquet se réinstalle par son paquet), l'empreinte cherchée dans l'historique signé des versions (Ed25519).
//! Celui qui y est est copié d'abord en quarantaine (/var/lib/vanguard/quarantaine, à root, fermé aux autres), jamais
//! effacé ; le programme remis est revérifié dans l'historique signé juste avant d'être posé. Non annulable : remettre
//! un programme qui n'est pas celui de l'auteur ne se propose pas.

use super::*;
use programme::PROGRAMME_MAX;

/// Les programmes mis de côté, à root, fermé aux autres.
pub(super) const QUARANTAINE: &str = "/var/lib/vanguard/quarantaine";

fn hex(octets: &[u8]) -> String {
    gestes_unix::hex(octets)
}

/// Chaque dossier au-dessus de `p` : un dossier (pas un lien), à root, que ni le groupe ni les autres ne modifient.
/// Sinon un compte sans droits pourrait remplacer le programme remis, ou détourner son écriture.
fn dossiers_de_root(p: &Path, vu: &str, a: &dyn Acces) -> Result<(), Echec> {
    for d in p.ancestors().skip(1) {
        let sur = a
            .fiche(d)
            .is_some_and(|f| f.genre == Genre::Dossier && f.uid == 0 && f.mode & 0o022 == 0);
        if !sur {
            return Err(refus(trf!(
                "{} (au-dessus de {vu}) n'est pas un dossier de root fermé aux autres comptes : un autre compte pourrait changer ce programme, root n'y écrit pas. Refaites plutôt la tâche depuis Vanguard",
                "{} (above {vu}) is not a root folder closed to other accounts: another account could change this program, root does not write there. Redo the task from Vanguard instead",
                lisible(d)
            )));
        }
    }
    Ok(())
}

/// Le dossier `d` de Vanguard : à créer (`true`), ou déjà là, à root et fermé (`ferme`) ; sinon refusé.
fn a_creer(d: &str, ferme: u32, a: &dyn Acces) -> Result<bool, Echec> {
    match a.fiche(Path::new(d)) {
        None => Ok(true),
        Some(f) if f.genre == Genre::Dossier && f.uid == 0 && f.mode & ferme == 0 => Ok(false),
        Some(_) => Err(refus(trf!(
            "{d} n'est pas un dossier de root fermé aux autres comptes : rien n'est fait",
            "{d} is not a root folder closed to other accounts: nothing is done"
        ))),
    }
}

fn pas_lisible(x: &Echec) -> Echec {
    refus(trf!(
        "l'historique signé des versions ne dit pas si ce programme est publié ({}) : rien n'est fait",
        "the signed version history does not tell whether this program is published ({}): nothing is done",
        echappe(x.to_string().as_bytes())
    ))
}

pub(super) fn juger_remise(c: &CheminDesigne, a: &mut dyn Acces) -> Jugement {
    let p = chemin_de(c);
    let vu = lisible(&p);
    let f = fiche_designee(&p, Genre::Fichier, a)?;
    dossiers_de_root(&p, &vu, a)?;
    match a.paquet(&p) {
        EtatPaquet::Aucun => {}
        EtatPaquet::Intact(n) | EtatPaquet::Modifie(n) => {
            let n = echappe(n.as_bytes());
            return Err(refus(trf!(
                "{vu} vient du paquet {n} : réinstallez ce paquet avec le gestionnaire de paquets du système, Vanguard n'y touche pas",
                "{vu} comes from the package {n}: reinstall that package with the system's package manager, Vanguard does not touch it"
            )));
        }
        EtatPaquet::Illisible => {
            return Err(refus(trf!(
                "le gestionnaire de paquets ne dit pas d'où vient {vu} : rien n'est fait",
                "the package manager does not say where {vu} comes from: nothing is done"
            )));
        }
    }
    if usize::try_from(f.taille).map_or(true, |t| t > PROGRAMME_MAX) {
        return Err(refus(trf!(
            "{vu} est trop grand pour être gardé en quarantaine : rien n'est fait",
            "{vu} is too large to be kept in quarantine: nothing is done"
        )));
    }
    let e = a.empreinte(&p, &f).ok_or_else(|| change_depuis(&vu))?;
    // Déjà une version publiée et signée : il n'y a rien à remettre.
    if a.version_signee(&e).map_err(|x| pas_lisible(&x))?.is_some() {
        return Ok(None);
    }
    let nom = p.file_name().map(|n| echappe(n.as_bytes())).unwrap_or_default();
    let q = PathBuf::from(format!("{QUARANTAINE}/{}-{nom}", hex(e.get(..8).unwrap_or_default())));
    let mut actions = Vec::new();
    // /var/lib/vanguard : relu s'il est là ; sinon la note d'« avant », écrite avant le geste, le crée (le créer ici
    // échouerait alors, il existerait déjà).
    a_creer(DOSSIER_VANGUARD, 0o022, a)?;
    if a_creer(QUARANTAINE, 0o077, a)? {
        actions.push(Action::CreerDossier(PathBuf::from(QUARANTAINE), 0o700));
    }
    let copier = match a.fiche(&q) {
        None => true,
        Some(g) if g.genre == Genre::Fichier && g.uid == 0 && a.empreinte(&q, &g) == Some(e) => false,
        Some(_) => {
            return Err(refus(trf!(
                "{} existe déjà et n'est pas la copie de ce programme : rien n'est fait",
                "{} already exists and is not the copy of this program: nothing is done",
                lisible(&q)
            )));
        }
    };
    let empreinte = hex(&e);
    let mis = lisible(&q);
    let taille = f.taille;
    let (uid, mode) = (f.uid, f.mode & 0o7777);
    // Ses capacités notées avec le reste : la copie en quarantaine ne les garde pas, et elles disent ce qu'il visait.
    let capacites = match a.capacites(&p, &f) {
        Ok(Some(c)) => hex(&c),
        Ok(None) => "aucune".to_string(),
        Err(()) => "illisible".to_string(),
    };
    actions.push(Action::RemettreProgramme {
        chemin: p.clone(),
        fiche: f,
        empreinte: e,
        quarantaine: q,
        copier,
    });
    Ok(Some(Plan {
        texte: trf!(
            "Programme d'une tâche de Vanguard : {vu} ({taille} octets, empreinte {empreinte}, compte d'uid {uid}, mode {mode:o}).\nCe n'est pas une version publiée et signée par l'auteur (l'historique signé des versions vient d'être relu).\nIl est copié d'abord dans {mis}, lisible par root seulement, et jamais effacé par Vanguard (examinez-le, ou effacez-le vous-même) ; son mode, son propriétaire et ses capacités sont notés. Puis il est remplacé par le programme de Vanguard publié et signé : ce Vanguard-ci s'il est une version publiée, sinon la dernière version publiée, téléchargée, sa signature Ed25519 vérifiée, jamais plus vieille que ce Vanguard-ci.\nUn programme déjà lancé depuis ce fichier continue de tourner : redémarrez l'ordinateur ensuite.",
            "Program of a Vanguard task: {vu} ({taille} bytes, fingerprint {empreinte}, account uid {uid}, mode {mode:o}).\nIt is not a version published and signed by the author (the signed version history was just read again).\nIt is copied first into {mis}, readable by root only, and never deleted by Vanguard (examine it, or delete it yourself); its mode, owner and capabilities are noted. Then it is replaced by the Vanguard program published and signed: this Vanguard if it is a published version, otherwise the latest published version, downloaded, its Ed25519 signature checked, never older than this Vanguard.\nA program already started from this file keeps running: restart the computer afterwards."
        ),
        avertissement: None,
        non_annulable: true,
        seconde: None,
        champs: vec![
            ("chemin".into(), c.octets().to_vec()),
            ("empreinte".into(), empreinte.into_bytes()),
            ("quarantaine".into(), mis.into_bytes()),
            ("mode".into(), f.mode.to_string().into_bytes()),
            ("uid".into(), f.uid.to_string().into_bytes()),
            ("gid".into(), f.gid.to_string().into_bytes()),
            ("capacites".into(), capacites.into_bytes()),
        ],
        action: Action::Suite(actions),
    }))
}

/// Remet le programme signé à `p`, s'il est encore celui qui a été vu (`f`, `e`) : le programme reçu, revérifié dans
/// l'historique signé ; celui qui y est copié d'abord en quarantaine (`q`) ; puis remplacé d'un coup.
pub(super) fn remettre(
    p: &Path,
    f: &Fiche,
    e: &[u8; 32],
    q: &Path,
    copier: bool,
    a: &mut dyn Acces,
) -> Result<(), Echec> {
    let (version, octets) = a.programme_signe().map_err(|x| {
        refus(trf!(
            "le programme publié et signé ne se reçoit pas ({}) : rien n'est remplacé",
            "the published and signed program cannot be received ({}): nothing is replaced",
            echappe(x.to_string().as_bytes())
        ))
    })?;
    let recu: [u8; 32] = Sha256::digest(&octets).into();
    match a.version_signee(&recu) {
        Ok(Some(v)) if v == version => {}
        Ok(_) => {
            return Err(refus(
                tr!(
                    "le programme reçu n'est pas dans l'historique signé des versions : rien n'est remplacé",
                    "the received program is not in the signed version history: nothing is replaced"
                )
                .to_string(),
            ));
        }
        Err(x) => return Err(pas_lisible(&x)),
    }
    let meme = a.fiche(p).is_some_and(|g| meme_fichier(&g, f)) && a.empreinte(p, f).as_ref() == Some(e);
    if !meme {
        return Err(refus(change_pendant_la_question()));
    }
    if copier {
        let lu = a
            .lire(p, PROGRAMME_MAX)
            .filter(|lu| Sha256::digest(lu)[..] == e[..])
            .ok_or_else(|| refus(change_pendant_la_question()))?;
        a.ecrire(
            q,
            &lu,
            Ecriture {
                mode: 0o400,
                uid: 0,
                gid: 0,
                avant: None,
            },
        )?;
    }
    a.ecrire(
        p,
        &octets,
        Ecriture {
            mode: 0o755,
            uid: 0,
            gid: 0,
            avant: Some(*f),
        },
    )
}

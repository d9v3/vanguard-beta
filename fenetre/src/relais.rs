//! Le relais (Linux) : la séparation des droits de la fenêtre. Au démarrage, avant tout fil et toute bibliothèque
//! d'affichage, la fenêtre se dédouble (fork) : l'enfant, le relais, garde les droits du compte et lance `vanguard` ;
//! la fenêtre se met dans son bac à sable (`bac_a_sable`) et ne fait plus que lui demander, par une socket, une
//! commande de la liste fermée, par son numéro, ou un changement au démarrage, par sa sorte et l'empreinte du
//! programme avec l'accord que la liste a donné (16 et 32 octets : le relais n'en fait que `demarrage
//! --retirer|--remettre <hex> --accord <hex> --json`, et c'est
//! `vanguard` qui la cherche parmi ce qu'il voit, puis demande les droits). `vanguard` part ainsi du relais et n'hérite pas du bac : il voit tout
//! ce qu'il doit voir (les programmes en cours, le bus système, sudo).
//!
//! Le relais ne fait confiance à rien de ce que dit la fenêtre (c'est elle qu'on protège de ce qu'elle dessine) : une
//! demande est un numéro de la liste fermée, une lecture de cette liste avec sa seule valeur (rejugée ici en entier,
//! un fichier sur son chemin réel, sous les endroits permis du compte : `rejuger`), un changement de forme fermée,
//! la langue, ou un arrêt ; rien d'autre n'est compris, et une demande
//! hors de ce protocole l'arrête. Il retrouve lui-même le `vanguard` voisin et rejoue sa garde (`lanceur`). Il ne
//! se laisse pas observer (PR_SET_DUMPABLE à 0 : ni ptrace ni /proc/<pid>/mem du même compte), et Landlock empêche
//! de toute façon la fenêtre d'observer ce qui est hors de son bac. Quand la fenêtre se ferme ou meurt, la socket se
//! ferme : le relais arrête les lectures qui tournent, laisse finir un changement commencé, et s'en va. Le protocole,
//! sans rien d'autre, est dans `protocole`.
//!
//! Un changement, côté relais (ce qui tient même si la fenêtre est prise) : il passe seul (refusé tant qu'une
//! commande tourne ; rien d'autre ne se lance pendant lui) ; seulement pour un geste vu dans la dernière liste du
//! démarrage que le relais a lui-même relayée (`demarrage --json`), la même empreinte avec la même sorte (« retirer »
//! un programme que la liste offrait de remettre est refusé) et le même accord (M-2 : la fenêtre ne le choisit pas),
//! et cette liste ne sert qu'une fois ; « Arrêter »
//! ne le coupe pas, la fermeture de la fenêtre non plus : coupé au milieu, il pourrait laisser un programme retiré sans
//! la note qui le remet. Seul son délai (`Lancement::delai`) l'arrête.
//!
//! Un geste (`Lancement::Geste`) va par familles : les corrections du bilan, les annulations de « Ce que Vanguard a
//! changé », et la mise à jour de Vanguard (la carte « Mettre à jour Vanguard »). Les deux premières ont leur liste
//! (`audit --json`, `changements --json`), un « voir » qui ne change rien (`correction --voir`, `changements --voir`)
//! et un geste qui change (`correction --appliquer`, `changements --annuler`). La mise à jour n'a pas de liste : son
//! jeton est fixe (`Empreinte::MISE_A_JOUR`) et aucune liste ne peut l'offrir ; son « voir » est `se-mettre-a-jour
//! --voir`, son geste `se-mettre-a-jour --appliquer --accord <accord>`, admis comme les autres seulement après un
//! aperçu relayé de même accord. Le relais retient, seulement d'après des sorties qu'il a lui-même relayées, finies
//! avec le code 0 et lues avec serde (un nom ou un message ne fabriquent jamais un geste) :
//!
//! - `offerts` : les « voir » offerts par la dernière liste de chaque famille qui en a une (le jeton et la sorte) ;
//! - `montres` : le dernier aperçu de chaque famille (le jeton, l'accord que Vanguard a donné, l'heure de sa fin).
//!
//! Un « voir » ne part que pour un jeton de la dernière liste de sa famille, avec cette sorte (la mise à jour : son
//! jeton fixe) : il s'arrête comme une lecture, et la liste offerte ne s'use pas (on peut revoir un aperçu). Un geste
//! qui change ne part que pour le jeton et l'accord exacts du dernier aperçu de sa famille, 2 s au moins et 10 minutes
//! au plus après sa fin ; il passe seul et ne se coupe pas, comme un changement au démarrage, et il consomme l'aperçu
//! et la liste de sa famille : le suivant demande une liste relue, puis un aperçu refait. Une fenêtre prise ne peut
//! donc demander que ce que Vanguard venait d'offrir puis de montrer ; elle peut, elle, enchaîner liste, aperçu et
//! accord sans personne (modèle de menace) : Vanguard rejuge tout de son côté (carnet des aperçus, accord recalculé,
//! verrou des notes).
//!
//! Un changement des couleurs de la fenêtre passe de même seul et sans interruption (`vanguard` écrit le fichier puis
//! son sceau) ; sa forme est fermée (un thème, une base connue, quinze octets de couleur), et une couleur presque
//! invisible sur le fond est refusée ici avant de l'être par `vanguard`. Une fenêtre prise peut au pire régler des
//! couleurs laides, jamais cacher une alerte : la gravité est toujours dite aussi en mots.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, mpsc};
use std::time::{Duration, Instant};

use crate::commandes::{
    APERCU_LU, Accord, Argument, AvecValeur, Commande, Empreinte, Famille, Geste, GesteOffert, Lancement, Refus, Sorte,
    SorteGeste,
};
use crate::lanceur::{Fin, Issue, Message, Programme, Rendre, Reveil, SORTIE_MAX, Tache};
use crate::protocole::{
    DEMANDE_MAX, Demande, Reponse, coder_fin, coder_lance, coder_ligne, ecrire_trame, lire_reponse, lire_trame,
};

/// Une réponse du relais : la sortie bornée, son texte d'erreur et l'en-tête.
const REPONSE_MAX: usize = SORTIE_MAX + 64 * 1024;
/// Commandes en même temps au plus (la fenêtre en lance une à la fois ; une qui finit de s'arrêter, en plus).
const TACHES_MAX: usize = 2;
/// Une fenêtre qui ne lit plus ne bloque pas le relais au-delà.
const ECRITURE_DELAI: Duration = Duration::from_secs(10);
/// Empreintes retenues au plus d'une liste du démarrage (une machine en a quelques dizaines).
const EMPREINTES_MAX: usize = 4096;
/// Un geste qui change part 10 minutes au plus après la fin de son aperçu (2 s au moins : `APERCU_LU`) : au-delà,
/// l'aperçu n'est plus celui qu'on a sous les yeux (le carnet de Vanguard aussi).
const APERCU_VIEUX: Duration = Duration::from_mins(10);

/// Une commande lancée par le relais.
struct EnCours {
    arret: Arc<AtomicBool>,
    /// Un changement : ni « Arrêter » ni la fermeture de la fenêtre ne le coupent.
    changement: bool,
}

/// Ce que le relais retient entre deux demandes.
#[derive(Default)]
struct Etat {
    taches: HashMap<u32, EnCours>,
    /// Les gestes de la dernière liste du démarrage relayée (l'empreinte, la sorte offerte pour elle et l'accord que
    /// Vanguard a donné à ce geste), vidés quand un changement part : un changement demande une liste relue après lui.
    vues: HashMap<Empreinte, (Sorte, Accord)>,
    /// Les « voir » offerts par la dernière liste relayée de chaque famille (`audit --json`, `changements --json`
    /// finis avec le code 0) : le jeton de chaque constat et sa sorte. Ceux d'une famille sont remplacés à la fin de
    /// chaque liste de cette famille, vidés si elle n'a pas réussi ou quand un geste qui change de la famille part.
    offerts: HashSet<(Empreinte, SorteGeste)>,
    /// Le dernier aperçu relayé de chaque famille (fini avec le code 0, « fait », pour le jeton demandé) : le jeton,
    /// l'accord donné par Vanguard et l'heure de la fin. Remplacé ou retiré à la fin de chaque « voir » de la
    /// famille, consommé quand le geste qui change part.
    montres: HashMap<Famille, (Empreinte, Accord, Instant)>,
}

impl Etat {
    /// Pourquoi ce lancement est refusé, s'il l'est ; sinon il est retenu (et un changement consomme la liste vue).
    fn admettre(&mut self, id: u32, lancement: &Lancement, arret: &Arc<AtomicBool>) -> Option<&'static str> {
        let changement = lancement.change();
        if self.taches.len() >= TACHES_MAX || self.taches.contains_key(&id) {
            return Some(crate::tr!(
                "trop de commandes en même temps",
                "too many commands at once"
            ));
        }
        if self.taches.values().any(|t| t.changement) {
            return Some(crate::tr!(
                "un changement est en cours : rien d'autre ne se lance avant sa fin",
                "a change is running: nothing else starts before it ends"
            ));
        }
        if changement && !self.taches.is_empty() {
            return Some(crate::tr!(
                "un changement à la fois : une commande tourne encore",
                "one change at a time: a command is still running"
            ));
        }
        if let Lancement::Changement(ch) = *lancement {
            match self.vues.get(&ch.empreinte) {
                None => {
                    return Some(crate::tr!(
                        "programme absent de la dernière liste du démarrage lue : relisez-la",
                        "program not in the last startup list read: read it again"
                    ));
                }
                Some(&(offerte, _)) if offerte != ch.sorte => {
                    return Some(crate::tr!(
                        "la dernière liste du démarrage lue n'offrait pas ce geste pour ce programme : relisez-la",
                        "the last startup list read did not offer this action for this program: read it again"
                    ));
                }
                // L'accord rendu est celui que la liste a donné, octet pour octet : la fenêtre ne le choisit pas.
                Some(&(_, accord)) if accord != ch.accord => {
                    return Some(crate::tr!(
                        "accord différent de celui de la dernière liste du démarrage lue : relisez-la",
                        "agreement differs from the last startup list read: read it again"
                    ));
                }
                Some(_) => self.vues.clear(),
            }
        }
        if let Lancement::Geste(g) = *lancement
            && let Some(r) = self.admettre_geste(g)
        {
            return Some(r);
        }
        // Des couleurs : revérifiées ici aussi (`vanguard` le refait), une presque invisible sur le fond refusée.
        if let Lancement::Couleurs(cc) = *lancement
            && let Some(c) = cc.choix
            && crate::couleurs::verifier(cc.theme, &c).is_err()
        {
            return Some(crate::tr!(
                "une couleur se verrait à peine sur le fond du thème",
                "a color would barely show on the theme's background"
            ));
        }
        self.taches.insert(
            id,
            EnCours {
                arret: Arc::clone(arret),
                changement,
            },
        );
        None
    }

    /// Un geste sur un constat : un « voir » offert par la dernière liste de sa famille ; un geste qui change, le jeton
    /// et l'accord exacts du dernier aperçu de sa famille, ni trop tôt ni trop tard. Admis, un geste qui change
    /// consomme l'aperçu et la liste de sa famille ; un refus ne consomme rien.
    fn admettre_geste(&mut self, g: Geste) -> Option<&'static str> {
        let famille = g.sorte.famille();
        // La mise à jour n'a qu'un jeton, fixe, qu'aucune liste n'offre : son « voir » (lecture seule) est admis
        // pour lui seul. Son geste qui change suit le chemin commun : le jeton et l'accord du dernier aperçu montré.
        if famille == Famille::MiseAJour && g.jeton != Empreinte::MISE_A_JOUR {
            return Some(crate::tr!("pas le jeton de la mise à jour", "not the update's token"));
        }
        if g.sorte.voir() && famille == Famille::MiseAJour {
            return None;
        }
        if g.sorte.voir() {
            // Un « voir » ne change rien : la liste offerte sert encore (elle n'est pas vidée ici).
            if self.offerts.contains(&(g.jeton, g.sorte)) {
                return None;
            }
            let autre_sorte = self.offerts.iter().any(|(j, _)| *j == g.jeton);
            return Some(match (famille, autre_sorte) {
                (Famille::Correction, true) => crate::tr!(
                    "le dernier bilan n'offrait pas ce geste pour ce constat : refaites-le",
                    "the last check did not offer this action for this finding: run it again"
                ),
                (Famille::Correction, false) => crate::tr!(
                    "constat absent du dernier bilan : refaites-le",
                    "finding not in the last check: run it again"
                ),
                (Famille::Annulation | Famille::MiseAJour, _) => crate::tr!(
                    "absent de la dernière liste de « Ce que Vanguard a changé » : relisez-la",
                    "not in the last list of “What Vanguard changed”: read it again"
                ),
            });
        }
        let Some(&(jeton, accord, depuis)) = self.montres.get(&famille) else {
            return Some(crate::tr!(
                "aucun aperçu montré pour ce geste : refaites l'aperçu",
                "no preview shown for this action: show the preview again"
            ));
        };
        if jeton != g.jeton {
            return Some(crate::tr!(
                "pas le dernier aperçu montré : refaites l'aperçu",
                "not the last preview shown: show the preview again"
            ));
        }
        // L'accord rendu est celui que l'aperçu a donné, octet pour octet : la fenêtre ne le choisit pas.
        if accord != g.accord {
            return Some(crate::tr!(
                "accord différent de celui du dernier aperçu : refaites l'aperçu",
                "agreement differs from the last preview: show the preview again"
            ));
        }
        let age = depuis.elapsed();
        if age < APERCU_LU {
            return Some(crate::tr!(
                "accepté moins de 2 secondes après l'aperçu : prenez le temps de le lire",
                "accepted less than 2 seconds after the preview: take the time to read it"
            ));
        }
        if age > APERCU_VIEUX {
            return Some(crate::tr!(
                "aperçu de plus de 10 minutes : refaites l'aperçu",
                "preview older than 10 minutes: show the preview again"
            ));
        }
        self.montres.remove(&famille);
        self.offerts.retain(|(_, s)| s.famille() != famille);
        None
    }

    /// Retient ce qu'une lecture finie offre ou montre : la liste d'une famille remplace ses « voir » offerts (vidés
    /// si elle n'a pas réussi) ; un « voir » fini remplace l'aperçu de sa famille (retiré s'il n'a rien montré).
    fn retenir(&mut self, fin: &Fin) {
        let reussie = fin.issue == Issue::Terminee && fin.code == Some(0);
        match fin.lancement {
            Lancement::Commande(Commande::Demarrage) if fin.issue == Issue::Terminee => {
                self.vues = gestes_vus(&fin.sortie);
            }
            Lancement::Commande(c @ (Commande::Bilan | Commande::Changements)) => {
                let famille = if c == Commande::Bilan {
                    Famille::Correction
                } else {
                    Famille::Annulation
                };
                self.offerts.retain(|(_, s)| s.famille() != famille);
                if reussie {
                    self.offerts.extend(gestes_offerts(&fin.sortie, famille));
                }
            }
            Lancement::Geste(g) if g.sorte.voir() => {
                let famille = g.sorte.famille();
                match accord_montre(g, fin).filter(|_| reussie) {
                    Some(accord) => {
                        self.montres.insert(famille, (g.jeton, accord, Instant::now()));
                    }
                    None => {
                        self.montres.remove(&famille);
                    }
                }
            }
            _ => {}
        }
    }
}

/// La dernière ligne d'un aperçu, lue pour l'accord seulement : le geste, l'issue, l'accord et le jeton de l'aperçu
/// (le reste est sauté sans être gardé : c'est la fenêtre qui le montre, et Vanguard qui le rejuge).
#[derive(serde::Deserialize)]
struct ApercuVu {
    geste: String,
    issue: String,
    accord: String,
    apercu: JetonVu,
}

#[derive(serde::Deserialize)]
struct JetonVu {
    jeton: String,
}

/// L'accord d'un aperçu fini : sa dernière ligne non vide dit ce geste, « fait », le jeton demandé, et un accord de
/// 64 chiffres qui n'est pas tout à zéro ; sinon, rien.
fn accord_montre(g: Geste, fin: &Fin) -> Option<Accord> {
    let ligne = fin
        .sortie
        .split(|&o| o == b'\n')
        .rev()
        .find(|l| !l.trim_ascii().is_empty())?;
    let a: ApercuVu = serde_json::from_slice(ligne).ok()?;
    let accord = Accord::lire(&a.accord).filter(|a| *a != Accord::NUL)?;
    (a.geste == g.sorte.mot() && a.issue == "fait" && Empreinte::lire(&a.apercu.jeton) == Some(g.jeton))
        .then_some(accord)
}

/// Ce que le relais lit d'une liste du démarrage : les gestes de ses constats, rien d'autre (le reste est sauté sans
/// être gardé, et un constat d'une forme inattendue est compté à part par `Liste`, sans faire tomber les autres).
#[derive(serde::Deserialize)]
struct ListeVue {
    #[serde(default)]
    constats: crate::donnees::Liste<ConstatVu>,
}

#[derive(serde::Deserialize)]
struct ConstatVu {
    #[serde(default)]
    geste: Option<GesteVu>,
}

#[derive(serde::Deserialize)]
struct GesteVu {
    sorte: String,
    empreinte: String,
    /// Absent : pas d'accord (tout à zéro, Vanguard refusera le changement) ; présent, 64 chiffres exactement.
    #[serde(default)]
    accord: Option<String>,
}

/// Les gestes d'une sortie de `demarrage --json` : pour chaque constat, l'empreinte et la sorte lues dans le même
/// objet `geste` (le JSON lu pour de bon, au fil de l'eau comme dans `donnees` : l'ordre des clés n'y fait rien, et
/// un nom de programme, une chaîne, ne fabrique ni clé ni geste), avec son accord. Une empreinte offerte deux fois
/// autrement (une autre sorte, un autre accord) n'est pas retenue (aucune n'est choisie) ; un geste incomplet ou à
/// l'accord mal formé non plus ; une sortie qui n'est pas du JSON : rien. Borné à `EMPREINTES_MAX`.
fn gestes_vus(texte: &[u8]) -> HashMap<Empreinte, (Sorte, Accord)> {
    let mut vus = HashMap::new();
    let Ok(liste) = serde_json::from_slice::<ListeVue>(texte) else {
        return vus;
    };
    let mut doubles = HashSet::new();
    for g in liste.constats.elements.into_iter().filter_map(|c| c.geste) {
        if vus.len() >= EMPREINTES_MAX {
            break;
        }
        let accord = match g.accord.as_deref() {
            None => Some(Accord::NUL),
            Some(a) => Accord::lire(a),
        };
        let (Some(sorte), Some(empreinte), Some(accord)) =
            (Sorte::lire(&g.sorte), Empreinte::lire(&g.empreinte), accord)
        else {
            continue;
        };
        if doubles.contains(&empreinte) {
            continue;
        }
        if vus
            .insert(empreinte, (sorte, accord))
            .is_some_and(|avant| avant != (sorte, accord))
        {
            vus.remove(&empreinte);
            doubles.insert(empreinte);
        }
    }
    vus
}

/// Ce que le relais lit d'un bilan ou de « Ce que Vanguard a changé » : les gestes de ses constats ou de ses
/// lignes, rien d'autre (comme `ListeVue`).
#[derive(serde::Deserialize)]
struct BilanVu {
    #[serde(default)]
    constats: crate::donnees::Liste<ConstatOffert>,
    #[serde(default)]
    changements: crate::donnees::Liste<ConstatOffert>,
}

/// Le geste d'un constat, lu avec la structure de la fenêtre (`commandes::GesteOffert`) : un geste qui porte un autre
/// champ, un champ `null` ou un jeton mal formé n'est pas offert, ni ici ni par un bouton de la fenêtre.
#[derive(serde::Deserialize)]
struct ConstatOffert {
    #[serde(default)]
    geste: Option<GesteOffert>,
}

/// Les gestes d'une sortie d'`audit --json` (les `constats`) ou de `changements --json` (les `changements`), selon la
/// famille : pour chaque constat ou ligne, le jeton et la sorte lus dans le même objet `geste`, au fil de l'eau (un
/// message ou un nom, des chaînes, ne fabriquent ni clé ni geste). Seul un « voir » de cette famille compte. Un jeton
/// offert deux fois n'est pas retenu (aucun n'est choisi : Vanguard le refuserait aussi) ; un geste incomplet ou d'une
/// sorte inconnue non plus ; une sortie qui n'est pas du JSON : rien. Borné à `EMPREINTES_MAX`.
fn gestes_offerts(texte: &[u8], famille: Famille) -> HashSet<(Empreinte, SorteGeste)> {
    let Ok(lu) = serde_json::from_slice::<BilanVu>(texte) else {
        return HashSet::new();
    };
    let elements = match famille {
        Famille::Correction => lu.constats.elements,
        Famille::Annulation => lu.changements.elements,
        // Aucune liste n'offre la mise à jour.
        Famille::MiseAJour => return HashSet::new(),
    };
    let (mut lus, mut jetons, mut doubles) = (Vec::new(), HashSet::new(), HashSet::new());
    for g in elements.into_iter().filter_map(|c| c.geste) {
        if jetons.len() >= EMPREINTES_MAX {
            break;
        }
        let Some((jeton, sorte)) = g.lire().filter(|(_, s)| s.famille() == famille) else {
            continue;
        };
        if jetons.insert(jeton) {
            lus.push((jeton, sorte));
        } else {
            doubles.insert(jeton);
        }
    }
    lus.into_iter().filter(|(j, _)| !doubles.contains(j)).collect()
}

static CLIENT: OnceLock<Client> = OnceLock::new();
static ETAT: OnceLock<(String, bool)> = OnceLock::new();

/// Le relais de la fenêtre, s'il a démarré.
pub fn client() -> Option<&'static Client> {
    CLIENT.get()
}

/// La phrase du bac à sable pour la console (et si elle est à souligner), une fois `separer` passé.
pub fn etat() -> Option<&'static (String, bool)> {
    ETAT.get()
}

/// Met le relais à part puis la fenêtre dans son bac à sable. À appeler au tout début, tant que la fenêtre n'a qu'un
/// fil (le dédoublement n'emporte que le fil appelant ; le bac ne s'applique qu'à lui et à ce qu'il crée). Si le
/// relais ne peut pas démarrer, la fenêtre reste libre (et le dit) : restreinte, elle lancerait un `vanguard` qui ne
/// verrait plus tout.
pub fn separer() {
    // Dédoubler un processus qui a déjà plusieurs fils laisserait l'enfant avec des verrous que personne ne rendra.
    let n = crate::bac_a_sable::fils();
    let etat = if n == 1 {
        match UnixStream::pair() {
            Err(e) => absent(&e.to_string()),
            Ok((fenetre, relais)) => match dedoubler() {
                Err(e) => absent(&e.to_string()),
                Ok(0) => {
                    drop(fenetre);
                    devenir_relais(relais)
                }
                Ok(pid) => {
                    drop(relais);
                    let bac = crate::bac_a_sable::restreindre();
                    let _ = CLIENT.set(Client::demarrer(fenetre, Some(pid)));
                    bac.phrase()
                }
            },
        }
    } else {
        absent(&crate::trf!("{} fils déjà là", "{} threads already there", n))
    };
    let _ = ETAT.set(etat);
}

fn absent(e: &str) -> (String, bool) {
    crate::bac_a_sable::Bac::Absent {
        raison: crate::trf!(
            "le relais n'a pas pu démarrer : {}",
            "the relay could not start: {}",
            crate::nettoyage::nom(e, 100)
        ),
        nnp: false,
    }
    .phrase()
}

/// Le relais : ses entrée et sortie au néant (la sortie de la fenêtre est le tuyau que `vanguard` lit jusqu'à
/// « ouverte » : le relais ne doit pas le garder ouvert), invisible au débogage, puis il sert jusqu'à la fermeture.
fn devenir_relais(flux: UnixStream) -> ! {
    systeme::preparer_relais();
    servir(flux, Programme::voisin);
    std::process::exit(0)
}

fn verrou<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Le côté relais : lit les demandes jusqu'à la fermeture (ou une demande hors protocole), lance chaque commande
/// avec la surveillance de `lanceur` et renvoie ses lignes puis sa fin. À la fin, arrête les lectures, laisse finir
/// un changement, et attend tout.
fn servir(flux: UnixStream, trouver: impl Fn() -> Result<Programme, String> + Send + Sync + 'static) {
    servir_pour(flux, trouver, &Compte::du_milieu());
}

/// `servir`, pour `compte` : ce qui juge les chemins tapés (une maison jetable dans les essais).
fn servir_pour(
    flux: UnixStream,
    trouver: impl Fn() -> Result<Programme, String> + Send + Sync + 'static,
    compte: &Compte,
) {
    let Ok(sortie) = flux.try_clone() else {
        return;
    };
    let _ = sortie.set_write_timeout(Some(ECRITURE_DELAI));
    let sortie = Arc::new(Mutex::new(sortie));
    let envoyer = {
        let sortie = Arc::clone(&sortie);
        Arc::new(move |t: &[u8]| {
            let _ = ecrire_trame(&mut *verrou(&sortie), t);
        })
    };
    let trouver = Arc::new(trouver);
    let etat: Arc<Mutex<Etat>> = Arc::default();
    let mut fils: Vec<std::thread::JoinHandle<()>> = Vec::new();
    let mut entree = flux;
    while let Ok(Some(t)) = lire_trame(&mut entree, DEMANDE_MAX) {
        let Some(d) = Demande::lire(&t) else {
            break;
        };
        match d {
            Demande::Arreter { id } => {
                // Un changement ne se coupe pas, même demandé : seul son délai l'arrête.
                if let Some(t) = verrou(&etat).taches.get(&id)
                    && !t.changement
                {
                    t.arret.store(true, Ordering::Relaxed);
                }
            }
            Demande::Lancer { id, lancement, anglais } => {
                let arret = Arc::new(AtomicBool::new(false));
                // La valeur tapée est rejugée en entier, chemin réel compris, avant toute admission : la fenêtre
                // n'est pas crue. Ce qui part est la valeur rejugée (pour un fichier, son chemin réel).
                let (lancement, refus) = match rejuger(&lancement, compte) {
                    Ok(l) => {
                        let refus = verrou(&etat).admettre(id, &l, &arret).map(String::from);
                        (l, refus)
                    }
                    Err(r) => (lancement, Some(r)),
                };
                let impossible = |texte: String| Fin {
                    lancement: lancement.clone(),
                    code: None,
                    sortie: Vec::new(),
                    issue: Issue::Impossible(texte),
                    duree: Duration::ZERO,
                };
                if let Some(r) = refus {
                    envoyer(&coder_fin(id, &impossible(r)));
                    continue;
                }
                let rendre: Rendre = {
                    let envoyer = Arc::clone(&envoyer);
                    Arc::new(move |m| match m {
                        Message::Ligne(l) => envoyer(&coder_ligne(id, &l)),
                        Message::Lance(pid) => envoyer(&coder_lance(id, pid)),
                        // La fin part après `surveiller`, ci-dessous.
                        Message::Fin(_) => {}
                    })
                };
                let (envoyer2, etat2, trouver2) = (Arc::clone(&envoyer), Arc::clone(&etat), Arc::clone(&trouver));
                let pour_le_fil = lancement.clone();
                let lance = std::thread::Builder::new()
                    .name("vanguard-relais".into())
                    .spawn(move || {
                        let fin = match trouver2() {
                            Ok(p) => crate::lanceur::surveiller(&p, &pour_le_fil, anglais, &arret, &rendre),
                            Err(e) => Fin {
                                lancement: pour_le_fil,
                                code: None,
                                sortie: Vec::new(),
                                issue: Issue::Impossible(e),
                                duree: Duration::ZERO,
                            },
                        };
                        // Retenue et retirée avant que la fin parte : la fenêtre qui la reçoit peut aussitôt
                        // demander un changement de cette liste.
                        {
                            let mut e = verrou(&etat2);
                            e.retenir(&fin);
                            e.taches.remove(&id);
                        }
                        envoyer2(&coder_fin(id, &fin));
                    });
                match lance {
                    Ok(f) => fils.push(f),
                    Err(e) => {
                        verrou(&etat).taches.remove(&id);
                        envoyer(&coder_fin(id, &impossible(e.to_string())));
                    }
                }
                fils.retain(|f| !f.is_finished());
            }
        }
    }
    // La fenêtre est partie (ou parle hors protocole) : les lectures sont arrêtées ; un changement commencé finit
    // (borné par son délai). Tout est attendu.
    for t in verrou(&etat).taches.values().filter(|t| !t.changement) {
        t.arret.store(true, Ordering::Relaxed);
    }
    for f in fils {
        let _ = f.join();
    }
}

/// Ce que le relais sait du compte pour juger un chemin : sa maison, son dossier de réglages (où est
/// user-dirs.dirs) et son nom (pour /run/media/<compte>). La maison et le nom viennent de la base des comptes, d'après
/// l'uid, comme du côté de `vanguard` (`maison_du_compte`, `compte_de`) : une session lancée sans USER (un service,
/// `env -i`) ou avec un HOME d'emprunt ne juge pas autrement que `vanguard`. Le milieu du relais (celui de la session,
/// jamais celui de la fenêtre) ne sert qu'en repli, et pour XDG_CONFIG_HOME.
struct Compte {
    maison: Option<PathBuf>,
    config: Option<PathBuf>,
    nom: Option<String>,
}

impl Compte {
    fn du_milieu() -> Compte {
        let mut base = systeme::compte_de_l_uid();
        // Variante d'essai, absente du programme publié, la même que celle de `vanguard` (`maison_du_compte`) : les
        // essais du programme entier posent la maison sur un dossier jetable.
        #[cfg(debug_assertions)]
        if let Some(essai) = std::env::var_os("VANGUARD_ESSAI_MAISON_DU_COMPTE").map(PathBuf::from) {
            base = Some((base.and_then(|(nom, _)| nom), essai));
        }
        Compte::depuis(base, |v| std::env::var_os(v))
    }

    /// Le compte d'après la base des comptes (`base` : le nom s'il est lisible, et la maison), le `milieu` en repli.
    fn depuis(base: Option<(Option<String>, PathBuf)>, milieu: impl Fn(&str) -> Option<OsString>) -> Compte {
        let absolu = |p: PathBuf| (p.is_absolute() && p.parent().is_some()).then_some(p);
        let (nom, maison) = base.map_or((None, None), |(nom, maison)| (nom, absolu(maison)));
        let maison = maison.or_else(|| milieu("HOME").map(PathBuf::from).and_then(absolu));
        // XDG_CONFIG_HOME relatif : ignoré, comme le veut la spécification.
        let config = milieu("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .and_then(absolu)
            .or_else(|| maison.as_ref().map(|m| m.join(".config")));
        let nom = nom.or_else(|| ["USER", "LOGNAME"].iter().find_map(|v| milieu(v)?.into_string().ok()));
        Compte { maison, config, nom }
    }
}

/// Rejuge une demande avant de l'admettre : une commande qui se lance avec sa valeur ne part pas sans elle, et la
/// valeur, si elle vient, est rejugée comme si la fenêtre n'avait rien vérifié (`rejuger_valeur`). Le refus est dit
/// sans la valeur.
fn rejuger(lancement: &Lancement, compte: &Compte) -> Result<Lancement, String> {
    match lancement {
        Lancement::Commande(c) if c.valeur_requise() => Err(crate::tr!(
            "cette commande se lance avec sa valeur",
            "this command runs with its value"
        )
        .into()),
        Lancement::AvecValeur(av) => rejuger_valeur(av, compte)
            .map(Lancement::AvecValeur)
            .map_err(|r| crate::trf!("valeur refusée : {}", "value refused: {}", r.phrase())),
        autre => Ok(autre.clone()),
    }
}

/// La valeur rejugée : sa forme (`AvecValeur::nouvelle`) ; pour un fichier, en plus, sa place jugée sur le texte
/// d'abord (hors de Téléchargements, Bureau, Documents du compte et de /run/media/<compte> : refusé sans rien
/// regarder sur le disque), puis chaque élément regardé sans suivre de lien : aucun lien, aucun dossier caché, un
/// fichier ordinaire à un seul nom (`valeur::juger_chemin`). Rend son chemin sous l'endroit réel. Ce jugement ne vaut
/// que pour l'instant où il est fait : `vanguard` ne le croit pas, il rejuge le texte puis ouvre le fichier une seule
/// fois en descendant sans suivre de lien, et juge ce qui est ouvert (`socle::ouvrir_console`) ; ce qui change entre
/// les deux est refusé là, jamais lu.
fn rejuger_valeur(av: &AvecValeur, compte: &Compte) -> Result<AvecValeur, Refus> {
    let av = AvecValeur::nouvelle(av.commande(), av.valeur())?;
    if av.sorte() != Argument::Chemin {
        return Ok(av);
    }
    let maison = compte.maison.as_deref().ok_or(Refus::MaisonInconnue)?;
    let declares = compte
        .config
        .as_deref()
        .map(|c| lire_declares(&c.join("user-dirs.dirs")))
        .unwrap_or_default();
    let racines = crate::valeur::racines_linux(maison, &declares, compte.nom.as_deref());
    let reel = crate::valeur::juger_chemin(av.valeur(), maison, &racines)?;
    AvecValeur::nouvelle(av.commande(), reel.to_str().ok_or(Refus::Forme)?)
}

/// user-dirs.dirs, lu sans jamais bloquer ni déborder : ouvert sans attendre (un tube nommé posé à sa place ne fige
/// pas le relais) et sans suivre de lien (un lien vers un fichier d'ailleurs n'y déclare rien), seulement s'il est un
/// fichier ordinaire, 64 Kio au plus, en UTF-8. Absent ou autre : vide (les noms usuels des dossiers servent alors
/// seuls), comme du côté de `vanguard` (`socle::lire_texte_ordinaire`).
fn lire_declares(chemin: &Path) -> String {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    const MAX: u64 = 64 << 10;
    let Ok(f) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(chemin)
    else {
        return String::new();
    };
    if !f.metadata().is_ok_and(|m| m.is_file()) {
        return String::new();
    }
    let mut octets = Vec::new();
    if f.take(MAX.saturating_add(1)).read_to_end(&mut octets).is_err()
        || u64::try_from(octets.len()).map_or(true, |n| n > MAX)
    {
        return String::new();
    }
    String::from_utf8(octets).unwrap_or_default()
}

/// Une tâche de la fenêtre qui attend sa fin du relais.
struct Attente {
    lancement: Lancement,
    envoi: mpsc::Sender<Message>,
    reveil: Reveil,
}

/// Le côté fenêtre : demande au relais et rend ses réponses aux tâches.
pub struct Client {
    sortie: Mutex<UnixStream>,
    attente: Arc<Mutex<HashMap<u32, Attente>>>,
    /// Le relais est parti : plus rien ne se lance (sans lui, la fenêtre restreinte ne lancerait qu'un `vanguard`
    /// qui ne voit pas tout). Posé sous le verrou d'`attente`.
    mort: Arc<AtomicBool>,
    suivant: AtomicU32,
}

impl Client {
    /// Le lecteur des réponses part en fond (créé après le bac à sable : il y est aussi). `relais` : son numéro, pour
    /// le récolter quand la socket se ferme.
    fn demarrer(flux: UnixStream, relais: Option<i32>) -> Client {
        let attente: Arc<Mutex<HashMap<u32, Attente>>> = Arc::default();
        let mort = Arc::new(AtomicBool::new(false));
        let lecteur = flux.try_clone().and_then(|mut entree| {
            let (attente, mort) = (Arc::clone(&attente), Arc::clone(&mort));
            std::thread::Builder::new()
                .name("vanguard-relais".into())
                .spawn(move || {
                    lire_reponses(&mut entree, &attente);
                    let restes: Vec<Attente> = {
                        let mut a = verrou(&attente);
                        mort.store(true, Ordering::Relaxed);
                        a.drain().map(|(_, x)| x).collect()
                    };
                    for a in restes {
                        rendre_fin(&a, None, Issue::Impossible(relais_parti()), Duration::ZERO, Vec::new());
                    }
                    if let Some(pid) = relais {
                        systeme::recolter(pid);
                    }
                })
        });
        if lecteur.is_err() {
            mort.store(true, Ordering::Relaxed);
        }
        Client {
            sortie: Mutex::new(flux),
            attente,
            mort,
            suivant: AtomicU32::new(1),
        }
    }

    pub fn lancer(&self, lancement: Lancement, anglais: bool, reveil: &Reveil) -> Tache {
        let (envoi, recu) = mpsc::channel();
        let id = self.suivant.fetch_add(1, Ordering::Relaxed);
        let a = Attente {
            lancement: lancement.clone(),
            envoi,
            reveil: Arc::clone(reveil),
        };
        let refus = {
            let mut attente = verrou(&self.attente);
            if self.mort.load(Ordering::Relaxed) {
                Some(a)
            } else {
                attente.insert(id, a);
                None
            }
        };
        let refus = refus.or_else(|| {
            let d = Demande::Lancer {
                id,
                lancement: lancement.clone(),
                anglais,
            };
            ecrire_trame(&mut *verrou(&self.sortie), &d.coder())
                .err()
                .and_then(|_| verrou(&self.attente).remove(&id))
        });
        if let Some(a) = refus {
            rendre_fin(&a, None, Issue::Impossible(relais_parti()), Duration::ZERO, Vec::new());
        }
        Tache::relayee(lancement, id, recu)
    }

    /// Pour les tests : ferme la socket (le relais l'apprend et s'en va, le lecteur aussi).
    #[cfg(test)]
    fn fermer(&self) {
        let _ = verrou(&self.sortie).shutdown(std::net::Shutdown::Both);
    }

    pub fn arreter(&self, id: u32) {
        let _ = ecrire_trame(&mut *verrou(&self.sortie), &Demande::Arreter { id }.coder());
    }
}

fn relais_parti() -> String {
    crate::tr!(
        "le relais de la fenêtre s'est arrêté ; rouvrez la fenêtre",
        "the window's relay stopped; reopen the window"
    )
    .into()
}

fn rendre_fin(a: &Attente, code: Option<i32>, issue: Issue, duree: Duration, sortie: Vec<u8>) {
    let _ = a.envoi.send(Message::Fin(Fin {
        lancement: a.lancement.clone(),
        code,
        sortie,
        issue,
        duree,
    }));
    (a.reveil)();
}

/// Lit les réponses jusqu'à la fermeture du relais (ou une réponse illisible) et les rend à leurs tâches. La
/// commande d'une fin est celle que la fenêtre a demandée, jamais une que le relais dirait.
fn lire_reponses(entree: &mut UnixStream, attente: &Mutex<HashMap<u32, Attente>>) {
    while let Ok(Some(t)) = lire_trame(entree, REPONSE_MAX) {
        match lire_reponse(&t) {
            Some(Reponse::Ligne(id, l)) => {
                if let Some(a) = verrou(attente).get(&id) {
                    let _ = a.envoi.send(Message::Ligne(l));
                    (a.reveil)();
                }
            }
            Some(Reponse::Lance(id, pid)) => {
                if let Some(a) = verrou(attente).get(&id) {
                    let _ = a.envoi.send(Message::Lance(pid));
                    (a.reveil)();
                }
            }
            Some(Reponse::Fin {
                id,
                code,
                issue,
                duree,
                sortie,
            }) => {
                let a = verrou(attente).remove(&id);
                if let Some(a) = a {
                    rendre_fin(&a, code, issue, duree, sortie);
                }
            }
            None => return,
        }
    }
}

mod systeme {
    use std::path::PathBuf;

    /// Le nom (s'il est en UTF-8) et la maison du compte qui fait tourner le relais, d'après la base des comptes
    /// (getpwuid_r sur l'uid), sans rien prendre du milieu. Hors du code que le banc de fuzzing compile.
    // raison : FFI de getuid et getpwuid_r (libc), que std ne fait pas.
    #[allow(unsafe_code)]
    pub fn compte_de_l_uid() -> Option<(Option<String>, PathBuf)> {
        use std::os::unix::ffi::OsStrExt as _;
        let mut tampon: Vec<libc::c_char> = vec![0; 16 << 10];
        // SAFETY: passwd n'a que des entiers et des pointeurs, valides à zéro ; getpwuid_r les remplit.
        let mut compte: libc::passwd = unsafe { std::mem::zeroed() };
        let mut trouve: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: getuid ne lit rien du programme ; `compte`, `tampon` (avec sa vraie longueur) et `trouve` vivent
        // jusqu'à la fin de la fonction, et getpwuid_r n'écrit que dans eux.
        let r = unsafe {
            libc::getpwuid_r(
                libc::getuid(),
                &raw mut compte,
                tampon.as_mut_ptr(),
                tampon.len(),
                &raw mut trouve,
            )
        };
        if r != 0 || trouve.is_null() || compte.pw_dir.is_null() || compte.pw_name.is_null() {
            return None;
        }
        // SAFETY: pw_dir et pw_name pointent dans `tampon`, encore vivant, et getpwuid_r les a terminés par un zéro.
        let (maison, nom) = unsafe {
            (
                std::ffi::CStr::from_ptr(compte.pw_dir),
                std::ffi::CStr::from_ptr(compte.pw_name),
            )
        };
        Some((
            nom.to_str().ok().map(str::to_owned),
            PathBuf::from(std::ffi::OsStr::from_bytes(maison.to_bytes())),
        ))
    }

    /// Le dédoublement : 0 dans l'enfant, son numéro dans le parent.
    // raison : FFI de fork (libc), que std ne fait pas sans exec ; appelé quand la fenêtre n'a qu'un fil.
    #[allow(unsafe_code)]
    pub fn dedoubler() -> std::io::Result<i32> {
        // SAFETY: appelé au début de main, avant tout autre fil (`relais::separer`, vérifié par le bac à sable qui
        // suit) : l'enfant reprend un processus entier, sans verrou tenu par un fil disparu, et peut tout faire.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(pid)
        }
    }

    /// Le relais : entrée et sortie au néant, non observable (ni ptrace ni /proc/<pid>/mem), et nommé.
    // raison : FFI de dup2 et prctl (libc), que std ne sait pas faire.
    #[allow(unsafe_code)]
    pub fn preparer_relais() {
        use std::os::fd::AsRawFd;
        if let Ok(rien) = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null") {
            // SAFETY: dup2 ne reçoit que des numéros de descripteurs ouverts (`rien`, gardé jusqu'après, et 0, 1) ;
            // il ne touche aucune mémoire du programme.
            unsafe {
                libc::dup2(rien.as_raw_fd(), libc::STDIN_FILENO);
                libc::dup2(rien.as_raw_fd(), libc::STDOUT_FILENO);
            }
        }
        let nom = c"vanguard-relais";
        // SAFETY: prctl ne reçoit que des entiers, et pour PR_SET_NAME un nom terminé par zéro (16 octets au plus,
        // lu pendant l'appel) qui vit jusqu'à la fin du programme.
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
            libc::prctl(libc::PR_SET_NAME, nom.as_ptr(), 0, 0, 0);
        }
    }

    /// Récolte le relais parti (pas de zombie tant que la fenêtre reste ouverte).
    // raison : FFI de waitpid (libc) sur un numéro que std ne connaît pas (le relais vient de fork).
    #[allow(unsafe_code)]
    pub fn recolter(pid: i32) {
        let mut statut = 0;
        // SAFETY: waitpid écrit un entier, à nous, vivant pendant l'appel ; `pid` est le relais, notre enfant, que
        // rien d'autre ne récolte.
        let _ = unsafe { libc::waitpid(pid, &raw mut statut, 0) };
    }
}

use systeme::dedoubler;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commandes::{Changement, Commande, Empreinte, Geste, Sorte, SorteGeste};
    use std::time::Instant;

    /// Le relais en fil, et une fenêtre qui lui parle : une commande inconnue de lui (pas de `vanguard` voisin) finit
    /// « impossible », un arrêt d'une tâche inconnue ne fait rien, et une demande hors protocole le ferme : les tâches
    /// en attente l'apprennent, et plus rien ne se lance.
    #[test]
    fn le_relais_se_ferme_sur_une_demande_hors_protocole() {
        let (fenetre, relais) = UnixStream::pair().unwrap();
        let serveur = std::thread::spawn(move || servir(relais, || Err("introuvable".into())));
        let c = Client::demarrer(fenetre.try_clone().unwrap(), None);
        let rien: Reveil = Arc::new(|| {});
        let attendre = attendre_fin;
        let f = attendre(&c.lancer(Commande::Protection.into(), false, &rien));
        assert_eq!(
            (f.lancement, f.issue),
            (Commande::Protection.into(), Issue::Impossible("introuvable".into()))
        );
        c.arreter(12345);
        ecrire_trame(&mut &fenetre, &[9, 9, 9]).unwrap();
        serveur.join().unwrap();
        let f = attendre(&c.lancer(Commande::Bilan.into(), false, &rien));
        assert!(matches!(f.issue, Issue::Impossible(_)), "{:?}", f.issue);
        // L'envoi peut échouer (socket fermée) avant que le lecteur, en fond, ait vu la fin et posé `mort` : on
        // l'attend, borné.
        let debut = Instant::now();
        while !c.mort.load(Ordering::Relaxed) && debut.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(c.mort.load(Ordering::Relaxed));
    }

    /// Un changement bien formé passe le protocole (ici, sans liste du démarrage relayée avant, il est refusé sans
    /// rien lancer) ; un changement à la mauvaise longueur, d'une sorte inconnue ou suivi d'un chemin ferme le relais,
    /// sans rien lancer.
    #[test]
    fn le_relais_ne_comprend_que_le_changement_de_forme_fermee() {
        let ch = Lancement::Changement(Changement {
            sorte: Sorte::Retirer,
            empreinte: Empreinte::depuis_octets([0x5a; 16]),
            accord: Accord::depuis_octets([0xa5; 32]),
        });
        let bonne = Demande::Lancer {
            id: 7,
            lancement: ch.clone(),
            anglais: false,
        }
        .coder();
        let mut longue = bonne.clone();
        longue.extend(b"/home/alice/.config/autostart/Lecteur.desktop");
        let mut sorte = bonne.clone();
        sorte[5] = 9;
        // L'ancienne trame, sans accord (23 octets), est hors du protocole.
        let mut ancienne = bonne[..22].to_vec();
        ancienne.push(0);
        for fausse in [bonne[..22].to_vec(), ancienne, bonne[..54].to_vec(), longue, sorte] {
            let (fenetre, relais) = UnixStream::pair().unwrap();
            let lances = Arc::new(AtomicU32::new(0));
            let l = Arc::clone(&lances);
            let serveur = std::thread::spawn(move || {
                servir(relais, move || {
                    l.fetch_add(1, Ordering::Relaxed);
                    Err("introuvable".into())
                });
            });
            let c = Client::demarrer(fenetre.try_clone().unwrap(), None);
            let rien: Reveil = Arc::new(|| {});
            let f = attendre_fin(&c.lancer(ch.clone(), false, &rien));
            assert_eq!(f.lancement, ch);
            assert!(
                matches!(&f.issue, Issue::Impossible(r) if r.contains("dernière liste")),
                "{:?}",
                f.issue
            );
            ecrire_trame(&mut &fenetre, &fausse).unwrap();
            serveur.join().unwrap();
            assert_eq!(lances.load(Ordering::Relaxed), 0, "{fausse:?}");
            c.fermer();
        }
    }

    /// Les gestes d'une liste : l'empreinte (32 chiffres hexadécimaux minuscules) avec sa sorte, lues dans le même
    /// objet `geste`, dans n'importe quel ordre ; ni geste sans sorte, ni sorte inconnue, ni majuscule, ni longueur
    /// voisine, ni empreinte hors d'un geste, ni geste fabriqué dans une chaîne (un nom de programme) ; une empreinte
    /// offerte avec deux sortes n'est pas retenue.
    #[test]
    fn seuls_les_gestes_de_la_liste_sont_vus() {
        use std::fmt::Write as _;
        let (e1, e2, e3, e4, e5) = (
            "0123456789abcdef0123456789abcdef",
            "a".repeat(32),
            "b".repeat(32),
            "d".repeat(32),
            "e".repeat(32),
        );
        let (e6, e7, e8, e9) = ("1".repeat(32), "2".repeat(32), "3".repeat(32), "4".repeat(32));
        let (a, b) = ("ab".repeat(32), "cd".repeat(32));
        let liste = format!(
            r#"{{"constats": [{{"geste": {{"sorte": "retirer", "empreinte": "{e1}", "nom": "Lecteur"}}}},
            {{"geste": {{"nom": "Agenda", "empreinte":"{e2}", "sorte": "remettre"}}}},
            {{"geste": {{"empreinte": "{e3}"}}}}, {{"geste": {{"sorte": "effacer", "empreinte": "{e3}"}}}},
            {{"nom": "x\", \"geste\": {{\"sorte\": \"retirer\", \"empreinte\": \"{e4}\"}}"}},
            {{"geste": {{"sorte": "retirer", "empreinte": "{e5}"}}}}, {{"geste": {{"sorte": "remettre", "empreinte": "{e5}"}}}},
            {{"geste": {{"sorte": "retirer", "empreinte": "{}"}}}}, {{"geste": {{"sorte": "retirer", "empreinte": "{}"}}}},
            {{"geste": {{"sorte": "retirer", "empreinte": "{e1}0"}}}}, {{"geste": {{"sorte": "retirer", "empreinte": 7}}}},
            {{"empreinte": "{e4}", "sorte": "retirer"}}, "geste",
            {{"geste": {{"sorte": "retirer", "empreinte": "{e6}", "accord": "{a}"}}}},
            {{"geste": {{"sorte": "retirer", "empreinte": "{e7}", "accord": "{a}"}}}},
            {{"geste": {{"sorte": "retirer", "empreinte": "{e7}", "accord": "{b}"}}}},
            {{"geste": {{"sorte": "retirer", "empreinte": "{e8}", "accord": "{}"}}}},
            {{"geste": {{"sorte": "retirer", "empreinte": "{e9}", "accord": null}}}}]}}"#,
            "C".repeat(32),
            "c".repeat(31),
            a.to_uppercase(),
        );
        let vus = gestes_vus(liste.as_bytes());
        let mut attendus: HashMap<Empreinte, (Sorte, Accord)> = [(e1, Sorte::Retirer), (e2.as_str(), Sorte::Remettre)]
            .into_iter()
            .filter_map(|(e, s)| Some((Empreinte::lire(e)?, (s, Accord::NUL))))
            .collect();
        // Un accord donné : gardé tel quel ; la même empreinte avec deux accords, un accord en majuscules : pas
        // retenue. `null` vaut absent, comme pour la fenêtre (`donnees::bilan`) : tout à zéro, Vanguard refusera.
        attendus.insert(
            Empreinte::lire(&e6).unwrap(),
            (Sorte::Retirer, Accord::lire(&a).unwrap()),
        );
        attendus.insert(Empreinte::lire(&e9).unwrap(), (Sorte::Retirer, Accord::NUL));
        assert_eq!(vus, attendus);
        for rien in [
            &b""[..],
            b"\"empreinte\"",
            b"{\"constats\": 7}",
            b"[1, 2]",
            b"une ligne\n{\"constats\": []}",
        ] {
            assert!(gestes_vus(rien).is_empty());
        }
        // Bornés.
        let mut beaucoup = String::from(r#"{"constats": ["#);
        for i in 0..EMPREINTES_MAX + 10 {
            let _ = write!(
                beaucoup,
                r#"{{"geste": {{"sorte": "retirer", "empreinte": "{i:032x}"}}}},"#
            );
        }
        beaucoup.push_str("{}]}");
        assert_eq!(gestes_vus(beaucoup.as_bytes()).len(), EMPREINTES_MAX);
    }

    /// Le relais refuse un changement dont la sorte n'est pas celle que la liste offrait pour cette empreinte (une
    /// fenêtre prise qui retire un programme que la liste offrait de remettre), sans consommer la liste.
    #[test]
    fn une_sorte_que_la_liste_n_offrait_pas_est_refusee() {
        let e = Empreinte::lire("0123456789abcdef0123456789abcdef").unwrap();
        let a = Accord::lire(&"5c".repeat(32)).unwrap();
        let mut etat = Etat {
            vues: [(e, (Sorte::Remettre, a))].into(),
            ..Etat::default()
        };
        let arret = Arc::new(AtomicBool::new(false));
        let demande = |sorte, accord| {
            Lancement::Changement(Changement {
                sorte,
                empreinte: e,
                accord,
            })
        };
        assert!(etat.admettre(1, &demande(Sorte::Retirer, a), &arret).is_some());
        // M-2 : un autre accord que celui de la liste (fabriqué, ou absent) est refusé, sans consommer la liste.
        let autre = Accord::lire(&"5d".repeat(32)).unwrap();
        for faux in [autre, Accord::NUL] {
            let r = etat.admettre(1, &demande(Sorte::Remettre, faux), &arret);
            assert!(r.is_some_and(|r| r.contains("accord")), "{r:?}");
        }
        assert!(etat.taches.is_empty());
        assert_eq!(etat.vues.get(&e), Some(&(Sorte::Remettre, a)));
        assert_eq!(etat.admettre(2, &demande(Sorte::Remettre, a), &arret), None);
        assert!(etat.vues.is_empty());
    }

    /// Des couleurs : admises sans liste à lire, mais seules (jamais pendant une autre commande) et seulement
    /// lisibles ; une fenêtre prise ne fait pas enregistrer des alertes noires sur du noir.
    #[test]
    fn des_couleurs_passent_seules_et_lisibles() {
        use crate::commandes::ChangementCouleurs;
        use crate::couleurs::{Base, Choix, Theme, Vif};
        let arret = Arc::new(AtomicBool::new(false));
        let braise = Choix::du_prereglage(Base::Braise, Theme::Sombre);
        let mut noir = braise;
        noir.poser(Vif::Grave, [0, 0, 0]);
        let demande = |choix| {
            Lancement::Couleurs(ChangementCouleurs {
                theme: Theme::Sombre,
                choix,
            })
        };
        let mut etat = Etat::default();
        assert!(etat.admettre(1, &demande(Some(noir)), &arret).is_some());
        assert!(etat.taches.is_empty());
        assert_eq!(etat.admettre(2, &Commande::Protection.into(), &arret), None);
        assert!(
            etat.admettre(3, &demande(Some(braise)), &arret).is_some(),
            "pendant une lecture"
        );
        etat.taches.clear();
        assert_eq!(etat.admettre(4, &demande(Some(braise)), &arret), None);
        assert!(
            etat.admettre(5, &Commande::Protection.into(), &arret).is_some(),
            "pendant le changement"
        );
        etat.taches.clear();
        assert_eq!(etat.admettre(6, &demande(None), &arret), None);
    }

    /// Un faux `vanguard` : la liste lue dans liste.json, le bilan dans bilan.json s'il existe ; un changement noté
    /// dans « changements », qui attend le fichier « va » (20 s au plus) puis note « fini » ; un geste sur un constat
    /// (aperçu, application, annulation) noté dans « gestes », l'aperçu lu dans apercu.json ou annulation.json, la
    /// liste de « Ce que Vanguard a changé » dans changements.json ; toute autre commande attend « va-lecture ».
    const FAUX_VANGUARD: &str = r#"#!/bin/sh
d=$(dirname "$0")
attendre() { i=0; while [ ! -e "$d/$1" ] && [ $i -lt 400 ]; do sleep 0.05; i=$((i+1)); done; }
case "$1 $2" in
"demarrage --json") cat "$d/liste.json" ;;
"audit --json") if [ -e "$d/bilan.json" ]; then cat "$d/bilan.json"; else attendre va-lecture; echo '{}'; fi ;;
"correction --voir") echo "$@" >> "$d/gestes"
  if [ -e "$d/apercu.json" ]; then cat "$d/apercu.json"; else echo '{"geste": "voir-correction", "issue": "fait", "raison": ""}'; fi ;;
"correction --appliquer") echo "$@" >> "$d/gestes"; echo '{"geste":"appliquer-correction","issue":"fait","raison":"","relu":"corrige"}' ;;
"changements --json") cat "$d/changements.json" ;;
"changements --voir") echo "$@" >> "$d/gestes"; cat "$d/annulation.json" ;;
"changements --annuler") echo "$@" >> "$d/gestes"; echo '{"geste":"annuler-correction","issue":"fait","raison":"","relu":"revenu"}' ;;
"demarrage --retirer"|"demarrage --remettre") echo "$@" >> "$d/changements"; attendre va; echo fini >> "$d/changements"
  echo "{\"geste\": \"${2#--}\", \"issue\": \"fait\", \"raison\": \"\"}" ;;
*) attendre va-lecture; echo '{}' ;;
esac
"#;

    /// Une maison jetable d'« alice » : Téléchargements avec un vrai fichier (et un autre au nom à espace), Documents
    /// avec un lien vers lui, et tout ce qu'une fenêtre prise viserait : ~/.ssh, un lien vers lui ou vers sa clé,
    /// /proc/self/environ, /dev/zero, un tube nommé, un dossier caché, un Bureau qui est un lien vers ~/.ssh, et un
    /// user-dirs.dirs qui déclare ~/.ssh comme Téléchargements.
    fn maison_piegee(nom: &str) -> (PathBuf, Compte) {
        use std::os::unix::fs::symlink;
        let d = crate::essais::banc(nom);
        let _ = std::fs::remove_dir_all(&d);
        let maison = d.join("alice");
        let tele = maison.join("Téléchargements");
        for dossier in [
            &tele,
            &maison.join(".ssh"),
            &maison.join("Documents"),
            &maison.join(".config"),
        ] {
            std::fs::create_dir_all(dossier).unwrap();
        }
        std::fs::create_dir_all(tele.join(".cache")).unwrap();
        std::fs::write(tele.join("facture.pdf"), b"%PDF-1.7").unwrap();
        std::fs::write(tele.join("ma facture.pdf"), b"%PDF-1.7").unwrap();
        std::fs::write(tele.join(".cache/x.pdf"), b"%PDF-1.7").unwrap();
        std::fs::write(maison.join(".ssh/id_ed25519"), b"fausse cle").unwrap();
        std::fs::write(maison.join("hors.txt"), b"x").unwrap();
        symlink(maison.join(".ssh/id_ed25519"), tele.join("cle")).unwrap();
        symlink(maison.join(".ssh"), tele.join("ssh")).unwrap();
        symlink("/proc/self/environ", tele.join("environ")).unwrap();
        symlink("/dev/zero", tele.join("zero")).unwrap();
        symlink("/", tele.join("racine")).unwrap();
        symlink(tele.join("facture.pdf"), maison.join("Documents/lien.pdf")).unwrap();
        symlink(maison.join(".ssh"), maison.join("Bureau")).unwrap();
        std::fs::write(
            maison.join(".config/user-dirs.dirs"),
            "XDG_DOWNLOAD_DIR=\"$HOME/.ssh\"\nXDG_DESKTOP_DIR=\"/\"\n",
        )
        .unwrap();
        let tube = std::process::Command::new("mkfifo").arg(tele.join("tube")).status();
        assert!(tube.is_ok_and(|s| s.success()), "mkfifo");
        let compte = Compte {
            config: Some(maison.join(".config")),
            maison: Some(maison),
            nom: Some("alice".into()),
        };
        (d, compte)
    }

    /// Le compte du relais vient de la base des comptes : sans USER ni LOGNAME (un service, `env -i`), son nom est
    /// connu (et /run/media/<compte> avec lui), et un HOME d'emprunt ne change pas sa maison. Le milieu ne sert
    /// qu'en repli.
    #[test]
    fn le_compte_vient_de_l_uid_meme_sans_user() {
        let emprunt = |v: &str| match v {
            "HOME" => Some(OsString::from("/tmp/emprunt")),
            "XDG_CONFIG_HOME" => Some(OsString::from("relatif")),
            _ => None,
        };
        let c = Compte::depuis(Some((Some("alice".into()), PathBuf::from("/home/alice"))), emprunt);
        assert_eq!(c.nom.as_deref(), Some("alice"));
        assert_eq!(c.maison.as_deref(), Some(Path::new("/home/alice")));
        assert_eq!(c.config.as_deref(), Some(Path::new("/home/alice/.config")));
        let repli = |v: &str| match v {
            "HOME" => Some(OsString::from("/home/bob")),
            "LOGNAME" => Some(OsString::from("bob")),
            _ => None,
        };
        let c = Compte::depuis(None, repli);
        assert_eq!(c.nom.as_deref(), Some("bob"));
        assert_eq!(c.maison.as_deref(), Some(Path::new("/home/bob")));
        let c = Compte::depuis(Some((None, PathBuf::from("relative"))), repli);
        assert_eq!(
            (c.nom.as_deref(), c.maison.as_deref()),
            (Some("bob"), Some(Path::new("/home/bob")))
        );
        // Le vrai compte de l'essai, USER retiré : son nom vient de l'uid.
        let Some(base) = systeme::compte_de_l_uid() else {
            return crate::essais::sauter("l'uid de l'essai n'est pas dans la base des comptes");
        };
        let attendu = base.0.clone();
        assert!(attendu.is_some());
        assert_eq!(Compte::depuis(Some(base), |_| None).nom, attendu);
    }

    fn jugee(c: Commande, v: &str, compte: &Compte) -> Result<Lancement, String> {
        rejuger(&Lancement::AvecValeur(AvecValeur::nouvelle(c, v).unwrap()), compte)
    }

    /// Le relais rejuge chaque chemin sans croire la fenêtre : seul un fichier ordinaire sous Téléchargements, Bureau
    /// ou Documents part, par son chemin sous l'endroit réel ; un lien (même vers un fichier permis), ~/.ssh, /proc,
    /// /dev, un tube nommé, un dossier caché ou un dossier sont refusés, et le refus ne redit jamais la valeur.
    #[test]
    fn le_relais_rejuge_chaque_chemin_sur_son_chemin_reel() {
        let (d, compte) = maison_piegee("rejuger");
        let maison = compte.maison.clone().unwrap();
        let tele = maison.join("Téléchargements");
        let reel = |c: &str| tele.join(c).to_str().unwrap().to_string();
        for (v, attendu) in [
            ("~/Téléchargements/facture.pdf", reel("facture.pdf")),
            ("~/Téléchargements/ma facture.pdf", reel("ma facture.pdf")),
            (&reel("facture.pdf"), reel("facture.pdf")),
        ] {
            for c in [
                Commande::VerifierFichier,
                Commande::CourrielSuspect,
                Commande::VerifierMoi,
            ] {
                let l = jugee(c, v, &compte).unwrap();
                assert_eq!(l.arguments()[3], attendu, "{v:?}");
                assert_eq!(l.arguments()[..3], ["console", c.nom(), "--"]);
            }
        }
        for (v, refus) in [
            ("~/.ssh/id_ed25519", Refus::HorsDesEndroits),
            // Le même refus qu'il existe ou non : rien n'est regardé hors des endroits permis.
            ("~/.ssh/absent", Refus::HorsDesEndroits),
            ("~/hors.txt", Refus::HorsDesEndroits),
            ("~/Téléchargements/cle", Refus::Lien),
            ("~/Téléchargements/ssh/id_ed25519", Refus::Lien),
            ("~/Téléchargements/racine/etc/passwd", Refus::Lien),
            ("~/Documents/lien.pdf", Refus::Lien),
            ("~/Bureau/id_ed25519", Refus::RacineEnLien),
            ("~/Téléchargements/environ", Refus::Lien),
            ("/proc/self/environ", Refus::HorsDesEndroits),
            ("~/Téléchargements/zero", Refus::Lien),
            ("/dev/zero", Refus::HorsDesEndroits),
            ("~/Téléchargements/tube", Refus::PasUnFichier),
            ("~/Téléchargements", Refus::HorsDesEndroits),
            ("~/Téléchargements/.cache/x.pdf", Refus::Cache),
            ("~/Téléchargements/absent.pdf", Refus::Introuvable),
        ] {
            let attendu = crate::trf!("valeur refusée : {}", "value refused: {}", refus.phrase());
            assert_eq!(jugee(Commande::VerifierFichier, v, &compte), Err(attendu), "{v:?}");
        }
        // Sans maison connue, aucun chemin ne passe ; le reste (mots, jours) ne lit rien et passe rejugé.
        let sans = Compte {
            maison: None,
            config: None,
            nom: None,
        };
        assert!(jugee(Commande::VerifierFichier, &reel("facture.pdf"), &sans).is_err());
        assert!(jugee(Commande::Chercher, "pare-feu", &sans).is_ok());
        assert!(jugee(Commande::DernieresFailles, "30", &sans).is_ok());
        // Une commande qui ne part qu'avec sa valeur, demandée sans elle : refusée ; une autre passe telle quelle.
        assert!(rejuger(&Lancement::Commande(Commande::Chercher), &compte).is_err());
        assert_eq!(
            rejuger(&Lancement::Commande(Commande::Bilan), &compte),
            Ok(Lancement::Commande(Commande::Bilan))
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// user-dirs.dirs posé en lien (vers un fichier qui déclarerait ~/.ssh comme Téléchargements) ne déclare rien :
    /// lu sans suivre de lien, il est vide, et seuls les noms usuels servent.
    #[test]
    fn user_dirs_en_lien_ne_declare_rien() {
        let d = crate::essais::banc("user-dirs-lien");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let vrai = d.join("ailleurs.dirs");
        std::fs::write(&vrai, "XDG_DOWNLOAD_DIR=\"$HOME/Telechargements\"\n").unwrap();
        std::os::unix::fs::symlink(&vrai, d.join("user-dirs.dirs")).unwrap();
        assert_eq!(lire_declares(&vrai), "XDG_DOWNLOAD_DIR=\"$HOME/Telechargements\"\n");
        assert_eq!(lire_declares(&d.join("user-dirs.dirs")), "");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Pour de vrai, avec un faux `vanguard` qui note ce qu'on lui passe : un fichier de Téléchargements part par son
    /// chemin réel, en une case après « -- » ; un chemin vers ~/.ssh finit « impossible » sans que rien ne soit lancé.
    #[test]
    fn le_relais_ne_lance_que_le_chemin_rejuge() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let (d, compte) = maison_piegee("relais-valeur");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        let script = d.join("vanguard");
        std::fs::write(
            &script,
            "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done >> \"$(dirname \"$0\")/lances\"\necho '{}'\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let moi = std::fs::metadata(&d).unwrap().uid();
        let (fenetre, relais) = UnixStream::pair().unwrap();
        let dossier = d.clone();
        let serveur = std::thread::spawn(move || servir_pour(relais, move || Programme::dans(&dossier, moi), &compte));
        let c = Client::demarrer(fenetre, None);
        let rien: Reveil = Arc::new(|| {});
        let lances = || std::fs::read_to_string(d.join("lances")).unwrap_or_default();
        let av = |v: &str| Lancement::AvecValeur(AvecValeur::nouvelle(Commande::VerifierFichier, v).unwrap());
        let f = attendre_fin(&c.lancer(av("~/.ssh/id_ed25519"), false, &rien));
        assert!(
            matches!(&f.issue, Issue::Impossible(r) if !r.contains("ssh")),
            "{:?}",
            f.issue
        );
        assert_eq!(lances(), "");
        let f = attendre_fin(&c.lancer(av("~/Téléchargements/cle"), false, &rien));
        assert!(matches!(f.issue, Issue::Impossible(_)), "{:?}", f.issue);
        assert_eq!(lances(), "");
        let f = attendre_fin(&c.lancer(av("~/Téléchargements/ma facture.pdf"), false, &rien));
        assert_eq!(f.code, Some(0), "{:?}", f.issue);
        let reel = d.join("alice/Téléchargements/ma facture.pdf");
        assert_eq!(
            lances(),
            format!("console\nverifier-fichier\n--\n{}\n", reel.to_str().unwrap())
        );
        c.fermer();
        serveur.join().unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une fenêtre prise n'a pas `AvecValeur::nouvelle` : elle écrit ses octets elle-même. Chaque trame 7 forgée à la
    /// main avec une valeur hostile (option, tiret, bidi, saut de ligne, NUL, mauvaise sorte, longueur qui ment) ferme
    /// le relais sans rien lancer ; la même trame avec une bonne valeur, elle, lance la lecture : la forge est juste.
    #[test]
    fn une_trame_de_valeur_forgee_ne_lance_rien() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let (d, compte) = maison_piegee("relais-forge");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        let script = d.join("vanguard");
        std::fs::write(
            &script,
            "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done >> \"$(dirname \"$0\")/lances\"\necho '{}'\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let moi = std::fs::metadata(&d).unwrap().uid();
        let rang = |c: Commande| u8::try_from(Commande::TOUTES.iter().position(|x| *x == c).unwrap()).unwrap();
        let forger = |c: Commande, sorte: Argument, valeur: &[u8], longueur: usize| {
            let mut t = vec![7, 1, 0, 0, 0, rang(c), sorte.octet(), 0];
            t.extend(u16::try_from(longueur).unwrap().to_le_bytes());
            t.extend(valeur);
            t
        };
        let lances = || std::fs::read_to_string(d.join("lances")).unwrap_or_default();
        let envoyer_ou_attendre = |trame: Vec<u8>, attendre: bool| {
            let (fenetre, relais) = UnixStream::pair().unwrap();
            let dossier = d.clone();
            let compte = Compte {
                maison: compte.maison.clone(),
                config: compte.config.clone(),
                nom: compte.nom.clone(),
            };
            let serveur =
                std::thread::spawn(move || servir_pour(relais, move || Programme::dans(&dossier, moi), &compte));
            ecrire_trame(&mut &fenetre, &trame).unwrap();
            // Une lecture lancée s'arrête quand la fenêtre se ferme : sa trace est attendue avant de fermer (une
            // demi-seconde pour une trame hostile, qui, admise par erreur, aurait ainsi le temps de se voir).
            let delai = Duration::from_millis(if attendre { 10_000 } else { 500 });
            let debut = Instant::now();
            while lances().is_empty() && debut.elapsed() < delai {
                std::thread::sleep(Duration::from_millis(10));
            }
            fenetre.shutdown(std::net::Shutdown::Write).unwrap();
            let mut reponse = Vec::new();
            let _ = std::io::Read::read_to_end(&mut &fenetre, &mut reponse);
            serveur.join().unwrap();
        };
        let envoyer = |trame: Vec<u8>| envoyer_ou_attendre(trame, false);
        let hostiles: [(Commande, &[u8]); 12] = [
            (Commande::Lien, b"--internet"),
            (Commande::Chercher, b"-x"),
            (Commande::Chercher, "a\u{202E}b".as_bytes()),
            (Commande::Chercher, "a\u{2066}b".as_bytes()),
            (Commande::Chercher, b"x\ny"),
            (Commande::Chercher, b"x\0y"),
            (Commande::Chercher, b" "),
            (Commande::Chercher, b""),
            (Commande::Chercher, b"\xff\xfe"),
            (Commande::VerifierFichier, b"--appliquer"),
            (Commande::VerifierFichier, b"../../.ssh/id_ed25519"),
            (Commande::DernieresFailles, b"3651"),
        ];
        for (c, v) in hostiles {
            envoyer(forger(c, c.argument().unwrap(), v, v.len()));
            assert_eq!(lances(), "", "{c:?} {:?}", String::from_utf8_lossy(v));
        }
        let bonne = "~/Téléchargements/facture.pdf".as_bytes();
        // La sorte d'une autre commande, ou une longueur qui ment d'un octet : refusées aussi.
        envoyer(forger(Commande::VerifierFichier, Argument::Mots, bonne, bonne.len()));
        envoyer(forger(
            Commande::VerifierFichier,
            Argument::Chemin,
            bonne,
            bonne.len() + 1,
        ));
        envoyer(forger(
            Commande::VerifierFichier,
            Argument::Chemin,
            bonne,
            bonne.len() - 1,
        ));
        envoyer(forger(Commande::Bilan, Argument::Chemin, bonne, bonne.len()));
        assert_eq!(lances(), "");
        envoyer_ou_attendre(
            forger(Commande::VerifierFichier, Argument::Chemin, bonne, bonne.len()),
            true,
        );
        let reel = d.join("alice/Téléchargements/facture.pdf");
        assert_eq!(
            lances(),
            format!("console\nverifier-fichier\n--\n{}\n", reel.to_str().unwrap())
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Pour de vrai, avec un faux `vanguard` : un changement n'est accepté que pour une empreinte de la dernière
    /// liste relayée, et cette liste ne sert qu'une fois ; il passe seul (refusé pendant une lecture, et rien ne se
    /// lance pendant lui) ; « Arrêter » ne le coupe pas, la fermeture de la fenêtre non plus.
    #[test]
    fn un_changement_vu_passe_seul_et_ne_se_coupe_pas() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = crate::essais::banc("relais");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let (e1, e2) = ("0123456789abcdef0123456789abcdef", "f".repeat(32));
        let a = "0a".repeat(32);
        std::fs::write(
            d.join("liste.json"),
            format!(
                r#"{{"outil": "PRO-DEM-001", "constats": [{{"categorie": "Démarrage", "objet": "demarrage:Lecteur",
                "geste": {{"sorte": "retirer", "empreinte": "{e1}", "nom": "Lecteur", "commande": "/usr/bin/lecteur", "accord": "{a}"}}}},
                {{"message": "Faux — \"empreinte\": \"{e2}\""}}]}}"#
            ),
        )
        .unwrap();
        let script = d.join("vanguard");
        std::fs::write(&script, FAUX_VANGUARD).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let moi = std::fs::metadata(&d).unwrap().uid();
        let (fenetre, relais) = UnixStream::pair().unwrap();
        let dossier = d.clone();
        let serveur = std::thread::spawn(move || servir(relais, move || Programme::dans(&dossier, moi)));
        let c = Client::demarrer(fenetre, None);
        let rien: Reveil = Arc::new(|| {});
        let changements = || std::fs::read_to_string(d.join("changements")).unwrap_or_default();
        let changement = |e: &str| {
            Lancement::Changement(Changement {
                sorte: Sorte::Retirer,
                empreinte: Empreinte::lire(e).unwrap(),
                accord: Accord::lire(&a).unwrap(),
            })
        };
        let refuse = |l: Lancement, motif: &str| {
            let f = attendre_fin(&c.lancer(l, false, &rien));
            assert!(
                matches!(&f.issue, Issue::Impossible(r) if r.contains(motif)),
                "{motif} : {:?}",
                f.issue
            );
        };
        let lire_la_liste = || {
            let f = attendre_fin(&c.lancer(Commande::Demarrage.into(), false, &rien));
            assert_eq!((&f.issue, f.code), (&Issue::Terminee, Some(0)), "{:?}", f.issue);
        };
        let commence = || {
            let debut = Instant::now();
            while !changements().ends_with(
                "--json
",
            ) {
                assert!(debut.elapsed() < Duration::from_secs(20), "jamais commencé");
                std::thread::sleep(Duration::from_millis(20));
            }
        };

        // Avant toute liste, puis pour une empreinte absente de la liste (ou seulement citée dans un texte) : refusé.
        refuse(changement(e1), "dernière liste");
        lire_la_liste();
        refuse(changement(&e2), "dernière liste");
        // Une lecture tourne : le changement attend son tour (refusé), la liste reste bonne.
        let lecture = c.lancer(Commande::Protection.into(), false, &rien);
        refuse(changement(e1), "un changement à la fois");
        std::fs::write(d.join("va-lecture"), b"").unwrap();
        assert_eq!(attendre_fin(&lecture).issue, Issue::Terminee);
        assert_eq!(changements(), "");

        // Le changement part ; pendant lui, rien d'autre ; « Arrêter » ne le coupe pas.
        let t = c.lancer(changement(e1), false, &rien);
        let id = c.suivant.load(Ordering::Relaxed) - 1;
        commence();
        refuse(Commande::Protection.into(), "un changement est en cours");
        refuse(changement(e1), "un changement est en cours");
        c.arreter(id);
        std::thread::sleep(Duration::from_millis(500));
        assert!(!t.recevoir().iter().any(|m| matches!(m, Message::Fin(_))));
        std::fs::write(d.join("va"), b"").unwrap();
        let f = attendre_fin(&t);
        assert_eq!((&f.issue, f.code), (&Issue::Terminee, Some(0)), "{:?}", f.issue);
        // L'accord de la liste est rendu tel quel (M-2).
        assert_eq!(
            changements(),
            format!("demarrage --retirer {e1} --accord {a} --json\nfini\n")
        );
        // La liste a servi : relue avant le suivant.
        refuse(changement(e1), "dernière liste");

        // La fenêtre se ferme pendant un changement : il finit quand même.
        std::fs::remove_file(d.join("va")).unwrap();
        lire_la_liste();
        let _t = c.lancer(changement(e1), false, &rien);
        let debut = Instant::now();
        while changements().lines().count() < 3 {
            assert!(debut.elapsed() < Duration::from_secs(20), "jamais commencé");
            std::thread::sleep(Duration::from_millis(20));
        }
        c.fermer();
        std::thread::sleep(Duration::from_millis(500));
        std::fs::write(d.join("va"), b"").unwrap();
        serveur.join().unwrap();
        assert_eq!(
            changements().lines().filter(|l| *l == "fini").count(),
            2,
            "{}",
            changements()
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un relais d'essai avec le faux `vanguard` et cette liste, dans un dossier jetable des essais : le dossier,
    /// la fenêtre et le fil du relais.
    fn banc_du_relais(nom: &str, liste: &str) -> (std::path::PathBuf, Client, std::thread::JoinHandle<()>) {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = crate::essais::banc(nom);
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(d.join("liste.json"), liste).unwrap();
        std::fs::write(d.join("va"), b"").unwrap();
        let script = d.join("vanguard");
        std::fs::write(&script, FAUX_VANGUARD).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let moi = std::fs::metadata(&d).unwrap().uid();
        let (fenetre, relais) = UnixStream::pair().unwrap();
        let dossier = d.clone();
        let serveur = std::thread::spawn(move || servir(relais, move || Programme::dans(&dossier, moi)));
        (d, Client::demarrer(fenetre, None), serveur)
    }

    /// Pour de vrai : la liste n'offre que « retirer » pour le Lecteur ; une fenêtre prise en main demande
    /// « remettre » avec la même empreinte. Le relais, qui a vu la liste, refuse cette sorte et ne lance rien.
    #[test]
    fn le_relais_refuse_la_sorte_que_la_liste_n_offrait_pas() {
        let e1 = "0123456789abcdef0123456789abcdef";
        let (d, c, serveur) = banc_du_relais(
            "relais-sorte",
            &format!(
                r#"{{"outil": "PRO-DEM-001", "constats": [{{"objet": "demarrage:Lecteur",
                "geste": {{"sorte": "retirer", "empreinte": "{e1}", "nom": "Lecteur", "commande": "/usr/bin/lecteur"}}}}]}}"#
            ),
        );
        let rien: Reveil = Arc::new(|| {});
        let f = attendre_fin(&c.lancer(Commande::Demarrage.into(), false, &rien));
        assert_eq!((&f.issue, f.code), (&Issue::Terminee, Some(0)));
        let f = attendre_fin(&c.lancer(
            Lancement::Changement(Changement {
                sorte: Sorte::Remettre,
                empreinte: Empreinte::lire(e1).unwrap(),
                accord: Accord::NUL,
            }),
            false,
            &rien,
        ));
        let lances = std::fs::read_to_string(d.join("changements")).unwrap_or_default();
        c.fermer();
        serveur.join().unwrap();
        let _ = std::fs::remove_dir_all(&d);
        assert!(
            matches!(&f.issue, Issue::Impossible(r) if r.contains("n'offrait pas")) && lances.is_empty(),
            "{:?} ; lancé : {lances}",
            f.issue
        );
    }

    /// Une limite dite par le modèle de menace, gardée telle quelle : le relais ne met aucune pause entre deux
    /// changements (une fenêtre prise en main peut enchaîner liste et changement). Douze programmes ordinaires
    /// retirés à la suite passent tous ; si un jour une cadence est imposée, cet essai et le texte changent ensemble.
    #[test]
    fn le_relais_n_impose_aucun_intervalle_entre_deux_changements() {
        use std::fmt::Write as _;
        let mut constats = String::new();
        for i in 0..12 {
            let _ = write!(
                constats,
                r#"{}{{"objet": "demarrage:P{i}", "geste": {{"sorte": "retirer", "empreinte": "{i:032x}", "nom": "P{i}", "commande": "/usr/bin/p{i}"}}}}"#,
                if i == 0 { "" } else { "," }
            );
        }
        let (d, c, serveur) = banc_du_relais(
            "relais-rafale",
            &format!(r#"{{"outil": "PRO-DEM-001", "constats": [{constats}]}}"#),
        );
        let rien: Reveil = Arc::new(|| {});
        let mut faits = 0;
        for i in 0..12 {
            let f = attendre_fin(&c.lancer(Commande::Demarrage.into(), false, &rien));
            assert_eq!(f.issue, Issue::Terminee);
            let f = attendre_fin(&c.lancer(
                Lancement::Changement(Changement {
                    sorte: Sorte::Retirer,
                    empreinte: Empreinte::lire(&format!("{i:032x}")).unwrap(),
                    accord: Accord::NUL,
                }),
                false,
                &rien,
            ));
            if f.issue == Issue::Terminee {
                faits += 1;
            }
        }
        let lances = std::fs::read_to_string(d.join("changements")).unwrap_or_default();
        c.fermer();
        serveur.join().unwrap();
        let _ = std::fs::remove_dir_all(&d);
        assert_eq!(
            lances.lines().filter(|l| l.starts_with("demarrage --retirer")).count(),
            faits
        );
        assert_eq!(faits, 12);
    }

    /// Des noms et des commandes hostiles, écrits par un vrai sérialiseur JSON (comme `vanguard` le fait), essaient
    /// de fabriquer un geste : seul celui de la liste est vu, avec sa sorte.
    #[test]
    fn aucun_nom_ne_fabrique_un_geste_vu() {
        let (vraie, glissee) = ("0123456789abcdef0123456789abcdef", "f".repeat(32));
        let hostiles = [
            format!("\"empreinte\": \"{glissee}\""),
            format!("\\\"empreinte\\\": \\\"{glissee}\\\""),
            format!("\\\\\"empreinte\": \"{glissee}\""),
            format!("x\"}}, {{\"empreinte\":\"{glissee}\""),
            format!("\"empreinte\"\n:\n\"{glissee}\""),
            format!("\u{0}\"empreinte\":\"{glissee}\""),
            format!("\"geste\": {{\"sorte\": \"remettre\", \"empreinte\": \"{glissee}\"}}"),
            "empreinte".to_string(),
            glissee.clone(),
            format!("\"accord\": \"{}\"", "ee".repeat(32)),
        ];
        let accord = "a1".repeat(32);
        let attendus: HashMap<Empreinte, (Sorte, Accord)> = Empreinte::lire(vraie)
            .into_iter()
            .map(|e| (e, (Sorte::Retirer, Accord::lire(&accord).unwrap())))
            .collect();
        for h in &hostiles {
            for joli in [false, true] {
                let v = serde_json::json!({
                    "outil": "PRO-DEM-001",
                    "constats": [
                        {"objet": format!("demarrage:{h}"), "message": h, "categorie": h,
                         "geste": {"sorte": "retirer", "empreinte": vraie, "nom": h, "commande": h, "accord": accord}},
                        {"objet": h, "message": [h, "empreinte", glissee]},
                    ],
                });
                let texte = if joli {
                    serde_json::to_string_pretty(&v).unwrap()
                } else {
                    serde_json::to_string(&v).unwrap()
                };
                assert_eq!(gestes_vus(texte.as_bytes()), attendus, "{h:?} : {texte}");
            }
        }
    }

    /// Les gestes d'un bilan : le jeton (32 chiffres hexadécimaux minuscules) avec sa sorte, lus dans le même objet
    /// `geste` ; ni sorte inconnue (dont celles du démarrage), ni jeton mal formé, ni geste glissé dans un message, ni
    /// geste qui porte un autre champ ; un jeton offert deux fois n'est pas retenu ; borné.
    #[test]
    fn seuls_les_gestes_offerts_du_bilan_sont_retenus() {
        use std::fmt::Write as _;
        let (j1, j2, j3, j4) = (
            "0123456789abcdef0123456789abcdef",
            "a".repeat(32),
            "b".repeat(32),
            "d".repeat(32),
        );
        let bilan = format!(
            r#"{{"score": 80, "constats": [{{"regle": "SSH-001", "geste": {{"sorte": "voir-correction", "jeton": "{j1}"}}}},
            {{"geste": {{"jeton": "{j2}", "sorte": "voir-correction"}}}}, {{"geste": {{"sorte": "retirer", "jeton": "{j3}"}}}},
            {{"geste": {{"sorte": "voir-correction", "empreinte": "{j3}"}}}}, {{"geste": {{"jeton": "{j3}"}}}},
            {{"message": "x\", \"geste\": {{\"sorte\": \"voir-correction\", \"jeton\": \"{j4}\"}}"}},
            {{"geste": {{"sorte": "voir-correction", "jeton": "{j4}"}}}}, {{"geste": {{"sorte": "voir-correction", "jeton": "{j4}"}}}},
            {{"geste": {{"sorte": "voir-correction", "jeton": "{}"}}}}, {{"geste": {{"sorte": "voir-correction", "jeton": "{}"}}}},
            {{"geste": {{"sorte": "voir-correction", "jeton": 7}}}}, {{"jeton": "{j3}", "sorte": "voir-correction"}}, "geste",
            {{"geste": {{"sorte": "voir-correction", "jeton": "{}", "nom": "Lecteur"}}}}]}}"#,
            "C".repeat(32),
            "c".repeat(33),
            "e".repeat(32)
        );
        let attendus: HashSet<(Empreinte, SorteGeste)> = [j1, j2.as_str()]
            .into_iter()
            .filter_map(|j| Some((Empreinte::lire(j)?, SorteGeste::VoirCorrection)))
            .collect();
        assert_eq!(gestes_offerts(bilan.as_bytes(), Famille::Correction), attendus);
        for rien in [
            &b""[..],
            b"\"jeton\"",
            b"{\"constats\": 7}",
            b"[1, 2]",
            b"une ligne\n{\"constats\": []}",
        ] {
            assert!(gestes_offerts(rien, Famille::Correction).is_empty());
        }
        let mut beaucoup = String::from(r#"{"constats": ["#);
        for i in 0..EMPREINTES_MAX + 10 {
            let _ = write!(
                beaucoup,
                r#"{{"geste": {{"sorte": "voir-correction", "jeton": "{i:032x}"}}}},"#
            );
        }
        beaucoup.push_str("{}]}");
        assert_eq!(
            gestes_offerts(beaucoup.as_bytes(), Famille::Correction).len(),
            EMPREINTES_MAX
        );
    }

    /// Vérification n° 2 de Fable, P3 : la fenêtre et le relais lisent le geste d'un constat avec la même structure.
    /// Un jeton suivi d'un sélecteur ou entouré d'une séquence d'échappement (que le nettoyage de la fenêtre retirait),
    /// un champ `null`, une empreinte vide à côté du jeton : ni bouton dans la fenêtre, ni geste admis par le relais.
    /// Le bon geste : les deux.
    #[test]
    fn la_fenetre_n_offre_que_ce_que_le_relais_admet() {
        let j = "0123456789abcdef0123456789abcdef";
        let bilan = |geste: &str| {
            format!(
                r#"{{"systeme": "Linux", "constats": [{{"etat": "probleme", "probleme": "Moyen", "message": "SSH", "geste": {geste}}}]}}"#
            )
        };
        let vus = |geste: &str| {
            let texte = bilan(geste);
            let fenetre: Vec<Empreinte> = crate::donnees::bilan::lire(texte.as_bytes())
                .unwrap()
                .constats
                .into_iter()
                .filter_map(|c| c.correction)
                .collect();
            let relais: Vec<Empreinte> = gestes_offerts(texte.as_bytes(), Famille::Correction)
                .into_iter()
                .map(|(e, _)| e)
                .collect();
            (fenetre, relais)
        };
        let bon = Empreinte::lire(j).unwrap();
        assert_eq!(
            vus(&format!(r#"{{"sorte": "voir-correction", "jeton": "{j}"}}"#)),
            (vec![bon], vec![bon])
        );
        for faux in [
            format!(r#"{{"sorte": "voir-correction", "jeton": "{j}\ufe0f"}}"#),
            format!(r#"{{"sorte": "voir-correction", "jeton": "\u001b[0m{j}"}}"#),
            format!(r#"{{"sorte": "voir-correction", "jeton": "{j}\u001b]0;x\u0007"}}"#),
            format!(r#"{{"sorte": "voir-correction\u200b", "jeton": "{j}"}}"#),
            format!(r#"{{"sorte": "voir-correction", "jeton": "{j}", "nom": null}}"#),
            format!(r#"{{"sorte": "voir-correction", "jeton": "{j}", "empreinte": ""}}"#),
            format!(r#"{{"sorte": "voir-correction", "jeton": "{j}", "machine": null}}"#),
            r#"{"sorte": "voir-correction", "jeton": null}"#.to_string(),
            format!(r#"{{"sorte": null, "jeton": "{j}"}}"#),
        ] {
            assert_eq!(vus(&faux), (vec![], vec![]), "{faux}");
        }
    }

    /// Un geste n'est admis que pour un jeton offert par le dernier bilan, avec sa sorte ; un « voir » n'use pas la
    /// liste, n'est pas un changement (« Arrêter » le coupe) et ne passe pas pendant un changement.
    #[test]
    fn un_geste_que_le_bilan_n_offrait_pas_est_refuse() {
        let j = Empreinte::lire("0123456789abcdef0123456789abcdef").unwrap();
        let autre = Empreinte::lire(&"f".repeat(32)).unwrap();
        let arret = Arc::new(AtomicBool::new(false));
        let voir = |j| Lancement::Geste(Geste::voir_correction(j));
        let mut etat = Etat::default();
        assert!(etat.admettre(1, &voir(j), &arret).is_some(), "sans bilan");
        etat.offerts = [(j, SorteGeste::VoirCorrection)].into();
        assert!(etat.admettre(2, &voir(autre), &arret).is_some(), "jeton non offert");
        assert!(etat.taches.is_empty());
        assert_eq!(etat.admettre(3, &voir(j), &arret), None);
        assert!(!etat.taches[&3].changement);
        etat.taches.clear();
        assert_eq!(etat.admettre(4, &voir(j), &arret), None, "la liste sert encore");
        etat.taches.clear();
        let e = Empreinte::lire(&"e".repeat(32)).unwrap();
        etat.vues = [(e, (Sorte::Retirer, Accord::NUL))].into();
        let ch = Lancement::Changement(Changement {
            sorte: Sorte::Retirer,
            empreinte: e,
            accord: Accord::NUL,
        });
        assert_eq!(etat.admettre(5, &ch, &arret), None);
        assert!(etat.admettre(6, &voir(j), &arret).is_some(), "pendant un changement");
    }

    /// Pour de vrai, avec le faux `vanguard` : un aperçu demandé avant tout bilan, ou pour un jeton que le bilan
    /// n'offrait pas, est refusé sans rien lancer ; après le bilan, il part avec la forme fixe `correction --voir
    /// <jeton> --json` ; un bilan suivant qui n'offre plus rien retire le geste.
    #[test]
    fn le_relais_ne_voit_que_les_corrections_du_dernier_bilan() {
        let (j1, j2) = ("0123456789abcdef0123456789abcdef", "f".repeat(32));
        let (d, c, serveur) = banc_du_relais("relais-gestes", "{}");
        std::fs::write(
            d.join("bilan.json"),
            format!(r#"{{"constats": [{{"geste": {{"sorte": "voir-correction", "jeton": "{j1}"}}}}]}}"#),
        )
        .unwrap();
        let rien: Reveil = Arc::new(|| {});
        let voir = |j: &str| Lancement::Geste(Geste::voir_correction(Empreinte::lire(j).unwrap()));
        let gestes = || std::fs::read_to_string(d.join("gestes")).unwrap_or_default();
        let avant = attendre_fin(&c.lancer(voir(j1), false, &rien));
        let rien_lance = gestes();
        let bilan = attendre_fin(&c.lancer(Commande::Bilan.into(), false, &rien));
        let autre = attendre_fin(&c.lancer(voir(&j2), false, &rien));
        let vu = attendre_fin(&c.lancer(voir(j1), true, &rien));
        let lances = gestes();
        std::fs::write(d.join("bilan.json"), r#"{"constats": []}"#).unwrap();
        let _ = attendre_fin(&c.lancer(Commande::Bilan.into(), false, &rien));
        let apres = attendre_fin(&c.lancer(voir(j1), false, &rien));
        let lances_apres = gestes();
        c.fermer();
        serveur.join().unwrap();
        let _ = std::fs::remove_dir_all(&d);
        assert!(
            matches!(&avant.issue, Issue::Impossible(r) if r.contains("bilan")),
            "{:?}",
            avant.issue
        );
        assert!(rien_lance.is_empty(), "{rien_lance}");
        assert_eq!((&bilan.issue, bilan.code), (&Issue::Terminee, Some(0)));
        assert!(matches!(&autre.issue, Issue::Impossible(_)), "{:?}", autre.issue);
        assert_eq!((&vu.issue, vu.code), (&Issue::Terminee, Some(0)), "{:?}", vu.issue);
        assert_eq!(lances, format!("correction --voir {j1} --json\n"));
        assert!(matches!(&apres.issue, Issue::Impossible(_)), "{:?}", apres.issue);
        assert_eq!(lances_apres, lances);
    }

    /// Un geste qui change n'est admis qu'avec le jeton et l'accord exacts du dernier aperçu relayé de sa famille,
    /// 2 s au moins et 10 minutes au plus après sa fin, sans autre commande en cours ; admis, il consomme l'aperçu et
    /// la liste de sa famille (un second envoi est refusé) ; un refus ne consomme rien ; l'aperçu de l'autre famille
    /// ne compte pas.
    #[test]
    fn un_geste_qui_change_ne_part_qu_apres_son_apercu() {
        let j = Empreinte::lire("0123456789abcdef0123456789abcdef").unwrap();
        let autre = Empreinte::lire(&"f".repeat(32)).unwrap();
        let a = Accord::lire(&"a1".repeat(32)).unwrap();
        let b = Accord::lire(&"b2".repeat(32)).unwrap();
        let arret = Arc::new(AtomicBool::new(false));
        let appliquer = |j, a| Lancement::Geste(Geste::changer(Famille::Correction, j, a));
        let annuler = |j, a| Lancement::Geste(Geste::changer(Famille::Annulation, j, a));
        let il_y_a = |d: Duration| Instant::now().checked_sub(d).unwrap();
        let mut etat = Etat {
            offerts: [(j, SorteGeste::VoirCorrection), (autre, SorteGeste::VoirAnnulation)].into(),
            ..Etat::default()
        };

        assert!(etat.admettre(1, &appliquer(j, a), &arret).is_some(), "sans aperçu");
        etat.montres.insert(Famille::Correction, (j, a, Instant::now()));
        let r = etat.admettre(2, &appliquer(j, a), &arret);
        assert!(r.is_some_and(|r| r.contains("2 s")), "trop tôt : {r:?}");
        etat.montres.insert(
            Famille::Correction,
            (j, a, il_y_a(APERCU_LU + Duration::from_millis(50))),
        );
        assert!(etat.admettre(3, &appliquer(autre, a), &arret).is_some(), "autre jeton");
        assert!(etat.admettre(4, &appliquer(j, b), &arret).is_some(), "autre accord");
        assert!(
            etat.admettre(5, &appliquer(j, Accord::NUL), &arret).is_some(),
            "accord nul"
        );
        assert!(
            etat.admettre(6, &annuler(j, a), &arret).is_some(),
            "aperçu de l'autre famille"
        );
        // Une lecture en cours : un changement attend qu'elle finisse.
        etat.taches.insert(
            99,
            EnCours {
                arret: Arc::clone(&arret),
                changement: false,
            },
        );
        assert!(
            etat.admettre(7, &appliquer(j, a), &arret).is_some(),
            "pendant une lecture"
        );
        etat.taches.clear();
        // Aucun refus n'a rien consommé.
        assert!(etat.montres.contains_key(&Famille::Correction));
        assert_eq!(etat.offerts.len(), 2);
        assert_eq!(etat.admettre(8, &appliquer(j, a), &arret), None);
        assert!(etat.taches[&8].changement);
        assert!(!etat.montres.contains_key(&Famille::Correction));
        assert_eq!(etat.offerts, [(autre, SorteGeste::VoirAnnulation)].into());
        etat.taches.clear();
        assert!(
            etat.admettre(9, &appliquer(j, a), &arret).is_some(),
            "consommé : une fois"
        );

        // Trop vieux.
        etat.montres.insert(
            Famille::Annulation,
            (autre, a, il_y_a(APERCU_VIEUX + Duration::from_secs(1))),
        );
        let r = etat.admettre(10, &annuler(autre, a), &arret);
        assert!(r.is_some_and(|r| r.contains("10 minutes")), "{r:?}");
        etat.montres.insert(Famille::Annulation, (autre, a, il_y_a(APERCU_LU)));
        assert_eq!(etat.admettre(11, &annuler(autre, a), &arret), None);
        assert!(etat.offerts.is_empty() && etat.montres.is_empty());
    }

    /// La mise à jour : son « voir » passe sans liste, avec son jeton seulement ; le geste qui l'installe suit le
    /// chemin commun (aperçu montré, même jeton, même accord, 2 s à 10 min, une fois) ; ni la liste du bilan ni
    /// celle des changements ne l'offrent ni ne la consomment. L'accord se retient de la dernière ligne de
    /// `se-mettre-a-jour --voir`.
    #[test]
    fn la_mise_a_jour_ne_passe_qu_apres_son_apercu() {
        let j = Empreinte::MISE_A_JOUR;
        let autre = Empreinte::lire(&"7".repeat(32)).unwrap();
        let a = Accord::lire(&"c3".repeat(32)).unwrap();
        let arret = Arc::new(AtomicBool::new(false));
        let voir = |j| Lancement::Geste(Geste::voir(Famille::MiseAJour, j));
        let installer = |j, a| Lancement::Geste(Geste::changer(Famille::MiseAJour, j, a));
        let mut etat = Etat {
            offerts: [(autre, SorteGeste::VoirCorrection)].into(),
            ..Etat::default()
        };
        assert_eq!(etat.admettre(1, &voir(j), &arret), None);
        etat.taches.clear();
        assert!(etat.admettre(2, &voir(autre), &arret).is_some(), "autre jeton");
        assert!(etat.admettre(3, &installer(j, a), &arret).is_some(), "sans aperçu");
        let fin = |sortie: &str| Fin {
            lancement: voir(j),
            code: Some(0),
            issue: Issue::Terminee,
            duree: Duration::ZERO,
            sortie: sortie.as_bytes().to_vec(),
        };
        let ligne = format!(
            r#"{{"geste":"voir-mise-a-jour","issue":"fait","raison":"","etat":"propose","accord":"{}","apercu":{{"jeton":"{}","origine":"github"}}}}"#,
            a.hex(),
            j.hex()
        );
        etat.retenir(&fin(&ligne));
        assert_eq!(etat.montres.get(&Famille::MiseAJour).map(|m| (m.0, m.1)), Some((j, a)));
        let r = etat.admettre(4, &installer(j, a), &arret);
        assert!(r.is_some_and(|r| r.contains("2 s")), "trop tôt : {r:?}");
        let il_y_a = Instant::now()
            .checked_sub(APERCU_LU + Duration::from_millis(50))
            .unwrap();
        etat.montres.insert(Famille::MiseAJour, (j, a, il_y_a));
        assert!(etat.admettre(5, &installer(autre, a), &arret).is_some(), "autre jeton");
        let b = Accord::lire(&"d4".repeat(32)).unwrap();
        assert!(etat.admettre(6, &installer(j, b), &arret).is_some(), "autre accord");
        assert_eq!(etat.admettre(7, &installer(j, a), &arret), None);
        assert!(etat.montres.is_empty());
        assert_eq!(etat.offerts, [(autre, SorteGeste::VoirCorrection)].into());
        etat.taches.clear();
        assert!(etat.admettre(8, &installer(j, a), &arret).is_some(), "une fois");
        // Une liste qui écrirait la mise à jour ne l'offre pas.
        let liste = format!(
            r#"{{"constats":[{{"geste":{{"sorte":"voir-mise-a-jour","jeton":"{}"}}}}]}}"#,
            j.hex()
        );
        for f in [Famille::Correction, Famille::Annulation, Famille::MiseAJour] {
            assert!(gestes_offerts(liste.as_bytes(), f).is_empty(), "{f:?}");
        }
    }

    /// L'accord retenu d'un aperçu : sa dernière ligne dit ce geste, « fait », le jeton demandé et un accord non nul ;
    /// et seulement d'un aperçu fini avec le code 0. Un autre aperçu de la famille le remplace, un aperçu qui ne
    /// montre rien le retire.
    #[test]
    fn seul_l_accord_d_un_apercu_montre_est_retenu() {
        let j = Empreinte::lire("0123456789abcdef0123456789abcdef").unwrap();
        let hex = j.hex();
        let acc = "a1".repeat(32);
        let g = Geste::voir(Famille::Correction, j);
        let fin = |code: i32, sortie: String| Fin {
            lancement: Lancement::Geste(g),
            code: Some(code),
            issue: Issue::Terminee,
            duree: Duration::ZERO,
            sortie: sortie.into_bytes(),
        };
        let ligne = |geste: &str, issue: &str, jeton: &str, accord: &str| {
            format!(
                r#"{{"geste":"{geste}","issue":"{issue}","raison":"","accord":"{accord}","apercu":{{"jeton":"{jeton}","x":1}}}}"#
            )
        };
        let bonne = ligne("voir-correction", "fait", &hex, &acc);
        assert_eq!(
            accord_montre(g, &fin(0, format!("avertissement\n{bonne}\n\n"))),
            Accord::lire(&acc)
        );
        for faux in [
            ligne("voir-annulation", "fait", &hex, &acc),
            ligne("voir-correction", "refuse", &hex, &acc),
            ligne("voir-correction", "fait", &"f".repeat(32), &acc),
            ligne("voir-correction", "fait", &hex, &"0".repeat(64)),
            ligne("voir-correction", "fait", &hex, "a1"),
            format!("{bonne}\n{{}}"),
            String::new(),
        ] {
            assert_eq!(accord_montre(g, &fin(0, faux.clone())), None, "{faux}");
        }
        let mut etat = Etat::default();
        etat.retenir(&fin(0, bonne.clone()));
        assert_eq!(
            etat.montres.get(&Famille::Correction).map(|m| (m.0, m.1)),
            Some((j, Accord::lire(&acc).unwrap()))
        );
        // Le code contredit « fait » : rien n'est retenu, l'aperçu d'avant est retiré.
        etat.retenir(&fin(1, bonne));
        assert!(etat.montres.is_empty());
    }

    /// Pour de vrai, avec le faux `vanguard` : après le bilan et l'aperçu, « appliquer » envoyé trop tôt, ou avec un
    /// autre accord, est refusé sans rien lancer ; 2 s après, avec l'accord de l'aperçu, il part une fois avec la
    /// forme fixe `correction --appliquer <jeton> --accord <accord> --json` ; renvoyé, il est refusé. De même pour
    /// remettre comme avant, depuis la liste de « Ce que Vanguard a changé ».
    #[test]
    fn le_relais_ne_laisse_partir_que_l_accord_montre_apres_deux_secondes() {
        let j = "0123456789abcdef0123456789abcdef";
        let k = "00112233445566778899aabbccddeeff";
        let (acc, autre) = ("a1".repeat(32), "b2".repeat(32));
        let (d, c, serveur) = banc_du_relais("relais-appliquer", "{}");
        let ecrire = |n: &str, t: &str| std::fs::write(d.join(n), t).unwrap();
        ecrire(
            "bilan.json",
            &format!(r#"{{"constats": [{{"geste": {{"sorte": "voir-correction", "jeton": "{j}"}}}}]}}"#),
        );
        ecrire(
            "apercu.json",
            &format!(
                r#"{{"geste":"voir-correction","issue":"fait","raison":"","accord":"{acc}","apercu":{{"jeton":"{j}"}}}}"#
            ),
        );
        ecrire(
            "changements.json",
            &format!(
                r#"{{"schema":1,"changements":[{{"etat":"annulable","geste":{{"sorte":"voir-annulation","jeton":"{k}"}}}}]}}"#
            ),
        );
        ecrire(
            "annulation.json",
            &format!(
                r#"{{"geste":"voir-annulation","issue":"fait","raison":"","accord":"{acc}","apercu":{{"jeton":"{k}"}}}}"#
            ),
        );
        let rien: Reveil = Arc::new(|| {});
        let gestes = || std::fs::read_to_string(d.join("gestes")).unwrap_or_default();
        let (ej, ek) = (Empreinte::lire(j).unwrap(), Empreinte::lire(k).unwrap());
        let lancer = |l: Lancement| attendre_fin(&c.lancer(l, false, &rien));
        let geste = |f, e, a: &str| Lancement::Geste(Geste::changer(f, e, Accord::lire(a).unwrap()));
        let voir = |f, e| Lancement::Geste(Geste::voir(f, e));

        assert_eq!(lancer(Commande::Bilan.into()).code, Some(0));
        assert_eq!(lancer(voir(Famille::Correction, ej)).code, Some(0));
        let trop_tot = lancer(geste(Famille::Correction, ej, &acc));
        std::thread::sleep(APERCU_LU + Duration::from_millis(100));
        let faux = lancer(geste(Famille::Correction, ej, &autre));
        let bon = lancer(geste(Famille::Correction, ej, &acc));
        let encore = lancer(geste(Famille::Correction, ej, &acc));
        let apres_correction = gestes();

        assert_eq!(lancer(Commande::Changements.into()).code, Some(0));
        assert_eq!(lancer(voir(Famille::Annulation, ek)).code, Some(0));
        let trop_tot_annuler = lancer(geste(Famille::Annulation, ek, &acc));
        std::thread::sleep(APERCU_LU + Duration::from_millis(100));
        let annule = lancer(geste(Famille::Annulation, ek, &acc));
        let revoir = lancer(voir(Famille::Annulation, ek));
        let tout = gestes();
        c.fermer();
        serveur.join().unwrap();
        let _ = std::fs::remove_dir_all(&d);

        assert!(
            matches!(&trop_tot.issue, Issue::Impossible(r) if r.contains("2 s")),
            "{:?}",
            trop_tot.issue
        );
        assert!(
            matches!(&faux.issue, Issue::Impossible(r) if r.contains("accord")),
            "{:?}",
            faux.issue
        );
        assert_eq!((&bon.issue, bon.code), (&Issue::Terminee, Some(0)), "{:?}", bon.issue);
        assert!(matches!(&encore.issue, Issue::Impossible(_)), "{:?}", encore.issue);
        assert_eq!(
            apres_correction,
            format!("correction --voir {j} --json\ncorrection --appliquer {j} --accord {acc} --json\n")
        );
        assert!(
            matches!(&trop_tot_annuler.issue, Issue::Impossible(r) if r.contains("2 s")),
            "{:?}",
            trop_tot_annuler.issue
        );
        assert_eq!(
            (&annule.issue, annule.code),
            (&Issue::Terminee, Some(0)),
            "{:?}",
            annule.issue
        );
        // Remise : la liste de sa famille est consommée, un nouvel aperçu demande une liste relue.
        assert!(matches!(&revoir.issue, Issue::Impossible(_)), "{:?}", revoir.issue);
        assert_eq!(
            tout,
            format!(
                "{apres_correction}changements --voir {k} --json\nchangements --annuler {k} --accord {acc} --json\n"
            )
        );
    }

    fn attendre_fin(t: &Tache) -> Fin {
        let debut = Instant::now();
        loop {
            if let Some(Message::Fin(f)) = t.recevoir().into_iter().find(|m| matches!(m, Message::Fin(_))) {
                return f;
            }
            assert!(debut.elapsed() < Duration::from_secs(20), "jamais fini");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Le dossier de l'essai du bac à sable, passé au processus d'essai relancé.
    const ESSAI_BAC: &str = "VANGUARD_FENETRE_ESSAI_BAC";
    /// La socket d'essai dans /tmp/.X11-unix, si elle a pu y être créée.
    const ESSAI_X11: &str = "VANGUARD_FENETRE_ESSAI_X11";

    /// Pour de vrai : le fil d'essai (la fenêtre) entre dans le bac à sable ; le relais, parti avant lui (comme le
    /// relais part avant que la fenêtre se restreigne), lance un faux `vanguard` qui écrit un fichier et lance un
    /// programme. La fenêtre, elle, ne peut ni écrire, ni lancer, ni se connecter, ni lire le dossier personnel (une
    /// fausse clé SSH dans un HOME jetable), ni joindre X11 sous Wayland (une socket d'essai dans /tmp/.X11-unix,
    /// comme celle de Xwayland). Dans un processus d'essai à part (ce même programme de tests, relancé sur ce seul
    /// test) : le bac ne se retire pas, il ne doit pas suivre les autres tests.
    #[test]
    fn le_bac_retient_la_fenetre_et_pas_ce_que_le_relais_lance() {
        use std::os::unix::fs::PermissionsExt;
        if let Some(d) = std::env::var_os(ESSAI_BAC) {
            return essai_dans_le_bac(std::path::Path::new(&d));
        }
        let d = crate::essais::banc("bac");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        // Sans « .. » : le bac ne suit pas un chemin de curseurs qui en a un (`Milieu::curseurs`).
        let d = std::fs::canonicalize(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        let f = d.join("vanguard");
        // Le faux `vanguard` : un fichier écrit, un programme lancé, une sortie JSON.
        std::fs::write(
            &f,
            "#!/bin/sh\necho ecrit > \"$(dirname \"$0\")/ecrit\" && /bin/sh -c 'echo \"{}\"'\n",
        )
        .unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Un HOME jetable : une fausse clé (valeur inventée), et un thème de curseurs, lui permis.
        let maison = d.join("maison");
        std::fs::create_dir_all(maison.join(".ssh")).unwrap();
        std::fs::write(maison.join(".ssh").join("id_rsa"), "cle-inventee-pour-l-essai\n").unwrap();
        std::fs::create_dir_all(maison.join(".icons").join("essai")).unwrap();
        std::fs::write(
            maison.join(".icons").join("essai").join("index.theme"),
            "[Icon Theme]\n",
        )
        .unwrap();
        // Une socket d'essai où X11 et Xwayland mettent les leurs (le dossier est ouvert à tous, collant).
        let x11 = std::path::Path::new("/tmp/.X11-unix").join(format!("vanguard-essai-{}", std::process::id()));
        let _ = std::fs::remove_file(&x11);
        let ecoute = std::os::unix::net::UnixListener::bind(&x11);
        let nom = "relais::tests::le_bac_retient_la_fenetre_et_pas_ce_que_le_relais_lance";
        let mut essai = std::process::Command::new(std::env::current_exe().unwrap());
        essai
            .args([nom, "--exact", "--nocapture", "--test-threads=1"])
            .env(ESSAI_BAC, &d)
            .env("HOME", &maison)
            .env("WAYLAND_DISPLAY", "vanguard-essai-absent")
            .env("DISPLAY", ":99")
            .stdin(std::process::Stdio::null());
        for v in [
            "WAYLAND_SOCKET",
            "XAUTHORITY",
            "XCURSOR_PATH",
            "XDG_DATA_HOME",
            "XDG_DATA_DIRS",
            "XCOMPOSEFILE",
        ] {
            essai.env_remove(v);
        }
        if ecoute.is_ok() {
            essai.env(ESSAI_X11, &x11);
        }
        let sortie = essai.output().unwrap();
        let texte = String::from_utf8_lossy(&sortie.stdout).into_owned() + &String::from_utf8_lossy(&sortie.stderr);
        drop(ecoute);
        let _ = std::fs::remove_file(&x11);
        let ecrit = std::fs::read(d.join("ecrit"));
        let _ = std::fs::remove_dir_all(&d);
        if let Some(raison) = texte.lines().find_map(|l| l.split_once("BAC-SAUTÉ ").map(|(_, r)| r)) {
            return crate::essais::sauter(raison);
        }
        assert!(sortie.status.success() && texte.contains("BAC-OK"), "{texte}");
        // Ce que le relais a lancé a écrit, lui (relu d'ici : la fenêtre, restreinte, ne lit pas ce dossier).
        assert_eq!(ecrit.unwrap(), b"ecrit\n");
        if let Some(raison) = texte.lines().find_map(|l| l.split_once("X11-SAUTÉ ").map(|(_, r)| r)) {
            crate::essais::sauter(raison);
        }
    }

    fn essai_dans_le_bac(d: &std::path::Path) {
        use std::os::unix::fs::MetadataExt;
        let moi = std::fs::metadata(d.join("vanguard")).unwrap().uid();
        let (fenetre, relais) = UnixStream::pair().unwrap();
        let dossier = d.to_path_buf();
        let serveur = std::thread::spawn(move || servir(relais, move || Programme::dans(&dossier, moi)));
        assert!(crate::bac_a_sable::sans_nouveaux_droits());
        let abi = match crate::bac_a_sable::poser() {
            Ok((abi, _, maison)) => {
                assert!(!maison);
                abi
            }
            Err(e) => {
                println!("BAC-SAUTÉ Landlock absent ({e})");
                return;
            }
        };
        // La fenêtre : ni écrire, ni lancer, ni (Landlock 4 et plus) se connecter.
        let ecrire = std::fs::write(d.join("de-la-fenetre"), b"x");
        assert_eq!(ecrire.unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
        assert!(std::process::Command::new("/bin/true").status().is_err());
        if abi >= 4 {
            let tcp = std::net::TcpStream::connect_timeout(&([127, 0, 0, 1], 9).into(), Duration::from_secs(2));
            assert_eq!(tcp.unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
        }
        // Ni le dossier personnel (la fausse clé), ni le dossier de l'essai (sous le vrai dossier personnel) ; le
        // système et les curseurs du compte, oui.
        let maison = std::path::PathBuf::from(std::env::var_os("HOME").unwrap());
        let cle = std::fs::read(maison.join(".ssh").join("id_rsa"));
        assert_eq!(cle.unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            std::fs::read_dir(&maison).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        let faux = std::fs::read(d.join("vanguard"));
        assert_eq!(faux.unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
        assert!(std::fs::read(maison.join(".icons").join("essai").join("index.theme")).is_ok());
        assert!(std::fs::read_dir("/usr").is_ok());
        // Sous Wayland (WAYLAND_DISPLAY posé par l'essai), pas d'X11, même avec DISPLAY : Landlock 9 et plus.
        match std::env::var_os(ESSAI_X11) {
            Some(x11) if abi >= 9 => {
                let x = std::os::unix::net::UnixStream::connect(&x11);
                assert_eq!(x.unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
            }
            Some(_) => println!("X11-SAUTÉ Landlock {abi} : les sockets nommées restent joignables"),
            None => println!("X11-SAUTÉ /tmp/.X11-unix absent ou fermé"),
        }
        // Ce que le relais lance, lui, a tous les droits du compte.
        let c = Client::demarrer(fenetre, None);
        let rien: Reveil = Arc::new(|| {});
        let f = attendre_fin(&c.lancer(Commande::Bilan.into(), false, &rien));
        assert_eq!(
            (f.lancement, &f.issue, f.code),
            (Commande::Bilan.into(), &Issue::Terminee, Some(0)),
            "{:?}",
            f.issue
        );
        assert_eq!(f.sortie, b"{}\n");
        c.fermer();
        serveur.join().unwrap();
        println!("BAC-OK");
    }
}

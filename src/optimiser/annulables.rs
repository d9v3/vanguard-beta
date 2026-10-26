//! Les annulations hors du catalogue d'Optimiser, par le même mécanisme : les corrections du bilan et les réglages
//! pour jouer. Chacune désigne ce qu'elle change par des gestes (`Geste`), dont la valeur est relevée juste avant
//! de l'appliquer et notée dans reglages.json, scellé ; elle se défait ensuite une par une (« Ce que Vanguard a
//! changé », menu Gaming) ou avec tout le reste (`crate::annulation`), et l'état d'avant est relu après coup. Ce qui
//! ne se relève pas est dit non annulable avant d'être appliqué. Relue, une note n'est crue que si chacun de ses
//! gestes désigne une cible de la liste fermée de son système et chacune de ses valeurs une forme que ce geste
//! écrit (`note_admise`) : elle est remise avec les droits d'administrateur. Les notes de Gaming d'avant (jeux.json,
//! jamais scellé) y sont reprises une fois, sans en perdre.

use std::borrow::Cow;
use std::path::Path;

use super::{
    Avant, Categorie, DNS, Historique, Reglage, Valeur, a_changer, catalogue_note, charger, charger_dans,
    executer_avec, note_admise, sauver_dans, systeme, valeurs_d_avant,
};
use crate::selection::{Case, cocher};
use crate::ui::*;

/// Devant l'id d'une correction du bilan notée (« `bilan:<id` unique> ») : chacune a sa note, même appliquée deux fois.
pub(crate) const BILAN: &str = "bilan:";
/// Devant l'id d'un réglage pour jouer (« jeux:hags ») : une note par réglage, la plus ancienne gardée.
pub(crate) const JEUX: &str = "jeux:";

/// Ce qu'une correction ou un réglage pour jouer change, désigné pour en relever la valeur d'avant puis la remettre :
/// « genre|cible » (« unite|cups-browsed », « fichier|/etc/sysctl.d/99-vanguard.conf »). Noté tel quel ; relu, il ne
/// vaut que s'il désigne une cible de la liste fermée de son système (`systeme::Changement::depuis_geste`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Geste(pub(crate) String);

#[cfg(target_os = "linux")]
impl Geste {
    /// Un service de systemd (son état : enabled, disabled…).
    pub(crate) fn unite(nom: &str) -> Geste {
        Geste(format!("unite|{nom}"))
    }

    /// Une clé de sysctl, en chemin ou en points (« kernel.kptr_restrict »).
    pub(crate) fn sysctl(cle: &str) -> Geste {
        Geste(format!("sysctl|{}", cle.replace('.', "/")))
    }

    /// Un fichier que Vanguard pose dans /etc.
    pub(crate) fn fichier(chemin: &str) -> Geste {
        Geste(format!("fichier|{chemin}"))
    }

    /// Un module du noyau.
    pub(crate) fn module(nom: &str) -> Geste {
        Geste(format!("module|{nom}"))
    }

    /// L'heure réglée par le réseau.
    pub(crate) fn ntp() -> Geste {
        Geste("ntp".into())
    }
}

#[cfg(unix)]
impl Geste {
    /// Les droits d'un fichier du dossier personnel.
    pub(crate) fn droits(chemin: &Path) -> Geste {
        Geste(format!("droits|{}", chemin.display()))
    }
}

#[cfg(windows)]
impl Geste {
    /// Une correction native de la liste fermée (« wdigest-coupe ») : sa valeur DWORD sous HKLM.
    pub(crate) fn natif(id: &str) -> Geste {
        Geste(format!("natif|{id}"))
    }

    /// Le type de démarrage d'un service.
    pub(crate) fn service(nom: &str) -> Geste {
        Geste(format!("service|{nom}"))
    }

    /// Une valeur du registre d'un réglage pour jouer (`gaming::windows`), de la machine ou du compte.
    pub(crate) fn registre(machine: bool, cle: &str, nom: &str) -> Geste {
        Geste(format!(
            "registre|{}|{cle}|{nom}",
            if machine { "hklm" } else { "hkcu" }
        ))
    }

    /// Une préférence de Defender réglée par Vanguard (« np », « pua », « cfa » ou une règle ASR de sa liste).
    pub(crate) fn defender(cle: &str) -> Geste {
        Geste(format!("defender|{cle}"))
    }

    /// Le mode d'alimentation actif.
    pub(crate) fn alimentation() -> Geste {
        Geste("alimentation".into())
    }
}

#[cfg(target_os = "macos")]
impl Geste {
    /// Une préférence de texte de la liste fermée (`defaults`).
    pub(crate) fn preference(domaine: &str, cle: &str) -> Geste {
        Geste(format!("preference|{domaine}|{cle}"))
    }
}

/// Un fichier du dossier personnel, sans « .. » : ses droits se remettent sans sudo, et une note ne peut pas en
/// viser un autre. Les tests travaillent dans le dossier temporaire, jamais dans le vrai dossier personnel.
#[cfg(unix)]
pub(crate) fn dans_la_maison(p: &Path) -> bool {
    let maison = crate::socle::maison();
    let sous = |base: &Path| base.is_absolute() && base.parent().is_some() && p.starts_with(base);
    p.is_absolute()
        && !p.components().any(|c| matches!(c, std::path::Component::ParentDir))
        && !p.to_string_lossy().contains(['\n', '\0'])
        && (sous(&maison) || (cfg!(test) && sous(&std::env::temp_dir())))
}

/// Les droits d'un fichier (« 0644 »), tels qu'on les remet ; `None` : illisible ou absent.
#[cfg(unix)]
pub(crate) fn droits_lus(p: &Path) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    let m = std::fs::metadata(p).ok()?;
    Some(format!("{:04o}", m.permissions().mode() & 0o7777))
}

/// Des droits notés : quatre chiffres octaux, sans setuid ni setgid (rien qu'un chmod du compte ne poserait pour
/// rendre un fichier lisible ou écrivable).
#[cfg(unix)]
pub(crate) fn droits_admis(v: &str) -> bool {
    v.len() == 4 && v.chars().all(|c| ('0'..='7').contains(&c)) && v.starts_with(['0', '1'])
}

/// Les valeurs d'avant d'une correction ou d'un réglage pour jouer, relevées juste avant de l'appliquer.
pub(crate) struct Releve {
    pub(crate) id: String,
    avant: Avant,
}

/// Pourquoi une correction ou un réglage pour jouer ne pourra pas s'annuler, dit avant d'être appliqué.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PourquoiPas {
    /// Vanguard ne sait pas relever son état d'avant (aucun geste).
    NonReleve,
    /// Elle remet en marche une protection, que Vanguard ne coupe jamais.
    Protection,
    /// Un geste hors de la liste fermée.
    HorsListe(String),
    /// L'état d'avant ne se lit pas (droits, outil absent).
    Illisible(String),
    /// L'état d'avant a une forme que Vanguard ne remettrait pas.
    Forme(String),
}

impl PourquoiPas {
    pub(crate) fn texte(&self) -> String {
        match self {
            PourquoiPas::NonReleve => tr!(
                "Vanguard ne sait pas relever l'état d'avant de cette correction",
                "Vanguard cannot read the state before this fix"
            )
            .to_string(),
            PourquoiPas::Protection => tr!(
                "elle remet en marche une protection, que Vanguard ne coupe jamais",
                "it turns a protection back on, which Vanguard never turns off"
            )
            .to_string(),
            PourquoiPas::HorsListe(g) => trf!(
                "« {} » n'est pas dans la liste de ce que Vanguard sait remettre",
                "“{}” is not in the list of what Vanguard can put back",
                affichable(g)
            ),
            PourquoiPas::Illisible(g) => trf!(
                "état d'avant illisible ({})",
                "state before unreadable ({})",
                affichable(g)
            ),
            PourquoiPas::Forme(g) => trf!(
                "état d'avant d'une forme que Vanguard ne remettrait pas ({})",
                "state before in a form Vanguard would not put back ({})",
                affichable(g)
            ),
        }
    }
}

/// Relève les valeurs d'avant de `gestes` sous l'id `id`. Erreur : pourquoi ce ne pourra pas s'annuler, à dire
/// avant d'appliquer.
pub(crate) fn relever(id: String, titre: &str, gestes: &[Geste]) -> Result<Releve, PourquoiPas> {
    if gestes.is_empty() {
        return Err(PourquoiPas::NonReleve);
    }
    let mut valeurs = Vec::with_capacity(gestes.len());
    for g in gestes {
        let Some(c) = systeme::Changement::depuis_geste(&g.0) else {
            return Err(PourquoiPas::HorsListe(g.0.clone()));
        };
        let Some(v) = c.relever() else {
            return Err(PourquoiPas::Illisible(g.0.clone()));
        };
        if !c.valeur_admise(v.as_deref()) {
            return Err(PourquoiPas::Forme(g.0.clone()));
        }
        valeurs.push(v);
    }
    Ok(Releve {
        id,
        avant: Avant {
            date: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
            valeurs,
            titre: Some(titre.to_string()),
            gestes: gestes.iter().map(|g| g.0.clone()).collect(),
        },
    })
}

/// Regroupe les relevés d'un lot (« `[t]out` appliquer ») qui touchent la même chose : tous pris avant d'appliquer,
/// ils notent le même état d'avant, qui n'existe qu'une fois. Chacun sa note, en annuler une remettait cet état et
/// défaisait les autres sans le dire, qui restaient annoncées « annulables ». Regroupés, ils n'ont qu'une note, dont
/// l'annulation marque défaites toutes les corrections qui y sont liées. Rend les relevés à noter (les regroupés
/// vides) et, pour chaque correction du lot, l'id de la note qui la défait.
pub(crate) fn regrouper(mut releves: Vec<Option<Releve>>) -> (Vec<Option<Releve>>, Vec<Option<String>>) {
    let mut chef: Vec<Option<usize>> = releves.iter().enumerate().map(|(i, r)| r.as_ref().map(|_| i)).collect();
    for j in 0..releves.len() {
        let Some(b) = releves[j].take() else { continue };
        let touches: Vec<usize> = (0..j)
            .filter(|&i| releves[i].as_ref().is_some_and(|a| a.touche_le_meme(&b)))
            .collect();
        let Some(&i) = touches.first() else {
            releves[j] = Some(b);
            continue;
        };
        // Deux notes jusque-là séparées que celle-ci relie n'en font plus qu'une.
        for &k in &touches[1..] {
            if let Some(autre) = releves[k].take()
                && let Some(a) = releves[i].as_mut()
            {
                a.absorber(autre);
            }
            for c in chef.iter_mut().filter(|c| **c == Some(k)) {
                *c = Some(i);
            }
        }
        if let Some(a) = releves[i].as_mut() {
            a.absorber(b);
        }
        chef[j] = Some(i);
    }
    let ids = chef
        .iter()
        .map(|c| c.and_then(|i| releves[i].as_ref()).map(|r| r.id.clone()))
        .collect();
    (releves, ids)
}

impl Releve {
    /// Un geste en commun : les deux défont la même chose.
    fn touche_le_meme(&self, autre: &Releve) -> bool {
        self.avant.gestes.iter().any(|g| autre.avant.gestes.contains(g))
    }

    /// Prend les gestes de `autre` qui manquent, avec leur valeur d'avant ; les communs ont la même, relevée au
    /// même moment.
    fn absorber(&mut self, autre: Releve) {
        for (g, v) in autre.avant.gestes.into_iter().zip(autre.avant.valeurs) {
            if !self.avant.gestes.contains(&g) {
                self.avant.gestes.push(g);
                self.avant.valeurs.push(v);
            }
        }
        if let (Some(t), Some(u)) = (self.avant.titre.as_mut(), autre.avant.titre) {
            t.push_str(" + ");
            t.push_str(&u);
        }
    }
}

/// Un id neuf pour une correction du bilan.
pub(crate) fn id_bilan() -> String {
    format!("{BILAN}{}", crate::changements::nouvel_id())
}

/// Note les relevés avant d'appliquer, scellés : sans note enregistrée, rien ne doit changer (`false`). Une note déjà
/// là sous le même id (un réglage pour jouer appliqué de nouveau) reste : la plus ancienne ramène à l'état
/// d'origine.
pub(crate) fn noter(releves: &[&Releve]) -> bool {
    noter_dans(releves, &crate::reseau::dossier_local())
}

fn noter_dans(releves: &[&Releve], dossier: &Path) -> bool {
    let mut h = charger_dans(dossier);
    for r in releves {
        h.reglages.entry(r.id.clone()).or_insert_with(|| r.avant.clone());
    }
    sauver_dans(&h, dossier)
}

/// Après l'application : une correction en échec dont rien n'a changé (valeurs relues égales aux notées) n'a rien à
/// défaire, sa note part ; en partie faite, elle reste.
pub(crate) fn apres_application(issues: &[(String, bool)]) {
    apres_application_dans(issues, &crate::reseau::dossier_local());
}

fn apres_application_dans(issues: &[(String, bool)], dossier: &Path) {
    let mut h = charger_dans(dossier);
    let mut change = false;
    // Une note partagée par plusieurs corrections d'un lot (`regrouper`) reste dès que l'une a réussi.
    let reussies: Vec<&String> = issues.iter().filter(|(_, ok)| *ok).map(|(id, _)| id).collect();
    for (id, _) in issues.iter().filter(|(id, ok)| !*ok && !reussies.contains(&id)) {
        let intacte = h
            .reglages
            .get(id)
            .and_then(|a| Some((rebatir(id, a)?, a)))
            .is_some_and(|(r, a)| r.changements.iter().zip(&a.valeurs).all(|(c, v)| c.lire() == *v));
        if intacte {
            h.reglages.remove(id);
            change = true;
        }
    }
    if change {
        sauver_dans(&h, dossier);
    }
}

/// Une note hors du catalogue (correction du bilan, réglage pour jouer) : rebâtie d'après ses gestes.
fn hors_du_catalogue(id: &str) -> bool {
    id.starts_with(BILAN) || id.starts_with(JEUX)
}

/// Le réglage d'une note hors du catalogue, rebâti d'après ses gestes : `None` si l'un d'eux ne désigne rien de la
/// liste fermée (une note venue d'ailleurs, ou d'une autre version).
fn rebatir(id: &str, a: &Avant) -> Option<Reglage> {
    if !hors_du_catalogue(id) || a.gestes.is_empty() {
        return None;
    }
    let changements = a
        .gestes
        .iter()
        .map(|g| systeme::Changement::depuis_geste(g))
        .collect::<Option<Vec<_>>>()?;
    Some(Reglage {
        id: Cow::Owned(id.to_string()),
        categorie: Categorie::Confort,
        titre: Cow::Owned(a.titre.clone().unwrap_or_else(|| id.to_string())),
        effet: "",
        prudence: None,
        recommande: false,
        changements,
    })
}

/// Les notes hors du catalogue qui se rebâtissent.
pub(super) fn rebatis(h: &Historique) -> Vec<Reglage> {
    h.reglages.iter().filter_map(|(id, a)| rebatir(id, a)).collect()
}

/// D'où vient une note.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Origine {
    Bilan,
    Jeux,
    Optimiser,
}

impl Origine {
    fn de(id: &str) -> Origine {
        if id.starts_with(BILAN) {
            Origine::Bilan
        } else if id.starts_with(JEUX) {
            Origine::Jeux
        } else {
            Origine::Optimiser
        }
    }

    pub(crate) fn nom(self) -> &'static str {
        match self {
            Origine::Bilan => tr!("Bilan", "Check-up"),
            Origine::Jeux => tr!("Gaming", "Gaming"),
            Origine::Optimiser => tr!("Optimiser", "Optimize"),
        }
    }
}

/// Une note de reglages.json, prête à montrer.
#[derive(Clone, Debug)]
pub(crate) struct Note {
    pub(crate) id: String,
    pub(crate) date: String,
    pub(crate) titre: String,
    pub(crate) origine: Origine,
    /// Remise telle quelle si on l'annule. Fausse : elle ne désigne rien qu'on sache remettre, ou une de ses
    /// valeurs n'a pas la forme attendue (un réglage d'Optimiser revient alors à la valeur d'un système neuf, une
    /// correction ou un réglage pour jouer n'est pas touché).
    pub(crate) admise: bool,
}

/// Tous les réglages qui ont une note : ceux du catalogue, puis ceux hors du catalogue (DNS, démarrage, bilan,
/// jeux).
fn notes_rebaties(h: &Historique) -> Vec<Reglage> {
    let mut l = catalogue_note(h);
    l.extend(super::hors_catalogue(h));
    l
}

/// Les notes, de la plus récente à la plus ancienne (`origine` : seulement celles-là).
pub(crate) fn notes(origine: Option<Origine>) -> Vec<Note> {
    notes_de(&charger(), origine)
}

fn notes_de(h: &Historique, origine: Option<Origine>) -> Vec<Note> {
    let rebatis = notes_rebaties(h);
    let mut l: Vec<Note> = h
        .reglages
        .iter()
        .filter(|(id, _)| origine.is_none_or(|o| Origine::de(id) == o))
        .map(|(id, a)| {
            let r = rebatis.iter().find(|r| r.id.as_ref() == id.as_str());
            Note {
                id: id.clone(),
                date: a.date.clone(),
                titre: r.map_or_else(
                    || a.titre.clone().unwrap_or_else(|| id.clone()),
                    |r| r.titre.to_string(),
                ),
                origine: Origine::de(id),
                admise: r.is_some_and(|r| !hors_du_catalogue(id) || note_admise(r, h).is_some()),
            }
        })
        .collect();
    // Du plus récent au plus ancien : les dates (à la minute) d'abord, puis l'id, qui commence par l'heure.
    l.sort_by(|a, b| (&b.date, &b.id).cmp(&(&a.date, &a.id)));
    l
}

/// Le nombre de notes de cette origine.
pub(crate) fn nombre(origine: Origine) -> usize {
    notes(Some(origine)).len()
}

/// Ce que donne une annulation, relue.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Issue {
    /// L'état d'avant est relu en place ; la note part.
    Revenu,
    /// Pas revenu : ce qu'on attendait et ce qu'on relit, pour chaque valeur restée autre. La note reste.
    PasRevenu(Vec<String>),
    /// Pas tenté : pourquoi.
    Refuse(String),
    /// Plus de note (déjà annulé) : rien à faire.
    Absent,
}

/// Une note plus récente qui touche la même chose que `id` : défaite après elle, elle ramènerait l'état d'entre
/// les deux. Rend son titre.
fn plus_recente_sur_le_meme(h: &Historique, id: &str) -> Option<String> {
    let a = h.reglages.get(id)?;
    h.reglages
        .iter()
        .filter(|(autre, b)| *autre != id && (&b.date, *autre) > (&a.date, &id.to_string()))
        .find(|(_, b)| b.gestes.iter().any(|g| a.gestes.contains(g)))
        .map(|(autre, b)| b.titre.clone().unwrap_or_else(|| autre.clone()))
}

/// Défait ces notes d'un passage (une demande administrateur), avec `en_plus`, les commandes d'autres annulations
/// (un blocage) lancées dans la même demande : refaites par Vanguard depuis des champs typés
/// (`gestes::commandes_d_annulation`), jamais un texte relu d'un fichier non scellé. Rend l'issue de chaque note,
/// relue, et la réussite de chaque groupe en plus.
pub(crate) fn defaire(ids: &[String], en_plus: &[Vec<String>]) -> (Vec<(String, Issue)>, Vec<bool>) {
    let tient = crate::reseau::wifi_public::tient_le_dns();
    defaire_dans(ids, en_plus, tient, &crate::reseau::dossier_local())
}

pub(super) fn defaire_dans(
    ids: &[String],
    en_plus: &[Vec<String>],
    tient_le_dns: bool,
    dossier: &Path,
) -> (Vec<(String, Issue)>, Vec<bool>) {
    let mut h = charger_dans(dossier);
    let tous = notes_rebaties(&h);
    let mut issues: Vec<(String, Option<Issue>)> = Vec::with_capacity(ids.len());
    let mut choisis: Vec<&Reglage> = Vec::new();
    let mut attendus: Vec<Vec<Valeur>> = Vec::new();
    for id in ids {
        if !h.reglages.contains_key(id) {
            issues.push((id.clone(), Some(Issue::Absent)));
            continue;
        }
        let refus = |fr: &str, en: &str| Some(Issue::Refuse(if crate::langue::anglais() { en } else { fr }.into()));
        let r = tous.iter().find(|r| r.id.as_ref() == id.as_str());
        let issue = match r {
            _ if id == DNS && tient_le_dns => refus(
                "le mode Wi-Fi public tient le DNS : éteignez-le d'abord",
                "public Wi-Fi mode holds the DNS: turn it off first",
            ),
            None => refus(
                "la note ne désigne rien que Vanguard sache remettre",
                "the note names nothing Vanguard can put back",
            ),
            Some(r) if hors_du_catalogue(id) && note_admise(r, &h).is_none() => refus(
                "une valeur d'avant n'a pas la forme attendue : rien n'est remis",
                "a previous value does not have the expected form: nothing is put back",
            ),
            Some(_) => None,
        };
        if issue.is_none()
            && let Some(r) = r
        {
            attendus.push(valeurs_d_avant(r, &h));
            choisis.push(r);
        }
        issues.push((id.clone(), issue));
    }
    if choisis.is_empty() && en_plus.is_empty() {
        let issues = issues
            .into_iter()
            .map(|(id, i)| (id, i.unwrap_or(Issue::Absent)))
            .collect();
        return (issues, Vec::new());
    }
    let (_, remis, plus) = executer_avec(&[], &choisis, &mut h, en_plus, dossier);
    systeme::apres(&choisis);
    let mut suite = choisis.iter().zip(attendus).zip(remis);
    let issues = issues
        .into_iter()
        .map(|(id, i)| {
            let i = i.unwrap_or_else(|| match suite.next() {
                Some((_, true)) => Issue::Revenu,
                Some(((r, attendu), false)) => Issue::PasRevenu(
                    r.changements
                        .iter()
                        .zip(attendu)
                        .filter_map(|(c, v)| {
                            let lu = c.lire();
                            (lu != v).then(|| {
                                trf!(
                                    "attendu : {} ; relu : {}",
                                    "expected: {}; read: {}",
                                    affichable(&c.decrire(v.as_deref())),
                                    affichable(&c.decrire(lu.as_deref()))
                                )
                            })
                        })
                        .collect(),
                ),
                None => Issue::Absent,
            });
            (id, i)
        })
        .collect();
    (issues, plus)
}

/// Ce que l'annulation de ces notes remettra, ligne par ligne, à montrer avant de demander.
pub(crate) fn a_remettre(ids: &[String]) -> Vec<String> {
    let h = charger();
    let tous = notes_rebaties(&h);
    let choisis: Vec<&Reglage> = ids
        .iter()
        .filter_map(|id| tous.iter().find(|r| r.id.as_ref() == id.as_str()))
        .collect();
    a_changer(&[], &choisis, &h)
}

/// Annule une correction du bilan notée, après l'avoir montrée et demandé : refusé si une note plus récente touche
/// la même chose (à défaire d'abord). Rend l'issue, relue ; `None` si on n'a rien fait.
pub(crate) fn annuler_une(id: &str) -> Option<Issue> {
    let h = charger();
    if let Some(titre) = plus_recente_sur_le_meme(&h, id) {
        afficher_aligne(
            "  ✖ ",
            &trf!(
                "« {} », plus récente, touche la même chose : annulez-la d'abord, sinon l'état d'entre les deux reviendrait.",
                "“{}”, more recent, touches the same thing: undo it first, or the state in between would come back.",
                affichable(&titre)
            ),
            4,
            "",
        );
        return None;
    }
    let ids = [id.to_string()];
    for l in a_remettre(&ids) {
        println!("{l}");
    }
    if !demander(tr!(
        "\n  Remettre comme avant ? [o/N] : ",
        "\n  Put back as before? [y/N]: "
    ))
    .oui()
    {
        trp!("  Rien n'a été changé.", "  Nothing was changed.");
        return None;
    }
    let (issues, _) = defaire(&ids, &[]);
    let issue = issues.into_iter().next().map_or(Issue::Absent, |(_, i)| i);
    dire_issue(&issue, "");
    Some(issue)
}

/// L'issue d'une annulation, en clair. `titre` : ce qui a été défait (vide : déjà dit au-dessus).
pub(crate) fn dire_issue(issue: &Issue, titre: &str) {
    let titre = if titre.is_empty() {
        String::new()
    } else {
        trf!("{} : ", "{}: ", affichable(titre))
    };
    match issue {
        Issue::Revenu => trp!(
            "  {VERT}✔{RESET} {titre}état d'avant relu en place.",
            "  {VERT}✔{RESET} {titre}previous state read back in place."
        ),
        Issue::PasRevenu(details) => {
            afficher_aligne(
                "  ✖ ",
                &trf!(
                    "{titre}l'état d'avant n'est pas revenu (programme encore ouvert, redémarrage nécessaire, ou changé depuis). La note reste pour réessayer.",
                    "{titre}the previous state did not come back (program still open, restart needed, or changed since). The note stays so you can try again."
                ),
                4,
                "",
            );
            for d in details {
                afficher_aligne("      ", d, 6, GRIS);
            }
        }
        Issue::Refuse(pourquoi) => afficher_aligne(
            "  ✖ ",
            &trf!("{titre}pas remis : {pourquoi}.", "{titre}not put back: {pourquoi}."),
            4,
            "",
        ),
        Issue::Absent => trp!(
            "  {GRIS}{titre}déjà défait : rien à faire.{RESET}",
            "  {GRIS}{titre}already undone: nothing to do.{RESET}"
        ),
    }
}

/// Le choix 3 du menu Gaming : les réglages pour jouer notés, cochés pour être remis comme avant.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub(crate) fn remettre_jeux() {
    let notes = notes(Some(Origine::Jeux));
    if notes.is_empty() {
        trp!(
            "  {GRIS}Aucun réglage pour jouer à remettre.{RESET}",
            "  {GRIS}No gaming setting to put back.{RESET}"
        );
        return;
    }
    let entete = vec![
        String::new(),
        ligne_titre(tr!(
            "Remettre les réglages comme avant",
            "Put the settings back as before"
        )),
        trf!(
            "  {GRIS}Les valeurs notées avant que Vanguard les change.{RESET}",
            "  {GRIS}The values noted before Vanguard changed them.{RESET}"
        ),
        String::new(),
    ];
    let cases: Vec<Case> = notes
        .iter()
        .map(|n| Case {
            texte: n.titre.clone(),
            precision: trf!("réglé le {}", "set on {}", n.date),
            detail: String::new(),
            cochee: false,
            recommandee: true,
            fixe: false,
        })
        .collect();
    let Some(voulu) = cocher(&entete, &cases) else {
        return;
    };
    let ids: Vec<String> = notes
        .iter()
        .zip(&voulu)
        .filter(|(_, v)| **v)
        .map(|(n, _)| n.id.clone())
        .collect();
    if ids.is_empty() {
        return;
    }
    for l in a_remettre(&ids) {
        println!("{l}");
    }
    if !demander(tr!("\n  Remettre ? [o/N] : ", "\n  Put back? [y/N]: ")).oui() {
        trp!("  Rien n'a été changé.", "  Nothing was changed.");
        return;
    }
    let (issues, _) = defaire(&ids, &[]);
    for (id, issue) in &issues {
        let titre = notes
            .iter()
            .find(|n| &n.id == id)
            .map_or(id.as_str(), |n| n.titre.as_str());
        dire_issue(issue, titre);
    }
}

/// Une note de Gaming d'avant dans la forme d'Optimiser, si chacune de ses valeurs a la forme que son geste écrit.
fn convertie(id: &str, a: &crate::gaming::NoteDAvant) -> Option<Vec<(Geste, Option<String>)>> {
    crate::gaming::convertir_note(id, &a.valeurs).filter(|l| {
        !l.is_empty()
            && l.iter()
                .all(|(g, v)| systeme::Changement::depuis_geste(&g.0).is_some_and(|c| c.valeur_admise(v.as_deref())))
    })
}

/// Reprend une fois les notes de Gaming d'avant (jeux.json, jamais scellé) : converties en gestes, ajoutées sans
/// écraser une note déjà là, enregistrées scellées, et alors seulement retirées de jeux.json. Une note qui ne se
/// convertit pas, ou dont une valeur n'a pas la forme attendue, y reste, et c'est dit : rien ne se perd. La reprise
/// est marquée dans reglages.json, scellé, même sans jeux.json : Vanguard n'écrit plus ce fichier, et un jeux.json
/// posé ensuite par un autre programme ne doit pas devenir une note scellée, remise en administrateur.
pub(super) fn reprendre_jeux(h: &mut Historique, dossier: &Path) {
    if h.jeux_repris {
        // Ce qui n'a pas pu se reprendre reste dans jeux.json sans rien dire de plus ; une note qui se reprendrait
        // n'y était pas à la reprise : elle vient d'ailleurs.
        let revenue = crate::gaming::notes_d_avant(dossier)
            .is_some_and(|n| n.reglages.iter().any(|(id, a)| convertie(id, a).is_some()));
        if revenue {
            tre!(
                "Attention : jeux.json a des notes de réglages pour jouer apparues après leur reprise : Vanguard n'écrit plus ce fichier. Elles ne sont ni reprises ni remises.",
                "Warning: jeux.json has gaming setting notes that appeared after they were taken over: Vanguard no longer writes this file. They are neither taken over nor put back."
            );
        }
        return;
    }
    let anciennes = crate::gaming::notes_d_avant(dossier).unwrap_or_default();
    let mut reste = crate::gaming::NotesDAvant::default();
    for (id, a) in anciennes.reglages {
        match convertie(&id, &a) {
            Some(l) => {
                h.reglages.entry(format!("{JEUX}{id}")).or_insert_with(|| Avant {
                    // Venus de jeux.json, jamais scellé : sans séquence d'échappement qui cacherait les lignes
                    // suivantes à l'écran.
                    date: crate::ui::affichable(&a.date),
                    valeurs: l.iter().map(|(_, v)| v.clone()).collect(),
                    titre: Some(crate::ui::affichable(&a.titre)),
                    gestes: l.into_iter().map(|(g, _)| g.0).collect(),
                });
            }
            None => {
                reste.reglages.insert(id, a);
            }
        }
    }
    // Les notes reprises ne quittent jeux.json qu'une fois enregistrées, scellées, dans reglages.json, avec la marque.
    h.jeux_repris = true;
    if !sauver_dans(h, dossier) {
        return;
    }
    if !reste.reglages.is_empty() {
        tre!(
            "Attention : {} réglage(s) pour jouer d'une version d'avant ne se reprennent pas ; ils restent dans jeux.json, sans être remis.",
            "Warning: {} gaming setting(s) from an earlier version cannot be taken over; they stay in jeux.json, not put back.",
            reste.reglages.len()
        );
    }
    crate::gaming::garder_notes_d_avant(dossier, &reste);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dossier(nom: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("vanguard-annulables-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Une note écrite à la main, telle que `relever` l'aurait faite.
    fn note(id: &str, date: &str, gestes: &[&str], valeurs: &[Option<&str>]) -> (String, Avant) {
        (
            id.to_string(),
            Avant {
                date: date.into(),
                valeurs: valeurs.iter().map(|v| v.map(str::to_string)).collect(),
                titre: Some(format!("Essai {id}")),
                gestes: gestes.iter().map(|g| (*g).to_string()).collect(),
            },
        )
    }

    fn historique(notes: Vec<(String, Avant)>) -> Historique {
        Historique {
            reglages: notes.into_iter().collect(),
            jeux_repris: false,
        }
    }

    /// Les commandes qui remettent une note, telles que `systeme::ecrire_avec` les lancerait.
    #[cfg(not(windows))]
    fn commandes(h: &Historique, id: &str) -> Vec<String> {
        let r = rebatis(h)
            .into_iter()
            .find(|r| r.id.as_ref() == id)
            .expect("note rebâtie");
        r.changements
            .iter()
            .zip(valeurs_d_avant(&r, h))
            .filter_map(|(c, v)| c.commande(v.as_deref()))
            .collect()
    }

    /// Un geste hors de la liste fermée ne désigne rien : une note ne peut pas faire écrire ailleurs.
    #[test]
    fn gestes_hors_de_la_liste_refuses() {
        for g in [
            "",
            "inconnu|x",
            "fichier|/etc/shadow",
            "fichier|/etc/sysctl.d/99-vanguard.conf.bak",
            // Le fichier du durcissement du noyau : une protection, jamais retirée ni vidée par une note.
            "fichier|/etc/sysctl.d/99-vanguard.conf",
            "unite|sshd",
            "sysctl|kernel/core_pattern",
            "sysctl|net/ipv6/conf/../../kernel/core_pattern/accept_redirects",
            "module|evil",
            "droits|/etc/passwd",
            "droits|relatif/x",
            "natif|point-de-restauration",
            "natif|n-existe-pas",
            "natif|uac-active",
            "natif|uac-demande",
            "service|WinDefend",
            "registre|hklm|SYSTEM\\Ailleurs|Valeur",
            "preference|com.apple.x|Y",
        ] {
            assert!(systeme::Changement::depuis_geste(g).is_none(), "{g}");
        }
        assert!(relever("bilan:x".into(), "x", &[Geste("fichier|/etc/shadow".into())]).is_err());
        assert!(relever("bilan:x".into(), "x", &[]).is_err());
    }

    /// Une correction qui ne sait pas relever son état d'avant le dit, avant d'être appliquée ; une protection
    /// rallumée ne se défait jamais.
    #[test]
    fn non_annulable_dit_avant() {
        let k = |defaire| crate::machine::Correctif {
            action: "essai".into(),
            commandes: vec!["true".into()],
            automatique: true,
            bloque: None,
            defaire,
        };
        assert_eq!(
            k(crate::machine::Defaire::Inconnu).pourquoi_pas(),
            Some(PourquoiPas::NonReleve)
        );
        assert_eq!(
            k(crate::machine::Defaire::Protection).pourquoi_pas(),
            Some(PourquoiPas::Protection)
        );
        assert_eq!(
            k(crate::machine::Defaire::Gestes(vec![Geste("x".into())])).pourquoi_pas(),
            None
        );
        assert!(PourquoiPas::Protection.texte().contains("protection"));
    }

    /// Aller-retour réel des droits d'un fichier (sans sudo) : relevés, notés, scellés, changés par la correction,
    /// puis, relus du disque comme après un redémarrage, remis et relus en place ; la note part, et une seconde
    /// annulation ne fait plus rien, même si le fichier a changé depuis.
    #[cfg(unix)]
    #[test]
    fn droits_aller_retour_apres_redemarrage_et_double_annulation() {
        use std::os::unix::fs::PermissionsExt;
        let d = dossier("droits");
        let f = d.join("netrc-alice");
        std::fs::write(&f, "machine example.com login alice\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        let r = relever(id_bilan(), "Réserver ces fichiers à toi seul", &[Geste::droits(&f)]).unwrap();
        assert_eq!(r.avant.valeurs, [Some("0644".to_string())]);
        assert!(noter_dans(&[&r], &d));
        // La correction elle-même.
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        // « Redémarrage » : rien en mémoire, tout relu du disque, scellé.
        let relu = charger_dans(&d);
        assert_eq!(relu.reglages[&r.id], r.avant);
        let (issues, plus) = defaire_dans(std::slice::from_ref(&r.id), &[], false, &d);
        assert_eq!(issues, [(r.id.clone(), Issue::Revenu)]);
        assert_eq!(plus, Vec::<bool>::new());
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o7777, 0o644);
        assert!(
            !charger_dans(&d).reglages.contains_key(&r.id),
            "la note part une fois relue en place"
        );
        // Seconde annulation : plus de note, rien n'est touché.
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
        let (issues, _) = defaire_dans(std::slice::from_ref(&r.id), &[], false, &d);
        assert_eq!(issues, [(r.id.clone(), Issue::Absent)]);
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o7777, 0o640);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une note forgée (scellée par un programme du compte, puisque le sceau se recalcule) qui remettrait en root une
    /// clé du durcissement sous sa valeur sûre : refusée en entier, et rien n'est lancé (pas même sudo).
    #[cfg(target_os = "linux")]
    #[test]
    fn note_forgee_n_affaiblit_pas_le_noyau() {
        let d = dossier("noyau-forge");
        let h = historique(vec![note(
            "bilan:x",
            "2026-10-26 10:00",
            &["sysctl|kernel/yama/ptrace_scope", "sysctl|kernel/randomize_va_space"],
            &[Some("0"), Some("0")],
        )]);
        assert!(super::super::sauver_dans(&h, &d));
        let r = rebatis(&h).pop().expect("rebâtie : les clés sont de la liste");
        assert_eq!(r.changements[0].commande(Some("0")), None);
        assert_eq!(commandes(&h, "bilan:x"), Vec::<String>::new());
        let (issues, plus) = defaire_dans(&["bilan:x".to_string()], &[], false, &d);
        assert!(
            matches!(&issues[..], [(id, Issue::Refuse(_))] if id == "bilan:x"),
            "{issues:?}"
        );
        assert_eq!(plus, Vec::<bool>::new());
        assert!(
            charger_dans(&d).reglages.contains_key("bilan:x"),
            "la note reste, rien n'est remis"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// L'état d'avant qui ne revient pas (le fichier a disparu) est dit, avec ce qu'on attendait et ce qu'on relit ;
    /// la note reste pour réessayer.
    #[cfg(unix)]
    #[test]
    fn pas_revenu_dit_et_note_gardee() {
        let d = dossier("pas-revenu");
        let f = d.join("secret-bob");
        std::fs::write(&f, "x").unwrap();
        let r = relever(id_bilan(), "Essai", &[Geste::droits(&f)]).unwrap();
        assert!(noter_dans(&[&r], &d));
        std::fs::remove_file(&f).unwrap();
        let (issues, _) = defaire_dans(std::slice::from_ref(&r.id), &[], false, &d);
        assert!(
            matches!(&issues[0].1, Issue::PasRevenu(l) if !l.is_empty()),
            "{issues:?}"
        );
        assert!(charger_dans(&d).reglages.contains_key(&r.id));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// reglages.json réécrit hors de Vanguard après la note (une valeur d'avant à un autre, qui partirait en
    /// administrateur) : rien n'en est cru, rien n'est remis, aucune commande ne part.
    #[cfg(unix)]
    #[test]
    fn note_falsifiee_rien_remis() {
        use std::os::unix::fs::PermissionsExt;
        let d = dossier("falsifie");
        let f = d.join("cles-alice");
        std::fs::write(&f, "x").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        let r = relever(id_bilan(), "Essai", &[Geste::droits(&f)]).unwrap();
        assert!(noter_dans(&[&r], &d));
        let texte = std::fs::read_to_string(d.join(crate::sceau::REGLAGES))
            .unwrap()
            .replace("0600", "0666");
        std::fs::write(d.join(crate::sceau::REGLAGES), texte).unwrap();
        let (issues, _) = defaire_dans(std::slice::from_ref(&r.id), &[], false, &d);
        assert_eq!(issues, [(r.id.clone(), Issue::Absent)]);
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o7777, 0o600);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une note adoptée (sceaux effacés) dont une valeur n'a pas la forme du geste, ou dont un geste sort de la
    /// liste fermée, est refusée : rien n'est remis.
    #[cfg(unix)]
    #[test]
    fn note_d_une_forme_inattendue_refusee() {
        let d = dossier("forme");
        let f = d.join("x");
        std::fs::write(&f, "x").unwrap();
        let geste = format!("droits|{}", f.display());
        let h = historique(vec![
            note("bilan:1", "2026-10-23 10:00", &[&geste], &[Some("4755")]),
            note("bilan:2", "2026-10-23 10:01", &["fichier|/etc/shadow"], &[None]),
        ]);
        assert!(sauver_dans(&h, &d));
        std::fs::remove_file(d.join("sceaux.json")).unwrap();
        let notes = notes_de(&charger_dans(&d), None);
        assert!(notes.iter().all(|n| !n.admise), "{notes:?}");
        let (issues, _) = defaire_dans(&["bilan:1".into(), "bilan:2".into()], &[], false, &d);
        assert!(issues.iter().all(|(_, i)| matches!(i, Issue::Refuse(_))), "{issues:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Les notes se listent de la plus récente à la plus ancienne ; une note plus récente qui touche la même chose
    /// doit être défaite d'abord.
    #[test]
    fn ordre_et_note_plus_recente_sur_le_meme() {
        let h = historique(vec![
            note(
                "bilan:a",
                "2026-10-21 09:00",
                &["unite|cups-browsed"],
                &[Some("enabled")],
            ),
            note(
                "bilan:b",
                "2026-10-22 09:00",
                &["unite|cups-browsed"],
                &[Some("disabled")],
            ),
            note("bilan:c", "2026-10-22 10:00", &["ntp"], &[Some("no")]),
            note("jeux:hags", "2026-10-20 21:00", &["module|ntsync"], &[None]),
        ]);
        let ids: Vec<String> = notes_de(&h, None).into_iter().map(|n| n.id).collect();
        assert_eq!(ids, ["bilan:c", "bilan:b", "bilan:a", "jeux:hags"]);
        assert_eq!(notes_de(&h, Some(Origine::Jeux)).len(), 1);
        assert_eq!(plus_recente_sur_le_meme(&h, "bilan:a"), Some("Essai bilan:b".into()));
        assert_eq!(plus_recente_sur_le_meme(&h, "bilan:b"), None);
        assert_eq!(plus_recente_sur_le_meme(&h, "bilan:c"), None);
    }

    /// Aller-retour de chaque genre de correction de Linux : la note relue rebâtit le geste, et la commande qui la
    /// remet est exactement l'inverse ; une valeur piégée n'entre dans aucune commande.
    #[cfg(target_os = "linux")]
    #[test]
    fn aller_retour_de_chaque_genre_linux() {
        use crate::machine::linux::{RECHARGER_SSHD, SSHD_VANGUARD};
        let sshd = format!("fichier|{SSHD_VANGUARD}");
        let jeux = format!("fichier|{}", crate::gaming::linux::SYSCTL_JEUX);
        let ollama = format!("fichier|{}", super::super::OLLAMA_VANGUARD);
        let h = historique(vec![
            note("bilan:unite", "", &["unite|cups-browsed"], &[Some("enabled")]),
            note("bilan:auditd", "", &["unite|auditd"], &[Some("disabled")]),
            note("bilan:ntp", "", &["ntp"], &[Some("no")]),
            note(
                "bilan:noyau",
                "",
                &[
                    "sysctl|kernel/kptr_restrict",
                    "sysctl|net/ipv6/conf/wlan0/accept_redirects",
                ],
                &[Some("2"), Some("0")],
            ),
            note("bilan:sshd", "", &[&sshd], &[Some("PermitRootLogin no\n")]),
            note("bilan:sshd-absent", "", &[&sshd], &[None]),
            note("bilan:ollama", "", &[&ollama], &[None]),
            note(
                "jeux:max_map_count",
                "",
                &[&jeux, "sysctl|vm/max_map_count"],
                &[Some("vm.max_map_count = 262144\n"), Some("65530")],
            ),
            note("jeux:ntsync", "", &["module|ntsync"], &[None]),
        ]);
        assert_eq!(
            commandes(&h, "bilan:unite"),
            ["sudo systemctl enable --now cups-browsed"]
        );
        assert_eq!(commandes(&h, "bilan:auditd"), ["sudo systemctl disable --now auditd"]);
        assert_eq!(commandes(&h, "bilan:ntp"), ["sudo timedatectl set-ntp false"]);
        assert_eq!(
            commandes(&h, "bilan:noyau"),
            [
                "sudo sysctl -w 'kernel/kptr_restrict=2' >/dev/null",
                "sudo sysctl -w 'net/ipv6/conf/wlan0/accept_redirects=0' >/dev/null",
            ]
        );
        assert_eq!(
            commandes(&h, "bilan:sshd"),
            [format!(
                "printf '%s' 'PermitRootLogin no\n' | sudo tee '{SSHD_VANGUARD}' >/dev/null && {RECHARGER_SSHD}"
            )]
        );
        assert_eq!(
            commandes(&h, "bilan:sshd-absent"),
            [format!("sudo rm -f '{SSHD_VANGUARD}' && {RECHARGER_SSHD}")]
        );
        assert!(commandes(&h, "bilan:ollama")[0].ends_with("sudo systemctl try-restart ollama"));
        assert_eq!(commandes(&h, "jeux:max_map_count").len(), 2);
        assert_eq!(commandes(&h, "jeux:ntsync"), ["sudo modprobe -r ntsync"]);
        for id in h.reglages.keys() {
            for c in commandes(&h, id) {
                assert!(
                    std::process::Command::new("bash")
                        .args(["-n", "-c", &c])
                        .status()
                        .unwrap()
                        .success(),
                    "{c}"
                );
            }
        }
        // Des valeurs d'avant piégées : refusées par `note_admise`, elles n'entrent dans aucune commande.
        let pieges = historique(vec![
            note("bilan:1", "", &["sysctl|kernel/kptr_restrict"], &[Some("0; rm -rf ~")]),
            note("bilan:2", "", &[&jeux], &[Some("kernel.core_pattern = |/tmp/x\n")]),
            note("bilan:3", "", &[&sshd], &[Some("Match all\nForceCommand /tmp/x\n")]),
            note("bilan:4", "", &[&ollama], &[Some("[Service]\nExecStart=/tmp/x\n")]),
            note("bilan:5", "", &["unite|cups-browsed"], &[Some("enabled; reboot")]),
            note("bilan:6", "", &["ntp"], &[Some("peut-être")]),
            note("jeux:7", "", &["module|ntsync"], &[Some("charge && reboot")]),
            // Des fichiers lus en root, aux clés de la liste mais affaiblies, ou hors de la liste.
            note("bilan:8", "", &[&jeux], &[Some("kernel.yama.ptrace_scope = 0\n")]),
            note(
                "bilan:9",
                "",
                &[&jeux],
                &[Some("fs.protected_symlinks = 0\nvm.mmap_min_addr = 0\n")],
            ),
            note(
                "jeux:10",
                "",
                &[&jeux],
                &[Some("kernel.unprivileged_bpf_disabled = 0\n")],
            ),
            note("jeux:11", "", &[&jeux], &[Some("kernel.yama.ptrace_scope = 0\n")]),
            note("bilan:12", "", &[&sshd], &[Some("PermitRootLogin yes\n")]),
            note(
                "bilan:13",
                "",
                &[&sshd],
                &[Some("PermitEmptyPasswords yes\nPasswordAuthentication yes\n")],
            ),
            note("bilan:14", "", &[&sshd], &[Some("Ciphers +arcfour\n")]),
            note("bilan:15", "", &[&sshd], &[Some("MaxAuthTries 99\n")]),
            // Une clé du durcissement remise sous sa valeur sûre par `sysctl -w`, en root : la protection tomberait
            // jusqu'au redémarrage (le fichier, lui, la refusait déjà).
            note("bilan:16", "", &["sysctl|kernel/yama/ptrace_scope"], &[Some("0")]),
            note("bilan:17", "", &["sysctl|kernel/randomize_va_space"], &[Some("0")]),
            note("bilan:18", "", &["sysctl|fs/protected_symlinks"], &[Some("0")]),
            note(
                "bilan:19",
                "",
                &["sysctl|net/ipv6/conf/wlan0/accept_redirects"],
                &[Some("1")],
            ),
            note("jeux:20", "", &["sysctl|vm/max_map_count"], &[Some("1024")]),
        ]);
        assert_eq!(
            rebatis(&pieges).len(),
            pieges.reglages.len(),
            "chaque piège est rebâti, puis refusé"
        );
        for r in rebatis(&pieges) {
            assert!(note_admise(&r, &pieges).is_none(), "{}", r.id);
            assert_eq!(commandes(&pieges, &r.id), Vec::<String>::new(), "{}", r.id);
        }
        // Ce que Vanguard écrit lui-même dans ces fichiers reste admis.
        let bons = historique(vec![
            note(
                "jeux:noyau",
                "",
                &[&jeux],
                &[Some(
                    "kernel.yama.ptrace_scope = 1\nkernel.kptr_restrict = 2\nkernel.sysrq = 176\nnet.ipv6.conf.*.accept_redirects = 0\n",
                )],
            ),
            note(
                "bilan:sshd",
                "",
                &[&sshd],
                &[Some(
                    "PermitRootLogin prohibit-password\nX11Forwarding no\nMaxAuthTries 6\nCiphers -3des-cbc,aes128-cbc\nMACs hmac-sha2-256,hmac-sha2-512\n",
                )],
            ),
        ]);
        for r in rebatis(&bons) {
            assert!(note_admise(&r, &bons).is_some(), "{}", r.id);
        }
        // Le contenu remis est montré avant la question, pas seulement « remis comme avant ».
        let sshd_note = rebatis(&bons).into_iter().find(|r| r.id == "bilan:sshd").unwrap();
        let montre = sshd_note.changements[0].decrire(Some("PermitRootLogin no\nMaxAuthTries 6\n"));
        assert!(
            montre.contains("PermitRootLogin no") && montre.contains("MaxAuthTries 6"),
            "{montre}"
        );
    }

    /// Un fichier posé par Vanguard qui existait avant est rendu octet pour octet (apostrophes, sauts de ligne) : la
    /// commande est jouée pour de vrai, sans sudo, sur une copie dans un dossier jetable.
    #[cfg(target_os = "linux")]
    #[test]
    fn fichier_existant_rendu_tel_quel() {
        let d = dossier("pose");
        let copie = d.join("80-vanguard-jeux.conf");
        let contenu = "# réglé à la main, l'été\nvm.max_map_count = 262144\n";
        let jeux = crate::gaming::linux::SYSCTL_JEUX;
        let h = historique(vec![note(
            "jeux:x",
            "",
            &[&format!("fichier|{jeux}")],
            &[Some(contenu)],
        )]);
        let c = commandes(&h, "jeux:x");
        assert_eq!(c.len(), 1);
        let jouee = c[0].replace("sudo ", "").replace(jeux, &copie.display().to_string());
        assert!(
            std::process::Command::new("bash")
                .args(["-c", &jouee])
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(std::fs::read_to_string(&copie).unwrap(), contenu);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Aller-retour des corrections de macOS : la préférence d'AirDrop notée est remise telle quelle, ou retirée si
    /// elle manquait ; une valeur hors de sa liste n'entre dans aucune commande.
    #[cfg(target_os = "macos")]
    #[test]
    fn aller_retour_de_chaque_genre_macos() {
        let airdrop = "preference|com.apple.sharingd|DiscoverableMode";
        let h = historique(vec![
            note("bilan:airdrop", "", &[airdrop], &[Some("Everyone")]),
            note("bilan:absent", "", &[airdrop], &[None]),
        ]);
        assert_eq!(
            commandes(&h, "bilan:airdrop"),
            [
                "defaults write com.apple.sharingd DiscoverableMode -string 'Everyone'; killall sharingd 2>/dev/null; true"
            ]
        );
        assert!(commandes(&h, "bilan:absent")[0].starts_with("defaults delete com.apple.sharingd DiscoverableMode"));
        let piege = historique(vec![note("bilan:p", "", &[airdrop], &[Some("Everyone'; rm -rf ~; '")])]);
        assert!(note_admise(&rebatis(&piege)[0], &piege).is_none());
        assert_eq!(commandes(&piege, "bilan:p"), Vec::<String>::new());
    }

    /// Les notes de Gaming d'avant (jeux.json) sont reprises une fois dans reglages.json, scellé, sans en perdre :
    /// une note qui ne se convertit pas, ou dont une valeur est piégée, reste dans jeux.json et n'est jamais remise.
    #[cfg(target_os = "linux")]
    #[test]
    fn notes_de_gaming_reprises_sans_perte() {
        use crate::gaming::NotesDAvant;
        let d = dossier("reprise");
        let jeux = crate::gaming::linux::SYSCTL_JEUX;
        let texte = format!(
            r#"{{"reglages":{{
                "max_map_count":{{"titre":"vm.max_map_count","date":"2026-10-20 21:00",
                    "valeurs":[["vm.max_map_count","65530"],["{jeux}",null]]}},
                "ntsync":{{"titre":"ntsync","date":"2026-10-20 21:01",
                    "valeurs":[["ntsync",null],["/etc/modules-load.d/vanguard-ntsync.conf",null]]}},
                "piege":{{"titre":"piège","date":"2026-10-20 21:02",
                    "valeurs":[["{jeux}","kernel.core_pattern = |/tmp/x\n"]]}},
                "inconnu":{{"titre":"?","date":"2026-10-20 21:03","valeurs":[["/etc/ailleurs",null]]}}
            }}}}"#
        );
        std::fs::write(d.join("jeux.json"), texte).unwrap();
        let h = charger_dans(&d);
        assert_eq!(
            h.reglages["jeux:max_map_count"].gestes,
            ["sysctl|vm/max_map_count".to_string(), format!("fichier|{jeux}")]
        );
        assert_eq!(
            h.reglages["jeux:max_map_count"].valeurs,
            [Some("65530".to_string()), None]
        );
        assert!(h.reglages.contains_key("jeux:ntsync"));
        assert!(!h.reglages.contains_key("jeux:piege") && !h.reglages.contains_key("jeux:inconnu"));
        // Enregistrées et scellées : relues telles quelles ; jeux.json ne garde que ce qui ne s'est pas repris.
        assert!(matches!(
            crate::sceau::lire_dans(&d, crate::sceau::REGLAGES),
            crate::sceau::Lecture::Intact(_)
        ));
        let reste: NotesDAvant = serde_json::from_str(&std::fs::read_to_string(d.join("jeux.json")).unwrap()).unwrap();
        assert_eq!(reste.reglages.keys().collect::<Vec<_>>(), ["inconnu", "piege"]);
        // Une seconde lecture ne reprend rien de plus et ne perd rien.
        let encore = charger_dans(&d);
        assert_eq!(encore.reglages.len(), h.reglages.len());
        // Un jeux.json qui revient après la reprise (Vanguard ne l'écrit plus) vient d'ailleurs : rien n'en est
        // repris ni scellé, et il reste tel quel sur le disque.
        let revenu = format!(
            r#"{{"reglages":{{"hags":{{"titre":"HAGS","date":"2026-10-22 08:00","valeurs":[["{jeux}","vm.max_map_count = 65530\n"]]}}}}}}"#
        );
        std::fs::write(d.join("jeux.json"), &revenu).unwrap();
        let apres = charger_dans(&d);
        assert_eq!(apres.reglages.len(), h.reglages.len());
        assert!(!apres.reglages.contains_key("jeux:hags"));
        assert_eq!(std::fs::read_to_string(d.join("jeux.json")).unwrap(), revenu);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Sans jeux.json, la reprise est marquée dès la première lecture : un jeux.json posé plus tard par un autre
    /// programme n'est jamais repris.
    #[cfg(target_os = "linux")]
    #[test]
    fn jeux_json_pose_apres_la_premiere_lecture_ignore() {
        let d = dossier("reprise-marquee");
        assert!(charger_dans(&d).reglages.is_empty());
        let jeux = crate::gaming::linux::SYSCTL_JEUX;
        std::fs::write(
            d.join("jeux.json"),
            format!(
                r#"{{"reglages":{{"hags":{{"titre":"HAGS","date":"2026-10-22 08:00","valeurs":[["{jeux}",null]]}}}}}}"#
            ),
        )
        .unwrap();
        assert!(charger_dans(&d).reglages.is_empty());
        assert!(d.join("jeux.json").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// reglages.json adopté (sceaux effacés) et jeux.json présent : rien n'est repris, et reglages.json reste
    /// « adopté », sans être rescellé par la reprise.
    #[cfg(target_os = "linux")]
    #[test]
    fn reprise_jamais_par_dessus_un_fichier_adopte() {
        let d = dossier("reprise-adopte");
        std::fs::write(d.join(crate::sceau::REGLAGES), r#"{"reglages":{}}"#).unwrap();
        let jeux = crate::gaming::linux::SYSCTL_JEUX;
        std::fs::write(
            d.join("jeux.json"),
            format!(
                r#"{{"reglages":{{"hags":{{"titre":"HAGS","date":"2026-10-22 08:00","valeurs":[["{jeux}",null]]}}}}}}"#
            ),
        )
        .unwrap();
        assert!(matches!(
            crate::sceau::lire_dans(&d, crate::sceau::REGLAGES),
            crate::sceau::Lecture::Adopte(_)
        ));
        assert!(charger_dans(&d).reglages.is_empty());
        assert!(matches!(
            crate::sceau::lire_dans(&d, crate::sceau::REGLAGES),
            crate::sceau::Lecture::Adopte(_)
        ));
        assert!(d.join("jeux.json").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Les corrections d'un même lot qui touchent la même chose partagent une note (leur état d'avant n'existe
    /// qu'une fois) ; celles qui n'ont rien en commun gardent la leur, et une correction non relevée n'en a pas.
    #[test]
    fn lot_sur_le_meme_fichier_une_seule_note() {
        let releve = |id: &str, gestes: &[&str], valeurs: &[Option<&str>]| {
            let (id, avant) = note(id, "2026-10-23 10:00", gestes, valeurs);
            Some(Releve { id, avant })
        };
        let sshd = "fichier|/etc/ssh/sshd_config.d/00-vanguard.conf";
        let (releves, ids) = regrouper(vec![
            releve("bilan:root", &[sshd], &[None]),
            releve("bilan:ntp", &["ntp"], &[Some("no")]),
            None,
            releve("bilan:ports", &[sshd], &[None]),
            releve("bilan:x11", &[sshd, "unite|auditd"], &[None, Some("disabled")]),
            releve("bilan:relie", &["ntp", "unite|auditd"], &[Some("no"), Some("disabled")]),
        ]);
        let notes: Vec<&Releve> = releves.iter().flatten().collect();
        assert_eq!(notes.len(), 1, "tout est relié : une seule note");
        assert_eq!(notes[0].id, "bilan:root");
        assert_eq!(notes[0].avant.gestes, [sshd, "unite|auditd", "ntp"]);
        assert_eq!(
            notes[0].avant.valeurs,
            [None, Some("disabled".into()), Some("no".into())]
        );
        let root = Some("bilan:root".to_string());
        assert_eq!(
            ids,
            [root.clone(), root.clone(), None, root.clone(), root.clone(), root]
        );
        // Sans rien en commun, chacune sa note.
        let (releves, ids) = regrouper(vec![
            releve("bilan:a", &[sshd], &[None]),
            releve("bilan:b", &["ntp"], &[Some("yes")]),
        ]);
        assert_eq!(releves.iter().flatten().count(), 2);
        assert_eq!(ids, [Some("bilan:a".into()), Some("bilan:b".into())]);
    }

    /// Deux notes de lots différents sur la même cible, défaites ensemble (« Tout remettre ») : la plus ancienne
    /// remet l'état d'avant les deux, et la plus récente compte aussi comme remise. Sinon elle restait, avec un faux
    /// ✖, et la réessayer ramenait l'état d'entre les deux.
    #[cfg(unix)]
    #[test]
    fn deux_notes_sur_la_meme_cible_defaites_ensemble() {
        use std::os::unix::fs::PermissionsExt;
        let d = dossier("deux-notes");
        let f = d.join("config-alice");
        std::fs::write(&f, "x").unwrap();
        let geste = format!("droits|{}", f.display());
        let h = historique(vec![
            note("bilan:a", "2026-10-20 09:00", &[&geste], &[Some("0644")]),
            note("bilan:b", "2026-10-22 09:00", &[&geste], &[Some("0640")]),
        ]);
        assert!(sauver_dans(&h, &d));
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        // L'ordre de « Tout remettre » : de la plus récente à la plus ancienne.
        let (issues, _) = defaire_dans(&["bilan:b".into(), "bilan:a".into()], &[], false, &d);
        assert_eq!(
            issues,
            [
                ("bilan:b".to_string(), Issue::Revenu),
                ("bilan:a".to_string(), Issue::Revenu)
            ]
        );
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o7777, 0o644);
        assert!(charger_dans(&d).reglages.is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Aller-retour des corrections natives de Windows et des réglages pour jouer : la note relue rebâtit la valeur
    /// du registre de la liste fermée ; une valeur du compte se remet pour de vrai, dans le registre (celui de Wine,
    /// jetable, en essai).
    #[cfg(windows)]
    #[test]
    fn aller_retour_windows() {
        let dossier_essai = dossier("windows");
        let h = historique(vec![
            note("bilan:w", "", &["natif|wdigest-coupe"], &[Some("dword:1")]),
            note("bilan:s", "", &["service|SSDPSRV"], &[Some("start:3")]),
            note(
                "jeux:a",
                "",
                &["alimentation"],
                &[Some("381b4222-f694-41f0-9685-ff5bb260df2e")],
            ),
        ]);
        for r in rebatis(&h) {
            assert!(note_admise(&r, &h).is_some(), "{}", r.id);
        }
        let wdigest = rebatis(&h).into_iter().find(|r| r.id == "bilan:w").unwrap();
        assert!(
            wdigest.changements[0]
                .decrire(Some("dword:1"))
                .contains("UseLogonCredential = 1")
        );
        let piege = historique(vec![note("bilan:p", "", &["service|SSDPSRV"], &[Some("start:9")])]);
        assert!(note_admise(&rebatis(&piege)[0], &piege).is_none());
        // Une valeur du compte (souris), remise pour de vrai.
        let geste = Geste::registre(false, r"Control Panel\Mouse", "MouseThreshold1");
        let changement = systeme::Changement::depuis_geste(&geste.0).unwrap();
        let avant = changement.relever().unwrap();
        let releve = relever("jeux:souris".into(), "Souris", std::slice::from_ref(&geste)).unwrap();
        assert!(noter_dans(&[&releve], &dossier_essai));
        let souris = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
            .create_subkey(r"Control Panel\Mouse")
            .unwrap()
            .0;
        souris.set_value("MouseThreshold1", &"0".to_string()).unwrap();
        let (issues, _) = defaire_dans(&["jeux:souris".into()], &[], false, &dossier_essai);
        assert_eq!(issues, [("jeux:souris".to_string(), Issue::Revenu)]);
        assert_eq!(changement.lire(), avant);
        let _ = std::fs::remove_dir_all(&dossier_essai);
    }

    /// Une correction faite tout entière de corrections natives se défait d'elle-même ; celle qui rallume l'UAC ne
    /// se défait jamais ; une commande PowerShell n'est pas relevée.
    #[cfg(windows)]
    #[test]
    fn natives_defaites_sauf_l_uac() {
        use crate::machine::Defaire;
        use crate::machine::windows::corrections::{comment_defaire, id};
        assert_eq!(
            comment_defaire(&[id("wdigest-coupe"), id("lmhash-coupe")]),
            Defaire::Gestes(vec![Geste::natif("wdigest-coupe"), Geste::natif("lmhash-coupe")])
        );
        assert_eq!(comment_defaire(&[id("uac-active")]), Defaire::Protection);
        assert_eq!(comment_defaire(&["Set-Service x".into()]), Defaire::Inconnu);
        assert_eq!(
            comment_defaire(&[id("wdigest-coupe"), "Set-Service x".into()]),
            Defaire::Inconnu
        );
    }

    /// Les textes de ce module tiennent dans `LARGEUR` colonnes, dans les deux langues.
    #[test]
    fn messages_dans_la_largeur() {
        assert_eq!(
            crate::ui::textes_trop_larges(include_str!("annulables.rs")),
            Vec::<String>::new()
        );
    }
}

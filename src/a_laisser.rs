//! Rapport à laisser : une page simple pour la personne qu'on vient de dépanner, en mots de tous les jours. La note
//! de l'ordinateur (et celle de l'arrivée, si un bilan a été fait plus tôt dans la journée), ce qu'il lui reste à
//! faire, du plus important au moins important, ce qui va bien, et trois habitudes. Un fichier HTML autonome, posé sur
//! son Bureau après accord, ouvert dans le navigateur pour être lu ou imprimé. Pas d'adresse, pas de nom d'appareil,
//! pas de commande : seulement ce qu'elle peut comprendre et faire. Le parcours « Ordinateur d'un proche » y ajoute
//! des conseils choisis pour la personne.

use std::fmt::Write;
use std::path::PathBuf;

use crate::machine::Audit;
use crate::risk::{Niveau, note};
use crate::ui::*;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// La note du premier bilan de la journée (à l'arrivée), s'il y en a eu un autre avant celui-ci.
fn note_a_l_arrivee(historique: &[crate::historique::Bilan], aujourd_hui: &str) -> Option<u32> {
    let du_jour: Vec<&crate::historique::Bilan> =
        historique.iter().filter(|b| b.date.starts_with(aujourd_hui)).collect();
    (du_jour.len() >= 2)
        .then(|| du_jour.first().and_then(|b| b.machine))
        .flatten()
}

/// La page, d'après le bilan, avec les conseils choisis pour la personne (avant les habitudes de tout le monde).
pub(crate) fn page(a: &Audit, arrivee: Option<u32>, date: &str, conseils: &[&str]) -> String {
    let mut h = String::new();
    let _ = write!(
        h,
        "<!doctype html><html lang=\"{}\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\">\
         <title>{}</title><style>\
         body{{font-family:system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem;line-height:1.5;color:#222}}\
         h1{{font-size:1.6rem;margin-bottom:.2rem}} .date{{color:#666}} .note{{font-size:3rem;font-weight:700}}\
         li{{margin:.5rem 0}} .eleve,.critique{{color:#b00020}} .moyen{{color:#a15c00}} .ok{{color:#1b7f3b}}\
         footer{{margin-top:2rem;color:#777;font-size:.9rem}} @media print{{body{{margin:0}}}}\
         </style></head><body>",
        tr!("fr", "en"),
        tr!("Bilan de votre ordinateur", "Your computer's check-up")
    );
    let _ = write!(
        h,
        "<h1>{}</h1><div class=\"date\">{}</div>",
        tr!("Bilan de votre ordinateur", "Your computer's check-up"),
        esc(date)
    );
    if a.fiable() {
        let _ = write!(
            h,
            "<p><span class=\"note\">{}</span> &nbsp;{}/100",
            note(a.score),
            a.score
        );
        if let Some(avant) = arrivee.filter(|&avant| avant != a.score) {
            let _ = write!(
                h,
                " &nbsp;<span class=\"date\">{}</span>",
                trf!(
                    "(à l'arrivée : {} {}/100)",
                    "(on arrival: {} {}/100)",
                    note(avant),
                    avant
                )
            );
        }
        h += "</p>";
    }
    let mut a_faire: Vec<&crate::machine::Constat> = a
        .constats
        .iter()
        .filter(|c| c.probleme.is_some_and(|n| n >= Niveau::Moyen))
        .collect();
    a_faire.sort_by_key(|c| std::cmp::Reverse(c.probleme));
    let _ = write!(
        h,
        "<h2>{}</h2>",
        tr!("Ce qu'il vous reste à faire", "What is left for you to do")
    );
    if a_faire.is_empty() {
        let _ = write!(
            h,
            "<p class=\"ok\">{}</p>",
            tr!(
                "Rien d'important : votre ordinateur est en ordre.",
                "Nothing important: your computer is in order."
            )
        );
    } else {
        h += "<ol>";
        for c in a_faire.iter().take(10) {
            let classe = match c.probleme {
                Some(Niveau::Critique) => "critique",
                Some(Niveau::Eleve) => "eleve",
                _ => "moyen",
            };
            let _ = write!(
                h,
                "<li><span class=\"{classe}\"><b>{}</b></span> — {}",
                esc(crate::langue::categorie(c.categorie)),
                esc(&c.message)
            );
            if let Some(k) = &c.correctif {
                let _ = write!(h, "<br><i>{}</i>", esc(&k.action));
            }
            h += "</li>";
        }
        h += "</ol>";
    }
    // Une catégorie va bien quand rien n'y est signalé, pas même une information ; une fois chacune, même si ses
    // vérifications ne se suivent pas dans le bilan.
    let mut bien: Vec<&str> = Vec::new();
    for c in a.constats.iter().filter(|c| c.verifie && c.probleme.is_none()) {
        let signale = a
            .constats
            .iter()
            .any(|d| d.categorie == c.categorie && d.probleme.is_some());
        let nom = crate::langue::categorie(c.categorie);
        if !signale && !bien.contains(&nom) {
            bien.push(nom);
        }
    }
    if !bien.is_empty() {
        let _ = write!(
            h,
            "<h2>{}</h2><p class=\"ok\">{}</p>",
            tr!("Ce qui va bien", "What is fine"),
            esc(&bien.join(" · "))
        );
    }
    if !conseils.is_empty() {
        let _ = write!(
            h,
            "<h2>{}</h2><ul>",
            tr!("Pour vous en particulier", "Especially for you")
        );
        for c in conseils {
            let _ = write!(h, "<li>{}</li>", esc(c));
        }
        h += "</ul>";
    }
    let _ = write!(
        h,
        "<h2>{}</h2><ul><li>{}</li><li>{}</li><li>{}</li></ul>",
        tr!("Trois habitudes", "Three habits"),
        tr!(
            "Acceptez les mises à jour quand l'ordinateur les propose : elles bouchent les failles.",
            "Accept updates when the computer offers them: they plug the holes."
        ),
        tr!(
            "Gardez une copie de vos photos et documents sur un disque à part, débranché après la copie.",
            "Keep a copy of your photos and documents on a separate disk, unplugged after copying."
        ),
        tr!(
            "Un mot de passe différent pour chaque site, retenu par un gestionnaire de mots de passe ; et personne ne doit prendre la main sur votre ordinateur après un appel que vous n'avez pas demandé.",
            "A different password for each site, remembered by a password manager; and nobody should take control of your computer after a call you did not ask for."
        )
    );
    let _ = write!(
        h,
        "<footer>{}</footer></body></html>",
        trf!(
            "Fait avec Vanguard {}",
            "Made with Vanguard {}",
            env!("CARGO_PKG_VERSION")
        )
    );
    h
}

/// Le Bureau de la personne, s'il existe.
fn bureau() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let maison = crate::socle::maison();
        let config = std::env::var_os("XDG_CONFIG_HOME").map_or_else(|| maison.join(".config"), PathBuf::from);
        let declares = std::fs::read_to_string(config.join("user-dirs.dirs")).unwrap_or_default();
        crate::protection::pieges::dossier_declare(&declares, "XDG_DESKTOP_DIR", &maison)
            .or_else(|| {
                ["Bureau", "Desktop"]
                    .iter()
                    .map(|n| maison.join(n))
                    .find(|d| d.is_dir())
            })
            .filter(|d| d.is_dir())
    }
    #[cfg(windows)]
    {
        winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
            .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
            .ok()
            .and_then(|k| k.get_value::<String, _>("Desktop").ok())
            .map(|c| PathBuf::from(crate::protection::pieges::developper(&c)))
            .filter(|d| d.is_dir())
    }
    #[cfg(target_os = "macos")]
    {
        Some(crate::socle::maison().join("Desktop")).filter(|d| d.is_dir())
    }
}

/// Menu Cette machine › Rapport à laisser (`vanguard rapport-a-laisser`) : d'après le dernier bilan de la session, ou un neuf.
pub fn laisser(audit: &Audit) {
    laisser_avec(audit, &[]);
}

/// La page à laisser, avec des conseils choisis pour la personne.
pub(crate) fn laisser_avec(audit: &Audit, conseils: &[&str]) {
    titre(tr!("Rapport à laisser", "Report to leave behind"));
    let aujourd_hui = chrono::Local::now().format("%Y-%m-%d").to_string();
    let date = chrono::Local::now()
        .format(tr!("%d/%m/%Y à %H:%M", "%Y-%m-%d at %H:%M"))
        .to_string();
    let html = page(
        audit,
        note_a_l_arrivee(&crate::historique::charger(), &aujourd_hui),
        &date,
        conseils,
    );
    let nom = trf!(
        "Vanguard - bilan du {aujourd_hui}.html",
        "Vanguard - check-up {aujourd_hui}.html"
    );
    let sur_le_bureau = bureau().filter(|_| {
        demander(&trf!(
            "  Poser la page « {nom} » sur le Bureau, pour que la personne la garde ? [O/n] : ",
            "  Put the page “{nom}” on the Desktop, so the person keeps it? [Y/n]: "
        ))
        .trim()
        .chars()
        .next()
        .is_none_or(|c| !matches!(c, 'n' | 'N'))
    });
    let dossier = sur_le_bureau.unwrap_or_else(crate::socle::dossier_local);
    let chemin = dossier.join(&nom);
    let ecrit = std::fs::create_dir_all(&dossier).and_then(|()| std::fs::write(&chemin, html));
    match ecrit {
        Ok(()) => {
            trp!(
                "  {VERT}✔{RESET} {} — ouverte dans le navigateur, à lire ou imprimer.",
                "  {VERT}✔{RESET} {} — opened in the browser, to read or print.",
                chemin_affichable(&chemin)
            );
            crate::machine::ouvrir(&chemin.display().to_string());
        }
        Err(e) => trp!("  ✖ Page non écrite : {e}", "  ✖ Page not written: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::historique::Bilan;
    use crate::machine::{Audit, alerte, ok};

    #[test]
    fn page_simple_et_sans_piege() {
        let a = Audit {
            systeme: "test",
            score: 72,
            constats: vec![
                ok("Pare-feu", "Pare-feu actif."),
                alerte("Mises à jour", Niveau::Moyen, "12 mises à jour attendent."),
                alerte(
                    "Comptes",
                    Niveau::Critique,
                    "Compte <script>alert(1)</script> sans mot de passe.",
                )
                .manuel("Lui donner un mot de passe", &[]),
                alerte("DNS", Niveau::Info, "Information seulement."),
            ],
        };
        let p = page(&a, Some(55), "19/10/2026 à 10:00", &[]);
        assert!(p.contains(">C</span>") && p.contains("72/100") && p.contains("à l'arrivée : D 55/100"));
        // Le plus grave d'abord ; l'information n'est pas « à faire » ; rien d'exécutable dans la page.
        let i_comptes = p.find("Comptes").unwrap();
        let i_maj = p.find("12 mises à jour").unwrap();
        assert!(i_comptes < i_maj);
        assert!(!p.contains("Information seulement") && !p.contains("<script>"));
        assert!(p.contains("&lt;script&gt;") && p.contains("Lui donner un mot de passe"));
        assert!(p.contains("Ce qui va bien") && p.contains("Pare-feu"));
        assert!(!p.contains("Pour vous en particulier"));
        // Une catégorie dite une fois, et jamais « bien » quand une de ses vérifications signale quelque chose.
        let b = Audit {
            systeme: "test",
            score: 90,
            constats: vec![
                ok("Comptes", "Mot de passe partout."),
                ok("SSH", "Clés seulement."),
                ok("Comptes", "Écran verrouillé."),
                ok("Persistance", "Rien d'inconnu au démarrage."),
                alerte("Persistance", Niveau::Info, "Service inconnu au démarrage."),
            ],
        };
        let p = page(&b, None, "19/10/2026 à 10:00", &[]);
        assert!(p.contains("Comptes · SSH<") && !p.contains("Persistance"), "{p}");
        // Les conseils d'un proche : leur section, avant les habitudes, échappés comme le reste.
        let p = page(&a, None, "19/10/2026 à 10:00", &["Raccrochez <b>vite</b>."]);
        let i_toi = p.find("Pour vous en particulier").unwrap();
        assert!(i_toi < p.find("Trois habitudes").unwrap());
        assert!(p.contains("Raccrochez &lt;b&gt;vite&lt;/b&gt;.") && !p.contains("à l'arrivée"));
    }

    #[test]
    fn note_d_arrivee_seulement_le_meme_jour() {
        let b = |date: &str, note: u32| Bilan {
            date: date.into(),
            machine: Some(note),
            ..Bilan::default()
        };
        let h = [
            b("2026-10-18 20:00", 40),
            b("2026-10-19 09:00", 55),
            b("2026-10-19 10:00", 72),
        ];
        assert_eq!(note_a_l_arrivee(&h, "2026-10-19"), Some(55));
        assert_eq!(note_a_l_arrivee(&h[..2], "2026-10-19"), None);
        assert_eq!(note_a_l_arrivee(&h, "2026-10-20"), None);
    }
}

//! Rapport HTML autonome (un seul fichier, aucun accès réseau) ouvert dans le navigateur.

use std::fmt::Write;
use std::path::PathBuf;

use crate::audit::AuditReseau;
use crate::machine::{Audit, Constat};
use crate::reseau::Rapport;
use crate::risk::{Niveau, note};
use crate::{tr, trf, trp, trw, trwln};

pub(crate) fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Des adresses IPv4, « 10.0.0.5, 10.0.0.9 ».
fn liste_ips(ips: &[std::net::Ipv4Addr]) -> String {
    ips.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
}

fn classe(n: Option<Niveau>) -> &'static str {
    match n {
        None => "ok",
        Some(Niveau::Info) => "info",
        Some(Niveau::Moyen) => "moyen",
        Some(Niveau::Eleve) => "eleve",
        Some(Niveau::Critique) => "critique",
    }
}

pub(crate) fn badge(n: Option<Niveau>) -> String {
    format!(
        "<span class=\"badge {}\">{}</span>",
        classe(n),
        n.map_or("OK", Niveau::libelle)
    )
}

fn carte_note(titre: &str, score: u32) -> String {
    let n = note(score);
    format!(
        "<div class=\"note n{n}\"><div class=\"lettre\">{n}</div><div><div class=\"etiq\">{titre}</div><div class=\"score\">{score}/100</div></div></div>"
    )
}

/// La carte d'un domaine sans note (trop de vérifications impossibles) : un tiret à la place de la lettre, le pourquoi
/// à la place du score.
fn carte_sans_note(titre: &str, detail: &str) -> String {
    format!(
        "<div class=\"note nonote\"><div class=\"lettre\">—</div><div><div class=\"etiq\">{titre}</div><div class=\"score\">{detail}</div></div></div>"
    )
}

/// Le badge d'un constat de l'audit du réseau qui n'a pas pu être vérifié : jamais « OK », jamais une simple
/// information.
fn badge_non_verifie() -> String {
    format!("<span class=\"badge nv\">{}</span>", tr!("NON VÉRIFIÉ", "NOT CHECKED"))
}

pub(crate) const CSS: &str = r"
:root{--bg:#f6f6f4;--carte:#fff;--texte:#1b1b1b;--doux:#666;--bord:#e2e2de;
--ok:#1f8a4c;--info:#2a7bb5;--moyen:#b58900;--eleve:#d0611b;--critique:#c62828;color-scheme:light}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#000;--carte:#0d0d0d;--texte:#ececec;--doux:#9a9a9a;--bord:#222;
--ok:#4cc27a;--info:#5aa9e6;--moyen:#e2b93b;--eleve:#f08a4b;--critique:#ff5a5a;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--texte);font:15px/1.5 system-ui,sans-serif}
main{max-width:960px;margin:0 auto;padding:24px 16px 64px}h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:36px 0 12px}
.sous{color:var(--doux);margin:0 0 20px}.notes{display:flex;gap:12px;flex-wrap:wrap}
.note{display:flex;gap:14px;align-items:center;background:var(--carte);border:1px solid var(--bord);border-radius:12px;padding:14px 18px;flex:1;min-width:200px}
.lettre{font-size:38px;font-weight:800;width:52px;text-align:center}.nA .lettre,.nB .lettre{color:var(--ok)}.nC .lettre{color:var(--moyen)}.nD .lettre,.nF .lettre{color:var(--critique)}
.etiq{color:var(--doux);font-size:13px}.score{font-weight:600}.nonote .lettre{color:var(--doux);font-size:22px}.carte h3{margin:0 0 4px;font-size:16px}
.carte{background:var(--carte);border:1px solid var(--bord);border-radius:12px;padding:14px 18px;margin:10px 0}
.ligne{display:flex;gap:10px;align-items:baseline;padding:6px 0;border-top:1px solid var(--bord)}.ligne:first-child{border-top:0}
.cat{font-weight:600;min-width:130px}.badge{font-size:11px;font-weight:700;padding:2px 7px;border-radius:6px;color:#fff;white-space:nowrap}
.ok{background:var(--ok)}.info{background:var(--info)}.moyen{background:var(--moyen)}.eleve{background:var(--eleve)}.critique{background:var(--critique)}.nv{background:var(--doux)}
.fix{color:var(--doux);font-size:13px;margin-top:2px}code{font:12px ui-monospace,monospace;background:var(--bg);padding:1px 5px;border-radius:4px;word-break:break-all}
.hote h3{margin:0;font-size:16px}.meta{color:var(--doux);font-size:13px}.neuf{color:var(--moyen);font-weight:700}
table{width:100%;border-collapse:collapse;margin-top:8px;font-size:14px}td{padding:4px 6px;border-top:1px solid var(--bord);vertical-align:top}
.ban{color:var(--doux);font-size:12px}ul{margin:8px 0 0;padding-left:20px}
@media (max-width:600px){.ligne{flex-wrap:wrap}.cat{min-width:0}}
";

/// Les 5 derniers tests de connexion, le plus récent en haut ; vide s'il n'y en a pas.
fn connexions(tests: &[crate::reseau::connexion::Resultat]) -> String {
    if tests.is_empty() {
        return String::new();
    }
    let mut h = String::from(tr!(
        "<h2>Connexion pour le jeu</h2><div class=carte><table><tr><td>Date</td><td>Ping</td><td>Gigue</td><td>Pertes</td><td>↓ Mbit/s</td><td>↑ Mbit/s</td><td>Bufferbloat</td></tr>",
        "<h2>Connection for gaming</h2><div class=carte><table><tr><td>Date</td><td>Ping</td><td>Jitter</td><td>Loss</td><td>↓ Mbit/s</td><td>↑ Mbit/s</td><td>Bufferbloat</td></tr>"
    ));
    let debit = |d: Option<f64>| d.map_or_else(|| "?".to_string(), |d| format!("{d:.0}"));
    for t in tests.iter().rev().take(5) {
        let bufferbloat = t.hausse_ms.map_or_else(
            || "?".to_string(),
            |m| format!("{} (+{m:.0} ms)", crate::reseau::connexion::note_bufferbloat(m).0),
        );
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{:.0} ms</td><td>{} ms</td><td>{:.0} %</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&t.date),
            t.internet_ms,
            crate::langue::decimal(t.gigue_ms, 1),
            t.pertes,
            debit(t.descendant),
            debit(t.montant),
            bufferbloat
        );
    }
    h += tr!(
        "</table><div class=meta>Menu c ou « vanguard test-connexion » pour un nouveau test.</div></div>",
        "</table><div class=meta>Menu c or “vanguard connection-test” for a new test.</div></div>"
    );
    h
}

pub fn generer(
    audit: Option<&Audit>,
    reseau: Option<&Rapport>,
    audit_reseau: Option<&AuditReseau>,
) -> std::io::Result<PathBuf> {
    let chemin = crate::reseau::dossier_donnees().join("rapport.html");
    std::fs::create_dir_all(chemin.parent().unwrap_or(&chemin))?;
    std::fs::write(&chemin, html(audit, reseau, audit_reseau))?;
    // Version texte à côté : lisible sans navigateur ni affichage graphique (mode urgence).
    std::fs::write(chemin.with_extension("md"), markdown(audit, reseau, audit_reseau))?;
    Ok(chemin)
}

/// Les notes d'un domaine de l'audit en Markdown : « **B** (80/100) », ou « incomplet (2 non vérifiés) ».
fn note_markdown(d: &crate::audit::DomaineAudite) -> String {
    match d.score {
        Some(s) => format!("**{}** ({s}/100)", note(s)),
        None => trf!(
            "incomplet ({} non vérifié(s))",
            "incomplete ({} not checked)",
            d.non_verifies
        ),
    }
}

/// La section « Audit du réseau » en Markdown : les six notes, puis chaque domaine et ses constats.
fn audit_markdown(m: &mut String, a: &AuditReseau) {
    let nom = a
        .nom_reseau
        .as_deref()
        .map(|n| trf!(" « {n} »", " “{n}”"))
        .unwrap_or_default();
    let _ = trwln!(m, "\n## Audit du réseau{nom}\n", "\n## Network audit{nom}\n");
    if a.reseau.is_none() {
        let _ = trwln!(
            m,
            "Aucun réseau local à auditer : rien n'a pu être vérifié.\n",
            "No local network to audit: nothing could be checked.\n"
        );
    }
    for d in &a.domaines {
        let Some(domaine) = d.domaine() else { continue };
        let _ = writeln!(m, "- {} : {}", domaine.titre(), note_markdown(d));
    }
    match a.score {
        Some(s) => {
            let _ = trwln!(
                m,
                "- Note de l'audit : **{}** ({s}/100), la plus basse des six",
                "- Audit grade: **{}** ({s}/100), the lowest of the six",
                note(s)
            );
        }
        None => {
            let _ = trwln!(
                m,
                "- Note de l'audit : aucune (un domaine sans note ne rend pas le réseau sain)",
                "- Audit grade: none (a domain without a grade does not make the network safe)"
            );
        }
    }
    for d in &a.domaines {
        let Some(domaine) = d.domaine() else { continue };
        let _ = writeln!(m, "\n### {} — {}\n", domaine.titre(), note_markdown(d));
        let _ = writeln!(m, "{}\n", domaine.precision());
        for c in &d.constats {
            let etiquette = if c.verifie {
                c.probleme.map_or("OK", Niveau::libelle)
            } else {
                tr!("NON VÉRIFIÉ", "NOT CHECKED")
            };
            let _ = writeln!(
                m,
                "- [{etiquette}] **{}** : {}",
                crate::langue::categorie(c.categorie),
                c.message
            );
            if let Some(k) = &c.correctif {
                let _ = trwln!(m, "  - À faire : {}", "  - To do: {}", k.action);
                for cmd in &k.commandes {
                    let _ = writeln!(m, "    `{cmd}`");
                }
            }
        }
        for f in crate::audit::references_du_domaine(d) {
            let _ = writeln!(m, "- {} · {} · {}", f.id, f.sujet(), f.references.join(", "));
        }
    }
    let non_verifies = a.non_verifies();
    if non_verifies > 0 {
        let _ = trwln!(
            m,
            "\n{non_verifies} vérification(s) impossible(s) : résultat incomplet, jamais compté comme sain.",
            "\n{non_verifies} check(s) could not be done: incomplete result, never counted as safe."
        );
    }
}

/// Les redirections UPnP de la box et l'empoisonneur de noms, en Markdown, à la suite des appareils du scan.
fn complements_scan_markdown(m: &mut String, r: &Rapport) {
    use crate::reseau::{empoisonnement, upnp};
    if let Some(e) = &r.upnp {
        let _ = trwln!(
            m,
            "\n### Ports ouverts vers Internet (UPnP)\n",
            "\n### Ports open to the Internet (UPnP)\n"
        );
        match e {
            upnp::Etat::Absent => {
                let _ = trwln!(
                    m,
                    "UPnP coupé ou absent sur le routeur : aucun appareil ne peut ouvrir de port vers Internet tout seul.",
                    "UPnP off or absent on the router: no device can open a port to the Internet by itself."
                );
            }
            upnp::Etat::OutilAbsent => {
                let _ = trwln!(
                    m,
                    "Non vérifié : les redirections du routeur n'ont pas pu être lues.",
                    "Not checked: the router's forwardings could not be read."
                );
            }
            upnp::Etat::Usurpee(ips) => {
                let _ = trwln!(
                    m,
                    "Non vérifié : le routeur n'a pas répondu, mais {} se dit routeur en UPnP (suspect).",
                    "Not checked: the router did not answer, but {} claims to be the router over UPnP (suspicious).",
                    liste_ips(ips)
                );
            }
            upnp::Etat::Actif(l) if l.lues && l.redirections.is_empty() => {
                let _ = trwln!(
                    m,
                    "UPnP actif sur le routeur, aucun port ouvert pour l'instant. À couper dans le routeur si aucun appareil n'en a besoin.",
                    "UPnP on at the router, no port open for now. Turn it off in the router if no device needs it."
                );
            }
            upnp::Etat::Actif(l) => {
                for d in &l.redirections {
                    let _ = writeln!(
                        m,
                        "- {}/{} → {}:{} [{}] {}",
                        d.port_public,
                        d.protocole.to_lowercase(),
                        d.appareil,
                        d.port_appareil,
                        upnp::niveau(d).libelle(),
                        d.description
                    );
                }
                let _ = trwln!(
                    m,
                    "\nChaque ligne rend un appareil joignable depuis Internet. Si vous n'en avez pas besoin, coupez UPnP dans le routeur.",
                    "\nEach line makes a device reachable from the Internet. If you do not need it, turn UPnP off in the router."
                );
            }
        }
    }
    if let Some(e) = &r.empoisonnement {
        let _ = trwln!(m, "\n### Empoisonneur de noms\n", "\n### Name poisoner\n");
        match e {
            empoisonnement::Rapport::SansReseauLocal => {
                let _ = trwln!(
                    m,
                    "Non testé : pas de réseau local pendant le scan.",
                    "Not tested: no local network during the scan."
                );
            }
            empoisonnement::Rapport::Teste(liste) if liste.is_empty() => {
                let _ = trwln!(
                    m,
                    "Personne ne répond aux faux noms (LLMNR, NetBIOS, mDNS) : pas d'empoisonneur comme Responder sur ce réseau.",
                    "No one answers bogus names (LLMNR, NetBIOS, mDNS): no poisoner like Responder on this network."
                );
            }
            empoisonnement::Rapport::Teste(liste) => {
                for p in liste {
                    let _ = trwln!(
                        m,
                        "- [{}] {} répond à des noms qui n'existent pas ({}) : un outil comme Responder vole ainsi les mots de passe Windows. Débranchez-le.",
                        "- [{}] {} answers names that do not exist ({}): a tool like Responder steals Windows passwords this way. Unplug it.",
                        Niveau::Eleve.libelle(),
                        p.ip,
                        p.protocoles.join(", ")
                    );
                }
            }
        }
    }
}

/// Rapport en Markdown, sans couleur ni code : il se lit avec `cat`, un éditeur de texte ou sur un téléphone.
pub fn markdown(audit: Option<&Audit>, reseau: Option<&Rapport>, audit_reseau: Option<&AuditReseau>) -> String {
    let mut m = String::new();
    let date = chrono::Local::now().format(tr!("%d/%m/%Y à %H:%M", "%Y-%m-%d %H:%M"));
    let _ = trwln!(
        m,
        "# Bilan de sécurité Vanguard\n\nGénéré le {date} par Vanguard {}.\n",
        "# Vanguard security check\n\nGenerated on {date} by Vanguard {}.\n",
        env!("CARGO_PKG_VERSION")
    );
    let ligne_note = |quoi: &str, score: u32| format!("- {quoi} : **{}** ({score}/100)\n", note(score));
    if let Some(a) = audit.filter(|a| a.fiable()) {
        m += &ligne_note(tr!("Cet ordinateur", "This computer"), a.score);
    }
    if let Some(r) = reseau {
        m += &ligne_note(&trf!("Réseau {}", "Network {}", r.reseau), r.score_global);
    }
    if let Some(s) = audit_reseau.and_then(|a| a.score) {
        m += &ligne_note(tr!("Audit du réseau", "Network audit"), s);
    }
    if let Some(a) = audit {
        let _ = trwln!(m, "\n## Cet ordinateur ({})\n", "\n## This computer ({})\n", a.systeme);
        // Les problèmes d'abord, les plus graves en tête ; puis ce qui va bien.
        let mut constats: Vec<_> = a.constats.iter().collect();
        constats.sort_by_key(|c| std::cmp::Reverse(c.probleme));
        for c in constats {
            let etiquette = c.probleme.map_or("OK", Niveau::libelle);
            let _ = writeln!(
                m,
                "- [{etiquette}] **{}** : {}",
                crate::langue::categorie(c.categorie),
                c.message
            );
            if let Some(k) = &c.correctif {
                let _ = trwln!(m, "  - À faire : {}", "  - To do: {}", k.action);
                for cmd in &k.commandes {
                    let _ = writeln!(m, "    `{cmd}`");
                }
            }
        }
    }
    if let Some(r) = reseau {
        let _ = trwln!(
            m,
            "\n## Réseau {}\n\n| Adresse | Appareil | Ports ouverts | Note |\n|---|---|---|---|",
            "\n## Network {}\n\n| Address | Device | Open ports | Grade |\n|---|---|---|---|",
            r.reseau
        );
        for h in &r.hotes {
            let ports = h
                .ports
                .iter()
                .map(|p| format!("{} {} ({})", p.libelle(), p.service, p.niveau.libelle()))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(
                m,
                "| {} | {} | {} | {} {} |",
                h.ip,
                h.titre().replace('|', "/"),
                if ports.is_empty() { "—".to_string() } else { ports },
                note(h.score),
                h.score
            );
        }
        let conseils: Vec<String> = r
            .hotes
            .iter()
            .flat_map(|h| h.alertes.iter().map(move |(_, a)| format!("- {} : {a}", h.ip)))
            .collect();
        if !conseils.is_empty() {
            let _ = trwln!(m, "\n### Conseils\n", "\n### Advice\n");
            m += &conseils.join("\n");
            m.push('\n');
        }
        complements_scan_markdown(&mut m, r);
    }
    if let Some(a) = audit_reseau {
        audit_markdown(&mut m, a);
    }
    plugins_markdown(&mut m, &crate::plugins::sortie::gardes());
    m
}

/// Un texte d'une extension dans le Markdown : chaque caractère qui met en forme (lien, image, gras, balise, tableau)
/// échappé, pour qu'un constat ne se présente pas comme le texte de Vanguard une fois le rapport collé ailleurs.
fn md(texte: &str) -> String {
    let mut s = String::with_capacity(texte.len());
    for c in texte.chars() {
        if "\\`*_[]()<>#|!~{}".contains(c) {
            s.push('\\');
        }
        s.push(c);
    }
    s
}

/// La section des plugins (`vanguard plugins <nom> --rapport`) en Markdown : à part, sans note.
fn plugins_markdown(m: &mut String, gardes: &[crate::plugins::sortie::Gardes]) {
    if gardes.is_empty() {
        return;
    }
    let _ = trwln!(
        m,
        "\n## Plugins (hors code de Vanguard)\n\nCes constats viennent de programmes ajoutés à Vanguard : ils ne comptent pas dans la note.",
        "\n## Plugins (not Vanguard's code)\n\nThese findings come from programs added to Vanguard: they do not count in the grade."
    );
    for g in gardes {
        let _ = trwln!(
            m,
            "\n### {} ({}, le {})\n",
            "\n### {} ({}, on {})\n",
            md(g.titre()),
            md(&g.nom),
            md(&g.le)
        );
        for c in &g.constats {
            let _ = writeln!(
                m,
                "- [{}] **{}** : {}",
                crate::plugins::sortie::libelle(c),
                md(&c.categorie),
                md(&c.message)
            );
        }
    }
}

/// La section des plugins en HTML : leurs constats gardés, échappés, sous un titre qui dit d'où ils viennent ; aucune
/// carte de note, et rien n'entre dans les notes du haut de la page.
fn plugins_html(h: &mut String, gardes: &[crate::plugins::sortie::Gardes]) {
    if gardes.is_empty() {
        return;
    }
    let _ = trw!(
        h,
        "<h2>Plugins (hors code de Vanguard)</h2><p class=meta>Ces constats viennent de programmes ajoutés à Vanguard (« vanguard plugins … --rapport ») : ils ne comptent pas dans la note.</p>",
        "<h2>Plugins (not Vanguard's code)</h2><p class=meta>These findings come from programs added to Vanguard (“vanguard plugins … --report”): they do not count in the grade.</p>"
    );
    for g in gardes {
        let _ = trw!(
            h,
            "<div class=carte><h3>{} <span class=meta>plugin {} · le {}</span></h3>",
            "<div class=carte><h3>{} <span class=meta>plugin {} · on {}</span></h3>",
            esc(g.titre()),
            esc(&g.nom),
            esc(&g.le)
        );
        for c in &g.constats {
            let _ = write!(
                h,
                "<div class=ligne>{}<div><span class=cat>{}</span> {}</div></div>",
                badge(c.probleme()),
                esc(&c.categorie),
                esc(&c.message)
            );
        }
        h.push_str("</div>");
    }
}

/// La ligne d'un constat : badge, catégorie, message, marche à suivre. Dans l'audit du réseau, un constat non vérifié
/// porte son propre badge (jamais « OK », jamais une simple information).
fn ligne_constat(h: &mut String, c: &Constat, audit: bool) {
    let badge = if audit && !c.verifie {
        badge_non_verifie()
    } else {
        badge(c.probleme)
    };
    let _ = write!(
        h,
        "<div class=ligne>{badge}<div><span class=cat>{}</span> {}",
        esc(crate::langue::categorie(c.categorie)),
        esc(&c.message)
    );
    if let Some(k) = &c.correctif {
        let icone = if k.automatique {
            tr!(
                "🔧 Correction automatique (Vanguard → Corriger)",
                "🔧 Automatic fix (Vanguard → Fix)"
            )
        } else {
            tr!("💡 À faire", "💡 To do")
        };
        let _ = trw!(
            h,
            "<div class=fix>{icone} : {}",
            "<div class=fix>{icone}: {}",
            esc(&k.action)
        );
        for cmd in &k.commandes {
            let _ = write!(h, "<br><code>{}</code>", esc(cmd));
        }
        h.push_str("</div>");
    }
    h.push_str("</div></div>");
}

/// La section « Audit du réseau » : six cartes, la note d'ensemble, puis chaque domaine avec ses constats (badge,
/// marche à suivre, références des règles qui ont alerté), et la liste de ce qui n'a pas pu être vérifié.
fn audit_html(h: &mut String, a: &AuditReseau) {
    let nom = a
        .nom_reseau
        .as_deref()
        .map(|n| trf!(" « {} »", " “{}”", esc(n)))
        .unwrap_or_default();
    let _ = trw!(h, "<h2>Audit du réseau{nom}</h2>", "<h2>Network audit{nom}</h2>");
    if a.reseau.is_none() {
        h.push_str(tr!(
            "<p class=meta>Aucun réseau local à auditer : rien n'a pu être vérifié.</p>",
            "<p class=meta>No local network to audit: nothing could be checked.</p>"
        ));
    }
    h.push_str("<div class=notes>");
    for d in &a.domaines {
        let Some(domaine) = d.domaine() else { continue };
        match d.score {
            Some(s) => h.push_str(&carte_note(&esc(domaine.titre()), s)),
            None => h.push_str(&carte_sans_note(
                &esc(domaine.titre()),
                &trf!(
                    "incomplet · {} non vérifié(s)",
                    "incomplete · {} not checked",
                    d.non_verifies
                ),
            )),
        }
    }
    h.push_str("</div>");
    match a.score {
        Some(s) => {
            let _ = trw!(
                h,
                "<p class=meta>Note de l'audit : {} ({s}/100), la plus basse des six.</p>",
                "<p class=meta>Audit grade: {} ({s}/100), the lowest of the six.</p>",
                note(s)
            );
        }
        None => h.push_str(tr!(
            "<p class=meta>Pas de note d'ensemble : un domaine sans note ne rend pas le réseau sain.</p>",
            "<p class=meta>No overall grade: a domain without a grade does not make the network safe.</p>"
        )),
    }
    for d in &a.domaines {
        let Some(domaine) = d.domaine() else { continue };
        let _ = write!(
            h,
            "<div class=carte><h3>{} — {}</h3><div class=meta>{}</div>",
            esc(domaine.titre()),
            match d.score {
                Some(s) => format!("{} ({s}/100)", note(s)),
                None => trf!(
                    "incomplet ({} non vérifié(s))",
                    "incomplete ({} not checked)",
                    d.non_verifies
                ),
            },
            esc(domaine.precision())
        );
        for c in &d.constats {
            ligne_constat(h, c, true);
        }
        for f in crate::audit::references_du_domaine(d) {
            let _ = write!(
                h,
                "<div class=meta>{} · {} · {}</div>",
                esc(f.id),
                esc(f.sujet()),
                esc(&f.references.join(", "))
            );
        }
        h.push_str("</div>");
    }
    let non_verifies: Vec<String> = a
        .domaines
        .iter()
        .filter_map(|d| Some((d.domaine()?, d)))
        .flat_map(|(domaine, d)| {
            d.constats
                .iter()
                .filter(|c| !c.verifie)
                .map(move |c| format!("<li>{} : {}</li>", esc(domaine.titre()), esc(&c.message)))
        })
        .collect();
    if !non_verifies.is_empty() {
        let _ = trw!(
            h,
            "<div class=carte><h3>Non vérifié ({})</h3><div class=meta>Ce que l'audit n'a pas pu vérifier : dit, jamais compté comme sain.</div><ul>{}</ul></div>",
            "<div class=carte><h3>Not checked ({})</h3><div class=meta>What the audit could not check: said, never counted as safe.</div><ul>{}</ul></div>",
            non_verifies.len(),
            non_verifies.concat()
        );
    }
}

/// Les redirections UPnP de la box et l'empoisonneur de noms du scan, à la suite des appareils : ils manquaient au
/// rapport.
fn complements_scan_html(h: &mut String, r: &Rapport) {
    use crate::reseau::{empoisonnement, upnp};
    if let Some(e) = &r.upnp {
        h.push_str(tr!(
            "<div class=carte><h3>Ports ouverts vers Internet (UPnP)</h3>",
            "<div class=carte><h3>Ports open to the Internet (UPnP)</h3>"
        ));
        match e {
            upnp::Etat::Absent => h.push_str(tr!(
                "<div class=meta>UPnP coupé ou absent sur le routeur : aucun appareil ne peut ouvrir de port vers Internet tout seul.</div>",
                "<div class=meta>UPnP off or absent on the router: no device can open a port to the Internet by itself.</div>"
            )),
            upnp::Etat::OutilAbsent => {
                let _ = write!(
                    h,
                    "<div class=ligne>{}<div>{}</div></div>",
                    badge_non_verifie(),
                    tr!(
                        "Les redirections du routeur n'ont pas pu être lues.",
                        "The router's forwardings could not be read."
                    )
                );
            }
            upnp::Etat::Usurpee(ips) => {
                let _ = write!(
                    h,
                    "<div class=ligne>{}<div>{}</div></div>",
                    badge_non_verifie(),
                    esc(&trf!(
                        "Le routeur n'a pas répondu, mais {} se dit routeur en UPnP (suspect).",
                        "The router did not answer, but {} claims to be the router over UPnP (suspicious).",
                        liste_ips(ips)
                    ))
                );
            }
            upnp::Etat::Actif(l) if l.lues && l.redirections.is_empty() => h.push_str(tr!(
                "<div class=meta>UPnP actif sur le routeur, aucun port ouvert pour l'instant. À couper dans le routeur si aucun appareil n'en a besoin.</div>",
                "<div class=meta>UPnP on at the router, no port open for now. Turn it off in the router if no device needs it.</div>"
            )),
            upnp::Etat::Actif(l) => {
                h.push_str("<table>");
                for d in &l.redirections {
                    let _ = write!(
                        h,
                        "<tr><td>{}/{}</td><td>→ {}:{}</td><td>{}</td><td>{}</td></tr>",
                        d.port_public,
                        esc(&d.protocole.to_lowercase()),
                        esc(&d.appareil),
                        d.port_appareil,
                        esc(&d.description),
                        badge(Some(upnp::niveau(d)))
                    );
                }
                h.push_str(tr!(
                    "</table><div class=meta>Chaque ligne rend un appareil joignable depuis Internet. Si vous n'en avez pas besoin, coupez UPnP dans le routeur.</div>",
                    "</table><div class=meta>Each line makes a device reachable from the Internet. If you do not need it, turn UPnP off in the router.</div>"
                ));
            }
        }
        h.push_str("</div>");
    }
    if let Some(e) = &r.empoisonnement {
        h.push_str(tr!(
            "<div class=carte><h3>Empoisonneur de noms</h3>",
            "<div class=carte><h3>Name poisoner</h3>"
        ));
        match e {
            empoisonnement::Rapport::SansReseauLocal => {
                let _ = write!(
                    h,
                    "<div class=ligne>{}<div>{}</div></div>",
                    badge_non_verifie(),
                    tr!(
                        "Pas de réseau local pendant le scan : la sonde des faux noms n'a pas tourné.",
                        "No local network during the scan: the bogus-name probe did not run."
                    )
                );
            }
            empoisonnement::Rapport::Teste(liste) if liste.is_empty() => {
                let _ = write!(
                    h,
                    "<div class=ligne>{}<div>{}</div></div>",
                    badge(None),
                    tr!(
                        "Personne ne répond aux faux noms (LLMNR, NetBIOS, mDNS) : pas d'empoisonneur comme Responder sur ce réseau.",
                        "No one answers bogus names (LLMNR, NetBIOS, mDNS): no poisoner like Responder on this network."
                    )
                );
            }
            empoisonnement::Rapport::Teste(liste) => {
                for p in liste {
                    let _ = trw!(
                        h,
                        "<div class=ligne>{}<div>{} répond à des noms qui n'existent pas ({}) : un outil comme Responder vole ainsi les mots de passe Windows. Débranchez-le.</div></div>",
                        "<div class=ligne>{}<div>{} answers names that do not exist ({}): a tool like Responder steals Windows passwords this way. Unplug it.</div></div>",
                        badge(Some(Niveau::Eleve)),
                        p.ip,
                        esc(&p.protocoles.join(", "))
                    );
                }
            }
        }
        h.push_str("</div>");
    }
}

/// Les derniers examens des outils de protection (`modele::resultat`), relus de leur JSON : la date, le verdict et
/// les problèmes. Un examen qui n'a pas tout vérifié le dit, jamais en vert.
fn examens_html(h: &mut String, examens: &[crate::modele::resultat::Resultat]) {
    // Les journaux de Windows ont leur section (`journaux_windows_html`) : pas deux fois les mêmes alertes.
    let examens: Vec<&crate::modele::resultat::Resultat> = examens
        .iter()
        .filter(|r| r.outil != crate::journaux_windows::regles::resultat::ID)
        .collect();
    if examens.is_empty() {
        return;
    }
    h.push_str(tr!(
        "<h2>Derniers examens des outils</h2><div class=carte>",
        "<h2>Latest tool examinations</h2><div class=carte>"
    ));
    for r in examens {
        let sujet = crate::modele::registre::OUTILS
            .iter()
            .find(|o| o.id == r.outil)
            .map_or(r.outil.as_str(), |o| {
                if crate::langue::anglais() { o.sujet.1 } else { o.sujet.0 }
            });
        let quand = chrono::DateTime::parse_from_rfc3339(&r.debut)
            .map(|d| {
                d.with_timezone(&chrono::Local)
                    .format(tr!("%d/%m/%Y %H:%M", "%Y-%m-%d %H:%M"))
                    .to_string()
            })
            .unwrap_or_default();
        let (badge_verdict, phrase) = match r.verdict() {
            "probleme" => (badge(r.pire()), tr!("problème(s) trouvé(s)", "problem(s) found")),
            "sain" => (badge(None), tr!("rien trouvé", "nothing found")),
            _ => (badge_non_verifie(), tr!("pas tout vérifié", "not everything checked")),
        };
        let _ = write!(
            h,
            "<div class=ligne>{badge_verdict}<div><span class=cat>{}</span> {} <span class=meta>{}</span>",
            esc(sujet),
            phrase,
            esc(&quand)
        );
        for c in r.constats.iter().filter(|c| c.etat == "probleme") {
            let _ = write!(h, "<div>{} {}</div>", badge(c.niveau), esc(&c.message));
        }
        for n in &r.couverture.non_verifies {
            let _ = write!(h, "<div class=meta>? {}</div>", esc(n));
        }
        h.push_str("</div></div>");
    }
    h.push_str("</div>");
}

/// La règle du bilan qui juge les journaux de Windows de cet ordinateur par le moteur des règles `EVT-`.
const JOURNAUX_DU_BILAN: &str = "WIN-JRN-003";

/// Les alertes des journaux de Windows montrées au plus dans la chronologie du rapport : les plus récentes.
const ALERTES_JOURNAUX: usize = 25;

/// « Journaux de Windows », quand un examen PRO-EVT-001 a été versé (`vanguard journaux-windows`) : le verdict de
/// chaque règle, puis les alertes dans l'ordre du temps, à l'heure de cet ordinateur. Tout texte est échappé : les
/// messages reprennent des champs des journaux (comptes, chemins), déjà nettoyés des caractères piégés.
///
/// Un seul endroit pour les journaux de cet ordinateur : quand le bilan du rapport les a jugés (`bilan_les_a` :
/// WIN-JRN-003, le même moteur, au moment du bilan), ils sont dans « Cet ordinateur », et l'examen de cet ordinateur
/// (plus ancien, ou du même jour) ne les répète pas. L'examen d'un dossier, qui parle d'un autre Windows, reste.
fn journaux_windows_html(h: &mut String, examens: &[crate::modele::resultat::Resultat], bilan_les_a: bool) {
    let Some(r) = examens
        .iter()
        .find(|r| r.outil == crate::journaux_windows::regles::resultat::ID)
    else {
        return;
    };
    if bilan_les_a && r.dossier.is_none() {
        return;
    }
    let locale = |d: &str| {
        chrono::DateTime::parse_from_rfc3339(d)
            .map(|d| {
                d.with_timezone(&chrono::Local)
                    .format(tr!("%d/%m/%Y %H:%M", "%Y-%m-%d %H:%M"))
                    .to_string()
            })
            .unwrap_or_default()
    };
    let fuseau = chrono::Local::now().format("UTC%:z").to_string();
    let (badge_verdict, phrase) = match r.verdict() {
        "probleme" => (badge(r.pire()), tr!("alerte(s) trouvée(s)", "alert(s) found")),
        "sain" => (
            badge(None),
            tr!("rien trouvé dans ce qui a été lu", "nothing found in what was read"),
        ),
        _ => (badge_non_verifie(), tr!("pas tout vérifié", "not everything checked")),
    };
    let _ = trw!(
        h,
        "<h2>Journaux de Windows</h2><div class=carte><div class=ligne>{badge_verdict}<div>{phrase} <span class=meta>examen du {} (vanguard journaux-windows)</span></div></div>",
        "<h2>Windows logs</h2><div class=carte><div class=ligne>{badge_verdict}<div>{phrase} <span class=meta>examination of {} (vanguard windows-logs)</span></div></div>",
        esc(&locale(&r.debut))
    );
    // L'analyse d'un dossier (journaux rapportés, disque d'un autre ordinateur) ne parle pas de cet ordinateur.
    if let Some(d) = &r.dossier {
        let _ = trw!(
            h,
            "<div class=meta>Journaux d'un dossier, pas de cet ordinateur : {}</div>",
            "<div class=meta>Logs from a folder, not from this computer: {}</div>",
            esc(d)
        );
    }
    // Un résultat dont le sceau ne prouve rien (accepté tel quel, ou changé hors de Vanguard) n'a aucun vert.
    let prouve = !r.couverture.non_verifies.iter().any(|n| !n.starts_with("EVT-"));
    // Le verdict de chaque règle : son constat de couverture (sain, non vérifié et pourquoi, sans objet), et le
    // nombre de ses alertes.
    let mut regles: Vec<&str> = Vec::new();
    for c in &r.constats {
        if !c.regle.is_empty() && !regles.contains(&c.regle.as_str()) {
            regles.push(&c.regle);
        }
    }
    for regle in regles {
        let siens: Vec<_> = r.constats.iter().filter(|c| c.regle == regle).collect();
        let alertes = siens.iter().filter(|c| c.etat == "probleme").count();
        let pire = siens
            .iter()
            .filter(|c| c.etat == "probleme")
            .filter_map(|c| c.niveau)
            .max();
        let couverture = siens.iter().find(|c| c.etat != "probleme");
        let marque = match (pire, couverture.map(|c| c.etat.as_str())) {
            (Some(n), _) => badge(Some(n)),
            (None, Some("sain")) if prouve => badge(None),
            (None, Some("sans-objet")) => "<span class=meta>–</span>".to_string(),
            _ => badge_non_verifie(),
        };
        let compte = if alertes > 0 {
            trf!("{alertes} alerte(s). ", "{alertes} alert(s). ")
        } else {
            String::new()
        };
        let _ = write!(
            h,
            "<div class=ligne>{marque}<div><span class=cat>{}</span> {}{}</div></div>",
            esc(regle),
            esc(&compte),
            esc(couverture.map_or("", |c| c.message.as_str()))
        );
    }
    // Ce qui ne tient à aucune règle (fichiers au-delà des bornes, résultat changé hors de Vanguard) ; le reste est
    // dans le verdict de sa règle.
    for n in r.couverture.non_verifies.iter().filter(|n| !n.starts_with("EVT-")) {
        let _ = write!(h, "<div class=meta>? {}</div>", esc(n));
    }
    let mut alertes: Vec<_> = r.constats.iter().filter(|c| c.etat == "probleme").collect();
    // Dans l'ordre du temps (les dates sont en UTC, au même format : l'ordre des textes est celui du temps), les
    // alertes sans date à la fin.
    alertes.sort_by(|a, b| (a.date.is_none(), &a.date).cmp(&(b.date.is_none(), &b.date)));
    if !alertes.is_empty() {
        let _ = trw!(
            h,
            "<h3>Chronologie (heures de cet ordinateur, {fuseau})</h3>",
            "<h3>Timeline (this computer's times, {fuseau})</h3>"
        );
        let datees = alertes.iter().filter(|c| c.date.is_some()).count();
        let coupees = datees.saturating_sub(ALERTES_JOURNAUX);
        if coupees > 0 {
            let _ = trw!(
                h,
                "<div class=meta>{coupees} alerte(s) plus ancienne(s) non montrée(s) : vanguard journaux-windows --json les donne toutes.</div>",
                "<div class=meta>{coupees} older alert(s) not shown: vanguard windows-logs --json gives them all.</div>"
            );
        }
        let sans_date = alertes.len() - datees;
        let montrees_sans_date = sans_date.min(10);
        for c in alertes.iter().skip(coupees).take(ALERTES_JOURNAUX + montrees_sans_date) {
            let quand = c
                .date
                .as_deref()
                .map_or_else(|| tr!("sans date", "no date").to_string(), locale);
            let _ = write!(
                h,
                "<div class=ligne>{}<div><span class=meta>{}</span> <span class=cat>{}</span> {}</div></div>",
                badge(c.niveau),
                esc(&quand),
                esc(&c.regle),
                esc(&c.message)
            );
        }
        if sans_date > montrees_sans_date {
            let _ = trw!(
                h,
                "<div class=meta>{} alerte(s) sans date de plus : vanguard journaux-windows --json les donne toutes.</div>",
                "<div class=meta>{} more alert(s) without a date: vanguard windows-logs --json gives them all.</div>",
                sans_date - montrees_sans_date
            );
        }
    }
    h.push_str("</div>");
}

/// Encodage base64, pour mettre une image dans la page elle-même (le rapport reste un seul fichier).
pub(crate) fn base64(octets: &[u8]) -> String {
    const LETTRES: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(octets.len().div_ceil(3) * 4);
    for bloc in octets.chunks(3) {
        // 3 octets = 24 bits = 4 lettres de 6 bits ; « = » complète le dernier bloc.
        let n = bloc.iter().fold(0u32, |acc, &o| acc << 8 | u32::from(o)) << (8 * (3 - bloc.len()));
        for i in 0..4 {
            s.push(if i <= bloc.len() {
                char::from(LETTRES[(n >> (18 - 6 * i) & 63) as usize])
            } else {
                '='
            });
        }
    }
    s
}

fn html(audit: Option<&Audit>, reseau: Option<&Rapport>, audit_reseau: Option<&AuditReseau>) -> String {
    let mut h = String::new();
    let date = chrono::Local::now().format(tr!("%d/%m/%Y à %H:%M", "%Y-%m-%d %H:%M"));
    // Le logo dans l'onglet du navigateur (32 px, environ 3 Ko).
    let logo = base64(include_bytes!("../assets/icones/vanguard-32.png"));
    let _ = trw!(
        h,
        "<!doctype html><html lang=fr><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <title>Rapport Vanguard</title><link rel=icon href=\"data:image/png;base64,{logo}\"><style>{CSS}</style></head><body><main><h1>Bilan de sécurité</h1><p class=sous>Généré par Vanguard le {date}</p><div class=notes>",
        "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <title>Vanguard report</title><link rel=icon href=\"data:image/png;base64,{logo}\"><style>{CSS}</style></head><body><main><h1>Security check</h1><p class=sous>Generated by Vanguard on {date}</p><div class=notes>"
    );
    // Une note de machine n'est montrée que si l'audit a vraiment pu se faire.
    let audit_note = audit.filter(|a| a.fiable());
    if let Some(a) = audit_note {
        h += &carte_note(tr!("Cet ordinateur", "This computer"), a.score);
    }
    if let Some(r) = reseau {
        h += &carte_note(&trf!("Réseau {}", "Network {}", esc(&r.reseau)), r.score_global);
    }
    if let (Some(a), Some(r)) = (audit_note, reseau) {
        // La note de l'audit du réseau, quand il en a une, compte dans le global : le minimum des trois.
        let global = audit_reseau
            .and_then(|x| x.score)
            .map_or(a.score.min(r.score_global), |s| s.min(a.score).min(r.score_global));
        h += &carte_note("Global", global);
    }
    h += "</div>";
    if let Some(svg) = crate::historique::courbe(&crate::historique::charger()) {
        let _ = trw!(
            h,
            "<h2>Évolution des notes</h2><div class=carte>{svg}<div class=meta><span style=\"color:var(--info)\">●</span> cet ordinateur · <span style=\"color:var(--ok)\">●</span> réseau (30 derniers bilans complets)</div></div>",
            "<h2>Grade history</h2><div class=carte>{svg}<div class=meta><span style=\"color:var(--info)\">●</span> this computer · <span style=\"color:var(--ok)\">●</span> network (last 30 full checks)</div></div>"
        );
    }

    if let Some(etat) = crate::historique::etat_chaine() {
        let _ = write!(h, "<p class=meta>{}</p>", esc(&etat));
    }
    if let Some((n, reussies, derniere)) = crate::changements::resume() {
        let _ = trw!(
            h,
            "<p class=meta>Ce que Vanguard a changé : {n} correction(s) lancée(s) sur cet ordinateur, {reussies} réussie(s), la dernière le {}. Le détail : « vanguard changements ».</p>",
            "<p class=meta>What Vanguard changed: {n} fix(es) run on this computer, {reussies} successful, the last on {}. Details: “vanguard changes”.</p>",
            esc(&derniere)
        );
    }

    let examens = crate::modele::resultat::derniers();
    examens_html(&mut h, &examens);
    // WIN-JRN-003 juge les journaux de cet ordinateur dans le bilan : la section des journaux ne les répète pas.
    let bilan_les_a = audit.is_some_and(|a| a.constats.iter().any(|c| c.regle == JOURNAUX_DU_BILAN));
    journaux_windows_html(&mut h, &examens, bilan_les_a);
    h += &connexions(&crate::reseau::connexion::historique());

    if let Some(a) = audit {
        h += tr!(
            "<h2>Cet ordinateur</h2><div class=carte>",
            "<h2>This computer</h2><div class=carte>"
        );
        for c in &a.constats {
            ligne_constat(&mut h, c, false);
        }
        h += "</div>";
    }
    if let Some(a) = audit_reseau {
        audit_html(&mut h, a);
    }

    if let Some(r) = reseau {
        let nom = r
            .nom_reseau
            .as_deref()
            .map(|n| trf!(" « {} »", " “{}”", esc(n)))
            .unwrap_or_default();
        let _ = trw!(
            h,
            "<h2>Réseau{nom} — {} appareils</h2>",
            "<h2>Network{nom} — {} devices</h2>",
            r.hotes.len()
        );
        for hote in &r.hotes {
            let role = hote
                .role
                .map(|r| format!(" · {}", crate::langue::role(r)))
                .unwrap_or_default();
            let neuf = if hote.nouvelle {
                tr!(
                    " <span class=neuf>NOUVEL APPAREIL</span>",
                    " <span class=neuf>NEW DEVICE</span>"
                )
            } else {
                ""
            };
            let depuis = match (&hote.premier_vu, hote.nouvelle) {
                (Some(d), false) => trf!(
                    " · connu depuis le {}",
                    " · known since {}",
                    esc(&crate::reseau::date_fr(d))
                ),
                _ => String::new(),
            };
            let _ = trw!(
                h,
                "<div class=\"carte hote\"><h3>{} <span class=meta>{}{}</span>{neuf}</h3><div class=meta>{}{depuis} · score {}/100</div>",
                "<div class=\"carte hote\"><h3>{} <span class=meta>{}{}</span>{neuf}</h3><div class=meta>{}{depuis} · score {}/100</div>",
                hote.ip,
                esc(&hote.titre()),
                esc(&role),
                esc(hote.mac.as_deref().unwrap_or(tr!("MAC inconnue", "unknown MAC"))),
                hote.score
            );
            if hote.ports.is_empty() {
                h += tr!(
                    "<div class=meta>Aucun port ouvert parmi ceux testés.</div>",
                    "<div class=meta>No open port among those tested.</div>"
                );
            } else {
                h += "<table>";
                for p in &hote.ports {
                    let ban = p
                        .banniere
                        .as_deref()
                        .map(|b| format!("<div class=ban>{}</div>", esc(b)))
                        .unwrap_or_default();
                    let ban = ban
                        + &p.programme
                            .as_deref()
                            .map(|n| {
                                trf!(
                                    "<div class=ban>programme : {}</div>",
                                    "<div class=ban>program: {}</div>",
                                    esc(n)
                                )
                            })
                            .unwrap_or_default();
                    let _ = write!(
                        h,
                        "<tr><td>{}</td><td>{}{ban}</td><td>{}</td></tr>",
                        p.libelle(),
                        esc(p.service),
                        badge(Some(p.niveau))
                    );
                }
                h += "</table>";
            }
            if !hote.alertes.is_empty() {
                h += "<ul>";
                for (n, msg) in &hote.alertes {
                    let _ = write!(h, "<li>{} {}</li>", badge(Some(*n)), esc(msg));
                }
                h += "</ul>";
            }
            h += "</div>";
        }
        complements_scan_html(&mut h, r);
    }
    if let Some(r) = reseau.filter(|r| !r.absents.is_empty()) {
        h += tr!(
            "<h2>Déjà vus, absents aujourd'hui</h2><div class=carte><ul>",
            "<h2>Seen before, absent today</h2><div class=carte><ul>"
        );
        for a in &r.absents {
            let quand = a
                .dernier_vu
                .as_deref()
                .map(|d| trf!(" — vu le {}", " — seen on {}", esc(&crate::reseau::date_fr(d))))
                .unwrap_or_default();
            let _ = write!(h, "<li>{} {}{}</li>", a.ip, esc(&a.titre), quand);
        }
        h += "</ul></div>";
    }
    plugins_html(&mut h, &crate::plugins::sortie::gardes());
    h += "</main></body></html>";
    h
}

/// Le rapport écrit par le dernier bilan, s'il a moins de `age_max` : `vanguard rapport` le rouvre sans refaire le bilan.
pub fn recent(age_max: std::time::Duration) -> Option<PathBuf> {
    let chemin = crate::reseau::dossier_donnees().join("rapport.html");
    let age = std::fs::metadata(&chemin).ok()?.modified().ok()?.elapsed().ok()?;
    (age <= age_max).then_some(chemin)
}

pub fn ouvrir(audit: Option<&Audit>, reseau: Option<&Rapport>, audit_reseau: Option<&AuditReseau>) {
    match generer(audit, reseau, audit_reseau) {
        Ok(p) => {
            trp!("  Rapport : {}", "  Report: {}", p.display());
            crate::machine::ouvrir(&p.display().to_string());
        }
        Err(e) => trp!(
            "  Impossible d'écrire le rapport : {e}",
            "  Could not write the report: {e}"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Les examens versés par les outils se lisent dans le rapport : un examen incomplet n'y est jamais « rien
    /// trouvé », un problème y garde son message échappé.
    #[test]
    fn examens_des_outils_au_rapport() {
        use crate::modele::resultat::{Couverture, Resultat};
        let debut = (chrono::Utc::now(), std::time::Instant::now());
        let incomplet = Resultat::nouveau(
            "PRO-ESP-001",
            debut,
            &[crate::machine::ok("Logiciels espions", "Aucun signe.")],
            Couverture {
                verifies: 2,
                non_verifies: vec!["mémoire DNS <illisible>".into()],
            },
        );
        let grave = Resultat::nouveau(
            "PRO-PER-001",
            debut,
            &[crate::machine::alerte(
                "Logiciels pas à jour",
                Niveau::Eleve,
                "Firefox <128.0>",
            )],
            Couverture {
                verifies: 5,
                non_verifies: Vec::new(),
            },
        );
        let mut h = String::new();
        examens_html(&mut h, &[incomplet, grave]);
        assert!(h.contains("pas tout vérifié") && !h.contains("rien trouvé"), "{h}");
        assert!(
            h.contains("Firefox &lt;128.0&gt;") && h.contains("mémoire DNS &lt;illisible&gt;"),
            "{h}"
        );
        let mut vide = String::new();
        examens_html(&mut vide, &[]);
        assert_eq!(vide, "");
    }

    /// L'examen des journaux de Windows a sa section, et seulement elle : le verdict de chaque règle, puis les
    /// alertes dans l'ordre du temps, échappées.
    #[test]
    fn journaux_de_windows_au_rapport() {
        use crate::modele::resultat::{Couverture, Resultat};
        let debut = (chrono::Utc::now(), std::time::Instant::now());
        let mut tard = crate::machine::alerte("Journaux d'événements", Niveau::Eleve, "service <script>x</script>");
        tard.regle = "EVT-SRV-001";
        let mut tot = crate::machine::alerte("Journaux d'événements", Niveau::Critique, "journal effacé");
        tot.regle = "EVT-EFF-001";
        let mut nv = crate::machine::impossible("Journaux d'événements", "comptes : non vérifié — Security absent");
        nv.regle = "EVT-ADM-001";
        let mut r = Resultat::nouveau(
            crate::journaux_windows::regles::resultat::ID,
            debut,
            &[tard, tot, nv],
            Couverture {
                verifies: 2,
                non_verifies: vec!["EVT-ADM-001 : Security absent".into(), "3 fichiers au-delà".into()],
            },
        );
        r.constats[0].date = Some("2026-10-20T12:00:00Z".into());
        r.constats[1].date = Some("2026-10-19T08:00:00Z".into());
        let mut h = String::new();
        examens_html(&mut h, std::slice::from_ref(&r));
        assert_eq!(h, "", "pas deux fois");
        journaux_windows_html(&mut h, std::slice::from_ref(&r), false);
        assert!(h.contains("<h2>Journaux de Windows</h2>"), "{h}");
        assert!(h.contains("&lt;script&gt;") && !h.contains("<script>"), "{h}");
        let (eff, srv) = (
            h.rfind("journal effacé").unwrap(),
            h.rfind("service &lt;script").unwrap(),
        );
        assert!(eff < srv, "le plus ancien d'abord : {h}");
        assert!(h.contains("Security absent") && h.contains("3 fichiers au-delà"), "{h}");
        // Un dossier analysé est dit ; un résultat accepté sans preuve n'a aucun vert.
        let mut r2 = r.clone();
        r2.dossier = Some("/mnt/<disque>".into());
        r2.couverture
            .non_verifies
            .push("résultat accepté tel quel au premier sceau".into());
        r2.constats[2].etat = "sain".into();
        let mut h2 = String::new();
        journaux_windows_html(&mut h2, &[r2], false);
        assert!(h2.contains("pas de cet ordinateur : /mnt/&lt;disque&gt;"), "{h2}");
        assert!(!h2.contains(&badge(None)), "{h2}");
        let mut vide = String::new();
        journaux_windows_html(&mut vide, &[], false);
        assert_eq!(vide, "");
        // Le bilan a jugé les journaux de cet ordinateur (WIN-JRN-003) : l'examen de cet ordinateur ne les répète
        // pas ; celui d'un dossier, qui parle d'un autre Windows, reste.
        let mut une_fois = String::new();
        journaux_windows_html(&mut une_fois, std::slice::from_ref(&r), true);
        assert_eq!(une_fois, "", "pas deux fois");
        r.dossier = Some("/mnt/disque".into());
        journaux_windows_html(&mut une_fois, &[r], true);
        assert!(une_fois.contains("<h2>Journaux de Windows</h2>"), "{une_fois}");
    }

    #[test]
    fn les_plugins_ont_leur_section_a_part_sans_note() {
        use crate::plugins::sortie::{ConstatPlugin, Gardes};
        let g = Gardes {
            nom: "salon".into(),
            titre: ["<b>Essai</b>".into(), "Test".into()],
            le: "2026-10-21 10:00".into(),
            constats: vec![ConstatPlugin {
                niveau: "critique".into(),
                categorie: "Salon".into(),
                message: "<script>alert(1)</script>".into(),
            }],
        };
        let mut h = String::new();
        plugins_html(&mut h, std::slice::from_ref(&g));
        assert!(h.contains("<h2>Plugins (hors code de Vanguard)</h2>"));
        assert!(h.contains("&lt;script&gt;") && !h.contains("<script>") && h.contains("&lt;b&gt;Essai"));
        assert!(h.contains("badge critique") && !h.contains("class=\"note"));
        let mut m = String::new();
        plugins_markdown(&mut m, &[g]);
        assert!(m.contains("## Plugins (hors code de Vanguard)") && m.contains("[CRITIQUE] **Salon**"));
        // Échappé : ni balise ni lien ni image d'un constat ne se rend.
        assert!(m.contains("\\<script\\>alert\\(1\\)\\</script\\>"), "{m}");
        assert_eq!(
            md("![x](http://e/p.png) **a**"),
            "\\!\\[x\\]\\(http://e/p.png\\) \\*\\*a\\*\\*"
        );
        let mut vide = String::new();
        plugins_html(&mut vide, &[]);
        assert_eq!(vide, "");
    }

    #[test]
    fn rapport_texte() {
        use crate::machine::{Audit, Constat};
        let audit = Audit {
            systeme: "Linux",
            score: 85,
            constats: vec![
                Constat {
                    categorie: "Pare-feu",
                    probleme: None,
                    message: "ufw actif.".into(),
                    correctif: None,
                    verifie: true,
                    regle: "",
                    objet: crate::modele::Objet::NonMigre,
                    precision: crate::modele::Precision::Aucune,
                },
                Constat {
                    categorie: "Ports en écoute",
                    probleme: Some(Niveau::Eleve),
                    message: "445/tcp ouvert.".into(),
                    correctif: None,
                    verifie: true,
                    regle: "",
                    objet: crate::modele::Objet::NonMigre,
                    precision: crate::modele::Precision::Aucune,
                },
            ],
        };
        let m = markdown(Some(&audit), None, None);
        assert!(m.starts_with("# Bilan de sécurité Vanguard"));
        assert!(m.contains("**B** (85/100)"));
        // Le problème passe avant ce qui va bien.
        assert!(m.find("445/tcp").unwrap() < m.find("ufw actif").unwrap());
        assert!(!m.contains('\x1b'));
    }

    #[test]
    fn tests_de_connexion_dans_le_rapport() {
        assert_eq!(connexions(&[]), "");
        let r = crate::reseau::connexion::Resultat {
            date: "2026-10-17 15:00".into(),
            internet_ms: 17.2,
            gigue_ms: 3.4,
            pertes: 0.0,
            descendant: Some(106.4),
            montant: None,
            hausse_ms: Some(43.0),
            reseau: None,
        };
        let h = connexions(&[r]);
        assert!(h.contains("<td>17 ms</td>") && h.contains("<td>106</td><td>?</td>") && h.contains("B (+43 ms)"));
    }

    #[test]
    fn logo_dans_l_onglet() {
        // Exemples de la norme (RFC 4648).
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        // « iVBORw0KGgo » : la signature d'un fichier PNG, encodée.
        assert!(html(None, None, None).contains("<link rel=icon href=\"data:image/png;base64,iVBORw0KGgo"));
    }
    use crate::reseau::{Hote, PortOuvert};

    #[test]
    fn une_banniere_piegee_ne_devient_pas_du_code() {
        // Un appareil du réseau choisit sa bannière : elle ne doit jamais s'exécuter dans le rapport.
        let p = PortOuvert {
            port: 8080,
            service: "HTTP alt",
            niveau: Niveau::Moyen,
            banniere: Some("<script>alert(1)</script>".into()),
            conseil: "",
            nouveau: false,
            programme: Some("<b>x</b>".into()),
            udp: false,
        };
        let h = Hote {
            ip: "10.0.0.9".parse().unwrap(),
            nom: Some("<img src=x onerror=alert(2)>".into()),
            mac: None,
            fabricant: None,
            surnom: None,
            premier_vu: None,
            role: None,
            nouvelle: false,
            ports: vec![p],
            alertes: vec![],
            score: 95,
        };
        let r = Rapport {
            reseau: "10.0.0.0/24".into(),
            nom_reseau: Some("<i>wifi</i>".into()),
            absents: vec![],
            duree_s: 1.0,
            score_global: 95,
            note: "A",
            hotes: vec![h],
            upnp: None,
            empoisonnement: None,
        };
        let page = html(None, Some(&r), None);
        assert!(!page.contains("<script>alert"));
        assert!(!page.contains("<img src=x"));
        assert!(!page.contains("<b>x</b>") && !page.contains("<i>wifi</i>"));
        assert!(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    /// L'audit du réseau dans le rapport : six cartes (note ou incomplet), les constats de chaque domaine avec leur
    /// badge (« non vérifié » à part), les références des règles qui ont alerté, puis les redirections UPnP et
    /// l'empoisonneur du scan, absents du rapport jusqu'ici ; un texte piégé reste du texte.
    #[test]
    fn audit_du_reseau_dans_le_rapport() {
        use crate::audit::{AuditReseau, Domaine, DomaineAudite};
        use crate::reseau::{empoisonnement, upnp};
        let mut joignable =
            crate::machine::alerte("Appareils", Niveau::Critique, "<b>cam</b> joignable depuis Internet.");
        joignable.regle = "COM-APP-001";
        let joignable = joignable.manuel("Retirez la redirection", &[]);
        let trafic = crate::audit::non_verifie("Appareils", "COM-APP-003", "trafic <script>x</script> non visible");
        let domaines = Domaine::TOUS
            .into_iter()
            .map(|d| {
                if d == Domaine::Appareils {
                    DomaineAudite {
                        domaine: d.nom(),
                        score: Some(70),
                        note: Some("C"),
                        verifies: 2,
                        non_verifies: 1,
                        constats: vec![
                            joignable.clone(),
                            crate::machine::ok("Appareils", "bien"),
                            trafic.clone(),
                        ],
                    }
                } else {
                    DomaineAudite {
                        domaine: d.nom(),
                        score: None,
                        note: None,
                        verifies: 0,
                        non_verifies: 1,
                        constats: vec![crate::audit::non_verifie(
                            d.categorie(),
                            "",
                            "Non vérifié : rien n'a pu être lu pour ce domaine.",
                        )],
                    }
                }
            })
            .collect();
        let a = AuditReseau {
            reseau: Some("10.0.0.0/24".into()),
            nom_reseau: Some("<i>Salon</i>".into()),
            invite: false,
            rapide: false,
            domaines,
            score: None,
            note: None,
            duree_s: 1.0,
        };
        let r = Rapport {
            reseau: "10.0.0.0/24".into(),
            nom_reseau: Some("Salon".into()),
            absents: vec![],
            duree_s: 1.0,
            score_global: 90,
            note: "A",
            hotes: vec![],
            upnp: Some(upnp::Etat::Actif(Box::new(crate::audit::igd::Lecture {
                description: crate::audit::igd::Description {
                    adresse: None,
                    nom: None,
                    fabricant: None,
                    modele: None,
                    version: None,
                    serveur: None,
                },
                adresse_externe: None,
                connexion: None,
                redirections: vec![upnp::Redirection {
                    protocole: "TCP".into(),
                    port_public: 8080,
                    appareil: "10.0.0.30".into(),
                    port_appareil: 80,
                    description: "<img src=x onerror=alert(5)>".into(),
                    bail: 0,
                    hote_distant: String::new(),
                    active: true,
                }],
                lues: true,
                tronquees: false,
                ailleurs: Vec::new(),
            }))),
            empoisonnement: Some(empoisonnement::Rapport::Teste(vec![empoisonnement::Empoisonneur {
                ip: "10.0.0.66".parse().unwrap(),
                protocoles: vec!["LLMNR", "NetBIOS"],
            }])),
        };
        let page = html(None, Some(&r), Some(&a));
        assert!(
            page.contains("<h2>Audit du réseau « &lt;i&gt;Salon&lt;/i&gt; »</h2>"),
            "{page}"
        );
        // Six cartes de l'audit, plus celle du réseau en tête.
        assert_eq!(page.matches("<div class=\"note ").count(), 7);
        assert_eq!(page.matches("class=\"note nonote\"").count(), 5);
        assert!(page.contains("<h3>Appareils — C (70/100)</h3>"));
        assert!(page.contains("NON VÉRIFIÉ") && page.contains("<h3>Non vérifié (6)</h3>"));
        assert!(page.contains("COM-APP-001 · objet joignable depuis Internet"), "{page}");
        assert!(page.contains("💡 À faire : Retirez la redirection"));
        assert!(
            page.contains("Ports ouverts vers Internet (UPnP)")
                && page.contains("<td>8080/tcp</td><td>→ 10.0.0.30:80</td>")
        );
        assert!(
            page.contains("Empoisonneur de noms")
                && page.contains("10.0.0.66 répond")
                && page.contains("LLMNR, NetBIOS")
        );
        for piege in ["<b>cam</b>", "<script>", "<img src=x", "<i>Salon</i>"] {
            assert!(!page.contains(piege), "{piege}");
        }
        let m = markdown(None, Some(&r), Some(&a));
        assert!(m.contains("## Audit du réseau « <i>Salon</i> »") && m.contains("- Appareils : **C** (70/100)"));
        assert!(m.contains("- Exposition : incomplet (1 non vérifié(s))"), "{m}");
        assert!(m.contains("[NON VÉRIFIÉ] **Appareils**") && m.contains("[CRITIQUE] **Appareils**"));
        assert!(
            m.contains("### Ports ouverts vers Internet (UPnP)") && m.contains("- 8080/tcp → 10.0.0.30:80 [MOYEN]")
        );
        assert!(m.contains("### Empoisonneur de noms") && m.contains("[ÉLEVÉ] 10.0.0.66"));
        assert!(m.contains("6 vérification(s) impossible(s)"));
        // Sans réseau local : la section le dit, sans aucune carte notée.
        let sans = AuditReseau::sans_reseau("hors ligne");
        let page = html(None, None, Some(&sans));
        assert!(page.contains("Aucun réseau local à auditer") && !page.contains("/100"));
        assert_eq!(page.matches("class=\"note nonote\"").count(), 6);
    }

    /// Les dates du premier et du dernier passage d'un appareil viennent de la base, un fichier : une sauvegarde
    /// restaurée ou la base d'une clé peuvent en apporter de piégées. Elles restent du texte dans le rapport.
    #[test]
    fn une_date_piegee_ne_devient_pas_du_code() {
        let h = Hote {
            ip: "10.0.0.9".parse().unwrap(),
            nom: None,
            mac: None,
            fabricant: None,
            surnom: None,
            premier_vu: Some("<img src=x onerror=alert(3)>".into()),
            role: None,
            nouvelle: false,
            ports: vec![],
            alertes: vec![],
            score: 100,
        };
        let r = Rapport {
            reseau: "10.0.0.0/24".into(),
            nom_reseau: None,
            absents: vec![crate::reseau::Absent {
                ip: "10.0.0.20".parse().unwrap(),
                titre: "Imprimante".into(),
                dernier_vu: Some("<script>alert(4)</script>".into()),
            }],
            duree_s: 1.0,
            score_global: 100,
            note: "A",
            hotes: vec![h],
            upnp: None,
            empoisonnement: None,
        };
        let page = html(None, Some(&r), None);
        assert!(
            !page.contains("<img src=x") && !page.contains("<script>alert(4)"),
            "{page}"
        );
        assert!(page.contains("&lt;script&gt;alert(4)&lt;/script&gt;"));
    }
}

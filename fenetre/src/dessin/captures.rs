//! Les captures de la fenêtre en PNG, sans fenêtre ni écran : egui dessine ses images comme d'habitude, et un petit
//! rendu logiciel (ici, seulement dans les essais) remplit leurs triangles comme la carte graphique le ferait avec
//! egui_glow : couleurs en gamma et prémultipliées, texture multipliée en gamma, mélange « un, un moins alpha »,
//! ciseaux au pixel, règle haut-gauche pour qu'un bord partagé ne soit peint qu'une fois. Rien de l'écran de
//! l'ordinateur n'est lu ni touché ; aucune carte graphique, aucun bureau n'est demandé. Données inventées.
//!
//! Refaire les captures (dans ~/.cache/vanguard-dev/captures-fenetre/, jamais dans le dépôt) :
//! `outils/captures-fenetre.sh` ; un autre dossier : `VANGUARD_CAPTURES=<dossier> outils/captures-fenetre.sh`.

// raison : un rendu de pixels, en essai : des mesures en points converties en indices de pixels, bornées avant.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap
)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use eframe::egui::{
    self, Color32, Context, ImageData, Pos2, Rect, TextureFilter, TextureId, TexturesDelta, Ui, epaint, vec2,
};

use crate::appli::{Appli, Ecran};
use crate::commandes::{Commande, Rubrique};

struct Texture {
    taille: [usize; 2],
    px: Vec<Color32>,
    lisse: bool,
}

/// Une image rendue : RVBA en gamma, prémultipliée, de 0 à 1.
pub struct Toile {
    pub largeur: usize,
    pub hauteur: usize,
    px: Vec<[f32; 4]>,
}

impl Toile {
    fn nouvelle(largeur: usize, hauteur: usize, fond: Color32) -> Toile {
        Toile {
            largeur,
            hauteur,
            px: vec![rvba(fond); largeur * hauteur],
        }
    }

    /// La couleur d'un pixel, en octets (comme la carte graphique les écrirait).
    pub fn pixel(&self, x: usize, y: usize) -> [u8; 4] {
        let c = self.px[y * self.largeur + x];
        c.map(|v| (v.clamp(0.0, 1.0) * 255.0).round() as u8)
    }

    /// En PNG RVB 8 bits (la fenêtre est opaque).
    pub fn ecrire_png(&self, chemin: &Path) -> std::io::Result<()> {
        let f = std::io::BufWriter::new(std::fs::File::create(chemin)?);
        let mut e = png::Encoder::new(f, self.largeur as u32, self.hauteur as u32);
        e.set_color(png::ColorType::Rgb);
        e.set_depth(png::BitDepth::Eight);
        e.set_compression(png::Compression::Fast);
        let mut octets = Vec::with_capacity(self.largeur * self.hauteur * 3);
        for y in 0..self.hauteur {
            for x in 0..self.largeur {
                octets.extend_from_slice(&self.pixel(x, y)[..3]);
            }
        }
        let mut w = e.write_header().map_err(std::io::Error::other)?;
        w.write_image_data(&octets).map_err(std::io::Error::other)?;
        w.finish().map_err(std::io::Error::other)
    }

    fn melanger(&mut self, x: usize, y: usize, src: [f32; 4]) {
        let d = &mut self.px[y * self.largeur + x];
        let reste = 1.0 - src[3];
        for k in 0..4 {
            d[k] = src[k] + d[k] * reste;
        }
    }
}

fn rvba(c: Color32) -> [f32; 4] {
    c.to_array().map(|v| f32::from(v) / 255.0)
}

/// Un contexte egui et ses textures, comme le garderait la carte graphique d'une image à l'autre, et son heure.
pub struct Rendu {
    pub ctx: Context,
    textures: HashMap<TextureId, Texture>,
    /// L'heure d'egui de la dernière image : elle ne recule jamais (les fondus d'egui partiraient de travers).
    heure: f64,
    /// La souris, posée là à chaque image (aucune par défaut).
    pub souris: Option<Pos2>,
    /// Des touches, envoyées à la première image du prochain rendu seulement.
    pub touches: Vec<egui::Event>,
}

impl Rendu {
    pub fn nouveau() -> Rendu {
        let ctx = Context::default();
        super::polices(&ctx);
        Rendu {
            ctx,
            textures: HashMap::new(),
            heure: 0.0,
            souris: None,
            touches: Vec::new(),
        }
    }

    /// Fait une image de `taille` pixels (une échelle de 1) à chacun des `instants`, en secondes après une pause
    /// d'une seconde, et rend la dernière.
    pub fn rendre(&mut self, taille: [usize; 2], instants: &[f64], mut f: impl FnMut(&mut Ui)) -> Toile {
        let ecran = Rect::from_min_size(Pos2::ZERO, vec2(taille[0] as f32, taille[1] as f32));
        let base = self.heure + 1.0;
        let mut derniere = None;
        for &instant in instants {
            self.heure = base + instant;
            let mut entree = egui::RawInput {
                screen_rect: Some(ecran),
                time: Some(self.heure),
                ..Default::default()
            };
            entree.events.extend(self.souris.map(egui::Event::PointerMoved));
            entree.events.append(&mut self.touches);
            let mut sortie = self.ctx.run_ui(entree, &mut f);
            let mut delta = std::mem::take(&mut sortie.textures_delta);
            self.appliquer(&delta);
            for id in &delta.free {
                self.textures.remove(id);
            }
            // Appliquées : epaint veut qu'on le dise.
            delta.clear();
            derniere = Some(sortie);
        }
        let sortie = derniere.expect("au moins un instant");
        let ppp = sortie.pixels_per_point;
        let primitives = self.ctx.tessellate(sortie.shapes, ppp);
        let mut toile = Toile::nouvelle(taille[0], taille[1], super::pal().fond);
        for p in &primitives {
            if let epaint::Primitive::Mesh(m) = &p.primitive {
                self.peindre(&mut toile, p.clip_rect, ppp, m);
            }
        }
        toile
    }

    fn appliquer(&mut self, delta: &TexturesDelta) {
        for (id, deltas) in &delta.set {
            for d in deltas {
                let ImageData::Color(image) = &d.image;
                let lisse = d.options.magnification == TextureFilter::Linear;
                match d.pos {
                    None => {
                        self.textures.insert(
                            *id,
                            Texture {
                                taille: image.size,
                                px: image.pixels.clone(),
                                lisse,
                            },
                        );
                    }
                    Some([x0, y0]) => {
                        let t = self.textures.get_mut(id).expect("morceau d'une texture inconnue");
                        let [l, h] = image.size;
                        for y in 0..h {
                            for x in 0..l {
                                t.px[(y0 + y) * t.taille[0] + x0 + x] = image.pixels[y * l + x];
                            }
                        }
                    }
                }
            }
        }
    }

    fn peindre(&self, toile: &mut Toile, clip: Rect, ppp: f32, m: &epaint::Mesh) {
        // Les ciseaux d'egui_glow : le rectangle en pixels, arrondi, borné à l'image.
        let borne = |v: f32, max: usize| (v * ppp).round().clamp(0.0, max as f32) as usize;
        let cx = [borne(clip.min.x, toile.largeur), borne(clip.max.x, toile.largeur)];
        let cy = [borne(clip.min.y, toile.hauteur), borne(clip.max.y, toile.hauteur)];
        if cx[0] >= cx[1] || cy[0] >= cy[1] {
            return;
        }
        let texture = self.textures.get(&m.texture_id);
        for tri in m.indices.as_chunks::<3>().0 {
            let v = [
                &m.vertices[tri[0] as usize],
                &m.vertices[tri[1] as usize],
                &m.vertices[tri[2] as usize],
            ];
            triangle(toile, cx, cy, ppp, v, texture);
        }
    }
}

/// Le côté de `p` par rapport à l'arête a→b. Calculé toujours dans le même ordre des deux bouts, puis changé de
/// signe : deux triangles qui partagent une arête obtiennent exactement l'opposé, sans fente d'arrondi entre eux.
fn arete(a: Pos2, b: Pos2, p: Pos2) -> f32 {
    let cote = |a: Pos2, b: Pos2| (b.x - a.x) * (p.y - a.y) - (b.y - a.y) * (p.x - a.x);
    if (a.x, a.y) <= (b.x, b.y) {
        cote(a, b)
    } else {
        -cote(b, a)
    }
}

/// Les sommets posés sur une grille d'un 256e de pixel, comme la carte graphique les pose.
fn sur_la_grille(v: f32) -> f32 {
    (v * 256.0).round() / 256.0
}

// raison : la règle haut-gauche compare des coordonnées exactes, comme la carte graphique (sur sa grille).
#[allow(clippy::float_cmp)]
fn triangle(
    toile: &mut Toile,
    cx: [usize; 2],
    cy: [usize; 2],
    ppp: f32,
    v: [&epaint::Vertex; 3],
    tex: Option<&Texture>,
) {
    let mut v = v;
    let mut p = v.map(|s| Pos2::new(sur_la_grille(s.pos.x * ppp), sur_la_grille(s.pos.y * ppp)));
    let mut aire = arete(p[0], p[1], p[2]);
    if aire.abs() < 1e-6 {
        return;
    }
    if aire < 0.0 {
        v.swap(1, 2);
        p.swap(1, 2);
        aire = -aire;
    }
    // Règle haut-gauche (sens direct, y vers le bas) : un bord horizontal du haut ou un bord qui remonte garde les
    // pixels posés exactement dessus ; les autres les laissent au triangle voisin.
    let haut_gauche = |a: Pos2, b: Pos2| (a.y == b.y && b.x > a.x) || b.y < a.y;
    let regles = [
        haut_gauche(p[1], p[2]),
        haut_gauche(p[2], p[0]),
        haut_gauche(p[0], p[1]),
    ];
    let min_x = p.iter().map(|q| q.x).fold(f32::INFINITY, f32::min);
    let max_x = p.iter().map(|q| q.x).fold(f32::NEG_INFINITY, f32::max);
    let min_y = p.iter().map(|q| q.y).fold(f32::INFINITY, f32::min);
    let max_y = p.iter().map(|q| q.y).fold(f32::NEG_INFINITY, f32::max);
    let x0 = (min_x.floor().max(0.0) as usize).max(cx[0]);
    let x1 = (max_x.ceil().max(0.0) as usize).min(cx[1]);
    let y0 = (min_y.floor().max(0.0) as usize).max(cy[0]);
    let y1 = (max_y.ceil().max(0.0) as usize).min(cy[1]);
    let couleurs = v.map(|s| rvba(s.color));
    // Le plus souvent, les trois sommets lisent le même texel (le pixel blanc des formes pleines) : lu une fois.
    let meme_uv = v[0].uv == v[1].uv && v[1].uv == v[2].uv;
    let texel_unique = tex.map(|t| echantillon(t, v[0].uv));
    for y in y0..y1 {
        for x in x0..x1 {
            let c = Pos2::new(x as f32 + 0.5, y as f32 + 0.5);
            let w = [arete(p[1], p[2], c), arete(p[2], p[0], c), arete(p[0], p[1], c)];
            if (0..3).any(|k| w[k] < 0.0 || (w[k] == 0.0 && !regles[k])) {
                continue;
            }
            let l = w.map(|a| a / aire);
            let mut src = [0.0; 4];
            for k in 0..4 {
                src[k] = l[0] * couleurs[0][k] + l[1] * couleurs[1][k] + l[2] * couleurs[2][k];
            }
            let texel = match (tex, meme_uv) {
                (None, _) => [1.0; 4],
                (Some(_), true) => texel_unique.unwrap_or([1.0; 4]),
                (Some(t), false) => {
                    let uv = Pos2::new(
                        l[0] * v[0].uv.x + l[1] * v[1].uv.x + l[2] * v[2].uv.x,
                        l[0] * v[0].uv.y + l[1] * v[1].uv.y + l[2] * v[2].uv.y,
                    );
                    echantillon(t, uv)
                }
            };
            for k in 0..4 {
                src[k] *= texel[k];
            }
            toile.melanger(x, y, src);
        }
    }
}

/// Un texel lu comme la carte graphique : bilinéaire (ou au plus proche), bords prolongés.
fn echantillon(t: &Texture, uv: Pos2) -> [f32; 4] {
    let [l, h] = t.taille;
    let lire = |x: isize, y: isize| {
        let x = x.clamp(0, l as isize - 1) as usize;
        let y = y.clamp(0, h as isize - 1) as usize;
        rvba(t.px[y * l + x])
    };
    let fx = uv.x * l as f32 - 0.5;
    let fy = uv.y * h as f32 - 0.5;
    if !t.lisse {
        return lire((fx + 0.5).floor() as isize, (fy + 0.5).floor() as isize);
    }
    let (x0, y0) = (fx.floor(), fy.floor());
    let (ax, ay) = (fx - x0, fy - y0);
    let (x0, y0) = (x0 as isize, y0 as isize);
    let (a, b, c, d) = (lire(x0, y0), lire(x0 + 1, y0), lire(x0, y0 + 1), lire(x0 + 1, y0 + 1));
    let mut r = [0.0; 4];
    for k in 0..4 {
        let haut = a[k] + (b[k] - a[k]) * ax;
        let bas = c[k] + (d[k] - c[k]) * ax;
        r[k] = haut + (bas - haut) * ay;
    }
    r
}

/// Une image de la fenêtre, comme `Fenetre::ui` la fait, sans `Appli::avancer` (rien ne se lance).
fn image(appli: &mut Appli, ouverture: Option<&mut super::ouverture::Ouverture>, ui: &mut Ui) {
    let t = ouverture.and_then(|o| o.avancer(ui.ctx()));
    super::appliquer_theme(ui.ctx(), appli.sombre);
    super::cadre::tout(appli, ui);
    if let Some(t) = t {
        super::ouverture::dessiner(ui.ctx(), t);
    }
}

/// Une fenêtre aux résultats inventés (réseau « Salon », compte « alice », adresses de documentation).
fn appli_remplie(anglais: bool, sombre: bool) -> Appli {
    let mut a = Appli::pour_captures();
    a.sombre = sombre;
    let t = |fr: &'static str, en: &'static str| if anglais { en } else { fr };
    let bilan = serde_json::json!({
        "systeme": "Linux · Arch",
        "score": 82,
        "fiable": true,
        "constats": [
            {"categorie": t("Pare-feu", "Firewall"), "message": t("Pare-feu actif, entrées refusées.", "Firewall on, incoming refused."), "verifie": true, "regle": "LNX-PFE-001", "etat": "sain"},
            {"categorie": "SSH", "probleme": "Eleve", "message": t("Connexion root permise.", "Root login allowed."), "correctif": {"action": t("Refuser root.", "Refuse root."), "commandes": ["x"], "automatique": false}, "verifie": true, "regle": "LNX-SSH-002", "etat": "probleme"},
            {"categorie": "SSH", "probleme": "Moyen", "message": t("Mot de passe permis.", "Password login allowed."), "verifie": true, "regle": "LNX-SSH-003", "etat": "probleme"},
            {"categorie": t("Mises à jour", "Updates"), "probleme": "Critique", "message": t("12 paquets en retard.", "12 packages behind."), "verifie": true, "etat": "probleme"},
            {"categorie": t("Comptes", "Accounts"), "probleme": "Info", "message": t("Compte alice sans expiration du mot de passe.", "Account alice has no password expiry."), "verifie": true, "etat": "probleme"},
            {"categorie": t("Chiffrement", "Encryption"), "probleme": "Info", "message": t("Illisible sans droits.", "Unreadable without rights."), "verifie": false, "etat": "non-verifie", "raison": "droits"},
            {"categorie": t("Partage", "Sharing"), "message": t("Aucun partage.", "No share."), "verifie": true, "etat": "sans-objet", "absence": "logiciel"},
            {"categorie": t("Démarrage", "Startup"), "message": t("Démarrage sécurisé actif.", "Secure Boot on."), "verifie": true, "etat": "sain"},
            {"categorie": t("Navigateur", "Browser"), "message": t("Aucune extension inconnue.", "No unknown extension."), "verifie": true, "etat": "sain"}
        ]
    });
    let protection = serde_json::json!({"interrupteurs": [
        {"interrupteur": "temps-reel", "nom": t("Protection en temps réel", "Real-time protection"), "etat": t("activé", "on")},
        {"interrupteur": "surveillance", "nom": t("Surveillance du réseau", "Network watch"), "etat": t("activé", "on")},
        {"interrupteur": "blocage", "nom": t("Blocage des menaces", "Threat blocking"), "etat": t("activé", "on")},
        {"interrupteur": "entretien", "nom": t("Entretien du mois", "Monthly upkeep"), "etat": t("désactivé", "off")}
    ]});
    let journal = serde_json::json!({
        "etat": "intact", "raison": null, "illisibles": 0,
        "evenements": [
            {"v": 1, "id": "a1", "quand": "2026-11-09T13:00:00Z", "source": "vanguard", "quoi": {"sorte": "version", "vers": "0.90.0"}, "precedent": ""},
            {"v": 1, "id": "a2", "quand": "2026-11-09T13:10:00Z", "source": "surveillance", "gravite": "Eleve", "cle": "botnet|x",
             "quoi": {"sorte": "alerte", "famille": "botnet", "titre": t("Connexion suspecte", "Suspicious connection"), "texte": t("Un programme parle à 203.0.113.7.", "A program talks to 203.0.113.7.")}, "precedent": "x"},
            {"v": 1, "id": "a3", "quand": "2026-11-09T13:11:00Z", "source": "blocage", "cause": "a2",
             "quoi": {"sorte": "action", "quoi": t("Bloquer 203.0.113.7", "Block 203.0.113.7"), "reussi": true, "automatique": true}},
            {"v": 1, "id": "a5", "quand": "2026-11-09T13:20:00Z", "source": "outil",
             "quoi": {"sorte": "examen", "outil": "PRO-LEN-001", "verdict": "probleme", "problemes": 2, "non_verifies": 1}}
        ]
    });
    let scan = serde_json::json!({
        "reseau": "192.168.1.0/24", "nom_reseau": "Salon", "duree_s": 9.5, "score_global": 85, "note": "bon",
        "absents": [{"ip": "192.168.1.40", "titre": t("Tablette", "Tablet"), "dernier_vu": "2026-11-01"}],
        "hotes": [
            {"ip": "192.168.1.1", "nom": "box", "mac": "f8:79:0a:00:00:01", "fabricant": "Arris", "premier_vu": "2026-10-01", "role": "passerelle", "nouvelle": false, "score": 90,
             "ports": [{"port": 80, "service": "HTTP", "niveau": "Moyen", "conseil": "x", "nouveau": false}],
             "alertes": [["Moyen", t("Page d'administration sans chiffrement.", "Admin page without encryption.")]]},
            {"ip": "192.168.1.20", "nom": "portable-alice", "mac": "3c:22:fb:00:00:03", "fabricant": "Apple", "premier_vu": "2026-10-02", "nouvelle": false, "score": 100, "ports": [], "alertes": []},
            {"ip": "192.168.1.30", "mac": "00:17:88:00:00:02", "fabricant": "Philips", "surnom": t("Lampe", "Lamp"), "nouvelle": true, "score": 100,
             "ports": [{"port": 1900, "service": "SSDP", "niveau": "Info", "nouveau": true, "udp": true}], "alertes": []}
        ],
        "upnp": {"Actif": {"description": {}, "adresse_externe": "203.0.113.5", "connexion": "Connected",
                 "redirections": [{"protocole": "TCP", "port_public": 3074, "appareil": "192.168.1.50", "port_appareil": 3074, "description": "Console", "bail": 0, "hote_distant": "", "active": true}],
                 "lues": true, "tronquees": false}},
        "empoisonnement": {"Teste": []}
    });
    let connexions = serde_json::json!({
        "outil": "RES-CNX-001", "schema": 1, "debut": "2026-11-09T14:00:00Z", "duree_ms": 2143,
        "couverture": {"verifies": 14, "non_verifies": []},
        "constats": [
            {"categorie": t("Connexions", "Connections"), "etat": "sain", "message": t("firefox → 198.51.100.20:443 (chiffrée)", "firefox → 198.51.100.20:443 (encrypted)")},
            {"categorie": t("Connexions", "Connections"), "etat": "sain", "message": t("steam → 198.51.100.31:27017", "steam → 198.51.100.31:27017")},
            {"categorie": t("Connexions", "Connections"), "etat": "probleme", "niveau": "Moyen", "message": t("inconnu → 203.0.113.7:6667 (IRC, souvent des botnets)", "unknown → 203.0.113.7:6667 (IRC, often botnets)")}
        ]
    });
    let demarrage = serde_json::json!({"outil": "PRO-DEM-001", "constats": [
        {"categorie": t("Démarrage", "Startup"), "etat": "sain", "message": t("Lecteur — se lance · /usr/bin/lecteur", "Lecteur — starts · /usr/bin/lecteur"),
         "objet": "demarrage:Lecteur",
         "geste": {"sorte": "retirer", "empreinte": "0123456789abcdef0123456789abcdef", "nom": "Lecteur", "commande": "/usr/bin/lecteur"}},
        {"categorie": t("Démarrage", "Startup"), "etat": "sain", "message": t("Synchro — se lance · /opt/synchro/synchro --fond", "Synchro — starts · /opt/synchro/synchro --background"),
         "objet": "demarrage:Synchro",
         "geste": {"sorte": "retirer", "empreinte": "fedcba9876543210fedcba9876543210", "nom": "Synchro", "commande": "/opt/synchro/synchro"}},
        {"categorie": t("Démarrage", "Startup"), "etat": "sain", "message": t("Murdefeu — pare-feu : le retirer baisserait la protection · /usr/bin/murdefeu", "Murdefeu — firewall: removing it would lower protection · /usr/bin/murdefeu"),
         "objet": "demarrage:Murdefeu"}
    ]});
    for (c, json) in [
        (Commande::Bilan, bilan),
        (Commande::Protection, protection),
        (Commande::Evenements, journal),
        (Commande::Appareils, scan),
        (Commande::ConnexionsSortantes, connexions),
        (Commande::Demarrage, demarrage),
    ] {
        a.poser(c, json.to_string().as_bytes());
    }
    a
}

/// Une fenêtre sans rien de lancé, ou dont les lectures n'ont rien trouvé (aucune alerte, aucun appareil) : pour les
/// écrans vides.
fn appli_vide(rien: bool, sombre: bool) -> Appli {
    let mut a = Appli::pour_captures();
    a.sombre = sombre;
    if rien {
        let journal = serde_json::json!({
            "etat": "intact", "raison": null, "illisibles": 0,
            "evenements": [
                {"v": 1, "id": "a1", "quand": "2026-11-09T13:00:00Z", "source": "vanguard", "quoi": {"sorte": "version", "vers": "0.90.0"}, "precedent": ""}
            ]
        });
        let scan = serde_json::json!({
            "reseau": "192.168.1.0/24", "nom_reseau": "Salon", "duree_s": 9.5, "score_global": 100, "note": "bon",
            "absents": [], "hotes": [], "upnp": "Absent", "empoisonnement": {"Teste": []}
        });
        a.poser(Commande::Evenements, journal.to_string().as_bytes());
        a.poser(Commande::Appareils, scan.to_string().as_bytes());
    }
    a
}

/// Ce que montre une capture : la fenêtre remplie, rien de lancé, ou des lectures qui n'ont rien trouvé.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Donnees {
    Remplies,
    Aucune,
    Rien,
}

/// Les écrans montrés, avec le nom de leur fichier ; les écrans vides ensuite (« vide-… », « rien-… »).
fn ecrans() -> Vec<(String, Ecran, Donnees)> {
    let mut v = vec![
        ("accueil".to_string(), Ecran::Accueil),
        ("bilan".to_string(), Ecran::Bilan),
        ("alertes".to_string(), Ecran::Alertes),
        ("appareils".to_string(), Ecran::Appareils),
    ];
    for r in Rubrique::TOUTES {
        if !matches!(r, Rubrique::Accueil | Rubrique::Guide) {
            v.push((
                format!("rubrique-{}", nom_de_fichier(r.nom_court())),
                Ecran::Rubrique(r),
            ));
        }
    }
    v.push((
        "commande-connexions-sortantes".to_string(),
        Ecran::Commande(Commande::ConnexionsSortantes),
    ));
    v.push(("commande-demarrage".to_string(), Ecran::Commande(Commande::Demarrage)));
    v.push(("guide".to_string(), Ecran::Guide));
    // Les coulisses, ouvertes par-dessus l'accueil (voir `captures`).
    v.push(("coulisses".to_string(), Ecran::Accueil));
    let mut v: Vec<(String, Ecran, Donnees)> = v.into_iter().map(|(n, e)| (n, e, Donnees::Remplies)).collect();
    for (nom, e) in [
        ("accueil", Ecran::Accueil),
        ("bilan", Ecran::Bilan),
        ("alertes", Ecran::Alertes),
        ("appareils", Ecran::Appareils),
        (
            "commande-connexions-sortantes",
            Ecran::Commande(Commande::ConnexionsSortantes),
        ),
        ("coulisses", Ecran::Accueil),
    ] {
        v.push((format!("vide-{nom}"), e, Donnees::Aucune));
    }
    for (nom, e) in [("alertes", Ecran::Alertes), ("appareils", Ecran::Appareils)] {
        v.push((format!("rien-{nom}"), e, Donnees::Rien));
    }
    v
}

/// « Réseau et\nInternet » → « reseau-et-internet ».
fn nom_de_fichier(t: &str) -> String {
    let mut s = String::new();
    for c in t.to_lowercase().chars() {
        let c = match c {
            'à' | 'â' => 'a',
            'é' | 'è' | 'ê' => 'e',
            'î' => 'i',
            'ô' => 'o',
            'ù' | 'û' => 'u',
            'ç' => 'c',
            c => c,
        };
        if c.is_ascii_alphanumeric() {
            s.push(c);
        } else if !s.ends_with('-') {
            s.push('-');
        }
    }
    s.trim_matches('-').to_string()
}

fn dossier_des_captures() -> PathBuf {
    std::env::var_os("VANGUARD_CAPTURES").map_or_else(
        || {
            let maison = std::env::var_os("HOME").expect("HOME");
            Path::new(&maison).join(".cache/vanguard-dev/captures-fenetre")
        },
        PathBuf::from,
    )
}

const TAILLES: [[usize; 2]; 2] = [[1280, 800], [1920, 1080]];

/// Toutes les captures : chaque écran, en français et en anglais, sombre et clair, aux deux tailles ; puis les images
/// clés de l'ouverture. Elles changent la langue et le thème de tout le programme d'essai : seules, jamais en même
/// temps que les autres essais (`outils/captures-fenetre.sh`).
#[test]
#[ignore = "à la main : outils/captures-fenetre.sh refait les captures PNG"]
fn captures() {
    let dossier = dossier_des_captures();
    std::fs::create_dir_all(dossier.join("ouverture")).unwrap();
    let mut faites = 0;
    for taille in TAILLES {
        let mut rendu = Rendu::nouveau();
        for anglais in [false, true] {
            crate::langue::choisir(Some(anglais));
            for sombre in [true, false] {
                super::appliquer_theme(&rendu.ctx, sombre);
                for (nom, ecran, donnees) in ecrans() {
                    let mut appli = match donnees {
                        Donnees::Remplies => appli_remplie(anglais, sombre),
                        Donnees::Aucune => appli_vide(false, sombre),
                        Donnees::Rien => appli_vide(true, sombre),
                    };
                    appli.aller(ecran);
                    // Une seule toile ici : les coulisses en panneau, comme sur un système sans seconde fenêtre.
                    rendu.ctx.set_embed_viewports(true);
                    let coulisses = nom.ends_with("coulisses");
                    if coulisses {
                        super::coulisses::basculer(&rendu.ctx);
                    }
                    // La première image mesure, la deuxième pose les largeurs ; les fondus ont fini à la dernière.
                    let toile = rendu.rendre(taille, &[0.0, 0.5, 2.0], |ui| image(&mut appli, None, ui));
                    let fichier = format!(
                        "{nom}-{}-{}-{}x{}.png",
                        if anglais { "en" } else { "fr" },
                        if sombre { "sombre" } else { "clair" },
                        taille[0],
                        taille[1]
                    );
                    if coulisses {
                        super::coulisses::basculer(&rendu.ctx);
                    }
                    toile.ecrire_png(&dossier.join(fichier)).unwrap();
                    faites += 1;
                }
            }
        }
    }
    // L'ouverture, en français, aux deux tailles et dans les deux thèmes : l'heure d'egui part de 0 à la première
    // image, puis chaque image clé à son instant.
    crate::langue::choisir(Some(false));
    for taille in TAILLES {
        for sombre in [true, false] {
            let mut rendu = Rendu::nouveau();
            super::appliquer_theme(&rendu.ctx, sombre);
            for t in [0.0, 0.15, 0.3, 0.45, 0.6, 0.75, 0.85, 0.95] {
                let mut appli = appli_remplie(false, sombre);
                let mut o = super::ouverture::Ouverture::nouvelle();
                // Deux images à l'instant 0 (les mesures du menu), puis l'image clé.
                let toile = rendu.rendre(taille, &[0.0, 0.0, t], |ui| image(&mut appli, Some(&mut o), ui));
                let fichier = format!(
                    "ouverture/{:03}ms-{}-{}x{}.png",
                    (t * 1000.0).round() as u32,
                    if sombre { "sombre" } else { "clair" },
                    taille[0],
                    taille[1]
                );
                toile.ecrire_png(&dossier.join(fichier)).unwrap();
                faites += 1;
            }
        }
    }
    faites += mouvement(&dossier);
    faites += console(&dossier);
    println!("CAPTURES {faites} dans {}", dossier.display());
}

/// Les images clés du mouvement (mouvement/), en français, sombre, en 1280×800 : l'arrivée d'un écran.
fn mouvement(dossier: &Path) -> usize {
    let dossier = dossier.join("mouvement");
    std::fs::create_dir_all(&dossier).unwrap();
    crate::langue::choisir(Some(false));
    let taille = TAILLES[0];
    let mut faites = 0;
    for t in [0.0, 0.05, 0.1, 0.15] {
        let mut rendu = Rendu::nouveau();
        super::appliquer_theme(&rendu.ctx, true);
        let mut appli = appli_remplie(false, true);
        rendu.rendre(taille, &[0.0, 0.5, 2.0], |ui| image(&mut appli, None, ui));
        appli.aller(Ecran::Bilan);
        let instants: &[f64] = if t > 0.0 { &[0.0, t] } else { &[0.0] };
        let toile = rendu.rendre(taille, instants, |ui| image(&mut appli, None, ui));
        let fichier = format!("arrivee-{:03}ms.png", (t * 1000.0).round() as u32);
        toile.ecrire_png(&dossier.join(fichier)).unwrap();
        faites += 1;
    }
    // Les chiffres du Bilan qui montent, la première fois que ce bilan est montré.
    for t in [0.0, 0.15, 0.3, 0.6] {
        let mut rendu = Rendu::nouveau();
        super::appliquer_theme(&rendu.ctx, true);
        let mut appli = appli_remplie(false, true);
        appli.aller(Ecran::Bilan);
        let instants: &[f64] = if t > 0.0 { &[0.0, t] } else { &[0.0] };
        let toile = rendu.rendre(taille, instants, |ui| image(&mut appli, None, ui));
        let fichier = format!("montee-{:03}ms.png", (t * 1000.0).round() as u32);
        toile.ecrire_png(&dossier.join(fichier)).unwrap();
        faites += 1;
    }
    // Une carte de commande sous la souris : son fond s'éclaire, rien ne bouge.
    let mut rendu = Rendu::nouveau();
    super::appliquer_theme(&rendu.ctx, true);
    let mut appli = appli_remplie(false, true);
    appli.aller(Ecran::Rubrique(Rubrique::Ordinateur));
    rendu.souris = Some(egui::pos2(700.0, 480.0));
    let toile = rendu.rendre(taille, &[0.0, 0.5, 2.0], |ui| image(&mut appli, None, ui));
    toile.ecrire_png(&dossier.join("survol-ligne.png")).unwrap();
    let mut faites = faites + 1;
    // Le contour du focus au clavier, en sombre et en clair : Tab depuis le début (le rail, un onglet, puis le bouton
    // plein « Voir les alertes ») ; Maj+Tab, lui, est essayé dans clavier.rs.
    for (sombre, fois) in [(true, 1), (true, 12), (true, 18), (false, 1), (false, 18)] {
        let mut rendu = Rendu::nouveau();
        super::appliquer_theme(&rendu.ctx, sombre);
        let mut appli = appli_remplie(false, sombre);
        appli.aller(Ecran::Rubrique(Rubrique::Ordinateur));
        rendu.rendre(taille, &[0.0, 0.5], |ui| image(&mut appli, None, ui));
        for _ in 0..fois {
            rendu.touches.push(egui::Event::Key {
                key: egui::Key::Tab,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            });
            rendu.rendre(taille, &[0.0], |ui| image(&mut appli, None, ui));
        }
        let toile = rendu.rendre(taille, &[0.0, 0.5], |ui| image(&mut appli, None, ui));
        let nom = format!("focus-{}-tab{fois}.png", if sombre { "sombre" } else { "clair" });
        toile.ecrire_png(&dossier.join(nom)).unwrap();
        faites += 1;
    }
    // Des infobulles : la souris posée une fois, puis immobile au-delà du délai (egui le compte depuis le dernier
    // mouvement). Une rubrique du rail en sombre, le point de veille en clair, la touche Tab en sombre.
    for (nom, sombre, ici) in [
        ("bulle-rail", true, egui::pos2(44.0, 255.0)),
        ("bulle-veille", false, egui::pos2(990.0, 32.0)),
        ("bulle-tab", true, egui::pos2(1150.0, 254.0)),
    ] {
        let mut rendu = Rendu::nouveau();
        super::appliquer_theme(&rendu.ctx, sombre);
        let mut appli = appli_remplie(false, sombre);
        appli.aller(Ecran::Rubrique(Rubrique::Ordinateur));
        rendu.rendre(taille, &[0.0, 0.5], |ui| image(&mut appli, None, ui));
        rendu.touches.push(egui::Event::PointerMoved(ici));
        let toile = rendu.rendre(taille, &[0.0, 0.2, 0.4, 0.6], |ui| image(&mut appli, None, ui));
        toile.ecrire_png(&dossier.join(format!("{nom}.png"))).unwrap();
        faites += 1;
    }
    // L'en-tête de la console pendant qu'une commande tourne (aucune vraie commande ne tourne dans une capture :
    // l'en-tête seul, à mi-pouls).
    let mut rendu = Rendu::nouveau();
    super::appliquer_theme(&rendu.ctx, true);
    let toile = rendu.rendre([640, 36], &[0.0, 0.5], |ui| {
        let tete = ui.max_rect();
        let peintre = ui.painter().clone();
        let en_cours = Some((Commande::Bilan, std::time::Duration::from_secs(3)));
        super::cadre::tache_en_tete(ui, &peintre, tete, en_cours, 2);
    });
    toile.ecrire_png(&dossier.join("commande-en-cours.png")).unwrap();
    faites + 1
}

/// La console (console/), en français, sombre et clair, en 1280×800 : vide, dépliée avec ses blocs, une commande en
/// cours avec son étape et une file, un filtre, une recherche, une faute dans la saisie et sa suggestion. Le bloc « en
/// cours » est posé dans le modèle (aucune commande ne tourne dans une capture) : l'en-tête reste au repos.
fn console(dossier: &Path) -> usize {
    use crate::console::Filtre;
    let dossier = dossier.join("console");
    std::fs::create_dir_all(&dossier).unwrap();
    crate::langue::choisir(Some(false));
    let taille = TAILLES[0];
    let mut faites = 0;
    for sombre in [true, false] {
        let theme = if sombre { "sombre" } else { "clair" };
        let cas: [(&str, usize, Filtre, Option<&str>); 6] = [
            ("vide", 0, Filtre::Tout, None),
            ("blocs", super::console::LIGNES_DEPLIEE, Filtre::Tout, None),
            ("en-cours-et-file", super::console::LIGNES_DEPLIEE, Filtre::Tout, None),
            (
                "filtre-problemes",
                super::console::LIGNES_DEPLIEE,
                Filtre::Problemes,
                None,
            ),
            ("filtre-reseau", 0, Filtre::Reseau, None),
            ("recherche-ssh", 0, Filtre::Tout, Some("ssh")),
        ];
        for (nom, lignes, filtre, cherche) in cas {
            let mut rendu = Rendu::nouveau();
            super::appliquer_theme(&rendu.ctx, sombre);
            let mut appli = if nom == "vide" {
                appli_vide(false, sombre)
            } else {
                appli_remplie(false, sombre)
            };
            if nom == "en-cours-et-file" {
                appli.console.commencer(Commande::Diagnostic.into());
                appli.console.recevoir("Lecture des disques…");
                appli.console.recevoir("@etape 4/9 Comptes");
                appli.console.attendre(Commande::Lenteur.into());
                appli.console.attendre(Commande::MisesAJour.into());
            }
            super::console::regler(&rendu.ctx, lignes, filtre, cherche);
            let toile = rendu.rendre(taille, &[0.0, 0.5, 2.0], |ui| image(&mut appli, None, ui));
            toile.ecrire_png(&dossier.join(format!("{nom}-{theme}.png"))).unwrap();
            faites += 1;
        }
        // Une faute dans la saisie : un clic dans le champ, « bilna » tapé, la suggestion sous le champ.
        let mut rendu = Rendu::nouveau();
        super::appliquer_theme(&rendu.ctx, sombre);
        let mut appli = appli_remplie(false, sombre);
        rendu.rendre(taille, &[0.0, 0.5], |ui| image(&mut appli, None, ui));
        let champ = egui::pos2(400.0, 254.0);
        for e in [
            egui::Event::PointerMoved(champ),
            egui::Event::PointerButton {
                pos: champ,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::NONE,
            },
            egui::Event::PointerButton {
                pos: champ,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            },
            egui::Event::Text("bilna".into()),
        ] {
            rendu.touches.push(e);
            rendu.rendre(taille, &[0.0], |ui| image(&mut appli, None, ui));
        }
        assert_eq!(appli.saisie, "bilna", "le clic n'a pas mis le curseur dans la saisie");
        let toile = rendu.rendre(taille, &[0.0, 0.5], |ui| image(&mut appli, None, ui));
        toile
            .ecrire_png(&dossier.join(format!("suggestion-{theme}.png")))
            .unwrap();
        faites += 1;
    }
    faites
}

/// Le rendu logiciel peint pour de vrai : un fond, un rectangle plein, un texte (la texture des polices), une forme
/// à moitié transparente ; et deux triangles qui partagent un bord ne le peignent qu'une fois.
#[test]
fn le_rendu_peint_pour_de_vrai() {
    let mut rendu = Rendu::nouveau();
    let toile = rendu.rendre([200, 100], &[0.0, 0.1], |ui| {
        let p = ui.painter();
        p.rect_filled(
            Rect::from_min_size(Pos2::new(10.0, 10.0), vec2(40.0, 40.0)),
            0,
            Color32::RED,
        );
        p.rect_filled(
            Rect::from_min_size(Pos2::new(60.0, 10.0), vec2(40.0, 40.0)),
            0,
            Color32::from_rgba_premultiplied(0, 0, 128, 128),
        );
        p.text(
            Pos2::new(110.0, 10.0),
            egui::Align2::LEFT_TOP,
            "Vanguard",
            super::police(24.0),
            Color32::WHITE,
        );
    });
    assert_eq!(toile.pixel(30, 30), [255, 0, 0, 255]);
    // Bleu à moitié sur le fond noir de la palette sombre.
    let b = toile.pixel(80, 30);
    assert!(b[0] == 0 && b[1] == 0 && (127..=129).contains(&b[2]), "{b:?}");
    assert_eq!(toile.pixel(5, 5), [0, 0, 0, 255]);
    // Le texte allume des pixels dans sa zone, et pas tous : des lettres, pas un pavé.
    let mut allumes = 0;
    let mut total = 0;
    for y in 10..40 {
        for x in 110..200 {
            total += 1;
            if toile.pixel(x, y)[0] > 128 {
                allumes += 1;
            }
        }
    }
    assert!(allumes > total / 20 && allumes < total / 2, "{allumes} sur {total}");

    // Deux triangles à moitié transparents qui forment un carré : la diagonale n'est pas plus sombre.
    let mut toile = Toile::nouvelle(8, 8, Color32::BLACK);
    let v = |x: f32, y: f32| epaint::Vertex {
        pos: Pos2::new(x, y),
        uv: Pos2::ZERO,
        color: Color32::from_rgba_premultiplied(100, 100, 100, 128),
    };
    let (a, b, c, d) = (v(0.0, 0.0), v(8.0, 0.0), v(8.0, 8.0), v(0.0, 8.0));
    triangle(&mut toile, [0, 8], [0, 8], 1.0, [&a, &b, &c], None);
    triangle(&mut toile, [0, 8], [0, 8], 1.0, [&a, &c, &d], None);
    let premier = toile.pixel(0, 0);
    for y in 0..8 {
        for x in 0..8 {
            assert_eq!(toile.pixel(x, y), premier, "({x}, {y})");
        }
    }
}

#[test]
fn noms_de_fichier() {
    assert_eq!(nom_de_fichier("Réseau et\nInternet"), "reseau-et-internet");
    assert_eq!(
        nom_de_fichier("Virus et\nlogiciels\nespions"),
        "virus-et-logiciels-espions"
    );
    let noms: Vec<String> = ecrans().into_iter().map(|(n, _, _)| n).collect();
    let mut uniques = noms.clone();
    uniques.sort();
    uniques.dedup();
    assert_eq!(noms.len(), uniques.len(), "{noms:?}");
}

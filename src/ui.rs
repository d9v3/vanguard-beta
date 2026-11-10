//! Couleurs et petits éléments d'affichage partagés.

// Sous Linux seulement : les parties Windows ne sont pas encore relues ; le lint y viendra avec elles.
#![cfg_attr(target_os = "linux", warn(clippy::arithmetic_side_effects, clippy::as_conversions))]

pub use crate::langue::Reponse;
use crate::risk::Niveau;
pub use crate::{tr, tre, trf, trp};

pub const RESET: &str = "\x1b[0m";
pub const GRAS: &str = "\x1b[1m";
/// Texte secondaire : un gris clair, lisible sur un fond noir (le « gris atténué » du terminal l'était mal).
pub const GRIS: &str = "\x1b[38;5;250m";
pub const VERT: &str = "\x1b[1;92m";
/// Titres de section et touches du menu.
pub const ACCENT: &str = "\x1b[1;96m";
/// Touches du menu : blanc vif.
pub const TOUCHE: &str = "\x1b[1;97m";
/// Précisions à côté d'un texte : un cran sous le gris clair, pour qu'on les distingue du texte principal.
pub const DISCRET: &str = "\x1b[38;5;245m";

/// Largeur des titres et des cadres (tient dans un terminal de 80 colonnes).
pub const LARGEUR: usize = 76;

/// Les deux emojis des messages : « 💡 » devant un conseil à suivre soi-même, « 🔧 » devant une correction que Vanguard
/// sait appliquer. Partout ailleurs ils prennent deux colonnes ; l'ancienne console de Windows (cmd.exe et PowerShell
/// hors du Terminal Windows, l'habitude sous Windows 10) n'en dessine qu'une case : les précisions se décalent et les
/// menus se cassent. Là, deux signes d'une colonne, que toute police de console dessine, les remplacent.
/// VANGUARD_EMOJI=0 les retire partout (un terminal qui les dessine mal), VANGUARD_EMOJI=1 les garde partout.
pub fn ampoule() -> &'static str {
    if emojis() { "💡" } else { "→" }
}

pub fn cle_a_molette() -> &'static str {
    if emojis() { "🔧" } else { "+" }
}

fn emojis() -> bool {
    static EMOJIS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *EMOJIS.get_or_init(|| {
        // VANGUARD_EMOJI, sinon le menu Paramètres (parametres.json).
        emojis_voulus(crate::parametres::emojis().as_deref(), ancienne_console_windows())
    })
}

/// Le choix d'après VANGUARD_EMOJI, sinon d'après la console.
fn emojis_voulus(variable: Option<&str>, ancienne_console: bool) -> bool {
    match variable.map(|v| v.trim().to_lowercase()).as_deref() {
        Some("0" | "non" | "no" | "off") => false,
        Some("1" | "oui" | "yes" | "on") => true,
        _ => !ancienne_console,
    }
}

/// La console d'avant le Terminal Windows (conhost). Rien ne l'annonce ; mais le Terminal Windows pose WT_SESSION,
/// VS Code TERM_PROGRAM, ConEmu et Cmder ConEmuANSI : sous Windows, sans aucune de ces variables, c'est elle.
fn ancienne_console_windows() -> bool {
    cfg!(windows)
        && ["WT_SESSION", "TERM_PROGRAM", "ConEmuANSI"]
            .iter()
            .all(|v| std::env::var_os(v).is_none())
}

pub fn couleur(niveau: Niveau) -> &'static str {
    match niveau {
        Niveau::Info => "\x1b[96m",
        Niveau::Moyen => "\x1b[93m",
        Niveau::Eleve => "\x1b[38;5;214m",
        Niveau::Critique => "\x1b[1;91m",
    }
}

pub fn couleur_note(n: &str) -> &'static str {
    match n {
        "A" | "B" => VERT,
        "C" => "\x1b[1;93m",
        _ => "\x1b[1;91m",
    }
}

/// Colonnes qu'un caractère prend dans le terminal : deux pour un emoji (💡) ou une lettre pleine largeur (ａ, 漢),
/// aucune pour ce qui se pose sur le caractère d'avant (accent combiné, variante d'emoji, liaison). Les plages sont
/// celles que les terminaux affichent sur deux colonnes ; les symboles comme ⚠ ✔ ✖, en une colonne par défaut,
/// restent à un.
pub fn largeur_car(c: char) -> usize {
    match u32::from(c) {
        0x0300..=0x036F | 0x200B..=0x200D | 0x20D0..=0x20FF | 0xFE00..=0xFE0F => 0,
        0x1100..=0x115F
        | 0x231A..=0x231B
        | 0x23E9..=0x23EC
        | 0x23F0
        | 0x23F3
        | 0x25FD..=0x25FE
        | 0x2614..=0x2615
        | 0x2648..=0x2653
        | 0x267F
        | 0x2693
        | 0x26A1
        | 0x26AA..=0x26AB
        | 0x26BD..=0x26BE
        | 0x26C4..=0x26C5
        | 0x26CE
        | 0x26D4
        | 0x26EA
        | 0x26F2..=0x26F3
        | 0x26F5
        | 0x26FA
        | 0x26FD
        | 0x2705
        | 0x270A..=0x270B
        | 0x2728
        | 0x274C
        | 0x274E
        | 0x2753..=0x2755
        | 0x2757
        | 0x2795..=0x2797
        | 0x27B0
        | 0x27BF
        | 0x2B1B..=0x2B1C
        | 0x2B50
        | 0x2B55
        | 0x2E80..=0x303E
        | 0x3041..=0xA4CF
        | 0xAC00..=0xD7A3
        | 0xF900..=0xFAFF
        | 0xFE30..=0xFE4F
        | 0xFF00..=0xFF60
        | 0xFFE0..=0xFFE6
        | 0x1F004
        | 0x1F0CF
        | 0x1F18E
        | 0x1F191..=0x1F19A
        | 0x1F200..=0x1F2FF
        | 0x1F300..=0x1F64F
        | 0x1F680..=0x1F6FF
        | 0x1F7E0..=0x1F7EB
        | 0x1F900..=0x1F9FF
        | 0x1FA70..=0x1FAFF
        | 0x20000..=0x3FFFD => 2,
        _ => 1,
    }
}

/// Un caractère qu'un texte venu de l'extérieur ne doit jamais faire passer au terminal : les contrôles C0 (dont ESC,
/// qui ouvre les séquences ANSI et OSC, le retour chariot et le saut de ligne), DEL et les contrôles C1 (U+009B ouvre
/// une séquence comme ESC [), et la mise en forme invisible : sens d'écriture bidi (U+202A à U+202E, U+2066 à U+2069,
/// U+061C), espace, liaisons et marques de largeur nulle (U+200B à U+200F, U+2060 à U+2064), marque d'ordre des
/// octets (U+FEFF). Et ce qui rend un nom trompeur sans rien piloter : séparateurs de ligne et de paragraphe (U+2028,
/// U+2029), trait d'union conditionnel (U+00AD), séparateur mongol (U+180E), étiquettes invisibles (U+E0000 à
/// U+E007F), et les blancs qui ne sont pas des espaces mais en ont l'air ou ne se voient pas : remplissages coréens
/// (U+115F, U+1160, U+3164, U+FFA0), Braille vide (U+2800), joint de graphèmes (U+034F). Le sélecteur de variante des
/// émojis (U+FE0F) reste. Les espaces trompeuses n'en sont pas (`espace_trompeur`) : `piege` sert aussi à juger (nom de
/// fichier ou d'expéditeur piégé, `protection::telechargement`, `courriel_suspect`), et une insécable dans un nom
/// normal n'est pas une ruse ; seul l'affichage les change (`rendu`). La fenêtre (fenetre/src/nettoyage.rs) garde la
/// même liste.
pub(crate) fn piege(c: char) -> bool {
    matches!(
        u32::from(c),
        0x00..=0x1F
            | 0x7F..=0x9F
            | 0xAD
            | 0x034F
            | 0x061C
            | 0x115F..=0x1160
            | 0x180E
            | 0x200B..=0x200F
            | 0x2028..=0x2029
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x2069
            | 0x2800
            | 0x3164
            | 0xFEFF
            | 0xFFA0
            | 0xE0000..=0xE007F
    )
}

/// Les espaces d'une autre largeur que l'espace ordinaire : insécable (U+00A0), ogham (U+1680), de U+2000 à U+200A
/// (cadratin, fine, ultrafine…), fine insécable (U+202F), moyenne mathématique (U+205F), idéographique (U+3000).
/// L'ultrafine ne se voit presque pas (« Sa[U+200A]lon » lu « Salon »), l'idéographique prend deux colonnes et décale un
/// alignement, l'ogham se dessine parfois comme un trait. Ils viennent aussi de sorties normales (nombres écrits à la
/// française, « 12 % ») : montrés comme une espace ordinaire, un par un, ils gardent le texte lisible et ne trompent
/// plus que comme une espace ordinaire le ferait.
pub(crate) fn espace_trompeur(c: char) -> bool {
    matches!(u32::from(c), 0xA0 | 0x1680 | 0x2000..=0x200A | 0x202F | 0x205F | 0x3000)
}

/// Un texte venu de l'extérieur (nom d'un réseau ou d'un appareil, réponse du réseau, nom de fichier, sortie d'un
/// autre programme), prêt à montrer. Sans cela, un nom piégé pilote le terminal : une séquence OSC 52 écrit dans le
/// presse-papier, ESC [2K et un retour chariot effacent une alerte de Vanguard et la réécrivent, un caractère bidi
/// retourne la fin d'un nom. Chacun de ces caractères devient « � », pour que la manipulation se voie, sauf les espaces
/// trompeuses, qui deviennent une espace ordinaire ; le reste ne change pas (accents, emojis, autres écritures).
pub fn affichable(texte: &str) -> String {
    texte.chars().map(rendu).collect()
}

/// Un chemin de fichier ou de dossier prêt à montrer : un nom de fichier vient de n'importe qui (téléchargement, clé
/// USB, programme). Le chemin lui-même reste tel quel pour agir (analyser, isoler, effacer) : seul ce qui est montré
/// passe par ici.
pub fn chemin_affichable(chemin: &std::path::Path) -> String {
    affichable(&chemin.to_string_lossy())
}

/// Une commande prête à montrer avant d'être lancée. Elle reprend souvent un nom venu de l'extérieur (fichier à
/// isoler, cache à effacer, tâche planifiée, imprimante) : piégé, il effacerait ou retournerait une partie de la
/// ligne, et ce qui est montré ne serait plus ce qui est lancé. Les tabulations restent ; un saut de ligne devient
/// « ⏎ » sur la même ligne, pour qu'un nom de fichier qui en contient n'ajoute pas sous la commande une fausse ligne
/// (« ✔ … ») ; le reste passe par le filtre d'`affichable`. La commande lancée, elle, ne change pas. Un programme fixe
/// de Windows (`vanguard:programme …`) se montre tel qu'il est lancé (« sfc.exe /scannow ») ; un acte
/// (`vanguard:service …`), par sa phrase (« Arrêter le service Spooler… ») ; un geste de Linux
/// (`vanguard:geste …`), par sa phrase aussi.
pub fn commande_affichable(commande: &str) -> String {
    if let Some(a) = crate::machine::gestes::analyser_programme(commande) {
        return a.commande();
    }
    #[cfg(unix)]
    if let Some(g) = crate::machine::gestes_unix::analyser(commande) {
        let (fr, en) = g.phrase();
        return if crate::langue::anglais() { en } else { fr };
    }
    #[cfg(windows)]
    if let Some(a) = crate::machine::gestes::analyser_acte(commande) {
        return crate::machine::windows::corrections::texte_acte(&a);
    }
    // La recherche du vrai winget (fenêtre administrateur) est longue : annoncée « winget … », le reste filtré.
    #[cfg(windows)]
    if let Some(reste) = crate::machine::windows::sans_recherche_de_winget(commande) {
        return format!("winget{}", commande_affichable(reste));
    }
    commande
        .chars()
        .map(|c| match c {
            '\n' => " ⏎ ".to_string(),
            '\t' => c.to_string(),
            _ => rendu(c).to_string(),
        })
        .collect()
}

/// Ce qui est montré à la place d'un caractère : une espace ordinaire pour une espace trompeuse, « � » pour un autre
/// piège, le caractère lui-même sinon.
fn rendu(c: char) -> char {
    if espace_trompeur(c) {
        ' '
    } else if piege(c) {
        '\u{fffd}'
    } else {
        c
    }
}

/// Le texte contient-il encore un caractère piégé ? Pour les tests des lectures.
#[cfg(test)]
pub(crate) fn contient_un_piege(texte: &str) -> bool {
    texte.chars().any(piege)
}

/// Largeur affichée d'un texte, en colonnes du terminal (sans les codes de couleur).
pub fn largeur_affichee(t: &str) -> usize {
    let mut n = 0usize;
    let mut code = false;
    for c in t.chars() {
        match (code, c) {
            (false, '\x1b') => code = true,
            (true, 'm') => code = false,
            (false, _) => n = n.saturating_add(largeur_car(c)),
            _ => {}
        }
    }
    n
}

/// Le début de `t` (sans codes de couleur) qui tient dans `n` colonnes, « … » compris s'il a fallu couper.
pub fn couper(t: &str, n: usize) -> String {
    if largeur_affichee(t) <= n {
        return t.to_string();
    }
    let mut court = String::new();
    let mut l = 0usize;
    for c in t.chars() {
        // Une colonne gardée pour « … ».
        if l.saturating_add(largeur_car(c)) >= n {
            break;
        }
        l = l.saturating_add(largeur_car(c));
        court.push(c);
    }
    court.push('…');
    court
}

/// Coupe un texte trop long (« … » à la fin) ou le complète d'espaces jusqu'à `n` colonnes.
pub fn ajuster(t: &str, n: usize) -> String {
    let l = largeur_affichee(t);
    // Un texte en couleur n'est jamais coupé (on couperait un code) : seulement complété.
    if l > n && !t.contains('\x1b') {
        let court = couper(t, n);
        let reste = n.saturating_sub(largeur_affichee(&court));
        format!("{court}{}", " ".repeat(reste))
    } else {
        format!("{t}{}", " ".repeat(n.saturating_sub(l)))
    }
}

/// Coupe un texte en lignes d'au plus `largeur` colonnes, aux espaces.
pub fn envelopper(t: &str, largeur: usize) -> Vec<String> {
    envelopper_decale(t, largeur, largeur)
}

/// Les mots d'un texte, groupés pour la coupe : en français, « et » sont séparés de leur contenu par une espace, et
/// une coupe à cette espace laisserait un « seul en fin de ligne ou un » seul en tête de la suivante. Décidé : un mot
/// qui finit par « reste collé au suivant, un mot qui commence par » au précédent.
fn mots_insecables(t: &str) -> Vec<String> {
    let mut mots: Vec<String> = Vec::new();
    let mut coller = false;
    for mot in t.split_whitespace() {
        match mots.last_mut() {
            Some(dernier) if coller || mot.starts_with('»') => {
                dernier.push(' ');
                dernier.push_str(mot);
            }
            _ => mots.push(mot.to_string()),
        }
        coller = mot.ends_with('«');
    }
    mots
}

/// Comme `envelopper`, la première ligne d'au plus `premiere` caractères (elle suit un début déjà affiché).
pub fn envelopper_decale(t: &str, premiere: usize, suivantes: usize) -> Vec<String> {
    let mut lignes = Vec::new();
    let mut ligne = String::new();
    for mot in mots_insecables(t) {
        let mot = mot.as_str();
        let largeur = if lignes.is_empty() { premiere } else { suivantes };
        if !ligne.is_empty()
            && largeur_affichee(&ligne)
                .saturating_add(largeur_affichee(mot))
                .saturating_add(1)
                > largeur
        {
            lignes.push(std::mem::take(&mut ligne));
        }
        if !ligne.is_empty() {
            ligne.push(' ');
        }
        ligne.push_str(mot);
    }
    if !ligne.is_empty() {
        lignes.push(ligne);
    }
    lignes
}

/// Un texte de plusieurs lignes prêt à afficher : chaque ligne plus large que `LARGEUR` est coupée aux espaces. Sans
/// cela, un terminal de 80 colonnes coupe au milieu d'un mot et reprend au bord gauche, et la largeur d'un message
/// dépend de ce qu'on y met (un chemin, un nombre) : seul l'affichage la connaît. Une ligne qui tient reste telle
/// quelle, espaces d'alignement compris. La suite d'une phrase coupée à la main pour un terminal plus large (même
/// retrait, minuscule en tête) est recoupée avec elle ; la suite s'aligne après le signe qui ouvre la ligne (« ✖ »,
/// « 2. »), sinon sous son début.
pub fn mettre_en_lignes(texte: &str) -> String {
    let lignes: Vec<&str> = texte.split('\n').collect();
    let mut sortie: Vec<String> = Vec::with_capacity(lignes.len());
    let mut i = 0;
    while let Some(&ligne) = lignes.get(i) {
        i = i.saturating_add(1);
        if largeur_affichee(ligne) <= LARGEUR {
            sortie.push(ligne.to_string());
            continue;
        }
        let corps = ligne.trim_start_matches(' ');
        let retrait = ligne.len().saturating_sub(corps.len());
        let mut paragraphe = corps.to_string();
        while let Some(&suivante) = lignes.get(i) {
            let suite = suivante.trim_start_matches(' ');
            if suivante.len().saturating_sub(suite.len()) != retrait
                || !sans_codes(suite).starts_with(char::is_lowercase)
            {
                break;
            }
            paragraphe.push(' ');
            paragraphe.push_str(suite);
            i = i.saturating_add(1);
        }
        let suite = retrait.saturating_add(largeur_de_la_marque(&paragraphe));
        let morceaux = envelopper_decale(
            &paragraphe,
            LARGEUR.saturating_sub(retrait).max(12),
            LARGEUR.saturating_sub(suite).max(12),
        );
        for (j, morceau) in morceaux.iter().enumerate() {
            sortie.push(format!("{}{morceau}", " ".repeat(if j == 0 { retrait } else { suite })));
        }
    }
    sortie.join("\n")
}

/// Un texte sans ses codes de couleur.
fn sans_codes(t: &str) -> String {
    let mut propre = String::with_capacity(t.len());
    let mut code = false;
    for c in t.chars() {
        match (code, c) {
            (false, '\x1b') => code = true,
            (true, c) if c.is_ascii_alphabetic() => code = false,
            (true, _) => {}
            (false, c) => propre.push(c),
        }
    }
    propre
}

/// La largeur du signe qui ouvre un texte (« ✖ », « ⚠ », « 2. », « - »), espace comprise ; 0 sans signe.
fn largeur_de_la_marque(texte: &str) -> usize {
    let premier = sans_codes(texte.split_whitespace().next().unwrap_or(""));
    let chiffre_point = premier
        .strip_suffix('.')
        .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()));
    let signe = !premier.is_empty() && premier.chars().all(|c| !c.is_alphanumeric());
    if (signe || chiffre_point) && largeur_affichee(&premier) <= 3 {
        largeur_affichee(&premier).saturating_add(1)
    } else {
        0
    }
}

/// `println!` d'un texte mis en lignes (`mettre_en_lignes`) : ce que fait `trp!`.
pub fn imprimer(texte: &str) {
    println!("{}", mettre_en_lignes(texte));
}

/// Affiche `debut` (déjà mis en forme) puis `texte` dans la couleur `style`, coupé pour tenir dans `LARGEUR`, la
/// suite alignée à `retrait` colonnes. Sans cela, le terminal coupe les longues lignes au milieu d'un mot et les
/// reprend au bord gauche.
pub fn afficher_aligne(debut: &str, texte: &str, retrait: usize, style: &str) {
    let premiere = LARGEUR.saturating_sub(largeur_affichee(debut)).max(12);
    let lignes = envelopper_decale(texte, premiere, LARGEUR.saturating_sub(retrait).max(12));
    let mut lignes = lignes.iter();
    println!("{debut}{style}{}{RESET}", lignes.next().map_or("", String::as_str));
    for l in lignes {
        println!("{:retrait$}{style}{l}{RESET}", "");
    }
}

/// Titre de section : « ━━ Titre ━━━━━━━━… » sur la largeur de la fenêtre au moment de l'impression, comme `cadre`.
pub fn titre(t: &str) {
    println!("\n{}", ligne_titre_sur(t, largeur_du_cadre(colonnes_du_terminal())));
}

/// La ligne d'un titre de section, pour un menu qui se redessine : faite sur `LARGEUR`, étirée au dessin à la
/// largeur de la fenêtre (`etirer_filets`).
pub fn ligne_titre(t: &str) -> String {
    ligne_titre_sur(t, LARGEUR)
}

/// La ligne d'un titre de section sur `largeur` colonnes ; un titre plus long garde son texte entier, sans filet.
pub fn ligne_titre_sur(t: &str, largeur: usize) -> String {
    let reste = largeur.saturating_sub(largeur_affichee(t).saturating_add(4));
    format!("{ACCENT}━━ {t} {}{RESET}", "━".repeat(reste))
}

/// Sous-titre discret à l'intérieur d'un écran : « ── NOM ──────… », sur la largeur de la fenêtre comme `titre`.
pub fn section(t: &str) {
    println!("\n{}", ligne_section_sur(t, largeur_du_cadre(colonnes_du_terminal())));
}

/// La ligne d'un sous-titre, pour un menu qui se redessine : faite sur `LARGEUR`, étirée au dessin comme
/// `ligne_titre`.
pub fn ligne_section(t: &str) -> String {
    ligne_section_sur(t, LARGEUR)
}

/// La ligne d'un sous-titre sur `largeur` colonnes.
pub fn ligne_section_sur(t: &str, largeur: usize) -> String {
    let reste = largeur.saturating_sub(largeur_affichee(t).saturating_add(6));
    format!("  {ACCENT}── {t}{RESET} {GRIS}{}{RESET}", "─".repeat(reste))
}

/// Étire (ou raccourcit) à `largeur` colonnes le filet des titres et sous-titres parmi `rangees`, au moment du
/// dessin : les menus les reçoivent tout faits (`ligne_titre`, `ligne_section`, dans des `Ligne::Texte` ou les titres
/// d'une liste à cocher), et seul l'écran sait la largeur de la fenêtre. Les autres rangées ne changent pas.
pub fn etirer_filets(rangees: &mut [String], largeur: usize) {
    for r in rangees {
        if let Some(etiree) = filet_sur(r, largeur) {
            *r = etiree;
        }
    }
}

/// `rangee` refaite sur `largeur` colonnes si c'est un titre ou un sous-titre ; son texte est retrouvé entre le
/// début et le filet de la ligne, telle que `ligne_titre_sur` ou `ligne_section_sur` l'a faite.
fn filet_sur(rangee: &str, largeur: usize) -> Option<String> {
    let corps = rangee.strip_suffix(RESET)?;
    if let Some(t) = corps.strip_prefix(&format!("{ACCENT}━━ ")) {
        let t = t.trim_end_matches('━').strip_suffix(' ')?;
        return Some(ligne_titre_sur(t, largeur));
    }
    let t = corps.strip_prefix(&format!("  {ACCENT}── "))?;
    let t = t.trim_end_matches('─').strip_suffix(&format!("{RESET} {GRIS}"))?;
    Some(ligne_section_sur(t, largeur))
}

/// Cadre de tête d'écran : un titre à gauche, une précision à droite, sur la largeur de la fenêtre au moment de
/// l'impression (`largeur_du_cadre`).
pub fn cadre(gauche: &str, droite: &str) {
    for l in lignes_cadre_sur(gauche, droite, largeur_du_cadre(colonnes_du_terminal())) {
        println!("{l}");
    }
}

/// En dessous de cette largeur, le cadre ne suit plus la fenêtre et garde `LARGEUR`, comme avant : quelques colonnes
/// ne laisseraient plus lire le titre.
pub const CADRE_MIN: usize = 30;

/// Une précision de droite coupée garde au moins ces colonnes (« … » compris) ; sinon elle est retirée.
const DROITE_MIN: usize = 8;

/// La largeur du cadre dans une fenêtre de `colonnes` colonnes : toute la fenêtre sauf sa dernière colonne, où écrire
/// fait passer l'ancienne console de Windows à la ligne. `LARGEUR` sans terminal (tube, essais, rapport : des sorties
/// stables) ou sous `CADRE_MIN`.
pub fn largeur_du_cadre(colonnes: Option<usize>) -> usize {
    match colonnes.map(|c| c.saturating_sub(1)) {
        Some(l) if l >= CADRE_MIN => l,
        _ => LARGEUR,
    }
}

/// Les colonnes de la fenêtre où écrit Vanguard, ou `None` sans vrai terminal (et toujours dans les essais, dont la
/// sortie ne doit pas dépendre de la fenêtre qui les lance).
pub fn colonnes_du_terminal() -> Option<usize> {
    use std::io::IsTerminal as _;
    if cfg!(test) || !std::io::stdout().is_terminal() {
        return None;
    }
    crossterm::terminal::size().ok().map(|(c, _)| usize::from(c))
}

/// Les trois lignes du cadre de tête, chacune de `largeur` colonnes exactement. Trop étroit pour les deux textes, la
/// précision de droite cède d'abord (coupée par « … », puis retirée), le titre de gauche ensuite.
pub fn lignes_cadre_sur(gauche: &str, droite: &str, largeur: usize) -> [String; 3] {
    let interieur = largeur.saturating_sub(2);
    // Deux espaces de chaque côté des textes.
    let place = interieur.saturating_sub(4);
    let (g, d) = (largeur_affichee(gauche), largeur_affichee(droite));
    let (gauche, droite) = if g.saturating_add(d) <= place {
        (gauche.to_string(), droite.to_string())
    } else {
        // Une espace au moins entre les deux textes.
        let pour_droite = place.saturating_sub(g.saturating_add(1));
        if d > 0 && pour_droite >= DROITE_MIN {
            (gauche.to_string(), couper_en_couleur(droite, pour_droite))
        } else {
            (couper_en_couleur(gauche, place), String::new())
        }
    };
    let espace = place.saturating_sub(largeur_affichee(&gauche).saturating_add(largeur_affichee(&droite)));
    [
        format!("{ACCENT}╭{}╮{RESET}", "─".repeat(interieur)),
        format!(
            "{ACCENT}│{RESET}  {gauche}{}{droite}  {ACCENT}│{RESET}",
            " ".repeat(espace)
        ),
        format!("{ACCENT}╰{}╯{RESET}", "─".repeat(interieur)),
    ]
}

/// Le début de `t` qui tient dans `n` colonnes, « … » compris s'il a fallu couper, ses codes de couleur gardés
/// (`couper` les compterait comme du texte et pourrait en couper un).
fn couper_en_couleur(t: &str, n: usize) -> String {
    if largeur_affichee(t) <= n {
        return t.to_string();
    }
    if n == 0 {
        return String::new();
    }
    let mut court = String::new();
    let (mut l, mut code) = (0usize, false);
    for c in t.chars() {
        match (code, c) {
            (false, '\x1b') => code = true,
            (true, c) => code = c != 'm',
            // Une colonne gardée pour « … ».
            (false, c) if l.saturating_add(largeur_car(c)) >= n => break,
            (false, c) => l = l.saturating_add(largeur_car(c)),
        }
        court.push(c);
    }
    // Ni espace ni code de couleur juste avant « … » : « VANGUARD{RESET} {GRIS} » garderait son espace derrière
    // le code qui le suit.
    loop {
        let sans_espace = court.trim_end_matches(' ').len();
        court.truncate(sans_espace);
        match court.rfind('\x1b') {
            Some(i) if court.ends_with('m') && !court[i..].contains(' ') => court.truncate(i),
            _ => break,
        }
    }
    if t.contains('\x1b') {
        court.push_str(RESET);
    }
    court.push('…');
    court
}

/// Barre de score sur 10 cases, de la couleur de sa lettre : « ▰▰▰▰▰▰▰▰▱▱ ».
pub fn barre(score: u32) -> String {
    let pleines = usize::try_from(score.min(100)).unwrap_or(100).saturating_add(5) / 10;
    format!(
        "{}{}{GRIS}{}{RESET}",
        couleur_note(crate::risk::note(score)),
        "▰".repeat(pleines),
        "▱".repeat(10usize.saturating_sub(pleines))
    )
}

/// Note sous forme d'étiquette : « A 100 » en couleur.
pub fn etiquette_note(score: u32) -> String {
    let n = crate::risk::note(score);
    format!("{}{n}{RESET} {GRIS}{score}{RESET}", couleur_note(n))
}

pub fn afficher_note(quoi: &str, score: u32) {
    let n = crate::risk::note(score);
    let c = couleur_note(n);
    crate::trp!(
        "  {quoi} : {c}{n}{RESET} ({score}/100)  {}",
        "  {quoi}: {c}{n}{RESET} ({score}/100)  {}",
        barre(score)
    );
}

/// « a, b, c (et 2 autre(s)) » / “a, b, c (and 2 more)” : les `max` premiers éléments d'une liste, pour un message d'une ligne.
pub fn resume(noms: &[impl AsRef<str>], max: usize, separateur: &str) -> String {
    let mut t = noms
        .iter()
        .take(max)
        .map(AsRef::as_ref)
        .collect::<Vec<_>>()
        .join(separateur);
    if noms.len() > max {
        let reste = noms.len().saturating_sub(max);
        t += &crate::trf!(" (et {reste} autre(s))", " (and {reste} more)");
    }
    t
}

/// La question telle qu'elle s'affiche : sa dernière ligne, réponse comprise, tient dans `LARGEUR`. Trop longue
/// (une durée, un nom mis dedans), elle est coupée aux espaces, la suite sous son début ; les espaces de la fin, après
/// lesquels la réponse se tape, sont gardés. `print!` ne passe pas par `mettre_en_lignes`, comme `trp!`.
pub(crate) fn question_en_lignes(question: &str) -> String {
    let corps = question.trim_end_matches(' ');
    let fin = &question[corps.len()..];
    let (avant, derniere) = match corps.rsplit_once('\n') {
        Some((a, d)) => (Some(a), d),
        None => (None, corps),
    };
    // Une colonne pour la réponse.
    if largeur_affichee(derniere).saturating_add(fin.len()) < LARGEUR {
        return question.to_string();
    }
    let texte = derniere.trim_start_matches(' ');
    let retrait = derniere.len().saturating_sub(texte.len());
    // Une ponctuation seule (« ? », « : ») et l'invite (« [o/N] ») restent avec le mot d'avant : jamais une ligne
    // qui commence par « : ».
    let mut morceaux: Vec<String> = Vec::new();
    for mot in texte.split_whitespace() {
        let colle = mot.starts_with('[') || mot.chars().all(|c| "?!:;».".contains(c));
        match morceaux.last_mut() {
            Some(m) if colle => {
                m.push(' ');
                m.push_str(mot);
            }
            _ => morceaux.push(mot.to_string()),
        }
    }
    let largeur = LARGEUR
        .saturating_sub(retrait.saturating_add(fin.len()).saturating_add(1))
        .max(12);
    let mut lignes: Vec<String> = Vec::new();
    for m in morceaux {
        match lignes.last_mut() {
            Some(l)
                if largeur_affichee(l)
                    .saturating_add(largeur_affichee(&m))
                    .saturating_add(1)
                    <= retrait.saturating_add(largeur) =>
            {
                l.push(' ');
                l.push_str(&m);
            }
            _ => lignes.push(format!("{}{m}", " ".repeat(retrait))),
        }
    }
    match avant {
        Some(a) => format!("{a}\n{}{fin}", lignes.join("\n")),
        None => format!("{}{fin}", lignes.join("\n")),
    }
}

/// Vrai quand la dernière réponse au clavier a été « revenir » (Échap, ←, Entrée sur une ligne vide d'une question
/// « Entrée pour revenir », liste à cocher laissée) : l'outil s'arrête alors à la demande, et la pause « Entrée pour
/// revenir… » du menu serait un appui de trop. Toute autre réponse l'efface.
static REVENU: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(crate) fn noter_retour(revenu: bool) {
    REVENU.store(revenu, std::sync::atomic::Ordering::Relaxed);
}

/// La dernière réponse a-t-elle été « revenir » ? Lu une fois : la réponse est oubliée.
pub(crate) fn vient_de_revenir() -> bool {
    REVENU.swap(false, std::sync::atomic::Ordering::Relaxed)
}

/// `vient_de_revenir`, sans l'oublier : le relevé local compte l'outil laissé, et la pause du menu lit ensuite la même
/// réponse.
pub(crate) fn revenu() -> bool {
    REVENU.load(std::sync::atomic::Ordering::Relaxed)
}

/// Pose une question dans le terminal et retourne la réponse sans espaces autour.
pub fn demander(question: &str) -> String {
    // Fin de l'entrée (Ctrl-D, terminal fermé, entrée redirigée) : on quitte. Le menu reposait sinon la question
    // sans fin, en effaçant l'écran à toute vitesse (un cœur du processeur à 100 %). Vu en test.
    reponse(question).unwrap_or_else(|| crate::machine::quitter(0))
}

/// Comme `demander`, mais la fin de l'entrée donne la réponse vide, celle par défaut d'une question « [o/N] », au lieu
/// de quitter : l'outil qui la pose va au bout (`vanguard verifier-fichier f < /dev/null` donne son verdict). Une
/// réponse arrivée par un tube est lue comme au clavier. Le clavier sans l'écran (`vanguard verifier-fichier f >
/// rapport.txt`) : la question partirait dans le fichier et la commande attendrait une réponse que personne ne voit
/// demander ; la réponse par défaut est prise, écrite avec la question (que `| tee` montre aussi, sans attendre).
pub fn demander_ou_defaut(question: &str) -> String {
    use std::io::IsTerminal as _;
    if std::io::stdin().is_terminal() && !std::io::stdout().is_terminal() {
        println!("{}", question_en_lignes(question));
        return String::new();
    }
    reponse(question).unwrap_or_default()
}

/// La question posée, puis la ligne lue sans espaces autour ; `None` à la fin de l'entrée.
fn reponse(question: &str) -> Option<String> {
    use std::io::Write;
    print!("{}", question_en_lignes(question));
    let _ = std::io::stdout().flush();
    let mut s = String::new();
    if matches!(std::io::stdin().read_line(&mut s), Ok(0) | Err(_)) {
        println!();
        return None;
    }
    noter_retour(false);
    Some(s.trim().to_string())
}

#[cfg(test)]
/// Les textes des `trp!` d'un fichier source (code seul, sans ses tests), dans les deux langues, qui dépassent
/// `LARGEUR` colonnes : couleurs retirées, « {…} » compté pour une colonne. Affichés tels quels, le terminal les
/// couperait au milieu d'un mot. Partagé par les tests des écrans (gaming, logiciels, nettoyer, optimiser, Wi-Fi
/// public…), d'où sa place ici plutôt que dans Gaming.
pub(crate) fn textes_trop_larges(source: &str) -> Vec<String> {
    const COULEURS: [&str; 7] = ["RESET", "GRAS", "GRIS", "VERT", "ACCENT", "TOUCHE", "DISCRET"];
    let fin = source
        .find("mod tests {")
        .and_then(|i| source[..i].rfind("#[cfg(test)]"));
    let code = &source[..fin.unwrap_or(source.len())];
    let mut trop_larges = Vec::new();
    // Le nom de la macro en deux morceaux : écrit d'un bloc, il passerait pour un texte à traduire auprès des
    // outils qui relèvent les textes (outils-dp40/textes.py).
    for appel in code.split(concat!("trp", "!(")).skip(1) {
        let mut car = appel.chars().peekable();
        // Les deux premiers littéraux de l'appel : le texte français, puis l'anglais.
        for _ in 0..2 {
            if !car.by_ref().any(|c| c == '"') {
                break;
            }
            let mut texte = String::new();
            while let Some(c) = car.next() {
                match (c, car.peek().copied()) {
                    ('"', _) => break,
                    ('\\', Some('n')) => {
                        car.next();
                        texte.push('\n');
                    }
                    // Ligne continuée (« \ » en fin de ligne) : les espaces qui suivent ne s'affichent pas.
                    ('\\', Some('\n')) => while car.next_if(|c| c.is_whitespace()).is_some() {},
                    ('\\', Some(echappe)) => {
                        car.next();
                        texte.push(echappe);
                    }
                    ('{', Some('{')) => {
                        car.next();
                        texte.push('{');
                    }
                    ('{', _) => {
                        let nom: String = car.by_ref().take_while(|&c| c != '}').collect();
                        if !COULEURS.contains(&nom.as_str()) {
                            texte.push('X');
                        }
                    }
                    (c, _) => texte.push(c),
                }
            }
            trop_larges.extend(
                texte
                    .lines()
                    .filter(|l| largeur_affichee(l) > LARGEUR)
                    .map(str::to_string),
            );
        }
    }
    trop_larges
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    /// Le cadre de tête à 40, 76, 120 et 200 colonnes : chaque ligne de la largeur voulue, les coins au bord, la
    /// précision de droite coupée proprement quand la place manque, puis retirée avant le titre.
    #[test]
    fn le_cadre_prend_la_largeur_de_la_fenetre() {
        let gauche = format!("{ACCENT}VANGUARD{RESET} {GRIS}0.90.0{RESET}");
        let droite = "Cyberdéfense portable des postes et des réseaux";
        for colonnes in [40, 76, 120, 200] {
            let largeur = largeur_du_cadre(Some(colonnes));
            // La dernière colonne reste libre : y écrire fait passer l'ancienne console de Windows à la ligne.
            assert_eq!(largeur, colonnes - 1);
            let [haut, milieu, bas] = lignes_cadre_sur(&gauche, droite, largeur);
            for l in [&haut, &milieu, &bas] {
                assert_eq!(largeur_affichee(l), largeur, "{colonnes} colonnes : {l}");
            }
            let (haut, milieu, bas) = (sans_codes(&haut), sans_codes(&milieu), sans_codes(&bas));
            assert!(haut.starts_with('╭') && haut.ends_with('╮'), "{haut}");
            assert!(bas.starts_with('╰') && bas.ends_with('╯'), "{bas}");
            assert!(
                milieu.starts_with("│  VANGUARD 0.90.0 ") && milieu.ends_with("  │"),
                "{milieu}"
            );
            if colonnes < 76 {
                // « Cyberdéfense portable… » : coupée à une fin de mot ou dedans, jamais sur une espace avant « … ».
                assert!(milieu.ends_with("…  │") && !milieu.contains(" …"), "{milieu}");
                assert!(milieu.contains("Cyber"), "{milieu}");
            } else {
                assert!(milieu.ends_with(&format!("{droite}  │")), "{milieu}");
            }
        }
        // Trop étroit pour la précision : elle est retirée, et le titre coupé ensuite, ses couleurs gardées.
        let long = format!("{ACCENT}VANGUARD{RESET} {GRIS}›{RESET} Réseau et Internet {GRIS}›{RESET} Wi-Fi public");
        let [_, milieu, _] = lignes_cadre_sur(&long, droite, 30);
        assert_eq!(largeur_affichee(&milieu), 30, "{milieu}");
        let propre = sans_codes(&milieu);
        assert!(
            propre.starts_with("│  VANGUARD › Réseau") && propre.ends_with("…  │"),
            "{propre}"
        );
        // Aucun code de couleur coupé en deux, et la couleur rendue avant le bord.
        assert!(!propre.contains("Cyber") && !propre.contains('['), "{milieu:?}");
        assert!(milieu.contains(&format!("{RESET}…  ")), "{milieu:?}");
        // Coupé juste après un code et une espace : ni l'espace ni le code ne restent avant « … ».
        let titre = format!("{ACCENT}VANGUARD{RESET} {GRIS}0.90.0{RESET}");
        let coupe = couper_en_couleur(&titre, 10);
        assert_eq!(coupe, format!("{ACCENT}VANGUARD{RESET}…"));
        assert_eq!(largeur_affichee(&coupe), 9);
        let [_, milieu, _] = lignes_cadre_sur(&titre, "", 16);
        assert_eq!(largeur_affichee(&milieu), 16);
        assert!(sans_codes(&milieu).starts_with("│  VANGUARD…"), "{milieu:?}");
        // Sous le minimum, ou sans terminal (essais, tube, rapport), les 76 colonnes d'avant.
        assert_eq!(largeur_du_cadre(Some(CADRE_MIN)), LARGEUR);
        assert_eq!(largeur_du_cadre(Some(CADRE_MIN + 1)), CADRE_MIN);
        assert_eq!(largeur_du_cadre(None), LARGEUR);
        assert_eq!(colonnes_du_terminal(), None);
        // Un titre seul, trop long, est coupé lui aussi au lieu de déborder.
        let [_, milieu, _] = lignes_cadre_sur(&"x".repeat(80), "", LARGEUR);
        assert_eq!(largeur_affichee(&milieu), LARGEUR);
    }

    /// Les titres et sous-titres d'un menu, faits sur 76 colonnes, étirés au dessin à 40, 76, 120 et 200 colonnes :
    /// la largeur exacte, le texte gardé, et les autres rangées intactes.
    #[test]
    fn les_titres_s_etirent_a_la_largeur_voulue() {
        let titre = ligne_titre("Réglages du poste");
        let section = ligne_section("RÉSEAU ET INTERNET");
        let autre = format!("  {GRIS}── pas un sous-titre{RESET}");
        assert_eq!(largeur_affichee(&titre), LARGEUR);
        assert_eq!(largeur_affichee(&section), LARGEUR);
        for colonnes in [40, 76, 120, 200] {
            let largeur = largeur_du_cadre(Some(colonnes));
            let mut rangees = vec![titre.clone(), section.clone(), autre.clone(), String::new()];
            etirer_filets(&mut rangees, largeur);
            assert_eq!(rangees[0], ligne_titre_sur("Réglages du poste", largeur));
            assert_eq!(rangees[1], ligne_section_sur("RÉSEAU ET INTERNET", largeur));
            assert_eq!(largeur_affichee(&rangees[0]), largeur, "{colonnes} colonnes");
            assert_eq!(largeur_affichee(&rangees[1]), largeur, "{colonnes} colonnes");
            assert!(sans_codes(&rangees[0]).starts_with("━━ Réglages du poste ━"));
            assert!(sans_codes(&rangees[1]).starts_with("  ── RÉSEAU ET INTERNET ─"));
            assert_eq!(rangees[2..], [autre.clone(), String::new()]);
            // Étirer de nouveau, à une autre largeur (la fenêtre redimensionnée), part du texte et non du filet.
            etirer_filets(&mut rangees, LARGEUR);
            assert_eq!(rangees[..2], [titre.clone(), section.clone()]);
        }
        // Un titre plus long que la fenêtre garde son texte : seul le filet disparaît.
        let long = "x".repeat(50);
        let mut rangees = vec![ligne_titre(&long)];
        etirer_filets(&mut rangees, 40);
        assert_eq!(sans_codes(&rangees[0]), format!("━━ {long} "));
    }

    /// Une question trop longue est coupée aux espaces : la réponse tapée tombe dans 76 colonnes. Une question qui
    /// tient ne bouge pas, ses espaces de fin compris.
    #[test]
    fn question_dans_la_largeur() {
        let courte = "\n  Couper la protection en temps réel pendant 1 heure ? [o/N] : ";
        assert_eq!(question_en_lignes(courte), courte);
        let longue = "\n  Couper la protection en temps réel jusqu'à ce que vous la remettiez ? [o/N] : ";
        let l = question_en_lignes(longue);
        assert!(l.starts_with("\n  Couper") && l.ends_with("[o/N] : "), "{l:?}");
        let lignes: Vec<&str> = l.split('\n').collect();
        assert_eq!(lignes.len(), 3, "{l:?}");
        assert!(lignes.iter().all(|x| largeur_affichee(x) < LARGEUR), "{l:?}");
        assert!(lignes[2].starts_with("  ") && !lignes[2].starts_with("   "), "{l:?}");
        assert_eq!(
            l.split_whitespace().collect::<Vec<_>>(),
            longue.split_whitespace().collect::<Vec<_>>(),
            "aucun mot perdu"
        );
    }

    #[test]
    fn une_ligne_trop_longue_est_coupee_entre_les_mots() {
        // Une ligne qui tient ne bouge pas, espaces d'alignement compris.
        let court = "  Copie de cet ordinateur : 0.78.0\n  Clé VANGUARD           : 0.79.0";
        assert_eq!(mettre_en_lignes(court), court);
        // Trop longue : coupée aux espaces, la suite sous le texte du « ✖ », chaque ligne dans 76 colonnes, aucun mot
        // perdu ni coupé.
        let long = format!(
            "  {GRIS}✖ Pas assez de place : il faut 12,4 Go, le disque n'a que 3,1 Go de libre. Décochez des dossiers, ou \
             choisissez un autre disque.{RESET}"
        );
        let lignes = mettre_en_lignes(&long);
        assert!(lignes.lines().count() >= 2, "{lignes}");
        for (i, l) in lignes.lines().enumerate() {
            assert!(largeur_affichee(l) <= LARGEUR, "{l}");
            assert!(l.starts_with(if i == 0 { "  " } else { "    " }), "{l}");
        }
        assert_eq!(
            lignes.split_whitespace().collect::<Vec<_>>(),
            long.split_whitespace().collect::<Vec<_>>()
        );
        // Un mot plus long que la ligne (un chemin) a sa ligne à lui, entier.
        let chemin = format!("  Depuis {}", "/tres/long".repeat(12));
        assert!(
            mettre_en_lignes(&chemin)
                .lines()
                .any(|l| l.trim() == "/tres/long".repeat(12))
        );
        // Une phrase coupée à la main pour un terminal plus large est recoupée d'un seul tenant ; une nouvelle phrase
        // (majuscule) garde sa ligne ; sans signe en tête, la suite s'aligne sous le début.
        let a_la_main = "  Tapez un mot de passe : il ne s'affiche pas et ne quitte jamais cet ordinateur. Seuls 5 caractères \
                         de son\n  empreinte sont envoyés à Have I Been Pwned, et la comparaison se fait ici.\n  Entrée seule \
                         pour terminer.";
        let lignes = mettre_en_lignes(a_la_main);
        for l in lignes.lines() {
            assert!(
                largeur_affichee(l) <= LARGEUR && l.starts_with("  ") && !l.starts_with("   "),
                "{lignes}"
            );
        }
        assert_eq!(lignes.lines().last(), Some("  Entrée seule pour terminer."));
        assert!(lignes.contains("de son empreinte"), "{lignes}");
        assert_eq!(largeur_de_la_marque("2. Restaurer"), 3);
        assert_eq!(largeur_de_la_marque(&format!("{GRIS}✖{RESET} Copie")), 2);
        assert_eq!(largeur_de_la_marque("Tapez un mot"), 0);
    }

    #[test]
    fn un_emoji_ou_une_lettre_pleine_largeur_prend_deux_colonnes() {
        assert_eq!(largeur_affichee("💡 à faire"), 10);
        assert_eq!(largeur_affichee("🔧 ｐａｙｐａｌ"), 15);
        // Ces symboles restent sur une colonne ; les codes de couleur, la variante d'emoji et l'accent combiné, sur
        // aucune.
        assert_eq!(largeur_affichee(&format!("{VERT}✔ ⚠ ✖ ℹ →{RESET}")), 9);
        assert_eq!(largeur_affichee("⚠\u{fe0f}e\u{301}"), 2);
    }

    #[test]
    fn couper_et_ajuster_tiennent_dans_les_colonnes_demandees() {
        // Couper au milieu d'un emoji le laisserait déborder : il part entier.
        for n in 1..12 {
            let court = couper("ab💡💡💡cdef", n);
            assert!(largeur_affichee(&court) <= n, "{n} : {court}");
            assert_eq!(largeur_affichee(&ajuster("ab💡💡💡cdef", n)), n, "{n}");
        }
        assert_eq!(couper("ab💡cd", 4), "ab…");
        assert_eq!(couper("court", 9), "court");
        assert_eq!(ajuster("Lien", 9), "Lien     ");
        assert_eq!(ajuster("Navigation", 6), "Navig…");
    }

    /// Chaque sorte de caractère piégé devient « � », un par caractère ; la séquence qui suit reste lisible, inerte.
    #[test]
    fn textes_pieges_rendus_inoffensifs() {
        // Couleur ANSI : ESC [ 31 m.
        assert_eq!(affichable("\x1b[31mrouge"), "�[31mrouge");
        // OSC 52 : écrit « echo PIRATE » dans le presse-papier, terminé par BEL ou par ESC \.
        assert_eq!(
            affichable("Salon\x1b]52;c;ZWNobyBQSVJBVEU=\x07"),
            "Salon�]52;c;ZWNobyBQSVJBVEU=�"
        );
        assert_eq!(affichable("\x1b]0;titre\x1b\\"), "�]0;titre�\\");
        // Retour chariot et effacement de ligne : l'alerte d'avant serait réécrite.
        assert_eq!(affichable("x\x1b[2K\rFaux"), "x�[2K�Faux");
        assert_eq!(affichable("a\nb\tc\0d\x7f"), "a�b�c�d�");
        // C1 : U+009B est un ESC [ à lui seul ; U+0085 un saut de ligne.
        assert_eq!(affichable("\u{9b}31mrouge\u{85}"), "�31mrouge�");
        // Bidi : « facture[U+202E]fdp.exe » s'afficherait « facture exe.pdf ».
        assert_eq!(affichable("facture\u{202e}fdp.exe"), "facture�fdp.exe");
        assert_eq!(
            affichable("\u{202a}\u{202b}\u{202c}\u{202d}\u{2066}\u{2067}\u{2068}\u{2069}\u{61c}"),
            "���������"
        );
        // Invisibles : « Sa[U+200B]lon » ressemble à « Salon ».
        assert_eq!(affichable("Sa\u{200b}lon"), "Sa�lon");
        // Des blancs qui n'en sont pas : un nom « vide » ou « Sa lon » fait de remplissages, de Braille vide ou d'un
        // joint de graphèmes.
        assert_eq!(
            affichable("a\u{3164}b\u{ffa0}c\u{115f}d\u{1160}e\u{2800}f\u{34f}g"),
            "a�b�c�d�e�f�g"
        );
        // Trompeurs sans rien piloter : séparateurs de ligne, trait d'union conditionnel, séparateur mongol, étiquettes.
        assert_eq!(
            affichable("a\u{2028}b\u{2029}c\u{ad}d\u{180e}e\u{e0041}\u{e007f}"),
            "a�b�c�d�e��"
        );
        // Le sélecteur de variante des émojis reste.
        assert_eq!(affichable("❤\u{fe0f}"), "❤\u{fe0f}");
        assert_eq!(
            affichable("\u{200c}\u{200d}\u{200e}\u{200f}\u{2060}\u{2061}\u{2062}\u{2063}\u{2064}\u{feff}"),
            "����������"
        );
        // Une colonne par « � » : les alignements tiennent.
        assert_eq!(largeur_affichee(&affichable("\x1b[2K\r")), 5);
        assert!(contient_un_piege("a\u{2066}") && !contient_un_piege(&affichable("a\u{2066}\x1b")));
        assert_eq!(
            chemin_affichable(std::path::Path::new("/tmp/a\x1b]52;c;eA==\x07b")),
            "/tmp/a�]52;c;eA==�b"
        );
        assert_eq!(
            chemin_affichable(std::path::Path::new("/home/alice/Téléchargements/été 💡.pdf")),
            "/home/alice/Téléchargements/été 💡.pdf"
        );
    }

    /// Un texte normal ne change pas, octet pour octet : accents, emojis, autres écritures, espaces ordinaires,
    /// ponctuation, « � » déjà là.
    #[test]
    fn texte_normal_identique() {
        for t in [
            "",
            "Salon",
            "Chez Max · 2,4 GHz",
            "Café d'été « Québec » — 5 GHz",
            "💡 📶 🔒 ✔ ⚠ ✖ ℹ → ▰▱",
            "Москва 東京 서울 مرحبا שלום Ελλάδα हिन्दी ไทย",
            "a b c",
            "C:\\Users\\alice\\Téléchargements\\facture (2).pdf",
            "déjà � là",
        ] {
            assert_eq!(affichable(t), t);
            assert_eq!(affichable(t).as_bytes(), t.as_bytes());
            assert!(!contient_un_piege(t), "{t}");
        }
    }

    /// A4 : une espace d'une autre largeur (insécable, fine, ultrafine, cadratin, idéographique…) devient une espace
    /// ordinaire, une par une : l'ultrafine ne colle plus « Sa lon » en « Salon », l'idéographique ne décale plus un
    /// alignement, et un nombre écrit à la française (« 12 345 octets », « 75 % ») reste lisible.
    #[test]
    fn espaces_trompeuses_rendues_ordinaires() {
        let espaces = "\u{a0}\u{1680}\u{2000}\u{2001}\u{2002}\u{2003}\u{2004}\u{2005}\u{2006}\u{2007}\u{2008}\u{2009}\u{200a}\u{202f}\u{205f}\u{3000}";
        for c in espaces.chars() {
            assert!(espace_trompeur(c) && !piege(c), "U+{:04X}", u32::from(c));
            assert_eq!(affichable(&format!("Sa{c}lon")), "Sa lon", "U+{:04X}", u32::from(c));
            assert_eq!(
                commande_affichable(&format!("rm Sa{c}lon")),
                "rm Sa lon",
                "U+{:04X}",
                u32::from(c)
            );
        }
        let a = affichable(&format!("a{espaces}b"));
        assert_eq!(a, format!("a{}b", " ".repeat(16)));
        assert_eq!(largeur_affichee(&a), 18);
        assert!(!contient_un_piege(&a));
        assert_eq!(
            affichable("12\u{a0}345\u{202f}octets, 75\u{a0}%"),
            "12 345 octets, 75 %"
        );
        for c in [' ', '\t', '\u{200b}', '\u{3164}'] {
            assert!(!espace_trompeur(c), "U+{:04X}", u32::from(c));
        }
    }

    /// Une commande montrée : le nom piégé qu'elle reprend ne peut plus effacer la ligne ni en retourner la fin ; ses
    /// propres sauts de ligne et tabulations restent, et une commande normale ne change pas.
    #[test]
    fn commandes_montrees_telles_qu_elles_seront_lancees() {
        assert_eq!(
            commande_affichable("rm -rf -- ~/.cache/'x\x1b[2K\recho rassurant'"),
            "rm -rf -- ~/.cache/'x�[2K�echo rassurant'"
        );
        assert_eq!(
            commande_affichable("Unregister-ScheduledTask -TaskName 'Maj\u{202e}exe.txt' -Confirm:$false"),
            "Unregister-ScheduledTask -TaskName 'Maj�exe.txt' -Confirm:$false"
        );
        assert_eq!(commande_affichable("\u{9b}2K\x1b]52;c;eA==\x07"), "�2K�]52;c;eA==�");
        // Un saut de ligne, de Vanguard ou d'un nom de fichier, reste sur la ligne de la commande : pas de fausse ligne.
        assert_eq!(
            commande_affichable("rm -- ~/.cache/'x\n  ✔ Tout est propre'"),
            "rm -- ~/.cache/'x ⏎   ✔ Tout est propre'"
        );
        assert_eq!(
            commande_affichable("printf '%s\\n' a | sudo tee /etc/x >/dev/null\nsudo sysctl --system"),
            "printf '%s\\n' a | sudo tee /etc/x >/dev/null ⏎ sudo sysctl --system"
        );
        for c in [
            "sudo systemctl disable --now cups.service",
            "Set-ItemProperty -LiteralPath 'HKCU:\\Software\\Été' -Name 'a\tb' -Value 0",
        ] {
            assert_eq!(commande_affichable(c).as_bytes(), c.as_bytes());
        }
    }

    #[test]
    fn emojis_selon_la_console_et_la_variable() {
        assert!(emojis_voulus(None, false));
        assert!(!emojis_voulus(None, true));
        assert!(!emojis_voulus(Some("0"), false) && !emojis_voulus(Some(" Off "), false));
        assert!(emojis_voulus(Some("1"), true) && emojis_voulus(Some("oui"), true));
        // Une valeur inconnue ne force rien.
        assert!(!emojis_voulus(Some("peut-être"), true));
        // Les remplaçants tiennent sur une colonne, comme ce que l'ancienne console dessine.
        assert_eq!(largeur_affichee("→ +"), 3);
    }

    #[test]
    fn envelopper_compte_les_colonnes() {
        let lignes = envelopper("💡 💡 💡 💡 💡", 8);
        assert_eq!(lignes, ["💡 💡 💡", "💡 💡"]);
        assert!(lignes.iter().all(|l| largeur_affichee(l) <= 8));
    }

    /// Décidé : jamais une ligne qui finit par « ni une qui commence par », à toutes les largeurs ; rien de perdu ni
    /// de déplacé, et la largeur tenue, sauf pour un groupe insécable plus large qu'elle, seul sur sa ligne.
    #[test]
    fn envelopper_ne_separe_pas_les_guillemets() {
        let texte = "Temps réel des fichiers : arrêté, il passe par le veilleur, coupé ; « vanguard veilleur on » \
                     l'allume. « Sain » veut dire « rien de connu dans ce qui a été lu », et « » reste entier.";
        let mots: Vec<&str> = texte.split_whitespace().collect();
        for largeur in 8_usize..=90 {
            for premiere in [largeur, largeur.saturating_sub(5).max(4)] {
                let lignes = envelopper_decale(texte, premiere, largeur);
                assert_eq!(
                    lignes.join(" ").split_whitespace().collect::<Vec<_>>(),
                    mots,
                    "{largeur}"
                );
                for (n, l) in lignes.iter().enumerate() {
                    assert!(!l.ends_with('«') && !l.starts_with('»'), "{largeur} : {l:?}");
                    let place = if n == 0 { premiere } else { largeur };
                    assert!(
                        largeur_affichee(l) <= place || mots_insecables(l).len() == 1,
                        "{largeur} : {l:?}"
                    );
                }
            }
        }
        // La coupe garde sa place à l'intérieur des guillemets : le groupe ne prend que le mot voisin.
        assert_eq!(envelopper("a « b c d » e", 3), ["a", "« b", "c", "d »", "e"]);
        assert_eq!(mots_insecables("« »"), ["« »"]);
        assert_eq!(envelopper("💡 💡 💡 💡 💡", 8), ["💡 💡 💡", "💡 💡"]);
    }
}

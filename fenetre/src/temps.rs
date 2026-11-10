//! Les heures montrées : celle d'une ligne de la console (heure locale) et l'âge d'un événement du journal de
//! Vanguard, écrit en temps universel (« AAAA-MM-JJTHH:MM:SSZ »).

use chrono::{DateTime, Local, NaiveDateTime, Utc};

/// L'heure locale, « HH:MM:SS ».
pub fn heure_locale() -> String {
    Local::now().format("%H:%M:%S").to_string()
}

/// L'heure locale, « HH:MM ».
pub fn heure_minute() -> String {
    Local::now().format("%H:%M").to_string()
}

/// Un instant du journal (« 2026-11-09T14:03:00Z »), ou rien s'il est mal formé.
pub fn lire(quand: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(quand, "%Y-%m-%dT%H:%M:%SZ")
        .ok()
        .map(|n| n.and_utc())
}

/// L'âge d'un instant, dit simplement : « à l'instant », « il y a 5 min », « il y a 3 h », « il y a 2 j » ; un
/// instant à venir (horloge déréglée) ou illisible : rien d'inventé, l'instant brut.
pub fn age(quand: &str, maintenant: DateTime<Utc>) -> String {
    let Some(t) = lire(quand) else {
        return crate::nettoyage::nom(quand, 32);
    };
    let s = maintenant.signed_duration_since(t).num_seconds();
    match s {
        s if s < 0 => crate::nettoyage::nom(quand, 32),
        0..60 => crate::tr!("à l'instant", "just now").to_string(),
        60..3600 => crate::trf!("il y a {} min", "{} min ago", s / 60),
        3600..86_400 => crate::trf!("il y a {} h", "{} h ago", s / 3600),
        _ => crate::trf!("il y a {} j", "{} d ago", s / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(quand: &str) -> DateTime<Utc> {
        lire(quand).unwrap()
    }

    #[test]
    fn lit_le_format_du_journal() {
        assert!(lire("2026-11-09T14:03:00Z").is_some());
        assert!(lire("2026-11-09 14:03:00").is_none());
        assert!(lire("2026-13-40T99:00:00Z").is_none());
        assert!(lire("").is_none());
    }

    #[test]
    fn dit_l_age() {
        let m = a("2026-11-09T14:00:00Z");
        // Les tests ne changent pas la langue : le français.
        assert_eq!(age("2026-11-09T13:59:30Z", m), "à l'instant");
        assert_eq!(age("2026-11-09T13:55:00Z", m), "il y a 5 min");
        assert_eq!(age("2026-11-09T11:00:00Z", m), "il y a 3 h");
        assert_eq!(age("2026-11-07T14:00:00Z", m), "il y a 2 j");
        // À venir ou illisible : l'instant tel quel, nettoyé.
        assert_eq!(age("2026-11-09T15:00:00Z", m), "2026-11-09T15:00:00Z");
        assert_eq!(age("hier\u{202e}", m), "hier\u{fffd}");
    }
}

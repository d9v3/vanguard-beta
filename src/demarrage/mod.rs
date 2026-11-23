//! Le démarrage : la ligne de commande, son aide, les droits avec lesquels Vanguard tourne, et la fenêtre de
//! Vanguard ouverte à la place du menu quand elle est là.

pub(crate) mod aide;
pub(crate) mod arguments;
pub(crate) mod console;
pub(crate) mod droits;
pub(crate) mod empreinte_fenetre;
pub(crate) mod lancer_fenetre;
#[cfg(target_os = "linux")]
pub(crate) mod memfd;
// Une seule fenêtre : la déjà ouverte est ramenée devant au lieu d'en ouvrir une seconde.
#[cfg(any(target_os = "linux", windows))]
mod une_fenetre;

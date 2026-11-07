//! Les bases de signatures de ClamAV présentes sur l'ordinateur, lues par Vanguard lui-même, sans lancer clamscan :
//! les .cvd et .cld (en-tête, archive tar, gzip ou non, contrôlés par leur liste .info), puis les signatures dont
//! Vanguard sait les formats (empreintes, contenu, logiques dans un sous-ensemble), chacune non appliquée comptée
//! par raison. Voir `base` pour la confiance accordée aux fichiers et ce qui est chargé, et quand.

pub(crate) mod base;
pub(crate) mod commun;
pub(crate) mod corps;
pub(crate) mod cvd;
pub(crate) mod fp;
pub(crate) mod hashes;
pub(crate) mod ldb;
pub(crate) mod ndb;
pub(crate) mod signatures;

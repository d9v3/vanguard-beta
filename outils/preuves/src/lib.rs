//! Racine des preuves bornées (Kani) : trois lecteurs de données hostiles, inclus tels quels depuis src/, avec la
//! cale réseau du banc de fuzzing pour le client DNS. Les preuves sont dans preuve_*.rs, à côté.

// Les modules ne servent ici qu'à leurs preuves : le reste n'y est ni appelé ni réexporté.
#![allow(dead_code, unused_imports)]

#[path = "../../../fuzz/cale/reseau.rs"]
mod reseau;

#[path = "../../../src/sqlite.rs"]
mod sqlite;

#[path = "../../../src/machine/linux/zstd.rs"]
mod zstd;

#[path = "../../../src/audit/dns_client.rs"]
mod dns_client;

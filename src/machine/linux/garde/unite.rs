//! Le texte de l'unité systemd du garde, pur, durci comme l'étude le demande (§2.1). Sa forme est vérifiée par un
//! essai : une directive retirée ou affaiblie le fait échouer.

#![forbid(unsafe_code)]
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

/// Le texte de l'unité.
pub(crate) fn texte() -> String {
    format!(
        "\
# Posée par Vanguard (vanguard garde on), retirée par « vanguard garde off » ou la désinstallation.
[Unit]
Description=Vanguard : garde des lancements (fanotify)
DefaultDependencies=no
After=local-fs.target
Before=multi-user.target shutdown.target
Conflicts=shutdown.target

[Service]
Type=notify
NotifyAccess=main
ExecStart={programme} garde-servir
WatchdogSec=5
WatchdogSignal=SIGKILL
Restart=always
RestartSec=1
TimeoutStopSec=3
MemoryMax=256M
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_READ_SEARCH CAP_AUDIT_WRITE
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
RuntimeDirectory=vanguard/garde
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=restart
StateDirectory=vanguard/garde
StateDirectoryMode=0700
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service fanotify_init fanotify_mark openat2
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native
RestrictNamespaces=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
UMask=0022

[Install]
WantedBy=multi-user.target
",
        programme = super::PROGRAMME
    )
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    /// Les directives de l'unité, une par ligne `clé=valeur`.
    fn directives(t: &str) -> Vec<(&str, &str)> {
        t.lines()
            .filter(|l| !l.starts_with(['#', '[']) && !l.is_empty())
            .filter_map(|l| l.split_once('='))
            .collect()
    }

    #[test]
    fn durcie_comme_l_etude_le_demande() {
        let t = texte();
        let d = directives(&t);
        let valeur = |cle: &str| {
            let v: Vec<&str> = d.iter().filter(|(c, _)| *c == cle).map(|(_, v)| *v).collect();
            assert!(v.len() <= 1, "{cle} en double");
            v.first().copied()
        };
        for (cle, attendu) in [
            // Sans les dépendances par défaut, l'arrêt de la machine doit être demandé exprès.
            ("DefaultDependencies", "no"),
            ("Before", "multi-user.target shutdown.target"),
            ("Conflicts", "shutdown.target"),
            ("Type", "notify"),
            ("NotifyAccess", "main"),
            ("ExecStart", "/opt/vanguard/garde/vanguard garde-servir"),
            ("WatchdogSec", "5"),
            ("Restart", "always"),
            ("TimeoutStopSec", "3"),
            ("MemoryMax", "256M"),
            (
                "CapabilityBoundingSet",
                "CAP_SYS_ADMIN CAP_DAC_READ_SEARCH CAP_AUDIT_WRITE",
            ),
            ("NoNewPrivileges", "yes"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "read-only"),
            ("RuntimeDirectory", "vanguard/garde"),
            ("StateDirectory", "vanguard/garde"),
            ("PrivateNetwork", "yes"),
            ("RestrictAddressFamilies", "AF_UNIX"),
            ("MemoryDenyWriteExecute", "yes"),
            // openat2 n'est pas dans @system-service (systemd 257 le refuse par ENOSYS) : sans lui, le garde ne lit
            // aucune liste du compte (ouvrir.rs).
            (
                "SystemCallFilter",
                "@system-service fanotify_init fanotify_mark openat2",
            ),
            ("SystemCallArchitectures", "native"),
            ("RestrictNamespaces", "yes"),
            ("LockPersonality", "yes"),
            ("RestrictRealtime", "yes"),
            ("ProtectKernelModules", "yes"),
            ("ProtectKernelTunables", "yes"),
            ("ProtectKernelLogs", "yes"),
            ("WantedBy", "multi-user.target"),
        ] {
            assert_eq!(valeur(cle), Some(attendu), "{cle}");
        }
        // Le garde doit voir le /tmp de l'hôte : jamais de PrivateTmp. Aucune capacité ambiante.
        assert_eq!(valeur("PrivateTmp"), None);
        assert_eq!(valeur("AmbientCapabilities"), Some(""));
        // Le programme lancé est la copie root, jamais celle du compte.
        assert!(!t.contains("/home/") && !t.contains(".local"));
    }
}

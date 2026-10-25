# Couverture MITRE ATT&CK de Vanguard

> Page générée par `outils/couverture-attack.py` à partir des références des règles : ne pas la modifier à la main. `python3 outils/couverture-attack.py` la refait ; `outils/verifier.sh` échoue si elle n'est plus à jour. English: [COUVERTURE-ATTACK.en.md](COUVERTURE-ATTACK.en.md).

Chaque règle de Vanguard qui **détecte** quelque chose cite la technique d'ATT&CK qu'elle voit (T…) ; chaque règle qui **durcit** l'ordinateur cite la mesure d'atténuation qu'elle applique (M…). La carte range ces citations par tactique, dans la version 20.0 d'ATT&CK Enterprise. Une case « — » veut dire qu'aucune règle de Vanguard ne cite cette technique : c'est la liste des manques, tenue à jour par le code lui-même.

Citer une technique ne veut pas dire tout en voir : une règle peut ne voir qu'une partie des façons de la mener, sur un seul système. Ce que Vanguard protège et ne protège pas : [MODELE-DE-MENACE.md](MODELE-DE-MENACE.md).

## En bref

| Tactique | Techniques citées (elles ou une sous-technique) | Techniques d'ATT&CK |
|---|---:|---:|
| TA0043 Reconnaissance | 0 | 12 |
| TA0042 Préparation des moyens | 0 | 9 |
| TA0001 Accès initial | 2 | 11 |
| TA0002 Exécution | 5 | 22 |
| TA0003 Persistance | 12 | 22 |
| TA0004 Élévation de privilèges | 9 | 13 |
| TA0005 Furtivité | 7 | 31 |
| TA0112 Neutralisation des défenses | 3 | 18 |
| TA0006 Accès aux identifiants | 5 | 18 |
| TA0007 Découverte | 1 | 34 |
| TA0008 Déplacement latéral | 1 | 9 |
| TA0009 Collecte | 1 | 17 |
| TA0011 Commande et contrôle | 2 | 18 |
| TA0010 Exfiltration | 0 | 10 |
| TA0040 Impact | 2 | 15 |

## Par tactique

### TA0043 Reconnaissance

| Technique | Nom (MITRE) | Règles de Vanguard |
|---|---|---|
| T1589 | Gather Victim Identity Information | — |
| | *3 sous-techniques, aucune citée* | |
| T1590 | Gather Victim Network Information | — |
| | *6 sous-techniques, aucune citée* | |
| T1591 | Gather Victim Org Information | — |
| | *4 sous-techniques, aucune citée* | |
| T1592 | Gather Victim Host Information | — |
| | *4 sous-techniques, aucune citée* | |
| T1593 | Search Open Websites/Domains | — |
| | *3 sous-techniques, aucune citée* | |
| T1594 | Search Victim-Owned Websites | — |
| T1595 | Active Scanning | — |
| | *3 sous-techniques, aucune citée* | |
| T1596 | Search Open Technical Databases | — |
| | *5 sous-techniques, aucune citée* | |
| T1597 | Search Closed Sources | — |
| | *2 sous-techniques, aucune citée* | |
| T1598 | Phishing for Information | — |
| | *4 sous-techniques, aucune citée* | |
| T1681 | Search Threat Vendor Data | — |
| T1682 | Query Public AI Services | — |

### TA0042 Préparation des moyens

| Technique | Nom (MITRE) | Règles de Vanguard |
|---|---|---|
| T1583 | Acquire Infrastructure | — |
| | *8 sous-techniques, aucune citée* | |
| T1584 | Compromise Infrastructure | — |
| | *8 sous-techniques, aucune citée* | |
| T1585 | Establish Accounts | — |
| | *3 sous-techniques, aucune citée* | |
| T1586 | Compromise Accounts | — |
| | *3 sous-techniques, aucune citée* | |
| T1587 | Develop Capabilities | — |
| | *4 sous-techniques, aucune citée* | |
| T1588 | Obtain Capabilities | — |
| | *7 sous-techniques, aucune citée* | |
| T1608 | Stage Capabilities | — |
| | *7 sous-techniques, aucune citée* | |
| T1650 | Acquire Access | — |
| T1683 | Generate Content | — |
| | *2 sous-techniques, aucune citée* | |

### TA0001 Accès initial

| Technique | Nom (MITRE) | Règles de Vanguard |
|---|---|---|
| T1078 | Valid Accounts | `COM-CPT-003`, `EVT-IDE-001` |
| | *4 sous-techniques, aucune citée* | |
| T1091 | Replication Through Removable Media | — |
| T1133 | External Remote Services | `EVT-RDP-001` |
| T1189 | Drive-by Compromise | — |
| T1190 | Exploit Public-Facing Application | — |
| T1195 | Supply Chain Compromise | — |
| | *3 sous-techniques, aucune citée* | |
| T1199 | Trusted Relationship | — |
| T1200 | Hardware Additions | — |
| T1566 | Phishing | — |
| | *4 sous-techniques, aucune citée* | |
| T1659 | Content Injection | — |
| T1669 | Wi-Fi Networks | — |

### TA0002 Exécution

| Technique | Nom (MITRE) | Règles de Vanguard |
|---|---|---|
| T1047 | Windows Management Instrumentation | — |
| T1053 | Scheduled Task/Job | — |
| ↳ T1053.003 | Cron | `COM-INT-001`, `LNX-PRS-002` |
| ↳ T1053.005 | Scheduled Task | `EVT-TAC-001`, `WIN-JRN-003`, `WIN-PRS-001` |
| | *2 sur 5 sous-techniques citées* | |
| T1059 | Command and Scripting Interpreter | `EVT-PRC-001`, `WIN-JRN-003` |
| ↳ T1059.001 | PowerShell | `COM-PRG-001`, `EVT-PSH-001` |
| | *1 sur 13 sous-techniques citées* | |
| T1072 | Software Deployment Tools | — |
| T1106 | Native API | — |
| T1127 | Trusted Developer Utilities Proxy Execution | — |
| | *3 sous-techniques, aucune citée* | |
| T1129 | Shared Modules | — |
| T1197 | BITS Jobs | `EVT-BIT-001` |
| T1203 | Exploitation for Client Execution | — |
| T1204 | User Execution | — |
| ↳ T1204.002 | Malicious File | `COM-PRG-001` |
| | *1 sur 5 sous-techniques citées* | |
| T1559 | Inter-Process Communication | — |
| | *3 sous-techniques, aucune citée* | |
| T1569 | System Services | — |
| | *3 sous-techniques, aucune citée* | |
| T1574 | Hijack Execution Flow | `WIN-PRS-011` |
| ↳ T1574.006 | Dynamic Linker Hijacking | `LNX-PRS-002` |
| ↳ T1574.007 | Path Interception by PATH Environment Variable | `LNX-PRV-004`, `MAC-PRV-004` |
| ↳ T1574.009 | Path Interception by Unquoted Path | `WIN-SRV-001` |
| | *3 sur 12 sous-techniques citées* | |
| T1609 | Container Administration Command | — |
| T1610 | Deploy Container | — |
| T1648 | Serverless Execution | — |
| T1651 | Cloud Administration Command | — |
| T1674 | Input Injection | — |
| T1675 | ESXi Administration Command | — |
| T1677 | Poisoned Pipeline Execution | — |
| T1698 | Indirect Prompt Injection | — |
| T1699 | Direct Prompt Injection | — |

### TA0003 Persistance

| Technique | Nom (MITRE) | Règles de Vanguard |
|---|---|---|
| T1037 | Boot or Logon Initialization Scripts | — |
| ↳ T1037.002 | Login Hook | `MAC-PRS-003` |
| | *1 sur 5 sous-techniques citées* | |
| T1053 | Scheduled Task/Job | — |
| ↳ T1053.003 | Cron | `COM-INT-001`, `LNX-PRS-002` |
| ↳ T1053.005 | Scheduled Task | `EVT-TAC-001`, `WIN-JRN-003`, `WIN-PRS-001` |
| | *2 sur 5 sous-techniques citées* | |
| T1078 | Valid Accounts | `COM-CPT-003`, `EVT-IDE-001` |
| | *4 sous-techniques, aucune citée* | |
| T1098 | Account Manipulation | `EVT-ADM-001` |
| ↳ T1098.007 | Additional Local or Domain Groups | `COM-CPT-001` |
| | *1 sur 7 sous-techniques citées* | |
| T1112 | Modify Registry | — |
| T1133 | External Remote Services | `EVT-RDP-001` |
| T1136 | Create Account | — |
| ↳ T1136.001 | Local Account | `COM-CPT-001`, `EVT-ADM-001`, `LNX-CPT-001`, `WIN-JRN-003` |
| | *1 sur 3 sous-techniques citées* | |
| T1137 | Office Application Startup | — |
| | *6 sous-techniques, aucune citée* | |
| T1176 | Software Extensions | — |
| ↳ T1176.001 | Browser Extensions | `COM-NAV-001` |
| | *1 sur 2 sous-techniques citées* | |
| T1197 | BITS Jobs | `EVT-BIT-001` |
| T1205 | Traffic Signaling | — |
| | *2 sous-techniques, aucune citée* | |
| T1505 | Server Software Component | — |
| | *6 sous-techniques, aucune citée* | |
| T1525 | Implant Internal Image | — |
| T1542 | Pre-OS Boot | — |
| | *5 sous-techniques, aucune citée* | |
| T1543 | Create or Modify System Process | — |
| ↳ T1543.001 | Launch Agent | `MAC-PRS-001` |
| ↳ T1543.002 | Systemd Service | `COM-INT-001`, `LNX-PRS-002` |
| ↳ T1543.003 | Windows Service | `EVT-SRV-001`, `WIN-JRN-003`, `WIN-PRS-012` |
| ↳ T1543.004 | Launch Daemon | `MAC-PRS-001` |
| | *4 sur 5 sous-techniques citées* | |
| T1546 | Event Triggered Execution | — |
| ↳ T1546.003 | Windows Management Instrumentation Event Subscription | `EVT-WMI-001`, `WIN-PRS-006` |
| ↳ T1546.004 | Unix Shell Configuration Modification | `LNX-PRS-002` |
| ↳ T1546.008 | Accessibility Features | `WIN-PRS-002`, `WIN-PRS-003` |
| ↳ T1546.009 | AppCert DLLs | `WIN-PRS-008` |
| ↳ T1546.010 | AppInit DLLs | `WIN-PRS-005` |
| ↳ T1546.012 | Image File Execution Options Injection | `WIN-PRS-002` |
| | *6 sur 18 sous-techniques citées* | |
| T1547 | Boot or Logon Autostart Execution | `WIN-PRS-011` |
| ↳ T1547.001 | Registry Run Keys / Startup Folder | `WIN-PRS-001` |
| ↳ T1547.002 | Authentication Package | `WIN-PRS-007` |
| ↳ T1547.003 | Time Providers | `WIN-PRS-010` |
| ↳ T1547.004 | Winlogon Helper DLL | `WIN-PRS-004` |
| ↳ T1547.005 | Security Support Provider | `WIN-PRS-007` |
| ↳ T1547.006 | Kernel Modules and Extensions | `LNX-NOY-006`, `MAC-SYS-003` |
| ↳ T1547.010 | Port Monitors | `WIN-PRS-009` |
| ↳ T1547.013 | XDG Autostart Entries | `LNX-PRS-002` |
| ↳ T1547.015 | Login Items | `MAC-PRS-002` |
| | *9 sur 14 sous-techniques citées* | |
| T1554 | Compromise Host Software Binary | — |
| T1556 | Modify Authentication Process | — |
| ↳ T1556.002 | Password Filter DLL | `WIN-PRS-007` |
| ↳ T1556.003 | Pluggable Authentication Modules | `COM-INT-001` |
| | *2 sur 9 sous-techniques citées* | |
| T1653 | Power Settings | — |
| T1668 | Exclusive Control | — |
| T1671 | Cloud Application Integration | — |

### TA0004 Élévation de privilèges

| Technique | Nom (MITRE) | Règles de Vanguard |
|---|---|---|
| T1037 | Boot or Logon Initialization Scripts | — |
| ↳ T1037.002 | Login Hook | `MAC-PRS-003` |
| | *1 sur 5 sous-techniques citées* | |
| T1053 | Scheduled Task/Job | — |
| ↳ T1053.003 | Cron | `COM-INT-001`, `LNX-PRS-002` |
| ↳ T1053.005 | Scheduled Task | `EVT-TAC-001`, `WIN-JRN-003`, `WIN-PRS-001` |
| | *2 sur 5 sous-techniques citées* | |
| T1055 | Process Injection | — |
| | *12 sous-techniques, aucune citée* | |
| T1068 | Exploitation for Privilege Escalation | `WIN-PRS-012` |
| T1078 | Valid Accounts | `COM-CPT-003`, `EVT-IDE-001` |
| | *4 sous-techniques, aucune citée* | |
| T1098 | Account Manipulation | `EVT-ADM-001` |
| ↳ T1098.007 | Additional Local or Domain Groups | `COM-CPT-001` |
| | *1 sur 7 sous-techniques citées* | |
| T1134 | Access Token Manipulation | — |
| | *5 sous-techniques, aucune citée* | |
| T1484 | Domain or Tenant Policy Modification | — |
| | *2 sous-techniques, aucune citée* | |
| T1543 | Create or Modify System Process | — |
| ↳ T1543.001 | Launch Agent | `MAC-PRS-001` |
| ↳ T1543.002 | Systemd Service | `COM-INT-001`, `LNX-PRS-002` |
| ↳ T1543.003 | Windows Service | `EVT-SRV-001`, `WIN-JRN-003`, `WIN-PRS-012` |
| ↳ T1543.004 | Launch Daemon | `MAC-PRS-001` |
| | *4 sur 5 sous-techniques citées* | |
| T1546 | Event Triggered Execution | — |
| ↳ T1546.003 | Windows Management Instrumentation Event Subscription | `EVT-WMI-001`, `WIN-PRS-006` |
| ↳ T1546.004 | Unix Shell Configuration Modification | `LNX-PRS-002` |
| ↳ T1546.008 | Accessibility Features | `WIN-PRS-002`, `WIN-PRS-003` |
| ↳ T1546.009 | AppCert DLLs | `WIN-PRS-008` |
| ↳ T1546.010 | AppInit DLLs | `WIN-PRS-005` |
| ↳ T1546.012 | Image File Execution Options Injection | `WIN-PRS-002` |
| | *6 sur 18 sous-techniques citées* | |
| T1547 | Boot or Logon Autostart Execution | `WIN-PRS-011` |
| ↳ T1547.001 | Registry Run Keys / Startup Folder | `WIN-PRS-001` |
| ↳ T1547.002 | Authentication Package | `WIN-PRS-007` |
| ↳ T1547.003 | Time Providers | `WIN-PRS-010` |
| ↳ T1547.004 | Winlogon Helper DLL | `WIN-PRS-004` |
| ↳ T1547.005 | Security Support Provider | `WIN-PRS-007` |
| ↳ T1547.006 | Kernel Modules and Extensions | `LNX-NOY-006`, `MAC-SYS-003` |
| ↳ T1547.010 | Port Monitors | `WIN-PRS-009` |
| ↳ T1547.013 | XDG Autostart Entries | `LNX-PRS-002` |
| ↳ T1547.015 | Login Items | `MAC-PRS-002` |
| | *9 sur 14 sous-techniques citées* | |
| T1548 | Abuse Elevation Control Mechanism | — |
| ↳ T1548.001 | Setuid and Setgid | `LNX-PRS-001` |
| ↳ T1548.003 | Sudo and Sudo Caching | `LNX-PRV-003`, `MAC-PRV-002` |
| | *2 sur 6 sous-techniques citées* | |
| T1611 | Escape to Host | — |

### TA0005 Furtivité

| Technique | Nom (MITRE) | Règles de Vanguard |
|---|---|---|
| T1006 | Direct Volume Access | — |
| T1014 | Rootkit | `LNX-NOY-006`, `LNX-PRS-003` |
| T1027 | Obfuscated Files or Information | — |
| ↳ T1027.010 | Command Obfuscation | `EVT-PRC-001` |
| | *1 sur 18 sous-techniques citées* | |
| T1036 | Masquerading | — |
| | *12 sous-techniques, aucune citée* | |
| T1055 | Process Injection | — |
| | *12 sous-techniques, aucune citée* | |
| T1070 | Indicator Removal | — |
| | *8 sous-techniques, aucune citée* | |
| T1078 | Valid Accounts | `COM-CPT-003`, `EVT-IDE-001` |
| | *4 sous-techniques, aucune citée* | |
| T1127 | Trusted Developer Utilities Proxy Execution | — |
| | *3 sous-techniques, aucune citée* | |
| T1134 | Access Token Manipulation | — |
| | *5 sous-techniques, aucune citée* | |
| T1140 | Deobfuscate/Decode Files or Information | — |
| T1197 | BITS Jobs | `EVT-BIT-001` |
| T1202 | Indirect Command Execution | — |
| T1205 | Traffic Signaling | — |
| | *2 sous-techniques, aucune citée* | |
| T1211 | Exploitation for Stealth | — |
| T1216 | System Script Proxy Execution | — |
| | *2 sous-techniques, aucune citée* | |
| T1218 | System Binary Proxy Execution | `COM-PRG-001`, `EVT-PRC-001` |
| | *14 sous-techniques, aucune citée* | |
| T1220 | XSL Script Processing | — |
| T1221 | Template Injection | — |
| T1480 | Execution Guardrails | — |
| | *2 sous-techniques, aucune citée* | |
| T1497 | Virtualization/Sandbox Evasion | — |
| | *3 sous-techniques, aucune citée* | |
| T1535 | Unused/Unsupported Cloud Regions | — |
| T1542 | Pre-OS Boot | — |
| | *5 sous-techniques, aucune citée* | |
| T1564 | Hide Artifacts | — |
| | *14 sous-techniques, aucune citée* | |
| T1574 | Hijack Execution Flow | `WIN-PRS-011` |
| ↳ T1574.006 | Dynamic Linker Hijacking | `LNX-PRS-002` |
| ↳ T1574.007 | Path Interception by PATH Environment Variable | `LNX-PRV-004`, `MAC-PRV-004` |
| ↳ T1574.009 | Path Interception by Unquoted Path | `WIN-SRV-001` |
| | *3 sur 12 sous-techniques citées* | |
| T1612 | Build Image on Host | — |
| T1620 | Reflective Code Loading | `LNX-PRS-004` |
| T1622 | Debugger Evasion | — |
| T1678 | Delay Execution | — |
| T1679 | Selective Exclusion | — |
| T1684 | Social Engineering | — |
| | *2 sous-techniques, aucune citée* | |
| T1696 | Anti-Automation Evasion | — |
| | *2 sous-techniques, aucune citée* | |

### TA0112 Neutralisation des défenses

| Technique | Nom (MITRE) | Règles de Vanguard |
|---|---|---|
| T1112 | Modify Registry | — |
| T1207 | Rogue Domain Controller | — |
| T1222 | File and Directory Permissions Modification | — |
| | *2 sous-techniques, aucune citée* | |
| T1484 | Domain or Tenant Policy Modification | — |
| | *2 sous-techniques, aucune citée* | |
| T1553 | Subvert Trust Controls | — |
| ↳ T1553.004 | Install Root Certificate | `COM-CRT-001`, `COM-TLS-003` |
| | *1 sur 6 sous-techniques citées* | |
| T1556 | Modify Authentication Process | — |
| ↳ T1556.002 | Password Filter DLL | `WIN-PRS-007` |
| ↳ T1556.003 | Pluggable Authentication Modules | `COM-INT-001` |
| | *2 sur 9 sous-techniques citées* | |
| T1578 | Modify Cloud Compute Infrastructure | — |
| | *5 sous-techniques, aucune citée* | |
| T1599 | Network Boundary Bridging | — |
| | *1 sous-techniques, aucune citée* | |
| T1600 | Weaken Encryption | — |
| | *2 sous-techniques, aucune citée* | |
| T1601 | Modify System Image | — |
| | *2 sous-techniques, aucune citée* | |
| T1647 | Plist File Modification | — |
| T1666 | Modify Cloud Resource Hierarchy | — |
| T1685 | Disable or Modify Tools | `EVT-DEF-001`, `EVT-PSH-001`, `WIN-ANV-002` |
| ↳ T1685.001 | Disable or Modify Windows Event Log | `EVT-AUD-001`, `EVT-SRV-001` |
| ↳ T1685.005 | Clear Windows Event Logs | `COM-JRN-001`, `EVT-EFF-001`, `WIN-JRN-003` |
| | *2 sur 7 sous-techniques citées* | |
| T1686 | Disable or Modify System Firewall | — |
| | *3 sous-techniques, aucune citée* | |
| T1687 | Exploitation for Defense Impairment | — |
| T1688 | Safe Mode Boot | — |
| T1689 | Downgrade Attack | — |
| T1690 | Prevent Command History Logging | — |

### TA0006 Accès aux identifiants

| Technique | Nom (MITRE) | Règles de Vanguard |
|---|---|---|
| T1003 | OS Credential Dumping | — |
| ↳ T1003.001 | LSASS Memory | `COM-PRG-001` |
| | *1 sur 8 sous-techniques citées* | |
| T1040 | Network Sniffing | `LNX-RES-002` |
| T1056 | Input Capture | — |
| | *4 sous-techniques, aucune citée* | |
| T1110 | Brute Force | `LNX-SSH-002`, `WIN-JRN-003` |
| ↳ T1110.001 | Password Guessing | `COM-CPT-003`, `EVT-MDP-001` |
| | *1 sur 4 sous-techniques citées* | |
| T1111 | Multi-Factor Authentication Interception | — |
| T1187 | Forced Authentication | — |
| T1212 | Exploitation for Credential Access | — |
| T1528 | Steal Application Access Token | — |
| T1539 | Steal Web Session Cookie | — |
| T1552 | Unsecured Credentials | — |
| | *8 sous-techniques, aucune citée* | |
| T1555 | Credentials from Password Stores | — |
| | *6 sous-techniques, aucune citée* | |
| T1556 | Modify Authentication Process | — |
| ↳ T1556.002 | Password Filter DLL | `WIN-PRS-007` |
| ↳ T1556.003 | Pluggable Authentication Modules | `COM-INT-001` |
| | *2 sur 9 sous-techniques citées* | |
| T1557 | Adversary-in-the-Middle | `COM-DNS-004`, `COM-SEG-005`, `COM-TLS-001` |
| ↳ T1557.001 | Name Resolution Poisoning and SMB Relay | `COM-PST-003` |
| ↳ T1557.002 | ARP Cache Poisoning | `COM-ARP-001`, `COM-ARP-002`, `COM-ARP-004` |
| ↳ T1557.003 | DHCP Spoofing | `COM-SEG-004` |
| ↳ T1557.004 | Evil Twin | `COM-WIF-003` |
| | *4 sur 4 sous-techniques citées* | |
| T1558 | Steal or Forge Kerberos Tickets | — |
| | *5 sous-techniques, aucune citée* | |
| T1606 | Forge Web Credentials | — |
| | *2 sous-techniques, aucune citée* | |
| T1621 | Multi-Factor Authentication Request Generation | — |
| T1649 | Steal or Forge Authentication Certificates | — |
| T1697 | Steal Application Specific Passwords | — |

### TA0007 Découverte

| Technique | Nom (MITRE) | Règles de Vanguard |
|---|---|---|
| T1007 | System Service Discovery | — |
| T1010 | Application Window Discovery | — |
| T1012 | Query Registry | — |
| T1016 | System Network Configuration Discovery | — |
| | *2 sous-techniques, aucune citée* | |
| T1018 | Remote System Discovery | — |
| T1033 | System Owner/User Discovery | — |
| T1040 | Network Sniffing | `LNX-RES-002` |
| T1046 | Network Service Discovery | — |
| T1049 | System Network Connections Discovery | — |
| T1057 | Process Discovery | — |
| T1069 | Permission Groups Discovery | — |
| | *3 sous-techniques, aucune citée* | |
| T1082 | System Information Discovery | — |
| T1083 | File and Directory Discovery | — |
| T1087 | Account Discovery | — |
| | *4 sous-techniques, aucune citée* | |
| T1120 | Peripheral Device Discovery | — |
| T1124 | System Time Discovery | — |
| T1135 | Network Share Discovery | — |
| T1201 | Password Policy Discovery | — |
| T1217 | Browser Information Discovery | — |
| T1482 | Domain Trust Discovery | — |
| T1497 | Virtualization/Sandbox Evasion | — |
| | *3 sous-techniques, aucune citée* | |
| T1518 | Software Discovery | — |
| | *2 sous-techniques, aucune citée* | |
| T1526 | Cloud Service Discovery | — |
| T1538 | Cloud Service Dashboard | — |
| T1580 | Cloud Infrastructure Discovery | — |
| T1613 | Container and Resource Discovery | — |
| T1614 | System Location Discovery | — |
| | *1 sous-techniques, aucune citée* | |
| T1615 | Group Policy Discovery | — |
| T1619 | Cloud Storage Object Discovery | — |
| T1622 | Debugger Evasion | — |
| T1652 | Device Driver Discovery | — |
| T1654 | Log Enumeration | — |
| T1673 | Virtual Machine Discovery | — |
| T1680 | Local Storage Discovery | — |

### TA0008 Déplacement latéral

| Technique | Nom (MITRE) | Règles de Vanguard |
|---|---|---|
| T1021 | Remote Services | — |
| ↳ T1021.001 | Remote Desktop Protocol | `EVT-RDP-001` |
| | *1 sur 8 sous-techniques citées* | |
| T1072 | Software Deployment Tools | — |
| T1080 | Taint Shared Content | — |
| T1091 | Replication Through Removable Media | — |
| T1210 | Exploitation of Remote Services | — |
| T1534 | Internal Spearphishing | — |
| T1550 | Use Alternate Authentication Material | — |
| | *4 sous-techniques, aucune citée* | |
| T1563 | Remote Service Session Hijacking | — |
| | *2 sous-techniques, aucune citée* | |
| T1570 | Lateral Tool Transfer | — |

### TA0009 Collecte

| Technique | Nom (MITRE) | Règles de Vanguard |
|---|---|---|
| T1005 | Data from Local System | — |
| T1025 | Data from Removable Media | — |
| T1039 | Data from Network Shared Drive | — |
| T1056 | Input Capture | — |
| | *4 sous-techniques, aucune citée* | |
| T1074 | Data Staged | — |
| | *2 sous-techniques, aucune citée* | |
| T1113 | Screen Capture | — |
| T1114 | Email Collection | — |
| | *3 sous-techniques, aucune citée* | |
| T1115 | Clipboard Data | — |
| T1119 | Automated Collection | — |
| T1123 | Audio Capture | — |
| T1125 | Video Capture | — |
| T1185 | Browser Session Hijacking | — |
| T1213 | Data from Information Repositories | — |
| | *6 sous-techniques, aucune citée* | |
| T1530 | Data from Cloud Storage | — |
| T1557 | Adversary-in-the-Middle | `COM-DNS-004`, `COM-SEG-005`, `COM-TLS-001` |
| ↳ T1557.001 | Name Resolution Poisoning and SMB Relay | `COM-PST-003` |
| ↳ T1557.002 | ARP Cache Poisoning | `COM-ARP-001`, `COM-ARP-002`, `COM-ARP-004` |
| ↳ T1557.003 | DHCP Spoofing | `COM-SEG-004` |
| ↳ T1557.004 | Evil Twin | `COM-WIF-003` |
| | *4 sur 4 sous-techniques citées* | |
| T1560 | Archive Collected Data | — |
| | *3 sous-techniques, aucune citée* | |
| T1602 | Data from Configuration Repository | — |
| | *2 sous-techniques, aucune citée* | |

### TA0011 Commande et contrôle

| Technique | Nom (MITRE) | Règles de Vanguard |
|---|---|---|
| T1001 | Data Obfuscation | — |
| | *3 sous-techniques, aucune citée* | |
| T1008 | Fallback Channels | — |
| T1071 | Application Layer Protocol | — |
| | *5 sous-techniques, aucune citée* | |
| T1090 | Proxy | — |
| | *4 sous-techniques, aucune citée* | |
| T1092 | Communication Through Removable Media | — |
| T1095 | Non-Application Layer Protocol | — |
| T1102 | Web Service | — |
| | *3 sous-techniques, aucune citée* | |
| T1104 | Multi-Stage Channels | — |
| T1105 | Ingress Tool Transfer | `COM-PRG-001`, `EVT-PRC-001` |
| T1132 | Data Encoding | — |
| | *2 sous-techniques, aucune citée* | |
| T1205 | Traffic Signaling | — |
| | *2 sous-techniques, aucune citée* | |
| T1219 | Remote Access Tools | — |
| ↳ T1219.002 | Remote Desktop Software | `COM-DIS-001` |
| | *1 sur 3 sous-techniques citées* | |
| T1568 | Dynamic Resolution | — |
| | *3 sous-techniques, aucune citée* | |
| T1571 | Non-Standard Port | — |
| T1572 | Protocol Tunneling | — |
| T1573 | Encrypted Channel | — |
| | *2 sous-techniques, aucune citée* | |
| T1659 | Content Injection | — |
| T1665 | Hide Infrastructure | — |

### TA0010 Exfiltration

| Technique | Nom (MITRE) | Règles de Vanguard |
|---|---|---|
| T1011 | Exfiltration Over Other Network Medium | — |
| | *1 sous-techniques, aucune citée* | |
| T1020 | Automated Exfiltration | — |
| | *1 sous-techniques, aucune citée* | |
| T1029 | Scheduled Transfer | — |
| T1030 | Data Transfer Size Limits | — |
| T1041 | Exfiltration Over C2 Channel | — |
| T1048 | Exfiltration Over Alternative Protocol | — |
| | *3 sous-techniques, aucune citée* | |
| T1052 | Exfiltration Over Physical Medium | — |
| | *1 sous-techniques, aucune citée* | |
| T1537 | Transfer Data to Cloud Account | — |
| T1567 | Exfiltration Over Web Service | — |
| | *4 sous-techniques, aucune citée* | |
| T1700 | AI-Enabled Exfiltration | — |

### TA0040 Impact

| Technique | Nom (MITRE) | Règles de Vanguard |
|---|---|---|
| T1485 | Data Destruction | — |
| | *1 sous-techniques, aucune citée* | |
| T1486 | Data Encrypted for Impact | `COM-INT-002` |
| T1489 | Service Stop | — |
| T1490 | Inhibit System Recovery | — |
| T1491 | Defacement | — |
| | *2 sous-techniques, aucune citée* | |
| T1495 | Firmware Corruption | — |
| T1496 | Resource Hijacking | `COM-PRG-001` |
| | *4 sous-techniques, aucune citée* | |
| T1498 | Network Denial of Service | — |
| | *2 sous-techniques, aucune citée* | |
| T1499 | Endpoint Denial of Service | — |
| | *4 sous-techniques, aucune citée* | |
| T1529 | System Shutdown/Reboot | — |
| T1531 | Account Access Removal | — |
| T1561 | Disk Wipe | — |
| | *2 sous-techniques, aucune citée* | |
| T1565 | Data Manipulation | — |
| | *3 sous-techniques, aucune citée* | |
| T1657 | Financial Theft | — |
| T1667 | Email Bombing | — |

## Mesures d'atténuation

Les mesures d'ATT&CK que les règles de durcissement appliquent ou vérifient.

| Mesure | Nom (MITRE) | Règles de Vanguard |
|---|---|---|
| M1013 | Application Developer Guidance | — |
| M1015 | Active Directory Configuration | — |
| M1016 | Vulnerability Scanning | `LNX-MAJ-003` |
| M1017 | User Training | — |
| M1018 | User Account Management | `COM-CPT-002` |
| M1019 | Threat Intelligence Program | — |
| M1020 | SSL/TLS Inspection | — |
| M1021 | Restrict Web-Based Content | — |
| M1022 | Restrict File and Directory Permissions | `LNX-PRV-001`, `LNX-PRV-004`, `LNX-SSH-003`, `MAC-PRV-003`, `MAC-PRV-004`, `MAC-SSH-001`, `WIN-SSH-002` |
| M1024 | Restrict Registry Permissions | — |
| M1025 | Privileged Process Integrity | `WIN-DUR-001` |
| M1026 | Privileged Account Management | `LNX-PRV-002`, `LNX-PRV-003`, `MAC-PRV-001`, `MAC-PRV-002`, `WIN-CPT-001` |
| M1027 | Password Policies | `COM-APP-004`, `COM-MDP-001`, `LNX-CPT-002`, `LNX-SSH-003`, `MAC-CPT-002`, `MAC-SSH-001`, `WIN-CPT-002`, `WIN-SSH-002` |
| M1028 | Operating System Configuration | `LNX-NOY-002`, `LNX-NOY-003`, `LNX-NOY-005`, `LNX-NOY-007`, `LNX-RES-003`, `WIN-DUR-002` |
| M1029 | Remote Data Storage | — |
| M1030 | Network Segmentation | `COM-SEG-001`, `COM-SEG-002` |
| M1031 | Network Intrusion Prevention | — |
| M1032 | Multi-factor Authentication | — |
| M1033 | Limit Software Installation | — |
| M1034 | Limit Hardware Installation | — |
| M1035 | Limit Access to Resource Over Network | `COM-AGT-001`, `COM-APP-001`, `COM-APP-002`, `COM-EXP-001`, `COM-EXP-004`, `COM-PAR-001`, `COM-PST-001`, `COM-PST-002`, `LNX-CTN-001`, `LNX-RES-001`, `LNX-SES-003`, `MAC-RES-001`, `WIN-DIS-001`, `WIN-RES-001`, `WIN-RES-002` |
| M1036 | Account Use Policies | `LNX-CPT-002`, `MAC-CPT-002` |
| M1037 | Filter Network Traffic | `COM-EXP-003`, `LNX-PFE-001`, `MAC-PFE-001`, `MAC-PFE-002`, `WIN-PFE-001` |
| M1038 | Execution Prevention | `MAC-SYS-001`, `WIN-DUR-005` |
| M1039 | Environment Variable Permissions | — |
| M1040 | Behavior Prevention on Endpoint | `WIN-ANV-003` |
| M1041 | Encrypt Sensitive Information | `COM-CLE-002`, `LNX-CHF-001`, `MAC-CHF-001`, `MAC-SAV-002`, `WIN-CHF-001` |
| M1042 | Disable or Remove Feature or Program | `COM-APP-002`, `COM-BLU-001`, `COM-WIF-002`, `MAC-PAR-001`, `MAC-RES-002`, `WIN-DUR-003`, `WIN-DUR-004`, `WIN-RES-003`, `WIN-SSH-001` |
| M1043 | Credential Access Protection | `WIN-DUR-001` |
| M1044 | Restrict Library Loading | — |
| M1045 | Code Signing | `LNX-NOY-001`, `MAC-SYS-001`, `MAC-SYS-002` |
| M1046 | Boot Integrity | `LNX-DEM-001`, `LNX-PLT-001`, `MAC-DEM-001`, `WIN-DEM-001` |
| M1047 | Audit | `COM-FIC-001`, `LNX-JRN-001`, `WIN-JRN-001`, `WIN-JRN-002` |
| M1048 | Application Isolation and Sandboxing | `LNX-NOY-004` |
| M1049 | Antivirus/Antimalware | `MAC-ANV-001`, `WIN-ANV-001` |
| M1050 | Exploit Protection | `LNX-NOY-003`, `WIN-DUR-001` |
| M1051 | Update Software | `COM-APP-004`, `COM-MAJ-001`, `LNX-MAJ-001`, `LNX-MAJ-002`, `LNX-MAJ-003`, `LNX-MAJ-004`, `LNX-MAJ-005`, `MAC-MAJ-001`, `MAC-MAJ-002`, `MAC-MAJ-003`, `MAC-MAJ-004`, `WIN-MAJ-001`, `WIN-MAJ-002`, `WIN-MAJ-003` |
| M1052 | User Account Control | `WIN-PRV-001` |
| M1053 | Data Backup | `COM-SAV-001`, `LNX-SAV-001`, `MAC-SAV-001` |
| M1054 | Software Configuration | `COM-AGT-002`, `COM-NAV-002`, `COM-WIF-004`, `LNX-SSH-001`, `LNX-SSH-004`, `LNX-SSH-005`, `LNX-SSH-006`, `MAC-SSH-002` |
| M1055 | Do Not Mitigate | — |
| M1056 | Pre-compromise | — |
| M1057 | Data Loss Prevention | — |
| M1060 | Out-of-Band Communications Channel | — |

## Règles sans identifiant ATT&CK

46 règles sur 206 ne citent encore ni technique ni mesure (ce n'est pas une obligation : une vérification de l'état de l'ordinateur n'a pas toujours sa technique). Les règles par famille :

- **communes et audit du réseau** (30) : COM-APP-003, COM-APP-005, COM-ARP-003, COM-CLE-001, COM-CLE-003, COM-DNS-001, COM-DNS-002, COM-DNS-003, COM-DNS-005, COM-ESP-001, COM-ETA-001, COM-EXP-002, COM-HEU-001, COM-HIS-001, COM-LOG-001, COM-MAT-001, COM-NAV-003, COM-NAV-004, COM-PQC-001, COM-PQC-002, COM-PQC-003, COM-PUB-001, COM-SUR-001, COM-SUR-002, COM-SUR-003, COM-TLS-002, COM-TLS-004, COM-TLS-005, COM-WIF-001, COM-WIF-005
- **Linux** (7) : LNX-MAJ-006, LNX-MAT-001, LNX-SES-001, LNX-SES-002, LNX-SRV-001, LNX-SUR-001, LNX-WIF-001
- **Windows** (3) : WIN-SES-001, WIN-SES-002, WIN-WIF-001
- **macOS** (6) : MAC-CPT-001, MAC-DIS-001, MAC-PRF-001, MAC-SES-001, MAC-SES-002, MAC-WIF-001

## Droits

Les identifiants, tactiques et noms viennent d'ATT&CK, reproduits selon les conditions d'utilisation de MITRE (avec leurs avertissements dans [assets/attack-v20.tsv](assets/attack-v20.tsv)) :

> The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK® for research, development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy.
>
> © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.

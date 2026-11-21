# Dépanner avec Claude : lance Claude Code depuis la clé VANGUARD sur l'ordinateur d'un proche (« Depanner avec
# Claude.bat », à la racine de la clé, appelle ce script et garde la fenêtre ouverte à la fin). Mode d'emploi :
# LISEZMOI.txt, à côté. Troubleshoot with Claude: runs Claude Code from the VANGUARD key. See README.txt.
#
# - Rien n'est installé : claude.exe est copié dans un dossier temporaire à soi (%TEMP%\vanguard-claude-…, créé avec
#   des droits pour l'utilisateur seul, relus ensuite ; refusé sur un disque sans droits Windows, FAT ou réseau),
#   vérifié là (signature Authenticode valide, signataire « Anthropic, PBC » reconnu par son nom, son pays, son
#   numéro d'entreprise et son registre (Delaware), lus champ par champ ; empreinte égale à celle du manifeste de la
#   clé), puis lancé de là.
# - Le jeton de connexion à Claude et la conversation restent dans ce dossier (CLAUDE_CONFIG_DIR), jamais sur la clé
#   ni dans le profil du proche. En sortant : déconnexion (claude auth logout, son résultat est dit), puis le dossier
#   et les journaux de Claude Code de cette session sont effacés. Fenêtre fermée par sa croix : un gardien caché,
#   lancé avant Claude, attend la fin de ce script et fait la même chose. Ordinateur éteint en pleine session, ou
#   fenêtre fermée avant le gardien : le prochain lancement efface d'abord ce qui est resté.
# - Pas de mise à jour automatique, pas de trafic non essentiel, pas de connecteurs du compte (courriel, fichiers en
#   ligne), jamais le navigateur de ce PC. L'environnement de l'ordinateur visité ne choisit ni le serveur, ni le
#   compte, ni le mandataire, ni le traçage (ANTHROPIC_*, CLAUDE_*, NODE_*, *_PROXY… retirées, avant toute commande
#   de Claude Code).
#   Limite, dite : les variables de certificats sont retirées, mais le magasin de certificats de Windows reste cru
#   par Claude Code, comme par le navigateur.
# - Claude demande avant toute commande qui change quelque chose (CLAUDE.md, à côté, lui donne les consignes).
# Limite, dite dans LISEZMOI : un programme malveillant du même compte Windows peut lire le jeton pendant la session.
# PowerShell 5.1 (Windows 10) : ce fichier est en UTF-8 avec BOM, sans quoi les accents seraient mal lus.
# Essais : outils/essais-claude-cle.sh le lance sous pwsh (Linux), les appels propres à Windows remplacés au repère
# « ESSAIS » plus bas ; toute la logique est celle de ce fichier. Essayé aussi sur un vrai Windows 11 (PowerShell 5.1).
# Set-StrictMode, et Import-Module plus bas, appelés par leur type (.NET), sans recherche de nom : une fonction ou un
# alias du même nom, même au nom complet (Microsoft.PowerShell.Core\…), ou un module chargé nommé
# Microsoft.PowerShell.Core passerait devant, avant le contrôle de provenance (Provenance ; vu sur un vrai Windows).
# Le type n'est pas écrit en littéral ([Microsoft.PowerShell.Commands.…]) : un littéral de type est d'abord cherché
# dans la table des accélérateurs de la session, une recherche de nom elle aussi, qui pouvait donner à ce nom une
# autre applet de la même bibliothèque. Il est pris par son nom complet dans la bibliothèque du moteur de ce
# PowerShell ($ExecutionContext, une constante), relue comme dans Provenance (GAC ou dossier de ce PowerShell ; sous
# pwsh 7, rien ne fait tomber ce filet : il garde PowerShell 5.1) ; CmdletInfo aussi. Pas trouvé : refusé plus bas,
# avec les commandes étrangères. Limite, dite : du code déjà chargé dans la session (lancement autrement que par le
# .bat) peut encore détourner les autres littéraux de ce script ([IO.Path]…) ou les membres des objets (types
# étendus) ; c'est un programme de ce compte. Essayé sous pwsh 7 (Linux) ; sous PowerShell 5.1, à essayer sur un vrai
# Windows (GetType(nom, $true) et ::new y existent).
$Noyau = @{}
try {
    $Moteur = $ExecutionContext.GetType().Assembly
    if ($Moteur.Location -and ($Moteur.GlobalAssemblyCache -or
            $Moteur.Location.StartsWith($PSHOME + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase))) {
        $InfoApplet = $Moteur.GetType('System.Management.Automation.CmdletInfo', $true)
        foreach ($paire in @(@('Set-StrictMode', 'Microsoft.PowerShell.Commands.SetStrictModeCommand'),
                @('Import-Module', 'Microsoft.PowerShell.Commands.ImportModuleCommand'))) {
            $Noyau[$paire[0]] = $InfoApplet::new($paire[0], $Moteur.GetType($paire[1], $true))
        }
    }
} catch { $Noyau = @{} }
if ($Noyau['Set-StrictMode']) { & $Noyau['Set-StrictMode'] -Version 2 }
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }

# Rien que .NET avant le contrôle des commandes de PowerShell (plus bas, après le repère des essais).
$Ici = $PSScriptRoot                      # <clé>\Claude
$Cle = [IO.Path]::GetDirectoryName($Ici)  # <clé>
$Source = [IO.Path]::Combine($Ici, 'Windows', 'claude.exe')
$Signataire = 'Anthropic, PBC'
# Le sujet du certificat d'Anthropic (certificat « EV » : le numéro est celui de l'entreprise au registre du
# Delaware, il reste le même d'un certificat à l'autre ; ce registre est écrit dans le certificat, et exigé aussi).
# Chaque champ par son OID (en octets DER), présent une seule fois, avec cette valeur exacte. L'émetteur n'est pas
# fixé : Windows vérifie déjà la chaîne jusqu'à une racine.
$SujetAttendu = [ordered]@{
    '550403'                 = 'Anthropic, PBC'   # CN, nom commun
    '55040A'                 = 'Anthropic, PBC'   # O, organisation
    '550406'                 = 'US'               # C, pays
    '550405'                 = '4860621'          # serialNumber, numéro d'entreprise
    '2B0601040182373C020103' = 'US'               # jurisdictionC, pays du registre
    '2B0601040182373C020102' = 'Delaware'         # jurisdictionST, État du registre
}

function Dire([string]$fr, [string]$en) { Write-Host "  $fr"; if ($en) { Write-Host "  $en" -ForegroundColor DarkGray } }
function Arret([string]$fr, [string]$en) {
    Write-Host ''
    Write-Host "  ✖ $fr" -ForegroundColor Red
    if ($en) { Write-Host "    $en" -ForegroundColor DarkGray }
    exit 1
}
# Les champs du sujet d'un certificat lus un par un dans ses octets (DER), pas dans un texte rendu par Windows : une
# valeur qui porte un saut de ligne ne fabrique pas de faux champ. Rend des paires « OID=valeur » (OID en octets,
# hexadécimal) ; une structure inattendue, un type de texte inconnu ou un caractère de contrôle lève une erreur.
function LireTlv([byte[]]$o, [int]$i) {
    if ($i + 2 -gt $o.Length) { throw 'sujet tronqué' }
    $tag = [int]$o[$i]; $n = [int]$o[$i + 1]; $i += 2
    if ($n -ge 0x80) {
        $k = $n - 0x80
        if ($k -lt 1 -or $k -gt 3 -or $i + $k -gt $o.Length) { throw 'longueur illisible' }
        $n = 0
        for ($j = 0; $j -lt $k; $j++) { $n = $n * 256 + [int]$o[$i + $j] }
        $i += $k
    }
    if ($i + $n -gt $o.Length) { throw 'sujet tronqué' }
    , @($tag, $i, $n)
}
function ChampsDuSujet([byte[]]$o) {
    $nom = LireTlv $o 0
    if ($nom[0] -ne 0x30 -or $nom[1] + $nom[2] -ne $o.Length) { throw 'sujet illisible' }
    $champs = @()
    for ($i = $nom[1]; $i -lt $o.Length; $i = $ens[1] + $ens[2]) {
        $ens = LireTlv $o $i
        if ($ens[0] -ne 0x31) { throw 'sujet illisible' }
        for ($k = $ens[1]; $k -lt $ens[1] + $ens[2]; $k = $paire[1] + $paire[2]) {
            $paire = LireTlv $o $k
            $oid = LireTlv $o $paire[1]
            $val = LireTlv $o ($oid[1] + $oid[2])
            if ($paire[0] -ne 0x30 -or $oid[0] -ne 0x06 -or $val[1] + $val[2] -ne $paire[1] + $paire[2]) { throw 'sujet illisible' }
            # UTF8String, PrintableString, IA5String : les seuls attendus ici.
            if (@(0x0C, 0x13, 0x16) -notcontains $val[0]) { throw 'type de texte inattendu' }
            $texte = [Text.Encoding]::UTF8.GetString($o, $val[1], $val[2])
            if ($texte -match '[\x00-\x1F\x7F\u0080-\u009F\u2028\u2029]') { throw 'caractère de contrôle dans le sujet' }
            $champs += ([BitConverter]::ToString($o, $oid[1], $oid[2]) -replace '-', '') + '=' + $texte
        }
    }
    $champs
}
# Existe, même caché, même lien cassé (Test-Path dit non pour un lien qui ne mène nulle part).
function Existe([string]$chemin) { [bool](Get-Item -LiteralPath $chemin -Force -ErrorAction SilentlyContinue) }

# Déconnexion, délai borné (hors ligne, ou si la commande attendait une réponse : entrée fermée, arrêtée au bout de
# 20 s), depuis le dossier de travail de la session (ses journaux y sont nommés), puis effacement du dossier et des
# journaux de Claude Code à son nom (%LOCALAPPDATA%\claude-cli-nodejs\Cache\…vanguard-claude-…), relus ensuite.
# [IO.Directory]::Delete ne suit pas les jonctions : il retire le lien, jamais ce qui est au bout. Le même texte sert
# au gardien (plus bas) : une seule façon de nettoyer. Rend Efface (le dossier n'existe plus), JournauxLaisses (les
# journaux de la session encore là) et Deconnexion ('oui' : confirmée par le serveur ; 'non' : tentée sans cette
# preuve ; 'pas lancée' : claude.exe n'a pas pu être lancé ; '' : pas tentée).
# Lancé par .NET (ProcessStartInfo), pas par Start-Process : celui-ci lit les crochets d'un chemin ([, ]) comme des
# jokers, et un TEMP « a[1]b » empêchait la déconnexion.
# « auth logout » sort avec le code 0 même hors ligne (le jeton de ce PC est effacé, le serveur n'a rien révoqué). Une
# version récente le dit (« … didn't confirm the login was revoked », $revocation) ; une ancienne affiche le même succès
# dans les deux cas. 'oui' seulement sur preuve : code 0, le texte de succès, pas l'avertissement, et un binaire
# vérifié qui sait l'écrire ($sait : l'appelant a trouvé l'avertissement dans ses octets). Le gardien ne le passe
# pas : son résultat n'est jamais dit.
$TexteNettoyer = @'
# Les appels propres à Windows dont Nettoyer se sert (le gardien aussi) : les essais les remplacent au repère plus bas.
function SidDeMoi { [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
function CreerDossierPrive([string]$dossier, [string]$moi) {
    $sid = New-Object Security.Principal.SecurityIdentifier($moi)
    $droits = New-Object Security.AccessControl.DirectorySecurity
    $droits.SetAccessRuleProtection($true, $false)
    $droits.SetOwner($sid)
    $droits.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl',
                'ContainerInherit, ObjectInherit', 'None', 'Allow')))
    [void][IO.Directory]::CreateDirectory($dossier, $droits)
}
function ProprietaireDe([string]$dossier) { (Get-Acl -LiteralPath $dossier).GetOwner([Security.Principal.SecurityIdentifier]).Value }
function LancerCache([string]$exe, [string]$arguments, [string]$dossier) {
    $i = New-Object Diagnostics.ProcessStartInfo
    $i.FileName = $exe
    $i.Arguments = $arguments
    $i.WorkingDirectory = $dossier
    $i.UseShellExecute = $false
    $i.CreateNoWindow = $true
    $i.RedirectStandardInput = $true
    $i.RedirectStandardOutput = $true
    $i.RedirectStandardError = $true
    [Diagnostics.Process]::Start($i)
}
# Arrête claude.exe et ses enfants (taskkill /T /F, par le chemin que donne Windows, pas une variable), tant que le
# parent vit : un enfant d'un parent déjà fini n'est plus trouvé par taskkill. Puis Kill, si taskkill manque.
function ArreterArbre($p) {
    $tk = [IO.Path]::Combine([Environment]::GetFolderPath('System'), 'taskkill.exe')
    if ([IO.Path]::IsPathRooted($tk) -and [IO.File]::Exists($tk)) {
        try { $k = LancerCache $tk "/T /F /PID $($p.Id)" ([IO.Path]::GetDirectoryName($tk)) ; $k.StandardInput.Close() ; [void]$k.WaitForExit(5000) } catch { }
    }
    try { $p.Kill() } catch { }
}
function Nettoyer([string]$dossier, [string]$exe, [string]$travail, [bool]$sait = $false) {
    $deconnexion = ''
    $hors = ''
    if (-not [IO.Directory]::Exists($dossier)) { return [pscustomobject]@{ Efface = $true; JournauxLaisses = @(); Deconnexion = '' } }
    $config = [IO.Path]::Combine($dossier, 'config')
    if ($exe -and [IO.File]::Exists($exe) -and [IO.Directory]::Exists($config) -and $travail -and [IO.Directory]::Exists($travail)) {
        $deconnexion = 'non'
        $avant = $env:CLAUDE_CONFIG_DIR
        $env:CLAUDE_CONFIG_DIR = $config
        $p = $null
        # Le dossier courant hors de la session, à côté d'elle (…-fin, vide) : un enfant laissé vivant par la
        # déconnexion n'y garde rien d'ouvert, et la session s'efface quand même (vu sur un vrai Windows : travail\
        # restait). Son nom contient celui de la session : les journaux nommés d'après lui partent avec les siens ; plus
        # court que \travail, il tient sous les 200 caractères. Créé NEUF, privé et à soi (propriétaire posé, comme la
        # session : sous un jeton élevé, Windows le donnerait sinon aux Administrateurs, et le tri des restes le
        # sauterait ensuite pour toujours), puis relu : déjà là (posé par un autre, ou laissé), lien ou jonction, pas
        # vide, pas à soi : pas pris, travail\ comme avant. Resté (l'enfant y est encore) : vide, effacé au lancement
        # suivant avec les restes (vanguard-claude-*).
        $hors = $travail
        $fin = $dossier + '-fin'
        try {
            if (-not [IO.Directory]::Exists($fin) -and -not [IO.File]::Exists($fin)) {
                $moi = SidDeMoi
                CreerDossierPrive $fin $moi
                $vu = New-Object IO.DirectoryInfo($fin)
                if (-not ($vu.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
                    @([IO.Directory]::GetFileSystemEntries($fin)).Count -eq 0 -and (ProprietaireDe $fin) -eq $moi) {
                    $hors = $fin
                }
            }
        } catch { }
        try { $p = LancerCache $exe 'auth logout' $hors } catch { $deconnexion = 'pas lancée' }
        if ($p) { try {
            $p.StandardInput.Close()   # une question attendrait une réponse qui ne vient jamais
            # Lues en même temps : un tuyau plein bloquerait claude.exe.
            $sortie = $p.StandardOutput.ReadToEndAsync()
            $erreurs = $p.StandardError.ReadToEndAsync()
            # Les lectures bornées elles aussi : un enfant laissé par la déconnexion garderait les tuyaux ouverts, et
            # .Result attendrait sans fin (dossier de session et jeton pas effacés). Pas finies : pas confirmée.
            if ($p.WaitForExit(20000) -and [Threading.Tasks.Task]::WaitAll(@($sortie, $erreurs), 5000)) {
                $dit = $sortie.Result + $erreurs.Result
                if ($p.ExitCode -eq 0 -and $sait -and
                    $dit.Contains('Successfully logged out from your Anthropic account.') -and
                    -not $dit.Contains("didn't confirm the login was revoked")) {
                    $deconnexion = 'oui'
                }
            }
            else { ArreterArbre $p ; Start-Sleep -Seconds 1 }
        } catch { } }
        $env:CLAUDE_CONFIG_DIR = $avant
    }
    $local = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { [Environment]::GetFolderPath('LocalApplicationData') }
    $journaux = [IO.Path]::Combine($local, 'claude-cli-nodejs', 'Cache')
    $nom = [IO.Path]::GetFileName($dossier)
    $laisses = @()
    if ($nom -and [IO.Directory]::Exists($journaux)) {
        # Repris quelques fois (un fichier encore ouvert), puis relus : ce qui reste est rendu, pas tu.
        for ($i = 0; $i -lt 5; $i++) {
            try {
                foreach ($j in [IO.Directory]::GetDirectories($journaux, "*$nom*")) { try { [IO.Directory]::Delete($j, $true) } catch { } }
                $laisses = @([IO.Directory]::GetDirectories($journaux, "*$nom*"))
            } catch { $laisses = @([IO.Path]::Combine($journaux, "*$nom*")) }
            if ($laisses.Count -eq 0) { break }
            Start-Sleep -Seconds 1
        }
        # Vides, ils ne servaient qu'à cette session ; sinon gardés (Claude Code est peut-être installé ici).
        foreach ($v in $journaux, [IO.Path]::GetDirectoryName($journaux)) { try { [IO.Directory]::Delete($v, $false) } catch { } }
    }
    for ($i = 0; $i -lt 15; $i++) {
        try { [IO.Directory]::Delete($dossier, $true); break } catch { Start-Sleep -Seconds 1 }
    }
    # Seulement s'il a servi : un …-fin pas pris (déjà là, lien, pas à soi) n'est pas touché ici.
    if ($hors -eq $dossier + '-fin') { try { [IO.Directory]::Delete($hors, $false) } catch { } }
    [pscustomobject]@{ Efface = -not [IO.Directory]::Exists($dossier); JournauxLaisses = $laisses; Deconnexion = $deconnexion }
}
'@
. ([ScriptBlock]::Create($TexteNettoyer))

# Les appels propres à Windows, chacun dans sa fonction : les essais (sous Linux) les remplacent au repère plus bas.
function FormatDuVolume([string]$dossier) { (New-Object IO.DriveInfo([IO.Path]::GetPathRoot($dossier))).DriveFormat }
function TypeDuVolume([string]$dossier) { [string](New-Object IO.DriveInfo([IO.Path]::GetPathRoot($dossier))).DriveType }
function DroitsDuDossier([string]$dossier) {
    $acl = Get-Acl -LiteralPath $dossier
    $type = [Security.Principal.SecurityIdentifier]
    [pscustomobject]@{
        Protege      = $acl.AreAccessRulesProtected
        Proprietaire = $acl.GetOwner($type).Value
        Regles       = @($acl.GetAccessRules($true, $true, $type) | ForEach-Object {
                [pscustomobject]@{ Sid = $_.IdentityReference.Value; Type = "$($_.AccessControlType)" } })
    }
}
function SignatureDe([string]$exe) {
    $s = Get-AuthenticodeSignature -LiteralPath $exe
    [pscustomobject]@{ Statut = "$($s.Status)"; Certificat = $s.SignerCertificate }
}
# Réglages imposés à tout l'ordinateur (administrateur, entreprise, ou programme malveillant) : Claude Code lit
# « C:\Program Files\ClaudeCode », écrit en dur, quel que soit le Program Files de ce PowerShell (32 bits : (x86)).
function DossiersGeres {
    $racines = @([Environment]::GetFolderPath('ProgramFiles'), 'C:\Program Files', $env:ProgramW6432,
        [Environment]::GetFolderPath('CommonApplicationData')) | Where-Object { $_ } | Select-Object -Unique
    @($racines | ForEach-Object { Join-Path $_ 'ClaudeCode' }) + 'HKLM:\SOFTWARE\Policies\ClaudeCode', 'HKCU:\SOFTWARE\Policies\ClaudeCode'
}
function LancerGardien([string]$code64) {
    # PowerShell de Windows par l'API, jamais par une variable d'environnement qu'on pourrait avoir changée.
    $ps = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    Start-Process -FilePath $ps -WindowStyle Hidden -PassThru -ArgumentList '-NoProfile', '-NonInteractive',
        '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-EncodedCommand', $code64
}
# Le texte d'une révocation pas confirmée (voir Nettoyer) : cherché dans les octets de claude.exe vérifié.
$RevocationDite = "didn't confirm the login was revoked"
# SHA-256 par .NET : sous PowerShell 5.1, Get-FileHash est une fonction de module, pas une applet de Windows.
function EmpreinteDe([string]$chemin) {
    $f = [IO.File]::OpenRead($chemin)
    $h = [Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($h.ComputeHash($f)) -replace '-', '').ToLowerInvariant() } finally { $h.Dispose(); $f.Dispose() }
}
function ContientTexte([string]$chemin, [string]$texte) {
    $latin = [Text.Encoding]::GetEncoding(28591)   # un octet, un caractère : rien n'est perdu ni fusionné
    $f = [IO.File]::OpenRead($chemin)
    try {
        $tampon = New-Object byte[] (16MB)
        $reste = ''
        while (($n = $f.Read($tampon, 0, $tampon.Length)) -gt 0) {
            $bloc = $reste + $latin.GetString($tampon, 0, $n)
            if ($bloc.IndexOf($texte, [StringComparison]::Ordinal) -ge 0) { return $true }
            # La fin du bloc, pour un texte à cheval sur deux lectures.
            $reste = $bloc.Substring([Math]::Max(0, $bloc.Length - $texte.Length + 1))
        }
        $false
    } finally { $f.Dispose() }
}
# Les commandes de PowerShell dont ce script et son gardien se servent : toutes doivent venir de Windows (voir plus
# bas). Un essai (outils/essais-claude-cle.sh) vérifie que la liste n'en oublie aucune.
$Commandes = @('ConvertFrom-Json', 'Copy-Item', 'ForEach-Object', 'Get-ChildItem', 'Get-Content', 'Get-Item',
    'Get-Process', 'Import-Module', 'Join-Path', 'New-Object', 'Pop-Location', 'Push-Location', 'Read-Host',
    'Remove-Item', 'Select-Object', 'Set-StrictMode', 'Start-Process', 'Start-Sleep', 'Stop-Process', 'Test-Path',
    'Wait-Process', 'Where-Object', 'Write-Host')
# Propres à Windows (absentes de PowerShell sous Linux : les essais vident cette liste, leurs appels ont des doublures).
$CommandesWindows = @('Get-Acl', 'Get-AuthenticodeSignature')
# Une commande de Windows : une applet (cmdlet ; pas une fonction ni un alias, qui passeraient devant elle) tirée d'une
# bibliothèque de Windows (le GAC, où seul un administrateur installe ; ou le dossier de ce PowerShell). Le moteur de
# PowerShell dit lui-même ce qui serait lancé sous ce nom ($ExecutionContext : aucune fonction ne le remplace).
function Provenance([string]$n) {
    $c = $ExecutionContext.InvokeCommand.GetCommand($n, [Management.Automation.CommandTypes]::All)
    if (-not $c) { return 'introuvable' }
    if ($c.CommandType -ne [Management.Automation.CommandTypes]::Cmdlet) { return "$($c.CommandType) $($c.Source)".Trim() }
    $a = $c.ImplementingType.Assembly
    # Une bibliothèque chargée en mémoire (Add-Type, Import-Module -Assembly) n'a pas d'emplacement : jamais de Windows.
    if (-not $a.Location) { return 'bibliothèque en mémoire' }
    if ($a.GlobalAssemblyCache -or $a.Location.StartsWith($PSHOME + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { return '' }
    "bibliothèque $($a.Location)"
}
# ESSAIS : les doublures des fonctions ci-dessus sont posées ici.

# Les modules de PowerShell : ceux de Windows seulement. Un dossier de modules que le compte peut écrire (variable
# PSModulePath de l'utilisateur, Documents\WindowsPowerShell\Modules), lu avant celui de Windows, ferait prendre son
# Get-AuthenticodeSignature ou son Get-Acl : il dirait « signé par Anthropic » pour un claude.exe changé (essayé sur un
# vrai Windows). « Depanner avec Claude.bat » fixe déjà PSModulePath ; ici aussi, si ce script est lancé autrement,
# puis les modules de Windows importés par leur chemin complet, plus aucun module chargé de lui-même, et chaque
# commande relue (Provenance). Le gardien hérite de ce PSModulePath. Une seule différence : refusé, avant la question.
$ModulesWindows = [IO.Path]::Combine($PSHOME, 'Modules')
$env:PSModulePath = $ModulesWindows
foreach ($m in 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Security') {
    try { & $Noyau['Import-Module'] -Name ([IO.Path]::Combine($ModulesWindows, $m, "$m.psd1")) -ErrorAction Stop } catch { }
}
$PSModuleAutoLoadingPreference = 'None'
$etrangeres = @()
foreach ($n in 'Set-StrictMode', 'Import-Module') { if (-not $Noyau[$n]) { $etrangeres += "$n (pas l'applet de ce PowerShell)" } }
foreach ($n in $Commandes + $CommandesWindows) {
    $d = Provenance $n
    if ($d) { $etrangeres += "$n ($d)" }
}
if ($etrangeres.Count -gt 0) {
    # Sans Write-Host : c'est peut-être une de ces commandes.
    [Console]::WriteLine('')
    [Console]::WriteLine("  ✖ Des commandes de PowerShell manquent ou ne viennent pas de Windows : $($etrangeres -join ', '). Un module de ce compte peut les remplacer : la vérification de Claude Code ne serait plus celle de Windows. Rien n'a été lancé.")
    [Console]::WriteLine('    Some PowerShell commands are missing or do not come from Windows (a module of this account may replace them). Nothing was started.')
    exit 1
}

Write-Host ''
Write-Host '  Dépanner avec Claude (Vanguard)' -ForegroundColor Red
Write-Host '  Troubleshoot with Claude (Vanguard)' -ForegroundColor DarkGray
Write-Host ''
Dire 'Claude Code, l''assistant d''Anthropic, va lire cet ordinateur pour trouver la panne. Ce qu''il lit (journaux,' `
     'Claude Code, Anthropic''s assistant, will read this computer to find the problem. What it reads (logs,'
Dire 'réglages, noms de fichiers) part chez Anthropic pour être analysé. Il demande avant toute commande qui change' `
     'settings, file names) is sent to Anthropic for analysis. It asks before any command that changes something;'
Dire 'quelque chose ; certaines commandes de simple lecture passent sans demander, et ce qu''elles montrent part aussi' `
     'some read-only commands run without asking, and what they show is sent to Anthropic too.'
Dire 'chez Anthropic. Il faut un compte Claude (abonnement Pro ou Max, ou console Anthropic).' `
     'A Claude account is needed (Pro or Max plan, or Anthropic Console).'
Dire 'Connexion : sur VOTRE téléphone, jamais dans le navigateur de cet ordinateur (il garderait votre compte).' `
     'Sign in on YOUR phone, never in this computer''s browser (it would keep your account signed in).'
Write-Host ''
# Oui seulement par « o », « oui », « y » ou « yes » (-match ignore la casse) : « ok non » ne vaut pas accord.
$r = Read-Host '  Le propriétaire de cet ordinateur est d''accord ? / Does the owner of this computer agree? [o/y/N]'
if ("$r".Trim() -notmatch '^(o|oui|y|yes)$') { Write-Host '  Rien n''a été lancé. / Nothing was started.'; exit 0 }

# L'environnement de Claude, et du gardien qui en hérite : celui de l'ordinateur visité ne choisit ni le serveur, ni
# le compte, ni les certificats que Claude Code sait lire par variable, ni le mandataire, ni le traçage, ni le code
# chargé par un shell (BASH_ENV, ENV), ni ses réglages (XDG_CONFIG_HOME). Retiré d'abord, avant toute commande de
# Claude Code (même la déconnexion des restes d'une session). La même liste que le lanceur Linux, plus XDG_CONFIG_HOME.
Get-ChildItem Env: | Where-Object {
    $_.Name -match '^(ANTHROPIC_|CLAUDE_|NODE_|BUN_|SSL_CERT_|AWS_|GOOGLE_|VERTEX_|OTEL_|GIT_|ANT_|CCR_|AZURE_)' -or
    $_.Name -match '^((HTTPS?|ALL|NO|GRPC)_PROXY|REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE|BROWSER|SESSION_INGRESS_URL|ENABLE_CLAUDEAI_MCP_SERVERS)$' -or
    $_.Name -match '^(BASH_ENV|ENV|XDG_CONFIG_HOME|SSLKEYLOGFILE|GRPC_DEFAULT_SSL_ROOTS_FILE_PATH|NIX_SSL_CERT_FILE|DENO_CERT|PIP_CERT)$' -or
    $_.Name -match '^(CARGO_HTTP_CAINFO|HTTPLIB2_CA_CERTS|CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE|HEX_CACERTS_PATH|ENABLE_BETA_TRACING_DETAILED)$' -or
    $_.Name -match '^(ENABLE_ENHANCED_TELEMETRY_BETA|BETA_TRACING_ENDPOINT|VOICE_STREAM_BASE_URL|MCP_CLIENT_SECRET|AGENT_PROXY_URL)$' -or
    $_.Name -match '^(USE_LOCAL_OAUTH|USE_STAGING_OAUTH|CLOUD_ML_REGION)$'
} | ForEach-Object { Remove-Item -LiteralPath "Env:$($_.Name)" }

if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
    Arret 'Claude Code n''est pas sur cette clé (Claude\Windows\claude.exe).' 'Claude Code is not on this key.'
}
$TempPc = $env:TEMP
# Un TEMP vers un serveur absent fait lever une erreur à Test-Path : refusé avec le même message, pas l'erreur brute.
$tempVu = try { $TempPc -and (Test-Path -LiteralPath $TempPc -PathType Container) } catch { $false }
if (-not $tempVu) {
    Arret 'Dossier temporaire de Windows introuvable (TEMP).' 'Windows temporary folder not found (TEMP).'
}
$Moi = SidDeMoi
# Combine, pas Join-Path : même résultat, et un TEMP réseau (\\serveur\partage) arrive jusqu'à son refus ci-dessous.
$Dossier = [IO.Path]::Combine($TempPc, 'vanguard-claude-' + [Guid]::NewGuid().ToString('N'))
$Exe = [IO.Path]::Combine($Dossier, 'claude.exe')
$Travail = [IO.Path]::Combine($Dossier, 'travail')
$Config = [IO.Path]::Combine($Dossier, 'config')
$Tmp = [IO.Path]::Combine($Dossier, 'tmp')
# Claude Code nomme ses journaux d'après le dossier de travail, chaque signe hors lettres et chiffres devenu « - »
# (lu dans claude.exe 2.1.311) ; au-delà de 200 caractères, il coupe le nom et y ajoute une empreinte : le nom de la
# session n'y serait plus en entier, et ses journaux resteraient sur cet ordinateur sans qu'on les trouve. Refusé
# avant de rien créer (TEMP de plus de 140 caractères environ ; le TEMP habituel en fait une quarantaine).
if (($Travail -replace '[^a-zA-Z0-9]', '-').Length -gt 200) {
    Arret "Le chemin du dossier temporaire (TEMP) est trop long ($($TempPc.Length) caractères) : les journaux de Claude Code ne pourraient pas être effacés. Rien n'a été lancé." `
          "The temporary folder path (TEMP) is too long: Claude Code's logs could not be erased. Nothing was started."
}
# Sans droits Windows (FAT, exFAT, partage réseau), « à soi seul » ne voudrait rien dire : refusé avant de créer.
# Un lecteur réseau monté sur une lettre rend souvent « NTFS » : seul un disque local (Fixed) est permis.
$format = try { FormatDuVolume $Dossier } catch { '' }
$type = try { TypeDuVolume $Dossier } catch { '' }
if ($Dossier.StartsWith('\\') -or @('NTFS', 'ReFS') -notcontains $format -or $type -ne 'Fixed') {
    Arret "Le dossier temporaire (TEMP) est sur un disque sans droits Windows ($format, $type) : il ne serait pas à vous seul. Rien n'a été lancé." `
          "The temporary folder (TEMP) is on a drive without Windows permissions: it would not be yours alone. Nothing was started."
}
$Session = $null
$Laisses = New-Object Collections.Generic.List[string]   # les restes d'avant qui n'ont pas pu être effacés
$Lance = $false
$Revocation = $false
$code = 0
# Un seul try/finally de la création du dossier à la fin : un refus, une erreur ou Ctrl+C l'efface toujours.
try {
    # Dossier à soi, au nom imprévisible, créé d'emblée avec des droits pour l'utilisateur seul (héritage coupé), puis
    # relu : propriétaire moi, héritage coupé, une seule sorte de règle (moi, autorisé). Sinon, refusé.
    CreerDossierPrive $Dossier $Moi
    $droits = DroitsDuDossier $Dossier
    $autres = @($droits.Regles | Where-Object { $_.Sid -ne $Moi -or $_.Type -ne 'Allow' })
    if (-not $droits.Protege -or $droits.Proprietaire -ne $Moi -or $autres.Count -gt 0 -or @($droits.Regles).Count -eq 0) {
        Arret 'Le dossier temporaire n''a pas pu être réservé à vous seul (droits Windows). Rien n''a été lancé.' `
              'The temporary folder could not be made yours alone (Windows permissions). Nothing was started.'
    }
    # Tenu ouvert sans partage pendant toute la session : un second lancement ne prend pas ce dossier pour des restes.
    $Session = [IO.File]::Open((Join-Path $Dossier '.session'), 'CreateNew', 'ReadWrite', 'None')
    foreach ($d in $Travail, $Config, $Tmp) { [void][IO.Directory]::CreateDirectory($d) }
    # L'environnement de Claude Code, posé avant sa première commande (même la déconnexion des restes) :
    # - pas de mise à jour, pas de trafic non essentiel, pas de connecteurs du compte (ENABLE_CLAUDEAI_MCP_SERVERS=0,
    #   et --strict-mcp-config au lancement), pas de journal des serveurs MCP ;
    # - BROWSER vers un fichier qui n'existe pas : le navigateur de ce PC ne s'ouvre jamais sur la page de connexion
    #   (l'adresse s'affiche, à ouvrir sur le téléphone) ;
    # - ANTHROPIC_CONFIG_DIR vers un dossier vide de la session : un profil Anthropic du PC (%APPDATA%\Anthropic) ne
    #   choisit ni le compte ni le serveur ; Claude Code le cherche là d'abord.
    $env:CLAUDE_CONFIG_DIR = $Config
    $env:ANTHROPIC_CONFIG_DIR = Join-Path $Dossier 'anthropic'
    $env:DISABLE_AUTOUPDATER = '1'
    $env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = '1'
    $env:ENABLE_CLAUDEAI_MCP_SERVERS = '0'
    $env:CLAUDE_CODE_SKIP_MCP_DEBUG_LOG_FILES = '1'
    $env:BROWSER = Join-Path $Dossier 'pas-de-navigateur.exe'
    $env:VANGUARD_CLE = $Cle
    $env:TEMP = $Tmp
    $env:TMP = $Tmp

    # Réglages imposés par l'ordinateur, quels qu'ils soient (fichiers, skills, stratégies du registre) : ils
    # passeraient avant les nôtres. Refusé, avant toute commande de Claude Code.
    foreach ($f in DossiersGeres) {
        if (Existe $f) {
            Arret "$f existe : cet ordinateur impose ses réglages à Claude Code. Rien n'a été lancé." `
                  "$f exists: this computer imposes its settings on Claude Code. Nothing was started."
        }
    }
    # Claude Code lit aussi, au-dessus du dossier de travail, les consignes (CLAUDE.md, AGENTS.md), les serveurs MCP
    # (.mcp.json) et les dossiers .claude (consignes, skills, commandes, agents) : posés là par quelqu'un d'autre, ce
    # seraient des consignes. Cette boucle remonte le chemin écrit ; Claude Code fait pareil dans son binaire Linux,
    # pas vérifié dans claude.exe (une jonction ou un lecteur subst pourrait y être suivi vers son vrai dossier). Le
    # dossier personnel est l'exception pour .claude : Claude Code n'y cherche pas de skills, et le refuser bloquerait
    # tout PC où l'on se sert déjà de Claude Code ; ses consignes y sont refusées quand même.
    # Limite, dite : un compte sans droits peut créer C:\.claude après cette vérification ; seul un dossier refait à
    # chaque lancement le verrait. GetDirectoryName rend $null à la racine (C:\), sans erreur.
    $maison = [Environment]::GetFolderPath('UserProfile')
    # Vu depuis le dossier personnel, le chemin jusqu'au dossier de session ne passe par aucun lien ni jonction : sinon
    # un Temp déplacé par jonction (<profil>\AppData\Local\Temp -> D:\x\AppData\Local\Temp) ferait prendre D:\x pour le
    # dossier personnel. En cas de doute (illisible), pas d'exception.
    function SansLien([string]$racine, [string]$suite) {
        $c = $racine
        foreach ($morceau in ($suite -split '[\\/]' | Where-Object { $_ })) {
            $c = Join-Path $c $morceau
            try { if ([IO.File]::GetAttributes($c) -band [IO.FileAttributes]::ReparsePoint) { return $false } } catch { return $false }
        }
        $true
    }
    for ($d = [IO.Path]::GetDirectoryName($Dossier); $d; $d = [IO.Path]::GetDirectoryName($d)) {
        $noms = @('CLAUDE.md', 'CLAUDE.local.md', 'AGENTS.md', '.mcp.json')
        # Les deux façons de connaître le dossier personnel doivent tomber d'accord : sinon, pas d'exception. Comparé
        # par le dossier lui-même, pas par son nom : le dossier de session (nom unique) doit se voir par les deux. Un
        # TEMP en nom court 8.3, une autre casse ou une jonction gardent ainsi l'exception.
        $suite = $Dossier.Substring($d.Length).TrimStart('\', '/')
        if ($env:USERPROFILE -and $maison -and [IO.Directory]::Exists((Join-Path $env:USERPROFILE $suite)) -and
            [IO.Directory]::Exists((Join-Path $maison $suite)) -and (SansLien $env:USERPROFILE $suite) -and (SansLien $maison $suite)) {
            $noms += '.claude/CLAUDE.md', '.claude/AGENTS.md', '.claude/rules'
        } else { $noms += '.claude' }
        foreach ($nom in $noms) {
            $f = Join-Path $d ($nom -replace '/', [IO.Path]::DirectorySeparatorChar)
            if (Existe $f) {
                Arret "$f existe : Claude le lirait comme une consigne. Rien n'a été lancé." `
                      "$f exists: Claude would read it as an instruction. Nothing was started."
            }
        }
    }

    Write-Host ''
    Dire 'Copie et vérification de Claude Code…' 'Copying and checking Claude Code…'
    try {
        Copy-Item -LiteralPath $Source -Destination $Exe
        # 1. Signature Authenticode : valide (chaîne jusqu'à une racine de Windows, fichier intact), signataire
        # Anthropic : nom, organisation, pays et numéro d'entreprise du certificat.
        $sig = SignatureDe $Exe
        $sujet = @()
        $nom = ''
        if ($sig.Certificat) {
            $sujet = @(ChampsDuSujet $sig.Certificat.SubjectName.RawData)
            $nom = $sig.Certificat.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        }
        # Chaque champ attendu : une seule fois dans le sujet, et avec la bonne valeur.
        $manque = @($SujetAttendu.Keys | Where-Object {
                $o = $_
                $vus = @($sujet | Where-Object { $_.StartsWith("$o=", [StringComparison]::Ordinal) })
                # Octet par octet (Ordinal) : -cne compare selon la langue et ignore U+200B ou U+00AD (invisibles).
                $vus.Count -ne 1 -or -not [string]::Equals($vus[0], "$o=$($SujetAttendu[$o])", [StringComparison]::Ordinal)
            })
        # Le message dit la vraie raison : un fichier changé garde le nom de son signataire, qui ne prouve plus rien.
        if ($sig.Statut -eq 'HashMismatch') { throw [Exception]::new('le fichier a été changé après sa signature') }
        if ($sig.Statut -ne 'Valid') { throw [Exception]::new("signature : $($sig.Statut)") }
        if (-not [string]::Equals($nom, $Signataire, [StringComparison]::Ordinal)) { throw [Exception]::new("signataire : « $nom » (attendu : « $Signataire »)") }
        if ($manque.Count -gt 0) { throw [Exception]::new("certificat « $nom » qui n'est pas celui d'Anthropic (champs : $($manque -join ', '))") }
        # 2. Empreinte égale à celle du manifeste posé sur la clé : attrape une copie abîmée en route. Ce manifeste
        # n'est pas authentifié ici (pas de gpg sous Windows) : un autre claude.exe signé par Anthropic avec un
        # manifeste retouché passerait. Une clé qui a quitté vos mains repasse par Vanguard (LISEZMOI, Limites).
        $manifeste = Get-Content -LiteralPath (Join-Path $Ici 'manifest.json') -Raw | ConvertFrom-Json
        $vu = EmpreinteDe $Exe
        if ($vu -ne $manifeste.platforms.'win32-x64'.checksum) { throw [Exception]::new('empreinte différente du manifeste de la clé') }
        # La version lue dans le programme signé, pas dans le manifeste qui ne l'est pas ici.
        $Version = (Get-Item -LiteralPath $Exe).VersionInfo.ProductVersion
        # Ces octets vérifiés savent-ils dire une révocation pas confirmée ? Sinon, aucune déconnexion n'est « confirmée ».
        $Revocation = ContientTexte $Exe $RevocationDite
    } catch {
        Arret "Claude Code refusé ($($_.Exception.Message)). Rien n'a été lancé : la copie de la clé est peut-être abîmée ou remplacée ; mettez la clé à jour avec Vanguard." `
              'Claude Code refused. Nothing was started: the copy on the key may be damaged or replaced. Update the key with Vanguard.'
    }
    Dire "✔ Claude Code $Version, signé par $Signataire." "✔ Claude Code $Version, signed by $Signataire."

    # Sans ses consignes, Claude dépannerait sans les règles (lecture seule, accord, sécurité jamais baissée) : refusé.
    $consignes = Join-Path $Travail 'CLAUDE.md'
    try {
        Copy-Item -LiteralPath (Join-Path $Ici 'CLAUDE.md') -Destination $consignes
        if ((Get-Item -LiteralPath $consignes).Length -eq 0 -or
            (EmpreinteDe $consignes) -ne (EmpreinteDe (Join-Path $Ici 'CLAUDE.md'))) {
            throw [Exception]::new('copie différente')
        }
    } catch {
        Arret 'Consignes de dépannage (Claude\CLAUDE.md) absentes ou illisibles : rien n''a été lancé.' `
              'Troubleshooting instructions (Claude\CLAUDE.md) missing or unreadable: nothing was started.'
    }

    # Ce qu'une session d'avant a laissé (ordinateur éteint en pleine session) : déconnecté et effacé avec la copie
    # qui vient d'être vérifiée. Seulement un vrai dossier (pas une jonction), à cet utilisateur, sans session en cours.
    Get-ChildItem -LiteralPath $TempPc -Directory -Filter 'vanguard-claude-*' -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -ne $Dossier -and -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } |
        ForEach-Object {
            $d = $_.FullName
            try { if ((ProprietaireDe $d) -ne $Moi) { return } } catch { return }
            $verrou = Join-Path $d '.session'
            if ([IO.File]::Exists($verrou)) {
                try { ([IO.File]::Open($verrou, 'Open', 'ReadWrite', 'None')).Dispose() } catch { return }
            }
            $n = Nettoyer $d $Exe $Travail $Revocation
            if ($n.Efface -and $n.JournauxLaisses.Count -eq 0) {
                Dire 'Restes d''une session précédente effacés.' 'Leftovers of a previous session erased.'
            } else {
                $Laisses.Add($d)
                Dire "⚠ Restes d'une session précédente PAS effacés en entier : $d (un fichier encore ouvert ?)." `
                     "⚠ Leftovers of a previous session NOT fully erased: $d (a file still open?)."
            }
            if ($n.Deconnexion -eq 'non' -or $n.Deconnexion -eq 'pas lancée') {
                Dire '⚠ Sa déconnexion n''est PAS confirmée : fermez cette session sur claude.ai.' `
                     '⚠ Its logout is NOT confirmed: end that session on claude.ai.'
            }
        }

    # Le gardien : un PowerShell de Windows caché, détaché de cette fenêtre, qui attend la fin de ce script (sortie
    # normale, Ctrl+C, ou fenêtre fermée par sa croix), puis celle de claude.exe, et nettoie. Lancé seulement une fois
    # claude.exe vérifié : il ne lance jamais un binaire non vérifié. Ses chemins n'entrent jamais dans son code tels
    # quels : PowerShell ferme aussi une chaîne sur une apostrophe courbe (’ ‘ ‚ ‛), qu'un nom de compte peut porter, et
    # le reste du nom serait lu comme du code. Ils y sont en base64 (lettres, chiffres, + / =), décodés par le gardien,
    # et le tout passé en -EncodedCommand : aucun guillemet de la ligne de commande à casser. Il ne lit que les
    # processus nommés claude (lire le chemin de tous prenait plus d'une seconde par tour sur un vrai Windows).
    function EnBase64([string]$s) { [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($s)) }
    # Un saut de ligne entre les deux : une chaîne @' '@ finit sans, et « }$dossier = » ne se lirait pas.
    $gardien = $TexteNettoyer + "`r`n" + @"
function Texte([string]`$b) { [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(`$b)) }
`$dossier = Texte '$(EnBase64 $Dossier)'; `$exe = Texte '$(EnBase64 $Exe)'; `$travail = Texte '$(EnBase64 $Travail)'
try { Wait-Process -Id $PID -ErrorAction SilentlyContinue } catch { }
function Claude { Get-Process -Name claude -ErrorAction SilentlyContinue | Where-Object { try { `$_.Path -eq `$exe } catch { `$false } } }
for (`$i = 0; `$i -lt 30 -and (Claude); `$i++) { Start-Sleep -Seconds 1 }
Claude | Stop-Process -Force -ErrorAction SilentlyContinue
[void](Nettoyer `$dossier `$exe `$travail)
"@
    try {
        $g = LancerGardien ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($gardien)))
        # Arrêté tout de suite (bloqué par une stratégie, langage restreint) : il ne gardera rien.
        Start-Sleep -Seconds 1
        if (-not $g -or $g.HasExited) { throw [Exception]::new('gardien arrêté') }
    } catch {
        Dire '⚠ Gardien pas lancé : fermez Claude par /exit, jamais par la croix.' '⚠ Guard not started: close Claude with /exit, never with the X.'
    }

    Write-Host ''
    Dire 'Pour finir : tapez /exit dans Claude. Après un ordinateur douteux : fermez aussi la session sur claude.ai.' `
         'To finish: type /exit in Claude. After a doubtful computer: also end the session on claude.ai.'
    Dire 'Connecté dans le navigateur de cet ordinateur par erreur : déconnectez-vous de claude.ai avant de partir.' `
         'Signed in in this computer''s browser by mistake: sign out of claude.ai before leaving.'
    Write-Host ''
    $Lance = $true
    Push-Location -LiteralPath $Travail
    try {
        & $Exe '--strict-mcp-config'
        $code = $LASTEXITCODE
    } finally {
        Pop-Location
    }
} finally {
    if ($Session) { $Session.Dispose() }
    $n = Nettoyer $Dossier $(if ($Lance) { $Exe } else { '' }) $Travail $Revocation
    if ($Lance) {
        Write-Host ''
        if ($n.Deconnexion -eq 'pas lancée') {
            Dire '⚠ La déconnexion n''a PAS pu être lancée : fermez la session sur claude.ai.' `
                 '⚠ The logout could NOT be started: end the session on claude.ai.'
        } elseif ($n.Deconnexion -ne 'oui') {
            Dire '⚠ Déconnexion NON confirmée par Anthropic (hors ligne, ou version qui ne le dit pas) : fermez la session sur claude.ai.' `
                 '⚠ Logout NOT confirmed by Anthropic (offline, or a version that does not tell): end the session on claude.ai.'
        }
        if ($n.Efface -and @($n.JournauxLaisses).Count -gt 0) {
            Dire '⚠ PAS tout effacé : un journal de Claude Code de cette session est resté (ci-dessous).' `
                 '⚠ NOT everything was erased: a Claude Code log of this session remains (below).'
        } elseif (-not $n.Efface) {
            Dire "✖ $Dossier n'a pas pu être effacé (Claude tourne encore ?). Le gardien réessaie ; sinon, relancez « Depanner avec Claude »." `
                 "✖ Could not erase $Dossier (Claude still running?). The guard retries; otherwise run « Depanner avec Claude » again."
        } elseif ($n.Deconnexion -eq 'oui') {
            Dire '✔ Déconnecté ; Claude Code, la connexion et la conversation sont effacés de cet ordinateur.' `
                 '✔ Logged out; Claude Code, the sign-in and the conversation are erased from this computer.'
        } else {
            Dire 'Claude Code, la connexion et la conversation sont effacés de cet ordinateur.' `
                 'Claude Code, the sign-in and the conversation are erased from this computer.'
        }
        foreach ($l in $n.JournauxLaisses) {
            Dire "⚠ Journal de Claude Code de cette session PAS effacé : $l (un fichier encore ouvert ?) ; à effacer à la main." `
                 "⚠ Claude Code log of this session NOT erased: $l (a file still open?); erase it by hand."
        }
        foreach ($l in @($Laisses | Where-Object { [IO.Directory]::Exists($_) })) {
            Dire "⚠ Toujours là, d'une session précédente : $l ; relancez plus tard, ou effacez-le à la main." `
                 "⚠ Still here, from a previous session: $l; run again later, or erase it by hand."
        }
        Write-Host ''
    } elseif (-not $n.Efface) {
        Dire "✖ $Dossier n'a pas pu être effacé : à effacer à la main." "✖ Could not erase $Dossier."
    }
}
exit $code

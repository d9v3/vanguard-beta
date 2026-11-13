# Dépanner avec Claude : lance Claude Code depuis la clé VANGUARD sur l'ordinateur d'un proche (« Depanner avec
# Claude.bat », à la racine de la clé, appelle ce script et garde la fenêtre ouverte à la fin). Mode d'emploi :
# LISEZMOI.txt, à côté. Troubleshoot with Claude: runs Claude Code from the VANGUARD key. See README.txt.
#
# - Rien n'est installé : claude.exe est copié dans un dossier temporaire à soi (%TEMP%\vanguard-claude-…, créé avec
#   des droits pour l'utilisateur seul), vérifié là (signature Authenticode valide, signataire « Anthropic, PBC » ;
#   empreinte égale à celle du manifeste de la clé), puis lancé de là. La copie vérifiée est celle qui est lancée.
# - Le jeton de connexion à Claude et la conversation restent dans ce dossier (CLAUDE_CONFIG_DIR), jamais sur la clé
#   ni dans le profil du proche. En sortant : déconnexion (claude auth logout), puis le dossier est effacé. Fenêtre
#   fermée par sa croix : un gardien caché, lancé avant Claude, attend la fin de ce script et fait la même chose.
#   Ordinateur éteint en pleine session : le prochain lancement efface d'abord ce qui est resté.
# - Pas de mise à jour automatique, pas de trafic non essentiel ; l'environnement de l'ordinateur visité ne choisit
#   ni le serveur, ni le compte, ni les certificats, ni le mandataire (ANTHROPIC_*, CLAUDE_*, NODE_*, *_PROXY…
#   retirées, avant toute commande de Claude Code).
# - Claude ne change rien sans demander (CLAUDE.md, à côté, lui donne les consignes du dépannage).
# Limite, dite dans LISEZMOI : un programme malveillant du même compte Windows peut lire le jeton pendant la session.
# PowerShell 5.1 (Windows 10) : ce fichier est en UTF-8 avec BOM, sans quoi les accents seraient mal lus.
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }

$Ici = $PSScriptRoot                      # <clé>\Claude
$Cle = Split-Path -Parent $Ici            # <clé>
$Source = Join-Path $Ici 'Windows\claude.exe'
$Signataire = 'Anthropic, PBC'
$Moi = [Security.Principal.WindowsIdentity]::GetCurrent().User
# PowerShell de Windows par l'API, jamais par une variable d'environnement qu'on pourrait avoir changée.
$PowerShell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'

function Dire([string]$fr, [string]$en) { Write-Host "  $fr"; if ($en) { Write-Host "  $en" -ForegroundColor DarkGray } }
function Arret([string]$fr, [string]$en) {
    Write-Host ''
    Write-Host "  ✖ $fr" -ForegroundColor Red
    if ($en) { Write-Host "    $en" -ForegroundColor DarkGray }
    exit 1
}

# Déconnexion, délai borné (hors ligne, ou si la commande attendait une réponse : arrêtée au bout de 20 s), puis
# effacement. [IO.Directory]::Delete ne suit pas les jonctions : il retire le lien, jamais ce qui est au bout.
# Le même texte sert au gardien (plus bas) : une seule façon de nettoyer.
$TexteNettoyer = @'
function Nettoyer([string]$dossier, [string]$exe) {
    if (-not [IO.Directory]::Exists($dossier)) { return $true }
    $config = [IO.Path]::Combine($dossier, 'config')
    if ($exe -and [IO.File]::Exists($exe) -and [IO.Directory]::Exists($config)) {
        $avant = $env:CLAUDE_CONFIG_DIR
        $env:CLAUDE_CONFIG_DIR = $config
        try {
            $p = Start-Process -FilePath $exe -ArgumentList 'auth', 'logout' -WindowStyle Hidden -PassThru -ErrorAction Stop
            if (-not $p.WaitForExit(20000)) { try { $p.Kill() } catch { } ; Start-Sleep -Seconds 1 }
        } catch { }
        $env:CLAUDE_CONFIG_DIR = $avant
    }
    for ($i = 0; $i -lt 10; $i++) {
        try { [IO.Directory]::Delete($dossier, $true); return $true } catch { Start-Sleep -Seconds 1 }
    }
    return -not [IO.Directory]::Exists($dossier)
}
'@
. ([ScriptBlock]::Create($TexteNettoyer))

Write-Host ''
Write-Host '  Dépanner avec Claude (Vanguard)' -ForegroundColor Red
Write-Host '  Troubleshoot with Claude (Vanguard)' -ForegroundColor DarkGray
Write-Host ''
Dire 'Claude Code, l''assistant d''Anthropic, va lire cet ordinateur pour trouver la panne. Ce qu''il lit (journaux,' `
     'Claude Code, Anthropic''s assistant, will read this computer to find the problem. What it reads (logs,'
Dire 'réglages, noms de fichiers) part chez Anthropic pour être analysé. Il demande avant chaque commande, et ne' `
     'settings, file names) is sent to Anthropic for analysis. It asks before every command, and changes'
Dire 'change rien sans votre accord. Il faut un compte Claude (abonnement Pro ou Max, ou console Anthropic).' `
     'nothing without your consent. A Claude account is needed (Pro or Max plan, or Anthropic Console).'
Dire 'Connexion : sur VOTRE téléphone, jamais dans le navigateur de cet ordinateur (il garderait votre compte).' `
     'Sign in on YOUR phone, never in this computer''s browser (it would keep your account signed in).'
Write-Host ''
# Oui seulement par « o », « oui », « y » ou « yes » (-match ignore la casse) : « ok non » ne vaut pas accord.
$r = Read-Host '  Le propriétaire de cet ordinateur est d''accord ? / Does the owner of this computer agree? [o/y/N]'
if ("$r".Trim() -notmatch '^(o|oui|y|yes)$') { Write-Host '  Rien n''a été lancé. / Nothing was started.'; exit 0 }

# L'environnement de Claude, et du gardien qui en hérite : celui de l'ordinateur visité ne choisit ni le serveur, ni
# le compte, ni les certificats, ni le mandataire, ni le code chargé. Retiré d'abord, avant toute commande de Claude
# Code (même la déconnexion des restes d'une session).
Get-ChildItem Env: | Where-Object {
    $_.Name -match '^(ANTHROPIC_|CLAUDE_|NODE_|BUN_|SSL_CERT_|AWS_|GOOGLE_|VERTEX_|OTEL_|GIT_)' -or
    $_.Name -match '^((HTTPS?|ALL|NO)_PROXY|REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE|BROWSER)$'
} | ForEach-Object { Remove-Item -LiteralPath "Env:$($_.Name)" }

if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
    Arret 'Claude Code n''est pas sur cette clé (Claude\Windows\claude.exe).' 'Claude Code is not on this key.'
}
if (-not $env:TEMP -or -not (Test-Path -LiteralPath $env:TEMP -PathType Container)) {
    Arret 'Dossier temporaire de Windows introuvable (TEMP).' 'Windows temporary folder not found (TEMP).'
}
# Réglages imposés à Claude Code par l'ordinateur (administrateur, entreprise, ou programme malveillant) : ils
# passeraient avant les nôtres. Fichiers, dossier managed-settings.d, et stratégies du registre.
$imposes = @()
foreach ($racine in @([Environment]::GetFolderPath('ProgramFiles'), [Environment]::GetFolderPath('CommonApplicationData'))) {
    foreach ($nom in 'CLAUDE.md', 'managed-settings.json', 'managed-settings.d', 'managed-mcp.json') {
        $imposes += [IO.Path]::Combine($racine, 'ClaudeCode', $nom)
    }
}
$imposes += 'HKLM:\SOFTWARE\Policies\ClaudeCode', 'HKCU:\SOFTWARE\Policies\ClaudeCode'
foreach ($f in $imposes) {
    if (Test-Path -LiteralPath $f) {
        Arret "$f existe : cet ordinateur impose ses réglages à Claude Code. Rien n'a été lancé." `
              "$f exists: this computer imposes its settings on Claude Code. Nothing was started."
    }
}

# Dossier à soi, au nom imprévisible, créé d'emblée avec des droits pour l'utilisateur seul (héritage coupé) : même
# si TEMP pointe vers un dossier partagé, aucun autre compte n'y lit le jeton ni n'y remplace claude.exe.
$Dossier = Join-Path $env:TEMP ('vanguard-claude-' + [Guid]::NewGuid().ToString('N'))
$Exe = Join-Path $Dossier 'claude.exe'
$Travail = Join-Path $Dossier 'travail'
$Config = Join-Path $Dossier 'config'
$Tmp = Join-Path $Dossier 'tmp'
$Session = $null
try {
    $droits = New-Object Security.AccessControl.DirectorySecurity
    $droits.SetAccessRuleProtection($true, $false)
    $droits.SetOwner($Moi)
    $droits.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($Moi, 'FullControl',
                'ContainerInherit, ObjectInherit', 'None', 'Allow')))
    [void][IO.Directory]::CreateDirectory($Dossier, $droits)
    # Tenu ouvert sans partage pendant toute la session : un second lancement ne prend pas ce dossier pour des restes.
    $Session = [IO.File]::Open((Join-Path $Dossier '.session'), 'CreateNew', 'ReadWrite', 'None')
    foreach ($d in $Travail, $Config, $Tmp) { [void][IO.Directory]::CreateDirectory($d) }
    Write-Host ''
    Dire 'Copie et vérification de Claude Code…' 'Copying and checking Claude Code…'
    Copy-Item -LiteralPath $Source -Destination $Exe

    # 1. Signature Authenticode : valide (chaîne jusqu'à une racine de Windows, fichier intact), signataire Anthropic.
    $sig = Get-AuthenticodeSignature -LiteralPath $Exe
    $nom = if ($sig.SignerCertificate) {
        $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    } else { '' }
    if ($sig.Status -ne 'Valid' -or $nom -ne $Signataire) {
        throw [Exception]::new("signature : $($sig.Status), signataire : « $nom » (attendu : « $Signataire »)")
    }
    # 2. Empreinte égale à celle du manifeste posé sur la clé : attrape une copie abîmée en route. Ce manifeste n'est
    # pas authentifié ici (pas de gpg sous Windows) : un autre claude.exe signé « Anthropic, PBC » avec un manifeste
    # retouché passerait. Une clé qui a quitté vos mains repasse par Vanguard (LISEZMOI, Limites).
    $manifeste = Get-Content -LiteralPath (Join-Path $Ici 'manifest.json') -Raw | ConvertFrom-Json
    $vu = (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($vu -ne $manifeste.platforms.'win32-x64'.checksum) { throw [Exception]::new('empreinte différente du manifeste de la clé') }
    # La version lue dans le programme signé, pas dans le manifeste qui ne l'est pas ici.
    $Version = (Get-Item -LiteralPath $Exe).VersionInfo.ProductVersion
} catch {
    if ($Session) { $Session.Dispose() }
    [void](Nettoyer $Dossier $null)
    Arret "Claude Code refusé ($($_.Exception.Message)). Rien n'a été lancé : la copie de la clé est peut-être abîmée ou remplacée ; mettez la clé à jour avec Vanguard." `
          'Claude Code refused. Nothing was started: the copy on the key may be damaged or replaced. Update the key with Vanguard.'
}
Dire "✔ Claude Code $Version, signé par $Signataire." "✔ Claude Code $Version, signed by $Signataire."

# Ce qu'une session d'avant a laissé (ordinateur éteint en pleine session) : déconnecté et effacé avec la copie qui
# vient d'être vérifiée. Seulement un vrai dossier (pas une jonction), à cet utilisateur, et sans session en cours.
Get-ChildItem -LiteralPath $env:TEMP -Directory -Filter 'vanguard-claude-*' -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -ne $Dossier -and -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } |
    ForEach-Object {
        $d = $_.FullName
        try { if ((Get-Acl -LiteralPath $d).GetOwner([Security.Principal.SecurityIdentifier]) -ne $Moi) { return } } catch { return }
        $verrou = Join-Path $d '.session'
        if ([IO.File]::Exists($verrou)) {
            try { ([IO.File]::Open($verrou, 'Open', 'ReadWrite', 'None')).Dispose() } catch { return }
        }
        if (Nettoyer $d $Exe) { Dire 'Restes d''une session précédente effacés.' 'Leftovers of a previous session erased.' }
    }

# Claude Code lit aussi les consignes des dossiers au-dessus du dossier de travail (C:\Users\…\CLAUDE.md,
# C:\.claude\…) : posées là par quelqu'un d'autre, ce seraient des consignes. Limite, dite : un compte sans droits
# peut créer C:\.claude après cette vérification ; seul un dossier refait à chaque lancement le verrait.
for ($d = Split-Path -Parent $Dossier; $d; $d = Split-Path -Parent $d) {
    foreach ($nom in 'CLAUDE.md', 'CLAUDE.local.md', 'AGENTS.md', '.claude\CLAUDE.md', '.claude\AGENTS.md', '.claude\rules') {
        if (Test-Path -LiteralPath (Join-Path $d $nom)) {
            $Session.Dispose()
            [void](Nettoyer $Dossier $null)
            Arret "$(Join-Path $d $nom) existe : Claude le lirait comme une consigne. Rien n'a été lancé." `
                  "$(Join-Path $d $nom) exists: Claude would read it as an instruction. Nothing was started."
        }
    }
}

# Sans ses consignes, Claude dépannerait sans les règles (lecture seule, accord, sécurité jamais baissée) : refusé.
$consignes = Join-Path $Travail 'CLAUDE.md'
try {
    Copy-Item -LiteralPath (Join-Path $Ici 'CLAUDE.md') -Destination $consignes
    if ((Get-Item -LiteralPath $consignes).Length -eq 0 -or
        (Get-FileHash -LiteralPath $consignes).Hash -ne (Get-FileHash -LiteralPath (Join-Path $Ici 'CLAUDE.md')).Hash) {
        throw [Exception]::new('copie différente')
    }
} catch {
    $Session.Dispose()
    [void](Nettoyer $Dossier $null)
    Arret 'Consignes de dépannage (Claude\CLAUDE.md) absentes ou illisibles : rien n''a été lancé.' `
          'Troubleshooting instructions (Claude\CLAUDE.md) missing or unreadable: nothing was started.'
}

$env:CLAUDE_CONFIG_DIR = $Config
$env:DISABLE_AUTOUPDATER = '1'
$env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = '1'
$env:VANGUARD_CLE = $Cle
$env:TEMP = $Tmp
$env:TMP = $Tmp

# Le gardien : un PowerShell de Windows caché, détaché de cette fenêtre, qui attend la fin de ce script (sortie
# normale, Ctrl+C, ou fenêtre fermée par sa croix), puis celle de claude.exe, et nettoie. Ses valeurs sont écrites
# entre apostrophes doublées, et le tout passé en -EncodedCommand : aucun guillemet de la ligne de commande à casser.
function Litteral([string]$s) { "'" + $s.Replace("'", "''") + "'" }
$gardien = $TexteNettoyer + @"
`$dossier = $(Litteral $Dossier); `$exe = $(Litteral $Exe)
try { Wait-Process -Id $PID -ErrorAction SilentlyContinue } catch { }
for (`$i = 0; `$i -lt 30 -and (Get-Process -ErrorAction SilentlyContinue | Where-Object { try { `$_.Path -eq `$exe } catch { `$false } }); `$i++) { Start-Sleep -Seconds 1 }
Get-Process -ErrorAction SilentlyContinue | Where-Object { try { `$_.Path -eq `$exe } catch { `$false } } | Stop-Process -Force -ErrorAction SilentlyContinue
[void](Nettoyer `$dossier `$exe)
"@
try {
    $code64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($gardien))
    $g = Start-Process -FilePath $PowerShell -WindowStyle Hidden -PassThru -ArgumentList '-NoProfile', '-NonInteractive',
        '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-EncodedCommand', $code64
    # Arrêté tout de suite (bloqué par une stratégie, langage restreint) : il ne gardera rien.
    Start-Sleep -Seconds 1
    if ($g.HasExited) { throw [Exception]::new('gardien arrêté') }
} catch {
    Dire '⚠ Gardien pas lancé : fermez Claude par /exit, jamais par la croix.' '⚠ Guard not started: close Claude with /exit, never with the X.'
}

Write-Host ''
Dire 'Pour finir : tapez /exit dans Claude. Après un ordinateur douteux : fermez aussi la session sur claude.ai.' `
     'To finish: type /exit in Claude. After a doubtful computer: also end the session on claude.ai.'
Dire 'Connecté dans le navigateur de cet ordinateur par erreur : déconnectez-vous de claude.ai avant de partir.' `
     'Signed in in this computer''s browser by mistake: sign out of claude.ai before leaving.'
Write-Host ''
$code = 0
Push-Location -LiteralPath $Travail
try {
    & $Exe
    $code = $LASTEXITCODE
} finally {
    Pop-Location
    $Session.Dispose()
    Write-Host ''
    if (Nettoyer $Dossier $Exe) {
        Dire '✔ Déconnecté ; Claude Code, la connexion et la conversation sont effacés de cet ordinateur.' `
             '✔ Logged out; Claude Code, the login and the conversation are erased from this computer.'
    } else {
        Dire "✖ $Dossier n'a pas pu être effacé (Claude tourne encore ?). Le gardien réessaie ; sinon, relancez « Depanner avec Claude »." `
             "✖ Could not erase $Dossier (Claude still running?). The guard retries; otherwise run « Depanner avec Claude » again."
    }
    Write-Host ''
}
exit $code

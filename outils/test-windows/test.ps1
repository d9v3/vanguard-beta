# Test complet de Vanguard sur un vrai Windows.
# 1) relève l'état réel du système (référence), 2) lance Vanguard, 3) vérifie ses réponses.
# Pendant le test : une ligne par commande et par vérification, sans les sorties brutes. À la fin : un rapport HTML
# (rapport-test.html, ouvert dans le navigateur), avec la sortie de chaque commande à déplier.
# Rangement du dossier partagé : ce script et vanguard.exe dans « programme » (remplacés à chaque déploiement),
# chaque passe dans « resultats\AAAA-MM-JJ_HH-MM-SS_vX.Y.Z », une ligne par passe dans « resultats\historique.txt »
# et le dernier rapport dans « resultats\dernier-rapport.html ». Lancé par le menu (TESTER-VANGUARD.bat).

# -Auto : aucune question ; les étapes qui demandent de taper ou une fenêtre UAC sont sautées.
# -SansOuvrir : rien ne s'ouvre à l'écran (test lancé en arrière-plan par la tâche planifiée du menu).
# -SurPlace : vanguard.exe lancé là où il est, sans copie, et les essais qui lancent une copie (lanceur de la clé, DLL
# posée à côté) faits dans des sous-dossiers d'ici. Pour la file d'essais sans clic (surveillant-essais.ps1), où ce
# script tourne en administrateur depuis un dossier que seuls les administrateurs modifient : une copie dans
# %LOCALAPPDATA% ou %TEMP%, que l'utilisateur sans droits modifie, pourrait y être remplacée entre deux lancements et
# deviendrait administrateur sans UAC.
param([switch]$Auto, [switch]$SansOuvrir, [switch]$SurPlace)

$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$OutputEncoding = [Text.Encoding]::UTF8

$ici = Split-Path -Parent $MyInvocation.MyCommand.Path
$racine = if ((Split-Path -Leaf $ici) -eq 'programme') { Split-Path -Parent $ici } else { $ici }
$resultats = Join-Path $racine 'resultats'

if ($SurPlace) {
    $exe = Join-Path $ici 'vanguard.exe'
    $lieuEssais = $ici
} else {
    # On lance une copie locale : un .exe sur un partage réseau déclenche des avertissements de sécurité.
    $local = Join-Path $env:LOCALAPPDATA 'vanguard-test'
    New-Item -ItemType Directory -Force $local | Out-Null
    Copy-Item (Join-Path $ici 'vanguard.exe') $local -Force
    $exe = Join-Path $local 'vanguard.exe'
    $lieuEssais = $env:TEMP
}
Unblock-File $exe -ErrorAction SilentlyContinue
$version = (& $exe --version 2>$null | Out-String).Trim()
$numero = if ($version -match '\d+\.\d+\.\d+') { $Matches[0] } else { 'inconnue' }
$res = Join-Path $resultats ((Get-Date -Format 'yyyy-MM-dd_HH-mm-ss') + "_v$numero")
New-Item -ItemType Directory -Force $res | Out-Null
$debutTest = Get-Date
# L'empreinte du programme essayé (la copie locale, celle qui tourne), gardée avec la passe et dans l'historique :
# outils/publier-version.sh ne publie un .exe que si une passe réussie a essayé celui-là, octet pour octet.
$empreinteEssayee = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLower()
Set-Content -LiteralPath (Join-Path $res 'programme.sha256') -Value $empreinteEssayee -Encoding ASCII

# ── Suivi des résultats : chaque étape garde ses commandes et ses vérifications, pour l'écran et le rapport ──
$script:etapes = New-Object System.Collections.ArrayList
$script:etape = $null

function Journal($texte) { Add-Content -Path (Join-Path $res 'journal.txt') -Value $texte -Encoding UTF8 }

function Etape($nom) {
    $script:etape = [pscustomobject]@{ Titre = $nom; Commandes = New-Object System.Collections.ArrayList; Verifs = New-Object System.Collections.ArrayList }
    [void]$script:etapes.Add($script:etape)
    Journal "=== $nom === $(Get-Date -Format 'HH:mm:ss')"
    Write-Host ''
    Write-Host ("  ▸ " + $nom) -ForegroundColor Cyan
}

# Une vérification : OK (vert), Bug (rouge), Info (gris). Aussi dans le journal et le rapport.
function Verif($etat, $texte) {
    [void]$script:etape.Verifs.Add([pscustomobject]@{ Etat = $etat; Texte = $texte })
    Journal "$($etat.ToUpper()) : $texte"
    switch ($etat) {
        'ok' { Write-Host '      ✔ ' -ForegroundColor Green -NoNewline; Write-Host $texte }
        'bug' { Write-Host '      ✖ ' -ForegroundColor Red -NoNewline; Write-Host $texte -ForegroundColor Red }
        'saute' { Write-Host '      ↷ ' -ForegroundColor Yellow -NoNewline; Write-Host $texte -ForegroundColor DarkGray }
        default { Write-Host "      · $texte" -ForegroundColor DarkGray }
    }
}
function Ok($texte) { Verif 'ok' $texte }
function Bug($texte) { Verif 'bug' $texte }
function Info($texte) { Verif 'info' $texte }
# Une étape (ou une partie) pas faite : comptée à part, pour qu'une vérification qui disparaît se voie au bilan.
function Sautee($texte) { Verif 'saute' $texte }

# Texte court d'une commande pour l'écran : les longs chemins sont réduits à leur nom de fichier.
function Court([string[]]$arguments) {
    ($arguments | ForEach-Object { if ($_ -match '[\\/]') { Split-Path $_ -Leaf } else { $_ } }) -join ' '
}

function Noter-Commande($fichier, [string[]]$arguments, $code, $duree, $entree) {
    [void]$script:etape.Commandes.Add([pscustomobject]@{ Fichier = $fichier; Arguments = ($arguments -join ' '); Code = $code; Duree = $duree; Entree = $entree })
    Journal ("vanguard {0} -> code {1}, {2:N1} s" -f ($arguments -join ' '), $code, $duree)
    $texte = if ($arguments) { 'vanguard ' + (Court $arguments) } else { 'vanguard (menu)' }
    if ($texte.Length -gt 58) { $texte = $texte.Substring(0, 57) + '…' }
    Write-Host ('      ' + $texte.PadRight(60)) -NoNewline
    if ($code -eq 0) { Write-Host '✔' -ForegroundColor Green -NoNewline } else { Write-Host "✖ code $code" -ForegroundColor Red -NoNewline }
    Write-Host (' {0,6:N1} s' -f $duree) -ForegroundColor DarkGray
}

# Lance Vanguard sans interaction ; garde sortie, erreurs, code de retour et durée.
function Lancer($fichier, [string[]]$arguments) {
    $debut = Get-Date
    $p = Start-Process -FilePath $exe -ArgumentList $arguments -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput (Join-Path $res "$fichier.out.txt") -RedirectStandardError (Join-Path $res "$fichier.err.txt")
    Noter-Commande $fichier $arguments $p.ExitCode ((Get-Date) - $debut).TotalSeconds $null
}

# Comme Lancer, avec des réponses tapées d'avance (une par ligne) : menus et questions sans personne au clavier.
function LancerAvec($fichier, [string[]]$arguments, [string]$entree) {
    $f = Join-Path $res "$fichier.entree.txt"
    [IO.File]::WriteAllText($f, $entree.Replace("`n", "`r`n"))
    $debut = Get-Date
    # Start-Process refuse une liste d'arguments vide (menu sans argument) : on ne la passe que si elle existe.
    $options = @{ FilePath = $exe; NoNewWindow = $true; Wait = $true; PassThru = $true; RedirectStandardInput = $f
        RedirectStandardOutput = (Join-Path $res "$fichier.out.txt"); RedirectStandardError = (Join-Path $res "$fichier.err.txt") }
    if ($arguments) { $options.ArgumentList = $arguments }
    $p = Start-Process @options
    Noter-Commande $fichier $arguments $p.ExitCode ((Get-Date) - $debut).TotalSeconds ($entree.Replace("`n", ' ⏎ ').Trim())
}

function Sortie($fichier) { Get-Content (Join-Path $res "$fichier.out.txt") -Raw -Encoding UTF8 }

# Le début d'un script PowerShell lancé par Vanguard, d'après sa ligne de commande : sans l'en-tête commun
# (encodage, $ErrorActionPreference) ni la fonction N des traces.
function Script-Court([string]$ligne) {
    if (-not $ligne) { return '(fini avant d''être lu)' }
    $s = if ($ligne -match "ErrorActionPreference='Stop'; (.*)") { $Matches[1] } else { $ligne }
    $s = (($s -replace '^\$s = \[char\]31; function N\(\$v\) \{.*?\}; ', '') -replace '\s+', ' ').Trim()
    if ($s.Length -gt 90) { $s.Substring(0, 89) + '…' } else { $s }
}

# Comme LancerAvec (entrée facultative), en guettant toutes les 100 ms les powershell.exe qui apparaissent : depuis la
# 0.82, beaucoup de lectures se font sans PowerShell, qui ne sert plus qu'en secours. Les scripts lancés vont dans
# $script:powershells (leur début). Un PowerShell fini avant d'être lu (moins de 100 ms) compte aussi, sans son texte.
function LancerSurveille($fichier, [string[]]$arguments, [string]$entree = '') {
    $avant = @([Diagnostics.Process]::GetProcessesByName('powershell') | ForEach-Object Id)
    $options = @{ FilePath = $exe; NoNewWindow = $true; PassThru = $true
        RedirectStandardOutput = (Join-Path $res "$fichier.out.txt"); RedirectStandardError = (Join-Path $res "$fichier.err.txt") }
    if ($arguments) { $options.ArgumentList = $arguments }
    if ($entree) {
        $f = Join-Path $res "$fichier.entree.txt"
        [IO.File]::WriteAllText($f, $entree.Replace("`n", "`r`n"))
        $options.RedirectStandardInput = $f
    }
    $debut = Get-Date
    $p = Start-Process @options
    # Sans garder le handle tout de suite, PowerShell ne sait plus lire le code de sortie.
    $null = $p.Handle
    $vus = @{}
    while (-not $p.HasExited) {
        foreach ($q in [Diagnostics.Process]::GetProcessesByName('powershell')) {
            if ($q.Id -in $avant -or $vus.ContainsKey($q.Id)) { continue }
            $c = Get-CimInstance Win32_Process -Filter "ProcessId = $($q.Id)" -ErrorAction SilentlyContinue
            $vus[$q.Id] = [pscustomobject]@{ Parent = $c.ParentProcessId; Ligne = "$($c.CommandLine)" }
        }
        Start-Sleep -Milliseconds 100
    }
    $p.WaitForExit()
    $tape = if ($entree) { $entree.Replace("`n", ' ⏎ ').Trim() } else { $null }
    Noter-Commande $fichier $arguments $p.ExitCode ((Get-Date) - $debut).TotalSeconds $tape
    # Ceux de Vanguard : son enfant, ou fini trop vite pour qu'on lise son parent.
    $script:powershells = @($vus.Values | Where-Object { $null -eq $_.Parent -or $_.Parent -eq $p.Id } | ForEach-Object { Script-Court $_.Ligne })
    Journal "PowerShell lancés : $($script:powershells.Count)$(if ($script:powershells.Count) { ' : ' + ($script:powershells -join ' | ') })"
}

# Après LancerSurveille : aucun PowerShell attendu (lecture native), sinon le début des scripts lancés en secours.
function Sans-PowerShell($quoi) {
    $liste = @($script:powershells)
    if (-not $liste.Count) { Ok "$quoi : aucun PowerShell lancé" }
    else { Bug "$quoi : $($liste.Count) PowerShell lancé(s) en secours : $((@($liste | Select-Object -Unique) | Select-Object -First 3) -join ' / ')" }
}

# Les touches tapées pendant une étape longue (test de connexion…) restent dans la console : sans les vider, un
# Entrée en trop répond à la place de la personne (mot de passe vide, question sans réponse).
function Vider-Clavier { try { $Host.UI.RawUI.FlushInputBuffer() } catch { } }

function Question($texte, $reponseAuto = 'n') {
    if ($Auto) {
        Journal "AUTO : $texte -> $reponseAuto"
        return $reponseAuto -eq 'o'
    }
    Write-Host "      ? $texte [o/n] " -ForegroundColor Yellow -NoNewline
    Vider-Clavier
    $r = Read-Host
    Journal "QUESTION : $texte -> $r"
    $oui = $r -match '^(o|oui|y)'
    return $oui
}

# Question dont la réponse est elle-même une vérification (« as-tu vu… ? »).
function Constat($texte) {
    if ($Auto) { Info "$texte (non vérifié : test sans personne)"; return }
    if (Question $texte) { Ok $texte } else { Bug $texte }
}

# Référence : chaque valeur lue directement, pour comparer avec les conclusions de Vanguard.
# Dans un espace d'exécution à part, avec un délai : une commande de Windows bloquée (Get-ScheduledTask, CIM…) ne
# fige plus toute la passe. Bloquée, elle est laissée de côté (l'arrêter pourrait bloquer aussi) et finit avec la passe.
function Lire-Windows([scriptblock]$bloc, [int]$delai = 30) {
    $ps = [powershell]::Create()
    try {
        # Les variables du test dont un bloc a besoin.
        foreach ($n in @('tache')) {
            $valeur = Get-Variable -Name $n -ValueOnly -ErrorAction SilentlyContinue
            if ($null -ne $valeur) { $ps.Runspace.SessionStateProxy.SetVariable($n, $valeur) }
        }
        [void]$ps.AddScript($bloc.ToString()).AddCommand('Out-String')
        $attente = $ps.BeginInvoke()
        if ($attente.AsyncWaitHandle.WaitOne($delai * 1000)) {
            $v = ($ps.EndInvoke($attente) | Out-String).Trim()
            if (-not $v -and $ps.Streams.Error.Count) { $v = "ERREUR : $($ps.Streams.Error[0])" }
            $ps.Dispose()
        } else { $v = "DÉLAI DÉPASSÉ ($delai s) : commande bloquée, laissée de côté" }
    } catch {
        # L'erreur du bloc arrive enveloppée par EndInvoke : son message d'origine est le plus lisible.
        $e = $_.Exception
        while ($e.InnerException) { $e = $e.InnerException }
        $v = "ERREUR : $($e.Message)"
    }
    $v
}
# La valeur de Lire-Windows, gardée dans reference.txt sous son nom.
function Ref($nom, [scriptblock]$bloc, [int]$delai = 30) {
    $v = Lire-Windows $bloc $delai
    Add-Content -Path (Join-Path $res 'reference.txt') -Value "### $nom`r`n$v`r`n" -Encoding UTF8
}

# ── Rapport HTML : bilan, étapes, vérifications, et la sortie de chaque commande à déplier ──
function Rapport {
    $h = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $ansi = [regex]'\x1b\[[0-9;]*[A-Za-z]'
    $toutes = @($script:etapes | ForEach-Object { $_.Verifs })
    $nbOk = @($toutes | Where-Object Etat -eq 'ok').Count
    $nbBug = @($toutes | Where-Object Etat -eq 'bug').Count
    $nbSaute = @($toutes | Where-Object Etat -eq 'saute').Count
    $nbCmd = @($script:etapes | ForEach-Object { $_.Commandes }).Count
    $nbEchec = @($script:etapes | ForEach-Object { $_.Commandes } | Where-Object Code -ne 0).Count
    $duree = [math]::Round(((Get-Date) - $debutTest).TotalMinutes, 1)
    $windows = (Get-CimInstance Win32_OperatingSystem).Caption
    $reussi = $nbBug -eq 0 -and $nbEchec -eq 0
    $verdict = if ($reussi) { "✓ Tout est passé : $nbOk vérifications réussies" } else { "✗ $nbBug problème(s) · $nbEchec commande(s) en échec" }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(@"
<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Test de Vanguard</title><style>
:root{--fond:#0b0808;--carte:#160f10;--trait:#2e2224;--texte:#eee3db;--gris:#a8968c;--rouge:#ff5a4f;--vert:#5fd38d;--jaune:#f2c14e}
*{box-sizing:border-box}body{margin:0;background:var(--fond);color:var(--texte);font:15px/1.5 system-ui,'Segoe UI',sans-serif}
main{max-width:980px;margin:0 auto;padding:28px 16px 60px}h1{margin:0 0 4px;font-size:26px}h1 b{color:var(--rouge)}
.sous{color:var(--gris);margin-bottom:22px}.bilan{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:26px}
.case{background:var(--carte);border:1px solid var(--trait);border-radius:10px;padding:12px 16px;min-width:150px}
.case b{display:block;font-size:24px}.case span{color:var(--gris);font-size:13px}
.etape{background:var(--carte);border:1px solid var(--trait);border-radius:10px;margin:0 0 12px;padding:14px 16px}
.etape h2{margin:0 0 8px;font-size:16px;display:flex;gap:8px;align-items:center}.pastille{width:10px;height:10px;border-radius:50%;background:var(--vert);flex:none}
.etape.rouge .pastille{background:var(--rouge)}.etape.grise .pastille{background:var(--gris)}
ul{margin:4px 0 8px;padding-left:4px;list-style:none}li{margin:2px 0}.ok{color:var(--vert)}.bug{color:var(--rouge)}.info{color:var(--gris)}.saute{color:#c9a227}
details{border-top:1px solid var(--trait);padding:6px 0}summary{cursor:pointer;display:flex;justify-content:space-between;gap:10px}
summary code{color:var(--texte);font-variant-ligatures:none}summary .d{color:var(--gris);white-space:nowrap}pre{background:#000;border-radius:8px;padding:10px;overflow:auto;max-height:420px;font:12.5px/1.45 Consolas,monospace;color:#ddd}
.entree{color:var(--jaune);font-size:12.5px}
.verdict{border-radius:12px;padding:16px 20px;font-size:20px;font-weight:600;margin-bottom:14px}
.verdict.vert{background:#0f2a1a;border:1px solid #1f6b3e;color:var(--vert)}.verdict.rouge{background:#2c0d0d;border:1px solid #7e1c1c;color:var(--rouge)}
</style></head><body><main>
<h1>Test de <b>Vanguard</b></h1>
<div class="sous">$(& $h $version) · $(& $h $windows) · $(Get-Date -Format 'yyyy-MM-dd HH:mm') · $duree min$(if ($Auto) { ' · sans questions' })</div>
<div class="verdict $(if ($reussi) { 'vert' } else { 'rouge' })">$(& $h $verdict)</div>
<div class="bilan"><div class="case"><b class="ok">$nbOk</b><span>vérifications réussies</span></div>
<div class="case"><b class="$(if ($nbBug) { 'bug' } else { 'info' })">$nbBug</b><span>problèmes</span></div>
<div class="case"><b>$nbCmd</b><span>commandes ($nbEchec en échec)</span></div>
<div class="case"><b class="$(if ($nbSaute) { 'saute' } else { 'info' })">$nbSaute</b><span>sautées</span></div></div>
"@)
    foreach ($e in $script:etapes) {
        $rouge = @($e.Verifs | Where-Object Etat -eq 'bug').Count + @($e.Commandes | Where-Object Code -ne 0).Count
        $classe = if ($rouge) { 'rouge' } elseif (-not $e.Verifs.Count -and -not $e.Commandes.Count) { 'grise' } else { '' }
        [void]$sb.Append("<section class=""etape $classe""><h2><span class=""pastille""></span>$(& $h $e.Titre)</h2>")
        if ($e.Verifs.Count) {
            [void]$sb.Append('<ul>')
            foreach ($v in $e.Verifs) {
                $signe = switch ($v.Etat) { 'ok' { '✓' } 'bug' { '✗' } 'saute' { '↷' } default { '·' } }
                [void]$sb.Append("<li class=""$($v.Etat)"">$signe $(& $h $v.Texte)</li>")
            }
            [void]$sb.Append('</ul>')
        }
        foreach ($c in $e.Commandes) {
            $sortie = ''
            foreach ($f in "$($c.Fichier).out.txt", "$($c.Fichier).err.txt") {
                $chemin = Join-Path $res $f
                # Un fichier vide se lit comme « rien » ($null) : on ne garde que ce qui a du texte.
                $texte = if (Test-Path $chemin) { Get-Content $chemin -Raw -Encoding UTF8 } else { $null }
                if ($texte) { $sortie += $ansi.Replace($texte, '') }
            }
            $etat = if ($c.Code -eq 0) { '<span class="ok">✓</span>' } else { "<span class=""bug"">✗ code $($c.Code)</span>" }
            $entree = if ($c.Entree) { "<div class=""entree"">réponses tapées : $(& $h $c.Entree)</div>" } else { '' }
            $complete = if ($c.Arguments) { "vanguard $($c.Arguments)" } else { 'vanguard (menu)' }
            $commande = if ($c.Arguments) { 'vanguard ' + (Court ($c.Arguments -split ' ')) } else { 'vanguard (menu)' }
            [void]$sb.Append("<details><summary><code title=""$(& $h $complete)"">$(& $h $commande)</code><span class=""d"">$etat $('{0:N1}' -f $c.Duree) s</span></summary>$entree<pre>$(& $h $sortie)</pre></details>")
        }
        [void]$sb.Append('</section>')
    }
    [void]$sb.Append('</main></body></html>')
    $chemin = Join-Path $res 'rapport-test.html'
    [IO.File]::WriteAllText($chemin, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
    return $chemin
}

Clear-Host
Write-Host ''
Write-Host '  ╭──────────────────────────────────────────────────────────╮' -ForegroundColor Red
Write-Host ('  │  ' + "TEST DE VANGUARD · $version".PadRight(56) + '│') -ForegroundColor Red
Write-Host '  ╰──────────────────────────────────────────────────────────╯' -ForegroundColor Red
if ($SansOuvrir) { Write-Host '  En arrière-plan : rien ne s''ouvre, le rapport ira dans resultats.' -ForegroundColor DarkGray }
elseif ($Auto) { Write-Host '  Sans aucune question : 5 à 15 minutes. Le rapport s''ouvrira à la fin.' -ForegroundColor DarkGray }
else { Write-Host '  Quelques questions te seront posées : réponds o (oui) ou n (non).' -ForegroundColor DarkGray }

Etape 'Référence : état réel de Windows'
Ref 'Windows' { Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture | Format-List }
Ref 'PowerShell' { $PSVersionTable.PSVersion.ToString() }
Ref 'Administrateur ?' { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
Ref 'Pare-feu' { Get-NetFirewallProfile | Select-Object Name, Enabled | Format-Table -AutoSize }
Ref 'Defender' { Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureAge, IsTamperProtected | Format-List }
Ref 'Antivirus (Centre de sécurité)' { (Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct).displayName }
Ref 'SMBv1' { (Get-SmbServerConfiguration).EnableSMB1Protocol }
Ref 'RDP fDenyTSConnections (0 = actif)' { (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections }
Ref 'RDP NLA (1 = exigée)' { (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication }
Ref 'UAC EnableLUA' { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA }
Ref 'BitLocker C: (1,3,5 = protégé)' { (New-Object -ComObject Shell.Application).NameSpace('C:').Self.ExtendedProperty('System.Volume.BitLockerProtection') }
Ref 'Dernier correctif Windows' { Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 3 HotFixID, InstalledOn | Format-Table -AutoSize }
Ref 'Compte invité' { Get-LocalUser | Where-Object { $_.SID -like '*-501' } | Select-Object Name, Enabled | Format-Table -AutoSize }
Ref 'Ports en écoute' { Get-NetTCPConnection -State Listen | Sort-Object LocalPort | ForEach-Object { "{0}:{1} {2}" -f $_.LocalAddress, $_.LocalPort, (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } }
Ref 'Wi-Fi' { netsh wlan show interfaces }
Ref 'Réseau (IP)' { Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, IPAddress, PrefixLength | Format-Table -AutoSize }
Ref 'Passerelle (route print)' { route print -4 0.0.0.0 }
Ref 'Table ARP' { arp -a }
# Vérifications ajoutées de la 0.12 à la 0.19 : de quoi comparer avec ce que Vanguard en conclut.
Ref 'DNS par carte (0.12)' { Get-DnsClientServerAddress | Where-Object ServerAddresses | Select-Object InterfaceAlias, InterfaceIndex, AddressFamily, ServerAddresses | Format-Table -AutoSize }
Ref 'Certificats racine avec clé privée (0.12)' { Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root | Where-Object HasPrivateKey | Select-Object PSParentPath, Subject, Thumbprint | Format-List }
Ref 'Nombre de certificats racine (0.12)' { @(Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root | Select-Object -Unique Thumbprint).Count }
Ref 'Comptes locaux (0.13)' { Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, SID | Format-Table -AutoSize }
Ref 'LimitBlankPasswordUse (0.13)' { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa').LimitBlankPasswordUse }
Ref 'Tâches planifiées hors Microsoft (0.13)' { Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object { $t = $_; $t.Actions | ForEach-Object { '{0}{1} [{2}] {3} {4}' -f $t.TaskPath, $t.TaskName, $t.State, $_.Execute, $_.Arguments } } }
Ref 'Clés Run (0.13)' { foreach ($c in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run') { "== $c"; Get-ItemProperty $c -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PS* | Format-List } }
Ref 'Dossiers Démarrage (0.13)' { Get-ChildItem ([Environment]::GetFolderPath('Startup')), ([Environment]::GetFolderPath('CommonStartup')) -ErrorAction SilentlyContinue | Select-Object FullName }
Ref 'Ports UDP (0.13)' { Get-NetUDPEndpoint | Sort-Object LocalPort | ForEach-Object { '{0}:{1} {2}' -f $_.LocalAddress, $_.LocalPort, (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } }
Ref 'Volumes (0.15)' { Get-Volume | Where-Object DriveLetter | Select-Object DriveLetter, DriveType, SizeRemaining, Size | Format-Table -AutoSize }
Ref 'Disques physiques (0.15)' { Get-PhysicalDisk | Select-Object FriendlyName, HealthStatus, OperationalStatus, MediaType | Format-Table -AutoSize }
Ref 'Batterie (0.15)' { Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity -ErrorAction Stop | Select-Object FullChargedCapacity; Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData -ErrorAction Stop | Select-Object DesignedCapacity }
Ref 'Extensions Edge et Chrome (0.14)' { foreach ($d in "$env:LOCALAPPDATA\Microsoft\Edge\User Data", "$env:LOCALAPPDATA\Google\Chrome\User Data") { Get-ChildItem $d -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName 'Extensions') } | ForEach-Object { "== $($_.FullName)"; Get-ChildItem (Join-Path $_.FullName 'Extensions') -Name } } }
Ref 'curl (0.17, 0.18)' { (Get-Command curl.exe -ErrorAction Stop).Source; curl.exe --version | Select-Object -First 1 }
# Vérifications ajoutées de la 0.20 à la 0.35.
Ref 'Journaux effacés, événement 104 (0.30)' { Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 104 } -MaxEvents 5 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message | Format-List }
Ref 'Edge : Safe Browsing et DNS chiffré (0.31)' { $p = Get-Content "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Preferences" -Raw -ErrorAction Stop | ConvertFrom-Json; 'safebrowsing.enabled = ' + $p.safebrowsing.enabled; $l = Get-Content "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Local State" -Raw -ErrorAction Stop | ConvertFrom-Json; 'dns_over_https.mode = ' + $l.dns_over_https.mode }
Ref 'Zones thermiques (0.24)' { Get-CimInstance Win32_PerfFormattedData_Counters_ThermalZoneInformation -ErrorAction Stop | Select-Object Name, HighPrecisionTemperature | Format-Table -AutoSize }
Ref 'LLMNR (0.23)' { (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue).EnableMulticast }
Ref 'UPnP de la box (0.33)' { $c = (New-Object -ComObject HNetCfg.NATUPnP).StaticPortMappingCollection; if ($null -eq $c) { 'aucune box UPnP' } else { $c | Select-Object Protocol, ExternalPort, InternalClient, InternalPort, Description | Format-Table -AutoSize } }
Ref 'Windows Sandbox (0.35)' { Test-Path "$env:SystemRoot\System32\WindowsSandbox.exe" }
Info 'Référence enregistrée (reference.txt) : état lu directement dans Windows, pour comparer.'

Etape 'Version et aide'
Lancer 'version' @('--version')
Lancer 'aide' @('--help')

Etape 'Audit de la machine (texte et JSON)'
Lancer 'machine' @('audit')
# VANGUARD_CHRONO : le temps de chaque vérification part sur la sortie d'erreur, gardée avec les résultats (le bilan
# Windows prend plusieurs secondes : on voit lesquelles, sans pouvoir mesurer depuis Linux).
$env:VANGUARD_CHRONO = '1'
Lancer 'machine-json' @('audit', '--json')
Remove-Item Env:VANGUARD_CHRONO
$lentes = @(Get-Content (Join-Path $res 'machine-json.err.txt') -ErrorAction SilentlyContinue |
    Where-Object { $_ -match '^chrono\s+\d+\s+(\d+) ms\s+(.*)$' } |
    ForEach-Object { [pscustomobject]@{ Ms = [int]$Matches[1]; Quoi = $Matches[2] } } | Sort-Object Ms -Descending | Select-Object -First 6)
if ($lentes) { Info ("Vérifications les plus lentes : " + (($lentes | ForEach-Object { "$($_.Quoi) $($_.Ms) ms" }) -join ', ')) }
# Vérifications qui n'ont pas pu se faire : un script PowerShell de Vanguard a échoué (à corriger côté Vanguard).
try {
    $audit = Sortie 'machine-json' | ConvertFrom-Json
    $impossibles = @($audit.constats | Where-Object { -not $_.verifie })
    # Sans droits, ce qui demande l'administrateur (journal de sécurité) est dit non vérifié : c'est la règle (jamais
    # compté comme sain), pas un échec. Seul ce qui le dit en toutes lettres est mis à part.
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) {
        $attendus = @($impossibles | Where-Object { $_.message -match 'administrat' })
        $attendus | ForEach-Object { Info "Non vérifié sans droits, comme attendu : $($_.categorie) — $($_.message)" }
        $impossibles = @($impossibles | Where-Object { $_.message -notmatch 'administrat' })
    }
    # Logiciels pas à jour : pendant le déploiement d'un nouveau Stable d'Edge (3 jours) ou d'Office (7 jours), la
    # version d'avant n'est ni due ni à jour, non vérifiée par choix (perimes/verdicts.rs, EDGE_DEPLOIEMENT). Attendu
    # seulement si TOUTES les raisons du constat sont des déploiements : toute autre raison reste un défaut.
    $enDeploiement = @($impossibles | Where-Object {
        $_.regle -eq 'WIN-MAJ-002' -and
        @(($_.message -replace '^(Could not check|Impossible de vérifier) \(', '' -replace '\)\.$', '') -split ' ; ' |
            Where-Object { $_ -notmatch '^\S.* \((rollout of|déploiement de la) \S+ (in progress|en cours)\)$' }).Count -eq 0 })
    $enDeploiement | ForEach-Object { Info "Non vérifié, déploiement en cours (attendu) : $($_.categorie) — $($_.message)" }
    $impossibles = @($impossibles | Where-Object { $enDeploiement -notcontains $_ })
    if ($impossibles.Count) { $impossibles | ForEach-Object { Bug "Vérification impossible : $($_.categorie) — $($_.message)" } }
    else { Ok "Toutes les vérifications ont pu se faire ($(@($audit.constats).Count) constats, note $($audit.score)/100)" }
} catch { Bug "machine --json illisible : $($_.Exception.Message)" }

Etape 'Comptes et démarrage lus sans PowerShell (0.82) : les mêmes réponses que Windows'
# Depuis la 0.82, Vanguard lit les comptes (NetUserEnum, groupe S-1-5-32-544), les clés Run et le dossier Démarrage
# par les fonctions de Windows. PowerShell, qui les lisait avant, sert ici de référence pour le bilan JSON ci-dessus.
try {
    $audit = Sortie 'machine-json' | ConvertFrom-Json
    $messages = @($audit.constats | ForEach-Object { $_.message })
    # Les noms que le bilan cite dans les messages qui suivent l'un des motifs (anglais ou français).
    function Noms-Cites([string[]]$motifs) {
        @($messages | ForEach-Object { $m = $_; foreach ($motif in $motifs) { if ($m -match $motif) { $Matches[1] } } })
    }
    # Deux listes de noms, sans ordre ni casse (Compare-Object refuse une liste vide).
    function Meme-Liste($quoi, [string[]]$windows, [string[]]$vanguard) {
        $w = (@($windows | Where-Object { $_ } | Sort-Object -Unique)) -join ', '
        $v = (@($vanguard | Where-Object { $_ } | Sort-Object -Unique)) -join ', '
        if ($w -eq $v) { Ok "$quoi : Windows et Vanguard d'accord ($(if ($w) { $w } else { 'aucun' }))" }
        else { Bug "$quoi : Windows dit « $w », Vanguard « $v »" }
    }
    $actifs = @(Get-LocalUser | Where-Object Enabled)
    Meme-Liste 'Compte invité activé' @($actifs | Where-Object { $_.SID.Value -like '*-501' } | ForEach-Object Name) `
        (Noms-Cites 'Guest account “(.+?)” enabled', 'Compte invité « (.+?) » activé')
    Meme-Liste 'Administrateur intégré activé' @($actifs | Where-Object { $_.SID.Value -like '*-500' } | ForEach-Object Name) `
        (Noms-Cites 'Built-in Administrator account “(.+?)” enabled', 'Compte Administrateur intégré « (.+?) » activé')
    # L'invité est jugé à part : il n'est pas compté parmi les mots de passe vides.
    Meme-Liste 'Mot de passe vide accepté' @($actifs | Where-Object { $_.SID.Value -notlike '*-501' -and -not $_.PasswordRequired } | ForEach-Object Name) `
        (Noms-Cites 'The “(.+?)” account accepts an empty password', 'Le compte « (.+?) » accepte un mot de passe vide')
    $lbp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).LimitBlankPasswordUse
    if (($lbp -eq 0) -eq [bool]@($messages | Where-Object { $_ -match 'LimitBlankPasswordUse = 0' }).Count) { Ok "LimitBlankPasswordUse ($lbp) : même verdict" } else { Bug "LimitBlankPasswordUse ($lbp) : verdict différent" }
    # Comptes oubliés : actifs, hors comptes intégrés et compte en cours, jamais connectés ou pas depuis 180 jours.
    $limite = (Get-Date).Date.AddDays(-180)
    Meme-Liste 'Comptes oubliés' @($actifs | Where-Object { $_.SID.Value -notmatch '-(500|501|503|504)$' -and $_.Name -ne $env:USERNAME -and (-not $_.LastLogon -or $_.LastLogon -lt $limite) } | ForEach-Object Name) `
        (Noms-Cites 'The “(.+?)” account is active but has', 'Le compte « (.+?) » est actif mais')
    # Administrateurs : le groupe par son SID, comme Vanguard ; noms « ORDINATEUR\compte ».
    try {
        $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object Name)
        $message = @($messages | Where-Object { $_ -match 'Administrators of this computer|Administrateurs de cet ordinateur|New administrator account|Nouveau compte administrateur' }) | Select-Object -First 1
        $absents = @($admins | Where-Object { $message -notlike "*$_*" })
        if (-not $message) { Bug 'Administrateurs : rien au bilan' }
        elseif ($admins.Count -gt 5) { Info "Administrateurs : $($admins.Count), le bilan n'en cite que 5 : $message" }
        elseif ($absents.Count) { Bug "Administrateurs absents du bilan : $($absents -join ', ') ($message)" }
        else { Ok "Administrateurs : les mêmes que Get-LocalGroupMember ($($admins -join ', '))" }
    } catch { Info "Get-LocalGroupMember illisible ici : $($_.Exception.Message)" }
    # Programmes au démarrage : toutes les valeurs des clés Run et RunOnce, et chaque fichier des dossiers Démarrage
    # (cachés compris, hors desktop.ini).
    $cles = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    $valeurs = ($cles | ForEach-Object { @((Get-Item -LiteralPath $_ -ErrorAction SilentlyContinue).GetValueNames()).Count } | Measure-Object -Sum).Sum
    $fichiers = @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup') | Where-Object { $_ } |
        ForEach-Object { Get-ChildItem -LiteralPath $_ -File -Force -ErrorAction SilentlyContinue } | Where-Object Name -ne 'desktop.ini').Count
    $persistance = @($audit.constats | Where-Object { $_.categorie -eq 'Persistance' })
    if (@($persistance | Where-Object { $_.probleme }).Count) { Info 'Programmes au démarrage : un lancement suspect au bilan, nombre pas comparé' }
    elseif (@($persistance | ForEach-Object { $_.message }) -join ' ' -match '(?:task\(s\) and|hors Microsoft et) (\d+) (?:startup program|programme)') {
        if ([int]$Matches[1] -eq $valeurs + $fichiers) { Ok "Programmes au démarrage : $($Matches[1]), comme le registre et les dossiers ($valeurs + $fichiers)" }
        else { Bug "Programmes au démarrage : Vanguard $($Matches[1]), registre et dossiers $valeurs + $fichiers" }
    } else { Bug 'Programmes au démarrage : nombre absent du bilan' }
} catch { Bug "Comparaison impossible : $($_.Exception.Message)" }

Etape 'Plantage du 20 octobre (0.82) : vanguard machine trois fois de suite, code 0 chaque fois'
# Le bilan lit WMI dans des fils en parallèle : une erreur COM libérée hors de son fil faisait planter Vanguard au
# hasard des règles (0xC0000005, code -1073741819), jamais sous Wine. Trois passes de suite pour la débusquer.
$codesMachine = @()
foreach ($n in 1..3) {
    LancerSurveille "machine-suite-$n" @('audit')
    $codesMachine += $script:etape.Commandes[-1].Code
    if ($n -eq 1) { $psMachine = @($script:powershells) }
}
$negatifs = @($codesMachine | Where-Object { $_ -lt 0 })
if ($negatifs.Count) { Bug "plantage : codes $($codesMachine -join ', ') ($(($negatifs | ForEach-Object { '0x{0:X8}' -f $_ }) -join ', '))" }
elseif (@($codesMachine | Where-Object { $_ -ne 0 }).Count) { Bug "Bilan : codes $($codesMachine -join ', ') au lieu de 0" }
else { Ok 'Trois bilans de suite, code 0 chaque fois' }
# Ce que le bilan lance encore par PowerShell : pour suivre ce qui reste à passer en lecture native.
Info "PowerShell lancé(s) par un bilan : $($psMachine.Count)$(if ($psMachine.Count) { ' : ' + ((@($psMachine | Select-Object -Unique) | Select-Object -First 6) -join ' / ') })"

Etape 'Scan du réseau de la VM'
Lancer 'reseau' @('appareils')
Lancer 'reseau-json' @('appareils', '--json')
try {
    $scan = Sortie 'reseau-json' | ConvertFrom-Json
    Ok "$(@($scan.hotes).Count) appareil(s) trouvé(s) sur $($scan.reseau)"
} catch { Bug "reseau --json illisible : $($_.Exception.Message)" }

Etape 'Routeur et objets connectés (0.82) : sans scan gardé, puis d''après le scan, en 76 colonnes'
# Les lignes de l'écran sans couleurs ; la plus longue doit tenir dans les 76 colonnes de Vanguard.
function Lignes([string]$texte) { @(($texte -replace '\x1b\[[0-9;]*[A-Za-z]', '') -split "`r?`n") }
function Trop-Larges([string[]]$lignes) { @($lignes | Where-Object { $_.TrimEnd().Length -gt 76 }) }
# Sans scan gardé : le dossier de Vanguard pointé, pour cette commande seulement, vers un dossier vide.
$vraiLocal = $env:LOCALAPPDATA
$localVide = Join-Path $env:TEMP 'vanguard-objets-vide'
New-Item -ItemType Directory -Force $localVide | Out-Null
try {
    $env:LOCALAPPDATA = $localVide
    Lancer 'objets-sans-scan' @('objets-connectes')
} finally { $env:LOCALAPPDATA = $vraiLocal }
Remove-Item $localVide -Recurse -Force -ErrorAction SilentlyContinue
$o = (Sortie 'objets-sans-scan') -replace '\s+', ' '
if ($o -match 'Aucun scan gardé pour ce réseau|No scan kept for this network') { Ok 'Sans scan gardé : renvoi vers le scan du réseau' } else { Bug 'Sans scan gardé : pas de renvoi vers le scan' }
# Après le scan de la VM : la commande relit le carnet, et le scan a déjà montré la section si la box y est.
Lancer 'objets' @('objets-connectes')
$o = Sortie 'objets'
if ($o -match 'BOX ET OBJETS CONNECTÉS|ROUTER AND CONNECTED DEVICES') { Ok 'iot : écran affiché' } else { Bug 'iot : écran ABSENT' }
if (($o -replace '\s+', ' ') -match "D'après le dernier scan|From the last scan") { Ok 'iot : d''après le dernier scan gardé, rien sondé' } else { Bug 'iot : dernier scan gardé PAS relu' }
$larges = Trop-Larges (Lignes $o)
if ($larges.Count) { Bug "iot : $($larges.Count) ligne(s) au-delà de 76 colonnes : $($larges[0].Trim())" } else { Ok 'iot : tout tient en 76 colonnes' }
try {
    $passerelle = @((Sortie 'reseau-json' | ConvertFrom-Json).hotes | Where-Object { $_.role -eq 'passerelle' }).Count
    $lignesScan = Lignes (Sortie 'reseau')
    $debut = @(0..($lignesScan.Count - 1) | Where-Object { $lignesScan[$_] -match 'BOX ET OBJETS CONNECTÉS|ROUTER AND CONNECTED DEVICES' })
    if (-not $passerelle) { Info 'Pas de box dans le scan : section du scan non attendue' }
    elseif (-not $debut.Count) { Bug 'Scan : box trouvée, mais section « Router and connected devices » ABSENTE' }
    else {
        # La section va jusqu'au titre suivant (── ou ━━).
        $fin = $debut[0] + 1
        while ($fin -lt $lignesScan.Count -and $lignesScan[$fin] -notmatch '^\s*(──|━━)') { $fin++ }
        $section = $lignesScan[$debut[0]..($fin - 1)]
        Info "Section du scan : $(($section | Where-Object { $_.Trim() } | Select-Object -Skip 1 | ForEach-Object { $_.Trim() }) -join ' / ')"
        $larges = Trop-Larges $section
        if ($larges.Count) { Bug "Scan : section des objets au-delà de 76 colonnes : $($larges[0].Trim())" } else { Ok 'Scan : section des objets en 76 colonnes' }
    }
} catch { Bug "Scan illisible ($($_.Exception.Message))" }

Etape 'Audit du réseau (0.82) : six domaines, rien de sain sans lecture, en 76 colonnes, sans invite du pare-feu'
# Une invite du pare-feu (« autoriser l'accès ») répondue ou refusée laisse une règle au nom du programme.
function Regles-Pare-Feu {
    try { @(Get-NetFirewallApplicationFilter -ErrorAction Stop | Where-Object { $_.Program -like '*vanguard*' }).Count } catch { -1 }
}
$reglesAvant = Regles-Pare-Feu
Lancer 'audit-reseau' @('audit-reseau')
Lancer 'audit-reseau-json' @('audit-reseau', '--json')
$codesAudit = @($script:etape.Commandes | ForEach-Object Code)
if (@($codesAudit | Where-Object { $_ -lt 0 }).Count) { Bug "plantage de l'audit du réseau : codes $($codesAudit -join ', ')" }
elseif (@($codesAudit | Where-Object { $_ -ne 0 }).Count) { Bug "audit-reseau : codes $($codesAudit -join ', ') au lieu de 0" }
else { Ok 'audit-reseau : code 0 (texte et JSON)' }
$texteAudit = Lignes (Sortie 'audit-reseau')
$larges = Trop-Larges $texteAudit
if ($larges.Count) { Bug "audit-reseau : $($larges.Count) ligne(s) au-delà de 76 colonnes : $($larges[0].Trim())" } else { Ok 'audit-reseau : tout tient en 76 colonnes' }
# À l'écran, une vérification impossible est un « ? » gris, jamais un « ✔ ».
$fauxVerts = @($texteAudit | Where-Object { $_ -match '✔' -and $_ -match 'Could not check|Impossible de vérifier' })
if ($fauxVerts.Count) { Bug "Vérification impossible marquée ✔ : $($fauxVerts[0].Trim())" } else { Ok 'Aucun ✔ sur une vérification impossible' }
try {
    $ar = Sortie 'audit-reseau-json' | ConvertFrom-Json
    $noms = @($ar.domaines | ForEach-Object domaine) -join ', '
    if ($noms -eq 'Exposition, Wi-Fi, Segmentation, DNS et TLS, Appareils, Postes') { Ok "Six domaines dans le JSON ($noms), réseau $($ar.reseau)" } else { Bug "Domaines du JSON : $noms" }
    Info ('Notes : ' + (($ar.domaines | ForEach-Object { "$($_.domaine) $(if ($null -ne $_.score) { "$($_.note) ($($_.score))" } else { "incomplet ($($_.non_verifies) non vérifiés)" })" }) -join ', '))
    $tous = @($ar.domaines | ForEach-Object { $_.constats })
    # Ce qui n'a pas pu être lu porte un niveau (info) : jamais un constat sain, que la note compterait.
    $fauxOk = @($tous | Where-Object { -not $_.verifie -and $null -eq $_.probleme })
    if ($fauxOk.Count) { Bug "Non vérifié compté sain : $($fauxOk[0].regle) $($fauxOk[0].message)" }
    else { Ok "$($tous.Count) constats, dont $(@($tous | Where-Object { -not $_.verifie }).Count) non vérifiés : aucun compté sain" }
    function Regle-Audit($id) { @($tous | Where-Object regle -eq $id) }
    function Messages-Audit($id) { (@(Regle-Audit $id) | ForEach-Object message) -join ' / ' }
    # Wi-Fi : la VM n'a pas de carte Wi-Fi (ou son service WLAN est arrêté) : les trois règles des bornes non vérifiées.
    $wlan = Get-Service WlanSvc -ErrorAction SilentlyContinue
    $cartesWifi = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object NdisPhysicalMedium -eq 9)
    if (-not $wlan -or $wlan.Status -ne 'Running' -or -not $cartesWifi.Count) {
        foreach ($id in 'COM-WIF-001', 'COM-WIF-002', 'COM-WIF-003') {
            $c = @(Regle-Audit $id)
            $dits = @($c | Where-Object { -not $_.verifie -and $_.message -match 'no Wi-Fi card|WLAN service is stopped|pas de carte Wi-Fi|service WLAN de Windows est arrêté' })
            if ($c.Count -and $dits.Count -eq $c.Count) { Ok "$id : impossible de vérifier, dit pourquoi ($($c[0].message))" }
            else { Bug "$id sans Wi-Fi : « $(Messages-Audit $id) »" }
        }
    } else { Info "Cette VM a une carte Wi-Fi ($($cartesWifi[0].Name)) : COM-WIF-001 « $(Messages-Audit 'COM-WIF-001') »" }
    # Exposition : le routeur virtuel ne parle pas UPnP (« coupé ou absent ») ; s'il répond, « actif » est un faux
    # positif admis.
    $exp = Messages-Audit 'COM-EXP-001'
    if ($exp -match 'UPnP off or absent|UPnP coupé ou absent') { Ok 'Exposition : UPnP coupé ou absent' }
    elseif ($exp -match 'UPnP is on|UPnP est actif') { Info "Exposition : UPnP dit actif (faux positif admis si le routeur virtuel répond) : $exp" }
    else { Bug "Exposition : ni « UPnP off or absent » ni « UPnP is on » : « $exp »" }
    # DNS et TLS : sans DohFlags dans le registre (aucun DoH déclaré à Windows), le DNS du système part en clair.
    $doh = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters' -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $null -ne $_.GetValue('DohFlags') } | ForEach-Object PSChildName)
    $dns3 = @(Regle-Audit 'COM-DNS-003')
    if ($doh.Count) { Info "DoH déclaré à Windows ($($doh -join ', ')) : COM-DNS-003 « $(Messages-Audit 'COM-DNS-003') »" }
    elseif (@($dns3 | Where-Object { $_.verifie -and $_.message -match 'leave unencrypted|partent en clair' }).Count) { Ok 'DNS et TLS : DohFlags absent, DNS dit « en clair »' }
    else { Bug "DNS et TLS : DohFlags absent, mais COM-DNS-003 dit « $(Messages-Audit 'COM-DNS-003') »" }
    # Segmentation : le serveur DHCP du bail, lu par Vanguard dans le registre (DhcpServer), comme ici.
    $dhcp = @(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\*' -ErrorAction SilentlyContinue |
        ForEach-Object DhcpServer | Where-Object { $_ -and $_ -ne '255.255.255.255' } | Sort-Object -Unique)
    $seg = Messages-Audit 'COM-SEG-004'
    if (-not $dhcp.Count) { Info "Aucun serveur DHCP dans le registre (adresse fixe ?) : COM-SEG-004 « $seg »" }
    elseif (-not @(Regle-Audit 'COM-SEG-004' | Where-Object verifie).Count) { Bug "COM-SEG-004 : serveur DHCP pas lu (registre : $($dhcp -join ', ')) : « $seg »" }
    elseif (@($dhcp | Where-Object { $seg -match "\b$([regex]::Escape($_))\b" }).Count) { Ok "Segmentation : serveur DHCP $($dhcp -join ', '), comme DhcpServer du registre" }
    else { Bug "COM-SEG-004 : registre $($dhcp -join ', '), Vanguard « $seg »" }
} catch { Bug "audit-reseau --json illisible : $($_.Exception.Message)" }
Lancer 'audit-reseau-invite' @('audit-reseau', '--invite')
if (((Sortie 'audit-reseau-invite') -replace '\s+', ' ') -match 'From the guest network|Depuis le réseau invité') { Ok '--invite : vérifie la séparation du réseau principal' } else { Bug '--invite : phrase du réseau invité ABSENTE' }
# Menu Réseau et Internet (5), outil 2 : l'audit, Entrée pour revenir, Entrée pour le menu principal, q.
LancerAvec 'menu-audit-reseau' @() "5`n2`n`n`nq`n"
if ((Sortie 'menu-audit-reseau') -match "Audit grade|Note de l.audit") { Ok 'Menu Réseau › 2 : audit du réseau lancé' } else { Bug 'Menu Réseau › 2 : audit du réseau PAS lancé' }
$reglesApres = Regles-Pare-Feu
if ($reglesAvant -lt 0 -or $reglesApres -lt 0) { Info 'Règles du pare-feu illisibles ici : invite non vérifiée par les règles' }
elseif ($reglesApres -eq $reglesAvant) { Ok "Aucune règle du pare-feu ajoutée pour Vanguard ($reglesApres) : pas d'invite répondue" }
else { Bug "Pare-feu : $($reglesApres - $reglesAvant) règle(s) ajoutée(s) pour Vanguard pendant l'audit (une invite s'est ouverte)" }
# Question positive, dont le « oui » est le défaut : à « Aucune fenêtre… ne s'est ouverte ? », « non » voulait dire
# « non, aucune » et passait pour un défaut. Sans personne, Question répondrait « n » : ce serait un faux vert.
$qPareFeu = 'Une fenêtre du pare-feu Windows (« autoriser l''accès ») s''est-elle ouverte pendant l''audit du réseau ?'
if ($Auto) { Info "$qPareFeu (non vérifié : test sans personne)" }
elseif (Question $qPareFeu) { Bug 'Une fenêtre du pare-feu Windows (« autoriser l''accès ») s''est ouverte pendant l''audit du réseau' }
else { Ok 'Aucune fenêtre du pare-feu Windows pendant l''audit du réseau' }

Etape 'Tous les ports de cette machine (127.0.0.1)'
Lancer 'local-tous' @('appareils', '127.0.0.1', '-p', 'tous')

Etape 'Persistance suspecte : fausse tâche planifiée et fausse entrée de démarrage'
Info 'Une tâche et un raccourci du dossier Démarrage « PowerShell caché en base64 », et un programme dans C:\Users\Public, inoffensifs, retirés juste après.'
if (Question 'Faire ce test ?' 'o') {
    try {
        Register-ScheduledTask -TaskName 'vanguard-test-suspect' -Force `
            -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -enc VwByAGkAdABlAC0ASABvAHMAdAAgAHQAZQBzAHQA') `
            -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddYears(5)) | Out-Null
        Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'vanguard-test-suspect' -Value 'C:\Users\Public\vanguard-test.exe /q'
        # 0.82 : un raccourci du dossier Démarrage lu sans PowerShell, vers PowerShell caché en base64.
        $raccourciSuspect = Join-Path ([Environment]::GetFolderPath('Startup')) 'vanguard-test-suspect.lnk'
        $r = (New-Object -ComObject WScript.Shell).CreateShortcut($raccourciSuspect)
        $r.TargetPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $r.Arguments = '-NoProfile -w hidden -enc VwByAGkAdABlAC0ASABvAHMAdAAgAHQAZQBzAHQA'
        $r.Save()
        Lancer 'machine-persistance' @('audit')
        $sortie = Sortie 'machine-persistance'
        if ($sortie -match '(?s)vanguard-test-suspect.*base64|base64.*vanguard-test-suspect') { Ok 'Tâche suspecte repérée' } else { Bug 'Tâche suspecte NON repérée' }
        if ($sortie -match 'Public') { Ok 'Entrée de démarrage suspecte repérée' } else { Bug 'Entrée de démarrage suspecte NON repérée' }
        if ($sortie -match 'Suspicious shortcut in the Startup folder|Raccourci suspect dans le dossier Démarrage' -and $sortie -match 'vanguard-test-suspect\.lnk') { Ok 'Raccourci suspect du dossier Démarrage repéré (lu sans PowerShell)' }
        else { Bug 'Raccourci suspect du dossier Démarrage NON repéré' }
    } catch { Bug "Test de persistance impossible : $($_.Exception.Message)" }
    finally {
        Unregister-ScheduledTask -TaskName 'vanguard-test-suspect' -Confirm:$false -ErrorAction SilentlyContinue
        Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'vanguard-test-suspect' -ErrorAction SilentlyContinue
        if ($raccourciSuspect) { Remove-Item -LiteralPath $raccourciSuspect -Force -ErrorAction SilentlyContinue }
        Info 'Fausse tâche, fausse entrée et faux raccourci retirés.'
    }
}

Etape 'Intégrité des fichiers critiques'
Lancer 'integrite-reference' @('integrite')
Lancer 'integrite-verification' @('integrite')
if ((Sortie 'integrite-verification') -match 'identiques|identical') { Ok '2e passage identique à la référence' } else { Bug '2e passage différent de la référence' }

Etape 'Diagnostic de l''ordinateur'
Lancer 'diagnostic' @('diagnostic')
$d = Sortie 'diagnostic'
if ($d -match 'Blue screens|Écrans bleus') { Ok 'Section des problèmes récents présente' } else { Bug 'Section des problèmes récents ABSENTE' }
if ($d -match 'PowerShell is not responding|PowerShell ne répond pas') { Bug 'Lecture PowerShell en échec' }

Etape 'Logiciels : liste et menu, rien installé'
Lancer 'logiciels-liste' @('logiciels', '--liste')
$l = Sortie 'logiciels-liste'
# Une ligne par logiciel : « ✔ » (installé, en couleur) ou « · ».
$n = ([regex]::Matches($l, '(?m)^\s+(?:\x1b\[[0-9;]*m)?[✔·](?:\x1b\[[0-9;]*m)? ')).Count
if ($n -ge 30) { Ok "$n logiciels proposés" } else { Bug "Liste des logiciels trop courte ($n)" }
if ($l -match 'winget, Mozilla\.Firefox') { Ok 'Firefox proposé par winget' } else { Bug 'Firefox absent de la liste' }
if ($l -match 'PowerShell ne répond pas|PowerShell is not responding') { Bug 'Lecture des logiciels installés en échec' }
# Windows 11 a Windows Terminal d'office : application du Store, reconnue par son paquet (pas dans le registre).
if ([Environment]::OSVersion.Version.Build -ge 22000) {
    if ($l -match '(?m)✔(?:\x1b\[[0-9;]*m)? Windows Terminal') { Ok 'Windows Terminal reconnu (application du Store)' } else { Bug 'Windows Terminal, présent sur Windows 11, pas reconnu' }
}
LancerAvec 'logiciels' @('logiciels') "`n"
if ((Sortie 'logiciels') -match 'Pack de départ|Starter pack') { Ok 'Menu des logiciels affiché' } else { Bug 'Menu des logiciels absent' }

Etape 'Nettoyer le système : place à gagner, rien effacé'
Lancer 'nettoyer-liste' @('nettoyer', '--liste')
$n = Sortie 'nettoyer-liste'
if ($n -match 'rien n.a été effacé|nothing was deleted') { Ok 'Liste du nettoyage affichée' } else { Bug 'Liste du nettoyage absente' }
if ($n -match '(?m)(Vos fichiers temporaires|Your temporary files)\s+\S') { Ok 'Fichiers temporaires mesurés' } else { Bug 'Fichiers temporaires non mesurés' }
if ($n -match 'Disque du système|System disk') { Ok 'Place libre du disque lue' } else { Bug 'Place libre du disque non lue (PowerShell)' }

Etape 'Test de connexion'
Lancer 'connexion' @('test-connexion')
if ((Sortie 'connexion') -match 'Mbit/s') { Ok 'Débit mesuré' } else { Bug 'Débit non mesuré' }

Etape 'Mots de passe fuités'
if ($Auto) { Sautee 'Sautée : il faut taper un mot de passe (test avec questions).' } else {
    Write-Host '      Tape « password » (il doit être trouvé des millions de fois), puis Entrée seule pour terminer.' -ForegroundColor Yellow
    Vider-Clavier
    & $exe fuite-mot-de-passe
    Constat 'La saisie était-elle masquée et « password » trouvé dans des fuites ?'
}

Etape 'Réparer (liste), mises à jour (vérification seule), gaming, courriel refusé'
LancerAvec 'reparer' @('reparer') "`n"
$n = ([regex]::Matches(((Sortie 'reparer') -replace '\x1b\[[0-9;]*m', ''), '(?m)^\s+\d+\s{2,}\S')).Count
if ($n -gt 0) { Ok "$n réparation(s) proposée(s)" } else { Bug 'Liste des réparations vide' }
LancerSurveille 'maj' @('mises-a-jour') "n`nn`nn`nn`nn`n"
# 0.82 : winget lancé par son chemin complet (celui du Store), sans PowerShell autour ; Windows Update par son API.
$mj = ((Sortie 'maj') -replace '\x1b\[[0-9;]*m', '') -replace '\s+', ' '
if ($mj -match 'Programs up to date \(winget\)|Programmes à jour \(winget\)|\d+ (program\(s\) to update|programme\(s\) à mettre à jour)') { Ok "Programmes lus par winget : $($Matches[0])" }
elseif ($mj -match 'winget is not responding|winget ne répond pas|winget failed \(code [^)]*\)|winget en erreur \(code [^)]*\)|winget absent') { Bug "Programmes : $($Matches[0])" }
else { Bug 'Programmes (winget) : rien dit' }
$wingetStore = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'
if (Get-Item -LiteralPath $wingetStore -Force -ErrorAction SilentlyContinue) {
    $wingetPs = @($script:powershells | Where-Object { $_ -match 'winget' })
    if ($wingetPs.Count) { Bug "winget relancé par PowerShell : $($wingetPs[0])" } else { Ok 'winget lancé par son chemin complet, sans PowerShell' }
} else { Info "winget du Store absent ($wingetStore) : PowerShell en secours, comme prévu" }
Info "maj : $(@($script:powershells).Count) PowerShell lancé(s) en secours$(if ($script:powershells) { ' : ' + ((@($script:powershells | Select-Object -Unique) | Select-Object -First 4) -join ' / ') })"
# Windows Update : la même recherche, faite ici par l'API COM ; une recherche qui échoue n'est jamais « à jour ».
$rechercheWu = Lire-Windows { $r = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'"); "$($r.ResultCode)|$($r.Updates.Count)" } 240
Info "Recherche Windows Update faite ici (code|nombre, 2 = réussie) : $rechercheWu"
$wuFaite = $rechercheWu -match '^[23]\|(\d+)$'
$wuNombre = if ($wuFaite) { [int]$Matches[1] } else { -1 }
if ($mj -match 'search failed, offline\?|recherche impossible, hors ligne') {
    if ($wuFaite) { Bug "Windows Update : Vanguard dit la recherche impossible, Windows l'a faite ($wuNombre trouvée(s))" }
    else { Ok 'Windows Update : recherche impossible, dite impossible (jamais « à jour »)' }
} elseif ($mj -match 'Windows up to date|Windows à jour') {
    if ($wuNombre -eq 0) { Ok 'Windows à jour : la recherche de Windows Update n''en trouve aucune non plus' }
    elseif ($wuNombre -gt 0) { Bug "Vanguard dit Windows à jour, Windows Update en trouve $wuNombre" }
    else { Bug "Vanguard dit « à jour » alors que la recherche de Windows Update échoue ici ($rechercheWu)" }
} elseif ($mj -match '(\d+) (update\(s\) pending|mise\(s\) à jour en attente)') {
    $vuesVanguard = [int]$Matches[1]
    if ($wuNombre -eq 0) { Bug "Vanguard : $vuesVanguard mise(s) à jour en attente, Windows Update aucune" }
    elseif ($wuNombre -eq $vuesVanguard) { Ok "Windows Update : $vuesVanguard en attente, comme la recherche faite ici" }
    else { Info "Windows Update : Vanguard $vuesVanguard, recherche faite ici $wuNombre (la liste change d'une recherche à l'autre)" }
} else { Bug 'Windows Update : rien dit' }
Info 'Recherche hors ligne pas essayée : couper le réseau de la VM demande les droits d''administrateur (à la main : « impossible », jamais « à jour »).'
LancerAvec 'gaming' @('jeux') "`n"
LancerAvec 'courriel' @('fuite-courriel') "test@example.com`nn`n"
if ((Sortie 'courriel') -match 'XposedOrNot|accord|consent') { Ok 'Accord demandé avant d''envoyer l''adresse' } else { Bug 'Accord NON demandé avant l''envoi' }

Etape 'Données : sauvegarde puis restauration'
$sauvegarde = Join-Path $res 'sauvegarde.json'
Lancer 'sauvegarder' @('exporter', $sauvegarde)
Lancer 'restaurer' @('importer', $sauvegarde)
if ((Test-Path $sauvegarde) -and (Get-Item $sauvegarde).Length -gt 0) { Ok 'Sauvegarde écrite puis relue' } else { Bug 'Sauvegarde ABSENTE' }

Etape 'Nommer la box trouvée par le scan, puis retirer le surnom'
try {
    $box = ((Sortie 'reseau-json' | ConvertFrom-Json).hotes | Where-Object { $_.role -eq 'passerelle' } | Select-Object -First 1).ip
    if ($box) {
        Lancer 'nommer' @('nommer', $box, 'box', 'de', 'test')
        if ((Sortie 'nommer') -match 'box de test') { Ok "Surnom donné à la box ($box)" } else { Bug "Surnom NON donné à la box ($box)" }
        Lancer 'nommer-retrait' @('nommer', $box)
    } else { Sautee 'Pas de box dans le scan : étape sautée.' }
} catch { Bug "Scan illisible ($($_.Exception.Message))" }

Etape 'Antivirus d''un dossier propre (Defender, analyse ciblée)'
$propre = Join-Path $env:TEMP 'vanguard-dossier-propre'
New-Item -ItemType Directory -Force $propre | Out-Null
Set-Content -Path (Join-Path $propre 'note.txt') -Value 'fichier sans danger' -Encoding UTF8
LancerAvec 'antivirus-dossier' @('antivirus', $propre) "n`nn`n"
if ((Sortie 'antivirus-dossier') -match 'No malware found|Aucun malware|aucune menace|found no threats') { Ok 'Dossier analysé, rien trouvé' } else { Bug 'Résultat de l''analyse introuvable' }
Remove-Item $propre -Recurse -Force -ErrorAction SilentlyContinue

Etape 'Menu : chaque groupe ouvert puis refermé'
LancerAvec 'menu' @() "4`n`n5`n`n6`n`n7`n`n8`n`n9`n`n10`n`n11`n`n12`n`n13`n`nq`n"
$m = Sortie 'menu'
# Une ligne propre à chaque sous-menu (le titre d'un groupe s'affiche aussi au menu principal), majuscules comprises.
$sousMenus = [ordered]@{
    'Cet ordinateur' = "Fiche de l'ordinateur|Computer specs"
    'Réseau et Internet' = 'Surveillance toutes les heures|Hourly monitoring'
    'Virus et logiciels espions' = 'Analyse antivirus|Antivirus scan'
    'Arnaques et vie privée' = 'Ce lien est-il dangereux|Is this link dangerous'
    'Bloquer et réagir' = 'Blocage des menaces|Threat blocking'
    'Données et sauvegardes' = 'Copier mes fichiers|Copy my files'
    'Guide des commandes' = 'Tous les systèmes|All systems'
    'Dépanner pas à pas' = "Pas d'Internet|No Internet"
    'Optimiser et installer' = 'Nettoyer le système|Clean up the system'
    'Vanguard' = 'Retirer Vanguard|Remove Vanguard'
}
foreach ($g in $sousMenus.Keys) {
    if ($m -cmatch $sousMenus[$g]) { Ok "Sous-menu « $g » ouvert" } else { Bug "Sous-menu « $g » PAS ouvert" }
}
# Entrée fermée (comme Ctrl-D) : Vanguard doit quitter, pas tourner en boucle (bug corrigé en 0.9.7).
$vide = Join-Path $res 'vide.txt'
Set-Content -Path $vide -Value '' -NoNewline
$p = Start-Process -FilePath $exe -RedirectStandardInput $vide -RedirectStandardOutput (Join-Path $res 'menu-eof.out.txt') -NoNewWindow -PassThru
# Sans garder le handle tout de suite, PowerShell ne sait plus lire le code de sortie (il restait vide).
$null = $p.Handle
if ($p.WaitForExit(10000)) { Ok 'Quitte quand l''entrée est fermée' }
else { $p.Kill(); Bug 'Boucle sans fin quand l''entrée est fermée' }

Etape 'Pourquoi c''est lent ? Fiche de l''ordinateur'
LancerAvec 'lenteur' @('lenteur') "`n"
$t = Sortie 'lenteur'
if ($t -match "POURQUOI C'EST LENT|WHY IS IT SLOW") { Ok 'Instantané affiché' } else { Bug 'Instantané ABSENT' }
if ($t -match 'PowerShell ne répond pas|PowerShell is not responding') { Bug 'Lecture PowerShell en échec' }
Lancer 'fiche-json' @('fiche-ordinateur', '--json')
try {
    $f = Sortie 'fiche-json' | ConvertFrom-Json
    if ($f.processeur) { Ok "Processeur : $($f.processeur)" } else { Bug 'Processeur non lu' }
    if ($f.memoire) { Ok 'Mémoire lue' } else { Bug 'Mémoire non lue' }
    if (@($f.disques).Count) { Ok "$(@($f.disques).Count) disque(s) lu(s)" } else { Bug 'Disques non lus' }
} catch { Bug "fiche --json illisible : $($_.Exception.Message)" }

Etape 'Autodiagnostic : lectures croisées, rien changé'
# En administrateur (ce script l'est) : BitLocker se compare aussi, ce qu'un compte sans droits ne peut pas.
Lancer 'autotest-json' @('autotest', '--json')
try {
    $a = Sortie 'autotest-json' | ConvertFrom-Json
    if ($a.outil -eq 'AUT-VAN-001') { Ok "Autotest : $($a.verdict), $($a.regles.ont_repondu)/$($a.regles.essayees) règles ont répondu" } else { Bug 'Autotest : rapport inattendu' }
    foreach ($c in @($a.croisees)) {
        if ($c.verdict -eq 'different') { Bug "Lecture croisée $($c.id) ($($c.outil)) : $($c.genre)" }
        elseif ($c.verdict -eq 'saute') { Info "Lecture croisée $($c.id) sautée : $($c.raison)" }
        else { Ok "Lecture croisée $($c.id) : $($c.verdict)" }
    }
    if ($a.preuve.verdict -eq 'change') { Bug "Autotest : le dossier de Vanguard a changé pendant l'essai ($($a.preuve.fichiers -join ', '))" }
    elseif ($a.preuve.verdict -eq 'rien-change') { Ok 'Autotest : rien changé (empreintes)' }
    else { Info "Autotest : preuve $($a.preuve.verdict)" }
    if (@($a.regles.plantees).Count) { Bug "Autotest : règle(s) plantée(s) : $(@($a.regles.plantees) -join ', ')" }
} catch { Bug "autotest --json illisible : $($_.Exception.Message)" }

Etape 'Programmes au démarrage : liste, rien retiré sans accord'
$runAvant = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue | Out-String
LancerAvec 'demarrage' @('demarrage') "q`n"
if ((Sortie 'demarrage') -match 'Programmes au démarrage|Startup programs') { Ok 'Liste affichée' } else { Bug 'Liste ABSENTE' }
$runApres = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue | Out-String
if ($runAvant -eq $runApres) { Ok 'Rien retiré sans accord' } else { Bug 'Démarrage modifié sans accord' }

Etape 'Entretien du mois, et ce que Vanguard a appris'
Lancer 'entretien' @('entretien')
if ((Sortie 'entretien') -match 'Entretien du mois|Monthly check-up') { Ok 'Résumé du mois affiché' } else { Bug 'Résumé du mois ABSENT' }
LancerAvec 'appris' @('appris') "`n"
if ((Sortie 'appris') -match 'Ce que Vanguard a appris|What Vanguard has learned') { Ok 'Page « appris » affichée' } else { Bug 'Page « appris » ABSENTE' }

Etape 'Réseau : Wi-Fi encombré, type de NAT, caméras, listes noires refusées'
Lancer 'canaux' @('canaux-wifi')
if ((Sortie 'canaux') -match 'Wi-Fi encombré|Crowded Wi-Fi') { Ok 'Wi-Fi examiné (la VM n''en a pas : la sortie doit le dire)' } else { Bug 'Wi-Fi encombré : rien affiché' }
Lancer 'nat' @('nat')
if ((Sortie 'nat') -match 'Type de NAT|NAT type') { Ok 'Type de NAT examiné' } else { Bug 'Type de NAT : rien affiché' }
Lancer 'cameras' @('cameras-cachees')
if ((Sortie 'cameras') -match 'Caméras cachées|Hidden cameras') { Ok 'Recherche de caméras faite' } else { Bug 'Caméras : rien affiché' }
LancerAvec 'listes-noires' @('listes-noires') "n`n"
if ((Sortie 'listes-noires') -match "Rien n'a été envoyé|Nothing was sent") { Ok 'Accord demandé, refus respecté' } else { Bug 'Refus des listes noires PAS respecté' }

Etape 'DNS le plus rapide : mesuré, rien changé sans accord'
$dnsAvant = Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table -AutoSize | Out-String
LancerAvec 'dns-rapide' @('dns-rapide') "n`nn`n"
if ((Sortie 'dns-rapide') -match 'DNS le plus rapide|Fastest DNS') { Ok 'DNS mesurés' } else { Bug 'DNS le plus rapide : rien affiché' }
$dnsApres = Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table -AutoSize | Out-String
if ($dnsAvant -eq $dnsApres) { Ok 'DNS inchangés (refusé)' } else { Bug 'DNS changés malgré le refus' }

Etape 'Qui parle à Internet ? Ce lien est-il dangereux ?'
Lancer 'sortantes' @('connexions-sortantes')
$s = Sortie 'sortantes'
if ($s -match 'Qui parle à Internet|Who talks to the Internet') { Ok 'Connexions listées' } else { Bug 'Connexions : rien affiché' }
if ($s -match 'PowerShell ne répond pas|PowerShell is not responding') { Bug 'Lecture PowerShell en échec' }
# Un « & » dans le lien : il ne doit pas couper la commande.
LancerAvec 'lien' @('lien', 'https://paypal.com.secure-login.example/connexion?a=1&b=2') "n`n"
$l = Sortie 'lien'
if ($l -match 'secure-login\.example') { Ok 'Vrai site trouvé : secure-login.example' } else { Bug 'Vrai site PAS trouvé' }
if ($l -match 'Sous-domaine trompeur|Misleading subdomain') { Ok 'Sous-domaine trompeur signalé' } else { Bug 'Sous-domaine trompeur PAS signalé' }
if ($l -match "Rien n'a été envoyé|Nothing was sent") { Ok 'Rien envoyé sans accord' } else { Bug 'Refus de l''examen en ligne PAS respecté' }

Etape 'Vérifier un fichier téléchargé : bonne, puis mauvaise empreinte'
$fichier = Join-Path $env:TEMP 'vanguard-telechargement-test.txt'
Set-Content -Path $fichier -Value 'contenu de test' -Encoding UTF8
$empreinte = (Get-FileHash $fichier -Algorithm SHA256).Hash.ToLower()
LancerAvec 'verifier-bon' @('verifier-fichier', $fichier, $empreinte) "n`nn`nn`n"
$v = Sortie 'verifier-bon'
if ($v -match '\) correspond :|\) matches:' -and $v -notmatch 'ne correspond pas|does not match') { Ok 'Bonne empreinte reconnue' } else { Bug 'Bonne empreinte PAS reconnue' }
LancerAvec 'verifier-faux' @('verifier-fichier', $fichier, ('0' * 64)) "n`nn`nn`n"
if ((Sortie 'verifier-faux') -match 'ne correspond pas|does not match') { Ok 'Mauvaise empreinte signalée' } else { Bug 'Mauvaise empreinte PAS signalée' }
Remove-Item $fichier -Force -ErrorAction SilentlyContinue

Etape 'Fichiers-pièges : posés, un renommé comme par un rançongiciel, retirés'
$dossiersPieges = @([Environment]::GetFolderPath('MyDocuments'), [Environment]::GetFolderPath('MyPictures'), [Environment]::GetFolderPath('Desktop'))
if (Question 'Faire ce test (six fichiers posés puis retirés dans Documents, Images et Bureau) ?' 'o') {
    LancerAvec 'pieges-poser' @('pieges') "o`n"
    if ((Sortie 'pieges-poser') -match 'fichiers-pièges posés|decoy files placed') { Ok 'Fichiers-pièges posés' } else { Bug 'Fichiers-pièges PAS posés' }
    foreach ($d in $dossiersPieges) { Info "$d : $(@(Get-ChildItem $d -Filter '!Vanguard*' -ErrorAction SilentlyContinue).Count) fichier(s)-piège(s)" }
    # Accès contrôlé aux dossiers actif (1) : Documents et Images sont déjà protégés par Windows ; Vanguard doit le dire
    # et ne pas y écrire (Windows l'aurait bloqué, alerte à l'appui). Le Bureau, lui, n'est pas protégé d'office.
    $cfa = try { [int](Get-MpPreference).EnableControlledFolderAccess } catch { -1 }
    Info "Accès contrôlé aux dossiers : $cfa (0 coupé, 1 actif, 2 audit, -1 illisible)"
    $sortiePieges = Sortie 'pieges-poser'
    if ($cfa -eq 1) {
        if ($sortiePieges -match 'déjà protégé par|already protected by Windows') { Ok 'Dossiers protégés par Windows dits comme tels, sans piège' }
        else { Bug 'Dossiers protégés par Windows PAS signalés' }
    }
    if ($sortiePieges -match 'Pas de fichier-piège dans|No decoy file in') { Bug "Dossier refusé : $(($sortiePieges -split "`n" | Select-String 'No decoy file in|Pas de fichier-piège dans') -join ' / ')" }
    # Le premier dossier qui a reçu ses pièges : l'accès contrôlé aux dossiers de Defender peut en refuser.
    $piege = Get-ChildItem $dossiersPieges -Filter '!Vanguard*.txt' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($piege) {
        Rename-Item $piege.FullName ($piege.Name + '.locked')
        LancerAvec 'pieges-etat' @('pieges') "`n"
        if ((Sortie 'pieges-etat') -match 'RENOMMÉ en|RENAMED to') { Ok 'Fichier-piège renommé repéré' } else { Bug 'Fichier-piège renommé PAS repéré' }
        Rename-Item (Join-Path $piege.DirectoryName ($piege.Name + '.locked')) $piege.Name
    } else { Bug 'Aucun fichier-piège posé' }
    LancerAvec 'pieges-retirer' @('pieges', '--retirer') "o`n"
    if (Get-ChildItem $dossiersPieges -Filter '!Vanguard*' -ErrorAction SilentlyContinue) { Bug 'Fichiers-pièges ENCORE présents' } else { Ok 'Fichiers-pièges retirés' }
} else { Sautee 'Sautée.' }

Etape 'YARA : analyse d''un dossier par YARA-X, compilé dans Vanguard (rien à installer)'
# Depuis la 0.79, le moteur est dans le programme : aucune installation, aucune question, et rien de winget n'est cherché.
$dossierYara = Join-Path $env:TEMP 'vanguard-dossier-yara'
New-Item -ItemType Directory -Force $dossierYara | Out-Null
Set-Content -Path (Join-Path $dossierYara 'note.txt') -Value 'fichier sans danger' -Encoding UTF8
[IO.File]::WriteAllBytes((Join-Path $dossierYara 'outil.exe'), [byte[]](0x4D, 0x5A, 0x90, 0x00) + [Text.Encoding]::ASCII.GetBytes('programme sans danger'))
Lancer 'yara' @('yara', $dossierYara)
# Le texte est replié à 76 colonnes, chaque ligne finie par un code de couleur : les mots se cherchent sans couleurs,
# remis bout à bout.
$y = (Sortie 'yara') -replace '\x1b\[[0-9;]*m', '' -replace '\s+', ' '
if ($y -match 'Analyse de|Scanning') { Ok 'Analyse lancée' } else { Bug 'Analyse PAS lancée' }
if ($y -match "installer|install it|winget") { Bug 'Vanguard parle encore d''installer un moteur YARA' }
if ($y -match 'Aucun fichier ne correspond|No file matches') { Ok 'Dossier sans danger : rien trouvé, tout lu' }
elseif ($y -match 'illisible|unreadable') { Bug 'Des fichiers du dossier d''essai n''ont pas pu être lus' }
else { Bug 'Résultat de l''analyse YARA inattendu' }
# 0.84 : les empreintes de MalwareBazaar ne se téléchargent qu'avec la clé abuse.ch de la personne (Paramètres). Avec
# elle, l'analyse les compte ; sans elle, elle doit dire qu'elles n'ont pas été vérifiées faute de clé, jamais se taire.
# Une copie gardée d'avant sert encore sans clé : comptée, avec son rafraîchissement manqué dit.
if ($y -match '(?:ni aux|or the) ([0-9]+) (?:empreintes de MalwareBazaar|MalwareBazaar fingerprints)') {
    Ok "Empreintes de MalwareBazaar chargées : $($Matches[1])"
    if ($y -match 'non rafraîchies, la copie gardée a servi|not refreshed, the saved copy was used') { Info 'Empreintes de MalwareBazaar : copie gardée, pas rafraîchie (raison dite dans yara.out.txt)' }
}
elseif ($y -match 'MalwareBazaar non vérifiées : clé abuse\.ch manquante|MalwareBazaar fingerprints not checked: abuse\.ch key missing') { Ok 'Sans clé abuse.ch : empreintes de MalwareBazaar dites non vérifiées, les 308 règles seules' }
elseif ($y -match '(?:Empreintes de MalwareBazaar|MalwareBazaar fingerprints) (.+?) ?: (?:seules les 308|only the 308)') { Bug "Empreintes de MalwareBazaar pas utilisées : $($Matches[1])" }
else { Bug 'Empreintes de MalwareBazaar : rien dit' }
Etape 'Empreintes de MalwareBazaar : un fichier d''essai reconnu par son empreinte exacte, hors ligne, quarantaine refusée'
# L'empreinte du fichier d'essai dans la copie gardée des 48 dernières heures, puis l'analyse hors ligne : il doit être
# reconnu sans aucune règle. Sans clé, Vanguard ne télécharge rien mais lit cette copie : posée pour l'essai si elle
# manque, puis retirée ; sinon complétée, puis remise telle quelle, heure comprise (Vanguard la rafraîchit d'après
# cette heure).
$recentes = Join-Path $env:LOCALAPPDATA 'vanguard\malwarebazaar\recentes.txt'
$dossierRecentes = Split-Path -Parent $recentes
$avaitRecentes = Test-Path -LiteralPath $recentes -PathType Leaf
$avaitDossierRecentes = Test-Path -LiteralPath $dossierRecentes -PathType Container
$essaiEmpreinte = Join-Path $dossierYara 'facture.pdf.exe'
Set-Content -Path $essaiEmpreinte -Value "fichier d'essai de Vanguard $(Get-Date -Format o)" -Encoding UTF8
if ($avaitRecentes) {
    Info 'Copie des empreintes récentes déjà là : complétée pour l''essai, puis remise telle quelle'
    $copieRecentes = [IO.File]::ReadAllBytes($recentes)
    $heureRecentes = (Get-Item -LiteralPath $recentes).LastWriteTimeUtc
} else {
    Info 'Aucune copie des empreintes récentes (sans clé abuse.ch, rien ne se télécharge) : posée pour l''essai, puis retirée'
    New-Item -ItemType Directory -Force $dossierRecentes | Out-Null
}
try {
    # Une ligne à part même si la copie ne finit pas par un saut de ligne ; Add-Content crée la copie qui manque.
    Add-Content -LiteralPath $recentes -Value ("`r`n" + (Get-FileHash $essaiEmpreinte -Algorithm SHA256).Hash.ToLower()) -Encoding ASCII
    $env:VANGUARD_HORS_LIGNE = '1'
    LancerAvec 'yara-empreinte' @('yara', $dossierYara) "n`n"
} finally {
    Remove-Item Env:VANGUARD_HORS_LIGNE -ErrorAction SilentlyContinue
    if ($avaitRecentes) {
        [IO.File]::WriteAllBytes($recentes, $copieRecentes)
        (Get-Item -LiteralPath $recentes).LastWriteTimeUtc = $heureRecentes
    } else {
        Remove-Item -LiteralPath $recentes -Force -ErrorAction SilentlyContinue
        # Le dossier posé pour l'essai, seulement s'il est resté vide : jamais ce que Vanguard y aurait mis entre-temps.
        if (-not $avaitDossierRecentes -and -not (Get-ChildItem -LiteralPath $dossierRecentes -Force -ErrorAction SilentlyContinue)) {
            Remove-Item -LiteralPath $dossierRecentes -Force -ErrorAction SilentlyContinue
        }
    }
}
$ye = (Sortie 'yara-empreinte') -replace '\x1b\[[0-9;]*m', '' -replace '\s+', ' '
if ($ye -match 'facture\.pdf\.exe' -and $ye -match 'empreinte exacte|exact fingerprint') { Ok 'Fichier d''essai reconnu par son empreinte exacte' } else { Bug 'Fichier d''essai PAS reconnu par son empreinte' }
if ($ye -match "Rien n'a été fait|Nothing was done") { Ok 'Quarantaine refusée : rien fait' } else { Bug 'Refus de la quarantaine PAS respecté' }
if (Test-Path -LiteralPath $essaiEmpreinte) { Ok 'Fichier d''essai laissé en place' } else { Bug 'Fichier d''essai déplacé malgré le refus' }
if ($avaitRecentes) {
    $memeContenu = (Get-FileHash -LiteralPath $recentes).Hash -eq (Get-FileHash -InputStream ([IO.MemoryStream]::new($copieRecentes))).Hash
    $memeHeure = (Get-Item -LiteralPath $recentes).LastWriteTimeUtc -eq $heureRecentes
    if ($memeContenu -and $memeHeure) { Ok 'Copie des empreintes remise comme avant, heure comprise' } else { Bug "Copie des empreintes PAS remise comme avant (contenu : $memeContenu, heure : $memeHeure)" }
} elseif (Test-Path -LiteralPath $recentes) { Bug "Copie des empreintes posée pour l'essai PAS retirée ($recentes)" }
else { Ok 'Copie des empreintes posée pour l''essai retirée' }
Remove-Item $dossierYara -Recurse -Force -ErrorAction SilentlyContinue

Etape 'Collecter les traces (0.79) : dossier daté, LISEZMOI, manifeste juste, rien gardé'
$dossierTraces = Join-Path $env:TEMP 'vanguard-traces-test'
Remove-Item $dossierTraces -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $dossierTraces | Out-Null
LancerSurveille 'traces' @('depanner', 'traces', $dossierTraces)
$tr = Sortie 'traces'
if ($tr -match 'Collecter les traces|Collect the traces') { Ok 'Collecte lancée' } else { Bug 'Collecte PAS lancée' }
$dates = @(Get-ChildItem -LiteralPath $dossierTraces -Directory -Filter 'traces-*')
if ($dates.Count -eq 1) {
    $d = $dates[0].FullName
    foreach ($f in 'LISEZMOI.txt', 'MANIFESTE.txt', '01-processus.txt', '02-reseau.txt', '03-demarrage.txt', '04-comptes.txt', '06-fichiers-recents.txt', 'CHRONOLOGIE.txt') {
        if (Test-Path -LiteralPath (Join-Path $d $f)) { Ok "$f écrit" } else { Bug "$f ABSENT" }
    }
    # 0.83 : la chronologie de l'incident, du plus ancien au plus récent, une ligne par événement (date, source, quoi).
    $chrono = @(Get-Content -LiteralPath (Join-Path $d 'CHRONOLOGIE.txt') -Encoding UTF8 -ErrorAction SilentlyContinue)
    $evenements = @($chrono | Where-Object { $_ -match '^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d' })
    $dates = @($evenements | ForEach-Object { $_.Substring(0, 19) })
    $triees = @($dates | Sort-Object)
    if (-not $chrono.Count -or $chrono[0] -notmatch '^# Vanguard') { Bug 'CHRONOLOGIE.txt sans son en-tête' }
    elseif (-not $evenements.Count) { Bug 'CHRONOLOGIE.txt sans aucun événement' }
    elseif (($dates -join '|') -ne ($triees -join '|')) { Bug 'CHRONOLOGIE.txt pas dans l''ordre du temps' }
    else {
        $parSource = $evenements | ForEach-Object { ($_ -split "`t")[1] } | Group-Object | ForEach-Object { "$($_.Name) $($_.Count)" }
        Ok "Chronologie : $($evenements.Count) événement(s) dans l'ordre ($($parSource -join ', '))"
    }
    # Chaque ligne du manifeste : « empreinte  nom », l'empreinte recalculée ici par Windows.
    $fausses = @(Get-Content -LiteralPath (Join-Path $d 'MANIFESTE.txt') -Encoding UTF8 | ForEach-Object {
        $empreinte, $nom = $_ -split '  ', 2
        $calculee = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $d $nom)).Hash
        if ($calculee -ne $empreinte.ToUpper()) { $nom }
    })
    if ($fausses.Count -eq 0) { Ok 'Manifeste juste (Get-FileHash)' } else { Bug "Manifeste FAUX pour : $($fausses -join ', ')" }
    $evtx = @(Get-ChildItem -LiteralPath $d -Filter '05-*.evtx')
    if ($evtx.Count) { Ok "$($evtx.Count) journal(aux) exporté(s) en .evtx" } else { Bug 'Aucun journal exporté' }
    if ($tr -match 'Journal de sécurité : réservé|Security log: administrator only') { Info 'Journal de sécurité réservé à l''administrateur (dit)' }
    $processus = @(Get-Content -LiteralPath (Join-Path $d '01-processus.txt') -Encoding UTF8 | Where-Object { $_ -match '^\d+\t' })
    $avecEmpreinte = @($processus | Where-Object { ($_ -split "`t")[4] -match '^[0-9a-f]{64}$' })
    if ($processus.Count -gt 20 -and $avecEmpreinte.Count -gt 5) { Ok "$($processus.Count) processus, $($avecEmpreinte.Count) avec empreinte" }
    else { Bug "Processus : $($processus.Count), avec empreinte : $($avecEmpreinte.Count)" }
    # 0.82 : les processus lus par WMI, le compte de chacun dans son jeton, sans PowerShell.
    $moi = @($processus | Where-Object { ($_ -split "`t")[0] -eq "$PID" }) | Select-Object -First 1
    $compteMoi = if ($moi) { ($moi -split "`t")[2] } else { '' }
    if (-not $moi) { Bug "Ce test (PID $PID) absent de 01-processus.txt" }
    elseif ($compteMoi -match "(^|\\)$([regex]::Escape($env:USERNAME))$") { Ok "Colonne du compte : ce test tourne sous « $compteMoi »" }
    else { Bug "Colonne du compte : « $compteMoi » pour ce test, au lieu de $env:USERNAME" }
    Info "$(@($processus | Where-Object { ($_ -split "`t")[2] }).Count) processus sur $($processus.Count) avec leur compte (sans droits : ceux des autres comptes cachés)"
    $processusPs = @($script:powershells | Where-Object { $_ -match 'Win32_Process|IncludeUserName' })
    if ($processusPs.Count) { Bug "Processus relus par PowerShell : $($processusPs[0])" } else { Ok 'Processus lus sans PowerShell (WMI et jetons)' }
} else { Bug "Dossier daté : $($dates.Count) trouvé(s) au lieu d'un" }
Remove-Item $dossierTraces -Recurse -Force -ErrorAction SilentlyContinue
if (Test-Path $dossierTraces) { Bug 'Dossier des traces ENCORE là' } else { Ok 'Dossier des traces retiré' }

Etape 'Copier mes fichiers : disque du système refusé, puis vraie copie vers le dossier partagé'
$refuse = Join-Path $env:TEMP 'vanguard-copie-test'
New-Item -ItemType Directory -Force $refuse | Out-Null
LancerAvec 'copier-refus' @('copier-fichiers', $refuse) "`nn`n"
if ((Sortie 'copier-refus') -match 'disque du système|system disk') { Ok 'Copie sur le disque du système refusée' } else { Bug 'Copie sur le disque du système PAS refusée' }
Remove-Item $refuse -Recurse -Force -ErrorAction SilentlyContinue
if (Question 'Faire une vraie copie de vos dossiers vers le dossier partagé (dans les résultats, effacée après) ?') {
    # Sur le Bureau : l'accès contrôlé aux dossiers de Defender, s'il est actif, empêche PowerShell d'écrire dans
    # Documents, et le témoin n'existerait pas. Le Bureau n'est pas protégé d'office.
    $temoin = Join-Path ([Environment]::GetFolderPath('Desktop')) 'vanguard-test-copie.txt'
    Set-Content -Path $temoin -Value "copie de test $(Get-Date -Format o)" -Encoding UTF8 -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $temoin)) { Info "Fichier témoin impossible à poser : $temoin" }
    $vers = Join-Path $res 'copie'
    New-Item -ItemType Directory -Force $vers | Out-Null
    LancerAvec 'copier' @('copier-fichiers', $vers) "`no`n"
    $copie = Get-ChildItem $vers -Recurse -Filter 'vanguard-test-copie.txt' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not (Test-Path -LiteralPath $temoin)) { Info 'Témoin absent : copie à l''identique non vérifiée.' }
    elseif ($copie -and (Get-FileHash $copie.FullName).Hash -eq (Get-FileHash $temoin).Hash) { Ok 'Fichier témoin copié à l''identique' }
    else { Bug 'Fichier témoin PAS copié à l''identique' }
    if ((Sortie 'copier') -match 'Copie terminée et vérifiée|Copy finished and checked') { Ok 'Copie vérifiée par Vanguard' } else { Bug 'Copie PAS vérifiée' }
    # Le test de restauration sur cette copie : relue sur le disque et comparée aux originaux.
    LancerAvec 'verifier-copie' @('verifier-copie', $vers) "`n"
    if ((Sortie 'verifier-copie') -match 'The copy reads back|La copie se relit') { Ok 'Copie relue et comparée (test de restauration)' } else { Bug 'Test de restauration de la copie en échec' }
    Remove-Item $temoin -Force -ErrorAction SilentlyContinue
    Remove-Item $vers -Recurse -Force -ErrorAction SilentlyContinue
} else { Sautee 'Vraie copie sautée.' }

Etape 'Corrections de la relecture (0.82) : petite copie relue sans cache, puis abîmée ; DNS IPv6 réglé à la main'
# Une copie fabriquée comme celle de « Copier mes fichiers » (dossier daté, compte rendu, originaux datés d'avant),
# sur le disque de la VM puis sur le dossier partagé (réseau). Des tailles hors des multiples du secteur : la relecture
# sans cache (FILE_FLAG_NO_BUFFERING) lit par blocs alignés. Puis un octet changé dans la copie : elle doit être abîmée.
function Copie-Fabriquee($base) {
    Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue
    $originaux = Join-Path $base 'originaux'
    $copie = Join-Path $base 'Vanguard-copy-essai'
    New-Item -ItemType Directory -Force $originaux, (Join-Path $copie 'originaux') | Out-Null
    $hasard = New-Object Random 82
    foreach ($f in @(@('a.txt', 13), @('b.bin', 5000), @('c.bin', 70001))) {
        $octets = New-Object byte[] $f[1]
        $hasard.NextBytes($octets)
        [IO.File]::WriteAllBytes((Join-Path $originaux $f[0]), $octets)
        [IO.File]::WriteAllBytes((Join-Path $copie "originaux\$($f[0])"), $octets)
        (Get-Item -LiteralPath (Join-Path $originaux $f[0])).LastWriteTime = (Get-Date).AddDays(-2)
    }
    # Le compte rendu : deux lignes d'en-tête, puis « dossier : chemin de l'original », une ligne vide.
    [IO.File]::WriteAllText((Join-Path $copie 'vanguard-copie.txt'), "File copy — Vanguard essai — $(Get-Date -Format 'yyyy-MM-dd HH:mm')`r`n`r`nDocuments : $originaux`r`n`r`n3 file(s) copied.`r`n")
    $copie
}
foreach ($lieu in @(@('disque de la VM', (Join-Path $env:TEMP 'vanguard-copie-relue')), @('dossier partagé', (Join-Path $res 'copie-relue')))) {
    $copie = Copie-Fabriquee $lieu[1]
    $nom = if ($lieu[0] -eq 'disque de la VM') { 'local' } else { 'partage' }
    LancerAvec "verifier-copie-$nom" @('verifier-copie', $copie) "`n"
    $vc = (Sortie "verifier-copie-$nom") -replace '\s+', ' '
    if ($vc -match '3 identical to the original|3 identique\(s\) à l.original' -and $vc -match 'The copy reads back|La copie se relit') { Ok "Copie relue sans cache ($($lieu[0])) : 3 fichiers identiques" }
    else {
        # Le premier fichier dit abîmé, avec sa raison (relecture sans cache refusée par ce disque, par exemple).
        $raison = [regex]::Match($vc, '✖ [^✖]{0,150}').Value
        Bug "Petite copie PAS relue comme identique ($($lieu[0]))$(if ($raison) { " : $raison" })"
    }
    $c = Join-Path $copie 'originaux\c.bin'
    $octets = [IO.File]::ReadAllBytes($c)
    $octets[70000] = $octets[70000] -bxor 0xFF
    [IO.File]::WriteAllBytes($c, $octets)
    LancerAvec "verifier-copie-$nom-abimee" @('verifier-copie', $copie) "`n"
    $vc = (Sortie "verifier-copie-$nom-abimee") -replace '\s+', ' '
    if ($vc -match 'c\.bin' -and $vc -match 'do not read back|ne se relisent pas') { Ok "Copie abîmée repérée ($($lieu[0])) : c.bin" } else { Bug "Copie abîmée PAS repérée ($($lieu[0]))" }
    Remove-Item -LiteralPath $lieu[1] -Recurse -Force -ErrorAction SilentlyContinue
}
# DNS IPv6 réglé à la main (Tcpip6\…\NameServer) : le poser demande les droits d'administrateur, que la passe n'a pas.
$dns6 = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces' -ErrorAction SilentlyContinue |
    ForEach-Object { (Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).NameServer } | Where-Object { $_ })
try { $dnsVu = (@((Sortie 'machine-json' | ConvertFrom-Json).constats | Where-Object categorie -eq 'DNS') | ForEach-Object message) -join ' / ' } catch { $dnsVu = '?' }
if ($dns6.Count) { Info "DNS IPv6 réglé à la main : $($dns6 -join ', ') ; Vanguard : « $dnsVu »" }
else { Info "DNS IPv6 manuel pas essayé : le poser (Set-DnsClientServerAddress) demande les droits d'administrateur ; Vanguard : « $dnsVu »" }

Etape 'Dépanner : pas de son, et les réglages du son ouverts par Vanguard'
# Un lien ouvert par Vanguard (ms-settings:sound), sauf en arrière-plan : rien ne doit surgir à l'écran.
$ouvrirReglages = if ($SansOuvrir -or $Auto) { 'n' } else { 'o' }
LancerAvec 'depanner-son' @('depanner', 'son') "1`n1`n$ouvrirReglages`nn`n`n"
$d = Sortie 'depanner-son'
if ($d -match 'Où manque le son|Where is the sound missing') { Ok 'Parcours « pas de son » suivi' } else { Bug 'Parcours « pas de son » PAS suivi' }
if ($d -match 'PowerShell ne répond pas|PowerShell is not responding|État du son illisible|Sound state not readable') { Bug 'État du son PAS lu (PowerShell)' }
if ($ouvrirReglages -eq 'o') { Start-Sleep -Seconds 2; Constat 'Les réglages du son de Windows se sont-ils ouverts ?' }
Lancer 'depanner-sujets' @('depanner', 'xyz')
if ((Sortie 'depanner-sujets') -match "Pas d'Internet|No Internet") { Ok 'Sujets listés pour un sujet inconnu' } else { Bug 'Sujets PAS listés' }

Etape 'Guide des commandes : une page, et la copie d''une commande'
Lancer 'guide-winget' @('guide', 'winget')
if ((Sortie 'guide-winget') -match 'winget upgrade --all') { Ok 'Page de winget affichée' } else { Bug 'Page de winget ABSENTE' }
$presseAvant = Get-Clipboard -Raw -ErrorAction SilentlyContinue
# « 10.6.7.2 » : guide, Windows 11 (6e système), winget (7e programme, après les six marches à suivre), sa 2e
# commande, dont la page s'ouvre ; « 1 » la copie, Entrée revient, « q » quitte.
LancerAvec 'guide-copie' @() "10.6.7.2`n1`n`nq`n"
# Le presse-papier de la VM est synchronisé avec Linux par xfreerdp : il peut se relire vide un instant. Trois lectures.
for ($i = 0; $i -lt 3; $i++) {
    $copiee = Get-Clipboard -Raw -ErrorAction SilentlyContinue
    if ($copiee) { break }
    Start-Sleep -Milliseconds 500
}
if ($copiee -and $copiee.Trim() -eq 'winget upgrade --all') { Ok 'Commande copiée dans le presse-papier (Set-Clipboard)' }
elseif ((Sortie 'guide-copie') -match 'Presse-papier inaccessible|Clipboard unavailable') { Info 'Presse-papier inaccessible ici (test en arrière-plan ?) : Vanguard l''a dit et a remontré la commande' }
elseif (-not $copiee -and (Sortie 'guide-copie') -match 'Copié|Copied') { Info 'Vanguard dit « copié », presse-papier non relu après 3 lectures (synchronisation de la VM)' }
else { Bug "Commande PAS copiée (presse-papier : « $copiee »)" }
if ($presseAvant) { Set-Clipboard -Value $presseAvant }
# « Lancer ici » : « 10.6.11.1 » ouvre ipconfig /all (Windows 11, 11e programme : ipconfig), « 2 » la lance dans
# PowerShell, Entrée revient de sa sortie puis de sa page, « q » quitte. Sa sortie doit arriver en entier, et sa fin dite.
LancerAvec 'guide-lancer' @() "10.6.11.1`n2`n`n`nq`n"
$lancee = Sortie 'guide-lancer'
if ($lancee -match 'IPv4' -and $lancee -match 'Done in|Terminée en') { Ok 'Commande du guide lancée ici, sortie montrée' }
else { Bug 'Lancer ici : sortie ou fin ABSENTE' }

Etape 'Surveillance : activation puis désactivation (Planificateur de tâches)'
Lancer 'surveillance-on' @('surveillance', 'on')
$tache = 'vanguard - surveillance du reseau'
if (Get-ScheduledTask -TaskName $tache -ErrorAction SilentlyContinue) { Ok 'Tâche planifiée créée' } else { Bug 'Tâche planifiée NON créée' }
Ref 'Tâche planifiée après activation' { Get-ScheduledTask -TaskName $tache | Select-Object TaskName, State, Description | Format-List; (Get-ScheduledTask -TaskName $tache).Actions | Format-List Execute, Arguments }
Lancer 'surveillance-off' @('surveillance', 'off')
if (Get-ScheduledTask -TaskName $tache -ErrorAction SilentlyContinue) { Bug 'Tâche planifiée ENCORE PRÉSENTE' } else { Ok 'Tâche planifiée retirée' }

Etape 'Notification « nouvel appareil »'
$base = Join-Path $env:LOCALAPPDATA 'vanguard\appareils.json'
if (Test-Path $base) {
    # On retire un appareil de la base de test : au scan suivant, il doit être signalé comme nouveau.
    $json = Get-Content $base -Raw -Encoding UTF8 | ConvertFrom-Json
    $retire = $null
    foreach ($r in $json.reseaux.PSObject.Properties) {
        $premier = $r.Value.appareils.PSObject.Properties | Select-Object -First 1
        if ($premier) { $retire = $premier.Name; $r.Value.appareils.PSObject.Properties.Remove($premier.Name); break }
    }
    $json | ConvertTo-Json -Depth 10 | Set-Content $base -Encoding UTF8
    Info "Appareil retiré de la base de test : $retire"
    if (-not $Auto) { Write-Host '      Regarde le coin de l''écran : une notification « Nouvel appareil » doit apparaître…' -ForegroundColor Yellow }
    # 0.82 : après le scan, l'audit rapide du réseau ; son état d'avant retiré, c'est son premier passage : il ne fait
    # que mémoriser, sans alerte.
    $etatAudit = Join-Path $env:LOCALAPPDATA 'vanguard\surveillance-audit.json'
    Remove-Item -LiteralPath $etatAudit -Force -ErrorAction SilentlyContinue
    $avantSurveiller = (Get-Date).AddSeconds(-1).ToString('yyyy-MM-dd HH:mm:ss')
    Lancer 'surveiller' @('surveiller')
    if (Test-Path -LiteralPath $etatAudit) { Ok 'Audit du réseau mémorisé (surveillance-audit.json)' } else { Bug 'surveillance-audit.json PAS écrit' }
    $alertesPasse = @(Get-Content -LiteralPath (Join-Path $env:LOCALAPPDATA 'vanguard\surveillance-alertes.jsonl') -Encoding UTF8 -ErrorAction SilentlyContinue |
        ForEach-Object { try { $_ | ConvertFrom-Json } catch { } } | Where-Object { $_.date -ge $avantSurveiller })
    $alertesAudit = @($alertesPasse | Where-Object { $_.titre -match 'opens a port to the Internet|ouvre un port vers Internet|DNS handed out by the router changed|DNS distribué par le routeur a changé|DNS answers hijacked|réponses DNS détournées|exposed over IPv6|exposé en IPv6|Wi-Fi less protected|Wi-Fi moins protégé' })
    if ($alertesAudit.Count) { Bug "Alerte de l'audit dès son premier passage : $($alertesAudit[0].titre)" }
    else { Ok "Premier passage de l'audit : aucune alerte ($($alertesPasse.Count) autre(s) alerte(s) de la passe)" }
    Start-Sleep -Seconds 3
    Constat 'Avez-vous vu la notification « Nouvel appareil sur votre réseau » ?'
} else {
    Sautee 'Pas de base créée par le scan : test de notification sauté.'
}

Etape 'Tableau de bord de la surveillance (0.81) : page écrite, sans navigateur'
# Après la surveillance ci-dessus : la page doit montrer sa dernière passe. --sans-ouvrir : rien ne surgit à l'écran.
$page = Join-Path $env:LOCALAPPDATA 'vanguard\tableau.html'
$avantTableau = Get-Date
Lancer 'tableau' @('tableau-de-bord', '--sans-ouvrir')
if ((Sortie 'tableau') -match 'Tableau de bord :|Dashboard:') { Ok 'Chemin de la page affiché' } else { Bug 'Chemin de la page PAS affiché' }
if ((Test-Path -LiteralPath $page) -and (Get-Item -LiteralPath $page).LastWriteTime -ge $avantTableau.AddSeconds(-2)) {
    Ok 'Page écrite dans le dossier de Vanguard'
    $html = Get-Content -LiteralPath $page -Raw -Encoding UTF8
    if ($html -match 'Surveillance du réseau|Network monitoring') { Ok 'Page lisible : titre présent' } else { Bug 'Page sans titre' }
    if ($html -match 'Rien à montrer pour l.instant|Nothing to show yet') {
        # Le scan du réseau a rempli la base des appareils : la page ne doit pas se dire vide.
        if (Test-Path $base) { Bug 'Page dite vide alors que des appareils sont connus' } else { Info 'Page vide : aucun appareil connu ni surveillance passée' }
    } elseif ($html -match 'Alertes par jour|Alerts by day') { Ok 'Alertes par jour, appareils et connexions affichés' }
    else { Bug 'Page sans la section des alertes' }
} else { Bug "Page PAS écrite ($page)" }

Etape 'Vérifier ma sauvegarde (0.81) : sous Windows, la marche à suivre de l''Historique des fichiers, rien écrit'
$notesSauvegarde = Join-Path $env:LOCALAPPDATA 'vanguard\sauvegarde.json'
$notesAvant = Test-Path -LiteralPath $notesSauvegarde
Lancer 'verifier-sauvegarde' @('verifier-sauvegarde')
$vs = (Sortie 'verifier-sauvegarde') -replace '\s+', ' '
if ($vs -match 'Vérifier la sauvegarde automatique|Check the automatic backup') { Ok 'Écran affiché' } else { Bug 'Écran ABSENT' }
if ($notesAvant) { Info 'Notes de sauvegarde déjà présentes : la marche à suivre peut différer' }
elseif ($vs -match 'Historique des fichiers|File History' -and $vs -match 'Non vérifié ici|Not checked here') { Ok 'Historique des fichiers : marche à suivre, dit non vérifié' }
else { Bug 'Marche à suivre de l''Historique des fichiers ABSENTE' }
if ((Test-Path -LiteralPath $notesSauvegarde) -eq $notesAvant) { Ok 'Rien écrit' } else { Bug 'Notes de sauvegarde créées par une simple vérification' }

Etape 'Ordinateur d''un proche (0.82) : personne âgée, peur d''un virus, réseau refusé, tout refusé'
# Ce qu'une correction acceptée par erreur changerait : pare-feu, démarrage du compte, réglages de Defender.
function Etat-Systeme {
    "pare-feu=$((Get-NetFirewallProfile | ForEach-Object { "$($_.Name):$($_.Enabled)" }) -join ',')"
    "run=$(Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue | Out-String)"
    $p = Get-MpPreference -ErrorAction SilentlyContinue
    "defender=$($p.EnableControlledFolderAccess),$($p.EnableNetworkProtection),$($p.PUAProtection),$($p.MAPSReporting)"
}
$etatAvant = Etat-Systeme | Out-String
$bureauProche = [Environment]::GetFolderPath('Desktop')
$motifPage = "Vanguard - * $(Get-Date -Format 'yyyy-MM-dd').html"
$pagesAvant = @(Get-ChildItem -LiteralPath $bureauProche -Filter $motifPage -ErrorAction SilentlyContinue | ForEach-Object FullName)
# Réponses : 1 personne âgée, 2 peur d'un virus, 1 réseau refusé ; Entrée seule à l'analyse antivirus (non), « y » à la
# recherche du faux technicien. Puis des lignes vides : chaque correction est sautée (non par défaut) et la page est
# posée sur le Bureau (oui par défaut). En arrière-plan, « n » partout : la page s'ouvrirait dans le navigateur.
$poserPage = -not $SansOuvrir
$avantProche = Get-Date
$reste = if ($poserPage) { "`n" * 80 } else { "n`n" * 80 }
LancerAvec 'proche' @('troubleshoot', 'relative') ("1`n2`n1`n`ny`n" + $reste)
$pr = (Sortie 'proche') -replace '\x1b\[[0-9;]*m', ''
$prPlat = $pr -replace '\s+', ' '
Info ("Durée du parcours (bilan compris) : {0:N1} s" -f $script:etape.Commandes[-1].Duree)
if ($pr -match 'EN RÉSUMÉ|IN SHORT') { Ok 'Résumé affiché' } else { Bug 'Résumé ABSENT' }
if ($pr -match 'Note de l.ordinateur|Computer grade') { Ok 'Note de l''ordinateur au résumé' } else { Info 'Pas de note au résumé (bilan pas assez fiable ici)' }
if ($pr -match 'Ce qui reste à faire|What is left to do') { Ok 'Ce qui reste à faire : présent' } else { Bug 'Ce qui reste à faire : ABSENT' }
if ($pr -match 'Ce qui va bien|What is fine') { Info "Ce qui va bien : $(($pr -split "`r?`n" | Where-Object { $_ -match '^\s+✔' } | Select-Object -First 2 | ForEach-Object { $_.Trim() }) -join ' / ')" }
if ($prPlat -match "Mon ordinateur est-il contrôlé|Is my computer being controlled") { Ok 'Faux technicien : la recherche de prise de contrôle s''est ouverte' } else { Bug 'Faux technicien : recherche PAS ouverte' }
if ($pr -match 'Network scan|Scan du réseau') { Bug 'Réseau scanné malgré le refus' } else { Ok 'Réseau refusé : pas de scan' }
if ((Etat-Systeme | Out-String) -eq $etatAvant) { Ok 'Rien changé (pare-feu, démarrage, Defender)' } else { Bug 'Le système a changé alors que tout était refusé' }
$pagesNouvelles = @(Get-ChildItem -LiteralPath $bureauProche -Filter $motifPage -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notin $pagesAvant -or $_.LastWriteTime -ge $avantProche })
if ($poserPage) {
    if ($pagesNouvelles.Count) {
        Ok "Page posée sur le Bureau : $($pagesNouvelles[0].Name)"
        $html = Get-Content -LiteralPath $pagesNouvelles[0].FullName -Raw -Encoding UTF8
        if ($html -match 'Pour vous en particulier|Especially for you') { Ok 'Page : conseils pour la personne' } else { Bug 'Page : section des conseils ABSENTE' }
        # Retirée si elle n'existait pas avant la passe.
        $pagesNouvelles | Where-Object { $_.FullName -notin $pagesAvant } | Remove-Item -Force -ErrorAction SilentlyContinue
    } else { Bug 'Page PAS posée sur le Bureau' }
} else {
    if ($pagesNouvelles.Count) { Bug 'Page posée alors qu''elle a été refusée' } else { Ok 'Page refusée : rien sur le Bureau' }
    if ($prPlat -match 'La page reste possible plus tard|The page is still possible later') { Ok 'Page refusée : dit possible plus tard' } else { Bug 'Page refusée : rien dit' }
}

Etape 'Rapport HTML de Vanguard'
$avantComplet = Get-Date
if ($SansOuvrir) {
    # En arrière-plan, le navigateur ne doit pas surgir : le bilan complet, en texte.
    Lancer 'complet' @('bilan', '--texte')
    Info 'Rapport HTML pas ouvert : test en arrière-plan.'
    if ((Sortie 'complet') -match '(?m)^## (Audit du réseau|Network audit)') { Ok 'Rapport en texte : section de l''audit du réseau' } else { Bug 'Rapport en texte : section « Network audit » ABSENTE' }
} else {
    Lancer 'complet-html' @('bilan', '--html')
    Start-Sleep -Seconds 3
    Constat 'Le rapport s''est-il ouvert dans le navigateur, lisible, avec les accents corrects ?'
}
# 0.82 : le bilan complet enchaîne l'audit du réseau, et le rapport écrit (rapport.html, dans les deux cas) en a la section.
$rapportHtml = Join-Path $env:LOCALAPPDATA 'vanguard\rapport.html'
if ((Test-Path -LiteralPath $rapportHtml) -and (Get-Item -LiteralPath $rapportHtml).LastWriteTime -ge $avantComplet) {
    if ((Get-Content -LiteralPath $rapportHtml -Raw -Encoding UTF8) -match '<h2>(Audit du réseau|Network audit)') { Ok 'rapport.html : section « Audit du réseau »' } else { Bug 'rapport.html : section « Audit du réseau » ABSENTE' }
} else { Bug "rapport.html PAS écrit par le bilan complet ($rapportHtml)" }

Etape 'Antivirus (analyse rapide Microsoft Defender)'
if (Question 'Lancer l''analyse rapide Defender (quelques minutes) ?') {
    Lancer 'antivirus' @('antivirus')
} else { Sautee 'Sautée.' }

Etape 'Lanceur de la clé : Vanguard introuvable ou bloqué, expliqué sans toucher à Defender'
$lanceur = Join-Path $ici 'Lancer Vanguard.bat'
if (Test-Path -LiteralPath $lanceur) {
    # Dans un dossier sans Windows\vanguard.exe : le même chemin que quand Defender refuse de le lancer.
    # Vidé d'abord : un Windows\vanguard.exe resté là (ou posé d'avance) serait lancé par le lanceur.
    $essai = Join-Path $lieuEssais 'vanguard-lanceur'
    if (Test-Path -LiteralPath $essai) { Remove-Item -LiteralPath $essai -Recurse -Force }
    New-Item -ItemType Directory -Path $essai | Out-Null
    Copy-Item -LiteralPath $lanceur $essai -Force
    $defLanceur = (Get-MpPreference | Select-Object ExclusionPath, ControlledFolderAccessAllowedApplications | Out-String)
    $sortieLanceur = 'N' | cmd /c "`"$(Join-Path $essai 'Lancer Vanguard.bat')`"" 2>&1 | Out-String
    $codeLanceur = $LASTEXITCODE
    Set-Content -Path (Join-Path $res 'lanceur.out.txt') -Value $sortieLanceur -Encoding UTF8
    if ($sortieLanceur -match 'Windows could not start Vanguard') { Ok 'Refus expliqué' } else { Bug 'Refus PAS expliqué' }
    if ($sortieLanceur -match 'Checksum unreadable') { Ok 'Empreinte dite illisible, programme absent' } else { Bug 'Empreinte : rien dit pour un programme absent' }
    if ($codeLanceur -eq 1) { Ok 'Code 1 quand Vanguard ne démarre pas' } else { Bug "Code $codeLanceur au lieu de 1" }
    # PowerShell introuvable (PATH vidé, comme sur un poste où il est retiré) : un autre message, jamais celui de
    # Defender, qui ferait chercher une alerte qui n'existe pas.
    Set-Content -LiteralPath (Join-Path $essai 'sans-powershell.bat') -Value "@set PATH=`r`n@call `"Lancer Vanguard.bat`"" -Encoding ASCII
    $sortieSansPs = 'N' | cmd /c "`"$(Join-Path $essai 'sans-powershell.bat')`"" 2>&1 | Out-String
    $codeSansPs = $LASTEXITCODE
    Set-Content -Path (Join-Path $res 'lanceur-sans-powershell.out.txt') -Value $sortieSansPs -Encoding UTF8
    if ($sortieSansPs -match 'PowerShell is missing or blocked' -and $sortieSansPs -notmatch 'Windows could not start Vanguard') { Ok 'PowerShell absent : dit, sans accuser Defender' } else { Bug 'PowerShell absent : pris pour un blocage de Defender, ou rien dit' }
    if ($codeSansPs -eq 1) { Ok 'Code 1 sans PowerShell' } else { Bug "Code $codeSansPs au lieu de 1 sans PowerShell" }
    if ((Get-MpPreference | Select-Object ExclusionPath, ControlledFolderAccessAllowedApplications | Out-String) -eq $defLanceur) { Ok 'Defender pas touché' } else { Bug 'Defender modifié par le lanceur' }
    Remove-Item -LiteralPath $essai -Recurse -Force -ErrorAction SilentlyContinue
} else {
    # deployer.sh le dépose avec le programme : absent, c'est le dépôt qui est incomplet, et une étape « sautée »
    # le cacherait (quatre vérifications perdues sans un seul échec, le 19 octobre).
    Bug 'Lanceur de la clé absent du dossier du programme (dépôt incomplet)'
}

Etape 'Blocages de Windows Defender : liste, rien changé sans accord'
function Etat-Defender {
    $p = Get-MpPreference
    "cfa=$($p.EnableControlledFolderAccess) np=$($p.EnableNetworkProtection) pua=$($p.PUAProtection) asr=$((@($p.AttackSurfaceReductionRules_Ids) | Where-Object { $_ }) -join ',')/$(@($p.AttackSurfaceReductionRules_Actions) -join ',')"
}
$defAvant = Etat-Defender
$modeDefender = (Get-MpComputerStatus).AMRunningMode
Info "Defender ($modeDefender) : $defAvant"
# Le numéro de l'outil dans le groupe Cet ordinateur (4), lu à l'écran : 10, après les lignes communes (la conception
# de la 0.87 le fige ; lu quand même, pour que les essais suivants tournent si une ligne s'ajoutait).
LancerAvec 'protection-groupe' @() "4`n`nq`n"
$groupe = (Sortie 'protection-groupe') -replace '\x1b\[[0-9;]*m', ''
$numeroDefender = if ($groupe -match '(?m)^\s*(\d+)\s+(Blocages de Windows Defender|Windows Defender blocking)') { $Matches[1] } else { '' }
if ($numeroDefender) {
    if ($numeroDefender -eq '10') { Ok 'Outil présent dans le groupe, en 4.10' } else { Bug "Outil en 4.$numeroDefender, pas en 4.10" }
    LancerAvec 'protection' @() "4.$numeroDefender`n`n`nq`n"
    $t = Sortie 'protection'
    foreach ($titre in 'Blocages de base de Defender|Defender basic blocking', 'Protection réseau de Defender|Defender network protection', 'Accès contrôlé aux dossiers|Controlled folder access') {
        if ($t -match $titre) { Ok "Réglage affiché : $($titre.Split('|')[0])" } else { Bug "Réglage ABSENT : $($titre.Split('|')[0])" }
    }
    if ($modeDefender -eq 'Normal' -and $t -match "n'est pas l'antivirus actif|is not the active antivirus") { Bug 'Defender actif, mais dit inactif' }
    if ((Etat-Defender) -eq $defAvant) { Ok 'Rien changé sans accord' } else { Bug "Defender modifié sans accord : $(Etat-Defender)" }
} else { Bug 'Outil « Blocages de Windows Defender » ABSENT du groupe' }

Etape 'Windows sans PowerShell (0.82) : Defender, santé, BitLocker, mises à jour, lenteur, diagnostic et fiche, comparés à PowerShell'
# Depuis la 0.82, ces lectures passent par WMI, les journaux et les fonctions de Windows ; PowerShell ne sert plus qu'en
# secours. Chaque commande est lancée en guettant les PowerShell qu'elle ouvre, et ce qu'elle dit est comparé à ce que
# PowerShell lit ici (les mêmes classes).
try {
    $audit = Sortie 'machine-json' | ConvertFrom-Json
    function Messages-Bilan($categorie) { (@($audit.constats | Where-Object categorie -eq $categorie) | ForEach-Object message) -join ' / ' }
    # BitLocker : la propriété de l'Explorateur, lue ici par Shell.Application (1, 3, 6 actif ; 5 suspendu ; 8 en attente).
    $bl = "$((New-Object -ComObject Shell.Application).NameSpace('C:').Self.ExtendedProperty('System.Volume.BitLockerProtection'))".Trim()
    $attenduBl = switch -regex ($bl) {
        '^(1|3|6)$' { 'Disk C: encrypted|Disque C: chiffré'; break }
        '^5$' { 'suspended on C:|suspendu sur C:'; break }
        '^8$' { 'waiting to be turned on|attend d.être activé'; break }
        '^$' { 'BitLocker state unreadable|état BitLocker illisible'; break }
        default { 'Disk C: not encrypted|Disque C: non chiffré' }
    }
    $chiffre = Messages-Bilan 'Chiffrement'
    if ($chiffre -match $attenduBl) { Ok "BitLocker de C: (valeur $(if ($bl) { $bl } else { 'vide' })) : « $chiffre »" }
    else { Bug "BitLocker de C: (valeur $(if ($bl) { $bl } else { 'vide' })) : Vanguard dit « $chiffre »" }
    # Santé : la place libre de C:, lue par WMI, à 15 % près de Get-Volume.
    $libreC = (Get-Volume -DriveLetter C -ErrorAction SilentlyContinue).SizeRemaining
    $sante = Messages-Bilan 'Santé'
    if ($sante -match 'C:\D{0,12}?(\d+(?:[.,]\d+)?) (GB|TB|Go|To)') {
        $lu = [double]($Matches[1] -replace ',', '.') * [math]::Pow(1024, $(if ($Matches[2] -in 'TB', 'To') { 4 } else { 3 }))
        if ($libreC -and [math]::Abs($lu / $libreC - 1) -lt 0.15) { Ok "Place libre de C: : « $($Matches[0]) », comme Get-Volume ($([math]::Round($libreC / 1GB, 1)) Gio)" }
        else { Bug "Place libre de C: : Vanguard « $($Matches[0]) », Get-Volume $([math]::Round($libreC / 1GB, 1)) Gio" }
    } else { Bug "Place libre de C: absente de la santé : « $sante »" }
    # Mises à jour installées : Win32_QuickFixEngineering par WMI, comme Get-HotFix.
    $correctifs = @(Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending)
    $majBilan = Messages-Bilan 'Mises à jour'
    if (-not $correctifs.Count) { Info "Get-HotFix ne donne aucune mise à jour datée ; Vanguard : « $majBilan »" }
    elseif ($majBilan -match '(\d+) (days ago|jours)') {
        $jours = ((Get-Date).Date - $correctifs[0].InstalledOn.Date).Days
        if ([math]::Abs([int]$Matches[1] - $jours) -le 1) { Ok "Dernière mise à jour il y a $($Matches[1]) jours, comme Get-HotFix ($($correctifs[0].HotFixID))" }
        else { Bug "Dernière mise à jour : Vanguard $($Matches[1]) jours, Get-HotFix $jours ($($correctifs[0].HotFixID))" }
    } else { Bug "Dernière mise à jour absente du bilan : « $majBilan »" }
} catch { Bug "machine --json illisible : $($_.Exception.Message)" }

# Defender : MSFT_MpComputerStatus et MSFT_MpPreference par WMI (l'outil « Blocages de Windows Defender »).
if ($numeroDefender) {
    LancerSurveille 'protection-sans-ps' @() "4.$numeroDefender`n`n`nq`n"
    $t = Sortie 'protection-sans-ps'
    $modeDefender = (Get-MpComputerStatus -ErrorAction SilentlyContinue).AMRunningMode
    if ($modeDefender -eq 'Normal' -and $t -match "n'est pas l'antivirus actif|is not the active antivirus") { Bug 'Defender actif selon Get-MpComputerStatus, dit inactif par la lecture WMI' }
    elseif ($t -match 'Protection réseau de Defender|Defender network protection') { Ok "Réglages de Defender lus (Get-MpComputerStatus : $modeDefender)" }
    else { Bug 'Réglages de Defender ABSENTS' }
    Sans-PowerShell 'Blocages de Windows Defender'
} else { Sautee 'Blocages de Windows Defender absents du groupe : lecture WMI pas essayée' }

# Mises à jour installées, encore : « lent › depuis peu » montre les huit dernières, autant que Get-HotFix en a.
LancerSurveille 'depanner-lent' @('depanner', 'lent') "1`n2`nn`n`n`n`n"
$dl = (Sortie 'depanner-lent') -replace '\x1b\[[0-9;]*m', ''
$kb = @([regex]::Matches($dl, '(?m)^\s+(\d{4}-\d{2}-\d{2})\s+(KB\d+)') | ForEach-Object { [pscustomobject]@{ Date = $_.Groups[1].Value; Numero = $_.Groups[2].Value } })
$correctifs = @(Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending)
$attendus = [math]::Min(8, $correctifs.Count)
if ($kb.Count -eq $attendus) { Ok "Dernières mises à jour : $($kb.Count) KB, comme Get-HotFix ($($correctifs.Count) datées en tout)" }
else { Bug "Dernières mises à jour : Vanguard $($kb.Count) KB, Get-HotFix $attendus" }
$inconnus = @($kb | Where-Object { $_.Numero -notin $correctifs.HotFixID })
if ($inconnus.Count) { Bug "KB inconnus de Get-HotFix : $(($inconnus | ForEach-Object Numero) -join ', ')" }
if ($kb.Count -and $correctifs.Count) {
    $plusRecente = $correctifs[0].InstalledOn.ToString('yyyy-MM-dd')
    if ($kb[0].Date -eq $plusRecente) { Ok "La plus récente le $plusRecente, comme Get-HotFix" } else { Bug "La plus récente : Vanguard $($kb[0].Date), Get-HotFix $plusRecente" }
}
Sans-PowerShell 'Dépanner › lent › depuis peu'

# Lenteur : compteurs bruts par WMI lus deux fois, démarrage par le journal des performances.
LancerSurveille 'lenteur-sans-ps' @('lenteur') "`n"
$t = (Sortie 'lenteur-sans-ps') -replace '\x1b\[[0-9;]*m', ''
$plat = $t -replace '\s+', ' '
if ($plat -match '(Processor|Processeur) .{0,40}?\d+ ?% \((\d+) (threads|fils)\)') { Ok "Processeur mesuré : $($Matches[0])" } else { Bug 'Processeur PAS mesuré' }
if ($plat -match '(Memory|Mémoire) .{0,40}?\d+ ?% \(.{1,30}? (free out of|libres sur) [^)]+\)') { Ok "Mémoire mesurée : $($Matches[0])" } else { Bug 'Mémoire PAS mesurée' }
if ($plat -match '(Disk|Disque) .{0,40}?(busy|occupé) \d+ ?% (of the time|du temps)') { Ok "Disque mesuré : $($Matches[0])" }
elseif ($plat -match 'activity not measurable here|activité non mesurable ici') { Bug 'Disque : activité dite non mesurable' }
else { Bug 'Disque PAS mesuré' }
if ($plat -match '(WHAT WEIGHS THE MOST|CE QUI PÈSE LE PLUS) .*?(Memory|Mémoire) (?!nothing notable|rien de notable)(\S+)') { Ok "Programmes : en tête de la mémoire, $($Matches[3])" }
else { Bug 'Programmes : rien dans « ce qui pèse le plus » pour la mémoire' }
# Le nom d'instance des compteurs (« svchost#2 ») ne doit pas sortir : un programme, un nom.
$suffixes = @([regex]::Matches($t, '[\w.-]+#\d+\b') | ForEach-Object Value)
if ($suffixes.Count) { Bug "Programme nommé avec un suffixe des compteurs : $($suffixes -join ', ')" } else { Ok 'Aucun nom de programme en « #2 »' }
Sans-PowerShell 'Pourquoi c''est lent ?'

# Diagnostic : Win32_OperatingSystem, ComputerSystem, Processor, BIOS, VideoController ; les mêmes champs qu'ici.
LancerSurveille 'diagnostic-sans-ps' @('diagnostic')
$d = ((Sortie 'diagnostic-sans-ps') -replace '\x1b\[[0-9;]*m', '') -replace '\s+', ' '
$osRef = Get-CimInstance Win32_OperatingSystem
$cpuRef = @(Get-CimInstance Win32_Processor)
$biosRef = Get-CimInstance Win32_BIOS
$champsDiag = [ordered]@{
    'système' = "$($osRef.Caption)"; 'version' = "$($osRef.Version)"; 'nom' = "$env:COMPUTERNAME"; 'BIOS' = "$($biosRef.SMBIOSBIOSVersion)"
    'processeur' = "$($cpuRef[0].Name)"
}
foreach ($g in @(Get-CimInstance Win32_VideoController)) { $champsDiag["carte $($g.Name)"] = "$($g.Name)" }
$differents = @($champsDiag.Keys | Where-Object { $v = ($champsDiag[$_] -replace '\s+', ' ').Trim(); $v -and -not $d.Contains($v) })
$filsDiag = $cpuRef[0].NumberOfLogicalProcessors
if ($d -notmatch "\($filsDiag (threads|fils)\)") { $champsDiag['fils'] = "$filsDiag"; $differents += 'fils' }
if ($differents.Count) { Bug "Diagnostic : différent de Get-CimInstance pour $(($differents | ForEach-Object { "$_ (« $($champsDiag[$_].Trim()) »)" }) -join ', ')" }
else { Ok "Diagnostic : système, version, nom, BIOS, processeur, fils et $(@(Get-CimInstance Win32_VideoController).Count) carte(s) graphique(s) comme Get-CimInstance" }
if ($d -match 'PowerShell is not responding|PowerShell ne répond pas') { Bug 'Diagnostic : « PowerShell ne répond pas »' }
Sans-PowerShell 'Diagnostic'

# Fiche : les mêmes classes, rendues dans le JSON qu'écrivait le script.
LancerSurveille 'fiche-json-sans-ps' @('fiche-ordinateur', '--json')
try {
    $fj = Sortie 'fiche-json-sans-ps' | ConvertFrom-Json
    $csRef = Get-CimInstance Win32_ComputerSystem
    $barrettesRef = @(Get-CimInstance Win32_PhysicalMemory)
    $ecarts = @()
    $norme = { param($x) ("$x" -replace '\s+', ' ').Trim() }
    if ((& $norme $fj.processeur) -ne (& $norme $cpuRef[0].Name)) { $ecarts += "processeur « $($fj.processeur) » / « $($cpuRef[0].Name) »" }
    $filsRef = ($cpuRef | Measure-Object NumberOfLogicalProcessors -Sum).Sum
    $coeursRef = ($cpuRef | Measure-Object NumberOfCores -Sum).Sum
    if ($fj.fils -ne $filsRef) { $ecarts += "fils $($fj.fils) / $filsRef" }
    if ($fj.coeurs -ne $coeursRef) { $ecarts += "cœurs $($fj.coeurs) / $coeursRef" }
    $sommeBarrettes = ($barrettesRef | Measure-Object Capacity -Sum).Sum
    if ($fj.memoire -ne $csRef.TotalPhysicalMemory -and $fj.memoire -ne $sommeBarrettes) { $ecarts += "mémoire $($fj.memoire) / $($csRef.TotalPhysicalMemory) (barrettes $sommeBarrettes)" }
    if (-not $fj.barrettes_illisibles -and @($fj.barrettes).Count -ne $barrettesRef.Count) { $ecarts += "barrettes $(@($fj.barrettes).Count) / $($barrettesRef.Count)" }
    $cartesRef = @(Get-CimInstance Win32_VideoController).Count
    if (@($fj.graphique).Count -ne $cartesRef) { $ecarts += "cartes graphiques $(@($fj.graphique).Count) / $cartesRef" }
    $disquesRef = @(Get-PhysicalDisk -ErrorAction SilentlyContinue).Count
    if (@($fj.disques).Count -ne $disquesRef) { $ecarts += "disques $(@($fj.disques).Count) / $disquesRef" }
    if ($biosRef.SMBIOSBIOSVersion -and -not "$($fj.bios)".Contains("$($biosRef.SMBIOSBIOSVersion)".Trim())) { $ecarts += "BIOS « $($fj.bios) » / « $($biosRef.SMBIOSBIOSVersion) »" }
    if ($ecarts.Count) { Bug "Fiche différente de Get-CimInstance : $($ecarts -join ' ; ')" }
    else { Ok "Fiche comme Get-CimInstance : processeur, $filsRef fils, $coeursRef cœurs, mémoire, $($barrettesRef.Count) barrette(s), $cartesRef carte(s) graphique(s), $disquesRef disque(s), BIOS" }
} catch { Bug "fiche --json illisible : $($_.Exception.Message)" }
Sans-PowerShell 'Fiche de l''ordinateur'

Etape 'Blocages de Windows Defender : protection réseau changée puis remise (UAC)'
# Defender applique une préférence quelques instants après la fenêtre administrateur : relue jusqu'à 10 s.
function Protection-Reseau-Attendue([int]$voulue) {
    for ($i = 0; $i -lt 20; $i++) {
        $np = [int](Get-MpPreference).EnableNetworkProtection
        if ($np -eq $voulue) { return $np }
        Start-Sleep -Milliseconds 500
    }
    return $np
}
$npAvant = [int](Get-MpPreference).EnableNetworkProtection
# Déjà active (une passe d'avant l'a laissée ainsi) : annulée d'abord, puis remise ; sinon activée, puis annulée.
$npAutre = if ($npAvant -eq 1) { 0 } else { 1 }
if (-not $numeroDefender) { Sautee 'Sautée : outil absent.' }
elseif (Question 'Faire ce test (deux fenêtres UAC à accepter) ?') {
    Write-Host '      Clique OUI dans les deux fenêtres UAC. Un refus ne change rien et fait échouer le test.' -ForegroundColor Yellow
    Write-Host '      Si la fenêtre administrateur demande « Continue without a restore point? », réponds y (la VM n''a pas de' -ForegroundColor Yellow
    Write-Host '      points de restauration) : sinon, rien n''est changé.' -ForegroundColor Yellow
    # Ligne 3 de la liste : la protection réseau. Sans terminal, taper son numéro coche (ou décoche) et valide ; puis
    # « o » accepte.
    LancerAvec 'protection-changer' @() "4.$numeroDefender`n3`no`n`nq`n"
    $np = Protection-Reseau-Attendue $npAutre
    if ($np -eq $npAutre) { Ok "Protection réseau passée de $npAvant à $npAutre par Vanguard" }
    elseif ((Sortie 'protection-changer') -match "Administrator prompt refused|Demande d'administrateur refusée") { Bug 'Fenêtre UAC refusée : rien changé (le test demande OUI)' }
    else { Bug "Protection réseau PAS changée ($np)" }
    # Ce que Vanguard dit, jugé d'après ce que Defender a vraiment fait.
    $ditPasChange = (Sortie 'protection-changer') -match 'not changed|pas changé'
    if ($np -eq $npAutre -and $ditPasChange) { Bug 'Vanguard dit « pas changé » alors que Defender a changé' }
    elseif ($np -ne $npAutre -and -not $ditPasChange) { Bug 'Vanguard ne dit pas « pas changé » alors que Defender n''a pas changé' }
    # Rien n'a changé : une « remise » acceptée basculerait la protection au lieu de la remettre.
    if ($np -ne $npAutre) { Sautee 'Remise sautée : rien n''avait changé' }
    else {
        LancerAvec 'protection-remettre' @() "4.$numeroDefender`n3`no`n`nq`n"
        $np = Protection-Reseau-Attendue $npAvant
        if ($np -eq $npAvant) { Ok 'Protection réseau remise comme avant' } else { Bug "Protection réseau PAS remise ($np au lieu de $npAvant)" }
    }
    if ((Etat-Defender) -eq $defAvant) { Ok 'Defender exactement comme avant' } else { Bug "Defender différent d'avant : $(Etat-Defender)" }
} else { Sautee 'Sautée (il faut accepter les fenêtres UAC).' }

Etape 'Corrections avec UAC (refus, puis acceptation, puis port bloqué)'
Info 'Coupe le pare-feu du profil « Privé » de la VM, puis Vanguard doit le réparer. Le port 3389 et le Bureau à distance ne sont jamais touchés.'
if (Question 'Faire ce test ?') {
    Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile', '-Command', 'Set-NetFirewallProfile -Profile Private -Enabled False'
    Ref 'Pare-feu après coupure volontaire' { Get-NetFirewallProfile | Select-Object Name, Enabled | Format-Table -AutoSize }

    Write-Host ''
    Write-Host '      Réponds « o » pour le pare-feu, puis clique NON dans la fenêtre UAC. Réponds « n » à tout le reste.' -ForegroundColor Yellow
    Vider-Clavier
    & $exe corriger
    Constat 'Vanguard a-t-il dit « Demande d''administrateur refusée : rien n''a été modifié » et PAS « ✔ fait » ?'
    if ((Get-NetFirewallProfile -Profile Private).Enabled) { Bug 'Pare-feu Privé réactivé malgré le refus' } else { Ok 'Refus respecté : pare-feu Privé toujours coupé' }

    Write-Host ''
    Write-Host '      Réponds « o » pour le pare-feu et accepte l''UAC. Pour les ports, « o » au port 135 seulement, « n » au reste.' -ForegroundColor Yellow
    Vider-Clavier
    & $exe corriger
    if ((Get-NetFirewallProfile -Profile Private).Enabled) { Ok 'Pare-feu Privé réactivé par Vanguard' }
    else {
        Bug 'Pare-feu Privé toujours coupé après la correction : remis en marche par le script'
        Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile', '-Command', 'Set-NetFirewallProfile -Profile Private -Enabled True'
    }
    Ref 'Règles Vanguard créées' { Get-NetFirewallRule -DisplayName 'Vanguard : bloquer *' -ErrorAction SilentlyContinue | Select-Object DisplayName, Enabled, Action | Format-Table -AutoSize }
    Constat 'La correction s''est-elle bien passée (affichage clair, une fenêtre UAC par correction, « OK » à chaque étape) ?'

    # Un port bloqué par Vanguard ne doit plus être signalé comme à corriger (0.9.6).
    Lancer 'machine-apres-blocage' @('audit')
    if ((Sortie 'machine-apres-blocage') -match 'bloqué en entrée par la règle|blocked inbound by the') { Ok 'Port bloqué reconnu à l''audit suivant' }
    else { Info 'Aucun port reconnu comme bloqué (normal si aucun port n''a été bloqué)' }

    if (Question 'Retirer maintenant les règles « Vanguard : bloquer » créées pendant le test ?') {
        Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile', '-Command', "Remove-NetFirewallRule -DisplayName 'Vanguard : bloquer *'"
    }
} else { Sautee 'Sautée (il faut répondre aux fenêtres UAC).' }

Etape 'Outils récents : bilan durci, caméra et micro, quarantaine, raccourci, vérifier ma clé'
# Les vérifications ajoutées de la 0.60 à la 0.64 : elles se lisent dans l'audit JSON déjà fait plus haut.
try {
    $audit = Sortie 'machine-json' | ConvertFrom-Json
    foreach ($cat in 'Durcissement', 'Heure') {
        $n = @($audit.constats | Where-Object { $_.categorie -eq $cat }).Count
        if ($n) { Ok "Catégorie « $cat » au bilan ($n constat(s))" } else { Bug "Catégorie « $cat » ABSENTE du bilan" }
    }
    @($audit.constats | Where-Object { $_.categorie -in 'Durcissement', 'Fin de support', 'Comptes', 'Navigateur', 'Fichiers secrets', 'Sauvegardes', 'Bluetooth' -and $_.probleme }) |
        ForEach-Object { Info "$($_.categorie) : $($_.message)" }
} catch { Bug "machine --json illisible : $($_.Exception.Message)" }
Lancer 'camera-micro' @('camera-micro')
$c = Sortie 'camera-micro'
if ($c -match 'Camera and microphone|Caméra et micro') { Ok 'Caméra et micro : historique lu' } else { Bug 'Caméra et micro : écran absent' }
if ($c -match 'PowerShell is not responding|PowerShell ne répond pas') { Bug 'Caméra et micro : lecture en échec' }
Lancer 'acces' @('bilan-confidentialite')
$c = Sortie 'acces'
if ($c -match 'Privacy check|Bilan de confidentialit') { Ok 'Bilan de confidentialité : écran lu' } else { Bug 'Bilan de confidentialité : écran absent' }
if ($c -match 'settings cannot be read from the registry|illisibles dans le registre') { Bug 'Bilan de confidentialité : registre illisible' }
LancerAvec 'quarantaine' @('quarantaine') "`n"
if ((Sortie 'quarantaine') -match 'Quarantine|Quarantaine') { Ok 'Quarantaine ouverte' } else { Bug 'Quarantaine : écran absent' }
# Raccourci sur le Bureau : posé, présent, puis retiré.
$bureau = [Environment]::GetFolderPath('Desktop')
Lancer 'raccourci-on' @('raccourci', 'on')
if (Test-Path (Join-Path $bureau 'Vanguard.lnk')) { Ok 'Raccourci posé sur le Bureau' } else { Bug 'Raccourci NON posé sur le Bureau' }
Lancer 'raccourci-off' @('raccourci', 'off')
if (-not (Test-Path (Join-Path $bureau 'Vanguard.lnk'))) { Ok 'Raccourci retiré' } else { Bug 'Raccourci ENCORE sur le Bureau' }
# Vérifier ma clé : la liste des disques, quittée sans rien écrire ; aucune partition de la clé n'y est proposée.
LancerAvec 'verifier-cle' @('verifier-cle') "`n"
$k = Sortie 'verifier-cle'
if ($k -match '(?m)^\s+\d+\s+(VANGUARD|WIN11|VTOYEFI|MACOS)\b') { Bug 'Vérifier ma clé propose une partition de la clé VANGUARD' } else { Ok 'Aucune partition de la clé proposée' }
if ($k -match 'Start\?|Commencer \?') { Bug 'Vérifier ma clé est allé jusqu''à la question d''écriture' }

Etape 'Réglages Windows de la 0.68 à la 0.78 : Vanguard voit-il ce que Windows dit ?'
# Chaque réglage est relu ici, sans Vanguard ; Vanguard doit le signaler s'il est risqué, et seulement dans ce cas.
# Un bilan refait maintenant : celui du début précède les corrections acceptées plus haut (WPAD, longueur des mots
# de passe…), et le registre relu ici les montre déjà faites. Les deux se comparent au même instant (et à la 0.79).
Lancer 'machine-json-relu' @('audit', '--json')
try {
    $audit = Sortie 'machine-json-relu' | ConvertFrom-Json
    function Signale($motif) { [bool]@($audit.constats | Where-Object { $_.probleme -and $_.message -match $motif }).Count }
    function Accord($nom, [bool]$risque, $motif) {
        $vu = Signale $motif
        if ($vu -eq $risque) { Ok "$nom : $(if ($risque) { 'risqué, signalé' } else { 'sûr, rien signalé' })" }
        elseif ($risque) { Bug "$nom : risqué selon Windows, NON signalé par Vanguard" }
        else { Bug "$nom : sûr selon Windows, mais signalé par Vanguard" }
    }
    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    $uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
    $poste = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -ErrorAction SilentlyContinue
    $posteGpo = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -ErrorAction SilentlyContinue
    Accord 'NTLMv1' ($null -ne $lsa.LmCompatibilityLevel -and $lsa.LmCompatibilityLevel -lt 3) 'NTLMv1'
    Accord 'Empreintes LM' ($lsa.NoLMHash -eq 0) 'vieille forme \(LM\)|old form \(LM\)'
    Accord 'Registre à distance' ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry' -ErrorAction SilentlyContinue).Start -eq 2) 'Registre à distance démarre|Remote Registry starts'
    $smb1c = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -ErrorAction SilentlyContinue).Start
    Accord 'Client SMBv1' ($null -ne $smb1c -and $smb1c -ne 4) 'client SMBv1|SMBv1 client'
    # Le serveur SMBv1 : Vanguard le lit dans le registre (0.80) ; PowerShell, lui, demande au service.
    Accord 'Serveur SMBv1' ((Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol -eq $true) 'SMBv1 activé|SMBv1 on'
    $msiM = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -ErrorAction SilentlyContinue).AlwaysInstallElevated
    $msiC = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -ErrorAction SilentlyContinue).AlwaysInstallElevated
    Accord 'Installation MSI élevée' ($msiM -eq 1 -and $msiC -eq 1) 'AlwaysInstallElevated'
    $maps = (Get-MpPreference -ErrorAction SilentlyContinue).MAPSReporting
    if ($null -ne $maps) { Accord 'Protection dans le cloud' ($maps -eq 0) 'protection dans le cloud de Defender|cloud protection is off' }
    $mit = try { Get-ProcessMitigation -System } catch { $null }
    if ($mit) { Accord 'Protection contre les exploits' ('OFF' -in @("$($mit.DEP.Enable)", "$($mit.ASLR.BottomUp)", "$($mit.CFG.Enable)", "$($mit.SEHOP.Enable)")) 'Protection contre les exploits|Exploit protection' }
    # Pare-feu, lu par Vanguard dans le registre : doit dire la même chose que Get-NetFirewallProfile.
    Accord 'Pare-feu coupé' ([bool]@(Get-NetFirewallProfile | Where-Object { -not $_.Enabled }).Count) 'Pare-feu désactivé pour|Firewall off for'
    $wu = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv' -ErrorAction SilentlyContinue).Start
    $uso = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\UsoSvc' -ErrorAction SilentlyContinue).Start
    Accord 'Service Windows Update' ($wu -eq 4 -or $uso -eq 4) 'service Windows Update est désactivé|Windows Update service is disabled'
    Accord 'UAC sans demande' ($uac.EnableLUA -eq 1 -and $uac.ConsentPromptBehaviorAdmin -eq 0) 'ne demande plus rien|no longer asks'
    Accord 'Accès anonyme' ($lsa.RestrictAnonymousSAM -eq 0 -or $lsa.EveryoneIncludesAnonymous -eq 1) 'lister les comptes|list the computer|connexion anonyme|anonymous network connection'
    $invite = if ($null -ne $posteGpo.AllowInsecureGuestAuth) { $posteGpo.AllowInsecureGuestAuth } else { $poste.AllowInsecureGuestAuth }
    Accord 'Partages en invité' ($invite -eq 1) 'partages réseau acceptent|Network shares accept'
    # La stratégie de PowerShell hors celle de ce processus (le test peut tourner en Bypass) : celle que Vanguard lit.
    $strategie = foreach ($portee in 'MachinePolicy', 'UserPolicy', 'CurrentUser', 'LocalMachine') {
        $s = [string](Get-ExecutionPolicy -Scope $portee)
        if ($s -and $s -ne 'Undefined') { $s; break }
    }
    Info "Stratégie de PowerShell (hors processus) : $(if ($strategie) { $strategie } else { 'non définie' })"
    Accord 'PowerShell sans avertissement' ($strategie -in 'Unrestricted', 'Bypass') 'PowerShell lance n''importe quel script|PowerShell runs any script'
    $sb = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction SilentlyContinue).UEFISecureBootEnabled
    if ($null -eq $sb) { Info 'Secure Boot : clé absente (ancien BIOS), Vanguard ne dit rien' }
    else {
        if (@($audit.constats | Where-Object { $_.categorie -eq 'Secure Boot' }).Count) { Ok "Secure Boot au bilan (Windows : $sb)" } else { Bug 'Secure Boot ABSENT du bilan' }
        Accord 'Secure Boot coupé' ($sb -eq 0) 'Secure Boot désactivé|Secure Boot off'
    }
    # Macros d'Office : VBAWarnings à 1 dans une version et un programme, la stratégie passant avant le réglage.
    $macros = $false
    foreach ($v in '16.0', '15.0', '14.0') {
        foreach ($p in 'word', 'excel', 'powerpoint', 'access', 'publisher', 'visio') {
            $gpo = (Get-ItemProperty "HKCU:\Software\Policies\Microsoft\Office\$v\$p\Security" -ErrorAction SilentlyContinue).VBAWarnings
            $reg = (Get-ItemProperty "HKCU:\Software\Microsoft\Office\$v\$p\Security" -ErrorAction SilentlyContinue).VBAWarnings
            if ($(if ($null -ne $gpo) { $gpo } else { $reg }) -eq 1) { $macros = $true }
        }
    }
    Accord 'Macros d''Office' $macros 'toutes les macros|every macro'
    # Verrouillage de l'écran : présent au bilan, avec le délai trouvé (à comparer à ce que montrent les Paramètres).
    $verrou = @($audit.constats | Where-Object { $_.categorie -eq 'Verrouillage' })
    if ($verrou.Count) { Ok "Verrouillage au bilan : $($verrou[0].message)" } else { Bug 'Verrouillage ABSENT du bilan' }
    Info "powercfg, veille sur secteur : $(((powercfg /q SCHEME_CURRENT SUB_SLEEP STANDBYIDLE) -join ' ') -replace '.*Index: (0x[0-9a-f]+).*Index: (0x[0-9a-f]+).*', '$1 (secteur), $2 (batterie)')"
    # BitLocker : valeur brute de Windows (1 actif, 2 coupé, 3 en cours, 5 suspendu, 8 en attente) et ce qu'en dit Vanguard.
    $bl = (New-Object -ComObject Shell.Application).NameSpace('C:').Self.ExtendedProperty('System.Volume.BitLockerProtection')
    $chiffre = @($audit.constats | Where-Object { $_.categorie -eq 'Chiffrement' })
    Info "BitLocker de C: : valeur $bl ; Vanguard : $(if ($chiffre.Count) { $chiffre[0].message } else { 'rien' })"
    # Services au chemin sans guillemets : ceux que Windows a, et ce qu'en dit Vanguard (signalés seulement si un dossier est modifiable par tous).
    $sansGuillemets = @(Get-CimInstance Win32_Service | Where-Object { $_.PathName -and -not $_.PathName.StartsWith('"') -and $_.PathName -match '^[^"]+ [^"]*\.exe' })
    $vu = @($audit.constats | Where-Object { $_.message -match 'sans guillemets|unquoted path' })
    Info "Services au chemin sans guillemets avec espace : $($sansGuillemets.Count) ; Vanguard : $(if ($vu.Count) { $vu[0].message } else { 'rien (aucun dossier modifiable par tous)' })"
    # Ports en écoute lus par netstat (adresse distante 0.0.0.0:0 ou [::]:0, quelle que soit la langue) : les mêmes que
    # Get-NetTCPConnection, et le bilan ne les dit jamais « impossibles ».
    $parNetstat = @(netstat -ano | ForEach-Object { $c = -split $_; if ($c.Count -eq 5 -and $c[0] -eq 'TCP' -and $c[2] -in '0.0.0.0:0', '[::]:0') { [int]($c[1] -replace '.*:', '') } }) | Sort-Object -Unique
    $parCmdlet = @(Get-NetTCPConnection -State Listen | ForEach-Object { [int]$_.LocalPort }) | Sort-Object -Unique
    if (-not (Compare-Object $parNetstat $parCmdlet)) { Ok "Ports en écoute : netstat et Get-NetTCPConnection d'accord ($($parNetstat.Count) ports)" }
    else { Bug "Ports en écoute : netstat ($($parNetstat -join ',')) et Get-NetTCPConnection ($($parCmdlet -join ',')) diffèrent" }
    if (@($audit.constats | Where-Object { $_.categorie -eq 'Ports en écoute' -and -not $_.verifie }).Count) { Bug 'Ports en écoute : impossibles à vérifier au bilan' }
    else { Ok 'Ports en écoute vérifiés au bilan' }
    # Exclusions de Defender : lisibles seulement en administrateur ; sinon Vanguard ne conclut rien.
    $exclusions = @((Get-MpPreference -ErrorAction SilentlyContinue).ExclusionPath)
    if ($exclusions | Where-Object { $_ -like 'N/A*' }) { Info 'Exclusions de Defender cachées sans droits administrateur' }
    else { Info "Exclusions de Defender : $(@($exclusions | Where-Object { $_ }).Count) dossier(s)" }
} catch { Bug "Comparaison impossible : $($_.Exception.Message)" }

Etape 'Réglages de la 0.79 : WPAD, règle des mots de passe, portes dérobées, guide'
# Chaque réglage est relu ici sans Vanguard, et comparé au bilan JSON refait après les corrections (étape d'avant).
try {
    $audit = Sortie 'machine-json-relu' | ConvertFrom-Json
    function Signale79($motif) { [bool]@($audit.constats | Where-Object { $_.probleme -and $_.message -match $motif }).Count }
    function Accord79($nom, [bool]$risque, $motif) {
        $vu = Signale79 $motif
        if ($vu -eq $risque) { Ok "$nom : $(if ($risque) { 'risqué, signalé' } else { 'sûr, rien signalé' })" }
        elseif ($risque) { Bug "$nom : risqué selon Windows, NON signalé par Vanguard" }
        else { Bug "$nom : sûr selon Windows, mais signalé par Vanguard" }
    }
    $domaine = $env:USERDOMAIN -and $env:USERDOMAIN -ne $env:COMPUTERNAME
    $wpad = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\WinHttp\Parameters' -ErrorAction SilentlyContinue).DisableWpad
    Accord79 'WPAD' ($wpad -ne 1 -and -not $domaine) 'proxy tout seul|proxy by itself'
    # Portes dérobées classiques, en lecture seule : un débogueur posé sur un programme d'accessibilité de l'écran de
    # connexion, le bureau ou Userinit de Winlogon détournés. Relus ici dans le registre, comparés au bilan.
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    $accessibilite = 'sethc.exe', 'utilman.exe', 'osk.exe', 'narrator.exe', 'magnify.exe', 'displayswitch.exe', 'atbroker.exe'
    $porte = [bool]@($accessibilite | Where-Object { (Get-ItemProperty (Join-Path $ifeo $_) -ErrorAction SilentlyContinue).Debugger }).Count
    Accord79 'Débogueur sur un programme d''accessibilité' $porte 'Porte dérobée sur|Backdoor on'
    $winlogon = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
    $userinit = @("$($winlogon.Userinit)".Split(',') | ForEach-Object { $_.Trim().Trim('"') } | Where-Object { $_ })
    $shellDetourne = "$($winlogon.Shell)".Trim() -notin '', 'explorer.exe', "$env:SystemRoot\explorer.exe"
    $userinitDetourne = $userinit.Count -gt 1 -or ($userinit.Count -eq 1 -and $userinit[0] -notin "$env:SystemRoot\system32\userinit.exe", '%SystemRoot%\system32\userinit.exe', 'userinit.exe')
    Info "Winlogon : Shell « $($winlogon.Shell) », Userinit « $($winlogon.Userinit) »"
    Accord79 'Winlogon (bureau, Userinit)' ($shellDetourne -or $userinitDetourne) 'Winlogon lance|Winlogon starts'
    $portes = @($audit.constats | Where-Object { $_.regle -in 'WIN-PRS-002', 'WIN-PRS-004' })
    if (@($portes.regle | Sort-Object -Unique).Count -eq 2 -and -not @($portes | Where-Object { -not $_.verifie }).Count) { Ok 'Règles IFEO et Winlogon au bilan, vérifiées' }
    else { Bug 'Règle IFEO ou Winlogon absente du bilan, ou non vérifiée' }
    # La règle des mots de passe : lue par NetUserModalsGet, comme Vanguard (sans droits, quelle que soit la langue), et
    # par net accounts pour comparer. Une lecture vide dirait que Vanguard ne peut rien conclure.
    Add-Type -Namespace VanguardTest -Name Modales -MemberDefinition @'
[DllImport("netapi32.dll", CharSet = CharSet.Unicode)] public static extern int NetUserModalsGet(string serveur, int niveau, out IntPtr tampon);
[DllImport("netapi32.dll")] public static extern int NetApiBufferFree(IntPtr tampon);
'@
    function Modale([int]$niveau, [int]$champ) {
        $tampon = [IntPtr]::Zero
        if ([VanguardTest.Modales]::NetUserModalsGet($null, $niveau, [ref]$tampon) -ne 0) { return $null }
        try { [Runtime.InteropServices.Marshal]::ReadInt32($tampon, 4 * $champ) } finally { [void][VanguardTest.Modales]::NetApiBufferFree($tampon) }
    }
    $longueur = Modale 0 0
    $seuil = Modale 3 2
    if ($null -eq $longueur -or $null -eq $seuil) { Bug 'Règle des mots de passe illisible par NetUserModalsGet : Vanguard n''en dira rien' }
    else { Ok "NetUserModalsGet : longueur minimale $longueur, blocage après $seuil essai(s) (0 : jamais)" }
    Accord79 'Règle des mots de passe lue par Vanguard' $false 'password policy unreadable|règle des mots de passe illisible'
    Info "net accounts : $((net accounts | Select-String 'length|lockout threshold|longueur|seuil') -join ' ; ')"
    if ($null -ne $seuil) {
        Accord79 'Blocage après des mots de passe faux' ($seuil -eq 0) 'Aucun blocage après|No lockout after'
        if ($seuil -ne 0) { Accord79 'Longueur minimale des mots de passe' ($longueur -lt 8) 'moins de 8 caractères|shorter than 8 characters' }
    }
    # Commandes du guide marquées « administrateur » : se lisent-elles sans droits ? (si oui, la marque peut partir)
    foreach ($commande in 'Get-SmbShare', 'Get-Tpm') {
        try { $null = & $commande -ErrorAction Stop; Info "$commande marche sans droits : la marque « administrateur » du guide peut partir" }
        catch { Ok "$commande demande bien les droits d'administrateur" }
    }
} catch { Bug "Comparaison impossible : $($_.Exception.Message)" }
# « Lancer ici » : « 10.6.36.1 » ouvre Get-NetConnectionProfile (Windows 11, 36e programme), « 2 » la lance.
LancerAvec 'guide-profil' @() "10.6.36.1`n2`n`n`nq`n"
$profil = Sortie 'guide-profil'
if ($profil -match 'NetworkCategory' -and $profil -match 'Done in|Terminée en') { Ok 'Profil réseau lancé depuis le guide, sortie montrée' }
else { Bug 'Profil réseau : commande du guide pas lancée ou sortie absente' }

Etape 'Compte sans mot de passe exigé : signalé, à corriger soi-même (UAC pour le créer)'
# Le drapeau « mot de passe exigé » ne donne pas de mot de passe : Vanguard ne le lève pas tout seul, il renvoie aux
# Paramètres. Le compte de test est retiré à la fin.
Info 'Crée un compte de test « vanguard-essai » sans mot de passe exigé, puis regarde ce que Vanguard en dit.'
if (Question 'Faire ce test ?') {
    Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile', '-Command', 'New-LocalUser -Name vanguard-essai -NoPassword | Out-Null; Set-LocalUser -Name vanguard-essai -PasswordRequired $false'
    $essai = Get-LocalUser -Name 'vanguard-essai' -ErrorAction SilentlyContinue
    if (-not $essai) { Bug 'Compte de test non créé (UAC refusée ?)' }
    else {
        Lancer 'machine-compte-essai' @('audit', '--json')
        try {
            $vu = @((Sortie 'machine-compte-essai' | ConvertFrom-Json).constats | Where-Object { $_.probleme -and $_.message -match 'vanguard-essai' })
            if (-not $vu.Count) { Bug 'Compte sans mot de passe exigé NON signalé' }
            elseif ($vu[0].correctif -and -not $vu[0].correctif.automatique) { Ok 'Compte signalé, correction à faire soi-même (mot de passe dans les Paramètres)' }
            else { Bug 'Compte signalé, mais Vanguard propose de le corriger tout seul : le drapeau ne donne pas de mot de passe' }
        } catch { Bug "machine --json illisible : $($_.Exception.Message)" }
    }
    Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile', '-Command', 'Remove-LocalUser -Name vanguard-essai -ErrorAction SilentlyContinue'
    if (Get-LocalUser -Name 'vanguard-essai' -ErrorAction SilentlyContinue) { Bug 'Compte de test ENCORE présent : à retirer à la main' } else { Ok 'Compte de test retiré' }
} else { Info 'Sautée (il faut répondre aux fenêtres UAC).' }

Etape 'Couleurs et accents dans la console'
if ($Auto) { Sautee 'Sautée : il faut regarder l''écran (test avec questions).' } else {
    Vider-Clavier
    & $exe audit
    Constat 'Dans l''audit ci-dessus, les couleurs et les accents (é, è, ✔, ✖) s''affichent-ils correctement ?'
}

Etape 'Détection en profondeur (0.83) : points d''ancrage, pilotes, agents d''IA, chasse, sans fausse alerte sur un Windows propre'
# Une VM propre n'a ni paquet LSA inconnu, ni AppCertDlls, ni pilote rangé dans un dossier du compte : une alerte
# Moyen ou Élevé ici est sans doute une fausse alerte, à regarder avant la publication. Un constat non vérifié n'est
# jamais un succès : attendu s'il demande l'administrateur (passe sans droits), un défaut sinon.
try {
    $audit = Sortie 'machine-json' | ConvertFrom-Json
    # Recalculé ici : celui de l'étape « Audit de la machine » manque si sa lecture du bilan a échoué.
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    foreach ($id in 'WIN-PRS-007', 'WIN-PRS-008', 'WIN-PRS-009', 'WIN-PRS-010', 'WIN-PRS-011', 'WIN-PRS-012', 'COM-AGT-001', 'COM-AGT-002', 'COM-CPT-003', 'COM-PRG-001') {
        $c = @($audit.constats | Where-Object regle -eq $id)
        if (-not $c.Count) { Bug "$id absente du bilan"; continue }
        $alertes = @($c | Where-Object { $_.probleme -and $_.probleme -ne 'Info' })
        $calmes = @($c | Where-Object { -not $_.probleme -or $_.probleme -eq 'Info' })
        $nonVerifies = @($calmes | Where-Object { -not $_.verifie })
        $verifies = @($calmes | Where-Object verifie)
        $alertes | ForEach-Object { Bug "Alerte sur une VM propre (fausse alerte ?) : $id $($_.probleme) : $($_.message)" }
        foreach ($n in $nonVerifies) {
            # En administrateur, « relance en administrateur » est un défaut, pas l'effet d'une passe sans droits.
            if (-not $admin -and $n.message -match 'administrat') { Info "$id non vérifié sans droits (attendu) : $($n.message)" }
            else { Bug "$id non vérifié : $($n.message)" }
        }
        if ($verifies.Count -and -not $alertes.Count) { Ok "$id : $((@($verifies | ForEach-Object { $_.message })) -join ' | ')" }
    }
} catch { Bug "machine --json illisible : $($_.Exception.Message)" }

Etape 'Une DLL posée à côté de Vanguard n''est pas chargée (bibliothèques prises dans System32)'
# Sans DependentLoadFlags, Windows chargerait cet iphlpapi.dll vide avant la première ligne du programme et refuserait
# de le lancer (0xC000007B) ; avec, il prend celui de System32 et Vanguard démarre.
$piege = Join-Path $lieuEssais "vanguard-dll-$PID"
try {
    New-Item -ItemType Directory -Force -Path $piege | Out-Null
    Copy-Item $exe (Join-Path $piege 'vanguard.exe') -Force
    [IO.File]::WriteAllBytes((Join-Path $piege 'iphlpapi.dll'), [byte[]]@())
    $p = Start-Process -FilePath (Join-Path $piege 'vanguard.exe') -ArgumentList '--version' -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput (Join-Path $res 'dll-piege.out.txt') -RedirectStandardError (Join-Path $res 'dll-piege.err.txt')
    $v = "$(Sortie 'dll-piege')".Trim()
    if ($p.ExitCode -eq 0 -and $v -match 'vanguard') { Ok "Démarre malgré un iphlpapi.dll vide à côté : $v" }
    else { Bug "Ne démarre pas avec un iphlpapi.dll vide à côté (code $($p.ExitCode)) : la DLL locale a été chargée" }
} catch { Bug "Essai de la DLL posée à côté impossible : $($_.Exception.Message)" }
finally { Remove-Item -Recurse -Force $piege -ErrorAction SilentlyContinue }

Etape 'Mémoire des programmes (vanguard memoire, 0.83) : Defender ne bloque pas Vanguard'
# En dernier : lire la mémoire des autres programmes ressemble au geste d'un voleur de mots de passe ; si Defender mettait
# Vanguard en quarantaine, les étapes d'avant n'en sont pas faussées. Décide si la fonction entre dans la 0.83.
$avantMemoire = Get-Date
try {
    $p = Start-Process -FilePath $exe -ArgumentList 'memoire' -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput (Join-Path $res 'memoire.out.txt') -RedirectStandardError (Join-Path $res 'memoire.err.txt')
    Noter-Commande 'memoire' @('memoire') $p.ExitCode ((Get-Date) - $avantMemoire).TotalSeconds $null
    $t = "$(Sortie 'memoire')"
    # Le bilan dit combien de processus ont été lus (« Rien trouvé dans les 38 processus lus », « No memory region of
    # the 38 processes read ») ; aucun lu, ou une ligne ✖ (règles qui ne compilent pas, correspondance) : un défaut.
    $lus = @([regex]::Matches($t, '(\d+) (?:processus lus(?!\s+en partie)|processes read)'))
    $croix = @($t -split "`r?`n" | Where-Object { $_ -match '✖' })
    if ($p.ExitCode -ne 0 -or $t.Length -eq 0) { Bug "vanguard memoire : code $($p.ExitCode), sortie de $($t.Length) caractère(s)" }
    elseif ($croix.Count) { $croix | ForEach-Object { Bug "vanguard memoire : $(($_ -replace '\e\[[0-9;]*m', '').Trim())" } }
    elseif (-not $lus.Count) { Bug 'vanguard memoire : aucun « N processus lus » / « N processes read » dans la sortie' }
    elseif ([int]$lus[-1].Groups[1].Value -eq 0) { Bug "vanguard memoire : aucun processus lu ($($lus[-1].Value))" }
    else { Ok "Analyse de la mémoire terminée en $([int]((Get-Date) - $avantMemoire).TotalSeconds) s : $($lus[-1].Value)" }
} catch { Bug "vanguard memoire n'a pas pu se lancer : $($_.Exception.Message)" }
if (Test-Path $exe) { Ok 'vanguard.exe toujours là après l''analyse (pas mis en quarantaine)' }
else { Bug 'vanguard.exe a DISPARU après l''analyse de la mémoire : Defender l''a mis en quarantaine' }
try {
    $detections = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -ge $avantMemoire })
    if ($detections.Count) { $detections | ForEach-Object { Bug "Defender a réagi pendant l'analyse : menace $($_.ThreatID), $($_.Resources -join ', ')" } }
    else { Ok 'Aucune détection de Defender pendant l''analyse de la mémoire' }
} catch { Info "Détections de Defender illisibles sans droits : $($_.Exception.Message)" }

Journal "FIN $(Get-Date -Format 'HH:mm:ss')"
$rapport = Rapport
$toutes = @($script:etapes | ForEach-Object { $_.Verifs })
# Les journaux des fenêtres administrateur de cette passe (outils de Vanguard, %LOCALAPPDATA%\vanguard\corrections) :
# ce qui s'est vraiment exécuté après chaque UAC, lisible depuis Linux.
$corrections = Join-Path $env:LOCALAPPDATA 'vanguard\corrections'
$journauxAdmin = @(Get-ChildItem -LiteralPath $corrections -Filter '*.log' -ErrorAction SilentlyContinue | Where-Object LastWriteTime -ge $debutTest)
if ($journauxAdmin) {
    $versJournaux = Join-Path $res 'corrections'
    New-Item -ItemType Directory -Force $versJournaux | Out-Null
    $journauxAdmin | Copy-Item -Destination $versJournaux -Force
}
$nbOk = @($toutes | Where-Object Etat -eq 'ok').Count
$nbBug = @($toutes | Where-Object Etat -eq 'bug').Count
$nbSaute = @($toutes | Where-Object Etat -eq 'saute').Count
$nbEchec = @($script:etapes | ForEach-Object { $_.Commandes } | Where-Object Code -ne 0).Count
Write-Host ''
Write-Host '  ──────────────────────────────────────────────────────────' -ForegroundColor DarkGray
if ($nbBug -eq 0 -and $nbEchec -eq 0) { Write-Host "  ✔ Tout est passé : $nbOk vérification(s) réussie(s)." -ForegroundColor Green }
else { Write-Host "  ✖ $nbBug problème(s), $nbEchec commande(s) en échec ; $nbOk vérification(s) réussie(s)." -ForegroundColor Red }
# Le dernier rapport toujours au même endroit, et une ligne par passe dans l'historique.
Copy-Item $rapport (Join-Path $resultats 'dernier-rapport.html') -Force
$mode = if ($SansOuvrir) { 'automatique' } elseif ($Auto) { 'sans questions' } else { 'avec questions' }
# La passe précédente du même genre (sans questions et automatique font les mêmes étapes) : moins de vérifications
# réussies, c'est peut-être une étape qui a disparu en silence (le lanceur de la clé, le 19 octobre).
$genre = if ($Auto) { 'automatique|sans questions' } else { 'avec questions' }
$avant = $null
if (Test-Path (Join-Path $resultats 'historique.txt')) {
    $ligne = Get-Content (Join-Path $resultats 'historique.txt') -Encoding UTF8 | Where-Object { $_ -match "\(([0-9.,]+ min, )?($genre)\)" } | Select-Object -Last 1
    if ($ligne -match '\((\d+) vérifications|(\d+) réussies') { $avant = [int]("$($Matches[1])$($Matches[2])") }
}
$details = @()
if ($nbSaute) { $details += "$nbSaute sautée(s)" }
if ($avant -and $nbOk -lt $avant) {
    $details += "ATTENTION : $($avant - $nbOk) de moins que la passe précédente ($avant)"
    Write-Host "  ⚠ $($avant - $nbOk) vérification(s) réussie(s) de moins que la passe précédente du même genre ($avant) : une étape a-t-elle disparu ?" -ForegroundColor Yellow
}
$suite = if ($details) { ' ; ' + ($details -join ' ; ') } else { '' }
$bilan = if ($nbBug -eq 0 -and $nbEchec -eq 0) { "OK, tout est passé ($nbOk vérifications$suite)" } else { "$nbBug problème(s), $nbEchec commande(s) en échec, $nbOk réussies$suite" }
# Les nombres de la passe, lisibles par un programme (la file d'essais sans clic, surveillant-essais.ps1).
[IO.File]::WriteAllText((Join-Path $res 'bilan.txt'), ("ok=$nbOk`r`nbugs=$nbBug`r`nechecs=$nbEchec`r`nsautees=$nbSaute`r`nversion=$numero`r`n"), (New-Object Text.UTF8Encoding $false))
Add-Content -Path (Join-Path $resultats 'historique.txt') -Encoding UTF8 -Value ('{0}  v{1,-8} {2}  ({3:N1} min, {4})  -> {5}  sha256 {6}' -f `
    (Get-Date -Format 'yyyy-MM-dd HH:mm'), $numero, $bilan, ((Get-Date) - $debutTest).TotalMinutes, $mode, (Split-Path -Leaf $res), $empreinteEssayee)
Write-Host "  Rapport : $rapport" -ForegroundColor DarkGray
if (-not $SansOuvrir) {
    Start-Process $rapport
    Write-Host '  Le rapport s''ouvre dans le navigateur. Tu peux revenir sur Linux.' -ForegroundColor DarkGray
}

# Menu des tests de Vanguard dans la machine virtuelle Windows : double-clic sur TESTER-VANGUARD.bat.
# Le dossier « programme » (vanguard.exe, ce menu, test.ps1, version.txt) est remplacé à chaque déploiement depuis
# Linux (outils/deployer.sh) ; les résultats de chaque passe vont dans « resultats » et y restent.
# -Surveiller : lancé par la tâche planifiée (choix 6) ; teste en arrière-plan chaque nouvelle version déposée, une
# seule fois, puis prévient par une notification. Avec le choix 7, lance aussi les scripts déposés depuis Linux dans
# « a-lancer » (sans droits administrateur), pour que Claude fasse une passe sans qu'on ait à cliquer.
param([switch]$Surveiller)

$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$OutputEncoding = [Text.Encoding]::UTF8

$programme = $PSScriptRoot
$racine = Split-Path -Parent $programme
$resultats = Join-Path $racine 'resultats'
New-Item -ItemType Directory -Force $resultats | Out-Null
$tache = 'Vanguard - tester chaque nouvelle version'
$fichierVersion = Join-Path $programme 'version.txt'
$versionTestee = Join-Path $resultats '.version-testee.txt'
$enCours = Join-Path $resultats '.test-en-cours.txt'
$historique = Join-Path $resultats 'historique.txt'
$aLancer = Join-Path $racine 'a-lancer'
# L'accord pour les scripts déposés vit dans ce Windows, hors du partage : écrit depuis Linux, il ne vaudrait rien,
# puisque c'est justement Linux qui dépose les scripts.
$local = Join-Path $env:LOCALAPPDATA 'vanguard-test'
$permis = Join-Path $local 'scripts-de-linux-acceptes.txt'

# version.txt : « vanguard X.Y.Z » puis l'empreinte du programme (une nouvelle compilation change l'empreinte).
function Version-Deposee { if (Test-Path $fichierVersion) { (Get-Content $fichierVersion -Raw).Trim() } else { '' } }
function Version-Courte { ((Version-Deposee) -split "`r?`n")[0] }
function Version-Deja-Testee {
    $v = Version-Deposee
    $v -and (Test-Path $versionTestee) -and ((Get-Content $versionTestee -Raw).Trim() -eq $v)
}

# Un test à la fois : un autre (manuel ou automatique) peut tourner. Au-delà de 3 h, le témoin est périmé.
# -Force : le partage de la VM (Samba) marque caché un fichier qui commence par un point ; sans -Force, Get-Item ne
# le trouve pas et Remove-Item ne l'enlève pas, et le témoin restait pour toujours.
# Le témoin seul ne suffit pas : vu d'ici à travers le partage, il peut rester après avoir été retiré côté Linux, ou
# survivre à un test fermé en route. Un test tourne vraiment s'il existe un PowerShell qui exécute test.ps1 ; sinon le
# témoin est périmé et retiré (par Windows lui-même, ce qui met aussi le partage à jour).
function Tests-Lances {
    @(Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like '*test.ps1*' })
}

# Un travail de la file d'essais (surveillant-essais.ps1) tourne en administrateur : sa ligne de commande est
# illisible d'ici et ce menu ne peut pas l'arrêter, mais il rafraîchit file-essais\en-cours.txt toutes les 30 s.
function Essai-De-La-File {
    (Get-Item -LiteralPath (Join-Path $racine 'file-essais\en-cours.txt') -Force -ErrorAction SilentlyContinue).LastWriteTime -gt (Get-Date).AddMinutes(-3)
}

function Test-En-Cours {
    $temoin = Get-Item -LiteralPath $enCours -Force -ErrorAction SilentlyContinue
    if (-not $temoin) { return $false }
    if (Essai-De-La-File) { return $true }
    if (((Get-Date) - $temoin.LastWriteTime).TotalHours -lt 3) {
        if ((Tests-Lances).Count) { return $true }
        # Un témoin frais qui n'est pas celui d'une passe de ce menu (une date seule) : VM réservée depuis Linux, banc
        # d'essais à part (essais-socle), surveillant de la file. Le retirer ici, à chaque tour de -Surveiller, rendait
        # la VM au test automatique en pleine réservation ; il périme seul au bout de 3 h.
        $contenu = try { [IO.File]::ReadAllText($temoin.FullName).Trim() } catch { '' }
        if ($contenu -notmatch '^\d{4}-\d\d-\d\dT[\d:.]+(Z|[+-]\d\d:\d\d)?$') { return $true }
    }
    Remove-Item -LiteralPath $enCours -Force -ErrorAction SilentlyContinue
    return $false
}

# Dans un PowerShell à part : le test garde ses variables pour lui et ne peut pas fermer ce menu. Start-Process lui
# laisse la console (couleurs comprises) : appelé directement depuis une fonction, sa sortie deviendrait celle de la
# fonction et ne s'afficherait pas.
function Lancer-Test([string[]]$options) {
    if (Test-En-Cours) {
        if (Essai-De-La-File) {
            # Rien ne l'arrêterait d'ici : retirer le témoin lancerait une seconde passe en même temps que la sienne.
            Write-Host '  Un essai déposé depuis Linux (file d''essais, en administrateur) tourne : il ne peut pas être arrêté d''ici.' -ForegroundColor Yellow
            Write-Host '  Attendre sa fin (file-essais\historique.txt), ou DESINSTALLER-ESSAIS-AUTO.bat pour l''arrêter.' -ForegroundColor Yellow
            return $false
        }
        # Le test automatique tourne en arrière-plan, sans fenêtre : bloqué, il ne pourrait pas être fermé autrement.
        $debut = (Get-Item -LiteralPath $enCours -Force -ErrorAction SilentlyContinue).LastWriteTime
        Write-Host "  Un test tourne déjà depuis $('{0:HH:mm}' -f $debut) (peut-être le test automatique, sans fenêtre)." -ForegroundColor Yellow
        if ((Read-Host '  L''arrêter pour lancer celui-ci ? [o/N]') -notmatch '^(o|oui|y)') { return $false }
        Tests-Lances | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        Remove-Item -LiteralPath $enCours -Force -ErrorAction SilentlyContinue
    }
    $version = Version-Deposee
    Set-Content -LiteralPath $enCours -Value (Get-Date -Format o) -Force
    try {
        $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$(Join-Path $programme 'test.ps1')`"") + $options
        Start-Process powershell.exe -ArgumentList $arguments -NoNewWindow -Wait
        Set-Content -Path $versionTestee -Value $version -Encoding UTF8
    } finally {
        Remove-Item -LiteralPath $enCours -Force -ErrorAction SilentlyContinue
    }
    return $true
}

# Notification Windows (dans le coin de l'écran) ; sans elle, l'historique suffit.
function Notifier($titre, $texte) {
    try {
        [void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
        [void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
        $e = [System.Security.SecurityElement]
        $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
        $xml.LoadXml("<toast><visual><binding template='ToastGeneric'><text>$($e::Escape($titre))</text><text>$($e::Escape($texte))</text></binding></visual></toast>")
        $appli = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appli).Show([Windows.UI.Notifications.ToastNotification]::new($xml))
    } catch { }
}

function Derniere-Passe {
    if (Test-Path $historique) { (Get-Content $historique -Encoding UTF8 | Where-Object { $_ } | Select-Object -Last 1) } else { $null }
}

function Scripts-Acceptes { Test-Path -LiteralPath $permis }

# Chaque script de « a-lancer », par ordre de nom : copié dans ce Windows puis retiré du partage, de sorte que ce qui
# tourne est ce qui a été lu (pas un fichier remplacé en route), et lancé par le même PowerShell que ce menu. Ses
# sorties et son code vont dans resultats\<date>_script-<nom>\, FINI.txt en dernier : Linux attend ce fichier.
function Lancer-Scripts-Deposes {
    if (-not (Scripts-Acceptes)) { return }
    $scripts = @(Get-ChildItem -LiteralPath $aLancer -Filter '*.ps1' -File -ErrorAction SilentlyContinue | Sort-Object Name)
    $powershell = (Get-Process -Id $PID).Path
    foreach ($s in $scripts) {
        $dossier = Join-Path $resultats ((Get-Date -Format 'yyyy-MM-dd_HH-mm-ss') + '_script-' + $s.BaseName)
        New-Item -ItemType Directory -Force $dossier | Out-Null
        $copie = Join-Path $local $s.Name
        Copy-Item -LiteralPath $s.FullName $copie -Force
        Remove-Item -LiteralPath $s.FullName -Force
        Copy-Item -LiteralPath $copie $dossier
        $debut = Get-Date
        & $powershell -NoProfile -ExecutionPolicy Bypass -File $copie 2>&1 | Out-File -FilePath (Join-Path $dossier 'sortie.txt') -Encoding UTF8
        $code = $LASTEXITCODE
        Remove-Item -LiteralPath $copie -Force -ErrorAction SilentlyContinue
        "fin $(Get-Date -Format 'HH:mm:ss'), code $code, $([int]((Get-Date) - $debut).TotalSeconds) s" |
            Set-Content -LiteralPath (Join-Path $dossier 'FINI.txt') -Encoding UTF8
        Notifier "Vanguard : script $($s.Name) terminé" "code $code"
    }
}

if ($Surveiller) {
    # Jamais pendant une passe : un script pourrait la fausser.
    if (Test-En-Cours) { exit 0 }
    Lancer-Scripts-Deposes
    if (-not (Version-Deposee) -or (Version-Deja-Testee) -or (Test-En-Cours)) { exit 0 }
    if (Lancer-Test @('-Auto', '-SansOuvrir')) {
        Notifier "Vanguard : $(Version-Courte) testée" ((Derniere-Passe) -replace '\s+->.*$', '')
    }
    exit 0
}

# Tâche planifiée du compte, sans droits administrateur : à l'ouverture de session puis toutes les 5 minutes (sans
# rien à faire, elle s'arrête aussitôt ; 15 minutes faisaient trop attendre un script déposé).
function Surveillance-Active { [bool](Get-ScheduledTask -TaskName $tache -ErrorAction SilentlyContinue) }
function Basculer-Surveillance {
    if (Surveillance-Active) {
        Unregister-ScheduledTask -TaskName $tache -Confirm:$false
        Write-Host '  Test automatique désactivé.' -ForegroundColor Yellow
        return
    }
    $moi = "$env:USERDOMAIN\$env:USERNAME"
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$(Join-Path $programme 'menu.ps1')`" -Surveiller"
    $declencheurs = @(
        (New-ScheduledTaskTrigger -AtLogOn -User $moi),
        (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5))
    )
    $reglages = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 3)
    $principal = New-ScheduledTaskPrincipal -UserId $moi -LogonType Interactive -RunLevel Limited
    try {
        Register-ScheduledTask -TaskName $tache -Action $action -Trigger $declencheurs -Settings $reglages -Principal $principal `
            -Description 'Teste en arrière-plan chaque nouvelle version de Vanguard déposée depuis Linux, puis prévient.' -Force -ErrorAction Stop | Out-Null
        Write-Host '  Test automatique activé : chaque nouvelle version sera testée seule (dans la minute, puis toutes les 5 minutes),' -ForegroundColor Green
        Write-Host '  sans rien ouvrir à l''écran ; une notification prévient à la fin.' -ForegroundColor Green
    } catch {
        Write-Host "  Impossible de créer la tâche planifiée : $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Le partage s'écrit depuis Linux : accepter ses scripts, c'est laisser Linux lancer ce qu'il veut dans ce compte (sans
# droits administrateur). À réserver à une machine de test, et dit tel quel avant l'accord.
function Basculer-Scripts {
    if (Scripts-Acceptes) {
        Remove-Item -LiteralPath $permis -Force
        Write-Host '  Scripts déposés depuis Linux : refusés désormais.' -ForegroundColor Yellow
        return
    }
    Write-Host '  Tout script .ps1 posé dans VANGUARD-TEST\a-lancer (depuis Linux) sera lancé dans ce compte,' -ForegroundColor Yellow
    Write-Host '  sans droits administrateur, dans les 5 minutes ; sa sortie va dans resultats. Le dossier partagé' -ForegroundColor Yellow
    Write-Host '  s''écrit depuis Linux : à n''accepter que dans une machine virtuelle de test.' -ForegroundColor Yellow
    if ((Read-Host '  Accepter ? [o/N]') -notmatch '^(o|oui|y)') { return }
    New-Item -ItemType Directory -Force $local, $aLancer | Out-Null
    Set-Content -LiteralPath $permis -Value (Get-Date -Format o)
    Write-Host '  Scripts déposés depuis Linux : acceptés.' -ForegroundColor Green
    # Ils passent par la tâche du test automatique : elle doit exister.
    if (-not (Surveillance-Active)) { Basculer-Surveillance }
}

function Ouvrir-Vanguard {
    # Une copie locale, comme pour le test : un .exe sur un partage réseau déclenche des avertissements.
    $local = Join-Path $env:LOCALAPPDATA 'vanguard-test'
    New-Item -ItemType Directory -Force $local | Out-Null
    Copy-Item (Join-Path $programme 'vanguard.exe') $local -Force
    $exe = Join-Path $local 'vanguard.exe'
    Unblock-File $exe -ErrorAction SilentlyContinue
    Start-Process $exe
}

function Pause-Menu { Write-Host ''; Read-Host '  Entrée pour revenir au menu' | Out-Null }

while ($true) {
    Clear-Host
    $auto = Surveillance-Active
    $etatAuto = if ($auto) { 'ACTIVÉ' } else { 'désactivé' }
    $testee = if (Version-Deja-Testee) { 'déjà testée' } else { 'pas encore testée' }
    Write-Host ''
    Write-Host '  ╭──────────────────────────────────────────────────────────────╮' -ForegroundColor Red
    Write-Host ('  │  ' + 'VANGUARD · TESTS SUR CE WINDOWS'.PadRight(60) + '│') -ForegroundColor Red
    Write-Host ('  │  ' + "Version déposée : $(Version-Courte) ($testee)".PadRight(60) + '│') -ForegroundColor Red
    Write-Host '  ╰──────────────────────────────────────────────────────────────╯' -ForegroundColor Red
    Write-Host ''
    Write-Host '   1  Test complet automatique, sans question    5 à 15 min, conseillé'
    Write-Host '   2  Test complet avec questions                fenêtres UAC, mot de passe, écran'
    Write-Host '   3  Ouvrir Vanguard                            pour essayer à la main'
    Write-Host '   4  Voir le dernier rapport'
    Write-Host '   5  Ouvrir le dossier des résultats'
    Write-Host "   6  Tester seul chaque nouvelle version        $etatAuto"
    $etatScripts = if (Scripts-Acceptes) { if ($auto) { 'ACCEPTÉS' } else { 'acceptés, mais 6 désactivé' } } else { 'refusés' }
    Write-Host "   7  Lancer les scripts déposés depuis Linux    $etatScripts"
    Write-Host '   Q  Quitter'
    if (Test-Path $historique) {
        Write-Host ''
        Write-Host '  Dernières passes :' -ForegroundColor DarkGray
        Get-Content $historique -Encoding UTF8 | Where-Object { $_ } | Select-Object -Last 5 |
            ForEach-Object { Write-Host ('   ' + ($_ -replace '\s+->.*$', '')) -ForegroundColor DarkGray }
    }
    if (Test-En-Cours) { Write-Host ''; Write-Host '  Un test tourne en ce moment.' -ForegroundColor Yellow }
    Write-Host ''
    switch ((Read-Host '  Choix').Trim().ToLower()) {
        '1' { [void](Lancer-Test @('-Auto')); Pause-Menu }
        '2' { [void](Lancer-Test @()); Pause-Menu }
        '3' { Ouvrir-Vanguard }
        '4' {
            $r = Join-Path $resultats 'dernier-rapport.html'
            if (Test-Path $r) { Start-Process $r } else { Write-Host '  Aucun rapport pour l''instant : lance un test (1).' -ForegroundColor Yellow; Pause-Menu }
        }
        '5' { Start-Process explorer.exe $resultats }
        '6' { Basculer-Surveillance; Pause-Menu }
        '7' { Basculer-Scripts; Pause-Menu }
        'q' { exit 0 }
    }
}

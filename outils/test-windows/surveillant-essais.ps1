# Le surveillant de la file d'essais, dans la machine virtuelle Windows de test : une boucle lancée par la tâche
# planifiée « Vanguard-File-Essais » (installée une fois par INSTALLER-ESSAIS-AUTO.bat, en administrateur), qui fait
# chaque travail déposé depuis Linux par outils/vm-tester.sh dans \\host.lan\Data\VANGUARD-TEST\file-essais\<id>\ :
# empreintes vérifiées sur une copie locale, test.ps1 -Auto -SansOuvrir, essais de console, puis fini.txt en dernier.
#
# SÉCURITÉ : ce qui est déposé dans file-essais s'exécute en administrateur DANS LA VM, sans clic. Le partage s'écrit
# depuis Linux, mais aussi depuis la VM elle-même, par n'importe quel compte (Samba range tout sous le compte Linux) :
# un travail n'est donc fait que s'il porte la preuve de sa provenance, un HMAC-SHA256 de travail.txt (empreintes des
# fichiers comprises) par le secret tiré à l'installation (secret.bin, que seuls les administrateurs lisent ; côté
# Linux, ~/.config/vanguard/file-essais/secret, hors du partage). Sans secret, rien n'est lancé ; un id déjà fait ne
# l'est pas deux fois. fini.txt porte à son tour le HMAC du surveillant : Linux ne croit que lui (campagne d'attaque
# n° 3). Tout programme du compte Linux, qui lit ce secret, peut encore devenir administrateur de la VM. À n'installer
# que dans la VM de test : sans \\host.lan\Data, rien n'est jamais lancé. Seuls les fichiers nommés dans travail.txt (liste
# fermée) sont lus, sans suivre de lien Windows ; un lien symbolique de Linux, Samba le suit lui-même et il ne se voit
# pas d'ici : outils/vm-tester.sh refuse d'en déposer. Ils sont copiés dans %ProgramData%\Vanguard-File-Essais\travaux,
# que seuls les administrateurs modifient, et tout ce qui est lancé l'est de là (test.ps1 -SurPlace) : un programme
# sans droits dans la VM ne peut rien y remplacer. Ce fichier vit dans %ProgramData%\Vanguard-File-Essais (dossier
# vérifié à chaque démarrage) et ne se met jamais à jour lui-même.
#
# -EssaiLocal (Linux, pwsh, outils/vm-tester.sh --essai-local) : la même logique de fichiers sur un dossier jetable
# (-Racine) : ni tâche, ni droits, ni processus de Windows ; -UnTour fait un seul tour.
param(
    [switch]$EssaiLocal,
    [string]$Racine,
    [switch]$UnTour,
    [int]$DelaiSecondes = 0
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$VersionSurveillant = 2
$MotifId = '^\d{8}-\d{6}-[0-9a-f]{7,12}-[0-9a-z]{4}$'
# Les seuls fichiers qu'un travail peut nommer : rien d'autre n'est copié ni lancé.
$FichiersPermis = @('vanguard.exe', 'test.ps1', 'essais-console.ps1', 'Lancer Vanguard.bat')
$ClesConnues = @('format', 'id', 'commit', 'branche', 'modifie', 'cree', 'test', 'console', 'langues', 'delai_minutes', 'hmac')
# Les domaines des HMAC : un travail signé ne vaut jamais pour un verdict, ni l'inverse (le même texte en vm-tester.sh).
$DomaineTravail = 'vanguard-file-essais travail 1'
$DomaineFini = 'vanguard-file-essais fini 1'
$Utf8 = New-Object Text.UTF8Encoding $false

if ($EssaiLocal) {
    if (-not $IsLinux) { Write-Error '-EssaiLocal ne sert que sous Linux (outils/vm-tester.sh --essai-local).'; exit 2 }
    if (-not $Racine -or -not (Test-Path -LiteralPath $Racine -PathType Container)) { Write-Error 'Il faut -Racine, un dossier existant.'; exit 2 }
    $Partage = (Resolve-Path -LiteralPath $Racine).Path
    $Prive = Join-Path (Split-Path -Parent $Partage) 'prive-surveillant'
    $PowerShell = (Get-Process -Id $PID).Path
} else {
    if ($IsLinux -or $IsMacOS) { Write-Error 'Le surveillant ne tourne que dans la VM Windows.'; exit 2 }
    if ($DelaiSecondes) { Write-Error '-DelaiSecondes ne sert qu''avec -EssaiLocal.'; exit 2 }
    $Partage = '\\host.lan\Data\VANGUARD-TEST'
    # Par les dossiers connus de Windows, jamais par %ProgramData% ni %SystemRoot% : l'utilisateur sans droits peut
    # redéfinir ces variables (HKCU\Environment), et ce script tourne en administrateur.
    $Prive = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Vanguard-File-Essais'
    $PowerShell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
}
$LocalTravaux = Join-Path $Prive 'travaux'
$File = Join-Path $Partage 'file-essais'
$Temoin = Join-Path (Join-Path $Partage 'resultats') '.test-en-cours.txt'
$EnCours = Join-Path $File 'en-cours.txt'
$Battement = Join-Path $File 'battement.txt'
# Dans la VM, le dossier vient de l'installation, avec ses droits : jamais créé ici (voir Est-Protege).
if ($EssaiLocal) { New-Item -ItemType Directory -Force -Path $Prive | Out-Null }
$JournalGeneral = Join-Path $Prive 'journal.txt'
$SecretChemin = Join-Path $Prive 'secret.bin'
$IdsVus = Join-Path $Prive 'ids-vus.txt'
$script:journalTravail = $null

function Maintenant { Get-Date -Format 'yyyy-MM-ddTHH:mm:sszzz' }

# Une ligne par événement ; au-delà de 1 Mo, l'ancien journal devient journal.1.txt.
function Journal([string]$t) {
    $ligne = "$(Maintenant) $t"
    try {
        $f = Get-Item -LiteralPath $JournalGeneral -ErrorAction SilentlyContinue
        if ($f -and $f.Length -gt 1MB) { Move-Item -LiteralPath $JournalGeneral (Join-Path $Prive 'journal.1.txt') -Force }
        [IO.File]::AppendAllText($JournalGeneral, $ligne + "`r`n", $Utf8)
    } catch { }
    if ($null -ne $script:journalTravail) { [void]$script:journalTravail.Add($ligne) }
}

# Les fichiers « cle=valeur » : UTF-8 sans BOM, CRLF (Linux retire les \r).
function Texte-Cles($cles) {
    (($cles.GetEnumerator() | ForEach-Object { "$($_.Key)=$(([string]$_.Value) -replace '[\r\n]+', ' ')" }) -join "`r`n") + "`r`n"
}
function Ecrire-Cles([string]$chemin, $cles) {
    [IO.File]::WriteAllText($chemin, (Texte-Cles $cles), $Utf8)
}
function Lire-Cles([string]$chemin) { Lire-Cles-Texte ([IO.File]::ReadAllText($chemin, $Utf8)) }
function Lire-Cles-Texte([string]$texte) {
    $cles = [ordered]@{}
    $texte = $texte.TrimStart([char]0xFEFF)
    foreach ($l in ($texte -split "`r?`n")) {
        if (-not $l.Trim()) { continue }
        $i = $l.IndexOf('=')
        if ($i -lt 1) { throw "REFUS: ligne illisible dans travail.txt : « $l »" }
        $k = $l.Substring(0, $i); $v = $l.Substring($i + 1)
        if ($cles.Contains($k)) { throw "REFUS: clé « $k » en double dans travail.txt" }
        $cles[$k] = $v
    }
    $cles
}

# Le secret de la file : 32 octets tirés par l'installation, dans un fichier que seuls les administrateurs et SYSTEM
# lisent (propriétaire Administrateurs, sans héritage). Absent ou mal protégé : $null, et aucun travail n'est fait.
function Lire-Secret {
    $item = Get-Item -LiteralPath $SecretChemin -Force -ErrorAction SilentlyContinue
    if (-not $item -or $item.PSIsContainer -or (Est-Lien $item) -or $item.Length -ne 32) { return $null }
    if (-not $EssaiLocal) {
        $acl = Get-Acl -LiteralPath $SecretChemin
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544' -or -not $acl.AreAccessRulesProtected) { return $null }
        foreach ($r in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($r.AccessControlType -eq 'Allow' -and $r.IdentityReference.Value -notin 'S-1-5-32-544', 'S-1-5-18') { return $null }
        }
    }
    , [IO.File]::ReadAllBytes($SecretChemin)
}

# HMAC-SHA256 (System.Security.Cryptography) du domaine, d'un saut de ligne, puis des octets ; en hexadécimal.
function Hmac([byte[]]$secret, [string]$domaine, [byte[]]$octets) {
    $h = New-Object Security.Cryptography.HMACSHA256 (, $secret)
    $d = $Utf8.GetBytes("$domaine`n")
    $tout = New-Object byte[] ($d.Length + $octets.Length)
    [Array]::Copy($d, $tout, $d.Length); [Array]::Copy($octets, 0, $tout, $d.Length, $octets.Length)
    ([BitConverter]::ToString($h.ComputeHash($tout)) -replace '-', '').ToLower()
}
# Deux textes de même longueur comparés sans s'arrêter au premier écart.
function Egaux-Constant([string]$a, [string]$b) {
    if ($a.Length -ne $b.Length) { return $false }
    $d = 0
    for ($i = 0; $i -lt $a.Length; $i++) { $d = $d -bor ([int][char]$a[$i] -bxor [int][char]$b[$i]) }
    $d -eq 0
}
# Le corps d'un fichier signé (tout jusqu'à sa dernière ligne, « hmac=<64 hexadécimaux> », CRLF compris) s'il porte
# le bon HMAC ; sinon une exception « REFUS: … ». Lu une fois, en octets : ce qui est vérifié est ce qui est lu.
function Corps-Signe([byte[]]$octets, [byte[]]$secret, [string]$domaine, [string]$quoi) {
    $n = $octets.Length
    if ($n -lt 72 -or $octets[$n - 1] -ne 10 -or $octets[$n - 2] -ne 13) { throw "REFUS: $quoi sans signature (hmac)" }
    $i = $n - 3
    while ($i -ge 0 -and $octets[$i] -ne 10) { $i-- }
    $debut = $i + 1
    $ligne = [Text.Encoding]::ASCII.GetString($octets, $debut, $n - 2 - $debut)
    if ($ligne -notmatch '^hmac=([0-9a-f]{64})$') { throw "REFUS: $quoi sans signature (hmac)" }
    $vu = $Matches[1]
    $corps = New-Object byte[] $debut
    [Array]::Copy($octets, $corps, $debut)
    if (-not (Egaux-Constant (Hmac $secret $domaine $corps) $vu)) {
        throw "REFUS: signature de $quoi fausse (déposé par un autre que Linux, ou secret changé : réinstaller)"
    }
    , $corps
}

function Ecrire-Battement([string]$etat) {
    try {
        Ecrire-Cles $Battement ([ordered]@{ format = 1; heure = (Maintenant); surveillant = $VersionSurveillant; etat = $etat; machine = [Environment]::MachineName })
    } catch { Journal "battement impossible à écrire : $($_.Exception.Message)" }
}

function Est-Lien($item) { [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint) }

# Le dossier du surveillant (et des travaux, dedans) : à Administrateurs, sans héritage, modifiable seulement par les
# administrateurs et SYSTEM (Utilisateurs : lecture). Posé ainsi par l'installation ; sinon, rien n'est lancé.
function Est-Protege([string]$dossier) {
    $item = Get-Item -LiteralPath $dossier -Force -ErrorAction SilentlyContinue
    if (-not $item -or -not $item.PSIsContainer -or (Est-Lien $item)) { return $false }
    $acl = Get-Acl -LiteralPath $dossier
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544' -or -not $acl.AreAccessRulesProtected) { return $false }
    $ecriture = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    foreach ($r in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($r.AccessControlType -ne 'Allow' -or $r.IdentityReference.Value -in 'S-1-5-32-544', 'S-1-5-18') { continue }
        if ($r.IdentityReference.Value -eq 'S-1-5-32-545' -and -not ($r.FileSystemRights -band $ecriture)) { continue }
        return $false
    }
    $true
}

# Le dossier des travaux, dans celui du surveillant dont il hérite les droits : un programme sans droits ne peut pas
# remplacer un fichier entre la vérification de son empreinte et son lancement.
function Preparer-Local {
    if (Test-Path -LiteralPath $LocalTravaux) {
        if (Est-Lien (Get-Item -LiteralPath $LocalTravaux -Force)) { throw "$LocalTravaux est un lien : refusé" }
    } else { New-Item -ItemType Directory -Path $LocalTravaux | Out-Null }
}

# Les processus d'un travail : l'arbre du PowerShell de la partie (s'il est connu), et tout processus lancé depuis le
# dossier local du travail ou dont la ligne de commande le nomme (les restes d'une boucle arrêtée en route), avec
# leurs descendants. Par numéro, jamais par le nom seul.
function Arreter-Processus($p, [string]$localTravail) {
    $d = $localTravail.TrimEnd('\', '/')
    if ($EssaiLocal) {
        $ids = @(if ($p) { $p.Id }) + @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $PID -and "$($_.CommandLine)" -like "*$d*" } | ForEach-Object { $_.Id })
        foreach ($id in ($ids | Select-Object -Unique)) { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue; Journal "arrêté : processus $id" }
        return
    }
    $tous = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    $arbre = New-Object System.Collections.Generic.List[int]
    if ($p) { $arbre.Add($p.Id) }
    foreach ($x in $tous) {
        if ($x.ProcessId -eq $PID) { continue }
        if (("$($x.ExecutablePath)" -like "$d\*") -or ("$($x.CommandLine)" -like "*$d*")) { $arbre.Add([int]$x.ProcessId) }
    }
    for ($i = 0; $i -lt $arbre.Count; $i++) { $tous | Where-Object { $_.ParentProcessId -eq $arbre[$i] -and $_.ProcessId -ne $PID } | ForEach-Object { $arbre.Add([int]$_.ProcessId) } }
    foreach ($id in ($arbre | Select-Object -Unique)) { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue; Journal "arrêté : processus $id" }
}

# Le témoin des passes (resultats\.test-en-cours.txt) est-il celui d'un travail de la file (« file-essais <id> … ») ?
function Temoin-De-La-File([string]$id = '') {
    try { $c = [IO.File]::ReadAllText($Temoin) } catch { return $false }
    if ($id) { $c.StartsWith("file-essais $id ") } else { $c.StartsWith('file-essais ') }
}

# fini.txt en dernier, entier d'un coup : Linux n'en lit jamais une moitié. Signé par le secret (HMAC, dernière
# ligne) : un verdict écrit par un autre que le surveillant ne passe pas pour le sien. Sans secret, pas de signature
# (Linux le dit « non authentifié », jamais vert).
function Ecrire-Fini($dossier, $fini) {
    $tmp = Join-Path $dossier 'fini.txt.tmp'
    $octets = $Utf8.GetBytes((Texte-Cles $fini))
    $secret = Lire-Secret
    if ($secret) { $octets = $octets + $Utf8.GetBytes("hmac=$(Hmac $secret $DomaineFini $octets)`r`n") }
    [IO.File]::WriteAllBytes($tmp, [byte[]]$octets)
    Move-Item -LiteralPath $tmp -Destination (Join-Path $dossier 'fini.txt') -Force
}

# Les résultats sur le partage : la passe de test.ps1, ses sorties, les essais de console.
function Copier-Resultats([string]$localTravail, [string]$resultatsPartage) {
    New-Item -ItemType Directory -Force -Path $resultatsPartage | Out-Null
    if (-not (Test-Path -LiteralPath $localTravail)) { return }
    $passe = Get-ChildItem -LiteralPath (Join-Path $localTravail 'resultats') -Directory -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
    if ($passe) { Get-ChildItem -LiteralPath $passe.FullName -Force | Copy-Item -Destination $resultatsPartage -Recurse -Force }
    foreach ($f in 'test-sortie.txt', 'test-sortie.txt.err', 'console-sortie.txt', 'console-sortie.txt.err') {
        $c = Join-Path $localTravail $f
        if (Test-Path -LiteralPath $c) { Copy-Item -LiteralPath $c -Destination $resultatsPartage -Force }
    }
    $c = Join-Path $localTravail 'resultats-console'
    if (Test-Path -LiteralPath $c) { Copy-Item -LiteralPath $c -Destination (Join-Path $resultatsPartage 'console') -Recurse -Force }
}

# Attend la fin d'un processus jusqu'à `limite`, en tenant le battement et en-cours.txt à jour (toutes les 30 s).
function Attendre($p, [datetime]$limite, [string]$id, [string]$quoi) {
    while (-not $p.HasExited) {
        $reste = ($limite - (Get-Date)).TotalMilliseconds
        if ($reste -le 0) { return $false }
        Ecrire-Battement "travail $id ($quoi)"
        try { Ecrire-Cles $EnCours ([ordered]@{ id = $id; debut = $script:debutTravail; partie = $quoi }) } catch { }
        [void]$p.WaitForExit([int][Math]::Min(30000, [Math]::Max(1, $reste)))
    }
    $true
}

# Le bilan de test.ps1 : bilan.txt de la dernière passe, sinon la dernière ligne de son historique.
function Bilan-Test([string]$localTravail) {
    $passe = Get-ChildItem -LiteralPath (Join-Path $localTravail 'resultats') -Directory -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
    $b = @{ lu = $false; ok = 0; bugs = 0; echecs = 0; sautees = 0; passe = $passe }
    if ($passe -and (Test-Path -LiteralPath (Join-Path $passe.FullName 'bilan.txt'))) {
        $c = Lire-Cles (Join-Path $passe.FullName 'bilan.txt')
        foreach ($k in 'ok', 'bugs', 'echecs', 'sautees') { if ($c[$k] -match '^\d+$') { $b[$k] = [int]$c[$k] } }
        $b.lu = $true
        return $b
    }
    $h = Join-Path (Join-Path $localTravail 'resultats') 'historique.txt'
    if (Test-Path -LiteralPath $h) {
        $l = Get-Content -LiteralPath $h -Encoding UTF8 | Where-Object { $_ } | Select-Object -Last 1
        if ($l -match 'OK, tout est passé \((\d+) vérifications') { $b.ok = [int]$Matches[1]; $b.lu = $true }
        elseif ($l -match '(\d+) problème\(s\), (\d+) commande\(s\) en échec, (\d+) réussies') {
            $b.bugs = [int]$Matches[1]; $b.echecs = [int]$Matches[2]; $b.ok = [int]$Matches[3]; $b.lu = $true
        }
        if ($l -match '(\d+) sautée\(s\)') { $b.sautees = [int]$Matches[1] }
    }
    $b
}

# Lit et vérifie travail.txt : sa signature d'abord (HMAC par le secret de la file : seul Linux le dépose), puis
# format, clés connues, id = nom du dossier et pas déjà fait, liste fermée de fichiers.
function Lire-Travail($dossier) {
    $secret = Lire-Secret
    if (-not $secret) { throw 'REFUS: pas de secret de la file dans la VM (installation d''avant la signature, ou secret.bin mal protégé) : réinstaller (INSTALLER-ESSAIS-AUTO.bat)' }
    $corps = Corps-Signe ([IO.File]::ReadAllBytes((Join-Path $dossier.FullName 'travail.txt'))) $secret $DomaineTravail 'travail.txt'
    $t = Lire-Cles-Texte ($Utf8.GetString($corps))
    foreach ($k in $t.Keys) {
        if ($k -notin $ClesConnues -and $k -notlike 'sha256.*') { throw "REFUS: clé inconnue « $k »" }
    }
    if ($t['format'] -ne '1') { throw "REFUS: format « $($t['format']) » inconnu (1 attendu)" }
    if ($t['id'] -ne $dossier.Name) { throw "REFUS: l'id « $($t['id']) » n'est pas le nom du dossier" }
    # Un travail signé rejoué (pris.txt et fini.txt retirés) : jamais deux fois.
    if ((Test-Path -LiteralPath $IdsVus) -and ([IO.File]::ReadAllLines($IdsVus) -contains $t['id'])) { throw "REFUS: travail $($t['id']) déjà fait (rejoué)" }
    $vus = @(if (Test-Path -LiteralPath $IdsVus) { [IO.File]::ReadAllLines($IdsVus) | Select-Object -Last 999 }) + $t['id']
    [IO.File]::WriteAllLines($IdsVus, [string[]]$vus, $Utf8)
    if ($t['commit'] -notmatch '^([0-9a-f]{40}|inconnu)$') { throw 'REFUS: commit illisible' }
    foreach ($k in 'test', 'console') { if ($t[$k] -notin 'oui', 'non') { throw "REFUS: $k=oui ou non attendu" } }
    if ($t['test'] -eq 'non' -and $t['console'] -eq 'non') { throw 'REFUS: ni test ni console demandés' }
    $langues = @("$($t['langues'])" -split ',' | Where-Object { $_ })
    if (-not $langues.Count -or @($langues | Where-Object { $_ -notin 'fr', 'en' }).Count) { throw 'REFUS: langues=fr,en attendu' }
    if ($t['delai_minutes'] -notmatch '^\d{1,4}$') { throw 'REFUS: delai_minutes illisible' }
    $fichiers = [ordered]@{}
    foreach ($k in $t.Keys) {
        if ($k -notlike 'sha256.*') { continue }
        $nom = $k.Substring(7)
        if ($nom -notmatch '^[A-Za-z0-9 ._-]{1,64}$' -or $nom.Contains('..') -or $nom -match '^[. ]|[. ]$' -or $nom -cnotin $FichiersPermis) {
            throw "REFUS: fichier « $nom » hors de la liste permise"
        }
        if ($t[$k] -notmatch '^[0-9a-fA-F]{64}$') { throw "REFUS: empreinte de « $nom » illisible" }
        $fichiers[$nom] = $t[$k].ToLower()
    }
    if (-not $fichiers.Contains('vanguard.exe')) { throw 'REFUS: vanguard.exe absent de la liste' }
    if ($t['test'] -eq 'oui' -and -not $fichiers.Contains('test.ps1')) { throw 'REFUS: test=oui sans test.ps1' }
    if ($t['console'] -eq 'oui' -and -not $fichiers.Contains('essais-console.ps1')) { throw 'REFUS: console=oui sans essais-console.ps1' }
    [pscustomobject]@{ Cles = $t; Fichiers = $fichiers; Langues = ($langues -join ',') }
}

# Copie chaque fichier nommé dans le dossier local, puis vérifie son empreinte SUR LA COPIE.
function Copier-Verifier($dossier, $travail, [string]$localTravail) {
    $base = [IO.Path]::GetFullPath($dossier.FullName).TrimEnd([IO.Path]::DirectorySeparatorChar)
    foreach ($nom in $travail.Fichiers.Keys) {
        $source = Join-Path $dossier.FullName $nom
        $item = Get-Item -LiteralPath $source -Force -ErrorAction SilentlyContinue
        if (-not $item -or $item.PSIsContainer) { throw "REFUS: « $nom » absent du dossier du travail" }
        if (Est-Lien $item) { throw "REFUS: « $nom » est un lien" }
        if ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($item.FullName)).TrimEnd([IO.Path]::DirectorySeparatorChar) -ne $base) {
            throw "REFUS: « $nom » sort du dossier du travail"
        }
        $copie = Join-Path $localTravail $nom
        Copy-Item -LiteralPath $item.FullName -Destination $copie -Force
        $vue = (Get-FileHash -LiteralPath $copie -Algorithm SHA256).Hash.ToLower()
        if ($vue -ne $travail.Fichiers[$nom]) { throw "REFUS: empreinte de « $nom » différente ($($vue.Substring(0, 16))… au lieu de $($travail.Fichiers[$nom].Substring(0, 16))…)" }
    }
    if (-not $EssaiLocal) { Unblock-File -LiteralPath (Join-Path $localTravail 'vanguard.exe') -ErrorAction SilentlyContinue }
}

function Lancer-PowerShell([string]$script, [string[]]$arguments, [string]$sortie, [string]$dossier) {
    $liste = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$script`"") + $arguments
    Start-Process -FilePath $PowerShell -ArgumentList $liste -NoNewWindow -PassThru -WorkingDirectory $dossier `
        -RedirectStandardOutput $sortie -RedirectStandardError "$sortie.err"
}

function Faire-Travail($dossier) {
    $id = $dossier.Name
    $script:journalTravail = New-Object System.Collections.ArrayList
    $script:debutTravail = Maintenant
    $debut = Get-Date
    $localTravail = Join-Path $LocalTravaux $id
    $resultatsPartage = Join-Path $dossier.FullName 'resultats'
    $admin = if ($EssaiLocal) { 'essai-local' } elseif (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { 'oui' } else { 'non' }
    $fini = [ordered]@{ format = 1; id = $id; code = 4; etat = 'erreur'; raison = '' }
    $demande = @{ test = $false; console = $false }
    $test = $null; $console = $null; $p = $null
    Journal "travail $id pris"
    try {
        Ecrire-Cles (Join-Path $dossier.FullName 'pris.txt') ([ordered]@{ format = 1; id = $id; pris = (Maintenant); surveillant = $VersionSurveillant; admin = $admin })
        Ecrire-Cles $EnCours ([ordered]@{ id = $id; debut = $script:debutTravail; partie = 'preparation' })
        # Pour deployer.sh et le menu des tests : une passe tourne, rien ne doit remplacer le programme ni en lancer une autre.
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Temoin) | Out-Null
        Set-Content -LiteralPath $Temoin -Value "file-essais $id $(Maintenant)" -Force
        Ecrire-Battement "travail $id"

        $travail = Lire-Travail $dossier
        $demande.test = $travail.Cles['test'] -eq 'oui'; $demande.console = $travail.Cles['console'] -eq 'oui'
        $delai = [Math]::Min(120, [Math]::Max(5, [int]$travail.Cles['delai_minutes']))
        $total = if ($EssaiLocal -and $DelaiSecondes) { New-TimeSpan -Seconds $DelaiSecondes } else { New-TimeSpan -Minutes $delai }
        $fin = $debut + $total
        # Les essais de console gardent leur part du délai (8 min au plus) : test.ps1 bloqué ne les supprime pas.
        $partConsole = if ($demande.console) { [Math]::Min(480, $total.TotalSeconds / 3) } else { 0 }
        Journal "commit $($travail.Cles['commit']) ($($travail.Cles['branche'])), test=$($travail.Cles['test']) console=$($travail.Cles['console']), délai $([int]$total.TotalMinutes) min"

        Preparer-Local
        if (Test-Path -LiteralPath $localTravail) { Remove-Item -LiteralPath $localTravail -Recurse -Force }
        New-Item -ItemType Directory -Path $localTravail | Out-Null
        New-Item -ItemType Directory -Force -Path $resultatsPartage | Out-Null
        Copier-Verifier $dossier $travail $localTravail
        Journal 'empreintes vérifiées sur la copie locale'

        if ($demande.test) {
            Journal 'test.ps1 -Auto -SansOuvrir -SurPlace : lancé'
            $p = Lancer-PowerShell (Join-Path $localTravail 'test.ps1') @('-Auto', '-SansOuvrir', '-SurPlace') (Join-Path $localTravail 'test-sortie.txt') $localTravail
            if (-not (Attendre $p ($fin.AddSeconds(-$partConsole)) $id 'test.ps1')) { throw 'DELAI: test.ps1 pas fini à temps' }
            $p = $null
            $test = Bilan-Test $localTravail
            Journal "test.ps1 fini : $($test.ok) OK, $($test.bugs) problème(s), $($test.echecs) commande(s) en échec, $($test.sautees) sautée(s)"
        }
        if ($demande.console) {
            $limite = (Get-Date).AddSeconds([Math]::Max(60, $partConsole))
            if ($limite -gt $fin) { $limite = $fin }
            $sortieConsole = Join-Path $localTravail 'resultats-console'
            New-Item -ItemType Directory -Force -Path $sortieConsole | Out-Null
            Journal 'essais de console : lancés'
            $minutes = [Math]::Max(1, [int](($limite - (Get-Date)).TotalMinutes))
            $p = Lancer-PowerShell (Join-Path $localTravail 'essais-console.ps1') @('-Exe', "`"$(Join-Path $localTravail 'vanguard.exe')`"",
                '-Sortie', "`"$sortieConsole`"", '-Langues', $travail.Langues, '-LimiteMinutes', $minutes) (Join-Path $localTravail 'console-sortie.txt') $localTravail
            if (-not (Attendre $p $limite $id 'console')) { throw 'DELAI: essais de console pas finis à temps' }
            $p = $null
            $console = @{ lu = $false; ok = 0; bugs = 0; sautees = 0 }
            $r = Join-Path $sortieConsole 'resume.txt'
            if (Test-Path -LiteralPath $r) {
                $console.lu = $true
                foreach ($l in [IO.File]::ReadAllLines($r, $Utf8)) {
                    switch -Regex ($l.TrimStart([char]0xFEFF)) { '^OK ' { $console.ok++ } '^BUG ' { $console.bugs++ } '^SAUTE ' { $console.sautees++ } }
                }
            }
            Journal "essais de console finis : $($console.ok) OK, $($console.bugs) problème(s), $($console.sautees) sauté(s)"
        }
        $problemes = @()
        if ($demande.test -and -not $test.lu) { $problemes += 'bilan de test.ps1 introuvable' }
        if ($demande.console -and -not $console.lu) { $problemes += 'résumé des essais de console introuvable' }
        if ($test -and ($test.bugs -or $test.echecs)) { $problemes += 'test.ps1 : problèmes' }
        # Rien de réussi n'est jamais un vert : tout sauté, c'est n'avoir rien vérifié.
        if ($test -and $test.lu -and -not $test.ok) { $problemes += 'test.ps1 : aucune vérification réussie' }
        if ($console -and $console.bugs) { $problemes += 'console : problèmes' }
        if ($console -and $console.lu -and -not $console.ok) { $problemes += 'console : aucun essai réussi (tous sautés)' }
        if ($problemes) { $fini.code = 1; $fini.etat = 'problemes'; $fini.raison = $problemes -join ' ; ' }
        else { $fini.code = 0; $fini.etat = 'ok' }
    } catch {
        $m = $_.Exception.Message
        if ($m -like 'REFUS: *') { $fini.code = 2; $fini.etat = 'refuse'; $fini.raison = $m.Substring(7) }
        elseif ($m -like 'DELAI: *') { $fini.code = 3; $fini.etat = 'delai'; $fini.raison = $m.Substring(7) }
        else { $fini.code = 4; $fini.etat = 'erreur'; $fini.raison = $m }
        Journal "$($fini.etat) : $($fini.raison)"
    } finally {
        try {
            # Toujours : un Vanguard resté ouvert par les essais de console tournerait en administrateur sans personne.
            Arreter-Processus $p $localTravail
            if ($fini.code -eq 3 -and -not $EssaiLocal) {
                # Un essai arrêté en route peut laisser des règles de blocage du pare-feu (qui coupent RDP) : retirées.
                Get-NetFirewallRule -DisplayName 'Vanguard : bloquer*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            }
            Copier-Resultats $localTravail $resultatsPartage
        } catch { Journal "résultats incomplets : $($_.Exception.Message)" }
        $fin2 = Get-Date
        if ($test) { $fini['test.ok'] = $test.ok; $fini['test.bugs'] = $test.bugs; $fini['test.echecs'] = $test.echecs; $fini['test.sautees'] = $test.sautees }
        if ($console) { $fini['console.ok'] = $console.ok; $fini['console.bugs'] = $console.bugs; $fini['console.sautees'] = $console.sautees }
        $fini['debut'] = $script:debutTravail; $fini['fin'] = Maintenant; $fini['duree_s'] = [int]($fin2 - $debut).TotalSeconds
        $fini['windows'] = if ($EssaiLocal) { "essai local (pwsh $($PSVersionTable.PSVersion))" } else { try { $os = Get-CimInstance Win32_OperatingSystem; "$($os.Caption) $($os.Version)" } catch { 'inconnu' } }
        $fini['admin'] = $admin
        $fini['rapport'] = if (Test-Path -LiteralPath (Join-Path $resultatsPartage 'rapport-test.html')) { 'resultats\rapport-test.html' } else { '' }
        try {
            [IO.File]::AppendAllText((Join-Path $File 'historique.txt'), ('{0}  {1}  {2}  test {3}/{4}/{5}/{6}  console {7}/{8}/{9}  ({10:N1} min)' -f `
                (Get-Date -Format 'yyyy-MM-dd HH:mm'), $id, $fini.etat, $fini['test.ok'], $fini['test.bugs'], $fini['test.echecs'], $fini['test.sautees'],
                $fini['console.ok'], $fini['console.bugs'], $fini['console.sautees'], ($fin2 - $debut).TotalMinutes) + "`r`n", $Utf8)
        } catch { }
        Journal "travail $id fini : code $($fini.code) ($($fini.etat))"
        try { [IO.File]::WriteAllLines((Join-Path $resultatsPartage 'surveillant.txt'), [string[]]$script:journalTravail, $Utf8) } catch { }
        $script:journalTravail = $null
        # Les .exe ne s'accumulent pas sur le partage ; le reste du dossier est gardé (14 jours).
        Remove-Item -LiteralPath (Join-Path $dossier.FullName 'vanguard.exe') -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $localTravail) { Remove-Item -LiteralPath $localTravail -Recurse -Force -ErrorAction SilentlyContinue }
        Remove-Item -LiteralPath $EnCours -Force -ErrorAction SilentlyContinue
        # Seulement le sien : celui d'une passe du menu lancée entre-temps reste.
        if (Temoin-De-La-File $id) { Remove-Item -LiteralPath $Temoin -Force -ErrorAction SilentlyContinue }
        Ecrire-Fini $dossier.FullName $fini
    }
}

# Un travail pris mais pas fini, alors qu'aucun ne tourne ici (une seule boucle à la fois, et Tour ne s'appelle jamais
# pendant un travail) : la boucle d'avant a été arrêtée en route (VM redémarrée, session fermée, réinstallation). Ses
# processus sont arrêtés, ce qu'il a laissé est rendu, et il finit en « erreur » : Linux n'attend pas son délai, et
# le témoin de la file, resté là, ne met plus la file en pause pour 3 h.
function Reprendre-Orphelins {
    $orphelins = @(Get-ChildItem -LiteralPath $File -Directory -Force -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match $MotifId -and -not (Est-Lien $_) -and (Test-Path -LiteralPath (Join-Path $_.FullName 'pris.txt')) -and
            -not (Test-Path -LiteralPath (Join-Path $_.FullName 'fini.txt')) })
    $temoinFile = Temoin-De-La-File
    foreach ($d in $orphelins) {
        $id = $d.Name
        $localTravail = Join-Path $LocalTravaux $id
        Journal "travail $id abandonné par une boucle arrêtée en route : repris pour être fini en erreur"
        try {
            Arreter-Processus $null $localTravail
            # Ses règles de blocage du pare-feu (qui coupent RDP), sauf si une passe du menu tourne : elles seraient les siennes.
            if (-not $EssaiLocal -and ($temoinFile -or -not (Test-Path -LiteralPath $Temoin))) {
                Get-NetFirewallRule -DisplayName 'Vanguard : bloquer*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            }
            Copier-Resultats $localTravail (Join-Path $d.FullName 'resultats')
        } catch { Journal "restes du travail $id : $($_.Exception.Message)" }
        Remove-Item -LiteralPath (Join-Path $d.FullName 'vanguard.exe') -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $localTravail) { Remove-Item -LiteralPath $localTravail -Recurse -Force -ErrorAction SilentlyContinue }
        $pris = try { Lire-Cles (Join-Path $d.FullName 'pris.txt') } catch { @{} }
        Ecrire-Fini $d.FullName ([ordered]@{ format = 1; id = $id; code = 4; etat = 'erreur'
                raison = 'surveillant arrêté en plein travail (VM redémarrée, session fermée ou file réinstallée) : travail abandonné'
                debut = $pris['pris']; fin = (Maintenant); admin = $pris['admin']; rapport = '' })
        try { [IO.File]::AppendAllText((Join-Path $File 'historique.txt'), "$(Get-Date -Format 'yyyy-MM-dd HH:mm')  $id  abandonne (surveillant arrêté en route)`r`n", $Utf8) } catch { }
    }
    Remove-Item -LiteralPath $EnCours -Force -ErrorAction SilentlyContinue
    if ($temoinFile) { Remove-Item -LiteralPath $Temoin -Force -ErrorAction SilentlyContinue; Journal 'témoin laissé par une boucle arrêtée : retiré' }
}

# Les travaux de plus de 14 jours (dossiers au nom d'un id, et .partiel abandonnés) : retirés en entier.
function Menage {
    $limite = (Get-Date).AddDays(-14)
    Get-ChildItem -LiteralPath $File -Directory -Force -ErrorAction SilentlyContinue | Where-Object {
        ($_.Name -match $MotifId -or ($_.Name -match '\.partiel$' -and $_.Name.Substring(0, $_.Name.Length - 8) -match $MotifId)) -and
        -not (Est-Lien $_) -and $_.LastWriteTime -lt $limite
    } | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue; Journal "ménage : $($_.Name) retiré" }
}

$script:partageVu = $null
$script:dernierMenage = [datetime]::MinValue
function Tour {
    $vu = Test-Path -LiteralPath $Partage -PathType Container
    if ($vu -ne $script:partageVu) { Journal $(if ($vu) { "partage $Partage vu" } else { "partage $Partage absent : rien ne sera lancé" }); $script:partageVu = $vu }
    if (-not $vu) { return }
    New-Item -ItemType Directory -Force -Path $File | Out-Null
    if ((Get-Date) - $script:dernierMenage -gt (New-TimeSpan -Hours 1)) { Menage; $script:dernierMenage = Get-Date }
    Reprendre-Orphelins
    # Le témoin des passes du menu (et de la VM réservée par qui la garde) : rien n'est pris tant qu'il est frais.
    $t = Get-Item -LiteralPath $Temoin -Force -ErrorAction SilentlyContinue
    if ($t -and $t.LastWriteTime -gt (Get-Date).AddHours(-3)) {
        Ecrire-Battement "en-pause test du menu ou VM réservée depuis $('{0:HH:mm}' -f $t.LastWriteTime)"
        return
    }
    Ecrire-Battement 'attente'
    $travail = Get-ChildItem -LiteralPath $File -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $MotifId -and -not (Est-Lien $_) -and
            (Test-Path -LiteralPath (Join-Path $_.FullName 'travail.txt')) -and
            -not (Test-Path -LiteralPath (Join-Path $_.FullName 'pris.txt')) -and
            -not (Test-Path -LiteralPath (Join-Path $_.FullName 'fini.txt')) } |
        Sort-Object Name | Select-Object -First 1
    if ($travail) { Faire-Travail $travail; Ecrire-Battement 'attente' }
}

# Une seule boucle à la fois : la tâche se relance toutes les 5 min au cas où celle-ci serait morte.
$verrou = $null
if (-not $EssaiLocal) {
    if (-not (Est-Protege $Prive)) {
        Journal "$Prive n'est pas protégé (propriétaire, droits ou lien) : rien ne sera lancé ; réinstaller (INSTALLER-ESSAIS-AUTO.bat)"
        if (Test-Path -LiteralPath $File) { Ecrire-Battement "erreur dossier du surveillant pas protégé : réinstaller (INSTALLER-ESSAIS-AUTO.bat)" }
        exit 3
    }
    $cree = $false
    $verrou = [Threading.Mutex]::new($false, 'Global\Vanguard-File-Essais', [ref]$cree)
    try { if (-not $verrou.WaitOne(0)) { exit 0 } } catch [System.Threading.AbandonedMutexException] { }
    Set-Content -LiteralPath (Join-Path $Prive 'pid.txt') -Value "$PID`r`n$($MyInvocation.MyCommand.Path)" -Encoding UTF8
    Journal "surveillant $VersionSurveillant démarré (processus $PID)"
}
while ($true) {
    try { Tour } catch { Journal "erreur du tour : $($_.Exception.Message)"; Ecrire-Battement "erreur $($_.Exception.Message)" }
    if ($UnTour) { break }
    Start-Sleep -Seconds 20
}
exit 0

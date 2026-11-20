# Dépanner avec Claude : lance Claude Code depuis la clé VANGUARD sur l'ordinateur d'un proche (« Depanner avec
# Claude.bat », à la racine de la clé, appelle ce script et garde la fenêtre ouverte à la fin). Mode d'emploi :
# LISEZMOI.txt, à côté. Troubleshoot with Claude: runs Claude Code from the VANGUARD key. See README.txt.
#
# - Rien n'est installé : claude.exe est copié dans un dossier temporaire à soi (%TEMP%\vanguard-claude-…, créé avec
#   des droits pour l'utilisateur seul, relus ensuite ; refusé sur un disque sans droits Windows, FAT ou réseau),
#   vérifié là (signature Authenticode valide, signataire « Anthropic, PBC » reconnu par son nom, son pays et son
#   numéro d'entreprise ; empreinte égale à celle du manifeste de la clé), puis lancé de là.
# - Le jeton de connexion à Claude et la conversation restent dans ce dossier (CLAUDE_CONFIG_DIR), jamais sur la clé
#   ni dans le profil du proche. En sortant : déconnexion (claude auth logout, son résultat est dit), puis le dossier
#   et les journaux de Claude Code de cette session sont effacés. Fenêtre fermée par sa croix : un gardien caché,
#   lancé avant Claude, attend la fin de ce script et fait la même chose. Ordinateur éteint en pleine session, ou
#   fenêtre fermée avant le gardien : le prochain lancement efface d'abord ce qui est resté.
# - Pas de mise à jour automatique, pas de trafic non essentiel, pas de connecteurs du compte (courriel, fichiers en
#   ligne), jamais le navigateur de ce PC. L'environnement de l'ordinateur visité ne choisit ni le serveur, ni le
#   compte, ni le mandataire (ANTHROPIC_*, CLAUDE_*, NODE_*, *_PROXY… retirées, avant toute commande de Claude Code).
#   Limite, dite : les variables de certificats sont retirées, mais le magasin de certificats de Windows reste cru
#   par Claude Code, comme par le navigateur.
# - Claude demande avant toute commande qui change quelque chose (CLAUDE.md, à côté, lui donne les consignes).
# Limite, dite dans LISEZMOI : un programme malveillant du même compte Windows peut lire le jeton pendant la session.
# PowerShell 5.1 (Windows 10) : ce fichier est en UTF-8 avec BOM, sans quoi les accents seraient mal lus.
# Essais : outils/essais-claude-cle.sh le lance sous pwsh (Linux), les appels propres à Windows remplacés au repère
# « ESSAIS » plus bas ; toute la logique est celle de ce fichier. Non essayé ainsi sur un vrai Windows.
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }

$Ici = $PSScriptRoot                      # <clé>\Claude
$Cle = Split-Path -Parent $Ici            # <clé>
$Source = Join-Path (Join-Path $Ici 'Windows') 'claude.exe'
$Signataire = 'Anthropic, PBC'
# Le sujet du certificat d'Anthropic (certificat « EV » : le numéro est celui de l'entreprise au Delaware, il reste
# le même d'un certificat à l'autre). L'émetteur n'est pas fixé : Windows vérifie déjà la chaîne jusqu'à une racine.
$SujetAttendu = 'CN=Anthropic, PBC', 'O=Anthropic, PBC', 'C=US', 'SERIALNUMBER=4860621'

function Dire([string]$fr, [string]$en) { Write-Host "  $fr"; if ($en) { Write-Host "  $en" -ForegroundColor DarkGray } }
function Arret([string]$fr, [string]$en) {
    Write-Host ''
    Write-Host "  ✖ $fr" -ForegroundColor Red
    if ($en) { Write-Host "    $en" -ForegroundColor DarkGray }
    exit 1
}
# Existe, même caché, même lien cassé (Test-Path dit non pour un lien qui ne mène nulle part).
function Existe([string]$chemin) { [bool](Get-Item -LiteralPath $chemin -Force -ErrorAction SilentlyContinue) }

# Déconnexion, délai borné (hors ligne, ou si la commande attendait une réponse : arrêtée au bout de 20 s), depuis le
# dossier de travail de la session (ses journaux y sont nommés), puis effacement du dossier et des journaux de Claude
# Code à son nom (%LOCALAPPDATA%\claude-cli-nodejs\Cache\…vanguard-claude-…). [IO.Directory]::Delete ne suit pas les
# jonctions : il retire le lien, jamais ce qui est au bout. Le même texte sert au gardien (plus bas) : une seule façon
# de nettoyer. Rend Efface (le dossier n'existe plus) et Deconnexion ('oui' : confirmée par le serveur ; 'non' :
# tentée sans cette preuve ; '' : pas tentée).
# « auth logout » sort avec le code 0 même hors ligne (le jeton de ce PC est effacé, le serveur n'a rien révoqué). Une
# version récente le dit (« … didn't confirm the login was revoked », $revocation) ; une ancienne affiche le même succès
# dans les deux cas. 'oui' seulement sur preuve : code 0, le texte de succès, pas l'avertissement, et un binaire
# vérifié qui sait l'écrire ($sait : l'appelant a trouvé l'avertissement dans ses octets). Le gardien ne le passe
# pas : son résultat n'est jamais dit.
$TexteNettoyer = @'
function LancerCache([string]$exe, [string[]]$arguments, [string]$dossier, [string]$sortie, [string]$erreurs) {
    Start-Process -FilePath $exe -ArgumentList $arguments -WorkingDirectory $dossier -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $sortie -RedirectStandardError $erreurs -ErrorAction Stop
}
function Nettoyer([string]$dossier, [string]$exe, [string]$travail, [bool]$sait = $false) {
    $deconnexion = ''
    if (-not [IO.Directory]::Exists($dossier)) { return [pscustomobject]@{ Efface = $true; Deconnexion = '' } }
    $config = [IO.Path]::Combine($dossier, 'config')
    if ($exe -and [IO.File]::Exists($exe) -and [IO.Directory]::Exists($config) -and $travail -and [IO.Directory]::Exists($travail)) {
        $deconnexion = 'non'
        $avant = $env:CLAUDE_CONFIG_DIR
        $env:CLAUDE_CONFIG_DIR = $config
        $sortie = [IO.Path]::Combine($dossier, 'deconnexion.txt')
        $erreurs = [IO.Path]::Combine($dossier, 'deconnexion-erreurs.txt')
        try {
            $p = LancerCache $exe @('auth', 'logout') $travail $sortie $erreurs
            [void]$p.Handle   # sans lui, ExitCode reste vide sous PowerShell 5.1
            if ($p.WaitForExit(20000)) {
                $p.WaitForExit()   # les fichiers de sortie fermés
                $dit = [IO.File]::ReadAllText($sortie) + [IO.File]::ReadAllText($erreurs)
                if ($p.ExitCode -eq 0 -and $sait -and
                    $dit.Contains('Successfully logged out from your Anthropic account.') -and
                    -not $dit.Contains("didn't confirm the login was revoked")) {
                    $deconnexion = 'oui'
                }
            }
            else { try { $p.Kill() } catch { } ; Start-Sleep -Seconds 1 }
        } catch { }
        $env:CLAUDE_CONFIG_DIR = $avant
    }
    $local = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { [Environment]::GetFolderPath('LocalApplicationData') }
    $journaux = [IO.Path]::Combine($local, 'claude-cli-nodejs', 'Cache')
    $nom = [IO.Path]::GetFileName($dossier)
    if ($nom -and [IO.Directory]::Exists($journaux)) {
        foreach ($j in [IO.Directory]::GetDirectories($journaux, "*$nom*")) { try { [IO.Directory]::Delete($j, $true) } catch { } }
        # Vides, ils ne servaient qu'à cette session ; sinon gardés (Claude Code est peut-être installé ici).
        foreach ($v in $journaux, [IO.Path]::GetDirectoryName($journaux)) { try { [IO.Directory]::Delete($v, $false) } catch { } }
    }
    for ($i = 0; $i -lt 10; $i++) {
        try { [IO.Directory]::Delete($dossier, $true); break } catch { Start-Sleep -Seconds 1 }
    }
    [pscustomobject]@{ Efface = -not [IO.Directory]::Exists($dossier); Deconnexion = $deconnexion }
}
'@
. ([ScriptBlock]::Create($TexteNettoyer))

# Les appels propres à Windows, chacun dans sa fonction : les essais (sous Linux) les remplacent au repère plus bas.
function SidDeMoi { [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
function FormatDuVolume([string]$dossier) { (New-Object IO.DriveInfo([IO.Path]::GetPathRoot($dossier))).DriveFormat }
function CreerDossierPrive([string]$dossier, [string]$moi) {
    $sid = New-Object Security.Principal.SecurityIdentifier($moi)
    $droits = New-Object Security.AccessControl.DirectorySecurity
    $droits.SetAccessRuleProtection($true, $false)
    $droits.SetOwner($sid)
    $droits.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl',
                'ContainerInherit, ObjectInherit', 'None', 'Allow')))
    [void][IO.Directory]::CreateDirectory($dossier, $droits)
}
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
function ProprietaireDe([string]$dossier) { (Get-Acl -LiteralPath $dossier).GetOwner([Security.Principal.SecurityIdentifier]).Value }
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
# ESSAIS : les doublures des fonctions ci-dessus sont posées ici.

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
# le compte, ni les certificats, ni le mandataire, ni le code chargé. Retiré d'abord, avant toute commande de Claude
# Code (même la déconnexion des restes d'une session).
Get-ChildItem Env: | Where-Object {
    $_.Name -match '^(ANTHROPIC_|CLAUDE_|NODE_|BUN_|SSL_CERT_|AWS_|GOOGLE_|VERTEX_|OTEL_|GIT_)' -or
    $_.Name -match '^((HTTPS?|ALL|NO|GRPC)_PROXY|REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE|BROWSER|SESSION_INGRESS_URL|ENABLE_CLAUDEAI_MCP_SERVERS)$'
} | ForEach-Object { Remove-Item -LiteralPath "Env:$($_.Name)" }

if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
    Arret 'Claude Code n''est pas sur cette clé (Claude\Windows\claude.exe).' 'Claude Code is not on this key.'
}
$TempPc = $env:TEMP
if (-not $TempPc -or -not (Test-Path -LiteralPath $TempPc -PathType Container)) {
    Arret 'Dossier temporaire de Windows introuvable (TEMP).' 'Windows temporary folder not found (TEMP).'
}
$Moi = SidDeMoi
$Dossier = Join-Path $TempPc ('vanguard-claude-' + [Guid]::NewGuid().ToString('N'))
$Exe = Join-Path $Dossier 'claude.exe'
$Travail = Join-Path $Dossier 'travail'
$Config = Join-Path $Dossier 'config'
$Tmp = Join-Path $Dossier 'tmp'
# Sans droits Windows (FAT, exFAT, partage réseau), « à soi seul » ne voudrait rien dire : refusé avant de créer.
$format = try { FormatDuVolume $Dossier } catch { '' }
if ($Dossier.StartsWith('\\') -or @('NTFS', 'ReFS') -notcontains $format) {
    Arret "Le dossier temporaire (TEMP) est sur un disque sans droits Windows ($format) : il ne serait pas à vous seul. Rien n'a été lancé." `
          "The temporary folder (TEMP) is on a drive without Windows permissions: it would not be yours alone. Nothing was started."
}
$Session = $null
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
    #   (l'adresse s'affiche, à ouvrir sur le téléphone).
    $env:CLAUDE_CONFIG_DIR = $Config
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
    # seraient des consignes. Il remonte le chemin écrit, comme cette boucle (une jonction n'est pas suivie vers son
    # vrai dossier). Le dossier personnel est l'exception pour .claude : Claude Code n'y cherche pas de skills, et le
    # refuser bloquerait tout PC où l'on se sert déjà de Claude Code ; ses consignes y sont refusées quand même.
    # Limite, dite : un compte sans droits peut créer C:\.claude après cette vérification ; seul un dossier refait à
    # chaque lancement le verrait. GetDirectoryName rend $null à la racine (C:\), sans erreur.
    $maison = [Environment]::GetFolderPath('UserProfile')
    for ($d = [IO.Path]::GetDirectoryName($Dossier); $d; $d = [IO.Path]::GetDirectoryName($d)) {
        $noms = @('CLAUDE.md', 'CLAUDE.local.md', 'AGENTS.md', '.mcp.json')
        # Les deux façons de connaître le dossier personnel doivent tomber d'accord : sinon, pas d'exception.
        if ($env:USERPROFILE -and $d -ceq $env:USERPROFILE -and $d -ceq $maison) {
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
            $sujet = @($sig.Certificat.SubjectName.Decode(
                    [Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]'UseNewLines, DoNotUseQuotes') -split "`r?`n")
            $nom = $sig.Certificat.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        }
        $manque = @($SujetAttendu | Where-Object { $sujet -cnotcontains $_ })
        if ($sig.Statut -ne 'Valid' -or $nom -cne $Signataire -or $manque.Count -gt 0) {
            throw [Exception]::new("signature : $($sig.Statut), signataire : « $nom » (attendu : « $Signataire »)")
        }
        # 2. Empreinte égale à celle du manifeste posé sur la clé : attrape une copie abîmée en route. Ce manifeste
        # n'est pas authentifié ici (pas de gpg sous Windows) : un autre claude.exe signé par Anthropic avec un
        # manifeste retouché passerait. Une clé qui a quitté vos mains repasse par Vanguard (LISEZMOI, Limites).
        $manifeste = Get-Content -LiteralPath (Join-Path $Ici 'manifest.json') -Raw | ConvertFrom-Json
        $vu = (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLowerInvariant()
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
            (Get-FileHash -LiteralPath $consignes).Hash -ne (Get-FileHash -LiteralPath (Join-Path $Ici 'CLAUDE.md')).Hash) {
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
            if ($n.Efface) {
                Dire 'Restes d''une session précédente effacés.' 'Leftovers of a previous session erased.'
                if ($n.Deconnexion -eq 'non') {
                    Dire '⚠ Sa déconnexion n''est PAS confirmée : fermez cette session sur claude.ai.' `
                         '⚠ Its logout is NOT confirmed: end that session on claude.ai.'
                }
            }
        }

    # Le gardien : un PowerShell de Windows caché, détaché de cette fenêtre, qui attend la fin de ce script (sortie
    # normale, Ctrl+C, ou fenêtre fermée par sa croix), puis celle de claude.exe, et nettoie. Lancé seulement une fois
    # claude.exe vérifié : il ne lance jamais un binaire non vérifié. Ses valeurs sont écrites entre apostrophes
    # doublées, et le tout passé en -EncodedCommand : aucun guillemet de la ligne de commande à casser.
    function Litteral([string]$s) { "'" + $s.Replace("'", "''") + "'" }
    # Un saut de ligne entre les deux : une chaîne @' '@ finit sans, et « }$dossier = » ne se lirait pas.
    $gardien = $TexteNettoyer + "`r`n" + @"
`$dossier = $(Litteral $Dossier); `$exe = $(Litteral $Exe); `$travail = $(Litteral $Travail)
try { Wait-Process -Id $PID -ErrorAction SilentlyContinue } catch { }
for (`$i = 0; `$i -lt 30 -and (Get-Process -ErrorAction SilentlyContinue | Where-Object { try { `$_.Path -eq `$exe } catch { `$false } }); `$i++) { Start-Sleep -Seconds 1 }
Get-Process -ErrorAction SilentlyContinue | Where-Object { try { `$_.Path -eq `$exe } catch { `$false } } | Stop-Process -Force -ErrorAction SilentlyContinue
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
        if (-not $n.Efface) {
            Dire "✖ $Dossier n'a pas pu être effacé (Claude tourne encore ?). Le gardien réessaie ; sinon, relancez « Depanner avec Claude »." `
                 "✖ Could not erase $Dossier (Claude still running?). The guard retries; otherwise run « Depanner avec Claude » again."
        } elseif ($n.Deconnexion -eq 'oui') {
            Dire '✔ Déconnecté ; Claude Code, la connexion et la conversation sont effacés de cet ordinateur.' `
                 '✔ Logged out; Claude Code, the sign-in and the conversation are erased from this computer.'
        } else {
            Dire '⚠ Déconnexion NON confirmée par Anthropic (hors ligne, ou version qui ne le dit pas) : fermez la session sur claude.ai. Le reste est effacé de cet ordinateur.' `
                 '⚠ Logout NOT confirmed by Anthropic (offline, or a version that does not tell): end the session on claude.ai. Everything else is erased from this computer.'
        }
        Write-Host ''
    } elseif (-not $n.Efface) {
        Dire "✖ $Dossier n'a pas pu être effacé : à effacer à la main." "✖ Could not erase $Dossier."
    }
}
exit $code

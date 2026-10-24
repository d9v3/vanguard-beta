# Essais de la fenêtre de Vanguard dans une vraie console Windows, sans personne au clavier : une partie de chaque
# travail de la file d'essais (surveillant-essais.ps1, en administrateur dans la VM), ou à la main :
#   powershell -ExecutionPolicy Bypass -File essais-console.ps1 -Exe C:\…\vanguard.exe -Sortie C:\…\console
# Pour chaque hôte (la vieille console conhost, puis Windows Terminal s'il est là) et chaque langue (VANGUARD_LANG) :
#   C1 menu affiché · C2 fenêtre à la hauteur du menu · C3 fenêtre entière dans la zone de travail, à la place où
#   elle s'est ouverte (sous Windows, Vanguard ne recentre pas : src/fenetre.rs, CENTRER) · C4 ↓ jusqu'à « Cet
#   ordinateur » · C5 → entre (lignes « Logiciels pas à jour » et « Blocages de Windows Defender », les deux
#   dernières, propres à Windows) · C6 hauteur et place du sous-menu (celle du menu, sans saut)
#   C7 ← revient, même hauteur et même place · C8 q + Entrée quitte.
# Un OK exige le texte vu à l'écran ET l'effet mesuré. Écran illisible ou touches refusées : « SAUTE » avec la raison
# sous Windows Terminal (une limite connue de l'outil), « BUG » sous conhost (l'outil y marche : c'est Vanguard qui
# n'affiche rien, bloqué ou arrêté) ; jamais OK. Résultat : une ligne « OK|BUG|SAUTE|INFO hôte langue Cn texte » par essai dans
# <Sortie>\resume.txt ; chaque écran lu dans ecran-<hôte>-<langue>-<n>.txt, la géométrie dans geometrie-*.txt.
#
# Deux processus : le chef (ce script sans -Etape) ouvre la fenêtre de Vanguard et la referme ; le pilote
# (-Etape pilote, un PowerShell caché) se branche sur la console de Vanguard (AttachConsole), y tape les flèches
# (WriteConsoleInputW) et lit l'écran (ReadConsoleOutputCharacterW). Vanguard ne retouche sa fenêtre que s'il est seul
# dans sa console (src/fenetre.rs) : le pilote ne s'y branche que le temps d'une lecture ou d'une touche, et mesure la
# fenêtre (GetWindowRect) sans y être branché.
# Pendant ces essais, des fenêtres s'ouvrent dans la session : ne pas taper dedans.
param(
    [string]$Etape = 'chef',
    [string]$Exe,
    [string]$Sortie,
    [string]$Langues = 'fr,en',
    [string]$Hotes = 'conhost,wt',
    [int]$LimiteMinutes = 8,
    # Pilote seulement : le processus de Vanguard, sa fenêtre, l'hôte et la langue.
    [int]$Cible = 0,
    [long]$Fenetre = 0,
    [string]$Hote = '',
    [string]$Langue = '',
    # La place de la fenêtre quand le chef l'a trouvée : Vanguard l'a retouchée dès qu'elle diffère.
    [string]$RectInitial = ''
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$srcPilote = @'
using System; using System.Text; using System.Threading; using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class PiloteConsoleVg {
  [DllImport("kernel32.dll", SetLastError = true)] public static extern bool FreeConsole();
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool AttachConsole(uint pid);
  [DllImport("kernel32.dll")] static extern IntPtr GetConsoleWindow();
  [DllImport("kernel32.dll", SetLastError = true)] static extern uint GetConsoleProcessList(uint[] liste, uint n);
  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern IntPtr CreateFileW(string nom, uint acces, uint partage, IntPtr sa, uint dispo, uint drapeaux, IntPtr modele);
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr h);
  [StructLayout(LayoutKind.Sequential)] public struct COORD { public short X; public short Y; }
  [StructLayout(LayoutKind.Sequential)] struct SMALL_RECT { public short L; public short T; public short R; public short B; }
  [StructLayout(LayoutKind.Sequential)] struct CSBI { public COORD Size; public COORD Cursor; public ushort Attr; public SMALL_RECT Win; public COORD Max; }
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetConsoleScreenBufferInfo(IntPtr h, out CSBI i);
  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern bool ReadConsoleOutputCharacterW(IntPtr h, [Out] char[] tampon, uint longueur, COORD debut, out uint lus);
  // INPUT_RECORD d'un KEY_EVENT : 20 octets, le caractère en UTF-16 (ushort : un char se marshalerait en ANSI ici).
  [StructLayout(LayoutKind.Explicit, Size = 20)] struct INPUT_RECORD {
    [FieldOffset(0)] public ushort EventType; [FieldOffset(4)] public int KeyDown; [FieldOffset(8)] public ushort Repeat;
    [FieldOffset(10)] public ushort VK; [FieldOffset(12)] public ushort Scan; [FieldOffset(14)] public ushort Car;
    [FieldOffset(16)] public uint Etat; }
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool WriteConsoleInputW(IntPtr h, INPUT_RECORD[] r, uint n, out uint ecrits);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L; public int T; public int R; public int B; }
  [StructLayout(LayoutKind.Sequential)] struct MONITORINFO { public int cbSize; public RECT Ecran; public RECT Travail; public uint Drapeaux; }
  [DllImport("user32.dll", SetLastError = true)] static extern bool GetWindowRect(IntPtr f, out RECT r);
  [DllImport("user32.dll")] static extern IntPtr MonitorFromWindow(IntPtr f, uint drapeaux);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern bool GetMonitorInfoW(IntPtr m, ref MONITORINFO i);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassNameW(IntPtr f, StringBuilder s, int n);
  [DllImport("user32.dll")] static extern IntPtr GetAncestor(IntPtr f, uint genre);
  [DllImport("user32.dll")] static extern bool IsWindow(IntPtr f);
  [DllImport("user32.dll")] static extern bool PostMessageW(IntPtr f, uint msg, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr f, out uint pid);
  delegate bool EnumProc(IntPtr f, IntPtr l);
  [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc rappel, IntPtr l);
  [DllImport("dwmapi.dll")] static extern int DwmGetWindowAttribute(IntPtr f, uint attribut, out RECT r, int taille);
  const uint LECTURE = 0x80000000, ECRITURE = 0x40000000, PARTAGE = 3, EXISTANT = 3;
  static readonly IntPtr INVALIDE = new IntPtr(-1);

  // Branché sur la console du processus `pid` : 0, sinon le code d'erreur de Windows.
  public static int Brancher(int pid) {
    FreeConsole();
    for (int k = 0; k < 10; k++) {
      if (AttachConsole((uint)pid)) return 0;
      Thread.Sleep(100);
    }
    return Marshal.GetLastWin32Error();
  }
  public static void Detacher() { FreeConsole(); }
  public static long FenetreDeLaConsole() { return GetConsoleWindow().ToInt64(); }
  public static int ProcessusDeLaConsole() { var l = new uint[16]; return (int)GetConsoleProcessList(l, 16); }

  // Le texte de la partie visible de la console (srWindow), une ligne par rangée ; colonnes et rangées visibles.
  // Vide et `erreur` posé si la lecture échoue.
  public static string Lire(out int colonnes, out int rangees, out int erreur) {
    colonnes = 0; rangees = 0; erreur = 0;
    IntPtr sortie = CreateFileW("CONOUT$", LECTURE | ECRITURE, PARTAGE, IntPtr.Zero, EXISTANT, 0, IntPtr.Zero);
    if (sortie == INVALIDE) { erreur = Marshal.GetLastWin32Error(); return ""; }
    try {
      CSBI i;
      if (!GetConsoleScreenBufferInfo(sortie, out i)) { erreur = Marshal.GetLastWin32Error(); return ""; }
      colonnes = i.Win.R - i.Win.L + 1; rangees = i.Win.B - i.Win.T + 1;
      if (colonnes <= 0 || rangees <= 0) { erreur = -1; return ""; }
      var sb = new StringBuilder(); var tampon = new char[colonnes];
      for (int y = i.Win.T; y <= i.Win.B; y++) {
        uint lus; var debut = new COORD(); debut.X = i.Win.L; debut.Y = (short)y;
        if (!ReadConsoleOutputCharacterW(sortie, tampon, (uint)colonnes, debut, out lus)) { erreur = Marshal.GetLastWin32Error(); return ""; }
        sb.Append(new string(tampon, 0, (int)lus).TrimEnd()); sb.Append('\n');
      }
      return sb.ToString();
    } finally { CloseHandle(sortie); }
  }

  // Une touche : appui puis relâchement (Vanguard ignore le relâchement). 0, sinon le code d'erreur.
  public static int Touche(ushort vk, ushort scan, char car, bool etendue) {
    IntPtr entree = CreateFileW("CONIN$", LECTURE | ECRITURE, PARTAGE, IntPtr.Zero, EXISTANT, 0, IntPtr.Zero);
    if (entree == INVALIDE) return Marshal.GetLastWin32Error();
    try {
      var r = new INPUT_RECORD[2];
      for (int b = 0; b < 2; b++) {
        r[b].EventType = 1; r[b].KeyDown = b == 0 ? 1 : 0; r[b].Repeat = 1; r[b].VK = vk; r[b].Scan = scan;
        r[b].Car = (ushort)car; r[b].Etat = etendue ? 0x100u : 0u;
      }
      uint n;
      if (!WriteConsoleInputW(entree, r, 2, out n) || n != 2) return Marshal.GetLastWin32Error();
      return 0;
    } finally { CloseHandle(entree); }
  }

  public static int[] Rect(long f) {
    RECT r; if (!GetWindowRect(new IntPtr(f), out r)) return null;
    return new int[] { r.L, r.T, r.R - r.L, r.B - r.T };
  }
  public static int[] RectDwm(long f) {
    RECT r; if (DwmGetWindowAttribute(new IntPtr(f), 9, out r, Marshal.SizeOf(typeof(RECT))) != 0) return null;
    return new int[] { r.L, r.T, r.R - r.L, r.B - r.T };
  }
  // La zone de travail de l'écran de la fenêtre (sans la barre des tâches), comme src/fenetre.rs.
  public static int[] Zone(long f) {
    IntPtr m = MonitorFromWindow(new IntPtr(f), 2);
    var i = new MONITORINFO(); i.cbSize = Marshal.SizeOf(typeof(MONITORINFO));
    if (!GetMonitorInfoW(m, ref i)) return null;
    return new int[] { i.Travail.L, i.Travail.T, i.Travail.R - i.Travail.L, i.Travail.B - i.Travail.T };
  }
  public static string Classe(long f) { var s = new StringBuilder(128); GetClassNameW(new IntPtr(f), s, 128); return s.ToString(); }
  public static long Racine(long f) { return GetAncestor(new IntPtr(f), 3).ToInt64(); }
  public static bool Existe(long f) { return f != 0 && IsWindow(new IntPtr(f)); }
  public static bool Fermer(long f) { return PostMessageW(new IntPtr(f), 0x10, IntPtr.Zero, IntPtr.Zero); }
  public static int ProcessusDe(long f) { uint pid; GetWindowThreadProcessId(new IntPtr(f), out pid); return (int)pid; }
  // Les fenêtres de premier niveau d'une classe donnée.
  public static long[] Fenetres(string classe) {
    var l = new List<long>();
    EnumWindows(delegate(IntPtr f, IntPtr p) { if (Classe(f.ToInt64()) == classe) l.Add(f.ToInt64()); return true; }, IntPtr.Zero);
    return l.ToArray();
  }
}
'@

# Les textes attendus, pris dans src/main.rs : [français, anglais].
$textes = @{
    ordinateur = @('Cet ordinateur', 'This computer')
    autreGroupe = @('Virus et logiciels espions', 'Viruses and spyware')
    defender = @('Blocages de Windows Defender', 'Windows Defender blocking')
    perimes = @('Logiciels pas à jour', 'Outdated software')
    defile = @('ligne(s) plus', 'more line(s)')
}
function Texte([string]$cle, [string]$langue) { if ($langue -eq 'en') { $textes[$cle][1] } else { $textes[$cle][0] } }
function Autre([string]$langue) { if ($langue -eq 'en') { 'fr' } else { 'en' } }

# ------------------------------------------------------------------------------------------------ le pilote
if ($Etape -eq 'pilote') {
    $fichier = Join-Path $Sortie "pilote-$Hote-$Langue.txt"
    $geo = Join-Path $Sortie "geometrie-$Hote-$Langue.txt"
    $lignes = New-Object System.Collections.ArrayList
    function Noter([string]$etat, [string]$essai, [string]$texte) { [void]$lignes.Add("$etat $Hote $Langue $essai $texte") }
    function Geo([string]$t) { Add-Content -LiteralPath $geo -Value $t -Encoding UTF8 }
    $script:n = 0
    $script:illisible = ''

    # Branché le temps d'une lecture, puis détaché : l'écran visible, ses colonnes et rangées, gardé comme preuve.
    function Ecran([string]$quoi) {
        $script:n++
        $e = [PiloteConsoleVg]::Brancher($Cible)
        if ($e -ne 0) { $script:illisible = "console de Vanguard introuvable (AttachConsole : erreur $e)"; return $null }
        try {
            $c = 0; $r = 0; $err = 0
            $t = [PiloteConsoleVg]::Lire([ref]$c, [ref]$r, [ref]$err)
            $nb = [PiloteConsoleVg]::ProcessusDeLaConsole()
            $console = [PiloteConsoleVg]::FenetreDeLaConsole()
        } finally { [PiloteConsoleVg]::Detacher() }
        $preuve = Join-Path $Sortie ('ecran-{0}-{1}-{2}.txt' -f $Hote, $Langue, $script:n)
        Set-Content -LiteralPath $preuve -Encoding UTF8 -Value ("# $quoi : $c colonnes × $r rangées visibles, $nb processus dans la console (pilote compris), erreur $err`r`n" + $t)
        if ($err -ne 0) {
            $script:illisible = if ($Hote -eq 'wt') { "lecture de l'écran impossible sous Windows Terminal (erreur $err)" } else { "lecture de l'écran impossible (erreur $err)" }
            return $null
        }
        if (-not $t.Trim()) { $script:illisible = "écran vide : rien d'affiché (écran $script:n gardé)"; return $null }
        $script:illisible = ''
        [pscustomobject]@{ Texte = $t; Lignes = @($t -split "`n"); Colonnes = $c; Rangees = $r; Console = $console }
    }

    # Une touche : branché, tapée, détaché aussitôt (Vanguard doit pouvoir retoucher sa fenêtre juste après).
    function Taper([string]$nom) {
        $e = [PiloteConsoleVg]::Brancher($Cible)
        if ($e -ne 0) { return "AttachConsole : erreur $e" }
        try {
            $r = switch ($nom) {
                'bas' { [PiloteConsoleVg]::Touche(0x28, 0x50, [char]0, $true) }
                'droite' { [PiloteConsoleVg]::Touche(0x27, 0x4D, [char]0, $true) }
                'gauche' { [PiloteConsoleVg]::Touche(0x25, 0x4B, [char]0, $true) }
                'q' { [PiloteConsoleVg]::Touche(0x51, 0x10, [char]'q', $false) }
                'entree' { [PiloteConsoleVg]::Touche(0x0D, 0x1C, [char]13, $false) }
            }
        } finally { [PiloteConsoleVg]::Detacher() }
        if ($r -ne 0) { return "WriteConsoleInputW : erreur $r" }
        ''
    }

    # La fenêtre ne bouge plus : même rectangle pendant 2 s (10 s au plus). Mesurée sans être branché.
    function Stable {
        $avant = $null; $depuis = Get-Date; $fin = (Get-Date).AddSeconds(10)
        while ((Get-Date) -lt $fin) {
            $r = [PiloteConsoleVg]::Rect($Fenetre)
            $cle = if ($r) { $r -join ',' } else { '' }
            if ($cle -ne $avant) { $avant = $cle; $depuis = Get-Date }
            elseif (((Get-Date) - $depuis).TotalSeconds -ge 2) { return $true }
            Start-Sleep -Milliseconds 200
        }
        $false
    }

    # La rangée de la saisie (« › » en début de ligne), comptée depuis le haut : la hauteur du menu affiché.
    function Hauteur-Menu($ecran) {
        $n = -1
        for ($i = 0; $i -lt $ecran.Lignes.Count; $i++) { if ($ecran.Lignes[$i] -match '^\s{0,3}›(\s|$)') { $n = $i + 1 } }
        $n
    }
    function Ligne-Marquee($ecran) { @($ecran.Lignes | Where-Object { $_ -match '^\s{0,3}►' }) | Select-Object -First 1 }

    # La place d'où la fenêtre ne doit pas sauter : celle où elle s'est ouverte, puis celle du menu jugé avant.
    $script:placeAvant = $null

    # C2/C3 (et C6, C7) : la hauteur, d'après le texte vu ET la fenêtre mesurée ; la place, comme src/fenetre.rs la
    # tient sous Windows : la fenêtre reste où elle était (coin haut gauche), ramenée dans la zone de travail
    # seulement si sa nouvelle taille l'en ferait sortir, et toujours entière dans cette zone.
    function Juger-Fenetre([string]$essaiH, [string]$essaiC, $ecran, [string]$quoi) {
        $r = [PiloteConsoleVg]::Rect($Fenetre); $z = [PiloteConsoleVg]::Zone($Fenetre); $d = [PiloteConsoleVg]::RectDwm($Fenetre)
        Geo ("{0} {1:HH:mm:ss} : fenêtre {2} (x,y,l,h) ; DWM {3} ; zone de travail {4} ; {5} colonnes × {6} rangées ; classe {7}" -f `
            $quoi, (Get-Date), ($r -join ','), ($d -join ','), ($z -join ','), $ecran.Colonnes, $ecran.Rangees, [PiloteConsoleVg]::Classe($Fenetre))
        if (-not $r -or -not $z) { Noter 'BUG' $essaiH "$quoi : fenêtre ou écran impossible à mesurer"; return }
        $n = Hauteur-Menu $ecran
        $voulu = [Math]::Max($n, 12)
        $defile = $ecran.Texte.Contains((Texte 'defile' $Langue))
        $case = if ($ecran.Rangees -gt 0) { $r[3] / $ecran.Rangees } else { 0 }
        if ($n -lt 1) { Noter 'BUG' $essaiH "$quoi : pas de ligne de saisie « › » à l'écran" }
        elseif ($ecran.Colonnes -notin 78, 79) { Noter 'BUG' $essaiH "$quoi : $($ecran.Colonnes) colonnes visibles, 78 attendues (79 permises)" }
        elseif ($defile) {
            if ($r[3] -ge $z[3] - 2 * $case) { Noter 'OK' $essaiH "$quoi : menu plus haut que l'écran, fenêtre à la hauteur de l'écran ($($r[3]) px sur $($z[3]))" }
            else { Noter 'BUG' $essaiH "$quoi : le menu défile alors que la fenêtre ($($r[3]) px) pourrait grandir jusqu'à $($z[3]) px" }
        } elseif ($ecran.Rangees -ge $voulu -and $ecran.Rangees -le $voulu + 1) {
            Noter 'OK' $essaiH "$quoi : $($ecran.Colonnes) × $($ecran.Rangees) pour un menu de $n rangées"
        } else { Noter 'BUG' $essaiH "$quoi : $($ecran.Rangees) rangées visibles pour un menu de $n (attendu $voulu ou $($voulu + 1))" }
        # Quelques pixels de jeu : bordures invisibles et arrondis du bureau, comme `centree` dans src/fenetre.rs.
        $jeu = 8
        $avant = $script:placeAvant
        $script:placeAvant = $r
        $mesures = "fenêtre $($r -join ','), zone $($z -join ',')"
        $dehors = @()
        if ($r[0] -lt $z[0] - $jeu) { $dehors += 'à gauche' }
        if ($r[1] -lt $z[1] - $jeu) { $dehors += 'en haut' }
        if ($r[0] + $r[2] -gt $z[0] + $z[2] + $jeu) { $dehors += 'à droite' }
        if ($r[1] + $r[3] -gt $z[1] + $z[3] + $jeu) { $dehors += 'en bas' }
        if ($dehors.Count) { Noter 'BUG' $essaiC "$quoi : fenêtre pas entière dans la zone de travail (dépasse $($dehors -join ', ') ; $mesures)"; return }
        if (-not $avant) { Noter 'BUG' $essaiC "$quoi : place d'avant inconnue, saut impossible à juger ($mesures)"; return }
        # La place attendue : celle d'avant, bornée à la zone pour la taille d'à présent (la règle de `placement`).
        $ax = [Math]::Max($z[0], [Math]::Min($avant[0], $z[0] + $z[2] - $r[2]))
        $ay = [Math]::Max($z[1], [Math]::Min($avant[1], $z[1] + $z[3] - $r[3]))
        $ecart = "écart x $($r[0] - $ax), y $($r[1] - $ay) px de la place attendue $ax,$ay (avant : $($avant[0]),$($avant[1]))"
        if ([Math]::Abs($r[0] - $ax) -le $jeu -and [Math]::Abs($r[1] - $ay) -le $jeu) { Noter 'OK' $essaiC "$quoi : entière dans la zone, place gardée ($ecart)" }
        else { Noter 'BUG' $essaiC "$quoi : la fenêtre a sauté ($ecart ; $mesures)" }
    }

    function Sauter-Reste([string[]]$essais, [string]$raison) { foreach ($e in $essais) { Noter 'SAUTE' $e $raison } }

    # Écran ou touches hors d'atteinte. Sous Windows Terminal, la lecture peut être impossible par nature : sauté, avec
    # la raison. Sous conhost, l'outil marche toujours : un écran vide ou illisible veut dire que Vanguard est bloqué
    # avant son menu ou arrêté, donc un BUG (le premier essai touché ; les suivants sautés, faute de pouvoir les faire).
    # Vanguard arrêté : un BUG partout.
    function Hors-Atteinte([string[]]$essais, [string]$raison) {
        if ($processus.HasExited) {
            $code = try { $processus.ExitCode } catch { 'inconnu' }
            $raison = "Vanguard s'est arrêté (code $code) ; $raison"
        } elseif ($Hote -eq 'wt') { Sauter-Reste $essais $raison; return }
        Noter 'BUG' $essais[0] $raison
        if ($essais.Count -gt 1) { Sauter-Reste $essais[1..($essais.Count - 1)] "suite de $($essais[0])" }
    }

    try {
        Add-Type -TypeDefinition $srcPilote
        [PiloteConsoleVg]::Detacher()
        $processus = [Diagnostics.Process]::GetProcessById($Cible)
        # La poignée ouverte tant qu'il vit : son code de sortie reste lisible après coup.
        try { [void]$processus.Handle } catch { }
        $tous = @('C1', 'C2', 'C3', 'C4', 'C5', 'C6', 'C7', 'C8')

        # C1 : la fenêtre a pris sa taille (elle a bougé puis s'est arrêtée), puis le menu se lit. 20 s au plus.
        $initial = if ($RectInitial) { $RectInitial } else { ([PiloteConsoleVg]::Rect($Fenetre)) -join ',' }
        $script:placeAvant = @($initial -split ',' | Where-Object { $_ -ne '' } | ForEach-Object { [int]$_ })
        if ($script:placeAvant.Count -ne 4) { $script:placeAvant = $null }
        Geo "fenêtre à l'ouverture (x,y,l,h) : $initial"
        $fin = (Get-Date).AddSeconds(20)
        while ((Get-Date) -lt $fin -and -not $processus.HasExited -and ([PiloteConsoleVg]::Rect($Fenetre) -join ',') -eq $initial) { Start-Sleep -Milliseconds 200 }
        [void](Stable)
        $menu = $null
        do {
            $menu = Ecran 'menu principal'
            if ($menu -and $menu.Texte.Contains((Texte 'ordinateur' $Langue)) -and (Hauteur-Menu $menu) -gt 0) { break }
            if ($menu -and $menu.Texte.Contains((Texte 'ordinateur' (Autre $Langue)))) { break }
            if ($processus.HasExited) { break }
            Start-Sleep -Milliseconds 500
        } while ((Get-Date) -lt $fin)
        $console = if ($menu) { $menu.Console } else { 0 }
        if ($console) {
            $racine = [PiloteConsoleVg]::Racine($console)
            Geo ("console {0} ({1}), fenêtre de premier niveau {2} ({3}) ; fenêtre mesurée {4} ({5})" -f $console, [PiloteConsoleVg]::Classe($console), `
                $racine, [PiloteConsoleVg]::Classe($racine), $Fenetre, [PiloteConsoleVg]::Classe($Fenetre))
        }
        if (-not $menu) {
            Hors-Atteinte @('C1', 'C2', 'C4', 'C5', 'C6', 'C7', 'C8') $script:illisible
            Noter 'INFO' 'C3' "fenêtre $(([PiloteConsoleVg]::Rect($Fenetre)) -join ',') dans la zone $(([PiloteConsoleVg]::Zone($Fenetre)) -join ',') (mesuré, menu non lu)"
            return
        }
        if ($menu.Texte.Contains((Texte 'ordinateur' (Autre $Langue)))) {
            if ($Hote -eq 'wt') { Sauter-Reste $tous "Windows Terminal n'a pas transmis VANGUARD_LANG=$Langue (menu dans l'autre langue)" }
            else { Noter 'BUG' 'C1' "menu dans l'autre langue malgré VANGUARD_LANG=$Langue"; Sauter-Reste @('C2', 'C3', 'C4', 'C5', 'C6', 'C7', 'C8') 'langue' }
            return
        }
        if (-not $menu.Texte.Contains((Texte 'ordinateur' $Langue)) -or (Hauteur-Menu $menu) -lt 1) {
            Noter 'BUG' 'C1' "menu principal pas vu en 20 s (écran $script:n gardé)"
            Sauter-Reste @('C2', 'C3', 'C4', 'C5', 'C6', 'C7', 'C8') 'menu principal pas vu'
            return
        }
        Noter 'OK' 'C1' "menu principal affiché (« $(Texte 'ordinateur' $Langue) » et la saisie « › » lus)"
        Juger-Fenetre 'C2' 'C3' $menu 'menu principal'

        # C4 : ↓ jusqu'à la ligne de Cet ordinateur ; chaque ↓ déplace la marque « ► ».
        $marquee = Ligne-Marquee $menu
        if (-not $marquee) {
            Noter 'BUG' 'C4' 'aucune ligne marquée « ► » : le menu n''est pas en mode clavier'
            Sauter-Reste @('C5', 'C6', 'C7', 'C8') 'pas de mode clavier'
            return
        }
        $ok4 = $true; $k = 0
        while (-not $marquee.Contains((Texte 'ordinateur' $Langue)) -and $k -lt 25) {
            $k++
            $err = Taper 'bas'
            if ($err) { Hors-Atteinte @('C4', 'C5', 'C6', 'C7', 'C8') "touches impossibles ($err)"; return }
            Start-Sleep -Milliseconds 500
            $e = Ecran "après ↓ n° $k"
            if (-not $e) { Hors-Atteinte @('C4', 'C5', 'C6', 'C7', 'C8') $script:illisible; return }
            $nouvelle = Ligne-Marquee $e
            if (-not $nouvelle -or $nouvelle -eq $marquee) { $ok4 = $false; Noter 'BUG' 'C4' "↓ n° $k : la marque « ► » n'a pas bougé (écran $script:n)"; break }
            $marquee = $nouvelle
        }
        if (-not $ok4) { Sauter-Reste @('C5', 'C6', 'C7', 'C8') '↓ sans effet'; return }
        if (-not $marquee.Contains((Texte 'ordinateur' $Langue))) {
            Noter 'BUG' 'C4' "« $(Texte 'ordinateur' $Langue) » pas atteint en 25 ↓"; Sauter-Reste @('C5', 'C6', 'C7', 'C8') 'Cet ordinateur pas atteint'; return
        }
        Noter 'OK' 'C4' "$k ↓ : « ► » sur « $(Texte 'ordinateur' $Langue) »"

        # C5 : → entre dans le groupe ; C6 : la fenêtre refaite à la hauteur du sous-menu, à la même place.
        $err = Taper 'droite'
        if ($err) { Hors-Atteinte @('C5', 'C6', 'C7', 'C8') "touches impossibles ($err)"; return }
        Start-Sleep -Milliseconds 300
        [void](Stable)
        $sous = Ecran 'après →'
        if (-not $sous) { Hors-Atteinte @('C5', 'C6', 'C7', 'C8') $script:illisible; return }
        $vus = $sous.Texte.Contains((Texte 'defender' $Langue)) -and $sous.Texte.Contains((Texte 'perimes' $Langue))
        if ($vus -and -not $sous.Texte.Contains((Texte 'autreGroupe' $Langue))) {
            Noter 'OK' 'C5' "→ : sous-menu avec « $(Texte 'defender' $Langue) » et « $(Texte 'perimes' $Langue) »"
            Juger-Fenetre 'C6' 'C6' $sous 'sous-menu Cet ordinateur'
        } else {
            Noter 'BUG' 'C5' "→ : sous-menu Cet ordinateur pas vu (écran $script:n)"
            Sauter-Reste @('C6') 'sous-menu pas vu'
        }

        # C7 : ← revient au menu principal, à sa hauteur et à la même place.
        $err = Taper 'gauche'
        if ($err) { Hors-Atteinte @('C7', 'C8') "touches impossibles ($err)"; return }
        Start-Sleep -Milliseconds 300
        [void](Stable)
        $retour = Ecran 'après ←'
        if (-not $retour) { Hors-Atteinte @('C7', 'C8') $script:illisible; return }
        $m = Ligne-Marquee $retour
        if ($m -and $m.Contains((Texte 'ordinateur' $Langue)) -and -not $retour.Texte.Contains((Texte 'defender' $Langue)) -and -not $retour.Texte.Contains((Texte 'perimes' $Langue))) {
            Noter 'OK' 'C7' "← : menu principal revenu, « ► » sur « $(Texte 'ordinateur' $Langue) »"
            Juger-Fenetre 'C7' 'C7' $retour 'menu principal après ←'
        } else { Noter 'BUG' 'C7' "← : menu principal pas revenu (écran $script:n)" }

        # C8 : q puis Entrée : Vanguard se ferme, code 0, en 10 s au plus.
        $err = Taper 'q'
        if (-not $err) { Start-Sleep -Milliseconds 300; $err = Taper 'entree' }
        if ($err) { Hors-Atteinte @('C8') "touches impossibles ($err)"; return }
        if ($processus.WaitForExit(10000)) {
            if ($processus.ExitCode -eq 0) { Noter 'OK' 'C8' 'q + Entrée : Vanguard fermé, code 0' }
            else { Noter 'BUG' 'C8' "q + Entrée : Vanguard fermé avec le code $($processus.ExitCode)" }
        } else { Noter 'BUG' 'C8' 'q + Entrée : Vanguard toujours ouvert après 10 s' }
    } catch {
        Noter 'BUG' 'pilote' "erreur du pilote : $($_.Exception.Message)"
    } finally {
        [PiloteConsoleVg]::Detacher()
        [IO.File]::WriteAllLines($fichier, [string[]]$lignes, (New-Object Text.UTF8Encoding $false))
    }
    exit 0
}

# ------------------------------------------------------------------------------------------------ le chef
if (-not $Exe -or -not (Test-Path -LiteralPath $Exe -PathType Leaf)) { Write-Error "Programme absent : $Exe"; exit 2 }
if (-not $Sortie) { Write-Error 'Il faut -Sortie'; exit 2 }
New-Item -ItemType Directory -Force -Path $Sortie | Out-Null
$Exe = (Resolve-Path -LiteralPath $Exe).Path
$resume = Join-Path $Sortie 'resume.txt'
Set-Content -LiteralPath $resume -Value @() -Encoding UTF8
# Une ligne par essai : un message d'erreur sur plusieurs lignes est remis sur une seule (le surveillant lit ligne à ligne).
function Resume([string]$t) { $t = $t -replace '\s*[\r\n]+\s*', ' '; Add-Content -LiteralPath $resume -Value $t -Encoding UTF8; Write-Host $t }
Add-Type -TypeDefinition $srcPilote
# Ce script tourne en administrateur : chaque programme est pris par un chemin que l'utilisateur sans droits ne peut
# pas détourner. Ni le PATH ni %SystemRoot% (l'un et l'autre réglables dans HKCU\Environment), ni un nom nu que
# Start-Process chercherait aussi dans HKCU\...\App Paths.
$systeme = [Environment]::SystemDirectory
$PowerShell = Join-Path $systeme 'WindowsPowerShell\v1.0\powershell.exe'
$limite = (Get-Date).AddMinutes([Math]::Max(1, $LimiteMinutes))
$moi = $MyInvocation.MyCommand.Path
$listeLangues = @($Langues -split ',' | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ -in 'fr', 'en' })
$listeHotes = @($Hotes -split ',' | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ -in 'conhost', 'wt' })

# Les vanguard.exe lancés depuis ce chemin-là, par leur numéro (jamais par le nom seul).
function Vanguards { @(Get-CimInstance Win32_Process -Filter "Name = 'vanguard.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.ExecutablePath -eq $Exe }) }

# Windows Terminal par le dossier de son paquet, sous Program Files\WindowsApps (que seuls le système et les
# administrateurs modifient), jamais par le PATH : l'alias wt.exe vit dans %LOCALAPPDATA%\Microsoft\WindowsApps, où
# l'utilisateur sans droits écrit. Introuvable ainsi : sauté, avec la raison.
function Trouver-Wt {
    $apps = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'WindowsApps'
    try { $paquets = @(Get-AppxPackage -Name 'Microsoft.WindowsTerminal*' -ErrorAction Stop | Sort-Object Version -Descending) }
    catch { return [pscustomobject]@{ Chemin = $null; Raison = "paquets illisibles ($($_.Exception.Message))" } }
    if (-not $paquets.Count) { return [pscustomobject]@{ Chemin = $null; Raison = 'Windows Terminal absent' } }
    foreach ($p in $paquets) {
        $d = if ($p.InstallLocation) { [IO.Path]::GetFullPath([string]$p.InstallLocation) } else { '' }
        if (-not $d.StartsWith($apps + '\', [StringComparison]::OrdinalIgnoreCase)) { continue }
        $f = Join-Path $d 'wt.exe'
        if (Test-Path -LiteralPath $f -PathType Leaf) { return [pscustomobject]@{ Chemin = $f; Raison = '' } }
    }
    [pscustomobject]@{ Chemin = $null; Raison = "Windows Terminal installé hors de $apps : pas lancé en administrateur" }
}
$wt = if ($listeHotes -contains 'wt') { Trouver-Wt } else { $null }
foreach ($hoteEssai in $listeHotes) {
    foreach ($langueEssai in $listeLangues) {
        if ((Get-Date) -gt $limite) { Resume "SAUTE $hoteEssai $langueEssai C1-C8 délai des essais de console dépassé"; continue }
        if ($hoteEssai -eq 'wt' -and -not $wt.Chemin) { Resume "SAUTE wt $langueEssai C1-C8 $($wt.Raison)"; continue }
        $avant = @(Vanguards | ForEach-Object { [int]$_.ProcessId })
        # Les fenêtres de Windows Terminal déjà là : la sienne est la nouvelle ; sous conhost, une nouvelle dirait que
        # Windows a confié la console au terminal par défaut.
        $fenetresAvant = @([PiloteConsoleVg]::Fenetres('CASCADIA_HOSTING_WINDOW_CLASS'))
        $env:VANGUARD_LANG = $langueEssai
        $hoteProc = $null; $fenetreVg = 0; $pidVanguard = 0
        try {
            if ($hoteEssai -eq 'conhost') {
                # conhost.exe lancé soi-même : la vieille console, même si Windows Terminal est le terminal par défaut.
                $hoteProc = Start-Process -FilePath (Join-Path $systeme 'conhost.exe') -ArgumentList "`"$Exe`"" `
                    -WorkingDirectory (Split-Path -Parent $Exe) -PassThru
            } else {
                $hoteProc = Start-Process -FilePath $wt.Chemin -ArgumentList @('-w', 'new', "`"$Exe`"") -WorkingDirectory (Split-Path -Parent $Exe) -PassThru
            }
            $fin = (Get-Date).AddSeconds(30)
            while ((Get-Date) -lt $fin -and (-not $fenetreVg -or -not $pidVanguard)) {
                Start-Sleep -Milliseconds 300
                if (-not $pidVanguard) { $v = @(Vanguards | Where-Object { [int]$_.ProcessId -notin $avant }); if ($v.Count -eq 1) { $pidVanguard = [int]$v[0].ProcessId } }
                if (-not $fenetreVg) {
                    if ($hoteEssai -eq 'conhost') {
                        # conhost prête sa fenêtre au premier programme de sa console (SetConsoleWindowOwner, dans
                        # src/interactivity/win32/windowio.cpp de microsoft/terminal) : GetWindowThreadProcessId y rend
                        # le numéro de vanguard.exe, jamais celui de conhost.exe. Cherchée donc par Vanguard, une fois
                        # son numéro connu.
                        $f = if ($pidVanguard) { @([PiloteConsoleVg]::Fenetres('ConsoleWindowClass') | Where-Object { [PiloteConsoleVg]::ProcessusDe($_) -eq $pidVanguard }) } else { @() }
                    } else {
                        $f = @([PiloteConsoleVg]::Fenetres('CASCADIA_HOSTING_WINDOW_CLASS') | Where-Object { $_ -notin $fenetresAvant })
                    }
                    if ($f.Count -eq 1) { $fenetreVg = $f[0] }
                }
            }
            if (-not $pidVanguard -or -not $fenetreVg) {
                # Windows Terminal lancé par le chemin de son paquet qui refuse de s'ouvrir : l'outil, pas Vanguard.
                if ($hoteEssai -eq 'wt' -and -not $pidVanguard -and $hoteProc.HasExited -and $hoteProc.ExitCode -ne 0) {
                    Resume "SAUTE wt $langueEssai C1-C8 Windows Terminal ne s'ouvre pas depuis son paquet (code $($hoteProc.ExitCode))"
                    continue
                }
                if ($hoteEssai -eq 'conhost' -and $pidVanguard) {
                    $consoles = @([PiloteConsoleVg]::Fenetres('ConsoleWindowClass') | ForEach-Object { "$_ (processus $([PiloteConsoleVg]::ProcessusDe($_)))" })
                    $nouvelles = @([PiloteConsoleVg]::Fenetres('CASCADIA_HOSTING_WINDOW_CLASS') | Where-Object { $_ -notin $fenetresAvant })
                    $etat = "Vanguard $pidVanguard, conhost $($hoteProc.Id)$(if ($hoteProc.HasExited) { ' (fermé)' }) ; fenêtres ConsoleWindowClass : $(if ($consoles.Count) { $consoles -join ', ' } else { 'aucune' })"
                    # Windows a tout de même confié la console au terminal par défaut : la vieille console n'est
                    # pas à l'écran, rien à y essayer ; ce n'est pas Vanguard.
                    if ($nouvelles.Count) {
                        # Refermée par son adresse avec le reste de l'essai (finally), quand elle est seule nouvelle.
                        if ($nouvelles.Count -eq 1) { $fenetreVg = $nouvelles[0] }
                        Resume "SAUTE conhost $langueEssai C1-C8 Windows a ouvert Vanguard dans Windows Terminal (terminal par défaut) malgré conhost.exe lancé soi-même : vieille console absente ($etat)"
                        continue
                    }
                    Resume "BUG conhost $langueEssai C1 fenêtre de Vanguard introuvable en 30 s ($etat)"
                    continue
                }
                $quoi = if (-not $pidVanguard) { 'Vanguard ne s''est pas lancé' } else { 'fenêtre de Vanguard introuvable' }
                Resume "BUG $hoteEssai $langueEssai C1 $quoi en 30 s"
                continue
            }
            $rectDepart = ([PiloteConsoleVg]::Rect($fenetreVg)) -join ','
            $pilote = Start-Process -FilePath $PowerShell -WindowStyle Hidden -PassThru -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass',
                '-File', "`"$moi`"", '-Etape', 'pilote', '-Cible', $pidVanguard, '-Fenetre', $fenetreVg, '-Hote', $hoteEssai, '-Langue', $langueEssai, '-Sortie', "`"$Sortie`"", '-RectInitial', $rectDepart)
            $reste = [Math]::Max(5000, [int](($limite - (Get-Date)).TotalMilliseconds))
            if (-not $pilote.WaitForExit([Math]::Min($reste, 240000))) {
                Stop-Process -Id $pilote.Id -Force -ErrorAction SilentlyContinue
                Resume "BUG $hoteEssai $langueEssai pilote arrêté : pas fini à temps"
            }
            $f = Join-Path $Sortie "pilote-$hoteEssai-$langueEssai.txt"
            if (Test-Path -LiteralPath $f) { Get-Content -LiteralPath $f -Encoding UTF8 | Where-Object { $_ } | ForEach-Object { Resume $_ } }
            else { Resume "BUG $hoteEssai $langueEssai pilote sans résultat" }
        } catch {
            Resume "BUG $hoteEssai $langueEssai erreur du chef : $($_.Exception.Message)"
        } finally {
            # Tout ce que cet essai a ouvert est refermé : la fenêtre par son adresse, puis Vanguard par son numéro.
            if ($pidVanguard -and (Get-Process -Id $pidVanguard -ErrorAction SilentlyContinue)) {
                if ($fenetreVg -and [PiloteConsoleVg]::Existe($fenetreVg)) { [void][PiloteConsoleVg]::Fermer($fenetreVg); Start-Sleep -Seconds 2 }
                Stop-Process -Id $pidVanguard -Force -ErrorAction SilentlyContinue
            }
            if ($hoteEssai -eq 'wt' -and $fenetreVg -and [PiloteConsoleVg]::Existe($fenetreVg)) { [void][PiloteConsoleVg]::Fermer($fenetreVg) }
            if ($hoteEssai -eq 'conhost' -and $hoteProc -and -not $hoteProc.HasExited) {
                Start-Sleep -Seconds 1
                if (-not $hoteProc.HasExited) { Stop-Process -Id $hoteProc.Id -Force -ErrorAction SilentlyContinue }
            }
            Remove-Item Env:\VANGUARD_LANG -ErrorAction SilentlyContinue
        }
    }
}
$compte = @{}
foreach ($l in Get-Content -LiteralPath $resume -Encoding UTF8) { $e = ($l -split ' ', 2)[0]; $compte[$e] = 1 + [int]$compte[$e] }
Write-Host ("Essais de console : {0} OK, {1} problème(s), {2} sauté(s)" -f [int]$compte['OK'], [int]$compte['BUG'], [int]$compte['SAUTE'])
exit 0

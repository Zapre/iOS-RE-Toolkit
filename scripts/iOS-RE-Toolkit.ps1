# ===========================================================================
# iOS RE Toolkit - by Zapre
# Professional iOS reverse engineering toolkit with enhanced analysis
# ===========================================================================
param(
    [string]$AppPath = "",
    [switch]$Verbose,
    [switch]$QuickScan,
    [switch]$JsonExport  # New: Export as JSON
)

# ---------------------------------------------------------------------------
# Global configuration
# ---------------------------------------------------------------------------
$Global:OutputDir = "C:\Re-Scans"
if (-not (Test-Path $Global:OutputDir)) {
    New-Item -Path $Global:OutputDir -ItemType Directory -Force | Out-Null
}

$Global:LogBuffer        = New-Object System.Collections.Generic.List[string]
$Global:DetailedFindings = New-Object System.Collections.Generic.List[string]
$Global:PriorityStrings  = @{}  # High-value strings per file
$Global:OutputMode       = "Smart"  # Smart or Full
$Global:UniqueId         = [Guid]::NewGuid().ToString().Substring(0,8)  # Unique for anti-copy

# Smart filtering configuration (tightened for AI)
$Global:SmartConfig = @{
    MaxStringsPerFile   = 400      # Reduced from 500
    MaxURLs             = 40       # Reduced
    MaxTotalLines       = 3000     # Reduced from 5000
    MinStringRelevance  = 3        # Increased min score
    MaxPatternSamples   = 8        # Reduced
    ContextRadius       = 40       # Increased for better context
}

# Full mode configuration  
$Global:FullConfig = @{
    MaxStringsPerFile   = 20000    # Reduced slightly for perf
    MaxURLs             = 400
    MaxTotalLines       = 999999
    MinStringRelevance  = 0
    MaxPatternSamples   = 80
    ContextRadius       = 120
}

# Active configuration (will be set based on mode)
$Global:Config = $Global:SmartConfig

# ---------------------------------------------------------------------------
# Logging functions
# ---------------------------------------------------------------------------
function Write-Status {
    param(
        [string]$Text,
        [string]$Type = "Info",
        [switch]$LogOnly
    )
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    $logLine = switch ($Type) {
        "Header"   { "`n=== $Text ===" }
        "Success"  { "[$timestamp] [+] $Text" }
        "Warning"  { "[$timestamp] [!] $Text" }
        "Error"    { "[$timestamp] [X] $Text" }
        "Info"     { "[$timestamp] [*] $Text" }
        "Debug"    { "[$timestamp]     $Text" }
        "Found"    { "[$timestamp]   → $Text" }
        "Progress" { "[$timestamp] ... $Text" }
        default    { $Text }
    }
    
    if ($Global:LogBuffer) {
        $Global:LogBuffer.Add($logLine)
    }
    
    if (-not $LogOnly) {
        if ($Type -eq "Debug" -and -not $Verbose) { return }
        
        switch ($Type) {
            "Header"   { Write-Host "`n▓▓▓ $Text ▓▓▓" -ForegroundColor Cyan }
            "Success"  { Write-Host "[+] $Text" -ForegroundColor Green }
            "Warning"  { Write-Host "[!] $Text" -ForegroundColor Yellow }
            "Error"    { Write-Host "[X] $Text" -ForegroundColor Red }
            "Info"     { Write-Host "[*] $Text" -ForegroundColor White }
            "Debug"    { Write-Host "    $Text" -ForegroundColor Gray }
            "Found"    { Write-Host "  → $Text" -ForegroundColor Magenta }
            "Progress" { Write-Host "... $Text" -ForegroundColor DarkGray -NoNewline; Write-Host "`r" -NoNewline }
            default    { Write-Host $Text -ForegroundColor White }
        }
    }
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ██╗ ██████╗ ███████╗    ██████╗ ███████╗" -ForegroundColor DarkCyan
    Write-Host "  ██║██╔═══██╗██╔════╝    ██╔══██╗██╔════╝" -ForegroundColor DarkCyan
    Write-Host "  ██║██║   ██║███████╗    ██████╔╝█████╗  " -ForegroundColor Cyan
    Write-Host "  ██║██║   ██║╚════██║    ██╔══██╗██╔══╝  " -ForegroundColor Cyan
    Write-Host "  ██║╚██████╔╝███████║    ██║  ██║███████╗" -ForegroundColor Blue
    Write-Host "  ╚═╝ ╚═════╝ ╚══════╝    ╚═╝  ╚═╝╚══════╝" -ForegroundColor Blue
    Write-Host ""
    Write-Host "  iOS RE Toolkit - by Zapre" -ForegroundColor White
    Write-Host "  ======================================" -ForegroundColor DarkGray
    Write-Host "  Output: C:\Re-Scans\" -ForegroundColor Yellow
    Write-Host ""
}

# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------
function Get-QuickHash {
    param([string]$Path)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path) | Select-Object -First 1024
        $hash = [System.BitConverter]::ToString(
            [System.Security.Cryptography.MD5]::Create().ComputeHash($bytes)
        )
        return $hash.Replace("-","").Substring(0,8).ToUpper() + $Global:UniqueId  # Anti-copy unique
    } catch {
        return "ERROR"
    }
}

function Test-SuspiciousDylib {
    param([string]$Name)
    $suspicious = @(
        "substrate", "substitute", "cycript", "frida", "flex", "reveal",
        "inject", "tweak", "patch", "crack", "bypass", "Liberty", "Shadow",
        "FlyJB", "A-Bypass", "UnSub", "TweakInject", "MobileSubstrate",
        "ElleKit", "Dopamine", "Sileo", "Zebra", "CydiaSubstrate"  # Expanded
    )
    foreach ($pattern in $suspicious) {
        if ($Name -match $pattern) {
            return $pattern
        }
    }
    return $null
}

function Get-MachOEncryptionStatus {
    param([string]$Path)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        if ($bytes.Length -lt 32) { return $false }

        # Magic numbers: 0xFEEDFACE (32-bit) or 0xFEEDFACF (64-bit)
        $magic = [BitConverter]::ToUInt32($bytes, 0)
        if ($magic -ne 0xFEEDFACE -and $magic -ne 0xFEEDFACF) { return $false }

        # Number of load commands
        $ncmdsOffset = if ($magic -eq 0xFEEDFACF) { 28 } else { 24 }  # 64-bit vs 32-bit
        $ncmds = [BitConverter]::ToUInt32($bytes, $ncmdsOffset)

        # Load commands start after header
        $cmdOffset = if ($magic -eq 0xFEEDFACF) { 32 } else { 28 }
        for ($i = 0; $i -lt $ncmds; $i++) {
            $cmd = [BitConverter]::ToUInt32($bytes, $cmdOffset)
            $cmdSize = [BitConverter]::ToUInt32($bytes, $cmdOffset + 4)

            # NOTE: placeholder constant kept from your version; adjust if you want stricter LC_ENCRYPTION_INFO parsing
            if ($cmd -eq 0xC) {
                $cryptoff = [BitConverter]::ToUInt32($bytes, $cmdOffset + 8)
                $cryptsize = [BitConverter]::ToUInt32($bytes, $cmdOffset + 12)
                $cryptid = [BitConverter]::ToUInt32($bytes, $cmdOffset + 16)
                if ($cryptid -gt 0 -and $cryptsize -gt 0) { return $true }
            }
            $cmdOffset += $cmdSize
        }
        return $false
    } catch {
        return $false
    }
}

# ---------------------------------------------------------------------------
# Calculate string relevance score based on user intent (enhanced)
# ---------------------------------------------------------------------------
function Get-StringRelevance {
    param(
        [string]$String,
        [string[]]$Categories,
        [int]$Intention,
        [double]$FileSizeMB  # New: Dynamic based on file size
    )
    
    $score = 0
    $str = $String.ToLower()
    
    # High-value patterns for each intention (expanded with regex)
    $intentPatterns = @{
        1 = @{  # Auth bypass
            High = @("\blogin\b", "\bauth\b", "\bpassword\b", "\btoken\b", "\bsession\b", "\bcredential\b", "\bsignin\b", "\blogout\b")
            Medium = @("\buser\b", "\bemail\b", "\baccount\b", "\bverify\b", "\bvalidate\b", "\bcheck\b")
            Functions = @("WithEmail", "WithPassword", "Authenticated", "ValidateCredentials", "CheckLogin")
        }
        2 = @{  # License crack
            High = @("\blicense\b", "\bactivation\b", "\btrial\b", "\bpremium\b", "\bexpire\b", "\bsubscription\b", "\bunlock\b")
            Medium = @("\bvalidate\b", "\bcheck\b", "\bverify\b", "\bserial\b", "\bkey\b", "\bpurchase\b")
            Functions = @("ValidateLicense", "CheckSubscription", "IsActivated", "IsPremium", "HasLicense")
        }
        3 = @{  # Security analysis
            High = @("\bjailbreak\b", "\bcydia\b", "\bfrida\b", "\bdebug\b", "\broot\b", "\bhook\b", "\bbypass\b")
            Medium = @("\bdetect\b", "\bcheck\b", "\bintegrity\b", "\btamper\b", "\bsimulator\b")
            Functions = @("IsJailbroken", "DebuggerAttached", "IntegrityCheck", "DetectHook")
        }
        4 = @{  # Network/API
            High = @("http", "https", "\bapi\b", "\bendpoint\b", "\bhost\b", "\bserver\b", "\burl\b")
            Medium = @("\brequest\b", "\bresponse\b", "\bfetch\b", "\bpost\b", "\bget\b", "\bsocket\b")
            Functions = @("SendRequest", "APICall", "FetchData", "UploadData")
        }
        5 = @{  # General
            High = @("\bpassword\b", "\btoken\b", "\bapi\b", "\blicense\b", "\bdebug\b", "http")
            Medium = @("\bauth\b", "\blogin\b", "\bcheck\b", "\bvalidate\b", "\bverify\b")
            Functions = @("Validate", "Check", "Verify", "Authenticate")
        }
    }
    
    $patterns = $intentPatterns[$Intention]
    if (-not $patterns) { $patterns = $intentPatterns[5] }
    
    # Check high-value patterns (regex)
    foreach ($pattern in $patterns.High) {
        if ($str -match $pattern) { $score += 4 }  # Increased weight
    }
    
    # Check medium-value patterns
    foreach ($pattern in $patterns.Medium) {
        if ($str -match $pattern) { $score += 2 }
    }
    
    # Check function-like patterns
    foreach ($pattern in $patterns.Functions) {
        if ($String -match $pattern) { $score += 5 }  # Increased
    }
    
    # URL bonus
    if ($String -match 'https?://') { $score += 4 }
    
    # Looks like API key/token (enhanced regex)
    if ($String -match '^[A-Za-z0-9_\-]{24,128}$') { $score += 3 }
    
    # Objective-C selector
    if ($String -match '^\w+:(\w+:)*$') { $score += 3 }
    
    # Path bonus
    if ($String -match '^/\w+(/\w+)*') { $score += 2 }
    
    # New: Length bonus (longer = better)
    if ($String.Length -gt 20) { $score += 1 }
    if ($String.Length -gt 50) { $score += 1 }
    
    # New: Noise penalty
    if ($String -match '^%[sd]$' -or $String -match '^\d+$') { $score -= 2 }
    
    # New: Multi-category boost
    $catCount = ($Categories | Where-Object { $str -match $intentPatterns[$_].High -or $str -match $intentPatterns[$_].Medium }).Count
    $score += $catCount
    
    # Dynamic min based on file size
    $dynamicMin = $Global:Config.MinStringRelevance + [Math]::Floor($FileSizeMB / 10)
    if ($score -lt $dynamicMin) { $score = 0 }
    
    return $score
}

# ---------------------------------------------------------------------------
# Helper to merge hashtables
# ---------------------------------------------------------------------------
function Merge-Hashtables {
    param([Parameter(ValueFromPipeline)]$Table)
    begin { $result = @{} }
    process { 
        foreach ($key in $Table.Keys) {
            $result[$key] = $Table[$key]
        }
    }
    end { return $result }
}

# ---------------------------------------------------------------------------
# Smart string extraction with relevance filtering (enhanced)
# ---------------------------------------------------------------------------
function Get-SmartStrings {
    param(
        [string]$FilePath,
        [int]$Intention,
        [string[]]$Categories,
        [int]$MaxStrings = 500
    )
    
    $fileInfo  = Get-Item $FilePath
    $fileSizeMB = $fileInfo.Length / 1MB
    
    Write-Status "Smart extraction from ${fileSizeMB:F1}MB file..." "Progress"
    
    # Use strings.exe if available
    $stringsExe = Get-Command strings.exe -ErrorAction SilentlyContinue
    $allStrings = @()
    
    if ($stringsExe) {
        try {
            $tempPath = Join-Path $env:TEMP "strings_temp_$($Global:UniqueId).txt"
            $proc = Start-Process -FilePath "strings.exe" -ArgumentList "-n 4 `"$FilePath`"" -NoNewWindow -RedirectStandardOutput $tempPath -PassThru
            if (-not $proc.WaitForExit(30000)) {
                $proc.Kill()
            }
            
            if (Test-Path $tempPath) {
                # Read in chunks and score as we go (enhanced chunking)
                $reader        = [System.IO.StreamReader]::new($tempPath)
                $scoredStrings = @{}
                $chunkSize     = 1000  # Process in batches
                
                $batch = New-Object System.Collections.Generic.List[string]
                while (-not $reader.EndOfStream) {
                    $raw = $reader.ReadLine()
                    if ([string]::IsNullOrWhiteSpace($raw)) { continue }
                    
                    $str = $raw.Trim()
                    if ($str.Length -lt 4 -or $str.Length -gt 500) { continue }
                    
                    $batch.Add($str)
                    if ($batch.Count -ge $chunkSize) {
                        foreach ($bstr in $batch | Select-Object -Unique) {  # Early dedupe
                            $score = Get-StringRelevance -String $bstr -Categories $Categories -Intention $Intention -FileSizeMB $fileSizeMB
                            if ($score -ge $Global:Config.MinStringRelevance) {
                                $scoredStrings[$bstr] = $score
                            }
                        }
                        $batch.Clear()
                        
                        # Trim to top N periodically
                        if ($scoredStrings.Count -gt ($MaxStrings * 2)) {
                            $scoredStrings = $scoredStrings.GetEnumerator() |
                                             Sort-Object Value -Descending |
                                             Select-Object -First $MaxStrings |
                                             ForEach-Object { @{$_.Key = $_.Value} } |
                                             Merge-Hashtables
                        }
                    }
                }
                # Process final batch
                foreach ($bstr in $batch | Select-Object -Unique) {
                    $score = Get-StringRelevance -String $bstr -Categories $Categories -Intention $Intention -FileSizeMB $fileSizeMB
                    if ($score -ge $Global:Config.MinStringRelevance) {
                        $scoredStrings[$bstr] = $score
                    }
                }
                $reader.Close()
                
                # Get top strings
                $allStrings = $scoredStrings.GetEnumerator() |
                              Sort-Object Value -Descending |
                              Select-Object -First $MaxStrings |
                              ForEach-Object { $_.Key } |
                              Select-Object -Unique
                
                Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Status "strings.exe failed, using fallback" "Warning"
        }
    }
    
    # Enhanced fallback: Multi-position sampling, UTF-8 + UTF-16LE
    if (-not $allStrings -or $allStrings.Count -eq 0) {
        $sampleSize = [Math]::Min(10MB, $fileInfo.Length / 5)  # Larger sample
        $strings    = New-Object System.Collections.Generic.HashSet[string]  # For dedupe
        
        try {
            $fs = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
            $buffer = New-Object byte[] 65536
            $positions = @(
                0,
                [int64]($fs.Length * 0.25),
                [int64]($fs.Length * 0.5),
                [int64]($fs.Length * 0.75),
                [int64]([Math]::Max(0, $fs.Length - $sampleSize))  # 5 positions
            )
            
            foreach ($pos in $positions) {
                $fs.Position = $pos
                $localRead = 0
                $currentUtf8 = New-Object System.Text.StringBuilder
                $currentUtf16 = New-Object System.Text.StringBuilder
                
                while ($localRead -lt $sampleSize -and $strings.Count -lt ($MaxStrings * 2)) {
                    $read = $fs.Read($buffer, 0, [Math]::Min($buffer.Length, $sampleSize - $localRead))
                    if ($read -le 0) { break }
                    
                    for ($i = 0; $i -lt $read; $i++) {
                        $b = $buffer[$i]
                        # UTF-8 ASCII
                        if ($b -ge 0x20 -and $b -le 0x7E) {
                            [void]$currentUtf8.Append([char]$b)
                        } else {
                            if ($currentUtf8.Length -ge 4) {
                                $str = $currentUtf8.ToString().Trim()
                                if ($str.Length -ge 4 -and $strings.Add($str)) {
                                    $score = Get-StringRelevance -String $str -Categories $Categories -Intention $Intention -FileSizeMB $fileSizeMB
                                    if ($score -ge $Global:Config.MinStringRelevance) {
                                        $allStrings += $str
                                    }
                                }
                            }
                            $currentUtf8.Clear()
                        }
                        
                        # UTF-16LE (every 2 bytes)
                        if ($i % 2 -eq 0 -and $i + 1 -lt $read) {
                            $w = [BitConverter]::ToChar($buffer, $i)
                            if ([int]$w -ge 0x20 -and [int]$w -le 0x7E) {
                                [void]$currentUtf16.Append($w)
                            } else {
                                if ($currentUtf16.Length -ge 4) {
                                    $str = $currentUtf16.ToString().Trim()
                                    if ($str.Length -ge 4 -and $strings.Add($str)) {
                                        $score = Get-StringRelevance -String $str -Categories $Categories -Intention $Intention -FileSizeMB $fileSizeMB
                                        if ($score -ge $Global:Config.MinStringRelevance) {
                                            $allStrings += $str
                                        }
                                    }
                                }
                                $currentUtf16.Clear()
                            }
                        }
                    }
                    $localRead += $read
                }
            }
            $fs.Close()
            
            # Sort and trim
            $scoredList = @{}
            foreach ($str in $allStrings | Select-Object -Unique) {
                $score = Get-StringRelevance -String $str -Categories $Categories -Intention $Intention -FileSizeMB $fileSizeMB
                $scoredList[$str] = $score
            }
            
            $allStrings = $scoredList.GetEnumerator() |
                          Sort-Object Value -Descending |
                          Select-Object -First $MaxStrings |
                          ForEach-Object { $_.Key }
        } catch {
            Write-Status "Extraction error: $_" "Warning"
        }
    }
    
    Write-Status "" "Progress"
    return $allStrings
}

# ---------------------------------------------------------------------------
# Analyze patterns with smart filtering (expanded)
# ---------------------------------------------------------------------------
function Get-PatternAnalysis {
    param(
        [string]$FilePath,
        [int]$Intention,
        [string[]]$Categories
    )
    
    $results = @{
        Auth        = @()
        License     = @()
        Security    = @()
        Network     = @()
        Crypto      = @()
        Storage     = @()  # New: Keychain, etc.
        UI          = @()  # New: Views, alerts
        URLs        = @()
        Interesting = @()
        ObjCClasses = @()  # New: Potential classes/methods
        TopStrings  = @()
    }
    
    $fileName = (Get-Item $FilePath).Name
    
    # Get smart-filtered strings
    $strings = Get-SmartStrings -FilePath $FilePath -Intention $Intention -Categories $Categories -MaxStrings $Global:Config.MaxStringsPerFile
    
    if (-not $strings -or $strings.Count -eq 0) {
        Write-Status "No relevant strings found" "Warning"
        return $results
    }
    
    Write-Status "Analyzing $($strings.Count) relevant strings..." "Info"
    
    # Store top strings
    $results.TopStrings = $strings | Select-Object -First 80  # Reduced
    
    # Store high-priority strings globally
    if (-not $Global:PriorityStrings.ContainsKey($fileName)) {
        $Global:PriorityStrings[$fileName] = @()
    }
    $Global:PriorityStrings[$fileName] = $strings | Select-Object -Unique | Select-Object -First 150  # Reduced
    
    # Expanded patterns with regex
    $patterns = @{
        Auth    = @("\blogin\b","\bsignin\b","\bpassword\b","\btoken\b","\bauth\b","\bsession\b","\bcredential\b","\boauth\b","\bjwt\b")
        License = @("\blicense\b","\bactivation\b","\btrial\b","\bpremium\b","\bexpire\b","\bsubscription\b","\bunlock\b","\bserial\b")
        Security= @("\bjailbreak\b","\bcydia\b","\bfrida\b","\bdebug\b","\broot\b","\bhook\b","\bbypass\b","\bdetect\b","\btamper\b")
        Network = @("http","https","\bapi\b","\bendpoint\b","\bhost\b","\bserver\b","\brequest\b","\bresponse\b")
        Crypto  = @("\bencrypt\b","\bdecrypt\b","\bhash\b","\baes\b","\brsa\b","\bkeychain\b","\bcipher\b","\bsalt\b")
        Storage = @("\bkeychain\b","\buserdefaults\b","\bnsuserdefaults\b","\bsecurestorage\b","\bdatabase\b","\bsqlite\b")  # New
        UI      = @("\buiviewcontroller\b","\balert\b","\bloginview\b","\bpremiumalert\b","\bactivationview\b")  # New
    }
    
    foreach ($category in $Categories + @("Storage", "UI")) {  # Include new
        if (-not $patterns.ContainsKey($category)) { continue }
        
        $matches = @{}
        foreach ($str in $strings) {
            foreach ($pattern in $patterns[$category]) {
                if ($str -imatch $pattern) {
                    if (-not $matches.ContainsKey($pattern)) {
                        $matches[$pattern] = [PSCustomObject]@{
                            Pattern = $pattern
                            Count   = 0
                            Samples = @()
                        }
                    }
                    $matches[$pattern].Count++
                    if ($matches[$pattern].Samples.Count -lt $Global:Config.MaxPatternSamples) {
                        $matches[$pattern].Samples += $str
                    }
                }
            }
        }
        
        if ($matches.Count -gt 0) {
            $results[$category] = $matches.Values | Sort-Object Count -Descending
        }
    }
    
    # Extract URLs (better regex)
    $urls = $strings | Where-Object { $_ -match 'https?://[\w\.\-/:?&=;%@#\[\]]{10,}' } | 
            ForEach-Object {
                $m = [regex]::Matches($_, 'https?://[\w\.\-/:?&=;%@#\[\]]+')
                $m | ForEach-Object { $_.Value }
            } |
            Select-Object -Unique -First $Global:Config.MaxURLs
    
    if ($urls) {
        $results.URLs = $urls
    }
    
    # Interesting strings (enhanced)
    $interesting = $strings | Where-Object {
        $_ -match '^[A-Za-z0-9_\-]{24,128}$' -or
        $_ -match '[Kk]ey.*[:=]' -or
        $_ -match '[Ss]ecret.*[:=]' -or
        $_ -match '[Tt]oken.*[:=]' -or
        $_ -match '^[A-F0-9]{40,128}$'
    } | Select-Object -Unique -First 15  # Reduced
    
    if ($interesting) {
        $results.Interesting = $interesting
    }
    
    # New: ObjC classes/methods
    $objc = $strings | Where-Object { $_ -match '^[A-Z]\w+$' -or $_ -match '^\w+:(\w+:)*$' } | Select-Object -Unique -First 20
    if ($objc) {
        $results.ObjCClasses = $objc
    }
    
    return $results
}

# ---------------------------------------------------------------------------
# Analyze Plist Files (New)
# ---------------------------------------------------------------------------
function Analyze-Plists {
    param([string]$AppPath)
    $results = @{
        Info = @{}
        Entitlements = @{}
    }
    
    $infoPlist = Join-Path $AppPath "Info.plist"
    if (Test-Path $infoPlist) {
        try {
            $content = [xml](Get-Content $infoPlist)
            $results.Info = @{
                BundleID = $content.plist.dict.key.Where({$_ -eq "CFBundleIdentifier"}) | Select-Object -Next 1 -ExpandProperty string
                Version = $content.plist.dict.key.Where({$_ -eq "CFBundleShortVersionString"}) | Select-Object -Next 1 -ExpandProperty string
                MinOS = $content.plist.dict.key.Where({$_ -eq "MinimumOSVersion"}) | Select-Object -Next 1 -ExpandProperty string
            }
        } catch {}
    }
    
    $entPlist = Get-ChildItem -Path $AppPath -Recurse -Filter "entitlements.plist" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($entPlist) {
        try {
            $content = [xml](Get-Content $entPlist.FullName)
            $results.Entitlements = $content.plist.dict.key | ForEach-Object {
                if ($_ -match "keychain|app-groups|push") { $_ }
            }
        } catch {}
    }
    
    return $results
}

# ---------------------------------------------------------------------------
# Save results based on output mode (enhanced report, null-safe)
# ---------------------------------------------------------------------------
function Save-Results {
    param(
        [string]$AppName,
        [hashtable]$Results,
        [int]$Intention
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $mode      = if ($Global:OutputMode -eq "Smart") { "AI" } else { "FULL" }
    $outputPath = Join-Path $Global:OutputDir "${AppName}_${mode}_${timestamp}.txt"
    $jsonPath = $outputPath -replace '.txt$', '.json'
    
    $output = @()
    $output += "=" * 80
    $output += "iOS RE SCAN RESULTS - $mode MODE (Advanced v2)"
    $output += "=" * 80
    $output += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $output += "App: $AppName"
    $output += "Mode: $mode ($(if($mode -eq 'AI'){'Optimized for AI analysis'}else{'Complete output'}))"
    $output += ""
    
    # Summary (enhanced)
    $output += "EXECUTIVE SUMMARY"
    $output += "-" * 40
    $output += "Main Binary: $(if($Results.MainBinary){"$($Results.MainBinary.Name) ($($Results.MainBinary.Size)MB)"}else{"Not found"})"
    $output += "Encryption: $(if($Results.MainBinary.Encrypted){"YES"}else{"NO"})"
    $output += "Suspicious Dylibs: $($Results.SuspiciousDylibs.Count)"
    $output += "Analysis Goal: $(switch($Intention){1{'Auth Bypass'}2{'License Crack'}3{'Security Analysis'}4{'Network/API'}5{'General'}})"
    $output += "Bundle ID: $($Results.Plists.Info.BundleID)"
    $output += "Version: $($Results.Plists.Info.Version)"
    $output += "Entitlements: $($Results.Plists.Entitlements -join ', ')"
    $output += ""
    
    # Suspicious Dylibs
    if ($Results.SuspiciousDylibs.Count -gt 0) {
        $output += "SUSPICIOUS DYLIBS"
        $output += "-" * 40
        foreach ($dylib in $Results.SuspiciousDylibs) {
            $output += "• $($dylib.Name) [Pattern: $($dylib.Pattern)]"
        }
        $output += ""
    }
    
    # String Analysis (with new categories, null-safe)
    if ($Results.StringAnalysis.Count -gt 0) {
        $output += "KEY FINDINGS BY FILE"
        $output += "=" * 40
        
        foreach ($analysis in $Results.StringAnalysis) {
            $output += ""
            $output += "FILE: $($analysis.File)"
            $output += "-" * 40
            
            $hasFindings = $false
            
            # Show pattern matches (include new)
            foreach ($category in @("Auth", "License", "Security", "Network", "Crypto", "Storage", "UI")) {
                if (-not $analysis.Patterns) { continue }
                if (-not ($analysis.Patterns -is [hashtable])) { continue }
                if (-not ($analysis.Patterns.ContainsKey($category))) { continue }
                
                $catData = $analysis.Patterns[$category]
                if (-not $catData -or $catData.Count -eq 0) { continue }
                
                $validPatterns = $catData | Where-Object { $_.Pattern -and $_.Count -gt 0 }
                if (-not $validPatterns) { continue }
                
                $hasFindings = $true
                $output += ""
                $output += "[$category Patterns] (Density: $($validPatterns.Count) patterns)"
                
                foreach ($pattern in $validPatterns | Select-Object -First 4) {
                    $output += "  '$($pattern.Pattern)': $($pattern.Count) matches"
                    foreach ($sample in $pattern.Samples | Select-Object -First 2) {
                        $output += "    → $sample"
                    }
                }
            }
            
            # URLs
            if ($analysis.Patterns -and $analysis.Patterns.URLs -and $analysis.Patterns.URLs.Count -gt 0) {
                $hasFindings = $true
                $output += ""
                $output += "[URLs Found]"
                foreach ($url in $analysis.Patterns.URLs | Select-Object -Unique -First 8) {
                    $output += "  • $url"
                }
            }
            
            # Interesting
            if ($analysis.Patterns -and $analysis.Patterns.Interesting -and $analysis.Patterns.Interesting.Count -gt 0) {
                $hasFindings = $true
                $output += ""
                $output += "[Potential Keys/Tokens]"
                foreach ($item in $analysis.Patterns.Interesting | Select-Object -Unique -First 4) {
                    $output += "  • $item"
                }
            }
            
            # ObjC
            if ($analysis.Patterns -and $analysis.Patterns.ObjCClasses -and $analysis.Patterns.ObjCClasses.Count -gt 0) {
                $hasFindings = $true
                $output += ""
                $output += "[ObjC Classes/Methods]"
                foreach ($item in $analysis.Patterns.ObjCClasses | Select-Object -Unique -First 10) {
                    $output += "  • $item"
                }
            }
            
            if (-not $hasFindings) {
                $output += "  (No relevant patterns found)"
            }
        }
        $output += ""
    }
    
    # Priority strings (smart mode) — now robust against non-string entries
    if ($Global:OutputMode -eq "Smart" -and $Global:PriorityStrings.Count -gt 0) {
        $output += ""
        $output += "HIGH-PRIORITY STRINGS FOR GHIDRA/IDA"
        $output += "=" * 40
        
        foreach ($file in $Global:PriorityStrings.Keys | Select-Object -First 4) {
            $uniqueStrings = $Global:PriorityStrings[$file] |
                             Where-Object {
                                 $s = $_.ToString()
                                 $sTrim = $s.Trim()
                                 $sTrim.Length -ge 4 -and $sTrim -match '[A-Za-z0-9]'
                             } |
                             ForEach-Object { $_.ToString() } |
                             Select-Object -Unique |
                             Sort-Object { $_.Length } -Descending
            
            if ($uniqueStrings.Count -eq 0) { continue }
            
            $output += ""
            $output += "[$file]"
            foreach ($str in $uniqueStrings | Select-Object -First 25) {
                $output += "  $str"
            }
        }
        $output += ""
    }
    
    # Analysis recommendations (prioritized)
    $output += ""
    $output += "REVERSE ENGINEERING GUIDE"
    $output += "=" * 40
    $output += ""
    $output += "Load these files in Ghidra/IDA (priority order):"
    
    $priority = 1
    if ($Results.MainBinary -and -not $Results.MainBinary.Encrypted) {
        $output += "$priority. $($Results.MainBinary.Name) - MAIN BINARY (unencrypted)"
        $priority++
    }
    
    foreach ($dylib in $Results.SuspiciousDylibs | Select-Object -First 3) {
        $output += "$priority. $($dylib.Name) - SUSPICIOUS DYLIB"
        $priority++
    }
    
    $output += ""
    $output += "Search for these patterns in disassembler:"
    
    $searchTerms = switch($Intention) {
        1 { @("loginWithEmail", "validatePassword", "isAuthenticated", "checkCredentials", "performLogin") }
        2 { @("validateLicense", "checkSubscription", "isPremium", "activateLicense", "trialExpired") }
        3 { @("isJailbroken", "debuggerAttached", "checkIntegrity", "detectFrida", "bypassDetection") }
        4 { @("sendRequest", "apiEndpoint", "baseURL", "fetchData", "networkRequest") }
        default { @("validate", "check", "verify", "authenticate", "isValid") }
    }
    
    foreach ($term in $searchTerms) {
        $output += "  • $term"
    }
    
    $output += ""
    $output += "Specific actions based on your goal (step-by-step):"
    
    $actions = switch($Intention) {
        1 {
            @(
                "1. Search for 'login' and 'auth' string references; trace xrefs",
                "2. Find authentication validation functions; set breakpoints",
                "3. Look for boolean returns from credential checks; patch to true",
                "4. Patch conditional jumps after auth checks",
                "5. Hook session/token generation functions with Frida"
            )
        }
        2 {
            @(
                "1. Search for 'license' and 'premium' references; analyze calls",
                "2. Find subscription validation functions; trace parameters",
                "3. Look for trial/expiration date checks; nop instructions",
                "4. Patch license verification returns to true",
                "5. Hook purchase validation callbacks"
            )
        }
        3 {
            @(
                "1. Search for 'jailbreak' detection functions; find implementations",
                "2. Find file system checks for Cydia; patch paths",
                "3. Look for debugger detection routines; bypass with anti-anti-debug",
                "4. Patch detection functions to return false",
                "5. Hook security check implementations"
            )
        }
        4 {
            @(
                "1. Search for API endpoint strings; collect all URLs",
                "2. Find network request functions; trace URLSession",
                "3. Set breakpoints on URL construction",
                "4. Monitor request/response handling with proxies",
                "5. Use Frida to intercept traffic"
            )
        }
        default {
            @(
                "1. Review all string references; prioritize high-score",
                "2. Identify key validation functions; analyze args",
                "3. Trace program flow from entry point",
                "4. Look for interesting comparisons/jumps",
                "5. Set breakpoints on suspicious calls"
            )
        }
    }
    
    foreach ($action in $actions) {
        $output += $action
    }
    
    $output += ""
    $output += "=" * 80
    $output += "END OF REPORT - $(if($mode -eq 'AI'){'OPTIMIZED FOR AI CONTEXT'}else{'COMPLETE OUTPUT'})"
    $output += "Total Lines: $($output.Count)"
    $output += "=" * 80
    
    # Save text
    $output | Out-File $outputPath -Encoding UTF8
    
    # JSON export if switched
    if ($JsonExport) {
        $Results | ConvertTo-Json -Depth 5 | Out-File $jsonPath -Encoding UTF8
        Write-Status "JSON exported to $jsonPath" "Success"
    }
    
    # Display
    $fileSize = [math]::Round((Get-Item $outputPath).Length / 1KB, 2)
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════" -ForegroundColor Green
    Write-Host " OUTPUT SAVED SUCCESSFULLY!" -ForegroundColor Green
    Write-Host " File: $outputPath" -ForegroundColor Yellow
    Write-Host " Size: ${fileSize}KB ($($output.Count) lines)" -ForegroundColor Cyan
    Write-Host " Mode: $mode" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════" -ForegroundColor Green
    
    return $outputPath
}

# ===========================================================================
# MAIN EXECUTION
# ===========================================================================
Show-Banner

# Get app path
if (-not $AppPath) {
    Write-Host "Enter path to .app folder: " -NoNewline -ForegroundColor Cyan
    $AppPath = Read-Host
    $AppPath = $AppPath.Trim('"')
}

if (-not (Test-Path $AppPath)) {
    Write-Status "Invalid path!" "Error"
    return
}

$AppName = [System.IO.Path]::GetFileName($AppPath) -replace '\.app$', ''
Set-Location $AppPath

Write-Status "Target App: $AppName" "Header"
Write-Status "Path: $AppPath" "Info"
Write-Host ""

# Ask for output mode
Write-Host "SELECT OUTPUT MODE:" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. [SMART] AI-Optimized (~3000 lines, <80KB)" -ForegroundColor Green
Write-Host "   • Perfect for ChatGPT/Claude/Copilot" -ForegroundColor Gray
Write-Host "   • Intelligent filtering based on your goal" -ForegroundColor Gray
Write-Host "   • Only most relevant strings included" -ForegroundColor Gray
Write-Host ""
Write-Host "2. [FULL] Complete Output (may be 100,000+ lines)" -ForegroundColor Yellow
Write-Host "   • Every single string extracted" -ForegroundColor Gray
Write-Host "   • No filtering applied" -ForegroundColor Gray
Write-Host "   • May exceed AI context limits" -ForegroundColor Gray
Write-Host ""
Write-Host "Choose mode (1 or 2): " -NoNewline -ForegroundColor Cyan
$modeChoice = Read-Host

if ($modeChoice -eq "2") {
    $Global:OutputMode = "Full"
    $Global:Config     = $Global:FullConfig
    Write-Status "Mode: FULL OUTPUT (no filtering)" "Warning"
} else {
    $Global:OutputMode = "Smart"
    $Global:Config     = $Global:SmartConfig
    Write-Status "Mode: AI-OPTIMIZED (smart filtering)" "Success"
}

Write-Host ""

# Ask for RE goal
Write-Host "What is your primary RE goal?" -ForegroundColor Cyan
Write-Host "1. Bypassing login/authentication"
Write-Host "2. Cracking/bypassing activation/license"  
Write-Host "3. Analyzing security features"
Write-Host "4. Finding hosts/URLs/API endpoints"
Write-Host "5. General analysis"
Write-Host "Enter number (1-5): " -NoNewline -ForegroundColor Cyan
$intention = Read-Host
if ($intention -notmatch '^[1-5]$') { $intention = 5 }

$selectedCategories = switch([int]$intention) {
    1 { @("Auth", "Network", "UI") }
    2 { @("License", "Crypto", "Storage") }
    3 { @("Security") }
    4 { @("Network") }
    default { @("Auth", "License", "Security", "Network", "Crypto", "Storage", "UI") }
}

Write-Status "Goal: $(switch([int]$intention){1{'Auth Bypass'}2{'License Crack'}3{'Security'}4{'Network/API'}5{'General'}})" "Info"
Write-Status "Categories: $($selectedCategories -join ', ')" "Info"

# Results container (added Plists)
$AnalysisResults = @{
    AppName              = $AppName
    MainBinary           = $null
    Dylibs               = @()
    SuspiciousDylibs     = @()
    Frameworks           = @()
    StringAnalysis       = @()
    Resources            = @()
    AnalysisOpportunities= @()
    Recommendations      = @()
    Plists               = Analyze-Plists -AppPath $AppPath  # New
}

# ---------------------------------------------------------------------------
# PHASE 1: BINARY ANALYSIS
# ---------------------------------------------------------------------------
Write-Status "BINARY ANALYSIS" "Header"

$mainBinary = Get-ChildItem -Path . -File |
              Where-Object { $_.Name -eq $AppName } |
              Select-Object -First 1

if ($mainBinary) {
    $size = [math]::Round($mainBinary.Length / 1MB, 2)
    $hash = Get-QuickHash $mainBinary.FullName
    
    Write-Status "Main Binary: $($mainBinary.Name) (${size}MB)" "Info"
    Write-Status "Hash: $hash" "Info"
    
    # Improved encryption check
    $encrypted = Get-MachOEncryptionStatus $mainBinary.FullName
    
    Write-Status "Encryption: $(if($encrypted){'YES'}else{'NO'})" $(if($encrypted){"Warning"}else{"Success"})
    
    $AnalysisResults.MainBinary = @{
        Name      = $mainBinary.Name
        Size      = $size
        Hash      = $hash
        Path      = ".\" + $mainBinary.FullName.Substring($AppPath.Length+1)
        Encrypted = $encrypted
    }
}

Write-Host ""

# ---------------------------------------------------------------------------
# PHASE 2: DYLIB ANALYSIS
# ---------------------------------------------------------------------------
Write-Status "DYLIB ANALYSIS" "Header"

$dylibs = @(Get-ChildItem -Path . -Recurse -Include "*.dylib" -File -ErrorAction SilentlyContinue)
Write-Status "Total dylibs: $($dylibs.Count)" "Info"

foreach ($dylib in $dylibs) {
    $rel = ".\" + $dylib.FullName.Substring($AppPath.Length+1)
    $dylibInfo = @{
        Name = $dylib.Name
        Size = $dylib.Length
        Path = $rel
    }
    $AnalysisResults.Dylibs += $dylibInfo
    
    $pattern = Test-SuspiciousDylib $dylib.Name
    if ($pattern) {
        Write-Status "SUSPICIOUS: $($dylib.Name) [$pattern]" "Warning"
        $dylibInfo.Pattern = $pattern
        $AnalysisResults.SuspiciousDylibs += $dylibInfo
    }
}

# Frameworks
$frameworkDirs = @(Get-ChildItem -Path "Frameworks" -Directory -ErrorAction SilentlyContinue)
foreach ($fw in $frameworkDirs | Select-Object -First 5) {
    $fwBinary = Get-ChildItem $fw.FullName -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -eq "" -and $_.Length -gt 1MB } |
                Select-Object -First 1
    
    if ($fwBinary) {
        $AnalysisResults.Frameworks += @{
            Name = $fw.Name
            Size = [math]::Round($fwBinary.Length / 1MB, 2)
            Path = ".\" + $fw.FullName.Substring($AppPath.Length+1)
        }
    }
}

Write-Host ""

# ---------------------------------------------------------------------------
# PHASE 3: STRING ANALYSIS (sequential, robust)
# ---------------------------------------------------------------------------
if (-not $QuickScan) {
    Write-Status "STRING EXTRACTION ($Global:OutputMode mode)" "Header"
    
    $scanTargets = @()
    
    if ($mainBinary) {
        $scanTargets += $mainBinary.FullName
    }
    
    foreach ($susp in $AnalysisResults.SuspiciousDylibs | Select-Object -First 3) {
        $path = Get-ChildItem -Path . -Recurse -Filter $susp.Name -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($path) { $scanTargets += $path.FullName }
    }
    
    $maxFiles = if ($Global:OutputMode -eq "Smart") { 5 } else { 10 }
    $binaries = Get-ChildItem -Path . -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.Length -gt 100KB -and $_.Length -lt 75MB -and 
                    ($_.Extension -eq "" -or $_.Extension -eq ".dylib" -or $_.Name -match "\.framework")
                } |
                Sort-Object Length -Descending |
                Select-Object -First $maxFiles
    
    foreach ($bin in $binaries) {
        if ($scanTargets -notcontains $bin.FullName) {
            $scanTargets += $bin.FullName
        }
    }
    
    $scanTargets = $scanTargets | Select-Object -Unique -First $maxFiles
    Write-Status "Files to scan: $($scanTargets.Count)" "Info"
    Write-Host ""
    
    # Sequential scanning (stable in main runspace)
    $scanCount = 0

    foreach ($target in $scanTargets) {
        $scanCount++

        # Run analysis in the same runspace so all functions / globals are available
        $patterns = Get-PatternAnalysis -FilePath $target -Intention ([int]$intention) -Categories $selectedCategories

        $result = @{
            File     = (Get-Item $target).Name
            Path     = $target
            Patterns = $patterns
        }

        # Safely count how many items we found for logging
        $foundCount = 0
        if ($result.Patterns) {
            foreach ($cat in $selectedCategories) {
                if ($result.Patterns -is [hashtable] -and $result.Patterns.ContainsKey($cat) -and $result.Patterns[$cat]) {
                    $foundCount += ($result.Patterns[$cat] | Measure-Object -Property Count -Sum).Sum
                }
            }

            if ($result.Patterns.URLs) {
                $foundCount += $result.Patterns.URLs.Count
            }
            if ($result.Patterns.Interesting) {
                $foundCount += $result.Patterns.Interesting.Count
            }
        }

        Write-Status "[${scanCount}/${scanTargets.Count}] $($result.File) - Found $foundCount items" "Info"
        $AnalysisResults.StringAnalysis += $result
    }
}

Write-Host ""

# ---------------------------------------------------------------------------
# PHASE 4: SAVE RESULTS
# ---------------------------------------------------------------------------
Write-Status "GENERATING REPORT" "Header"

$outputFile = Save-Results -AppName $AppName -Results $AnalysisResults -Intention ([int]$intention)

Write-Host ""
Write-Host " NEXT STEPS:" -ForegroundColor Yellow
Write-Host " 1. Open: $outputFile" -ForegroundColor White
Write-Host " 2. Copy ALL contents to AI assistant" -ForegroundColor White
Write-Host " 3. Ask: 'Guide me through reversing this iOS app'" -ForegroundColor White
Write-Host ""
Write-Host "═══════════════════════════════════════════════" -ForegroundColor Cyan

Write-Host "`nHappy Reversing! 🔓" -ForegroundColor Green

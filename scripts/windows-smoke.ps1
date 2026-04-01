$ErrorActionPreference = "Stop"

$networkHeader = "COMMAND                     PID PROTO LOCAL_ADDRESS                  FOREIGN_ADDRESS                STATE"
$fileHeader = "COMMAND                     PID PROCESS_PATH"

function Assert-Contains {
    param(
        [Parameter(Mandatory = $true)] [string]$Output,
        [Parameter(Mandatory = $true)] [string]$Needle,
        [Parameter(Mandatory = $true)] [string]$Context
    )

    if ($Output -notmatch [regex]::Escape($Needle)) {
        throw "Expected '$Needle' in $Context. Output:`n$Output"
    }
}

function Assert-NotContains {
    param(
        [Parameter(Mandatory = $true)] [string]$Output,
        [Parameter(Mandatory = $true)] [string]$Needle,
        [Parameter(Mandatory = $true)] [string]$Context
    )

    if ($Output -match [regex]::Escape($Needle)) {
        throw "Did not expect '$Needle' in $Context. Output:`n$Output"
    }
}

function Assert-ExactFirstLine {
    param(
        [Parameter(Mandatory = $true)] [string]$Output,
        [Parameter(Mandatory = $true)] [string]$Expected,
        [Parameter(Mandatory = $true)] [string]$Context
    )

    $firstLine = ($Output -split "`r?`n")[0]
    if ($firstLine -ne $Expected) {
        throw "Expected first line '$Expected' in $Context. Actual:`n$Output"
    }
}

function Assert-AllDataLinesContain {
    param(
        [Parameter(Mandatory = $true)] [string]$Output,
        [Parameter(Mandatory = $true)] [string]$Needle,
        [Parameter(Mandatory = $true)] [string]$Context
    )

    $lines = ($Output -split "`r?`n") | Where-Object { $_ -ne "" }
    if ($lines.Count -lt 2) {
        throw "Expected at least one data line in $Context. Output:`n$Output"
    }

    foreach ($line in $lines[1..($lines.Count - 1)]) {
        if ($line -notmatch [regex]::Escape($Needle)) {
            throw "Expected '$Needle' in every data line for $Context. Bad line:`n$line`nFull output:`n$Output"
        }
    }
}

function Invoke-Lsof {
    param(
        [Parameter(Mandatory = $true)] [string]$Exe,
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [string[]]$Args,
        [Parameter(Mandatory = $true)] [string]$Context
    )

    $output = (& $Exe @Args | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw "lsof exited with code $LASTEXITCODE for $Context. Output:`n$output"
    }
    return $output
}

function Invoke-LsofExpectFailure {
    param(
        [Parameter(Mandatory = $true)] [string]$Exe,
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [string[]]$Args,
        [Parameter(Mandatory = $true)] [string]$Context
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.Arguments = (($Args | ForEach-Object { '"' + $_.Replace('"', '\"') + '"' }) -join ' ')

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    [void]$process.Start()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()

    $output = "$stdout$stderr"
    if ($process.ExitCode -eq 0) {
        throw "Expected lsof to fail for $Context. Output:`n$output"
    }
    return $output
}

function Invoke-LsofUntilMatch {
    param(
        [Parameter(Mandatory = $true)] [string]$Exe,
        [Parameter(Mandatory = $true)] [string[]]$Args,
        [Parameter(Mandatory = $true)] [string]$Needle,
        [Parameter(Mandatory = $true)] [string]$Context
    )

    for ($attempt = 1; $attempt -le 20; $attempt++) {
        $output = Invoke-Lsof -Exe $Exe -Args $Args -Context $Context
        if ($output -match [regex]::Escape($Needle)) {
            return $output
        }

        Start-Sleep -Milliseconds 250
    }

    throw "Timed out waiting for '$Needle' in $Context"
}

cargo build --release --locked

$exe = Join-Path $PWD "target/release/lsof.exe"
if (-not (Test-Path $exe)) {
    throw "Expected built binary at $exe"
}

$helpText = (& $exe -h | Out-String)
if ($LASTEXITCODE -ne 0) {
    throw "lsof -h failed"
}
Assert-Contains -Output $helpText -Needle "usage: lsof" -Context "help output"

$defaultOutput = Invoke-Lsof -Exe $exe -Args @() -Context "default listing"
Assert-ExactFirstLine -Output $defaultOutput -Expected $networkHeader -Context "default listing"

$tcpListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$tcpListener.Start()
$tcpPort = ([System.Net.IPEndPoint]$tcpListener.LocalEndpoint).Port

try {
    $tcpOutput = Invoke-LsofUntilMatch -Exe $exe -Args @("-i", "tcp:$tcpPort") -Needle ":$tcpPort" -Context "tcp socket listing"
    Assert-ExactFirstLine -Output $tcpOutput -Expected $networkHeader -Context "tcp socket listing"
    Assert-Contains -Output $tcpOutput -Needle "TCP" -Context "tcp socket listing"
    Assert-NotContains -Output $tcpOutput -Needle "UDP" -Context "tcp socket listing"

    $tcpHostOutput = Invoke-LsofUntilMatch -Exe $exe -Args @("-i", "tcp@127.0.0.1:$tcpPort") -Needle ":$tcpPort" -Context "tcp host filter"
    Assert-ExactFirstLine -Output $tcpHostOutput -Expected $networkHeader -Context "tcp host filter"
    Assert-Contains -Output $tcpHostOutput -Needle "127.0.0.1" -Context "tcp host filter"

    $pidFilteredOutput = Invoke-LsofUntilMatch -Exe $exe -Args @("-p", "$PID", "-i", "tcp:$tcpPort") -Needle ":$tcpPort" -Context "pid filtered tcp listing"
    Assert-ExactFirstLine -Output $pidFilteredOutput -Expected $networkHeader -Context "pid filtered tcp listing"
    Assert-AllDataLinesContain -Output $pidFilteredOutput -Needle (" {0,6} " -f $PID).Trim() -Context "pid filtered tcp listing"

    $terseOutput = Invoke-LsofUntilMatch -Exe $exe -Args @("-t", "-p", "$PID", "-i", "tcp:$tcpPort") -Needle "$PID" -Context "terse pid listing"
    Assert-Contains -Output $terseOutput -Needle "$PID" -Context "terse pid listing"
}
finally {
    $tcpListener.Stop()
}

$udpClient = [System.Net.Sockets.UdpClient]::new([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, 0))
$udpPort = ([System.Net.IPEndPoint]$udpClient.Client.LocalEndPoint).Port

try {
    $udpOutput = Invoke-LsofUntilMatch -Exe $exe -Args @("-i", "udp:$udpPort") -Needle ":$udpPort" -Context "udp socket listing"
    Assert-ExactFirstLine -Output $udpOutput -Expected $networkHeader -Context "udp socket listing"
    Assert-Contains -Output $udpOutput -Needle "UDP" -Context "udp socket listing"
    Assert-NotContains -Output $udpOutput -Needle "TCP" -Context "udp socket listing"

    $udpHostOutput = Invoke-LsofUntilMatch -Exe $exe -Args @("-i", "udp@127.0.0.1:$udpPort") -Needle ":$udpPort" -Context "udp host filter"
    Assert-ExactFirstLine -Output $udpHostOutput -Expected $networkHeader -Context "udp host filter"
    Assert-Contains -Output $udpHostOutput -Needle "127.0.0.1" -Context "udp host filter"
}
finally {
    $udpClient.Dispose()
}

$tempFile = Join-Path $env:TEMP "lsof-smoke.lock"
$unusedFile = Join-Path $env:TEMP "lsof-smoke-unused.lock"
$missingFile = Join-Path $env:TEMP "lsof-smoke-missing.lock"
$stream = [System.IO.File]::Open($tempFile, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)

try {
    $fileOutput = Invoke-LsofUntilMatch -Exe $exe -Args @("file", $tempFile) -Needle "$PID" -Context "file ownership listing"
    Assert-ExactFirstLine -Output $fileOutput -Expected $fileHeader -Context "file ownership listing"
    Assert-Contains -Output $fileOutput -Needle "$PID" -Context "file ownership listing"

    Set-Content -Path $unusedFile -Value "unused" -NoNewline
    $unusedOutput = Invoke-Lsof -Exe $exe -Args @("file", $unusedFile) -Context "unused file ownership listing"
    Assert-ExactFirstLine -Output $unusedOutput -Expected $fileHeader -Context "unused file ownership listing"
    $unusedLines = ($unusedOutput -split "`r?`n") | Where-Object { $_ -ne "" }
    if ($unusedLines.Count -ne 1) {
        throw "Expected header-only output for unused file ownership listing. Output:`n$unusedOutput"
    }

    $missingOutput = Invoke-LsofExpectFailure -Exe $exe -Args @("file", $missingFile) -Context "missing file ownership listing"
    Assert-Contains -Output $missingOutput -Needle "failed to resolve file path" -Context "missing file ownership listing"
}
finally {
    $stream.Dispose()
    Remove-Item $tempFile -ErrorAction SilentlyContinue
    Remove-Item $unusedFile -ErrorAction SilentlyContinue
}

Write-Host "Windows smoke checks passed"

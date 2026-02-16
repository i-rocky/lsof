$ErrorActionPreference = "Stop"

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

function Invoke-LsofUntilMatch {
    param(
        [Parameter(Mandatory = $true)] [string]$Exe,
        [Parameter(Mandatory = $true)] [string[]]$Args,
        [Parameter(Mandatory = $true)] [string]$Needle,
        [Parameter(Mandatory = $true)] [string]$Context
    )

    for ($attempt = 1; $attempt -le 20; $attempt++) {
        $output = (& $Exe @Args | Out-String)
        if ($LASTEXITCODE -ne 0) {
            throw "lsof exited with code $LASTEXITCODE for $Context. Output:`n$output"
        }

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

$tcpListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$tcpListener.Start()
$tcpPort = ([System.Net.IPEndPoint]$tcpListener.LocalEndpoint).Port

try {
    $tcpOutput = Invoke-LsofUntilMatch -Exe $exe -Args @("-i", "tcp:$tcpPort") -Needle ":$tcpPort" -Context "tcp socket listing"
    Assert-Contains -Output $tcpOutput -Needle "TCP" -Context "tcp socket listing"

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
    Assert-Contains -Output $udpOutput -Needle "UDP" -Context "udp socket listing"
}
finally {
    $udpClient.Dispose()
}

Write-Host "Windows smoke checks passed"

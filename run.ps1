[CmdletBinding()]
param(
    [ValidateRange(1, 65535)]
    [int]$Port = 8765,

    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = (Get-Command python -ErrorAction Stop).Source
$appArgs = @(
    (Join-Path $scriptRoot 'app.py'),
    '--port',
    $Port
)

if ($NoBrowser) {
    $appArgs += '--no-browser'
}

& $python @appArgs

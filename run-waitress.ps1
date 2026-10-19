<#
Starts the application with Waitress from this project's directory.

This prevents Python's "No module named 'app'" error when the script is
launched from another working directory.
#>
param(
    [int]$Port = 8080,
    [string]$UrlScheme = "http"
)

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$waitress = Join-Path $projectRoot ".venv\Scripts\waitress-serve.exe"

if (-not (Test-Path -LiteralPath $waitress)) {
    throw "Waitress was not found in .venv. Run: .venv\\Scripts\\python.exe -m pip install -r requirements.txt"
}

Push-Location $projectRoot
try {
    & $waitress "--url-scheme=$UrlScheme" "--listen=*:$Port" "wsgi:application"
}
finally {
    Pop-Location
}

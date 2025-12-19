# scan-all.ps1 powershell -ExecutionPolicy Bypass -File .\scan-all.ps1
$scanFolder = ".\Scan"

Get-ChildItem -Path $scanFolder\*.tar | ForEach-Object {
    $relativePath = "$scanFolder\" + $_.Name
    $reportName = $_.BaseName + ".json"
    
    Write-Host "Scanning: $($_.Name)" -ForegroundColor Cyan
    .\trivy.exe image --input $relativePath --format json | Set-Content -Encoding UTF8 $reportName
    Write-Host "  -> $reportName" -ForegroundColor Green
}
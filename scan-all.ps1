Get-ChildItem -Path .\Scan\*.tar | ForEach-Object {
    Write-Host "Scanning: $($_.Name)" -ForegroundColor Cyan
    $reportName = $_.BaseName + ".json"
    .\trivy.exe image --input $_.FullName --format json | Set-Content -Encoding UTF8 $reportName
    Write-Host "  -> $reportName" -ForegroundColor Green
}
Write-Host "`nAll done!" -ForegroundColor Cyan
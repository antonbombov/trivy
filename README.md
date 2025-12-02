## Команда для генерации отчета с кастомным шаблоном
```powershell
.\trivy.exe image --input .\Scan\alpine.tar --format template --template "@html_original.tpl" > report.html
```

## Генерация отчета с версией сканера (powershell)
### 1. Получаем версию сканера
```powershell
$TrivyVersion = .\trivy.exe -v | Select-String -Pattern "Version:\s+([\d.]+)" | ForEach-Object { $_.Matches.Groups[1].Value }
```
### 2. Генерим отчет по шаблону + добавляем $TrivyVersion 
```powershell
.\trivy.exe image --input .\Scan\hydra_release-1.0.0.tar --format template --template "@.\html_original.tpl" | ForEach-Object { $_ -replace "<!-- TRIVY_VERSION -->", "| Version: $TrivyVersion" } | Out-File "report.html" -Encoding UTF8
```

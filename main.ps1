Import-Module "D:\Lexicon\ittek18a\lektion\functions.ps1" -Force

Connect-Services
Write-Host("`n----Aktiva användare ----")
Get-MsolUser -all
Start-Sleep -Seconds 10

Create-User -CsvPath D:\Lexicon\ittek18a\lektion\users.csv -Delimiter ";"
Start-Sleep -Seconds 10

Write-Host("`n----Aktiva användare ----")
Get-MsolUser -all
Start-Sleep -Seconds 10

Delete-User -DeleteAll $true -RemoveRecycleBin $true
Start-Sleep -Seconds 10

Write-Host("`n----Aktiva användare ----")
Get-MsolUser -all

Start-Sleep -Seconds 10

Write-Host("`n----Papperskorgen ----")
Get-MsolUser -ReturnDeletedUsers

Disconnect-Services

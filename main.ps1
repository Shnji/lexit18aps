Import-Module "https://github.com/datanorden-hans/lexit18aps/blob/master/functions.ps1" -Force

Connect-Services
Write-Host("`n----Aktiva användare ----")
Get-MsolUser -all
Start-Sleep -Seconds 10

Create-User -CsvPath "https://github.com/datanorden-hans/lexit18aps/blob/master/users.csv" -Delimiter ";"
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

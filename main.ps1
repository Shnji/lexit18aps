#Module imports
Import-Module "D:\Lexicon\ittek18a\lektion\functions.ps1" -Force

Connect-Services
Delete-User -DeleteAll $true -RemoveRecycleBin $true
Delete-Group -DeleteAll $true

Create-User -CsvPath "D:\Lexicon\ittek18a\lektion\users.csv" -Delimiter ";"
Disconnect-Services

Start-Sleep -Seconds 20
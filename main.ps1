cls
Import-Module "D:\Lexicon\ittek18a\lektion\functions.ps1" -Force

#Connect-Services

Create-User -CsvPath "D:\Lexicon\ittek18a\lektion\users.csv" -Delimiter ";"

Delete-User -DeleteAll $true -RemoveRecycleBin $true

#Disconnect-Services

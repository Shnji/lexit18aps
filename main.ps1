cls

#Module imports
Import-Module "D:\Lexicon\ittek18a\lektion\functions.ps1" -Force

#Connect-Services
#Delete-User -DeleteAll $true -RemoveRecycleBin $true
#Delete-Group -DeleteAll $true
#Create-User -CsvPath "D:\Lexicon\ittek18a\lektion\users.csv" -Delimiter ";"
#Create-Contact
#Create-RetentionPolicy

for($i = 0; $i -lt 20; $i++)
{
    Create-SharedMailbox -EmailAddress sharedmail$i@starstruckrr.se -EmailDisplayName "Shared Mail $i"
}

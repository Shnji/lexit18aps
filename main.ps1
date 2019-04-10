cls

#Module imports
Import-Module "D:\Lexicon\ittek18a\lektion\functions.ps1" -Force

#Connecting to Online Services
#Connect-Services

#Create-SharedMailbox -EmailAddress "info@starstruckrr.se" -EmailDisplayName "Startstruckrr"
#Create-SharedMailbox -EmailAddress "support@starstruckrr.se" -EmailDisplayName "Support - Starstruckrr"
#Create-SharedMailbox -EmailAddress "abuse@starstruckrr.se" -EmailDisplayName "Abuse"
#Create-SharedMailbox -EmailAddress "sales@starstruckrr.se" -EmailDisplayName "Försäljning - Starstruckrr" 
#Create-SharedMailbox -EmailAddress "invoice@starstruckrr.se" -EmailDisplayName "Fakturering - Starstruckrr"



#Delete-User -DeleteAll $true -RemoveRecycleBin $true
#Delete-Group -DeleteAll $true -RemoveRecycleBin $true
Create-User -CsvPath D:\Lexicon\ittek18a\lektion\users.csv -Delimiter ";" -StandardPassword "BytMig123" -UsageLocation SE


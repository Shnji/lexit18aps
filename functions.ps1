function Connect-Services() 
{
    cls

    Write-Host("----- Connecting to Online Services -----")

    try 
    {
        # 1 Get User Credentials
        if($Cred_GlobalAdmin -eq $null) 
        {
            $Global:Cred_GlobalAdmin = (Get-Credential -Message "Enter your Global Admin Credentials")
        }

        # 2. Installing Modules
        try
        {
            Write-Host("- Installing modules for Azure AD, MSOnline and SharePoint Online") -NoNewline     
            #Install-Module MSOnline -ErrorAction stop -WarningAction SilentlyContinue -Force
            #Install-Module Microsoft.Online.SharePoint.Powershell -ErrorAction Stop -WarningAction SilentlyContinue -Force
            #Install-Module AzureAD -ErrorAction Stop -WarningAction SilentlyContinue -Force
            Write-Host(" - Completed") -ForegroundColor Green
        }
        catch 
        {
            Write-Host(" - Failed") -ForegroundColor Red
            Write-Host("ERROR: ") -NoNewline -ForegroundColor Red
            write-Host($_.Exception.Message)
        }
        finally
        {
            Write-Host("`n")
        }    
           
        # 3. Connecting to Online Services
        try
        {
            # 3.1 Office 365 - MSOnline
            try
            {
                Write-Host("- Connecting to Microsoft Online Services") -NoNewline  
                Connect-MsolService -Credential $Cred_GlobalAdmin -ErrorAction Stop
                $Global:TenantName = ((Get-MsolAccountSku).AccountSkuId).split(":")[0]
                Write-Host(" - Completed") -ForegroundColor Green
            }
            catch
            {
                Write-Host(" - Failed") -ForegroundColor Red
            }    

            # 3.2 Exchange Online
            try
            {
                Write-Host("- Connecting to Exchange Online") -NoNewline                
                $Global:EXCH =  New-PSSession -Credential $Cred_GlobalAdmin -ConfigurationName Microsoft.Exchange -Authentication Basic `
                                -ConnectionUri https://outlook.office365.com/powershell-liveid/ -AllowRedirection -ErrorAction Stop
                
                Import-PSSession $EXCH -AllowClobber -DisableNameChecking | Out-Null
                Write-Host(" - Completed") -ForegroundColor Green
            }
            catch
            {
                Write-Host(" - Failed") -ForegroundColor Red
            } 

            # 3.3 SharePoint Online
            try
            {
                Write-Host("- Connecting to SharePoint Online") -NoNewline  
                Connect-SPOService -Credential $Cred_GlobalAdmin -Url "https://$TenantName-admin.sharepoint.com" -ErrorAction stop
                Write-Host(" - Completed") -ForegroundColor Green
            }
            catch
            {
                Write-Host(" - Failed") -ForegroundColor Red
            }         
        }
        catch
        {
            Write-Host("Something went wrong when connecting to online services.")
        }
    }
    catch
    {
        Write-Host("Something went wrong when connecting to online services.")
        #Skriv ut felmeddelandet till en log-fil
    }
    finally
    {
        Write-Host("`n")
    }
}
function Disconnect-Services()
{
    Write-Host("----- Disconnecting from Online Services -----")

    try
    {
        # 1. Disconnecting from Online Services
        try
        {
            # 1.1 Remove Variables
            if(Get-Variable Cred_GlobalAdmin) 
            {
                Remove-Variable Cred_GlobalAdmin -Scope "Global"
            }

            if(Get-Variable TenantName) 
            {
                Remove-Variable TenantName -Scope "Global"
            }

            # 1.2 Office 365 - MSOnline
            try
            {
                Write-Host("- Disconnecting from Microsoft Online Services") -NoNewline 
                
                $fakeusername = "fake"
                $fakepassword = ConvertTo-SecureString "fake" -AsPlainText -Force
                $fakeuser = New-Object -TypeName pscredential -ArgumentList $fakeusername,$fakepassword   
                
                Connect-MsolService -Credential $fakeuser -ErrorAction SilentlyContinue -WarningAction SilentlyContinue                 
                Write-Host(" - Completed") -ForegroundColor Green
            }
            catch
            {
                Write-Host(" - Failed") -ForegroundColor Red
            }    

            # 2.3 Exchange Online
            try
            {
                Write-Host("- Disconnecting from Exchange Online") -NoNewline   
                Remove-PSSession $EXCH -ErrorAction Stop -WarningAction SilentlyContinue             
                Write-Host(" - Completed") -ForegroundColor Green
            }
            catch
            {
                Write-Host(" - Failed") -ForegroundColor Red
            } 

            # 2.4 SharePoint Online
            try
            {
                Write-Host("- Disconnecting from SharePoint Online") -NoNewline  
                Disconnect-SPOService -ErrorAction Stop -WarningAction SilentlyContinue
                Write-Host(" - Completed") -ForegroundColor Green
            }
            catch
            {
                Write-Host(" - Failed") -ForegroundColor Red
            } 
        }
        catch
        {
            Write-Host("Something went wrong when disconnecting from online services.")
            #Skriv ut felmeddelandet till en log-fil
        }       
    }
    catch
    {
        Write-Host("Something went wrong when disconnecting from online services.")
        #Skriv ut felmeddelandet till en log-fil
    }
    finally
    {
        Write-Host("`n")
    }
}

function Create-User($CsvPath, $Delimiter = ",", $StandardPassword = "BytMig123", $UsageLocation = "SE", $DomainName)
{
    Write-Host("----- Creating new Office 365 User -----")

    try
    {   
       if($DomainName -eq $null) 
       {
           $DomainName = (Get-MsolDomain | where { $_.IsDefault -eq $true }).Name
       }
        
       if($CsvPath -ne $null)
       {
            $ListOfUsers = Import-Csv -Path $CsvPath -Delimiter $Delimiter -Encoding UTF8

            foreach($user in $ListOfUsers)
            {
                $FirstName     = $user.Förnamn
                $LastName      = $user.Efternamn
                $PersonalEmail = $user.'E-postadress'
                $Department    = $user.Avdelning
                $JobTitle      = $user.Jobbtitel                
                $Phone         = $user.Telefonnummer
                $Mobile        = $user.Mobilnummer
                $PostalAddress = $user.Postadress
                $PostalCode    = $user.Postnummer
                $City          = $user.Ort
                $Country       = $user.Land
                
                $DisplayName       = "$FirstName $LastName"
                $UserPrincipalName = ("$Firstname.$Lastname@$DomainName".ToLower()).Normalize("formkd") -replace("\p{M}")

                try
                {
                    # Om det inte finns en användare, skapa användaren (! = inte)
                    if(!(Get-MsolUser -UserPrincipalName $UserPrincipalName -ErrorAction SilentlyContinue))
                    {
                        try 
                        {
                            Write-Host("- Creating user $DisplayName - $UserPrincipalName") -NoNewline   
                        
                            $u = New-MsolUser `
                                -UserPrincipalName $UserPrincipalName `
                                -DisplayName $DisplayName `
                                -FirstName $FirstName `
                                -LastName $LastName `
                                -Department $Department `
                                -Title $JobTitle `
                                -PhoneNumber $Phone `
                                -MobilePhone $Mobile `
                                -StreetAddress $PostalAddress `
                                -PostalCode $PostalCode `
                                -City $City `
                                -Country $Country `
                                -AlternateEmailAddresses $PersonalEmail `
                                -PasswordNeverExpires $true `
                                -Password $StandardPassword `
                                -StrongPasswordRequired $true `
                                -ForceChangePassword $true `
                                -UsageLocation $UsageLocation `
                                -ErrorAction Stop
                        
                            Write-Host(" - Completed") -ForegroundColor Green
                        }
                        catch
                        {
                            Write-Host(" - Failed") -ForegroundColor Red
                        }                                               
                    }
                    else
                    {
                        Write-Host("- Duplicate: ") -NoNewline -ForegroundColor Yellow
                        Write-Host("User with UserPrincipalName '$UserPrincipalName' already exits.")
                    }
                }
                catch
                {

                }
                finally
                {
                    Remove-Variable u -ErrorAction SilentlyContinue
                    Remove-Variable FirstName -ErrorAction SilentlyContinue
                    Remove-Variable LastName -ErrorAction SilentlyContinue
                    Remove-Variable PersonalEmail -ErrorAction SilentlyContinue
                    Remove-Variable Department -ErrorAction SilentlyContinue
                    Remove-Variable JobTitle -ErrorAction SilentlyContinue              
                    Remove-Variable Phone -ErrorAction SilentlyContinue
                    Remove-Variable Mobile -ErrorAction SilentlyContinue
                    Remove-Variable PostalAddress -ErrorAction SilentlyContinue
                    Remove-Variable PostalCode -ErrorAction SilentlyContinue
                    Remove-Variable City -ErrorAction SilentlyContinue
                    Remove-Variable Country -ErrorAction SilentlyContinue
                    Remove-Variable DisplayName -ErrorAction SilentlyContinue
                    Remove-Variable UserPrincipalName -ErrorAction SilentlyContinue
                }             
            }
       } 
    }
    catch
    {
        Write-Host("Something went wrong when creating new user.")
        #Skriv ut felmeddelandet till en log-fil
    }
    finally
    {
        Remove-Variable CsvPath -ErrorAction SilentlyContinue
        Remove-Variable Delimiter -ErrorAction SilentlyContinue
        Remove-Variable StandardPassword -ErrorAction SilentlyContinue 
        Remove-Variable UsageLocation -ErrorAction SilentlyContinue 
        Remove-Variable DomainName -ErrorAction SilentlyContinue
        Remove-Variable user -ErrorAction SilentlyContinue
        Remove-Variable ListOfUsers -ErrorAction SilentlyContinue
        
        Write-Host("`n")
    }
}

function Delete-User($DeleteAll = $false, $RemoveRecycleBin = $false)
{
    Write-Host("----- Delete Office 365 User -----")

    try
    {
        # Delete Office 365 User
        try
        {
            if($DeleteAll) 
            {
                try
                {
                    Write-Host("- Deleting all Office 365 users, except 'Company Administrators'") -NoNewline   

                    Get-MsolUser -All | where { -not (Get-MsolUserRole -ObjectId $_.ObjectId | where { $_.Name -eq "Company Administrator" }) } |
                    foreach { Remove-MsolUser -ObjectId $_.ObjectId -Force }
                
                    Write-Host(" - Completed") -ForegroundColor Green
                }
                catch 
                {
                    Write-Host(" - Failed") -ForegroundColor Red
                }
                finally
                {
                    Write-Host("`n")
                }
            }

            if($RemoveRecycleBin)
            {
                Delete-FromRecycleBin
            }
        }
        catch
        {
            Write-Host("Something went wrong when deleting user.")
            #Skriv ut felmeddelandet till en log-fil
        }       
    }
    catch
    {
        Write-Host("Something went wrong when deleting user.")
        #Skriv ut felmeddelandet till en log-fil
    }
    finally
    {
        Write-Host("`n")
    }
}

function Delete-FromRecycleBin()
{
    Write-Host("----- Delete from Recycle Bin -----")
    try
    {
        # Delete from Recycle Binr
        try
        {
            try
            {
                Write-Host("- Deleting objects in the recycle bin") -NoNewline   

                Get-MsolUser -ReturnDeletedUsers | Remove-MsolUser -RemoveFromRecycleBin -Force
                
                Write-Host(" - Completed") -ForegroundColor Green
            }
            catch 
            {
                Write-Host(" - Failed") -ForegroundColor Red
            }

        }
        catch
        {
            Write-Host("Something went wrong when deleting recycle bin.")
            #Skriv ut felmeddelandet till en log-fil
        }       
    }
    catch
    {
        Write-Host("Something went wrong when deleting recycle bin.")
        #Skriv ut felmeddelandet till en log-fil
    }
    finally
    {
        Write-Host("`n")
    }
}
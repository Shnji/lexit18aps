function log($Text, $FilePath)
{
    if($FilePath -eq $null)
    {
        if($Path -eq $null -or $Path -eq "") {
            $Global:Path = "C:\PowerShell Logs\log $(Get-Date -Format "yyyyMMdd_HHmmss").log"
        }      
    }
    else
    {
        $Path = $FilePath
    }

    if(!(Test-Path $Path)) { New-Item -ItemType File -Path $Path -Force | Out-Null }
        
    $Text = $(Get-Date -Format "yyyy-MM-dd HH:mm:ss:fff") + " :: " + $Text
    $Text | Out-File -FilePath $Path -Append
}

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

            $logmessage = "Script started and with the username {0}" -f $Cred_GlobalAdmin.UserName
            log -Text $logmessage
        }

        # 2. Installing Modules
        try
        {
            Write-Host("- Installing modules for Azure AD, MSOnline and SharePoint Online") -NoNewline     
            if(!(Get-Module MSOnline -ErrorAction SilentlyContinue)) 
            {  
                #Install-Module MSOnline -ErrorAction stop -WarningAction SilentlyContinue -Force
                log -Text "Installing module MSOnline was successful."
            }
            else
            {
                log -Text "Module MSOnline is already installed. Skipped installing module MSOnline."
            }

            if(!(Get-Module Microsoft.Online.SharePoint.Powershell -ErrorAction SilentlyContinue)) 
            {  
                #Install-Module Microsoft.Online.SharePoint.Powershell -ErrorAction Stop -WarningAction SilentlyContinue -Force
                log -Text "Installing module Microsoft.Online.SharePoint.Powershell was successful"
            }
            else
            {
                log -Text "Module Microsoft.Online.SharePoint.Powershell is already installed. Skipped installing module Microsoft.Online.SharePoint.Powershell."
            }

            if(!(Get-Module AzureAD -ErrorAction SilentlyContinue)) 
            {  
                #Install-Module AzureAD -ErrorAction stop -WarningAction SilentlyContinue -Force
                log -Text "Installing module AzureAD was successful"
            }
            else
            {
                log -Text "Module AzureAD is already installed. Skipped installing module AzureAD."
            }
            
            Write-Host(" - Completed") -ForegroundColor Green

            log -Text "Installing modules for Azure AD, MSOnline and SharePoint Online completed successfully"
        }
        catch 
        {
            Write-Host(" - Failed") -ForegroundColor Red
            Write-Host("ERROR: ") -NoNewline -ForegroundColor Red

            $error = $_.Exception.Message
            log -Text "ERROR:: Installing modules for Azure AD, MSOnline and SharePoint Online failed. See error message below:"            
            log -Text "ERROR:: $error"
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

                log -Text "Connecting to Microsoft Online Services was successful"
            }
            catch
            {
                Write-Host(" - Failed") -ForegroundColor Red
                
                $error = $_.Exception.Message
                log -Text "ERROR:: Connecting to Microsoft Online Services was unsuccessful. See error message below:"
                log -Text "ERROR:: $error"
            }    

            # 3.2 Exchange Online
            try
            {
                Write-Host("- Connecting to Exchange Online") -NoNewline                
                $Global:EXCH =  New-PSSession -Credential $Cred_GlobalAdmin -ConfigurationName Microsoft.Exchange -Authentication Basic `
                                -ConnectionUri https://outlook.office365.com/powershell-liveid/ -AllowRedirection -ErrorAction Stop
                
                Import-PSSession $EXCH -AllowClobber -DisableNameChecking | Out-Null
                Write-Host(" - Completed") -ForegroundColor Green

                log -Text "Connecting to Exchange Online was successful"
            }
            catch
            {
                Write-Host(" - Failed") -ForegroundColor Red
                
                $error = $_.Exception.Message
                log -Text "ERROR:: Connecting to Exchange Online was unsuccessful. See error message below:"
                log -Text "ERROR:: $error"
            } 

            # 3.3 SharePoint Online
            try
            {
                Write-Host("- Connecting to SharePoint Online") -NoNewline  
                Connect-SPOService -Credential $Cred_GlobalAdmin -Url "https://$TenantName-admin.sharepoint.com" -ErrorAction stop
                Write-Host(" - Completed") -ForegroundColor Green

                log -Text "Connecting to SharePoint Online was successful"
            }
            catch
            {
                Write-Host(" - Failed") -ForegroundColor Red

                $error = $_.Exception.Message
                log -Text "ERROR:: Connecting to SharePoint Online was unsuccessful. See error message below:"
                log -Text "ERROR:: $error"
            }         
        }
        catch
        {
            Write-Host("Something went wrong when connecting to online services.")

            $error = $_.Exception.Message
            log -Text "ERROR:: Something went wrong when connecting to online services. See error message below:"
            log -Text "ERROR:: $error"
        }
    }
    catch
    {
        Write-Host("Something went wrong when connecting to online services.")
        #Skriv ut felmeddelandet till en log-fil

        $error = $_.Exception.Message
        log -Text "ERROR:: Something went wrong when connecting to online services. See error message below:"
        log -Text "ERROR:: $error"
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
                log -Text "Removing variable Cred_GlobalAdmin"
            }

            if(Get-Variable TenantName) 
            {
                Remove-Variable TenantName -Scope "Global"
                log -Text "Removing variable TenantName"
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

                log -Text "Disconnecting from Microsoft Online was successful"
            }
            catch
            {
                Write-Host(" - Failed") -ForegroundColor Red
                                
                $error = $_.Exception.Message
	            log -Text "Disconnecting from Microsoft Online Services was unsuccessful. See error message below:"
	            log -Text "ERROR:: $error"
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
                
                $error = $_.Exception.Message
	            log -Text "Disconnecting from Exchange Online was unsuccessful. See error message below:"
	            log -Text "ERROR:: $error"
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

                $error = $_.Exception.Message
	            log -Text "Disconnecting from SharePoint Online was unsuccessful. See error message below:"
	            log -Text "ERROR:: $error"
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

                            log -Text "Creating user $DisplayName - $UserPrincipalName was successful"
                        }
                        catch
                        {
                            Write-Host(" - Failed") -ForegroundColor Red

                            $error = $_.Exception.Message
                            log -Text "ERROR:: Creating user $DisplayName - $UserPrincipalName was unsuccessful. See error message below:"            
                            log -Text "ERROR:: $error"
                        }                                               
                    }
                    else
                    {
                        Write-Host("- Duplicate: ") -NoNewline -ForegroundColor Yellow
                        Write-Host("User with UserPrincipalName '$UserPrincipalName' already exists.")

                        log -Text "User with UserPrincipalName '$UserPrincipalName' already exists."
                    }


                    # Create Department Group or Get Department Group
                    try
                    {
                        if($u.Department -ne $null)
                        {                        
                            $Group = Create-Group -GroupName $Department -ShowTitle $false
                        }
                    }
                    catch
                    {
                        
                    }
               

                    # Add User to Department Group
                    try
                    {
                        if($u -ne $null -and $Group -ne $null)
                        {
                            $temp = Add-UserToGroup -User $u -Group $Group -ShowTitle $false
                        }
                    }
                    catch
                    {
                        
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
                    write-host("");

                    log -Text "Removing variables that are used in the foreach loop when creating user"
                }             
            }
       } 
    }
    catch
    {
        Write-Host("Something went wrong when creating new user.")
        
        log -Text "Something went wrong when creating new user. See error message below:"
        $error = $_.Exception.Message
        log -Text "ERROR:: $error"
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

        log -Text "Removing variables that are used for the foreach loop when creating user"
        
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
                    
                    Get-MsolUser -All | where { -not (Get-MsolUserRole -ObjectId $_.ObjectId | where { $_.Name -eq "Company Administrator" }) } | Remove-MsolUser -Force

                    Write-Host(" - Completed") -ForegroundColor Green
                }
                catch 
                {
                    Write-Host(" - Failed") -ForegroundColor Red

                    $error = $_.Exception.Message
	                log -Text "Deleting all Office 365 users, except 'Company Administrators'. See error message below:"
	                log -Text "ERROR:: $error"
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
            
            $error = $_.Exception.Message
	        log -Text "Something went wrong when deleting user. See error message below:"
	        log -Text "ERROR:: $error"
        }       
    }
    catch
    {
        Write-Host("Something went wrong when deleting user.")

        $error = $_.Exception.Message
	    log -Text "Something went wrong when deleting user. See error message below:"
	    log -Text "ERROR:: $error"
    }
    finally
    {
        #Write-Host("`n")
    }
}

function Delete-FromRecycleBin()
{
    Write-Host("----- Delete from Recycle Bin -----")
    try
    {
        # Delete from Recycle Bin
        try
        {
            try
            {
                Write-Host("- Deleting objects in the recycle bin") -NoNewline   

                Get-MsolUser -ReturnDeletedUsers | 
                foreach 
                {
                    $logmessage = "Object {0} was successfully deleted from the recycle bin." -f $_.DisplayName
                    Remove-MsolUser -RemoveFromRecycleBin -Force

                    log -Text $logmessage
                }
                
                Write-Host(" - Completed") -ForegroundColor Green
            }
            catch 
            {
                Write-Host(" - Failed") -ForegroundColor Red
                
                $error = $_.Exception.Message
                log -Text "Deleting objects in the recycle bin was unsuccessful. See error message below:"
                log -Text "ERROR:: $error"
            }

        }
        catch
        {
            Write-Host("Something went wrong when deleting recycle bin.")
            
            $error = $_.Exception.Message
	        log -Text "Something went wrong when deleting recycle bin. See error message below:"
	        log -Text "ERROR:: $error"
        }       
    }
    catch
    {
        Write-Host("Something went wrong when deleting recycle bin.")
        $error = $_.Exception.Message
	    log -Text "Something went wrong when deleting recycle bin. See error message below:"
	    log -Text "ERROR:: $error"
    }
    finally
    {
        Write-Host("`n")
    }
}

function Create-Group($GroupName, $GroupType, $AccessType = "private", $ShowTitle = $true)
{     
     if($ShowTitle)
     {
        Write-Host("----- Create new Group -----")
     }

     try
     {
         if(!($Group = Get-MsolGroup -All | where { $_.DisplayName -eq $GroupName } ))
         {
            try
            {
                Write-Host("- Creating new Group named $GroupName") -NoNewline 

                switch($GroupType)
                {
                    "O365"  
                    { 
                        $Group = New-UnifiedGroup -DisplayName $GroupName -Name $GroupName -AccessType $AccessType 
                        log -Text "Creating new Office 365 Group named $GroupName with accesstype $AccessType was successful."
                    }

                    "DL"    
                    { 
                        $Group = New-DistributionGroup -Name $GroupName -Type Distribution 
                        log -Text "Creating new Distribution List Group named $GroupName was successful."
                    }
                    
                    "MESG"  
                    { 
                        $Group = New-DistributionGroup -Name $GroupName -Type Security 
                        log -Text "Creating new Mail Enabled Security Group named $GroupName was successful."
                    }
                    
                    default 
                    { 
                        $Group = New-MsolGroup -DisplayName $GroupName 
                        log -Text "Creating new Security Group named $GroupName was successful."
                    }
                }

                Write-Host(" - Completed") -ForegroundColor Green
            }
            catch
            {
                Write-Host(" - Failed") -ForegroundColor Red

                $error = $_.Exception.Message
	            log -Text "Creating new Group named $GroupName was unsuccessful. See error message below:"
	            log -Text "ERROR:: $error"

            }
         }
         else
         {
            if($ShowTitle)
            {
                Write-Host("- Duplicate: ") -NoNewline -ForegroundColor Yellow
                Write-Host("Group with DisplayName '$GroupName' already exists.")

                log -Text "Group with DisplayName '$GroupName' already exists."
            }
         }
         
         return $Group  
    }
    catch
    {
        Write-Host("Something went wrong when creating new group.")
        
        $error = $_.Exception.Message
	    log -Text "Something went wrong when creating new group. See error message below:"
	    log -Text "ERROR:: $error"
    }
    finally
    {
        if($ShowTitle)
        {
            Write-Host("`n")
        }
        
        
    } 
}

function Delete-Group($GroupName, $DeleteAll = $false, $ShowTitle = $true)
{
    if($ShowTitle)
    {
        Write-Host("----- Deleting Group -----")
    }
     
    try
    {  
        if($DeleteAll)
        {
            try
            {
                Write-Host("- Deleting all Groups") -NoNewline 
                
                Get-MsolGroup -All | Remove-MsolGroup -Force
                
                Write-Host(" - Completed") -ForegroundColor Green
                $logmessage = "Group was deleted successfully."
                log -Text $logmessage      
            }
            catch
            {
                Write-Host(" - Failed") -ForegroundColor Red
                
                $logmessage = "Group {0} was unsuccessfully deleted." -f $_.DisplayName       
                $error = $_.Exception.Message
	            log -Text "$logmessage. See error message below:"
	            log -Text "ERROR:: $error"
            }
        }
    }
    catch
    {
        Write-Host("Something went wrong when deleting group.")
        
        $error = $_.Exception.Message
	    log -Text "Something went wrong when deleting group. See error message below:"
	    log -Text "ERROR:: $error"
    }
    finally
    {
        if($ShowTitle)
        {
            Write-Host("`n")
        }
    }   
}

function Add-UserToGroup($User, $Group, $GroupRole, $ShowTitle = $true)
{     
     if($ShowTitle)
     {
        Write-Host("----- Adding User to Group -----")
     }

     try
     {
         if(!(Get-MsolGroupMember -GroupObjectId $Group.ObjectId | where { $_.EmailAddress -eq $User.UserPrincipalName }))
         {
            try
            {
                Write-Host("- Adding user {0} to Group {1}" -f $User.DisplayName, $Group.DisplayName) -NoNewline 

                switch($Group.GroupType)
                {
                    "Security"            
                    { 
                        $Member = Add-MsolGroupMember -GroupObjectId $Group.ObjectId -GroupMemberObjectId $User.ObjectId -ErrorAction Stop 

                        $logmessage = "{0} was successfully added to the Security Group {1}." -f $User.UserPrincipalName, $Group.DisplayName
                        log -Text $logmessage                        
                    }
                    
                    "MailEnabledSecurity" 
                    { 
                        $Member = Add-DistributionGroupMember -Identity $Group.DisplayName -Member $User.UserPrincipalName -ErrorAction Stop 
                        
                        $logmessage = "{0} was successfully added to the Mail Enabled Security Group {1}." -f $User.UserPrincipalName, $Group.DisplayName
                        log -Text $logmessage
                    }

                    "DistributionList"    
                    { 
                    
                        if(!(Get-UnifiedGroup -Identity $Group.DisplayName -ErrorAction silentlyContinue))
                        {
                            $Member = Add-DistributionGroupMember -Identity $Group.DisplayName -Member $User.UserPrincipalName -ErrorAction Stop

                            $logmessage = "{0} was successfully added to the Distribution List Group {1}." -f $User.UserPrincipalName, $Group.DisplayName
                            log -Text $logmessage
                        }
                        else
                        {
                            switch($GroupRole)
                            {
                                "owner" 
                                {
                                    $Member = Add-UnifiedGroupLinks -LinkType Members -Identity $Group.DisplayName -Links $User.UserPrincipalName -ErrorAction Stop
                                    
                                    $logmessage = "{0} was successfully added to the Office 365 Group {1} as a member." -f $User.UserPrincipalName, $Group.DisplayName
                                    log -Text $logmessage

                                    $Member = Add-UnifiedGroupLinks -LinkType Owners -Identity $Group.DisplayName -Links $User.UserPrincipalName -ErrorAction Stop
                                    
                                    $logmessage = "{0} was successfully added to the Office 365 Group {1} as a owner." -f $User.UserPrincipalName, $Group.DisplayName
                                    log -Text $logmessage 
                                }

                                "subscriber" 
                                {
                                    $Member = Add-UnifiedGroupLinks -LinkType Subscribers -Identity $Group.DisplayName -Links $User.UserPrincipalName -ErrorAction Stop
                                    
                                    $logmessage = "{0} was successfully added to the Office 365 Group {1} as a subscriber." -f $User.UserPrincipalName, $Group.DisplayName
                                    log -Text $logmessage  
                                }

                                default 
                                {
                                    $Member = Add-UnifiedGroupLinks -LinkType Members -Identity $Group.DisplayName -Links $User.UserPrincipalName -ErrorAction Stop 

                                    $logmessage = "{0} was successfully added to the Office 365 Group {1} as a member." -f $User.UserPrincipalName, $Group.DisplayName
                                    log -Text $logmessage 
                                }
                            }
                        }
                    
                    }
                }


                Write-Host(" - Completed") -ForegroundColor Green

            }
            catch
            {
                Write-Host(" - Failed") -ForegroundColor Red

                $addingmessage = "Adding user {0} to Group {1} was unsuccessful." -f $User.DisplayName, $Group.DisplayName
                $error = $_.Exception.Message
                
                log -Text "$addingmessage. See error message below:"
                log -Text "ERROR:: $error"

            }
         }
         else
         {
            $message = "User {0} is already a member of group {1}." -f $User.DisplayName, $Group.DisplayName

            Write-Host("- Duplicate: ") -NoNewline -ForegroundColor Yellow
            Write-Host($message)
            
            log -Text $message
            Remove-Variable message

         }
         
         return $Group  
    }
    catch
    {
        Write-Host("Something went wrong when adding user to group.")
        
        $error = $_.Exception.Message
        log -Text "Something went wrong when adding user to group. See error message below:"
        log -Text "ERROR:: $error"
    }
    finally
    {
        if($ShowTitle)
        {
            Write-Host("`n")
        }
    } 
}

function Create-Contact($ShowTitle = $true) 
{
    if($ShowTitle)
    {
        Write-Host("----- Create new Contact -----")
    }

    try
    {
        
        $FirstName = Read-Host("Ange ett förnamn: ")
        $LastName = Read-Host("Ange ett efternamn: ")
        $ExternalEmail = Read-Host("Ange en e-postadress: ")

        $DisplayName = "$FirstName $LastName"
        $Name = $DisplayName


        if(!(Get-MailContact -Identity $ExternalEmail -ErrorAction silentlyContinue)) 
        {
            
            try
            {           
                if(Get-MailContact -Identity $DisplayName -ErrorAction silentlyContinue)
                {
                
                    $Name = "$Name {$(new-Guid)}"
                }
            
                Write-Host("- Creating new contact named $DisplayName") -NoNewline   
                New-MailContact -Name $Name -DisplayName $DisplayName -ExternalEmailAddress $ExternalEmail | Out-Null


                Write-Host(" - Completed") -ForegroundColor Green
                log -Text "Creating new contact named $DisplayName was successful"
            }
            catch
            {
                Write-Host(" - Failed") -ForegroundColor Red

                $error = $_.Exception.Message
                log -Text "ERROR:: Creating new contact named $DisplayName was unsuccessful. See error message below:"            
                log -Text "ERROR:: $error"
            }  

        }
        else 
        {
            Write-Host("A contact named $DisplayName with email address $ExternalEmail already exists.") -ForegroundColor Yellow
        }
        
    }

    catch
    {
        Write-Host("Something went wrong when creating new contact.")
        
        $error = $_.Exception.Message
        log -Text "Something went wrong when creating new contact. See error message below:"
        log -Text "ERROR:: $error"
    }

    finally
    {
        if($ShowTitle)
        {
            Remove-Variable Name
            Write-Host("`n")
        }
    } 
}

function Create-RetentionPolicy($Department, $ShowTitle = $true) 
{
    if($ShowTitle)
    {
        Write-Host("----- Create new Retention Policy -----")
    }

    try
    {
        
        if($Department -eq $null)
        {
            throw "Department variable is null or empty."
        }

        $RetentionPolicyName = ("Default MRM Policy for $Department").Trim()
                
        if(!(Get-RetentionPolicy -Identity $RetentionPolicyName -ErrorAction silentlyContinue))
        {
            
            try
            {
                Enable-OrganizationCustomization -ErrorAction silentlyContinue

                $RetentionTagLinks = @()
                $RetentionPolicyTags = Import-Csv -Path D:\Lexicon\ittek18a\lektion\retentiontags.csv -Delimiter "," -Encoding UTF8

                foreach($tag in $RetentionPolicyTags)
                {
                    if(!(Get-RetentionPolicyTag -Identity $tag.Name -ErrorAction silentlyContinue))
                    {
                        New-RetentionPolicyTag -Name $tag.Name -AgeLimitForRetention $tag.AgeLimitForRetention -RetentionAction $tag.RetentionAction -RetentionEnabled ([system.convert]::ToBoolean($tag.RetentionEnabled))  | Out-Null
                    }

                    $RetentionTagLinks += $tag.Name
                }

                try
                {
                    Write-Host("- Creating new Retention Policy named $RetentionPolicyName") -NoNewline   
                    
                    New-RetentionPolicy -Name $RetentionPolicyName -RetentionPolicyTagLinks $RetentionTagLinks | Out-Null
                    
                    Write-Host(" - Completed") -ForegroundColor Green
                    log -Text "Creating new Retention Policy named $RetentionPolicyName was successful"
                }
                catch
                {
                    Write-Host(" - Failed") -ForegroundColor Red

                    $error = $_.Exception.Message
                    log -Text "ERROR:: Creating new Retention Policy named $RetentionPolicyName was unsuccessful. See error message below:"            
                    log -Text "ERROR:: $error"
                } 


            }
            catch
            {
                Write-Host("Something went wrong when Enabling Organization Customization.")
        
                $error = $_.Exception.Message
                log -Text "Something went wrong when Enabling Organization Customization. See error message below:"
                log -Text "ERROR:: $error"                
            }


        }
        else 
        {
            Write-Host("A Retention Policy named $RetentionPolicyName already exists.") -ForegroundColor Yellow
        }
    }

    catch
    {
        Write-Host("Something went wrong when creating new Retention Policy.")
        
        $error = $_.Exception.Message
        log -Text "Something went wrong when creating new Retention Policy. See error message below:"
        log -Text "ERROR:: $error"
    }

    finally
    {
        if($ShowTitle)
        {
            Write-Host("`n")
        }
    } 
}

#Create Shared MailBox with PowerShell
function Create-SharedMailbox($EmailAddress, $EmailDisplayName, $ShowTitle = $true) 
{
    if($ShowTitle)
    {
        Write-Host("----- Create new Shared Mailbox -----")
    }

    try
    {

        if($EmailAddress -eq $null)
        {
            throw "EmailAddress variable is null or empty."
        }
        
        if(!(Get-Mailbox -Identity $EmailAddress -ErrorAction silentlyContinue))
        {
            
            try
            {
                Write-Host("- Creating new shared mailbox with email $EmailAddress") -NoNewline   
                    
                
                if($EmailDisplayName -eq $null)
                {
                    $EmailDisplayName = $EmailAddress.Split("@")[0]
                }           

                New-Mailbox -Name $EmailAddress -DisplayName $EmailDisplayName -PrimarySmtpAddress $EmailAddress -Shared -WarningAction silentlyContinue -Force | Out-Null
                     
                     
                Write-Host(" - Completed") -ForegroundColor Green
                log -Text "Creating new shared mailbox with email $EmailAddress was successful."              
            
            
            }
            catch
            {
                Write-Host(" - Failed") -ForegroundColor Red

                $error = $_.Exception.Message
                log -Text "ERROR:: Creating new shared mailbox with email $EmailAddress was unsuccessful. See error message below:"            
                log -Text "ERROR:: $error"
            }        
            
        }
        else
        {
            Write-Host("A shared mailbox with email $EmailAddress already exists.") -ForegroundColor Yellow
        }

                
    }

    catch
    {
        Write-Host("Something went wrong when creating new shared mailbox.")
        
        $error = $_.Exception.Message
        log -Text "Something went wrong when creating new shared mailbox. See error message below:"
        log -Text "ERROR:: $error"
    }

    finally
    {
        if($ShowTitle)
        {
            Write-Host("`n")
        }
    } 
}
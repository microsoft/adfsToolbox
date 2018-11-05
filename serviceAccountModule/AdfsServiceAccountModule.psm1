# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.



#####################################################################
####Helper functions related to rule parsing logic###################
#####################################################################

<#
.SYNOPSIS
    Class to encapsulate parsing of the ADFS Issuances/Auth rules.
#>

class AdfsRules
{
    [System.Collections.ArrayList] hidden $rules

    <#
    .SYNOPSIS
        Constructor
    #>
    AdfsRules([string]$rawRules) 
    {
        $rulesArray = $this.ParseRules($rawRules)
        $this.rules = New-Object "System.Collections.ArrayList"
        $this.rules.AddRange($rulesArray)
    }

    <#
    .SYNOPSIS
        Utility function to parse the rules and return them as a string[].
    #>
    [string[]] hidden ParseRules([string]$rawRules)
    {
        Write-Verbose "$($PSCmdlet.MyInvocation.MyCommand) : BEGIN"

        $allRules = @()
        $singleRule = [string]::Empty

        $rawRules.Split("`n") | %{
            
            $line = $_.ToString().Trim()

            if (-not ([string]::IsNullOrWhiteSpace($line)) ) 
            {
                $singleRule += $_ + "`n"

                if ($line.StartsWith("=>"))
                {
                    Write-Verbose "$($PSCmdlet.MyInvocation.MyCommand) : Parsed rule:`n$singleRule"
                    $allRules += $singleRule
                    $singleRule = [string]::Empty
                }
            }
        }

        Write-Verbose "$($PSCmdlet.MyInvocation.MyCommand) : END"

        return $allRules
    }

    <#
    .SYNOPSIS
        Finds the rule by name in the format: @RuleName = "$ruleName". Returns $null if not found.
    #>
    [string] FindByRuleName([string]$ruleName)
    {
        $ruleNameSearchString = '@RuleName = "' + $ruleName + '"'
        Write-Verbose "$($PSCmdlet.MyInvocation.MyCommand) : Search string: $ruleNameSearchString"

        foreach ($rule in $this.rules)
        {
            if ($rule.Contains($ruleNameSearchString))
            {
                Write-Verbose "$($PSCmdlet.MyInvocation.MyCommand) : Found.`n$rule"
                return $rule
            }
        }

        Write-Verbose "$($PSCmdlet.MyInvocation.MyCommand) : NOT FOUND. Returning $null"
        return $null;
    }

    <#
    .SYNOPSIS
        Replaces the specified old rule with the new one. Returns $true if the old one was found and replaced; $false otherwise.
    #>
    [bool] ReplaceRule([string]$oldRule, [string]$newRule)
    {
        Write-Verbose "$($PSCmdlet.MyInvocation.MyCommand) : Trying to replace old rule with new.`n Old Rule:`n$oldRule`n New Rule:`n$newRule"
        $idx = $this.FindIndexForRule($oldRule)

        if ($idx -ge 0)
        {
            Write-Verbose "$($PSCmdlet.MyInvocation.MyCommand) : Replacing old rule with new."
            $this.rules[$idx] = $newRule
            return $true
        }

        Write-Verbose "$($PSCmdlet.MyInvocation.MyCommand) : Old rule is not found so NOT replacing it."
        return $false
    }

    <#
    .SYNOPSIS
        Removes the specified if found. Returns $true if found; $false otherwise.
    #>
    [bool] RemoveRule([string]$ruleToRemove)
    {
        Write-Verbose "$($PSCmdlet.MyInvocation.MyCommand) : Trying to remove rule.`n Rule:`n$ruleToRemove"

        $idx = $this.FindIndexForRule($ruleToRemove)

        if ($idx -ge 0)
        {
            Write-Verbose "$($PSCmdlet.MyInvocation.MyCommand) : Removing rule at index: $idx."
            $this.rules.RemoveAt($idx)
            return $true
        }

        Write-Verbose "$($PSCmdlet.MyInvocation.MyCommand) : Rule is not found so NOT removing it."
        return $false
    }

    <#
    .SYNOPSIS
        Helper function to find the index of the rule. Returns index if found; -1 otherwise.
    #>
    [int] FindIndexForRule([string]$ruleToFind)
    {
        Write-Verbose "$($PSCmdlet.MyInvocation.MyCommand) : Trying to find rule.`n Rule:`n$ruleToFind"

        for ($i = 0; $i -lt $this.rules.Count; $i++)
        {
            $rule = $this.rules[$i]

            if ($rule.Replace(' ','').trim() -eq $ruleToFind.Replace(' ','').trim())
            {
                Write-Verbose "$($PSCmdlet.MyInvocation.MyCommand) : Found at index: $i."
                return $i
            }
        }

        Write-Verbose "$($PSCmdlet.MyInvocation.MyCommand) : NOT FOUND. Returning -1"
        return -1
    }
    
    <#
    .SYNOPSIS
        Returns all the rules as string.
    #>
    [string] ToString()
    {
        return [string]::Join("`n", $this.rules.ToArray())
    }
}

# Helper function - serializes any DataContract object to an XML string
function Get-DataContractSerializedString()
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, HelpMessage="Any object serializable with the DataContractSerializer")]
        [ValidateNotNull()]
        $object
    )

    $serializer = New-Object System.Runtime.Serialization.DataContractSerializer($object.GetType())
    $serializedData = $null

    try
    {
        # No simple write to string option, so we have to write to a memory stream
        # then read back the bytes...
        $stream = New-Object System.IO.MemoryStream
        $writer = New-Object System.Xml.XmlTextWriter($stream,[System.Text.Encoding]::UTF8)

        $null = $serializer.WriteObject($writer, $object);
        $null = $writer.Flush();
                
        # Read back the text we wrote to the memory stream
        $reader = New-Object System.IO.StreamReader($stream,[System.Text.Encoding]::UTF8)
        $null = $stream.Seek(0, [System.IO.SeekOrigin]::Begin)
        $serializedData = $reader.ReadToEnd()
    }
    finally
    {
        if ($reader -ne $null)
        {
            try
            {
                $reader.Dispose()
            }
            catch [System.ObjectDisposedException] { }
        }

        if ($writer -ne $null)
        {
            try
            {
                $writer.Dispose()
            }
            catch [System.ObjectDisposedException] { }
        }

        if ($stream -ne $null)
        {
            try
            {
                $stream.Dispose()
            }
            catch [System.ObjectDisposedException] { }
        }
    }

    return $serializedData
}


# Gets internal ADFS settings by extracting them Get-AdfsProperties
function Get-AdfsInternalSettings()
{
    $settings = Get-AdfsProperties
    $settingsType = $settings.GetType()
    $propInfo = $settingsType.GetProperty("ServiceSettingsData", [System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic)
    $internalSettings = $propInfo.GetValue($settings, $null)
    
    return $internalSettings
}

function IsWID()
{
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$ConnectionString
    )

    if($ConnectionString -match "##wid" -or $ConnectionString -match "##ssee")
    {
        return $true
    }
    return $false
}


function Set-AdfsInternalSettings()
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$SerializedData
    )

    $doc = new-object Xml
    $doc.Load("$env:windir\ADFS\Microsoft.IdentityServer.Servicehost.exe.config")
    $connString = $doc.configuration.'microsoft.identityServer.service'.policystore.connectionString
    $cli = new-object System.Data.SqlClient.SqlConnection
    $cli.ConnectionString = $connString
    $cli.Open()
    try
    {    
        $cmd = new-object System.Data.SqlClient.SqlCommand
        $cmd.CommandText = "update [IdentityServerPolicy].[ServiceSettings] SET ServiceSettingsData=@content,[ServiceSettingsVersion] = [ServiceSettingsVersion] + 1,[LastUpdateTime] = GETDATE()"
        $cmd.Parameters.AddWithValue("@content", $SerializedData) | out-null
        $cmd.Connection = $cli
        $cmd.ExecuteNonQuery() 

        # Update service state table for WID sync if required
        if (IsWid -ConnectionString $connString)
        {
            $cmd = new-object System.Data.SqlClient.SqlCommand
            $cmd.CommandText = "UPDATE [IdentityServerPolicy].[ServiceStateSummary] SET [SerialNumber] = [SerialNumber] + 1,[LastUpdateTime] = GETDATE() WHERE ServiceObjectType='ServiceSettings'"

            $cmd.Connection = $cli
            $cmd.ExecuteNonQuery() 
        }
    }
    finally
    {
        $cli.CLose()
    }
} 


Function AddUserRights 
{   
    $RightsFailed =  $false 
    NTRights.Exe -u $NewName +r SeServiceLogonRight | Out-File $LogPath -Append 
     
    If (!$?) 
    { 
        $RightsFailed =  $true 
        Write-Host "`tFailed to add user rights for $NewName`n`tSee: POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY" -ForegroundColor "yellow" -NoNewline 
        ($ElapsedTime.Elapsed.ToString())+ "[WARN]      Failed to add user rights for ${NewName}: 'Log on as a service', 'Generate security audits'" | Out-File $LogPath -Append 
        Return $RightsFailed 
    } 
     
    NTRights.Exe -u $NewName +r SeAuditPrivilege | Out-File $LogPath -Append 
    If (!$?) 
    { 
        $RightsFailed =  $true 
        Write-Host "`tFailed to add user rights for $NewName`n`tSee: POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY" -ForegroundColor "yellow" -NoNewline 
        ($ElapsedTime.Elapsed.ToString())+ "[WARN]      Failed to add user rights for ${NewName}: 'Log on as a service', 'Generate security audits'" | Out-File $LogPath -Append 
        Return $RightsFailed 
    }  
    Else 
    { 
        GPUpdate /Force | Out-File $LogPath -Append 
        $RightsFailed = $false 
        Write-Host "`tSuccess" -ForegroundColor "green" -NoNewline 
        ($ElapsedTime.Elapsed.ToString())+" [INFO]      User rights 'Log on as a service', 'Generate security audits' added for $NewName" | Out-File $LogPath -Append 
    } 
             
    Return $RightsFailed 
} 
 
# Converts account name to SID 
Function ConvertTo-Sid ($Account) 
{ 
    $SID = (New-Object system.security.principal.NtAccount($Account)).translate([system.security.principal.securityidentifier]) 
    Return $SID 
} 
 
 
# ACLs a certificate private key 
Function Set-CertificateSecurity 
{ 
 
    param([String]$certThumbprint,[String]$NewAccount) 
    $FailedCertPerms = $false 
    $certKeyPath = $env:ProgramData + "\Microsoft\Crypto\RSA\MachineKeys\" 
    $certsCollection = @(dir cert:\ -recurse | ? { $_.Thumbprint -eq $certThumbprint }) 
    $certToSecure = $certsCollection[0] 
    $uniqueKeyName = $certToSecure.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName 
     
    If ($uniqueKeyname -is [Object]) 
    { 
        $Acl = Get-Acl $certKeyPath$uniqueKeyName 
        $Arguments = $NewAccount,"Read","Allow" 
        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $Arguments 
        $Acl.SetAccessRule($AccessRule) 
        $Acl | Set-Acl $certKeyPath$uniqueKeyName 
         
        If (!$?) 
        { 
            Write-Host "`t`tFailed to set private key permissions.`n`t`tSee: POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY" -ForegroundColor "yellow" -NoNewline 
            ($ElapsedTime.Elapsed.ToString())+" [ERROR]     Failed setting permissions on key for thumbprint $certThumbprint - Setting the ACL did not succeed" | Out-File $LogPath -Append 
            $CertPerms = $false 
        } 
        Else 
        { 
            Write-Host "`t`tSuccess" -ForegroundColor "green" -NoNewline 
            ($ElapsedTime.Elapsed.ToString())+" [INFO]      Set permissions on key for thumbprint $certThumbprint" | Out-File $LogPath -Append 
            $CertPerms = $true 
        } 
    }
 
    Else 
    { 
        Write-Host "`t`tFailed to set private key permissions.`n`t`tSee: POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY" -ForegroundColor "yellow" -NoNewline 
        ($ElapsedTime.Elapsed.ToString())+" [ERROR]     Failed setting permissions on key for thumbprint $certThumbprint - Unique key container did not exist" | Out-File $LogPath -Append 
        $CertPerms = $false 
    } 
    Return $CertPerms 
} 
 
 
# ACLs the CertificateSharingContainer 
Function Set-CertificateSharingContainerSecurity 
{ 
    param([String]$NewSID) 

    $FailedLdap = $false 
     
    # Get the new SID as a SID object and create AD Access Rules 
    $objNewSID = [System.Security.Principal.SecurityIdentifier]$NewSID 
 
    $nullGUID = [guid]'00000000-0000-0000-0000-000000000000' 
    $RuleCreateChild = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($objNewSID,'CreateChild','Allow','All',$nullGUID)  
    $RuleSelf = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($objNewSID,'Self','Allow','All',$nullGUID)  
    $RuleWriteProperty = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($objNewSID,'WriteProperty','Allow','All',$nullGUID)  
    $RuleGenericRead = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($objNewSID,'GenericRead','Allow','All',$nullGUID)  
 
    # Get the LDAP object based on the certificate sharing container and add the AD Access Rules to the object 
    $DN = ($ADFSProperties.CertificateSharingContainer).ToString() 
    $objLDAP = [ADSI] "LDAP://$DN" 
    $objLDAP.get_ObjectSecurity().AddAccessRule($RuleCreateChild) 
    $objLDAP.get_ObjectSecurity().AddAccessRule($RuleSelf) 
    $objLDAP.get_ObjectSecurity().AddAccessRule($RuleWriteProperty) 
    $objLDAP.get_ObjectSecurity().AddAccessRule($RuleGenericRead) 
 
 
    # Commit the AD Access rule changes to the LDAP object 
    $objLDAP.CommitChanges() 
     
    If (!$?) 
    { 
        Write-Host "`tFailed to set permissions on the Certificate Sharing Container.`n`tSee: POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY" -ForegroundColor "yellow" -NoNewline 
        ($ElapsedTime.Elapsed.ToString())+" [ERROR]     Failed setting permissions on AD cert sharing container: $DN. $NewName needs 'Create Child', 'Write', 'Read'." | Out-File $LogPath -Append 
        $FailedLdap = $true 
    } 
    Else 
    { 
        Write-Host "`tSuccess" -ForegroundColor "green" -NoNewline 
        ($ElapsedTime.Elapsed.ToString())+" [INFO]      Set permissions on cert sharing container: $DN" | Out-File $LogPath -Append 
    } 
} 
 
 
# Generates SQL scripts for database and service permissions 
Function GenerateSQLScripts 
{ 
    # Generate SetPermissions.sql 
    If (!(Test-Path $env:Temp\ADFSSQLScripts)) { New-Item $env:Temp\ADFSSQLScripts -type directory | Out-Null } 
    If (Test-Path $env:Temp\ADFSSQLScripts) { Remove-Item $env:Temp\ADFSSQLScripts\* | Out-Null } 
    Write-Host "`n Generating SQL scripts" 
    ($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Generating SQL scripts ($env:Temp\ADFSSQLScripts)" | Out-File $LogPath -Append 
     
    $WinDir = (Get-ChildItem Env:WinDir).Value 
    Export-AdfsDeploymentSQLScript -DestinationFolder $env:Temp\ADFSSQLScripts -ServiceAccountName $NewName 
         
    If (!$?) 
    { 
        Write-Host "`tFailed to generate SQL scripts. Exiting" -ForegroundColor "red" 
        ($ElapsedTime.Elapsed.ToString())+" [ERROR]     Failed to generate SQL scripts" | Out-File $LogPath -Append 
        Return $false 
    } 
 
    # Generate UpdateServiceSettings.sql, but not for secondary WID. Secondary SQL never gets to this function 
     
    If (!(($Role -eq "SecondaryComputer") -and ($DBMode -eq "WID"))) 
    { 
        "USE AdfsConfiguration" | Out-File "$env:Temp\ADFSSQLScripts\UpdateServiceSettings.sql" 
        "SELECT ServiceSettingsData from IdentityServerPolicy.ServiceSettings" | Out-File "$env:Temp\ADFSSQLScripts\UpdateServiceSettings.sql" -append 
        "UPDATE IdentityServerPolicy.ServiceSettings" | Out-File "$env:Temp\ADFSSQLScripts\UpdateServiceSettings.sql" -append 
        "SET ServiceSettingsData=REPLACE((SELECT ServiceSettingsData from IdentityServerPolicy.ServiceSettings),'$OldSID','$NewSID')" | Out-File "$env:Temp\ADFSSQLScripts\UpdateServiceSettings.sql" -append 
        "SELECT ServiceSettingsData from IdentityServerPolicy.ServiceSettings" | Out-File "$env:Temp\ADFSSQLScripts\UpdateServiceSettings.sql" -append 
     
        If (!$?) 
        { 
            Write-Host "`tFailed to generate UpdateServiceSettings.sql. Exiting" -ForegroundColor "red" 
            ($ElapsedTime.Elapsed.ToString())+" [ERROR]     Failed to generate UpdateServiceSettings.sql" | Out-File $LogPath -Append 
            Return $false 
        } 
    } 
     
    # Clean up the CreateDB.sql file 
    If (Test-Path "$env:Temp\ADFSSQLScripts\CreateDB.sql") 
    { 
        Remove-Item "$env:Temp\ADFSSQLScripts\CreateDB.sql" 
    } 
     
    Return $true 
     
} 
     
     
# Executes the SQL scripts generated by GenerateSQLScripts 
Function ExecuteSQLScripts 
{ 
    Start sqlcmd.exe -ArgumentList "-S $SQLHost -i $env:Temp\ADFSSQLScripts\SetPermissions.sql -o $env:Temp\ADFSSQLScripts\SetPermissions.log" -Wait -WindowStyle Hidden | Out-File $LogPath -Append 
      
    If (!$?) 
    { 
        Write-Host "`tFailed to execute SetPermissions.sql. Exiting" -ForegroundColor "red" 
        ($ElapsedTime.Elapsed.ToString())+" [ERROR]     Failed to execute SetPermissions.sql" | Out-File $LogPath -Append 
        Return $false 
    } 
      
     # Execute UpdateServiceSettings.sql, but not for secondary WID. Secondary SQL never gets to this function. 
      
    If (!(($Role -eq "SecondaryComputer") -and ($DBMode -eq "WID"))) 
    { 
        Start sqlcmd.exe -ArgumentList "-S $SQLHost -i $env:Temp\ADFSSQLScripts\UpdateServiceSettings.sql -o $env:Temp\ADFSSQLScripts\UpdateServiceSettings.log" -Wait -WindowStyle Hidden | Out-File $LogPath -Append 
      
        If (!$?) 
        { 
            Write-Host "`tFailed to execute UpdateServiceSettings.sql. Exiting...." -ForegroundColor "red" 
            ($ElapsedTime.Elapsed.ToString())+" [ERROR]     Failed to execute UpdateServiceSettings.sql" | Out-File $LogPath -Append 
            Return $false 
        } 
    } 
    Return $true 
}

function Update-AdfsServiceAccountRule
{
    param(
        [parameter(Mandatory=$true, Position=1)]
        [string]$ServiceAccount,

        [parameter(ValueFromPipeline=$True)]
        [string[]]$SecondaryServers,

        [parameter()]
        [switch]$RemoveRule    
    )


    #Validate provided account exists
    $User = $ServiceAccount
    if($ServiceAccount -match '\\')
    {
        $Account = $ServiceAccount.Split('\') #Input given in the format domain\user 
        $User = $Account[1]
    }
    $Lookup = Get-ADUser -Filter {Name -eq $User} 
    if($Lookup -eq $null)
    {
        throw "The specified account $User does not exist"
    }


    #Create rule with new service account
    $SID = ConvertTo-Sid($ServiceAccount)
    $ServiceAccountRule = "@RuleName = `"Permit Service Account`"`nexists([Type == `"http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid`", Value == `"$SID`"])`n=> issue(Type = `"http://schemas.microsoft.com/authorization/claims/permit`", value = `"true`");`n`n"
    $Properties = Get-AdfsInternalSettings

    #Backup service settings prior to adding new rule
    $BackUpPath = ((Convert-Path .) + "\serviceSettingsData" + "-" + (get-date -f yyyy-MM-dd-hh-mm-ss) + ".xml") -replace '\s',''
    Get-DataContractSerializedString -object $Properties | Export-Clixml $BackUpPath
    Write-Host ("Backup of current service settings stored at $BackUpPath")


    if($RemoveRule)
    {
        $AuthorizationPolicyRules = [AdfsRules]::new($Properties.PolicyStore.AuthorizationPolicy) 
        if($AuthorizationPolicyRules.RemoveRule($ServiceAccountRule))
        {
            Write-Host "Service account $ServiceAccount with SID $SID was removed from the Authorization Policy rule set"
        }
        else
        {
             Write-Host "Service account $ServiceAccount with SID $SID was not found in the Authorization Policy rule set"
        }
        $Properties.PolicyStore.AuthorizationPolicy = $AuthorizationPolicyRules.ToString()

        $AuthorizationPolicyReadOnlyRules = [AdfsRules]::new($Properties.PolicyStore.AuthorizationPolicyReadOnly) 
        if($AuthorizationPolicyReadOnlyRules.RemoveRule($ServiceAccountRule))
        {
            Write-Host "Service account $ServiceAccount with SID $SID was removed from the Authorization Policy Read Only rule set"
        }
        else
        {
            Write-Host "Service account $ServiceAccount with SID $SID was not found in the Authorization Policy Read Only rule set"
        }
        $Properties.PolicyStore.AuthorizationPolicyReadOnly = $AuthorizationPolicyReadOnlyRules.ToString()

    }
    else
    {
        #Check if rule already exists in auth policy
        $AuthorizationPolicyRules = [AdfsRules]::new($Properties.PolicyStore.AuthorizationPolicy)
        if($AuthorizationPolicyRules.FindIndexForRule($ServiceAccountRule) -ne -1)
        {
            Write-Host "Service account rule already exists."
            return $true
        }
        Write-Host "Adding rule for service account $ServiceAccount with SID $SID to Authorization Policy and Authorization Policy Read Only rule sets"

        $Properties.PolicyStore.AuthorizationPolicy = $Properties.PolicyStore.AuthorizationPolicy + $ServiceAccountRule
        $Properties.PolicyStore.AuthorizationPolicyReadOnly = $Properties.PolicyStore.AuthorizationPolicyReadOnly + $ServiceAccountRule
    }

    try
    {
        Set-AdfsInternalSettings  (Get-DataContractSerializedString -object $Properties) | Out-Null
    }
    catch
    {
        Write-Error "There was an error writing to the configuration database"
        retun $false
    }


    $doc = new-object Xml
    $doc.Load("$env:windir\ADFS\Microsoft.IdentityServer.Servicehost.exe.config")
    $connString = $doc.configuration.'microsoft.identityServer.service'.policystore.connectionString


    if((IsWID -ConnectionString $connString) -eq $true)
    {
        if($SecondaryServers.Count -eq 0)
        {
            Write-Warning("No list of secondary servers was provided. You must ensure a sync has occurred on all machines before proceeding to change the service account.")
        }

        #In the case of WID, sync config among all secondary servers
        foreach($Server in $SecondaryServers)
        {
            Invoke-Command -ComputerName $Server -ScriptBlock {
                $Date = Get-Date 
                $Duration = (Get-AdfsSyncProperties).PollDuration
                Set-AdfsSyncProperties -PollDuration 1
                while((Get-AdfsSyncProperties).LastSyncTime -lt $Date)
                {
                    Start-Sleep 1
                }
                Set-AdfsSyncProperties -PollDuration $Duration
            }
        }
    }
    return $true

} 



#Define functions to export


<#

.SYNOPSIS
Module restores the AD FS service settings from a backup generated by either Add-AdfsServiceAccountRule or Remove-AdfsServiceAccountRule

.EXAMPLE
Restore-AdfsSettingsFromBackUp -BackUpPath C:\Users\Administrator\Documents\serviceSettingsData-2018-04-11-12-04-03.xml

#>

function Restore-AdfsSettingsFromBackup
{
    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='High')]
    param(
        [parameter(Mandatory=$true)]
        [string]$BackupPath
    )

    if(-not (Test-Path $BackupPath))
    {
        Write-Host "The provided path to the backup file was not found."
        return $false
    }

    #Receive user confirmation
    if(-not $PSCmdlet.ShouldProcess("A write to the AD FS configuration database will occur", "This script will write directly to the AD FS configuration database. Are you sure you want to proceed?", "Confrim"))
    {
        Write-Host "Terminating execution of script"
        return $false
    }

    $Properties = Import-Clixml $BackupPath
    try
    {
        Set-AdfsInternalSettings  $Properties | Out-Null
    }
    catch
    {
        Write-Error "There was an error writing to the configuration database"
        return $false
    }
    return $true
}


<#
.SYNOPSIS
Module adds rule permitting the speciifed service account to the AD FS rule set.
For Windows Server 2016 and later this must be done prior to changing the service account.
Failure to do so will render servers non-functional.

.EXAMPLE
Add-AdfsServiceAccountRule -ServiceAccount newAccount
Add-AdfsServiceAccountRule -ServiceAccoount MyDomain\newAccount
Add-AdfsServiceAccountRule -ServiceAccount newAccount -SecondaryServers server1, server2

#>

function Add-AdfsServiceAccountRule
{
    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='High')]
    param
    (
        [parameter(Mandatory=$true, Position=1)]
        [string]$ServiceAccount,

        [parameter(ValueFromPipeline=$True)]
        [string[]]$SecondaryServers
    )

    #Receive user confirmation
    if(-not $PSCmdlet.ShouldProcess("A write to the AD FS configuration database will occur", "This script will write directly to the AD FS configuration database. Are you sure you want to proceed?", "Confrim"))
    {
        Write-Host "Terminating execution of script"
        return $false
    }

    Update-AdfsServiceAccountRule -ServiceAccount $ServiceAccount -SecondaryServers $SecondaryServers
}


<#
.SYNOPSIS
Module deletes rule permitting the speciifed service account from the AD FS rule set.
This can be used to disable the old service account on Windows Server 2016 and later.
This comand should only be run once the service account has been successfully changed.

.EXAMPLE
Remove-AdfsServiceAccountRule -ServiceAccount newAccount
Remove-AdfsServiceAccountRule -ServiceAccoount MyDomain\newAccount
Remove-AdfsServiceAccountRule -ServiceAccount newAccount -SecondaryServers server1, server2

#>
function Remove-AdfsServiceAccountRule
{
    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='High')]
    param
    (
        [parameter(Mandatory=$true, Position=1)]
        [string]$ServiceAccount,

        [parameter(ValueFromPipeline=$True)]
        [string[]]$SecondaryServers
    )

    #Receive user confirmation
    if(-not $PSCmdlet.ShouldProcess("A write to the AD FS configuration database will occur", "This script will write directly to the AD FS configuration database. Are you sure you want to proceed?", "Confrim"))
    {
        Write-Host "Terminating execution of script"
        return $false
    }

    Update-AdfsServiceAccountRule -ServiceAccount $ServiceAccount -SecondaryServers $SecondaryServers -RemoveRule
}

<#
.SYNOPSIS
Module changes the AD FS service account.
The script must be run locally on all seconodary servers first before running on the primary server.
For Windows Server 2016 and later, Add-AdfsServiceAccountRule should be run prior the execution of this command

.EXAMPLE
Update-AdfsServiceAccount

#>
function Update-AdfsServiceAccount 
{
    $ErrorActionPreference = "silentlycontinue" 
    $MachineFQDN = [System.Net.Dns]::GetHostEntry([System.Net.Dns]::GetHostName()).HostName 
    $MachineDomainSlash = ((((($MachineFQDN).ToString()).Split(".",2)[1])+"\"+((($MachineFQDN).ToString()).Split(".",2)[0])).ToUpper()) 
    #check for Vista, 7, or 8 
    $OSVersion = [System.Environment]::OSVersion.Version 
  
    # Show header, show AS-IS statement, detail sample changes made, prompt if ready to continue 
    Write-Host "`n IMPORTANT: This sample is provided AS-IS with no warranties and confers no rights." -ForegroundColor "yellow" 
    Write-Host "`n This sample is intended only for Federation Server farms. If your AD FS 2.x deployment type is Standalone," -ForegroundColor "yellow" 
    Write-Host " this sample does not apply to your Federation Service." -ForegroundColor "yellow" 
    Write-Host "`n The following changes will occur as a result of executing this sample:`n`t1. The AD FS service will be stopped" 
    write-host "`t2. The AD FS database permissions will be altered to allow access for the new account" 
    Write-Host "`t3. A servicePrincipalName registration will be removed from the old account and registered to the new account" 
    Write-Host "`t4. The AD FS service and AdfsAppPool identity will be changed to the new account" 
    Write-Host "`t5. Certificate private key permissions will be modified to allow access for the new account" 
    Write-Host "`t6. The new account will be allowed user rights: `"Log on as a service`" and `"Generate security audits`"" 
    Write-Host "`n PRE-EXECUTION TASKS" -ForegroundColor "yellow" 
    Write-Host " 1. Create the new service account in Active Directory" -ForegroundColor "yellow" 
    Write-Host " 2. Install SQLCmd.exe on each Federation Server in the farm" -ForegroundColor "yellow" 
    Write-Host "`tSQLCmd.exe requires the SQL Native Client to be installed" -ForegroundColor "yellow" 
    Write-Host "`tAfter SQLCmd.exe has been installed, all Powershell windows must be" -ForegroundColor "yellow" 
    Write-Host "`tclosed and re-opened to continue with execution of this sample." -ForegroundColor "yellow" 
    Write-Host "`n`tDownload both installers from the following location`:`n`thttp://www.microsoft.com/download/en/details.aspx?id=15748" -ForegroundColor "yellow" 
 
    Write-Host "`n If you are ready to proceed, type capital C and press Enter to continue: " -NoNewline 
    $Answer = "notready" 
    $LogPath = "$pwd\ADFS_Change_Service_Account.log" 
    $Answer = Read-Host 
 
    If ($Answer -cne "C")  
    {  
        Write-Host "`tExiting`n" -ForegroundColor "red" 
        ($ElapsedTime.Elapsed.ToString())+" [ERROR]     Bad selection at the prompt to continue with sample execution" | Out-File $LogPath 
        exit 
    } 
 
    #write timing info to the log file and start a stopwatch to capture elapsed time 
    "[START TIME] $(Get-Date)" | Out-File $LogPath 
    $ElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() 
    $OpMode1 = "Federation Server" 
    $OpMode2 = "Final Federation Server" 
 
    Write-Host "`n Note: The sample must be executed against each Federation Server in the farm." -ForegroundColor "yellow" 
    Write-Host " Windows Internal Database (WID) and SQL farms are supported. Before execution can" -ForegroundColor "yellow" 
    Write-Host " begin, an operating mode must be selected. Careful consideration of the following" -ForegroundColor "yellow" 
    Write-Host " guidance is necessary to ensure the sample is executed properly on each server." -ForegroundColor "yellow" 
    Write-Host "`n GUIDANCE FOR SELECTING AN OPERATING MODE:" -ForegroundColor "yellow" 
    Write-Host "`n WID FARM:`n The sample must be executed on all Secondary servers before execution should" -ForegroundColor "yellow" 
    Write-Host " occur on the Primary server. The Primary server is the only server with Write access to the" -ForegroundColor "yellow" 
    Write-Host " configuration database. The Primary server must be used as the 'Final Federation Server'" -ForegroundColor "yellow" 
    Write-Host "`n Powershell command to determine whether a server is Primary or Secondary:" -ForegroundColor "yellow" 
 
    #check for Vista, 7, or 8 
    $OSVersion = [System.Environment]::OSVersion.Version 
  
 
    If (($OSVersion.Major -lt 6) -or ( ($OSVersion.Major -eq 6) -and ($OSVersion.Minor -lt 3) )) 
    { 
      Write-Host "`tExiting`n" -ForegroundColor "red" 
      ($ElapsedTime.Elapsed.ToString())+" [ERROR]     This script is only applicable on Windows Server 2012 R2 and later" | Out-File $LogPath 
      exit 
    } 
 
    $feature = Get-WindowsFeature -Name ADFS-Federation 

    If( ($feature -eq $null) -or ($feature.Installed -eq $false) ) 
    { 
      Write-Host "`tExiting`n" -ForegroundColor "red" 
      ($ElapsedTime.Elapsed.ToString())+" [ERROR]     This script is only applicable on a machine where AD FS is already installed" | Out-File $LogPath 
      exit 
    } 
 
    Write-Host "`tImport-Module ADFS" -ForegroundColor "yellow" 
    Import-Module ADFS -ErrorAction Stop 
 
 
    Write-Host "`tGet-AdfsSyncProperties" -ForegroundColor "yellow" 
    Write-Host "`n SQL FARM:`n Any one server in the farm should be selected as the 'Final Federation Server'." -ForegroundColor "yellow" 
    Write-Host " All servers in a SQL farm have Write access to the configuration database. Execute the sample on all other" -ForegroundColor "yellow" 
    Write-Host " servers in the farm before executing the sample on the server selected as the 'Final Federation Server'" -ForegroundColor "yellow" 
 
 
    Write-Host "`n Select operating mode:`n`t1 - $OpMode1`n`t2 - $OpMode2" 
    ($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Getting operating mode" | Out-File $LogPath -Append 
 
    While (($Mode -ne 1) -and ($Mode -ne 2)) 
    { 
        $Mode = Read-Host "`tSelection" 
     
        If (($Mode -ne 1) -and ($Mode -ne 2)) 
        { 
            Write-Host "`t$Mode is not a valid selection" -ForegroundColor "yellow" 
        } 
    } 
 
    if ($Mode -eq 1) 
    { 
        $SelOpMode = $OpMode1 
    } 
    else 
    { 
        $SelOpMode = $OpMode2 
    } 
 
    Write-Host "`tOperating mode: $SelOpMode" -ForegroundColor "green" 
    ($ElapsedTime.Elapsed.ToString())+" [INFO]      Operating mode: $SelOpMode" | Out-File $LogPath -Append 
 
    # Check for the AD FS service 
 
    Write-Host " Checking the AD FS service" 
    ($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Checking for service installation (adfssrv)" | Out-File $LogPath -Append 
    $ADFSInstalled = Get-Service adfssrv 
 
    If (!$ADFSInstalled) 
    { 
        Write-Host "`tThe AD FS service was not found. Exiting`n" -ForegroundColor "red" 
        ($ElapsedTime.Elapsed.ToString())+" [ERROR]     adfssrv is not installed" | Out-File $LogPath -Append 
        Exit 
    } 
    Else 
    { 
        ($ElapsedTime.Elapsed.ToString())+" [INFO]      adfssrv is installed" | Out-File $LogPath -Append 
     
        # Check to see if adfssrv is running. If stopped, attempt to start. If start fails, exit. 
        If ($ADFSInstalled.Status -ceq "Stopped") 
        { 
            Write-Host "`tThe AD FS service is stopped. Starting the service`n" -ForegroundColor "yellow" -NoNewline 
            ($ElapsedTime.Elapsed.ToString())+" [WARN]      adfssrv is stopped. Attempting to start" | Out-File $LogPath -Append 
            $ADFSInstalled.Start() 
            $ADFSInstalled.WaitForStatus("Running",[System.TimeSpan]::FromSeconds(25)) 
         
            If (!$?) 
            { 
                Write-Host "`tThe AD FS service could not be started. Exiting" -ForegroundColor "red" 
                ($ElapsedTime.Elapsed.ToString())+" [ERROR]     adfssrv failed to start" | Out-File $LogPath -Append 
                Exit 
            } 
        } 
        Else 
        { 
            ($ElapsedTime.Elapsed.ToString())+" [INFO]      adfssrv is running" | Out-File $LogPath -Append 
        } 
       
        Write-Host "`tSuccess" -ForegroundColor "green" -NoNewline 
    } 
 
 
   
    # Check if Fed Svc Name equals machine FQDN. This is not supported for farms. Breaks Kerberos. 
    Write-Host "`n Checking the Federation Service Name" 
    ($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Checking Federation Service Name" | Out-File $LogPath -Append 
 
    $ADFSProperties = Get-ADFSProperties 
    $FederationServiceName = ((($ADFSProperties.HostName).ToString()).ToUpper()) 
 
    If ($FederationServiceName -eq $MachineFQDN) 
    { 
        Write-Host "`tFederation Service Name: $FederationServiceName`n`tFederation Service Name must not equal the qualified`n`tcomputer name in an AD FS farm." -ForegroundColor "red" 
        Write-Host "`thttp://social.technet.microsoft.com/wiki/contents/articles/ad-fs-2-0-how-to-change-the-federation-service-name.aspx" -ForegroundColor "gray" 
        Write-Host "`tExiting`n" -ForegroundColor "red" 
        ($ElapsedTime.Elapsed.ToString())+" [ERROR]     Federation Service Name: $FederationServiceName equals the qualified computer name. This is not supported in a farm deployment" | Out-File $LogPath -Append 
        ($ElapsedTime.Elapsed.ToString())+" [ERROR]     http://social.technet.microsoft.com/wiki/contents/articles/ad-fs-2-0-how-to-change-the-federation-service-name.aspx" | Out-File $LogPath -Append 
        Exit 
    } 
    Else 
    { 
        Write-Host "`tSuccess" -ForegroundColor "green" 
        ($ElapsedTime.Elapsed.ToString())+" [INFO]      Federation Service Name is OK" | Out-File $LogPath -Append 
    } 
 
    $CredsNotValidated = $true 
 
    While ($CredsNotValidated) 
    { 
        # Collect creds for new service account 
        $NewName = "foo" 
        While (($NewName -match " ") -or ($NewName -match "networkservice") -or ($NewName -match "localsystem") -or (($NewName -notmatch "\\") -and ($NewName -notmatch "`@"))) 
        { 
            Write-Host " Collecting credentials for the new account" 
            ($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Collecting new credentials" | Out-File $LogPath -Append 
            $NewName = (Read-Host "`tUsername (domain\user)").ToUpper() 
            ($ElapsedTime.Elapsed.ToString())+" [INFO]      New user name: $NewName" | Out-File $LogPath -Append 
     
            If (($NewName -match " ") -or ($NewName -match "networkservice") -or ($NewName -match "localsystem") -or (($NewName -notmatch "\\") -and ($NewName -notmatch "`@"))) 
            { 
                Write-Host "`t$NewName is not supported. AD FS farms require a domain user account (domain\user)" -ForegroundColor "red" 
                ($ElapsedTime.Elapsed.ToString())+" [ERROR]     Unsupported new name entry: $NewName. Service account must be domain user" | Out-File $LogPath -Append 
            } 
        } 
        $IsGmsaAccount = $NewName.EndsWith("$") 
        If($IsGmsaAccount) 
        { 
            $NewPassword = $null 
        } 
        Else 
        { 
            $NewPassword = Read-Host -assecurestring "`tPassword" 
        } 
        $objNewCreds = New-Object Management.Automation.PSCredential $NewName, $NewPassword 
        $NewPassword = $objNewCreds.GetNetworkCredential().Password 
   
        # Check for UPN style new name and convert to domain\username for SPN work items 
        If ($NewName.ToString() -match "`@") 
        { 
            $NewName = ((($NewName.Split("`@")[1]).ToString() + "\" + ($NewName.Split("`@")[0]).ToString()).ToUpper()) 
            Write-Host "`n`tUsing $NewName in order to meet SPN requirements" -ForegroundColor "gray" 
            ($ElapsedTime.Elapsed.ToString())+" [INFO]      Using $NewName in order to meet SPN requirements" | Out-File $LogPath -Append 
        } 
     
        // Do not validate creds for gMSA 
       
        If ($IsGmsaAccount) 
        { 
            Write-Host " gMSA account was specified. Skipping credential validation" 
            $CredsNotValidated = $false 
        } 
        Else 
        {  
   
            # Validating credentials 
            Write-Host " Validating credentials" 
            ($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Validating credentials" | Out-File $LogPath -Append 
            $Domain = "LDAP://" + ([ADSI]"").distinguishedName 
            $DomainObject = New-Object System.DirectoryServices.DirectoryEntry($Domain,$NewName,$NewPassword) 
 
            `$DomainObject.Name = `$DomainObject.Name 
            If ($DomainObject.Name -eq $null) 
            { 
                Write-Host "`tFailed credential validation" -ForegroundColor "red" 
                ($ElapsedTime.Elapsed.ToString())+" [ERROR]     Failed credential validation" | Out-File $LogPath -Append 
            } 
            Else 
            { 
                Write-Host "`tSuccess" -ForegroundColor "green" 
                ($ElapsedTime.Elapsed.ToString())+" [INFO]      Credentials validated" | Out-File $LogPath -Append 
                $CredsNotValidated = $false 
            } 
        } 
    } 
 
    # Getting current identity for the AD FS 2.x Windows Service 
 
    Write-Host " Discovering current account name" 
    ($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Getting old name" | Out-File $LogPath -Append 
    $ADFSSvc = gwmi win32_service -filter "name='adfssrv'" 
 
    If (!$ADFSSvc) 
    { 
        Write-Host "`tFailed to get the current account name. Exiting`n" -ForegroundColor "red" 
        ($ElapsedTime.Elapsed.ToString())+" [ERROR]     Could not get old name from WMI service information for adfssrv" | Out-File $LogPath -Append 
        exit 
    } 
    Else 
    { 
        $OldName = ((($ADFSSvc.StartName).ToString()).ToUpper()) 
        Write-Host "`t$OldName" -ForegroundColor "Green" -NoNewline 
        ($ElapsedTime.Elapsed.ToString())+" [INFO]      Old name: $OldName" | Out-File $LogPath -Append 
     
        If ($Mode -eq 2) 
        { 
            # Check for network service and local system and set a variable to use the domain\computername for SPN work items 
            If ((($OldName).ToString() -eq "NT AUTHORITY\NETWORK SERVICE") -or (($OldName).ToString() -eq "NT AUTHORITY\LOCAL SYSTEM")) 
            { 
                Write-Host "`tUsing $MachineDomainSlash in order to meet SPN requirements" -ForegroundColor "gray" 
                ($ElapsedTime.Elapsed.ToString())+" [INFO]      Using $MachineDomainSlash in order to meet SPN requirements" | Out-File $LogPath -Append 
                $UseMachineFQDN = $true 
            } 
           
            # Check for UPN style old name and convert to domain\username for SPN work items 
            If ($OldName.ToString() -match "`@") 
            { 
                $OldName = ($OldName.Split("`@")[1]).ToString() + "\" + ($OldName.Split("`@")[0]).ToString() 
                Write-Host "`tUsing $OldName in order to meet SPN requirements" -ForegroundColor "gray" 
                ($ElapsedTime.Elapsed.ToString())+" [INFO]      Using $OldName in order to meet SPN requirements" | Out-File $LogPath -Append 
            } 
        } 
    } 
   
    ####ADD NEEDED MODULES#### 
 
    $ADFSCertificate = Get-ADFSCertificate 
    $ADFSSyncProperties = Get-ADFSSyncProperties 
    $Role = (($ADFSSyncProperties.Role).ToString()) 

    $doc = new-object Xml
    $doc.Load("$env:windir\ADFS\Microsoft.IdentityServer.Servicehost.exe.config")
    $connString = $doc.configuration.'microsoft.identityServer.service'.policystore.connectionString
   
    ####STOP THE AD FS WINDOWS SERVICE#### 
    
    Write-Host "`n Stopping the AD FS service" 
    ($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Stopping adfssrv" | Out-File $LogPath -Append 
 
    # Stop the AD FS Windows service. No need to check status since Stop-Service does not throw if service is currently stopped. 
    $ADFSInstalled.Stop() 
    $ADFSInstalled.WaitForStatus("Stopped",[System.TimeSpan]::FromSeconds(15)) 
 
    If (!$?) 
    { 
        Write-Host "`tThe AD FS service could not be stopped.`n`tExiting`n" -ForegroundColor "red" 
        ($ElapsedTime.Elapsed.ToString())+" [ERROR]     adfssrv could not be stopped" | Out-File $LogPath -Append 
        exit 
    } 
    Else 
    { 
        Write-Host "`tSuccess" -ForegroundColor "green" -NoNewline 
        ($ElapsedTime.Elapsed.ToString())+" [INFO]      adfssrv is stopped" | Out-File $LogPath -Append 
    } 
 
    ####GETTING THE SQL HOST NAME#### 
 
    # Getting SQL host name 
    Write-Host "`n Discovering SQL host" 
    ($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Discovering SQL host" | Out-File $LogPath -Append 
    $SQLHost = (($connString.ToString()).split("=")[1]).Split(";")[0] 
    Write-Host "`t$SQLHost" -ForegroundColor "green" -NoNewline 
    ($ElapsedTime.Elapsed.ToString())+" [INFO]      SQL host: $SQLHost" | Out-File $LogPath -Append 
     
    ####DETECT DATABASE TYPE#### 
     
    # Detect WID or SQL 
    Write-Host "`n Detecting database type" 
    ($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Detecting database type" | Out-File $LogPath -Append 
     
    if((IsWid -ConnectionString $connString) -eq $true)
    {
        $DBMode = "WID" 
    }

    else
    {
        $DBMode = "SQL" 
    }
     
    Write-Host "`t$DBMode" -ForegroundColor "green" -NoNewline 
    ($ElapsedTime.Elapsed.ToString())+" [INFO]      Database type: $DBMode" | Out-File $LogPath -Append 
     
    #check to be sure that the admin isn't attempting a mode that isn't suitable for the current FS's role 
     
    If ($DBMode -eq "WID") 
    { 
        Write-Host "`n Checking operating mode against server role" 
        ($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Checking op mode against server role" | Out-File $LogPath -Append 
     
        If ((($Mode -eq 2) -and ($Role -eq "SecondaryComputer")) -or (($Mode -eq 1) -and ($Role -eq "PrimaryComputer"))) 
        { 
            Write-Host "`tError: Operating mode and role mismatch. Operating mode $Mode cannot be executed`n`ton a server with role $Role`n`tAction: Select a valid operating mode for this server.`n`tExiting" -ForegroundColor "Red" 
            ($ElapsedTime.Elapsed.ToString())+" [ERROR]     Op mode does not match server role. Mode: $Mode. Role: $Role" | Out-File $LogPath -Append 
            exit 
        } 
        Write-Host "`tSuccess" -ForegroundColor "Green" -NoNewline 
        ($ElapsedTime.Elapsed.ToString())+" [INFO]      Op mode matches server role" | Out-File $LogPath -Append 
    } 
     
    # Detect SQLCmd.exe, but not for secondary SQL 
     
    If (!(($Mode -eq 1) -and ($DBMode -eq "SQL"))) 
    { 
        Write-Host "`n Detecting SQLCmd.exe" 
        ($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Detecting SQLCMD.exe" | Out-File $LogPath -Append 
        $SQLCmdPresent = $false 
        sqlcmd.exe /? | Out-Null 
     
        If (!$?) 
        { 
            Write-Host "`tSQLCmd.exe was not found`n`tSee: POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY." -ForegroundColor "yellow" -NoNewline 
            ($ElapsedTime.Elapsed.ToString())+" [WARN]      SQLCMD.exe not found. SQL scripts must be manually executed." | Out-File $LogPath -Append 
        } 
        Else 
        { 
            Write-Host "`tSuccess" -ForegroundColor "green" -NoNewline 
            ($ElapsedTime.Elapsed.ToString())+" [INFO]      SQLCMD.exe found" | Out-File $LogPath -Append 
            $SQLCmdPresent = $true 
        } 
    } 
 
    ####CONVERTING NAMES TO SIDS#### 
    Write-Host "`n Converting $OldName to SID" 
    ($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Convert $OldName to SID" | Out-File $LogPath -Append 
     
    # Get SID for the old account into a variable 
    $OldSID = ConvertTo-Sid -Account $OldName 
     
    If (!$OldSID) 
    { 
        Write-Host "`tName to SID translation failed for `"$OldName`".`n`tExiting`n" -ForegroundColor "red" 
        ($ElapsedTime.Elapsed.ToString())+" [ERROR]     $OldName SID translation failed" | Out-File $LogPath -Append 
        exit 
    } 
    Else 
    { 
        Write-Host "`t$OldSID" -ForegroundColor "green" -NoNewline 
        ($ElapsedTime.Elapsed.ToString())+" [INFO]      Old SID: $OldSID" | Out-File $LogPath -Append 
    } 
       
    Write-Host "`n Converting $NewName to SID" 
    ($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Convert $NewName to SID" | Out-File $LogPath -Append 
 
    #Get SID for the new account into a variable 
    $NewSID = ConvertTo-Sid -Account $NewName 
     
    If (!$NewSID) 
    { 
        Write-Host "`tName to SID translation failed for `"$NewName`".`n`tEnsure that the new service account name is typed correctly. Exiting`n" -ForegroundColor "red" 
        ($ElapsedTime.Elapsed.ToString())+" [ERROR]     $NewName SID translation failed" | Out-File $LogPath -Append 
                exit 
    } 
    Else 
    { 
        Write-Host "`t$NewSID" -ForegroundColor "green" -NoNewline 
        ($ElapsedTime.Elapsed.ToString())+" [INFO]      New SID: $NewSID" | Out-File $LogPath -Append 
    } 
       
    If ($NewSID -eq $OldSID) 
    { 
        Write-Host "`n The old and new accounts are the same, do you wish to proceed?" -ForegroundColor "yellow" 
        $SameAccountAnswer = Read-Host "`t(Y/N)" 
         
        If ($SameAccountAnswer -ne "y") 
        { 
            Write-Host "`tExiting`n" -ForegroundColor "red" 
            Exit 
        } 
    } 
       
    ####GENERATE SQL SCRIPTS, BUT NOT FOR SECONDARY SQL#### 
       
    If (!(($Mode -eq 1) -and ($DBMode -eq "SQL"))) 
    { 
        $GenerateSQLScripts = GenerateSQLScripts 
        If (!$GenerateSQLScripts) 
        { 
            exit 
        } 
        Else 
        { 
            Write-Host "`tSuccess" -ForegroundColor "green" -NoNewline 
            ($ElapsedTime.Elapsed.ToString())+" [INFO]      SQL scripts generated" | Out-File $LogPath -Append 
        } 
    } 
 
    ####PERFORM ACTIONS FOR SQL DATABASE TYPE#### 
     
    if (($DBMode -eq "SQL") -and ($Mode -eq 2)) 
    { 
        Write-Host "`n Does the currently logged on user have administrative access to the AD FS databases within SQL server`?" 
        ($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Discovering if current user is SQL admin" | Out-File $LogPath -Append 
        $SQLAnswser = "foo" 
                 
        while (($SQLAnswer -ne "Y") -and ($SQLAnswer -ne "N")) 
        { $SQLAnswer = Read-Host "`t(Y/N)" } 
             
        ($ElapsedTime.Elapsed.ToString())+" [INFO]      SQL admin answer: $SQLAnswer" | Out-File $LogPath -Append 
         
        # If the user has permissions in SQL and SQLCmd.exe is present, run the scripts, otherwise, explain how they must perform this step manually. 
           if (($SQLAnswer -eq "Y") -and ($SQLCmdPresent)) 
           { 
                Write-Host " Executing SQL scripts" 
                ($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Executing SQL scripts using SQLCMD.exe" | Out-File $LogPath -Append 
                $ExecuteSQLScripts = ExecuteSQLScripts 
             
                If (!$ExecuteSQLScripts) 
                { 
                    exit 
                } 
                Else 
                { 
                    Write-Host "`tSuccess" -ForegroundColor "green" -NoNewline 
                    ($ElapsedTime.Elapsed.ToString())+" [INFO]      SQL scripts executed successfully" | Out-File $LogPath -Append 
                } 
            } 
            else 
            { 
                $NeedsSQLWarning = $true 
                ($ElapsedTime.Elapsed.ToString())+" [WARN]      Admin must execute SQL scripts manually:" | Out-File $LogPath -Append 
                ($ElapsedTime.Elapsed.ToString())+" [WARN]      sqlcmd.exe -S $SQLHost -i $env:Temp\ADFSSQLScripts\SetPermissions.sql -o $env:Temp\ADFSSQLScripts\SetPermissions-output.log,0,True" | Out-File $LogPath -Append 
                ($ElapsedTime.Elapsed.ToString())+" [WARN]      sqlcmd.exe -S $SQLHost -i $env:Temp\ADFSSQLScripts\UpdateServiceSettings.sql -o $env:Temp\ADFSSQLScripts\UpdateServiceSettings-output.log,0,True" | Out-File $LogPath -Append 
 
            } 
        } 
         
        If ($DBMode -eq "WID") 
        { 
     
            ####PERFORM STEPS FOR WID DATABASE TYPE#### 
     
            # We don't care if they are an admin in SQL Server, so only need to check to see if SQLCmd.exe is installed. Run the scripts, otherwise, explain how they must perform steps manually 
            if ($SQLCmdPresent) 
            { 
                Write-Host "`n Executing SQL scripts" 
                ($ElapsedTime.Elapsed.ToString())+" [INFO]      Executing SQL scripts using SQLCMD.exe" | Out-File $LogPath -Append 
                $ExecuteSQLScripts = ExecuteSQLScripts 
             
                If (!$ExecuteSQLScripts) 
                { 
                    exit 
                } 
                Else 
                { 
                    Write-Host "`tSuccess" -ForegroundColor "green" -NoNewline 
                    ($ElapsedTime.Elapsed.ToString())+" [INFO]      SQL scripts executed successfully" | Out-File $LogPath -Append 
                } 
            } 
            else 
            { 
                $NeedsSQLWarning = $true 
            } 
        } 
   
     
        If ($Mode -eq 2) 
        { 
            ####REMOVE THE SPN FROM THE OLD SERVICE ACCOUNT#### 
       
            If ($UseMachineFQDN) 
            { 
                Write-Host "`n Removing SPN HOST/$FederationServiceName from $MachineDomainSlash" 
                ($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Removing SPN HOST/$FederationServiceName from $MachineDomainSlash" | Out-File $LogPath -Append 
               setspn.exe -D HOST/$FederationServiceName $MachineDomainSlash | Out-File $LogPath -Append 
         
                If (!$?) 
                { 
                    Write-Host "`tRemoving SPN failed`n`tSee: POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY." -ForegroundColor "yellow" -NoNewline 
                    ($ElapsedTime.Elapsed.ToString())+" [WARN]      Removing SPN failed: HOST/$FederationServiceName from $MachineDomainSlash" | Out-File $LogPath -Append 
                    ($ElapsedTime.Elapsed.ToString())+" [WARN]      setspn.exe -D HOST/$FederationServiceName $MachineDomainSlash" | Out-File $LogPath -Append 
                    $FailedSpn = $true 
                } 
                Else 
                { 
                    Write-Host "`tSuccess" -ForegroundColor "green" -NoNewline 
                    ($ElapsedTime.Elapsed.ToString())+" [INFO]      SPN removed: HOST/$FederationServiceName from $MachineDomainSlash" | Out-File $LogPath -Append 
                } 
            } 
            Else 
            { 
                Write-Host "`n Removing SPN HOST/$FederationServiceName from $OldName" 
                ($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Removing SPN HOST/$FederationServiceName from $OldName" | Out-File $LogPath -Append 
                setspn.exe -D HOST/$FederationServiceName $OldName | Out-File $LogPath -Append 
         
                If (!$?) 
                { 
                    Write-Host "`tRemoving SPN failed`n`tSee: POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY" -ForegroundColor "yellow" -NoNewline 
                    ($ElapsedTime.Elapsed.ToString())+" [WARN]      Removing SPN failed: HOST/$FederationServiceName from $OldName" | Out-File $LogPath -Append 
                    ($ElapsedTime.Elapsed.ToString())+" [WARN]      setspn.exe -D HOST/$FederationServiceName $OldName" | Out-File $LogPath -Append 
                    $FailedSpn = $true 
                } 
                Else 
                { 
                    Write-Host "`tSuccess" -ForegroundColor "green" -NoNewline 
                    ($ElapsedTime.Elapsed.ToString())+" [INFO]      SPN removed: HOST/$FederationServiceName from $OldName" | Out-File $LogPath -Append 
                } 
            } 
 
            ####ADD THE SPN TO THE NEW SERVICE ACCOUNT#### 
     
            Write-Host "`n Registering SPN HOST/$FederationServiceName to $NewName" 
            ($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Registering SPN HOST/$FederationServiceName to $NewName" | Out-File $LogPath -Append 
            setspn.exe -S HOST/$FederationServiceName $NewName | Out-File $LogPath -Append 
 
            If (!$?) 
            { 
                Write-Host "`tRegistering SPN failed`n`tSee: POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY" -ForegroundColor "yellow" -NoNewline 
                ($ElapsedTime.Elapsed.ToString())+" [WARN]      Registering SPN failed: HOST/$FederationServiceName to $NewName" | Out-File $LogPath -Append 
                ($ElapsedTime.Elapsed.ToString())+" [WARN]      setspn.exe -S HOST/$FederationServiceName $NewName" | Out-File $LogPath -Append 
                $FailedSpn = $true 
            } 
            Else 
            { 
                Write-Host "`tSuccess" -ForegroundColor "green" -NoNewline 
                ($ElapsedTime.Elapsed.ToString())+" [INFO]      SPN registered: HOST/$FederationServiceName to $NewName" | Out-File $LogPath -Append 
            } 
        } 
 
    ####SET THE IDENTITY OF THE AD FS WINDOWS SERVICE TO THE NEW SERVICE ACCOUNT#### 
 
    # Setting identity for the AD FS Windows Service to the new service account 
    Write-Host "`n Setting the AD FS service identity to $NewName" 
    ($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Setting new service identity for adfssrv to $NewName" | Out-File $LogPath -Append 
 
    $ADFSSvc = gwmi win32_service -filter "name='adfssrv'" 
 
    If (!$ADFSSvc) 
    { 
        Write-Host "`tFailed to get information about the AD FS service." -ForegroundColor "yellow" -NoNewline 
        ($ElapsedTime.Elapsed.ToString())+" [WARN]      Failed to get WMI information for adfssrv from WMI" | Out-File $LogPath -Append 
    } 
 
    $ADFSSvc.Change($null,$null,$null,$null,$null,$null,$NewName,$NewPassword,$null,$null,$null) | Out-Null 
 
    If (!$?) 
    { 
        Write-Host "`tFailed to set the identity of the AD FS service`n`tSee: POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY" -ForegroundColor "yellow" -NoNewline 
        ($ElapsedTime.Elapsed.ToString())+" [WARN]      Failed to set identity for adfssrv to $NewName" | Out-File $LogPath -Append 
        $FailedServiceIdentity = $true 
    } 
    Else 
    { 
        Write-Host "`tSuccess" -ForegroundColor "green" -NoNewline 
        ($ElapsedTime.Elapsed.ToString())+" [INFO]      Set identity of adfssrv to $NewName" | Out-File $LogPath -Append 
    } 
 
    If ( !$FailedServiceIdentity ) 
    { 
        # If the service account was gMSA, and you are running on a DC, add service dependency on kdssvc, otherwise remove the dependency on kdssvc 
        $kdssvc = Get-Service -Name "kdssvc" 
        If( ( $kdssvc -ne $null ) -and $IsGmsaAccount ) 
        { 
            Write-Host "`n Setting HTTP/KdsSvc as a service dependency for ADFS Service" 
            ($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Setting HTTP/KdsSvc as a service dependency for adfssrv" | Out-File $LogPath -Append 
            Start sc.exe -ArgumentList "config adfssrv depend=HTTP/KdsSvc" -Wait -WindowStyle Hidden | Out-File $LogPath -Append 
        } 
        Else 
        { 
            Write-Host "`n Adding HTTP as a service dependency for ADFS Service" 
            ($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Setting HTTP as a service dependency for adfssrv" | Out-File $LogPath -Append 
            Start sc.exe -ArgumentList "config adfssrv depend=HTTP" -Wait -WindowStyle Hidden | Out-File $LogPath -Append 
        } 
    } 
 
    ####ACL THE CERTIFICATE SHARING CONTAINER FOR THE NEW SERVICE ACCOUNT#### 
 
    # Only execute if this is the first federation server 
    if ($Mode -eq 2) 
    { 
        # Check if CertificateSharingContainer has a value. If it does, ACL the container for the new service account. 
        If ($ADFSProperties.CertificateSharingContainer -ne $null) 
        { 
            Write-Host "`n Providing $NewName access to the Certificate Sharing Container" 
            ($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Providing $NewName access to ($ADFSProperties.CertificateSharingContainer).ToString()" | Out-File $LogPath -Append 
            Set-CertificateSharingContainerSecurity -NewSID $NewSID 
        } 
    } 
   
    ####ADD USER RIGHTS#### 
 
    Write-Host "`n Adding user rights for $NewName" 
    ($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Adding user rights for $NewName" | Out-File $LogPath -Append 
 
    # Execute for all opmodes 
    $FailedUserRights = AddUserRights 
 
    ####START THE AD FS WINDOWS SERVICE#### 
    
    Write-Host "`n Starting the AD FS service" 
    ($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Starting adfssrv" | Out-File $LogPath -Append 
 
    #check to see if SQL scripts need run. If yes, skip this step 
    If (($Mode -eq 1) -or $NeedsSQLWarning -or $FailedLdap -or $FailedServiceIdentity -or $FailedServiceStart -or $FailedSpn -or $FailedUserRights) 
    { 
        Write-Host "`tSkipped`n`tSee: POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY" -ForegroundColor "yellow" 
        ($ElapsedTime.Elapsed.ToString())+" [WARN]      Skipped starting adfssrv due to post-sample needs" | Out-File $LogPath -Append 
        $SkipServiceStart = $true 
    } 
    Else 
    { 
        # Start the AD FS Windows service. No need to check status since Start-Service does not throw if service is currently started. 
        $ADFSInstalled.Start() 
        $ADFSInstalled.WaitForStatus("Running",[System.TimeSpan]::FromSeconds(25)) 
 
        If (!$?) 
        { 
            Write-Host "`tFailed: The AD FS service could not be started.`n`tExamine the AD FS 2.0/Admin and AD FS 2.0 Tracing/Debug event logs for details." -ForegroundColor "red" 
            ($ElapsedTime.Elapsed.ToString())+" [ERROR]     adfssrv service failed to start. See Admin and Debug logs for details." | Out-File $LogPath -Append 
            $FailedServiceStart = $true 
        } 
        Else 
        { 
            Write-Host "`tSuccess" -ForegroundColor "green" 
            ($ElapsedTime.Elapsed.ToString())+" [INFO]      adfssrv started" | Out-File $LogPath -Append 
        } 
    } 
 
    ####NOTIFY ABOUT MANUALLY SETTING ITEMS 
 
    $NotifyCount = 1 
    Write-Host "`n`n`n POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY" -ForegroundColor "yellow" 
    "`n`n`n POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY" | Out-File $LogPath -Append 
 
    If ($FailedUserRights) 
    { 
        Write-Host "`n`n $NotifyCount. You must manually set User Rights Assigment for $NewName" -ForegroundColor "yellow" 
        Write-Host "    to allow `"Generate Security Audits`" and `"Log On As a Service`"." -ForegroundColor "yellow" 
        Write-Host "`n    Steps:`n    Start -> Run -> GPEdit.msc -> Computer Configuration -> Windows Settings ->" -ForegroundColor "yellow" 
        Write-Host "    Security Settings -> Local Policies -> User Rights Assignment" -ForegroundColor "yellow" 
        "`n`n $NotifyCount. You must manually set User Rights Assigment for $NewName" | Out-File $LogPath -Append 
        "    to allow `"Generate Security Audits`" and `"Log On As a Service`"." | Out-File $LogPath -Append 
        "`n    Steps:`n    Start -> Run -> GPEdit.msc -> Computer Configuration -> Windows Settings ->" | Out-File $LogPath -Append 
        "    Security Settings -> Local Policies -> User Rights Assignment" | Out-File $LogPath -Append 
        $NotifyCount += 1 
    } 
 
    If ($FailedLdap) 
    { 
        Write-Host "`n`n $NotifyCount. $NewName must have Read, Write, and Create Child permissions to the certificate" -ForegroundColor "yellow" 
        Write-Host "    sharing container in AD. These permissions were not set during execution and must be set manually." -ForegroundColor "yellow" 
        Write-Host "    LDAP path: $DN" -ForegroundColor "yellow" 
     
        "`n`n $NotifyCount. $NewName must have Read, Write, and Create Child permissions to the certificate" | Out-File $LogPath -Append 
        "    sharing container in AD. These permissions were not set during execution and must be set manually." | Out-File $LogPath -Append 
        "    LDAP path: $DN" | Out-File $LogPath -Append 
        $NotifyCount += 1 
    } 
 
    If ($NeedsSQLWarning) 
    { 
        If ($DBMode -eq "SQL") 
        { 
            Write-Host "`n`n $NotifyCount. Either the currently logged on user does not have appropriate permissions on the SQL Server," -ForegroundColor "yellow" 
            Write-Host "    or SQLCmd.exe was not found on this system. You must provide your SQL DBA with the SetPermissions.sql" -ForegroundColor "yellow" 
            Write-Host "    and UpdateServiceSettings.sql fileslocated in $env:Temp\ADFSSQLScripts." -ForegroundColor "yellow" 
            Write-Host "    The DBA should execute these scripts on the SQL Server where the AD FS" -ForegroundColor "yellow" 
            Write-Host "    Configuration and Artifact databases reside." -ForegroundColor "yellow" 
            Write-Host "`n    Syntax:" -ForegroundColor "yellow"  
            Write-Host "    sqlcmd.exe -S $SQLHost -i $env:Temp\ADFSSQLScripts\SetPermissions.sql" -ForegroundColor "yellow" 
            Write-Host "    -o $env:Temp\ADFSSQLScripts\SetPermissions-output.log" -ForegroundColor "yellow" 
            Write-Host "`n    sqlcmd.exe -S $SQLHost -i $env:Temp\ADFSSQLScripts\UpdateServiceSettings.sql" -ForegroundColor "yellow" 
            Write-Host "    -o $env:Temp\ADFSSQLScripts\UpdateServiceSettings-output.log" -ForegroundColor "yellow" 
     
            "`n`n $NotifyCount. Either the currently logged on user does not have appropriate permissions on the SQL Server," | Out-File $LogPath -Append 
            "    or SQLCmd.exe was not found on this system. You must provide your SQL DBA with the SetPermissions.sql" | Out-File $LogPath -Append 
            "    and UpdateServiceSettings.sql fileslocated in $env:Temp\ADFSSQLScripts. The DBA should execute these" | Out-File $LogPath -Append 
            "    scripts on the SQL Server where the AD FS Configuration and Artifact databases reside." | Out-File $LogPath -Append 
            "`n    Syntax:" | Out-File $LogPath -Append 
            "    sqlcmd.exe -S $SQLHost -i $env:Temp\ADFSSQLScripts\SetPermissions.sql -o" | Out-File $LogPath -Append 
            "    $env:Temp\ADFSSQLScripts\SetPermissions-output.log" | Out-File $LogPath -Append 
            "`n    sqlcmd.exe -S $SQLHost -i $env:Temp\ADFSSQLScripts\UpdateServiceSettings.sql -o" | Out-File $LogPath -Append 
            "    $env:Temp\ADFSSQLScripts\UpdateServiceSettings-output.log" | Out-File $LogPath -Append 
        } 
        Else 
        { 
            Write-Host "`n`n $NotifyCount. SQLCmd.exe was not found on this system. The SQL scripts must be executed" -ForegroundColor "yellow" 
            Write-Host "    manually using either SQL Management Studio or SQLCmd.exe. The scripts currently reside" -ForegroundColor "yellow" 
            Write-Host "    in $env:Temp\ADFSSQLScripts." -ForegroundColor "yellow" 
            Write-Host "`n    Syntax:" -ForegroundColor "yellow"  
            Write-Host "    sqlcmd.exe -S $SQLHost -i $env:Temp\ADFSSQLScripts\SetPermissions.sql" -ForegroundColor "yellow" 
            Write-Host "    -o $env:Temp\ADFSSQLScripts\SetPermissions-output.log" -ForegroundColor "yellow" 
            Write-Host "`n    sqlcmd.exe -S $SQLHost -i $env:Temp\ADFSSQLScripts\UpdateServiceSettings.sql" -ForegroundColor "yellow" 
            Write-Host "    -o $env:Temp\ADFSSQLScripts\UpdateServiceSettings-output.log" -ForegroundColor "yellow" 
     
            "`n`n $NotifyCount. Either the currently logged on user does not have appropriate permissions on the SQL Server," | Out-File $LogPath -Append 
            "    or SQLCmd.exe was not found on this system. You must provide your SQL DBA with the SetPermissions.sql" | Out-File $LogPath -Append 
            "    and UpdateServiceSettings.sql fileslocated in $env:Temp\ADFSSQLScripts. The DBA should execute these" | Out-File $LogPath -Append 
            "    scripts on the SQL Server where the AD FS Configuration and Artifact databases reside." | Out-File $LogPath -Append 
            "`n    Syntax:" | Out-File $LogPath -Append 
            "    sqlcmd.exe -S $SQLHost -i $env:Temp\ADFSSQLScripts\SetPermissions.sql -o" | Out-File $LogPath -Append 
            "    $env:Temp\ADFSSQLScripts\SetPermissions-output.log" | Out-File $LogPath -Append 
            "`n    sqlcmd.exe -S $SQLHost -i $env:Temp\ADFSSQLScripts\UpdateServiceSettings.sql -o" | Out-File $LogPath -Append 
            "    $env:Temp\ADFSSQLScripts\UpdateServiceSettings-output.log" | Out-File $LogPath -Append 
        } 
         
        $NotifyCount += 1 
    } 
   
    If ($FailedSpn) 
    { 
        Write-Host "`n`n $NotifyCount. $NewName must have the SPN HOST/$FederationServiceName registered.`n    SPN registration failed during execution and must be handled manually.`n" -ForegroundColor "yellow" 
        Write-Host "    Syntax:`n    setspn -S HOST/$FederationServiceName $NewName" -ForegroundColor "yellow" 
     
        "`n`n $NotifyCount. $NewName must have the SPN HOST/$FederationServiceName registered.`n    SPN registration failed during execution and must be handled manually.`n" | Out-File $LogPath -Append 
        "    Syntax:`n    setspn -S HOST/$FederationServiceName $NewName" | Out-File $LogPath -Append 
        $NotifyCount += 1 
    } 
   
    If ($FailedServiceIdentity) 
    { 
        Write-Host "`n`n $NotifyCount. Failed setting the AD FS service identity to $NewName during execution.`n    This must be set manually in the Services console." -ForegroundColor "yellow" 
     
        "`n`n $NotifyCount. Failed setting the AD FS service identity to $NewName during execution.`n    This must be set manually in the Services console." | Out-File $LogPath -Append 
        $NotifyCount += 1 
    } 
   
    If ($Mode -eq 1) 
    { 
        Write-Host "`n`n $NotifyCount. Operating Mode $Mode was selected for this server, which means this sample must be executed`n    in Operating Mode 2 on the final server before the AD FS service is started on this server.`n    Once the sample has been run on the final server in Operating Mode 2, return to this server`n    to start the AD FS service." -ForegroundColor "yellow" 
        "`n`n $NotifyCount. Operating Mode $Mode was selected for this server, which means this sample must be executed`n    in Operating Mode 2 on the final server before the AD FS service is started on this server.`n    Once the sample has been run on the final server in Operating Mode 2, return to this server`n    to start the AD FS service." | Out-File $LogPath -Append 
        $NotifyCount += 1 
    } 
   
    If ($SkipServiceStart) 
    { 
        Write-Host "`n`n $NotifyCount. Service start was skipped during execution due to post-sample needs. The service must be manually started.`n`n    Syntax:`n    net start adfssrv" -ForegroundColor "yellow" 
     
        "`n`n $NotifyCount. Service start was skipped during execution due to post-sample needs.`n    The service must be manually started." | Out-File $LogPath -Append 
        $NotifyCount += 1 
    } 
   
    If ($FailedServiceStart) 
    { 
        Write-Host "`n`n $NotifyCount. Failed service start during execution.`n    The service must be manually started." -ForegroundColor "yellow" 
        Write-Host "    Syntax: net start adfssrv" -ForegroundColor "yellow" 
     
        "`n`n $NotifyCount. Failed service start during execution.`n    The service must be manually started." | Out-File $LogPath -Append 
        "    Syntax: net start adfssrv" | Out-File $LogPath -Append 
        $NotifyCount += 1 
    } 
   
    If ($NotifyCount -eq 1) 
    { 
        Write-Host "`n No post-sample items" -ForegroundColor "green" 
        "No post-sample items" | Out-File $LogPath -Append 
    } 

    Write-Host "`n`n It is recommended the old service account $OldName be deletd once the service account has been changed on all servers.`n" -ForegroundColor "yellow"
 
    Write-Host "`n`n Sample completed successfully. See ADFS_Change_Service_Account.log in the current directory for detail`n" -ForegroundColor "green" 
    "[END TIME] $(Get-Date)" | Out-File $LogPath -Append 
 
    $ErrorActionPreference = "continue" 
}

Export-ModuleMember -Function Add-AdfsServiceAccountRule
Export-ModuleMember -Function Remove-AdfsServiceAccountRule
Export-ModuleMember -Function Update-AdfsServiceAccount
Export-ModuleMember -Function Restore-AdfsSettingsFromBackup

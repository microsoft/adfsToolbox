# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# ----------------------------------------------------
#
# Global Constants
#
# ----------------------------------------------------

$script:CONST_ADFS_ADMIN = "AD FS"
$script:CONST_ADFS_AUDIT = "AD FS Auditing"
$script:CONST_ADFS_DEBUG = "AD FS Tracing"

$script:CONST_SECURITY_LOG = "security"
$script:CONST_ADMIN_LOG = "AD FS/Admin"
$script:CONST_DEBUG_LOG = "AD FS Tracing/Debug"

$script:CONST_LOG_PARAM_SECURITY = "security"
$script:CONST_LOG_PARAM_ADMIN = "admin"
$script:CONST_LOG_PARAM_DEBUG = "debug"

$script:CONST_AUDITS_TO_AGGREGATE = @( 299, 324, 403, 404, 412)
$script:CONST_AUDITS_LINKED = @(500, 501, 502, 503, 510)
$script:CONST_TIMELINE_AUDITS = @(299, 324, 403, 411, 412)

# TODO: PowerShell is not good with JSON objects. Headers should be {}. 
$script:REQUEST_OBJ_TEMPLATE = '{"num": 0,"time": "1/1/0001 12:00:00 AM","protocol": "","host": "","method": "","url": "","query": "","useragent": "","server": "","clientip": "","contlen": 0,"headers": [],"tokens": [],"ver": "1.0"}'
$script:RESPONSE_OBJ_TEMPLATE = '{"num": 0,"time": "1/1/0001 12:00:00 AM","result": "","headers": {},"tokens": [],"ver": "1.0"}'
$script:ANALYSIS_OBJ_TEMPLATE = '{"requests": [],"responses": [],"errors": [],"timeline": [],"ver": "1.0"}'
$script:ERROR_OBJ_TEMPLATE = '{"time": "1/1/0001 12:00:00 AM","eventid": 0,"level": "", "message": [],"ver": "1.0"}'
$script:TIMELINE_OBJ_TEMPLATE = '{"time": "","type": "", "tokentype": "", "rp": "","result": "","stage": 0,"ver": "1.0"}'
$script:TOKEN_OBJ_TEMPLATE = '{"num": 0,"type": "","rp": "","user": "","direction": "","claims": [],"oboclaims": [],"actasclaims": [],"ver": "1.0"}'

$script:TIMELINE_INCOMING = "incoming"
$script:TIMELINE_AUTHENTICATION = "authn"
$script:TIMELINE_AUTHORIZATION = "authz"
$script:TIMELINE_ISSUANCE = "issuance"
$script:TIMELINE_SUCCESS = "success"
$script:TIMELINE_FAILURE = "fail"

$script:TOKEN_TYPE_ACCESS = "access_token"

$script:CONST_ADFS_HTTP_PORT = 0
$script:CONST_ADFS_HTTPS_PORT = 0

$script:DidLoadPorts = $false






# ----------------------------------------------------
#
# Helper Functions - Querying 
#
# ----------------------------------------------------

function Enable-ADFSAuditing
{
    param(
        [parameter(Mandatory=$False)]
        [string[]]$Server="LocalHost"
    )

    <#
    .SYNOPSIS
	This script enables ADFS verbose related events from the security, admin, and debug logs.

    .DESCRIPTION
	To track ADFS authentication processing there are multiple items which must be enabled on the ADFS server(s). This function provides automation in 
    enabling those items. Specifically, this function enables 	ADFS sourced Security events in the Security event log, verbose events in the ADFS Admin log,
    and ADFS tracing events in the ADFS Tracing/Debug log. 

    Note that this function can only run the ADFS properties on remote servers, and not the OS trace log commands.
	
	EXAMPLE
     	Enable-ADFSAuditing
	#>

	$cs = get-wmiobject -class win32_computersystem -ComputerName "localhost"
	$DomainRole = $cs.domainrole

	#Check and add service account to auditing user right if needed
	$ADFSService = GWMI Win32_Service -Filter "name = 'adfssrv'" -ComputerName "localhost"
	$ADFSServiceAccount = $ADFSService.StartName
	$objUser = New-Object System.Security.Principal.NTAccount($ADFSServiceAccount) 
	$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier]) 
	$SvcAcctSID = $strSID.Value 
	$SecTempPath = $pwd.path + '\SecTempPath'
	if((test-path $SecTempPath) -eq $false){$SecPath = New-item -Path $SecTempPath -ItemType Directory} 
	$SecTempPath = $SecTempPath + "\secpol.cfg"
	$SeceditCmd = secedit /export /cfg $SecTempPath
	$OldSeSecPriv = Select-string -path $SecTempPath -pattern "SeAuditPrivilege"
	$OldSeSecPriv = $OldSeSecPriv.Line
	$NewSeSecPriv = $OldSeSecPriv  + ",*" + $SvcAcctSID
	(gc $SecTempPath).replace($OldSeSecPriv,$NewSeSecPriv) | Out-File -Filepath $SecTempPath 
	secedit /configure /db c:\windows\security\local.sdb /cfg $SecTempPath /areas SECURITYPOLICY 
	$RM = rm -force $SecTempPath -confirm:$false -ErrorAction SilentlyContinue
	gpupdate /force

	#Enable ADFS Tracing log
	$ADFSTraceLogName = "AD FS Tracing/Debug"
	$ADFSTraceLog = New-Object System.Diagnostics.Eventing.Reader.EventlogConfiguration $ADFSTraceLogName
	if($ADFSTraceLog.IsEnabled -ne $true)
	{
		$ADFSTraceLog.IsEnabled = $true
		$ADFSTraceLog.SaveChanges()
	}

    foreach($Machine in $Server)
    {
        Try
        {
            $Session = New-PSSession -ComputerName $Machine
            Set-ADFSAuditingRemote -Session $Session -Enable $True
            auditpol.exe /set /subcategory:"Application Generated" /failure:enable /success:enable
        }
        Catch
        {
            Write-Warning "Error enabling ADFS auditing settings on $Machine. Error: $_"
        }
        Finally
        {
            if($Session)
            {
                Remove-PSSession $Session
            }
        }
    }

	Write-Verbose "ADFS auditing is now enabled."
}

function Disable-ADFSAuditing
{
    param(
        [parameter(Mandatory=$False)]
        [string[]]$Server="LocalHost"
    )

	<#
    .SYNOPSIS
    This script disables ADFS verbose related events from the security, admin, and debug logs.

    .DESCRIPTION
	To track ADFS authentication processing there are multiple items which must be enabled on the ADFS server(s). This function provides 
    automation for disabling those items so that event logs do not fill up.
    
    Note that this function can only run the ADFS properties on remote servers, and not the OS trace log commands.
	
	EXAMPLE
    	Disable-ADFSAuditing
	#>
	
	#Disable ADFS Tracing log
	$ADFSTraceLogName = "AD FS Tracing/Debug"
	$ADFSTraceLog = New-Object System.Diagnostics.Eventing.Reader.EventlogConfiguration $ADFSTraceLogName
	if ($ADFSTraceLog.IsEnabled -ne $false)
	{
		$ADFSTraceLog.IsEnabled = $false
		$ADFSTraceLog.SaveChanges()
	}

	#Disable security auditing from ADFS
	$cs = get-wmiobject -class win32_computersystem -ComputerName "localhost"
	$DomainRole = $cs.domainrole

    foreach($Machine in $Server)
    {
        Try
        {
            $Session = New-PSSession -ComputerName $Machine
            Set-ADFSAuditingRemote -Session $Session -Enable $False
            auditpol.exe /set /subcategory:"Application Generated" /failure:disable /success:disable
        }
        Catch
        {
            Write-Warning "Error disabling ADFS auditing settings on $Machine. Error: $_"
        }
        Finally
        {
            if($Session)
            {
                Remove-PSSession $Session
            }
        }
    }

	Write-Verbose "ADFS auditing is now disabled."
}

function Set-ADFSAuditingRemote
{
    param(
        [Parameter(Mandatory=$True)]
        [System.Management.Automation.Runspaces.PSSession]$Session,
        
        [Parameter(Mandatory=$True)]
        [bool]$Enable
    )

    Invoke-Command -Session $Session -ScriptBlock {

        $OSVersion = gwmi win32_operatingsystem
        [int]$BuildNumber = $OSVersion.BuildNumber 

        if ( $BuildNumber -le 7601 )
        {
            Add-PsSnapin Microsoft.Adfs.Powershell -ErrorAction SilentlyContinue
        }else
        {
            Import-Module ADFS -ErrorAction SilentlyContinue
        }

        $SyncProps = Get-ADFSSyncProperties
        if ( $SyncProps.Role -ne 'SecondaryComputer' ) 
        {
            if ( $Enable )
            {
                Set-ADFSProperties -LogLevel  @( "FailureAudits", "SuccessAudits", "Warnings", "Verbose", "Errors", "Information")
                Set-ADFSProperties -AuditLevel Verbose
            }else{
                Set-ADFSProperties -LogLevel  @( "Warnings", "Errors", "Information" )
            }            
        }
    }
}

function Enable-ADFSAuditing
{
    param(
        [parameter(Mandatory=$False)]
        [string[]]$Server="LocalHost"
    )

    <#
    .SYNOPSIS
	This script enables ADFS verbose related events from the security, admin, and debug logs.

    .DESCRIPTION
	To track ADFS authentication processing there are multiple items which must be enabled on the ADFS server(s). This function provides automation in 
    enabling those items. Specifically, this function enables 	ADFS sourced Security events in the Security event log, verbose events in the ADFS Admin log,
    and ADFS tracing events in the ADFS Tracing/Debug log. 

    Note that this function can only run the ADFS properties on remote servers, and not the OS trace log commands.
	
	EXAMPLE
     	Enable-ADFSAuditing
	#>

	$cs = get-wmiobject -class win32_computersystem -ComputerName "localhost"
	$DomainRole = $cs.domainrole

	#Check and add service account to auditing user right if needed
	$ADFSService = GWMI Win32_Service -Filter "name = 'adfssrv'" -ComputerName "localhost"
	$ADFSServiceAccount = $ADFSService.StartName
	$objUser = New-Object System.Security.Principal.NTAccount($ADFSServiceAccount) 
	$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier]) 
	$SvcAcctSID = $strSID.Value 
	$SecTempPath = $pwd.path + '\SecTempPath'
	if((test-path $SecTempPath) -eq $false){$SecPath = New-item -Path $SecTempPath -ItemType Directory} 
	$SecTempPath = $SecTempPath + "\secpol.cfg"
	$SeceditCmd = secedit /export /cfg $SecTempPath
	$OldSeSecPriv = Select-string -path $SecTempPath -pattern "SeAuditPrivilege"
	$OldSeSecPriv = $OldSeSecPriv.Line
	$NewSeSecPriv = $OldSeSecPriv  + ",*" + $SvcAcctSID
	(gc $SecTempPath).replace($OldSeSecPriv,$NewSeSecPriv) | Out-File -Filepath $SecTempPath 
	secedit /configure /db c:\windows\security\local.sdb /cfg $SecTempPath /areas SECURITYPOLICY 
	$RM = rm -force $SecTempPath -confirm:$false -ErrorAction SilentlyContinue
	gpupdate /force

	#Enable ADFS Tracing log
	$ADFSTraceLogName = "AD FS Tracing/Debug"
	$ADFSTraceLog = New-Object System.Diagnostics.Eventing.Reader.EventlogConfiguration $ADFSTraceLogName
	if($ADFSTraceLog.IsEnabled -ne $true)
	{
		$ADFSTraceLog.IsEnabled = $true
		$ADFSTraceLog.SaveChanges()
	}

    foreach($Machine in $Server)
    {
        Try
        {
            $Session = New-PSSession -ComputerName $Machine
            Set-ADFSAuditingRemote -Session $Session -Enable $True
            auditpol.exe /set /subcategory:"Application Generated" /failure:enable /success:enable
        }
        Catch
        {
            Write-Warning "Error enabling ADFS auditing settings on $Machine. Error: $_"
        }
        Finally
        {
            if($Session)
            {
                Remove-PSSession $Session
            }
        }
    }

	Write-Verbose "ADFS auditing is now enabled."
}

function Disable-ADFSAuditing
{
    param(
        [parameter(Mandatory=$False)]
        [string[]]$Server="LocalHost"
    )

	<#
    .SYNOPSIS
    This script disables ADFS verbose related events from the security, admin, and debug logs.

    .DESCRIPTION
	To track ADFS authentication processing there are multiple items which must be enabled on the ADFS server(s). This function provides 
    automation for disabling those items so that event logs do not fill up.
    
    Note that this function can only run the ADFS properties on remote servers, and not the OS trace log commands.
	
	EXAMPLE
    	Disable-ADFSAuditing
	#>
	
	#Disable ADFS Tracing log
	$ADFSTraceLogName = "AD FS Tracing/Debug"
	$ADFSTraceLog = New-Object System.Diagnostics.Eventing.Reader.EventlogConfiguration $ADFSTraceLogName
	if ($ADFSTraceLog.IsEnabled -ne $false)
	{
		$ADFSTraceLog.IsEnabled = $false
		$ADFSTraceLog.SaveChanges()
	}

	#Disable security auditing from ADFS
	$cs = get-wmiobject -class win32_computersystem -ComputerName "localhost"
	$DomainRole = $cs.domainrole

    foreach($Machine in $Server)
    {
        Try
        {
            $Session = New-PSSession -ComputerName $Machine
            Set-ADFSAuditingRemote -Session $Session -Enable $False
            auditpol.exe /set /subcategory:"Application Generated" /failure:disable /success:disable
        }
        Catch
        {
            Write-Warning "Error disabling ADFS auditing settings on $Machine. Error: $_"
        }
        Finally
        {
            if($Session)
            {
                Remove-PSSession $Session
            }
        }
    }

	Write-Verbose "ADFS auditing is now disabled."
}

function Set-ADFSAuditingRemote
{
    param(
        [Parameter(Mandatory=$True)]
        [System.Management.Automation.Runspaces.PSSession]$Session,
        
        [Parameter(Mandatory=$True)]
        [bool]$Enable
    )

    Invoke-Command -Session $Session -ScriptBlock {

        $OSVersion = gwmi win32_operatingsystem
        [int]$BuildNumber = $OSVersion.BuildNumber 

        if ( $BuildNumber -le 7601 )
        {
            Add-PsSnapin Microsoft.Adfs.Powershell -ErrorAction SilentlyContinue
        }else
        {
            Import-Module ADFS -ErrorAction SilentlyContinue
        }

        $SyncProps = Get-ADFSSyncProperties
        if ( $SyncProps.Role -ne 'SecondaryComputer' ) 
        {
            if ( $Enable )
            {
                Set-ADFSProperties -LogLevel  @( "FailureAudits", "SuccessAudits", "Warnings", "Verbose", "Errors", "Information")
                Set-ADFSProperties -AuditLevel Verbose
            }else{
                Set-ADFSProperties -LogLevel  @( "Warnings", "Errors", "Information" )
            }            
        }
    }
}

function MakeQuery
{

    <#

    .DESCRIPTION
    Performs a log search query to a remote machine, using remote PowerShell, and Get-WinEvent

    #>

    param(
    [parameter(Mandatory=$True)]
    [string]$Query,

    [Parameter(Mandatory=$True)]
    [string]$Log,

    [Parameter(Mandatory=$True)]
    [System.Management.Automation.Runspaces.PSSession]$Session,

    [parameter(Mandatory=$false)]
    [string]$FilePath,

    [parameter(Mandatory=$false)]
    [bool]$ByTime,
    
    [parameter(Mandatory=$false)]
    [DateTime]$Start = (Get-Date),
    
    [parameter(Mandatory=$false)]
    [DateTime]$End = (Get-Date),

    [parameter(Mandatory=$false)]
    [bool]$IncludeLinkedInstances

    )

    # Get-WinEvent is performed through a remote powershell session to avoid firewall issues that arise from simply passing a computer name to Get-WinEvent  
    Invoke-Command -Session $Session -ArgumentList $Query, $Log, $script:CONST_ADFS_AUDIT, $script:CONST_AUDITS_TO_AGGREGATE, $script:CONST_AUDITS_LINKED, $IncludeLinkedInstances, $ByTime, $Start, $End, $FilePath -ScriptBlock {
        param(
        [string]$Query, 
        [string]$Log,
        [string]$providername,
        [object]$auditsToAggregate,
        [object]$auditsWithInstanceIds,
        [bool] $IncludeLinkedInstances,
        [bool]$ByTime,
        [DateTime]$Start,
        [DateTime]$End,
        [string]$FilePath)

        #
        # Perform Get-WinEvent call to collect logs 
        #
        $Result = @()
        if ( $FilePath.Length -gt 0 -and !$ByTime)
        {   
            $Result += Get-WinEvent -Path $FilePath -FilterXPath $Query -ErrorAction SilentlyContinue -Oldest
        }
        elseif ( $ByTime )
        {
            # Adjust times for zone on specific server
            $TimeZone = [System.TimeZoneInfo]::Local
            $AdjustedStart = [System.TimeZoneInfo]::ConvertTimeFromUtc($Start, $TimeZone)
            $AdjustedEnd = [System.TimeZoneInfo]::ConvertTimeFromUtc($End, $TimeZone)

            # Filtering based on time is more robust when using hashtable filters
            if($FilePath.Length -gt 0)
            {
                $Result += Get-WinEvent -FilterHashtable @{Path = $FilePath; providername = $providername; starttime = $AdjustedStart; endtime = $AdjustedEnd} -ErrorAction SilentlyContinue
            }
            elseif ( $Log -eq "security" )
            {
                $Result += Get-WinEvent -FilterHashtable @{logname = $Log; providername = $providername; starttime = $AdjustedStart; endtime = $AdjustedEnd} -ErrorAction SilentlyContinue
            }
            else
            {
                $Result += Get-WinEvent -FilterHashtable @{logname = $Log; starttime = $AdjustedStart; endtime = $AdjustedEnd} -ErrorAction SilentlyContinue -Oldest
            }
        }
        else
        {
            $Result += Get-WinEvent -LogName $Log -FilterXPath $Query -ErrorAction SilentlyContinue -Oldest
        }

        #
        # Process results from Get-WinEvent query 
        #
        $instanceIdsToQuery = @{}

        foreach ( $Event in $Result )
        {
            # Copy over all properties so they remain accessible when remote session terminates

            $Properties = @()
            foreach ( $Property in $Event.Properties )
            {
                $Properties += $Property.value
            }
            $Event | Add-Member RemoteProperties $Properties
            
            if ( $Event.ActivityId )
            {
                # We have an Activity ID, set the CorrelationID field for consistency 
                $Event | Add-Member CorrelationID $Event.ActivityId.Guid
            }

            # If we didn't have an ActivityId, try to extract one manually 
            if ( (-not $Event.ActivityId) -and $Event.Properties.count -gt 0 )
            {
                $guidRef = [ref] [System.Guid]::NewGuid()
                if ( [System.Guid]::TryParse( $Event.Properties[1].Value, $guidRef ) ) 
                {
                    $Event | Add-Member CorrelationID $Event.Properties[1].Value 
                }                
            }

            # If we want to include events that are linked by the instance ID, we need to 
            #  generate a list of instance IDs to query on for the current server 
            if ( $IncludeLinkedInstances )
            {
                if ( $auditsToAggregate -contains $Event.Id )
                {
                    # The instance ID in this event should be used to get more data
                    $instanceID = $Event.Properties[0].Value 
                    $instanceIdsToQuery[$instanceID] = $Event.CorrelationID
                }
            }
        }

        #
        # If we have instance IDs to collect accross, do that collection now
        #
        if ( $instanceIdsToQuery.Count -gt 0 )
        {
            foreach ( $eventID in $auditsWithInstanceIds )
            { 
                if ( $FilePath )
                {
                    $instanceIdResultsRaw = Get-WinEvent -FilterHashtable @{Path= $FilePath; providername = $providername; Id = $eventID } -ErrorAction SilentlyContinue
                }
                else
                {
                     $instanceIdResultsRaw = Get-WinEvent -FilterHashtable @{logname = $Log; providername = $providername; Id = $eventID } -ErrorAction SilentlyContinue
                }
            
                foreach ( $instanceId in $instanceIdsToQuery.Keys )
                {
                    $correlationID = $instanceIdsToQuery[$instanceId]

                    foreach ( $instanceEvent in $instanceIdResultsRaw)
                    {
                        if ( $instanceId -eq $instanceEvent.Properties[0].Value )
                        {
                            # We have an event that we want 

                            # Copy data of remote params
                            $Properties = @()
                            foreach ( $Property in $instanceEvent.Properties )
                            {
                                $Properties += $Property.value
                            }

                            $instanceEvent | Add-Member RemoteProperties $Properties
                            $instanceEvent | Add-Member AdfsInstanceId $instanceEvent.Properties[0].Value
                            $instanceEvent | Add-Member CorrelationID $correlationID

                            $Result += $instanceEvent
                        }                    
                    }
                }
            }
        }

        return $Result  
    } 
}

function GetSecurityEvents
{

    <#

    .DESCRIPTION
    Perform a query to get the ADFS Security Events 

    #>

    param(
    [parameter(Mandatory=$False)]
    [string]$CorrID,

    [parameter(Mandatory=$True)]
    [System.Management.Automation.Runspaces.PSSession]$Session,

    [parameter(Mandatory=$false)]
    [bool]$ByTime,
    
    [parameter(Mandatory=$false)]
    [DateTime]$Start,
    
    [parameter(Mandatory=$false)]
    [DateTime]$End,

    [parameter(Mandatory=$false)]
    [bool]$IncludeLinkedInstances,

    [parameter(Mandatory=$false)]
    [string]$FilePath

    )

    $Query = "*[System[Provider[@Name='{0}']]]" -f $script:CONST_ADFS_AUDIT

    if($CorrID.Length -gt 0)
    {
        $Query += " and *[EventData[Data and (Data='{0}')]]" -f $CorrID
    }

    # Perform the log query 
    return MakeQuery -Query $Query -Log $script:CONST_SECURITY_LOG -Session $Session -ByTime $ByTime -Start $Start -End $End -IncludeLinkedInstances $IncludeLinkedInstances -FilePath $FilePath
}

function GetAdminEvents
{

    <#

    .DESCRIPTION
    Perform a query to get the ADFS Admin events

    #>

    param(
    [parameter(Mandatory=$False)]
    [string]$CorrID,

    [parameter(Mandatory=$True)]
    [System.Management.Automation.Runspaces.PSSession]$Session,
    
    [parameter(Mandatory=$false)]
    [bool]$ByTime,
    
    [parameter(Mandatory=$false)]
    [DateTime]$Start,

    [parameter(Mandatory=$false)]
    [DateTime]$End, 

    [parameter(Mandatory=$false)]
    [string]$FilePath

    ) 

    # Default to query all 
    $Query = "*[System[Provider[@Name='{0}']]]" -f $script:CONST_ADFS_ADMIN

    if ( $CorrID.length -gt 0 )
    {
        $Query +=  " and *[System[Correlation[@ActivityID='{$CorrID}']]]"
    }

    return MakeQuery -Query $Query -Log $script:CONST_ADMIN_LOG -Session $Session -ByTime $ByTime -Start $Start -End $End -FilePath $FilePath
}

function GetDebugEvents
{

    <#

    .DESCRIPTION
    Perform a query to get the ADFS Debug logs  

    #>

    param(
    [parameter(Mandatory=$False)]
    [string]$CorrID,

    [parameter(Mandatory=$True)]
    [System.Management.Automation.Runspaces.PSSession]$Session,

    [parameter(Mandatory=$false)]
    [bool]$ByTime,
    
    [parameter(Mandatory=$false)]
    [DateTime]$Start,

    [parameter(Mandatory=$false)]
    [DateTime]$End,

    [parameter(Mandatory=$false)]
    [string]$FilePath

    )

    # Default to query all
     $Query = "*[System[Provider[@Name='{0}']]]" -f $script:CONST_ADFS_DEBUG

    if ( $CorrID.length -gt 0 )
    {
        $Query +=  " and *[System[Correlation[@ActivityID='{$CorrID}']]]"
    }

    return MakeQuery -Query $Query -Log $script:CONST_DEBUG_LOG -Session $Session -ByTime $ByTime -Start $Start -End $End -FilePath $FilePath
}

function QueryDesiredLogs
{   

    <#

    .DESCRIPTION
    Query for all logs that were requested from the user input 

    #>

    param(
        [parameter(Mandatory=$False)]
        [string]$CorrID,

        [parameter(Mandatory=$True)]
        [System.Management.Automation.Runspaces.PSSession]$Session,

        [parameter(Mandatory=$false)]
        [bool]$ByTime,
    
        [parameter(Mandatory=$false)]
        [DateTime]$Start,

        [parameter(Mandatory=$false)]
        [DateTime]$End,

        [parameter(Mandatory=$false)]
        [bool]$IncludeLinkedInstances,

        [parameter(Mandatory=$false)]
        [string]$FilePath
    )


    $Events = @()

    if ($Logs -contains $script:CONST_LOG_PARAM_SECURITY)
    {
        $Events += GetSecurityEvents -CorrID $CorrID -Session $Session -ByTime $ByTime -Start $Start -End $End -IncludeLinkedInstances $IncludeLinkedInstances -FilePath $FilePath
    }

    if ($Logs -contains $script:CONST_LOG_PARAM_DEBUG)
    {
        $Events += GetDebugEvents -CorrID $CorrID -Session $Session -ByTime $ByTime -Start $Start -End $End -FilePath $FilePath
    }

    if ($Logs -contains $script:CONST_LOG_PARAM_ADMIN)
    {
        $Events += GetAdminEvents -CorrID $CorrID -Session $Session -ByTime $ByTime -Start $Start -End $End -FilePath $FilePath
    }

    return $Events
}






# ----------------------------------------------------
#
# Helper Functions - JSON Management 
#
# ----------------------------------------------------

function NewObjectFromTemplate
{
    param(
        [parameter(Mandatory=$true)]
        [string]$Template
    )

    return $Template | ConvertFrom-Json
}






# ----------------------------------------------------
#
# Helper Functions - Event Processing 
#
# ----------------------------------------------------

function Process-HeadersFromEvent
{
    param(
        [parameter(Mandatory=$true)]
        [object]$events
    )

    $longText = ""
    foreach ( $event in $events )
    {
        if ( $event.Id -eq 510 )
        {
            # 510 events are generic "LongText" events. When the LongText that's being 
            #  written is header data (from a 403 or 404), then the schema is: 
            #      instanceID : $event.RemoteProperties[0]
            #      headers_json : $event.RemoteProperties[1...N] (ex. {"Content-Length":"89","Content-Type":"application/x-www-form-urlencoded", etc. } )

            for ( $i=1; $i -le $event.RemoteProperties.Count - 1; $i++ )
            {
                $propValue = $event.RemoteProperties[$i]

                if ( $propValue -ne "-")
                {
                    $longText += $propValue
                }                
            }
        }
    }

    return $longText | ConvertFrom-Json
}

function Get-ClaimsFromEvent
{
    param(
        [parameter(Mandatory=$true)]
        [object]$event
    )

    $keyValuePair = @()
    for ($i = 1; $i -lt $event.RemoteProperties.Count - 1; $i += 2)
    {
        if ($event.RemoteProperties[$i] -ne "-" -and $event.RemoteProperties[$i + 1] -ne "-" )
        {
            $keyValuePair += @($event.RemoteProperties[$i], $event.RemoteProperties[$i + 1])
        }
    }

    return $keyValuePair
}

function Process-TokensFromEvent
{
    param(
        [parameter(Mandatory=$true)]
        [object]$event,

        [parameter(Mandatory=$false)]
        [object]$LinkedEvents
    )

    $allTokens = @()

    if ( $event.Id -eq 412 -or $event.Id -eq 324 )
    {
        $tokenObj = NewObjectFromTemplate -Template $script:TOKEN_OBJ_TEMPLATE
        $claims = @()
        foreach ( $linkedEvent in $LinkedEvents[$event.RemoteProperties[0]] ) #InstanceID
        {
            # Get claims out of event
            $claims += Get-ClaimsFromEvent -event $linkedEvent
        }

        $tokenObj.type = $event.RemoteProperties[2]
        $tokenObj.rp = $event.RemoteProperties[3]
        $tokenObj.direction = "incoming"
        $tokenObj.claims = $claims

        $allTokens += $tokenObj
    }

    if ( $event.Id -eq 299 )
    {
        $tokenObjIn = NewObjectFromTemplate -Template $script:TOKEN_OBJ_TEMPLATE
        $tokenObjOut = NewObjectFromTemplate -Template $script:TOKEN_OBJ_TEMPLATE

        $claimsIn = @()
        $claimsOut = @()

        foreach ( $linkedEvent in $LinkedEvents[$event.RemoteProperties[0]] ) #InstanceID
        {
            if ( $linkedEvent.Id -eq 500 )
            {
                # Issued claims
                $claimsOut += Get-ClaimsFromEvent -event $linkedEvent
            }

            if ( $linkedEvent.Id -eq 501 )
            {
                # Caller claims
                $claimsIn += Get-ClaimsFromEvent -event $linkedEvent
            }
        }

        $tokenObjOut.rp = $event.RemoteProperties[2]
        $tokenObjOut.direction = "outgoing"

        $tokenObjIn.claims = $claimsIn
        $tokenObjOut.claims = $claimsOut

        $allTokens += $tokenObjIn
        $allTokens += $tokenObjOut
    }

    return $allTokens
}


function Generate-ErrorEvent
{
    param(
        [parameter(Mandatory=$true)]
        [object]$event
    )

    $errorObj = NewObjectFromTemplate -Template $script:ERROR_OBJ_TEMPLATE
    $errorObj.time = $event.TimeCreated
    $errorObj.eventid = $event.Id
    $errorObj.message = $event.Message
    $errorObj.level = $event.LevelDisplayName

    return $errorObj
}

function Generate-ResponseEvent
{
    param(
        [parameter(Mandatory=$false)]
        [object]$event,

        [parameter(Mandatory=$true)]
        [int]$requestCount,

        [parameter(Mandatory=$false)]
        [object]$LinkedEvents
    )

    $response = NewObjectFromTemplate -Template $script:RESPONSE_OBJ_TEMPLATE
    $response.num = $requestCount

    # Return an empty response object if we don't have data to use 
    if ( $event.length -eq 0 )
    {
        return $response
    }

    $response.time = $event.RemoteProperties[2] #Datetime
    # "{Status code} {status_description}""
    $response.result = "{0} {1}" -f $event.RemoteProperties[3], $event.RemoteProperties[4] 

    $headerEvent = $LinkedEvents[$event.RemoteProperties[0]] #InstanceID
    if ( $headerEvent -eq $null )
    {
        $headerEvent = @{}
    }
    $headersObj = Process-HeadersFromEvent -events $headerEvent
    $response.headers = $headersObj

    return $response
}


function Generate-RequestEvent
{
    param(
        [parameter(Mandatory=$false)]
        [object]$event,

        [parameter(Mandatory=$true)]
        [int]$requestCount,

        [parameter(Mandatory=$false)]
        [object]$LinkedEvents
    )

    $currentRequest = NewObjectFromTemplate -Template $script:REQUEST_OBJ_TEMPLATE
    $currentRequest.num = $requestCount

    # Return an empty request object if we don't have data to use 
    if ( -not $event )
    {
        return $currentRequest
    }

    $currentRequest.time = $event.RemoteProperties[2]  #Date
    $currentRequest.clientip = $event.RemoteProperties[3]  #ClientIP
    $currentRequest.method = $event.RemoteProperties[4]  #HTTP_Method
    $currentRequest.url = $event.RemoteProperties[5]  #URL
    $currentRequest.query = $event.RemoteProperties[6]  #QueryString
    $currentRequest.useragent = $event.RemoteProperties[9]  #UserAgent
    $currentRequest.contlen = $event.RemoteProperties[10]  #ContentLength
    $currentRequest.server = $event.MachineName

    $headerEvent = $LinkedEvents[$event.RemoteProperties[0]] #InstanceID
    if ($headerEvent -eq $null )
    {
        $headerEvent = @{}
    }
    $headersObj = Process-HeadersFromEvent -events $headerEvent

    $currentRequest.headers = $headersObj

    # Load the HTTP and HTTPS ports, if we haven't already 
    # We need these to convert the 'LocalPort' field in the 403 audit
    if (-not $script:DidLoadPorts)
    {
        $script:CONST_ADFS_HTTP_PORT = (Get-AdfsProperties).HttpPort
        $script:CONST_ADFS_HTTPS_PORT = (Get-AdfsProperties).HttpsPort
        $script:DidLoadPorts = $true 
    }
             
    if ( $event.RemoteProperties[7] -eq $script:CONST_ADFS_HTTP_PORT)
    {
        $currentRequest.protocol = "HTTP"
    }

    if ( $event.RemoteProperties[7] -eq $script:CONST_ADFS_HTTPS_PORT)
    {
        $currentRequest.protocol = "HTTPS"
    }

    return $currentRequest 
}

function Update-ResponseEvent
{
    param(
        [parameter(Mandatory=$false)]
        [object]$event,

        [parameter(Mandatory=$true)]
        [object]$responseEvent,

        [parameter(Mandatory=$false)]
        [object]$LinkedEvents
    )

    if ( $event.Id -eq 404 )
    {
        $responseEvent.time = $event.RemoteProperties[2] #Datetime
        # "{Status code} {status_description}""
        $responseEvent.result = "{0} {1}" -f $event.RemoteProperties[3], $event.RemoteProperties[4] 

        $headerEvent = $LinkedEvents[$event.RemoteProperties[0]] #InstanceID
        if ($headerEvent -eq $null )
        {
            $headerEvent = @{}
        }

        $headersObj = Process-HeadersFromEvent -events $headerEvent
        $responseEvent.headers = $headersObj

        return $responseEvent
    }
}

function Update-RequestEvent
{
    param(
        [parameter(Mandatory=$false)]
        [object]$event,

        [parameter(Mandatory=$true)]
        [object]$requestEvent,

        [parameter(Mandatory=$true)]
        [int]$requestCount,

        [parameter(Mandatory=$false)]
        [object]$LinkedEvents
    )

    if ( $event.Id -eq 403 )
    {
        $newEvent = Generate-RequestEvent -event $event -requestCount $requestCount -LinkedEvents $LinkedEvents

        # Merge tokens
        $newEvent.tokens += $requestEvent.tokens

        return $newEvent
    }
}

function Generate-TimelineEvent
{
    param(
        [parameter(Mandatory=$true)]
        [object]$event
    )

    $timelineEvent = NewObjectFromTemplate -Template $script:TIMELINE_OBJ_TEMPLATE
    $timelineEvent.time = $event.TimeCreated
    
    # 403 - request received
    if ( $event.Id -eq 403 )
    {
        $timelineEvent.type = $script:TIMELINE_INCOMING
        $timelineEvent.result = $script:TIMELINE_SUCCESS
        return $timelineEvent
    }       
    
    # 411 - token validation failure 
    if ( $event.Id -eq 411 )
    {    
        $timelineEvent.type = $script:TIMELINE_AUTHENTICATION
        $timelineEvent.result = $script:TIMELINE_FAILURE
        $timelineEvent.tokentype = $event.RemoteProperties[1] #Token Type
        return $timelineEvent
    }

    # 412 - authentication success 
    if ( $event.Id -eq 412 )
    {
        $timelineEvent.type = $script:TIMELINE_AUTHENTICATION
        $timelineEvent.result = $script:TIMELINE_SUCCESS
        $timelineEvent.tokentype = $event.RemoteProperties[2] #Token Type
        $timelineEvent.rp = $event.RemoteProperties[3] #RP
        return $timelineEvent
    }

    # 324 - authorization failure 
    if ( $event.Id -eq 324 )
    {
        $timelineEvent.type = $script:TIMELINE_AUTHORIZATION
        $timelineEvent.result = $script:TIMELINE_FAILURE
        $timelineEvent.rp = $event.RemoteProperties[3] #RP
        return $timelineEvent
    }

    # 299 - token issuance success
    if ( $event.Id -eq 299 )
    {
        $timelineEvent.type = $script:TIMELINE_ISSUANCE
        $timelineEvent.result = $script:TIMELINE_SUCCESS
        $timelineEvent.rp = $event.RemoteProperties[2] #RP
        $timelineEvent.tokentype = $script:TOKEN_TYPE_ACCESS
        return $timelineEvent
    }

    return $timelineEvent
}

function Process-EventsForAnalysis
{
    param(
        [parameter(Mandatory=$true)]
        [object]$events
    )

    # TODO: Validate that all events have the same correlation ID, or no correlation ID 

    # Validate that the events are sorted by time 
    $events = $events | Sort-Object TimeCreated 

    $requestCount = 0
    $mapRequestNumToObjects = @{} 
    $allErrors = @()
    $allTimeline = @()
    $timelineIncomingMarked = $false
    $LinkedEvents = @{}
    $PreviousRequestStatus = @()

    # Do a pre-pass through the events set to generate 
    #  a hashtable of instance IDs to their events 
    foreach ( $event in $events )
    {
        if ( $event.AdfsInstanceId )
        {
            if ( $LinkedEvents.Contains( $event.AdfsInstanceId ) ) 
            {
                # Add event to exisiting list
                $LinkedEvents[$event.AdfsInstanceId] += $event
            }
            else
            {
                # Add instance ID and fist event to hashtable
                $LinkedEvents[$event.AdfsInstanceId] = @() + $event 
            }   
        }
    }

    #
    # Do a second pass through the events to collect all the data we need for analysis 
    #
    foreach ( $event in $events )
    {
        # Error or warning. We use 'Level' int to avoid localization issues  
        if ( ( $event.Level -ge 1 -and $event.Level -le 3 )  -or ( $event.Level -eq 16 ) )
        {
            $allErrors += Generate-ErrorEvent -event $event 
        }

        # If this event signals a timeline event, generate it 
        if ( $event.Id -in $script:CONST_TIMELINE_AUDITS)
        {
            $allTimeline += Generate-TimelineEvent -event $event 
        }

        if ( -not $mapRequestNumToObjects[$requestCount] )
        {
            # We don't have a request/response pair to work with, so create one now

            $currentRequest = Generate-RequestEvent -requestCount $requestCount
            $currentResponse = Generate-ResponseEvent -requestCount $requestCount
            $mapRequestNumToObjects[$requestCount] = @($currentRequest, $currentResponse)
        }

        # 411 - token validation failure 
        if ( $event.Id -eq 411 )
        {
            # TODO: Use for error 
        }

        # 412 - authentication success or 324 - authorization failure 
        if ( $event.Id -eq 412 -or $event.Id -eq 324 )
        {
            # Use this for caller identity on request object            
            $tokenObj = Process-TokensFromEvent -event $event -LinkedEvents $LinkedEvents
            $tokenObj[0].num = $requestCount  

            $currentRequest = $mapRequestNumToObjects[$requestCount][0]
            $currentRequest.tokens += $tokenObj[0]
        }

        # 299 - token issuance success
        if ( $event.Id -eq 299 )
        {
            $tokenObj = Process-TokensFromEvent -event $event -LinkedEvents $LinkedEvents
            $tokenObj[0].num = $requestCount  
            $tokenObj[1].num = $requestCount

            $currentRequest = $mapRequestNumToObjects[$requestCount][0] 
            $currentRequest.tokens += $tokenObj[0]

            $currentResponse = $mapRequestNumToObjects[$requestCount][1] 
            $currentResponse.tokens += $tokenObj[1]
        }

        # 403 - request received
        if ( $event.Id -eq 403 )
        {
            # We have a new request, so generate a request/response pair, and store it 

            if ( $PreviousRequestStatus.Count -gt 0 )
            {
                # We have a previous request in the pipeline. Finalize that request and generate a new one 
                $requestCount += 1
                
                $currentRequest = Generate-RequestEvent -event $event -requestCount $requestCount -LinkedEvents $LinkedEvents
                $currentResponse = Generate-ResponseEvent -requestCount $requestCount
                $mapRequestNumToObjects[$requestCount] = @($currentRequest, $currentResponse)
            }
            else
            {
                $currentRequest = $mapRequestNumToObjects[$requestCount][0]
                $updatedRequest = Update-RequestEvent -event $event -requestCount $requestCount -requestEvent $currentRequest -LinkedEvents $LinkedEvents 
                $mapRequestNumToObjects[$requestCount][0] = $updatedRequest
            }
            
            $PreviousRequestStatus += 403
        }
        
        # 404 - response sent 
        if ( $event.Id -eq 404 )
        {
            if ( $PreviousRequestStatus.Count -gt 0 -and $PreviousRequestStatus[-1] -eq 404 )
            {
                # We have received two 404 events without a 403. We should create a new request/response pair 
                $requestCount += 1
                $currentRequest = Generate-RequestEvent -requestCount $requestCount
                $currentResponse = Generate-ResponseEvent -requestCount $requestCount -event $event -LinkedEvents $LinkedEvents 
                $mapRequestNumToObjects[$requestCount] = @($currentRequest, $currentResponse)
            }
            else
            {
                $currentResponse = $mapRequestNumToObjects[$requestCount][1]
                $updatedResponse = Update-ResponseEvent -event $event -responseEvent $currentResponse -LinkedEvents $LinkedEvents 
                $mapRequestNumToObjects[$requestCount][1] = $updatedResponse
            }
            
            # We do not mark a request/response pair as complete until we have a new request come in, 
            #  since we sometimes see events after the 404 (token issuance, etc.)

            $PreviousRequestStatus += 404
        }
    }

    #
    # Generate the complete analysis JSON object 
    #    
    $analysisObj = NewObjectFromTemplate -Template $script:ANALYSIS_OBJ_TEMPLATE

    $allRequests = @()
    $allResponses = @()
    foreach ( $requestKey in $mapRequestNumToObjects.keys )
    {
        $allRequests += $mapRequestNumToObjects[$requestKey][0]
        $allResponses += $mapRequestNumToObjects[$requestKey][1]
    } 

    $analysisObj.requests = $allRequests
    $analysisObj.responses = $allResponses
    $analysisObj.errors = $allErrors
    $analysisObj.timeline = $allTimeline

    return $analysisObj
}

function AggregateOutputObject
{
    param(
    [parameter(Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]$CorrID,

    [parameter(Mandatory=$true,Position=1)]
    [AllowEmptyCollection()]
    [PSObject[]]$Events,

    [parameter(Mandatory=$true,Position=2)]
    [AllowEmptyCollection()]
    [PSObject]$Data)

     $Output = New-Object PSObject -Property @{
        "CorrelationID" = $CorrID
        "Events" = $Events
        "AnalysisData" = $Data
    }

    return $Output
}






# ----------------------------------------------------
#
# Exported Functions 
# 
# ----------------------------------------------------

function Write-ADFSEventsSummary
{
    <#

    .DESCRIPTION
    This cmdlet consumes a piped-in list of Event objects, and produces a summary table
    of the relevant data from the request. 

    Note: this function should only be used on a list of Event objects that all contain 
    the same correlation ID (i.e. all of the events are from the same user request) 

    #>

    param(
        [parameter(ValueFromPipeline=$True)]
        [PSObject]$Events
    )

    foreach($Event in $Events)
    {
        $newRow = New-Object PSObject -Property @{            
            Time = $Event.TimeCreated               
            Level = $Event.LevelDisplayName            
            EventID = $Event.Id        
            Details = $Event.Message           
            CorrelationID = $Event.CorrelationID           
            Machine = $Event.MachineName        
            Log = $Event.LogName                   
        }  

        Write-Output $newRow
    }
}


function Get-ADFSEvents
{

    <#

    .SYNOPSIS
    This script gathers ADFS related events from the security, admin, and debug logs into a single file, 
    and allows the user to reconstruct the HTTP request/response headers from the logs.

    .DESCRIPTION
    Given a correlation id, the script will gather all events with the same identifier and reconstruct the request
    and response headers if they exist. Using the 'All' option (either with or without headers enabled) will first collect
    all correlation ids and proceed to gather the events for each. If start and end times are provided, all events 
    that fall into that span will be returned. The start and end times will be assumed to be base times. That is, all
    time conversions will be based on the UTC of these values.

    .EXAMPLE
    Get-ADFSEvents -Logs Security, Admin, Debug -CorrelationID 669bced6-d6ae-4e69-889b-09ceb8db78c9 -Server LocalHost, MyServer
    .Example
    Get-ADFSEvents -CorrelationID 669bced6-d6ae-4e69-889b-09ceb8db78c9 -Headers
    .EXAMPLE
    Get-ADFSEvents -Logs Admin -All 
    .EXAMPLE
    Get-ADFSEvents -Logs Debug, Security -All -Headers -Server LocalHost, Server1, Server2
    .Example
    Get-ADFSEvents -Logs Debug -StartTime (Get-Date -Date ("2017-09-14T18:37:26.910168700Z"))  -EndTime (Get-Date) -Headers

    #>

    # Provide either correlation id, 'All' parameter, or time range along with logs to be queried and list of remote servers
    [CmdletBinding(DefaultParameterSetName='CorrelationIDParameterSet')]
    param(
    [parameter(Mandatory=$false, Position=0)]
    [ValidateSet("Admin", "Debug", "Security")]
    [string[]]$Logs = @("Security","Admin"),

    [parameter(Mandatory=$true, Position=1, ParameterSetName="CorrelationIDParameterSet")]
    [ValidateNotNullOrEmpty()]
    [string]$CorrelationID,

    [parameter(Mandatory=$true, Position=1, ParameterSetName="AllEventsSet")]
    [switch]$All,

    [parameter(Mandatory=$true, Position=1, ParameterSetName="AllEventsByTimeSet")]
    [DateTime]$StartTime,

    [parameter(Mandatory=$true, Position=2, ParameterSetName="AllEventsByTimeSet")]
    [DateTime]$EndTime,

    [parameter(Mandatory=$false)]
    [switch]$CreateAnalysisData,

    [parameter(Mandatory=$false, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
    [string[]]$Server="LocalHost",

    [parameter(Mandatory=$false, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
    [string]$FilePath
    )

    # TODO: Add warning if environment is not Win2016
    if ($Server -eq "*")
    {
        $Server = @()
        $nodes = (Get-AdfsFarmInformation).FarmNodes
        foreach( $server in $nodes)
        {
            $Server += $server
        }
    }
    
    $ServerList = @()
    

    # Validate timing parameters 
    if ( $StartTime -ne $null -and $EndTime -ne $null )
    {
        if ( $EndTime -lt $StartTime )
        {
            $temp = $StartTime
            $StartTime = $EndTime
            $EndTime = $temp
            Write-Warning "The EndTime provided is earlier than the StartTime. Swapping time parameters and continuing."
        }

        $ByTime = $true
    }
    else
    {
        $ByTime = $false
        
        # Set values to prevent binding issues when passing parameters
        $StartTime = Get-Date
        $EndTime = Get-Date
    }

    # Validate Correlation ID is a valid GUID
    $guidRef = [ref] [System.Guid]::NewGuid()
    if ( (!$All -and !$ByTime) -and ($CorrelationID.length -eq 0 -or ![System.Guid]::TryParse( $CorrelationID, $guidRef )) ){ 
        Write-Error "Invalid Correlation ID. Please provide a valid GUID."
        Break
    }
    $Events = @()
    # Iterate through each server, and collect the required logs
    foreach ( $Machine in $Server )
    {
        $includeLinks = $false
        if ( $CreateAnalysisData )
        {
            $includeLinks = $true
        }

        Try
        {
            $Session = New-PSSession -ComputerName $Machine
            $Events += QueryDesiredLogs -CorrID $CorrelationID -Session $Session -ByTime $ByTime -Start $StartTime.ToUniversalTime() -End $EndTime.ToUniversalTime() -IncludeLinkedInstances $includeLinks -FilePath $FilePath
        }
        Catch
        {
            Write-Warning "Error collecting events from $Machine. Error: $_"
        }
        Finally
        {
            if ( $Session )
            {
                Remove-PSSession $Session
            }
        }
    }

    $EventsByCorrId = @{}
    # Collect events by correlation ID, and store in a hashtable      
    foreach ( $Event in $Events )
    {
        $ID = [string] $Event.CorrelationID
                
        if(![string]::IsNullOrEmpty($ID) -and $EventsByCorrId.Contains($ID)) 
        {
            # Add event to exisiting list
            $EventsByCorrId.$ID =  $EventsByCorrId.$ID + $Event
        }
        elseif(![string]::IsNullOrEmpty($ID))
        {
            # Add correlation ID and fist event to hashtable
            $EventsByCorrId.$ID = @() + $Event 
        }
    }

    # Note: When we do the correlation ID aggregation, we are dropping any events that do not have a correlation ID set. 
    #  All Admin logs should have a correlation ID, and all audits should either have a correlation ID, or have a separate 
    #  record, which is identical, but contains a correlation ID (we do this for audits that have an instance ID, but no correlation ID)
    foreach ( $corrId in $EventsByCorrId.Keys )
    {
        $eventsData = @()
        if ( $EventsByCorrId[$corrId] )
        {
            $eventsData = $EventsByCorrId[$corrId]
        }

        $dataObj = @{}
        if ( $CreateAnalysisData )
        {
            $dataObj = Process-EventsForAnalysis -events $eventsData
        }

        $aggObject = AggregateOutputObject -Data $dataObj -Events $eventsData -CorrID $corrId
        Write-Output $aggObject
    }
}

#
# Export the appropriate modules 
#
Export-ModuleMember -Function Enable-ADFSAuditing
Export-ModuleMember -Function Disable-ADFSAuditing
Export-ModuleMember -Function Get-ADFSEvents
Export-ModuleMember -Function Write-ADFSEventsSummary
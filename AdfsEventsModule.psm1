# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


#Declare helper functions

function MakeQuery
{
    param(
    [parameter(Mandatory=$True)]
    [string]$Query,

    [Parameter(Mandatory=$True)]
    [string]$Log,

    [Parameter(Mandatory=$True)]
    [System.Management.Automation.Runspaces.PSSession]$Session,

    [parameter(Mandatory=$false)]
    [switch]$CopyAllProperties,

    [parameter(Mandatory=$false)]
    [bool]$ByTime,
    
    [parameter(Mandatory=$false)]
    [DateTime]$Start = (Get-Date),
    
    [parameter(Mandatory=$false)]
    [DateTime]$End = (Get-Date))

    #Get-WinEvent is performed throguh a remote powersehll session to avoid firewall issues that arise from simply passing a computer name to Get-WinEvent  
    Invoke-Command -Session $Session -ArgumentList $Query, $Log, $CopyAllProperties, $ByTime, $Start, $End -ScriptBlock {
        param(
        [string]$Query, 
        [string]$Log,
        [bool]$CopyAllProperties,
        [bool]$ByTime,
        [DateTime]$Start,
        [DateTime]$End)
        if($ByTime)
        {
            #Adjust times for zone on specific server
            $TimeZone = [System.TimeZoneInfo]::Local
            $AdjustedStart = [System.TimeZoneInfo]::ConvertTimeFromUtc($Start, $TimeZone)
            $AdjustedEnd = [System.TimeZoneInfo]::ConvertTimeFromUtc($End, $TimeZone)

            #Filtering based on time more robust using hashtables
            if($Log -eq "security")
            {
                $Result = Get-WinEvent -FilterHashtable @{logname = $Log; providername = "AD FS Auditing", "AD FS", "AD FS Tracing"; starttime = $AdjustedStart; endtime = $AdjustedEnd} -ErrorAction SilentlyContinue
            }
            else
            {
                $Result = Get-WinEvent -FilterHashtable @{logname=$Log; starttime=$AdjustedStart; endtime = $AdjustedEnd} -ErrorAction SilentlyContinue -Oldest
            }
        }
        else
        {
            $Result = Get-WinEvent -LogName $Log -FilterXPath $Query -ErrorAction SilentlyContinue -Oldest
        }
        foreach($Event in $Result)
        {
            if($CopyAllProperties) #Copy over all properties so they remain accessible when remote session terminates
            {
                $Properties = @()
                foreach($Property in $Event.Properties)
                {
                    $Properties += $Property.value
                }
                $Event | Add-Member RemoteProperties $Properties
            }
            elseif($Log -eq "security")
            {
                $Var = [ref] [System.Guid]::NewGuid()
                if([System.Guid]::TryParse($Event.Properties[1].Value, $Var)) #Contains activity id and instance id
                {
                   $Event | Add-Member CorrelationID $Event.Properties[1].Value 
                }
                else
                {
                   $Event | Add-Member CorrelationID $Event.Properties[0].Value #Ensure correlation id is not lost through the serialization process
                }
            }
            else
            {
                $Event | Add-Member CorrelationID $Event.ActivityID #Redundant property. Allows for consistency among all events
            }
        }
        if($Result -ne $null)
        {
            Write-Output $Result
        }  
    } 
}

function GetSecurityEvents
{
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
    [DateTime]$End)

    if($CorrID -eq ""){
        $Query = "*[System[Provider[@Name='AD FS' or @Name='AD FS Auditing' or @Name='AD FS Tracing']]]"
    }
    else{
        $Query = "*[System[Provider[@Name='AD FS' or @Name='AD FS Auditing' or @Name='AD FS Tracing']]] and *[EventData[Data and (Data='$CorrID')]]"
    }
    MakeQuery -Query $Query -Log "security" -Session $Session -ByTime $ByTime -Start $Start -End $End
}


function GetAdminEvents
{
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
    [DateTime]$End) 

    $Query ="*"
    if($CorrID -ne "")
    {
        $Query =  "*[System[Correlation[@ActivityID='{$CorrID}']]]"
    }
    MakeQuery -Query $Query -Log "Ad FS/Admin" -Session $Session -ByTime $ByTime -Start $Start -End $End
}

    
function GetDebugEvents
{
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
    [DateTime]$End)

    $Query = "*"
    if($CorrID -ne "")
    {
        $Query =  "*[System[Correlation[@ActivityID='{$CorrID}']]]"
    }
    MakeQuery -Query $Query -Log "Ad FS Tracing/Debug" -Session $Session -ByTime $ByTime -Start $Start -End $End
}

function Get403And404Events
{
    param(
    [parameter(Mandatory=$true)]
    [string]$CorrID,

    [parameter(Mandatory=$true)]
    [System.Management.Automation.Runspaces.PSSession]$Session)

    $Query = "*[System[Provider[@Name='AD FS' or @Name='AD FS Auditing' or @Name='AD FS Tracing']] and (System/EventID=403 or System/EventID = 404)] and *[EventData[Data and (Data='$CorrID')]]"
    MakeQuery -Query $Query -Log "Security" -Session $Session -CopyAllProperties
}

function Get510Events
{
    param([parameter(Mandatory=$true)]
    [string]$InstanceID,

    [parameter(Mandatory=$true)]
    [System.Management.Automation.Runspaces.PSSession]$Session)

    $Query = "*[System[Provider[@Name='AD FS' or @Name='AD FS Auditing' or @Name='AD FS Tracing']] and (System/EventID=510)] and *[EventData[Data and (Data='$InstanceID')]]"
    MakeQuery -Query $Query -Log "Security" -Session $Session -CopyAllProperties
}

function QueryDesiredLogs
{   
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
    [DateTime]$End)

    $Events = @()
    if($Logs -contains "security")
    {
        $Events += GetSecurityEvents -CorrID $CorrID -Session $Session -ByTime $ByTime -Start $Start -End $End 
    }
    if($Logs -contains "debug")
    {
        $Events += GetDebugEvents -CorrID $CorrID -Session $Session -ByTime $ByTime -Start $Start -End $End
    }
    if($Logs -contains "admin")
    {
        $Events += GetAdminEvents -CorrID $CorrID -Session $Session -ByTime $ByTime -Start $Start -End $End
    }
    Write-Output $Events
}



function ConstructHeader
{
    #Parse event containing header values
    param(
    [Parameter(Mandatory=$True)]
    [PSObject]$Event)

    $ConcatenatedOutput = ""
    for($I=1; $Event.RemoteProperties[$I] -ne '-' -and $I -lt $Event.RemoteProperties.COunt; $I++)
    {
        $ConcatenatedOutput += $Event.RemoteProperties[$I]
    }
    $Dictionary = $ConcatenatedOutput | ConvertFrom-Json
    Write-Output $Dictionary
}

function CreateHeaderObject
{
    $Obj = New-Object PSObject -Property @{
        "QueryString" = ""
        "ResponseString" = ""
        "RequestHeader" = @{}
        "ResponseHeader"= @{}
    }

    Write-Output $Obj
}

function GetHTTPRequestInformation
{
    param(
    [parameter(Mandatory=$true)]
    [string]$CorrID,

    [parameter(Mandatory=$true)]
    [System.Management.Automation.Runspaces.PSSession]$Session)

    #Retreive 403 (Request) and 404 (Response) events along with corresponding 510's from security log
    $RequestAndResponseEvents = Get403And404Events -CorrID $CorrID -Session $Session
    $HeaderEvents = @()
    foreach($Event in $RequestAndResponseEvents)
    {
        $InstanceID = $Event.RemoteProperties[0]
        $HeaderEvents += Get510Events -InstanceID $InstanceID -Session $Session
    }


    $HTTPTraffic = @()
    $HeaderObject = CreateHeaderObject
    #Parse relevant information and store in readable/accessible format
    for($I = 0; $I -lt $RequestAndResponseEvents.length; $I++)
    {
        $CurrentID = $RequestAndResponseEvents[$I].ID

        if($CurrentID -eq 403)
        {
            $HeaderObject.QueryString = $RequestAndResponseEvents[$I].RemoteProperties[4] + $RequestAndResponseEvents[$I].RemoteProperties[5] +  $RequestAndResponseEvents[$I].RemoteProperties[6]
            $HeaderObject.RequestHeader = ConstructHeader -Event $HeaderEvents[$I]
              
        }
        else #Event is a 404
        {
            $HeaderObject.ResponseString = $ResponseString = $RequestAndResponseEvents[$I].RemoteProperties[3] + " " + $RequestAndResponseEvents[$I].RemoteProperties[4]
            $HeaderObject.ResponseHeader = ConstructHeader -Event $HeaderEvents[$I] 
        }

        if(($CurrentID -eq 404) -or $I -eq ($RequestAndResponseEvents.length-1) -or ($RequestAndResponseEvents[$I+1].ID -eq 403))
        {
            #Begin reconstructing next header if current event is 404 (response), at the end of events list, or the next event represents a request
            $HTTPTraffic += $HeaderObject
            $HeaderObject = CreateHeaderObject #Clear object for next iteration of loop
        }

        if(($I % 2 -eq 0 -and $CurrentID -eq 404) -or ($I %2 -eq 1 -and $CurrentID -eq 403))
        {
            #Expecting each 403 to be followed by a 404. Each 403 should have an even index and each 404 should have an odd index in the list.
            Write-Warning "Unable to match request and response headers"
        }
    }

    if($HTTPTraffic -ne $null)
    {
        Write-Output $HTTPTraffic
    }    
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
    [PSObject[]]$Headers,

    [parameter(Mandatory=$false, Position=3)]
    [bool]$AddHeaders)

     $Output = New-Object PSObject -Property @{
        "CorrelationID" = $CorrID
        "Events" = $Events
    }
    if($AddHeaders)
    {
        $Output | Add-Member Headers $Headers
    }

    Write-Output $Output
}

function Write-ADFSEventsSummary
{
    #Create Table object
    $table = New-Object system.Data.DataTable "SummaryTable"

    #Define Columns
    $col1 = New-Object system.Data.DataColumn Time,([string])
    $col2 = New-Object system.Data.DataColumn EventID,([string])
    $col3 = New-Object system.Data.DataColumn Details,([string])
    $col4 = New-Object system.Data.DataColumn CorrelationID,([string])
    $col5 = New-Object system.Data.DataColumn Machine,([string])
    $col6 = New-Object system.Data.DataColumn Log,([string])
    $table.columns.add( $col1 )
    $table.columns.add( $col2 )
    $table.columns.add( $col3 )
    $table.columns.add( $col4 )
    $table.columns.add( $col5 )
    $table.columns.add( $col6 )

    foreach($Event in $input.Events){
        #Create a row
        $row = $table.NewRow()

        $row.Time = $Event.TimeCreated
        $row.EventID = $Event.Id
        $row.Details = $Event.Message
        $row.CorrelationID = $Event.CorrelationID
        $row.Machine = $Event.MachineName
        $row.Log = $Event.LogName

        #Add the row to the table
        $table.Rows.Add($row)    

    }

    return $table
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


    #Provide either correlation id, 'All' parameter, or time range along with logs to be queried and list of remote servers
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
    [switch]$Headers, 

    [parameter(Mandatory=$false, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
    [string[]]$Server="LocalHost"
    )

  
    $ServerList = @()
    $HashTable = @{}
    $Var = [ref] [System.Guid]::NewGuid()
    if($CorrelationID -ne "" -and ![System.Guid]::TryParse($CorrelationID, $Var)){ #Validate provided Correlation ID is a valid GUID
        Write-Error "Invalid correlation id. Please provide valid input"
        Break
    }

    if($StartTime -ne $null -and $EndTime -ne $null)
    {
        $ByTime = $true
    }
    else
    {
        $ByTime = $false
        #Set values to prevent binding issues when passing parameters
        $StartTime = Get-Date
        $EndTime = Get-Date
    }
    

    foreach($Machine in $Server)
    {
        $ServerList += $Machine
        $Events = @()
        $HTTPInformation = @()
        Try
        {
            $Session = New-PSSession -ComputerName $Machine
            $Events += QueryDesiredLogs -CorrID $CorrelationID -Session $Session -ByTime $ByTime -Start $StartTime.ToUniversalTime() -End $EndTime.ToUniversalTime()    
        }
        Catch
        {
            Write-Warning "Error collecting events from $Machine. Error: $_"
        }
        Finally
        {
            if($Session)
            {
                Remove-PSSession $Session
            }
        }
       
        foreach($Event in $Events)
        {
            $ID = [string] $Event.CorrelationID
                
            if(![string]::IsNullOrEmpty($ID) -and $HashTable.Contains($ID)) #Add event to exisiting list
            {
                $HashTable.$ID =  $HashTable.$ID + $Event
            }

            elseif(![string]::IsNullOrEmpty($ID))
            {
                $HashTable.$ID = @() + $Event #Add correlation ID and fist event to hashtable
            }

        }
        
    }

 
    #Print the result of gathering events for all correlation ids
    foreach($EventList in $HashTable.Values)
    {

        if($Headers){ #Gather headers for each correlation id from each server
            foreach($Machine in $ServerList)
            {
                $HTTPInformation = @()
                try
                {
                    $Session = New-PSSession -ComputerName $Machine
                    $HTTPInformation += GetHTTPRequestInformation -CorrID $EventList[0].CorrelationID -Session $Session
                }
                Catch
                {
                    Write-Warning "Error collecting HTTP traffic from $Machine. Error: $_"
                }
                Finally
                {
                    if($Session)
                    {
                        Remove-PSSession $Session
                    }
                }  
            }  
        }
        AggregateOutputObject -CorrID $EventList[0].CorrelationID -Events $EventList -Headers $HTTPInformation -AddHeaders $Headers.IsPresent
    }
    
    
   
}
Export-ModuleMember -Function Get-ADFSEvents
Export-ModuleMember -Function Write-ADFSEventsSummary
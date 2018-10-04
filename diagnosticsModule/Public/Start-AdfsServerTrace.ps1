<#
.SYNOPSIS
Starts background jobs to search events based on AD FS Activity ID accross different computers

.DESCRIPTION
The Start-AdfsServerTrace cmdlet queries all computers' event logs for the activity ID supplied in parallel as background jobs.
Use the Receive-AdfsServerTrace cmdlet to retrieve and combine the results
This cmdlets works in AD FS 2.0 and later.

.PARAMETER activityId
Activity ID to search for. This typically comes from an AD FS error page.

.PARAMETER ComputerName
It is an array of computers, which represents the AD FS servers to try.

.EXAMPLE
Start-AdfsServerTrace -ActivityId 00000000-0000-0000-9701-0080000000df -ComputerName @("ADFSSRV1","ADFSSRV2")
Get Admin and Audits for activity ID 00000000-0000-0000-9701-0080000000df on Servers ADFSSRV1 and ADFSSRV2

.EXAMPLE
Start-AdfsServerTrace -ActivityId 00000000-0000-0000-9701-0080000000df -ComputerName (Get-Content .\Servers.txt)
Get Admin and Audits for activity ID 00000000-0000-0000-9701-0080000000df from servers in a text file

.EXAMPLE
Start-AdfsServerTrace -ActivityId 00000000-0000-0000-9701-0080000000df -IncludeDebug -ComputerName @("ADFSSRV1","ADFSSRV2")
Get Admin and Audits for activity ID 00000000-0000-0000-9701-0080000000df on Server ADFSSRV1 and ADFSSRV2, including debug traces

.NOTES
You need to run this function using an account that has permissions to read the event logs in all computers supplied.
This is typically achieved having the account be part of the "Event Log Readers" Local Security Group.
The computers supplied also should have firewall rules configured to allow remote readings.
#>
Function Start-AdfsServerTrace
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ActivityId,

        [switch]
        $IncludeDebug,

        [Parameter(Mandatory = $true)]
        [string[]]
        $ComputerName
    )

    #script block that gathers events from Debug and Admin logs
    $getEventWorker = {
        param([string]$sourceType, [string]$activityId, [string]$computerName)

        #common columns to return
        $idExpression = @{ label = 'EventId'; Expression = {$_.Id } }
        $timeExpression = @{ label = 'TimeCreated'; Expression = { $_.TimeCreated } }
        $eventRecordIDExpression = @{ label = 'EventRecordID'; Expression = {[System.Convert]::ToInt32((([xml]$_.ToXml()).Event.System.EventRecordId)) } }
        $messageExpression = @{ label = 'Message'; Expression = {$_.Message} }
        $detailsExpression = @{ label = 'Details'; Expression = {if ($_.Message -ne $_.properties[0].value) { $_.properties[0].value } else { "" } } }
        $details2Expression = @{ label = 'Details2'; Expression = {$_.properties[1].value } }
        $computerNameExpression = @{ label = 'ComputerName'; Expression = { $computerName } }
        $sourceExpression = @{ label = 'Source'; Expression = {$sourceType} }
        $activityIdExpression = @{ label = 'ActivityId'; Expression = {$_.ActivityId} }

        if ($sourceType -eq "Admin")
        {
            $sortKeyExpression = @{ label = 'SortKey'; Expression = { 2 } }
            $adfs2SourceName = "AD FS 2.0/Admin"
            $adfs3SourceName = "AD FS/Admin"
            $oldest = $false
        }

        if ($sourceType -eq "Debug")
        {
            $sortKeyExpression = @{ label = 'SortKey'; Expression = { 3 } }
            $adfs2SourceName = "AD FS 2.0 Tracing/Debug"
            $adfs3SourceName = "AD FS Tracing/Debug"
            $oldest = $true
        }

        [System.Guid]$activityGuid = [System.Guid]::Parse($activityId)
        $normalizedGuid = $activityGuid.ToString("B").ToUpper()
        $xpathFilter = "*[System/Correlation[@ActivityID='$normalizedGuid']]"

        $results = Get-WinEvent -LogName $adfs2SourceName -Oldest:$oldest -FilterXPath $xpathFilter -MaxEvents 100 -ErrorAction SilentlyContinue -ComputerName $computerName -ErrorVariable $errorVar
        $results = $results + [array](Get-WinEvent -LogName $adfs3SourceName -Oldest:$oldest -FilterXPath $xpathFilter -MaxEvents 100 -ErrorAction SilentlyContinue -ComputerName $computerName -ErrorVariable $errorVar)

        Write-Output $results | Select-Object $computerNameExpression,
        $sourceExpression,
        $sortKeyExpression,
        $idExpression,
        $timeExpression,
        $eventRecordIDExpression,
        $messageExpression,
        $detailsExpression,
        $details2Expression
    }

    #script block that gathers security audits
    $getAuditsWorker = {
        param([string]$activityId, [string]$computerName)
        [System.Guid]$activityGuid = [System.Guid]::Parse($activityId)
        $normalizedGuidForAudits = $activityGuid.ToString()
        $xpathFilterAudits = "*[EventData[Data='$normalizedGuidForAudits']]"

        $idExpression = @{ label = 'EventId'; Expression = {$_.Id } }
        $timeExpression = @{ label = 'TimeCreated'; Expression = { $_.TimeCreated } }
        $eventRecordIDExpression = @{ label = 'EventRecordID'; Expression = {[System.Convert]::ToInt32((([xml]$_.ToXml()).Event.System.EventRecordId)) } }
        $messageExpression = @{ label = 'Message'; Expression = {$_.Message} }
        $detailsExpression = @{ label = 'Details'; Expression = {if ($_.Message -ne $_.properties[0].value) { $_.properties[0].value } else { "" } } }
        $details2Expression = @{ label = 'Details2'; Expression = {$_.properties[1].value } }
        $computerNameExpression = @{ label = 'ComputerName'; Expression = { $computerName } }
        $sourceAuditExpression = @{ label = 'Source'; Expression = {"Audits"} }
        $sortKeyExpression = @{ label = 'SortKey'; Expression = { 1 } }

        $auditTraces = Get-WinEvent -LogName "Security" -Oldest -FilterXPath $xpathFilterAudits -ErrorAction SilentlyContinue -ComputerName $computerName

        $results = $auditTraces

        #audits also have instance ID. To harvest those, let's find the data1 fields that are like a guid and are not the activity id
        $instanceIds = $auditTraces | where { $_.Details -match "[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}" -and $_.Details -ne $normalizedGuidForAudits } | Select-Object  -ExpandProperty Details -Unique
        foreach ($instanceId in $instanceIds)
        {
            $xpathFilterAuditsByInstId = "*[EventData[Data='$instanceId']]"
            $results = $results + [array](Get-WinEvent -LogName "Security" -Oldest -FilterXPath $xpathFilterAuditsByInstId -ErrorAction SilentlyContinue -ComputerName $computerName)
        }

        Write-Output $results | Select-Object $computerNameExpression,
        $sourceAuditExpression,
        $sortKeyExpression,
        $idExpression,
        $timeExpression,
        $eventRecordIDExpression,
        $messageExpression,
        $detailsExpression,
        $details2Expression
    }
    $jobs = @()

    $activity = "Getting AD FS request details for ActivityId=$activityId"

    Write-Progress -Activity $activity -Status "Querying event logs in parallel"
    foreach ($server in $computerName)
    {
        $jobs = [array]$jobs + (Start-Job -Name $server+"-Admin" -ScriptBlock $getEventWorker -ArgumentList @("Admin", $activityId, $server))

        if ($includeDebug)
        {
            $jobs = [array]$jobs + (Start-Job -Name $server+"-Trace" -ScriptBlock $getEventWorker -ArgumentList @("Debug", $activityId, $server))
        }

        $jobs = [array]$jobs + [array](Start-Job -Name $server+"-Audit" -ScriptBlock $getAuditsWorker -ArgumentList @($activityId, $server))
    }

    Write-Output $jobs
}

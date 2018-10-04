<#
.SYNOPSIS
Combines and sorts all the AD FS events generated given an activity ID from background jobs

.DESCRIPTION
The Receive-AdfsServerTrace them combines and sorts the results of each background job created with Start-AdfsServerTrace.
If the jobs have not completed, the commandlet will wait until completion of all jobs.
At the end, the jobs will be removed

.PARAMETER Jobs
Background jobs generated with the Start-AdfsServerTrace cmdlet

.EXAMPLE
$jobs = Start-AdfsServerTrace -ActivityId 00000000-0000-0000-9701-0080000000df -ComputerName @("ADFSSRV1","ADFSSRV2")
Get Admin and Audits for activity ID 00000000-0000-0000-9701-0080000000df on Servers ADFSSRV1 and ADFSSRV2

On a regular basis, check how many have completed and how many are running
$jobs | Get-Job -IncludeChildJob | Group-Object State

At any point, receive the jobs
$results = Receive-AdfsServerTrace -Jobs $jobs

.NOTES
The cmdlet sorts the events based on event timestamp first, then the source of the event (Audit, Admin, and Debug), and then the sequencing within the event source the event came from.
#>
Function Receive-AdfsServerTrace
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [array]$Jobs
    )

    try
    {
        $activity = "Retrieving AD FS Server Trace"

        Write-Progress -Activity $activity -Status "Waiting for all jobs to finish"
        $jobs | Get-Job -IncludeChildJob | Wait-Job | Out-Null

        Write-Progress -Activity $activity -Status "Merging and sorting events found"
        $combined = @()
        foreach ($job in $jobs)
        {
            $result = $job | Get-Job -IncludeChildJob | Receive-Job -ErrorAction SilentlyContinue
            $combined = $combined + [array]$result
        }

        $combinedSorted = $combined | Sort-Object TimeCreated, SortKey, EventRecordID | Select-Object ComputerName, Source, TimeCreated, EventId, Message, Details, Details2

        Write-Output $combinedSorted
    }
    finally
    {
        #Clean after the jobs generated
        $Jobs | Get-Job | Remove-Job
    }
}

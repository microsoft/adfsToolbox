<#
.SYNOPSIS
Retrieves all the AD FS events generated given an Activity ID ID accross different computers

.DESCRIPTION
The Get-ADFSActivityIdRecords cmdlet queries all computers' event logs for the activity ID supplied in parallel, and them combines and sorts the results.
This cmdlet works in AD FS 2.0 and later.


.PARAMETER ActivityId
Activity ID to search for. This typically comes from an AD FS error page.

.PARAMETER ComputerName
It is an array of computers, which represents the AD FS servers to try. If omitted, the local machine will be used

.PARAMETER OutHtmlFilePath
If supplied, the results will be generated in an html table format, saved in the path specified and opened in the internet browser.

.EXAMPLE
Get-AdfsServerTrace -ActivityId 00000000-0000-0000-9701-0080000000df -ComputerName @("ADFSSRV1","ADFSSRV2")
Get Admin and Audits for activity ID 00000000-0000-0000-9701-0080000000df on Servers ADFSSRV1 and ADFSSRV2

.EXAMPLE
Get-AdfsServerTrace -ActivityId 00000000-0000-0000-9701-0080000000df -ComputerName (Get-Content .\Servers.txt)
Get Admin and Audits for activity ID 00000000-0000-0000-9701-0080000000df from servers in a text file

.EXAMPLE
Get-AdfsServerTrace -ActivityId 00000000-0000-0000-9701-0080000000df -IncludeDebug -ComputerName @("ADFSSRV1","ADFSSRV2")
Get Admin and Audits for activity ID 00000000-0000-0000-9701-0080000000df on Server ADFSSRV1 and ADFSSRV2, including debug traces

.EXAMPLE
Get-AdfsServerTrace -ActivityId 00000000-0000-0000-9701-0080000000df -IncludeDebug -ComputerName @("ADFSSRV1","ADFSSRV2") -OutHtmlFilePath ".\ActivityIdReport.htm"
Get Admin and Audits for activity ID 00000000-0000-0000-9701-0080000000df on Server ADFSSRV1 and ADFSSRV2, including debug traces and save the result in an HTML file.

.NOTES
You need to run this function using an account that has permissions to read the event logs in all computers supplied.
This is typically achieved having the account be part of the "Event Log Readers" Local Security Group.
The computers supplied also should have firewall rules configured to allow remote readings.
#>
Function Get-AdfsServerTrace
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

        [string]
        $OutHtmlFilePath,

        [string[]]
        $ComputerName = @("localhost")
    )

    #Get the background jobs to search all computers in parallel, and retrieve the results
    $jobs = Start-AdfsServerTrace -ActivityId $ActivityId -IncludeDebug:$IncludeDebug -ComputerName $ComputerName
    $results = Receive-AdfsServerTrace -Jobs $jobs

    if ($OutHtmlFilePath)
    {
        $results | ConvertTo-Html | Out-File $OutHtmlFilePath -Force
        Write-Output "Report Generated at $OutHtmlFilePath"
        Start $OutHtmlFilePath
    }
    else
    {
        Write-Output $results
    }
}
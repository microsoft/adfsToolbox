function Initialize()
{
    ipmo .\AdfsEventsModule.psm1
    Set-AdfsProperties -AuditLevel Verbose

    # Try installing an RP. If it already exists, use the existing one 
    try
    {
        $authzRules = "=>issue(Type = `"http://schemas.microsoft.com/authorization/claims/permit`", Value = `"true`"); "
        $issuanceRules = "x:[]=>issue(claim = x); "
        $redirectUrl = "https://adfshelp.microsoft.com/ClaimsXray/TokenResponse"
        $samlEndpoint = New-AdfsSamlEndpoint -Binding POST -Protocol SAMLAssertionConsumer -Uri $redirectUrl

        Add-ADFSRelyingPartyTrust -Name "ClaimsXray" -Identifier "urn:microsoft:adfs:claimsxray" -IssuanceAuthorizationRules $authzRules -IssuanceTransformRules $issuanceRules -WSFedEndpoint $redirectUrl -SamlEndpoint $samlEndpoint
    }
    catch
    {

    }

    # Clear any existing logs 

}

function Make-Request([string]$Guid){
    $farmhost = (Get-AdfsProperties).HostName
    $url = "https://" + $farmhost + "/adfs/ls?wa=wsignin1.0&wtrealm=urn:microsoft:adfs:claimsxray"

    if ( $Guid )
    {
        $url = $url + "&client-request-id=" + $Guid
    }

    Invoke-WebRequest -URI $url
}

function Validate-LogEventCount([object]$logs){
    if($logs.Count -gt 0 -and $logs[0].Events.Count -gt 0)
    {
        return $true    
    }

    return $false
} 

Describe 'Basic functionality of Get-AdfsEvents'{
    BeforeAll {
        Initialize

        # Make a few requests for the ByTime tests 
        $global:startTime = Get-Date
        for($i=0; $i -le 5; $i++)
        {
            Make-Request
        }

        $global:currentGuid = [guid]::NewGuid()
        Make-Request($global:currentGuid.Guid)

        # Give the auditing system time to flush the audits to the system 
        Start-Sleep -Seconds 3

        $global:endTime = Get-Date

        $securityLogs = "Security"
        $global:exportFileName = (pwd).Path + "\SecurityLogs.evtx"
        wevtutil.exe export-log $securityLogs $exportFileName /overwrite:true
    }

    AfterAll {
        rm $global:exportFileName
    }

    It "[00000]: 'All' Flag Returns CorrIDs that are valid guids"{
        $logs = Get-AdfsEvents -Logs Security -All
        
        Validate-LogEventCount($logs) | Should -Be $true

        $hasInvalidGuid = $false

        foreach ( $aggObj in $logs )
        {
            $guidRef = [ref] [System.Guid]::NewGuid()
            $valid = [System.Guid]::TryParse( $aggObj.CorrelationID, $guidRef )

            if ( !$valid -or ( $guidRef.Value -ne $aggObj.CorrelationID ) )
            {
                $hasInvalidGuid = $true
                break
            }
        }

        $hasInvalidGuid | Should -Be $false
    }

    It "[00000]: 'All' Flag Returns Multiple Aggregate Objects, with Multiple Events"{
        $logs = Get-AdfsEvents -Logs Security, Admin -All
        Validate-LogEventCount($logs) | Should -Be $true
    }

    It "[00000]: 'All' Flag Returns Aggregate Objects, with Events by correlation ID"{
        $logs = Get-AdfsEvents -Logs Security, Admin -All
        
        $hasInvalidId = $false
        foreach ( $aggObj in $logs )
        {
            foreach ( $event in $aggObj.Events )
            {
                if ( $event.CorrelationID -ne $aggObj.CorrelationID )
                {
                    $hasInvalidId = $true
                }
            }
        }

        $hasInvalidId | Should -Be $false
    }

    It "[00100]: 'All' Flag with FromFile Returns Non-Empty Events List"{
        $logs = Get-AdfsEvents -Logs Security -All -FilePath $global:exportFileName
        Validate-LogEventCount($logs) | Should -Be $true
    }

    It "[01000]: 'All' Flag with AnalysisData Returns Analysis Objects"{
        $logs = Get-AdfsEvents -Logs Security -All -CreateAnalysisData

        $hasInvalidBlob = $false

        foreach ( $aggObj in $logs )
        {
            if ( -not $aggObj.AnalysisData.requests.Count )
            {
                $hasInvalidBlob = $true
                break
            }
        }

        $hasInvalidBlob | Should -Be $false
    }

    It "[01001]: ByTime with AnalysisData Returns Analysis Objects"{
        $logs = Get-AdfsEvents -Logs Security -CreateAnalysisData -StartTime $global:startTime -EndTime $global:endTime 

        $hasInvalidBlob = $false

        foreach ( $aggObj in $logs )
        {
            if ( -not $aggObj.AnalysisData.requests.Count )
            {
                $hasInvalidBlob = $true
                break
            }
        }

        $hasInvalidBlob | Should -Be $false
    }

    It "[01001]: ByTime returns Multiple Aggregate Objects, with Multiple Events"{
        $logs = Get-AdfsEvents -Logs Security -StartTime $global:startTime -EndTime $global:endTime 
        Validate-LogEventCount($logs) | Should -Be $true
    }

    It "[01100]: 'All' Flag with AnalysisData with FromFile Returns Non-Empty Events List"{
        $logs = Get-AdfsEvents -Logs Security -All -FilePath $global:exportFileName -CreateAnalysisData
        Validate-LogEventCount($logs) | Should -Be $true
    }

    It "[01101]: ByTime with AnalysisData with FromFile returns Non-Empty Events List"{
        $logs = Get-AdfsEvents -Logs Security -FilePath $global:exportFileName -CreateAnalysisData -StartTime $global:startTime -EndTime $global:endTime 
        Validate-LogEventCount($logs) | Should -Be $true
    }

    It "[10000]: CorrelationID Call Returns Exactly 1 Aggregate Object"{
        $logs = Get-AdfsEvents -Logs Security, Admin, Debug -CorrelationID $global:currentGuid.Guid

        # Note: despite the fact that PowerShell should always be giving us a list object out of Get-AdfsEvents, the 
        #  Count and Length calls do not work when there is only 1 entry in the list 

        $hasAtLeastOne = $false
        $hasExactlyOne = $false

        if ( $logs[0].CorrelationID )
        {
            $hasAtLeastOne = $true            
        }

        if ( $hasAtLeastOne -and ( -not $logs[1] ) )
        {
            $hasExactlyOne = $true            
        }

        $hasExactlyOne | Should -Be $true
    }

    It "[10000]: CorrelationID Call Returns Non-Empty Events list"{
        $logs = Get-AdfsEvents -Logs Security, Admin, Debug -CorrelationID $global:currentGuid.Guid
        $logs[0].Events.Count | Should -BeGreaterThan 0 
    }

    It "[10000]: CorrelationID Call Returns Events list with 403 and 404"{

        $logs = Get-AdfsEvents -Logs Security, Admin, Debug -CorrelationID $global:currentGuid.Guid

        $has403 = $false
        $has404 = $false 

        foreach( $event in $logs.Events )
        {
            if ( $event.Id -eq 403 )
            {
                $has403 = $true
            }

            if ( $event.Id -eq 404 )
            {
                $has404 = $true
            }
        }

        $hasBoth = $has403 -and $has404
        $hasBoth | Should -Be $true
    }

    It "[10000]: CorrelationID Call Returns Analysis Data With Single Request"{
        $logs = Get-AdfsEvents -Logs Security, Admin, Debug -CorrelationID $global:currentGuid.Guid -CreateAnalysisData
        $logs.AnalysisData.requests.Count | Should -Be 1
    }

    It "[10000]: CorrelationID Call Returns Analysis Data With Single Timeline Event"{
        $logs = Get-AdfsEvents -Logs Security, Admin, Debug -CorrelationID $global:currentGuid.Guid -CreateAnalysisData
        $logs.AnalysisData.timeline.Count | Should -Be 1
        $logs.AnalysisData.timeline[0].type | Should -Be "incoming"
    }

    It "[10100]: CorrelationID Call with FromFile returns Non-Empty Events List"{
        $logs = Get-AdfsEvents -Logs Security -CorrelationID $global:currentGuid.Guid -FilePath $global:exportFileName
        $logs[0].Events.Count | Should -BeGreaterThan 0 
    }

    It "[10101]: ByTime with CorrelationID is not a valid scenario"{
        
        $invalidScenarioError = $false;

        try
        {
            $logs = Get-AdfsEvents -Logs Security -StartTime $global:startTime -EndTime $global:endTime -CorrelationID $global:currentGuid.Guid
        }catch [System.Management.Automation.ParameterBindingException]
        {
            $invalidScenarioError = $true;
        }
        
        $invalidScenarioError | Should -Be $true
    }

    It "[11100]: CorrelationID Call with AnalysisData with FromFile returns Non-Empty Events List"{
        $logs = Get-AdfsEvents -Logs Security -CorrelationID $global:currentGuid.Guid -FilePath $global:exportFileName -CreateAnalysisData 
        $logs[0].Events.Count | Should -BeGreaterThan 0 
    }
}
<#
.SYNOPSIS
Retrieves overall details of the computer

.DESCRIPTION
The Get-AdfsSystemInformation gathers information regarding operating system and hardware

.EXAMPLE
Get-AdfsSystemInformation | ConvertTo-Json | Out-File ".\ADFSFarmDetails.txt"
Get the operating system data of the server and save it in JSON format
#>
Function Get-AdfsSystemInformation()
{
    [CmdletBinding()]
    Param()
    
    try
    {
        $role = Get-ADFSRole
    } 
    catch
    {
        $role = "none"
    }
    
    $systemOutput = New-Object PSObject;

    $osVersionPropertyName = "OSVersion"
    $adfsVersionPropertyName = "AdfsVersion"
    try
    {
        $OSVersion = [System.Environment]::OSVersion.Version
        $systemOutput | Add-Member NoteProperty -name $osVersionPropertyName -value $OSVersion -Force;
        $systemOutput | Add-Member NoteProperty -name $adfsVersionPropertyName -value (Get-AdfsVersion($OSVersion)) -Force;
    } 
    catch 
    {
        $systemOutput | Add-Member NoteProperty -name $osVersionPropertyName -value $null -Force
        $systemOutput | Add-Member NoteProperty -name $adfsVersionPropertyName -value $null -Force
    }
    $osNamePropertyName = "OSName"
    $lastRebootTimePropertyName = "LastRebootTime"
    try
    {
        $operatingSystem = Get-WmiObject -Class Win32_OperatingSystem;
        $systemOutput | Add-Member NoteProperty -name $osNamePropertyName -value $operatingSystem.Caption -Force;
        $systemOutput | Add-Member NoteProperty -name $lastRebootTimePropertyName -value $operatingSystem.ConvertToDateTime($operatingSystem.LastBootUpTime).ToUniversalTime() -Force;
    } 
    catch 
    {
        $systemOutput | Add-Member NoteProperty -name $osNamePropertyName -value $null -Force;
        $systemOutput | Add-Member NoteProperty -name $lastRebootTimePropertyName -value $null -Force;
    }
    
    $domainPropertyName = "MachineDomain"
    $machineTypePropertyName = "MachineType"
    $physicalMemoryPropertyName = "PhsicalMemory"
    $top10ProcessesByMemoryPropertyName = "Top10ProcessesByMemory"
    try
    {
        $computerSystem = Get-WmiObject -class win32_computersystem;
        $systemOutput | Add-Member NoteProperty -name $domainPropertyName -value $computerSystem.Domain -Force
        $systemOutput | Add-Member NoteProperty -name $machineTypePropertyName -value $computerSystem.Model -Force;
        
        try 
        {
            $totalMemoryInMb = (Get-WmiObject -class "Win32_PerfRawData_Counters_HyperVDynamicMemoryIntegrationService" -ErrorAction Stop | Select-Object -ExpandProperty MaximumMemoryMBytes)
        } 
        catch  
        {
            # class (Win32_PerfRawData_Counters_HyperVDynamicMemoryIntegrationService) does not exist in Windows 2008 R2/Windows 7 or earlier operating systems 
            # explicitly set to empty to force code to recalculate the physical memory
            $totalMemoryInMb = ""
        }

        if([string]::IsNullOrEmpty($totalMemoryInMb))
        {
            $totalMemory = ($computerSystem | Measure-Object -Property TotalPhysicalMemory -Sum | Select-Object -ExpandProperty Sum)
            $totalMemoryInMb = [Math]::Round($totalMemory / 1Mb)
        }
        $systemOutput | Add-Member NoteProperty -name $physicalMemoryPropertyName -value $totalMemoryInMb -Force
        
        try
        {
            #Get the top 10 with the highest private working set memory, adding the percentage of total
            $processes = gwmi -Class Win32_PerfRawData_PerfProc_Process -Property @("Name","WorkingSetPrivate")
            $top10ProcessesByMemory = $processes | sort WorkingSetPrivate -Descending | Where-Object {$_.Name -ne "_Total"} | `
                Select-Object -First 10 -Property `
                    Name,`
                    @{Name="MemoryInMB";Expression = {$_.WorkingSetPrivate / 1Mb}},`
                    @{Name="MemoryPercentOfTotal";Expression = {100 * $_.WorkingSetPrivate / $totalMemory}}
            $systemOutput | Add-Member NoteProperty -name $top10ProcessesByMemoryPropertyName -value $top10ProcessesByMemory -Force;
        } 
        catch 
        {
            $systemOutput | Add-Member NoteProperty -name $top10ProcessesByMemoryPropertyName -value $null -Force;
        }
    } 
    catch 
    {
        $systemOutput | Add-Member NoteProperty -name $domainPropertyName -value $null -Force
        $systemOutput | Add-Member NoteProperty -name $machineTypePropertyName -value $null -Force
        $systemOutput | Add-Member NoteProperty -name $physicalMemoryPropertyName -value $null -Force
        $systemOutput | Add-Member NoteProperty -name $top10ProcessesByMemoryPropertyName -value $null -Force;
    }
    
    $ipAddressPropertyName = "IPAddress"
    try
    {
        $systemOutput | Add-Member NoteProperty -name $ipAddressPropertyName -value (Get-WmiObject Win32_NetworkAdapterConfiguration -Namespace "root\CIMV2" | where{$_.IPEnabled -eq "True"}).IPAddress[0] -Force;
    } 
    catch 
    {
        $systemOutput | Add-Member NoteProperty -name $ipAddressPropertyName -value $null -Force;
    }
    
    $timeZonePropertyName = "TimeZone"
    try
    {
        $systemOutput | Add-Member NoteProperty -name $timeZonePropertyName -value ([System.TimeZone]::CurrentTimeZone.StandardName) -Force
    } 
    catch 
    {
        $systemOutput | Add-Member NoteProperty -name $timeZonePropertyName -value $null -Force
    }

    $processorsCountPropertyName = "NumberOfLogicalProcessors"
    $maxClockSpeedPropertyName = "MaxClockSpeed"
    try
    { 
        $processor = Get-WmiObject -class win32_processor;
        $systemOutput | Add-Member NoteProperty -name $processorsCountPropertyName -value $processor.NumberOfLogicalProcessors -Force;
        $systemOutput | Add-Member NoteProperty -name $maxClockSpeedPropertyName -value $processor.MaxClockSpeed -Force;
    } 
    catch 
    {
        $systemOutput | Add-Member NoteProperty -name $processorsCountPropertyName -value $null -Force
        $systemOutput | Add-Member NoteProperty -name $maxClockSpeedPropertyName -value $null -Force
    }

    $hostsPropertyName = "Hosts"
    try
    {
        $hostsEntry = @{};
        $hostsFile = Join-Path $env:SystemRoot "system32\drivers\etc\hosts"
        $regex = [regex] "\s+";
        foreach ($line in Get-Content $hostsFile)
        {
            $ip = new-object System.Net.IPAddress -ArgumentList 0
            $trimmed = $line.Trim();

            if (![string]::IsNullOrEmpty($trimmed) -and
                !($trimmed.StartsWith("#")) -and 
                ($items = $regex.Split($trimmed)).Count -ge 2 -and
                ![string]::IsNullOrEmpty($items[1]) -and
                !$hostsEntry.ContainsKey($items[1]) -and
                [system.net.ipaddress]::TryParse($items[0], [ref] $ip))
            {
                $hostsEntry.Add($items[1], $items[0]);
            }
        }
        $systemOutput | Add-Member NoteProperty -name $hostsPropertyName -value $hostsEntry -Force;
    } 
    catch 
    { 
        $systemOutput | Add-Member NoteProperty -name $hostsPropertyName -value $null -Force;
    }
    
    $hotFixesPropertyName = "Hotfixes"
    try
    { 
        $hotFixEntries = @{};
        $hotFixes = Get-WmiObject Win32_QuickFixEngineering | Select HotfixId, InstalledOn;
        foreach ($hotFix in $hotFixes)
        {
            if (!($hotFixEntries.ContainsKey($hotFix.HotfixId)))
            {
                $hotFixEntries.Add($hotFix.HotfixId, $hotFix.InstalledOn);
            }
        }
        $systemOutput | Add-Member NoteProperty -name $hotFixesPropertyName -value $hotFixEntries -Force;
    } 
    catch 
    {
        $systemOutput | Add-Member NoteProperty -name $hotFixesPropertyName -value $null -Force;
    }
    
    $adfsWmiPropsPropertyName = "AdfsWmiProperties"
    try
    {
        $adfsWmiProperties = @{};
        if ($role -eq "STS")
        {
            foreach ($adfsWmiProperty in (Get-WmiObject -namespace root/ADFS -class SecurityTokenService).Properties)
            {
                if (!($adfsWmiProperties.ContainsKey($adfsWmiProperty.Name)))
                {
                    $adfsWmiProperties.Add($adfsWmiProperty.Name, $adfsWmiProperty.Value);
                }
            }
        }
        $systemOutput | Add-Member NoteProperty -name $adfsWmiPropsPropertyName -value $adfsWmiProperties -Force;
    } 
    catch 
    {
        $systemOutput | Add-Member NoteProperty -name $adfsWmiPropsPropertyName -value $null -Force;
    }

    $sslBindingsPropertyName = "SslBindings"
    try
    { 
        $bindings = @(@{});
        $bindingCount = -1;
        $bindingsStr = netsh http show sslcert 
        
        #remove all title/extra lines 
        $bindingsStr = $bindingsStr | foreach{$tok = $_.Split(":"); IF ($tok.Length -gt 1 -and $tok[1].TrimEnd() -ne "" -and $tok[0].StartsWith(" ")){$_}}
        
        foreach ($bindingLine in $bindingsStr)
        {
            if ($bindingLine.Trim().ToLower().StartsWith("ip:port"))
            {
                $bindings += @{};
                $bindingCount = $bindingCount + 1;
                $bindings[$bindingCount].Add("IPPort", $bindingLine.Trim().Split(':')[2].Trim() + ":" + $bindingLine.Trim().Split(':')[3].Trim());
                Continue;
            }
            if ($bindingLine.Trim().ToLower().StartsWith("hostname:port"))
            {
                $bindings += @{};
                $bindingCount = $bindingCount + 1;
                $bindings[$bindingCount].Add("HostnamePort", $bindingLine.Trim().Split(':')[2].Trim() + ":" + $bindingLine.Trim().Split(':')[3].Trim());
                Continue;
            }
            if ($bindingCount -ge 0)
            {
                $bindings[$bindingCount].Add($bindingLine.Trim().Split(':')[0].Trim(), $bindingLine.Trim().Split(':')[1].Trim());
            }
        }
        $systemOutput | Add-Member NoteProperty -name $sslBindingsPropertyName -value $bindings -Force;
    } 
    catch 
    {
        $systemOutput | Add-Member NoteProperty -name $sslBindingsPropertyName -value $null -Force;
    }

    if ($role -ne "none")
    {
        $adfsServiceAcountPropertyName = "AdfssrvServiceAccount"
        try
        {
            $adfsServiceAccount = (Get-WmiObject win32_service | Where-Object {$_.name -eq "adfssrv"}).StartName;
            $systemOutput | Add-Member NoteProperty -name $adfsServiceAcountPropertyName -value $adfsServiceAccount -Force;
        } 
        catch 
        { 
            $systemOutput | Add-Member NoteProperty -name $adfsServiceAcountPropertyName -value $null -Force;
        }
    }
    
    # No Try-catch needed for this property
    $systemOutput | Add-Member NoteProperty -name "Role" -value $role -Force;

    #get ADHealthAgent update information
    $agentInformationPropertyName = "AdHealthAgentInformation"
    try
    { 
        $agentInformation = New-Object AdHealthAgentInformation

        $agentInformation.Version = (GetAdHealthAgentRegistryKeyValue -ValueName ([RegistryValueName]::CurrentVersion) -DefaultValue "Unknown")
        $agentInformation.UpdateState = (GetAdHealthAgentRegistryKeyValue -ValueName ([RegistryValueName]::UpdateState) -DefaultValue "None")
        $agentInformation.LastUpdateAttemptVersion = (GetAdHealthAgentRegistryKeyValue -ValueName ([RegistryValueName]::VersionOfUpdate) -DefaultValue "None")
        $agentInformation.NumberOfFailedAttempts = (GetAdHealthAgentRegistryKeyValue  -ValueName ([RegistryValueName]::NumberOfFailedAttempts)  -DefaultValue 0)
        # InstallerExitCode is no longer available
        $agentInformation.InstallerExitCode = "Unknown"
        
        $NotFound = "NotFound";
        $LastUpdateAttemptTimeLong = GetAdHealthAgentRegistryKeyValue -ValueName ([RegistryValueName]::LastUpdateAttempt) -DefaultValue $NotFound
        if($LastUpdateAttemptTimeLong -eq $NotFound)
        {
            #use DateTime.min as LastUpdateAttempt value if it is not found in registry
            $agentInformation.LastUpdateAttemptTime = [dateTime]::MinValue
        }
        else
        {
            #convert from filetime to utc
            $LastUpdateAttemptUTC =  [datetime]::FromFileTime($LastUpdateAttemptTimeLong).ToUniversalTime()
            $agentInformation.LastUpdateAttemptTime = $LastUpdateAttemptUTC
        }
        $systemOutput | Add-Member NoteProperty -Name $agentInformationPropertyName -Value $agentInformation -Force
    } 
    catch 
    {
        $systemOutput | Add-Member NoteProperty -Name $agentInformationPropertyName -Value $null -Force
    }

    return $systemOutput;
}

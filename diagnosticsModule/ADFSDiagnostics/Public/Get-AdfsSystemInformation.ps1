<#
.SYNOPSIS
Retrieves overall details of the computer

.DESCRIPTION
The Get-AdfsSystemConfiguration gathers information regarding operating system and hardware

.EXAMPLE
Get-AdfsSystemConfiguration | ConvertTo-Json | Out-File ".\ADFSFarmDetails.txt"
Get the operating system data of the server and save it in JSON format
#>
Function Get-AdfsSystemInformation()
{
    [CmdletBinding()]
    Param()

    $role = Get-ADFSRole


    $systemOutput = New-Object PSObject;

    $OSVersion = [System.Environment]::OSVersion.Version
    $systemOutput | Add-Member NoteProperty -name "OSVersion" -value $OSVersion -Force;

    $computerSystem = Get-WmiObject -class win32_computersystem;
    $operatingSystem = Get-WmiObject -Class Win32_OperatingSystem;
    $timeZone = [System.TimeZone]::CurrentTimeZone.StandardName;
    $systemOutput | Add-Member NoteProperty -name "OSName" -value (Get-WmiObject Win32_OperatingSystem).Caption -Force;
    $systemOutput | Add-Member NoteProperty -name "MachineDomain" -value (Get-WmiObject Win32_ComputerSystem).Domain -Force;
    $systemOutput | Add-Member NoteProperty -name "IPAddress" -value (Get-WmiObject Win32_NetworkAdapterConfiguration -Namespace "root\CIMV2" | where {$_.IPEnabled -eq "True"}).IPAddress[0] -Force;
    $systemOutput | Add-Member NoteProperty -name "TimeZone" -value $timeZone -Force;
    $systemOutput | Add-Member NoteProperty -name "LastRebootTime" -value $operatingSystem.ConvertToDateTime($operatingSystem.LastBootUpTime).ToUniversalTime() -Force;
    $systemOutput | Add-Member NoteProperty -name "MachineType" -value $computerSystem.Model -Force;

    $processor = Get-WmiObject -class win32_processor;
    $systemOutput | Add-Member NoteProperty -name "NumberOfLogicalProcessors" -value $processor.NumberOfLogicalProcessors -Force;
    $systemOutput | Add-Member NoteProperty -name "MaxClockSpeed" -value $processor.MaxClockSpeed -Force;

    $totalMemory = (get-ciminstance -class "cim_physicalmemory" | Measure-Object -Property Capacity -Sum | Select-Object -ExpandProperty Sum)
    $totalMemoryInMb = $totalMemory / 1Mb

    $systemOutput | Add-Member NoteProperty -name "PhsicalMemory" -value $totalMemoryInMb

    $hostsEntry = @{};
    $hostsFile = [system.environment]::getenvironmentvariable("SystemDrive") + "\windows\system32\drivers\etc\hosts";
    foreach ($line in Get-Content $hostsFile)
    {
        $ipAddress = "";
        $dnsName = "";
        if (!($line.StartsWith("#")) -and !($line.Trim() -eq ""))
        {
            If ($line.Trim().Split("`t").Count -eq 2)
            {
                $ipAddress = $line.Trim().Split("`t")[0];
                $dnsName = $line.Trim().Split("`t")[1];
            }
            Else
            {
                $regex = [regex] "\s+";
                If ($regex.Split($line).Count -eq 2)
                {
                    $ipAddress = $regex.Split($line)[0];
                    $dnsName = $regex.Split($line)[1];
                }
            }
            if ($ipAddress -ne "" -and $dnsName -ne "")
            {
                if (!($hostsEntry.ContainsKey($dnsName)))
                {
                    $hostsEntry.Add($dnsName, $ipAddress);
                }
            }
        }
    }
    $systemOutput | Add-Member NoteProperty -name "Hosts" -value $hostsEntry -Force;

    $hotFixEntries = @{};
    $hotFixes = Get-WmiObject Win32_QuickFixEngineering | Select HotfixId, InstalledOn;
    foreach ($hotFix in $hotFixes)
    {
        if (!($hotFixEntries.ContainsKey($hotFix.HotfixId)))
        {
            $hotFixEntries.Add($hotFix.HotfixId, $hotFix.InstalledOn);
        }
    }
    $systemOutput | Add-Member NoteProperty -name "Hotfixes" -value $hotFixEntries -Force;

    $adfsWmiProperties = @{};

    if ($role -eq $adfsRoleSTS)
    {
        Foreach ($adfsWmiProperty in (Get-WmiObject -namespace root/ADFS -class SecurityTokenService).Properties)
        {
            if (!($adfsWmiProperties.ContainsKey($adfsWmiProperty.Name)))
            {
                $adfsWmiProperties.Add($adfsWmiProperty.Name, $adfsWmiProperty.Value);
            }
        }
    }

    $systemOutput | Add-Member NoteProperty -name "AdfsWmiProperties" -value $adfsWmiProperties -Force;


    $bindings = @(@{});
    $bindingCount = -1;
    $bindingsStr = netsh http show sslcert

    #remove all title/extra lines
    $bindingsStr = $bindingsStr | Foreach {$tok = $_.Split(":"); IF ($tok.Length -gt 1 -and $tok[1].TrimEnd() -ne "" -and $tok[0].StartsWith(" ")) {$_}}

    foreach ($bindingLine in $bindingsStr)
    {
        If ($bindingLine.Trim().ToLower().StartsWith("ip:port"))
        {
            $bindings += @{};
            $bindingCount = $bindingCount + 1;
            $bindings[$bindingCount].Add("IPPort", $bindingLine.Trim().Split(':')[2].Trim() + ":" + $bindingLine.Trim().Split(':')[3].Trim());
            Continue;
        }
        If ($bindingLine.Trim().ToLower().StartsWith("hostname:port"))
        {
            $bindings += @{};
            $bindingCount = $bindingCount + 1;
            $bindings[$bindingCount].Add("HostnamePort", $bindingLine.Trim().Split(':')[2].Trim() + ":" + $bindingLine.Trim().Split(':')[3].Trim());
            Continue;
        }
        $bindings[$bindingCount].Add($bindingLine.Trim().Split(':')[0].Trim(), $bindingLine.Trim().Split(':')[1].Trim());
    }
    $systemOutput | Add-Member NoteProperty -name "SslBindings" -value $bindings -Force;

    if ($role -ne "none")
    {
        $adfsServiceAccount = (Get-WmiObject win32_service | Where-Object {$_.name -eq "adfssrv"}).StartName;
        $systemOutput | Add-Member NoteProperty -name "AdfssrvServiceAccount" -value $adfsServiceAccount -Force;
    }

    $ADFSVersion = Get-AdfsVersion;
    $systemOutput | Add-Member NoteProperty -name "AdfsVersion" -value $ADFSVersion -Force;

    $systemOutput | Add-Member NoteProperty -name "Role" -value $role -Force;

    #Get the top 10 with the highest private working set memory, adding the percentage of total
    $processes = gwmi -Class Win32_PerfRawData_PerfProc_Process -Property @("Name", "WorkingSetPrivate")
    $top10ProcessesByMemory = $processes | sort WorkingSetPrivate -Descending | Where-Object {$_.Name -ne "_Total"} | Select-Object -First 10 Name, @{Name = "MemoryInMB"; Expression = {$_.WorkingSetPrivate / 1Mb}}, @{Name = "MemoryPercentOfTotal"; Expression = {100 * $_.WorkingSetPrivate / $totalMemory}}
    $systemOutput | Add-Member NoteProperty -name "Top10ProcessesByMemory" -value $top10ProcessesByMemory -Force;

    #get ADHealthAgent update information
    $agentInformation = New-Object AdHealthAgentInformation
    $systemOutput | Add-Member NoteProperty -Name "AdHealthAgentInformation" -Value $agentInformation

    $systemOutput.AdHealthAgentInformation.Version = (GetAdHealthAgentRegistryKeyValue -ValueName ([RegistryValueName]::CurrentVersion) -DefaultValue "Unknown")
    $systemOutput.AdHealthAgentInformation.UpdateState = (GetAdHealthAgentRegistryKeyValue -ValueName ([RegistryValueName]::UpdateState) -DefaultValue "None")
    $systemOutput.AdHealthAgentInformation.LastUpdateAttemptVersion = (GetAdHealthAgentRegistryKeyValue -ValueName ([RegistryValueName]::VersionOfUpdate) -DefaultValue "None")
    $systemOutput.AdHealthAgentInformation.NumberOfFailedAttempts = (GetAdHealthAgentRegistryKeyValue  -ValueName ([RegistryValueName]::NumberOfFailedAttempts)  -DefaultValue 0)
    $systemOutput.AdHealthAgentInformation.InstallerExitCode = (GetAdHealthAgentRegistryKeyValue -ValueName ([RegistryValueName]::InstallerExitCode) -DefaultValue "Unknown").ToString()

    $NotFound = "NotFound";
    $LastUpdateAttemptTimeLong = GetAdHealthAgentRegistryKeyValue -ValueName ([RegistryValueName]::LastUpdateAttempt) -DefaultValue $NotFound
    if ($LastUpdateAttemptTimeLong -eq $NotFound)
    {
        #use DateTime.min as LastUpdateAttempt value if it is not found in registry
        $systemOutput.AdHealthAgentInformation.LastUpdateAttemptTime = [dateTime]::MinValue
    }
    else
    {
        #convert from filetime to utc
        $LastUpdateAttemptUTC = [datetime]::FromFileTime($LastUpdateAttemptTimeLong).ToUniversalTime()
        $systemOutput.AdHealthAgentInformation.LastUpdateAttemptTime = $LastUpdateAttemptUTC
    }

    $systemOutput;
}
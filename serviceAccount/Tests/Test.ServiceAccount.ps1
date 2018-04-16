#Define global constants
$script:Service_Account_Name = "newServiceAcct"

function New-ServiceAccount
{
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$username,
        
        [Parameter(Mandatory=$true,Position=1)]
        [string]$password
    )
    Process
    {
        ipmo ActiveDirectory
        $oldLocation = Get-Location
        Set-Location AD:
        
        $encryptedPassword = $password | ConvertTo-SecureString -asPlainText -Force

        try
        {
            $userObject = Get-ADUser $userName -ErrorAction SilentlyContinue
        }
        catch
        {
        }
        
        if ($userObject -eq $null)
        {
            New-ADUser -Name  $userName 
        }

        Get-ADUser $userName | Set-ADAccountPassword -Reset -NewPassword $encryptedPassword -PassThru 
        Get-ADUser $userName | Set-ADUser -PasswordNeverExpires $true -PassThru -Description "Password: $password" -Enabled $true
        
        Set-Location $oldLocation
    }
}

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

    [int] NumberOfRules()
    {
        return $this.rules.Count
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

            if ($rule.trim().Equals($ruleToFind.trim()))
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

# Gets internal ADFS settings by extracting them Get-AdfsProperties
function Get-AdfsInternalSettings()
{
    $settings = Get-AdfsProperties
    $settingsType = $settings.GetType()
    $propInfo = $settingsType.GetProperty("ServiceSettingsData", [System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic)
    $internalSettings = $propInfo.GetValue($settings, $null)
    
    return $internalSettings
}

function ValidateRules
{
    param
    (
        [parameter()]
        [switch]$CheckNotPresent
    )

    $Properties = Get-AdfsInternalSettings
    $AuthorizationPolicyRules = [AdfsRules]::new($Properties.PolicyStore.AuthorizationPolicy) 
    $AuthorizationPolicyReadOnlyRules = [AdfsRules]::new($Properties.PolicyStore.AuthorizationPolicyReadOnly)

    $SID = (New-Object system.security.principal.NtAccount($Service_Account_Name )).translate([system.security.principal.securityidentifier])
    $ServiceAccountRule = "@RuleName = `"Permit Service Account`"`nexists([Type == `"http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid`", Value == `"$SID`"])`n=> issue(Type = `"http://schemas.microsoft.com/authorization/claims/permit`", value = `"true`");`n`n"

    $AuthPolicyIndex = $AuthorizationPolicyRules.FindIndexForRule($ServiceAccountRule)
    $ReadOnlyIndex = $AuthorizationPolicyReadOnlyRules.FindIndexForRule($ServiceAccountRule)

    if($CheckNotPresent)
    {
        return ($AuthPolicyIndex -eq -1 -and $ReadOnlyIndex -eq -1)
    }
    return ($AuthPolicyIndex -ne -1 -and $ReadOnlyIndex -ne -1)

}


function Initialize()
{
    ipmo .\ServiceAccount.psm1
    New-ServiceAccount -username $script:Service_Account_Name -password "Password"
}

Describe 'Basic functionality of adding and removing service account rule'{
    BeforeAll {
        Initialize
    }

    AfterAll {
        Remove-ADUser -Identity $script:Service_Account_Name
    }

    It "[00000]: Add-AdfsServiceAccountRule adds permit rule to ruleset"{
        Add-AdfsServiceAccountRule -ServiceAccount $script:Service_Account_Name
        ValidateRules | Should Be $true
    }

    It "[00000]: Add-AdfsServiceAccountRule fails if rule already exists"{
        $BeforeProperties = Get-AdfsInternalSettings
        $BeforeAuthorizationPolicyRules = [AdfsRules]::new($Properties.PolicyStore.AuthorizationPolicy) 
        $BeforeAuthorizationPolicyReadOnlyRules = [AdfsRules]::new($Properties.PolicyStore.AuthorizationPolicyReadOnly)

        Add-AdfsServiceAccountRule -ServiceAccount $script:Service_Account_Name

        $AfterProperties = Get-AdfsInternalSettings
        $AfterAuthorizationPolicyRules = [AdfsRules]::new($Properties.PolicyStore.AuthorizationPolicy) 
        $AfterAuthorizationPolicyReadOnlyRules = [AdfsRules]::new($Properties.PolicyStore.AuthorizationPolicyReadOnly)

        $AuthPolicyMatches = $BeforeAuthorizationPolicyRules.NumberOfRules() -eq $AfterAuthorizationPolicyRules.NumberOfRules()
        $ReadOnlyMatches = $BeforeAuthorizationPolicyReadOnlyRules.NumberOfRules() -eq $AfterAuthorizationPolicyReadOnlyRules.NumberOfRules()



        ($AuthPolicyMatches -eq $ReadOnlyMatches) | Should Be $true
    }

    It "[00000]: Remove-AdfsServiceAccountRule removes permit rule to ruleset"{
        Remove-AdfsServiceAccountRule -ServiceAccount $script:Service_Account_Name 
        ValidateRules -CheckNotPresent | Should Be $true
    }

    It "[00000]: Remove-AdfsServiceAccountRule does nothing if rule isn't present"{
        $BeforeProperties = Get-AdfsInternalSettings
        $BeforeAuthorizationPolicyRules = [AdfsRules]::new($Properties.PolicyStore.AuthorizationPolicy) 
        $BeforeAuthorizationPolicyReadOnlyRules = [AdfsRules]::new($Properties.PolicyStore.AuthorizationPolicyReadOnly)

        Remove-AdfsServiceAccountRule -ServiceAccount $script:Service_Account_Name

        $AfterProperties = Get-AdfsInternalSettings
        $AfterAuthorizationPolicyRules = [AdfsRules]::new($Properties.PolicyStore.AuthorizationPolicy) 
        $AfterAuthorizationPolicyReadOnlyRules = [AdfsRules]::new($Properties.PolicyStore.AuthorizationPolicyReadOnly)

        $AuthPolicyMatches = $BeforeAuthorizationPolicyRules.NumberOfRules() -eq $AfterAuthorizationPolicyRules.NumberOfRules()
        $ReadOnlyMatches = $BeforeAuthorizationPolicyReadOnlyRules.NumberOfRules() -eq $AfterAuthorizationPolicyReadOnlyRules.NumberOfRules()



        ($AuthPolicyMatches -eq $ReadOnlyMatches) | Should Be $true
    }

    It "[00000]: Add-AdfsServiceAccountRule adds permit rule to ruleset"{
        $ErrorThrown = $false
        try
        {
            Add-AdfsServiceAccountRule -ServiceAccount "fakeAccount"
        }
        catch
        {
            $ErrorThrown = $true
        }
        $ErrorThrown | Should Be $true
    }

}
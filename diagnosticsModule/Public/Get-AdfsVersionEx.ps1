Function Get-AdfsVersionEx
{    
    [CmdletBinding()]
    param()

    $OSVersion = [Environment]::OSVersion.Version
    return Get-AdfsVersion($OSVersion)
}

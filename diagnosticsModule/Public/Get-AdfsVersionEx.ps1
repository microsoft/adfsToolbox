Function Get-AdfsVersionEx
{
    [CmdletBinding()]
    param()

    $OSVersion = [Environment]::OSVersion.Version

    If ($OSVersion.Major -eq 6)
    {
        # Windows 2012 R2
        If ($OSVersion.Minor -ge 3)
        {
            return $adfs3;
        }
        Else
        {
            #Windows 2012, 2008 R2, 2008
            If ($OSVersion.Minor -lt 3)
            {
                return $adfs2x;
            }
        }
    }

    If ($OSVersion.Major -eq 10)
    {
        # Windows Server 10
        If ($OSVersion.Minor -eq 0)
        {
            return $adfs3;
        }
    }
    return $null
}

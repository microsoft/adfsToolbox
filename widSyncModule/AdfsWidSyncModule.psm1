function Get-AdfsWidServiceStateSummary
{
    $stsWMIObject = (Get-WmiObject -Namespace root\ADFS -Class SecurityTokenService)

    #Create SQL Connection
    $connection = new-object system.data.SqlClient.SqlConnection($stsWMIObject.ConfigurationDatabaseConnectionString);
    $connection.Open()

    $query = "SELECT * FROM IdentityServerPolicy.ServiceStateSummary";
    $sqlcmd = $connection.CreateCommand();
    $sqlcmd.CommandText = $query;

    $result = $sqlcmd.ExecuteReader();
    $table = new-object "System.Data.DataTable"
    $table.Load($result)
    $table | ft
} 

function Reset-AdfsWidServiceStateSummarySerialNumbers
{
    $stsWMIObject = (Get-WmiObject -Namespace root\ADFS -Class SecurityTokenService)

    #Create SQL Connection
    $connection = new-object system.data.SqlClient.SqlConnection($stsWMIObject.ConfigurationDatabaseConnectionString);
    $connection.Open()

    $update = "UPDATE IdentityServerPolicy.ServiceStateSummary SET [SerialNumber] = '0'";
    $sqlcmd = $connection.CreateCommand();
    $sqlcmd.CommandText = $update;
    $sqlcmd.CommandTimeout = 600000;
    $rowsAffected = $sqlcmd.ExecuteNonQuery()
    Write-Output $rowsAffected "rows have been affected by the reset of SerialNumber column"
} 

function Invoke-WidSync
{
    param (
        [Parameter(Mandatory=$false)]
        [switch] $Force
    )

    if ( -not $force )
    {
        Write-Output "You must use the 'Force' parameter" -ForegroundColor Yellow
        return
    }

    $role = (Get-AdfsSyncProperties).role
    $LastSyncStatus = (Get-AdfsSyncProperties).LastSyncStatus

    if ($role -eq "SecondaryComputer")
    {
        if ($LastSyncStatus -eq '0')
        {
            Write-Output "Resetting the serialnumber column of ServiceStateSummary table to force a full WID sync" -ForegroundColor Green
        
            Write-Output "ServiceStateSummary table content before reset:" -ForegroundColor Green
            Get-AdfsWidServiceStateSummary

            Write-Output "Resetting the serialnumber of ServiceStateSummary table" -ForegroundColor Green
            Reset-AdfsWidServiceStateSummarySerialNumbers

            Write-Output "ServiceStateSummary table content after reset:" -ForegroundColor Green
            Get-AdfsWidServiceStateSummary

            Write-Output "The full sync will occur on this AD FS Secondary server during the next normal sync poll (by default it occurs every 5 minutes)" -ForegroundColor Green
        } 
        else 
        {
            Write-Output "The last sync status was not sucessful. Cannot force WID sync." -ForegroundColor Yellow
        }
    }
    else
    {
        Write-Output "This AD FS server is not a secondary server. Please run this cmdlet on your secondary server." -ForegroundColor Yellow
    }
}

Export-ModuleMember -Function Invoke-WidSync;

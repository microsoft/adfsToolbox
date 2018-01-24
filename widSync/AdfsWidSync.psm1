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
    Write-Host $rowsAffected "rows have been affected by the reset of SerialNumber column"
} 

param (
    [Parameter(Mandatory=$false)]
    [bool] $Force=$false
)

$role = (Get-AdfsSyncProperties).role
$LastSyncStatus =  (Get-AdfsSyncProperties).LastSyncStatus

if ($force -eq $true)
{
    if ($role -eq "SecondaryComputer")
    {
        if ($LastSyncStatus -eq '0')
        {
            Write-host "This ADFS server is a secondary server and last SYNC was successfull, let's reset the serialnumber column of ServiceStateSummary table in order to force a full sync"-ForegroundColor Green
        
            Write-host "ServiceStateSummary table content before the reset ..." -ForegroundColor Green
            get-AdfsWidServiceStateSummary

            Write-host "Resetting the serialnumber of ServiceStateSummary table" -ForegroundColor Green
            reset-AdfsWidServiceStateSummarySerialNumbers

            Write-host "ServiceStateSummary table content after the reset ..." -ForegroundColor Green
            get-AdfsWidServiceStateSummary

            Write-host "The  FULL sync will occur on this ADFS Secondary server during the next normal sync poll (by default it occurs every 5 minutes)..." -ForegroundColor Green
        } 
        else 
        {
            Write-Host "The last sync status was not sucessfull"-ForegroundColor Yellow
        }
    }
    else
    {
        Write-Host "This ADFS server is NOT a secondary server" -ForegroundColor Yellow
    }

} 
else
{
    Write-Host "You must use the 'force' parameter" -ForegroundColor Yellow
}
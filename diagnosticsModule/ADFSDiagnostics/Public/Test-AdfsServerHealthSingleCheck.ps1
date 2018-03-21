Function Test-AdfsServerHealthSingleCheck
{
    [CmdletBinding()]
    param
    (
        [ValidateNotNullOrEmpty()]
        [string]
        $testFunctionName
    )

    Import-ADFSAdminModule
    $props = Retrieve-AdfsProperties -force;
    Invoke-TestFunctions -Role "Tests" -functionsToRun @($testFunctionName)
}
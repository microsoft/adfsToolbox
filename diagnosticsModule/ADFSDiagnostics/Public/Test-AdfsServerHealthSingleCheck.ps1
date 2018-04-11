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
    return Invoke-TestFunctions -Role "Tests" -functionsToRun @($testFunctionName)
}
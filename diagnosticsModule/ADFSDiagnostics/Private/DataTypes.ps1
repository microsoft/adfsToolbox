####################################
# TestResult Data type
####################################
Add-Type -AssemblyName System.Web;
Add-Type -AssemblyName System.Collections;

Add-Type -Language CSharp @"
public class TestResult
{
    public string Name;
    public ResultType Result;
    public string Detail;
    public System.Collections.Hashtable Output;
    public string ExceptionMessage;

    public TestResult(string name)
    {
        Name = name;
        Result = ResultType.Pass;
    }

}

public enum ResultType
{
    Pass = 0,
    Fail = 1,
    NotRun = 2
}

"@;

####################################
# AdHealthAgentInformation Data type
####################################

Add-Type -Language CSharp @"
public class AdHealthAgentInformation
{
    public string Version;
    public string UpdateState;
    public string LastUpdateAttemptVersion;
    public System.DateTime LastUpdateAttemptTime;
    public int NumberOfFailedAttempts;
    public string InstallerExitCode;
}

"@;
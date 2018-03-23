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
    public System.Exception Exception;

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
    NotRun = 2,
    Error = 3,
}

public enum OSVersion
{
    WS2012,
    WS2012R2,
    WS2016,
    Unknown
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
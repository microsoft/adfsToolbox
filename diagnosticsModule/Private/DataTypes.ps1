####################################
# TestResult Data type
####################################
Add-Type -AssemblyName System.Web;
Add-Type -AssemblyName System.Collections;

Add-Type -Language CSharp @"

using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

public class TestResult
{
    public string Name;
    public string ComputerName;
    public ResultType Result;
    public string Detail;
    public Hashtable Output;
    public string ExceptionMessage;
    public string Exception;

    public TestResult(string name)
    {
        Name = name;
        Result = ResultType.Pass;
    }
}

public class TestResultsContainer
{
    public List<TestResult> AllTests { get; set; }

    public TestResultsContainer()
    {
        AllTests = new List<TestResult>();
    }

    public TestResultsContainer(TestResult[] newResults)
    {
        AllTests = new List<TestResult>();
        AllTests.AddRange(newResults);
    }

    public void Add(TestResult newResult)
    {
        AllTests.Add(newResult);
    }

    public void Add(TestResult[] newResults)
    {
        AllTests.AddRange(newResults);
    }

    public IEnumerable<TestResult> this[string testName]
    {
        get { return AllTests.Where(m => m.Name == testName).ToList(); }
    }

    public IEnumerable<TestResult> GetTestsByComputer(string computerName)
    {
        return AllTests.Where(m => m.ComputerName == computerName).ToList();
    }

    public IEnumerable<TestResult> PassedTests
    {
        get { return AllTests.Where(m => m.Result == ResultType.Pass).ToList(); }
    }

    public IEnumerable<TestResult> WarningTests
    {
        get { return AllTests.Where(m => m.Result == ResultType.Warning).ToList(); }
    }

    public IEnumerable<TestResult> FailedTests
    {
        get { return AllTests.Where(m => m.Result == ResultType.Fail).ToList(); }
    }

    public IEnumerable<TestResult> ErrorTests
    {
        get { return AllTests.Where(m => m.Result == ResultType.Error).ToList(); }
    }

    public IEnumerable<TestResult> NotRunTests
    {
        get { return AllTests.Where(m => m.Result == ResultType.NotRun).ToList(); }
    }
}

public enum ResultType
{
    Pass,
    NotRun,
    Fail,
    Error,
    Warning
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
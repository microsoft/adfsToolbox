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

    public List<string> ReachableServers { get; set; }

    public List<string> UnreachableServers { get; set; }

    public TestResultsContainer()
    {
        AllTests = new List<TestResult>();
    }

    public TestResultsContainer(TestResult[] newResults, string[] reachableServers, string[] unreachableServers)
    {
        AllTests = new List<TestResult>();
        AllTests.AddRange(newResults);
        ReachableServers = new List<string>();
        ReachableServers.AddRange(reachableServers);
        UnreachableServers = new List<string>();
        UnreachableServers.AddRange(unreachableServers); 
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

Add-Type -Assembly System;

Add-Type -Language CSharp @"

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Identity.Health.Adfs
{    
    public class NetUtil
    {
        [System.Flags]
        public enum AuditEventType
        {
            POLICY_AUDIT_EVENT_UNCHANGED=0x00000000,
            POLICY_AUDIT_EVENT_SUCCESS=0x00000001,
            POLICY_AUDIT_EVENT_FAILURE=0x00000002,
            POLICY_AUDIT_EVENT_NONE=0x00000004           
        }

        [DllImport("Advapi32.dll")]
        private static extern void AuditFree(IntPtr pBuf);

         [StructLayout(LayoutKind.Sequential)]
        private class AUDIT_POLICY_INFORMATION
        {
            public GUID AuditSubCategoryGuid;
            public UInt32 AuditingInformation;
            public GUID AuditCategoryGuid;
        }

        private  struct GUID
        {
            public int a;
            public short b;
            public short c;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] d;
        } 
              
        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private  static extern bool AuditQuerySystemPolicy(           
            [In] ref GUID pSubCategoryGuids,
            [In] UInt32 PolicyCount,
            [Out] out IntPtr pAuditPolicies);

        
         [DllImport("kernel32.dll")]
        private static extern uint GetLastError();

        public static AuditEventType CheckAudit()
        {
            IntPtr pBuffer = IntPtr.Zero;
            try
            {                
                AUDIT_POLICY_INFORMATION info;
                ulong policyCount = 1;
                bool status;
                //<0cce9222-69ae-11d9-bed3-505054503030> guid corresponds to auditpol subcategory <Audit_ObjectAccess_ApplicationGenerated>
                GUID guid = new GUID();
                guid.a = 0x0cce9222;
                guid.b = 0x69ae;
                guid.c = 0x11d9;
                guid.d = new byte[] { 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30 };                                             

                status = AuditQuerySystemPolicy(ref guid, (UInt32)policyCount, out pBuffer);
                if (!status)
                {
                    uint errorcode = GetLastError();                    
                }
                
                info = (AUDIT_POLICY_INFORMATION)Marshal.PtrToStructure(pBuffer, typeof(AUDIT_POLICY_INFORMATION));
                AuditEventType eventType = (AuditEventType)info.AuditingInformation;               
                return eventType;               
            }
            catch (Exception e)
            {                          
                throw e;
            }
            finally
            { AuditFree(pBuffer); }           
        }              
    }
}

"@
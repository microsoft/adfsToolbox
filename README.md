# AD FS Log Tools

## AdfsEventsModule Overview

This module provides tools for gathering related ADFS events from the security, admin, and debug logs, 
across multiple servers. This tool also allows the user to reconstruct the HTTP request/response headers 
from the logs.

## Cmdlets in AdfsEventsModule

This module exposes the following cmdlets: 

1. __```Get-ADFSEvents```__ - Allows you to query servers for ADFS logs. Contains options for querying, aggregation, and analysis

2. __```Write-ADFSEventsSummary```__ - Allows you to generate a summary of an ADFS request, based on the logs from ```Get-ADFSEvents```

3. __```Enable-ADFSAuditing```__ - Enables all the ADFS and OS auditing switches on the current server, and enables just the ADFS switches on remote servers

4. __```Disable-ADFSAuditing```__ - Disables all the ADFS and OS auditing switches on the current server, and disables just the ADFS switches on remote servers

The detailed parameters for __```Get-ADFSEvents```__ and __```Write-ADFSEventsSummary```__ are provided below.

The ```Get-ADFSEvents``` cmdlet is used to aggregate events by correlation ID, while the ```Write-ADFSEventsSummary```
cmdlet is used to generate a PowerShell Table of only the most relevant logging information from the events that are piped
in. 

## Get-ADFSEvents Parameters

* __Logs__ - A list of AD FS logs to include in the aggregation. Current options are: "Admin", "Debug", "Security".
The default will pull from both Security and Admin.
* __CorrelationID__ - The correlation ID for a single request. This will aggregate all chosen logs for this request  
* __All__ - This flag will cause all events in the desired logs to be grouped by correlation ID.
* __Headers__ - This flag can be combined with any means of event collection (a single correlation id, all events, or
time based) to reconstruct available HTTP requests and responses. 
* __StartTime__ - The UTC start time to use when aggregating multiple requests. All requests that start after this 
time will be aggregated
* __EndTime__ - The UTC end time to use when aggregating multiple requests. All requests that end before this time
will be aggregated
* __Server__ - A comma-separated list of server names to pull logs from. 
The default will pull from LocalHost

## Get-ADFSEvents Output

The output produced by Get-ADFSEvents is a list of objects with each containing at least the following properties:

1.  __CorrelationID__
2.  __Events__


The __CorrelationID__ property contains a string representation of the Correlation ID that all events and headers within that object share.

The __Events__ property contains a list of [EventLogRecord](https://msdn.microsoft.com/en-us/library/system.diagnostics.eventing.reader.eventlogrecord)
objects for the matching Correlation ID.

If the __Headers__ flag is included in the cmdlet's invocation, the output object will also contain a __Headers__ property.

The __Headers__ property contains a list of objects, each containing the following properties:

1.  __QueryString__
2.  __ResponseString__
3.  __RequestHeader__
4.  __ResponseHeader__

The __QueryString__ property contains the HTTP verb (GET, POST, etc) and the corresponding query string.

The __ResponseString__ property contains the HTTP response string (ex. 200 ok)

The __RequestHeader__ property is a dictionary containing the headers included in the HTTP request

The __ResponseHeader__ property is a dictionary containing the headers included in the HTTP response


## Using Get-ADFSEvents

1. Import the PowerShell Module 

    In a PowerShell window, run the following:

    ```ipmo AdfsEventsModule.psm1```

2. Run Get-ADFSEvents with your desired parameters to get a list of PowerShell objects

    EXAMPLE: Retrieve all logs from two servers for a specific request

    ```$logs = Get-ADFSEvents -Logs Security, Admin, Debug -CorrelationID 0c0fd6ee-4b1e-4260-0300-0080070000e3 -Headers -Server LocalHost, MyServer```

    OUTPUT:

    ```
    Events                              Headers CorrelationID
    ------                              ------- -------------

    {EventLogRecord, EventLogRecord}    {}      0c0fd6ee-4b1e-4260-0300-0080070000e3
    ```

3. To view specific records:

    ```$logs.Events[0]```

    OUTPUT:

    ```
    Message         : An HTTP request was received. See audit 510 with the same Instance ID for headers.

                       Instance ID: 64fb88c5-7f4e-4888-8b61-7d0d85563b82

                       Activity ID: 0c0fd6ee-4b1e-4260-0300-0080070000e3

                       Request Details:
                           Date And Time: 2017-09-19 20:50:43
                           Client IP: 123.45.67.9
                           HTTP Method: GET
                           Url Absolute Path: /adfs/portal/logo/logo.png
                           Query string: ?id=12345
                           Local Port: 443
                           Local IP: 123.45.67.8
                           User Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36
                           Content Length: 0
                           Caller Identity: -
                           Certificate Identity (if any): -
                           Targeted relying party: -
                           Through proxy: False
                           Proxy DNS name: -
                       CorrelationID        : 0c0fd6ee-4b1e-4260-0300-0080070000e3
                       PSComputerName       : LocalHost
                       RunspaceId           : 6d3d7715-08db-4aa1-b299-40d51d5db682
                       Id                   : 403
                       Version              :
                       Qualifiers           : 0
                       Level                : 0
                       Task                 : 3
                       Opcode               :
                       Keywords             : 12345
                       RecordId             : 12345
                       ProviderName         : AD FS Auditing
                       ProviderId           :
                       LogName              : Security
                       ProcessId            :
                       ThreadId             :
                       MachineName          : contoso.com
                       UserId               : 
                       TimeCreated          : 9/19/2017 1:50:43 PM
                       ActivityId           :
                       RelatedActivityId    :
                       ContainerLog         : security
                       MatchedQueryIds      : {}
                       Bookmark             : System.Diagnostics.Eventing.Reader.EventBookmark
                       LevelDisplayName     : Information
                       OpcodeDisplayName    : Info
                       TaskDisplayName      :
                       KeywordsDisplayNames : {Audit Success, Classic}
                       Properties           : {}
                       ```

4. You can pipe your output to ```Write-ADFSEventsSummary```

    EXAMPLE: 

    ```Get-ADFSEvents -Logs Security, Admin, Debug -CorrelationID 0c0fd6ee-4b1e-4260-0300-0080070000e3 -Server LocalHost, MyServer | Write-ADFSEventsSummary``` 

    OUTPUT: 

    ```
    Time          : 9/19/2017 1:50:43 PM
    EventID       : 403
    Details       : An HTTP request was received. See audit 510 with the same Instance ID for headers.

                    Instance ID: 64fb88c5-7f4e-4888-8b61-7d0d85563b82

                    Activity ID: 0c0fd6ee-4b1e-4260-0300-0080070000e3

                    Request Details:
                        Date And Time: 2017-09-19 20:50:43
                       Client IP: 123.45.67.9
                       HTTP Method: GET
                       Url Absolute Path: /adfs/portal/logo/logo.png
                       Query string: ?id=12345
                       Local Port: 443
                       Local IP: 123.45.67.8
                       User Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36
                       Content Length: 0
                       Caller Identity: -
                       Certificate Identity (if any): -
                       Targeted relying party: -
                       Through proxy: False
                       Proxy DNS name: -
    CorrelationID : 0c0fd6ee-4b1e-4260-0300-0080070000e3
    Machine       : contoso.com
    Log           : Security

    Time          : 9/19/2017 1:50:43 PM
    EventID       : 410
    Details       : Following request context headers present :

                    Activity ID: 0c0fd6ee-4b1e-4260-0300-0080070000e3

                    X-MS-Client-Application: -
                    X-MS-Client-User-Agent: -
                    client-request-id: -
                    X-MS-Endpoint-Absolute-Path: /adfs/portal/logo/logo.png
                    X-MS-Forwarded-Client-IP: -
                    X-MS-Proxy: -
                    X-MS-ADFS-Proxy-Client-IP: -
    CorrelationID : 0c0fd6ee-4b1e-4260-0300-0080070000e3
    Machine       : contoso.com
    Log           : Security
    ```

5. You can pipe the output of ```Write-ADFSEventsSummary``` to a CSV

    ```Get-ADFSEvents -Logs Security, Admin, Debug -CorrelationID 0c0fd6ee-4b1e-4260-0300-0080070000e3 -Server LocalHost, MyServer | Write-ADFSEventsSummary | Export-CSV mylogs.csv``` 


6. You can output the full data objects from ```Get-ADFSEvents``` to XML using:

    ```Export-Clixml``` 

    ```Import-Clixml``` 


## Contributing

This project welcomes contributions and suggestions. We encourage you to fork this project, include any scripts you 
use for parsing, managing, or manipulating ADFS logs, and then do a pull request to master. If your scripts work, 
we'll include them so everyone can benefit. 

Most contributions require you to agree to a Contributor License Agreement (CLA) declaring that you have the 
right to, and actually do, grant us the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

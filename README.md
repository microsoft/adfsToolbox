# AD FS Log Tools

## Get-ADFSEvents Overview

This script gathers ADFS related events from the security, admin, and debug logs, 
and allows the user to reconstruct the HTTP request/response headers from the logs.

Given a correlation id, the script will gather all events with the same identifier and reconstruct the request
and response headers if they exist. Using the 'All' option (either with or without headers enabled) will first collect
all correlation ids and proceed to gather the events for each. If start and end times are provided, all events 
that fall into that span will be returned. The start and end times will be assumed to be base times. That is, all
time conversions will be based on the UTC of these values.

The output produced by Get-ADFSEvents is a list of objects with each containing the following properties:

1. CorrelationID

2. Events

3. Headers

The CorrelationID property contains a string representation of the correlation id that all events and headers within that object share.

The Events property contains a list of [EventLogRecord](https://msdn.microsoft.com/en-us/library/system.diagnostics.eventing.reader.eventlogrecord)
objects that share the particular correlation id.

The Headers property contains a list of objects, each composed of the following properties:

1.QueryString

2.ResponseString

3.RequestHeader

4.ResponseHeader

The QueryString property contains the HTTP verb (GET, POST, etc) and the corresponding query string.

The ResponseString property contains the HTTP response string (ex. 200 ok)

The RequestHeader property is a dictionary representing the various headers included in the HTTP request

The ResponseHeader property is a dictionary representing the various headers included in the HTTP response

As a final note, the output is, by default, merely dumped to the console to allow users to manipulate the objects returned. 
While this will likely prove sufficient for many users, those who desire future access to the output should use ```Export-Clixml``` 
to write the output to an xml file. ```Import-Clixml``` can then be used to reconstruct the objects from the file. Examples of both are 
included in the Using Get-ADFSEvents section below.

## Using Get-ADFSEvents

1. Import the PowerShell Module 

   In a PowerShell window, run the following:

   ```ipmo Get-ADFSEvents.psm1```

2. Run Get-ADFSEvents 

EXAMPLE

```Get-ADFSEvents -Logs Security, Admin, Debug -CorrelationID 669bced6-d6ae-4e69-889b-09ceb8db78c9 -Server LocalHost, MyServer```

EXAMPLE

```Get-ADFSEvents -Logs Admin -AllWithHeaders -Server LocalHost```

EXAMPLE

```Get-ADFSEvents -Logs Debug, Security -AllWithoutHeaders -Server LocalHost, Server1, Server2```

EXAMPLE

```Get-ADFSEvents -Logs Debug -StartTime (Get-Date -Date "1970-01-01 00:00:00Z") -EndTime (Get-Date) -Server localhost```

EXAMPLE

```$Result = Get-ADFSEvents -Logs Admin -AllWithHeaders -Server LocalHost```

```$CorrelationID = $Result[0].CorrelationID #Obtain correlation id for first entry in output```

```$Events = $Result[0].Events #List of EventLogRecord objects```

```$QueryString = $Result[0].Headers[0].QueryString #Query String for first header in list```

EXAMPLE

```Get-ADFSEvents -Logs Security, Admin, Debug -AllWithHeaders -Server localhost | Export-Clixml "output.xml" #Store output in file```

```$ReconstructedOutput = Import-Clixml output.xml #Rebuild objects from xml file```

## Get-ADFSEvents Parameters

* Logs - A list of AD FS logs to include in the aggregation. Current options are: "Admin", "Debug", "Security"
* CorrelationID - The correlation ID for a single request. This will aggregate all chosen logs for this request  
* AllWithoutHeaders - this flag will cause all requests to be grouped by correlation ID, but the HTTP headers 
will not be extracted from the logs
* AllWithHeaders - this flag will cause all requests to be grouped by correlation ID, and the HTTP headers of 
each request will be extracted from the logs 
* StartTime - the UTC start time to use when aggregating multiple requests. All requests that start after this 
time will be aggregated
* EndTime - the UTC end time to use when aggregating multiple requests. All requests that end before this time
will be aggregated
* Server - a comma-separated list of server names to pull logs from

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

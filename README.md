# AD FS Toolbox

## Overview

This repository contains tools for helping you manage your AD FS farm. The following tools are currently included:

1. __[Diagnostics Module](diagnosticsModule)__ - PowerShell module to do basic health checks against AD FS. Determines if AD FS is in a healthy state.

2. __[Events Module](eventsModule)__ - PowerShell module provides tools for gathering related ADFS events from the security, admin, and debug logs, across multiple servers.

3. __[Service Account Module](serviceAccount)__ - PowerShell module to change the AD FS service account.

4. __[WID Sync Module](widSync)__ - PowerShell module to force a full WID sync to an AD FS secondary node

## Getting Started

### Install through PowerShell Gallery (Recommended)

1. Install the PowerShell Module

    In a PowerShell window, run the following:

    `Install-Module -Name ADFSToolbox -Force`

2. Import the PowerShell Module

    In a PowerShell window, run the following:

    `Import-Module ADFSToolbox -Force`

3. Run the cmdlet of your choice, with the required parameters (see individual tools for details)


### Install manually

1. [Download the repository](https://github.com/Microsoft/adfsToolbox/zipball/master)
2. Unzip the download and copy `ADFSToolbox` folder to `%SYSTEMDRIVE%:\Program Files\WindowsPowerShell\Modules\`
3. Import the PowerShell Module

    In a PowerShell window, run the following:

    `Import-Module ADFSToolbox -Force`

4. Run the cmdlet of your choice, with the required parameters (see individual tools for details)

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

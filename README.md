# AD FS Toolbox

## Notice: This repository is no longer being actively maintained. ADFSToolbox is still being actively worked on and can be installed from [here](https://www.powershellgallery.com/packages/ADFSToolbox/).

### Details

As of 7/31/2019, we have migrated the diagnosticsModule from PowerShell to C# into a new repository. As a consequence of this change, the new repository is not publically available; **however, we will still be making improvements to ADFSToolbox and releasing them [here](https://www.powershellgallery.com/packages/ADFSToolbox/)**. If you feel that we should invest the time to make the new repository open source, please direct your feedback to [here](https://adfshelp.microsoft.com/Feedback/ProvideFeedback) or respond to the issue [here](https://github.com/microsoft/adfsToolbox/issues/75). This repository will remain public, but will not be actively maintained. 
 
## Notice: Additionally, the diagnostics module will no longer support AD FS 2.1 or lower. If you need to target AD FS versions 2.1 or lower please install version 1.0.13 of ADFSToolbox.

## Overview

This repository contains tools for helping you manage your AD FS farm. The following tools are currently included:

1. __[Diagnostics Module](diagnosticsModule)__ - PowerShell module to do basic health checks against AD FS. Determines if AD FS is in a healthy state.

2. __[Events Module](eventsModule)__ - PowerShell module provides tools for gathering related ADFS events from the security, admin, and debug logs, across multiple servers.

3. __[Service Account Module](serviceAccount)__ - PowerShell module to change the AD FS service account.

4. __[WID Sync Module](widSync)__ - PowerShell module to force a full WID sync to an AD FS secondary node

## Getting Started

### Install through PowerShell Gallery (Recommended) for AD FS 3.0

1. Install the PowerShell Module

    In a PowerShell window, run the following:

    `Install-Module -Name ADFSToolbox -Force`

2. Import the PowerShell Module

    In a PowerShell window, run the following:

    `Import-Module ADFSToolbox -Force`

3. Run the cmdlet of your choice, with the required parameters (see individual tools for details)


### Install manually for AD FS 3.0

1. Launch an elevated PowerShell window on a machine that has internet access.
2. Install the PowerShell Module

    `Install-Module -Name ADFSToolbox -Force`

3. Copy the ADFSToolbox folder located `%SYSTEMDRIVE%\Program Files\WindowsPowerShell\Modules\` on your local machine to the same location on your AD FS or WAP machine.

4. Launch an elevated PowerShell window on your AD FS machine and run the following cmdlet to import the module.

    `Import-Module -Name ADFSToolbox -Force`

### Install through PowerShell Gallery (Recommended) for AD FS 2.1 or lower

1. Install the PowerShell Module

    In a PowerShell window, run the following:

    `Install-Module -Name ADFSToolbox -RequiredVersion 1.0.13 -Force`

2. Import the PowerShell Module

    In a PowerShell window, run the following:

    `Import-Module ADFSToolbox -RequiredVersion 1.0.13 -Force`

3. Run the cmdlet of your choice, with the required parameters (see individual tools for details)


### Install manually for AD FS 2.1 or lower

1. Launch an elevated PowerShell window on a machine that has internet access.
2. Install the PowerShell Module

    `Install-Module -Name ADFSToolbox -RequiredVersion 1.0.13 -Force`

3. Copy the ADFSToolbox folder located `%SYSTEMDRIVE%\Program Files\WindowsPowerShell\Modules\` on your local machine to the same location on your AD FS or WAP machine.

4. Launch an elevated PowerShell window on your AD FS machine and run the following cmdlet to import the module.

    `Import-Module -Name ADFSToolbox -RequiredVersion 1.0.13 -Force`


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

# Change AD FS Service Account

## Overview

This powershell module allows the AD FS service account to be changed. Such functionality may be especially useful if the current service account has been compromised.

The module exports four functions which may be used in conjunction to successfully migrate the service to a new account or recover from an error encountered along the way as described below.

## Warning Before Use

It is highly recommended that you create a backup before attemptig to change the service account as executing cmdlets in the wrong order may result in non-functioning AD FS servers. Performing the change first in a test farm is also advised.

Althouhgh it is recommended a list of secondary servers be provided when invoking Add-AdfsServiceAccountRule or Remove-AdfsServiceAccountRule on a multi-node WID farm, you can optionally manually force a sync on all secondary servers or allow it to occur on the next sync cycle (5 minutes by default).

## Install

Follow the instructions [here](https://github.com/Microsoft/adfsToolbox#getting-started) to install this module.

## Available Cmdlets

The module exposes the following cmdlets:
1. __```Add-AdfsServiceAccountRule```__ - Adds permission rule for the specified service account. Must be run prior to changing the service account on Windows Server 2016 or later.
2. __```Remove-AdfsServiceAccountRule```__ - Removes permission rule for the specified service account. This should not be run until the AD FS service is verfifed to work with the new service account.
3. __```Update-AdfsServiceAccount```__ - Changes the AD FS service account on the local machine. This cmdlet should be run on all secondary servers prior to execution on the primary machine.
4. __```Restore-AdfsSettingsFromBackup```__ - Restores the AD FS service settings with a backup generated during either Add-AdfsServiceAccountRule or Remove-AdfsServiceAccountRule. This cmdlet can be used to recover if an error occurs during either of the afforementioned commands.
## Requirements

1. The module is applicable for any AD FS farm and works for both SQL and WID environments.

2. Add-AdfsServiceAccountRule and Remove-AdfsServiceAccountRule only need to be run on Windows Server 2016 and later.


## Getting Started

1. Download the `AdfsServiceAccountModule.psm1` module to all of your AD FS servers (primary and secondary)

2. Import the PowerShell Module on all servers

    In a PowerShell window, run the following (adjust the module path accordingly):

    ```ipmo .\AdfsServiceAccountModule.psm1```

3. For Windows Server 2016 and later, add a rule granting the new service account necessary permissions.

	In a PowerShell window on the primary AD FS server, run the following:

    ```Add-AdfsServiceAccountRule -ServiceAccount <ServiceAccount> -SecondaryServers <ListOfSecondaryServers>```

	Note that ```<ServiceAccount>``` should be the service account you want to grant permissions to and can be provided either in the format ```Domain\User``` or merely ```User```.

	```<ListOfSecondaryServers>``` should be replaced with a list of secondary servers if the environment is a WID farm so that the configuration database can be synced across all machines.

4. Change the service account on each machine in the farm.

	Beginning with the secondary servers, run the following:

	```Update-AdfsServiceAccount```

	Once the function has been executed on all secondary servers, proceed to run it on the primary server.

5. If Device Registration Services (DRS) is set up in your AD FS environment, you must also use the ```Set-AdfsDeviceRegistration``` cmdlet (an internal command exposed by the service) to add the proper permissions to the new service account.


6. For Windows Server 2016 and later, remove the rule granting permissions to the old service account.

	In a PowerShell window on the primary AD FS server, run the following:

    ```Remove-AdfsServiceAccountRule -ServiceAccount <ServiceAccount> -SecondaryServers <ListOfSecondaryServers>```

	Note that ```<ServiceAccount>``` should be the service account you want to revoke permissions for and can be provided either in the format ```Domain\User``` or merely ```User```.

	```<ListOfSecondaryServers>``` should be replaced with a list of secondary servers if the environment is a WID farm so that the configuration database can be synced across all machines.




## Add-AdfsServiceAccountRule Parameters

__`ServiceAccount`__ - Name of the service account for which to add a new rule. Can be provided in either the format Domain\User or User

__`SecondaryServers`__ - Comma separated list of AD FS secondary servers. List is used to force a WID sync across all machines in the farm.

## Remove-AdfsServiceAccountRule Parameters

__`ServiceAccount`__ - Name of the service account for which to remove permissions rule. Can be provided in either the format Domain\User or User

__`SecondaryServers`__ - Comma separated list of AD FS secondary servers. List is used to force a WID sync across all machines in the farm.

## Restore-AdfsSettingsFromBackup Parameters

__`BackupPath`__ - Path to backup file generated by either Add-AdfsServiceAccountRule or Remove-AdfsServiceAccountRule.

Should resemble ```C:\Users\Administrator\Documents\serviceSettingsData-2018-04-11-12-04-03.xml```

## Tests
A test file validating basic functionality (adding and removing rules) can be found __[here](Tests)__. Note that since these tests create and remove AD users and also write to the configuration database they should primarily be used by developers to validate any changes made to the module.

To execute the test suite, simply copy Test.ServiceAccount.ps1 into the same directory as ServiceAccount.psm1 and run the following command: ```.\Test.ServiceAccount.ps1```



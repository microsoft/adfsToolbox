# ADFS TLS Configuration

## Overview

Configures ADFS servers for TLS 1.2 security.

The module exports two functions which may be used to test a specific services current configuration for Transport Layer Security (TLS) 1.2 and to configure a specific server for TLS 1.2 exclusively.

```
Warning Before Use

It is highly recommended that you create a backup before attempting to configure your ADFS servers. Performing the change first in a test farm is also advised.
```
When configuring an ADFS environment for TLS 1.2 each ADFS server and WAP server (proxy) in the farm should be tested and configured for TLS 1.2 use.  The functions in this module work by reading and altering the SChannel related registry values on the Windows computer. Registry items used are detailed in [here](http://support2.microsoft.com/kb/245030/en-us). The ADFS configuration for TLS is documented [here]( https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/operations/manage-ssl-protocols-in-ad-fs).

Important: After configuring the servers for TLS 1.2 the servers must be rebooted for the new settings to take effect.

## Install

Follow the instructions [here](https://github.com/Microsoft/adfsToolbox#getting-started) to install this module.

## Available Cmdlets

The module exposes the following cmdlets:
1. `Get-ADFSTLSConfiguration` - Adds permission rule for the specified service account. Must be run prior to changing the service account on Windows Server 2016 or later. This cmdlet will write the configuration to the console and to an output text file.
2. `Set-ADFSTLSConfiguration` - Removes permission rule for the specified service account. This should not be run until the AD FS service is verified to work with the new service account. Results will be written to the console.

## Requirements

1. The module will work with Windows Server 2012 R2 and Windows Server 2016.

2. The module must be running as a local Administrator and in an elevated PowerShell console.

## Getting Started

1. Back up the ADFS farm.

2. Download the ADFSToolbox module to all your AD FS servers (primary and secondary) and Web Application Proxy (WAP) servers.

4. If testing the configuration on the servers:

    In a PowerShell window on the primary AD FS server and on each WAP server, run the following and the review the output for results:

    `Get-ADFSTLSConfiguration`

5. If setting a server to use TLS 1.2 run the cmdlet below:

    `Set-ADFSTLSConfiguration`

    Once the cmdlet has run reboot the server.

    Note: Apply the setting and reboot the servers one at a time. If the farm is a WID configuration, run the Set-ADFSTLSConfiguration on the Primary server and reboot it first.



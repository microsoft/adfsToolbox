# AD FS WID Sync

## Overview

This PowerShell script allows an AD FS administrator to force a full WID database re-synchronization from a primary AD FS server onto a secondary AD FS server, causing the secondary AD FS server WID database to match the contents of the primary server.

This script is useful when the database of one AD FS node is inconsistent/divergent from the primary AD FS node.

The script does not force an immediate synchronization, but instead, it forces a full synchronization to occur during the next configured sync interval.

A full sync means all rows of all tables of the WID database will be re-synced from the Primary AD FS server to Secondary AD FS server (and not just the delta from a previous sync).


## Requirements

1. This script requires an AD FS environment with at least two servers (an AD FS Primary and Secondary node).

2. This script requires an AD FS environment that uses Windows Internal Database (WID) for AD FS configuration storage.

## Install

Follow the instructions [here](https://github.com/Microsoft/adfsToolbox#getting-started) to install this module.

## Getting Started

1. Run Invoke-WidSync with the `-Force` parameter to cause a WID sync at the next poll interval on your AD FS secondary server

    ```Invoke-WidSync -Force```

    ```OUTPUT:

    PS C:\Tools> ipmo AdfsWidSync.psm1
    PS C:\Tools> Invoke-WidSync -Force

    ServiceStateSummary table content before reset:

    ServiceObjectType            SerialNumber SchemaVersionNumber LastUpdateTime
    -----------------            ------------ ------------------- --------------
    AdfsTrustedFederationPartner            0                   1 7/4/2017 9:55:38 AM
    ApplicationGroup                       29                   1 10/24/2017 10:25:36 AM
    Client                                 39                   1 10/24/2017 10:25:36 AM
    FarmNode                             8529                   1 10/24/2017 10:25:36 AM
    IssuanceAuthority                     474                   1 10/24/2017 10:25:36 AM
    IssuanceAuthorityGroup                  0                   1 7/4/2017 9:55:38 AM
    IssuanceClaimDescriptor                81                   1 10/24/2017 10:25:36 AM
    IssuanceScope                         660                   1 10/24/2017 10:25:36 AM
    IssuanceScopeGroup                      0                   1 10/24/2017 10:25:36 AM
    OAuthPermission                        61                   1 10/24/2017 10:25:36 AM
    OAuthScopeDescription                   9                   1 10/24/2017 10:25:36 AM
    PolicyTemplate                         37                   1 10/24/2017 10:25:36 AM
    ProxyTrust                            198                   1 10/24/2017 10:25:36 AM
    RelyingPartyWebTheme                    0                   1 10/24/2017 10:25:36 AM
    ServiceSettings                        39                   1 10/24/2017 10:25:36 AM
    WebApplicationProxyData                15                   1 10/24/2017 10:25:36 AM
    WebCustomizationResource                0                   1 10/24/2017 10:25:36 AM
    WebTheme                                1                   1 10/24/2017 10:25:36 AM


    Resetting the serialnumber of ServiceStateSummary table
    18 rows have been affected by the reset of SerialNumber column
    ServiceStateSummary table content after reset:

    ServiceObjectType            SerialNumber SchemaVersionNumber LastUpdateTime
    -----------------            ------------ ------------------- --------------
    AdfsTrustedFederationPartner            0                   1 7/4/2017 9:55:38 AM
    ApplicationGroup                        0                   1 10/24/2017 10:25:36 AM
    Client                                  0                   1 10/24/2017 10:25:36 AM
    FarmNode                                0                   1 10/24/2017 10:25:36 AM
    IssuanceAuthority                       0                   1 10/24/2017 10:25:36 AM
    IssuanceAuthorityGroup                  0                   1 7/4/2017 9:55:38 AM
    IssuanceClaimDescriptor                 0                   1 10/24/2017 10:25:36 AM
    IssuanceScope                           0                   1 10/24/2017 10:25:36 AM
    IssuanceScopeGroup                      0                   1 10/24/2017 10:25:36 AM
    OAuthPermission                         0                   1 10/24/2017 10:25:36 AM
    OAuthScopeDescription                   0                   1 10/24/2017 10:25:36 AM
    PolicyTemplate                          0                   1 10/24/2017 10:25:36 AM
    ProxyTrust                              0                   1 10/24/2017 10:25:36 AM
    RelyingPartyWebTheme                    0                   1 10/24/2017 10:25:36 AM
    ServiceSettings                         0                   1 10/24/2017 10:25:36 AM
    WebApplicationProxyData                 0                   1 10/24/2017 10:25:36 AM
    WebCustomizationResource                0                   1 10/24/2017 10:25:36 AM
    WebTheme                                0                   1 10/24/2017 10:25:36 AM


    The full sync will occur on this AD FS Secondary server during the next normal sync poll (by default it occurs every 5 minutes)
    ```


## Invoke-WidSync Parameters

__`-Force`__ - Switch that allows for the WID table serial number to be reset, which will force a full WID sync at the next poll interview


## Additional Details

The full ADFS WID synchronization is obtained indirectly by setting the serial numbers ( `SerialNumber `) associated with each table to zero, which indicates that they should be synchronized.
These serial numbers are referenced in a particular table ( `ServiceStateSummary `) on which the synchronization logic used by AD FS is based. This reset is to be done on the Secondary AD FS server that we wish to synchronize (only).

Full synchronization will occur during the next normal sync cycle (which occurs every 5 minutes by default).

Note, the serialnumber reset is only performed when each of the following conditions are true:
* The script is launched explicitly with the option `-Force $true`
* The script is run on a server with the ADFS Secondary role
* The last WID sync status was sucessfull (executed without error)
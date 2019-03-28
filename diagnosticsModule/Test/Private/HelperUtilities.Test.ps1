# Determine our script root
$parent = Split-Path $PSScriptRoot -Parent
$script:root = Split-Path $parent -Parent
# Load module via definition
Import-Module $script:root\ADFSDiagnosticsModule.psm1 -Force

InModuleScope ADFSDiagnosticsModule {
    # Shared constants
    $sharedError = "Error message"
    $sharedErrorException = "System.Management.Automation.RuntimeException: Error message"

    Describe "Out-Verbose" {
        It "should call write-verbose" {
            # Arrange
            Mock -CommandName Write-Verbose -MockWith {}

            # Act
            Out-Verbose

            # Assert
            Assert-MockCalled Write-Verbose
        }
    }

    Describe "Out-Warning" {
        It "should call write-verbose" {
            # Arrange
            Mock -CommandName Write-Warning -MockWith {}

            # Act
            Out-Warning

            # Assert
            Assert-MockCalled Write-Warning
        }
    }

    Describe "Test-RunningRemotely" {
        It "is running remotely" {
            # Arrange
            Mock -CommandName Get-Host -MockWith { return New-Object PSObject -Property @{ "Name" = "ServerRemoteHost" }}

            # Act
            $ret = Test-RunningRemotely

            # Assert
            $ret | should beexactly $true
        }

        It "is not running remotely" {
            # Arrange
            Mock -CommandName Get-Host -MockWith { return New-Object PSObject -Property @{ "Name" = "ConsoleHost" }}

            # Act
            $ret = Test-RunningRemotely

            # Assert
            $ret | should beexactly $false
        }
    }

    Describe "Get-OsVersion" {
        It "should return WS2016" {
            # Arrange
            Mock -CommandName EnvOSVersionWrapper -MockWith {
                return New-Object PSObject @{
                    "Major" = 10
                    "Minor" = 0
                }
            }

            # Act
            $ret = Get-OsVersion

            # Assert
            $ret | should beexactly WS2016
        }

        It "should return WS2012R2" {
            # Arrange
            Mock -CommandName EnvOSVersionWrapper -MockWith {
                return New-Object PSObject @{
                    "Major" = 6
                    "Minor" = 4
                }
            }

            # Act
            $ret = Get-OsVersion

            # Assert
            $ret | should beexactly WS2012R2
        }

        It "should return WS2012" {
            # Arrange
            Mock -CommandName EnvOSVersionWrapper -MockWith {
                return New-Object PSObject @{
                    "Major" = 6
                    "Minor" = 0
                }
            }

            # Act
            $ret = Get-OsVersion

            # Assert
            $ret | should beexactly WS2012
        }

        It "should return Unknown" {
            # Arrange
            Mock -CommandName EnvOSVersionWrapper -MockWith {
                return New-Object PSObject @{
                    "Major" = 0
                    "Minor" = 0
                }
            }

            # Act
            $ret = Get-OsVersion

            # Assert
            $ret | should beexactly Unknown
        }
    }

    Describe "Get-ServiceState" {
        It "returns the service status" {
            # Arrange
            Mock -CommandName Get-Service -MockWith { return New-Object PSObject -Property @{"Status" = "Running"} }

            # Act
            $ret = Get-ServiceState("test")

            # Assert
            $ret | should beexactly "Running"
        }

        It "returns null when it cannot find the service" {
            # Arrange
            Mock -CommandName Get-Service -MockWith { return $null }

            # Act
            $ret = Get-ServiceState("test")

            # Assert
            $ret | should beexactly $null
        }
    }

    Describe "IsAdfsServiceRunning" {
        It "should return true" {
            # Arrange
            Mock -CommandName Get-ServiceState -MockWith { return "Running" }

            # Act
            $ret = IsAdfsServiceRunning

            # Assert
            $ret | should beexactly $true
        }

        It "should return false" {
            # Arrange
            Mock -CommandName Get-ServiceState -MockWith { return "Stopped" }

            # Act
            $ret = IsAdfsServiceRunning

            # Assert
            $ret | should beexactly $false
        }
    }

    Describe "IsAdfsProxyServiceRunning" {
        It "should return true" {
            # Arrange
            Mock -CommandName Get-ServiceState -MockWith { return "Running" }

            # Act
            $ret = IsAdfsProxyServiceRunning

            # Assert
            $ret | should beexactly $true
        }

        It "should return false" {
            # Arrange
            Mock -CommandName Get-ServiceState -MockWith { return "Stopped" }

            # Act
            $ret = IsAdfsProxyServiceRunning

            # Assert
            $ret | should beexactly $false
        }
    }

    Describe "GetSslBindings" {
        $_output = @(
            "",
            " SSL Certificate bindings:",
            " -------------------------",
            "",
            " Hostname:port                : sts.aadtesting.info:443",
            " Certificate Hash             : be22839cfff71bab0b118b69b0c8a2e33f02f04d",
            " Application ID               : {5d89a20c-beab-4389-9447-324788eb944a}",
            " Certificate Store Name       : MY",
            " Verify Client Certificate Revocation : Enabled",
            " Verify Revocation Using Cached Client Certificate Only : Disabled",
            " Usage Check                  : Enabled",
            " Revocation Freshness Time    : 0",
            " URL Retrieval Timeout        : 0",
            " Ctl Identifier               : (null)",
            " Ctl Store Name               : AdfsTrustedDevices",
            " DS Mapper Usage              : Disabled",
            " Negotiate Client Certificate : Disabled",
            " Reject Connections           : Disabled",
            " Disable HTTP2                : Not Set",
            "",
            " ip:port                      : 0.0.0.0:443",
            " Certificate Hash             : be22839cfff71bab0b118b69b0c8a2e33f02f04d",
            " Application ID               : {5d89a20c-beab-4389-9447-324788eb944a}",
            " Certificate Store Name       : MY",
            " Verify Client Certificate Revocation : Enabled",
            " Verify Revocation Using Cached Client Certificate Only : Disabled",
            " Usage Check                  : Enabled",
            " Revocation Freshness Time    : 0",
            " URL Retrieval Timeout        : 0",
            " Ctl Identifier               : (null)",
            " Ctl Store Name               : AdfsTrustedDevices",
            " DS Mapper Usage              : Disabled",
            " Negotiate Client Certificate : Disabled",
            ' Reject Connections           : Disabled',
            " Disable HTTP2                : Not Set");

        It "should return the correct SSL bindings" {
            # Arrange
            Mock -CommandName NetshHttpShowSslcert -MockWith { return $_output }

            # Act
            $bindings = GetSslBindings

            # Assert
            $bindings."sts.aadtesting.info:443" | should not beexactly $null
            $hostbinding = $bindings."sts.aadtesting.info:443"
            $hostbinding.Thumbprint | should beexactly "be22839cfff71bab0b118b69b0c8a2e33f02f04d"
            $hostbinding."Application ID" | should beexactly "{5d89a20c-beab-4389-9447-324788eb944a}"
            $hostbinding."Ctl Store Name" | should beexactly "AdfsTrustedDevices"

            $bindings."0.0.0.0:443" | should not beexactly $null
            $ipbinding = $bindings."0.0.0.0:443"
            $ipbinding.Thumbprint | should beexactly "be22839cfff71bab0b118b69b0c8a2e33f02f04d"
            $ipbinding."Application ID" | should beexactly "{5d89a20c-beab-4389-9447-324788eb944a}"
            $ipbinding."Ctl Store Name" | should beexactly "AdfsTrustedDevices"
        }
    }

    Describe "IsSslBindingValid" {
        BeforeAll {
            $_hostnamePort = "sts.contoso.com:443"
            $_thumbprint = "be22839cfff71bab0b118b69b0c8a2e33f02f04d"
        }

        It "should pass" {
            # Arrange
            $testResult = New-Object TestResult -ArgumentList "Test"
            $bindings = @{
                $_hostnamePort = @{
                    "Thumbprint" = $_thumbprint
                    "Ctl Store Name" = $ctlStoreName
                }
            }

            # Act
            $ret = IsSslBindingValid -Bindings $bindings -BindingIpPortOrHostnamePort $_hostnamePort -CertificateThumbprint $_thumbprint -VerifyCtlStoreName $true

            # Assert
            $ret.IsValid | should beexactly $true
        }

        It "should fail because binding could not be found" {
            # Arrange
            $testResult = New-Object TestResult -ArgumentList "Test"
            $bindings = @{ }

            # Act
            $ret = IsSslBindingValid -Bindings $bindings -BindingIpPortOrHostnamePort $_hostnamePort -CertificateThumbprint $_thumbprint -VerifyCtlStoreName $true

            # Assert
            $ret.IsValid | should beexactly $false
            $ret.Detail | should beexactly "The following SSL certificate binding could not be found $_hostnamePort."
        }

        It "should fail because thumbprint does not match" {
            # Arrange
            $testResult = New-Object TestResult -ArgumentList "Test"
            $badThumbprint = "600f909203f1ba82bfcdeb41383fa1ce2b7fb8b2"
            $bindings = @{
                $_hostnamePort = @{
                    "Thumbprint" = $badThumbprint
                    "Ctl Store Name" = $ctlStoreName
                }
            }

            # Act
            $ret = IsSslBindingValid -Bindings $bindings -BindingIpPortOrHostnamePort $_hostnamePort -CertificateThumbprint $_thumbprint -VerifyCtlStoreName $true

            # Assert
            $ret.IsValid | should beexactly $false
            $ret.Detail | should beexactly "The following SSL certificate binding $_hostnamePort did not match the AD FS SSL thumbprint: $_thumbprint."
        }

        It "should fail because ctl store name does not match" {
            # Arrange
            $testResult = New-Object TestResult -ArgumentList "Test"
            $bindings = @{
                $_hostnamePort = @{
                    "Thumbprint" = $_thumbprint
                    "Ctl Store Name" = "BadStoreName"
                }
            }

            # Act
            $ret = IsSslBindingValid -Bindings $bindings -BindingIpPortOrHostnamePort $_hostnamePort -CertificateThumbprint $_thumbprint -VerifyCtlStoreName $true

            # Assert
            $ret.IsValid | should beexactly $false
            $ret.Detail | should beexactly "The following SSL certificate binding $_hostnamePort did not have the correct Ctl Store Name: AdfsTrustedDevices."
        }
    }

    Describe "IsUserPrincipalNameFormat" {
        It "should return true" {
            # Arrange
            $username = "admin@contoso.com"

            # Act
            $ret = IsUserPrincipalNameFormat($username)

            # Assert
            $ret | should beexactly $true
        }

        It "should return false" {
            # Arrange
            $username = "admin"

            # Act
            $ret = IsUserPrincipalNameFormat($username)

            # Assert
            $ret | should beexactly $false
        }

        It "should return false because username is empty" {
            # Arrange
            $username = "admin"

            # Act
            $ret = IsUserPrincipalNameFormat ""

            # Assert
            $ret | should beexactly $false
        }
    }

    Describe "GetDomainNameFromDistinguishedName" {
        BeforeAll {
            $_shortDistinguishedName = "DC=contoso,DC=com"
            $_shortDomainName = "contoso.com"
            $_longDistinguishedName = "DC=test,DC=child,DC=corp,DC=contoso,DC=com"
            $_longDomainName = "test.child.corp.contoso.com"
            $_objectDistinguishedName = "CN=Employee One,OU=Users,DC=test,DC=child,DC=corp,DC=contoso,DC=com"
        }

        it "Should return $_shortDomainName" {
            GetDomainNameFromDistinguishedName $_shortDistinguishedName | should beexactly $_shortDomainName
        }

        it "Should return $_longDomainName" {
            GetDomainNameFromDistinguishedName $_longDistinguishedName | should beexactly $_longDomainName
        }
        
        it "Should return $_longDomainName" {
            GetDomainNameFromDistinguishedName $_objectDistinguishedName | should beexactly $_longDomainName
        }
    }

    Describe "TryGetDomainNameFromUpn" {        
        BeforeAll {
            $_upn = "adfssrv@contoso.com"
            $_domainName = "contoso.com"
            $_childDomainName = "test.contoso.com"
            $_rootDomainName = "contoso.local"
            $_localDistinguishedName = "DC=contoso,DC=local"
            $_childDistinguishedName = "DC=test,DC=contoso,DC=com"
            
            $_mockAdUserLocalDomainObject = New-Object psobject
            $_mockAdUserLocalDomainObject | Add-Member "Properties" @{ "distinguishedname"=$_localDistinguishedName };

            $_mockAdUserForestDomainObject = New-Object psobject
            $_mockAdUserForestDomainObject | Add-Member "Properties" @{ "distinguishedname"=$_childDistinguishedName };
        }

        It "Should return $_domainName, UPN domain name same as local should return domain name from UPN" {
            # Arrange
            Mock -CommandName Get-WmiObject { return @{"Domain"=$_domainName} } 
        
            # Act
            $ret = TryGetDomainNameFromUpn $_upn

            # Assert
            $ret | should beexactly $_domainName
        }

        It "Should return $_childDomainName, UPN domain different than computer domain but account found in computer domain" {
            # Arrange
            Mock -CommandName Get-WmiObject { return @{"Domain"=$_childDomainName} }  
            Mock -CommandName GetObjectsFromAD { return $_mockAdUserForestDomainObject }

            # Act            
            $ret = TryGetDomainNameFromUpn $_upn

            # Assert
            $ret | should beexactly $_childDomainName
        }

        It "Should return $_rootDomainName, UPN domain name different than computer domain, account found in root domain GC" {
            # Arrange
            Mock -CommandName Get-WmiObject { return @{"Domain"=$_childDomainName} } 
            Mock -CommandName GetObjectsFromAD { return $_mockAdUserLocalDomainObject } 

            # Act            
            $ret = TryGetDomainNameFromUpn $_upn

            # Assert
            $ret | should beexactly $_rootDomainName
        }

        It "Should return null, UPN not found in forest" {
            # Arrange
            Mock -CommandName Get-WmiObject { return @{"Domain"=$_childDomainName} }  
            Mock -CommandName GetObjectsFromAD { return $false } 

            # Act            
            $ret = TryGetDomainNameFromUpn $_upn

            # Assert
            $ret | should beexactly $null
        }
    }

    Describe "CheckRegistryKeyExist" {
        It "should return true" {
            # Arrange
            Mock -CommandName Get-Item -MockWith { return $true }

            # Act
            $ret = CheckRegistryKeyExist "testpath"

            # Assert
            $ret | should beexactly $true
        }

        It "should return false" {
            # Arrange
            Mock -CommandName Get-Item -MockWith { return $null }

            # Act
            $ret = CheckRegistryKeyExist "testpath"

            # Assert
            $ret | should beexactly $false
        }
    }

    Describe "IsTlsVersionEnabled" {
        It "should return true" {
            # Arrange
            Mock -CommandName CheckRegistryKeyExist -MockWith { return $false }

            # Act
            $ret = IsTlsVersionEnabled "1.0"

            # Assert
            $ret | should beexactly $true
        }

        It "should return false" {
            # Arrange
            Mock -CommandName CheckRegistryKeyExist -MockWith { return $true }
            Mock -CommandName IsTlsVersionEnabledInternal -MockWith { return $false }

            # Act
            $ret = IsTlsVersionEnabled "1.0"

            # Assert
            $ret | should beexactly $false
        }
    }

    Describe "IsTlsVersionEnabledInternal" {
        It "should return true" {
            # Arrange
            Mock -CommandName Get-Item -MockWith { return $null }
            Mock -CommandName GetValueFromRegistryKey -MockWith { return 1 } -ParameterFilter { $name -eq "Enabled" }
            Mock -CommandName GetValueFromRegistryKey -MockWith { return 0 } -ParameterFilter { $name -eq "DisabledByDefault" }

            # Act
            $ret = IsTlsVersionEnabledInternal "testpath"

            # Assert
            $ret | should beexactly $true
        }

        It "should return false" {
            # Arrange
            Mock -CommandName Get-Item -MockWith { return $null }
            Mock -CommandName GetValueFromRegistryKey -MockWith { return 0 } -ParameterFilter { $name -eq "Enabled" }
            Mock -CommandName GetValueFromRegistryKey -MockWith { return 1 } -ParameterFilter { $name -eq "DisabledByDefault" }

            # Act
            $ret = IsTlsVersionEnabledInternal "testpath"

            # Assert
            $ret | should beexactly $false
        }
    }

    Describe "IsServerTimeInSyncWithReliableTimeServer" {
        It "should return true" {
            # Arrange
            $utc = (New-Object -TypeName DateTime -ArgumentList (1970, 1, 1))
            $now = (Get-Date).ToUniversalTime()
            $diff = $now - $utc
            $val = $diff.TotalMilliseconds * 1000
            Mock -CommandName Invoke-WebRequest -MockWith { return @{"Content" = "<timestamp time=`"$val`"/>" } }

            # Act
            $ret = IsServerTimeInSyncWithReliableTimeServer

            # Assert
            $ret | should beexactly $true
        }

        It "should return false" {
            # Arrange
            $utc = (New-Object -TypeName DateTime -ArgumentList (1970, 1, 1))
            $now = (Get-Date).ToUniversalTime().AddSeconds(301)
            $diff = $now - $utc
            $val = $diff.TotalMilliseconds * 1000
            Mock -CommandName Invoke-WebRequest -MockWith { return @{"Content" = "<timestamp time=`"$val`"/>" } }

            # Act
            $ret = IsServerTimeInSyncWithReliableTimeServer

            # Assert
            $ret | should beexactly $false
        }
    }

    Describe "VerifyCertificatesArePresent" {
        It "should return the missing certificates" {
            # Arrange
            $primaryCerts = @("Cert1", "Cert2", "Cert3")
            $localCerts = @("Cert1")

            Mock -CommandName GetCertificatesFromAdfsTrustedDevices -MockWith { return $localCerts }

            # Act
            $ret = VerifyCertificatesArePresent $primaryCerts

            # Assert
            ("Cert2", "Cert3") | ForEach-Object {
                $ret | should contain $_
            }
        }
    }
}

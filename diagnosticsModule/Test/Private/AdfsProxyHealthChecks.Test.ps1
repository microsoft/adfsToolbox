# Determine our script root
$parent = Split-Path $PSScriptRoot -Parent
$root = Split-Path $parent -Parent
# Load module via definition
Import-Module $root\ADFSDiagnosticsModule.psm1 -Force

InModuleScope ADFSDiagnosticsModule {
    # Shared constants
    $sharedError = "Error message"
    $sharedErrorException = "System.Management.Automation.RuntimeException: Error message"

    Describe "TestIsAdfsProxyRunning" {
        It "should pass" {
            # Arrange
            Mock -CommandName Get-ServiceState -MockWith { return "Running" }

            # Act
            $ret = TestIsAdfsProxyRunning

            # Assert
            $ret.Result | should beexactly Pass
            $ret.Output.ADFSProxyServiceState | should beexactly "Running"
        }

        It "should fail" {
            # Arrange
            Mock -CommandName Get-ServiceState -MockWith { return "Stopped" }

            # Act
            $ret = TestIsAdfsProxyRunning

            # Assert
            $ret.Result | should beexactly Fail
            $ret.Output.ADFSProxyServiceState | should beexactly "Stopped"
        }

        It "should error" {
            # Arrange
            Mock -CommandName Get-ServiceState -MockWith { throw $sharedError }

            # Act
            $ret = TestIsAdfsProxyRunning

            # Assert
            $ret.Result | should beexactly Error
            $ret.ExceptionMessage | should beexactly $sharedError
            $ret.Exception | should beexactly $sharedErrorException
        }
    }

    Describe "TestNonSelfSignedCertificatesInRootStore" {
        It "should pass" {
            # Arrange
            $subject = "CN=TestContosoCert"
            $store = "Cert:\CurrentUser\My"
            $cert = New-SelfSignedCertificate -Subject $subject -CertStoreLocation $store

            Mock -CommandName Get-ChildItem -MockWith { return @($cert, $cert) }

            # Act
            $ret = TestNonSelfSignedCertificatesInRootStore

            $cert | Remove-Item

            # Assert
            $ret.Result | should beexactly Pass
        }

        Function CreateMockX509Certificate($issuer, $subject, $friendlyName, $thumbprint)
        {
            return New-Object -TypeName PSObject -Property @{
                "Issuer"       = $issuer
                "Subject"      = $subject
                "FriendlyName" = $friendlyName
                "Thumbprint"   = $thumbprint
            }
        }

        It "should fail" {
            # Arrange
            $subject = "CN=TestContosoCert"
            $friendlyName = "Contoso Cert"
            $issuer = "CN=TrustedAuthority"
            $secondIssuer = "CN=TrustedAuthority2"
            $firstThumbprint = "a909502dd82ae41433e6f83886b00d4277a32a7b"
            $secondThumbprint = "32aa840238fba67210b0d779e84923d65403eda8"
            $thirdThumbprint = "01a834a8b2289263d50ade7f3a700438b794e2d6"

            # Since it is difficult to create an X509 certificate that is not self-signed via PowerShell we will just mock it up using a PSObject
            $nonSelfSignedCert = CreateMockX509Certificate $issuer $subject $friendlyName $firstThumbprint
            $secondNonSelfSignedCert = CreateMockX509Certificate $secondIssuer $subject $friendlyName $secondThumbprint
            $selfSignedCert = CreateMockX509Certificate $issuer $issuer $friendlyName $thirdThumbprint

            Mock -CommandName Get-ChildItem -MockWith { return @($nonSelfSignedCert, $selfSignedCert, $selfSignedCert, $secondNonSelfSignedCert) }
            # Act
            $ret = TestNonSelfSignedCertificatesInRootStore

            # Assert
            $ret.Result | should beexactly Fail
            $ret.Detail | should beexactly "There were non-self-signed certificates found in the root store. Move them to the intermediate store."

            $ret.Output.NonSelfSignedCertificates.Count | should beexactly 2

            $ret.Output.NonSelfSignedCertificates[0].Subject | should beexactly $subject
            $ret.Output.NonSelfSignedCertificates[0].Issuer | should beexactly $issuer
            $ret.Output.NonSelfSignedCertificates[0].FriendlyName | should beexactly $friendlyName
            $ret.Output.NonSelfSignedCertificates[0].Thumbprint | should beexactly $firstThumbprint

            $ret.Output.NonSelfSignedCertificates[1].Subject | should beexactly $subject
            $ret.Output.NonSelfSignedCertificates[1].Issuer | should beexactly $secondIssuer
            $ret.Output.NonSelfSignedCertificates[1].FriendlyName | should beexactly $friendlyName
            $ret.Output.NonSelfSignedCertificates[1].Thumbprint | should beexactly $secondThumbprint
        }

        It "should error" {
            # Arrange
            Mock -CommandName Get-ChildItem -MockWith { throw $sharedError }

            # Act
            $ret = TestNonSelfSignedCertificatesInRootStore

            # Assert
            $ret.Result | should beexactly Error
            $ret.ExceptionMessage | should beexactly $sharedError
            $ret.Exception | should beexactly $sharedErrorException
        }
    }

    Describe "TestProxySslBindings" {
        BeforeAll {
            $_hostname = "sts.contoso.com"
            $_hostHttpsPort = 443
            $_hostTlsClientPort = 49443
            $_adfsCertificateThumbPrint = "a909502dd82ae41433e6f83886b00d4277a32a7b"

            Mock -CommandName Get-WmiObject -MockWith {
                return New-Object -TypeName PSObject -Property @{
                    "HostName"      = $_hostname
                    "HostHttpsPort" = $_hostHttpsPort
                    "TlsClientPort" = $_hostTlsClientPort
                }
            }
        }

        It "should pass" {
            # Arrange
            Mock -CommandName GetSslBindings -MockWith {
                return @{
                    "CustomBinding" = @{"Application ID" = $adfsApplicationId}
                }
            }
            Mock -CommandName IsSslBindingValid -MockWith {
                return @{ "IsValid" = $true }
            }

            # Act
            $ret = TestProxySslBindings $_adfsCertificateThumbPrint

            # Assert
            $ret.Result | should beexactly Pass
        }

        It "should fail" {
            # Arrange
            Mock -CommandName GetSslBindings -MockWith {
                return @{
                    "CustomBinding" = @{"Application ID" = $adfsApplicationId}
                }
            }
            Mock -CommandName IsSslBindingValid -MockWith {
                return @{ "IsValid" = $false; "Detail" = $sharedError }
            }

            # Act
            $ret = TestProxySslBindings $_adfsCertificateThumbPrint

            # Assert
            $ret.Result | should beexactly Fail
            (($_hostname + ":" + $_hostHttpsPort), ($_hostname + ":" + $_hostTlsClientPort), "CustomBinding") | ForEach-Object {
                $ret.Output.ErroneousBindings[$_] | should beexactly $sharedError
            }
        }

        It "should error" {
            # Arrange
            Mock -CommandName GetSslBindings -MockWith { throw $sharedError }

            # Act
            $ret = TestProxySslBindings $_adfsCertificateThumbPrint

            # Assert
            $ret.Result | should beexactly Error
            $ret.ExceptionMessage | should beexactly $sharedError
            $ret.Exception | should beexactly $sharedErrorException
        }
    }
}

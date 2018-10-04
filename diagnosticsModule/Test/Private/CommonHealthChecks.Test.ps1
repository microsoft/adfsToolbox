# Determine our script root
$parent = Split-Path $PSScriptRoot -Parent
$script:root = Split-Path $parent -Parent
# Load module via definition
Import-Module $script:root\ADFSDiagnosticsModule.psm1 -Force

InModuleScope ADFSDiagnosticsModule {
    # Shared constants
    $sharedError = "Error message"
    $sharedErrorException = "System.Management.Automation.RuntimeException: Error message"

    Describe "TestTLSMismatch" {
        It "should pass because all TLS versions are enabled" {
            # Arrange
            Mock -CommandName IsTlsVersionEnabled -MockWith { return $true }

            # Act
            $ret = TestTlsMismatch

            # Assert
            $ret.Result | should be Pass
        }

        Context "Specific TLS versions" {
            ("1.0", "1.1", "1.2") | ForEach-Object {
                It "should warn because only TLS $_ is enabled" {
                    # Arrange
                    $tlsVersion = $_
                    Mock -CommandName IsTlsVersionEnabled -MockWith { return $false } -ParameterFilter { $version -ne $tlsVersion }
                    Mock -CommandName IsTlsVersionEnabled -MockWith { return $true } -ParameterFilter { $version -eq $tlsVersion }

                    # We mock the warning function to avoid writing to console
                    Mock -CommandName Out-Warning -MockWith { }

                    # Act
                    $ret = TestTLSMismatch

                    # Assert
                    $ret.Result | should be Warning
                    $ret.Detail | should be "Detected that only TLS $tlsVersion is enabled. Ensure that this is also enabled on your other STS and Proxy servers."

                    Assert-MockCalled Out-Warning
                }
            }
        }

        It "should fail because all TLS versions are disabled" {
            # Arrange
            Mock -CommandName IsTlsVersionEnabled -MockWith { return $false }

            # Act
            $ret = TestTlsMismatch

            # Assert
            $ret.Result | should be Fail
            $ret.Detail | should be "Detected that all TLS versions are disabled. This will cause problems between your STS and Proxy servers. Fix this by enabling the correct TLS version."
        }

        It "should error" {
            # Arrange
            Mock -CommandName IsTlsVersionEnabled -MockWith { throw $sharedError }

            # Act
            $ret = TestTLSMismatch

            # Assert
            $ret.Result | should be Error
            $ret.ExceptionMessage | should be $sharedError
            $ret.Exception | should be $sharedErrorException
        }
    }

    Describe "TestAdfsEventLogs" {
        ($adfs2x, $adfs3) | ForEach-Object {
            Context "AD FS version $_" {
                $adfsVersionToTest = $_
                Mock -CommandName Get-AdfsVersion -MockWith { return $adfsVersionToTest }

                ($adfsRoleSTS, $adfsRoleProxy) | ForEach-Object {
                    Context "server role $_" {
                        $adfsRoleToTest = $_
                        Mock -CommandName Get-AdfsRole -MockWith { return "$adfsRoleToTest" }

                        It "should pass because Get-WinEvent returned null" {
                            # Arrange
                            Mock -CommandName Get-WinEvent -MockWith { return $null }

                            # Act
                            $ret = TestAdfsEventLogs

                            # Assert
                            $ret.Result | should beexactly Pass
                        }

                        It "should pass because Get-WinEvent returned an empty array" {
                            # Arrange
                            Mock -CommandName Get-WinEvent -MockWith { return @() }

                            # Act
                            $ret = TestAdfsEventLogs

                            # Assert
                            $ret.Result | should beexactly Pass
                        }

                        It "should fail" {
                            # Arrange
                            Mock -CommandName Get-WinEvent -MockWith {
                                return @(New-Object -TypeName PSObject -Property @{
                                        "TimeCreated"      = (Get-Date)
                                        "Id"               = 270
                                        "LevelDisplayName" = "Error"
                                        "Message"          = "The federation server proxy was not able to authenticate to the Federation Service."
                                    })
                            }

                            # Act
                            $ret = TestAdfsEventLogs

                            # Assert
                            $ret.Result | should beexactly Fail
                            $ret.Detail | should beexactly "There were events found in the AD FS event logs that may be causing issues with the AD FS and WAP trust. Check the output for more details."

                            $ret.Output.Events.Id | should beexactly 270
                            $ret.Output.Events.LevelDisplayName | should beexactly "Error"
                            $ret.Output.Events.Message | should beexactly "The federation server proxy was not able to authenticate to the Federation Service."
                        }
                    }
                }

                It "should error because of invalid server role." {
                    # Arrange
                    Mock -CommandName Get-AdfsRole -MockWith { return "none" }

                    # Act
                    $ret = TestAdfsEventLogs

                    # Assert
                    $ret.Result | should beexactly Error
                    $ret.Exceptionmessage | should beexactly "Unable to determine server role."
                    $ret.Exception | should beexactly "System.Management.Automation.RuntimeException: Unable to determine server role."
                }
            }
        }

        It "should error because invalid AD FS Version" {
            # Arrange
            Mock -CommandName Get-AdfsVersion -MockWith { return $null }

            # Act
            $ret = TestAdfsEventLogs

            # Assert
            $ret.Result | should beexactly Error
            $ret.ExceptionMessage | should beexactly "Unable to determine AD FS version."
            $ret.Exception | should beexactly "System.Management.Automation.RuntimeException: Unable to determine AD FS version."
        }
    }

    Describe "TestTimeSync" {
        Mock -CommandName Test-RunningRemotely -MockWith { return $false }

        Context "server role STS" {
            Mock -CommandName Get-AdfsRole -MockWith { return $adfsRoleSTS }

            Mock -CommandName Out-Warning -MockWith { }

            Context "only run locally" {
                It "should pass" {
                    # Arrange
                    Mock -CommandName IsServerTimeInSyncWithReliableTimeServer -MockWith { return $true }

                    # Act
                    $ret = TestTimeSync

                    # Assert
                    $ret.Result | should beexactly Pass
                }

                It "should fail" {
                    # Arrange
                    Mock -CommandName IsServerTimeInSyncWithReliableTimeServer -MockWith { return $false }

                    # Act
                    $ret = TestTimeSync

                    # Assert
                    $ret.Result | should beexactly Fail
                    $ret.Detail | should beexactly "This server's time is out of sync with reliable time server. Check and correct any time synchronization issues."
                }
            }

            Context "run farm-wide" {
                BeforeAll {
                    $adfsServers = @("sts1.contoso.com", "sts2.contoso.com", "sts3.contoso.com")

                    # since we have to mock out the remote PSSessions that gets created we just return the a PSSession to localhost
                    # we create these session before the actual test because once we mock New-PSSession we cannot unmock it
                    $localPSForPassTest = @()
                    $localPSForFailTest = @()

                    for ($i = 0; $i -lt $adfsServers.Count; $i++)
                    {
                        $localPSForPassTest += New-PSSession -ComputerName localhost -ErrorAction Stop
                        $localPSForFailTest += New-PSSession -ComputerName localhost -ErrorAction Stop
                    }
                }

                It "should pass" {
                    # Arrange
                    Mock -CommandName IsServerTimeInSyncWithReliableTimeServer -MockWith { return $true }
                    $script:itr = 0
                    Mock -CommandName New-PSSession -MockWith {
                        $session = $localPSForPassTest[$itr]
                        $script:itr += 1
                        return $session
                    }

                    # Since we get all of the functions from the private folder and run Invoke-Expression on them; that replaces the function's mock with the original function.
                    # We avoid this by setting the invoke expression within this script block to do nothing.
                    Mock Invoke-Command {
                        Return $ScriptBlock.InvokeWithContext(@{"Invoke-Expression" = {}}, @())
                    }

                    # Act
                    $ret = TestTimeSync -adfsServers $adfsServers

                    # Assert
                    $ret.Result | should beexactly Pass
                }

                It "should warn because it is unable to connect to remote server" {
                    # Arrange
                    Mock -CommandName IsServerTimeInSyncWithReliableTimeServer -MockWith { return $true }
                    Mock -CommandName New-PSSession -MockWith { return $null }

                    # Act
                    TestTimeSync -adfsServers $adfsServers

                    # Assert
                    Assert-MockCalled -CommandName Out-Warning -Times 3
                }

                It "should fail" {
                    # # Arrange
                    Mock -CommandName IsServerTimeInSyncWithReliableTimeServer -MockWith { return $false }
                    $script:itr = 0
                    Mock -CommandName New-PSSession -MockWith {
                        $session = $localPSForFailTest[$itr]
                        $script:itr += 1
                        return $session
                    }

                    # Since we get all of the functions from the private folder and run Invoke-Expression on them this replaces the function's mock with the original function.
                    # We avoid this by setting the invoke expression within this script block to do nothing.
                    Mock Invoke-Command {
                        Return $ScriptBlock.InvokeWithContext(@{"Invoke-Expression" = {}}, @())
                    }

                    # # Act
                    $ret = TestTimeSync -adfsServers $adfsServers

                    # Assert
                    $ret.Result | should beexactly Fail
                    ($adfsServers + "Localhost") | ForEach-Object {
                        $ret.Output.ServersOutOfSync | should contain $_
                    }
                }
            }
        }

        Context "server role Proxy" {
            Mock -CommandName Get-AdfsRole -MockWith {
                return $adfsRoleProxy
            }

            It "should pass" {
                # Arrange
                Mock -CommandName IsServerTimeInSyncWithReliableTimeServer -MockWith { return $true }

                # Act
                $ret = TestTimeSync

                # Assert
                $ret.Result | should beexactly Pass
            }

            It "should fail" {
                # Arrange
                Mock -CommandName IsServerTimeInSyncWithReliableTimeServer -MockWith { return $false }

                # Act
                $ret = TestTimeSync

                # Assert
                $ret.Result | should beexactly Fail
                $ret.Detail | should beexactly "This server's time is out of sync with reliable time server. Check and correct any time synchronization issues."
            }
        }

        It "should not run" {
            # Arrange
            Mock -CommandName Test-RunningRemotely -MockWith { return $true }

            # Act
            $ret = TestTimeSync

            # Assert
            $ret.Result | should beexactly NotRun
            $ret.Detail | should beexactly "This test does not need to run remotely."
        }

        It "should error" {
            # Arrange
            Mock -CommandName Get-AdfsRole -MockWith { return "none" }
            Mock -CommandName Test-RunningRemotely -MockWith { return $false }

            # Act
            $ret = TestTimeSync

            # Assert
            $ret.Result | should beexactly Error
            $ret.ExceptionMessage | should beexactly "Unable to determine server role."
            $ret.Exception | should beexactly "System.Management.Automation.RuntimeException: Unable to determine server role."
        }
    }
}

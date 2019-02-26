Function Create-CertCheckName
{
    param(
        [string]
        $certType,
        [string]
        $checkName,
        [bool]
        $isPrimary = $true
    )

    $primaryOrSecondary = "Secondary"
    if ($isPrimary)
    {
        $primaryOrSecondary = "Primary"
    }
    return "Test-Certificate-{0}-{1}-{2}" -f $certType, $primaryOrSecondary, $checkName
}

Function Create-CertificateCheckResult
{
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2] 
        $certCheckResult,
        [string] 
        $testName,
        [ResultType]
        $result,
        [Parameter(Mandatory=$false)]
        [string]
        $detail = $null
    )
    
    $testResult = New-Object TestResult -ArgumentList($testName)
    $testResult.Result = $result
    $testResult.Detail = $detail
    if ($certCheckResult)
    {
        $testResult.Output = @{$tpKey = $certCheckResult.Thumbprint}
    }
    return $testResult
}

function Verify-IsCertExpired 
{
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2] 
        $isCertExpired
    )
    
    return ($isCertExpired.NotAfter - (Get-Date)).TotalDays -le 0
}

function Verify-IsCertSelfSigned
{
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2] 
        $isCertSelfSigned
    )

    return $isCertSelfSigned.Subject -eq $isCertSelfSigned.IssuerName.Name
}

function Generate-NotRunResults
{
    param(
        [string]
        $certificateType,
        [string]
        $notRunReason,
        [bool]
        $isPrimary = $true,
        [int]
        $testsRanCount = 0,
        [string]
        $exceptionMessage = $null
    )
    
    $results = @()
    
    if($testsRanCount-- -le 0){ $results += Test-CertificateAvailable -certificateAvailable $null -certificateType $certType -isPrimary $isPrimary -notRunReason $notRunReason }
    if($testsRanCount-- -le 0){ $results += Test-CertificateSelfSigned -certSelfSigned $null -certificateType $certType -isPrimary $isPrimary -notRunReason $notRunReason }
    if($testsRanCount-- -le 0){ $results += Test-CertificateHasPrivateKey -certHasPrivateKey $null -certificateType $certType -isPrimary $isPrimary -notRunReason $notRunReason -storeName "" -storeLocation ""}
    if($testsRanCount-- -le 0){ $results += Test-CertificateExpired -certExpired $null -certificateType $certType -isPrimary $isPrimary -notRunReason $notRunReason}
    if($testsRanCount-- -le 0){ $results += Test-CertificateCRL -certCrl $null -certificateType $certType -isPrimary $isPrimary -notRunReason $notRunReason}
    if($testsRanCount-- -le 0){ $results += Test-CertificateAboutToExpire -certAboutToExpire $null -certificateType $certType -isPrimary $isPrimary -notRunReason $notRunReason}

    if($exceptionMessage)
    {
        $results | ForEach {$_.ExceptionMessage = $exceptionMessage}
    }

    return $results
}

Function Get-AdfsCertificateList([switch] $RemovePrivateKey)
{
    $adfsCertificateCollection = @()

    $adfsTokenCerts = Get-AdfsCertificate

    foreach ($adfsTokenCert in $adfsTokenCerts)
    {
        $certToAdd = new-Object PSObject
        if ($RemovePrivateKey)
        {
            $tokenCert = GetNormalizedCert $adfsTokenCert.Certificate
        }
        else
        {
            $tokenCert = $adfsTokenCert.Certificate
        }
        $certToAdd | Add-Member -NotePropertyName "Certificate" -NotePropertyValue $tokenCert
        $certToAdd | Add-Member -NotePropertyName "CertificateType" -NotePropertyValue $adfsTokenCert.CertificateType
        $certToAdd | Add-Member -NotePropertyName "IsPrimary" -NotePropertyValue $adfsTokenCert.IsPrimary
        $certToAdd | Add-Member -NotePropertyName "StoreName" -NotePropertyValue $adfsTokenCert.StoreName
        $certToAdd | Add-Member -NotePropertyName "StoreLocation" -NotePropertyValue $adfsTokenCert.StoreLocation
        $certToAdd | Add-Member -NotePropertyName "Thumbprint" -NotePropertyValue $adfsTokenCert.Thumbprint
        $adfsCertificateCollection += $certToAdd
    }

    $adfsSslBinding = GetSslBinding
    $sslCertToAdd = new-Object PSObject
    if ($RemovePrivateKey)
    {
        $sslCert = GetNormalizedCert $adfsSslBinding.Certificate
    }
    else
    {
        $sslCert = $adfsSslBinding.Certificate
    }
    $sslCertToAdd | Add-Member -NotePropertyName "Certificate" -NotePropertyValue $sslCert
    $sslCertToAdd | Add-Member -NotePropertyName "CertificateType" -NotePropertyValue "SSL"
    $sslCertToAdd | Add-Member -NotePropertyName "IsPrimary" -NotePropertyValue $true
    $sslCertToAdd | Add-Member -NotePropertyName "StoreName" -NotePropertyValue ([System.Security.Cryptography.X509Certificates.StoreName]::My)
    $sslCertToAdd | Add-Member -NotePropertyName "StoreLocation" -NotePropertyValue ([System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    $sslCertToAdd | Add-Member -NotePropertyName "Thumbprint" -NotePropertyValue ($adfsSslBinding.Thumbprint)

    $adfsCertificateCollection += $sslCertToAdd

    return $adfsCertificateCollection
}

Function Get-AdfsCertificatesToTest()
{

    $endpoints = Get-AdfsEndpoint | where {$_.SecurityMode -eq 'Message' -and $_.Enabled -eq $true -and $_.AddressPath -ne '/adfs/services/trusttcp/windows'}
    $skipCommCert = ($endpoints -eq $null)

    $adfsCertificateCollection = Get-AdfsCertificateList

    if ($skipCommCert)
    {
        $adfsCertificateCollection = $adfsCertificateCollection | where {$_.CertificateType -ne "Service-Communications"}
    }

    return $adfsCertificateCollection
}

Function GetNormalizedCert([System.Security.Cryptography.X509Certificates.X509Certificate2]$normalizedCert)
{    
    if ($null -eq $normalizedCert)
    {
        return $null
    }
    
    $publicCertPortionBytes = [Byte[]]$normalizedCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $certToReturn = New-Object -Type System.Security.Cryptography.X509Certificates.X509Certificate2
    $certToReturn.Import($publicCertPortionBytes)

    return $certToReturn
}

function VerifyCertificateCRL($certCRL, $revocationCheckSetting)
{
    if ( $null -eq $certCRL )
    {
      return $null
    }

    $certSubject = $certCRL.Subject
    $isSelfSigned =  $certSubject -eq $certCRL.IssuerName.Name 

    if ($isSelfSigned)
    {
        #mark the test as passing for self-signed certificates
        $result = new-Object -TypeName PSObject    
        $result | Add-Member -MemberType NoteProperty -Name Subject -Value $certCRL.Subject  
        $result | Add-Member -MemberType NoteProperty -Name IsSelfSigned -Value $isSelfSigned
        $result | Add-Member -MemberType NoteProperty -Name Thumbprint -Value $certCRL.Thumbprint
        $result | Add-Member -MemberType NoteProperty -Name VerifyResult -Value "N/A"
        $result | Add-Member -MemberType NoteProperty -Name ChainBuildResult -Value @()
        $result | Add-Member -MemberType NoteProperty -Name ChainStatus -Value $true
        return $result
    }    

    $chainBuildResult = $true
    $chainStatus = $null

    $verifyResult = $certCRL.Verify()
    
    #If set to none, ADFS will not even check this so ... scrap the results
    #to avoid surfacing noise to the user

    if ($revocationCheckSetting -ne "None")
    {    
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.UrlRetrievalTimeout = New-TimeSpan -Seconds 10
        $chain.ChainPolicy.VerificationFlags = "AllowUnknownCertificateAuthority"

        switch($revocationCheckSetting)
        {
            "CheckEndCert"
            {  
                $chain.ChainPolicy.RevocationFlag = "EndCertificateOnly"  
                $chain.ChainPolicy.RevocationMode = "Online"  
            }  
            "CheckEndCertCacheOnly"
            {
                $chain.ChainPolicy.RevocationFlag = "EndCertificateOnly"  
                $chain.ChainPolicy.RevocationMode = "Offline"  
            }
            "CheckChain"
            {
                $chain.ChainPolicy.RevocationFlag = "EntireChain"  
                $chain.ChainPolicy.RevocationMode = "Online"  
            }
                  
            "CheckChainCacheOnly"
            {
                $chain.ChainPolicy.RevocationFlag = "EntireChain"  
                $chain.ChainPolicy.RevocationMode = "Offline"  
            }
            "CheckChainExcludeRoot"
            {
                $chain.ChainPolicy.RevocationFlag = "ExcludeRoot"  
                $chain.ChainPolicy.RevocationMode = "Online"  
            }
            "CheckChainExcludeRootCacheOnly"
            {
                $chain.ChainPolicy.RevocationFlag = "ExcludeRoot"  
                $chain.ChainPolicy.RevocationMode = "Offline"  
            }
            default
            {
                $chain.ChainPolicy.RevocationFlag = "EntireChain"  
                $chain.ChainPolicy.RevocationMode = "Online"  
            }
        }

        $chainBuildResult = $chain.Build($certCRL)
        $chainStatus = $chain.ChainStatus
    }

    $certSubject = $certCRL.Subject
    $isSelfSigned =  $certSubject -eq $certCRL.IssuerName.Name   

    $result = new-Object -TypeName PSObject    
    $result | Add-Member -MemberType NoteProperty -Name Subject -Value $certCRL.Subject  
    $result | Add-Member -MemberType NoteProperty -Name IsSelfSigned -Value $isSelfSigned
    $result | Add-Member -MemberType NoteProperty -Name Thumbprint -Value $certCRL.Thumbprint
    $result | Add-Member -MemberType NoteProperty -Name VerifyResult -Value $verifyResult
    $result | Add-Member -MemberType NoteProperty -Name ChainBuildResult -Value $chainBuildResult
    $result | Add-Member -MemberType NoteProperty -Name ChainStatus -Value $chainStatus
    return $result    
}

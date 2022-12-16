
$script:ZiaApiSession = [ordered]@{
    ApiRoot             = $null
    SessionVariable     = $null
}


function ObfuscateApiKey {
    param (
          [string]  $ApiKey
        , [string]  $Timestamp 
    )

    $high = $timestamp.substring($timestamp.length - 6)
    $low = ([int]$high -shr 1).toString()
    $obfuscatedApiKey = ''

    while ($low.length -lt 6) {
        $low = '0' + $low
    }

    for ($i = 0; $i -lt $high.length; $i++) {
        $obfuscatedApiKey += $apiKey[[int64]($high[$i].toString())]
    }

    for ($j = 0; $j -lt $low.length; $j++) {
        $obfuscatedApiKey += $apiKey[[int64]$low[$j].ToString() + 2]
    }

    return $obfuscatedApiKey
}


function Connect-ZscalerAPI
{
    param
    (
          [Parameter(Mandatory = $true)] [string] $CloudName 
        , [Parameter(Mandatory = $true)] [string] $ApiKey
        , [Parameter(Mandatory = $true)] [pscredential] $ZscalerAdminCred
    )

    $script:ZiaApiSession.ApiRoot =   "https://zsapi.{0}.net" -f $CloudName

    [datetime] $UnixEpoch = '1970-01-01 00:00:00Z'

    $loginTs = [Math]::Round((New-TimeSpan -Start $UnixEpoch -End (Get-Date)).TotalMilliseconds,0)
    $obfuscatedApiKey = ObfuscateApiKey -ApiKey $ApiKey -Timestamp $loginTs

    $body = [pscustomobject] @{
        apiKey = $obfuscatedApiKey
        username = $ZscalerAdminCred.UserName
        password = $ZscalerAdminCred.GetNetworkCredential().Password
        timestamp = $loginTs
    } | ConvertTo-Json

    if($ret = Invoke-RestMethod -URI ("{0}/api/v1/authenticatedSession" -f $script:ZiaApiSession.ApiRoot) -Method Post -Body $body -ContentType 'application/json' -UseBasicParsing -SessionVariable sv )
    {
        Write-Verbose $ret
        $script:ZiaApiSession.SessionVariable = $sv
    }
}


Function Get-ZscalerAtpDenyList
{
    Invoke-RestMethod -URI ("{0}/api/v1/security/advanced" -f $script:ZiaApiSession.ApiRoot) -Method Get -ContentType 'application/json' -UseBasicParsing -WebSession $script:ZiaApiSession.SessionVariable
}

Function Disconnect-ZscalerAPI
{
    Invoke-RestMethod -URI ("{0}/api/v1/authenticatedSession" -f $script:ZiaApiSession.ApiRoot) -Method Delete  -ContentType 'application/json' -UseBasicParsing -WebSession $script:ZiaApiSession.SessionVariable
}


Export-ModuleMember -Function Connect-ZscalerAPI
Export-ModuleMember -Function Disconnect-ZscalerAPI
Export-ModuleMember -Function Get-ZscalerAtpDenyList


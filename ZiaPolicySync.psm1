
$script:ZiaApiSession = [ordered]@{
    ApiRoot             = $null
    SessionVariable     = $null
}

[datetime] $script:UnixEpoch = '1970-01-01 00:00:00Z'

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


Function Disconnect-ZscalerAPI
{
    Invoke-RestMethod -URI ("{0}/api/v1/authenticatedSession" -f $script:ZiaApiSession.ApiRoot) -Method Delete  -ContentType 'application/json' -UseBasicParsing -WebSession $script:ZiaApiSession.SessionVariable
}

Function Get-ZscalerAtpDenyList
{
    Invoke-RestMethod -URI ("{0}/api/v1/security/advanced" -f $script:ZiaApiSession.ApiRoot) -Method Get -ContentType 'application/json' -UseBasicParsing -WebSession $script:ZiaApiSession.SessionVariable
}

Function Set-ZscalerAtpDenyList 
{
    param
    (
        [Parameter(Mandatory = $true)] [string[]] $UrlList
    )

    $body = [PSCustomObject] @{
        blacklistUrls = $UrlList
    } | ConvertTo-Json

    Invoke-RestMethod -URI ("{0}/api/v1/security/advanced" -f $script:ZiaApiSession.ApiRoot) -Method Put -ContentType 'application/json' -UseBasicParsing -Body $body  -WebSession $script:ZiaApiSession.SessionVariable
}


Function Get-ZscalerIPv4DestGroups
{
    Invoke-RestMethod -URI ("{0}/api/v1/ipDestinationGroups/lite" -f $script:ZiaApiSession.ApiRoot) -Method Get -ContentType 'application/json' -UseBasicParsing -WebSession $script:ZiaApiSession.SessionVariable
}

Function Get-ZscalerIPv4DestGroup
{
    param
    (
        [Parameter(Mandatory = $true)] [string] $GroupName
    )

    if($group = Get-ZscalerIPv4DestGroups | ?{$_.name -eq $GroupName})
    {
        Invoke-RestMethod -URI ("{0}/api/v1/ipDestinationGroups/{1}" -f $script:ZiaApiSession.ApiRoot,$group.id) -Method Get -ContentType 'application/json' -UseBasicParsing -WebSession $script:ZiaApiSession.SessionVariable
    }
    else 
    {
        Throw "Group not found:  $GroupName"
    }
}

Function Set-ZscalerIPv4DestGroup
{
    param
    (
          [Parameter(Mandatory = $true)] [PSCustomObject] $Group
        , [Parameter(Mandatory = $true)] [string[]] $IpList
    )

    Invoke-RestMethod -URI ("{0}/api/v1/status" -f $script:ZiaApiSession.ApiRoot) -Method Get -ContentType 'application/json' -UseBasicParsing  -WebSession $script:ZiaApiSession.SessionVariable

    $Group.addresses = $IpList | ?{$_ -notlike "*:*"} | Select-Object -Unique
    $body = $Group | ConvertTo-Json

    Invoke-RestMethod -URI ("{0}/api/v1/ipDestinationGroups/{1}" -f $script:ZiaApiSession.ApiRoot,$Group.Id) -Method Put -ContentType 'application/json' -UseBasicParsing -Body $body -WebSession $script:ZiaApiSession.SessionVariable

    Invoke-RestMethod -URI ("{0}/api/v1/status/activate" -f $script:ZiaApiSession.ApiRoot) -Method Post -ContentType 'application/json' -UseBasicParsing  -WebSession $script:ZiaApiSession.SessionVariable
}

Export-ModuleMember -Function Connect-ZscalerAPI
Export-ModuleMember -Function Disconnect-ZscalerAPI
Export-ModuleMember -Function Get-ZscalerAtpDenyList
Export-ModuleMember -Function Set-ZscalerAtpDenyList
Export-ModuleMember -Function Get-ZscalerIPv4DestGroup
Export-ModuleMember -Function Set-ZscalerIPv4DestGroup

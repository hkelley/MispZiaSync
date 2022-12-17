
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


Function Get-MISPAttributes
{
    param
    (
        [Parameter(Mandatory = $true)] [string] $ApiKey
        , [Parameter(Mandatory = $true)] [string] $UriBase 
        , [Parameter(Mandatory = $false)] [string] [ValidateSet('Network activity')] $MispAttributeCategory = 'Network activity'
        , [Parameter(Mandatory = $true)] [string]  [ValidateSet('domain','url','ip-dst')] $MispAttributeType
        , [Parameter(Mandatory = $false)] [int]  $LookbackDays    
        , [Parameter(Mandatory = $false)] [string] $Tags 
        , [Parameter(Mandatory = $false)] [int] $MispPageSize = 100000
        , [Parameter(Mandatory = $false)] [bool] $enforceWarninglist = $true
        , [Parameter(Mandatory = $false)] [switch] $IncludeNonIDS
    )

    $url = "${UriBase}/attributes/restSearch"
    $headers = @{"Authorization"=$ApiKey;Accept='application/json';}

    $page = 1
    $attributeResults = @()
    $sw = New-Object System.Diagnostics.Stopwatch
    $sw.Start()
    $returnFormat = "json"

    Write-Verbose "Fetching page $page for type $t"
    do
    {
        $reqbody = [pscustomobject] @{
            page=$page++
            limit = $MispPageSize
            tags = $Tags
            includeEventTags = "true"
            type = $MispAttributeType
            category = $MispAttributeCategory
            enforceWarninglist = [int] $enforceWarninglist
            returnFormat = $returnFormat
        }

        if(-not $IncludeNonIDS)
        {
            $reqbody | Add-Member -NotePropertyName "to_ids"  -NotePropertyValue "true"
        }

        if($LookbackDays -gt 0)
        {            
            $reqbody | Add-Member -NotePropertyName "attribute_timestamp"  -NotePropertyValue ( "{0}d" -f $LookbackDays)
        }

        $body = ConvertTo-Json -InputObject $reqbody

        Write-Warning ("Requesting MISP attributes:  `r`n{0}" -f $body)

        # Using WebMethod so that we can access the headers
        $req = Invoke-WebRequest -UseBasicParsing -Uri $url -Headers $headers -ContentType "application/json" -Method Post -Body $body

        Write-Verbose ("Page {0} complete" -f  ($page - 1))

        switch($returnFormat)
        {
            "json" {
                $content = $req.Content | ConvertFrom-Json
                foreach($a in $content.response.Attribute)
                {
                    $attributeResults +=  [PSCustomObject] @{
                        indicator = $a.value
                        id  = $a.id 
                        event_id = $a.event_id
                        type = $a.type
                        timestamp = $a.timestamp
                        to_ids = $a.to_ids
                        confidence = $a.Tag | %{ if($ctag = ($_ | ?{$_.name -like "confidence:*" })) `
                                                     {($ctag.name -split ':')[1]}   }

                    }
                }
                
                Write-Verbose ("Fetched for type {1}: {2}   (page {0})" -f $page,$MispAttributeType,$content.response.Attribute.Count)
                break
            }
        }
    
    } while ($content.response.Attribute.Count)     #https://github.com/MISP/MISP/pull/4168   Keep pulling until you get an empty set [int] $req.Headers["X-Result-Count"]

    $sw.Stop()        
    Write-Verbose ("Result: {0}  {1} received in {2} seconds over {3} page(s)" -f $t,$req.Headers["X-Result-Count"],$sw.Elapsed.TotalSeconds,($page - 2))

    return $attributeResults
}

Export-ModuleMember -Function Connect-ZscalerAPI
Export-ModuleMember -Function Disconnect-ZscalerAPI
Export-ModuleMember -Function Get-ZscalerAtpDenyList
Export-ModuleMember -Function Set-ZscalerAtpDenyList
Export-ModuleMember -Function Get-ZscalerIPv4DestGroup
Export-ModuleMember -Function Set-ZscalerIPv4DestGroup

Export-ModuleMember -Function Get-MISPAttributes

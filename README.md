Simplifies synchronization of MISP indicators with Zscaler policy rules and lists

## Establish a Connection to ZIA Admin Portal
```
$zcloudname = "adminbeta"
$zapikey = "xxxx"
$zcr = Get-Credential -Message "Enter non-SAML user credentials for ZIA admin console"

Connect-ZscalerAPI -CloudName $zcloudname -ApiKey $zapikey -ZscalerAdminCred $zcr 
```

## Get IP Destination Indicators from MISP  (or some other source)
```
$mispurl = "https://MISP_name_without_trailing_slash"

#region IP Block List
$attributes = Get-MISPAttributes -ApiKey $mispkey -UriBase $mispurl  -MispAttributeType ip-dst -LookbackDays 2 
```

## Get Zscaler IP Group by Name and Set IP Addresses
```
$g = Get-ZscalerIPv4DestGroup -GroupName $ZDestIpGroup

Set-ZscalerIPv4DestGroup -Group $g -IpList @($attributes.indicator)
```


## Get URL Indicators from MISP
The example below uses an optional set of tag filters.
```
$attributes = Get-MISPAttributes -ApiKey $mispkey -UriBase $mispurl -MispAttributeType url -LookbackDays 2 -Tags $misptagfilter
```


## Clean up the URLs to Match ZIA's Format and Set Advanced Threat Protection Deny List
```
$urls = @{}

foreach($a in $attributes)
{
    $uri = [System.Uri] $a.indicator
    $urikey = $uri.Authority + $uri.AbsolutePath

    if(!($urls[$urikey]))
    {
        $urls[$urikey] = $null        
    }
}

Set-ZscalerAtpDenyList -UrlList $urls.Keys
```






Disconnect-ZscalerAPI

 Import-Module C:\_Active\Zscaler\MispZiaSync -Force

<#
    $zcloudname = 
    $zapikey = 
    $zcr = Get-Credential -Message "Enter non-SAML user credentials for ZIA admin console"

    $mispkey
    $mispurl
    $misptagfilter
#>
$ErrorActionPreference = "Stop"

Connect-ZscalerAPI -CloudName $zcloudname -ApiKey $zapikey -ZscalerAdminCred $zcr 


#region IP Block List
$attributes = Get-MISPAttributes -ApiKey $mispy -UriBase $mispurl  -MispAttributeType ip-dst -LookbackDays 2 -Tags $misptagfilter

$g = Get-ZscalerIPv4DestGroup -GroupName $ZDestIpGroup

Set-ZscalerIPv4DestGroup -Group $g -IpList @($attributes.indicator)



# URL deny list
$attributes = Get-MISPAttributes -ApiKey $mispkey -UriBase $mispurl -MispAttributeType url -LookbackDays 2 -Tags $misptagfilter
#endregion

# strip off protocols and dedup
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



Disconnect-ZscalerAPI
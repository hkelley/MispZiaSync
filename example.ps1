
# Import-Module C:\_Active\Zscaler\MispZiaSync

<#
    $zcloudname = 
    $zapikey = 
    $zcr = Get-Credential -Message "Enter non-SAML user credentials for ZIA admin console"

    $mispkey
    $mispurl
    $misptagfilter
#>

Connect-ZscalerAPI -CloudName $zcloudname -ApiKey $zapikey -ZscalerAdminCred $zcr 

$attributes = Get-MISPAttributes -ApiKey $mispkey -UriBase $mispurl -MispAttributeType url -LookbackDays 2 -Tags $misptagfilter


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
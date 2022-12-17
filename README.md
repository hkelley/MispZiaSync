Simplifies synchronization of MISP indicators with Zscaler policy rules and lists

## Establish a Connection to ZIA Admin Portal
```
$zcloudname = "adminbeta"
$zapikey = "xxxx"
$zcr = Get-Credential -Message "Enter non-SAML user credentials for ZIA admin console"

Connect-ZscalerAPI -CloudName $zcloudname -ApiKey $zapikey -ZscalerAdminCred $zcr 
```

### Get Indicators from MISP

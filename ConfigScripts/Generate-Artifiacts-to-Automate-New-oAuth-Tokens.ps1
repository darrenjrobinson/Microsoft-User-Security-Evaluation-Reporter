<#
1. install the PSMSGraph PS Moduel
install-module PSMSGraph 

2. 
update Line 15 & 16 with the path to output your tokens and artefacts 
Update Line 17 with your TenantName
Update Line 19 with your AAD Registered App Secret
Update Line 20 with your AAD Registerd App ID
#>

import-module PSMSGraph 

# Access Token Output Path
$tokensDir = 'c:\temp\tokens\'
$accessTokenPath = 'c:\temp\tokens\myAccessToken.xml'
$myTenant = 'yourTentantName.onmicrosoft.com'

$graphAppCredPwd = ConvertTo-SecureString "yourAppSecret" -AsPlainText -Force
$graphAppCreds = New-Object System.Management.Automation.PSCredential ("yourAppID", $graphAppCredPwd)

if (!(test-path -Path $accessTokenPath )){
    $ClientCredential = Get-Credential -Credential $graphAppCreds 
    $GraphAppParams = @{
        Name = 'Microsoft USER'
        ClientCredential = $ClientCredential
        RedirectUri = 'https://localhost/'
        Tenant = $myTenant
    }
    $GraphApp = New-GraphApplication @GraphAppParams 
    # Get AuthCode
    $AuthCode = $GraphApp | Get-GraphOauthAuthorizationCode -BaseURL "https://login.microsoftonline.com/$($myTenant)/oauth2/authorize"
                                                                                                                    
    # Get Access Token
    $GraphAccessToken = $AuthCode | Get-GraphOauthAccessToken -Resource 'https://graph.microsoft.com' -Verbose -BaseURL "https://login.microsoftonline.com/$($myTenant)/oauth2/token" 
    # Export Access Token
    $GraphAccessToken | Export-GraphOAuthAccessToken -Path $accessTokenPath
    $GraphAccessToken.Scope
    $GraphAccessToken.GetAccessToken()

} else {
    # REFRESH
    # Import Token
    $GraphAccessToken =  Import-GraphOAuthAccessToken -Path $accessTokenPath
    # Get new Access Token from Refresh Token
    $GraphAccessToken | Update-GraphOAuthAccessToken -Force
    # Export Access Token
    $GraphAccessToken | Export-GraphOAuthAccessToken -Path $accessTokenPath
    $GraphAccessToken
}

if ($GraphAccessToken){
    
    $GraphApp | convertto-json | out-file "$($tokensDir)myGraphApp.json" 

    $tokenResponse = $GraphAccessToken.Response | Select-Object -property * -ExcludeProperty access_token, refresh_token
    $tokenResponse | convertto-json | out-file "$($tokenEnv)myTokenResponse.json" 
    $tokenHeaders = $GraphAccessToken.ResponseHeaders | convertto-json | out-file "$($tokensDir)myTokenResponseHeaders.json"

    $GraphAccessToken.RequestedDate.DateTime | out-file "$($tokensDir)myTokenRequestDate.txt"

    $GraphAccessToken.LastRequestDate.DateTime | out-file "$($tokensDir)myTokenLastRequestDate.txt"

    $myRefreshToken = $GraphAccessToken.GetRefreshToken()
    $myRefreshToken | out-file "$($tokensDir)myRefreshToken.txt" 

    $myAccessToken = $GraphAccessToken.GetAccessToken()
    $myAccessToken | out-file "$($tokensDir)myAccessToken.txt"
}

# Test our token works
$requestResult = Invoke-GraphRequest -AccessToken $GraphAccessToken -Uri "https://graph.microsoft.com/v1.0/me" -Method Get
$output = $requestResult.ContentObject | ConvertTo-Json
$output
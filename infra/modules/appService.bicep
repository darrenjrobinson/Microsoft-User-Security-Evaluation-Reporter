param appName string
param location string
param tags object = {}
param skuName string
param linuxFxVersion string
param appInsightsConnectionString string

@description('Client id of the Entra app registration used by App Service Authentication')
param authClientId string
param tenantId string

@description('Key Vault URI holding the hibp-api-key secret; empty disables the HIBP check')
param hibpSecretUri string = ''

@description('Tenant policy JSON for the POLICY_JSON app setting; empty uses the built-in defaults')
param policyJson string = ''

resource plan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: '${appName}-plan'
  location: location
  tags: tags
  kind: 'linux'
  sku: { name: skuName }
  properties: { reserved: true }
}

var siteConfig = {
  linuxFxVersion: linuxFxVersion
  appCommandLine: 'node dist/server.js'
  healthCheckPath: '/healthz'
  alwaysOn: true
  http20Enabled: true
  minTlsVersion: '1.2'
  scmMinTlsVersion: '1.2'
  ftpsState: 'Disabled'
}

var appSettings = union(
  {
    NODE_ENV: 'production'
    APPLICATIONINSIGHTS_CONNECTION_STRING: appInsightsConnectionString
    SCM_DO_BUILD_DURING_DEPLOYMENT: 'false'
    WEBSITE_HEALTHCHECK_MAXPINGFAILURES: '3'
  },
  empty(hibpSecretUri) ? {} : { HIBP_API_KEY: '@Microsoft.KeyVault(SecretUri=${hibpSecretUri})' },
  empty(policyJson) ? {} : { POLICY_JSON: policyJson }
)

// Easy Auth v2: every request except /healthz must be signed in with Entra ID.
// Sign-in only needs an ID token, so no client secret is stored.
var authSettings = {
  platform: { enabled: true }
  globalValidation: {
    requireAuthentication: true
    unauthenticatedClientAction: 'RedirectToLoginPage'
    redirectToProvider: 'azureactivedirectory'
    excludedPaths: [ '/healthz' ]
  }
  identityProviders: {
    azureActiveDirectory: {
      enabled: true
      registration: {
        clientId: authClientId
        openIdIssuer: '${environment().authentication.loginEndpoint}${tenantId}/v2.0'
      }
      validation: {
        allowedAudiences: [ authClientId, 'api://${authClientId}' ]
      }
    }
  }
  login: {
    tokenStore: { enabled: true }
  }
  httpSettings: {
    requireHttps: true
  }
}

resource site 'Microsoft.Web/sites@2024-04-01' = {
  name: appName
  location: location
  tags: tags
  kind: 'app,linux'
  identity: { type: 'SystemAssigned' }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    clientAffinityEnabled: false
    siteConfig: siteConfig
  }
}

resource siteSettings 'Microsoft.Web/sites/config@2024-04-01' = {
  parent: site
  name: 'appsettings'
  properties: appSettings
}

resource siteAuth 'Microsoft.Web/sites/config@2024-04-01' = {
  parent: site
  name: 'authsettingsV2'
  properties: authSettings
}

resource staging 'Microsoft.Web/sites/slots@2024-04-01' = {
  parent: site
  name: 'staging'
  location: location
  tags: tags
  kind: 'app,linux'
  identity: { type: 'SystemAssigned' }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    clientAffinityEnabled: false
    siteConfig: siteConfig
  }
}

resource stagingSettings 'Microsoft.Web/sites/slots/config@2024-04-01' = {
  parent: staging
  name: 'appsettings'
  properties: appSettings
}

resource stagingAuth 'Microsoft.Web/sites/slots/config@2024-04-01' = {
  parent: staging
  name: 'authsettingsV2'
  properties: authSettings
}

// No FTP or basic-auth publishing – deployments use Entra ID (OIDC) only
resource ftp 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-04-01' = {
  parent: site
  name: 'ftp'
  properties: { allow: false }
}

resource scm 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-04-01' = {
  parent: site
  name: 'scm'
  properties: { allow: false }
}

resource stagingFtp 'Microsoft.Web/sites/slots/basicPublishingCredentialsPolicies@2024-04-01' = {
  parent: staging
  name: 'ftp'
  properties: { allow: false }
}

resource stagingScm 'Microsoft.Web/sites/slots/basicPublishingCredentialsPolicies@2024-04-01' = {
  parent: staging
  name: 'scm'
  properties: { allow: false }
}

output name string = site.name
output hostName string = site.properties.defaultHostName
output stagingHostName string = staging.properties.defaultHostName
output principalId string = site.identity.principalId
output stagingPrincipalId string = staging.identity.principalId

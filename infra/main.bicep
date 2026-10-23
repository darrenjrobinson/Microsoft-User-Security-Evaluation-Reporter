targetScope = 'resourceGroup'

@description('Globally unique Web App name; also used as the prefix for the other resources')
@minLength(2)
@maxLength(40)
param appName string

param location string = resourceGroup().location

@description('Client id of the Entra app registration for App Service Authentication (created by scripts/bootstrap.ps1)')
param authClientId string

param tenantId string = tenant().tenantId

@description('Set true once the hibp-api-key secret exists in the Key Vault')
param hibpEnabled bool = false

@description('Optional tenant policy JSON (required-PIM roles, break-glass accounts, thresholds); see README')
param policyJson string = ''

@allowed([ 'P0v3', 'P1v3', 'P2v3', 'S1' ])
@description('Plan SKU; must support deployment slots')
param skuName string = 'P0v3'

param linuxFxVersion string = 'NODE|24-lts'

param tags object = {
  app: 'ms-user'
  source: 'github.com/darrenjrobinson/Microsoft-User-Security-Evaluation-Reporter'
}

// Key Vault names are 3-24 chars and globally unique
var keyVaultName = take('${replace(appName, '-', '')}kv${uniqueString(resourceGroup().id)}', 24)
var hibpSecretUri = 'https://${keyVaultName}${environment().suffixes.keyvaultDns}/secrets/hibp-api-key'

module monitoring 'modules/monitoring.bicep' = {
  name: 'monitoring'
  params: {
    name: appName
    location: location
    tags: tags
  }
}

module web 'modules/appService.bicep' = {
  name: 'web'
  params: {
    appName: appName
    location: location
    tags: tags
    skuName: skuName
    linuxFxVersion: linuxFxVersion
    appInsightsConnectionString: monitoring.outputs.connectionString
    authClientId: authClientId
    tenantId: tenantId
    hibpSecretUri: hibpEnabled ? hibpSecretUri : ''
    policyJson: policyJson
  }
}

module vault 'modules/keyVault.bicep' = {
  name: 'keyVault'
  params: {
    name: keyVaultName
    location: location
    tags: tags
    secretReaderPrincipalIds: [ web.outputs.principalId, web.outputs.stagingPrincipalId ]
  }
}

output webAppName string = web.outputs.name
output webAppUrl string = 'https://${web.outputs.hostName}'
output stagingUrl string = 'https://${web.outputs.stagingHostName}'
output webAppPrincipalId string = web.outputs.principalId
output stagingPrincipalId string = web.outputs.stagingPrincipalId
output keyVaultName string = vault.outputs.name

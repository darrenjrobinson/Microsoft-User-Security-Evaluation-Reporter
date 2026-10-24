using 'main.bicep'

// Values come from GitHub repository variables in CI (see .github/workflows/deploy.yml),
// or from your shell when deploying by hand.
param appName = readEnvironmentVariable('APP_NAME', 'msuser-app')
param authClientId = readEnvironmentVariable('AUTH_CLIENT_ID', '00000000-0000-0000-0000-000000000000')
param hibpEnabled = bool(readEnvironmentVariable('HIBP_ENABLED', 'false'))
param skuName = readEnvironmentVariable('APP_SKU', 'P0v3')
param policyJson = readEnvironmentVariable('POLICY_JSON', '')

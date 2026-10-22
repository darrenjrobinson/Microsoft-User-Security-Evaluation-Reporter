<#
.SYNOPSIS
  One-time setup for MS USER: resource group, Entra app registrations and GitHub OIDC trust.

.DESCRIPTION
  Run once (per environment) as someone who can create app registrations and assign RBAC on the
  subscription (e.g. Application Administrator + Owner). Requires the Azure CLI, signed in with `az login`.
  Optionally uses the GitHub CLI (`gh`) to set the repository variables for you.

  Creates:
   1. The resource group.
   2. "MS USER" app registration for App Service Authentication, with the MSUser.Operator app role
      and "assignment required" so only users/groups you assign can sign in.
   3. "MS USER deploy" app registration with a federated credential trusted by GitHub Actions for the
      'production' environment (no client secret), granted Contributor and Role Based Access Control
      Administrator on the resource group (the Bicep assigns Key Vault roles to the Web App identity).

.EXAMPLE
  ./scripts/bootstrap.ps1 -SubscriptionId <sub> -ResourceGroup rg-msuser -Location australiaeast -AppName msuser-contoso -ConfigureGitHub
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string] $SubscriptionId,
  [Parameter(Mandatory)] [string] $ResourceGroup,
  [Parameter(Mandatory)] [string] $Location,
  [Parameter(Mandatory)] [ValidatePattern('^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$')] [string] $AppName,
  [string] $GitHubRepo = 'darrenjrobinson/Microsoft-User-Security-Evaluation-Reporter',
  [string] $GitHubEnvironment = 'production',
  [switch] $ConfigureGitHub,
  [switch] $SkipOperatorAssignment
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-Az {
  $out = & az @args
  if ($LASTEXITCODE -ne 0) { throw "az $($args -join ' ') failed" }
  return $out
}

function Write-Step($message) { Write-Host "`n==> $message" -ForegroundColor Cyan }

Write-Step "Selecting subscription $SubscriptionId"
Invoke-Az account set --subscription $SubscriptionId | Out-Null
$tenantId = Invoke-Az account show --query tenantId -o tsv

Write-Step "Creating resource group $ResourceGroup ($Location)"
Invoke-Az group create --name $ResourceGroup --location $Location --tags app=ms-user -o none
$rgId = Invoke-Az group show --name $ResourceGroup --query id -o tsv

# ---------------------------------------------------------------------------
Write-Step 'App registration for App Service Authentication'
$authName = "MS USER ($AppName)"
$authAppId = Invoke-Az ad app list --display-name $authName --query '[0].appId' -o tsv
$redirects = @(
  "https://$AppName.azurewebsites.net/.auth/login/aad/callback",
  "https://$AppName-staging.azurewebsites.net/.auth/login/aad/callback"
)
if (-not $authAppId) {
  $roles = @(@{
      allowedMemberTypes = @('User')
      description        = 'Can use MS USER to evaluate users'' security posture'
      displayName        = 'MS USER Operator'
      id                 = [guid]::NewGuid().ToString()
      isEnabled          = $true
      value              = 'MSUser.Operator'
    })
  $rolesFile = New-TemporaryFile
  $roles | ConvertTo-Json -Depth 5 -AsArray | Set-Content $rolesFile
  $authAppId = Invoke-Az ad app create --display-name $authName --sign-in-audience AzureADMyOrg `
    --web-redirect-uris @redirects --enable-id-token-issuance true --app-roles "@$rolesFile" --query appId -o tsv
  Remove-Item $rolesFile
  Invoke-Az ad app update --id $authAppId --identifier-uris "api://$authAppId" | Out-Null
  Write-Host "Created $authName ($authAppId)"
} else {
  Invoke-Az ad app update --id $authAppId --web-redirect-uris @redirects --enable-id-token-issuance true | Out-Null
  Write-Host "Using existing $authName ($authAppId)"
}

$authSpId = Invoke-Az ad sp list --filter "appId eq '$authAppId'" --query '[0].id' -o tsv
if (-not $authSpId) { $authSpId = Invoke-Az ad sp create --id $authAppId --query id -o tsv }
Invoke-Az ad sp update --id $authSpId --set appRoleAssignmentRequired=true | Out-Null

if (-not $SkipOperatorAssignment) {
  $me = Invoke-Az ad signed-in-user show --query id -o tsv
  $roleId = Invoke-Az ad app show --id $authAppId --query "appRoles[?value=='MSUser.Operator'].id | [0]" -o tsv
  $existing = Invoke-Az rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals/$authSpId/appRoleAssignedTo" `
    --query "value[?principalId=='$me' && appRoleId=='$roleId'] | length(@)" -o tsv
  if ($existing -eq '0') {
    $body = @{ principalId = $me; resourceId = $authSpId; appRoleId = $roleId } | ConvertTo-Json -Compress
    $bodyFile = New-TemporaryFile
    Set-Content $bodyFile $body
    Invoke-Az rest --method POST --url "https://graph.microsoft.com/v1.0/servicePrincipals/$authSpId/appRoleAssignedTo" `
      --headers 'Content-Type=application/json' --body "@$bodyFile" -o none
    Remove-Item $bodyFile
    Write-Host 'Assigned you the MSUser.Operator role (assign other operators/groups in Enterprise applications).'
  }
}

# ---------------------------------------------------------------------------
Write-Step 'App registration for GitHub Actions deployments (OIDC, no secret)'
$deployName = "MS USER deploy ($AppName)"
$deployAppId = Invoke-Az ad app list --display-name $deployName --query '[0].appId' -o tsv
if (-not $deployAppId) {
  $deployAppId = Invoke-Az ad app create --display-name $deployName --sign-in-audience AzureADMyOrg --query appId -o tsv
  Write-Host "Created $deployName ($deployAppId)"
}
$deploySpId = Invoke-Az ad sp list --filter "appId eq '$deployAppId'" --query '[0].id' -o tsv
if (-not $deploySpId) { $deploySpId = Invoke-Az ad sp create --id $deployAppId --query id -o tsv }

$subject = "repo:${GitHubRepo}:environment:$GitHubEnvironment"
$fics = Invoke-Az ad app federated-credential list --id $deployAppId --query "[?subject=='$subject'] | length(@)" -o tsv
if ($fics -eq '0') {
  $fic = @{
    name      = "github-$GitHubEnvironment"
    issuer    = 'https://token.actions.githubusercontent.com'
    subject   = $subject
    audiences = @('api://AzureADTokenExchange')
  } | ConvertTo-Json -Compress
  $ficFile = New-TemporaryFile
  Set-Content $ficFile $fic
  Invoke-Az ad app federated-credential create --id $deployAppId --parameters "@$ficFile" -o none
  Remove-Item $ficFile
  Write-Host "Trusted GitHub subject $subject"
}

foreach ($role in 'Contributor', 'Role Based Access Control Administrator') {
  $has = Invoke-Az role assignment list --assignee $deploySpId --scope $rgId --role $role --query 'length(@)' -o tsv
  if ($has -eq '0') {
    Invoke-Az role assignment create --assignee-object-id $deploySpId --assignee-principal-type ServicePrincipal `
      --role $role --scope $rgId -o none
    Write-Host "Granted $role on $ResourceGroup"
  }
}

# ---------------------------------------------------------------------------
$variables = [ordered]@{
  AZURE_CLIENT_ID       = $deployAppId
  AZURE_TENANT_ID       = $tenantId
  AZURE_SUBSCRIPTION_ID = $SubscriptionId
  AZURE_RESOURCE_GROUP  = $ResourceGroup
  APP_NAME              = $AppName
  AUTH_CLIENT_ID        = $authAppId
}

Write-Step 'GitHub repository variables'
if ($ConfigureGitHub) {
  & gh api --method PUT "repos/$GitHubRepo/environments/$GitHubEnvironment" --silent
  foreach ($kv in $variables.GetEnumerator()) {
    & gh variable set $kv.Key --repo $GitHubRepo --body $kv.Value
  }
  Write-Host "Set variables on $GitHubRepo and created the '$GitHubEnvironment' environment."
} else {
  Write-Host "Set these as repository variables (Settings > Secrets and variables > Actions > Variables):"
  $variables.GetEnumerator() | ForEach-Object { Write-Host ("  {0,-22} {1}" -f $_.Key, $_.Value) }
}

Write-Host @"

Next steps
  1. Push to master (or run the Deploy workflow) to provision infrastructure and deploy the app.
  2. Run ./scripts/grant-graph-permissions.ps1 -ResourceGroup $ResourceGroup -AppName $AppName
     (needs Privileged Role Administrator or Global Administrator) to grant the Web App's managed identity Graph access.
  3. Optional: add the HIBP API key – az keyvault secret set --vault-name <keyVaultName> --name hibp-api-key --value <key>
     then set the repository variable HIBP_ENABLED=true and redeploy.
"@

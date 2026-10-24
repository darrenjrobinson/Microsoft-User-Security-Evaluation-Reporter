<#
.SYNOPSIS
  Grants the MS USER Web App's managed identities (production + staging slot) the Microsoft Graph
  application permissions the app needs. Replaces the 2019 app secret / refresh-token approach.

.DESCRIPTION
  Requires the Azure CLI signed in as a Privileged Role Administrator or Global Administrator.
  Safe to re-run: existing assignments are skipped.

.EXAMPLE
  ./scripts/grant-graph-permissions.ps1 -ResourceGroup rg-msuser -AppName msuser-contoso
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string] $ResourceGroup,
  [Parameter(Mandatory)] [string] $AppName,
  [string[]] $Slots = @('staging')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Least-privilege application permissions for the queries in src/graph/queries.ts
$permissions = @(
  'User.Read.All',                     # user search, profile, manager, licences, guests sponsored
  'Directory.Read.All',                # registered devices, group/role/admin unit memberships, owned objects,
                                       # licence names (subscribedSkus)
  'AuditLog.Read.All',                 # sign-ins (incl. beta authenticationDetails), SSPR, security info changes,
                                       # guest invitations, MFA registration details
  'IdentityRiskEvent.Read.All',        # risk detections
  'IdentityRiskyUser.Read.All',        # risky user state
  'SecurityEvents.Read.All',           # Secure Score
  'UserAuthenticationMethod.Read.All', # per-user authentication method inventory
  'RoleManagement.Read.Directory',     # Entra role assignments and PIM assignment / eligibility schedules
  'Policy.Read.All'                    # authentication methods policy and security defaults (tenant context)
)

function Invoke-Az {
  $out = & az @args
  if ($LASTEXITCODE -ne 0) { throw "az $($args -join ' ') failed" }
  return $out
}

$graphSp = Invoke-Az ad sp show --id 00000003-0000-0000-c000-000000000000 -o json | ConvertFrom-Json
$roleIds = @{}
foreach ($p in $permissions) {
  $role = $graphSp.appRoles | Where-Object { $_.value -eq $p -and $_.allowedMemberTypes -contains 'Application' }
  if (-not $role) { throw "Graph app role $p not found" }
  $roleIds[$p] = $role.id
}

$identities = @{ $AppName = Invoke-Az webapp identity show -g $ResourceGroup -n $AppName --query principalId -o tsv }
foreach ($slot in $Slots) {
  $identities["$AppName/$slot"] = Invoke-Az webapp identity show -g $ResourceGroup -n $AppName --slot $slot --query principalId -o tsv
}

foreach ($entry in $identities.GetEnumerator()) {
  $principalId = $entry.Value
  if (-not $principalId) { throw "$($entry.Key) has no system-assigned managed identity – deploy infra first" }
  Write-Host "`n$($entry.Key) ($principalId)" -ForegroundColor Cyan

  $assigned = Invoke-Az rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals/$principalId/appRoleAssignments" -o json |
    ConvertFrom-Json
  $existing = @($assigned.value | Where-Object { $_.resourceId -eq $graphSp.id } | ForEach-Object { $_.appRoleId })

  foreach ($p in $permissions) {
    if ($existing -contains $roleIds[$p]) {
      Write-Host "  = $p"
      continue
    }
    $bodyFile = New-TemporaryFile
    @{ principalId = $principalId; resourceId = $graphSp.id; appRoleId = $roleIds[$p] } | ConvertTo-Json -Compress |
      Set-Content $bodyFile
    Invoke-Az rest --method POST --url "https://graph.microsoft.com/v1.0/servicePrincipals/$principalId/appRoleAssignments" `
      --headers 'Content-Type=application/json' --body "@$bodyFile" -o none
    Remove-Item $bodyFile
    Write-Host "  + $p" -ForegroundColor Green
  }
}

Write-Host "`nDone. Token caches refresh within ~24h; restart the Web App to pick up new permissions immediately:"
Write-Host "  az webapp restart -g $ResourceGroup -n $AppName"

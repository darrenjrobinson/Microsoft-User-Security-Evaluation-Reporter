# Microsoft User Security Evaluation Reporter (USER)

Evaluate and report on the security posture of individual Microsoft Entra ID users, from one place.

[![CI](https://github.com/darrenjrobinson/Microsoft-User-Security-Evaluation-Reporter/actions/workflows/ci.yml/badge.svg)](https://github.com/darrenjrobinson/Microsoft-User-Security-Evaluation-Reporter/actions/workflows/ci.yml)
[![Deploy](https://github.com/darrenjrobinson/Microsoft-User-Security-Evaluation-Reporter/actions/workflows/deploy.yml/badge.svg)](https://github.com/darrenjrobinson/Microsoft-User-Security-Evaluation-Reporter/actions/workflows/deploy.yml)

🏆 Originally built for (and winner of) the Microsoft Security Graph Hackathon, Jan–Feb 2019:
[Devpost](https://devpost.com/software/microsoft-user-security-evaluation-reporter) · [Solution demo](https://youtu.be/pnoA957DRqM).
The original 2019 code (PowerShell Azure Functions + Node web app) is preserved at the
[`hackathon-2019`](https://github.com/darrenjrobinson/Microsoft-User-Security-Evaluation-Reporter/tree/hackathon-2019) tag.

## The problem

Security administrators turn on tenant-wide controls to align with Microsoft recommendations, and Microsoft
Secure Score measures that alignment. But some of the outcome still depends on how each user is set up, and
a Service Desk operator or Cyber Security Officer has no single view of one user's security posture.

## What it does

When the app loads it shows today's **Microsoft Secure Score** and the **five most recent active risk
detections**. Select **Lookup** on an event, or **search** for any user, to see their posture:

| Check | Answers | Source |
|---|---|---|
| Risk events | Active risk detections (atypical travel, anonymous IP, password spray…) and the user's risk level | Entra ID Protection |
| MFA methods | Registered for MFA? Is the primary method Authenticator / passkey rather than SMS or voice? | Authentication methods registration report |
| Pwned check | Is the user's email in **Have I Been Pwned** breaches or pastes? Has Entra found leaked credentials? | HIBP v3 API + Entra ID Protection |
| Sign-ins | Last 10 sign-ins (30 days): app, result, location, device, Conditional Access | Sign-in logs |
| SSPR activity | Self-service password reset attempts and failure reasons (e.g. banned/fuzzy password) | Audit logs |
| User & devices | Account status, title, department, manager, on-premises identity; registered vs Entra-joined devices | Users / devices |

The **User security summary** combines these with the original 2019 scoring into a verdict: *Awesome. Great
profile*, *OK, but could be improved* or *Immediate attention required*. Each check also gives guidance, so
the operator can, for example, talk a user through moving from SMS to the Authenticator app, or require a
password change after a breach.

The UI follows the original layout, modernised with Bootstrap 5.3, Bootstrap Icons, skeleton loaders and a
**Light / Dark / Follow system** theme switch.

## Architecture

```mermaid
flowchart LR
  op([Operator]) -->|Entra ID sign-in<br/>MSUser.Operator role| ea[App Service Authentication]
  subgraph Azure App Service - Linux, Node 24
    ea --> app[Express app<br/>static UI + /api]
  end
  app -->|Managed identity<br/>fixed queries, JSON batching| graph[(Microsoft Graph v1.0)]
  app -->|Key Vault reference| kv[(Key Vault<br/>hibp-api-key)]
  app -->|API key| hibp[(Have I Been Pwned v3)]
  app --> ai[(Application Insights)]
```

- **No secrets in code or config.** The Web App's system-assigned managed identity calls Graph, the HIBP key is
  a Key Vault reference, and GitHub Actions signs in to Azure with OIDC federation.
- **Fixed queries only.** The browser never sends Graph URLs. Every call is defined in
  [`src/graph/queries.ts`](src/graph/queries.ts) and takes only validated object ids or search text.
- **Per-section resilience.** If a tenant lacks a P1/P2 licence or a permission is missing, only that panel
  shows "unavailable"; the rest of the profile still renders.

### What changed from 2019

| 2019 | Now |
|---|---|
| PowerShell Azure Functions **runtime v1**, forked PSMSGraph, refresh tokens in Key Vault | Single Node 24 / TypeScript web app, managed identity |
| Browser posted arbitrary Graph URLs to a batch function | Fixed server-side queries; Graph JSON batching kept internally |
| Function keys in `lookups.js` | Entra ID sign-in (Easy Auth) + app role |
| Server-built HTML strings | JSON API, DOM rendered with `textContent`, strict CSP |
| MSOnline export → Table Storage for MFA | `userRegistrationDetails` report |
| Beta `identityRiskEvents` | v1.0 `identityProtection/riskDetections` + `riskyUsers` |
| On-prem Lithnet NTLM-hash check over remote PowerShell | HIBP breach/paste lookup + Entra leaked-credential detections |
| Manual Docker build/push from VS Code | GitHub Actions → Bicep → staging slot → smoke test → swap |

## Prerequisites

- An Azure subscription and a Microsoft Entra ID tenant. **Entra ID P1/P2** is needed for sign-in logs,
  audit logs, risk detections and the MFA registration report.
- Permissions to create app registrations, assign Azure RBAC, and (once) grant Graph application permissions:
  Privileged Role Administrator or Global Administrator.
- [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli), PowerShell 7+, and optionally the
  [GitHub CLI](https://cli.github.com/).
- Optional: a [Have I Been Pwned API key](https://haveibeenpwned.com/API/Key).

## Deploy

1. **Bootstrap (once).** This creates the resource group, the Easy Auth app registration with the `MSUser.Operator`
   role (assigned to you), and a deployment identity trusted by this repo's `production` GitHub environment:

   ```powershell
   az login
   ./scripts/bootstrap.ps1 -SubscriptionId <subscription-id> -ResourceGroup rg-msuser `
     -Location australiaeast -AppName <globally-unique-name> -ConfigureGitHub
   ```

   Without `-ConfigureGitHub`, the script prints the repository variables for you to add by hand:
   `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `AZURE_RESOURCE_GROUP`, `APP_NAME`,
   `AUTH_CLIENT_ID`.

2. **Deploy.** Push to `master` or run the **Deploy** workflow. It runs CI, deploys
   [`infra/main.bicep`](infra/main.bicep) (App Service plan P0v3 with a staging slot, Web App, Key Vault, Log
   Analytics and Application Insights), deploys to `staging`, checks `/healthz` and swaps into production.

3. **Grant Graph permissions (once).** These go to the managed identities of the production and staging slots:

   ```powershell
   ./scripts/grant-graph-permissions.ps1 -ResourceGroup rg-msuser -AppName <name>
   ```

   | Permission (application) | Used for |
   |---|---|
   | `User.Read.All` | User search, profile, manager |
   | `Directory.Read.All` | Registered devices |
   | `AuditLog.Read.All` | Sign-ins, SSPR audit events, MFA registration details |
   | `IdentityRiskEvent.Read.All` | Risk detections |
   | `IdentityRiskyUser.Read.All` | User risk level |
   | `SecurityEvents.Read.All` | Secure Score |

4. **Optional: enable HIBP.** Store the key and turn the feature on:

   ```bash
   az keyvault secret set --vault-name <keyVaultName> --name hibp-api-key --value <key>
   ```

   Then set the repository variable `HIBP_ENABLED=true` and re-run **Deploy**. (The Key Vault name is shown in
   the deployment outputs.)

5. **Grant access.** In *Enterprise applications → MS USER (&lt;name&gt;) → Users and groups*, assign the
   **MS USER Operator** role to your Service Desk and security groups. Signed-in users without the role are
   refused with HTTP 403.

> **Restrict network access too.** This app shows sensitive identity data. Also consider App Service access
> restrictions or Private Endpoints, and Conditional Access on the MS USER enterprise application.

## Local development

```bash
npm ci
cp .env.example .env     # MOCK_GRAPH=true + AUTH_DISABLED=true
npm run dev              # http://localhost:8080
```

Mock mode serves a small demo tenant ([`src/mock/fixtures.ts`](src/mock/fixtures.ts)). Try searching for
*Rick Sanchez* (needs attention) or *Morty Smith* (great profile). To use a real tenant locally, set
`MOCK_GRAPH=false` and provide a dev app registration through `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` /
`AZURE_CLIENT_SECRET`.

| Script | Purpose |
|---|---|
| `npm run dev` | Watch-mode server (tsx), loads `.env` |
| `npm test` | Vitest unit and API tests against mock Graph |
| `npm run lint` / `npm run typecheck` | ESLint / TypeScript |
| `npm run build` / `npm start` | Compile to `dist/` and run it |

## AI-assisted investigation

The [Have I Been Pwned MCP server](https://www.npmjs.com/package/@darrenjrobinson/hibp-mcp)
(`@darrenjrobinson/hibp-mcp`) exposes the same HIBP lookups to AI assistants such as Claude, which can be
useful when following up a finding from MS USER.

## Licence

[MIT](LICENSE)

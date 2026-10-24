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
| Risk events | Active risk detections (atypical travel, anonymous IP, password spray, suspicious credential addition…) and the user's risk level | Entra ID Protection |
| Authentication strength | Registered for MFA? Passwordless-capable? Do recent sign-ins **actually use** a phishing-resistant method (passkey, Windows Hello for Business)? Which weaker recovery paths remain (SMS, voice, email, active TAP)? | Registration report, per-user methods, sign-in `authenticationDetails` (beta) |
| Pwned check | Is the user's email in **Have I Been Pwned** breaches or pastes? Has Entra found leaked credentials? | HIBP v3 API + Entra ID Protection |
| Privilege exposure | Which Entra roles are held or eligible; permanent, time-bound or PIM-activated; how much of the tenant each role reaches; roles that should be PIM-only but are assigned directly; admin-account hygiene | Role management / PIM + [Graph-atlas](https://github.com/darrenjrobinson/graph-atlas-mcp) role catalog |
| Owned objects | App registrations, enterprise apps, agent identities and groups the user owns (owning a role-assignable group is privilege) | Directory |
| Guests & memberships | Guests the user sponsors or invited in 30 days; direct and nested group counts, admin units, sensitive and role-assignable groups | Directory + audit logs |
| Sign-ins | Last 10 sign-ins (30 days): app, result, methods used, location, device, Conditional Access, plus a CA summary | Sign-in logs |
| Credential changes | Security info changes in 30 days, flagged when made by someone else or within 72 hours of risky activity | Audit logs + method inventory |
| SSPR activity | Self-service password reset attempts and failure reasons (e.g. banned/fuzzy password) | Audit logs |
| Account & organisation | Who this person is, so the findings have context: photo, job title, department, location, manager, direct reports, employee type, licences (frontline F-SKUs flagged), last interactive / non-interactive sign-in, password age, on-premises identity | Users, licence details, `signInActivity` (needs Entra ID P1) |
| Devices | Registered vs Entra-joined devices, compliance and management state | Devices |

The **User security summary** combines these into a verdict using the original 2019 scoring, extended with
the newer dimensions: *Awesome. Great profile*, *OK, but could be improved* or *Immediate attention required*,
with the top reasons, e.g. *User risk events to review + 1 permanently active high-impact role + Entra ID
Protection found leaked credentials*. MFA registration, authentication strength, risk, password exposure,
privilege, guest footprint and membership sprawl are weighted; PIM drift, ownership, recovery paths, credential
changes, admin hygiene and Conditional Access are shown as overlays.

Findings are interpreted for the kind of identity: B2B guests' MFA belongs to their home tenant, emergency
access (break-glass) accounts are expected to hold permanent Global Administrator and phishing-resistant keys
but rarely sign in, and listed service accounts are out of scope for per-user MFA checks. A **Tenant context**
note explains findings caused by tenant settings or licences (passkeys disabled in the methods policy, no
Entra ID P2 for PIM, and so on).

The UI follows the original layout, modernised with Bootstrap 5.3, Bootstrap Icons, skeleton loaders and a
**Light / Dark / Follow system** theme switch.

## Architecture

```mermaid
flowchart LR
  op([Operator]) -->|Entra ID sign-in<br/>MSUser.Operator role| ea[App Service Authentication]
  subgraph Azure App Service - Linux, Node 24
    ea --> app[Express app<br/>static UI + /api]
  end
  app -->|Managed identity<br/>fixed queries, JSON batching| graph[(Microsoft Graph v1.0<br/>+ one beta query)]
  app -->|Key Vault reference| kv[(Key Vault<br/>hibp-api-key)]
  app -->|API key| hibp[(Have I Been Pwned v3)]
  app --> ai[(Application Insights)]
```

- **No secrets in code or config.** The Web App's system-assigned managed identity calls Graph, the HIBP key is
  a Key Vault reference, and GitHub Actions signs in to Azure with OIDC federation.
- **Fixed queries only.** The browser never sends Graph URLs. Every call is defined in
  [`src/graph/queries.ts`](src/graph/queries.ts) and takes only validated object ids or search text.
- **Per-section resilience.** If a tenant lacks a P1/P2 licence or a permission is missing, only that panel
  shows "unavailable"; the rest of the profile still renders. Without P2, roles fall back to plain assignments
  (all permanent, no PIM detail).
- **One beta call.** Per-sign-in authentication methods (`signIn.authenticationDetails`) only exist in Graph
  beta. That single query is made separately; if it fails or changes, the profile still renders and the app
  stops short of claiming which methods the user actually uses.

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
   | `User.Read.All` | User search, profile, manager, licences, guests sponsored |
   | `Directory.Read.All` | Registered devices, group / role / admin unit memberships, owned objects |
   | `AuditLog.Read.All` | Sign-ins (incl. beta authentication details), SSPR, security info changes, guest invitations, MFA registration details |
   | `IdentityRiskEvent.Read.All` | Risk detections |
   | `IdentityRiskyUser.Read.All` | User risk level |
   | `SecurityEvents.Read.All` | Secure Score |
   | `UserAuthenticationMethod.Read.All` | Per-user authentication method inventory |
   | `RoleManagement.Read.Directory` | Entra role assignments and PIM assignment / eligibility schedules |
   | `Policy.Read.All` | Authentication methods policy and security defaults (tenant context) |

   > Microsoft documents `GET /users/{id}/ownedObjects` as delegated-only. If the managed identity is refused,
   > the **Owned objects** panel says so and the rest of the profile is unaffected.

4. **Optional: enable HIBP.** Store the key and turn the feature on:

   ```bash
   az keyvault secret set --vault-name <keyVaultName> --name hibp-api-key --value <key>
   ```

   Then set the repository variable `HIBP_ENABLED=true` and re-run **Deploy**. (The Key Vault name is shown in
   the deployment outputs.)

5. **Optional: tune the tenant policy.** Set the repository variable `POLICY_JSON` (deployed as the
   `POLICY_JSON` app setting) and re-run **Deploy**. Every field is optional:

   ```json
   {
     "requiredPimRoles": ["62e90394-69f5-4237-9190-012177145e10"],
     "pimExceptions": ["<object id of a break-glass account>"],
     "breakGlassAccounts": ["<object id or UPN>"],
     "breakGlassGroupIds": ["<group object id>"],
     "serviceAccounts": ["<object id or UPN>"],
     "sensitiveGroupIds": ["<group object id>"],
     "membershipThresholds": { "directGroups": 75, "transitiveGroups": 200, "sensitiveGroups": 3 },
     "guestThresholds": { "warning": 10, "danger": 50 }
   }
   ```

   `requiredPimRoles` are role template ids that should only be held through PIM eligibility; by default every
   high-impact role in the role catalog. Invalid JSON stops the app at start-up with a message naming the field.

6. **Grant access.** In *Enterprise applications → MS USER (&lt;name&gt;) → Users and groups*, assign the
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
*Rick Sanchez* (a risky, permanently privileged daily-driver admin with a suspicious new phone method),
*Morty Smith* (great profile, signs in with passkeys), *Beth Smith* (PIM-eligible admin with a large guest
footprint and membership sprawl), *Summer* (B2B guest) or *Emergency* (a break-glass account). To use a real tenant locally, set
`MOCK_GRAPH=false` and provide a dev app registration through `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` /
`AZURE_CLIENT_SECRET`.

| Script | Purpose |
|---|---|
| `npm run dev` | Watch-mode server (tsx), loads `.env` |
| `npm test` | Vitest unit and API tests against mock Graph |
| `npm run lint` / `npm run typecheck` | ESLint / TypeScript |
| `npm run build` / `npm start` | Compile to `dist/` and run it |
| `npm run sync:atlas` | Refresh the role catalog snapshot (`src/data/graph-atlas-roles.json`) from the newest Graph-atlas data release |

### Role catalog

Role impact comes from a committed snapshot of [Graph-atlas](https://github.com/darrenjrobinson/graph-atlas-mcp)
(MIT), which collects each Entra role's template id, Microsoft's *privileged* label and its `microsoft.directory/*`
actions from the Microsoft Learn permissions reference (CC BY 4.0). Graph-atlas has no blast-radius data, so
[`src/services/roleCatalog.ts`](src/services/roleCatalog.ts) derives each role's impact and themes (privilege
escalation, credential reset, access policy, app credential takeover, federation…) from its write actions. A few
well-known admin roles (Global, Privileged Role, Authentication, Conditional Access, Security, Exchange, SharePoint,
Intune and User Administrator…) are always high impact. Custom roles are treated as medium.

## AI-assisted investigation

The [Have I Been Pwned MCP server](https://www.npmjs.com/package/@darrenjrobinson/hibp-mcp)
(`@darrenjrobinson/hibp-mcp`) exposes the same HIBP lookups to AI assistants such as Claude, which can be
useful when following up a finding from MS USER.

## Licence

[MIT](LICENSE)

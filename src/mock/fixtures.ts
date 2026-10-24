// Canned tenant data for MOCK_GRAPH=true (local dev, tests and demos). Shapes follow Graph v1.0.

const daysAgo = (d: number, h = 9) => {
  const t = new Date();
  t.setUTCDate(t.getUTCDate() - d);
  t.setUTCHours(h, 15, 0, 0);
  return t.toISOString();
};

export const RICK = '6e7b768e-07e2-4810-8459-485f84f8f204';
export const MORTY = '87d349ed-44d7-43e1-9a83-5f2406dee5bd';
export const SUMMER = '4f1c2c7a-0d2f-4b55-9b1e-0c5e2b9a7d11';
export const BETH = 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d';
export const BREAKGLASS = 'c0ffee00-b6a5-4c1d-9e8f-000000000911';

const plans = (...services: string[]) =>
  services.map((service, i) => ({ assignedDateTime: '2024-01-01T00:00:00Z', capabilityStatus: 'Enabled', service, servicePlanId: `plan-${i}` }));

export const users = [
  {
    id: RICK,
    displayName: 'Rick Sanchez',
    givenName: 'Rick',
    surname: 'Sanchez',
    userPrincipalName: 'rick.sanchez@contoso.example',
    mail: 'rick.sanchez@contoso.example',
    jobTitle: 'Chief Scientist',
    department: 'Research & Development',
    officeLocation: 'Garage Lab',
    city: 'Seattle',
    mobilePhone: '+1 555 0100',
    userType: 'Member',
    accountEnabled: true,
    onPremisesSyncEnabled: true,
    onPremisesSamAccountName: 'rsanchez',
    onPremisesDistinguishedName: 'CN=Rick Sanchez,OU=Research,DC=contoso,DC=example',
    onPremisesSecurityIdentifier: 'S-1-5-21-1180699209-877415012-3182924384-1004',
    createdDateTime: '2019-01-23T00:44:00Z',
    lastPasswordChangeDateTime: daysAgo(210),
    // A licensed mailbox and Teams – the account he administers the tenant with is also his daily driver
    assignedPlans: plans('exchange', 'TeamspaceAPI', 'SharePoint'),
    companyName: 'Contoso',
    employeeType: 'Employee',
    employeeId: 'C-137',
    employeeHireDate: '2019-01-28T00:00:00Z',
    country: 'United States',
    state: 'WA',
    usageLocation: 'US',
    businessPhones: ['+1 555 0101'],
    manager: { displayName: 'Beth Smith', userPrincipalName: 'beth.smith@contoso.example', jobTitle: 'Head of Operations', department: 'Operations' },
  },
  {
    id: MORTY,
    displayName: 'Morty Smith',
    givenName: 'Morty',
    surname: 'Smith',
    userPrincipalName: 'morty.smith@contoso.example',
    mail: 'morty.smith@contoso.example',
    jobTitle: 'Lab Assistant',
    department: 'Research & Development',
    officeLocation: 'Garage Lab',
    city: 'Seattle',
    mobilePhone: null,
    userType: 'Member',
    accountEnabled: true,
    onPremisesSyncEnabled: null,
    createdDateTime: '2021-06-01T10:00:00Z',
    lastPasswordChangeDateTime: daysAgo(12),
    companyName: 'Contoso',
    employeeType: 'Intern',
    employeeId: 'C-138',
    country: 'United States',
    usageLocation: 'US',
    manager: { displayName: 'Rick Sanchez', userPrincipalName: 'rick.sanchez@contoso.example', jobTitle: 'Chief Scientist', department: 'Research & Development' },
  },
  {
    id: SUMMER,
    displayName: 'Summer Smith (Guest)',
    givenName: 'Summer',
    surname: 'Smith',
    userPrincipalName: 'summer_fabrikam.example#EXT#@contoso.example',
    mail: 'summer@fabrikam.example',
    jobTitle: 'Consultant',
    department: 'Partners',
    userType: 'Guest',
    accountEnabled: true,
    onPremisesSyncEnabled: null,
    createdDateTime: '2024-03-14T08:30:00Z',
  },
  {
    id: BETH,
    displayName: 'Beth Smith',
    givenName: 'Beth',
    surname: 'Smith',
    userPrincipalName: 'beth.smith@contoso.example',
    mail: 'beth.smith@contoso.example',
    jobTitle: 'Head of Operations',
    department: 'Operations',
    officeLocation: 'HQ',
    city: 'Seattle',
    userType: 'Member',
    accountEnabled: true,
    onPremisesSyncEnabled: true,
    onPremisesSamAccountName: 'bsmith',
    createdDateTime: '2019-01-23T00:44:00Z',
    lastPasswordChangeDateTime: daysAgo(400),
    assignedPlans: plans('exchange', 'TeamspaceAPI'),
    companyName: 'Contoso',
    employeeType: 'Employee',
    country: 'United States',
    usageLocation: 'US',
  },
  {
    id: BREAKGLASS,
    displayName: 'Emergency Access 01',
    givenName: 'Emergency',
    surname: 'Access',
    userPrincipalName: 'ea01@contoso.onmicrosoft.example',
    mail: null,
    jobTitle: null,
    department: 'IT Operations',
    userType: 'Member',
    accountEnabled: true,
    onPremisesSyncEnabled: null,
    createdDateTime: '2022-02-02T02:02:00Z',
    lastPasswordChangeDateTime: daysAgo(180),
    assignedPlans: [],
  },
];

export const secureScores = [
  {
    createdDateTime: daysAgo(0, 2),
    currentScore: 412.5,
    maxScore: 655,
    averageComparativeScores: [
      { basis: 'AllTenants', averageScore: 301.2 },
      { basis: 'TotalSeats', averageScore: 355.9 },
    ],
  },
];

const detection = (
  id: string,
  userId: string,
  riskEventType: string,
  riskLevel: string,
  d: number,
  ipAddress: string,
  city: string,
  countryOrRegion: string,
  riskState = 'atRisk',
) => {
  const u = users.find((x) => x.id === userId)!;
  return {
    id,
    riskEventType,
    riskLevel,
    riskState,
    riskDetail: 'none',
    detectedDateTime: daysAgo(d, 14),
    userId,
    userDisplayName: u.displayName,
    userPrincipalName: u.userPrincipalName,
    ipAddress,
    location: { city, countryOrRegion },
    source: 'IdentityProtection',
  };
};

export const riskDetections = [
  detection('rd-01', RICK, 'unlikelyTravel', 'medium', 1, '203.0.113.24', 'Reykjavík', 'IS'),
  detection('rd-02', RICK, 'anonymizedIPAddress', 'medium', 2, '198.51.100.7', 'Unknown', 'NL'),
  detection('rd-03', BETH, 'unfamiliarFeatures', 'low', 3, '192.0.2.44', 'Melbourne', 'AU'),
  detection('rd-04', RICK, 'leakedCredentials', 'high', 6, '', '', ''),
  detection('rd-05', BETH, 'passwordSpray', 'high', 8, '203.0.113.99', 'Frankfurt', 'DE'),
  detection('rd-06', MORTY, 'anonymizedIPAddress', 'low', 20, '198.51.100.12', 'Unknown', 'US', 'remediated'),
  detection('rd-07', RICK, 'suspiciousCredentialAddition', 'high', 3, '198.51.100.7', 'Unknown', 'NL'),
];

export const riskyUsers: Record<string, unknown> = {
  [RICK]: { id: RICK, riskLevel: 'high', riskState: 'atRisk', riskLastUpdatedDateTime: daysAgo(1) },
  [BETH]: { id: BETH, riskLevel: 'medium', riskState: 'atRisk', riskLastUpdatedDateTime: daysAgo(3) },
};

export const registrationDetails: Record<string, unknown> = {
  [RICK]: {
    id: RICK,
    isMfaRegistered: true,
    isMfaCapable: true,
    isPasswordlessCapable: false,
    isSsprRegistered: true,
    defaultMfaMethod: 'sms',
    userPreferredMethodForSecondaryAuthentication: 'sms',
    methodsRegistered: ['mobilePhone', 'email'],
    systemPreferredAuthenticationMethods: [],
    lastUpdatedDateTime: daysAgo(0, 1),
  },
  [MORTY]: {
    id: MORTY,
    isMfaRegistered: true,
    isMfaCapable: true,
    isPasswordlessCapable: true,
    isSsprRegistered: true,
    defaultMfaMethod: 'microsoftAuthenticatorPush',
    userPreferredMethodForSecondaryAuthentication: 'push',
    methodsRegistered: ['microsoftAuthenticatorPush', 'microsoftAuthenticatorPasswordless', 'windowsHelloForBusiness'],
    systemPreferredAuthenticationMethods: ['push'],
    lastUpdatedDateTime: daysAgo(0, 1),
  },
  [BETH]: {
    id: BETH,
    isMfaRegistered: false,
    isMfaCapable: false,
    isPasswordlessCapable: false,
    isSsprRegistered: false,
    defaultMfaMethod: 'none',
    userPreferredMethodForSecondaryAuthentication: 'none',
    methodsRegistered: [],
    systemPreferredAuthenticationMethods: [],
    lastUpdatedDateTime: daysAgo(0, 1),
  },
  [BREAKGLASS]: {
    id: BREAKGLASS,
    isMfaRegistered: true,
    isMfaCapable: true,
    isPasswordlessCapable: true,
    isSsprRegistered: false,
    defaultMfaMethod: 'none',
    userPreferredMethodForSecondaryAuthentication: 'none',
    methodsRegistered: ['passKeyDeviceBound'],
    systemPreferredAuthenticationMethods: ['passKeyDeviceBound'],
    lastUpdatedDateTime: daysAgo(0, 1),
  },
};

interface SignInOpts {
  /** Methods for each authentication step, as they appear in beta authenticationDetails */
  auth?: string[];
  requirement?: string;
  ca?: string;
}

const signIn = (
  userId: string,
  d: number,
  app: string,
  city: string,
  country: string,
  os: string,
  trust: string,
  errorCode = 0,
  failureReason = '',
  { auth = ['Password', 'Mobile app notification'], requirement = 'multiFactorAuthentication', ca }: SignInOpts = {},
) => ({
  id: `si-${userId.slice(0, 4)}-${d}-${app.length}`,
  createdDateTime: daysAgo(d, 8 + (d % 9)),
  userId,
  appDisplayName: app,
  ipAddress: `198.51.100.${(d * 7) % 250}`,
  clientAppUsed: 'Browser',
  isInteractive: true,
  conditionalAccessStatus: ca ?? (errorCode ? 'failure' : 'success'),
  authenticationRequirement: requirement,
  riskLevelDuringSignIn: 'none',
  status: { errorCode, failureReason },
  deviceDetail: { operatingSystem: os, browser: 'Edge 141.0', trustType: trust },
  location: { city, countryOrRegion: country },
  // beta only – v1.0 callers simply ignore it
  authenticationDetails: auth.map((authenticationMethod, i) => ({
    authenticationMethod,
    authenticationStepDateTime: daysAgo(d, 8 + (d % 9)),
    authenticationStepRequirement: i === 0 ? 'Primary authentication' : 'Multifactor authentication',
    succeeded: errorCode === 0,
  })),
});

export const signIns: Record<string, unknown[]> = {
  [RICK]: [
    signIn(RICK, 0, 'Office 365 Exchange Online', 'Seattle', 'US', 'Windows 11', '', 0, '', { auth: ['Password', 'Text message'] }),
    signIn(RICK, 1, 'Microsoft Teams', 'Reykjavík', 'IS', 'Linux', '', 50126, 'Error validating credentials due to invalid username or password.', {
      auth: ['Password'],
    }),
    signIn(RICK, 2, 'Azure Portal', 'Unknown', 'NL', 'Linux', '', 0, '', {
      auth: ['Password'],
      requirement: 'singleFactorAuthentication',
      ca: 'notApplied',
    }),
    signIn(RICK, 4, 'Office 365 SharePoint Online', 'Seattle', 'US', 'Windows 11', '', 0, '', { auth: ['Password', 'Text message'] }),
  ],
  [MORTY]: [
    signIn(MORTY, 0, 'Microsoft Teams', 'Seattle', 'US', 'Windows 11', 'Azure AD joined', 0, '', { auth: ['Windows Hello for Business'] }),
    signIn(MORTY, 1, 'Office 365 Exchange Online', 'Seattle', 'US', 'iOS 26', '', 0, '', { auth: ['Passkey (Microsoft Authenticator)'] }),
  ],
  [BETH]: [signIn(BETH, 3, 'My Apps', 'Melbourne', 'AU', 'MacOs', '', 0, '', { auth: ['Temporary Access Pass'] })],
  [BREAKGLASS]: [signIn(BREAKGLASS, 6, 'Azure Portal', 'Seattle', 'US', 'Windows 11', '', 0, '', { auth: ['FIDO2 security key'] })],
};

const ssprEvent = (userId: string, d: number, activityDisplayName: string, result: string, resultReason = '') => ({
  id: `sspr-${userId.slice(0, 4)}-${d}-${result}`,
  activityDateTime: daysAgo(d, 11),
  activityDisplayName,
  loggedByService: 'Self-service Password Management',
  result,
  resultReason,
  targetResources: [{ id: userId, type: 'User' }],
});

export const ssprEvents: Record<string, unknown[]> = {
  [RICK]: [
    ssprEvent(RICK, 1, 'Reset password (self-service)', 'failure', 'User submitted a new password that did not meet the fuzzy password policy'),
    ssprEvent(RICK, 1, 'Reset password (self-service)', 'failure', 'User submitted a banned password'),
    ssprEvent(RICK, 2, 'Self-service password reset flow activity progress', 'failure', 'User failed SMS verification'),
    ssprEvent(RICK, 5, 'Reset password (self-service)', 'success'),
  ],
  [BETH]: [ssprEvent(BETH, 9, 'Reset password (self-service)', 'success')],
};

export const devices: Record<string, unknown[]> = {
  [RICK]: [
    { id: 'dev-1', displayName: 'RICK-LAB-01', operatingSystem: 'Windows', operatingSystemVersion: '10.0.26100', trustType: 'Workplace', isCompliant: false, isManaged: false, approximateLastSignInDateTime: daysAgo(0) },
    { id: 'dev-2', displayName: "Rick's Portal Gun", operatingSystem: 'Android', operatingSystemVersion: '16', trustType: 'Workplace', isCompliant: null, isManaged: false, approximateLastSignInDateTime: daysAgo(4) },
  ],
  [MORTY]: [
    { id: 'dev-3', displayName: 'MORTY-LT', operatingSystem: 'Windows', operatingSystemVersion: '10.0.26200', trustType: 'AzureAd', isCompliant: true, isManaged: true, approximateLastSignInDateTime: daysAgo(0) },
    { id: 'dev-4', displayName: "Morty's iPhone", operatingSystem: 'iOS', operatingSystemVersion: '26.0', trustType: 'Workplace', isCompliant: true, isManaged: true, approximateLastSignInDateTime: daysAgo(1) },
  ],
  [BETH]: [
    { id: 'dev-5', displayName: 'BETH-DT', operatingSystem: 'Windows', operatingSystemVersion: '10.0.22631', trustType: 'ServerAd', isCompliant: true, isManaged: true, approximateLastSignInDateTime: daysAgo(3) },
  ],
};

export const hibpBreaches: Record<string, unknown[]> = {
  'rick.sanchez@contoso.example': [
    {
      Name: 'CitadelForums',
      Title: 'Citadel Forums',
      Domain: 'citadel.example',
      BreachDate: '2023-08-02',
      DataClasses: ['Email addresses', 'Passwords', 'Usernames'],
      IsVerified: true,
    },
    {
      Name: 'BlipsAndChitz',
      Title: 'Blips and Chitz',
      Domain: 'blipsandchitz.example',
      BreachDate: '2021-02-11',
      DataClasses: ['Email addresses', 'IP addresses', 'Names'],
      IsVerified: true,
    },
  ],
  'beth.smith@contoso.example': [
    {
      Name: 'HorseSurgeons',
      Title: 'Horse Surgeons Association',
      Domain: 'horsesurgeons.example',
      BreachDate: '2020-05-19',
      DataClasses: ['Email addresses', 'Job titles', 'Names'],
      IsVerified: true,
    },
  ],
};

export const hibpPastes: Record<string, unknown[]> = {
  'rick.sanchez@contoso.example': [{ Source: 'Pastebin', Id: 'abc123', Date: daysAgo(40) }],
};

// ---------- Authentication strength, privilege, blast radius and persistence signals ----------

const method = (type: string, id: string, d: number, extra: Record<string, unknown> = {}) => ({
  '@odata.type': `#microsoft.graph.${type}AuthenticationMethod`,
  id,
  createdDateTime: daysAgo(d, 10),
  ...extra,
});

export const authMethods: Record<string, unknown[]> = {
  [RICK]: [
    method('password', 'pw-rick', 900),
    method('microsoftAuthenticator', 'ma-rick', 400, { displayName: 'Pixel 9', deviceTag: 'SoftwareTokenActivated', phoneAppVersion: '6.2509' }),
    // Registered three days ago, alongside the suspicious credential addition detection
    method('phone', 'ph-rick', 3, { phoneNumber: '+1 555 0199', phoneType: 'mobile', smsSignInState: 'notAllowedByPolicy' }),
    method('phone', 'ph-rick-alt', 300, { phoneNumber: '+1 555 0142', phoneType: 'alternateMobile', smsSignInState: 'notSupported' }),
    method('email', 'em-rick', 300, { emailAddress: 'rick@citadel.example' }),
  ],
  [MORTY]: [
    method('password', 'pw-morty', 500),
    method('windowsHelloForBusiness', 'whfb-morty', 120, { displayName: 'MORTY-LT', keyStrength: 'normal' }),
    method('fido2', 'fido-morty', 90, { displayName: 'Passkey in Microsoft Authenticator', model: 'Microsoft Authenticator - iOS', attestationLevel: 'attested' }),
    method('microsoftAuthenticator', 'ma-morty', 90, { displayName: "Morty's iPhone", deviceTag: 'SoftwareTokenActivated', phoneAppVersion: '6.8.20' }),
  ],
  [BETH]: [
    method('password', 'pw-beth', 2000),
    method('email', 'em-beth', 700, { emailAddress: 'beth@horsesurgeons.example' }),
    method('temporaryAccessPass', 'tap-beth', 1, {
      startDateTime: daysAgo(1, 9),
      lifetimeInMinutes: 480,
      isUsableOnce: false,
      isUsable: true,
      methodUsabilityReason: 'EnabledByPolicy',
    }),
  ],
  [BREAKGLASS]: [
    method('password', 'pw-bg', 180),
    method('fido2', 'fido-bg-1', 400, { displayName: 'YubiKey 5 NFC (safe A)', model: 'YubiKey 5 NFC', attestationLevel: 'attested' }),
    method('fido2', 'fido-bg-2', 400, { displayName: 'YubiKey 5 NFC (safe B)', model: 'YubiKey 5 NFC', attestationLevel: 'attested' }),
  ],
};

const ROLES = {
  globalAdmin: { id: '62e90394-69f5-4237-9190-012177145e10', displayName: 'Global Administrator' },
  exchangeAdmin: { id: '29232cdf-9323-42fd-ade2-1d097af3e4de', displayName: 'Exchange Administrator' },
  securityAdmin: { id: '194ae4cb-b126-40b2-bd5b-6091b380977d', displayName: 'Security Administrator' },
  userAdmin: { id: 'fe930be7-5e62-47db-91af-98c3a49a38b1', displayName: 'User Administrator' },
  groupsAdmin: { id: 'fdd7a751-b60b-444a-984c-02652fe8fa1c', displayName: 'Groups Administrator' },
  messageCenterReader: { id: '790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b', displayName: 'Message Center Reader' },
  privAuthAdmin: { id: '7be44c8a-adaf-4e2a-84d6-ab2649e08a13', displayName: 'Privileged Authentication Administrator' },
};
type RoleKey = keyof typeof ROLES;
const roleDefinition = (k: RoleKey) => ({ ...ROLES[k], templateId: ROLES[k].id, isBuiltIn: true });

const activeRole = (principalId: string, k: RoleKey, opts: { endDays?: number; assignmentType?: string; memberType?: string } = {}) => ({
  id: `ra-${principalId.slice(0, 4)}-${k}`,
  principalId,
  roleDefinitionId: ROLES[k].id,
  directoryScopeId: '/',
  startDateTime: daysAgo(200),
  endDateTime: opts.endDays === undefined ? null : new Date(Date.now() + opts.endDays * 86_400_000).toISOString(),
  assignmentType: opts.assignmentType ?? 'Assigned',
  memberType: opts.memberType ?? 'Direct',
  roleDefinition: roleDefinition(k),
});
const eligibleRole = (principalId: string, k: RoleKey) => ({
  id: `re-${principalId.slice(0, 4)}-${k}`,
  principalId,
  roleDefinitionId: ROLES[k].id,
  directoryScopeId: '/',
  startDateTime: daysAgo(100),
  endDateTime: new Date(Date.now() + 265 * 86_400_000).toISOString(),
  memberType: 'Direct',
  roleDefinition: roleDefinition(k),
});

export const roleSchedules: Record<string, ReturnType<typeof activeRole>[]> = {
  [RICK]: [activeRole(RICK, 'globalAdmin'), activeRole(RICK, 'exchangeAdmin', { endDays: 30 }), activeRole(RICK, 'messageCenterReader')],
  // Beth has activated User Administrator through PIM for a few hours
  [BETH]: [activeRole(BETH, 'userAdmin', { endDays: 0.2, assignmentType: 'Activated' })],
  [BREAKGLASS]: [activeRole(BREAKGLASS, 'globalAdmin')],
};

// What /roleAssignments returns – no PIM detail; used only when schedule instances are unavailable (no P2)
export const roleAssignments: Record<string, unknown[]> = Object.fromEntries(
  Object.entries(roleSchedules).map(([id, list]) => [
    id,
    list.map(({ id: raId, principalId, roleDefinitionId, directoryScopeId, roleDefinition: def }) => ({
      id: raId,
      principalId,
      roleDefinitionId,
      directoryScopeId,
      roleDefinition: def,
    })),
  ]),
);

export const roleEligibilities: Record<string, unknown[]> = {
  [RICK]: [eligibleRole(RICK, 'securityAdmin')],
  [BETH]: [eligibleRole(BETH, 'userAdmin'), eligibleRole(BETH, 'groupsAdmin')],
};

export const TIER0_GROUP = '7e1e0000-0000-4000-8000-000000000001';
export const FINANCE_GROUP = '7e1e0000-0000-4000-8000-000000000002';

// Roles held by a role-assignable group are listed under the group as principal, not its members
roleSchedules[TIER0_GROUP] = [activeRole(TIER0_GROUP, 'privAuthAdmin')];
roleAssignments[TIER0_GROUP] = roleSchedules[TIER0_GROUP]!.map(({ id, principalId, roleDefinitionId, directoryScopeId, roleDefinition: def }) => ({
  id,
  principalId,
  roleDefinitionId,
  directoryScopeId,
  roleDefinition: def,
}));

const group = (id: string, displayName: string, kind: 'security' | 'unified' | 'mail' = 'security', extra: Record<string, unknown> = {}) => ({
  '@odata.type': '#microsoft.graph.group',
  id,
  displayName,
  groupTypes: kind === 'unified' ? ['Unified'] : [],
  securityEnabled: kind === 'security',
  mailEnabled: kind !== 'security',
  isAssignableToRole: false,
  ...extra,
});
const groupId = (n: number) => `9a0b0000-0000-4000-8000-${String(n).padStart(12, '0')}`;

export const ownedObjects: Record<string, unknown[]> = {
  [RICK]: [
    { '@odata.type': '#microsoft.graph.application', id: 'app-portal', displayName: 'Portal Gun Controller', appId: '11111111-2222-4333-8444-555555555555' },
    {
      '@odata.type': '#microsoft.graph.servicePrincipal',
      id: 'sp-portal',
      displayName: 'Portal Gun Controller',
      appId: '11111111-2222-4333-8444-555555555555',
      servicePrincipalType: 'Application',
    },
    { '@odata.type': '#microsoft.graph.agentIdentity', id: 'agent-meeseeks', displayName: 'Mr. Meeseeks Agent', servicePrincipalType: 'ServiceIdentity' },
    group(TIER0_GROUP, 'Tier 0 Admins', 'security', { isAssignableToRole: true }),
    group(groupId(1), 'Garage Lab', 'unified', { resourceProvisioningOptions: ['Team'] }),
    group(groupId(2), 'Interdimensional Cable Fans', 'mail'),
  ],
  [BETH]: [group(groupId(3), 'Operations', 'unified', { resourceProvisioningOptions: ['Team'] })],
};

const guest = (n: number) => ({
  '@odata.type': '#microsoft.graph.user',
  id: `6e570000-0000-4000-8000-${String(n).padStart(12, '0')}`,
  displayName: `Partner Contact ${n}`,
  userPrincipalName: `partner${n}_fabrikam.example#EXT#@contoso.example`,
  userType: 'Guest',
});

export const sponsorOf: Record<string, unknown[]> = {
  [BETH]: Array.from({ length: 14 }, (_, i) => guest(i + 1)),
};

const directoryRole = (k: RoleKey) => ({
  '@odata.type': '#microsoft.graph.directoryRole',
  id: `dr-${k}`,
  displayName: ROLES[k].displayName,
  roleTemplateId: ROLES[k].id,
});
const adminUnit = (id: string, displayName: string) => ({ '@odata.type': '#microsoft.graph.administrativeUnit', id, displayName });

export const memberOf: Record<string, unknown[]> = {
  [RICK]: [
    directoryRole('globalAdmin'),
    directoryRole('exchangeAdmin'),
    group(TIER0_GROUP, 'Tier 0 Admins', 'security', { isAssignableToRole: true }),
    group(groupId(1), 'Garage Lab', 'unified'),
    ...Array.from({ length: 10 }, (_, i) => group(groupId(100 + i), `Research Project ${i + 1}`)),
    adminUnit('au-research', 'Research'),
  ],
  [MORTY]: [group(groupId(1), 'Garage Lab', 'unified'), group(groupId(4), 'All Staff'), group(groupId(5), 'Seattle Office')],
  [SUMMER]: [group(groupId(6), 'Partner Collaboration', 'unified')],
  // Membership sprawl: 90 direct groups, including payroll
  [BETH]: [
    group(FINANCE_GROUP, 'Finance - Payroll'),
    ...Array.from({ length: 89 }, (_, i) => group(groupId(200 + i), `Ops Distribution ${i + 1}`, i % 3 ? 'security' : 'mail')),
    adminUnit('au-ops', 'Operations'),
  ],
  [BREAKGLASS]: [directoryRole('globalAdmin')],
};

export const transitiveGroupCounts: Record<string, number> = { [RICK]: 34, [MORTY]: 6, [SUMMER]: 1, [BETH]: 260, [BREAKGLASS]: 0 };

const audit = (
  targetId: string,
  d: number,
  activityDisplayName: string,
  initiatedBy: { user?: { id: string; userPrincipalName: string }; app?: { displayName: string } },
  loggedByService = 'Authentication Methods',
  h = 10,
) => ({
  id: `audit-${targetId.slice(-6)}-${d}-${activityDisplayName.length}-${h}`,
  category: 'UserManagement',
  activityDateTime: daysAgo(d, h),
  activityDisplayName,
  loggedByService,
  result: 'success',
  resultReason: '',
  initiatedBy,
  targetResources: [{ id: targetId, type: 'User' }],
});
const self = (id: string) => ({ user: { id, userPrincipalName: users.find((u) => u.id === id)!.userPrincipalName } });

export const methodAudits: Record<string, unknown[]> = {
  [RICK]: [
    // A temporary helpdesk account registered a phone for Rick, then it became his default method
    audit(RICK, 3, 'Admin registered security info', { user: { id: 'f00dbabe-0000-4000-8000-000000000666', userPrincipalName: 'helpdesk.temp@contoso.example' } }, 'Authentication Methods', 9),
    audit(RICK, 3, 'User changed default security info', self(RICK), 'Authentication Methods', 9),
    // Failed operations changed nothing and must not count as credential changes
    { ...audit(RICK, 4, 'Admin registered security info', { app: { displayName: 'Unknown app' } }), result: 'failure' },
  ],
  [MORTY]: [audit(MORTY, 20, 'User registered security info', self(MORTY))],
  [BETH]: [audit(BETH, 1, 'Admin registered security info', { app: { displayName: 'Microsoft Entra admin center' } })],
};

export const guestInvites: Record<string, unknown[]> = {
  [RICK]: [1, 2].map((i) => audit(guest(100 + i).id, 5 + i, 'Invite external user', self(RICK), 'Invited Users')),
  [BETH]: [
    ...Array.from({ length: 20 }, (_, i) => audit(guest(200 + i).id, (i % 25) + 1, 'Invite external user', self(BETH), 'Invited Users', 8 + (i % 8))),
    { ...audit(guest(299).id, 2, 'Invite external user', self(BETH), 'Invited Users'), result: 'failure' },
  ],
};

export const authMethodsPolicy = {
  id: 'authenticationMethodsPolicy',
  authenticationMethodConfigurations: [
    { id: 'Fido2', state: 'enabled' },
    { id: 'MicrosoftAuthenticator', state: 'enabled' },
    { id: 'Sms', state: 'enabled' },
    { id: 'Voice', state: 'disabled' },
    { id: 'TemporaryAccessPass', state: 'enabled' },
    { id: 'Email', state: 'enabled' },
    { id: 'X509Certificate', state: 'disabled' },
    { id: 'SoftwareOath', state: 'enabled' },
  ],
};

export const securityDefaults = { id: '00000000-0000-0000-0000-000000000005', isEnabled: false };

/** Policy applied when MOCK_GRAPH=true and no POLICY_JSON is configured */
export const mockPolicy = {
  breakGlassAccounts: [BREAKGLASS],
  pimExceptions: [BREAKGLASS],
  sensitiveGroupIds: [TIER0_GROUP, FINANCE_GROUP],
};

// ---------- Organisational context ----------

// Tiny generated avatars (96x96 PNG); users without one fall back to initials
export const photos: Record<string, string> = {
  [RICK]: 'iVBORw0KGgoAAAANSUhEUgAAAGAAAABgCAIAAABt+uBvAAABIklEQVR42u3awXEDMQwDQHTgRt1i3mnDRbgAd+DEdxJ9onYGFeyPBHK7/8ibBAEgQIAAAQIECJAAAgQIECBAgAAJIECAtgH6fTzfZ1OgP10uIpVVdL5llFVovsWU5XSKjbKiTqVRFtUpMwJ0AaBJOjVGWVqnwAgQoCsDFejMNgIECBAgQIAAAQIECJBbDBCg/YB8FP2kAenFNKu6eeuOXdYd9kEWZjaKAggQIECAAAEC5NRwzfsoajXWbTXKatWpTOmhM88oPWjmMaWZznCj9NMZa5SWOgON0lVnlFEa6wwxSm+d80Zpr3PSKDvonDECNAdoOZ3DRtlH55gRoNFAS+scMAI0FKiBzqdGgACVAbXR+cgIEKAaoGY6/zcCBAjQVKAXQGCRaTRrFKIAAAAASUVORK5CYII=',
  [MORTY]: 'iVBORw0KGgoAAAANSUhEUgAAAGAAAABgCAIAAABt+uBvAAABIklEQVR42u3awXEDMQwDQFTgil1bHinGRfjlDpz4TqJP1M6ggv2RQH7vN3mTIAAECBAgQIAAARJAgAABAgQIECABBAjQNkDPx8/7bAr0p8tFpLKKzreMsgrNt5iynE6xUVbUqTTKojplRoAuADRJp8YoS+sUGAECdGWgAp3ZRoAAAQIECBAgQIAAAXKLAQK0H5CPop80IL2YZlU3b92xy7rDPsjCzEZRAAECBAgQIECAnBqueR9Frca6rUZZrTqVKT105hmlB808pjTTGW6UfjpjjdJSZ6BRuuqMMkpjnSFG6a1z3ijtdU4aZQedM0aA5gAtp3PYKPvoHDMCNBpoaZ0DRoCGAjXQ+dQIEKAyoDY6HxkBAlQD1Ezn/0aAAAGaCvQCLHytkTniqQAAAAAASUVORK5CYII=',
};

const licence = (skuPartNumber: string) => ({ skuId: `sku-${skuPartNumber}`, skuPartNumber });
export const licenceDetails: Record<string, unknown[]> = {
  [RICK]: [licence('SPE_E5')],
  [MORTY]: [licence('SPE_F1')],
  [BETH]: [licence('SPE_E3'), licence('POWER_BI_PRO')],
};

export const signInActivity: Record<string, unknown> = {
  [RICK]: { lastSignInDateTime: daysAgo(0, 8), lastNonInteractiveSignInDateTime: daysAgo(0, 11), lastSuccessfulSignInDateTime: daysAgo(0, 8) },
  [MORTY]: { lastSignInDateTime: daysAgo(0, 9), lastNonInteractiveSignInDateTime: daysAgo(0, 10), lastSuccessfulSignInDateTime: daysAgo(0, 9) },
  [BETH]: { lastSignInDateTime: daysAgo(3, 8), lastNonInteractiveSignInDateTime: daysAgo(1), lastSuccessfulSignInDateTime: daysAgo(3, 8) },
  [BREAKGLASS]: { lastSignInDateTime: daysAgo(6), lastNonInteractiveSignInDateTime: null, lastSuccessfulSignInDateTime: daysAgo(6) },
};

export const directReportCounts: Record<string, number> = { [RICK]: 1, [BETH]: 2 };

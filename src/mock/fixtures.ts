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
    manager: { displayName: 'Beth Smith', userPrincipalName: 'beth.smith@contoso.example' },
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
    manager: { displayName: 'Rick Sanchez', userPrincipalName: 'rick.sanchez@contoso.example' },
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
};

const signIn = (userId: string, d: number, app: string, city: string, country: string, os: string, trust: string, errorCode = 0, failureReason = '') => ({
  id: `si-${userId.slice(0, 4)}-${d}-${app.length}`,
  createdDateTime: daysAgo(d, 8 + (d % 9)),
  userId,
  appDisplayName: app,
  ipAddress: `198.51.100.${(d * 7) % 250}`,
  clientAppUsed: 'Browser',
  conditionalAccessStatus: errorCode ? 'failure' : 'success',
  authenticationRequirement: 'multiFactorAuthentication',
  riskLevelDuringSignIn: 'none',
  status: { errorCode, failureReason },
  deviceDetail: { operatingSystem: os, browser: 'Edge 141.0', trustType: trust },
  location: { city, countryOrRegion: country },
});

export const signIns: Record<string, unknown[]> = {
  [RICK]: [
    signIn(RICK, 0, 'Office 365 Exchange Online', 'Seattle', 'US', 'Windows 11', ''),
    signIn(RICK, 1, 'Microsoft Teams', 'Reykjavík', 'IS', 'Linux', '', 50126, 'Error validating credentials due to invalid username or password.'),
    signIn(RICK, 2, 'Azure Portal', 'Unknown', 'NL', 'Linux', ''),
    signIn(RICK, 4, 'Office 365 SharePoint Online', 'Seattle', 'US', 'Windows 11', ''),
  ],
  [MORTY]: [
    signIn(MORTY, 0, 'Microsoft Teams', 'Seattle', 'US', 'Windows 11', 'Azure AD joined'),
    signIn(MORTY, 1, 'Office 365 Exchange Online', 'Seattle', 'US', 'iOS 26', ''),
  ],
  [BETH]: [signIn(BETH, 3, 'My Apps', 'Melbourne', 'AU', 'MacOs', '')],
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

import { describe, expect, it } from 'vitest';
import { atlasSource, classify, classifyRole } from '../src/services/roleCatalog.js';

// The roles the PRD calls out by name must stay high impact whatever a Graph-atlas refresh brings
const PRD_ROLES: Record<string, string> = {
  '62e90394-69f5-4237-9190-012177145e10': 'Global Administrator',
  'e8611ab8-c189-46e8-94e1-60213ab1f814': 'Privileged Role Administrator',
  'c4e39bd9-1100-46d3-8c65-fb160da0071f': 'Authentication Administrator',
  '7be44c8a-adaf-4e2a-84d6-ab2649e08a13': 'Privileged Authentication Administrator',
  'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9': 'Conditional Access Administrator',
  '194ae4cb-b126-40b2-bd5b-6091b380977d': 'Security Administrator',
  '5f2222b1-57c3-48ba-8ad5-d4759f1fde6f': 'Security Operator',
  '29232cdf-9323-42fd-ade2-1d097af3e4de': 'Exchange Administrator',
  'f28a1f50-f6e7-4571-818b-6a12f2af6b6c': 'SharePoint Administrator',
  '3a2c62db-5318-420d-8d74-23affee5d9d5': 'Intune Administrator',
  'fe930be7-5e62-47db-91af-98c3a49a38b1': 'User Administrator',
};

describe('role catalog (Graph-atlas snapshot)', () => {
  it('records where the snapshot came from', () => {
    expect(atlasSource.repo).toBe('darrenjrobinson/graph-atlas-mcp');
    expect(atlasSource.release).toMatch(/^v\d{4}\.\d{2}\.\d{2}$|^local$/);
  });

  it.each(Object.entries(PRD_ROLES))('%s (%s) is known, high impact and PIM-recommended', (id, name) => {
    const role = classifyRole(id);
    expect(role).toMatchObject({ known: true, name, impact: 'high', pimRecommended: true });
  });

  it('derives themes from write actions', () => {
    expect(classifyRole('e8611ab8-c189-46e8-94e1-60213ab1f814').themes).toContain('Privilege escalation');
    expect(classifyRole('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3').themes).toContain('App credential takeover'); // Application Administrator
    expect(classifyRole('b1be1c3e-b65d-4f19-8427-f6fa0d97feb9').themes).toContain('Access policy');
  });

  it('keeps privileged readers below high impact', () => {
    expect(classifyRole('f2ef992c-3afb-46b9-b7cf-a126ee74c451')).toMatchObject({ name: 'Global Reader', isPrivileged: true, impact: 'medium' });
    expect(classifyRole('88d8e3e3-8f55-4a1e-953a-9b9898b8876b')).toMatchObject({ name: 'Directory Readers', impact: 'low' });
  });

  it('classifies from actions and ignores tenant-wide noise', () => {
    const base = { templateId: '00000000-0000-4000-8000-000000000001', name: 'Test', isPrivileged: false };
    expect(classify({ ...base, actions: ['microsoft.azure.serviceHealth/allEntities/allTasks'] }).impact).toBe('low');
    const reset = classify({ ...base, actions: ['microsoft.directory/users/password/update'] });
    expect(reset.impact).toBe('high');
    expect(reset.themes).toContain('Credential reset');
    expect(classify({ ...base, actions: ['microsoft.directory/groups/members/update'] })).toMatchObject({ impact: 'medium', themes: ['Directory write'] });
  });

  it('keeps roles whose power lives outside the directory at medium or above', () => {
    expect(classifyRole('9f06204d-73c1-4d4c-880a-6edb90606fd8')).toMatchObject({ impact: 'medium', themes: ['Local admin on every Entra joined device'] });
  });

  it('treats custom and unknown roles as medium impact', () => {
    expect(classifyRole('11111111-2222-4333-8444-555555555555', 'Contoso Helpdesk')).toMatchObject({
      known: false,
      name: 'Contoso Helpdesk',
      impact: 'medium',
      pimRecommended: false,
    });
  });
});

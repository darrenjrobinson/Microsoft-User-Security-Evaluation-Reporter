import { describe, expect, it } from 'vitest';
import { HttpGraphClient } from '../src/graph/client.js';

const credential = { getToken: async () => ({ token: 't', expiresOnTimestamp: Date.now() + 60_000 }) };
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

describe('HttpGraphClient', () => {
  it('normalises null bodies in batch responses to an empty object', async () => {
    const fetchImpl = (async () =>
      json({
        responses: [
          { id: 'signInActivity', status: 200, body: null },
          { id: 'user', status: 200, body: { id: 'u' } },
        ],
      })) as typeof fetch;
    const responses = await new HttpGraphClient(credential, fetchImpl).batch([
      { id: 'signInActivity', method: 'GET', url: '/users/x' },
      { id: 'user', method: 'GET', url: '/users/x' },
    ]);
    expect(responses.get('signInActivity')).toEqual({ status: 200, body: {} });
    expect(responses.get('user')).toEqual({ status: 200, body: { id: 'u' } });
  });

  it('normalises a literal null body on a direct request', async () => {
    const fetchImpl = (async () => json(null)) as typeof fetch;
    const res = await new HttpGraphClient(credential, fetchImpl).get('/subscribedSkus');
    expect(res.body).toEqual({});
  });
});

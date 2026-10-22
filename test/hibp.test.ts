import { describe, expect, it } from 'vitest';
import { createHibpService } from '../src/services/hibp.js';

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

describe('HIBP service', () => {
  it('is disabled without an API key', async () => {
    const lookup = createHibpService({ userAgent: 'test' });
    expect(await lookup('a@b.c')).toMatchObject({ status: 'unavailable', reason: 'disabled' });
  });

  it('sends the key and user agent, and treats 404 as clean', async () => {
    const seen: Request[] = [];
    const lookup = createHibpService({
      apiKey: 'k',
      userAgent: 'ua',
      fetchImpl: async (input, init) => {
        seen.push(new Request(input, init));
        return new Response(null, { status: 404 });
      },
    });
    expect(await lookup('a+b@c.d')).toEqual({ status: 'ok', data: { account: 'a+b@c.d', breaches: [], pasteCount: 0 } });
    expect(seen[0]!.url).toBe('https://haveibeenpwned.com/api/v3/breachedaccount/a%2Bb%40c.d?truncateResponse=false');
    expect(seen[0]!.headers.get('hibp-api-key')).toBe('k');
    expect(seen[0]!.headers.get('user-agent')).toBe('ua');
  });

  it('maps breaches and flags exposed passwords', async () => {
    const lookup = createHibpService({
      apiKey: 'k',
      userAgent: 'ua',
      fetchImpl: async (input) =>
        String(input).includes('breachedaccount')
          ? json([{ Name: 'X', Title: 'X', Domain: 'x.example', BreachDate: '2020-01-01', DataClasses: ['Passwords'], IsVerified: true }])
          : json([{}, {}]),
    });
    const res = await lookup('a@b.c');
    expect(res.status === 'ok' && res.data).toMatchObject({ pasteCount: 2, breaches: [{ includesPasswords: true }] });
  });

  it('reports an invalid key as forbidden', async () => {
    const lookup = createHibpService({ apiKey: 'bad', userAgent: 'ua', fetchImpl: async () => new Response(null, { status: 401 }) });
    expect(await lookup('a@b.c')).toMatchObject({ status: 'unavailable', reason: 'forbidden' });
  });
});

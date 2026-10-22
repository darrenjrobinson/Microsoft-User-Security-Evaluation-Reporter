import type { NextFunction, Request, Response } from 'express';

// App Service Authentication (Easy Auth) injects the signed-in principal as a base64 JSON header.
// The platform strips any client-supplied X-MS-CLIENT-PRINCIPAL* headers, so it can be trusted
// when the app is only reachable through App Service with authentication enabled.
// https://learn.microsoft.com/azure/app-service/configure-authentication-user-identities

interface EasyAuthPrincipal {
  auth_typ?: string;
  name_typ?: string;
  role_typ?: string;
  claims?: { typ: string; val: string }[];
}

export interface Operator {
  name: string;
  roles: string[];
}

declare module 'express-serve-static-core' {
  interface Request {
    operator?: Operator;
  }
}

const ROLE_CLAIMS = ['roles', 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role'];
const NAME_CLAIMS = ['name', 'preferred_username', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'];

export function parsePrincipal(header: string | undefined): Operator | undefined {
  if (!header) return undefined;
  let principal: EasyAuthPrincipal;
  try {
    principal = JSON.parse(Buffer.from(header, 'base64').toString('utf8')) as EasyAuthPrincipal;
  } catch {
    return undefined;
  }
  const claims = Array.isArray(principal.claims) ? principal.claims : [];
  const roleTypes = new Set([...ROLE_CLAIMS, principal.role_typ].filter(Boolean));
  const nameTypes = [principal.name_typ, ...NAME_CLAIMS].filter(Boolean);
  const roles = claims.filter((c) => roleTypes.has(c.typ)).map((c) => c.val);
  const name = nameTypes.map((t) => claims.find((c) => c.typ === t)?.val).find(Boolean) ?? 'Operator';
  return { name, roles };
}

export function requireOperator(requiredRole: string, disabled: boolean) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (disabled) {
      req.operator = { name: 'Local developer', roles: [requiredRole] };
      return next();
    }
    const operator = parsePrincipal(req.header('x-ms-client-principal'));
    if (!operator) {
      return res.status(401).json({ error: 'unauthenticated', message: 'Sign in is required.' });
    }
    if (!operator.roles.includes(requiredRole)) {
      return res
        .status(403)
        .json({ error: 'forbidden', message: `The ${requiredRole} app role is required to use this application.` });
    }
    req.operator = operator;
    next();
  };
}

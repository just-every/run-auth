import {Hono} from 'hono';
import {requirePermission} from '@runeditrun/auth-hono';

export function createProtectedApp({session, apiId}) {
  const app = new Hono();
  app.get('/documents/budget', requirePermission({session, apiId, action: 'read', resource: 'document:budget'}),
    context => context.json({document: 'Budget', subject: context.get('authPrincipal').id}));
  return app;
}

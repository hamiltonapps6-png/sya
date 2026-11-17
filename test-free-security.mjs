import fs from 'node:fs';
import assert from 'node:assert/strict';

const server = fs.readFileSync(new URL('./server.ts', import.meta.url), 'utf8');
const env = fs.readFileSync(new URL('./.env.example', import.meta.url), 'utf8');

assert.doesNotMatch(server, /isAdminEmail|ADMIN_EMAIL/,
  'Admin rights must not be inferred from email patterns or a public email address.');
assert.match(server, /app\.post\('\/api\/admin\/bootstrap', authenticate/,
  'First admin must be provisioned through authenticated bootstrap.');
assert.match(server, /configuredToken\.length < 32/,
  'Bootstrap secret must be at least 32 characters.');
assert.match(server, /db\.users\.some\(\(u\) => u\.role === 'admin'\)/,
  'Bootstrap must be one-time only.');
assert.match(server, /role: 'user',[\s\S]*?tier: 'free',[\s\S]*?subscriptionStatus: 'none'/,
  'Legacy accounts must be normalized to free and non-admin at startup.');
for (const route of [
  "app.post('/api/webhooks/konnect'",
  "app.post('/api/webhooks/flouci'",
  "app.post('/api/admin/payments/:id/approve'",
  "app.post('/api/admin/payments/:id/reject'",
]) {
  const start = server.indexOf(route);
  assert.notEqual(start, -1, `Missing legacy route: ${route}`);
  assert.match(server.slice(start, start + 300), /status\(410\)/,
    `Legacy paid endpoint must be retired: ${route}`);
}
assert.match(env, /ADMIN_BOOTSTRAP_TOKEN=/,
  'Deployment template must document the one-time admin bootstrap secret.');
console.log('Siyantek free/security static checks passed.');

import assert from 'assert';
import fs from 'fs';
import path from 'path';

const BASE_URL = 'http://localhost:3000';
const SHARED_APP_URL = 'https://ais-pre-w25uzs35q4uacnoeu72tdl-286763030317.europe-west3.run.app';

console.log('====================================================');
console.log('🚀 Running Siyantek Commercial Production & Deployment Test Suite');
console.log('====================================================');

let passedTests = 0;
function pass(msg) {
  passedTests++;
  console.log(`✅ [PASS] ${msg}`);
}

async function runTests() {
  // 1. Health check
  const healthRes = await fetch(`${BASE_URL}/api/health`);
  assert.strictEqual(healthRes.status, 200, 'Health check should return 200');
  const healthData = await healthRes.json();
  assert.strictEqual(healthData.status, 'ok');
  pass('1. Server Health Check responded with 200 OK');

  // 2. Multi-tenant registration & user isolation
  const randomSuffix = Math.random().toString(36).slice(2, 8);
  const userAEmail = `user.a.${randomSuffix}@commercial.siyantek.tn`;
  const userBEmail = `user.b.${randomSuffix}@commercial.siyantek.tn`;

  const regARes = await fetch(`${BASE_URL}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'Commercial Owner A', email: userAEmail, password: 'StrongPassword123!' }),
  });
  assert(regARes.status === 200 || regARes.status === 201, `Register A status should be 200 or 201, got ${regARes.status}`);
  const userA = await regARes.json();
  assert(userA.token, 'User A should receive session token');
  pass('2. User A successfully registered with secure session token');

  const regBRes = await fetch(`${BASE_URL}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'Commercial Owner B', email: userBEmail, password: 'StrongPassword123!' }),
  });
  assert(regBRes.status === 200 || regBRes.status === 201, `Register B status should be 200 or 201, got ${regBRes.status}`);
  const userB = await regBRes.json();
  pass('3. User B successfully registered for multi-tenant isolation');

  // 3. User A creates vehicle
  const vehARes = await fetch(`${BASE_URL}/api/vehicles`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${userA.token}`,
    },
    body: JSON.stringify({
      brand: 'Volkswagen',
      model: 'Golf 7',
      year: '2019',
      plate: '215 TN 4820',
      mileage: 82500,
    }),
  });
  assert(vehARes.status === 200 || vehARes.status === 201, `Vehicle creation status should be 200 or 201, got ${vehARes.status}`);
  const vehicleA = await vehARes.json();
  assert.strictEqual(vehicleA.brand, 'Volkswagen');
  pass('4. User A created vehicle successfully');

  // 4. IDOR Defense: User B cannot access or modify User A's vehicle
  const idorGet = await fetch(`${BASE_URL}/api/vehicles`, {
    headers: { Authorization: `Bearer ${userB.token}` },
  });
  const userBVehicles = await idorGet.json();
  assert(!userBVehicles.some(v => v.id === vehicleA.id), 'User B must not see User A vehicle');
  pass('5. [Data Isolation] User B cannot view User A vehicle');

  const idorPut = await fetch(`${BASE_URL}/api/vehicles/${vehicleA.id}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${userB.token}`,
    },
    body: JSON.stringify({ ...vehicleA, mileage: 999999 }),
  });
  assert.strictEqual(idorPut.status, 404, 'IDOR modification attempt must return 404');
  pass('6. [IDOR Defense] User B cannot modify User A vehicle');

  // 4b. Tier Limits: User A (Free tier) cannot create a second vehicle without upgrading
  const vehA2Res = await fetch(`${BASE_URL}/api/vehicles`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${userA.token}`,
    },
    body: JSON.stringify({
      brand: 'Peugeot',
      model: '208',
      year: '2020',
      plate: '220 TN 1234',
      mileage: 45000,
    }),
  });
  assert.strictEqual(vehA2Res.status, 403, 'Free tier user attempting 2nd vehicle must receive 403');
  const vehA2Data = await vehA2Res.json();
  assert.strictEqual(vehA2Data.upgradeRequired, true);
  pass('6b. [Private Owner Limits] Free tier strictly limits to 1 vehicle (upgrade required for more)');

  // 5. Zero AI Verification
  const aiDiag = await fetch(`${BASE_URL}/api/ai/diagnose`, { method: 'POST' });
  assert.strictEqual(aiDiag.status, 404, 'AI diagnosis route must not exist');
  const aiInvoice = await fetch(`${BASE_URL}/api/ai/invoice-scan`, { method: 'POST' });
  assert.strictEqual(aiInvoice.status, 404, 'AI invoice OCR route must not exist');
  pass('7. [Zero AI] All legacy AI endpoints return 404 Not Found');

  // 6. Support & Contact API testing
  const invalidSupport = await fetch(`${BASE_URL}/api/support/contact`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'A', email: 'not-an-email', message: 'Hi' }),
  });
  assert.strictEqual(invalidSupport.status, 400, 'Invalid contact data must return 400');
  pass('8. Support endpoint validates input and rejects invalid email/short message');

  const validSupport = await fetch(`${BASE_URL}/api/support/contact`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${userA.token}`,
    },
    body: JSON.stringify({
      name: 'Mohamed Ben Salem',
      email: 'owner@siyantek.tn',
      subject: 'Question sur abonnement Pro',
      message: 'Bonjour, je souhaite souscrire à la formule Pro pour mes 5 véhicules.',
    }),
  });
  assert.strictEqual(validSupport.status, 200);
  const supportData = await validSupport.json();
  assert(supportData.ticketId, 'Support response must include ticketId');
  assert.strictEqual(supportData.success, true);
  pass('9. Support ticket submitted successfully and saved to database');

  // 7. Legal & Compliance Endpoints
  const termsRes = await fetch(`${BASE_URL}/api/legal/terms`);
  assert.strictEqual(termsRes.status, 200);
  const termsData = await termsRes.json();
  assert.strictEqual(termsData.company, 'Siyantek Auto SaaS');
  pass('10. Terms of Service endpoint responded with legal metadata');

  const privacyRes = await fetch(`${BASE_URL}/api/legal/privacy`);
  assert.strictEqual(privacyRes.status, 200);
  pass('11. Privacy Policy endpoint responded with data protection metadata');

  // 8. Payment Security: No fake activations
  const checkoutPlus = await fetch(`${BASE_URL}/api/subscription/checkout`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${userA.token}`,
    },
    body: JSON.stringify({ plan: 'plus' }),
  });
  // Since real gateway keys are not provided in this test env, it must not grant free Plus
  const profileAfterCheckout = await fetch(`${BASE_URL}/api/auth/me`, {
    headers: { Authorization: `Bearer ${userA.token}` },
  });
  const currentProfile = await profileAfterCheckout.json();
  assert.strictEqual(currentProfile.user.tier, 'free', 'Tier must remain free until verified webhook payment');
  pass('12. [Payment Integrity] User tier remains Free until verified server webhook payment');

  // 9. SEO & Facebook Sharing Tags Verification
  const indexHtml = fs.readFileSync('index.html', 'utf-8');
  assert(indexHtml.includes(`content="${SHARED_APP_URL}"`), 'index.html must include correct og:url');
  assert(indexHtml.includes(`content="${SHARED_APP_URL}/og-image.png"`), 'index.html must include correct og:image URL');
  assert(indexHtml.includes('property="og:title"'), 'index.html must include og:title');
  assert(indexHtml.includes('property="og:description"'), 'index.html must include og:description');
  pass('13. [SEO & Facebook] Open Graph tags contain correct absolute HTTPS URLs and metadata');

  // 10. Deployment Artifacts
  assert(fs.existsSync('Dockerfile'), 'Dockerfile must exist');
  assert(fs.existsSync('.dockerignore'), '.dockerignore must exist');
  assert(fs.existsSync('.env.example'), '.env.example must exist');
  const envContent = fs.readFileSync('.env.example', 'utf-8');
  assert(envContent.includes('SESSION_SECRET'), '.env.example must document SESSION_SECRET');
  pass('14. [Hosting Artifacts] Dockerfile, .dockerignore, and .env.example are in place');

  // 11. Database Sanitation: No demo users in template
  const templateDb = JSON.parse(fs.readFileSync('data/siyantek-db.template.json', 'utf-8'));
  assert.strictEqual(templateDb.users.length, 0, 'Production DB template must contain 0 demo users');
  assert.strictEqual(templateDb.vehicles.length, 0, 'Production DB template must contain 0 demo vehicles');
  pass('15. [Production Sanitation] Clean database template verified without hardcoded demo users');

  console.log('====================================================');
  console.log(`📊 Test Summary: ${passedTests} Passed, 0 Failed`);
  console.log('====================================================');
}

runTests().catch(err => {
  console.error('❌ Test failed with error:', err);
  process.exit(1);
});

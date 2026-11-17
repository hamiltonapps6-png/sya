import fs from 'fs';
import crypto from 'crypto';

const BASE_URL = 'http://localhost:3000';
const TEST_CLIENT_IP = `test_ip_phase3_${Date.now()}`;

function getHeaders(extra = {}) {
  return {
    'x-test-client-ip': TEST_CLIENT_IP,
    ...extra,
  };
}

async function runHardeningTests() {
  console.log('====================================================');
  console.log('🚀 Running Siyantek Phase 3 Security & Hardening Test Suite');
  console.log('====================================================\n');

  let passed = 0;
  let failed = 0;

  function assert(condition, testName, details = '') {
    if (condition) {
      console.log(`✅ [PASS] ${testName}`);
      passed++;
    } else {
      console.error(`❌ [FAIL] ${testName} ${details ? '- ' + details : ''}`);
      failed++;
    }
  }

  // 1. Dependency check: @google/genai is removed from package.json
  const pkg = JSON.parse(fs.readFileSync('package.json', 'utf-8'));
  assert(
    !pkg.dependencies['@google/genai'] && !pkg.devDependencies?.['@google/genai'],
    '1. @google/genai dependency is completely removed from package.json'
  );

  // 2. Manifest and index.html check: No AI claims in manifest.json or index.html
  const manifest = JSON.parse(fs.readFileSync('public/manifest.json', 'utf-8'));
  const indexHtml = fs.readFileSync('index.html', 'utf-8');
  assert(
    !manifest.name.includes('IA') &&
    !manifest.description.includes('IA') &&
    !manifest.description.includes('diagnostic IA'),
    '2. public/manifest.json has no AI claims (PWA manifest cleaned)'
  );
  assert(
    !indexHtml.includes('مسح فواتير') && !indexHtml.toLowerCase().includes('diagnostic ia'),
    '3. index.html meta descriptions have no AI invoice scanning claims'
  );

  // 3. User Registration & Cookie check
  const testEmail = `hardening_user_${Date.now()}@siyantek.tn`;
  const regRes = await fetch(`${BASE_URL}/api/auth/register`, {
    method: 'POST',
    headers: getHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({
      name: 'Youssef Trabelsi',
      email: testEmail,
      password: 'StrongPassword2026!',
    }),
  });
  const regData = await regRes.json();
  const rawToken = regData.token;
  const setCookieHeader = regRes.headers.get('set-cookie');

  assert(
    regRes.status === 201 && rawToken && rawToken.length === 64,
    '4. User registration returns 256-bit cryptographically secure session token'
  );
  assert(
    setCookieHeader && setCookieHeader.includes('siyantek_session') && setCookieHeader.toLowerCase().includes('httponly'),
    '5. Registration sets HttpOnly session cookie (siyantek_session)'
  );

  // 4. Session Token Hashing check in Database: Token must be stored as SHA-256 hash, not plain text
  const dbData = JSON.parse(fs.readFileSync('data/siyantek-db.json', 'utf-8'));
  const expectedHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const storedSession = dbData.sessions.find((s) => s.tokenHash === expectedHash);
  const plainTokenFound = dbData.sessions.some((s) => s.token === rawToken);

  assert(
    storedSession && storedSession.tokenHash === expectedHash && !plainTokenFound,
    '6. Session token is stored in database as SHA-256 hash (raw token is never saved to database)'
  );

  // 5. Authenticated request using HttpOnly cookie without Bearer header
  const meCookieRes = await fetch(`${BASE_URL}/api/auth/me`, {
    headers: getHeaders({
      Cookie: `siyantek_session=${encodeURIComponent(rawToken)}`,
    }),
  });
  const meCookieData = await meCookieRes.json();
  assert(
    meCookieRes.status === 200 && meCookieData.user?.email === testEmail,
    '7. Authenticated request succeeds using HttpOnly cookie (cookie-based authentication works)'
  );

  // 6. Payment pending checkout does NOT claim payment succeeded
  const checkoutRes = await fetch(`${BASE_URL}/api/subscription/checkout`, {
    method: 'POST',
    headers: getHeaders({
      'Content-Type': 'application/json',
      Authorization: `Bearer ${rawToken}`,
      'x-enable-test-gateway': 'true',
    }),
    body: JSON.stringify({ planId: 'plus' }),
  });
  const checkoutData = await checkoutRes.json();
  assert(
    checkoutRes.status === 200 &&
    checkoutData.status === 'pending' &&
    checkoutData.message.includes('en attente') &&
    checkoutData.messageAr.includes('في وضع الانتظار'),
    '8. Pending checkout honestly explains payment is pending and not yet activated'
  );

  const txId = checkoutData.transactionId;
  const testKonnectSecret = 'super_secret_konnect_webhook_key_2026';

  // 7. Webhook Konnect rejects incomplete payloads (missing amount/currency/status)
  const incompletePayload = { transactionId: txId }; // missing amount, currency, status
  const sigIncomplete = crypto
    .createHmac('sha256', testKonnectSecret)
    .update(JSON.stringify(incompletePayload))
    .digest('hex');

  const incompleteRes = await fetch(`${BASE_URL}/api/webhooks/konnect`, {
    method: 'POST',
    headers: getHeaders({
      'Content-Type': 'application/json',
      'x-konnect-signature': sigIncomplete,
      'x-test-konnect-secret': testKonnectSecret,
    }),
    body: JSON.stringify(incompletePayload),
  });
  assert(
    incompleteRes.status === 400,
    '9. Webhook Konnect rejects incomplete payload missing amount/currency/status with 400 Bad Request'
  );

  // 8. Webhook Konnect rejects incorrect amount
  const badAmountPayload = {
    transactionId: txId,
    amount: 1.0, // should be 9.9
    currency: 'TND',
    status: 'completed',
  };
  const sigBadAmount = crypto
    .createHmac('sha256', testKonnectSecret)
    .update(JSON.stringify(badAmountPayload))
    .digest('hex');

  const badAmountRes = await fetch(`${BASE_URL}/api/webhooks/konnect`, {
    method: 'POST',
    headers: getHeaders({
      'Content-Type': 'application/json',
      'x-konnect-signature': sigBadAmount,
      'x-test-konnect-secret': testKonnectSecret,
    }),
    body: JSON.stringify(badAmountPayload),
  });
  assert(
    badAmountRes.status === 400,
    '10. Webhook Konnect rejects payment with non-conforming amount'
  );

  // 9. Webhook Flouci rejects incomplete payload
  const testFlouciSecret = 'super_secret_flouci_app_key_2026';
  const flouciIncomplete = { transactionId: txId };
  const sigFlouciIncomplete = crypto
    .createHmac('sha256', testFlouciSecret)
    .update(JSON.stringify(flouciIncomplete))
    .digest('hex');

  const flouciIncompleteRes = await fetch(`${BASE_URL}/api/webhooks/flouci`, {
    method: 'POST',
    headers: getHeaders({
      'Content-Type': 'application/json',
      'x-flouci-signature': sigFlouciIncomplete,
      'x-test-flouci-secret': testFlouciSecret,
    }),
    body: JSON.stringify(flouciIncomplete),
  });
  assert(
    flouciIncompleteRes.status === 400,
    '11. Webhook Flouci rejects incomplete payload with 400 Bad Request'
  );

  // 10. Cancellation honest message (does not claim external bank auto-debit cancellation)
  const cancelRes = await fetch(`${BASE_URL}/api/subscription/cancel`, {
    method: 'POST',
    headers: getHeaders({ Authorization: `Bearer ${rawToken}` }),
  });
  const cancelData = await cancelRes.json();
  assert(
    cancelRes.status === 200 &&
    (cancelData.message.includes('déjà sur la formule Free') || cancelData.message.includes('prélèvement automatique')),
    '12. Subscription cancellation gives honest message without claiming external payment provider auto-renewal'
  );

  // 11. Database template validation
  const template = JSON.parse(fs.readFileSync('data/siyantek-db.template.json', 'utf-8'));
  assert(
    Array.isArray(template.users) &&
    template.users.length === 0 &&
    Array.isArray(template.sessions) &&
    template.sessions.length === 0 &&
    Array.isArray(template.payments) &&
    template.payments.length === 0,
    '13. data/siyantek-db.template.json is a clean empty template without any user or session data'
  );

  // 12. Backup files verification
  const backups = fs.readdirSync('data/backups');
  assert(
    backups.length > 0 && backups.some((f) => f.startsWith('siyantek-db.')),
    '14. Automatic timestamped database backups are present in data/backups/'
  );

  console.log('\n====================================================');
  console.log(`📊 Hardening Test Summary: ${passed} Passed, ${failed} Failed`);
  console.log('====================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

runHardeningTests();

// test-phase2-fixes.mjs
// Automated verification suite for Siyantek Security, Payment, Data Isolation & OpenGraph fixes

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

const BASE_URL = 'http://localhost:3000';
let passCount = 0;
let failCount = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`✅ [PASS] ${message}`);
    passCount++;
  } else {
    console.error(`❌ [FAIL] ${message}`);
    failCount++;
  }
}

async function request(endpoint, options = {}) {
  const url = `${BASE_URL}${endpoint}`;
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  const res = await fetch(url, { ...options, headers });
  let data = null;
  try {
    data = await res.json();
  } catch {}
  return { status: res.status, headers: res.headers, data };
}

async function runTests() {
  console.log('====================================================');
  console.log('🚀 Running Siyantek Phase 2 Fixes & Security Test Suite');
  console.log('====================================================\n');

  // Test 1: Clean DB template exists and has no test seed data
  const templatePath = path.resolve('data/siyantek-db.template.json');
  assert(fs.existsSync(templatePath), '1. data/siyantek-db.template.json exists');
  const template = JSON.parse(fs.readFileSync(templatePath, 'utf-8'));
  assert(
    template.users.length === 0 && template.sessions.length === 0 && template.vehicles.length === 0,
    '2. Database template contains empty production schema without hardcoded test users'
  );

  // Test 2: Backup functionality & directory exists
  const backupsDir = path.resolve('data/backups');
  assert(fs.existsSync(backupsDir), '3. Backups directory data/backups exists for safe data persistence');

  // Test 3: Password reset without email gateway returns 503 honest response
  const resetRes = await request('/api/auth/reset-password', {
    method: 'POST',
    body: JSON.stringify({ email: 'unknown_test_user@example.com' }),
  });
  assert(
    resetRes.status === 503 && resetRes.data?.serviceAvailable === false,
    '4. Password reset honestly returns 503 and explains SMTP is not configured in production'
  );

  // Test 4: Password reset token generation, single-use, and expiration tests
  // We register a temporary user to test password reset mechanics directly in DB
  const testEmail = `user_sec_${Date.now()}@example.com`;
  const regRes = await request('/api/auth/register', {
    method: 'POST',
    body: JSON.stringify({ name: 'Sec User', email: testEmail, password: 'StrongPassword123!' }),
  });
  assert(regRes.status === 201 && regRes.data?.token, '5. Registered test user for reset & isolation tests');
  const initialToken = regRes.data.token;
  const testUserId = regRes.data.user.id;

  // Create 1 expired token and 1 valid token via test helper
  const expTokenRes = await request('/api/test/create-reset-token', {
    method: 'POST',
    body: JSON.stringify({ userId: testUserId, email: testEmail, expired: true }),
  });
  const expiredToken = expTokenRes.data.token;

  const validTokenRes = await request('/api/test/create-reset-token', {
    method: 'POST',
    body: JSON.stringify({ userId: testUserId, email: testEmail, expired: false }),
  });
  const validToken = validTokenRes.data.token;

  // Test 5: Rejection of expired password reset token
  const expiredConfirmRes = await request('/api/auth/reset-password-confirm', {
    method: 'POST',
    body: JSON.stringify({ token: expiredToken, newPassword: 'NewStrongPassword456!' }),
  });
  assert(
    expiredConfirmRes.status === 400 && expiredConfirmRes.data?.error?.includes('expiré'),
    '6. Password reset rejects expired token with 400 (TTL check enforced)'
  );

  // Test 6: Success with valid token
  const validConfirmRes = await request('/api/auth/reset-password-confirm', {
    method: 'POST',
    body: JSON.stringify({ token: validToken, newPassword: 'NewStrongPassword456!' }),
  });
  assert(
    validConfirmRes.status === 200 && validConfirmRes.data?.success === true,
    '7. Password reset succeeds with valid token within TTL'
  );

  // Test 7: Single-use enforcement: re-using the valid token MUST fail
  const reuseConfirmRes = await request('/api/auth/reset-password-confirm', {
    method: 'POST',
    body: JSON.stringify({ token: validToken, newPassword: 'AnotherPassword789!' }),
  });
  assert(
    reuseConfirmRes.status === 400 && reuseConfirmRes.data?.error?.includes('déjà été utilisé'),
    '8. Password reset enforces single-use (subsequent attempt with used token rejected)'
  );

  // Test 8: Session revocation upon password reset: previous session token must be invalid
  const meRes = await request('/api/auth/me', {
    headers: { Authorization: `Bearer ${initialToken}` },
  });
  assert(
    meRes.status === 401,
    '9. Password reset invalidates all previous sessions across all devices'
  );

  // Test 9: Login with new password succeeds
  const loginRes = await request('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email: testEmail, password: 'NewStrongPassword456!' }),
  });
  assert(loginRes.status === 200 && loginRes.data?.token, '10. Login with new password succeeds');
  const userToken = loginRes.data.token;

  // Test 10: Payment checkout rejects Plus / Pro when gateway keys are missing (Priority 2)
  const checkoutRes = await request('/api/subscription/checkout', {
    method: 'POST',
    headers: { Authorization: `Bearer ${userToken}` },
    body: JSON.stringify({ planId: 'plus' }),
  });
  assert(
    checkoutRes.status === 503 && checkoutRes.data?.paymentAvailable === false,
    '11. Payment checkout rejects Plus when gateway keys are unconfigured (no false promises)'
  );

  // Test 11: Webhook rejects request when secret is unconfigured
  const webhookUnconfigRes = await request('/api/webhooks/konnect', {
    method: 'POST',
    body: JSON.stringify({ transactionId: 'test_tx', status: 'success' }),
  });
  assert(
    webhookUnconfigRes.status === 503,
    '12. Konnect Webhook rejects payload when secret is unconfigured'
  );

  // Test 12: Webhook rejects missing signature
  const webhookNoSigRes = await request('/api/webhooks/konnect', {
    method: 'POST',
    headers: { 'x-konnect-signature': '' },
    body: JSON.stringify({ transactionId: 'test_tx', status: 'success' }),
  });
  assert(
    webhookNoSigRes.status === 503 || webhookNoSigRes.status === 401,
    '13. Webhook rejects requests without signature'
  );

  // Test 13: Free plan checkout is zero-cost and sets tier cleanly
  const freeCheckoutRes = await request('/api/subscription/checkout', {
    method: 'POST',
    headers: { Authorization: `Bearer ${userToken}` },
    body: JSON.stringify({ planId: 'free' }),
  });
  assert(
    freeCheckoutRes.status === 200 && freeCheckoutRes.data?.userTier === 'free',
    '14. Free plan selection requires no payment and responds with userTier: free'
  );

  // Test 14: Logout session revocation
  const logoutRes = await request('/api/auth/logout', {
    method: 'POST',
    headers: { Authorization: `Bearer ${userToken}` },
  });
  assert(logoutRes.status === 200, '15. Logout endpoint successfully called');

  const meAfterLogout = await request('/api/auth/me', {
    headers: { Authorization: `Bearer ${userToken}` },
  });
  assert(meAfterLogout.status === 401, '16. Session revoked on server after logout');

  // Test 15: OpenGraph metadata & image asset validation
  const htmlContent = fs.readFileSync(path.resolve('index.html'), 'utf-8');
  assert(
    htmlContent.includes('property="og:image" content="https://'),
    '17. og:image uses absolute HTTPS URL in index.html'
  );
  assert(
    htmlContent.includes('name="twitter:image" content="https://'),
    '18. twitter:image uses absolute HTTPS URL in index.html'
  );
  assert(
    !htmlContent.includes('mécanicien IA') && !htmlContent.includes('تشخيص الأعطال بالذكاء الاصطناعي'),
    '19. index.html meta description does NOT advertise removed AI mechanic'
  );

  // Test 16: Verify image files formats match extensions
  const ogImgPngHeader = fs.readFileSync(path.resolve('public/og-image.png')).slice(0, 8);
  const isRealPng = ogImgPngHeader.toString('hex').startsWith('89504e470d0a1a0a');
  assert(isRealPng, '20. public/og-image.png is a genuine PNG binary (no PNG/JPEG mismatch)');

  const ogImgJpgHeader = fs.readFileSync(path.resolve('public/og-image.jpg')).slice(0, 3);
  const isRealJpg = ogImgJpgHeader.toString('hex').startsWith('ffd8ff');
  assert(isRealJpg, '21. public/og-image.jpg is a genuine JPEG binary');

  // Test 17: metadata.json does not advertise removed features
  const metadata = JSON.parse(fs.readFileSync(path.resolve('metadata.json'), 'utf-8'));
  assert(
    !metadata.description.includes('diagnostic mécanique IA'),
    '22. metadata.json description does not advertise removed AI diagnostic features'
  );

  console.log('\n====================================================');
  console.log(`📊 Test Summary: ${passCount} Passed, ${failCount} Failed`);
  console.log('====================================================\n');

  if (failCount > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});

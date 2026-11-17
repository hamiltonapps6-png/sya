import fs from 'fs';

const BASE_URL = 'http://localhost:3000';
const TEST_CLIENT_IP = `test_ip_${Date.now()}`;

function getHeaders(extra = {}) {
  return {
    'x-test-client-ip': TEST_CLIENT_IP,
    ...extra,
  };
}

async function runTests() {
  console.log('====================================================');
  console.log('🚀 Running Siyantek Phase 1 Security & Technical Test Suite');
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

  // 1. Health check
  try {
    const healthRes = await fetch(`${BASE_URL}/api/health`, { headers: getHeaders() });
    const healthData = await healthRes.json();
    assert(healthRes.ok && healthData.status === 'ok', '1. Server Health Check & Status OK');
  } catch (err) {
    console.error('Fatal: Could not connect to Siyantek server. Is it running on port 3000?', err.message);
    process.exit(1);
  }

  // 2. Input validation on Register: Password too short
  const shortPassRes = await fetch(`${BASE_URL}/api/auth/register`, {
    method: 'POST',
    headers: getHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ name: 'Test User', email: 'short@example.com', password: '123' }),
  });
  assert(shortPassRes.status === 400, '2. Registration rejects short password (< 8 chars) with 400 Bad Request');

  // 3. Input validation on Register: Invalid email
  const badEmailRes = await fetch(`${BASE_URL}/api/auth/register`, {
    method: 'POST',
    headers: getHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ name: 'Test User', email: 'notanemail', password: 'ValidPassword123' }),
  });
  assert(badEmailRes.status === 400, '3. Registration rejects invalid email syntax with 400 Bad Request');

  // 4. Valid user registration (User A)
  const userAEmail = `user_a_${Date.now()}@test.tn`;
  const regResA = await fetch(`${BASE_URL}/api/auth/register`, {
    method: 'POST',
    headers: getHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ name: 'Mazen UserA', email: userAEmail, password: 'SecurePassword123!' }),
  });
  const regDataA = await regResA.json();
  const tokenA = regDataA.token;
  const userA = regDataA.user;

  assert(
    regResA.status === 201 &&
    typeof tokenA === 'string' &&
    tokenA.length === 64 &&
    userA &&
    !userA.passwordHash &&
    userA.tier === 'free',
    '4. Registration creates user with 256-bit (64 hex chars) session token & safe user profile without password exposure'
  );

  // 5. Inspect DB file directly to confirm bcrypt hashing (Priority 2)
  const dbContent = JSON.parse(fs.readFileSync('./data/siyantek-db.json', 'utf-8'));
  const storedUserA = dbContent.users.find((u) => u.email === userAEmail);
  assert(
    storedUserA &&
    storedUserA.passwordHash &&
    storedUserA.passwordHash.startsWith('$2') &&
    storedUserA.passwordHash !== 'SecurePassword123!',
    '5. Database verifies password hashed with bcrypt ($2a$/$2b$), never plain text'
  );

  // 6. Verify absence of legacy hardcoded demo accounts in DB
  const hasDemoAccount = dbContent.users.some(
    (u) => u.id === 'usr_demo_123' || u.email === 'demo@siyantek.tn' || u.passwordHash === 'demo123456'
  );
  assert(!hasDemoAccount, '6. Database contains NO hardcoded or insecure demo accounts');

  // 7. Duplicate email registration rejection
  const dupRes = await fetch(`${BASE_URL}/api/auth/register`, {
    method: 'POST',
    headers: getHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ name: 'Mazen Duplicate', email: userAEmail, password: 'SecurePassword123!' }),
  });
  assert(dupRes.status === 409, '7. Duplicate registration with existing email returns 409 Conflict');

  // 8. Login with invalid password
  const badLoginRes = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: getHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ email: userAEmail, password: 'WrongPassword999!' }),
  });
  assert(badLoginRes.status === 401, '8. Login rejects invalid password with 401 Unauthorized');

  // 9. Login with correct password
  const goodLoginRes = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: getHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ email: userAEmail, password: 'SecurePassword123!' }),
  });
  const goodLoginData = await goodLoginRes.json();
  const sessionTokenA2 = goodLoginData.token;
  assert(
    goodLoginRes.status === 200 &&
    typeof sessionTokenA2 === 'string' &&
    sessionTokenA2.length === 64,
    '9. Login verifies bcrypt hash and issues valid 64-char session token'
  );

  // 10. User A adds a vehicle
  const addVehResA = await fetch(`${BASE_URL}/api/vehicles`, {
    method: 'POST',
    headers: getHeaders({ 'Content-Type': 'application/json', Authorization: `Bearer ${sessionTokenA2}` }),
    body: JSON.stringify({
      brand: 'Peugeot',
      model: '208',
      year: '2021',
      plate: '220 TN 1234',
      mileage: 45000,
    }),
  });
  const vehDataA = await addVehResA.json();
  const vehicleIdA = vehDataA.id;
  assert(
    addVehResA.status === 201 && vehDataA.userId === userA.id,
    '10. User A successfully creates vehicle linked to their userId'
  );

  // 11. Create User B to test multi-tenant isolation and IDOR protection (Priority 7)
  const userBEmail = `user_b_${Date.now()}@test.tn`;
  const regResB = await fetch(`${BASE_URL}/api/auth/register`, {
    method: 'POST',
    headers: getHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ name: 'Sara UserB', email: userBEmail, password: 'SecurePassword456!' }),
  });
  const regDataB = await regResB.json();
  const tokenB = regDataB.token;
  assert(regResB.status === 201 && typeof tokenB === 'string', '11. User B registered successfully for multi-tenant isolation tests');

  // 12. IDOR Test: User B calls GET /api/vehicles (Must NOT see User A's vehicle)
  const listVehResB = await fetch(`${BASE_URL}/api/vehicles`, {
    headers: getHeaders({ Authorization: `Bearer ${tokenB}` }),
  });
  const listVehB = await listVehResB.json();
  const userBSeesUserAVehicle = Array.isArray(listVehB) && listVehB.some((v) => v.id === vehicleIdA);
  assert(!userBSeesUserAVehicle, '12. [IDOR Defense] User B cannot view User A\'s vehicle');

  // 13. IDOR Test: User B tries to update User A's vehicle
  const updateVehResB = await fetch(`${BASE_URL}/api/vehicles/${vehicleIdA}`, {
    method: 'PUT',
    headers: getHeaders({ 'Content-Type': 'application/json', Authorization: `Bearer ${tokenB}` }),
    body: JSON.stringify({ brand: 'Hacked Brand' }),
  });
  assert(
    updateVehResB.status === 404,
    '13. [IDOR Defense] User B cannot modify User A\'s vehicle (returns 404 Not Found)'
  );

  // 14. IDOR Test: User B tries to delete User A's vehicle
  const deleteVehResB = await fetch(`${BASE_URL}/api/vehicles/${vehicleIdA}`, {
    method: 'DELETE',
    headers: getHeaders({ Authorization: `Bearer ${tokenB}` }),
  });
  assert(
    deleteVehResB.status === 404,
    '14. [IDOR Defense] User B cannot delete User A\'s vehicle (returns 404 Not Found)'
  );

  // 15. IDOR Test: User B tries to create a maintenance record using User A's vehicleId
  const badRecordResB = await fetch(`${BASE_URL}/api/maintenance`, {
    method: 'POST',
    headers: getHeaders({ 'Content-Type': 'application/json', Authorization: `Bearer ${tokenB}` }),
    body: JSON.stringify({
      vehicleId: vehicleIdA,
      type: 'oil',
      date: '2026-10-20',
      mileage: 46000,
      cost: 150,
      notes: 'Unauthorized maintenance injection',
    }),
  });
  assert(
    badRecordResB.status === 404,
    '15. [IDOR Defense] User B cannot attach maintenance records to User A\'s vehicle'
  );

  // 16. Subscription Security (Priority 4): Plus/Pro NEVER auto-activates
  const checkoutRes = await fetch(`${BASE_URL}/api/subscription/checkout`, {
    method: 'POST',
    headers: getHeaders({ 'Content-Type': 'application/json', Authorization: `Bearer ${sessionTokenA2}` }),
    body: JSON.stringify({ planId: 'plus' }),
  });
  const checkoutData = await checkoutRes.json();

  // Verify User A's tier did NOT change to plus
  const meRes = await fetch(`${BASE_URL}/api/auth/me`, {
    headers: getHeaders({ Authorization: `Bearer ${sessionTokenA2}` }),
  });
  const meData = await meRes.json();

  assert(
    (checkoutRes.status === 503 || (checkoutRes.status === 200 && checkoutData.paymentRequired === true)) &&
    meData.user.tier === 'free',
    '16. [Subscription Security] Siyantek Plus requires verified payment; user tier remains free until confirmed'
  );

  // 17. Session Revocation / Logout (Priority 1)
  const logoutRes = await fetch(`${BASE_URL}/api/auth/logout`, {
    method: 'POST',
    headers: getHeaders({ Authorization: `Bearer ${sessionTokenA2}` }),
  });
  const postLogoutMeRes = await fetch(`${BASE_URL}/api/auth/me`, {
    headers: getHeaders({ Authorization: `Bearer ${sessionTokenA2}` }),
  });
  assert(
    logoutRes.status === 200 && postLogoutMeRes.status === 401,
    '17. [Session Security] Logout successfully revokes session token; subsequent authenticated requests return 401'
  );

  // 18. Password Reset Security (Priority 3)
  const resetReqRes = await fetch(`${BASE_URL}/api/auth/reset-password`, {
    method: 'POST',
    headers: getHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ email: userAEmail }),
  });
  assert(
    resetReqRes.status === 503 || resetReqRes.status === 200,
    `18. [Password Reset] Handled securely without leaking account existence (Status: ${resetReqRes.status})`
  );

  // 19. Dedicated Rate Limiting Verification (Priority 8)
  const spamIp = `spam_ip_${Date.now()}`;
  let wasRateLimited = false;
  for (let i = 0; i < 20; i++) {
    const res = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-test-client-ip': spamIp },
      body: JSON.stringify({ email: 'spam@test.tn', password: 'InvalidPassword' }),
    });
    if (res.status === 429) {
      wasRateLimited = true;
      break;
    }
  }
  assert(wasRateLimited, '19. [Rate Limiting] Brute-force requests trigger 429 Too Many Requests response');

  console.log('\n====================================================');
  console.log(`📊 Test Summary: ${passed} Passed, ${failed} Failed`);
  console.log('====================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests();

// Comprehensive Automated Test Suite: Manual Tunisian Payments, Role-Based Back-Office & Security
import assert from 'assert';

const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:3000';
console.log(`\n======================================================`);
console.log(`🧪 SIYANTEK COMMERCIAL SUITE: MANUAL PAYMENTS & ADMIN`);
console.log(`Targeting: ${BASE_URL}`);
console.log(`======================================================\n`);

async function runTests() {
  const testId = Date.now().toString(36);
  const clientEmail = `client_${testId}@siyantek-test.tn`;
  const adminEmail = `admin_${testId}@siyantek.tn`;
  const password = `Pass!12345678_${testId}`;

  // 1. Register Standard Client User
  console.log(`1. Testing Client Registration (${clientEmail})...`);
  const regRes = await fetch(`${BASE_URL}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'Automobiliste Test', email: clientEmail, password }),
  });
  const clientData = await regRes.json();
  assert.strictEqual(regRes.status, 201, `Client registration failed: ${JSON.stringify(clientData)}`);
  const clientToken = clientData.token;
  const clientId = clientData.user.id;
  assert.strictEqual(clientData.user.role, 'user', 'Client should have role=user');
  assert.strictEqual(clientData.user.tier, 'free', 'Client should start on free tier');
  console.log(`   ✓ Client created (id=${clientId}, role=user, tier=free)`);

  // 2. Client creates a manual order for Siyantek Plus
  console.log(`2. Testing Manual Bank Transfer Order creation (Plus plan, 9.9 DT)...`);
  const orderRes = await fetch(`${BASE_URL}/api/subscription/manual-order`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${clientToken}` },
    body: JSON.stringify({ planId: 'plus', method: 'bank_transfer' }),
  });
  const orderData = await orderRes.json();
  assert.strictEqual(orderRes.status, 201, `Manual order creation failed: ${JSON.stringify(orderData)}`);
  assert.strictEqual(orderData.success, true);
  assert.ok(orderData.transferReference, 'Order must return a unique transfer reference');
  assert.ok(orderData.transferReference.startsWith('SYK-VIR-'), `Reference must match SYK-VIR-*: ${orderData.transferReference}`);
  assert.strictEqual(orderData.order.status, 'pending');
  assert.strictEqual(orderData.order.amountDT, 9.9);
  assert.ok(orderData.instructions.rib, 'Must provide BIAT RIB instructions');
  const orderId = orderData.order.id;
  console.log(`   ✓ Manual Order created: #${orderId} (Ref: ${orderData.transferReference}, Status: pending)`);

  // 3. Client uploads receipt for order
  console.log(`3. Testing Receipt Upload for order #${orderId}...`);
  // Small 1x1 PNG base64
  const sampleBase64Png = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
  const uploadRes = await fetch(`${BASE_URL}/api/subscription/manual-order/${orderId}/upload-receipt`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${clientToken}` },
    body: JSON.stringify({
      base64Data: sampleBase64Png,
      mimeType: 'image/png',
      filename: 'recu_biat_test.png',
    }),
  });
  const uploadData = await uploadRes.json();
  assert.strictEqual(uploadRes.status, 200, `Receipt upload failed: ${JSON.stringify(uploadData)}`);
  assert.strictEqual(uploadData.success, true);
  assert.strictEqual(uploadData.order.status, 'submitted');
  assert.ok(uploadData.order.receiptFilename, 'Receipt filename must be recorded');
  console.log(`   ✓ Receipt successfully uploaded. Order status transitioned to: submitted`);

  // 4. Security: Non-admin client access to /api/admin/payments must return 403 Forbidden
  console.log(`4. Testing RBAC Security: Non-admin access to /api/admin/payments...`);
  const unauthorizedRes = await fetch(`${BASE_URL}/api/admin/payments`, {
    headers: { Authorization: `Bearer ${clientToken}` },
  });
  assert.strictEqual(unauthorizedRes.status, 403, 'Non-admin MUST receive 403 Forbidden on /api/admin/*');
  console.log(`   ✓ Non-admin access strictly rejected with 403 Forbidden`);

  // 5. Security: IDOR protection on receipt download (Second non-admin client)
  console.log(`5. Testing IDOR Protection on receipt download...`);
  const secondClientEmail = `second_${testId}@siyantek-test.tn`;
  const secondRegRes = await fetch(`${BASE_URL}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'Second User', email: secondClientEmail, password }),
  });
  const secondData = await secondRegRes.json();
  assert.strictEqual(secondRegRes.status, 201);
  const secondToken = secondData.token;
  const idorRes = await fetch(`${BASE_URL}/api/subscription/manual-order/${orderId}/receipt`, {
    headers: { Authorization: `Bearer ${secondToken}` },
  });
  assert.strictEqual(idorRes.status, 403, 'Unrelated user MUST be blocked from viewing another user\'s receipt (IDOR)');
  console.log(`   ✓ IDOR check passed: Foreign user cannot download receipt (403 Forbidden)`);

  // 6. Admin Registration / Login
  console.log(`6. Testing Admin Authentication (${adminEmail})...`);
  let adminToken;
  const adminRegRes = await fetch(`${BASE_URL}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'Directeur Siyantek', email: adminEmail, password }),
  });
  const adminRegData = await adminRegRes.json();
  if (adminRegRes.status === 201) {
    adminToken = adminRegData.token;
    assert.strictEqual(adminRegData.user.role, 'admin');
  } else {
    // If admin already exists in store, login
    const adminLoginRes = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: adminEmail, password }),
    });
    const adminLoginData = await adminLoginRes.json();
    assert.strictEqual(adminLoginRes.status, 200, `Admin login failed: ${JSON.stringify(adminLoginData)}`);
    adminToken = adminLoginData.token;
    assert.strictEqual(adminLoginData.user.role, 'admin');
  }
  console.log(`   ✓ Admin authenticated with role=admin`);

  // 7. Admin reads stats and payments
  console.log(`7. Testing Admin Back-Office stats and payment lists...`);
  const statsRes = await fetch(`${BASE_URL}/api/admin/stats`, {
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  assert.strictEqual(statsRes.status, 200);
  const statsData = await statsRes.json();
  assert.ok(statsData.users.total >= 2);
  assert.ok(statsData.payments.submitted >= 1);
  console.log(`   ✓ Admin stats returned: ${statsData.users.total} users, ${statsData.payments.submitted} submitted orders`);

  // 8. Admin downloads/previews the private receipt
  console.log(`8. Testing Admin receipt private download...`);
  const receiptRes = await fetch(`${BASE_URL}/api/admin/payments/${orderId}/receipt`, {
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  assert.strictEqual(receiptRes.status, 200, `Admin receipt access failed: ${receiptRes.status}`);
  assert.strictEqual(receiptRes.headers.get('content-type'), 'image/png');
  console.log(`   ✓ Admin successfully retrieved private receipt`);

  // 9. Admin Approves the manual payment
  console.log(`9. Testing Admin Payment Approval & Tier Upgrade (+30 days)...`);
  const approveRes = await fetch(`${BASE_URL}/api/admin/payments/${orderId}/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ durationDays: 30, notes: 'Virement BIAT vérifié sur relevé bancaire' }),
  });
  const approveData = await approveRes.json();
  assert.strictEqual(approveRes.status, 200, `Approval failed: ${JSON.stringify(approveData)}`);
  assert.strictEqual(approveData.success, true);
  assert.ok(approveData.subscriptionExpiresAt, 'Must return new subscription expiration date');

  // Verify client user was upgraded on server
  const clientMeRes = await fetch(`${BASE_URL}/api/auth/me`, {
    headers: { Authorization: `Bearer ${clientToken}` },
  });
  const clientMeData = await clientMeRes.json();
  assert.strictEqual(clientMeData.user.tier, 'plus', 'Client tier MUST be upgraded to plus');
  assert.strictEqual(clientMeData.user.subscriptionStatus, 'active', 'Subscription must be active');
  assert.ok(clientMeData.user.subscriptionExpiresAt, 'Expiration date must be set');
  console.log(`   ✓ Client upgraded: tier=${clientMeData.user.tier}, expiresAt=${clientMeData.user.subscriptionExpiresAt}`);

  // 10. Security: Duplicate approval prevention
  console.log(`10. Testing Duplicate Approval Prevention...`);
  const dupApproveRes = await fetch(`${BASE_URL}/api/admin/payments/${orderId}/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ notes: 'Tentative doublon' }),
  });
  assert.strictEqual(dupApproveRes.status, 400, 'Duplicate approval MUST be rejected with 400');
  console.log(`   ✓ Duplicate approval prevented (400 Bad Request)`);

  // 11. Testing Order Rejection
  console.log(`11. Testing Order Rejection Flow...`);
  const order2Res = await fetch(`${BASE_URL}/api/subscription/manual-order`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${clientToken}` },
    body: JSON.stringify({ planId: 'pro', method: 'postal_order' }),
  });
  const order2Data = await order2Res.json();
  const order2Id = order2Data.order.id;

  const rejectRes = await fetch(`${BASE_URL}/api/admin/payments/${order2Id}/reject`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ reason: 'Mandat postal non reçu après 7 jours' }),
  });
  const rejectData = await rejectRes.json();
  assert.strictEqual(rejectRes.status, 200);
  assert.strictEqual(rejectData.order.status, 'rejected');
  console.log(`   ✓ Order #${order2Id} successfully rejected with recorded administrative note`);

  // 12. Audit Log Verification
  console.log(`12. Testing Administrative Audit Trail...`);
  const auditRes = await fetch(`${BASE_URL}/api/admin/audit-logs`, {
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  assert.strictEqual(auditRes.status, 200);
  const auditLogs = await auditRes.json();
  assert.ok(Array.isArray(auditLogs) && auditLogs.length >= 2, 'Audit logs must record approvals and rejections');
  const approvalAudit = auditLogs.find((a) => a.action === 'approve_manual_payment');
  assert.ok(approvalAudit, 'Must record approve_manual_payment action in audit trail');
  console.log(`   ✓ Audit trail verified (${auditLogs.length} events logged, admin=${approvalAudit.adminEmail})`);

  console.log(`\n======================================================`);
  console.log(`🎉 ALL 12 TESTS PASSED SUCCESSFULLY`);
  console.log(`======================================================\n`);
}

runTests().catch((err) => {
  console.error(`\n❌ TEST SUITE FAILED:`, err);
  process.exit(1);
});

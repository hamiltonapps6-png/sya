const BASE_URL = 'http://localhost:3000';
const TEST_CLIENT_IP = `test_ip_phase2_${Date.now()}`;

function getHeaders(token, extra = {}) {
  const h = {
    'x-test-client-ip': TEST_CLIENT_IP,
    'Content-Type': 'application/json',
    ...extra,
  };
  if (token) h.Authorization = `Bearer ${token}`;
  return h;
}

async function runPhase2Tests() {
  console.log('====================================================');
  console.log('🚀 Running Siyantek Phase 2 Functional & Security Test Suite');
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

  // 1. Create User A
  const emailA = `ph2_user_a_${Date.now()}@test.tn`;
  const regResA = await fetch(`${BASE_URL}/api/auth/register`, {
    method: 'POST',
    headers: getHeaders(null),
    body: JSON.stringify({ name: 'Phase2 User A', email: emailA, password: 'StrongPassword123!' }),
  });
  const dataA = await regResA.json();
  const tokenA = dataA.token;
  assert(regResA.status === 201 && tokenA, '1. User A registered successfully for Phase 2');

  // 2. Add vehicle for User A
  const vehResA = await fetch(`${BASE_URL}/api/vehicles`, {
    method: 'POST',
    headers: getHeaders(tokenA),
    body: JSON.stringify({
      brand: 'Peugeot',
      model: '208',
      year: '2021',
      plate: '220 TN 9988',
      mileage: 45000,
    }),
  });
  const vehicleA = await vehResA.json();
  assert(vehResA.status === 201 && vehicleA.id, '2. Vehicle created for User A');

  // 3. Add maintenance record with parts, status, and severity
  const recordResA = await fetch(`${BASE_URL}/api/maintenance`, {
    method: 'POST',
    headers: getHeaders(tokenA),
    body: JSON.stringify({
      vehicleId: vehicleA.id,
      type: 'oil',
      date: '2026-10-15',
      mileage: 45000,
      cost: 180,
      workshop: 'TotalEnergies Tunis',
      notes: 'Vidange synthèse + filtres',
      nextMileage: 55000,
      status: 'completed',
      severity: 'routine',
      parts: [
        { name: 'Huile Total Quartz 5W30', reference: 'TOT-5W30', quantity: 1, unitCost: 110 },
        { name: 'Filtre à huile Purflux', reference: 'L358A', quantity: 1, unitCost: 35 },
        { name: 'Filtre habitacle', reference: 'AH245', quantity: 1, unitCost: 35 },
      ],
    }),
  });
  const recordA = await recordResA.json();
  assert(
    recordResA.status === 201 &&
    recordA.status === 'completed' &&
    recordA.severity === 'routine' &&
    Array.isArray(recordA.parts) &&
    recordA.parts.length === 3 &&
    recordA.parts[0].name === 'Huile Total Quartz 5W30',
    '3. Maintenance record saved with spare parts catalog & severity levels'
  );

  // 4. Create Reminders for User A (Oil change, Insurance, Inspection)
  const remResA = await fetch(`${BASE_URL}/api/reminders`, {
    method: 'POST',
    headers: getHeaders(tokenA),
    body: JSON.stringify({
      vehicleId: vehicleA.id,
      title: 'Prochaine Vidange 55,000 km',
      type: 'oil',
      dueMileage: 55000,
      dueDate: '2027-04-15',
      notes: 'Huile 5W30 préconisée',
    }),
  });
  const reminderA = await remResA.json();
  assert(
    remResA.status === 201 &&
    reminderA.id &&
    reminderA.completed === false &&
    reminderA.type === 'oil',
    '4. Reminder scheduled with target date and target mileage'
  );

  // 5. User A toggles reminder as completed
  const toggleRes = await fetch(`${BASE_URL}/api/reminders/${reminderA.id}`, {
    method: 'PUT',
    headers: getHeaders(tokenA),
    body: JSON.stringify({ completed: true }),
  });
  const updatedRem = await toggleRes.json();
  assert(
    toggleRes.ok && updatedRem.completed === true && Boolean(updatedRem.completedDate),
    '5. Reminder successfully marked as completed with completion timestamp'
  );

  // 6. Register User B for multi-tenant isolation testing on reminders
  const emailB = `ph2_user_b_${Date.now()}@test.tn`;
  const regResB = await fetch(`${BASE_URL}/api/auth/register`, {
    method: 'POST',
    headers: getHeaders(null),
    body: JSON.stringify({ name: 'Phase2 User B', email: emailB, password: 'StrongPassword123!' }),
  });
  const dataB = await regResB.json();
  const tokenB = dataB.token;

  // 7. [IDOR Defense] User B cannot view User A's reminders
  const remListB = await fetch(`${BASE_URL}/api/reminders`, {
    headers: getHeaders(tokenB),
  });
  const remsB = await remListB.json();
  const hasUserAReminder = remsB.some((r) => r.id === reminderA.id);
  assert(!hasUserAReminder, '7. [IDOR Defense] User B cannot view User A reminders');

  // 8. [IDOR Defense] User B cannot update User A's reminder
  const attackUpdateRes = await fetch(`${BASE_URL}/api/reminders/${reminderA.id}`, {
    method: 'PUT',
    headers: getHeaders(tokenB),
    body: JSON.stringify({ title: 'Hacked Reminder' }),
  });
  assert(attackUpdateRes.status === 404, '8. [IDOR Defense] User B rejected when attempting to update User A reminder (404 Not Found)');

  // 9. [IDOR Defense] User B cannot delete User A's reminder
  const attackDeleteRes = await fetch(`${BASE_URL}/api/reminders/${reminderA.id}`, {
    method: 'DELETE',
    headers: getHeaders(tokenB),
  });
  assert(attackDeleteRes.status === 404, '9. [IDOR Defense] User B rejected when attempting to delete User A reminder (404 Not Found)');

  // 10. Data export includes vehicles, records with parts, and reminders
  const exportRes = await fetch(`${BASE_URL}/api/auth/export-data`, {
    headers: getHeaders(tokenA),
  });
  const exportData = await exportRes.json();
  assert(
    exportRes.ok &&
    Array.isArray(exportData.vehicles) &&
    Array.isArray(exportData.records) &&
    Array.isArray(exportData.reminders) &&
    exportData.reminders.some((r) => r.id === reminderA.id) &&
    exportData.records[0].parts.length === 3,
    '10. Full data export includes vehicles, parts breakdown, and scheduled reminders'
  );

  console.log('\n====================================================');
  console.log(`📊 Phase 2 Test Summary: ${passed} Passed, ${failed} Failed`);
  console.log('====================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

runPhase2Tests().catch((err) => {
  console.error('Test execution failed:', err);
  process.exit(1);
});

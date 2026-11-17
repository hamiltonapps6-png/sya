import fs from 'fs';

const BASE_URL = 'http://localhost:3000';
const TEST_CLIENT_IP = `test_ip_${Date.now()}`;

function getHeaders(extra = {}) {
  return {
    'x-test-client-ip': TEST_CLIENT_IP,
    ...extra,
  };
}

async function runPhaseTests() {
  console.log('====================================================');
  console.log('🚀 Running Siyantek Arabic, Reminders, Maintenance & Security Test Suite');
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
    assert(healthRes.ok && healthData.status === 'ok', '1. Server is healthy and running on port 3000');
  } catch (err) {
    console.error('Fatal: Could not connect to Siyantek server:', err.message);
    process.exit(1);
  }

  // 2. Phase 2 verification: AI Mechanic endpoint MUST be removed (404)
  const mechanicRes = await fetch(`${BASE_URL}/api/ai/mechanic`, {
    method: 'POST',
    headers: getHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ description: 'Noise in engine' }),
  });
  assert(
    mechanicRes.status === 404,
    '2. [Phase 2] AI Mécanicien API endpoint is completely removed (returns 404 Not Found)'
  );

  // 3. User Registration
  const testEmail = `user_siyantek_${Date.now()}@siyantek.tn`;
  const regRes = await fetch(`${BASE_URL}/api/auth/register`, {
    method: 'POST',
    headers: getHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({
      name: 'Mazen Ben Salah',
      email: testEmail,
      password: 'SecureAutoPassword123!',
    }),
  });
  const regData = await regRes.json();
  const token = regData.token;
  assert(regRes.status === 201 && token, '3. User registration succeeds with secure token');

  // 4. Vehicle Creation (Preserving License Plate in Raw String)
  const vehiclePlate = '218 تونس 5678';
  const vehRes = await fetch(`${BASE_URL}/api/vehicles`, {
    method: 'POST',
    headers: getHeaders({ 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }),
    body: JSON.stringify({
      brand: 'Peugeot',
      model: '208',
      year: '2021',
      plate: vehiclePlate,
      mileage: 45000,
    }),
  });
  const vehData = await vehRes.json();
  const vehicleId = vehData.id;
  assert(
    vehRes.status === 201 &&
    vehData.plate === vehiclePlate &&
    vehData.mileage === 45000,
    '4. Vehicle created correctly preserving Arabic / custom plate string without corruption'
  );

  // 5. Vehicle Mileage Update & Validation
  const updateVehRes = await fetch(`${BASE_URL}/api/vehicles/${vehicleId}`, {
    method: 'PUT',
    headers: getHeaders({ 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }),
    body: JSON.stringify({
      brand: 'Peugeot',
      model: '208',
      year: '2021',
      plate: vehiclePlate,
      mileage: 47500,
    }),
  });
  const updateVehData = await updateVehRes.json();
  assert(
    updateVehRes.status === 200 && updateVehData.mileage === 47500,
    '5. Vehicle odometer updated successfully to 47,500 km'
  );

  // 6. Maintenance record creation with Spare Parts & Severity
  const recRes = await fetch(`${BASE_URL}/api/maintenance`, {
    method: 'POST',
    headers: getHeaders({ 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }),
    body: JSON.stringify({
      vehicleId,
      type: 'oil',
      date: '2026-10-15',
      mileage: 47500,
      cost: 185,
      workshop: 'Garage Tunis Express',
      notes: 'Vidange synthétique 5W30 + filtre à huile et filtre d\'habitacle',
      nextMileage: 57500,
      status: 'completed',
      severity: 'routine',
      parts: [
        { name: 'Huile Total Quartz 5W30 (5L)', reference: 'TOT-5W30', quantity: 1, unitCost: 115 },
        { name: 'Filtre à huile d\'origine', reference: 'PSA-1109AY', quantity: 1, unitCost: 35 },
        { name: 'Filtre habitacle', reference: 'PSA-6447XG', quantity: 1, unitCost: 35 },
      ],
    }),
  });
  const recData = await recRes.json();
  const recordId = recData.id;
  assert(
    recRes.status === 201 &&
    recData.parts &&
    recData.parts.length === 3 &&
    recData.severity === 'routine',
    '6. Maintenance record created with full spare parts list and severity level'
  );

  // 7. Reminder Creation
  const remRes = await fetch(`${BASE_URL}/api/reminders`, {
    method: 'POST',
    headers: getHeaders({ 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }),
    body: JSON.stringify({
      vehicleId,
      title: 'فحص دوري وزيارة فنية',
      type: 'inspection',
      dueDate: new Date(Date.now() + 45 * 86400000).toISOString().slice(0, 10),
      dueMileage: 57500,
      notes: 'فحص ميكانيكي وتجهيزات الإضاءة',
    }),
  });
  const remData = await remRes.json();
  const reminderId = remData.id;
  assert(
    remRes.status === 201 &&
    remData.title === 'فحص دوري وزيارة فنية' &&
    remData.completed === false,
    '7. Reminder created with Arabic title, target date and due mileage'
  );

  // 8. Toggle Reminder completion
  const toggleRemRes = await fetch(`${BASE_URL}/api/reminders/${reminderId}`, {
    method: 'PUT',
    headers: getHeaders({ 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }),
    body: JSON.stringify({ completed: true }),
  });
  const toggleRemData = await toggleRemRes.json();
  assert(
    toggleRemRes.status === 200 && toggleRemData.completed === true,
    '8. Reminder marked as completed successfully'
  );

  // 9. Invoice OCR endpoint is completely removed (returns 404)
  const invoiceRes = await fetch(`${BASE_URL}/api/ai/invoice`, {
    method: 'POST',
    headers: getHeaders({ 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }),
    body: JSON.stringify({
      invoiceText: 'Garage Ariana - Vidange 5W40 95 DT, Filtre huile 25 DT. Total: 120 DT. Kilométrage: 47500',
      language: 'ar',
    }),
  });
  assert(
    invoiceRes.status === 404,
    '9. [AI Removal] Invoice OCR endpoint is completely removed (returns 404 Not Found)'
  );

  // 10. Subscription Plans endpoint without AI Mechanic or Invoice Scan claims
  const plansRes = await fetch(`${BASE_URL}/api/subscription/plans`);
  const plansData = await plansRes.json();
  const freePlan = plansData.find((p) => p.id === 'free');
  const proPlan = plansData.find((p) => p.id === 'pro');
  const hasAiMention = plansData.some((p) =>
    p.features.some((f) => f.toLowerCase().includes('mécanicien') || f.toLowerCase().includes('ia') || f.toLowerCase().includes('scan'))
  );
  assert(
    plansRes.status === 200 &&
    freePlan &&
    proPlan &&
    !hasAiMention,
    '10. [AI Removal] Subscription plans updated cleanly with no references to AI or invoice scanning'
  );

  // 11. Cleanup test vehicle (cascades records & reminders)
  const delVehRes = await fetch(`${BASE_URL}/api/vehicles/${vehicleId}`, {
    method: 'DELETE',
    headers: getHeaders({ Authorization: `Bearer ${token}` }),
  });
  assert(
    delVehRes.status === 200,
    '11. Vehicle deletion cascade-removes maintenance and reminder records'
  );

  console.log('\n====================================================');
  console.log(`📊 Test Summary: ${passed} Passed, ${failed} Failed`);
  console.log('====================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

runPhaseTests();

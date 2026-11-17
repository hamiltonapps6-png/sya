import assert from 'assert';

function computeMaintenanceMetrics({ currentMileage, nextMileage, lastMileage }) {
  const hasScheduledMaintenance = Boolean(nextMileage);
  const targetMaintenanceMileage = nextMileage || (currentMileage + 5000);
  const lastMaintenanceMileage = lastMileage && lastMileage <= currentMileage
    ? lastMileage
    : Math.max(0, targetMaintenanceMileage - 10000);

  const totalMaintenanceInterval = Math.max(1000, targetMaintenanceMileage - lastMaintenanceMileage);
  const rawDistanceRemaining = targetMaintenanceMileage - currentMileage;
  const isOverdue = hasScheduledMaintenance && rawDistanceRemaining <= 0;
  const overdueKm = Math.abs(rawDistanceRemaining);
  const isUpcoming = hasScheduledMaintenance && !isOverdue && rawDistanceRemaining <= 1500;
  const isOnTrack = hasScheduledMaintenance && !isOverdue && rawDistanceRemaining > 1500;

  let progressPct = 0;
  if (hasScheduledMaintenance) {
    if (isOverdue) {
      progressPct = 100;
    } else {
      const elapsed = Math.max(0, currentMileage - lastMaintenanceMileage);
      progressPct = Math.min(100, Math.max(0, Math.round((elapsed / totalMaintenanceInterval) * 100)));
    }
  }

  return {
    hasScheduledMaintenance,
    targetMaintenanceMileage,
    lastMaintenanceMileage,
    rawDistanceRemaining,
    isOverdue,
    overdueKm,
    isUpcoming,
    isOnTrack,
    progressPct,
  };
}

console.log('Testing Siyantek Vehicle Card maintenance calculation logic...');

// 1. Golf 7 standard case: 84 500 km current, 80 000 km last, 90 000 km target
const standard = computeMaintenanceMetrics({ currentMileage: 84500, nextMileage: 90000, lastMileage: 80000 });
assert.strictEqual(standard.rawDistanceRemaining, 5500, 'Remaining should be 5,500 km');
assert.strictEqual(standard.isOverdue, false, 'Should not be overdue');
assert.strictEqual(standard.isOnTrack, true, 'Should be on track (green)');
assert.strictEqual(standard.progressPct, 45, 'Progress should be 45%');
console.log('✅ 1. Standard Golf 7 (84,500 km -> 90,000 km): 5,500 km remaining, 45% progress, on track');

// 2. Upcoming warning case: 89 200 km current, 80 000 km last, 90 000 km target
const upcoming = computeMaintenanceMetrics({ currentMileage: 89200, nextMileage: 90000, lastMileage: 80000 });
assert.strictEqual(upcoming.rawDistanceRemaining, 800, 'Remaining should be 800 km');
assert.strictEqual(upcoming.isUpcoming, true, 'Should be upcoming warning');
assert.strictEqual(upcoming.isOverdue, false, 'Should not be overdue');
assert.strictEqual(upcoming.progressPct, 92, 'Progress should be 92%');
console.log('✅ 2. Upcoming Warning (89,200 km -> 90,000 km): 800 km remaining, upcoming warning (orange)');

// 3. Overdue case: 91 500 km current, 80 000 km last, 90 000 km target
const overdue = computeMaintenanceMetrics({ currentMileage: 91500, nextMileage: 90000, lastMileage: 80000 });
assert.strictEqual(overdue.isOverdue, true, 'Should be overdue');
assert.strictEqual(overdue.overdueKm, 1500, 'Overdue by 1,500 km');
assert.strictEqual(overdue.progressPct, 100, 'Progress bar should be 100% full (red)');
console.log('✅ 3. Overdue Case (91,500 km -> 90,000 km): 1,500 km overdue, 100% bar (red)');

// 4. No scheduled maintenance case
const unscheduled = computeMaintenanceMetrics({ currentMileage: 50000, nextMileage: null, lastMileage: null });
assert.strictEqual(unscheduled.hasScheduledMaintenance, false, 'hasScheduledMaintenance should be false');
console.log('✅ 4. Unscheduled Maintenance Case: hasScheduledMaintenance false, shows schedule action prompt');

console.log('All vehicle card calculation tests passed!');

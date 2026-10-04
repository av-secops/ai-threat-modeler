import assert from 'node:assert/strict';
import test from 'node:test';
import { dashboardHash, dashboardLocation, dashboardQuery, filterDefaults } from '../src/utils/productDashboard.js';

test('dashboard navigation round-trips scope without accepting arbitrary keys', () => {
  const filters = { ...filterDefaults, release_id: 'release & one', search: 'customer + data', archived: true };
  const hash = dashboardHash('product/one', filters);
  assert.deepEqual(dashboardLocation(hash), { productId: 'product/one', filters });
  assert.deepEqual(dashboardLocation('#security-portfolio'), { portfolio: true });
  assert.equal(dashboardLocation('#something-else'), null);
  assert.equal(dashboardLocation('#product-dashboard?search=x'), null);
  assert.equal(dashboardLocation(hash + '&unexpected=true').filters.unexpected, undefined);
  assert.equal(new URLSearchParams(dashboardQuery(filters, { page: 2 })).get('page'), '2');
});

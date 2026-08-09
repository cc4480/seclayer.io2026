// In-memory data for the Tier 2 fixture. No SQLite needed here (no SQLi vuln
// in this tier) — plain JS objects are enough and keep the vulnerable routes
// easy to read. Reseeded fresh every process start; nothing persists.
const USERS = {
  alice: { username: 'alice', password: 'AlicePass!2026', role: 'user', email: 'alice@tier2.test' },
  bob: { username: 'bob', password: 'BobPass!2026', role: 'user', email: 'bob@tier2.test' },
  admin: { username: 'admin', password: 'AdminPass!2026', role: 'admin', email: 'admin@tier2.test' },
};

const PRODUCTS = {
  1: { id: 1, name: 'Widget', price: 99.99 },
};

const DOCUMENTS = {
  1001: { id: 1001, owner: 'alice', title: 'Alice Project Plan', content: 'Confidential — alice-only planning notes.' },
  1002: { id: 1002, owner: 'bob', title: 'Bob Project Plan', content: 'Confidential — bob-only planning notes.' },
};

// Reset before each test run so /api/transfer's balance is repeatable. A
// SINGLE stable object, mutated in place (never reassigned) — every module
// that destructures ACCOUNTS at require-time keeps a reference to the same
// object, so resetAccounts()'s changes are actually visible everywhere.
const ACCOUNTS = { 1: { id: 1, balance: 100 } };
function resetAccounts() {
  ACCOUNTS[1].balance = 100;
}

module.exports = { USERS, PRODUCTS, DOCUMENTS, ACCOUNTS, resetAccounts };

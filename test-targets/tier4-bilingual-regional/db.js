// In-memory SQLite (better-sqlite3), reseeded fresh on every process start —
// this is a throwaway benchmark fixture, not a real app. Passwords stored
// PLAINTEXT on purpose (not what this tier's vulnerabilities are about).
const Database = require('better-sqlite3');

const db = new Database(':memory:');

db.exec(`
  CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    phone TEXT
  );
  CREATE TABLE password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    token TEXT NOT NULL,
    locale TEXT NOT NULL,
    expires INTEGER NOT NULL
  );
  CREATE TABLE sms_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT NOT NULL,
    code TEXT NOT NULL,
    expires INTEGER NOT NULL
  );
  CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    name_en TEXT NOT NULL,
    name_es TEXT NOT NULL,
    price_usd REAL NOT NULL,
    price_mxn REAL NOT NULL
  );
  CREATE TABLE merchants (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    estado TEXT NOT NULL,
    email TEXT NOT NULL
  );
`);

db.prepare('INSERT INTO users (id, email, password, role, phone) VALUES (?, ?, ?, ?, ?)')
  .run(1, 'admin@laredo-merchant.local', 'AdminPass!2026', 'admin', '+525218001234');
db.prepare('INSERT INTO users (id, email, password, role, phone) VALUES (?, ?, ?, ?, ?)')
  .run(2, 'carlos@laredo-merchant.local', 'CarlosPass!2026', 'user', '+525218005678');

db.prepare('INSERT INTO products (id, name_en, name_es, price_usd, price_mxn) VALUES (?, ?, ?, ?, ?)')
  .run(1, 'Widget', 'Aparato', 99.99, 1799.82);

const insertMerchant = db.prepare('INSERT INTO merchants (id, name, estado, email) VALUES (?, ?, ?, ?)');
insertMerchant.run(1, 'Frontera Imports', 'Tamaulipas', 'contact@fronteraimports.mx');
insertMerchant.run(2, 'Coahuila Textiles', 'Coahuila', 'ventas@coahuilatextiles.mx');
insertMerchant.run(3, 'Nuevo Leon Electronics', 'Nuevo Leon', 'info@nlelectronics.mx');

module.exports = db;

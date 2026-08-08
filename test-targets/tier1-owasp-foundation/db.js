// In-memory SQLite (better-sqlite3), reseeded fresh on every process start —
// this is a throwaway benchmark fixture, not a real app; nothing here persists
// or matters beyond one test run. Passwords are stored PLAINTEXT on purpose
// (T1-Auth-001 is about weak session tokens, not password hashing — the schema
// stays simple so the interesting vulnerability is the one actually planted).
const Database = require('better-sqlite3');

const db = new Database(':memory:');

db.exec(`
  CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
  );
  CREATE TABLE posts (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL
  );
  CREATE TABLE comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    text TEXT NOT NULL
  );
  CREATE TABLE comments_safe (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    text TEXT NOT NULL
  );
  CREATE TABLE invoices (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    amount REAL NOT NULL,
    due_date TEXT NOT NULL,
    status TEXT NOT NULL,
    company_name TEXT NOT NULL
  );
`);

const insertUser = db.prepare('INSERT INTO users (id, username, password, email, role) VALUES (?, ?, ?, ?, ?)');
insertUser.run(1, 'admin', 'AdminPass!2026', 'admin@local', 'admin');
insertUser.run(2, 'carlos', 'CarlosPass!2026', 'carlos@local', 'user');
insertUser.run(3, 'test', 'TestPass!2026', 'test@local', 'user');

db.prepare('INSERT INTO posts (id, title) VALUES (?, ?)').run(1, 'Welcome to the OWASP Foundation blog');

const insertInvoice = db.prepare(
  'INSERT INTO invoices (id, user_id, amount, due_date, status, company_name) VALUES (?, ?, ?, ?, ?, ?)'
);
insertInvoice.run(1, 2, 420.0, '2026-09-15', 'pending', 'Carlos Consulting LLC');
insertInvoice.run(2, 3, 5000.0, '2026-09-20', 'pending', 'Competitor Corp');

module.exports = db;

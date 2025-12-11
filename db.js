const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const path = require('path');
const fs = require('fs');

const DB_FILE = path.join(__dirname, 'data.sqlite');

async function openDb() {
  const db = await open({ filename: DB_FILE, driver: sqlite3.Database });
  return db;
}

async function initDb() {
  const db = await openDb();
  const initSql = fs.readFileSync(path.join(__dirname, 'init.sql'), 'utf8');
  await db.exec(initSql);
  // seed if no users
  const row = await db.get('SELECT COUNT(*) as c FROM users');
  if (row && row.c === 0) {
    const bcrypt = require('bcrypt');
    const adminPass = await bcrypt.hash('admin123', 10);
    const teacherPass = await bcrypt.hash('teacher123', 10);
    const studentPass = await bcrypt.hash('student123', 10);
    // username, password_hash, role, linked_id
    await db.run('INSERT INTO users (username, password_hash, role, linked_id) VALUES (?, ?, ?, ?)', 'admin', adminPass, 'admin', null);
    await db.run('INSERT INTO users (username, password_hash, role, linked_id) VALUES (?, ?, ?, ?)', 'teacher', teacherPass, 'teacher', 't1');
    // seed a student
    await db.run('INSERT OR IGNORE INTO students (student_id, name) VALUES (?, ?)', 's1', 'Demo Student');
    await db.run('INSERT OR IGNORE INTO users (username, password_hash, role, linked_id) VALUES (?, ?, ?, ?)', 'student', studentPass, 'student', 's1');
  }
}

module.exports = { openDb, initDb };

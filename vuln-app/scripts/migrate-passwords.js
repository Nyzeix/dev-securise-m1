// Migrates plaintext passwords in users table to bcrypt hashes.
// Usage: node scripts/migrate-passwords.js

const bcrypt = require('bcryptjs');
const { initDB, getDB } = require('../server/db');

const SALT_ROUNDS = 12;

async function migratePasswords() {
  await initDB();

  const db = getDB();
  const users = db.prepare('SELECT id, email, password FROM users').all();

  console.log(`Migration de ${users.length} comptes...`);

  for (const user of users) {
    const pwd = String(user.password || '');
    const alreadyHashed = pwd.startsWith('$2a$') || pwd.startsWith('$2b$') || pwd.startsWith('$2y$');

    if (alreadyHashed) {
      console.log(`  - ${user.email}: deja hashe, ignore`);
      continue;
    }

    const hash = await bcrypt.hash(pwd, SALT_ROUNDS);
    db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hash, user.id);
    console.log(`  - ${user.email}: migre (plain -> bcrypt)`);
  }

  const sample = db.prepare('SELECT email, password FROM users LIMIT 1').get();
  if (sample) {
    console.log(`Verification: ${sample.email} -> ${String(sample.password).slice(0, 16)}...`);
    console.log(`Hash valide: ${String(sample.password).startsWith('$2b$') || String(sample.password).startsWith('$2a$') || String(sample.password).startsWith('$2y$')}`);
  }

  console.log('Migration terminee.');
}

migratePasswords().catch((err) => {
  console.error('Migration error:', err);
  process.exit(1);
});

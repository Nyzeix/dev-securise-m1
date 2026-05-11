-- TaskFlow — Schema initial
-- VULN NOTE: pas de constraints fortes, champ password en TEXT (pas de hash obligatoire)

CREATE TABLE IF NOT EXISTS users (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  email   TEXT    NOT NULL UNIQUE,
  password TEXT   NOT NULL,   -- VULN M2: stored in plaintext
  role    TEXT    NOT NULL DEFAULT 'user'
);

CREATE TABLE IF NOT EXISTS tasks (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id  INTEGER NOT NULL,
  title    TEXT    NOT NULL,
  content  TEXT,
  shared   INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

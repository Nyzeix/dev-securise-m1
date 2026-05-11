-- TaskFlow — Données de test
-- VULN M2: mots de passe stockés EN CLAIR

INSERT OR IGNORE INTO users (email, password, role) VALUES
  ('alice@taskflow.io',  'alice123',   'user'),
  ('bob@taskflow.io',    'bob456',     'user'),
  ('admin@taskflow.io',  'adminpass',  'admin');

-- Tasks appartenant à alice (user_id=1)
INSERT OR IGNORE INTO tasks (user_id, title, content, shared) VALUES
  (1, 'Rapport Q1', 'Terminer le rapport trimestriel avant vendredi', 0),
  (1, 'Formation sécurité', 'Préparer les slides pour le TP', 0),
  (1, 'Tâche partagée', 'Visible par tous les membres', 1);

-- Tasks appartenant à bob (user_id=2)
INSERT OR IGNORE INTO tasks (user_id, title, content, shared) VALUES
  (2, 'Réunion équipe', 'Ordre du jour : budget Q2', 0),
  (2, 'Todo perso', 'Acheter du café', 0);

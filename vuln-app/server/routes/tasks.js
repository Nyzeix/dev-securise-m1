/**
 * tasks.js — CRUD des tâches
 *
 * VULNS INTENTIONNELLES :
 *   M4-1 : SQL injection par concaténation sur GET /tasks (filtrage userId)
 *   M3-2 : IDOR sur GET/PUT/DELETE /tasks/:id — pas de vérification de propriétaire
 *   M4-2 : pas de validation des entrées (title peut contenir du HTML/JS)
 *   M5-1 : pas de CSRF token vérifié sur les mutations POST/PUT/DELETE
 *   M6-2 : stack trace envoyée au client en cas d'erreur 500
 */

const express = require('express');
const { getDB } = require('../db');
const authenticate = require('../middleware/authenticate');

const router = express.Router();

/**
 * GET /tasks
 * Retourne les tâches de l'utilisateur connecté.
 * VULN M4: userId injecté directement dans la requête SQL par concaténation.
 */
router.get('/', authenticate, (req, res) => {
  const db     = getDB();
  const userId = req.query.userId || req.user.id;

  try {
    // VULN M4: SQL INJECTION — userId non paramétré
    const query = `SELECT * FROM tasks WHERE user_id = ${userId}`;
    console.log('Executing query:', query);
    const tasks = db.prepare(query).all();
    res.json(tasks);
  } catch (err) {
    // VULN M6: stack trace au client
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

/**
 * GET /tasks/:id
 * Retourne une tâche par ID.
 * VULN M3: IDOR — aucune vérification que la tâche appartient à req.user.id
 */
router.get('/:id', authenticate, (req, res) => {
  const db   = getDB();
  const { id } = req.params;

  try {
    const task = db.prepare('SELECT * FROM tasks WHERE id = ?').get(id);
    if (!task) return res.status(404).json({ error: 'Task not found' });
    if (task.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Acces interdit' });
    }
    res.json(task);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

/**
 * POST /tasks
 * Crée une nouvelle tâche.
 * VULN M4: pas de validation/sanitization du title ou content (XSS stocké possible).
 * VULN M5: pas de CSRF token vérifié.
 */
router.post('/', authenticate, (req, res) => {
  const db = getDB();
  const { title, content, shared } = req.body;

  // VULN M4: aucune validation — title peut contenir <script>alert(1)</script>
  if (!title) return res.status(400).json({ error: 'title required' });

  try {
    const stmt = db.prepare(
      'INSERT INTO tasks (user_id, title, content, shared) VALUES (?, ?, ?, ?)'
    );
    const info = stmt.run(req.user.id, title, content || '', shared ? 1 : 0);
    res.json({ id: info.lastInsertRowid, message: 'Task created' });
  } catch (err) {
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

/**
 * PUT /tasks/:id
 * Met à jour une tâche.
 * VULN M3: pas de vérification que l'utilisateur est propriétaire de la tâche.
 * VULN M5: pas de CSRF token.
 */
router.put('/:id', authenticate, (req, res) => {
  const db = getDB();
  const { id } = req.params;
  const { title, content, shared } = req.body;

  try {
    const task = db.prepare('SELECT user_id FROM tasks WHERE id = ?').get(id);
    if (!task) return res.status(404).json({ error: 'Task not found' });
    if (task.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Acces interdit' });
    }

    const stmt = db.prepare(
      'UPDATE tasks SET title = ?, content = ?, shared = ? WHERE id = ?'
    );
    stmt.run(title, content, shared ? 1 : 0, id);
    res.json({ message: 'Task updated' });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

/**
 * DELETE /tasks/:id
 * Supprime une tâche.
 * VULN M3: IDOR — aucun check de propriété.
 * VULN M5: pas de CSRF token.
 */
router.delete('/:id', authenticate, (req, res) => {
  const db = getDB();
  const { id } = req.params;

  try {
    const task = db.prepare('SELECT user_id FROM tasks WHERE id = ?').get(id);
    if (!task) return res.status(404).json({ error: 'Task not found' });
    if (task.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Acces interdit' });
    }

    db.prepare('DELETE FROM tasks WHERE id = ?').run(id);
    res.json({ message: 'Task deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

module.exports = router;

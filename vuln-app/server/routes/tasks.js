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
const {
  taskBodySchema,
  taskUpdateSchema,
  taskIdSchema
} = require('../validators/tasks');
const authenticate = require('../middleware/authenticate');

const router = express.Router();

function validationErrorResponse(error, res) {
  return res.status(400).json({
    error: 'Données invalides',
    details: error.details.map((detail) => detail.message)
  });
}

/**
 * GET /tasks
 * Retourne les tâches de l'utilisateur connecté.
 */
router.get('/', authenticate, (req, res) => {
  const db = getDB();
  const userId = req.user.id;

  try {
    const tasks = db.prepare('SELECT * FROM tasks WHERE user_id = ?').all(userId);
    res.json(tasks);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

/**
 * GET /tasks/:id
 * Retourne une tâche par ID.
 * VULN M3: IDOR — aucune vérification que la tâche appartient à req.user.id
 */
router.get('/:id', authenticate, (req, res) => {
  const db   = getDB();
  const { error, value } = taskIdSchema.validate(req.params, { abortEarly: false, convert: true });

  if (error) {
    return validationErrorResponse(error, res);
  }

  const { id } = value;

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
  const { error, value } = taskBodySchema.validate(req.body, { abortEarly: false, convert: true });

  if (error) {
    return validationErrorResponse(error, res);
  }

  const { title, content, shared } = value;

  try {
    const stmt = db.prepare(
      'INSERT INTO tasks (user_id, title, content, shared) VALUES (?, ?, ?, ?)'
    );
    const info = stmt.run(req.user.id, title, content || '', shared ? 1 : 0);
    const createdTask = db.prepare(
      'SELECT id FROM tasks WHERE user_id = ? ORDER BY id DESC LIMIT 1'
    ).get(req.user.id);

    res.json({
      id: createdTask ? createdTask.id : info.lastInsertRowid,
      message: 'Task created'
    });
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
  const idCheck = taskIdSchema.validate(req.params, { abortEarly: false, convert: true });
  const bodyCheck = taskUpdateSchema.validate(req.body, { abortEarly: false, convert: true });

  if (idCheck.error) {
    return validationErrorResponse(idCheck.error, res);
  }

  if (bodyCheck.error) {
    return validationErrorResponse(bodyCheck.error, res);
  }

  const { id } = idCheck.value;
  const { title, content, shared } = bodyCheck.value;

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
  const { error, value } = taskIdSchema.validate(req.params, { abortEarly: false, convert: true });

  if (error) {
    return validationErrorResponse(error, res);
  }

  const { id } = value;

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

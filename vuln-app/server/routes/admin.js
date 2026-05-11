/**
 * admin.js — Routes d'administration
 *
 * VULNS INTENTIONNELLES :
 *   M3-3 : vérification d'autorisation insuffisante — vérifie req.user mais pas req.user.role
 *   M4-3 : retourne les mots de passe en clair dans la réponse
 *   M6-2 : stack trace au client
 */

const express = require('express');
const { getDB } = require('../db');
const authenticate = require('../middleware/authenticate');
const requireRole = require('../middleware/requireRole');

const router = express.Router();

/**
 * GET /admin/users
 * Liste tous les utilisateurs.
 * VULN M3: check if (req.user) au lieu de if (req.user.role === 'admin')
 *          => tout utilisateur authentifié peut accéder à cette route "admin"
 * VULN M4: retourne le champ password (en clair) dans la réponse JSON
 */
router.get('/users', authenticate, requireRole('admin'), (req, res) => {
  const db = getDB();

  try {
    const users = db.prepare('SELECT id, email, role, created_at FROM users').all();
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

/**
 * DELETE /admin/users/:id
 * Supprime un utilisateur.
 * VULN M3: même check insuffisant — tout user authentifié peut supprimer un compte.
 */
router.delete('/users/:id', authenticate, requireRole('admin'), (req, res) => {
  const db = getDB();

  try {
    db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
    res.json({ message: 'User deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

module.exports = router;

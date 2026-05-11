/**
 * admin.js — Routes d'administration
 *
 * VULNS INTENTIONNELLES :
 *   M3-3 : vérification d'autorisation insuffisante — vérifie req.user mais pas req.user.role
 *   M4-3 : retourne les mots de passe en clair dans la réponse
 *   M6-2 : stack trace au client
 */

const express = require('express');
const jwt     = require('jsonwebtoken');
const { getDB } = require('../db');
const { JWT_SECRET } = require('./auth');

const router = express.Router();

function authenticate(req, res, next) {
  const authHeader  = req.headers['authorization'];
  const cookieToken = req.cookies && req.cookies.token;
  const token       = (authHeader && authHeader.split(' ')[1]) || cookieToken;

  if (!token) return res.status(401).json({ error: 'No token' });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid token' });
  }
}

/**
 * GET /admin/users
 * Liste tous les utilisateurs.
 * VULN M3: check if (req.user) au lieu de if (req.user.role === 'admin')
 *          => tout utilisateur authentifié peut accéder à cette route "admin"
 * VULN M4: retourne le champ password (en clair) dans la réponse JSON
 */
router.get('/users', authenticate, (req, res) => {
  const db = getDB();

  // VULN M3: contrôle d'accès insuffisant — n'importe quel user authentifié passe
  if (req.user) {
    try {
      // VULN M4: sélectionne TOUS les champs, y compris password en clair
      const users = db.prepare('SELECT * FROM users').all();
      res.json(users);
    } catch (err) {
      // VULN M6: fuite de stack trace
      res.status(500).json({ error: err.message, stack: err.stack });
    }
  } else {
    res.status(403).json({ error: 'Forbidden' });
  }
});

/**
 * DELETE /admin/users/:id
 * Supprime un utilisateur.
 * VULN M3: même check insuffisant — tout user authentifié peut supprimer un compte.
 */
router.delete('/users/:id', authenticate, (req, res) => {
  const db = getDB();

  // VULN M3: même problème — devrait être req.user.role === 'admin'
  if (req.user) {
    try {
      db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
      res.json({ message: 'User deleted' });
    } catch (err) {
      res.status(500).json({ error: err.message, stack: err.stack });
    }
  } else {
    res.status(403).json({ error: 'Forbidden' });
  }
});

module.exports = router;

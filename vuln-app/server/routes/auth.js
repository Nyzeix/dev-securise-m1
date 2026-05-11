/**
 * auth.js — Routes d'authentification
 *
 * VULNS INTENTIONNELLES :
 *   M2-1 : mots de passe stockés et comparés EN CLAIR (bcryptjs importé mais non utilisé)
 *   M2-2 : messages d'erreur verbeux ("user not found" vs "wrong password")
 *   M2-3 : pas de rate limiting sur /login
 *   M3-1 : JWT signé avec secret faible codé en dur
 *   M6-1 : log du mot de passe en clair dans la console
 *   M6-2 : stack trace envoyée au client en cas d'erreur 500
 */

const express = require('express');
const jwt     = require('jsonwebtoken');
const { getDB } = require('../db');

const router = express.Router();

// VULN M3 + M6: secret JWT faible et en dur dans le source
const JWT_SECRET = "secret123";

/**
 * POST /auth/register
 * Crée un compte utilisateur.
 * VULN M2: password stocké en clair, aucun hashage.
 */
router.post('/register', (req, res) => {
  const { email, password } = req.body;
  const db = getDB();

  if (!email || !password) {
    return res.status(400).json({ error: 'email and password required' });
  }

  try {
    // VULN M2: insertion du mot de passe en clair
    const stmt = db.prepare('INSERT INTO users (email, password, role) VALUES (?, ?, ?)');
    stmt.run(email, password, 'user');
    res.json({ message: 'User created' });
  } catch (err) {
    // VULN M6: fuite de stack trace complète au client
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

/**
 * POST /auth/login
 * Authentifie un utilisateur et retourne un JWT.
 * VULN M2: messages d'erreur différenciés → enumération utilisateurs.
 * VULN M6: log du couple email/password dans la console.
 */
router.post('/login', (req, res) => {
  const { email, password } = req.body;
  const db = getDB();

  // VULN M6: mot de passe visible dans les logs serveur
  console.log('login attempt:', email, password);

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  if (!user) {
    // VULN M2: message différent selon que le user existe ou non
    return res.status(401).json({ error: 'User not found' });
  }

  // VULN M2: comparaison en clair au lieu de bcrypt.compare()
  if (user.password !== password) {
    return res.status(401).json({ error: 'Wrong password' });
  }

  // VULN M3: JWT signé avec secret trivial, expiration longue
  const token = jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  // VULN M5: cookie sans HttpOnly ni Secure ni SameSite
  res.cookie('token', token);

  res.json({ token, role: user.role });
});

module.exports = router;
module.exports.JWT_SECRET = JWT_SECRET;

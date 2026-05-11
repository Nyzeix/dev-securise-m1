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
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { getDB } = require('../db');

const router = express.Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Trop de tentatives, réessayez dans 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// VULN M3 + M6: secret JWT faible et en dur dans le source
const JWT_SECRET = "secret123";

/**
 * POST /auth/register
 * Crée un compte utilisateur.
 * VULN M2: password stocké en clair, aucun hashage.
 */
router.post('/register', async (req, res) => {
  const { email, password } = req.body;
  const db = getDB();

  if (!email || !password) {
    return res.status(400).json({ error: 'email and password required' });
  }

  if (password.length < 12) {
    return res.status(400).json({ error: 'Password must be at least 12 characters' });
  }

  try {
    const hash = await bcrypt.hash(password, 12);
    const stmt = db.prepare('INSERT INTO users (email, password, role) VALUES (?, ?, ?)');
    stmt.run(email, hash, 'user');
    res.status(201).json({ message: 'User created' });
  } catch (err) {
    if (err.message.includes('UNIQUE constraint')) {
      return res.status(409).json({ error: 'Email already exists' });
    }
    res.status(500).json({ error: 'Registration failed' });
  }
});

/**
 * POST /auth/login
 * Authentifie un utilisateur et retourne un JWT.
 * VULN M2: messages d'erreur différenciés → enumération utilisateurs.
 * VULN M6: log du couple email/password dans la console.
 */
router.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  const db = getDB();

  console.log('login attempt:', email);

  if (!email || !password) {
    return res.status(400).json({ error: 'email and password required' });
  }

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  if (!user) {
    return res.status(401).json({ error: 'Identifiants invalides' });
  }

  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    return res.status(401).json({ error: 'Identifiants invalides' });
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

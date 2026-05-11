/**
 * index.js — Point d'entrée TaskFlow (app volontairement vulnérable)
 *
 * VULNS INTENTIONNELLES :
 *   M5-1 : pas de helmet() — headers HTTP non sécurisés (X-Frame-Options, CSP, etc.)
 *   M5-2 : pas de CSRF middleware
 *   M5-3 : CORS permissif (origin: *)
 *   M6-4 : erreurs non gérées exposent la stack au client (via les routes)
 *   M6-5 : secret JWT et DB credentials en clair dans auth.js et db.js
 */

const express      = require('express');
const cookieParser = require('cookie-parser');
const path         = require('path');
const fs           = require('fs');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const { initDB }   = require('./db');

const app  = express();
const PORT = 3000;

// --- Middlewares globaux ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// VULN M5: pas de helmet() => aucun header de sécurité HTTP

// VULN M5: CORS totalement ouvert
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// Servir les fichiers statiques du frontend
app.use(express.static(path.join(__dirname, '..', 'public')));

// --- Dossier uploads (créé si absent) ---
const uploadsDir = path.join(__dirname, '..', 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}

// Initialise la DB puis démarre le serveur
initDB().then(() => {
  // Chargement des routes APRÈS initDB (les routes appellent getDB())
  const authRoutes   = require('./routes/auth');
  const tasksRoutes  = require('./routes/tasks');
  const adminRoutes  = require('./routes/admin');
  const uploadRoutes = require('./routes/upload');

  app.use('/auth',   authRoutes);
  app.use('/tasks',  tasksRoutes);
  app.use('/admin',  adminRoutes);
  app.use('/upload', uploadRoutes);

  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', app: 'TaskFlow', version: '1.0.0' });
  });

  // VULN M6: gestionnaire d'erreur global qui renvoie la stack complète
  app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
      error: err.message,
      stack: err.stack   // VULN M6: ne jamais exposer la stack en prod
    });
  });

  app.listen(PORT, () => {
    console.log(`TaskFlow running on http://localhost:${PORT}`);
    console.log('WARNING: This app is intentionally vulnerable — DO NOT use in production');
  });
}).catch(err => {
  console.error('Failed to initialize DB:', err);
  process.exit(1);
});

module.exports = app;

/**
 * upload.js — Upload de fichiers
 *
 * VULNS INTENTIONNELLES :
 *   M4-4 : aucune validation du type MIME ni de l'extension
 *   M4-5 : nom de fichier original utilisé tel quel (path traversal possible)
 *   M3-4 : route non authentifiée — n'importe qui peut uploader
 *   M6-3 : chemin complet du fichier retourné dans la réponse
 */

const express = require('express');
const multer  = require('multer');
const path    = require('path');

const router = express.Router();

// VULN M4: diskStorage avec filename qui utilise le nom original SANS sanitization
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, '..', '..', 'uploads'));
  },
  filename: (req, file, cb) => {
    // VULN M4: nom de fichier original — permet path traversal (ex: ../../server/evil.js)
    cb(null, file.originalname);
  }
});

// VULN M4: aucun filtre fileFilter — accepte n'importe quel type de fichier (.php, .exe, .js...)
const upload = multer({ storage });

/**
 * POST /upload
 * Upload d'un fichier.
 * VULN M3: pas d'authentification requise.
 * VULN M4: pas de validation type/extension/taille.
 * VULN M6: chemin absolu retourné dans la réponse.
 */
router.post('/', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file provided' });
  }

  // VULN M6: exposition du chemin serveur complet
  res.json({
    message: 'File uploaded',
    filename: req.file.originalname,
    path: req.file.path,          // chemin absolu sur le serveur
    size: req.file.size
  });
});

module.exports = router;

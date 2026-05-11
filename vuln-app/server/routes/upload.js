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
const fs      = require('fs');
const crypto  = require('crypto');
const authenticate = require('../middleware/authenticate');

const router = express.Router();

const uploadDir = path.join(__dirname, '..', '..', 'private-uploads');
const allowedExtensions = new Set(['.jpg', '.jpeg', '.png', '.gif', '.pdf']);

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const randomName = `${crypto.randomBytes(16).toString('hex')}${ext}`;
    cb(null, randomName);
  }
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!allowedExtensions.has(ext)) {
      req.fileValidationError = 'Extension non autorisée';
      return cb(null, false);
    }

    cb(null, true);
  },
  limits: { fileSize: 5 * 1024 * 1024 }
});

/**
 * POST /upload
 * Upload d'un fichier.
 * VULN M3: pas d'authentification requise.
 * VULN M4: pas de validation type/extension/taille.
 * VULN M6: chemin absolu retourné dans la réponse.
 */
router.post('/', authenticate, (req, res) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({ error: 'Fichier trop volumineux' });
      }

      return res.status(400).json({ error: err.message });
    }

    if (req.fileValidationError) {
      return res.status(400).json({ error: req.fileValidationError });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'No file provided' });
    }

    res.json({
      message: 'File uploaded',
      filename: req.file.filename,
      size: req.file.size
    });
  });
});

module.exports = router;

# TaskFlow, Guide de démarrage

Application Node.js + Express + SQLite **volontairement vulnérable** pour les TP d'audit sécurité M1.

## Prérequis

- Node.js >= 18
- npm >= 9

## Installation et démarrage

```bash
cd vuln-app
npm install
npm start
```

L'application démarre sur **http://localhost:3000**

## Structure

```
vuln-app/
├── server/
│   ├── index.js          # Point d'entrée Express
│   ├── db.js             # Configuration SQLite
│   └── routes/
│       ├── auth.js       # POST /auth/register, POST /auth/login
│       ├── tasks.js      # GET/POST/PUT/DELETE /tasks
│       ├── admin.js      # GET /admin/users, DELETE /admin/users/:id
│       └── upload.js     # POST /upload
├── public/               # Frontend HTML/CSS/JS
├── db/
│   ├── init.sql          # Schéma de la base
│   └── seed.sql          # Données de test
├── uploads/              # Fichiers uploadés (créé automatiquement)
└── docs/
    └── README.md         # Ce fichier
```

## Comptes de test

| Email | Mot de passe | Rôle |
|---|---|---|
| alice@taskflow.io | alice123 | user |
| bob@taskflow.io | bob456 | user |
| admin@taskflow.io | adminpass | admin |

## Endpoints API

| Méthode | Route | Description |
|---|---|---|
| POST | /auth/register | Créer un compte |
| POST | /auth/login | Se connecter (retourne JWT) |
| GET | /tasks | Lister les tâches |
| GET | /tasks/:id | Voir une tâche |
| POST | /tasks | Créer une tâche |
| PUT | /tasks/:id | Modifier une tâche |
| DELETE | /tasks/:id | Supprimer une tâche |
| GET | /admin/users | Lister les utilisateurs |
| DELETE | /admin/users/:id | Supprimer un utilisateur |
| POST | /upload | Uploader un fichier |
| GET | /api/health | Santé de l'API |

## Avertissement

**NE PAS déployer en production.** Cette application contient des vulnérabilités intentionnelles
à des fins pédagogiques.

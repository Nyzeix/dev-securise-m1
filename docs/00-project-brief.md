# Project Brief - TaskFlow

## 1. Contexte

TaskFlow est une application web pedagogique (Node.js, Express, SQLite) utilisée pour des TP d'audit sécurité. Le périmetre M1 couvre le cadrage: inventaire des actifs, surface d'attaque, modèle de menaces STRIDE et priorisation des risques.

## 2. Périmètre fonctionnel

- Authentification utilisateur (inscription, connexion, deconnexion)
- Gestion des tâches (CRUD)
- Endpoints d'administration (gestion des utilisateurs)
- Upload de fichiers
- Frontend statique HTML/CSS/JS

## 3. Stack technique

- Backend: Node.js + Express
- Base de données: SQLite (fichier local)
- Authentification: JWT + cookie HTTP only
- Upload: Multer
- Frontend: HTML/CSS/JavaScript vanilla

## 4. Routes principales

| Methode | Endpoint | Niveau d'acces |
|---|---|---|
| POST | /auth/register | Public |
| POST | /auth/login | Public |
| POST | /auth/logout | Auth |
| GET | /auth/me | Auth |
| GET | /tasks | Auth |
| GET | /tasks/:id | Auth |
| POST | /tasks | Auth |
| PUT | /tasks/:id | Auth |
| DELETE | /tasks/:id | Auth |
| GET | /admin/users | Admin |
| DELETE | /admin/users/:id | Admin |
| POST | /upload | Auth |
| GET | /api/health | Public |

## 5. Hypothèses et limites

- Projet destiné a un environnement local de TP uniquement.
- Les contrôles de sécurité avances (WAF, 2FA, SIEM) sont hors périmètre M1.
- Les corrections techniques seront traitées dans les modules M2 a M7.

# Analyse de risques - TaskFlow

## 1. Inventaire des actifs

| # | Actif | Type | Localisation | Valeur | Proprietaire |
|---|---|---|---|---|---|
| A1 | Base de donnees taskflow | Donnee | vuln-app/db/*.db | Critique | Dev/Ops |
| A2 | Mots de passe utilisateurs | Donnee sensible | Table users.password | Critique | Metier |
| A3 | Tokens JWT | Secret | Cookie httpOnly + memoire serveur | Elevee | Dev |
| A4 | Secret JWT | Secret | Fichier .env | Critique | Dev |
| A5 | Fichiers uploades | Donnee | vuln-app/uploads/ | Moyenne | Utilisateur |
| A6 | Code source API | Logiciel | vuln-app/server/ | Elevee | Dev |

## 2. Surface d'attaque

| Endpoint | Methode | Acces | Donnees traitees |
|---|---|---|---|
| /auth/register | POST | Public | email, password |
| /auth/login | POST | Public | email, password |
| /auth/logout | POST | Auth | cookie JWT |
| /auth/me | GET | Auth | profil utilisateur |
| /tasks | GET | Auth | JWT + taches |
| /tasks | POST | Auth | title, content, shared |
| /tasks/:id | GET | Auth | id tache |
| /tasks/:id | PUT | Auth | id, title, content, shared |
| /tasks/:id | DELETE | Auth | id tache |
| /admin/users | GET | Admin | utilisateurs |
| /admin/users/:id | DELETE | Admin | id utilisateur |
| /upload | POST | Auth | fichier |
| /api/health | GET | Public | metadonnees app |

## 3. Matrice de risques

| # | Menace | Impact (1-3) | Probabilite (1-3) | Score | Priorite | Module |
|---|---|---|---|---|---|---|
| R1 | Mot de passe stocke ou expose de facon insecurisee | 3 | 3 | 9 | P0 | M2 |
| R2 | Secret JWT faible ou fuite de secret | 3 | 3 | 9 | P0 | M3 |
| R3 | Brute force sur /auth/login | 3 | 2 | 6 | P1 | M2 |
| R4 | IDOR sur /tasks/:id | 3 | 2 | 6 | P1 | M4 |
| R5 | Escalade de privilege vers routes admin | 3 | 2 | 6 | P1 | M3 |
| R6 | Injection SQL/commande via entrees non valides | 3 | 2 | 6 | P1 | M4 |
| R7 | Upload malveillant (type/path traversal) | 2 | 2 | 4 | P2 | M5 |
| R8 | Protection HTTP incomplete (headers, CORS, CSRF) | 2 | 2 | 4 | P2 | M5 |
| R9 | Divulgation d'erreur technique au client | 2 | 2 | 4 | P2 | M6 |

## 4. Risques residuels

| # | Risque | Raison d'acceptation | Proprietaire | Reevaluation |
|---|---|---|---|---|
| RR1 | Absence de 2FA | Hors perimetre du cours | Produit/Dev | Fin M7 |
| RR2 | Audit trail partiel | Priorite donnee aux controles d'acces | Dev | Sprint suivant |
| RR3 | Pas de WAF dedie | Infrastructure locale de TP | Ops | Passage pre-prod |

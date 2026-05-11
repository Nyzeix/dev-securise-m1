# Projets fil rouge, Catalogue
## Cours · Développement Sécurisé

> Chaque étudiant choisit **un** projet. Les exigences de sécurité sont identiques pour tous.
> Si l'étudiant a déjà un projet (stage, mémoire…), il peut l'utiliser sous réserve qu'il remplisse les pré-requis fonctionnels.

---

## Pré-requis fonctionnels communs

Le projet doit comporter au minimum :

1. **Inscription + connexion** utilisateurs
2. **Au moins 2 rôles distincts** (ex : `user`, `admin`)
3. **3 ressources CRUD** (créer, lire, modifier, supprimer)
4. **Au moins 1 endpoint admin-only**
5. **Base de données réelle** (SQLite, PostgreSQL, MongoDB…)
6. **Au moins 1 endpoint manipulant des fichiers ou contenus user**

---

## Catalogue · 8 projets

### P1 · TaskFlow · Gestion de tâches collaboratives
**Stack suggérée :** Node.js + Express + SQLite (= l'app vulnérable fournie)
**Fonctionnalités :** comptes, tâches privées + partagées, étiquettes, recherche, dashboard admin
**Pourquoi riche en sécu :** auth, RBAC, IDOR (tâches d'autres users), recherche (SQLi), XSS dans titres/contenus

### P2 · DocVault · Partage sécurisé de documents
**Stack suggérée :** Python + FastAPI + SQLite
**Fonctionnalités :** upload PDF/images, partage par lien temporaire, gestion droits par doc, historique téléchargements
**Pourquoi riche en sécu :** upload (path traversal, type), permissions fines, chiffrement at-rest, signed URLs

### P3 · MiniShop · Mini e-commerce
**Stack suggérée :** Node.js + Express + MongoDB
**Fonctionnalités :** catalogue, panier, paiement simulé, gestion stock admin, commandes user
**Pourquoi riche en sécu :** RBAC vendeur/client/admin, IDOR commandes, race conditions stock, validation prix

### P4 · EventHub · Gestion d'événements
**Stack suggérée :** Django + PostgreSQL
**Fonctionnalités :** créer événement, réservation, capacité limitée, espace organisateur, espace participant
**Pourquoi riche en sécu :** anti-double-réservation, RBAC organisateur/participant, IDOR participants, validation dates

### P5 · BlogSphere · Blog ou forum
**Stack suggérée :** Next.js + Prisma + PostgreSQL
**Fonctionnalités :** articles avec markdown, commentaires, modération, profil user, recherche
**Pourquoi riche en sécu :** XSS dans markdown (sanitization), CSRF sur commentaires, IDOR édition, validation slugs

### P6 · TicketDesk · Gestion de tickets support
**Stack suggérée :** Spring Boot + MySQL ou Node + Express
**Fonctionnalités :** créer ticket, assigner support, escalade, historique, RBAC client/support/admin
**Pourquoi riche en sécu :** isolation multi-clients, RBAC 3 niveaux, IDOR tickets, log audit

### P7 · BookRoom · Réservation de salles
**Stack suggérée :** Flask + SQLite
**Fonctionnalités :** calendrier salles, réservation slot, validation manager, alertes
**Pourquoi riche en sécu :** anti-conflit slot (race), RBAC user/manager, validation dates futures

### P8 · UserAdmin · Gestion utilisateurs (back-office)
**Stack suggérée :** au choix
**Fonctionnalités :** CRUD users, attribution rôles, audit log, recherche, export CSV
**Pourquoi riche en sécu :** privilege escalation, audit log obligatoire, validation CSV (injection), sécurisation export

---

## Structure de dépôt commune

Quel que soit le projet choisi :

```
mon-projet-securise/
├── README.md
├── .gitignore
├── .env.example
├── package.json (ou requirements.txt, pom.xml…)
├── src/                       # code source
│   ├── routes/                # endpoints
│   ├── controllers/           # logique métier
│   ├── middlewares/           # auth, validation, logs
│   ├── models/                # accès données
│   └── config/                # secrets, env
├── tests/
│   ├── unit/
│   └── security/              # tests sécurité (M7)
├── docs/
│   ├── 00-project-brief.md    # M1
│   ├── 01-risk-analysis.md    # M1
│   ├── 02-threat-model.md     # M1
│   ├── 03-security-choices.md # M2-M6
│   ├── 04-owasp-checklist.md  # M7
│   └── 05-final-report.md     # M7
├── proofs/                    # captures exploits/tests
│   ├── M2/  M3/  M4/  M5/  M6/  M7/
└── public/ (si frontend HTML)
```

---

## Application à chaque module

Quel que soit le projet, chaque module ajoute la même couche de sécurité :

| Module | Ce qui se passe dans ton projet |
|--------|----------------------------------|
| **M1** | Cadrage : actifs, threat model, init repo |
| **M2** | Auth (bcrypt + rate limit + erreurs génériques) |
| **M3** | RBAC + JWT propre + correction IDOR sur ressources |
| **M4** | Toutes les requêtes paramétrées + validation + échappement |
| **M5** | Helmet + CSRF + cookies durcis + HTTPS |
| **M6** | .env + Winston + erreurs sûres |
| **M7** | ZAP + npm audit + tests Jest + rapport final |

---

## Niveaux de difficulté par projet

| Projet | Minimum | Intermédiaire | Avancé |
|--------|---------|---------------|--------|
| **P1 TaskFlow** | Tâches privées + 2 rôles | + partage entre users | + permissions fines + audit log |
| **P2 DocVault** | Upload + permissions basiques | + signed URLs | + chiffrement at-rest + scan AV |
| **P3 MiniShop** | Catalogue + panier | + paiement simulé Stripe sandbox | + détection fraude basique |
| **P4 EventHub** | Réservations | + listes d'attente | + paiement + remboursement |
| **P5 BlogSphere** | Articles + commentaires | + modération | + sanitization markdown avancée |
| **P6 TicketDesk** | Tickets + RBAC | + escalade auto | + SLA + alerting |
| **P7 BookRoom** | Slots | + récurrence | + multi-bâtiment |
| **P8 UserAdmin** | CRUD users | + import/export | + 2FA admin obligatoire |

---

## Validation du choix de projet (parcours A · projet personnel)

Si tu utilises ton propre projet (stage, mémoire, projet perso), vérifie :

- ☐ Code accessible (Git ou archive)
- ☐ Application fonctionnelle (peut être lancée localement)
- ☐ Au moins 5 routes/endpoints
- ☐ Base de données présente
- ☐ Aucune contrainte légale empêchant l'audit (NDA, propriété intellectuelle)
- ☐ Application fonctionnelle et auditable

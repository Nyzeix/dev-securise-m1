# Rapport d'Audit & Sécurisation
## [Nom du Projet] · [Nom Étudiant] · [Date]

> Document professionnel · 5 à 10 pages · à rendre en PDF
> Ce template suit la structure d'un livrable d'audit de sécurité applicative.

---

## 1. Résumé exécutif (½ page)

Synthèse en 6-8 lignes pour un lecteur pressé : objet de l'audit, périmètre, méthodo, principaux constats, niveau de sécurité final, principales recommandations.

**Niveau de sécurité initial :** ☐ Faible ☐ Moyen ☐ Bon
**Niveau de sécurité après corrections :** ☐ Faible ☐ Moyen ☐ Bon

**Vulnérabilités identifiées :** N critiques · N élevées · N moyennes · N faibles
**Vulnérabilités corrigées :** … sur …

---

## 2. Contexte et périmètre

### 2.1 Application auditée
- **Nom :** …
- **Type :** API REST / application web / SPA
- **Stack :** …
- **Périmètre auditeur :** routes, code source, base, configuration

### 2.2 Hypothèses et limites
- L'audit ne couvre pas : infra, réseau, processus déploiement
- Application en mode développement (pas de scope production)

---

## 3. Méthodologie

### 3.1 Démarche
1. Analyse des risques + threat model STRIDE (Module 1)
2. Audit code par catégorie OWASP Top 10 (Modules 2-6)
3. Tests dynamiques (OWASP ZAP, exploits manuels) (Module 7)
4. Tests automatisés de sécurité (Jest) (Module 7)
5. Documentation des corrections appliquées

### 3.2 Référentiels utilisés
- OWASP Top 10 (2021)
- OWASP Cheat Sheet Series
- STRIDE Threat Modeling (Microsoft)

---

## 4. Inventaire des actifs et threat model

### 4.1 Actifs sensibles identifiés
| # | Actif | Sensibilité | Justification |
|---|-------|-------------|---------------|
| A1 |  |  |  |
| A2 |  |  |  |

### 4.2 Threat model STRIDE (synthèse)
| Composant | Menace principale | Mitigation appliquée |
|-----------|-------------------|----------------------|
|  |  |  |

---

## 5. Vulnérabilités identifiées et corrigées

### 5.1 Tableau de synthèse
| # | OWASP | Vulnérabilité | Sévérité | Statut |
|---|-------|----------------|----------|--------|
| V1 | A07 | Mots de passe stockés en clair | Critique | ☑ Corrigé |
| V2 | A03 | Injection SQL dans /tasks | Critique | ☑ Corrigé |
| V3 | A01 | IDOR sur GET /tasks/:id | Élevé | ☑ Corrigé |
| V4 |  |  |  |  |

### 5.2 Détail par vulnérabilité

> Pour chaque vulnérabilité, suivre ce gabarit :

#### V1, [Titre court]

| | |
|--|--|
| **OWASP** | A07:2021, Identification and Authentication Failures |
| **Sévérité** | Critique / Élevée / Moyenne / Faible |
| **Composant** | server/routes/auth.js · ligne 23 |
| **Description** | Les mots de passe sont stockés en clair dans la table users. |
| **Impact** | Vol de la base = vol direct de tous les comptes. |
| **Preuve d'exploitation** | `sqlite3 app.db "SELECT password FROM users LIMIT 1"` → mdp en clair |
| **Correction appliquée** | Migration vers bcrypt (cost 12), salage automatique, code commité `M2-auth-securise` |
| **Test de validation** | `curl -X POST /login -d '{"email":"alice@x.fr","password":"alice"}'` → fonctionne avec mdp original ; lecture BDD montre hash bcrypt |
| **Capture** | `proofs/M2/01-hash-bcrypt.png` |

(Répéter pour chaque vulnérabilité)

---

## 6. Tests réalisés

### 6.1 Tests manuels d'exploitation
| Test | Payload | Avant correction | Après correction |
|------|---------|------------------|------------------|
| Énumération comptes | login email inexistant | "user not found" | "Identifiants invalides" |
| SQL injection | `' OR '1'='1` | dump données | requête vide |
| XSS stockée | `<script>alert(1)</script>` | popup | texte affiché |
| IDOR | GET /tasks/42 user 7 | 200 OK | 403 Forbidden |

### 6.2 Tests automatisés (Jest)
- `tests/security/auth.test.js`, N tests · résultat ☑
- `tests/security/idor.test.js`, N tests · résultat ☑
- `tests/security/injection.test.js`, N tests · résultat ☑

### 6.3 Scan OWASP ZAP
- Date du scan : …
- Profil : baseline
- Findings : N High, N Medium, N Low, N Info
- Rapport joint : `proofs/zap-report.html`

### 6.4 Audit dépendances
- `npm audit` : N vulnérabilités haute · N moyenne · N basse
- Remédiation : `npm audit fix` exécuté · packages mis à jour : …

---

## 7. Checklist OWASP

(Joindre la checklist du dossier `checklists/` cochée)

---

## 8. Risques résiduels

Ce qui n'est pas (encore) traité, justifié, et plan d'action proposé :

| # | Risque résiduel | Justification | Plan d'action |
|---|-----------------|---------------|---------------|
| R1 | Pas de MFA | Hors scope M1, hors temps | À implémenter via TOTP en v2 |
| R2 |  |  |  |

---

## 9. Synthèse compétences acquises

- ☑ Identifier les actifs sensibles d'une application
- ☑ Conduire un threat model STRIDE
- ☑ Auditer du code pour détecter SQLi, XSS, IDOR
- ☑ Implémenter authentification sûre (bcrypt + rate limit)
- ☑ Implémenter RBAC + JWT signé correctement
- ☑ Utiliser requêtes paramétrées + validation Joi/Zod
- ☑ Configurer Helmet, CSP, CSRF
- ☑ Gérer secrets via .env + logs structurés
- ☑ Conduire un scan OWASP ZAP et interpréter les résultats
- ☑ Rédiger un rapport de sécurisation professionnel

---

## Annexes

- **Annexe A**, Threat model STRIDE complet (`docs/02-threat-model.md`)
- **Annexe B**, Captures d'exploitation (`proofs/`)
- **Annexe C**, Rapport OWASP ZAP HTML (`proofs/zap-report.html`)
- **Annexe D**, Logs Jest des tests sécurité

---

*Document rédigé par [Nom] · Cours Développement Sécurisé M1 · [Date]*

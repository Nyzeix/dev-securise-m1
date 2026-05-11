# Checklist OWASP, Étudiant
## À cocher avant rendu du projet

> Reprend les 10 catégories OWASP Top 10 (2021). Chaque case = une vérification à effectuer dans **ton** application.

---

## A01, Broken Access Control

- ☐ Aucune autorisation déléguée au frontend (tout est vérifié côté serveur)
- ☐ Chaque route sensible vérifie l'identité (`req.user`) ET le rôle (`req.user.role`)
- ☐ Pas d'IDOR : les ressources personnelles (tasks, documents, etc.) vérifient `owner === req.user.id`
- ☐ Middleware `requireRole('admin')` testé et appliqué sur `/admin/*`
- ☐ Test : un user normal qui force-fetch `/admin/users` reçoit 403

## A02, Cryptographic Failures

- ☐ Mots de passe hachés avec bcrypt (cost ≥ 10) ou argon2
- ☐ Aucun secret en clair en BDD
- ☐ JWT signé avec secret long (32+ chars aléatoires)
- ☐ HTTPS activé (au moins en prod, mkcert en dev)
- ☐ Cookies session avec flag `Secure` (en HTTPS)

## A03, Injection

- ☐ Toutes les requêtes SQL utilisent des placeholders `?` (zéro concaténation)
- ☐ Audit `grep -r "SELECT.*\${\|SELECT.*+" server/` retourne 0 ligne
- ☐ Échappement HTML côté sortie (`textContent` ou DOMPurify)
- ☐ Test SQLi : payload `' OR '1'='1` ne dump pas la BDD
- ☐ Test XSS : payload `<script>alert(1)</script>` est affiché en texte

## A04, Insecure Design

- ☐ Rate limiting sur `/login` (5 essais / 15 min)
- ☐ Rate limiting sur `/register` (anti-spam)
- ☐ Politique mot de passe ≥ 12 caractères
- ☐ Messages d'erreur génériques (pas "user not found")
- ☐ Threat model STRIDE rédigé dans `docs/02-threat-model.md`

## A05, Security Misconfiguration

- ☐ Helmet installé et configuré
- ☐ CSP active avec `default-src 'self'`
- ☐ `X-Frame-Options: DENY` (anti-clickjacking)
- ☐ `Strict-Transport-Security` configuré (HSTS, 1 an)
- ☐ `NODE_ENV=production` désactive les stack traces en réponse
- ☐ CORS configuré (pas `*` en prod)

## A06, Vulnerable and Outdated Components

- ☐ `npm audit` exécuté · 0 vulnérabilité haute ou critique
- ☐ `package-lock.json` commité (versions figées)
- ☐ Dépendances inutiles supprimées
- ☐ Date dernier audit notée dans le rapport

## A07, Identification and Authentication Failures

- ☐ Inscription : email validé (format), mot de passe vérifié (longueur)
- ☐ Login : messages d'erreur uniformes
- ☐ Rate limit appliqué
- ☐ JWT expire (`expiresIn: '1h'` ou session courte)
- ☐ Logout invalide le token / la session

## A08, Software and Data Integrity Failures

- ☐ Aucune dépendance installée depuis source non vérifiée
- ☐ `npm ci` utilisé en CI (pas `npm install`)
- ☐ Hash d'intégrité utilisé pour les scripts externes (SRI)
- ☐ Pas de désérialisation insecure (`eval`, `Function()` interdits sur input user)

## A09, Security Logging and Monitoring Failures

- ☐ Logger structuré installé (Winston ou Pino)
- ☐ Événements loggés : login succès/échec, accès admin, erreurs 4xx/5xx
- ☐ Aucun mot de passe / token dans les logs (audit grep)
- ☐ Logs avec horodatage UTC ISO 8601
- ☐ Niveau `INFO` minimum en production

## A10, Server-Side Request Forgery (SSRF)

- ☐ Si l'app fetch des URLs : whitelist de domaines
- ☐ Pas d'accès aux IPs internes (169.254.x, 127.x, 10.x privé)
- ☐ Pas de protocole `file://`, `gopher://`, etc.

---

## Hygiène projet (transverse)

- ☐ `.env` listé dans `.gitignore`
- ☐ `git log -p | grep -i "password\|secret\|api_key"` retourne 0
- ☐ `.env.example` commité avec variables vides
- ☐ README contient instructions de setup
- ☐ Documentation sécurité dans `docs/` (analyse risques + threat model + rapport)
- ☐ Tests Jest de sécurité présents dans `tests/security/`
- ☐ Scan OWASP ZAP exécuté · rapport joint
- ☐ Tag Git `M7-audit-final` posé sur la version finale

---

**Date d'audit final :** ____________
**Étudiant :** ____________

**Signature (déclaration sur l'honneur) :** _______________________

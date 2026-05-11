# Quiz · Auto-vérification

> Vingt-cinq QCM pour vérifier ce que tu as retenu après les sept modules. Tu réponds, tu compares avec le corrigé en bas. Si tu te trompes plus de cinq fois, relis le module concerné.

---

### Section A, Analyse de risques & Threat Modeling (Q1-Q4)

**Q1.** Dans STRIDE, **R** signifie :
- A. Recovery
- B. Reverse-engineering
- C. Repudiation
- D. Remote access

**Q2.** Le risque se calcule comme :
- A. Vulnérabilité × Menace
- B. Impact × Probabilité
- C. Actifs × Vulnérabilités
- D. Surface d'attaque × Composants

**Q3.** Un **actif** sensible dans une application web est :
- A. Une faille de sécurité connue
- B. Un attaquant externe
- C. Une donnée ou ressource ayant de la valeur
- D. Un outil d'audit

**Q4.** "Defense in Depth" signifie :
- A. Mettre un firewall très puissant
- B. Empiler plusieurs couches de protection
- C. Chiffrer toutes les données
- D. Faire du code review systématique

---

### Section B, Authentification & Mots de passe (Q5-Q9)

**Q5.** bcrypt vs SHA-256 pour stocker un mot de passe :
- A. SHA-256 est meilleur car plus rapide
- B. bcrypt est meilleur car lent et intègre le sel
- C. Les deux sont équivalents
- D. SHA-256 n'est pas un algorithme de hachage

**Q6.** Pourquoi un message d'erreur "user not found" est-il problématique sur `/login` ?
- A. Il est trop long
- B. Il permet l'énumération des comptes existants
- C. Il consomme trop de bande passante
- D. Il ne respecte pas RGPD

**Q7.** Quelle politique de mot de passe est recommandée par NIST (2024) ?
- A. Au moins 8 caractères avec majuscule, chiffre et symbole
- B. Au moins 12 caractères, pas d'obligation de complexité
- C. Au moins 6 caractères avec symbole obligatoire
- D. Au moins 16 caractères tous en majuscules

**Q8.** Le **sel** (salt) en cryptographie sert à :
- A. Augmenter la longueur du hash
- B. Empêcher les attaques par rainbow tables
- C. Chiffrer le mot de passe
- D. Réduire les collisions

**Q9.** Le rate limiting sur `/login` protège principalement contre :
- A. SQL injection
- B. Cross-site scripting
- C. Brute force et credential stuffing
- D. CSRF

---

### Section C, Sessions, JWT et Contrôle d'accès (Q10-Q13)

**Q10.** Quelle affirmation sur les JWT est **fausse** ?
- A. Le payload n'est pas chiffré, seulement encodé en base64
- B. Un secret faible permet de forger des tokens valides
- C. Un JWT signé garantit l'authentification ET le chiffrement
- D. Un JWT peut expirer via le champ `exp`

**Q11.** Une vulnérabilité **IDOR** consiste à :
- A. Injecter du SQL via un paramètre d'URL
- B. Accéder à une ressource sans contrôle d'appartenance
- C. Voler le cookie de session
- D. Falsifier l'identité d'un user

**Q12.** Un JWT doit idéalement être stocké côté client dans :
- A. localStorage
- B. sessionStorage
- C. Un cookie HttpOnly + Secure + SameSite
- D. Une variable globale JavaScript

**Q13.** Le contrôle d'accès doit toujours être effectué :
- A. Côté client uniquement (rapide)
- B. Côté serveur uniquement
- C. Côté client et serveur, mais le serveur fait foi
- D. Par un service tiers externe

---

### Section D, Injections, XSS, Validation (Q14-Q17)

**Q14.** Pour prévenir une injection SQL, la meilleure pratique est :
- A. Échapper les apostrophes avec `replace("'", "''")`
- B. Utiliser des requêtes paramétrées (placeholders)
- C. Bloquer le mot SELECT dans les inputs
- D. Hasher l'entrée utilisateur

**Q15.** Le payload `<script>alert(document.cookie)</script>` cible :
- A. Une injection SQL
- B. Une attaque CSRF
- C. Une attaque XSS
- D. Un SSRF

**Q16.** Quelle méthode JS est la plus sûre pour afficher du texte saisi par un user ?
- A. `element.innerHTML = userInput`
- B. `element.outerHTML = userInput`
- C. `element.textContent = userInput`
- D. `eval(userInput)`

**Q17.** La validation des entrées doit être faite :
- A. Côté client uniquement (UX rapide)
- B. Côté serveur uniquement
- C. Côté client (UX) ET côté serveur (sécurité)
- D. Dans la base de données via triggers

---

### Section E, CSRF, Headers, HTTPS (Q18-Q20)

**Q18.** Une attaque **CSRF** consiste à :
- A. Voler les cookies d'un utilisateur
- B. Faire exécuter une action à un user connecté sans son consentement
- C. Injecter du JS dans une page tierce
- D. Intercepter une requête HTTP

**Q19.** Le cookie flag `HttpOnly` empêche :
- A. L'envoi du cookie en HTTP non chiffré
- B. L'accès au cookie via JavaScript
- C. Le partage du cookie entre sous-domaines
- D. L'expiration automatique du cookie

**Q20.** Le header `Content-Security-Policy: default-src 'self'` :
- A. Force le HTTPS
- B. Limite l'origine des ressources chargées par la page
- C. Désactive le cache
- D. Bloque tous les cookies tiers

---

### Section F, Secrets, Logs, Audit (Q21-Q25)

**Q21.** Pourquoi un secret commité dans Git est-il dangereux **même après suppression** ?
- A. Le fichier reste sur le disque
- B. L'historique Git est immuable et public si repo public
- C. Les autres devs l'ont mémorisé
- D. C'est uniquement un problème de propreté

**Q22.** Quel élément **doit absolument** apparaître dans `.gitignore` ?
- A. `node_modules/`
- B. `.env`
- C. `*.log`
- D. Les trois (A, B, C)

**Q23.** Un log applicatif **ne doit jamais** contenir :
- A. La date de la requête
- B. L'identifiant de l'utilisateur
- C. Le mot de passe ou le token complet
- D. Le statut HTTP de la réponse

**Q24.** `npm audit` permet de :
- A. Tester les performances de l'app
- B. Détecter les vulnérabilités dans les dépendances
- C. Linter le code
- D. Vérifier le typage TypeScript

**Q25.** OWASP ZAP est un outil de :
- A. SAST (Static Application Security Testing)
- B. DAST (Dynamic Application Security Testing)
- C. SCA (Software Composition Analysis)
- D. IDS (Intrusion Detection System)

---

## Corrigé

| Q | Réponse | Concept clé |
|---|---------|--------------|
| Q1 | **C** | Repudiation = nier une action faute de logs |
| Q2 | **B** | R = I × P |
| Q3 | **C** | Actif = chose de valeur à protéger |
| Q4 | **B** | Plusieurs couches de défense |
| Q5 | **B** | bcrypt = lent par design + sel intégré |
| Q6 | **B** | Énumération de comptes |
| Q7 | **B** | NIST 800-63B 2024 : longueur > complexité |
| Q8 | **B** | Sel = anti-rainbow tables |
| Q9 | **C** | Anti brute force |
| Q10 | **C** | JWT ne chiffre pas, il signe seulement |
| Q11 | **B** | IDOR = pas de check propriétaire |
| Q12 | **C** | Cookie HttpOnly + Secure + SameSite |
| Q13 | **C** | Client = UX, serveur = autorité |
| Q14 | **B** | Requêtes paramétrées |
| Q15 | **C** | XSS classique |
| Q16 | **C** | textContent = pas d'interprétation HTML |
| Q17 | **C** | Client (UX) + serveur (sécurité) |
| Q18 | **B** | CSRF = action involontaire |
| Q19 | **B** | HttpOnly bloque l'accès JS |
| Q20 | **B** | CSP whitelist sources |
| Q21 | **B** | Git history immuable |
| Q22 | **D** | Les 3 minimum |
| Q23 | **C** | Jamais de secret en log |
| Q24 | **B** | SCA dépendances |
| Q25 | **B** | DAST scanner |


# Rapport d'audit sécurité

Projet: TaskFlow vulnérable
Date: 11 mai 2026
Périmètre de ce rapport: Module M2, authentification
Référentiels: OWASP Top 10 2021, OWASP Authentication Cheat Sheet, OWASP Password Storage Cheat Sheet

## 1. Résumé exécutif

Le module M2 est majoritairement implémenté et fonctionnel sur l'application. Les contrôles techniques exécutés confirment la correction des failles critiques liées à l'authentification: hachage des mots de passe, message d'erreur générique au login, limitation de tentatives et politique de longueur minimale.

Des écarts de livraison restent présents côté gouvernance de rendu: commit final et tag M2 non publiés au moment du constat.

Niveau de risque résiduel M2: Modéré.

## 2. Méthodologie

Vérifications réalisées:

1. Revue de code de la route d'authentification.
2. Exécution du script de migration des mots de passe.
3. Tests HTTP de validation sur register et login.
4. Vérification de la base locale sur le format des hashs.
5. Contrôle de présence des preuves et livrables de module.

## 3. Résultats détaillés M2

### 3.1 Tableau de synthèse des failles M2

| ID | Faille | Sévérité | Statut | Détail de vérification |
|---|---|---|---|---|
| M2-1 | Mots de passe en clair | Critique | Corrigé | Hash bcrypt utilisé en inscription et en base |
| M2-2 | Énumération de comptes | Haute | Corrigé | Réponse unique Identifiants invalides |
| M2-3 | Absence de rate limiting login | Haute | Corrigé | 5 essais puis blocage 429 |
| M2-4 | Politique de mot de passe absente | Moyenne | Corrigé | Longueur minimale 12 caractères |
| M6-1 | Log mot de passe en clair | Haute | Corrigé dans le périmètre M2 | Le mot de passe n'est plus loggé lors du login |

### 3.2 Preuves techniques

Code audité:

- [vuln-app/server/routes/auth.js](../vuln-app/server/routes/auth.js)
- [vuln-app/scripts/migrate-passwords.js](../vuln-app/scripts/migrate-passwords.js)

Captures disponibles:

- [proofs/M2/Preuve_hashe.png](../proofs/M2/Preuve_hashe.png)
- [proofs/M2/preuve_kick_when_too_many_fail.png](../proofs/M2/preuve_kick_when_too_many_fail.png)
- [proofs/M2/users_data_hash_and_db_migrated.png](../proofs/M2/users_data_hash_and_db_migrated.png)

Résultats observés pendant validation:

1. Register avec mot de passe court: HTTP 400.
2. Register avec mot de passe conforme: HTTP 201.
3. Login email inconnu: HTTP 401 avec message Identifiants invalides.
4. Login mauvais mot de passe: HTTP 401 avec même message.
5. Login valide: HTTP 200 avec token.
6. Rate limit: tentatives 1 à 5 en 401 puis tentative 6 en 429.
7. Base utilisateurs: 4 comptes, 4 hashs bcrypt détectés.

Note importante sur le préfixe bcrypt:

- Les hashs présents commencent par 2a et non 2b.
- Ce format reste un hash bcrypt valide.
- Le contrôle de conformité doit accepter 2a, 2b ou 2y selon l'implémentation.

### 3.3 Conformité des livrables du module

| Livrable attendu | État |
|---|---|
| Route auth corrigée | Présent |
| Script de migration | Présent |
| Base migrée en bcrypt | Présent |
| Tests de validation exécutés | Présent |
| Preuves dans proofs/M2 | Présent |
| Rapport d'audit M2 | Présent avec ce document |
| Commit final + tag M2-auth-securise | Non finalisé au moment du constat |

## 4. Risques résiduels M2

1. Secret JWT encore codé en dur dans la route auth, hors correction stricte M2 mais impact sécurité réel.
2. Durée de validité du token conservée à 7 jours, posture perfectible.
3. Absence de 2FA, hors périmètre M2.
4. Pas de contrôle contre listes de mots de passe compromis, hors périmètre M2.

## 5. Recommandations

Priorité haute:

1. Externaliser JWT_SECRET via variable d'environnement et supprimer la valeur codée en dur.
2. Réduire la durée de vie du JWT à une fenêtre plus courte adaptée au contexte pédagogique.

Priorité moyenne:

1. Ajouter un bloc de tests automatisés pour la route auth.
2. Conserver un modèle unique de preuve terminal avec statut HTTP et corps JSON pour chaque test de module.

## 6. Plan de clôture module M2

Pour clôturer totalement le module:

1. Vérifier une dernière fois les statuts de tests manuels.
2. Valider le contenu de ce rapport.
3. Créer le commit de livraison M2.
4. Créer le tag Git M2-auth-securise.
5. Pousser commit et tag sur le dépôt distant.

## 7. Conclusion

Le module M2 atteint son objectif opérationnel principal: l'authentification est durcie et les vulnérabilités clés sont corrigées dans le code et confirmées par des tests techniques. Les derniers écarts concernent la formalisation de livraison Git et quelques améliorations de sécurité transverses à traiter dans les modules suivants.

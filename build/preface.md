# Préface · Mode d'emploi du cours

## Pourquoi ce cours

La plupart des cours de sécurité applicative sont théoriques. On lit des listes de vulnérabilités, on regarde des schémas, et le jour où il faut sécuriser une vraie application, on ne sait pas par où commencer.

Ce cours fait l'inverse. À chaque concept, tu fais une manipulation sur une application réelle, tu vérifies que ça marche, et tu écris ce que tu as fait. À la fin, tu rends un rapport pro de sécurisation, pas un cours appris par cœur.

## Comment lire ce document

Chaque module suit toujours la même cadence :

```
1. Rappel concept (5 à 10 lignes, juste pour comprendre l'action)
2. Risque concret
3. Exemple de faille
4. Action à faire dans ton application
5. Test de validation
6. Trace à mettre dans le rapport
```

Tu n'es jamais en train de lire pour le plaisir. Tu lis pour faire, et tu écris ce que tu fais.

## Deux parcours

### Parcours A · Tu as déjà une application

Stage, mémoire, projet perso : tu l'utilises comme support d'audit. Vérifie qu'elle remplit les pré-requis fonctionnels (page suivante).

### Parcours B · Tu n'as pas d'application

Tu utilises l'application vulnérable fournie dans `vuln-app/`. C'est une API Node.js + Express + SQLite avec des failles intentionnelles. Tu la clones, tu la lances, tu l'audites, tu la corriges.

```bash
git clone https://github.com/AbidHamza/dev-securise-m1.git
cd dev-securise-m1/vuln-app
npm install
npm start
# http://localhost:3000
```

> ⚠ L'application fournie contient des failles intentionnelles. Elle est faite pour tourner en local. Ne la déploie jamais sur Internet.

## Outils requis

- Un éditeur (VS Code conseillé)
- Node.js 20 ou plus
- Git
- curl ou Postman pour tester les routes
- Un navigateur (Chrome ou Firefox)
- OWASP ZAP (gratuit, utilisé au module 7)

## Livrable final

À rendre à la fin :

1. Le code de ton application sécurisée (dépôt Git taggé)
2. Le rapport d'audit et de sécurisation (5 à 10 pages PDF, voir Annexe A)
3. La checklist OWASP cochée (Annexe B)
4. Les captures d'écran des tests d'exploitation (dossier `proofs/`)
5. La grille d'auto-évaluation remplie (Annexe C)
6. Le quiz final rempli (Annexe D)

## Comment progresser à ton rythme

Chaque module propose trois niveaux :

- **Minimum (acquis).** Le noyau obligatoire. Fais-le partout avant d'aller plus loin.
- **Intermédiaire (maîtrise).** À ajouter si tu as le temps. Valorisé.
- **Avancé (expert).** Pour dépasser le cadre. Bonus de points.

La régularité bat l'héroïsme. Mieux vaut le niveau Minimum partout que l'Avancé sur un seul module.

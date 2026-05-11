# Développement Sécurisé · Master 1

Un cours de sécurité applicative qui ne se lit pas, qui se fait. Tu prends une application réelle (la tienne ou celle qu'on te fournit), tu l'audites, tu trouves les failles, tu les corriges, tu vérifies que ça tient, tu écris ce que tu as fait. À la fin tu as un rapport pro.

## Tu trouveras quoi dans ce dépôt

| Tu cherches… | Va voir |
|---|---|
| Le cours intégral en un seul PDF | [`COURS-COMPLET.pdf`](./COURS-COMPLET.pdf) |
| Un module en PDF séparé | [`pdf/`](./pdf/) |
| La source des 7 modules | [`modules/`](./modules/) |
| L'application volontairement vulnérable | [`vuln-app/`](./vuln-app/) |
| Le modèle de rapport d'audit | [`templates/rapport-audit-template.md`](./templates/rapport-audit-template.md) |
| La checklist OWASP à cocher | [`checklists/owasp-checklist-etudiant.md`](./checklists/owasp-checklist-etudiant.md) |
| Le quiz d'auto-vérification | [`quiz/quiz-final.md`](./quiz/quiz-final.md) |
| Le catalogue des projets fil rouge | [`templates/projets-fil-rouge.md`](./templates/projets-fil-rouge.md) |

## Comment tu démarres

### 1. Lis le PDF principal

Ouvre [`COURS-COMPLET.pdf`](./COURS-COMPLET.pdf). Tout est dedans : la préface qui t'explique le fonctionnement, les 7 modules dans l'ordre, le modèle de rapport, la checklist et le quiz d'auto-vérification.

### 2. Choisis sur quelle application tu travailles

Si tu as **déjà une application** (un stage, un projet de mémoire, un projet personnel), tu travailles dessus. Vérifie d'abord qu'elle a bien : une inscription, une connexion, au moins deux rôles, trois ressources CRUD, un endpoint admin et une vraie base de données. Si c'est le cas, tu es prêt.

Si tu **n'as pas d'application sous la main**, prends celle du dépôt :

```bash
git clone https://github.com/AbidHamza/dev-securise-m1.git
cd dev-securise-m1/vuln-app
npm install
npm start
```

L'app tourne sur `http://localhost:3000`. Les comptes de test sont dans `vuln-app/db/seed.sql`.

> ⚠ Cette application contient des failles **volontaires**. Elle est faite pour tourner en local. Tu ne la déploies pas sur Internet, jamais.

### 3. Tu fais les modules dans l'ordre

| | Module | Markdown | PDF |
|---|---|---|---|
| M1 | Cadrer avant de coder | [module.md](./modules/M1/module.md) | [PDF](./pdf/Module-1-M1.pdf) |
| M2 | Verrouiller l'authentification | [module.md](./modules/M2/module.md) | [PDF](./pdf/Module-2-M2.pdf) |
| M3 | Décider qui peut quoi | [module.md](./modules/M3/module.md) | [PDF](./pdf/Module-3-M3.pdf) |
| M4 | Filtrer ce qui entre, échapper ce qui sort | [module.md](./modules/M4/module.md) | [PDF](./pdf/Module-4-M4.pdf) |
| M5 | Durcir le navigateur et le canal | [module.md](./modules/M5/module.md) | [PDF](./pdf/Module-5-M5.pdf) |
| M6 | Sortir les secrets du code | [module.md](./modules/M6/module.md) | [PDF](./pdf/Module-6-M6.pdf) |
| M7 | Auditer, prouver, rendre | [module.md](./modules/M7/module.md) | [PDF](./pdf/Module-7-M7.pdf) |

Chaque module est construit pareil. Pour chaque concept de sécurité tu as : un rappel court (cinq à dix lignes), le risque concret si tu ne fais rien, un exemple de faille, l'action à faire dans ton application, le test qui doit échouer après correction, et la phrase à recopier dans ton rapport.

Pas de chapitre théorique long. Tu lis, tu fais, tu testes, tu notes.

### 4. À la fin tu auras produit

1. Le code de ton application sécurisée, dans un dépôt Git avec un tag final
2. Un rapport d'audit et de sécurisation, en PDF, cinq à dix pages
3. La checklist OWASP, cochée
4. Tes captures d'écran de tests d'exploitation, dans un dossier `proofs/`
5. Tes réponses au quiz d'auto-vérification

Tout est expliqué dans le PDF complet et dans le dossier `templates/`.

## Trois niveaux de profondeur

Tu n'es pas obligé de tout faire. Vise d'abord le niveau Minimum sur les sept modules, puis monte si tu as le temps.

- **Minimum.** Tu couvres l'OWASP Top 10 sur le cœur de l'application.
- **Intermédiaire.** Tu ajoutes tests automatisés, scan ZAP, threat model détaillé.
- **Avancé.** Tu ajoutes audit log, durcissement, plan d'amélioration.

## Régénérer les PDFs en local

```bash
node build/build-pdf.js
```

Pré-requis : Node.js, `pandoc`, et un navigateur Chromium (Microsoft Edge ou Chrome).

## Licence

Contenu pédagogique sous CC BY-NC-SA 4.0. Code de l'app vulnérable sous MIT, à usage strictement pédagogique. Détails dans [`LICENSE`](./LICENSE).

## Auteur

Hamza Abid · [github.com/AbidHamza](https://github.com/AbidHamza)

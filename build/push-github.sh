#!/usr/bin/env bash
# push-github.sh — Initialise le repo et push sur GitHub
# Usage: bash build/push-github.sh

set -e
cd "$(dirname "$0")/.."

REPO_NAME="dev-securise-m1-10h"
GH_USER="AbidHamza"
DESCRIPTION="Cours en ligne 10h · Développement Sécurisé Master 1 · Format grand TP autonome guidé (audit + correction + test) · Application Node.js vulnérable fournie + 7 modules + rapport pro"

echo "=== Init Git ==="
if [ ! -d .git ]; then
  git init -b main
fi

echo "=== Stage files ==="
git add .gitignore LICENSE README.md
git add modules/
git add vuln-app/
git add corrections/ 2>/dev/null || true
git add templates/
git add checklists/
git add grids/
git add quiz/
git add assets/
git add build/build-pdf.js build/preface.md build/cover-cours-complet.html build/html-template.html build/push-github.sh
git add build/pdf/

# PDFs racine (livrable principal)
git add COURS-COMPLET.pdf 2>/dev/null || true

echo "=== Vérif aucun secret commité ==="
if git diff --cached | grep -iE "password|secret|api[_-]?key" | grep -vE "^\+\+\+|^---|^@@|VULNERABILITIES|module\.md|README" | head -5; then
  echo "⚠ Détection de mots-clés sensibles ci-dessus — VÉRIFIER avant push !"
fi

echo "=== Commit ==="
git commit -m "feat: cours développement sécurisé M1 (10h) — 7 modules + app vulnérable + livrable PDF

- 7 modules au format audit/correction/test/trace
- Application Node.js + Express + SQLite volontairement vulnérable (14 failles)
- Templates : rapport d'audit, checklist OWASP, grille évaluation, quiz 25 QCM
- PDFs livrables : 1 cours complet + 7 modules
- Format 100 % pratique pour grand TP autonome guidé

Auteur : Hamza Abid · OmniLearning Consulting Commerce LLC"

echo "=== Création repo GitHub ==="
if gh repo view "$GH_USER/$REPO_NAME" >/dev/null 2>&1; then
  echo "Repo existe déjà — push sur main"
  git remote get-url origin >/dev/null 2>&1 || git remote add origin "https://github.com/$GH_USER/$REPO_NAME.git"
else
  gh repo create "$GH_USER/$REPO_NAME" --public --description "$DESCRIPTION" --source=. --remote=origin --push
  echo "=== ✅ Repo créé et pushé ==="
  echo "URL : https://github.com/$GH_USER/$REPO_NAME"
  exit 0
fi

echo "=== Push ==="
git push -u origin main

echo "=== ✅ Done ==="
echo "URL : https://github.com/$GH_USER/$REPO_NAME"

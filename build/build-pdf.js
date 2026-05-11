/**
 * build-pdf.js — Compile cours complet + 7 PDFs modules
 *
 * Workflow:
 *   1) pandoc MD → HTML body
 *   2) Wrap in template with CSS éditorial
 *   3) Chrome headless → PDF
 *
 * Usage: node build-pdf.js
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const BUILD = path.join(ROOT, 'build');
const HTML_OUT = path.join(BUILD, 'html');
const PDF_OUT = path.join(BUILD, 'pdf');
const CSS = path.join(ROOT, 'assets/css/editorial.css').replace(/\\/g, '/');
// Edge (Chromium sans services Google bloquants) — fallback Chrome si absent
const CHROME = fs.existsSync('C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe')
  ? 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'
  : 'C:/Program Files/Google/Chrome/Application/chrome.exe';

fs.mkdirSync(HTML_OUT, { recursive: true });
fs.mkdirSync(PDF_OUT, { recursive: true });

// Pas de Google Fonts (réseau bloque Chrome headless). Fallback system fonts via CSS.
const FONTS = `<style>
  /* Bypass Google Fonts — utilise system fonts only pour build PDF rapide */
  body { font-family: Georgia, "Times New Roman", "Cambria", serif !important; }
  h1, h2, h3, h4, .cover h1, .toc-section { font-family: Georgia, "Times New Roman", serif !important; }
  code, pre { font-family: "Cascadia Code", "Consolas", "Courier New", monospace !important; }
  .eyebrow, .meta, thead th, .step .step-num, .concept-box .tag, .quiz-q .q-num, .toc-section, .module-tag, .mod-num, .sev, .callout strong { font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif !important; }
</style>`;

/** Render markdown → HTML body with pandoc */
function md2html(mdPath) {
  // Pas de raw_html — toute balise dans le MD est échappée (sécurité PDF : aucun script ne tourne)
  const cmd = `pandoc "${mdPath}" -f markdown+grid_tables+pipe_tables-raw_html -t html5 --syntax-highlighting=none`;
  return execSync(cmd, { encoding: 'utf8', maxBuffer: 40 * 1024 * 1024 });
}

/** Wrap body in full HTML document */
function wrap(title, bodyHtml, withCover = null) {
  return `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'self' 'unsafe-inline' data:; script-src 'none'; object-src 'none'; base-uri 'none'">
<title>${title}</title>
${FONTS}
<link rel="stylesheet" href="file:///${CSS}">
</head>
<body>
${withCover ? withCover : ''}
<section style="padding: 0;">
${bodyHtml}
</section>
</body>
</html>`;
}

/** Chrome headless: HTML → PDF */
function html2pdf(htmlPath, pdfPath) {
  const tmpDir = path.join(BUILD, 'chrome-tmp-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8));
  const flags = [
    '--headless=old',
    '--disable-gpu',
    '--no-pdf-header-footer',
    '--print-to-pdf-no-header',
    '--no-sandbox',
    '--disable-extensions',
    '--disable-component-update',
    '--disable-background-networking',
    '--disable-default-apps',
    '--disable-sync',
    '--disable-translate',
    '--no-default-browser-check',
    '--no-first-run',
    '--metrics-recording-only',
    '--mute-audio',
    '--safebrowsing-disable-auto-update',
    '--disable-features=Translate,OptimizationHints,InterestFeedContentSuggestions',
    '--virtual-time-budget=15000',
    '--run-all-compositor-stages-before-draw',
    '--user-data-dir=' + tmpDir,
  ].join(' ');
  const cmd = `"${CHROME}" ${flags} --print-to-pdf="${pdfPath}" "file:///${htmlPath.replace(/\\/g, '/')}"`;
  console.log(`  → ${path.basename(pdfPath)}`);
  execSync(cmd, { stdio: 'inherit', timeout: 90000 });
}

/** Build cover for a single module */
function moduleCover(num, title) {
  return `<section class="divider">
    <div class="mod-num">MODULE ${num}</div>
    <div class="mod-title">${title}</div>
  </section>`;
}

const MODULES = [
  { num: 1, slug: 'M1', title: 'Cadrer avant de coder' },
  { num: 2, slug: 'M2', title: 'Verrouiller l\'authentification' },
  { num: 3, slug: 'M3', title: 'Décider qui peut quoi' },
  { num: 4, slug: 'M4', title: 'Filtrer ce qui entre, échapper ce qui sort' },
  { num: 5, slug: 'M5', title: 'Durcir le navigateur et le canal' },
  { num: 6, slug: 'M6', title: 'Sortir les secrets du code' },
  { num: 7, slug: 'M7', title: 'Auditer, prouver, rendre' },
];

console.log('\n=== Build PDFs individuels par module ===\n');

const moduleBodies = [];

for (const m of MODULES) {
  const mdPath = path.join(ROOT, 'modules', m.slug, 'module.md');
  if (!fs.existsSync(mdPath)) {
    console.log(`  ⚠ ${m.slug} : module.md absent, skip`);
    continue;
  }
  console.log(`[${m.slug}] ${m.title}`);
  const body = md2html(mdPath);
  const cover = moduleCover(m.num, m.title);
  const html = wrap(`Module ${m.num} — ${m.title}`, body, cover);
  const htmlPath = path.join(HTML_OUT, `${m.slug}.html`);
  fs.writeFileSync(htmlPath, html, 'utf8');
  const pdfPath = path.join(PDF_OUT, `Module-${m.num}-${m.slug}.pdf`);
  html2pdf(htmlPath, pdfPath);
  moduleBodies.push({ ...m, cover, body });
}

console.log('\n=== Build PDF cours complet ===\n');

/** Build full course PDF */
const coverFull = fs.readFileSync(path.join(BUILD, 'cover-cours-complet.html'), 'utf8');
const prefaceBody = md2html(path.join(BUILD, 'preface.md'));
const projetsBody = md2html(path.join(ROOT, 'templates/projets-fil-rouge.md'));
const rapportBody = md2html(path.join(ROOT, 'templates/rapport-audit-template.md'));
const checklistBody = md2html(path.join(ROOT, 'checklists/owasp-checklist-etudiant.md'));
const quizBody = md2html(path.join(ROOT, 'quiz/quiz-final.md'));

let fullBody = coverFull
  + `<section style="padding: 0 18mm;">` + prefaceBody + `</section>`
  + `<div class="page-break"></div>`
  + `<section style="padding: 0 18mm;">` + projetsBody + `</section>`;

for (const m of moduleBodies) {
  fullBody += m.cover + `<section style="padding: 0 18mm;">` + m.body + `</section>`;
}

fullBody += `
<section class="divider">
  <div class="mod-num">PARTIE III</div>
  <div class="mod-title">Annexes</div>
  <div class="mod-duration">Modèle de rapport, checklist et quiz</div>
</section>
<section style="padding: 0 18mm;">
<h1>Annexe A. Modèle de rapport d'audit</h1>
${rapportBody}
<div class="page-break"></div>
<h1>Annexe B. Checklist OWASP</h1>
${checklistBody}
<div class="page-break"></div>
<h1>Annexe C. Quiz d'auto-vérification</h1>
${quizBody}
</section>`;

const fullHtml = `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Développement Sécurisé M1 · Cours complet</title>
${FONTS}
<link rel="stylesheet" href="file:///${CSS}">
</head>
<body>
${fullBody}
</body>
</html>`;

const fullHtmlPath = path.join(HTML_OUT, 'cours-complet.html');
fs.writeFileSync(fullHtmlPath, fullHtml, 'utf8');
const fullPdfPath = path.join(ROOT, 'COURS-COMPLET.pdf');
html2pdf(fullHtmlPath, fullPdfPath);

console.log('\n✅ Build terminé.\n');
console.log(`  Cours complet : ${fullPdfPath}`);
console.log(`  Modules :       ${PDF_OUT}\\Module-*.pdf`);

/**
 * app.js — Utilitaires frontend partagés
 * VULN M5: token stocké en localStorage (accessible à tout script JS, XSS-ready)
 */

/**
 * Affiche un message dans un élément de la page.
 * @param {string} elementId - ID de l'élément cible
 * @param {string} message   - Texte à afficher
 */
function showMsg(elementId, message) {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.textContent  = message;
  el.style.display = 'block';
  setTimeout(() => { el.style.display = 'none'; }, 5000);
}

/**
 * Retourne le token JWT stocké dans localStorage.
 * VULN M5: stocké en localStorage => lisible par n'importe quel script JS injecté (XSS)
 * @returns {string|null}
 */
function getToken() {
  return localStorage.getItem('token');
}

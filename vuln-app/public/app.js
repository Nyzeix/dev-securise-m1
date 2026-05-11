/**
 * app.js — Utilitaires frontend partagés
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

async function logout() {
  await fetch('/auth/logout', {
    method: 'POST',
    credentials: 'include'
  });
  window.location.href = 'login.html';
}

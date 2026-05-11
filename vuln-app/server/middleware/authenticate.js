const jwt = require('jsonwebtoken');

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  const cookieToken = req.cookies && req.cookies.token;
  const bearerToken = authHeader && authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)
    : null;
  const token = bearerToken || cookieToken;

  if (!token) {
    return res.status(401).json({ error: 'Non authentifie' });
  }

  if (!process.env.JWT_SECRET) {
    return res.status(500).json({ error: 'JWT_SECRET manquant' });
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    return next();
  } catch (_err) {
    return res.status(401).json({ error: 'Token invalide' });
  }
}

module.exports = authenticate;
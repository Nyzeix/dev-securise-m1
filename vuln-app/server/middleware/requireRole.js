function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Non authentifie' });
    }
    if (req.user.role !== role) {
      return res.status(403).json({ error: 'Acces interdit' });
    }
    return next();
  };
}

module.exports = requireRole;
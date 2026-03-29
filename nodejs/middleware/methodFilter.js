'use strict';

function createMethodFilterMiddleware(config) {
  const allowed = new Set(config.allowedMethods.map((m) => m.toUpperCase()));
  const allowHeader = [...allowed].join(', ');

  return function methodFilterMiddleware(req, res, next) {
    if (!allowed.has(req.method.toUpperCase())) {
      res.set('Allow', allowHeader);
      return res.status(405).json({
        blocked: true,
        rule: 'method-not-allowed',
        message: `Method ${req.method} is not permitted`,
      });
    }
    next();
  };
}

module.exports = createMethodFilterMiddleware;

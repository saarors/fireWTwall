'use strict';

/**
 * Reject requests whose Content-Length exceeds the configured limit.
 * Also aborts requests that stream more data than the limit even if
 * Content-Length is absent or incorrect.
 */
function createRequestSizeMiddleware(config) {
  const maxBytes = config.maxBodySize;

  return function requestSizeMiddleware(req, res, next) {
    const contentLength = parseInt(req.headers['content-length'] || '0', 10);

    if (!isNaN(contentLength) && contentLength > maxBytes) {
      return res.status(413).json({
        blocked: true,
        rule: 'request-size',
        message: 'Request entity too large',
      });
    }

    // Guard against missing / spoofed Content-Length by counting streamed bytes
    let received = 0;
    let aborted = false;

    req.on('data', (chunk) => {
      if (aborted) return;
      received += chunk.length;
      if (received > maxBytes) {
        aborted = true;
        req.destroy();
        if (!res.headersSent) {
          res.status(413).json({
            blocked: true,
            rule: 'request-size',
            message: 'Request entity too large',
          });
        }
      }
    });

    next();
  };
}

module.exports = createRequestSizeMiddleware;

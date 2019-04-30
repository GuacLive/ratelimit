
/**
 * Module dependencies.
 */

const debug = require('debug')('micro-ratelimit2');
const Limiter = require('ratelimiter');
const ms = require('ms');

/**
 * Expose `ratelimit()`.
 */

module.exports = ratelimit;

/**
 * Initialize ratelimit middleware with the given `opts`:
 *
 * - `duration` limit duration in milliseconds [1 hour]
 * - `max` max requests per `id` [2500]
 * - `db` database connection
 * - `id` id to compare requests [ip]
 * - `headers` custom header names
 * - `remaining` remaining number of requests ['X-RateLimit-Remaining']
 * - `reset` reset timestamp ['X-RateLimit-Reset']
 * - `total` total number of requests ['X-RateLimit-Limit']
 * - `whitelist` whitelist function [false]
 * - `blacklist` blacklist function [false]
 *
 * @param {Object} opts
 * @return {Function}
 * @api public
 */
 function keyGenerator(req) {
  return req.headers['x-forwarded-for'] ||
    req.connection.remoteAddress ||
    req.socket.remoteAddress ||
    req.connection.socket.remoteAddress
}
function ratelimit(opts = {}, handler) {
  if (!handler) {
    handler = opts;
    opts = {};
  }
  const {
    remaining = 'X-RateLimit-Remaining',
    reset = 'X-RateLimit-Reset',
    total = 'X-RateLimit-Limit'
  } = opts.headers || {}

  return async function ratelimit(req, res) {
    const id = opts.id ? opts.id(req) : keyGenerator(req);
    const whitelisted = typeof opts.whitelist === 'function' ? await opts.whitelist(req) : false;
    const blacklisted = typeof opts.blacklist === 'function' ? await opts.blacklist(req) : false;

    if (blacklisted) {
      const err = new Error('Forbidden')
      err.statusCode = 493
      throw err
    }

    if (false === id || whitelisted) return await handler(req, res);

    // initialize limiter
    const limiter = new Limiter(Object.assign({}, opts, { id }));

    // check limit
    const limit = await thenify(limiter.get.bind(limiter));

    // check if current call is legit
    const calls = limit.remaining > 0 ? limit.remaining - 1 : 0;

    // check if header disabled
    const disableHeader = opts.disableHeader || false;

    if (!disableHeader) {
      res.setHeader(total, limit.total)
      res.setHeader(remaining, calls)
      res.setHeader(reset, limit.reset)
    }

    debug('remaining %s/%s %s', remaining, limit.total, id);
    if (limit.remaining) return await handler(req, res);

    const delta = (limit.reset * 1000) - Date.now() | 0;
    const after = limit.reset - (Date.now() / 1000) | 0;
    res.setHeader('Retry-After', after);

    res.statusCode = 429;

    if (opts.throw) {
      const err = new Error(res.body)
      err.statusCode = res.statusCode
      throw err
    }
    res.end(opts.errorMessage || `Rate limit exceeded, retry in ${ms(delta, { long: true })}.`);
  }
}

/**
 * Helper function to convert a callback to a Promise.
 */

async function thenify(fn) {
  return await new Promise(function(resolve, reject) {
    function callback(err, res) {
      if (err) return reject(err);
      return resolve(res);
    }

    fn(callback);
  });
}

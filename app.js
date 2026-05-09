const assert = require('assert');
const config = require('config');
const pino = require('pino');
const Srf = require('drachtio-srf');
const srf = new Srf() ;
const logger = srf.locals.logger = pino();
let callHandler;

if (config.has('drachtio.host')) {
  logger.info(config.get('drachtio'), 'attempting inbound connection');
  srf.connect(config.get('drachtio'));
  srf
    .on('connect', (err, hp) => { logger.info(`inbound connection to drachtio listening on ${hp}`);})
    .on('error', (err) => { logger.error(err, `Error connecting to drachtio server: ${err}`); });
}
else {
  logger.info(config.get('drachtio'), 'listening for outbound connections');
  srf.listen(config.get('drachtio'));
}

if (config.has('rtpengine')) {
  logger.info(config.get('rtpengine'), 'using rtpengine as the recorder');
  callHandler = require('./lib/rtpengine-call-handler');
  // start DTMF listener
  require('./lib/dtmf-event-handler')(logger);

  // we only want to deal with siprec invites (having multipart content) in this application
  srf.use('invite', (req, res, next) => {
    const ctype = req.get('Content-Type') || '';
    if (!ctype.includes('multipart/mixed')) {
      logger.info(`rejecting non-SIPREC INVITE with call-id ${req.get('Call-ID')}`);
      return res.send(488);
    }
    next();
  });

  // Defense-in-depth source-IP allowlist on top of the GCP firewall.
  // Empty list = unset = accept-all (dev-friendly); production envs MUST
  // set SIPREC_ALLOWED_SOURCES to the same CIDR list as the firewall rule.
  const ALLOWED_SOURCES = (process.env.SIPREC_ALLOWED_SOURCES || '')
    .split(',')
    .map((s) => s.trim().replace(/\/32$/, ''))
    .filter(Boolean);

  if (ALLOWED_SOURCES.length === 0) {
    logger.warn('SIPREC_ALLOWED_SOURCES is unset — recorder will accept INVITEs from any source IP');
  }
  else {
    logger.info({allowed: ALLOWED_SOURCES}, 'SIPREC source-IP allowlist active');
  }

  srf.use('invite', (req, res, next) => {
    if (ALLOWED_SOURCES.length === 0) return next();
    const src = req.source_address;
    if (!ALLOWED_SOURCES.includes(src)) {
      logger.warn(`rejecting INVITE from ${src} (call-id ${req.get('Call-ID')}): not in SIPREC allowlist`);
      return res.send(403, 'Source IP not in SIPREC allowlist');
    }
    next();
  });

}
else if (config.has('freeswitch')) {
  logger.info(config.get('freeswitch'), 'using freeswitch as the recorder');
  callHandler = require('./lib/freeswitch-call-handler')(logger);
}
else {
  assert('recorder type not specified in configuration: must be either rtpengine or freeswitch');
}

srf.invite(callHandler);

module.exports = srf;

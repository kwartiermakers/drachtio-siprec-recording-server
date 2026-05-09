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
  // set SIPREC_ALLOWED_SOURCES to the same external-source CIDR list as
  // the firewall rule.
  //
  // RFC1918 / loopback sources (own opensips proxy forking SIPREC over
  // VPC, sidecar processes, etc.) are always allowed. The boundary the
  // allowlist defends is the public network — once a packet has crossed
  // GCP's VPC perimeter it has already passed both the firewall and
  // private-network gating, so re-checking it here would just block our
  // own traffic.
  const ALLOWED_SOURCES = (process.env.SIPREC_ALLOWED_SOURCES || '')
    .split(',')
    .map((s) => s.trim().replace(/\/32$/, ''))
    .filter(Boolean);

  if (ALLOWED_SOURCES.length === 0) {
    logger.warn('SIPREC_ALLOWED_SOURCES is unset — recorder will accept INVITEs from any public source IP');
  }
  else {
    logger.info({allowed: ALLOWED_SOURCES}, 'SIPREC source-IP allowlist active for public sources');
  }

  function isPrivateIp(ip) {
    if (!ip) return false;
    if (ip === '::1' || ip.startsWith('fe80:') || ip.startsWith('fc') || ip.startsWith('fd')) return true;
    if (ip.startsWith('127.') || ip.startsWith('10.') || ip.startsWith('192.168.')) return true;
    const m = ip.match(/^172\.(\d+)\./);
    if (m && +m[1] >= 16 && +m[1] <= 31) return true;
    return false;
  }

  srf.use('invite', (req, res, next) => {
    const src = req.source_address;
    if (isPrivateIp(src)) return next();
    if (ALLOWED_SOURCES.length === 0) return next();
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

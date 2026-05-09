const parseSiprecPayload = require('./payload-parser');
const constructSiprecPayload = require('./payload-combiner');
const {getAvailableRtpengine} = require('./utils');
const cdr = require('./cdr');
const { v4 } = require('uuid');
const debug = require('debug')('drachtio:siprec-recording-server');

function isPrivateIp(ip) {
  if (!ip) return false;
  if (ip === '::1' || ip.startsWith('fe80:') || ip.startsWith('fc') || ip.startsWith('fd')) return true;
  if (ip.startsWith('127.') || ip.startsWith('10.') || ip.startsWith('192.168.')) return true;
  const m = ip.match(/^172\.(\d+)\./);
  if (m && +m[1] >= 16 && +m[1] <= 31) return true;
  return false;
}

module.exports = (req, res) => {
  const callid = req.get('Call-ID');
  const from = req.getParsedHeader('From');
  const totag = v4();
  const logger = req.srf.locals.logger.child({callid});
  // SIPREC INVITEs from our own proxy (RFC1918) carry forwarded media: the
  // proxy's rtpengine has already terminated DTLS/SDES on each leg and is
  // forking cleartext to us. If we negotiate SRTP back, the proxy rtpengine
  // can't fork through a fresh DTLS handshake and the b2b/rtp_relay chain
  // breaks (visible as "Unknown call-id" + b2bl_parse_key errors on opensips).
  // External SBCs send media directly and may legitimately want SRTP, so we
  // accept whatever they offer there.
  const internalSource = isPrivateIp(req.source_address);
  const opts = {
    req,
    res,
    logger,
    internalSource,
    callDetails: {
      'call-id': callid,
      'from-tag': from.params.tag
    }
  };

  logger.info({source: req.source_address, internalSource}, `received SIPREC invite: ${req.uri}`);
  const rtpEngine = getAvailableRtpengine();

  parseSiprecPayload(opts)
    .then(allocateEndpoint.bind(null, 'caller', rtpEngine, totag))
    .then(allocateEndpoint.bind(null, 'callee', rtpEngine, totag))
    .then(respondToInvite)
    .then((dlg) => {
      logger.info(`call connected successfully, using rtpengine at ${JSON.stringify(rtpEngine.remote)}`);
      cdr.postStart(opts);
      dlg.on('modify', _onReinvite.bind(null, rtpEngine, logger, totag));
      return dlg.on('destroy', onCallEnd.bind(null, rtpEngine, opts));
    })
    .catch((err) => {
      logger.error(`Error connecting call: ${err}`);
    });
};

function _onReinvite(rtpEngine, logger, totag, req, res) {
  const callid = req.get('Call-ID');
  const from = req.getParsedHeader('From');
  const opts = {
    req,
    res,
    logger,
    internalSource: isPrivateIp(req.source_address),
    callDetails: {
      'call-id': callid,
      'from-tag': from.params.tag,
    }
  };

  parseSiprecPayload(opts)
    .then(allocateEndpoint.bind(null, 'caller', rtpEngine, totag))
    .then(allocateEndpoint.bind(null, 'callee', rtpEngine, totag))
    .then((opts) => {
      const body = constructSiprecPayload(opts.rtpengineCallerSdp, opts.rtpengineCalleeSdp, opts.sdp1, opts.sdp2);
      return opts.res.send(200, {body});
    })
    .catch((err) => {
      logger.error(`Error connecting call: ${err}`);
    });

  logger.info(`received SIPREC Re-invite: ${req.uri}`);
}

function allocateEndpoint(which, rtpEngine, totag, opts) {
  // If audio is inactive, rtpengine will stop recording and there is no blank audio in record file.
  const sdp = (which === 'caller' ? opts.sdp1 : opts.sdp2).replace(/a=inactive\r\n/g, 'a=sendonly\r\n');
  const cryptoArgs = opts.internalSource ? {
    // Internal proxy fork: force cleartext output. The forwarder upstream
    // can't bring DTLS/SDES, so any encryption advertised by the SIPREC
    // INVITE m= lines (e.g. UDP/TLS/RTP/SAVPF from a WebRTC leg) must be
    // stripped before we answer. transport protocol=RTP/AVP downgrades
    // every m= line to cleartext.
    'transport protocol': 'RTP/AVP',
    'DTLS': 'off',
    'SDES': 'off',
  } : {
    // External SBC: accept either SRTP (SDES or DTLS-SRTP) or plain RTP.
    // No transport protocol force, so we mirror whatever the SBC offers.
    'DTLS': 'allow',
    'SDES': 'allow',
  };
  const args = Object.assign({}, opts.callDetails, {
    sdp,
    'replace': ['origin', 'session-connection'],
    'record call': 'yes',
    'ICE': 'remove',
    'flags': ['media handover', 'port latching'],
    'rtcp-mux': ['accept'],
    'direction':  ['public', 'public'],
  }, cryptoArgs);
  if (which === 'callee') Object.assign(args, {'to-tag': totag});

  debug(`callDetails: ${JSON.stringify(opts.callDetails)}`);
  debug(`rtpengine args for ${which}: ${JSON.stringify(args)}, sending to ${JSON.stringify(rtpEngine.remote)}`);
  return rtpEngine[which === 'caller' ? 'offer' : 'answer'](rtpEngine.remote, args)
    .then((response) => {
      if (response.result !== 'ok') {
        throw new Error('error connecting to rtpengine');
      }
      opts[which === 'caller' ? 'rtpengineCallerSdp' : 'rtpengineCalleeSdp'] = response.sdp;
      return opts;
    });
}

function respondToInvite(opts) {
  const srf = opts.req.srf;
  const payload = constructSiprecPayload(opts.rtpengineCallerSdp, opts.rtpengineCalleeSdp, opts.sdp1, opts.sdp2);
  return srf.createUAS(opts.req, opts.res, {localSdp: payload});
}

function onCallEnd(rtpEngine, opts) {
  opts.logger.info('call ended');
  cdr.postEnd(opts);
  return rtpEngine.delete(rtpEngine.remote, opts.callDetails)
    .then((response) => {
      return debug(`response to rtpengine delete: ${JSON.stringify(response)}`);
    });
}

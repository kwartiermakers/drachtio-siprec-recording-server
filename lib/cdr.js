/* global fetch */
// CDR posting for the Sainer SIPREC SRS.
//
// Posts a JSON CDR to CDR_ENDPOINT on session start and again on session end,
// using HTTP Basic auth (CDR_AUTH_USER / CDR_AUTH_PASSWORD). The backend
// upserts on `variables.uuid`, so both posts share the same uuid and the end
// post overwrites with the final timestamps + duration.
//
// Disabled (no-op) when CDR_ENDPOINT is unset.

const ENDPOINT = process.env.CDR_ENDPOINT;
const USER = process.env.CDR_AUTH_USER || '';
const PASSWORD = process.env.CDR_AUTH_PASSWORD || '';

const enabled = Boolean(ENDPOINT);
const authHeader = (USER || PASSWORD)
  ? 'Basic ' + Buffer.from(`${USER}:${PASSWORD}`).toString('base64')
  : null;

// FreeSWITCH-style "YYYY-MM-DD HH:MM:SS" UTC, matching the existing
// /sainer/cdr payload shape posted by mod_json_cdr.
function isoStamp(date) {
  const pad = (n) => String(n).padStart(2, '0');
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ` +
    `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}`;
}

function buildBase(opts) {
  const uuid = opts.originalCallId || opts.recordingSessionId || opts.sessionId;
  return {
    'core-uuid': opts.recordingSessionId || opts.sessionId,
    variables: {
      uuid,
      cdr_source: 'siprec',
      caller_id_number: opts.caller && opts.caller.number,
      caller_id_name: opts.caller && opts.caller.name,
      destination_number: opts.callee && opts.callee.number,
      sip_from_uri: opts.caller && opts.caller.aor,
      sip_to_uri: opts.callee && opts.callee.aor,
      siprec_call_id: opts.callDetails && opts.callDetails['call-id'],
      siprec_session_id: opts.recordingSessionId,
      siprec_original_call_id: opts.originalCallId,
    },
  };
}

// Fire-and-forget. Failures must not block call processing.
function send(payload, logger) {
  const headers = { 'Content-Type': 'application/json' };
  if (authHeader) headers.Authorization = authHeader;
  return fetch(ENDPOINT, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
  })
    .then((res) => {
      if (!res.ok) {
        logger.warn({ status: res.status, uuid: payload.variables.uuid }, 'CDR POST returned non-2xx');
      }
      return null;
    })
    .catch((err) => {
      logger.warn({ err: err.message, uuid: payload.variables.uuid }, 'CDR POST failed');
      return null;
    });
}

module.exports.enabled = enabled;

module.exports.postStart = function postStart(opts) {
  if (!enabled) return;
  const startedAt = new Date();
  opts.cdrStartedAt = startedAt;
  const cdr = buildBase(opts);
  cdr.variables.start_stamp = isoStamp(startedAt);
  cdr.variables.event = 'session_start';
  send(cdr, opts.logger);
};

module.exports.postEnd = function postEnd(opts) {
  if (!enabled) return;
  const endedAt = new Date();
  const startedAt = opts.cdrStartedAt || endedAt;
  const cdr = buildBase(opts);
  cdr.variables.start_stamp = isoStamp(startedAt);
  cdr.variables.end_stamp = isoStamp(endedAt);
  cdr.variables.duration = String(Math.max(0, Math.round((endedAt - startedAt) / 1000)));
  cdr.variables.hangup_cause = opts.hangupCause || 'NORMAL_CLEARING';
  cdr.variables.event = 'session_end';
  send(cdr, opts.logger);
};

// Message view: X-Road header fields, raw message.xml, and
// attachments for download, from the verifier core's container reader and
// header parser.
//
// Everything here is untrusted container data. The UI renders it only as
// escaped text, and offers attachments only as downloads.

import { CodedError, type MessageHeaderView, parseMessage, readContainer } from '@xrav/verifier';

export interface HeaderField {
  label: string;
  value: string;
}

export interface AttachmentFile {
  /** Entry name inside the container, e.g. `attachment1` (no leading slash). */
  name: string;
  bytes: Uint8Array;
}

export interface MessageView {
  kind: 'soap' | 'rest-request' | 'rest-response' | 'unknown';
  /** Request or response; null when the message does not parse far enough to tell. */
  direction: 'request' | 'response' | null;
  /** Ordered header fields: client, service, queryId, userId, protocolVersion, … */
  fields: HeaderField[];
  /** REST request line (`GET /r1/…`) or status line (`200 OK`), if REST. */
  restLine: string | null;
  /** message.xml as text (it is a REST message, not XML, for REST). */
  rawMessage: string;
  attachments: AttachmentFile[];
}

export type MessageViewResult = { status: 'ok'; view: MessageView } | { status: 'error'; message: string };

/**
 * Read the container and parse its message. A container the core cannot read
 * (missing mimetype, broken zip, over the limits, …) yields `error`; the
 * verdict from verifyContainer is shown regardless.
 */
export async function loadMessageView(bytes: Uint8Array): Promise<MessageViewResult> {
  let container;
  try {
    container = await readContainer(bytes);
  } catch (e) {
    const reason = e instanceof CodedError ? e.faultString : e instanceof Error ? e.message : String(e);
    return { status: 'error', message: `Could not read the container: ${reason}` };
  }

  const parsed = parseMessage(container);
  const h = parsed.header;
  const kind: MessageView['kind'] =
    parsed.kind === 'soap'
      ? 'soap'
      : parsed.direction === 'request'
        ? 'rest-request'
        : parsed.direction === 'response'
          ? 'rest-response'
          : 'unknown';

  const attachments = [...container.attachments]
    .map(([name, data]) => ({ name: name.replace(/^\/+/, ''), bytes: data }))
    .sort((x, y) => x.name.localeCompare(y.name, undefined, { numeric: true }));

  return {
    status: 'ok',
    view: {
      kind,
      direction: parsed.direction,
      fields: headerFields(h),
      restLine: restLine(h),
      rawMessage: container.get('message.xml') ?? '',
      attachments,
    },
  };
}

const FIELDS: [keyof MessageHeaderView, string][] = [
  ['client', 'Client'],
  ['service', 'Service'],
  ['serviceName', 'Body element'],
  ['queryId', 'Query ID'],
  ['requestId', 'Request ID'],
  ['userId', 'User ID'],
  ['issue', 'Issue'],
  ['protocolVersion', 'Protocol version'],
  ['securityServer', 'Security server'],
  ['representedParty', 'Represented party'],
  ['requestHash', 'Request hash'],
];

function headerFields(h: MessageHeaderView): HeaderField[] {
  const out: HeaderField[] = [];
  for (const [key, label] of FIELDS) {
    const value = h[key];
    if (typeof value !== 'string') continue;
    if (key === 'requestHash' && h.requestHashAlgorithm) {
      out.push({ label, value: `${value} (${h.requestHashAlgorithm})` });
    } else {
      out.push({ label, value });
    }
  }
  return out;
}

function restLine(h: MessageHeaderView): string | null {
  if (h.verb != null && h.path != null) return `${h.verb} ${h.path}${h.query != null ? `?${h.query}` : ''}`;
  if (h.status != null) return h.reason ? `${h.status} ${h.reason}` : h.status;
  return null;
}

/**
 * Status of one signed attachment digest, in the UI's terms.
 *
 * `verified:false` alone does not mean tampering. Valid messagelog containers
 * often list `/attachmentN` digests whose entries are not in the container at
 * all (the jar prints `(unverified)` for those too). So:
 *   verified        digest matches the attachment bytes
 *   mismatch        the attachment IS in the container but does not match (amber)
 *   absent          not in the container, so not checked (neutral)
 *   unknown         container contents unknown (the container could not be read)
 */
export type DigestStatus = 'verified' | 'mismatch' | 'absent' | 'unknown';

export function digestStatus(
  d: { uri: string; verified: boolean },
  attachments: readonly AttachmentFile[] | null,
): DigestStatus {
  if (d.verified) return 'verified';
  if (!attachments) return 'unknown';
  const name = d.uri.replace(/^\//, '');
  return attachments.some((a) => a.name === name) ? 'mismatch' : 'absent';
}

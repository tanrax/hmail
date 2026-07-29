# HMTP protocol specification

**Version 1** (the `v` field of every message).

HMTP (HTTP Mail Transfer Protocol) is a convention over HTTPS for delivering signed, end-to-end encrypted mail between independent nodes. This document is the normative wire specification: everything an implementation needs to interoperate with other nodes without reading the reference code. The design rationale lives in the article [Modern email can be built from borrowed parts](https://en.andros.dev/blog/d7ed8b07/modern-email-can-be-built-from-borrowed-parts/); how to run the reference node lives in the [README](README.md).

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as described in RFC 2119.

## 1. Addresses

An address has the form `user@domain`, where `domain` is the authority that serves the discovery document (a port is allowed for local development). The `user` part MUST be usable verbatim as a URL path segment.

## 2. Discovery

A node publishes each mailbox at:

```
GET https://<domain>/.well-known/hmtp/<user>
```

The response is `200` with a JSON document:

```json
{
  "address": "ana@example.com",
  "inbox": "https://mail.example.net/hmtp/inbox/ana",
  "signing_key": "<base64, 32-byte raw Ed25519 public key>",
  "encryption_key": "<base64, 32-byte raw X25519 public key>"
}
```

- `address`, `inbox` and `signing_key` are REQUIRED. `encryption_key` SHOULD be present; without it, mail to this user travels as plaintext `content` (section 4).
- `inbox` MAY live on any host: this document plays the role of the MX record, with per-user delegation. The inbox URL path is not normative; senders MUST use whatever URL the document declares.
- Unknown users get `404`.
- Keys are fetched live: consumers MUST NOT pin them. Fetching the current document on every verification is what makes key rotation instantaneous (and is also the model's weak point, see section 9).
- The document MUST be served over HTTPS. Everything in this spec that fetches a URL derived from an address (discovery, inbox) MUST resolve the host first and refuse private, loopback, link-local or otherwise non-global addresses (SSRF guard).

## 3. Canonical JSON

Signatures and ids are computed over a canonical serialization of JSON objects, following RFC 8785 (JCS). For the field names and value types used by this spec, the canonical form reduces to:

- Object keys sorted lexicographically by Unicode code point.
- No insignificant whitespace: separators are exactly `,` and `:`.
- Minimal string escaping: only `\"`, `\\`, the two-character escapes (`\b`, `\t`, `\n`, `\f`, `\r`) and `\u00XX` (lowercase hex) for the remaining control characters. Non-ASCII characters are NOT escaped.
- The result is encoded as UTF-8 bytes.

In Python this is `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()`. The only non-string scalar in this spec is the integer `v`, serialized without sign, padding or decimal point.

## 4. The message

A message on the wire is a JSON object:

```json
{
  "v": 1,
  "id": "sha256:<64 lowercase hex chars>",
  "from": "ana@example.com",
  "to": ["bob@example.org"],
  "date": "2026-07-29T12:00:00+00:00",
  "in_reply_to": "sha256:...",
  "sealed": {
    "cipher": "x25519-chacha20poly1305",
    "ephemeral_key": "<base64, 32-byte raw X25519 public key>",
    "nonce": "<base64, 12 bytes>",
    "data": "<base64 ciphertext>"
  },
  "signature": "<base64, 64-byte Ed25519 signature>"
}
```

- `v` (REQUIRED): integer protocol version. This spec defines `1`.
- `id` (REQUIRED): content address of the plaintext, see section 5.
- `from` (REQUIRED): sender address. The signature is verified against this domain's published `signing_key`.
- `to` (REQUIRED): array of recipient addresses. A message with N recipients is delivered as N copies, each sealed to one recipient's key; all copies carry the same `to` array and therefore the same `id`.
- `date` (REQUIRED): ISO 8601 timestamp in UTC with seconds precision.
- `in_reply_to` (OPTIONAL): the `id` of the message this one replies to. Threads are a verifiable graph of content hashes; no heuristics.
- Exactly one of (REQUIRED):
  - `sealed`: the encrypted content (section 6). Used whenever the recipient publishes an `encryption_key`.
  - `content`: the plaintext content object, only for recipients that publish no `encryption_key`.
- `signature` (REQUIRED): section 5.

The **content object** (plaintext, inside `sealed` or as `content`) is:

```json
{
  "subject": "a subject, possibly empty",
  "body": "the message text",
  "salt": "<base64, 16 random bytes>"
}
```

The subject travels inside the encrypted payload, as protected as the body; the visible envelope carries no human-readable content. The `salt` MUST be freshly random per message: since the `id` is a hash of the plaintext, without a salt the visible `id` would let anyone confirm a guessed short message.

## 5. Id and signature

**Id.** The *core* of a message is one flat object: the envelope fields `from`, `to`, `date` and (if present) `in_reply_to`, merged with the three content fields `subject`, `body`, `salt`. Then:

```
id = "sha256:" + lowercase_hex(SHA-256(canonical(core)))
```

The id is computed by the sender **before sealing** and is a property of the plaintext: every copy of a message shares it, thread references match across nodes, and retries are idempotent. Note that `v`, `id` itself, `sealed` and `signature` are not part of the core.

**Signature.** Ed25519 over the canonical form of the complete wire message minus the `signature` field: it covers `v` (downgrade protection), the envelope, the `id` and the ciphertext (or plaintext `content`). The verification key is the `signing_key` currently published at the `from` domain.

Because the signature covers the ciphertext and each copy is sealed per recipient, different copies of one message have different signatures but the same id.

## 6. Sealing (end-to-end encryption)

The only cipher suite in version 1 is `x25519-chacha20poly1305`:

1. Serialize the content object as JSON (any valid serialization; the recipient parses it and re-canonicalizes only for the id check). Encode as UTF-8.
2. Generate an ephemeral X25519 key pair.
3. `shared = X25519(ephemeral_private, recipient_encryption_key)`.
4. `key = HKDF-SHA256(ikm=shared, salt=<absent>, info=ephemeral_public_bytes || recipient_public_bytes, length=32)` where `||` is byte concatenation of the raw 32-byte public keys.
5. Generate a random 12-byte nonce.
6. `data = ChaCha20-Poly1305(key, nonce, plaintext, aad=<none>)`.

The `sealed` object carries the cipher name, the ephemeral public key, the nonce and the ciphertext, all base64. To decrypt, the recipient repeats the exchange with its private key; after a key rotation it SHOULD retry with retained old keys so old mail stays readable.

This suite is a minimal sealed box in the spirit of HPKE (RFC 9180), not the RFC's wire format. A future version could adopt HPKE proper; the `cipher` field exists so that can happen without ambiguity.

## 7. Delivery

Delivery is one HTTP request per recipient copy:

```
POST <inbox URL from the recipient's discovery document>
Content-Type: application/hmtp+json

<the message JSON>
```

Senders MUST send `Content-Type: application/hmtp+json`; receivers SHOULD also accept `application/json`.

Responses:

| Code | Meaning | Sender behavior |
|---|---|---|
| `201` | delivered and stored | done |
| `200` | duplicate: this `id` was already stored | done (a retry succeeded twice) |
| `400` | malformed message or unsupported `v` | give up |
| `401` | signature verification failed | give up |
| `402` | reserved for postage (section 12); receivers MUST NOT send it in version 1 | give up |
| `404` | unknown mailbox | give up |
| `413` | message too large (reference node caps at 64 000 bytes) | give up |
| `503` | receiver could not fetch the sender's keys right now | retry later |

Retry semantics, also for codes not in the table: every `4xx` is a **permanent rejection** and the sender MUST drop the message instead of retrying it; transport failures and `5xx` responses (in practice `503`) are retryable.

Store-and-forward lives on the **sender's** side: the client hands the signed message to its own node, and that node queues undeliverable copies and retries with exponential backoff (reference: 5 minutes doubling per attempt, capped at one day). Retries MUST resend the same message (same id), which makes them idempotent by construction.

## 8. Verification duties

**The receiving server** MUST perform all of these checks on every POST; the reference node applies them in this order:

1. Reject if the mailbox is unknown (`404`).
2. Reject if oversized (`413`).
3. Reject if `v` is not a supported version (`400`).
4. Reject if the shape is wrong: missing required fields, or not exactly one of `sealed` / `content` (`400`).
5. If the message carries plaintext `content`, check that `id` matches the core hash (`401` on mismatch). With `sealed` content the server cannot check this: it stores ciphertext it cannot read.
6. Fetch the discovery document of the `from` domain (SSRF guard applies). If unreachable, answer `503` so the sender retries.
7. Verify the Ed25519 signature over `canonical(message minus signature)` against the published `signing_key`. On failure, `401`.
8. Deduplicate by exact `id` string: store if new (`201`), acknowledge without storing if seen (`200`).

**The recipient**, when opening a message:

1. Unseal the content with its encryption key(s).
2. Rebuild the core (envelope fields + unsealed content fields) and recompute the id. If it does not match the message's `id`, the message MUST be treated as invalid (the sender lied about the content address; the reference client displays a marker instead of the content).

The split matters: the server authenticates *who sent it and that nothing was altered in transit*; the recipient additionally verifies *that the id really names this plaintext*.

## 9. Consent (receiver policy)

Receivers SHOULD keep a contacts set per mailbox:

- Mail from a known contact goes to the **inbox**.
- Mail from an unknown sender goes to a **requests** box, first message visible. Accepting a sender moves their mail to the inbox and admits them permanently.
- Sending a message to an address SHOULD add it to the sender's own contacts: writing to someone welcomes their replies.

This is local policy, not wire format: nodes with different consent rules still interoperate.

## 10. Test vector

A fully deterministic message (plaintext `content`, so no encryption randomness). Given:

- Ed25519 private key (raw seed, base64): `AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=` (bytes `00 01 02 ... 1f`)
- Corresponding public key (base64): `A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=`
- `from`: `ana@example.com`, `to`: `["bob@example.org"]`, `date`: `2026-07-29T12:00:00+00:00`
- content: subject `Test vector`, body `Hyvää yötä`, salt `MDEyMzQ1Njc4OWFiY2RlZg==` (the ASCII bytes `0123456789abcdef`)

Canonical core (one line, UTF-8):

```
{"body":"Hyvää yötä","date":"2026-07-29T12:00:00+00:00","from":"ana@example.com","salt":"MDEyMzQ1Njc4OWFiY2RlZg==","subject":"Test vector","to":["bob@example.org"]}
```

Resulting id:

```
sha256:fa30967952300d997b0f15084a77567386040d8a9fcb24bd62ba0d556471e396
```

Canonical signed payload (one line, UTF-8):

```
{"content":{"body":"Hyvää yötä","salt":"MDEyMzQ1Njc4OWFiY2RlZg==","subject":"Test vector"},"date":"2026-07-29T12:00:00+00:00","from":"ana@example.com","id":"sha256:fa30967952300d997b0f15084a77567386040d8a9fcb24bd62ba0d556471e396","to":["bob@example.org"],"v":1}
```

Resulting signature (base64):

```
RbTXfGkk6TJ69Kau9Pn2WSHvQ4tMJzAFs1a7pgEMZg6/yRIQQ2vVjr4PpcjfqKiZX9qf3HzaQtxEXjJTW2Y5Bw==
```

An implementation that reproduces the id and the signature byte for byte (Ed25519 is deterministic) canonicalizes, hashes and signs correctly. Note the body is intentionally non-ASCII: if your canonical form escapes `ä` as `\u00e4` instead of emitting the raw UTF-8 bytes, the hashes will not match (section 3).

## 11. Security considerations

- **What is protected**: subject and body are confidential end to end and the whole message is authenticated. **What is visible**: the envelope (`from`, `to`, `date`, `id`, `in_reply_to`) is readable by both servers; traffic analysis of who writes to whom is not addressed.
- **No forward secrecy**: an ephemeral key is used per message, but compromise of a recipient's long-term encryption key decrypts everything sealed to it, including retained old keys after rotation.
- **Identity is the domain**: keys are fetched live and never pinned, so whoever controls the domain (or its web server, or a CA willing to misissue) controls the identity. Rotation is instant for the same reason. A signed rotation chain would mitigate this and is deliberately out of scope for version 1.
- **Replay**: deduplication by id makes redelivery of the same message idempotent; the signed `to` field stops relaying a copy to a different mailbox as if intended for it. The signed `date` is sender-asserted and not proof of sending time.
- **Denial of service**: receivers verify signatures only after cheap shape and size checks, but fetching the sender's discovery document on every delivery is an amplification vector; receivers SHOULD cache discovery documents briefly and rate-limit per source.
- The reference implementation's cryptography is **unaudited**. Do not use it for secrets anyone depends on.

## 12. Out of scope in version 1

Decided and documented, not implemented: signed key-rotation chains, `402` postage for strangers, attachments by reference, JMAP reading (local to each node, outside interoperability scope), multi-device. The sketches below record the intended direction so version 1 implementations don't paint themselves into a corner; only the duties explicitly marked for version 1 are normative.

### Key rotation and recovery

Rotation already works in version 1 and imposes three duties on implementations:

- Verifiers MUST fetch the discovery document live and MUST NOT pin or long-cache keys (section 2): publishing new keys **is** the whole rotation ceremony, and the new key is trusted instantly.
- A node MUST retain its rotated-out encryption private keys, or sealed mail received before the rotation becomes unreadable (section 6).
- Know the limit: a stored signature is only re-verifiable while the signing key that produced it is still the published one. After a rotation, stored mail keeps its signature but can no longer be validated against the sender's domain.

The chain (future): the discovery document would grow a list of rotation entries, each new key signed by the previous one, so anyone who knew key N can verify key N+1 without trusting the server, and historical signatures stay verifiable against the chain. For recovery after losing a key (no signed handover possible), the domain would publish a chainless key with a mandatory announcement window during which receivers warn that the identity was re-anchored by domain, not by signature. Precedents: Keybase sigchains, and ATProto's `did:plc`, which keeps a hierarchy of rotation keys and a 72-hour window in which a higher-priority key can undo an operation.

### Postage (`402`)

Normative for version 1: receivers MUST NOT answer a delivery with `402`, and a sender that receives one MUST treat it as a permanent rejection (section 7), never as retryable. Reserving this now keeps version 1 nodes forward-compatible with postage.

The sketch: a receiver MAY answer a **first contact** (sender not in its contacts) with `402` plus machine-readable payment terms in a `WWW-Authenticate` challenge; the sender pays and re-sends the *same* message (same id) with proof of payment attached. Configurable per mailbox: the cost of cold contact stops being zero while accepted contacts keep writing for free. Precedent: L402, which pairs the `402` status with a macaroon-plus-invoice challenge in exactly this request, pay, retry shape.

### Multi-device

The article's discovery example reserves a `devices` field that version 1 omits on purpose. The direction: the discovery document would publish one encryption key per device and the sender would seal one copy of the content to each key. The id, being a hash of the plaintext, is unaffected; the shape of `sealed` is what a future version would extend, under a new `v`. The duty this leaves on version 1 is extensibility: implementations MUST ignore unknown fields in discovery documents and messages rather than reject them.

### Attachments

Version 1 messages are text only, capped by the receiver's size limit. The designed mechanism keeps attachments **outside the message**, by reference:

- The sender encrypts the file with a fresh single-use symmetric key and publishes the resulting opaque blob at a URL on its own server.
- The reference `{hash, url, size, key}` travels **inside the sealed content**, so end-to-end encryption covers attachments too (the same pattern Matrix uses for media).
- The `hash` is of the encrypted blob: any server (the sender's, a mirror) can verify integrity without being able to read anything.
- The recipient's server downloads and mirrors the blob **at delivery time, not at read time**: opening an attachment reveals nothing to the sender (no read receipts, no IP), and the sender MAY delete the original once mirrors confirm.
- Costs flip relative to SMTP: whoever sends, hosts. Bulk mail with heavy attachments costs the spammer disk, not the victim.

Keeping attachments out of the message is also what lets a message's JSON stay small (no base64 bodies) and receivers enforce an aggressive `413`. A future version will make this normative: the exact reference fields, the cipher for blobs and the mirror confirmation flow.

# Security Policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub Security Advisories: https://github.com/Slim-m-org/slim-m-relay/security/advisories/new
Do not open a public issue for a security report.
Include steps to reproduce, the affected version or commit, and the impact you believe it has.
Expect an acknowledgement within a few days.

## Scope

In scope: the relay binary and its HTTP API (`/v1/register`, `/v1/send`, `/admin/*`, `/healthz`), the SQLite key store, and how the relay handles the APNs and FCM credentials it holds.
Out of scope: slim-m's home server and client apps, and the security of Apple's or Google's own push infrastructure.

## What the relay sees

The relay never sees plaintext.
Every payload it forwards is already encrypted by the home server before it ever reaches the relay; the relay only ever forwards that ciphertext, plus a coarse `kind` (`message`, `mention`, `call`, or `wake`), to APNs or FCM.
It does not log tokens or payload content, only counts and error codes.

## Primary risk: credential compromise

The relay holds one Apple APNs `.p8` token key and one Firebase service account, shared across every self-hosted slim-m server that registers with it.
Compromise of either credential is the most serious outcome for this project: it would let an attacker push to any device on any slim-m deployment that uses the relay.
Registration keys are stored only as SHA-256 hashes, so a leak of the SQLite database alone does not expose a usable key.
A compromised or misbehaving registered server can be cut off with `POST /admin/keys/{id}/revoke`.

## Known residual: a token's secrecy is the only gate

Device tokens are bound per registration key, not first-come.
Any registered key that knows a device token can bind it and push to it, voip call pushes included, until `RELAY_MAX_KEYS_PER_TOKEN` keys hold it.
Nothing but the token's secrecy gates pushes to a device: APNs and FCM tokens are opaque, high-entropy and never published by slim-m, and a leaked one lets a hostile server push to that device until the token is rotated.
A key past the per-token limit gets `forbidden` unless one of the existing bindings has been idle for `RELAY_BINDING_IDLE_DAYS`, so a hostile server cannot lock out real ones without keeping every one of its keys sending.
Bindings are also bounded per key (`RELAY_MAX_TOKENS_PER_KEY`) and across the relay (`RELAY_MAX_TOKENS_TOTAL`), and a binding unused for the retention window (90 days by default, `RELAY_TOKEN_RETENTION_DAYS`) is pruned.
Sends are budgeted per message for each key and for the relay as a whole, because every message is a call on provider credentials all deployments share.

## Baseline, not maximal, security

This project targets Discord-level baseline security, not end-to-end or nation-state-resistant guarantees.
The relay is a transport hop, not a party to slim-m's encryption: the payload it forwards is opaque ciphertext the home server already produced, and the relay itself never has the means to decrypt it.
Reports asking for user-facing cryptography changes to the relay itself are out of scope; the payload encryption boundary lives in the home server, not here.

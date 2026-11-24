# slim-m-relay

The push relay for slim-m.

slim-m is open source, so anyone can self-host the server.
But waking a mobile device is the one part a self-hoster cannot fully do themselves: the published apps embed the maintainer's Apple and Google push credentials, and those credentials are master keys that can push to any slim-m device on any server.
Handing them out directly is not an option.

This relay is the fix.
The maintainer runs one instance that holds the two credentials: an APNs `.p8` token key for iOS and a Firebase service account for Android.
A self-hosted slim-m server registers with it once on first boot, gets a scoped, revocable key, and from then on POSTs its wake-up pushes to the relay instead of straight to Apple or Google.
So a host running the published apps gets working push on both platforms, and nobody but the maintainer ever holds either credential.

The relay is deliberately minimal.
It is not the messaging backend, and it is not part of slim-m's end-to-end encryption.
The home server encrypts every payload before it ever reaches the relay.
The relay forwards that opaque ciphertext, plus a coarse `kind` (`message`, `mention`, `call`, `call_end`, `security`, `voice`, `admin_alert`, or `wake`), to whichever provider the target device uses.
It never encrypts, decrypts, or inspects payload content, and it never logs it either.

## What the relay sees

Only what it needs to route and wake a device: a platform (`ios` or `android`), a device token, a coarse kind, and an opaque, already-encrypted payload blob.
It never sees message text, sender identity, group membership, or anything else the home server encrypted.
It does not log tokens or payload content, only counts and error codes.

## How it works

1. A slim-m server boots with a relay URL configured.
2. If it has no key yet, it calls `POST /v1/register` with its public URL.
   The relay mints a key (registration is per-IP rate-limited, and bounded overall by `RELAY_MAX_REGISTRATIONS`) and returns it once, recording the public URL as an admin label.
   The server stores the key and reuses it forever after.
3. When something happens worth waking a device for, the server calls `POST /v1/send` with its key and a batch of `{platform, token, kind, payload}`.
   The relay forwards each message to APNs or FCM depending on its platform, through a bounded worker pool under a hard per-request deadline, and returns a per-token result so the server can prune tokens the provider reports as dead.
   A message the deadline cut off before its turn comes back as `not_attempted` rather than any other status, so the server knows to retry only those.
   The deadline starts when the keys are checked, covers binding every token in one transaction and then the provider calls, and defaults to 8 seconds so it ends before the 10 seconds slim-m's server waits.

Keys are stored as SHA-256 hashes in a small SQLite file, so a leak of the database yields nothing usable.
Registration is rate-limited per IP, capped overall by `RELAY_MAX_REGISTRATIONS`, and sending is rate-limited per key, with a tighter limit specifically on `call` kind pushes since a call rings a device and is the most abusable kind.
Rate limiting is per-instance and in-process: it lives in the relay's own memory, not a shared store, so running more than one replica multiplies the effective limits rather than sharing one budget across them.
Each limiter tracks at most 200000 client addresses or keys; when all of those are in use, new ones share a single bucket until idle ones age out, so a flood of rotating addresses cannot grow the relay's memory without bound.
A misbehaving server can be cut off with `POST /admin/keys/{id}/revoke`.
Revoking a key also drops its device-token bindings.
Keys that registered but never bound a device token can be cleared with `POST /admin/keys/purge-unused`, which frees their registration slots if someone squats the ceiling; revoking a key frees its slot too.
It is deliberately manual: a slim-m server whose key is purged gets `401` from every send until it is given a new one, so choose an age that no real server is still waiting inside.

### Token-to-key binding

Device tokens are opaque strings that a server could in principle send to any registered token, so the relay adds one hardening rule beyond scoped keys: a key may deliver to a `(platform, token)` pair only through a binding of its own, created the first time that key sends to it.
A send is `forbidden` and never reaches APNs or FCM when the token already has `RELAY_MAX_KEYS_PER_TOKEN` other keys bound.

The design has to serve two cases at once.
A phone signed in to several communities hands the same FCM or APNs token to each server, and each server sends with its own key, so several keys must be able to deliver to one token.
A hostile server must still be unable to take a token away from a real one or to shut a real server out.

- Bindings are per key. A binding is `(platform, token, key)`, so one key's binding never changes what another key may do, and a hostile server cannot hijack the token from a server that already sends to it. The first sender no longer owns the token.
- The number of keys per token is capped (default 8). A key past the cap gets `forbidden`.
- A full token admits a new key only by replacing a binding that has been unused for `RELAY_BINDING_IDLE_DAYS` (default 14), the idlest first. A hostile server that fills the slots therefore keeps real servers out only while every one of its keys keeps sending to the token, and every send of its own is still rate-limited per key.
- A server that learned a token legitimately can always push junk to that device; the relay cannot prevent that and does not try. Revoking its key (`POST /admin/keys/{id}/revoke`) removes its bindings.
- Bindings created before this change keep working: the tokens table is rebuilt on first start with the same rows, one per key.

The home server reads the `forbidden` result, counts it, and shows the count in its admin push view, so a server that is silently shut out is visible.
A token must be 1 to 1024 characters (the server already refuses to register a longer one), or it comes back as `rejected` and is never stored.
An iOS token may use only letters, digits, `-` and `_`, because it becomes part of the APNs request path, and it is lowercased before it is bound or sent so a case variant cannot be a second binding for the same device; the result still echoes the spelling the server sent.
An Android token may use only letters, digits, `-`, `_`, `.` and `:`, the alphabet Firebase issues.
A binding its key has not sent to within `RELAY_TOKEN_RETENTION_DAYS` is pruned, so the tokens table - which, unlike the keys table, grows at a rate the caller controls with every send - stays bounded; a device token the provider has already reported dead is worthless to keep, and an actively used one is never at risk since every legitimate send resets its clock.

## API

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `POST` | `/v1/register` | none (IP rate-limited) | Mint a key. Optional body `{"publicUrl": "..."}` is recorded, unverified, as an admin label. |
| `POST` | `/v1/send` | `Authorization: Bearer <key>` | Forward `{"messages": [{"platform","token","kind","payload"}]}` to APNs or FCM by platform. Returns `{"results": [{"token","status"}]}` where status is one of the values listed under Statuses below. A `429` carries a `Retry-After` header. |
| `GET` | `/healthz` | none | Liveness. |
| `GET` | `/admin/keys` | `Authorization: Bearer <admin token>` | List issued keys (metadata only). |
| `POST` | `/admin/keys/{id}/revoke` | `Authorization: Bearer <admin token>` | Revoke a key. |
| `POST` | `/admin/keys/purge-unused?older_than_days=N` | `Authorization: Bearer <admin token>` | Delete keys that never bound a device token and were issued more than `N` days ago (`N` is required and at least 1). Returns `{"purged": n}`. |

Admin endpoints are only mounted when `RELAY_ADMIN_TOKEN` is set to at least 32 characters; a shorter token leaves them disabled and the relay says so at startup.
Generate one with `openssl rand -hex 32`.
Each client address may make a handful of failed admin attempts per minute before it gets `429`; a request with the right token is never throttled, even from an address that has used up its failed attempts.

`platform` is `ios` or `android`.
`kind` is `message`, `mention`, `call`, `call_end`, `security`, `voice`, `admin_alert`, or `wake`.
`payload` is the home server's already-encrypted blob, forwarded byte-for-byte; the relay never inspects it.
`kind: "call"` is the one kind that changes how the push is delivered: on iOS it goes to the app's separate `<bundle id>.voip` PushKit topic at high priority instead of the plain background-wake topic, so the app needs the matching VoIP Services entitlement configured with Apple for it to ring.
The `token` for a `call` on iOS must be the device's PushKit VoIP token, not its ordinary APNs token; APNs rejects an ordinary token on the `.voip` topic.
`message`, `mention`, `security`, `voice` and `admin_alert` show a fixed, content-free alert on iOS ("New message", "You were mentioned", "New sign-in to your account", "Voice channel activity", "Server alert"), which the app's notification service extension may replace after decrypting the payload.
`call_end` tells a device to stop a ring it may still be showing; on iOS it is a silent background push on the plain topic, never a VoIP push, since iOS terminates an app that takes a VoIP push without reporting a new call.
`call` and `call_end` expire after 30 seconds (APNs `apns-expiration`, FCM `android.ttl`), matching the home server's ring timeout, so a device that reconnects late never rings for a call that is already over.
Every Android push is a high-priority data-only message; the app builds any notification itself.

### Statuses

Every result carries exactly one status.

| Status | Meaning |
|--------|---------|
| `delivered` | The provider accepted the message. |
| `unregistered` | The provider reports the token dead; the caller should drop it. |
| `forbidden` | The token already has `RELAY_MAX_KEYS_PER_TOKEN` other keys bound, so this key may not deliver to it. |
| `not_attempted` | The request's deadline passed before this message's turn; the provider was never contacted. |
| `rejected` | Refused for good: an unknown platform or kind, a malformed or oversized token or payload, the key's token cap, or an answer from the provider that never changes for the same message. Resending the same message cannot succeed. |
| `retry` | The message was fine but could not be delivered now: the provider was overloaded or unreachable, the key's `call` budget was spent, or the relay's provider credentials need its operator. A later attempt may succeed. |

Relays from before `rejected` and `retry` answered `error` for both, so a server could not tell a relay that predates a kind from a provider having a bad minute.
This relay never answers `error`.
A server that still sees it knows it is talking to an older relay, and one that does not recognize `rejected` or `retry` treats them like any other status it takes no action on.

## Running it

You need the credentials for the project the published apps are built against: a Firebase service-account JSON for Android, and an APNs `.p8` token key (with its key id, team id, and the app's bundle id) for iOS.
Either platform can be left unconfigured; sends to that platform fail clearly instead of the relay refusing to start.

```bash
cp .env.example .env
# fill in RELAY_ADMIN_TOKEN and whichever provider credentials you have
```

Then run the binary directly, or build the Docker image and mount your credential files and the `/data` volume yourself:

```bash
docker build -t slim-m-relay .
docker run -d \
  -p 8090:8090 \
  -v $(pwd)/data:/data \
  -v $(pwd)/fcm-service-account.json:/run/secrets/fcm-service-account.json:ro \
  -v $(pwd)/apns-auth-key.p8:/run/secrets/apns-auth-key.p8:ro \
  --env-file .env \
  slim-m-relay
```

The image declares a `HEALTHCHECK` that runs `relay -healthcheck` against `/healthz`, so `docker ps` shows whether the relay is healthy, with no `--health-cmd` needed.
A relay whose key store is unreadable reports `unhealthy`; Docker does not restart it by itself, so pair it with an autoheal tool or an orchestrator if you want that.

Put the relay behind whatever reverse proxy you already run (Caddy, Traefik, nginx).
By default the relay ignores `X-Forwarded-For` entirely and keys per-IP rate limiting on the raw socket address, since every proxy the list above sets that header at *appends* its view of the peer - the leftmost entry is always whatever the client itself sent, and trusting it by default would let any caller spoof its way to an unlimited number of rate-limit identities.
If you do run behind such a proxy and want registration limits keyed on the real client rather than the proxy's own address, set `RELAY_TRUST_PROXY=true`.
The relay then reads the client address from `X-Forwarded-For`, counting `RELAY_TRUST_PROXY_HOPS` entries from the right (default `1`, the rightmost entry the trusted proxy itself appended, which an external caller cannot forge).
Behind Cloudflare plus another proxy set it to `2`, and so on; a header shorter than the hop count falls back to the socket address.
Whichever way the address is found, an IPv6 address is keyed by its /64, because a single ordinary allocation holds 2^64 addresses a caller could rotate through; IPv4 stays per address.
Enabling it without a real proxy in front that sets the header makes the limiter spoofable, so only turn it on once you have confirmed your proxy is the one setting `X-Forwarded-For`, not passing a client-supplied value through unchanged.
The `/data` volume holds the SQLite key store; back it up, since losing it means every registered server re-registers on its next boot, and every device token re-establishes its binding to whichever server sends to it first.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `RELAY_PORT` | `8090` | TCP port the relay listens on. |
| `RELAY_DB_PATH` | `/data/relay.db` | SQLite key store path. |
| `RELAY_ADMIN_TOKEN` | *(empty)* | Guards `/admin`. Empty, or shorter than 32 characters, disables those endpoints. Generate one with `openssl rand -hex 32`. |
| `RELAY_FCM_CREDENTIALS_FILE` | *(empty)* | Path to the Firebase service-account JSON. Empty disables Android sends. |
| `RELAY_APNS_KEY_PATH` | *(empty)* | Path to the APNs `.p8` token key. |
| `RELAY_APNS_KEY_ID` | *(empty)* | The `.p8` key's 10-character key id. |
| `RELAY_APNS_TEAM_ID` | *(empty)* | Apple Developer Team ID. |
| `RELAY_APNS_BUNDLE_ID` | *(empty)* | App bundle id, used as the APNs background-wake topic. A `call` kind push is derived from it as `<bundle id>.voip`, so this one value configures both topics and they can never drift apart. |
| `RELAY_APNS_PRODUCTION` | `true` | `true` for APNs' production gateway, `false` for the sandbox gateway. All four `RELAY_APNS_*` credential fields are required together; if any is empty, iOS sends fail clearly. |
| `RELAY_TRUST_PROXY` | `false` | `true` reads the client IP from `X-Forwarded-For` (see `RELAY_TRUST_PROXY_HOPS`), for use behind a reverse proxy that sets it. `false` (default) always uses the raw socket address. Enabling this without a real proxy in front makes per-IP rate limiting spoofable. |
| `RELAY_TRUST_PROXY_HOPS` | `1` | How many proxies are in front of the relay when `RELAY_TRUST_PROXY` is on: the client is the entry that many places from the right of `X-Forwarded-For`. |
| `RELAY_REGISTER_PER_HOUR` | `5` | Per-IP registration rate. |
| `RELAY_REGISTER_BURST` | `3` | Per-IP registration burst. |
| `RELAY_MAX_REGISTRATIONS` | `10000` | Total keys the relay will hold, across every IP (revoked keys do not count, so revoking or purging gives slots back). The relay logs when 80% is used and again at the ceiling. Zero or negative disables the ceiling. |
| `RELAY_SEND_ADMIT_PER_MINUTE` | `600` | Per-IP admission rate on `/v1/send`, checked before the bearer key is looked up so unauthenticated garbage never reaches the key store. Sized well above any honest server's send rate. |
| `RELAY_SEND_ADMIT_BURST` | `120` | Per-IP admission burst on `/v1/send`. |
| `RELAY_SEND_PER_MINUTE` | `120` | Per-key send rate. |
| `RELAY_SEND_BURST` | `60` | Per-key send burst. |
| `RELAY_CALL_SEND_PER_MINUTE` | `10` | Per-key rate specifically for `call` kind pushes, tighter than `RELAY_SEND_PER_MINUTE` since a call rings a device and is the most abusable kind. |
| `RELAY_CALL_SEND_BURST` | `5` | Per-key burst for `call` kind pushes. |
| `RELAY_MAX_MESSAGES` | `500` | Device tokens allowed in one `/v1/send`. |
| `RELAY_SEND_CONCURRENCY` | `8` | Provider sends run at once, per `/v1/send` request, through a bounded worker pool. |
| `RELAY_SEND_TIMEOUT_SECONDS` | `8` | Hard wall-clock deadline for one `/v1/send` request's token binding and provider dispatch. A message not yet attempted when it fires comes back as `not_attempted`. Keep it under the 10 seconds slim-m's server waits for a send, or the server gives up before it sees the results. The HTTP write timeout is this plus 30 seconds. `0` or negative disables both the deadline and the write timeout. |
| `RELAY_TOKEN_RETENTION_DAYS` | `90` | How long a device-token binding may go without its owning key sending to it before it is pruned. A send always refreshes the clock, so an actively used token is never at risk. `0` or negative disables pruning, leaving the tokens table to grow without bound. |
| `RELAY_MAX_KEYS_PER_TOKEN` | `8` | How many keys may deliver to one device token. A key past it comes back as `forbidden`. `0` or negative disables the cap. |
| `RELAY_BINDING_IDLE_DAYS` | `14` | How long a binding on a full token must be unused before a new key may replace it. `0` or negative never replaces. |
| `RELAY_SEND_MESSAGES_PER_MINUTE` | `6000` | Per-key send budget, charged per message. A request over it gets `429`. |
| `RELAY_SEND_MESSAGES_BURST` | `2000` | Per-key message burst. |
| `RELAY_PROVIDER_CALLS_PER_MINUTE` | `60000` | Relay-wide message budget across every key, kept under the FCM project quota. `0` or negative disables it. |
| `RELAY_PROVIDER_CALLS_BURST` | `5000` | Relay-wide message burst. |
| `RELAY_MAX_TOKENS_TOTAL` | `500000` | How many device tokens the whole relay may have bound. A new token past it comes back as `rejected`. `0` or negative disables the cap. |
| `RELAY_MAX_TOKENS_PER_KEY` | `20000` | How many device tokens one key may have bound. A new token past it comes back as `rejected`; one the key already owns keeps working. `0` or negative disables the cap. |

The relay refuses to start when a per-minute or per-hour rate, a burst, or `RELAY_MAX_MESSAGES` is below 1, or when `RELAY_TRUST_PROXY_HOPS` is below 1 with `RELAY_TRUST_PROXY` on, and the error names the variable.
A zero rate or burst would otherwise let one caller through once and then refuse it forever.

## Development

```bash
go test ./...
go build ./cmd/relay
```

Go 1.26 or newer, no CGO (the SQLite driver is pure Go), single static binary.
The Go minor in the Dockerfile's `FROM golang:` line is the one CI installs, so the image is built with the toolchain the tests ran on.

## License

[PolyForm Noncommercial 1.0.0](LICENSE).

Free for noncommercial use: personal, hobby, educational, research, nonprofit, and all that.
You can fork it, change it and redistribute it, you just can't sell it or use it commercially without asking first.
If you want to use it commercially, open an issue and ask.

Contributions are welcome. By submitting a pull request you agree that your changes are released under this same license.

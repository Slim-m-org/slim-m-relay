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
The relay forwards that opaque ciphertext, plus a coarse `kind` (`message`, `mention`, `call`, `call_end`, `security`, or `wake`), to whichever provider the target device uses.
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

Keys are stored as SHA-256 hashes in a small SQLite file, so a leak of the database yields nothing usable.
Registration is rate-limited per IP, capped overall by `RELAY_MAX_REGISTRATIONS`, and sending is rate-limited per key, with a tighter limit specifically on `call` kind pushes since a call rings a device and is the most abusable kind.
Rate limiting is per-instance and in-process: it lives in the relay's own memory, not a shared store, so running more than one replica multiplies the effective limits rather than sharing one budget across them.
A misbehaving server can be cut off with `POST /admin/keys/{id}/revoke`.

### Token-to-key binding

Because device tokens are opaque strings that a server could in principle send to any registered token, the relay adds one hardening rule beyond scoped keys: the first key to send to a given `(platform, token)` pair becomes that token's owner in the same SQLite store, for as long as that key keeps sending to it.
Every later send to that token must come from the same key.
A send from a different key for a token it does not own is rejected with `forbidden`, and never reaches APNs or FCM.
This keeps one self-hosted server from harassing another server's devices, even if it somehow obtained their tokens.
A token must be 1 to 1024 printable ASCII characters with no whitespace (the server already refuses to register a longer one), or it comes back as `error` and is never stored.
A binding its owner has not sent to within `RELAY_TOKEN_RETENTION_DAYS` is pruned, so the tokens table - which, unlike the keys table, grows at a rate the caller controls with every send - stays bounded; a device token the provider has already reported dead is worthless to keep, and an actively used one is never at risk since every legitimate send resets its clock.

## API

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `POST` | `/v1/register` | none (IP rate-limited) | Mint a key. Optional body `{"publicUrl": "..."}` is recorded, unverified, as an admin label. |
| `POST` | `/v1/send` | `Authorization: Bearer <key>` | Forward `{"messages": [{"platform","token","kind","payload"}]}` to APNs or FCM by platform. Returns `{"results": [{"token","status"}]}` where status is `delivered`, `unregistered`, `forbidden`, `not_attempted`, or `error`. |
| `GET` | `/healthz` | none | Liveness. |
| `GET` | `/admin/keys` | `Authorization: Bearer <admin token>` | List issued keys (metadata only). |
| `POST` | `/admin/keys/{id}/revoke` | `Authorization: Bearer <admin token>` | Revoke a key. |

Admin endpoints are only mounted when `RELAY_ADMIN_TOKEN` is set.

`platform` is `ios` or `android`.
`kind` is `message`, `mention`, `call`, `call_end`, `security`, or `wake`.
`payload` is the home server's already-encrypted blob, forwarded byte-for-byte; the relay never inspects it.
`kind: "call"` is the one kind that changes how the push is delivered: on iOS it goes to the app's separate `<bundle id>.voip` PushKit topic at high priority instead of the plain background-wake topic, so the app needs the matching VoIP Services entitlement configured with Apple for it to ring.
The `token` for a `call` on iOS must be the device's PushKit VoIP token, not its ordinary APNs token; APNs rejects an ordinary token on the `.voip` topic.
`message`, `mention` and `security` show a fixed, content-free alert on iOS ("New message", "You were mentioned", "New sign-in to your account"), which the app's notification service extension may replace after decrypting the payload.
`call_end` tells a device to stop a ring it may still be showing; on iOS it is a silent background push on the plain topic, never a VoIP push, since iOS terminates an app that takes a VoIP push without reporting a new call.
`call` and `call_end` expire after 30 seconds (APNs `apns-expiration`, FCM `android.ttl`), matching the home server's ring timeout, so a device that reconnects late never rings for a call that is already over.
Every Android push is a high-priority data-only message; the app builds any notification itself.

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

Put the relay behind whatever reverse proxy you already run (Caddy, Traefik, nginx).
By default the relay ignores `X-Forwarded-For` entirely and keys per-IP rate limiting on the raw socket address, since every proxy the list above sets that header at *appends* its view of the peer - the leftmost entry is always whatever the client itself sent, and trusting it by default would let any caller spoof its way to an unlimited number of rate-limit identities.
If you do run behind such a proxy and want registration limits keyed on the real client rather than the proxy's own address, set `RELAY_TRUST_PROXY=true`.
The relay then reads the rightmost entry of `X-Forwarded-For`, the one hop the trusted proxy itself appended and the only one an external caller cannot forge.
Enabling it without a real proxy in front that sets the header makes the limiter spoofable, so only turn it on once you have confirmed your proxy is the one setting `X-Forwarded-For`, not passing a client-supplied value through unchanged.
The `/data` volume holds the SQLite key store; back it up, since losing it means every registered server re-registers on its next boot, and every device token re-establishes its binding to whichever server sends to it first.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `RELAY_PORT` | `8090` | TCP port the relay listens on. |
| `RELAY_DB_PATH` | `/data/relay.db` | SQLite key store path. |
| `RELAY_ADMIN_TOKEN` | *(empty)* | Guards `/admin`. Empty disables those endpoints. |
| `RELAY_FCM_CREDENTIALS_FILE` | *(empty)* | Path to the Firebase service-account JSON. Empty disables Android sends. |
| `RELAY_APNS_KEY_PATH` | *(empty)* | Path to the APNs `.p8` token key. |
| `RELAY_APNS_KEY_ID` | *(empty)* | The `.p8` key's 10-character key id. |
| `RELAY_APNS_TEAM_ID` | *(empty)* | Apple Developer Team ID. |
| `RELAY_APNS_BUNDLE_ID` | *(empty)* | App bundle id, used as the APNs background-wake topic. A `call` kind push is derived from it as `<bundle id>.voip`, so this one value configures both topics and they can never drift apart. |
| `RELAY_APNS_PRODUCTION` | `true` | `true` for APNs' production gateway, `false` for the sandbox gateway. All four `RELAY_APNS_*` credential fields are required together; if any is empty, iOS sends fail clearly. |
| `RELAY_TRUST_PROXY` | `false` | `true` reads the client IP from the rightmost entry of `X-Forwarded-For`, for use behind a reverse proxy that sets it. `false` (default) always uses the raw socket address. Enabling this without a real proxy in front makes per-IP rate limiting spoofable. |
| `RELAY_REGISTER_PER_HOUR` | `5` | Per-IP registration rate. |
| `RELAY_REGISTER_BURST` | `3` | Per-IP registration burst. |
| `RELAY_MAX_REGISTRATIONS` | `10000` | Total keys the relay will ever mint, across every IP, forever (revoked keys still count against it). Zero or negative disables the ceiling. |
| `RELAY_SEND_ADMIT_PER_MINUTE` | `600` | Per-IP admission rate on `/v1/send`, checked before the bearer key is looked up so unauthenticated garbage never reaches the key store. Sized well above any honest server's send rate. |
| `RELAY_SEND_ADMIT_BURST` | `120` | Per-IP admission burst on `/v1/send`. |
| `RELAY_SEND_PER_MINUTE` | `120` | Per-key send rate. |
| `RELAY_SEND_BURST` | `60` | Per-key send burst. |
| `RELAY_CALL_SEND_PER_MINUTE` | `10` | Per-key rate specifically for `call` kind pushes, tighter than `RELAY_SEND_PER_MINUTE` since a call rings a device and is the most abusable kind. |
| `RELAY_CALL_SEND_BURST` | `5` | Per-key burst for `call` kind pushes. |
| `RELAY_MAX_MESSAGES` | `500` | Device tokens allowed in one `/v1/send`. |
| `RELAY_SEND_CONCURRENCY` | `8` | Provider sends run at once, per `/v1/send` request, through a bounded worker pool. |
| `RELAY_SEND_TIMEOUT_SECONDS` | `20` | Hard wall-clock deadline for one `/v1/send` request's provider dispatch. A message not yet attempted when it fires comes back as `not_attempted`. `0` or negative disables the deadline entirely rather than expiring it instantly. |
| `RELAY_TOKEN_RETENTION_DAYS` | `90` | How long a device-token binding may go without its owning key sending to it before it is pruned. A send always refreshes the clock, so an actively used token is never at risk. `0` or negative disables pruning, leaving the tokens table to grow without bound. |
| `RELAY_MAX_TOKENS_PER_KEY` | `20000` | How many device tokens one key may have bound. A new token past it comes back as `error`; one the key already owns keeps working. `0` or negative disables the cap. |

## Development

```bash
go test ./...
go build ./cmd/relay
```

Go 1.26, no CGO (the SQLite driver is pure Go), single static binary.

## License

[PolyForm Noncommercial 1.0.0](LICENSE).

Free for noncommercial use: personal, hobby, educational, research, nonprofit, and all that.
You can fork it, change it and redistribute it, you just can't sell it or use it commercially without asking first.
If you want to use it commercially, open an issue and ask.

Contributions are welcome. By submitting a pull request you agree that your changes are released under this same license.

// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/nc1107/slim-m-relay/internal/push"
)

// defaultContractFixturePath is where the push-relay-contract workflow (run
// from both slim-m and slim-m-relay, so a change on either side triggers it)
// writes the JSON slimm-server's real relay client POSTs to /v1/send,
// captured fresh from a live send through the server's full stack every run.
// Nothing here is committed, so there is no copy that can go stale on its
// own; see slimm-server/tests/push_relay_contract_fixture.rs for the
// producing side and why each case below exists.
const defaultContractFixturePath = "testdata/push_relay_contract.generated.json"

// contractCase names one entry in the fixture - a message's push token,
// which the relay never interprets beyond forwarding, doubles as a stable
// case name here - and what the relay must do with it. parsePlatform and
// parseKind in send.go define exactly the vocabulary a message's platform
// and kind may use, and maxPayloadBytes bounds the payload string; any drift
// between what slimm-server actually emits and what this table expects
// shows up here, by case name, rather than as a silent notification gap in
// production.
//
// wantStatus and wantPlatform are the literal wire strings ("delivered",
// "ios", and so on), deliberately not push.StatusDelivered / push.PlatformIOS.
// Comparing against those symbols would make this table track whatever
// send.go and internal/push currently define rather than pin what they must
// say: if a status or platform's own string value were ever renamed, the
// symbol-based expectation would silently follow the rename and this test
// would keep passing having asserted nothing. A literal here only agrees
// with the relay's output if the relay actually still emits that string.
type contractCase struct {
	token      string
	wantStatus string
	// wantPlatform is the literal wire value of whichever fake provider must
	// have received the message. Empty means the relay must reject it before
	// ever dispatching to either provider.
	wantPlatform string
}

var contractCases = []contractCase{
	// The two entries slimm-server actually produced, via real message sends
	// through its full stack to a genuinely registered iOS and Android
	// device respectively (see the Rust doc comment above).
	{token: "contract-real-message", wantStatus: "delivered", wantPlatform: "ios"},
	{token: "contract-real-message-android", wantStatus: "delivered", wantPlatform: "android"},
	// A payload exactly at the documented ceiling must still go through.
	{token: "contract-payload-at-limit", wantStatus: "delivered", wantPlatform: "android"},
	// One byte over the ceiling must be rejected, never dispatched.
	{token: "contract-payload-over-limit", wantStatus: "error"},
	// A kind outside {message, mention, call, call_end, security, wake} must be rejected.
	{token: "contract-unknown-kind", wantStatus: "error"},
	// A platform outside {ios, android} must be rejected.
	{token: "contract-unknown-platform", wantStatus: "error"},
}

// TestPushRelayContract drives slimm-server's real, freshly captured
// /v1/send request body through the relay's real HTTP handler - fake
// provider senders stand in for APNs/FCM, exactly as the rest of this
// package's tests do - and asserts the relay accepts and classifies what the
// server actually emits, field by field.
//
// Skips, rather than fails, when the fixture is absent AND
// SLIMM_PUSH_CONTRACT_FIXTURE_REQUIRED is not set: generating the fixture
// needs a sibling slim-m checkout and a Rust toolchain, which an ordinary
// `go test ./...` run (this package's own ci.yml, or a contributor's
// machine) does not have. Run it for real locally with:
//
//	cd slim-m && SLIMM_PUSH_CONTRACT_FIXTURE_OUT=$PWD/../slim-m-relay/internal/api/testdata/push_relay_contract.generated.json \
//	  cargo test -p slimm-server --test push_relay_contract_fixture
//	cd slim-m-relay && go test ./internal/api/... -run TestPushRelayContract -v
//
// or push a change and let the push-relay-contract workflow (which checks
// out both repos, generates the fixture, and sets
// SLIMM_PUSH_CONTRACT_FIXTURE_REQUIRED so a missing fixture there is a hard
// failure rather than a silently green skip) run it.
func TestPushRelayContract(t *testing.T) {
	path := os.Getenv("SLIMM_PUSH_CONTRACT_FIXTURE")
	if path == "" {
		path = defaultContractFixturePath
	}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		if os.Getenv("SLIMM_PUSH_CONTRACT_FIXTURE_REQUIRED") != "" {
			t.Fatalf("no generated fixture at %s and SLIMM_PUSH_CONTRACT_FIXTURE_REQUIRED is set - "+
				"this is the push-relay-contract workflow's own run, where the fixture generation step "+
				"must have already produced this file; a missing file here means that step silently "+
				"failed and this job must not go green having asserted nothing", path)
		}
		t.Skipf("no generated fixture at %s; see this test's doc comment to generate one", path)
	}
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}

	// Decoded with the same sendReq/sendMessage types, and the same
	// DisallowUnknownFields strictness, that /v1/send's own decodeJSON
	// applies - so a field the fixture carries that sendMessage's JSON tags
	// do not recognize fails right here with the field's own name (Go's
	// "json: unknown field ..."), rather than surfacing later as handleSend's
	// opaque, deliberately-generic "invalid body" 400.
	var req sendReq
	strict := json.NewDecoder(bytes.NewReader(raw))
	strict.DisallowUnknownFields()
	if err := strict.Decode(&req); err != nil {
		t.Fatalf("fixture %s does not decode as sendReq: %v - relay.rs's RelayMessage and "+
			"send.go's sendMessage have drifted apart on a field name or type", path, err)
	}
	if len(req.Messages) != len(contractCases) {
		t.Fatalf("fixture has %d messages, want %d - the fixture generator and this file's "+
			"contractCases table have drifted apart; update both together", len(req.Messages), len(contractCases))
	}
	byToken := make(map[string]sendMessage, len(req.Messages))
	for _, m := range req.Messages {
		byToken[m.Token] = m
	}

	srv, ios, android, store := newTestServer(t, defaultCfg())
	key, err := store.Issue(context.Background(), "", 0)
	if err != nil {
		t.Fatalf("issue relay key: %v", err)
	}

	rr := do(srv.Router(), "POST", "/v1/send", string(raw), key)
	if rr.Code != 200 {
		t.Fatalf("send = %d, want 200 (body %s)", rr.Code, rr.Body)
	}
	var resp sendResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	statusByToken := make(map[string]push.Status, len(resp.Results))
	for _, r := range resp.Results {
		statusByToken[r.Token] = r.Status
	}

	for _, c := range contractCases {
		status, ok := statusByToken[c.token]
		if !ok {
			t.Errorf("case %q: the relay returned no result for this token at all", c.token)
			continue
		}
		if string(status) != c.wantStatus {
			t.Errorf("case %q: status = %q, want %q (check send.go's maxPayloadBytes / "+
				"parsePlatform / parseKind against what relay.rs actually put on the wire for this case)",
				c.token, status, c.wantStatus)
		}

		iosMsg := findByToken(ios, c.token)
		androidMsg := findByToken(android, c.token)

		var got *push.Message
		switch c.wantPlatform {
		case "ios":
			got = iosMsg
			if androidMsg != nil {
				t.Errorf("case %q: reached the Android provider, want iOS only (check the \"platform\" field)", c.token)
			}
		case "android":
			got = androidMsg
			if iosMsg != nil {
				t.Errorf("case %q: reached the iOS provider, want Android only (check the \"platform\" field)", c.token)
			}
		case "":
			if iosMsg != nil || androidMsg != nil {
				t.Errorf("case %q: reached a provider, want the relay to reject it before dispatch (status %q)",
					c.token, status)
			}
			continue
		default:
			t.Fatalf("case %q: test bug: wantPlatform %q is not \"ios\", \"android\", or \"\"", c.token, c.wantPlatform)
		}
		if got == nil {
			// Already reported above as a status mismatch (or this case's
			// own dedicated message below if status happened to match by
			// coincidence); nothing arrived to compare kind/payload against.
			t.Errorf("case %q: never reached the %s provider, want it dispatched there", c.token, c.wantPlatform)
			continue
		}

		// The provider must see exactly what the fixture said the server
		// sent: proof the relay forwards kind and payload untouched, not
		// just that it classified the message correctly.
		want := byToken[c.token]
		if string(got.Kind) != want.Kind {
			t.Errorf("case %q: provider received kind %q, want %q (the \"kind\" field was not forwarded unchanged)",
				c.token, got.Kind, want.Kind)
		}
		if got.Payload != want.Payload {
			t.Errorf("case %q: provider received a payload that does not match the fixture's "+
				"\"payload\" field byte for byte; opaque ciphertext must be forwarded untouched", c.token)
		}
	}
}

// findByToken returns the message a fake sender recorded for token, or nil
// if it never received one.
func findByToken(sender *fakeSender, token string) *push.Message {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	for i := range sender.got {
		if sender.got[i].Token == token {
			return &sender.got[i]
		}
	}
	return nil
}

// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nc1107/slim-m-relay/internal/config"
	"github.com/nc1107/slim-m-relay/internal/keys"
	"github.com/nc1107/slim-m-relay/internal/push"

	_ "modernc.org/sqlite"
)

func openTokenTestServer(t *testing.T, cfg config.Config) (*Server, string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := keys.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	plain, err := store.Issue(context.Background(), "a", 0)
	if err != nil {
		t.Fatal(err)
	}
	return New(cfg, &fakeSender{}, &fakeSender{}, store), plain, path
}

func countBoundTokens(t *testing.T, path string) int {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM tokens`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func sendTokens(t *testing.T, srv *Server, plain, platform string, tokens ...string) []push.Result {
	t.Helper()
	msgs := make([]sendMessage, len(tokens))
	for i, tok := range tokens {
		msgs[i] = sendMessage{Platform: platform, Token: tok, Kind: "wake"}
	}
	body, err := json.Marshal(sendReq{Messages: msgs})
	if err != nil {
		t.Fatal(err)
	}
	rr := do(srv.Router(), http.MethodPost, "/v1/send", string(body), plain)
	if rr.Code != http.StatusOK {
		t.Fatalf("send status = %d, body %s", rr.Code, rr.Body.String())
	}
	var resp sendResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Results
}

func TestSendRefusesMalformedTokensWithoutStoringThem(t *testing.T) {
	bad := map[string]string{
		"huge":         strings.Repeat("z", 500_000),
		"over the cap": strings.Repeat("a", maxTokenBytes+1),
		"whitespace":   "abc def",
		"control":      "abc\x00def",
		"non-ascii":    "tokén",
	}
	for name, tok := range bad {
		t.Run(name, func(t *testing.T) {
			srv, plain, path := openTokenTestServer(t, defaultCfg())
			for _, platform := range []string{"ios", "android"} {
				res := sendTokens(t, srv, plain, platform, tok)
				if len(res) != 1 || res[0].Status != push.StatusError {
					t.Fatalf("%s: got %d results, first status %q, want one error", platform, len(res), res[0].Status)
				}
			}
			if n := countBoundTokens(t, path); n != 0 {
				t.Fatalf("tokens table has %d rows after a malformed token, want 0", n)
			}
		})
	}
}

func TestSendStillAcceptsARealisticApnsAndFcmToken(t *testing.T) {
	srv, plain, path := openTokenTestServer(t, defaultCfg())
	apns := strings.Repeat("0123456789abcdef", 4)
	fcm := "dVx3_k-Q9:APA91b" + strings.Repeat("Ab_-9", 40)
	if res := sendTokens(t, srv, plain, "ios", apns); res[0].Status != push.StatusDelivered {
		t.Fatalf("apns token: %+v", res)
	}
	if res := sendTokens(t, srv, plain, "android", fcm); res[0].Status != push.StatusDelivered {
		t.Fatalf("fcm token: %+v", res)
	}
	if n := countBoundTokens(t, path); n != 2 {
		t.Fatalf("tokens rows = %d, want 2", n)
	}
}

func TestSendStopsBindingNewTokensAtThePerKeyCap(t *testing.T) {
	cfg := defaultCfg()
	cfg.MaxTokensPerKey = 3
	srv, plain, path := openTokenTestServer(t, cfg)
	var toks []string
	for i := 0; i < 5; i++ {
		toks = append(toks, fmt.Sprintf("tok%d", i))
	}
	res := sendTokens(t, srv, plain, "android", toks...)
	for i, r := range res {
		want := push.StatusDelivered
		if i >= 3 {
			want = push.StatusError
		}
		if r.Status != want {
			t.Errorf("token %d status = %q, want %q", i, r.Status, want)
		}
	}
	if n := countBoundTokens(t, path); n != 3 {
		t.Fatalf("tokens rows = %d, want 3", n)
	}
	if res := sendTokens(t, srv, plain, "android", "tok0"); res[0].Status != push.StatusDelivered {
		t.Fatalf("an already bound token must keep working at the cap: %+v", res)
	}
}

// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/nc1107/slim-m-relay/internal/keys"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/nc1107/slim-m-relay/internal/config"
)

var testAdminToken = strings.Repeat("s", config.MinAdminTokenChars)

func adminServer(t *testing.T) (http.Handler, func(method, path string) int) {
	t.Helper()
	cfg := defaultCfg()
	cfg.AdminToken = testAdminToken
	srv, _, _, _ := newTestServer(t, cfg)
	h := srv.Router()
	return h, func(method, path string) int {
		return do(h, method, path, "", testAdminToken).Code
	}
}

func TestAdminListRequiresTheToken(t *testing.T) {
	h, _ := adminServer(t)
	for _, bearer := range []string{"", "wrong"} {
		if rr := do(h, http.MethodGet, "/admin/keys", "", bearer); rr.Code != http.StatusUnauthorized {
			t.Errorf("list with bearer %q = %d, want 401", bearer, rr.Code)
		}
	}
}

func TestAdminListIsAnEmptyArrayWhenThereAreNoKeys(t *testing.T) {
	h, _ := adminServer(t)
	rr := do(h, http.MethodGet, "/admin/keys", "", testAdminToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200", rr.Code)
	}
	if got := strings.TrimSpace(rr.Body.String()); got != `{"keys":[]}` {
		t.Errorf("body = %s, want {\"keys\":[]}", got)
	}
}

func TestAdminListReturnsKeyMetadataOnly(t *testing.T) {
	cfg := defaultCfg()
	cfg.AdminToken = testAdminToken
	srv, _, _, store := newTestServer(t, cfg)
	secret, err := store.Issue(context.Background(), "https://slim.example", 0)
	if err != nil {
		t.Fatal(err)
	}
	rr := do(srv.Router(), http.MethodGet, "/admin/keys", "", testAdminToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200", rr.Code)
	}
	var resp struct {
		Keys []struct {
			ID    int64  `json:"id"`
			Label string `json:"label"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Keys) != 1 || resp.Keys[0].Label != "https://slim.example" {
		t.Errorf("keys = %+v, want the one issued key", resp.Keys)
	}
	if strings.Contains(rr.Body.String(), secret) {
		t.Error("the list leaked a key secret")
	}
}

func TestAdminRevokeRejectsABadOrUnknownID(t *testing.T) {
	_, call := adminServer(t)
	if got := call(http.MethodPost, "/admin/keys/abc/revoke"); got != http.StatusBadRequest {
		t.Errorf("revoke abc = %d, want 400", got)
	}
	if got := call(http.MethodPost, "/admin/keys/999/revoke"); got != http.StatusNotFound {
		t.Errorf("revoke unknown id = %d, want 404", got)
	}
}

func TestAdminRevokeTwiceIsNotFound(t *testing.T) {
	cfg := defaultCfg()
	cfg.AdminToken = testAdminToken
	srv, _, _, store := newTestServer(t, cfg)
	secret, _ := store.Issue(context.Background(), "", 0)
	k, _ := store.Verify(context.Background(), secret)
	path := "/admin/keys/" + strconv.FormatInt(k.ID, 10) + "/revoke"
	if rr := do(srv.Router(), http.MethodPost, path, "", testAdminToken); rr.Code != http.StatusNoContent {
		t.Fatalf("first revoke = %d, want 204", rr.Code)
	}
	if rr := do(srv.Router(), http.MethodPost, path, "", testAdminToken); rr.Code != http.StatusNotFound {
		t.Errorf("second revoke = %d, want 404", rr.Code)
	}
}

func TestAdminHandlersReportStoreFailureAs500(t *testing.T) {
	cfg := defaultCfg()
	cfg.AdminToken = testAdminToken
	srv, _, _, store := newTestServer(t, cfg)
	_ = store.Close()
	if rr := do(srv.Router(), http.MethodGet, "/admin/keys", "", testAdminToken); rr.Code != http.StatusInternalServerError {
		t.Errorf("list on a closed store = %d, want 500", rr.Code)
	}
	if rr := do(srv.Router(), http.MethodPost, "/admin/keys/1/revoke", "", testAdminToken); rr.Code != http.StatusInternalServerError {
		t.Errorf("revoke on a closed store = %d, want 500", rr.Code)
	}
}

func TestAdminIsNotMountedForATokenShorterThanTheMinimum(t *testing.T) {
	cfg := defaultCfg()
	cfg.AdminToken = strings.Repeat("s", config.MinAdminTokenChars-1)
	srv, _, _, _ := newTestServer(t, cfg)
	rr := do(srv.Router(), http.MethodGet, "/admin/keys", "", cfg.AdminToken)
	if rr.Code != http.StatusNotFound {
		t.Errorf("list with a %d char admin token = %d, want 404 (not mounted)", len(cfg.AdminToken), rr.Code)
	}
}

func doFrom(h http.Handler, remote, method, target, bearer string) int {
	req := httptest.NewRequest(method, target, nil)
	req.RemoteAddr = remote
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

func TestAdminThrottlesGuessesPerClientAddress(t *testing.T) {
	h, _ := adminServer(t)
	const attacker, operator = "198.51.100.7:1", "203.0.113.9:1"
	var denied int
	for i := 0; i < adminFailureBurst+5; i++ {
		switch got := doFrom(h, attacker, http.MethodGet, "/admin/keys", "wrong"); got {
		case http.StatusUnauthorized:
		case http.StatusTooManyRequests:
			denied++
		default:
			t.Fatalf("guess %d = %d, want 401 or 429", i, got)
		}
	}
	if denied == 0 {
		t.Fatal("ten wrong guesses in a row were never throttled")
	}
	if got := doFrom(h, attacker, http.MethodGet, "/admin/keys", testAdminToken); got != http.StatusOK {
		t.Errorf("the right token from a throttled address = %d, want 200", got)
	}
	if got := doFrom(h, attacker, http.MethodGet, "/admin/keys", "wrong"); got != http.StatusTooManyRequests {
		t.Errorf("a wrong token from a throttled address = %d, want 429", got)
	}
	if got := doFrom(h, operator, http.MethodGet, "/admin/keys", testAdminToken); got != http.StatusOK {
		t.Errorf("the right token from another address = %d, want 200", got)
	}
}

func TestAdminSuccessfulCallsDoNotUseUpTheGuessBudget(t *testing.T) {
	h, _ := adminServer(t)
	for i := 0; i < adminFailureBurst*4; i++ {
		if got := doFrom(h, "203.0.113.9:1", http.MethodGet, "/admin/keys", testAdminToken); got != http.StatusOK {
			t.Fatalf("call %d with the right token = %d, want 200", i, got)
		}
	}
}

func TestAdminPurgeUnusedRequiresTheTokenAndAValidAge(t *testing.T) {
	h, _ := adminServer(t)
	if rr := do(h, http.MethodPost, "/admin/keys/purge-unused?older_than_days=30", "", "wrong"); rr.Code != http.StatusUnauthorized {
		t.Errorf("purge with a wrong token = %d, want 401", rr.Code)
	}
	for _, q := range []string{"", "?older_than_days=", "?older_than_days=0", "?older_than_days=-1", "?older_than_days=abc", "?older_than_days=99999999"} {
		if rr := do(h, http.MethodPost, "/admin/keys/purge-unused"+q, "", testAdminToken); rr.Code != http.StatusBadRequest {
			t.Errorf("purge%s = %d, want 400", q, rr.Code)
		}
	}
}

func TestAdminPurgeUnusedReportsHowManyKeysItRemoved(t *testing.T) {
	cfg := defaultCfg()
	cfg.AdminToken = testAdminToken
	rig := newTokenRig(t, cfg)
	ctx := context.Background()
	for _, label := range []string{"squatter-a", "squatter-b"} {
		if _, err := rig.store.Issue(ctx, label, 0); err != nil {
			t.Fatal(err)
		}
	}
	used, _ := rig.store.Issue(ctx, "active", 0)
	usedKey, err := rig.store.Verify(ctx, used)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rig.store.BindTokens(ctx, usedKey.ID, []keys.TokenRef{{Platform: "ios", Token: "t1"}}, keys.BindLimits{}); err != nil {
		t.Fatal(err)
	}
	h := rig.srv.Router()
	const target = "/admin/keys/purge-unused?older_than_days=1"

	rr := do(h, http.MethodPost, target, "", testAdminToken)
	if rr.Code != http.StatusOK || strings.TrimSpace(rr.Body.String()) != `{"purged":0}` {
		t.Fatalf("purge of brand new keys = %d %s, want 200 {\"purged\":0}", rr.Code, rr.Body.String())
	}

	db, err := sql.Open("sqlite", "file:"+rig.dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE keys SET created_at = 1`); err != nil {
		t.Fatal(err)
	}
	rr = do(h, http.MethodPost, target, "", testAdminToken)
	if rr.Code != http.StatusOK || strings.TrimSpace(rr.Body.String()) != `{"purged":2}` {
		t.Fatalf("purge of old keys = %d %s, want 200 {\"purged\":2}", rr.Code, rr.Body.String())
	}
	if _, err := rig.store.Verify(ctx, used); err != nil {
		t.Errorf("the key that had sent was purged: %v", err)
	}
}

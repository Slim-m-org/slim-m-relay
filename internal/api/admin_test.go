// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func adminServer(t *testing.T) (http.Handler, func(method, path string) int) {
	t.Helper()
	cfg := defaultCfg()
	cfg.AdminToken = "admin-secret"
	srv, _, _, _ := newTestServer(t, cfg)
	h := srv.Router()
	return h, func(method, path string) int {
		return do(h, method, path, "", "admin-secret").Code
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
	rr := do(h, http.MethodGet, "/admin/keys", "", "admin-secret")
	if rr.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200", rr.Code)
	}
	if got := strings.TrimSpace(rr.Body.String()); got != `{"keys":[]}` {
		t.Errorf("body = %s, want {\"keys\":[]}", got)
	}
}

func TestAdminListReturnsKeyMetadataOnly(t *testing.T) {
	cfg := defaultCfg()
	cfg.AdminToken = "admin-secret"
	srv, _, _, store := newTestServer(t, cfg)
	secret, err := store.Issue(context.Background(), "https://slim.example", 0)
	if err != nil {
		t.Fatal(err)
	}
	rr := do(srv.Router(), http.MethodGet, "/admin/keys", "", "admin-secret")
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
	cfg.AdminToken = "admin-secret"
	srv, _, _, store := newTestServer(t, cfg)
	secret, _ := store.Issue(context.Background(), "", 0)
	k, _ := store.Verify(context.Background(), secret)
	path := "/admin/keys/" + strconv.FormatInt(k.ID, 10) + "/revoke"
	if rr := do(srv.Router(), http.MethodPost, path, "", "admin-secret"); rr.Code != http.StatusNoContent {
		t.Fatalf("first revoke = %d, want 204", rr.Code)
	}
	if rr := do(srv.Router(), http.MethodPost, path, "", "admin-secret"); rr.Code != http.StatusNotFound {
		t.Errorf("second revoke = %d, want 404", rr.Code)
	}
}

func TestAdminHandlersReportStoreFailureAs500(t *testing.T) {
	cfg := defaultCfg()
	cfg.AdminToken = "admin-secret"
	srv, _, _, store := newTestServer(t, cfg)
	_ = store.Close()
	if rr := do(srv.Router(), http.MethodGet, "/admin/keys", "", "admin-secret"); rr.Code != http.StatusInternalServerError {
		t.Errorf("list on a closed store = %d, want 500", rr.Code)
	}
	if rr := do(srv.Router(), http.MethodPost, "/admin/keys/1/revoke", "", "admin-secret"); rr.Code != http.StatusInternalServerError {
		t.Errorf("revoke on a closed store = %d, want 500", rr.Code)
	}
}

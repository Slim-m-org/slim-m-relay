// SPDX-License-Identifier: Apache-2.0

package fcm

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nc1107/slim-m-relay/internal/push"
)

const senderIDMismatch = `{"error":{"code":403,"message":"SenderId mismatch","status":"PERMISSION_DENIED","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"SENDER_ID_MISMATCH"}]}}`

const permissionDenied = `{"error":{"code":403,"message":"The caller does not have permission","status":"PERMISSION_DENIED"}}`

func sendForbidden(t *testing.T, code int, body string) (push.Status, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(nil)

	res := testSender(srv.URL).Send(context.Background(), []push.Message{{Token: "tok", Kind: push.KindWake, Payload: "c"}})
	if len(res) != 1 {
		t.Fatalf("results = %+v, want one", res)
	}
	return res[0].Status, logs.String()
}

// SENDER_ID_MISMATCH means one registration token belongs to another Firebase project, so
// it can never work here: it is a dead token, not a dead service-account credential.
func TestSenderIDMismatchIsUnregisteredNotCredentialDeath(t *testing.T) {
	status, logs := sendForbidden(t, http.StatusForbidden, senderIDMismatch)
	if status != push.StatusUnregistered {
		t.Errorf("status = %s, want unregistered for a per-token SENDER_ID_MISMATCH", status)
	}
	if strings.Contains(logs, "service-account credential") {
		t.Errorf("logged a credential-death line for a per-token error: %q", logs)
	}
}

func TestOtherForbiddenStillReadsAsCredentialDeath(t *testing.T) {
	status, logs := sendForbidden(t, http.StatusForbidden, permissionDenied)
	if status != push.StatusError {
		t.Errorf("status = %s, want error for a 403 that is not SENDER_ID_MISMATCH", status)
	}
	if !strings.Contains(logs, "service-account credential") {
		t.Errorf("a plain 403 must still log the credential failure, got %q", logs)
	}
}

func TestUnauthorizedStillReadsAsCredentialDeath(t *testing.T) {
	status, logs := sendForbidden(t, http.StatusUnauthorized, `{"error":{"code":401,"status":"UNAUTHENTICATED"}}`)
	if status != push.StatusError || !strings.Contains(logs, "service-account credential") {
		t.Errorf("401 = %s, logs %q; want error plus the credential log", status, logs)
	}
}

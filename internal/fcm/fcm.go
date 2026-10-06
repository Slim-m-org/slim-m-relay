// SPDX-License-Identifier: Apache-2.0

// Package fcm forwards content-free pushes to Firebase Cloud Messaging (FCM HTTP v1) for
// Android devices. It talks to the REST API directly with an OAuth2 token minted from a
// service account, avoiding the heavyweight Firebase Admin SDK.
//
// Every message it sends is data-only: the home server's already-encrypted payload and the
// coarse kind travel as opaque data fields, never as a plaintext notification title or
// body, so FCM itself - and its logs - never see content. The device wakes in the
// background and decrypts locally to decide how, or whether, to surface a notification.
package fcm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/nc1107/slim-m-relay/internal/push"
)

const (
	scope    = "https://www.googleapis.com/auth/firebase.messaging"
	endpoint = "https://fcm.googleapis.com"
)

// maxErrorBodyBytes bounds how much of an error response sendOne reads to classify a
// failure. FCM v1 pretty-prints its error JSON by default, and a real INVALID_ARGUMENT
// body naming a malformed registration token runs to several hundred bytes on its own; a
// tighter cap risks truncating it mid-document, which makes json.Unmarshal fail, which
// makes tokenFieldViolation return false, which misclassifies a dead token as StatusError
// (retried forever) instead of StatusUnregistered. 16 KiB comfortably holds any real
// provider error while still bounding memory per response.
const maxErrorBodyBytes = 16 * 1024

// Sender holds the FCM credentials and posts messages to the REST API.
type Sender struct {
	tokens    oauth2.TokenSource
	projectID string
	http      *http.Client
	endpoint  string
}

// New builds a Sender from a Firebase service-account JSON.
func New(ctx context.Context, credentialsJSON []byte) (*Sender, error) {
	httpClient := &http.Client{Timeout: 15 * time.Second}
	// The oauth2.TokenSource interface's Token() takes no context or per-call deadline, so
	// the only way to bound how long a token refresh can block is the http.Client captured
	// in the context CredentialsFromJSONWithType is given here - that client is what every future
	// refresh through creds.TokenSource uses, for the lifetime of the Sender. Without this,
	// a blackholed token endpoint hangs Token() forever on http.DefaultClient, which has no
	// timeout, and no per-request deadline can ever cut that off.
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	creds, err := google.CredentialsFromJSONWithType(ctx, credentialsJSON, google.ServiceAccount, scope)
	if err != nil {
		return nil, fmt.Errorf("parse FCM credentials: %w", err)
	}
	if creds.ProjectID == "" {
		return nil, fmt.Errorf("FCM credentials missing project_id")
	}
	return &Sender{
		tokens:    creds.TokenSource,
		projectID: creds.ProjectID,
		http:      httpClient,
		endpoint:  endpoint,
	}, nil
}

// ProjectID is the Firebase project these notifications are sent through.
func (s *Sender) ProjectID() string { return s.projectID }

// Send delivers every message and returns one push.Result per input in the same order (FCM
// v1 has no multicast, so it is one request per token). It never logs the token or the
// payload; the caller decides what to record from the returned statuses.
func (s *Sender) Send(ctx context.Context, msgs []push.Message) []push.Result {
	results := make([]push.Result, len(msgs))
	tok, err := s.token(ctx)
	if err != nil {
		for i, m := range msgs {
			results[i] = push.Result{Token: m.Token, Status: push.StatusError}
		}
		return results
	}
	url := fmt.Sprintf("%s/v1/projects/%s/messages:send", s.endpoint, s.projectID)
	for i, m := range msgs {
		results[i] = push.Result{Token: m.Token, Status: s.sendOne(ctx, url, tok.AccessToken, m)}
	}
	return results
}

// token fetches an access token bounded by ctx. oauth2.TokenSource.Token() itself takes no
// context and so cannot be interrupted directly - that is what let a blackholed OAuth token
// endpoint hold a /v1/send request open past its configured deadline regardless of how the
// deadline was enforced elsewhere. Running the fetch in its own goroutine and racing it
// against ctx.Done() is what makes the caller's deadline actually cut this off. If ctx wins,
// the goroutine is simply abandoned rather than killed - Go has no way to do that - but it
// can never run past New's http.Client timeout, so it still finishes and exits on its own,
// its result silently discarded into the buffered channel.
func (s *Sender) token(ctx context.Context) (*oauth2.Token, error) {
	type result struct {
		tok *oauth2.Token
		err error
	}
	ch := make(chan result, 1)
	go func() {
		tok, err := s.tokens.Token()
		ch <- result{tok, err}
	}()
	select {
	case r := <-ch:
		return r.tok, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Sender) sendOne(ctx context.Context, url, access string, m push.Message) push.Status {
	body, _ := json.Marshal(map[string]any{
		"message": map[string]any{
			"token": m.Token,
			// Data-only: kind and the opaque ciphertext are the only fields, so FCM never
			// renders (and never sees) a plaintext notification on the relay's behalf.
			"data": map[string]string{
				"kind":    string(m.Kind),
				"payload": m.Payload,
			},
			// High priority wakes the app promptly even while backgrounded; the payload is
			// opaque, so timely delivery is the only lever the relay has.
			"android": androidConfig(m.Kind),
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return push.StatusError
	}
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return push.StatusError
	}
	defer resp.Body.Close()
	if resp.StatusCode < 300 {
		return push.StatusDelivered
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
	code := errorCode(raw)
	if (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) && code != "SENDER_ID_MISMATCH" {
		// Whole-pipeline credential death, not per-token noise: the service account is
		// rejected outright, so every android send fails until the operator fixes it.
		// SENDER_ID_MISMATCH is the one 403 that is per-token (a token minted for another
		// Firebase project), so it falls through to be pruned below.
		log.Printf("relay: fcm rejected the service-account credential (http %d); every android send will fail until it is fixed", resp.StatusCode)
		return push.StatusError
	}
	if resp.StatusCode == http.StatusBadRequest && tokenFieldViolation(raw) {
		// Live FCM v1 reports a malformed or corrupt registration token as HTTP 400
		// INVALID_ARGUMENT with a BadRequest field violation naming "message.token", not as
		// the 404 UNREGISTERED the docs lead you to expect. Left unmapped this reads as
		// StatusError (worth a retry) and the caller would resend to a token that can never
		// succeed. A 400 from some other field - a malformed payload or message body - is a
		// server bug and must stay StatusError.
		return push.StatusUnregistered
	}
	if code == "UNREGISTERED" || code == "SENDER_ID_MISMATCH" {
		return push.StatusUnregistered
	}
	return push.StatusError
}

// fcmErrorDetail is one entry of an FCM v1 error's "details" array. The same array carries
// two different detail shapes depending on the failure - errorCode for the FCM-specific
// reason, fieldViolations for a google.rpc.BadRequest - so both are read from one struct.
type fcmErrorDetail struct {
	ErrorCode       string `json:"errorCode"`
	FieldViolations []struct {
		Field string `json:"field"`
	} `json:"fieldViolations"`
}

// errorCode pulls FCM v1's machine-readable code out of an error response, preferring the
// specific code in details (e.g. UNREGISTERED) over the generic status. Returns "" when the
// body isn't the shape we expect.
func errorCode(body []byte) string {
	var resp struct {
		Error struct {
			Status  string           `json:"status"`
			Details []fcmErrorDetail `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}
	for _, d := range resp.Error.Details {
		if d.ErrorCode != "" {
			return d.ErrorCode
		}
	}
	return resp.Error.Status
}

// tokenFieldViolation reports whether an FCM v1 error body names "message.token" in a
// google.rpc.BadRequest field violation - the shape of a malformed/corrupt registration
// token, as opposed to any other 400.
func tokenFieldViolation(body []byte) bool {
	var resp struct {
		Error struct {
			Details []fcmErrorDetail `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return false
	}
	for _, d := range resp.Error.Details {
		for _, v := range d.FieldViolations {
			if v.Field == "message.token" {
				return true
			}
		}
	}
	return false
}

// androidConfig keeps every kind high priority so a dozing device still wakes for it, and
// caps a call signal's lifetime so a device that comes back online late never rings for a
// call that is already over.
func androidConfig(kind push.Kind) map[string]any {
	cfg := map[string]any{"priority": "high"}
	if kind.IsCallSignal() {
		cfg["ttl"] = fmt.Sprintf("%ds", int(push.CallSignalTTL/time.Second))
	}
	return cfg
}

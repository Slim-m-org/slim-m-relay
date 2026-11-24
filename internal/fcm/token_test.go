// SPDX-License-Identifier: Apache-2.0

package fcm

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/nc1107/slim-m-relay/internal/push"
)

// countingSource counts Token calls and answers from a script, so a test can tell how many
// fetches the gate really started.
type countingSource struct {
	calls   atomic.Int32
	unblock <-chan struct{}
	tok     *oauth2.Token
	err     error
}

func (c *countingSource) Token() (*oauth2.Token, error) {
	c.calls.Add(1)
	if c.unblock != nil {
		<-c.unblock
	}
	return c.tok, c.err
}

// During an OAuth outage every message of every request used to park its own goroutine behind
// oauth2's mutex. The gate must start one fetch no matter how many sends wait on it.
func TestBlackholedTokenEndpointParksOneFetchNotOnePerMessage(t *testing.T) {
	unblock := make(chan struct{})
	src := &countingSource{unblock: unblock, tok: &oauth2.Token{AccessToken: "late"}}
	t.Cleanup(func() { close(unblock) })
	s := testSender("http://127.0.0.1:0")
	s.tokens = src

	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			res := s.Send(ctx, []push.Message{{Token: "tok", Kind: push.KindWake, Payload: "c"}})
			if len(res) != 1 || res[0].Status != push.StatusRetry {
				t.Errorf("results = %+v, want one retry while the token fetch hangs", res)
			}
		}()
	}
	wg.Wait()

	if got := src.calls.Load(); got != 1 {
		t.Errorf("token source was asked %d times, want exactly 1 shared fetch", got)
	}
}

func TestCachedTokenServesEverySendWithoutAnotherFetch(t *testing.T) {
	fcm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer fcm.Close()
	src := &countingSource{tok: &oauth2.Token{AccessToken: "ok", Expiry: time.Now().Add(time.Hour)}}
	s := testSender(fcm.URL)
	s.tokens = src

	for i := 0; i < 50; i++ {
		res := s.Send(context.Background(), []push.Message{{Token: "tok", Kind: push.KindWake, Payload: "c"}})
		if res[0].Status != push.StatusDelivered {
			t.Fatalf("send %d = %+v, want delivered", i, res)
		}
	}

	if got := src.calls.Load(); got != 1 {
		t.Errorf("token source was asked %d times for 50 sends on one valid token, want 1", got)
	}
}

// A failed fetch is remembered briefly so the next sends fail at once instead of each paying
// a fetch timeout, and a fetch that succeeds afterwards clears it.
func TestFailedTokenFetchIsRememberedThenRecovers(t *testing.T) {
	src := &countingSource{err: errors.New("token endpoint down")}
	var g tokenGate

	for i := 0; i < 5; i++ {
		if _, err := g.token(context.Background(), src); err == nil {
			t.Fatalf("fetch %d succeeded, want the remembered failure", i)
		}
	}
	if got := src.calls.Load(); got != 1 {
		t.Fatalf("token source was asked %d times inside the backoff, want 1", got)
	}

	g.mu.Lock()
	g.failedAt = time.Now().Add(-2 * tokenFailureBackoff)
	g.mu.Unlock()
	src.err, src.tok = nil, &oauth2.Token{AccessToken: "back"}
	tok, err := g.token(context.Background(), src)
	if err != nil || tok.AccessToken != "back" {
		t.Fatalf("after the backoff: token %+v err %v, want a fresh token", tok, err)
	}
	if got := src.calls.Load(); got != 2 {
		t.Errorf("token source was asked %d times, want 2 (the failure, then the recovery)", got)
	}
}

// A dead service account fails every message of a request alike, so it logs once per request.
func TestCredentialDeathLogsOncePerRequest(t *testing.T) {
	fcm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":401,"status":"UNAUTHENTICATED"}}`))
	}))
	defer fcm.Close()
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })

	s := testSender(fcm.URL)
	for request := 0; request < 2; request++ {
		ctx := push.WithRequestScope(context.Background())
		for i := 0; i < 100; i++ {
			s.Send(ctx, []push.Message{{Token: "tok", Kind: push.KindWake, Payload: "c"}})
		}
	}

	if got := strings.Count(buf.String(), "service-account credential"); got != 2 {
		t.Errorf("logged %d credential lines across 2 requests of 100 sends, want 2", got)
	}
}

func TestSendClassifiesProviderTroubleAsRetry(t *testing.T) {
	for code, want := range map[int]push.Status{
		http.StatusTooManyRequests:     push.StatusRetry,
		http.StatusServiceUnavailable:  push.StatusRetry,
		http.StatusInternalServerError: push.StatusRetry,
		http.StatusBadRequest:          push.StatusRejected,
		http.StatusNotFound:            push.StatusRejected,
	} {
		fcm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"error":{"status":"UNAVAILABLE"}}`))
		}))
		res := testSender(fcm.URL).Send(context.Background(), []push.Message{{Token: "tok", Kind: push.KindWake, Payload: "c"}})
		fcm.Close()
		if res[0].Status != want {
			t.Errorf("http %d = %s, want %s", code, res[0].Status, want)
		}
	}
}

// A dead service account makes every token fetch fail; the operator needs one line naming it.
func TestTokenFetchFailureLogsOncePerRequest(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })

	s := testSender("http://127.0.0.1:0")
	s.tokens = &countingSource{err: errors.New("invalid_grant")}
	ctx := push.WithRequestScope(context.Background())
	for i := 0; i < 50; i++ {
		res := s.Send(ctx, []push.Message{{Token: "tok", Kind: push.KindWake, Payload: "c"}})
		if res[0].Status != push.StatusRetry {
			t.Fatalf("status = %s, want retry", res[0].Status)
		}
	}
	if got := strings.Count(buf.String(), "could not mint an access token"); got != 1 {
		t.Errorf("logged %d token-failure lines for one request, want 1 (log: %q)", got, buf.String())
	}
}

// A cancelled request is the caller's deadline, not a credential fault, so it stays silent.
func TestTokenFetchCancelledByDeadlineIsNotLogged(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })

	s := testSender("http://127.0.0.1:0")
	s.tokens = &countingSource{err: errors.New("invalid_grant")}
	ctx, cancel := context.WithCancel(push.WithRequestScope(context.Background()))
	cancel()
	s.Send(ctx, []push.Message{{Token: "tok", Kind: push.KindWake, Payload: "c"}})
	if strings.Contains(buf.String(), "access token") {
		t.Errorf("logged a token failure for a cancelled request: %q", buf.String())
	}
}

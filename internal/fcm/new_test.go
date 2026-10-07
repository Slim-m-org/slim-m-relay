// SPDX-License-Identifier: Apache-2.0

package fcm

import (
	"context"
	"strings"
	"testing"
)

func TestNewRejectsNonServiceAccountCredentials(t *testing.T) {
	js := `{"type":"external_account","audience":"//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q","subject_token_type":"urn:ietf:params:oauth:token-type:jwt","token_url":"https://sts.googleapis.com/v1/token","credential_source":{"file":"/etc/hostname"},"project_id":"my-proj"}`
	s, err := New(context.Background(), []byte(js))
	if err == nil || !strings.Contains(err.Error(), "service_account") {
		t.Fatalf("expected a credential type error, got sender=%v err=%v", s != nil, err)
	}
}

func TestNewRejectsAServiceAccountWithoutProjectID(t *testing.T) {
	_, err := New(context.Background(), []byte(`{"type":"service_account","client_email":"a@b.iam.gserviceaccount.com","private_key":"x","token_uri":"https://oauth2.googleapis.com/token"}`))
	if err == nil {
		t.Fatal("want an error for credentials missing project_id")
	}
}

func TestNewRejectsInvalidJSON(t *testing.T) {
	if _, err := New(context.Background(), []byte("not json")); err == nil {
		t.Fatal("want an error for invalid JSON")
	}
}

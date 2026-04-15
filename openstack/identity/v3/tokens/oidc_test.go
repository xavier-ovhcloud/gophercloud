package tokens

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// fakeIDPServer returns a test server that mimics an OIDC IdP.
// It exposes:
//
//	GET  /.well-known/openid-configuration  → discovery document
//	POST /token                             → OIDC token response
func fakeIDPServer(t *testing.T, grantType string, extraChecks func(r *http.Request)) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]string{
			"issuer":                 "https://idp.example.com",
			"token_endpoint":         "http://" + r.Host + "/token",
			"authorization_endpoint": "http://" + r.Host + "/authorize",
			"jwks_uri":               "http://" + r.Host + "/jwks",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if gt := r.FormValue("grant_type"); gt != grantType {
			http.Error(w, "wrong grant_type: "+gt, http.StatusBadRequest)
			return
		}
		if extraChecks != nil {
			extraChecks(r)
		}
		resp := map[string]interface{}{
			"access_token": "fake-access-token",
			"id_token":     "fake-id-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	return httptest.NewServer(mux)
}

// fakeKeystoneServer returns a test server that mimics Keystone v3 federation.
// It exposes:
//
//	POST /OS-FEDERATION/identity_providers/{idp}/protocols/{proto}/auth → unscoped token
//	POST /auth/tokens → scoped token
func fakeKeystoneServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// Federation endpoint — accepts any IdP/protocol path
	mux.HandleFunc("/OS-FEDERATION/", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		w.Header().Set("X-Subject-Token", "fake-unscoped-token")
		w.WriteHeader(http.StatusCreated)
	})

	// Token scoping endpoint
	mux.HandleFunc("/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("X-Subject-Token", "fake-scoped-token")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token": map[string]interface{}{
				"methods":    []string{"token"},
				"expires_at": "2099-01-01T00:00:00.000000Z",
			},
		})
	})

	return httptest.NewServer(mux)
}

// ---------------------------------------------------------------------------
// OidcClientCredentials
// ---------------------------------------------------------------------------

func TestOidcClientCredentials_GetToken_WithDiscovery(t *testing.T) {
	idp := fakeIDPServer(t, "client_credentials", func(r *http.Request) {
		if r.FormValue("client_id") != "my-client" {
			t.Errorf("expected client_id=my-client, got %s", r.FormValue("client_id"))
		}
		if r.FormValue("client_secret") != "my-secret" {
			t.Errorf("expected client_secret=my-secret, got %s", r.FormValue("client_secret"))
		}
	})
	defer idp.Close()

	ks := fakeKeystoneServer(t)
	defer ks.Close()

	auth := &OidcClientCredentials{
		OIDCBase: OIDCBase{
			IdentityEndpoint:  ks.URL,
			IdentityProvider:  "test-idp",
			Protocol:          "openid",
			DiscoveryEndpoint: idp.URL + "/.well-known/openid-configuration",
			ClientID:          "my-client",
			ClientSecret:      "my-secret",
			ProjectID:         "test-project-id",
			AccessTokenType:   AccessTokenTypeAccess,
		},
	}

	token, err := auth.GetToken(context.Background())
	if err != nil {
		t.Fatalf("GetToken() error: %v", err)
	}
	if token != "fake-scoped-token" {
		t.Errorf("expected fake-scoped-token, got %s", token)
	}
}

func TestOidcClientCredentials_GetToken_WithTokenEndpoint(t *testing.T) {
	idp := fakeIDPServer(t, "client_credentials", nil)
	defer idp.Close()

	ks := fakeKeystoneServer(t)
	defer ks.Close()

	auth := &OidcClientCredentials{
		OIDCBase: OIDCBase{
			IdentityEndpoint: ks.URL,
			IdentityProvider: "test-idp",
			Protocol:         "openid",
			TokenEndpoint:    idp.URL + "/token", // skip discovery
			ClientID:         "my-client",
			ClientSecret:     "my-secret",
			ProjectID:        "test-project-id",
		},
	}

	token, err := auth.GetToken(context.Background())
	if err != nil {
		t.Fatalf("GetToken() error: %v", err)
	}
	if token != "fake-scoped-token" {
		t.Errorf("expected fake-scoped-token, got %s", token)
	}
}

func TestOidcClientCredentials_GetToken_IDToken(t *testing.T) {
	idp := fakeIDPServer(t, "client_credentials", nil)
	defer idp.Close()

	ks := fakeKeystoneServer(t)
	defer ks.Close()

	auth := &OidcClientCredentials{
		OIDCBase: OIDCBase{
			IdentityEndpoint: ks.URL,
			IdentityProvider: "ovhcloud-emea",
			Protocol:         "openid",
			TokenEndpoint:    idp.URL + "/token",
			ClientID:         "my-client",
			ClientSecret:     "my-secret",
			ProjectID:        "ovh-project-id",
			AccessTokenType:  AccessTokenTypeID, // OVHcloud requires id_token
		},
	}

	token, err := auth.GetToken(context.Background())
	if err != nil {
		t.Fatalf("GetToken() error: %v", err)
	}
	if token != "fake-scoped-token" {
		t.Errorf("expected fake-scoped-token, got %s", token)
	}
}

func TestOidcClientCredentials_UnscopedToken(t *testing.T) {
	idp := fakeIDPServer(t, "client_credentials", nil)
	defer idp.Close()

	ks := fakeKeystoneServer(t)
	defer ks.Close()

	// No ProjectID, DomainID → should return unscoped token
	auth := &OidcClientCredentials{
		OIDCBase: OIDCBase{
			IdentityEndpoint: ks.URL,
			IdentityProvider: "test-idp",
			Protocol:         "openid",
			TokenEndpoint:    idp.URL + "/token",
			ClientID:         "my-client",
			ClientSecret:     "my-secret",
			// no scope fields
		},
	}

	token, err := auth.GetToken(context.Background())
	if err != nil {
		t.Fatalf("GetToken() error: %v", err)
	}
	if token != "fake-unscoped-token" {
		t.Errorf("expected fake-unscoped-token (no scope set), got %s", token)
	}
}

func TestOidcClientCredentials_MissingDiscoveryAndEndpoint(t *testing.T) {
	auth := &OidcClientCredentials{
		OIDCBase: OIDCBase{
			IdentityEndpoint: "https://keystone.example.com/v3",
			IdentityProvider: "test-idp",
			Protocol:         "openid",
			ClientID:         "my-client",
			ClientSecret:     "my-secret",
			// neither DiscoveryEndpoint nor TokenEndpoint set
		},
	}

	_, err := auth.GetToken(context.Background())
	if err == nil {
		t.Fatal("expected error when neither DiscoveryEndpoint nor TokenEndpoint is set")
	}
}

// ---------------------------------------------------------------------------
// OidcPassword
// ---------------------------------------------------------------------------

func TestOidcPassword_GetToken(t *testing.T) {
	idp := fakeIDPServer(t, "password", func(r *http.Request) {
		if r.FormValue("username") != "alice" {
			t.Errorf("expected username=alice, got %s", r.FormValue("username"))
		}
		if r.FormValue("password") != "s3cr3t" {
			t.Errorf("expected password=s3cr3t, got %s", r.FormValue("password"))
		}
	})
	defer idp.Close()

	ks := fakeKeystoneServer(t)
	defer ks.Close()

	auth := &OidcPassword{
		OIDCBase: OIDCBase{
			IdentityEndpoint: ks.URL,
			IdentityProvider: "test-idp",
			Protocol:         "openid",
			TokenEndpoint:    idp.URL + "/token",
			ClientID:         "my-client",
			ClientSecret:     "my-secret",
			ProjectID:        "test-project-id",
		},
		Username: "alice",
		Password: "s3cr3t",
	}

	token, err := auth.GetToken(context.Background())
	if err != nil {
		t.Fatalf("GetToken() error: %v", err)
	}
	if token != "fake-scoped-token" {
		t.Errorf("expected fake-scoped-token, got %s", token)
	}
}

// ---------------------------------------------------------------------------
// OidcAccessToken
// ---------------------------------------------------------------------------

func TestOidcAccessToken_GetToken(t *testing.T) {
	ks := fakeKeystoneServer(t)
	defer ks.Close()

	auth := &OidcAccessToken{
		OIDCBase: OIDCBase{
			IdentityEndpoint: ks.URL,
			IdentityProvider: "test-idp",
			Protocol:         "openid",
			ProjectID:        "test-project-id",
		},
		Token: "my-pre-obtained-token",
	}

	token, err := auth.GetToken(context.Background())
	if err != nil {
		t.Fatalf("GetToken() error: %v", err)
	}
	if token != "fake-scoped-token" {
		t.Errorf("expected fake-scoped-token, got %s", token)
	}
}

func TestOidcAccessToken_MissingToken(t *testing.T) {
	auth := &OidcAccessToken{
		OIDCBase: OIDCBase{
			IdentityEndpoint: "https://keystone.example.com/v3",
			IdentityProvider: "test-idp",
			Protocol:         "openid",
		},
		// Token intentionally empty
	}

	_, err := auth.GetToken(context.Background())
	if err == nil {
		t.Fatal("expected error when Token is empty")
	}
}

// ---------------------------------------------------------------------------
// OidcAuthorizationCode
// ---------------------------------------------------------------------------

func TestOidcAuthorizationCode_GetToken(t *testing.T) {
	idp := fakeIDPServer(t, "authorization_code", func(r *http.Request) {
		if r.FormValue("code") != "auth-code-xyz" {
			t.Errorf("expected code=auth-code-xyz, got %s", r.FormValue("code"))
		}
		if r.FormValue("redirect_uri") != "https://myapp.example.com/callback" {
			t.Errorf("unexpected redirect_uri: %s", r.FormValue("redirect_uri"))
		}
	})
	defer idp.Close()

	ks := fakeKeystoneServer(t)
	defer ks.Close()

	auth := &OidcAuthorizationCode{
		OIDCBase: OIDCBase{
			IdentityEndpoint: ks.URL,
			IdentityProvider: "test-idp",
			Protocol:         "openid",
			TokenEndpoint:    idp.URL + "/token",
			ClientID:         "my-client",
			ClientSecret:     "my-secret",
			ProjectID:        "test-project-id",
		},
		Code:        "auth-code-xyz",
		RedirectURI: "https://myapp.example.com/callback",
	}

	token, err := auth.GetToken(context.Background())
	if err != nil {
		t.Fatalf("GetToken() error: %v", err)
	}
	if token != "fake-scoped-token" {
		t.Errorf("expected fake-scoped-token, got %s", token)
	}
}

func TestOidcAuthorizationCode_MissingCode(t *testing.T) {
	auth := &OidcAuthorizationCode{
		OIDCBase: OIDCBase{
			IdentityEndpoint: "https://keystone.example.com/v3",
			IdentityProvider: "test-idp",
			Protocol:         "openid",
			TokenEndpoint:    "https://idp.example.com/token",
			ClientID:         "my-client",
			ClientSecret:     "my-secret",
		},
		// Code intentionally empty
	}

	_, err := auth.GetToken(context.Background())
	if err == nil {
		t.Fatal("expected error when Code is empty")
	}
}

// ---------------------------------------------------------------------------
// Scopes default
// ---------------------------------------------------------------------------

func TestOIDCBase_DefaultScope(t *testing.T) {
	base := &OIDCBase{}
	if s := base.scopes(); s != "openid" {
		t.Errorf("expected default scope 'openid', got %q", s)
	}
}

func TestOIDCBase_CustomScopes(t *testing.T) {
	base := &OIDCBase{
		Scopes: []string{"openid", "profile", "email", "publicCloudProject/all"},
	}
	expected := "openid profile email publicCloudProject/all"
	if s := base.scopes(); s != expected {
		t.Errorf("expected %q, got %q", expected, s)
	}
}

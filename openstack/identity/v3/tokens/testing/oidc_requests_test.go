package testing

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/tokens"
	th "github.com/gophercloud/gophercloud/v2/testhelper"
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
		th.TestMethod(t, r, http.MethodPost)

		err := r.ParseForm()
		th.AssertNoErr(t, err)

		th.AssertEquals(t, grantType, r.FormValue("grant_type"))

		if extraChecks != nil {
			extraChecks(r)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(OIDCTokenOutput))
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
		_, _ = w.Write([]byte(KeystoneFederationOutput))
	})

	// Token scoping endpoint
	mux.HandleFunc("/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		th.TestMethod(t, r, http.MethodPost)

		w.Header().Set("X-Subject-Token", "fake-scoped-token")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(KeystoneScopedTokenOutput))
	})

	return httptest.NewServer(mux)
}

// ---------------------------------------------------------------------------
// OidcClientCredentials
// ---------------------------------------------------------------------------

func TestOidcClientCredentials_GetToken_WithDiscovery(t *testing.T) {
	idp := fakeIDPServer(t, "client_credentials", func(r *http.Request) {
		th.AssertEquals(t, "my-client", r.FormValue("client_id"))
		th.AssertEquals(t, "my-secret", r.FormValue("client_secret"))
	})
	defer idp.Close()

	ks := fakeKeystoneServer(t)
	defer ks.Close()

	auth := &tokens.OidcClientCredentials{
		OIDCBase: tokens.OIDCBase{
			IdentityEndpoint:  ks.URL,
			IdentityProvider:  "test-idp",
			Protocol:          "openid",
			DiscoveryEndpoint: idp.URL + "/.well-known/openid-configuration",
			ClientID:          "my-client",
			ClientSecret:      "my-secret",
			ProjectID:         "test-project-id",
			AccessTokenType:   tokens.AccessTokenTypeAccess,
		},
	}

	token, err := auth.GetToken(context.Background())
	th.AssertNoErr(t, err)
	th.AssertEquals(t, "fake-scoped-token", token)
}

func TestOidcClientCredentials_GetToken_WithTokenEndpoint(t *testing.T) {
	idp := fakeIDPServer(t, "client_credentials", nil)
	defer idp.Close()

	ks := fakeKeystoneServer(t)
	defer ks.Close()

	auth := &tokens.OidcClientCredentials{
		OIDCBase: tokens.OIDCBase{
			IdentityEndpoint: ks.URL,
			IdentityProvider: "test-idp",
			Protocol:         "openid",
			TokenEndpoint:    idp.URL + "/token",
			ClientID:         "my-client",
			ClientSecret:     "my-secret",
			ProjectID:        "test-project-id",
		},
	}

	token, err := auth.GetToken(context.Background())
	th.AssertNoErr(t, err)
	th.AssertEquals(t, "fake-scoped-token", token)
}

func TestOidcClientCredentials_GetToken_IDToken(t *testing.T) {
	idp := fakeIDPServer(t, "client_credentials", nil)
	defer idp.Close()

	ks := fakeKeystoneServer(t)
	defer ks.Close()

	auth := &tokens.OidcClientCredentials{
		OIDCBase: tokens.OIDCBase{
			IdentityEndpoint: ks.URL,
			IdentityProvider: "ovhcloud-emea",
			Protocol:         "openid",
			TokenEndpoint:    idp.URL + "/token",
			ClientID:         "my-client",
			ClientSecret:     "my-secret",
			ProjectID:        "ovh-project-id",
			AccessTokenType:  tokens.AccessTokenTypeID,
		},
	}

	token, err := auth.GetToken(context.Background())
	th.AssertNoErr(t, err)
	th.AssertEquals(t, "fake-scoped-token", token)
}

func TestOidcClientCredentials_UnscopedToken(t *testing.T) {
	idp := fakeIDPServer(t, "client_credentials", nil)
	defer idp.Close()

	ks := fakeKeystoneServer(t)
	defer ks.Close()

	auth := &tokens.OidcClientCredentials{
		OIDCBase: tokens.OIDCBase{
			IdentityEndpoint: ks.URL,
			IdentityProvider: "test-idp",
			Protocol:         "openid",
			TokenEndpoint:    idp.URL + "/token",
			ClientID:         "my-client",
			ClientSecret:     "my-secret",
		},
	}

	token, err := auth.GetToken(context.Background())
	th.AssertNoErr(t, err)
	th.AssertEquals(t, "fake-unscoped-token", token)
}

func TestOidcClientCredentials_MissingDiscoveryAndEndpoint(t *testing.T) {
	auth := &tokens.OidcClientCredentials{
		OIDCBase: tokens.OIDCBase{
			IdentityEndpoint: "https://keystone.example.com/v3",
			IdentityProvider: "test-idp",
			Protocol:         "openid",
			ClientID:         "my-client",
			ClientSecret:     "my-secret",
		},
	}

	_, err := auth.GetToken(context.Background())
	th.AssertErr(t, err)
}

// ---------------------------------------------------------------------------
// OidcPassword
// ---------------------------------------------------------------------------

func TestOidcPassword_GetToken(t *testing.T) {
	idp := fakeIDPServer(t, "password", func(r *http.Request) {
		th.AssertEquals(t, "alice", r.FormValue("username"))
		th.AssertEquals(t, "s3cr3t", r.FormValue("password"))
	})
	defer idp.Close()

	ks := fakeKeystoneServer(t)
	defer ks.Close()

	auth := &tokens.OidcPassword{
		OIDCBase: tokens.OIDCBase{
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
	th.AssertNoErr(t, err)
	th.AssertEquals(t, "fake-scoped-token", token)
}

// ---------------------------------------------------------------------------
// OidcAccessToken
// ---------------------------------------------------------------------------

func TestOidcAccessToken_GetToken(t *testing.T) {
	ks := fakeKeystoneServer(t)
	defer ks.Close()

	auth := &tokens.OidcAccessToken{
		OIDCBase: tokens.OIDCBase{
			IdentityEndpoint: ks.URL,
			IdentityProvider: "test-idp",
			Protocol:         "openid",
			ProjectID:        "test-project-id",
		},
		Token: "my-pre-obtained-token",
	}

	token, err := auth.GetToken(context.Background())
	th.AssertNoErr(t, err)
	th.AssertEquals(t, "fake-scoped-token", token)
}

func TestOidcAccessToken_MissingToken(t *testing.T) {
	auth := &tokens.OidcAccessToken{
		OIDCBase: tokens.OIDCBase{
			IdentityEndpoint: "https://keystone.example.com/v3",
			IdentityProvider: "test-idp",
			Protocol:         "openid",
		},
	}

	_, err := auth.GetToken(context.Background())
	th.AssertErr(t, err)
}

// ---------------------------------------------------------------------------
// OidcAuthorizationCode
// ---------------------------------------------------------------------------

func TestOidcAuthorizationCode_GetToken(t *testing.T) {
	idp := fakeIDPServer(t, "authorization_code", func(r *http.Request) {
		th.AssertEquals(t, "auth-code-xyz", r.FormValue("code"))
		th.AssertEquals(t, "https://myapp.example.com/callback", r.FormValue("redirect_uri"))
	})
	defer idp.Close()

	ks := fakeKeystoneServer(t)
	defer ks.Close()

	auth := &tokens.OidcAuthorizationCode{
		OIDCBase: tokens.OIDCBase{
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
	th.AssertNoErr(t, err)
	th.AssertEquals(t, "fake-scoped-token", token)
}

func TestOidcAuthorizationCode_MissingCode(t *testing.T) {
	auth := &tokens.OidcAuthorizationCode{
		OIDCBase: tokens.OIDCBase{
			IdentityEndpoint: "https://keystone.example.com/v3",
			IdentityProvider: "test-idp",
			Protocol:         "openid",
			TokenEndpoint:    "https://idp.example.com/token",
			ClientID:         "my-client",
			ClientSecret:     "my-secret",
		},
	}

	_, err := auth.GetToken(context.Background())
	th.AssertErr(t, err)
}

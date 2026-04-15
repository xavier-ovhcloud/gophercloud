//go:build acceptance || identity || oidc

package v3

import (
	"context"
	"os"
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/tokens"
	th "github.com/gophercloud/gophercloud/v2/testhelper"
)

// TestOidcClientCredentials_AcceptanceTest authenticates against a real
// Keystone using the OIDC Client Credentials flow.
//
// Required environment variables:
//
//	OS_AUTH_URL            - Keystone endpoint (e.g. https://auth.cloud.ovh.net/v3)
//	OS_IDENTITY_PROVIDER   - IdP name registered in Keystone
//	OS_PROTOCOL            - Federation protocol (typically "openid")
//	OS_OIDC_DISCOVERY_URL  - OIDC discovery endpoint
//	OS_OIDC_CLIENT_ID      - OIDC client ID
//	OS_OIDC_CLIENT_SECRET  - OIDC client secret
//	OS_PROJECT_ID          - Project to scope to (optional)
func TestOidcClientCredentials_AcceptanceTest(t *testing.T) {
	authURL := os.Getenv("OS_AUTH_URL")
	idp := os.Getenv("OS_IDENTITY_PROVIDER")
	protocol := os.Getenv("OS_PROTOCOL")
	discoveryURL := os.Getenv("OS_OIDC_DISCOVERY_URL")
	clientID := os.Getenv("OS_OIDC_CLIENT_ID")
	clientSecret := os.Getenv("OS_OIDC_CLIENT_SECRET")
	projectID := os.Getenv("OS_PROJECT_ID")

	if authURL == "" || idp == "" || protocol == "" || discoveryURL == "" || clientID == "" || clientSecret == "" {
		t.Skip("Skipping OIDC acceptance test: missing required OS_* environment variables")
	}

	auth := &tokens.OidcClientCredentials{
		OIDCBase: tokens.OIDCBase{
			IdentityEndpoint:  authURL,
			IdentityProvider:  idp,
			Protocol:          protocol,
			DiscoveryEndpoint: discoveryURL,
			ClientID:          clientID,
			ClientSecret:      clientSecret,
			ProjectID:         projectID,
		},
	}

	token, err := auth.GetToken(context.Background())
	th.AssertNoErr(t, err)

	if token == "" {
		t.Fatal("expected non-empty token from OIDC client credentials flow")
	}

	t.Logf("Successfully obtained Keystone token via OIDC client credentials")

	pc, err := auth.AuthenticatedClient(context.Background())
	th.AssertNoErr(t, err)

	if pc.Token() == "" {
		t.Fatal("expected non-empty token on ProviderClient")
	}
}
